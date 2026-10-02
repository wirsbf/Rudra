#!/usr/bin/env python3
"""
audit_syntax.py — 用 gcc -fsyntax-only 逐函数检查 Rudra 反编译输出的 C 语法正确性。

一个能"对齐 Ghidra"的反编译输出，最低门槛是自身 C 语法合法（Ghidra 输出一定能过编译）。
本脚本把每个函数包成独立 .c 文件，补上类型/外部函数桩，跑 gcc 语法检查，统计错误。

用法:
    python tools/audit_syntax.py result/curl.c
    python tools/audit_syntax.py /tmp/curl_cur.c
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# 匈牙利前缀 → C 类型（用于补声明遗漏的变量）
PREFIX_TYPE = {
    "bVar": "bool", "cVar": "char", "sVar": "short", "iVar": "int", "lVar": "long",
    "uVar": "long", "fVar": "float", "dVar": "double",
    "piVar": "long *", "pcVar": "char *", "psVar": "void *",
    "ppVar": "void *", "pvVar": "void *",
}

STUB_HEADERS = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
/* typedefs emitted inline by printc before each function body */
int curl_version(); int maprintf(); int curl_easy_setopt(); int curl_easy_perform();
int curl_version(); int maprintf(); int curl_easy_setopt(); int curl_easy_perform();
int curl_easy_cleanup(); int curl_slist_free_all(); int helpf(); int parseconfig_constprop_0();
int parseconfig(); int fopen(); int fwrite(); int fclose(); int free(); int malloc();
int strdup(); int strnequal(); int strequal(); int next_url(); int glob_url();
int strstr(); int strrchr(); int fputc(); int ferror(); int ap_get_local_host(); int ap_log_error();
int ap_fini_vhost_config(); int ap_run_test_config(); int ap_init_vhost_config();
int ap_parse_vhost_addrs(); int ap_matches_request_vhost();
int ap_update_vhost_from_headers(); int ap_vhost_iterate_given_conn();
int ap_update_vhost_given_ip(); int ap_ht_time(); int ap_strcmp_match();
int ap_strcasecmp_match(); int ap_is_matchexp(); int ap_strcasestr();
int ap_stripprefix(); int ap_pregsub(); int ap_getparents();
int FUN_0002abc0(); int FUN_0002acb0(); int FUN_0002aa50(); int FUN_0002c520();
int FUN_0002b1a0(); int FUN_0002ab70(); int FUN_0002a820(); int FUN_0002b070();
int FUN_0002a710(); int FUN_0002b430(); int FUN_0002ae60();
/* NOTE: gcc builtins (__fprintf_chk, __vfprintf_chk, __printf_chk, __sprintf_chk,
 * __xstat, exit, puts, strlen, realloc, strchr) are NOT declared here — gcc
 * provides their own prototypes, and declaring them with int() would cause
 * 'conflicting types' or 'too many/few arguments' false failures. */
/* Ghidra base type vocabulary (AUDIT-SYNTAX-SKIPLINE-0001): the locked 12.0.4
 * golden relies on Ghidra's implicit type environment instead of inline
 * typedefs. Lines here whose name is re-declared by the audited file's own
 * inline preamble are dropped per function (see _declared_names), so Rudra
 * output that emits its own typedefs keeps its own spelling. */
typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long undefined8;
/* Ghidra prints calls through unknown-signature function pointers as
 * (*(code *)p)(...) — including result-assigned forms — so code must be an
 * unprototyped int-returning function type. */
typedef int code();
/* Opaque pointer-passed domain types (syntax-level only; member access on
 * these stays a genuine audit finding). */
typedef struct _IO_FILE FILE;
typedef struct stat stat;
typedef struct EVP_PKEY_CTX EVP_PKEY_CTX;
typedef long time_t;
typedef int CURLcode;
typedef int HttpReq;
typedef int URLPatternType;
extern void *stderr;
extern void *stdin;
extern void *stdout;
"""

# Convention-stubbed globals: Ghidra names memory-slot pointer globals PTR_*
# and raw data globals DAT_*; the golden has no extern section for them, so we
# declare every such token found in the audited text (Rudra output declares
# its own globals inline, and those inline lines are deduped per function).
_PTR_GLOBAL_RE = re.compile(r"\b((?:PTR|DAT)_\w+)\b")


def _decl_name(line):
    """Declared name of a typedef/extern line (last identifier before ';')."""
    s = line.strip()
    if s.startswith("typedef ") or s.startswith("extern "):
        m = re.search(r"(\w+)\s*;", s)
        if m:
            return m.group(1)
    return None


def _declared_names(lines):
    """Names declared by typedef/extern lines (last identifier before ';')."""
    return {n for n in (_decl_name(l) for l in lines) if n}


def _brace_delta(line):
    """Net brace delta of a line, ignoring braces inside literals/comments.

    Ghidra golden bodies contain character literals like cVar3 != '{' whose
    braces must not perturb function-boundary depth counting (glob_set was
    previously absorbed into glob_word's body through exactly this).
    """
    s = re.sub(r"/\*.*?\*/", "", line)
    s = re.sub(r"'(\\.|[^'\\])*'", "''", s)
    s = re.sub(r'"(\\.|[^"\\])*"', '""', s)
    return s.count("{") - s.count("}")


def split_functions(text: str):
    """从反编译输出文本中切分出每个函数（签名行到匹配的 '}'）。"""
    lines = text.splitlines()
    funcs = []
    pending_typedefs = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Capture typedef and extern lines (emitted before each function by printc)
        if line.strip().startswith("typedef ") or line.strip().startswith("extern "):
            pending_typedefs.append(line)
            i += 1
            continue
        # Skip blank lines and comment headers between functions
        stripped = line.strip()
        if not stripped or stripped.startswith("/*") or stripped.startswith("Found ") or stripped.startswith("==="):
            i += 1
            continue
        # 函数签名行：以返回类型开头，含 '('，下一行或本行以 '{' 结尾。
        # 词表含 Ghidra 基础类型（undefinedN/ulong/uint/ushort/byte/FILE/time_t/
        # CURLcode 等），否则 golden 中这些返回类型的函数会被静默漏提取；
        # 名字允许一个空格分段（Ghidra processEntry _start 布局）。
        m = re.match(
            r'^(int|long|void|char|short|bool|float|double|size_t|unsigned|uint|ulong|ushort|byte|wchar_t|time_t|undefined\d*|CURLcode|FILE|uchar)\s'
            r'(\*{0,3})\s*\w+( \w+)?\s*\(',
            line,
        )
        if m:
            # 收集到匹配的 '}'
            start = i
            depth = _brace_delta(line)
            j = i + 1
            if depth == 0:
                # skip_line 布局（Ghidra 默认）：签名行、空行（或少量外提的局部
                # 声明行）、独立 '{' 行。depth 从签名行起算会立刻为 0 而吞不掉
                # 函数体（golden 自身 116/116 FAIL 根因，AUDIT-SYNTAX-
                # SKIPLINE-0001）。跳过空行/声明行找到独立 '{' 行才起算 depth；
                # 找不到则回滚到原有基线（j 已指向 i+1，签名行单独成 body，
                # gcc 会以 expected '{' 响亮失败）。
                k = j
                while k < len(lines):
                    s = lines[k].strip()
                    if not s or re.match(r'^[A-Za-z_][\w \t\*]*;\s*$', s):
                        k += 1
                        continue
                    break
                if k < len(lines) and lines[k].strip() == "{":
                    depth += _brace_delta(lines[k])
                    j = k + 1
            while j < len(lines) and depth > 0:
                depth += _brace_delta(lines[j])
                j += 1
            body = "\n".join(lines[start:j])
            name_match = re.search(r'\b(\w+)\s*\(', line)
            name = name_match.group(1) if name_match else f"func_{i}"
            # Prepend accumulated typedefs so size-based type names (byte etc.) resolve
            if pending_typedefs:
                body = "\n".join(pending_typedefs) + "\n" + body
                pending_typedefs = []
            funcs.append((name, body))
            i = j
        else:
            i += 1
    return funcs


def audit_one(text: str, label: str):
    funcs = split_functions(text)
    print(f"\n=== {label}: {len(funcs)} functions ===")
    total_err = 0
    err_kinds = {}
    failures = []
    # Check for struct.h sibling (from struct_recover.py)
    struct_h_path = Path(label).with_suffix('.struct.h')
    struct_typedef = ""
    if struct_h_path.exists():
        struct_typedef = struct_h_path.read_text()
    # If no struct.h, don't add _struct typedef — it's in the function body
    # Convention externs for Ghidra memory-slot globals (see STUB_HEADERS
    # note): PTR_* are pointer slots (compared to NULL / cast to code *),
    # DAT_* are raw data globals that also appear in arithmetic, hence long.
    # Types are self-contained so per-function dedup of the typedef block
    # cannot leave these referencing a removed typedef.
    conv_globals = sorted(set(_PTR_GLOBAL_RE.findall(text)))
    ptr_externs = "\n".join(
        f"extern unsigned char *{g};" if g.startswith("PTR_") else f"extern long {g};"
        for g in conv_globals
    )

    for name, body in funcs:
        # Build stub that excludes the function being compiled (avoids
        # 'conflicting types' when our int() stub disagrees with the
        # function's own inferred signature). Also drop stub typedef/extern
        # lines whose name is re-declared by this file's inline preamble, so
        # audited files that carry their own declarations keep their spelling.
        stub = STUB_HEADERS + ptr_externs + struct_typedef
        own_names = _declared_names(
            l for l in body.splitlines() if l.startswith(("typedef ", "extern "))
        )
        stub_lines = [l for l in stub.split('\n')
                      if not (f' {name}(' in l or f' {name};' in l)
                      and _decl_name(l) not in own_names]
        stub = '\n'.join(stub_lines)
        src = stub + "\n" + body + "\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False, encoding="utf-8") as f:
            f.write(src)
            tmp = f.name
        try:
            r = subprocess.run(
                ["gcc", "-fsyntax-only", "-w", tmp],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                # Classify errors; ignore 'conflicting types' since those come
                # from our extern stubs (int f()) disagreeing with Rudra's
                # inferred signature, not from Rudra's own output.
                stub_conflict = False
                real_errors = []
                for line in r.stderr.splitlines():
                    if "conflicting types" in line.lower():
                        stub_conflict = True
                        continue
                    real_errors.append(line)
                    if "undeclared" in line.lower():
                        err_kinds["undeclared"] = err_kinds.get("undeclared", 0) + 1
                    elif "expected" in line.lower():
                        err_kinds["syntax"] = err_kinds.get("syntax", 0) + 1
                    else:
                        err_kinds["other"] = err_kinds.get("other", 0) + 1
                # If the only errors were stub conflicts, don't count as failure
                if stub_conflict and not real_errors:
                    continue
                total_err += 1
                # 抓第一行真实错误（跳过 conflicting types 行）
                first_err = next(
                    (l for l in r.stderr.splitlines()
                     if "error:" in l.lower() and "conflicting types" not in l.lower()),
                    "?",
                )
                failures.append((name, first_err.strip()[:120]))
        except Exception as e:
            failures.append((name, f"AUDIT_EXC: {e}"))
        finally:
            Path(tmp).unlink(missing_ok=True)
    ok = len(funcs) - total_err
    print(f"  C-syntax OK: {ok}/{len(funcs)}")
    print(f"  FAIL: {total_err}")
    if err_kinds:
        print(f"  error kinds: {err_kinds}")
    for name, err in failures[:15]:
        print(f"    [{name}] {err}")
    if len(failures) > 15:
        print(f"    ... and {len(failures)-15} more")
    return ok, total_err


def main():
    if len(sys.argv) < 2:
        print("usage: audit_syntax.py <decompiled.c> [<decompiled2.c> ...]")
        sys.exit(2)
    total_ok = total_fail = 0
    for path in sys.argv[1:]:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        ok, fail = audit_one(text, path)
        total_ok += ok
        total_fail += fail
    print(f"\n=== TOTAL: {total_ok} OK, {total_fail} FAIL ===")
    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
