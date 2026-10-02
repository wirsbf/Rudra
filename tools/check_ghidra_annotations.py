#!/usr/bin/env python3
"""
check_ghidra_annotations.py — AGENTS.md 铁律 1.3 执行工具。

每个 src/*.rs 中的非测试函数定义上方，必须有一行 `// Ghidra:` 注释，
引用其对应的 Ghidra 源码位置（file:line + 函数名）。
没有该注释 = 自创函数 = 违反对齐原则（AGENTS.md 铁律 1.3）。

豁免:
  - `#[test]` 标注的函数
  - `#[cfg(test)] mod tests { ... }` 内的所有函数
  - `fn main` / `fn run`（二进制入口；用 // RUDRA-GLUE: 标注即可豁免）
  - 显式标注 `// RUDRA-GLUE:` 的函数（构造器/访问器/无 Ghidra 对应的
    Rust 语言结构必需的胶水，如 new/take_emit/get_emit/set_emit，每次
    豁免必须在注释里写明为何 Ghidra 没有对应物）

用法:
    python tools/check_ghidra_annotations.py          # 检查全量 src/*.rs
    python tools/check_ghidra_annotations.py --staged # 只检查暂存的 .rs 改动
    python tools/check_ghidra_annotations.py src/foo.rs  # 检查指定文件

退出码:
    0 = 所有非测试函数都有 Ghidra 注释
    1 = 存在违规（自创函数）
"""

import re
import sys
import os
import subprocess
from pathlib import Path

try:  # ``python -m tools.check_ghidra_annotations``
    from .rust_fn_scanner import RustFunction, run_self_test as run_scanner_self_test
    from .rust_fn_scanner import scan_rust_functions
except ImportError:  # ``python tools/check_ghidra_annotations.py``
    from rust_fn_scanner import RustFunction, run_self_test as run_scanner_self_test
    from rust_fn_scanner import scan_rust_functions

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

# Ghidra 注释正则：`// Ghidra:` （允许前导空白和 // 后空格）
GHIDRA_RE = re.compile(r"//\s*Ghidra:")

# RUDRA-GLUE 豁免标记
GLUE_RE = re.compile(r"//\s*RUDRA-GLUE:")

def detect_git_prefix() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, cwd=PROJECT_ROOT
    )
    git_root = Path(result.stdout.strip())
    try:
        rel = PROJECT_ROOT.relative_to(git_root)
        prefix = str(rel).replace("\\", "/")
        return (prefix + "/") if prefix and prefix != "." else ""
    except ValueError:
        return ""


GIT_PREFIX = detect_git_prefix()


def strip_prefix(path: str) -> str:
    if GIT_PREFIX and path.startswith(GIT_PREFIX):
        return path[len(GIT_PREFIX):]
    return path


def get_staged_rs_files() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--staged"],
        capture_output=True, text=True, cwd=PROJECT_ROOT
    )
    raw = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    out = []
    for f in raw:
        f = strip_prefix(f)
        if f.startswith("src/") and f.endswith(".rs"):
            out.append(f)
    return out


def _staged_added_line_numbers(rs_rel: str) -> set[int]:
    """Return the set of 1-based line numbers that are ADDED or MODIFIED in
    the staged version of `rs_rel` (relative to its staged parent). Used by
    --staged mode to limit annotation violations to fns actually touched by
    this commit, so the gate is incremental rather than paralyzed by
    pre-existing un-annotated fns elsewhere in the same file."""
    out: set[int] = set()
    # diff staged (index vs working tree is NOT what we want; we want HEAD vs
    # index for an amended-commit-style view, but for a normal commit the
    # staged set is index-vs-HEAD). Use --cached (== --staged) against HEAD.
    result = subprocess.run(
        ["git", "diff", "--cached", "--unified=0", "--", rs_rel],
        capture_output=True, text=True, cwd=PROJECT_ROOT
    )
    cur = 0
    for line in result.stdout.splitlines():
        if line.startswith("@@"):
            # @@ -a,b +c,d @@  -> new hunk starts at line c
            m = re.search(r"\+(\d+)", line)
            if m:
                cur = int(m.group(1))
            else:
                cur = 0
        elif line.startswith("+") and not line.startswith("+++"):
            if cur > 0:
                out.add(cur)
            cur += 1
        elif line.startswith("-") and not line.startswith("---"):
            # deletion: doesn't advance the new-file line counter
            pass
        else:
            cur += 1
    return out


def get_all_rs_files() -> list[str]:
    out = []
    for root, _, files in os.walk(SRC_DIR):
        for f in files:
            if f.endswith(".rs"):
                full = Path(root) / f
                out.append(str(full.relative_to(PROJECT_ROOT)).replace("\\", "/"))
    return out


def _has_alignment_marker(lines: list[str], fn_line: int) -> bool:
    """Check the comment/attribute block immediately above a function item."""

    j = fn_line - 1
    while j >= 0:
        stripped = lines[j].strip()
        if not stripped or stripped.startswith("#![") or stripped.startswith("#["):
            j -= 1
            continue
        if stripped.startswith("//"):
            if GHIDRA_RE.search(stripped) or GLUE_RE.search(stripped):
                return True
            j -= 1
            continue
        break
    return False


def _find_fn_violation_records(text: str) -> list[tuple[RustFunction, str]]:
    lines = text.split("\n")
    violations: list[tuple[RustFunction, str]] = []
    records = scan_rust_functions(text)
    first_item_on_line: dict[int, int] = {}
    for record in records:
        first_item_on_line.setdefault(record.start_line, record.start)
    for record in records:
        can_use_above_marker = first_item_on_line[record.start_line] == record.start
        if record.is_test or (
            can_use_above_marker and _has_alignment_marker(lines, record.start_line)
        ):
            continue
        reason = "缺少 `// Ghidra: <file>:<line> <fn>` 对齐注释"
        if record.name in ("main", "run", "default"):
            reason = (
                f"入口/语言胶水函数 `{record.name}` 缺少 `// RUDRA-GLUE:` "
                "标注（说明为何 Ghidra 无对应物）"
            )
        violations.append((record, reason))
    return violations


def find_fn_violations(rs_abs: Path) -> list[tuple[int, str, str]]:
    """Return unannotated, non-test Rust function items."""

    try:
        text = rs_abs.read_text(encoding="utf-8")
    except Exception:
        return []
    return [
        (record.start_line + 1, record.name, reason)
        for record, reason in _find_fn_violation_records(text)
    ]


def run_self_test() -> None:
    run_scanner_self_test()
    fixture = r'''
// Ghidra: test.cc:1 annotated
pub const fn annotated() {}
pub const fn const_item() {}
pub(crate) fn restricted() {}
pub extern "C" fn exported() {}
pub unsafe extern "C" fn unsafe_exported() {}
trait T { fn declared(&self); }
struct Compact;
impl Compact { pub fn compact() {} }
// Ghidra: test.cc:2 first_on_line
impl Pair { fn first_on_line() {} fn second_on_line() {} }
#[cfg(test)]
mod arbitrary_name { mod nested { fn nested_test() {} } }
fn production_after_test() {}
mod production_module {
    #[cfg(test)]
    mod fixtures { fn nested_test_two() {} }
    fn nested_production() {}
}
#[cfg(not(test))]
fn cfg_not_test() {}
// fn fake_comment() {}
const S: &str = "fn fake_string() {}";
'''
    violations = _find_fn_violation_records(fixture)
    names = [record.name for record, _ in violations]
    assert names == [
        "const_item", "restricted", "exported", "unsafe_exported", "declared",
        "compact", "second_on_line", "production_after_test", "nested_production",
        "cfg_not_test",
    ], names
    assert "annotated" not in names and "nested_test" not in names



def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        run_self_test()
        print("✅ check_ghidra_annotations self-test passed")
        return 0
    mode = "--all"
    explicit_files = []
    for a in args:
        if a in ("--all", "--staged"):
            mode = a
        elif a.endswith(".rs"):
            explicit_files.append(a)

    if explicit_files:
        rs_files = explicit_files
    elif mode == "--staged":
        rs_files = get_staged_rs_files()
        if not rs_files:
            print("✅ 暂存区无 .rs 文件改动")
            return 0
    else:
        rs_files = get_all_rs_files()

    # In --staged mode, only flag fns whose definition line is part of the
    # staged diff (added/modified fn). This makes the gate INCREMENTAL: it
    # blocks new/changed un-annotated fns without being paralyzed by the
    # pre-existing 4560 historical un-annotated fns (which `--all` would
    # surface). `--all` mode remains a full-repo audit. This realises the
    # gate's stated intent: "无注释 = 自创函数 = 拒绝" applied to NEW work.
    staged_added_lines: dict[str, set[int]] = {}
    if mode == "--staged":
        for f in rs_files:
            staged_added_lines[f] = _staged_added_line_numbers(f)

    total_violations = 0
    file_count = 0
    for rs_rel in rs_files:
        rs_abs = PROJECT_ROOT / rs_rel
        if not rs_abs.exists():
            continue
        file_count += 1
        text = rs_abs.read_text(encoding="utf-8")
        violation_records = _find_fn_violation_records(text)
        vios = [
            (record.start_line + 1, record.name, reason)
            for record, reason in violation_records
        ]
        if mode == "--staged":
            added = staged_added_lines.get(rs_rel, set())
            vios = [
                (record.start_line + 1, record.name, reason)
                for record, reason in violation_records
                if any(record.start_line + 1 <= line <= record.end_line + 1 for line in added)
            ]
        if vios:
            total_violations += len(vios)
            print(f"\n❌ {rs_rel}  ({len(vios)} 个违规)")
            for line_no, name, reason in vios[:30]:
                print(f"   {rs_rel}:{line_no}  fn {name}  — {reason}")
            if len(vios) > 30:
                print(f"   ... 还有 {len(vios) - 30} 个")

    if total_violations == 0:
        print(f"✅ 扫描 {file_count} 个 .rs 文件：所有非测试函数都有 Ghidra/RUDRA-GLUE 注释")
        return 0

    print(f"\n━━━ 共 {total_violations} 个自创函数（无 Ghidra 对齐注释）━━━")
    print("每个非测试函数上方必须有一行 `// Ghidra: <file>:<line> <ghidraFnName>`，")
    print("或对真正的语言结构胶水（构造器/访问器）标注 `// RUDRA-GLUE: <理由>`。")
    print("详见 AGENTS.md 铁律 1.3。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
