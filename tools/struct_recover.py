#!/usr/bin/env python3
"""
struct_recover.py — 从 Rudra 反编译输出中恢复 struct 字段访问。

1. 扫描所有 *(long *)(var + 0xN) 模式，按变量分组
2. 只保留被 ≥2 个不同小偏移（<256B）访问的变量（保守启发式）
3. 生成 _struct typedef with matching fields
4. 重写变量声明为 _struct *
5. 重写 *(long *)(var + 0xN) → var->field_N

用法:
    python tools/struct_recover.py result/curl_cur.c > result/curl_final.c
    python tools/struct_recover.py result/httpd_cur.c > result/httpd_final.c
"""
import re
import sys
from collections import defaultdict
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("usage: struct_recover.py <decompiled.c>", file=sys.stderr)
        sys.exit(2)

    text = Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')

    # Phase 1: Collect var → set of offsets (only small, aligned offsets)
    var_offsets = defaultdict(set)
    for m in re.finditer(r'\*\(long \*\)\(([a-zA-Z_][a-zA-Z0-9_]*) \+ (0x[0-9a-f]+|\d+)\)', text):
        var = m.group(1)
        off_str = m.group(2)
        off = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
        if off < 256 and off % 8 == 0:
            var_offsets[var].add(off)

    # Conservative: only vars with >= 2 distinct offsets
    struct_vars = {var: offsets for var, offsets in var_offsets.items() if len(offsets) >= 2}

    if not struct_vars:
        print(text, end='')
        return

    # Phase 2: Collect ALL offsets for struct typedef (not just conservative ones)
    # The struct needs all field members that will be accessed via ->
    all_struct_offsets = set()
    for var, offsets in var_offsets.items():
        if len(offsets) >= 2:  # conservative vars only get -> rewriting
            all_struct_offsets.update(offsets)
    # Also include offsets from non-conservative vars that share name with conservative
    # (in case the same var has both small and large offsets)
    for var in struct_vars:
        all_struct_offsets.update(var_offsets[var])

    sorted_offsets = sorted(all_struct_offsets)

    members = []
    prev_end = 0
    for off in sorted_offsets:
        if off > prev_end:
            members.append(f"  char _pad_{off:x}[{off - prev_end}];")
        members.append(f"  long field_{off:x};")
        prev_end = off + 8
    struct_decl = f"typedef struct {{\n{chr(10).join(members)}\n}} _struct;\n"

    # Phase 3: Rewrite the text
    result = text

    # Replace ONLY the first _struct typedef with real one, remove ALL others.
    # audit_syntax.py provides _struct from .struct.h in stub, so function bodies
    # don't need their own _struct typedef.
    real_struct_decl = f"typedef struct {{\n{chr(10).join(members)}\n}} _struct;"
    # Remove ALL _struct typedefs from function bodies (stub provides it)
    result = re.sub(
        r'typedef struct \{ char _anon\[256\]; \} _struct;\n?',
        '',
        result
    )

    # Rewrite variable declarations: "long VAR;" → "_struct * VAR;"
    for var in struct_vars:
        for pat in [f"long {var};", f"void * {var};", f"char * {var};",
                    f"int * {var};", f"long * {var};"]:
            result = result.replace(pat, f"_struct * {var};")

    # Rewrite field accesses: *(long *)(VAR + 0xN) → VAR->field_N
    for var in struct_vars:
        for off in struct_vars[var]:
            off_hex = f"0x{off:x}"
            off_dec = str(off)
            for old in [f"*(long *)({var} + {off_hex})", f"*(long *)({var} + {off_dec})"]:
                result = result.replace(old, f"{var}->field_{off:x}")

    # Write the _struct typedef to a stub file for audit_syntax.py
    # Named after the OUTPUT file, not the input
    out_name = Path(sys.argv[1]).stem.replace('_cur', '_final')
    stub_path = Path(sys.argv[1]).parent / f"{out_name}.struct.h"
    stub_path.write_text(struct_decl + "\n", encoding='utf-8')

    # Output result (typedefs are inline per function, first replaced, rest removed)
    print(result, end='')


if __name__ == '__main__':
    main()
