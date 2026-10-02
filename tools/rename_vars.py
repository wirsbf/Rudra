#!/usr/bin/env python3
"""
rename_vars.py — 从 DWARF debug_info 提取函数局部变量名，
将 Rudra 输出中的 lVarN/piVarN/local_N 匿名变量替换为源代码变量名。

映射策略：
1. 从 DWARF 提取每个函数的 DW_TAG_variable 的 DW_AT_name + DW_OP_fbreg 偏移
2. Rudra 的 local_XX 对应栈帧偏移（通常 local_XX 的 XX 是 DWARF fbreg 的负偏移的十六进制）
3. 直接在输出文本中替换 local_XX → 源代码变量名

用法:
    python tools/rename_vars.py examples/curl result/curl_final.c > result/curl_named.c
"""
import subprocess
import re
import sys
from collections import defaultdict
from pathlib import Path


def extract_dwarf_varnames(binary: str) -> dict:
    """Parse DWARF debug_info and extract function → {fbreg_offset: varname}."""
    result = subprocess.run(
        ["readelf", "--debug-dump=info", binary],
        capture_output=True, text=True, timeout=30
    )
    lines = result.stdout.splitlines()

    func_vars = {}  # func_name → {fbreg_offset: varname}
    current_func = None
    current_depth = 0

    for i, line in enumerate(lines):
        # Detect subprogram (function)
        m = re.search(r'<(\d+)><[0-9a-f]+>.*DW_TAG_subprogram', line)
        if m:
            depth = int(m.group(1))
            if depth == 1:
                current_func = None

        # Check for DW_AT_name on this or next line
        name_match = re.search(r'DW_AT_name\s*:.*:\s*(\w+)', line)
        if name_match:
            name = name_match.group(1)
            # Check if this is a function name (preceded by DW_TAG_subprogram)
            for j in range(max(0, i-3), i):
                if 'DW_TAG_subprogram' in lines[j]:
                    current_func = name
                    func_vars[current_func] = {}
                    break

        # Check for variable with DW_OP_fbreg
        if current_func and 'DW_TAG_variable' in line:
            # Look ahead for name and location
            var_name = None
            fbreg_off = None
            for j in range(i+1, min(i+10, len(lines))):
                nm = re.search(r'DW_AT_name\s*:.*:\s*(\w+)', lines[j])
                if nm and var_name is None:
                    var_name = nm.group(1)
                # DW_OP_fbreg: offset
                loc = re.search(r'DW_OP_fbreg:\s*(-?\d+)', lines[j])
                if loc:
                    fbreg_off = int(loc.group(1))
                if var_name and fbreg_off is not None:
                    break
            if var_name and fbreg_off is not None:
                func_vars[current_func][fbreg_off] = var_name

    return func_vars


def rename_in_output(text: str, func_vars: dict) -> str:
    """Replace anonymous variable names with DWARF-derived names."""
    lines = text.splitlines()
    result = []

    # Track which function we're in
    current_func = None
    # Build a mapping of local_XX → real_name for the current function
    var_map = {}

    for line in lines:
        # Detect function header
        func_match = re.search(r'/\* ---- 0x[0-9a-f]+: (\S+) ', line)
        if func_match:
            current_func = func_match.group(1)
            var_map = {}
            # Build mapping from DWARF info
            # Try normalized function name (replace . with _)
            norm_name = current_func.replace('.', '_')
            for fn in [current_func, norm_name,
                       current_func.split('.')[0],  # "parseconfig.constprop.0" → "parseconfig"
                       norm_name.split('_')[0] if '_' in norm_name else norm_name]:
                if fn in func_vars:
                    for fbreg_off, var_name in func_vars[fn].items():
                        # Rudra's local_XX uses hex of the absolute offset
                        # DWARF fbreg is relative to frame base (usually -RBP or -RSP)
                        # local_XX where XX = abs(fbreg) in hex
                        local_name = f"local_{abs(fbreg_off):x}"
                        var_map[local_name] = var_name
                    break

        new_line = line
        if var_map:
            for local_name, real_name in var_map.items():
                # Replace local_XX → real_name (word boundary)
                new_line = re.sub(r'\b' + re.escape(local_name) + r'\b', real_name, new_line)

        result.append(new_line)

    return '\n'.join(result)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("usage: rename_vars.py <binary> <decompiled.c>")
        sys.exit(2)

    binary = sys.argv[1]
    decomp_path = sys.argv[2]

    func_vars = extract_dwarf_varnames(binary)
    text = Path(decomp_path).read_text(encoding='utf-8', errors='replace')
    result = rename_in_output(text, func_vars)

    # Stats
    total_vars = sum(len(v) for v in func_vars.values())
    print(f"/* rename_vars: {total_vars} DWARF variables extracted from {len(func_vars)} functions */",
          file=sys.stderr)

    print(result, end='')
