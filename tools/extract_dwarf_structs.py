#!/usr/bin/env python3
"""
extract_dwarf_structs.py — 从 ELF 的 DWARF debug_info 中提取 struct 定义，
生成 C struct 定义（用于注入 Rudra 的反编译输出）。

用法:
    python tools/extract_dwarf_structs.py examples/curl > result/curl_structs.h
"""
import subprocess
import sys
import re
from pathlib import Path


def extract_structs(binary_path: str) -> str:
    """Parse DWARF debug_info and generate C struct definitions."""
    result = subprocess.run(
        ["readelf", "--debug-dump=info", binary_path],
        capture_output=True, text=True, timeout=30
    )
    lines = result.stdout.splitlines()

    structs = {}  # struct_name -> [(member_name, offset, type_ref)]
    current_struct = None

    i = 0
    while i < len(lines):
        line = lines[i]
        # Look for DW_TAG_structure_type with a name
        if "DW_TAG_structure_type" in line:
            # Find the name on subsequent lines
            j = i + 1
            struct_name = None
            byte_size = 0
            while j < len(lines) and j < i + 10:
                m = re.search(r'DW_AT_name\s*:.*:\s*(\w+)', lines[j])
                if m and struct_name is None:
                    struct_name = m.group(1)
                m2 = re.search(r'DW_AT_byte_size\s*:\s*(\d+)', lines[j])
                if m2:
                    byte_size = int(m2.group(1))
                if "DW_AT_sibling" in lines[j] or "DW_TAG_member" in lines[j]:
                    break
                j += 1
            if struct_name and byte_size > 0:
                current_struct = struct_name
                structs[struct_name] = []
                # Collect members
                k = j
                while k < len(lines):
                    if "DW_TAG_member" in lines[k]:
                        mname = None
                        moff = None
                        kk = k + 1
                        while kk < len(lines) and kk < k + 8:
                            mn = re.search(r'DW_AT_name\s*:.*:\s*(\w+)', lines[kk])
                            if mn and mname is None:
                                mname = mn.group(1)
                            mo = re.search(r'DW_AT_data_member_location:\s*(\d+)', lines[kk])
                            if mo:
                                moff = int(mo.group(1))
                            if mname and moff is not None:
                                break
                            kk += 1
                        if mname and moff is not None:
                            structs[struct_name].append((mname, moff, "long"))
                    elif "<1>" in lines[k] and "DW_TAG_structure_type" in lines[k]:
                        break
                    elif "<1>" in lines[k] and "DW_TAG_" in lines[k] and "member" not in lines[k]:
                        break
                    k += 1
                current_struct = None
        i += 1

    # Generate C definitions
    output = []
    output.append("/* DWARF-derived struct definitions */\n")
    for sname, members in sorted(structs.items()):
        if not members:
            continue
        output.append(f"struct {sname} {{")
        for mname, moff, mtype in members:
            output.append(f"  {mtype} {mname}; /* offset {moff} */")
        output.append("};\n")

    # Also generate offset → field name lookup for each struct
    output.append("/* Offset → field name mapping for struct field recovery */")
    for sname, members in sorted(structs.items()):
        if not members:
            continue
        for mname, moff, _ in members:
            output.append(f"/* {sname} + {moff:#x} = {mname} */")

    return "\n".join(output)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: extract_dwarf_structs.py <binary>")
        sys.exit(1)
    print(extract_structs(sys.argv[1]))
