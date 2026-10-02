"""
patch_ffi_opcode_map.py — 修复 ffi.rs 中 map_ghidra_opcode 使其与 Ghidra opcodes.hh 严格 1:1 对齐
"""
path = r"d:\ghidra\rudra\src\ffi.rs"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

OLD_MAP = """fn map_ghidra_opcode(opcode: i32) -> Option<OpCode> {
    match opcode {
        1 => Some(OpCode::CPUI_COPY),
        2 => Some(OpCode::CPUI_LOAD),
        3 => Some(OpCode::CPUI_STORE),
        4 => Some(OpCode::CPUI_BRANCH),
        5 => Some(OpCode::CPUI_CBRANCH),
        6 => Some(OpCode::CPUI_BRANCHIND),
        7 => Some(OpCode::CPUI_CALL),
        8 => Some(OpCode::CPUI_CALLIND),
        10 => Some(OpCode::CPUI_RETURN),

        11 => Some(OpCode::CPUI_INT_EQUAL),
        12 => Some(OpCode::CPUI_INT_NOTEQUAL),
        13 => Some(OpCode::CPUI_INT_SLESS),
        14 => Some(OpCode::CPUI_INT_SLESSEQUAL),
        15 => Some(OpCode::CPUI_INT_LESS),
        16 => Some(OpCode::CPUI_INT_LESSEQUAL),
        17 => Some(OpCode::CPUI_INT_ZEXT),
        18 => Some(OpCode::CPUI_INT_SEXT),
        19 => Some(OpCode::CPUI_INT_ADD),
        20 => Some(OpCode::CPUI_INT_SUB),
        21 => Some(OpCode::CPUI_INT_MULT),
        22 => Some(OpCode::CPUI_INT_DIV),
        23 => Some(OpCode::CPUI_INT_SDIV),
        24 => Some(OpCode::CPUI_INT_NEG),
        25 => Some(OpCode::CPUI_INT_NOT),
        26 => Some(OpCode::CPUI_INT_XOR),
        27 => Some(OpCode::CPUI_INT_AND),
        28 => Some(OpCode::CPUI_INT_OR),
        29 => Some(OpCode::CPUI_INT_LEFT),
        30 => Some(OpCode::CPUI_INT_RIGHT),
        31 => Some(OpCode::CPUI_INT_SRIGHT),
        32 => Some(OpCode::CPUI_INT_MULT),
        33 => Some(OpCode::CPUI_INT_DIV),
        34 => Some(OpCode::CPUI_INT_SDIV),
        35 => Some(OpCode::CPUI_INT_REM),
        36 => Some(OpCode::CPUI_INT_SREM),

        37 => Some(OpCode::CPUI_BOOL_NOT),
        38 => Some(OpCode::CPUI_BOOL_XOR),
        39 => Some(OpCode::CPUI_BOOL_AND),
        40 => Some(OpCode::CPUI_BOOL_OR),

        41 => Some(OpCode::CPUI_FLOAT_EQUAL),
        42 => Some(OpCode::CPUI_FLOAT_NOTEQUAL),
        43 => Some(OpCode::CPUI_FLOAT_LESS),
        44 => Some(OpCode::CPUI_FLOAT_LESSEQUAL),
        47 => Some(OpCode::CPUI_FLOAT_ADD),
        48 => Some(OpCode::CPUI_FLOAT_DIV),
        49 => Some(OpCode::CPUI_FLOAT_MULT),
        50 => Some(OpCode::CPUI_FLOAT_SUB),
        51 => Some(OpCode::CPUI_FLOAT_NEG),
        52 => Some(OpCode::CPUI_FLOAT_ABS),
        53 => Some(OpCode::CPUI_FLOAT_SQRT),

        62 => Some(OpCode::CPUI_PIECE),
        63 => Some(OpCode::CPUI_SUBPIECE),

        72 => Some(OpCode::CPUI_POPCOUNT),
        73 => Some(OpCode::CPUI_LZCOUNT),

        _ => None,
    }
}"""

# 严格按照 Ghidra opcodes.hh 的枚举值重写
NEW_MAP = """fn map_ghidra_opcode(opcode: i32) -> Option<OpCode> {
    // 严格按照 Ghidra opcodes.hh 枚举值映射，1:1 对拍红线
    match opcode {
        // === Data Movement ===
        1 => Some(OpCode::CPUI_COPY),
        2 => Some(OpCode::CPUI_LOAD),
        3 => Some(OpCode::CPUI_STORE),

        // === Control Flow ===
        4 => Some(OpCode::CPUI_BRANCH),
        5 => Some(OpCode::CPUI_CBRANCH),
        6 => Some(OpCode::CPUI_BRANCHIND),
        7 => Some(OpCode::CPUI_CALL),
        8 => Some(OpCode::CPUI_CALLIND),
        9 => Some(OpCode::CPUI_CALLOTHER),
        10 => Some(OpCode::CPUI_RETURN),

        // === Integer Comparison ===
        11 => Some(OpCode::CPUI_INT_EQUAL),
        12 => Some(OpCode::CPUI_INT_NOTEQUAL),
        13 => Some(OpCode::CPUI_INT_SLESS),
        14 => Some(OpCode::CPUI_INT_SLESSEQUAL),
        15 => Some(OpCode::CPUI_INT_LESS),
        16 => Some(OpCode::CPUI_INT_LESSEQUAL),

        // === Extension ===
        17 => Some(OpCode::CPUI_INT_ZEXT),
        18 => Some(OpCode::CPUI_INT_SEXT),

        // === Integer Arithmetic ===
        19 => Some(OpCode::CPUI_INT_ADD),
        20 => Some(OpCode::CPUI_INT_SUB),
        21 => Some(OpCode::CPUI_INT_CARRY),    // Ghidra: INT_CARRY, NOT INT_MULT!
        22 => Some(OpCode::CPUI_INT_SCARRY),   // Ghidra: INT_SCARRY, NOT INT_DIV!
        23 => Some(OpCode::CPUI_INT_SBORROW),  // Ghidra: INT_SBORROW, NOT INT_SDIV!
        24 => Some(OpCode::CPUI_INT_NEG),      // Ghidra: INT_2COMP (twos complement)
        25 => Some(OpCode::CPUI_INT_NOT),      // Ghidra: INT_NEGATE (bitwise ~)

        // === Bitwise ===
        26 => Some(OpCode::CPUI_INT_XOR),
        27 => Some(OpCode::CPUI_INT_AND),
        28 => Some(OpCode::CPUI_INT_OR),
        29 => Some(OpCode::CPUI_INT_LEFT),
        30 => Some(OpCode::CPUI_INT_RIGHT),
        31 => Some(OpCode::CPUI_INT_SRIGHT),

        // === Integer Multiply/Divide ===
        32 => Some(OpCode::CPUI_INT_MULT),
        33 => Some(OpCode::CPUI_INT_DIV),
        34 => Some(OpCode::CPUI_INT_SDIV),
        35 => Some(OpCode::CPUI_INT_REM),
        36 => Some(OpCode::CPUI_INT_SREM),

        // === Boolean ===
        37 => Some(OpCode::CPUI_BOOL_NOT),     // Ghidra: BOOL_NEGATE
        38 => Some(OpCode::CPUI_BOOL_XOR),
        39 => Some(OpCode::CPUI_BOOL_AND),
        40 => Some(OpCode::CPUI_BOOL_OR),

        // === Floating Point ===
        41 => Some(OpCode::CPUI_FLOAT_EQUAL),
        42 => Some(OpCode::CPUI_FLOAT_NOTEQUAL),
        43 => Some(OpCode::CPUI_FLOAT_LESS),
        44 => Some(OpCode::CPUI_FLOAT_LESSEQUAL),
        // 45 is unused in Ghidra
        46 => Some(OpCode::CPUI_FLOAT_NAN),
        47 => Some(OpCode::CPUI_FLOAT_ADD),
        48 => Some(OpCode::CPUI_FLOAT_DIV),
        49 => Some(OpCode::CPUI_FLOAT_MULT),
        50 => Some(OpCode::CPUI_FLOAT_SUB),
        51 => Some(OpCode::CPUI_FLOAT_NEG),
        52 => Some(OpCode::CPUI_FLOAT_ABS),
        53 => Some(OpCode::CPUI_FLOAT_SQRT),

        // === Float Conversion ===
        54 => Some(OpCode::CPUI_FLOAT_INT2FLOAT),
        55 => Some(OpCode::CPUI_FLOAT_FLOAT2FLOAT),
        56 => Some(OpCode::CPUI_FLOAT_TRUNC),
        57 => Some(OpCode::CPUI_FLOAT_CEIL),
        58 => Some(OpCode::CPUI_FLOAT_FLOOR),
        59 => Some(OpCode::CPUI_FLOAT_ROUND),

        // === Internal / SSA ===
        60 => Some(OpCode::CPUI_MULTIEQUAL),
        61 => Some(OpCode::CPUI_INDIRECT),
        62 => Some(OpCode::CPUI_PIECE),
        63 => Some(OpCode::CPUI_SUBPIECE),

        // === Type / Pointer ===
        // 64 => CPUI_CAST (Rudra 暂无此变体)
        65 => Some(OpCode::CPUI_PTRADD),
        66 => Some(OpCode::CPUI_PTRSUB),
        67 => Some(OpCode::CPUI_SEGMENTOP),
        68 => Some(OpCode::CPUI_CPOOLREF),
        69 => Some(OpCode::CPUI_NEW),
        70 => Some(OpCode::CPUI_INSERT),
        71 => Some(OpCode::CPUI_EXTRACT),
        72 => Some(OpCode::CPUI_POPCOUNT),
        73 => Some(OpCode::CPUI_LZCOUNT),

        _ => None,
    }
}"""

if OLD_MAP in content:
    content = content.replace(OLD_MAP, NEW_MAP)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("✅ 成功修复 map_ghidra_opcode (严格对齐 Ghidra opcodes.hh)")
else:
    print("❌ 未找到旧映射表，可能格式已变化")
    # Debug: find the function
    idx = content.find("fn map_ghidra_opcode")
    if idx >= 0:
        print(f"函数在字符位置 {idx}，附近内容:")
        print(repr(content[idx:idx+200]))
    else:
        print("函数本身也找不到!")
