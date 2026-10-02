"""
ffi_test.py — Rudra FFI 常量求值全覆盖验证套件
严格按照 Ghidra opcodes.hh 编号，覆盖所有整数算术/位运算/比较/扩展操作
"""
import ctypes
import os
import sys

# === DLL 加载 ===
script_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(script_dir)
dll_path = os.path.join(root_dir, "target", "debug", "rudra.dll")

if not os.path.exists(dll_path):
    print(f"错误: 找不到 {dll_path}")
    print("请先运行 'cargo build --features ffi-test' 生成动态库。")
    sys.exit(1)

try:
    lib = ctypes.CDLL(dll_path)
except Exception as e:
    print(f"无法加载 DLL: {e}")
    sys.exit(1)

# === 函数签名 ===
lib.rudra_evaluate_constant.argtypes = [
    ctypes.c_int32,  # opcode
    ctypes.c_size_t, # size_out
    ctypes.c_uint64, # val1
    ctypes.c_size_t, # size1
    ctypes.c_uint64, # val2
    ctypes.c_size_t, # size2
    ctypes.c_bool    # has_val2
]
lib.rudra_evaluate_constant.restype = ctypes.c_uint64
lib.rudra_version.restype = ctypes.c_char_p

# === Ghidra opcodes.hh 编号（权威标准）===
CPUI_INT_EQUAL       = 11
CPUI_INT_NOTEQUAL    = 12
CPUI_INT_SLESS       = 13
CPUI_INT_SLESSEQUAL  = 14
CPUI_INT_LESS        = 15
CPUI_INT_LESSEQUAL   = 16
CPUI_INT_ZEXT        = 17
CPUI_INT_SEXT        = 18
CPUI_INT_ADD         = 19
CPUI_INT_SUB         = 20
# 21 = CARRY, 22 = SCARRY, 23 = SBORROW (目前 Rudra 未实现求值)
CPUI_INT_2COMP       = 24   # twos complement = NEG
CPUI_INT_NEGATE      = 25   # bitwise NOT = ~
CPUI_INT_XOR         = 26
CPUI_INT_AND         = 27
CPUI_INT_OR          = 28
CPUI_INT_LEFT        = 29
CPUI_INT_RIGHT       = 30
CPUI_INT_SRIGHT      = 31
CPUI_INT_MULT        = 32
CPUI_INT_DIV         = 33
CPUI_INT_SDIV        = 34
CPUI_INT_REM         = 35
CPUI_INT_SREM        = 36

def eval_const(opcode, size_out, v1, s1, v2=0, s2=0, has_v2=True):
    return lib.rudra_evaluate_constant(opcode, size_out, v1, s1, v2, s2, has_v2)

def run_tests():
    print(f"Rudra 版本: {lib.rudra_version().decode()}")
    print("=" * 70)
    print(f"{'测试项':<30} | {'结果':<18} | {'状态'}")
    print("-" * 70)

    passed = 0
    failed = 0

    # (名称, opcode, size_out, v1, s1, v2, s2, has_v2, 预期值)
    test_cases = [
        # === 基础算术 ===
        ("ADD: 1+2 (32-bit)",         CPUI_INT_ADD, 4, 1, 4, 2, 4, True, 3),
        ("ADD: 溢出 0xFFFFFFFF+1",    CPUI_INT_ADD, 4, 0xFFFFFFFF, 4, 1, 4, True, 0),
        ("ADD: 64-bit 大数",          CPUI_INT_ADD, 8, 0x100000000, 8, 0x200000000, 8, True, 0x300000000),
        ("SUB: 10-3",                 CPUI_INT_SUB, 4, 10, 4, 3, 4, True, 7),
        ("SUB: 下溢 0-1 (32-bit)",    CPUI_INT_SUB, 4, 0, 4, 1, 4, True, 0xFFFFFFFF),
        ("MULT: 5*6",                 CPUI_INT_MULT, 4, 5, 4, 6, 4, True, 30),
        ("MULT: 溢出 0x10000*0x10000", CPUI_INT_MULT, 4, 0x10000, 4, 0x10000, 4, True, 0),
        ("DIV: 100/7",                CPUI_INT_DIV, 4, 100, 4, 7, 4, True, 14),
        ("DIV: 除以0",                CPUI_INT_DIV, 4, 42, 4, 0, 4, True, 0),
        ("SDIV: -10/3",               CPUI_INT_SDIV, 8, (-10) & 0xFFFFFFFFFFFFFFFF, 8, 3, 8, True, (-3) & 0xFFFFFFFFFFFFFFFF),
        ("REM: 100%7",                CPUI_INT_REM, 4, 100, 4, 7, 4, True, 2),
        ("REM: 除以0",                CPUI_INT_REM, 4, 42, 4, 0, 4, True, 0),

        # === 一元运算 ===
        ("NEG(2COMP): ~0+1 (32-bit)", CPUI_INT_2COMP, 4, 1, 4, 0, 0, False, 0xFFFFFFFF),
        ("NEG(2COMP): 0 (32-bit)",    CPUI_INT_2COMP, 4, 0, 4, 0, 0, False, 0),
        ("NEG(2COMP): -1 (64-bit)",   CPUI_INT_2COMP, 8, 1, 8, 0, 0, False, 0xFFFFFFFFFFFFFFFF),
        ("NOT(NEGATE): ~0 (32-bit)",  CPUI_INT_NEGATE, 4, 0, 4, 0, 0, False, 0xFFFFFFFF),
        ("NOT(NEGATE): ~1 (32-bit)",  CPUI_INT_NEGATE, 4, 1, 4, 0, 0, False, 0xFFFFFFFE),
        ("NOT(NEGATE): ~0 (64-bit)",  CPUI_INT_NEGATE, 8, 0, 8, 0, 0, False, 0xFFFFFFFFFFFFFFFF),

        # === 位运算 ===
        ("AND: 0xFF & 0x0F",          CPUI_INT_AND, 4, 0xFF, 4, 0x0F, 4, True, 0x0F),
        ("OR: 0xF0 | 0x0F",          CPUI_INT_OR, 4, 0xF0, 4, 0x0F, 4, True, 0xFF),
        ("XOR: 0xFF ^ 0xFF",         CPUI_INT_XOR, 4, 0xFF, 4, 0xFF, 4, True, 0),

        # === 移位 ===
        ("LEFT: 1<<31 (32-bit)",     CPUI_INT_LEFT, 4, 1, 4, 31, 4, True, 0x80000000),
        ("LEFT: 1<<32 (32-bit截断)", CPUI_INT_LEFT, 4, 1, 4, 32, 4, True, 0),  # 超出32位
        ("RIGHT: 0x80000000>>31",    CPUI_INT_RIGHT, 4, 0x80000000, 4, 31, 4, True, 1),
        ("SRIGHT: -4>>1 (32-bit)",   CPUI_INT_SRIGHT, 4, 0xFFFFFFFC, 4, 1, 4, True, 0xFFFFFFFE),

        # === 比较 ===
        ("EQUAL: 42==42",            CPUI_INT_EQUAL, 1, 42, 4, 42, 4, True, 1),
        ("EQUAL: 42==43",            CPUI_INT_EQUAL, 1, 42, 4, 43, 4, True, 0),
        ("NOTEQUAL: 1!=2",           CPUI_INT_NOTEQUAL, 1, 1, 4, 2, 4, True, 1),
        ("LESS: 1<2",               CPUI_INT_LESS, 1, 1, 4, 2, 4, True, 1),
        ("LESS: 2<1",               CPUI_INT_LESS, 1, 2, 4, 1, 4, True, 0),
        ("LESSEQUAL: 2<=2",         CPUI_INT_LESSEQUAL, 1, 2, 4, 2, 4, True, 1),
        ("SLESS: -1<0 (signed)",    CPUI_INT_SLESS, 1, 0xFFFFFFFF, 4, 0, 4, True, 1),
        ("SLESS: 0<-1 (signed)",    CPUI_INT_SLESS, 1, 0, 4, 0xFFFFFFFF, 4, True, 0),

        # === 扩展 ===
        ("ZEXT: 0xFF (1->4)",       CPUI_INT_ZEXT, 4, 0xFF, 1, 0, 0, False, 0xFF),
        ("SEXT: 0x80 (1->4)",       CPUI_INT_SEXT, 4, 0x80, 1, 0, 0, False, 0xFFFFFF80),
        ("SEXT: 0x7F (1->4)",       CPUI_INT_SEXT, 4, 0x7F, 1, 0, 0, False, 0x7F),
        ("SEXT: 0xFFFF (2->4)",     CPUI_INT_SEXT, 4, 0xFFFF, 2, 0, 0, False, 0xFFFFFFFF),
    ]

    for name, op, sout, v1, s1, v2, s2, has_v2, expected in test_cases:
        result = eval_const(op, sout, v1, s1, v2, s2, has_v2)
        if result == expected:
            status = "✅ PASS"
            passed += 1
        else:
            status = f"❌ FAIL (预期 {expected:x}, 实际 {result:x})"
            failed += 1
        print(f"{name:<30} | {result:<18x} | {status}")

    print("=" * 70)
    total = passed + failed
    print(f"总计: {total} 项, 通过: {passed}, 失败: {failed}")
    if failed > 0:
        print(f"⚠️  通过率: {passed/total*100:.1f}%")
        sys.exit(1)
    else:
        print("✅ 全部通过!")
        sys.exit(0)

if __name__ == "__main__":
    run_tests()
