import ctypes
import os
import sys

# P-code OpCodes (Ghidra standard)
CPUI_COPY = 1
CPUI_INT_ADD = 19
CPUI_INT_SUB = 20
CPUI_INT_XOR = 26

# Address Space IDs
SPACE_RAM = 0
SPACE_REGISTER = 1

class VarnodeFFI(ctypes.Structure):
    _fields_ = [
        ("space_id", ctypes.c_int32),
        ("offset", ctypes.c_uint64),
        ("size", ctypes.c_uint32)
    ]

def run_test():
    print("Rudra P-code Structural Comparison Test")
    print("=" * 50)

    # Load DLL
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(script_dir)
    dll_path_release = os.path.join(root_dir, "target", "release", "rudra.dll")
    dll_path_debug = os.path.join(root_dir, "target", "debug", "rudra.dll")

    if os.path.exists(dll_path_release):
        dll_path = dll_path_release
    elif os.path.exists(dll_path_debug):
        dll_path = dll_path_debug
    else:
        print(f"Error: Could not find rudra.dll in target/release or target/debug")
        return

    print(f"Loading Rudra library from: {dll_path}")
    try:
        lib = ctypes.CDLL(dll_path)
    except Exception as e:
        print(f"Failed to load DLL: {e}")
        return

    # Check for symbols (optional but helpful)
    if not hasattr(lib, "rudra_compare_pcode"):
        print("Error: rudra_compare_pcode not found in DLL. Did you run 'cargo build' after editing ffi.rs?")
        return

    # Configure signatures
    lib.rudra_compare_pcode.argtypes = [
        ctypes.c_uint64,               # op_addr
        ctypes.c_int32,                # opcode
        ctypes.POINTER(VarnodeFFI),    # out_vn
        ctypes.POINTER(VarnodeFFI),    # inputs
        ctypes.c_int32                 # input_count
    ]

    lib.rudra_add_test_op.argtypes = [
        ctypes.c_uint64, # addr
        ctypes.c_int32,  # opcode
        ctypes.c_int32,  # out_space
        ctypes.c_uint64, # out_offset
        ctypes.c_uint32  # out_size
    ]

    # --- Setup Test State ---
    print("[Step 1] Initializing Rudra test program...")
    lib.rudra_init_test_program()

    # Add an expected op in Rudra: 0x401000: RAX = INT_ADD(...)
    lib.rudra_add_test_op(0x401000, CPUI_INT_ADD, SPACE_REGISTER, 0, 8)

    # Add another op: 0x401008: RBX = COPY(...)
    lib.rudra_add_test_op(0x401008, CPUI_COPY, SPACE_REGISTER, 8, 8)

    print("[Step 2] Simulating Ghidra data feeding...")

    # Case 1: Exact Match (0x401000)
    print("\nCase A: Perfect Match (Expect NO diff output)")
    out_vn = VarnodeFFI(SPACE_REGISTER, 0, 8) # RAX
    lib.rudra_compare_pcode(0x401000, CPUI_INT_ADD, ctypes.byref(out_vn), None, 0)

    # Case 2: Opcode Mismatch
    print("\nCase B: Opcode Mismatch (Expect DIFF)")
    lib.rudra_compare_pcode(0x401000, CPUI_INT_SUB, ctypes.byref(out_vn), None, 0)

    # Case 3: Output Variable Mismatch
    print("\nCase C: Output Variable Mismatch (Expect DIFF)")
    wrong_out = VarnodeFFI(SPACE_REGISTER, 0x100, 8) # Wrong register offset
    lib.rudra_compare_pcode(0x401008, CPUI_COPY, ctypes.byref(wrong_out), None, 0)

    # Case 4: Missing Op in Rudra
    print("\nCase D: Missing Instruction in Rudra (Expect DIFF)")
    lib.rudra_compare_pcode(0x402000, CPUI_INT_XOR, None, None, 0)

    print("\n" + "=" * 50)
    print("Test complete. Check console for [RUDRA DIFF] logs.")

if __name__ == "__main__":
    run_test()
