# Ghidra Python script to export decompiled code
# @category Export

import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    # Setup decompiler
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    # Output file path
    output_path = r"D:\ghidra\rudra\ghidra_curl.c"

    print("Exporting decompiled code to: " + output_path)

    try:
        with open(output_path, "w") as f:
            # Iterate over all functions
            func_iter = currentProgram.getFunctionManager().getFunctions(True)
            for func in func_iter:
                # Decompile
                # timeout = 60 seconds
                res = decomp.decompileFunction(func, 60, monitor)

                if res.decompileCompleted():
                    c_code = res.getDecompiledFunction().getC()

                    # Write header
                    f.write("\n// Function: {} at {}\n".format(func.getName(), func.getEntryPoint()))
                    f.write(c_code)
                    f.write("\n")
                else:
                    f.write("// Failed to decompile function: {}\n".format(func.getName()))

        print("Export completed successfully.")

    except Exception as e:
        print("Error writing file: " + str(e))

if __name__ == "__main__":
    run()
