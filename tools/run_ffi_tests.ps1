$ErrorActionPreference = "Stop"

Write-Host "========================================="
Write-Host "   Rudra FFI Alignment Verification Suite  "
Write-Host "========================================="

Write-Host "`n[1/3] Compiling Rudra DLL..."
cargo build --features ffi-test
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed"
    exit 1
}
Write-Host "Build successful."

Write-Host "`n[2/3] Running Constant Evaluation Baseline..."
python tools/ffi_test.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "ffi_test.py failed"
    exit 1
}

Write-Host "`n[3/3] Running P-code Structural Comparison..."
python tools/pcode_compare_test.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "pcode_compare_test.py failed"
    exit 1
}

Write-Host "`n========================================="
Write-Host " All FFI Alignment Tests Passed! `n"
Write-Host "========================================="
