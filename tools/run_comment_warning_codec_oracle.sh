#!/usr/bin/env bash
# Locked COMMENT-WARNING-CODEC-0001 bilateral oracle runner.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=cb43401df869f5771f2c1acadc53de102773b4d9
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/comment_warning_codec_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/comment_warning_codec_1204.cc"
rust_fixture="$repo_root/tests/oracle/comment_warning_codec_1204.rs"
comment_source="$repo_root/src/comment.rs"
api_document="$repo_root/docs/api/comment.md"
runner="$repo_root/tools/run_comment_warning_codec_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rudra-comment-warning-codec-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-comment-warning-codec-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# Freeze the Rudra comparand at the recorded base and overlay only this task's
# owned source. Freeze the oracle directly from the locked Ghidra commit.
rudra_workspace="$oracle_tmp/rudra"
mkdir -p "$rudra_workspace" "$oracle_tmp/ghidra"
git -C "$repo_root" archive "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  | tar -x -C "$rudra_workspace"
cp -- "$comment_source" "$rudra_workspace/src/comment.rs"
git -C "$ghidra_root" archive "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  | tar -x -C "$oracle_tmp/ghidra"
mkdir -p "$rudra_workspace/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp" \
  "$rudra_workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
snapshot_cpp="$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$comment_source" "$api_document" "$runner" "$repo_root/Cargo.lock" \
  "$ghidra_root" "$oracle_commit" "$oracle_tag" "$rudra_base_commit" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name, cpp_name, rust_name, source_name, docs_name, runner_name,
    lock_name, ghidra_root_name, oracle_commit, oracle_tag, rudra_base_commit,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["oracle"] != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if metadata["rugra_base_commit"] != rudra_base_commit:
    raise SystemExit("metadata Rudra base mismatch")
if metadata["projection_status"] != "MATCH" or metadata["overall_status"] != "MISMATCH":
    raise SystemExit("fixture status must remain projection MATCH / overall MISMATCH")
for field in ("architecture", "compiler_spec", "analysis_options", "input_manifest"):
    if not metadata.get(field):
        raise SystemExit(f"missing oracle descriptor: {field}")
cpp_tree = subprocess.check_output([
    "git", "-C", ghidra_root_name, "rev-parse",
    f"{oracle_commit}:Ghidra/Features/Decompiler/src/decompile/cpp",
], text=True).strip()
if cpp_tree != metadata["comparand_sha256"]["ghidra_cpp_tree"]:
    raise SystemExit("locked Ghidra C++ tree mismatch")
paths = {
    "cpp_fixture": pathlib.Path(cpp_name),
    "rust_fixture": pathlib.Path(rust_name),
    "rugra_comment_source": pathlib.Path(source_name),
    "api_document": pathlib.Path(docs_name),
    "runner": pathlib.Path(runner_name),
    "cargo_lock": pathlib.Path(lock_name),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand_sha256"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: metadata={expected} actual={actual}")
payload = json.dumps(
    metadata["input_manifest"]["cases"],
    sort_keys=True, separators=(",", ":"), ensure_ascii=False,
).encode()
actual_input = "sha256:" + hashlib.sha256(payload).hexdigest()
if metadata["input_manifest"]["fingerprint"] != actual_input:
    raise SystemExit("input manifest fingerprint mismatch")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$snapshot_cpp" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$snapshot_cpp" "$cpp_fixture" \
  "$snapshot_cpp/libdecomp.a" -lz \
  -o "$oracle_tmp/comment_warning_codec_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$rudra_workspace/Cargo.toml" --lib
CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo test --offline --locked --quiet --manifest-path "$rudra_workspace/Cargo.toml" \
  --lib comment::tests:: >"$oracle_tmp/comment-tests.stdout"
grep -Fq 'test result: ok.' "$oracle_tmp/comment-tests.stdout"
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/comment_warning_codec_rust"

set +e
"$oracle_tmp/comment_warning_codec_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/comment_warning_codec_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
set -e
if [[ "$ghidra_status" -ne 0 || -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture failed or emitted runtime diagnostics" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if [[ "$rudra_status" -ne 0 || -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture failed or emitted runtime diagnostics" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 6
test "$(wc -l < "$oracle_tmp/rudra.stdout")" -eq 6
grep -Fxq 'schema=1|fixture=COMMENT-WARNING-CODEC-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b' "$oracle_tmp/ghidra.stdout"
grep -Fq 'case=roundtrip|schema=1|duplicate=0|inserted=1|comments=[8:4096:4096:0:Header;16:4096:8192:0:Test warning;16:4096:8192:1:Second warning;2:4096:8192:2:User note]' "$oracle_tmp/ghidra.stdout"
grep -Fq 'case=filter|f1000=[8:4096:4096:1:Header;2:4096:12288:0:User note]|f5000=[16:20480:24576:0:Other warning]' "$oracle_tmp/ghidra.stdout"
grep -Fq 'case=unknown_type|error=Unknown comment type: bogus|type=0|emitted=0|func=43690|addr=48059|uniq=7|text=sentinel' "$oracle_tmp/ghidra.stdout"
grep -Fq 'case=missing_offset|error=Address is missing offset|type=16|emitted=0|func=43690|addr=48059|uniq=7|text=sentinel' "$oracle_tmp/ghidra.stdout"
grep -Fq 'case=unknown_property_encode|error=Unknown comment type|stream_empty=1|type=64|emitted=1|func=43690|addr=48059|uniq=7|text=sentinel' "$oracle_tmp/ghidra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if actual != metadata["expected_stdout_sha256"]:
    raise SystemExit(
        f"oracle stdout hash mismatch: metadata={metadata['expected_stdout_sha256']} actual={actual}"
    )
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'comment_warning_codec_1204: projection=MATCH overall=MISMATCH\n'
