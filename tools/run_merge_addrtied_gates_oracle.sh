#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_merge_addrtied_gates_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
HOME=$user_home
export HOME

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=8c223a9623d6833319564776c35c5d4c50b17b95
ghidra_root="$repo_root/ghidra"
metadata_live="$repo_root/tests/oracle/merge_addrtied_gates_1204.metadata.json"
cache_root="$HOME/.cache"
/usr/bin/mkdir -p "$cache_root"
run_tmp=$(/usr/bin/mktemp -d "$cache_root/rudra-merge-addrtied-gates.XXXXXX")
/usr/bin/mkdir -p "$run_tmp/tmp"
cleanup() {
  case "$run_tmp" in
    "$cache_root"/rudra-merge-addrtied-gates.??????)
      /usr/bin/rm -rf -- "$run_tmp"
      ;;
    *)
      echo "refusing unsafe cleanup target: $run_tmp" >&2
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for tool in /usr/bin/git /usr/bin/python3 /usr/bin/g++ /usr/bin/gcc \
    /usr/bin/ar /usr/bin/make /usr/bin/cargo /usr/bin/rustc /usr/bin/flock; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

# Snapshot every mutable comparand once. The runner is read through its
# already-open descriptor, so a concurrent edit cannot change this execution.
/usr/bin/mkdir -p "$run_tmp/candidate"
for candidate in \
    tests/oracle/merge_addrtied_gates_1204.metadata.json \
    tests/oracle/merge_addrtied_gates_1204.cc \
    tests/oracle/merge_addrtied_gates_1204.rs \
    src/merge.rs Cargo.toml Cargo.lock build.rs; do
  /usr/bin/cp -- "$repo_root/$candidate" "$run_tmp/candidate/$(/usr/bin/basename "$candidate")"
done
metadata="$run_tmp/candidate/merge_addrtied_gates_1204.metadata.json"
cpp_fixture="$run_tmp/candidate/merge_addrtied_gates_1204.cc"
rust_fixture="$run_tmp/candidate/merge_addrtied_gates_1204.rs"
merge_source="$run_tmp/candidate/merge.rs"
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

actual_oracle=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -C "$ghidra_root" rev-parse HEAD)
tag_oracle=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_oracle" != "$oracle_commit" || "$tag_oracle" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    /usr/bin/git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$merge_source" "$runner_fd_path" \
  "$runner_sha" "$repo_root" "$ghidra_root" "$oracle_commit" "$oracle_tag" \
  "$rudra_base_commit" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(metadata_name, cpp_name, rust_name, merge_name, runner_name, runner_sha,
 repo_name, ghidra_name, oracle_commit, oracle_tag, base_commit) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit or metadata["oracle"]["tag"] != oracle_tag:
    raise SystemExit("metadata oracle identity mismatch")
if metadata["rugra"]["base_commit"] != base_commit:
    raise SystemExit("metadata Rudra base mismatch")
if metadata["overall_status"] != "MISMATCH":
    raise SystemExit("mergeAddrTied must remain MISMATCH while residuals are open")
if metadata["coverage"]["covered_projection"] != "MATCH":
    raise SystemExit("covered projection must be MATCH")
for key in ("architecture", "compiler_spec", "analysis_options", "input_manifest", "residuals"):
    if not metadata.get(key):
        raise SystemExit(f"missing oracle descriptor: {key}")

paths = {
    "cpp_fixture_sha256": pathlib.Path(cpp_name),
    "rust_fixture_sha256": pathlib.Path(rust_name),
    "merge_rs_sha256": pathlib.Path(merge_name),
    "runner_sha256": pathlib.Path(runner_name),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata["comparand"][key] != actual:
        raise SystemExit(f"comparand hash mismatch for {key}: {actual}")
if metadata["comparand"]["runner_sha256"] != runner_sha:
    raise SystemExit("immutable runner snapshot hash mismatch")

descriptor = json.dumps(metadata["input_manifest"]["descriptor"], sort_keys=True,
                        separators=(",", ":"), ensure_ascii=False).encode()
if hashlib.sha256(descriptor).hexdigest() != metadata["input_manifest"]["sha256"]:
    raise SystemExit("input manifest fingerprint mismatch")

repo = pathlib.Path(repo_name)
ghidra = pathlib.Path(ghidra_name)
git = "/usr/bin/git"
base_tree = subprocess.check_output([git, "-C", str(repo), "rev-parse",
    f"{base_commit}^{{tree}}"], text=True).strip()
if base_tree != metadata["rugra"]["base_tree"]:
    raise SystemExit("Rudra base tree mismatch")
for path, expected in metadata["rugra"]["base_blobs"].items():
    actual = subprocess.check_output([git, "-C", str(repo), "rev-parse",
        f"{base_commit}:{path}"], text=True).strip()
    if actual != expected:
        raise SystemExit(f"Rudra base blob mismatch: {path}")
cpp_tree = subprocess.check_output([git, "-C", str(ghidra), "rev-parse",
    f"{oracle_commit}:Ghidra/Features/Decompiler/src/decompile/cpp"], text=True).strip()
if cpp_tree != metadata["oracle"]["decompiler_cpp_tree"]:
    raise SystemExit("Ghidra C++ tree mismatch")
for path, expected in metadata["oracle"]["source_blobs"].items():
    actual = subprocess.check_output([git, "-C", str(ghidra), "rev-parse",
        f"{oracle_commit}:Ghidra/Features/Decompiler/src/decompile/cpp/{path}"],
        text=True).strip()
    if actual != expected:
        raise SystemExit(f"Ghidra source blob mismatch: {path}")

versions = {
    "cxx": subprocess.check_output(["/usr/bin/g++", "--version"], text=True).splitlines()[0],
    "rustc": subprocess.check_output(["/usr/bin/rustc", "--version"], text=True).strip(),
    "cargo": subprocess.check_output(["/usr/bin/cargo", "--version"], text=True).strip(),
}
if versions != metadata["toolchain"]["versions"]:
    raise SystemExit(f"toolchain version drift: {versions}")
PY

# Recreate both codebases from immutable Git objects. Only the leased
# candidate src/merge.rs is overlaid on the pinned Rudra base.
/usr/bin/mkdir -p "$run_tmp/ghidra" "$run_tmp/rudra"
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -C "$ghidra_root" archive --format=tar "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/tar -x -C "$run_tmp/ghidra"
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -C "$repo_root" archive --format=tar "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs | \
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/tar -x -C "$run_tmp/rudra"
/usr/bin/cp -- "$merge_source" "$run_tmp/rudra/src/merge.rs"
/usr/bin/mkdir -p "$run_tmp/rudra/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$run_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp" \
  "$run_tmp/rudra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
oracle_cpp="$run_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$run_tmp/tmp" \
  /usr/bin/make --silent -C "$oracle_cpp" -j 4 CXX="/usr/bin/g++ -std=c++11" \
  EXTRA= libdecomp.a
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$run_tmp/tmp" /usr/bin/g++ \
  -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" -lz \
  -o "$run_tmp/merge_addrtied_cpp"

# The Cargo build is the only step holding the shared lock. The runner,
# Ghidra build, rustc fixture link, executions, and validation are not locked.
/usr/bin/flock -x /tmp/rudra-cargo-build.lock \
  /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
  TMPDIR="$run_tmp/tmp" \
  CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  CARGO_TARGET_DIR="$run_tmp/cargo-target" CXX=/usr/bin/g++ CC=/usr/bin/gcc \
  AR=/usr/bin/ar RUSTC=/usr/bin/rustc \
  /usr/bin/cargo build --offline --locked --quiet --lib \
  --manifest-path "$run_tmp/rudra/Cargo.toml"

rudra_rlib="$run_tmp/cargo-target/debug/librudra.rlib"
native_archive=$(/usr/bin/find "$run_tmp/cargo-target/debug/build" \
  -path '*/out/librudra_sleigh.a' -print -quit)
if [[ ! -f "$rudra_rlib" || ! -f "$native_archive" ]]; then
  echo "isolated Rudra build did not produce required libraries" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")
/usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
  TMPDIR="$run_tmp/tmp" \
  /usr/bin/rustc --edition=2021 -O \
  -L "dependency=$run_tmp/cargo-target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m "$rust_fixture" -o "$run_tmp/merge_addrtied_rust"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$run_tmp/merge_addrtied_cpp" \
  >"$run_tmp/ghidra.stdout" 2>"$run_tmp/ghidra.stderr"
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$run_tmp/merge_addrtied_rust" \
  >"$run_tmp/rudra.stdout" 2>"$run_tmp/rudra.stderr"
test ! -s "$run_tmp/ghidra.stderr"
test ! -s "$run_tmp/rudra.stderr"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -S - \
  "$metadata" "$run_tmp/ghidra.stdout" "$run_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
if len(ghidra.splitlines()) != 8 or len(rudra.splitlines()) != 8:
    raise SystemExit("fixture must emit exactly 8 lines per side")
for side, payload in (("ghidra", ghidra), ("rugra", rudra)):
    actual = hashlib.sha256(payload).hexdigest()
    expected = metadata["comparand"][f"expected_{side}_stdout_sha256"]
    if actual != expected:
        raise SystemExit(f"{side} stdout fingerprint drift: {actual}")
if ghidra != rudra:
    raise SystemExit("covered projection is not byte-identical")
text = ghidra.decode("utf-8")
required = (
    "case=space_type_gate|stage=after|error=none",
    "case=addrtied_first_member_gate|stage=after|error=none",
    "case=transitive_overlap_group|stage=after|error=none",
    "case=forced_implied_error|stage=after|error=Cannot force merge of range",
    "AI[AI,A0,A1]",
    "[0:8:A0,4:8:B0,10:2:C0]",
)
for token in required:
    if token not in text:
        raise SystemExit(f"missing decisive observation: {token}")
print("merge_addrtied_gates_1204: covered_projection=8/8 byte-identical")
print("overall_status=MISMATCH (see metadata residuals; scoped MATCH only)")
PY

/usr/bin/cat "$run_tmp/ghidra.stdout"
