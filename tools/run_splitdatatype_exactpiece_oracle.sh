#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
# Locked bilateral runner for SPLITDATATYPE-EXACTPIECE-0001.
#
# Single mode. Verifies the locked Ghidra oracle identity, rebuilds the C++
# fixture from an archived cpp tree, materializes the frozen Rudra production
# commit as a git archive (no live Rust source is read by Cargo), links the
# standalone Rust fixture against that archive's Cargo-built artifacts, runs
# both sides, and requires the pinned 31-record byte-identical projection:
#
#   gv*     SplitDatatype::getValueDatatype            subflow.cc:2910-2938
#          (canonical TypeFactory::getExactPiece, type.cc:4090-4117)
#   split* SplitDatatype::splitCopy/splitStore/splitLoad gates
#                                                  subflow.cc:2717/2808/2756
#   apply* RuleSplitStore/RuleSplitLoad::applyOp   subflow.cc:2970-3004
#   stab*  second sweep over every op (rule-repeatapply stability)
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
runner="$repo_root/tools/run_splitdatatype_exactpiece_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

if [[ $# -ne 0 ]]; then
  echo "usage: $runner (no arguments)" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root=$(/usr/bin/readlink -f "$repo_root/ghidra")
metadata="$repo_root/tests/oracle/splitdatatype_exactpiece_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/splitdatatype_exactpiece_1204.cc"
rust_fixture="$repo_root/tests/oracle/splitdatatype_exactpiece_1204.rs"

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi

host_cxx=$(/usr/bin/readlink -f /usr/bin/g++)
host_make=$(/usr/bin/readlink -f /usr/bin/make)
host_git=$(/usr/bin/readlink -f /usr/bin/git)
host_python=$(/usr/bin/readlink -f /usr/bin/python3)
host_cargo=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc=$(/usr/bin/readlink -f /usr/bin/rustc)
host_tar=$(/usr/bin/readlink -f /usr/bin/tar)
expected_cargo_sha=131c52b36a4aa4016a1c5e8478ed232a349f2e2d5a9fc4110f3f69f2d61b9e93
expected_rustc_sha=060916a7ed17951343fb461ad068179a56a33eb675910f1d7d7ab738fed3b618
expected_cxx_sha=f04191f6a7b2cd7d9a62e1745872b8a6088791e5af6955488c69c9b2c4668bc9
expected_cargo_vv_sha=62d278ffb732aa9b6ac09108cbcea47dd24d6221c5c63f6d942784ca419cb9fc
expected_rustc_vv_sha=3b56b3021e5f91088c797c1d6ba31cc6e4a2170670446d47f883b91407e66768
expected_cxx_v_sha=ddba3d014b73deb2a8869cad4ab507e29a48630c8cd280adf2559e0e10891d23
for tool in "$host_cxx" "$host_make" "$host_git" "$host_python" \
  "$host_cargo" "$host_rustc" "$host_tar" /usr/bin/flock; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
verify_tool() {
  local label=$1 tool=$2 path=$3 sha=$4 vsha=$5; shift 5
  if [[ "$tool" != "$path" ]]; then
    echo "pinned $label path mismatch: expected=$path actual=$tool" >&2
    exit 1
  fi
  if [[ "$(/usr/bin/sha256sum "$tool" | /usr/bin/awk '{print $1}')" != "$sha" ]]; then
    echo "pinned $label executable hash mismatch" >&2
    exit 1
  fi
  local actual
  actual=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$tool" "$@" | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
  if [[ "$actual" != "$vsha" ]]; then
    echo "pinned $label version output mismatch" >&2
    exit 1
  fi
}
verify_tool cargo "$host_cargo" /usr/bin/cargo "$expected_cargo_sha" "$expected_cargo_vv_sha" --version --verbose
verify_tool rustc "$host_rustc" /usr/bin/rustc "$expected_rustc_sha" "$expected_rustc_vv_sha" --version --verbose
verify_tool g++ "$host_cxx" /usr/bin/g++ "$expected_cxx_sha" "$expected_cxx_v_sha" --version

for file in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$file" || -L "$file" ]]; then
    echo "required input is not a regular non-symlink file: $file" >&2
    exit 1
  fi
done

actual_oracle=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse HEAD)
actual_tag=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_oracle" != "$oracle_commit" || "$actual_tag" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" diff --cached --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi

work_root=/home/wirs/.cache/rudra-splitdatatype-exactpiece
/usr/bin/mkdir -p "$work_root"
oracle_tmp=$(/usr/bin/mktemp -d "$work_root/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    /home/wirs/.cache/rudra-splitdatatype-exactpiece/run.??????)
      /usr/bin/rm -rf -- "$oracle_tmp"
      ;;
    *)
      echo "refusing unsafe cleanup target: $oracle_tmp" >&2
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" "$runner_sha" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$repo_root" <<'PY'
import hashlib, json, pathlib, re, sys

(
    metadata_path, cpp_path, rust_path, runner_path, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, repo_raw,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
metadata = json.loads(pathlib.Path(metadata_path).read_text(encoding="utf-8"))

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, label):
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise SystemExit(f"{label} is still pending: {value}")

require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle cpp tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)

expected_runner_key = "runner_sha256"
comparand = metadata["comparand"]
live = {
    "cpp_fixture_sha256": pathlib.Path(cpp_path),
    "rust_fixture_sha256": pathlib.Path(rust_path),
    "runner_sha256": pathlib.Path(runner_path),
    "subflow_rs_sha256": repo / "src/subflow.rs",
    "subflow_doc_sha256": repo / "docs/api/subflow.md",
    "datatype_rs_sha256": repo / "src/type_system/datatype.rs",
    "datatype_doc_sha256": repo / "docs/api/type_system/datatype.md",
    "cargo_toml_sha256": repo / "Cargo.toml",
    "cargo_lock_sha256": repo / "Cargo.lock",
    "build_rs_sha256": repo / "build.rs",
}
for key, path in live.items():
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"comparand input must be a regular file: {path}")
    reject_pending(comparand[key], f"comparand.{key}")
    require(key, hashlib.sha256(path.read_bytes()).hexdigest(), comparand[key])
require("runner fd hash", runner_sha, comparand["runner_sha256"])

require("fixture id", metadata["fixture_id"], "SPLITDATATYPE-EXACTPIECE-0001")

candidate = metadata["rugra_candidate"]
reject_pending(candidate["commit"], "rudra_candidate.commit")
reject_pending(candidate["tree"], "rudra_candidate.tree")
if re.fullmatch(r"[0-9a-f]{40}", candidate["commit"]) is None or \
   re.fullmatch(r"[0-9a-f]{40}", candidate["tree"]) is None:
    raise SystemExit("rudra_candidate commit/tree are not git oids")
critical = candidate["critical_git_blobs"]
expected_critical = {
    "src/subflow.rs", "src/type_system/datatype.rs",
    "Cargo.toml", "Cargo.lock", "build.rs",
}
if set(critical) != expected_critical:
    raise SystemExit(f"critical blob path set drift: {sorted(critical)}")
for path, blob in critical.items():
    reject_pending(blob, f"critical blob {path}")
    if re.fullmatch(r"[0-9a-f]{40}", blob) is None:
        raise SystemExit(f"critical blob is not a git oid: {path}")

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
reject_pending(manifest["sha256"], "input_manifest.sha256")
require("input manifest sha256", hashlib.sha256(canonical).hexdigest(), manifest["sha256"])
if len(manifest["cases"]) != 31:
    raise SystemExit("input manifest must hold 25 cases")

for key in ("expected_ghidra_stdout_sha256", "expected_rudra_stdout_sha256"):
    reject_pending(metadata[key], key)
for key in metadata["expected_lines"]:
    if not isinstance(key, str) or "|" not in key:
        raise SystemExit("expected lines must be record strings")
if len(metadata["expected_lines"]) != 31:
    raise SystemExit("expected lines must hold 31 records")

crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-splitdatatype-exactpiece-lib-snapshot-v1\0")

def snapshot(relative):
    source = repo / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular file: {relative}")
    return source.read_bytes()

def source_files(directory):
    root = repo / directory
    result = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SystemExit(f"source snapshot rejects symlink: {path}")
        if path.is_file():
            result.append(path.relative_to(repo).as_posix())
    return sorted(result)

crate_files = ["Cargo.toml", "Cargo.lock", "build.rs"] \
    + source_files("src") + source_files("sleigh_shim")
crate_files = sorted(set(crate_files))
for relative in crate_files:
    data = snapshot(relative)
    encoded = relative.encode("utf-8")
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)
require(
    "crate snapshot scheme", comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-splitdatatype-exactpiece-lib-snapshot-v1 plus sorted length-prefixed relative paths and contents",
)
reject_pending(comparand["rust_crate_tree_sha256"], "comparand.rust_crate_tree_sha256")
require(
    "rust crate tree sha256",
    crate_hasher.hexdigest(),
    comparand["rust_crate_tree_sha256"],
)
print("metadata_pins_ok")
PY

candidate_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S -c \
  "import json,sys;print(json.load(open(sys.argv[1]))['rudra_candidate']['commit'])" "$metadata")
candidate_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S -c \
  "import json,sys;print(json.load(open(sys.argv[1]))['rudra_candidate']['tree'])" "$metadata")

actual_candidate=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" rev-parse "$candidate_commit^{commit}")
actual_candidate_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" rev-parse "$candidate_commit^{tree}")
if [[ "$actual_candidate" != "$candidate_commit" || \
      "$actual_candidate_tree" != "$candidate_tree" ]]; then
  echo "frozen Rudra candidate identity mismatch" >&2
  exit 1
fi
while IFS=: read -r blob_path blob_id; do
  actual_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" rev-parse "$candidate_commit:$blob_path")
  if [[ "$actual_blob" != "$blob_id" ]]; then
    echo "frozen candidate blob mismatch: $blob_path" >&2
    exit 1
  fi
done < <(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S -c \
  "import json,sys;[print(f'{k}:{v}') for k,v in json.load(open(sys.argv[1]))['rudra_candidate']['critical_git_blobs'].items()]" "$metadata")

oracle_source_root="$oracle_tmp/ghidra-source"
/usr/bin/mkdir -p "$oracle_source_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_tar" -xf - \
  -C "$oracle_source_root"
oracle_cpp="$oracle_source_root/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
compiler_tmp="$oracle_tmp/tmp"
/usr/bin/mkdir -p "$compiler_tmp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$compiler_tmp" \
  "$host_make" --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$host_cxx -std=c++11" EXTRA= libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$compiler_tmp" "$host_cxx" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" -Wl,--whole-archive "$oracle_cpp/libdecomp.a" \
  -Wl,--no-whole-archive -lz -o "$oracle_tmp/splitdatatype_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/splitdatatype_cpp" >"$oracle_tmp/ghidra.stdout" \
  2>"$oracle_tmp/ghidra.stderr"; then
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

candidate_root="$oracle_tmp/rudra-candidate"
/usr/bin/mkdir -p "$candidate_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" archive --format=tar "$candidate_commit" | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_tar" -xf - -C "$candidate_root"
if [[ -e "$candidate_root/ghidra" || -L "$candidate_root/ghidra" ]]; then
  echo "candidate archive unexpectedly contains ghidra path" >&2
  exit 1
fi
/usr/bin/ln -s "$oracle_source_root" "$candidate_root/ghidra"

cargo_home="$user_home/.cargo"
if [[ ! -d "$cargo_home" || -L "$cargo_home" ]]; then
  echo "Cargo home is not a regular non-symlink directory: $cargo_home" >&2
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$candidate_root" "$cargo_home" <<'PY'
import pathlib, sys
candidate = pathlib.Path(sys.argv[1]).resolve(strict=True)
cargo_home = pathlib.Path(sys.argv[2])
if cargo_home.is_symlink() or not cargo_home.is_dir():
    raise SystemExit(f"Cargo home is not a regular directory: {cargo_home}")
cargo_home = cargo_home.resolve(strict=True)
config_paths = {cargo_home / "config", cargo_home / "config.toml"}
for directory in (candidate, *candidate.parents):
    config_paths.add(directory / ".cargo" / "config")
    config_paths.add(directory / ".cargo" / "config.toml")
present = sorted(str(p) for p in config_paths if p.exists() or p.is_symlink())
if present:
    raise SystemExit("Cargo config discovery is forbidden for this fixture: " + ", ".join(present))
PY

cargo_target="$oracle_tmp/cargo-target"
/usr/bin/mkdir -p "$cargo_target"
if ! (
  builtin cd "$candidate_root"
  /usr/bin/flock /tmp/rudra-cargo-build.lock /usr/bin/env -i \
    HOME="$user_home" CARGO_HOME="$cargo_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
    CARGO_NET_OFFLINE=true TMPDIR="$compiler_tmp" \
    RUSTC="$host_rustc" CXX="$host_cxx" \
    "$host_cargo" build --quiet --offline --locked --lib \
    --manifest-path "$candidate_root/Cargo.toml"
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$cargo_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" ]]; then
  echo "cargo build did not produce a regular $rudra_rlib" >&2
  exit 1
fi
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$cargo_target/debug/build" -path '*/out/librudra_sleigh.a' -type f
)
if [[ "${#native_archives[@]}" -ne 1 ]]; then
  echo "expected one Cargo-built librudra_sleigh.a, found ${#native_archives[@]}" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$compiler_tmp" "$host_rustc" --edition=2021 -O -Awarnings \
  -L "dependency=$cargo_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/splitdatatype_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/splitdatatype_rust" >"$oracle_tmp/rudra.stdout" \
  2>"$oracle_tmp/rudra.stderr"; then
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  >"$oracle_tmp/direct.diff"
diff_status=$?
set -e
if [[ "$diff_status" -ne 0 ]]; then
  echo "expected byte-identical split-datatype observations, diff exit=$diff_status" >&2
  /usr/bin/cat "$oracle_tmp/direct.diff" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib, json, pathlib, sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
outputs = {}
for label, path in (("Ghidra", sys.argv[2]), ("Rudra", sys.argv[3])):
    outputs[label] = pathlib.Path(path).read_bytes()
expected_lines = metadata["expected_lines"]
for label, raw in outputs.items():
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 31:
        raise SystemExit(f"expected 31 {label} records, found {len(lines)}")
    if lines != expected_lines:
        raise SystemExit(f"{label} records are not the exact pinned lines: {lines!r}")
for label, key in (("Ghidra", "expected_ghidra_stdout_sha256"),
                   ("Rudra", "expected_rudra_stdout_sha256")):
    actual = hashlib.sha256(outputs[label]).hexdigest()
    if actual != metadata[key]:
        raise SystemExit(f"{label} stdout hash mismatch: expected={metadata[key]} actual={actual}")
print("records=31 bilateral=byte-identical")
PY

/usr/bin/printf 'splitdatatype_exactpiece_1204: MATCH records=31 gv=7 split=10 apply=13 stab=1 oracle=%s candidate=%s\n' \
  "$oracle_commit" "$candidate_commit"
