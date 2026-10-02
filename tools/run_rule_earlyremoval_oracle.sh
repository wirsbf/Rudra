#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# Locked bilateral gate for RULE-PORT-EARLYREMOVAL-0001.  `--capture-pins`
# is a development-only readout for replacing PENDING_* metadata after the
# main writer freezes the three source overlays.  Normal and --validate-only
# modes reject every pending pin.

runner_fd=/proc/$$/fd/3
if [[ "${BASH_SOURCE[0]}" != "$runner_fd" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd")
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_rule_earlyremoval_oracle.sh"
if [[ "$runner_source" != "$runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner identity mismatch" >&2
  exit 1
fi
if [[ "$(/usr/bin/stat -Lc '%a' "$runner_fd")" != 755 ]]; then
  echo "runner must have mode 755" >&2
  exit 1
fi

mode=both
if [[ $# -eq 1 && "$1" == --validate-only ]]; then
  mode=validate
elif [[ $# -eq 1 && "$1" == --capture-pins ]]; then
  mode=capture
elif [[ $# -ne 0 ]]; then
  echo "usage: $runner [--validate-only|--capture-pins]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=7e91aef6aa28cbf0a77b9812858c276cafa7fbd3
rudra_base_tree=fd155bc4dd996000d3012c2d49f7244c3a6308ec
rudra_base_src_tree=c6a2eb0fb690ff9ac693d12d6ea45b606bc713ae
rudra_base_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_base_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_base_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
input_commit=34a3febff160031c265cfbd841a94022c68c2c19
input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/rule_earlyremoval_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/rule_earlyremoval_1204.cc"
rust_fixture="$repo_root/tests/oracle/rule_earlyremoval_1204.rs"
ruleaction_overlay="$repo_root/src/ruleaction.rs"
heritage_overlay="$repo_root/src/heritage.rs"
space_overlay="$repo_root/src/space.rs"
varnode_overlay="$repo_root/src/varnode.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

host_cxx=/usr/bin/g++
host_cc=/usr/bin/gcc
host_ar=/usr/bin/ar
host_make=/usr/bin/make
host_git=/usr/bin/git
host_python=/usr/bin/python3
host_cargo=/usr/bin/cargo
host_rustc=/usr/bin/rustc
host_timeout=/usr/bin/timeout
for tool in "$host_cxx" "$host_cc" "$host_ar" "$host_make" "$host_git" \
  "$host_python" "$host_cargo" "$host_rustc" "$host_timeout" /usr/bin/flock; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$ruleaction_overlay" \
  "$heritage_overlay" "$space_overlay" "$varnode_overlay" "$bfd_header" \
  "$bfd_library" "$runner"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required input is not a regular non-symlink file: $input" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git" -C "$ghidra_root" diff --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp \
      Ghidra/Processors/x86/data/languages || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git" -C "$ghidra_root" diff --cached --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp \
      Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra oracle source is dirty" >&2
  exit 1
fi

for binding in \
  "$rudra_base_commit^{commit}:$rudra_base_commit" \
  "$rudra_base_commit^{tree}:$rudra_base_tree" \
  "$rudra_base_commit:src:$rudra_base_src_tree" \
  "$rudra_base_commit:Cargo.toml:$rudra_base_cargo_toml_blob" \
  "$rudra_base_commit:Cargo.lock:$rudra_base_cargo_lock_blob" \
  "$rudra_base_commit:build.rs:$rudra_base_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra base mismatch: $expression" >&2
    exit 1
  fi
done
resolved_input_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$input_commit^{commit}")
resolved_input_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$input_commit:examples/curl")
if [[ "$resolved_input_commit" != "$input_commit" || \
      "$resolved_input_blob" != "$input_blob" ]]; then
  echo "pinned input identity mismatch" >&2
  exit 1
fi

runner_sha=$(/usr/bin/sha256sum "$runner_fd" | /usr/bin/awk '{print $1}')
"$host_python" -I -S - "$repo_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$runner_fd" "$runner_sha" "$ruleaction_overlay" \
  "$heritage_overlay" "$space_overlay" "$varnode_overlay" "$mode" \
  "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$rudra_base_src_tree" "$rudra_base_cargo_toml_blob" \
  "$rudra_base_cargo_lock_blob" "$rudra_base_build_rs_blob" \
  "$input_commit" "$input_blob" "$bfd_header" "$bfd_library" \
  "$host_cxx" "$host_rustc" "$host_cargo" <<'PYVALIDATE'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, runner_raw, runner_sha,
    ruleaction_raw, heritage_raw, space_raw, varnode_raw, mode, oracle_tag, oracle_commit,
    cpp_tree, language_tree, makefile_blob, base_commit, base_tree,
    base_src_tree, cargo_toml_blob, cargo_lock_blob, build_rs_blob,
    input_commit, input_blob, bfd_header_raw, bfd_library_raw, host_cxx,
    host_rustc, host_cargo,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
capture = mode == "capture"

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def pinned(label, expected, actual):
    if isinstance(expected, str) and expected.startswith("PENDING_"):
        if capture:
            print(f"PIN {label}={actual}")
            return
        raise SystemExit(f"{label} is not pinned; actual={actual}")
    require(label, actual, expected)

require("schema", metadata["schema_version"], 2)
require("fixture id", metadata["fixture_id"], "RULE-PORT-EARLYREMOVAL-0001")
require("covered status", metadata["covered_projection_status"], "MATCH")
require("overall status", metadata["overall_status"], "MISMATCH")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", oracle["x86_language_tree"], language_tree)
require("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob)
source = metadata["rugra_source"]
for key, expected in {
    "base_commit": base_commit,
    "base_tree": base_tree,
    "base_src_tree": base_src_tree,
    "base_cargo_toml_blob": cargo_toml_blob,
    "base_cargo_lock_blob": cargo_lock_blob,
    "base_build_rs_blob": build_rs_blob,
}.items():
    require(key, source[key], expected)
paths = [item["path"] for item in source["overlays"]]
require("overlay paths", paths,
        ["src/ruleaction.rs", "src/heritage.rs", "src/space.rs", "src/varnode.rs"])
for item, path in zip(source["overlays"],
                      [ruleaction_raw, heritage_raw, space_raw, varnode_raw]):
    pinned(f"overlay:{item['path']}", item["sha256"], sha(path))

comparand = metadata["comparand"]
for key, path in {
    "cpp_fixture_sha256": cpp_raw,
    "rust_fixture_sha256": rust_raw,
    "ruleaction_rs_sha256": ruleaction_raw,
    "heritage_rs_sha256": heritage_raw,
    "space_rs_sha256": space_raw,
    "varnode_rs_sha256": varnode_raw,
}.items():
    pinned(key, comparand[key], sha(path))
pinned("runner_sha256", comparand["runner_sha256"], runner_sha)
versions = {
    "host_cxx": subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0],
    "host_rustc": subprocess.check_output([host_rustc, "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output([host_cargo, "--version"], text=True).strip(),
}
for key, actual in versions.items():
    require(key, comparand[key], actual)

assets = metadata["assets"]
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    record = assets[key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} source", record["source_repository_commit"], input_commit)
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{input_commit}:{relative}"],
        text=True,
    ).strip()
    require(f"{key} blob", record["git_blob_oid"], oid)
    data = subprocess.check_output(
        ["git", "-C", str(repo), "cat-file", "blob", oid]
    )
    require(f"{key} sha", record["sha256"], hashlib.sha256(data).hexdigest())
    require(f"{key} size", record["size"], len(data))
binary = assets["binary"]
require("binary source", binary["source_repository_commit"], input_commit)
require("binary blob", binary["git_blob_oid"], input_blob)
binary_data = subprocess.check_output(
    ["git", "-C", str(repo), "cat-file", "blob", input_blob]
)
require("binary sha", binary["sha256"], hashlib.sha256(binary_data).hexdigest())
require("binary size", binary["size"], len(binary_data))
require("BFD header sha", assets["bfd"]["header_sha256"], sha(bfd_header_raw))
require("BFD header size", assets["bfd"]["header_size"], pathlib.Path(bfd_header_raw).stat().st_size)
require("BFD library sha", assets["bfd"]["library_sha256"], sha(bfd_library_raw))
require("BFD library size", assets["bfd"]["library_size"], pathlib.Path(bfd_library_raw).stat().st_size)

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "functions": manifest["functions"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
pinned("input_manifest.sha256", manifest["sha256"], hashlib.sha256(canonical).hexdigest())
require("residual todo ids", metadata["residual_todo_ids"],
        ["RULE-PORT-EARLYREMOVAL-0001", "OPBANK-0001", "HERITAGE-0001", "ARCH-0001"])
PYVALIDATE

if [[ "$mode" == validate ]]; then
  echo "rule_earlyremoval_1204 metadata/source validation passed"
  exit 0
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | \
  /usr/bin/awk -F: 'NR == 1 {print $6}')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
cache_parent="$user_home/.cache/rudra-rule-earlyremoval-1204"
/usr/bin/mkdir -p "$cache_parent"
exec 9>"$cache_parent/runner.lock"
if ! /usr/bin/flock -n 9; then
  echo "another rule_earlyremoval_1204 runner is active" >&2
  exit 1
fi
work=$(/usr/bin/mktemp -d "$cache_parent/run.XXXXXX")
cleanup() {
  case "$work" in
    "$cache_parent"/run.??????) ;;
    *) echo "refusing unexpected cleanup path: $work" >&2; return 1 ;;
  esac
  if [[ -d "$work" && ! -L "$work" ]]; then
    /usr/bin/rm -rf -- "$work"
  fi
}
trap cleanup EXIT
/usr/bin/mkdir -p "$work/tmp" "$work/workspace/tests/oracle" \
  "$work/workspace/tools" "$work/workspace/examples"
snapshot="$work/workspace"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" archive --format=tar \
  --output="$work/rudra-base.tar" "$rudra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches
/usr/bin/tar -xf "$work/rudra-base.tar" -C "$snapshot"
/usr/bin/cp -- "$ruleaction_overlay" "$snapshot/src/ruleaction.rs"
/usr/bin/cp -- "$heritage_overlay" "$snapshot/src/heritage.rs"
/usr/bin/cp -- "$space_overlay" "$snapshot/src/space.rs"
/usr/bin/cp -- "$varnode_overlay" "$snapshot/src/varnode.rs"
/usr/bin/cp -- "$cpp_fixture" "$snapshot/tests/oracle/rule_earlyremoval_1204.cc"
/usr/bin/cp -- "$rust_fixture" "$snapshot/tests/oracle/rule_earlyremoval_1204.rs"
/usr/bin/cp -- "$metadata" "$snapshot/tests/oracle/rule_earlyremoval_1204.metadata.json"
/usr/bin/cp -- "$runner_fd" "$snapshot/tools/run_rule_earlyremoval_oracle.sh"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" cat-file blob "$input_blob" \
  >"$snapshot/examples/curl"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  /usr/bin/mkdir -p "$snapshot/$(/usr/bin/dirname "$asset")"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" cat-file blob "$input_commit:$asset" \
    >"$snapshot/$asset"
done

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive --format=tar \
  --output="$work/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/tar -xf "$work/ghidra-cpp.tar" -C "$work"
oracle_cpp="$work/Ghidra/Features/Decompiler/src/decompile/cpp"
"$host_python" -I -S - "$oracle_cpp" "$metadata" "$mode" <<'PYPATCH'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
capture = sys.argv[3] == "capture"
patches = {
    "heritage.hh": [(
        "  int4 getPass(void) const { return pass; }\t///< Get overall count of heritage passes",
        "  int4 getPass(void) const { return pass; }\t///< Get overall count of heritage passes\n"
        "  int4 fixtureGetDeadRemoved(AddrSpace *spc) const { return getInfo(spc)->deadremoved; }\n"
        "  void fixtureSetPass(int4 val) { pass = val; }",
    )],
    "funcdata.hh": [(
        "  int4 getHeritagePass(void) const { return heritage.getPass(); }\t///< Get overall count of heritage passes",
        "  int4 getHeritagePass(void) const { return heritage.getPass(); }\t///< Get overall count of heritage passes\n"
        "  int4 fixtureGetDeadRemoved(AddrSpace *spc) const { return heritage.fixtureGetDeadRemoved(spc); }\n"
        "  void fixtureSetHeritagePass(int4 val) { heritage.buildInfoList(); heritage.fixtureSetPass(val); }",
    )],
}
hasher = hashlib.sha256()
hasher.update(b"ghidra-rule-earlyremoval-instrumentation-v1\0")
for name in sorted(patches):
    path = root / name
    text = path.read_text(encoding="utf-8")
    for old, new in patches[name]:
        if text.count(old) != 1:
            raise SystemExit(f"instrumentation anchor count drifted: {name}")
        text = text.replace(old, new)
        for value in (name.encode(), old.encode(), new.encode()):
            hasher.update(len(value).to_bytes(8, "big"))
            hasher.update(value)
    path.write_text(text, encoding="utf-8")
actual = hasher.hexdigest()
expected = metadata["comparand"]["ghidra_instrumentation_sha256"]
if expected.startswith("PENDING_"):
    if capture:
        print(f"PIN ghidra_instrumentation_sha256={actual}")
    else:
        raise SystemExit(f"instrumentation is not pinned; actual={actual}")
elif expected != actual:
    raise SystemExit(f"instrumentation hash mismatch: {expected} != {actual}")
PYPATCH

/usr/bin/mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$work/tmp" \
  "$host_make" --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$host_cxx -std=c++11" EXTRA= libdecomp.a
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$work/tmp" \
  "$host_cxx" -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$work/rule_earlyremoval_cpp"

# The main writer explicitly selected the repository default target cache.
# Serialize Cargo mutation; the locked C++ build and comparisons do not hold
# this global lane.
cargo_lock=/tmp/rudra-cargo-build.lock
/usr/bin/flock "$cargo_lock" /usr/bin/env -i \
  HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 TMPDIR="$work/tmp" \
  CARGO_HOME="$user_home/.cargo" CARGO_TARGET_DIR="$repo_root/target" \
  CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CXX="$host_cxx" CC="$host_cc" \
  AR="$host_ar" RUSTC="$host_rustc" RUSTFLAGS=-Awarnings \
  "$host_cargo" build --offline --locked --quiet \
  --manifest-path "$snapshot/Cargo.toml" --lib
rudra_rlib="$repo_root/target/debug/librudra.rlib"
native_archive=$(/usr/bin/find "$repo_root/target/debug/build" \
  -path '*/out/librudra_sleigh.a' -type f -printf '%T@ %p\n' | \
  /usr/bin/sort -nr | /usr/bin/head -1 | /usr/bin/cut -d' ' -f2-)
if [[ ! -f "$rudra_rlib" || -z "$native_archive" || ! -f "$native_archive" ]]; then
  echo "Rudra build did not produce required libraries" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")
/usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$work/tmp" "$host_rustc" --edition=2021 -O -Awarnings \
  -L "dependency=$repo_root/target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m "$rust_fixture" \
  -o "$work/rule_earlyremoval_rust"

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  LD_LIBRARY_PATH="$(/usr/bin/dirname "$bfd_library")" \
  "$host_timeout" --signal=TERM --kill-after=2s 30s \
  "$work/rule_earlyremoval_cpp" "$snapshot/sleigh_specs" \
  "$snapshot/examples/curl" >"$work/ghidra.stdout" 2>"$work/ghidra.stderr"
ghidra_status=$?
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_timeout" --signal=TERM --kill-after=2s 30s \
  "$work/rule_earlyremoval_rust" >"$work/rudra.stdout" 2>"$work/rudra.stderr"
rudra_status=$?
"$host_python" -I -S - "$work/ghidra.stdout" "$work/rudra.stdout" \
  "$work/ghidra.covered" "$work/rudra.covered" <<'PYCOVER'
import pathlib
import sys

for source_raw, covered_raw in ((sys.argv[1], sys.argv[3]),
                                (sys.argv[2], sys.argv[4])):
    lines = pathlib.Path(source_raw).read_text(encoding="utf-8").splitlines()
    residuals = [line for line in lines if line.startswith("residual=")]
    if len(residuals) != 3:
        raise SystemExit(f"expected exactly three residual records, got {len(residuals)}")
    covered = [line for line in lines if not line.startswith("residual=")]
    pathlib.Path(covered_raw).write_text(
        "\n".join(covered) + "\n", encoding="utf-8"
    )
PYCOVER
/usr/bin/diff -u --label ghidra-covered --label rudra-covered \
  "$work/ghidra.covered" "$work/rudra.covered" >"$work/covered.diff"
covered_status=$?
/usr/bin/diff -u --label ghidra --label rudra \
  "$work/ghidra.stdout" "$work/rudra.stdout" >"$work/raw.diff"
raw_status=$?
set -e

"$host_python" -I -S - "$metadata" "$mode" \
  "$work/ghidra.stdout" "$work/ghidra.stderr" "$work/rudra.stdout" \
  "$work/rudra.stderr" "$work/ghidra.covered" "$work/rudra.covered" \
  "$work/covered.diff" "$work/raw.diff" "$ghidra_status" "$rudra_status" \
  "$covered_status" "$raw_status" <<'PYVERDICT'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
capture = sys.argv[2] == "capture"
keys = [
    "ghidra_stdout_sha256", "ghidra_stderr_sha256",
    "rudra_stdout_sha256", "rudra_stderr_sha256",
    "ghidra_covered_sha256", "rudra_covered_sha256",
    "covered_diff_sha256", "raw_diff_sha256",
]
paths = [pathlib.Path(value) for value in sys.argv[3:11]]
statuses = {
    "ghidra_exit_code": int(sys.argv[11]),
    "rugra_exit_code": int(sys.argv[12]),
    "covered_diff_exit_code": int(sys.argv[13]),
    "raw_diff_exit_code": int(sys.argv[14]),
}
expected = metadata["expected_results"]
for key, path in zip(keys, paths):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    pinned = expected[key]
    if isinstance(pinned, str) and pinned.startswith("PENDING_"):
        if not capture:
            raise SystemExit(f"{key} is not pinned; actual={actual}")
        print(f"PIN {key}={actual}")
    elif actual != pinned:
        raise SystemExit(f"{key} mismatch: expected={pinned} actual={actual}")
for key, actual in statuses.items():
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
if paths[1].stat().st_size or paths[3].stat().st_size:
    raise SystemExit("fixture stderr must be empty")
records = paths[0].read_text(encoding="utf-8").splitlines()
order = [
    "typed_oplist=" if line.startswith("typed_oplist=") else line.split("|", 1)[0]
    for line in records
]
if order != expected["record_order"]:
    raise SystemExit(f"record order mismatch: {order!r}")
if len(records) != metadata["build"]["expected_stdout_lines"]:
    raise SystemExit("raw record count mismatch")
covered = paths[4].read_text(encoding="utf-8").splitlines()
if len(covered) != metadata["build"]["covered_stdout_lines"]:
    raise SystemExit("covered record count mismatch")
PYVERDICT

/usr/bin/cat "$work/ghidra.stdout"
/usr/bin/printf '%s\n' \
  'rule_earlyremoval_1204: covered_projection=14/14 MATCH overall=MISMATCH'
/usr/bin/printf '%s\n' \
  'residuals=raw opcode buckets 0/45,nullable input arity,full Heritage/Architecture manager closure'
