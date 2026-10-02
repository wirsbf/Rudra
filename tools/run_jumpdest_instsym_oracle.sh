#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# CSPEC-JUMPDEST-INSTSYM-0001 oracle runner: JUMPSYM snippet-compiler
# parity (inst_start/inst_next/inst_next2 language symbols + local
# inst_dest/inst_ref).  Builds the locked Ghidra 12.0.4 oracle (bare
# SLEIGH engine on the production x86-64.sla, the same
# `const SleighBase *` handle PcodeInjectLibrarySleigh::parseInject
# hands to PcodeSnippet) and the Rudra snippet compiler
# (PcodeSnippet + PredefinedJumpSymbols), compiles the same ten
# JUMPSYM snippets on both sides, and diffs the ConstructTpl XML
# projections byte for byte.

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
runner="$repo_root/tools/run_jumpdest_instsym_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
runner_mode=$(/usr/bin/stat -Lc '%a' "$runner_fd_path")
if [[ "$runner_mode" != 755 ]]; then
  echo "immutable runner mode mismatch: expected=755 actual=$runner_mode" >&2
  exit 1
fi

if [[ $# -ne 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin="$user_home/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/cargo"
host_rustc_bin="$user_home/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc"
for tool in "$host_cxx_bin" "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/jumpdest_instsym_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/jumpdest_instsym_1204.cc"
rust_fixture="$repo_root/tests/oracle/jumpdest_instsym_1204.rs"
spec_sla="$repo_root/sleigh_specs/x86-64.sla"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$spec_sla"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$ghidra_root" diff --cached --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-jumpdest-instsym-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-jumpdest-instsym-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

oracle_cpp="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx_bin -std=c++11" "EXTRA=" libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
standard_archive="$oracle_cpp/libdecomp.a"
if [[ ! -f "$standard_archive" || -L "$standard_archive" ]]; then
  echo "locked Makefile did not produce a regular libdecomp.a" >&2
  exit 1
fi

# Rust side: build the library from the working tree (WIP model; the
# metadata records the current tree hashes).
if ! (
  cd "$repo_root"
  /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
    RUSTUP_TOOLCHAIN=nightly-x86_64-unknown-linux-gnu PATH="$clean_path" \
    LC_ALL=C.UTF-8 CARGO_NET_OFFLINE=true RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --release --quiet --locked --offline --lib
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib=$(ls -t "$repo_root/target/release/deps/librudra"*.rlib | /usr/bin/head -1)
if [[ -z "$rudra_rlib" || ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce a librudra.rlib" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O0 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/sleigh.cc" "$standard_archive" -lz \
  -o "$oracle_tmp/jumpdest_instsym_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN=nightly-x86_64-unknown-linux-gnu PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "$repo_root/target/release/deps" --extern "rudra=$rudra_rlib" \
  "$rust_fixture" -o "$oracle_tmp/jumpdest_instsym_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/jumpdest_instsym_1204_cpp" "$repo_root/sleigh_specs" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/jumpdest_instsym_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  "$cpp_fixture" "$rust_fixture" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, ghidra_raw, rudra_raw, cpp_fixture_raw, rust_fixture_raw,
    runner_sha, oracle_commit, oracle_tag, cpp_tree, makefile_blob,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
ghidra = pathlib.Path(ghidra_raw).read_bytes()
rudra = pathlib.Path(rudra_raw).read_bytes()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, label="metadata"):
    if isinstance(value, dict):
        for key, child in value.items():
            reject_pending(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_pending(child, f"{label}[{index}]")
    elif isinstance(value, str) and value.startswith("PENDING"):
        raise SystemExit(f"{label} is pending: {value}")

reject_pending(metadata)
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "CSPEC-JUMPDEST-INSTSYM-0001")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)

if ghidra != rudra:
    raise SystemExit("byte comparison unexpectedly diverged after diff succeeded")
if not ghidra.endswith(b"\n"):
    raise SystemExit("fixture output lacks final newline")
lines = ghidra.decode("utf-8").splitlines()
if lines[-1] != "DONE":
    raise SystemExit(f"fixture summary mismatch: {lines[-1]!r}")
prefixes = {}
for line in lines:
    prefix = line.split("|", 1)[0]
    prefixes[prefix] = prefixes.get(prefix, 0) + 1
if prefixes != metadata["coverage"]["record_counts"]:
    raise SystemExit(f"fixture record counts mismatch: {prefixes}")

comparand = metadata["comparand"]
require(
    "cpp fixture sha256",
    sha(pathlib.Path(cpp_fixture_raw).read_bytes()),
    comparand["cpp_fixture_sha256"],
)
require(
    "rust fixture sha256",
    sha(pathlib.Path(rust_fixture_raw).read_bytes()),
    comparand["rust_fixture_sha256"],
)
require("runner sha256", runner_sha, comparand["runner_sha256"])

capture = metadata["locked_capture"]
actual_hash = sha(ghidra)
if len(ghidra) != capture["bytes"] or len(lines) != capture["records"]:
    raise SystemExit("locked capture size mismatch")
if actual_hash != capture["stdout_sha256"]:
    raise SystemExit("locked capture hash mismatch")

print(f"records={len(lines)} bytes={len(ghidra)} stdout_sha256={actual_hash}")
print("jumpsym_symbol_status=MATCH overall=MATCH")
PY
