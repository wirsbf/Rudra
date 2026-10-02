#!/usr/bin/env bash
# PRINTC-UNLINKED-REF-FAMILY slices C+B1+A oracle runner (A35 audit
# section 5).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned oracle
# commit, links the C++ fixture against the binutils-2.38 BFD environment,
# rebuilds the Rudra crate from the pinned base commit with the live
# src/printc.rs overlay (slice B1: the unnamed-location fallback address
# source unified to the high's name representative, printlanguage.cc:244;
# slice A: the fallback token form unified to PrintC::pushUnnamedLocation,
# printc.cc:1938-1945 — space name + AddrSpace::printRaw, space.cc:206-222,
# merging the three divergent Rudra space ladders), compiles both
# fixtures, runs them, and classifies every stdout line:
#
#   - a line pair that byte-matches is COVERED;
#   - a line pair that differs is only acceptable when it is REGISTERED in
#     metadata["registered_divergence_lines"] with BOTH side's exact text
#     and sha256 — the gap evidence this fixture exists to pin (the
#     default-unknown typechar; the slice-A unnamed-location token form
#     rows were eliminated when the fallback ladders merged);
#   - any unregistered divergence, envelope/order/line-count drift, or a
#     STALE registration whose sides now byte-match (a fix landed — re-pin
#     the fixture and shrink the registered table) fails the run.  A
#     registration whose recorded side text no longer reproduces (drift)
#     fails the run the same way — that was the B1 acceptance signal
#     (slice B1 re-pinned line 31 after the multi_instance site=b label
#     collapsed onto the representative address) and the A acceptance
#     signal (slice A flipped lines 7/23/30/31 to `unique0x10000000`
#     byte-matches and shrank the registered table to the two typechar
#     rows).
#
# The observation surface is never narrowed to go green.
#
# Build discipline: /tmp/rudra-cargo-build.lock serializes Cargo, the
# CARGO_TARGET_DIR is the dedicated /tmp/rudra-target-printc-unnamed symlink
# to ~/.cache/rudra-target-printc-unnamed, and every build/compile step runs
# under timeout 600.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=bf4483327d91dca85f3dd8377255326fb05704a7
rudra_base_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/printc_unnamed_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/printc_unnamed_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_unnamed_1204.rs"

bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_rpath=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu

cargo_lock=/tmp/rudra-cargo-build.lock
cargo_target=/tmp/rudra-target-printc-unnamed
cargo_storage="$HOME/.cache/rudra-target-printc-unnamed"
if [[ -L "$cargo_storage" || ( -e "$cargo_storage" && ! -d "$cargo_storage" ) ]]; then
  echo "Cargo backing path must be a real directory: $cargo_storage" >&2
  exit 1
fi
mkdir -p "$cargo_storage"
if [[ ! -e "$cargo_target" && ! -L "$cargo_target" ]]; then
  ln -s "$cargo_storage" "$cargo_target"
fi
if [[ ! -L "$cargo_target" || "$(readlink -f "$cargo_target")" != "$cargo_storage" ]]; then
  echo "dedicated Cargo target must resolve $cargo_target -> $cargo_storage" >&2
  exit 1
fi

user_home=$(getent passwd "$(id -u)" | awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi

# Serialize concurrent invocations of this runner (they share the stable
# comparand workspace below).
exec 9>/tmp/rudra-printc-unnamed-runner.lock
if ! flock -n 9; then
  echo "another printc_unnamed_1204 runner is active" >&2
  exit 1
fi

# Cargo's package identity includes the manifest's absolute path, so a fresh
# mktemp snapshot would force a full rebuild on every run.  Use a stable
# workspace path under the user's cache instead; it is wiped and re-extracted
# from the pinned commit each run, so its content stays immutable while the
# fingerprints stay warm.
rudra_snapshot="$user_home/.cache/rudra-printc-unnamed-workspace"

for path in "$metadata" "$cpp_fixture" "$rust_fixture" "$0" "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$path" || -L "$path" ]]; then
    echo "required input is not a regular non-symlink file: $path" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
language_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$cpp_tree" != "$oracle_cpp_tree" || "$language_tree" != "$oracle_language_tree" || \
      "$makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra identity mismatch" >&2
  exit 1
fi
if [[ -n "$(git -C "$ghidra_root" status --porcelain -- \
    Ghidra/Features/Decompiler/src/decompile/cpp Ghidra/Processors/x86/data/languages)" ]]; then
  echo "locked Ghidra decompiler/x86 tree is dirty" >&2
  exit 1
fi
if [[ "$(git -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")" != "$rudra_base_commit" || \
      "$(git -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")" != "$rudra_base_tree" || \
      "$(git -C "$repo_root" rev-parse "$rudra_base_commit:src")" != "$rudra_base_src_tree" ]]; then
  echo "pinned Rudra source identity mismatch" >&2
  exit 1
fi

runner_sha=$(sha256sum "$0" | awk '{print $1}')

oracle_tmp=$(mktemp -d /tmp/rudra-printc-unnamed-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-printc-unnamed-1204.??????)
      [[ ! -e "$oracle_tmp" || ( -d "$oracle_tmp" && ! -L "$oracle_tmp" ) ]] || return 1
      rm -rf --one-file-system "$oracle_tmp"
      ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

owned=("$metadata" "$cpp_fixture" "$rust_fixture" "$0")
sha256sum "${owned[@]}" >"$oracle_tmp/owned.before"

# --- pre-flight: metadata pins, asset blobs, crate tree hash -------------
mkdir -p "$oracle_tmp/source" "$oracle_tmp/overlay"
rm -rf --one-file-system "$rudra_snapshot"
mkdir -p "$rudra_snapshot"
cp -- "$cpp_fixture" "$oracle_tmp/overlay/printc_unnamed_1204.cc"
cp -- "$rust_fixture" "$oracle_tmp/overlay/printc_unnamed_1204.rs"
cpp_fixture_snapshot="$oracle_tmp/overlay/printc_unnamed_1204.cc"
rust_fixture_snapshot="$oracle_tmp/overlay/printc_unnamed_1204.rs"

git -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  tar -xf - -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

git -C "$repo_root" archive --format=tar "$rudra_base_commit" \
  Cargo.toml Cargo.lock README.md build.rs src sleigh_shim \
  benches/decompile_bench.rs tests/oracle/decompress_1204.rs \
  tests/oracle/funcproto_lock_1204.rs | \
  tar -xf - -C "$rudra_snapshot"
# Slice B1+A overlay: the live src/printc.rs replaces the base version in
# the snapshot (the comparand under test).  The python pre-flight pins its
# exact sha256 through metadata["comparand"]["overlays"].
cp -- "$repo_root/src/printc.rs" "$rudra_snapshot/src/printc.rs"
mkdir -p "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile" \
  "$rudra_snapshot/sleigh_specs" "$rudra_snapshot/tests/oracle" \
  "$rudra_snapshot/examples"
ln -s "$oracle_cpp" "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
cp -- "$cpp_fixture_snapshot" "$rudra_snapshot/tests/oracle/printc_unnamed_1204.cc"
cp -- "$rust_fixture_snapshot" "$rudra_snapshot/tests/oracle/printc_unnamed_1204.rs"
cp -- "$metadata" "$rudra_snapshot/tests/oracle/printc_unnamed_1204.metadata.json"
for spec in x86-64.sla x86-64.pspec x86-64-gcc.cspec x86.ldefs; do
  git -C "$repo_root" cat-file blob "$rudra_base_commit:sleigh_specs/$spec" \
    >"$rudra_snapshot/sleigh_specs/$spec"
done
git -C "$repo_root" cat-file blob "$rudra_base_commit:examples/curl" \
  >"$rudra_snapshot/examples/curl"

python3 -I -S - "$repo_root" "$ghidra_root" "$rudra_snapshot" "$metadata" \
  "$cpp_fixture_snapshot" "$rust_fixture_snapshot" "$runner_sha" "$oracle_tag" \
  "$oracle_commit" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$rudra_base_src_tree" "$bfd_header" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(repo_raw, ghidra_raw, rudra_raw, metadata_raw, cpp_raw, rust_raw,
 runner_sha, oracle_tag, oracle_commit, cpp_tree, language_tree,
 makefile_blob, base_commit, base_tree, base_src_tree,
 bfd_header_raw, bfd_library_raw) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
ghidra_repo = pathlib.Path(ghidra_raw).resolve()
rudra = pathlib.Path(rudra_raw).resolve()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def git_output(repository, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(repository), *arguments], text=True
    ).strip()

def reject_pending(value, path="metadata"):
    if isinstance(value, dict):
        for key, child in value.items():
            reject_pending(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_pending(child, f"{path}[{index}]")
    elif isinstance(value, str) and value.startswith("PENDING"):
        raise SystemExit(f"{path} is pending: {value}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
reject_pending(metadata)
require("metadata schema", metadata["schema"], 2)
require("fixture id", metadata["fixture_id"], "PRINTC-UNLINKED-REF-FAMILY")
require("slice", metadata["slice"], "C")
require("covered projection status", metadata["covered_projection_status"], "MATCH")
require("expected exit code", metadata["expected_exit_code"], 0)
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", oracle["x86_language_tree"], language_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)

comparand = metadata["comparand"]
require("Rudra base commit", comparand["rugra_base_commit"], base_commit)
require("Rudra base tree", comparand["rugra_base_tree"], base_tree)
require("Rudra base src tree", comparand["rugra_base_src_tree"], base_src_tree)
require("C++ fixture hash", sha(pathlib.Path(cpp_raw).read_bytes()), comparand["cpp_fixture_sha256"])
require("Rust fixture hash", sha(pathlib.Path(rust_raw).read_bytes()), comparand["rust_fixture_sha256"])
require("runner hash", runner_sha, comparand["runner_sha256"])
overlays = comparand["overlays"]
if not (
    isinstance(overlays, list)
    and len(overlays) == 1
    and isinstance(overlays[0], dict)
    and overlays[0].get("path") == "src/printc.rs"
    and isinstance(overlays[0].get("sha256"), str)
    and len(overlays[0]["sha256"]) == 64
):
    raise SystemExit(f"slice B1 must overlay exactly src/printc.rs: {overlays!r}")
overlay_live = repo / "src/printc.rs"
if overlay_live.is_symlink() or not overlay_live.is_file():
    raise SystemExit("overlay input must be a regular non-symlink file: src/printc.rs")
require("overlay live sha256", sha(overlay_live.read_bytes()), overlays[0]["sha256"])
require(
    "overlay snapshot sha256",
    sha((rudra / "src/printc.rs").read_bytes()),
    overlays[0]["sha256"],
)

raw_paths = subprocess.check_output([
    "git", "-C", str(repo), "ls-tree", "-r", "-z", "--name-only",
    base_commit, "--",
    "Cargo.toml", "Cargo.lock", "README.md", "build.rs", "src", "sleigh_shim",
    "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
    "tests/oracle/funcproto_lock_1204.rs",
])
paths = sorted(
    (pathlib.Path(item.decode()) for item in raw_paths.split(b"\0") if item),
    key=lambda path: path.as_posix(),
)
hasher = hashlib.sha256()
hasher.update(b"rudra-printc-unnamed-base-overlay-b1-v1\0")
hasher.update(base_commit.encode())
for relative in paths:
    source = rudra / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"crate input is not a regular file: {relative}")
    data = source.read_bytes()
    encoded = relative.as_posix().encode()
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)
require(
    "crate hash scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-printc-unnamed-base-overlay-b1-v1 plus base commit and sorted length-prefixed Cargo.toml/Cargo.lock/README.md/build.rs/src/sleigh_shim/benches/decompile_bench.rs/tests/oracle/{decompress_1204.rs,funcproto_lock_1204.rs} paths and bytes at rudra_base_commit with src/printc.rs overlaid from the live tree (slice A: unnamed-location fallback token form unified to PrintC::pushUnnamedLocation, printc.cc:1938-1945, on top of slice B1's name-representative address source, printlanguage.cc:244)",
)
require("checkpoint crate hash", hasher.hexdigest(), comparand["rust_crate_tree_sha256"])

for key, relative in (
    ("binary", "examples/curl"),
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    asset = metadata["build"]["assets"][key]
    data = (rudra / relative).read_bytes()
    require(f"{key} git blob", git_output(repo, "rev-parse", f"{base_commit}:{relative}"), asset["git_blob"])
    require(f"{key} sha256", sha(data), asset["sha256"])
bfd = metadata["build"]["assets"]["bfd"]
require("BFD header sha256", sha(pathlib.Path(bfd_header_raw).read_bytes()), bfd["header_sha256"])
require("BFD library sha256", sha(pathlib.Path(bfd_library_raw).read_bytes()), bfd["library_sha256"])

payload = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": metadata["input_manifest"]["cases"],
}
canonical = json.dumps(
    payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha256", sha(canonical), metadata["input_manifest"]["sha256"])

registered = metadata["registered_divergence_lines"]
expected_lines = metadata["expected_stdout"]["lines"]
require("expected line count", expected_lines, 35)
registered_indexes = sorted(int(key) for key in registered)
require("registered count", len(registered_indexes), 2)
if registered_indexes != [2, 3]:
    raise SystemExit(f"registered divergence line set drifted: {registered_indexes}")
for key, record in registered.items():
    for side in ("ghidra", "rugra"):
        text = record[side]
        require(
            f"registered line {key} {side} sha256",
            record[f"{side}_sha256"],
            sha(text.encode("utf-8")),
        )
        if "domain" not in record or not record["domain"]:
            raise SystemExit(f"registered line {key} lacks a domain attribution")
print("pre-flight pins verified", flush=True)
PY

# --- build the locked oracle and the C++ fixture --------------------------
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
if (( jobs > 8 )); then jobs=8; fi
if ! timeout 600 nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="g++ -std=c++11" EXTRA= libdecomp.a \
    >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  cat "$oracle_tmp/make.stdout" "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if [[ ! -f "$oracle_cpp/libdecomp.a" || -L "$oracle_cpp/libdecomp.a" ]]; then
  echo "locked archive rebuild did not produce a regular libdecomp.a" >&2
  exit 1
fi
if ! timeout 600 g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
    -I"$bfd_include" -I"$oracle_cpp" \
    "$cpp_fixture_snapshot" "$oracle_cpp/libdecomp.cc" \
    "$oracle_cpp/sleigh_arch.cc" "$oracle_cpp/inject_sleigh.cc" \
    "$oracle_cpp/bfd_arch.cc" "$oracle_cpp/loadimage_bfd.cc" \
    -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive \
    "$bfd_library" -lz -Wl,-rpath,"$bfd_rpath" \
    -o "$oracle_tmp/printc_unnamed_1204_cpp" \
    >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  cat "$oracle_tmp/cxx.stdout" "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

# --- build the Rudra comparand --------------------------------------------
if ! flock "$cargo_lock" -c \
    "CARGO_TARGET_DIR='$cargo_target' timeout 600 cargo build --offline --locked --quiet --lib --manifest-path '$rudra_snapshot/Cargo.toml'" \
    >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  cat "$oracle_tmp/cargo.stdout" "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$cargo_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" ]]; then
  echo "cargo build did not produce a regular Rudra rlib at $rudra_rlib" >&2
  exit 1
fi
if ! timeout 600 rustc --edition=2021 -O "$rust_fixture_snapshot" \
    --extern "rudra=$rudra_rlib" \
    -L "dependency=$cargo_target/debug/deps" \
    -o "$oracle_tmp/printc_unnamed_1204_rust" \
    >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  cat "$oracle_tmp/rustc.stdout" "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

# --- run both fixtures -----------------------------------------------------
timeout 60s env LD_LIBRARY_PATH="$bfd_rpath" \
  "$oracle_tmp/printc_unnamed_1204_cpp" sleigh_specs examples/curl \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
timeout 60s "$oracle_tmp/printc_unnamed_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
if [[ "$ghidra_status" -ne 0 || "$rudra_status" -ne 0 ]]; then
  echo "fixture exit mismatch: ghidra=$ghidra_status rudra=$rudra_status" >&2
  cat "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if grep -qv '^WARNING: ' "$oracle_tmp/ghidra.stderr" || [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "fixture stderr must be empty (Ghidra WARNING lines excepted)" >&2
  cat "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

# --- classification gate ---------------------------------------------------
gate_summary=$(python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
rudra = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()

def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

expected = metadata["expected_stdout"]
envelope = (
    "schema=1|fixture=PRINTC-UNLINKED-REF-FAMILY|slice=C"
    "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
)
if len(ghidra) != expected["lines"] or len(rudra) != expected["lines"]:
    raise SystemExit(
        f"line-count drift: ghidra={len(ghidra)} rudra={len(rudra)}"
        f" expected={expected['lines']}"
    )
if ghidra[0] != envelope or rudra[0] != envelope:
    raise SystemExit("envelope mismatch")

case_order = metadata["case_order"]
seen_cases = []
for line in ghidra[1:]:
    if line.startswith("case="):
        case = line[len("case="):].split("|", 1)[0]
        if not seen_cases or seen_cases[-1] != case:
            seen_cases.append(case)
if seen_cases != case_order:
    raise SystemExit(f"case order drift: {seen_cases}")

registered = {
    int(key): record
    for key, record in metadata["registered_divergence_lines"].items()
}
covered = 0
for index, (gline, rline) in enumerate(zip(ghidra, rudra), start=1):
    if gline == rline:
        covered += 1
        if index in registered:
            raise SystemExit(
                f"stale registration at line {index}: both sides now byte-match"
                " — a fix landed; re-pin the fixture and remove the"
                " registration (this is the B1/A acceptance signal)"
            )
        continue
    record = registered.get(index)
    if record is None:
        raise SystemExit(
            f"UNREGISTERED divergence at line {index}:\n"
            f"  ghidra: {gline}\n  rudra:  {rline}"
        )
    if record["ghidra"] != gline or sha(gline) != record["ghidra_sha256"]:
        raise SystemExit(
            f"registered ghidra side drifted at line {index}:\n"
            f"  registered: {record['ghidra']}\n  actual:      {gline}"
        )
    if record["rugra"] != rline or sha(rline) != record["rudra_sha256"]:
        raise SystemExit(
            f"registered rudra side drifted at line {index}:\n"
            f"  registered: {record['rudra']}\n  actual:      {rline}"
        )

ghidra_bytes = pathlib.Path(sys.argv[2]).read_bytes()
rudra_bytes = pathlib.Path(sys.argv[3]).read_bytes()
if hashlib.sha256(ghidra_bytes).hexdigest() != expected["ghidra_stdout_sha256"]:
    raise SystemExit("ghidra full-stdout hash drift")
if hashlib.sha256(rudra_bytes).hexdigest() != expected["rudra_stdout_sha256"]:
    raise SystemExit("rudra full-stdout hash drift")

total = expected["lines"]
mismatches = len(registered)
print(f"covered={covered}/{total} registered_mismatch={mismatches}")
for index in sorted(registered):
    record = registered[index]
    print(f"  line {index}: [{record['domain'].split(';')[0].strip()}]")
    print(f"    ghidra: {record['ghidra']}")
    print(f"    rudra:  {record['rudra']}")
if covered + mismatches != total:
    raise SystemExit("classification accounting mismatch")
PY
)

sha256sum "${owned[@]}" >"$oracle_tmp/owned.after"
if ! diff -u "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"; then
  echo "owned comparands drifted during the run" >&2
  exit 1
fi

printf '%s\n' "$gate_summary"
covered_part=${gate_summary%% *}
covered_part=${covered_part#covered=}
echo "printc_unnamed_1204: covered_projection=MATCH($covered_part) overall=MISMATCH slice=PRINTC-UNLINKED-REF-FAMILY/C+B1+A"
