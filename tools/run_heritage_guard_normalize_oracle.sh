#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# HERITAGE-GUARD-NORMALIZE-0001.  The runner snapshots the locked Ghidra
# e40ed130 sources and the pinned Rudra commit, overlays the frozen fixture,
# serializes only Cargo through the repository-wide lock, and compares stdout
# byte-for-byte.

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
if [[ $# -ne 0 ]]; then
  echo "usage: tools/run_heritage_guard_normalize_oracle.sh" >&2
  exit 2
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
repo_root=$(builtin cd "$({ /usr/bin/dirname "$runner_source"; })/.." && builtin pwd -P)
runner="$repo_root/tools/run_heritage_guard_normalize_oracle.sh"
if [[ "$runner_source" != "$runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "runner did not resolve to the expected regular file" >&2
  exit 1
fi

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=dcead226b33d3541fb5426693cdde9b380656026
rudra_source_tree=d4ef825b510df5e74ec506857e28fd16e472ae8a
rudra_source_src_tree=038823b07b7801304593f850f32d0217903fba28
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/heritage_guard_normalize_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/heritage_guard_normalize_1204.cc"
rust_fixture="$repo_root/tests/oracle/heritage_guard_normalize_1204.rs"
cargo_target=/tmp/rudra-target-heritage-guard-norm
cargo_lock=/tmp/rudra-cargo-build.lock
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
cargo_storage="$user_home/.cache/rudra-target-heritage-guard-norm"
if [[ -L "$cargo_storage" || ( -e "$cargo_storage" && ! -d "$cargo_storage" ) ]]; then
  echo "Cargo backing path must be a real directory: $cargo_storage" >&2
  exit 1
fi
/usr/bin/mkdir -p "$cargo_storage"
if [[ ! -e "$cargo_target" && ! -L "$cargo_target" ]]; then
  /usr/bin/ln -s "$cargo_storage" "$cargo_target"
fi
if [[ ! -L "$cargo_target" || "$(/usr/bin/readlink -f "$cargo_target")" != "$cargo_storage" ]]; then
  echo "dedicated Cargo target must resolve $cargo_target -> $cargo_storage" >&2
  exit 1
fi

for path in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$path" || -L "$path" ]]; then
    echo "required input is not a regular non-symlink file: $path" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
cpp_tree=$(/usr/bin/git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
makefile_blob=$(/usr/bin/git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$cpp_tree" != "$oracle_cpp_tree" || "$makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra identity mismatch" >&2
  exit 1
fi
if [[ -n "$(/usr/bin/git -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp)" ]]; then
  echo "locked Ghidra decompiler tree is dirty" >&2
  exit 1
fi
if [[ "$(/usr/bin/git -C "$repo_root" rev-parse "$rudra_source_commit^{commit}")" != "$rudra_source_commit" || \
      "$(/usr/bin/git -C "$repo_root" rev-parse "$rudra_source_commit^{tree}")" != "$rudra_source_tree" || \
      "$(/usr/bin/git -C "$repo_root" rev-parse "$rudra_source_commit:src")" != "$rudra_source_src_tree" ]]; then
  echo "pinned Rudra source identity mismatch" >&2
  exit 1
fi

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-heritage-guard-norm-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-heritage-guard-norm-1204.??????)
      [[ ! -e "$oracle_tmp" || ( -d "$oracle_tmp" && ! -L "$oracle_tmp" ) ]] || return 1
      /usr/bin/rm -rf -- "$oracle_tmp"
      ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

owned=("$metadata" "$cpp_fixture" "$rust_fixture" "$runner")
/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.before"
/usr/bin/mkdir -p "$oracle_tmp/source" "$oracle_tmp/rudra" "$oracle_tmp/overlay"
/usr/bin/cp -- "$cpp_fixture" "$oracle_tmp/overlay/heritage_guard_normalize_1204.cc"
/usr/bin/cp -- "$rust_fixture" "$oracle_tmp/overlay/heritage_guard_normalize_1204.rs"
cpp_fixture_snapshot="$oracle_tmp/overlay/heritage_guard_normalize_1204.cc"
rust_fixture_snapshot="$oracle_tmp/overlay/heritage_guard_normalize_1204.rs"
/usr/bin/git -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
/usr/bin/git -C "$repo_root" archive --format=tar "$rudra_source_commit" \
  Cargo.toml Cargo.lock README.md build.rs src sleigh_shim \
  benches/decompile_bench.rs tests/oracle/decompress_1204.rs \
  tests/oracle/funcproto_lock_1204.rs | \
  /usr/bin/tar -xf - -C "$oracle_tmp/rudra"
rudra_snapshot="$oracle_tmp/rudra"
/usr/bin/mkdir -p "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
/usr/bin/python3 -I -S - "$repo_root" "$ghidra_root" "$rudra_snapshot" "$metadata" \
  "$cpp_fixture_snapshot" "$rust_fixture_snapshot" "$runner_sha" "$oracle_tag" \
  "$oracle_commit" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$rudra_source_commit" "$rudra_source_tree" "$rudra_source_src_tree" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(repo_raw, ghidra_raw, rudra_snapshot_raw, metadata_raw, cpp_raw, rust_raw,
 runner_sha, oracle_tag, oracle_commit, cpp_tree, makefile_blob, source_commit,
 source_tree, source_src_tree) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
ghidra_repo = pathlib.Path(ghidra_raw).resolve()
rudra_snapshot = pathlib.Path(rudra_snapshot_raw).resolve()
metadata_path = pathlib.Path(metadata_raw)
cpp_path = pathlib.Path(cpp_raw)
rust_path = pathlib.Path(rust_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def git_output(repository, *arguments):
    return subprocess.check_output(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        text=True,
    ).strip()

def committed_blob(repository, revision, relative):
    return git_output(repository, "rev-parse", f"{revision}:{relative}")

def file_blob(repository, path):
    return git_output(repository, "hash-object", "--no-filters", str(path))

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob)
comparand = metadata["comparand"]
require("source commit", comparand["rugra_base_commit"], source_commit)
require("source tree", comparand["rugra_base_tree"], source_tree)
require("source src tree", comparand["rugra_base_src_tree"], source_src_tree)
require("C++ fixture hash", sha(cpp_path.read_bytes()), comparand["cpp_fixture_sha256"])
require("Rust fixture hash", sha(rust_path.read_bytes()), comparand["rust_fixture_sha256"])
require("runner hash", runner_sha, comparand["runner_sha256"])

raw_paths = subprocess.check_output([
    "/usr/bin/git", "-C", str(repo), "ls-tree", "-r", "-z", "--name-only",
    source_commit, "--",
    "Cargo.toml", "Cargo.lock", "README.md", "build.rs", "src", "sleigh_shim",
    "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
    "tests/oracle/funcproto_lock_1204.rs",
])
paths = sorted(
    (pathlib.Path(item.decode()) for item in raw_paths.split(b"\0") if item),
    key=lambda path: path.as_posix(),
)
hasher = hashlib.sha256()
hasher.update(b"rudra-heritage-guard-norm-checkpoint-crate-v2\0")
for relative in paths:
    source = rudra_snapshot / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"crate input is not a regular file: {relative}")
    data = source.read_bytes()
    encoded = relative.as_posix().encode()
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)
require("crate hash scheme", comparand["rust_crate_tree_hash_scheme"],
        "sha256 of rudra-heritage-guard-norm-checkpoint-crate-v2 plus sorted length-prefixed Cargo.toml/Cargo.lock/README.md/build.rs/src/sleigh_shim/benches/decompile_bench.rs/tests/oracle/{decompress_1204.rs,funcproto_lock_1204.rs} paths and bytes at repository_commit")
crate_tree_sha = hasher.hexdigest()
require("source crate hash", crate_tree_sha, comparand["rust_crate_tree_sha256"])
for relative, key in (
    ("src/heritage.rs", "heritage_rs_sha256"),
    ("src/funcdata.rs", "funcdata_rs_sha256"),
    ("src/fspec.rs", "fspec_rs_sha256"),
    ("src/database.rs", "database_rs_sha256"),
    ("src/varnode.rs", "varnode_rs_sha256"),
    ("src/op.rs", "op_rs_sha256"),
    ("src/block.rs", "block_rs_sha256"),
):
    require(key, sha((rudra_snapshot / relative).read_bytes()), comparand[key])

architecture = (
    "locked synthetic LE 64-bit Architecture: const=0, other=1, unique=2, "
    "ram=3, register=4, stack=5, join=6, iop=7; register delay=0, stack delay=1"
)
compiler_spec = (
    "synthetic prototype fixtures: guardnorm_ret8 output=register:0x0:8, "
    "guardnorm_ret4hi output=register:0x4:4, guardnorm_call empty (no effect "
    "records); extrapop=0, no symbols, high-level disabled; whole-ram persist "
    "property band [0x1000,0x2000]"
)
analysis_options = {
    "entrypoint": "Fresh Funcdata per case. Cases 1/2/4/5 run one canonical Funcdata::opHeritage call after structureLoops/calcForwardDominator/buildInfoList; case 3 likewise with the persist property band installed on Architecture::symboltab; case 6 runs three opHeritage calls (stack delay=1). Case 1/2 additionally install the function model via FuncProto::setModel and Funcdata::initActiveOutput. Cases 4/6 push a FuncCallSpecs bound to the exact CALL op. No Action tree or C emission.",
    "prestate": "All observed PcodeOps are created with production newOp/opSetOpcode, fully inserted into named BlockBasic objects through opInsertEnd before order observation, and connected through opSetInput/opSetOutput/newUniqueOut. Free reads are distinct bank objects with one descendant. Halt RETURNs are marked via Funcdata::opMarkHalt (missing / badinstruction).",
    "observation": "Seven fixed-order lines (envelope + six cases). Each case records pass/heritagePass, the function output trial projection (offset:size:slot:killedbycall in registration order), per-RETURN input counts and last-input descriptors, the op immediately preceding selected RETURNs with return_copy/halt/indirect_creation/indirect_store flag booleans, INDIRECT census per pass, and the complete integrated block/op/slot order with first-seen alias ids, storage, class, defining opcode, activeHeritage/addrForce/writeMask/persist booleans.",
    "normalization": "Only raw object addresses are replaced by deterministic first-seen aN ids, preserving all equality/alias relations. Unique-space offsets are omitted (implementation allocation identity); size, class, flags, definitions and order remain. Raw flag words are not compared (implementation bit layouts differ); the semantic booleans are. No block, op, slot or trial order is sorted or removed."
}
cases = [
    {
        "id": "guard_returns_trial_register",
        "funcdata": "name=guard_returns_trial_register, ram base=0x6100, size=0x20, fresh bank/CFG/Heritage, funcp model=guardnorm_ret8, initActiveOutput",
        "blocks_in_order": ["b0", "b1", "b2"],
        "edges_in_order": ["b0->b1", "b0->b2"],
        "ops_creation_order": [
            "read@ram:0x6100 INT_OR declared_inputs=2; s0=fresh free register:0x0:8; s1=constant:8:0x21; out=unique:8; inserted b0",
            "ret0@ram:0x6101 RETURN declared_inputs=1; s0=constant:8:0x6100; inserted b0",
            "rhalt@ram:0x6102 RETURN declared_inputs=1; s0=constant:8:0x6101; inserted b1; opMarkHalt(missing)",
            "ret2@ram:0x6103 RETURN declared_inputs=1; s0=constant:8:0x6102; inserted b2",
        ],
        "preparation": "structureLoops; calcForwardDominator; Heritage::buildInfoList",
        "entrypoint": "one Funcdata::opHeritage call",
    },
    {
        "id": "guard_returns_overlapping_subpiece",
        "funcdata": "name=guard_returns_overlapping_subpiece, ram base=0x6200, size=0x20, fresh bank/CFG/Heritage, funcp model=guardnorm_ret4hi, initActiveOutput",
        "blocks_in_order": ["b0", "b1"],
        "edges_in_order": ["b0->b1"],
        "ops_creation_order": [
            "read@ram:0x6200 INT_ADD declared_inputs=2; s0=fresh free register:0x0:8; s1=constant:8:0x22; out=unique:8; inserted b0",
            "ret0@ram:0x6201 RETURN declared_inputs=1; s0=constant:8:0x6200; inserted b0",
            "rhalt@ram:0x6202 RETURN declared_inputs=1; s0=constant:8:0x6201; inserted b1; opMarkHalt(badinstruction)",
        ],
        "preparation": "structureLoops; calcForwardDominator; Heritage::buildInfoList",
        "entrypoint": "one Funcdata::opHeritage call",
    },
    {
        "id": "persist_return_copy_suffix",
        "funcdata": "name=persist_return_copy_suffix, ram base=0x6300, size=0x20, fresh bank/CFG/Heritage, no active output, whole-ram persist property band [0x1000,0x2000] on Architecture::symboltab",
        "blocks_in_order": ["b0", "b1"],
        "edges_in_order": ["b0->b1"],
        "ops_creation_order": [
            "read@ram:0x6300 INT_OR declared_inputs=2; s0=fresh free ram:0x1000:8; s1=constant:8:0x23; out=unique:8; inserted b0",
            "ret0@ram:0x6301 RETURN declared_inputs=1; s0=constant:8:0x6300; inserted b0",
            "rhalt@ram:0x6302 RETURN declared_inputs=1; s0=constant:8:0x6301; inserted b1; opMarkHalt(missing)",
        ],
        "preparation": "structureLoops; calcForwardDominator; Heritage::buildInfoList",
        "entrypoint": "one Funcdata::opHeritage call",
    },
    {
        "id": "normalize_write_call_piece",
        "funcdata": "name=normalize_write_call_piece, ram base=0x6400, size=0x20, fresh bank/CFG/Heritage, one CALL with guardnorm_call spec",
        "blocks_in_order": ["b0"],
        "edges_in_order": [],
        "ops_creation_order": [
            "call@ram:0x6400 CALL declared_inputs=1; s0=constant:8:0x4000; out=register:0x12:2; inserted b0; FuncCallSpecs pushed",
            "read@ram:0x6401 INT_OR declared_inputs=2; s0=fresh free register:0x10:4; s1=constant:8:0x24; out=unique:8; inserted b0",
            "ret0@ram:0x6402 RETURN declared_inputs=1; s0=constant:8:0x6400; inserted b0",
        ],
        "preparation": "structureLoops; calcForwardDominator; Heritage::buildInfoList",
        "entrypoint": "one Funcdata::opHeritage call",
    },
    {
        "id": "normalize_write_subpiece_piece",
        "funcdata": "name=normalize_write_subpiece_piece, ram base=0x6500, size=0x20, fresh bank/CFG/Heritage",
        "blocks_in_order": ["b0"],
        "edges_in_order": [],
        "ops_creation_order": [
            "w@ram:0x6500 INT_SUB declared_inputs=2; s0=constant:8:0x31; s1=constant:8:0x32; out=register:0x22:2; inserted b0",
            "read@ram:0x6501 INT_OR declared_inputs=2; s0=fresh free register:0x20:4; s1=constant:8:0x25; out=unique:8; inserted b0",
            "ret0@ram:0x6502 RETURN declared_inputs=1; s0=constant:8:0x6500; inserted b0",
        ],
        "preparation": "structureLoops; calcForwardDominator; Heritage::buildInfoList",
        "entrypoint": "one Funcdata::opHeritage call",
    },
    {
        "id": "guard_retry_pass_boundary",
        "funcdata": "name=guard_retry_pass_boundary, ram base=0x6600, size=0x20, fresh bank/CFG/Heritage, one CALL with guardnorm_call spec, stack range 0x20:8",
        "blocks_in_order": ["b0"],
        "edges_in_order": [],
        "ops_creation_order": [
            "call@ram:0x6600 CALL declared_inputs=1; s0=constant:8:0x4000; inserted b0; FuncCallSpecs pushed",
            "read@ram:0x6601 INT_OR declared_inputs=2; s0=fresh free stack:0x20:8; s1=constant:8:0x26; out=unique:8; inserted b0",
            "ret0@ram:0x6602 RETURN declared_inputs=1; s0=constant:8:0x6600; inserted b0",
        ],
        "preparation": "structureLoops; calcForwardDominator; Heritage::buildInfoList",
        "entrypoint": "three Funcdata::opHeritage calls (pass 0 register-only, pass 1 stack guard fires, pass 2 old range inert)",
    },
]
oracle_source_root = "Ghidra/Features/Decompiler/src/decompile/cpp"
oracle_source_names = (
    "database.cc", "funcdata_op.cc", "funcdata_varnode.cc", "fspec.cc",
    "fspec.hh", "heritage.cc", "heritage.hh", "op.hh", "varnode.hh",
)
oracle_source_blobs = {
    name: committed_blob(ghidra_repo, oracle_commit, f"{oracle_source_root}/{name}")
    for name in oracle_source_names
}
for name, blob in oracle_source_blobs.items():
    actual_blob = file_blob(
        ghidra_repo, ghidra_repo / pathlib.Path(oracle_source_root) / name
    )
    require(f"locked oracle worktree blob {name}", actual_blob, blob)

rudra_source_names = (
    "src/block.rs", "src/database.rs", "src/funcdata.rs", "src/fspec.rs",
    "src/heritage.rs", "src/op.rs", "src/varnode.rs",
)
rudra_source_blobs = {
    name: committed_blob(repo, source_commit, name) for name in rudra_source_names
}
for name, blob in rudra_source_blobs.items():
    require(
        f"snapshotted Rudra blob {name}",
        file_blob(repo, rudra_snapshot / pathlib.Path(name)),
        blob,
    )

fixture_records = {}
for relative, fixture_path in (
    ("tests/oracle/heritage_guard_normalize_1204.cc", cpp_path),
    ("tests/oracle/heritage_guard_normalize_1204.rs", rust_path),
):
    fixture_records[relative] = {
        "git_blob_oid": file_blob(repo, fixture_path),
        "sha256": sha(fixture_path.read_bytes()),
    }

expected_manifest = {
    "schema": "rudra-heritage-guard-norm-input-v1",
    "canonicalization": "SHA-256 over the entire input_manifest object encoded as UTF-8 by json.dumps with sort_keys=true, separators=(',',':'), ensure_ascii=false; no floats",
    "oracle": {
        "tag": oracle_tag,
        "commit": oracle_commit,
        "decompiler_cpp_tree": cpp_tree,
        "decompiler_makefile_blob": makefile_blob,
        "source_root": oracle_source_root,
        "relevant_source_blobs": oracle_source_blobs,
    },
    "architecture": architecture,
    "compiler_spec": compiler_spec,
    "analysis_options": analysis_options,
    "cases": cases,
    "fixtures": fixture_records,
    "rugra": {
        "repository_commit": source_commit,
        "repository_tree": source_tree,
        "repository_src_tree": source_src_tree,
        "tracked_crate_tree_hash_scheme": comparand["rust_crate_tree_hash_scheme"],
        "tracked_crate_tree_sha256": crate_tree_sha,
        "critical_source_blobs": rudra_source_blobs,
    },
}
require("architecture descriptor", metadata["architecture"], architecture)
require("compiler spec descriptor", metadata["compiler_spec"], compiler_spec)
require("analysis options descriptor", metadata["analysis_options"], analysis_options)
require("input manifest", metadata.get("input_manifest"), expected_manifest)
canonical = json.dumps(
    expected_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require(
    "input fingerprint",
    metadata.get("input_fingerprint"),
    "sha256:" + sha(canonical),
)
require("covered projection", metadata["covered_projection_status"], "MATCH")
if not metadata["overall_status"].startswith("MISMATCH:"):
    raise SystemExit("overall_status must remain conservative MISMATCH")
coverage = metadata["coverage"]
for key in (
    "guard_returns_trial_register",
    "guard_returns_overlapping_subpiece",
    "persist_return_copy_suffix",
    "normalize_write_call_piece",
    "normalize_write_subpiece_piece",
    "guard_retry_pass_boundary",
):
    if not coverage[key].startswith("MATCH"):
        raise SystemExit(f"covered projection {key} must remain MATCH")
for key in ("guard_fl_addrtied_holdind", "guard_fl_scope_symbol_flags"):
    if not coverage[key].startswith("UNTESTED"):
        raise SystemExit(f"residual {key} must remain UNTESTED")
if not coverage["remaining_heritage_closure"].startswith("UNTESTED"):
    raise SystemExit("remaining_heritage_closure must remain UNTESTED")
for key, status in coverage.items():
    if status.startswith("MISMATCH"):
        raise SystemExit(f"unregistered divergence in {key}")
PY

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
if (( jobs > 8 )); then jobs=8; fi
/usr/bin/nice -n 10 /usr/bin/make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="/usr/bin/g++ -std=c++11" EXTRA= libdecomp.a
/usr/bin/g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  "$cpp_fixture_snapshot" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" -Wl,--whole-archive "$oracle_cpp/libdecomp.a" \
  -Wl,--no-whole-archive -lz -o "$oracle_tmp/fixture_cpp"

/usr/bin/flock "$cargo_lock" -c \
  "CARGO_TARGET_DIR='$cargo_target' /usr/bin/cargo build --offline --locked --quiet --lib --manifest-path '$rudra_snapshot/Cargo.toml'"
/usr/bin/rustc --edition=2021 -O "$rust_fixture_snapshot" \
  --extern "rudra=$cargo_target/debug/librudra.rlib" \
  -L "dependency=$cargo_target/debug/deps" \
  -o "$oracle_tmp/fixture_rust"

/usr/bin/timeout 60s "$oracle_tmp/fixture_cpp" >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
/usr/bin/timeout 60s "$oracle_tmp/fixture_rust" >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
if [[ -s "$oracle_tmp/ghidra.stderr" || -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "fixture stderr must be empty" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
# Per-case gate: every line must byte-match the locked Ghidra oracle
# output. The former guard_returns_overlapping_subpiece divergence
# (fspec.rs justified_contain_range -1 polarity vs Address::justifiedContain,
# address.cc:131-141) was dual-pinned per side; the polarity fix merged
# into the re-pinned commit flips it to MATCH, so any divergence is now
# unregistered.
/usr/bin/python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib, json, pathlib, sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
glines = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
rlines = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()
prefixes = (
    "schema=1|fixture=HERITAGE-GUARD-NORMALIZE-0001|",
    "case=guard_returns_trial_register|",
    "case=guard_returns_overlapping_subpiece|",
    "case=persist_return_copy_suffix|",
    "case=normalize_write_call_piece|",
    "case=normalize_write_subpiece_piece|",
    "case=guard_retry_pass_boundary|",
)
if len(glines) != len(prefixes) or len(rlines) != len(prefixes):
    raise SystemExit("stdout line-count mismatch")
for gl, rl, prefix in zip(glines, rlines, prefixes):
    if not gl.startswith(prefix) or not rl.startswith(prefix):
        raise SystemExit(f"stdout case order mismatch at {prefix}")
for index, (gl, rl) in enumerate(zip(glines, rlines)):
    if gl != rl:
        raise SystemExit(f"divergence on line {index + 1}: {prefixes[index]}")
expected = metadata["expected_stdout"]
ghidra_sha = hashlib.sha256("\n".join(glines).encode() + b"\n").hexdigest()
if ghidra_sha != expected["ghidra_stdout_sha256"]:
    raise SystemExit(f"ghidra stdout hash mismatch: expected={expected['ghidra_stdout_sha256']} actual={ghidra_sha}")
rudra_sha = hashlib.sha256("\n".join(rlines).encode() + b"\n").hexdigest()
if rudra_sha != expected["rudra_stdout_sha256"]:
    raise SystemExit(f"rudra stdout hash mismatch: expected={expected['rudra_stdout_sha256']} actual={rudra_sha}")
PY

/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.after"
/usr/bin/diff -u "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"
/usr/bin/cat "$oracle_tmp/ghidra.stdout"
echo "heritage_guard_normalize_1204: covered_projection=MATCH(6) registered_mismatch=0 overall=MISMATCH cases=6"
