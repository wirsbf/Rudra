#!/usr/bin/env bash
set -euo pipefail

mode=both
if [[ $# -eq 1 && "$1" == --validate-only ]]; then
  mode=validate
elif [[ $# -ne 0 ]]; then
  echo "usage: ${BASH_SOURCE[0]} [--validate-only]" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runner="$repo_root/tools/run_getstr_pipeline_oracle.sh"
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/getstr_pipeline_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/getstr_pipeline_1204.cc"
rust_example="$repo_root/examples/getstr_stage_snapshot.rs"
binary="$repo_root/examples/curl"
spec_root="$repo_root/sleigh_specs"
stage_diff="$repo_root/tools/stage_diff.py"
output_root="$repo_root/result/pipeline_snapshots/getstr"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 language source is dirty" >&2
  exit 1
fi

bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" && -f /tmp/rudra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
fi
if [[ -z "$bfd_include" && -f /usr/include/bfd.h ]]; then
  bfd_include=/usr/include
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" ]]; then
  echo "binutils 2.38 bfd.h not found; set RUDRA_BFD_INCLUDE to its include directory" >&2
  exit 1
fi
bfd_library=${RUDRA_BFD_LIBRARY:-}
if [[ -z "$bfd_library" && -f /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so ]]; then
  bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
fi
if [[ -z "$bfd_library" && \
      -f /tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so ]]; then
  bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
fi
if [[ ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD library not found: $bfd_library" >&2
  exit 1
fi
bfd_library_dir=$(dirname "$bfd_library")

cpp_tree=$(git -C "$ghidra_root" rev-parse HEAD:Ghidra/Features/Decompiler/src/decompile/cpp)
x86_tree=$(git -C "$ghidra_root" rev-parse HEAD:Ghidra/Processors/x86/data/languages)
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_example" "$binary" \
  "$runner" "$stage_diff" "$repo_root/src" "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" \
  "$repo_root/build.rs" "$repo_root/sleigh_shim" "$spec_root" \
  "$bfd_include/bfd.h" "$bfd_library" \
  "$oracle_commit" "$oracle_tag" "$cpp_tree" "$x86_tree" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_example_name,
    binary_name,
    runner_name,
    stage_diff_name,
    rust_src_name,
    cargo_manifest_name,
    cargo_lock_name,
    build_script_name,
    sleigh_shim_name,
    spec_root_name,
    bfd_header_name,
    bfd_library_name,
    oracle_commit,
    oracle_tag,
    cpp_tree,
    x86_tree,
) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle tag/commit mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("unexpected compiler spec metadata")
if metadata.get("observation", {}).get("overall_status") != "MISMATCH":
    raise SystemExit("pipeline snapshot must remain MISMATCH until all six layers match")

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def tree_digest(root_name, pattern="*"):
    root = pathlib.Path(root_name)
    result = hashlib.sha256()
    for path in sorted(path for path in root.rglob(pattern) if path.is_file()):
        relative = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        result.update(len(relative).to_bytes(8, "big"))
        result.update(relative)
        result.update(len(data).to_bytes(8, "big"))
        result.update(data)
    return result.hexdigest()

input_bytes = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
actual_input_fingerprint = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
if metadata.get("input_fingerprint") != actual_input_fingerprint:
    raise SystemExit("metadata input fingerprint mismatch")

comparands = {
    "cpp_fixture": cpp_fixture_name,
    "rust_example": rust_example_name,
    "runner": runner_name,
    "stage_diff": stage_diff_name,
    "cargo_manifest": cargo_manifest_name,
    "cargo_lock": cargo_lock_name,
    "build_script": build_script_name,
}
for key, path in comparands.items():
    actual = digest(path)
    expected = metadata["comparand_sha256"].get(key)
    if actual != expected:
        raise SystemExit(f"comparand hash mismatch for {key}: {actual} != {expected}")
tree_comparands = {
    "rugra_src_tree": (rust_src_name, "*.rs"),
    "sleigh_shim_tree": (sleigh_shim_name, "*"),
}
for key, (path, pattern) in tree_comparands.items():
    actual = tree_digest(path, pattern)
    expected = metadata["comparand_sha256"].get(key)
    if actual != expected:
        raise SystemExit(f"comparand tree hash mismatch for {key}: {actual} != {expected}")

assets = metadata["assets"]
asset_paths = {
    "sla_sha256": pathlib.Path(spec_root_name) / "x86-64.sla",
    "pspec_sha256": pathlib.Path(spec_root_name) / "x86-64.pspec",
    "cspec_sha256": pathlib.Path(spec_root_name) / "x86-64-gcc.cspec",
    "ldefs_sha256": pathlib.Path(spec_root_name) / "x86.ldefs",
    "bfd_header_sha256": pathlib.Path(bfd_header_name),
    "bfd_library_sha256": pathlib.Path(bfd_library_name),
}
for key, path in asset_paths.items():
    actual = digest(path)
    if assets.get(key) != actual:
        raise SystemExit(f"asset hash mismatch for {key}: {actual} != {assets.get(key)}")
if assets.get("ghidra_cpp_tree") != cpp_tree:
    raise SystemExit("locked Ghidra C++ tree mismatch")
if assets.get("ghidra_x86_language_tree") != x86_tree:
    raise SystemExit("locked Ghidra x86 language tree mismatch")
if digest(binary_name) != metadata["input"]["binary_sha256"]:
    raise SystemExit("curl input hash mismatch")

compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata.get("host_compiler") != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
if metadata.get("host_rustc") != rustc:
    raise SystemExit(f"host rustc mismatch: {rustc}")
PY

if [[ "$mode" == validate ]]; then
  echo "getstr_pipeline_1204 metadata/source validation passed"
  exit 0
fi

source_tree_hash() {
  python3 -I -S - "$repo_root/src" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob("*.rs")):
    relative = path.relative_to(root).as_posix().encode()
    data = path.read_bytes()
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
print(digest.hexdigest())
PY
}

rudra_source_before=$(source_tree_hash)
user_home=$(getent passwd "$(id -u)" | awk -F: 'NR == 1 {print $6}')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
cache_parent="$user_home/.cache/rudra-getstr-pipeline-1204"
mkdir -p "$cache_parent"
oracle_tmp=$(mktemp -d "$cache_parent/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$cache_parent"/run.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$oracle_tmp/ghidra" "$oracle_tmp/rudra" "$oracle_tmp/rudra-repeat"
mkdir -m 0700 "$oracle_tmp/build-tmp"
export TMPDIR="$oracle_tmp/build-tmp"
mkdir -p "$output_root/ghidra" "$output_root/rudra" "$output_root/rudra-repeat"
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
cp "$cpp_fixture" "$oracle_tmp/fixture.cc"
g++ -std=c++11 -O2 -I"$bfd_include" -I"$cpp_root" \
  "$oracle_tmp/fixture.cc" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" \
  -Wl,-rpath,"$bfd_library_dir" -lz \
  -o "$oracle_tmp/getstr_pipeline_1204"

fixture_target="$cache_parent/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --release --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" \
  --example getstr_stage_snapshot
rudra_fixture="$fixture_target/release/examples/getstr_stage_snapshot"
if [[ ! -x "$rudra_fixture" ]]; then
  echo "cargo did not produce the GetStr snapshot example" >&2
  exit 1
fi

"$oracle_tmp/getstr_pipeline_1204" "$spec_root" "$binary" "$oracle_tmp/ghidra"
"$rudra_fixture" "$binary" "$oracle_tmp/rudra"
"$rudra_fixture" "$binary" "$oracle_tmp/rudra-repeat"
rudra_source_after=$(source_tree_hash)
if [[ "$rudra_source_before" != "$rudra_source_after" ]]; then
  echo "Rudra source tree changed while the fixture was running" >&2
  exit 1
fi

python3 -I -S - "$oracle_tmp/ghidra" "$oracle_tmp/rudra" "$oracle_tmp/rudra-repeat" <<'PY'
import json
import pathlib
import sys

stages = (
    "00_raw_pcode.json",
    "01_cfg.json",
    "02_heritage_ssa.json",
    "03_action_ir.json",
    "04_structure.json",
    "05_c.json",
)
for directory_name in sys.argv[1:]:
    directory = pathlib.Path(directory_name)
    for expected_stage, name in zip((item[:-5] for item in stages), stages):
        path = directory / name
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schema") != 1 or document.get("state") != "OK":
            raise SystemExit(f"invalid snapshot envelope: {path}")
        if document.get("stage") != expected_stage:
            raise SystemExit(f"stage label mismatch: {path}")
        path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
PY

for stage in 00_raw_pcode 01_cfg 02_heritage_ssa 03_action_ir 04_structure 05_c; do
  cp "$oracle_tmp/ghidra/$stage.json" "$output_root/ghidra/$stage.json"
  cp "$oracle_tmp/rudra/$stage.json" "$output_root/rudra/$stage.json"
  cp "$oracle_tmp/rudra-repeat/$stage.json" "$output_root/rudra-repeat/$stage.json"
done

common_context=(
  --context "binary_sha256=$(sha256sum "$binary" | awk '{print $1}')"
  --context "function=GetStr@0x36d0+74"
  --context "rudra_commit=$(git -C "$repo_root" rev-parse HEAD)"
  --context "rudra_src_tree=$rudra_source_before"
)
common_stages=(
  --stage "00_raw_pcode=$output_root/ghidra/00_raw_pcode.json"
  --stage "01_cfg=$output_root/ghidra/01_cfg.json"
  --stage "02_heritage_ssa=$output_root/ghidra/02_heritage_ssa.json"
  --stage "03_action_ir=$output_root/ghidra/03_action_ir.json"
  --stage "04_structure=$output_root/ghidra/04_structure.json"
  --stage "05_c=$output_root/ghidra/05_c.json"
)
python3 "$stage_diff" snapshot --metadata "$metadata" --producer ghidra-12.0.4 \
  "${common_context[@]}" "${common_stages[@]}" \
  --output "$output_root/ghidra.manifest.json"

common_stages=(
  --stage "00_raw_pcode=$output_root/rudra/00_raw_pcode.json"
  --stage "01_cfg=$output_root/rudra/01_cfg.json"
  --stage "02_heritage_ssa=$output_root/rudra/02_heritage_ssa.json"
  --stage "03_action_ir=$output_root/rudra/03_action_ir.json"
  --stage "04_structure=$output_root/rudra/04_structure.json"
  --stage "05_c=$output_root/rudra/05_c.json"
)
python3 "$stage_diff" snapshot --metadata "$metadata" --producer rudra \
  "${common_context[@]}" "${common_stages[@]}" \
  --output "$output_root/rudra.manifest.json"

set +e
python3 "$stage_diff" compare "$output_root/ghidra.manifest.json" \
  "$output_root/rudra.manifest.json" --pretty --report "$output_root/stage-manifest-diff.json"
manifest_status=$?
set -e
if [[ $manifest_status -ne 1 ]]; then
  echo "expected a known stage mismatch, stage_diff rc=$manifest_status" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$output_root" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
root = pathlib.Path(sys.argv[2])
stage_names = (
    "00_raw_pcode",
    "01_cfg",
    "02_heritage_ssa",
    "03_action_ir",
    "04_structure",
    "05_c",
)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def counts(document):
    result = {}
    if document.get("ops"):
        result["ops"] = len(document["ops"])
    if document.get("varnodes"):
        result["varnodes"] = len(document["varnodes"])
    if document.get("blocks"):
        result["blocks"] = len(document["blocks"])
    structure = document.get("structure")
    if isinstance(structure, dict):
        result["root_children"] = len(structure.get("children", []))
    text = document.get("text")
    if isinstance(text, str):
        result["text_bytes"] = len(text.encode())
    return result

def validate_expected(actual, expected, producer, stage):
    for key, value in expected.items():
        if actual.get(key) != value:
            raise SystemExit(
                f"unexpected {producer} {stage} {key}: "
                f"actual={actual.get(key)} expected={value}"
            )

def first_difference(left, right, path="$", left_label="ghidra", right_label="rugra"):
    if type(left) is not type(right):
        return {"path": path, "kind": "type", left_label: type(left).__name__, right_label: type(right).__name__}
    if isinstance(left, dict):
        left_keys = set(left)
        right_keys = set(right)
        if left_keys != right_keys:
            return {"path": path, "kind": "keys", "ghidra_only": sorted(left_keys-right_keys), "rudra_only": sorted(right_keys-left_keys)}
        for key in sorted(left_keys):
            result = first_difference(left[key], right[key], f"{path}.{key}", left_label, right_label)
            if result is not None:
                return result
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {"path": f"{path}.length", "kind": "value", left_label: len(left), right_label: len(right)}
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            result = first_difference(left_item, right_item, f"{path}[{index}]", left_label, right_label)
            if result is not None:
                return result
        return None
    if left != right:
        return {"path": path, "kind": "value", left_label: left, right_label: right}
    return None

documents = {"ghidra": {}, "rugra": {}}
stage_report = []
for stage in stage_names:
    for producer in documents:
        path = root / producer / f"{stage}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        documents[producer][stage] = document
        expected = metadata["expected"][producer][stage]
        actual = {"sha256": digest(path), **counts(document)}
        validate_expected(actual, expected, producer, stage)
    stage_report.append(
        {
            "stage": stage,
            "ghidra": counts(documents["ghidra"][stage]),
            "rugra": counts(documents["rugra"][stage]),
            "first_difference": first_difference(
                documents["ghidra"][stage], documents["rugra"][stage]
            ),
        }
    )

focused = metadata["focused_projections"]
for projection_name in ("char_zero_read_facing", "short_circuit_character_token"):
    if focused[projection_name]["status"] != "MATCH":
        raise SystemExit(f"focused projection is not pinned MATCH: {projection_name}")
if focused.get("does_not_override_overall_status") is not True or not focused.get("residual_ids"):
    raise SystemExit("focused projection must preserve overall MISMATCH and residual bindings")

def expect_equal(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} drift: actual={actual!r} expected={expected!r}")

def unique_op(document, locator, label):
    matches = [
        op for op in document["ops"]
        if op["address"] == {
            "space": 3,
            "space_name": "ram",
            "offset": locator["address_offset"],
        }
        and op["opcode"] == locator["opcode"]
        and len(op["inputs"]) == locator["input_count"]
    ]
    if len(matches) != 1:
        raise SystemExit(f"{label} locator selected {len(matches)} ops")
    return matches[0]

def varnode_by_id(document, varnode_id, label):
    matches = [vn for vn in document["varnodes"] if vn["id"] == varnode_id]
    if len(matches) != 1:
        raise SystemExit(f"{label} selected {len(matches)} varnodes")
    return matches[0]

def storage(vn, include_def=False):
    result = {
        "space": vn["space"],
        "space_name": vn["space_name"],
        "offset": vn["offset"],
        "size": vn["size"],
    }
    if include_def:
        result["def"] = vn["def"]
    return result

char_spec = focused["char_zero_read_facing"]
token_spec = focused["short_circuit_character_token"]
focused_records = {}
for producer in ("ghidra", "rugra"):
    action = documents[producer]["03_action_ir"]
    guard = unique_op(action, char_spec["locator"]["value_pointer_guard"],
                      f"{producer} pointer guard")
    load = unique_op(action, char_spec["locator"]["character_load"],
                     f"{producer} character load")
    compare = unique_op(action, char_spec["locator"]["character_compare"],
                        f"{producer} character compare")
    branch = unique_op(action, char_spec["locator"]["consumer_branch"],
                       f"{producer} consumer branch")

    value_pointer_id = guard["inputs"][0]
    expect_equal(f"{producer} LOAD pointer identity", load["inputs"][1], value_pointer_id)
    value_pointer = varnode_by_id(action, value_pointer_id, f"{producer} value pointer")
    expect_equal(f"{producer} value pointer storage", storage(value_pointer),
                 char_spec["value_pointer_storage"])

    pointer_zero = varnode_by_id(action, guard["inputs"][1], f"{producer} pointer zero")
    expect_equal(f"{producer} pointer zero", storage(pointer_zero, True),
                 char_spec["pointer_zero_storage"])

    expect_equal(f"{producer} compare input defined directly by LOAD",
                 compare["inputs"][0], load["output"])
    loaded_char = varnode_by_id(action, compare["inputs"][0], f"{producer} loaded char")
    expect_equal(f"{producer} loaded char defining op", loaded_char["def"], load["id"])
    expect_equal(f"{producer} loaded char stored type", loaded_char["type"],
                 char_spec["stored_character_type"])

    char_zero = varnode_by_id(action, compare["inputs"][1], f"{producer} character zero")
    expect_equal(f"{producer} character zero storage", storage(char_zero, True),
                 char_spec["character_zero_storage"])
    expect_equal(f"{producer} character zero stored type", char_zero["type"],
                 char_spec["stored_character_type"])
    expect_equal(f"{producer} read-facing input types",
                 compare["input_high_read_types"], char_spec["input_high_read_types"])
    expect_equal(f"{producer} compare output branch slot",
                 branch["inputs"][1], compare["output"])

    expected_line = token_spec["producer_lines"][producer]
    c_text = documents[producer]["05_c"]["text"]
    line_count = c_text.splitlines().count(expected_line)
    expect_equal(f"{producer} exact short-circuit character line count", line_count, 1)
    focused_records[producer] = {
        "value_pointer_varnode": value_pointer_id,
        "pointer_guard_op": guard["id"],
        "character_load_op": load["id"],
        "character_compare_op": compare["id"],
        "consumer_branch_op": branch["id"],
        "input_high_read_types": compare["input_high_read_types"],
        "condition_line": expected_line,
    }

focused_projection_report = {
    "state": "MATCH",
    "char_zero_read_facing": "MATCH",
    "short_circuit_character_token": "MATCH",
    "producer_records": focused_records,
    "role_projection": token_spec["role_projection"],
    "normalization": token_spec["normalization"],
    "does_not_override_overall_status": True,
    "residual_ids": focused["residual_ids"],
}

first = stage_report[0]["first_difference"]
expected_first = metadata["observation"]["first_difference"]
if first != {
    "path": expected_first["path"],
    "kind": "value",
    "ghidra": expected_first["ghidra"],
    "rugra": expected_first["rugra"],
}:
    raise SystemExit(f"first pipeline difference changed: {first}")

ghidra_ops = documents["ghidra"]["00_raw_pcode"]["ops"]
rudra_ops = documents["rugra"]["00_raw_pcode"]["ops"]
substantive = None
for index, (left, right) in enumerate(zip(ghidra_ops, rudra_ops)):
    left_key = (left["address"]["offset"], left["opcode"], len(left["inputs"]))
    right_key = (right["address"]["offset"], right["opcode"], len(right["inputs"]))
    if left_key != right_key:
        substantive = {
            "index": index,
            "ghidra": {"address": left_key[0], "opcode": left_key[1], "input_count": left_key[2]},
            "rugra": {"address": right_key[0], "opcode": right_key[1], "input_count": right_key[2]},
        }
        break
expected_substantive = metadata["observation"]["first_substantive_op_difference"]
if expected_substantive is not None or substantive is not None:
    raise SystemExit(f"numeric op signature sequence changed: {substantive}")

def varnode_location(document, varnode_id):
    if varnode_id is None:
        return None
    varnode = document["varnodes"][varnode_id]
    return {
        "space": varnode["space"],
        "offset": varnode["offset"],
        "size": varnode["size"],
        "pointer_ref_kind": varnode["pointer_ref_kind"],
    }

storage_difference = None
for index, (left, right) in enumerate(zip(ghidra_ops, rudra_ops)):
    left_storage = {
        "output": varnode_location(documents["ghidra"]["00_raw_pcode"], left["output"]),
        "inputs": [
            varnode_location(documents["ghidra"]["00_raw_pcode"], item)
            for item in left["inputs"]
        ],
    }
    right_storage = {
        "output": varnode_location(documents["rugra"]["00_raw_pcode"], right["output"]),
        "inputs": [
            varnode_location(documents["rugra"]["00_raw_pcode"], item)
            for item in right["inputs"]
        ],
    }
    if left_storage != right_storage:
        storage_difference = {
            "index": index,
            "ghidra": left_storage,
            "rugra": right_storage,
        }
        break
expected_storage = metadata["observation"]["first_op_storage_difference"]
for key in ("index", "ghidra", "rugra"):
    if storage_difference[key] != expected_storage[key]:
        raise SystemExit(f"op storage difference changed: {storage_difference}")
storage_difference["diagnosis"] = expected_storage["diagnosis"]

varnode_state_difference = None
for index, (left, right) in enumerate(
    zip(
        documents["ghidra"]["00_raw_pcode"]["varnodes"],
        documents["rugra"]["00_raw_pcode"]["varnodes"],
    )
):
    left_state = {"flags": left["flags"], "type": left["type"]}
    right_state = {"flags": right["flags"], "type": right["type"]}
    if left_state != right_state:
        varnode_state_difference = {
            "index": index,
            "ghidra": left_state,
            "rugra": right_state,
        }
        break
expected_varnode_state = metadata["observation"]["first_varnode_state_difference"]
if expected_varnode_state is None:
    if varnode_state_difference is not None:
        raise SystemExit(f"varnode state difference changed: {varnode_state_difference}")
else:
    if varnode_state_difference is None:
        raise SystemExit("expected a Varnode-state difference but raw states now match")
    for key in ("index", "ghidra", "rugra"):
        if varnode_state_difference[key] != expected_varnode_state[key]:
            raise SystemExit(f"varnode state difference changed: {varnode_state_difference}")
    varnode_state_difference["diagnosis"] = expected_varnode_state["diagnosis"]

repeat_documents = {}
repeat_report = []
for stage in stage_names:
    path = root / "rudra-repeat" / f"{stage}.json"
    repeat = json.loads(path.read_text(encoding="utf-8"))
    repeat_documents[stage] = repeat
    difference = first_difference(
        documents["rugra"][stage], repeat, left_label="primary", right_label="repeat"
    )
    repeat_report.append(
        {
            "stage": stage,
            "first_difference": difference,
            "primary": counts(documents["rugra"][stage]),
            "repeat": counts(repeat),
        }
    )
first_repeat_difference = next(
    (item for item in repeat_report if item["first_difference"] is not None), None
)
if first_repeat_difference is not None:
    raise SystemExit(f"Rudra layered snapshot is unexpectedly nondeterministic: {first_repeat_difference}")

manifest_diff = json.loads((root / "stage-manifest-diff.json").read_text(encoding="utf-8"))
comparison = {
    "schema": 1,
    "state": "MISMATCH",
    "fixture_id": metadata["fixture_id"],
    "oracle": metadata["oracle"],
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "input_fingerprint": metadata["input_fingerprint"],
    "first_stage_difference": {"stage": stage_names[0], **first},
    "numeric_op_signature_sequence": {
        "state": "MATCH",
        "ops": len(ghidra_ops),
        "fields": ["address.offset", "opcode", "input_count", "has_output"],
    },
    "first_op_storage_difference": storage_difference,
    "first_varnode_state_difference": varnode_state_difference,
    "focused_projections": focused_projection_report,
    "stages": stage_report,
    "rudra_determinism": {
        "state": "STABLE_TWO_RUNS",
        "first_difference": first_repeat_difference,
        "runs": repeat_report,
        "note": metadata["observation"]["rugra_determinism_note"],
    },
    "manifest_comparison": manifest_diff,
    "limitations": metadata["observation"]["untested"],
}
(root / "comparison.json").write_text(
    json.dumps(comparison, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
(root / "ghidra.c").write_text(documents["ghidra"]["05_c"]["text"], encoding="utf-8")
(root / "rudra.c").write_text(documents["rugra"]["05_c"]["text"], encoding="utf-8")
(root / "rudra-repeat.c").write_text(
    repeat_documents["05_c"]["text"], encoding="utf-8"
)

summary = [
    "# GetStr layered pipeline snapshot",
    "",
    "- Oracle: Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`",
    "- Input: `examples/curl`, `GetStr` at `0x36d0`, 74 bytes",
    "- Overall: `MISMATCH`",
    f"- First difference: `{stage_names[0]}` `{first['path']}` = {first['ghidra']} vs {first['rudra']}",
    f"- Numeric op signature sequence: `MATCH` ({len(ghidra_ops)} ops)",
    f"- First op-storage difference: index {storage_difference['index']}",
    f"- Storage diagnosis: {storage_difference['diagnosis']}",
    (
        f"- First Varnode-state difference: index {varnode_state_difference['index']}"
        if varnode_state_difference is not None
        else "- First Varnode-state difference: none across 272 ordered raw nodes"
    ),
    f"- Rudra repeatability: {comparison['rudra_determinism']['state']}",
    "- Focused char read-facing/token projection: `MATCH` (overall remains `MISMATCH`)",
    "",
    "| Stage | Ghidra | Rudra | First structural difference |",
    "|---|---:|---:|---|",
]
for item in stage_report:
    left = ", ".join(f"{key}={value}" for key, value in item["ghidra"].items()) or "envelope"
    right = ", ".join(f"{key}={value}" for key, value in item["rugra"].items()) or "envelope"
    summary.append(f"| `{item['stage']}` | {left} | {right} | `{item['first_difference']['path']}` |")
(root / "README.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
PY

printf 'getstr_pipeline_1204: overall=MISMATCH; focused char read-facing/token=MATCH; reachable raw signature MATCH 103 ops; raw Varnode flags/types MATCH 272 nodes; first storage diff=CALL fspec; Rudra two-run snapshot stable; artifacts=%s\n' "$output_root"
