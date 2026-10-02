#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_dir="$repo_root/tests/oracle/program_flow_metadata_1204"
metadata="$repo_root/tests/oracle/program_flow_metadata_1204.metadata.json"
assembly="$fixture_dir/program_flow_metadata_1204.S"
ghidra_script="$fixture_dir/ProgramFlowMetadata1204.java"

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_version=12.0.4
release_asset=ghidra_12.0.4_PUBLIC_20260303.zip
release_sha256=c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120
release_page_url="https://github.com/NationalSecurityAgency/ghidra/releases/tag/$oracle_tag"
release_url="https://github.com/NationalSecurityAgency/ghidra/releases/download/$oracle_tag/$release_asset"
cache_root=${RUDRA_PROGRAM_FLOW_GHIDRA_CACHE:-/tmp/rudra-program-flow-ghidra-1204}
release_zip="$cache_root/$release_asset"
update_expected=0

if [[ ${1:-} == --update-expected ]]; then
  update_expected=1
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $0 [--update-expected]" >&2
  exit 2
fi

die() {
  echo "run_program_flow_metadata_oracle: $*" >&2
  exit 1
}

actual_commit=$(git -C "$repo_root/ghidra" rev-parse HEAD)
tag_commit=$(git -C "$repo_root/ghidra" rev-parse "refs/tags/$oracle_tag^{commit}")
[[ "$actual_commit" == "$oracle_commit" ]] || \
  die "Ghidra HEAD=$actual_commit; expected $oracle_commit"
[[ "$tag_commit" == "$oracle_commit" ]] || \
  die "$oracle_tag resolves to $tag_commit; expected $oracle_commit"

oracle_java_files=(
  Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/SharedReturnAnalyzer.java
  Ghidra/Features/Base/src/main/java/ghidra/app/cmd/analysis/SharedReturnAnalysisCmd.java
  Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/NoReturnFunctionAnalyzer.java
  Ghidra/Features/Base/src/main/java/ghidra/app/cmd/disassemble/SetFlowOverrideCmd.java
  Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/InstructionPcodeOverride.java
)
for oracle_file in "${oracle_java_files[@]}"; do
  git -C "$repo_root/ghidra" diff --quiet -- "$oracle_file" || \
    die "dirty locked oracle file: $oracle_file"
done

for required in curl sha256sum unzip as ld readelf python3; do
  command -v "$required" >/dev/null 2>&1 || die "missing required tool: $required"
done

runtime_tmp_root=${RUDRA_PROGRAM_FLOW_RUNTIME_TMP:-/var/tmp}
[[ -d "$runtime_tmp_root" && -w "$runtime_tmp_root" ]] || \
  die "runtime temp root is not writable: $runtime_tmp_root"
fixture_tmp=$(mktemp -d "$runtime_tmp_root/rudra-program-flow-metadata-1204.XXXXXX")
cleanup() {
  if [[ ${RUDRA_KEEP_TMP:-0} == 1 ]]; then
    echo "preserving fixture temp directory: $fixture_tmp" >&2
    return
  fi
  case "$fixture_tmp" in
    "$runtime_tmp_root"/rudra-program-flow-metadata-1204.??????) rm -rf -- "$fixture_tmp" ;;
    *) echo "refusing unsafe cleanup target: $fixture_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$cache_root"
[[ -d "$cache_root" && ! -L "$cache_root" ]] || \
  die "release cache root must be a real directory: $cache_root"
if [[ -L "$release_zip" || ( -e "$release_zip" && ! -f "$release_zip" ) ]]; then
  die "cached release must be a regular non-symlink file: $release_zip"
fi
if [[ ! -e "$release_zip" ]]; then
  download="$fixture_tmp/$release_asset.download"
  curl -fL --retry 5 --retry-all-errors -o "$download" "$release_url"
  actual_partial_sha=$(sha256sum "$download" | cut -d' ' -f1)
  [[ "$actual_partial_sha" == "$release_sha256" ]] || \
    die "official release SHA-256=$actual_partial_sha; expected $release_sha256"
  mv "$download" "$release_zip"
fi
actual_release_sha=$(sha256sum "$release_zip" | cut -d' ' -f1)
if [[ "$actual_release_sha" != "$release_sha256" ]]; then
  mv "$release_zip" "$fixture_tmp/$release_asset.invalid"
  die "official release SHA-256=$actual_release_sha; expected $release_sha256; invalid cache entry removed"
fi
unexpected_cache=$(find "$cache_root" -mindepth 1 -maxdepth 1 \
  ! -name "$release_asset" -printf '%f\n' | sort)
[[ -z "$unexpected_cache" ]] || \
  die "release cache must contain only the verified zip; unexpected: $unexpected_cache"

zip_roots=$(unzip -Z1 "$release_zip" | sed 's,/.*,,g' | sort -u)
[[ "$zip_roots" == ghidra_12.0.4_PUBLIC ]] || \
  die "release archive root is not exactly ghidra_12.0.4_PUBLIC: $zip_roots"
release_unpack="$fixture_tmp/official-release"
mkdir -p "$release_unpack"
unzip -q "$release_zip" -d "$release_unpack"
post_extract_release_sha=$(sha256sum "$release_zip" | cut -d' ' -f1)
[[ "$post_extract_release_sha" == "$release_sha256" ]] || \
  die "official release changed while extracting: $post_extract_release_sha"
dist_root="$release_unpack/ghidra_12.0.4_PUBLIC"
headless="$dist_root/support/analyzeHeadless"
[[ -x "$headless" ]] || die "analyzeHeadless missing after verified release extraction"
application_properties="$dist_root/Ghidra/application.properties"
[[ -f "$application_properties" ]] || die "application.properties missing"
actual_version=$(sed -n 's/^application\.version=//p' "$application_properties" | tr -d '[:space:]')
actual_release_name=$(sed -n 's/^application\.release\.name=//p' "$application_properties" | tr -d '[:space:]')
actual_revision=$(sed -n 's/^application\.revision\.ghidra=//p' "$application_properties" | tr -d '[:space:]')
[[ "$actual_version" == "$ghidra_version" ]] || \
  die "distribution version=$actual_version; expected $ghidra_version"
[[ "$actual_release_name" == PUBLIC ]] || \
  die "distribution release name=$actual_release_name; expected PUBLIC"
[[ "$actual_revision" == "$oracle_commit" ]] || \
  die "distribution Ghidra revision=$actual_revision; expected $oracle_commit"
if rg -q '12\.1' "$application_properties"; then
  die "12.1.x marker found in locked 12.0.4 application.properties"
fi

as --64 -o "$fixture_tmp/program_flow_metadata_1204.o" "$assembly"
ld -m elf_x86_64 -nostdlib -static --build-id=none -e _start \
  -Ttext=0x401000 -o "$fixture_tmp/program_flow_metadata_1204.elf" \
  "$fixture_tmp/program_flow_metadata_1204.o"

elf="$fixture_tmp/program_flow_metadata_1204.elf"
object_file="$fixture_tmp/program_flow_metadata_1204.o"
elf_sha=$(sha256sum "$elf" | cut -d' ' -f1)
object_sha=$(sha256sum "$object_file" | cut -d' ' -f1)
assembly_sha=$(sha256sum "$assembly" | cut -d' ' -f1)
script_sha=$(sha256sum "$ghidra_script" | cut -d' ' -f1)
runner_sha=$(sha256sum "$repo_root/tools/run_program_flow_metadata_oracle.sh" | cut -d' ' -f1)
assembler_version=$(as --version | head -1)
linker_version=$(ld --version | head -1)
elf_header=$(readelf -hW "$elf" | sed -n \
  -e 's/^[[:space:]]*Class:[[:space:]]*/Class=/p' \
  -e 's/^[[:space:]]*Data:[[:space:]]*/Data=/p' \
  -e 's/^[[:space:]]*Machine:[[:space:]]*/Machine=/p' \
  -e 's/^[[:space:]]*Entry point address:[[:space:]]*/Entry=/p' | paste -sd ';' -)

canonicalize() {
  local raw=$1
  local output=$2
  local lane=$3
  python3 -I -S - "$raw" "$output" "$lane" "$metadata" \
    "$release_asset" "$release_url" "$release_sha256" "$oracle_tag" \
    "$oracle_commit" "$ghidra_version" "$assembly_sha" "$object_sha" \
    "$elf_sha" "$assembler_version" "$linker_version" "$elf_header" \
    "$actual_release_name" "$actual_revision" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    raw_name,
    output_name,
    lane,
    metadata_name,
    release_asset,
    release_url,
    release_sha256,
    oracle_tag,
    oracle_commit,
    ghidra_version,
    assembly_sha256,
    object_sha256,
    elf_sha256,
    assembler,
    linker,
    elf_header,
    application_release_name,
    application_revision_ghidra,
) = sys.argv[1:]

raw = json.loads(pathlib.Path(raw_name).read_text(encoding="utf-8"))
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if raw["fixture_id"] != metadata["fixture_id"] or raw["lane"] != lane:
    raise SystemExit("raw fixture identity/lane mismatch")
if raw["oracle"] != {
    "tag": oracle_tag,
    "commit": oracle_commit,
    "ghidra_version": ghidra_version,
}:
    raise SystemExit("raw locked oracle identity mismatch")

provenance = {
    "official_release": {
        "repository": "NationalSecurityAgency/ghidra",
        "tag": oracle_tag,
        "asset": release_asset,
        "url": release_url,
        "sha256": release_sha256,
        "version": ghidra_version,
        "release_name": application_release_name,
        "revision_ghidra": application_revision_ghidra,
    },
    "input": {
        "assembly_sha256": assembly_sha256,
        "object_sha256": object_sha256,
        "elf_sha256": elf_sha256,
        "elf_header": elf_header.split(";"),
    },
    "toolchain": {
        "assembler": assembler,
        "assembler_flags": ["--64"],
        "linker": linker,
        "linker_flags": [
            "-m", "elf_x86_64", "-nostdlib", "-static", "--build-id=none",
            "-e", "_start", "-Ttext=0x401000",
        ],
    },
    "headless": {
        "processor": "x86:LE:64:default",
        "compiler_spec": "gcc",
        "target_analyzers_disabled_in_prescript": [
            "Non-Returning Functions - Known",
            "Shared Return Calls",
        ],
        "fresh_project_per_lane": True,
    },
}
fingerprint_input = {
    "architecture": raw["program"]["language_id"],
    "compiler_spec": raw["program"]["compiler_spec_id"],
    "image_base": raw["program"]["image_base"],
    "lane": lane,
    "analysis_options": metadata["analysis_options"],
    "input": provenance["input"],
    "toolchain": provenance["toolchain"],
}
encoded = json.dumps(
    fingerprint_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
raw["provenance"] = provenance
raw["input_fingerprint"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
pathlib.Path(output_name).write_text(
    json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)
PY
}

run_lane_once() {
  local lane=$1
  local repeat=$2
  local raw="$fixture_tmp/$lane.$repeat.raw.json"
  local canonical="$fixture_tmp/$lane.$repeat.json"
  local project_dir="$fixture_tmp/projects-$lane-$repeat"
  mkdir -p "$project_dir"
  "$headless" "$project_dir" "program_flow_${lane}_${repeat}" \
    -import "$elf" -overwrite \
    -processor x86:LE:64:default -cspec gcc \
    -scriptPath "$fixture_dir" \
    -preScript ProgramFlowMetadata1204.java configure \
    -postScript ProgramFlowMetadata1204.java capture "$lane" "$raw" \
    -deleteProject >"$fixture_tmp/$lane.$repeat.headless.log" 2>&1
  [[ -s "$raw" ]] || die "$lane repeat $repeat produced no raw capture"
  canonicalize "$raw" "$canonical" "$lane"
}

for lane in direct_only conditional_enabled; do
  run_lane_once "$lane" 1
  run_lane_once "$lane" 2
  diff -u "$fixture_tmp/$lane.1.json" "$fixture_tmp/$lane.2.json" || \
    die "$lane is not byte-reproducible across fresh projects"
  expected="$fixture_dir/expected/$lane.json"
  if [[ $update_expected -eq 1 ]]; then
    mkdir -p "$fixture_dir/expected"
    cp "$fixture_tmp/$lane.1.json" "$expected"
  else
    [[ -f "$expected" ]] || die "missing expected capture: $expected"
    diff -u "$expected" "$fixture_tmp/$lane.1.json"
  fi
done

if [[ $update_expected -eq 0 ]]; then
  python3 -I -S - "$metadata" "$assembly" "$ghidra_script" \
    "$repo_root/tools/run_program_flow_metadata_oracle.sh" \
    "$fixture_dir/expected/direct_only.json" \
    "$fixture_dir/expected/conditional_enabled.json" "$elf_sha" "$object_sha" \
    "$assembler_version" "$linker_version" "$release_page_url" \
    "$release_asset" "$release_url" "$release_sha256" "$oracle_tag" \
    "$oracle_commit" "$ghidra_version" "$actual_release_name" \
    "$actual_revision" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_name,
    assembly_name,
    script_name,
    runner_name,
    direct_name,
    conditional_name,
    elf_sha,
    object_sha,
    assembler,
    linker,
    release_page_url,
    release_asset,
    release_url,
    release_sha256,
    oracle_tag,
    oracle_commit,
    ghidra_version,
    application_release_name,
    application_revision_ghidra,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))

def check_fields(path, actual_value, expected_value):
    if isinstance(expected_value, dict):
        if not isinstance(actual_value, dict):
            raise SystemExit(f"metadata {path} is not an object")
        if set(actual_value) != set(expected_value):
            raise SystemExit(
                f"metadata {path} field set mismatch: "
                f"actual={sorted(actual_value)} expected={sorted(expected_value)}"
            )
        for key, value in expected_value.items():
            check_fields(f"{path}.{key}", actual_value[key], value)
        return
    if isinstance(expected_value, list):
        if not isinstance(actual_value, list) or len(actual_value) != len(expected_value):
            raise SystemExit(f"metadata {path} list shape mismatch")
        for index, value in enumerate(expected_value):
            check_fields(f"{path}[{index}]", actual_value[index], value)
        return
    if actual_value != expected_value:
        raise SystemExit(
            f"metadata {path}={actual_value!r}; expected {expected_value!r}"
        )

check_fields("oracle", metadata.get("oracle"), {
    "tag": oracle_tag,
    "commit": oracle_commit,
    "version": ghidra_version,
})
check_fields("architecture", metadata.get("architecture"), "x86:LE:64:default")
check_fields("compiler_spec", metadata.get("compiler_spec"), "gcc")
check_fields("analysis_options", metadata.get("analysis_options"), {
    "baseline_disabled": [
        "Non-Returning Functions - Known",
        "Shared Return Calls",
    ],
    "manual_order": [
        "Non-Returning Functions - Known",
        "Shared Return Calls",
    ],
    "known_no_return": {"Create Analysis Bookmarks": True},
    "shared_return_common": {"Assume Contiguous Functions Only": True},
    "lanes": {
        "direct_only": {"Allow Conditional Jumps": False},
        "conditional_enabled": {"Allow Conditional Jumps": True},
    },
})
check_fields("official_release", metadata.get("official_release"), {
    "repository": "NationalSecurityAgency/ghidra",
    "release_url": release_page_url,
    "asset": release_asset,
    "asset_url": release_url,
    "asset_sha256": release_sha256,
    "application_version": ghidra_version,
    "application_release_name": application_release_name,
    "application_revision_ghidra": application_revision_ghidra,
    "digest_source": "GitHub release expanded-assets response",
})
check_fields(
    "observation.overall_status",
    metadata.get("observation", {}).get("overall_status"),
    "UNTESTED",
)
check_fields(
    "observation.covered_projection_status",
    metadata.get("observation", {}).get("covered_projection_status"),
    "ORACLE_CAPTURED",
)

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

actual = {
    "assembly": digest(assembly_name),
    "ghidra_script": digest(script_name),
    "runner": digest(runner_name),
    "direct_only_expected": digest(direct_name),
    "conditional_enabled_expected": digest(conditional_name),
}
if metadata["comparand_sha256"] != actual:
    raise SystemExit(f"comparand SHA mismatch: expected={metadata['comparand_sha256']} actual={actual}")
expected = metadata["expected"]
checks = {
    "direct_only_sha256": actual["direct_only_expected"],
    "conditional_enabled_sha256": actual["conditional_enabled_expected"],
    "generated_elf_sha256": elf_sha,
    "generated_object_sha256": object_sha,
    "assembler": assembler,
    "linker": linker,
}
if expected != checks:
    raise SystemExit(f"expected provenance mismatch: expected={expected} actual={checks}")

fingerprints = []
for path in (direct_name, conditional_name):
    capture = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    fingerprints.append(capture["input_fingerprint"])
fingerprint_doc = {
    "direct_only": fingerprints[0],
    "conditional_enabled": fingerprints[1],
}
encoded = json.dumps(
    fingerprint_doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
combined = "sha256:" + hashlib.sha256(encoded).hexdigest()
if metadata["input_fingerprint"] != combined:
    raise SystemExit(f"combined input fingerprint mismatch: {combined}")
PY
fi

echo "PROGRAM-FLOW-METADATA-FIXTURE-0001: OK"
echo "oracle=$oracle_tag@$oracle_commit version=$actual_version revision=$actual_revision asset_sha256=$actual_release_sha"
echo "elf_sha256=$elf_sha object_sha256=$object_sha"
echo "lanes=direct_only,conditional_enabled repeats=2 overall_status=UNTESTED covered_projection=ORACLE_CAPTURED"
