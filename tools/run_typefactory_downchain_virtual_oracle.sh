#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
# Locked bilateral runner for TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001.
#
# --ghidra-only builds and runs the locked C++ oracle while candidate/output
# pins remain pending. Normal mode builds a complete git archive of the frozen
# Rudra production commit. No live Rust production source is copied or read by
# Cargo; the standalone fixture is compiled separately against the exact
# artifacts reported by that Cargo invocation.
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
runner="$repo_root/tools/run_typefactory_downchain_virtual_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
runner_mode=$(/usr/bin/stat -Lc '%a' "$runner_fd_path")
if [[ "$runner_mode" != 755 ]]; then
  echo "immutable runner mode mismatch: expected=755 actual=$runner_mode" >&2
  exit 1
fi

ghidra_only=false
if [[ ${1:-} == "--ghidra-only" ]]; then
  ghidra_only=true
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $runner [--ghidra-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=3c16f4fc11a24f7f3fb0676b49a657d6f1f492c4
ghidra_root=$(/usr/bin/readlink -f "$repo_root/ghidra")
metadata="$repo_root/tests/oracle/typefactory_downchain_virtual_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/typefactory_downchain_virtual_1204.cc"
rust_fixture="$repo_root/tests/oracle/typefactory_downchain_virtual_1204.rs"
cargo_target_root=/home/wirs/.cache/rudra-a7-dcv-target
compiler_tmp=/home/wirs/.cache/rudra-a7-dcv-tmp
cargo_build_lock=/tmp/rudra-cargo-build.lock
artifact_parent=/home/wirs/.cache/rudra-a7-dcv-artifacts

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
expected_host_cargo_sha=131c52b36a4aa4016a1c5e8478ed232a349f2e2d5a9fc4110f3f69f2d61b9e93
expected_host_rustc_sha=060916a7ed17951343fb461ad068179a56a33eb675910f1d7d7ab738fed3b618
expected_host_cxx_sha=f04191f6a7b2cd7d9a62e1745872b8a6088791e5af6955488c69c9b2c4668bc9
expected_host_cargo_version_sha=62d278ffb732aa9b6ac09108cbcea47dd24d6221c5c63f6d942784ca419cb9fc
expected_host_rustc_version_sha=3b56b3021e5f91088c797c1d6ba31cc6e4a2170670446d47f883b91407e66768
expected_host_cxx_version_sha=ddba3d014b73deb2a8869cad4ab507e29a48630c8cd280adf2559e0e10891d23
for tool in "$host_cxx" "$host_make" "$host_git" "$host_python" \
  "$host_cargo" "$host_rustc" "$host_tar" /usr/bin/flock; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
verify_host_tool() {
  local label=$1
  local tool=$2
  local expected_path=$3
  local expected_sha=$4
  local expected_version_sha=$5
  shift 5
  if [[ "$tool" != "$expected_path" || -L "$tool" ]]; then
    echo "pinned $label path mismatch: expected=$expected_path actual=$tool" >&2
    exit 1
  fi
  local actual_sha
  actual_sha=$(/usr/bin/sha256sum "$tool" | /usr/bin/awk '{print $1}')
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "pinned $label executable hash mismatch" >&2
    exit 1
  fi
  local actual_version_sha
  actual_version_sha=$(
    /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$tool" "$@" |
      /usr/bin/sha256sum | /usr/bin/awk '{print $1}'
  )
  if [[ "$actual_version_sha" != "$expected_version_sha" ]]; then
    echo "pinned $label version output mismatch" >&2
    exit 1
  fi
}
verify_host_tool cargo "$host_cargo" /usr/bin/cargo \
  "$expected_host_cargo_sha" "$expected_host_cargo_version_sha" \
  --version --verbose
verify_host_tool rustc "$host_rustc" /usr/bin/rustc \
  "$expected_host_rustc_sha" "$expected_host_rustc_version_sha" \
  --version --verbose
verify_host_tool g++ "$host_cxx" /usr/bin/g++ \
  "$expected_host_cxx_sha" "$expected_host_cxx_version_sha" --version
for file in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$file" || -L "$file" ]]; then
    echo "required input is a regular non-symlink file: $file" >&2
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
actual_base=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
if [[ "$actual_base" != "$rudra_base_commit" ]]; then
  echo "pinned Rudra baseline is unavailable" >&2
  exit 1
fi

/usr/bin/mkdir -p "$cargo_target_root" "$compiler_tmp" "$artifact_parent"
for persistent_dir in "$cargo_target_root" "$compiler_tmp" "$artifact_parent"; do
  if [[ ! -d "$persistent_dir" || -L "$persistent_dir" ]]; then
    echo "persistent runner path is not a regular directory: $persistent_dir" >&2
    exit 1
  fi
done
oracle_tmp=$(/usr/bin/mktemp -d "$cargo_target_root/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    /home/wirs/.cache/rudra-a7-dcv-target/run.??????)
      /usr/bin/rm -rf -- "$oracle_tmp"
      ;;
    *)
      echo "refusing unsafe cleanup target: $oracle_tmp" >&2
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

publish_snapshot() {
  local staged=$1
  local final=$2
  shift 2
  if [[ ! -e "$final" && ! -L "$final" ]]; then
    if /usr/bin/mv -T -- "$staged" "$final" 2>/dev/null; then
      return 0
    fi
  fi
  if [[ ! -d "$final" || -L "$final" ]]; then
    echo "artifact destination is not a completed regular directory: $final" >&2
    return 1
  fi
  local relative
  for relative in "$@"; do
    if [[ ! -f "$final/$relative" || -L "$final/$relative" ]] || \
       ! /usr/bin/cmp -s "$staged/$relative" "$final/$relative"; then
      echo "existing artifact is incomplete or differs: $final/$relative" >&2
      return 1
    fi
  done
}

verify_tree_manifest_safety() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
    "$1" "$2" <<'PY'
import pathlib
import sys

entries = pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
label = sys.argv[2]
paths = set()
for raw in entries:
    if not raw:
        continue
    metadata, encoded_path = raw.split(b"\t", 1)
    mode, kind, _ = metadata.decode("ascii").split()
    path = encoded_path.decode("utf-8")
    pure_path = pathlib.PurePosixPath(path)
    if kind != "blob" or mode not in {"100644", "100755"}:
        raise SystemExit(f"unsupported {label} tree entry: {mode} {kind} {path}")
    if pure_path.is_absolute() or ".." in pure_path.parts or not pure_path.parts:
        raise SystemExit(f"unsafe {label} tree path: {path!r}")
    if path in paths:
        raise SystemExit(f"duplicate {label} tree path: {path!r}")
    paths.add(path)
if not paths:
    raise SystemExit(f"empty {label} tree manifest")
PY
}

oracle_source_root="$oracle_tmp/ghidra-source"
/usr/bin/mkdir -p "$oracle_source_root"
oracle_tree_manifest="$oracle_tmp/ghidra-cpp-tree.manifest"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" ls-tree -rz \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp" \
  >"$oracle_tree_manifest"
verify_tree_manifest_safety "$oracle_tree_manifest" "locked cpp"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_tar" -xf - \
    -C "$oracle_source_root"
oracle_cpp="$oracle_source_root/Ghidra/Features/Decompiler/src/decompile/cpp"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$oracle_tree_manifest" "$oracle_cpp" <<'PY'
import hashlib
import pathlib
import stat
import sys

manifest = pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
root = pathlib.Path(sys.argv[2])
expected = set()
for raw in manifest:
    if not raw:
        continue
    metadata, encoded_path = raw.split(b"\t", 1)
    mode, kind, oid = metadata.decode("ascii").split()
    path = encoded_path.decode("utf-8")
    if kind != "blob" or mode not in {"100644", "100755"}:
        raise SystemExit(f"unsupported locked cpp tree entry: {mode} {kind} {path}")
    if pathlib.PurePosixPath(path).is_absolute() or ".." in pathlib.PurePosixPath(path).parts:
        raise SystemExit(f"unsafe locked cpp tree path: {path}")
    archived = root / path
    if not archived.is_file() or archived.is_symlink():
        raise SystemExit(f"missing/non-regular archived cpp input: {path}")
    executable = bool(archived.stat().st_mode & stat.S_IXUSR)
    if executable != (mode == "100755"):
        raise SystemExit(f"archived cpp mode mismatch: {path} expected={mode}")
    data = archived.read_bytes()
    actual_oid = hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii") + data
    ).hexdigest()
    if actual_oid != oid:
        raise SystemExit(
            f"archived cpp blob mismatch: {path} expected={oid} actual={actual_oid}"
        )
    expected.add(path)
actual = set()
for archived in root.rglob("*"):
    if archived.is_symlink():
        raise SystemExit(f"symlink in archived cpp tree: {archived.relative_to(root)}")
    if archived.is_file():
        actual.add(archived.relative_to(root).as_posix())
if actual != expected:
    raise SystemExit(
        f"archived cpp path-set mismatch: missing={sorted(expected - actual)} "
        f"extra={sorted(actual - expected)}"
    )
PY

/usr/bin/mkdir -p "$oracle_tmp/fixtures"
for fixture in "$metadata" "$cpp_fixture" "$rust_fixture"; do
  /usr/bin/cp -- "$fixture" "$oracle_tmp/fixtures/$(/usr/bin/basename "$fixture")"
done
metadata_snapshot="$oracle_tmp/fixtures/typefactory_downchain_virtual_1204.metadata.json"
cpp_snapshot="$oracle_tmp/fixtures/typefactory_downchain_virtual_1204.cc"
rust_snapshot="$oracle_tmp/fixtures/typefactory_downchain_virtual_1204.rs"

candidate_identity=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python" -I -S - \
  "$metadata_snapshot" "$cpp_snapshot" "$rust_snapshot" \
  "$runner_fd_path" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$rudra_base_commit" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

(
    metadata_name,
    cpp_name,
    rust_name,
    runner_name,
    runner_sha,
    oracle_commit,
    oracle_tag,
    cpp_tree,
    makefile_blob,
    rudra_base_commit,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def require_pin(label, value, pending):
    if value != pending and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None:
        raise SystemExit(f"{label} is neither its pending marker nor a pinned hash: {value!r}")

require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001")
if metadata["covered_projection_status"] not in {"UNTESTED", "MATCH", "MISMATCH"}:
    raise SystemExit("invalid covered projection status")
require("overall status", metadata["overall_status"], metadata["covered_projection_status"])
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)
require("Rudra base", metadata["rugra_base_commit"], rudra_base_commit)
for stable in metadata["oracle"]["stable_functions"]:
    if not stable.startswith("ghidra::"):
        raise SystemExit(f"invalid stable function entry: {stable!r}")
for field in ("architecture", "compiler_spec", "analysis_options", "input_manifest"):
    if not metadata.get(field):
        raise SystemExit(f"missing oracle descriptor: {field}")

expected_host_toolchain = {
    "cargo": {
        "path": "/usr/bin/cargo",
        "sha256": "131c52b36a4aa4016a1c5e8478ed232a349f2e2d5a9fc4110f3f69f2d61b9e93",
        "version": "cargo 1.97.1 (c980f4866 2026-06-30) (Arch Linux rust 1:1.97.1-1)",
        "version_output_sha256": "62d278ffb732aa9b6ac09108cbcea47dd24d6221c5c63f6d942784ca419cb9fc",
    },
    "rustc": {
        "path": "/usr/bin/rustc",
        "sha256": "060916a7ed17951343fb461ad068179a56a33eb675910f1d7d7ab738fed3b618",
        "version": "rustc 1.97.1 (8bab26f4f 2026-07-14) (Arch Linux rust 1:1.97.1-1)",
        "version_output_sha256": "3b56b3021e5f91088c797c1d6ba31cc6e4a2170670446d47f883b91407e66768",
    },
    "cxx": {
        "path": "/usr/bin/g++",
        "sha256": "f04191f6a7b2cd7d9a62e1745872b8a6088791e5af6955488c69c9b2c4668bc9",
        "version": "g++ (GCC) 16.2.1 20260810",
        "version_output_sha256": "ddba3d014b73deb2a8869cad4ab507e29a48630c8cd280adf2559e0e10891d23",
    },
}
toolchain = metadata["host_toolchain"]
for key, expected in expected_host_toolchain.items():
    for field, value in expected.items():
        require(f"host toolchain {key}.{field}", toolchain[key][field], value)
require(
    "Cargo config policy",
    toolchain["cargo_config_policy"],
    "reject config and config.toml in CARGO_HOME and every candidate working-directory ancestor, including the candidate root",
)
if not toolchain.get("unfingerprinted_host_closure"):
    raise SystemExit("host toolchain residual closure must be explicit")

cases = metadata["input_manifest"]["cases"]
require("case count", len(cases), 25)
require("unique case ids", len({case["id"] for case in cases}), 25)
manifest_case_ids = [case["id"] for case in cases]

def extract_fixture_records(path, language):
    source = pathlib.Path(path).read_text(encoding="utf-8")
    if language == "cpp":
        direct_pattern = re.compile(
            r"\bemitDownchain(?:Step)?\s*\(\s*types\s*,\s*\"([^\"]+)\""
        )
    else:
        direct_pattern = re.compile(
            r"\bemit_downchain(?:_step)?\s*\(\s*&mut\s+factory\s*,\s*\"([^\"]+)\""
        )
    found = [
        (match.start(), "downchain", match.group(1))
        for match in direct_pattern.finditer(source)
    ]
    return [(kind, case_id) for _, kind, case_id in sorted(found)]

cpp_records = extract_fixture_records(cpp_name, "cpp")
rust_records = extract_fixture_records(rust_name, "rust")
require("C++ fixture case order", [record[1] for record in cpp_records], manifest_case_ids)
require("Rust fixture case order", [record[1] for record in rust_records], manifest_case_ids)
payload = json.dumps(
    cases,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode()
require(
    "input manifest",
    hashlib.sha256(payload).hexdigest(),
    metadata["input_manifest"]["sha256"],
)
require("expected record count", metadata["build"]["expected_stdout_lines"], 25)
record_kinds = metadata["observation_schema"]["record_kinds_in_manifest_order"]
require("record-kind count", len(record_kinds), 25)
if any(kind != "downchain" for kind in record_kinds):
    raise SystemExit(f"invalid record-kind manifest: {record_kinds!r}")
require("C++ fixture record kinds", [record[0] for record in cpp_records], record_kinds)
require("Rust fixture record kinds", [record[0] for record in rust_records], record_kinds)
comparison = metadata["comparison_policy"]
require("exact difference policy", comparison["require_exact_difference_set"], True)
allowed = comparison["allowed_value_differences"]
require("unique allowed differences", len(allowed), len(set(allowed)))
if metadata["covered_projection_status"] == "MISMATCH":
    if not allowed:
        raise SystemExit("MISMATCH fixture must declare its exact allowed difference set")
    require("observed difference count", comparison["observed_difference_count"], len(allowed))
    if not comparison["observed_differing_cases"]:
        raise SystemExit("MISMATCH fixture must declare its differing cases")
else:
    if allowed:
        raise SystemExit("non-MISMATCH fixture must declare an empty allowed difference set")
    require("observed difference count", comparison["observed_difference_count"], 0)
    require("observed differing cases", comparison["observed_differing_cases"], [])
case_ids = {case["id"] for case in cases}
for difference in allowed:
    if "." not in difference:
        raise SystemExit(f"invalid allowed difference key: {difference!r}")
    case_id, field = difference.split(".", 1)
    if case_id not in case_ids or not field:
        raise SystemExit(f"invalid allowed difference target: {difference!r}")

paths = {
    "cpp_fixture_sha256": pathlib.Path(cpp_name),
    "rust_fixture_sha256": pathlib.Path(rust_name),
    "runner_sha256": pathlib.Path(runner_name),
}
for key, path in paths.items():
    require(
        key,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        metadata["comparand"][key],
    )
require("runner fd hash", runner_sha, metadata["comparand"]["runner_sha256"])

coverage = metadata["coverage"]
for key, entry in coverage.items():
    if entry["status"] not in {"UNTESTED", "MATCH", "MISMATCH"}:
        raise SystemExit(f"invalid coverage status: {key}")
require(
    "candidate snapshot model",
    metadata["rugra_candidate"]["snapshot_model"],
    "git archive of the frozen production commit; no live Rust source overlays",
)

candidate = metadata["rugra_candidate"]
require_pin("candidate commit", candidate["commit"], "PENDING_PRODUCTION_COMMIT")
require_pin("candidate tree", candidate["tree"], "PENDING_PRODUCTION_TREE")
critical = candidate["critical_git_blobs"]
expected_critical = {
    "src/type_system/datatype.rs": "PENDING_DATATYPE_RS_BLOB",
    "src/type_system/typefactory.rs": "PENDING_TYPEFACTORY_RS_BLOB",
    "Cargo.toml": "PENDING_CARGO_TOML_BLOB",
    "Cargo.lock": "PENDING_CARGO_LOCK_BLOB",
    "build.rs": "PENDING_BUILD_RS_BLOB",
}
require("critical blob paths", set(critical), set(expected_critical))
for path, pending in expected_critical.items():
    require_pin(f"critical blob {path}", critical[path], pending)
for key in (
    "datatype_rs_sha256",
    "typefactory_rs_sha256",
    "cargo_toml_sha256",
    "cargo_lock_sha256",
    "build_rs_sha256",
):
    if re.fullmatch(r"[0-9a-f]{64}", metadata["comparand"][key]) is None:
        raise SystemExit(f"invalid comparand SHA-256: {key}")
require_pin(
    "expected Ghidra stdout",
    metadata["comparand"]["expected_ghidra_stdout_sha256"],
    "PENDING_ORACLE_RUN",
)
require_pin(
    "expected Rudra stdout",
    metadata["comparand"]["expected_rudra_stdout_sha256"],
    "PENDING_API_IMPLEMENTATION",
)
require_pin(
    "observed output diff",
    metadata["comparand"]["observed_output_diff_sha256"],
    "PENDING_OUTPUT_DIFF",
)

print(
    "\t".join(
        [
            candidate["commit"],
            candidate["tree"],
            critical["src/type_system/datatype.rs"],
            critical["src/type_system/typefactory.rs"],
            critical["Cargo.toml"],
            critical["Cargo.lock"],
            critical["build.rs"],
        ]
    )
)
PY
)
IFS=$'\t' read -r candidate_commit candidate_tree datatype_blob \
  typefactory_blob cargo_toml_blob cargo_lock_blob build_rs_blob \
  <<< "$candidate_identity"

candidate_root="$oracle_tmp/rudra-candidate"
if ! $ghidra_only; then
  for pin in "$candidate_commit" "$candidate_tree" "$datatype_blob" \
    "$typefactory_blob" "$cargo_toml_blob" "$cargo_lock_blob" "$build_rs_blob"; do
    if [[ "$pin" == PENDING_* ]]; then
      echo "normal mode requires frozen rudra_candidate commit/tree/blob pins" >&2
      exit 1
    fi
  done

  actual_candidate=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" rev-parse "$candidate_commit^{commit}")
  actual_candidate_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" rev-parse "$candidate_commit^{tree}")
  if [[ "$actual_candidate" != "$candidate_commit" || \
        "$actual_candidate_tree" != "$candidate_tree" ]]; then
    echo "frozen Rudra candidate identity mismatch" >&2
    exit 1
  fi
  cargo_target="$oracle_tmp/cargo-target"
  /usr/bin/mkdir -p "$cargo_target"
  if [[ ! -d "$cargo_target" || -L "$cargo_target" ]]; then
    echo "candidate-scoped Cargo target is not a regular directory" >&2
    exit 1
  fi
  for path_and_blob in \
    "src/type_system/datatype.rs:$datatype_blob" \
    "src/type_system/typefactory.rs:$typefactory_blob" \
    "Cargo.toml:$cargo_toml_blob" \
    "Cargo.lock:$cargo_lock_blob" \
    "build.rs:$build_rs_blob"; do
    path=${path_and_blob%%:*}
    expected_blob=${path_and_blob#*:}
    actual_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git" -C "$repo_root" rev-parse "$candidate_commit:$path")
    if [[ "$actual_blob" != "$expected_blob" ]]; then
      echo "frozen candidate blob mismatch: $path" >&2
      exit 1
    fi
  done

  /usr/bin/mkdir -p "$candidate_root"
  candidate_tree_manifest="$oracle_tmp/rudra-candidate-tree.manifest"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" ls-tree -rz "$candidate_commit" \
    >"$candidate_tree_manifest"
  verify_tree_manifest_safety "$candidate_tree_manifest" "frozen candidate"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" archive "$candidate_commit" | \
    /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_tar" -xf - -C "$candidate_root"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
    "$candidate_tree_manifest" "$candidate_root" <<'PY'
import hashlib
import pathlib
import stat
import sys

manifest = pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
root = pathlib.Path(sys.argv[2])
expected = set()
for raw in manifest:
    if not raw:
        continue
    metadata, encoded_path = raw.split(b"\t", 1)
    mode, kind, oid = metadata.decode("ascii").split()
    path = encoded_path.decode("utf-8")
    if kind != "blob" or mode not in {"100644", "100755"}:
        raise SystemExit(
            f"unsupported frozen candidate tree entry: {mode} {kind} {path}"
        )
    pure_path = pathlib.PurePosixPath(path)
    if pure_path.is_absolute() or ".." in pure_path.parts:
        raise SystemExit(f"unsafe frozen candidate path: {path}")
    archived = root / path
    if not archived.is_file() or archived.is_symlink():
        raise SystemExit(f"missing/non-regular archived candidate input: {path}")
    executable = bool(archived.stat().st_mode & stat.S_IXUSR)
    if executable != (mode == "100755"):
        raise SystemExit(
            f"archived candidate mode mismatch: {path} expected={mode}"
        )
    data = archived.read_bytes()
    actual_oid = hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii") + data
    ).hexdigest()
    if actual_oid != oid:
        raise SystemExit(
            f"archived candidate blob mismatch: {path} "
            f"expected={oid} actual={actual_oid}"
        )
    expected.add(path)
actual = set()
for archived in root.rglob("*"):
    if archived.is_symlink():
        raise SystemExit(f"symlink in archived candidate tree: {archived.relative_to(root)}")
    if archived.is_file():
        actual.add(archived.relative_to(root).as_posix())
if actual != expected:
    raise SystemExit(
        f"archived candidate path-set mismatch: missing={sorted(expected - actual)} "
        f"extra={sorted(actual - expected)}"
    )
PY
  for pinned in \
    "$candidate_root/src/type_system/datatype.rs" \
    "$candidate_root/src/type_system/typefactory.rs" \
    "$candidate_root/Cargo.toml" "$candidate_root/Cargo.lock" \
    "$candidate_root/build.rs"; do
    if [[ ! -f "$pinned" || -L "$pinned" ]]; then
      echo "archived candidate input is not a regular file: $pinned" >&2
      exit 1
    fi
  done
  for path_and_blob in \
    "src/type_system/datatype.rs:$datatype_blob" \
    "src/type_system/typefactory.rs:$typefactory_blob" \
    "Cargo.toml:$cargo_toml_blob" \
    "Cargo.lock:$cargo_lock_blob" \
    "build.rs:$build_rs_blob"; do
    path=${path_and_blob%%:*}
    expected_blob=${path_and_blob#*:}
    archived_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
      "$host_git" hash-object --no-filters "$candidate_root/$path")
    if [[ "$archived_blob" != "$expected_blob" ]]; then
      echo "archived candidate blob mismatch: $path" >&2
      exit 1
    fi
  done
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
    "$metadata_snapshot" "$candidate_root" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
root = pathlib.Path(sys.argv[2])
paths = {
    "datatype_rs_sha256": root / "src/type_system/datatype.rs",
    "typefactory_rs_sha256": root / "src/type_system/typefactory.rs",
    "cargo_toml_sha256": root / "Cargo.toml",
    "cargo_lock_sha256": root / "Cargo.lock",
    "build_rs_sha256": root / "build.rs",
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
PY

  if [[ -e "$candidate_root/ghidra" || -L "$candidate_root/ghidra" ]]; then
    echo "candidate archive unexpectedly contains ghidra path" >&2
    exit 1
  fi
  /usr/bin/ln -s "$oracle_source_root" "$candidate_root/ghidra"
fi

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$compiler_tmp" \
  "$host_make" --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$host_cxx -std=c++11" EXTRA= libdecomp.a
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$compiler_tmp" "$host_cxx" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_snapshot" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" -lz \
  -o "$oracle_tmp/typefactory_downchain_virtual_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/typefactory_downchain_virtual_cpp" >"$oracle_tmp/ghidra.stdout" \
  2>"$oracle_tmp/ghidra.stderr"; then
  /usr/bin/sed -n '1,100p' "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  /usr/bin/sed -n '1,100p' "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$metadata_snapshot" "$oracle_tmp/ghidra.stdout" "$ghidra_only" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
output = pathlib.Path(sys.argv[2]).read_bytes()
if not output.endswith(b"\n"):
    raise SystemExit("Ghidra output has no final newline")
try:
    text = output.decode("utf-8")
except UnicodeDecodeError as error:
    raise SystemExit(f"Ghidra output is not UTF-8: {error}")
lines = text[:-1].split("\n")
expected_lines = metadata["build"]["expected_stdout_lines"]
if len(lines) != expected_lines:
    raise SystemExit(
        f"unexpected Ghidra record count: {len(lines)} expected={expected_lines}"
    )
manifest_case_ids = [case["id"] for case in metadata["input_manifest"]["cases"]]
expected_kinds = metadata["observation_schema"]["record_kinds_in_manifest_order"]
for index, line in enumerate(lines):
    parts = line.split("|")
    kind = parts[0]
    if kind != expected_kinds[index]:
        raise SystemExit(
            f"Ghidra record kind mismatch at {index + 1}: "
            f"expected={expected_kinds[index]!r} actual={kind!r}"
        )
    fields = []
    seen = set()
    for segment in parts[1:]:
        if "=" not in segment:
            raise SystemExit(
                f"Ghidra record {index + 1} has malformed field: {segment!r}"
            )
        name, value = segment.split("=", 1)
        if not name or name in seen:
            raise SystemExit(
                f"Ghidra record {index + 1} has empty/duplicate field: {name!r}"
            )
        seen.add(name)
        fields.append((name, value))
    if not fields or fields[0][0] != "case":
        raise SystemExit(f"Ghidra record {index + 1} does not start with case=")
    if fields[0][1] != manifest_case_ids[index]:
        raise SystemExit(
            f"Ghidra record order mismatch at {index + 1}: "
            f"expected={manifest_case_ids[index]!r} actual={fields[0][1]!r}"
        )
actual = hashlib.sha256(output).hexdigest()
expected = metadata["comparand"]["expected_ghidra_stdout_sha256"]
if expected == "PENDING_ORACLE_RUN":
    if sys.argv[3] != "true":
        raise SystemExit(
            f"normal mode requires pinned Ghidra stdout; observed sha256={actual}"
        )
    print(f"oracle_stdout_sha256={actual} pin_required=1")
elif actual != expected:
    raise SystemExit(f"Ghidra stdout fingerprint drift: {actual}")
else:
    print(f"oracle_stdout_sha256={actual} pin_ok=1")
PY

if $ghidra_only; then
  ghidra_output_sha=$(/usr/bin/sha256sum "$oracle_tmp/ghidra.stdout" | \
    /usr/bin/awk '{print $1}')
  metadata_output_sha=$(/usr/bin/sha256sum "$metadata_snapshot" | \
    /usr/bin/awk '{print $1}')
  ghidra_artifact_dir="$artifact_parent/ghidra-$ghidra_output_sha-$metadata_output_sha"
  ghidra_artifact_stage="$oracle_tmp/publish-ghidra"
  /usr/bin/mkdir "$ghidra_artifact_stage"
  /usr/bin/cp -- "$oracle_tmp/ghidra.stdout" \
    "$ghidra_artifact_stage/ghidra.stdout"
  /usr/bin/cp -- "$metadata_snapshot" "$ghidra_artifact_stage/metadata.json"
  /usr/bin/printf \
    'fixture_id=TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001\nkind=ghidra\noracle_commit=%s\nstdout_sha256=%s\nmetadata_sha256=%s\n' \
    "$oracle_commit" "$ghidra_output_sha" "$metadata_output_sha" \
    >"$ghidra_artifact_stage/COMPLETE"
  publish_snapshot "$ghidra_artifact_stage" "$ghidra_artifact_dir" \
    ghidra.stdout metadata.json COMPLETE
  /usr/bin/cat "$oracle_tmp/ghidra.stdout"
  /usr/bin/printf \
    'typefactory_downchain_virtual_1204: ghidra_only records=25 oracle=%s artifacts=%s\n' \
    "$oracle_commit" "$ghidra_artifact_dir"
  exit 0
fi

cargo_home="$user_home/.cargo"
if [[ ! -d "$cargo_home" || -L "$cargo_home" ]]; then
  echo "Cargo home is not a regular non-symlink directory: $cargo_home" >&2
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$candidate_root" "$cargo_home" <<'PY'
import pathlib
import sys

candidate = pathlib.Path(sys.argv[1]).resolve(strict=True)
cargo_home = pathlib.Path(sys.argv[2])
if cargo_home.is_symlink() or not cargo_home.is_dir():
    raise SystemExit(f"Cargo home is not a regular directory: {cargo_home}")
cargo_home = cargo_home.resolve(strict=True)
config_paths = {
    cargo_home / "config",
    cargo_home / "config.toml",
}
for directory in (candidate, *candidate.parents):
    config_paths.add(directory / ".cargo" / "config")
    config_paths.add(directory / ".cargo" / "config.toml")
present = sorted(
    str(path) for path in config_paths if path.exists() or path.is_symlink()
)
if present:
    raise SystemExit(
        "Cargo config discovery is forbidden for this fixture: " + ", ".join(present)
    )
PY

# Only this Cargo subprocess is serialized. Archive creation, oracle work,
# standalone rustc, execution, hashing, and diffing remain outside the flock.
cargo_messages="$oracle_tmp/cargo.messages.jsonl"
cargo_stderr="$oracle_tmp/cargo.stderr"
if ! (
  builtin cd "$candidate_root"
  /usr/bin/flock "$cargo_build_lock" /usr/bin/env -i \
    HOME="$user_home" CARGO_HOME="$cargo_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
    CARGO_NET_OFFLINE=true TMPDIR="$compiler_tmp" \
    RUSTC="$host_rustc" CXX="$host_cxx" \
    "$host_cargo" build --offline --locked --lib \
    --message-format=json-render-diagnostics \
    --manifest-path "$candidate_root/Cargo.toml"
) >"$cargo_messages" 2>"$cargo_stderr"; then
  /usr/bin/sed -n '1,100p' "$cargo_stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$cargo_messages" "$oracle_tmp/cargo.artifacts" "$cargo_target" <<'PY'
import json
import pathlib
import sys

messages = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
target_root_input = pathlib.Path(sys.argv[3])
if target_root_input.is_symlink() or not target_root_input.is_dir():
    raise SystemExit("candidate-scoped Cargo target is not a regular directory")
target_root = target_root_input.resolve(strict=True)
debug_dir = target_root / "debug"
deps_dir = debug_dir / "deps"
for label, path in (("debug", debug_dir), ("debug/deps", deps_dir)):
    if path.is_symlink() or not path.is_dir():
        raise SystemExit(f"Cargo target {label} is not a regular directory: {path}")
    if path.resolve(strict=True) != path:
        raise SystemExit(f"Cargo target {label} escapes through an ancestor: {path}")
expected_deps = deps_dir
rlibs = set()
decoded = []

def is_rudra_rlib(message):
    target = message.get("target", {})
    return (
        message.get("reason") == "compiler-artifact"
        and target.get("name") == "rugra"
        and "rlib" in target.get("crate_types", [])
    )

for raw in messages.read_text(encoding="utf-8").splitlines():
    if not raw:
        continue
    try:
        message = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit(f"non-JSON Cargo stdout record: {error}")
    decoded.append(message)
    if is_rudra_rlib(message):
        target = message.get("target", {})
        for filename in message.get("filenames", []):
            path = pathlib.Path(filename)
            if path.suffix == ".rlib" and not path.is_absolute():
                raise SystemExit(f"Cargo reported a relative Rudra rlib: {path}")
            if path.suffix == ".rlib" and path.is_file() and not path.is_symlink():
                resolved = path.resolve(strict=True)
                try:
                    relative = resolved.relative_to(target_root)
                except ValueError:
                    raise SystemExit(
                        f"Cargo-reported Rudra rlib escaped target: {resolved}"
                    )
                if relative != pathlib.PurePath("debug", "librudra.rlib"):
                    raise SystemExit(
                        f"unexpected Cargo-reported Rudra rlib location: {resolved}"
                    )
                rlibs.add(resolved)
rudra_package_ids = {
    message.get("package_id")
    for message in decoded
    if is_rudra_rlib(message)
}
rudra_package_ids.discard(None)
if len(rudra_package_ids) != 1:
    observed_targets = [
        (
            message.get("target", {}).get("name"),
            message.get("target", {}).get("kind"),
            message.get("target", {}).get("crate_types"),
            message.get("package_id"),
        )
        for message in decoded
        if message.get("reason") == "compiler-artifact"
    ]
    raise SystemExit(
        f"Cargo invocation reported {len(rudra_package_ids)} Rudra package ids, "
        f"expected 1; compiler targets={observed_targets!r}"
    )
rudra_package_id = next(iter(rudra_package_ids))
native_archives = set()
for message in decoded:
    if (
        message.get("reason") == "build-script-executed"
        and message.get("package_id") == rudra_package_id
    ):
        out_dir = message.get("out_dir")
        if out_dir:
            out_path = pathlib.Path(out_dir)
            if not out_path.is_absolute():
                raise SystemExit(f"Cargo reported a relative Rudra OUT_DIR: {out_dir}")
            archive = out_path / "librudra_sleigh.a"
            if archive.is_file() and not archive.is_symlink():
                resolved = archive.resolve(strict=True)
                try:
                    relative = resolved.relative_to(target_root)
                except ValueError:
                    raise SystemExit(
                        f"Cargo-reported Rudra native archive escaped target: {resolved}"
                    )
                if (
                    len(relative.parts) < 5
                    or relative.parts[0:2] != ("debug", "build")
                    or relative.parts[-2:] != ("out", "librudra_sleigh.a")
                ):
                    raise SystemExit(
                        f"unexpected Rudra native archive location: {resolved}"
                    )
                native_archives.add(resolved)
if len(rlibs) != 1:
    raise SystemExit(f"Cargo invocation reported {len(rlibs)} Rudra rlibs, expected 1")
if len(native_archives) != 1:
    raise SystemExit(
        f"Cargo invocation reported {len(native_archives)} Rudra native archives, expected 1"
    )
destination.write_text(
    f"{next(iter(rlibs))}\n{next(iter(native_archives))}\n",
    encoding="utf-8",
)
PY
mapfile -t cargo_artifacts < "$oracle_tmp/cargo.artifacts"
if [[ ${#cargo_artifacts[@]} -ne 2 ]]; then
  echo "invalid exact Cargo artifact manifest" >&2
  exit 1
fi
rudra_rlib=${cargo_artifacts[0]}
native_archive=${cargo_artifacts[1]}
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" || \
      ! -f "$native_archive" || -L "$native_archive" ]]; then
  echo "Cargo-reported Rudra artifacts are missing" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")

/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$compiler_tmp" "$host_rustc" --edition=2021 -O -Awarnings \
  -L "dependency=$cargo_target/debug/deps" \
  -L "native=$native_dir" --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_snapshot" -o "$oracle_tmp/typefactory_downchain_virtual_rust"

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/typefactory_downchain_virtual_rust" >"$oracle_tmp/rudra.stdout" \
  2>"$oracle_tmp/rudra.stderr"; then
  /usr/bin/sed -n '1,100p' "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  /usr/bin/sed -n '1,100p' "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

ghidra_output_sha=$(/usr/bin/sha256sum "$oracle_tmp/ghidra.stdout" | \
  /usr/bin/awk '{print $1}')
rudra_output_sha=$(/usr/bin/sha256sum "$oracle_tmp/rudra.stdout" | \
  /usr/bin/awk '{print $1}')
metadata_output_sha=$(/usr/bin/sha256sum "$metadata_snapshot" | \
  /usr/bin/awk '{print $1}')
bilateral_artifact_dir="$artifact_parent/bilateral-$ghidra_output_sha-$rudra_output_sha-$metadata_output_sha"
bilateral_artifact_stage="$oracle_tmp/publish-bilateral"
/usr/bin/mkdir "$bilateral_artifact_stage"
/usr/bin/cp -- "$oracle_tmp/ghidra.stdout" \
  "$bilateral_artifact_stage/ghidra.stdout"
/usr/bin/cp -- "$oracle_tmp/rudra.stdout" \
  "$bilateral_artifact_stage/rudra.stdout"
/usr/bin/cp -- "$metadata_snapshot" "$bilateral_artifact_stage/metadata.json"
/usr/bin/diff -u --label ghidra.stdout --label rudra.stdout \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  >"$bilateral_artifact_stage/output.diff" || true
/usr/bin/printf \
  'fixture_id=TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001\nkind=bilateral-capture\noracle_commit=%s\ncandidate_commit=%s\nghidra_stdout_sha256=%s\nrudra_stdout_sha256=%s\nmetadata_sha256=%s\n' \
  "$oracle_commit" "$candidate_commit" "$ghidra_output_sha" \
  "$rudra_output_sha" "$metadata_output_sha" \
  >"$bilateral_artifact_stage/CAPTURE_COMPLETE"
publish_snapshot "$bilateral_artifact_stage" "$bilateral_artifact_dir" \
  ghidra.stdout rudra.stdout metadata.json output.diff CAPTURE_COMPLETE

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$metadata_snapshot" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  "$bilateral_artifact_dir/output.diff" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
diff_path = pathlib.Path(sys.argv[4])
if diff_path.is_symlink() or not diff_path.is_file():
    raise SystemExit("published output diff is not a regular non-symlink file")
output_diff = diff_path.read_bytes()
expected_lines = metadata["build"]["expected_stdout_lines"]
manifest_case_ids = [case["id"] for case in metadata["input_manifest"]["cases"]]
expected_kinds = metadata["observation_schema"]["record_kinds_in_manifest_order"]

def parse_records(label, raw):
    if not raw.endswith(b"\n"):
        raise SystemExit(f"{label} output has no final newline")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(f"{label} output is not UTF-8: {error}")
    lines = text[:-1].split("\n")
    if len(lines) != expected_lines:
        raise SystemExit(
            f"unexpected {label} record count: {len(lines)} expected={expected_lines}"
        )
    records = []
    for index, line in enumerate(lines):
        parts = line.split("|")
        kind = parts[0]
        if kind != expected_kinds[index]:
            raise SystemExit(
                f"{label} record kind mismatch at {index + 1}: "
                f"expected={expected_kinds[index]!r} actual={kind!r}"
            )
        fields = []
        seen = set()
        for segment in parts[1:]:
            if "=" not in segment:
                raise SystemExit(
                    f"{label} record {index + 1} has malformed field: {segment!r}"
                )
            name, value = segment.split("=", 1)
            if not name or name in seen:
                raise SystemExit(
                    f"{label} record {index + 1} has empty/duplicate field: {name!r}"
                )
            seen.add(name)
            fields.append((name, value))
        if not fields or fields[0][0] != "case":
            raise SystemExit(f"{label} record {index + 1} does not start with case=")
        expected_case = manifest_case_ids[index]
        if fields[0][1] != expected_case:
            raise SystemExit(
                f"{label} record order mismatch at {index + 1}: "
                f"expected={expected_case!r} actual={fields[0][1]!r}"
            )
        records.append((kind, fields))
    return records

ghidra_records = parse_records("Ghidra", ghidra)
rudra_records = parse_records("Rudra", rudra)
actual_differences = set()
for index, ((ghidra_kind, ghidra_fields), (rudra_kind, rudra_fields)) in enumerate(
    zip(ghidra_records, rudra_records)
):
    case_id = manifest_case_ids[index]
    if ghidra_kind != rudra_kind:
        raise SystemExit(
            f"record kind mismatch for {case_id}: "
            f"Ghidra={ghidra_kind!r} Rudra={rudra_kind!r}"
        )
    ghidra_names = [name for name, _ in ghidra_fields]
    rudra_names = [name for name, _ in rudra_fields]
    if ghidra_names != rudra_names:
        raise SystemExit(
            f"field name/order mismatch for {case_id}: "
            f"Ghidra={ghidra_names!r} Rudra={rudra_names!r}"
        )
    for (field, ghidra_value), (_, rudra_value) in zip(
        ghidra_fields, rudra_fields
    ):
        if ghidra_value != rudra_value:
            actual_differences.add(f"{case_id}.{field}")

allowed_differences = set(
    metadata["comparison_policy"]["allowed_value_differences"]
)
missing_differences = sorted(allowed_differences - actual_differences)
extra_differences = sorted(actual_differences - allowed_differences)
if missing_differences or extra_differences:
    raise SystemExit(
        "exact allowed difference set drift: "
        f"missing={missing_differences!r} extra={extra_differences!r}"
    )

actual_rust = hashlib.sha256(rudra).hexdigest()
expected_rust = metadata["comparand"]["expected_rudra_stdout_sha256"]
if expected_rust == "PENDING_API_IMPLEMENTATION":
    raise SystemExit(f"Rudra stdout is not pinned yet; observed sha256={actual_rust}")
if actual_rust != expected_rust:
    raise SystemExit(f"Rudra stdout fingerprint drift: {actual_rust}")
actual_diff = hashlib.sha256(output_diff).hexdigest()
expected_diff = metadata["comparand"]["observed_output_diff_sha256"]
if expected_diff == "PENDING_OUTPUT_DIFF":
    raise SystemExit(f"output diff is not pinned yet; observed sha256={actual_diff}")
if actual_diff != expected_diff:
    raise SystemExit(f"output diff fingerprint drift: {actual_diff}")

actual_projection = "MATCH" if not actual_differences else "MISMATCH"
expected_projection = metadata["covered_projection_status"]
if actual_projection != expected_projection:
    raise SystemExit(
        f"projection status drift: expected={expected_projection} actual={actual_projection}"
    )
print(
    f"records={expected_lines} projection_status={actual_projection} "
    f"allowed_differences={len(actual_differences)} "
    f"overall_status={metadata['overall_status']}"
)
PY

bilateral_verified_stage="$oracle_tmp/bilateral.VERIFIED"
/usr/bin/printf \
  'fixture_id=TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001\nstatus=verified\nmetadata_sha256=%s\n' \
  "$metadata_output_sha" >"$bilateral_verified_stage"
if [[ ! -e "$bilateral_artifact_dir/VERIFIED" && \
      ! -L "$bilateral_artifact_dir/VERIFIED" ]]; then
  /usr/bin/mv -- "$bilateral_verified_stage" \
    "$bilateral_artifact_dir/VERIFIED" 2>/dev/null || true
fi
if [[ -e "$bilateral_verified_stage" ]]; then
  if [[ ! -f "$bilateral_artifact_dir/VERIFIED" || \
        -L "$bilateral_artifact_dir/VERIFIED" ]] || \
     ! /usr/bin/cmp -s "$bilateral_verified_stage" \
      "$bilateral_artifact_dir/VERIFIED"; then
    echo "could not atomically publish bilateral VERIFIED marker" >&2
    exit 1
  fi
elif [[ ! -f "$bilateral_artifact_dir/VERIFIED" || \
        -L "$bilateral_artifact_dir/VERIFIED" ]]; then
  echo "bilateral VERIFIED marker disappeared after atomic publish" >&2
  exit 1
fi

if ! /usr/bin/cmp -s "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"; then
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" || true
fi
/usr/bin/printf \
  'typefactory_downchain_virtual_1204: declared projection verified artifacts=%s\n' \
  "$bilateral_artifact_dir"
