#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail
umask 077

# Immutable bilateral runner for ACTION-INFERTYPES-PTRWIDTH-0001.
# The caller supplies the full candidate commit OID.  All evidence files and
# the Rudra overlay are materialized from that object before this script
# re-executes itself from the captured runner blob.
runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  if [[ -L "${BASH_SOURCE[0]}" || ! -f "${BASH_SOURCE[0]}" ]]; then
    echo "runner entrypoint must be a regular non-symlink file" >&2
    exit 1
  fi
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "runner fd must resolve to a regular non-symlink file" >&2
  exit 1
fi

captured_stage=false
if [[ ${1:-} == --captured-stage ]]; then
  if [[ $# -ne 11 ]]; then
    echo "invalid captured-stage invocation" >&2
    exit 2
  fi
  captured_stage=true
  captured_repo_root=$2
  run_root=$3
  candidate_commit=$4
  candidate_tree=$5
  candidate_blob_oids=("$6" "$7" "$8" "$9" "${10}" "${11}")
  set --
  repo_root=$(builtin cd "$captured_repo_root" && builtin pwd -P)
  if [[ "$repo_root" != "$captured_repo_root" ]]; then
    echo "captured repository root is not canonical" >&2
    exit 1
  fi
  expected_runner="$run_root/evidence/tools/run_action_infertypes_ptrwidth_oracle.sh"
  if [[ "$runner_source" != "$expected_runner" ]]; then
    echo "captured stage is not executing the materialized runner blob" >&2
    exit 1
  fi
else
  if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
    echo "usage: ${BASH_SOURCE[0]} <full-candidate-commit-oid>" >&2
    exit 2
  fi
  candidate_commit=$1
  repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
  expected_runner="$repo_root/tools/run_action_infertypes_ptrwidth_oracle.sh"
  if [[ "$runner_source" != "$expected_runner" ]]; then
    echo "runner fd resolved outside the expected repository path" >&2
    exit 1
  fi
  candidate_tree=""
  candidate_blob_oids=()
fi

clean_path=/usr/bin:/bin
base_commit=172582b21f6359c836d028cdfddf5aa54b8f9675
base_tree=ffb005738f1801a2124863e35a022e272ee121be
base_src_tree=1288ea058f04812d63e89d4b2e0190e53cf7bde5
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
expected_manifest_sha=2d6938eb0724581deaa3ae6b224d1d36a0945641d6de88710dd4778166e72a4d

owned_paths=(
  src/coreaction.rs
  docs/api/coreaction.md
  tests/oracle/action_infertypes_ptrwidth_1204.cc
  tests/oracle/action_infertypes_ptrwidth_1204.rs
  tests/oracle/action_infertypes_ptrwidth_1204.metadata.json
  tools/run_action_infertypes_ptrwidth_oracle.sh
)
owned_modes=(100644 100644 100644 100644 100644 100755)
expected_changes=(
  $'M\tdocs/api/coreaction.md'
  $'M\tsrc/coreaction.rs'
  $'A\ttests/oracle/action_infertypes_ptrwidth_1204.cc'
  $'A\ttests/oracle/action_infertypes_ptrwidth_1204.metadata.json'
  $'A\ttests/oracle/action_infertypes_ptrwidth_1204.rs'
  $'A\ttools/run_action_infertypes_ptrwidth_oracle.sh'
)

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_flock_bin=$(/usr/bin/readlink -f /usr/bin/flock)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_flock_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" || -L "$tool" ]]; then
    echo "required tool must be an executable regular file: $tool" >&2
    exit 1
  fi
done

git_clean() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
    "$host_git_bin" "$@"
}

reject_replace_refs() {
  local checked_repo=$1
  local refs
  refs=$(git_clean -C "$checked_repo" for-each-ref --format='%(refname)' refs/replace/)
  if [[ -n "$refs" ]]; then
    echo "Git replace refs are forbidden in $checked_repo" >&2
    echo "$refs" >&2
    exit 1
  fi
}

if [[ ! "$candidate_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "candidate must be a full lowercase SHA-1 object id" >&2
  exit 1
fi
if [[ "$(git_clean -C "$repo_root" cat-file -t "$candidate_commit")" != commit || \
      "$(git_clean -C "$repo_root" rev-parse --verify "$candidate_commit^{commit}")" != "$candidate_commit" ]]; then
  echo "candidate object is not the supplied commit" >&2
  exit 1
fi
actual_parent_line=$(git_clean -C "$repo_root" rev-list --parents -n 1 "$candidate_commit")
if [[ "$actual_parent_line" != "$candidate_commit $base_commit" ]]; then
  echo "candidate must have exactly the pinned base parent" >&2
  exit 1
fi
actual_tree=$(git_clean -C "$repo_root" rev-parse --verify "$candidate_commit^{tree}")
if [[ ! "$actual_tree" =~ ^[0-9a-f]{40}$ || \
      "$(git_clean -C "$repo_root" cat-file -t "$actual_tree")" != tree ]]; then
  echo "candidate tree identity is invalid" >&2
  exit 1
fi
if $captured_stage; then
  if [[ "$candidate_tree" != "$actual_tree" ]]; then
    echo "captured candidate tree changed" >&2
    exit 1
  fi
else
  candidate_tree=$actual_tree
fi

actual_base_tree=$(git_clean -C "$repo_root" rev-parse --verify "$base_commit^{tree}")
actual_base_src_tree=$(git_clean -C "$repo_root" rev-parse --verify "$base_commit:src")
if [[ "$actual_base_tree" != "$base_tree" || "$actual_base_src_tree" != "$base_src_tree" ]]; then
  echo "pinned Rudra base tree identity mismatch" >&2
  exit 1
fi
for binding in \
  "$base_commit:src/coreaction.rs|ae2cf089a3f644385d8a64ce213f7f1b0b88103a" \
  "$base_commit:docs/api/coreaction.md|80105e484ad0af872be5997069a591085d7b774a" \
  "$base_commit:Cargo.toml|f15ed7d02b38aef3c21a564641344a156855b632" \
  "$base_commit:Cargo.lock|9736a3c5619f7fd188abd9609d0dccd20ef06607" \
  "$base_commit:build.rs|a0c81c8521547efebbb463a640ecec69d83ed4c5"; do
  expression=${binding%%|*}
  expected=${binding#*|}
  if [[ "$(git_clean -C "$repo_root" rev-parse --verify "$expression")" != "$expected" ]]; then
    echo "pinned Rudra base blob mismatch: $expression" >&2
    exit 1
  fi
done
reject_replace_refs "$repo_root"

mapfile -t actual_changes < <(git_clean -C "$repo_root" diff-tree \
  --no-commit-id --name-status -r --no-renames "$base_commit" "$candidate_commit")
if [[ ${#actual_changes[@]} -ne ${#expected_changes[@]} ]]; then
  echo "candidate write-set size mismatch" >&2
  /usr/bin/printf '%s\n' "${actual_changes[@]}" >&2
  exit 1
fi
for index in "${!expected_changes[@]}"; do
  if [[ "${actual_changes[$index]}" != "${expected_changes[$index]}" ]]; then
    echo "candidate write-set mismatch" >&2
    /usr/bin/printf '%s\n' "${actual_changes[@]}" >&2
    exit 1
  fi
done

candidate_blob_sha256=()
for index in "${!owned_paths[@]}"; do
  relative=${owned_paths[$index]}
  entry=$(git_clean -C "$repo_root" ls-tree "$candidate_commit" -- "$relative")
  mode=$(/usr/bin/awk 'NR == 1 { print $1 }' <<<"$entry")
  type=$(/usr/bin/awk 'NR == 1 { print $2 }' <<<"$entry")
  blob=$(/usr/bin/awk 'NR == 1 { print $3 }' <<<"$entry")
  path=${entry#*$'\t'}
  if [[ "$mode" != "${owned_modes[$index]}" || "$type" != blob || \
        "$path" != "$relative" || ! "$blob" =~ ^[0-9a-f]{40}$ || \
        "$(git_clean -C "$repo_root" cat-file -t "$blob")" != blob ]]; then
    echo "candidate path has wrong mode/type/identity: $relative" >&2
    exit 1
  fi
  if $captured_stage; then
    if [[ "${candidate_blob_oids[$index]}" != "$blob" ]]; then
      echo "candidate blob changed across captured exec: $relative" >&2
      exit 1
    fi
  else
    candidate_blob_oids+=("$blob")
  fi
  sha=$(git_clean -C "$repo_root" cat-file blob "$blob" | \
    /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
  candidate_blob_sha256+=("$sha")
done
runner_fd_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
if [[ "$runner_fd_sha" != "${candidate_blob_sha256[5]}" ]]; then
  echo "executing runner fd is not the candidate runner blob" >&2
  exit 1
fi

ghidra_root=$(/usr/bin/readlink -f "$repo_root/ghidra")
if [[ -z "$ghidra_root" || ! -d "$ghidra_root" ]]; then
  echo "locked Ghidra repository is unavailable" >&2
  exit 1
fi
reject_replace_refs "$ghidra_root"
actual_oracle_head=$(git_clean -C "$ghidra_root" rev-parse --verify HEAD^{commit})
actual_oracle_tag=$(git_clean -C "$ghidra_root" rev-parse --verify "refs/tags/$oracle_tag^{commit}")
actual_oracle_tree=$(git_clean -C "$ghidra_root" rev-parse --verify \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git_clean -C "$ghidra_root" rev-parse --verify \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_oracle_head" != "$oracle_commit" || \
      "$actual_oracle_tag" != "$oracle_commit" || \
      "$actual_oracle_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra identity mismatch" >&2
  exit 1
fi
for binding in \
  "coreaction.cc|a392076ad23ddad3350e0fe7a2ebe96a8868f74b" \
  "coreaction.hh|d974875d7d71ac76121379eba139c2e8450ae8a3" \
  "typeop.cc|5197e3eefd185ed39c58e65af0687d605e34ec5e" \
  "typeop.hh|90ac4ed35194c5fd9bbb86759481c89a5388cb52" \
  "varnode.cc|a04614c582a1fd987d615dcec4a8b47d3501f95f" \
  "varnode.hh|b78368fc8c3fbdda2a419122b759b4dcd44fe8d2"; do
  relative=${binding%%|*}
  expected=${binding#*|}
  expression="$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/$relative"
  if [[ "$(git_clean -C "$ghidra_root" rev-parse --verify "$expression")" != "$expected" ]]; then
    echo "locked Ghidra source blob mismatch: $relative" >&2
    exit 1
  fi
done

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
cache_root="$user_home/.cache"
if [[ -z "$user_home" || ! -d "$cache_root" || -L "$cache_root" || \
      "$(/usr/bin/readlink -f "$cache_root")" != "$cache_root" ]]; then
  echo "current-user cache root must be a canonical real directory" >&2
  exit 1
fi
HOME=$user_home
export HOME

cleanup() {
  case "${run_root:-}" in
    "$cache_root"/rudra-action-infertypes-ptrwidth.??????)
      if [[ -e "$run_root" || -L "$run_root" ]]; then
        if [[ ! -d "$run_root" || -L "$run_root" ]]; then
          echo "refusing unsafe cleanup target: $run_root" >&2
          return 1
        fi
        /usr/bin/chmod -R u+w -- "$run_root" 2>/dev/null || true
        /usr/bin/rm -rf -- "$run_root"
      fi
      ;;
    *) echo "refusing unsafe cleanup target: ${run_root:-unset}" >&2; return 1 ;;
  esac
}

if ! $captured_stage; then
  run_root=$(/usr/bin/mktemp -d "$cache_root/rudra-action-infertypes-ptrwidth.XXXXXX")
  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  evidence="$run_root/evidence"
  /usr/bin/mkdir -p "$evidence"
  for index in "${!owned_paths[@]}"; do
    relative=${owned_paths[$index]}
    destination="$evidence/$relative"
    /usr/bin/mkdir -p "$(/usr/bin/dirname "$destination")"
    git_clean -C "$repo_root" cat-file blob "${candidate_blob_oids[$index]}" >"$destination"
    if [[ ! -f "$destination" || -L "$destination" || \
          "$(/usr/bin/sha256sum "$destination" | /usr/bin/awk '{print $1}')" != "${candidate_blob_sha256[$index]}" ]]; then
      echo "candidate evidence materialization failed: $relative" >&2
      exit 1
    fi
  done
  /usr/bin/chmod 755 "$evidence/tools/run_action_infertypes_ptrwidth_oracle.sh"
  /usr/bin/chmod a-w \
    "$evidence/src/coreaction.rs" "$evidence/docs/api/coreaction.md" \
    "$evidence/tests/oracle/action_infertypes_ptrwidth_1204.cc" \
    "$evidence/tests/oracle/action_infertypes_ptrwidth_1204.rs" \
    "$evidence/tests/oracle/action_infertypes_ptrwidth_1204.metadata.json"
  /usr/bin/sha256sum "${owned_paths[@]/#/$evidence/}" >"$run_root/evidence.before"
  if ! /usr/bin/cmp --silent "$runner_fd_path" \
    "$evidence/tools/run_action_infertypes_ptrwidth_oracle.sh"; then
    echo "materialized runner differs from executing candidate fd" >&2
    exit 1
  fi
  trap - EXIT HUP INT TERM
  exec /usr/bin/env -i PATH="$clean_path" /usr/bin/bash \
    "$evidence/tools/run_action_infertypes_ptrwidth_oracle.sh" \
    --captured-stage "$repo_root" "$run_root" "$candidate_commit" "$candidate_tree" \
    "${candidate_blob_oids[@]}"
fi

case "$run_root" in
  "$cache_root"/rudra-action-infertypes-ptrwidth.??????) ;;
  *) echo "captured stage received unsafe run root" >&2; exit 1 ;;
esac
if [[ ! -d "$run_root" || -L "$run_root" || \
      "$(/usr/bin/readlink -f "$run_root")" != "$run_root" ]]; then
  echo "captured run root is not a canonical real directory" >&2
  exit 1
fi
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

evidence="$run_root/evidence"
snapshot_runner="$evidence/tools/run_action_infertypes_ptrwidth_oracle.sh"
if ! /usr/bin/sha256sum --check --status "$run_root/evidence.before"; then
  echo "captured evidence changed across self-exec" >&2
  exit 1
fi
if ! /usr/bin/cmp --silent "$runner_fd_path" "$snapshot_runner"; then
  echo "captured runner fd changed across self-exec" >&2
  exit 1
fi

snapshot="$run_root/rudra"
oracle_source="$run_root/ghidra-source"
tool_tmp="$run_root/tmp"
cargo_target="$run_root/cargo-target"
/usr/bin/mkdir -p "$snapshot" "$oracle_source" "$tool_tmp" "$cargo_target"
git_clean -C "$repo_root" archive --format=tar --output="$run_root/rudra-base.tar" \
  "$base_commit"
/usr/bin/tar -xf "$run_root/rudra-base.tar" -C "$snapshot"
git_clean -C "$repo_root" cat-file blob "${candidate_blob_oids[0]}" \
  >"$snapshot/src/coreaction.rs"
git_clean -C "$ghidra_root" archive --format=tar --output="$run_root/ghidra-cpp.tar" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/tar -xf "$run_root/ghidra-cpp.tar" -C "$oracle_source"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"
if [[ ! -d "$oracle_cpp" || -L "$oracle_cpp" ]]; then
  echo "captured Ghidra cpp tree is invalid" >&2
  exit 1
fi
bad_source_link=$(/usr/bin/find "$snapshot" "$oracle_source" -type l -print -quit)
if [[ -n "$bad_source_link" ]]; then
  echo "captured source archive contains an unexpected symlink: $bad_source_link" >&2
  exit 1
fi
/usr/bin/mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

host_cargo=$(/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_rustc=$(/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" -dumpmachine)
host_cc=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cc_bin" --version | /usr/bin/head -1)
host_make=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_make_bin" --version | /usr/bin/head -1)
host_ar=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_ar_bin" --version | /usr/bin/head -1)
host_git=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_git_bin" --version)
host_flock=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_flock_bin" --version | /usr/bin/head -1)
host_python=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" --version)
host_platform=$(/usr/bin/uname -srm)

# Validate the entire decision-bearing metadata and immutable source closure
# before any compiler runs.
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$evidence/tests/oracle/action_infertypes_ptrwidth_1204.metadata.json" \
  "$evidence" "$snapshot" "$runner_fd_sha" "$expected_manifest_sha" \
  "$host_cargo" "$host_rustc" "$host_cxx" "$host_cxx_target" "$host_cc" \
  "$host_make" "$host_ar" "$host_git" "$host_flock" "$host_python" \
  "$host_platform" "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_flock_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

(
    metadata_raw, evidence_raw, snapshot_raw, runner_sha, manifest_sha,
    host_cargo, host_rustc, host_cxx, host_cxx_target, host_cc,
    host_make, host_ar, host_git, host_flock, host_python, host_platform,
    host_cxx_bin, host_cc_bin, host_ar_bin, host_make_bin, host_flock_bin,
    host_python_bin, host_git_bin, host_cargo_bin, host_rustc_bin,
) = sys.argv[1:]
metadata_path = pathlib.Path(metadata_raw)
evidence = pathlib.Path(evidence_raw)
snapshot = pathlib.Path(snapshot_raw)
m = json.loads(metadata_path.read_text(encoding="utf-8"))

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def regular(path):
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"expected regular non-symlink file: {path}")
    return path.read_bytes()

def sha(data):
    return hashlib.sha256(data).hexdigest()

require("schema", m["schema_version"], 2)
require("fixture", m["fixture_id"], "ACTION-INFERTYPES-PTRWIDTH-0001")
require("overall", m["overall_status"], "MISMATCH")
require("covered projection", m["covered_projection_status"], "MATCH")
oracle = m["oracle"]
require("oracle tag", oracle["tag"], "Ghidra_12.0.4_build")
require("oracle commit", oracle["commit"], "e40ed13014025f82488b1f8f7bca566894ac376b")
require("oracle cpp tree", oracle["decompiler_cpp_tree"], "b02e230a539c65de14e50f357d0ba834d8184f4f")
require("oracle Makefile", oracle["decompiler_makefile_blob"], "ca0719fa5f17aabd14c52f40ed8b030f54d2aac6")
require("oracle source blob keys", set(oracle["source_blobs"]), {
    "coreaction.cc", "coreaction.hh", "typeop.cc", "typeop.hh",
    "varnode.cc", "varnode.hh",
})

manifest_payload = {
    "architecture": m["architecture"],
    "compiler_spec": m["compiler_spec"],
    "analysis_options": m["analysis_options"],
    "graph": m["input_manifest"]["graph"],
    "cases": m["input_manifest"]["cases"],
}
manifest = json.dumps(
    manifest_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
require("manifest canonicalization", m["input_manifest"]["canonicalization"],
        "SHA-256 of sorted compact JSON over architecture, compiler_spec, analysis_options, graph, and cases")
require("manifest embedded hash", m["input_manifest"]["sha256"], manifest_sha)
require("manifest actual hash", sha(manifest), manifest_sha)

comparand = m["comparand"]
require("base commit", comparand["rust_base_commit"], "172582b21f6359c836d028cdfddf5aa54b8f9675")
require("base tree", comparand["rust_base_tree"], "ffb005738f1801a2124863e35a022e272ee121be")
require("base src tree", comparand["rust_base_src_tree"], "1288ea058f04812d63e89d4b2e0190e53cf7bde5")
expected_base_blobs = {
    "src/coreaction.rs": "ae2cf089a3f644385d8a64ce213f7f1b0b88103a",
    "docs/api/coreaction.md": "80105e484ad0af872be5997069a591085d7b774a",
    "Cargo.toml": "f15ed7d02b38aef3c21a564641344a156855b632",
    "Cargo.lock": "9736a3c5619f7fd188abd9609d0dccd20ef06607",
    "build.rs": "a0c81c8521547efebbb463a640ecec69d83ed4c5",
}
require("base blobs", comparand["rust_base_blobs"], expected_base_blobs)
for relative in ("Cargo.toml", "Cargo.lock", "build.rs"):
    regular(snapshot / relative)

overlay_paths = {
    "src/coreaction.rs",
    "docs/api/coreaction.md",
    "tests/oracle/action_infertypes_ptrwidth_1204.cc",
    "tests/oracle/action_infertypes_ptrwidth_1204.rs",
}
require("overlay path set", set(comparand["overlay_sha256"]), overlay_paths)
for relative, expected in comparand["overlay_sha256"].items():
    require(f"overlay {relative}", sha(regular(evidence / relative)), expected)
require("runner sha metadata", comparand["runner_sha256"], runner_sha)
require("runner sha bytes", sha(regular(evidence / "tools/run_action_infertypes_ptrwidth_oracle.sh")), runner_sha)
require("source policy", comparand["source_policy"],
        "An externally supplied full candidate commit OID anchors the exact six-file diff. The runner materializes every evidence file from candidate Git blobs, archives the pinned Rudra base, overlays only candidate src/coreaction.rs, and executes only run-private snapshots with pre/post Git-object readback.")

candidate = m["candidate_evidence"]
require("candidate evidence", candidate, {
    "external_anchor": "full candidate commit/tree and six blob OIDs recorded by independent review; metadata is not self-authenticating",
    "owned_paths": [
        "src/coreaction.rs",
        "docs/api/coreaction.md",
        "tests/oracle/action_infertypes_ptrwidth_1204.cc",
        "tests/oracle/action_infertypes_ptrwidth_1204.rs",
        "tests/oracle/action_infertypes_ptrwidth_1204.metadata.json",
        "tools/run_action_infertypes_ptrwidth_oracle.sh",
    ],
    "materialization": "git cat-file blobs into a private home-backed snapshot followed by fixed-FD self-exec",
    "metadata_self_authentication": False,
})

expected_raw = [
    {"record": "pre", "case": "L16", "ghidra": "array", "rugra": "unknown"},
    {"record": "pre", "case": "L32", "ghidra": "array", "rugra": "unknown"},
    {"record": "pre", "case": "S16", "ghidra": "array", "rugra": "unknown"},
    {"record": "pre", "case": "S32", "ghidra": "array", "rugra": "unknown"},
    {"record": "pass1", "case": "L16", "ghidra": "array", "rugra": "unknown"},
    {"record": "pass1", "case": "S16", "ghidra": "array", "rugra": "unknown"},
]
require("raw difference contract", m["known_raw_differences"], expected_raw)

residuals = set(m["residual_ids"])
require("residual set", residuals, {
    "ACTION-INFERTYPES-DISPATCH-0001",
    "TYPE-UNKNOWN-0001",
    "TYPEFACTORY-EXACTPIECE-0001",
    "TYPEFIELD-IDENT-REPRESENTATION-0001",
})
observed_residuals = set()
for name, entry in m["coverage"].items():
    if entry["status"] not in {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}:
        raise SystemExit(f"{name}: invalid coverage status")
    found = {value for value in residuals if value in entry["detail"]}
    if entry["status"] == "MATCH":
        require(f"{name} MATCH residuals", found, set())
    elif not found:
        raise SystemExit(f"{name}: non-MATCH coverage lacks a residual id")
    observed_residuals.update(found)
require("coverage residual union", observed_residuals, residuals)

empty_sha = sha(b"")
require("stdout expectations", m["expected_stdout_sha256"], {
    "ghidra": "f20f3c8a0c90945dfc641b5ea13324b527211a5edb83ddbc8d871f06cbfbb75f",
    "rugra": "9b73e923bc3b32b9086780db939b1fdf6245d022cf35a3af482688e0f59fa701",
})
require("stderr expectations", m["expected_stderr_sha256"], {
    "ghidra": empty_sha, "rugra": empty_sha,
})
require("raw diff expectation", m["expected_raw_diff_sha256"],
        "9101eb6eb7b29f0a062e47f8e94df8928769105ef63c5edd05f64ca9509916d3")
require("exit expectations", m["expected_exit_code"], {
    "ghidra": 0, "rugra": 0, "raw_diff": 1, "runner": 0,
})
require("execution evidence", m["execution_evidence"], [])

toolchain = m["host_toolchain"]
actual_tools = {
    "cargo": (host_cargo_bin, host_cargo),
    "rustc": (host_rustc_bin, host_rustc),
    "cxx": (host_cxx_bin, host_cxx),
    "cc": (host_cc_bin, host_cc),
    "make": (host_make_bin, host_make),
    "ar": (host_ar_bin, host_ar),
    "git": (host_git_bin, host_git),
    "flock": (host_flock_bin, host_flock),
    "python": (host_python_bin, host_python),
}
for key, (path, version) in actual_tools.items():
    require(f"{key} path", toolchain[key]["path"], path)
    require(f"{key} version", toolchain[key]["version"], version)
    require(f"{key} binary", toolchain[key]["sha256"], sha(regular(pathlib.Path(path))))
require("cxx target", toolchain["cxx_target"], host_cxx_target)
require("platform", toolchain["platform"], host_platform)
require("build environment", m["build_environment"], {
    "PATH": "/usr/bin:/bin",
    "cargo_incremental": False,
    "cargo_jobs": 2,
    "cargo_lock": "/tmp/rudra-cargo-build.lock",
    "cargo_mode": "--frozen --locked --offline --lib",
    "rustflags": "-Awarnings",
    "temp_policy": "private home-backed run root and TMPDIR",
})
PY

if [[ -e "$HOME/.cargo/config" || -e "$HOME/.cargo/config.toml" ]]; then
  echo "user Cargo configuration is forbidden for this fixture" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$tool_tmp" \
  "$host_make_bin" --silent -C "$oracle_cpp" -j 2 \
  CXX="$host_cxx_bin -std=c++11" CC="$host_cc_bin" AR="$host_ar_bin" \
  EXTRA= libdecomp.a >"$run_root/make.stdout" 2>"$run_root/make.stderr"; then
  /usr/bin/cat "$run_root/make.stdout" "$run_root/make.stderr" >&2
  exit 1
fi
if [[ ! -f "$oracle_cpp/libdecomp.a" || -L "$oracle_cpp/libdecomp.a" ]]; then
  echo "cold Ghidra build did not produce a regular libdecomp.a" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$tool_tmp" \
  "$host_cxx_bin" -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" \
  "$evidence/tests/oracle/action_infertypes_ptrwidth_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" -lz \
  -o "$run_root/action_infertypes_cpp" \
  >"$run_root/cxx.stdout" 2>"$run_root/cxx.stderr"; then
  /usr/bin/cat "$run_root/cxx.stdout" "$run_root/cxx.stderr" >&2
  exit 1
fi

cargo_status=0
(
  builtin cd "$snapshot"
  "$host_flock_bin" /tmp/rudra-cargo-build.lock \
    /usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
      CARGO_HOME="$HOME/.cargo" CARGO_TARGET_DIR="$cargo_target" \
      CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 RUSTFLAGS=-Awarnings \
      TMPDIR="$tool_tmp" CXX="$host_cxx_bin" CC="$host_cc_bin" \
      AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
      "$host_cargo_bin" build --jobs 2 --frozen --locked --offline --lib \
        --manifest-path "$snapshot/Cargo.toml"
) >"$run_root/cargo.stdout" 2>"$run_root/cargo.stderr" || cargo_status=$?
if [[ "$cargo_status" -ne 0 ]]; then
  echo "Cargo build failed with exit code $cargo_status" >&2
  /usr/bin/cat "$run_root/cargo.stdout" "$run_root/cargo.stderr" >&2
  exit 1
fi

rudra_rlib="$cargo_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$cargo_target/debug/build" -path '*/out/librudra_sleigh.a' \
    -type f -print | /usr/bin/sort
)
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" || ${#native_archives[@]} -ne 1 ]]; then
  echo "Cargo build did not produce exactly one Rudra rlib/native archive" >&2
  /usr/bin/printf '%s\n' "${native_archives[@]}" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
if ! /usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$tool_tmp" RUSTFLAGS=-Awarnings \
  "$host_rustc_bin" --edition=2021 -O -Awarnings \
  -L "dependency=$cargo_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m \
  "$evidence/tests/oracle/action_infertypes_ptrwidth_1204.rs" \
  -o "$run_root/action_infertypes_rust" \
  >"$run_root/rustc.stdout" 2>"$run_root/rustc.stderr"; then
  /usr/bin/cat "$run_root/rustc.stdout" "$run_root/rustc.stderr" >&2
  exit 1
fi

ghidra_status=0
/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C \
  "$run_root/action_infertypes_cpp" \
  >"$run_root/ghidra.stdout" 2>"$run_root/ghidra.stderr" || ghidra_status=$?
rudra_status=0
/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C \
  "$run_root/action_infertypes_rust" \
  >"$run_root/rudra.stdout" 2>"$run_root/rudra.stderr" || rudra_status=$?
diff_status=0
/usr/bin/diff -u --label ghidra-12.0.4 --label rudra-candidate \
  "$run_root/ghidra.stdout" "$run_root/rudra.stdout" \
  >"$run_root/raw.diff" || diff_status=$?

# Validate exact output bytes and the six-token selected projection.
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$evidence/tests/oracle/action_infertypes_ptrwidth_1204.metadata.json" \
  "$run_root/ghidra.stdout" "$run_root/ghidra.stderr" \
  "$run_root/rudra.stdout" "$run_root/rudra.stderr" "$run_root/raw.diff" \
  "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, gout_raw, gerr_raw, rout_raw, rerr_raw, diff_raw, gs, rs, ds = sys.argv[1:]
m = json.loads(pathlib.Path(metadata_path).read_text(encoding="utf-8"))

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

gout = pathlib.Path(gout_raw).read_bytes()
rout = pathlib.Path(rout_raw).read_bytes()
gerr = pathlib.Path(gerr_raw).read_bytes()
rerr = pathlib.Path(rerr_raw).read_bytes()
raw_diff = pathlib.Path(diff_raw).read_bytes()
require(int(gs) == m["expected_exit_code"]["ghidra"], "unexpected Ghidra exit")
require(int(rs) == m["expected_exit_code"]["rugra"], "unexpected Rudra exit")
require(int(ds) == m["expected_exit_code"]["raw_diff"], "unexpected raw diff exit")
require(sha(gout) == m["expected_stdout_sha256"]["ghidra"], "Ghidra stdout drift")
require(sha(rout) == m["expected_stdout_sha256"]["rugra"], "Rudra stdout drift")
require(sha(gerr) == m["expected_stderr_sha256"]["ghidra"] and not gerr,
        "Ghidra stderr must remain empty")
require(sha(rerr) == m["expected_stderr_sha256"]["rugra"] and not rerr,
        "Rudra stderr must remain empty")
require(sha(raw_diff) == m["expected_raw_diff_sha256"], "raw diff drift")

expected = [
    {"record": "pre", "case": "L16", "ghidra": "array", "rugra": "unknown"},
    {"record": "pre", "case": "L32", "ghidra": "array", "rugra": "unknown"},
    {"record": "pre", "case": "S16", "ghidra": "array", "rugra": "unknown"},
    {"record": "pre", "case": "S32", "ghidra": "array", "rugra": "unknown"},
    {"record": "pass1", "case": "L16", "ghidra": "array", "rugra": "unknown"},
    {"record": "pass1", "case": "S16", "ghidra": "array", "rugra": "unknown"},
]
require(m["known_raw_differences"] == expected, "raw projection contract changed")

def lines(data, side):
    require(data.endswith(b"\n") and b"\r" not in data, f"{side} newline drift")
    result = data.decode("utf-8", errors="strict")[:-1].split("\n")
    require([line.split("|", 1)[0] for line in result] ==
            ["schema=1", "pre", "pass1", "pass2"],
            f"{side} record order drift")
    return result

def replace_raw(line, case, old, new):
    fields = line.split("|")
    positions = [i for i, field in enumerate(fields) if field.startswith("types=")]
    require(len(positions) == 1, f"{case}: types field shape drift")
    position = positions[0]
    cells = fields[position][len("types="):].split(",")
    matches = [i for i, cell in enumerate(cells) if cell.split(":", 1)[0] == case]
    require(len(matches) == 1, f"{case}: cell cardinality drift")
    cell_index = matches[0]
    parts = cells[cell_index].split("/")
    raw_indices = [i for i, part in enumerate(parts) if part.startswith("raw=")]
    require(len(raw_indices) == 1, f"{case}: raw field shape drift")
    raw_index = raw_indices[0]
    require(parts[raw_index] == f"raw={old}", f"{case}: raw token drift")
    parts[raw_index] = f"raw={new}"
    cells[cell_index] = "/".join(parts)
    fields[position] = "types=" + ",".join(cells)
    return "|".join(fields)

glines = lines(gout, "ghidra")
rlines = lines(rout, "rugra")
gmap = {line.split("|", 1)[0]: i for i, line in enumerate(glines)}
projected = list(glines)
for item in expected:
    record = item["record"]
    projected[gmap[record]] = replace_raw(
        projected[gmap[record]], item["case"], item["ghidra"], item["rugra"]
    )
require(gout != rout, "raw outputs unexpectedly match")
require(("\n".join(projected) + "\n").encode() == rout,
        "outputs differ outside the six declared raw tokens")
PY

# Candidate Git objects and captured evidence must still read back byte-for-byte.
reject_replace_refs "$repo_root"
reject_replace_refs "$ghidra_root"
if [[ "$(git_clean -C "$repo_root" rev-parse --verify "$candidate_commit^{tree}")" != "$candidate_tree" ]]; then
  echo "candidate tree changed after execution" >&2
  exit 1
fi
for index in "${!owned_paths[@]}"; do
  readback="$run_root/readback.$index"
  git_clean -C "$repo_root" cat-file blob "${candidate_blob_oids[$index]}" >"$readback"
  if ! /usr/bin/cmp --silent "$readback" "$evidence/${owned_paths[$index]}"; then
    echo "candidate blob readback changed: ${owned_paths[$index]}" >&2
    exit 1
  fi
done
if ! /usr/bin/sha256sum --check --status "$run_root/evidence.before"; then
  echo "captured evidence changed during execution" >&2
  exit 1
fi

/usr/bin/printf '%s\n' \
  "ACTION-INFERTYPES-PTRWIDTH-0001 overall=MISMATCH covered_projection=MATCH" \
  "candidate_commit=$candidate_commit" \
  "candidate_tree=$candidate_tree" \
  "candidate_blobs=${candidate_blob_oids[*]}" \
  "ghidra_stdout_sha256=$(/usr/bin/sha256sum "$run_root/ghidra.stdout" | /usr/bin/awk '{print $1}')" \
  "rudra_stdout_sha256=$(/usr/bin/sha256sum "$run_root/rudra.stdout" | /usr/bin/awk '{print $1}')" \
  "raw_diff_sha256=$(/usr/bin/sha256sum "$run_root/raw.diff" | /usr/bin/awk '{print $1}')" \
  "comparand_stderr=empty" \
  "cargo=$host_cargo" \
  "rustc=$host_rustc"
