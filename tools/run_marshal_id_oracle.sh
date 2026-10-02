#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH="/usr/bin:/bin" /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_marshal_id_oracle.sh"
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
rust_toolchain=nightly-x86_64-unknown-linux-gnu
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/cargo"
host_rustc_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/rustc"
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=e69de217098cb1c0a3a1a920f8d4740cf10b743b
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/marshal_id_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/marshal_id_1204.cc"
rust_fixture="$repo_root/tests/oracle/marshal_id_1204.rs"
marshal_rs="$repo_root/src/marshal.rs"
marshal_doc="$repo_root/docs/api/marshal.md"
registry_cache="$user_home/.cargo/registry/cache"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$marshal_rs" \
  "$marshal_doc"; do
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

actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_base_tree" != "$rudra_base_tree" ]]; then
  echo "locked Rudra base tree mismatch" >&2
  exit 1
fi

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-marshal-id-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-marshal-id-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot_root="$oracle_tmp/workspace"
cargo_home="$oracle_tmp/cargo-home"
oracle_source="$oracle_tmp/oracle-source"
mkdir -p "$snapshot_root" "$oracle_source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive "$rudra_base_commit" | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$snapshot_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$oracle_source"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/cp -- "$marshal_rs" "$snapshot_root/src/marshal.rs"
/usr/bin/cp -- "$marshal_doc" "$snapshot_root/docs/api/marshal.md"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools"
/usr/bin/cp -- "$cpp_fixture" "$snapshot_root/tests/oracle/marshal_id_1204.cc"
/usr/bin/cp -- "$rust_fixture" "$snapshot_root/tests/oracle/marshal_id_1204.rs"
/usr/bin/cp -- "$metadata" "$snapshot_root/tests/oracle/marshal_id_1204.metadata.json"
/usr/bin/cp -- "$runner_fd_path" "$snapshot_root/tools/run_marshal_id_oracle.sh"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$snapshot_root" "$oracle_cpp" "$cargo_home" "$registry_cache" \
  "$runner_sha" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$host_git_bin" "$host_python_bin" "$host_cxx_bin" "$host_rustc_bin" "$host_cargo_bin" \
  "$host_cc_bin" "$host_ar_bin" "$host_make_bin" "$rust_toolchain" \
  "$user_home" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(
    snapshot_raw, oracle_cpp_raw, cargo_home_raw, registry_cache_raw,
    runner_sha, oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    base_commit, base_tree, host_git, host_python, host_cxx, host_rustc, host_cargo,
    host_cc, host_ar, host_make, rust_toolchain, user_home,
) = sys.argv[1:]
snapshot = pathlib.Path(snapshot_raw)
oracle_cpp = pathlib.Path(oracle_cpp_raw)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

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

metadata_path = snapshot / "tests/oracle/marshal_id_1204.metadata.json"
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
metadata_without_capture = dict(metadata)
metadata_without_capture.pop("locked_capture", None)
reject_pending(metadata_without_capture)
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "MARSHAL-ID-0001")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require("base commit", metadata["comparand"]["rugra_base_commit"], base_commit)
require("base tree", metadata["comparand"]["rugra_base_tree"], base_tree)
require("architecture", metadata["architecture"], "process-global marshal scope-0")
require("compiler spec", metadata["compiler_spec"], "N/A")
require("overall status", metadata["overall_status"], "MISMATCH: (B2 canonicalization)")
require("source attr count", metadata["coverage"]["source_manifest_attribute_count"], 146)
require("source elem count", metadata["coverage"]["source_manifest_element_count"], 274)
require("source union count", metadata["coverage"]["source_manifest_union_count"], 420)
require("standard attr count", metadata["coverage"]["standard_libdecomp_attribute_count"], 136)
require("standard elem count", metadata["coverage"]["standard_libdecomp_element_count"], 243)
require("standard total count", metadata["coverage"]["standard_libdecomp_total_count"], 379)
require("alternate count", metadata["coverage"]["alternate_frontend_only_count"], 41)
require("id observation status", metadata["coverage"]["id_table_observation_status"], "MATCH")
require("tree observation status", metadata["coverage"]["tree_end_unknown_order_status"], "MATCH")
require("reverse projection", metadata["coverage"]["id_to_name_observation"], "source-manifest object scan; no locked Ghidra reverse-lookup API")
require(
    "residual statuses",
    [item["status"] for item in metadata["residuals"]],
    ["MISMATCH", "MISMATCH", "UNTESTED"],
)
require(
    "snapshot model",
    metadata["comparand"]["snapshot_model"],
    "git archive locked base tree plus exact owned-file overlays",
)
require(
    "overlay paths",
    metadata["comparand"]["overlay_paths"],
    [
        "src/marshal.rs", "docs/api/marshal.md",
        "tests/oracle/marshal_id_1204.cc",
        "tests/oracle/marshal_id_1204.rs",
        "tests/oracle/marshal_id_1204.metadata.json",
        "tools/run_marshal_id_oracle.sh",
    ],
)

paths = {
    "cpp_fixture_sha256": snapshot / "tests/oracle/marshal_id_1204.cc",
    "rust_fixture_sha256": snapshot / "tests/oracle/marshal_id_1204.rs",
    "marshal_rs_sha256": snapshot / "src/marshal.rs",
    "marshal_doc_sha256": snapshot / "docs/api/marshal.md",
    "runner_sha256": snapshot / "tools/run_marshal_id_oracle.sh",
    "cargo_toml_sha256": snapshot / "Cargo.toml",
    "cargo_lock_sha256": snapshot / "Cargo.lock",
    "build_rs_sha256": snapshot / "build.rs",
}
for key, path in paths.items():
    actual = sha(path.read_bytes())
    expected = metadata["comparand"][key]
    require(key, actual, expected)
require("immutable runner hash", sha(paths["runner_sha256"].read_bytes()), runner_sha)

host = metadata["host_tools"]
require("host cxx", subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0], host["cxx"])
require("host cxx target", subprocess.check_output([host_cxx, "-dumpmachine"], text=True).strip(), host["cxx_target"])
require("host cc", subprocess.check_output([host_cc, "--version"], text=True).splitlines()[0], host["cc"])
require("host cc target", subprocess.check_output([host_cc, "-dumpmachine"], text=True).strip(), host["cc_target"])
require("host ar", subprocess.check_output([host_ar, "--version"], text=True).splitlines()[0], host["ar"])
require("host make", subprocess.check_output([host_make, "--version"], text=True).splitlines()[0], host["make"])
require("host python", subprocess.check_output([host_python, "--version"], text=True).strip(), host["python"])
require("host git", subprocess.check_output([host_git, "--version"], text=True).strip(), host["git"])
require("host rustc", subprocess.check_output([host_rustc, "--version"], text=True).strip(), host["rustc"])
require("host cargo", subprocess.check_output([host_cargo, "--version"], text=True).strip(), host["cargo"])
require("rust toolchain", host["rust_toolchain"], rust_toolchain)

source_pattern = re.compile(
    r'^\s*(AttributeId|ElementId)\s+(\w+)\s*=\s*\1\('
    r'"([^"]+)",\s*(\d+)(?:,\s*([^\)]+))?\)', re.M
)
rows = []
source_files = sorted(oracle_cpp.glob("*.cc"), key=lambda path: path.name)
require("locked cc count", len(source_files), 114)
for source in source_files:
    expected_blob = oracle["source_blobs"].get(source.name)
    if expected_blob is None:
        continue
    actual_blob = subprocess.check_output(
        [host_git, "-C", str(oracle_cpp.parents[6]), "rev-parse", "HEAD"],
        text=True,
    ).strip() if False else sha(source.read_bytes())
    require(f"source sha256 {source.name}", actual_blob, expected_blob)
    for match in source_pattern.finditer(source.read_text(encoding="utf-8")):
        scope = (match.group(5) or "0").strip()
        if scope == "0":
            rows.append({
                "file": source.name, "kind": match.group(1),
                "symbol": match.group(2), "name": match.group(3),
                "id": int(match.group(4)),
            })
require("source manifest row count", len(rows), 420)
manifest_payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
require("source manifest hash", sha(manifest_payload), metadata["input_manifest"]["sha256"])

attribute_rows = sorted((row for row in rows if row["kind"] == "AttributeId"), key=lambda row: row["id"])
element_rows = sorted((row for row in rows if row["kind"] == "ElementId"), key=lambda row: row["id"])
if len({row["id"] for row in attribute_rows}) != len(attribute_rows) or len({row["name"] for row in attribute_rows}) != len(attribute_rows):
    raise SystemExit("attribute source manifest contains duplicate name or id")
if len({row["id"] for row in element_rows}) != len(element_rows) or len({row["name"] for row in element_rows}) != len(element_rows):
    raise SystemExit("element source manifest contains duplicate name or id")

header = snapshot / "tests/oracle/marshal_id_generated.hh"
with header.open("w", encoding="utf-8", newline="\n") as stream:
    for label, manifest_rows in (("ATTRIBUTE_OBJECTS", attribute_rows), ("ELEMENT_OBJECTS", element_rows)):
        stream.write(f"#define {label}(X) \\\n")
        for index, row in enumerate(manifest_rows):
            suffix = " \\\n" if index + 1 != len(manifest_rows) else "\n"
            stream.write(f"  X({row['symbol']}){suffix}")
        stream.write("\n")

package_blocks = paths["cargo_lock_sha256"].read_text(encoding="utf-8").split("[[package]]")[1:]
registry_packages = []
for block in package_blocks:
    fields = {}
    for field in ("name", "version", "source", "checksum"):
        match = re.search(rf'(?m)^{field} = "([^"\\]+)"$', block)
        if match:
            fields[field] = match.group(1)
    source = fields.get("source")
    if source is None:
        continue
    require("Cargo source", source, "registry+https://github.com/rust-lang/crates.io-index")
    registry_packages.append((fields["name"], fields["version"], fields["checksum"]))
require("registry package count", len(registry_packages), metadata["build"]["registry_packages"])
if registry_cache.is_symlink() or not registry_cache.is_dir():
    raise SystemExit("registry archive cache is not a real directory")
vendor_root = snapshot / "vendor"
vendor_root.mkdir()
for name, version, checksum in registry_packages:
    archive_name = f"{name}-{version}.crate"
    matches = []
    for namespace in registry_cache.iterdir():
        if namespace.is_symlink() or not namespace.is_dir():
            raise SystemExit(f"invalid registry cache namespace: {namespace}")
        candidate = namespace / archive_name
        if candidate.exists():
            matches.append(candidate)
    if len(matches) != 1:
        raise SystemExit(f"expected one cached archive for {name} {version}, found {matches}")
    archive_bytes = matches[0].read_bytes()
    require(f"Cargo checksum {name} {version}", sha(archive_bytes), checksum)
    package_root_name = f"{name}-{version}"
    package_root = vendor_root / package_root_name
    package_root.mkdir()
    file_hashes = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            member_path = pathlib.PurePosixPath(member.name)
            parts = member_path.parts
            if not parts or parts[0] != package_root_name or any(part in ("", ".", "..") for part in parts):
                raise SystemExit(f"unsafe crate path: {member.name!r}")
            relative_parts = parts[1:]
            if not relative_parts:
                if not member.isdir():
                    raise SystemExit(f"crate root is not a directory: {member.name!r}")
                continue
            relative = pathlib.PurePosixPath(*relative_parts).as_posix()
            if relative in seen:
                raise SystemExit(f"duplicate crate path: {member.name!r}")
            seen.add(relative)
            destination = package_root.joinpath(*relative_parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                destination.chmod(member.mode & 0o777)
                continue
            if not member.isfile():
                raise SystemExit(f"unsupported crate member: {member.name!r}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            file_object = archive.extractfile(member)
            if file_object is None:
                raise SystemExit(f"crate member has no data: {member.name!r}")
            data = file_object.read()
            require(f"crate member size {member.name}", len(data), member.size)
            destination.write_bytes(data)
            destination.chmod(member.mode & 0o777)
            file_hashes[relative] = sha(data)
    (package_root / ".cargo-checksum.json").write_text(
        json.dumps({"files": file_hashes, "package": checksum}, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    "[source.crates-io]\nreplace-with = \"locked-vendor\"\n\n"
    "[source.locked-vendor]\n"
    f"directory = {json.dumps(str(vendor_root))}\n",
    encoding="utf-8",
)
PY

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
archive_members="$oracle_tmp/libdecomp.members"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_ar_bin" t "$standard_archive" \
  >"$archive_members"
synthetic_id_source="$oracle_tmp/marshal_id_synthetic_projection.cc"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$oracle_cpp" "$archive_members" "$synthetic_id_source" \
  "$snapshot_root/tests/oracle/marshal_id_1204.metadata.json" <<'PY'
import json
import pathlib
import re
import sys

oracle_cpp = pathlib.Path(sys.argv[1])
member_path = pathlib.Path(sys.argv[2])
synthetic_path = pathlib.Path(sys.argv[3])
metadata = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
pattern = re.compile(
    r'^\s*(AttributeId|ElementId)\s+\w+\s*=\s*\1\('
    r'"[^"]+",\s*\d+(?:,\s*([^\)]+))?\)', re.M
)
archive_sources = {
    pathlib.Path(member).stem + ".cc"
    for member in member_path.read_text(encoding="utf-8").splitlines()
}
rows = []
for source_name in metadata["oracle"]["source_blobs"]:
    source = oracle_cpp / source_name
    for match in pattern.finditer(source.read_text(encoding="utf-8")):
        if (match.group(2) or "0").strip() == "0":
            full = match.group(0)
            symbol_match = re.match(r'^\s*(AttributeId|ElementId)\s+(\w+)\s*=\s*', full)
            value_match = re.search(r'\("([^"]+)",\s*(\d+)', full)
            if symbol_match is None or value_match is None:
                raise SystemExit(f"could not project source declaration: {full!r}")
            rows.append({
                "source": source_name,
                "kind": match.group(1),
                "symbol": symbol_match.group(2),
                "name": value_match.group(1),
                "id": int(value_match.group(2)),
            })
standard = [row for row in rows if row["source"] in archive_sources]
extras = [row for row in rows if row["source"] not in archive_sources]
standard_attributes = sum(row["kind"] == "AttributeId" for row in standard)
standard_elements = sum(row["kind"] == "ElementId" for row in standard)
expected_coverage = metadata["coverage"]
if (standard_attributes, standard_elements, len(standard)) != (
    expected_coverage["standard_libdecomp_attribute_count"],
    expected_coverage["standard_libdecomp_element_count"],
    expected_coverage["standard_libdecomp_total_count"],
):
    raise SystemExit(
        "standard libdecomp scope-0 projection mismatch: "
        f"attributes={standard_attributes} elements={standard_elements} total={len(standard)}"
    )
extra_sources = sorted({row["source"] for row in extras})
expected_extra_sources = [
    "bfd_arch.cc", "callgraph.cc", "ghidra_arch.cc", "ghidra_process.cc",
    "loadimage_xml.cc", "raw_arch.cc", "sleigh_arch.cc", "xml_arch.cc",
]
if extra_sources != expected_extra_sources:
    raise SystemExit(f"alternate-front-end source complement mismatch: {extra_sources}")
if len(extras) != expected_coverage["alternate_frontend_only_count"]:
    raise SystemExit(f"alternate-front-end ID count mismatch: {len(extras)}")
lines = ['#include "marshal.hh"', '', 'namespace ghidra {', '']
for row in extras:
    lines.append(
        f'{row["kind"]} {row["symbol"]} = '
        f'{row["kind"]}({json.dumps(row["name"])},{row["id"]});'
    )
lines.extend(['', '} // End namespace ghidra', ''])
synthetic_path.write_text("\n".join(lines), encoding="utf-8")
PY

fixture_target="$oracle_tmp/cargo-target"
for cargo_config in \
  "$snapshot_root/.cargo/config" "$snapshot_root/.cargo/config.toml" \
  "$oracle_tmp/.cargo/config" "$oracle_tmp/.cargo/config.toml" \
  "/tmp/.cargo/config" "/tmp/.cargo/config.toml" \
  "/.cargo/config" "/.cargo/config.toml"; do
  if [[ -e "$cargo_config" ]]; then
    echo "ambient Cargo config is outside the comparand: $cargo_config" >&2
    exit 1
  fi
done
if ! (
  cd "$snapshot_root"
  /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
    RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
    AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --quiet --locked --offline --lib
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" ]]; then
  echo "cargo build did not produce a regular librudra.rlib" >&2
  exit 1
fi
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f
)
if [[ "${#native_archives[@]}" -ne 1 ]]; then
  echo "expected one Cargo-built librudra_sleigh.a, found ${#native_archives[@]}" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")

cpp_fixture="$snapshot_root/tests/oracle/marshal_id_1204.cc"
generated_header="$snapshot_root/tests/oracle/marshal_id_generated.hh"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  -I"$snapshot_root/tests/oracle" "$cpp_fixture" "$synthetic_id_source" \
  "$standard_archive" -lz \
  -o "$oracle_tmp/marshal_id_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

rust_fixture="$snapshot_root/tests/oracle/marshal_id_1204.rs"
if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/marshal_id_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/marshal_id_1204_cpp" >"$oracle_tmp/ghidra.stdout"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/marshal_id_1204_rust" >"$oracle_tmp/rudra.stdout"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$snapshot_root/tests/oracle/marshal_id_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
if ghidra != rudra:
    raise SystemExit("byte comparison unexpectedly diverged after diff succeeded")
if not ghidra.endswith(b"\n"):
    raise SystemExit("fixture output lacks final newline")
lines = ghidra.decode("utf-8").splitlines()
counts = {prefix: sum(line.startswith(prefix + "|") for line in lines) for prefix in ("H", "A", "E", "C", "T", "S")}
expected = {"H": 1, "A": 146, "E": 274, "C": 1, "T": 1, "S": 1}
if counts != expected or len(lines) != 424:
    raise SystemExit(f"fixture record count mismatch: {counts}, total={len(lines)}")
if lines[0] != "H|1|146|274|159|289":
    raise SystemExit("fixture header mismatch")
if lines[-3] != "C|19|20|159|289|159|289|NONE|NONE|19|1":
    raise SystemExit("fixture constants/unknown observation mismatch")
if lines[-2] != "T|1|1|19,159,20,0|1|1|0|289|289|0|0|0|0":
    raise SystemExit("fixture TreeDecoder observation mismatch")
if lines[-1] != "S|MATCH|420|0":
    raise SystemExit("fixture summary mismatch")
capture = metadata["locked_capture"]
actual_hash = hashlib.sha256(ghidra).hexdigest()
if isinstance(capture["bytes"], str) and capture["bytes"].startswith("PENDING"):
    raise SystemExit(
        f"locked capture is pending: records={len(lines)} bytes={len(ghidra)} "
        f"stdout_sha256={actual_hash}"
    )
if len(ghidra) != capture["bytes"] or len(lines) != capture["records"]:
    raise SystemExit("locked capture size mismatch")
if actual_hash != capture["stdout_sha256"]:
    raise SystemExit("locked capture hash mismatch")
print(lines[0])
print(lines[-3])
print(lines[-2])
print(lines[-1])
PY
