#!/usr/bin/env bash
# Locked-oracle stage projection producer for the stage-bisect harness
# (spec v1.2 + v1.2.1 opcode-domain erratum).  Verifies the locked Ghidra
# tree, rebuilds the fixture against an instrumented temporary copy of the
# oracle source, runs the stepping walk, validates the full v1.2.1 stream,
# and installs the projection at the RAM-disk product path.
#
# CLI (batch-driver contract: bash tools/run_<runner>.sh <corpus> <entry> <fn>)
#   run_stage_projection_oracle.sh                          # pinned default:
#   run_stage_projection_oracle.sh curl 4ff0 next_url       #   curl next_url @0x4ff0
#   run_stage_projection_oracle.sh curl 0x25a0 main         # parameterized target
#   run_stage_projection_oracle.sh httpd 0x2b820 main
#   run_stage_projection_oracle.sh curl 22f0 -              # address-only target
#
# corpus is curl|httpd -> examples/<corpus>; entry_addr is hex (0x optional).
# The zero-argument / next_url form keeps the legacy fully-pinned mode
# (metadata input pins + expected projection sha256/counts) and the legacy
# output name next_url.oracle.projection.  Parameterized targets resolve
# pins from the metadata "functions" map (key "<corpus>/<func>",
# per-function comparand: entry, binary_sha256, projection_expectations);
# a target absent from the map runs in capture mode: full structural
# validation only (META keys / seq contiguity / LIFO nesting / @SNAP counts /
# v1.2.1 grammar), sha256 + counts reported for later pinning.
#
# Address-only targets (func_name "-", mode=address) pass STAGE_PROJ_ADDR
# without STAGE_PROJ_FUNC: the fixture keeps the address query first and,
# when no symbol covers the entry (PLT thunks), registers the function at
# the address the way the console `load <addr>` command does.  They always
# run in capture mode (the address carries no name identity to pin a
# "functions" key on; the bank manifest is the pin of record) and the META
# func_name field is left unvalidated here: the fixture derives it via
# Architecture::nameFunction, the rugra driver carries the ledger spelling,
# and the bisect treats func_name as advisory (the same contract as the
# BFD/DWARF constprop spelling differences).
#
# RUDRA_STAGE_PROJECTION_BUILD=<dir> optionally caches the instrumented
# oracle build (extracted tree + libdecomp.a + linked fixture) across
# invocations.  Batch drivers set it once and rebuild only when the fixture
# changes: the tree inside is produced from the locked commit + sha-pinned
# instrumentation only, so a cached binary equals a fresh build.
#
# Canonical capture recipe (baked in; mirrors tools/run_stage_drill_oracle.sh,
# Lane AT broadcast): cwd=repo_root, argv=sleigh_specs examples/<corpus>
# (relative), env=`env -i` + STAGE_PROJ_FUNC/STAGE_PROJ_ADDR only, ASLR off
# via `setarch -R`.  The oracle's application order depends on the process's
# early heap allocation sequence; argv path form selects the variant
# (relative vs absolute demonstrably flip the drill stream) and ASLR makes
# large functions (curl/httpd main) unstable run-to-run, so both are pinned.
# The zero-argument form runs the same recipe without the target variables,
# keeping the fixture on its historical argv-entry lookup path.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tools/run_stage_projection_oracle.sh [corpus entry_addr func_name]
  corpus:      curl | httpd (examples/<corpus> binary)
  entry_addr:  hex entry of the function (0x prefix optional)
  func_name:   BFD symbol name (STAGE_PROJ_FUNC target of the harness)
               "-": address-only target (STAGE_PROJ_ADDR arm; the fixture
                    registers the function at the entry when no BFD symbol
                    covers it -- PLT thunks)
  no arguments: pinned default capture of curl next_url @0x4ff0
EOF
}

mode=parameterized
corpus=curl
func=next_url
entry=0x4ff0
if [[ $# -eq 0 ]]; then
  mode=default
elif [[ $# -eq 3 ]]; then
  corpus=$1
  entry=$2
  func=$3
else
  usage
  exit 2
fi
addr_only=no
if [[ "$func" == "-" ]]; then
  if [[ "$mode" != "parameterized" ]]; then
    echo "address-only target '-' needs the parameterized form" >&2
    exit 2
  fi
  addr_only=yes
  mode=address
fi
case "$corpus" in
  curl|httpd) ;;
  *) echo "unknown corpus: $corpus (expected curl|httpd)" >&2; exit 2 ;;
esac
case "$entry" in
  0x?*|0X?*) entry_digits=${entry:2} ;;
  *) entry_digits=$entry ;;
esac
if [[ "$entry_digits" =~ ^[0-9a-fA-F]+$ ]]; then
  entry_norm=$(printf '0x%x' "$((16#$entry_digits))")
else
  echo "entry_addr is not hexadecimal: $entry" >&2
  exit 2
fi
# The fixture's argv-entry parser is the historical bare-hex form; the
# canonical STAGE_PROJ_ADDR carries the 0x-prefixed pin text.
entry_arg=${entry_norm#0x}

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/stage_projection_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/stage_projection_1204.cc"
binary="$repo_root/examples/$corpus"
spec_root="$repo_root/sleigh_specs"
analysis_options=default
if [[ "$mode" == "default" ]]; then
  projection_out=${RUDRA_STAGE_PROJECTION_OUT:-/dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection}
elif [[ "$mode" == "address" ]]; then
  projection_out=${RUDRA_STAGE_PROJECTION_OUT:-/dev/shm/rugra-tests/sb-oracle/${corpus}.addr${entry_norm}.oracle.projection}
else
  projection_out=${RUDRA_STAGE_PROJECTION_OUT:-/dev/shm/rugra-tests/sb-oracle/${corpus}.${func}.oracle.projection}
fi

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
if [[ -n "$(git -C "$repo_root" status --porcelain -- "$cpp_fixture" "$metadata")" ]]; then
  echo "fixture or metadata has uncommitted changes" >&2
  exit 1
fi

bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" && -f /usr/include/bfd.h ]]; then
  bfd_include=/usr/include
fi
if [[ -z "$bfd_include" && -f /tmp/rugra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" ]]; then
  echo "binutils 2.38 bfd.h not found; set RUDRA_BFD_INCLUDE" >&2
  exit 1
fi
bfd_library=${RUDRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD library not found: $bfd_library" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$binary" "$spec_root" \
  "$bfd_include/bfd.h" "$bfd_library" "$oracle_commit" "$oracle_tag" \
  "$mode" "$corpus" "$func" "$entry_norm" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_name,
    binary_name,
    spec_root_name,
    bfd_header_name,
    bfd_library_name,
    oracle_commit,
    oracle_tag,
    mode,
    corpus,
    func,
    entry_norm,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("unexpected compiler-spec metadata")

def digest(name):
    return hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()

comparands = {"cpp_fixture": cpp_name}
for key, name in comparands.items():
    actual = digest(name)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(f"{key} hash mismatch: {actual}")
producer = subprocess.check_output(
    ["git", "hash-object", cpp_name], text=True
).strip()
if metadata["projection_expectations"].get("producer_blob") != producer:
    raise SystemExit(f"producer blob drifted: {producer}")

# Per-function pin lookup (metadata["functions"], key "<corpus>/<func>",
# same map contract as stage_drill_1204.metadata.json).
functions = metadata.get("functions", {})
func_entry = functions.get(f"{corpus}/{func}") if mode == "parameterized" else None

shared_assets = {
    "sla_sha256": pathlib.Path(spec_root_name) / "x86-64.sla",
    "pspec_sha256": pathlib.Path(spec_root_name) / "x86-64.pspec",
    "cspec_sha256": pathlib.Path(spec_root_name) / "x86-64-gcc.cspec",
    "ldefs_sha256": pathlib.Path(spec_root_name) / "x86.ldefs",
    "bfd_header_sha256": bfd_header_name,
    "bfd_library_sha256": bfd_library_name,
}
binary_pins = {}  # expected sha256 -> file to check against
if mode == "default":
    actual_input = json.dumps(
        metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    fingerprint = "sha256:" + hashlib.sha256(actual_input).hexdigest()
    if metadata.get("input_fingerprint") != fingerprint:
        raise SystemExit("input fingerprint mismatch")
    shared_assets["binary_sha256"] = binary_name
elif func_entry is not None:
    normalize = lambda s: s.lower().removeprefix("0x").lstrip("0") or "0"
    pinned_entry = func_entry.get("entry", "")
    if normalize(pinned_entry) != normalize(entry_norm):
        raise SystemExit(
            f"functions[{corpus}/{func}] entry pin mismatch: {pinned_entry} vs {entry_norm}"
        )
    if "binary_sha256" in func_entry:
        binary_pins[func_entry["binary_sha256"]] = binary_name
    elif corpus == "curl":
        # examples/curl is already pinned by the top-level assets block.
        shared_assets["binary_sha256"] = binary_name
    # corpus binary without any pin (fresh httpd target): capture mode for
    # the binary asset, reported by the post-run block.
else:
    if corpus == "curl":
        shared_assets["binary_sha256"] = binary_name
for expected, name in binary_pins.items():
    actual = digest(name)
    if actual != expected:
        raise SystemExit(f"{corpus}/{func} binary_sha256 mismatch: {actual}")
for key, name in shared_assets.items():
    actual = digest(name)
    if metadata["assets"].get(key) != actual:
        raise SystemExit(f"{key} mismatch: {actual}")
compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
if metadata.get("host_compiler") != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
PY

oracle_tmp=$(mktemp -d /tmp/rugra-stage-projection-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-stage-projection-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Optional build cache (see the header comment): batch drivers set
# RUDRA_STAGE_PROJECTION_BUILD so the instrumented tree + libdecomp.a +
# linked fixture are built once per fixture change instead of once per
# target.  A cached binary is produced from the locked commit + sha-pinned
# instrumentation + the same fixture the pre-run block just hash-verified,
# so it equals a fresh build; the run scratch (projection.txt / stderr)
# stays in the per-invocation mktemp dir.
build_cache=${RUDRA_STAGE_PROJECTION_BUILD:-}
oracle_bin="$oracle_tmp/stage_projection_1204"
if [[ -n "$build_cache" && -x "$build_cache/stage_projection_1204" ]]; then
  oracle_bin="$build_cache/stage_projection_1204"
fi

if [[ "$oracle_bin" == "$oracle_tmp/stage_projection_1204" ]]; then
  if [[ -n "$build_cache" ]]; then
    # First invocation with an empty cache: build here, then populate the
    # cache with the finished binary (atomic mv).
    mkdir -p "$build_cache"
  fi

git -C "$ghidra_root" archive --format=tar --output="$oracle_tmp/ghidra.tar" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/oracle"
tar -xf "$oracle_tmp/ghidra.tar" -C "$oracle_tmp/oracle"
oracle_cpp="$oracle_tmp/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"

# Observation-only accessor for ActionRestartGroup::curstart (implicitly
# private members; the fixture's access-macro include wrapper only rewrites
# explicit labels).  Same instrumentation as run_action_break_pool_oracle.sh.
python3 -I -S - "$oracle_cpp/action.hh" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
header = pathlib.Path(sys.argv[1])
text = header.read_text(encoding="utf-8")
anchor = (
    "class ActionRestartGroup : public ActionGroup {\n"
    "  int4 maxrestarts;\t\t\t///< Maximum number of restarts allowed\n"
    "  int4 curstart;\t\t\t///< Current restart iteration\n"
    "public:\n"
)
insertion = "  int4 fixtureGetCurstart(void) const { return curstart; }\n"
if text.count(anchor) != 1:
    raise SystemExit("action.hh instrumentation anchor drifted")
text = text.replace(anchor, anchor + insertion)
header.write_text(text, encoding="utf-8")
actual = hashlib.sha256(header.read_bytes()).hexdigest()
expected = metadata["comparand_sha256"]["ghidra_instrumented_action_hh_sha256"]
if actual != expected:
    raise SystemExit(f"instrumented action.hh mismatch: expected={expected} actual={actual}")
PY

# Observation-only accessors for SleighArchitecture::languageindex /
# ::description (implicitly private: declared with no access label, so the
# macro include wrapper cannot expose them).  The accessors only READ the
# resolved LanguageDescription so the fixture can derive the canonical META
# identity keys (language id + compiler tag id) from the live conf object.
python3 -I -S - "$oracle_cpp/sleigh_arch.hh" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
header = pathlib.Path(sys.argv[1])
text = header.read_text(encoding="utf-8")
anchor = (
    "  static void loadLanguageDescription(const string &specfile,ostream &errs);\n"
    "  bool isTranslateReused(void);\t\t\t\t///< Test if last Translate object can be reused\n"
    "protected:\n"
)
insertion = (
    "public:\n"
    "  int4 fixtureGetLanguageIndex(void) const { return languageindex; }\n"
    "  static const LanguageDescription &fixtureGetLanguage(int4 i) { return description[i]; }\n"
)
if text.count(anchor) != 1:
    raise SystemExit("sleigh_arch.hh instrumentation anchor drifted")
text = text.replace(anchor, anchor.replace("protected:\n", "") + insertion + "protected:\n")
header.write_text(text, encoding="utf-8")
actual = hashlib.sha256(header.read_bytes()).hexdigest()
expected = metadata["comparand_sha256"]["ghidra_instrumented_sleigh_arch_hh_sha256"]
if actual != expected:
    raise SystemExit(f"instrumented sleigh_arch.hh mismatch: expected={expected} actual={actual}")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" \
  "$oracle_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/stage_projection_1204"
if [[ -n "$build_cache" ]]; then
  # Populate the cache only after a fully successful build.
  cp "$oracle_tmp/stage_projection_1204" "$build_cache/stage_projection_1204.tmp"
  mv "$build_cache/stage_projection_1204.tmp" "$build_cache/stage_projection_1204"
fi
fi # end of the (uncached) build branch

binary_sha=$(sha256sum "$binary" | cut -d' ' -f1)
producer=$(git hash-object "$cpp_fixture")

# Canonical capture recipe (see the header comment): repo-root cwd, relative
# argv, scrubbed environment, ASLR off.  The mktemp scratch paths stay
# absolute and never enter the walked code path (only the projection output
# argument, which the fixture opens, and the absolute binary path argument
# are absolute — the binary/spec argv are the relative canonical form).
if ! command -v setarch >/dev/null 2>&1; then
  echo "setarch not found: projection captures require ASLR-disabled execution" >&2
  exit 1
fi
cd "$repo_root"
target_env=()
if [[ "$mode" == "parameterized" ]]; then
  target_env+=(STAGE_PROJ_FUNC="$func" STAGE_PROJ_ADDR="$entry_norm")
elif [[ "$mode" == "address" ]]; then
  target_env+=(STAGE_PROJ_ADDR="$entry_norm")
fi
if ! setarch "$(uname -m)" -R env -i "${target_env[@]}" \
  "$oracle_bin" sleigh_specs "examples/$corpus" \
  "$entry_arg" "$oracle_tmp/projection.txt" "$binary_sha" "$producer" \
  "$analysis_options" 2>"$oracle_tmp/run.stderr"; then
  cat "$oracle_tmp/run.stderr" >&2
  exit 1
fi

if ! python3 -I -S - "$oracle_tmp/projection.txt" "$metadata" \
  "$mode" "$corpus" "$func" "$entry_norm" "$binary_sha" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

projection = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
mode, corpus, func, entry_norm, binary_sha = sys.argv[3:]

raw = projection.read_bytes()
actual_sha = hashlib.sha256(raw).hexdigest()
lines = raw.decode("utf-8").splitlines()
meta = {}
for line in lines[:4]:
    if not line.startswith("META "):
        raise SystemExit(f"missing META header line: {line[:40]!r}")
    for item in line[5:].split(" "):
        key, _, value = item.partition("=")
        meta[key] = value

func_entry = metadata.get("functions", {}).get(f"{corpus}/{func}") \
    if mode == "parameterized" else None
pin = metadata["projection_expectations"] if mode == "default" \
    else (func_entry or {}).get("projection_expectations")

normalize = lambda s: s.lower().removeprefix("0x").lstrip("0") or "0"
if normalize(meta.get("func_entry", "")) != normalize(entry_norm):
    raise SystemExit(
        f"META func_entry drifted: {meta.get('func_entry')!r} != {entry_norm}"
    )
fields = {
    "side": "oracle",
    "oracle_commit": metadata["oracle"]["commit"],
    "arch": metadata["architecture"],
    "cspec": metadata["compiler_spec"],
    "analysis_options": "default",
    "build_flags": "v1-no-OPACTION_DEBUG",
    "binary_sha256": binary_sha,
    "load_mode": metadata["analysis_options"]["load_mode"],
    "producer": metadata["projection_expectations"]["producer_blob"],
    "maxrestarts": str(metadata["input"]["maxrestarts"]),
    "unique_base": metadata["input"]["unique_base"],
    "func_name": metadata["input"]["function"] if mode == "default" else func,
}
if mode == "address":
    # Address-only target: the fixture derives the name via
    # Architecture::nameFunction while the rugra driver carries the ledger
    # spelling, so func_name is advisory-only here (the same bisect
    # contract as the constprop BFD/DWARF spellings); every identity key
    # (func_entry above, binary, oracle pins) stays validated.
    del fields["func_name"]
for key, value in fields.items():
    if meta.get(key) != value:
        raise SystemExit(f"META field {key} drifted: {meta.get(key)!r} != {value!r}")

begins, ends, snaps, restarts = {}, {}, [], 0
stack = []
op_lines = 0
pending = None
# v1.2.1 op-line grammar.  <OPC_NAME> is the CPUI enum domain: the fixture
# emits get_opname(op->code()) verbatim (opcodes.cc opcode_name table), per
# the v1.2.1 opcode-domain ruling.  The check is driven by the OPCODE_DOMAIN
# name-table constant so a re-ruling lands as a one-line change:
#   "cpui"   complete 74-name enum alphabet from opcodes.cc opcode_name
#            (table order; token shape ^[A-Z][A-Z0-9_]*$) — v1.2.1 canonical
#   "typeop" the 34 typeop.cc name spellings this stream carried before the
#            ruling (lossy: goto = BRANCH+CBRANCH, "+" = INT_ADD et al.)
#   "any"    non-blank token only (ruling-free fallback)
OPCODE_DOMAIN = "cpui"
OPCODE_NAMES = {
    "cpui": frozenset((
        "BLANK COPY LOAD STORE "
        "BRANCH CBRANCH BRANCHIND CALL "
        "CALLIND CALLOTHER RETURN INT_EQUAL "
        "INT_NOTEQUAL INT_SLESS INT_SLESSEQUAL INT_LESS "
        "INT_LESSEQUAL INT_ZEXT INT_SEXT INT_ADD "
        "INT_SUB INT_CARRY INT_SCARRY INT_SBORROW "
        "INT_2COMP INT_NEGATE INT_XOR INT_AND "
        "INT_OR INT_LEFT INT_RIGHT INT_SRIGHT "
        "INT_MULT INT_DIV INT_SDIV INT_REM "
        "INT_SREM BOOL_NEGATE BOOL_XOR BOOL_AND "
        "BOOL_OR FLOAT_EQUAL FLOAT_NOTEQUAL FLOAT_LESS "
        "FLOAT_LESSEQUAL UNUSED1 FLOAT_NAN FLOAT_ADD "
        "FLOAT_DIV FLOAT_MULT FLOAT_SUB FLOAT_NEG "
        "FLOAT_ABS FLOAT_SQRT INT2FLOAT FLOAT2FLOAT "
        "TRUNC CEIL FLOOR ROUND "
        "BUILD DELAY_SLOT PIECE SUBPIECE CAST "
        "LABEL CROSSBUILD SEGMENTOP CPOOLREF NEW "
        "INSERT EXTRACT POPCOUNT LZCOUNT"
    ).split(" ")),
    "typeop": frozenset((
        "! != & && * + - / < << <= == >> ? [] ^ | || "
        "call callind CARRY (cast) CONCAT copy goto load POPCOUNT return "
        "SBORROW SCARRY SEXT store SUB ZEXT"
    ).split(" ")),
    "any": None,
}
OPCODE_TOKEN_SHAPES = {
    "cpui": r"[A-Z][A-Z0-9_]*",
    "typeop": r"\S+",
    "any": r"\S+",
}
op_re = re.compile(
    r"^[0-9a-f]+:[0-9a-f]+ " + OPCODE_TOKEN_SHAPES[OPCODE_DOMAIN]
    + r" d=[01] out=\S+ in=\S+$"
)
# v1.2 vn descriptors: c:/n:/u: (v1.1) plus the pointer pseudonyms
# s:<spacename>, f:<addr>:<time> (fspec), o:<addr>:<time> / o:- (iop),
# ratified by the v1.2 addendum.
vn_re = re.compile(
    r"^(c:[0-9a-f]+:\d+|n:[A-Za-z0-9_]+:[0-9a-f]+:\d+|u:[0-9a-f]+:\d+"
    r"|s:[A-Za-z0-9_]+|f:[0-9a-f]+:[0-9a-f]+|o:[0-9a-f]+:[0-9a-f]+|o:-|-)$"
)
for ln, line in enumerate(lines, 1):
    if line.startswith("META") or line.startswith("@"):
        if pending is not None:
            raise SystemExit(f"line {ln}: @SNAP block truncated")
        if line.startswith("@BEGIN"):
            seq = int(line.split()[1]); begins[seq] = line.split()[2]
            stack.append(seq)
        elif line.startswith("@END"):
            part = line.split()
            seq = int(part[1])
            ends[seq] = part[2]
            if begins.get(seq) != part[2]:
                raise SystemExit(f"line {ln}: seq {seq} path mismatch")
            if not stack or stack[-1] != seq:
                raise SystemExit(f"line {ln}: nesting violation closing seq {seq}")
            stack.pop()
            if not re.match(
                r"^@END \d+ \S+ result=-?\d+ count=-?\d+ tests=\d+ apply=\d+$", line
            ):
                raise SystemExit(f"line {ln}: @END grammar")
        elif line.startswith("@SNAP"):
            pending = int(line.split()[3]); snaps.append(pending)
        elif line.startswith("@RESTART"):
            restarts += 1
    elif pending is not None:
        if not op_re.match(line):
            raise SystemExit(f"line {ln}: op-line grammar: {line[:80]}")
        parts = line.split(" ", 3)
        opcode_allowed = OPCODE_NAMES[OPCODE_DOMAIN]
        if opcode_allowed is not None and parts[1] not in opcode_allowed:
            raise SystemExit(
                f"line {ln}: opcode token {parts[1]!r} outside "
                f"OPCODE_DOMAIN={OPCODE_DOMAIN!r}"
            )
        for token in re.split(r"out=|in=|,", parts[3]):
            token = token.strip()
            if token and not vn_re.match(token):
                raise SystemExit(f"line {ln}: varnode descriptor {token!r}")
        op_lines += 1; pending -= 1
        if pending == 0: pending = None
    else:
        raise SystemExit(f"line {ln}: stray record outside @SNAP: {line[:60]!r}")

if len(begins) != len(ends):
    raise SystemExit(f"event count drifted: {len(begins)}/{len(ends)}")
if sorted(begins) != list(range(1, len(begins) + 1)):
    raise SystemExit("seq numbers are not contiguous 1-based")
if set(begins) != set(ends):
    raise SystemExit("@BEGIN/@END seq sets differ")
if stack:
    raise SystemExit(f"unclosed events at EOF: {stack}")

stats = {
    "begins": len(begins),
    "ends": len(ends),
    "snaps": len(snaps),
    "restarts": restarts,
    "total_op_lines": op_lines,
    "max_snap_ops": max(snaps) if snaps else 0,
    "min_snap_ops": min(snaps) if snaps else 0,
    "bytes": len(raw),
}
if pin is not None:
    for key, value in stats.items():
        if pin.get(key) != value:
            raise SystemExit(f"{key} drifted: {value} (pinned {pin.get(key)})")
    if actual_sha != pin["sha256"]:
        raise SystemExit(f"projection sha256 drifted: {actual_sha}")
else:
    if mode == "default":
        raise SystemExit("default mode requires projection_expectations")
pin_state = "pinned" if pin is not None else "capture(unpinned)"
target_label = f"{corpus}/addr:{entry_norm}" if mode == "address" else f"{corpus}/{func}"
print(
    f"stage_projection_1204: target={target_label} entry={entry_norm} "
    f"mode={pin_state}"
)
print(
    "stage_projection_1204: events={begins} snaps={snaps} "
    "ops={total_op_lines} restarts={restarts} bytes={bytes}".format(**stats)
)
if pin is None:
    print(
        "stage_projection_1204: max_snap_ops={max_snap_ops} "
        "min_snap_ops={min_snap_ops}".format(**stats)
    )
    print(f"stage_projection_1204: sha256={actual_sha} binary_sha256={binary_sha}")
PY
then
  # A drift must be investigable: preserve the offending projection (and
  # the stderr it produced) before the EXIT trap wipes the scratch dir.
  drift_dir=/dev/shm/rugra-tests/sb-oracle/drift
  mkdir -p "$drift_dir"
  drift_tag=$(date +%Y%m%d_%H%M%S)
  drift_tag_name=${func}
  if [[ "$mode" == "address" ]]; then
    drift_tag_name=addr${entry_norm}
  fi
  cp "$oracle_tmp/projection.txt" "$drift_dir/${corpus}.${drift_tag_name}.${drift_tag}.projection"
  cp "$oracle_tmp/run.stderr" "$drift_dir/${corpus}.${drift_tag_name}.${drift_tag}.stderr"
  echo "drift artifacts preserved in $drift_dir/${corpus}.${drift_tag_name}.${drift_tag}.*" >&2
  exit 1
fi

install -D -m 0644 "$oracle_tmp/projection.txt" "$projection_out"
printf 'projection installed at %s\n' "$projection_out"
