#!/usr/bin/env python3
"""regen_ghidra_golden.py — regenerate the locked-oracle Ghidra 12.0.4 golden
C outputs for the curl and httpd regression binaries (TODO ORACLE-0002).

Canonical path (path 1): a real Ghidra 12.0.4 headless distribution built from
the locked source commit by tools/build_ghidra_1204_headless.sh.  The
distribution's analyzeHeadless imports each binary, runs the default headless
analysis (loader, PLT, references, demangler, DWARF, ...) and drives the
postScript tools/ghidra_decompile_all.py, which decompiles every function and
writes the `/* ---- 0xADDR: NAME (SIZE bytes) ---- */` blocks this project's
differential tooling expects.  Pass --headless <analyzeHeadless> (defaults to
the location tools/build_ghidra_1204_headless.sh produces).

Supplementary path (fallback A): a "direct runner" that compiles the locked
decompiler C++ tree (git archive of the oracle commit, never the working
checkout) together with an embedded fixture that mirrors
tests/oracle/getstr_pipeline_1204.cc: BfdArchitecture over the locked
sleigh_specs assets, per-function followFlow + full universal action +
PrintC docFunction.  It is NOT the Java headless analyzer: loader symbols come
from the BFD static/dynamic tables plus raw .rela.plt parsing, no analyzer
options / demangler / DWARF / reference analysis run, and image addresses are
BFD VMAs (PIE base 0).  Use --direct-runner to (re)generate the supplementary
golden ghidra_<name>_1204.direct-runner.c and to quantify the equivalence gap
against the canonical headless golden.

Outputs (per target, written under tests/golden/):
  ghidra_<name>_1204.c                        canonical (headless) golden
  ghidra_<name>_1204.provenance.json          full provenance + ledger
  ghidra_<name>_1204.direct-runner.c          supplementary direct-runner golden

Self-check (acceptance for ORACLE-0002):
  python3 tools/regen_ghidra_golden.py --check

Exit codes: 0 success, 1 any failure.
"""

import argparse
import difflib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

ORACLE_TAG = "Ghidra_12.0.4_build"
ORACLE_COMMIT = "e40ed13014025f82488b1f8f7bca566894ac376b"
EXPECTED_CPP_TREE = "b02e230a539c65de14e50f357d0ba834d8184f4f"
EXPECTED_X86_LANGUAGE_TREE = "84265e1e6fe7ac9725367b57fb861253e4915984"
ARCHITECTURE = "x86:LE:64:default"
COMPILER_SPEC = "gcc"

DEFAULT_HEADLESS = Path(
    "/tmp/rugra-ghidra-1204-headless/dist/ghidra_12.0.4_DEV/support/analyzeHeadless"
)

EXPECTED_ASSET_SHA256 = {
    "x86-64.sla": "406bfa48bca420786dd61e2b739913c30f85822fff5af1b1a10578e3b83cf52a",
    "x86-64.pspec": "3c3dab75a2ac0b98b0552856f690e613d661e0df7cf94d6252e5604d9821629f",
    "x86-64-gcc.cspec": "5eaa848f3eba7ebd4023541f9f37645dae077e8426fb562592f398d599530a9e",
    "x86.ldefs": "b2aa14d94a6162844b18bf47f2aed8579bf90cef3459f6e322b9c1f58146098b",
}

# Input lineage for examples/curl (checked into git 2026-08-13 with DWARF,
# GetStr@0x36d0+74 — the binary used by every wave since PIPE-REACH-0001):
#   2026-08-12 DWARF-PROTO-0001 era recorded sha256 4ee4002b...c6b5d1a
#   2026-08-13+ current binary sha256 8af50bca...22d41  (pinned below)
# The 11.3.2 golden (tests/golden/ghidra_curl.c) was generated from yet
# another, older curl build (its GetStr is 68 bytes, not 74), so part of the
# 11.3.2-vs-12.0.4 diff comes from input drift, not from the Ghidra version.
CURL_INPUT_SHA256 = "8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41"

TARGETS = {
    "curl": {
        "binary": REPO_ROOT / "examples" / "curl",
        "golden": REPO_ROOT / "tests" / "golden" / "ghidra_curl_1204.c",
        "provenance": REPO_ROOT / "tests" / "golden" / "ghidra_curl_1204.provenance.json",
        "direct_runner": REPO_ROOT / "tests" / "golden" / "ghidra_curl_1204.direct-runner.c",
        "legacy_golden": REPO_ROOT / "tests" / "golden" / "ghidra_curl.c",
        "legacy_version": "11.3.2",
        "expected_input_sha256": CURL_INPUT_SHA256,
        "headless_timeout": 2400,
        "determinism_rerun": True,
        "direct_runner_cross_check": True,
    },
    "httpd": {
        "binary": REPO_ROOT / "examples" / "httpd",
        "golden": REPO_ROOT / "tests" / "golden" / "ghidra_httpd_1204.c",
        "provenance": REPO_ROOT / "tests" / "golden" / "ghidra_httpd_1204.provenance.json",
        "direct_runner": REPO_ROOT / "tests" / "golden" / "ghidra_httpd_1204.direct-runner.c",
        "legacy_golden": None,
        "legacy_version": None,
        "expected_input_sha256": None,
        "headless_timeout": 7200,
        "determinism_rerun": False,
        "direct_runner_cross_check": True,
    },
}

BFD_INCLUDE_CANDIDATES = [
    os.environ.get("RUDRA_BFD_INCLUDE", ""),
    "/tmp/rugra-ghidra-bfd-2.38/usr/include",
    "/usr/include",
]
BFD_LIBRARY_CANDIDATES = [
    os.environ.get("RUDRA_BFD_LIBRARY", ""),
    "/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so",
]

HEADLESS_EQUIVALENCE_NOTES = [
    "canonical golden produced by a real analyzeHeadless distribution built "
    "from the locked oracle commit with tools/build_ghidra_1204_headless.sh",
    "postScript decompilation timeout is 30s per function "
    "(tools/ghidra_decompile_all.py); functions exceeding it are recorded as "
    "FAILED blocks, not omitted",
    "addresses use the headless image base 0x100000 for PIE binaries",
]

DIRECT_RUNNER_EQUIVALENCE_RISKS = [
    "direct-runner golden: functions come from BFD static+dynamic symbol "
    "tables plus raw .rela.plt JUMP_SLOT parsing only; a real headless "
    "import discovers additional functions (analyzer-discovered symbol-less "
    "code) that are absent here",
    "no Java analyzer runs: no demangler, no function-id signatures, no "
    "reference/string analyzers, no DWARF prototype import, no headless "
    "analyzer options; the decompiler library performs its own parameter "
    "recovery instead",
    "image addresses are BFD VMAs (PIE base 0, e.g. 0x25a0) instead of the "
    "headless image base 0x100000 (e.g. 0x1025a0)",
    "raw ELF symbol names are preserved (GCC suffixes like .constprop.0 "
    "survive) whereas the headless analyzer strips them",
    "fixture loader ingestion re-implements Architecture::readLoaderSymbols "
    "(architecture.cc) but skips undefined import symbols, which console "
    "mode would register at offset 0 with no code",
    "canonical mode decompiles each function in a fresh process/architecture; "
    "cross-function analysis state (callee prototype discovery order) can "
    "differ from a single-session sequential decompilation — the recorded "
    "determinism check proves the hermetic mode is at least self-stable",
]

# ---------------------------------------------------------------------------
# Embedded C++ fixture (compiled against the git-archive'd locked cpp tree).
# ---------------------------------------------------------------------------

FIXTURE_CPP = r'''/*
 * golden_dump_1204.cc — locked Ghidra 12.0.4 direct-runner golden generator
 * (ORACLE-0002 fallback A).  Mirrors tests/oracle/getstr_pipeline_1204.cc:
 * BfdArchitecture over the locked sleigh_specs assets, full universal action,
 * PrintC docFunction.
 *
 * Modes:
 *   golden_dump_1204 list SPEC_ROOT BINARY OUT_JSON
 *   golden_dump_1204 all  SPEC_ROOT BINARY OUT_DIR
 *   golden_dump_1204 one  SPEC_ROOT BINARY INDEX OUT_JSON
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostream;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

string jsonEscape(const string &value)
{
  ostringstream out;
  for (string::const_iterator iter = value.begin(); iter != value.end(); ++iter) {
    unsigned char ch = static_cast<unsigned char>(*iter);
    switch (ch) {
    case '"': out << "\\\""; break;
    case '\\': out << "\\\\"; break;
    case '\b': out << "\\b"; break;
    case '\f': out << "\\f"; break;
    case '\n': out << "\\n"; break;
    case '\r': out << "\\r"; break;
    case '\t': out << "\\t"; break;
    default:
      if (ch < 0x20) {
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<unsigned int>(ch) << std::dec;
      }
      else
        out << static_cast<char>(ch);
      break;
    }
  }
  return out.str();
}

void writeString(ostream &out,const string &value)
{
  out << '"' << jsonEscape(value) << '"';
}

void registerFunctionSymbol(Architecture &arch, AddrSpace *code,
                             const char *name, uintb value)
{
  if (name == (const char *)0) return;
  Address address(code, value);
  if (arch.symboltab->getGlobalScope()->queryFunction(address) != (Funcdata *)0)
    return; // already registered from another symbol source
  string basename;
  Scope *scope = arch.symboltab->findCreateScopeFromSymbolName(
      name, "::", basename, (Scope *)0);
  scope->addFunction(address, basename);
}

// Mirror Architecture::readLoaderSymbols (architecture.cc) together with
// LoadImageBfd::advanceToNextSymbol's BSF_FUNCTION/name filter, pulling from
// either the static or the dynamic BFD symbol table.  One declared deviation:
// undefined import symbols are skipped — console mode would register them
// as functions at offset 0 with no code behind them.
void registerBfdFunctionSymbols(Architecture &arch,const string &binary,bool dynamicTable)
{
  bfd *abfd = bfd_openr(binary.c_str(),"default");
  if (abfd == (bfd *)0)
    throw runtime_error("bfd_openr failed: " + binary);
  if (!bfd_check_format(abfd, bfd_object)) {
    bfd_close(abfd);
    return;
  }
  long upper = dynamicTable ? bfd_get_dynamic_symtab_upper_bound(abfd)
                            : bfd_get_symtab_upper_bound(abfd);
  if (upper <= 0) {
    bfd_close(abfd);
    return;
  }
  asymbol **symbols = (asymbol **)malloc(upper);
  if (symbols == (asymbol **)0) {
    bfd_close(abfd);
    throw runtime_error("symbol table malloc failed");
  }
  long count = dynamicTable ? bfd_canonicalize_dynamic_symtab(abfd, symbols)
                            : bfd_canonicalize_symtab(abfd, symbols);
  AddrSpace *code = arch.getDefaultCodeSpace();
  for (long index = 0; index < count; ++index) {
    asymbol *symbol = symbols[index];
    if (symbol == (asymbol *)0 || symbol->name == (const char *)0) continue;
    if ((symbol->flags & BSF_FUNCTION) == 0) continue;
    if (symbol->section == (asection *)0 || bfd_is_und_section(symbol->section))
      continue;
    registerFunctionSymbol(arch, code, symbol->name, bfd_asymbol_value(symbol));
  }
  free(symbols);
  bfd_close(abfd);
}

// Register PLT stubs so that calls into imported functions carry the import
// name, mirroring what the headless ELF loader + PLT analysis produces.
// The mapping plt.sec[i] <-> .rela.plt[i] (16-byte entries, JUMP_SLOT only,
// .plt+16*(i+1) when .plt.sec is absent) is the x86-64 psABI contract the
// dynamic loader itself relies on, not a heuristic.  The .dynsym/.dynstr and
// .rela.plt sections are parsed raw (Elf64_Sym / Elf64_Rela) because BFD's
// canonicalized dynamic symbol array drops the null symbol at index 0 and
// therefore does not preserve ELF relocation symbol indices.  .plt.got
// thunks are not registered (known gap: usually only __cxa_finalize).
void registerPltStubs(Architecture &arch,const string &binary)
{
  bfd *abfd = bfd_openr(binary.c_str(),"default");
  if (abfd == (bfd *)0)
    throw runtime_error("bfd_openr failed: " + binary);
  if (!bfd_check_format(abfd, bfd_object)) {
    bfd_close(abfd);
    return;
  }
  asection *relaplt = bfd_get_section_by_name(abfd, ".rela.plt");
  asection *dsymsec = bfd_get_section_by_name(abfd, ".dynsym");
  asection *dstrsec = bfd_get_section_by_name(abfd, ".dynstr");
  asection *pltsec = bfd_get_section_by_name(abfd, ".plt.sec");
  asection *plt = bfd_get_section_by_name(abfd, ".plt");
  bool plausible = relaplt != (asection *)0 && dsymsec != (asection *)0
      && dstrsec != (asection *)0 && (pltsec != (asection *)0 || plt != (asection *)0)
      && (relaplt->size % 24) == 0 && (dsymsec->size % 24) == 0;
  if (plausible) {
    vector<unsigned char> rela(relaplt->size);
    vector<unsigned char> dsym(dsymsec->size);
    vector<unsigned char> dstr(dstrsec->size);
    if (bfd_get_section_contents(abfd, relaplt, &rela[0], 0, relaplt->size)
        && bfd_get_section_contents(abfd, dsymsec, &dsym[0], 0, dsymsec->size)
        && bfd_get_section_contents(abfd, dstrsec, &dstr[0], 0, dstrsec->size)) {
      AddrSpace *code = arch.getDefaultCodeSpace();
      size_t count = rela.size() / 24;
      size_t symbolCount = dsym.size() / 24;
      for (size_t index = 0; index < count; ++index) {
        const unsigned char *record = &rela[index * 24];
        uintb info;
        std::memcpy(&info, record + 8, 8); // Elf64_Rela.r_info
        uint4 type = static_cast<uint4>(info & 0xffffffffU);
        uint4 symindex = static_cast<uint4>(info >> 32);
        if (type != 7 /* R_X86_64_JUMP_SLOT */) continue;
        if (symindex >= symbolCount) continue;
        uint4 nameOffset;
        std::memcpy(&nameOffset, &dsym[symindex * 24], 4); // Elf64_Sym.st_name (4 bytes)
        if (nameOffset >= dstr.size()) continue;
        const char *name = reinterpret_cast<const char *>(&dstr[0]) + nameOffset;
        uintb stub = 0;
        if (pltsec != (asection *)0 && pltsec->size >= (index + 1) * 16)
          stub = pltsec->vma + index * 16;
        else if (plt != (asection *)0 && plt->size >= (index + 2) * 16)
          stub = plt->vma + (index + 1) * 16;
        else
          continue;
        registerFunctionSymbol(arch, code, name, stub);
      }
    }
  }
  bfd_close(abfd);
}

struct FunctionEntry {
  Funcdata *fd;
  string name;
  uintb offset;
};

// Mirror IfaceDecompCommand::iterateFunctionsAddrOrder /
// iterateScopesRecursive (ifacedecomp.cc): every function in the global scope
// and its sub-scopes, in address order.
void collectFunctionsRecursive(Scope *scope, std::set<Funcdata *> &seen,
                                vector<FunctionEntry> &entries)
{
  if (!scope->isGlobal()) return;
  MapIterator miter = scope->begin();
  MapIterator menditer = scope->end();
  while (miter != menditer) {
    Symbol *sym = (*miter)->getSymbol();
    FunctionSymbol *fsym = dynamic_cast<FunctionSymbol *>(sym);
    ++miter;
    if (fsym == (FunctionSymbol *)0) continue;
    Funcdata *fd = fsym->getFunction();
    if (fd == (Funcdata *)0) continue;
    if (!seen.insert(fd).second) continue;
    FunctionEntry entry;
    entry.fd = fd;
    entry.name = fd->getName();
    entry.offset = fd->getAddress().getOffset();
    entries.push_back(entry);
  }
  ScopeMap::const_iterator iter = scope->childrenBegin();
  ScopeMap::const_iterator enditer = scope->childrenEnd();
  for (; iter != enditer; ++iter)
    collectFunctionsRecursive((*iter).second, seen, entries);
}

vector<FunctionEntry> collectFunctions(Architecture &arch)
{
  vector<FunctionEntry> entries;
  std::set<Funcdata *> seen;
  collectFunctionsRecursive(arch.symboltab->getGlobalScope(), seen, entries);
  std::sort(entries.begin(), entries.end(),
            [](const FunctionEntry &left, const FunctionEntry &right) {
              if (left.offset != right.offset) return left.offset < right.offset;
              return left.name < right.name;
            });
  return entries;
}

// Same per-function drive as tests/oracle/getstr_pipeline_1204.cc: full flow
// range, universal action to completion (resuming past any breakpoint), then
// PrintC docFunction.
string decompileFunction(Architecture &arch, Funcdata *fd, uintb &sizeOut)
{
  AddrSpace *codeSpace = arch.getDefaultCodeSpace();
  fd->followFlow(Address(codeSpace, 0), Address(codeSpace, codeSpace->getHighest()));
  Action *root = arch.allacts.getCurrent();
  if (root == (Action *)0)
    throw runtime_error("no current decompile action");
  root->reset(*fd);
  int4 result;
  do {
    result = root->perform(*fd);
  } while (result < 0);
  ostringstream cOutput;
  arch.print->setOutputStream(&cOutput);
  arch.print->docFunction(fd);
  sizeOut = fd->getSize();
  return cOutput.str();
}

void writeFunctionRecord(const string &path,long index,const FunctionEntry &entry,
                         const string &status,const string &text,uintb size)
{
  ostringstream out;
  out << "{\"schema\":1,\"index\":" << index << ",\"name\":";
  writeString(out, entry.name);
  out << ",\"offset\":" << entry.offset << ",\"size\":" << size << ",\"status\":";
  writeString(out, status);
  out << ",\"text\":";
  writeString(out, text);
  out << "}\n";
  std::ofstream file(path.c_str(), std::ios::binary);
  if (!file) throw runtime_error("unable to create record: " + path);
  file << out.str();
}

void decompileAtIndex(Architecture &arch, vector<FunctionEntry> &entries,
                      long index, const string &outPath)
{
  const FunctionEntry &entry = entries[static_cast<size_t>(index)];
  if (entry.fd->hasNoCode()) {
    writeFunctionRecord(outPath, index, entry, "no_code", "", 0);
    return;
  }
  try {
    uintb size = 0;
    string text = decompileFunction(arch, entry.fd, size);
    writeFunctionRecord(outPath, index, entry, "OK", text, size);
  }
  catch (const ghidra::LowlevelError &error) {
    writeFunctionRecord(outPath, index, entry,
                        string("error: ") + error.explain, "", 0);
  }
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 5 && !(argc == 6 && std::string(argv[1]) == "one")) {
    std::cerr << "usage: golden_dump_1204 list|all SPEC_ROOT BINARY OUT\n"
              << "       golden_dump_1204 one SPEC_ROOT BINARY INDEX OUT_JSON\n";
    return 2;
  }
  const string mode = argv[1];
  const string specRoot = argv[2];
  const string binary = argv[3];
  const string outPath = (mode == "one") ? argv[5] : argv[4];
  try {
    vector<string> specPaths;
    specPaths.push_back(specRoot);
    startDecompilerLibrary(specPaths);
    BfdArchitecture architecture(binary, "default", &std::cerr);
    DocumentStorage store;
    architecture.init(store);
    registerBfdFunctionSymbols(architecture, binary, false);
    registerBfdFunctionSymbols(architecture, binary, true);
    registerPltStubs(architecture, binary);
    vector<FunctionEntry> entries = collectFunctions(architecture);

    if (mode == "list") {
      ostringstream out;
      out << "{\"schema\":1,\"count\":" << entries.size() << ",\"functions\":[";
      for (size_t index = 0; index < entries.size(); ++index) {
        if (index != 0) out << ',';
        out << "{\"index\":" << index << ",\"name\":";
        writeString(out, entries[index].name);
        out << ",\"offset\":" << entries[index].offset << '}';
      }
      out << "]}\n";
      std::ofstream file(outPath.c_str(), std::ios::binary);
      if (!file) throw runtime_error("unable to create list output");
      file << out.str();
    }
    else if (mode == "one") {
      decompileAtIndex(architecture, entries, std::atol(argv[4]), outPath);
    }
    else if (mode == "all") {
      // outPath is a directory; every function gets <index>.json
      for (size_t index = 0; index < entries.size(); ++index) {
        ostringstream name;
        name << outPath << '/' << index << ".json";
        decompileAtIndex(architecture, entries, static_cast<long>(index), name.str());
        std::cerr << "[golden_dump_1204] " << (index + 1) << '/' << entries.size()
                  << ' ' << entries[index].name << '\n';
      }
    }
    else {
      throw runtime_error("unknown mode: " + mode);
    }
    shutdownDecompilerLibrary();
    return 0;
  }
  catch (const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch (const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
'''

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def log(message):
    print(message, flush=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_output(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def load_compare_ghidra():
    path = REPO_ROOT / "tools" / "compare_ghidra.py"
    spec = importlib.util.spec_from_file_location("compare_ghidra", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight():
    """Verify the locked oracle and the locked spec assets. Returns env info."""
    ghidra_repo = REPO_ROOT / "ghidra"
    if not (ghidra_repo / ".git").exists():
        raise RuntimeError(f"missing Ghidra repository: {ghidra_repo}")
    head = git_output(ghidra_repo, "rev-parse", "HEAD")
    if head != ORACLE_COMMIT:
        raise RuntimeError(f"Ghidra HEAD={head}; expected {ORACLE_COMMIT}")
    cpp_tree = git_output(ghidra_repo, "rev-parse",
                          f"{ORACLE_COMMIT}:Ghidra/Features/Decompiler/src/decompile/cpp")
    x86_tree = git_output(ghidra_repo, "rev-parse",
                          f"{ORACLE_COMMIT}:Ghidra/Processors/x86/data/languages")
    if cpp_tree != EXPECTED_CPP_TREE:
        raise RuntimeError(f"cpp tree={cpp_tree}; expected {EXPECTED_CPP_TREE}")
    if x86_tree != EXPECTED_X86_LANGUAGE_TREE:
        raise RuntimeError(f"x86 language tree={x86_tree}; expected {EXPECTED_X86_LANGUAGE_TREE}")
    dirty = subprocess.run(
        ["git", "-C", str(ghidra_repo), "diff", "--quiet", "--",
         "Ghidra/Features/Decompiler/src/decompile/cpp",
         "Ghidra/Processors/x86/data/languages"],
    ).returncode != 0
    if dirty:
        raise RuntimeError("locked Ghidra decompiler/x86 language source is dirty")
    spec_root = REPO_ROOT / "sleigh_specs"
    for name, expected in EXPECTED_ASSET_SHA256.items():
        path = spec_root / name
        if not path.exists():
            raise RuntimeError(f"missing locked spec asset: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(f"asset {name} sha256={actual}; expected {expected}")
    return {
        "ghidra_repo": str(ghidra_repo),
        "cpp_tree": cpp_tree,
        "x86_language_tree": x86_tree,
        "spec_root": str(spec_root),
    }


HEADER_LINE_RE = re.compile(
    r"^/\* ---- 0x([0-9a-f]+): (\S+) \((\d+) bytes\) ---- \*/$")


def parse_golden_blocks(text):
    """Parse a golden file into ordered [(offset, name, size, block_text)]."""
    blocks = []
    current = None
    lines = []
    for line in text.splitlines():
        match = HEADER_LINE_RE.match(line)
        if match:
            if current is not None:
                blocks.append((current[0], current[1], current[2],
                               "\n".join(lines) + "\n"))
            current = (int(match.group(1), 16), match.group(2),
                       int(match.group(3)))
            lines = []
        elif current is not None:
            lines.append(line)
    if current is not None:
        blocks.append((current[0], current[1], current[2], "\n".join(lines) + "\n"))
    return blocks


def ledger_from_golden(blocks, failed_blocks):
    ledger = []
    for offset, name, size, block in blocks:
        ledger.append({
            "name": name,
            "offset": offset,
            "size": size,
            "status": "FAILED" if (offset, name) in failed_blocks else "OK",
            "line_count": block.count("\n"),
            "sha256": hashlib.sha256(
                (f"/* ---- 0x{offset:x}: {name} ({size} bytes) ---- */\n"
                 + block).encode()).hexdigest(),
        })
    return ledger


# ---------------------------------------------------------------------------
# canonical path 1: real headless distribution
# ---------------------------------------------------------------------------


def headless_environment(headless_exe):
    dist_root = Path(headless_exe).resolve().parent.parent
    props = dist_root / "Ghidra" / "application.properties"
    if not props.exists():
        props = dist_root / "application.properties"
    if not props.exists():
        raise RuntimeError(f"no application.properties under {dist_root}")
    version = None
    for line in props.read_text(errors="replace").splitlines():
        if line.startswith("application.version="):
            version = line.split("=", 1)[1].strip()
    if version != "12.0.4":
        raise RuntimeError(f"headless distribution version={version}; expected 12.0.4")
    build_env = {}
    build_env_path = dist_root.parent.parent / "build-environment.json"
    if build_env_path.exists():
        build_env = json.loads(build_env_path.read_text(encoding="utf-8"))
        if build_env.get("oracle_commit") != ORACLE_COMMIT:
            raise RuntimeError("headless build-environment.json oracle commit mismatch")
    java_home = os.environ.get("RUDRA_JDK21_HOME", "")
    if not java_home:
        candidate = dist_root.parent.parent / "jdk21"
        if (candidate / "bin" / "java").exists():
            java_home = str(candidate)
    return {
        "analyzeHeadless": str(headless_exe),
        "distribution_root": str(dist_root),
        "version": version,
        "build_environment": build_env,
        "java_home": java_home,
    }


def prepare_postscript(workdir):
    """Copy tools/ghidra_decompile_all.py into the work dir with a Jython
    coding declaration added (the tracked file contains a non-ASCII em dash
    in a comment, which Jython 2.7 rejects without an explicit encoding).
    The declaration is purely lexical — zero behavior change."""
    source = REPO_ROOT / "tools" / "ghidra_decompile_all.py"
    text = source.read_text(encoding="utf-8")
    if "coding: utf-8" not in text.splitlines()[0] and "coding: utf-8" not in (
            text.splitlines()[1] if len(text.splitlines()) > 1 else ""):
        lines = text.splitlines(keepends=True)
        if lines and lines[0].startswith("#!"):
            lines.insert(1, "# -*- coding: utf-8 -*-\n")
        else:
            lines.insert(0, "# -*- coding: utf-8 -*-\n")
        text = "".join(lines)
    target = Path(workdir) / "ghidra_decompile_all.py"
    target.write_text(text, encoding="utf-8")
    return target.parent


def run_headless_import(headless_info, binary, out_path, workdir, timeout):
    env = {k: v for k, v in os.environ.items() if k != "LD_PRELOAD"}
    if headless_info["java_home"]:
        env["JAVA_HOME"] = headless_info["java_home"]
        env["PATH"] = f"{headless_info['java_home']}/bin:" + env.get("PATH", "")
    project_dir = Path(workdir) / "ghidra-project"
    project_dir.mkdir(parents=True, exist_ok=True)
    script_path = prepare_postscript(workdir)
    cmd = [
        headless_info["analyzeHeadless"],
        str(project_dir), "golden_regen",
        "-import", str(binary),
        "-scriptPath", str(script_path),
        "-postScript", "ghidra_decompile_all.py", str(out_path),
        "-deleteProject",
    ]
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, env=env, cwd=str(workdir))
    elapsed = time.monotonic() - started
    done_line = None
    for line in proc.stdout.splitlines():
        if line.startswith("GHIDRA_DECOMP_DONE"):
            done_line = line
            break
    if proc.returncode != 0 or done_line is None:
        raise RuntimeError(
            f"analyzeHeadless failed rc={proc.returncode} after {elapsed:.0f}s; "
            f"stdout tail: {proc.stdout[-1500:]}; stderr tail: {proc.stderr[-1500:]}")
    return done_line, elapsed, proc


def regenerate_headless(target, args, env_info, headless_info):
    cfg = TARGETS[target]
    binary = cfg["binary"]
    binary_sha = sha256_file(binary)
    if cfg["expected_input_sha256"] and binary_sha != cfg["expected_input_sha256"]:
        raise RuntimeError(
            f"{target} input sha256={binary_sha}; expected {cfg['expected_input_sha256']}")

    workdir = Path(tempfile.mkdtemp(prefix=f"rugra-golden-headless-{target}-"))
    try:
        out_path = workdir / "headless-out.c"
        done_line, elapsed, _ = run_headless_import(
            headless_info, binary, out_path, workdir, cfg["headless_timeout"])
        text = out_path.read_text(encoding="utf-8")
        log(f"[{target}] headless run: {done_line} ({elapsed:.0f}s)")

        failed = set()
        for match in re.finditer(
                r"^/\* ---- 0x([0-9a-f]+): (\S+) FAILED ---- \*/$",
                text, re.MULTILINE):
            failed.add((int(match.group(1), 16), match.group(2)))
        blocks = parse_golden_blocks(
            "\n".join(line for line in text.splitlines()
                      if not re.match(r"^/\* ---- 0x[0-9a-f]+: \S+ FAILED ---- \*/$", line)))
        cfg["golden"].write_text(text, encoding="utf-8")
        ledger = ledger_from_golden(blocks, failed)
        log(f"[{target}] golden: {len(blocks)} functions "
            f"({len(failed)} FAILED) -> {cfg['golden'].relative_to(REPO_ROOT)}")

        determinism = None
        if cfg["determinism_rerun"]:
            out2 = workdir / "headless-out-2.c"
            done2, elapsed2, _ = run_headless_import(
                headless_info, binary, out2, workdir, cfg["headless_timeout"])
            second = out2.read_text(encoding="utf-8")
            determinism = {
                "method": "full independent headless re-import",
                "first_run_seconds": round(elapsed, 1),
                "repeat_run_seconds": round(elapsed2, 1),
                "byte_identical": second == text,
                "repeat_summary": done2,
            }
            log(f"[{target}] determinism rerun: byte_identical="
                f"{determinism['byte_identical']}")

        direct_cross = None
        if cfg["direct_runner_cross_check"] and not args.skip_direct_runner:
            direct_cross = run_direct_runner_cross_check(
                target, args, env_info, blocks)

        legacy_diff = diff_against_legacy(target, blocks)

        provenance = {
            "schema": 1,
            "fixture_id": "ghidra_1204_headless_golden",
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "generator": "tools/regen_ghidra_golden.py",
            "path": {
                "selected": "path1_headless_distribution",
                "built_by": "tools/build_ghidra_1204_headless.sh",
                "analyzeHeadless": headless_info["analyzeHeadless"],
                "distribution_root": headless_info["distribution_root"],
                "build_environment": headless_info["build_environment"],
            },
            "oracle": {
                "product": "ghidra",
                "version": "12.0.4",
                "tag": ORACLE_TAG,
                "commit": ORACLE_COMMIT,
            },
            "architecture": ARCHITECTURE,
            "compiler_spec": COMPILER_SPEC,
            "analysis_options": {
                "profile": "analyzeHeadless defaults (no -processor/-analysis "
                           "option overrides)",
                "postScript": "tools/ghidra_decompile_all.py (verbatim copy "
                              "with a Jython 'coding: utf-8' declaration "
                              "inserted; Jython 2.7 rejects the tracked "
                              "file's non-ASCII comment otherwise)",
                "per_function_decompile_timeout_seconds": 30,
                "project_deleted_after_run": True,
            },
            "input": {
                "path": str(binary.relative_to(REPO_ROOT)),
                "sha256": binary_sha,
                "function_discovery": "full headless analysis (loader, PLT, "
                                      "references, demangler, DWARF, ...)",
                "function_count": len(blocks),
                "lineage_note": (
                    "examples/curl was replaced on 2026-08-13 (DWARF added, "
                    "GetStr 74 bytes); sha256 differs from the 4ee4002b... "
                    "recorded in the 2026-08-12 DWARF-PROTO-0001 era and from "
                    "the older binary behind the 11.3.2 golden (68-byte GetStr)"
                ) if target == "curl" else None,
            },
            "assets": {
                "ghidra_cpp_tree": env_info["cpp_tree"],
                "ghidra_x86_language_tree": env_info["x86_language_tree"],
            },
            "golden": {
                "path": str(cfg["golden"].relative_to(REPO_ROOT)),
                "total_lines": text.count("\n"),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "address_note": "headless image base 0x100000 for PIE inputs",
            },
            "functions": ledger,
            "determinism": determinism,
            "direct_runner_cross_check": direct_cross,
            "legacy_diff": legacy_diff,
            "equivalence_notes": HEADLESS_EQUIVALENCE_NOTES,
        }
        cfg["provenance"].write_text(
            json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        log(f"[{target}] provenance -> {cfg['provenance'].relative_to(REPO_ROOT)}")
        return provenance
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# supplementary path 2: direct runner
# ---------------------------------------------------------------------------


def resolve_bfd():
    for include in BFD_INCLUDE_CANDIDATES:
        if include and Path(include, "bfd.h").exists():
            break
    else:
        raise RuntimeError("bfd.h not found; set RUDRA_BFD_INCLUDE")
    for library in BFD_LIBRARY_CANDIDATES:
        if library and Path(library).exists():
            break
    else:
        raise RuntimeError("libbfd not found; set RUDRA_BFD_LIBRARY")
    return include, library


def build_runner(workdir, env_info):
    """Extract the locked cpp tree with git archive and compile the fixture."""
    ghidra_repo = Path(env_info["ghidra_repo"])
    cpp_root = (Path(workdir) / "Ghidra" / "Features" / "Decompiler" / "src"
                / "decompile" / "cpp")
    if not (cpp_root / "libdecomp.hh").exists():
        archive = Path(workdir) / "locked-cpp.tar"
        subprocess.run(
            ["git", "-C", str(ghidra_repo), "archive", "--format=tar",
             f"--output={archive}", ORACLE_COMMIT,
             "Ghidra/Features/Decompiler/src/decompile/cpp"],
            check=True,
        )
        cpp_root.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["tar", "-xf", str(archive), "-C", str(workdir)], check=True)
    fixture = Path(workdir) / "golden_dump_1204.cc"
    fixture.write_text(FIXTURE_CPP, encoding="utf-8")

    jobs = min(16, max(2, (os.cpu_count() or 4) // 4))
    make = subprocess.run(
        ["make", "--silent", "-C", str(cpp_root), "-j", str(jobs),
         "EXTRA=", "libdecomp.a"],
        capture_output=True, text=True,
    )
    if make.returncode != 0:
        raise RuntimeError(
            f"libdecomp.a build failed rc={make.returncode}: {make.stderr[-3000:]}")
    include, library = resolve_bfd()
    binary = Path(workdir) / "golden_dump_1204"
    compile_proc = subprocess.run(
        ["g++", "-std=c++11", "-O2", f"-I{include}", f"-I{cpp_root}",
         str(fixture),
         str(cpp_root / "libdecomp.cc"),
         str(cpp_root / "sleigh_arch.cc"),
         str(cpp_root / "inject_sleigh.cc"),
         str(cpp_root / "bfd_arch.cc"),
         str(cpp_root / "loadimage_bfd.cc"),
         str(cpp_root / "libdecomp.a"), library, "-lz",
         "-o", str(binary)],
        capture_output=True, text=True,
    )
    if compile_proc.returncode != 0:
        raise RuntimeError(
            f"fixture compile failed: {compile_proc.stderr[-3000:]}")
    compiler = subprocess.run(["g++", "--version"], capture_output=True, text=True
                              ).stdout.splitlines()[0]
    return binary, {
        "fixture_sha256": sha256_file(fixture),
        "build_command": (
            "g++ -std=c++11 -O2 -I<bfd-include> -I<locked-cpp> golden_dump_1204.cc "
            "libdecomp.cc sleigh_arch.cc inject_sleigh.cc bfd_arch.cc "
            "loadimage_bfd.cc libdecomp.a <libbfd> -lz"
        ),
        "host_compiler": compiler,
        "bfd_include": include,
        "bfd_library": library,
        "bfd_header_sha256": sha256_file(Path(include) / "bfd.h"),
        "bfd_library_sha256": sha256_file(Path(library)),
    }


def run_mode(runner, mode, spec_root, binary, *extra, timeout=900):
    cmd = [str(runner), mode, str(spec_root), str(binary), *(str(x) for x in extra)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def list_functions(runner, spec_root, binary):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        out = Path(handle.name)
    try:
        proc = run_mode(runner, "list", spec_root, binary, out, timeout=600)
        if proc.returncode != 0:
            raise RuntimeError(
                f"list mode failed rc={proc.returncode}: {proc.stderr[-2000:]}")
        document = json.loads(out.read_text(encoding="utf-8"))
        if document.get("schema") != 1:
            raise RuntimeError("unexpected list schema")
        return document["functions"]
    finally:
        out.unlink(missing_ok=True)


def decompile_one(runner, spec_root, binary, index, timeout):
    started = time.monotonic()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        out = Path(handle.name)
    try:
        try:
            proc = run_mode(runner, "one", spec_root, binary, index, out,
                            timeout=timeout)
            if proc.returncode != 0:
                return {
                    "index": index, "status": "crash",
                    "stderr_tail": proc.stderr[-1500:],
                }, time.monotonic() - started
            record = json.loads(out.read_text(encoding="utf-8"))
            record.pop("index", None)
            return record, time.monotonic() - started
        except subprocess.TimeoutExpired:
            return {
                "index": index, "status": "timeout",
                "timeout_seconds": timeout,
            }, time.monotonic() - started
    finally:
        out.unlink(missing_ok=True)


def run_all_mode(runner, spec_root, binary, workdir):
    out_dir = Path(workdir) / "all-mode"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = run_mode(runner, "all", spec_root, binary, out_dir, timeout=7200)
    records = {}
    for path in out_dir.glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        records[record["index"]] = record
    return proc, records


def direct_runner_results(runner, spec_root, binary, function_list, timeout, workers):
    results = [None] * len(function_list)

    def work(item):
        index, descriptor = item
        record, wall = decompile_one(runner, spec_root, binary, index, timeout)
        record.setdefault("name", descriptor["name"])
        record.setdefault("offset", descriptor["offset"])
        record["wall_seconds"] = wall
        return index, record

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, record in pool.map(work, enumerate(function_list)):
            results[index] = record
    return results


def assemble_direct_golden(path, functions):
    blocks = []
    ledger = []
    for function in functions:
        header = (f"/* ---- 0x{function['offset']:x}: {function['name']} "
                  f"({function.get('size') or 0} bytes) ---- */")
        if function["status"] == "OK":
            text = function["text"]
            if not text.endswith("\n"):
                text += "\n"
            block = header + "\n" + text
            blocks.append(block)
            ledger.append({
                "name": function["name"],
                "offset": function["offset"],
                "size": function["size"],
                "status": "OK",
                "line_count": block.count("\n"),
                "sha256": hashlib.sha256(block.encode()).hexdigest(),
            })
        else:
            ledger.append({
                "name": function["name"],
                "offset": function["offset"],
                "size": function.get("size") or 0,
                "status": function["status"],
            })
    path.write_text("".join(blocks), encoding="utf-8")
    return ledger


def determinism_check(runner, spec_root, binary, functions, timeout, workers, sample=12):
    if len(functions) <= sample:
        indices = list(range(len(functions)))
    else:
        step = len(functions) / sample
        indices = sorted({int(i * step) for i in range(sample)})
    unstable = []

    def rerun(index):
        record, _ = decompile_one(runner, spec_root, binary, index, timeout)
        return index, record

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, record in pool.map(rerun, indices):
            original = functions[index]
            if record.get("status") != "OK" or original["status"] != "OK":
                if record.get("status") != original["status"]:
                    unstable.append({
                        "index": index, "name": original.get("name"),
                        "first_status": original["status"],
                        "repeat_status": record.get("status"),
                    })
                continue
            if record["text"] != original["text"]:
                unstable.append({
                    "index": index, "name": original["name"],
                    "first_sha256": hashlib.sha256(original["text"].encode()).hexdigest(),
                    "repeat_sha256": hashlib.sha256(record["text"].encode()).hexdigest(),
                })
    return {
        "sample_indices": indices,
        "sample_size": len(indices),
        "byte_identical_repeats": len(indices) - len(unstable),
        "unstable": unstable,
    }


def run_direct_runner_cross_check(target, args, env_info, headless_blocks=None):
    """Run the direct runner for a target; write the supplementary golden and
    compare against the canonical headless blocks when provided."""
    cfg = TARGETS[target]
    binary = cfg["binary"]
    workdir = Path(tempfile.mkdtemp(prefix=f"rugra-golden-direct-{target}-"))
    try:
        runner, build_info = build_runner(workdir, env_info)
        spec_root = Path(env_info["spec_root"])
        function_list = list_functions(runner, spec_root, binary)
        started = time.monotonic()
        results = direct_runner_results(runner, spec_root, binary,
                                        function_list, args.timeout, args.workers)
        log(f"[{target}] direct-runner: {len(results)} functions in "
            f"{time.monotonic() - started:.1f}s")
        ledger = assemble_direct_golden(cfg["direct_runner"], results)
        ok_count = sum(1 for entry in ledger if entry["status"] == "OK")
        log(f"[{target}] direct-runner golden: {ok_count} OK -> "
            f"{cfg['direct_runner'].relative_to(REPO_ROOT)}")
        determinism = determinism_check(runner, spec_root, binary, results,
                                        args.timeout, args.workers)

        headless_comparison = None
        if headless_blocks is not None:
            compare = load_compare_ghidra()
            headless_by_key = {}
            for offset, name, size, block in headless_blocks:
                headless_by_key[(offset - 0x100000, compare.strip_gcc_suffix(name))] = block
            matched = identical = 0
            mismatches = []
            for entry, function in zip(ledger, results):
                if entry["status"] != "OK":
                    continue
                key = (entry["offset"], compare.strip_gcc_suffix(entry["name"]))
                headless_block = headless_by_key.get(key)
                if headless_block is None:
                    continue
                matched += 1
                text = function["text"]
                if not text.endswith("\n"):
                    text += "\n"
                if text.strip() == headless_block.strip():
                    identical += 1
                elif len(mismatches) < 10:
                    mismatches.append({
                        "offset": entry["offset"], "name": entry["name"],
                        "direct_sha256": entry["sha256"],
                    })
            headless_comparison = {
                "matched_by_offset_and_name": matched,
                "identical_text": identical,
                "changed_text": matched - identical,
                "first_mismatches": mismatches,
                "note": "direct-runner vs canonical headless equivalence gap; "
                        "differences expected from analyzer-provided "
                        "signatures/references (see direct-runner risks)",
            }
            log(f"[{target}] direct-vs-headless: {identical}/{matched} identical, "
                f"{matched - identical} changed")

        return {
            "golden_path": str(cfg["direct_runner"].relative_to(REPO_ROOT)),
            "golden_sha256": sha256_file(cfg["direct_runner"]),
            "runner": {
                "mode": "one (per-function hermetic process)",
                "fixture_sha256": build_info["fixture_sha256"],
                "build_command": build_info["build_command"],
                "host_compiler": build_info["host_compiler"],
                "per_function_timeout_seconds": args.timeout,
                "parallel_workers": args.workers,
                "bfd_header_sha256": build_info["bfd_header_sha256"],
                "bfd_library_sha256": build_info["bfd_library_sha256"],
            },
            "function_count": len(function_list),
            "ok_count": ok_count,
            "functions": ledger,
            "determinism": determinism,
            "headless_comparison": headless_comparison,
            "equivalence_risks": DIRECT_RUNNER_EQUIVALENCE_RISKS,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# legacy (11.3.2) diff statistics
# ---------------------------------------------------------------------------


def diff_against_legacy(target, blocks):
    cfg = TARGETS[target]
    if cfg["legacy_golden"] is None or not cfg["legacy_golden"].exists():
        return None
    compare = load_compare_ghidra()
    legacy_text = cfg["legacy_golden"].read_text(encoding="utf-8")
    legacy_funcs = compare.parse_functions(legacy_text)

    def norm_key(offset, name):
        return (offset, compare.strip_gcc_suffix(name))

    legacy_by_key = {}
    for addr, name, size, body in legacy_funcs:
        offset = addr - 0x100000 if addr >= 0x100000 else addr
        legacy_by_key[norm_key(offset, name)] = (name, size, body)
    new_by_key = {}
    for offset, name, size, block in blocks:
        new_by_key[norm_key(offset if offset < 0x100000 else offset - 0x100000,
                            name)] = (name, size, block)

    matched = identical = 0
    changed_line_delta = 0
    changed = []
    for key, (new_name, _, new_body) in new_by_key.items():
        legacy = legacy_by_key.get(key)
        if legacy is None:
            continue
        matched += 1
        if new_body.strip() == legacy[2].strip():
            identical += 1
        else:
            diff_lines = list(difflib.unified_diff(
                legacy[2].splitlines(), new_body.splitlines(), lineterm=""))
            delta = sum(1 for line in diff_lines[2:]
                        if line.startswith(("+", "-")))
            changed_line_delta += delta
            if len(changed) < 20:
                changed.append({
                    "offset": key[0], "legacy_name": legacy[0],
                    "new_name": new_name, "diff_lines": delta,
                })
    only_new = sorted(new_by_key.keys() - legacy_by_key.keys())
    only_legacy = sorted(legacy_by_key.keys() - new_by_key.keys())
    real_text_start = min((key[0] for key in new_by_key), default=0)
    only_legacy_plt = [k for k in only_legacy if k[0] < real_text_start]
    return {
        "legacy_golden": str(cfg["legacy_golden"].relative_to(REPO_ROOT)),
        "legacy_ghidra_version": cfg["legacy_version"],
        "legacy_function_count": len(legacy_funcs),
        "new_function_count": len(new_by_key),
        "matched": matched,
        "identical_text": identical,
        "changed_text": matched - identical,
        "changed_line_delta_total": changed_line_delta,
        "changed_examples": changed,
        "only_in_1204": [
            {"offset": off, "name": new_by_key[(off, nm)][0]} for off, nm in only_new
        ],
        "only_in_legacy": [
            {"offset": off, "name": legacy_by_key[(off, nm)][0],
             "plt_stub_estimate": off < real_text_start}
            for off, nm in only_legacy
        ],
        "only_in_legacy_plt_stub_estimate": len(only_legacy_plt),
        "input_drift_note": (
            "the 11.3.2 golden was generated from an older, different curl "
            "binary (68-byte GetStr); part of the changed_text count is input "
            "drift, not Ghidra version drift"
        ) if target == "curl" else None,
        "note": "matched by (relative offset, gcc-suffix-stripped name); "
                "addresses rebased to the PIE-relative base",
    }


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def cmd_check(args):
    env_info = preflight()
    failures = []
    for target in resolve_targets(args):
        cfg = TARGETS[target]
        if not cfg["provenance"].exists():
            failures.append(f"{target}: missing provenance {cfg['provenance']}")
            continue
        if not cfg["golden"].exists():
            failures.append(f"{target}: missing golden {cfg['golden']}")
            continue
        provenance = json.loads(cfg["provenance"].read_text(encoding="utf-8"))
        if provenance.get("schema") != 1:
            failures.append(f"{target}: unexpected provenance schema")
            continue
        if provenance["oracle"] != {
            "product": "ghidra", "version": "12.0.4",
            "tag": ORACLE_TAG, "commit": ORACLE_COMMIT,
        }:
            failures.append(f"{target}: provenance oracle mismatch")
        if provenance["architecture"] != ARCHITECTURE:
            failures.append(f"{target}: provenance architecture mismatch")
        if provenance["compiler_spec"] != COMPILER_SPEC:
            failures.append(f"{target}: provenance compiler spec mismatch")
        if provenance["assets"]["ghidra_cpp_tree"] != env_info["cpp_tree"]:
            failures.append(f"{target}: cpp tree drift vs current oracle")
        if provenance["assets"]["ghidra_x86_language_tree"] != env_info["x86_language_tree"]:
            failures.append(f"{target}: x86 language tree drift vs current oracle")
        binary_sha = sha256_file(cfg["binary"])
        if provenance["input"]["sha256"] != binary_sha:
            failures.append(
                f"{target}: input sha256 drift ({binary_sha} != "
                f"{provenance['input']['sha256']})")

        golden_text = cfg["golden"].read_text(encoding="utf-8")
        golden_sha = hashlib.sha256(golden_text.encode()).hexdigest()
        if golden_sha != provenance["golden"]["sha256"]:
            failures.append(f"{target}: golden file hash drift")
        if golden_text.count("\n") != provenance["golden"]["total_lines"]:
            failures.append(f"{target}: golden line count drift")

        text_no_failed = "\n".join(
            line for line in golden_text.splitlines()
            if not re.match(r"^/\* ---- 0x[0-9a-f]+: \S+ FAILED ---- \*/$", line))
        blocks = parse_golden_blocks(text_no_failed)
        if len(blocks) != len(provenance["functions"]):
            failures.append(
                f"{target}: golden block count {len(blocks)} != ledger "
                f"{len(provenance['functions'])}")
        for entry, block in zip(provenance["functions"], blocks):
            if (entry["offset"], entry["name"]) != (block[0], block[1]):
                failures.append(
                    f"{target}: ledger/golden order drift at 0x{block[0]:x}")
                break
            if entry["line_count"] != block[3].count("\n"):
                failures.append(
                    f"{target}: block line count drift: 0x{entry['offset']:x} "
                    f"{entry['name']}")
            block_text = (f"/* ---- 0x{entry['offset']:x}: {entry['name']} "
                          f"({entry['size']} bytes) ---- */\n{block[3]}")
            if hashlib.sha256(block_text.encode()).hexdigest() != entry["sha256"]:
                failures.append(
                    f"{target}: block hash drift: 0x{entry['offset']:x} "
                    f"{entry['name']}")
        ok_count = sum(1 for entry in provenance["functions"]
                       if entry["status"] == "OK")
        log(f"[{target}] check: {len(provenance['functions'])} ledger entries "
            f"({ok_count} OK), golden {provenance['golden']['total_lines']} lines")
    if failures:
        for failure in failures:
            print(f"[check] FAIL {failure}", file=sys.stderr)
        return 1
    log("[check] all targets verified against provenance")
    return 0


def resolve_targets(args):
    if args.targets:
        return [t for t in ("curl", "httpd") if t in args.targets.split(",")]
    return ["curl", "httpd"]


def cmd_regen(args):
    env_info = preflight()
    headless_exe = Path(args.headless) if args.headless else DEFAULT_HEADLESS
    if not headless_exe.exists():
        raise RuntimeError(
            f"analyzeHeadless not found at {headless_exe}; build one with "
            f"tools/build_ghidra_1204_headless.sh or pass --headless")
    headless_info = headless_environment(headless_exe)
    for target in resolve_targets(args):
        regenerate_headless(target, args, env_info, headless_info)
    return cmd_check(args)


def cmd_direct_runner(args):
    env_info = preflight()
    for target in resolve_targets(args):
        run_direct_runner_cross_check(target, args, env_info)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--regen", action="store_true",
                        help="regenerate canonical goldens via headless")
    parser.add_argument("--direct-runner", action="store_true",
                        help="(re)generate supplementary direct-runner goldens")
    parser.add_argument("--check", action="store_true",
                        help="verify existing goldens against provenance")
    parser.add_argument("--headless", default=None,
                        help="path to analyzeHeadless of the locked 12.0.4 "
                             "distribution (default: the location produced by "
                             "tools/build_ghidra_1204_headless.sh)")
    parser.add_argument("--targets", default=None,
                        help="comma-separated subset: curl,httpd")
    parser.add_argument("--timeout", type=int, default=600,
                        help="direct-runner per-function timeout seconds")
    parser.add_argument("--workers", type=int,
                        default=min(16, max(2, (os.cpu_count() or 4) // 4)),
                        help="direct-runner parallel worker processes")
    parser.add_argument("--skip-direct-runner", action="store_true",
                        help="skip the supplementary direct-runner cross-check")
    args = parser.parse_args()
    if not args.regen and not args.check and not args.direct_runner:
        parser.error("choose --regen, --direct-runner or --check")
    if args.direct_runner:
        sys.exit(cmd_direct_runner(args))
    if args.regen:
        sys.exit(cmd_regen(args))
    sys.exit(cmd_check(args))


if __name__ == "__main__":
    main()
