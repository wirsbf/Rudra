/*
 * RULE-SUBCOMMUTE-CANCELEXT-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleSubCommute::applyOp (ruleaction.cc:4514-4653) into
 * RuleSubCommute::cancelExtensions (ruleaction.cc:4483-4512) via the
 * INT_DIV/INT_REM (ZEXT, cc:4542-4568) and INT_SDIV/INT_SREM (SEXT,
 * cc:4570-4602) arms: SUBPIECE(longform,0) where an extension input is
 * bigger than the SUBPIECE output — the PARTIAL commute where SUBPIECE
 * cancels the extensions but survives on the truncated longform output.
 * (WORKPKG-UNMAP-RULEADJ-0013; the DIV/REM wiring closes
 * RULEACTION-SUBCOMMUTE-ZEXT-PARTIAL-0001.)
 *
 * Per case atoms (a4/a8/b4/b8 = COPY outputs of the given width, kept
 * written unless the case frees one):
 *   ext0 = INT_ZEXT|SEXT(aN, 16), ext1 = INT_ZEXT|SEXT(bN, 16)
 *   longform = INT_DIV|REM|SDIV|SREM(ext0Out, ext1Out) 16-byte output
 *   op = SUBPIECE(longformOut, #0) 4-byte output
 *
 * Cases: equal-size cancel (both ext inputs 8 > 4), unequal both orders
 * (shortenExtension on the 4-byte side, cc:4494-4505), SEXT-arm mirrors,
 * the three in-helper rejects (longform output second reader cc:4488,
 * equal-arm free input cc:4489-4493, shorten-side loneDescend cc:4499),
 * plus the full-commute fall-through (both ext inputs <= 4) as contrast.
 *
 * Observations (one block per case, ops in SeqNum order, then keep lines
 * for the captured extension-input varnodes):
 *   case=<name>|ce_apply=<0/1>
 *     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
 *     keep=<tag>|<cls>|<size>|readers=<n>|descends=<n>
 *   endcase
 * readers counts ops in the case window reading the captured varnode at any
 * slot; descends is the live descendant count.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

RuleSubCommute subCommuteRule("analysis");

char vnClass(const Varnode *vn)
{
  if (vn == (const Varnode *)0)
    return '_';
  if (vn->isConstant())
    return 'c';
  if (vn->isWritten())
    return 'w';
  return 'o';
}

void printOpLine(PcodeOp *op)
{
  ostringstream out;
  out << "  op=" << static_cast<int4>(op->code())
      << "@0x" << std::hex << op->getAddr().getOffset() << std::dec
      << "|nin=" << op->numInput();
  for (int4 i = 0; i < 2; ++i) {
    const Varnode *vn = op->numInput() > i ? op->getIn(i) : (const Varnode *)0;
    if (vn != (const Varnode *)0)
      out << "|in" << i << '=' << vnClass(vn)
          << '|' << vn->getSize()
          << "|0x" << std::hex << vn->getOffset() << std::dec;
    else
      out << "|in" << i << "=_|0|0x0";
  }
  out << "|out=" << (op->getOut() != (Varnode *)0 ? op->getOut()->getSize() : -1)
      << '\n';
  std::cout << out.str();
}

void dumpCaseWindow(Funcdata &fd, const Address &lo, const Address &hi)
{
  for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
    PcodeOp *op = iter->second;
    const Address &a = op->getAddr();
    if (a < lo || hi < a)
      continue;
    printOpLine(op);
  }
}

void dumpKeepLines(Funcdata &fd, const vector<Varnode *> &keeps,
                   const vector<string> &tags, const Address &lo,
                   const Address &hi)
{
  for (uint4 k = 0; k < keeps.size(); ++k) {
    Varnode *vn = keeps[k];
    int4 readers = 0;
    for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      PcodeOp *op = iter->second;
      const Address &a = op->getAddr();
      if (a < lo || hi < a)
        continue;
      for (int4 s = 0; s < op->numInput(); ++s)
        if (op->getIn(s) == vn)
          ++readers;
    }
    int4 descends = 0;
    for (auto iter = vn->beginDescend(); iter != vn->endDescend(); ++iter)
      ++descends;
    std::cout << "  keep=" << tags[k] << '|' << vnClass(vn)
              << '|' << vn->getSize()
              << "|readers=" << readers << "|descends=" << descends << '\n';
  }
}

// extraKind: 0 none, 1 second SUBPIECE reading the longform output
// (cc:4488 reject), 2 free the ext0 input a8 (cc:4489-4493 equal-arm
// reject), 3 second reader on the SHORTENED side's extension output
// (cc:4499 loneDescend reject).
struct CaseBuilt {
  PcodeOp *subOp;
  vector<Varnode *> keeps;
  vector<string> tags;
};

CaseBuilt cancelExtCase(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                        uint4 base, int opc, int4 asz, int4 bsz,
                        int4 extSize, int4 outSize, int4 extraKind)
{
  CaseBuilt r;
  r.subOp = (PcodeOp *)0;
  OpCode extOpc = (opc == 0 || opc == 1) ? CPUI_INT_ZEXT : CPUI_INT_SEXT;
  OpCode longOpc = (opc == 0) ? CPUI_INT_DIV
                  : (opc == 1) ? CPUI_INT_REM
                  : (opc == 2) ? CPUI_INT_SDIV
                               : CPUI_INT_SREM;
  Varnode *ins[2];
  PcodeOp *writers[2];
  const uintb vals[2] = {0x33, 0x55};
  int4 sizes[2] = {asz, bsz};
  for (int4 slot = 0; slot < 2; ++slot) {
    PcodeOp *writer = fd.newOp(1, Address(code, base + 0x10 + 0x8 * slot));
    fd.opSetOpcode(writer, CPUI_COPY);
    Varnode *fv = fd.newUniqueOut(sizes[slot], writer);
    fd.opSetInput(writer, fd.newConstant(sizes[slot], vals[slot]), 0);
    fd.opInsertEnd(writer, block);
    writers[slot] = writer;
    ins[slot] = fv;
  }
  PcodeOp *exts[2];
  for (int4 slot = 0; slot < 2; ++slot) {
    PcodeOp *ext = fd.newOp(1, Address(code, base + 0x20 + 0x8 * slot));
    fd.opSetOpcode(ext, extOpc);
    fd.newUniqueOut(extSize, ext);
    fd.opSetInput(ext, ins[slot], 0);
    fd.opInsertEnd(ext, block);
    exts[slot] = ext;
  }
  PcodeOp *longform = fd.newOp(2, Address(code, base + 0x30));
  fd.opSetOpcode(longform, longOpc);
  fd.newUniqueOut(extSize, longform);
  fd.opSetInput(longform, exts[0]->getOut(), 0);
  fd.opSetInput(longform, exts[1]->getOut(), 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x40));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(outSize, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, fd.newConstant(4, 0), 1);
  fd.opInsertEnd(subOp, block);
  if (extraKind == 1) {
    // cc:4488: longform output has a second reader besides subOp.
    PcodeOp *sub2 = fd.newOp(2, Address(code, base + 0x50));
    fd.opSetOpcode(sub2, CPUI_SUBPIECE);
    fd.newUniqueOut(outSize, sub2);
    fd.opSetInput(sub2, longform->getOut(), 0);
    fd.opSetInput(sub2, fd.newConstant(4, 0), 1);
    fd.opInsertEnd(sub2, block);
  }
  else if (extraKind == 2) {
    // cc:4489-4493: free the ext0 input (COPY writer unset, descend kept).
    fd.opUnsetOutput(writers[0]);
  }
  else if (extraKind == 3) {
    // cc:4499: the SHORTENED side's extension output has a second reader
    // (only meaningful when asz < bsz; reads ext0's output).
    PcodeOp *sub2 = fd.newOp(2, Address(code, base + 0x50));
    fd.opSetOpcode(sub2, CPUI_SUBPIECE);
    fd.newUniqueOut(4, sub2);
    fd.opSetInput(sub2, exts[0]->getOut(), 0);
    fd.opSetInput(sub2, fd.newConstant(4, 0), 1);
    fd.opInsertEnd(sub2, block);
  }
  r.keeps.push_back(ins[0]);
  r.keeps.push_back(ins[1]);
  r.tags.push_back("a");
  r.tags.push_back("b");
  r.subOp = subOp;
  return r;
}

struct CaseSpec {
  const char *name;
  uint4 base;
  int opc; // 0 DIV, 1 REM, 2 SDIV, 3 SREM
  int4 asz;
  int4 bsz;
  int4 extSize; // extension output width (16)
  int4 outSize; // SUBPIECE output width (4)
  int4 extraKind;
};

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 4) {
    std::cerr << "usage: rule_subcommute_cancelext_1204 SPEC_ROOT CURL_BINARY MODE(normal)\n";
    return 2;
  }
  try {
    vector<string> specPaths;
    specPaths.push_back(argv[1]);
    startDecompilerLibrary(specPaths);
    {
      std::ostringstream diagnostics;
      BfdArchitecture architecture(argv[2], "default", &diagnostics);
      DocumentStorage store;
      architecture.init(store);
      architecture.readLoaderSymbols("::");
      Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
      if (fd == (Funcdata *)0)
        throw std::runtime_error("GetStr was not found in the BFD symbol table");
      if (fd->getName() != "GetStr" ||
          fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
        throw std::runtime_error("GetStr input identity drifted");
      if (architecture.archid != "x86:LE:64:default:gcc")
        throw std::runtime_error("runtime architecture/compiler drifted: " +
                                 architecture.archid);

      string mode = argv[3];
      if (mode != "normal")
        throw std::runtime_error("unknown mode: " + mode);
      AddrSpace *code = fd->getArch()->getDefaultCodeSpace();
      BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
      BlockBasic *block = graph.newBlockBasic(fd);

      const vector<CaseSpec> cases = {
        // ZEXT equal arm: both ext inputs 8 > 4 — DIV rebound to a8/b8.
        {"div_partial_eq", 0x810000, 0, 8, 8, 16, 4, 0},
        // ZEXT unequal, smaller side 0: shortenExtension(ZEXT(a4), 8).
        {"div_partial_shorten0", 0x810100, 0, 4, 8, 16, 4, 0},
        // ZEXT unequal, smaller side 1.
        {"rem_partial_shorten1", 0x810200, 1, 8, 4, 16, 4, 0},
        // SEXT arm mirrors (cc:4570-4602).
        {"sdiv_partial_eq", 0x810300, 2, 8, 8, 16, 4, 0},
        {"srem_partial_shorten0", 0x810400, 3, 4, 8, 16, 4, 0},
        // cc:4488 reject: second SUBPIECE on the longform output.
        {"div_partial_two_readers", 0x811000, 0, 8, 8, 16, 4, 1},
        // cc:4489-4493 reject: freed extension input (equal arm).
        {"div_partial_free_in", 0x811100, 0, 8, 8, 16, 4, 2},
        // cc:4499 reject: shortened side's extension output has another
        // reader (loneDescend != longform).
        {"div_partial_shorten_reader", 0x811200, 0, 4, 8, 16, 4, 3},
        // Full commute contrast: both ext inputs 4 <= 4 — generic tail,
        // SUBPIECE destroyed, DIV takes the 4-byte output.
        {"div_fallthrough_full", 0x812000, 0, 4, 4, 8, 4, 0},
      };
      static const char *opcNames[4] = {"div", "rem", "sdiv", "srem"};
      (void)opcNames;

      for (uint4 ci = 0; ci < cases.size(); ++ci) {
        const CaseSpec &spec = cases[ci];
        CaseBuilt built = cancelExtCase(*fd, block, code, spec.base, spec.opc,
                                        spec.asz, spec.bsz, spec.extSize,
                                        spec.outSize, spec.extraKind);
        int4 apply = subCommuteRule.applyOp(built.subOp, *fd);
        std::cout << "case=" << spec.name << "|ce_apply=" << apply << '\n';
        dumpCaseWindow(*fd, Address(code, spec.base),
                       Address(code, spec.base + 0x80));
        dumpKeepLines(*fd, built.keeps, built.tags, Address(code, spec.base),
                      Address(code, spec.base + 0x80));
        std::cout << "endcase\n";
        std::cout.flush();
      }
    }
    shutdownDecompilerLibrary();
    return 0;
  }
  catch(const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
