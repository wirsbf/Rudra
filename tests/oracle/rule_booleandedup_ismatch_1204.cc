/*
 * RULE-BOOLEANDEDUP-ISMATCH-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleBooleanDedup::applyOp (ruleaction.cc:2832-2955) whose pairing
 * and flipped-form semantics live in RuleBooleanDedup::isMatch
 * (ruleaction.cc:2817-2831 -> BooleanMatch::evaluate, expression.cc:111-216)
 * — WORKPKG-UNMAP-RULEADJ-0013: Rugra previously matched the four input
 * pairings by raw varnode identity only (no complements) and computed the
 * "other input of op1" slot as 4-bi, which is never op1's other input for
 * bi in {2,3}.
 *
 * Atoms per case (fresh per case, construction order fixes unique offsets):
 *   x1/x2/x3/x4 = COPY(#0x11/#0x22/#0x33/#0x44) 8-byte outputs
 *   A/B/C/D     = INT_LESS(x1/x2/x3/x4, #5/#7/#9/#11) 1-byte bool outputs
 *   nA/nB       = BOOL_NEGATE(A) / BOOL_NEGATE(B)
 * The central op is BOOL_AND/BOOL_OR(op0, op1) with op0/op1 BOOL_AND or
 * BOOL_OR over the atoms; applyOp then either factors the shared atom,
 * folds a complementary form to a constant, or rejects.
 *
 * Cases: same-match dedup (AND/OR central), distribute (AND under OR),
 * complement folds (!A forms -> COPY(#0)/COPY(#1)), mixed flipped OR
 * (both operand orders — finalA picks the un-negated side), De Morgan
 * complementary pairing (evaluate's AND-vs-OR branch), the pair-(0,3) and
 * pair-(1,2) slots that witness the rightO/leftO index fix, an
 * uncorrelated reject, and a flipped AND-central reject.
 *
 * Observations (one block per case, ops in SeqNum order):
 *   case=<name>|bd_apply=<0/1>
 *     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
 *   endcase
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

RuleBooleanDedup dedupRule("analysis");

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

struct Atoms {
  Varnode *a;
  Varnode *b;
  Varnode *c;
  Varnode *d;
  Varnode *na;
  Varnode *nb;
};

// Builds the per-case atoms in a fixed construction order so unique-space
// offsets are deterministic: x1..x4 COPYs, A..D INT_LESS, nA/nB BOOL_NEGATE.
Atoms buildAtoms(Funcdata &fd, BlockBasic *block, AddrSpace *code, uint4 b)
{
  Atoms at;
  Varnode *xs[4];
  const uintb xvals[4] = {0x11, 0x22, 0x33, 0x44};
  const uintb cvals[4] = {5, 7, 9, 11};
  for (int4 k = 0; k < 4; ++k) {
    PcodeOp *w = fd.newOp(1, Address(code, b + 0x10 + 0x4 * k));
    fd.opSetOpcode(w, CPUI_COPY);
    xs[k] = fd.newUniqueOut(8, w);
    fd.opSetInput(w, fd.newConstant(8, xvals[k]), 0);
    fd.opInsertEnd(w, block);
  }
  Varnode *less[4];
  for (int4 k = 0; k < 4; ++k) {
    PcodeOp *l = fd.newOp(2, Address(code, b + 0x20 + 0x4 * k));
    fd.opSetOpcode(l, CPUI_INT_LESS);
    less[k] = fd.newUniqueOut(1, l);
    fd.opSetInput(l, xs[k], 0);
    fd.opSetInput(l, fd.newConstant(8, cvals[k]), 1);
    fd.opInsertEnd(l, block);
  }
  at.a = less[0];
  at.b = less[1];
  at.c = less[2];
  at.d = less[3];
  PcodeOp *n1 = fd.newOp(1, Address(code, b + 0x30));
  fd.opSetOpcode(n1, CPUI_BOOL_NEGATE);
  at.na = fd.newUniqueOut(1, n1);
  fd.opSetInput(n1, at.a, 0);
  fd.opInsertEnd(n1, block);
  PcodeOp *n2 = fd.newOp(1, Address(code, b + 0x34));
  fd.opSetOpcode(n2, CPUI_BOOL_NEGATE);
  at.nb = fd.newUniqueOut(1, n2);
  fd.opSetInput(n2, at.b, 0);
  fd.opInsertEnd(n2, block);
  return at;
}

PcodeOp *boolPair(Funcdata &fd, BlockBasic *block, AddrSpace *code, uint4 addr,
                  OpCode opc, Varnode *l, Varnode *r)
{
  PcodeOp *op = fd.newOp(2, Address(code, addr));
  fd.opSetOpcode(op, opc);
  fd.newUniqueOut(1, op);
  fd.opSetInput(op, l, 0);
  fd.opSetInput(op, r, 1);
  fd.opInsertEnd(op, block);
  return op;
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 4) {
    std::cerr << "usage: rule_booleandedup_ismatch_1204 SPEC_ROOT CURL_BINARY MODE(normal)\n";
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

      for (uint4 ci = 0; ci < 12; ++ci) {
        const uint4 b = 0x710000 + 0x100 * ci;
        Atoms at = buildAtoms(*fd, block, code, b);
        PcodeOp *op0;
        PcodeOp *op1;
        OpCode central;
        switch (ci) {
        case 0: // (A&&B) && (A&&C)  ->  A && (B&&C)
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_AND, at.a, at.c);
          central = CPUI_BOOL_AND;
          break;
        case 1: // (A||B) || (A||C)  ->  A || (B||C)
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_OR, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_OR, at.a, at.c);
          central = CPUI_BOOL_OR;
          break;
        case 2: // (A&&B) || (A&&C)  ->  A && (B||C)
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_AND, at.a, at.c);
          central = CPUI_BOOL_OR;
          break;
        case 3: // (A&&B) && (!A&&C)  ->  COPY(#0)
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_AND, at.na, at.c);
          central = CPUI_BOOL_AND;
          break;
        case 4: // (A||B) || (!A||C)  ->  COPY(#1)
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_OR, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_OR, at.na, at.c);
          central = CPUI_BOOL_OR;
          break;
        case 5: // (A||B) || (!A&&C)  ->  A || (B||C)
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_OR, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_AND, at.na, at.c);
          central = CPUI_BOOL_OR;
          break;
        case 6: // (!A&&C) || (A||B)  ->  A || (C||B)   (finalA = rightA)
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.na, at.c);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_OR, at.a, at.b);
          central = CPUI_BOOL_OR;
          break;
        case 7: // (A&&B) || (!A||!B)  ->  De Morgan complementary pairing
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_OR, at.na, at.nb);
          central = CPUI_BOOL_OR;
          break;
        case 8: // (A&&B) && (C&&A): match at pair (0,3) — rightO index fix
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_AND, at.c, at.a);
          central = CPUI_BOOL_AND;
          break;
        case 9: // (A&&B) && (C&&B): match at pair (1,2) — leftO index fix
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_AND, at.c, at.b);
          central = CPUI_BOOL_AND;
          break;
        case 10: // (A&&B) && (C&&D): uncorrelated reject
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_AND, at.c, at.d);
          central = CPUI_BOOL_AND;
          break;
        default: // (A&&B) && (!A||C): flipped AND-central reject
          op0 = boolPair(*fd, block, code, b + 0x40, CPUI_BOOL_AND, at.a, at.b);
          op1 = boolPair(*fd, block, code, b + 0x44, CPUI_BOOL_OR, at.na, at.c);
          central = CPUI_BOOL_AND;
          break;
        }
        PcodeOp *centralOp = boolPair(*fd, block, code, b + 0x48, central,
                                      op0->getOut(), op1->getOut());
        int4 apply = dedupRule.applyOp(centralOp, *fd);
        static const char *names[12] = {
            "dedup_and", "dedup_or", "cross_and_or", "flip_and0",
            "flip_or1", "flip_or_mixed", "flip_or_mixed_swap", "demorgan",
            "pair_03", "pair_12", "uncorr", "flip_and_mixed_rej",
        };
        std::cout << "case=" << names[ci] << "|bd_apply=" << apply << '\n';
        dumpCaseWindow(*fd, Address(code, b), Address(code, b + 0x100));
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
