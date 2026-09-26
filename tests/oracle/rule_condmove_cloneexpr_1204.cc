/*
 * RULEACTION-CLONEBLOCKOPS-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleConditionalMove::applyOp (ruleaction.cc:9390-9558) through
 * RuleConditionalMove::constructBool (ruleaction.cc:9328-9341) into the
 * compareOp sort (ruleaction.hh:1433, cc:9333) and
 * CloneBlockOps::cloneExpression (funcdata_block.cc:1024-1040): the
 * non-const BOOL_AND/BOOL_AND rewriting paths where the boolean is formed
 * INSIDE the conditional branch and must be cloned out.
 *
 * Case CFG shapes (root ends in CBRANCH unless noted):
 *   clone_or_root_in0:  root(=inblock0) --out0--> b1 --out1--> bb;
 *                       b1 --> bb. bool0=INT_AND in root, bool1=INT_OR in
 *                       b1 → BOOL_OR(bool0, clone(bool1)), cc:9448-9467.
 *   clone_and_negate:   same CFG; CBRANCH cond = BOOL_NEGATE(bool0) in root
 *                       → andorselect flips → BOOL_AND(bool0, clone(bool1)).
 *   clone_via_root_in1: bb.in0=b0 (bool0=INT_AND there), bb.in1=root;
 *                       root --out0--> b0 --out1--> bb; b0 --> bb;
 *                       bool1=INT_OR in root → BOOL_OR(bool1, clone(bool0)),
 *                       cc:9469-9489.
 *   no_clone_pre_branch:p0 --> root; bool0/bool1 both formed in p0 (before
 *                       the branch) → gather lists empty → plain
 *                       BOOL_OR(bool0, bool1), no clones.
 *   reject_no_cbranch:  root ends in INT_ADD (no CBRANCH) → apply=0.
 *
 * Observations (ops in SeqNum order within the case window):
 *   case=<name>|apply=<0/1>
 *     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
 *   endcase
 * Cloned ops reuse the original op address (buildOpClone →
 * data.newOp(op->numInput(), op->getAddr()), funcdata_block.cc:970) and the
 * cloned output reuses the original output storage
 * (buildVarnodeOutput → newVarnodeOut(size, origAddr, cloneOp),
 * funcdata_block.cc:988).
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

RuleConditionalMove condMoveRule("analysis");

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

/// Build a 1-byte boolean op (`opc`) at `addr` inside `blk` reading two
/// constants. `opc` must be a comparison (INT_LESS/INT_EQUAL/...): their
/// TypeOp constructors carry PcodeOp::booloutput (typeop.cc ctor opflags),
/// which opSetOpcode copies onto the op — the checkBoolean gate
/// (cc:9259-9276) requires it and PcodeOp::setFlag is private.
PcodeOp *buildBoolOp(Funcdata &fd, BlockBasic *blk, const Address &addr,
                     OpCode opc, uintb cv0, uintb cv1)
{
  PcodeOp *op = fd.newOp(2, addr);
  fd.opSetOpcode(op, opc);
  fd.newUniqueOut(1, op);
  fd.opSetInput(op, fd.newConstant(1, cv0), 0);
  fd.opSetInput(op, fd.newConstant(1, cv1), 1);
  fd.opInsertEnd(op, blk);
  return op;
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 4) {
    std::cerr << "usage: rule_condmove_cloneexpr_1204 SPEC_ROOT CURL_BINARY MODE(normal)\n";
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

      static const char *caseNames[5] = {
        "clone_or_root_in0", "clone_and_negate", "clone_via_root_in1",
        "no_clone_pre_branch", "reject_no_cbranch",
      };

      for (uint4 ci = 0; ci < 5; ++ci) {
        const uintb base = 0x830000 + 0x100 * ci;
        Address b(code, base);
        BlockBasic *root = graph.newBlockBasic(fd);
        BlockBasic *bb = graph.newBlockBasic(fd);
        PcodeOp *multiOp = (PcodeOp *)0;
        Varnode *bool0 = (Varnode *)0;
        Varnode *bool1 = (Varnode *)0;
        Varnode *condVn = (Varnode *)0;

        if (ci == 0 || ci == 1 || ci == 4) {
          // root(=inblock0) --out0--> b1 --out1--> bb; b1 --> bb.
          BlockBasic *b1 = graph.newBlockBasic(fd);
          graph.addEdge(root, b1);  // root out0 = b1
          graph.addEdge(root, bb);  // root out1 = bb (true), bb in0 = root
          graph.addEdge(b1, bb);    // bb in1 = b1
          bool0 = buildBoolOp(*fd, root, b + 0x10, CPUI_INT_LESS, 1, 0)
                      ->getOut();
          if (ci == 1) {
            // BOOL_NEGATE(bool0) in root; CBRANCH cond = negate output.
            PcodeOp *neg = fd->newOp(1, b + 0x18);
            fd->opSetOpcode(neg, CPUI_BOOL_NEGATE);
            fd->newUniqueOut(1, neg);
            fd->opSetInput(neg, bool0, 0);
            fd->opInsertEnd(neg, root);
            condVn = neg->getOut();
          }
          else
            condVn = bool0;
          bool1 = buildBoolOp(*fd, b1, b + 0x50, CPUI_INT_EQUAL, 0, 1)
                      ->getOut();
        }
        else if (ci == 2) {
          // root --out0--> b0 --out1--> bb; b0 --> bb (bb in0 = b0,
          // bb in1 = root).
          BlockBasic *b0 = graph.newBlockBasic(fd);
          graph.addEdge(root, b0); // root out0 = b0, b0 in0 = root
          graph.addEdge(b0, bb);   // bb in0 = b0
          graph.addEdge(root, bb); // root out1 = bb (true), bb in1 = root
          bool1 = buildBoolOp(*fd, root, b + 0x10, CPUI_INT_EQUAL, 1, 0)
                      ->getOut();
          bool0 = buildBoolOp(*fd, b0, b + 0x50, CPUI_INT_SLESS, 0, 1)
                      ->getOut();
          condVn = bool1;
        }
        else {
          // p0 --> root; root --out0--> b1 --out1--> bb; b1 --> bb.
          // Both booleans formed in p0 (before the branch).
          BlockBasic *p0 = graph.newBlockBasic(fd);
          BlockBasic *b1 = graph.newBlockBasic(fd);
          graph.addEdge(p0, root);
          graph.addEdge(root, b1);
          graph.addEdge(root, bb);
          graph.addEdge(b1, bb);
          bool0 = buildBoolOp(*fd, p0, b + 0x08, CPUI_INT_LESS, 1, 0)
                      ->getOut();
          bool1 = buildBoolOp(*fd, p0, b + 0x0c, CPUI_INT_EQUAL, 0, 1)
                      ->getOut();
          condVn = bool0;
        }

        // Root terminator: CBRANCH(cond) for cases 0-3, INT_ADD for case 4.
        if (ci != 4) {
          PcodeOp *cbr = fd->newOp(2, b + 0x30);
          fd->opSetOpcode(cbr, CPUI_CBRANCH);
          fd->opSetInput(cbr, fd->newConstant(8, base + 0x70), 0);
          fd->opSetInput(cbr, condVn, 1);
          fd->opInsertEnd(cbr, root);
        }
        else {
          PcodeOp *tail = fd->newOp(2, b + 0x30);
          fd->opSetOpcode(tail, CPUI_INT_ADD);
          fd->newUniqueOut(1, tail);
          fd->opSetInput(tail, condVn, 0);
          fd->opSetInput(tail, fd->newConstant(1, 1), 1);
          fd->opInsertEnd(tail, root);
        }

        // MULTIEQUAL(bool0, bool1) in bb.
        multiOp = fd->newOp(2, b + 0x70);
        fd->opSetOpcode(multiOp, CPUI_MULTIEQUAL);
        fd->newUniqueOut(1, multiOp);
        fd->opSetInput(multiOp, bool0, 0);
        fd->opSetInput(multiOp, bool1, 1);
        fd->opInsertEnd(multiOp, bb);

        int4 apply = condMoveRule.applyOp(multiOp, *fd);
        std::cout << "case=" << caseNames[ci] << "|apply=" << apply << '\n';
        dumpCaseWindow(*fd, Address(code, base),
                       Address(code, base + 0x80));
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
    std::cerr << "std exception: " << error.what() << '\n';
  }
  return 1;
}
