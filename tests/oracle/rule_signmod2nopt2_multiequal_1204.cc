/*
 * RULE-SIGNMOD2NOPT2-ME-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleSignMod2nOpt2::applyOp (ruleaction.cc:8859-8922) on the
 * MULTIEQUAL path — checkMultiequalForm (ruleaction.cc:8941-8985) — the
 * `V = (V s< 0) ? V + 2^n-1 : V` adjusted-dividend recognition whose block
 * structure checks were previously deferred in Rugra
 * (WORKPKG-UNMAP-RULEADJ-0013).
 *
 * The IR form per case (npow = 4, 8-byte base):
 *
 *     D:  sless = INT_SLESS(base, #0)                 (or x2 / #1 for rejects)
 *         cb    = CBRANCH(#addr, sless)               (flip via opFlipCondition)
 *     N:  add   = INT_ADD(base, #3)
 *     M:  mult  = MULTIEQUAL(addOut, base)            (slot per case)
 *         and   = INT_AND(multOut, #0xfffffffffffffffc)
 *         mpy   = INT_MULT(andOut, #0xffffffffffffffff)   <- rule target
 *         root  = INT_ADD(mpyOut, base)               -> INT_SREM(base, #4)
 *
 * The CFG is the compiled diamond the oracle expects: decision D branches
 * to inner N (the INT_ADD block) and DIRECTLY to merge M; M's other in-edge
 * must be D itself (cc:8960-8972). In-edge/out-edge ORDER is controlled by
 * addEdge call order; MULTIEQUAL input slot i corresponds to M's in-edge i.
 *
 * Cases: 4 positive (slot0/slot1, no-flip/flip, plus the sless-in0 laxity
 * the oracle does NOT check — cc:8975-8982 never compares lessOp in(0) to
 * base), 8 rejects (wrong add constant, other base, inner with extra
 * out-edge, no diamond, non-CBRANCH last op, sless constant != 0, negative
 * branch slot mismatch, 3-input MULTIEQUAL).
 *
 * Observations (one block per case, ops in SeqNum order, then block edge
 * counts in creation order):
 *   case=<name>|me_apply=<0/1>
 *     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
 *     blk=<k>|in=<n>|out=<n>
 *   endcase
 * in class: c=constant, w=written, o=other (free).
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

RuleSignMod2nOpt2 signModRule("analysis");

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

void dumpBlocks(const vector<BlockBasic *> &blocks)
{
  for (uint4 k = 0; k < blocks.size(); ++k) {
    std::cout << "  blk=" << k << "|in=" << blocks[k]->sizeIn()
              << "|out=" << blocks[k]->sizeOut() << '\n';
  }
}

// edgeKind encodes the addEdge call order per case:
//   'a' = N->M, D->M, D->N   (M.in=[N,D], D.out=[M,N])
//   'b' = D->M, N->M, D->N   (M.in=[D,N], D.out=[M,N])
//   'c' = D->N, D->M, N->M   (M.in=[D,N], D.out=[N,M])
//   'd' = N->M, D->N, D->M   (M.in=[N,M->wait, see comment]
//        -> M.in=[N,D], D.out=[N,M])
struct CaseSpec {
  const char *name;
  uint4 base;        // address window base
  char edgeKind;
  int4 slot;         // MULTIEQUAL slot carrying addOut (-1 = 3-input case)
  bool flip;         // cbranch boolean_flip
  int4 addConst;     // INT_ADD constant (3 = npow-1 for npow=4)
  bool otherBase;    // MULTIEQUAL in(1-slot) is x2, not base
  bool slessOnX2;    // INT_SLESS in(0) is x2 (oracle laxity case)
  int4 slessConst;   // INT_SLESS in(1) constant
  bool noCbranch;    // append a dummy INT_ADD after cb in D
  bool innerExtraOut;// N also flows to an extra block X
  bool noDiamond;    // E->M instead of D->M
};

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 4) {
    std::cerr << "usage: rule_signmod2nopt2_multiequal_1204 SPEC_ROOT CURL_BINARY MODE(normal)\n";
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

      const vector<CaseSpec> cases = {
        // Positive: slot0, M.in=[N,D], D.out=[M,N], no flip: negBlock =
        // getTrueOut() = D.out[1] = N == inner -> negSlot 0 == slot.
        {"me_pos_slot0_noflip", 0x610000, 'a', 0, false, 3, false, false, 0, false, false, false},
        // Positive: slot1, M.in=[D,N] (inner picked at in-slot 1), D.out=[M,N]:
        // negBlock = getTrueOut() = D.out[1] = N == inner -> negSlot = 1 == slot.
        {"me_pos_slot1_noflip", 0x610100, 'b', 1, false, 3, false, false, 0, false, false, false},
        // Positive: flip, M.in=[N,D], D.out=[N,M]: negBlock = getFalseOut()
        // = D.out[0] = N == inner -> negSlot 0 == slot.
        {"me_pos_flip", 0x610200, 'd', 0, true, 3, false, false, 0, false, false, false},
        // Positive laxity: INT_SLESS compares x2, not base — cc:8975-8982
        // never checks lessOp in(0) against base, both sides must accept.
        {"me_lax_sless_in0", 0x610300, 'a', 0, false, 3, false, true, 0, false, false, false},
        // Reject: add constant 5 != npow-1.
        {"me_rej_addconst", 0x611000, 'a', 0, false, 5, false, false, 0, false, false, false},
        // Reject: other MULTIEQUAL input is x2, not base.
        {"me_rej_otherbase", 0x611100, 'a', 0, false, 3, true, false, 0, false, false, false},
        // Reject: N has a second out-edge: no M in-edge is 1-in/1-out.
        {"me_rej_inner_extra", 0x611200, 'a', 0, false, 3, false, false, 0, false, true, false},
        // Reject: E->M instead of D->M: M's other in-edge != decision.
        {"me_rej_no_diamond", 0x611300, 'a', 0, false, 3, false, false, 0, false, false, true},
        // Reject: D's last op is a dummy INT_ADD, not a CBRANCH.
        {"me_rej_not_cbranch", 0x611400, 'a', 0, false, 3, false, false, 0, true, false, false},
        // Reject: INT_SLESS in(1) constant is 1, not 0.
        {"me_rej_sless_const", 0x611500, 'a', 0, false, 3, false, false, 1, false, false, false},
        // Reject: flip but D.out=[M,N]: negBlock = getFalseOut() = M ->
        // negSlot = 1 != slot 0.
        {"me_rej_negslot", 0x611600, 'a', 0, true, 3, false, false, 0, false, false, false},
        // Reject: 3-input MULTIEQUAL (early numInput != 2).
        {"me_rej_3inputs", 0x611700, 'a', -1, false, 3, false, false, 0, false, false, false},
      };

      for (uint4 ci = 0; ci < cases.size(); ++ci) {
        const CaseSpec &spec = cases[ci];
        const uint4 b = spec.base;

        // Written non-const atoms: base and x2 (COPY writers).
        Varnode *baseVn;
        Varnode *x2;
        {
          PcodeOp *w1 = fd->newOp(1, Address(code, b + 0x08));
          fd->opSetOpcode(w1, CPUI_COPY);
          baseVn = fd->newUniqueOut(8, w1);
          fd->opSetInput(w1, fd->newConstant(8, 0x1234), 0);
          fd->opInsertEnd(w1, graph.newBlockBasic(fd));
          PcodeOp *w2 = fd->newOp(1, Address(code, b + 0x10));
          fd->opSetOpcode(w2, CPUI_COPY);
          x2 = fd->newUniqueOut(8, w2);
          fd->opSetInput(w2, fd->newConstant(8, 0x5678), 0);
          fd->opInsertEnd(w2, graph.newBlockBasic(fd));
        }

        // Blocks: D (decision), N (inner/INT_ADD), M (merge).
        vector<BlockBasic *> blocks;
        BlockBasic *D = graph.newBlockBasic(fd);
        BlockBasic *N = graph.newBlockBasic(fd);
        BlockBasic *M = graph.newBlockBasic(fd);
        blocks.push_back(D);
        blocks.push_back(N);
        blocks.push_back(M);

        // D: sless + cbranch (+ optional dummy last op).
        PcodeOp *sless = fd->newOp(2, Address(code, b + 0x20));
        fd->opSetOpcode(sless, CPUI_INT_SLESS);
        Varnode *slessOut = fd->newUniqueOut(1, sless);
        fd->opSetInput(sless, spec.slessOnX2 ? x2 : baseVn, 0);
        fd->opSetInput(sless, fd->newConstant(8, spec.slessConst), 1);
        fd->opInsertEnd(sless, D);
        PcodeOp *cb = fd->newOp(2, Address(code, b + 0x28));
        fd->opSetOpcode(cb, CPUI_CBRANCH);
        fd->opSetInput(cb, fd->newConstant(8, b + 0x80), 0);
        fd->opSetInput(cb, slessOut, 1);
        fd->opInsertEnd(cb, D);
        if (spec.flip)
          fd->opFlipCondition(cb);
        if (spec.noCbranch) {
          PcodeOp *dummy = fd->newOp(2, Address(code, b + 0x2c));
          fd->opSetOpcode(dummy, CPUI_INT_ADD);
          fd->newUniqueOut(8, dummy);
          fd->opSetInput(dummy, baseVn, 0);
          fd->opSetInput(dummy, fd->newConstant(8, 1), 1);
          fd->opInsertEnd(dummy, D);
        }

        // N: add = INT_ADD(base, #addConst).
        PcodeOp *add = fd->newOp(2, Address(code, b + 0x30));
        fd->opSetOpcode(add, CPUI_INT_ADD);
        Varnode *addOut = fd->newUniqueOut(8, add);
        fd->opSetInput(add, baseVn, 0);
        fd->opSetInput(add, fd->newConstant(8, spec.addConst), 1);
        fd->opInsertEnd(add, N);

        // M: MULTIEQUAL + and + mpy + root.
        int4 nIn = (spec.slot < 0) ? 3 : 2;
        PcodeOp *mult = fd->newOp(nIn, Address(code, b + 0x40));
        fd->opSetOpcode(mult, CPUI_MULTIEQUAL);
        Varnode *multOut = fd->newUniqueOut(8, mult);
        if (spec.slot < 0) {
          // 3-input reject: [addOut, base, x2].
          fd->opSetInput(mult, addOut, 0);
          fd->opSetInput(mult, baseVn, 1);
          fd->opSetInput(mult, x2, 2);
        }
        else if (spec.slot == 0) {
          fd->opSetInput(mult, addOut, 0);
          fd->opSetInput(mult, spec.otherBase ? x2 : baseVn, 1);
        }
        else {
          fd->opSetInput(mult, baseVn, 0);
          fd->opSetInput(mult, addOut, 1);
        }
        fd->opInsertEnd(mult, M);
        PcodeOp *andop = fd->newOp(2, Address(code, b + 0x48));
        fd->opSetOpcode(andop, CPUI_INT_AND);
        Varnode *andOut = fd->newUniqueOut(8, andop);
        fd->opSetInput(andop, multOut, 0);
        fd->opSetInput(andop, fd->newConstant(8, 0xfffffffffffffffcULL), 1);
        fd->opInsertEnd(andop, M);
        PcodeOp *mpy = fd->newOp(2, Address(code, b + 0x50));
        fd->opSetOpcode(mpy, CPUI_INT_MULT);
        Varnode *mpyOut = fd->newUniqueOut(8, mpy);
        fd->opSetInput(mpy, andOut, 0);
        fd->opSetInput(mpy, fd->newConstant(8, 0xffffffffffffffffULL), 1);
        fd->opInsertEnd(mpy, M);
        PcodeOp *root = fd->newOp(2, Address(code, b + 0x58));
        fd->opSetOpcode(root, CPUI_INT_ADD);
        fd->newUniqueOut(8, root);
        fd->opSetInput(root, mpyOut, 0);
        fd->opSetInput(root, baseVn, 1);
        fd->opInsertEnd(root, M);

        // Edges (order is the semantics under test).
        BlockBasic *X = (BlockBasic *)0;
        BlockBasic *E = (BlockBasic *)0;
        if (spec.innerExtraOut) {
          X = graph.newBlockBasic(fd);
          blocks.push_back(X);
        }
        if (spec.noDiamond) {
          E = graph.newBlockBasic(fd);
          blocks.push_back(E);
        }
        switch (spec.edgeKind) {
        case 'a': // M.in=[N,D], D.out=[M,N]
          graph.addEdge(N, M);
          graph.addEdge(spec.noDiamond ? E : D, M);
          graph.addEdge(D, N);
          break;
        case 'b': // M.in=[D,N], D.out=[M,N]
          graph.addEdge(D, M);
          graph.addEdge(N, M);
          graph.addEdge(D, N);
          break;
        case 'c': // M.in=[D,N], D.out=[N,M]
          graph.addEdge(D, N);
          graph.addEdge(D, M);
          graph.addEdge(N, M);
          break;
        default: // 'd': M.in=[N,D], D.out=[N,M]
          graph.addEdge(N, M);
          graph.addEdge(D, N);
          graph.addEdge(D, M);
          break;
        }
        if (spec.innerExtraOut)
          graph.addEdge(N, X);

        int4 apply = signModRule.applyOp(mpy, *fd);
        std::cout << "case=" << spec.name << "|me_apply=" << apply << '\n';
        dumpCaseWindow(*fd, Address(code, b), Address(code, b + 0x100));
        dumpBlocks(blocks);
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
