/*
 * RULEACTION-RS0-RELGATE-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleStructOffset0::applyOp (ruleaction.cc:6675-6756) into the
 * formal relative-pointer branch (ruleaction.cc:6695-6725:
 * `ct->isFormalPointerRel() && evaluateThruParent(0)`), exercising:
 *   - the field-start rewrite (getSubType newoff 0 → PTRSUB(#0), cc:6721-6722)
 *   - the interior-offset INT_ADD back-fill (newoff != 0 → PTRSUB(#-newoff &
 *     mask) + INT_ADD(newoff), cc:6716-6720)
 *   - wordsize scaling via AddrSpace::byteToAddress(newoff, ws) (cc:6709)
 *   - the STORE form (movesize = op->getIn(2)->getSize(), cc:6684-6686)
 *   - the evaluateThruParent(0) gate rejection (pointed-to type is a struct,
 *     type.cc:2591-2592 → plain path, cc:6726+)
 *   - the subtype-too-small guard (cc:6708)
 *   - the past-parent gate rejection (offset folds to >= parent size)
 *
 * Per case canvas (fake code-space window, ops built in this order):
 *   COPY  @base+0x10  out8 <- #0x100          (the pointer varnode)
 *   LOAD  @base+0x40  out<movesize> <- [spaceid, ptrout]
 *   (STORE variant: STORE @base+0x40 <- [spaceid, ptrout, value4])
 * The formal rel type is built with TypeFactory::getTypePointerRel
 * (type.hh:849) over a 2-field int struct {a@0, b@4} (size 8).
 *
 * Observations (ops in SeqNum order within the case window):
 *   case=<name>|apply=<0/1>
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

RuleStructOffset0 structOffset0Rule("analysis");

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
  for (int4 i = 0; i < 3; ++i) {
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

struct CaseSpec {
  const char *name;
  uintb base;
  bool isStore;
  int4 relOff;			// TypePointerRel byte offset
  int4 wordsize;
  bool ptrToIsStruct;		// true → evaluateThruParent(0) gate rejects
  int4 moveSize;		// LOAD out / STORE value size
};

} // namespace

int main(int argc, char **argv)
{
  if (argc != 4) {
    std::cerr << "usage: rule_structoffset0_relptr_1204 SPEC_ROOT CURL_BINARY MODE(normal)\n";
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
      fd->startTypeRecovery(); // hasTypeRecoveryStarted gate (cc:6680)

      // Shared canvas types: parent struct {a@0 int, b@4 int} (size 8).
      TypeFactory *types = architecture.types;
      Datatype *int4t = types->getBase(4, TYPE_INT, "int");
      TypeStruct *parentStruct = types->getTypeStruct("parent2");
      {
        vector<TypeField> fields;
        fields.push_back(TypeField(0, 0, "a", int4t));
        fields.push_back(TypeField(4, 4, "b", int4t));
        types->setFields(fields, parentStruct, 8, 4, 0);
      }

      AddrSpace *code = fd->getArch()->getDefaultCodeSpace();
      BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
      BlockBasic *block = graph.newBlockBasic(fd);

      const vector<CaseSpec> cases = {
        // Rel offset 4 = field b start: newoff 0 → PTRSUB(#0) direct rewire
        // (cc:6721-6722).
        {"rel_field_start", 0x820000, false, 4, 1, false, 4},
        // Rel offset 6 inside field b: getSubType newoff 2 → PTRSUB(#-2 &
        // mask) + INT_ADD(#2) (cc:6716-6720).
        {"rel_interior_int_add", 0x820100, false, 6, 1, false, 4},
        // Wordsize 2: byteToAddress(2,2)=1 → PTRSUB(#-1 & mask) + INT_ADD(#1)
        // (cc:6709).
        {"rel_wordsize2", 0x820200, false, 6, 2, false, 4},
        // STORE form: movesize = value input size (cc:6684-6686), interior
        // offset with the same INT_ADD back-fill.
        {"rel_store_interior", 0x820300, true, 6, 1, false, 4},
        // Gate rejection: ptrto is the (nonempty) struct → evaluateThruParent
        // (0) false (type.cc:2591-2592) → plain path on ptrto → PTRSUB(#0).
        {"rel_thru_parent_gate", 0x820400, false, 6, 1, true, 4},
        // Subtype too small: rel offset 0 (field a, newoff 0) but the move
        // is 8 bytes > field a's 4 (cc:6708) → 0, no ops.
        {"rel_subtype_too_small", 0x820500, false, 0, 1, false, 8},
        // Past parent: offset 8 folds (0+8)&mask = 8 NOT < 8 → gate false →
        // plain path on int ptrto → 0, no ops.
        {"rel_offset_past_parent", 0x820600, false, 8, 1, false, 4},
      };

      for (uint4 ci = 0; ci < cases.size(); ++ci) {
        const CaseSpec &spec = cases[ci];
        Address base(code, spec.base);
        // Formal rel pointer over the parent struct (per-case name: the
        // factory dedups by name and rejects structural redefinition).
        Datatype *ptrTo = spec.ptrToIsStruct
            ? static_cast<Datatype *>(parentStruct)
            : int4t;
        string relName = string("relptr_") + spec.name;
        TypePointerRel *rel = types->getTypePointerRel(
            8, parentStruct, ptrTo, spec.wordsize, spec.relOff, relName);
        // COPY @base+0x10: out8 <- #0x100, typed as the rel pointer.
        PcodeOp *writer = fd->newOp(1, base + 0x10);
        fd->opSetOpcode(writer, CPUI_COPY);
        Varnode *ptrOut = fd->newUniqueOut(8, writer);
        fd->opSetInput(writer, fd->newConstant(8, 0x100), 0);
        ptrOut->updateType(rel);
        fd->opInsertEnd(writer, block);
        // LOAD/STORE @base+0x40. The spaceid constant is a plain #1: the
        // rule only reads in(1), and both sides print the same value.
        PcodeOp *op;
        if (spec.isStore) {
          op = fd->newOp(3, base + 0x40);
          fd->opSetOpcode(op, CPUI_STORE);
          fd->opSetInput(op, fd->newConstant(8, 1), 0);
          fd->opSetInput(op, ptrOut, 1);
          fd->opSetInput(op, fd->newConstant(spec.moveSize, 0x5a), 2);
        }
        else {
          op = fd->newOp(2, base + 0x40);
          fd->opSetOpcode(op, CPUI_LOAD);
          fd->newUniqueOut(spec.moveSize, op);
          fd->opSetInput(op, fd->newConstant(8, 1), 0);
          fd->opSetInput(op, ptrOut, 1);
        }
        fd->opInsertEnd(op, block);

        int4 apply = structOffset0Rule.applyOp(op, *fd);
        std::cout << "case=" << spec.name << "|apply=" << apply << '\n';
        dumpCaseWindow(*fd, Address(code, spec.base),
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
    std::cerr << "std exception: " << error.what() << '\n';
  }
  return 1;
}
