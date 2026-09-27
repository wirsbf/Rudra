/*
 * PROTOCAST (CURLCANON-PROTOCAST-INPUTS-0001): locked Ghidra 12.0.4 oracle
 * projection for the CAST-A facing-type decision points — the argument
 * facing type (HighVariable::getType via getTypeRepresentative,
 * variable.cc:377-396) versus the prototype-declared required type
 * (TypeOpCall::getInputLocal typeop.cc:687-718 / TypeOpReturn::getInputLocal
 * typeop.cc:901-922 / TypeOpStore::getInputCast typeop.cc:520-555), decided
 * by CastStrategyC::castStandard (cast.cc:300-392), whose object-identity
 * arms are cc:304 (`curtype == reqtype`) and cc:329 (`curbase == reqbase`
 * after pointer/typedef strip).
 *
 * The canon residuals this fixture pins (ghidra_curl_1204.c):
 *   - my_get_line:1300 `fgets(buf,0x1000,(FILE *)fp)` — a locked libc
 *     prototype parameter facing a distinct-object struct-typed argument
 *     high (the clib-universe FILE vs the DWARF-universe FILE) must CAST,
 *     while the same-object state (parseconfig `fclose(__stream)`, helpf
 *     `fwrite(...,stderr)`) must NOT;
 *   - getparameter `file2string((FILE *)V)` — cross-struct argument cast;
 *   - main `outs.stream = (FILE *)fopen(...)` — store value slot cast (the
 *     address input's propagated high FILE** strips one level, cc:530-532,
 *     then castStandard on the field/value pointer pair);
 *   - getparameter `V = (Configurable *)fopen(...)` — castOutput's flipped
 *     roles (coreaction.cc:2590 castStandard(outHighResolve,tokenct)) with
 *     the cast target being the OUTPUT HIGH type;
 *   - my_get_line `return (char *)__dest;` — TypeOpReturn::getInputLocal
 *     (the value is slot 1, printc.cc:764) feeding the base
 *     TypeOp::getInputCast (typeop.cc:295-303).
 *
 * Part A queries the unmodified Architecture-registered TypeOp objects
 * through the real getInputCast virtual dispatch on a real followFlow'd
 * function (the coreaction_callin0_clobber_1204 bootstrap). Part B projects
 * castOutput's flipped-role decision (coreaction.cc:2585-2592) through the
 * real getOutputToken virtual and HighVariable::getType. The Rust twin must
 * print the identical stream.
 */
#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "typeop.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using namespace std;

/// Deterministic type label shared with the Rust twin: printRaw for named
/// composites/pointers, canonical base names for scalars, and `unk<size>`
/// for UNKNOWN bases (whose factory spelling is not part of the projection).
string typeLabel(const Datatype *ct)

{
  if (ct == (const Datatype *)0)
    return "NONE";
  if (ct->getMetatype() == TYPE_UNKNOWN)
    return "unk" + to_string(ct->getSize());
  ostringstream stream;
  ct->printRaw(stream);
  return stream.str();
}

void attachOwnHigh(Varnode *vn)

{
  HighVariable *high = new HighVariable(vn);
  if (high == (HighVariable *)0)
    throw runtime_error("high attach failed");
}

/// Build a callee Funcdata whose FuncProto carries a platform-recovered
/// locked signature through the real setPieces channel (fspec.cc:3843-3852)
/// — the same production path the CALLSPEC-COPY fixture pins.
static Funcdata *build_locked_callee(Architecture &arch, Scope *globalScope,
                                      const Address &addr, const string &name,
                                      Datatype *outtype, vector<Datatype *> intypes,
                                      vector<string> innames)
{
  FunctionSymbol *sym = globalScope->addFunction(addr, name);
  Funcdata *callee = sym->getFunction();
  PrototypePieces pieces;
  pieces.model = (ProtoModel *)0;	// keep the constructor-bound defaultfp
  pieces.name = name;
  pieces.outtype = outtype;
  pieces.intypes = intypes;
  pieces.innames = innames;
  pieces.firstVarArgSlot = -1;
  callee->getFuncProto().setPieces(pieces);
  return callee;
}

/// Build a CALL op bound to a callsite FuncCallSpecs carrying a copy of the
/// callee's locked prototype — the flow.cc:685 setupCallSpecs +
/// coreaction.cc:2321-2324 ActionDefaultParams copy channel state.
static PcodeOp *build_call_site(Funcdata *fd, FuncCallSpecs **fcOut,
                                 Funcdata *callee, const Address &pc,
                                 Varnode *arg)

{
  // The entry constant matches the pointer transport size (flow.cc creates
  // it from the code address).
  static const int4 pointer_size_hint = 8;
  PcodeOp *op = fd->newOp(2, pc);
  fd->opSetOpcode(op, CPUI_CALL);
  // flow.cc setupCallSpecs order: the CALL op carries its entry-point
  // constant in slot 0 when the FuncCallSpecs ctor reads it (fspec.cc:4932
  // call_op->getIn(0)->getAddr()); the fspec annotation varnode replaces it
  // only afterwards (flow.cc:685).
  fd->opSetInput(op, fd->newConstant(pointer_size_hint, callee->getAddress().getOffset()), 0);
  FuncCallSpecs *fc = new FuncCallSpecs(op);
  fc->copy(callee->getFuncProto());
  fd->opSetInput(op, fd->newVarnodeCallSpecs(fc), 0);
  fd->opSetInput(op, arg, 1);
  *fcOut = fc;
  return op;
}

void runFixture(const string &specDirectory, const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary, "default", &cerr);
  DocumentStorage store;
  arch.init(store);
  arch.readLoaderSymbols("::");
  if (arch.archid != "x86:LE:64:default:gcc")
    throw runtime_error("runtime architecture/compiler drifted: " + arch.archid);

  TypeFactory *factory = arch.types;
  AddrSpace *code = arch.getDefaultCodeSpace();
  AddrSpace *ram = arch.getDefaultDataSpace();
  if (factory == (TypeFactory *)0 || code == (AddrSpace *)0 || ram == (AddrSpace *)0)
    throw runtime_error("required architecture service missing");

  CastStrategyC strategy;
  strategy.setTypeFactory(factory);

  const int4 pointerSize = factory->getSizeOfPointer();
  const int4 wordSize = ram->getWordSize();

  // The two type universes the canon golden proves the oracle holds: the
  // DWARF-side FILE (the binary's DWARF materializes a struct named FILE,
  // DWARF-SYMFIELD-TYPESTATE-0001) and the clib-side FILE minted separately
  // by the platform signature source (generic_clib). castStandard never
  // compares names — only object identity (cast.cc:304/329) — so the
  // fixture mints two distinct structs.
  Datatype *fileDwarf = factory->getTypeStruct("FILE");
  Datatype *fileClib = factory->getTypeStruct("_IO_FILE");
  Datatype *confDwarf = factory->getTypeStruct("Configurable");
  if (fileDwarf == fileClib)
    throw runtime_error("distinct struct minting failed");

  Datatype *charType = factory->getTypeChar(factory->getSizeOfChar());
  Datatype *uint8Type = factory->getBase(8, TYPE_UINT);
  Datatype *unknown8Type = factory->getBase(8, TYPE_UNKNOWN);

  Datatype *fileDwarfPtr = factory->getTypePointer(pointerSize, fileDwarf, wordSize);
  Datatype *fileClibPtr = factory->getTypePointer(pointerSize, fileClib, wordSize);
  Datatype *confDwarfPtr = factory->getTypePointer(pointerSize, confDwarf, wordSize);
  Datatype *charPtr = factory->getTypePointer(pointerSize, charType, wordSize);
  Datatype *uint8Ptr = factory->getTypePointer(pointerSize, uint8Type, wordSize);
  Datatype *fileDwarfPtrPtr = factory->getTypePointer(pointerSize, fileDwarfPtr, wordSize);
  Datatype *fileClibPtrPtr = factory->getTypePointer(pointerSize, fileClibPtr, wordSize);

  cout << "FIXTURE=PROTOCAST-FACING-1204\n";
  cout << "ARCH=" << arch.archid << "\n";
  cout << "DISTINCT|file_dwarf_ne_file_clib=" << ((fileDwarf != fileClib) ? 1 : 0) << "\n";
  cout << "DISTINCT|ptr_dwarf_ne_ptr_clib=" << ((fileDwarfPtr != fileClibPtr) ? 1 : 0) << "\n";

  Scope *global = arch.symboltab->getGlobalScope();

  // Callees for the callsite prototypes: the clib-locked fgets/fclose shape
  // (param FILE*_clib), the DWARF-locked my_get_line/file2string shape
  // (param FILE*_dwarf), and the fopen shape (output FILE*_clib).
  vector<Datatype *> clibIntypes; clibIntypes.push_back(fileClibPtr);
  vector<string> oneName; oneName.push_back("fixture_fp");
  Funcdata *calleeClib = build_locked_callee(arch, global,
      Address(code, 0x600000), "fixture_fgets_clib", charPtr, clibIntypes, oneName);
  vector<Datatype *> dwarfIntypes; dwarfIntypes.push_back(fileDwarfPtr);
  Funcdata *calleeDwarf = build_locked_callee(arch, global,
      Address(code, 0x600100), "fixture_my_get_line_dwarf", charPtr, dwarfIntypes, oneName);
  vector<Datatype *> noIntypes;
  vector<string> noNames;
  Funcdata *calleeOut = build_locked_callee(arch, global,
      Address(code, 0x600200), "fixture_fopen_clib", fileClibPtr, noIntypes, noNames);
  if (!calleeClib->getFuncProto().isInputLocked() || !calleeClib->getFuncProto().isModelLocked())
    throw runtime_error("callee setPieces did not lock");

  // Real-function bootstrap (coreaction_callin0_clobber_1204 pattern):
  // followFlow + structureReset give real BlockBasics so
  // TypeOpReturn::getInputLocal's op->getParent()->getFuncdata() chain and
  // the ActionSetCasts::apply block walk both take their production path.
  Funcdata *fd = global->queryFunction("my_fwrite");
  if (fd == (Funcdata *)0 || fd->getAddress().getOffset() != 0x3460)
    throw runtime_error("my_fwrite fixture identity drifted");
  fd->startProcessing();
  if (fd->getBasicBlocks().getSize() == 0)
    throw runtime_error("no basic blocks after startProcessing");
  // Production order runs the universal action group (which calls
  // setHighLevel via ActionStartTypes' heritage pass) before setcasts;
  // ActionSetCasts::resolveUnion/castOutput dereference highs on the real
  // ops, so the fixture reaches the same state here.
  fd->setHighLevel();
  BlockBasic *realBlock = (BlockBasic *)fd->getBasicBlocks().getBlock(0);

  // The caller's own output type through the real setPieces channel
  // (TypeOpReturn::getInputLocal reads it unconditionally; the
  // isOutputLocked gate at typeop.cc:917 is commented out in 12.0.4).
  {
    PrototypePieces pieces;
    pieces.model = (ProtoModel *)0;
    pieces.name = fd->getName();
    pieces.outtype = charPtr;
    pieces.firstVarArgSlot = -1;
    fd->getFuncProto().setPieces(pieces);
  }

  // ------------------------------------------------------------------
  // Part A — decision projection through the real getInputCast dispatch.
  // Synthetic varnodes live far above the function's real frame.
  // ------------------------------------------------------------------

  // RETURN arm (typeop.cc:901-922 via base TypeOp::getInputCast 295-303).
  PcodeOp *retDistinctOp = (PcodeOp *)0;
  {
    // ret_distinct: output char* vs a uint8* high (my_get_line
    // `return (char *)__dest;`). Block-attached so the parent chain works;
    // the apply half below reports the inserted CAST on this same op.
    Varnode *val = fd->newVarnode(8, Address(ram, 0x40000000));
    val->updateType(uint8Ptr, false, false);
    attachOwnHigh(val);
    retDistinctOp = fd->newOp(2, Address(code, 0x500010));
    fd->opSetOpcode(retDistinctOp, CPUI_RETURN);
    fd->opSetInput(retDistinctOp, fd->newConstant(1, 0), 0);
    fd->opSetInput(retDistinctOp, val, 1);
    fd->opInsertEnd(retDistinctOp, realBlock);
    const Datatype *ct = retDistinctOp->getOpcode()->getInputCast(retDistinctOp, 1, &strategy);
    cout << "DECISION|ret_distinct|req=" << typeLabel(fd->getFuncProto().getOutputType())
         << "|cur=" << typeLabel(val->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
  }
  {
    // ret_same: same object -> no cast.
    Varnode *val = fd->newVarnode(8, Address(ram, 0x40000010));
    val->updateType(charPtr, false, false);
    attachOwnHigh(val);
    PcodeOp *op = fd->newOp(2, Address(code, 0x500020));
    fd->opSetOpcode(op, CPUI_RETURN);
    fd->opSetInput(op, fd->newConstant(1, 0), 0);
    fd->opSetInput(op, val, 1);
    fd->opInsertEnd(op, realBlock);
    const Datatype *ct = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|ret_same|cur=" << typeLabel(val->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
  }
  {
    // ret_size_mismatch: output int4 (size 4 != 8) -> base default req.
    PrototypePieces pieces;
    pieces.model = (ProtoModel *)0;
    pieces.name = fd->getName();
    pieces.outtype = factory->getBase(4, TYPE_INT);
    pieces.firstVarArgSlot = -1;
    fd->getFuncProto().setPieces(pieces);
    Varnode *val = fd->newVarnode(8, Address(ram, 0x40000020));
    val->updateType(uint8Ptr, false, false);
    attachOwnHigh(val);
    PcodeOp *op = fd->newOp(2, Address(code, 0x500030));
    fd->opSetOpcode(op, CPUI_RETURN);
    fd->opSetInput(op, fd->newConstant(1, 0), 0);
    fd->opSetInput(op, val, 1);
    fd->opInsertEnd(op, realBlock);
    const Datatype *ct = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|ret_size_mismatch|req=" << typeLabel(fd->getFuncProto().getOutputType())
         << "|cur=" << typeLabel(val->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
    // Restore the char* output for the apply half below.
    PrototypePieces restore;
    restore.model = (ProtoModel *)0;
    restore.name = fd->getName();
    restore.outtype = charPtr;
    restore.firstVarArgSlot = -1;
    fd->getFuncProto().setPieces(restore);
  }
  {
    // ret_slot0: the indeterminate marker slot takes the base default. The
    // marker constant carries a high (production setHighLevel gives every
    // varnode one; getHighTypeReadFacing would dereference it).
    Varnode *mark = retDistinctOp->getIn(0);
    mark->updateType(factory->getBase(1, TYPE_UNKNOWN), false, false);
    attachOwnHigh(mark);
    const Datatype *ct = retDistinctOp->getOpcode()->getInputCast(retDistinctOp, 0, &strategy);
    cout << "DECISION|ret_slot0|result=" << typeLabel(ct) << "\n";
  }

  // CALL arm (typeop.cc:687-718 via base TypeOp::getInputCast). These stay
  // detached (no block) — the call arm reads no parent.
  {
    // call_locked_distinct: fgets-shape — clib-locked FILE* param facing a
    // DWARF-FILE* argument high (my_get_line:1300 `(FILE *)fp`).
    Varnode *arg = fd->newVarnode(8, Address(ram, 0x40000100));
    arg->updateType(fileDwarfPtr, false, false);
    attachOwnHigh(arg);
    FuncCallSpecs *fc;
    PcodeOp *op = build_call_site(fd, &fc, calleeClib, Address(code, 0x500110), arg);
    const Datatype *ct = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|call_locked_distinct|req=" << typeLabel(fc->getParam(0)->getType())
         << "|cur=" << typeLabel(arg->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
  }
  {
    // call_locked_same: fclose/stdin-shape — same object -> no cast.
    Varnode *arg = fd->newVarnode(8, Address(ram, 0x40000110));
    arg->updateType(fileClibPtr, false, false);
    attachOwnHigh(arg);
    FuncCallSpecs *fc;
    PcodeOp *op = build_call_site(fd, &fc, calleeClib, Address(code, 0x500120), arg);
    const Datatype *ct = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|call_locked_same|req=" << typeLabel(fc->getParam(0)->getType())
         << "|cur=" << typeLabel(arg->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
  }
  {
    // call_locked_vs_unknown: weak facing -> base-size mismatch -> cast.
    Varnode *arg = fd->newVarnode(8, Address(ram, 0x40000120));
    arg->updateType(unknown8Type, false, false);
    attachOwnHigh(arg);
    FuncCallSpecs *fc;
    PcodeOp *op = build_call_site(fd, &fc, calleeClib, Address(code, 0x500130), arg);
    const Datatype *ct = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|call_locked_vs_unknown|req=" << typeLabel(fc->getParam(0)->getType())
         << "|cur=" << typeLabel(arg->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
  }
  {
    // call_unlocked_noparam: a callsite whose prototype holds no recovered
    // parameters — the production-reachable state is ActionDefaultParams'
    // setInternal(evalfp, void) (coreaction.cc:2327-2328); a model-less
    // FuncCallSpecs never reaches setcasts (fspec.cc:3782 keeps store
    // null until a model assigns one).
    Varnode *arg = fd->newVarnode(8, Address(ram, 0x40000130));
    arg->updateType(fileDwarfPtr, false, false);
    attachOwnHigh(arg);
    PcodeOp *op = fd->newOp(2, Address(code, 0x500140));
    fd->opSetOpcode(op, CPUI_CALL);
    fd->opSetInput(op, fd->newConstant(8, 0), 0);
    FuncCallSpecs *fc = new FuncCallSpecs(op);
    ProtoModel *evalfp = arch.evalfp_called;
    if (evalfp == (ProtoModel *)0)
      evalfp = arch.defaultfp;
    fc->setInternal(evalfp, factory->getTypeVoid());
    fd->opSetInput(op, fd->newVarnodeCallSpecs(fc), 0);
    fd->opSetInput(op, arg, 1);
    const Datatype *ct = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|call_unlocked_noparam|cur=" << typeLabel(arg->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
  }
  {
    // call_conf_vs_file: getparameter `file2string((FILE *)V)` — DWARF
    // prototype param FILE* facing a Configurable* argument high.
    Varnode *arg = fd->newVarnode(8, Address(ram, 0x40000140));
    arg->updateType(confDwarfPtr, false, false);
    attachOwnHigh(arg);
    FuncCallSpecs *fc;
    PcodeOp *op = build_call_site(fd, &fc, calleeDwarf, Address(code, 0x500150), arg);
    const Datatype *ct = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|call_conf_vs_file|req=" << typeLabel(fc->getParam(0)->getType())
         << "|cur=" << typeLabel(arg->getHigh()->getType())
         << "|result=" << typeLabel(ct) << "\n";
  }

  // STORE arm (typeop.cc:520-555): the address input's high is the
  // propagated field-address type (FILE**), stripped exactly one level.
  {
    // store_distinct: `outs.stream = (FILE *)fopen(...)` — DWARF field
    // pointer vs clib value pointer.
    PcodeOp *op = fd->newOp(3, Address(code, 0x500210));
    fd->opSetOpcode(op, CPUI_STORE);
    fd->opSetInput(op, fd->newConstant(8, (uintb)(uintp)ram), 0);
    Varnode *addr = fd->newVarnode(8, Address(ram, 0x40000200));
    addr->updateType(fileDwarfPtrPtr, false, false);
    attachOwnHigh(addr);
    fd->opSetInput(op, addr, 1);
    Varnode *val = fd->newVarnode(8, Address(ram, 0x40000210));
    val->updateType(fileClibPtr, false, false);
    attachOwnHigh(val);
    fd->opSetInput(op, val, 2);
    const Datatype *ct2 = op->getOpcode()->getInputCast(op, 2, &strategy);
    const Datatype *ct1 = op->getOpcode()->getInputCast(op, 1, &strategy);
    cout << "DECISION|store_distinct|slot2=" << typeLabel(ct2)
         << "|slot1=" << typeLabel(ct1) << "\n";
  }
  {
    // store_same: same universe field+value -> no cast.
    PcodeOp *op = fd->newOp(3, Address(code, 0x500220));
    fd->opSetOpcode(op, CPUI_STORE);
    fd->opSetInput(op, fd->newConstant(8, (uintb)(uintp)ram), 0);
    Varnode *addr = fd->newVarnode(8, Address(ram, 0x40000220));
    addr->updateType(fileClibPtrPtr, false, false);
    attachOwnHigh(addr);
    fd->opSetInput(op, addr, 1);
    Varnode *val = fd->newVarnode(8, Address(ram, 0x40000230));
    val->updateType(fileClibPtr, false, false);
    attachOwnHigh(val);
    fd->opSetInput(op, val, 2);
    const Datatype *ct2 = op->getOpcode()->getInputCast(op, 2, &strategy);
    cout << "DECISION|store_same|slot2=" << typeLabel(ct2) << "\n";
  }

  // ------------------------------------------------------------------
  // Part B — output-cast decision projection. castOutput (coreaction.cc
  // :2532-2616, private static) decides through the flipped roles at
  // cc:2585-2592: `outct = outHighResolve; ct = castStandard(outct, tokenct,
  // false, true)` — the OUTPUT HIGH type is the required side, so the cast
  // target is the high's type (getparameter `V = (Configurable *)fopen`).
  // The token and the high are real (virtual getOutputToken + HighVariable
  // ::getType); the implied-varnode and union-resolution arms cannot fire
  // for these shapes (explicit output, non-union types), and the PTRSUB
  // alternative at cc:2586 needs an offset-0 field on the token side, which
  // the fieldless fixture structs cannot provide. The insertion tail
  // (newOp/opSetInput plumbing) is exercised end-to-end by the canon gate.
  // ------------------------------------------------------------------
  {
    PcodeOp *op = fd->newOp(1, Address(code, 0x500060));
    fd->opSetOpcode(op, CPUI_CALL);
    fd->opSetInput(op, fd->newConstant(8, 0), 0);
    FuncCallSpecs *fc = new FuncCallSpecs(op);
    fc->copy(calleeOut->getFuncProto());
    fd->opSetInput(op, fd->newVarnodeCallSpecs(fc), 0);
    Varnode *out = fd->newVarnode(8, Address(ram, 0x40000060));
    out->updateType(confDwarfPtr, false, false);
    attachOwnHigh(out);
    fd->opSetOutput(op, out);

    Datatype *tokenct = op->getOpcode()->getOutputToken(op, &strategy);
    Datatype *outHighType = out->getHigh()->getType();
    if (tokenct == outHighType) {
      cout << "OUTCAST|call_out_distinct|token=" << typeLabel(tokenct)
           << "|high=" << typeLabel(outHighType) << "|result=NONE\n";
    }
    else {
      Datatype *outct = outHighType;
      Datatype *ct = strategy.castStandard(outct, tokenct, false, true);
      cout << "OUTCAST|call_out_distinct|token=" << typeLabel(tokenct)
           << "|high=" << typeLabel(outHighType)
           << "|result=" << ((ct == (Datatype *)0) ? string("NONE") : typeLabel(outct)) << "\n";
    }
  }
  {
    // call_out_same: token == high (same object) -> the cc:2544 short
    // circuit, no cast.
    PcodeOp *op = fd->newOp(1, Address(code, 0x500070));
    fd->opSetOpcode(op, CPUI_CALL);
    fd->opSetInput(op, fd->newConstant(8, 0), 0);
    FuncCallSpecs *fc = new FuncCallSpecs(op);
    fc->copy(calleeOut->getFuncProto());
    fd->opSetInput(op, fd->newVarnodeCallSpecs(fc), 0);
    Varnode *out = fd->newVarnode(8, Address(ram, 0x40000070));
    out->updateType(fileClibPtr, false, false);
    attachOwnHigh(out);
    fd->opSetOutput(op, out);

    Datatype *tokenct = op->getOpcode()->getOutputToken(op, &strategy);
    Datatype *outHighType = out->getHigh()->getType();
    if (tokenct == outHighType) {
      cout << "OUTCAST|call_out_same|token=" << typeLabel(tokenct)
           << "|high=" << typeLabel(outHighType) << "|result=NONE\n";
    }
    else {
      Datatype *outct = outHighType;
      Datatype *ct = strategy.castStandard(outct, tokenct, false, true);
      cout << "OUTCAST|call_out_same|token=" << typeLabel(tokenct)
           << "|high=" << typeLabel(outHighType)
           << "|result=" << ((ct == (Datatype *)0) ? string("NONE") : typeLabel(outct)) << "\n";
    }
  }

  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)

{
  if (argc != 3) {
    cerr << "usage: protocast_facing_1204 <specdir> <binary>\n";
    return 2;
  }
  const string specDirectory = argv[1];
  const string binary = argv[2];
  try {
    runFixture(specDirectory, binary);
  }
  catch (const exception &error) {
    cerr << "protocast_facing_1204: " << error.what() << "\n";
    return 1;
  }
  catch (...) {
    cerr << "protocast_facing_1204: unknown failure\n";
    return 1;
  }
  return 0;
}
