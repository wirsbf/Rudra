/*
 * Locked Ghidra 12.0.4 oracle fixture for PRINTC-SINGLETON-IRFIX-0001:
 * the full-IR bilateral observation of
 *   PrintC::checkAddressOfCast (printc.cc:376-418)
 *   PrintC::pushImpliedField  (printc.cc:2085-2116)
 *
 * The singleton emission fixture (printc_singleton_emission_1204.cc)
 * covered the directly-constructible text-level singletons; these two
 * predicates need hand-built PcodeOp/Varnode/HighVariable/SymbolEntry
 * graphs (the residual registered by WORKPKG-UNMAP-PRINTC-0004).
 *
 * Observation surface: the REAL PrintC::emitExpression (printc.cc:2465-
 * 2494) — assignment push + TypeOp::push + recurse() — over hand-built
 * CAST and RETURN statements. Every input edge of both predicates is a
 * real IR object built through the public Funcdata kit (newOp /
 * opSetOpcode / opSetInput / opSetOutput / opInsertEnd / setHighLevel /
 * setUnionField) and the resident TypeFactory, so the emitted bytes are
 * the full-IR state projection (varnode flags/type/symbol/def edges,
 * opcode wiring, union-resolution map entries).
 *
 *   cast.ptrsub_positive       — (a) out int(*)[4], in0 = implied
 *                                PTRSUB(S*,0) typed int*  -> "&sp->x"
 *                                (checkAddressOfCast PTRSUB-def arm,
 *                                 cc:400-412: rootType S* -> S ->
 *                                 getSubType(0) = int[4], size 16==16)
 *   cast.dtnonptr_reject       — (b) dt1 = int (mapped symbol) rejects
 *                                at cc:382-383 -> "(int (*)[4])ib"
 *   cast.nonarray_base0_reject — (c) out int* (base0 non-array)
 *                                rejects at cc:386-387 -> "(int *)ic"
 *   cast.elem_mismatch_reject  — (d) in0 typed uint* (base1=uint !=
 *                                base0 elem int) rejects at cc:394-395
 *                                -> "(int (*)[4])id->x"
 *   cast.size_mismatch_reject  — (e) out int(*)[2] but PTRSUB selects
 *                                int[4] (16 != 8) rejects at cc:415-417
 *                                -> "(int (*)[2])ie->x"
 *   cast.symbolentry_positive  — (f) whole-map symbol entry (int[2], 8
 *                                bytes, symbolOffset -1 via 8==8 perfect
 *                                match, variable.cc:1727-1729) + the
 *                                read-facing type overridden to int*
 *                                (Varnode::updateType(ct,0,1), varnode.
 *                                cc:474-490) -> symbolEntry arm cc:397-
 *                                399: symbolType int[2], size 8==8 ->
 *                                "&iw"
 *
 *   implied.union_proceed      — (u1) RETURN value vn: high type U
 *                                (needsResolution union), implied +
 *                                has_implied_field, def COPY(const 5);
 *                                fd union map entry (U,op,slot 1) ->
 *                                field b -> "return 5.b" (cc:2100-2115:
 *                                object_member + defOp push + field
 *                                atom)
 *   implied.struct_proceed     — (u4) parent = single-field struct
 *                                (needs_resolution set by the REAL
 *                                TypeFactory::setFields, type.cc:1569-
 *                                1571), fieldNum 0 -> beginField "x"
 *                                (cc:2096-2099) -> "return 5.x"
 *   implied.union_nores        — (u2) union parent, NO map entry: res
 *                                null -> !proceed plain defOp push
 *                                (cc:2108-2111) -> "return 5"
 *   implied.plain_parent       — (u3) int parent: needsResolution gate
 *                                closed at cc:2091 -> "return 5"
 *
 * Object graph (per arm): a GetStr Funcdata over the pinned curl binary
 * (BfdArchitecture, same construction pattern as printc_subpiece_
 * fieldextract_1204.cc). Type-locked register symbols attach through
 * ScopeLocal::addSymbol + newVarnode's queryProperties auto-attach
 * (Varnode::setSymbolProperties, varnode.cc:409-421); implied marks via
 * the public Varnode::setImplied/setImpliedField (varnode.hh:309/335);
 * ops inserted into a real BlockBasic so op->getParent()->getFuncdata()
 * is live for pushImpliedField's union consult (cc:2092).
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "funcdata.hh"
#include "printc.hh"
#include "prettyprint.hh"
#include "type.hh"
#include "unionresolve.hh"
#include "variable.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

// PrintLanguage::emit is protected (the ctor installs an EmitMarkup);
// swap for the plain-text EmitNoMarkup stream — same pattern as
// printc_subpiece_fieldextract_1204.cc. The render trampoline drives the
// REAL emitExpression entry with the local scope pushed so pushSymbol
// does not qualify local names.
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g)
      : PrintC(g, "printc-checkaddr-impliedfield-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  string renderExpression(const PcodeOp *op, Scope *localScope) {
    ostringstream output;
    setOutputStream(&output);
    pushScope(localScope);
    emitExpression(op);
    popScope();
    emit->flush();
    return output.str();
  }
};

// All factory types are built EXACTLY ONCE per process (findAdd rejects
// redefinition of a completed name, type.cc:3421-3423).
struct FixtureTypes {
  Datatype *int4;
  Datatype *uint4;
  Datatype *int8;
  TypeArray *intArr4;
  TypeArray *intArr2;
  TypeStruct *boxStruct;
  TypeUnion *altUnion;
  TypeStruct *innerStruct;
  Datatype *ptrIntArr4;
  Datatype *ptrIntArr2;
  Datatype *ptrInt;
  Datatype *ptrUint;
  Datatype *ptrBox;

  explicit FixtureTypes(TypeFactory *types)
  {
    int4 = types->getBase(4, TYPE_INT);
    uint4 = types->getBase(4, TYPE_UINT);
    int8 = types->getBase(8, TYPE_INT);
    intArr4 = types->getTypeArray(4, int4);
    intArr2 = types->getTypeArray(2, int4);
    // fixture_box { int x[4] @0; long tail @16 } — two fields, no
    // needs_resolution (field[0] does not fill the whole struct).
    boxStruct = types->getTypeStruct("fixture_box");
    {
      vector<TypeField> fields;
      fields.push_back(TypeField(0, 0, "x", intArr4));
      fields.push_back(TypeField(1, 16, "tail", int8));
      types->setFields(fields, boxStruct, 24, 8, 0);
    }
    altUnion = types->getTypeUnion("fixture_alt");
    {
      vector<TypeField> ufields;
      ufields.push_back(TypeField(0, 0, "a", int4));
      ufields.push_back(TypeField(1, 0, "b", uint4));
      types->setFields(ufields, altUnion, 4, 4, 0);
    }
    // fixture_inner { long x } — single field fills the whole struct, so
    // the REAL TypeFactory::setFields sets needs_resolution (type.cc:
    // 1569-1871) — the printc.cc:2096-2099 TYPE_STRUCT proceed arm rides
    // on exactly this flag.
    innerStruct = types->getTypeStruct("fixture_inner");
    if (innerStruct->isIncomplete()) {
      vector<TypeField> innerFields;
      innerFields.push_back(TypeField(0, 0, "x", int8));
      types->setFields(innerFields, innerStruct, 8, 8, 0);
    }
    ptrIntArr4 = types->getTypePointer(8, intArr4, 1);
    ptrIntArr2 = types->getTypePointer(8, intArr2, 1);
    ptrInt = types->getTypePointer(8, int4, 1);
    ptrUint = types->getTypePointer(8, uint4, 1);
    ptrBox = types->getTypePointer(8, boxStruct, 1);
  }
};

// Per-arm IR builder: type-locked register symbols (auto-attach), hand
// wired ops, one fresh BlockBasic, then a single setHighLevel pass.
struct IrFixture {
  Funcdata &fd;
  Architecture *glb;
  AddrSpace *registerSpace;
  AddrSpace *codeSpace;
  uintb pc;
  vector<PcodeOp *> ops;

  IrFixture(Funcdata &f, Architecture *g, uintb basePc)
    : fd(f), glb(g), pc(basePc)
  {
    registerSpace = glb->getSpaceByName("register");
    codeSpace = glb->getDefaultCodeSpace();
    if (registerSpace == (AddrSpace *)0 || codeSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires register and code spaces");
  }

  // Type-locked register Varnode with a whole-map Symbol attached via
  // newVarnode's queryProperties consult (varnode.cc:409-421). The vn's
  // own type is forced to the symbol type (SymbolEntry::updateType,
  // database.cc) — identical to the subpiece fixture's buildSubpiece.
  Varnode *symbolVn(Datatype *symbolType, const char *nm, uintb regOffset,
                    int4 vnSize)
  {
    SymbolEntry *entry = fd.getScopeLocal()->addSymbol(
        nm, symbolType, Address(registerSpace, regOffset), Address());
    fd.getScopeLocal()->setAttribute(entry->getSymbol(), Varnode::typelock);
    Varnode *vn = fd.newVarnode(vnSize, Address(registerSpace, regOffset));
    if (vn->getSymbolEntry() == (SymbolEntry *)0)
      throw std::runtime_error("type-locked symbol did not attach to the varnode");
    return vn;
  }

  PcodeOp *newOpAt(int4 ninputs, OpCode opc)
  {
    PcodeOp *op = fd.newOp(ninputs, Address(codeSpace, pc));
    pc += 0x10;
    fd.opSetOpcode(op, opc);
    return op;
  }

  // PTRSUB(root, 0) whose output carries `elemPtrType` on the Varnode
  // (updateType before highs exist) and the implied mark.
  Varnode *impliedPtrsubOut(Varnode *root, Datatype *elemPtrType)
  {
    PcodeOp *ptrsub = newOpAt(2, CPUI_PTRSUB);
    fd.opSetInput(ptrsub, root, 0);
    fd.opSetInput(ptrsub, fd.newConstant(8, 0), 1);
    Varnode *outvn = fd.newUnique(8);
    outvn->updateType(elemPtrType);
    fd.opSetOutput(ptrsub, outvn);
    outvn->setImplied();
    ops.push_back(ptrsub);
    return outvn;
  }

  // CAST(in0) -> out (the type-locked symbol varnode).
  PcodeOp *castOp(Varnode *in0, Varnode *out)
  {
    PcodeOp *castop = newOpAt(1, CPUI_CAST);
    fd.opSetInput(castop, in0, 0);
    fd.opSetOutput(castop, out);
    ops.push_back(castop);
    return castop;
  }

  // RETURN(indeterminate, value) with value = implied + has_implied_field
  // vn typed `parentType`, defined by COPY(const5).
  PcodeOp *returnOfImplied(Datatype *parentType, int4 constSize, uintb constVal)
  {
    Varnode *valueVn = fd.newUnique(parentType->getSize());
    valueVn->updateType(parentType);
    PcodeOp *copyop = newOpAt(1, CPUI_COPY);
    Varnode *constVn = fd.newConstant(constSize, constVal);
    constVn->updateType(glb->types->getBase(constSize, TYPE_INT));
    fd.opSetInput(copyop, constVn, 0);
    fd.opSetOutput(copyop, valueVn);
    valueVn->setImplied();
    valueVn->setImpliedField();
    PcodeOp *retop = newOpAt(2, CPUI_RETURN);
    fd.opSetInput(retop, fd.newConstant(1, 0), 0);
    fd.opSetInput(retop, valueVn, 1);
    ops.push_back(copyop);
    ops.push_back(retop);
    return retop;
  }

  // Insert the wired ops into a fresh basic block (the union consult in
  // pushImpliedField dereferences op->getParent()->getFuncdata()) and
  // run the single high-creation pass.
  void finish(void)
  {
    BlockBasic *bl =
        const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);
    for(int4 i = 0; i < (int4)ops.size(); ++i)
      fd.opInsertEnd(ops[i], bl);
    fd.setHighLevel();
  }

  string render(PcodeOp *op)
  {
    FixturePrintC printer(glb);
    return printer.renderExpression(op, fd.getScopeLocal());
  }
};

void runCastMatrix(Funcdata &fd, Architecture *glb, const FixtureTypes &ft)
{
  // (a) positive PTRSUB-def arm: out int(*)[4] "ca"; in0 = implied
  //     PTRSUB(sp, 0) out typed int*; sp = type-locked S* register.
  {
    IrFixture fx(fd, glb, 0x5000);
    Varnode *sp = fx.symbolVn(ft.ptrBox, "sp", 0x100, 8);
    Varnode *in0 = fx.impliedPtrsubOut(sp, ft.ptrInt);
    Varnode *out = fx.symbolVn(ft.ptrIntArr4, "ca", 0x120, 8);
    PcodeOp *castop = fx.castOp(in0, out);
    fx.finish();
    std::cout << "cast.ptrsub_positive=" << fx.render(castop) << '\n';
  }
  // (b) dt1 non-pointer: in0 = mapped int symbol "ib".
  {
    IrFixture fx(fd, glb, 0x5200);
    Varnode *ib = fx.symbolVn(ft.int4, "ib", 0x128, 4);
    Varnode *out = fx.symbolVn(ft.ptrIntArr4, "cb", 0x130, 8);
    PcodeOp *castop = fx.castOp(ib, out);
    fx.finish();
    std::cout << "cast.dtnonptr_reject=" << fx.render(castop) << '\n';
  }
  // (c) base0 non-array: out = int* "cc"; in0 = mapped int* symbol "ic".
  {
    IrFixture fx(fd, glb, 0x5400);
    Varnode *ic = fx.symbolVn(ft.ptrInt, "ic", 0x138, 8);
    Varnode *out = fx.symbolVn(ft.ptrInt, "cc", 0x140, 8);
    PcodeOp *castop = fx.castOp(ic, out);
    fx.finish();
    std::cout << "cast.nonarray_base0_reject=" << fx.render(castop) << '\n';
  }
  // (d) element mismatch: in0 = implied PTRSUB(id, 0) out typed uint*.
  {
    IrFixture fx(fd, glb, 0x5600);
    Varnode *id = fx.symbolVn(ft.ptrBox, "id", 0x148, 8);
    Varnode *in0 = fx.impliedPtrsubOut(id, ft.ptrUint);
    Varnode *out = fx.symbolVn(ft.ptrIntArr4, "cd", 0x150, 8);
    PcodeOp *castop = fx.castOp(in0, out);
    fx.finish();
    std::cout << "cast.elem_mismatch_reject=" << fx.render(castop) << '\n';
  }
  // (e) symbol-array size mismatch: out = int(*)[2] "ce"; PTRSUB
  //     selects fixture_box.x int[4] (16 != 8).
  {
    IrFixture fx(fd, glb, 0x5800);
    Varnode *ie = fx.symbolVn(ft.ptrBox, "ie", 0x158, 8);
    Varnode *in0 = fx.impliedPtrsubOut(ie, ft.ptrInt);
    Varnode *out = fx.symbolVn(ft.ptrIntArr2, "ce", 0x160, 8);
    PcodeOp *castop = fx.castOp(in0, out);
    fx.finish();
    std::cout << "cast.size_mismatch_reject=" << fx.render(castop) << '\n';
  }
  // (f) symbolEntry arm positive: whole-map int[2] symbol "iw" (8 bytes,
  //     perfect match -> symbolOffset -1, variable.cc:1727-1729), the
  //     vn read-facing type overridden to int* (updateType(.,0,1),
  //     varnode.cc:474-490 keeps the mapentry); out int(*)[2] "cf".
  {
    IrFixture fx(fd, glb, 0x5a00);
    Varnode *iw = fx.symbolVn(ft.intArr2, "iw", 0x168, 8);
    iw->updateType(ft.ptrInt, false, true);
    Varnode *out = fx.symbolVn(ft.ptrIntArr2, "cf", 0x170, 8);
    PcodeOp *castop = fx.castOp(iw, out);
    fx.finish();
    std::cout << "cast.symbolentry_positive=" << fx.render(castop) << '\n';
  }
}

void runImpliedArms(Funcdata &fd, Architecture *glb, const FixtureTypes &ft)
{
  // (u1) union proceed arm: (U, op, slot 1) -> field b.
  {
    IrFixture fx(fd, glb, 0x7000);
    PcodeOp *retop = fx.returnOfImplied(ft.altUnion, 4, 5);
    fx.finish();
    ResolvedUnion resolve(ft.altUnion, 1, *glb->types);
    fd.setUnionField(ft.altUnion, retop, 1, resolve);
    std::cout << "implied.union_proceed=" << fx.render(retop) << '\n';
  }
  // (u4) struct proceed arm: single-field needs_resolution struct,
  //      fieldNum 0 -> beginField "x".
  {
    IrFixture fx(fd, glb, 0x7200);
    PcodeOp *retop = fx.returnOfImplied(ft.innerStruct, 8, 5);
    fx.finish();
    ResolvedUnion resolve(ft.innerStruct, 0, *glb->types);
    fd.setUnionField(ft.innerStruct, retop, 1, resolve);
    std::cout << "implied.struct_proceed=" << fx.render(retop) << '\n';
  }
  // (u2) union parent, NO map entry: res null -> !proceed plain arm.
  {
    IrFixture fx(fd, glb, 0x7400);
    PcodeOp *retop = fx.returnOfImplied(ft.altUnion, 4, 5);
    fx.finish();
    std::cout << "implied.union_nores=" << fx.render(retop) << '\n';
  }
  // (u3) int parent: the needsResolution gate never opens.
  {
    IrFixture fx(fd, glb, 0x7600);
    PcodeOp *retop = fx.returnOfImplied(ft.int4, 4, 5);
    fx.finish();
    std::cout << "implied.plain_parent=" << fx.render(retop) << '\n';
  }
}

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary, "default", &std::cerr);
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
      throw std::runtime_error("runtime architecture/compiler drifted: " + architecture.archid);

    FixtureTypes fixtureTypes(architecture.types);
    runCastMatrix(*fd, &architecture, fixtureTypes);
    runImpliedArms(*fd, &architecture, fixtureTypes);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: printc_checkaddr_impliedfield_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const ghidra::RecovError &error) {
    std::cerr << "Ghidra RecovError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
