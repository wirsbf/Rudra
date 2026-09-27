/*
 * CALLSPEC-COPY-0001: locked Ghidra 12.0.4 oracle for the ActionDefaultParams
 * prototype-copy channel (coreaction.cc:2311-2337).  Loads the real production
 * x86-64-gcc.cspec through a full BfdArchitecture::init, builds a callee whose
 * FuncProto carries a platform-recovered locked signature (the DWARF /
 * generic_clib boundary state, fspec.cc:3843 setPieces lock tail), then runs
 * the exact ActionDefaultParams loop body over call sites in the three oracle
 * arm shapes and prints the post-copy call-site state the Rust side must
 * reproduce byte for byte:
 *   - COPY: queryCall resolved the callee (fc->setFuncdata, flow.cc:662) so
 *     `fc->copy(otherfunc->getFuncProto())` (fspec.cc:3789) transfers model,
 *     extrapop, the whole flag word, the cloned parameter store (names, types,
 *     typelock/namelock markup, storage addresses) and the effect list; the
 *     callsite's own name survives (the name is FuncCallSpecs state, not part
 *     of the FuncProto copy); the matching-model tail does not override the
 *     copied default-matching model.
 *   - COPY_LOCKEDMISMATCH: a model-locked callee on a foreign model keeps it
 *     (cc:2325 `!fc->isModelLocked()` gate blocks the evalfp override).
 *   - NOFUNC: no callee resolved -> `setInternal(evalfp, void)`
 *     (cc:2327-2328): zero parameters, void output, evaluation model bound.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "database.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "xml.hh"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::runtime_error;
using std::string;
using std::vector;

static void print_callsite_state(const char *tag, FuncCallSpecs &fc, Architecture &arch)
{
  cout << tag << "_NUMPARAMS|" << fc.numParams() << "\n";
  for(int4 i=0;i<fc.numParams();++i) {
    ProtoParameter *param = fc.getParam(i);
    const Address &addr(param->getAddress());
    cout << tag << "_PARAM|" << i
         << "|" << param->getName()
         << "|" << (param->isTypeLocked() ? 1 : 0)
         << "|" << (param->isNameLocked() ? 1 : 0)
         << "|" << param->getType()->getName()
         << "|" << param->getType()->getSize()
         << "|" << (int4)param->getType()->getMetatype()
         << "|" << addr.getSpace()->getName()
         << "|0x" << std::hex << addr.getOffset() << std::dec
         << "|" << param->getSize() << "\n";
  }
  cout << tag << "_OUT|" << fc.getOutput()->getType()->getName()
       << "|" << fc.getOutput()->getSize()
       << "|" << (fc.isOutputLocked() ? 1 : 0) << "\n";
  cout << tag << "_INLOCK|" << (fc.isInputLocked() ? 1 : 0) << "\n";
  cout << tag << "_MODELLOCK|" << (fc.isModelLocked() ? 1 : 0) << "\n";
  cout << tag << "_MODEL|" << (fc.hasModel() ? 1 : 0)
       << "|" << (fc.hasMatchingModel(arch.defaultfp) ? 1 : 0)
       << "|" << fc.getModelName()
       << "|" << fc.getExtraPop() << "\n";
  cout << tag << "_NAME|" << fc.getName() << "\n";
}

/// Build a callee Funcdata whose FuncProto carries a platform-recovered
/// locked signature through the real setPieces channel (fspec.cc:3843-3852:
/// storage assignment + input/output/model locks).
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

void runFixture(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary, "default", &std::cerr);
  DocumentStorage documents;
  arch.init(documents);

  cout << "SCHEMA|1\n";
  cout << "ARCH_DEFAULTFP|" << arch.defaultfp->getName() << "\n";

  Scope *globalScope = arch.symboltab->getGlobalScope();
  AddrSpace *ram = arch.getDefaultCodeSpace();

  // The recovered-signature types: a char* output and a two-parameter input
  // list (char*, struct FILE*) built through the real TypeFactory interning
  // paths (getTypeChar type.cc:3681, getTypeStruct type.cc:3914,
  // getTypePointer type.hh:836).
  Datatype *chartype = arch.types->getTypeChar(1);
  Datatype *filestruct = arch.types->getTypeStruct("FILE");
  Datatype *charptr = arch.types->getTypePointer(arch.types->getSizeOfPointer(), chartype, 1);
  Datatype *fileptr = arch.types->getTypePointer(arch.types->getSizeOfPointer(), filestruct, 1);

  // CALLEE 1: default-matching locked signature.
  vector<Datatype *> intypes1;
  intypes1.push_back(charptr);
  intypes1.push_back(fileptr);
  vector<string> innames1;
  innames1.push_back("fixture_buf");
  innames1.push_back("fixture_fp");
  Funcdata *callee1 = build_locked_callee(arch, globalScope,
      Address(ram, 0x600000), "fixture_callee_copy", charptr, intypes1, innames1);
  cout << "CALLEE_LOCKED|" << callee1->getFuncProto().numParams()
       << "|" << (callee1->getFuncProto().isInputLocked() ? 1 : 0)
       << "|" << (callee1->getFuncProto().isOutputLocked() ? 1 : 0)
       << "|" << (callee1->getFuncProto().isModelLocked() ? 1 : 0)
       << "|" << callee1->getFuncProto().getModelName() << "\n";

  // CALLEE 2: model-locked on a foreign model (MSABI), so the copied
  // callsite must keep it (cc:2325 isModelLocked gate).
  vector<Datatype *> intypes2;
  intypes2.push_back(charptr);
  vector<string> innames2;
  innames2.push_back("fixture_only");
  Funcdata *callee2 = build_locked_callee(arch, globalScope,
      Address(ram, 0x600100), "fixture_callee_msabi", charptr, intypes2, innames2);
  map<string,ProtoModel *>::const_iterator msabi = arch.protoModels.find("MSABI");
  if (msabi == arch.protoModels.end())
    throw runtime_error("MSABI model missing from x86-64-gcc.cspec");
  callee2->getFuncProto().setModel(msabi->second);

  // CALLER: a Funcdata with two CALLIND call sites in the flow.cc:723 shape.
  FunctionSymbol *callersym = globalScope->addFunction(Address(ram, 0x601000), "fixture_caller");
  Funcdata *caller = callersym->getFunction();

  PcodeOp *op1 = caller->newOp(1, Address(ram, 0x601100));
  caller->opSetOpcode(op1, CPUI_CALLIND);
  FuncCallSpecs fc1(op1);
  // flow.cc:646-666 queryCall slice: the direct target resolved to callee1.
  fc1.setFuncdata(callee1);

  PcodeOp *op2 = caller->newOp(1, Address(ram, 0x601200));
  caller->opSetOpcode(op2, CPUI_CALLIND);
  FuncCallSpecs fc2(op2);
  fc2.setFuncdata(callee2);

  PcodeOp *op3 = caller->newOp(1, Address(ram, 0x601300));
  caller->opSetOpcode(op3, CPUI_CALLIND);
  FuncCallSpecs fc3(op3);			// no callee: setInternal arm

  // The ActionDefaultParams arm per call site (the loop iterates qlst in the
  // oracle; the arm body is what is under test, run here on each site).
  ProtoModel *evalfp = arch.evalfp_called;
  if (evalfp == (ProtoModel *)0)
    evalfp = arch.defaultfp;
  {
    FuncCallSpecs *sites[3] = { &fc1, &fc2, &fc3 };
    for(int4 i=0;i<3;++i) {
      FuncCallSpecs *fc = sites[i];
      if (!fc->hasModel()) {
        Funcdata *otherfunc = fc->getFuncdata();
        if (otherfunc != (Funcdata *)0) {
          fc->copy(otherfunc->getFuncProto());
          if ((!fc->isModelLocked())&& !fc->hasMatchingModel(evalfp))
            fc->setModel(evalfp);
        }
        else
          fc->setInternal(evalfp,arch.types->getTypeVoid());
      }
    }
  }

  print_callsite_state("COPY", fc1, arch);
  print_callsite_state("COPY_LOCKEDMISMATCH", fc2, arch);
  print_callsite_state("NOFUNC", fc3, arch);

  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: callspec_copy_1204 <specdir> <binary>\n";
    return 2;
  }
  const string specDirectory = argv[1];
  const string binary = argv[2];
  struct stat buf;
  if (stat(specDirectory.c_str(), &buf) < 0 || !S_ISDIR(buf.st_mode)) {
    cerr << "spec directory does not exist: " << specDirectory << "\n";
    return 2;
  }
  try {
    runFixture(specDirectory, binary);
  }
  catch (const LowlevelError &e) {
    cerr << "fixture failed: " << e.explain << "\n";
    return 1;
  }
  catch (const exception &e) {
    cerr << "fixture failed: " << e.what() << "\n";
    return 1;
  }
  catch (...) {
    cerr << "fixture failed: unknown error\n";
    return 1;
  }
  return 0;
}
