/*
 * Locked Ghidra 12.0.4 ScopeLocal::decodeWrappingAttributes oracle for
 * VARMAP-DECODEWRAP-0001 (handed over from MIGW1-DATABASE-0005 phase 3,
 * ruling R5).
 *
 * varmap.cc:479-486 — the ONLY override of the base-class no-op
 * Scope::decodeWrappingAttributes (database.hh:719):
 *
 *   rangeLocked = false;
 *   if (decoder.readBool(ATTRIB_LOCK))
 *     rangeLocked = true;
 *   space = decoder.readSpace(ATTRIB_MAIN);
 *
 * The call point under test is the production one: Database::decodeScope
 * (database.cc:3375-3393) invokes newScope->decodeWrappingAttributes at
 * database.cc:3385 when the opened element is not <scope> — the <localdb>
 * transport of Funcdata::decode (funcdata.cc:804-810) — BEFORE the <scope>
 * child is opened (database.hh:714-718). Each case therefore drives a real
 * ScopeLocal through symboltab->decodeScope over an XML <localdb> wrapper
 * carrying a <scope><parent id="257"/></scope> child (the harness global
 * scope id), exactly the shape ScopeLocal::encode writes (varmap.cc:462-470).
 *
 * Cases:
 *
 *   decode_lock_true    main="stack" lock="true": locked=1, space=stack.
 *   decode_lock_false   main="stack" lock="false": the unconditional
 *                       rangeLocked=false (varmap.cc:482) clears a stale
 *                       lock; locked=0, space=stack.
 *   decode_lock_one     main="stack" lock="1": xml_readbool's first-char
 *                       parse (xml.hh:391-396) → locked=1.
 *   decode_lock_yes     main="stack" lock="yes": xml_readbool's legacy
 *                       first-char 'y' arm (xml.hh:398, "For backward
 *                       compatibility") → locked=1 — MARSHAL-READBOOL-0001
 *                       arm 1 (oracle true).
 *   decode_lock_truecap main="stack" lock="True": the first-char parse is
 *                       case-sensitive — 'T' is not 't' (xml.hh:396) →
 *                       locked=0 — MARSHAL-READBOOL-0001 arm 2 (oracle
 *                       false).
 *   decode_main_ram     main="ram" lock="true": the space is REASSIGNED
 *                       from the constructor's stack to ram.
 *   decode_main_other   main="other" lock="true": a non-canonical space
 *                       name resolves through the manager (the Rust
 *                       value model's Other(index) fallback arm; the
 *                       oracle observation is getName()=="other").
 *   decode_main_unknown main="nosuch": DecoderError
 *                       "Unknown address space name: nosuch" (marshal.cc:421).
 *   decode_main_missing no main attribute: DecoderError
 *                       "Attribute missing: main" (marshal.cc:275 via
 *                       findMatchingAttribute).
 *   decode_lock_missing no lock attribute: readBool(ATTRIB_LOCK) runs
 *                       BEFORE the main read (varmap.cc:483), so
 *                       findMatchingAttribute throws on the lock first —
 *                       DecoderError "Attribute missing: lock"
 *                       (marshal.cc:275-276) — MARSHAL-READBOOL-0001
 *                       arm 3, aborted before the (present, resolvable)
 *                       main read.
 *   reset_locked        lock="true" decode, sentinel min/max param offsets
 *                       + flipped stackGrowsNegative, then resetLocalWindow:
 *                       the cc:435-437 refresh still runs (min=~0, max=0,
 *                       growneg=1) but the cc:439 guard skips the union
 *                       install — the (empty) window survives.
 *   reset_unlocked      lock="false" decode + the same sentinel state +
 *                       resetLocalWindow: the default union installs
 *                       ([0,0x1ff] ∪ [0xfffffffffff0bdc0,0xffffffffffffffff]
 *                       in RangeList tree order, ascending by first).
 */

#include <bits/stdc++.h>

// Test-only access is required to read ScopeLocal::rangeLocked / space /
// minParamOffset / maxParamOffset / stackGrowsNegative — members that are
// private BY CLASS DEFAULT (no explicit label), so `#define private
// public` alone cannot reach them. `class` -> `struct` flips the default
// access for every locked-oracle class parsed below; the decompile tree
// uses no `template<class ...>`/`enum class`/elaborated-class constructs
// the substitution would break, and the Rust comparand exposes the same
// fields publicly on its value-model ScopeLocal.
#define class struct
#define private public
#define protected public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varmap.hh"
#include "varnode.hh"
#undef protected
#undef private
#undef class

using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8, 1,
                                   3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false, 8,
                                   1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this, this, "stack", 5, 8, ram, 1,
                                               true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(4);
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override {
    return (PcodeInjectLibrary *)0;
  }
  void buildTypegrp(DocumentStorage &) override {}
  void buildCoreTypes(DocumentStorage &) override {}
  void buildCommentDB(DocumentStorage &) override {}
  void buildStringManager(DocumentStorage &) override {}
  void buildConstantPool(DocumentStorage &) override {}
  void buildContext(DocumentStorage &) override {}
  void buildSymbols(DocumentStorage &) override {}
  void buildSpecFile(DocumentStorage &) override {}
  void modifySpaces(Translate *) override {}
  void resolveArchitecture(void) override {}

public:
  FixtureArchitecture() {
    FixtureTranslate *fixture_translate = new FixtureTranslate();
    translate = fixture_translate;
    copySpaces(fixture_translate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("int", 4, TYPE_INT, false);
    types->setCoreType("long", 8, TYPE_INT, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"dw_default\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

/// Render a RangeList as `first-last` hex pairs, ';'-joined, in tree order.
static std::string ranges_text(const RangeList &rlist) {
  std::ostringstream out;
  bool first = true;
  set<Range>::const_iterator iter;
  for (iter = rlist.begin(); iter != rlist.end(); ++iter) {
    if (!first) out << ';';
    first = false;
    out << hex << (*iter).getFirst() << '-' << (*iter).getLast();
  }
  return out.str();
}

/// One decode case: a fresh Funcdata + ScopeLocal (constructor default
/// space = stack), decoded through the PRODUCTION call point
/// Database::decodeScope (database.cc:3375) over the given <localdb> XML.
/// Returns the observation line body: `locked=..|space=..` on success or
/// `err=..` on the oracle's DecoderError channels.
struct DecodeCaseResult {
  std::string body;
  ScopeLocal *scope;
  Funcdata *fd;
};

static DecodeCaseResult run_decode_case(FixtureArchitecture &arch,
                                        const std::string &name,
                                        const std::string &xml,
                                        uint8 scope_id, uintb fd_off) {
  AddrSpace *ram = arch.getSpace(3);
  Funcdata *fd = new Funcdata(name, name, arch.symboltab->getGlobalScope(),
                              Address(ram, fd_off), (FunctionSymbol *)0, 0x20);
  fd->getFuncProto().setModel(arch.protoModels["dw_default"]);
  ScopeLocal *lm = new ScopeLocal(scope_id, arch.getSpace(5), fd, &arch);
  DecodeCaseResult result;
  result.scope = lm;
  result.fd = fd;
  try {
    std::istringstream stream(xml);
    XmlDecode decoder(&arch);
    decoder.ingestStream(stream);
    arch.symboltab->decodeScope(decoder, lm);
    ostringstream out;
    out << "locked=" << (lm->rangeLocked ? 1 : 0)
        << "|space=" << lm->space->getName();
    result.body = out.str();
  }
  catch (const DecoderError &error) {
    result.body = std::string("err=") + error.explain;
  }
  return result;
}

} // anonymous namespace

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=VARMAP-DECODEWRAP-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    // The minimal well-formed <scope> the production transport carries:
    // a <parent> (parseParentTag, database.cc:3300) and the <symbollist>
    // ScopeInternal::decode REQUIRES (database.cc:2766 —
    // openElement(ELEM_SYMBOLLIST) throws "Expecting <symbollist>" on an
    // exhausted child list, so ScopeLocal::encode's always-present
    // symbollist is part of the shape).
    const std::string scope_child = "<scope><parent id=\"257\"/><symbollist/></scope>";

    // decode_lock_true: lock="true" main="stack".
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_lock_true",
          "<localdb main=\"stack\" lock=\"true\">" + scope_child + "</localdb>",
          0x102, 0x9000);
      std::cout << "case=decode_lock_true|" << r.body << '\n';
    }
    // decode_lock_false: the unconditional reset clears a stale lock — the
    // previous case's scope had locked=1, this decode's scope starts
    // fresh (ctor varmap.cc:347) and stays unlocked.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_lock_false",
          "<localdb main=\"stack\" lock=\"false\">" + scope_child + "</localdb>",
          0x103, 0x9020);
      std::cout << "case=decode_lock_false|" << r.body << '\n';
    }
    // decode_lock_one: xml_readbool first-char parse (xml.hh:391-396).
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_lock_one",
          "<localdb main=\"stack\" lock=\"1\">" + scope_child + "</localdb>",
          0x104, 0x9040);
      std::cout << "case=decode_lock_one|" << r.body << '\n';
    }
    // decode_lock_yes: xml_readbool's legacy first-char 'y' arm
    // (xml.hh:398 — "For backward compatibility"); MARSHAL-READBOOL-0001.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_lock_yes",
          "<localdb main=\"stack\" lock=\"yes\">" + scope_child + "</localdb>",
          0x10b, 0x9120);
      std::cout << "case=decode_lock_yes|" << r.body << '\n';
    }
    // decode_lock_truecap: the first-char parse is case-sensitive — 'T'
    // is not 't' (xml.hh:396), so the lock stays off.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_lock_truecap",
          "<localdb main=\"stack\" lock=\"True\">" + scope_child + "</localdb>",
          0x10c, 0x9140);
      std::cout << "case=decode_lock_truecap|" << r.body << '\n';
    }
    // decode_main_ram: the space is reassigned away from the ctor stack.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_main_ram",
          "<localdb main=\"ram\" lock=\"true\">" + scope_child + "</localdb>",
          0x105, 0x9060);
      std::cout << "case=decode_main_ram|" << r.body << '\n';
    }
    // decode_main_other: a non-canonical space name resolves through the
    // manager and re-points the scope space (the Rust value model's
    // Other(index) fallback arm).
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_main_other",
          "<localdb main=\"other\" lock=\"true\">" + scope_child + "</localdb>",
          0x10a, 0x9100);
      std::cout << "case=decode_main_other|" << r.body << '\n';
    }
    // decode_main_unknown: the manager lookup rejects unknown names.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_main_unknown",
          "<localdb main=\"nosuch\" lock=\"true\">" + scope_child + "</localdb>",
          0x106, 0x9080);
      std::cout << "case=decode_main_unknown|" << r.body << '\n';
    }
    // decode_main_missing: findMatchingAttribute throws.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_main_missing",
          "<localdb lock=\"true\">" + scope_child + "</localdb>",
          0x107, 0x90a0);
      std::cout << "case=decode_main_missing|" << r.body << '\n';
    }
    // decode_lock_missing: readBool(ATTRIB_LOCK) runs BEFORE the main
    // read (varmap.cc:483), so findMatchingAttribute throws on the lock
    // first (marshal.cc:275-276) — even though main is present and
    // resolvable; MARSHAL-READBOOL-0001.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "decode_lock_missing",
          "<localdb main=\"stack\">" + scope_child + "</localdb>",
          0x10d, 0x9160);
      std::cout << "case=decode_lock_missing|" << r.body << '\n';
    }
    // reset_locked: cc:435-437 refresh runs, cc:439 guard skips the
    // window install.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "reset_locked",
          "<localdb main=\"stack\" lock=\"true\">" + scope_child + "</localdb>",
          0x108, 0x90c0);
      r.scope->minParamOffset = 0x10;
      r.scope->maxParamOffset = 0x20;
      r.scope->stackGrowsNegative = false;
      r.scope->resetLocalWindow();
      std::cout << "case=reset_locked|locked=" << (r.scope->rangeLocked ? 1 : 0)
                << "|union=" << ranges_text(r.scope->getRangeTree())
                << "|min=" << hex << r.scope->minParamOffset
                << "|max=" << r.scope->maxParamOffset
                << "|growneg=" << (r.scope->stackGrowsNegative ? 1 : 0) << '\n';
    }
    // reset_unlocked: the default union installs.
    {
      DecodeCaseResult r = run_decode_case(
          arch, "reset_unlocked",
          "<localdb main=\"stack\" lock=\"false\">" + scope_child + "</localdb>",
          0x109, 0x90e0);
      r.scope->minParamOffset = 0x10;
      r.scope->maxParamOffset = 0x20;
      r.scope->stackGrowsNegative = false;
      r.scope->resetLocalWindow();
      std::cout << "case=reset_unlocked|locked=" << (r.scope->rangeLocked ? 1 : 0)
                << "|union=" << ranges_text(r.scope->getRangeTree())
                << "|min=" << hex << r.scope->minParamOffset
                << "|max=" << r.scope->maxParamOffset
                << "|growneg=" << (r.scope->stackGrowsNegative ? 1 : 0) << '\n';
    }
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
