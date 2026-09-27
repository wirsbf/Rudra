// PRINTC-PRINTLIST-WIRING-0001 fixture — the option-to-printer wiring hop
// (OptionCommentStyle::apply -> glb->print->setCommentStyle), the
// architecture printlist structure (architecture.hh:205-206), and the
// emitter half of the resetDefaults chain (printlanguage.cc:674 ->
// EmitPrettyPrint::resetDefaults, prettyprint.cc:1237-1242) against locked
// Ghidra 12.0.4.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Coverage (bilateral, production bodies linked unchanged):
//   OptionCommentStyle::apply      (options.cc:523-527) — the route to the
//                                  architecture's current printer for
//                                  c/cplusplus/"/*"-sample/"//"-sample and
//                                  the LowlevelError rejection.
//   PrintC::setCommentStyle        (printc.cc:2350-2361) — reached through
//                                  the option, observed via emitLineComment.
//   Architecture printlist         (architecture.hh:205-206, ctor push at
//                                  architecture.cc:171-172) — the ctor-built
//                                  default printer is list element 0 and
//                                  the current printer.
//   Architecture::resetDefaults    (architecture.cc:1438-1445) — the
//                                  printlist loop resets every printer:
//                                  comment style back to C and the pretty
//                                  emitter's max line size back to 100.
//   EmitPrettyPrint::resetDefaults (prettyprint.cc:1237-1242) — the emitter
//                                  half of PrintLanguage::resetDefaults
//                                  (printlanguage.cc:674).
//
// The minimal Architecture subclass stubs the pure virtuals the option path
// never calls (same shape as the OPTIONS-SPLITDATATYPE-WIRING-0002
// fixture); the synthetic allacts root keeps the allacts half of
// Architecture::resetDefaults (architecture.cc:1442) from aborting on the
// missing "decompile" root.
#include <bits/stdc++.h>
#define class struct
#define private public
#define protected public
#include "architecture.hh"
#include "options.hh"
#include "comment.hh"
#undef class
#undef private
#undef protected

using namespace ghidra;
using std::cout;
using std::runtime_error;

// The inherited flags word carries this leaf's construction ordinal (a
// monotonically increasing counter) solely as an allocator-independent
// identity channel (same convention as OPTIONS-SPLITDATATYPE-WIRING-0002).
static int next_script_ordinal = 100;

class ScriptAction final : public Action {
public:
  ScriptAction(const string &g, const string &nm)
      : Action((uint4)next_script_ordinal++, nm, g) {}

  Action *clone(const ActionGroupList &grouplist) const override {
    if (!grouplist.contains(getGroup()))
      return (Action *)0;
    return new ScriptAction(getGroup(), getName());
  }

  int4 apply(Funcdata &) override { return 0; }
};

class TestArch : public Architecture {
public:
  TestArch(void) : Architecture() {}
  virtual ~TestArch(void) {}

  void printMessage(const string &message) const override {
    (void)message;
  }
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
};

// Render one line comment through the architecture's current printer, the
// same production path the singleton family's renderComment uses
// (setOutputStream + emitLineComment + flush).
static string render(TestArch &arch) {
  std::ostringstream hold;
  arch.print->setOutputStream(&hold);
  Address addr;
  Comment comm(Comment::user2, addr, addr, 0, "fixture body");
  arch.print->emitLineComment(0, &comm);
  arch.print->emit->flush();
  return hold.str();
}

int main(void) {
  // ghidra_process.cc:523 registers the linked capabilities (the C print
  // language) before any Architecture construction — the ctor's
  // buildLanguage (architecture.cc:171) picks PrintC from it.
  CapabilityPoint::initializeAll();

  TestArch arch;

  // Minimal synthetic allacts root so Architecture::resetDefaults'
  // allacts.resetDefaults() (architecture.cc:1442) finds the "decompile"
  // root it rederives.
  ActionRestartGroup *universal =
      new ActionRestartGroup(Action::rule_onceperfunc, "universal", 1);
  universal->addAction(new ScriptAction("base", "start"));
  arch.allacts.registerAction("universal", universal);
  const char *decompile_members[] = {"base", (const char *)0};
  arch.allacts.setGroup("decompile", decompile_members);
  arch.allacts.setCurrent("decompile");

  // architecture.cc:171-172: the ctor built the default printer and pushed
  // it; print points at it.
  cout << "case=structure|count=" << arch.printlist.size()
       << "|name=" << arch.print->getName() << '\n';

  // ---- the option route (options.cc:523-527) ----
  struct Route {
    const char *tag;
    const char *style;
  };
  const Route routes[] = {
      {"cplusplus", "cplusplus"},
      {"c", "c"},
      {"blockslash", "/*custom"},
      {"lineslash", "//custom"},
      {"bad", "badstyle"},
  };
  OptionCommentStyle option;
  for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) {
    bool threw = false;
    string msg;
    try {
      msg = option.apply(&arch, routes[i].style, "", "");
    } catch (const LowlevelError &e) {
      threw = true;
      msg = e.explain;
    }
    cout << "case=route." << routes[i].tag << "|threw=" << (threw ? 1 : 0)
         << "|msg=" << msg << "|text=" << render(arch) << '\n';
  }

  // ---- the emitter half of resetDefaults (prettyprint.cc:1237-1242) ----
  // Mutate the pretty emitter's max line size off its default, flip the
  // style off default, then run the full Architecture::resetDefaults —
  // the printlist loop must restore both (comment style via
  // PrintC::resetDefaults -> resetDefaultsPrintC -> setCStyleComments,
  // width via EmitPrettyPrint::resetDefaults -> setMaxLineSize(100)).
  arch.print->emit->setMaxLineSize(60);
  option.apply(&arch, "cplusplus", "", "");
  cout << "case=emit.before|width=" << arch.print->emit->getMaxLineSize()
       << "|text=" << render(arch) << '\n';
  arch.resetDefaults();
  cout << "case=reset|count=" << arch.printlist.size()
       << "|width=" << arch.print->emit->getMaxLineSize()
       << "|text=" << render(arch) << '\n';
  return 0;
}
