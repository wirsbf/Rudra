/*
 * PARSEADJ-PARSEFACE-PCODE-0001: locked Ghidra 12.0.4 oracle projection for
 * the pcode-snippet parser whole face (the "generator absorbed" equivalence
 * unit for pcodeparse.cc's bison yyparse + yy* skeleton and its handwritten
 * PcodeLexer / PcodeSnippet members, GENERATOR_ABSORBED_2026-09-27.md §3/§4).
 *
 * The fixture boots a bare SLEIGH engine on the production x86-64.sla (the
 * same `const SleighBase *` handle PcodeInjectLibrarySleigh::parseInject
 * hands to PcodeSnippet, inject_sleigh.cc:387) and drives the unmodified
 * snippet compiler through its public surface — PcodeSnippet ctor seeding,
 * parseStream, setUniqueBase/getUniqueBase, clear, addOperand, hasErrors/
 * getErrorMessage, releaseResult — on a bounded case matrix of p-code
 * semantic strings.  Every case prints a stable record:
 *
 *   SCHEMA|1                        — version marker
 *   SYM|<name>|<facts>              — SleighBase::findSymbol probes fixing
 *                                     the language-side symbol universe the
 *                                     snippets resolve against
 *   SNIP|<id>|OK|<xml>              — compiled ConstructTpl through
 *                                     ConstructTpl::encode(encoder,-1), the
 *                                     exact encoding InjectPayloadSleigh::
 *                                     printTemplate uses
 *   SNIP|<id>|ERR|<firsterror>      — parse failure: PcodeSnippet's first
 *                                     reported error text (yyparse aborts on
 *                                     the first error; reportError keeps the
 *                                     first message only)
 *   SNIP|<id>|EXC|<explain>         — SleighError escaping parseStream
 *                                     (buildTruncatedVarnode throws,
 *                                     pcodecompile.cc:580 — parseStream has
 *                                     no handler, matching production)
 *   LF|<id>|<observation>           — direct lifecycle member probes
 *   DONE                            — terminal marker
 *
 * The case matrix deliberately probes the face dimensions the whole-parser
 * equivalence unit must reproduce: the lexer state machine (comments,
 * s/f-prefix two/three-char operators, hex/dec strings, overflow →
 * BADINTEGER, illegal characters → stream end), the statement forms
 * (assignments, local declarations with/without size, stores, userop calls,
 * bitrange assignments, goto/if/call/return, labels), the expression
 * operator set with Bison's precedence and the swapped-operand semantic
 * actions (a > b → INT_LESS(b,a), f> → FLOAT_LESS swapped, ...), the
 * constructor's address-space seeding (x86-64.sla spaces const/OTHER/
 * unique/ram/register — NO stack, NO iop), error-text actions, size
 * propagation (fillinZero/propagateSize incl. force_size local-temp
 * sharing), and the lifecycle members (allocateTemp via unique offsets,
 * addSymbol duplicates, clear semantics, addOperand handles).
 */

#include "loadimage.hh"
#include "marshal.hh"
#include "pcodeparse.hh"
#include "sleigh.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::istringstream;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

// A LoadImage that answers every fetch with zeros; snippet compilation
// never fetches instruction bytes (the PcodeSnippet constructor at
// pcodeparse.y:676-696 only reads the symbol/space tables).
class ZeroLoadImage : public LoadImage {
public:
  ZeroLoadImage(void) : LoadImage("pcode_face_zero") {}
  virtual void loadFill(unsigned char *ptr, int4 size, const Address &addr)
  {
    for (int4 i = 0; i < size; ++i)
      ptr[i] = 0;
  }
  virtual string getArchType(void) const { return "pcode-face"; }
  virtual void adjustVma(long) {}
};

string escapeNewlines(const string &value)
{
  string out;
  for (string::const_iterator iter = value.begin(); iter != value.end(); ++iter) {
    if (*iter == '\n')
      out += "\\n";
    else
      out += *iter;
  }
  return out;
}

// Compile one snippet with a fresh PcodeSnippet (the
// PcodeInjectLibrarySleigh::parseInject lifecycle: fresh compiler, default
// tempbase, one parseStream call) and print the result record.  SleighError
// escapes parseStream in production (no catch between yyparse and the
// payload compiler); the fixture mirrors that by catching it here and
// printing the EXC channel.
void runSnippet(const SleighBase *slgh, const char *id, const string &snippet)
{
  PcodeSnippet compiler(slgh);
  istringstream stream(snippet);
  try {
    bool ok = compiler.parseStream(stream);
    if (!ok || compiler.hasErrors()) {
      cout << "SNIP|" << id << "|ERR|" << escapeNewlines(compiler.getErrorMessage())
           << "\n";
      return;
    }
    ConstructTpl *tpl = compiler.releaseResult();
    if (tpl == (ConstructTpl *)0) {
      cout << "SNIP|" << id << "|ERR|no result\n";
      return;
    }
    ostringstream buffer;
    XmlEncode encoder(buffer);
    tpl->encode(encoder, -1);
    delete tpl;
    cout << "SNIP|" << id << "|OK|" << escapeNewlines(buffer.str()) << "\n";
  }
  catch(const SleighError &err) {
    cout << "SNIP|" << id << "|EXC|" << escapeNewlines(err.explain) << "\n";
  }
}

void runFixture(const string &specDirectory)
{
  const string slaPath = specDirectory + "/x86-64.sla";
  ZeroLoadImage loader;
  ContextInternal contextDatabase;
  Sleigh engine(&loader, &contextDatabase);
  DocumentStorage store;
  // SleighArchitecture::buildSpecFile (sleigh_arch.cc:412-417): the .sla is
  // registered as a synthetic <sleigh>path</sleigh> tag; Sleigh::initialize
  // (sleigh.cc:558-568) then streams the binary file through
  // sla::FormatDecode.
  istringstream sleighTag("<sleigh>" + slaPath + "</sleigh>");
  Document *doc = store.parseDocument(sleighTag);
  store.registerTag(doc->getRoot());
  engine.initialize(store);

  cout << "SCHEMA|1\n";

  // --- SYM: language-side findSymbol probes (pcodeparse.cc:3223 fallback) --
  // symbol_type ordinals follow slghsymbol.hh:28-32.  VarnodeSymbol facts
  // print as space:offset:size (the VarnodeTpl getVarnode builds,
  // slghsymbol.cc VarnodeSymbol::getVarnode); UserOpSymbol prints its
  // index.  ram/OTHER/stack are ABSENT from the language table: the space
  // symbols live in the snippet-local tree seeded by the PcodeSnippet ctor
  // (pcodeparse.y:686-692) — their reachability is probed by the spNN
  // snippets below.
  const char *probeNames[] = {
    "RAX","EAX","AL","RCX","RDX","RBX","RSP","RBP","RSI","RDI","RIP","SF","ZF",
    "cpuid","inst_start","inst_next","inst_next2","ram","OTHER","stack",
  };
  const int probeCount = (int)(sizeof(probeNames) / sizeof(probeNames[0]));
  for (int i = 0; i < probeCount; ++i) {
    const SleighSymbol *sym = engine.findSymbol(probeNames[i]);
    if (sym == (const SleighSymbol *)0) {
      cout << "SYM|" << probeNames[i] << "|ABSENT\n";
      continue;
    }
    cout << "SYM|" << probeNames[i] << "|type=" << (int4)sym->getType();
    if (sym->getType() == SleighSymbol::varnode_symbol) {
      VarnodeTpl *vn = ((VarnodeSymbol *)sym)->getVarnode();
      cout << "|space=" << vn->getSpace().getSpace()->getName()
           << "|off=0x" << std::hex << vn->getOffset().getReal() << std::dec
           << "|size=" << vn->getSize().getReal();
      delete vn;
    }
    if (sym->getType() == SleighSymbol::userop_symbol)
      cout << "|index=" << (int4)((UserOpSymbol *)sym)->getIndex();
    cout << "\n";
  }

  // --- SNIP: address-space seeding face (PcodeSnippet ctor, y:686-692) ----
  // x86-64.sla spaces: const(IPTR_CONSTANT) OTHER/ram/register(IPTR_PROCESSOR)
  // unique(IPTR_INTERNAL) — all five seeded; stack/iop are NOT in the .sla
  // and NOT seeded.
  runSnippet((const SleighBase *)&engine,"sp01","*[ram]:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp02","*[register]:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp03","*[unique]:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp04","*[const]:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp05","*[OTHER]:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp06","*[stack]:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp07","*[iop]:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp08","*:8 RAX = RBX;");
  runSnippet((const SleighBase *)&engine,"sp09","local v:8 = *:8 RAX;");
  runSnippet((const SleighBase *)&engine,"sp10","local w:8 = * RAX;");

  // --- SNIP: statement forms (statement rule, y:106-125) ------------------
  runSnippet((const SleighBase *)&engine,"st01","RAX = RAX + 1;");
  runSnippet((const SleighBase *)&engine,"st02","local t = EAX;");
  runSnippet((const SleighBase *)&engine,"st03","local t:8 = 0x10;");
  runSnippet((const SleighBase *)&engine,"st04","q = RAX;");
  runSnippet((const SleighBase *)&engine,"st05","q:4 = 5;");
  runSnippet((const SleighBase *)&engine,"st06","local d:8 = inst_ref;");
  runSnippet((const SleighBase *)&engine,"st07","cpuid();");
  runSnippet((const SleighBase *)&engine,"st08","cpuid(RAX,RBX);");
  runSnippet((const SleighBase *)&engine,"st09","RAX[0,16] = RCX;");
  runSnippet((const SleighBase *)&engine,"st10","RAX[4,8] = 0x1;");
  runSnippet((const SleighBase *)&engine,"st11","RAX:4 = RAX;");
  runSnippet((const SleighBase *)&engine,"st12","RAX(2);");
  runSnippet((const SleighBase *)&engine,"st13","return;");
  runSnippet((const SleighBase *)&engine,"st14","return [RAX];");
  runSnippet((const SleighBase *)&engine,"st15","local RAX = 1;");
  runSnippet((const SleighBase *)&engine,"st16","goto 0x1000;");
  runSnippet((const SleighBase *)&engine,"st17","goto 0x1000[ram];");
  runSnippet((const SleighBase *)&engine,"st18","goto 0x20[register];");
  runSnippet((const SleighBase *)&engine,"st19","goto inst_next;");
  runSnippet((const SleighBase *)&engine,"st20","<lab> RAX = RBX; goto <lab>;");
  runSnippet((const SleighBase *)&engine,"st21","goto nosuch;");
  runSnippet((const SleighBase *)&engine,"st22","if (RAX == 0) goto 0x40;");
  runSnippet((const SleighBase *)&engine,"st23","call 0x1000;");
  runSnippet((const SleighBase *)&engine,"st24","call [RBX];");
  runSnippet((const SleighBase *)&engine,"st25","goto [RAX + 0x8];");
  runSnippet((const SleighBase *)&engine,"st26","local q:8 = 1; local q:4 = 2;");
  runSnippet((const SleighBase *)&engine,"st27","<a> RAX = 1; <a> RBX = 2;");
  runSnippet((const SleighBase *)&engine,"st28","zz;");
  runSnippet((const SleighBase *)&engine,"st29","RAX = zzz + 1;");
  runSnippet((const SleighBase *)&engine,"st30","RAX = = 1;");
  runSnippet((const SleighBase *)&engine,"st31","goto 18446744073709551616;");
  runSnippet((const SleighBase *)&engine,"st32","local t:8 = 0x10000000000000000;");
  runSnippet((const SleighBase *)&engine,"st33","local t = RAX f+ RBX;");
  runSnippet((const SleighBase *)&engine,"st34","RAX[0,0] = 1;");
  runSnippet((const SleighBase *)&engine,"st35","AL[0,16] = 1;");
  runSnippet((const SleighBase *)&engine,"st36","RAX[0,64] = RBX;");
  runSnippet((const SleighBase *)&engine,"st37","local t = RAX:8;");
  runSnippet((const SleighBase *)&engine,"st38","local t = AL[0,16];");
  runSnippet((const SleighBase *)&engine,"st39","local q; local r; q = r; r = RBX;");
  runSnippet((const SleighBase *)&engine,"st40","local q; RAX = q;");

  // --- SNIP: expression operator face (expr rule, y:126-189) --------------
  runSnippet((const SleighBase *)&engine,"ex01","local t:8 = RAX + RBX * 2 - RCX / 3 % 4;");
  runSnippet((const SleighBase *)&engine,"ex02","local t:8 = RAX - RBX - RCX;");
  runSnippet((const SleighBase *)&engine,"ex03","local t:8 = RAX - (RBX - RCX);");
  runSnippet((const SleighBase *)&engine,"ex04","local a:1 = RAX > RBX; local b:1 = RAX >= RBX;");
  runSnippet((const SleighBase *)&engine,"ex05","local a:1 = RAX s> RBX; local b:1 = RAX s>= RBX;");
  runSnippet((const SleighBase *)&engine,"ex06","local a:8 = RAX f+ RBX; local b:8 = RAX f- RBX; local c:8 = RAX f* RBX; local d:8 = RAX f/ RBX;");
  runSnippet((const SleighBase *)&engine,"ex07","local a:1 = RAX f> RBX; local b:1 = RAX f>= RBX; local c:1 = RAX f== RBX; local d:1 = RAX f!= RBX;");
  runSnippet((const SleighBase *)&engine,"ex08","local a:8 = -RAX; local b:8 = ~RAX; local c:1 = !(RAX == RBX); local d:8 = f- RAX;");
  runSnippet((const SleighBase *)&engine,"ex09","local a:1 = RAX && RBX; local b:1 = RAX || RBX; local c:1 = RAX ^^ RBX;");
  runSnippet((const SleighBase *)&engine,"ex10","local a:8 = RAX << RBX; local b:8 = RAX >> RBX; local c:8 = RAX s>> RBX;");
  runSnippet((const SleighBase *)&engine,"ex11","local a:8 = zext(EAX); local b:8 = sext(EAX); local c:1 = carry(RAX,RBX); local d:1 = scarry(RAX,RBX); local e:1 = sborrow(RAX,RBX);");
  runSnippet((const SleighBase *)&engine,"ex12","local a:8 = abs(RAX); local b:8 = sqrt(RAX); local c:8 = ceil(RAX); local d:8 = floor(RAX); local e:8 = round(RAX);");
  runSnippet((const SleighBase *)&engine,"ex13","local a:1 = nan(RAX); local b:8 = trunc(RAX); local c:8 = int2float(EAX); local d:8 = float2float(RAX);");
  runSnippet((const SleighBase *)&engine,"ex14","local t = EAX(1);");
  runSnippet((const SleighBase *)&engine,"ex15","local a = EAX:2; local b = RAX[0,16]; local c = EAX[4,4];");
  runSnippet((const SleighBase *)&engine,"ex16","local t:8 = cpuid(RAX);");
  runSnippet((const SleighBase *)&engine,"ex17","local p = &RAX; local q = &:8 RBX; local r = &inst_start;");
  runSnippet((const SleighBase *)&engine,"ex18","local t:4 = 0xdeadbeef:4;");
  runSnippet((const SleighBase *)&engine,"ex19","local v:8 = *[ram]:8 RAX + 0x8;");
  runSnippet((const SleighBase *)&engine,"ex20","local n:8 = new(RAX); local m:8 = new(RAX,RBX);");

  // --- SNIP: lexer face (moveState/getNextToken, y:297-606) ---------------
  runSnippet((const SleighBase *)&engine,"lx01","# lead comment\n\tRAX = RAX;\nRAX = RBX; # tail comment\n");
  runSnippet((const SleighBase *)&engine,"lx02","local a:1 = EAX s<= EAX; local b:1 = EAX s>= EAX; local c:8 = EAX s>> EAX; local d:1 = EAX f== EAX; local e:1 = EAX f!= EAX;");
  runSnippet((const SleighBase *)&engine,"lx03","local a_b.c:1 = 1; local size1:1 = 2; local floorx:1 = 3;");
  runSnippet((const SleighBase *)&engine,"lx04","local a:8 = 0xff + 255;");
  runSnippet((const SleighBase *)&engine,"lx05","local t:8 = 0xffffffffffffffff;");
  runSnippet((const SleighBase *)&engine,"lx06","RAX = RAX $ 1;");

  // --- LF: lifecycle member probes ----------------------------------------
  // lf1: setUniqueBase/getUniqueBase (pcodeparse.hh:92-93) and allocateTemp
  // (y:632) through the compiled offsets.
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    compiler.setUniqueBase(0x1234);
    cout << "LF|ub|" << std::hex << compiler.getUniqueBase() << std::dec << "\n";
    istringstream stream("local q:8 = 1;");
    bool ok = compiler.parseStream(stream);
    ConstructTpl *tpl = ok ? compiler.releaseResult() : (ConstructTpl *)0;
    if (tpl != (ConstructTpl *)0) {
      ostringstream buffer;
      XmlEncode encoder(buffer);
      tpl->encode(encoder, -1);
      delete tpl;
      cout << "LF|ubparse|OK|" << escapeNewlines(buffer.str()) << "\n";
    }
    else
      cout << "LF|ubparse|ERR|" << escapeNewlines(compiler.getErrorMessage()) << "\n";
  }
  // lf2: clear() drops non-space symbols (y:652-674) — the defined local q
  // becomes unknown after clear.
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    istringstream a("local q:8 = 1; q = q + 1;");
    bool oka = compiler.parseStream(a);
    cout << "LF|clr1|" << (oka && !compiler.hasErrors() ? "OK" : "ERR") << "\n";
    compiler.clear();
    istringstream b("q = q + 1;");
    compiler.parseStream(b);
    cout << "LF|clr2|" << escapeNewlines(compiler.getErrorMessage()) << "\n";
  }
  // lf3: clear() does NOT reset tempbase (y:670 commented-out reset) — the
  // second parse's local lands at offset 16.
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    istringstream a("local a:8 = 1;");
    compiler.parseStream(a);
    compiler.clear();
    istringstream b("local b:8 = 2;");
    bool ok = compiler.parseStream(b);
    ConstructTpl *tpl = ok ? compiler.releaseResult() : (ConstructTpl *)0;
    if (tpl != (ConstructTpl *)0) {
      ostringstream buffer;
      XmlEncode encoder(buffer);
      tpl->encode(encoder, -1);
      delete tpl;
      cout << "LF|clrtb|OK|" << escapeNewlines(buffer.str()) << "\n";
    }
    else
      cout << "LF|clrtb|ERR|" << escapeNewlines(compiler.getErrorMessage()) << "\n";
  }
  // lf4: clear() resets the label counter (resetLabelCount, y:673) — the
  // label index after clear starts from 0 again.
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    istringstream a("<x> goto <x>;");
    compiler.parseStream(a);
    compiler.clear();
    istringstream b("<y> goto <y>;");
    bool ok = compiler.parseStream(b);
    ConstructTpl *tpl = ok ? compiler.releaseResult() : (ConstructTpl *)0;
    if (tpl != (ConstructTpl *)0) {
      ostringstream buffer;
      XmlEncode encoder(buffer);
      tpl->encode(encoder, -1);
      delete tpl;
      cout << "LF|clrlbl|OK|" << escapeNewlines(buffer.str()) << "\n";
    }
    else
      cout << "LF|clrlbl|ERR|" << escapeNewlines(compiler.getErrorMessage()) << "\n";
  }
  // lf5: clear() resets the error state (y:671-672).
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    istringstream a("return;");
    compiler.parseStream(a);
    cout << "LF|clrerr1|" << escapeNewlines(compiler.getErrorMessage()) << "\n";
    compiler.clear();
    istringstream b("RAX = RAX;");
    bool okb = compiler.parseStream(b);
    cout << "LF|clrerr2|" << (okb && !compiler.hasErrors() ? "OK" : "ERR") << "\n";
  }
  // lf6: addSymbol duplicate detection (y:640-650) reached through the
  // public addOperand — "ram" collides with the ctor-seeded SpaceSymbol.
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    compiler.addOperand("ram", 0);
    cout << "LF|dup|" << (compiler.hasErrors() ? escapeNewlines(compiler.getErrorMessage()) : string("noerr")) << "\n";
    compiler.clear();
    istringstream b("RAX = RBX;");
    bool okb = compiler.parseStream(b);
    cout << "LF|duprec|" << (okb && !compiler.hasErrors() ? "OK" : "ERR") << "\n";
  }
  // lf7: addOperand handles (y:787-792) — operand symbols feed the
  // OPERANDSYM varnode/handle forms.
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    compiler.addOperand("in0", 0);
    compiler.addOperand("in1", 1);
    istringstream stream("local o:8 = in0 + in1; local p:4 = in0(2);");
    bool ok = compiler.parseStream(stream);
    ConstructTpl *tpl = ok ? compiler.releaseResult() : (ConstructTpl *)0;
    if (tpl != (ConstructTpl *)0) {
      ostringstream buffer;
      XmlEncode encoder(buffer);
      tpl->encode(encoder, -1);
      delete tpl;
      cout << "LF|ops|OK|" << escapeNewlines(buffer.str()) << "\n";
    }
    else
      cout << "LF|ops|ERR|" << escapeNewlines(compiler.getErrorMessage()) << "\n";
  }
  // lf8: releaseResult ownership (pcodeparse.hh:85) — the second release
  // returns null.
  {
    PcodeSnippet compiler((const SleighBase *)&engine);
    istringstream stream("RAX = RBX;");
    compiler.parseStream(stream);
    ConstructTpl *first = compiler.releaseResult();
    delete first;
    ConstructTpl *second = compiler.releaseResult();
    cout << "LF|release2|" << (second == (ConstructTpl *)0 ? "null" : "some") << "\n";
  }

  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 2) {
    cerr << "usage: pcode_snippet_face_1204 <specdir>\n";
    return 2;
  }
  try {
    runFixture(argv[1]);
  }
  catch(const LowlevelError &err) {
    cerr << "pcode_snippet_face_1204: LowlevelError: " << err.explain << "\n";
    return 1;
  }
  catch(const exception &error) {
    cerr << "pcode_snippet_face_1204: " << error.what() << "\n";
    return 1;
  }
  catch(...) {
    cerr << "pcode_snippet_face_1204: unknown exception\n";
    return 1;
  }
  return 0;
}
