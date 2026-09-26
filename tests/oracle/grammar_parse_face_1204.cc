/*
 * WORKPKG-UNMAP-PARSEADJ-0015: locked Ghidra 12.0.4 oracle projection for the
 * C-declaration parser whole face (the "generator absorbed" equivalence
 * unit for grammar.cc's bison yyparse + yy* skeleton).
 *
 * The fixture drives the unmodified bison-backed CParse through the same
 * public entry points the decompiler pipeline uses — parse_type
 * (grammar.cc:3112, doc_parameter_declaration) and parse_protopieces
 * (grammar.cc:3131, doc_declaration) — on a bounded input set of C type
 * strings / DWARF-style declaration strings built from the C++ core type
 * names (int4/uint8/char/float8/...). For every case it prints a stable
 * key=value record of the parse tree face: the built type's printRaw form,
 * metatype, and size for parse_type; the PrototypePieces (out type, model
 * name, prototype name, input types, first varargs slot) or the exact
 * ParseError text for parse_protopieces. The Rugra twin must print the
 * identical stream.
 *
 * Cases deliberately probe the bison reduction order that the recursive
 * descent driver must reproduce: pointer modifiers append AFTER the
 * direct-declarator suffixes (grammar.y:153 -> mergePointer), grouping
 * '(' declarator ')' shares the inner TypeDeclarator (grammar.y:158),
 * the lone-(void) parameter clearing (FunctionModifier ctor
 * grammar.cc:2423-2430), the varargs trailer slot (grammar.y:180 +
 * getPrototype grammar.cc:2534), and the extra-void-parameter rejection
 * (FunctionModifier::isValid grammar.cc:2450-2462).
 */
#include "bfd_arch.hh"
#include "grammar.hh"
#include "libdecomp.hh"
#include "type.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using namespace std;

void emitTypeFields(const string &tag,const Datatype *ct)

{
  if (ct == (const Datatype *)0) {
    cout << tag << ".type=NONE" << '\n';
    return;
  }
  ostringstream stream;
  ct->printRaw(stream);
  cout << tag << ".type=" << stream.str() << '\n';
  cout << tag << ".meta=" << static_cast<int4>(ct->getMetatype()) << '\n';
  cout << tag << ".size=" << dec << ct->getSize() << '\n';
}

void runParseType(const string &id,const char *text,Architecture *glb)

{
  const string tag = "case." + id;
  istringstream in(text);
  string name;
  try {
    Datatype *ct = parse_type(in,name,glb);
    cout << tag << ".name=" << (name.empty() ? string("<none>") : name) << '\n';
    emitTypeFields(tag,ct);
  }
  catch(const ParseError &err) {
    cout << tag << ".error=" << err.explain << '\n';
  }
}

void runParseProtopieces(const string &id,const char *text,Architecture *glb)

{
  const string tag = "case." + id;
  istringstream in(text);
  PrototypePieces pieces;
  try {
    parse_protopieces(pieces,in,glb);
    emitTypeFields(tag + ".out",pieces.outtype);
    cout << tag << ".model=" << (pieces.model != (ProtoModel *)0 ? pieces.model->getName() : string("<null>")) << '\n';
    cout << tag << ".pname=" << (pieces.name.empty() ? string("<none>") : pieces.name) << '\n';
    cout << tag << ".intypes=" << dec << pieces.intypes.size() << '\n';
    for(uint4 i=0;i<pieces.intypes.size();++i) {
      ostringstream stream;
      if (pieces.intypes[i] != (Datatype *)0)
	pieces.intypes[i]->printRaw(stream);
      else
	stream << "NONE";
      cout << tag << ".intype" << dec << i << '=' << stream.str() << '\n';
    }
    cout << tag << ".vararg=" << dec << pieces.firstVarArgSlot << '\n';
  }
  catch(const ParseError &err) {
    cout << tag << ".error=" << err.explain << '\n';
  }
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths(1,specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&cerr);
  DocumentStorage store;
  architecture.init(store);
  if (architecture.archid != "x86:LE:64:default:gcc")
    throw runtime_error("runtime architecture/compiler drifted: " + architecture.archid);

  // parse_type face (doc_parameter_declaration).
  runParseType("pt01","int4 x",&architecture);
  runParseType("pt02","uint8 *",&architecture);
  runParseType("pt03","char **x",&architecture);
  runParseType("pt04","float8 x",&architecture);
  runParseType("pt05","int4 x[5]",&architecture);
  runParseType("pt06","int4 *x[3]",&architecture);	// array-of-pointer order probe
  runParseType("pt07","int4 (*x)[3]",&architecture);	// grouping probe
  runParseType("pt08","int4 (*)(int4, int8)",&architecture);	// group+suffix probe
  runParseType("pt09","struct pair { int4 lo ; int4 hi ; }",&architecture);	// struct definition
  runParseType("pt10","int4",&architecture);		// specifiers-only abstract

  // parse_protopieces face (doc_declaration).
  runParseProtopieces("pp01","int4 f(int4, char *);",&architecture);
  runParseProtopieces("pp02","uint8 f(void);",&architecture);		// lone-(void) clearing
  runParseProtopieces("pp03","int4 f(int4, ...);",&architecture);	// varargs slot
  runParseProtopieces("pp04","char *strcpy(char *, const char *);",&architecture);	// qualified abstract params
  runParseProtopieces("pp05","void f(int4);",&architecture);
  runParseProtopieces("pp06","int4 (*fptr)(uint4, int8);",&architecture);	// not a prototype (mods[0]=pointer)
  runParseProtopieces("pp07","uint8 f(void, int4);",&architecture);	// extra void parameter
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument("usage: grammar_parse_face_1204 SPEC_DIRECTORY BINARY");
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const LowlevelError &err) {
    cerr << "LowlevelError: " << err.explain << '\n';
  }
  catch(const exception &err) {
    cerr << "std::exception: " << err.what() << '\n';
  }
  return 1;
}
