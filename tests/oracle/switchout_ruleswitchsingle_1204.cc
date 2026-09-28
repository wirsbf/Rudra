/*
 * switchout_ruleswitchsingle_1204.cc — locked Ghidra 12.0.4 (e40ed130)
 * B2 fixture for SWITCHOUT-CLEAR-REMOVETABLE-0001: the real-oracle
 * observation of the RuleSwitchSingle jumptable-elimination chain on the
 * constructed single-target dispatch binary
 * (/dev/shm/rugra-tests/switchout/switchout_single).
 *
 * Scenario: single_target_switch holds a BRANCHIND at 0x40117a whose
 * 8-entry table .rodata:jtab is all -> .Lbody(0x40117c). Jumptable
 * recovery yields 8 labelled entries with one destination, the dispatch
 * block has sizeOut==1, so RuleSwitchSingle (ruleaction.cc:5412-5471)
 * fires during the universal action: BRANCHIND->BRANCH, warningHeader
 * ("Switch with 1 destination removed at ..."), removeJumpTable clears
 * f_switch_out from the dispatch block parent (funcdata_block.cc:76).
 *
 * Load contract = the direct-runner golden generator (same as
 * tests/oracle/namevars_badjumptable_1204.cc): BfdArchitecture over the
 * raw binary, readLoaderSymbols, full-range followFlow, universal action
 * to completion, PrintC::docFunction to stdout.
 *
 * Observation set:
 *   stderr [BLOCKFLAGS] one line per basic block after the pipeline:
 *                        start address, raw flag bits, isSwitchOut() —
 *                        the direct observable of funcdata_block.cc:76.
 *   stderr [JT-REMAIN]   numJumpTables + surviving tables' op addresses
 *                        (the eliminated table must be gone).
 *   stdout               META line + rendered C (the warning header
 *                        renders as a comment; the post-elimination
 *                        structure shows the cat-merged chain).
 *
 * usage: switchout_ruleswitchsingle_1204 SPEC_ROOT BINARY
 *   target via STAGE_DRILL_FUNC (default single_target_switch)
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;

void runFixture(const string &specDirectory,const string &binary)
{
  const char *funcEnv = std::getenv("STAGE_DRILL_FUNC");
  const string funcName = (funcEnv != nullptr && *funcEnv != '\0')
    ? string(funcEnv) : string("single_target_switch");
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(funcName);
    if (fd == (Funcdata *)0)
      throw runtime_error(funcName + " was not found in the BFD symbol table");
    if (fd->hasNoCode())
      throw runtime_error(funcName + " has no code");

    AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
    fd->followFlow(Address(codeSpace,0),Address(codeSpace,codeSpace->getHighest()));

    Action *root = architecture.allacts.getCurrent();
    if (root == (Action *)0)
      throw runtime_error("no current decompile action");
    root->reset(*fd);
    int4 result;
    do {
      result = root->perform(*fd);
    } while (result < 0);

    std::cout << "META side=oracle-switchout oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b"
              << " func=" << funcName << " entry=0x" << std::hex
              << fd->getAddress().getOffset() << std::dec
              << " arch=x86:LE:64:default cspec=gcc seed=none"
              << " observations=blockflags+jt-remain+c-render" << '\n';

    // Observation 1: per-basic-block final flags. The dispatch block
    // (start 0x...176, holds the converted former BRANCHIND) must show
    // switch_out=0 — removeJumpTable cleared f_switch_out.
    const BlockGraph &blocks = fd->getBasicBlocks();
    for(int4 i=0;i<blocks.getSize();++i) {
      const FlowBlock *b = blocks.getBlock(i);
      std::cerr << "[BLOCKFLAGS] i=" << i
                << " start=0x" << std::hex << b->getStart().getOffset() << std::dec
                << " flags=0x" << std::hex << b->getFlags() << std::dec
                << " switch_out=" << (b->isSwitchOut() ? 1 : 0)
                << " sizein=" << b->sizeIn() << " sizeout=" << b->sizeOut() << '\n';
    }

    // Observation 2: the eliminated JumpTable is gone from jumpvec.
    std::cerr << "[JT-REMAIN] count=" << fd->numJumpTables();
    for(int4 i=0;i<fd->numJumpTables();++i) {
      const JumpTable *jt = fd->getJumpTable(i);
      std::cerr << " opaddr=0x" << std::hex
                << jt->getOpAddress().getOffset() << std::dec;
    }
    std::cerr << '\n';

    // Observation 3: the rendered C — the warning header comment proves
    // the rule fired with "8 cases all go to same destination".
    std::ostringstream cOutput;
    architecture.print->setOutputStream(&cOutput);
    architecture.print->docFunction(fd);
    std::cout << cOutput.str();
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: switchout_ruleswitchsingle_1204 SPEC_ROOT BINARY\n"
              << "  target via STAGE_DRILL_FUNC\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[2]);
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
