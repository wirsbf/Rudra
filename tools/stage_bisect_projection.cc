// RUDRA-GLUE: no oracle counterpart. Ghidra has no "projection file" writer;
// everything here is a fixture-harness skeleton that WRAPS the locked oracle
// (Ghidra 12.0.4, commit e40ed13014025f82488b1f8f7bca566894ac376b) purely to
// OBSERVE it, and to emit the line format consumed by tools/stage_bisect.py.
// It must never change any pipeline semantics: no Action/Rule is modified,
// no IR is injected, no traversal order is altered. Per
// docs/alignment_docs/PIPELINE_STAGES_1204.md section 5 this is tooling
// outside the perform() tree.
//
// SKELETON — NOT COMPILED, NOT PART OF ANY BUILD TARGET.
// Print it with:  python3 tools/stage_bisect.py --emit-harness
//
// -----------------------------------------------------------------------------
// [1] Purpose
//
// A "stage projection" is the per-application modification stream of ONE
// decompilation run: every PcodeOp that an Action/Rule application modified,
// as a before/after printDebug pair, plus stage boundary markers with counter
// state. tools/stage_bisect.py compares a Ghidra-side projection against a
// Rudra-side projection and reports the FIRST divergence boundary addressed
// by stage path + restart round + repeatapply pass + counters
// (PIPELINE_STAGES_1204.md section 4 requires exactly this tuple).
//
// [2] Oracle mechanisms consumed (locked commit e40ed130)
//
//   - funcdata.cc:1010-1052  Funcdata::debugModCheck / debugModClear /
//     debugModPrint, all `#ifdef OPACTION_DEBUG`: after each Action::apply
//     (action.cc:317-321) or Rule::applyOp inside a pool
//     (action.cc:839-845, ActionPool::processOp), every modified PcodeOp in
//     the debug range is printed as a before/after pair under a
//     "DEBUG <n>: <name>" header. <n> is the global opactdbg_count
//     (funcdata.hh:584-602) which only advances when the application
//     actually modified a traced op — that number is the projection <seq>.
//   - op.cc:376-385           PcodeOp::printDebug: "<seqnum-addr>: <printRaw>"
//     for live ops, "<seqnum-addr>: **" for dead/unattached ops. printRaw can
//     emit '|' (INT_OR spelling) — see the escaping rule in [3].
//   - action.cc:265-282       getSubAction/getSubRule: ':'-separated name-path
//     addressing, e.g. "universal:fullloop:mainloop". Same path space used by
//     setBreakPoint (ifacedecomp.cc:1196/1222).
//   - action.cc:298-340       Action::perform state machine: a breakpoint
//     returns -1 and "A successive call to perform() will 'continue' from the
//     break point". This is what makes a stage-by-stage walk possible
//     without touching the tree.
//   - action.cc:506 / 553-580 / 877  ActionGroup::apply (child order, count
//     accumulation), ActionRestartGroup::apply (curstart restart rounds),
//     ActionPool::apply (per-op, per-rule traversal order).
//   - action.hh:111-112       Action::getNumTests/getNumApply — the only
//     PUBLIC counters; `count`/`lcount` have no public getter, so boundary
//     markers carry perform() returns and tests/apply deltas.
//   - architecture.hh:255-256 Architecture::setDebugStream/printDebug —
//     capture point for the DEBUG stream.
//   - ifacedecomp.cc:149-155  console commands: "debug action <name>",
//     "trace break <n>", "trace address <pclo> <pchi> [uqlo uqhi]",
//     "trace enable|disable|clear|list".
//
// IMPORTANT LIMITATION (why generators must exist at all): the native DEBUG
// stream prints only the action's leaf getName(), never the tree path, and it
// has no boundary markers. Path attribution and boundary markers are the
// projection generator's job (see [4] route A ambiguity note and [5]).
//
// [3] Projection line format (must match `tools/stage_bisect.py --format`)
//
//   # comment                       (ignored)
//   META side=ghidra commit=<sha> func=<id> arch=<ldefid> [k=v ...]
//   @BEGIN <stage_path> [k=v ...]   application starts
//   <seq> <action_path> <before>|<after>
//   @END <stage_path> [k=v ...]     application ended; canonical keys:
//                                   changes=<perform return or delta>
//                                   tests=<getNumTests delta>
//                                   apply=<getNumApply delta>
//   @CONVERGED <stage_path>         sugar for "@END <path> changes=0"
//   @RESTART <curstart>             universal restart round boundary
//
//   - <seq> is the native opactdbg_count of the application. One application
//     that modified k ops emits k consecutive record lines sharing <seq>, in
//     the native modify_list order (funcdata.cc:1046-1052 loop order).
//   - Before/after are printDebug strings verbatim, with '|' escaped as '\|'
//     and '\' as '\\' (INT_OR raw syntax contains '|').
//   - Stage paths are the oracle's ':' name-path space; pool rules are
//     addressed as "<pool_path>:<RuleName>" via ActionPool::getSubRule.
//   - @RESTART resets all pass counters (stage_bisect derives per-group pass
//     counters by counting @BEGIN per path since the last @RESTART).
//
// [4] Ghidra-side collection — Route A: console binary + script (no C++)
//
//   Build the console with the compile-time switch (Makefile:6 defines
//   ADDITIONAL_FLAGS, Makefile:110 documents OPACTION_DEBUG; a CLEAN rebuild
//   is required because objects are cached without the define):
//
//     ORACLE_CPP=ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
//     make -C "$ORACLE_CPP" clean
//     make -C "$ORACLE_CPP" -j"$(nproc)" \
//         CXX="g++ -std=c++11" EXTRA= \
//         ADDITIONAL_FLAGS="-DOPACTION_DEBUG" decomp_dbg
//
//   Drive it with a console script (commands from ifacedecomp.cc:149-155 and
//   the standard load/dissect/func/decompile flow; "<...>" are placeholders):
//
//     set specpath <sleigh_specs export dir>
//     load file <input binary>
//     disassemble <entry addr>
//     func <entry addr>
//     trace address <pclow> <pchigh>     # or omit for the entire function
//     trace enable                       # Funcdata::debugEnable()
//     decompile
//     quit
//
//   The DEBUG blocks land on the console stream; a small post-processor
//   (awk/python) then:
//     1. keeps every "DEBUG <n>: <name>" block, converting each before/after
//        pair into one record line, escaping '|' and '\';
//     2. attributes a full tree path to each block by walking the KNOWN
//        traversal order of universal (coreaction.cc:5462-5739, mirrored in
//        PIPELINE_STAGES_1204.md section 2);
//     3. emits @BEGIN/@END boundaries from the same traversal knowledge and
//        @RESTART when the post-processor observes the second traversal of
//        the head actions (maxrestarts=1).
//
//   Route A ambiguity (documented limitation): names are not unique in the
//   tree — ActionDirectWrite appears twice in mainloop, DynamicSymbols twice
//   in the tail — so path attribution by occurrence index can mis-attribute
//   when one side skips an application. Route B removes the ambiguity.
//
// [5] Ghidra-side collection — Route B: this harness (schematic code)
//
//   Build commands (libdecomp.a + this fixture; the link line mirrors
//   tools/run_action_perform_oracle.sh:616-642):
//
//     ORACLE_CPP=ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
//     make -C "$ORACLE_CPP" clean
//     make -C "$ORACLE_CPP" -j"$(nproc)" \
//         CXX="g++ -std=c++11" EXTRA= \
//         ADDITIONAL_FLAGS="-DOPACTION_DEBUG" libdecomp.a
//     g++ -std=c++11 -O2 -Wall -Wno-sign-compare -DOPACTION_DEBUG \
//         -I"$ORACLE_CPP" \
//         tests/oracle/stage_projection_1204.cc \
//         "$ORACLE_CPP/libdecomp.cc" "$ORACLE_CPP/sleigh_arch.cc" \
//         "$ORACLE_CPP/inject_sleigh.cc" "$ORACLE_CPP/bfd_arch.cc" \
//         "$ORACLE_CPP/loadimage_bfd.cc" "$ORACLE_CPP/libdecomp.a" \
//         -lbfd -lz -o /tmp/stage_projection_ghidra
//
//   (copy this skeleton to tests/oracle/stage_projection_1204.cc and fill
//   the TODOs; register a metadata json like the other *_1204 fixtures,
//   recording `-DOPACTION_DEBUG` as a build flag — a fixture built with a
//   debug switch MUST record it or it is NO_ORACLE for gate purposes.)
//
// [6] Rudra-side emitter contract
//
//   The Rudra side emits the SAME format from a driver-layer wrapper around
//   its own action tree (RUDRA-GLUE: pure observation, outside the aligned
//   perform() semantics; PIPELINE_STAGES_1204.md section 5 rules apply).
//   Requirements for byte-comparable projections:
//     - same traversal order as the oracle tree (universal head 8 -> fullloop
//       -> mainloop 18 -> stackstall/oppool1 -> ... per section 2 of the doc);
//     - before/after strings produced by the same printDebug semantics
//       (address + raw op syntax, "**" for dead ops);
//     - seq advances only for applications that modified a traced op;
//     - restart boundaries emitted exactly when the restart group re-runs.
//
// [7] Bisect workflow at root integration
//
//     # 1. collect both sides (same function input, same arch/options):
//     /tmp/stage_projection_ghidra <fixture binary> > /tmp/ghidra.proj
//     rudra driver wrapper <same fixture>             > /tmp/rudra.proj
//     # 2. locate the first divergence boundary:
//     python3 tools/stage_bisect.py /tmp/ghidra.proj /tmp/rudra.proj
//     #    -> kind, stage path, restart round, per-group passes, counters,
//     #       before/after pair, last good boundary
//     # 3. BEFORE_DIVERGENCE: rerun with a wider trace range or bisect back
//     #    to the last good boundary; AFTER_DIVERGENCE: the defect is inside
//     #    the reported Action/Rule application of that round.
//
// -----------------------------------------------------------------------------

#if 0  // SKELETON — schematic code, never compiled as-is.

#include "capability.hh"
#include "sleigh_arch.hh"
#include "funcdata.hh"
#include "action.hh"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Deterministic traversal order of the universal tree, from
// coreaction.cc:5462-5739 (see PIPELINE_STAGES_1204.md section 2). The walk
// needs it because Action::getName() is not unique across the tree.
static const char *STAGE_WALK[] = {
    "universal",
    "universal:base",                       // ActionStart(group) etc.
    "universal:fullloop",
    "universal:fullloop:mainloop",
    "universal:fullloop:mainloop:ActionHeritage",
    "universal:fullloop:mainloop:stackstall",
    "universal:fullloop:mainloop:stackstall:oppool1",
    // ... full list per section 2; pool rules appended as
    //     "<pool_path>:<RuleName>" in perop registration order ...
    nullptr
};

// TODO: architecture bootstrap identical to the other tests/oracle/*_1204.cc
// fixtures (spec paths, loadimage, context registers), then:

static int run(const char *binaryPath, const char *entryAddr)
{
  // TODO: Architecture *conf = ...;  Funcdata *fd = ...;
  //   conf->followFlow(...);  conf->allacts.getCurrent()->reset(*fd);

  // Capture point for the native DEBUG stream (architecture.hh:255-256).
  std::ostringstream debugSink;
  conf->setDebugStream(&debugSink);

  // Trace the entire function: an invalid Address range plus the default
  // uq bounds pass every filter in Funcdata::debugCheckRange
  // (funcdata.cc:1076-1097). For a narrower trace use real pc/unique bounds.
  fd->debugSetRange(Address(), Address());
  fd->debugEnable();          // Funcdata::debugEnable() (funcdata.hh:584+)

  // Stage-by-stage walk. Core idea (action.cc:298-340): a break_start on the
  // NEXT stage makes perform() return -1 right before it; the next perform()
  // call continues from there. Between two stops, everything the sink
  // collected belongs to the stages that ran.
  Action *root = conf->allacts.getCurrent();
  for (const char **path = STAGE_WALK; *path != nullptr; ++path) {
    root->clearBreakPoints();
    if (!root->setBreakPoint(Action::break_start, *path))
      return 1;                       // path no longer matches the tree

    // Counters before the stage application (action.hh:111-112).
    // TODO: resolve the Action* for *path once and keep per-stage
    //       last_tests/last_apply deltas across passes.

    int4 res;
    do {
      std::ostringstream stageSink;
      conf->setDebugStream(&stageSink);
      res = root->perform(*fd);       // -1 == stopped at the breakpoint
      // TODO: emit "@BEGIN <path> ..." once per application; convert every
      //       "DEBUG <n>: <name>" block in stageSink into record lines with
      //       the full path prefix, '|' and '\' escaped; emit "@END <path>
      //       changes=<res> tests=<delta> apply=<delta>".
      // TODO: detect ActionRestartGroup re-entry (second traversal of the
      //       head actions) and emit "@RESTART <curstart>".
    } while (res < 0);                // continue from the breakpoint

    // TODO: repeatapply groups: the walk naturally revisits group members
    //       until the pass produces count==0 — emit "@CONVERGED <group>".
  }
  fd->debugDisable();
  return 0;
}

int main(int argc, char **argv)
{
  if (argc != 3) { std::cerr << "usage: prog <binary> <entry>\n"; return 2; }
  return run(argv[1], argv[2]);
}

#endif  // SKELETON
