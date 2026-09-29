//! Analysis actions and transformation rules
//!
//! Corresponds to Ghidra's `action.hh`

use crate::blockaction::*;
use crate::coreaction::*;
use crate::error::Result;
use crate::funcdata::Funcdata;
use std::sync::Arc;

// RUGRA-GLUE: Rust type-erased constructor retained at an Action registration slot so a filtered clone can construct the same concrete leaf without widening every concrete Action's write-set
type ActionFactory = Arc<dyn Fn() -> Box<dyn Action> + Send + Sync>;
// RUGRA-GLUE: Rust type-erased constructor retained at a Rule registration slot so ActionPool::clone can honor Ghidra's fresh-instance Rule::clone contract
type RuleFactory = Arc<dyn Fn() -> Box<dyn Rule> + Send + Sync>;

// RUGRA-GLUE: keeps each concrete Rule constructor at its locked coreaction.cc registration slot while storing a reusable fresh-instance factory
macro_rules! register_rule {
    ($pool:expr, $group:expr, $rule:expr) => {
        $pool.add_rule_factory_in_group($group, || $rule);
    };
}

// RUGRA-GLUE: ACTIONLOOP-RESTART-0001 env-gated dispatch-loop observation
// counters (RUGRA_ACTION_STATS=1; stderr only, default off). Event
// accounting of the Action-dispatch/restart cycle — the per-restart
// amplification the ticket asks to quantify: perform() invocations,
// ActionPool passes, ops visited, Rule applyOp attempts/hits. The oracle
// accumulates the same kind of per-attempt data in Rule::count_tests /
// Action::count_tests (dumped via printStatistics, action.cc:91-96 /
// 275-280); these counters add restart-boundary aggregation on top and
// change no dispatch behavior.
mod action_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct ActionLoopStats {
        pub perform_calls: AtomicU64,
        pub pool_passes: AtomicU64,
        pub ops_visited: AtomicU64,
        pub rule_tries: AtomicU64,
        pub rule_hits: AtomicU64,
        pub restarts: AtomicU64,
    }

    pub static STATS: ActionLoopStats = ActionLoopStats {
        perform_calls: AtomicU64::new(0),
        pool_passes: AtomicU64::new(0),
        ops_visited: AtomicU64::new(0),
        rule_tries: AtomicU64::new(0),
        rule_hits: AtomicU64::new(0),
        restarts: AtomicU64::new(0),
    };

    // RUGRA-GLUE: ACTIONLOOP-RESTART-0001 observation gate (no Ghidra counterpart; the counted events mirror Rule::count_tests)
    fn enabled() -> bool {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var("RUGRA_ACTION_STATS").is_ok_and(|v| v == "1"))
    }

    // RUGRA-GLUE: ACTIONLOOP-RESTART-0001 relaxed counter step (no Ghidra counterpart)
    pub fn bump(counter: &AtomicU64) {
        if enabled() {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One stderr line per restart-group boundary (restart cycle or final
    /// completion) with the cumulative event totals — the per-restart
    /// repeated-work profile (SPEEDPROF-ACTIONLOOP-RESTART-0001 task ①).
    // RUGRA-GLUE: ACTIONLOOP-RESTART-0001 per-restart-boundary stderr report (no Ghidra counterpart)
    pub fn boundary_line(fn_name: &str, curstart: i32) {
        if !enabled() {
            return;
        }
        eprintln!(
            "[ACTIONSTATS] fn={fn_name} curstart={curstart} restarts={} perform={} pool_passes={} ops={} rule_tries={} rule_hits={}",
            STATS.restarts.load(Ordering::Relaxed),
            STATS.perform_calls.load(Ordering::Relaxed),
            STATS.pool_passes.load(Ordering::Relaxed),
            STATS.ops_visited.load(Ordering::Relaxed),
            STATS.rule_tries.load(Ordering::Relaxed),
            STATS.rule_hits.load(Ordering::Relaxed),
        );
    }
}


// ---- Action rule/status/break flags (action.hh:55-87) ----
// These mirror Ghidra's flag bit values exactly, used by the perform() state
// machine to drive repeatapply / onceperfunc semantics.

/// Action rule flags (action.hh:56-63). Stored in an Action's `flags` field.
pub mod action_flags {
    /// Apply repeatedly until no change (action.hh:56).
    pub const RULE_REPEATAPPLY: u32 = 4;
    /// Apply once per function, regardless of whether it changed (action.hh:57).
    pub const RULE_ONCEPERFUNC: u32 = 8;
    /// Apply at most once per function, only if it makes a change (action.hh:58).
    pub const RULE_ONEACTPERFUNC: u32 = 16;
    /// Debug tracing enabled (action.hh:59).
    pub const RULE_DEBUG: u32 = 32;
    /// Warnings will be issued (action.hh:60).
    pub const RULE_WARNINGS_ON: u32 = 64;
    /// A warning has been issued for this action (action.hh:61).
    pub const RULE_WARNINGS_GIVEN: u32 = 128;
}

/// Action status flags (action.hh:65-70). Tracks the perform() state machine.
pub mod status_flags {
    pub const STATUS_START: u32 = 1;
    pub const STATUS_BREAKSTARTHIT: u32 = 2;
    pub const STATUS_REPEAT: u32 = 4;
    pub const STATUS_MID: u32 = 8;
    pub const STATUS_END: u32 = 16;
    pub const STATUS_ACTIONBREAK: u32 = 32;
}

/// Breakpoint flags (action.hh:73-77). Used for debugging — halt at specific points.
pub mod break_flags {
    pub const BREAK_START: u32 = 1;
    pub const TMPBREAK_START: u32 = 2;
    pub const BREAK_ACTION: u32 = 4;
    pub const TMPBREAK_ACTION: u32 = 8;
}

/// Rule property flags (action.hh:197-201). Stored in a Rule's executor slot.
pub mod rule_flags {
    pub const TYPE_DISABLE: u32 = 1;
    pub const RULE_DEBUG: u32 = 2;
    pub const WARNINGS_ON: u32 = 4;
    pub const WARNINGS_GIVEN: u32 = 8;
}

#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum ActionTargetMutation {
    Break(u32),
    Warning(bool),
}

#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum RuleTargetMutation {
    Break(u32),
    Warning(bool),
    Disabled(bool),
}

/// Base trait for all analysis actions
///
/// Corresponds to Ghidra's `Action` class. An action represents a high-level
/// analysis or transformation step performed on a function.
///
/// State management: Ghidra's Action carries `status`/`flags`/`count` fields
/// that drive the `perform()` state machine (repeatapply/onceperfunc). Rugra
/// mirrors this via `ActionState`, stored alongside each Action in its container.
// RUGRA-GLUE: Send + Sync supertrait (Ghidra's decompiler objects live on one thread; Architecture embeds the ActionDatabase, so the Rust Arc<RwLock> embedding needs the bounds)
pub trait Action: Send + Sync {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Perform the action's work on the given function data.
    ///
    /// # Returns
    /// 0 if no change occurred, positive if changes were made, negative for
    /// partial completion (breakpoint).
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32>;

    // RUGRA-GLUE: gives container Actions access to their externalized Ghidra Action base fields while preserving the public apply signature
    /// Apply with the companion executor state visible. Leaf actions use the
    /// ordinary `apply`; ActionGroup uses this to check its own breakpoint at
    /// the exact child-completion boundary.
    fn apply_with_state(&mut self, fd: &mut Funcdata, _state: &mut ActionState) -> Result<i32> {
        self.apply(fd)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the name of the action
    fn get_name(&self) -> &str;

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Reset derived action state for a new function. The Rust container or
    /// root entry resets the companion `ActionState` to `STATUS_START` and
    /// clears only the warning-issued flag; Ghidra does not clear count/stats
    /// in `Action::reset`.
    fn reset(&mut self, _fd: &mut Funcdata) {}

    // Ghidra: action.cc:100 Action::reset
    /// Apply the base Action reset mutation and then reset derived state.
    fn reset_for_function(&mut self, fd: &mut Funcdata, state: &mut ActionState) {
        state.reset_for_function();
        self.reset(fd);
    }

    // Ghidra: action.cc:108 Action::resetStats
    /// Reset this Action's statistics and all container-owned descendants.
    fn reset_stats(&mut self, state: &mut ActionState) {
        state.reset_stats();
        if let Some(group) = self.as_action_group_mut() {
            group.reset_child_stats();
        } else if let Some(pool) = self.as_action_pool_mut() {
            pool.reset_rule_stats();
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the rule flags (repeatapply / onceperfunc / etc). Default: 0
    /// (single-pass). Containers override to return their group's flags.
    fn get_flags(&self) -> u32 { 0 }

    // Ghidra: action.hh:119 Action *clone(const ActionGroupList &grouplist) const
    /// Construct a fresh, selectively filtered copy. Leaf Actions registered
    /// by Rugra's universal builder use their registration-slot factory;
    /// container and fixture Actions can implement the virtual directly.
    fn clone_for_groups(&self, _grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        None
    }

    // RUGRA-GLUE: exposes changes accumulated in a Rust container while preserving Ghidra's apply return convention
    /// Return and clear changes accumulated independently of `apply()`'s
    /// control-flow return code. Ghidra stores these in `Action::count`.
    fn take_count_delta(&mut self) -> i32 { 0 }

    // RUGRA-GLUE: passes the external Rust ActionState status to derived actions whose Ghidra base-class status is directly visible
    /// Prepare one `apply()` attempt for the current executor status.
    fn prepare_apply(&mut self, _status: u32) {}

    // RUGRA-GLUE: read-only restart-round view for tooling/emitters; mirrors
    // the protected ActionRestartGroup::curstart field read that the locked
    // C++ oracle fixtures perform (same protected-field access pattern).
    // Default 0 for every non-restart Action.
    fn fixture_curstart(&self) -> i32 { 0 }

    // RUGRA-GLUE: fixture-only nested tree view; Ghidra exposes the same nesting via Action::print (action.cc:417-440)
    /// Read-only downcast for tree-walking fixtures: returns the container
    /// view if this Action is an ActionGroup/ActionRestartGroup.
    fn as_action_group(&self) -> Option<&ActionGroup> { None }

    // RUGRA-GLUE: fixture-only mutable container view for subtree-driving fixtures
    /// Mutable downcast mirroring `as_action_group`.
    fn as_action_group_mut(&mut self) -> Option<&mut ActionGroup> { None }

    // RUGRA-GLUE: fixture-only pool view; Ghidra holds the same class identity via the virtual ActionPool (action.hh:262)
    /// Read-only downcast for tree-walking fixtures: returns the pool view
    /// if this Action is an ActionPool.
    fn as_action_pool(&self) -> Option<&ActionPool> { None }

    // RUGRA-GLUE: fixture/debug mutable pool view paired with as_action_pool
    fn as_action_pool_mut(&mut self) -> Option<&mut ActionPool> { None }

    // RUGRA-GLUE: mutable restart-group view for the driver's restart-flow
    // callback installation — the driver owns the loader/lifter bridge that
    // stands in for the Architecture-owned followFlow of the oracle restart
    // cycle (PIPE-RESTART-0001)
    fn as_restart_group_mut(&mut self) -> Option<&mut ActionRestartGroup> { None }

    // Ghidra: action.cc:275 Action::getSubAction
    #[doc(hidden)]
    fn sub_action_match_count(&self, specify: &str) -> usize {
        if let Some(group) = self.as_action_group() {
            group.action_match_count(specify)
        } else {
            usize::from(self.get_name() == specify)
        }
    }

    // Ghidra: action.cc:285 Action::getSubRule
    #[doc(hidden)]
    fn sub_rule_match_count(&self, specify: &str) -> usize {
        if let Some(group) = self.as_action_group() {
            group.rule_match_count(specify)
        } else if let Some(pool) = self.as_action_pool() {
            pool.rule_match_count(specify)
        } else {
            0
        }
    }

    // Ghidra: action.cc:171 Action::setBreakPoint
    #[doc(hidden)]
    fn mutate_action_target(
        &mut self,
        state: &mut ActionState,
        specify: &str,
        mutation: ActionTargetMutation,
    ) -> bool {
        if self.as_action_group().is_some() {
            return self
                .as_action_group_mut()
                .expect("ActionGroup downcast changed across one call")
                .mutate_action_target(state, specify, mutation);
        }
        if self.get_name() != specify {
            return false;
        }
        match mutation {
            ActionTargetMutation::Break(tp) => state.set_break(tp),
            ActionTargetMutation::Warning(value) => state.set_warning(value),
        }
        true
    }

    // Ghidra: action.cc:171 Action::setBreakPoint Rule fallback
    #[doc(hidden)]
    fn mutate_rule_target(&mut self, specify: &str, mutation: RuleTargetMutation) -> bool {
        if self.as_action_group().is_some() {
            return self
                .as_action_group_mut()
                .expect("ActionGroup downcast changed across one call")
                .mutate_rule_target(specify, mutation);
        }
        if self.as_action_pool().is_some() {
            return self
                .as_action_pool_mut()
                .expect("ActionPool downcast changed across one call")
                .mutate_rule_target(specify, mutation);
        }
        false
    }

    // Ghidra: action.cc:171 Action::setBreakPoint
    /// Set an Action or Rule breakpoint by the same colon-separated unique
    /// name lookup used by Ghidra. An ambiguous Action lookup falls through to
    /// the Rule lookup, exactly like the two calls in the oracle.
    fn set_break_point(&mut self, state: &mut ActionState, tp: u32, specify: &str) -> bool {
        if self.sub_action_match_count(specify) == 1
            && self.mutate_action_target(state, specify, ActionTargetMutation::Break(tp))
        {
            return true;
        }
        self.sub_rule_match_count(specify) == 1
            && self.mutate_rule_target(specify, RuleTargetMutation::Break(tp))
    }

    // Ghidra: action.cc:187 Action::clearBreakPoints
    /// Clear all Action and Rule breakpoints in this subtree.
    fn clear_break_points(&mut self, state: &mut ActionState) {
        state.clear_break_points();
        if let Some(group) = self.as_action_group_mut() {
            group.clear_child_break_points();
        } else if let Some(pool) = self.as_action_pool_mut() {
            pool.clear_rule_break_points();
        }
    }

    // Ghidra: action.cc:199 Action::setWarning
    /// Toggle the warning property on one uniquely named Action or Rule.
    fn set_warning(&mut self, state: &mut ActionState, value: bool, specify: &str) -> bool {
        if self.sub_action_match_count(specify) == 1
            && self.mutate_action_target(state, specify, ActionTargetMutation::Warning(value))
        {
            return true;
        }
        self.sub_rule_match_count(specify) == 1
            && self.mutate_rule_target(specify, RuleTargetMutation::Warning(value))
    }

    // Ghidra: action.cc:226 Action::disableRule
    /// Disable one uniquely named Rule in this subtree.
    fn disable_rule(&mut self, specify: &str) -> bool {
        self.sub_rule_match_count(specify) == 1
            && self.mutate_rule_target(specify, RuleTargetMutation::Disabled(true))
    }

    // Ghidra: action.cc:242 Action::enableRule
    /// Enable one uniquely named Rule in this subtree.
    fn enable_rule(&mut self, specify: &str) -> bool {
        self.sub_rule_match_count(specify) == 1
            && self.mutate_rule_target(specify, RuleTargetMutation::Disabled(false))
    }

    // Ghidra: action.cc:298 Action::perform
    /// Run this action to completion using Ghidra's status/count state machine.
    /// Positive Rust `apply()` results adapt Ghidra actions that increment their
    /// protected `count` field and return zero.
    fn perform(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        action_stats::bump(&action_stats::STATS.perform_calls);
        loop {
            let apply_now = match state.status {
                status_flags::STATUS_START => {
                    state.count = 0;
                    if state.check_start_break() {
                        state.status = status_flags::STATUS_BREAKSTARTHIT;
                        return Ok(-1);
                    }
                    state.count_tests += 1;
                    state.lcount = state.count;
                    true
                }
                status_flags::STATUS_BREAKSTARTHIT | status_flags::STATUS_REPEAT => {
                    state.lcount = state.count;
                    true
                }
                status_flags::STATUS_MID => true,
                status_flags::STATUS_END => return Ok(0),
                status_flags::STATUS_ACTIONBREAK => false,
                _ => {
                    state.status = status_flags::STATUS_START;
                    continue;
                }
            };

            if apply_now {
                self.prepare_apply(state.status);
                // OPACTION_DEBUG-equivalent drill pair (action.cc:316-322):
                // activate before apply, flush under the action's leaf name
                // after; the pool's per-rule pair (process_op) overrides
                // inside pool applies, exactly like the oracle.
                crate::drillobserve::activate();
                let res = self.apply_with_state(fd, state)?;
                crate::drillobserve::flush(self.get_name());
                let accumulated = self.take_count_delta();
                state.count += accumulated;
                if res < 0 {
                    state.status = status_flags::STATUS_MID;
                    return Ok(res);
                }
                state.count += res;
                if state.lcount < state.count {
                    state.issue_warning(fd, self.get_name());
                    state.count_apply += 1;
                    if state.check_action_break() {
                        state.status = status_flags::STATUS_ACTIONBREAK;
                        return Ok(-1);
                    }
                }
            }

            state.status = status_flags::STATUS_REPEAT;
            let flags = state.flags | self.get_flags();
            if state.lcount >= state.count || (flags & action_flags::RULE_REPEATAPPLY) == 0 {
                break;
            }
        }

        let flags = state.flags | self.get_flags();
        if (flags & (action_flags::RULE_ONCEPERFUNC | action_flags::RULE_ONEACTPERFUNC)) != 0 {
            if state.count > 0 || (flags & action_flags::RULE_ONCEPERFUNC) != 0 {
                state.status = status_flags::STATUS_END;
            } else {
                state.status = status_flags::STATUS_START;
            }
        } else {
            state.status = status_flags::STATUS_START;
        }
        Ok(state.count)
    }
}

/// Per-Action execution state, mirroring Ghidra's Action member fields
/// (action.hh:79-87). Stored in containers alongside each child Action.
#[derive(Debug, Clone)]
pub struct ActionState {
    pub status: u32,
    pub count: i32,
    pub lcount: i32,
    pub count_tests: u32,
    pub count_apply: u32,
    /// Rule flags for this Action (repeatapply / onceperfunc).
    pub flags: u32,
    /// Persistent and temporary start/action breakpoint bits.
    pub breakpoint: u32,
}

impl ActionState {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new(flags: u32) -> Self {
        Self {
            status: status_flags::STATUS_START,
            count: 0,
            lcount: 0,
            count_tests: 0,
            count_apply: 0,
            flags,
            breakpoint: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Resolve effective flags.
    pub fn get_flags_val(&self) -> u32 {
        self.flags
    }

    // Ghidra: action.cc:52 Action::checkStartBreak
    fn check_start_break(&mut self) -> bool {
        if (self.breakpoint & (break_flags::BREAK_START | break_flags::TMPBREAK_START)) == 0 {
            return false;
        }
        self.breakpoint &= !break_flags::TMPBREAK_START;
        true
    }

    // Ghidra: action.cc:117 Action::checkActionBreak
    fn check_action_break(&mut self) -> bool {
        if (self.breakpoint & (break_flags::BREAK_ACTION | break_flags::TMPBREAK_ACTION)) == 0 {
            return false;
        }
        self.breakpoint &= !break_flags::TMPBREAK_ACTION;
        true
    }

    // Ghidra: action.hh:103 Action::setBreakPoint target mutation
    pub fn set_break(&mut self, tp: u32) {
        self.breakpoint |= tp;
    }

    // Ghidra: action.cc:187 Action::clearBreakPoints
    pub fn clear_break_points(&mut self) {
        self.breakpoint = 0;
    }

    // Ghidra: action.cc:199 Action::setWarning target mutation
    pub fn set_warning(&mut self, value: bool) {
        if value {
            self.flags |= action_flags::RULE_WARNINGS_ON;
        } else {
            self.flags &= !action_flags::RULE_WARNINGS_ON;
        }
    }

    // Ghidra: action.cc:41 Action::issueWarning
    fn issue_warning(&mut self, fd: &Funcdata, name: &str) {
        if (self.flags
            & (action_flags::RULE_WARNINGS_ON | action_flags::RULE_WARNINGS_GIVEN))
            != action_flags::RULE_WARNINGS_ON
        {
            return;
        }
        self.flags |= action_flags::RULE_WARNINGS_GIVEN;
        let message = format!("WARNING: Applied action {name}");
        if let Some(arch) = fd.get_arch() {
            arch.print_message(&message);
        } else {
            eprintln!("{message}");
        }
    }

    // Ghidra: action.cc:100 Action::reset
    pub fn reset_for_function(&mut self) {
        self.status = status_flags::STATUS_START;
        self.flags &= !action_flags::RULE_WARNINGS_GIVEN;
    }

    // Ghidra: action.cc:108 Action::resetStats
    pub fn reset_stats(&mut self) {
        self.count_tests = 0;
        self.count_apply = 0;
    }
}

/// Base trait for small-scale transformation rules
///
/// Corresponds to Ghidra's `Rule` class. A rule typically targets a specific
/// P-code opcode and performs a local simplification or optimization.
// RUGRA-GLUE: Send + Sync supertrait (Ghidra's Rule objects live on one thread; ActionPool trees sit inside Architecture's ActionDatabase, so the Rust Arc<RwLock> embedding needs the bounds)
pub trait Rule: Send + Sync {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Apply the rule to a specific operation
    ///
    /// # Returns
    /// 0 if no change occurred, positive if changes were made
    fn apply_op(
        &self, op: &std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>, fd: &mut Funcdata,
    ) -> Result<i32>;

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the name of the rule
    fn get_name(&self) -> &str;

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Get the opcodes this rule applies to
    fn get_opcodes(&self) -> Vec<crate::opcodes::OpCode>;

    // RUGRA-GLUE: externalized Ghidra Rule base flags; concrete Rules override only when their constructor passes non-zero flags
    fn get_flags(&self) -> u32 { 0 }

    // Ghidra: action.hh:236 Rule *clone(const ActionGroupList &grouplist) const
    /// Return a fresh Rule when its group survives, or `None` otherwise.
    /// Production rules are reconstructed by the ActionPool registration-slot
    /// factory; custom rules may override this virtual contract directly.
    fn clone_for_groups(&self, _grouplist: &ActionGroupList) -> Option<Box<dyn Rule>> {
        None
    }

    // Ghidra: action.hh:216 const string &getGroup(void) const
    /// Group recorded by a Rule implementation. Production Rule instances use
    /// the equivalent ActionPool registration-slot group.
    fn get_group(&self) -> &str { "" }

    // RUGRA-GLUE: read-only fixture projection of Ghidra Rule inherited state (action.hh:220-225)
    fn get_rule_flags(&self) -> u32 { 0 }
    // RUGRA-GLUE: read-only fixture projection of Ghidra Rule inherited state (action.hh:221)
    fn get_breakpoint(&self) -> u32 { 0 }
    // Ghidra: action.hh:217 Rule::getNumTests
    fn get_num_tests(&self) -> u32 { 0 }
    // Ghidra: action.hh:218 Rule::getNumApply
    fn get_num_apply(&self) -> u32 { 0 }

    // Ghidra: action.cc:650 Rule::reset
    /// Reset derived Rule state for a new Funcdata. The pool clears the base
    /// warning-given bit in the companion RuleState before this call.
    fn reset(&mut self, _fd: &mut Funcdata) {}

    // RUGRA-GLUE: virtual-reset seam preserving whether a derived Ghidra Rule override invokes Rule::reset
    /// Reset this Rule for a new function. Derived Rules whose locked-oracle
    /// override deliberately omits `Rule::reset` override this method and
    /// leave the companion warning-given bit untouched.
    fn reset_for_function(&mut self, fd: &mut Funcdata, state: &mut RuleState) {
        state.reset_for_function();
        self.reset(fd);
    }

    // Ghidra: action.cc:658 Rule::resetStats
    /// Reset statistics owned by a derived Rule.
    fn reset_stats(&mut self) {}
}

/// Per-Rule execution state, mirroring `Rule` fields in action.hh:203-210.
#[derive(Debug, Clone)]
pub struct RuleState {
    pub flags: u32,
    pub breakpoint: u32,
    pub count_tests: u32,
    pub count_apply: u32,
}

impl RuleState {
    // RUGRA-GLUE: companion-state constructor for Ghidra Rule's base constructor
    pub fn new(flags: u32) -> Self {
        Self {
            flags,
            breakpoint: 0,
            count_tests: 0,
            count_apply: 0,
        }
    }

    // Ghidra: action.hh:219 Rule::setBreak
    pub fn set_break(&mut self, tp: u32) {
        self.breakpoint |= tp;
    }

    // Ghidra: action.hh:221 Rule::clearBreakPoints
    pub fn clear_break_points(&mut self) {
        self.breakpoint = 0;
    }

    // Ghidra: action.hh:222 Rule::turnOnWarnings
    pub fn set_warning(&mut self, value: bool) {
        if value {
            self.flags |= rule_flags::WARNINGS_ON;
        } else {
            self.flags &= !rule_flags::WARNINGS_ON;
        }
    }

    // Ghidra: action.hh:225 Rule::setDisable
    pub fn set_disabled(&mut self, value: bool) {
        if value {
            self.flags |= rule_flags::TYPE_DISABLE;
        } else {
            self.flags &= !rule_flags::TYPE_DISABLE;
        }
    }

    // Ghidra: action.hh:224 Rule::isDisabled
    pub fn is_disabled(&self) -> bool {
        (self.flags & rule_flags::TYPE_DISABLE) != 0
    }

    // Ghidra: action.cc:638 Rule::issueWarning
    fn issue_warning(&mut self, fd: &Funcdata, name: &str) {
        if (self.flags & (rule_flags::WARNINGS_ON | rule_flags::WARNINGS_GIVEN))
            != rule_flags::WARNINGS_ON
        {
            return;
        }
        self.flags |= rule_flags::WARNINGS_GIVEN;
        let message = format!("WARNING: Applied rule {name}");
        if let Some(arch) = fd.get_arch() {
            arch.print_message(&message);
        } else {
            eprintln!("{message}");
        }
    }

    // Ghidra: action.cc:718 Rule::checkActionBreak
    fn check_action_break(&mut self) -> bool {
        if (self.breakpoint & (break_flags::BREAK_ACTION | break_flags::TMPBREAK_ACTION)) == 0 {
            return false;
        }
        self.breakpoint &= !break_flags::TMPBREAK_ACTION;
        true
    }

    // Ghidra: action.cc:650 Rule::reset
    pub fn reset_for_function(&mut self) {
        self.flags &= !rule_flags::WARNINGS_GIVEN;
    }

    // Ghidra: action.cc:658 Rule::resetStats
    fn reset_stats(&mut self) {
        self.count_tests = 0;
        self.count_apply = 0;
    }
}

/// A group of actions executed together
///
/// Corresponds to Ghidra's `ActionGroup` class. On `apply`, runs each child
/// Action's `perform()` in sequence. The parent's `perform()` (via the trait
/// default) drives repeatapply if the group's flags include it.
pub struct ActionGroup {
    name: String,
    actions: Vec<Box<dyn Action>>,
    /// Per-child execution state (status/count/etc). Parallel to `actions`.
    child_states: Vec<ActionState>,
    /// Ghidra: basegroup member of each child Action (action.hh:88). Ghidra
    /// stores the group inside every Action instance; Rugra records it at
    /// the registration slot in the parent (RUGRA-GLUE: per-instance storage
    /// would require touching Action classes owned by other write-sets).
    /// Observably identical for the default tree: every instance is
    /// registered exactly once at one fixed slot (coreaction.cc:5462-5738).
    child_groups: Vec<String>,
    /// Fresh constructors parallel to `actions`. A container can clone itself
    /// virtually; concrete leaves use the factory retained at registration.
    child_factories: Vec<Option<ActionFactory>>,
    /// Iterator index for breakpoint resume (action.hh:146 `state`).
    state: usize,
    /// This group's rule flags (repeatapply etc).
    flags: u32,
    /// Changes made by completed children since the parent last observed us.
    pending_count: i32,
}

// Ghidra: action.cc:257 next_specifyterm
fn next_specify_term(specify: &str) -> (&str, &str) {
    match specify.split_once(':') {
        Some((token, remain)) => (token, remain),
        None => (specify, ""),
    }
}

impl ActionGroup {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new(name: &str) -> Self {
        Self::with_flags(name, 0)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Create with explicit rule flags (e.g. rule_repeatapply for fullloop).
    pub fn with_flags(name: &str, flags: u32) -> Self {
        Self {
            name: name.to_string(),
            actions: Vec::new(),
            child_states: Vec::new(),
            child_groups: Vec::new(),
            child_factories: Vec::new(),
            state: 0,
            flags,
            pending_count: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn add_action(&mut self, action: Box<dyn Action>) {
        self.push_action(action, "", None);
    }

    // RUGRA-GLUE: registration-site group record mirroring the basegroup string passed to each Ghidra Action ctor (coreaction.cc:5477-5738)
    /// Add a child together with the basegroup string its Ghidra ctor
    /// receives at this registration slot (`new ActionX(group)`).
    pub fn add_action_in_group(&mut self, action: Box<dyn Action>, group: &str) {
        self.push_action(action, group, None);
    }

    // RUGRA-GLUE: captures the concrete Rust constructor at the Ghidra addAction registration site so leaf Action::clone can remain write-set-local
    pub fn add_action_factory_in_group<F>(&mut self, group: &str, factory: F)
    where
        F: Fn() -> Box<dyn Action> + Send + Sync + 'static,
    {
        let factory: ActionFactory = Arc::new(factory);
        let action = factory();
        self.push_action(action, group, Some(factory));
    }

    // RUGRA-GLUE: single registration path keeping Action/list/state/group/factory vectors in lock-step
    fn push_action(
        &mut self,
        action: Box<dyn Action>,
        group: &str,
        factory: Option<ActionFactory>,
    ) {
        let child_flags = action.get_flags();
        self.actions.push(action);
        self.child_states.push(ActionState::new(child_flags));
        self.child_groups.push(group.to_string());
        self.child_factories.push(factory);
    }

    // Ghidra: action.cc:391 Action *ActionGroup::clone(const ActionGroupList &grouplist) const
    fn clone_group(&self, grouplist: &ActionGroupList) -> Option<Self> {
        let mut result: Option<Self> = None;
        for index in 0..self.actions.len() {
            let cloned = self.actions[index].clone_for_groups(grouplist).or_else(|| {
                if !grouplist.contains(&self.child_groups[index]) {
                    return None;
                }
                self.child_factories[index]
                    .as_ref()
                    .map(|factory| factory())
            });
            let Some(action) = cloned else {
                continue;
            };
            let group = result.get_or_insert_with(|| Self::with_flags(&self.name, self.flags));
            group.push_action(
                action,
                &self.child_groups[index],
                self.child_factories[index].clone(),
            );
        }
        result
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn get_name_str(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn num_actions(&self) -> usize { self.actions.len() }
    // RUGRA-GLUE: read-only fixture/debug view of Ghidra ActionGroup's protected iterator
    pub fn current_index(&self) -> usize { self.state }
    // RUGRA-GLUE: resets the inherited ActionGroup iterator after a restart
    // cycle — ActionRestartGroup::apply drives the embedded group's
    // apply_children directly, bypassing perform/prepare_apply's
    // status-based cursor re-initialization (action.cc:508-509
    // `if (status != status_mid) state = list.begin()`).
    pub fn reset_apply_cursor(&mut self) { self.state = 0; }
    // RUGRA-GLUE: read-only fixture/debug view of a child Action's externalized executor state
    pub fn child_state(&self, index: usize) -> Option<&ActionState> {
        self.child_states.get(index)
    }
    // RUGRA-GLUE: mutable fixture projection of Ghidra's inherited per-child Action fields
    pub fn child_state_mut(&mut self, index: usize) -> Option<&mut ActionState> {
        self.child_states.get_mut(index)
    }
    // RUGRA-GLUE: read-only ordered fixture view of Ghidra ActionGroup::list (action.hh:145); Ghidra prints the same sequence via Action::print (action.cc:417-440)
    pub fn child_names(&self) -> Vec<&str> {
        self.actions.iter().map(|a| a.get_name()).collect()
    }
    // RUGRA-GLUE: fixture-only read-only child view for tree-walking tests (Ghidra iterates the same protected list in Action::print)
    pub fn child_actions(&self) -> &[Box<dyn Action>] {
        &self.actions
    }
    // RUGRA-GLUE: fixture-only mutable child view for driving one subtree through the exact perform() sequence (Ghidra's ActionGroup::apply drives the same protected list)
    pub fn child_actions_mut(&mut self) -> &mut [Box<dyn Action>] {
        &mut self.actions
    }
    // RUGRA-GLUE: registration-site basegroup view for tree-walking fixtures (Ghidra Action::getGroup, action.hh:109)
    pub fn child_group(&self, index: usize) -> &str {
        &self.child_groups[index]
    }
    // RUGRA-GLUE: fixture executor view — drives child `index` through the exact perform() call ActionGroup::apply makes (src/action.rs ActionGroup::apply line above); Ghidra's ActionGroup::apply drives Action::perform the same way (action.cc:511-527)
    pub fn perform_child(
        &mut self,
        index: usize,
        fd: &mut Funcdata) -> crate::error::Result<i32> {
        self.actions[index].perform(fd, &mut self.child_states[index])
    }

    // Ghidra: action.cc:456 ActionGroup::getSubAction
    fn action_match_count(&self, specify: &str) -> usize {
        let (token, remain) = next_specify_term(specify);
        let child_specify = if self.name == token {
            if remain.is_empty() {
                return 1;
            }
            remain
        } else {
            specify
        };
        let mut match_count = 0;
        for action in &self.actions {
            if action.sub_action_match_count(child_specify) != 0 {
                match_count += 1;
                if match_count > 1 {
                    return 0;
                }
            }
        }
        match_count
    }

    // Ghidra: action.cc:481 ActionGroup::getSubRule
    fn rule_match_count(&self, specify: &str) -> usize {
        let (token, remain) = next_specify_term(specify);
        let child_specify = if self.name == token {
            if remain.is_empty() {
                return 0;
            }
            remain
        } else {
            specify
        };
        let mut match_count = 0;
        for action in &self.actions {
            if action.sub_rule_match_count(child_specify) != 0 {
                match_count += 1;
                if match_count > 1 {
                    return 0;
                }
            }
        }
        match_count
    }

    // Ghidra: action.cc:456 ActionGroup::getSubAction target selection
    fn mutate_action_target(
        &mut self,
        state: &mut ActionState,
        specify: &str,
        mutation: ActionTargetMutation,
    ) -> bool {
        let (token, remain) = next_specify_term(specify);
        let child_specify = if self.name == token {
            if remain.is_empty() {
                match mutation {
                    ActionTargetMutation::Break(tp) => state.set_break(tp),
                    ActionTargetMutation::Warning(value) => state.set_warning(value),
                }
                return true;
            }
            remain
        } else {
            specify
        };
        let Some(index) = self
            .actions
            .iter()
            .position(|action| action.sub_action_match_count(child_specify) == 1)
        else {
            return false;
        };
        let (actions, child_states) = (&mut self.actions, &mut self.child_states);
        actions[index].mutate_action_target(
            &mut child_states[index],
            child_specify,
            mutation)
    }

    // Ghidra: action.cc:481 ActionGroup::getSubRule target selection
    fn mutate_rule_target(&mut self, specify: &str, mutation: RuleTargetMutation) -> bool {
        let (token, remain) = next_specify_term(specify);
        let child_specify = if self.name == token {
            if remain.is_empty() {
                return false;
            }
            remain
        } else {
            specify
        };
        let Some(index) = self
            .actions
            .iter()
            .position(|action| action.sub_rule_match_count(child_specify) == 1)
        else {
            return false;
        };
        self.actions[index].mutate_rule_target(child_specify, mutation)
    }

    // Ghidra: action.cc:382 ActionGroup::clearBreakPoints
    fn clear_child_break_points(&mut self) {
        let (actions, child_states) = (&mut self.actions, &mut self.child_states);
        for (action, state) in actions.iter_mut().zip(child_states.iter_mut()) {
            action.clear_break_points(state);
        }
    }

    // Ghidra: action.cc:418 ActionGroup::resetStats
    fn reset_child_stats(&mut self) {
        let (actions, child_states) = (&mut self.actions, &mut self.child_states);
        for (action, state) in actions.iter_mut().zip(child_states.iter_mut()) {
            action.reset_stats(state);
        }
    }

    // Ghidra: action.cc:506 ActionGroup::apply
    fn apply_children(
        &mut self,
        fd: &mut Funcdata,
        mut group_state: Option<&mut ActionState>,
    ) -> Result<i32> {
        while self.state < self.actions.len() {
            let res = self.actions[self.state].perform(fd, &mut self.child_states[self.state])?;
            // TEMP PROBE (selectgoto2 lane): per-child-action bbsig dump —
            // the counterpart of the oracle probe's GLM_ACTSIG hook at
            // ActionGroup::apply's child dispatch (action.cc:514). Env-gated,
            // default off; debug-only, no pipeline behavior.
            if std::env::var("RUGRA_ACTSIG").is_ok() {
                use std::fmt::Write as _;
                static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                static BUF: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
                let mut guard = BUF.lock().unwrap();
                let sig = guard.get_or_insert_with(String::new);
                let _ = write!(
                    sig,
                    "@ACT {} {} res={}\n",
                    seq,
                    self.actions[self.state].get_name(),
                    res
                );
                for i in 0..fd.bblocks.get_size() {
                    let Some(b) = fd.bblocks.get_block(i) else {
                        continue;
                    };
                    let rg = b.read().unwrap();
                    let start = rg.get_start_addr().as_u64();
                    let _ = write!(sig, "  bb{} {:#x} o={}", i, start, rg.size_out());
                    if rg.size_out() > 0 {
                        let _ = write!(sig, " -> [");
                        for j in 0..rg.size_out() {
                            if j > 0 {
                                let _ = write!(sig, ",");
                            }
                            if let Some(e) = rg.get_out(j) {
                                let _ = write!(
                                    sig,
                                    "{:#x}",
                                    e.point.read().unwrap().get_start_addr().as_u64()
                                );
                            }
                        }
                        let _ = write!(sig, "]");
                    }
                    let _ = writeln!(sig);
                }
                let _ = std::fs::write(format!("{}.actsig", fd.name), sig.as_str());
            }
            if res > 0 {
                self.pending_count += res;
                if group_state
                    .as_deref_mut()
                    .is_some_and(ActionState::check_action_break)
                {
                    self.state += 1;
                    return Ok(-1);
                }
            } else if res < 0 {
                return Ok(-1);
            }
            self.state += 1;
        }
        Ok(0)
    }
}

impl Action for ActionGroup {
    // Ghidra: action.cc:506 ActionGroup::apply
    /// Run every child through its `perform()` state machine in list order.
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        self.apply_children(fd, None)
    }

    // RUGRA-GLUE: exposes the inherited Action base state needed by ActionGroup::apply's checkActionBreak call
    fn apply_with_state(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        self.apply_children(fd, Some(state))
    }

    // RUGRA-GLUE: mirrors ActionGroup::apply reading its inherited Action::status before initializing the protected iterator
    fn prepare_apply(&mut self, status: u32) {
        if status != status_flags::STATUS_MID {
            self.state = 0;
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 { self.flags }

    // Ghidra: action.cc:391 Action *ActionGroup::clone(const ActionGroupList &grouplist) const
    fn clone_for_groups(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        self.clone_group(grouplist)
            .map(|group| Box::new(group) as Box<dyn Action>)
    }

    // RUGRA-GLUE: fixture-only nested tree view (see Action::as_action_group)
    fn as_action_group(&self) -> Option<&ActionGroup> { Some(self) }
    // RUGRA-GLUE: fixture-only mutable nested tree view for subtree-driving fixtures (Ghidra reaches the same list via protected ActionGroup::list)
    fn as_action_group_mut(&mut self) -> Option<&mut ActionGroup> { Some(self) }

    // RUGRA-GLUE: externalizes Ghidra ActionGroup's inherited `count` member
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.pending_count)
    }

    // Ghidra: action.cc:408 ActionGroup::reset
    fn reset(&mut self, fd: &mut Funcdata) {
        for i in 0..self.actions.len() {
            self.actions[i].reset_for_function(fd, &mut self.child_states[i]);
        }
    }
}

/// Driver-boundary callback type for the restart cycle's flow regeneration.
/// In the oracle, `ActionRestartGroup::apply` (action.cc:574) calls
/// `Architecture::clearAnalysis`, and the second pass's `ActionStart` re-enters
/// `Funcdata::startProcessing` → `followFlow` (funcdata.cc:157), regenerating
/// the raw p-code through the Architecture-owned loader/lifter. Rugra's flow
/// generation lives at the driver boundary (`rugra::flow::follow_flow*`,
/// because the followFlow port inside `Funcdata::start_processing` is a
/// registered gap), so the driver installs this callback — the Rust
/// equivalent of the Architecture-owned followFlow — on the derived root it
/// is about to perform.
// RUGRA-GLUE: driver-side seam for the Architecture-owned loader/lifter half of the oracle restart cycle (PIPE-RESTART-0001)
pub type RestartFlowCallback =
    std::sync::Arc<dyn Fn(&mut Funcdata) -> crate::error::Result<()> + Send + Sync>;

/// A partial restartable action group — the top-level container for the
/// universal pipeline.
///
/// Wraps an `ActionGroup`. After the group converges (apply returns 0), if
/// `Funcdata::has_restart_pending()` is true, the group clears the analysis
/// (`Architecture::clearAnalysis`), regenerates the flow through the
/// driver-installed [`RestartFlowCallback`], resets every child Action and
/// re-runs the subtree — mirroring `ActionRestartGroup::apply`
/// (action.cc:553-582).
pub struct ActionRestartGroup {
    name: String,
    group: ActionGroup,
    maxrestarts: i32,
    curstart: i32,
    /// State for this Action (used by parent perform — though this is root).
    flags: u32,
    /// Changes accumulated by the embedded ActionGroup across restarts.
    pending_count: i32,
    /// Driver-installed raw-flow regeneration hook used between
    /// `clearAnalysis` and the child resets of each restart cycle. `None`
    /// for standalone fixtures without a loader bridge; those take the
    /// bounded-completion path in `apply_restart`.
    restart_flow: Option<RestartFlowCallback>,
}

impl ActionRestartGroup {
    /// Create with rule flags and max restart count.
    /// Ghidra: `ActionRestartGroup(rule_onceperfunc, "universal", 1)`.
    pub fn new(name: &str, flags: u32, maxrestarts: i32) -> Self {
        Self {
            name: name.to_string(),
            group: ActionGroup::with_flags(name, flags),
            maxrestarts,
            curstart: 0,
            flags,
            pending_count: 0,
            restart_flow: None,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn add_action(&mut self, action: Box<dyn Action>) {
        self.group.add_action(action);
    }

    // RUGRA-GLUE: registration-site group record passthrough (see ActionGroup::add_action_in_group)
    pub fn add_action_in_group(&mut self, action: Box<dyn Action>, group: &str) {
        self.group.add_action_in_group(action, group);
    }

    // RUGRA-GLUE: registration-factory passthrough to the embedded ActionGroup
    pub fn add_action_factory_in_group<F>(&mut self, group: &str, factory: F)
    where
        F: Fn() -> Box<dyn Action> + Send + Sync + 'static,
    {
        self.group.add_action_factory_in_group(group, factory);
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn num_actions(&self) -> usize {
        self.group.num_actions()
    }

    // RUGRA-GLUE: registration-site basegroup view passthrough (Ghidra Action::getGroup, action.hh:109)
    pub fn child_group(&self, index: usize) -> &str {
        self.group.child_group(index)
    }

    // RUGRA-GLUE: read-only ordered fixture view through to the embedded ActionGroup's children (Ghidra ActionRestartGroup inherits ActionGroup::list)
    pub fn child_names(&self) -> Vec<&str> {
        self.group.child_names()
    }

    // RUGRA-GLUE: fixture executor view — drives child `index` of the embedded group exactly as ActionRestartGroup::apply would
    pub fn perform_child(
        &mut self,
        index: usize,
        fd: &mut Funcdata) -> crate::error::Result<i32> {
        self.group.perform_child(index, fd)
    }

    // RUGRA-GLUE: read-only fixture/debug view of a child Action's externalized executor state
    pub fn child_state(&self, index: usize) -> Option<&ActionState> {
        self.group.child_state(index)
    }

    // RUGRA-GLUE: mutable fixture projection passthrough for inherited per-child Action fields
    pub fn child_state_mut(&mut self, index: usize) -> Option<&mut ActionState> {
        self.group.child_state_mut(index)
    }

    // Ghidra: action.cc:529 Action *ActionRestartGroup::clone(const ActionGroupList &grouplist) const
    pub fn clone_restart_group(&self, grouplist: &ActionGroupList) -> Option<Self> {
        self.group.clone_group(grouplist).map(|group| Self {
            name: self.name.clone(),
            group,
            maxrestarts: self.maxrestarts,
            curstart: 0,
            flags: self.flags,
            pending_count: 0,
            // RUGRA-GLUE: the restart-flow callback is driver state, not
            // tree state — the oracle's clone builds a fresh object and the
            // Architecture reaches its loader through Funcdata::getArch();
            // the driver installs the callback on the derived root it will
            // actually perform (ActionDatabase::set_restart_flow).
            restart_flow: None,
        })
    }

    // RUGRA-GLUE: driver-side installation point for the restart-cycle flow
    // regeneration callback (see the `restart_flow` field and
    // [`RestartFlowCallback`]). Install on the derived root that will
    // actually run — the production driver's "decompile" clone — before
    // performing it.
    pub fn set_restart_flow(&mut self, callback: RestartFlowCallback) {
        self.restart_flow = Some(callback);
    }

    // RUGRA-GLUE: fixture-only observation accessor (the locked C++ fixture reads the protected curstart field via its private/protected access hack)
    #[doc(hidden)]
    pub fn fixture_curstart(&self) -> i32 {
        self.curstart
    }

    // Ghidra: action.cc:553 ActionRestartGroup::apply
    /// The restart loop of `ActionRestartGroup::apply` (action.cc:553-582),
    /// with the externally held inherited Action base state threaded into
    /// every embedded `ActionGroup::apply` call — Ghidra's restart group
    /// inherits that method, so the child-boundary `checkActionBreak`
    /// (action.cc:517) reads the restart group's own breakpoint field.
    fn apply_restart(
        &mut self,
        fd: &mut Funcdata,
        mut group_state: Option<&mut ActionState>,
    ) -> Result<i32> {
        if self.curstart == -1 {
            return Ok(0); // Already completed (action.cc:558)
        }
        loop {
            let res = self
                .group
                .apply_children(fd, group_state.as_deref_mut())?;
            self.pending_count += self.group.take_count_delta();
            if res != 0 {
                return Ok(res); // action.cc:561
            }
            if !fd.has_restart_pending() {
                self.curstart = -1;
                action_stats::boundary_line(&fd.name, -1);
                return Ok(0); // action.cc:562-565
            }
            // Don't restart during jumptable recovery (action.cc:566-567).
            if fd.is_jumptable_recovery_on() {
                action_stats::boundary_line(&fd.name, self.curstart);
                return Ok(0);
            }
            self.curstart += 1;
            if self.curstart > self.maxrestarts {
                fd.warning_header("Exceeded maximum restarts with more pending");
                self.curstart = -1;
                action_stats::boundary_line(&fd.name, -1);
                return Ok(0); // action.cc:568-573
            }
            action_stats::bump(&action_stats::STATS.restarts);
            action_stats::boundary_line(&fd.name, self.curstart);
            // The oracle's restart cycle re-enters ActionStart →
            // Funcdata::startProcessing → followFlow (funcdata.cc:157),
            // regenerating the raw p-code through the Architecture-owned
            // loader/lifter. Rugra's flow generation lives at the driver
            // boundary, so the driver-installed restart_flow callback
            // performs the regeneration here, after clearAnalysis and
            // before the child resets — the same point relative to
            // clearAnalysis as the oracle's followFlow, which runs inside
            // the second pass's ActionStart after those resets.
            // The oracle has no callback-less path (its Architecture
            // always owns a loader); standalone Rugra callers without a
            // driver bridge take the bounded completion BELOW, before any
            // state mutation, so the print phase keeps the converged
            // first-pass analysis.
            let restart_flow = self.restart_flow.clone();
            let Some(restart_flow) = restart_flow else {
                // Bounded completion for callback-less callers (standalone
                // fixtures without a loader bridge): the pending flag stays
                // set, matching the oracle's end state on the maxrestarts
                // path (only Funcdata::clear or an explicit
                // setRestartPending(false) ever clear it; this loop is its
                // sole consumer — action.cc:562). Documented degradation,
                // PIPE-RESTART-0001.
                eprintln!(
                    "[ACTION] restart pending: no restart-flow callback installed (PIPE-RESTART-0001 bounded completion); completing without restart"
                );
                return Ok(0);
            };
            // data.getArch()->clearAnalysis(&data) (action.cc:574;
            // architecture.cc:335-341) = Funcdata::clear (funcdata.cc:84-112:
            // the analysis flag bits including restart_pending and
            // processing_started, unlocked localmap symbols, active output,
            // blocks, obank, vbank, callspecs, jumptables, heritage and
            // covermerge are wiped; overrides survive funcdata.cc:106) plus
            // the Architecture-owned comment wipe
            // commentdb->clearType(fd->getAddress(),
            //                        Comment::warning|Comment::warningheader)
            // keyed by the function's entry address.
            fd.clear();
            let commentdb = fd
                .get_arch()
                .and_then(|arch| arch.commentdb.clone());
            if let Some(commentdb) = commentdb {
                if let Ok(mut comments) = commentdb.write() {
                    comments.clear_type(
                        fd.baseaddr,
                        crate::comment::comment_type::WARNING
                            | crate::comment::comment_type::WARNINGHEADER,
                    );
                }
            }
            restart_flow(fd)?;
            // Reset everything but ourselves (action.cc:576-580): each
            // subrule reset re-arms the rule_onceperfunc gates (e.g.
            // mapglobals) for the second pass. ActionStart — the first
            // child of the restarted subtree — invokes
            // Funcdata::start_processing exactly once (coreaction.hh:41-43);
            // Funcdata::clear cleared the processing_started guard, so this
            // loop must NOT call start_processing itself (a second entry
            // would trip the LowlevelError guard, funcdata.cc:153-154).
            self.group.reset(fd);
            // status = status_start (action.cc:581) plus the derived
            // iterator re-initialization of the next ActionGroup::apply
            // (action.cc:508-509 `if (status != status_mid)
            // state = list.begin()`): the embedded-group composition drives
            // apply_children directly, bypassing perform/prepare_apply's
            // status-based cursor reset, so reset the child cursor
            // explicitly.
            self.group.reset_apply_cursor();
            if let Some(state) = group_state.as_deref_mut() {
                state.status = status_flags::STATUS_START;
            }
        }
    }
}

impl Action for ActionRestartGroup {
    // Ghidra: action.cc:553 ActionRestartGroup::apply
    /// Run the restart loop without an externally held group breakpoint
    /// (Ghidra's apply reads the inherited base fields directly).
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        self.apply_restart(fd, None)
    }

    // RUGRA-GLUE: forwards the externalized inherited Action base state into the embedded group (Ghidra's ActionRestartGroup inherits ActionGroup::apply's child-boundary checkActionBreak, action.cc:517)
    fn apply_with_state(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        self.apply_restart(fd, Some(state))
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str {
        &self.name
    }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: action.cc:529 Action *ActionRestartGroup::clone(const ActionGroupList &grouplist) const
    fn clone_for_groups(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        self.clone_restart_group(grouplist)
            .map(|group| Box::new(group) as Box<dyn Action>)
    }
    // RUGRA-GLUE: shares the external restart-group executor status with its embedded Rust ActionGroup
    fn prepare_apply(&mut self, status: u32) {
        self.group.prepare_apply(status);
    }
    // RUGRA-GLUE: fixture-only nested tree view (see Action::as_action_group)
    fn as_action_group(&self) -> Option<&ActionGroup> { Some(&self.group) }
    // RUGRA-GLUE: fixture-only mutable nested tree view for subtree-driving fixtures (Ghidra ActionRestartGroup inherits ActionGroup::list)
    fn as_action_group_mut(&mut self) -> Option<&mut ActionGroup> { Some(&mut self.group) }
    // RUGRA-GLUE: mutable restart-group view for the driver's restart-flow callback installation (see Action::as_restart_group_mut)
    fn as_restart_group_mut(&mut self) -> Option<&mut ActionRestartGroup> { Some(self) }
    // RUGRA-GLUE: trait-level read-only passthrough of the protected curstart for the stage-projection emitter (see Action::fixture_curstart)
    fn fixture_curstart(&self) -> i32 { self.curstart }
    // RUGRA-GLUE: externalizes Ghidra ActionRestartGroup's inherited `count` member
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.pending_count)
    }

    // Ghidra: action.cc:546 ActionRestartGroup::reset
    fn reset(&mut self, fd: &mut Funcdata) {
        self.curstart = 0;
        self.pending_count = 0;
        self.group.reset(fd);
    }
}

/// A pool of Rules applied to every matching P-code op.
///
/// Corresponds to Ghidra's `ActionPool` (action.hh:262). On `apply`, does a
/// **single pass** over all live ops, dispatching each to matching Rules.
/// The repeat-until-stable behaviour is driven by the parent's `perform()`
/// via `rule_repeatapply` (action.cc:350), not by this pool itself.
pub struct ActionPool {
    name: String,
    rules: Vec<Box<dyn Rule>>,
    /// Per-Rule base state, parallel to `rules`/Ghidra `allrules`.
    rule_states: Vec<RuleState>,
    /// Ghidra Rule::basegroup at each `allrules` registration slot.
    rule_groups: Vec<String>,
    /// Fresh constructors parallel to `rules` for concrete production Rules.
    rule_factories: Vec<Option<RuleFactory>>,
    /// Opcode → indices into `rules`, built on add_rule for O(1) dispatch.
    /// ACTIONLOOP-RESTART-0001: array indexed by the `#[repr(i32)]` OpCode
    /// discriminant (opcodes.rs:16, CPUI_MAX = 74) — the exact shape of
    /// Ghidra's `vector<Rule *> perop[CPUI_MAX]` (action.hh:264). The prior
    /// SipHash `HashMap` lookup cost one hash per rule attempt per op
    /// (action.cc:836 `while(rule_index < perop[opc].size())` re-reads the
    /// bucket each iteration in the oracle; the array read is the same
    /// O(1) with no hashing).
    per_op: Vec<Vec<usize>>,
    /// Rule flags — RULE_REPEATAPPLY so perform() loops this pool.
    flags: u32,
    /// Current PcodeOpTree element retained across a Rule breakpoint, in
    /// id form (the retained `PcodeOpTree::const_iterator` op_state of
    /// action.hh:265 — PERF-ARENA-FLIP-0001 (c): the arena cell carries the
    /// denormalized SeqNum key and opcode, so the cursor advances and the
    /// dispatch's per-try `op->code()` re-reads resolve lock-free).
    op_state: Option<crate::arena::OpId>,
    /// Next index in the current opcode's per-op Rule vector.
    rule_index: usize,
    /// Changes accumulated in Ghidra's inherited Action::count.
    pending_count: i32,
}

impl ActionPool {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new(name: &str) -> Self {
        Self::with_flags(name, action_flags::RULE_REPEATAPPLY)
    }

    // RUGRA-GLUE: explicit ActionPool constructor flags mirroring ActionPool(uint4,const string&) in action.hh:269
    pub fn with_flags(name: &str, flags: u32) -> Self {
        Self {
            name: name.to_string(),
            rules: Vec::new(),
            rule_states: Vec::new(),
            rule_groups: Vec::new(),
            rule_factories: Vec::new(),
            // ACTIONLOOP-RESTART-0001: perop[CPUI_MAX] array shape
            // (action.hh:264); one spare slot so OpCode::CPUI_MAX itself
            // indexes in bounds during defensive reads.
            per_op: vec![Vec::new(); (crate::opcodes::OpCode::CPUI_MAX as i32 as usize) + 1],
            flags,
            op_state: None,
            rule_index: 0,
            pending_count: 0,
        }
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    /// Register a Rule. Faithful to `ActionPool::addRule` — the rule's
    /// opcodes are indexed for fast per-op dispatch.
    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        let group = rule.get_group().to_string();
        self.push_rule(rule, &group, None);
    }

    // RUGRA-GLUE: captures the concrete Rust constructor at the Ghidra addRule registration site so Rule::clone remains fresh without editing concrete Rule modules
    pub fn add_rule_factory_in_group<F>(&mut self, group: &str, factory: F)
    where
        F: Fn() -> Box<dyn Rule> + Send + Sync + 'static,
    {
        let factory: RuleFactory = Arc::new(factory);
        let rule = factory();
        self.push_rule(rule, group, Some(factory));
    }

    // Ghidra: action.cc:740 void ActionPool::addRule(Rule *rl)
    fn push_rule(&mut self, rule: Box<dyn Rule>, group: &str, factory: Option<RuleFactory>) {
        let idx = self.rules.len();
        let opcodes = rule.get_opcodes();
        let rule_flags = rule.get_flags();
        self.rules.push(rule);
        self.rule_states.push(RuleState::new(rule_flags));
        self.rule_groups.push(group.to_string());
        self.rule_factories.push(factory);
        for opc in opcodes {
            // ACTIONLOOP-RESTART-0001: array-bucket append — the mirror of
            // `perop[opc].push_back(rl)` (action.cc:749).
            self.per_op[opc as i32 as usize].push(idx);
        }
    }

    // Ghidra: action.cc:899 Action *ActionPool::clone(const ActionGroupList &grouplist) const
    pub fn clone_pool(&self, grouplist: &ActionGroupList) -> Option<Self> {
        let mut result: Option<Self> = None;
        for index in 0..self.rules.len() {
            let cloned = self.rules[index].clone_for_groups(grouplist).or_else(|| {
                if !grouplist.contains(&self.rule_groups[index]) {
                    return None;
                }
                self.rule_factories[index].as_ref().map(|factory| factory())
            });
            let Some(rule) = cloned else {
                continue;
            };
            let pool = result.get_or_insert_with(|| Self::with_flags(&self.name, self.flags));
            pool.push_rule(
                rule,
                &self.rule_groups[index],
                self.rule_factories[index].clone(),
            );
        }
        result
    }

    // RUGRA-GLUE: fixture-only rule registration view (pool purity fixture
    // tests/oracle/pool_purity_1204; the Ghidra fixture reads the same
    // sequence through the public virtual ActionPool::print, action.cc:
    // 753-775, which iterates allrules in registration order). No dispatch
    // state is exposed.
    pub fn rules(&self) -> &[Box<dyn Rule>] { &self.rules }

    // Ghidra: action.hh:216 const string &Rule::getGroup(void) const
    pub fn rule_group(&self, index: usize) -> &str { &self.rule_groups[index] }

    // RUGRA-GLUE: ordered fixture projection of ActionPool::perop[opcode], whose list entries are appended by addRule (action.cc:740-751)
    pub fn rule_names_for_opcode(&self, opcode: crate::opcodes::OpCode) -> Vec<&str> {
        self.per_op[opcode as i32 as usize]
            .iter()
            .map(|index| self.rules[*index].get_name())
            .collect()
    }

    // RUGRA-GLUE: read-only view of the externalized Ghidra Rule base fields
    pub fn rule_state(&self, index: usize) -> Option<&RuleState> {
        self.rule_states.get(index)
    }

    // RUGRA-GLUE: fixture-only mutable view of the externalized Ghidra Rule base fields (the locked C++ fixture writes the same fields directly under its private/protected access hack)
    #[doc(hidden)]
    pub fn rule_state_mut(&mut self, index: usize) -> Option<&mut RuleState> {
        self.rule_states.get_mut(index)
    }

    // RUGRA-GLUE: read-only breakpoint-resume cursor used by the locked fixture
    pub fn resume_state(&self, fd: &Funcdata) -> (Option<crate::address::SeqNum>, usize) {
        (
            self.op_state
                .and_then(|id| fd.obank.op_by_id(id))
                .map(|op| *op.0.read().unwrap().get_seq_num()),
            self.rule_index,
        )
    }

    // Ghidra: action.cc:789 ActionPool::getSubRule
    fn rule_match_count(&self, specify: &str) -> usize {
        let (token, remain) = next_specify_term(specify);
        let rule_name = if self.name == token {
            if remain.is_empty() {
                return 0;
            }
            remain
        } else {
            specify
        };
        let match_count = self
            .rules
            .iter()
            .filter(|rule| rule.get_name() == rule_name)
            .count();
        usize::from(match_count == 1)
    }

    // Ghidra: action.cc:789 ActionPool::getSubRule target selection
    fn mutate_rule_target(&mut self, specify: &str, mutation: RuleTargetMutation) -> bool {
        let (token, remain) = next_specify_term(specify);
        let rule_name = if self.name == token {
            if remain.is_empty() {
                return false;
            }
            remain
        } else {
            specify
        };
        let mut matches = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.get_name() == rule_name)
            .map(|(index, _)| index);
        let Some(index) = matches.next() else {
            return false;
        };
        if matches.next().is_some() {
            return false;
        }
        match mutation {
            RuleTargetMutation::Break(tp) => self.rule_states[index].set_break(tp),
            RuleTargetMutation::Warning(value) => self.rule_states[index].set_warning(value),
            RuleTargetMutation::Disabled(value) => self.rule_states[index].set_disabled(value),
        }
        true
    }

    // Ghidra: action.cc:890 ActionPool::clearBreakPoints
    fn clear_rule_break_points(&mut self) {
        for state in &mut self.rule_states {
            state.clear_break_points();
        }
    }

    // Ghidra: action.cc:926 ActionPool::resetStats
    fn reset_rule_stats(&mut self) {
        for (rule, state) in self.rules.iter_mut().zip(self.rule_states.iter_mut()) {
            state.reset_stats();
            rule.reset_stats();
        }
    }

    // RUGRA-GLUE: Rust cursor reconstruction for Ghidra's retained PcodeOpTree::const_iterator
    fn first_op(fd: &Funcdata) -> Option<crate::arena::OpId> {
        fd.obank.optree.first_id()
    }

    // RUGRA-GLUE: strict-successor reconstruction for Ghidra's op_state++
    // iterator mutation. ACTIONLOOP-RESTART-0001 established the strict-key
    // range successor as the `++` of the oracle's live map iterator.
    // PERF-ARENA-FLIP-0001 (c): the cursor holds the current OpId, so the
    // range bound is the cell's denormalized seq_key — a lock-free arena
    // read replacing the per-advance op guard (SeqNum read + SpaceOff
    // projection) and the successor Arc clone of the handle-cursor form.
    fn next_op_after(fd: &Funcdata, current: crate::arena::OpId) -> Option<crate::arena::OpId> {
        fd.obank.optree.next_id_after(current)
    }

    // RUGRA-GLUE: advances the externalized PcodeOpTree iterator without
    // holding a Rust borrow across Rule mutation. ACTIONLOOP-RESTART-0001:
    // the current element is an OpId (Copy) — the successor search reads
    // only the cell's stored key.
    fn advance_op_state(&mut self, fd: &Funcdata, current: crate::arena::OpId) {
        self.op_state = Self::next_op_after(fd, current);
    }

    // Ghidra: action.cc:822 ActionPool::processOp
    fn process_op(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // ACTIONLOOP-RESTART-0001: take ownership of the cursor element for
        // this step (Ghidra's op_state iterator hands the element to
        // processOp by pointer, action.cc:885). The id cursor resolves the
        // handle once per visit; Rules receive it by reference and the
        // breakpoint-resume path parks the cursor as a Copy id.
        let op_id = self
            .op_state
            .expect("processOp requires a current PcodeOpTree element");
        action_stats::bump(&action_stats::STATS.ops_visited);
        // The one per-visit handle resolution (Ghidra hands processOp the
        // bare PcodeOp*; the Arc clone replaces the former cursor-held
        // clone taken by next_op_after — one reference-count round-trip per
        // visited op either way).
        let op_arc = std::sync::Arc::clone(
            &fd.obank
                .op_by_id(op_id)
                .expect("processOp cursor cell vanished")
                .0,
        );
        // Single read of the entry state the oracle reads as isDead
        // (action.cc:829); the initial `opc = op->code()` (:835) resolves
        // lock-free through the cell's denormalized opcode shadow.
        let is_dead = op_arc.read().unwrap().is_dead();
        if is_dead {
            self.advance_op_state(fd, op_id);
            fd.obank.destroy(crate::op::PcodeOpRef(op_arc));
            self.rule_index = 0;
            return Ok(0);
        }
        let mut opcode = fd
            .obank
            .opcode_of(op_id)
            .expect("processOp cursor cell vanished");

        loop {
            // perop[opc] array dispatch (action.cc:836-837) — the
            // bucket read per rule iteration is an array index, not a
            // SipHash probe.
            let Some(rule_index) = self
                .per_op[opcode as i32 as usize]
                .get(self.rule_index)
                .copied()
            else {
                break;
            };
            self.rule_index += 1;
            if self.rule_states[rule_index].is_disabled() {
                continue;
            }

            // OPACTION_DEBUG-equivalent drill pair (action.cc:839-845):
            // activate before each rule application, flush under the rule's
            // leaf name after; the enclosing pool perform's own pair becomes
            // a no-op via the active-flag reset, as in the oracle.
            // PERF-OPPOOL-0001: the flush call site guards on the same env
            // gate so the per-try vtable name fetch is skipped when the
            // drill is off (flush itself no-ops then; its bool is discarded).
            crate::drillobserve::activate();
            action_stats::bump(&action_stats::STATS.rule_tries);
            self.rule_states[rule_index].count_tests += 1;
            let result = self.rules[rule_index].apply_op(&op_arc, fd)?;
            if crate::drillobserve::is_enabled() {
                crate::drillobserve::flush(self.rules[rule_index].get_name());
            }
            if result > 0 {
                action_stats::bump(&action_stats::STATS.rule_hits);
                self.rule_states[rule_index].count_apply += 1;
                self.pending_count += result;
                let rule_name = self.rules[rule_index].get_name();
                self.rule_states[rule_index].issue_warning(fd, rule_name);
                if self.rule_states[rule_index].check_action_break() {
                    // Breakpoint resume keeps op_state parked on this op,
                    // exactly like the oracle's retained op_state
                    // (action.cc:851-852 returns with the iterator still
                    // pointing here).
                    self.op_state = Some(op_id);
                    return Ok(-1);
                }
                // cc:846 `if (op->isDead()) break;` — the flag read stays a
                // guarded read (the DEAD bit has no cell shadow); the
                // follow-up `opc != op->code()` (:847-849) is the lock-free
                // shadow read.
                let now_dead = op_arc.read().unwrap().is_dead();
                if now_dead {
                    break;
                }
                let new_opcode = fd
                    .obank
                    .opcode_of(op_id)
                    .expect("processOp cursor cell vanished");
                if new_opcode != opcode {
                    opcode = new_opcode;
                    self.rule_index = 0;
                }
            } else {
                // cc:853-857 `else if (opc != op->code())` — the lying-rule
                // audit re-read every miss. SPEEDPROF2 §2 measured this as
                // 27.7M RwLock round-trips on the VdbeExec pole; the shadow
                // read below is a plain arena cell load.
                let new_opcode = fd
                    .obank
                    .opcode_of(op_id)
                    .expect("processOp cursor cell vanished");
                if new_opcode != opcode {
                    let message = format!(
                        "ERROR: Rule {} changed op without returning result of 1!",
                        self.rules[rule_index].get_name(),
                    );
                    if let Some(arch) = fd.get_arch() {
                        arch.print_message(&message);
                    } else {
                        eprintln!("{message}");
                    }
                    opcode = new_opcode;
                    self.rule_index = 0;
                }
            }
        }

        self.advance_op_state(fd, op_id);
        self.rule_index = 0;
        Ok(0)
    }

    // Ghidra: action.cc:877 ActionPool::apply
    fn apply_from_status(&mut self, fd: &mut Funcdata, status: u32) -> Result<i32> {
        if status != status_flags::STATUS_MID {
            self.op_state = Self::first_op(fd);
            self.rule_index = 0;
        }
        action_stats::bump(&action_stats::STATS.pool_passes);
        let count_before = self.pending_count;
        while self.op_state.is_some() {
            if self.process_op(fd)? != 0 {
                return Ok(-1);
            }
        }
        if std::env::var("RUGRA_RULE_STATS").is_ok_and(|value| value == "1")
            && self.pending_count > count_before
        {
            eprintln!(
                "[RULESTATS] {} pool={} pass_changes={}",
                fd.name,
                self.name,
                self.pending_count - count_before,
            );
        }
        Ok(0)
    }
}

impl Action for ActionPool {
    // Ghidra: action.cc:877 ActionPool::apply
    /// Single-pass Rule application over the live, SeqNum-ordered PcodeOpTree.
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        self.apply_from_status(fd, status_flags::STATUS_START)
    }

    // RUGRA-GLUE: makes ActionPool::apply observe the externalized inherited status for exact breakpoint resume
    fn apply_with_state(&mut self, fd: &mut Funcdata, state: &mut ActionState) -> Result<i32> {
        self.apply_from_status(fd, state.status)
    }

    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { &self.name }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_flags(&self) -> u32 { self.flags }

    // Ghidra: action.cc:899 Action *ActionPool::clone(const ActionGroupList &grouplist) const
    fn clone_for_groups(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        self.clone_pool(grouplist)
            .map(|pool| Box::new(pool) as Box<dyn Action>)
    }

    // RUGRA-GLUE: fixture-only pool view (see Action::as_action_pool)
    fn as_action_pool(&self) -> Option<&ActionPool> { Some(self) }
    // RUGRA-GLUE: fixture/debug mutable pool view (see Action::as_action_pool_mut)
    fn as_action_pool_mut(&mut self) -> Option<&mut ActionPool> { Some(self) }

    // RUGRA-GLUE: externalizes ActionPool's inherited count while apply preserves Ghidra's zero control-flow return
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.pending_count)
    }

    // Ghidra: action.cc:916 ActionPool::reset
    fn reset(&mut self, fd: &mut Funcdata) {
        for (rule, state) in self.rules.iter_mut().zip(self.rule_states.iter_mut()) {
            rule.reset_for_function(fd, state);
        }
    }
}

// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
/// Build the oppool1 `ActionPool` mirroring Ghidra's `actprop`
/// (coreaction.cc:5511-5649). Pool name is "oppool1" exactly as
/// `new ActionPool(Action::rule_repeatapply,"oppool1")` (:5511).
///
/// Every Rule is registered unconditionally (the raw universal tree,
/// coreaction.cc:5462-5738); each `register_rule!` slot retains the
/// basegroup string of the oracle ctor call so `ActionPool::clone`
/// (action.cc:899-914) performs the grouplist filtering on a fresh
/// factory instance, and a pool with no surviving Rule clones to null
/// exactly as the oracle's `res == (ActionPool*)0` result is dropped by
/// `ActionGroup::clone` (action.cc:397-405).
pub fn build_oppool1() -> ActionPool {
    use crate::ruleaction::*;
    let mut pool = ActionPool::new("oppool1");
    // Mirrors Ghidra's oppool1 (coreaction.cc:5511-5649) — the universal
    // simplification pool applied repeatedly to a fixed point. Rules are
    // registered in Ghidra's exact order so their interactions match.
    // Entries whose Rust port does not yet exist are noted as skipped.

    register_rule!(pool, "deadcode", Box::new(RuleEarlyRemoval::new()));       // 5512 — six guards; doesDeadcode spaces are gated by Heritage pass/delay
    register_rule!(pool, "analysis", Box::new(RuleTermOrder::new()));          // 5513
    register_rule!(pool, "analysis", Box::new(RuleSelectCse::new()));          // 5514
    register_rule!(pool, "analysis", Box::new(RuleCollectTerms::new()));       // 5515
    register_rule!(pool, "analysis", Box::new(RulePullsubMulti::new()));       // 5516
    register_rule!(pool, "analysis", Box::new(RulePullsubIndirect::new()));    // 5517
    register_rule!(pool, "nodejoin", Box::new(RulePushMulti::new()));          // 5518
    register_rule!(pool, "analysis", Box::new(RuleSborrow::new()));            // 5519
    register_rule!(pool, "analysis", Box::new(RuleScarry::new()));             // 5520
    register_rule!(pool, "analysis", Box::new(RuleIntLessEqual::new()));       // 5521
    register_rule!(pool, "analysis", Box::new(RuleTrivialArith::new()));       // 5522
    register_rule!(pool, "analysis", Box::new(RuleTrivialBool::new()));        // 5523
    register_rule!(pool, "analysis", Box::new(RuleTrivialShift::new()));       // 5524
    register_rule!(pool, "analysis", Box::new(RuleSignShift::new()));          // 5525
    register_rule!(pool, "analysis", Box::new(RuleTestSign::new()));           // 5526
    register_rule!(pool, "analysis", Box::new(RuleIdentityEl::new()));         // 5527
    register_rule!(pool, "analysis", Box::new(RuleOrMask::new()));             // 5528
    register_rule!(pool, "analysis", Box::new(RuleAndMask::new()));            // 5529
    register_rule!(pool, "analysis", Box::new(RuleOrConsume::new()));          // 5530
    register_rule!(pool, "analysis", Box::new(RuleOrCollapse::new()));         // 5531
    register_rule!(pool, "analysis", Box::new(RuleAndOrLump::new()));          // 5532
    register_rule!(pool, "analysis", Box::new(RuleShiftBitops::new()));        // 5533
    register_rule!(pool, "analysis", Box::new(RuleRightShiftAnd::new()));      // 5534
    register_rule!(pool, "analysis", Box::new(RuleNotDistribute::new()));      // 5535
    register_rule!(pool, "analysis", Box::new(RuleHighOrderAnd::new()));       // 5536
    register_rule!(pool, "analysis", Box::new(RuleAndDistribute::new()));      // 5537
    register_rule!(pool, "analysis", Box::new(RuleAndCommute::new()));         // 5538
    register_rule!(pool, "analysis", Box::new(RuleAndPiece::new()));           // 5539
    register_rule!(pool, "analysis", Box::new(RuleAndZext::new()));            // 5540
    register_rule!(pool, "analysis", Box::new(RuleAndCompare::new()));         // 5541
    register_rule!(pool, "analysis", Box::new(RuleDoubleSub::new()));          // 5542
    register_rule!(pool, "analysis", Box::new(RuleDoubleShift::new()));        // 5543
    register_rule!(pool, "analysis", Box::new(RuleDoubleArithShift::new()));   // 5544
    register_rule!(pool, "analysis", Box::new(RuleConcatShift::new()));        // 5545
    register_rule!(pool, "analysis", Box::new(RuleLeftRight::new()));          // 5546
    register_rule!(pool, "analysis", Box::new(RuleShiftCompare::new()));       // 5547
    register_rule!(pool, "analysis", Box::new(RuleShift2Mult::new()));         // 5548
    register_rule!(pool, "analysis", Box::new(RuleShiftPiece::new()));     // 5549 — (zext(V)<<sa)|zext(V) => PIECE (ruleaction.cc:3791)
    register_rule!(pool, "analysis", Box::new(RuleMultiCollapse::new()));      // 5550
    register_rule!(pool, "analysis", Box::new(RuleIndirectCollapse::new()));   // 5551
    register_rule!(pool, "analysis", Box::new(Rule2Comp2Mult::new()));         // 5552
    register_rule!(pool, "analysis", Box::new(RuleSub2Add::new()));            // 5553
    register_rule!(pool, "analysis", Box::new(RuleCarryElim::new()));          // 5554
    register_rule!(pool, "analysis", Box::new(RuleBxor2NotEqual::new()));      // 5555
    register_rule!(pool, "analysis", Box::new(RuleLess2Zero::new()));          // 5556
    register_rule!(pool, "analysis", Box::new(RuleLessEqual2Zero::new()));     // 5557
    register_rule!(pool, "analysis", Box::new(RuleSLess2Zero::new()));     // 5558 — INT_SLESS with 0/-1 simplification (ruleaction.cc:5711)
    register_rule!(pool, "analysis", Box::new(RuleEqual2Zero::new()));         // 5559
    register_rule!(pool, "analysis", Box::new(RuleEqual2Constant::new()));     // 5560
    register_rule!(pool, "analysis", Box::new(RuleThreeWayCompare::new()));    // 5561
    register_rule!(pool, "analysis", Box::new(RuleXorCollapse::new()));        // 5562
    register_rule!(pool, "analysis", Box::new(RuleAddMultCollapse::new()));    // 5563
    register_rule!(pool, "analysis", Box::new(RuleCollapseConstants::new()));  // 5564
    register_rule!(pool, "analysis", Box::new(RuleTransformCpool::new()));     // 5565
    register_rule!(pool, "analysis", Box::new(RulePropagateCopy::new()));      // 5566
    register_rule!(pool, "analysis", Box::new(RuleZextEliminate::new()));      // 5567
    register_rule!(pool, "analysis", Box::new(RuleSlessToLess::new()));        // 5568
    register_rule!(pool, "analysis", Box::new(RuleZextSless::new()));          // 5569
    register_rule!(pool, "analysis", Box::new(RuleBitUndistribute::new()));    // 5570
    register_rule!(pool, "analysis", Box::new(RuleBooleanUndistribute::new())); // 5571
    register_rule!(pool, "analysis", Box::new(RuleBooleanDedup::new()));       // 5572
    register_rule!(pool, "analysis", Box::new(RuleBoolZext::new()));           // 5573
    register_rule!(pool, "analysis", Box::new(RuleBooleanNegate::new()));      // 5574
    register_rule!(pool, "analysis", Box::new(RuleLogic2Bool::new()));         // 5575
    register_rule!(pool, "analysis", Box::new(RuleSubExtComm::new()));         // 5576
    register_rule!(pool, "analysis", Box::new(RuleSubCommute::new()));        // 5577 — SUBPIECE commute with binary ops (ruleaction.cc:4534)
    register_rule!(pool, "analysis", Box::new(RuleConcatCommute::new()));      // 5578
    register_rule!(pool, "analysis", Box::new(RuleConcatZext::new()));         // 5579
    register_rule!(pool, "analysis", Box::new(RuleZextCommute::new()));        // 5580
    register_rule!(pool, "analysis", Box::new(RuleZextShiftZext::new()));      // 5581
    register_rule!(pool, "analysis", Box::new(RuleShiftAnd::new()));           // 5582
    register_rule!(pool, "analysis", Box::new(RuleConcatZero::new()));         // 5583
    register_rule!(pool, "analysis", Box::new(RuleConcatLeftShift::new()));    // 5584
    register_rule!(pool, "analysis", Box::new(RuleSubZext::new()));            // 5585
    register_rule!(pool, "analysis", Box::new(RuleSubCancel::new()));          // 5586
    register_rule!(pool, "analysis", Box::new(RuleShiftSub::new()));           // 5587
    register_rule!(pool, "analysis", Box::new(RuleHumptyDumpty::new()));       // 5588
    register_rule!(pool, "analysis", Box::new(RuleDumptyHump::new()));         // 5589
    register_rule!(pool, "analysis", Box::new(RuleHumptyOr::new()));           // 5590
    register_rule!(pool, "analysis", Box::new(RuleNegateIdentity::new()));     // 5591
    register_rule!(pool, "analysis", Box::new(RuleSubNormal::new()));          // 5592
    register_rule!(pool, "analysis", Box::new(RulePositiveDiv::new()));        // 5593
    register_rule!(pool, "analysis", Box::new(RuleDivTermAdd::new()));    // 5594 — optimized division term add (ruleaction.cc:7832)
    register_rule!(pool, "analysis", Box::new(RuleDivTermAdd2::new()));   // 5595 — optimized division term add variant (ruleaction.cc:7955)
    register_rule!(pool, "analysis", Box::new(RuleDivOpt::new()));             // 5596
    register_rule!(pool, "analysis", Box::new(RuleSignForm::new()));           // 5597
    register_rule!(pool, "analysis", Box::new(RuleSignForm2::new()));          // 5598
    register_rule!(pool, "analysis", Box::new(RuleSignDiv2::new()));           // 5599
    register_rule!(pool, "analysis", Box::new(RuleDivChain::new()));           // 5600
    register_rule!(pool, "analysis", Box::new(RuleSignNearMult::new()));       // 5601
    register_rule!(pool, "analysis", Box::new(RuleModOpt::new()));         // 5602 — x/d*(-d)+x => x%d (ruleaction.cc:8612)
    register_rule!(pool, "analysis", Box::new(RuleSignMod2nOpt::new()));       // 5603
    register_rule!(pool, "analysis", Box::new(RuleSignMod2nOpt2::new())); // 5604 — V-(Vadj&~(2^n-1)) => V s% 2^n (ruleaction.cc:8867)
    register_rule!(pool, "analysis", Box::new(RuleSignMod2Opt::new()));  // 5605 — (V-sign)&1+sign => V s% 2 (ruleaction.cc:8794)
    register_rule!(pool, "analysis", Box::new(RuleSwitchSingle::new()));       // 5606
    register_rule!(pool, "analysis", Box::new(RuleCondNegate::new()));         // 5607
    register_rule!(pool, "analysis", Box::new(RuleBoolNegate::new()));         // 5608
    register_rule!(pool, "analysis", Box::new(RuleLessEqual::new()));          // 5609
    register_rule!(pool, "analysis", Box::new(RuleLessNotEqual::new()));       // 5610
    register_rule!(pool, "analysis", Box::new(RuleLessOne::new()));            // 5611
    register_rule!(pool, "analysis", Box::new(RuleRangeMeld::new()));          // 5612
    register_rule!(pool, "analysis", Box::new(RuleFloatRange::new()));         // 5613
    register_rule!(pool, "analysis", Box::new(RulePiece2Zext::new()));         // 5614
    register_rule!(pool, "analysis", Box::new(RulePiece2Sext::new()));         // 5615
    register_rule!(pool, "analysis", Box::new(RulePopcountBoolXor::new())); // 5616 — popcount parity to XOR (ruleaction.cc:10265)
    register_rule!(pool, "analysis", Box::new(RuleXorSwap::new()));            // 5617
    register_rule!(pool, "analysis", Box::new(RuleLzcountShiftBool::new()));   // 5618
    register_rule!(pool, "analysis", Box::new(RuleFloatSign::new()));       // 5619 — float sign-bit manipulation (ruleaction.cc:10714)
    register_rule!(pool, "analysis", Box::new(RuleOrCompare::new()));          // 5620
    // subvar family (subflow.cc, coreaction.cc:5621-5628) — SubvariableFlow
    register_rule!(
        pool, "subvar", Box::new(crate::subflow::RuleSubvarAnd::new())
    );       // 5621
    register_rule!(
        pool, "subvar", Box::new(crate::subflow::RuleSubvarSubpiece::new())
    );  // 5622
    register_rule!(
        pool, "subvar", Box::new(crate::subflow::RuleSplitFlow::new())
    );       // 5623
    register_rule!(pool, "subvar", Box::new(RulePtrFlow::new()));           // 5624
    register_rule!(
        pool, "subvar", Box::new(crate::subflow::RuleSubvarCompZero::new())
    );  // 5625
    register_rule!(
        pool, "subvar", Box::new(crate::subflow::RuleSubvarShift::new())
    );     // 5626
    register_rule!(
        pool, "subvar", Box::new(crate::subflow::RuleSubvarZext::new())
    );      // 5627
    register_rule!(
        pool, "subvar", Box::new(crate::subflow::RuleSubvarSext::new())
    );      // 5628
    register_rule!(pool, "analysis", Box::new(RuleNegateNegate::new()));       // 5629
    register_rule!(pool, "conditionalexe", Box::new(RuleConditionalMove::new()));    // 5630
    register_rule!(
        pool, "conditionalexe", Box::new(crate::condexe::RuleOrPredicate::new())
    ); // 5631
    register_rule!(pool, "analysis", Box::new(RuleFuncPtrEncoding::new()));    // 5632
    register_rule!(
        pool, "floatprecision", Box::new(crate::subflow::RuleSubfloatConvert::new())
    ); // 5633
    register_rule!(pool, "floatprecision", Box::new(RuleFloatCast::new()));          // 5634 — registered here per Ghidra (coreaction.cc:5634)
    register_rule!(pool, "floatprecision", Box::new(RuleIgnoreNan::new()));          // 5635
    register_rule!(pool, "analysis", Box::new(RuleUnsigned2Float::new()));     // 5636
    register_rule!(pool, "analysis", Box::new(RuleInt2FloatCollapse::new()));  // 5637
    register_rule!(pool, "typerecovery", Box::new(RulePtraddUndo::new()));         // 5638
    register_rule!(pool, "typerecovery", Box::new(RulePtrsubUndo::new()));         // 5639
    register_rule!(pool, "segment", Box::new(RuleSegment::new()));            // 5640
    register_rule!(pool, "protorecovery", Box::new(RulePiecePathology::new()));     // 5641
    // skip 5642 (gap in Ghidra numbering — reserved)
    register_rule!(
        pool, "doubleload", Box::new(crate::double_precis::RuleDoubleLoad::new())
    );  // 5643
    register_rule!(
        pool, "doubleprecis", Box::new(crate::double_precis::RuleDoubleStore::new())
    ); // 5644
    register_rule!(
        pool, "doubleprecis", Box::new(crate::double_precis::RuleDoubleIn::new())
    );    // 5645
    register_rule!(
        pool, "doubleprecis", Box::new(crate::double_precis::RuleDoubleOut::new())
    );   // 5646

    // Pool ends at RuleDoubleOut (5646), exactly as Ghidra's oppool1. The
    // remaining oracle loop (coreaction.cc:5647-5649) only absorbs
    // CPU-specific conf->extra_pool_rules, of which the x86-64 gcc spec
    // registers none. PIPE-POOL-LOCAL-RULES-0001 removed the former
    // Rugra-local registrations of RuleSextEliminate (no oracle class at
    // all) and RuleEquality (oracle class exists, ruleaction.hh:243, but
    // is never instantiated anywhere in the locked tree).
    // NOTE: RuleMultNegOne (x*-1 -> INT_2COMP) and Rule2Comp2Sub are NOT here
    // — they belong in the separate cleanup pool (see build_cleanup_pool) per
    // Ghidra coreaction.cc:5694-5710. Putting them in oppool1 alongside
    // Rule2Comp2Mult (which does the reverse) causes an infinite ping-pong;
    // Ghidra avoids it by PHASE SEPARATION (main pool converges first, then
    // cleanup pool runs once).
    pool
}

// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
/// Build the cleanup `ActionPool` mirroring Ghidra's `actcleanup`
/// (coreaction.cc:5694-5710). Runs AFTER the main simplify pool so that
/// canonical forms produced by oppool1 (e.g. INT_MULT(x,-1) from
/// Rule2Comp2Mult) get cleaned up to their final form (INT_2COMP) without
/// ping-ponging — the main pool has already converged, so the reverse
/// transform here cannot re-trigger Rule2Comp2Mult.
///
/// Grouplist filtering is performed by `ActionPool::clone`
/// (action.cc:899-914) from the registration-slot group and factory: a
/// Rule survives iff its basegroup is in the list; no survivors clones
/// the pool to null (`None`).
pub fn build_cleanup_pool() -> ActionPool {
    use crate::ruleaction::*;
    let mut pool = ActionPool::new("cleanup");
    register_rule!(pool, "cleanup", Box::new(RuleMultNegOne::new()));   // coreaction.cc:5696
    register_rule!(pool, "cleanup", Box::new(RuleAddUnsigned::new()));  // 5697
    register_rule!(pool, "cleanup", Box::new(Rule2Comp2Sub::new()));    // 5698
    register_rule!(
        pool, "cleanup", Box::new(crate::subflow::RuleDumptyHumpLate::new())
    ); // 5699
    register_rule!(pool, "cleanup", Box::new(RuleSubRight::new()));     // 5700
    register_rule!(pool, "cleanup", Box::new(RuleFloatSignCleanup::new())); // 5701
    register_rule!(pool, "cleanup", Box::new(RuleExpandLoad::new()));   // 5702
    register_rule!(pool, "cleanup", Box::new(RulePtrsubCharConstant::new())); // 5703
    register_rule!(pool, "cleanup", Box::new(RuleExtensionPush::new())); // 5704
    register_rule!(pool, "cleanup", Box::new(RulePieceStructure::new())); // 5705
    register_rule!(
        pool, "splitcopy", Box::new(crate::subflow::RuleSplitCopy::new())
    );  // 5706
    register_rule!(
        pool, "splitpointer", Box::new(crate::subflow::RuleSplitLoad::new())
    );  // 5707
    register_rule!(
        pool, "splitpointer", Box::new(crate::subflow::RuleSplitStore::new())
    ); // 5708
    // RuleStringCopy / RuleStringStore are wired (constseq.cc:954-1002).
    // Detection phase only — transform requires CALLOTHER/userop infrastructure
    // (tracked as a follow-up; matches Ghidra registration at 5709-5710).
    register_rule!(
        pool, "constsequence", Box::new(crate::constseq::RuleStringCopy::new())
    );   // coreaction.cc:5709
    register_rule!(
        pool, "constsequence", Box::new(crate::constseq::RuleStringStore::new())
    );  // coreaction.cc:5710
    // Pool ends at RuleStringStore (5710), exactly as Ghidra's actcleanup
    // (coreaction.cc:5694-5711). PIPE-POOL-LOCAL-RULES-0001 removed the
    // former Rugra-local re-registration of RuleTrivialArith here — the
    // oracle cleanup pool has no such entry; Ghidra registers
    // RuleTrivialArith exactly once, in oppool1 (coreaction.cc:5522).
    pool
}

/// Ghidra: action.hh:31-40 `ActionGroupList`
///
/// The set of group names steering a root-Action derivation. Any Rule or
/// leaf Action belongs to a group; the groups in this list together define
/// which children survive `ActionDatabase::deriveAction`'s selective clone.
#[derive(Debug, Clone)]
pub struct ActionGroupList {
    groups: std::collections::BTreeSet<String>,
}

impl ActionGroupList {
    // RUGRA-GLUE: static-member constructor (Ghidra fills the same set via ActionDatabase::setGroup's argv, action.cc:1059-1070; addToGroup/removeFromGroup mutate it with runtime strings, action.cc:1090-1109)
    pub fn from_members(members: &[&'static str]) -> Self {
        Self {
            groups: members.iter().map(|m| m.to_string()).collect(),
        }
    }

    // Ghidra: action.hh:39 ActionGroupList::contains
    pub fn contains(&self, nm: &str) -> bool {
        self.groups.contains(nm)
    }

    // RUGRA-GLUE: read-only fixture view of the private set in sorted order (the C++ fixtures read ActionGroupList::list through their private-access hack; std::set<string> and BTreeSet<String> iterate in the same lexicographic order)
    pub fn member_names(&self) -> Vec<&str> {
        self.groups.iter().map(|s| s.as_str()).collect()
    }
}

/// Ghidra: coreaction.cc:5419-5458 `ActionDatabase::buildDefaultGroups` —
/// the preconfigured root-Action grouplists, verbatim member order (set
/// semantics; order is not observable through `contains`).
pub mod default_groups {
    /// `setGroup("decompile", members)` — coreaction.cc:5424-5432. The
    /// default decompilation root. Note what is ABSENT: `normalanalysis`,
    /// `noproto`, `protorecovery_b`, `siganalysis`, `normalizebranches`.
    pub const DECOMPILE: &[&str] = &[
        "base", "protorecovery", "protorecovery_a", "deindirect", "localrecovery",
        "deadcode", "typerecovery", "stackptrflow",
        "blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
        "cleanup", "splitcopy", "splitpointer", "merge", "dynamic", "casts", "analysis",
        "fixateglobals", "fixateproto", "constsequence",
        "segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
        "unreachable", "subvar", "floatprecision",
        "conditionalexe",
    ];
    /// `setGroup("jumptable", jumptab)` — coreaction.cc:5434-5436.
    pub const JUMPTABLE: &[&str] = &[
        "base", "noproto", "localrecovery", "deadcode", "stackptrflow",
        "stackvars", "analysis", "segment", "subvar", "normalizebranches",
        "conditionalexe",
    ];
    /// `setGroup("normalize", normali)` — coreaction.cc:5438-5443.
    pub const NORMALIZE: &[&str] = &[
        "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
        "deadcode", "stackptrflow", "normalanalysis",
        "stackvars", "deadcontrolflow", "analysis", "fixateproto", "nodejoin",
        "unreachable", "subvar", "floatprecision", "normalizebranches",
        "conditionalexe",
    ];
    /// `setGroup("paramid", paramid)` — coreaction.cc:5445-5450.
    pub const PARAMID: &[&str] = &[
        "base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
        "deadcode", "typerecovery", "stackptrflow", "siganalysis",
        "stackvars", "deadcontrolflow", "analysis", "fixateproto",
        "unreachable", "subvar", "floatprecision",
        "conditionalexe",
    ];
    /// `setGroup("register", regmemb)` — coreaction.cc:5452-5453.
    pub const REGISTER: &[&str] = &["base", "analysis", "subvar"];
    /// `setGroup("firstpass", firstmem)` — coreaction.cc:5455-5456.
    pub const FIRSTPASS: &[&str] = &["base"];
}

///
/// Corresponds to Ghidra's `ActionDatabase` class (action.hh:298-324)
pub struct ActionDatabase {
    /// Ghidra `actionmap` (action.hh:302): registered root Actions by name.
    /// Entries hold `None` for a derived root whose clone was null — Ghidra
    /// registers the null clone under its group name too (action.cc:1158).
    actionmap: Vec<(String, Option<Box<dyn Action>>)>,
    /// Ghidra `groupmap` (action.hh:301): root name → steering grouplist.
    groupmap: Vec<(String, ActionGroupList)>,
    /// Ghidra `currentact` (action.hh:299): the current root Action.
    currentact: Option<usize>,
    /// Ghidra `currentactname` (action.hh:300).
    currentactname: String,
    /// Ghidra `isDefaultGroups` (action.hh:303).
    is_default_groups: bool,
}
// RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
/// Build the oppool2 `ActionPool` mirroring Ghidra's `actprop2`
/// (coreaction.cc:5662-5671). These are type-recovery / stack-variable Rules
/// that run after oppool1 within the main loop.
///
/// Grouplist filtering is performed by `ActionPool::clone`
/// (action.cc:899-914) from the registration-slot group and factory: a
/// Rule survives iff its basegroup is in the list; no survivors clones
/// the pool to null (`None`) — e.g. the "register" root drops oppool2
/// entirely because neither "typerecovery" nor "stackvars" is a member.
pub fn build_oppool2() -> ActionPool {
    use crate::ruleaction::*;
    let mut pool = ActionPool::new("oppool2");
    register_rule!(pool, "typerecovery", Box::new(RulePushPtr::new()));           // 5664
    register_rule!(pool, "typerecovery", Box::new(RuleStructOffset0::new()));     // 5665
    register_rule!(pool, "typerecovery", Box::new(RulePtrArith::new()));          // 5666
    register_rule!(pool, "stackvars", Box::new(RuleLoadVarnode::new()));       // 5668
    register_rule!(pool, "stackvars", Box::new(RuleStoreVarnode::new()));      // 5669
    pool
}

impl ActionDatabase {
    // Ghidra: action.hh:310 ActionDatabase::ActionDatabase
    pub fn new() -> Self {
        Self {
            actionmap: Vec::new(),
            groupmap: Vec::new(),
            currentact: None,
            currentactname: String::new(),
            is_default_groups: false,
        }
    }

    // Ghidra: action.cc:1126 ActionDatabase::registerAction
    /// Register a root Action under `nm`; the database takes ownership
    /// (Ghidra deletes a previously registered object of the same name).
    fn register_action_named(&mut self, nm: &str, act: Option<Box<dyn Action>>) {
        if let Some(idx) = self.actionmap.iter().position(|(key, _)| key == nm) {
            self.actionmap[idx].1 = act;
        } else {
            self.actionmap.push((nm.to_string(), act));
        }
    }

    // RUGRA-GLUE: legacy pub registration under the Action's own name (Ghidra registers roots by explicit key only)
    pub fn register_action(&mut self, action: Box<dyn Action>) {
        let nm = action.get_name().to_string();
        self.register_action_named(&nm, Some(action));
    }

    // Ghidra: action.cc:1112 ActionDatabase::getAction (index lookup form)
    fn action_index(&self, nm: &str) -> Option<usize> {
        self.actionmap.iter().position(|(key, _)| key == nm)
    }

    // RUGRA-GLUE: pub lookup mirroring Ghidra getAction's throw as None
    pub fn get_action(&self, name: &str) -> Option<&dyn Action> {
        self.action_index(name)
            .and_then(|idx| self.actionmap[idx].1.as_deref())
    }

    // RUGRA-GLUE: pub mutable lookup mirroring Ghidra getAction's throw as None
    pub fn get_action_mut(&mut self, name: &str) -> Option<&mut (dyn Action + '_)> {
        let idx = self.action_index(name)?;
        let action = self.actionmap[idx].1.as_mut()?;
        Some(action.as_mut())
    }

    // RUGRA-GLUE: distinguishes Ghidra actionmap's cached null clone from an absent map key for fixtures and callers avoiding getCurrent on null
    pub fn has_action_entry(&self, name: &str) -> bool {
        self.action_index(name).is_some()
    }

    // RUGRA-GLUE: read-only fixture view of the registry size (the C++ fixtures read actionmap.size() through their private-access hack)
    pub fn actionmap_size(&self) -> usize {
        self.actionmap.len()
    }

    // Ghidra: action.cc:1059 ActionDatabase::setGroup (member-list form)
    pub fn set_group(&mut self, grp: &str, members: &[&'static str]) {
        let grouplist = ActionGroupList::from_members(members);
        if let Some(idx) = self.groupmap.iter().position(|(key, _)| key == grp) {
            self.groupmap[idx].1 = grouplist;
        } else {
            self.groupmap.push((grp.to_string(), grouplist));
        }
        self.is_default_groups = false;
    }

    // Ghidra: action.cc:1006 ActionDatabase::getGroup
    pub fn get_group(&self, grp: &str) -> Option<&ActionGroupList> {
        self.groupmap
            .iter()
            .find(|(key, _)| key == grp)
            .map(|(_, list)| list)
    }

    // Ghidra: coreaction.cc:5419 ActionDatabase::buildDefaultGroups
    fn build_default_groups(&mut self) {
        if self.is_default_groups {
            return;
        }
        self.groupmap.clear();
        self.set_group("decompile", default_groups::DECOMPILE);
        self.set_group("jumptable", default_groups::JUMPTABLE);
        self.set_group("normalize", default_groups::NORMALIZE);
        self.set_group("paramid", default_groups::PARAMID);
        self.set_group("register", default_groups::REGISTER);
        self.set_group("firstpass", default_groups::FIRSTPASS);
        self.is_default_groups = true;
    }

    // Ghidra: coreaction.cc:5462 ActionDatabase::universalAction
    /// Build the raw universal Action and register it under "universal"
    /// (Ghidra `registerAction(universalname, act)`, coreaction.cc:5475).
    pub fn universal_action(&mut self) {
        let act = universal_action(None).expect("universal root always survives");
        self.register_action_named("universal", Some(Box::new(act)));
    }

    // Ghidra: action.cc:986 ActionDatabase::resetDefaults
    /// Clear out (possibly altered) root Actions, reset the default groups,
    /// and set the default root action "decompile".
    pub fn reset_defaults(&mut self) {
        // Keep the registered universal; delete every other old root
        // (action.cc:991-999), then re-register universal in a cleared map.
        let universal = self
            .action_index("universal")
            .map(|idx| self.actionmap.remove(idx));
        self.actionmap.clear();
        if let Some((_, act)) = universal {
            self.actionmap.push(("universal".to_string(), act));
        }
        self.build_default_groups();
        self.set_current("decompile"); // The default root action (action.cc:1003)
    }

    // Ghidra: action.cc:1021 ActionDatabase::setCurrent
    pub fn set_current(&mut self, actname: &str) {
        self.currentactname = actname.to_string();
        self.derive_action("universal", actname);
        let index = self
            .action_index(actname)
            .expect("setCurrent: derived root must be registered");
        self.currentact = Some(index);
    }

    // Ghidra: action.cc:1145 ActionDatabase::deriveAction
    /// Build the Action object for root name `grp` by selectively copying
    /// components from `baseaction` based on `grp`'s grouplist. Ghidra
    /// deep-clones the registered base tree via `Action::clone`
    /// (action.cc:1153-1155: getGroup + getAction(baseaction) + clone) and
    /// registers the result — including a null clone — under `grp`
    /// (action.cc:1157-1158).
    fn derive_action(&mut self, baseaction: &str, grp: &str) {
        if self.action_index(grp).is_some() {
            return; // Already derived this action (action.cc:1149-1151)
        }
        let grouplist = self
            .get_group(grp)
            .unwrap_or_else(|| panic!("Action group does not exist: {grp}"))
            .clone();
        let newact = self
            .get_action(baseaction)
            .unwrap_or_else(|| panic!("Base action does not exist: {baseaction}"))
            .clone_for_groups(&grouplist);
        self.register_action_named(grp, newact);
    }

    // Ghidra: action.hh:313 ActionDatabase::getCurrent
    pub fn get_current(&self) -> &dyn Action {
        self.actionmap[self.currentact.expect("no current root action")]
            .1
            .as_deref()
            .expect("current root action is null")
    }

    // Ghidra: action.hh:314 ActionDatabase::getCurrentName
    pub fn get_current_name(&self) -> &str {
        &self.currentactname
    }

    // Ghidra: action.cc:1090 ActionDatabase::addToGroup
    /// Add a group to the grouplist for a particular root Action. The
    /// groupmap entry is default-inserted if absent (Ghidra's
    /// `groupmap[grp]`), and `isDefaultGroups` is cleared before the insert.
    /// Returns true for a new addition, false if the group was already
    /// present.
    pub fn add_to_group(&mut self, grp: &str, basegroup: &str) -> bool {
        self.is_default_groups = false;
        let curgrp = self.groupmap_entry(grp);
        curgrp.groups.insert(basegroup.to_string())
    }

    // Ghidra: action.cc:1103 ActionDatabase::removeFromGroup
    /// Remove the group from the grouplist of a particular root Action.
    /// The groupmap entry is default-inserted if absent (Ghidra's
    /// `groupmap[grp]`), and `isDefaultGroups` is cleared before the erase.
    /// Returns true if the group existed and was removed.
    pub fn remove_from_group(&mut self, grp: &str, basegrp: &str) -> bool {
        self.is_default_groups = false;
        let curgrp = self.groupmap_entry(grp);
        curgrp.groups.remove(basegrp)
    }

    // RUGRA-GLUE: get-or-insert view of Ghidra map<string,ActionGroupList>::operator[] (action.cc:1094/1107); kept private like the raw index it stands in for
    fn groupmap_entry(&mut self, grp: &str) -> &mut ActionGroupList {
        if let Some(idx) = self.groupmap.iter().position(|(key, _)| key == grp) {
            &mut self.groupmap[idx].1
        } else {
            self.groupmap
                .push((grp.to_string(), ActionGroupList::from_members(&[])));
            let last = self.groupmap.len() - 1;
            &mut self.groupmap[last].1
        }
    }

    // Ghidra: action.cc:1036 ActionDatabase::toggleAction
    /// A particular group is either added or removed from the grouplist
    /// defining a particular root Action. The root Action is then
    /// (re)derived from the universal. Ghidra returns the new root Action
    /// pointer; the Rust caller re-fetches it through `get_action`/`get_current`
    /// (the registry replaced the old object, mirroring Ghidra's delete in
    /// `registerAction`).
    pub fn toggle_action(&mut self, grp: &str, basegrp: &str, val: bool) {
        // action.cc:1039 `Action *act = getAction(universalname);` — resolves
        // the universal root (throwing if absent) BEFORE any group mutation,
        // so a missing universal leaves the grouplists untouched.
        let universal_idx = self
            .action_index("universal")
            .unwrap_or_else(|| panic!("No registered action: universal"));
        // action.cc:1040-1043 addToGroup / removeFromGroup on the steering grouplist
        if val {
            self.add_to_group(grp, basegrp);
        } else {
            self.remove_from_group(grp, basegrp);
        }
        // action.cc:1044 `const ActionGroupList &curgrp(getGroup(grp)); // Group should already exist`
        let curgrp = self
            .get_group(grp)
            .unwrap_or_else(|| panic!("Action group does not exist: {grp}"))
            .clone();
        // action.cc:1045 `Action *newact = act->clone(curgrp);` — always cloned
        // from the registered universal, never from the previous root.
        let newact = self.actionmap[universal_idx]
            .1
            .as_deref()
            .expect("universal root action is null")
            .clone_for_groups(&curgrp);
        // action.cc:1047 `registerAction(grp,newact);` — replaces (drops) any
        // previously registered root of the same name.
        self.register_action_named(grp, newact);
        // action.cc:1049-1050 `if (grp == currentactname) currentact = newact;`
        if grp == self.currentactname {
            self.currentact = self.action_index(grp);
        }
    }

    // RUGRA-GLUE: Rust ownership adapter for Ghidra's Architecture current Action pointer followed by Action::reset and Action::perform
    /// Reset and perform one registered root action.
    pub fn perform_action(
        &mut self,
        name: &str,
        fd: &mut crate::funcdata::Funcdata,
    ) -> crate::error::Result<Option<i32>> {
        let Some(index) = self.action_index(name) else {
            return Ok(None);
        };
        let Some(action) = self.actionmap[index].1.as_deref_mut() else {
            return Ok(None);
        };
        action.reset(fd);
        let flags = action.get_flags();
        let mut state = ActionState::new(flags);
        action.perform(fd, &mut state).map(Some)
    }

    // RUGRA-GLUE: driver-side installation of the restart-cycle flow
    // regeneration callback (PIPE-RESTART-0001) on a registered root —
    // the production driver's derived "decompile" clone. Ghidra's restart
    // cycle reaches the Architecture-owned loader through
    // Funcdata::getArch() inside the second pass's startProcessing →
    // followFlow; Rugra's flow generation lives at the driver boundary, so
    // the driver injects its loader bridge through the database handle it
    // already owns, before performing the root. Returns false when the
    // named root is absent or is not an ActionRestartGroup.
    pub fn set_restart_flow(
        &mut self,
        root_name: &str,
        callback: RestartFlowCallback,
    ) -> bool {
        match self.get_action_mut(root_name) {
            Some(action) => match action.as_restart_group_mut() {
                Some(restart_group) => {
                    restart_group.set_restart_flow(callback);
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    // RUGRA-GLUE: mirrors the production driver (ghidra_process.cc:310 allacts.getCurrent()->perform(fd)); the former name is kept for the legacy callers
    /// Perform the current root Action (after a per-root reset) on the
    /// given function data.
    pub fn apply_all(&mut self, fd: &mut crate::funcdata::Funcdata) -> crate::error::Result<i32> {
        let index = self.currentact.expect("no current root action");
        let action = self.actionmap[index]
            .1
            .as_deref_mut()
            .expect("current root action is null");
        action.reset(fd);
        let flags = action.get_flags();
        let mut state = ActionState::new(flags);
        action.perform(fd, &mut state)
    }

    // RUGRA-GLUE: production entry mirroring Architecture::buildAction (architecture.cc:582-591: allacts.universalAction(this); allacts.resetDefaults();)
    /// Set up the default decompiler actions: build the raw universal tree,
    /// then derive the default "decompile" root through `resetDefaults`.
    pub fn set_default_actions(&mut self) {
        self.universal_action();
        self.reset_defaults();
    }
}

// Ghidra: coreaction.cc:5462-5738 ActionDatabase::universalAction
/// Build the universal Action tree containing every component at its exact
/// oracle slot. With `grouplist == None` the raw universal tree is built
/// (every Action registered). With `Some(list)` the construction mirrors
/// the survival semantics of `Action::clone` under `deriveAction`
/// (action.cc:1145-1158): a leaf is registered iff its basegroup is in the
/// list, and a group/pool node is registered iff at least one child
/// survived (ActionGroup::clone action.cc:391-406 / ActionPool::clone
/// action.cc:899-914 / ActionRestartGroup::clone action.cc:529-544).
/// Rule-level filtering is performed by each ActionPool clone from the exact
/// group and constructor retained at its locked registration slot.
pub fn universal_action(grouplist: Option<&ActionGroupList>) -> Option<ActionRestartGroup> {
    // RUGRA-GLUE: retain the concrete constructor and basegroup at each
    // addAction slot; selective construction happens only through clone.
    macro_rules! add {
        ($parent:expr, $group:expr, $action:expr) => {
            $parent.add_action_factory_in_group($group, || $action);
        };
    }
    // Root: ActionRestartGroup(Action::rule_onceperfunc,"universal",1) — coreaction.cc:5474
    let mut universal = ActionRestartGroup::new(
        "universal",
        action_flags::RULE_ONCEPERFUNC,
        1);

    // --- Universal head (coreaction.cc:5477-5485) ---
    add!(
        universal, "base", Box::new(crate::coreaction::ActionStart::new())
    ); // :5477
    add!(
        universal, "base", Box::new(crate::coreaction::ActionConstbase::new())
    ); // :5478
    add!(
        universal, "normalanalysis", Box::new(crate::coreaction::ActionNormalizeSetup::new())
    ); // :5479
    add!(
        universal, "base", Box::new(crate::coreaction::ActionDefaultParams::new())
    ); // :5480
    add!(
        universal, "base", Box::new(crate::coreaction::ActionExtraPopSetup::new())
    ); // :5482
    add!(
        universal, "protorecovery", Box::new(crate::coreaction::ActionPrototypeTypes::new())
    ); // :5483
    add!(
        universal, "protorecovery", Box::new(crate::coreaction::ActionFuncLink::new())
    ); // :5484
    add!(
        universal, "noproto", Box::new(crate::coreaction::ActionFuncLinkOutOnly::new())
    ); // :5485

    // --- fullloop (coreaction.cc:5487, rule_repeatapply) ---
    let mut fullloop = ActionGroup::with_flags("fullloop", action_flags::RULE_REPEATAPPLY);
    {
        // --- mainloop (coreaction.cc:5489, rule_repeatapply) ---
        let mut mainloop = ActionGroup::with_flags("mainloop", action_flags::RULE_REPEATAPPLY);
        add!(
            mainloop, "base", Box::new(crate::coreaction::ActionUnreachable::new())
        ); // :5490
        add!(
            mainloop, "base", Box::new(crate::coreaction::ActionVarnodeProps::new())
        ); // :5491
        add!(mainloop, "base", Box::new(ActionHeritage::new())); // :5492
        add!(
            mainloop, "protorecovery", Box::new(crate::coreaction::ActionParamDouble::new())
        ); // :5493
        add!(
            mainloop, "base", Box::new(crate::coreaction::ActionSegmentize::new())
        ); // :5494
        add!(
            mainloop, "base", Box::new(crate::coreaction::ActionInternalStorage::new())
        ); // :5495
        add!(
            mainloop, "blockrecovery", Box::new(crate::coreaction::ActionForceGoto::new())
        ); // :5496
        add!(
            mainloop, "protorecovery_a", Box::new(crate::coreaction::ActionDirectWrite::new(true))
        ); // :5497 (propagateIndirect=true)
        add!(
            mainloop, "protorecovery_b", Box::new(crate::coreaction::ActionDirectWrite::new(false))
        ); // :5498 (propagateIndirect=false; filtered from the decompile root)
        add!(
            mainloop, "protorecovery", Box::new(crate::coreaction::ActionActiveParam::new())
        ); // :5499
        add!(
            mainloop, "protorecovery", Box::new(crate::coreaction::ActionReturnRecovery::new())
        ); // :5500
        add!(
            mainloop, "localrecovery", Box::new(crate::coreaction::ActionRestrictLocal::new())
        ); // :5502
        add!(mainloop, "deadcode", Box::new(ActionDeadCode::new())); // :5503
        add!(
            mainloop, "dynamic", Box::new(crate::coreaction::ActionDynamicMapping::new())
        ); // :5504
        add!(
            mainloop, "localrecovery", Box::new(crate::coreaction::ActionRestructureVarnode::new())
        ); // :5505
        add!(
            mainloop, "base", Box::new(crate::coreaction::ActionSpacebase::new())
        ); // :5506
        add!(
            mainloop, "analysis", Box::new(crate::coreaction::ActionNonzeroMask::new())
        ); // :5507
        add!(
            mainloop, "typerecovery", Box::new(crate::coreaction::ActionInferTypes::new())
        ); // :5508

        // --- stackstall (coreaction.cc:5509, rule_repeatapply) ---
        let mut stackstall = ActionGroup::with_flags("stackstall", action_flags::RULE_REPEATAPPLY);
        stackstall.add_action(Box::new(build_oppool1())); // :5511-5650 oppool1
        add!(
            stackstall, "base", Box::new(crate::coreaction::ActionLaneDivide::new())
        ); // :5652
        add!(
            stackstall, "analysis", Box::new(crate::coreaction::ActionMultiCse::new())
        ); // :5653
        add!(
            stackstall, "analysis", Box::new(crate::coreaction::ActionShadowVar::new())
        ); // :5654
        add!(
            stackstall, "deindirect", Box::new(crate::coreaction::ActionDeindirect::new())
        ); // :5655
        add!(
            stackstall, "stackptrflow", Box::new(ActionStackPtrFlow::new())
        ); // :5656
        if stackstall.num_actions() > 0 {
            mainloop.add_action(Box::new(stackstall)); // :5657
        }

        add!(
            mainloop, "deadcontrolflow", Box::new(crate::coreaction::ActionRedundBranch::new())
        ); // :5658
        add!(
            mainloop, "blockrecovery", Box::new(ActionBlockStructure::new())
        ); // :5659
        add!(
            mainloop, "typerecovery", Box::new(crate::coreaction::ActionConstantPtr::new())
        ); // :5660
        mainloop.add_action(Box::new(build_oppool2())); // :5662-5671 oppool2
        add!(
            mainloop, "unreachable", Box::new(crate::coreaction::ActionDeterminedBranch::new())
        ); // :5672
        add!(
            mainloop, "unreachable", Box::new(crate::coreaction::ActionUnreachable::new())
        ); // :5673
        add!(
            mainloop, "nodejoin", Box::new(crate::coreaction::ActionNodeJoin::new())
        ); // :5674
        add!(
            mainloop, "conditionalexe", Box::new(crate::condexe::ActionConditionalExe::new())
        ); // :5675
        add!(
            mainloop, "analysis", Box::new(crate::coreaction::ActionConditionalConst::new())
        ); // :5676
        if mainloop.num_actions() > 0 {
            fullloop.add_action(Box::new(mainloop)); // :5678
        }

        // --- fullloop tail (coreaction.cc:5679-5688, after mainloop) ---
        add!(
            fullloop, "protorecovery", Box::new(crate::coreaction::ActionLikelyTrash::new())
        ); // :5679
        add!(
            fullloop, "protorecovery_a", Box::new(crate::coreaction::ActionDirectWrite::new(true))
        ); // :5680
        add!(
            fullloop, "protorecovery_b", Box::new(crate::coreaction::ActionDirectWrite::new(false))
        ); // :5681 (filtered from the decompile root)
        add!(fullloop, "deadcode", Box::new(ActionDeadCode::new())); // :5682
        add!(
            fullloop, "deadcontrolflow", Box::new(crate::coreaction::ActionDoNothing::new())
        ); // :5683
        add!(
            fullloop, "switchnorm", Box::new(crate::coreaction::ActionSwitchNorm::new())
        ); // :5684
        add!(
            fullloop, "returnsplit", Box::new(crate::coreaction::ActionReturnSplit::new())
        ); // :5685
        add!(
            fullloop, "protorecovery", Box::new(crate::coreaction::ActionUnjustifiedParams::new())
        ); // :5686
        add!(
            fullloop, "typerecovery", Box::new(crate::coreaction::ActionStartTypes::new())
        ); // :5687
        add!(
            fullloop, "protorecovery", Box::new(crate::coreaction::ActionActiveReturn::new())
        ); // :5688
    }
    if fullloop.num_actions() > 0 {
        universal.add_action(Box::new(fullloop)); // :5690
    }

    // --- Post-fullloop top-level (coreaction.cc:5691-5738) ---
    add!(
        universal, "localrecovery", Box::new(crate::coreaction::ActionMappedLocalSync::new())
    ); // :5691
    add!(
        universal, "cleanup", Box::new(crate::coreaction::ActionStartCleanUp::new())
    ); // :5692
    universal.add_action(Box::new(build_cleanup_pool())); // :5694-5712 cleanup pool
    add!(
        universal, "blockrecovery", Box::new(crate::coreaction::ActionPreferComplement::new())
    ); // :5714
    add!(
        universal, "blockrecovery", Box::new(crate::coreaction::ActionStructureTransform::new())
    ); // :5715
    add!(
        universal, "normalizebranches", Box::new(ActionNormalizeBranches::new())
    ); // :5716 (filtered from the decompile root — coreaction.cc:5424-5431)
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionAssignHigh::new())
    ); // :5717
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMergeRequired::new())
    ); // :5718
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMarkExplicit::new())
    ); // :5719
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMarkImplied::new())
    ); // :5720
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMergeMultiEntry::new())
    ); // :5721
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMergeCopy::new())
    ); // :5722
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionDominantCopy::new())
    ); // :5723
    add!(
        universal, "dynamic", Box::new(crate::coreaction::ActionDynamicSymbols::new())
    ); // :5724
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMarkIndirectOnly::new())
    ); // :5725
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMergeAdjacent::new())
    ); // :5726
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionMergeType::new())
    ); // :5727
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionHideShadow::new())
    ); // :5728
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionCopyMarker::new())
    ); // :5729
    add!(
        universal, "localrecovery", Box::new(crate::coreaction::ActionOutputPrototype::new())
    ); // :5730
    add!(
        universal, "fixateproto", Box::new(crate::coreaction::ActionInputPrototype::new())
    ); // :5731
    add!(
        universal, "fixateglobals", Box::new(crate::coreaction::ActionMapGlobals::new())
    ); // :5732
    add!(
        universal, "dynamic", Box::new(crate::coreaction::ActionDynamicSymbols::new())
    ); // :5733
    add!(
        universal, "merge", Box::new(crate::coreaction::ActionNameVars::new())
    ); // :5734
    add!(
        universal, "casts", Box::new(crate::coreaction::ActionSetCasts::new())
    ); // :5735
    add!(
        universal, "blockrecovery", Box::new(ActionFinalStructure::new())
    ); // :5736
    add!(
        universal, "protorecovery", Box::new(crate::coreaction::ActionPrototypeWarnings::new())
    ); // :5737
    add!(
        universal, "base", Box::new(crate::coreaction::ActionStop::new())
    ); // :5738

    if let Some(grouplist) = grouplist {
        return universal.clone_restart_group(grouplist);
    }
    Some(universal)
}

// RUGRA-GLUE: derived default root — mirrors ActionDatabase::resetDefaults + setCurrent("decompile") for callers that only need the tree
/// Build the derived default "decompile" pipeline root (the tree that
/// `ActionDatabase::set_default_actions` registers as the current root).
pub fn build_default_pipeline() -> ActionRestartGroup {
    universal_action(Some(&ActionGroupList::from_members(
        default_groups::DECOMPILE,
    )))
        .expect("decompile grouplist keeps the universal head (base group)")
}

/// ActionTypePropagate: Conservative P-code struct pointer type propagation.
/// Marks varnodes used as base in >=2 distinct small (<256B, 8-byte-aligned)
/// offsets via INT_ADD → LOAD/STORE. Mirrors Ghidra's ActionTypePropagate.
pub struct ActionTypePropagate;

impl ActionTypePropagate {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    pub fn new() -> Self { Self }
}

impl Action for ActionTypePropagate {
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        crate::analysis::type_infer::propagate_types(fd);
        Ok(0)
    }
    // RUGRA-GLUE: src/action.rs helper (no direct Ghidra counterpart)
    fn get_name(&self) -> &str { "typepropagate" }
}

/// Status codes for Action execution
pub mod action_status {
    pub const NO_CHANGE: i32 = 0;
    pub const CHANGE: i32 = 1;
    pub const RESTART: i32 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    // PIPE-MERGETYPE-ORDER-0001 + PIPE-DERIVED-TREE-0001: the post-cleanup
    // child sequence of the derived default pipeline must mirror the
    // coreaction.cc:5714-5738 slots after decompile-grouplist filtering —
    // ActionNormalizeBranches (:5716, group "normalizebranches") is NOT a
    // member of the decompile grouplist (coreaction.cc:5424-5431) and is
    // dropped by the derive clone, three structural transforms lead
    // (:5714-5715 + assignhigh :5717), a single ActionMergeType late
    // (:5727, after mergeadjacent, before hideshadow).
    #[test]
    fn test_post_cleanup_sequence_matches_ghidra_5714_5738() {
        let root = build_default_pipeline();
        let names = root.child_names();
        let start = names
            .iter()
            .position(|n| *n == "prefercomplement")
            .expect("prefercomplement must be registered");
        let tail: Vec<&str> = names[start..].to_vec();
        assert_eq!(
            tail,
            vec![
                "prefercomplement",     // :5714
                "structuretransform",   // :5715
                // "normalizebranches" (:5716) filtered: group not in decompile
                "assignhigh",           // :5717
                "mergerequired",        // :5718
                "markexplicit",         // :5719
                "markimplied",          // :5720
                "mergemultientry",      // :5721
                "mergecopy",            // :5722
                "dominantcopy",         // :5723
                "dynamicsymbols",       // :5724 (first instance)
                "markindirectonly",     // :5725
                "mergeadjacent",        // :5726
                "mergetype",            // :5727 — the single instance
                "hideshadow",           // :5728
                "copymarker",           // :5729
                "outputprototype",      // :5730
                "inputprototype",       // :5731
                "mapglobals",           // :5732
                "dynamicsymbols",       // :5733 (second instance)
                "namevars",             // :5734
                "setcasts",             // :5735
                "finalstructure",       // :5736
                "prototypewarnings",    // :5737
                "stop",                 // :5738
            ]
        );
        // Exactly one mergetype in the whole tree (the premature post-cleanup
        // instance and the build_full_pipeline_actions duplicates are gone).
        assert_eq!(names.iter().filter(|n| **n == "mergetype").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "assignhigh").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "dominantcopy").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "copymarker").count(), 1);
    }

    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④: universalAction registers every
    // Action exactly once (coreaction.cc:5462-5738); ActionPrototypeWarnings
    // appears only at :5737. The former build_full_pipeline_actions()
    // consumption used to double-register it (stderr 48 = 24×2
    // unknown-convention warnings per E2E run) along with 16 other Actions
    // this builder owns; that vec path is now deleted outright
    // (PIPE-HEAD-FLAT-ACTIONS-0001).
    #[test]
    fn test_prototype_warnings_registered_once() {
        let root = build_default_pipeline();
        let names = root.child_names();
        // coreaction.cc:5737 — exactly one top-level prototypewarnings.
        assert_eq!(
            names.iter().filter(|n| **n == "prototypewarnings").count(), 1
        );
        // R2 closeout (unblocked by 533412a; see the SINGLE REGISTRATION
        // comment in build_default_pipeline): outputprototype/inputprototype
        // are sole-registered at their oracle positions — exactly one
        // top-level instance each, never in any pre-fullloop flat run.
        for name in ["outputprototype", "inputprototype"] {
            assert_eq!(
                names.iter().filter(|n| **n == name).count(),
                1,
                "sole registration for {name}"
            );
        }
        assert_eq!(
            names.iter().filter(|n| **n == "setcasts").count(),
            1,
            "setcasts must be sole-registered at the :5735 position"
        );
        // The other deduplicated builder-owned names: base/merge ones appear
        // exactly once at top level, mainloop/fullloop ones only inside their
        // group (zero top-level instances).
        for (name, expected_top_level) in [
            ("defaultparams", 1),      // :5480
            ("prototypetypes", 1),     // :5483
            ("hideshadow", 1),         // :5728
            ("varnodeprops", 0),       // mainloop :5491
            ("paramdouble", 0),        // mainloop :5493
            ("directwrite", 0),        // mainloop/fullloop only
            ("activeparam", 0),        // mainloop :5499
            ("returnrecovery", 0),     // mainloop :5500
            ("nonzeromask", 0),        // mainloop :5507
            ("infertypes", 0),         // mainloop :5508
            ("unjustifiedparams", 0),  // fullloop :5686
            ("starttypes", 0),         // fullloop :5687
            ("activereturn", 0),       // fullloop :5688
            ("switchnorm", 0),         // fullloop :5684
        ] {
            assert_eq!(
                names.iter().filter(|n| **n == name).count(),
                expected_top_level,
                "top-level count for {name}"
            );
        }
    }

    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④ + PIPE-DERIVED-TREE-0001: the
    // derived decompile head is coreaction.cc:5477-5486 after grouplist
    // filtering — Start, Constbase, [NormalizeSetup filtered — group
    // "normalanalysis" is not in the decompile grouplist], DefaultParams,
    // ExtraPopSetup, PrototypeTypes, FuncLink, [FuncLinkOutOnly filtered —
    // group "noproto" is not in the decompile grouplist], immediately
    // followed by fullloop. The raw universal tree still registers both
    // filtered nodes at their head slots (see universal_action).
    #[test]
    fn test_base_group_order_matches_ghidra_5477_5485() {
        let root = build_default_pipeline();
        let names = root.child_names();
        let expected_prefix = [
            "start",             // :5477
            "constbase",         // :5478
            "defaultparams",     // :5480
            "extrapopsetup",     // :5482
            "prototypetypes",    // :5483
            "funclink",          // :5484
            "fullloop",          // :5487 group
        ];
        assert!(names.len() >= expected_prefix.len());
        let prefix: Vec<&str> = names[..expected_prefix.len()].to_vec();
        assert_eq!(prefix, expected_prefix.to_vec());
    }

    // PIPE-DERIVED-TREE-0001: the raw universal head keeps both filtered
    // nodes (normalizesetup :5479, funclink_outonly :5485) — derive only
    // drops them for roots whose grouplist lacks their groups.
    #[test]
    fn test_raw_universal_head_keeps_filtered_nodes() {
        let root = universal_action(None).expect("raw universal root");
        let names = root.child_names();
        let expected_prefix = [
            "start",              // :5477
            "constbase",          // :5478
            "normalizesetup",     // :5479 (normalanalysis)
            "defaultparams",      // :5480
            "extrapopsetup",      // :5482
            "prototypetypes",     // :5483
            "funclink",           // :5484
            "funclink_outonly",   // :5485 (noproto)
            "fullloop",           // :5487
        ];
        let prefix: Vec<&str> = names[..expected_prefix.len()].to_vec();
        assert_eq!(prefix, expected_prefix.to_vec());
    }

    struct ScriptAction {
        script: Vec<i32>,
        cursor: usize,
        flags: u32,
        calls: Arc<AtomicUsize>,
    }

    impl ScriptAction {
        fn new(script: Vec<i32>, flags: u32, calls: Arc<AtomicUsize>) -> Self {
            Self {
                script,
                cursor: 0,
                flags,
                calls,
            }
        }
    }

    impl Action for ScriptAction {
        fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.script.get(self.cursor).copied().unwrap_or(0);
            self.cursor += 1;
            Ok(result)
        }

        fn get_name(&self) -> &str {
            "script"
        }

        fn get_flags(&self) -> u32 {
            self.flags
        }
    }

    fn fixture_funcdata() -> Funcdata {
        Funcdata::new("action_fixture", Address::new(0x1000), 1)
    }

    #[test]
    fn perform_repeats_until_no_change() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut action = ScriptAction::new(
            vec![1, 1, 0],
            action_flags::RULE_REPEATAPPLY,
            calls.clone());
        let mut state = ActionState::new(action_flags::RULE_REPEATAPPLY);
        let mut fd = fixture_funcdata();

        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(state.count, 2);
        assert_eq!(state.lcount, 2);
        assert_eq!(state.count_tests, 1);
        assert_eq!(state.count_apply, 2);
        assert_eq!(state.status, status_flags::STATUS_START);
    }

    #[test]
    fn perform_resumes_partial_without_restarting_counters() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut action = ScriptAction::new(vec![-1, 1], 0, calls.clone());
        let mut state = ActionState::new(0);
        let mut fd = fixture_funcdata();

        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), -1);
        assert_eq!(state.status, status_flags::STATUS_MID);
        assert_eq!(state.count_tests, 1);
        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(state.count_tests, 1);
        assert_eq!(state.count_apply, 1);
        assert_eq!(state.status, status_flags::STATUS_START);
    }

    #[test]
    fn once_per_function_stops_until_reset() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut action = ScriptAction::new(
            vec![0, 0],
            action_flags::RULE_ONCEPERFUNC,
            calls.clone());
        let mut state = ActionState::new(action_flags::RULE_ONCEPERFUNC);
        let mut fd = fixture_funcdata();

        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 0);
        assert_eq!(state.status, status_flags::STATUS_END);
        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        state.status = status_flags::STATUS_START;
        action.reset(&mut fd);
        assert_eq!(action.perform(&mut fd, &mut state).unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // the CFG without that reset, so the stale ADT never contains the new
    // joined block; renameRecurse (heritage.cc:2522-2540) then never fills
    // the joined edge's MULTIEQUAL input slots, leaving free-with-descendant
    // phi inputs that make Merge::allocateCopyTrim (merge.cc:411) trip the
    // "Free varnode has multiple descendants" invariant (varnode.cc:333-336)
    // in ActionMergeRequired — the curl match_url/getparameter P0 panic.
    // This fixture locks the oracle contract: after ActionNodeJoin creates
    // a join block, heritage MUST be force-restructured. It is #[ignore]d
    // until the coreaction.rs owner lands the structure_reset call; remove
    // the attribute together with that fix.
    #[test]
    fn nodejoin_join_block_forces_heritage_restructure() {
        use crate::block::BlockBasic;
        use crate::coreaction::ActionNodeJoin;
        use crate::opcodes::OpCode;
        use std::sync::RwLock as StdRwLock;

        let mut fd = Funcdata::new("nodejoin_structurereset", Address::new(0x1000), 1);
        // Diamond: bb and bb2 both branch to exita/exitb on DIFFERENT
        // conditions, so ActionNodeJoin takes the join-block path.
        let blocks: Vec<_> = [0x1000u64, 0x1010, 0x1020, 0x1030]
            .iter()
            .map(|&off| {
                let b: Arc<StdRwLock<dyn crate::block::FlowBlock + Send + Sync>> = Arc::new(
                    StdRwLock::new(BlockBasic::new(0, Address::new(off))),
                );
                fd.bblocks.add_block(b.clone());
                b
            })
            .collect();
        let (bb, bb2, exita, exitb) = (&blocks[0], &blocks[1], &blocks[2], &blocks[3]);
        // One CBRANCH per branch block (in[0]=target const, in[1]=condition).
        let cbranch = |fd: &mut Funcdata, addr: u64, cond: &Arc<std::sync::RwLock<crate::varnode::Varnode>>| {
            let op = fd.new_op(2, Address::new(addr));
            fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
            let target = fd.new_constant(8, 0x1020);
            fd.op_set_input(&op, target, 0);
            fd.op_set_input(&op, cond.clone(), 1);
            op
        };
        // Shared WRITTEN condition varnode for both cbranches: F3/F4 port
        // the oracle findDups gates — vn1==vn2 is a complete match, but
        // constant conditions are !isWritten and must NOT join (bilateral
        // fixture D_unwritten locks count=0). Build INT_EQUAL(const,const)
        // so the condition is a written varnode read by both CBRANCHes.
        let cond_def = {
            let op = fd.new_op(2, Address::new(0x1005));
            fd.op_set_opcode(&op, OpCode::CPUI_INT_EQUAL);
            let lhs = fd.new_constant(4, 7);
            let rhs = fd.new_constant(4, 7);
            fd.op_set_input(&op, lhs, 0);
            fd.op_set_input(&op, rhs, 1);
            let out = fd.new_unique_out(1, &op);
            fd.op_insert_begin(&op, bb);
            out
        };
        let cb1 = cbranch(&mut fd, 0x1000, &cond_def);
        fd.op_insert_end(&cb1, bb);
        let cb2 = cbranch(&mut fd, 0x1010, &cond_def);
        fd.op_insert_end(&cb2, bb2);
        // Same out-edge order for both branch blocks.
        fd.bblocks.add_edge(bb.clone(), exita.clone());
        fd.bblocks.add_edge(bb.clone(), exitb.clone());
        fd.bblocks.add_edge(bb2.clone(), exita.clone());
        fd.bblocks.add_edge(bb2.clone(), exitb.clone());
        // Simulate an already-built augmented dominator tree (post-first
        // ActionHeritage state): maxdepth is a real depth, not the -1
        // restructure sentinel.
        fd.heritage.maxdepth = 3;

        let mut action = ActionNodeJoin::new();
        let _ = action.apply(&mut fd).expect("nodejoin apply must not fail");

        // Ghidra contract: the join-block creation ends in structureReset(),
        // which forces the next heritage pass to rebuild the ADT.
        assert_eq!(
            fd.heritage.maxdepth, -1,
            "ActionNodeJoin must force-restructure heritage (maxdepth=-1) after creating a join block"
        );
        // CFG shape contract (R-NODEJOIN-CROSSREVIEW F1): the canonical
        // diamond exercises the swapa==swapb statement-order path, where the
        // second getOutIndex must be taken AFTER the first move. The correct
        // terminal shape is the clean triangle: the join block holds BOTH
        // moved exit edges (size_out==2), and both branch blocks are left
        // with only their new edge into the join (size_out==1 each).
        let join = fd
            .bblocks
            .blocks
            .iter()
            .find(|b| b.read().unwrap().get_flags() & crate::block::block_flags::JOINED_BLOCK != 0)
            .expect("join block created")
            .clone();
        assert_eq!(
            join.read().unwrap().size_out(),
            2,
            "join block must own both moved exit edges (statement-order F1 regression)"
        );
        for branch in [bb, bb2] {
            assert_eq!(
                branch.read().unwrap().size_out(),
                1,
                "canonical diamond (swapa==swapb): branch blocks keep only the join edge"
            );
        }
    }
}
