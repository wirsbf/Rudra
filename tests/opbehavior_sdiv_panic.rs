//! KUNAUB-SDIV-0001 crash-form regression lock (adjudication (a): keep the panic).
//!
//! Locked Ghidra 12.0.4 oracle (commit e40ed13014025f82488b1f8f7bca566894ac376b):
//! `OpBehaviorIntSdiv::evaluateBinary` (opbehavior.cc:507-517) and
//! `OpBehaviorIntSrem::evaluateBinary` (opbehavior.cc:529-539) guard ONLY
//! `in2 == 0` (throwing EvaluationError) and then execute the raw C++ `intb`
//! division/remainder:
//!
//! ```text
//! intb sres = num/denom;   // opbehavior.cc:514
//! intb sres = val % mod;   // opbehavior.cc:536
//! ```
//!
//! On `(in1, in2) = (INT64_MIN, -1)`, `sizein = 8` this is a synchronous
//! hardware trap: the oracle process dies with SIGFPE. The mainline path
//! ruleaction.cc:3854 RuleCollapseConstants::applyOp -> op.cc:466
//! PcodeOp::collapse -> evaluateBinary wraps the call in
//! `catch(LowlevelError&)` (ruleaction.cc:3867), which handles the
//! divide-by-zero EvaluationError only — a hardware fault is not a C++
//! exception, so no handler engages and the process is killed.
//!
//! Rudra: all four division sites (safe free functions opbehavior.rs
//! CPUI_INT_SDIV / CPUI_INT_SREM arms, and the `OpBehavior` trait impls)
//! likewise guard only `in2 == 0` and then perform the native `i64`
//! division/remainder, which is defined in Rust to panic on the
//! INT64_MIN / -1 overflow in EVERY profile (this is not an
//! overflow-checks setting; it is unconditional). Root adjudication
//! 2026-09-26 (lane KUNASDIV): a panic is the closest observable crash
//! form to the oracle's SIGFPE for a normal run — both terminate the
//! process — so the panic is KEPT (option (a)); converting it to a
//! LowlevelError/opMarkNoCollapse soft failure would be a deliberate
//! divergence (oracle dies, Rudra survives) and was rejected.
//!
//! Deployment boundary note: under service-style `catch_unwind` wrappers a
//! Rudra panic is catchable while the oracle's SIGFPE is not. The oracle
//! has no serviced form, so this is a deployment boundary, not an
//! alignment defect.
//!
//! Bilateral reproduction evidence (2026-09-26):
//! - oracle: sdiv_srem.c (-O0, f_sdiv/f_srem) decompiled through the full
//!   universal action pipeline -> killed by SIGFPE, rc 136, no golden C
//!   output producible (both functions).
//! - Rudra: at the time of this lane the E2E panic is MASKED by an
//!   upstream fold gap — RuleSubCommute's INT_SDIV/INT_SREM commute case
//!   (the oracle rewrite `SUB168(SDIV16(SEXT816(a),SEXT816(b)),0)` ->
//!   `SDIV8(a,b)`, ruleaction.cc:4574-4601) is deferred in Rudra
//!   (ruleaction.rs "INT_SDIV / INT_SREM deferred"), so the trap input
//!   never reaches the fold on the gen face. Bilateral non-trap proof of
//!   the gap: g_div `100/-7` -> oracle prints folded constant
//!   `0xfffffffffffffff2`, Rudra prints `SUB168(SEXT816(100) /
//!   SEXT816(-7),0)`. Registered as
//!   RULEACTION-SUBCOMMUTE-SDIV-SEXT16-0001; these two unit tests are the
//!   direct-trigger crash-form lock for the four division sites
//!   themselves.
//! Evidence archive: /dev/shm/rudra-tests/kunasdiv/ (see
//! /dev/shm/rudra-reports/LANE_KUNASDIV_2026-09-26.md).

/// INT_SDIV constant folding on (INT64_MIN, -1), sizein=8: must panic
/// ("attempt to divide with overflow") — mirroring the oracle's SIGFPE
/// (opbehavior.cc:514 `num/denom`).
#[test]
#[should_panic(expected = "attempt to divide with overflow")]
fn sdiv_int64_min_over_minus_one_panics() {
    let _ = rudra::opbehavior::evaluate_binary(
        rudra::opcodes::OpCode::CPUI_INT_SDIV,
        8,
        8,
        0x8000_0000_0000_0000,
        0xFFFF_FFFF_FFFF_FFFF,
    );
}

/// INT_SREM constant folding on (INT64_MIN, -1), sizein=8: must panic
/// ("attempt to calculate the remainder with overflow") — mirroring the
/// oracle's SIGFPE (opbehavior.cc:536 `val % mod`).
#[test]
#[should_panic(expected = "attempt to calculate the remainder with overflow")]
fn srem_int64_min_rem_minus_one_panics() {
    let _ = rudra::opbehavior::evaluate_binary(
        rudra::opcodes::OpCode::CPUI_INT_SREM,
        8,
        8,
        0x8000_0000_0000_0000,
        0xFFFF_FFFF_FFFF_FFFF,
    );
}
