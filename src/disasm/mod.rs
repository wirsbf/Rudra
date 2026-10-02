//! Disassembly module for Rudra
//!
//! P-code emission for the decompiler pipeline. The retired iced-x86
//! bootstrap decoder and its hand-written X86Lifter are gone
//! (SLEIGH-RUSTIFY-PHASE3-0001): every decode path — the canonical curl and
//! httpd drivers, the CLI pre-pass, the Funcdata test sites, and the probe
//! examples — rides the locked .sla through `sleigh_lift`, mirroring
//! Ghidra's single-decoder architecture (`Translate::oneInstruction`,
//! translate.hh:419; `Sleigh::oneInstruction`, sleigh.cc:741).

pub mod sleigh_lift;
