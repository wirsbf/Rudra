//! KUNAUB-PAGECOPY-0001 panic-form regression lock (adjudication (a): keep
//! the panic; src/memstate.rs left untouched).
//!
//! Locked Ghidra 12.0.4 oracle (commit e40ed13014025f82488b1f8f7bca566894ac376b):
//! the DEFAULT `MemoryBank::getPage` (memstate.cc:93-123) and `setPage`
//! (memstate.cc:136-171) head-trim condition compares against the wrong
//! object — `if (startalign < addr)` (getPage :113 / setPage :153) — where
//! `addr` is the PAGE-ALIGNED offset passed by getChunk/setChunk
//! (memstate.cc:335-359 / :302-327), while the misalignment lives in
//! `ptraddr = addr + skip` (getPage :97 / setPage :140). Since
//! `startalign = ptraddr & ~(wordsize-1) >= addr` always holds, the head
//! trim is DEAD CODE as written. Consequence on `skip % wordsize != 0`:
//! the word loop over-copies up to `wordsize-1` bytes past the requested
//! range — `memcpy(res,ptr,sz)` (getPage :119) writes past the caller's
//! buffer / `memcpy(ptr,val,sz)` (setPage :161) reads past it — i.e. the
//! oracle's observable behavior on this input is a silent heap
//! out-of-bounds access (undefined behavior), NOT any defined output.
//!
//! Rudra: `memstate.rs get_page/set_page` mirror the same dead trim
//! (`if startalign < addr`, memstate.rs:164/:202), but the carrier is a
//! `Vec<u8>`/slice, so the same over-copy manifests as a Rust slice-range
//! panic ("range end index N out of range for slice of length M") in EVERY
//! profile — bounds checks on slice indexing are unconditional, unlike
//! overflow-checks arithmetic.
//!
//! Adjudication 2026-09-26 (lane KUNAUB2, same shape as the KUNAUB-SDIV-0001
//! precedent): the oracle has NO defined behavior on this input to match
//! (silent OOB vs panic are both crashes of undefined content), so the
//! panic is KEPT as the closest defensible crash form (option (a)); a panic
//! is strictly safer than the oracle's silent corruption. Rewriting the
//! trim to the evident intent (`startalign < ptraddr`, the
//! MemoryImage::getPage semantics, memstate.cc:386-399) would be a
//! deliberate divergence from oracle-as-written and remains an open option
//! only with a roadmap entry.
//!
//! Reachability note: `get_chunk/set_chunk` currently have ZERO production
//! callers in Rudra (src/ + examples/; MemState consumers use the word-level
//! get_value/set_value API), and in the oracle the default page path is
//! reachable only through banks that do not override getPage/setPage
//! (MemoryHashOverlay, memstate.hh:130-141 — emulation/standalone face; the
//! GUI decompiler mainline uses the page-overlay family). This file is a
//! test harness, not a production caller. Constraint recorded on the
//! ticket: do NOT introduce production get_chunk/set_chunk callers while
//! this adjudication stands.
//! Cross-check evidence: docs/alignment_audit/KUNA_UB_CROSSCHECK_2026-09-26.md
//! (K5) and /dev/shm/rudra-reports/LANE_KUNAUB2_2026-09-26.md.

use rudra::memstate::MemoryBank;
use rudra::space::AddressSpace;

/// get_chunk with `skip % wordsize != 0` (ws=8, chunk at page offset +1):
/// the dead head-trim mirror over-copies past the requested size and the
/// slice write panics (oracle: silent OOB write past the caller buffer,
/// memstate.cc:113 dead trim + :119 memcpy).
#[test]
#[should_panic(expected = "out of range for slice of length")]
fn get_chunk_unaligned_skip_overcopies_and_panics() {
    let bank = MemoryBank::new(AddressSpace::Ram, 8, 4096);
    // offalign = 0x1000, skip = 1, cursize = 8 -> get_page(0x1000, 1, 8):
    // iter1 fills res[0..8]; iter2 (startalign 0x1008, endalign 0x1010)
    // trims to sz=1 and touches res[8..9] on a length-8 Vec -> panic.
    let _ = bank.get_chunk(0x1001, 8);
}

/// set_chunk with `skip % wordsize != 0` (ws=8, chunk at page offset +1):
/// the second word iteration reads one byte past the source slice and the
/// slice read panics (oracle: silent OOB read past the caller buffer,
/// memstate.cc:153 dead trim + :161 memcpy).
#[test]
#[should_panic(expected = "out of range for slice of length")]
fn set_chunk_unaligned_skip_overreads_and_panics() {
    let mut bank = MemoryBank::new(AddressSpace::Ram, 8, 4096);
    // set_page(0x1000, val, 1, 8): iter1 consumes val[0..8] as a whole
    // word; iter2 trims to sz=1 and indexes val[8..9] on a length-8
    // slice -> panic.
    bank.set_chunk(0x1001, &[0u8, 1, 2, 3, 4, 5, 6, 7]);
}

/// Control: word-aligned skip (skip % wordsize == 0) stays on the defined
/// path on both sides — this pins that the panic lock above is specific to
/// the unaligned-skip UB input, not to the chunk API as a whole.
#[test]
fn chunk_word_aligned_skip_is_defined_on_both_sides() {
    let mut bank = MemoryBank::new(AddressSpace::Ram, 8, 4096);
    bank.set_chunk(0x1000, &[1u8, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(bank.get_chunk(0x1000, 8), vec![1u8, 2, 3, 4, 5, 6, 7, 8]);
    // Word-aligned skip with a short tail that still lands on word
    // boundaries relative to addr (skip=8, size=8 on a 0x1008 chunk).
    bank.set_chunk(0x1008, &[9u8, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(bank.get_chunk(0x1008, 8), vec![9u8, 10, 11, 12, 13, 14, 15, 16]);
}
