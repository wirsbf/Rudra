//! FUNCDATA-CANONICAL-ARCH-0001: Rudra mirror of the locked Ghidra 12.0.4
//! Funcdata constructor-invariant fixture
//! (`tests/oracle/funcdata_canonical_arch_1204.cc`).  `Funcdata::new`
//! binds the canonical default Architecture (the stand-in for the oracle's
//! unconditional `glb = scope->getArch()`, funcdata.cc:48, until Rudra's
//! constructor grows a Scope parameter — FUNCDATA-LOCALSCOPE-OWNERSHIP-0001).
//! The printed lines must match the C++ oracle stdout byte-for-byte;
//! Rudra-only tails (min_laned_size field equality, set_arch override) are
//! in-binary assertions so the diffed projections stay symmetric.
use std::sync::Arc;

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::funcdata::Funcdata;
use rudra::subflow::SplitDatatype;

fn main() {
    let mut fd = Funcdata::new("f", Address::new(0x1000), 0x10);
    let arch = fd
        .get_arch()
        .expect("Funcdata::new binds canonical Architecture")
        .clone();
    // funcdata.cc:49 `minLanedSize = glb->getMinimumLanedRegisterSize();`
    // — Rudra-only assertion: the field itself carries the source value.
    assert_eq!(
        fd.min_laned_size,
        arch.get_minimum_laned_register_size() as u32
    );
    println!("case=construct arch_nonnull=1");
    // funcdata.cc:54 `AddrSpace *stackid = glb->getStackSpace();` — the
    // ctor consumes the constructor-time Architecture's stack space.
    println!(
        "case=stack space_name={}",
        arch.stack_space.name()
    );

    // SplitDatatype reads the same constructor-time Architecture
    // (subflow.cc:2704-2707; the oracle class keeps this state private
    // with no getters, so the C++ twin observes it only at the source
    // level): the canonical default config (architecture.cc:1430-1432
    // resetDefaultsInternal struct|array|pointer) turns both gates on.
    let s = SplitDatatype::new(&mut fd);
    assert!(s.split_structures && s.split_arrays && !s.is_load_store);

    let mut fd2 = Funcdata::new("g", Address::new(0x2000), 0x10);
    let shared = Arc::ptr_eq(
        fd.get_arch().expect("fd arch"),
        fd2.get_arch().expect("fd2 arch"),
    );
    println!("case=share arch_identity_shared={}", shared as u8);

    // Rudra-only override tail (not printed; the curl/httpd runner path):
    // set_arch replaces the canonical binding and rebinds the ctor tail,
    // and a caller-supplied config is what SplitDatatype observes then.
    let mut custom = Architecture::new();
    custom.split_datatype_config = 0;
    fd2.set_arch(Arc::new(custom));
    let overridden = fd2.get_arch().expect("set_arch overwrote canonical");
    assert!(!Arc::ptr_eq(overridden, &arch));
    assert_eq!(overridden.split_datatype_config, 0);
    let s2 = SplitDatatype::new(&mut fd2);
    assert!(!s2.split_structures && !s2.split_arrays);
}
