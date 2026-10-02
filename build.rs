// INFRA-EXAMPLES-STALELINK-0001 build-side: embed the source digest of the
// stale-guard domain (every src/**/*.rs file + examples/gen_decompile.rs +
// examples/common/stale_guard_hash.rs + build.rs — the guard's own build
// inputs are domain anchors, found as a blind spot during lane red/green
// verification) into every compilation of this package so the example
// binaries can fail fast at startup when cargo reuses a stale examples
// artifact — the exact accident shape that bit MB29 integration (r3merge
// mirror effect missed: sq −86 / sqlite −138 measured with an un-relinked
// binary) and the CASTFUSEB lane (the same deltas mis-attributed to an
// unrelated commit; CR-CASTFUSEB net-baseline A/B proved both bites).
//
// The digest core is shared VERBATIM with the runtime side via
// examples/common/stale_guard_hash.rs (single source of truth — the
// build-time and run-time algorithms cannot drift apart).

// RUDRA-GLUE: build infrastructure — the locked Ghidra oracle has no
// counterpart for build-script plumbing; the guarded decompiler pipeline is
// untouched (guard is silent on success, driver-side only).
include!("examples/common/stale_guard_hash.rs");

// RUDRA-GLUE: emit the domain digest + rerun triggers. When any watched
// input changes the digest changes, which re-compiles the package units
// that consume the env var (the examples); when nothing changes the output
// is byte-identical and cargo skips everything, so steady-state builds see
// no extra work beyond one directory walk per actual source change.
fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=crates");
    println!("cargo:rerun-if-changed=examples/gen_decompile.rs");
    println!("cargo:rerun-if-changed=examples/common/stale_guard_hash.rs");
    match source_digest(std::path::Path::new(".")) {
        Ok((digest, count)) => {
            println!("cargo:rustc-env=RUGRA_BUILD_SOURCE_DIGEST={digest:016x}");
            println!("cargo:rustc-env=RUGRA_BUILD_SOURCE_FILE_COUNT={count}");
        }
        Err(error) => {
            // Fail the build loudly: a package build without a readable
            // src/ tree means the guard contract itself is broken.
            panic!("INFRA-EXAMPLES-STALELINK-0001 source digest failed: {error}");
        }
    }
}
