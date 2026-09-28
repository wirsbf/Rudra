// INFRA-EXAMPLES-STALELINK-0001: shared source-digest core for the examples
// stale-binary guard. This file is included VERBATIM by two consumers so the
// build-time and run-time sides can never drift apart:
//
//   * build.rs                  — include!("examples/common/stale_guard_hash.rs")
//   * examples/gen_decompile.rs — #[path = "common/stale_guard_hash.rs"] mod
//
// Digest domain (v1): the CONTENT of every `src/**/*.rs` file plus the
// guard's own build inputs — `examples/gen_decompile.rs`,
// `examples/common/stale_guard_hash.rs` (the verbatim shared core) and
// `build.rs` (the digest emitter) — framed as (relative POSIX path, NUL,
// u64-LE length, bytes) over FNV-1a-64 with a domain-separation prefix. The
// digest is checkout-location independent (relative paths): a binary built
// in worktree A validates fresh against a worktree B with byte-identical
// sources, and FAILS the moment any covered source byte differs — the exact
// stale-link accident shapes of MB29 (integration missed the r3merge mirror
// effect: sq −86 / sqlite −138 measured with an un-relinked examples
// binary) and the CASTFUSEB lane (the same −86/−138 mis-attributed to an
// unrelated commit; CR-CASTFUSEB net-baseline A/B proved both).
//
// mtime is deliberately NOT part of the digest: touching a file without a
// content change is not staleness (the binary still matches the sources).
// mtime gating stays in tools/verify_mirror_gate.sh as the complementary
// pre-run check ("binary must be younger than HEAD commit") covering the
// curl/httpd faces.
//
// The file must stay std-only and free of inner doc comments (`//!`) because
// build.rs includes it at top level.

use std::fs;
use std::path::{Path, PathBuf};

// RUGRA-GLUE: build/verification infrastructure — the locked Ghidra oracle
// has no counterpart for build-script plumbing; the guarded decompiler
// pipeline is untouched by this module.
pub const STALE_GUARD_DOMAIN: &str = "RUGRA-STALE-GUARD-V1";

// RUGRA-GLUE: FNV-1a-64 constants (public 64-bit variant).
const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

// RUGRA-GLUE: one FNV-1a-64 stream step over a byte slice.
pub fn fnv1a64(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(FNV1A_PRIME);
    }
    state
}

// RUGRA-GLUE: recursively collect the `.rs` files of `root` into `out`
// (unsorted; callers sort). Read errors on individual entries are skipped —
// a file that vanishes mid-walk simply drops out of both sides equally.
fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

// RUGRA-GLUE: digest of the guard domain under `root` — every
// `root/src/**/*.rs` plus the guard's own build inputs
// (`root/examples/gen_decompile.rs`,
// `root/examples/common/stale_guard_hash.rs`, `root/build.rs`), sorted by
// path, hashed with the framing documented in the module header. Returns
// (digest, file_count); Err only when the domain is unreadable (missing
// `src/` tree or an unreadable covered file) — callers treat that as
// fail-closed, never as "fresh".
pub fn source_digest(root: &Path) -> std::io::Result<(u64, usize)> {
    // Domain anchors are REQUIRED: an absent src/ tree (or guard build
    // input) is a broken domain (wrong CWD / not a checkout), not an empty
    // one — it must Err so callers fail closed with the unreadable-tree
    // verdict instead of mistaking a foreign directory for a valid empty
    // source tree.
    let src_root = root.join("src");
    if !src_root.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no src/ tree under {}", root.display()),
        ));
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    collect_rs_files(&src_root, &mut paths);
    for anchor in [
        root.join("examples").join("gen_decompile.rs"),
        root.join("examples").join("common").join("stale_guard_hash.rs"),
        root.join("build.rs"),
    ] {
        if !anchor.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("guard domain anchor missing: {}", anchor.display()),
            ));
        }
        paths.push(anchor);
    }
    paths.sort();
    let mut state = fnv1a64(FNV1A_OFFSET_BASIS, STALE_GUARD_DOMAIN.as_bytes());
    state = fnv1a64(state, &(paths.len() as u64).to_le_bytes());
    let mut count = 0usize;
    for path in &paths {
        let content = fs::read(path)?;
        // Location-independent framing: relative POSIX path bytes, so two
        // checkouts with identical content digest identically.
        let relative = path.strip_prefix(root).unwrap_or(path.as_path());
        let relative_bytes = relative.to_string_lossy().into_owned().into_bytes();
        state = fnv1a64(state, &relative_bytes);
        state = fnv1a64(state, &[0u8]);
        state = fnv1a64(state, &(content.len() as u64).to_le_bytes());
        state = fnv1a64(state, &content);
        count += 1;
    }
    Ok((state, count))
}

// RUGRA-GLUE: runtime verdict of the embedded build-time digest against the
// current source tree. `embedded_hex` is the build.rs-emitted
// RUGRA_BUILD_SOURCE_DIGEST (None when the build script did not run/emit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Embedded digest matches the current source tree (guard passes).
    Fresh { digest: u64 },
    /// Embedded digest differs — the binary is stale for this tree.
    Stale { embedded: u64, current: u64 },
    /// No usable build-time digest was embedded (fail-closed, not fresh).
    NoEmbeddedDigest,
    /// The digest domain itself is unreadable — wrong CWD or missing src.
    UnreadableSourceTree,
}

// RUGRA-GLUE: pure decision function (unit-tested below); callers render
// messages and exit codes.
pub fn guard_verdict(embedded_hex: Option<&str>, root: &Path) -> GuardVerdict {
    let Some(hex) = embedded_hex else {
        return GuardVerdict::NoEmbeddedDigest;
    };
    let Ok(embedded) = u64::from_str_radix(hex.trim(), 16) else {
        return GuardVerdict::NoEmbeddedDigest;
    };
    match source_digest(root) {
        Ok((current, _)) => {
            if current == embedded {
                GuardVerdict::Fresh { digest: current }
            } else {
                GuardVerdict::Stale { embedded, current }
            }
        }
        Err(_) => GuardVerdict::UnreadableSourceTree,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // RUGRA-GLUE: scratch fixture tree factory (content-addressed guard
    // semantics exercised on temp dirs, cleaned up best-effort).
    fn scratch_tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rugra-stale-guard-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).expect("scratch src dir");
        fs::create_dir_all(dir.join("examples/common")).expect("scratch examples dir");
        fs::write(dir.join("src/lib.rs"), b"fn alpha() {}\n").expect("scratch lib");
        fs::write(dir.join("examples/gen_decompile.rs"), b"fn main() {}\n")
            .expect("scratch driver");
        fs::write(
            dir.join("examples/common/stale_guard_hash.rs"),
            b"pub fn core() {}\n",
        )
        .expect("scratch shared core");
        fs::write(dir.join("build.rs"), b"fn main() {}\n").expect("scratch build script");
        dir
    }

    #[test]
    fn digest_is_stable_and_location_independent() {
        let tree_a = scratch_tree("loc-a");
        let tree_b = scratch_tree("loc-b");
        let (digest_a, count_a) = source_digest(&tree_a).expect("digest a");
        let (digest_b, count_b) = source_digest(&tree_b).expect("digest b");
        assert_eq!(digest_a, digest_b, "identical content must digest equally");
        assert_eq!(count_a, count_b);
        assert_eq!(
            count_a, 4,
            "src/lib.rs + driver + shared core + build.rs"
        );
        // Round-trip through the verdict: embedded hex -> Fresh.
        let hex = format!("{digest_a:016x}");
        assert_eq!(
            guard_verdict(Some(&hex), &tree_a),
            GuardVerdict::Fresh { digest: digest_a }
        );
        let _ = fs::remove_dir_all(tree_a);
        let _ = fs::remove_dir_all(tree_b);
    }

    #[test]
    fn content_change_flips_verdict_to_stale() {
        let tree = scratch_tree("content");
        let (digest, _) = source_digest(&tree).expect("digest");
        let hex = format!("{digest:016x}");
        fs::write(tree.join("src/lib.rs"), b"fn alpha() { 1 }\n").expect("mutate lib");
        match guard_verdict(Some(&hex), &tree) {
            GuardVerdict::Stale { embedded, current } => {
                assert_eq!(embedded, digest);
                assert_ne!(current, digest);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
        let _ = fs::remove_dir_all(tree);
    }

    #[test]
    fn guard_core_change_flips_verdict_to_stale() {
        // Regression for the RED-5 blind spot found in lane verification: a
        // change confined to examples/common/stale_guard_hash.rs (or
        // build.rs) alters the binary but was NOT in the original domain —
        // a binary stale only w.r.t. those files probed Fresh. Both are
        // domain anchors now.
        let tree = scratch_tree("guard-core");
        let (digest, _) = source_digest(&tree).expect("digest");
        let hex = format!("{digest:016x}");
        fs::write(
            tree.join("examples/common/stale_guard_hash.rs"),
            b"pub fn core() { 1 }\n",
        )
        .expect("mutate shared core");
        assert_ne!(
            guard_verdict(Some(&hex), &tree),
            GuardVerdict::Fresh { digest }
        );
        fs::write(tree.join("build.rs"), b"fn main() { 1 }\n").expect("mutate build script");
        assert_ne!(
            guard_verdict(Some(&hex), &tree),
            GuardVerdict::Fresh { digest }
        );
        let _ = fs::remove_dir_all(tree);
    }

    #[test]
    fn domain_membership_change_flips_verdict_to_stale() {
        // The accident shape: a NEW source file appears (e.g. a lane lands a
        // fix) but the old binary keeps running — content of existing files
        // unchanged, domain grew.
        let tree = scratch_tree("domain");
        let (digest, _) = source_digest(&tree).expect("digest");
        let hex = format!("{digest:016x}");
        fs::write(tree.join("src/new_module.rs"), b"pub fn beta() {}\n").expect("grow domain");
        assert_ne!(
            guard_verdict(Some(&hex), &tree),
            GuardVerdict::Fresh { digest }
        );
        let _ = fs::remove_dir_all(tree);
    }

    #[test]
    fn missing_digest_and_unreadable_tree_fail_closed() {
        let tree = scratch_tree("failclosed");
        assert_eq!(guard_verdict(None, &tree), GuardVerdict::NoEmbeddedDigest);
        assert_eq!(
            guard_verdict(Some("not-hex"), &tree),
            GuardVerdict::NoEmbeddedDigest
        );
        let ghost = std::env::temp_dir().join(format!(
            "rugra-stale-guard-{}-ghost",
            std::process::id()
        ));
        let (digest, _) = source_digest(&tree).expect("digest");
        let hex = format!("{digest:016x}");
        assert_eq!(
            guard_verdict(Some(&hex), &ghost),
            GuardVerdict::UnreadableSourceTree
        );
        let _ = fs::remove_dir_all(tree);
    }

    #[test]
    fn empty_file_framing_is_unambiguous() {
        // Length framing must distinguish (path, b"") from (path, NUL...)
        // collisions: same paths, one empty one non-empty file.
        let tree = scratch_tree("framing");
        fs::write(tree.join("src/empty.rs"), b"").expect("empty file");
        let (with_empty, _) = source_digest(&tree).expect("digest with empty");
        fs::remove_file(tree.join("src/empty.rs")).expect("remove empty");
        let (without_empty, _) = source_digest(&tree).expect("digest without empty");
        assert_ne!(with_empty, without_empty);
        let _ = fs::remove_dir_all(tree);
    }
}
