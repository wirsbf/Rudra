// (kuna) Build script for kuna-sleigh: emit a content digest over the SOURCE
// TREES of the three kuna crates whose code can change the decoded SLEIGH
// table graph (kuna-base [marshal/space], kuna-num [opcodes/pcoderaw],
// kuna-sleigh [the engine itself]) as KUNA_SLEIGH_BUILD_DIGEST.
//
// SPEEDPROF-SLEIGH-SNAPSHOT-0001 uses this digest as part of the engine
// table snapshot cache key, so ANY source change in those trees automatically
// invalidates every previously written snapshot: a snapshot produced by one
// build is never decoded by a build whose decode/encode code differs.  This
// mirrors the framing discipline of the root package's stale-guard
// (examples/common/stale_guard_hash.rs): relative POSIX paths, NUL, u64-LE
// length, bytes, over FNV-1a-64 with a domain-separation prefix.
//
// RUDRA-GLUE: build/verification infrastructure — the locked Ghidra oracle
// has no counterpart for build-script plumbing; the guarded decompiler
// pipeline is untouched by this module.

use std::fs;
use std::path::{Path, PathBuf};

const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;
const BUILD_DIGEST_DOMAIN: &str = "KUNA-SLEIGH-BUILD-DIGEST-V1";

fn fnv1a64(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(FNV1A_PRIME);
    }
    state
}

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

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    // The digest domain: the vendored kuna source trees. The rerun triggers
    // make cargo re-run this script (and hence rebuild the crate and its
    // dependents) whenever any covered file changes.
    for crate_name in ["kuna-base", "kuna-num", "kuna-sleigh"] {
        let src = manifest_dir.join("..").join(crate_name).join("src");
        println!("cargo:rerun-if-changed={}", src.display());
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for crate_name in ["kuna-base", "kuna-num", "kuna-sleigh"] {
        let src = manifest_dir.join("..").join(crate_name).join("src");
        if !src.is_dir() {
            panic!("kuna build digest: missing source tree {}", src.display());
        }
        collect_rs_files(&src, &mut paths);
    }
    // Anchor on this build script too: changing the digest framing itself
    // must re-key every snapshot.
    let build_script = manifest_dir.join("build.rs");
    println!("cargo:rerun-if-changed={}", build_script.display());
    paths.push(build_script);
    paths.sort();
    let mut state = fnv1a64(FNV1A_OFFSET_BASIS, BUILD_DIGEST_DOMAIN.as_bytes());
    state = fnv1a64(state, &(paths.len() as u64).to_le_bytes());
    for path in &paths {
        let content = match fs::read(path) {
            Ok(content) => content,
            Err(error) => panic!("kuna build digest: cannot read {}: {error}", path.display()),
        };
        // Relative to the workspace root (crates/<name>/src/...), so two
        // checkouts with identical content digest identically.
        let relative = path
            .strip_prefix(manifest_dir.join(".."))
            .unwrap_or(path.as_path());
        let relative_bytes = relative.to_string_lossy().into_owned().into_bytes();
        state = fnv1a64(state, &relative_bytes);
        state = fnv1a64(state, &[0u8]);
        state = fnv1a64(state, &(content.len() as u64).to_le_bytes());
        state = fnv1a64(state, &content);
    }
    println!("cargo:rustc-env=KUNA_SLEIGH_BUILD_DIGEST={state:016x}");
}
