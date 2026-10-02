# capability.rs — Capability extension points API

Faithful port of Ghidra's `capability.hh` / `capability.cc` (51 lines).

**Status:** L1 → L2. Complete CapabilityPoint trait + CapabilityRegistry +
global singleton. This is the base system that ArchitectureCapability,
PrintLanguageCapability, and other extension points build upon.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/capability.{hh,cc}`.

## Trait `CapabilityPoint`
Base trait for extension points (capability.hh:39).
- `initialize()` — complete initialization (capability.hh:49).

## `CapabilityRegistry`
Registry of extension point singletons (capability.cc:24).
- `new()` — empty registry.
- `register(point)` — register an extension (capability.cc:33 behavior).
- `initialize_all()` — call initialize on all, then clear (capability.cc:40).
- `num_points() -> usize`, `is_empty() -> bool`.

## `global_registry()`
Get the global singleton registry (replaces Ghidra's static `getList()`).
<!-- annotation-pass: 2026-07-04 -->
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
