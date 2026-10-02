# HTTPD follow-flow mirror loading (RUGRA-FLOW-MIRROR on the httpd driver)

Lane BP (wt/sb-httpdff), 2026-09-22. Deliverable: an env-gated follow-flow
loading path for `examples/httpd_decompile.rs` that reproduces the oracle
single-function input contract (third input contract convergence), so the
stage-projection consumer's `load_mode` identity key stops hard-blocking
httpd cross-side comparison. The default (env-unset) path stays
byte-identical.

## 1. Oracle input contract (locked, e40ed130)

`tests/oracle/stage_projection_1204.cc` (wt/sb-oracle 5ec5107) `run()`:

1. `BfdArchitecture(binary, "default")` — raw SLEIGH/BFD load, every PT_LOAD
   mapped, no Java analyzers, no DWARF import, no generic_clib signatures.
2. `readLoaderSymbols("::")` — static `.symtab` only (loadimage_bfd.cc:194-225);
   httpd is stripped, registers nothing.
3. Fallback `registerDynamicFunctionSymbols` — `.dynsym` `BSF_FUNCTION`,
   undefined imports skipped, `Scope::addFunction` per symbol. httpd: 473
   defined FUNC dynsyms (main @0x2b820, st_size 3062).
4. `queryFunction("main")` → Funcdata; entry identity pinned to 0x2b820.
5. `fd->followFlow(Address(code,0), Address(code,code->getHighest()))` — the
   unbounded-range flow walk (funcdata_op.cc:756).
6. META emits `load_mode=single_function_bfd`, `unique_base=0x364200`
   (advisory-only in the consumer).

Existing oracle artifact (no rebuild needed):
`/dev/shm/rudra-tests/sb-oracle/httpd.main.oracle.projection`
(events=294 snaps=294 ops=878973 restarts=0,
sha256=3815f999ef5676a5b17a85f0be60938fad3dfa1e7dabc9be5cefca007d95d8a3,
binary_sha256=805f89cdbdce827f8f6ccd877aa7c344ff1105713b7bf7b0e6f313affa93b1c1).

## 2. What is transplanted from the curl driver (master AQ lineage)

- `worker_memory_image_bytes` example-layer construction: PT_LOAD segments
  laid out at their virtual addresses, image top = max(vaddr+memsz), NOBITS
  (.bss) zero-fill. Identical builder works for httpd (see §3.1).
- Gate: `RUDRA_MIRROR=1` (canonical bundle key) or legacy
  `RUDRA_FLOW_MIRROR=1` → `mirror_flow_enabled()`
  (MIRROR-ENVS-CANONICAL-0001 accessor form). httpd has no libc-signature
  ledger and no known-noreturn marking, so the bundle reduces to the flow
  component on this driver.
- Under the gate: SLEIGH configured over the full image at base 0
  (`configure_x86_64(&full_image, 0)`) + `rudra::flow::follow_flow_range(fd,
  sleigh, 0, u64::MAX, ∅)` + projection META `load_mode=single_function_bfd`
  (D10 honest literal).
- Everything env-unset: the historical iced linear disassemble → lift →
  `inject_raw_ops` path, byte-identical (verified by `cmp`).

## 3. httpd diff points vs curl

### 3.1 PT_LOAD
httpd is PIE with 4 PT_LOADs:

| vaddr | flags | filesz | memsz | content |
|---|---|---|---|---|
| 0x0 | R | 0x28b40 | 0x28b40 | headers, .rela.* |
| 0x29000 | R E | 0x50535 | 0x50535 | .plt .plt.sec .text (main @0x2b820) |
| 0x7a000 | R | 0x1ef80 | 0x1ef80 | .rodata |
| 0x999f0 | RW | 0x6df0 | 0xa3d0 | .data/.got + .bss zero-fill |

Image top = 0xa3cc0 (~419 KB). The memsz>filesz tail is the .bss zero-fill
the curl builder already handles (`vec![0; top]` then copy filesz bytes).
No builder change needed.

### 3.2 symbols
curl has a full `.symtab`; httpd is stripped — the oracle's only function
source is the 473 defined `.dynsym` FUNC entries. Under the mirror gate the
driver seeds exactly that set (`functions` list = symtab ∪ dynsym-defined;
symtab is empty here). NOT seeded under mirror:
- PLT thunk import names (`.plt.sec` 0x2a420..0x2b7f0) — Ghidra's Java
  ELF/PLT analyzer creates those thunks; the bare BFD harness has none.
- `FUN_0012xxxx` defaults for analysis-discovered functions — same reason.
Default path keeps the full seeded table (HTTPD-URAM-SYMBOLIZE-0001).

### 3.3 PLT
httpd's imports (apr_*/libc) are UND dynsyms; direct calls land on `.plt.sec`
thunks. Under the unbounded `(0, u64::MAX)` walk, tail jumps into thunks are
followed in-function; the thunk's GOT-indirect jump becomes BRANCHIND →
jumptable recovery fail-thunk truncation (jumptable.cc:2304-2320 → flow.cc
:727/735 CALLIND + artificial halt) — the same contract the curl mirror
established for its PLT. SLEIGH decodes the thunks because the image covers
0x29000+.

### 3.4 driver-side state skipped under mirror (oracle-bare parity)
- Tail-call `CALL_RETURN` localoverrides: inject-path TailCallAnalyzer
  transport — the oracle runs no analyzers. Default path keeps them.
- `fd.external_prototypes` (prepass-inferred param counts): driver-only data;
  the bare BFD harness carries no callee signature data (same principle as
  curl's `RUDRA_BARE_LOAD` emptying the libc ledger). Left empty.
- `.rodata` string seeding is KEPT: the oracle StringManager reads the same
  bytes through the loader (stringmanage.cc loadFill), so the seed mirrors
  oracle-side data, not analyzer output.

### 3.5 lifter
Default path: iced (`X86_64Disassembler` + `X86Lifter` + `inject_raw_ops`).
Mirror path: `SleighLifter` + `follow_flow_range` — first SLEIGH-driven load
in this driver. The lifter is constructed inside the per-function thread
(SLEIGH ctx is not Send; one configure per selected function, same shape as
the curl worker). flow.rs itself registers call specs during the walk
(`setup_call_specs`, flow.cc:680), so no driver-side qlst registration is
needed on this path.

## 4. Verification results (M3, 2026-09-22)

1. **load_mode flip** — `RUDRA_MIRROR=1 RUDRA_STAGE_PROJ=1
   RUDRA_STAGE_FUNC=main RUDRA_STAGE_PROJ_OUT=…` produces
   `META binary_sha256=805f89cd… func_entry=0x2b820 func_name=main
   load_mode=single_function_bfd` — the consumer's identity precheck
   passes against the locked oracle projection (only advisory warnings:
   producer blob, unique_base 0x364200 vs 10000000). Projection:
   `/dev/shm/rudra-tests/sb-httpdff/httpd_main_mirror2.proj`
   (sha256 bc203c43…, 263 @SNAPs).
2. **Cross-side first divergence (new territory)** — first run exposed a
   driver-side loading defect, then the converged contract's first real
   divergence:
   - Run 1 (bare Architecture, no loader): first divergence at stage
     ordinal 2 (`universal:start`), op-line 476 — oracle keeps
     `2ba94:1dc BRANCHIND` (a relative-offset switch: table @0x88530 via
     `lea 0x5caa6(%rip); movslq (%rcx,%rax,4); add %rcx,%rax;
     notrack jmp *%rax`, guarded at 2ba7f) and walks the case bodies at
     0x2ba97+; Rudra fail-thunked it into `CALLIND` + artificial
     `RETURN` (1404 ops / 55 blocks vs oracle walking on). Root cause:
     jumptable recovery reads table bytes through `fd.arch.loader`
     (jumptable.rs:2568/3152/5229 — the jumptable.cc:1225-1226/1588-1598
     MemoryImage channel); fixed by attaching a RawLoadImage over the
     PT_LOAD bytes to the mirror-path Architecture (commit fef1ba2).
   - Run 2 (loader attached): stages 1-2 snapshots are **op-line
     identical on both sides** — the loading contract converges (main
     loads 2040 ops / 92 blocks). First divergence moves to stage
     ordinal 3, tree-path `universal:constbase`, round 0, op-line 3
     (`/dev/shm/rudra-tests/sb-httpdff/cross_side_report2.txt`):
     - oracle-only: `2b824:7f8 COPY d=0 out=n:register:20a:1 in=c:0:1`
       (uniq 0x7f8 = 2040 — freshly allocated after the initial tree,
       i.e. created during start/constbase on the oracle side);
     - rudra-only: `2b826:6 INT_ZEXT d=0 out=n:register:10:8
       in=n:register:10:4` (uniq 6 — in Rudra's initial tree: the
       implicit 32→64 zero-extension of the `xor edx,edx` write at
       0x2b826).
     Attribution is pipeline-level (a start/constbase-phase transform
     difference around partial-register writes vs zero-extension), NOT a
     loading difference — beyond this lane's write-set; recorded for
     dispatch.
3. **env-off byte identity** — full default E2E with the final binary vs
   a master-build binary: `cmp` clean, both
   sha256 e91880ddb84bc3c430a5573a527a240b04ab6e0e5a0f9b6ca85501189149a897
   (29 function headers, `/dev/shm/rudra-tests/sb-httpdff/envoff_*.c`).

## 5. Known advisory deltas (recorded, not blocking)

- `unique_base`: oracle 0x364200 vs Rudra 10000000 — advisory warning in the
  consumer (compare-the-base-first canary); same standing delta as the curl
  lane.
- `producer` blob and `callspec_link=inject-path` annotation remain
  producer-level notes, never identity keys.
