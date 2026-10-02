# Projection Bank — mechanism B2 solidified fixtures

Per-function stage-projection fixture bank: for each banked function, the
frozen oracle-side and rugra-side v1.2 stage projections plus a manifest
that pins provenance and byte identity. This directory is the durable,
in-repo form of the RAM-disk lane evidence (the `/dev/shm/rugra-tests/sb-*`
projection products are lost on reboot); it exists so that the banked
proven-MATCH functions cannot silently regress.
projection products are lost on reboot); it exists so that every
banked proven-MATCH function cannot silently regress.

## Layout

```
tests/fixtures/projections/
  README.md                          <- this manifest
  curl_<function>/
    oracle.projection                <- locked-oracle capture (frozen)
    rugra.projection                 <- rugra driver capture (frozen)
    manifest.toml                    <- provenance + sha256 pins + status
```

## Banked functions (all MATCH; 10 original + 15 cascade-harvest + helpf + 45 curl PLT-thunk + 320 httpd PLT-thunk address-arm harvest = 391)

| entry | function | entry addr | stages | ops | oracle pin |
|---|---|---|---|---|---|
| curl_next_url | next_url | 0x4ff0 | 335 | 96,457 | metadata (default-mode, cross-mode byte-verified) |
| curl_match_url | match_url | 0x5220 | 340 | 80,385 | bank sha256 |
| curl_parseconfig.constprop.0 | parseconfig.constprop.0 | 0x3c80 | 335 | 130,099 | bank sha256 (== lane pin b2ace56a…) |
| curl_myprogress | myprogress | 0x34d0 | 402 | 84,249 | bank sha256 |
| curl_getparameter.constprop.0 | getparameter.constprop.0 | 0x3f00 | 371 | 913,373 | metadata functions map |
| curl_glob_set | glob_set | 0x4bc0 | 366 | 141,943 | bank sha256 (capture-mode first, then frozen) |
| curl_glob_word | glob_word | 0x4a60 | 335 | 208,414 | bank sha256 (capture mode, re-capture byte-verified) |
| curl_glob_range | glob_range | 0x4d60 | 299 | 68,330 | bank sha256 (capture mode, double-run byte-verified) |
| curl_file2string.part.0 | file2string.part.0 | 0x3a90 | 340 | 87,957 | bank sha256 (== sb-oracle pin c0981445…) |
| curl_my_get_token | my_get_token | 0x3720 | 520 | 53,359 | bank sha256 (capture mode, direct MATCH, no fix needed) |
| curl_main_free | main_free | 0x4970 | 150 | 200 | bank sha256 (capture mode, cascade harvest) |
| curl_main_init | main_init | 0x4960 | 155 | 615 | bank sha256 (capture mode, cascade harvest) |
| curl_SetHTTPrequest.part.0 | SetHTTPrequest.part.0 | 0x3c50 | 191 | 1,655 | bank sha256 (capture mode, cascade harvest) |
| curl_SetHTTPrequest | SetHTTPrequest | 0x4980 | 191 | 4,511 | bank sha256 (capture mode, cascade harvest) |
| curl_glob_url | glob_url | 0x4f70 | 191 | 7,288 | bank sha256 (capture mode, cascade harvest) |
| curl_frame_dummy | frame_dummy | 0x3450 | 186 | 2,785 | bank sha256 (capture mode, cascade harvest) |
| curl___do_global_dtors_aux | __do_global_dtors_aux | 0x3410 | 191 | 5,363 | bank sha256 (capture mode, cascade harvest) |
| curl__init | _init | 0x2000 | 191 | 2,149 | bank sha256 (capture mode, cascade harvest) |
| curl__fini | _fini | 0x5478 | 150 | 506 | bank sha256 (capture mode, cascade harvest) |
| curl___libc_csu_fini | __libc_csu_fini | 0x5470 | 150 | 200 | bank sha256 (capture mode, cascade harvest) |
| curl___libc_csu_init | __libc_csu_init | 0x5400 | 227 | 7,064 | bank sha256 (capture mode, cascade harvest) |
| curl_deregister_tm_clones | deregister_tm_clones | 0x33a0 | 186 | 1,172 | bank sha256 (capture mode, cascade harvest) |
| curl_register_tm_clones | register_tm_clones | 0x33d0 | 186 | 2,747 | bank sha256 (capture mode, cascade harvest) |
| curl_GetStr | GetStr | 0x36d0 | 191 | 5,349 | bank sha256 (capture mode, cascade harvest) |
| curl_my_fwrite | my_fwrite | 0x3460 | 268 | 7,788 | bank sha256 (capture mode, cascade harvest) |
| curl_helpf | helpf | 0x3980 | 345 | 195,009 | bank sha256 (capture mode; PM-HF lane, mark_unaliased range-walk fix) |

PLT-thunk entries (2026-09-25, lane ADDRARM2; all captured through the
oracle harness **address-only arm** — these entries carry no BFD symbol
in any table, so the runner CLI passes `-` as the function token and the
fixture registers the function at the entry exactly like the console
`load <addr>` command; the rugra side uses the address-form selector).
44 of the 45 share the uniform stub shape 186 stages / 742 ops; PLT0 is
richer (191 / 1,240):

| entry | function | entry addr | stages | ops |
|---|---|---|---|---|
| curl_plt_plt0 | FUN_00102020 (PLT0 header) | 0x2020 | 191 | 1,240 |
| curl_plt___cxa_finalize | __cxa_finalize (.plt.got) | 0x22e0 | 186 | 742 |
| curl_plt_free | free | 0x22f0 | 186 | 742 |
| curl_plt___vfprintf_chk | __vfprintf_chk | 0x2300 | 186 | 742 |
| curl_plt_strcpy | strcpy | 0x2310 | 186 | 742 |
| curl_plt_puts | puts | 0x2320 | 186 | 742 |
| curl_plt_isatty | isatty | 0x2330 | 186 | 742 |
| curl_plt_curl_easy_perform | curl_easy_perform | 0x2340 | 186 | 742 |
| curl_plt_curl_slist_append | curl_slist_append | 0x2350 | 186 | 742 |
| curl_plt_fclose | fclose | 0x2360 | 186 | 742 |
| curl_plt_strlen | strlen | 0x2370 | 186 | 742 |
| curl_plt___stack_chk_fail | __stack_chk_fail | 0x2380 | 186 | 742 |
| curl_plt_strchr | strchr | 0x2390 | 186 | 742 |
| curl_plt_strrchr | strrchr | 0x23a0 | 186 | 742 |
| curl_plt_maprintf | maprintf | 0x23b0 | 186 | 742 |
| curl_plt_fputc | fputc | 0x23c0 | 186 | 742 |
| curl_plt_fgets | fgets | 0x23d0 | 186 | 742 |
| curl_plt_strtol | strtol | 0x23e0 | 186 | 742 |
| curl_plt_memcpy | memcpy | 0x23f0 | 186 | 742 |
| curl_plt_time | time | 0x2400 | 186 | 742 |
| curl_plt_fileno | fileno | 0x2410 | 186 | 742 |
| curl_plt___xstat | __xstat | 0x2420 | 186 | 742 |
| curl_plt_malloc | malloc | 0x2430 | 186 | 742 |
| curl_plt___isoc99_sscanf | __isoc99_sscanf | 0x2440 | 186 | 742 |
| curl_plt_curl_easy_init | curl_easy_init | 0x2450 | 186 | 742 |
| curl_plt_curl_getenv | curl_getenv | 0x2460 | 186 | 742 |
| curl_plt_realloc | realloc | 0x2470 | 186 | 742 |
| curl_plt___printf_chk | __printf_chk | 0x2480 | 186 | 742 |
| curl_plt_curl_version | curl_version | 0x2490 | 186 | 742 |
| curl_plt_curl_slist_free_all | curl_slist_free_all | 0x24a0 | 186 | 742 |
| curl_plt_fopen | fopen | 0x24b0 | 186 | 742 |
| curl_plt_strcat | strcat | 0x24c0 | 186 | 742 |
| curl_plt_curl_easy_setopt | curl_easy_setopt | 0x24d0 | 186 | 742 |
| curl_plt_curl_getdate | curl_getdate | 0x24e0 | 186 | 742 |
| curl_plt_exit | exit | 0x24f0 | 186 | 742 |
| curl_plt_fwrite | fwrite | 0x2500 | 186 | 742 |
| curl_plt___fprintf_chk | __fprintf_chk | 0x2510 | 186 | 742 |
| curl_plt_curl_easy_cleanup | curl_easy_cleanup | 0x2520 | 186 | 742 |
| curl_plt_strdup | strdup | 0x2530 | 186 | 742 |
| curl_plt_strequal | strequal | 0x2540 | 186 | 742 |
| curl_plt_curl_formparse | curl_formparse | 0x2550 | 186 | 742 |
| curl_plt_strstr | strstr | 0x2560 | 186 | 742 |
| curl_plt_strnequal | strnequal | 0x2570 | 186 | 742 |
| curl_plt___ctype_b_loc | __ctype_b_loc | 0x2580 | 186 | 742 |
| curl_plt___sprintf_chk | __sprintf_chk | 0x2590 | 186 | 742 |

Common provenance (also recorded per manifest):

- oracle: Ghidra `Ghidra_12.0.4_build`, commit
  `e40ed13014025f82488b1f8f7bca566894ac376b` (the project's locked oracle)
- architecture `x86:LE:64:default`, compiler spec `gcc`,
  analysis_options `default`, build_flags `v1-no-OPACTION_DEBUG`
- corpus binary: `examples/curl`
  (sha256 `8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`)
- rugra driver commit at capture: `dc7a0d0ad5ba94cebb9488549ff17db3a0a0c0ca`
  for the original five (master when the bank was cut); the bank commit
  itself only adds fixtures. `curl_glob_set` was captured later at
  `cd071239883d9e536aca5ed71adc6f6d6ee52b04` (per its manifest).

## Verification

```bash
tools/verify_projection_bank.sh                     # all entries
tools/verify_projection_bank.sh curl_next_url       # single entry
```

Exit 0 only when every entry is complete, both projections still match
their manifest sha256 pins, and `tools/run_stage_bisect.sh` (=
`stage_bisect.py --v1`, strict offsets, no relax-unique) reports
`kind: MATCH`. The runner is the CI-gate form of mechanism B2 for these
functions; a failure names the entry and the offending check.

Advisory-only META differences between the two sides (expected, reported
as warnings by the bisect, never identity failures): `side`, `producer`
(rugra-tree commit vs oracle fixture blob), `unique_base` (driver prints
its allocation base; strict op offsets still compare), and
`func_name` for the two GCC constprop clones (the rugra driver's FuncInfo
layer carries the DWARF spelling `parseconfig`/`getparameter`; the oracle
fixture carries the BFD spelling — identity is entry-address based), and
`func_name` for the PLT-thunk entries (oracle `func_0x…` nameFunction
default vs driver ledger spelling — same entry-address identity basis).

## Re-capture recipes (byte-identical reproduction)

Both producers must be re-run and re-bisected before any projection byte
may change; a re-capture that produces different bytes is a regression to
investigate, not a pin to update silently.

Oracle side (requires the locked ghidra tree + binutils 2.38 BFD, see
`tools/run_stage_projection_oracle.sh` header for the environment
contract; `/tmp/rugra-ghidra-bfd-2.38` is the usual include root):

```bash
RUDRA_STAGE_PROJECTION_OUT=tests/fixtures/projections/curl_<fn>/oracle.projection \
  bash tools/run_stage_projection_oracle.sh curl <entry-hex> <function>
# next_url may equivalently use the zero-arg default mode (same bytes).
# PLT-thunk entries (no BFD symbol): pass "-" as the function token to
# take the address-only arm, e.g. ... curl 22f0 -   (see curl_plt_*).
# Batch drivers may set RUDRA_STAGE_PROJECTION_BUILD=<dir> to cache the
# instrumented oracle build across invocations.
```

Rugra side (cwd = repo root; projection lands via RUDRA_STAGE_PROJ_OUT;
each capture is run twice and `cmp`-verified deterministic before banking):

```bash
RUDRA_MIRROR=1 RUDRA_STAGE_PROJ=1 RUDRA_STAGE_FUNC=<selector> \
  RUDRA_STAGE_PROJ_OUT=tests/fixtures/projections/curl_<fn>/rugra.projection \
  cargo run --profile fast-release --example curl_decompile
```

Selector spellings: `next_url`, `match_url`, `myprogress`, `glob_set`,
`parseconfig` (DWARF spelling of `parseconfig.constprop.0`),
`getparameter` (DWARF spelling of `getparameter.constprop.0`),
`glob_word`, `glob_range`; the address form `0x<entry>` is
observation-equivalent (verified byte-identical on parseconfig).
`file2string` (DWARF spelling of `file2string.part.0`); the
address form `0x<entry>` is observation-equivalent (verified byte-identical
on parseconfig). The `file2string` entry's advisory-only `func_name` META
difference is the same constprop-clone BFD/DWARF spelling class.
`helpf` (local symbol; no spelling divergence — BFD and the driver's
FuncInfo layer agree on this name).

The 15 cascade-harvest entries (2026-09-24, lane HARVEST) were captured
with the address-form selector `RUDRA_STAGE_FUNC=0x<entry>`
(`main_free`, `main_init`, `SetHTTPrequest.part.0`, `SetHTTPrequest`,
`glob_url`, `frame_dummy`, `__do_global_dtors_aux`, `_init`, `_fini`,
`__libc_csu_fini`, `__libc_csu_init`, `deregister_tm_clones`,
`register_tm_clones`, `GetStr`, `my_fwrite`); their manifests record
the exact per-entry commands. All entries and pins use the oracle
harness's nm-style address convention (no 0x100000 image base), the
same convention as `main@0x25a0` in the metadata functions map.

Non-MATCH scan residue from the same harvest pass (first divergence
recorded for later lanes; not banked):

| function | entry | kind | first divergence |
|---|---|---|---|
| hugehelp | 0x4a00 | op-line | ordinal 2 `universal:start` op 14: oracle `BRANCH in=n:ram:2320:1` vs rugra `CALL in=f:4a0f:c`; op totals 1,699 vs 4,314 |
| main | 0x25a0 | op-line | ordinal 5 `universal:extrapopsetup` op 1792: identical INT_ADD at differing op-creation ordinal (`2d04:c15` oracle vs `2d04:c0e` rugra, +7 pool offset); op totals 2,414,145 vs 2,413,566 |
| my_get_line | 0x3840 | result-count | ordinal 52 `universal:fullloop:mainloop:condconst`: result/count 2 vs 1 |
| helpf | 0x3980 | result-count | ordinal 70 `universal:fullloop:mainloop:stackstall:oppool1`: result/count 118 vs 110 |
| _start | 0x3370 | result-count | ordinal 149 `universal:fullloop:mainloop:constantptr`: result/count/apply 3/3/1 vs 0/0/0 (ACTION-SYMDB-DATASYM-0001 class) |
| progressbarinit | 0x49a0 | op-line | ordinal 123 `universal:fullloop:activereturn` op 9: CALL out `n:register:0:8` vs `u:0:8` |

Oracle-side capture limitation observed in the 2026-09-24 harvest pass
and **resolved 2026-09-25 (lane ADDRARM2)**: PLT thunk functions (the
`.plt.sec`/`.plt.got` stubs and the PLT0 header, e.g. `free@0x22f0`)
carry no BFD symbol in any table (static `.symtab` has nothing; the
dynamic table only carries the undefined import), so the harness's
`STAGE_PROJ_FUNC` name lookup could not target them. The runner now has
an address-only arm: `bash tools/run_stage_projection_oracle.sh curl
<entry-hex> -` passes `STAGE_PROJ_ADDR` without `STAGE_PROJ_FUNC`, and
the fixture then registers the function at the entry exactly like the
Ghidra console `load <addr>` command (IfcAddrrangeLoad,
ifacedecomp.cc:496-514: `Architecture::nameFunction` default name +
global-scope `addFunction`). The full ledger-populated thunk population
(45 entries, 0x2020 + 0x22e0-0x2590 nm-form) was swept through this arm
and every one of them matched on first verification (see the PLT table
above). The `func_name` META field differs by construction on these
entries (oracle `func_0x000022f0`-style default vs the driver's ledger
spelling) and is advisory under the bisect contract — the same class as
the constprop BFD/DWARF spellings. The remaining out-of-reach golden
corpus entries are the EXTERNAL-block pseudo functions at 0x19xxx-nm
(they have no backing ELF section at all — no code to follow on either
side; the driver prints stub sections, the oracle has nothing to load).

Fixture producer re-pin (same lane): the fixture grew the address arm,
so its git blob (the META `producer=` value inside every oracle
projection) changed from `f6cb61d1…` to `24a4bec2…`; all 26 pre-existing
entries' oracle projections were re-captured and re-pinned with the
producer line verified as the only byte difference.

## httpd PLT-thunk population (2026-09-25, lanes HBANK + HBANK2 — inventoried,
## oracle-captured, unlocked and banked: 320/320 first-verification MATCH)

The httpd corpus carries the same first-section PLT thunk family curl
has, at a larger scale. Enumerated with the same readelf `-S`/`-r`
method as the curl sweep (only real code slots in the executable PLT
sections enter — EXTERNAL pseudo-functions have no code bytes and are
excluded by construction):

| segment | entries | stages/ops |
|---|---|---|
| PLT0 header @0x29020 | 1 | 191 / 1,240 |
| .plt.got (apr_bucket_free @0x2a400, __cxa_finalize @0x2a410) | 2 | 186 / 742 |
| .plt.sec @0x2a420-0x2b7e0 | 317 | 186 / 742 |

320 entries total (ledger: `make_inventory.py` method over readelf
`-S`/`-r`; httpd is stripped, so unlike curl none of these thunks appear
in any BFD symbol table — the address-only arm is the only oracle
capture channel). All 320 oracle projections were captured
deterministically (double-run cmp) through it with the shared build
cache (`RUDRA_STAGE_PROJECTION_BUILD`) by lane HBANK, and lane HBANK2
unlocked the rugra side: the httpd driver's stage-selectable function
ledger was dynsym-defined-only (473 entries, first at 0x2b820), so
`RUDRA_STAGE_FUNC=0x2a430` exited 1 — the driver now carries a
stage-gated PLT-thunk ledger arm (`HBANK-DRIVER-STAGELEDGER-0001`,
driver commit 534f9802) scanning the same slot population (PLT0 via
the `.plt` head with the golden `FUN_00129020` spelling, `.plt.got` via
per-slot GOT-tail decode against `.rela.dyn` GLOB_DAT owners — both
bnd and plain `ff 25` spellings, httpd is plain — and `.plt.sec` slot i
via the i-th `.rela.plt` JUMP_SLOT; ledger 793 = 473 dynsym + 320
thunks). The arm is selector surface only: it is gated on the stage
envs and lands after every other ledger consumer, and the env-unset
default E2E output stays byte-identical to the parent build (cmp
verified; the only stderr difference is the pre-existing `[INJECT]`
log interleave order, which the parent build also exhibits between its
own two runs).

Every one of the 320 entries matched on first verification (bisect
`--v1` strict offsets; the advisory-only META set is the same class as
the curl PLT entries: `func_name` oracle `func_0x…` default vs driver
ledger spelling, `producer`, `unique_base`). The two `.plt.got` plain-
form slots (apr_bucket_free, __cxa_finalize) decode through the
driver-side arm — the shared `debugproto::ElfPltImports` name layer
still misses them (bnd-only `.plt.got` decode, registered in the TODO
board; that layer feeds call-site naming on the canon E2E face and is
outside this bank's selector surface).

| entry | function | entry addr | stages | ops |
|---|---|---|---|---|
| httpd_plt_plt0 | FUN_00129020 (PLT0 header) | 0x29020 | 191 | 1240 |
| httpd_plt_apr_bucket_free | apr_bucket_free | 0x2a400 | 186 | 742 |
| httpd_plt___cxa_finalize | __cxa_finalize | 0x2a410 | 186 | 742 |
| httpd_plt_apr_file_open_stdout | apr_file_open_stdout | 0x2a420 | 186 | 742 |
| httpd_plt_apr_procattr_cmdtype_set | apr_procattr_cmdtype_set | 0x2a430 | 186 | 742 |
| httpd_plt_apr_brigade_putstrs | apr_brigade_putstrs | 0x2a440 | 186 | 742 |
| httpd_plt_apr_getopt_init | apr_getopt_init | 0x2a450 | 186 | 742 |
| httpd_plt_apr_proc_mutex_unlock | apr_proc_mutex_unlock | 0x2a460 | 186 | 742 |
| httpd_plt___ctype_toupper_loc | __ctype_toupper_loc | 0x2a470 | 186 | 742 |
| httpd_plt_getenv | getenv | 0x2a480 | 186 | 742 |
| httpd_plt_apr_table_add | apr_table_add | 0x2a490 | 186 | 742 |
| httpd_plt_apr_hash_first | apr_hash_first | 0x2a4a0 | 186 | 742 |
| httpd_plt_apr_bucket_pool_create | apr_bucket_pool_create | 0x2a4b0 | 186 | 742 |
| httpd_plt_apr_xml_parser_done | apr_xml_parser_done | 0x2a4c0 | 186 | 742 |
| httpd_plt_apr_array_make | apr_array_make | 0x2a4d0 | 186 | 742 |
| httpd_plt_apr_time_exp_gmt | apr_time_exp_gmt | 0x2a4e0 | 186 | 742 |
| httpd_plt_free | free | 0x2a4f0 | 186 | 742 |
| httpd_plt_apr_dso_error | apr_dso_error | 0x2a500 | 186 | 742 |
| httpd_plt_apr_md5_init | apr_md5_init | 0x2a510 | 186 | 742 |
| httpd_plt_putchar | putchar | 0x2a520 | 186 | 742 |
| httpd_plt_apr_brigade_pflatten | apr_brigade_pflatten | 0x2a530 | 186 | 742 |
| httpd_plt_strcasecmp | strcasecmp | 0x2a540 | 186 | 742 |
| httpd_plt_apr_md5_update | apr_md5_update | 0x2a550 | 186 | 742 |
| httpd_plt_apr_pmemdup | apr_pmemdup | 0x2a560 | 186 | 742 |
| httpd_plt_abort | abort | 0x2a570 | 186 | 742 |
| httpd_plt_apr_terminate | apr_terminate | 0x2a580 | 186 | 742 |
| httpd_plt_apr_table_addn | apr_table_addn | 0x2a590 | 186 | 742 |
| httpd_plt_apr_proc_mutex_child_init | apr_proc_mutex_child_init | 0x2a5a0 | 186 | 742 |
| httpd_plt___errno_location | __errno_location | 0x2a5b0 | 186 | 742 |
| httpd_plt_unlink | unlink | 0x2a5c0 | 186 | 742 |
| httpd_plt_strncpy | strncpy | 0x2a5d0 | 186 | 742 |
| httpd_plt_apr_file_read_full | apr_file_read_full | 0x2a5e0 | 186 | 742 |
| httpd_plt_apr_bucket_alloc_create | apr_bucket_alloc_create | 0x2a5f0 | 186 | 742 |
| httpd_plt_strncmp | strncmp | 0x2a600 | 186 | 742 |
| httpd_plt_apr_strtoi64 | apr_strtoi64 | 0x2a610 | 186 | 742 |
| httpd_plt_apr_ctime | apr_ctime | 0x2a620 | 186 | 742 |
| httpd_plt_apr_pstrmemdup | apr_pstrmemdup | 0x2a630 | 186 | 742 |
| httpd_plt_apr_time_now | apr_time_now | 0x2a640 | 186 | 742 |
| httpd_plt_apr_file_getc | apr_file_getc | 0x2a650 | 186 | 742 |
| httpd_plt_strcpy | strcpy | 0x2a660 | 186 | 742 |
| httpd_plt_chroot | chroot | 0x2a670 | 186 | 742 |
| httpd_plt_apr_procattr_dir_set | apr_procattr_dir_set | 0x2a680 | 186 | 742 |
| httpd_plt_apu_version_string | apu_version_string | 0x2a690 | 186 | 742 |
| httpd_plt_apr_pool_tag | apr_pool_tag | 0x2a6a0 | 186 | 742 |
| httpd_plt_apr_hash_set | apr_hash_set | 0x2a6b0 | 186 | 742 |
| httpd_plt_apr_array_copy | apr_array_copy | 0x2a6c0 | 186 | 742 |
| httpd_plt_apr_app_initialize | apr_app_initialize | 0x2a6d0 | 186 | 742 |
| httpd_plt_apr_allocator_owner_set | apr_allocator_owner_set | 0x2a6e0 | 186 | 742 |
| httpd_plt_apr_dir_open | apr_dir_open | 0x2a6f0 | 186 | 742 |
| httpd_plt_apr_pool_parent_get | apr_pool_parent_get | 0x2a700 | 186 | 742 |
| httpd_plt_puts | puts | 0x2a710 | 186 | 742 |
| httpd_plt_apr_thread_rwlock_unlock | apr_thread_rwlock_unlock | 0x2a720 | 186 | 742 |
| httpd_plt_apr_version_string | apr_version_string | 0x2a730 | 186 | 742 |
| httpd_plt_qsort | qsort | 0x2a740 | 186 | 742 |
| httpd_plt_apr_table_do | apr_table_do | 0x2a750 | 186 | 742 |
| httpd_plt_sigaction | sigaction | 0x2a760 | 186 | 742 |
| httpd_plt_apr_pvsprintf | apr_pvsprintf | 0x2a770 | 186 | 742 |
| httpd_plt_apr_cpystrn | apr_cpystrn | 0x2a780 | 186 | 742 |
| httpd_plt_apr_base64_encode | apr_base64_encode | 0x2a790 | 186 | 742 |
| httpd_plt_apr_table_set | apr_table_set | 0x2a7a0 | 186 | 742 |
| httpd_plt_apr_bucket_transient_create | apr_bucket_transient_create | 0x2a7b0 | 186 | 742 |
| httpd_plt_apr_pool_create_ex | apr_pool_create_ex | 0x2a7c0 | 186 | 742 |
| httpd_plt_apr_file_pipe_create | apr_file_pipe_create | 0x2a7d0 | 186 | 742 |
| httpd_plt_apr_date_parse_http | apr_date_parse_http | 0x2a7e0 | 186 | 742 |
| httpd_plt_getpid | getpid | 0x2a7f0 | 186 | 742 |
| httpd_plt_apr_table_get | apr_table_get | 0x2a800 | 186 | 742 |
| httpd_plt_apr_hash_copy | apr_hash_copy | 0x2a810 | 186 | 742 |
| httpd_plt_apr_pool_clear | apr_pool_clear | 0x2a820 | 186 | 742 |
| httpd_plt_apr_filepath_root | apr_filepath_root | 0x2a830 | 186 | 742 |
| httpd_plt_apr_brigade_puts | apr_brigade_puts | 0x2a840 | 186 | 742 |
| httpd_plt_apr_base64_decode_len | apr_base64_decode_len | 0x2a850 | 186 | 742 |
| httpd_plt_apr_os_proc_mutex_get | apr_os_proc_mutex_get | 0x2a860 | 186 | 742 |
| httpd_plt_getpwuid | getpwuid | 0x2a870 | 186 | 742 |
| httpd_plt_apr_table_compress | apr_table_compress | 0x2a880 | 186 | 742 |
| httpd_plt_apr_allocator_create | apr_allocator_create | 0x2a890 | 186 | 742 |
| httpd_plt_apr_ipsubnet_create | apr_ipsubnet_create | 0x2a8a0 | 186 | 742 |
| httpd_plt_apr_file_open_stderr | apr_file_open_stderr | 0x2a8b0 | 186 | 742 |
| httpd_plt_apr_file_dup2 | apr_file_dup2 | 0x2a8c0 | 186 | 742 |
| httpd_plt_apr_itoa | apr_itoa | 0x2a8d0 | 186 | 742 |
| httpd_plt_apr_filepath_name_get | apr_filepath_name_get | 0x2a8e0 | 186 | 742 |
| httpd_plt_apr_table_elts | apr_table_elts | 0x2a8f0 | 186 | 742 |
| httpd_plt_apr_proc_create | apr_proc_create | 0x2a900 | 186 | 742 |
| httpd_plt_strlen | strlen | 0x2a910 | 186 | 742 |
| httpd_plt_apr_off_t_toa | apr_off_t_toa | 0x2a920 | 186 | 742 |
| httpd_plt_apr_brigade_partition | apr_brigade_partition | 0x2a930 | 186 | 742 |
| httpd_plt_apr_file_info_get | apr_file_info_get | 0x2a940 | 186 | 742 |
| httpd_plt_apr_password_validate | apr_password_validate | 0x2a950 | 186 | 742 |
| httpd_plt_chdir | chdir | 0x2a960 | 186 | 742 |
| httpd_plt_apr_pool_cleanup_kill | apr_pool_cleanup_kill | 0x2a970 | 186 | 742 |
| httpd_plt___stack_chk_fail | __stack_chk_fail | 0x2a980 | 186 | 742 |
| httpd_plt_apr_bucket_pipe_create | apr_bucket_pipe_create | 0x2a990 | 186 | 742 |
| httpd_plt_apr_bucket_socket_create | apr_bucket_socket_create | 0x2a9a0 | 186 | 742 |
| httpd_plt_apr_dso_sym | apr_dso_sym | 0x2a9b0 | 186 | 742 |
| httpd_plt_apr_procattr_error_check_set | apr_procattr_error_check_set | 0x2a9c0 | 186 | 742 |
| httpd_plt_apr_file_seek | apr_file_seek | 0x2a9d0 | 186 | 742 |
| httpd_plt_strchr | strchr | 0x2a9e0 | 186 | 742 |
| httpd_plt_apr_procattr_limit_set | apr_procattr_limit_set | 0x2a9f0 | 186 | 742 |
| httpd_plt_apr_file_write_full | apr_file_write_full | 0x2aa00 | 186 | 742 |
| httpd_plt_apr_sockaddr_ip_get | apr_sockaddr_ip_get | 0x2aa10 | 186 | 742 |
| httpd_plt_apr_bucket_heap_make | apr_bucket_heap_make | 0x2aa20 | 186 | 742 |
| httpd_plt_apr_time_exp_lt | apr_time_exp_lt | 0x2aa30 | 186 | 742 |
| httpd_plt_apr_optional_hook_get | apr_optional_hook_get | 0x2aa40 | 186 | 742 |
| httpd_plt_apr_hook_sort_all | apr_hook_sort_all | 0x2aa50 | 186 | 742 |
| httpd_plt_apr_vformatter | apr_vformatter | 0x2aa60 | 186 | 742 |
| httpd_plt_apr_hash_overlay | apr_hash_overlay | 0x2aa70 | 186 | 742 |
| httpd_plt_strrchr | strrchr | 0x2aa80 | 186 | 742 |
| httpd_plt_apr_strftime | apr_strftime | 0x2aa90 | 186 | 742 |
| httpd_plt_apr_socket_connect | apr_socket_connect | 0x2aaa0 | 186 | 742 |
| httpd_plt_apr_socket_send | apr_socket_send | 0x2aab0 | 186 | 742 |
| httpd_plt_apr_xml_parser_feed | apr_xml_parser_feed | 0x2aac0 | 186 | 742 |
| httpd_plt_apr_brigade_vprintf | apr_brigade_vprintf | 0x2aad0 | 186 | 742 |
| httpd_plt_apr_ltoa | apr_ltoa | 0x2aae0 | 186 | 742 |
| httpd_plt_apr_pollset_create | apr_pollset_create | 0x2aaf0 | 186 | 742 |
| httpd_plt_apr_table_unset | apr_table_unset | 0x2ab00 | 186 | 742 |
| httpd_plt_apr_brigade_writev | apr_brigade_writev | 0x2ab10 | 186 | 742 |
| httpd_plt_apr_pool_cleanup_register | apr_pool_cleanup_register | 0x2ab20 | 186 | 742 |
| httpd_plt_apr_hash_this | apr_hash_this | 0x2ab30 | 186 | 742 |
| httpd_plt_memset | memset | 0x2ab40 | 186 | 742 |
| httpd_plt_apr_table_overlap | apr_table_overlap | 0x2ab50 | 186 | 742 |
| httpd_plt_geteuid | geteuid | 0x2ab60 | 186 | 742 |
| httpd_plt_apr_hook_deregister_all | apr_hook_deregister_all | 0x2ab70 | 186 | 742 |
| httpd_plt_freopen | freopen | 0x2ab80 | 186 | 742 |
| httpd_plt_apr_bucket_immortal_make | apr_bucket_immortal_make | 0x2ab90 | 186 | 742 |
| httpd_plt_apr_uri_unparse | apr_uri_unparse | 0x2aba0 | 186 | 742 |
| httpd_plt_apr_base64_decode | apr_base64_decode | 0x2abb0 | 186 | 742 |
| httpd_plt_apr_palloc | apr_palloc | 0x2abc0 | 186 | 742 |
| httpd_plt_apr_brigade_destroy | apr_brigade_destroy | 0x2abd0 | 186 | 742 |
| httpd_plt_apr_uid_get | apr_uid_get | 0x2abe0 | 186 | 742 |
| httpd_plt_strspn | strspn | 0x2abf0 | 186 | 742 |
| httpd_plt_apr_filepath_set | apr_filepath_set | 0x2ac00 | 186 | 742 |
| httpd_plt_apr_pollset_remove | apr_pollset_remove | 0x2ac10 | 186 | 742 |
| httpd_plt_apr_shm_create | apr_shm_create | 0x2ac20 | 186 | 742 |
| httpd_plt_apr_file_inherit_unset | apr_file_inherit_unset | 0x2ac30 | 186 | 742 |
| httpd_plt_apr_proc_wait_all_procs | apr_proc_wait_all_procs | 0x2ac40 | 186 | 742 |
| httpd_plt_strcspn | strcspn | 0x2ac50 | 186 | 742 |
| httpd_plt_apr_xml_parser_create | apr_xml_parser_create | 0x2ac60 | 186 | 742 |
| httpd_plt_apr_socket_accept | apr_socket_accept | 0x2ac70 | 186 | 742 |
| httpd_plt_apr_getnameinfo | apr_getnameinfo | 0x2ac80 | 186 | 742 |
| httpd_plt_apr_pstrcatv | apr_pstrcatv | 0x2ac90 | 186 | 742 |
| httpd_plt_apr_proc_mutex_create | apr_proc_mutex_create | 0x2aca0 | 186 | 742 |
| httpd_plt_memcmp | memcmp | 0x2acb0 | 186 | 742 |
| httpd_plt_apr_pool_userdata_get | apr_pool_userdata_get | 0x2acc0 | 186 | 742 |
| httpd_plt_apr_socket_recv | apr_socket_recv | 0x2acd0 | 186 | 742 |
| httpd_plt_apr_hook_debug_show | apr_hook_debug_show | 0x2ace0 | 186 | 742 |
| httpd_plt_apr_vsnprintf | apr_vsnprintf | 0x2acf0 | 186 | 742 |
| httpd_plt_apr_proc_mutex_name | apr_proc_mutex_name | 0x2ad00 | 186 | 742 |
| httpd_plt_apr_tokenize_to_argv | apr_tokenize_to_argv | 0x2ad10 | 186 | 742 |
| httpd_plt_apr_brigade_flatten | apr_brigade_flatten | 0x2ad20 | 186 | 742 |
| httpd_plt_calloc | calloc | 0x2ad30 | 186 | 742 |
| httpd_plt_apr_thread_mutex_lock | apr_thread_mutex_lock | 0x2ad40 | 186 | 742 |
| httpd_plt_apr_brigade_create | apr_brigade_create | 0x2ad50 | 186 | 742 |
| httpd_plt_apr_file_read | apr_file_read | 0x2ad60 | 186 | 742 |
| httpd_plt_strcmp | strcmp | 0x2ad70 | 186 | 742 |
| httpd_plt_apr_array_append | apr_array_append | 0x2ad80 | 186 | 742 |
| httpd_plt_apr_table_mergen | apr_table_mergen | 0x2ad90 | 186 | 742 |
| httpd_plt_apr_procattr_child_err_set | apr_procattr_child_err_set | 0x2ada0 | 186 | 742 |
| httpd_plt_apr_xml_parser_geterror | apr_xml_parser_geterror | 0x2adb0 | 186 | 742 |
| httpd_plt_getpwnam | getpwnam | 0x2adc0 | 186 | 742 |
| httpd_plt_sigemptyset | sigemptyset | 0x2add0 | 186 | 742 |
| httpd_plt_apr_pool_userdata_setn | apr_pool_userdata_setn | 0x2ade0 | 186 | 742 |
| httpd_plt_apr_allocator_max_free_set | apr_allocator_max_free_set | 0x2adf0 | 186 | 742 |
| httpd_plt_apr_os_global_mutex_get | apr_os_global_mutex_get | 0x2ae00 | 186 | 742 |
| httpd_plt_apr_table_setn | apr_table_setn | 0x2ae10 | 186 | 742 |
| httpd_plt_apr_file_close | apr_file_close | 0x2ae20 | 186 | 742 |
| httpd_plt_apr_brigade_split_line | apr_brigade_split_line | 0x2ae30 | 186 | 742 |
| httpd_plt_strtol | strtol | 0x2ae40 | 186 | 742 |
| httpd_plt_apr_dir_read | apr_dir_read | 0x2ae50 | 186 | 742 |
| httpd_plt_memcpy | memcpy | 0x2ae60 | 186 | 742 |
| httpd_plt_apr_procattr_io_set | apr_procattr_io_set | 0x2ae70 | 186 | 742 |
| httpd_plt_apr_signal_description_get | apr_signal_description_get | 0x2ae80 | 186 | 742 |
| httpd_plt_getgrnam | getgrnam | 0x2ae90 | 186 | 742 |
| httpd_plt_apr_procattr_child_in_set | apr_procattr_child_in_set | 0x2aea0 | 186 | 742 |
| httpd_plt_apr_proc_mutex_lock | apr_proc_mutex_lock | 0x2aeb0 | 186 | 742 |
| httpd_plt_prctl | prctl | 0x2aec0 | 186 | 742 |
| httpd_plt_kill | kill | 0x2aed0 | 186 | 742 |
| httpd_plt_apr_pstrdup | apr_pstrdup | 0x2aee0 | 186 | 742 |
| httpd_plt_apr_collapse_spaces | apr_collapse_spaces | 0x2aef0 | 186 | 742 |
| httpd_plt_apr_socket_create | apr_socket_create | 0x2af00 | 186 | 742 |
| httpd_plt_apr_file_flush | apr_file_flush | 0x2af10 | 186 | 742 |
| httpd_plt_apr_bucket_file_create | apr_bucket_file_create | 0x2af20 | 186 | 742 |
| httpd_plt_apr_array_pstrcat | apr_array_pstrcat | 0x2af30 | 186 | 742 |
| httpd_plt_apr_socket_shutdown | apr_socket_shutdown | 0x2af40 | 186 | 742 |
| httpd_plt_apr_hash_make | apr_hash_make | 0x2af50 | 186 | 742 |
| httpd_plt_apr_socket_timeout_set | apr_socket_timeout_set | 0x2af60 | 186 | 742 |
| httpd_plt_apr_bucket_immortal_create | apr_bucket_immortal_create | 0x2af70 | 186 | 742 |
| httpd_plt_apr_snprintf | apr_snprintf | 0x2af80 | 186 | 742 |
| httpd_plt_apr_psprintf | apr_psprintf | 0x2af90 | 186 | 742 |
| httpd_plt_apr_procattr_child_errfn_set | apr_procattr_child_errfn_set | 0x2afa0 | 186 | 742 |
| httpd_plt_apr_file_pipe_timeout_set | apr_file_pipe_timeout_set | 0x2afb0 | 186 | 742 |
| httpd_plt_malloc | malloc | 0x2afc0 | 186 | 742 |
| httpd_plt_strncasecmp | strncasecmp | 0x2afd0 | 186 | 742 |
| httpd_plt_apr_shm_destroy | apr_shm_destroy | 0x2afe0 | 186 | 742 |
| httpd_plt_killpg | killpg | 0x2aff0 | 186 | 742 |
| httpd_plt_apr_bucket_flush_create | apr_bucket_flush_create | 0x2b000 | 186 | 742 |
| httpd_plt_apr_procattr_create | apr_procattr_create | 0x2b010 | 186 | 742 |
| httpd_plt_apr_socket_opt_get | apr_socket_opt_get | 0x2b020 | 186 | 742 |
| httpd_plt_apr_os_thread_current | apr_os_thread_current | 0x2b030 | 186 | 742 |
| httpd_plt___isoc99_sscanf | __isoc99_sscanf | 0x2b040 | 186 | 742 |
| httpd_plt_apr_procattr_addrspace_set | apr_procattr_addrspace_set | 0x2b050 | 186 | 742 |
| httpd_plt_apr_optional_hook_add | apr_optional_hook_add | 0x2b060 | 186 | 742 |
| httpd_plt_apr_dynamic_fn_retrieve | apr_dynamic_fn_retrieve | 0x2b070 | 186 | 742 |
| httpd_plt_apr_file_eof | apr_file_eof | 0x2b080 | 186 | 742 |
| httpd_plt_apr_socket_close | apr_socket_close | 0x2b090 | 186 | 742 |
| httpd_plt_apr_shm_size_get | apr_shm_size_get | 0x2b0a0 | 186 | 742 |
| httpd_plt_apr_file_flags_get | apr_file_flags_get | 0x2b0b0 | 186 | 742 |
| httpd_plt_apr_sleep | apr_sleep | 0x2b0c0 | 186 | 742 |
| httpd_plt_apr_brigade_cleanup | apr_brigade_cleanup | 0x2b0d0 | 186 | 742 |
| httpd_plt_apr_socket_opt_set | apr_socket_opt_set | 0x2b0e0 | 186 | 742 |
| httpd_plt_apr_bucket_alloc | apr_bucket_alloc | 0x2b0f0 | 186 | 742 |
| httpd_plt_chown | chown | 0x2b100 | 186 | 742 |
| httpd_plt_apr_proc_other_child_unregister | apr_proc_other_child_unregister | 0x2b110 | 186 | 742 |
| httpd_plt_apr_table_copy | apr_table_copy | 0x2b120 | 186 | 742 |
| httpd_plt_apr_table_overlay | apr_table_overlay | 0x2b130 | 186 | 742 |
| httpd_plt_apr_parse_addr_port | apr_parse_addr_port | 0x2b140 | 186 | 742 |
| httpd_plt_apr_table_clear | apr_table_clear | 0x2b150 | 186 | 742 |
| httpd_plt_apr_brigade_write | apr_brigade_write | 0x2b160 | 186 | 742 |
| httpd_plt_apr_sockaddr_info_get | apr_sockaddr_info_get | 0x2b170 | 186 | 742 |
| httpd_plt_apr_uri_parse | apr_uri_parse | 0x2b180 | 186 | 742 |
| httpd_plt_apr_array_push | apr_array_push | 0x2b190 | 186 | 742 |
| httpd_plt_apr_pool_destroy | apr_pool_destroy | 0x2b1a0 | 186 | 742 |
| httpd_plt___printf_chk | __printf_chk | 0x2b1b0 | 186 | 742 |
| httpd_plt_apr_uid_homepath_get | apr_uid_homepath_get | 0x2b1c0 | 186 | 742 |
| httpd_plt_apr_stat | apr_stat | 0x2b1d0 | 186 | 742 |
| httpd_plt_apr_shm_remove | apr_shm_remove | 0x2b1e0 | 186 | 742 |
| httpd_plt_apr_fnmatch | apr_fnmatch | 0x2b1f0 | 186 | 742 |
| httpd_plt_apr_strnatcmp | apr_strnatcmp | 0x2b200 | 186 | 742 |
| httpd_plt_apr_procattr_child_out_set | apr_procattr_child_out_set | 0x2b210 | 186 | 742 |
| httpd_plt_apr_hash_pool_get | apr_hash_pool_get | 0x2b220 | 186 | 742 |
| httpd_plt_memmove | memmove | 0x2b230 | 186 | 742 |
| httpd_plt_apr_shm_detach | apr_shm_detach | 0x2b240 | 186 | 742 |
| httpd_plt___syslog_chk | __syslog_chk | 0x2b250 | 186 | 742 |
| httpd_plt_apr_file_open | apr_file_open | 0x2b260 | 186 | 742 |
| httpd_plt_apr_dir_close | apr_dir_close | 0x2b270 | 186 | 742 |
| httpd_plt_setgid | setgid | 0x2b280 | 186 | 742 |
| httpd_plt_apr_file_puts | apr_file_puts | 0x2b290 | 186 | 742 |
| httpd_plt_apr_bucket_shared_make | apr_bucket_shared_make | 0x2b2a0 | 186 | 742 |
| httpd_plt_apr_bucket_mmap_create | apr_bucket_mmap_create | 0x2b2b0 | 186 | 742 |
| httpd_plt_apr_socket_listen | apr_socket_listen | 0x2b2c0 | 186 | 742 |
| httpd_plt_apr_pollset_poll | apr_pollset_poll | 0x2b2d0 | 186 | 742 |
| httpd_plt_getpgrp | getpgrp | 0x2b2e0 | 186 | 742 |
| httpd_plt_apr_proc_kill | apr_proc_kill | 0x2b2f0 | 186 | 742 |
| httpd_plt_apr_uid_name_get | apr_uid_name_get | 0x2b300 | 186 | 742 |
| httpd_plt_apr_table_make | apr_table_make | 0x2b310 | 186 | 742 |
| httpd_plt_apr_proc_detach | apr_proc_detach | 0x2b320 | 186 | 742 |
| httpd_plt_times | times | 0x2b330 | 186 | 742 |
| httpd_plt_apr_proc_other_child_register | apr_proc_other_child_register | 0x2b340 | 186 | 742 |
| httpd_plt_apr_brigade_vputstrs | apr_brigade_vputstrs | 0x2b350 | 186 | 742 |
| httpd_plt_apr_pool_note_subprocess | apr_pool_note_subprocess | 0x2b360 | 186 | 742 |
| httpd_plt_apr_hook_sort_register | apr_hook_sort_register | 0x2b370 | 186 | 742 |
| httpd_plt_apr_uri_parse_hostinfo | apr_uri_parse_hostinfo | 0x2b380 | 186 | 742 |
| httpd_plt_apr_proc_mutex_lockfile | apr_proc_mutex_lockfile | 0x2b390 | 186 | 742 |
| httpd_plt_sysconf | sysconf | 0x2b3a0 | 186 | 742 |
| httpd_plt_apr_brigade_split | apr_brigade_split | 0x2b3b0 | 186 | 742 |
| httpd_plt_apr_pollset_add | apr_pollset_add | 0x2b3c0 | 186 | 742 |
| httpd_plt_apr_base64_encode_len | apr_base64_encode_len | 0x2b3d0 | 186 | 742 |
| httpd_plt_apr_pool_userdata_set | apr_pool_userdata_set | 0x2b3e0 | 186 | 742 |
| httpd_plt_apr_thread_rwlock_wrlock | apr_thread_rwlock_wrlock | 0x2b3f0 | 186 | 742 |
| httpd_plt_apr_rfc822_date | apr_rfc822_date | 0x2b400 | 186 | 742 |
| httpd_plt_apr_pstrcat | apr_pstrcat | 0x2b410 | 186 | 742 |
| httpd_plt_apr_bucket_eos_create | apr_bucket_eos_create | 0x2b420 | 186 | 742 |
| httpd_plt_apr_sockaddr_equal | apr_sockaddr_equal | 0x2b430 | 186 | 742 |
| httpd_plt_apr_md5_final | apr_md5_final | 0x2b440 | 186 | 742 |
| httpd_plt_apr_dynamic_fn_register | apr_dynamic_fn_register | 0x2b450 | 186 | 742 |
| httpd_plt_apr_hash_merge | apr_hash_merge | 0x2b460 | 186 | 742 |
| httpd_plt_semctl | semctl | 0x2b470 | 186 | 742 |
| httpd_plt_apr_proc_other_child_alert | apr_proc_other_child_alert | 0x2b480 | 186 | 742 |
| httpd_plt_apr_proc_other_child_refresh_all | apr_proc_other_child_refresh_all | 0x2b490 | 186 | 742 |
| httpd_plt_apr_proc_mutex_defname | apr_proc_mutex_defname | 0x2b4a0 | 186 | 742 |
| httpd_plt_apr_socket_sendfile | apr_socket_sendfile | 0x2b4b0 | 186 | 742 |
| httpd_plt_getpgid | getpgid | 0x2b4c0 | 186 | 742 |
| httpd_plt_apr_socket_timeout_get | apr_socket_timeout_get | 0x2b4d0 | 186 | 742 |
| httpd_plt_openlog | openlog | 0x2b4e0 | 186 | 742 |
| httpd_plt_apr_hash_next | apr_hash_next | 0x2b4f0 | 186 | 742 |
| httpd_plt_apr_pstrndup | apr_pstrndup | 0x2b500 | 186 | 742 |
| httpd_plt_apr_file_gets | apr_file_gets | 0x2b510 | 186 | 742 |
| httpd_plt_apr_strfsize | apr_strfsize | 0x2b520 | 186 | 742 |
| httpd_plt_exit | exit | 0x2b530 | 186 | 742 |
| httpd_plt_apr_strmatch_precompile | apr_strmatch_precompile | 0x2b540 | 186 | 742 |
| httpd_plt_apr_signal | apr_signal | 0x2b550 | 186 | 742 |
| httpd_plt_apr_pool_cleanup_run | apr_pool_cleanup_run | 0x2b560 | 186 | 742 |
| httpd_plt_apr_brigade_length | apr_brigade_length | 0x2b570 | 186 | 742 |
| httpd_plt_apr_socket_sendv | apr_socket_sendv | 0x2b580 | 186 | 742 |
| httpd_plt___fprintf_chk | __fprintf_chk | 0x2b590 | 186 | 742 |
| httpd_plt_apr_thread_rwlock_rdlock | apr_thread_rwlock_rdlock | 0x2b5a0 | 186 | 742 |
| httpd_plt_getrlimit | getrlimit | 0x2b5b0 | 186 | 742 |
| httpd_plt_apr_strnatcasecmp | apr_strnatcasecmp | 0x2b5c0 | 186 | 742 |
| httpd_plt_apr_is_empty_array | apr_is_empty_array | 0x2b5d0 | 186 | 742 |
| httpd_plt___strncat_chk | __strncat_chk | 0x2b5e0 | 186 | 742 |
| httpd_plt_apr_ipsubnet_test | apr_ipsubnet_test | 0x2b5f0 | 186 | 742 |
| httpd_plt_apr_bucket_file_enable_mmap | apr_bucket_file_enable_mmap | 0x2b600 | 186 | 742 |
| httpd_plt_setuid | setuid | 0x2b610 | 186 | 742 |
| httpd_plt_apr_is_empty_table | apr_is_empty_table | 0x2b620 | 186 | 742 |
| httpd_plt_apr_file_write | apr_file_write | 0x2b630 | 186 | 742 |
| httpd_plt_apr_thread_mutex_create | apr_thread_mutex_create | 0x2b640 | 186 | 742 |
| httpd_plt_strerror | strerror | 0x2b650 | 186 | 742 |
| httpd_plt_apr_fnmatch_test | apr_fnmatch_test | 0x2b660 | 186 | 742 |
| httpd_plt_apr_shm_baseaddr_get | apr_shm_baseaddr_get | 0x2b670 | 186 | 742 |
| httpd_plt_apr_strerror | apr_strerror | 0x2b680 | 186 | 742 |
| httpd_plt_apr_bucket_shared_destroy | apr_bucket_shared_destroy | 0x2b690 | 186 | 742 |
| httpd_plt_apr_socket_bind | apr_socket_bind | 0x2b6a0 | 186 | 742 |
| httpd_plt_apr_strtok | apr_strtok | 0x2b6b0 | 186 | 742 |
| httpd_plt_apr_file_printf | apr_file_printf | 0x2b6c0 | 186 | 742 |
| httpd_plt_initgroups | initgroups | 0x2b6d0 | 186 | 742 |
| httpd_plt_apr_getopt | apr_getopt | 0x2b6e0 | 186 | 742 |
| httpd_plt_apr_filepath_merge | apr_filepath_merge | 0x2b6f0 | 186 | 742 |
| httpd_plt_apr_strtoff | apr_strtoff | 0x2b700 | 186 | 742 |
| httpd_plt_sleep | sleep | 0x2b710 | 186 | 742 |
| httpd_plt_sigaddset | sigaddset | 0x2b720 | 186 | 742 |
| httpd_plt_fork | fork | 0x2b730 | 186 | 742 |
| httpd_plt_strstr | strstr | 0x2b740 | 186 | 742 |
| httpd_plt_apr_file_ungetc | apr_file_ungetc | 0x2b750 | 186 | 742 |
| httpd_plt_apr_socket_addr_get | apr_socket_addr_get | 0x2b760 | 186 | 742 |
| httpd_plt___ctype_tolower_loc | __ctype_tolower_loc | 0x2b770 | 186 | 742 |
| httpd_plt_apr_hash_get | apr_hash_get | 0x2b780 | 186 | 742 |
| httpd_plt___ctype_b_loc | __ctype_b_loc | 0x2b790 | 186 | 742 |
| httpd_plt_apr_thread_mutex_unlock | apr_thread_mutex_unlock | 0x2b7a0 | 186 | 742 |
| httpd_plt_apr_procattr_detach_set | apr_procattr_detach_set | 0x2b7b0 | 186 | 742 |
| httpd_plt_apr_proc_wait | apr_proc_wait | 0x2b7c0 | 186 | 742 |
| httpd_plt_apr_gethostname | apr_gethostname | 0x2b7d0 | 186 | 742 |
| httpd_plt_apr_dso_load | apr_dso_load | 0x2b7e0 | 186 | 742 |

## Adding a function

1. capture both sides with the recipes above (double-run determinism check
   on the rugra side);
2. `bash tools/run_stage_bisect.sh <oracle> <rugra>` must print
   `kind: MATCH`;
3. create `manifest.toml` (copy a sibling; update function/entry/selector,
   sha256 pins, stages/ops, date, pin_mode);
4. add the row here and to the table above;
5. run `tools/verify_projection_bank.sh` — must print OK for the new entry.
