# frontend.rs — Native ELF front-end API

**Status:** 🟢 **FRONTEND-MINIMAL-0001 基础阶段（2026-09-26 交付）**. Pure
additive front-end module — no locked-tree counterpart exists (Ghidra's ELF
import/analysis runs in the Java layer, outside the decompile-cpp oracle
tree), so every function carries a `// RUDRA-GLUE:` annotation with its
System V ABI spec basis. 13 unit tests, all green; data-level differential
vs the canon manual seed data recorded below.

Ghidra role correspondence (Java analyzer layer, **not** in the locked
decompile-cpp tree — the oracle's Program arrives pre-populated):

| Rugra (`src/frontend.rs`) | Ghidra Java layer | ELF spec basis |
|---|---|---|
| `import_symbols` | `ElfProgramBuilder.addSymbols` | System V ABI 4.1 ch.4 "Symbol Table" |
| `discover_functions` | `ElfProgramBuilder.addFunctionsFromSymbolTable` + entry-point analyzer | System V ABI 4.1 ch.4 (`e_entry`, `SHF_EXECINSTR`) |
| `derive_memory_map` | `ElfProgramBuilder` memory blocks (BfdArchitecture maps every `PT_LOAD`) | System V ABI 4.1 ch.4 "Program Header" |
| `demangle` | `DemanglerAnalyzer` (`DemanglerCmd`) | Itanium C++ ABI §5 (mangled names) |

## Enums

### `SymbolType`
`st_info` low nibble (System V ABI "Symbol Table"): `NoType`(0),
`Object`(1), `Function`(2), `Section`(3), `File`(4), `Common`(5), `Tls`(6),
`GnuIfunc`(10), `Other(u8)`. Decoder: `from_info(info: u8) -> SymbolType`.

### `SymbolBinding`
`st_info` high nibble: `Local`(0), `Global`(1), `Weak`(2), `GnuUnique`(10),
`Other(u8)`. Decoder: `from_info(info: u8) -> SymbolBinding`.

### `SymbolTable`
`Symtab` (`.symtab`, absent in stripped binaries) / `Dynsym` (`.dynsym`).

### `FunctionSeedKind`
`EntryPoint` (`e_entry`, no covering symbol) / `SymtabFunction` /
`DynsymFunction`.

## Structs

### `ElfSymbol`
The six-field symbol data shape: `name: String` (demangled when mangled),
`mangled_name: Option<String>` (raw spelling, present only when it differed),
`address: u64` (`st_value`), `size: u64` (`st_size`), `sym_type: SymbolType`,
`binding: SymbolBinding`, `defined: bool` (`st_shndx != SHN_UNDEF` — export
vs import), `table: SymbolTable`.

### `SymbolImport`
The imported universe: `.symtab` entries then `.dynsym` entries, each in
table order, skipping the reserved null index 0 and empty-name entries.
- `len() -> usize`, `is_empty() -> bool`, `symbols() -> &[ElfSymbol]`
- `exports() -> impl Iterator<Item = &ElfSymbol>` — defined symbols
- `imports() -> impl Iterator<Item = &ElfSymbol>` — undefined symbols
  (a fully-linked PIE keeps its UND set in both tables: curl = 96 = 48
  `.symtab` UND + 48 `.dynsym` UND; the EXTERNAL-block set is the dynsym
  subset)
- `function_symbols() -> impl Iterator<Item = &ElfSymbol>` — defined
  `STT_FUNC` (the non-stripped function universe)
- `lookup_address(address: u64) -> Option<&ElfSymbol>` — first hit,
  `.symtab` wins over `.dynsym`

### `FunctionSeed`
The canon driver's function-table shape: `vaddr: u64`, `size: u64`,
`name: String`, `kind: FunctionSeedKind`. `size` keeps `st_size` when
non-zero; size-0 symbols (crt stubs, `_init`/`_fini`) take a working bound —
the next seed's address capped by the owning executable section's end
(`_init`/`_fini` alone in their sections get the exact section extent, 27/13
on curl — identical to the locked ledger's values). The bound is a working
extent, not the oracle's flow-derived body.

### `MemorySegment`
One `PT_LOAD` segment: `vaddr`, `memsz`, `filesz`, `file_offset`,
`readable`/`writable`/`executable` (`PF_R`/`PF_W`/`PF_X`).
- `read_only() -> bool` — `PF_R && !PF_W` (the driver's read-only
  property-range filter)
- `range_bounds() -> Option<(u64, u64)>` — `(p_vaddr, p_vaddr + p_memsz - 1)`,
  the exact form the drivers' `add_range` loops build

### `FrontendSeed`
Aggregate: `entry_point: u64` (raw `e_entry`), `functions: Vec<FunctionSeed>`
(sorted by vaddr), `segments: Vec<MemorySegment>` (program-header order),
`symbols: SymbolImport`.

## Functions

- `demangle(name: &str) -> Option<String>` — Itanium C++ ABI demangling,
  gated on the `_Z` prefix; `None` for non-mangled or unparseable names.
- `import_symbols(bytes: &[u8]) -> Result<SymbolImport>` — walks `.symtab`
  then `.dynsym`; names demangled on the way in; GNU version tags
  (`@GLIBC_...`) live in `.gnu.version` and stay with the driver-side
  EXTERNAL-block channel.
- `discover_functions(bytes: &[u8]) -> Result<Vec<FunctionSeed>>` — defined
  `STT_FUNC` from both tables inside `SHF_EXECINSTR` sections (`.symtab`
  wins on address collision), plus `e_entry` when uncovered (merged with a
  covering symbol otherwise; bare entry named `"entry"`); sorted by vaddr.
- `derive_memory_map(bytes: &[u8]) -> Result<Vec<MemorySegment>>` — every
  `PT_LOAD` with `p_memsz > 0`, program-header order.
- `build_seed(bytes: &[u8]) -> Result<FrontendSeed>` — all channels in one
  call; the future driver-side replacement for the manual seeding loops.

## Data-level differential（验收记录，2026-09-26）

自动派生种子数据 vs 手工播种数据（锁定 oracle provenance ledger + 驱动手工
循环形态），逐项归因分级。测试载体：`src/frontend.rs` tests
（`curl_ledger_differential_classified` / `httpd_driver_manual_form_equivalence`
/ `httpd_ledger_differential_classified` / `sqlite3_ledger_differential_classified`
/ `pt_load_memory_map_matches_driver_add_range_form`）。

### curl（非 stripped，124-entry 锁定 ledger）

| 项 | 数值 | 归因 |
|---|---|---|
| 模块发现 | 31 seeds，全部在 ledger 内（0 extra） | ✅ 可自动 |
| ledger 残差 | 93 = 45 PLT stubs（0x2020..0x25a0）+ 48 EXTERNAL slots（0x19000+） | 驱动 PLT/EXTERNAL 通道（本模块范围外，保留 override） |
| 名字对照 | 27/31 全等 | ✅ 可自动 |
| 名字差异 | 4：GCC clone 后缀（`file2string.part.0`→`file2string` 等） | DWARF 通道（debugproto，DWARF-NAME-PRECEDENCE-0001） |
| 尺寸对照 | 11/31 全等（含 `_init`/`_fini`/`_start` 工作边界精确命中 27/13/47） | ✅ 可自动 |
| 尺寸差异 | 20：17 个 st_size≠oracle 流导尺寸 + 4 个 size-0 工作边界 vs 流导（deregister 48 vs 34 等） | oracle 流导 body 尺寸是反编译期产物——需保留 override（ledger 尺寸） |

### httpd（stripped，2010-entry ledger）

| 项 | 数值 | 归因 |
|---|---|---|
| 模块发现 | 473 dynsym FUNC seeds，全部在 ledger 内（0 extra） | ✅ 可自动 |
| 驱动手工形态等价 | 473/473 地址+名字+尺寸全等（`httpd_driver_manual_form_equivalence`：file_off>0 规则与本模块 in-exec 规则在该语料重合；512 size-0 fallback 未触发） | ✅ 可自动 |
| 名字对照 | 473/473 全等 | ✅ 可自动 |
| ledger 残差 | 1537 | stripped 函数发现（analyzer 级）——STRIPPED-DISCOVERY 工作包，Phase 3 决策点 |

### sqlite3（stripped .so，1385-entry ledger）

| 项 | 数值 | 归因 |
|---|---|---|
| 模块发现 | 1339 dynsym FUNC seeds，全部在 ledger 内（0 extra） | ✅ 可自动（provenance `defined_dynsym_func: 1339` 恒等） |
| 名字对照 | 1339/1339 全等 | ✅ 可自动 |
| ledger 残差 | 46 = `.plt.sec` jump-slot stubs（0x1e320..0x1e600） | 驱动 PLT 通道（provenance `jump_slot_stubs: 46` 恒等） |

### 内存映射（双语料）

`derive_memory_map` ≡ 驱动手工 add_range 循环（同一程序头走查）：
curl 4 段（3 RO + 1 RW，exec 段 0x2000 R+E）、httpd 4 段（exec 段 0x29000
R+E）、sqlite3 4 段；`range_bounds()` 逐段等于驱动 `add_range` 的
(first, last) 形态。✅ 可自动。

## 范围边界（诚实声明）

- **PLT/EXTERNAL/调用图发现不在本模块**：curl 的 45 PLT stubs + 48
  EXTERNAL slots、sqlite3 的 46 jump slots 由驱动的 PLT/EXTERNAL 投影通道
  产出（FULL-CORPUS-0001 discovery layer 已有实现）；预播种通道保留为
  override（roadmap Phase 2 措辞）。
- **stripped 函数发现不在本模块**：httpd 的 1537 残差是 analyzer 级函数
  发现（STRIPPED-DISCOVERY 工作包，Phase 3 实测后决策）。
- **oracle 流导 body 尺寸不可从 ELF 派生**：ledger 尺寸与 st_size/工作边界
  的 20+297 处差异是反编译期流分析产物；驱动侧保留 ledger 尺寸 override。
- **GNU version tag**（`@GLIBC_...`）不进本模块数据形态——它属于驱动
  EXTERNAL-block 渲染通道。
- **demangle 接线已就绪但 canon 语料为纯 C**：无 mangled 名可喂；单测用
  Itanium 样例锁定行为（`_ZN5space3fooEibc` → `space::foo(int, bool, char)`）。
