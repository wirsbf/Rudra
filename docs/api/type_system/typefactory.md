# `type_system/typefactory.rs` API Reference

## 2026-09-27：get_typedef per-type 通道（Lane TYPEDEFIMM，wt/typedefimm）

`get_typedef`（type.cc:3818-3840）补齐 oracle 的 per-Datatype 通道语义：

- 克隆 base 记录后显式置 `base.typedef_imm = Some(ct)`（type.cc:3834
  `res->typedefImm = ct;`——无条件覆写，typedef-of-typedef 的克隆携带链被
  换成立即基）。通道随 `find_add` 插入的 Arc 进入工厂树。
- 同名去重检查从 `typedefs` 名字侧表改为现有类型的 per-type 通道
  （type.cc:3825 `if (ct != res->getTypedef()) throw`）——指针同一性。
- `typedefs` 名字索引与 `get_typedef_target(name)` 保留为 debug/test 可达性
  helper（Ghidra 无名字键访问器——type.cc:3850 是 `getTypePointerStripArray`；
  生产消费点一律走 `Datatype::get_typedef` 通道），注解从失实的
  `Ghidra: type.cc:3850` 更正为 RUDRA-GLUE。
- 消费点接线（cast.cc:325-328 / printc.cc:390-393 / typeop.cc:2337-2340
  剥离环）见 `docs/api/type_system/cast.md`、`docs/api/printc.md`、
  `docs/api/coreaction.md` 同日条目。

## 2026-09-26：DataOrg flavor 补 `code` 核心注册（Lane TYPINGPX，TYPINGPX-PXNAME-0001）

`init_data_org_core_types` 在 `undefined1..8` 之后显式注册
`set_core_type_result("code", 1, Code, false)` 再 `cache_core_types()` ——
ghidra_arch.cc:349 `types->setCoreType("code",1,TYPE_CODE,false);` 的逐字对应
（下方 2026-09-24 条目列出的 Java 投影表本就含 `code`，但代码侧漏注册——
文档-代码漂移就此闭合）。语义链：cacheCoreTypes（type.cc:3239-3244）填
`typecache[1][TYPE_CODE]`，使 `get_base(1, Code)` 与 `get_type_code()`
（type.cc:3680 同一 cache 槽探针）统一返回**命名** `code` 核心对象；此前
data-org flavor 下 `get_base(1, Code)` 返回**未命名** base——`printNameBase`
（type.hh:273）贡献空字符，mapGlobals 命名落 `pRam`（oracle `pcRam`；
双侧 fixture `tests/oracle/typingpx_pxname_1204.*` case d 钉死）。新单测
`test_data_org_code_core_named_and_unified` 固定：`get_base(1,Code)` 名为
`code`、与 `get_type_code()`/`find_by_name("code")` Arc 同一。canon 双语料
字节恒等亲证（E2E 门禁，Lane TYPINGPX 终报）。
## 2026-09-26：decode 告警尾接线（WORKPKG-UNMAP-TYPEUNION-0003，wt/typeunion）

- `decode_struct` 的 overlap 告警从丢弃改为逐字构建并接入
  `insert_warning`（type.cc:1849-1860 告警文本两形态 +
  4357-4358 `if (!warning.empty()) insertWarning(ct, warning)`）：
  首个 overlap 命名字段，后续 collapse 为 multiple-overlapping 形态；
  匿名（id-0）类型使 `insert_warning` 抛逐字
  `Can only issue warnings for named data-types`（type.cc:3753-3754）；
  返回 Arc 为 flag 写入后的注册体（define_replace 重包语义）。
- `decode_enum` 的重复名告警同样接通（type.cc:4326-4327）。
  union decode 路径无告警通道（type.cc:4382 丢弃返回值）——镜像保持。
- B2 证明：`tests/oracle/typefactory_recalcptr_1204`（42 records，40 逐字节
  MATCH；2 条 identity 记录为已登记 `TYPEFACTORY-ARC-IDENTITY-0001`
  MISMATCH——runner 棘轮精确钉住该已登记 delta）；新增单测
  `test_decode_struct_overlap_warning_rides_insert_warning`（命名告警
  注册+逐字文本、匿名逐字抛错、无 overlap 不注册）。
## 2026-09-24：DataOrg core-type 表改为 Java headless `<coretypes>` 精确投影（Lane GH）

`init_data_org_core_types` 的整数命名不再用 `int{N}`/`uint{N}` 约定式拼写，改为
正典 golden 背后的 Java 客户端 `PcodeDataTypeManager.generateCoreTypes`
（PcodeDataTypeManager.java:1154-1228）在 x86-64 gcc data organization
（short=2/int=4/long=8/longlong=8）下的精确注册表：

- signed: `sbyte(1) short(2) int3(3) int(4) int5(5) int6(6) int7(7) long(8) int16(16)`
  （AbstractIntegerDataType.java:544-566 的 longSize 覆写使 `longlong` 槽位被
  `long` 取代，表中无 `longlong`）
- unsigned: `byte(1) ushort(2) uint3(3) uint(4) uint5(5) uint6(6) uint7(7) ulong(8) uint16(16)`
- `undefined1..8`（Undefined.java:31-38，无 10/16）、`float(4) double(8) longdouble(16)`、
  `code`、`char(1,int,ASCII)`、`wchar_t(4,int,UTF)`、`bool`、`void`

语义影响链：类型名直接进 printC 拼写（`int8`→`long`、`uint8`→`ulong`、
`int2`→`short`、`uint1`→`byte`），并经 `Datatype::printNameBase`（type.hh:273，
取 name 首字符）改变默认变量名前缀（`iVar`↔`lVar/sVar`、`uVar`↔`bVar`）。
canon golden（headless Java 桥）全量使用该表拼写；direct-runner golden（纯 C++
库，SLEIGH standalone 表 `int8/uint8`）不受影响——两 golden 契约差异已在
GOLDEN-CONTRACT-PUSHABSORB-0001/FI 判例框架内登记。E2E：curl 1910→1847、
httpd 1960→1782（defects/numbering 双零保持，逐函数零回退）；五投影
（next_url/match_url/parseconfig/getparameter/myprogress，RUDRA_MIRROR=1 正典
bundle）MATCH 保持——投影快照不含核心类型名。新单测
`test_data_org_core_inventory_matches_java_coretypes` 固定表与 cache 槽位
（`get_base(8,Int)==long`、`get_base(2,Int)==short`、`get_base(1,Uint)==byte`、
`get_base(8,Float)==double`）。

## 2026-09-22：`intern_imported` — DWARF 导入边界的工厂注册（HERITAGE-PROMOTE-SYMBOLTAIL-0001 配套）

新 `pub(crate) fn intern_imported(candidate)`：`find_add(candidate, true)` 的公共包装，
对应 type.cc:3390 `TypeFactory::findAdd` 的 DWARF/type-manager 导入通道（Ghidra
的 DWARF analyzer 把每个导入类型注册进 Architecture 的唯一工厂，跨引用恒等由此
成立）。调用方为 `debugproto.rs` 的 `intern_named` 软驻留（见 docs/api/debugproto.md
同日条目）；对齐计算走生产 find_add 路径，导入类型携带 DWARF byte size。


## 2026-08-28：三种 core-type bootstrap

`CoreTypeFlavor` 现区分 compiler-supplied DataOrg、
`ArchitectureGhidra::buildCoreTypes` fallback 与
`SleighArchitecture::buildCoreTypes` fallback。两种 fallback 按锁定源码固定顺序注册
完整表后统一 `cacheCoreTypes`；ASCII `char` 成为 `(1,TYPE_INT)` 首选对象，普通
`int1/sbyte` 保留在 no-char cache。GetStr 聚焦 identity 已复核，完整 factory ordered
tree、Arc identity 和 decoded `<coretypes>` 状态仍为 L2 residual。

## 文档状态

- **状态**: L2。当前单名称 map 与 immutable `Arc<Datatype>` 不等价于
  Ghidra 结构主树 + `(name,id)` 树和原位对象突变；exact-piece series D
  已落 production walk；锁定 bilateral fixture 已运行 32 条记录，30 条逐字节
  一致，剩余 explicit-align struct/union 共 46 个 allowlist 字段，整体为
  `MISMATCH`。
  layout/rekey 的 scoped A 片只保证 factory 当前 tree/name 槽
  一致，旧句柄及 factory-owned dependencies 仍绑定
  `TYPEFACTORY-ARC-IDENTITY-0001`。series B 只闭合 array/partial/virtual
  stripped 的 registry 投影；series C 增加 Pointer/PointerRel canonical
  key、ephemeral parent geometry 与 grammar 默认指针闭包。A-C 的 B2
  投影不能外推为完整函数 MATCH；`calcTruncate` attachment、完整
  Architecture/AddrSpace wiring 与 immutable Arc identity 仍是 residual，
  模块整体为 **MISMATCH / L2**，不能升 L3。


**源代码路径**: `src/type_system/typefactory.rs`

## 模块说明 (Module Doc)

Type management and deduplication

Corresponds to Ghidra's `TypeFactory` class in `type.hh`. This class is responsible
for the lifecycle of all `Datatype` objects, ensuring that identical types are
deduplicated and providing a central point for type lookup.

## 导出的公共 API (Public API)

### `pub struct TypeFactory`

Managed container for all Datatype objects

### `pub fn new(ptr_size: usize) -> Self`

Create a new TypeFactory and initialize core types

# Arguments
* `ptr_size` - Default pointer size for the target architecture (e.g., 4 or 8)

**2026-09-25（GENSMOKE-T1，wt/vshfix）**: `new` 现按进程档位选择核心类型表
（flavor）。oracle 有两个 harness 档：`SleighArchitecture::buildCoreTypes`
（sleigh_arch.cc:204-238）在架构描述无 `<coretypes>` 元素时装**控制台/独立**
表（`xunknownN`/`int4`/`uint1`/`code`）= direct-runner 契约；
`ArchitectureGhidra` 接收 Java 客户端 `<coretypes>` 流
（PcodeDataTypeManager.encodeCoreTypes）拼 `undefinedN`/`int`/`long` =
canon headless 门。Rudra 驱动以环境变量选契约（curl/httpd =
`RUDRA_MIRROR`/`RUDRA_FLOW_MIRROR`，泛化驱动 = `RUDRA_GEN_MIRROR`，
MIRROR-ENVS-CANONICAL-0001），故 `new` 在这些进程中构造 Standalone 表，
默认进程保持 DataOrg（canon 脸不变）。探测函数为
[`direct_runner_tier_active`](#pub-fn-direct_runner_tier_active---bool)。
显式 `new_flavor` 调用方（oracle fixtures）不受影响。

### `pub fn direct_runner_tier_active() -> bool`

进程级档位探针（RUDRA-GLUE，Ghidra 以架构子类选择 buildCoreTypes 而非
环境）：`RUDRA_MIRROR`/`RUDRA_FLOW_MIRROR`/`RUDRA_GEN_MIRROR` 任一在进程
环境中即本进程运行 direct-runner（独立 SLEIGH）oracle 契约。当前消费方 =
`TypeFactory::new` 的表档位选择。（printc.rs 的 typedef 前言**不**消费此
探针——curl 驱动的 worker 协议要求每个 worker 文档以 TYPEDEF_PREAMBLE
开头（examples/curl_decompile.rs:5974-5990），档位化会在那里破裂；
typedef 行被 compare_ghidra.py:109/141 从所有差分面归一化掉。）

### `pub fn get_type_array(num_elements: usize, array_of: Arc<Datatype>) -> Arc<Datatype>`

`TypeFactory::getTypeArray(as,ao)`（type.cc:3902-3909）的移植：先对元素做
一次虚 `getStripped`（:3905-3906），再按 `TypeArray(int4 n, Datatype *ao)`
内联构造子（type.hh:937-946）铸**匿名**壳——3 参 `Datatype(size,
alignment, TYPE_ARRAY)` 基构造（type.hh:215）给出空名/空显示名、
`size = n × ao->getAlignSize()`、`alignSize = size`、`alignment =
ao->getAlignment()`、`submeta = base2sub[TYPE_ARRAY]`、零 flag——随后
`findAdd`（type.cc:3412）findNoName 结构树去重；`n == 1` 时置
`needs_resolution`（type.hh:944-945）。匿名名对打印承重：buildTypeStack
（printc.cc:148-151）钻过无名 ARRAY 层，声明拼 `T name [N]`
（array_expr postsurround，printc.cc:76）。首个消费方 =
`varmap.rs` `create_entry`（varmap.cc:625，TYPE-WIRING-0001 收口，
GENSMOKE-T5）。

### `pub fn find_by_name(&self, name: &str) -> Option<Arc<Datatype>>`

Find a type by name

### `pub fn dwarf_conventional_bool(&self, name: &str) -> Option<Arc<Datatype>>`

Resolve a DWARF typedef whose NAME is a conventional boolean spelling
(`bool`/`_Bool`) to this factory's registered core boolean type
(`setCoreType("bool",1,TYPE_BOOL,false)` shape — sleigh_arch.cc:204,
type.cc:3178-3195). Returns `None` for any other name, or when the
factory's `bool` entry is not the exact core shape (metatype BOOL, size 1),
in which case callers fall back to their alias materialization.

**2026-09-24（PRINTC-BOOLLITERAL-0001）**: the DWARF import boundary
(`debugproto.rs` resolve_type 的 typedef 分支,1-byte underlying 门控) consults
this helper so a `typedef bool -> char` (curl.h line 394) lands as the core
TYPE_BOOL instead of a renamed char clone — the type identity that drives
`ActionSetCasts::castInput`'s constant absorption (coreaction.cc:2687-2691)
and `PrintC::pushConstant`'s TYPE_BOOL arm (printc.cc:1769-1771), printing
`true`/`false` for the canonical golden's typedef-bool fields
(`::config.showerror = true;`).

### `pub fn get_base(&self, size: usize, metatype: TypeMetatype) -> Option<Arc<Datatype>>`

Compat projection of `getBase` (type.cc:3631-3660): preferred core cache
first, then the canonical unnamed atomic type from the structural tree.
Core names are never inferred. The byte-faithful port — including the
`size > max_basetype_size` array conversion (type.cc:3652-3657) and the
"TypeFactory alignment map not initialized" LowlevelError of the raw
constructor state — is `get_base_result`.

**2026-09-23（VARGROUP-ABSORB-0001 §4-4）**: 本 twin 补齐 type.cc:3652-3657 的
超尺寸转换——`size > max_base_type_size` 的请求一律变成 `size` 字节 1-byte
unknown 数组（与请求的 metatype 无关，`xunknown1 [280]` 即此来源）。数组经
`oversize_unknown_array`（&self 镜像 of get_array_result）在 `base_type_tree`
里以 `find_add` 同款结构键取/放，与 &mut 路径共享同一 `Arc` 身份。此前 twin 对
任意尺寸构造标量 TypeBase，280B 输入影子被定型为标量 INT（`unkint280`），
`is_piece_structured`（TYPE_ARRAY 家族）不命中 → RuleSubRight 的特殊打印标记
（ruleaction.cc:7256）不触发 → 字段件退化成 INT_RIGHT 移位梯。

TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001 (2026-08-23): every in-lease caller
(cpool.rs, merge.rs, grammar.rs, typefactory internals incl. the partial-type
constructors, `down_chain_pointer`, `get_ptr_to_from_parent`, and the decode
paths) is migrated to `get_base_result`. The twin is retained for callers
outside that lease holding `&TypeFactory` read guards (`arch.rs:2327`,
`varnode.rs`, `userop.rs`, `varmap.rs:919`, `coreaction.rs:4240`,
`ruleaction.rs`, internal `concretize` pinned `&self` by `varmap.rs:2546`)
and for the pinned `typefactory_local_cache_1204` differential snapshot base
(71971b2 cpool.rs/merge.rs compile against this file; re-pinned from the
uncompilable-at-HEAD 296c128 pin by this same migration). Migrate them when
their leases free up, then delete the twin.

### `pub fn get_base_result(&mut self, size: usize, metatype: TypeMetatype) -> Result<Arc<Datatype>, String>`

The faithful `TypeFactory::getBase(int4,type_metatype)` port
(type.cc:3631-3660): `typecache[size][m]` for `size < 9` and printable
scalar metatypes, the dedicated 10/16-byte float slots, the
`size > max_base_type_size` (=10, architecture.cc:1422) conversion into an
unnamed array of the cached 1-byte unknown (element typedef-stripped,
`TypeArray` ctor sizing `n * element.get_align_size()`), and the unnamed
`TypeBase` `findAdd` canonicalization whose miss path raises the
uninitialized-alignment-map LowlevelError.

### `pub fn get_base_no_char(&self, size: usize, metatype: TypeMetatype) -> Option<Arc<Datatype>>`

Matches Ghidra `getBaseNoChar`: only `(1, Int)` can select the cached
non-ASCII signed-byte type instead of the preferred printable ASCII type;
all other requests delegate to `get_base`. The faithful twin delegating to
`get_base_result` (LowlevelError propagation included) is
`get_base_no_char_result`.

TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001 (2026-08-23): zero current-tree
callers (merge.rs `factory_nochar_distinct` and the typefactory tests are
migrated to `get_base_no_char_result`); retained only for the pinned
`typefactory_local_cache_1204` differential snapshot base (71971b2
merge.rs). Delete when that runner re-pins to a post-migration commit.

### `pub fn clear(&mut self)`

Clears all factory-owned types and the preferred/nochar/character caches,
while retaining size and alignment configuration. The pending incomplete-
typedef queue is cleared before a same-name type can be recreated, matching
`TypeFactory::clear` (type.cc:3251-3263).

### `pub fn set_core_type_result(&mut self, name: &str, size: usize, metatype: TypeMetatype, chartp: bool) -> Result<Arc<Datatype>, String>`

The faithful `TypeFactory::setCoreType` port (type.cc:3178-3195): `chartp`
size 1 dispatches to `getTypeChar(name)`, `chartp` otherwise to
`getTypeUnicode(name,size,meta)`, code to `getTypeCode(name)`, void to
`getTypeVoid()`, everything else to the named `getBase` — each canonicalized
through `findAdd`, whose LowlevelErrors surface as `Err` with no partial
state. The final `ct->flags |= coretype` runs through `promote_core`:
Ghidra ORs the flag onto the canonical object in place so every alias sees
it; Rust's immutable `Arc` model instead replaces the promoted object in
every factory-owned channel (`types`, `core_types`, `base_type_tree`,
`base_cache`, `char_cache`, `type_nochar`, identical `typedefs`/
`rel_pointers` values), making all factory-mediated observations identical.
Flag visibility through an external stale Arc handle remains the
TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001 residual (needs an
interior-mutability rework of `Datatype`, separate lease).

### `pub fn set_core_type(&mut self, name: &str, size: usize, metatype: TypeMetatype, chartp: bool) -> Arc<Datatype>`

Arc-returning thin assertion layer (panics with the LowlevelError text on
conflict, i.e. exactly the throw of type.cc:3178).
TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001 (2026-08-23): zero current-tree
callers — cpool.rs, merge.rs and the typefactory tests are migrated to
`set_core_type_result`; the layer is retained only because the pinned
`typefactory_local_cache_1204` differential snapshot base (71971b2
cpool.rs:614, merge.rs) compiles against this file. Delete when that
runner re-pins to a post-migration commit.

### `pub fn cache_core_types(&mut self)`

Walks the ordered core tree and updates preferred atomic, character, 10/16-byte
float, and one-byte non-character caches with Ghidra's overwrite/first-fill
rules.

### `pub fn get_ptr(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype>`

Compatibility name for `get_type_pointer_default`; it no longer synthesizes
or deduplicates through a pointee-name string. The default-space wrapper calls
the same unnamed structural pointer factory as grammar's PointerModifier.

### `pub fn get_type_pointer(size, ptr_to, wordsize) -> Arc<Datatype>`

Runs one concrete virtual `getStripped` step, constructs `TypePointer`, and
canonicalizes by submeta, pointee identity, wordsize, optional-space presence,
projected Rust enum `space_id`, descending size, then id (`type.cc:954-967`,
`3867-3875`). This projection is not equivalent to Ghidra's `AddrSpace*`
object-identity gate followed by architecture `getIndex()` ordering. Ordinary
typedefs remain pointees; Partial and ephemeral PointerRel values use their
stripped object. `get_type_pointer_default` supplies Rudra's current default
geometry for the grammar caller. Because Rudra's production Architecture still
records `types->setupSizes()` as a no-op (`CSPEC-TYPEORG-STATE-0001`), this Rust
glue uses the same structural key with the registered primitive-layout fallback;
the explicit `get_type_pointer` API remains fail-closed on an empty align map.

`get_type_pointer_named(size, ptr_to, wordsize, name)` is the named overload
at `type.cc:3885`: it sets both names and `hashName(name)` before the same
concrete comparator/tree insertion.

### `pub fn get_type_pointer_rel_ephemeral(parent_pointer, ptr_to, offset)`

Implements the unnamed overload at `type.cc:4016-4023`: size, wordsize and
container come from the parent pointer; `markEphemeral` installs the canonical
plain pointer and sets `HAS_STRIPPED` (plus `SUB_PTRREL_UNK` for an unknown
pointee); the relative pointer is interned by pointee/offset/parent/wordsize.

### `pub fn down_chain_virtual(ptr, off, par, par_off, allow_array_wrap) -> Option<Arc<Datatype>>`

Reproduces the C++ virtual call `pointer->downChain(off,par,parOff,
allowArrayWrap,typegrp)` (virtual declaration `type.hh:429`, `TypePointerRel`
override `type.hh:681`; production callers include
`TypeOpIntAdd::propagateAddIn2Out` at typeop.cc:1241 and
`TypeOpPtrsub::getOutputToken` at typeop.cc:2357). For the represented
plain/PointerRel variants, dispatch follows the C++ vtable routing:
a pointer carrying `pointer_rel` state (the canonical `TypePointerRel`
representation installed by `get_type_pointer_rel_ephemeral`) or a legacy
named `is_ptrrel` side-table entry routes to the relative override `down_chain`
(`type.cc:2656-2672`); every other pointer routes to the private plain
`down_chain_pointer` (`type.cc:1084-1121`). Non-pointer inputs yield `None`
(the virtual call is ill-typed in C++).

`off` is the in/out offset (`int8 &off`, renormalized by `getSubType` and the
wrap branch), while `par`/`par_off` are the caller-shared container
accumulators that survive across a `propagateAddIn2Out` do-while chain. The
plain override writes `par = this` (`type.cc:1111`) and its wrap-to-zero early
return yields the descended pointer itself (`type.cc:1098`), so both preserve
the input `Arc` identity without re-interning. The relative override converts
the offset to parent-relative coordinates `relOff = (off + offset) &
calc_mask(size)`, rejects `relOff` outside the parent, returns the freshly
interned parent pointer on the recover-parent path (`relOff == 0 && offset !=
0`) without touching the accumulators, and otherwise recurses into the plain
override on that parent pointer, returning its result directly, `None`
included (`type.cc:2671`).

### 2026-08-24：downChain 虚分派地基（TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001）

为 `progressbarinit` PTRSUB 根因修复（B1）铺路的 TypeFactory 切片：

- **`down_chain_virtual` 新增**：按 `pointer_rel` 状态/legacy `is_ptrrel`
  侧表路由 rel/plain 两版 downChain，替代 C++ 虚分派；双侧 fixture
  `typefactory_downchain_virtual_1204` 锁定 26-record 投影（字段命中、
  非字段/空洞偏移、`off==0`/`off==size` 边界、负编码 wrap、enum 分支、
  多层 array/链式调用、rel 输入再传播、plain/rel 路由判别）。
- **rel 版两处 oracle 偏差修正**（typefactory.rs `down_chain`）：
  `relOff==0 && offset!=0` 恢复父容器分支不再写 `par/par_off`
  （type.cc:2669-2670 无此写入）；尾部递归直接返回 plain 结果（可为
  `None`），删除旧 `result.or(Some(orig_pointer))` fallback
  （type.cc:2671）。旧行为会把"命中父容器内非字段偏移"错误地退回父
  指针而不是 `NULL`，并污染容器累加器。
- **plain 版 `this` 语义修正**（`down_chain_pointer`）：`par = this` 与
  wrap-to-zero `return this` 均返回被下降指针本身的 `Arc`（type.cc:1098/
  1111），不再无条件 `get_type_pointer` 重 intern 一个 plain 指针——这同
  时修掉 rel 延迟路径（type.cc:2660-2662 经 `TypePointerRel` 对象调用
  plain 版）中 `par` 丢失 rel 身份的偏差，并消除对工厂的多余写入。
- **签名**：`down_chain` 首参由 `&TypePointer` 改为 `&Arc<Datatype>`
  （被下降指针本身，即 C++ `this`），`down_chain_pointer` 同理保持私有。
  新增 production caller 为 `TypeOpPtrsub::getOutputToken`
  （typeop.cc:2349-2364 → Rust `TypeOpPtrsub::get_output_token`）；既有
  `TypeOpIntAdd::propagateAddIn2Out`、PointerRel 与 exact-piece consumer 状态不变。

### 2026-08-27：downChain component Arc identity 窄修复

`down_chain_pointer` 的 `ptrto->getSubType(off,&off)` 现在通过
`Datatype::get_sub_type_arc` 返回容器中实际存储的 component Arc，不再把 borrowed
component 深拷贝成结构相等但 identity 不同的新 Arc。fixture 的普通 Struct 字段
恰好存储 canonical core Arc，因此后续 `get_type_pointer` 在该窄路径使用与 oracle
相同的 dependency identity；这不证明任意 component 都由 factory 拥有。
（2026-09-22 起该性质推广：`Datatype::get_sub_type` 本身返回 canonical Arc
——`TYPE-SPACEBASE-SUBTYPE-DISPATCH-0001` 签名变更——`get_ptr_to_from_parent`
等所有 walk 位点不再出现 `Arc::new(s.clone())` 深拷贝。）

`ptrsub_output_token_1204` direct projection 的 exact0/exact8/exact24 验证了
component pointee identity、pointer token identity 和重复调用 identity；这里只
证明 fixture 中的普通 Struct component 路径。array、PartialStruct、PointerRel、
enum、Spacebase、stale external Arc、incomplete composite 原位突变与冷 factory
插入仍为 MISMATCH/UNTESTED，不能关闭 `TYPEFACTORY-ARC-IDENTITY-0001` 或提升
模块级别。该 24-record fixture 中 selected ActionSetCasts raw
`result=0,count=1` 与 ActionInferTypes output canonical identity=1 现均为 MATCH；
overall 仍因 Rust-only count bridge `NO_ORACLE` 及完整 action/type 闭包的
MISMATCH/UNTESTED 而保持 MISMATCH。这些边界不属于本 component-identity 子投影。

2026-08-28 本轮五个 source overlay 合跑的 production curl A/B 暴露了另一条
下游边界：factory 构造的匿名 `TypePointer` 允许空 `TypeBase::name`，而当前局部
声明路径最终直接打印 `Datatype::get_name()`，没有按 Ghidra typestack 递归展开
pointer declarator。main/getparameter/glob_word/glob_set/next_url/match_url 的
concrete-pointer 命名前缀虽改变，声明类型 token 却为空。该 final-C 信号不能单因
归于本节 component Arc identity 修复；六项语法 MISMATCH 绑定
`PTRSUB-TYPED-DECL-RESIDUAL-0001`，上游 golden identity 继续由
`TYPE-UNKNOWN-0001` / `PRINTC-SYMBOL-DECL-0001` / `ACTION-INFERTYPES-DISPATCH-0001`
跟踪。同一 A/B 的 glob_set cast churn 绑定 `PTRSUB-SWITCH-CAST-RESIDUAL-0001`，
也不属于本节 component Arc identity 的 MATCH 投影；禁止用打印期字符串 backfill
掩盖任一差异。

### `pub fn get_exact_piece(&mut self, ct, offset, size) -> Option<Arc<Datatype>>`

Implements `TypeFactory::getExactPiece` (`type.cc:4090-4117`) in its original
range-check → exact-size → union → virtual-descent order. The loop retains the
last type/offset before each descent; a stopped struct/array becomes a canonical
PartialStruct, an unstripped enum becomes a canonical PartialEnum, and a union
becomes a canonical PartialUnion before descent. Exact hits preserve the input
or nested component `Arc`; negative offsets and zero sizes are not normalized.
The Rust signature exposes `i64` offsets and non-negative `usize` sizes, while
the oracle signature is `(int4 offset, int4 size)`: the covered claim is limited
to offsets in the `int4` domain and non-negative sizes representable by both.

The Arc-preserving virtual dispatch covers Struct, Array, PartialStruct and the
currently modeled Spacebase symbol lookup. `TypePointer::truncate`, a TypeCode
with an attached factory, and Spacebase's byte/address-unit conversion,
`resolveConstant`, scope lookup, and no-symbol `unknown1` fallback are not fully
representable. Immutable stale composite handles can also change descent after
definition replacement. These whole-function differences remain
`MISMATCH/UNTESTED` under `TYPE-0001`, `TYPEFACTORY-ARC-IDENTITY-0001`,
`DATATYPE-SPACEBASE-SPACEID-0001`, `ARCH-0001`, `ADDRESS-0001`, and
`DATABASE-0001`。series-D bilateral fixture 已运行：32 条记录中 30 条逐字节
一致，explicit-align struct/union 的 46 个字段差异已登记，overall=MISMATCH。

This foundation currently has no production caller. `variable.rs`,
`database.rs`, `funcdata.rs`, and `ruleaction.rs` still carry local
`getExactPiece` fallbacks that lose partial results or canonical identity. Their
migration remains part of the `TYPE-0001` consumer closure; series D alone does
not claim a user-visible pipeline repair.

### `pub fn get_array(&mut self, array_of: Arc<Datatype>, num_elements: usize) -> Arc<Datatype>`

Get or create an unnamed canonical array type. `getTypeArray` first invokes
the element's concrete virtual `getStripped`; ordinary typedefs do not strip,
while partial subclasses and ephemeral PointerRel do. The
inline `TypeArray` ctor (type.hh:937-944) uses
`num_elements * element.getAlignSize()`, inherits element alignment, stores
total `alignSize`, and sets `needs_resolution` for one element. Repeated calls
with the same element identity/count return the same `Arc`; equal-width arrays
with different element identities occupy distinct structural keys.

### `pub fn create_struct(&mut self, name: &str) -> Arc<Datatype>`

构造带 `hashName(name)` id、独立 display name 和 `type_incomplete` 的
registered struct stub，对应 `getTypeStruct` (type.cc:3914)。

### `pub fn set_fields(&mut self, name: &str, fields: Vec<TypeField>) -> Option<Arc<Datatype>>`

Set fields for an existing structure and update its size (size derived from
the fields — the grammar.cc:2798 derived-newSize form). Applies the
`TypeStruct::setFields` single-field arm (type.cc:1569-1571) against
Ghidra's caller-supplied `newSize` semantics: for the grammar path (this
function's only production caller) the arm recomputes
`calc_align_size(field.get_align_size(), field.get_alignment().max(1))`
(`TypeStruct::assignFieldOffsets`, type.cc:1971-1993) and ORs
`needs_resolution` in when the single field's full `get_size()` equals it.
The stored structure `size` is that alignment-rounded `newSize`, not the raw
maximum `offset + field.get_size()`; a size-3/alignment-2 field therefore
produces a 4-byte structure.
Comparing against the derived `max(offset + get_size())` instead would
over-fire for a field type whose `alignSize > size` (an XML-decoded
unrounded struct: Ghidra newSize 8 vs field size 5 keeps the flag clear) —
pinned by the `grammar.overfire` fixture record.

### `pub fn set_fields_sized(&mut self, name: &str, fields: Vec<TypeField>, new_size: usize, new_align: usize) -> Option<Arc<Datatype>>`

Explicit-newSize twin of `TypeFactory::setFields` (type.cc:3479-3490 /
`TypeStruct::setFields` type.cc:1563-1574): sets `size = new_size`
unconditionally and evaluates the single-field needs_resolution arm against
that EXPLICIT size. This is the only form under which the "single field
does not fill" and "offset not examined" matrix cells are reachable.
`new_align` 写入 `TypeBase.alignment`，并以
`calc_align_size(new_size, new_align)` 写入 `align_size`。

### `pub fn num_types(&self) -> usize`

Get the number of types currently managed

### `pub fn clear_non_core(&mut self)`

Faithful `clearNoncore` (type.cc:3266-3285): retains exactly the core-flagged
entries of the name map, core set, ordered tree, and preferred cache —
including in-place-promoted entries — and leaves the preferred-type caches
otherwise untouched (every cached entry is core by construction). It also
clears the incomplete-typedef queue, as `clearNoncore` does at type.cc:3284.

### Internal `find_add`

The `TypeFactory::findAdd` port (type.cc:3412-3439): named candidates require
a non-zero id (`"Datatype must have a valid id: {name}"`), a name+id hit with
a differing concrete `compareDependency` raises
`"Trying to alter definition of type: {name}"` while an equal definition
returns the existing object, unnamed candidates probe the ordered tree
structurally, and a miss inserts with the `"Shared type id: {id:x}"`
(including `printRaw` fragments, type.cc:139/910/1204) conflict path. Miss
时先把 `getPrimitiveAlignSize(size)` 和随后
`getAlignment(alignSize)` 写入候选 `TypeBase`，再注册。alignment map 的
`"TypeFactory alignment map not initialized"`
LowlevelError is enforced on the `get_base_result` entry only — production
Rudra factories do not yet thread the decoded alignment map
(TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001).

For series B, the ordered key additionally projects TypeArray's element
pointer and each Partial type's parent/container pointer plus offset before
descending size and id, matching type.cc:1225-1232, 2302-2310, 2406-2414,
and 2478-2486. Pointer/Struct/Union/Code concrete dependency closures remain
outside this slice under `TYPEFACTORY-POINTER-CANONICAL-0001` (pointer) and
`TYPE-0001` (the remaining general registry closure). Named `find_add` probes
therefore use the concrete comparator only for Array and Partial variants;
all other variants retain the series-A submeta/size projection in this commit.

### 2026-08-24：layout / definition replacement（series A）

- `create_struct` / `get_type_union` 先以非零 hash id 注册 incomplete stub。
- `decode_union` 从 `TypeUnion` ctor 的 incomplete 状态开始：空字段定义
  （包括 size 0）保持 incomplete，至少一个字段才 `markComplete`。
- generic/named/decoded `TypeCode` 均从 locked ctor 的 1-byte size、
  alignment 1、alignSize 1 出发；无显式 alignment 的 decode 不退化为
  primitive fallback 或 `-1`。
- `set_fields(_sized)`、`set_union_fields(_sized)` 与 struct/union decode
  写入 size、alignment、alignSize 并清 incomplete；definition mutation
  先要求 old tree/name 槽精确 `Arc::ptr_eq`，再拒绝任何无关 new-key 或
  new-name occupant，最后执行 old-key erase → new-key insert → name-map
  同步。不存在静默覆盖或旧 tree stub 遗留；四个 public setter 将
  replacement `Err` 显式提升为与 Ghidra `LowlevelError` 对应的 panic，
  不再以 `.ok()` 静默折叠为 `None`。
- Rust 不能像 Ghidra 一样原位修改同一对象：返回的新 Arc 与 factory
  relookup 相同，但调用者先前保存的 Arc，以及已捕获该 Arc 的 array、
  pointer、partial type、typedef/incomplete side table 和 cache 不会自动
  更新。这是稳定残差 `TYPEFACTORY-ARC-IDENTITY-0001`。
- `get_typedef` 先经 `find_add` 同时注册主 tree/name 槽，成功后才写
  typedef 与 incomplete side tables；`resolve_incomplete_typedefs` 将
  replacement 错误作为 `Result::Err` 传播，只有成功后才移除 pending 项。
  已有同名 typedef 只有在 side table 的 target 与输入 `Arc` 精确
  `ptr_eq` 时才复用；普通同名类型或不同 target 会抛出冲突。`clear` 与
  `clear_non_core` 均先清空 pending queue，因此清理后的同名重建不会被
  旧 typedef 项二次 resolve。
- `order_recurse` 在 concrete dependencies 之前先沿 typedef side table
  递归 target，保持 `typedefImm` 的 locked 顺序，即使 alias 的 tree/hash
  顺序早于 target，也总是 target 先进入 `dependent_order` 输出。

A 的单元测试只验证 Rust registry invariant，行为状态仍为 `UNTESTED`；
锁定 Ghidra 12.0.4 的同输入 fixture 在不可分割 series D 落地，并以
fail-closed allowlist 将 pre/post identity 差异记为 `MISMATCH`。A-D 全栈
完成前本片不得单独集成或声明 MATCH。

### 2026-08-24：array / partial canonicalization（series B）

- `get_array_result` 是 `getTypeArray` 的 Result 胶水，供 large-base
  conversion 保持错误通道；public `get_array` 只在边界把错误提升为
  `LowlevelError` 风格 panic。
- array factory 与 decode 都保留匿名 name/displayName、继承 element
  alignment，并经 `find_add` 注册。size-3/alignment-2/alignSize-4 元素的
  3-element array 因此是 size/alignSize 12、alignment 2，而不是 9。
  decode 对缺失、0 或负 `arraysize` 均执行 oracle 的 `arraysize<=0`
  LowlevelError 分支，即使声明的 array 总 size 也是 0；合法 decode 与
  factory 构造共享同一个 canonical entry。
- `get_type_partial_struct/enum/union` 不再制造 `__part*` 名字；三者以
  parent/container `Arc`、offset、descending size、id=0 canonicalize。
- `getTypeArray` 的 stripping 只认 concrete virtual state。普通 scalar
  typedef 保留为 array element；Partial 的 typedef clone 保留 subclass
  stripped 指针并剥到同一个 undefined fallback。
- TypePartialEnum 的 stored metatype 修正为 Uint，独立 submeta 保持
  UintPartialEnum；parent 由配置驱动的 `get_type_enum_result` 构造，避免
  legacy 4-byte/signed enum getter 污染判别输入。

B 的 Rust 判别测试覆盖上述状态与 identity。Pointer/PointerRel 反向 scope
test 在 B 固定了当时的已知 MISMATCH，随后由 series C 的 concrete comparator
与 tree key 转为拒绝 same-name/id redefinition；getExactPiece descent、负
offset/zero size 和最终 bilateral fixture 仍留给 D。series-B B2 投影保持
`NO_ORACLE`，B 不能单独集成或声明 MATCH。匿名 array 对 PrintC base token
的下游影响仍在 `TYPE-0001` 闭包内，最终 series D 的 E2E 必须显式观察。

### 2026-08-24：pointer canonicalization（series C）

- `TypeTreeKey` 对普通 Pointer 按 submeta、pointee `Arc`、wordsize、optional-space
  presence、投影后的 Rust enum `space_id`、descending size、id 排序；该投影不等价于
  Ghidra `AddrSpace*` 对象身份与 architecture `getIndex()`。PointerRel 按 submeta、
  pointee、offset、parent `Arc`、wordsize、descending size、id 排序。Named
  `find_add` 同样调用 concrete `compare_dependency`，direct `insert` collision
  保持 `Shared type id` fail-closed 且不改变完整 key set。
- `get_type_pointer` 只进行一次 virtual stripping，构造匿名 `TypePointer`
  后进入同一 structural tree。不同匿名 array pointee 不再因旧合成名 `" *"`
  合并；`grammar::PointerModifier::modType` 已迁到 default-geometry canonical
  wrapper，并由两个同宽、不同 element 的匿名 array 判别测试固定身份。
- default wrapper 与普通 pointer decode 在 Architecture 尚未接通
  `setupSizes` 时只对 layout 使用既有 compatibility fallback；二者仍进入同一
  pointer structural tree。显式 `get_type_pointer` 对 raw factory 保持
  `TypeFactory alignment map not initialized`，且失败前后 key set 不变。
- named overload 写入相同 name/displayName 与 `hashName(name)` id；同名同定义
  复用，dependency 不同走 `Trying to alter definition`。普通 pointer decode
  保留匿名输入，不再合成 pointee 名，并通过 `find_add` 使重复 decode 返回
  既有 canonical `Arc`，而不是在 direct `insert` 上冲突。但 Rust decode 当前
  读取后丢弃 Pointer XML 的 `<space>` 属性；locked Ghidra `TypePointer::decode`
  (`type.cc:1022-1024`) 将 `readSpace()` 保存到 pointer state，因此该字段仍是
  确定性 MISMATCH。
- `get_type_pointer_rel_ephemeral` 从 parent pointer 读取 size/wordsize/container，
  先 canonicalize stripped plain pointer，再写入 `IS_PTRREL|HAS_STRIPPED`、
  parent/offset/stripped；unknown pointee 使用 `SUB_PTRREL_UNK`。重复输入保留
  同一 `Arc`，parent/offset/pointee/wordsize 任一不同均不合并。
- `resize_pointer` 只剥 concrete `HAS_STRIPPED`，不再通过 typedef name side
  table 错剥普通 typedef；新宽度和原 wordsize 进入 pointer tree。raw factory
  的空 alignment map 在插入前返回 oracle 的 LowlevelError，且无 key 泄漏。

Series C 仍是 `NO_ORACLE / MISMATCH`，不能独立集成或解除整个 stable ID：
`TypePointer::calcTruncate` 的 attached subcomponent 尚未表示（`TYPE-0001`）；
TypeFactory 没有 Ghidra `Architecture *glb`，default-wordsize 与具体 AddrSpace
registry、production `setupSizes` state 仍是 architecture wiring residual；flat
`(name)` map 与 immutable Arc
差异也分别受 `TYPE-0001`、`TYPEFACTORY-ARC-IDENTITY-0001` 约束。最终 series
D bilateral fixture 与 E2E 之前，不得把 Rust tests 解释为 MATCH。

### Internal `insert`

`type.cc:3390 TypeFactory::insert` projection for decode arms: atomic,
Pointer/PointerRel, TypeArray, and the three Partial variants enter the ordered
tree using their concrete dependency key; named values also enter the flat
name map. Other container variants remain under TYPE-0001. A direct `insert`
collision raises the same Shared-type-id LowlevelError channel instead of
silently retaining the previous occupant.



### 2026-07-01：get_base(size, metatype)（type.cc:3631-3660）
- 按 (size, metatype) 查 core_types（int→int/int2/int8, uint→uint/uint2/uint8, float→float/double），未命中则现场创建 Base type。

### 2026-07-01（续）：补全 14 个 TypeFactory 工厂方法
get_type_void/char/unicode、get_type_union+set_union_fields、get_type_enum+set_enum_values、get_type_code、legacy `get_type_pointer_rel` side-table glue、get_typedef、resize_pointer、find_by_id/find_by_id_local、concretize/deconcretize、hash_size。+rel_pointers/typedefs 侧表字段。18 新测试。锁定 type.cc:4016 的 parent-pointer overload 由上面的 series-C `get_type_pointer_rel_ephemeral` 取代该历史胶水。
<!-- annotation-pass: 2026-07-04 -->

**2026-07-22 (printc batch 2)**: +3 TypeFactory methods to support
`PrintC::docTypeDefinitions` (printc.cc:2401) dependency-ordered type emission:

- `dependent_order(&mut Vec<Arc<Datatype>>)` — type.cc:3563
  `TypeFactory::dependentOrder`. Iterates the type tree (BTreeMap, sorted by
  name = matches Ghidra's `tree` ordered set) and recursively orders each via
  `order_recurse`. Output excludes nothing — callers filter core types.
- `order_recurse(deporder, mark, ct)` — type.cc:3545
  `TypeFactory::orderRecurse`. Visits typedef target first, then each
  `getDepend(i)` for `i in 0..numDepend()`, then pushes `ct`. Cycle-break via
  insert-second-check on a `HashSet<usize>` (Arc pointer identity, mirroring
  Ghidra's DatatypeSet pointer-identity semantics).
- `depends_of(ct)` — RUDRA-GLUE aggregator of Ghidra's per-variant
  `Datatype::numDepend` + `Datatype::getDepend` virtual dispatch table
  (type.hh:261 base; overrides 422 Pointer, 455 Array, 526 Struct, 555 Union,
  629 Code). C++ uses virtual dispatch; Rust matches on the Datatype enum.

## 2026-08-11 ANN-J annotation bootstrap

`TypeFactory::insert` received its real locked-source start line only. No
behavior changed, no runtime oracle was added, and the method/module remains
L2 with formal status `NO_ORACLE`; the annotation must not be interpreted as
`MATCH`.

## 2026-08-13 TYPE-UNKNOWN-0001

`TypeFactory::get_base(size, TypeMetatype::Unknown)` now preserves the
targeted canonical object semantics of locked Ghidra 12.0.4
`TypeFactory::getBase(int4,type_metatype)` (`type.cc:3631`):

- sizes 1, 2, 4, and 8 resolve to the SLEIGH core types `xunknown1`,
  `xunknown2`, `xunknown4`, and `xunknown8`, with the exact Ghidra name hash,
  core flag, size, and metatype;
- other in-range sizes resolve to one unnamed, id-zero, non-core `TypeBase`
  per `(size, metatype)`, enter the factory's atomic structural registry, and
  repeated requests return the same `Arc`;
- `get_base_named` mirrors the named overload at `type.cc:3667`: it hashes the
  name, canonicalizes repeated equivalent requests, and rejects a conflicting
  same-name definition with Ghidra's error text.

The direct runtime fixture is `tests/oracle/type_unknown_1204.{cc,rs}` and the
gate is `tools/run_type_unknown_oracle.sh`. It compares fixed-order JSON
byte-for-byte for type properties, repeated pointer identity, cross-size
non-identity, named identity, the collision error, anonymous structural order,
and `clearNoncore` removal plus post-clear repeated-recreation identity. The
fixture intentionally does not compare a Ghidra pointer retained across
`clearNoncore`: Ghidra deletes that object, whereas a cloned Rust `Arc` would
keep it alive, so external-old-handle lifetime/identity remains `UNTESTED`.
The Rust closure is a verified
archive of commit `6e373f08f42fd5d3b0a02d282d4245c046387558` with only the owned
`src/type_system/typefactory.rs` snapshot overlaid, so unrelated live source
churn cannot change the comparand. The runner also materializes curl and every
SLEIGH/spec input from verified blobs at provenance commit
`34a3febff160031c265cfbd841a94022c68c2c19`; it never reads the live
`examples/curl` or spec worktree and does not require runtime HEAD equality.

This closes only the observed unknown atomic-base slice. The module remains
L2: sizes above `Architecture::max_basetype_size` (array-of-unknown-byte
conversion), decode/cache rebuilding, Address/Varnode consumers, and the
general pointer/array/aggregate structural registry remain unproved. The
latter is the existing `TYPE-0001` mismatch; atomic ordering evidence must not
be read as proof that the whole TypeFactory tree is aligned.

## 2026-08-15 TYPEFACTORY-UNDEFNAME-0001

`TypeFactory::init_core_types` now names the four core TYPE_UNKNOWN base types
`undefined1/undefined2/undefined4/undefined8` (was `xunknown1/2/4/8`),
following the Ghidra data-organization registration
`ArchitectureGhidra::buildCoreTypes` (`ghidra_arch.cc:349-352`:
`setCoreType("undefined",1,TYPE_UNKNOWN,false)` … `"undefined8"`). The id
remains `Datatype::hash_name(name)` per the named `getBase` overload
(`type.cc:3667-3673`), so ids change with the name exactly as in Ghidra. The
canonical headless oracle output uses this family (`undefined8`, `undefined2`
casts, and via `Datatype::printNameBase` (`type.hh:273`, first character of
the name) the `uVar`/`auVar`/`puVar` prefixes; cf.
`tests/golden/ghidra_curl.c` `undefined1 auVar21 [24];`).

Ghidra itself has two legitimate registration flavors and this rename chooses
the headless/data-organization one deliberately:

- `ArchitectureGhidra::buildCoreTypes` (ghidra_arch.cc:349-352) —
  `undefined*`, the flavor the E2E diff gate targets;
- `SleighArchitecture::buildCoreTypes` standalone else-branch
  (sleigh_arch.cc:229-232) — `xunknown*`, the flavor the standalone console /
  direct-runner goldens (`tests/golden/ghidra_{curl,httpd}_1204.direct-runner.c`)
  and the `type_unknown_1204` oracle harness (BfdArchitecture) observe.

Consequences, registered under `TYPEFACTORY-UNDEFNAME-0001`:

- the 2026-08-13 `type_unknown_1204` recorded MATCH is superseded: its Ghidra
  side runs the SLEIGH standalone fallback, so re-running the gate against the
  renamed factory now yields a name/id MISMATCH on the four core unknowns
  (structural identity, anonymous ordering, and clear/recreate behavior are
  unaffected). This is a registered inter-flavor divergence — Rudra has one
  factory default rather than per-architecture core-type registration — not a
  port defect of `getBase` itself;
- the `xVar` prefix family disappears for every name sourced from the factory;
  `VarnodeBank`'s bank-local default adapter (`src/varnode.rs`
  `unknown_datatype`, `TYPE-UNKNOWN-0001`) still produces `xunknown{size}`
  names and is out of this change's write-set.

## 2026-08-17 CSPEC-TYPEORG-STATE-0001

`TypeFactory` now persists the `<data_organization>` state Ghidra keeps in
its private members (`type.hh:763-771`), replacing the previous
return-only snapshots:

- New private fields `size_of_int/long/char/wchar/pointer/alt_pointer`,
  `enum_size`, `enum_type`, `align_map` — zeroed at construction exactly as
  `TypeFactory::TypeFactory` (type.cc:3106-3119). Public snapshot getters
  `get_size_of_int/long/char/wchar/pointer/alt_pointer` mirror the inline
  accessors at type.hh:813-818.
- `decode_data_organization` (type.cc:4583-4615) stores the five consumed
  size children into the fields; every other child
  (`machine_alignment`, `short_size`, `float_size`, ...) is
  closed-and-skipped. No defaulting happens at decode: an absent
  `<char_size>` leaves `size_of_char == 0` until `setup_sizes`. The
  `<size_alignment_map>` branch falls through to the unified
  `close_element(sub_id)` exactly as the oracle's sam branch falls to
  `closeElement` (type.cc:4604-4612), so children *after* the map are
  still consumed (review-rework fix: a stray `continue` used to leave the
  TreeDecoder stack on the map element and silently drop trailing
  children).
- `decode_alignment_map` (type.cc:4619-4641) fixed three divergences:
  index 0 now keeps the `-1` fill sentinel (unless an explicit
  `<entry size="0">` exists), an empty `<size_alignment_map>` leaves the
  map empty (the default install belongs to `setup_sizes`, and no invented
  exception), and duplicates let the later entry win as in the oracle.
- `set_default_alignment_map` (type.cc:4644-4656) now applies
  `resize(9, 0)` semantics, so the default map is
  `[0,1,2,2,4,4,4,4,8]` — index 0 is 0, not 1.
- `setup_sizes(arch: &SizeArchInputs)` (type.cc:3137-3170) applies the
  full default derivation 1:1 (int from the stack spacebase clamped to 4,
  long via `(int==4) ? 8 : int`, char 1, wchar 2, pointer from the default
  data space, far-pointer `alt_pointer`, default map, enum defaults).
  Because Rudra's factory has no `glb` Architecture handle yet, the
  `glb->getStackSpace()/getDefaultDataSpace()/getSegmentOp()/getDefaultSize()`
  lookups are passed in as `SizeArchInputs` (RUDRA-GLUE).
- New readers `get_alignment(u32) -> Result<i32, String>` (type.cc:3296;
  verbatim `LowlevelError("TypeFactory alignment map not initialized")`
  text, last-entry fallback for sizes at/beyond the map end) and
  `get_primitive_align_size(u32)` (type.cc:3312; unsigned 32-bit modulo
  semantics, so a `-1` alignment behaves as `0xFFFFFFFF`).
- `parse_enum_config` (type.cc:4662-4672) is now an instance method that
  stores `enum_size`/`enum_type` instead of returning a tuple.

Oracle evidence: `tests/oracle/cspec_typeorg_state_1204.{cc,rs,metadata.json}`
+ `tools/run_cspec_typeorg_state_oracle.sh` — the locked 12.0.4 oracle
(production `BfdArchitecture::init` chain plus seven synthetic
`<data_organization>` documents) and the Rust comparand emit
byte-identical state projections (`DECLARED_OBSERVATIONS_MATCH`,
expected_stdout_sha256 locked in metadata). Residuals (UNTESTED/MISMATCH)
are registered in the metadata `coverage` block: enum state is private in
the oracle (no getters), live Architecture input derivation is unwired on
Rust, ill-formed non-entry map children diverge (unreachable via
well-formed specs), zero-alignment primitive queries abort on both sides.

## 2026-08-16 TYPE-WIRING-0001

The dual-track unknown typing is closed: `VarnodeBank`'s bank-local
`xunknown{size}` adapter no longer exists, so every production Varnode /
RangeHint / symbol unknown type now resolves through a `TypeFactory`.

- `TypeFactory::shared_default()` (`typefactory.rs`) models the locked
  headless oracle's single Architecture: Ghidra builds exactly one
  `TypeFactory` per `Architecture` (`TypeFactory::TypeFactory(Architecture*)`,
  `type.cc:3106-3119`) and the headless oracle runs one Architecture per
  process. Production Rudra `Funcdata` does not yet carry an attached
  Architecture (`FUNCPROTO-MODEL-BIND-0001` chain), so factory-less callers
  resolve this process-wide DataOrg-flavor canonical instance. An explicitly
  injected handle (`VarnodeBank::set_type_factory`, `fd.arch.types` in
  `ScopeLocal::restructure_varnode`) always wins, reproducing Ghidra's
  per-Architecture channel.
- `TypeFactory::concretize` now routes its TYPE_CODE→unknown substitution
  through `get_base(1, TYPE_UNKNOWN)` (`type.cc:4147`) instead of minting a
  fresh `undefined1` object; repeated calls return the same factory `Arc`,
  and the RUDRA-GLUE `deconcretize` inverse still recognizes the core
  `undefined1` spelling.
- Residual: Ghidra's `ScopeLocal::createEntry` wraps multi-element symbols
  via `glb->types->getTypeArray` (`varmap.cc:625`); Rust has no
  `TypeFactory::getTypeArray` yet, so the array shell is still built locally
  around the factory-owned element type (factory array dedup identity
  remains unproved).

## 2026-08-18 TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001

The complete `needs_resolution` setting matrix is now mirrored on every
TypeFactory creation path, closing the audit gap where Rudra never produced
a single-field `needsResolution` struct (the SUBPIECE findResolve write-side
producer):

- `set_fields` — `TypeStruct::setFields` single-field arm
  (type.cc:1569-1571): ORs the flag in (never cleared) when exactly one
  field's full `get_size()` equals the caller-supplied `newSize`. Rudra's
  arm recomputes the grammar-path newSize
  (`calc_align_size(field.get_align_size(), field.get_alignment().max(1))`,
  `assignFieldOffsets` type.cc:1971-1993) instead of comparing against the
  derived `max(offset + get_size())`, which would over-fire for a field type
  with `alignSize > size` (XML-decoded unrounded struct) — pinned by the
  `grammar.overfire` record.
- `set_fields_sized` (new) — explicit `newSize`/`newAlign` twin of
  `TypeFactory::setFields` (type.cc:3479-3490): `size = new_size`
  unconditionally, single-field arm against the EXPLICIT size. Proves the
  "not fills" (explicit size > field size → 0) and "offset not examined"
  (single field @4 whose type size == newSize → 1) cells.
- `decode_struct` — the full `TypeStruct::decodeFields` acceptance loop
  (type.cc:1839-1870) plus tail (1871-1877): per-field void-metatype throw,
  strictly-lower-offset order throw, overlap throw-out (the dropped field is
  observable via the surviving field count and feeds the single-field arm),
  does-not-fit throw — all four LowlevelError texts verbatim; tail leaves
  the factory type `type_incomplete` iff it ended with zero fields (the
  decodeStruct→`TypeFactory::setFields` transfer, type.cc:4350-4356 +
  3487-3488) and sets the single-field arm against the decoded `size`
  attribute.
- `get_ptr` / `get_type_pointer` / `get_type_pointer_rel` /
  `resize_pointer` / decode pointer branch — `TypePointer::calcSubmeta`
  inheritance arm (type.cc:1051-1052, run by every Ghidra `TypePointer`
  ctor): pointer to a resolution-needing pointee inherits the flag, never
  through a second pointer level. Consumers waive `TYPE_PTR` at every
  needsResolution rejection (printc.cc:1962), so the flag on pointers
  changes no resolved type — it makes the waiver load-bearing, as in Ghidra.
- `get_array` — inline `TypeArray` ctor size-1 arm (type.hh:937-944).
- decode array branch — `TypeArray::decode` `arraysize == 1` arm
  (type.cc:1341-1342) plus the `arraysize<=0 || arraysize*alignSize != size`
  validation (type.cc:1338-1339, "Bad size for array of type"), plus a real
  bug fix: the branch now `rewind_attributes()` after `decode_basic` before
  reading `arraysize` (type.cc:1331) — previously the attribute loop had
  consumed the element and every decoded array errored "Bad size for array
  of type".

Scope notes: the pointer constructor now records calcSubmeta, inheritable
flags, array/relative state and the concrete factory key. The attached
`truncate` pointer built by `calcTruncate` is still not represented, and the
enum AddressSpace projection cannot preserve a Ghidra registry object's raw
identity. `set_fields`'s stored `st.base.size` stays the derived
`max(offset + get_size())` (can differ from Ghidra's
align-rounded grammar newSize for trailing padding; plumbing the explicit
size from the grammar caller is a registered follow-up in grammar.rs's
domain).

Historical pre-series-C oracle evidence:
`tests/oracle/typefactory_needsres_1204.{cc,rs,metadata.json}`
+ `tools/run_typefactory_needsres_oracle.sh` — 27 records
(set/grammar/dec/arr.factory/ptr/union.setfields + grammar.regressions
[overfire + nested], ptr.ordering [stub-time pointer never inherits; cached
pointer stays clear; differently-sized new pointer inherits],
dec.acceptance [overlap throw-out ×2, empty size-8 and size-0 incomplete
residue], dec.err [order/fit/void/name-empty/name+void-precedence verbatim
error texts]), real locked-12.0.4 oracle vs Rudra byte-identical
(`records=27 … MATCH`), expected stdout sha256 locked in metadata. Series C
changes the pointer factory bytes, so this older fixture cannot upgrade the
new projection above from `NO_ORACLE`. Its historical E2E curl
output byte-identical to the pre-change baseline (diff 0 lines;
differential gates defects=0/numbering=0 on both
`tests/golden/ghidra_curl.c` and `result/ghidra_curl_12.0.4.c`), confirming
the activated flag paths have no observable E2E effect on the current corpus
(all pointer consumers waive TYPE_PTR; no curl-parsed single-field struct
reaches the SUBPIECE walk). The printc_subpiece fixture's Rust-side manual
flag on `fixture_inner` is now reclaimable (root noted: not urgent).

## 2026-08-20 TYPEFACTORY-LOCALTYPE-CACHE-0001

The local atomic-core cache now follows locked Ghidra 12.0.4
`TypeFactory::cacheCoreTypes/getBase/getBaseNoChar` identity semantics
(`type.cc:3200-3248`, `3619-3660`) instead of inferring `int1`, `uint1`,
`float`, or `double` names:

- `set_core_type` preserves the properties after Ghidra's dispatch: one-byte
  character requests force `TYPE_INT`; void forces `void`/size 0; code forces
  size 1; the remaining scalar/unicode branches retain caller properties.
  It assigns the resulting `hashName` id/core and character flags and inserts
  the canonical `Arc` into the atomic cache-traversal tree.
- `cache_core_types` implements ordinary first-fill, ASCII character forced
  preference, `charcache` updates, 10/16-byte float slots, and enum exclusion
  for core entries that actually reach `base_type_tree`, plus the ordered
  overwrite of `type_nochar` by each such non-ASCII one-byte `TYPE_INT`. It
  deliberately does not clear first, preserving repeated-call state.
- `get_base` is cache-first and returns cached named core `Arc`s independent
  of spelling. For the within-base-limit projection, a miss creates/reuses an
  unnamed id-zero structural entry. The architecture-dependent large-base
  array branch remains missing. `get_base_no_char` substitutes `type_nochar`
  only for `(size=1, metatype=Int)` and otherwise delegates unchanged.
- `clear` resets the full type registry plus `base_cache`, `type_nochar`, and
  `char_cache`, retaining data-organization sizes/alignment.

The locked differential fixture is
`tests/oracle/typefactory_local_cache_1204.{cc,rs,metadata.json}`, run by
`tools/run_typefactory_local_cache_oracle.sh`. Its 99 fixed-order records
compare exact custom names, unsigned ids, flags, metatypes, and canonical
pointer/`Arc` identity for two non-ASCII signed bytes, two unsigned bytes,
an ASCII byte, repeated cache calls, a later higher-id signed byte, double
clear, empty-cache fallback, and post-clear plain→ASCII reconstruction. The
runner builds Ghidra at commit `e40ed130…376b` and an isolated Rudra closure
from pinned commit `8012627…8c65` with only this task's hash-verified
`typefactory.rs` overlaid, so concurrent dirty files cannot affect the
comparand. Result: all 99 records byte-identical, stdout SHA-256
`4780c75cf8247139ef631fe9060300d4c8bb393248a03b8b9711685ed9c14879`.

This is a targeted cache/nochar projection `MATCH`; fixture
`overall_status=MISMATCH`, and neither the mapped functions nor the module are
L3. Existing-noncore promotion cannot preserve the old external `Arc`'s
identity/flag mutation and is tracked by
`TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001`. Other known mismatches are:
decoded core enums do not enter `base_type_tree`; same-name conflicts panic
instead of surfacing a `LowlevelError`-equivalent `Result`;
`get_type_char(size)` constructs on cache miss instead of throwing; raw
`TypeFactory::new` is architecture-bootstrap glue rather than Ghidra's empty
constructor; and large-base requests cannot inspect
`Architecture::max_basetype_size`. Core-stream decode is known `MISSING`
(`clear_non_core` plus child skipping instead of `clear` plus force-core
decode); wide-character and 10/16-byte float observations, lock poisoning,
external-handle lifetime after `clear`, and the general pointer/aggregate tree
remain `UNTESTED` or covered by the existing `TYPE-0001` mismatch.
Constructor/destructor propagation in
`decodeTypeWithCodeFlags` is the separate serial follow-up
`TYPEFACTORY-CODEFLAGS-DECODE-0001`.

## 2026-08-23 TYPEFACTORY-LOCALTYPE-CACHE-0001 REWORK

Independent review rejected the 99-record projection's global alignment;
the six registered gaps are closed as follows against locked
`type.cc`/`type.hh` (commit `e40ed130…376b`):

- **Canonical `findAdd` core** (`type.cc:3412-3439`): named candidates need a
  non-zero id; a `(name,id)` hit returning a `compareDependency`-equal
  (sub-metatype + size, `type.cc:227-234`) existing object is the aliasing
  point; differing definitions raise `"Trying to alter definition of
  type: …"`; unnamed candidates probe the ordered tree structurally
  (`DatatypeCompare`, type.hh:306-310: sub-metatype ascending, size
  descending, id ascending); misses insert with the `"Shared type id: {id:x}"`
  conflict message including the `printRaw` fragments (type.cc:139/910/1204).
  The alignment-map LowlevelError (type.cc:3433-3436 via
  `getPrimitiveAlignSize`/`getAlignment`) is enforced on the faithful
  `getBase` port only (TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001).
- **Promotion aliasing** (`type.cc:3194`): `set_core_type_result` promotes an
  existing equal definition by replacing the immutable `Arc` in every
  factory-owned channel (`promote_core`); all factory-mediated observations
  (name/id/flags queries, cacheCoreTypes participation, clearNoncore
  retention) match the oracle's in-place OR. Flag visibility through an
  external stale handle stays TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001 (needs
  the `Datatype` interior-mutability rework in datatype.rs — separate lease).
- **Error paths**: conflicts, missing ids, shared ids, and the raw-constructor
  alignment error now propagate as `Result::Err` with the oracle messages and
  no partial state; the legacy `set_core_type` Arc wrapper is now a zero-caller
  thin assertion layer kept for the pinned differential snapshot base
  (TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001, migrated 2026-08-23).
- **Legacy-caller migration** (TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001,
  2026-08-23): cpool.rs, merge.rs, grammar.rs and every in-file caller of
  `set_core_type`/`get_base`/`get_base_no_char`/`get_type_void` are migrated
  to the faithful Result twins. In-file behavior deltas of the swap, each
  toward oracle fidelity: `get_type_partial_struct/enum/union` and
  `get_ptr_to_from_parent` now run the real `findAdd` (alignment error
  surfaces as the LowlevelError panic instead of a fabricated `undefined1`
  fallback that the old twin's never-None contract made unreachable);
  `down_chain_pointer`'s enum arm uses the faithful `getBase(1,TYPE_UINT)`;
  `decode_type_no_ref`/`decode_code_define` create the void singleton through
  `get_type_void_result` exactly as Ghidra's getTypeVoid does on a miss.
  `concretize` stays on the lenient `&self` twin because its caller
  (varmap.rs:2546, varmap.cc:622) holds a read guard — the cached
  `undefined1` entry hits the identical typecache fast path.
- **Core enums enter the tree**: `decode_enum` canonicalizes through
  `find_add` (name map + ordered tree), so a core enum participates in
  `cacheCoreTypes` — a size-1 signed enum wins `type_nochar`
  (type.cc:3220-3222 runs before the `isEnumType` break) while the preferred
  slot stays empty for it; enum signedness comes from the `enum_int`/
  `enum_uint` metatype string (Rust's `TypeMetatype` collapses Ghidra's
  TYPE_ENUM_INT/TYPE_ENUM_UINT).
- **`getTypeChar(int4 s)`** (type.cc:3678-3687): cache lookup only;
  every miss (and every `s >= 5`) raises
  `"Request for unsupported character data-type"`. The creation paths are the
  named ports `get_type_char_named`/`get_type_unicode_named`
  (TypeChar type.hh:356 / TypeUnicode type.cc:862-867 with
  `submeta_override`), `get_type_code_named` (type.cc:3707-3717), and
  `get_type_enum_result` (type.cc:3967-3973 over the configured
  `enumsize`/`enumtype`).
- **Raw constructor** (`type.cc:3106-3119`): `TypeFactory::raw()` exposes the
  pre-bootstrap state — zeroed sizes, no alignment map, no core types,
  cleared caches; `get_type_void_result`/`get_type_code` now create on miss
  exactly like type.cc:3575-3588/3692-3701.
- **Large-base conversion** (type.cc:3652-3657): `get_base_result` converts
  `size > max_base_type_size` (=10, architecture.cc:1422, now a factory
  field) into an unnamed array of the cached 1-byte unknown, element
  typedef-stripped, `TypeArray` ctor sizing `n * element.get_align_size()`,
  canonicalized through `find_add`.
- **`decodeCoreTypes`** (type.cc:4567-4577): full `clear()`, force-core
  `decodeTypeNoRef` children (the char/utf arms now build through the
  TypeChar/TypeUnicode constructor ports; the `metatype="void"` arm runs the
  decoded-id `TypeVoid` through `findAdd` instead of returning the
  singleton), then `cacheCoreTypes()` — skipped when a child raised, leaving
  the partial state observable. The delegating enum/struct/union/code arms
  now close their element (type.cc:4546) — previously the decoder stack
  leaked the open element and subsequent siblings were dropped.
- **`hashSize` fix**: the module-level `hash_size` now delegates to the
  faithful XOR port `Datatype::hash_size` (type.cc:709-716) instead of the
  invented `(id << 8) | sz` fold; `find_by_id` folds sizes correctly.
- **`clearNoncore`** retains core-flagged entries directly (promoted entries
  included) instead of rebuilding from the bootstrap core set.
- **Tree keys** derive from `Datatype::get_submeta()` (constructor-assigned
  sub-metatypes with `submeta_override`) instead of flag inference, fixing
  TypeUnicode sizes other than 1/2/4 and the size-1 `getTypeUnicode` case.

Remaining registered residuals: external stale-handle promotion visibility
(TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001), legacy Arc wrapper callers
(TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001), production alignment-map wiring
(TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001), the general container tree /
multi-id name map (TYPE-0001), `RwLock` poisoning (Rust glue, no Ghidra
input), and the code-flags decode family
(TYPEFACTORY-CODEFLAGS-DECODE-0001). Oracle evidence: the extended
`tests/oracle/typefactory_local_cache_1204.{cc,rs,metadata.json}` fixture —
see the runner `tools/run_typefactory_local_cache_oracle.sh` output in the
task report for the record count and stdout SHA.

Fixture-commit addendum (same rework): removed two no-op `drop(&mut …)`
reference drops (`find_add`, `get_type_void_result`) flagged by the compiler;
no behavior change — the pinned oracle run in this commit's Differential
block covers the exact final bytes.

## 2026-08-23 TYPEFACTORY-CODEFLAGS-DECODE-0001

`decodeTypeWithCodeFlags` (type.cc:4193-4212) and the `decodeCode` chain it
calls are ported 1:1 against locked `type.cc`/`marshal.cc`:

- **`decode_type_with_code_flags`** (type.cc:4193-4212): opens the `<type>`
  element, runs `decodeBasic`, raises `"Special type decode does not see
  pointer"` for a non-`ptr` metatype, then executes the WORDSIZE attribute
  loop **without** a preceding `rewindAttributes` (type.cc:4201-4207, unlike
  `TypePointer::decode` at type.cc:1015). Because neither `XmlDecode`
  (marshal.cc:231-241) nor Rudra's `TreeDecoder` restarts an exhausted
  attribute enumeration, the loop reads nothing and `wordsize` keeps the
  `TypePointer` ctor default 1 (type.hh:407). `decodeCode` then re-reads the
  SAME still-open element and raises `"Bad size for type "` (empty name) —
  the locked 12.0.4 oracle's behaviour for every nested pointer→code XML,
  verified empirically against the pinned build (all varargs/model/ctor/
  dtor/thiscall flag combinations byte-identical). The success tail
  (`closeElement`, `calcTruncate` guard, `findAdd`) is structurally present;
  `TypePointer.truncate` is the TYPE-0001 structural residual.
- **`decode_code`** (type.cc:4401-4429) full port replacing the stub-insert
  version: `decodeStub` + metatype check + forcecore flag +
  `findByIdLocal(name,id)`; a miss canonicalizes the scratch through
  `find_add` (stub for recursive definitions), a non-code occupant raises
  `"Trying to redefine type: {name}"`; `decode_prototype` fills the scratch
  with the constructor/destructor chain; a completed container entry runs
  `compareDependency` (`"Redefinition of code data-type: {name}"`), an
  incomplete stub is defined in place via the factory `setPrototype`
  wrapper — which completes prototype-less stubs too (Ghidra clears
  `type_incomplete` even for a null prototype, type.cc:3518-3528);
  `resolveIncompleteTypedefs` runs at the end.
- **`set_prototype_define`** (type.cc:3518-3528): the Arc-channel mirror of
  the factory wrapper — incomplete guard with the verbatim LowlevelError,
  `TypeCode::setPrototype(this,fp)` copy, `type_incomplete` clear, the
  `(variable_length | type_incomplete)` flag OR, and re-registration under
  the unchanged ordered-tree key.
- **`resolve_incomplete_typedefs`** (type.cc:3777-3809) + the
  `incomplete_typedefs` list populated by `get_typedef` (type.cc:3837-3838):
  struct/union entries complete through the setFields wrapper's field copy
  and flag merge (type.cc:3479-3492 / 3500-3511), code entries through the
  factory `setPrototype` with the referenced type's prototype and flags.
- **`decodeCode` is private** in the oracle (type.hh:791): its only public
  callers are `decodeTypeNoRef` (flags false) and
  `decodeTypeWithCodeFlags`; the constructor/destructor flag chain therefore
  has no reachable public success observation in 12.0.4.
- `decode_basic` (datatype.rs) now raises `"Bad size for type {name}"`
  (type.cc:671-672) instead of coercing the size to 0; every decode arm
  propagates the error.

Oracle evidence: `tests/oracle/typefactory_codeflags_decode_1204.{cc,rs,
metadata.json}` + runner `tools/run_typefactory_codeflags_decode_oracle.sh`
(89 records, projection MATCH). Registered residual: a present
`<prototype>` child errors in Rudra until `FuncProto::decode`
(fspec.cc:4675-4839, fspec.rs lease) is ported — the stub inserted before
the throw survives exactly like the oracle's own prototype-decode
failures; live ctor/dtor/`has_thisptr` flag observation is gated on the
same port (TYPEFACTORY-CODEFLAGS-DECODE-0001 residual).


## 2026-08-25：spacebase 类型携带 scope 快照（B3-COREACTION-CONSTANTPTR-0001 段(b)）

- `TypeFactory::symboltab: Option<Arc<RwLock<Database>>>`（两构造器
  初始化 None）+ `set_spacebase_scope_source(db)`：Ghidra 的
  `TypeSpacebase::getMap` 每次 `glb->symboltab->getGlobalScope()` 动态解析
  （type.cc:2935-2945）；Rudra 类型不携带 Architecture，改为构造时快照
  （符号图在反编译前安装、期间稳定，与 oracle 可观察答案一致）。
- `TypeFactory::live_local_scopes: BTreeMap<u64, Arc<RwLock<ScopeLocal>>>`
  （2026-09-24 VARMAP-STACKBOUNDARY-0001 新字段，两构造器初始化空表）+
  `get_type_spacebase` 构造期立即挂接（`frame.is_null()` 判定 local frame；
  registry `entry().or_insert_with()` 保证缓存类型**自诞生即带句柄**，
  后续发布只替换句柄内容）；`Funcdata::publish_scope_to_spacebase` 在每趟
  `ActionRestructureVarnode` 后把重构 ScopeLocal 发布进句柄——这是 Ghidra
  getMap local 臂（type.cc:2938-2944 `fd->getScopeLocal()` 动态解析）的
  Rust 所有权镜像：spacebase 子类型查询由此读到**活跃**局部图。
- `get_type_spacebase` 在句柄存在时把 global scope 克隆进新 spacebase 产品
  的 `scope` 字段——`TypeSpacebase::get_sub_type`（RulePtrsubUndo 的
  isPtrsubMatching 守卫）由此获得 global-frame 的 subtype 答案。去重键不变
  （`__spacebase_{ws}_{frame}`），首次构造定格快照。

## 2026-09-23：spacebase 类型名清空（SPACEBASE-SYMNAME-0001）

`get_type_spacebase` 此前把合成去重键 `__spacebase_{ws}_{frame}` 同时当作
TypeSpacebase 的**类型名**，8 个挂载函数的 SP 输入声明泄漏为
`__spacebase_1_<frame> *in_RSP`。核实 oracle：`TypeSpacebase(AddrSpace*,
const Address&, Architecture*)`（type.hh:735-736）基类构造
`Datatype(0,1,TYPE_SPACEBASE)`（type.hh:214）**name 为空**——匿名类型；
`PrintC::buildTypeStack`（printc.cc:143-163）在匿名非 PTR/ARRAY/CODE 类型处
终止，`pushTypeStart` 匿名分支（printc.cc:280-285）经 `genericTypeName`
（printc.cc:3373）拼出 **`BADSPACEBASE`**（cc:3387-3389，无 size 后缀）。
现 Rudra 侧 `TypeBase::new(String::new(), ...)` 与 oracle 同为空名，
printc 的 `push_type_start_opt` 匿名分支 → `generic_type_name` →
`BADSPACEBASE *in_RSP`。合成键仅存续为 name-keyed BTreeMap 的去重槽位
（Ghidra 经 findAdd 的 compare 树去重，type.cc:3996/3045-3055）。curl E2E
前后差分 = 仅 8 行声明行改名，defects=0/numbering=0、skeleton 2993==基线；
httpd 2339==基线；glob_set/glob_range/glob_url 与 next_url 输出零行变化。

## 2026-08-28：PrototypePieces 借用适配

本文件的两处测试构造改为传入 `Option<&Arc<Datatype>>`，与 fspec 的
`PrototypePieces` carrier 保持同一 Arc 身份。TypeFactory 生产算法没有因此
改变；`TYPEFACTORY-ARC-IDENTITY-0001`、hidden-return pointer canonicalization
和 oversized local cache 等残差不变，模块仍为 L2/MISMATCH。

## 2026-08-29：shared_default attach 时补齐 setupSizes 对齐 guard（HTTPD-TFALIGN-PANIC-0001）

- `TypeFactory::shared_default`（typefactory.rs）的 `get_or_init` 在构造
  `TypeFactory::new(8)` 后执行 `if factory.align_map.is_empty() {
  factory.set_default_alignment_map(); }`——对应 oracle 的
  `Architecture::decode` 尾部 `types->setupSizes();`（architecture.cc:1350）
  的对齐 guard `if (alignMap.empty()) setDefaultAlignmentMap();`
  （type.cc:3164-3165，默认阶梯 type.cc:4644-4656）。
- 语义依据：Ghidra 中管线可达的工厂必经 decode→setupSizes，`alignMap` 永不
  为空；`"TypeFactory alignment map not initialized"` LowlevelError
  （type.cc:3296-3305 getAlignment，经 findAdd type.cc:3433-3436 触发）只在
  raw 构造与 decode 之间可达，绝不会出现在被反编译函数内。Rudra 的
  httpd 驱动没有 Architecture，进程级工厂此前停在 raw 构造态，首个
  `getTypePointer` 树 miss 即触发该错误（panic 桥）→ 共享工厂 RwLock 中毒
  → 后续 worker PoisonError 级联（master 上 httpd 仅 4/29 函数输出）。
- 修复后该工厂与 curl 驱动手工接线（curl_decompile.rs
  `set_default_alignment_map`）的同一实例状态一致：guard 幂等，非空
  `size_alignment_map` 不被覆盖。httpd E2E 恢复为 28/29 函数输出、0 panic。
- 附带发现（不在本修复范围）：ap_strcasecmp_match 在 collapse restart
  循环不收敛（`orderLoopBodies`→`finalize_structure: 3 -> 1` 无限重复），
  属 blockaction/collapse 模块缺陷，需独立 TODO 跟踪。

## 2026-09-24：spacebase scope 快照角色收窄为 getMap 全局腿（RULEARITH-SPACEBASE-ARRAYSNAP-0001）

`get_type_spacebase` 构造期克隆的全局 scope 现在只充当 `TypeSpacebase::getMap`
（type.cc:2935-2945）的**全局腿**（全局 spacebase 或 queryFunction miss）；
localframe 有效的查询不得读它——管线的 restructureVarnode 会持续改写
ScopeLocal，RulePtrArith 查询路径（ruleaction.rs `AddTreeState::spacebase_map`）
改为查询点从被反编译 Funcdata 解析活跃 ScopeLocal
（`SpacebaseMap::Local`）后传入 datatype.rs 的 `*_in_map` 查询族。
快照克隆对 localframe 查询的可见缺陷（oppool2 时点全部栈偏移查询 miss，
extra 恒 0）就此消灭；构造签名与去重键不变。

## 2026-09-25（Lane MIRROR2）：canonical_unknown_base_1 —— 1 字节 TYPE_UNKNOWN 的工厂命名通道（MIRROR2-UNKBYTE-0001）

- **根因（镜面残差族=unkbyte 拼写）**：oracle 的 spacebase/符号查询 miss 臂
  一律返回 `glb->types->getBase(1,TYPE_UNKNOWN)`（type.cc:2965-2967；
  database.cc:629/681/731）——经工厂解析为**命名**核心类型
  （standalone 档 `xunknown1`、DataOrg 档 `undefined1`）。Rudra 的
  datatype.rs 六处 miss/untyped 臂构造**裸匿名** `TypeBase::new("",1,
  Unknown)` → `PrintC::genericTypeName`（printc.cc:3383）拼成 `unkbyte1`
  （curl 镜 5 处、httpd 镜 1 处 `(unkbyte1 *)` cast 实证）。
- **修法**：`TypeFactory::canonical_unknown_base_1()`（typefactory.rs）+
  datatype.rs 六处改调。**锁安全**（eu-stack 亲证死锁根因）：主调用链
  `TypeFactory::down_chain_pointer`（持工厂**写**租约）→
  `TypeSpacebase::get_sub_type` → 查询，helper 若重入 `shared_default`
  的 RwLock 即自死锁（canon main/_start >10s 超时的根因；w1 假象 671
  实为 3 函数死锁丢弃）。因此缓存 `CANONICAL_UNKNOWN_BASE_1`（OnceLock）
  在 `shared_default` 构造闭包内**无租约**急切填充——任何租约存在必在
  构造完成后 → 快路径恒已武装，查询零锁。工厂身份保留（与 typecache
  同一 Arc），身份敏感下游（类型传播 ptr-eq、char-print 旗标读取）在
  规范对象上决策。
- **效果**：curl 镜/httpd 镜 unkbyte 0 残留；canon 466 不回退、零超时；
  vsh 镜（gen 驱动）维持全函数健康。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 2 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-26 — TF-SINGLETON-WIRING-0001 第一步：current-Architecture 工厂解析

- `TypeFactory::shared_default()` 从进程单例入口改造为**解析入口**：线程的
  current-Architecture 工厂（`Architecture::set_types`/`ensure_types` 在 oracle
  `buildTypegrp` 时刻——sleigh_arch.cc:201 / ghidra_arch.cc:321——发布）优先；
  无发布时回退 process-canonical 工厂（原 OnceLock 构造配方逐字节冻结，更名
  `process_canonical_factory`）。单 Architecture 进程两臂返回同一句柄（驱动经
  `set_types` 安装 PC），全部既有观察字节恒等；多 Architecture 进程（bin_sweep
  双二进制）各 Architecture 的类型累积表互相隔离，恢复 oracle
  per-Architecture 工厂生命周期（architecture.cc:162 构造 null → buildTypegrp
  new → 211-212 delete）。
- 新增 `TypeFactory::fresh_canonical()`：per-Architecture 工厂构造配方（new(8)
  核心类型 + architecture.cc:1350 decode 尾默认对齐表 type.cc:3164-3165 + 无租约
  unknown1 预热），供 `ensure_types` fresh 路径与 per-binary 驱动使用。
- 新增发布/退订/查询 API（`publish_current_arch`/`unpublish_current_arch`/
  `current_arch_factory`，pub(crate)）：线程局部 current-Architecture 注册表
  （工厂句柄 + 发布期预热的 1 字节 unknown 快照）。`canonical_unknown_base_1`
  改为线程局部快照优先——MIRROR2 无锁快路径在发布期（无租约）武装，写租约
  持有者（down_chain_pointer→get_sub_type）不再进入工厂 RwLock。
- `Architecture::ensure_types` fresh 路径从借用 PC 改为构造 OWN fresh 工厂并
  发布；`Architecture` 新增 `Drop`（architecture.cc:211-212 镜像）——注册表仍
  指向自己的工厂时清除，否则不动（其它 Architecture 的发布优先）。
- 39 个 `shared_default` 引用点（9 文件，含被持域 coreaction.rs 3 点）零改动：
  全部经该单一入口自动获得 per-Architecture 解析。oracle 语义对照与调用点域
  分类见 `docs/alignment_docs/TYPEFACTORY_PERARCH_2026-09-26.md`。已知限制：
  线程局部=最后发布者胜；同线程交错双 Architecture 处理（无现存驱动形态）不在
  覆盖面；跨线程 drop 不清原线程 TLS（Arc 保活，退化到旧工厂，不 panic）。

### 2026-09-26 — WORKPKG-UNMAP-TYPEUNION-0003（type.cc 3724/3445/3750/3761/4055/4122/3479/3500 残项）

- **`pub struct DatatypeWarning`**（type.hh:752-762）：警告记录
  `{ type_name, type_id, warning }`——Ghidra 存 `Datatype*`，Rudra 记
  `removeWarning` 比较所用的 (id,name) 身份对（type.cc:3766）。新字段
  `warnings: Vec<DatatypeWarning>`（type.hh:760）随两个构造器初始化。
- **`pub fn insert_warning(&mut self, dt, warn) -> Result<Arc<Datatype>, String>`**
  （type.cc:3750-3757）：id==0 → Err（oracle 抛 LowlevelError）；经
  registered-slot replace 置 `warning_issued`（type.hh:185 = 0x20000）后
  追加记录。
- **`pub fn remove_warning(&mut self, dt: &Datatype)`**（type.cc:3761-3773）：
  保序遍历，(id,name) 双等即删。
- **`pub fn set_name(&mut self, ct, n) -> Result<Arc<Datatype>, String>`**
  （type.cc:3445-3459）：经 define_replace 完成 nametree/tree 双通道
  erase-reinsert、`name`/`displayName` 同置、id==0 时 `hashName(n)`。
  与 oracle 的分歧：撞名/撞树键时 oracle std::set::insert 静默失败（类型
  不入索引），Rudra 以 `Err` 显式拒绝（注册表误用面）。
- **`pub fn recalc_pointer_submeta(&mut self, base, sub)`**
  （type.cc:3724-3745）：忠实移植——`TypePointer top(1,base,0)` 探针的
  calcSubmeta 即当前正确 submeta；相等早退；否则从
  `lower_bound((sub, base, 0,0,0, no-space, Reverse(1), 0))` 起沿树序走，
  首个非 TYPE_PTR 或 `ptrto != base`（Arc 身份）即 break；old-key submeta
  分量 == sub 的条目 remove + 以当前投影重插（Ghidra 原位改
  `ptr->submeta = curSub`，Rudra submeta 为派生量，重键即迁移）。探针
  形状继承 oracle 的 wordsize-0/无空间/size-1 错过面。define_replace 的
  Arc 重包接缝限制：pointee 为完成前旧 Arc 的指针不可达
  （TYPEFACTORY-ARC-IDENTITY-0001）。
- **`pub fn get_type_pointer_with_space(&mut self, ptr_to, space, nm)`**
  （type.cc:4055-4065）：`TypePointer::new_with_space`（wordsize=
  space.word_size()、spaceid、calcSubmeta）+ name/displayName/id=hashName +
  findAdd(enforce) + calcTruncate 尾（TYPE-0001 残差形态：守卫 +
  resizePointer 注册副作用，同 decode 路径 kludge）。注意无
  `getStripped` 前置（异于 getTypePointer）。
- **`pub fn destroy_type(&mut self, ct) -> Result<(), String>`**
  （type.cc:4122-4132）：coretype → Err；hasWarning 先排空；nametree/tree
  双通道按 Arc 身份或 (name,id)/树键等价删除。
- **`set_fields_flags` / `set_union_fields_flags`**（type.cc:3479/3500 全
  签名形）：补齐 flags 掩码尾——struct 掩码
  `opaque_string|variable_length|type_incomplete`（type.cc:3487-3488），
  union 掩码无 `opaque_string`（type.cc:3508-3509）；旧
  `set_fields_sized`/`set_union_fields_sized` 委托 flags=0 投影。
  struct 完成路径（`set_fields`/`set_fields_sized`/`set_fields_flags`）
  现补齐 `recalcPointerSubmeta(ot,SUB_PTR)` + `(ot,SUB_PTR_STRUCT)` 迁移
  尾（type.cc:3490-3491，union 版无此调用）。
