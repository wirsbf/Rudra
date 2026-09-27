# `debugproto.rs` API Reference

## 2026-09-26：DWARF 匿名类型命名指纹（DWARF-ANON-TYPENAME-0001）

**根因（cast 名残差族 −44 票面）**：Rugra 对无名 `DW_TAG_structure_type`/
`union_type`（及 `shallow_type` 回边投影）一律落 `struct_<offset>`/`union_<offset>`
占位拼写；Ghidra 的匿名复合体名由 **Java 侧 DWARF importer** 在 Program 导入期
合成（非 cpp 反编译器）：`DWARFProgram.getDWARFName`（DWARFProgram.java:608-675）
对无名结构类走
`anon_<container>_<layout fingerprint>_for_<referring member fields>`，指纹 =
`DWARFUtil.getStructLayoutFingerprint`（DWARFUtil.java:267-298）：
`String.format("%d_%d_%08x", byte_size, memberCount, memberNames.hashCode())`，
`memberNames` = 排序后的 `"%04x_%s" % (memberOffset, memberName)` 列表
（Java `List.hashCode` = 31 折叠，初值 1；`String.hashCode` = UTF-16 31 多项式
32 位回绕）。锁定见证：curl golden `(anon_union_16_3_e2f18bb4_for_content)`
（ghidra_curl_1204.c:767-788）= union@0xa49（byte_size=16，成员 Set/CharRange/
NumRange 全部无 `DW_AT_data_member_location` → 偏移 0，count=3），`_for_content`
来自唯一引用成员 `content`（struct@0xa77 字段 0xa8d，
`getReferringMemberFieldNames` DWARFProgram.java:792-819）。Java 12.0.4 build 树
`/data/ls/DiffClip/tools/ghidra-12.0.4-build/src`（application.version=12.0.4 亲核），
basis 记录于 TODO 票行。

**承载（`composite_type_name` 驱动链）**：`build_dwarf_die_table` 一次
`.debug_info` 全量走查建节（DIE 身份 = `(unit 基偏移, unit 相对偏移)`，等价
Java 节全局 `DebugInfoEntry.getOffset()`，DebugInfoEntry.java:162；`type_refs`
保 `indexDIEATypeRefs`（DWARFProgram.java:375-385）的插入序 = 走查序）；
`struct_layout_fingerprint` 逐字承载指纹（成员过滤 `DW_TAG_member|DW_TAG_inheritance`、
`DW_AT_external` 跳过、`UNNAMED_MEMBER_<count>`、`parseDataMemberOffset` 语义
（DIEAggregate.java:613-637，数值/表达式形态、越界回 0））；
`referring_member_field_names` 承载 `_for_` 后缀（异父中止回 ""、未名成员
`<parentName>_<positionInParent(x->true)>`，DWARFProgram.java:1472-1490）；
`ensure_safe_name_length` 承载 2000 字符钳（SymbolUtilities.java:35 +
`NAME_HASH_REPLACEMENT_SIZE=8+2+2`，DWARFProgram.java:63-64）——指纹拼写本身
在 :674 提前返回不过钳，与 Java 一致。`resolve_type_inner`/`shallow_type`
无名臂改走该链；**有名**回边投影保持历史占位拼写（语料见证均由 typedef
物化层重命名，不动）。

**保守降级两处（铁律 1.5，恢复路径已注明）**：①`:650-656` 单入边 typedef
偷名不承载——Rugra 以 `materialized_alias` 把 typedef 物化为改名克隆（无
`TypeTypedef` 变体，type.hh:431），偷名的端到端效果已由别名层承载；指纹名
对该路径不可见（curl 4 例 0xa77/0xaa7/0x4952/0x4982 唯一入边即 typedef，
全 DAG 无回边投影）。②匿名 enum 保持 `enum_<offset>` 拼写，不承载
`anon_enum_<bits>`（:684-686→:771-774）——Java 里匿名 enum 终名同样来自
typedef 偷名，二者不可分；无偷名时共享 `anon_enum_32` 会在名键工厂里合并
不同 enum 的值表（实测 HTTPREQ_* 渲染成 TIMECOND_*，+40 canon 行）。
零语料面（无匿名 enum 名进输出）；随 `TypeTypedef` 落地一并恢复。

**语料事实（readelf 亲测）**：curl 12 个匿名复合体（8 指纹路径 + 4 typedef
路径），`DW_AT_data_member_location` 全常数形态（196 处零 exprloc）、类型引用
全 `DW_FORM_ref4`（零跨 CU）；httpd/vsh stripped 零 DWARF；sq 40 个匿名复合体
（多数 typedef 路径）。CU1/CU2 同源 union 指纹相同（布局键名，Java 语义）→
名键工厂合一，与 Ghidra 类型管理器去重一致。

## 2026-09-25：OUTSTRUCT-ID0 命名类型注册修复（C4 STRUCT-SEED 通道前置）

**根因（`find_by_name` 对直接命名复合体恒 None）**：`intern_named` 对 id=0 候选
恒失效——`base_type`/`struct_type`/`union_type`/`enum_type` 构造时 `TypeBase id=0`，
`TypeFactory::find_add` 拒绝零 id（type.cc:3417-3425 "Datatype must have a valid
id"），`intern_imported` Err 后静默返回**未注册**候选：直接命名的 DWARF 复合体
（`OutStruct`/`stat`/`LongShort`/`ProgressData`）从不进名树——HashMap 消费者
（libc 签名表 type_names）无感，但任何名树解析（`find_by_name`）恒 None。typedef
路径（`alias_type`）因显式 `hash_name` 而一直正常（`FILE`/`URLGlob` 可解析）。
**修复（2 处）**：①`intern_named` 在注册前按 oracle 传输规则补 id：
`id = hashName(name)`（type.cc:675-676 `Datatype::decodeBasic` "There must be
some kind of id"）；零尺寸（`DW_AT_declaration` 不完整复合体）候选保持未注册
课程——Ghidra 的 DWARF 前端从不把不完整复合体喂给 `findAdd`
（`getPrimitiveAlignSize(0)` 对默认对齐表零项取模即除零，type.cc:3429-3437）。
②`parse_c_type` 的 `other` 臂在 bail 前先查共享工厂名树——Ghidra C 解析器对
TYPE_NAME token 的 `glb->types->findByName` 镜像（grammar.cc:2989）；工厂名树由
驱动无条件 `parse_type_names` DWARF 导入填充，签名路径与种子路径同一身份域。
**行为影响（身份统一，无门禁启用即发生）**：直接命名复合体现在真正驻留——
同型分组/指针恒等比较生效；curl 默认 1099→1096（main −1、getparameter −2，
零回退；W1b/C2DWARF 见证基线随之移 3 行，见 Differential 归因）；mirror 五投影
新鲜复跑 next_url/getparameter **MATCH**（97,466 行投影体逐字节=冻结银行，仅
META producer 行异）。C4 STRUCT-SEED 通道（RUGRA_STRUCTSEED 门）依赖本修复：
`OutStruct`/`stat` 等拼写经名树解析为带字段复合体。


## 2026-09-24：GLIBC-PROTO-PARAMNAME-0001 签名类型工厂驻留（libc + DWARF 剩余碎片点）

**根因（curl main 48 行 glibc 参数名族）**：canon headless（12.0.4/12.1.2 双证）在
`ActionNameVars::lookForFuncParamNames`（coreaction.cc:2853-2897）只给
`numMergeClasses==1` 的未命名局部挂 libc/DWARF 形参名（coreaction.cc:2887
`high->getNumMergeClasses() > 1` 挡板）；多区复用的指针临时在 canon 里被
`ActionMergeType`→`Merge::mergeLinear`（coreaction.hh:414 → merge.cc:272-292/359-402）
按**类型指针恒等**（merge.cc:387 `ct == high->getType()`）投机合并成多类，从而
**不**继承 `__haystack/__ptr/__filename/__s/nextarg` 之类名字；寄存器常驻单类值
（main 的 R14/R15 FILE*）才得名 `__stream/__stream_00`。Rugra 侧
`parse_c_type`（libc 24 表）此前**每次 `Arc::new` 裸铸**类型，per-call-site 身份
碎片化使同型分组无法成组 → 临时恒单类 → 被过命名（main 多 4 名 48 行；
`nextarg` 为 DWARF callee 同病）。**修复（本文件 3 处 + curl 驱动 1 处）**：
①`parse_c_type` 全面走 `TypeFactory::shared_default()`——基础拼写按
`find_by_name` 名树（grammar.cc:2989 lexer TYPE_NAME 规则的镜像），未命中经
`factory_named_base`→`get_base_named`（findAdd 驻留，type.cc:3412），指针层走
`get_type_pointer` 3 参匿名重载（grammar.cc:2402-2411 PointerModifier::modType →
type.cc:3867-3875）；②`void_type` 改 `get_type_void()` 单例；③`dwarf_base_type`
的 char 臂改经 `intern_named` 名驻留（DWARF char = 工厂 char 同一对象）；
④curl 驱动 `build_worker_architecture` 的 cspec data_organization 解码目标由
per-process 裸工厂改为 `shared_default()` 单例——与 `Architecture::ensure_types`
既有的"canonical headless-oracle factory"口径合一，使管线推断/libc 签名/DWARF
三通道共享一个身份域（Ghidra 每 Architecture 恰一个 TypeFactory，
type.cc:3106）。**验收**：curl main 只剩 canon 同款 `__stream/__stream_00`；
curl E2E 1740→**1561**/0/0、httpd **1698**/0/0、五投影 MATCH×5、双跑恒等。
**移交**：`MERGE-SAMETYPE-COVER-PARITY-0001`（my_get_line +33/glob_range +7
编号级联与 file2string/parseconfig 欠命名 = merge 覆盖粒度分歧双向残差，
merge 域）。


## 2026-09-22：VARGROUP-ABSORB-0001 车道探针剥离（无 API 变更）

剥离车道私有 `[DBG]` 诊断探针（wip 1cd9f682/d3755452 声明的临时探针清单含本文件），
源码恢复至车道 f7348207 状态（与 merge-base 36f26db3 同树）。探针结论已记录于
`docs/alignment_docs/VARGROUP_ABSORB_MECHANISM_2026-09-22.md`，无接口/语义变化。


## 2026-09-22：DWARF 类型工厂驻留（HERITAGE-PROMOTE-SYMBOLTAIL-0001 配套）

`base_type`/`struct_type`/`union_type`/`enum_type`/`alias_type` 的产物与
`pointer_type` 此前每次 `Arc::new` 裸建，不进共享 `TypeFactory`。Ghidra 的
DWARF analyzer 把每个 DIE 类型解析进 Architecture 的**唯一** TypeFactory
（type.cc findByName/setName 驻留），所以两个 DWARF 通道（globals 的
`DebugGlobalDatabase` 与原型的 `DebugPrototypeDatabase`）看到的同名结构是**同一**
interned 对象——指针恒等比较（`CastStrategyC::castStandard` 的
`curtype == reqtype`，cast.cc:299；ActionSetCasts 的 store-value cast，
coreaction.cc:553-554）判定相等、免 cast。Rugra 双通道各自裸建时，
`*glob = glob_expand;`（`URLGlob**` 形参 vs typelocked `URLGlob*` 全局读）多出
伪 `(URLGlob *)` cast（glob_url 4→6）。修复：`intern_named` 软驻留——共享工厂
按名命中且**枚举变体/size/metatype 全同**时复用既有 Arc（形状守卫使环回
shallow 投影不得遮蔽同名字段的完整定义），未命中时经新
`TypeFactory::intern_imported`（find_add 包装，type.cc:3390 导入边界）注册；
`pointer_type` 走 `get_type_pointer`（pointee 已驻留后结构去重生效）。

`src/debugproto.rs` implements Rugra's native equivalent of Ghidra's
pre-decompiler debug-import boundary. Ghidra's DWARF analyzer writes declared
function prototypes into the Program database; the C++ decompiler subsequently
receives a locked `FuncProto`. Rugra now parses concrete ELF DWARF subprograms,
follows `DW_AT_abstract_origin` / `DW_AT_specification`, preserves formal
parameter order, names, resolved scalar/pointer types and varargs, asks the
bound compiler model to assign register or stack storage, and locks
input/output/model state before Actions run. The current production evidence
is scoped to the locked `x86-64-gcc.cspec`; it is not a generic ABI claim.

It also imports DWARF global variables (`DWARF-TYPE-IMPORT-0001`):
`DebugGlobalDatabase::parse_elf` walks `DW_TAG_variable` DIEs whose
`DW_AT_location` is exactly `DW_OP_addr <addr>` and records each global's
storage address, name, and resolved data type. `address_pointer_map` projects
those globals into the `Funcdata::global_struct_ptrs` seeding form: the type
of an address constant that references the global, i.e. a pointer to the
declared variable type with C array decay (0x17660 `glob_expand` →
`URLGlob **`, 0x17520 `config` → `Configurable *`, 0x17680 `glob_buffer`
→ `char *`).

Function-statics — `DW_TAG_variable` nested inside a `DW_TAG_subprogram` —
carry the enclosing function's name in `DebugGlobalVariable::
parent_function` (gimli's `next_dfs` yields a depth DELTA per entry, so the
absolute level is accumulated before the scope stack pops; misreading the
delta as the absolute level used to drop the subprogram frame and flatten
every static to a bare name — `CURLCANON-DBSYM-DUP-RAWNAME-0001`). The
driver renders those as `<parent>::<name>` spellings in both the Program-DB
DWARF layer and the name-proxy overlay: locked witnesses
`my_get_token::save` @0x17510 and `next_url::beenhere` @0x17518
(`ghidra_curl_1204.c:1226+`).

`DebugGlobalDatabase::seed_global_locked` (`GLOBWORD-C5-GLOBAL-TYPEFLOW-0001`)
is the driver-side projection of the DWARF front end's committed-data-type
semantic: Ghidra's analyzer creates Data with a locked-in type, the decompiler
interface exports it as ATTRIB_TYPELOCK, and `Symbol::decodeHeader`
(database.cc:439-442) folds it into the Symbol's typelock flag. It seeds one
global into the query-channel `Database` (`add_symbol_mapped` + TYPELOCK).
Both typelock-gated consumers — `SymbolEntry::updateType` (database.cc:135-141,
reached through `Varnode::setSymbolProperties` varnode.cc:413) and
`ActionInferTypes::buildLocaltypes`' exact-piece branch (coreaction.cc:5021-
5027) — depend on the flag to attach the global Symbol's DWARF type onto the
address varnode `RuleLoadVarnode` materializes (ruleaction.cc:4293). Without
it the global's value degrades to raw offsets in the C output
(`*(int *)(glob_expand + 0x128)` instead of `glob_expand->size`).

## Locked libc ABI signatures (`CALLSPEC-DRIVER-0001`)

`LibcSignatureTable` is Rugra's native front-end adapter for the platform-side
signature data Ghidra ships as generic_clib: the decompile/cpp code never
parses these declarations — the Program database holds the locked `FuncProto`
for each EXTERNAL symbol, `FlowInfo::queryCall` (flow.cc:656-672) associates
the call site with it, and `ActionDefaultParams` (coreaction.cc:2322-2330)
copies the prototype onto the call site. The table encodes the same 24 public
glibc ABI declarations verbatim (glibc reserved `__`-prefixed parameter names
included) that back the external-stub rendering
(`EXTERNAL-STUB-SUPPORT-0001`).

- `LibcSignatureTable::lookup(name)` — the signature record for an imported
  symbol, `None` for anything else (unknown imports stay unlocked).
- `LibcSignatureTable::empty()` — bare-load constructor
  (RUGRA-FLOW-MIRROR-0001 M3): an empty table whose every lookup misses,
  reproducing the raw-BFD load environment of the oracle single-function
  harness (BfdArchitecture + readLoaderSymbols carry no generic_clib
  signature data; ACTIVEPARAM-COUNT-9V2-0001 RCA-1). The curl driver
  selects it under `RUGRA_BARE_LOAD=1`; default construction keeps the full
  locked ledger.
- `LibcSignatureTable::locked_proto(name, model_carrier, type_names)` — builds
  a clean callee `FuncProto` that shares the carrier's resolved model, then
  routes the declared types through `FuncProto::setPieces` and that model's
  `assignParameterStorage`. Input, output, and model are all locked. Returns
  `Ok(None)` for unknown imports and `Err` when the compiler model cannot
  assign the prototype. A seventh scalar input can therefore spill to stack;
  aggregate/ModelRule and non-x86 behavior remain unproved.
  Every materialized parameter additionally carries
  `protoparam_flags::NAME_LOCKED` (2026-08-25,
  COREACTION-FUNCPARAMNAMES-RECOMMEND-0001): the platform-side signature
  decode reads ATTRIB_NAMELOCK into `ParameterPieces::namelock`
  (fspec.cc:3503-3506) and `FuncProto::decode` propagates it via
  `curparam->setNameLock(...)` (fspec.cc:3564) — the bit
  `ActionNameVars::lookForFuncParamNames` gates recommendations on
  (coreaction.cc:2818 `param->isNameLocked()`), which names call-site
  variables after locked callee parameter names (`strtol` → `__nptr`).

### The two FILE type domains (`GLIBC-CLIB-FILE-TYPEDOMAIN-0001`,
### 2026-09-27, CANON-VARNAM-NAMEREC-TIEBREAK-0001)

The locked curl canon golden proves the oracle's type graph carried TWO FILE
structures that never unified:

- the **generic_clib_64 archive FILE** behind every locked libc prototype
  (fclose/fgets/fwrite/fputc/fileno params, fopen return) and the extern
  std-stream globals (stdin/stdout/stderr) — struct layout is the glibc
  compat form, 29 fields / 216 bytes, with the offset-152..176 slots named
  `__pad1..__pad4` (extracted from the locked oracle tree's own
  `Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt`);
- curl's **DWARF FILE** (typedef FILE → struct _IO_FILE — same 29 slots,
  offsets 152..176 named `_codecvt/_wide_data/_freeres_list/_freeres_buf`
  per the binary's .debug_info) behind DWARF subprogram prototypes and
  struct fields.

Both print `FILE *`, but they are distinct Datatype objects, and two
observable oracle behaviors depend on the split:

1. `ActionNameVars::lookForFuncParamNames`' repeat-recommendation tie-break
   (coreaction.cc:2833-2845): parseconfig's FILE\* local gets `fp`
   (my_get_line's DWARF FILE\*, inserted first in callspec order), then
   `__stream` (fclose's archive FILE\*) — `TypeStruct::compare`
   (type.cc:1742-1780) walks offset/name/metatype per field and returns +1
   at the FIRST field-name difference (offset 152: `_codecvt` > `__pad1`
   string-wise), so the archive recommendation OVERRIDES and the golden
   names the local `__stream` (a single-FILE model ties at typeOrder 0 and
   keeps `fp`).
2. `ActionSetCasts`' call-argument casts: `castStandard` strips typedefs and
   compares the pointee structs BY IDENTITY (cast.cc:325), so the split
   produces exactly the golden's `(FILE *)` casts at the domain-crossing
   call sites (ghidra_curl_1204.c:1300 `my_get_line((FILE *)__stream)`)
   and bare args where both sides live in one domain
   (`fclose(__stream)`, `fwrite(...,stderr)`).

Rugra models the split with:

- `clib_file_types()` — a process-wide OnceLock holding the archive FILE
  struct (deliberately NOT registered in the factory name tree — the "FILE"
  name slot belongs to the DWARF materialized alias, and `intern_named`'s
  (name, shape, size, metatype) dedupe would collapse the domains) plus its
  factory-interned pointer (one stable TypePointer identity per domain for
  `ActionMergeType`'s same-type grouping). The cache must be warmed outside
  any factory-lock scope (init interns through the factory write lock;
  `DebugGlobalDatabase::parse_elf` warms it first thing because the DWARF
  walk holds that lock across its unit loop).
- `libc_type_resolution_index(type_names)` — the base-spelling map
  `locked_proto` parses every ledger spelling through: the DWARF
  named-type index with `FILE` overridden to the archive struct (`size_t`
  and every other spelling keeps the DWARF resolution; `stat` joins the
  override list below).
- `remap_external_clib_file_pointer` (inside `DebugGlobalDatabase::parse_elf`)
  — extern FILE\* declarations (stdin/stdout/stderr) enter the archive
  domain; subprogram parameters and struct fields keep the DWARF FILE.

httpd is unaffected: its driver resolves its own import ledger through
`resolve_import_type`/the census interner (one FILE domain — the binary is
stripped, no DWARF competitor), and the httpd canon face is byte-stable
across this change. The mirror faces are bare-load (no libc ledger, no
DWARF seeds) and equally unaffected.

### The archive stat domain (`CURLCANON-CASTA-STAT-0001`, 2026-09-28)

The locked golden's `__xstat` call sites prove the same two-domain split
for `stat` (PROTOCAST43 §③ root R1): golden prints
`__xstat(1,x,(stat *)&fileinfo)` (main:797/:878, getparameter:2105) — the
signature's `stat *` and the local's DWARF `stat *` are distinct objects,
so `castStandard`'s pointer-identity early-exits (cast.cc:304/:329) do not
fire and the struct default arm (:387) casts. Rugra resolved the ledger's
`stat` spelling through the DWARF name index, collapsing signature param
and local to one interned object (`&fileinfo`, no cast). The fix follows
the FILE precedent verbatim:

- `clib_stat_types()` — a process-wide OnceLock holding the archive stat
  struct (glibc x86-64 bits/stat.h, 144 bytes / 15 fields:
  st_dev@0 .. __glibc_reserved[3]@120, the ABI form curl's own DWARF
  `<444>` struct stat carries) plus its factory-interned pointer. Built
  standalone (never name-interned), so the DWARF `stat` (interned by
  `struct_type`) and the archive `stat` stay distinct objects;
  `TypeStruct::compare` (type.cc:1742-1780) orders the equal-shape pair
  by object id — the tie the locked oracle's own two same-header-derived
  stat objects also hold.
- `libc_type_resolution_index` now overrides `stat` alongside `FILE`;
  every other spelling keeps the DWARF resolution.

canon curl moved 110→95 (−15) with the three `(stat *)` sites converged
plus main's line reflow back to the golden wrap; httpd byte-stable.

### DWARF cv-qualifier strip (`CURLCANON-CASTA-CONST-0001`, 2026-09-28)

The locked goldens carry ZERO `const`/`volatile`/`restrict` tokens across
all six corpora (curl 11.3.2/1204, httpd, sq, sqlite, vsh): the oracle's
DWARF front end drops qualifier wrappers at import. my_get_token's DWARF
`const char *` param chain (0x3ca ptr → 0x186 const → char,
readelf-verified) prints as `char * my_get_token(char *line)` with
`(char *)0x0` constant casts (golden :1213/:1226/:1603). Rugra's
`resolve_type` used to mint an `alias_type("const char", char)` — an
independent qualifier object as the prototype's req, printing
`const char *` signatures and `(const char *)0x0` casts. The qualifier
arm now strips to the underlying type (a qualifier DIE with no
`DW_AT_type` is cv-qualified void → the canonical `void_type()`); corpus
witnesses: the dead glibc `memcpy` decl chain (restrict→ptr→const-void)
and curl's 10 const / 7 restrict DIEs, none of which reach output.

Supporting parsers: `split_parameter_list` / `split_declaration` split the
comma-separated `TYPE NAME` declarations (the trailing identifier run is the
name, pointer stars belong to the type: `void *__ptr`), and `parse_c_type`
maps the C spellings (`void`, `char`, `int`, `long`, `size_t`, `time_t`,
`ushort`, opaque base names, pointer layers) onto `Datatype` metatype/size
pairs. Unit tests cover the 24-entry table, SYSV storage assignment
(`free`→RDI void*, `strtol`→RDI/RSI/RDX, `__ctype_b_loc`→locked void input,
`ushort **` return), and the unknown-import unlock path.

## Type resolution

`resolve_type` materializes the DWARF type graph into `Datatype` objects:

- base types resolve in the locked analyzer's order
  (DEBUGPROTO-DWARF-BASENAME-0001, 2026-09-26): a `DW_AT_name` spelling a
  standard C alias (`long int`, `short int`, `unsigned int`, `long long
  int`, …) first hits the alias table
  (DWARFDataTypeManager.java:477-549 initBaseDataTypes, consulted at
  :403 in getBaseType) — when the canonical type's dataOrganization size
  equals `DW_AT_byte_size` and the encoding is compatible
  (isEncodingCompatible :359-369: `DW_ATE_signed` rejects unsigned
  canonicals, `DW_ATE_unsigned` rejects signed ones, everything else
  passes), the canonical Program type is returned DIRECTLY with no typedef
  wrap, so DWARF `long int` (8, signed) IS the cspec `long` and casts print
  `(long)` (12.0.4 golden: `(long)` 55x curl / 1165x httpd, `long int` zero
  occurrences). Factory-present canonicals (`char`/`short`/`ushort`/`int`/
  `uint`/`long`/`ulong`/`float`/`double`/`longdouble`/`bool`/`wchar_t`/
  `undefined1`) intern onto the factory's same-named core entry
  (TypeFactory::findAdd, type.cc:3412-3425) — one object with the
  signature-data `long`, so identical-type casts disappear;
  `uchar`/`longlong`/`ulonglong` are Java-DTM-only names (the C++
  coretypes stream's same-size longlong slot is overwritten by `long`),
  interning as named non-core types exactly as the database transport
  delivers them. The locked analyzer's character distinction is also
  retained: the `DW_ATE_signed_char` fallback (for names outside the alias
  table) becomes a `CHARTYPE`/`SUB_INT_CHAR` datatype, while
  `DW_ATE_unsigned_char` resolves through the alias table to the ordinary
  unsigned `uchar` type; every other name keeps its DWARF spelling (the
  typedef-wrap arm — Rugra materializes typedefs as the renamed underlying
  type);
- pointers/references build `Datatype::Pointer` with the pointee's spelling
  (`URLGlob *`, and `URLGlob **` for pointer-to-pointer);
- `DW_TAG_structure_type`/`DW_TAG_union_type` build fielded
  `Datatype::Struct`/`Datatype::Union` from `DW_TAG_member` children (name,
  `DW_AT_data_member_location` constant or `DW_OP_plus_uconst`, resolved
  member type) — named by `DW_AT_name` without a `struct `/`union ` prefix,
  which is the spelling Ghidra's type manager prints (`Configurable *`,
  matching the 12.0.4 golden). Imported unions carry the
  `NEEDS_RESOLUTION` flag (COREACT-C3-UNIONRES-0001, 2026-09-25):
  Ghidra's `TypeUnion` constructor sets `needs_resolution` on every
  instance (type.hh:551) and pointers to the union inherit it in
  `TypePointer::calcSubmeta` (type.cc:1048-1049) — the flag is what drives
  `ActionInferTypes::propagateTypeEdge`'s always-resolve arm
  (coreaction.cc:5081-5084) and `ActionSetCasts::resolveUnion`
  (coreaction.cc:2490); the DWARF import completes fields at construction,
  so only the resolution flag is set (`type_incomplete` is cleared by the
  factory's setFields counterpart, exactly as the ctor+setFields decode
  path in the oracle). Same flagging pattern as the enum `ENUMTYPE` note
  above;
- `DW_TAG_enumeration_type` builds `TypeEnum` with its `DW_TAG_enumerator`
  value table;
- `DW_TAG_array_type` builds `Datatype::Array` from the first subrange's
  `DW_AT_count`/`DW_AT_upper_bound`+1 (`char *[10]`, `URLPattern[9]`);
- typedefs/qualifiers clone and rename the complete resolved datatype instead
  of reducing it to a base `(size, metatype)` pair. This preserves character
  flags/submeta and pointer/array/composite shape. Rugra still has no
  `TypeTypedef` variant or importer-side TypeFactory registry identity;
  **exception（PRINTC-BOOLLITERAL-0001, 2026-09-24）**: the conventional
  boolean typedef names (`bool`/`_Bool`, 1-byte underlying) short-circuit to
  the factory's core `bool` via `TypeFactory::dwarf_conventional_bool`
  (docs/api/type_system/typefactory.md) — mirroring Ghidra's DWARF front end
  mapping `typedef char bool` (curl.h line 394) to its boolean primitive, the
  identity behind the canonical golden's `true`/`false` constant prints on
  typedef-bool fields (`::config.showerror = true;` /
  `::config.progressmode = (bool)(::config.progressmode ^ 1);`) via
  `ActionSetCasts::castInput`'s constant absorption (coreaction.cc:2687-2691)
  and `PrintC::pushConstant`'s TYPE_BOOL arm (printc.cc:1769-1771). Known
  residual of the same family: plain-`char` fields (`config.remotefile`) and
  `bool[N]` stack arrays in the canonical golden come from the Java-headless
  analyzer layer (Data Type Propagation), which has no decompiler-library
  counterpart — the library-level direct-runner golden prints `'\0'`/`'\x01'`
  for those same stores;
- recursive type graphs (`FILE` → `struct _IO_FILE` → `_chain FILE *`) break
  at the back edge with a shallow named projection (name/size/metatype, no
  fields), mirroring how Ghidra's two-phase type manager exposes an
  already-created type before its members are filled.

This is the first `DWARF-PROTO-0001` closure, not a claim of complete DWARF or
prototype recovery. Cross-compilation-unit references, location-list state,
aggregate ModelRules, split DWARF and non-x86 compiler specs remain explicitly
unsupported. Scalar stack parameters are now assigned by the bound model, but
that narrow result does not prove aggregate/join/hidden-return behavior.
Stripped-binary inference remains
`PARAM-RECOVERY-0001`. The module and signature pipeline therefore remain L2.

The current curl regression input has SHA-256
`4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a`.
Rust-side import tests cover `GetStr` (2 fixed parameters), `myprogress` (5),
`helpf` (1 plus varargs), the optimized `getparameter` definition (4 via
`DW_AT_abstract_origin`), locked zero-input `hugehelp`, and the DWARF
globals of the curl fixture (`config`, `save`, `beenhere`, `glob_buffer`,
`glob_expand`, plus the copy-relocation externals `stdout`/`stdin`/`stderr`
with their FILE* declaration types) including the `URLGlob` 304-byte layout
(literal char*[10] @0, pattern URLPattern[9] @80, size int @296) and the
`&global` pointer map.
This is useful regression evidence, but it is not a complete Ghidra
DWARF-analyzer oracle fixture; the importer remains `NO_ORACLE` under mechanism
B2. A fresh production GetStr differential does prove the resulting visible
character-token projection (`*value != '\0'`) against the locked 12.0.4 golden;
it does not prove the importer state or factory-identity closure.

#### 会话状态（2026-08-16）
本 session 在此文件对应的 `src/debugproto.rs` 上落地了
`CALLSPEC-DRIVER-0001`（`LibcSignatureTable` 24 条 glibc ABI 签名 + 按入口地址
解析调用目标）与 DWARF 全局变量类型图（`address_pointer_map` 投影，见上文
`DWARF-TYPE-IMPORT-0001` 段落）。两者均为 front-end 适配层：Ghidra 对应行为
发生在 Program 数据库与 analyzer 侧，decompile/cpp 内无逐行对应物，因此标注为
`RUGRA-GLUE` 类桥接，不参与机制 C 核心白名单。端到端效果由
`result/curl_cur.c` 对 `tests/golden/ghidra_curl_1204.c` 的差分门禁回归
（`FUN_0` → `free`/`strdup` 调用解析与全局类型指针化在本 session 达到
byte-stable）。

## 2026-08-28：零参数不改变调用约定模型

### `DebugPrototypeDatabase::apply` 的模型状态（fspec.cc:4690-4698/4776）

锁定的 Program-database 签名经 `FuncProto::decode` 进入反编译器：ATTRIB_MODEL
携带平台侧调用约定名，无法识别的名字走 `createUnknownModel`
（fspec.cc:4697 → architecture.cc:1159-1166），得到克隆 defaultfp 行为、
`isUnknown()=true`、且名字 "unknown" 不打印进声明的 `UnknownProtoModel`；
空参列表的 voidlock 置位 modellock（fspec.cc:4776）。

旧实现按 `parameters.is_empty()` 强制写入 `unknown`，这不是 Ghidra 机制，现已
删除。Program database 编码的 `ATTRIB_MODEL` 决定是否创建
`UnknownProtoModel`；`voidinputlock` 只锁定空输入列表，不替换已经绑定的模型。
因此零参数和带参数原型都保留 `model_carrier` 的共享模型身份。

对应回归测试改为 `void_signature_dwarf_prototype_keeps_bound_model`。真正显式
unknown 模型的 warning 仍由 coreaction 的独立测试覆盖；本适配层没有真实
Program database 双侧 fixture，整体继续是 `NO_ORACLE` / L2。

## 2026-08-25：COREACTION-FUNCPARAMNAMES-RECOMMEND-0001 — 锁定签名的参数名锁位

### `NAME_LOCKED` 在两个 front-end 适配层的落位（fspec.cc:3564）

Ghidra 的锁定签名经 `FuncProto::decode` 进入反编译器时，每个 `<param>` 的
ATTRIB_NAMELOCK 置 `ParameterPieces::namelock`（fspec.cc:3503-3506），
`curparam->setNameLock((pieces[i].flags & namelock)!=0)`（fspec.cc:3564）把它
落到 `ProtoParameter` 上。`ActionNameVars::lookForFuncParamNames`
（coreaction.cc:2858-2897）推荐命名的第一道门禁就是
`param->isNameLocked()`（coreaction.cc:2818，经 `makeRec`）——没有该位，
strtol 的 `__nptr`/strstr 的 `__haystack` 永远不会推荐到调用点变量。

Rugra 此前 `ProtoParameter::new` 恒 `flags: 0`，两个适配层都只靠
`set_input_lock(true)` 置 TYPE_LOCKED，NAME_LOCKED 全程缺失，推荐链断在
数据侧（coreaction.rs 的 lookForFuncParamNames 内联实现本身已齐全）。修复：

- **`LibcSignatureTable::locked_proto`**：每个物化参数置 NAME_LOCKED
  （generic_clib 签名数据全部带真名，`split_declaration` 拒绝无名声明）。
- **`DebugPrototypeDatabase::apply`**：仅 DWARF 真实 `DW_AT_name` 参数置
  NAME_LOCK；无名 DIE 的 `param_N` 合成名不锁（Ghidra 侧无名 DIE 保持未命名、
  由 buildDefaultName 接管；lookForFuncParamNames 另有 `param_` 前缀过滤，
  coreaction.cc:2831）。

### 端到端效果（curl 12.0.4 golden 差分）

- `progressbarinit` 的 strtol 调用点变量 `extraout_RAX` → `__nptr`
  （golden 同名，函数级 defects=0/numbering=0）。
- 全量 124 函数：13 个函数获得推荐命名（`__s`/`__dest`/`__ptr`/`__n`/
  `__nptr`/`__stream`/`__haystack`/`__filename`，即 golden 中 fwrite/fgets/
  strcat/strcpy/free/realloc/fopen/strstr/strtol 的锁定参数名），
  skeleton 差异 2863 → 2849（-14），defects=0、numbering=0 保持。
  其余 skeleton 差异均为独立既有缺口（curl_getenv 赋值语句缺失、"COLUMNS"
  字符串引用、char* cast 传播等）。

## 2026-08-25：CALLSPEC-ENV-SCOPE-0001 — DWARF 签名链接到调用点（queryCall→copy 边界）

### 缺口

`DebugPrototypeDatabase::apply` 只把 DWARF 签名锁到**被反编译函数自身**的
`fd.funcp`；调用点的 105 个 callspec 里只有 24 个 generic_clib 导入拿到锁定
原型（`LibcSignatureTable`），其余 81 个（curl 内部函数：glob_url/
getparameter/parseconfig/match_url 等）在 flow 期保持 `fd.funcp.clone()`
（flow.rs:1390，Ghidra 的 `FuncCallSpecs` ctor 克隆 default 而非调用者）。
headless golden 的环境里这些 callee 的 DWARF 签名被 analyzer 锁进 Program
数据库，`FlowInfo::queryCall`（flow.cc:656-672）解析 callee `Funcdata`，
`ActionDefaultParams`（coreaction.cc:2322-2330）`fc->copy(otherfunc->
getFuncProto())` 把整份 callee 原型（model + 全部锁位 + 参数 store 的 clone，
`FuncProto::copy` fspec.cc:3789-3804）复制到调用点——这是 golden main
`glob_url(&urls,pcVar12,&urlnum)`（3 参）与 `curl_version()`（0 参）的来源。

### 落地

- `DebugPrototypeDatabase::locked_callsite_proto(entry, model_carrier)`：同一
  Program-数据库边界的调用点半边。`model_carrier` 提供模型
  ——与 callee 自身 `Funcdata` 绑定的 Architecture defaultfp 相同（driver 传
  `fd.funcp`，FUNCPROTO-MODEL-BIND-0001 的 set_arch 绑定后）。锁配方与
  `apply` 完全一致（共享 `locked_proto` 构建器，fspec.cc:3843-3852 setPieces
  语义）：模型驱动的存储、DW_AT_name 才 NAME_LOCKED、input/output/model
  三锁，且参数数量不改写模型。`Ok(None)` = 该地址无 DWARF 定义（thunk/
  导入：generic_clib 表或 active recovery 负责）。
- driver `link_call_specs`：libc 表未命中（thunk 地址无 DWARF 定义、DWARF
  函数名不在 24 条导入表内——两源按构造不相交）后查 DWARF，命中即整体替换
  callspec `prototype`。`[PREPASS]` 日志新增 locked DWARF signatures 计数。

### 可观察效果与边界（诚实账）

- main：`extraout_var` 声明位次变化（14 个 DWARF 锁定 callee 的 output_type
  _locked 改变了 funcLinkOutput 的锁定路径与 active-output trial 集合）。
  **调用实参个数不变**：`curl_version(lVar50,in_RDX,argv,argc,in_R8,in_R9)`
  仍 6 个试验参数——实参个数由 CALL op 的 input varnodes 决定
  （printc opCall 按 `op->numInput()-1` 渲染，printc.cc:610-624）。
  `ActionFuncLink::func_link_input` 现读取锁定原型参数并使用模型分配的
  register/stack 存储，不再读取硬编码 ABI 表；后续 trial commit/trim 路径仍
  有独立残差。
- aggregate/join/hidden-return 参数仍受未移植 ModelRules、TypeFactory identity
  与完整 Address 身份约束；不能从 scalar stack case 外推。

## parse_type_names：DWARF 命名类型索引（2026-08-26）

`parse_type_names`（RUGRA-GLUE，Program-import 边界）：遍历 DWARF 单元的
structure/union/enumeration/typedef/base_type DIE 建立名字→类型索引，供
`LibcSignatureTable::locked_proto` 解析签名基础拼写（如 `FILE`）。Ghidra 侧
由 DWARF analyzer 填充 program type manager；重复名首见优先（锁定 curl
语料无冲突）。

## 2026-09-23：DWARF-SYMFIELD-TYPESTATE-0001 — typedef 拼写与 copy-reloc 外部符号

两处 DWARF 前端类型态修复（锁定输入 `examples/curl`，oracle
`ghidra_curl_1204.c` main 行为证据）：

1. **typedef 拼写保留**（`parse_type_names`）：`DW_TAG_typedef` 条目此前直接
   解析 `DW_AT_type` 目标，索引里 `FILE` 落成底层 `struct _IO_FILE`
   （216B）——所有 libc 签名与 cast 随之打印 `_IO_FILE *`。现在 typedef 条目
   经 `resolve_type` 的 typedef 分支物化为**改名为 typedef 拼写**的底层类型
   （Ghidra 侧 TypeTypedef type.hh:522 保名语义），`type_names["FILE"]` 为
   名为 `FILE` 的 216B struct，`_IO_FILE` 仍以原名共存。golden 证据：
   `FILE *__stream` 声明、`(FILE *)0x0` cast、`int fclose(FILE *__stream)`。
2. **copy-reloc 外部符号导入**（`DebugGlobalDatabase::parse_elf`）：DWARF 中
   `stdout/stdin/stderr` 只有 `DW_AT_declaration`（无 `DW_AT_location`），
   此前被 located-global 循环跳过，驱动侧 ELF 回退把它们种成匿名
   `undefined *`，符号名带 `@@GLIBC_2.2.5` 后缀。现在 walk 期间收集
   external 声明（`DW_AT_declaration`+`DW_AT_external`+`DW_AT_type`，名字
   首见优先），walk 后用 goblin 枚举 `R_X86_64_COPY` 重定位目标
   （`copy_reloc_object_symbols`，STT_OBJECT、剥 `@@VERSION`），按地址种入
   globals（located globals 仍优先）。curl 语料受影响集合恰为
   {stdout@0x174e0, stdin@0x174f0, stderr@0x17500}，类型 = 指向统一 `FILE`
   的指针（与 `type_names["FILE"]` 同一 Arc 身份）。httpd 无 DWARF FILE
   typedef/声明，路径惰性（globals=0）。

**可见效果**（curl E2E，main）：`__stream = stdin;`/`__stream_00 = stdout;`
裸赋值（原 `(_IO_FILE *)stdout@@GLIBC_2.2.5` cast）、`stdout == (FILE *)0x0`、
`heads.stream = (FILE *)stdout;` field-store cast 重现（golden 896）、全部
`_IO_FILE` 拼写改 `FILE`。三门禁：curl skeleton 2665→**2614**（main
605→583、libc FILE thunk 11→9、my_fwrite 12→4、getparameter 748→743、
helpf 81→77，10 函数改善 0 回退），defects=0/numbering=0；httpd 2331==基线
0/0；next_url/match_url 字节级不变（103/76）。lib 测试 18 失败==已知基线
（预存 flaky 集合）。

**残余**（登记 TODO DWARF-SYMFIELD-TYPESTATE-0001 ②③，不在 debugproto 域）：
`glob.pattern[8].content.Set.elements = (undefined8)in_stack_...fd90` 的
`(char **)` 缺失——Rugra 在该 STORE 插入的是 `union_a49` 8 字节 PartialUnion
cast（`get_exact_piece` union 臂，dump op@0x30d6
`CAST(PartialUnion)=in_stack_fd90`），oracle 经 ScoreUnionFields/
derefPointer 钻取 Set→elements@0 尺寸匹配后 cast 到叶子类型 char**；
`glob._296_8_ = (undefined8)uVar32` 同类（PartialStruct 剩余片）。修复域在
coreaction/unionresolve 的 store-cast 目标选择。

## parse_c_type/split_pointer_depth：嵌套指针归一（2026-08-27）

`split_pointer_depth` 逐星剥离（星 + 前导空格循环），任意间距形式
（`char **`/`char**`/`char * *`）归一到 base+depth；旧
`trim_end_matches(" *")` 剥不掉第二颗星，双指针落入 unknown-name 基臂产出
`Base("char **", TYPE_UNKNOWN)` 而非结构化 Pointer-to-Pointer。
generic_clib 的核心 `char` 现在用字符构造器，
而不是仅名称相同的普通 1-byte `TYPE_INT`；因此 `strdup` 等锁定签名的 pointee
保留 `isCharPrint()`。

## 2026-08-29：PTRSUB-TYPED-DECL-RESIDUAL-0001 — 解析指针改匿名（Ghidra 对齐）

`parse_c_type` 的嵌套指针层与 DWARF 边界的 `pointer_type`/DW_TAG_array_type
数组构建此前给类型附带组合显示名（`"char *"`/`"char **"`/`"char *[10]"`）。
Ghidra 的对应路径（`PointerModifier::modType` → `TypeFactory::getTypePointer`
3-arg，grammar.cc:2403-2411 / type.cc:3867-3875；`getTypeArray` type.cc:3902）
一律构造**匿名**类型——`"char *"` 是语法拼写不是类型身份。组合名使这些指针成为
**命名单层指针**，printc 忠实渲染为 `char * pcVar1`（oracle
printc_anonymous_pointer_decl_1204 named_ptr_contrast），偏离 golden 的匿名
多层钻取形 `char *pcVar1`。现在 `parse_c_type`/`pointer_type`/DWARF 数组均
构造匿名类型（`TypePointer::new`/空名 `TypeArray`），结构断言取代名称断言
（`libc_locked_proto...`/`curl_dwarf_globals...` 等测试已同步）。

## 2026-08-28：DEBUGPROTO-DWARF-CHAR-0001 — GetStr 字符类型边界

锁定输入 `examples/curl`（SHA-256
`8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`）中，
GetStr 的 `value` 参数沿 DWARF DIE `0x28c6 → 0x174 → 0x17f` 指向
`name=char,size=1,DW_ATE_signed_char`。Ghidra 12.0.4 的决定链为：

- `DWARFDataTypeManager.java:397-449` 先按 name/size/encoding compatibility
  查核心类型，再做 encoding fallback；`:426` 选择 `baseDataTypeChar`，`:427`
  明确把 unsigned-char 选择为普通 `baseDataTypeUchar`；
- `PcodeDataTypeManager.java:1180-1200,1238-1253` 为核心 CharDataType 编码
  `char=true`；
- C++ `type.cc:4511-4523` 解码为 factory-owned `TypeChar`，其
  `chartype`/`SUB_INT_CHAR` 使 `isCharPrint()` 为真。

旧 importer 只构造 `TypeBase::new(name,1,TYPE_INT)`，名称虽为 `char`，flags
仍为 0；read-facing 打印路径因此正确地输出了数值 `0`。现在
`dwarf_base_type` 保留 signed-character/core-char 分类，`parse_c_type("char")`
也使用字符构造器，typedef/qualifier clone 保留完整 flags/submeta 和结构形状。

定向 Rust 回归覆盖实际 GetStr DWARF 参数、libc `strdup` pointee，以及
typedef/qualifier 的字符语义与 pointer shape。fresh release 生产路径随后得到：

```c
if ((value != (char *)0x0) && (*value != '\0')) {
```

`compare_ghidra.py --func GetStr -v` 报告 skeleton identical、defects=0、
numbering=0。这个结果只把 GetStr 的最终可见字符投影升为 `MATCH`。完整 importer
仍有明确残差：尚未实现 Java 的全量 name-first base-type 表、Program database
typedef identity、Architecture TypeFactory `findAdd`/canonical cache，以及
signed/unsigned/UTF/非标准 data-organization 的双侧矩阵；状态保持
`NO_ORACLE`/L2。

## 2026-08-28：模型驱动签名存储边界

libc/DWARF producer 已删除手写 SysV resource 表：它们从当前 Architecture 的
model carrier 构造干净 callee prototype，再由 `setPieces` 调用模型的
`assignParameterStorage`。零参数只设置 void input lock，不再凭 arity 制造
UnknownProtoModel；真实参数名才置 NAME_LOCKED。

FuncLink bilateral fixture 会消费这些 producer 形成的 scalar register/stack
storage，但并没有运行真实 Ghidra Program database/analyzer importer。因此本
front-end adapter 本身仍为 `NO_ORACLE`/L2；aggregate ModelRules、非 x86、完整
ProtoStore codec 与错误状态均未获批准。

## 2026-08-30：HTTPD-URAM-SYMBOLIZE-0001 — PLT thunk 名与默认 FUN_ 符号导入

`ElfPltImports::parse_elf` 是 ELF PLT thunk 名导入边界（Ghidra Java
ELF/PLT analyzer 的 native 对应物）：`.plt.sec`/`.plt` 槽位按索引对应
`.rela.plt` JUMP_SLOT 重定位（第 i 项 ↔ `base + 16*i`，`.plt` 跳过解析器头
从 1 起），`.plt.got` 槽位逐个解码 `f2 ff 25 <disp32>` 尾巴并匹配拥有该
GOT 地址的 R_X86_64_GLOB_DAT 重定位。几何与匹配沿用 curl 驱动已锁定的实现
（原 examples/curl_decompile.rs 内联块，提炼为共享边界）；httpd witness：
slot 43 = 0x2a6d0 = `apr_app_initialize`，`.plt`@0x29020、`.plt.got`@0x2a400、
`.plt.sec`@0x2a420，317 个 JUMP_SLOT 全部解析。

`analyze_headless_function_symbol_name(vaddr, image_base)` 镜像 Java
SymbolManager 的默认函数符号策略：`FUN_` + analyzeHeadless image-base 地址
的 8 位零填充 hex（ET_DYN image 装载于 0x100000，golden 的共享尾块
0x2c520 → `FUN_0012c520`）。

消费链（对齐 flow.cc:656-672 `queryCall` → fspec.cc:4949-4960 `setFuncdata`
→ printc.cc:601-609 `opCall` 的 `fc->getName()`）：驱动把 thunk 名与未命名
call-target 的默认名种入 callpoint-symbol 替身表，`map_globals` 对已命名地址
经 has_symbol 门跳过 `uRam<offset>` 合成，`PrintC` 的 CPUI_CALL 臂按地址取名。
E2E（httpd 29 函数口径）：uRam 调用 87→0（82 thunk + 5 发现函数全部按 golden
拼写命名），skeleton 2278→2274，defects=0、numbering=0；curl 输出字节不变
（3090/0/0）。单元测试 3 项（slot 重定位映射、image-base 命名、非 ELF 拒绝）
锁 httpd 语料。前端 adapter 本身仍 `NO_ORACLE`/L2（无真实 Java analyzer
对拍；oracle 证据=12.0.4 headless golden 的 thunk/默认名拼写与计数）。

## 2026-09-24：DWARF 枚举补 ENUMTYPE 旗标（Lane GG2）

`enum_type` 构造的 TypeBase 现置 `type_flags::ENUMTYPE`——Ghidra TypeEnum
自带 enumtype 旗标（type.hh:490-494，isEnumType() 按旗标判定，type.hh:219），
缺旗标的枚举对 pushConstant 的枚举臂不可见（打印退化为默认 cast）。
另：前代 DWARF-VOID-UNKNOWN-MODEL-0001（0 参 DWARF 签名 → model "unknown"，
golden 三函数 Unknown-calling-convention 警告见证）的单测期望已同步翻转
（void_signature_dwarf_prototype_pins_unknown_model）。

## 2026-09-24：LibcSignatureTable 原型钉 unknown 约定名（Lane CURB，PLTSTUB-WARNLOSS-0001 收口）

`LibcSignatureTable::locked_proto` 产物在锁定 storage 之外现在额外钉
`set_model_name("unknown")`——镜像 generic_clib 引入路径的约定名状态：
ELF thunk 的 FunctionDB 从未被赋予 calling convention（ELF 导入器不给
thunk 指定约定；`FunctionPrototype.grabFromFunction`（FunctionPrototype.java:
129-141）回读为 "unknown"），`FuncProto::decode`（fspec.cc:4675 起）将
model="unknown" 路由到 `createUnknownModel`（architecture.cc:1159-1166：
UnknownProtoModel 从 defaultfp 克隆行为——paramrange/localrange/
stackgrowsnegative 与默认模型一致、printInDecl=false），参数存储仍经该
模型分配且 typelock 保留（ProtoStoreInternal::decode，fspec.cc:3464-3567）。
可观测出口=`ActionPrototypeWarnings`（coreaction.cc:4901-4908：
isModelUnknown && !hasCustomStorage && (inputLocked || outputLocked)）——
锁定 curl golden 上恰好 24 个 generic_clib 锁定 PLT 桩
（0x102310 strcpy / 0x102320 puts 等见 witnesses）的头注释
`/* WARNING: Unknown calling convention -- yet parameter storage is locked */`；
表外 21 个引入（curl_easy_*、__vfprintf_chk、__cxa_finalize 等）无锁定
签名、golden 同样无警告。Rugra 只钉名字符串：绑定的 ProtoModelFull 仍是
defaultfp 克隆，模型对象消费者（hasEffect、derive_input_map、varmap 名字
键注册表回退 defaultfp）保持 UnknownProtoModel 的占位行为。

验收（fast-release 亲测，基线=亲父 37014110）：curl 1329/0/0→1215/0/0
（45 个 PLT 桩 diff 3/2→0；本节 −24 行 + jumptable 警告 −90 行合并账，
jumptable 半边见 PLTSTUB-THUNKRELRO-0001）；零差函数 62→107；
逐函数 0 回退；httpd 输出字节恒等；8/8 投影银行 MATCH。

## parse_c_type 扩展：数组声明符 + C1 种子基类型（HEADLESS-BRIDGE-V1-TYPESEED，2026-09-25）

`parse_c_type` 改为 `pub(crate)` 并扩展两类输入（HEADLESS-BRIDGE-V1-TYPESEED
的 manifest 声明拼写）：①最外层数组声明符（`long[4]`、`char *[2]`）——按
`TypeFactory::get_array`（type.cc:3902 getTypeArray 镜像）折叠，
对应 TypeArray::decode 的 arraysize×alignsize 重建（type.cc:1330-1342）；
②x86-64 gcc 数据布局基类型表（undefined/undefined1/2/4/8、uint4、ulong8、
byte1、short2、float4、double8、bool1）。既有 24 条 libc 签名拼写路径不变
（新臂只在新拼写上点火）。指针层与名字树解析（factory_named_base/
find_by_name 身份复用）保持 GL 判例语义。

## 2026-09-25：BRIDGE1-TYPESEED 三连修（Lane TYPEFIX：PIDT/MULTIDIM/PARSEFAIL）

CR-BRIDGE1 复核登记的三个条件项收口（基亲父 22957a15）：

- **`__pid_t`（PIDT，P2）**：基类型表补 glibc typedef 镜像条目
  `"__pid_t" => (4, Int)`——httpd canon 在 ap_signal_server 提交
  `__pid_t local_34;`（ghidra_httpd_1204.c:24574，glibc `typedef int
  __pid_t` 的 analyzeHeadless DWARF 导入），oracle 侧 `<localdb>` 编码表
  （gen_seed_xml.py BASES，stage_seed_diag 验证）同载 (4,int)。httpd 驱动
  无 DWARF 名字索引，提交 typedef 与其它种子基一样走表解析。
- **未知命名基禁止 address_size 回退（PIDT 根因面）**：`parse_c_type`
  的 other 臂不再静默铸造 8B 未知基——oracle 两条路径都不允许裸名猜尺寸：
  `<type>` 传输只读显式 ATTRIB_SIZE（`Datatype::decodeBasic`，type.cc:623-637，
  经 `TypeFactory::decodeTypeNoRef` default 臂 type.cc:4536-4543），C 签名
  路径经 `glb->types->findByName`（grammar.cc:2989）解析，未知名仅产出
  IDENTIFIER 使解析失败。不可解析基现为 parse error，由种子调用方
  （coreaction 的 PARSERFAIL 降级臂）报告并跳过。
- **多维数组维序（MULTIDIM，P3）**：数组折叠改剥**最左**维（C 声明维序，
  `long[2][4]` = array(2) of array(4) of long，镜像 TypeArray::encode 的
  外层 arraysize=左维嵌套，type.cc:1326-1347）；原最右维剥离产生倒置的
  array(4) of array(2)。单维拼写形状不变。
- 新增单测 3 例：`typeseed_pidt_base_carries_committed_four_byte_int` /
  `typeseed_unknown_base_is_parse_error_not_address_sized_mint` /
  `typeseed_multidim_array_strips_leftmost_dimension`。

coreaction 侧（F3，注释声明不改逻辑）：种子 parse 失败臂登记
BRIDGE1-TYPESEED-PARSEFAIL 降级——oracle 的 decodeType 失败抛 LowlevelError
使整函数数据库解码失败；Rust 通道按符号 skip+eprintln（仅损坏 manifest
可观测），详见 docs/api/coreaction.md 同日节。
