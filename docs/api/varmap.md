## 2026-09-28：live_symbols memo 失效钩（OUTSTREAM-MEMO-INVALIDATION-0001，CR-OUTSTREAM3 条件 1）

`ScopeLocal::invalidate_live_symbol(idx)`：rename/namelock 写点（两个
apply-recommendation 臂 + `rename_symbol`）即刻丢弃该槽位的 memo 条目。
Ghidra 的 scope 拥有每映射一个堆 `Symbol`（database.hh:809），晚改名/
namelock 写对所有已交出的 `Symbol *` 天然可见；Rust 的 memo 是快照，
必须在突变时落钩才能保持该活性语义。当前管线内不可达（物化仅发生在
op 装接属性尾；生产写点先于后续装接；晚重绑走 `remap_varnode` 独立
端口）——钩为未来管线位移设防。测试：rename 后 memo 条目被丢弃。
同 commit：`live_symbol_entry` 的 `// Ghidra:` 引用修正为定义行
database.cc:1246（CR-OUTSTREAM3 条件 2）。

# `varmap.rs` API Reference

## 2026-09-28：ScopeLocal::live_symbol_entry 活符号入口物化（DB-LOCALSCOPE-MAP-0001 local-leg completion，wt/outstream）

`ScopeLocal` 此前无活 SymbolEntry 对象（DB-LOCALSCOPE-MAP-0001 split 的
已知残留）：`query_properties_ex`（database.cc:1263-1281 对应物）的入口
命中只回 `LocalMapEntry` 值快照 + flags 折叠，上层无法运行完整
`Varnode::setSymbolProperties` 端口。本次补齐两件：

1. `live_symbols: Arc<RwLock<BTreeMap<usize, Arc<RwLock<database::Symbol>>>>>`
   ——按槽位 id memo 的活 Symbol 句柄缓存。Ghidra 的 scope 拥有每映射
   **一个**堆 `Symbol`（database.hh:809），跨查询交出同一对象，
   `Varnode::setSymbolProperties` 的 `mapentry != entry`（varnode.cc:415）
   以指针身份判重复链接；Rust 形态 = `same_storage_identity` 的
   `Arc::ptr_eq(symbol)` 需要 memo 化句柄才能观测到"已链接"。
   `Arc` 包裹使 `Clone` scope 拷贝（printc.rs）共享缓存——句柄身份跨
   拷贝恒等，对应 Ghidra 堆指针在 scope 只读拷贝下存活。
2. `live_symbol_entry(&LocalMapEntry) -> Option<Arc<RwLock<SymbolEntry>>>`
   ——从 map 命中物化活入口：Symbol 的 name/display_name/dtype/flags
   （typelock/namelock/addrtied/persist/property_flags，database.hh:271
   getAllFlags 镜像）+ `SymbolEntry::new_static(extraflags, addr=start,
   offset, size, uselimit)`。消费方 = funcdata.rs 两处属性尾（见
   docs/api/funcdata.md 同日条目）。

A/B 与证据链见 funcdata.md 条目（canon curl 95→85/0/0，httpd 字节恒等，
镜面五面 PASS）；单测
`test_set_varnode_properties_struct_downchain_lock`（funcdata.rs）覆盖
memo 恒等与入口字段。**机制 C 注记**：本条目触及 varmap 核心算法层
（ScopeLocal），commit 附完整 Alignment Evidence 块，CR 需求已在车道
终报标注。

## 2026-09-26：ScopeLocal::decodeWrappingAttributes 覆写移植（VARMAP-DECODEWRAP-0001，wt/varmapdecode）

DATABASE7 车道移交票（MIGW1-DATABASE-0005 phase 3 裁决 R5：数据库层基类体逐字
`{}` 双侧同构免修；唯一覆写在 varmap 域）。三件交付：

1. `range_locked` 字段（varmap.hh:220，构造 init false = varmap.cc:347）+
   `decode_wrapping_attributes` 方法（varmap.cc:479-486 逐字语义：复位→
   ATTRIB_LOCK→ATTRIB_MAIN→space 重指，见 API 节）；
2. `reset_local_window` 的 `if (rangeLocked) return;` 守卫（varmap.cc:439）——
   cc:435-437 的 stackGrowsNegative/min/max 复位仍在守卫**之前**运行，仅并集
   窗口安装被跳过；生产路径 `range_locked` 恒 false（无写入方），行为零变化；
3. B2 双侧 fixture `tests/oracle/varmap_decodewrap_1204.{cc,rs}`（runner
   `tools/run_varmap_decodewrap_oracle.sh`）：oracle 侧经生产调用点
   `Database::decodeScope`（database.cc:3385 分发）驱动真实 ScopeLocal，十二
   case 双侧 stdout 字节恒等——lock true/false/"1"/"yes"（legacy 'y' 首字符
   臂，xml.hh:398）/"True"（大小写敏感拒绝，xml.hh:396）解析、main stack/ram
   空间重指、main other 非规范名（Rust 值模型 `Other(index)` 回退臂，oracle
   观察面 `getName()=="other"`）、未知空间名（marshal.cc:421）与缺失 main
   （marshal.cc:275）与缺失 lock（marshal.cc:275，lock 读在 main 读之前
   varmap.cc:483）的逐字 DecoderError 文本、锁定/解锁下 resetLocalWindow
   的守卫语义（空窗存活 + 刷新仍跑 vs 并集安装）。cargo 单测 3 项（lock/space
   摄入含 Other 臂、错误通道、守卫）。

## 2026-09-25：create_entry 数组壳改走 TypeFactory::get_type_array（GENSMOKE-T5，wt/vshfix）

`create_entry`（varmap.cc:617-628）num>1 分支不再本地铸造**带名**数组壳
（旧实现 `format!("{}[{}]", elem, num)`，TYPE-WIRING-0001 residual），改调
`TypeFactory::get_type_array(num, ct)`（type.cc:3902-3909 的移植，见
docs/api/type_system/typefactory.md）。oracle `glb->types->getTypeArray`
经 `TypeArray(n,ao) : Datatype(n*ao->getAlignSize(), ao->getAlignment(),
TYPE_ARRAY)`（type.hh:937）铸造**匿名**壳并 findAdd 去重；匿名名对打印是
承重的——`buildTypeStack`（printc.cc:148-151）的 named-break 只对具名类型
停钻，数组层被钻过时声明走 array_expr postsurround 形（printc.cc:76/
294-295）：`char acStack_138 [8]`，括号永不烤进类型名（旧拼写
`char[8] acStack_138`）。行为验证：vsh 镜脸 skeleton 549→55（T5 族 17 行
归零）；curl canon 脸唯一文本变化 `undefined1[8] auStack_8;` →
`undefined1 auStack_8 [8];`（==canon golden 1043 行逐字节），
487→481/0/0。壳尺寸语义（num × 元素 alignSize、余数留洞，
VARMAP-SPALIAS-ARRAYSHELL-SIZE-0001）由 get_type_array 的 ctor 逐行镜像
保持不变。

## 2026-09-24：数组壳尺寸 = num × 元素 alignSize（VARMAP-SPALIAS-ARRAYSHELL-SIZE-0001，wt/p3batch）

`create_entry`（varmap.cc:617-628）的 num>1 数组壳尺寸修正：Ghidra
`glb->types->getTypeArray(num,ct)` 构造 `TypeArray(n,ao) : Datatype(n*ao->getAlignSize(),…)`
（type.hh:937）——数组壳尺寸 = **num × 元素 getAlignSize()**，即
`floor(hint.size/align) × align ≤ hint.size`。非整扩展余数（open hint 被 varmap.cc:1315
扩过界，如 14B/4B 元素 → num=3、壳 12B）尾部**留洞**，不进符号映射。Rugra 原以
`hint.size` 整段作壳尺寸，把余数也映射进数组壳。本语料（curl/httpd）hint 全为整倍数
=latent 零行为差；判据由 varmap 既有单测族 + 三门禁恒等锁定。与上一节
（VARMAP-SPALIAS-RETYPE-0001：addSymbol 尺寸取自类型而非 hint.size）同域收口。

## 2026-09-24：create_entry 符号尺寸改由数据类型决定（VARMAP-SPALIAS-RETYPE-0001，wt/spalias2）

**结论先行（车道裁决）**：GK 移交的两个症状——①SP-alias 栈符号陷入
`undefined1[32]` 自举固定点（canon golden `long local_c8[4]`）；②pass2+ 丢失
-0xd0/-0xd8 alias——**均非 varmap 移植缺陷，而是 canon golden 的 headless 全程序
分析环境差异**。证据=锁定 oracle（e40ed130）单函数 drill（stage_drill 变体，
`-DOPACTION_DEBUG` + `Scope::turnOnDebug` 打开 `MapState::addRange` 的
`Add Range: <st>:<sz> <type>` 流与 `ScopeLocal::restructure`/`adjustFit` 埋点，
httpd main @0x2b820）：

- **逐 pass hint 流双侧等价**：pass0=16 个别名、open hint 全 unknown1；
  pass1=fixed undefined8@-0xd0（标记 store 转 COPY 后的直写 varnode）+
  {-0xa8,-0x9c,-0x40} fixed；pass2+ **oracle 同样丢掉 -0xd0 fixed hint**、
  open 集恒为 {-0xc8,-0x9c,-0xa8}（晚期元素类型 undefined8/undefined4）——
  与 Rugra maplist 探针逐项相同。
- **oracle 终态符号表与 Rugra 修复前仅差一处**：oracle
  {axStack_c8[32]@-0xc8, xStack_a8 **8B**@-0xa8, axStack_9c 92B@-0x9c,
  xStack_40 8B@-0x40}；Rugra 修复前 uStack_a8 为 **12B**。
- `long`/`local_d0`/`local_d8` 在单函数 oracle 核心的 hint 流里**从未出现**
  （无任何 TYPE_INT 元素 open hint）；direct-runner 产物（真 Ghidra 核心+
  合成工厂）同样收敛到 `axStack_c8[32]`/无 d0/d8。canon golden 的 long 族
  由 analyzeHeadless 整程序分析层（锁定类型/已提交签名，含 decompiler
  parameter ID 循环）播种，golden 自身的已提交原型全是 undefined8*/int（如
  `FUN_0012c520(undefined8*,int)`、`ap_setup_prelinked_modules(undefined8*)`），
  说明种子经由更深的分析侧通道，非反编译器核心行为。

**本提交修复（唯一真缺陷）**：`ScopeLocal::create_entry` 原来在 `add_symbol`
之后用 `symbols[idx].size = hint.size` 覆写符号尺寸。Ghidra
`ScopeLocal::createEntry`（varmap.cc:617-628）只把（可能数组包裹的）concrete
类型交给 `addSymbol("",ct,addr,usepoint)`，符号/映射条目尺寸取自数据类型；
open hint 在 `restructure` 里被 `cur.size = next->sstart-cur.sstart`
（varmap.cc:1315）扩到下一个符号起点时经常非整（如 12B/undefined8 元素），
createEntry 按 `num = a.size/align`（varmap.cc:623）向下取整到整元素数，尾部
字节留空不映射（oracle drill 实测：-0xa8 hint 扩到 12、adjustFit longestFit=
120 不缩，8B 符号完全来自类型尺寸，[-0xa0,-0x9c) 保持无符号洞）。修复=删除
该覆写（`add_symbol` 已按 final_dt 定尺寸），Rugra 终态表与 oracle drill 逐项
一致。E2E 输出恒等（两语料都不触及该洞）：curl 1438/0/0、httpd 1447/0/0 与
亲父 cd071239 字节一致；五投影 MATCH×5；varmap 单测 45/45。

**B2 证据（可复用方法）**：drill 变体源码+产物归档
`/dev/shm/rugra-reports/sb-spalias2/`（stage_drill_scope_1204.cc：在
stage_drill_1204.cc 基础上加 scope `turnOnDebug` 与终态符号表 dump；埋点版
varmap.cc 仅存在于车道私有 /dev/shm 构建树，共享 sb-drill 树未触碰）。

**登记移交（不属 varmap 域）**：SP-cast 印刷形（`(int *)x - 8` vs oracle
direct 的 `(int8)x + -8` vs canon 的 `plVar12[-1]`）=cast/printc 域元素尺度
发射差；long 族种子 = headless 分析环境（driver/fspec 域）。

## 2026-09-22：VARGROUP-ABSORB-0001 车道探针剥离（无 API 变更）

剥离车道私有 `[DBG]` 诊断探针（wip 1cd9f682/d3755452 声明的临时探针清单含本文件），
源码恢复至车道 f7348207 状态（与 merge-base 36f26db3 同树）。探针结论已记录于
`docs/alignment_docs/VARGROUP_ABSORB_MECHANISM_2026-09-22.md`，无接口/语义变化。


**状态**: 骨架已实现（L2），集成待完成
**源代码路径**: `src/varmap.rs`

**2026-08-24 修复（VARMAP-LOCALWINDOW-0001）**: local 分析窗口接线——`restructure_varnode` 内硬编码的正向 `[0, 0x100000)` 窗口（参数侧半区）替换为忠实的 `reset_local_window`（varmap.cc:432-460）：并集树 = 原型 localRange ∪ paramRange（默认负增长 8 字节栈 = `[u64::MAX-999999, u64::MAX] ∪ [0,511]`），MapState 构造逐条减 paramrange（varmap.cc:870-875），initialize 端点 = `wrapOffset(getLastSignedRange+1)`（= 0，varmap.cc:1070），并补齐 `reconcile_datatypes`（varmap.cc:960）。此前每条符号扩展负偏移 local/open hint 在 `add_range` 门被丢弃（varmap.cc:902），4096B 数组无从恢复、负偏移名回绕（`in_stack_ffffffffffff…`）。原型 localRange 与并集树分立缓存（`proto_local_range` vs `local_range`——buildVariableName 读前者，varmap.cc:555，正偏移参数命名不回归）。锁定 oracle 双侧 fixture：`tools/run_varmap_localwindow_oracle.sh`（VARMAP-LOCALWINDOW-0001，四 case：默认窗、进窗/出窗门、open 数组延伸+端点截断、命名分支）。

**2026-08-23 修复（GETSTR-ZERODIFF-C）**: `restructure_varnode` 开头的符号全清改为 `clearUnlockedCategory(-1)` 忠实移植（Ghidra varmap.cc:1273 调用 ScopeInternal::clearUnlockedCategory，database.cc:2086-2096：`if (sym->getCategory() >= 0) continue;` —— 参数/equate 类符号无条件存活；category<0 且 typelock 的存活（未锁名重置为 $$undef 占位，cc:2091-2094）；其余 removeSymbol）。旧实现 `self.symbols.clear()` 抹掉平台播种的 function_parameter 符号，导致 input-locked DWARF 参数每次重结构化退化为 in_RXX 不规则输入名。幸存者的 nametree/category/mapentry 以旧索引→新索引重链。

## 模块说明

Ghidra `varmap.cc` (1620行) 的 Rust 移植。负责局部变量的栈帧重构和映射。

## 导出的公共 API

### `pub struct RangeHint`
栈地址空间上的类型化范围提示。对应 Ghidra RangeHint。
- `start: u64` — 起始偏移
- `size: i32` — 字节大小
- `sstart: i64` — 有符号起始偏移（用于比较）
- `dtype: Option<Arc<Datatype>>` — 数据类型
- `flags: u32` — 标志（TYPE_LOCK, COPY_CONSTANT, UNALIASED, MAPPED）
- `range_type: RangeType` — Fixed/Open/Endpoint

#### RangeHint 方法（2026-06-26 完整对齐 Ghidra varmap.cc）
以下方法现已 **1:1 对齐 Ghidra**（此前为简化版，已替换）：

- `is_const_absorbable(&self, b)` — `RangeHint::isConstAbsorbable` (varmap.cc:30)
- `reconcile(&self, b)` — `RangeHint::reconcile` (varmap.cc:62)，含 `get_sub_type` 对齐遍历
  （2026-09-22 起 chain 持 canonical component Arc，与 Ghidra factory-owned
  `Datatype*` 镜像一致；见 `docs/api/type_system/datatype.md`）。
  **2026-09-27 POINTTEE 数组臂收紧（GA2-SWITCHVN-POINTEE-TYPE-0001）**：STRUCT/UNION
  之外的数组放行条件从"任意数组"改为 oracle 逐字（varmap.cc:92-94
  `meta != TYPE_ARRAY || arrayBase->getMetatype() != TYPE_UNKNOWN → return false`）——
  仅 array-of-unknown 落到 b 元类型 UNKNOWN/INT/UINT 接受臂（cc:96-99）
- `contain(&self, b)` — `RangeHint::contain` (varmap.cc:109)
- `preferred(&self, b, reconcile)` — `RangeHint::preferred` (varmap.cc:126)
- `absorb(&mut self, b)` — `RangeHint::absorb` (varmap.cc:217)
- `merge_with(&mut self, b, types)` — `RangeHint::merge` (varmap.cc:259)，三态 resType（0/1/2）；`types` 对应 Ghidra 签名的 `TypeFactory *typeFactory` 参数（varmap.hh:124），resType==2 时经 `getBase(size,TYPE_UNKNOWN)` 取未知类型（varmap.cc:309）（2026-08-16，`TYPE-WIRING-0001`）
- `compare(a, b)` — `RangeHint::compare` (varmap.cc:321)，排序：offset→size小优先→rangeType→flags→highind
- `attempt_join(&mut self, b)` — `RangeHint::attemptJoin` (varmap.cc:170)，数组元素吸收。**2026-09-26 提交时序修复**（GENSMOKE-S2-TYPEINFER-METATYPE-0001 毒环入口）：oracle 的 `settype = b->type`（varmap.cc:192）只改局部替身，`type = settype` 的提交发生在 `diffsz > highind` 越界拒绝检查**之后**（varmap.cc:208）；旧实现把 `self.dtype = Some(b_dt)` 写在 keep_b 臂（检查之前），被拒绝的吸收（probeSys 的 -0x40 int8 canary 提示，`diffsz=4 > highind=3`）仍把 int8 泄进 open range，随后调用方的 `cur.size = next->sstart - cur.sstart` + createEntry 把 `int8[4]` 写进符号层，喂出整个 int8 反哺环（符号 int8 → downChain `ptr→int8` → INT_EQUAL/φ 横传 → gatherOpen int8 → 下轮 restructure）。修复后局部 `settype` 贯穿检查链，diffsz 的模/除用（可能已替换的）settype 对齐尺寸（varmap.cc:205 语义），仅在全部通过后提交

### `pub struct AliasChecker`
栈指针别名分析器。对应 Ghidra AliasChecker。
**2026-06-26 完整对齐**（此前为简化版，仅扫描 STORE）。
**2026-07-05 方向约定修正**：`direction` 字段遵循 Ghidra 约定
（`varmap.cc:700` `direction = stackGrowsNegative() ? 1 : -1`），
即 `1` = 负向增长（x86）、`-1` = 正向增长。此前 `ScopeLocal::new`
误初始化为 `-1`，导致 `has_local_alias` 在 x86 上恒返回 false，静默
关闭了别名分析（P0-1，详见 `docs/alignment_audit/INDEX.md`）。
- `pub aliases: Vec<u64>` — 别名偏移（gather 后按 gather 序；`sort_aliases` 后升序，varmap.cc:726）
- `pub add_base: Vec<AddBase>` — 加法基根（base + index）
- `direction: i32` — 方向：`1`=负向增长(x86)，`-1`=正向增长（与 Ghidra `AliasChecker::direction` 同号）
- `gather(&mut self, fd, stack_grows_negative, defer)` — `AliasChecker::gather` (varmap.cc:692-704)：复位状态、`direction = stackGrowsNegative() ? 1 : -1`（Rugra 无 per-space 增长位，传 scope 的原型派生旗标——与 Ghidra 栈空间的位同源配置）、`derive_boundaries(fd 原型)`、非 defer 立即 `gather_internal`。**2026-08-25 VARMAP-GATHEROPEN-GUARD-0001**：deriveBoundaries 从此经该入口接入 varmap 域（此前管线从不调用，边界恒 0x1000000）
- `gather_internal(&mut self, fd)` — `AliasChecker::gatherInternal` (varmap.cc:660)；`alias_boundary` 初值 = `local_extreme`（非硬编码 ~0——正向增长时为 localBoundary），列表清理由 `gather` 承担（varmap.cc:698-699），此处不再排序（sortAlias 独立，varmap.cc:1279）
- `gather_additive_base(&mut self, startvn)` — `AliasChecker::gatherAdditiveBase` (varmap.cc:741)，递归 BFS 追踪 INT_ADD/INT_SUB/PTRADD/PTRSUB/SEGMENTOP/COPY 后继
- `sort_aliases(&mut self)` — `AliasChecker::sortAlias` (varmap.cc:726)，restructureVarnode varmap.cc:1279 调用（checkUnaliasedReturn 的 lower_bound 依赖有序）
- `has_local_alias(&self, vn)` — `AliasChecker::hasLocalAlias` (varmap.cc:711)；`direction==-1`（正向增长）时返回 false；`!calculated` 时保守 true（Ghidra 此处现场 gatherInternal——Rust 取 &self，管线两条路径均预计算，未计算分支不可达）
- `derive_boundaries(&mut self, localrange, paramrange, has_model)` — `AliasChecker::deriveBoundaries` (varmap.cc:633-655)：默认 `localExtreme=~0 / localBoundary=0x1000000`（正向增长时 `localExtreme=localBoundary`）；**有模型时** `localBoundary = paramrange 末 range 的 last`（默认负增长模型 = **511**，fspec.cc:2298-2307——此前死区 [511,0x1000000) 内的正偏移加法基不收缩 aliasBoundary，R8 §6.3 证伪"行为等价"后的修复），正向增长改 `paramrange 首 range 的 first` 且 `localExtreme = localBoundary`
- `boundaries()` — RUGRA-GLUE 观察口：`(localBoundary, localExtreme, aliasBoundary)`（C++ fixture 经 `#define private public` 直读成员）

辅助函数：
- `pub fn gather_offset(vn)` — `AliasChecker::gatherOffset` (varmap.cc:817)，递归求和常量偏移（COPY/ADD/SUB/PTRADD/SEGMENTOP），末尾按字节大小掩码；`VARMAP-GATHEROFFSET-0001` 已按 `address.hh:499` 的 `size >= 8` 钳位语义修复 8-byte 边界，并由锁定 12.0.4 的 7/8-byte 直接状态 fixture 验证。该窄分支的 `MATCH` 不提升整个 `AliasChecker` 模块状态。
- `fn find_spacebase_input(fd)` — `Funcdata::findSpacebaseInput`，Rugra 中 RSP = Register@0x20 size8 无 def 的输入 varnode

### `pub struct MapState`
范围提示收集器和重构器。对应 Ghidra MapState。
**2026-06-26 完整对齐**（此前为简化版）；**2026-08-24 VARMAP-LOCALWINDOW-0001**：分析窗口
由硬编码半开 `[0,0x100000)` 换为 Ghidra 的 `range` 成员模型（varmap.hh:176）——
`MapState(spc,rn,pm,dt) : range(rn)` 后逐条减 paramrange（varmap.cc:864-875），以排序
闭区间 `Vec<(first,last)>` 承载，add_range 的门与 initialize 的端点都从该真值窗口推导：
- `new(range)` / `new_with_default(range, default_type)` — 构造器（varmap.cc:864-867）：`range` 为
  分析窗口（scope 并集树减 paramrange，由 `ScopeLocal::build_map_state` 按 varmap.cc:1260 组装）
- `analysis_range()` / `hints()` — RUGRA-GLUE 只读观察口（锁定 fixture 的观察面；C++ 侧经
  `#define private public` 直读 `range`/`maplist`）
- `add_range(start, dtype, flags, rt, high_ind)` — `MapState::addRange` (varmap.cc:896)：**2026-09-25
  RANGEHINT-CR-F2** `ct==NULL || ct->getSize()==0` 一律代换 `defaultType` 后**继续**（varmap.cc:899-900；
  此前 `Some(零尺寸)` 走 `size<=0` 早退被直接丢弃=欠收 hint，与 oracle 的"代换后继续"相悖——零尺寸
  Some 现进 default 类型与尺寸；default-less 测试构造器保持匿名 size-1 形继续，不再丢弃；单测
  `test_mapstate_add_range_zero_size_substitutes_default` / `..._bare_constructor_keeps_flow` 钉死）；
  完整 extent `[st, st+size-1]`（uintb 回绕）不在分析窗口单一 range 内则丢弃（`range.inRange(addr,sz)`，
  varmap.cc:902 / address.cc:468-487，`window_in_range`）；`sst` 为
  byteToAddress+sign_extend+addressToByte（varmap.cc:904-906，1-word-size 8 字节栈上即
  `start as i64`——负偏移保持负值供 `RangeHint::compare` 有符号排序）
- `add_fixed_type(start, dtype, flags)` — `MapState::addFixedType` (varmap.cc:926)
- `gather_varnodes(fd)` — `MapState::gatherVarnodes` (varmap.cc:1124)，逐 op-code 分支（INDIRECT/MULTIEQUAL/PIECE/SUBPIECE/COPY/默认），含 same-storage 去重与 `is_read_active`。PIECE 视为两个 COPY（little-endian slot=1，addr+=inFirst.size）；SUBPIECE 用 little-endian `trunc = in1.offset`，`addr = in0.off + trunc` 后与 vn 地址比较。**2026-09-28 PIECE 半值 hint 落址修正（SQLCENSUS-CODESTAR-DOWNCHAIN-0001 根因二，S2R2 车道）**：oracle 的两处 `addFixedType(addr.getOffset(), inXxx->getType())`（varmap.cc:1172/1176）落在**输出地址**与**输出地址+低位尺寸**上（输入地址只用于 same-storage 判定）；Rugra 此前落在输入 varnode 自身地址上——寄存器半值地址不在栈分析窗内被 `window_in_range` 静默丢弃，8 字节槽的高半 hint（如 -0x78 槽的 -0x74@4 字节）永不出现 → RangeHint::merge 的 resType=2 confuse 稳定器（varmap.cc:298-312，oracle 同槽 MERGE 折叠日志亲证：`cur=:8(open) next=uint4:4 res=2` 重置为标量）永不触发 → varmap↔downChain 反馈环每轮 +1 星（sqlite3Select -0x78 槽 xunknown8→uint4\*→…→uint4\*\*\*\*\*\*，GETSUBTYPE 348 查询里 384→指针态、`(code*)` 0/7 星 387 行）。修复后 -0x78 槽 348 次 getSubType 全程恒 xunknown8（=oracle 逐查询恒等），Select 镜面 2257→90
- `gather_open(fd, types)` — `MapState::gatherOpen` (varmap.cc:1211-1249)：先跑内嵌 checker 的 `gather(fd, grows, false)`（varmap.cc:1214，含 deriveBoundaries），对每个 AddBase 根：指针→pointee，**数组层全下钻**（varmap.cc:1226-1227 `while`——此前单层是缺陷），index 在则 minItems=3；非指针传 `None`（Ghidra 传 NULL，"Do unknown array"，varmap.cc:1230），由 `add_range` 回退默认类型（varmap.cc:896）；随后遍历 `fd.heritage.load_guard`/`store_guard` 走 `add_guard`（varmap.cc:1241-1248）。**checker 现为 MapState 成员**（varmap.hh MapState `AliasChecker checker`），`sort_alias`/`get_alias` 是 restructureVarnode 的消费口（varmap.cc:1279-1284）
- `set_stack_grows_negative(grows)` — RUGRA-GLUE：Ghidra 由 space 成员的增长位（varmap.cc:700）供 checker.gather 取向；Rugra AddressSpace 无该位，装 scope 的原型派生值
- `add_guard(guard, opc, types)` — **2026-08-25 VARMAP-GATHEROPEN-GUARD-0001** `MapState::addGuard` (varmap.cc:1003-1039)：`isValid`（op 活且 opcode 匹配，heritage.hh:169）→ step==0 拒 → 地址输入类型指针下钻数组层 → outSize 匹配/整除 step（整除时假装 outSize 数组）→ 对齐不匹配且 step<=8 时工厂 `getBase(step,TYPE_UNKNOWN)` 重型 → range-locked（`analysis_state==2`）`minItems=(max-min+1)/step-1` 否则 3 → open hint。**R23 followup 5.1 已闭合（2026-08-25 VARMAP-UNIONFACING-READFACING-0001）**：地址输入类型改取 op 版 `get_type_read_facing_op(&op, 1)`（= `getTypeReadFacing(op)`，varnode.cc:639-645，getIn(1) 恒 slot 1），union 指针经 `TypePointer::findResolve`（type.cc:1192-1202，needs_resolution 由 calcSubmeta type.cc:1051-1052 传播）；Rugra 侧 findResolve 目前 identity（varnode.rs `get_type_read_facing_op`），两版同值休眠——双侧 fixture 复跑 sha `3b5e1b65…` 三方同一（编辑后 Rust == R23 pin == oracle 重跑）。**2026-09-25 RANGEHINT 补齐（VARMAP-RANGEHINT-ARRAYELEM-0001）**：oracle 的 Varnode 恒带类型（`newVarnodeOut`/`newUniqueOut`/`newVarnode` 一律装 `getBase(s,TYPE_UNKNOWN)`，funcdata_varnode.cc:107/132/153-154；`getTypeReadFacing` 非联合直接返回 `type`，varnode.cc:639-645），故 varmap.cc:1009-1038 的 `ct` 永不为 null、无 null 早退；Rugra 以 `v_type=None` 建模未定型 varnode，此前 None 直接 `return` 丢 guard hint——现 None 臂代以工厂 `undefined<addr_vn_size>`（正是 oracle 侧 `getIn(1)->getTypeReadFacing` 的返回值），非指针 ct 继续走 outSize/step/对齐检查（与 Ghidra 单流一致）。curl/httpd E2E 逐字节恒等（None 路径在双语料不触发，行为中性）
- `gather_symbols(scope)` — **2026-08-25** `MapState::gatherSymbols` (varmap.cc:1044-1059)：按 space 的 maptable 列表序回灌每个映射符号（entry 起始偏移、符号类型、typelock→hint 旗标）为 fixed hint——restructureVarnode varmap.cc:1269 的 typelocked 符号回灌
- `sort_alias()` / `get_alias()` — varmap.cc:1279/1281-1284 的 `state.sortAlias()`/`state.getAlias()`
- `is_read_active(vn)` — `MapState::isReadActive` (varmap.cc:1088)。**2026-09-27 POINTTEE 全臂补齐（GA2-SWITCHVN-POINTTEE-TYPE-0001）**：此前为两臂简化版（marker 同址检查 + 其余一律 active），缺 oracle 的 PIECE 对齐臂（cc:1102-1109：`slot = out.isBigEndian() ? 0 : 1`，非低位输入的期望地址 = 输出地址 + 低位尺寸，地址不齐才 active）与 SUBPIECE 忽略臂（cc:1112-1113："Any data-type information comes from the output Varnode, so we ignore input"——SUBPIECE 读取不构成 active）。简化版的危害链（sqlite3Pragma 双侧 TYPEPROP drill 亲证）：8 字节槽 -0x90 的 4 字节上半 SUBPIECE 读（same-storage + read_active 误判 true）在 gatherVarnodes 注入 `undefined4`@-0x8c fixed hint → RangeHint::merge 的 resType=2 confuse 臂（varmap.cc:298-312）把整槽符号打成 `undefined8` → `TypeSpacebase::getSubType`（type.cc:2947）经 PTRSUB(RSP,-0x90) downChain 返回 xunknown8* 而非 uint8* → 8 字节 LOAD 证据（INT_LESS 子代 seed uint8，typeop.cc:1093 TypeOpIntLessEqual 构造 TYPE_UINT）进不了指针环 → 参数面 `uint1*×4`、switch 头缺 `(uint1)` cast/`puVar[1]` 元素形。修复后参数面 `uint8*×3`、6 位点 `switch((uint1)puVarNN[1])` 形与 golden 同构（残差=param_4 int8 折叠，另票）。单测 `test_is_read_active_piece_subpiece_arms` 钉四臂
- `initialize()` — `MapState::initialize` (varmap.cc:1063-1082)：先取分析窗口的
  ** getLastSignedRange**（`get_last_signed_range`，address.cc:562-583——正半区
  `first <= midway` 末位，否则负半区末位），端点在 `wrapOffset(last+1)`
  （varmap.cc:1070，8 字节负增长默认窗 → 偏移 0，即"窗口顶端"），size=1/endpoint/-2；
  之后 stable_sort + `reconcile_datatypes`（varmap.cc:1078-1079）
- `reconcile_datatypes()` — `MapState::reconcileDatatypes` (varmap.cc:960-996)：同
  start/size/flags 组内取 `typeOrder < 0` 最具体类型统一到全组，`compare == 0` 的重复
  hint 消除（2026-08-24 随 VARMAP-LOCALWINDOW-0001 补齐——窗口打开后 hint 量激增，
  initialize 的该步骤成为必需）
- ~~`gather_spacebase(fd, types)`~~ — **已退役（2026-09-26，SLOTDEEP 车道，GEN4-SQ-STACKSLOT-MATERIALIZE-0001 根因）**：Rugra 专有补偿层（扫描 LOAD/STORE 的 RSP 派生地址合成 fixed RangeHint）。退役证据=oracle 侧探针（锁定库 varmap.cc 补 read-only `MapState::dumpHints`/`ScopeLocal::slotdeepDumpGather`，golden_dump_1204 one-mode 克隆）：sigwinch_handler(--one 165) 与 read_block(--one 186) 的 oracle 末趟 hint 全集里 fixed hint **只**来自 gatherVarnodes（loc_tree Stack varnode），Rugra 的 gather_varnodes 在相同槽位产出**同数** hint——gather_spacebase 全部产出为双重计数或假阳性：(a) `resolve_rsp_offset_via_bank` 的空间回查把 Unique:0x9d00 上的循环携带堆指针（PTRADD→MULTIEQUAL→LOAD 链）与曾占用同一 unique 位置的 `&buffer` 计算混同 → sigwinch 槽 0xe3 上 31 条伪 fixed hint，与 open hint 同 start 合并成 confused-merge 固定 8 字节标量（`xunknown8 xStack_e3`），杀死 oracle 的 open-hint 数组分解 `xunknown1 axStack_e3 [11]`（oracle 该槽仅一条 open xunknown1 hint，size 由 varmap.cc:1314-1315 到下条 hint 的间隙定 11）；(b) read_block 假阳性解析产出垃圾偏移符号 `xStack_40d8/xStack_4090/xStack_2058/xStack_2030`，且在槽 0x46 的 7 条额外 hint 把 oracle 的 `uint2 uStack_46`（fixed+open 同并）翻成 `axStack_46 [22]` 数组吞噬 0x44/0x40。oracle 的 `restructureVarnode`（varmap.cc:1256-1269）**没有** spacebase 扫描相：fixed hint 只来自 gatherVarnodes，指针引用只来自 gatherOpen。退役后：sq 面 skeleton 7748→6494（OTHER 桶 2138→1665）、canon curl/httpd **字节恒等**（md5 8ce81daa/a5fa22e5）、镜面三面全 PASS 且棘轮未重钉、bank 391/391。配套删除 `resolve_rsp_offset`/`resolve_rsp_offset_via_bank`/`resolve_rsp_offset_signed`（含测试）——`find_spacebase_input` 保留（AliasChecker/annotateRawStackPtr 在用）。printc.rs/funcdata.rs 中提及 gather_spacebase 的历史注释已过时（本车道写域外，未动）。

### `pub struct LocalSymbol`
重构后的局部变量符号（Ghidra Symbol database.hh:168 + 首个整映射 SymbolEntry）。
- `name: String` — 变量名（Symbol::name）
- `start: u64` — 栈偏移
- `size: i32` — 大小
- `dtype: Option<Arc<Datatype>>` — 类型
- `unaliased: bool` — 是否无别名（可安全合并）
- `is_param: bool` — 是否为函数参数
- `display_name: String` — Symbol::displayName（database.hh:179），输出用名
- `name_dedup: u32` — Symbol::nameDedup（database.hh:181），nametree 同名去重 id
- `category: i32` — Symbol::category（-1/0/1/2/3 = 无/参数/equate/union_facet/fake_input，见 `symbol_category`）
- `cat_index: u32` — Symbol::catindex，category 内位置
- `typelock`/`namelock: bool` — Symbol::flags 的 typelock/namelock 位
- `addrtied: bool` — database.cc:1149-1150（任一空 uselimit 静态映射置位）
- `persist: bool` — database.cc:1131-1132/1138-1139（全局 scope 或全局发现域
  命中，装图时折入符号）
- `property_flags: u32` — database.cc:1153 的 addMap 属性折入位（flagbase 的
  readonly/volatile 折到符号 flags，一次性、装图时）
- `usepoint: Option<u64>` — 首个 SymbolEntry 的 first use address（None = invalid Address；`buildDefaultName` 据此决定 addrtied flag，database.cc:1776）
- `is_name_undefined()` — `Symbol::isNameUndefined`（database.cc:246）：15 字符 `$$undef` 前缀

### `pub struct ScopeLocal`
局部变量作用域。对应 Ghidra ScopeLocal。`#[derive(Debug, Clone)]`（2026-06-26：
Clone 用于 printc 从 `fd.scope` 复用）。
**2026-06-26 完整对齐**（类型面 2026-08-16 `TYPE-WIRING-0001` 统一到 TypeFactory 单轨：`restructure_varnode` 解析工厂句柄——`fd.arch.types` 优先，无 Architecture 生产路径回退 `TypeFactory::shared_default()`（DataOrg flavor，模拟 headless 单 Architecture 进程）——并贯穿 `gather_spacebase`/`restructure`/`merge_with`/`create_entry`/`fake_input_symbols`；Ghidra 对应 `glb->types` 于 varmap.cc:1261/1309、`fd.getArch()->types` 于 varmap.cc:1129/1438）：
- `restructure_varnode(fd, aliasyes)` — 主入口（**fd 取 `&mut`**：annotateRawStackPtr 插 PTRSUB op，varmap.cc:405-406）：`ScopeLocal::restructureVarnode` (varmap.cc:1256-1286) 完整编排：clearUnlockedCategory(-1) 存活逻辑→build_map_state→gather_varnodes→~~gather_spacebase~~（**2026-09-26 退役，见上**）→gather_open（内嵌 checker.gather + addGuard）→**gather_symbols 回灌（:1269）**→restructure→**clear_unlocked_category(function_parameter) + clear_category(fake_input)（:1275-1276）**→fake_input_symbols→**sort_alias（:1279）→`if (aliasyes)` mark_unaliased→check_unaliased_return（:1280-1282，2026-09-23 SB-MATCHURL-ORD70-0001 穿透 aliasyes=（numpass!=0），coreaction.cc:2279）→alias[0]==0 时 annotate_raw_stack_ptr（:1284-1285，不受 aliasyes 门）**；默认类型 = 工厂 `getBase(1,TYPE_UNKNOWN)`（varmap.cc:1261）。fakeInputSymbols 先于 markUnaliased（Ghidra varmap.cc:1272-1277 的注释："define fake symbols so that mark_unaliased will work"——此前 Rugra 顺序颠倒）。reset_local_window 不在本函数（见下——生命周期移至 scope 构造）
- `clear_unlocked_category(cat)` — `ScopeInternal::clearUnlockedCategory` (database.cc:2071-2090) 的 cat>=0 分支（varmap.cc:1275 对 function_parameter 调用）：typelock 存活（未 namelock 的已定义名重置 $$undef，database.cc:2080-2082）；`resetSizeLockType`（:2085-2086）无 Rugra 路径（LocalSymbol 无 sizelock 概念，不可达）；其余 removeSymbol。**走查序边界（CR-VARMREKEY F2）**：oracle 按 category[cat] 的 catindex 序走查（database.cc:2077-2090），Rugra 按插入（槽位）序——同集同终态、删除序不可观察，但 rename 遍喂给有状态的 buildUndefinedName 计数器，单次调用 ≥2 个 rename 且 catindex 序≠插入序时 $$undefNNNNNNNN 编号可与 oracle 相异（旧 dense 形态同插入序 ⇒ 预存 seam 非本次存储变化；建议后续 B2 fixture 覆盖该边界）
- `clear_category(cat)` — `ScopeInternal::clearCategory` (database.cc:2022-2029) 的 cat>=0 分支（varmap.cc:1276 对 fake_input 调用）
- `check_unaliased_return(fd, alias)` — **2026-08-25** `ScopeLocal::checkUnaliasedReturn` (varmap.cc:414-428)：首个 RETURN 的值输入在栈空间且无别名（有序表的 lower_bound）触达 `[off, off+size-1]` 时 `mark_not_mapped(off, size, false)`（删重叠符号 + 并集树去范围）
- `annotate_raw_stack_ptr(fd)` — **2026-08-25** `ScopeLocal::annotateRawStackPtr` (varmap.cc:386-408)：type recovery 已开始时，栈指针的非加法读者（跳过 eval-special 非调用与 INT_ADD/PTRSUB/PTRADD）改为消费占位 `PTRSUB(sp,#0)`（newOpBefore + opSetInput 到 getSlot 槽位）
- `reset_local_window(fd)` — `ScopeLocal::resetLocalWindow` (varmap.cc:432-460)：`stackGrowsNegative` 取自原型（:435），`min/maxParamOffset` 复位（:436-437；**2026-09-23 SB-MATCHURL-ORD70-0001 起等价性完整**：Ghidra 只在构造/`Funcdata::clear`/decode 调 resetLocalWindow（funcdata.cc:70/96/836），RULE_REPEATAPPLY 重启不 clear（action.cc:539-570）；Rugra 现在 scope 跨趟持久（coreaction.rs ActionRestructureVarnode 构造时创建+reset_local_window，之后每趟复用），markNotMapped 窄化窗口与跨趟累积 min/max 与 oracle 一致——`VARMAP-CROSSPASS-PERSISTENCE-0001` 就此关闭），并集树 = 原型 localRange ∪ paramRange（:441-458）装入 `local_range`；原型自身 localRange 另存 `proto_local_range`（buildVariableName 的门读原型而非并集，varmap.cc:555）。`rangeLocked`（:439）守卫已补（**2026-09-26 VARMAP-DECODEWRAP-0001**：`<localdb lock>` 属性经 `decode_wrapping_attributes` 摄入，锁定时跳过并集安装）。**2026-08-24 VARMAP-LOCALWINDOW-0001**：替换原先硬编码的正向 `[0,0x100000)` 窗口——那是参数侧半区，把每条符号扩展负偏移 local/open hint 在 add_range 门丢弃（4096B 数组不恢复、负偏移名回绕的单点根因）
- `reset_local_window(fd)` — `ScopeLocal::resetLocalWindow` (varmap.cc:432-460)：`stackGrowsNegative` 取自原型（:435），`min/maxParamOffset` 复位（:436-437。**2026-09-23 VARMAP-CROSSPASS-PERSISTENCE-0001 已修**（VARGROUP-ABSORB-0001 §4-4）：`restructure_varnode` 不再每趟调用本函数，`ActionRestructureVarnode` 复用 `fd.scope` 持久 ScopeLocal（Ghidra localmap 是 Funcdata 生命周期单一对象，resetLocalWindow 仅在 funcdata.cc:70/96/836 生命周期点运行）；窗口只在首趟构造时安装一次，ActionRestrictLocal 的 markNotMapped 窄化跨趟存活——此前每趟全量重装把 30d6 出参影子区复活回局部窗口，字段件全部 addr-tied、`Stack_388` 符号复活，吸收链整体失效。`is_first_pass_construct` 标志门住首趟的平台参数符号 seed + 窗口安装），并集树 = 原型 localRange ∪ paramRange（:441-458）装入 `local_range`；原型自身 localRange 另存 `proto_local_range`（buildVariableName 的门读原型而非并集，varmap.cc:555）。`rangeLocked`（:439）守卫已补（**2026-09-26 VARMAP-DECODEWRAP-0001**：`<localdb lock>` 属性经 `decode_wrapping_attributes` 摄入，锁定时跳过并集安装）。**2026-08-24 VARMAP-LOCALWINDOW-0001**：替换原先硬编码的正向 `[0,0x100000)` 窗口——那是参数侧半区，把每条符号扩展负偏移 local/open hint 在 add_range 门丢弃（4096B 数组不恢复、负偏移名回绕的单点根因）
- `build_map_state(fd, types)` — varmap.cc:1260-1261 的 MapState 组装：分析窗口 = 并集树逐条减 paramrange（varmap.cc:870-875 "Clear possible input symbols"）+ `getBase(1,TYPE_UNKNOWN)` 默认类型
- `decode_wrapping_attributes(decoder, spc_manager)` — **2026-09-26 VARMAP-DECODEWRAP-0001** `ScopeLocal::decodeWrappingAttributes` (varmap.cc:479-486)，基类空体 `Scope::decodeWrappingAttributes` (database.hh:719) 的唯一覆写：`range_locked` 无条件复位（:482）→ ATTRIB_LOCK（属性 id 133）读入（:483-484，`xml_readbool` 首字符解析）→ ATTRIB_MAIN（id 134）经 `read_space` 管理器解析并重指 `space`（:485，解析名→`AddressSpace` 枚举，非规范名回退 `Other(index)`）。调用面（oracle）：`Database::decodeScope` 在打开元素非 `<scope>` 时分发 `newScope->decodeWrappingAttributes`（database.cc:3385），即 `Funcdata::decode` 的 `<localdb>` 传输（funcdata.cc:804-810），属性在 `<scope>` 子元素打开**之前**摄入（database.hh:714-718）；Rust 值模型 ScopeLocal 不入 `Database::scopes`（Funcdata 直拥有的所有权 seam），committed_locals 传输尚不携带 lock/main 属性，故本方法为该通道的摄入钩子（双侧 fixture `tools/run_varmap_decodewrap_oracle.sh` 十二 case 全 MATCH：lock true/false/1/yes（legacy 'y' 首字符臂，xml.hh:398）/True（大小写敏感 'T'≠'t' 拒绝，xml.hh:396）、main stack/ram/other（非规范名→`Other(index)` 回退臂）、未知空间名与缺失 main、**缺失 lock** 的逐字 DecoderError 文本（marshal.cc:421/275——lock 读在 main 读之前，varmap.cc:483）、锁定时 reset 的 cc:435-437 刷新+cc:439 守卫、解锁时并集安装）。**原登记的 marshal glue 双分歧已关闭（2026-09-27 MARSHAL-READBOOL-0001）**：②值域——`TreeDecoder::read_bool`/`read_bool_attr` 经 1:1 `xml_readbool` 移植对齐首字符大小写敏感解析（t/1/y 为真，xml.hh:391-400）；①缺失 lock——`decode_wrapping_attributes` 的 lock 读改为按名扫描（镜像 C++ `readBool(attribId)` 经 `findMatchingAttribute` 的解析序，marshal.cc:286-293），缺失即 `Err("Attribute missing: lock")` 逐字（marshal.cc:276）且在 main 读之前中止（varmap.cc:483→485）。该分歧仅 legacy/畸形流可达（生产 encode 经 writeBool 恒写 "true"/"false" 双属性，varmap.cc:466-467+marshal.cc:508-510），fixture 三臂（"yes"/"True"/缺失 lock）双侧对拍如实钉死；函数级 `read_bool_attr` 缺失通道残差登记于 marshal.md/TODO（PERSIST-0012 票系）。
- `restructure(state, types)` — `ScopeLocal::restructure` (varmap.cc:1294)，相交→merge_with(工厂句柄)，不相交→attempt_join/adjust_fit/create_entry
- `adjust_fit(a)` — `ScopeLocal::adjustFit` (varmap.cc:587)，typelock/size0 拒绝 + 符号重叠收缩
- `create_entry(hint, types)` — `ScopeLocal::createEntry` (varmap.cc:617)：空名 addSymbol（$$undef 占位）+ `concretize`（工厂，varmap.cc:622）+ 数组类型包装（varmap.cc:625——Rust 无 `TypeFactory::getTypeArray`，数组壳仍本地构造，元素类型为工厂对象；登记 TYPE-WIRING-0001 残差）；命名推迟到 assign_default_names
- `fake_input_symbols(fd, types)` — **完整 1:1** `ScopeLocal::fakeInputSymbols` (varmap.cc:1392-1448)：按 `fd->beginDef(Varnode::input)`（VarnodeCompareDefLoc：space/offset/size）遍历 input Varnode；仅以**首地址 1 字节**做 `getParamRange().inRange(addr,1)` 过滤（varmap.cc:1407，负增长 flipped 局部被滤除）；内层按重叠（`off2 <= endpoint`，**相邻不合并**，varmap.cc:1412）吸收同 space 组员；组员 typelock 则整组跳过（varmap.cc:1416-1420）；`lockedinputs != 0` 时以**内层最后检视的（breaker）Varnode** 做 `queryProperties` 探测，命中 `function_parameter` 符号则 continue（varmap.cc:1428-1435）；endpoint/size 为 uintb 模 2^64 回绕（varmap.cc:1408/1413/1437）；`addSymbol("",getBase(size,TYPE_UNKNOWN),addr,invalid)` + `setCategory(fake_input,-1)`，LowlevelError（无类型 / 映射越过地址空间末端，database.cc:1822-1823/1855-1861）被捕获并路由 `fd->warningHeader` 后继续扫描（varmap.cc:1439-1445）。fixture：`tools/run_scope_fake_input_symbols_oracle.sh`（VARMAP-FAKEINPUT-0001，八 case 全观察点 MATCH）
- `get_category_size(cat)` — `ScopeInternal::getCategorySize` (database.cc:2806)：负数/未分配类别返回 0；fake_input_symbols 的 `lockedinputs` 探测源
- `find_container_invalid_usepoint(space, addr, size)` — `ScopeInternal::findContainer`（invalid usepoint 形态，database.cc:2250-2282）+ `SymbolEntry::inUse`（database.cc:114-120，仅 addrtied 项匹配 invalid usepoint）：降序 (first,last) 遍历、严格更小替换、精确尺寸短路，平局取升序末位；dynamic 项不参与；父作用域链（Scope::queryProperties 的 stackContainer 上溯）在 varmap ScopeLocal 无父链——database-scope 统一前为登记残差
- `add_fake_input_symbol(types, addr, size)` — `Scope::addSymbol` 的 LowlevelError 面（database.cc:1810 addSymbolInternal 的 no-type 检查 + database.cc:1843 addMapInternal 的地址空间末端回绕检查），错误文本携带 `buildUndefinedName` 占位名
- `func_proto_param_range(fd)`（自由函数）— `FuncProto::getParamRange` (fspec.hh:1540)：Rugra FuncProto 不持有模型 Arc，按 `FuncProto::setScope` 的回退序（fspec.cc:3879-3885）经 Architecture 注册表解析——约定名 → defaultfp → 无 Architecture 时以 `ProtoModelFull::new`（= `defaultParamRange`，fspec.cc:2292，8 字节负增长栈 [0,511]）作 FUNCPROTO-MODEL-BIND-0001 期占位
- `func_proto_local_range(fd)`（自由函数）— `FuncProto::getLocalRange` (fspec.hh:1539)：与 param 版同一回退序的 local 窗口桥（2026-08-24 VARMAP-LOCALWINDOW-0001）；无 Architecture 回退 `ProtoModelFull::new` 的 `default_local_range`（fspec.cc:2263-2290，负增长 8 字节栈 = `[u64::MAX-999999, u64::MAX]`——heritage 符号扩展负偏移所在半区）
- `func_proto_stack_grows_negative(fd)`（自由函数）— `FuncProto::isStackGrowsNegative` (fspec.hh:1541)：同回退序读模型 `stackgrowsnegative`（resetLocalWindow :435 消费）；无模型回退 `true`（ProtoModel 默认构造，fspec.cc:2349）
- `func_proto_has_model(fd)`（自由函数）— `FuncProto::hasModel` (fspec.hh:1389)：同回退序探测模型是否绑定；derive_boundaries 的 `if (proto.hasModel())` 门（varmap.cc:641）——无 Architecture 时 false，边界保持 0x1000000 默认（与 Ghidra 无模型原型一致；Ghidra 侧经 Funcdata 构造的 setScope（funcdata.cc:68）模型恒绑定，该 false 分支在 oracle fixture 域不可构造，仅 Rust 单测覆盖）
- `window_in_range(ranges, offset, size)`（自由函数）— `RangeList::inRange(addr,size)` (address.cc:468-487) 的 Vec 窗口形态：完整 extent（uintb 回绕）须落在单一 range 内
- `get_last_signed_range(ranges)`（自由函数）— `RangeList::getLastSignedRange` (address.cc:562-583)：正半区（`first <= midway`）末位，无则负半区末位；initialize 的端点推导源
- `param_range_in_range(paramrange, offset)`（自由函数）— `RangeList::inRange(addr,1)` (address.cc:468-487)：空表 false，否则最后一个 `first <= offset` 的 range 须 `last >= offset`（Rugra fspec RangeList 无 space 字段——参数 range 全为 stack 且调用方已过滤 scope space，Ghidra 的 space 测试被覆盖）
- `make_int_type(types, size)` — 辅助：工厂 `getBase(size,TYPE_UNKNOWN)`（varmap.cc:942/1031 同型调用），供 add_guard 的无类型回退与 fallback（gather_spacebase 退役后不再有调用方依赖 size 访问宽）
- `build_variable_name(space, offset, usepoint, ct, index, flags)` — **权威命名覆盖** `ScopeLocal::buildVariableName` (varmap.cc:548)：addrtied 且在 local_range 内走 `<printNameBase>Stack[X|Y]_hex`，否则落到 `build_variable_name_internal`
- `build_variable_name_internal(...)` — `ScopeInternal::buildVariableName` (database.cc:2434)：unaffected/persist/irregular input/param_N/addrtied/extraout/default local 七分支 + 10 次碰撞 bump + makeNameUnique
- `make_name_unique(nm)` — `ScopeInternal::makeNameUnique` (database.cc:2553)：`_NN`(2位)/`_xNNNNN`(5位) 后缀递增
- `find_first_by_name(nm)` / `insert_name_tree(idx)` — `findFirstByName`/`insertNameTree` (database.cc:2733/2712)：SymbolNameTree (name, nameDedup) BTreeMap 模拟
- `rename_symbol(idx, newname)` — `ScopeInternal::renameSymbol` (database.cc:2152)：erase→改名+display→reinsert
- `build_undefined_name()` — `ScopeInternal::buildUndefinedName` (database.cc:2520)：`$$undefXXXXXXXX` 递增序列
- `add_symbol(nm, ct, start, usepoint)` — `Scope::addSymbol`+`addSymbolInternal`+`addMapPoint` (database.cc:1530/1810/1548)
- `build_default_name(idx, base, vn, fd)` — `Scope::buildDefaultName` (database.cc:1756)：entry 路径由 usepoint 推导 flags、function_parameter 用 catindex+1；vn 分支保留（待 ActionNameVars 接入）
- `assign_default_names(base)` — **`ScopeInternal::assignDefaultNames`** (database.cc:2850)：nametree 顺序、共享 `int4 base` 计数器、二次运行幂等
- `set_category(idx, cat, ind)` / `get_category_symbol(cat, ind)` / `get_category_size(cat)` — `ScopeInternal::setCategory`/`getCategorySymbol`/`getCategorySize` (database.cc:2824/2814/2806)
- `symbols_in_nametree_order()` — RUGRA-GLUE：锁定 fixture 的 nametree 顺序只读观察口
- `mark_unaliased(aliases)` — `ScopeLocal::markUnaliased` (varmap.cc:1332-1391) 忠实状态机：按 maptable 条目序（per-space rangemap `(first,size,subsort)` 升序）遍历；**跨条目 sticky 状态**（`aliason` 初 false、alias 游标 `i` 单调推进、rangeIter 不回退）；别名消费循环 `alias[i] <= curoff`（:1358-1361）；**range-tree 走查**（:1363-1375，"别名不穿过 unmapped 区域"：范围 `first > curalias && curoff >= first` 或被越过的范围 `last > curalias` 关闭 aliason，`last >= curoff` 时 break 且游标停在当前范围）；0xffff 距离启发式（:1378，**可变更 aliason 对后续条目生效**）；`setAttribute(nolocalalias)` **只置位不清位**（database.cc:2200-2207 |= 语义）；locked-type 阻断（:1381-1390，`glb->alias_block_level` 默认 2=struct+array 阻断，arch_lookup 接入，fixture 无 arch 回退 0）。2026-09-24 PM-HF 车道 oracle 探针实证（helpf：entry -0xf8 与 alias -0x228..-0x220 相距 <0xffff，仅 range-gap 规则可判 unaliased——旧实现按符号独立重算且无 range 走查，判 aliased 致 RuleIndirectCollapse 拒折 6 个 free-阻 INDIRECT，oppool1 count 118 vs 110）
- `find_symbol(offset)` — 按偏移查找重构后的符号

**命名状态字段**（database.hh:809/805, varmap.cc:345-348）：`symbols: SymbolStore`
（**稳定槽位 arena，2026-09-26 PERF-VARMAP-REMOVE-REKEY-0001**——database.hh:795-813
ScopeInternal 无符号向量，Symbol 对象由 nametree 按指针拥有；Rugra 以
"分配即新槽位 id、删除即墓碑"复刻指针身份，id 永不复用、跨删除稳定）、
`nametree: BTreeMap<(String,u32),usize>`（值=稳定槽位 id，erase 零重键 database.cc:2148）、
`category_lists`（`Some(id)`=稳定槽位 id）、`local_range: Vec<(first,last)>`（symboltab 并集范围树——resetLocalWindow
装入的 localRange ∪ paramRange，`longest_fit`/`local_range_remove_range`/`in_scope` 消费）、
`proto_local_range: Vec<(first,last)>`（**原型自身 localRange** 缓存——buildVariableName 的门，
varmap.cc:555；正偏移参数在并集内但不在本窗口，命名落入 ScopeInternal 分支）、`min_param_offset`/
`max_param_offset`（markNotMapped parameter=true 更新，varmap.cc:519-524）、`stack_grows_negative`、
`register_names`（Translate::getRegisterName 表，translate.hh:380 的调用方装填桥——fixture 回退路径）、
`arch_lookup: Option<Arc<Architecture>>`（生产路径：Ghidra ScopeInternal 自带 `glb` 指针，
database.cc:2447/2454/2462/2472/2485 的 getRegisterName 读 `glb->translate`；Rugra 的
ScopeLocal 是 plain struct，由 `set_arch_lookup` 在 scope 构造时挂 Architecture，
`get_register_name` 优先委派 `Architecture::get_register_name`——sleighbase.cc:144-168
的忠实端口，B3-VARMAP-REGNAME-0001）。

## 当前限制

varmap 算法层（RangeHint/AliasChecker/MapState/ScopeLocal）已 1:1 对齐 Ghidra。
尚未完成：
- ~~**集成到 printc.rs**：变量命名仍用启发式 get_stack_variable_name，未走 ScopeLocal 符号查找~~ → 2026-08-15 已完成：printc 消费 `assign_default_names` 建立的权威名（见 printc.md），命名源切换
- alias_block_level 配置（影响 markUnaliased 的 struct/array 阻断）
- ~~LoadGuard/StoreGuard 在 gatherOpen 中的 addGuard 路径~~ → 2026-08-25 VARMAP-GATHEROPEN-GUARD-0001 已移植（MapState::addGuard + gather_open 消费 `fd.heritage.load_guard/store_guard`），锁定 oracle 双侧 fixture 验证
- coreaction.rs ActionActiveParam 的 `AliasChecker::new(1)+gather_internal` 改走 `gather`（coreaction.cc:1731 `aliascheck.gather(&data,stack,true)` 的 defer 语义 + deriveBoundaries）——fspec/coreaction 租约外，登记 VARMAP-ACTIVEPARAM-GATHER-0001
- fspec.rs `check_input_trial_use` 缺 fspec.cc:5618 `!getLocalRange().inRange → markNoUse` 与 callee_pop 分支（fspec.cc:5619-5625）——func_proto_local_range 桥已可供，fspec.rs 租约外，登记 FSPEC-TRIALUSE-LOCALRANGE-0001
- derive_boundaries 的 direction==-1（正向增长栈）分支无 fixture 驱动（fixture 栈为负增长；可构造分歧输入需正向增长 SpacebaseSpace）
- TYPE_PARTIALSTRUCT/PARTIALUNION 在 addFixedType 的处理（Rugra 无此元类型）
- buildDefaultName 的代表 Varnode 分支（database.cc:1759-1771）已移植但无 fixture 驱动（需活 Funcdata/HighVariable；绑定 ActionNameVars caller 闭包）
- ~~真实 Translate 寄存器表接入 ScopeLocal::register_names（生产管线 Architecture 桥接待做）~~ → 2026-08-25 B3-VARMAP-REGNAME-0001 已完成：SLEIGH 全量注册名表（`SleighBase::getAllRegisters`，sleighbase.cc:182-186）由 driver 装入 `Architecture::register_xref`，`ScopeLocal::set_arch_lookup` 挂 Architecture 后 `get_register_name` 委派 `Architecture::get_register_name`（sleighbase.cc:144-168 忠实端口：upper_bound+iter-- = key≤probe 最大元素、覆盖判定 `off+size≥off'+size'`、回走 base-offset 断裂即空）；ActionRestructureVarnode 构造 scope 时接线，无 Architecture 的 fixture 走原 flat 表回退。E2E：`in_register_0000002x` 族裸名 40 处 → `in_RSP`/`in_R8`/`in_RDX`/`in_R9`（与 golden 的 database.cc:2470-2475 产物同形），唯一残差 `in_register_0000003c`（CW 2 字节 vs 4 字节 probe 不覆盖——lifter flag 读取结构性差异，登记 RULE 家族残差）
- Symbol::symbolId 分配（database.cc:1813-1816）与 multiEntrySet 维护：Rugra LocalSymbol 单整映射模型暂无对应物

测试：varmap::tests 26 个（compare/contain/reconcile/preferred/merge/absorb/const_absorbable/
build_variable_name×2/assign_default_names 共享计数器/make_name_unique 后缀/param category/
typelock 存留/name_dedup/$$undef 序列/mark_unaliased/restructure/spacebase）。
锁定 oracle：`tools/run_varmap_naming_oracle.sh`（VARMAP-NAMING-0001，六 case 投影 MATCH）、
`tools/run_scope_fake_input_symbols_oracle.sh`（VARMAP-FAKEINPUT-0001，八 case 全观察点 MATCH：
paramrange 首字节过滤/重叠吸收+standalone 对照/相邻不合并/跨 space 断裂/typelock 整组跳过/
lockedinputs breaker 与 leader-only 双向/翻转栈 max 边界回绕异常经 warningHeader 继续）。

### 2026-06-27（会话3 续）：MapState::hint_count（诊断）

- `MapState::hint_count() -> usize` — 诊断辅助：返回已收集的 RangeHint 数量。用于核实 gather_spacebase 的实际产出（发现多数函数返回 0，定位 G3 阻塞根因）。

### 2026-06-27（会话3 G3 深水区诊断）：uVar 碎片根因实证定位

通过 `examples/diag_stack.rs` 实证诊断 curl 函数的 P-code，确认 uVar 碎片的**两个根因**：

**根因 A：def 链断链（主要）**
`inject_raw_ops` 为每个 op 的 input 创建**全新的** varnode（`create_with_space`），而非复用产出该地址的 op 的 output varnode。例如 myprogress 的 `STORE@0x34f0` 地址是 `INT_ADD(COPY(INT_SUB(RSP,0x258)), 0x248)`，但 STORE 的 input varnode 是新对象（`Unique:0x1018`），其 def=None——与产出它的 INT_ADD 的 output 是不同 Arc。

`resolve_rsp_offset` 已正确处理 COPY/INT_ADD/INT_SUB 递归，但因 def 链断裂，递归到 def=None 就终止。

**根因 B：参数指针基址（次要）**
my_fwrite 的 `LOAD@0x3475` 是 `INT_ADD(param_4=Register:0x8, 8)`——参数指针解引用，正确地**不应**被当作栈访问。这类"碎片"其实是参数访问。

**为何不能简单复用 varnode**：尝试在 inject 里 `find_by_loc` 复用同 (size,offset) 的 varnode，导致 7 个 SSA 测试失败——Rugra 的 SSA 基于 Arc identity 区分定义点，合并对象破坏了 SSA 语义。正确方案需重新设计 def 链建立（heritage 后统一），非 inject 时合并。

**剩余工作**：重新设计 inject/heritage 的 def 链建立，使 LOAD/STORE 的地址 varnode 能追溯到产出它的 op（保留 SSA 独立性的同时建立 use-def）。这是 G3 的核心阻塞。

诊断工具 `examples/diag_stack.rs` 保留，可打印任意函数的 LOAD/STORE def 链 + scope symbol 数。

### 2026-06-27（会话3 G3 续2）：resolve_rsp_offset_via_bank 重新启用 — spacebase 解析恢复

- `resolve_rsp_offset_via_bank(addr, fd)` — 只读空间回查：当 addr varnode 的 def 链断裂（inject 创建独立 def-less 输入 varnode），在 vbank 中查找同 (space, offset) 且有 def 的 varnode，通过它解析到 RSP 派生偏移。**不修改任何 varnode**（保持 SSA identity），作用域仅限 varmap 的 gather_spacebase。

**关键决策**：此前全局 def-linking（inject Phase 4）虽正确解析栈符号（helpf 10 个），但扰动 typeop 推断（struct 指针类型泄漏到 switch/算术上下文）。via_bank 只读法**不扰动 typeop/copyprop**，避免回归。

**验证效果**：helpf 的栈符号解析 StackX 使用 5→9（scope 10 符号中 9 个被引用）。配合 printc scope 声明增强（声明所有 scope 符号），输出 24/24 + 29/29 全绿。

**uVar 碎片**：spacebase 修复的是*栈变量*恢复，而 uVar_N 是 SSA 中间临时碎片（main 69 个），属 printc 表达式内联问题（独立子系统）。

### 2026-06-29：ScopeLocal::mark_not_mapped + has_overlap
- `mark_not_mapped(offset, size, parameter)` — 忠实移植 Ghidra `ScopeLocal::markNotMapped`（varmap.cc:510-546）。从符号列表移除与范围重叠的符号。用于 ActionRestrictLocal 防止特定栈位置（保存的寄存器、调用参数）被当作局部变量。
- `has_overlap(offset, size)` — 检查范围是否与任何符号重叠。

### 2026-07-01：query_by_addr
- `ScopeLocal::query_by_addr(offset, size) -> Option<(&LocalSymbol, i32)>` — 查栈范围匹配符号，返回符号+偏移（partial read）。
<!-- annotation-pass: 2026-07-04 -->
 

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`LocalSymbol` 增补 `space`/`is_dynamic`/`hash` 字段：linkSymbol 建立的
register/unique/ram 空间符号与 restructureVarnode 的栈符号共用
`ScopeLocal::symbols`，`find_symbol` 及 funcdata.rs 各扫描改为按空间过滤。
`ScopeLocal::add_symbol` 携带空间参数（Ghidra addSymbol 的 Address 语义）；
新增 `add_dynamic_symbol`（database.cc:1690-1701）与 `query_properties`
（database.cc:1263-1281：最小包含 + use-limit 判定，动态项不可按址查询）。
`buildDefaultName` 无 vn 路径改用符号自身空间；vn 路径的
`HighVariable::isInput` 读取前先 `update_flags()`（variable.hh:200 的惰性
updateFlags 语义）。

## ScopeInternal 查询层 r2（SCOPELOCAL-QUERY-0001，2026-08-23）

r1 复核 REJECT 的逐项关闭：查询层从「符号级 Vec+min_by_key」重构为
**条目级 rangemap 委托**（复用 RANGEMAP-COMMON-REFINEMENT-0001 已对拍的
`src/rangemap.rs`），遍历序/subsort tie-break/等价键插入序由该组件的 43/43
oracle 证据承担：

- `EntrySubsort`（database.hh:107-134）——`(useindex, useoffset)` 全序，
  `minimum()/maximum()` 对应 `EntrySubsort(false)/(true)`；`ghidra_space_index`
  按锁定 x86-64 oracle 实测（const=0、unique=2、ram=3、stack=8，
  fixture setup 记录双端核对）。
- `LocalMapEntry`（database.hh:75 SymbolEntry）——一条静态映射
  `{sym, space, start, size, offset, extraflags, uselimit, subsort}`；
  `uselimit` 为 `(space index, first, last)` 区间表（空=全程有效=符号
  addrtied，database.cc:1149-1150 的符号级标志由任一空 uselimit 条目置位）；
  `offset>0` 表达 partial piece（join 拆片，database.cc:1156-1177）。
  `ScopeLocal::mapentry_log` 为插入序条目日志（maptable 数据源），
  `materialize_maptable` 每查询按序重放成 `RangeMap`（`ScopeLocal: Clone`
  无法持有非 Clone 的 RangeMap；等价键插入序与 erase 后幸存者相对序由
  重放保真，fixture 的 removal 案例覆盖）。
- `clear_symbols_wholesale`（RUGRA-GLUE，2026-09-26 GENWIRE）——funcdata
  startProcessing/clear 两 seam 的 wholesale-clear 配套（Ghidra
  `localmap->clearUnlocked()` 投影）：symbols + nametree +
  category_lists + mapentry_log **同拍清空**。oracle 侧符号经
  clearUnlocked→removeSymbol 死亡时其 maptable 条目
  （removeSymbolMappings，database.cc:2117-2136）与 nametree/category
  引用（database.cc:2148-2149）原子同步消亡——派生状态永不持有死符号
  引用。Rugra 的 `SymbolStore::clear` 清空 arena 后 slot id 从 0 复用，
  若 id 配对结构（nametree/category_lists/mapentry_log）单方残留：
  mapentry_log 陈旧条目在 materialize_maptable/entry_in_use 索引死槽
  panic（重启第二遍首现，PIPE-RESTART-0001 链②），nametree 残留 key
  会把名字解析错绑到 id 复用后的新占位符号（find_first_by_name 的
  liveness 检查对复用 id 通过）。单删路径（remove_symbol）本就配对
  （retain+erase+remove_slot）；本方法把同一配对纪律延伸到整体清 seam。
  typelock 幸存偏差不变（MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001）。
- `add_map_entry`（database.cc:1843 addMapInternal）——条目安装（无属性折入
  的生产形态，`property` 恒 0——Database 未接线，DB-LOCALSCOPE-MAP-0001）：
  委托 `add_map_entry_with_property`。
- `add_map_entry_with_property`（database.cc:1843 + addMap 折入
  database.cc:1149-1153）——空 uselimit 置符号 addrtied **并**把
  `property(space, start)`（`glb->symboltab->getProperty(entry.addr)` 的
  flagbase 查询）OR 进 `LocalSymbol::property_flags`（符号级，一次性，
  装图时折入；后装属性区间不污染已装符号——victim 构造序）；uselimit 按
  `(index,first)` 排序并合并相邻（address.cc RangeList 语义）、subsort 在
  插入时冻结（rangemap.hh:238，属性位不入 getSubsort，database.cc:98-106）。
- `install_symbol`——fixture/测试构造路径（addSymbol+addMapPoint 单条目镜像；
  动态符号不装静态条目；零属性闭包）。`add_symbol` 生产路径现在同步建条目。
- `install_symbol_with_property` / `install_symbol_addmap`（database.cc:1530 +
  1126-1155）——完整 addMap 规则集：全局 scope 置 `LocalSymbol::persist`
  （database.cc:1131-1132）；`addmap` 形态另带全局发现域闭包
  （`glbScope->inScope`，database.cc:1138）——命中置 persist **并清 uselimit**
  （database.cc:1140），清空后的 uselimit 进入 addrtied+折入分支
  （db_localscope_map_1204 的 fold_discovery 决定性案例）；空 uselimit 折入
  property_flags。`entry_all_flags` 把 persist/property_flags 投影进
  getAllFlags（database.hh:271）。
- `find_overlap`/`find_overlap_entry`（database.cc:2392）——直接委托
  `RangeMap::find_overlap`：`(last,subsort)` 最左相交分区单元的 owner。
  oracle 实测怪癖：等值等 subsort 的二次插入会以 hinted+tail 双 part
  「包夹」首条（rangemap.hh:223-277 的 break-不更新-f 路径），双向遍历都
  答**后插入者**——Rust rangemap 同构复现，fixture equal_subsort 双案覆盖。
- `find_addr`/`find_addr_entry`（database.cc:2224）——
  `find_with_subsort(point, min, EntrySubsort(usepoint))` 窗口的 `.rev()`
  反向走：精确起点 + `entry_in_use`（database.cc:114：addrtied 全程有效，
  否则 uselimit 区间**包含**判定 + 空间维——跨空间 uselimit 区间不匹配
  代码空间 usepoint）。
- `find_container_entry`（database.cc:2250）——反向走 + 严格更小者替换 +
  精确尺寸短路（oldsize 只在 inUse 通过后更新）。
- `query_properties_ex`（database.cc:1263 + 943 stackContainer + 3185
  mapScope）——完整三分支 flags：`getAllFlags`（extraflags|符号
  addrtied/typelock/namelock/global-persist，database.hh:271）、scope-only
  `mapped|addrtied(|persist)|property(addr)`、property-only；parent 以
  `Option<&ScopeLocal>`（`is_global_scope=true`）建模全局 scope 链；
  常量空间短路（database.cc:950）。`query_properties` 旧签名保持
  （linkSymbol 投影，parent=None/property=0 的生产残差）。
- `has_overlap_in(space, offset, size)`——queryProperties 无效 usepoint 探针
  的空间维形式；`has_overlap(offset,size)` 保持无空间签名（funcdata.rs
  mapGlobals 冻结调用面的兼容 shim，遍历日志中出现过的空间）。
- `remove_symbol` 改 pub（database.hh:601 公共入口）并维护条目日志
  （retain）。**2026-09-26 存储重设计（PERF-VARMAP-REMOVE-REKEY-0001）**：
  `symbols: SymbolStore` 稳定槽位 arena 取代 dense `Vec<LocalSymbol>`——
  槽位 id 单调分配、删除仅墓碑化（`delete symbol`，database.cc:2149），
  nametree/category_lists/mapentry_log 全部持稳定 id，**删除零重键**
  （oracle database.cc:2138-2150 指针身份纪律：nametree erase O(log n)+
  rangemap erase，无任何 survivor 引用迁移；旧 dense 形态 `Vec::remove`+
  四处下移重键使 markNotMapped/clearCategory/collectNameRecs 的删除循环
  O(n²)）。容器 Vec-mimicking 面（iter/get/Index/len/push/clear/last/
  IntoIterator）只产生 live 符号、槽位 id 序==压实 Vec 序——旧调用方
  观察序不变；stale id 读作 dead/absent（null `Symbol*` 语义）而非静默
  别名移位后的邻居——**边界（CR-VARMREKEY F1）**：该"读作 absent"仅对
  纯删除产生的陈旧成立；`clear()` 后槽位 id 归零重启，clear 前捕获的 id
  会别名重填入同槽的新符号（与旧 `< len()` 检查同样别名），可观察行为与
  dense 基线恒等（pre-clear 陈旧因所有持有者跨 clear seam 重新同步而
  今日不可达）。micro-bench（/dev/shm/rugra-tests/varmrekey/bench，
  n=8000/删半）：legacy 240.9ms → new 59.3ms（4.1×，legacy 二次方增长）。
  `in_scope`（database.hh:597 rangetree.inRange 全包含）。

验证：varmap:: 43/43 单测绿；`tests/oracle/scopelocal_query_1204` 27 记录
（equal-subsort 双向、wide/narrow 双序、多 uselimit 二区间/间隙、跨空间
存储、多映射+删除重查、findContainer 最小/等值 tie、partial offset 拆片、
queryProperties 三分支+parent+常量、markNotMapped 窗口分裂）双侧逐字节
MATCH。残差：multiEntrySet/wholeCount 迭代无查询可观察（未建模）、
addMap 属性折入符号 flags（database.cc:1153）与 Database flagbase 归
DB-LOCALSCOPE-MAP-0001、生产 mapGlobals/linkSymbol 消费者不线程 parent/空间
归 funcdata 轮（r1 REJECT 第 4 项）。


## 动态符号化投影锁定（VARMAP-DYNAMICSYM-0001，2026-08-23）

`PRINTC-UNLINKED-REF-0001` 的 varmap 域残差（explicit 未符号化 high 走
buildDynamicSymbol）以 `tests/oracle/varmap_dynamicsym_1204` 三件套 +
`tools/run_varmap_dynamicsym_oracle.sh` 锁定（pin-base schema2，base
e9baabd，无源码 overlay——基线链路已忠实，fixture 是 B2 证据而非修复）：

- **explicit 冲突 → 动态符号**（`explicit_conflict_dynamic`）：同存储、同
  指令地址定义的两个 explicit high——第二个 `linkSymbol` 的
  `queryProperties` 命中首符号的单点 uselimit，`handleSymbolConflict`
  在 loc-set 走查中发现异 high，`buildDynamicSymbol`（funcdata_varnode.cc:
  1283-1306）经 `DynamicHash::uniqueHash` 建动态 Symbol（database.cc:1690
  `addDynamicSymbol`：$$undef 名 + 哈希映射 + 单地址 uselimit），namerec →
  `buildDefaultName` vn 路径 → `ScopeInternal::buildVariableName` 局部分支
  共享计数器命名（iVar3/uVar4）→ `renameSymbol`。12/12 记录双侧逐字节
  MATCH。
- **uselimit 门**（`separate_usepoints_two_statics`）：同存储不同 usepoint
  → 两个静态符号，动态路径不触发。
- **implied 拒绝**（`implied_conflict_rejected`）：implied 成员在
  `hasName`（variable.cc:729-733）处被拒，linkSymbol 不运行——implied
  语义零改动（与 varmap_unlinked_locals 基线一致）。
- **input/addrtied 附着**（`illegal_input_attach`/`addrtied_attach_conflict`）：
  handleSymbolConflict 的 isInput/isAddrTied 腿（cc:1000-1003）附着既有
  条目，不建动态符号；栈分支经 cspec localrange 窗口命名 iStack_c0。
- **spacebase 拒绝**（`spacebase_input_rejected`）：unaffected+spacebase
  输入在 cc:737-745 被拒。

**E2E 残差归因（fixture 排除 varmap 域缺口）**：curl 6 函数的
`uVar_<unique偏移>` GLUE 兜底名（printc 注入组）不是 varmap 缺路径——
explicit 代表所在 high 混入 implied 实例（如 my_get_token unique+0x23b00：
15 实例含 3 implied），`hasName` 在 linkSymbol 之前拒绝。oracle 序
markimplied(:5720) < mergetype(:5727) 在 Rugra 注册正确，但
`ActionMergeRequired`/mergeOp 把同槽实例强并入一个 high 后，Rugra 的
`check_implied_cover` 近似（静态聚合 cover）标出 mixed 而 Ghidra 的
inflateTest cover 模型对已合并 high 整体判 explicit（Ghidra 中 mixed 态
不可达——hasName 会 throw "Implied varnode has been merged"）。修复归
merge/cover 域（`MERGE-MIXEDHIGH-0001`：merge.rs `inflate_test` /
coreaction.rs `check_implied_cover`）。另有 `DYNAMICSYM-PROD-0001`
（ActionDynamicSymbols stub：attemptDynamicMappingLate 未接）、
`DYNAMICSYM-EQUATE-0001`（常量 equate 腿经 ActionNameVars 投影不可达）、
`VNCREATE-PROPS-0001`（newVarnode 的 setVarnodeProperties scope-ownership
查询：Rugra set_varnode_properties 查 flat symbol_table 而非
ScopeLocal::queryProperties，创建期 mapped 位与 oracle 不同）。

## 引用行号勘误（2026-08-24，root，getstr 复核必改项）

survivor-clear 注释引用 varmap.cc:1273 修正为 1259（`clearUnlockedCategory(-1)` 实际位置；1275 是 function_parameter 的另一调用）。

## RESIDMAP-NEGRIDX-PRINTFAMILY-0001（2026-09-24，wt/idxemit，基 3925922a）

A 族 varmap 侧前提补全：`resolve_rsp_offset_signed`（RSP 派生地址的常量偏移回解，
服务 gather_spacebase 的固定 RangeHint 合成）新增两个臂，语义对齐
AliasChecker::gatherOffset（varmap.cc:817-855）：

- **PTRSUB 臂（cc:830-834，与 INT_ADD 同构）**：`base_off + 常量字节偏移`。此前所有
  PTRSUB 寻址的栈访问（`lea` 形 load/store 的规则产物）对 hint 合成不可见。
- **PTRADD 臂（cc:839-849）**：常量索引贡献 `index * stride`；非常量索引仅当
  stride==1 时继续跟进（oracle 注释原文 "We only follow getIn(1) if the PTRADD
  multiply is by 1"），其余形态（变索引×非 1 步长）不可解为固定栈偏移。

与 gatherOffset 的差异（有意，注释在案）：oracle gatherOffset 是宽松部分和（叶节点
贡献 0 继续累加），本解析器严格（任一项不可解即 None）——调用方合成的是**固定**
RangeHint，oracle 中固定 hint 只来自常量地址 varnode（MapState::gatherVarnodes
varmap.cc:1124），变索引（open）引用走 gather_open 通道。

实证：httpd main 正向下标族（`puVar10[0xb]` 等）经此臂获得符号化前提后由 printc
下标发射消费，E2E httpd −160；包装偏移合计 wrapping_add/wrapping_mul 与 oracle
uintb 模 2^64 算术一致。机制 C：本改动落在 varmap AliasChecker 域，commit 已请求
独立 Cross-Review。

## 2026-09-26（F7NAME lane）：NameRecommend 存储与恢复链（HTTPDMAIN-F7-NAMERECOMMEND-0001 机制半）

`ScopeLocal` 补齐 varmap.cc 的名字推荐存储+恢复链（此前 coreaction.rs
ActionNameVars::apply 的 cc:2984 调用点是 RUGRA-GAP 明文"no name-recommendation
store is ported yet"）：

- **`NameRecommend` / `DynamicRecommend` / `TypeRecommend`**（varmap.hh:36/56/74）
  — 三个推荐载荷结构：静态（空间+偏移+usepoint+尺寸+名+symbolId）、动态
  （usepoint+hash+名+id）、类型（空间+偏移+Datatype）。`ScopeLocal` 新增
  `name_recommend` / `dyn_recommend` / `type_recommend` 三列表（varmap.hh:
  214-216）。
- **`collect_name_recs()`**（varmap.cc:357-381）— 把 name-locked 但非
  type-locked 的符号降级为名字推荐并移除（category<0 者），nametree 序遍历；
  "this"指针臂（指向 struct 的指针类型）在降级前经 `add_type_recommendation`
  保留数据类型（cc:367-377）。Rust 索引稳定 seam（**2026-09-26 稳定槽位形**）：
  快照 nametree 序后按序在**同一快照 id** 上重放 `add_recommend_name`（即时
  移除）——SymbolStore 槽位 id 跨删除稳定（oracle `*iter++` 指针稳定性），
  追加序/移除时机/终态与 oracle 单循环一致（CR-F7NAME 校过的 dense-shift
  校正术随存储退役，可观察集/序/时机逐字保持）。调用点=ActionRestructureVarnode
  scope 构造块尾（localdb decode 边界，varmap.cc:476 `ScopeLocal::decode` 尾调
  语义）。
- **`add_recommend_name(sym_idx)`**（varmap.cc:1600-1618）— 静态映射入
  name_recommend（addr+usepoint+size+name+id），动态映射入 dyn_recommend；
  category<0 移除符号。LocalSymbol 新增 `symbol_id`（database.hh:184）与
  `this_ptr`（database.hh:208 dispflags 位）两字段承载恢复契约。
- **`recover_name_recommendations_for_symbols(fd)`**（varmap.cc:1507-1570）—
  ActionNameVars::apply 在 lookForFuncParamNames 之前调用（coreaction.cc:2984，
  RUGRA-GAP 关闭）：无效 usepoint 臂=findOverlap+地址相等+符号 addrtied+
  findLinkedVarnode（**无尺寸门**，cc:1518-1527）；有效 usepoint 臂=
  param_usepoint（fd 地址−1）走 findVarnodeInput、否则 findVarnodeWritten
  （vbank.find_vn），符号非 addrtied+首整映射尺寸相等（cc:1540）；命中后
  renameSymbol(makeNameUnique)+setSymbolId+namelock+remapVarnode。动态尾=
  DynamicHash::findVarnode 逐条同链（cc:1553-1569）。
- **`apply_type_recommendations(fd)`**（varmap.cc:1574-1584）— ActionInferTypes::
  apply 头部调用（coreaction.cc:5398 位置）：输入 varnode 命中推荐地址即
  `updateType(dt, true, false)`（锁入不覆写）。当前唯一生产者=collect_name_recs
  的 this 指针臂；funcdata_varnode.cc:1725-1742 的第二生产者
  （checkParamTypeRecommendations）属参数分析域未移植——登记
  **VARMAP-PARAMTYPERECOMM-0001**（has_type_recommendations 访问器已备）。
  **CR-F7NAME 复审修**（同 commit）：恢复链 invalid-usepoint 臂的 vn 解析按
  entry 自身 uselimit 取 first-use 地址（database.cc:122-127：空 uselimit=invalid
  Address → findLinkedVarnode 的 addr-tied 扫描臂 funcdata_varnode.cc:1233-1241；
  有限 uselimit=首 range 首地址 → usepoint-in-range 扫描臂 :1242-1249——修前误传
  存储偏移，恒走扫描臂）；remap 传参改用 rename 后的最终唯一名（oracle 传 Symbol
  本体 funcdata_varnode.cc:1104-1126，修前传 pre-unique 推荐名，碰撞去重时
  symbol_table 记录名≠符号名）；新增真 vbank 双侧 fixture（addr-tied 正/负 +
  uselimit 有限正/负）覆盖修前 UNTESTED 分支。

可观测性：TYPESEED committed locals 全部 name+type-locked、平台参数符号
name+type-locked，故当前所有语料下三存储恒空、恢复链恒 no-op（与 oracle
httpd canon 的空 localdb 推荐态一致——`__s1` 类局部名来自
lookForFuncParamNames 的锁定原型参数名通道，非本存储）。9 个单元测试覆盖
降级/移除/nametree 序/参数类目存活/恢复重命名/地址不匹配跳过/无效 usepoint
臂无尺寸门（oracle 语义文档化）/类型推荐存储/this 指针臂。机制 C：varmap
核心算法白名单——CR 已请求（见车道终报）。
### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor
- 本模块 4 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
