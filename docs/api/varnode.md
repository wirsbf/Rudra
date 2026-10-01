# `varnode.rs` API Reference

**源代码路径**: `src/varnode.rs`

## 2026-09-30（同日第二笔）：SpaceOff 投影 offset 修复 + vn_by_id

- **`space_off_of_address` 修复（红线事件, 见车道终报 §2）**: 无空间 legacy
  Address 原投影为 `SpaceOff::null()`（offset 硬编码 0）——def-op 的 pc offset
  被清零, written varnode 的 def-SeqNum 排序从 oracle `(pc, uniq)`
  （SeqNum::operator<, address.hh:154-158）退化为 `uniq` 单键, inject 路径
  （pc 序≠创建序）下两 varnode 交换树序 → canon curl 变量重编号漂移
  （md5 c4cc29a7, 74 hunk 全重命名零结构差）。修复 = null 空间码 + 真实
  offset（`Address::operator<` (None,None)→offset 的逐字投影）。canon 双面
  修复后回钉值。
- **`VarnodeBank::vn_by_id(VnId)`**: id→存储 Arc 的解析（`Funcdata::vn_by_id`
  的底层; P1 读形态, W1(b) 交接面）。

## 2026-09-30：PERF-ARENA-FLIP-0001 (a) — VarnodeBank 双树 POD 键化 + 存储迭代器 arena 单元

`VarnodeBank` 的两棵排序树从 `BTreeSet<VarnodeLocRef>` / `BTreeSet<VarnodeDefRef>`
（比较器 `Ord` 每侧一次 RwLock 读——VARMAPOPCREATE 实测 398,450 次下降 / 1.47s 锁税）
翻转为 **POD 键映射** `VarnodeLocSet { BTreeMap<VnLocKey, VarnodeLocRef> }` /
`VarnodeDefSet { BTreeMap<VnDefKey, VarnodeDefRef> }`（键类型 = W0 冻结的
`src/arena.rs`，序由单测对 varnode.cc:34-79 逐字转写差分锁定）：

- **键投影单点**（ARENA_DESIGN §5 R2）: `vn_loc_key` / `vn_def_key` /
  `vn_def_state` / `vn_space_off` / `space_off_of_address`。字段序逐字段复刻
  `VarnodeCompareLocDef`（varnode.cc:34-53: address_space→loc→size→(f-1) 旗标
  排名→written:defSeqNum / free:createIndex）与 `VarnodeCompareDefLoc`
  （varnode.cc:60-79: 旗标→written:defSeqNum 相等落到 addr→addr→size→
  free:createIndex）。`AddressSpace` 投影打包 `(space_id, 枚举判别)` 为单个
  u32（`compare_address_spaces` 的全序），`Varnode::loc` 的 `Option<SpaceTag>`
  以 stride 打包（所有 bank varnode 的 loc 均为无空间 legacy Address，
  debug 断言边界）。
- **桥接面（消费层零改动）**: `loc_tree`/`def_tree` 公共字段类型换为包装集合，
  保留 `iter()` / `&set` IntoIterator（产出 `&VarnodeLocRef` / `&VarnodeDefRef`）/
  `range(bounds)`（DoubleEnded，probe 键翻译）/ `insert(v) -> bool`（重复键
  keep-first，= `BTreeSet::insert`）/ `len` / `is_empty` / `contains` / `clear` /
  Debug set 形态。heritage/merge/varmap/coreaction/printc/flow 与 examples/tests
  的全部既有调用形态不变。
- **存储迭代器（stored-iterator）擦除**: 新增 `vn_arena: Arena<VnCell, VnId>` +
  `Varnode::vn_id` 回指。每个 bank 分配的 Varnode 在 `allocate` 时占一槽，cell
  持反规范化 `loc_key`/`def_key` 副本，仅在 oracle 的擦除+重插位点
  （`insert_free`/`xref`/`make_free_prevalidated`）刷新。
  `erase_loc_identity`/`erase_def_identity` 主路径按 **cell 内存储键** 删除并校验
  Arc 身份（= oracle `loc_tree.erase(vn->lociter)`，varnode.cc:1282-1283/1319-1320/
  1366-1367/1396-1397，O(log n)，对 `Funcdata::destroyVarnode` 先清 def 造成的
  live-key 漂移免疫）；cell-less（手搓 fixture 直插集合面）走原 live-key take +
  身份 retain 兜底。gen 守卫：`clear()` 后历史句柄 `vn_id` 查询得 None → 兜底路径。
- **迭代序恒等论证**: 键序 = 比较器投影全序（W0 单测锁），键仅在 oracle 同位点
  重算 ⇒ 与原 BTreeSet 序归纳同构；`xref` 去重 `get`、`find_free` 精确键 `get`、
  `set_input_varnode` 的 `def_tree.range(..search).next_back()` 前驱查询
  （funcdata_varnode.cc:346-361 形态）全部按 POD 键执行，结果与 live 比较器在
  树一致态（重键纪律成立）下逐调用恒等。
- 返回类型纯化: `begin_loc`/`end_loc`/`begin_def`/`end_def`/`end_loc_space`/
  `end_def_fl`/`end_def_addr` 与 funcdata.rs 的同名转发器从
  `btree_set::Iter` 具体类型改为 `impl Iterator<Item = &…Ref>`（调用点零改动）。
- 门禁: `cargo test --lib` 2018P/0F/5I 恒等 + 全 integration tests 2025P；
  canon/镜面门禁见车道终报（LANE_ARENAFLIP_A_2026-09-30.md）。

## 2026-10-02：PERF-VARNODE-DESCEND-SHADOW-0001 descend 存活影子（live/len 内联计数）

规则体残量移交项（RULEBODY2 终报 §6 登记、DESCENDSHADOW 车道承接）。[DESCENDPROF]
语料级探针（73.4M `has_no_descend` 调用/16.5M `lone_descend`/14.7M `erase_descend`）
澄清了 RULEBODY2 E2/E3 ≈115ns/try 的真实机理：**不是 tombstone 线性扫长度**（全语料
has_dead=0/erase_miss=0/destroy 终态 census_dead=0——零死条目），而是非空表上
首个条目的解引用链（Vec 缓冲行 + PcodeOp 控制块行，两次相依 cache miss）。oracle
`descend.empty()`（varnode.hh:286）读的是 Varnode 内联的一个字，零额外 miss。

本条为 `descend: Vec<Weak<PcodeOp>>` 增设两个私有内联影子字段并保持判定恒等：

- `descend_live: AtomicUsize` — 存活（`strong_count > 0`）条目数；
- `descend_len: AtomicUsize` — 最近一次精确观测时的 `descend.len()`。

函数形态（判定逐调用恒等，四类决定性语义见车道 Evidence 块）：

- `has_no_descend`（varnode.hh:286）— `all(dead)` ⇔ `live == 0`，影子命中时零解引用
  O(1)（对位 oracle `descend.empty()`）；影子陈旧（`descend_len != len`，仅测试夹具
  raw push 可致）时先全表 reconcile 再作答。debug 构建内联 `debug_assert` 用旧谓词
  逐调用机检影子恒等（测试套件跑在 debug）。
- `lone_descend`（varnode.cc:676-688）— `live == 0` → None（cc:681）；`live >= 2` →
  None 零解引用零 upgrade（cc:687 短路；旧形态在拒绝路径先 upgrade 首后代——
  6.77M 拒绝/语料 次白付原子对）；`live == 1` → 首可 upgrade 项（即唯一存活项，
  与旧全扫描返回同元素）。三臂各带 debug 恒等断言。
- `count_descends` — 全表扫描原形，顺手把影子刷新为精确值（自愈位点）。
- `add_descend`（varnode.cc:330）— free 检查改 `!has_no_descend()`（`any(live)` ⇔
  `!all(dead)` 逐位恒等，含影子 reconcile）；push 后 live+1/len+1（新 downgrade 的
  调用方持有 Arc 构造即存活）。
- `erase_descend`（varnode.cc:316）— 陈旧先 reconcile（保证 fetch_sub 落在精确值上，
  杜绝回绕）；命中项经 upgrade 匹配 = 存活 → live−1/len−1；未命中路径（全表已扫）
  就地精确刷新影子 + 原 WARN 原样。
- `destroy_descend`（varnode.cc:344）— clear 后 live=0/len=0（空表的精确终态）。
- `VarnodeBank::replace` 的两处直接 Vec 操作（逐 occurrence 摘除 + 终态 clear）按同
  一契约维护影子。

**精确性契约**（字段注释全录）：① 生产全部变更走 add/erase/destroy/bank-replace 四
方法（代码审计；字段私有）——曾有一处历史例外：ActionCse::apply（coreaction.rs）的
raw `descend.push`；CR-DESCENDSHADOW 独立枚举（2026-10-02）证伪了原"grep: 非测试
域无 raw push"的主张，该位点已在同批（MB61 整改，`CR-DESC-F1-CONTRACT-FALSIFIED-0001`）
转换走 `add_descend`；② 其余直接变更 = `#[cfg(test)]` 内的 raw `descend.push`
（CR 枚举 27 处），len 快照陈旧检查是**对任意来源 raw push 的通用兜底**——raw push
改变 `len` 不改 `descend_len` → 陈旧检查强制下次观测前全表 reconcile——raw push
永不可能让影子失真，只付一次扫描（理论盲区=保形整体赋值 `descend = vec![..]`
[len 不变内容变]可绕过 len 快照；现库唯一位点 coreaction.rs:22249 为 0→1 变长、
可检测，无现行盲区实例——`CR-DESC-F3-SHAPE-ASSIGN-BLINDSPOT-0001` 注记）；③ 无生产
路径在 descend 列表仍持有 Weak 时丢弃 PcodeOp Arc（= oracle 裸指针链表依赖的同一
不变量，逐 op 销毁路径先 erase）：运行时普查 has_dead=0（73.4M 扫描点）+ erase_miss=0
+ destroy 终态 census_dead=0（1,433,590 张被销毁 varnode 的终态表）于全 sqlite 语料
+ curl/httpd canon 面。假想的未来违例只可能让 `descend_live` 偏高——descend_iter/
erase 匹配仍过滤死条目（可观测输出不变），仅 O(1) 守卫会从陈旧计数作答，且 debug
断言与差分门禁会现形。

同步语义：影子访问全部处于 Varnode 自身 RwLock 纪律下（读者持读锁、写者持写锁），
Relaxed 序即可；原子类型只为 `Varnode: Sync`。

行为恒等验证（车道终报全录）：VdbeExec `--one 1055` stdout md5 15b47cf7 恒等 +
ACTIONSTATS 五值双二进制逐值恒等 + canon curl b7773087/httpd 54f9b02c + corpus
assembled 29f54d21 + 镜面五面钉值 + `cargo test --lib` 2031P。

## 2026-09-29：PERF-OPPOOL-0001 lone_descend 免分配化与 has_no_descend 无计数存活探测

规则池派发热路径（[OPPROF] 钻探：earlyremoval 5.02M 次尝试、TermOrder::collect
每边、multicollapse 每输入）高频调用后代查询，本条削减每次调用的纯常数，判定
结果逐调用不变：

- `lone_descend`（varnode.cc:676-688）— 原实现先 `Vec::collect` 全部存活后代再
  数长度（每次调用一次堆分配 + 全表 Weak upgrade）；现改为单趟免分配扫描：
  `Weak::strong_count == 0` 跳过死引用，第二个存活项即早退（对应 oracle
  `iter != descend.end()` 短路），唯一存活项才 `upgrade`。零/一/多后代三种
  判定与返回的 Arc 与原实现逐调用恒等。
- `has_no_descend`（varnode.hh:286）— 存活探测改用 `Weak::strong_count() == 0`
  （无引用计数往返），谓词语义不变（无存活后代）。Rugra 的 `descend` 是
  `Vec<Weak>`（oracle 是被主动维护的裸指针链表），存活过滤语义原样保留。

VdbeExec `--one 1055` stdout 字节恒等 + canon/镜面门禁见车道 OPPPOOL 报告。

## 2026-08-28：WRITE_MASK 与 AUTOLIVE_HOLD 正交

`set/clear/is_write_mask` 现使用 Ghidra 的 `addlflags::WRITE_MASK`，不再占用主 flags
中的 `AUTOLIVE_HOLD=0x40000000`。这直接关闭了 GetStr 中 writemask-only 临时量被
EarlyRemoval 错误保活的问题；2×2 双侧 fixture 与定向单测均验证 write-mask 和
autolive 可独立设置/清除。

## 2026-08-28：GetStr reader-facing High 与 Architecture 类型身份

`get_local_type`/High read-facing 查询现在让 GetStr `0x36ee` NOTEQUAL 的 LOAD 输出与
size-1 zero 两个精确 input slot 都观察 canonical `char`，配套六阶段 runner 保留
完整 def-use/identity 并验证最终 `*param_1 != '\0'`。这不表示 Varnode 全面对齐：
`Funcdata::set_arch` 接通 Architecture-owned standalone TypeFactory 后，fresh stage 0
的 272 个有序 Varnode 已全部同 raw flags 与完整 type record，其中双方均为
174×`xunknown8` + 93×`xunknown1` + 5×`code`；原 `undefined*` 分叉不再由 GetStr
fixture 观察到。仍未闭合的是 FSPEC/AddressSpace、resolution、High identity 和完整
local-type closure，继续为 `MISMATCH/UNTESTED`。

## 文档状态

- **状态**: 已核对（当前有效）
- **Ghidra 12.0.4 对齐级别**: L2；`VARNODE-INIT-0001` 仅对初始化与若干 bank 有效路径给出 PARTIAL_MATCH，不代表完整 `VARNODE-0001`
- **可信度**: 高
- **文档定位**: 当前源码的接口解释层
- **可信边界**: 以 `src/varnode.rs` 实际代码为准
- **注意**: 本文描述的是 Rugra 当前的 **storage-node / IR data node** 模型，不等同于“与 Ghidra 运行时行为已完全一致”的证明

---

## 模块说明

`varnode.rs` 定义了 Rugra 中最核心的数据节点类型之一：`Varnode`。

在当前实现里，`Varnode` 的职责可以概括为：

1. 表示一个**具备地址空间、偏移和大小**的数据存储单元
2. 作为 P-code / IR 中操作数和结果值的基础承载对象
3. 为后续的：
   - def-use 关系
   - SSA 版本标记
   - 类型传播
   - 变量恢复
   - 输出打印
   提供统一的数据节点模型

它对应的是一种**存储节点 / 数据节点模型**，而不是高层变量本身。  
也就是说：

- `Varnode` 更接近“某个位置上的值”
- 而不是“用户源码里最终看到的那个逻辑变量名”

---

## 设计定位：当前的 storage-node 模型

在当前 Rugra 架构里，`Varnode` 主要围绕以下三个维度组织：

### 1. 位置语义
一个 `Varnode` 首先要能说明"它在哪"：

- 属于哪个 `AddressSpace`
- 偏移是多少
- 占多少字节

这使它可以表示：

- 寄存器值
- RAM 中的值
- 栈槽中的值
- 内部临时值（如 `unique` 空间）
- 常量值（通过特定空间或构造方式表达）

**bank 排序键**（2026-08-13，`VARNODE-INIT-0001`）：`VarnodeLocRef::Ord` 在当前 fixture 的合法、唯一数字 space-id 域内按完整 Address（numeric space id、offset）、size、`input < written < free` 分类排序；written 以定义 op 的不可变 `SeqNum(Address,time)` 破同值，free 以 `create_index` 破同值。`VarnodeDefRef::Ord` 先按同一分类/定义点，再按完整 Address、size、free create-index 排序。两个 wrapper 的 `Eq` 都定义为 `cmp == Equal`，块内 `SeqNum.order` 重编号不会改变键。Rugra enum 可以构造两个不同 variant 却使用同一个数字 id；这种 Ghidra manager 不允许的输入使用稳定 enum tie-break 保持 Rust `Eq/Ord` 合约，但不作为 oracle MATCH。defining-op AddressSpace 仍受简化 Address 模型限制。

**初始状态与 bank 分配**（2026-08-13，`VARNODE-INIT-0001`）：`Varnode::new_with_space` 现在按锁定 Ghidra 12.0.4 `Varnode::Varnode` 初始化主 flags、`nzm` 与 `consumed`：普通存储为 `COVERDIRTY`，常量为 `CONSTANT` 且 `nzm=offset`，IOP annotation 为 `ANNOTATION|COVERDIRTY`，`consumed=~0`。`VarnodeBank::set_def` / `set_input` 对合法 bank-owned free 输入分别形成 `WRITTEN|INSERT|COVERDIRTY` 与 `INPUT|INSERT|COVERDIRTY`，并返回 xref 选出的 canonical `Arc`；重复键会按 descendant 列表顺序重接全部输入槽。`create_def_with_space` 直接走 Ghidra `createDef` 的 allocate→setDef→xref 路径。`make_free` 先按对象身份移除两个树键、突变，再重插，并以 Arc identity 拒绝 foreign/stale equal-key handle。analysis-owned unique 地址从 `0x10000000` 起，并在 `clear()` 后重置到该值。显式 space 在插入两个 `BTreeSet` 索引前即固定。

**makeFree/setInput/setDef 的 stored-iterator 删除语义**（2026-08-15，`VARNODE-BANK-KEY-LIVE-0001`）：Ghidra `VarnodeBank::makeFree`（varnode.cc:1316-1327）、`setInput`（cc:1358-1372）、`setDef`（cc:1380-1404）全部通过保存在 Varnode 内的 `lociter/defiter` 删除树节点——删除从不重算比较键，也没有 ownership 预检。Rugra 原实现用 `BTreeSet::remove(&live_key)` 重算键删除，一旦调用方在 Varnode 树内驻留期间原地突变 key 字段（手搓 fixture 直接写 `def`/`WRITTEN`，或 `Funcdata::destroyVarnode` 先清 def），live key 便不再指向存储位置，删除 miss → `makeFree ownership preflight disagrees with removal` panic（曾致 5 个单测失败与 E2E `ActionSetCasts::cast_output` panic）。修复：新增 `erase_loc_identity` / `erase_def_identity` 模拟 stored-iterator 语义——快路径按 live key `take` 并校验取出的就是该 Arc（防止 live key 撞上其它成员误删，误中则放回），否则退化为 `Arc::ptr_eq` 全树 retain 精确删除该对象；`make_free_prevalidated`、`transition_input`、`transition_def` 三处转换统一改用。debug 断言改为断言「对象确实在树中并被删除」（Ghidra 的构造性前提），不再断言 live-key 一致。4 case 行为门禁 `tests/oracle/setcasts_output_bank_1204.*`（castOutput 语义 opSetOutput 换绑两次、手搓 in-place key drift 后走 opUnsetOutput→makeFree、write→free→rebind→destroy、same-output 早退）对锁定 oracle 字节级 MATCH；A/B 验证旧 key 删除实现在 drift case 即 panic。

**DeadCode 工作队列标记**（2026-08-14，`DEADCODE-SELFLOOP-0001`）：新增
`is_consume_list` / `set_consume_list` / `clear_consume_list`，逐项映射锁定
`varnode.hh:207/209/211` 的 `lisconsume` 访问器。该位表示 Varnode 已在
`ActionDeadCode` 的 LIFO 工作队列中；push 时用于按对象身份去重，pop 后立即清除，
与 `vacconsume`（存在通往正式读取的赋值路径）语义相互独立。

`VarnodeBank::destroy_varnode` 现在返回 `Result<()>`：与 `varnode.cc:1276-1285` 一样，存在 defining op 或任一 descendant 时先返回 `Deleting integrated varnode`，不会改动两个索引；Rust 还以 Arc identity 拒绝 foreign/stale equal-key handle。Ghidra 通过保存在 Varnode 内的 `lociter/defiter` 删除，因此 `Funcdata::destroyVarnode` 先清 def 也不影响定位；Rust 的 `destroy_varnode_prevalidated` 对应改为扫描两个树的 Arc identity 后精确 retain 删除，避免按已突变 key 查找失败。定向测试覆盖 written VN 经过 `setOrder`、清 def 后仍只删除目标且同位置邻居保留。

`Varnode::term_order` 已按 `varnode.cc:1153-1172` 收窄为表达式项排序：两个常量互等且排在非常量之后；written `INT_MULT(base, constant)` 各自剥一层到 `base`；最后只比较完整 Address 的 numeric space id 与 offset，不比较 size。该算法由 `RULE-COLLECTTERMS-0001` 的独立逐函数 oracle 负责最终行为门禁，不包含在初始化 fixture 的 MATCH 分母中。

**默认类型单轨（2026-08-16，`TYPE-WIRING-0001`）**：bank-local `xunknown<size>` adapter 已删除。Ghidra 的 `VarnodeBank::create(s,m,ct)`（varnode.cc:1250）从不自造类型——每个 `Funcdata::newVarnode*` 调用方传入 `glb->types->getBase(s,TYPE_UNKNOWN)`（funcdata_varnode.cc:69/87/107/132/154/179/193/208），即 Architecture 唯一 `TypeFactory`（type.cc:3106）的产物。Rugra 现由 `default_unknown_type` 解析同一工厂对象：`VarnodeBank::set_type_factory` 注入的句柄优先（per-Architecture 通道，Standalone flavor 等测试注入走此路）；无注入时用 `TypeFactory::shared_default()`（DataOrg flavor，模拟 headless oracle 单 Architecture 进程）。生产未知类型因此改拼 `undefined{size}`（核心 1/2/4/8 尺寸为命名核心类型，其它尺寸为未命名 id=0 TypeBase——即 Ghidra `findAdd` 的无名插入），并取得跨 bank 的同对象 identity。`VarnodeBank` 改为手写 `Debug`（工厂句柄无 Debug 面）。原「synthetic fixture caller-supplied TypeBase（xunknownN/id=0/non-core）」投影随之过期：`varnode_init_1204` fixture 的 Rust 侧 `type=`/`type_id=`/`type_core=` 字段将变为 `undefinedN`/hashName/1，需重 pin（登记交 root）。

`Varnode::get_cover` 现在按 `getCover()` 先在 dirty+non-null 分支调用 `Cover::rebuild`，再清 `COVERDIRTY`。fixture 同时证明 raw input sentinel、lazy invocation 和 dirty 清除。**2026-08-15 `COVER-REBUILD-SELFLOCK-0001` 更新**：input sentinel 已按 `getUIndex(2)=0` 语义修正（Rust 直接存 uindex 域 0，见 cover.md 同日条目），此前「sentinel 保存为数值 2 导致的 Cover MISMATCH」不再是当前行为；8 case 完整 Cover 投影（含 slot2 自引用、双槽读、implied 链、setAll 前驱填充）由 `tests/oracle/cover_rebuild_1204.*` 行为门禁覆盖为 MATCH，残差（MULTIEQUAL-tip 旧 stop 判别、INDIRECT 目标 order）见该 metadata 的 coverage 表。

**`update_cover_locked` 与 `self_ref`（2026-08-15，`COVER-REBUILD-SELFLOCK-0001`）**：`Varnode::update_cover_locked(root: &Arc<RwLock<Varnode>>)` 取代旧 `update_cover(&mut self)` 生产入口（`merge.rs::update_high_cover` 改调它）：持 root 写锁 → 快照 def/is_input/descend/is_implied → `Cover::rebuild_from_root_snapshot`（root Arc 仅作身份令牌，MULTIEQUAL 槽匹配用 `Arc::ptr_eq`，descendant op 输出恰为 root 时用快照的 implied 标志避免写锁重入，全程不再锁 root）→ 复位同一 Box → 无条件清 `COVERDIRTY`（对齐 varnode.cc:233-241，含 hasCover 而 cover 对象为 null 时只清 dirty 的分支）。新增 `self_ref: Weak<RwLock<Varnode>>` 由 `VarnodeBank::allocate` 对所有 bank 分配的 Varnode 设置，供 `get_cover` 在 `&mut self` 路径升级出 root Arc；unmanaged Arc（无 self_ref）时保守返回现有 Cover 并保留 dirty。

该窄域不代表完整 `VARNODE-0001` 已完成。除上述 TypeFactory/Cover/SeqNum 残差外，Ghidra unmanaged constructor 可接收 null Address space/Datatype，而 Rugra enum Address 与默认类型 adapter 无法表达该状态；FSPEC 与 IOP 仍合并为一个 Rust enum variant；`Varnode` 的 key 字段仍可被外部 public 直接突变；direct `Varnode::operator<`/`operator==`、public `setDef` duplicate canonical return 与 `replace` 的 defining-op self-edge guard尚未单独对拍；`Funcdata::setInputVarnode` 的 partial-overlap 异常和 ProtoModel 属性传播未由本 bank fixture 证明；外部 `Arc` 在 Ghidra 会 delete 的 xref/clear 后仍可存活；create/unique 计数器溢出、corrupt descendant、HighVariable dirty propagation、32-bit `uintb` 与 big-endian 分支均未闭合。

**varnode 去重（find_or_create_input_space）**（2026-06-29）：新增 `VarnodeBank::find_or_create_input_space(size, space, offset)`——查找已有的同 (space, offset, size) 的 free/input varnode（不含 written），复用它；没有则创建。对齐 Ghidra `Funcdata::newVarnode`（funcdata_varnode.cc:148）——建 free varnode，由 rename 连接到 written。修复了 descend 链碎片化（RSP input 从 1 个 descend 变 64 个）。

**find_input 空间限定**（2026-09-24，`BANK-FINDINPUT-SPACE-0001`，wt/p3batch）：`VarnodeBank::find_input(size, space, loc)` 补空间匹配——对齐 `VarnodeBank::findInput`（varnode.cc:1465-1478）的 `beginLoc(s,loc,Varnode::input)` + `vn->getAddr()==loc` 全地址比较（空间+偏移）。此前只匹配 size/offset：x86-64 寄存器偏移与其它空间不碰撞故无可观察差，但其它 ABI（寄存器偏移与栈/唯一偏移重叠）下会跨空间误命中。消费面经 `Funcdata::find_varnode_input`/`find_spacebase_input`（见 funcdata.md）：RestrictLocal 的 EffectRecord 溢出槽 walk（`effect.space`）、RestructureVarnode 参数 typelock（Register 臂）、spacebase 输入定位（`point.space`=Register 空间）。

**INSERT/activeHeritage flag 模型**（2026-06-29 续）：对齐 Ghidra varnode flag 语义。`VarnodeBank::create` 不设 INSERT（对齐 varnode.cc:1250，free varnode 无 INSERT → `isHeritageKnown` false → rename 处理）。`set_def`/`set_input` 设 INSERT（对齐 createDef/makeInput→xref）。新增 `addl_flags` 模块（ACTIVE_HERITAGE=0x01 等，对齐 varnode.hh:115）。`is_heritage_known()` 检查 `flags & (INSERT|CONSTANT|ANNOTATION)`（对齐 varnode.hh:298）。`set_active_heritage()`/`is_active_heritage()` 访问器。

### 2. 数据流节点语义
`Varnode` 是 `PcodeOp` 的输入或输出节点，因此它天然处于数据流图中：

- 可以被某个操作定义
- 可以被后续多个操作使用
- 可以在分析阶段携带更多附加状态

### 3. 分析附着点
随着分析推进，`Varnode` 还可能承担：

- SSA 版本标记
- flags 状态
- 输入/写入/常量等标签
- 类型与命名恢复的挂载点

因此，`Varnode` 不是一个单纯的“地址 + 大小”元组，而是**可参与整个函数级分析流程的数据节点对象**。

---

## 与其他核心对象的关系

`Varnode` 在当前架构中通常与以下对象强关联：

### 与 `Address`
`Address` 负责表达“位置”的统一语义。  
`Varnode` 通过 `Address` 或 `AddressSpace + offset` 来定位自己。

### 与 `AddressSpace`
`AddressSpace` 决定一个 `Varnode` 属于：

- 寄存器空间
- 内存空间
- 常量空间
- 栈空间
- unique 临时空间
- 其他内部空间

### 与 `PcodeOp`
`Varnode` 是 `PcodeOp` 的输入与输出载体：

- 输入 `Varnode` 表示操作读取哪些值
- 输出 `Varnode` 表示操作定义了什么值

### 与 `Funcdata`
在函数级分析上下文中，`Varnode` 一般不是孤立存在的，而是被组织到 `Funcdata` 的内部图结构中。

### 与变量恢复 / 类型系统
`Varnode` 不是最终高层变量，但它是：

- 变量合并的候选单元
- 类型传播的附着点
- 打印层恢复更高层表示的基础

---

## 常量标志位（Flags）

本模块公开了一组 `u32` 位标志，用来描述 `Varnode` 的状态或性质。

这些标志大体可分为几类：

### 基础身份类
- `CONSTANT`
- `INPUT`
- `WRITTEN`

用于区分：
- 是否是常量
- 是否是输入值
- 是否已被某个操作写入

### 命名 / 类型 /绑定类
- `TYPELOCK`
- `NAMELOCK`
- `ADDRTIED`
- `MAPPED`

用于表达某些语义是否已固定，或是否与特定地址绑定。

### 存储属性类
- `READONLY`
- `VOLATIL`
- `PERSIST`
- `SPACEBASE`
- `RETURN_ADDRESS`

用于表达该节点的存储属性或在调用语义中的特殊角色。

### 间接 / 辅助分析类
- `INDIRECTONLY`
- `INDIRECT_CREATION`
- `INDIRECTSTORAGE`
- `INCIDENTAL_COPY`
- `AUTOLIVE_HOLD`

这类标志主要服务于分析过程和中间状态管理。

### 覆盖 / 精度 / 原型相关类
- `COVERDIRTY`
- `PRECISLO`
- `PRECISHI`
- `HIDDENRETPARM`
- `PROTO_PARTIAL`

这类状态更接近高级分析或恢复阶段使用的辅助标签。

> 注意：  
> 这些 flag 的存在，说明 `Varnode` 不只是一个静态数据结构，而是一个会随着分析过程逐步积累状态的节点对象。

---

## 导出的公共 API

## `pub struct Varnode`

### 语义

`Varnode` 是 Rugra 当前 IR 中的基础存储节点，表示：

- 一个有位置的数据单元
- 一个数据流节点
- 一个可被分析和打印流程继续加工的载体

### 当前模型下应如何理解

请把它理解为：

> “某个地址空间里的某个值节点”

而不是：

> “已经恢复完成的源码变量”

---

## 构造函数

### `pub fn new(size: usize, loc: Address) -> Self`

创建一个新的 `Varnode`。

### 作用
- 直接用现成的 `Address` 构造节点
- 适合已经有统一地址对象的场景

### 参数
- `size`: 节点大小（字节）
- `loc`: 节点位置

### 返回
- 一个新的 `Varnode`

### 说明
文档中提到它带有某种向后兼容语义，但在理解上应以“使用已有地址对象构造存储节点”为主。

---

### `pub fn new_with_space(size: usize, space: AddressSpace, offset: u64) -> Self`

使用显式地址空间和偏移构造 `Varnode`。

### 作用
- 当调用方还没有完整 `Address`，但已知空间和偏移时使用
- 是当前 storage-node 模型里更直观的构造方式之一

### 参数
- `size`: 节点大小
- `space`: 地址空间
- `offset`: 空间内偏移

### 返回
- 一个新的 `Varnode`

---

### `pub fn new_constant(val: u64, size: usize) -> Self`

构造常量 `Varnode`。

### 作用
用于把立即数、字面值等表示成 IR 数据节点。

### 参数
- `val`: 常量值
- `size`: 字节大小

### 返回
- 表示常量的 `Varnode`

### 说明
常量在数据流中仍然以节点存在，因此它依然遵守 `Varnode` 统一接口。

---

### `pub fn new_register(offset: u64, size: usize) -> Self`

构造寄存器空间中的 `Varnode`。

### 作用
表示寄存器上的值。

### 参数
- `offset`: 寄存器空间偏移
- `size`: 节点大小

---

### `pub fn new_ram(offset: u64, size: usize) -> Self`

构造 RAM 空间中的 `Varnode`。

### 作用
表示普通内存中的值。

---

### `pub fn new_stack(offset: u64, size: usize) -> Self`

构造栈相关 `Varnode`。

### 作用
用于表示栈槽、局部变量候选位置等。

### 说明
这很重要，因为后续变量恢复往往会从栈空间节点出发。

---

### `pub fn new_unique(offset: u64, size: usize) -> Self`

构造 unique 空间中的 `Varnode`。

### 作用
表示内部临时值、提升阶段或中间运算阶段产生的临时节点。

### 说明
这类节点通常不是最终用户想看到的源码变量，而是中间 IR 的内部载体。

---

## 位置与空间访问接口

### `pub fn get_addr(&self) -> &Address`

返回节点的完整地址对象。

### 用途
- 获取统一位置表示
- 用于排序、显示、关联其他图节点

---

### `pub fn get_space(&self) -> AddressSpace`

返回节点所属的地址空间。

### 用途
判断当前节点属于：
- register
- ram
- stack
- unique
- const
- 其他空间

---

### `pub fn get_offset(&self) -> u64`

返回节点的偏移。

### 说明
偏移的意义依赖于 `AddressSpace`。  
不能脱离空间单独解释。

---

### `pub fn offset(&self) -> u64`

返回偏移。

### 说明
这是较短形式的访问接口，与 `get_offset()` 属于相同语义层。

---

### `pub fn space(&self) -> AddressSpace`

返回地址空间。

### 说明
这是较短形式的访问接口，与 `get_space()` 属于相同语义层。

---

### `pub fn get_val(&self) -> u64`

返回底层值语义。

### 说明
这个接口通常更适用于：
- 常量节点
- 或某些将节点值视作原始整数的场景

使用时应注意：
- 它不自动等价于“高层可直接显示的值”
- 在不同空间中的语义并不相同

---

### `pub fn constant_value(&self) -> Option<u64>`

若该节点是常量，则返回其常量值。

### 返回
- `Some(value)`: 当前节点可被解释为常量
- `None`: 当前节点不是常量

### 作用
这是判断“这个节点是否可当立即数使用”的更安全方式。

---

## 大小与版本接口

### `pub fn size(&self) -> usize`

返回节点大小。

---

### `pub fn get_size(&self) -> usize`

返回节点大小。

### 说明
与 `size()` 语义相同，属于不同风格的访问接口。

---

### `pub fn version(&self) -> usize`

返回节点的版本号。

### 作用
用于表达 SSA 相关版本信息。

### 重要说明
这里“有 version 字段/接口”并不等于：
- SSA 行为已经与 Ghidra 完全一致
- 版本分配已完成运行时对拍

它只说明当前 `Varnode` 模型已为 SSA 版本信息预留了表达位点。

---

### `pub fn with_version(self, _version: usize) -> Self`

返回一个携带指定版本信息的新节点。

### 作用
用于构造或传播带版本号的节点表示。

### 说明
这是 storage-node 模型向 SSA 语义扩展的入口之一。

---

### `pub fn get_create_index(&self) -> u32`

返回创建索引。

### 用途
通常用于：
- 稳定排序
- 调试
- 追踪节点创建先后关系

---

## 判定接口

### `pub fn is_unique(&self) -> bool`

判断该节点是否位于 unique 空间。

### 典型意义
表示内部临时值。

---

### `pub fn is_register(&self) -> bool`

判断该节点是否位于寄存器空间。

---

### `pub fn is_constant(&self) -> bool`

判断该节点是否为常量节点。

---

### `pub fn is_input(&self) -> bool`

判断该节点是否被标记为输入节点。

### 典型场景
- 函数输入
- 初始状态值
- 某些未在本函数内定义的入口值

---

### `pub fn is_written(&self) -> bool`

判断该节点是否已被某个操作写入。

---

### `pub fn is_free(&self) -> bool`

判断该节点是否处于未绑定/自由状态。

### 说明
这通常更偏向内部状态管理，而不是最终用户语义。

---

## 状态修改接口

### `pub fn set_flags(&mut self, f: u32)`

为节点添加一个或多个 flag。两条通知臂（varnode.cc:356-360）：
①`flagsDirty`（FLAGSDIRTY|NAMEREPDIRTY）**无条件**点火——派生旗通道
`HighVariable::updateFlags`（variable.cc:352）的存活读者=merge_test_required、
coreaction namevars/参数名门、varmap、is_name_lock；②`COVERDIRTY` 掩码门控
（MERGE-HIGHCOVER-PROPAGATION-0001）。实现=varnode.rs
`propagate_flag_change_to_high`（两臂共享一次写锁获取，piece walk 分段）。
varnode.hh 经 setFlags/clearFlags 路由的内联访问器（setImplied/clearImplied、
setExplicit/clearExplicit、setAddrForce/clearAddrForce、setPrecisLo/Hi+clear、
setUnaffected）已同形改走 set_flags/clear_flags；mark/directwrite/return_address/
autolive_hold/proto_partial 在 oracle 也是裸写，维持内联。

### 参数
- `f`: 位标志集合

### 用途
- 在分析过程中标记节点状态
- 更新输入/写入/绑定/恢复相关标签

---

### `pub fn clear_flags(&mut self, f: u32)`

清除一个或多个 flag。

### 参数
- `f`: 要清除的位标志集合

### 用途
- 撤销中间状态
- 调整分析流程中的节点属性

---

## 包装类型

### `pub struct VarnodeLocRef(pub Arc<RwLock<Varnode>>)` 

### 作用
位置排序或位置相关集合操作的包装器。

### 说明
当前实现使用共享所有权和读写锁包装 `Varnode`，说明：
- 节点会在多个分析阶段共享
- 节点状态可能被逐步更新
- 需要面向图结构和并发/共享访问设计

> 注意：旧文档里若还写着 `Rc<RefCell<Varnode>>` 一类表述，应视为历史遗留描述，不应再作为当前实现结论。

---

### `pub struct VarnodeDefRef(pub Arc<RwLock<Varnode>>)` 

### 作用
定义点相关的包装器。

### 典型用途
- 按定义关系组织节点
- 在 def-use 或 SSA 相关集合中使用

---

## 当前文档应如何使用

建议你把 `varnode.rs` 看作以下问题的入口：

1. **一个值节点如何定位？**  
   看：
   - `Address`
   - `AddressSpace`
   - `get_addr()`
   - `get_space()`
   - `get_offset()`

2. **一个值节点如何区分常量、寄存器、栈槽、临时值？**  
   看：
   - `new_constant()`
   - `new_register()`
   - `new_stack()`
   - `new_unique()`
   - `is_constant()`
   - `is_register()`
   - `is_unique()`

3. **一个值节点如何进入 SSA / 分析流程？**  
   看：
   - `version()`
   - `with_version()`
   - flags
   - `Funcdata`
   - `PcodeOp`

4. **一个值节点如何被更高层恢复成变量或打印结果？**  
   看：
   - `variable.rs`
   - `heritage.rs`
   - `printlanguage.rs`
   - `printc.rs`

---

## 已知边界与风险提示

### 1. `Varnode` 不是最终源码变量
不要把它直接理解为用户看到的 `local_10`、`param_1` 这类逻辑变量。

### 2. 有版本字段不代表 SSA 已完全验证
`version()` 的存在，只能说明当前模型支持 SSA 表达，不代表当前 SSA 行为已经完成运行时等价验证。

### 3. 空间语义非常重要
同一个偏移在不同 `AddressSpace` 下不是同一个东西。  
任何脱离空间理解 `Varnode` 的做法都会导致语义偏差。

### 4. `unique` 节点通常是内部临时值
它们对分析非常重要，但通常不是最终输出中希望直接暴露给用户的高层变量。

---

## 推荐联动阅读

如果你正在理解 `Varnode`，建议继续阅读：

- `address.md`
- `space.md`
- `op.md`
- `pcoderaw.md`
- `funcdata.md`
- `heritage.md`
- `printc.md`
- `../data_contract.md`

---

## 一句话总结

`Varnode` 是 Rugra 当前 storage-node 模型中的基础数据节点：  
它统一承载“位置 + 大小 + 节点状态 + 分析附着点”这几类信息，是从原始 P-code、函数级图模型、SSA 分析到最终打印输出之间最重要的底层数据载体之一。
## 2026-06-26：Ghidra-faithful flag 访问器（varnode.hh:235-330）

新增与 Ghidra 一致的 Varnode flag 访问/设置方法，解锁 coreaction Action
（ActionMarkExplicit/MarkImplied/RestrictLocal 等）：

- `is_mark/set_mark/clear_mark` (varnode.hh:263,303,304) + `is_marked`/`clear_marks`（2026-07-16 新增，供 ActionConditionalConst flowToAlternatePath 使用）
- `is_implied/set_implied/clear_implied` (varnode.hh:235,309,310)
- `is_explicit/set_explicit/clear_explicit` (varnode.hh:236,311,312)
- `is_direct_write/set_direct_write/clear_direct_write` (varnode.hh:247,305,306)
- `is_addr_tied`（addrtied|insert 同置，varnode.hh:250）
- `is_persist` (246), `is_unaffected/set_unaffected` (255,167)
- `is_illegal_input`（input 置而 directwrite 清，varnode.hh:240）

测试：varnode::tests 4 个新增（mark、explicit/implied、addr_tied 双标志、illegal_input）。

## 2026-06-26（续）：get_nz_mask（2026-08-23 FUNCDATA-CALCNZM-0003 更正语义）

- `get_nz_mask(&self) -> u64`（varnode.hh:231）：非零掩码，**直接返回 `nzm` 字段**（oracle 语义）。
  字段由构造函数初始化（varnode.cc:590-606：常量=offset、其他=~0），并由
  `Funcdata::calcNZMask`（funcdata_varnode.cc:856-927：DFS 经 `PcodeOp::getNZMaskLocal`
  赋输出 + MULTIEQUAL worklist 传播）前向精化；主管线中 `ActionNonzeroMask`
  （coreaction.cc:5507）每轮 mainloop 在规则池之前运行它。旧实现（常量=值、
  其他=calc_mask(size) 的保守近似）已删除。解锁 RuleSlessToLess 等 NZM 相关 Rule。

## 2026-06-26（续）：lone_descend / has_no_descend

- `lone_descend(&self) -> Option<Arc<RwLock<PcodeOp>>>` — `Varnode::loneDescend`：返回唯一后代 op（无或多个则 None）。
- `has_no_descend(&self) -> bool` — `Varnode::hasNoDescend`：无后代读取。
解锁 RuleDoubleShift/RuleSubZext/RuleXorCollapse 等独占使用检查。

## 2026-06-26（续）：consume/nzm 访问器

- `get_consume() -> u64` / `set_consume(val)`（varnode.hh:205-206）：dead-code 维护的 consumed 位掩码。
- `get_nzm() -> u64` / `set_nzm(val)`：Heritage 维护的 nzm 字段原始访问。
解锁 RuleOrConsume/RuleAndMask 等依赖 consume 的 Rule。

## 2026-06-26（续）：is_boolean_value

- `is_boolean_value(use_annotation) -> bool`（varnode.cc:942）：判断 varnode 是否为已知布尔值（由 calculated_bool 标志的 op 定义）。解锁 RuleBooleanNegate/RuleLogic2Bool。

## 2026-06-27：def / descend / flag 访问器（L3 基础设施）

新增 def-chain 遍历所需访问器，解锁 jumptable/ruleaction/condexe 等模块的深度遍历：

- `get_def() -> Option<Arc<RwLock<PcodeOp>>>`（varnode.hh:213）：升级内部 Weak→Arc，返回定义此 varnode 的 PcodeOp。
- `is_read_only() -> bool`（varnode.hh:243）：是否来自只读内存空间。
- `is_annotation() -> bool`（varnode.hh:237）：是否为反编译器插入的注解 varnode。
- `is_spacebase() -> bool`：是否为 spacebase 指针 varnode。
- `is_persist_global() -> bool`：是否为持久化（全局）varnode。
- `descend_iter() -> impl Iterator<Item = Arc<RwLock<PcodeOp>>>`（varnode.hh:219-220）：遍历活跃的后继 op（beginDescend/endDescend）。
- `count_descends() -> usize`：活跃后继计数。
- `add_descend(&Arc<RwLock<PcodeOp>>)`（varnode.hh:295）：添加后继引用。
- `is_bool_output_def() -> bool`：定义 op 是否有布尔输出（getDef()->isBoolOutput）。

### 2026-06-27（会话2 续）：is_constant_extended（解锁 RuleDivOpt）

- `is_constant_extended() -> Option<(u64, u64)>` — `Varnode::isConstantExtended`（varnode.cc:799-840）：检测扩展常量，返回 128 位值 (lo, hi)。普通常量返回 (offset, 0)；INT_ZEXT/INT_SEXT/PIECE 链递归解析。被 RuleDivOpt::findForm 用于处理超过 64 位的乘法常量（除法乘法编码 c 可能 > 2^64）。

### 2026-07-16：is_eventual_constant 完整递归（解锁 lastChanceLoad 依赖）

- `is_eventual_constant(max_binary, max_load)` — 对齐 `Varnode::isEventualConstant`（varnode.cc:854-893）完整递归算法：COPY/ZEXT/SEXT 迭代跟随 in(0)；LOAD 递减 maxLoad 跟随 in(1)；INT_ADD/SUB/XOR/OR/AND 递减 maxBinary 递归两输入；INT_LEFT/RIGHT/SRIGHT/MULT 要求 in(1) 常量跟随 in(0)；其他返回 false。此前是简化 1 层检查。是 `ActionDeadCode::lastChanceLoad`（coreaction.cc:3916）的依赖。
- **新增访问器**（2026-07-16）：`is_auto_live`（修复：现正确检查 ADDRFORCE|AUTOLIVE_HOLD）、`is_auto_live_hold`/`set_auto_live_hold`（varnode.hh:253/327）、`is_consume_vacuous`/`set_consume_vacuous`/`clear_consume_vacuous`（varnode.hh:208-212）。解锁 `ActionDeadCode::lastChanceLoad`。

### 2026-06-27（会话3 G3 诊断）：find_by_loc

- `VarnodeBank::find_by_loc(size, loc) -> Option<Arc<Varnode>>` — 空间查找辅助：扫描 loc_tree 找任意 (size, loc) 匹配的 varnode（忽略 create_index），返回 create_index 最大者。用于 G3 诊断时桥接断链的 use-def（实验性，当前未被主管线调用）。
### 2026-06-27（续；2026-08-28 勘误）：is_auto_live（RuleEarlyRemoval）
- “保守返回 false”是已废止的旧实现。当前 `is_auto_live()` 精确读取
  `ADDRFORCE | AUTOLIVE_HOLD`；writemask 使用独立 addlflags 位，不再与
  AUTOLIVE_HOLD 冲突。2×2 双侧投影与 EarlyRemoval covered fixture 均已验证该
  范围，完整 flag producer/consumer 生命周期仍由各自 TODO 跟踪。

### 2026-07-01：Ghidra flag accessor + 几何 API（解锁 ~20 Rule TODO）
- `is_addr_force/set_addr_force/clear_addr_force`（varnode.hh:251/307-308）— ADDRFORCE flag。
- `is_type_lock/is_name_lock`（varnode.hh:299-300）— TYPELOCK/NAMELOCK flag。
- `is_precis_lo/is_precis_hi` + set/clear（varnode.hh:275-276/321-324）— PRECISLO/PRECISHI flag。解锁 RulePullsubMulti/Indirect/SubCommute/SubNormal 的 omitted 守卫。
- `is_proto_partial` + set/clear（varnode.hh:258/329-330）— PROTO_PARTIAL flag。解锁 RulePieceStructure。
- `is_ptr_flow` + set/clear（varnode.hh:260/317-318）— addlflags PTR_FLOW。解锁 RulePtrFlow。
- `is_indirect_creation`（varnode.hh:248）— INDIRECT_CREATION flag 访问器。
- `get_type`（varnode.hh:192）— 返回 v_type。解锁 RulePieceStructure 的 leaf->getType() 路径。
- `characterize_overlap(&Varnode) -> i32`（varnode.cc:155-170）— 0=无重叠/1=部分/2=完全相同。解锁 RuleIndirectCollapse。
- `contains_storage(&Varnode) -> i32`（varnode.cc:105-116）— 0=包含/-1=op在前/1=越界/2=op在后/3=不同空间。含 `IPTR_CONSTANT → 3` 短路（cc:109）：当 `self` 处于常量空间时直接返回 3，等价 Ghidra `loc.getSpace()->getType()==IPTR_CONSTANT`。
- `overlap(&Varnode) -> i32`（varnode.cc:178 + address.cc:153-165）— 返回 LSB 相对偏移。含 `IPTR_CONSTANT → -1` 短路（address.cc:159）：当 `self` 处于常量空间时直接返回 -1。范围算术用 unsigned `wrapping_sub` 模拟 Ghidra `wrapOffset`（address.cc:161），`dist >= size → -1`（cc:163）。

### 2026-09-23：update_type/update_type_lock 补 high typeDirty（MATCHURL-SETCASTS-337-0001）

- `update_type(ct)` / `update_type_lock(ct, lock, override)` 现在在写入
  `v_type` 后对挂接的 HighVariable 置 TYPEDIRTY（varnode.cc:461-463 /
  500-501 的 `if (high != 0) high->typeDirty();`），替换旧注释的
  "typeDirty on high — no-op" 占位。HighVariable 侧
  `get_type()`/`get_type_representative()`（variable.hh:174 →
  variable.cc:400-415）的惰性重推导链因此第一次对
  `Varnode::update_type` 的调用方可观察：同一 Action 内对某 varnode
  `update_type` 后，紧随的 `get_high_type_read_facing` /
  `get_high_type_def_facing`（varnode.cc:665/651）读到重推导后的类型，
  与 oracle 的 `high->getType()` 时序一致。
- 效果示例（match_url setcasts 337）：castInput 的 double-cast 调整臂对
  LOAD 地址 varnode `updateType(code * *)` 后，castOutput 计算 LOAD token
  （TypeOpLoad::getOutputToken，typeop.cc:472）经 read-facing 读到
  `code * *` 的 pointee `code *`，与输出 high 相等 → 短路不插 CAST。

### 2026-07-01（续 2）：update_type + get_type_read_facing + copy_symbol（解锁 ~15 TODO）
- `update_type(ct)`（varnode.cc:456-464）— 无锁设类型，typelock 时不改。
- `update_type_lock(ct, lock, override)`（varnode.cc:474-489）— TYPE_UNKNOWN 强制 unlock + lock/override 控制。
- `get_type_read_facing()`（varnode.cc:639-645）— 退化版直接返回 v_type（union 解析路径 Rugra 无 union varnode）。
- `copy_symbol(vn)`（varnode.cc:493-505）— 退化版复制 type + typelock/namelock flag（mapentry stub 不碰）。

### 2026-07-01（续 3）：has_no_local_alias + destroy_varnode
- `has_no_local_alias()/set_no_local_alias()/clear_no_local_alias()`（varnode.hh:262）— NOLOCALALIAS flag。
- `VarnodeBank::destroy_varnode(&vn)`（varnode.hh）— 从 loc_tree/def_tree 移除。

### 2026-07-05：VarnodeBank::set_input_varnode
- `VarnodeBank::set_input_varnode(vn) -> Arc<Varnode>`（对齐 `Funcdata::setInputVarnode`
  funcdata_varnode.cc:340-373 的 vbank-level 核心）。Ghidra 语义：(1) early-out if already
  input，(2) overlap dedup against existing inputs（exact match 返回已存在的，partial overlap
  Ghidra 抛 LowlevelError，Rugra log + 继续），(3) `vbank.set_input(vn)`（set INPUT|INSERT
  并重新插入两棵树）。省略 (4) ProtoModel 效果属性（unaffected/return_address）—— 这些
  不影响 SSA 正确性，只影响后续 type/recovery pass。**用于 heritage rename 的 empty-stack
  promotion**（heritage.cc:2502/2512）。`Funcdata::set_input_varnode` 是 thin wrapper。

### 2026-07-01（续 4）：SymbolEntry 统一 + get_symbol_entry + get_structured_type
- 移除 stub SymbolEntry，改用 database.rs 的真实 SymbolEntry。mapentry 字段现在持有真实符号映射。
- `get_symbol_entry() -> Option<Arc<RwLock<SymbolEntry>>>`（varnode.hh:190）。
- `get_structured_type() -> Option<Arc<Datatype>>`（varnode.cc:1137-1148）— 优先 mapentry 的 symbol 类型，否则 v_type；返回 piece-structured 类型。
- `copy_symbol` 完善：现在复制 mapentry（不再退化）。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- `contains_storage` → `contains`（对齐 `Varnode::contains` varnode.hh:226，返回 int4/i32 含5种关系码）。
- 删除 `is_persist_global`：是 `is_persist`（:579）的死重复副本（两者都读 PERSIST flag）。Ghidra 只有一个 `isPersist`。

### 2026-07-04：新增 copy_shadow / partial_copy_shadow
- `copy_shadow(op2)`（对齐 varnode.cc:977）：双向追踪 COPY 链判断是否同源。供 eliminate_intersect 使用。
- `partial_copy_shadow(whole, rel_off)`（对齐 varnode.cc:1102）：**保守 stub**（返回 false）。完整 SUBPIECE 影子分析（findSubpieceShadow）待移植。
- 文件级 helper `collect_copy_sources`：沿 COPY 链收集源 Arc，支持 copy_shadow 的双向比较。

### 2026-07-04（续 2）：完整移植 SUBPIECE/PIECE 影子分析
- `partial_copy_shadow` 从保守 stub（返回 false）改为完整实现（对齐 varnode.cc:1102-1131）。
- 新增 `find_subpiece_shadow`（对齐 varnode.cc:1006-1053）：递归 SUBPIECE 影子判定，含 COPY 透传、常量短路、MULTIEQUAL 1 层递归（recurse 限 1）。
- 新增 `find_piece_shadow`（对齐 varnode.cc:1062-1091）：递归 PIECE 影子判定。
- 辅助函数 `copy_chain_hits`/`copy_chain_source_def`/`whole_terminal_offset`：沿 COPY 链遍历（借用安全）。
- 这让 eliminate_intersect 的部分重叠判定忠实于 Ghidra（之前 stub 会把值包含误判为真相交，导致多余 snip）。

### 2026-07-04（续 3）：新增 has_cover
- `has_cover()`（对齐 varnode.hh:284）：`(flags & (constant|annotation|insert)) == insert`。供 merge_test_must 使用。
<!-- annotation-pass: 2026-07-04 -->
<!-- activeparam-port: 1783158350.9706767 -->
 

### 2026-07-05: erase_descend 新增 + add_descend 补检查
- `Varnode::erase_descend`（varnode.cc:316）：删除恰好一个匹配 weak ref，使同一 op
  在多个输入槽读取同一 Varnode 时，每次 `opUnsetInput` 只消费对应的一条 descendant
  记录；`VARNODE-INIT-0001` 的 combine/duplicate fixture 覆盖同 op 重复槽。
- `Varnode::add_descend`(cc:330): 补 free 非 spacebase 多 descend 检查。
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

### 2026-08-15: add_descend free 检查只计 live 条目（FUNC-GLOBRANGE-HANG-0001）

- `Varnode::add_descend`（varnode.cc:330-341）：free 非 spacebase 多 descend
  检查从 `!descend.is_empty()` 改为「存在 `strong_count() > 0` 的条目」。
  Ghidra 的 descend list 不可能持有已销毁 op（opDestroy 先逐槽 eraseDescend
  再释放 op），`empty()` 等价于「无 live reader」；Rust 的死 Weak 条目
  （op Arc 已释放但未走 unset）是 Ghidra 不可达的漂移态，把它计入会伪造
  "multiple descendants" 信号。`has_no_descend`/`count_descends`/`descend_iter`
  本来就过滤死条目，本改动使 add_descend 与之一致。
- 关联：`erase_descend`（varnode.cc:316-325）按 upgrade 后 Arc identity 匹配，
  死条目永远匹配不上——这正是旧版 `total_replace` 「扫描直到清空」循环
  无法终止的根源之一；`total_replace` 侧已改为 Ghidra 迭代器快照语义
  （见 docs/api/funcdata.md 2026-08-15 节）。

### 2026-08-17: add_descend 恢复 throw 语义（VARNODE-ADDDESCEND-THROW-0001）

- `Varnode::add_descend`（varnode.cc:330-340）：free 非 spacebase varnode 已有
  live descendant 时，WARN 软化恢复为与 `throw LowlevelError("Free varnode
  has multiple descendants")`（varnode.cc:336）一致的 `panic!`，消息逐字相同；
  panic 在 push/coverdirty 之前触发，与 C++ throw 前状态不变语义一致。
  错误通道选择 `panic!` 而非 `Result`：Ghidra 的 addDescend 为 void + throw，
  E2E worker 的 per-function 隔离把 panic 归入该函数失败桶，正对应 Ghidra
  LowlevelError 中止单函数的模型（memstate.rs 只读 bank 写入同款先例）。
  两个非法生产者（subflow raw INPUT / inject_raw_ops 共享 free）已随 aa3d5e8
  消除；恢复后 E2E 剩余触发点的登记见 docs/TODO_BOARD.md 该行。
- 常量无豁免：`isFree()`（varnode.hh:238）只查 written|input，常量在
  addDescend 层同样是 free，仅靠 `Funcdata::opSetInput` 的常量去重
  （funcdata_op.cc:108-115）上游保护——fixture `varnode_add_descend_1204`
  双侧钉死该分支。
- fixture：`tests/oracle/varnode_add_descend_1204.{cc,rs,metadata.json}` +
  `tools/run_varnode_add_descend_oracle.sh`（锁定 oracle 双侧逐字对拍：
  throw 文本、spacebase 豁免、written/input 累积、push 顺序、throw 后状态
  不变）。

### 2026-08-15: copy_shadow 身份比较修复（VARNODE-COPYSHADOW-ARC-0001）

- `Varnode::copy_shadow`（varnode.cc:977-995）从「两侧收集 Arc 集合求交」重写为
  忠实两循环结构：`copy_chain_hits(self, op2)` 实现 cc:982 的 `this==op2` 与
  cc:984-988（沿 this 的 COPY 链回溯，逐节点与 op2 比较）；随后用
  `copy_chain_source_def(self)` 解析链源（cc:989-993 的 vn），再
  `copy_chain_hits(op2, &链源)` 完成第二循环。链源解析依赖 def↔output 不变量
  （funcdata_op.cc:78-82 `vn = vbank.setDef(vn,op); op->setOutput(vn);`）：
  `written=true` 时链源 = 终端 def 的 output；`written=false` 时链源 = 终端 COPY
  的 inrefs[0]；this 无 def（cc:984 循环不前进，vn 即 this）。
- 根因：被删除的文件级 helper `collect_copy_sources` 首迭代用
  `Arc::as_ptr(&out_arc)`（RwLock 分配基址）对比 guard 借用 `&Varnode`
  （payload 地址）——`RwLock<T>` payload 不在偏移 0，两地址永不相等 →
  恒走 "Mismatch; bail" → sources 恒空 → `copy_shadow` 恒 false。此外该实现
  对无 def 的起始节点同样返回空集，丢失 Ghidra「op2 的链与 this 本身比较」
  语义（cc:989-993 第二循环的 vn=this 分支）。重写后两类缺陷一并消除。
- 身份比较统一为 payload↔payload `std::ptr::eq`（`copy_chain_hits` 既有范式，
  varnode.cc:982/987/992 的裸指针 `==` 对应物）；全文件审计确认无其它
  「基址 vs payload」混用点（2090 行 `Arc::as_ptr(&op) as usize` 仅作 BTreeMap
  key，形式一致自洽；1779 行 `as_ptr` 仅用于诊断打印）。

## add_descend 注释更正（2026-08-17，随 op_insert_input 收编）

`add_descend` 的 coverdirty 说明更正：该 flag 实际被
`get_cover/update_cover_locked` 消费（cover 重算路径）——op_insert_input
收编后新增的 coverdirty 输入在 httpd 侧表现为 `[HERITAGE] WARN` 诊断
量增（+11363 行，stdout/throw/函数集三方不变），与 Ghidra cc:339 无条件
置位同方向。旧注释"does not track the coverdirty flag"系 585bdd7 遗留，
已删除。
<!-- annotation-pass: 2026-08-17 -->

### 2026-08-23：copySymbolIfValid 忠实化 + isValueClose 移植（VARNODE-COPYSYMBOL-EQUATE-0001）

- `Varnode::copy_symbol_if_valid(vn)`（varnode.cc:510-522）从保守近似
  （「双方均 constant 即复制 mapentry」）改为逐行忠实移植：cc:513-515 无
  SymbolEntry 早退；cc:516-518 `dynamic_cast<EquateSymbol*>` 失败即拒绝非
  equate 符号；cc:519-521 仅当 `isValueClose(loc.offset, size)` 成立时
  `copy_symbol(vn)` 传播 markup。旧的「双 constant」守卫为自创语义，删除。
- `EquateSymbol::is_value_close(op2_value, size)` +
  `EquateSymbol::is_value_close_value(value, op2_value, size)`（database.cc:640-659，
  inherent impl 落在 varnode.rs——database.rs 不在本租约 write-set 内）：
  cc:642 全宽相等；cc:643-644 `calc_mask(size)` 截断；cc:645-649 掩掉的
  '1' 位仅允许符号扩展（`sign_extend(maskValue,size,8)`，Rust 对应
  `rangeutil::sign_extend_size`）；cc:650-654 mask 内 相等/按位取反/取负/
  +1/-1 五种 close 形式（uintb 环绕 = `wrapping_neg/add/sub`）；cc:655 全不
  匹配返回 false。
- `equate_symbol_registry::{register_value, query_value}`（RUGRA-GLUE）：
  C++ 侧 EquateSymbol 是 Symbol 子类，`dynamic_cast` 从多态 `Symbol*` 同时
  恢复 equate 身份与 `value` 字段；Rugra `database::Symbol` 无 equate 载荷
  且 `SymbolEntry::symbol` 为具体 `Arc<RwLock<Symbol>>`，故 varnode 域内以
  符号身份（Arc 指针）→ value 侧表最小建模。条目刻意不删除（镜像 C++
  「EquateSymbol 终身是 EquateSymbol」的对象生命周期语义，避免地址复用
  ABA 误判）。接线（DATABASE-EQUATE-VALUE-REGISTRY-0001）：
  `database::Scope::add_equate_symbol` 与 `add_map_sym` 的
  `<equatesymbol>` 腿已在本体注册符号，主管线 equate（database::Scope 侧）
  携带 value 到达 `copy_symbol_if_valid`；varmap/funcdata 侧的
  `buildDynamicSymbol` 常量腿仍走 varmap 模型（见 database.md 变更日志残差）。
- 行为影响：`RuleCollapseConstants` 折叠时非 equate mapentry 不再传播
  （与 oracle 一致方向）；`ruleaction::tests::
  collapse_constants_symbol_propagation_via_marked_input` 原断言保守行为，
  需在其测试内改用 `equate_symbol_registry::register_value` 注册 equate
  （ruleaction.rs 不在本租约，登记给 root）。oracle 行为门禁：
  `tests/oracle/varnode_copysymbol_1204`（pin-base schema2，
  `tools/run_varnode_copysymbol_oracle.sh`）。
<!-- annotation-pass: 2026-08-23 -->

### 2026-08-23（续）：copySymbol high!=0 分支完整移植（VARNODE-COPYSYMBOL-HIGHBRANCH-0001）

- `Varnode::copy_symbol_arc(self_arc, vn)`（varnode.cc:493-505 完整移植）：
  字段半（cc:496-499）复用 `copy_symbol`，随后补上此前缺失的 cc:500-504
  high 簿记——`high->typeDirty()`（variable.hh:166）无条件触发；
  `mapentry != 0` 时 `high->setSymbol(this)`（variable.cc:245，注意传的是
  **目标** varnode 而非 vn）。以关联函数 + `&Arc<RwLock<Varnode>>` self 的
  形态存在，因为 `HighVariable::set_symbol` 需要目标的 Arc 身份，`&mut
  self` 签名无法恢复；write guard 在簿记前释放，避免 set_symbol 内部
  重取 read 锁死锁。
- `Varnode::copy_symbol(&mut self, vn)` 保留为字段半（cc:496-499），
  funcdata.rs 去重腿与 ruleaction.rs RuleAddUnsigned 两个越界调用点不变
  （前者在调用点手工执行等价簿记，后者登记残差）。
- `Varnode::copy_symbol_if_valid(self_arc, vn)` 拓宽为关联函数：cc:519
  isValueClose 以短 read 锁读取目标 loc/size 后释放，cc:520 尾调用完整
  `copy_symbol_arc`；op.rs `collapse_constant_symbol` 调用点同步适配。
- oracle 行为门禁：`tests/oracle/varnode_highbranch_1204`（pin-base
  schema2，`tools/run_varnode_highbranch_oracle.sh`）——双侧覆盖 close
  传播（typeDirty 位 0→1、setSymbol 附着 FIXTURE_EQ/-1、惰性 isTypeLock/
  type 重推导翻转）/ not-close 干净 / 空 mapentry 仅 typeDirty / 无 high
  外层守卫 / op 级 markedInput 五投影，逐字节 MATCH。
- 残差登记：`HighVariable::get_type` 缺少 variable.hh:174 的惰性
  `updateType()`（建议 VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001）；
  ruleaction.rs:10588 RuleAddUnsigned 调用点走字段半未执行 high 簿记
  （建议 RULEACTION-ADDUNSIGNED-COPYSYMBOL-HIGH-0001）。

### 2026-08-24：CALLSPEC-IDENTITY-D0 typed FSPEC handle

- `Varnode` 新增 `call_spec: Option<Weak<RwLock<FuncCallSpecs>>>`，并通过
  `bind_call_spec` / `get_call_spec` 写入和升级。它是 Ghidra
  `IPTR_FSPEC` 地址中裸 `FuncCallSpecs *` 的 Rust 非拥有对应物；权威持久强所有权
  在 `Funcdata::callspecs`，CALL 输入不会延长 callspec 生命周期，也不会和
  callspec → op 的反向边形成 `Arc` 环。
- `Funcdata::new_varnode_call_specs` 创建 annotation 时同时写入 typed `Weak`。
  direct call 的 Iop 数值 payload 目前保留 entry offset，作为尚未消费 typed
  callspec 的 legacy PrintC 兼容 shadow；entry 缺失时才回退为 owner pointer 诊断值。
  查找绝不从任一整数反解身份，因此一个数值 payload 相同、但没有 typed handle 的
  普通 constant 不能解析成 callspec。该 numeric codec 与 Iop space 都仍是
  `TYPEOP-FSPEC-SPACE-0001` 的 `MISMATCH`，不能当作 oracle identity 证据。
- `clone_varnode` 会复制这个 `Weak`，对应 Ghidra 克隆 annotation 地址时暂时复制
  同一裸指针；`truncated_flow` 随后必须创建新的 callspec owner，并把新 CALL 的
  input(0) 重绑到新 owner，不能让克隆长期指回源函数。
- D0 整体仍为 `MISMATCH`：Rugra 暂用 `AddressSpace::Iop`，尚无专用
  `IPTR_FSPEC`，numeric payload 也不是 Ghidra 的 raw `FuncCallSpecs *` codec
  （`TYPEOP-FSPEC-SPACE-0001`）；本阶段不接 TypeOp getter、PrintC typed callspec
  consumer 或 StringManager。其余既有 Varnode 残差与模块级状态不提升。

## R9-F1：overlap_addr 补 BE 分支（2026-08-24，HERITAGE-GUARD-NORMALIZE 整改）

`Varnode::overlap_addr`（varnode.cc:217 `Varnode::overlap`）此前只实现 LE
半边（`loc.overlap(0,…)`）。本轮补齐 BE 分支（varnode.cc:221-226）：
`over = wrap(vn.off + vn.size - 1 - op.off)`；`over ∈ [0, op2size)` 时返回
`op2size-1-over`（自最低显著侧起算），否则 -1。调用方仅 heritage 两个
normalize 位点（LE 值与修复前逐位一致；BE 域整体 UNTESTED，登记
`HERITAGE-BE-OVERLAP`）。跨 space 的 -1 哨兵（address.cc:161 `base != op.base`）
为已登记残差 —— Rugra `Address` 无 space 身份，调用方自守（见函数注释）。

## 2026-08-24：get_local_type 核心算法 + STOP flag 常量（VARNODE-LOCALTYPE-RESOLUTION-0001）

实现 `Varnode::getLocalType`（varnode.cc:900-936）的核心算法，并以 62-record
selected projection 对拍；这不包含 production buildLocaltypes/SymbolEntry/特殊
TypeOp 消费闭包。它替换此前只 clone
`v_type` 的 stub（旧签名 `(&self, &mut bool) -> Option<Arc<Datatype>>` 无调用方，
新签名无迁移成本）：

- `get_local_type(&self, block_up: &mut bool, type_factory: &Arc<RwLock<TypeFactory>>) -> anyhow::Result<Option<Arc<Datatype>>>`
  — 已实现的核心路径逐项映射 varnode.cc:900-936（完整函数仍受下述 null/特殊
  TypeOp/production 消费闭包残差约束）：
  1. `is_type_lock()` 早退返回锁类型（cc:906-907，不触碰 blockup）；
  2. def 存在 → `ct = def->outputTypeLocal()`（cc:910-911，经下方派发表）；
  3. `def->stopsTypePropagation()`（op flag 0x40 消费端）→ `*block_up = true` +
     提前返回 ct，跳过全部 readers（cc:912-914）；
  4. descend 按 `addDescend` 插入序遍历（std::list 无排序，cc:921），
     `i = op->getSlot(this)` 指针身份取槽（op.hh:166），
     `ct` 仅在 `0 > newct->typeOrder(*ct)` 严格更小时替换（cc:929，
     submeta 升序 + size 降序，type.cc:212-218），平局保留先遇者；
  5. 全空 → `Err("NULL local type")`（cc:933-934 LowlevelError 通道）。
  `type_factory` 参数承接 Ghidra 经 `PcodeOp::opcode->tlst`（op.hh:122）隐式
  可达的 Architecture TypeFactory —— Rugra `PcodeOp` 无 parent 链，工厂显式传入。
  `Ok(None)` 对应 Ghidra 返回 null `Datatype*` 的两条路径（typelock null type /
  STOP 早退时 ct 为 null）；`newct==null && ct!=null` 在 Ghidra 是 null-this UB，
  Rugra 保守保留现任（注释在函数体内，override 表任何可达 op 均不产生该状态）。
- **派发表**（本文件私有，`// Ghidra:` 逐行引用）：`op_output_type_local` /
  `op_input_type_local`（op.hh:251-252 转发器）+ `local_meta_pair`（TypeOp
  ctor metain/metaout 表）+ `local_base`（typeop.cc:264/274 基类默认
  `getBase(size,TYPE_UNKNOWN)`）。当前 selected 派发切片覆盖下列 Ghidra
  override；CALLIND/RETURN/CPOOLREF 等完整分支仍按本节末残差开放：PTRADD/PTRSUB 全
  INT（typeop.cc:2235/2241/2311/2317）、shift slot-1
  `getBaseNoChar(size,INT)`（:1510-1516/1535-1541/1600-1606）、CBRANCH
  slot1 BOOL + slot0 code-ptr（:609-619）、INDIRECT slot1 code-ptr（:1992-2003）、
  INSERT/EXTRACT slot0 UNKNOWN（:2535-2541/2550-2556）、CPOOLREF 输入 INT
  （:2465-2469）、CALL input 委托 R3-approved 的 D1
  `TypeOpCall::get_input_local`（typeop.cc:687-718）、CALL output 全量 720-735
  （fspec 门 → outputLocked 门 → VOID 门 → 锁定返回类型）、CALLIND input 委托
  R19-approved 的 D2 `TypeOpCallind::get_input_local`（typeop.cc:745-774）——
  slot0 code-ptr（:752-756）与参数槽 fc==null 基类默认（:758-759）都经 typeop
  单拷贝解析，消除此前 slot0 的内联重复；参数槽完整 callspec 分支
  （isTypeLocked/isThisPointer，:760-772）在 `get_input_local_in_fd`
  （ActionInferTypes coreaction 臂接线）。
  **PTRSUB local/output-token 边界**：`op_output_type_local` 对 PTRADD/PTRSUB
  都请求 TypeFactory 的 `getBase(output-size, TYPE_INT)`（typeop.cc:2238-2242/
  2308-2312）；它不得调用 `TypeOpPtrsub::get_output_token`。24-record bilateral
  fixture 的 14 个 8 字节 direct case 执行该派发器并另行断言其结果与
  `TypeOpPtrsub::get_output_local` identity 相同，均观察到 `local=int8`、
  `local_identity=1`、`local_core=1`。超出 max-basetype-size 的闭包仍绑定
  `TYPEFACTORY-LOCALTYPE-CACHE-0001`。
  字段敏感 token 只由后续 `ActionSetCasts::castOutput` 消费。fixture 新增的
  infer canary 会执行 Ghidra `Varnode::getLocalType` 与双方 production
  `ActionInferTypes::apply`：selected base/out int8 shape、STOP、定义边和 canonical
  identity 均 MATCH，且 production `build_localtypes` 已调用映射的
  `Varnode::get_local_type`。这仍不是任一完整函数的 MATCH 证据：
  `Varnode::getLocalType` core projection 另有 62/62 双侧 MATCH；production
  buildLocaltypes 的 SymbolEntry/exact-piece、特殊 TypeOp 派发、reader/STOP
  消费闭包与异常状态仍绑定 `VARNODE-LOCALTYPE-RESOLUTION-0001` /
  `ACTION-INFERTYPES-DISPATCH-0001`。
  2026-08-28 formal release curl A/B 进一步证明 production closure 未闭合：六个
  受影响 local 的名称前缀转为 concrete pointer 后，PrintC 声明路径从匿名 pointer
  取得空 type name，形成无类型声明。直接语法断点绑定
  `PTRSUB-TYPED-DECL-RESIDUAL-0001`；达到 golden 的上游 identity 闭包仍由
  `ACTION-INFERTYPES-DISPATCH-0001`、`TYPE-UNKNOWN-0001` 与
  `PRINTC-SYMBOL-DECL-0001` 跟踪。glob_set 同轮新增的 outer/nested cast churn 另绑
  `PTRSUB-SWITCH-CAST-RESIDUAL-0001`。这些 final-C 信号都不属于 14-case direct
  local identity 的 MATCH 结论，也不能单因归于本文件改动。
   **为什么本地表而非 typeop.rs trait**：现行 typeop.rs 宏族
  （binary/unary/functional）与 COPY/LOAD/STORE/MULTIEQUAL 的
  get*Local 覆盖读对侧 varnode 的 v_type 而非 `getBase(size,metatype)`
  （登记残差 PRINTC-CAST-OPNAME-0001 M1）；M1 落地后 root 可将两张表合并。
  残差：CALLIND 参数槽经 fd-less 委托观测 fc==null 基类默认（完整 callspec
  分支在 coreaction 臂，typeop.rs `get_input_local_in_fd`）、RETURN 参数槽
  （需 parent→Funcdata，走 Ghidra 自身的 bb==null 基类默认路径）、
  CPOOLREF 记录路径（无 cpool 基础设施）。
  ~~CALLOTHER userop 元数据（TypeFactory 无 arch 反链）~~ —— 已由
  TYPEOP-LOCALTYPE-CALLOTHER-0001 闭包接线关闭（见下节）。
- **flag 常量**（varnode.hh:131-132）：`addl_flags::STOP_UP_PROPAGATION=0x800`、
  `HAS_IMPLIED_FIELD=0x1000`。注意 0x800 在主 `varnode_flags` 里是 `volatil`
  （varnode.hh:93）—— 两个枚举同值不同义，STOP 落 `addl_flags`（u16
  `addlflags`），不得混入主 flags。
- **访问器**：`stops_up_propagation()`（varnode.hh:267）、
  `set_stop_up_propagation()`（:333）和 `clear_stop_up_propagation()`（:334；Ghidra
  全源码零调用，接口对等）。2026-08-25 的 coreaction 窄路径已在
  `build_localtypes` 写 STOP，并在 `ActionInferTypes::propagateTypeEdge`
  （coreaction.cc:5093）读取。
- **行为影响**：双侧 fixture `tests/oracle/varnode_localtype_res_1204.*`
  覆盖：单 def 无 readers、typeOrder-min（两种插入序）、平局先遇（char*/int*
  等价指针）、def STOP 早退+blockup、path 指针胜整型、typelock union 直返、
  null local type 错误通道，核心投影 62/62 MATCH。完整生产
  buildLocaltypes/SymbolEntry/特殊 TypeOp/错误状态仍未由该 fixture 证明。

## 2026-08-25：CALLOTHER userop 闭包接线（TYPEOP-LOCALTYPE-CALLOTHER-0001，TYPEOP-LOCALTYPE-DISPATCH-0001 CALLOTHER 切片）

关闭 A48 复核精确定位的 caller 闭包：`PcodeOp → TypeOpCallother::get*Local →
tlst->getArch()->userops.getOp(in(0).offset) → 基类 canonical 回落`
（typeop.cc:855-873）。

- **方案论证**（userops 参数线程 vs TypeFactory arch 反链）：选**参数线程**。
  (1) Rugra `Architecture::ensure_types` 借 `TypeFactory::shared_default()`
  进程级单例充任 canonical 工厂（TYPE-WIRING-0001 D0 临时态）——反链落在共享
  单例上是跨 Architecture 的 last-writer-wins 污染，Ghidra 每架构独占工厂
  （type.hh:819 `getArch()` 无此歧义）；(2) `Architecture::set_types(&mut self)`
  在 Architecture 被 Arc 包装**之前**调用（fixture/管线两处形态皆然），
  `Weak<Architecture>` 在唯一可靠设置点无法成形，~13 处独立工厂构造点需逐一
  回填接线；(3) 参数线程沿用同函数既有 `type_factory` 参数的先例与理由
  （"Rugra PcodeOp 无 parent 链"，varnode.rs:1747-1750 注释）；
  (4) `get_local_type` 全仓零生产调用方，线程侵入面 = 3 个函数签名 + 1 个
  pinned fixture 调用点更新，`None`（无宿主 Architecture）行为等价于
  metadata-less 描述符走基类默认。
- **签名**：`get_local_type(&self, block_up, type_factory,
  userops: Option<&Arc<RwLock<UserOpManage>>>)`；`op_output_type_local` /
  `op_input_type_local` 同参并转 `pub`（对应 op.hh:250-252
  `PcodeOp::outputTypeLocal/inputTypeLocal` 的公开入口地位，供双侧 fixture
  直接观察 PcodeOp 级闭包）。
- **CALLOTHER arm**（typeop.cc:855-873）：slot-0 常量 offset 截 32 位后查
  `UserOpManage::get_op`（对齐 `getOp(uint4)`，userop.cc:408-415）；描述符
  metadata 命中即返回（`DatatypeUserOp` slot-1 压缩在 userop.cc:79，
  `UserPcodeOp::get_input_local` 已实现）；null → TypeOp 基类默认
  `getBase(size,TYPE_UNKNOWN)`（typeop.cc:261-275），含 slot 0 自身与越界槽。
  **UB-cover**：Ghidra 对未注册 index 在 cc:859 前即空指针解引用（生产不可达：
  SLEIGH 在发射任何 CALLOTHER 前注册全部 userop index）；Rust
  `get_output_local/get_input_local` 把该态折叠进同一 None，以同一 canonical
  回落覆盖而非崩溃（注释在 arm 内）。
- **dormant 兄弟残差**：typeop.rs `TypeOpCallother::get_operator_name` 的
  `callother_userop_name` None-stub **不在本线程可解范围**——其宿主
  `TypeOpManager` 全仓零实例化（打印活性路径在 `PrintC::op_callother`，
  printc.rs:8504-8515 已持 `self.userops` 忠实解析）；登记
  `TYPEOP-CALLOTHER-PRINTNAME-0001` 待 TypeOpManager 激活时接线。
- **行为影响**：`get_local_type` 仍零生产调用方，主管线行为零变化；双侧
  fixture `tests/oracle/callother_userop_closure_1204.*` 覆盖：memcpy
  DatatypeUserOp（void*/void*/void*/int4）out/全槽/def 侧/reader 侧闭包、
  metadata-less UnspecializedPcodeOp 全链 canonical 回落、builtin 注册身份、
  slot-0 常量与越界槽的基类默认。varnode_localtype_res_1204 fixture 调用点
  同步补 `None` 线程（行为逐字节不变，runner 重钉验证）。
### 2026-08-25：O(n) 扫描移除（heritage rename 超时修复）
- `VarnodeBank::set_input`（varnode.cc:1358-1371）— 先 `erase_loc_identity`/`erase_def_identity`
  再置 INPUT 标志；erase 的 residency bool 取代原 `owns_loc_ref`/`owns_def_ref` 全量扫描
  （Ghidra 经 stored lociter/defiter erase，erase 本身即所有权证明）。语义不变：free/constant
  检查、`Err("Making input out of unmanaged varnode")` 均保留。
- `VarnodeBank::destroy_varnode` / `destroy_varnode_prevalidated`（varnode.cc:1276-1285）—
  两处全量 `retain` 改为 identity-erase（O(log n) 快路径 + 兜底 identity 扫描）；预检
  owns 扫描由 erase 结果取代，`Err("Deleting unmanaged varnode")` 保留。
- `VarnodeBank::set_input_varnode`（funcdata_varnode.cc:340-373 的 vbank 层）— overlap 去重
  从全量 loc_tree 线性扫描改为 Ghidra 的 `beginDef(input, addr+size)` 前驱查询：
  `def_tree.range(..search).next_back()`（search 为 flags=INPUT、loc=addr+size、size=0 的
  合成键，对应 varnode.cc:1916-1918 的 searchvn），只检查紧邻前驱一条；精确匹配返回既有
  input，部分重叠保持既有 WARN 降级。Heritage rename 的每次空栈提升从 O(n) 降为 O(log n)。

## spacebase placeholder 访问器（varnode.hh:261/319/320，本次新增）

- `Varnode::is_spacebase_placeholder` / `set_spacebase_placeholder` /
  `clear_spacebase_placeholder`：`addlflags & SPACEBASE_PLACEHOLDER (0x400)`
  的读/置/清，逐行对齐 Ghidra 内联访问器。置位方：
  `FuncCallSpecs::create_placeholder`；清除方：`RuleLoadVarnode` 解析尾巴。

## VarnodeBank::set_def 所有权证明重构（本次性能修复）

Ghidra `setDef`（varnode.cc:1390-1398）以存储在 Varnode 内的 lociter/defiter
执行 erase —— erase 本身即所有权证明，O(log n)。Rugra 原实现先做
`owns_loc_ref`/`owns_def_ref` 两个 O(n) 全树扫描再 `transition_def`，使
heritage/pool 的 setDef 路径在大函数上呈二次方。现 `transition_def` 返回
`Option<Arc<..>>`（identity-erase 的两个 residency bool 作为所有权证明），
`set_def` 据此产出同样的 `Err("Defining unmanaged varnode")`，
`set_def_prevalidated` 保留 panic 契约。可观测行为（成功/Err 分支）不变。

### 2026-08-26：Varnode::setSymbolProperties 补 updateType 腿（varnode.cc:413）
- `set_symbol_properties` 开头补 `entry->updateType(this)`（cc:413，
  database.cc:135-144 的 sized-piece 类型替换）：type-locked 符号现在先把
  varnode 类型替换为 entry 的对应尺寸片段（`update_type_lock(dt, true,
  true)`），再做 mapentry 链接与 flag 折叠（cc:414-421 原有）。此前缺
  updateType 腿，PTR_ 槽位符号的 `undefined *` 类型到不了 varnode。
## 2026-08-25（ACTIONDW-COPYDEF-MARKING-0001）：is_stack_store / set_stack_store 访问器

- `is_stack_store()`（varnode.hh:265）：`(addlflags & stack_store) != 0`——是否由显式 CPUI_STORE 产生（RuleStoreVarnode 转 STORE→COPY 时设置，ruleaction.cc:4333；ActionDirectWrite 的 COPY 源追踪消费，coreaction.cc:1382）。flag 常量 `STACK_STORE=0x100` 先前已存在且 RuleStoreVarnode 已写入，仅缺访问器。
- `set_stack_store()`（varnode.hh:338）：`addlflags |= stack_store`。

## 2026-08-29（FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001）：set_symbol_properties_arc（HighVariable 反连 + 守卫内 setSymbol）

`set_symbol_properties(&mut self, entry)` 重构为关联函数
`set_symbol_property_arc(self_arc, entry) -> bool`（varnode.cc:410-424 全量）：

- cc:413 `res = entry->updateType(this)`：typelock-gated `get_sized_type` +
  `update_type_lock(dt, true, true)`（database.cc:135-144）。
- cc:414-421 `mapentry != entry` 指针恒等用
  `SymbolEntry::same_storage_identity`（symbol Arc ptr_eq + addr/offset/size/hash，
  代理 C++ 指针比较；Database 查询返回克隆 Arc 无法用 Arc 恒等）。命中时
  `mapentry = entry`、`high->setSymbol(this)`（variable.cc:245-275）、`res = true`。
  **setSymbol 调用在守卫内**：非 typelock 或已链接的 entry 不触碰 HighVariable
  （早期版本把 setSymbol 提到守卫外，会把旧 mapentry 的 symbol/offset 重写并清
  symboldirty——已修正）。
- cc:422 `setFlags(entry->getAllFlags() & ~typelock)`。

需要的调用方（funcdata.rs new_varnode_symbol_tail / mapGlobals 路径）全部改为
`Varnode::set_symbol_properties_arc(vn, &entry_arc)` 形态。

## 2026-08-30:get_use_point 自由腿哨兵(VARNODE-GETUSEPOINT-FREELEG-0001, O-2)

varnode.rs `get_use_point` 此前自由腿(非 written varnode)返回 `Address::new(0)`
(对应 oracle 中被注释掉的旧行 `constant(0)`),oracle varnode.cc:690-703 实为
`fd.getAddress()+-1` —— 输入 varnode 视作在函数入口前一个地址able 单元处进入作用域。
修正为 `fd.get_address().offset(-1)`(Address::offset 即 address.hh:423 `operator+`,
带空间的偏移经 wrapOffset 包装)。written 腿仍返回 def op 地址。注意 funcdata.rs 内
`varnode_use_point_offset` 等本地重实现本就是 baseaddr-1,本修正消除双轨。
双侧 fixture:tests/oracle/varnode_getusepoint_1204.{cc,rs} +
tools/run_varnode_getusepoint_oracle.sh(written/input/free/zero_base 回绕四形态,MATCH)。
E2E:curl 3119→3115,defects/numbering 保持 0(此前因祸得福的 Address(0) 未掩盖任何
queryProperties/inUse 差异)。

- 2026-09-23: getAddr anchor corrected to header inline definition.

## 2026-09-24：op_input_type_local 增 RETURN 臂 + fd 输出类型穿线（Lane GG2）

`op_input_type_local` 新增 `fd_output_type: Option<&Arc<Datatype>>` 参数与
`(CPUI_RETURN, slot@1..)` 臂（typeop.cc:883-897 的表格化镜像：proto 输出类型
非 void 且尺寸匹配→该类型；否则 `local_base(size, Unknown)`）。`get_local_type`
同步穿线；唯一生产调用方 `coreaction.rs build_localtypes` 传
`Some(fd.funcp.return_type.clone())`（Ghidra 的 op→getParent()→getFuncdata()
通道）。slot 0（indeterminate marker）走 `_` 默认臂，与 Ghidra slot==0 →
基类默认一致。

## 2026-09-24（CR29 返工）：RETURN 臂锚行修正

`op_input_type_local` 的 RETURN 臂注释锚行随 typeop.cc 修正：定义行 901（原
883=printRaw，行漂移），fp->getOutputType()=cc:918，void/尺寸失配=cc:919-920。
无行为变化。

## 2026-09-24：create_unique_typed（PM-F2S）

`VarnodeBank::create_unique_typed(size, ct)` — `VarnodeBank::createUnique(int4 s,
Datatype *ct)`（varnode.cc:1265-1271）的 typed 镜像：分配 unique 地址偏移后以
显式 `ct` 构造 varnode（ctor `type = dt`，varnode.cc:583）。Ghidra 要求 ct 非空
（null 默认在 `Funcdata::newUnique` cc:86-87 完成），Rugra 侧由
`Funcdata::new_unique_typed` 承担同一默认。调用方：
`Merge::allocateCopyTrim`（merge.cc:416/429）与 `Merge::trimOpOutput`
（merge.cc:668/677）的 trim COPY 输出携带源 varnode 类型（PM-F2S ord337 修复）。

## 2026-09-25：coverDirty 传播半边接线（MERGE-HIGHCOVER-PROPAGATION-0001，Lane HIGHCOV）

oracle 不变量：任何弄脏成员 varnode cover 的突变同步传播 coverDirty 到所属
high（varnode.cc:352-361 setFlags / 365-374 clearFlags 的 cc:358-359/371-372
臂；触发者 addDescend cc:339、eraseDescend cc:325、calcCover cc:261、
VarnodeBank::replace cc:1350-1351、makeFree→setDef cc:1322）——存储聚合
（`HighVariable::getCover` 裸读 internalCover，无惰性更新）的新鲜度完全靠它。

接线（本日）：①新增 `propagate_cover_dirty_to_high(high)`（RUGRA-GLUE 借用安全
helper：high 写锁置位 COVERDIRTY → 释放 → piece walk，规避
markExtendCoverDirty 末腿 variable.cc:136 的同锁重入；merge.rs
`mark_high_cover_dirty` 委托同一实现）；②`set_flags`/`clear_flags` 掩码含
`COVERDIRTY` 时自动传播；③`add_descend`/`erase_descend`/`calc_cover` 的内联
`flags |= COVERDIRTY` 改走 `set_flags`（oracle 字面 setFlags 调用形态）——
replace/make_free/创建位点（set_input/set_output 置
`INPUT|COVERDIRTY`/`WRITTEN|COVERDIRTY`，high==None 时传播臂自然 no-op，
=oracle high==null 分支）随之自动携带。

**锁不可达的 clear 侧**：`update_cover_locked`（varnode.cc:239
clearFlags→传播）与 `get_cover`（varnode.hh:202 → updateCover）不传播——
调用方持 high 读守卫（checkImpliedCover 借用 `&HighVariable`、
aggregate_high_cover_from），见两函数 NOTE 注释；由 HighVariable::new 初始
脏（variable.cc:224）+ 构造性闭合（attach-hole 审计——bec3474a 起
update_high 已回归 oracle 单标志位原形 variable.cc:1148-1156,实例扫描
已移除;「成员脏∧high 旗净」构造性不可达）+ inflate/aggregate 现聚合吸收。
该角落承载「成员在 attach 前已脏」的首次重建置脏语义。

**flagsDirty 半边（CR-HIGHCOV 发现 1 修正，2026-09-25 二轮）**:首轮提交的
"Rust 无 high flagsdirty 消费者" 声明为假（存活调用者: merge.rs
merge_test_required、coreaction.rs namevars/参数名门×2、varmap.rs、
variable.rs is_name_lock）；oracle varnode.cc:357/:370 对每次带 high 的
setFlags/clearFlags **无条件 flagsDirty()**（无掩码门——与 coverDirty 不同）。
已物化：`propagate_flag_change_to_high` 拆双臂（FLAGSDIRTY|NAMEREPDIRTY
无条件半+coverdirty 掩码半，共享一次写锁获取）；varnode.hh 经 setFlags 路由
的访问器家族（implied/explicit/addrforce/precis*/unaffected）同形改走
set_flags/clear_flags；mark_implied 的内联传播半边与
compute_varnode_covers 的显式传播简化为字面 setFlags 调用（merge.cc:1598/
:1603）。锁纪律按加宽调用点集重验：261 处 set_flags/clear_flags + 32 处
访问器 + 4 处 set_unaffected 作用域感知机械扫描，唯一共存候选=测试内
（守卫已 drop 且 vn 无 high），零生产死锁面；双语料 cmp 逐字节恒等重跑。

验证：curl/httpd 默认脸对亲父 a9475ecc cmp 逐字节恒等；cargo test --lib
1713P/1F（nonzeromask 预存）；bank 391/391；annotations/refs --strict 绿。
详见 docs/api/merge.md 同日节。

## 2026-09-26：read/def-facing 四方法 Arc 共享（UNIONRES-FIELDOFF-PTRSUBNORM-0001，settle 契约）

- `get_type_def_facing()` / `get_type_read_facing_op(op,slot)` /
  `get_high_type_def_facing()` / `get_high_type_read_facing(op,slot)` 的
  needs_resolution 臂此前 `Arc::new((*ct).clone())` 每调用产**新 Arc** —— 破坏
  `Varnode::updateType` 的 `type == ct`（varnode.cc:481,Rust `Arc::ptr_eq`）
  settle 契约:oracle 的 TypeFactory interning 保证 findResolve 结果指针稳定,
  逐调用克隆是 `localcount >= 7` "not settling" 家族（coreaction.cc:5390-5392）
  的身份翻转源之一。现在这些退化臂共享原 v_type/high Arc —— 即 oracle
  findResolve map-miss 臂 `return this`（type.cc:586-590/1192-1202）在无
  Funcdata 通道签名下的精确可达语义。
- 零参 `get_type_read_facing()` 保留（无 Ghidra 零参对应;对非 resolution 类型
  与 oracle `getTypeReadFacing` 等价）,注释更新指向 fd-aware 咨询孪生:
  unionresolve.rs 的 `vn_type_read_facing` / `vn_type_def_facing` /
  `vn_high_type_read_facing` / `vn_high_type_def_facing`（持 fd 的消费者使用,
  map 命中时返回 interned 字段类型）。

## 2026-09-26：hasImpliedField/setImpliedField 访问器（PRINTC-UNMAP-SINGLETON-0001）

- `has_implied_field()` / `set_implied_field()`（`// Ghidra: varnode.hh:268 /
  varnode.hh:335`）——`addl_flags::HAS_IMPLIED_FIELD`（0x1000）旗标自
  UNIONRESOLVE 车道起已在位但无访问 seam；本批补齐内联访问器对（varnode.hh:268
  `hasImpliedField` / :335 `setImpliedField` 逐字形态）。消费半=printc.rs
  `rpn_push_implied_field`（printlanguage.cc:527-529 的 recurse 分支 →
  PrintC::pushImpliedField printc.cc:2085-2116）；生产半=coreaction.cc:2519
  `vn->setImpliedField()`（ActionSetCasts::resolveHeir 的 implied 臂）——
  coreaction 在飞租约 handover（该处既有注记称旗标不存在已过期，本批未触碰
  coreaction.rs 域，落地后 3 行接线即可激活）。单测
  `printc::tests::test_push_implied_field_union_arm` 以手工置旗+union 解析
  快照锁定消费侧行为。

## 2026-09-27：op_output_type_local CALLOTHER 臂补 InternalStringOp 覆写（PRINTC-STRDATA-TYPELOCK-0001）

`op_output_type_local`（`op.hh:251 PcodeOp::outputTypeLocal` 转发器）的
CPUI_CALLOTHER 臂在「描述符固定元数据 → 基类默认」两段之间补
`InternalStringOp::getOutputLocal`（userop.cc:361-364，亲读）覆写：描述符
`is_string_data()` 时返回 **op 出口 varnode 自身的 v_type**
（`op->getOut()->getType()` 的 1:1）。stringdata 描述符本就无固定元数据
（`registerBuiltin` 只置 `display_string` 旗标），oracle 的输出局部类型即出口
vn 类型——这一身份回声正是 typelock 尊重链的锚点：

- `Funcdata::getInternalString`（funcdata_varnode.cc:1430-1431）在创建时对
  出口 `updateType(ptrType, true, false)` 上 char* typelock；
- `Varnode::getLocalType`（varnode.cc:911 `def->outputTypeLocal()`）与
  `ActionSetCasts::castOutput` 的 token（typeop.cc:282 虚分派）双双读到该
  char* → token==outHighType 短路（coreaction.cc:2544-2548），cast 阶段对
  STRINGDATA 出口零改写。

消费闭包：`Varnode::get_local_type`（ActionInferTypes buildLocaltypes 种子）、
coreaction `cast_output` 新 CALLOTHER token 臂（docs/api/coreaction.md 同日节）。
出口 vn 的 `v_type` 为 `None` 的状态（bank 创建即种子 unknown 基，理论不可达）
保守落入描述符/基类默认链，与 oracle 永非空 `getType()` 语义对齐。

## 2026-09-27：op_output_type_local CALLOTHER 臂补 VolatileReadOp::getOutputLocal（VARNODE-CALLOTHER-VOLATILEOUT-0001）

- **`op_output_type_local` CALLOTHER 臂**（typeop.cc:865-873 虚分派链）补
  volatile-read 描述符覆写（userop.cc:128-141 逐字）：
  - cc:131 `if (!op->doesSpecialPropagation()) return 0` — special_prop
    （op.hh:109 addlflags 0x1，`Funcdata::replaceVolatile`
    funcdata_varnode.cc:761-762 仅在源 varnode typelock 时置位）为第一道门；
  - cc:133-136 `addr = op->getIn(1)->getAddr()`（volatile 内存 annotation，
    newCodeRef 形态）、`size = op->getOut()->getSize()`、
    `usepoint = op->getAddr()`；`uint4 vflags=0` 出参被唯一消费者丢弃；
  - cc:136 `glb->symboltab->getGlobalScope()->queryProperties(...)` →
    cc:137-139 `entry->getSizedType(addr,size)`（可空→回落）。
  上述任一门未过 → 描述符固定 metadata → 基类默认
  `getBase(out.size,TYPE_UNKNOWN)`（typeop.cc:261-265）。
- **`symboltab` 线程**：`op_output_type_local` /
  `Varnode::get_local_type` 签名各加
  `symboltab: Option<&Arc<RwLock<Database>>>`——oracle 经描述符
  `glb->symboltab` 边（userop.hh:38）到达全局 scope，Rugra `UserOpManage`
  无该反链，沿既有 `userops` Option-thread 先例（TYPEOP-LOCALTYPE-DISPATCH-0001）
  显式传参；`None`（无宿主 Architecture）= 描述符 metadata-less 同回落。
  生产接线=`coreaction.rs build_localtypes` 从 `fd.arch.symboltab` 提取。
- **query_properties_entry**：消费侧新增
  `Database::query_properties_entry`（database.cc:1263-1281 的
  `SymbolEntry*` 返回形态）供 `entry->getSizedType`；flags 出参按
  userop.cc:135-136（初始化 0 后永不读）丢弃。
- **单测** `test_output_type_local_volatile_read_symbol_arm`：正例=global
  符号 int@0x1000 addr-tied + special_prop 置位 → 返回符号 sized type；
  三负例=special_prop 清除 / 地址无符号 / symboltab=None 线程 → 全部
  UNKNOWN 基（size 保持），永非有符号 Int 基。
- **休眠证明（五语料零差）**：触发链全序=①cspec `<volatile>` 注册
  read_volatile/write_volatile builtins（architecture decodeVolatile）→
  ②varnode 获 `volatil` 属性（flagbase/property 通道）→ ③ActionVolatile 调
  `replace_volatile` 发射 CALLOTHER → ④源 varnode typelock 才置
  special_prop → ⑤本臂查全局符号。锁定 x86-64-gcc.cspec 无 `<volatile>`
  元素（Ghidra_12.0.4 源树 grep 干净）→ 链首即断，②-⑤ 全不可达；
  curl/httpd/vsh/sq/sqlite canon A/B 字节恒等（构造性：CALLOTHER 臂内
  新路径仅 volatile_read+special_prop 双门同时通过才激活）。
