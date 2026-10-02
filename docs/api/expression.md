# `expression.rs` API Reference

## 2026-10-02：PERF-RULEBODY2-0001 TermOrder 缓冲池化 + collect 就地扫描（性能恒等重排）

`TermOrder` 是 collect_terms 每 try 构造的规则体专用 helper（本模块唯一消费方）。
原形每次 try 付 4 次堆分配（terms/sorter/sort键/opstack Vec）+ 每 popped op 的
inputs Vec 克隆（分配 + 每 input 一对 Arc 原子往返 + 推入 term 时二次克隆）。本条：

- **`TermOrder::collect`（expression.cc:236-283）—— 就地扫描**。输入扫描在单次
  PcodeOp 读守卫下直接迭代 `op.inrefs`（oracle `curop->getIn(i)` 裸指针读），
  每个推入的 AdditiveEdge 只克隆它存储的句柄。LIFO 栈序、逐 slot 扫描序、term
  推入序逐行不变。
- **`TermOrder`/`Drop` —— 四缓冲线程本地池化**（`term_scratch` 模块，池容量 4）。
  `terms/sorter/sort_keys/opstack` 从 thread-local 池取用，Drop 时 clear 后归还。
  clear() 丢弃 Arc 句柄的时刻 == 原 owned Vec 析构时刻（同一语句末端），可观测
  析构序不变；`sort_terms` 的 sorter 重建与稳定排序比较器逐位不变（键投影同
  PERF-OPPOOL-0001 形）。

**行为恒等**：纯存储复用，零突变面变化；证明链见 docs/api/ruleaction.md 同日条
（VdbeExec md5 `15b47cf7` + ACTIONSTATS 单极/语料 2.32 亿尝试计数恒等 + assembled
字节恒等）。collect_terms 语料 4.21→3.58s（−15.1%，3 轮负载共享对跑中位数）。

## 2026-10-01：PERF-ACTIONPOOL-ITER-0001 functional_equality_level_code 投影（性能恒等重排）

新增 `pub fn functional_equality_level_code(vn1, vn2) -> i32`——`functional_equality_level`
的 code-only 投影,服务只读返回码的调用方（RuleMultiCollapse cc:3280、ActionDirectWrite
dedup 扫描、NodeJoin::findDups cc:1936-1938、`functional_equality` 包装器）。
oracle 的 res1/res2 输出缓冲写是裸指针存（expression.cc:475-477）,调用方丢弃缓冲时
零可观测效应;投影保持双 op 读守卫借读输入句柄,零 pair 物化、零 Arc 往返,每个测试
读同一字段同一序,返回码与 `functional_equality_level(..).code` 逐位相同。
`functional_equality` 包装器改道该投影。完整 pair 返回形（push_multi 等 code==1
读 pairs 的调用方）保持不变。

**源代码路径**: `src/expression.rs`
**Ghidra 对应**: `expression.hh` / `expression.cc`
**状态**: 🔧 **L2**——部分函数已有实现和测试，但模块级逐函数 oracle 闭包尚未完成；不得沿用旧 L3 声明。

## 2026-09-29：PERF-OPPOOL-0001 TermOrder 收集/排序每边锁合并（性能恒等重排）

[OPPROF] 钻探（VdbeExec `--one 1055`，RUDRA_OPPROF=1 探针，交付前撤净）显示
`collect_terms` 是 oppool1 22-28s 残差的单一最大项：8.47s / 617,430 次尝试 /
**13.7µs 每次尝试**（oracle 同规则密度采样仅 ~0.5s = 17× 实现级常数差）。本条
消除该常数，算法与可观察结果不变：

- `TermOrder::collect` — 每次 `opstack.pop()` 现以**单次 PcodeOp 读锁**快照
  输入 Arc 句柄表（原实现每边重取 `curop.read()`）；每边以**单次 Varnode 读锁**
  批量读出 oracle 逐字段读的 `isWritten`/`loneDescend`/`getDef`（expression.cc
  :243-280 逐字对应）；`AdditiveEdge` 直接以已克隆句柄构造（原 `AdditiveEdge::new`
  重锁读取 op 再取 `inrefs[slot]`——oracle `expression.hh:106` 构造器是裸指针
  `vn = op->getIn(slot)`）。LIFO 栈序、逐 slot 扫描序、term 推入序逐行不变。
- `TermOrder::sort_terms` — `additiveCompare` 投影（常量类 + 剥离 INT_MULT 常数
  系数后的完整 storage address，varnode.cc:1153-1175 `termOrder`）改为**每 term
  预计算键** `(class, space_id, AddressSpace, offset)`（键序=varnode.rs
  `compare_address_spaces` 的 `space_id().cmp().then(a.cmp(&b))` 逐字复刻），
  排序在缓存键上进行（原实现每比较 2 次 Varnode 锁 + MULT 剥离最多 3 次额外
  锁）。`sort_by` 稳定性与等价类结果逐对不变（投影相同 → Less/Greater/Equal
  判决逐对相同；`Arc::ptr_eq` 短路保留）。

行为恒等论证：collect 全程零突变（纯走查，锁合并在无突变区间内可交换）；
排序键是 term_order 的全序键化。VdbeExec `--one 1055` stdout 与基线逐字节恒等
（md5 `4c557d1f…`，四连测），canon 双语素 + 镜面五面零漂移（车道 OPPPOOL 门禁）。

## 2026-08-13：TermOrder 收集边界与比较器修正

`TermOrder::collect` 在 `INT_MULT(INT_ADD(...), constant)` 路径上现在检查底层
`INT_ADD` 输出是否 lone-descend，对应锁定 Ghidra 12.0.4
`expression.cc:267-273`。旧实现重复检查外层 `INT_MULT` 输出，会错误穿透具有多个
使用者的共享 ADD 子树。

`TermOrder::sort_terms` 不再以 Rust `Arc` 分配地址排序，也不再把常量反向排在最前；
比较器改为调用 `Varnode::term_order`，由后者实现常量置后、剥离常量系数乘法并按完整
storage address 比较。该闭包由 `RULE-COLLECTTERMS-0001` 的七组目标结构投影 fixture
验证。多个 `termOrder == 0` 等价项下，Ghidra `std::sort` 与 Rust stable sort 的具体
tie 重排仍为 `UNTESTED`；整个 expression 模块及 RuleCollectTerms 均不能据此升级 L3。

## 模块说明

表达式分析基础设施，用于加法表达式树的项收集、排序和等价匹配。
对应 Ghidra 的 `expression.hh`。

## 导出的公共 API

### `pub struct AdditiveEdge`
加法表达式中的一个项。对应 Ghidra `AdditiveEdge`。
- `op: Arc<RwLock<PcodeOp>>` — 读取该 term 的 op
- `slot: usize` — 输入槽位
- `vn: Arc<RwLock<Varnode>>` — 该 term 的 varnode
- `mult: Option<Arc<RwLock<PcodeOp>>>` — 可选的乘法 op

### `pub struct TermOrder`
加法表达式项排序器。对应 Ghidra `TermOrder`。
- `new(root)` — 以 INT_ADD root op 构造
- `collect()` — 遍历 ADD/MULT 链收集所有项（expression.cc:236-283）
- `sort_terms()` — 按项排序（expression.cc:285-293）
- `get_sort()` / `get_term(idx)` — 访问排序结果

### `pub struct AddExpression`
轻量级加法表达式匹配（最多 2 项 + 常量）。对应 Ghidra `AddExpression`。
- `gather_two_terms_subtract(a, b)` — 从两个相减根收集（expression.cc:368）
- `gather_two_terms_add(a, b)` — 从两个相加根收集（expression.cc:379）
- `gather_two_terms_root(root)` — 从单个根收集（expression.cc:389）
- `is_equivalent(other)` — 判断两表达式是否等价（expression.cc:309）

测试：expression::tests 2 个（常量折叠、等价匹配）。

## 2026-08-14：functional_equality_level raw 输出 buffer 契约

`functional_equality_level` 现在保留锁定 Ghidra 12.0.4
`functionalEqualityLevel` 的完整输出参数写入时机。Ghidra 在通过 opcode、arity、marker、
call、LOAD 地址和 PTRADD 元素大小等结构守卫后，先按输入槽顺序写入
`res1[i]`/`res2[i]`，再决定最终返回 `-1`、`0`、`1` 或 `2`。因此即使返回值非正，
调用者提供的 buffer 也可能已被写入。

Rust 的 `FunctionalEqualityResult::pairs` 表示这些已写入的 raw
`(res1[i], res2[i])` 槽，而不是只在返回值为正时才存在的精简列表：

- `code > 0` 时，前 `code` 项是决定相等性的 varnode pair；
- `code <= 0` 时，`pairs` 仍可能非空，精确保留 Ghidra 在返回前完成的写入；
- 在结构守卫之前返回时 `pairs` 为空，对应调用者 buffer 保持原 sentinel；
- 锁定输入顺序后，第二 pair 会复制到 slot 0；交换律路径只覆盖指定的
  `res1[0]` 或 `res2[0]`，最终翻转路径只交换两个 `res2` 槽。

该契约修复了 unary contingent、binary slot-1 exact、non-commutative code-2，
以及 commutative cross-impossible/original-valid code-2 四条曾返回正 code 却遗漏 pair
的路径。`RulePushMulti::applyOp` 是当前唯一消费正返回 buffer 的调用者；它读取
`pairs[0]` 与 Ghidra 读取 `buf1[0]`/`buf2[0]` 相同，不需要也不允许在消费处兜底。
其余调用者仅检查返回 code。

### `pub fn functional_equality(vn1, vn2) -> bool`

对应 `expression.cc:520-525` 的薄封装，调用同一个完整
`functional_equality_level` 并仅在 `code == 0` 时返回 `true`。旧代码误从
`address.rs` 引入仅实现 level-0 的同名 helper，导致结构上完全相同的已写表达式也无法
被证明相等；现在 `AddExpression` 与公开 wrapper 都经过完整的一层定义比较。wrapper
自身不暴露 raw buffers，也不修改 IR。

## 2026-06-27（续）：functional_equality_level — expression.cc:404-512

移植 Ghidra 的 `functionalEqualityLevel`（值相等性分析）；模块完整闭包状态仍以本页
顶部 L2 声明和逐函数 oracle 账本为准。

### `pub fn functional_equality_level(vn1, vn2) -> FunctionalEqualityResult`
尝试判断两个 Varnode 是否持有相同值，对应 expression.cc:432-512。
- 返回 `code == -1`：不相等 / 无法立即验证
- 返回 `code == 0`：确定相等
- 返回 `code > 0`：contingent（取决于 `pairs` 前 `code` 个 varnode 对是否相等）

### `pub struct FunctionalEqualityResult`
- `code: i32` — 相等性代码
- `pairs: Vec<(vn1, vn2)>` — Ghidra 已写入的 raw 输出 buffer 槽；正返回时前
  `code` 项是需要匹配的 varnode 对

### 算法细节
- **Level 0**（`functional_equality_level0`）：相同指针→0；不同大小→-1；都是常量→比较 offset；free→-1；其他→1。
- **深层比较**：两者都必须 written，定义 op 必须相同 opcode、相同输入数、非 marker、非 call。LOAD 需要相同指令地址。PTRADD 检查 slot 2（元素大小）。
- **交换律**：对可交换运算符（INT_ADD/INT_MULT/INT_XOR/INT_AND/INT_OR），尝试翻转输入对匹配。
- 用于 `RulePushMulti`、`RuleMultiCollapse`、`ActionMultiCse` 和 `Funcdata` CSE
  检测；锁定 Ghidra 的 `ConditionalJoin::findDups` 也调用该函数，当前 Rudra 尚无等价
  调用闭包，因此模块不能据此升级 L3。

测试：expression::tests 新增 5 个（same_pointer/constants_equal/constants_unequal/different_sizes/free_varnodes）。

## 2026-06-27（续 2）：BooleanMatch — expression.cc:57-216

完整移植 Ghidra 的 `BooleanMatch`（布尔值相关性分析）。

### `pub fn boolean_match_evaluate(vn1, vn2, depth) -> i32`
判断两个布尔 Varnode 是否持有相关值。忠实移植 expression.cc:111-216。
返回 `boolean_match::SAME`(1) / `COMPLEMENTARY`(2) / `UNCORRELATED`(3)。

### `pub mod boolean_match`
常量：`SAME = 1`, `COMPLEMENTARY = 2`, `UNCORRELATED = 3`。

### 算法细节
- **BOOL_NEGATE 递归**：如果任一 vn 由 BOOL_NOT 定义，递归评估并翻转结果（same↔complementary）。
- **BOOL_AND/OR/XOR 递归**：对深度 > 0，递归评估输入对，应用德摩根律。
- **直接比较**：相同 opcode → varnodeSame 检查所有输入 → same；sameOpComplement 检查 x<n, n-1<x 模式 → complementary。
- **翻转比较**：get_booleanflip 检查互补运算符对（INT_EQUAL/INT_NOTEQUAL, INT_LESS/INT_LESSEQUAL 等）。

### 辅助函数
- `varnode_same(a, b)` — expression.cc:93-100：相同指针或相同常量值。
- `same_op_complement(bin1op, bin2op)` — expression.cc:57-86：检查 INT_LESS/INT_SLESS 的 x<n, n-1<x 互补模式。

测试：expression::tests 新增 3 个（same_pointer/uncorrelated_constants/complement_via_flip）。
解锁 RuleBooleanUndistribute/RuleBooleanDedup 的完整 De Morgan 定律实现。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
<!-- annotation-pass: 2026-07-04 -->
