# `action.rs` API Reference

**源代码路径**: `src/action.rs`

## 2026-09-29：PERF-OPPOOL-0001 派发循环 drillobserve flush 调用点门控

`ActionPool::process_op` 每 rule 尝试后的 `drillobserve::flush(rule_name)` 调用点
现以 `drillobserve::is_enabled()` 同门预判（action.cc:844-846 的
`data.debugModPrint(rl->getName())` 在 oracle 是 OPACTION_DEBUG **编译期**开关，
Rugra 外部化为运行期 env 门）。drill 关闭时跳过每次尝试的 vtable `get_name()`
取名（flush 本体在关闭时为立即返回，返回 bool 被丢弃）——调用/不调用语义恒等
（OnceLock 门一经初始化不可翻转）。VdbeExec 27.7M 次尝试各省一次虚调用。

钻探侧记（[OPPROF]，交付前撤净）：oppool1 22-28s 残差分解 = 规则体 miss 常数
（collect_terms 8.47s 领跑）+ BTreeSet 后继下降 5.05s（`Ord for PcodeOpRef`
每比较 2 读锁 × O(log n)——**op.rs 写域，归并 PERF-ACTIONPOOL-ITER-0001**，
oracle `std::map<SeqNum,PcodeOp*>` 迭代器摊还 O(1) 无锁）+ miss 重读 opcode
1.14s（action.cc:865 裸读 vs 每尝试一次 RwLock 读——同 op.rs 键化票域）。
oracle 侧 55 样本 gdb 采样：VdbeExec 8.8s 中 oppool ≈27/55≈50%（≈4.6s），
其派发机制本身占池时间 ~26%。

## 2026-09-28：Actions 派发循环逐 op 常量削减（ACTIONLOOP-RESTART-0001）

SPEEDPROF 车道 gdb 采样：top-10 慢函数计算线程帧 68.5% 落在 Action 派发循环
（perform/apply_children/apply_restart），named 叶含 Sip13::write/RawVec——票
SPEEDPROF-ACTIONLOOP-RESTART-0001。oracle 侧亲读判定（action.cc:553-582 重启
=clearAnalysis+全子树 reset+整树重跑，无"跳过已完成"机制——重启重跑是算法本体，
重启次数与执行序不可动）；本票只消**每次派发的纯常数开销**，五处：

1. `ActionPool::per_op` 由 `HashMap<OpCode, Vec<usize>>` 改为 `Vec<Vec<usize>>`
   按 `#[repr(i32)]` OpCode 判别值索引（opcodes.rs:16，CPUI_MAX=74）——oracle
   `perop[CPUI_MAX]`（action.hh:264）的原生数组形态。原实现**每条 rule 尝试**
   都做一次 SipHash 探测（process_op 内循环重复 `per_op.get(&opcode)`）。
2. `process_op` 入口 `op_state.take()` 持有所有权（原每次 op 克隆一个 Arc）；
   断点续跑路径（action.cc:851-852 保留 op_state 指向当前 op）显式放回。
3. `next_op_after` 的 range 边界改 `Bound<&PcodeOpRef>` 借用形态（原
   `current.clone()` 再克隆一次 Arc）——严格后继重建（对应 oracle `op_state++`）
   的树下降与 SeqNum 序（op.hh:280）不变。
4. process_op 对 op 的 `is_dead`+`opcode` 合并单次读锁（oracle 的两次裸读取值
   相同；两次锁获取→一次）。
5. 派发内两个 `get_name().to_string()` 每次分配删除（drillobserve::flush 本取
   &str；issue_warning 用 rules/rule_states 不相交字段借用）。

同 commit 新增 env 门控观察计数 `RUGRA_ACTION_STATS=1`（stderr
`[ACTIONSTATS]` 行：per 重启边界的 perform/pool_passes/ops/rule_tries/rule_hits
累计——重启放大事件级量化通道，与 oracle Rule::count_tests 同类事件账）。
行为恒等链：canon 双语素 md5 恒等 + 镜面五面钉值 + bank 391（见票行验收）。

## 2026-08-28：EarlyRemoval 注册语义说明

`build_oppool1` 仍在 Ghidra `coreaction.cc:5512` 的原始位置注册
`RuleEarlyRemoval`；注释现在明确其第六守卫由 Heritage 的
`pass > deadcodedelay`/`deadremoved` 状态驱动。规则的 72 个 typed live-opcode
投影已有锁定 12.0.4 双侧 fixture，raw bucket 0/45 仍是显式残差。

## 2026-08-24：ActionPool 选择性 fresh clone 与真实基树派生

锁定 Ghidra `Rule::clone`（`action.hh:230-236`）、`ActionPool::clone`
（`action.cc:899-914`）和 `ActionDatabase::deriveAction`
（`action.cc:1145-1160`）的共同契约是：按 `allrules` 注册顺序逐个请求 Rule
克隆；不在 grouplist 的 Rule 返回 null；第一个幸存 Rule 出现时才创建目标池；
随后用 `addRule` 重建每个 opcode 的有序索引。Rule 克隆由构造器产生 fresh
实例，因此不继承 disabled/warning-given、breakpoint 或统计值；ActionPool 本身
则复制源池的 Action flags/name，但 status、breakpoint 和统计值重新初始化。

Rugra 的 `Rule::clone_for_groups` 和 `Action::clone_for_groups` 提供对应虚拟契约。
由于本改动的租约不能触碰约 150 个具体 Rule/Action 文件，默认 universal builder
在每个锁定 `coreaction.cc` 注册槽保存 group 和无捕获构造工厂；容器或自定义实现
可以直接覆盖虚拟 clone。`ActionPool::clone_pool`、`ActionGroup::clone_group` 与
`ActionRestartGroup::clone_restart_group` 都保持原 vector 顺序并采用相同的懒创建/
null 规则，所有克隆执行状态从构造初值开始。`ActionDatabase::derive_action` 不再
重新调用 universal builder，而是克隆数据库里以 `baseaction` 键注册的真实对象；
空结果也会作为 null map entry 缓存，重复派生不会再次克隆。

真实双侧门禁 `tools/run_action_pool_clone_filter_oracle.sh` 使用同一合成 Rule 池，
覆盖 all/custom/empty grouplist、null 派生缓存、Rule 和 per-op 的完整顺序，以及
池/Rule 的 flags、status、breakpoint、count_tests/count_apply。该覆盖投影为
`MATCH`。ActionPool 全函数状态仍保守为 `MISMATCH`（rebase 合并 BREAKPOOL 执行器
后，per-rule disabled/warnings/breakpoint 调度与 `op_state`/`rule_index` 断点续跑
已由 `tools/run_action_break_pool_oracle.sh` 双侧门禁覆盖，残余差异以两个门禁
登记的 TODO 为准），因此本改动不宣称模块 L3。

## 2026-08-24：Action/Rule 断点与 live ActionPool 续跑

`ActionState` 与 `RuleState` 现在承载锁定 Ghidra `Action` / `Rule` 基类的
运行字段，包括 persistent/temporary start/action breakpoint、warning 位和
tests/applies 统计。`Action::perform` 按 `action.cc:298-362` 的时机执行：start
break 在 tests 增量前返回 `-1`；temporary 位只在对应检查命中时清除；从
`status_actionbreak` 继续时不重复调用刚完成的 `apply`；正向完成后按
warning → applies 增量 → action break 的顺序处理。`reset_for_function` 只恢复
status 并清 warning-given，断点、warning-enable、行为 flags、count/lcount 和
统计均保留；`reset_stats` 单独清统计。

公开的 `set_break_point`、`set_warning`、`disable_rule`、`enable_rule` 与
`clear_break_points` 使用 Ghidra 的首个冒号分段和逐层局部唯一匹配规则。
同一层出现多个非空匹配即歧义；一个内部已经歧义并返回空的子树不会增加父层
匹配计数，因此另一 immediate child 的唯一匹配仍可胜出。

`ActionGroup` 在 group 自身 action breakpoint 命中时先推进 child cursor 再
返回 `-1`；child 自身返回负数时保留当前 cursor。`ActionPool` 不再快照
`alivelist`，而是保存 `op_state` / `rule_index` 并遍历 live `PcodeOpTree`：Rule
指针在 disable/test/apply 前以 `rule_index++` 取出；Rule break 保留当前 op 和
已经推进的 rule index；resume 遇 dead op 时先求后继，再执行 dead-and-gone
清理。迭代排序键是 `SeqNum(address, creation-time)`，所以当前 cursor 之后的新
op 本轮可见，之前的新 op 留待下一轮。

锁定双侧门禁为 `tools/run_action_break_pool_oracle.sh`，fixture
`ACTION-EXECUTOR-BREAKPOOL-0001` 同时比较 stdout 与 warning stderr，覆盖 Action
和 Rule 断点续跑、Group 游标、Pool 当前 op 前后插入、当前 op 删除、初始 dead
op 清理、精确 result 累加、disabled Rule、局部 lookup 歧义、synthetic 与
production（`RuleSubvarSext` / `RuleDoubleIn`）derived reset 派发、
`ActionRestartGroup` 继承断点在 child 边界的命中/续跑，以及 raw universal 与
`decompile` / `jumptable` / `register` 派生根的完整树投影（全部 Action/Rule
名字与存活过滤逐字节一致）。

2026-08-24 rework（`ACTION-EXECUTOR-BREAKPOOL-0001` REJECT 闭合）：

- **Pool Rule 级 clone 过滤**（原 REJECT "非 decompile root 未按 grouplist
  clone"）：`build_oppool1` / `build_oppool2` / `build_cleanup_pool` 现接受
  `Option<&ActionGroupList>`，逐 Rule 按 oracle 注册槽的 basegroup 过滤，
  全部被滤除的池返回 `None`（对应 `ActionPool::clone` 的 null clone，
  action.cc:899-914）。
- **Rule 名对齐**（原 REJECT "raw Rule 名仍漂移"）：116 个 production Rule
  `get_name` 字面量改为锁定 oracle 构造器字符串（ruleaction.hh /
  subflow.hh / double.hh / constseq.hh / condexe.hh）；raw universal 树的
  154 Rule + 78 Action 名经 fixture 树投影 `MATCH`。
- **Production derived reset seam**（原 REJECT "derived reset 未接 virtual
  seam"）：`RuleSubvarSext::reset_for_function`（subflow.cc:1742-1746，读
  `Architecture::aggressive_ext_trim`）与 `RuleDoubleIn::reset_for_function`
  （double.cc:3198-3202，`set_double_precis_recovery(true)`）通过池的
  virtual-reset 派发，且两者均按 oracle 覆盖意图**不**清 base warning-given
  位。oracle 全树仅这两个 Rule 重写 `reset`。
- **RestartGroup 继承 state**（原 REJECT "RestartGroup drops root
  ActionState at child boundaries"）：`ActionRestartGroup::apply_with_state`
  把外部持有的基类 state 传入嵌套 group 的每个 child 边界断点检查
  （action.cc:517/560）。

production 调用闭包仍为 `MISMATCH` 的残差：restart 循环的
`Architecture::clearAnalysis` 未建模（`PIPE-RESTART-0001`）；Pool 状态机对
E2E 语料的完整 IR/order/stats 差分与独立复核未完成（`PIPE-POOL-0001`）；
`Action::print` / `printState` / `printStatistics` 控制台投影未移植
（`PIPE-BREAK-0001`）；`PcodeOpBank::create` 新建 op 初始 alive/dead lifecycle
不匹配（`OPBANK-0001`）。

## 2026-08-14：ActionPool opcode 变化后立即重派发

锁定 Ghidra `ActionPool::processOp`（`action.cc:822-875`）在每次 Rule
返回后立即重新观察目标 PcodeOp。正返回值路径先累计 change，再检查 dead/opcode；
非正返回值若仍修改了 opcode，则通过 Architecture 输出精确错误消息。两条
opcode-change 路径都会丢弃旧 opcode 尚未执行的 Rule，并从新 opcode 的规则表
索引 0 重新派发。`ActionPool::apply`（`action.cc:877-887`）负责遍历 op bank。

Rugra 现在恢复了上述 enabled/live、单 op、无断点投影，修复
SUBPIECE 被 RuleSubExtComm 改写为 INT_ZEXT 后仍继续调用旧 SUBPIECE Rule、最终
越界读取输入 1 的崩溃。真实锁定 oracle 门禁为
`tools/run_action_opcode_redispatch_oracle.sh`；它覆盖返回 1 的正常改写与“改写但
返回 0”的诊断路径，并比较调用事件、规则尝试/命中观察以及完整目标 op 状态。

上述 2026-08-14 的即时重派发门禁仍保留为窄回归信号；其当时列出的 disabled、
Rule 统计/warning/breakpoint、`op_state`/`rule_index`、live tree 与 dead cleanup
缺口已由 2026-08-24 的执行器批次补齐，并由新的组合 fixture 覆盖。

## 2026-08-12：默认 decompile 组保留已知原型锁

锁定 Ghidra `ActionDatabase::buildDefaultGroups`（`coreaction.cc:5421-5441`）
只把 `normalanalysis` 放入 `normalize` 根组；默认 `decompile` 根组不包含它。
`ActionNormalizeSetup` 虽存在于 universal tree（`:5479`），但其 group 是
`normalanalysis`，标准反编译时不会执行。Rugra 此前把 universal tree 全部平铺，
导致正常反编译也清除已导入原型的 output/model lock。本轮从默认 decompile
构造中排除该 Action；完整六组选择与其余平铺差异仍由 `PIPE-0001` 跟踪，模块
不因此升级。

## 文档状态

- **状态**: 已核对（当前有效，2026-07-02）——mainloop repeatapply 仍未启用（overflow 根因见 action.rs:806 注释，CFT 树遍历迁移后重新评估）
- **文档目标**: 说明 Rugra 当前 `Action` / `Rule` 分析流水线的职责、边界与公开接口
- **可信边界**: 本文档描述的是当前源码可见的 **Action / Rule 管线抽象**，不是对“所有规则都已实现”或“与 Ghidra 行为已完全一致”的证明
- **阅读建议**: 建议结合以下文档一起阅读：
  - `lib.md`
  - `funcdata.md`
  - `op.md`
  - `heritage.md`
  - `coreaction.md`
  - `ruleaction.md`
  - `../data_contract.md`
  - `../../VERIFICATION_GUIDE.md`

---

## 模块定位

`action.rs` 是 Rugra 当前分析流水线中的**动作调度层与规则抽象层**。  
它的核心作用不是直接表示指令或变量，而是定义：

1. 什么是一个“高层分析动作”（`Action`）
2. 什么是一个“局部变换规则”（`Rule`）
3. 如何把多个动作组织成组（`ActionGroup`）
4. 如何把动作注册、查找并形成默认分析流水线（`ActionDatabase`）

从当前主线架构来看，它处于如下位置：

```text
raw semantics / PcodeOp / Varnode / Funcdata
  -> Heritage / block-level preparation
  -> Action / Rule pipeline
  -> additional simplification / normalization / recovery
  -> PrintLanguage / PrintC
```

也就是说：

- `Action` / `Rule` 主要消费 `Funcdata` 及其内部图结构
- 它们对 IR 做分析、规范化、简化、命名或恢复相关处理
- 它们属于“过程层 / 调度层”，不是底层数据模型本身

---

## 设计意图

Rugra 当前的 `action` 层明显受 Ghidra 反编译器中 `Action` / `Rule` 体系启发。  
这一层的价值在于：把复杂的分析流程拆分成可组合、可替换、可局部扩展的步骤。

### 为什么要有 `Action`
如果把所有分析逻辑都堆在一个“大函数”里，会带来这些问题：

- 难以调试
- 难以插拔
- 难以控制执行顺序
- 难以局部替换或扩展
- 难以和 Ghidra 的分阶段流水线建立语义映射

因此，`Action` 的引入让 Rugra 可以：

- 用多个分析阶段组织函数处理流程
- 明确哪些步骤是“管线级动作”
- 为未来对齐和实验提供更清晰的插入点

### 为什么要有 `Rule`
相比 `Action`，`Rule` 更偏向于：

- 局部
- 小规模
- 面向某类操作码
- 以模式匹配和重写为主

它适合处理：

- 小型简化
- 局部等价变换
- 常量传播相关重写
- 某些规范化步骤

---

## 当前职责边界

为了避免文档继续失真，这里明确 `action.rs` 当前**应负责**和**不应负责**的内容。

### 应负责
- 定义 Action 抽象
- 定义 Rule 抽象
- 组织 ActionGroup
- 管理 ActionDatabase
- 提供默认动作流水线入口
- 为后续分析和变换建立统一执行框架

### 不应负责
- 直接定义底层 IR 节点（这是 `op.rs` / `varnode.rs` 的职责）
- 直接定义 SSA 数据结构（这是 `heritage.rs` 的重点）
- 直接负责最终 C 文本输出（这是 `printlanguage.rs` / `printc.rs` 的职责）
- 单独证明所有分析步骤都已完整落地
- 单独证明当前动作序列已与 Ghidra 完全一致

---

## 与其他模块的关系

### 与 `Funcdata`
`Action` / `Rule` 体系最主要的工作对象通常是 `Funcdata`。  
也就是说，这一层不是围绕裸 `PcodeOp` 序列孤立运作，而是围绕**函数级分析上下文**来工作。

### 与 `heritage.rs`
`heritage` 更偏向 SSA / heritage 构建与相关准备。  
`action` 层则更像是在这些基础上组织进一步的分析与变换。

### 与 `coreaction.rs`
`coreaction.rs` 更可能承载一批“核心动作实现”。  
`action.rs` 则更偏向定义抽象和调度骨架。

### 与 `ruleaction.rs`
`ruleaction.rs` 更可能承载规则型动作或规则应用实现。  
`action.rs` 则是这套体系的上层抽象入口。

### 与 `printlanguage.rs` / `printc.rs`
`Action` / `Rule` 的目标之一，是让函数级语义在进入打印层前尽量变得：

- 更稳定
- 更规范
- 更适合恢复
- 更适合输出

但打印本身不属于 `action.rs` 的职责。

---

## 导出的公共 API

---

## `pub trait Action`

`Action` 是当前 Rugra 中“高层分析动作”的基础抽象。

> trait 声明为 `Action: Send + Sync`（`Rule` 同）。Ghidra 的反编译器对象
> 全部存活于单线程，这是 Rust 侧 glue：`Architecture` 通过
> `Arc<RwLock<ActionDatabase>>` 内嵌 allacts（architecture.hh:212）后，
> trait 对象必须跨线程共享（RUGRA-GLUE 注释见 src/action.rs）。

### 角色
它表示一个**面向函数级上下文的分析或变换步骤**。  
一个 `Action` 通常不是只改一条操作，而是代表一个更完整的阶段，例如：

- 命名恢复相关动作
- DCE 相关动作
- copy merge 相关动作
- 某类规范化过程
- 一组规则的应用包装

### 当前应如何理解
你可以把 `Action` 理解为：

> “对 `Funcdata` 做一次有明确目的的阶段性处理。”

而不是：

> “任意一条局部 rewrite 规则。”

### 设计意义
有了 `Action` trait 之后，Rugra 可以：

- 把分析阶段模块化
- 让不同动作可注册、可替换
- 通过名字或顺序组织完整流水线
- 更接近 Ghidra 的动作数据库设计思路

### 文档边界
`Action` trait 的存在说明**动作调度框架已存在**，但不等于：

- 所有动作都已实现
- 所有动作都已稳定
- 当前默认动作集就是最优或最终版本
- 已与 Ghidra 当前版本动作序列完全一致

---

## `pub trait Rule`

`Rule` 是当前 Rugra 中“局部变换规则”的基础抽象。

### 角色
它通常表示一个更小粒度的规则，往往针对：

- 某类 `OpCode`
- 某种局部图模式
- 某种可证明安全的局部重写
- 某种局部简化或规范化

### 与 `Action` 的区别
可以粗略理解为：

- `Action`：较高层、阶段性、面向整体函数上下文
- `Rule`：较低层、局部性、偏模式匹配和局部重写

### 当前典型用途
规则系统适合承载以下内容：

- 算术简化
- 常量折叠相关变换
- 某些无意义中间节点消除
- 局部逻辑规约
- 为打印层准备更简洁 IR

### 当前文档边界
`Rule` trait 的存在不应被写成：

- 所有规则都已完备
- 规则库已经非常丰富
- 当前局部优化已足以达到成熟反编译器质量
- 规则执行结果已全部通过行为级对拍

---

## `pub struct ActionGroup`

`ActionGroup` 用于把多个 `Action` 组织成一个逻辑组。

### 角色
它的作用是把若干动作聚合在一起，以便：

- 按组执行
- 形成阶段性动作集合
- 让某类动作可以统一编排
- 方便默认流水线装配

### 适合理解为
你可以把它理解为：

> “一组按逻辑归类的分析动作容器。”

而不是：

> “全局唯一调度器”。

### 使用价值
当动作数量变多时，直接平铺会带来管理困难。  
`ActionGroup` 可以帮助：

- 明确某几步属于同一个阶段
- 做更清晰的流程分组
- 为默认动作集构建提供中间组织层

---

### `pub fn new(name: &str) -> Self`

创建一个新的动作组。

#### 参数
- `name`: 动作组名称

#### 作用
为一组相关
动作建立一个具名容器。

#### 典型用途
- 构造某个分析阶段的动作组
- 在默认流水线中按名字组织动作阶段
- 在调试时更方便识别当前执行的动作组

---

### `pub fn add_action(&mut self, action: Box<dyn Action>)`

向动作组中添加一个动作。

#### 参数
- `action`: 一个实现了 `Action` 的动作对象

#### 作用
把某个动作注册到当前组中，以便后续统一执行。

#### 说明
这说明当前动作体系采用的是：

- 动态分发
- trait object
- 运行时组合

这种设计更适合做：

- 插拔
- 实验
- 分阶段装配
- 与不同动作实现解耦

---

## `pub struct ActionDatabase`

`ActionDatabase` 是当前 Rugra 动作体系中最关键的管理对象之一。

### 角色
它负责统一管理已注册动作，并提供默认分析动作集的构建和访问入口。

从概念上可以把它理解为：

> “整个函数级动作流水线的注册表 / 调度入口 / 默认动作集容器。”

### 典型职责
- 注册动作
- 按名称查找动作
- 建立默认动作集
- 为高层分析流程提供统一入口

### 当前在架构中的意义
`ActionDatabase` 的存在非常重要，因为它意味着 Rugra 当前不再把分析阶段写成“硬编码大流程”，而是在向：

- 可注册
- 可组合
- 可扩展
- 可对齐
- 可阶段化

的动作数据库设计靠拢。

### 但要注意
`ActionDatabase` 的存在不等于：

- 默认动作链已经全部成熟
- 当前动作顺序已经稳定到可视作最终答案
- 所有动作都已经高质量实现
- 已经完成与 Ghidra 动作库的逐项等价验证

---

### `pub fn new() -> Self`

创建一个新的动作数据库。

#### 作用
初始化一个空的 `ActionDatabase`。

#### 典型用途
- 测试中手动装配动作集
- 构建自定义动作管线
- 从零注册动作后再执行

---

### `pub fn register_action(&mut self, action: Box<dyn Action>)`

向数据库中注册一个动作。

#### 参数
- `action`: 一个实现了 `Action` 的动作对象

#### 作用
把动作放入数据库中，供后续查找或执行。

#### 设计意义
这说明动作系统不是硬编码绑定的，而是允许：

- 动态装配
- 试验性添加
- 定制动作集
- 分场景选择动作链

---

### `pub fn get_action(&self, name: &str) -> Option<&dyn Action>`

按名称获取动作。

#### 参数
- `name`: 动作名称

#### 返回
- 找到时返回对应动作的只读引用
- 未找到时返回 `None`

#### 作用
提供按名字访问动作的能力，便于：

- 调试
- 检查默认动作集
- 做定向调用或验证
- 构建更复杂的调度逻辑

#### 注意事项
按名称查找动作本身很有用，但名称存在不代表：
- 动作一定已经在当前主线中执行
- 动作一定已经稳定可用
- 同名动作的行为已经最终定型

---

### `pub fn set_default_actions(&mut self)`

建立默认动作集（生产入口）。

### 作用
镜像 `Architecture::buildAction`（architecture.cc:582-591）的完整序列：
`universal_action()` 构建原始 universal 树并注册为 `"universal"`，随后
`reset_defaults()`（action.cc:986）保留 universal、重建默认 grouplist
（`build_default_groups`，coreaction.cc:5419-5458，六个根：decompile/
jumptable/normalize/paramid/register/firstpass），最后
`set_current("decompile")` → `derive_action("universal","decompile")`
（action.cc:1145）按 decompile grouplist 做 clone 存活过滤，派生出
默认根并登记为 current。

### 派生过滤（PIPE-DERIVED-TREE-0001 + 2026-08-24 rework Rule 级闭合）
`universal_action(Some(&grouplist))` 在每个注册槽上应用 Ghidra
`Action::clone` 的存活语义（action.cc:391-406/899-914/529-544）：
叶子当且仅当其 basegroup ∈ grouplist 才注册；组/池当且仅当仍有存活
子节点才挂到父节点；**池内 Rule 逐条按其注册槽 basegroup 过滤，
无存活 Rule 的池整体省略**（`Rule::clone` group check +
`ActionPool::clone` null 语义，action.cc:899-914）。对默认 `decompile`
grouplist（coreaction.cc:5424-5431）：
- 头部 8 槽中 `normalizesetup`（normalanalysis）与 `funclink_outonly`（noproto）被过滤；
- `directwrite` 的两个 protorecovery_b 实例（:5498/:5681）被过滤；
- 尾部 `normalizebranches`（:5716，group 名 normalizebranches 不在 decompile 集）被过滤；
- 根节点名保持 `"universal"`（clone 保留 getName()），数据库键为 `"decompile"`。

对拍证据：`tests/oracle/pipeline_tree_1204.*` +
`tools/run_pipeline_tree_oracle.sh`（78 节点 DFS 双侧字节一致，
path/ordinal/kind/name/basegroup/flags），以及
`tests/oracle/action_break_pool_1204.*` 的 `dtree` 投影（raw +
decompile/jumptable/register 三派生根的全部 Action/Rule 名与存活过滤）。

### 相关新增 API
- `ActionGroupList`（action.hh:31-40）：`from_members`/`contains`/`member_names`
  （成员键为 `String`，支持 `addToGroup`/`removeFromGroup` 的运行时串）。
- `default_groups` 模块：六个默认 grouplist 的逐字成员表。
- `ActionDatabase::universal_action()`（coreaction.cc:5462）。
- `ActionDatabase::reset_defaults()` / `set_current()` / `derive_action()` /
  `get_current()` / `get_current_name()`（action.cc:986/1021/1145、action.hh:313-314）。
- `ActionDatabase::get_group()`（action.hh:315 `getGroup`，pub 化）。
- `ActionDatabase::toggle_action(grp, basegrp, val)`（action.cc:1036）：
  在指定 root 的 grouplist 上 add/remove 组，随后**始终**从 universal 重新
  clone、重注册（替换旧对象），并在 `grp == currentactname` 时更新 currentact。
  Ghidra 返回新 root 指针；Rust 侧调用方经 `get_action`/`get_current` 重取。
- `ActionDatabase::add_to_group(grp, basegroup) -> bool` /
  `remove_from_group(grp, basegrp) -> bool`（action.cc:1090/1103）：grouplist
  条目缺失时默认插入（`groupmap[grp]` 语义），`isDefaultGroups` 先清零；
  返回值语义 = set insert `.second` / erase 计数 > 0。
- `ActionDatabase::actionmap_size()`：注册表大小的 fixture 观察视图。
- `universal_action(Option<&ActionGroupList>) -> Option<ActionRestartGroup>`：
  coreaction.cc:5462-5738 的全槽镜像构建（None = 原始树）。
- `build_default_pipeline()`：派生 decompile 根的测试/示例便捷入口。
- `ActionGroup::add_action_in_group` / `child_group`：注册槽 basegroup 记录
  （Ghidra 存于 Action 实例的 basegroup 成员）。
- `Action::as_action_pool`：树遍历 fixture 的池视图。
- `build_oppool1(Option<&ActionGroupList>) -> Option<ActionPool>`（原
  `build_simplify_pool`）：池名从 `simplifypool` 改为 oracle 精确名
  `oppool1`（coreaction.cc:5511）；grouplist 传入时逐 Rule 按 basegroup
  过滤（Rule::clone 语义）。`build_oppool2` / `build_cleanup_pool` 同形。

### toggleAction 的 oracle 行为证据（OPTIONS-SPLITDATATYPE-WIRING-0002）
双侧 fixture `tests/oracle/options_wiring_1204.*`：oracle 侧以最小
Architecture 子类驱动真实 `OptionSplitDatatypes::apply`（options.cc:999）
→ `toggleAction`（action.cc:1036）；Rust 侧驱动生产
`options::OptionSplitDatatypes::apply` + `split_action_toggles` + 两次
`toggle_action` 转发序列。25 条记录双侧逐字节一致，覆盖：
- 每次**成功** apply 都重 clone 并替换当前 root（含 config 不变的重申场景），
  universal 根永不替换（构造序数通道观察，规避分配器地址复用）；
- p1 未知 token 抛错前零突变；p2 未知 token 留下 p1 部分赋值且不进 toggle 块。

### 当前意义
这是当前动作系统中最重要的“默认流水线入口”之一。  
它体现了项目已经开始把“函数分析阶段”收敛成一套默认动作顺序。

### 更准确的理解
当前应把它理解为：

> “为当前 Rugra 架构建立一套默认动作装配方案。”

而不是：

> “已经完成、不可更改、与 Ghidra 全等的最终动作链。”

### 为什么这个接口重要
因为它直接影响：

- 哪些分析步骤默认会运行
- 顺序如何组织
- 是否更容易得到可打印的 IR
- 后续输出质量的基础状态

---

## 动作执行结果常量

本模块公开了一组整型常量，用于表达动作执行后的结果状态。

### `pub const NO_CHANGE: i32 = 0`
表示本次动作执行后**没有产生变化**。

#### 典型语义
- 当前动作检查过了，但无需修改
- 对当前函数上下文没有带来有效变换
- 可用于调度器判断是否继续推进某些迭代逻辑

---

### `pub const CHANGE: i32 = 1`
表示本次动作执行后**产生了变化**。

#### 典型语义
- IR 被改写
- 节点状态发生变化
- 某些结构被重建或清理
- 后续阶段可能需要重新评估某些条件

---

### `pub const RESTART: i32 = 2`
表示本次动作执行后需要**
重新开始某类流程**。

#### 典型语义
这通常用于更复杂的调度场景，例如：

- 某些变换改变了前提条件
- 需要重新扫描规则
- 需要重新执行某些阶段
- 当前迭代已不适合继续沿用原状态推进

### 说明
`RESTART` 的存在说明动作调度并不总是线性的。  
某些动作可能会让整个局部分析状态发生较大变化，从而需要重新进入某一轮流程。

---

## 当前主线中如何理解 Action / Rule 流水线

结合当前架构，`Action` / `Rule` 流水线更适合被理解为：

```text
Funcdata ready
  -> default actions prepared in ActionDatabase
  -> actions run in configured sequence
  -> some actions may apply local rules
  -> IR becomes more stable / simpler / more printable
  -> output stage consumes the result
```

也就是说：

- `Funcdata` 提供上下文
- `ActionDatabase` 提供组织方式
- `Action` 提供阶段性处理
- `Rule` 提供局部改写
- `PrintC` 等输出层消费最终结果

---

## 当前应避免的误解

### 1. 有 `ActionDatabase` 不等于默认动作链已经最终成熟
这
只能说明当前项目已经有了“动作数据库式”组织结构。

### 2. 有 `Rule` trait 不等于局部规则库已经完备
规则库是否足够丰富、是否覆盖关键模式，要看具体实现与测试。

### 3. 动作存在不等于行为已验证
即使某个动作已注册，也不能自动推出：
- 它已通过运行时对拍
- 它与 Ghidra 行为一致
- 它不会引入输出回归

### 4. 调度层不等于结果质量本身
动作体系是“过程组织层”，不是最终输出质量的唯一决定因素。

---

## 与 `coreaction.rs` / `ruleaction.rs` 的分工建议

虽然真正实现细节应以源码为准，但从文档层面建议这样理解：

- `action.rs`
  - 定义抽象
  - 定义数据库
  - 定义动作组和执行结果常量
- `coreaction.rs`
  - 承载较核心、较大粒度的动作实现
- `ruleaction.rs`
  - 承载基于规则的局部重写实现

这种理解方式更符合当前主线的职责划分，也比旧式笼统描述更不容易误导。

---

## 推荐联动阅读

若你正在理解当前 Rugra 的动作管线，建议继续阅读：

1. `funcdata.md`
2. `op.md`
3. `varnode.md`
4. `heritage.md`
5. `coreaction.md`
6. `ruleaction.md`
7. `blockaction.md`
8. `printc.md`
9. `../VERIFICATION_GUIDE.md`

---

## 文档维护建议

后续若继续维护 `action.rs` 的 API 文档，建议同步关注以下变化：

- `Action` / `Rule` trait 的签名是否变化
- `ActionGroup` 是否新增执行逻辑
- `ActionDatabase` 是否新增默认构建入口
- 默认动作集是否发生结构变化
- 动作执行状态常量是否扩展
- `coreaction` / `ruleaction` 的分工是否调整

同时应避免再次把以下内容写成既成事实：

- “默认动作集已经完全成熟”
- “当前动作顺序已经与 Ghidra 一致”
- “规则系统已经足以覆盖所有关键优化”
- “动作数据库存在就说明分析流水线已稳定收敛”

---

## 一句话总结

`action.rs` 是 Rugra 当前 **Action / Rule 分析流水线的抽象与调度入口**：它定义了什么是动作、什么是规则、如何把动作组织成组、如何通过数据库建立默认分析管线。它是当前主线架构中非常关键的过程组织层，但不应被文档夸大成“所有分析能力已成熟”或“与 Ghidra 动作体系已完全一致”的证明。
### 2026-06-24：ActionTypePropagate 集成

- ActionTypePropagate 在 ActionCopyPropagate 之后运行，保守标记 struct pointer varnode。

### 2026-06-27（会话2）：ActionConditionalExe 接入主管线

- `ActionConditionalExe`（crate::condexe）注册在 `decompile` group 的 `ActionDeadCode` 之后、`ActionBlockStructure` 之前，对应 Ghidra coreaction.cc:5675 mainloop 顺序。条件执行消除（condexe.cc:712）在结构化前折叠冗余 CBRANCH 汇合。

### 2026-07-02：ActionInferTypes 接入 mainloop（对齐 coreaction.cc:5508）

- `ActionInferTypes`（coreaction.cc:5508 "typerecovery"）现注册在 mainloop 的 `ActionRestructureVarnode` 之后、`ActionConditionalExe` 之前，faithful to Ghidra 注册顺序。此前它**只有实现没有注册**，导致类型恢复从不执行，所有 Unique varnode 的 `vn.v_type = None`，`printc::maybe_apply_type_prefix` 无法升级前缀。
- 效果（curl）：uVarN 453→0（全部升级为 lVar/iVar/sVar/bVar 等类型前缀），lVar_etc 346→474（接近 Ghidra 481）。pcVar_etc 81（Ghidra 246）—— 指针类型恢复仍弱，是类型系统下一步。
- 自限 7 轮（coreaction.cc:5411 `local_count >= 7` 停止），无收敛警告，957/957 测试通过。
- 依赖 `ActionStartTypes`（build_full_pipeline_actions，coreaction.cc:5687）先 `set_type_recovery_started()`，否则 InferTypes 立即 NO_CHANGE。

### 2026-06-27（会话3 续）：ActionRestructureVarnode 接入主管线

- `ActionRestructureVarnode`（coreaction.cc:5505 "localrecovery"）现注册在 `decompile` group 的 `ActionDeadCode` 之后、`ActionConditionalExe` 之前。此前它**未接入**，导致 `fd.scope` 永远为 None，printc 的 `get_stack_variable_name` 永远找不到栈变量名 → uVar 碎片。接入后 scope 被构建，local_ 统计从 81→78（curl）。**G3 剩余**：多数函数 gather_spacebase 收集到 0 hints，根因是栈访问用 RBP/param 指针而非 RSP 直派，需扩展 spacebase 基址识别 + 修复 SSA def 断链。

### 2026-06-29：ActionMarkType 移到 dead-code 之后（对齐 Ghidra 管线顺序）

- `ActionMergeType` 此前注册在 `CopyPropagate` **之前**（action.rs 416），违反 Ghidra 顺序（coreaction.cc:5682 deadcode → 5718-5729 merge 阶段）。后果：merge 在 copy-prop/dead-code 删除 op 之前建立 `high.instances`，之后这些 instances 永不更新（copy-prop/dead-code 不清理），printc 拿到陈旧 instances → 自建 4 套 map 重建 def 关系。
- 现顺序：`CopyPropagate → TypePropagate → CallParams → RestrictLocal → DeadCode → ActionMergeType → MarkExplicit → MarkImplied → RestructureVarnode`。MarkExplicit/MarkImplied 在 MergeType 之后（Ghidra 的 MergeRequired 在 MarkImplied 前建 high，Rugra 的 merge_all 合并了 MergeRequired+MergeType，故 MarkImplied 跟在 merge_all 后）。配合 `Merge::is_live_varnode`（merge.rs）跳过死 varnode，`high.instances` 现反映 dead-code 后的 varnode 集，成为 printc 可信的权威来源。这是 P0 "声明却未赋值" 症状的根因修复（详见 `docs/alignment_docs/P0_DEF_CHAIN_DIAGNOSIS_2026-06-29.md`）。
- **implied 机制接入**（2026-06-29）：MarkImplied 用 checkImpliedCover（cover 相交）标记 implied varnode；printc 的 emit_block_ops 跳过 implied-output 的 op（对齐 printc.cc:2704），push_varnode 对 implied varnode 递归 inline 其 def 表达式（recurse 等价）。这是 Ghidra 控制内联的权威机制，替代 printc 自造的 4 套 map。
- curl 审计保持 24/24；`debug_my_fwrite` 中间变量（如 `piVar1`/`lVar3`）被正确内联。已知调优项：部分函数有重复变量声明（块内 shadow，gcc 允许但影响可读性）。

### 2026-06-29：ActionFuncLink 接入主管线（在 ActionHeritage 之前）

- `ActionFuncLink` 注册在 decompile_group 的 `ActionStart` 之后、`ActionHeritage` **之前**（对齐 Ghidra coreaction.cc:5484 FuncLink → 5492 Heritage）。它在 ActionFuncLink::apply 里调 `ensure_callspecs`（对齐 FlowInfo::setupCallSpecs flow.cc:680）扫描所有 alive CALL op 建立 FuncCallSpecs，存入 fd.callspecs，再对每个调 funcLinkInput/funcLinkOutput。此前 callspecs 仅测试填充。funcLink 的 locked 路径（opInsertInput/newVarnode/newVarnodeOut）仍 deferred。

- **移除 ActionCallParams**（2026-06-29 完整移植）：CALL 参数现由 ActionFuncLink::funcLinkInput 建立（opInsertInput + newVarnode），对齐 Ghidra coreaction.cc:1474。ActionCallParams（lifter 挂寄存器 + trim 的简化方案）已移除。

### 2026-06-27（会话3 续）：ActionPool — Rule 调度器接入主管线（G6 核心补全）

**系统性架构补全**：Rugra 此前 ~90 个 Rule 全部实现了 `apply_op` 但**均未接入主管线**——无 Ghidra ActionPool 式的 Rule 遍历调度。本次补全：

- 新增 `ActionPool` struct（对应 Ghidra `ActionPool`，action.hh:262）：持有 `Vec<Box<dyn Rule>>` + `per_op: Vec<Vec<usize>>` 按 OpCode 判别值索引的数组（2026-09-28 ACTIONLOOP-RESTART-0001 起，原为 `HashMap<OpCode, Vec<usize>>`，即 oracle `perop[CPUI_MAX]` action.hh:264 的数组形态）。`add_rule` 注册 Rule 并按 opcode 建索引；`apply` 遍历所有 live op，按 opcode 匹配 Rule，循环至固定点（对应 Ghidra rule_repeatapply）。
- `build_simplify_pool()` 注册 **112 个简化 Rule**（2026-06-29 实测：`grep -cE 'pool\.add_rule'` = 105）。**镜像 Ghidra `oppool1` 精确顺序**（coreaction.cc:5511-5649）：每行标注 Ghidra 源码行号，未移植的 Rule 以 `skip` 注释标注。**2026-06-29 新增**：RuleSubCommute（5577）、RuleFloatSign（5619）、RuleSLess2Zero（5558）。
- **`build_cleanup_pool()`**（对齐 Ghidra `actcleanup` coreaction.cc:5694-5710）：独立池，含 `RuleMultNegOne`/`Rule2Comp2Sub` + **`RuleStringCopy`/`RuleStringStore`（constseq，coreaction.cc:5709-5710）**。constseq 模块此前代码完整但从未接入主管线（死代码），现已接入。**在 simplify 池之后跑**（阶段分隔）。这解决了一个收敛 bug：RuleMultNegOne（`x*-1→INT_2COMP`）若与 Rule2Comp2Mult（`INT_2COMP→x*-1`，oppool1 内）同池会无限 ping-pong；Ghidra 靠阶段分隔（主池先收敛、cleanup 池再跑一次）避免循环，Rugra 现忠实移植此机制。constseq 的 transform 阶段（替换为 CALLOTHER）仍待 userop 基础设施。
- RuleEarlyRemoval(5512) 的“只允许 CONSTANT”是历史实现，现已废止。当前锁定
  fixture 覆盖六守卫、严格 `pass > deadcodedelay`、writemask/autolive 正交、
  OTHER policy 与 72 个 typed-opcode dispatch（68 删除、四类 call/new 保留），
  14/14 covered records MATCH。完整 reset/clear、FSPEC/overlay manager、nullable
  input、op-bank 与错误生命周期仍为 MISMATCH/UNTESTED，不能据此宣称整个 Rule 或
  ActionPool 闭包 MATCH。
- 接入 `set_default_actions`：`ActionStart` → `ActionHeritage` → **`ActionSpacebase`** → `ActionStackPtrFlow` → `ActionSimplify` → `build_simplify_pool()` → `build_cleanup_pool()` → ... → `ActionCallParams` → **`ActionRestrictLocal`**（2026-06-29 新增）→ `ActionDeadCode` → ...

**验证（2026-06-28 量化核实）**：`ActionPool::apply` 增加可选 per-Rule 触发计数（环境变量 `RUGRA_RULE_STATS=1` 开启，默认关闭，不影响行为）。实测 `RUGRA_RULE_STATS=1 cargo run --example curl_decompile`：curl 24 函数反编译中 Rule 池触发 **515 次简化**，涉及 **21 个不同 Rule**（propagate_copy 244 / and_mask 43 / sub2_add 40 / less2_zero 39 / or_consume 29 / collapse_constants 23 / add_mult_collapse 20 / mult_neg_one 18 / 2comp2sub 18 / bool_negate 11 / ...）。**此前声称"实际反编译不触发任何 Rule 简化"为过期误判，已作废。** 776/776 测试通过，curl 24/24 + httpd 29/29 gcc 审计，0 goto。

**注意**：**2026-06-29 ActionSpacebase 接入后，uVar 碎片 149→0**（此前的说明"uVar 碎片数未变 149"已过时）。spacebase 标记让 varmap/printc 正确识别 RSP 为栈空间指针，消除了变量恢复层的 def 断链问题。

### 2026-06-27（会话3 G5）：结构清理 Action 未接入说明

ActionDeterminedBranch/ActionUnreachable/ActionDoNothing/ActionRedundBranch 的 apply() 已完整移植（coreaction.cc:3457-3528），但**未接入 set_default_actions**。set_default_actions 中有 NOTE 说明：Ghidra 在 selectGoto→collapseInternal 循环内运行这些清理 Action，structurer 围绕块删除设计；Rugra 的 staged-phase structurer 依赖这些块，接入导致回归。完整接入需 staged→collapseInternal 架构迁移（G4 可选优化）。apply() 逻辑已就绪。
### 2026-06-27（续）：ActionStackPtrFlow 接入管线（Heritage 后）
- set_default_actions 在 ActionHeritage 后接入 ActionStackPtrFlow（对齐 Ghidra actstackstall, coreaction.cc:5656）。

### 2026-07-01：oppool1/cleanup pool 大批补缺 Rule 注册接入

`build_oppool1`（原 `build_simplify_pool`，池名已改为 oracle 精确名 `oppool1`）按 Ghidra coreaction.cc:5511-5649 顺序补齐此前 skip 的注册槽：
- 5517 RulePullsubIndirect、5551 RuleIndirectCollapse、5565 RuleTransformCpool、5606 RuleSwitchSingle
- 5621-5628 subvar 族（RuleSubvarAnd/Subpiece/SplitFlow/SubvarCompZero/Shift/Zext/Sext，来自 subflow.rs）
  - 例外：5624 RulePtrFlow 仍未移植（ruleaction.cc:9177，重）
- 5629-5641：RuleNegateNegate/ConditionalMove/FuncPtrEncoding/IgnoreNan/Unsigned2Float/Int2FloatCollapse/PtraddUndo/PtrsubUndo/Segment/PiecePathology
  - 例外：5631 RuleOrPredicate 存于 condexe.rs 但非 Rule trait impl，暂 skip
- 5633 RuleSubfloatConvert（subflow.rs）、5634 RuleFloatCast（从 local-extras 移至 Ghidra 正确槽位）
- 5643-5646 RuleDoubleLoad/Store/In/Out（来自 double_precis.rs）

`build_cleanup_pool`（actcleanup）补齐 coreaction.cc:5696-5708：
- 5697 RuleAddUnsigned、5700 RuleSubRight、5701 RuleFloatSignCleanup、5702 RuleExpandLoad、
  5703 RulePtrsubCharConstant、5704 RuleExtensionPush、5705 RulePieceStructure、
  5706-5708 RuleSplitCopy/Load/Store（来自 subflow.rs）
  - 例外：5699 RuleDumptyHumpLate 仍未移植（subflow.cc:3012）

lib.rs 新增 `pub mod double_precis`。RuleFloatCast 从 local-extras 移除（避免与 5634 重复注册）。

验证：832/832 测试，curl 24/24 无回归。

### 2026-07-01（重大）：管线架构改造 — perform 调度引擎 + 嵌套树结构
- **perform 状态机**：移植 Ghidra action.cc:298-362。`Action::perform(&mut self, fd, &mut ActionState)` 驱动 repeatapply/onceperfunc 语义。ActionState 持有 status/count/flags 字段。
- **Action trait 改 `&mut self`**：apply/reset 签名变更，全仓连锁修改（coreaction.rs/blockaction.rs/condexe.rs/funcdata.rs/examples/bin）。
- **ActionGroup 改 perform 驱动**：apply 调子 Action 的 perform（而非直接 apply），支持状态续传。
- **ActionPool 单遍化**：移除内部 repeat loop，由父级 perform 的 rule_repeatapply 驱动。补 opcode 变化检测（action.cc:862-867）。
- **ActionRestartGroup 新建**：移植 action.cc:554-583。universal 根容器，支持 restart pending → clearAnalysis → 重跑。
- **Funcdata +restart_pending + has_restart_pending/set_restart_pending + is_jumptable_recovery_on**。
- **set_default_actions 重构为嵌套树**：universal(ActionRestartGroup) → fullloop(ActionGroup) → mainloop(ActionGroup) → stackstall(ActionGroup) → oppool1(ActionPool)。
- **TODO**：fullloop/mainloop/stackstall 暂不设 RULE_REPEATAPPLY（Rugra 自造 Action 非幂等，重复会导致死循环）。待自造 Action 幂等化或替换为 Ghidra 机制后启用。
- **apply_all 改 perform 驱动**：每个函数先 reset，再 perform。

### 2026-07-01（续）：perform count 修复 + stackstall repeatapply 启用
- perform count 累加 bug 修复：count/count_tests 只在循环外清零/递增一次（对齐 action.cc:298-362）。
- ActionRestartGroup apply 返回值修复：只在 res<0（断点）时早返回。
- stackstall 启用 RULE_REPEATAPPLY（唯一子节点 simplify pool 可收敛）。
- mainloop/fullloop 暂不启用（非幂等子 Action 导致死循环）。

### 2026-07-01（续 2）：接入 22 个 pipeline Action

### 2026-07-01（续 3）：oppool2 接入 + build_full_pipeline_actions 更新
- build_oppool2() 新增，注册进 mainloop（stackstall 之后，coreaction.cc:5662）。
- build_full_pipeline_actions 新增 ActionStartTypes/AssignHigh/DominantCopy/CopyMarker。

### 2026-07-01（续 4）：注册 3 条缺失 Rule
RulePtrFlow(oppool1:5624) + RuleOrPredicate(oppool1:5631) + RuleDumptyHumpLate(cleanup:5699) 全部注册。

### 2026-07-01（续 5）：mainloop repeatapply 调查结果
mainloop RULE_REPEATAPPLY 测试：导致无限循环。根因：build_full_pipeline_actions 的 22 个 Action 中某些（ActionDirectWrite/ActiveParam 等）每次 apply 都报告变化。启用需要逐个验证这些 Action 的幂等性。暂不启用，标注 TODO。

### 2026-07-01（续 6）：perform loop cap + mainloop repeatapply 调查（栈溢出）
perform 加 100 次迭代安全阀（防止非幂等 Action 死循环）。mainloop RULE_REPEATAPPLY 测试：simplifypool 达到 cap 后 mainloop repeatapply 导致栈溢出（复杂函数）。结论：启用需要所有 22 个 extra Action 真正幂等（第二次 apply 返回 0 无副作用）。当前不启用。DoNothing/RedundBranch 接入测试：破坏 16 个结构化测试预期（splice 改变 bblocks），回退。

### 2026-07-01（续 7）：perform cap=3 + mainloop repeatapply 根因分析
cap 从 100→10→3。mainloop repeatapply 根因：ActionGroup.perform 在嵌套树中递归调用子 Action perform（5 层 × repeatapply 迭代），每个 RwLock guard ~2KB 栈，3³=27 层嵌套 perform 超过 Windows 8MB 栈。修复需重写 ActionGroup.perform 为迭代（非递归）或增大栈。cap=3 保留作为 ActionPool 叶子级安全阀。

### 2026-07-01（续 8）：256MB 线程栈 + mainloop repeatapply 深度根因
curl_decompile 改用 256MB 线程栈（防嵌套 perform 递归溢出）。mainloop repeatapply 在 256MB 栈下仍溢出→根因不是栈大小，而是 **pipeline 非收敛**：repeatapply 导致 Rule 在每轮创建新 op，alivelist 无限增长，ActionPool apply 的 clone(alivelist) 消耗全部内存。这是 pipeline 正确性问题（某些 Rule/Action 每轮产生新 op 而非收敛到不动点），需要逐个验证哪个 Rule/Action 不收敛。暂不启用 mainloop repeatapply。

### 2026-07-01（续 9）：迭代式 ActionGroup.apply（消除 perform 递归）
ActionGroup::apply 改为：对有 repeatapply flag 的子 Action 调 perform（如 ActionPool），对没有的调 apply（如中间 ActionGroup）。这消除了 perform→apply→child.perform→child.apply 的递归链——只有叶子级 repeatapply Action（ActionPool）使用 perform，中间 ActionGroup 用 apply + 父级 perform 循环。

mainloop repeatapply 仍不启用：即使迭代式 apply + 256MB 栈仍溢出。根因是 Rule apply_op 内部的深层 RwLock guard 链（Rule 接收 &Arc<RwLock<PcodeOp>>，apply_op 内部可能持有嵌套 read/write guard）。修复需重构 Rule apply_op 避免 nested lock，或用非递归 pipeline executor。

### 2026-07-01（续 10）：迭代式 ActionGroup.perform + mainloop repeatapply 最终根因
ActionGroup.perform 重写为迭代式：循环调 self.apply()，不递归进默认 perform。cap=1+mainloop repeatapply→24/24 通过；cap=2→glob_range 栈溢出。

### 2026-07-02：移除 perform/ActionGroup 迭代上限（R73 对齐 Ghidra，输出中性）
- **变更**：`Action::perform` 删除 `if iterations > 1 { break; }`（action.rs:90-92），`ActionGroup::perform` 删除 `if iterations > 2 { break; }`（action.rs:270）。两者改为纯 `lcount >= count` 终止（与 Ghidra action.cc:298-362 的无界 do-while 一致）。
- **动机**：audit R73。原上限是续 7/10 时期防 glob_range 栈溢出/死循环的安全阀；但续 9（迭代式 ActionGroup.apply）+ 续 10（迭代式 perform）已修复溢出根因（递归 perform→apply→child.perform 链），该上限已是冗余技术债，且静默禁用了 repeatapply 收敛（如 `V^V→0` 折叠后传播到 RETURN 的多轮简化）。
- **验证（2026-07-02 19:50 实测）**：
  - `cargo test --lib` 961/961 通过，零回归零挂起。
  - curl_decompile 连跑 3 次：rc=0，1281 行，glob_range 函数体完整（1266 字符，以 `}` 收尾），**无栈溢出**。
  - func_gap_audit（vs tests/golden/ghidra_curl.c）：0 EXACT / 24 DIFF — 与移除前**完全一致**（输出中性）。即此改动既未引入回归也未带来改善，但消除了收敛性阻塞，为后续 Rule 多轮简化生效扫清障碍。
- **诚实声明**：本次改动对 curl 当前输出**无可见影响**（return-V^V 等缺陷未变）。其根因经诊断（RUGRA_DBG_XOR）证实不在迭代上限，而在更深处（main_init 的 `iVar1^iVar1` 中 iVar1 为未初始化 varnode，由 printc 返回值启发式合成，非真实 `xor eax,eax`）。单指令 `xor eax,eax` 提升测试（test_xor_eax_eax_input_identity）证明 lifter 的 varnode 身份 dedup 正确（ptreq=true），故 main_init 缺陷需在返回值恢复层（ActionReturnRecovery）继续追查。

**最终根因**：mainloop repeatapply 重新运行 ActionHeritage（有深层递归 rename 逻辑 visit_rename_impl）。glob_range 有 17 bblocks，Heritage 的递归重命名在多轮 repeatapply 下累积递归深度，即使 256MB 栈也溢出。修复需要让 Heritage 的 rename 迭代化（非递归），或接受 Rugra 的 Actions 有内部循环不需要外部 repeatapply。

### 2026-07-01（续 11）：mainloop repeatapply 仍阻塞（迭代 Heritage 后 cap=1 仍溢出）

### 2026-07-01（续 12）：mainloop repeatapply 最终根因确认
通过加 `[STEP]` 日志定位：栈溢出发生在 `[STEP] glob_range action done` **之后**——即 pipeline 已完成，溢出在 `printer.doc_function()` 期间。这证明根因不是 pipeline 执行时的栈深度，而是 **sblocks 与 bblocks 不同步**：
1. mainloop repeatapply 第 1 轮：ActionBlockStructure 构建 sblocks
2. mainloop repeatapply 第 2 轮：其他 Action（Heritage/Simplify/CopyPropagate）改变 bblocks（新 op/varnode）
3. ActionBlockStructure 检查 `sblocks.get_size() != 0` → 跳过（不重建 sblocks）
4. sblocks 此时与 bblocks 不一致
5. printc 的 `emit_block_structured` 递归遍历 sblocks → 结构不匹配 → 无限递归 → 栈溢出

修复需要：sblocks 失效机制（bblocks 变化时清除 sblocks 让 ActionBlockStructure 重建）或将结构化 Action 移出 repeatapply 循环。这是架构级改进。

### 2026-07-01（续 13）：sblocks 失效 + printc 递归溢出
ActionBlockStructure: +last_op_count，op count 变化时 clear sblocks 重建。mainloop repeatapply 仍不启用：sblocks 重建后 printc emit_block_structured 在新结构上递归溢出。修复需迭代化 printc。

### 2026-07-01（续 14）：printc depth guard + mainloop repeatapply 最终状态
printc emit_block_structured +thread_local depth guard（>200 回退）。sblocks 失效重建保留。mainloop repeatapply 测试：depth guard+rebuild 仍溢出（200层×栈帧>256MB）。不启用。

### 2026-07-01（续 15）：mainloop repeatapply 栈帧分析
根因=emit_block_structured match 栈帧巨大（所有 arm 局部变量同帧）。depth=50+256MB 仍溢出。修复需拆分 per-arm helpers 或完全迭代化。

### 2026-07-01（续 16）：per-arm printc helpers + mainloop repeatapply 最终诊断（无限递归）
printc emit_block_structured 拆分 7 个 per-arm helpers。mainloop repeatapply 测试 depth 20-200+256MB：全部溢出。最终诊断=不是栈帧大小而是 sblocks 重建后的真正无限递归。

### cleanup pool 加 RuleTrivialArith（2026-07-03）— **2026-08-23 已回退（PIPE-POOL-LOCAL-RULES-0001）**
- ~~在 `build_cleanup_pool` 末尾注册 `RuleTrivialArith`。~~ 该 Rugra-local 注册已
  删除：oracle actcleanup（coreaction.cc:5694-5711）没有 RuleTrivialArith；Ghidra
  只在 oppool1（coreaction.cc:5522）注册它一次。Ghidra 靠 mainloop repeatapply
  `actprop` 重简化后期新创建的 op；Rugra 此前靠 cleanup 补刀是绕过基础设施缺口
  的上层适配（铁律 1.4/1.5 违例），已回退。"mainloop 不 repeatapply 导致后期
  trivial op 不被再简化"是真实残差，登记为 TODO（见 pipeline_tree_1204.metadata
  的 mainloop 阶段残差；对齐路径 = 补齐 mainloop RULE_REPEATAPPLY，而非在
  cleanup 池塞 oracle 没有的规则）。E2E 门禁数据（2026-08-23，curl 1204 语料）：
  删除前后 defects/numbering/skeleton 零变化——该补刀在当前语料上无可观测收益。

### 启用 ActionSetCasts（2026-07-03 续）
- `set_default_actions` 里 ActionSetCasts 之前被注释掉（注释说"需要 ActionInferTypes 先跑"）。ActionInferTypes 已在 mainloop（line 864）跑，所以条件满足。
- 按 Ghidra 顺序（coreaction.cc:5735：MarkImplied → NameVars → SetCasts → FinalStructure）在 ActionMarkImplied 后、ActionNormalizeBranches 前启用。
- 当前 castInput 只覆盖 integer binary/unary 路径（PTRADD/PTRSUB/resolveUnion/castOutput 待补），所以对当前输出影响小（类型系统还太松，cast 机会少），但这是把 SetCasts 接入主管线的正确步骤，后续补全 castInput 范围后会逐步产生 cast。

### ActionAssignHigh 注册澄清（2026-07-03 续）
- set_default_actions 里移除了重复的 ActionAssignHigh 注册——它已在 build_full_pipeline_actions（coreaction.rs:7084）注册，RULE_ONCEPERFUNC 保证幂等，无需在 universal 层重复。

### ActionOutputPrototype + ActionInputPrototype 接入主管线（2026-07-03 续）
- 两个 Action 之前已实现（coreaction.rs:4180/4254）但未在 set_default_actions 注册。
- 按 Ghidra 顺序（coreaction.cc:5730-5731）在 MarkImplied 后、SetCasts 前注册。
  - ActionOutputPrototype：从 RETURN ops 推导返回类型（已由 ActionReturnRecovery 挂载返回值）。
  - ActionInputPrototype：从 input varnodes 推导参数个数/类型（已由 ActionInferParams 做初步检测）。

### 主管线全量审计 + 注册（2026-07-03 续）
- 审计了 Ghidra universalAction（coreaction.cc:5462-5738）的全部 72 个 Action，对比 Rugra 注册情况。
- 发现 24 个 Ghidra Action 有 struct 定义但未注册。
- **安全注册**了无害的：ActionPrototypeWarnings（:5737）。
- **禁用**了导致回归的（注释说明原因）：ActionConstbase/ExtraPopSetup/Unreachable/RedundBranch/DeterminedBranch/NodeJoin/ConditionalConst/LikelyTrash/DoNothing/ReturnSplit/MappedLocalSync/StartCleanUp/PreferComplement/StructureTransform/MarkIndirectOnly/MapGlobals/DynamicSymbols/Stop。
  - 这些 Action 的 apply() 有副作用（删 op/块），实现不够成熟，启用后导致函数体丢失（24→14 函数）。
  - 需要逐个对照 Ghidra 源码验证其 apply 逻辑后才能安全启用。
- curl gcc 24/24（保持），0 defects，956/956 测试。

### ActionUnreachable 入口检测修复 + 禁用诊断（2026-07-03 续）
- 修了 `remove_unreachable_blocks` 的入口检测：之前只查 `ENTRY_POINT` flag（从不设），改为查 `size_in()==0`（对齐 Ghidra block.hh:325）。
- 但诊断发现根因：bblocks CFG 构建不完整（跳转表/间接分支边缺失），BFS 误判可达块。ActionUnreachable 保持禁用，注释说明根因 + 修复路径。

### ActionUnreachable 深度诊断结果（2026-07-03 续 2）
- 入口检测修复正确（size_in()==0），保守门禁（>=5 且 >5%）通过单元测试。
- 但即使移除 1 块也破坏函数体（myprogress 24→18 函数）→ 根因是 block 移除逻辑（branchRemove + blockRemove + structure_reset）不对齐 Ghidra。
- ActionUnreachable 保持禁用。修复路径：①CFG 边完整化（BRANCHIND）②block 移除逻辑对齐 Ghidra funcdata_block.cc。

### ActionUnreachable 根因更正（2026-07-03 续 3）
- **更正**：curl 的 24 个函数中 **0 个 BRANCHIND op**（之前误诊为 BRANCHIND 边缺失）。CFG 边对 BRANCH/CBRANCH 基本完整（仅 3 个目标因地址对齐偏移 3 字节未解析，不影响块可达性）。
- **真根因**：Rugra 的块移除（remove_block_arc/remove_edge_blocks）**不修补数据流**。Ghidra 的 `blockRemoveInternal`（funcdata_block.cc:255-335）移除 MULTIEQUAL 输入、修补后代 Varnode、处理搁浅引用。Rugra 只删 CFG 边和块 → 留下悬空 phi-node 和断裂数据流 → 函数体损坏。
- **修复路径**：移植 Ghidra `blockRemoveInternal`（含 MULTIEQUAL 调整 + descendantsOutside 检查）。

### ActionUnreachable op-destruction + 仍禁用（2026-07-03 续 4）
- remove_unreachable_blocks 新增 op 销毁（mark_dead）——正确的前提，但不够。
- 仍需 MULTIEQUAL phi 修补（funcdata_block.cc:278-294 的 opRemoveInput+opZeroMulti）。
- ActionUnreachable 保持禁用，注释更新。

### ActionUnreachable descendantsOutside（2026-07-03 续 5）
- remove_unreachable_blocks 的 Phase 2 改进：descendantsOutside 检查（只销毁无外部后代的 op）。对齐 Ghidra funcdata_block.cc:312。
- ActionUnreachable 仍禁用：根因是 pipeline 顺序——Action 在 mainloop 最开始运行时 bblocks 可能不完整。

### ActionUnreachable 安全启用（2026-07-03 续 6）★
- **将 ActionUnreachable 移到 ActionBlockStructure 之后**——解决了 pipeline 顺序问题。
- 根因：Rugra 的 bblocks CFG 在 mainloop 最开始（heritage 之前）不完整（sblocks 还没建），在此阶段移除块破坏后续阶段。移到 BlockStructure 后，CFG 完整，只有真不可达块被移除。
- Ghidra 在 :5490（更早）运行此 Action，但 Ghidra 的 CFG 在反汇编阶段就已完整。Rugra 需要在 BlockStructure 后才能保证 CFG 完整。
- **curl gcc 24/24（确定，3/3 runs），0 defects，956/956 测试**。

### 批量启用 13 个 Actions（2026-07-03 续 7）★
- 通过逐个二分测试，安全启用了 13 个之前禁用的 Actions：
  - **Stubs (安全 no-op)**: Constbase, ConditionalConst, MappedLocalSync, StartCleanUp, PreferComplement, StructureTransform, MapGlobals, DynamicSymbols, Stop
  - **Has-logic (验证安全)**: ExtraPopSetup, DeterminedBranch, LikelyTrash, DoNothing, MarkIndirectOnly
- **禁用 (1个有破坏性)**: RedundBranch — spliceBlockBasic 破坏输出（my_get_token gcc fail）
- **仍禁用 (2个 stub)**: NodeJoin, ReturnSplit — 留作占位
- 主管线覆盖率从 68/85 → **81/85 = 95%**（仅 RedundBranch/NodeJoin/ReturnSplit 3 个禁用 + ActionUnreachable 已启用）

### RedundBranch spliceBlockBasic op-moving（2026-07-03 续 8）
- spliceBlockBasic 修了 op-moving（ops 从 out_block 移到 bb），但还差 setOrder（seq_num 重置）。
- RedundBranch 保持禁用，注释说明剩余缺口（BlockBasic::set_order 未实现）。

### RedundBranch 启用（2026-07-03 续 10）
- spliceBlockBasic 现在忠实对齐 `BlockGraph::spliceBlock`（block.cc:1597-1620）：moveOutEdge 循环 + flags 合并（f_unstructured_targ/f_entry_point/f_switch_out）。
- ActionRedundBranch 重新接入主管线（action.rs，coreaction.cc:5658）。
- 验证：curl 24/24 反编译，23/24 gcc 审计通过。唯一失败 `file2string_part_0` 的 `goto ;` 是**预先存在的**结构化 bug（branch op 的 in(0) 缺失），与 RedundBranch 无关——禁用时同样失败。见续 11。
- 主管线覆盖率 81/85 → **82/85**（仅 NodeJoin/ReturnSplit 2 个 stub 禁用）。

### mainloop 顺序对齐：RedundBranch 移到 BlockStructure 之前（2026-07-03 续 11）★
- Ghidra coreaction.cc:5658-5659 的精确顺序：`ActionRedundBranch("deadcontrolflow")` 在 `ActionBlockStructure("blockrecovery")` **之前**。死分支 splice 必须在结构化前 settle CFG。
- Rugra 之前顺序反了（BlockStructure → Unreachable → RedundBranch），导致：结构化产出 sblocks 后，RedundBranch 改 bblocks → 下轮 mainloop 检测到 bblocks 变化清空 sblocks → 若 repeatapply 在重建前退出，print 时 sblocks=0 → 退化为 flat bblocks 遍历。
- 修复后顺序（action.rs mainloop 尾段）：
  `ConditionalExe → RedundBranch(:5658) → BlockStructure(:5659) → DeterminedBranch(:5672) → Unreachable(:5673) → ConditionalConst(:5676)`
- 效果：之前 4 个函数（my_get_token/file2string/getparameter/glob_range）sblocks=0（flat 退化），现在**全部 sblocks>0**（正确结构化）。
- 残留：`goto ;` 仍存在（1 处，file2string）——根因是结构化块 emit 时未跳过被消费的低层 branch op（Ghidra 用 no_branch mod）。这是 printc 的 emit 逻辑缺口，待续 12 处理。
- 956/956 单元测试通过。curl gcc 审计维持 23/24（重排未引入新缺陷）。

### BlockBasic::set_order + RedundBranch（2026-07-03 续 9）
- 新增 BlockBasic::set_order（block.rs:451）——重置 seq_num.order（Ghidra block.cc:2638）。
- spliceBlockBasic 调用 set_order。但 RedundBranch 仍禁用：goto 目标引用未更新。
<!-- annotation-pass: 2026-07-04 -->
<!-- fullloop-repeatapply: 1783144461.7680526 -->
<!-- mainloop-repeatapply: 1783144837.4436781 -->
<!-- delete-simplify: 1783145834.634057 -->
<!-- delete-4-self-invented: 1783146996.239581 -->

## 2026-08-13：PIPE-0000 根执行入口与子 Action 状态机

- 生产 CLI、curl/httpd、GetStr snapshot 及诊断 examples 不再直接调用根
  `Action::apply`，统一经 `ActionDatabase::perform_action` 执行
  `reset → perform`。
- `ActionGroup::apply` 按 Ghidra `action.cc:506-528` 的列表顺序，对每个子
  Action 无条件调用 `perform`；`onceperfunc`、`oneactperfunc` 和不带
  `repeatapply` 的子 Action 不再绕过自己的 status/count 状态。
- `Action::perform` 显式处理 `status_start/repeat/mid/end`，只在
  `status_start` 清 count/增加 tests，并在负返回时保留 `status_mid` 供下一次
  调用续传。
- `ActionGroup::reset` 与 `action.cc:408-415` 一样只重置基类/子 Action
  状态，不移动受保护的 child iterator；下一次 `perform` 通过
  `STATUS_START` 初始化 iterator。restart 组内部重跑也显式传递这一状态，
  避免把 reset 本身错误地变成游标突变。
- `ActionRestartGroup` 仍用 Rust 返回值承载外置 count，但不再丢掉已完成子树的
  change count。锁定 12.0.4 scripted fixture 的 repeat/once/partial/group
  executor 状态已逐字 MATCH；reset 的 warning flag、跨函数统计、breakpoint、
  `clearAnalysis`、Rule pool 及默认有序树仍分别归 `PIPE-BREAK-0001`、
  `PIPE-RESTART-0001`、`PIPE-POOL-0001`、`PIPE-TREE-0001`。该 fixture 是
  `PARTIAL_MATCH`，模块保持 L2。

---

## 2026-08-15：PIPE-MERGETYPE-ORDER-0001 — cleanup 后动作序列对齐 coreaction.cc:5714-5738

### `pub fn build_default_pipeline() -> ActionRestartGroup`（新增，RUGRA-GLUE）

`set_default_actions` 的完整树构造抽为自由函数 `build_default_pipeline`，
`set_default_actions` 仅注册其结果。行为不变；这是单一构造来源（ordered-action
fixture `tests/oracle/action_merge_order_1204.rs` 枚举同一构造）。

### cleanup 后子序列重排（锁定 oracle coreaction.cc:5714-5738）

原顺序（历史层积，见 78186a2/2f3116f/c45b2fa）为 `cleanup → MergeType(过早)
→ NormalizeBranches → PreferComplement → StructureTransform → MergeRequired…
→ MergeType(第二份)`。现与 raw universal 逐字对齐：

```
prefercomplement(:5714) → structuretransform(:5715) → normalizebranches(:5716)
→ assignhigh(:5717) → mergerequired(:5718) → markexplicit(:5719)
→ markimplied(:5720) → mergemultientry(:5721) → mergecopy(:5722)
→ dominantcopy(:5723) → dynamicsymbols(:5724 首份) → markindirectonly(:5725)
→ mergeadjacent(:5726) → mergetype(:5727 单份) → hideshadow(:5728)
→ copymarker(:5729) → outputprototype(:5730) → inputprototype(:5731)
→ mapglobals(:5732) → dynamicsymbols(:5733 第二份) → namevars(:5734)
→ setcasts(:5735) → finalstructure(:5736) → prototypewarnings(:5737)
→ stop(:5738)
```

- 删除过早的 cleanup 后首个 `ActionMergeType`；`MergeType` 全树仅一份（:5727）。
- `ActionAssignHigh`/`ActionDominantCopy`/`ActionCopyMarker` 从
  `build_full_pipeline_actions`（fullloop 前平铺）移入 :5717/:5723/:5729 精确
  位置——Ghidra 的 HideShadow/MarkExplicit/mergeByDatatype 无条件解引用
  `getHigh()`（coreaction.cc:4831/3237、merge.cc:370），AssignHigh 必须先行。
- `finalstructure(:5736)` 与 `prototypewarnings(:5737)` 恢复 oracle 先后。
- fixture：`tests/oracle/action_merge_order_1204.{cc,rs}` + 
  `tools/run_action_merge_order_oracle.sh`（pinned base 91b4774 + 
  src/{action,coreaction}.rs overlay）。锁定 oracle 侧通过
  `universalAction + setGroup("all") + setCurrent("all")` 公有 API 得到
  无过滤 universal 克隆，枚举 seq 并逐 child `perform`；Rust 侧枚举同一
  `build_default_pipeline` 构造。29 行观察中 28 行逐字节一致；唯一残差为
  `finalstructure` count 桥（blockaction.rs 硬编码 `changed += 1`，oracle
  apply 不增 count；域外租约，登记跟进 TODO）。
- E2E：curl 22/24 → **24/24**（0 PANICKED/TIMEOUT），输出与基线逐字节相同。

### 新增只读/编排 API（RUGRA-GLUE）

- `ActionGroup::{child_names, perform_child}`、
  `ActionRestartGroup::{child_names, perform_child, child_state}`：
  fixture 可观测视图；`perform_child` 复用 `ActionGroup::apply` 对 child 的
  逐字 perform 驱动（对应 Ghidra action.cc:511-527 的 child 驱动方式）。

### 残差（不因本改动升级状态）

- `build_full_pipeline_actions` 平铺层仍有 HideShadow/OutputPrototype/
  InputPrototype/SetCasts/PrototypeWarnings 的过早重复注册（PIPE-TREE-0001
  T6 域）；本轮只移除已迁移到精确位置的三个。
- 主管线独立 merge Action（mergerequired/mergecopy/mergeadjacent）在无
  cover 前提下运行：Ghidra 的 `data.getMerge()` 是 Funcdata 持久对象且
  testCache 惰性建 cover，Rugra 每 Action 新建 `Merge::new()`（live_set/
  covers 未建立）——`merge_adjacent` 对同尺寸 (in,out) 对会凭空合并。merge.rs
  域外租约，登记跟进 TODO；fixture 图以常量输入规避该路径。

---

## 2026-08-17：UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④ — 双注册去重 + base 组 oracle 序

### `build_default_pipeline` 单注册过滤（coreaction.cc:5462-5738）

`universalAction` 对每个 Action 恰好注册一次（`ActionPrototypeWarnings` 仅在
:5737）。`build_default_pipeline` 此前把 `build_full_pipeline_actions()` 的
Vec 整体平铺进 universal 顶层，与本函数下方按 oracle 位置显式注册的条目
形成双注册：`ActionPrototypeWarnings` 每函数跑两次（E2E stderr
48 = 24×2 条 unknown-convention 警告），DefaultParams/PrototypeTypes/
VarnodeProps/ParamDouble/DirectWrite/ActiveParam/ReturnRecovery/NonzeroMask/
InferTypes/UnjustifiedParams/StartTypes/ActiveReturn/SwitchNorm/HideShadow
也各多跑一趟错误位置（:5482 之前）。

现按 `get_name()` 跳过本 builder 拥有的 15 个名字（常量
`BUILDER_OWNED_ACTION_NAMES`）；Vec 存活条目（FuncLinkOutOnly :5485、
Segmentize :5494、InternalStorage :5495、MultiCse :5653、ShadowVar :5654、
Deindirect :5655）保持原注册上下文。

### base 组重排为 coreaction.cc:5477-5485 逐字序

`start(:5477) → constbase(:5478) → [normalizesetup 排除——normalanalysis 组
不在 decompile 根 toggle 集，coreaction.cc:5424-5443] → defaultparams(:5480)
→ extrapopsetup(:5482) → prototypetypes(:5483) → funclink(:5484)`。此前
FunLink 在 ExtraPopSetup/PrototypeTypes 之前，与 oracle 相反。

### 登记残差（DELIBERATE RESIDUAL）

> 2026-08-17 更新：该残差已全部收口——setcasts 由 HERITAGE-FLAGFREE-SSA-0001
> 移出，outputprototype/inputprototype 由 R2 收口移出（见下方
> 「outputprototype/inputprototype 单注册」节），跳过集现为 17 名，无残余。

[历史记录，已被 R2 收口取代——保留作归因审计] 当时 `outputprototype`/
`inputprototype`/`setcasts` 仍双注册（顶层各 2 份）。A/B 实测：去重这三者
会暴露 printc 侧局部名碰撞（`uVarN` 重复声明，numbering 0→3，仅 glob_url；
复核方四变体独立复现）。setcasts 由 HERITAGE-FLAGFREE-SSA-0001（8fa91f5）
先行移出（早期趟在 pre-SSA IR 上跑 CAST 是 351 WARN 家族根因）；
outputprototype/inputprototype 由 R2 收口（本节上方）移出——解除条件
（printc 局部声明命名去重 = 533412a 的 control_flow_opener 门控）已满足。

### 度量（锁定 curl E2E）

- Matched 123 不变 / defects 0 不变 / numbering 16 → **0** / skeleton 3152 → 3166。
- stderr unknown-convention 警告 48 → 24（配合 ① commentdb 接线后为 0——
  警告改存 CommentDatabaseInternal）。

### 新增测试

- `test_prototype_warnings_registered_once`：prototypewarnings 顶层恰 1 份；
  15 个去重名字的顶层份数；3 个残差双注册恰 2 份。
- `test_base_group_order_matches_ghidra_5477_5485`：顶层前缀逐字序。

## setcasts 单注册（2026-08-17，HERITAGE-FLAGFREE-SSA-0001）

`BUILDER_OWNED_ACTION_NAMES` 的 DELIBERATE RESIDUAL 注释与相关断言随
setcasts 的移出更新：`test_prototype_warnings_registered_once` 现断言
setcasts 顶层恰 1（:5735 位）、base 组前缀不再含 setcasts；残余双注册
清单只剩 outputprototype/inputprototype（等 printc 命名去重的最后收口；
已于同日 R2 收口，见下节）。
早期 setcasts 注册曾对 pre-SSA IR 跑 CAST（351 multiple-descendants WARN
的根因，Ghidra root head 无此条目）。

## outputprototype/inputprototype 单注册（2026-08-17，UNKNOWN-PROTOMODEL-WARN-EMIT-0001 R2 收口）

`BUILDER_OWNED_ACTION_NAMES` 15 → **17** 名，加入 `outputprototype`(:5730)/
`inputprototype`(:5731)：提前趟（fullloop 前平铺位）从 Vec 消费中移除，
两 Action 与 `universalAction`（coreaction.cc:5462-5738）一致地全树恰一份，
唯一注册在 :5730（`ActionOutputPrototype("localrecovery")`）与 :5731
（`ActionInputPrototype("fixateproto")`）——已在锁定 oracle 全函数体
（5462-5739 行）核实无第二处注册。**残余双注册清单清空**。解除条件已由
533412a（printc 命名门控，prettyprint `control_flow_opener`，
PRINTC-WARN-EMIT-0001 R2）满足：glob_url 的 `uVarN` 重复声明块根因
（`if ((bool)(piVar1 <= 0x1000 /* 4096 */))` 的十六进制注解 ` */` 被误判为
签名形状）已修，全量去重后 numbering 保持 0。

### 测试更新

- `test_prototype_warnings_registered_once`：残余双注册断言循环（count=2）
  改为单注册断言（count=1，:5730/:5731 位）；17 名去重清单注释同步。
- `test_base_group_order_matches_ghidra_5477_5485`：前缀中的
  `outputprototype`/`inputprototype` 两项为「residual early double」注释标注
  的临时项（读测试确认语义：其存在仅因双注册的 Vec 提前趟），随收口从前缀
  删除——前缀现为 `deindirect → fullloop` 直连；两名的唯一位置由
  `test_post_cleanup_sequence_matches_ghidra_5714_5738`（:5730/:5731 尾段）
  与单注册计数断言锁定。

### 度量（锁定 curl E2E，收口前后新鲜捕获对照）

收口前（004816a 干净树）与收口后均：Matched **123** / defects **0** /
numbering **0** / `multiple descendants` 0 / `/* WARNING: Unknown calling
convention` **51** / gcc 审计 16 FAIL 持平；glob_url 单声明块（无重复注入）。
<!-- annotation-pass: 2026-08-17 -->

## 嵌套树寻址 WIP（2026-08-22，PIPE-DERIVED-TREE-0001）

- `Action::as_action_group` / `ActionGroup::as_action_group` / `child_actions` —
  树下行访问原语（为 ':'名字路径寻址与 pipeline_tree_1204 DFS 投影铺路，
  对应 action.cc getSubAction/getSubRule 寻址族）；default 树 head/mainloop/
  stackstall 子序列断言（coreaction.cc:5477-5486/:5493-5500/:5651-5656）。
  WIP：derive tree 双侧 fixture pending，见 docs/alignment_docs/
  PIPELINE_STAGES_1204.md 阶段树参考。

## 派生默认管线树对拍完成（2026-08-23，PIPE-DERIVED-TREE-0001）

- `ActionDatabase` 重构为 Ghidra actionmap/groupmap/currentact 镜像：
  `universal_action()`（coreaction.cc:5462）注册原始 universal 树；
  `reset_defaults()`（action.cc:986）→ `set_current("decompile")` →
  `derive_action`（action.cc:1145）按 decompile grouplist
  （coreaction.cc:5424-5431，`default_groups::DECOMPILE` 逐字成员表）
  做 clone 存活过滤派生默认根；`get_current()`（action.hh:313）返回派生根。
- `universal_action(Option<&ActionGroupList>)` 以 coreaction.cc:5462-5738
  的全槽顺序构建（`add!` 宏逐槽应用 action.cc:391-406/899-914/529-544 的
  clone 存活语义）；组/池仅在仍有存活子节点时挂父。
- r1 REJECT 修复：`funclink_outonly`（noproto）与 `normalizesetup`
  （normalanalysis）在派生 decompile 根中过滤（原始树仍注册）；
  根键 `decompile` vs 根节点名 `universal`（clone 保留 getName()）；
  `deadcode` 移到 fullloop 尾 :5682 实际位置（donothing 之前）；
  精确 action 名（`restructure_varnode`/`unjustparams`/`mapped_local_sync`/
  `funclink_outonly`/`condconst`）；`normalizebranches`（group 名不在
  decompile 集）从派生根过滤——Ghidra 默认反编译根不运行它（仅在
  normalize/jumptable 根运行）；mainloop 恢复 oracle 全序
  （unreachable(base) 首槽、forcegoto :5496、dynamicmapping :5504、
  restrictlocal→deadcode→restructure_varnode→spacebase→nonzeromask→
  infertypes）；Rugra-local `inferparams` 从树中移除；池名
  simplifypool→oppool1；lanedivide=onceperfunc、donothing=repeatapply、
  normalizesetup=onceperfunc flags 对齐 ctor。
- 对拍：`tools/run_pipeline_tree_oracle.sh`（pin-base schema2，base=dd76d37
  + action.rs/coreaction.rs overlay）——Ghidra 真实
  universalAction→resetDefaults→getCurrent DFS 与 Rugra 实际默认数据库
  DFS **78 节点字节一致**（path/ordinal/kind/name/basegroup/flags，
  重复节点保留不排序），stdout_sha256=60af6c04…，overall=MATCH。
- 残差：rule 级 clone 过滤（非 decompile 根）无 oracle 观察
  （PIPE-RULE-CLONE-FILTER-0001 建议）；oppool1/cleanup 内 Rugra-local
  Rule 未在 Action 节点投影中观察（PIPE-POOL-LOCAL-RULES-0001 建议）；
  节点 apply 体/计数反馈归 PIPE-STACKSTALL-COUNT-0001。

## 树驱动 fixture 视图（2026-08-23，PIPE-STACKSTALL-COUNT-0001）

- `Action::as_action_group_mut` / `ActionGroup::child_actions_mut`：树下行
  可变视图，供 stackstall_count_1204 一类子树驱动 fixture 精确复刻
  ActionGroup::apply 对 protected list 的驱动顺序。
- `ActionRestartGroup` 透传 `as_action_group_mut`（Ghidra 继承同一 list）。

## Stage 投影 emitter 访问器（2026-09-22，STAGE-BISECT-E2E Lane C）

- **新增只读 trait 默认方法**：`Action::fixture_curstart() -> i32`（默认 0）
  与 `ActionRestartGroup` 重载（返回 protected `curstart`）——供
  examples/curl_decompile.rs 的 v1.1 stage 投影 emitter（env 门控
  RUGRA_STAGE_PROJ=1）检测 @RESTART 轮次；与既有具体方法
  `ActionRestartGroup::fixture_curstart`（fixture-only，action_break_pool
  protected-field 读取模式）同源同义。零管线语义变更（Rugra 侧重启未接线，
  PIPE-RESTART-0001，恒返回 0）。emitter 本体与树遍历/断点步进
  （BREAK_START 前沿候选集、索引寻址绕开同名叶子歧义、开帧 LIFO 收口）
  全部位于 examples 层，复用既有 fixture 视图
  （`as_action_group`/`child_state`/`child_state_mut`/`set_break`），
  不新增其它 src/ 接口。

## oppool1/cleanup 注册纯净度（2026-08-23，PIPE-POOL-LOCAL-RULES-0001）

- **新增 fixture-only API**：`ActionPool::rules() -> &[Box<dyn Rule>]`——注册序
  规则只读视图（oracle 侧对应物是公有虚函数 `ActionPool::print`，
  action.cc:753-775，按 allrules 注册序逐条打印规则名，即 console
  printActionList 的数据源；oracle fixture 经 print 输出解析读取，Rugra
  fixture 经 rules() 读取，两侧同一投影）。
- **删除三处 Rugra-local 注册**（ruleaction 审计确认的存量违例，复核锁定
  oracle e40ed130 全树后执行）：
  1. oppool1 末尾的 `RuleSextEliminate`——oracle 全源码树不存在该类（grep
     零命中），struct 连同注册一并删除（无单测引用）。
  2. oppool1 末尾的 `RuleEquality`——oracle 定义了类（ruleaction.hh:243-250，
     方法体 ruleaction.cc:624/631）但从未实例化（全树无 `new RuleEquality`）。
     Rugra 移除注册，struct + 3 单测保留为未注册存档（与 oracle 死代码状态
     1:1，注释说明）。
  3. cleanup 池末尾的 `RuleTrivialArith`——oracle actcleanup
     （coreaction.cc:5694-5711）无此条目；Ghidra 只在 oppool1:5522 注册一次。
- 删除后 `build_oppool1` 以 `RuleDoubleOut`（5646）结尾、`build_cleanup_pool`
  以 `RuleStringStore`（5710）结尾，与 oracle 池序逐条一致（oracle 后续只有
  CPU-specific `conf->extra_pool_rules` 吸收循环，x86-64 gcc spec 注册 0 条）。
- 对拍：`tools/run_pool_purity_oracle.sh`（pin-base schema2）——Ghidra 真实
  universalAction 原始树与 Rugra 实际默认数据库中 oppool1/oppool2/cleanup
  三池的 rule 注册序列投影（pool|index|name|basegroup 逐条）**字节一致**，
  overall=MATCH。
- E2E 门禁（curl 1204 语料，fast-release）：删除前后 defects=1/numbering=0/
  skeleton=2076 全部不变，72 decompiled/1 timeout/3 panic 不变——三处删除在
  当前语料零可观测输出影响（见 commit `## Differential` 块）。
- 残差：mainloop 未启用 RULE_REPEATAPPLY 导致后期 trivial op 不被再简化
  （原 cleanup 补刀掩盖的缺口，现暴露；对齐路径=补 mainloop repeatapply 基础
  设施，非池注册 hack）。

### 2026-08-26：RuleState 恢复 Clone（诊断脚手架摘除）
- `RuleState`（action.hh:203-210 的 Rule 字段镜像）曾为挂
  `prof_op_hits: AtomicU32` 循环诊断计数器临时摘除 `Clone`；诊断结束后
  字段删除，derive 恢复 `#[derive(Debug, Clone)]`，可观测行为无变化
  （Ghidra 的 Rule 字段本身可拷贝）。
## 2026-08-25（ACTIONDW-COPYDEF-MARKING-0001）：ActionDirectWrite 双注册接线 propagateIndirect

`universalAction`（coreaction.cc:5497/:5498 mainloop、:5680/:5681 fullloop）的四个 ActionDirectWrite 注册点现按 oracle 传 `propagate_indirect`：protorecovery_a=`true`、protorecovery_b=`false`（coreaction.hh:244 构造器参数）。此前两注册共用无参 `new()`，phase-2 推播门与分支④的 marker 收集都无法区分两种注册语义。

## 2026-08-27（MAIN-POSTSTRUCT-SPIN-0001）：ActionRestartGroup 重启环降级为有界完成

`apply_restart`（action.cc:553-582）的重启分支（cc:574-580
clearAnalysis → 逐子 reset → status_start → 重跑）在 Rugra 侧不可执行：
oracle 的重启环依赖 `Funcdata::startProcessing → followFlow`
（funcdata.cc:157）在清空的 Funcdata 上重新生成原始 p-code，而 Rugra 的
流生成在驱动侧（`rugra::flow::follow_flow*` 于管线前调用），
`Funcdata::start_processing` 无法重入。旧代码在未清空状态上
`group.reset + STATUS_START` 重跑整个子树——这正是
MAIN-POSTSTRUCT-SPIN-0001 观察到的 post-blockstruct 动作环不收敛形态
（≥250s 静默挂起 / subflow tryCallPull 连发）。

> **2026-09-26 更新（PIPE-RESTART-0001）**：本条目描述的保守降级已被
> 真实重启环取代，见下方 2026-09-26 条目；无回调安装面（standalone
> fixture）仍走有界完成路径。

现行行为（保守降级，登记 PIPE-RESTART-0001）：curstart 未超
maxrestarts 时，`eprintln!("[ACTION] restart pending after convergence:
...")` 后 `return Ok(0)` 有界完成；pending 标志保持置位（与 oracle
maxrestarts 路径的终态一致，本循环是其唯一消费者 action.cc:562）。
curstart 超 maxrestarts 路径（cc:569-573 warningHeader + curstart=-1）
保持原样。收敛证据：curl 124/124、0 timeout/0 panic（main 独立 7.1s）、
defects=0/numbering=0；语料内唯一 restart 触发者=match_url（heritage
bump register，见 heritage.md）。真实重启环（clearAnalysis + in-Funcdata
流再生成 + 双侧 fixture 对拍）归 PIPE-RESTART-0001。

## 2026-09-26（PIPE-RESTART-0001）：ActionRestartGroup 真实重启环落地

`apply_restart`（action.cc:553-582）的重启分支现按 oracle 逐句执行
（替代上文的保守降级）：

1. **clearAnalysis 两半**（action.cc:574 → architecture.cc:335-341）：
   `fd.clear()`（funcdata.cc:84-112 的忠实移植已在 funcdata.rs，含
   restart_pending/processing_started 标志清除、overrides 存活）+
   `commentdb.clear_type(fd.baseaddr, WARNING|WARNINGHEADER)`（Architecture
   持有的注释库按函数入口地址清 warning/warningheader 注释）。
2. **流再生成 seam**：oracle 第二遍经 `ActionStart → startProcessing →
   followFlow`（funcdata.cc:157）在 Architecture 持有的 loader/lifter 上
   重建原始 p-code；Rugra 的流生成在驱动边界，故由驱动安装的
   `RestartFlowCallback`（`Arc<dyn Fn(&mut Funcdata) -> Result<()> +
   Send + Sync>`）在此处执行——与 clearAnalysis 的相对位置和 oracle 的
   followFlow 一致。**未安装回调的调用面（standalone fixture）走有界完成**
   （eprintln + `return Ok(0)`，pending 保持置位）——降级路径保留，
   因为 `Funcdata::start_processing` 的 followFlow 移植仍是登记缺口。
   该降级分支在 clearAnalysis **之前**返回：无回调面零状态突变，打印
   阶段保留第一遍收敛态（oracle 无此路径——其 Architecture 恒持有
   loader）。
3. **逐子 reset**（action.cc:576-580）：`group.reset(fd)` 重新武装
   rule_onceperfunc 门（mapglobals 等）供第二遍重跑。**本环不调用
   `start_processing`**——重启子树的首子 ActionStart 恰好调用一次
   （coreaction.hh:41-43），`fd.clear()` 已清 processing_started 守卫，
   环内再调会双入 LowlevelError 守卫（funcdata.cc:153-154）。
4. **status_start + 游标复位**（action.cc:581 + action.cc:508-509）：
   `group.reset_apply_cursor()`（RUGRA-GLUE：组合模型绕过
   perform/prepare_apply 的 status 基游标复位）+ 外置 group_state 的
   `STATUS_START`。

新增公开面（全部 RUGRA-GLUE，无 Ghidra 对应物——oracle 经
`Funcdata::getArch()` 直达 Architecture 持有的 loader）：

- `pub type RestartFlowCallback`：驱动边界回调类型。
- `ActionRestartGroup::set_restart_flow(callback)`：安装点。
- `ActionDatabase::set_restart_flow(root_name, callback) -> bool`：驱动
  经数据库句柄在派生根（"decompile"）上安装；非 restart-group 根返回
  false。`clone_restart_group` 产出的派生根从 `None` 起步（回调是驱动
  状态而非树状态），驱动须在 perform 前安装到实际运行的根上。
- `ActionGroup::reset_apply_cursor()`：重启环的派生迭代器复位。
- `Action::as_restart_group_mut()`：trait 级 mutable 下转视图。

驱动侧安装（examples/curl_decompile.rs）见同日 examples 条目：回调捕获
post-F2B 配置好的 `SleighLifter`（`Arc<Mutex>`）+ no-return callee 表 +
镜像门，重启时按第一遍同一流契约再生成（mirror 模式=oracle 全空间
`followFlow(baddr,eaddr)` 载入契约 RUGRA-FLOW-MIRROR-0001；默认模式=
历史有界驱动区间）。

> **CR-PIPESALV 注记（2026-09-26，随 MERGEBATCH14 登记，F1-F4）**：
> - **F1（回调流半边缺口）**：上述回调只重放 followFlow 流半边——
>   `link_call_specs`（libc/DWARF 锁定签名+noreturn 表）与
>   `install_callee_siglock_protos`/paramid 通道第二遍丢失；oracle 第二遍
>   经 queryCall 全量重取锁定签名。真实点火时第二遍调用签名为可观测
>   分歧（当前全语料 0 触发不可达）。登记于 PIPE-RESTART-0001 剩余项 e。
> - **F2（勘误）**：早期记录称 fspec.cc:5503 forceSet 触发点 "Rugra 未移植
>   =CALLSPEC-0001 seam 已知缺口"——表述过期：fspec deindirect（:5471）/
>   forceSet（:5503）两 `setRestartPending(true)` 触发点已移植。
> - **F3（standalone 注记）**：clearAnalysis 的
>   `commentdb.clear_type(baseaddr, WARNING|WARNINGHEADER)` 半边在无 arch
>   句柄面（`fd.get_arch()`=None，standalone fixture 形态）静默跳过——
>   oracle Architecture 恒持 commentdb 无此分支；生产驱动恒有 arch，
>   行为不可达面，不另开票。
> - **F4（B2 覆盖项注记）**：环内再调 `start_processing` 的双入
>   LowlevelError 守卫（funcdata.cc:153-154）panic 形态是 B2 locked
>   restart fixture（PIPE-RESTART-0001 剩余项 b）的覆盖项。

## 2026-08-29:nodejoin join-block 强制 heritage 重构 fixture(NODEJOIN-STRUCTURERESET-0001)

新增测试 `action::tests::nodejoin_join_block_forces_heritage_restructure`(w-nonconverge 锁定,
root 集成时去 ignore):构造不同条件菱形 CFG,断言 ActionNodeJoin 走 join-block 路径后
`fd.heritage.maxdepth == -1`(Ghidra nodeJoinCreateBlock 尾部 structureReset 契约,
funcdata_block.cc:816)。修复前红/修复后绿双态已验;配套修复见 coreaction.md 同日条目。

nodejoin fixture 补 CFG 形状断言(F1 整改):canonical(swapa==swapb)终态=join 块 2 出边、两分支各 1 出边(仅 join 边)。

nodejoin fixture 测试构造修正(njf2 移交项):原 fixture 用不同常量条件(修复前 over-join 行为的编码);
F4 门序落地后常量条件 !isWritten 不 join(双侧 fixture D_unwritten 锁定 count=0)。改为共享 written 条件
varnode(INT_EQUAL 输出)供两 CBRANCH 读取——F3 语义 vn1==vn2 完整 match 走全套 join,断言不变。

## 2026-09-22: v2 drill 边界钩子(Lane AA; action.cc:316-322/839-845 同位)

`Action::perform` 的 apply 两侧加 `drillobserve::activate()/flush(name)`,
`ActionPool::process_op` 的 `apply_op` 两侧加 per-rule 同对(镜像
action.cc:316-322 与 :839-845;pool 自身的 flush 因 active 位被 rule 对
复位而自然 no-op,与 oracle 相同)。env 门控 `RUGRA_STAGE_DRILL`;
env-off 字节一致性验证:05c8314 基线 vs 本分支,examples/
rugra_decompile_func 对 examples/curl 的 next_url 输出逐字节相同。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-28：`RUGRA_ACTSIG` 逐动作 CFG 签名探针（SELECTGOTO2 车道）

`ActionGroup::apply_children`（action.cc:506 ActionGroup::apply 的子分发尾）
新增 env 门控（默认关闭，debug-only）诊断：`RUGRA_ACTSIG=1` 时每个 child
`perform` 返回后把 `@ACT <seq> <name> res=<res>` + `fd.bblocks` 全量 CFG 签名
（块地址/出度/目标列表，与 RUGRA_BBSIG 同格式）累积落 `<fn>.actsig`——
oracle 侧 GLM_ACTSIG 同点插桩（scratch 树 ActionGroup::apply 子分发尾钩）
的对照面。本轮用它证明 fn 653 的 518 步动作序与前 87 步逐动作 CFG 双侧
恒等，把 round-2→3 窗口首分歧钉到 @ACT 87 nodejoin（oracle res=2 vs
Rugra res=1），最终定位 RuleSubZext INT_RIGHT 臂缺失（详见
docs/api/ruleaction.md 与 docs/api/blockaction.md 的 SELECTGOTO 修复③节）。

## 2026-09-30（c 段）：ActionPool 游标 OpId 化 + 派发复读槽影化（PERF-ARENA-FLIP-0001 (c)）

`op_state: Option<PcodeOpRef>` → `Option<OpId>`（oracle 保留的
`PcodeOpTree::const_iterator`，action.hh:265）。`first_op` = `optree.first_id`；
`next_op_after` = 槽 `seq_key` + map 严格后继（锁自由；原形态每推进一次
SeqNum 读守卫 + SpaceOff 投影 + 后继 Arc 克隆）；`process_op` 每访问一次
经 `op_by_id` 解引用句柄（与原游标持有克隆同数量级的引用计数往返）。
`resume_state(&self)` → `resume_state(&self, fd)`（游标不再持有句柄，
SeqNum 经 bank 解引用读取；fixture 调用点同 commit 机械改写）。

派发复读（`processOp` cc:846/853-857）：命中/未命中路径的
`opc != op->code()` 复读改走 `PcodeOpBank::opcode_of`（OpCell opcode
影子，锁自由）；入口 isDead 判定与命中路径 isDead 复核当时保持守卫读
（DEAD 位当时无影子；后由 PERF-DISPATCH-0001 死位影子收口，见
2026-10-02 节）。RULE-POOL 派发残差三件（advance 键下降、miss 复读
27.7M 锁、per-visit 常数）中前两件由此收口。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。


## 2026-10-02（DISPATCH）：processOp 派发三件套（PERF-DISPATCH-0001）

oppool 派发面（W2REMEASURE 勘定 VdbeExec 极 2.61s、语料级派发残量）的
三项恒等收敛，全部作用于 `ActionPool::process_op`（action.cc:822-875）的
派发路径，规则体零触碰：

1. **isDead 死位影子读**：入口判定（cc:829 `if (op->isDead())`）与命中后
   复核（cc:846）改走 `PcodeOpBank::is_dead_of(op_id)`（OpCell `dead`
   影子，写点纪律见 op.md 2026-10-02 节）——去掉派发路径上的 PcodeOp
   RwLock 往返（VdbeExec 极 5.83M 访问 ×2 读点）。
2. **早算后继 memo + optree version 守卫**：oracle 的 `op_state++`
   （cc:871/830，活 map 迭代器 O(1)）在 Rugra id 空间 = 每次推进一次
   BTreeMap range 搜索（~73ns × 5.2M 推进）。现为规则循环**前**预算
   `next_op_after(op_id)`（此时游标自身槽行正热），尾推进在
   `optree_version()` 未变时直接复用（同 version ⇒ inner 未变 ⇒ 同树
   同键 ⇒ 严格后继同值，构造即恒等）；任何插入/删除/clear bump version
   回退 fresh 搜索（ACTIONLOOP-RESTART-0001 原形，含 hit 路径
   totalReplace/死删除的守卫语义）。空 per-opcode 桶跳过 memo（无规则体
   时间可掩藏预取，尾搜索反正必付）。
3. **PREFETCHT0 + drill 门提升**：后继槽行地址投影（`cell_hint_addr`，
   纯指针算术）发非阻塞 T0 提示（miss 延迟落在规则体下而非下一次访问
   的关键路径；x86_64 门外 no-op）；per-try 的 `drillobserve` activate/
   flush 双门统一提升为循环外单次 `is_enabled()` 布尔（env 中途不可变，
   OnceLock 同值——与 oracle `#ifdef OPACTION_DEBUG` 编译期消除同形）。
   附带：`rule_states[rule_index]` 的 is_disabled/count_tests 访问合并为
   单借用。

**行为恒等面**（详证链见车道终报 LANE_DISPATCH_2026-10-02）：
VdbeExec 双面 md5 恰钉值 + ACTIONSTATS 五值逐值恒等（双二进制）+ 语料
assembled 双面字节恒等 + canon 双 md5 + 镜面五面恰钉值 + tests 基线。
