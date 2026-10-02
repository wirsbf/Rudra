# AI-Native Decompiler 架构愿景（Rudra 后迁移优化路线）

> 创建: 2026-09-23。依据: stage-bisect wave(~48h、40+ 车道、双全函数 MATCH)的实战证据。
> 性质: **设计愿景文档**,非当前任务。所有优化均为迁移完成后的分层工作,须过差分门禁。
> 地位: 与 AGENTS.md 对齐纪律的关系——优化只走 additive flag,正典 sequential perform
> 路径在 parity 被证明前不动。

## 逐项文档索引

| 文档 | 内容 | 依赖 |
|---|---|---|
| [L1_EVENT_SOURCING.md](L1_EVENT_SOURCING.md) | 事件溯源: mutation 事件流,归因/解释查询原生化 | 无 |
| [L2_DETERMINISM.md](L2_DETERMINISM.md) | 确定性构造化: 容器策略进类型系统 | 无 |
| [L3_STAGE_SPLIT.md](L3_STAGE_SPLIT.md) | 显式阶段拆分 + 声明式依赖 + per-stage 缓存 | L1 |
| [L4_PERSISTENT_IR.md](L4_PERSISTENT_IR.md) | 持久化 IR + fork_at 分叉,O(diff) 试错 | L1,L2 |
| [L5_DUAL_MODE.md](L5_DUAL_MODE.md) | fidelity/fast 双模并行 | L2,L3,L4 |
| [L6_IR_QUERY.md](L6_IR_QUERY.md) | 结构化 IR 查询 API,读侧门面 | L1,L4 |

## 0. 一句话

把 wave 里 AI 编排层手工做的"bisect→归因→分叉试探→择优"变成**反编译器内核的原生能力**:
agent 的作业单元从"函数"降为"阶段+事件",探索成本从"全量重跑"降为"结构 diff"。

## 1. 依据: wave 实证过的痛点(Ghidra C++ 结构性限制)

| 痛点 | wave 中的代价 | 根因 |
|---|---|---|
| 观测靠外接示波器 | stage 投影 harness 搭了 ~10 个车道才齐(v1.0→v1.2.2 演进) | Action/Rule 只做 in-place 突变,无事件流 |
| 探索=全量重跑 | 每个假设修复→release 构建 4-5min+E2E 1min | Funcdata 单一可变状态,无快照/分叉 |
| 归因靠 40 个 sub-agent | bisect→drill→分类学→根因,每环人工编排 | 无结构化 diff/查询 API |
| 确定性靠纪律 | HashMap 迭代序/共享 scope/遍历翻转三起 P0 | 无序容器进 IR 关键路径 |
| 78 节点树隐式依赖 | blockstructure 依赖 heritage 结果但结构不可见 | 嵌套 repeatapply 无声明式 stage 边界 |
| 112 核浪费 | 单函数单线程,规则池顺序 apply | C++ 可变共享状态无法安全并行 |

## 2. 优化分层(按依赖序)

### L1 — 事件溯源(观测原生化)

- 每条 Rule 每次 apply 发结构化 mutation 事件(持久 log): `{stage, seq, op, before, after, reason}`。
- wave 的 stage_bisect/drill/projection harness 全部退役为**查询 API**:"这个 op 谁杀的"
  = event log 一次检索;归因从天级降到毫秒级。
- 实现: Action/Rule trait 加 event sink(RUDRA-GLUE 层已有雏形——drillobserve.rs 的
  mod_check/flush 即其原型),IO 与逻辑分离。

### L2 — 确定性构造化

- IR 关键路径全 BTreeMap/显式迭代序;容器选择进类型系统而非纪律。
- wave 三起确定性 P0(DETERM-COPYTRIM/DOMINANTCOPY/遍历序)证明:这不是风格问题,
  是**门禁可信度的根基**——差分门禁信任链依赖 run-to-run 字节恒等。

### L3 — 显式阶段拆分 + 声明式依赖

- 78 节点树拆 typed stage 流: `lift → SSA/Heritage → structure → type → print`,
  stage 间输入输出声明化(依赖图静态可见)。
- 收益: ①per-stage 缓存(改打印规则不重跑 lift);②stage 边界=API 断点(现在
  breakpoint hack 正规化);③跨函数 stage 级并行;④failure attribution 直接到 stage。
- 注意: 拆分是**逻辑投影**不是执行重排——正典执行序仍逐字节对齐 Ghidra
  (bisect 对拍依赖此)。物理拆分只在 parity 证明后开启。

### L4 — 持久化 IR + 廉价 fork/回滚

- Funcdata IR 用 Arc 结构共享(类 git 的 IR): `fork_at(run, stage) -> RunHandle`,
  同快照跑 N 个假设修复、结构 diff、择优、O(diff) 回滚。
- wave 最贵动作"改一行→全量重跑→对比"降为结构 diff;agent 试错预算放大数量级。
- 与 L1 组合: fork 天然携带事件流,diff_runs = 事件流对齐比较(native stage_bisect)。

### L5 — 双模运行(fidelity / fast)

- **fidelity 模式**(正典): 严格 Ghidra sequential perform 顺序,字节对齐门禁专用。
- **fast 模式**(探索): 规则池内按 op 并行(不可变快照下安全)、跳过声明无关的
  stage(L3 依赖图提供)、宽松迭代序。AI 假设验证、大规模扫描用。
- 两模共享同一 IR 与事件语义,fast 结果不可作对齐证据(AGENTS B2 口径)。

### L6 — 结构化 IR 查询

- 类型化查询替代遍历: `query(run, Ops::Ptrsub.with_type(X))`、
  "stage N 后活着的所有 COPY"——wave 的 RUDRA_DUMP_FUNC/env 探针是原型,
  正规化为索引层 API。

## 3. AI-Native SDK 形态(终局草图)

```rust
let run  = decompile(func, options)?;                 // -> { stages, events, text }
let div  = diff_runs(&run_a, &run_b)?;                // native stage_bisect
let fork = fork_at(&run, Stage::Heritage)?;           // 从任意阶段分叉试探
let hits = query(&run, Ops::Ptrsub.with_type(T))?;    // 结构化 IR 检索
let why  = explain(&run, op_addr)?;                   // 事件溯源: 谁改的这个 op
```

agent 编排层(本 wave 的 orchestrator)从"40 个 sub-agent + 外部 harness"收敛为
SDK 调用编排;**AI 的杠杆点从'读代码猜'变为'查事件改'**。

## 4. 铁律(不可妥协)

1. 优化永远 additive flag,正典路径在 parity 证明前不动——golden 差分体系是资产。
2. fast 模式结果不得作对齐证据(AGENTS 机制 B2 口径延伸)。
3. 每层落地必须过双门禁: 逐函数 stage 投影 MATCH + 双语料 E2E defects=numbering=0。
4. 顺序即语义: Ghidra 的 perform/apply/迭代序是行为的一部分(L3 拆分不得隐式重排)。

## 5. 与现有资产的关系

| wave 资产 | 在终局中的角色 |
|---|---|
| stage 投影规范(v1.2.2) | L1 事件格式的语义基准(格式已被 oracle 复核钉死) |
| 双侧 fixture 体系(机制 B2) | 各层优化的 parity 门禁直接复用 |
| 确定性修复(DETERM-*) | L2 的前哨战,验证手段已就绪 |
| drill/projection harness(src/drillobserve 等) | L1/L6 的原型,迁入核心层后退役 |
| batch_driver/targets 体系 | L4 之上 agent 批量编排的雏形 |

## 6. 排期原则

迁移主线(Ghidra 算法 1:1 对齐)完成前不动任何 L 层;完成后按 L1→L6 依赖序,
每层独立过门禁、独立提交。L1/L2 成本低收益即时(归因与门禁信任),L4/L5 是
AI-native 的分水岭。
