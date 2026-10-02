# `structurer` API Reference

**状态**: 已核对（当前有效）
**源代码路径**: `src/sailr/structurer.rs`

ENHANCEMENT 域（无 Ghidra 对照物）— 本文件为 `docs/api/sailr/mod.md` 的分文件条目；
模块总览、schema 级联、门禁与 Phase 2 接入缝见该文件。

所有函数均为 `// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr <file> / kuna <file>)` 形态注解。

### `structurer.rs`

- `pub enum LoopKind { While, DoWhile, Inf }` — 循环分类（`for` 是 Phase 2
  数据流缝 `init`/`iterate` 钩子的升级目标）。
- `pub enum GotoKind { Plain, Break, Continue }` — 恢复的非结构化跳转类别。
- `pub enum CondExpr { Leaf(CondLeaf), And(..), Or(..) }` + `pub struct
  CondLeaf { addr, external, invert }` — 抽象条件（叶 = 分支块终态条件按址引
  用；`invert` = 否定奇偶；`negate()` = De Morgan 分布）。`Or`/`And` 的选择
  忠实 `BlockGraph::newBlockCondition`（`Or` 当且仅当第二块在第一块的 false
  出边上）。
- `pub enum StructuredNode { Block, Seq, Condition, If, IfElse, Switch,
  WhileDo, DoWhile, InfLoop, Goto }` — 结构化输出 IR，与 `block.rs` 块类别
  一一对应（Seq↔List、Condition↔Condition、If/IfElse↔If、Switch↔Switch、
  WhileDo/DoWhile/InfLoop↔同名、Goto↔Goto）。
- `pub struct SwitchCase { target_addr, is_default, body }` — switch case。
- `pub struct CfgBlock { addr, complex, switch, simple_return, external }` /
  `pub struct CfgEdge { src, dst, default_edge }` / `pub struct SailrInput {
  blocks, edges, entry }` — 输入投影（Phase 2 适配缝：从 `bblocks` 预计算，
  同 `ActionBlockStructure` 为 `CollapseStructure` 预计算的面）。
- `pub struct Structurer`：
  - `new(&SailrInput) -> Result<Structurer>` — 播种工作图（边序 = 输入序，
    out[0]=false/out[1]=true；back edges 由入口 DFS 标定）；
  - `with_cyclic_loops(Vec<CyclicLoop>)` — 附接 RI 循环投影（RI 接地精化；
    退化整体函数 frontier 自动回退结构走查）；
  - `structure() -> Result<Option<StructuredNode>>` — 驱动级联至单一入口根
    （残余组件为 goto 目标岛 — Ghidra 多顶层形态）；`None` = 诚实部分失败
    （调用者回退）。完成后 `classify_gotos` 后处理把循环作用域内的 goto 分
    类为 Break/Continue。

