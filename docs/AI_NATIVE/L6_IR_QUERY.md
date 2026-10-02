# L6 — 结构化 IR 查询（Structured IR Query）

> 依赖: L1(事件)、L4(快照句柄)。状态: 设计。

## 动机（wave 实证）

wave 的观测原语全是**过程性的**: RUDRA_DUMP_FUNC(dump 函数全文)、
RUDRA_RULE_STATS(规则计数)、RUDRA_BS_DUMP(树 dump)——agent 要"找某类 op"只能
dump 全文再人读/脚本过滤。lane 们反复重写 grep/awk/difflib 探针(内存盘里散落
analyze_*.py 上十个)。

## 设计

**类型化查询 API 取代 dump+grep:**

```rust
// 检索
query(&run, Ops(Ptrsub).with_input_type(T::Ptr).in_stage(Stage::Type))?
query(&run, Ops(Copy).same_high().printed())?          // junk COPY 族直查
query(&run, Ops.dead().killed_by(rule_id).round(n))?    // 谁杀的,哪轮
// 解释(= L1 事件检索的语法糖)
explain(&run, op_addr)?  // 该 op 的完整变更史
// 探针原语退役
```

- 实现层: 索引(op-by-opcode/by-addr/by-rule kill 表)挂在 L4 快照句柄上,
  增量维护(事件流回放即可重建)。
- 查询语言形态: 先 Rust API(类型安全),后续可加声明式子集(JSON/DSL)供外部 agent。
- **wave 场景直接映射**: junk COPY 族(DR 车道)≈ `Ops(Copy).same_high().printed()`;
  DETERM 探查 ≈ `diff_events(runA, runB)`。

## 与 SDK 的关系

L1-L6 汇合为终局 SDK(见 README §3);本层是外部 agent 消费的**读侧门面**,
fidelity/fast 双模(L5)同构暴露。
