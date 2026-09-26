# SAILR Phase 2 集成设计 — 双脸结构化缝

> 车道 SAILRPORT · 日期 2026-09-26 · 状态: 设计稿（Phase 1 已交付: `src/sailr/`
> 算法 + 40 单测, 零管线接入）
>
> **域声明**: ENHANCEMENT。SAILR 层无 Ghidra 对照物, 逐函数 oracle 对齐纪律
> **不适用**于本层; 纪律边界 = 默认脸不受任何扰动（canon 字节恒等）+ 增强脸
> 的行为由 kuna/DecBench 语料回归与 GED 方向性指标约束（非逐函数 oracle）。
>
> 参考: angr `analyses/decompiler/structuring/{phoenix,sailr,recursive_structurer}.py`
> + `region_identifier.py`; kuna `p7_regions`/`p8_structure/region_structurer.rs`
> （`--option regionstructure` 默认 OFF 的先例）; LANE_DECBENCH_2026-09-26.md
> （增强轨 GED 杠杆: kuna 用 SAILR 族把 GED 从 28.45 拉到 39.05）。

---

## 0. 设计原则（不可协商项）

1. **默认脸零扰动**: 忠实 `blockaction`（CollapseStructure/TraceDAG）路径的
   代码、行为、canon 输出一律不变。增强脸的一切代码在默认配置下是死代码
   （kuna `regionstructure` option 默认 OFF 的同款安全性）。
2. **可配置、可回退**: 增强脸按函数粒度可尝试、可放弃 — 结构化失败
   （`structure() -> None`, honest-partial）时回退默认脸, 该函数输出与默认脸
   逐字节相同。**增强脸只允许"更结构化"的差异, 不允许引入失败**。
3. **账本纪律**: ENHANCEMENT 域改动不触碰 FUNCTION_MAP 的 Ghidra 映射函数;
   `src/sailr/*` 全部 `// RUGRA-GLUE: SAILR enhancement layer` 注解;
   blockaction/printc 侧的**任何**默认脸代码改动仍走完整 oracle 对齐门禁。
4. **可测量**: 增强脸开启前后的 GED/结构指标必须可在 canon 语料与 DecBench
   sailr 子集上分列度量（默认脸列恒等校验 + 增强脸列指标变化）。

## 1. 双脸架构

```
                        ┌─ 默认脸 (default face) ──────────────────────┐
Funcdata::bblocks ──►   │ ActionBlockStructure → CollapseStructure     │──► PrintC ──► canon C
                        │   (忠实 blockaction 移植, 对齐纪律不动)        │
                        └──────────────────────────────────────────────┘
                        ┌─ 增强脸 (enhanced face, option: sailr) ───────┐
                   └──► │ seed_sblocks 投影 → RegionIdentifier.compute   │──► 结构化树映射回
                        │   → Structurer.structure()                    │     BlockGraph → PrintC
                        │   失败 ⇒ 回退默认脸（该函数字节恒等）            │
                        └──────────────────────────────────────────────┘
```

- **脸选择点**: `ActionBlockStructure::apply` 入口处按 option 分流。默认 OFF。
  增强脸不修改 bblocks（分析只读）; 它在自己的 `sblocks` 种子副本上工作
  （与 `CollapseStructure` 相同的工作面）。
- **不是替代而是并列**: 两脸共享 seed/预计算（switch_maps/complex_blocks）,
  差异只在坍缩算法。这使"增强失败回退默认"成为零成本重放。

## 2. 接入点选项（裁决: 方案 B）

| 方案 | 描述 | 裁决 |
|---|---|---|
| A. blockaction **之后**后处理 | 先跑默认脸, 再把 goto 密集函数重跑 SAILR | ❌ 双倍结构化成本; CollapseStructure 的 goto 标记会污染输入投影 |
| B. **替代式分流**（kuna 先例） | option 开 → seed 后直接走 SAILR 路径; `structure()==None` → 重 seed 回退 CollapseStructure | ✅ kuna `run_region_structurer` 形态（返回 `(bool, flips)`, 失败 caller re-seed + fallback）; 零默认脸代码路径扰动（分流在入口, 默认臂原样） |
| C. 主管线外离线批处理 | 只在 DecBench runner 里用 | ❌ 无法产出 canon 面; 双脸对比不可复现 |

**方案 B 的缝**（`src/blockaction.rs` 默认臂不动的实现形态）:

```rust
// ActionBlockStructure::apply 分流（伪码; blockaction.rs 的改动走完整
// oracle 对齐门禁 — 该函数本就是 Ghidra 映射函数）
if arch.sailr_structure {                       // option, 默认 off
    match sailr::run(&mut data)? {              // 新 crate 门口薄封装
        SailrOutcome::Collapsed(tree, flips) => { /* 树映射 + flips 落地 */ }
        SailrOutcome::Fallback => { /* 原默认臂逐字节重放 */ }
    }
} else {
    /* 原默认臂, 不动一行 */
}
```

## 3. 输入/输出映射（Phase 1 已预留的缝）

### 3.1 输入投影（`Funcdata` → `SailrInput`）

| SailrInput 字段 | 来源（Phase 2 实现） | 备注 |
|---|---|---|
| `blocks[i].addr` | `bblocks` 块i `block_start().get_offset()` | RI 的 `(addr,ident)` 全序键 |
| `blocks[i].external` | bblocks `BlockId` | CondLeaf/Goto 按址回查 |
| `blocks[i].complex` | `bb_is_complex(bl)` | 同 `ActionBlockStructure` 预计算 |
| `blocks[i].switch` | `is_switch_out` ∧ tail BRANCHIND 有已恢复 `JumpTable` | 同 `compute_switch_maps` |
| `blocks[i].simple_return` | tail op 是 RETURN 且块内无其他副作用 | H3 启发式 |
| `edges` | bblocks out-edge 全表（顺序 = 块内 out 序, 二元块 out[0]=fallthru/out[1]=taken） | 与 Ghidra 边序约定一致 |
| `entry` | `bblocks` 起始块 | |

`RegionIdentifier::build_from_cfg` 直接吃同表（branchy = tail op ∈
{BRANCHIND, CBRANCH}, Phase 1 已实现该缝）。

### 3.2 输出映射（`StructuredNode` → `block.rs` 构件）

| StructuredNode | block.rs 构件 | 消费方（现有默认脸机器, 复用） |
|---|---|---|
| `Block{addr}` | `BlockCopy`（copy=bblocks 块） | printc 语句发射 |
| `Seq` | `new_block_list` | — |
| `Condition` | `new_block_condition`（opcode 由 CondExpr And/Or 对应 INT_AND/INT_OR） | ruleBlockIf/WhileDo 后续消费 |
| `If` / `IfElse` | `new_block_if` / `new_block_if_else` | — |
| `Switch` | `new_block_switch` + CaseOrder | `finalize_switch_printing` |
| `WhileDo` / `DoWhile` / `InfLoop` | `new_block_while_do` / `new_block_do_while` / `new_block_inf_loop` | overflow/label 机器 |
| `Goto{Plain/Break/Continue}` | `set_goto_branch` + `f_break_goto`/`f_continue_goto`（Break/Continue 类别） | `scopeBreak`/loop 构造 |

**关键: 映射是"重建"不是"翻译"** — 增强脸按结构化树重新调用与默认脸相同的
BlockGraph 构件族, 因此 `ActionFinalStructure`/printc 的全部下游机器
（mark_unstructured/finalize_switch/label/gotoPrints）零改动复用。

### 3.3 条件恢复（`CondExpr` → P-code）

Phase 1 的 CondLeaf 是按址抽象。Phase 2 的数据流缝:

1. **沿用 Ghidra 机器**: 增强脸不发明条件求值 — 映射回 BlockGraph 后,
   块的 terminal CBRANCH 即条件源, `boolean_flip`（pending_flips 奇偶 =
   CondLeaf.invert 的 XOR 归约）与 `fallthru_true` 由映射层落地, 与
   `negateCondition` 的数据流半完全同机制。
2. **复合条件**: `Condition` 构件接受 INT_AND/INT_OR（与
   `new_block_condition` 的 Ghidra 语义一致 — Phase 1 的 Or/And 选择已按
   `newBlockCondition` 的 false-out 规则忠实移植, De Morgan 否定已按
   `BlockCondition::negateCondition` 分布语义建模）。
3. **for 循环升级钩子**: `WhileDo.init/iterate`（Option）由 Phase 2 的归纳
   变量分析填（Ghidra `BlockWhileDo` 的 initialize_op/iterate_op 机器）;
   未填 = 打印为 while。

## 4. 配置面

- option `sailrstructure`（on/off, **默认 off**）— 主开关, kuna
  `regionstructure` 同名同义先例。
- option `sailrlooprefine`（默认 on when 主开关 on）— 循环精化（二级出口
  break/二级锁存 continue）。对应 kuna `regionlooprefine`。
- option `sailredgeorder`（默认 on when 主开关 on）— SAILR H1/H2/H3 支配层
  化边虚拟化序。对应 kuna `regionedgeorder`。
- **无新 Architecture 状态进入 canon 路径**: 全部经 options 注册表
  （`options.rs` 已有 `--option` 机器）, OFF = 死代码 = 字节恒等。

## 5. 默认脸中性门禁形态

1. **canon 字节恒等（每 PR 硬门禁）**: option OFF 下 curl/httpd 双语料与
   golden 逐字节比对（既有 compare_ghidra 门禁, 增强脸不豁免）。
2. **OFF-ON 双跑差分（增强脸验收）**: 同语料 ON 跑一遍; 差异必须全部落在
   结构化形态（skeleton diff 类）, `defects=0` 必须保持; 每处 ON/OFF 差异
   归因登记（增强收益 or 待修）。
3. **回退正确性**: 构造 `structure()==None` 的 fixture（不可约结）, 验证
   回退臂输出与纯默认脸字节恒等。
4. **逐函数 oracle 纪律边界声明**: ENHANCEMENT 域无 oracle 对照; 但凡为接
   入而修改的默认脸文件（blockaction.rs 预计 +10 行分流）, 该文件的全部既有
   映射函数门禁照常执行（fixture 重钉 + canon 恒等）。

## 6. 工作量分解（Phase 2 票建议）

| WP | 内容 | 量级 | 风险 |
|---|---|---|---|
| WP-2.1 | `sailr::run(&mut Funcdata)` 薄封装: 投影（§3.1）+ RI + Structurer + `SailrOutcome` | 2–3 天 | 低（缝已在 Phase 1 预留并测试） |
| WP-2.2 | `StructuredNode` → BlockGraph 重建器（§3.2）+ flips 落地 | 3–5 天 | 中（构件边序/旗标细节; 用默认脸 golden 反向校验重建一致性） |
| WP-2.3 | 分流接入 `ActionBlockStructure` + 三个 option + 回退臂 | 1–2 天 | 中（默认脸文件触碰 → 完整门禁 + fixture 重钉） |
| WP-2.4 | OFF-ON 双跑差分 harness + canon/sqlite3 DecBench sailr 子集 GED 度量 | 3–4 天 | 低（DECBENCH WP3 依赖） |
| WP-2.5 | 循环精化调参 + for 升级钩子（归纳变量） | 1 周+ | 中（数据流面, 可独立后置） |

依赖: Phase 1（本票）✅; WP-2.4 依赖 DECBENCH WP1/WP3（跑分台）。

## 7. Phase 1 交付清单（本票实际落地）

- `src/sailr/graph.rs`（~1,970 行）: 图基底 + DFS/quasi-topo/支配者/增量支
  配者, 16 单测。
- `src/sailr/region_id.rs`（~2,430 行）: RegionIdentifier 全相
  （supergraph/循环相含 angr master `_natural_loop_subgraph` 可约分发 +
  `_refine_loop` 三阶段/无环相 postdom 攀爬 + 增量支配者修补/
  `cyclic_loops` 投影/`build_from_cfg` 适配缝）, 7 单测。
- `src/sailr/structurer.rs`（~2,700 行）: 工作图 + 七级 schema 级联
  （短路/switch/序列/ITE/循环折叠+精化/goto 包装/SAILR H1-H2-H3 虚拟化）+
  `StructuredNode` IR + Break/Continue 分类, 17 单测。
- `src/lib.rs` +1 行 mod 声明; `docs/api/sailr/{mod,graph,region_id,structurer}.md`。

忠实性锚点: 所有算法决策均有 angr/Ghidra 行号引用注解; 其中三个关键语义
在移植中发现并按**语义源优先**裁决:
1. `_find_initial_loop_nodes` 用 angr master 的 `_natural_loop_subgraph`
   （可约分发）而非 kuna 的纯 slice 形态（kuna 形态在串联双锁存下把第二锁
   存误判为出口 — Phase 1 单测 regionid_multi_exit_loop 钉死）。
2. `ruleBlockCat` 的 `isDecisionOut` 守卫（f_back_edge 排除）防止序列 schema
   跨回边吞并循环体（Ghidra block.hh:336 逐字核对）。
3. `newBlockSwitch` 的 `clearFlag(f_switch_out)`（Ghidra block.cc 逐字核对）
   防止 switch 对自身输出的再匹配。
