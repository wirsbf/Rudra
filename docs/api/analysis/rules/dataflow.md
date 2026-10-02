# `analysis/rules/dataflow.rs` API Reference（历史/待复核说明）

**文档路径**: `docs/api/analysis/rules/dataflow.md`  
**对应旧源码路径**: `src/analysis/rules/dataflow.rs`  
**当前状态**: ⚠️ **历史遗留文档，待根据当前源码主线重新核实**  
**可信边界**: 本文档当前只用于说明 Rudra 旧版“数据流规则 / 规则化优化”分层的历史定位，**不应被当作当前主线规则系统、当前默认优化流水线或当前已验证能力的权威说明**。

---

## 1. 文档定位

本文档用于标记并解释旧版 `analysis/rules/dataflow.rs` 文档在当前 Rudra 文档体系中的位置。

它现在最适合承担的角色是：

- 旧版“数据流规则”分层的历史入口
- 说明项目曾经如何把 copy propagation、dead code elimination、type-based simplification、load/store propagation、control-flow simplification 等内容组织在独立规则目录中
- 为后续逐篇 API 文档复核提供待核对目标
- 帮助读者区分“当前 Action / Rule 主线”与“旧版 analysis/rules 文档层”

它**不负责**说明以下内容：

- 当前 Rudra 的主线规则实现一定仍然位于 `src/analysis/rules/dataflow.rs`
- 当前默认规则流水线仍然直接按该文件中的结构组织
- 当前这些规则已经与 Ghidra 完成运行时一致性验证
- 当前这些规则都已经稳定、完整并可作为输出质量保证依据

---

## 2. 为什么这份文档必须降级为历史说明

Rudra 当前文档基线已经明确：

- 当前主线应优先围绕真实 `src/` 可见结构来理解
- 旧 `analysis/` / `pcode/Program` / `codegen/` / `translator/` 分层应视为历史说明
- 当前更接近主线的理解应围绕：
  - `Funcdata`
  - `PcodeOp`
  - `Varnode`
  - `BlockBasic`
  - `Heritage`
  - `Action`
  - `Rule`
  - `ActionDatabase`
  - `PrintLanguage`
  - `PrintC`

在这个前提下，`analysis/rules/dataflow.rs` 这类文档不能再继续被写成：

- 当前规则系统的主入口
- 当前优化能力的权威说明
- 当前与 Ghidra 规则系统已一致的证据
- 当前输出质量已经建立在成熟数据流规则之上的证明

因此，本页应明确标记为：

> **历史遗留 / 待重新验证**

---

## 3. 旧版 `analysis/rules/dataflow.rs` 主题本身在讲什么

尽管它现在被降级为历史文档，但“数据流规则”这个主题本身在反编译主链路中仍然很重要。

旧版文档通常围绕以下规则或主题展开：

- Copy Propagation
- Dead Code Elimination
- Global Propagation
- Type-based Simplification
- Identity Copy Elimination
- Truncation Elimination
- Load/Store Propagation
- Control Flow Simplification

这些主题本身都具有明确的工程意义，因为它们分别试图回答：

### 3.1 哪些值可以直接传播
例如：
- `A = COPY B` 之后，是否可以把 `A` 的使用点直接替换成 `B`
- 某个中间变量是否只是过渡值，没有继续保留的必要

### 3.2 哪些定义实际上已经无用
例如：
- 一个输出值没有任何后续使用
- 一条操作只有副作用判定后才决定是否应保留
- 某些临时定义只是噪音节点

### 3.3 哪些低层模式可以被进一步简化
例如：
- 冗余 copy
- 冗余 truncation
- 某些可被消除的 load/store 中转
- 依赖类型信息的冗余转换或包装

### 3.4 哪些控制流或数据流形态可以被规整
例如：
- 恒真 / 恒假的条件传播
- 简单跳转规整
- 可提前决策的路径简化

这些主题依然重要，但问题在于：

> **这些主题的重要性，不等于旧版 `analysis/rules/dataflow.rs` 文档今天仍然准确映射当前主线实现。**

---

## 4. 当前为什么不能直接把旧规则文档当现状

当前不能继续把旧 `analysis/rules/dataflow.rs` 文档当作事实入口，主要原因有以下几点：

### 4.1
 当前主线规则系统更应从 `action.rs` / `ruleaction.rs` 理解
从当前可见源码和已修正文档看，Rudra 当前更接近主线的规则 / 动作组织方式，是围绕：

- `Action`
- `Rule`
- `ActionGroup`
- `ActionDatabase`
- `coreaction.rs`
- `ruleaction.rs`

来理解，而不是继续优先把旧 `analysis/rules/` 看作默认入口。

### 4.2 旧规则文档容易制造“规则库已成熟”的错觉
只要保留了一组看起来完整的规则名称，读者就很容易误判为：

- 当前规则系统已经丰富稳定
- 当前 copy propagation 已全面可用
- 当前 DCE 已精确稳定
- 当前 load/store propagation 已成熟
- 当前 control-flow simplification 已可靠

但这些都不能仅靠旧文档得出。

### 4.3 旧规则文档容易把旧 `Program` 架构带回来
历史规则说明常常默认依赖：

- `Program`
- `FunctionAnalysis`
- 旧分析分层
- 旧优化阶段组织方式

这会和当前已经转向 `Funcdata` / `Heritage` / `ActionDatabase` 的理解冲突。

---

## 5. 当前更接近真实主线的规则阅读入口

如果你现在想理解 Rudra **当前更真实的规则与变换主线**，建议优先阅读以下文档，而不是优先阅读这份历史页：

### 优先 API 文档
- `../../action.md`
- `../../coreaction.md`
- `../../ruleaction.md`
- `../../funcdata.md`
- `../../op.md`
- `../../varnode.md`
- `../../heritage.md`
- `../../printc.md`

### 优先总控文档
- `../../../PROJECT_STRUCTURE.md`
- `../../../README.md`
- `../../../../CURRENT_STATUS.md`
- `../../../../ALIGNMENT_PROGRESS.md`
- `../../../VERIFICATION_GUIDE.md`
- `../../../data_contract.md`

### 推荐理解顺序
当前更可靠的理解路径应当是：

1. `Funcdata`：函数级总容器  
2. `PcodeOp` / `Varnode`：操作与值节点  
3. `Heritage`：SSA / heritage 过程  
4. `Action` / `Rule`：当前更接近主线的动作与规则抽象  
5. `ActionDatabase`：默认动作流水线组织  
6. `PrintC`：最终输出消费层  

也就是说，今天更应把 `action.rs` / `ruleaction.rs` 看作当前规则主线理解入口，而不是把 `analysis/rules/dataflow.rs` 当作默认事实起点。

---

## 6. 这份历史文档现在还能提供什么价值

虽然它不再是当前主线说明，但仍然有这些价值：

### 6.1 帮助理解项目历史演化
它能说明 Rudra 曾经如何试图把一批“数据流相关局部优化规则”独立组织成子目录。

### 6.2 帮助识别旧术语来源
当你在旧日志、旧设计稿、旧 API 文档里看到以下词汇时，可以知道它们来自旧分层语境：

- `RuleCopyPropagation`
- `RuleDeadCodeElimination`
- `RuleGlobalPropagation`
- `RuleTypePropagation`
- `RuleIdentityCopy`
- `RuleTruncationElimination`
- `RuleLoadStorePropagation`
- `RuleControlFlowSimplification`

### 6.3 帮助后续做迁移审计
如果将来要系统清理或复核旧文档，这一页可以作为“数据流规则历史页”的入口保留下来。

---

## 7. 当前不应从本页继续推导的结论

阅读本页时，请特别避免继续推出以下结论：

### 不应推导 1：当前规则系统仍主要围绕旧 `analysis/rules/`
当前更接近主线的理解应围绕 `action.rs`、`ruleaction.rs` 和 `ActionDatabase`。

### 不应推导 2：当前所有规则都已存在且可运行
历史文档中的规则名称只说明项目曾计划或曾实现过这些方向，不代表它们今天都仍是当前主线的一部分。

### 不应推导 3：数据流规则行为已经成熟稳定
文档里有这些规则名，不等于：
- 规则实现已完成
- 规则已进入默认流水线
- 规则没有副作用问题
- 规则已完成回归验证

### 不应推导 4：与 Ghidra 的规则行为已经一致
这是当前最危险的误解之一。  
旧文档中的规则集合完整度，绝不等于行为级证据。

### 不应推导 5：输出质量已经由这些规则保证
即使这些规则在概念上都很有价值，也不能仅因为历史文档存在，就推导出当前输出层已经成熟。

---

## 8. 当前推荐状态标签

若后续对 API 文档体系引入统一状态标识，本页最合适的标签应为：

- **状态**: 历史遗留
- **可信度**: 待核对
- **用途**: 主题参考 / 迁移参考
- **不应用途**: 当前主线实现说明

也可以纳入统一标签体系中的这一类：

> **历史遗留（仅供参考）**

---

## 9. 后续若要重写为“当前有效文档”，需要核对什么

如果将来要把“数据流规则”主题重新写回“当前主线 API 文档”，至少应先核清以下问题：

1. 当前主线规则系统是否完全围绕 `Action` / `Rule` / `ActionDatabase`  
2. 当前是否仍存在独立可用的 `analysis/rules/dataflow.rs`  
3. 当前这些规则是否已有真实实现并接入主流程：
   - copy propagation
   - dead code elimination
   - global propagation
   - truncation elimination
   - load/store propagation
   - control-flow simplification
4. 当前这些规则是否：
   - 已实现
   - 部分实现
   - 计划中
   - 已验证
   - 尚未验证
5. 当前这些规则是否已有：
   - 测试
   - 回归记录
   - 行为差异分析
   - 与 Ghidra 的验证证据

在这些问题没有核清之前，本页不能恢复为“当前主线说明”。

---

## 10. 一句话结论

`docs/api/analysis/rules/dataflow.md` 当前应被理解为：

> **Rudra 旧版“数据流规则 / 局部优化规则”分层思路的历史文档入口。它有助于理解 copy propagation、dead code elimination、load/store propagation 等主题的重要性，但不能继续被当作当前主线规则实现、当前验证状态或当前成熟能力的权威说明。**

---
"}