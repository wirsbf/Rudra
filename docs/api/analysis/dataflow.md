# `analysis/dataflow.rs` API Reference（历史/待复核说明）

**文档路径**: `docs/api/analysis/dataflow.md`  
**对应旧源码路径**: `src/analysis/dataflow.rs`  
**当前状态**: ⚠️ **历史遗留文档，待根据当前源码主线重新核实**

---

## 1. 文档定位

本文档用于说明旧版 `analysis/dataflow.rs` 这类“数据流分析”文档在当前 Rudra 文档体系中的正确定位。

它在当前阶段更适合作为：

- 历史分析分层的参考材料
- 项目曾经如何规划“数据流分析”能力的背景说明
- 后续 API 文档复核时的待核对入口
- 理解旧版 `Program` 架构下分析流程的辅助资料

它**不是**当前主干数据流实现的权威说明，也不应继续被当作当前源码结构或当前已验证能力的直接映射。

当前最合适的状态标签应为：

> **历史遗留 / 待重新验证**

---

## 2. 为什么需要标记为历史文档

Rudra 当前文档基线已经明确区分：

- 当前主线对象与模块
- 历史分层架构
- 静态结构对齐
- 运行时验证
- 尚未完成验证的能力

在这个基线下，`analysis/` 目录整体都不应再默认被视为当前主干 API 的准确映射。  
原因主要有：

1. 当前主线已经更多围绕以下对象组织：
   - `Funcdata`
   - `PcodeOp`
   - `Varnode`
   - `BlockBasic`
   - `Heritage`
   - `ActionDatabase`
   - `PrintLanguage`
   - `PrintC`

2. 旧版 `analysis/` 分层文档往往对应：
   - 旧的 `Program` 风格容器
   - 旧的分析入口
   - 旧的数据流 / SSA / 类型推断 / 变量恢复组织方式

3. 即使“数据流分析”这个主题今天仍然重要，也**不能**因为主题仍然重要，就把旧文档直接当作当前代码事实。

---

## 3. 这份文档现在可以表达什么

在当前阶段，`dataflow.md` 最稳妥的职责是说明：

- Rudra 曾经或计划将“数据流分析”作为独立主题处理
- 数据流分析通常涉及：
  - reaching definitions
  - live variable analysis
  - use-def chains
  - def-use chains
  - available expressions
  - dead code detection
- 这些能力今天依然属于项目的重要方向
- 旧架构中曾尝试把这些能力作为独立分析层组织起来

但它**不能直接证明**：

- 当前 `src/analysis/dataflow.rs` 仍然是主线实现
- 当前数据流分析逻辑已经稳定存在并可直接使用
- 当前 reaching definitions / live analysis 已与 Ghidra 完全一致
- 当前数据流结果已经过运行时对拍验证
- 当前所有优化或恢复流程都还依赖旧 `analysis/dataflow.rs`

---

## 4. 数据流分析主题本身的重要性

尽管本文档当前被标记为历史说明，但“dataflow” 这个主题本身依然是反编译主链路中的关键组成部分。

典型数据流分析通常会回答以下问题：

### 4.1 一个值从哪里来
例如：

- 某个变量当前由哪几个定义点到达
- 哪些定义在某个点仍然有效
- 哪条路径上的定义覆盖了另一条路径

### 4.2 一个定义会流向哪里
也就是：

- 某条定义被哪些使用点消费
- 哪些值在后续流程中仍然活跃
- 某个定义是否最终无用

### 4.3 某个值在某个位置是否还活着
这是活跃性分析的重要问题，通常会影响：

- 变量合并
- SSA 组织
- 输出层变量恢复
- 某些局部优化

### 4.4 某些表达式能否被消除或复用
例如：

- 公共子表达式
- 死代码
- 冗余定义
- 无效赋值

### 4.5 后续恢复是否有足够的数据流证据
这类证据会直接影响：

- 变量恢复
- 类型传播
- 高级变量合并
- 更高层输出质量

因此，哪怕这份文档当前是历史说明，“数据流分析”本身仍然是 Rudra 必须认真对待的核心方向。

---

## 5. 旧文档中常见的能力分类

按旧文档描述，这一层通常会声称或计划覆盖：

- Reaching Definitions
- Live Variable Analysis
- Use-Def Chains
- Def-Use Chains
- Available Expressions
- Dead Code Detection

这些主题仍然都具有概念价值。  
但在当前阶段应理解为：

- 它们是项目能力目标的一部分
- 它们可能在当前主线中以别的方式存在或被拆散实现
- 它们**不应**再因为旧文档存在，就被视为“当前已有完整独立模块支撑”

---

## 6. 当前阅读这份文档时的正确姿势

### 可以这样理解
- 它是“数据流分析”这个主题的历史入口
- 它反映了项目早期对数据流分析的分层想法
- 它可以帮助后续整理 Rudra 数据流分析应覆盖哪些能力
- 它可以作为后续 API 文档复核时的主题清单

### 不应这样理解
- 它就是当前主干数据流实现
- 只要有这份文档，当前数据流分析就已经成熟
- 这份文档里的 API 现在一定还能直接对应到源码
- 当前 reaching definitions / liveness / use-def 已经完成验证
- 当前优化与变量恢复仍严格依赖旧版 `analysis/dataflow.rs`

---

## 7. 与当前主线更接近的阅读入口

如果你想理解 Rudra **当前更真实的数据流相关主线**，建议优先查看这些文档与源码对象：

### 优先文档
- `../lib.md`
- `../funcdata.md`
- `../op.md`
- `../varnode.md`
- `../block.md`
- `../heritage.md`
- `../action.md`
- `../printc.md`
- `../../VERIFICATION_GUIDE.md`
- `../../../CURRENT_STATUS.md`

### 优先源码对象
- `Funcdata`
- `PcodeOp`
- `Varnode`
- `BlockBasic`
- `Heritage`
- `ActionDatabase`

原因是当前数据流分析结果更可能以“分散在函数级主线对象和规则系统中”的方式存在，而不是继续严格停留在旧 `analysis/dataflow.rs` 那种目录分层里。

---

## 8. 当前推荐状态标签

后续如果继续维护这份文档，建议在页首或索引中保持如下状态：

- **状态**: 历史遗留
- **可信度**: 待核对
- **用途**: 主题参考 / 迁移参考
- **不应用途**: 当前实现权威说明

也可以考虑在后续统一引入这样的标签体系：

- `已核对（当前有效）`
- `部分有效（需对照源码）`
- `历史遗留（仅供参考）`
- `明显过期（待重写）`

而本文件当前最合适的状态就是：

> **历史遗留（仅供参考）**

---

## 9. 后续重写时应核对什么

未来如果要把这份文档重新升级为“当前有效 API 文档”，至少应核对以下问题：

1. 当前是否仍存在独立的数据流分析模块  
2. 当前数据流分析是否围绕：
   - `Funcdata`
   - `PcodeOp`
   - `Varnode`
   - `Heritage`
   - `Action`
   - `Rule`
   来组织  
3. 当前是否已经：
   - 建立 reaching definitions
   - 建立 use-def / def-use 追踪
   - 建立活跃性分析
   - 为变量恢复或优化提供可用数据流证据
4. 当前这些能力是：
   - 已实现
   - 部分实现
   - 计划中
   - 已验证
   - 尚未验证

在这些问题未核清之前，这份文档不应恢复为“当前主干说明”。

---

## 10. 与其他历史文档的关系

本文件与以下文档一起构成旧版 `analysis/` 分层的一部分：

- `analysis/mod.md`
- `analysis/ssa.md`
- `analysis/liveness.md`
- `analysis/high_variable.md`
- `analysis/optimization.md`
- `analysis/type_inference.md`
- `analysis/type_propagation.md`
- `analysis/variables.md`

它们共同有助于理解项目曾经如何拆分“高级分析”主题。  
但当前都不应自动被视为当前源码主线的等价映射。

---

## 11. 一句话结论

`docs/api/analysis/dataflow.md` 当前应被理解为：

> **Rudra 旧版“数据流分析”分层思路的历史文档入口，可用于理解 reaching definitions、活跃性、use-def/def-use 等主题的重要性，但不能继续被当作当前主线实现或当前已验证能力的权威说明。**

---