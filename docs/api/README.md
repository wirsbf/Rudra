# Rudra API 文档索引

本目录用于存放 `rudra/src/` 对应的 API 参考文档，目标是为开发者提供一份**基于当前源码现状的接口索引、阅读入口与维护说明**。

它不是自动生成的 Rust API 网页，也不是面向终端用户的使用手册。  
它主要服务于以下场景：

- 快速定位 `src/` 中某个模块对应的说明文档
- 理解 Rudra 核心对象之间的职责边界
- 辅助进行 Ghidra 对齐开发
- 在修改公共接口后同步维护文档
- 识别哪些文档已经过期、哪些仍需补齐

---

## 1. 文档状态标签规则

为了让 `docs/api/` 里的文档可信度更清晰，后续所有 API 文档建议统一使用以下状态标签之一，并在文档开头显式标注。

### `已核对（当前有效）`
用于表示：

- 已对照当前 `src/` 源码核实过
- 模块职责说明与当前主线一致
- 公开接口说明基本可作为当前参考
- 没有明显的旧架构误导表述

这并不自动代表：

- 该模块行为已经完成运行时验证
- 该模块已经成熟稳定
- 与 Ghidra 已完成一致性证明

它只表示：**文档本身已与当前源码状态基本对齐。**

### `部分有效（需对照源码）`
用于表示：

- 文档中的部分内容仍有参考价值
- 但尚未逐项与当前源码完全核实
- 某些接口、结构或示例可能已经滞后
- 阅读时必须同时对照 `src/` 源码

这类文档适合作为：

- 过渡参考
- 迁移中说明
- 后续重写前的临时说明

### `历史遗留（仅供参考）`
用于表示：

- 文档主要反映旧架构、旧分层或旧实现阶段
- 不能再作为当前主线 API 的权威说明
- 适合帮助理解项目历史演化、术语来源和旧设计思路
- 不适合作为当前能力判断依据

这类文档通常出现在：

- 旧 `analysis/` 分层
- 旧 `pcode/Program` 架构
- 旧 `codegen/` 分层
- 旧 `translator/` 分层

### `明显过期（待重写）`
用于表示：

- 文档内容与当前源码结构冲突明显
- 存在高概率误导
- 已不适合继续作为有效参考
- 应优先进入重写队列

如果一个文档仍保留旧 API、旧主线入口、旧示例代码，且容易让读者误判现状，应优先标成这一类。

### 标签使用原则

后续维护 `docs/api/` 时，建议遵守以下规则：

1. 每篇 API 文档开头都尽量给出状态标签
2. 如果拿不准，不要轻易写成“已核对（当前有效）”
3. 旧架构说明优先使用“历史遗留（仅供参考）”
4. 明显冲突但尚未重写的文件，应优先标为“明显过期（待重写）”
5. 状态标签描述的是**文档可信度**，不是模块完成度

---

## 2. 使用原则

阅读本目录时，请始终遵循以下原则：

> **以 `rudra/src/` 的真实代码为准，以 `docs/api/` 作为辅助解释层。**

如果 API 文档与源码冲突，应优先修正文档，而不是假定源码错误。

这意味着：

- 某个接口出现在文档中，**不代表**该接口当前一定稳定可用
- 某个模块有文档，**不代表**该模块的所有能力都已经完整实现
- 某个目录存在，**不代表**其中所有内容都已与当前代码严格同步
- 某个设计被写进文档，**不代表**它已经通过测试或验证

---

## 3. 当前文档定位

`docs/api/` 的职责是描述：

- 模块做什么
- 公开类型和函数大致承担什么角色
- 它们在整体反编译链路中的位置
- 它们与 Ghidra 风格概念的映射关系
- 当前文档覆盖到什么程度

`docs/api/` **不负责**直接证明以下内容：

- CLI 已完整可用
- 端到端反编译流程已稳定
- 与 Ghidra 已达到 1:1 行为一致
- 所有验证链路都已打通
- 某个模块已经达到生产可用级别

这些判断应结合以下文档一起看：

- `../PROJECT_STRUCTURE.md`
- `../../CURRENT_STATUS.md`
- `../../GAP_ANALYSIS.md`
- `../../ALIGNMENT_PROGRESS.md`
- `../VERIFICATION_GUIDE.md`

---

## 4. 当前覆盖状态说明

本目录当前应被理解为：

### 3.1 已有较完整覆盖的部分
主要是 `src/` 根目录中的一批核心模块说明文档，例如：

- `address.md`
- `space.md`
- `varnode.md`
- `op.md`
- `opcodes.md`
- `pcoderaw.md`
- `block.md`
- `funcdata.md`
- `heritage.md`
- `action.md`
- `coreaction.md`
- `ruleaction.md`
- `blockaction.md`
- `printlanguage.md`
- `printc.md`

### 3.2 已建立分类目录的部分
当前目录下还存在若干分类子目录，例如：

- `align/`
- `analysis/`
- `bin/`
- `binary/`
- `codegen/`
- `disasm/`
- `pcode/`
- `translator/`
- `type_system/`

这些目录说明文档体系曾按更细分的结构组织过，但**并不意味着这些分类仍与当前源码结构完全一一对应**。

### 3.3 存在历史失真与过期风险的部分
当前需要特别警惕以下类型的问题：

- 文档仍反映旧架构
- 文档引用了当前已停用或已注释的接口
- 目录结构说明滞后于代码重构
- 计划中能力被误写成“已完成能力”
- 旧的 `Program` 式流程或旧分层命名仍残留在部分说明中

因此，本目录当前更适合作为：

> **“基于现有源码的 API 说明集合”**  
> 而不是  
> **“绝对精确、自动同步、100% 权威的镜像文档系统”**

---

## 5. 当前源码主线模块索引

结合当前可见的 `src/` 结构，Rudra 的主线更接近以下组织方式。

### 4.1 基础对象与地址空间
- `address.rs`
- `space.rs`
- `types.rs`

对应文档通常包括：

- `address.md`
- `space.md`
- `types.md`

### 4.2 IR / 语义核心对象
- `varnode.rs`
- `variable.rs`
- `op.rs`
- `opcodes.rs`
- `pcoderaw.rs`
- `block.rs`

对应文档通常包括：

- `varnode.md`
- `variable.md`
- `op.md`
- `opcodes.md`
- `pcoderaw.md`
- `block.md`

### 4.3 函数级分析主流程
- `funcdata.rs`
- `heritage.rs`
- `action.rs`
- `coreaction.rs`
- `ruleaction.rs`
- `blockaction.rs`
- `merge.rs`
- `cover.rs`
- `fspec.rs`

对应文档通常包括：

- `funcdata.md`
- `heritage.md`
- `action.md`
- `coreaction.md`
- `ruleaction.md`
- `blockaction.md`
- `merge.md`
- `cover.md`
- `fspec.md`

### 4.4 输出与打印
- `prettyprint.rs`
- `printlanguage.rs`
- `printc.rs`

对应文档通常包括：

- `prettyprint.md`
- `printlanguage.md`
- `printc.md`

### 4.5 类型系统
- `typeop.rs`
- `type_system/`

对应文档通常包括：

- `typeop.md`
- `type_system/`

---

## 6. 当前主线文档清单（建议优先阅读）

以下清单用于帮助你快速定位**当前主线架构**中优先参考的 API 文档。  
这些页面更接近当前 `src/` 可见结构与当前总控文档口径，适合在继续开发、校对接口或追踪模块职责时优先阅读。

> 说明：  
> 1. 下列清单强调“当前主线阅读优先级”，不是模块成熟度排名。  
> 2. 即使文档状态为“已核对（当前有效）”，也**不等于**该模块已经完成运行时验证或达到 Ghidra 一致性。  
> 3. 若与源码冲突，仍以 `src/` 实际实现为准。

### 6.1 库入口与总览
- `lib.md`
- `error.md`

### 6.2 基础对象与地址空间
- `address.md`
- `space.md`

### 6.3 IR / 语义核心对象
- `varnode.md`
- `op.md`
- `opcodes.md`
- `pcoderaw.md`
- `block.md`

### 6.4 函数级分析与恢复主线
- `funcdata.md`
- `heritage.md`
- `action.md`
- `coreaction.md`
- `ruleaction.md`
- `blockaction.md`
- `merge.md`
- `cover.md`
- `fspec.md`
- `typeop.md`

### 6.5 输入、反汇编与桥接
- `binary/mod.md`
- `disasm/mod.md`
- `disasm/x86_64.md`
- `disasm/x86_lift.md`
- `ffi.md`
- `bin/rudra.md`

### 6.6 输出层
- `printc.md`

### 6.7 对齐与验证主线
- `align/mod.md`
- `align/address.md`
- `align/action.md`
- `align/block.md`
- `align/datatype.md`
- `align/heritage.md`
- `align/pcodeop.md`
- `align/range.md`
- `align/runtime_verify.md`
- `align/varnode.md`

---

## 7. 历史文档清单（仅供参考）

以下清单主要用于帮助你识别**历史架构、旧分层或待复核页面**。  
这些文档可以帮助理解项目演化路径、旧术语来源和历史设计思路，但**不应**直接作为当前主线能力判断依据。

### 7.1 旧分析分层
- `analysis/mod.md`
- `analysis/calls.md`
- `analysis/dataflow.md`
- `analysis/high_variable.md`
- `analysis/liveness.md`
- `analysis/optimization.md`
- `analysis/ssa.md`
- `analysis/type_inference.md`
- `analysis/type_propagation.md`
- `analysis/variables.md`
- `analysis/api/mod.md`
- `analysis/rules/mod.md`
- `analysis/rules/algebra.md`
- `analysis/rules/constants.md`
- `analysis/rules/dataflow.md`

### 7.2 旧 P-code / Program 分层
- `pcode/mod.md`
- `pcode/program.md`

### 7.3 旧输出 / 翻译分层
- `codegen/mod.md`
- `translator/mod.md`
- `translator/x86_64.md`
- `translator/registers.md`

### 7.4 使用建议
阅读这些历史文档时，建议同时交叉核对：

- `docs/README.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- 当前 `src/` 真实实现

如果历史文档与当前总控文档冲突，应优先以**当前源码 + 当前总控文档**为准。

---

## 8. 后续维护建议

为了让这份索引继续保持可用，后续维护时建议同步执行以下动作：

1. 新增当前主线 API 文档时，评估是否应加入“当前主线文档清单”
2. 将明显转入历史语境的页面移入“历史文档清单”
3. 当某页完成重写或重新核对后，更新其状态标签
4. 当某页不再适合作为主线参考时，及时从主线清单移出
5. 若 `src/` 结构发生明显调整，应同步回看本索引的两份清单是否仍成立

### 4.6 配套模块
- `binary/`
- `disasm/`
- `align/`
- `ffi.rs`
- `error.rs`
- `utils.rs`

对应文档通常包括：

- `binary/`
- `disasm/`
- `align/`
- `ffi.md`
- `error.md`
- `utils.md`

---

## 6. 根级 API 文档索引

以下文档通常对应 `src/` 根目录下的单个 Rust 源文件：

- `action.md`
- `address.md`
- `block.md`
- `blockaction.md`
- `coreaction.md`
- `cover.md`
- `error.md`
- `ffi.md`
- `fspec.md`
- `funcdata.md`
- `heritage.md`
- `lib.md`
- `merge.md`
- `op.md`
- `opcodes.md`
- `pcoderaw.md`
- `prettyprint.md`
- `printc.md`
- `printlanguage.md`
- `ruleaction.md`
- `space.md`
- `typeop.md`
- `types.md`
- `utils.md`
- `variable.md`
- `varnode.md`

这些文档是当前 API 阅读的主要入口。

---

## 7. 子目录索引与注意事项

### `align/`
用于承载与 Ghidra 对齐验证相关的接口说明和补充材料。

适合查阅场景：

- 静态结构对齐
- 对齐辅助对象
- 运行时验证框架相关说明

注意：

- 对齐文档不等于“已证明与 Ghidra 行为完全一致”
- 静态对齐不等于运行时一致性验证完成

---

### `analysis/`
分析相关的文档分区。

注意：

- 当前源码主干并不完全按单独 `analysis/` 目录组织
- 该目录中的内容可能带有旧分层结构痕迹
- 使用时应对照 `src/` 当前真实文件布局

---

### `bin/`
CLI 或二进制入口相关文档分区。

注意：

- 当前 `src/bin/rudra.rs` 处于受限/临时简化状态
- 文档中不应继续把 CLI 描述成完整稳定的产品入口
- 若此目录中存在旧命令说明，应优先核对并修正

---

### `binary/`
二进制解析相关模块文档。

适合查阅：

- 格式解析
- 节区/段/符号处理
- 加载期元信息组织

---

### `codegen/`
代码生成相关文档分区。

注意：

- 当前实际输出主线更多体现为 `printlanguage` / `printc`
- 若此目录内仍使用旧的 `codegen` 分层说法，应结合源码判断是否过期

---

### `disasm/`
反汇编与指令语义相关文档分区。

适合查阅：

- 架构相关反汇编
- 指令级提升
- x86/x86-64 语义入口

---

### `pcode/`
P-code 相关文档分区。

注意：

- 当前核心实现更围绕 `PcodeOp`、`PcodeOpRaw`、`Funcdata` 等对象组织
- 旧文档若仍强依赖早期 `Program` 架构，应视为待校正内容

---

### `translator/`
指令提升/翻译相关文档分区。

注意：

- 如果源码实现已经迁移或收敛到 `disasm/`、`pcoderaw` 或其他主链路模块，该目录中的说明可能需要人工复核

---

### `type_system/`
类型系统相关文档分区。

适合查阅：

- `Datatype`
- 类型构造
- cast / typefactory 等子模块说明

---

## 8. 推荐阅读顺序

如果你是第一次从 API 层理解 Rudra，建议按下面顺序阅读。

### 第一层：库入口与总览
1. `lib.md`

用于理解：

- 当前公开模块有哪些
- 工程对外暴露了哪些核心概念
- 哪些接口仍可能处于过渡状态

### 第二层：核心数据对象
2. `address.md`
3. `space.md`
4. `varnode.md`
5. `op.md`
6. `opcodes.md`
7. `pcoderaw.md`
8. `block.md`

用于理解：

- 地址和空间怎么表达
- IR 数据节点和操作节点怎么组织
- raw p-code 与正式 IR 的关系
- CFG 的块级表示如何落地

### 第三层：函数与分析流程
9. `funcdata.md`
10
. `heritage.md`
11. `action.md`
12. `coreaction.md`
13. `ruleaction.md`
14. `blockaction.md`
15. `merge.md`
16. `fspec.md`

用于理解：

- 单函数分析上下文
- SSA / heritage 相关流程
- Action / Rule 的组织方式
- 函数签名与参数建模

### 第四层：输出与类型
17. `prettyprint.md`
18. `printlanguage.md`
19. `printc.md`
20. `typeop.md`
21. `type_system/`

用于理解：

- 输出层如何组织
- C 风格文本如何生成
- 类型系统如何接入分析和打印

### 第五层：配套模块
22. `binary/`
23. `disasm/`
24. `align/`
25. `ffi.md`
26. `error.md`
27. `utils.md`

用于理解：

- 二进制入口
- 架构相关语义
- 对齐验证入口
- FFI、错误与工具支撑

---

## 9. 当前已知限制

在维护和使用本目录时，需要特别注意以下限制。

### 8.1 文档不能替代测试结论
文档只能说明“代码里存在某个对象、接口或模块说明”，不能替代：

- 测试通过记录
- FFI 打通记录
- 与 Ghidra 的对拍证据
- 端到端输出质量评估

### 8.2 文档不能自动推导实现成熟度
某模块有文档，不代表：

- 模块已稳定
- 模块已完整
- 模块已完成验证
- 模块已适合对外承诺

### 8.3 历史目录可能滞后于当前源码
如果你看到如下情况，应优先怀疑文档过期：

- 文档使用旧架构名词
- 文档引用当前不存在的模块路径
- 文档把旧接口写成当前主入口
- 文档描述与 `src/lib.rs` 的导出列表明显冲突

### 8.4 `lib.md` 等总览文档风险较高
总览文档最容易出现以下问题：

- 引用被注释的接口
- 继续描述已停用的 `Decompiler`
- 把过渡期 API 写成正式稳定入口
- 沿用旧架构示例代码

因此维护时应优先审阅总览文档。

---

## 10. 文档维护规则

后续维护 `docs/api/` 时，应遵循以下规则。

### 9.1 修改公共接口时同步检查文档
当 `src/` 中出现以下变化时，必须同步检查对应 API 文档：

- 新增 `pub` 结构体、枚举、函数、常量
- 删除或停用公共接口
- 修改类型签名
- 重命名源文件或模块
- 修改模块职责边界

### 9.2 新增文件时评估是否需要新增文档
不是每个文件都必须立刻写成“完整 API 文档”，但至少应回答：

- 这个文件是否属于主链路
- 是否对外暴露了公共接口
- 是否需要被其他开发者快速理解
- 是否需要在 `docs/api/` 中建立入口

### 9.3 删除或停用文件时及时清理过期文档
如果源码中某个模块被：

- 删除
- 注释停用
- 迁移到别的目录
- 改为仅内部使用

则对应 API 文档也必须跟进，至少做以下之一：

- 删除文档
- 标注“已停用”
- 改写为“历史说明，不再作为当前主入口”

### 9.4 明确标注状态词
后续文档中请尽量明确区分：

- **已实现**
- **部分实现**
- **计划中**
- **待验证**
- **临时禁用**
- **已停用**
- **历史遗留**

不要再把这些状态混写成“已支持”。

### 9.5 不得把未来设计写成当前事实
以下写法应避免：

- “已经完整支持……”
- “已经与 Ghidra 一致……”
- “当前可直接用于……”
- “所有 API 都已同步……”

除非确实有源码、测试和验证记录可以支撑。

---

## 11. 建议的文档审计优先级

如果要继续清理 `docs/api/` 的失真，建议按以下优先级推进。

### 第一优先级
- `lib.md`
- `funcdata.md`
- `op.md`
- `varnode.md`
- `printc.md`
- `action.md`

因为这些文档最容易影响对整体架构的理解。

### 第二优先级
- `binary/`
- `disasm/`
- `align/`
- `type_system/`

因为这些目录直接关系到主链路输入、验证和类型恢复。

### 第三优先级
- `analysis/`
- `codegen/`
- `pcode/`
- `translator/`
- `bin/`

因为这些分类目录更容易保留旧结构痕迹，需要重点判断“是否仍反映现状”。

---

## 12. 与其他文档的关系

本目录只负责“接口与模块层面的参考说明”。  
如果你需要了解其他维度，请查阅：

- 项目整体结构：`../PROJECT_STRUCTURE.md`
- 当前状态评估：`../../CURRENT_STATUS.md`
- 差距分析：`../../GAP_ANALYSIS.md`
- 对齐进度：`../../ALIGNMENT_PROGRESS.md`
- 验证方式：`../VERIFICATION_GUIDE.md`
- 任务看板：`../TODO_BOARD.md`

推荐理解方式如下：

- `README.md` 负责项目定位
- `PROJECT_STRUCTURE.md` 负责目录与模块索引
- `docs/api/` 负责接口与对象说明
- `CURRENT_STATUS.md` 负责现状判断
- `ALIGNMENT_PROGRESS.md` 负责对齐分层结论
- `VERIFICATION_GUIDE.md` 负责验证口径和路径

---

## 13. 一句话结论

`docs/api/` 的目标不是制造“看起来很全”的假象，而是提供一份**尽量忠实于当前源码状态的 API 索引与解释层**。  
后续所有补充和修订，都应以以下三点为第一原则：

1. 减少失真  
2. 提升可追溯性  
3. 明确能力边界

只要坚持这三点，这套 API 文档才能真正服务于 Rudra 的持续开发，而不是继续放大认知偏差。
## tracedag.md — TraceDAG (selectGoto 主算法)

Ghidra blockaction.cc 行 499-1014 的 TraceDAG 移植。追踪控制流图找 likely goto 边。
当前实现是骨架（BranchPoint/BlockTrace 结构 + pushBranches 算法），但 check_open 和
select_bad_edge 使用简化近似（需完整 BadEdgeScore + visit-count 追踪），已禁用。
