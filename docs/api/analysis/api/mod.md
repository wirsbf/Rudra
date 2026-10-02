# `analysis/api/mod.rs` API Reference（历史/待复核说明）

**文档路径**: `docs/api/analysis/api/mod.md`  
**对应旧源码路径**: `src/analysis/api/mod.rs`  
**当前状态**: ⚠️ **历史遗留文档，待根据当前源码主线重新核实**  
**可信边界**: 本文档当前仅用于说明 Rudra 旧版“API 知识库 / 外部函数原型注册表”分层的历史定位，**不应被当作当前主线实现、当前验证状态或当前可用能力的权威说明**。

---

## 1. 文档定位

本文档用于标记并解释旧版 `analysis/api/mod.rs` 文档在当前 Rudra 文档体系中的位置。

它现在最适合承担的角色是：

- 旧版“API 知识库 / 外部函数原型注册表”分层的历史入口
- 说明项目曾经如何围绕标准库函数、外部 API 原型与参数类型信息组织辅助知识库
- 为后续逐篇 API 文档复核提供待核对目标
- 帮助读者区分“当前主线类型/调用恢复”与“旧版独立 API registry 文档层”

它**不负责**说明以下内容：

- 当前 Rudra 的外部函数原型系统一定仍以 `src/analysis/api/mod.rs` 为主入口
- 当前标准库 / libc / API 原型知识库已经完整接入当前主线
- 当前参数恢复、返回值恢复和类型恢复已经稳定依赖这套旧 registry
- 当前外部函数原型行为已经与 Ghidra 或其它参考实现完成一致性验证

---

## 2. 为什么这份文档必须降级为历史说明

Rudra 当前文档基线已经明确：

- 当前主线应优先围绕真实 `src/` 可见结构来理解
- `analysis/` 目录整体不再默认视为当前主干架构的权威映射
- 旧 `Program` / `analysis` / `codegen` / `translator` 分层应视为历史说明
- 当前主线更接近围绕这些对象组织：
  - `Funcdata`
  - `PcodeOp`
  - `Varnode`
  - `BlockBasic`
  - `Heritage`
  - `ActionDatabase`
  - `PrintLanguage`
  - `PrintC`
  - `FuncProto`
  - `ProtoParameter`
  - `Datatype`
  - `TypeMetatype`

在这个前提下，`analysis/api/mod.rs` 这类文档不能再继续被写成：

- 当前主线的 API 原型注册中心
- 当前最权威的外部函数签名恢复入口
- 当前类型恢复与调用恢复的事实依据
- 当前已完成验证的外部函数知识库说明

因此，本页应明确标记为：

> **历史遗留 / 待重新验证**

---

## 3. 旧版 `analysis/api/mod.rs` 主题本身在讲什么

尽管它现在被降级为历史文档，但“API 知识库 / 外部函数原型注册表”这个主题本身在反编译器里依然很重要。

旧版文档通常试图说明以下内容：

### 3.1 外部函数原型描述
也就是如何表达某个外部 API 的签名信息，例如：

- 函数名
- 返回值类型
- 参数类型列表
- 是否为可变参数函数

### 3.2 已知 API 的注册与查找
通过注册表维护一组“已知函数签名”，用于后续查询：

- `printf`
- `malloc`
- `memcpy`
- `strlen`
- 以及其它标准库或平台 API

### 3.3 用于辅助类型恢复和参数映射
当反编译过程中识别出调用目标名称时，这套知识库理论上可以帮助：

- 恢复参数个数和参数类型
- 推断返回值类型
- 改善调用点的高层表达
- 给类型传播提供更可靠的锚点

这些内容从主题上看都是合理且重要的，但问题在于：

> **这些主题的重要性，不等于旧版 `analysis/api/mod.rs` 文档今天仍然准确映射当前主线实现。**

---

## 4. 当前为什么不能直接把旧 API registry 文档当现状

当前不能继续把旧 `analysis/api/mod.rs` 文档当成事实入口，主要原因有以下几点：

### 4.1 当前主线已更明显转向函数级上下文与统一类型系统
从现有文档基线来看，当前更接近主线的理解应围绕：

- `Funcdata`
- `FuncProto`
- `ProtoParameter`
- `Datatype`
- `TypeMetatype`
- `ActionDatabase`
- `PrintC`

而不是默认认为“独立的 `analysis/api` 注册层”仍是当前主干入口。

### 4.2 旧文档容易把概念模型误写成当前实现
旧文档中常见的对象和名称，例如：

- `ApiPrototype`
- `ApiRegistry`
- variadic 原型描述
- 标准 API 预注册逻辑

这些可能代表某一历史实现阶段的对象模型，但不能直接推出：

- 当前主线仍以这些对象作为正式公开 API
- 当前类型恢复与调用恢复仍
稳定依赖这套 registry
- 当前外部函数签名恢复已经接入默认分析流程

### 4.3 旧文档容易制造“已知 API 知识库已成熟”的错觉
只要保留了一套完整的外部原型文档，读者就很容易误判为：

- 当前已知库函数签名已经较完善
- 当前 variadic 处理已经成熟
- 当前 API 注册表已经接入主线
- 当前调用恢复质量已经有稳定锚点
- 当前输出中的外部函数调用已经可靠恢复

但当前总控文档明确反对这种推断方式。

---

## 5. 当前更接近真实主线的阅读入口

如果你现在想理解 Rudra **当前更真实的函数签名 / 类型 / 调用恢复主线**，建议优先阅读以下文档，而不是优先阅读这份历史页：

### 优先 API 文档
- `../funcdata.md`
- `../fspec.md`
- `../varnode.md`
- `../op.md`
- `../typeop.md`
- `../type_system/`
- `../printc.md`
- `../action.md`

### 优先总控文档
- `../../PROJECT_STRUCTURE.md`
- `../../README.md`
- `../../../CURRENT_STATUS.md`
- `../../../ALIGNMENT_PROGRESS.md`
- `../../VERIFICATION_GUIDE.md`
- `../../data_contract.md`

### 推荐理解方式
当前更可靠的理解顺序应当是：

1. `Funcdata`：函数级总容器  
2. `FuncProto` / `ProtoParameter`：当前函数原型建模  
3. `Datatype` / `TypeMetatype`：统一类型系统  
4. `PcodeOp` / `Varnode`：低层语义节点  
5. `ActionDatabase`：后续动作与规则处理  
6. `PrintC`：最终对调用点和函数签名进行高层文本表达  

也就是说，今天更应把函数签名恢复和类型锚点看作**主线对象与规则系统的一部分**，而不是直接把旧 `analysis/api/mod.rs` 当作默认事实起点。

---

## 6. 这份历史文档现在还能提供什么价值

虽然它不再是当前主线说明，但仍然有这些价值：

### 6.1 帮助理解项目历史演化
它能说明 Rudra 曾经如何尝试把外部 API 原型知识库做成一个独立分析分层。

### 6.2 帮助识别旧术语来源
当你在旧日志、旧设计稿、旧 API 文档里看到：

- `ApiPrototype`
- `ApiRegistry`
- variadic 原型
- 外部函数签名注册
- libc 原型知识库

时，可以知道这些术语来自旧架构语境。

### 6.3 帮助后续做迁移审计
如果将来要系统清理或复核旧文档，`analysis/api/mod.md` 可以作为“API registry 历史页”的入口保留下来。

---

## 7. 当前不应从本页继续推导的结论

阅读本页时，请特别避免继续推出以下结论：

### 不应推导 1：当前主线仍主要围绕 `ApiRegistry`
当前更接近主线的理解应围绕 `Funcdata`、`FuncProto`、统一类型系统和调用点语义，而不是默认认为 `ApiRegistry` 仍是核心正式对象。

### 不应推导 2：当前标准库原型已完整覆盖
旧文档提到可预注册常见 API，并不代表当前覆盖面已经完整、可靠或经过系统验证。

### 不应推导 3：当前 variadic 支持已经成熟
文档里有 `variadic()` 一类语义，不等于当前 `printf`、`scanf` 等可变参数函数已经被高质量恢复。

### 不应推导 4：当前调用恢复已经稳定依赖 API 原型知识库
即使旧文档设想如此，也不能因此认定当前主线仍如此工作。

### 不应推导 5：与 Ghidra 的外部函数签名恢复已经一致
这是当前最危险的误解之一。  
旧文档里的概念完整度，绝不等于行为级证据。

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

如果将来要把这类“API 知识库 / 外部函数原型”主题重新写回“当前主线 API 文档”，至少应先核清以下问题：

1. 当前主线是否仍存在独立的外部函数原型注册系统  
2. 当前函数签名恢复是否仍围绕类似 `ApiRegistry` 的中心对象  
3. 当前 variadic、标准库原型、外部调用锚点是否真正接入主线  
4. 当前相关逻辑究竟挂在：
   - `FuncProto`
   - `Datatype`
   - `ActionDatabase`
   - `PrintC`
   - 还是其他辅助结构上  
5. 当前是否已有：
   - 可重复测试
   - 运行时对拍
   - 外部 API 恢复实验记录
   - 样本级验证  
6. 当前相关能力属于：
   - 已实现
   - 部分实现
   - 计划中
   - 已验证
   - 尚未验证

在这些问题没有核清之前，本页不能恢复为“当前主线说明”。

---

## 10. 一句话结论

`docs/api/analysis/api/mod.md` 当前应被理解为：

> **Rudra 旧版“外部 API 原型知识库 / 注册表”分层思路的历史文档入口。它有助于理解项目曾如何围绕标准库函数签名、参数类型和可变参数支持组织辅助知识层，但不能继续被当作当前主线实现、当前验证状态或当前成熟能力的权威说明。**

---
","old_text":"# `analysis/api/mod.rs` API Reference\n\n**源代码路径**: `src/analysis/api/mod.rs`\n\n## 模块说明 (Module Doc)\n\nAPI Knowledge Base for Rudra Decompiler\n\nThis module provides information about standard library functions (libc, etc.)\nto assist in type recovery and parameter mapping during decompilation.\n\n## 导出的公共 API (Public API)\n\n### `pub struct ApiPrototype`\n\nRepresents a function prototype for an external API call\n\n### `pub fn new(name: &str, ret: DataType, params: Vec<DataType>) -> Self`\n\nCreate a new API prototype\n\n### `pub fn variadic(mut self) -> Self`\n\nSet variadic flag\n\n### `pub struct ApiRegistry`\n\nRegistry of known API prototypes\n\n### `pub fn new() -> Self`\n\nCreate a new registry and populate it with common symbols\n\n### `pub fn get_prototype(&self, name: &str) -> Option<&ApiPrototype>`\n\nFind a prototype by function name\n\n### `pub fn register(&mut self, proto: ApiPrototype)`\n\nRegister a new prototype\n\n ","diff":"@@ -1,35 +1,221 @@\n-# `analysis/api/mod.rs` API Reference\n+# `analysis/api/mod.rs` API Reference（历史/待复核说明）\n \n-**源代码路径**: `src/analysis/api/mod.rs`\n+**文档路径**: `docs/api/analysis/api/mod.md`  \n+**对应旧源码路径**: `src/analysis/api/mod.rs`  \n+**当前状态**: ⚠️ **历史遗留文档，待根据当前源码主线重新核实**  \n+**可信边界**: 本文档当前仅用于说明 Rudra 旧版“API 知识库 / 外部函数原型注册表”分层的历史定位，**不应被当作当前主线实现、当前验证状态或当前可用能力的权威说明**。\n \n-## 模块说明 (Module Doc)\n+---\n \n-API Knowledge Base for Rudra Decompiler\n+## 1. 文档定位\n \n-This module provides information about standard library functions (libc, etc.)\n-to assist in type recovery and parameter mapping during decompilation.\n+本文档用于标记并解释旧版 `analysis/api/mod.rs` 文档在当前 Rudra 文档体系中的位置。\n \n-## 导出的公共 API (Public API)\n+它现在最适合承担的角色是：\n \n-### `pub struct ApiPrototype`\n+- 旧版“API 知识库 / 外部函数原型注册表”分层的历史入口\n+- 说明项目曾经如何围绕标准库函数、外部 API 原型与参数类型信息组织辅助知识库\n+- 为后续逐篇 API 文档复核提供待核对目标\n+- 帮助读者区分“当前主线类型/调用恢复”与“旧版独立 API registry 文档层”\n \n-Represents a function prototype for an external API call\n+它**不负责**说明以下内容：\n \n-### `pub fn new(name: &str, ret: DataType, params: Vec<DataType>) -> Self`\n+- 当前 Rudra 的外部函数原型系统一定仍以 `src/analysis/api/mod.rs` 为主入口\n+- 当前标准库 / libc / API 原型知识库已经完整接入当前主线\n+- 当前参数恢复、返回值恢复和类型恢复已经稳定依赖这套旧 registry\n+- 当前外部函数原型行为已经与 Ghidra 或其它参考实现完成一致性验证\n \n-Create a new API prototype\n+---\n \n-### `pub fn variadic(mut self) -> Self`\n+## 2. 为什么这份文档必须降级为历史说明\n \n-Set variadic flag\n+Rudra 当前文档基线已经明确：\n \n-### `pub struct ApiRegistry`\n+- 当前主线应优先围绕真实 `src/` 可见结构来理解\n+- `analysis/` 目录整体不再默认视为当前主干架构的权威映射\n+- 旧 `Program` / `analysis` / `codegen` / `translator` 分层应视为历史说明\n+- 当前主线更接近围绕这些对象组织：\n+  - `Funcdata`\n+  - `PcodeOp`\n+  - `Varnode`\n+  - `BlockBasic`\n+  - `Heritage`\n+  - `ActionDatabase`\n+  - `PrintLanguage`\n+  - `PrintC`\n+  - `FuncProto`\n+  - `ProtoParameter`\n+  - `Datatype`\n+  - `TypeMetatype`\n \n-Registry of known API prototypes\n+在这个前提下，`analysis/api/mod.rs` 这类文档不能再继续被写成：\n \n-### `pub fn new() -> Self`\n+- 当前主线的 API 原型注册中心\n+- 当前最权威的外部函数签名恢复入口\n+- 当前类型恢复与调用恢复的事实依据\n+- 当前已完成验证的外部函数知识库说明\n \n-Create a new registry and populate it with common symbols\n+因此，本页应明确标记为：\n \n-### `pub fn get_prototype(&self, name: &str) -> Option<&ApiPrototype>`\n+> **历史遗留 / 待重新验证**\n \n-Find a prototype by function name\n+---\n \n-### `pub fn register(&mut self, proto: ApiPrototype)`\n+## 3. 旧版 `analysis/api/mod.rs` 主题本身在讲什么\n \n-Register a new prototype\n+尽管它现在被降级为历史文档，但“API 知识库 / 外部函数原型注册表”这个主题本身在反编译器里依然很重要。\n \n- \n+旧版文档通常试图说明以下内容：\n+\n+### 3.1 外部函数原型描述\n+也就是如何表达某个外部 API 的签名信息，例如：\n+\n+- 函数名\n+- 返回值类型\n+- 参数类型列表\n+- 是否为可变参数函数\n+\n+### 3.2 已知 API 的注册与查找\n+通过注册表维护一组“已知函数签名”，用于后续查询：\n+\n+- `printf`\n+- `malloc`\n+- `memcpy`\n+- `strlen`\n+- 以及其它标准库或平台 API\n+\n+### 3.3 用于辅助类型恢复和参数映射\n+当反编译过程中识别出调用目标名称时，这套知识库理论上可以帮助：\n+\n+- 恢复参数个数和参数类型\n+- 推断返回值类型\n+- 改善调用点的高层表达\n+- 给类型传播提供更可靠的锚点\n+\n+这些内容从主题上看都是合理且重要的，但问题在于：\n+\n+> **这些主题的重要性，不等于旧版 `analysis/api/mod.rs` 文档今天仍然准确映射当前主线实现。**\n+\n+---\n+\n+## 4. 当前为什么不能直接把旧 API registry 文档当现状\n+\n+当前不能继续把旧 `analysis/api/mod.rs` 文档当成事实入口，主要原因有以下几点：\n+\n+### 4.1 当前主线已更明显转向函数级上下文与统一类型系统\n+从现有文档基线来看，当前更接近主线的理解应围绕：\n+\n+- `Funcdata`\n+- `FuncProto`\n+- `ProtoParameter`\n+- `Datatype`\n+- `TypeMetatype`\n+- `ActionDatabase`\n+- `PrintC`\n+\n+而不是默认认为“独立的 `analysis/api` 注册层”仍是当前主干入口。\n+\n+### 4.2 旧文档容易把概念模型误写成当前实现\n+旧文档中常见的对象和名称，例如：\n+\n+- `ApiPrototype`\n+- `ApiRegistry`\n+- variadic 原型描述\n+- 标准 API 预注册逻辑\n+\n+这些可能代表某一历史实现阶段的对象模型，但不能直接推出：\n+\n+- 当前主线仍以这些对象作为正式公开 API\n+- 当前类型恢复与调用恢复仍稳定依赖这套 registry\n+- 当前外部函数签名恢复已经接入默认分析流程\n+\n+### 4.3 旧文档容易制造“已知 API 知识库已成熟”的错觉\n+只要保留了一套完整的外部原型文档，读者就很容易误判为：\n+\n+- 当前已知库函数签名已经较完善\n+- 当前 variadic 处理已经成熟\n+- 当前 API 注册表已经接入主线\n+- 当前调用恢复质量已经有稳定锚点\n+- 当前输出中的外部函数调用已经可靠恢复\n+\n+但当前总控文档明确反对这种推断方式。\n+\n+---\n+\n+## 5. 当前更接近真实主线的阅读入口\n+\n+如果你现在想理解 Rudra **当前更真实的函数签名 / 类型 / 调用恢复主线**，建议优先阅读以下文档，而不是优先阅读这份历史页：\n+\n+### 优先 API 文档\n+- `../funcdata.md`\n+- `../fspec.md`\n+- `../varnode.md`\n+- `../op.md`\n+- `../typeop.md`\n+- `../type_system/`\n+- `../printc.md`\n+- `../action.md`\n+\n+### 优先总控文档\n+- `../../PROJECT_STRUCTURE.md`\n+- `../../README.md`\n+- `../../../CURRENT_STATUS.md`\n+- `../../../ALIGNMENT_PROGRESS.md`\n+- `../../VERIFICATION_GUIDE.md`\n+- `../../data_contract.md`\n+\n+### 推荐理解方式\n+当前更可靠的理解顺序应当是：\n+\n+1. `Funcdata`：函数级总容器  \n+2. `FuncProto` / `ProtoParameter`：当前函数原型建模  \n+3. `Datatype` / `TypeMetatype`：统一类型系统  \n+4. `PcodeOp` / `Varnode`：低层语义节点  \n+5. `ActionDatabase`：后续动作与规则处理  \n+6. `PrintC`：最终对调用点和函数签名进行高层文本表达  \n+\n+也就是说，今天更应把函数签名恢复和类型锚点看作**主线对象与规则系统的一部分**，而不是直接把旧 `analysis/api/mod.rs` 当作默认事实起点。\n+\n+---\n+\n+## 6. 这份历史文档现在还能提供什么价值\n+\n+虽然它不再是当前主线说明，但仍然有这些价值：\n+\n+### 6.1 帮助理解项目历史演化\n+它能说明 Rudra 曾经如何尝试把外部 API 原型知识库做成一个独立分析分层。\n+\n+### 6.2 帮助识别旧术语来源\n+当你在旧日志、旧设计稿、旧 API 文档里看到：\n+\n+- `ApiPrototype`\n+- `ApiRegistry`\n+- variadic 原型\n+- 外部函数签名注册\n+- libc 原型知识库\n+\n+时，可以知道这些术语来自旧架构语境。\n+\n+### 6.3 帮助后续做迁移审计\n+如果将来要系统清理或复核旧文档，`analysis/api/mod.md` 可以作为“API registry 历史页”的入口保留下来。\n+\n+---\n+\n+## 7. 当前不应从本页继续推导的结论\n+\n+阅读本页时，请特别避免继续推出以下结论：\n+\n+### 不应推导 1：当前主线仍主要围绕 `ApiRegistry`\n+当前更接近主线的理解应围绕 `Funcdata`、`FuncProto`、统一类型系统和调用点语义，而不是默认认为 `ApiRegistry` 仍是核心正式对象。\n+\n+### 不应推导 2：当前标准库原型已完整覆盖\n+旧文档提到可预注册常见 API，并不代表当前覆盖面已经完整、可靠或经过系统验证。\n+\n+### 不应推导 3：当前 variadic 支持已经成熟\n+文档里有 `variadic()` 一类语义，不等于当前 `printf`、`scanf` 等可变参数函数已经被高质量恢复。\n+\n+### 不应推导 4：当前调用恢复已经稳定依赖 API 原型知识库\n+即使旧文档设想如此，也不能因此认定当前主线仍如此工作。\n+\n+### 不应推导 5：与 Ghidra 的外部函数签名恢复已经一致\n+这是当前最危险的误解之一。  \n+旧文档里的概念完整度，绝不等于行为级证据。\n+\n+---\n+\n+## 8. 当前推荐状态标签\n+\n+若后续对 API 文档体系引入统一状态标识，本页最合适的标签应为：\n+\n+- **状态**: 历史遗留\n+- **可信度**: 待核对\n+- **用途**: 主题参考 / 迁移参考\n+- **不应用途**: 当前主线实现说明\n+\n+也可以纳入统一标签体系中的这一类：\n+\n+> **历史遗留（仅供参考）**\n+\n+---\n+\n+## 9. 后续若要重写为“当前有效文档”，需要核对什么\n+\n+如果将来要把这类“API 知识库 / 外部函数原型”主题重新写回“当前主线 API 文档”，至少应先核清以下问题：\n+\n+1. 当前主线是否仍存在独立的外部函数原型注册系统  \n+2. 当前函数签名恢复是否仍围绕类似 `ApiRegistry` 的中心对象  \n+3. 当前 variadic、标准库原型、外部调用锚点是否真正接入主线  \n+4. 当前相关逻辑究竟挂在：\n+   - `FuncProto`\n+   - `Datatype`\n+   - `ActionDatabase`\n+   - `PrintC`\n+   - 还是其他辅助结构上  \n+5. 当前是否已有：\n+   - 可重复测试\n+   - 运行时对拍\n+   - 外部 API 恢复实验记录\n+   - 样本级验证  \n+6. 当前相关能力属于：\n+   - 已实现\n+   - 部分实现\n+   - 计划中\n+   - 已验证\n+   - 尚未验证\n+\n+在这些问题没有核清之前，本页不能恢复为“当前主线说明”。\n+\n+---\n+\n+## 10. 一句话结论\n+\n+`docs/api/analysis/api/mod.md` 当前应被理解为：\n+\n+> **Rudra 旧版“外部 API 原型知识库 / 注册表”分层思路的历史文档入口。它有助于理解项目曾如何围绕标准库函数签名、参数类型和可变参数支持组织辅助知识层，但不能继续被当作当前主线实现、当前验证状态或当前成熟能力的权威说明。**\n+\n+---\n"}