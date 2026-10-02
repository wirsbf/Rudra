# Rudra 项目结构总览（Project Structure）

本文档用于提供 `rudra/` 子项目的**真实结构索引**，帮助开发者快速理解：

- 当前源码模块如何组织
- 哪些目录是核心实现，哪些是实验/示例/验证配套
- 文档体系应该去哪里查、去哪里更新
- 哪些内容已经存在，哪些仍处于占位、重构中或待补完状态

> **事实基线**
>
> 本文档以当前仓库中实际存在的 `rudra/` 目录为准。  
> 如果其他文档出现与本文不一致的旧描述，应优先修正文档，而不是沿用失真说法。

---

## 1. 项目定位

`Rudra` 是一个基于 Rust 的、受 Ghidra 启发的**二进制反编译与程序分析框架**。  
当前可确认的目标方向包括：

1. 二进制格式解析（ELF / PE / Mach-O）
2. 指令反汇编与语义提升
3. 围绕 Ghidra 风格核心对象构建中间表示
4. 执行控制流、数据流、SSA、类型相关分析
5. 输出更可读的 C 风格结果
6. 逐步与 Ghidra 的行为和数据模型进行对齐验证

---

## 2. 当前顶层目录结构

以下为 `rudra/` 当前主要目录的职责说明：

| 路径 | 类型 | 说明 |
|------|------|------|
| `src/` | 核心源码 | Rust 主库代码，当前最重要的实现目录 |
| `src/bin/` | CLI 入口 | 命令行入口；当前 CLI 处于临时简化/禁用状态 |
| `tests/` | 集成测试 | 工程级测试入口 |
| `examples/` | 示例程序 | 用于演示反汇编、反编译、调试等能力 |
| `benches/` | 基准测试 | 性能测试与基准代码 |
| `docs/` | 项目文档 | 总控文档、API 文档、流程模板、日志、实验等 |
| `tools/` | 辅助脚本 | 开发、文档、验证等辅助工具 |
| `result/` | 结果产物 | 输出结果与实验产物归档目录 |
| `ghidra/` | 外部参考/镜像目录 | 仓库内包含的 Ghidra 相关内容，用于参考、对齐或配套工作 |
| `target/` | 构建产物 | Cargo 构建输出目录，不作为人工维护对象 |

---

## 3. 核心源码结构（`src/`）

当前 `src/` 的组织方式，已经明显转向 **Ghidra 风格核心对象 + 分析动作链** 的建模方式。  
与一些旧文档中提到的 `analysis/`、`codegen/`、`pcode/`、`translator/` 独立目录结构不同，**当前真实源码以顶层模块文件为主**，并辅以少量子目录。

### 3.1 顶层核心模块

| 文件 | 角色 | 说明 |
|------|------|------|
| `src/lib.rs` | 库入口 | 暴露公共模块与类型重导出，定义当前库的整体入口 |
| `src/address.rs` | 地址模型 | 地址、序号、范围等基础寻址语义 |
| `src/space.rs` | 地址空间 | 地址空间抽象，如寄存器、内存、唯一空间等 |
| `src/varnode.rs` | Varnode 模型 | Ghidra 风格变量节点表示 |
| `src/op.rs` | PcodeOp 模型 | P-code 操作对象及其核心行为 |
| `src/opcodes.rs` | 操作码枚举 | P-code 操作码定义与映射 |
| `src/typeop.rs` | 类型操作 | 与类型语义、操作行为相关的基础支持 |
| `src/pcoderaw.rs` | 原始 P-code | 尚未完全进入高层结构前的原始操作表示 |
| `src/block.rs` | 基本块/图块 | 控制流图中的块级结构 |
| `src/funcdata.rs` | 函数级核心
对象 | 函数分析期的核心容器，承载大量中间状态 |
| `src/fspec.rs` | 函数原型
 | 函数签名、参数等描述 |
| `src/heritage.rs` | SSA / Heritage | 与 SSA 相关的 heritage 过程和
变量版本传播 |
| `src/variable.rs` | 变量层抽象 | 较高层的变量概念与组织方式 |
|
 `src/merge.rs` | 合并逻辑 | 变量/节点/语义
对象的合并支持 |
| `src/cover.rs` | 覆盖范围 | 范围覆盖、
区间关系等辅助逻辑 |
| `src/prettyprint.rs` | 输出辅助 | 格式化输出相关基础设施 |
| `src/printlanguage.rs
` | 输出语言层 | 输出语言抽象层 |
| `src/printc.rs` | C 风格输出
 | C 代码风格输出的主要实现
位置 |
| `src/action.rs` | Action 框
架 | 分析/优化动作的抽象与调度 |
|
 `src/coreaction.rs` | 核心动作 | 核心分析动作集合 |
| `src
/ruleaction.rs` | 规则动作 | 规则
级变换与应用 |
| `src/blockaction.rs` | 块级动作 | 面向控制流块的处理动作 |
| `src/types.rs` | 通
用类型 | 架构等全局通用类型定义 |
| `src/error.rs` | 错误类型 | 项目错误定义与错误包装 |
| `src/utils.rs` | 工具函数 | 杂项工具能力 |

### 3.2 子目录模块

#### `src/type_system/`
类型系统相关子模块目录。

| 路径 | 说明 |
|------|------|
| `src/type_system/mod.rs` | 类型系统模块入口 |
| `src/type_system/datatype.rs` | 数据类型定义 |
| `src/type_system/typefactory.rs` | 类型工厂/构造支持 |
| `src/type_system/cast.rs` | 类型转换相关逻辑 |

#### `src/binary/`
二进制解析相关模块目录。

| 路径 | 说明 |
|------|------|
| `src/binary/mod
.rs` | 二进制解析模块入口 |

> 当前二进制相关实现存在，但其能力边界应以实际代码和
测试为准，不应仅
根据旧文档宣称“完整生产可用”。

#### `src/disasm/`
反汇编与提升相关目录。

| 路径 | 说明 |
|------|------|
| `src/disasm/mod.rs` | 反汇编模块入口 |
| `src/disasm/x86_64.rs` | x86-64 反汇编相关实现 |
| `src/disasm/x86_lift.rs` | x86 指令提升
/语义转换相关实现 |

#### `src/align/`
与 Ghidra 对齐验证直接相关的目录。

| 路
径 | 说明 |
|------|------|
| `src/align/mod.rs` | 对齐模块入口 |
| `src/align/address.rs` | 地址
类对齐验证 |
| `src/align/action.rs` | Action
 相关对齐 |
| `src/align/block.rs` | 控制流块结构对齐 |
| `src/align/datatype.rs` | 类型系统对
齐 |
| `src/align/heritage.rs` | SSA / heritage 对齐 |
| `src/align/pcode
op.rs` | PcodeOp 对齐 |
| `src/align/range.rs` | 范围对象对齐 |
| `src/align/runtime_verify.rs` | 运行时对比/验证框架 |
| `src/align/varnode.rs` | Varnode 对
齐 |

#### `src/bin/`
命令行程序
入口目录。

| 路径 | 说明 |
|------|
------|
| `src/bin/rudra.rs` | CLI 主入口 |

> 当前代码中 CLI 入口仅输出“暂时禁用/对齐中”的提示，因此
**不能把本项目描述为一个已完整开放的
命令行反编译产品**。

---

## 4. 当前实现状态说明


为了避免文档失真，这里只写当前能从代码结构中
稳妥得出的结论。

### 4.1 可以确认的事实

-
 工程是一个 Rust crate，`Cargo.toml` 存在且结构完整
- `src/lib.rs` 暴露了大量 Ghidra 风格核心模块
- 已存在二进制解析、反汇编、P-code、SSA、打印输出、FFI、对齐验证等实现骨架或部分实现
- `examples/
`、`tests/`、`benches/`、
`docs/` 都已建立
- `src/align/` 显示项目明确在做与 Ghidra 的对齐工作
- `src/bin/rudra.rs` 当前 CLI 明确处于临时不可用/禁用状态

### 4.2 不应再继续写入既成事实的说法

以下说法如果没有新的代码、测试和验证依据，不应在文档中写成“已完成”：

- “已经与 Ghidra 100% 一致”
- “所有运行时
验证已完成”
- “端到端输出质量已达到 Ghidra 水平”
- “
CLI 已完整可用”
- “analysis/、pcode/、codegen/、translator/ 已按旧目录结构存在并稳定运行”
- “自动文档生成可以 1:1 准确覆盖全部接口”

---

## 5. 示例、测试与基准
目录

### 5
.1 `examples/`

该目录用于放置可执行示例，帮助理解当前能力边界和
调试路径。

常见用途
包括：

- 反编译演示
- 反汇编
演示
- CFG / 调试输出
- 针对真实二进制
（如 `curl`）的实验代码

> 示例代码是了解“当前项目到底能跑到哪一步”的重要入口，但示例能跑通不等于整个产品已经稳定可交付。

### 5.2 `tests/`

用于集成测试、行为验证和回归测试。

文档中不应简单把“存在 tests 目录”解释成“所有核心路径都已有充分测试覆盖”；  
测试覆盖情况应基于实际测试文件、测试结果和 CI 现状单独评估。

### 5.3 `benches/`

当前用于基准测试和性能评估。

---

## 6. 文档系统索引（`docs/`）

`docs/` 是本项目的文档总入口。  
后续新增文档、修复文档失真、沉淀研发记录时，应优先放入这里的正确子目录，而不是散落在项目根目录。

### 6.1 总控文档

| 路径 | 说明 |
|------|------|
| `docs/PROJECT_STRUCTURE.md` | 本文档；项目结构与文档索引总览 |
| `docs/TODO_BOARD.md` | 任务看板，跟踪未完成事项 |
| `docs/VERIFICATION_GUIDE.md` | 对齐/验证相关说明 |
| `docs/data_contract.md` | 数据接口契约，当前仍需继续补完 |

### 6.2 会话与进度记录

| 路径 | 说明 |
|------|------|
| `docs/archive/agentlog/` | AI / 工程
会话日志目录 |
| `docs/archive/agentlog/TEMPLATE.md` | 会话日志模板 |

###
 6.3 API 文档

| 路径 | 说明 |
|------|------|
| `docs/api/` | 与源码
接口相关的参考文档目录 |
| `docs/api/README.md` | API 文档入口说明 |

> 注意：当前 `docs/api/` 中存在与真实源码结构不完全一致的旧描述，需要逐步校正。  
> API 文档应以 `src/
` 实际模块为准，不应继续沿用过时的“analysis/codegen/pcode/translator 全量稳定目录映射”表述。

### 6.4 对齐与参考
材料


| 路径 | 说明 |
|------|------|
| `docs/alignment_docs/` | 更细粒度的对齐说明、映射规则、验证材料 |
| `docs/src_ref/` | 源码参考类文档 |

### 6.
5 工作流与规范


| 路径 | 说明 |
|------|------|
| `docs/workflow/` | 开发工作流说明目录 |
| `docs/workflow/TEMPLATE.md` | 工作流模板 |

### 6.6 其他专题目录

| 路径 | 说明 |
|------|------|
| `docs/decisions/` | 架构决策记录 |
| `docs/experiments/` | 实验文档目录 |
| `docs/method/` | 方法论沉淀 |
| `docs/method/impl/` | 方法实现细节 |
| `docs/branches/` | 分支状态记录 |

---

## 7. 结果与产物目录

### `result/`

用于存放运行结果、实验输出、生成物或对比结果。

文档、脚本、临
时调试产物不应随意堆放到项目根目录；  
如果属于输出结果，应优先归档到 `result/` 或其子目录。

---

## 8. 辅助与外部参考目录

### `tools/
`
放置工程辅助脚本，例如：

- 文档修复辅助
- API 文档辅助
- 验证配套脚本

- 其他自动化开发工具

### `ghidra/`
该目录包含仓库内置的 Ghidra 相关内容。  
它可
用于：

- 源码对照
- 对齐参考
- 验证环境辅助
-
 相关配套材料

但它**不是** `rudra` 自身源码的一部分，不应把其中的类或结构误写
为 Rudra 当前已实现模块。

---

## 9. 当前推荐阅读顺序

如果你第一次进入这个项目，推荐按以下顺序阅读：

1. `README.md
`  
   先了解项目定位与总体目标
。

2. `AGENTS.md`  
   了解本项目对 AI / 工程协作的规范要求。

3. `docs/PROJECT_STRUCTURE.md`  
   通过本文掌握目录结构和文档入口。

4. `CURRENT_STATUS.md`  
   看当前状态评估，但要注意核对是否存在夸大或过时结论。

5. `GAP_ANALYSIS.md`  
   看与目标状态、与 Ghidra 对比的差距。

6. `ALIGNMENT_PROGRESS.md`  
   了解哪些对齐工作只是静态完成，哪些仍缺运行时验证。

7. `docs/TODO_BOARD.md`  
   找到下一步待做事项。

8. `src/lib.rs`  
   从库入口观察当前真实公开模块。

9. `src/funcdata.rs`、`src/op.rs`、`src/varnode.rs`、`src/printc.rs`  
   进一步理解函数分析对象、P-code 对象和输出链路。

---

## 10. 文档维护原则

为了避免继续失真，后续维护本文档时必须遵守以下原则：

### 10.1 只写“看得见、能核实”的结构
如果目录、文件、模块实际不存在，就不要写进结构图。

### 10.2 区分“已有文件”和“能力完整”
存在某个 `.rs` 文件，不等于对应能力已经完整、稳定、生产可用。

### 10.3 区分“静态对齐”和“运行时一致”
字段、类型、接口名字对齐，不等于运行时行为已经与 Ghidra 一致。

### 10.4 文档索引必须能导航
本文档应始终回答两个问题：

- “代码在哪？”
- “文档在哪？”

### 10.5 结构变化必须同步更新本文
发生以下任一情况时，应同步更新本文件：

- 新增、删除、重命名 `src/` 模块
- 新增、删除、重命名 `docs/` 下的总控或专题文档
- 新增/删除 CLI、examples、tests、tools 的关键入口
- 项目实际主目录结构发生变化

---

## 11. 简版结构图

下面
给出一个与当前实际项目状态相符的简版结构图：

```text
rudra/
├─ Cargo.toml
├─ README.md
├─ AGENTS.md
├─ CURRENT_STATUS.md
├─ GAP_ANALYSIS.md
├─ ALIGNMENT_PROGRESS.md
├─ benches/
├─ examples/

├─ tests/
├─ tools/
├─ result/
├─ docs/
│  ├─ PROJECT_STRUCTURE.md
│  ├─ TODO_BOARD.md
│  ├─ VERIFICATION_GUIDE.md
│  ├─ data_contract.md
│  ├─ AgentLog/
│  ├─ api/
│  ├─ alignment
_docs/
│  ├─ workflow/
│  ├─ decisions/
│  ├─ experiments/
│  ├─ method
/
│  ├─ branches/
│  └─ src_ref/
└
─ src/
   ├─ lib.rs
   ├─ action.rs
   ├─ address.rs
   ├─ block.rs
   ├─ blockaction.rs

   ├─ coreaction.rs

   ├─ cover.rs
   ├─ error.rs
   ├─ ffi.rs
   ├─ fspec.rs
   ├─ funcdata.rs
   ├─ heritage.rs
   ├─ merge.rs
   ├
─ op.rs
   ├─ opcodes.rs
   ├─ pcoderaw.rs
   ├─ prettyprint.rs
   ├─ printc.rs
   ├─ printlanguage.rs
   ├─ ruleaction.rs
   ├─ space.rs
   ├─
 typeop.rs
   ├─ types.rs
   ├─ utils.rs
   ├
─ variable.rs
   ├─ varnode.rs
   ├
─ align/
   ├
─ bin/
   ├─ binary/
   ├─ disasm
/
   └─ type_system/
```

---

## 12. 结语

本文档的目标不是“把项目写得更厉害”，而
是
把项目**写得更真实、可
导航、可维护**。  
如果你发现
本文仍与代码现状不符，请优先修正文档，并在相关日志中记录
修正原因。