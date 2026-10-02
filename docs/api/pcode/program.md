# `pcode/program.rs` API Reference（历史 Program 架构说明）

**文档路径**: `docs/api/pcode/program.md`  
**对应旧源码路径**: `src/pcode/program.rs`  
**当前状态**: ⚠️ **历史遗留文档，仅作为旧版 `Program` 架构参考，不应视为当前主干 API 入口**

---

## 1. 文档定位

本文档用于说明 Rudra 旧版 `Program` 容器在项目历史中的角色、边界与当前参考价值。

它的作用是帮助读者理解：

- 早期 Rudra
 如何组织一组 P-code 操作
- 为什么项目曾经需要 `Program` 这样的中间容器
- 为什么今天仍保留这份说明
- 为什么现在不能再把它当作当前主线架构的权威入口

这份文档**不是**当前主干实现状态的直接说明书。

---

## 2. 一句话结论

`Program` 应被理解为：

> **Rudra 早期围绕 P-code 操作集合组织分析流程时使用的旧版中间容器。它对理解项目历史和旧设计有参考价值，但当前主线已经不再应以它作为核心函数分析入口。**

---

## 3. 历史背景

在较早阶段，Rudra 更明显地采用了一种“先生成 P-code 程序容器，再基于该容器做分析和输出”的组织方式。

在这套设计下：

- 机器码先被反汇编
- 再翻译为一组 P-code 操作
- 这些操作被放入 `Program`
- 后续分析、优化、打印围绕 `Program` 展开

因此，`Program` 的历史定位可以概括为：

- 一组 P-code 操作的集中容器
- 旧版分析管线的输入对象
- 旧版唯一 ID 与入口地址管理位置
- 从翻译层到分析层的桥接对象

---

## 4. 为什么它现在被标记为“历史架构”

结合当前项目的文档基线和现有源码主线，Rudra 已经更明显地转向以下组织方式：

- 用 `Funcdata` 表示单函数分析上下文

- 用 `PcodeOp` / `Varnode` / block 图直接承载函数级 IR
- 用 `Heritage` 和 `ActionDatabase` 驱动后续变换
- 用 `PrintLanguage` / `PrintC` 组织输出层
- 用 `align/` 下的模块逐步做 Ghidra 对齐

因此，当前更贴近真实主线的理解是：

```text
PcodeOpRaw
  -> Funcdata
  -> PcodeOp / Varnode / Block
  -> Heritage / Actions
  -> PrintLanguage / PrintC
```

而不是：

```text
Program
  -> analysis
  -> codegen
```

这也是为什么 `Program` 文档现在必须显式标记为“历史参考”。

---

## 5. `Program` 的历史职责

从旧架构角度看，`Program` 一般承担以下职责：

### 5.1 保存操作集合
集中管理一批 P-code 操作，而不是让它们散落在多个局部结构中。

### 5.2 维护唯一标识或顺序信息
为操作分配或维护唯一 ID、顺序或入口信息，便于查找和遍历。

### 5.3 作为分析输入对象
让旧版的分析流程可以直接接收一个统一容器，而不是在函数级上下文中处理更复杂的对象网络。

### 5.4 作为打印前的中间载体
在旧设计下，它也常常是输出前的重要中间阶段。

---

## 6. 这类设计曾经为什么合理

从工程演化角度看，`Program` 架构并不是“错误设计”，它在早期通常有这些优点：

- 容易快速搭建原型
- 容易集中管理 P-code 序列
- 对从指令翻译到分析过渡比较直接
- 对简单分析流程比较友好
- 在工程还未演化出完整函数级上下文时，便于快速推进

但随着 Rudra 向更接近 Ghidra 的对象模型收敛，这种设计的局限逐渐显现，例如：

- 不够自然地承载函数级全局上下文
- 与 block / SSA / heritage / action 深度联动时不够灵活
- 不如 `Funcdata` 那样贴近 Ghidra 的主对象语义
- 容易让“操作集合”成为主语义中心，而不是“函数分析上下文”成为中心

---

## 7. 当前阅读这份文档时的正确姿势

### 可以把它当作
- 历史架构说明
- 旧版 API 的参考
- 理解项目演化路径的材料
- 帮助识别旧文档为什么会提到 `Program`

### 不应把它当作
- 当前函数分析主入口
- 当前最推荐的中间容器
- 当前主线 API 总览
- 当前端到端反编译流程的事实描述
- 当前 README 示例应直接调用的对象

---

## 8. 如果你在旧文档里看到 `Program`

后续阅读其他历史文档时，如果你看到如下叙述：

- `Program` 持有所有 P-code 操作
- 分析函数接受 `Program`
- 代码生成接受 `Program`
- `Program` 是当前核心容器

请优先理解为：

> **这反映的是 Rudra 旧版分层思路，而不是当前主干架构现状。**

这类描述通常需要回到当前主线文档重新校准，建议对照：

- `docs/api/lib.md`
- `docs/api/funcdata.md`
- `docs/api/op.md`
- `docs/api/varnode.md`
- `docs/api/block.md`
- `docs/api/heritage.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`

---

## 9. 与当前主线的替代关系

当前更应优先关注的替代对象与模块包括：

### 9.1 `Funcdata`
当前函数级总容器，承接 raw p-code 注入、block/CFG、heritage、action 与输出链路。

### 9.2 `PcodeOp`
当前正式进入图结构的操作节点。

### 9.3 `Varnode`
当前 storage-node / data-node 模型，是输入输出与 SSA 附着点。

### 9.4 `BlockBasic` / `BlockGraph`
当前控制流结构的重要承载体。

### 9.5 `ActionDatabase`
当前分析与变换流水线的重要组织方式。

### 9.6 `PrintLanguage` / `PrintC`
当前输出层主线。

因此，如果你的目标是理解 Rudra **现在怎么工作**，应优先阅读这些对象，而不是从 `Program` 出发。

---

## 10. `Program` 文档当前应使用的口径

为了避免文档继续失真，后续引用 `Program` 时建议使用以下说法。

### 推荐表述
- “`Program` 是 Rudra 旧版 P-code 容器”
- “该对象属于历史 Program 架构的一部分”
- “当前主线已更多围绕 `Funcdata` 组织”
- “本文件仅保留历史参考价值”

### 不推荐表述
- “`Program` 是当前主分析容器”
- “当前函数分析仍主要围绕 `Program` 展开”
- “当前所有代码生成仍以 `Program` 为输入”
- “`Program` 可以代表当前 Rudra 的主线 IR 架构”

---

## 11. 如果未来发生变化

如果未来项目又重新引入一个正式、稳定、未注释、可测试的 `Program` 主对象，并明确回到类似架构，那么本文档应被重写为“当前 API 说明”。

但在当前阶段，这份文档应始终维持：

- **历史说明**
- **低承诺**
- **不夸大**
- **不替当前主线背书**

---

## 12. 推荐联动阅读

为了避免误用 `Program` 文档，建议同时阅读：

1. `docs/api/lib.md`
2. `docs/api/funcdata.md`
3. `docs/api/op.md`
4. `docs/api/varnode.md`
5. `docs/api/pcoderaw.md`
6. `docs/api/block.md`
7. `docs/api/heritage.md`
8. `docs/PROJECT_STRUCTURE.md`
9. `CURRENT_STATUS.md`

---

## 13. 最终结论

`docs/api/pcode/program.md` 当前应被视为：

> **对 Rudra 旧版 `Program` 式 P-code 容器架构的保留说明。它有助于理解历史设计与旧文档，但不能继续被当成当前主干架构、当前主容器或当前稳定 API 的权威入口。**
