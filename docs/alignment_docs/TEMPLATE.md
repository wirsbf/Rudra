# 规范模板：Ghidra 对齐规则说明 (Alignment Rules Template)

**[状态]**: 🔴 TODO / 🟡 WIP (进行中) / 🟢 DONE (已对齐)  
**[目标模块]**: (如：x86_64 寄存器映射，或者 PcodeOp::INT_ADD 的翻译规则)  
**[关联 Ghidra 源码位置]**: (如：`Ghidra/Features/Decompiler/src/decompile/cpp/translate.cc:150`)  
**[关联 Rudra 源码位置]**: (如：`src/translator/x86_64.rs`)  

---

## 1. 目标描述 (Description)

> 描述需要对齐的具体规则或机制。为何要在 Rudra 中进行特别处理？

（请在此处填入：该机制的背景、在反编译中起到的作用等）

## 2. Ghidra 的实现逻辑 (Ghidra Implementation)

> 此处提取 Ghidra C++ 源码中关于此逻辑的核心算法、特判机制或数据结构。
> （必须包含代码路径和核心分支逻辑）

- **数据结构**: 
- **核心算法/特判**:

## 3. Rudra 的对齐方案 (Rudra Approach)

> 描述在 Rust 端我们是如何（或计划如何）等价实现这一套规则的。如果因为语言特性有所舍弃或调整，请指明偏差。

- [ ] **TODO: 步骤 1** (如：在 `x86_64.rs` 中建表映射所有寻址寄存器)
- [ ] **TODO: 步骤 2** (如：处理特殊的 REX 前缀对于变元分配大小的影响)
- [ ] **TODO: 测试验证** (如：利用 `tests/align/` 下的数据断言生成结果与 Ghidra 输出的 XML 完全一致)

## 4. 差异与风险 (Discrepancies & Risks)

> 如果遇到由于基础设施不足暂时无法做到 100% 一致的地方，必须记录在此。

- **已知差异**:
- **潜在风险**:
