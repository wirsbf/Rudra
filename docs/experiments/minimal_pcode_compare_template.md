# 最小 P-code 对拍记录模板

本文档用于记录 **Rudra ↔ Ghidra** 的最小 P-code 局部对拍结果。  
目标不是一次性描述整个反编译流程，而是把**单条指令**或**极短指令序列**的对拍结果记录清楚，形成可复现、可追踪、可积累的最小证据链。

> **使用范围**
>
> 本模板适用于：
>
> - 单条指令的 lifting / raw p-code 对拍
> - 极短指令序列的 raw p-code / injected op 对拍
> - 后续逐步扩展到 SSA / CFG 前的基础行为验证
>
> 本模板**不适用于**：
>
> - 大样本端到端输出质量报告
> - 最终 C 输出风格比较
> - 没有明确输入样本和可复现步骤的主观观察记录

---

## 1. 记录元信息

- **记录标题**：
- **日期**：
- **记录人 / 会话**：
- **验证层级**：
  - [ ] Level A：静态结构对齐
  - [ ] Level B：运行时局部对拍
  - [ ] Level C：端到端语义验证
- **当前状态**：
  - [ ] 待运行
  - [ ] 已运行
  - [ ] 已比对
  - [ ] 已归档
- **是否为最小样本**：
  - [ ] 是
  - [ ] 否

---

## 2. 对拍目标

### 2.1 目标类型
- [ ] 单条指令
- [ ] 极短指令序列
- [ ] 小函数片段

### 2.2 指令 / 序列说明
填写要验证的对象，例如：

- `mov rbx, rax`
- `add rax, 1`
- `sub rax, 8`
- `and rax, rbx`
- `shl rax, 1`
- `mov rax, [rbx]`
- `mov [rbx], rax`

### 2.3 为什么选择这个样本
说明原因，例如：

- 对应最基础的 `COPY`
- 可验证常量输入组织
- 可验证算术 opcode 映射
- 可验证 shift 语义
- 可验证最小 memory load/store 路径
- 可验证 `Funcdata::inject_raw_ops(...)` 的稳定性

---

## 3. 输入样本

### 3.1 架构
- `x86-64`

### 3.2 原始字节
填写机器码字节，例如：

```/dev/null/minimal_pcode_compare_template.bin#L1-1
48 89 c3
```

### 3.3 文本形式
例如：

```/dev/null/minimal_pcode_compare_template.asm#L1-1
mov rbx, rax
```

### 3.4 地址上下文
- **起始地址**：
- **是否依赖上下文寄存器状态**：
  - [ ] 否
  - [ ] 是，说明如下：

### 3.5 若为序列，完整序列如下
```/dev/null/minimal_pcode_compare_template.asm#L1-3
mov rax, rbx
add rax, 1
sub rax, 2
```

---

## 4. Rudra 侧执行路径

### 4.1 入口链路
按当前主线，通常应填写：

- `disasm::Instruction`
- `disasm::x86_lift::X86Lifter::lift(...)`
- `pcoderaw::PcodeOpRaw`
- `funcdata::Funcdata::inject_raw_ops(...)`
- `align::runtime_verify::verify_pcode_generation(...)`

### 4.2 相关代码文件
- `src/disasm/mod.rs`
- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`
- `src/align/runtime_verify.rs`
- `src/ffi.rs`

### 4.3 实际执行备注
记录本次实际走到哪一步，例如：

- [ ] 已完成指令解析
- [ ] 已完成 raw p-code 生成
- [ ] 已完成 `Funcdata` 注入
- [ ] 已进入局部比较入口
- [ ] 已记录 mismatch / match

---

## 5. Ghidra / 参考侧比较入口

### 5.1 参考来源
- [ ] Ghidra 原生结果
- [ ] Ghidra FFI 对拍入口
- [ ] 手工参考输出
- [ ] 其他参考实现

### 5.2 相关比较入口
可填写：

- `rudra_compare_pcode(...)`
- `runtime_verify::verify_pcode_generation(...)`
- 其他：

### 5.3 当前参考结果获取方式
说明是：

- 已真实运行得到
- 部分真实运行
- 手工构造占位
- 当前尚未稳定获取

---

## 6. Rudra 结果记录

### 6.1 Disasm 结果
```/dev/null/minimal_pcode_compare_template.txt#L1-20
(在这里填写 Rudra 解析出的 Instruction / operands 摘要)
```

### 6.2 Raw P-code 结果
```/dev/null/minimal_pcode_compare_template.txt#L21-60
(在这里填写 PcodeOpRaw 序列)
```

### 6.3 Injected Op 结果
```/dev/null/minimal_pcode_compare_template.txt#L61-120
(在这里填写 inject_raw_ops(...) 后的 op / varnode / block 摘要)
```

### 6.4 统计信息
- **raw op 数量**：
- **injected op 数量**：
- **是否出现 block 切分**：
- **是否出现 control-flow terminator**：

---

## 7. 参考结果记录

### 7.1 参考侧结果
```/dev/null/minimal_pcode_compare_template.txt#L121-180
(在这里填写 Ghidra / 参考实现结果)
```

### 7.2 参考结果来源说明
- [ ] 真实运行得到
- [ ] 来自已有对拍框架
- [ ] 手工记录
- [ ] 暂缺，仅记录预期

---

## 8. 差异对比

### 8.1 是否一致
- [ ] 完全一致
- [ ] 部分一致
- [ ] 不一致
- [ ] 当前无法判断

### 8.2 差异类别
可多选：

- [ ] opcode 不一致
- [ ] raw op 数量不一致
- [ ] 输入顺序不一致
- [ ] 输出 varnode 不一致
- [ ] 常量组织方式不一致
- [ ] 地址空间 / offset 不一致
- [ ] block 切分不一致
- [ ] 当前只是入口跑通，尚未形成有效逐项比较
- [ ] 其他：

### 8.3 差异详情
```/dev/null/minimal_pcode_compare_template.txt#L181-260
(在这里详细写 mismatch 内容)
```

---

## 9. 当前结论

请尽量使用以下口径之一：

- `已具备最小比较入口，但尚未形成稳定结果`
- `当前样本在 raw p-code 数量上已对齐，细节仍待比较`
- `当前样本已发现 opcode 映射差异`
- `当前样本已发现输入/输出组织差异`
- `当前样本可稳定复现，是下一轮修复的有效锚点`
- `当前样本尚不能构成有效对拍证据`

### 9.1 结论
- 

### 9.2 证据来源
至少填写一类：

- 源码：
- 测试 / 示例：
- 对拍入口：
- 日志 / 实验记录：

---

## 10. 下一步动作

### 10.1 最小修复目标
例如：

- 修正某条指令的 opcode 映射
- 修正立即数在 `Const` 空间的组织方式
- 修正 `inject_raw_ops(...)` 后的输出绑定
- 让 `verify_pcode_generation(...)` 产出更有意义的比较结果

### 10.2 下一轮优先级
- [ ] 继续同一样本
- [ ] 扩展到同类指令
- [ ] 进入下一类指令
- [ ] 暂停，等待框架补齐

---

## 11. 填写示例（可删）

下面给出一个最小示例，帮助后续快速上手。

### 示例：`mov rbx, rax`

- **目标类型**：单条指令
- **原始字节**：
```/dev/null/example.bin#L1-1
48 89 c3
```
- **文本形式**：
```/dev/null/example.asm#L1-1
mov rbx, rax
```
- **预期观察点**：
  - 是否生成单条 `CPUI_COPY`
  - 输入寄存器是否为 `rax`
  - 输出寄存器是否为 `rbx`
- **Rudra 侧入口链路**：
  - `Instruction`
  - `X86Lifter::lift(...)`
  - `PcodeOpRaw`
  - `Funcdata::inject_raw_ops(...)`
  - `verify_pcode_generation(...)`
- **可能结论写法**：
  - `当前样本适合作为最小 COPY 路径对拍锚点；若产生差异，应优先检查寄存器映射与 raw op 注入逻辑。`

---

## 12. 最终原则

这个模板的目标不是“把实验写得很像完成报告”，而是帮助你把每一次最小对拍都记录成：

1. **可复现**
2. **可定位**
3. **可积累**
4. **可回链**

只有这样，Rudra 后续恢复对齐 Ghidra 的工作，才会从“看起来在做”变成“真的在逐步收敛”。