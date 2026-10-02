# `mov rbx, rax` 首条真实运行记录填写清单

本文档用于把 **`mov rbx, rax`** 这条最小 P-code 对拍样本，从“样本草案”推进成**第一条真实运行记录**。  
它不是最终报告模板，而是一份**按步骤执行、按步骤填写**的清单。

> 目标：  
> 让这条样本至少完成一次从：
>
> `Instruction -> X86Lifter::lift(...) -> Vec<PcodeOpRaw> -> Funcdata::inject_raw_ops(...) -> verify_pcode_generation(...)`
>
> 的真实记录。

---

## 0. 样本基本信息

- **样本 ID**: `PCode-Min-001`
- **目标层级**: `P-code`
- **目标指令**: `mov rbx, rax`
- **原始字节**:

```/dev/null/sample.bin#L1-1
48 89 c3
```

- **预期汇编文本**:

```/dev/null/sample.asm#L1-1
mov rbx, rax
```

---

## 1. 开始前先确认的事情

在真正填写运行记录前，先逐项确认：

- [ ] 当前记录目标是**最小局部对拍**，不是端到端输出质量
- [ ] 当前记录目标是**形成第一条真实样本记录**
- [ ] 当前不把“未运行”写成“已通过”
- [ ] 当前不把“入口存在”写成“已完成一致性验证”
- [ ] 当前允许结果是：
  - [ ] 已拿到 `Instruction`
  - [ ] 已拿到 `PcodeOpRaw`
  - [ ] 已完成 `inject_raw_ops(...)`
  - [ ] 已进入比较入口
  - [ ] 已发现 mismatch
  - [ ] 当前比较粒度仍不足
- [ ] 当前不要求立刻得到“与 Ghidra 完全一致”

---

## 2. 真实运行记录主表

后续填写时，先把这一小节补完整。

### 2.1 元信息
- **执行日期**:
- **执行人 / 会话**:
- **当前分支 / 工作状态**:
- **记录状态**:
  - [ ] 待执行
  - [ ] 执行中
  - [ ] 已完成第一轮记录
  - [ ] 已归档

### 2.2 本次目标
- [ ] 先拿到正确 `Instruction`
- [ ] 先拿到正确 `PcodeOpRaw`
- [ ] 先拿到注入后的 op 数量
- [ ] 先确认比较入口是否被调用
- [ ] 先得到第一条真实差异分类
- [ ] 其他：

---

## 3. Step 1：记录 `Instruction` 层结果

### 3.1 需要确认的最小事实
你应至少确认并填写：

- **mnemonic**:
- **instruction text**:
- **instruction length**:
- **operand count**:
- **operand0**:
- **operand1**:
- **is_branch**:
- **is_call**:
- **is_return**:

### 3.2 当前合格标准
本层只要满足以下条件，就算通过本步：

- [ ] `mnemonic = "mov"`
- [ ] 操作数数量为 `2`
- [ ] `operand0` 是 `rbx`
- [ ] `operand1` 是 `rax`
- [ ] 不是 branch / call / return

### 3.3 记录区
```/dev/null/mov_rbx_rax_instruction_record.txt#L1-40
mnemonic:
text:
length:
operand_count:
operand0:
operand1:
is_branch:
is_call:
is_return:
notes:
```

### 3.4 如果这一步失败，先查哪里
优先排查：

1. 指令字节是否正确
2. 反汇编是否按 64-bit 模式进行
3. 文本格式是否只是显示差异，而不是操作数语义错误
4. 操作数顺序是否被误解

---

## 4. Step 2：记录 `PcodeOpRaw` 层结果

### 4.1 需要确认的最小事实
至少填写：

- **raw op 数量**:
- **raw opcode 列表**:
- **第 1 条 raw op 的 output**:
- **第 1 条 raw op 的 input0**:
- **是否存在核心 `CPUI_COPY`**:

### 4.2 当前合格标准
本层只要满足以下条件，就算通过本步：

- [ ] raw op 数量大于 0
- [ ] 至少存在一条核心 `CPUI_COPY`
- [ ] 输出看起来对应 `rbx`
- [ ] 输入看起来对应 `rax`

### 4.3 记录区
```/dev/null/mov_rbx_rax_raw_pcode_record.txt#L1-80
raw_op_count:
raw_opcodes:
op0_opcode:
op0_output:
op0_input0:
all_raw_ops:
notes:
```

### 4.4 如果这一步失败，先查哪里
优先排查：

1. `mov` 分支是否真的走到了复制路径
2. 操作数方向是否被写反
3. 寄存器映射是否偏了
4. raw op 不是 `COPY` 而是别的 opcode

---

## 5. Step 3：记录 `inject_raw_ops(...)` 后结果

### 5.1 需要确认的最小事实
至少填写：

- **injected op 数量**:
- **block 数量**:
- **首条 injected op opcode**:
- **首条 injected op output 摘要**:
- **首条 injected op input 摘要**:

### 5.2 当前合格标准
本层只要满足以下条件，就算通过本步：

- [ ] injected op 数量大于 0
- [ ] block 数量为最小单块，或至少没有异常切分
- [ ] 首条或核心 op 仍可识别为 `COPY`
- [ ] 输出仍能对应 `rbx`
- [ ] 输入仍能对应 `rax`

### 5.3 记录区
```/dev/null/mov_rbx_rax_injected_record.txt#L1-100
injected_op_count:
basic_block_count:
first_op_opcode:
first_op_output:
first_op_inputs:
all_injected_ops_summary:
notes:
```

### 5.4 如果这一步失败，先查哪里
优先排查：

1. raw op 注入时 opcode 转换是否失败
2. output / input 绑定是否丢失
3. 寄存器 varnode 是否在注入后变了
4. 是否引入不必要的噪声 op
5. block 构建是否错误切分了最小单指令样本

---

## 6. Step 4：记录比较入口结果

### 6.1 需要确认的最小事实
至少填写：

- **比较入口是否被调用**:
- **返回类型**:
  - [ ] Match
  - [ ] Mismatch
  - [ ] GhidraError
  - [ ] RudraError
  - [ ] 当前无法判断
- **当前比较粒度**:
  - [ ] 计数级
  - [ ] opcode 级
  - [ ] 输入输出级
  - [ ] 其他：
- **是否产生 mismatch 记录**:
- **mismatch 摘要**:

### 6.2 当前合格标准
当前阶段本步的合格标准不是“必须 Match”，而是：

- [ ] 比较入口被真实调用
- [ ] 能得到明确结果类型
- [ ] 即使是 mismatch，也能形成可记录信息
- [ ] 如果只是计数级比较，也能明确写出来

### 6.3 记录区
```/dev/null/mov_rbx_rax_compare_record.txt#L1-80
compare_entry_called:
result_type:
compare_granularity:
mismatch_exists:
mismatch_summary:
stats_if_any:
notes:
```

### 6.4 如果这一步失败，先查哪里
优先排查：

1. 当前程序状态是否已正确准备
2. 比较入口是不是只存在但未形成有效数据输入
3. 是否只是参考侧结果尚未接通
4. 是否只是当前比较粒度还不足，而不是 lifting 本身错误

---

## 7. 差异分类填写规则

如果本条样本没有完全通过，请务必给出**最小差异分类**，不要只写“失败”。

可用分类：

- [ ] `Instruction 层错误`
- [ ] `raw opcode 错误`
- [ ] `输入顺序差异`
- [ ] `输出 varnode 差异`
- [ ] `寄存器映射差异`
- [ ] `注入后结构变化`
- [ ] `block 切分异常`
- [ ] `比较入口已调用，但粒度不足`
- [ ] `参考侧结果尚未形成`
- [ ] `其他`

### 差异详情记录区
```/dev/null/mov_rbx_rax_diff_record.txt#L1-80
diff_category:
diff_details:
first_layer_where_diff_appeared:
suspected_root_cause:
```

---

## 8. 当前结论写法约束

### 8.1 可以写的
- `已拿到第一条真实样本记录`
- `已形成第一条最小可复现 P-code 样本`
- `当前样本已进入比较入口`
- `当前样本已发现 mismatch`
- `当前样本的比较粒度仍不足`
- `当前样本已足够作为下一轮修复锚点`

### 8.2 不能写的
- `已经与 Ghidra 完全一致`
- `P-code 已完成对齐`
- `该路径已稳定通过`
- `端到端对齐已恢复`
- `只凭这一条样本就说明整体没问题`

---

## 9. 第一条样本的最小成功标准

请在填写完成后，用下面标准判断这条记录是否算“首条真实样本已落地”：

- [ ] 已固定输入字节
- [ ] 已记录 `Instruction` 摘要
- [ ] 已记录 raw op 数量 / opcode
- [ ] 已记录 injected op 数量
- [ ] 已说明比较入口是否被调用
- [ ] 已给出当前结果类型
- [ ] 已给出差异分类或明确说明当前粒度不足
- [ ] 已给出下一步最小动作

> 只要上面这些都具备，  
> 即使结果不是 `Match`，  
> 这条样本也已经可以算作：**第一条真实运行记录已成立**。

---

## 10. 填写完成后的下一步

当 `mov rbx, rax` 这条记录成型后，建议按以下顺序继续：

1. `add rax, 1`
2. `sub rax, 8`
3. `and/or/xor`
4. `shl/shr/sar`

理由：

- 先把最小复制路径跑稳
- 再把最小算术路径跑稳
- 再进入逻辑和移位
- 最后才碰 memory / jcc

---

## 11. 一句话提醒

当前这条 `mov rbx, rax` 样本的核心目标不是“证明已经对齐”，而是：

> **先把 Rudra 的最小 P-code 对拍真正变成一条可复现、可记录、可定位差异的真实样本记录。**