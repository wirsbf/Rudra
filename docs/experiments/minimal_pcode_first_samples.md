# 最小 P-code 首批样本记录草案

本文档用于为 Rudra 恢复 Ghidra 对齐工作的第一批**最小 P-code 局部对拍样本**建立统一记录模板，并先给出 3 条样本的草案。

这些样本的目标不是直接证明端到端一致性，而是优先验证以下最小闭环：

`Instruction -> X86Lifter::lift(...) -> Vec<PcodeOpRaw> -> Funcdata::inject_raw_ops(...) -> verify_pcode_generation(...) -> FFI compare`

---

## 1. 使用原则

### 1.1 本文档的用途
本文档主要用于：

- 固定第一批最小指令样本
- 统一记录格式
- 降低后续“样本跑过了但没人知道具体比了什么”的风险
- 为后续差异归档、回归验证和局部修复提供模板

### 1.2 本文档不代表什么
本文档**不代表**：

- 当前这些样本已经全部跑通
- 当前已经与 Ghidra 达成逐条一致
- 这些记录已经包含真实运行结果
- 当前端到端对齐已恢复完成

当前这些内容应被理解为：

> **第一批最小 P-code 对拍样本的记录草案 / 实验模板**

### 1.3 记录层级
每条样本都应明确当前比较层级，例如：

- `P-code`
- `SSA`
- `CFG`
- `Output`

本文件当前全部样本都属于：

- **P-code 层级**

---

## 2. 建议记录模板

后续新增样本时，建议统一使用以下结构。

### 模板字段

- **样本 ID**
- **优先级**
- **层级**
- **目标指令 / 指令序列**
- **代表性目的**
- **原始字节**
- **预期 Rudra 入口**
- **预期比较入口**
- **当前预期关注点**
- **潜在风险点**
- **当前状态**
- **证据来源**
- **运行结果记录**
- **差异记录**
- **下一步动作**

---

## 3. 首批样本草案

---

## Sample 01: `mov rbx, rax`

- **样本 ID**: `PCode-Min-001`
- **优先级**: 最高
- **层级**: `P-code`
- **目标指令 / 指令序列**: 单条寄存器复制指令
- **代表性目的**:
  - 验证最简单的寄存器到寄存器提升路径
  - 验证 `COPY` 类 raw op 生成
  - 验证输入/输出 varnode 在寄存器空间下的组织
  - 验证注入后 op 数量和顺序是否稳定

### 原始字节
```/dev/null/sample.bin#L1-1
48 89 c3
```

### 首次真实运行记录填写清单
建议你第一次真正落这条样本时，按下面顺序逐项填写，不要跳步：

1. **先补地址**
   - 给本条指令固定一个起始地址，例如 `0x1000`
   - 后续所有记录都围绕同一个地址展开，避免比较时出现“地址不同但语义相同”导致的噪声

2. **先填 `Instruction` 层**
   - 记录：
     - `mnemonic`
     - `length`
     - `operands.len()`
     - operand0
     - operand1
   - 如果这里已经不符合预期，就先不要进入后面的比较

3. **再填 raw p-code 层**
   - 记录：
     - raw op 数量
     - raw op opcode 列表
     - 每条 raw op 的输入/输出摘要
   - 首轮先看是否至少出现一条核心 `CPUI_COPY`

4. **再填 injected op 层**
   - 记录：
     - `inject_raw_ops(...)` 后 op 数量
     - block 数量
     - 核心 injected op 摘要
   - 如果这里出现多余噪声 op，也要如实写下来

5. **最后填比较入口层**
   - 记录：
     - 比较入口是否成功执行
     - 当前返回是 `Match` / `Mismatch(...)` / 还是仅能确认入口已跑通
     - 若有 mismatch，抄下摘要

6. **最后写“下一步动作”**
   - 不要写泛泛结论，直接写最小修复目标，例如：
     - 检查寄存器映射
     - 检查 `COPY` 输入输出方向
     - 检查比较入口粒度

### 汇编文本
```/dev/null/sample.asm#L1-1
mov rbx, rax
```

### 预期 Rudra 入口
- `src/disasm/mod.rs`
  - `Instruction`
  - `Operand`
- `src/disasm/x86_lift.rs`
  - `X86Lifter::lift(...)`
- `src/pcoderaw.rs`
  - `PcodeOpRaw`
  - `VarnodeRaw`
- `src/funcdata.rs`
  - `Funcdata::inject_raw_ops(...)`

### 预期比较入口
- `src/align/runtime_verify.rs`
  - `verify_pcode_generation(...)`
- `src/ffi.rs`
  - `rudra_compare_pcode(...)`

### 当前预期关注点
1. 是否生成单条核心 `CPUI_COPY`
2. 输出 varnode 是否对应 `rbx`
3. 输入 varnode 是否对应 `rax`
4. 寄存器偏移映射是否稳定
5. 注入后 `PcodeOpBank` 中 op 数量是否为最小可接受值

### 预期最小 P-code 观察目标
当前不把这里写成“最终真值”，只写成**首轮应重点观察的目标**：

```/dev/null/sample_pcode_goal.txt#L1-3
opcode: CPUI_COPY
output: register(rbx)
input0: register(rax)
```

### 潜在风险点
- 寄存器名到 offset 的映射是否与预期一致
- 输出 / 输入方向是否被写反
- 注入后是否额外产生不必要 op
- FFI 比较入口当前是否只做计数级比较而非字段级比较

### 当前状态
- **状态**: 第一条真实记录草案（未完成参考侧实测）
- **可信边界**:
  - 当前草案已经把 Rudra 侧最小链路、预期关键字段与可复现输入固定下来
  - 但尚未补入真实参考侧输出，因此**不能**写成“已通过”或“已一致”

### 证据来源
- `src/disasm/mod.rs`
- `src/disasm/x86_64.rs`
- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`
- `src/align/runtime_verify.rs`
- `src/ffi.rs`

### 运行结果记录
- **Rudra 侧最小输入**:
```/dev/null/sample.bin#L1-1
48 89 c3
```
- **固定起始地址**: 待填写（建议固定为单一地址，如 `0x1000`）
- **Rudra 侧指令层记录**:
  - `mnemonic`: 待填写（预期 `mov`）
  - `length`: 待填写
  - `operands.len()`: 待填写（预期 `2`）
  - operand0: 待填写（预期 `Register { name: "rbx", size: 8 }`）
  - operand1: 待填写（预期 `Register { name: "rax", size: 8 }`）
- **Rudra 侧 lifting 记录**:
  - raw op 数量: 待填写
  - raw op opcode 列表: 待填写
  - raw op 输入/输出摘要: 待填写
  - 首轮重点观察：是否至少出现 1 条核心 `CPUI_COPY`
- **Rudra 侧注入后记录**:
  - injected op 数量: 待填写
  - block 数量: 待填写
  - 核心 injected op 摘要: 待填写
  - 首轮重点观察：是否仍保持最小单块结构
- **比较入口记录**:
  - `verify_pcode_generation(...)` 是否成功执行: 待填写
  - 返回摘要: 待填写
  - 当前结果属于：
    - [ ] Match
    - [ ] Mismatch
    - [ ] 入口已跑通但比较粒度不足
- **参考结果**: 当前待补真实运行结果
- **是否可复现**:
  - Rudra 侧输入样本：是
  - 参考侧输出：待补
- **比较层级**: `P-code`

### 差异记录
- **当前差异**: 尚未填写真实比较结果
- **当前已知高风险点**:
  - 寄存器名到 offset 的映射是否与预期一致
  - `COPY` 的输入/输出方向是否被写反
  - 注入后是否引入额外噪声 op
  - 比较入口是否仍只停留在计数级比较
- **差异分类**:
  - 当前尚未形成真实差异记录
  - 首轮建议优先观察：
    - `opcode 差异`
    - `输出 varnode 差异`
    - `输入顺序/寄存器映射差异`
    - `框架已运行但比较粒度不足`
- **是否阻断后续样本**:
  - 若该样本不能稳定走完最小链路，则应暂缓进入 `add/sub` 之外的更复杂样本

### 下一步动作
- 第一步：固定真实起始地址并完成 `Instruction` 层记录
- 第二步：记录 `X86Lifter::lift(...)` 的实际 raw op 数量与 opcode 列表
- 第三步：记录 `Funcdata::inject_raw_ops(...)` 后的实际 op 数量
- 第四步：确认 `verify_pcode_generation(...)` 是否真正进入比较入口
- 第五步：若仅形成“入口跑通但比较粒度不足”，也应把它作为首轮真实结果写入，不要继续保留为“待填写”

### 首次真实运行时的最小填写顺序
如果你只想快速把第一条记录落下来，建议按以下最小顺序填写：

1. 原始字节
2. 固定起始地址
3. `Instruction` 摘要
4. raw op 数量 + opcode 列表
5. injected op 数量
6. 比较入口是否被调用
7. 当前结果分类
8. 下一步最小修复动作

这个顺序的好处是：即使参考侧结果还没完全拿到，你也已经能形成一条**不失真的首轮真实记录**。

### 最小可执行对拍走查（建议先按这条路径执行）
以下步骤用于把 `mov rbx, rax` 推进成第一条真正可记录的最小对拍样本。

#### Step 1：固定输入
先把样本固定为：

```/dev/null/sample.bin#L1-1
48 89 c3
```

对应文本：

```/dev/null/sample.asm#L1-1
mov rbx, rax
```

本条样本的目标不是证明“已经与 Ghidra 一致”，而是确认这条最短链路是否已经能够稳定给出**可记录结果**。

#### Step 2：先看反汇编是否稳定
优先确认 `Instruction` 层至少能稳定得到：

- `mnemonic = "mov"`
- 两个寄存器操作数
- 地址与长度可用

按当前仓库代码，较合理的最小检查目标可以收敛为：

- `mnemonic = "mov"`
- `operands.len() = 2`
- `operand0 = Register { name: "rbx", size: 8 }`
- `operand1 = Register { name: "rax", size: 8 }`

如果连这一层都不稳定，就不要继续往 `X86Lifter::lift(...)` 推进。

#### Step 3：检查 raw p-code 结果
把关注点收敛到最小问题：

- `X86Lifter::lift(...)` 是否返回非空 `Vec<PcodeOpRaw>`
- 是否至少存在一条核心 `CPUI_COPY`
- 输入/输出是否都落在寄存器空间

此处建议先记录：

- raw op 数量
- raw op 的 opcode 列表
- 每条 raw op 的输入 / 输出摘要

而不是一开始就尝试写“完全一致”。

#### Step 4：检查注入后结果
调用 `Funcdata::inject_raw_ops(...)` 后，最先记录：

- 注入后的 op 数量
- 是否只形成一个最小 basic block
- `PcodeOpBank` 中的首条或核心 op 是否仍能对应 `COPY`
- 输出 varnode 是否看起来仍指向 `rbx`
- 输入 varnode 是否看起来仍指向 `rax`

如果在这里已经发生结构变化，就先把变化记录清楚，不要直接归因给参考实现差异。

#### Step 5：再进入比较入口
只有在前面 4 步都有最小可记录结果时，才进入：

- `verify_pcode_generation(...)`
- 以及后续比较入口

按当前可见实现，第一轮更现实的目标不是“逐字段完全一致”，而是先确认：

- 比较入口能不能稳定被调用
- 当前能不能得到：
  - `Match`
  - `Mismatch(...)`
  - 或者至少形成“当前比较粒度不足”的明确记录
- mismatch 是否能形成文字记录

#### Step 6：第一轮记录时最少要填写什么
第一次真正落样本时，至少应补齐以下字段：

- 原始字节
- 实际 `Instruction` 摘要
- 实际 raw op 数量
- 实际 injected op 数量
- 核心 opcode 摘要
- 当前比较入口是否成功运行
- 当前差异分类
- 下一步最小修复目标

#### Step 7：如果失败，先查哪里
建议按下面顺序排查，不要一开始就泛化成“大闭环坏了”：

1. **反汇编层**
   - 指令文本与操作数是否正确
2. **lifting 层**
   - `mov` 是否真的进入 `CPUI_COPY`
3. **raw p-code 组织**
   - 输入输出是否反了
4. **注入层**
   - `inject_raw_ops(...)` 是否改变了最小结构
5. **比较入口**
   - 是否只是比较入口尚不完整，而不是 lifting 本身错误

#### 当前阶段的合格标准
对于这第一条样本，当前阶段的“合格”标准建议设为：

> 能稳定形成一份可复现、可记录、可定位差异的样本记录

而不是：

> 已经完全与 Ghidra 一致

只要能稳定记录，`mov rbx, rax` 就已经足够成为第一条最小对拍锚点。

#### 当前最小可执行记录草案（可直接作为首轮真实记录骨架）
下面给出一份更接近“第一次实际填写”时的最小骨架：

- **样本 ID**: `PCode-Min-001`
- **目标指令**: `mov rbx, rax`
- **原始字节**:
```/dev/null/sample.bin#L1-1
48 89 c3
```
- **Rudra 侧预期最小链路**:
  - `Instruction`
  - `X86Lifter::lift(...)`
  - `Vec<PcodeOpRaw>`
  - `Funcdata::inject_raw_ops(...)`
  - `verify_pcode_generation(...)`
- **首轮必须补实的字段**:
  - `Instruction` 实际摘要
  - raw op 数量
  - raw op opcode 列表
  - injected op 数量
  - 是否进入比较入口
  - 当前结论属于：
    - `已可运行`
    - `已发现 mismatch`
    - 或 `比较粒度不足`
- **首轮不要急着写的字段**:
  - “已与 Ghidra 完全一致”
  - “已无差异”
  - “已完成 P-code 对齐”

---

## Sample 02: `add rax, 1`

- **样本 ID**: `PCode-Min-002`
- **优先级**: 最高
- **层级**: `P-code`
- **目标指令 / 指令序列**: 单条寄存器加立即数
- **代表性目的**:
  - 验证二元算术路径
  - 验证立即数是否进入 `Const` 空间
  - 验证 `INT_ADD` 类 opcode 映射
  - 验证目标寄存器回写路径

### 原始字节
```/dev/null/sample.bin#L1-1
48 83 c0 01
```

### 预期汇编文本
```/dev/null/sample.asm#L1-1
add rax, 1
```

### 预期 Rudra 入口
- `src/disasm/mod.rs`
- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`

### 预期比较入口
- `src/align/runtime_verify.rs`
  - `verify_pcode_generation(...)`
- `src/ffi.rs`
  - `rudra_compare_pcode(...)`

### 当前预期关注点
1. 是否生成 `CPUI_INT_ADD`
2. 立即数 `1` 是否被编码为 `AddressSpace::Const`
3. 输入槽顺序是否稳定
4. 输出是否仍正确落在 `rax`
5. 注入后是否只保留最小算术结构

### 预期最小 P-code 观察目标
```/dev/null/sample_pcode_goal.txt#L1-4
opcode: CPUI_INT_ADD
output: register(rax)
input0: register(rax) 或等价源寄存器读取结果
input1: const(1)
```

> 注：这里故意使用“或等价源寄存器读取结果”这种保守表述，避免在尚未实测前把具体实现路径写死成既成事实。

### 潜在风险点
- `add` 的输入顺序可能与预期不同
- 立即数大小 / offset 表达方式可能与参考实现不一致
- 目标寄存器是否直接原地回写，还是先生成临时节点
- FFI 比较可能暂时无法观察到全部字段差异

### 当前状态
- **状态**: 待执行
- **可信边界**: 当前仅为样本设计草案，尚未记录真实运行结果

### 证据来源
- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`
- `src/opcodes.rs`
- `src/align/runtime_verify.rs`
- `src/ffi.rs`

### 运行结果记录
- Rudra 结果: 待填写
- 参考结果: 待填写
- 是否可复现: 待填写
- 比较层级: `P-code`

### 差异记录
- 当前差异: 待填写
- 差异分类: 待填写
- 是否阻断后续样本: 待填写

### 下一步动作
- 若此样本跑通，说明：
  - 算术 opcode 映射开始具备最小可信验证基础
- 若失败，优先排查：
  - immediate 解析
  - opcode 映射
  - raw op 组织

---

## Sample 03: `sub rax, 8`

- **样本 ID**: `PCode-Min-003`
- **优先级**: 高
- **层级**: `P-code`
- **目标指令 / 指令序列**: 单条寄存器减立即数
- **代表性目的**:
  - 验证 `INT_SUB` 路径
  - 与 `add` 配对，确认二元算术映射的一致性
  - 观察不同立即数值是否影响 raw op 组织稳定性

### 原始字节
```/dev/null/sample.bin#L1-1
48 83 e8 08
```

### 预期汇编文本
```/dev/null/sample.asm#L1-1
sub rax, 8
```

### 预期 Rudra 入口
- `src/disasm/mod.rs`
- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`

### 预期比较入口
- `src/align/runtime_verify.rs`
- `src/ffi.rs`

### 当前预期关注点
1. 是否正确映射为 `CPUI_INT_SUB`
2. 立即数 `8` 是否稳定进入常量空间
3. 输入顺序是否和 `add` 类样本保持相同约定
4. 输出寄存器是否仍为 `rax`
5. 是否会引入意外临时节点

### 预期最小 P-code 观察目标
```/dev/null/sample_pcode_goal.txt#L1-4
opcode: CPUI_INT_SUB
output: register(rax)
input0: register(rax) 或等价读取结果
input1: const(8)
```

### 潜在风险点
- `sub` 路径虽然与 `add` 相似，但 opcode 映射可能单独出错
- 立即数 `8` 的表达可能暴露 size / sign 处理问题
- 若 `add` 通过而 `sub` 不通过，优先怀疑 opcode / 输入顺序，而不是整条链路都坏

### 当前状态
- **状态**: 待执行
- **可信边界**: 当前仅为样本设计草案，尚未记录真实运行结果

### 证据来源
- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`
- `src/opcodes.rs`
- `src/align/runtime_verify.rs`
- `src/ffi.rs`

### 运行结果记录
- Rudra 结果: 待填写
- 参考结果: 待填写
- 是否可复现: 待填写
- 比较层级: `P-code`

### 差异记录
- 当前差异: 待填写
- 差异分类: 待填写
- 是否阻断后续样本: 待填写

### 下一步动作
- 若 `mov`、`add`、`sub` 三者都可稳定形成记录，就说明：
  - 第一批最小算术/复制样本已经可以构成第一组局部对拍基线
- 这时再进入位运算和移位样本更稳妥

---

## 4. 建议的首轮执行顺序

推荐先按下面顺序推进：

1. `mov rbx, rax`
2. `add rax, 1`
3. `sub rax, 8`

理由：

- `mov` 先验证最短复制链路
- `add` 再验证最小算术链路
- `sub` 用来确认同类算术路径不是偶然通过

如果这三条样本都能形成可复现记录，再继续推进：

4. `and/or/xor`
5. `shl/shr/sar`
6. 简单 memory load/store
7. 简单 `jcc`
8. 短序列

---

## 5. 首轮记录约定

为避免后续记录继续失真，第一批样本建议遵守以下约定：

### 5.1 在没有真实运行结果前
只能写：

- `待执行`
- `待记录`
- `待验证`
- `预期关注点`

不能写：

- `已通过`
- `已一致`
- `与 Ghidra 相同`
- `已确认无差异`

### 5.2 每条样本至少要能回答
1. 输入是什么？
2. 走了哪条代码路径？
3. 比较入口是什么？
4. 当前结果是什么？
5. 差异在哪？
6. 下一步修哪里？

### 5.3 第一批样本的目标
第一批样本的目标不是“证明已经追平 Ghidra”，而是：

> **让项目第一次拥有一组最小、真实、可复现、可记录的 P-code 局部对拍样本。**

---

## 6. 一句话结论

当前最适合恢复 Ghidra 对齐工作的第一批样本，应优先从：

- `mov reg, reg`
- `add reg, imm`
- `sub reg, imm`

这 3 类最小指令开始。  
它们最容易走通 `x86_lift -> pcoderaw -> inject_raw_ops -> verify_pcode_generation -> ffi compare` 这条最小闭环，并形成第一批可信的局部对拍记录。
"}
