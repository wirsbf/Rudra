# `opcodes.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/opcodes.rs`

## 模块说明 (Module Doc)

P-code operation codes

Corresponds to Ghidra's `opcodes.hh`

## 导出的公共 API (Public API)

### `pub enum OpCode`

P-code operation type (OpCode in Ghidra)

This enum represents all possible P-code operations. Each operation
has specific semantics for how it operates on its input and output varnodes.
Prefixes match Ghidra's `CPUI_` naming convention.

**2026-06-27 新增 `CPUI_CAST` (=73)**：对齐 Ghidra `opcodes.hh:119`。P-code
annotation op — 保持 bit pattern，仅标注 metatype/size 变更。ActionSetCasts
在 P-code 层插入，print 层渲染 cast 语法。`CPUI_MAX` 相应 73→74。

**待对齐的命名缺口**（Rugra 改名 vs Ghidra 规范名，205 处引用待重命名）：
- `CPUI_BOOL_NOT` ← Ghidra `CPUI_BOOL_NEGATE` (opcodes.hh:81)
- `CPUI_INT_NEG` ← Ghidra `CPUI_INT_2COMP` (opcodes.hh:67)
- `CPUI_INT_NOT` ← Ghidra `CPUI_INT_NEGATE` (opcodes.hh:68)
- `CPUI_TRUNC`：Ghidra opcodes.hh 无此 op（Rugra 多出）

### `pub fn name(&self) -> &'static str`

`get_opname`（opcodes.cc:60-64）的 1:1 移植：按枚举值直查 opcodes.cc:29-48 的
`opcode_name[]` 表。注意表的占位别名槽位（opcodes.cc:23-28 头注释，为 SLEIGH
编译器/解释器保留）：`MULTIEQUAL→"BUILD"`、`INDIRECT→"DELAY_SLOT"`、
`PTRADD→"LABEL"`、`PTRSUB→"CROSSBUILD"`；float 族六成员去 `FLOAT_` 前缀
（`INT2FLOAT/FLOAT2FLOAT/TRUNC/CEIL/FLOOR/ROUND`）。`opcode_indices`
（opcodes.cc:50-56）只服务于 `get_opcode` 的名字→枚举二分搜索，与本查表无关。

### `pub fn from_i32(raw: i32) -> Option<OpCode>`

Convert from raw integer opcode to OpCode enum

Used by the P-code injection bridge to convert `PcodeOpRaw.opcode`
integer values into typed `OpCode` variants.

### `pub fn is_block_terminator(&self) -> bool`

Check if this opcode is a control flow terminator (ends a basic block)

### `pub fn is_commutative(&self) -> bool`

Check if this opcode is commutative (operand order doesn't matter). 镜像
Ghidra typeop.cc ctor bodies 中 \`opflags = ... | PcodeOp::commutative\` 的集合
（与 op.rs::opcode_flags 的 COMMUTATIVE 位一致）。

完整集合：INT_ADD, INT_MULT, INT_AND, INT_OR, INT_XOR, INT_EQUAL, INT_NOTEQUAL,
**INT_CARRY, INT_SCARRY**, BOOL_AND, BOOL_OR, BOOL_XOR, FLOAT_ADD, FLOAT_MULT,
FLOAT_EQUAL, FLOAT_NOTEQUAL。

注意 INT_LEFT（左移）和 INT_DIV（无符号除）在 Ghidra 中**不**可交换
（typeop.cc:1505/1645 opflags 仅 binary），尽管常被误判。

### `pub fn is_commutative_or_pure(&self) -> bool`

Check if this opcode is a deterministic, side-effect-free operation
suitable for CSE (Common Subexpression Elimination).

Excludes LOAD/STORE (memory side-effects), branches, calls, and
SSA-internal ops (MULTIEQUAL, INDIRECT).

 
## 2026-06-26：get_booleanflip（opcodes.cc:94-135）

### `pub fn get_booleanflip(opc: OpCode, reorder: &mut bool) -> OpCode`
比较 op 的互补翻转表（Ghidra opcodes.cc:94-135）：
- `INT_EQUAL ↔ INT_NOTEQUAL`（reorder=false）
- `INT_LESS ↔ INT_LESSEQUAL`、`INT_SLESS ↔ INT_SLESSEQUAL`（reorder=true，需换序）
- `BOOL_NOT → COPY`（reorder=false）。注：Rugra `CPUI_BOOL_NOT` == Ghidra `BOOL_NEGATE`。
- `FLOAT_EQUAL ↔ FLOAT_NOTEQUAL`、`FLOAT_LESS ↔ FLOAT_LESSEQUAL`
非可翻 op 返回 `CPUI_MAX`。用于 RuleBoolNegate。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
<!-- annotation-pass: 2026-07-04 -->
<!-- opcode-correct: 1783180039.0464888 -->

## 2026-09-27：name() 拼写表 1:1 对齐 get_opname（PCODE-OPNAME-TABLE-0001）

`OpCode::name()` 十个成员重钉为锁定 oracle `opcode_name[]` 表拼写
（亲读 opcodes.cc:29-48 全表 + :23-28 占位别名头注释）：

| 枚举 | 旧拼写 | 新拼写（oracle） | 表索引 |
|---|---|---|---|
| `CPUI_FLOAT_INT2FLOAT` | FLOAT_INT2FLOAT | **INT2FLOAT** | 54 |
| `CPUI_FLOAT_FLOAT2FLOAT` | FLOAT_FLOAT2FLOAT | **FLOAT2FLOAT** | 55 |
| `CPUI_FLOAT_TRUNC` | FLOAT_TRUNC | **TRUNC** | 56 |
| `CPUI_FLOAT_CEIL` | FLOAT_CEIL | **CEIL** | 57 |
| `CPUI_FLOAT_FLOOR` | FLOAT_FLOOR | **FLOOR** | 58 |
| `CPUI_FLOAT_ROUND` | FLOAT_ROUND | **ROUND** | 59 |
| `CPUI_MULTIEQUAL` | MULTIEQUAL | **BUILD** | 60 |
| `CPUI_INDIRECT` | INDIRECT | **DELAY_SLOT** | 61 |
| `CPUI_PTRADD` | PTRADD | **LABEL** | 65 |
| `CPUI_PTRSUB` | PTRSUB | **CROSSBUILD** | 66 |

前 7 个由 `pcode_snippet_face_1204` fixture 的 XML 编码通道亲测钉出；后 3 个
（MULTIEQUAL/INDIRECT/PTRSUB）为整表亲读时确认的同伴占位别名（snippet 语法不可
产生这三类 op，fixture 无法观察到）。行为面：诊断字符串、unify C++ 生成文本、
printc opFunc 兜底（printc.cc:430 用 TypeOp::getOperatorName——float 六成员的
TypeOp 名即表拼写 typeop.cc:1840-1937，本修使其一致；MULTIEQUAL/INDIRECT/
PTRADD/PTRSUB 有专用 emitter，兜底不可达）。相邻残差（另行登记）：
typeop.rs 宏的 TypeOp nametext 面（getOperatorName，float 六成员拼写同此分歧，
Rugra 侧无消费者）不在本票写域。
