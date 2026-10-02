# `opbehavior.rs` API Reference

**源代码路径**: `src/opbehavior.rs`
**Ghidra 对应**: `opbehavior.hh` / `opbehavior.cc` (823 行)
**状态**: 🔧 L2 / NO_ORACLE——大量 opcode evaluator 与 trait 表面已实现，
但没有覆盖完整分支、异常、输入别名和突变状态的锁定 12.0.4 同输入 fixture；
`TypeOp`/`PcodeOp` flag 与 behavior 接线也仍由 `PCODE-0002` 跟踪。
函数来源注释及 Rust 自测不构成 L3/L4 证据。

## 模块说明

P-code 操作行为模拟。对应 Ghidra 的 `opbehavior.hh` / `opbehavior.cc`。
每个 opcode 有对应的 `OpBehavior` 子类，描述如何模拟该操作：
`evaluateUnary` / `evaluateBinary` / `evaluateTernary` 以及逆操作
`recoverInputUnary` / `recoverInputBinary`。用于常量折叠
（RuleCollapseConstants）和跳转表分析 emulator。

本模块提供两套并行 API：
- **自由函数**（`evaluate_unary`、`evaluate_binary`、…）—— Rust 风格的
  便利接口，被 `emulate.rs`、`op.rs`、`jumptable.rs`、`unify.rs` 使用。
  每个 `match` 分支是对应 `OpBehavior*::evaluate*` body 的 1:1 移植。
- **OOP trait + 子类**（`OpBehavior` trait，`OpBehaviorIntAdd` 等）——
  C++ 类层级的直接移植，便于逐类审计 Rudra 与 Ghidra 的对齐。
  `OpBehaviorFactory` 对应 `OpBehavior::registerInstructions`。

## 导出的公共 API

### 自由函数（Rust 便利接口）

#### `pub fn evaluate_unary(opc, size_out, size_in, in1) -> Option<u64>`
模拟一元 P-code 操作。覆盖 COPY/ZEXT/SEXT/INT_NEGATE/INT_2COMP/
BOOL_NEGATE/POPCOUNT/LZCOUNT。`None` 表示该 opcode 无一元行为。
对齐 `OpBehavior*::evaluateUnary`（cc:185-821）。

#### `pub fn evaluate_binary(opc, size_out, size_in, in1, in2) -> Option<u64>`
模拟二元 P-code 操作。覆盖 ADD/SUB/MULT/DIV/SDIV/REM/SREM/AND/OR/XOR/
LEFT/RIGHT/SRIGHT/EQUAL/NOTEQUAL/LESS/SLESS/LESSEQUAL/SLESSEQUAL/
CARRY/SCARRY/SBORROW/BOOL_AND/BOOL_OR/BOOL_XOR/PIECE/SUBPIECE/PTRSUB/
PTRADD(binary)。除零返回 `None`（Ghidra 抛 `EvaluationError`）。
对齐 `OpBehavior*::evaluateBinary`（cc:197-809）。

#### `pub fn evaluate_ternary(opc, size_out, size_in, in1, in2, in3) -> Option<u64>`
模拟三元 P-code 操作。仅 `CPUI_PTRADD`：`(in1 + in2*in3) & mask`。
对齐 `OpBehaviorPtradd::evaluateTernary`（cc:768）。

#### `pub fn recover_input_unary(opc, size_out, out, size_in) -> Option<u64>`
一元操作的逆运算，从输出恢复输入。覆盖 COPY/ZEXT/SEXT/INT_NEGATE/
INT_2COMP。超范围返回 `None`（Ghidra 抛 `EvaluationError`）。
对齐 `OpBehavior*::recoverInputUnary`（cc:191-302）。

#### `pub fn recover_input_binary(opc, slot, size_out, out, size_in, other) -> Option<u64>`
二元操作的逆运算，从输出和另一个输入恢复指定 slot 的输入。
覆盖 INT_ADD/INT_SUB/INT_LEFT/INT_RIGHT/INT_SRIGHT。slot 1（移位量）
或超范围返回 `None`。对齐 `OpBehavior*::recoverInputBinary`
（cc:179,312-514）。

#### `pub fn evaluate_unary_no_exc(opc, size_out, size_in, in1) -> Option<u64>`
#### `pub fn evaluate_binary_no_exc(opc, size_out, size_in, in1, in2) -> Option<u64>`
非 panic 变体，对齐 Ghidra Java `OpBehavior.evaluateUnaryNoExc` /
`evaluateBinaryNoExc` 语义。失败返回 `None`。

### OOP trait + 子类层级（C++ 类层级直接移植）

#### `pub trait OpBehavior`
对应 `opbehavior.hh:44 OpBehavior`。提供 `meta()`/`opcode()`/`is_special()`/
`is_unary()`，以及虚拟方法 `evaluate_unary`/`evaluate_binary`/`evaluate_ternary`/
`recover_input_unary`/`recover_input_binary`（默认 body 复现 C++ 基类抛异常）。

#### `pub struct OpBehaviorMeta`
对应 `opbehavior.hh:44-47` 的 opcode/isunary/isspecial 字段。
`OpBehaviorMeta::new(opc, isun)` 对应 `opbehavior.hh:85`，`new_special(opc,isun,spec)`
对应 `opbehavior.hh:97`。

#### 子类（对齐 `opbehavior.hh:128-538`）
全部 40+ 子类已移植，每个 `impl OpBehavior for Op*` 方法带 `// Ghidra: opbehavior.cc:<行>` 注释：

| Rust 结构体 | Ghidra 类 | hh 行 | 主要 cc 行 |
|---|---|---|---|
| `OpBehaviorCopy` | OpBehaviorCopy | 128 | 185, 191 |
| `OpBehaviorEqual` | OpBehaviorEqual | 136 | 197 |
| `OpBehaviorNotEqual` | OpBehaviorNotEqual | 143 | 204 |
| `OpBehaviorIntSless` | OpBehaviorIntSless | 150 | 211 |
| `OpBehaviorIntSlessEqual` | OpBehaviorIntSlessEqual | 157 | 231 |
| `OpBehaviorIntLess` | OpBehaviorIntLess | 164 | 251 |
| `OpBehaviorIntLessEqual` | OpBehaviorIntLessEqual | 171 | 258 |
| `OpBehaviorIntZext` | OpBehaviorIntZext | 178 | 265, 271 |
| `OpBehaviorIntSext` | OpBehaviorIntSext | 186 | 280, 287 |
| `OpBehaviorIntAdd` | OpBehaviorIntAdd | 194 | 304, 312 |
| `OpBehaviorIntSub` | OpBehaviorIntSub | 202 | 319, 327 |
| `OpBehaviorIntCarry` | OpBehaviorIntCarry | 210 | 339 |
| `OpBehaviorIntScarry` | OpBehaviorIntScarry | 217 | 346 |
| `OpBehaviorIntSborrow` | OpBehaviorIntSborrow | 224 | 362 |
| `OpBehaviorInt2Comp` | OpBehaviorInt2Comp | 231 | 378, 386 |
| `OpBehaviorIntNegate` | OpBehaviorIntNegate | 239 | 393, 401 |
| `OpBehaviorIntXor` | OpBehaviorIntXor | 247 | 408 |
| `OpBehaviorIntAnd` | OpBehaviorIntAnd | 254 | 416 |
| `OpBehaviorIntOr` | OpBehaviorIntOr | 261 | 424 |
| `OpBehaviorIntLeft` | OpBehaviorIntLeft | 268 | 432, 443 |
| `OpBehaviorIntRight` | OpBehaviorIntRight | 276 | 454, 465 |
| `OpBehaviorIntSright` | OpBehaviorIntSright | 284 | 477, 498 |
| `OpBehaviorIntMult` | OpBehaviorIntMult | 292 | 516 |
| `OpBehaviorIntDiv` | OpBehaviorIntDiv | 299 | 524 |
| `OpBehaviorIntSdiv` | OpBehaviorIntSdiv | 306 | 534 |
| `OpBehaviorIntRem` | OpBehaviorIntRem | 313 | 548 |
| `OpBehaviorIntSrem` | OpBehaviorIntSrem | 320 | 558 |
| `OpBehaviorBoolNegate` | OpBehaviorBoolNegate | 327 | 570 |
| `OpBehaviorBoolXor` | OpBehaviorBoolXor | 334 | 577 |
| `OpBehaviorBoolAnd` | OpBehaviorBoolAnd | 341 | 584 |
| `OpBehaviorBoolOr` | OpBehaviorBoolOr | 348 | 591 |
| `OpBehaviorFloatEqual..FloatRound` | (18 个 float 子类) | 355-496 | 598-779 |
| `OpBehaviorFloatInt2Float` | OpBehaviorFloatInt2Float | 451 | 718 |
| `OpBehaviorFloatFloat2Float` | OpBehaviorFloatFloat2Float | 459 | 728 |
| `OpBehaviorFloatTrunc` | OpBehaviorFloatTrunc | 467 | 741 |
| `OpBehaviorPiece` | OpBehaviorPiece | 501 | 752 |
| `OpBehaviorSubpiece` | OpBehaviorSubpiece | 508 | 759 |
| `OpBehaviorPtradd` | OpBehaviorPtradd | 513 | 768 |
| `OpBehaviorPtrsub` | OpBehaviorPtrsub | 520 | 775 |
| `OpBehaviorPopcount` | OpBehaviorPopcount | 527 | 782 |
| `OpBehaviorLzcount` | OpBehaviorLzcount | 534 | 788 |

#### `pub struct OpBehaviorFactory`
对应 `opbehavior.cc:24 OpBehavior::registerInstructions`。`OpBehaviorFactory::new()`
按 Ghidra 注册顺序填充 `table[1..CPUI_MAX]`：9 个 control-flow special +
2 个 merge special + 29 个 int/bool 行为 + 1 个 CAST special + PTRADD/PTRSUB
+ 18 个 float 行为 + SEGMENTOP/CPOOLREF/NEW special + INSERT/EXTRACT +
POPCOUNT/LZCOUNT。`get(opc)` 查表，`len()` 返回已注册条目数。

### 辅助类型/函数

- `pub struct EvaluationError` — 对应 `opbehavior.hh:30`，除零 / 超范围时使用。
- `pub fn float_format(size) -> Option<&'static FloatFormat>` — RUDRA-GLUE：
  替代 Ghidra 的 `Translate::getFloatFormat(size)`，返回静态 IEEE754
  single(4)/double(8) `FloatFormat`。float 子类经此路由到 `float_emulate`。

## 内部辅助函数

- `mask_bits(bits)` — 位宽 mask（RUDRA-GLUE，无 Ghidra 对应）。
- `sign_extend_to_i64(val, in_size)` — 对齐 `sign_extend(val, sizein*8-1)`
  （address.hh:555）。
- `uintb_negate(val, size_bytes)` — 对齐 `uintb_negate`（address.cc:654）。
- `zero_extend(sres, size_out)` — 对齐 `zero_extend`（opbehavior.cc:542）。
- 复用 `crate::address::{calc_mask, count_leading_zeros, signbit_negative}`、
  `crate::rangeutil::sign_extend_size`、`crate::float_emulate::FloatFormat`。

## 测试

`opbehavior::tests`：25 个测试，覆盖：
- 自由函数：add/sub/and-or-xor/shifts(含 INT_SRIGHT 符号扩展与超大移位)/
  compare(含 SLESS/SLESSEQUAL)/unary(NEGATE/2COMP/SEXT)/popcount-lzcount/
  div-rem(含 SDIV/SREM 与除零)/carry-scarry-sborrow/piece-subpiece/
  ternary-ptradd/left-overflow
- recover_input：add-sub/left/right(含超范围)/sright(含正数失败)/unary
  (COPY/NEGATE/2COMP/ZEXT 超范围)
- OOP trait：int_add(含 recoverInputBinary)、int_left_recover(含 slot 1 panic)、
  int_div_panics_on_zero(catch_unwind)、popcount、copy、float_add
- factory：registry 抽样验证（control-flow/int/bool/merge/float/piece/
  popcount/lzcount 全部类别）
- evaluate_no_exc：unary/binary/未知 opcode

另有集成测试 `tests/opbehavior_sdiv_panic.rs`（KUNAUB-SDIV-0001 崩溃形态锁，
2 个 `#[should_panic]`：SDIV/SREM 在 `(INT64_MIN,-1)`、sizein=8 输入上
恒 panic，镜像 oracle SIGFPE——见下方 2026-09-26 裁决节）。

## 对齐说明（关键修复）

本次移植将原有 35% 覆盖率的胶水代码提升至全量对齐，关键变更：
1. **INT_SRIGHT** 现严格复刻 cc:477 的符号扩展逻辑（先判 `signbit_negative`，
   再 `(mask>>in2)^mask` 填高位），替代之前的简易 `sign_extend>>` 近似。
2. **INT_LEFT/RIGHT** 现正确处理 `in2 >= sizeout*8 ⇒ 0`（cc:432,454）。
3. **PIECE** 现使用 `(in1<<((sizeout-sizein)*8))|in2`（cc:781），而非旧版
   错误的 `size_in*8`。
4. **SUBPIECE** 现按 cc:788 处理 `in2 >= 8 ⇒ 0` 与字节偏移语义。
5. **新增 recover_input_binary** 的 INT_RIGHT/INT_SRIGHT 分支（cc:465,498），
   含 Ghidra 的精确范围校验。
6. **新增全部 OOP 子类 + OpBehaviorFactory**，使注册表对齐 registerInstructions。
<!-- annotation-pass: 2026-07-22 -->

### ANN-H 注释 bootstrap（2026-08-11）

- 为 36 个缺失 marker 的 Rust `Display`、宏模板、trait 元数据适配及 registry helper 补充具体 `RUDRA-GLUE` 说明；这些函数在 Ghidra 中没有单一同签名对应物。
- 仅补注释，不改变行为；既有越界引用留待后续串行处理。未生成函数级 oracle fixture，因此不声明 `MATCH` 或提升模块等级。

### ANN-K const constructor 注释 bootstrap（2026-08-12）

- 为 expanded scanner 识别出的 42 个 `const fn new` 补齐直属 marker：40 个具体 behavior constructor 映射到锁定 oracle 的内联 constructor 起始行。
- 其余 2 个 float 宏模板使用具体 `RUDRA-GLUE`，因为一个 Rust 源级函数模板会分别生成多种类型，不能绑定到单一 Ghidra constructor。三个显式 Rust float unit constructor仍映射真实 Ghidra constructor；它们省略了 Ghidra 必需并保存的 `Translate *`，属于已知行为缺口，而不是“无对应物”的胶水。
- 此轮仅补注释，不改变对象构造或求值行为；未生成函数级 oracle fixture，因此不声明 `MATCH` 或提升模块等级。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 79 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-26 — KUNAUB-SDIV-0001 崩溃形态裁决（INT64_MIN / -1 常量折叠）

**裁决：(a) 维持 panic**（root 2026-09-26；零生产代码改动）。1:1 对齐原则下
oracle 在 `INT_SDIV`/`INT_SREM` 常量折叠遇到 `(in1,in2)=(INT64_MIN,-1)`、
`sizein=8` 时为 SIGFPE 硬死，Rust panic 在正常运行下同样终止进程——形态最贴近。
选 (b) LowlevelError→opMarkNoCollapse 软失败=主动分歧（oracle 死 Rudra 活），
不采。

**oracle 侧（锁定 e40ed130，亲读核对）**：
`OpBehaviorIntSdiv::evaluateBinary`（opbehavior.cc:507-517）与
`OpBehaviorIntSrem::evaluateBinary`（:529-539）只守卫 `in2 == 0`
（抛 `EvaluationError`），随后直接执行原生 `intb` 除法/取余
（:514 `num/denom` / :536 `val % mod`）——`INT64_MIN / -1` 是同步硬件陷阱，
进程被 SIGFPE 杀死。主管线可达路径：ruleaction.cc:3854
`RuleCollapseConstants::applyOp` → op.cc:466 `PcodeOp::collapse` →
`opcode->evaluateBinary`；ruleaction.cc:3867 的 `catch(LowlevelError&)` 只能
接住除零 `EvaluationError`，接不住硬件 fault。

**Rudra 侧（四处除法位点现状核对，2026-09-26）**——全部只守卫 `in2 == 0`、
随后执行原生 `i64` 除法/取余，无溢出守卫：
- safe 自由函数版：`src/opbehavior.rs` `CPUI_INT_SDIV` 臂（:188-196，
  `zero_extend(num / denom, size_out)`）与 `CPUI_INT_SREM` 臂（:205-213，
  `zero_extend(val % modulus, size_out)`）；`mask_bits(64)→u64::MAX`、
  `sign_extend_to_i64(x,8)=x as i64` 已核对，sizein=8 时即计算字面量
  `i64::MIN / -1`。
- OOP trait 版：`OpBehaviorIntSdiv::evaluate_binary`（:1350-1358，
  `num / denom`）与 `OpBehaviorIntSrem::evaluate_binary`（:1398-1408，
  `val % modulus`）。
- Rust 语义：`i64::MIN / -1`（及 `% -1`）**在所有 profile 下恒 panic**
  （"attempt to divide with overflow" / "attempt to calculate the
  remainder with overflow"）——这不是 overflow-checks 配置项，是无条件行为。主管线汇聚点
  （ruleaction.rs → op.rs → typeop.rs）与 `unify.rs` 调用点同池。

**双侧复现实证（2026-09-26，/dev/shm/rudra-tests/kunasdiv/）**：
- 构造：`sdiv_srem.c`（`f_sdiv`/`f_srem`，-O0，`cqto`+`idivq` 保留）。SLEIGH
  `IDIV rm64` 本义即 16 字节形（ia.sinc:3576-3580：`tmp:16=(zext(RDX)<<64)|zext(RAX);
  quotient = tmp s/ sext(rm64)`）。
- oracle：`sdiv_crash_1204`（锁定树 git-archive 全管线驱动）对两函数均
  **SIGFPE 杀进程（rc 136，core dumped），stdout 0 字节——golden 不可产出**，
  末行日志停在进入 action pipeline。oracle 侧折叠链：RuleSubCommute 的
  SDIV/SREM 臂（ruleaction.cc:4574-4601）先把 `SUB168(SDIV16(SEXT816(a),
  SEXT816(b)),0)` commute 成 8 字节 `SDIV8(a,b)`，再由 RuleCollapseConstants
  折叠进 `evaluateBinary(sizein=8)` → `i64::MIN / -1` → SIGFPE。
- Rudra：**E2E panic 当前被上游折叠缺口屏蔽**——Rudra 的
  `RuleSubCommute::apply_op` 对 INT_SDIV/INT_SREM 臂标注 deferred
  （ruleaction.rs 注释 "INT_SDIV / INT_SREM deferred (need sign_extend
  helper)"），16 字节成语不重写、折叠不发生，`gen_decompile` 全管线跑完
  输出未折叠表达式（trap 形与常形皆然）。非 trap 双侧实证（g_div
  `100/-7`）：oracle 折成常量 `0xfffffffffffffff2`，Rudra 打印
  `SUB168(SEXT816(100) / SEXT816(-7),0)`。该缺口与本模块四个除法位点无关，
  已开票 **RULEACTION-SUBCOMMUTE-SDIV-SEXT16-0001**（见 TODO_BOARD）。
- 单测锁形：`tests/opbehavior_sdiv_panic.rs`（2 个 `#[should_panic]` 集成
  测试，直触 `opbehavior::evaluate_binary(CPUI_INT_SDIV/SREM,8,8,
  0x8000000000000000,0xFFFFFFFFFFFFFFFF)`——四个除法位点本身的崩溃形态由
  直触锁定，绕开上游缺口）。

**服务化边界注记（部署边界，非对齐缺陷）**：service 式 `catch_unwind` 包装下
Rudra panic 可捕获继续而 oracle SIGFPE 不可捕获=可观测分歧。oracle 无服务化
形态，故不构成对齐缺陷；服务化部署如需硬死对齐，应在 wrapper 层显式
`std::process::abort`/拒绝恢复，而非改本模块。

**B2 状态**：本条为崩溃形态裁决登记，oracle 侧无输出可比对（进程死），
四个除法位点保持 `UNTESTED→崩溃形态锁定`（`#[should_panic]` 为 Rust 侧回归
锁，不升 MATCH）。
