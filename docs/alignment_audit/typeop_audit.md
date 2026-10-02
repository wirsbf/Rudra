# typeop 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 2572行 (`typeop.cc`) / Rudra: 2153行 (`src/typeop.rs`) / 比率: 83%

Ghidra 头文件 `typeop.hh` 声明的内联/虚方法（`push`/`printRaw`/`getOutputLocal`/`getInputLocal`/`getOutputToken`/`getInputCast`/`propagateType`/`getOpcode`/`getName`/`getFlags` 等）一并纳入。

## 设计说明（重要架构偏差）
Ghidra 用 `TypeOp` 抽象基类 + 约 60 个 `TypeOpXxx` 子类（每个子类 override `push`/`printRaw`/`getOutputLocal` 等）；Rudra 用 `TypeOp` trait + struct 实现，并通过 `binary_op!`/`unary_op!`/`functional_binary_op!`/`functional_unary_op!`/`compare_op_impl!`/`signed_compare_op_impl!` 六个宏批量生成算术/逻辑/比较/浮点子类，手写 struct 仅留给有特殊类型传播逻辑的少数 op（Copy/Load/Store/Call/Ptradd/Ptrsub/Multi/Indirect/IntAdd 等）。`TypeOpManager`（Rudra）承载 Ghidra 的 `inst` 表与 `registerInstructions`。所有宏生成入口均带 `// Ghidra:` 注释，符合对齐铁律。

## 已对齐函数 (按类统计)

### TypeOp 基类 / trait (8)
- `TypeOp::get_opcode` — Ghidra: typeop.hh:71 `getOpcode` ✅
- `TypeOp::get_name` — Ghidra: typeop.hh:70 `getName` ✅
- `TypeOp::get_flags` — Ghidra: typeop.hh:72 `getFlags` ✅
- `TypeOp::print_raw` — Ghidra: typeop.hh:176 `printRaw` ✅
- `TypeOp::push` — Ghidra: typeop.hh:170 `push` ✅ (trait 默认 + 各子类 override)
- `TypeOp::get_output_local` — Ghidra: typeop.hh:149 `getOutputLocal` ✅
- `TypeOp::get_input_local` — Ghidra: typeop.hh:152 `getInputLocal` ✅
- `TypeOp::get_output_token` — Ghidra: typeop.hh:155 `getOutputToken` ✅
- `TypeOp::get_input_cast` — Ghidra: typeop.hh:158 `getInputCast` ✅
- `TypeOp::propagate_type` — Ghidra: typeop.hh:161 `propagateType` ✅
- `TypeOp::propagate_to_pointer` — Ghidra: typeop.cc:186 `propagateToPointer` ✅
- `TypeOp::propagate_from_pointer` — Ghidra: typeop.cc:206 `propagateFromPointer` ✅
- `TypeOp::registerInstructions` — Ghidra: typeop.cc:24 ✅ (在 `TypeOpManager::new` 内联实现，合理)

### TypeOpBinary / TypeOpUnary / TypeOpFunc (基类, 6)
- `TypeOpBinary::print_raw` — Ghidra: typeop.cc:335 ✅
- `TypeOpBinary::get_output_local` — Ghidra: typeop.cc:323 ✅
- `TypeOpBinary::get_input_local` — Ghidra: typeop.cc:329 ✅
- `TypeOpUnary::print_raw` — Ghidra: typeop.cc:357 ✅
- `TypeOpUnary::get_output_local` — Ghidra: typeop.cc:345 ✅
- `TypeOpUnary::get_input_local` — Ghidra: typeop.cc:351 ✅
- `TypeOpFunc::print_raw` — Ghidra: typeop.cc:377 ✅
- `TypeOpFunc::get_output_local` — Ghidra: typeop.cc:365 ✅
- `TypeOpFunc::get_input_local` — Ghidra: typeop.cc:371 ✅

### 手写 struct 子类 (含 printRaw/push/getOutputLocal/getInputLocal/getOutputToken/getInputCast/propagateType)
- `TypeOpCopy` ✅ (printRaw cc:425, push hh:261, getOutputToken cc:405, propagateType cc:411, getInputCast cc:397)
- `TypeOpLoad` ✅ (printRaw cc:502, push hh:274, getOutputToken cc:472, propagateType cc:487, getInputCast cc:440)
- `TypeOpStore` ✅ (printRaw cc:572, push hh:286, propagateType cc:557, getInputCast cc:520)
- `TypeOpBranch` ✅ (printRaw cc:590)
- `TypeOpCbranch` ✅ (printRaw cc:621, getInputLocal cc:609)
- `TypeOpBranchind` ✅ (printRaw cc:653)
- `TypeOpCall` ✅ (printRaw cc:667, push hh:319, getInputLocal cc:687, getOutputLocal cc:720)
- `TypeOpCallind` ✅ (printRaw cc:791, getInputLocal cc:745)
- `TypeOpCallother` ✅ (printRaw cc:818)
- `TypeOpReturn` ✅ (printRaw cc:882, push hh:350)
- `TypeOpPtradd` ✅ (printRaw cc:2283, getOutputLocal cc:2238, getInputLocal cc:2232)
- `TypeOpPtrsub` ✅ (printRaw cc:2380, getOutputLocal cc:2308)
- `TypeOpMulti` ✅ (printRaw cc:1967, push hh:758, propagateType cc:1951)
- `TypeOpIndirect` ✅ (printRaw cc:2022, push hh:769, propagateType cc:2005)
- `TypeOpSegment` ✅ (printRaw cc:2397)
- `TypeOpCpoolref` ✅ (printRaw cc:2471)
- `TypeOpNew` ✅ (printRaw cc:2511)
- `TypeOpIntAdd` ✅ (printRaw 二元继承, push hh:439, getOutputToken cc:1175, propagateType cc:1181)

### 宏生成子类 (printRaw/push/getOutputLocal/getInputLocal 由宏统一提供，对应 Ghidra TypeOpBinary/Unary/Func 基类逻辑)
- 算术: `TypeOpIntSub`/`TypeOpIntMult`/`TypeOpIntDiv`/`TypeOpIntSdiv`/`TypeOpIntRem`/`TypeOpIntSrem`/`TypeOpIntNeg`(INT_2COMP)/`TypeOpIntCarry`/`TypeOpIntScarry`/`TypeOpIntSborrow` ✅
- 位运算: `TypeOpIntAnd`/`TypeOpIntOr`/`TypeOpIntXor`/`TypeOpIntNot`(INT_NEGATE)/`TypeOpIntLeft`/`TypeOpIntRight`/`TypeOpIntSright` ✅ (注: IntSright 用通用二元 printRaw，缺 Ghidra 自定义的有符号 `(int)` cast 打印)
- 比较: `TypeOpIntEqual`/`TypeOpIntNotEqual`/`TypeOpIntLess`/`TypeOpIntLessEqual`/`TypeOpIntSless`/`TypeOpIntSlessEqual` ✅ (含 getInputCast/propagateType 特化)
- 扩展: `TypeOpIntZext`/`TypeOpIntSext` ✅ ; `TypeOpTrunc`(SUBPIECE) ✅
- 浮点 (16个全部): `TypeOpFloatAdd`/`TypeOpFloatSub`/`TypeOpFloatMult`/`TypeOpFloatDiv`/`TypeOpFloatNeg`/`TypeOpFloatAbs`/`TypeOpFloatSqrt`/`TypeOpFloatEqual`/`TypeOpFloatNotEqual`/`TypeOpFloatLess`/`TypeOpFloatLessEqual`/`TypeOpFloatNan`/`TypeOpFloatFloat2Float`/`TypeOpFloatInt2Float`/`TypeOpFloatTrunc`/`TypeOpFloatCeil`/`TypeOpFloatFloor`/`TypeOpFloatRound` ✅
- 布尔: `TypeOpBoolAnd`/`TypeOpBoolOr`/`TypeOpBoolXor`/`TypeOpBoolNot` ✅
- 特殊: `TypeOpPiece`/`TypeOpSubpiece`/`TypeOpPopcount`/`TypeOpLzcount` ✅
- 现代: `TypeOpInsert`/`TypeOpExtract` ✅

## 缺失函数 (12个)

### TypeOp 基类 — 缺失 3 个
- `TypeOp::selectJavaOperators` — Ghidra: typeop.cc:114 — 优先级: 低 — 为 Java 目标语言切换部分算子的显示名（如 `!=` 改 `^`）。Rudra 无 Java 后端，缺失不影响 C 输出。
- `TypeOp::floatSignManipulation` — Ghidra: typeop.cc:153 — 优先级: 中 — 判定一个浮点 op 是否为"符号位操作"（用于 float 符号优化）。Rudra 缺失，影响浮点符号化简规则。
- `TypeOp::isCommutative` — Ghidra: typeop.cc:252 — 优先级: 中 — 判定算子是否可交换（用于重排操作数以触发其它规则）。Rudra 缺失，影响依赖交换律的化简（如 `a+b → b+a` 对齐）。

### 缺失整个子类 (1个)
- `TypeOpCast` — Ghidra: typeop.cc:2209 (`TypeOpCast::TypeOpCast`) / typeop.hh:780 — 优先级: **高** — `CPUI_CAST` 的类型算子。`TypeOpManager` 注册表无 `CPUI_CAST` 条目（typeop.rs:1948-1966 注册段未包含），任何 CAST op 的 `push`/`printRaw`/类型传播都无入口。Ghidra 中 CAST 用于显式类型转换的打印（`(type)x`），缺失会导致带显式 cast 的输出退化为裸 op。

### 子类特有方法 — 缺失 8 个
- `TypeOpIntSright::printRaw` — Ghidra: typeop.cc:1575 — 优先级: 中 — 有符号右移的特化打印：对有符号输入加 `(int)` cast。Rudra 用通用二元 printRaw（输出 `a s>> b`），丢失了符号提示 cast，可能影响可读性。
- `TypeOpCallother::getOperatorName` — Ghidra: typeop.cc:837 — 优先级: **高** — 从用户操作表查询 callother 的实际名字（如 `strncpy`/`memcpy`）。Rudra `printRaw` 直接打 `callother(...)`，不查 UserOpManage，导致 CALLOTHER 输出无意义数字而非函数名。constseq 模块生成的 strncpy/memcpy CALLOTHER 会受影响。
- `TypeOpIntZext::getOperatorName` — Ghidra: typeop.cc:1122 — 优先级: 低 — ZEXT 的算子名（带 `(uint)` cast 描述）。Rudra 用静态名 "INT_ZEXT"。
- `TypeOpIntSext::getOperatorName` — Ghidra: typeop.cc:1148 — 优先级: 低 — SEXT 的算子名（带 `(int)` cast 描述）。
- `TypeOpIntCarry::getOperatorName` — Ghidra: typeop.cc:1340 — 优先级: 低
- `TypeOpIntScarry::getOperatorName` — Ghidra: typeop.cc:1356 — 优先级: 低
- `TypeOpIntSborrow::getOperatorName` — Ghidra: typeop.cc:1372 — 优先级: 低
- `TypeOpPiece::getOperatorName` — Ghidra: typeop.cc:2048 — 优先级: 低 — PIECE 算子名（描述拼接的位宽）。
- `TypeOpSubpiece::getOperatorName` — Ghidra: typeop.cc:2127 — 优先级: 低 — SUBPIECE 算子名（描述截断的位置）。
- `TypeOpIntAdd::propagateAddPointer` — Ghidra: typeop.cc:1268 — 优先级: **高** — INT_ADD 涉及指针时的偏移传播算法（区分基指针与常量偏移分量）。Rudra `TypeOpIntAdd::propagate_type` 用简化逻辑，未实现完整的指针+偏移分解，可能导致指针算术的类型传播不精确。
- `TypeOpFloatInt2Float::preferredZextSize` — Ghidra: typeop.cc:1891 — 优先级: 低 — int→float 转换的优先零扩展尺寸。Rudra 缺失。
- `TypeOpPiece::computeByteOffsetForComposite` — Ghidra: typeop.cc:2104 — 优先级: 中 — 计算 PIECE 在复合类型中的字节偏移（用于结构体字段重建）。Rudra 缺失，影响复合类型重组。
- `TypeOpSubpiece::computeByteOffsetForComposite` — Ghidra: typeop.cc:2195 — 优先级: 中 — 同上，针对 SUBPIECE。

## 高优先级缺失清单 (4个)
1. **`TypeOpCast` 整个类** (typeop.cc:2209) — `CPUI_CAST` 无任何处理入口，显式类型转换无法正确打印与传播
2. **`TypeOpCallother::getOperatorName`** (typeop.cc:837) — CALLOTHER 不查 UserOpManage 名字，strncpy/memcpy 等内置调用打印为无意义内容
3. **`TypeOpIntAdd::propagateAddPointer`** (typeop.cc:1268) — 指针算术类型传播不精确，影响指针变量类型推断
4. **`TypeOpPiece/Subpiece::computeByteOffsetForComposite`** (typeop.cc:2104/2195) — 复合类型字段偏移计算缺失，影响结构体重建

## 说明
- 约 50 个宏生成的 TypeOp 子类均带正确的 `// Ghidra:` 注释（指向各自 opcode 与 Ghidra 的 printRaw/push 行），其 `push` 用通用 dispatch（`lng.op_binary`/`op_unary`）替代 Ghidra 的逐子类 override，输出等价，属合理 Rust 适配。
- `TypeOpIntZext/Sext/Carry/Scarry/Sborrow/Piece/Subpiece::getOperatorName` 在 Rudra 中以 trait 方法 `get_name` 返回静态字符串替代，但 Ghidra 的 `getOperatorName` 是 per-op 动态的（依赖具体 op 的位宽/类型），故列为部分缺失（低优先级）。
- 构造函数（各 `TypeOpXxx::TypeOpXxx`）在 Rudra 中由 struct 字段 + 宏承担，无 1:1 对应，不计为缺失。
- `TypeOp::registerInstructions` 在 `TypeOpManager::new` 中内联，属合理。
