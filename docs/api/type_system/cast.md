# `type_system/cast.rs` API Reference

## 2026-09-27：castStandard typedef 剥离环（Lane TYPEDEFIMM，wt/typedefimm）

`cast_standard_full`（cast.cc:300-392）补齐 cc:325-328 的两条剥离环：
指针层同步下潜后、`findadd_equal` 基型比较前，`reqbase`/`curbase` 各自沿
per-type `typedef_imm` 通道（type.hh:196/244，工厂 `get_typedef` type.cc:3834
置位）走到根——"Different typedefs could point to the same type"（cast.cc:329）。
非 typedef 基型通道为空、立即停步，与 oracle 的 null `typedefImm` 恒等；外部
铸造的同名 look-alike（通道为空）不剥离，保持其 cast（实例键语义）。新增单测
`test_cast_standard_full_typedef_strip`（alias/base、链式 alias、size 门、
look-alike 负控）。

## 2026-08-30：arithmetic_output_standard（PTRSUB-SWITCH-CAST-RESIDUAL-0001 step 5）

新增 `pub fn arithmetic_output_standard(op, tlst)`（cast.cc:394
`CastStrategyC::arithmeticOutputStandard` 逐行投影；RUDRA-GLUE：自由函数传入
TypeFactory——Rudra 的 CastStrategyC 无 `tlst` 成员）：in0 high read-facing 起步，
BOOL 降为同尺寸 base int 且不参与竞争；后续输入 `type_order < 0`（更早=更大/更
specific：同尺寸 uint 优先于 int、大尺寸优先、指针优先于基型）时替换。消费方：
typeop 算术族 token 与 coreaction cast_output 分发。`is_char_type`/`is_enum_type`
改为 pub（markExplicitUnsigned 需要）。

## 2026-08-28：比较整数提升

补入 `localExtensionType`、`intPromotionType` 与
`checkIntPromotionForCompare` 的 reader-aware 投影：按常量唯一 reader、显式/定义
状态和各算术 opcode 的 signed/unsigned extension 位判定比较 cast。GetStr char/char
分支已复核；错误路径、跨架构 promote-size 与完整 CastStrategyC 仍按 TODO 保持
`MISMATCH/UNTESTED`，本节不维持旧的整模块 L3 口径。

## 文档状态

**2026-08-23 修复（GETSTR-ZERODIFF-D）**: `base_type_for` 补 `(Bool,1) => "bool"` 映射——Ghidra 比较类 op 的输出 token 是 TypeFactory 的 interned `bool` 基型（TypeOpFunc::getOutputLocal typeop.cc:365-380），旧 fall-through 把 1 字节 bool 标成 "long"。


- **状态**: 🔧 **L2（2026-08-28 当前权威口径）**——2026-07-02 的“完整 L3”结论
  已被后续 reader-facing、promotion、typedef/partial/enum、跨架构 promote-size 与
  错误路径缺口推翻。GetStr char/char 比较只是聚焦 `MATCH`；完整 CastStrategyC
  仍为 `MISMATCH/UNTESTED`，不得用单元测试数量恢复 L3 声明。
- **2026-08-17（PRINTC-SUBPIECE-FIELDEXTRACT-0001 缺口 c）**：`is_subpiece_cast` 输入白名单补齐 PartialStruct/PartialUnion 臂（cast.cc:416-418 逐字 `inmeta!=TYPE_PARTIALSTRUCT && inmeta!=TYPE_PARTIALUNION`），输出白名单与 PTR→int 特例补 enum 映射——Ghidra `TypeEnum` 构造器（type.hh:489-494）把存储 metatype 归一为 TYPE_INT/TYPE_UINT，故 Ghidra 的 enum 输入/输出以 UINT/INT 通过白名单；Rudra `TypeMetatype::Enum` 显式列入（与本文件 check_int_promotion_for_extension/compare 的既有约定一致）。真 oracle fixture（tests/oracle/printc_subpiece_fieldextract_1204）8 条 cast 记录逐字节 MATCH，新增 2 个单元测试（partial 臂 + enum 映射）。
- **2026-08-17 审计返工（REWORK #2）**：三白名单再补 `TypeMetatype::PartialEnum`——`TypePartialEnum` 构造器（type.cc:2255-2262）委托同一 TypeEnum 构造器归一化为 TYPE_UINT，Ghidra 的 partial-enum 与 plain enum 同样全过白名单（真 oracle 实测 `cast.int_partialenum_0=1`/`cast.partialenum_out_0=1`，fixture cast sweep 8→10 条）。


**源代码路径**: `src/type_system/cast.rs`

## 模块说明 (Module Doc)

Type casting and promotion strategies

Corresponds to Ghidra's `cast.hh`. This module defines the rules
for when explicit casts are required in the output C code and how
types are promoted during arithmetic operations.

## 导出的公共 API (Public API)

### `pub trait CastStrategy`

Interface for determining when a cast is necessary

Corresponds to Ghidra's `CastStrategy` class.

### `pub struct CastStrategyC`

Standard C-language casting strategy

Corresponds to Ghidra's `CastStrategyC` class.

### `pub fn new(promote_size: usize) -> Self`

*暂无代码注释*

### `pub fn get_promote_size(&self) -> usize`

Size of the `int` data-type (size that integers get promoted to). Ghidra
`CastStrategy::promoteSize`（cast.hh:57）为保护字段，在
`CastStrategy::setTypeFactory` 中一次性赋值（`promoteSize = tlst->getSizeOfInt()`，
cast.cc:27）；Ghidra 侧消费者（cast.cc:86/182/284）均为 strategy 成员函数直接读字段，
故无访问器。Rudra 的 cast.cc:284 消费者 `is_extension_cast_implied` 落在
printc.rs（`PrintC` impl），字段私有故跨模块读取需要本访问器——纯 Rust 可见性胶水，
无自身行为（PRINTC-PTRCONST-DAT-SYMBOL-0001 M4，2026-08-25）。
钉住测试：`test_get_promote_size_matches_constructor`。

### `pub fn base_type_for(size: usize, meta: TypeMetatype) -> Arc<Datatype>`

Build a base integer/unsigned type for a given size and metatype.
Faithful to Ghidra `TypeFactory::getBase(size, metatype)` (type.cc) for
the integer cases: size 1→char/byte, 2→short, 4→int, 8→long (signed) /
ulong (unsigned). Used by input-type-local to derive the type an op
expects for its input slot (`TypeOpBinary::getInputLocal`, typeop.cc:329-333).

### `pub fn cast_standard_full(&self, reqtype: &Arc<Datatype>, curtype: &Arc<Datatype>, care_uint_int: bool, care_ptr_uint: bool) -> Option<Arc<Datatype>>`

Faithful 1:1 port of Ghidra `CastStrategyC::castStandard` (cast.cc:300-392).
Determines whether an explicit cast is required when a varnode of
`curtype` feeds an op expecting `reqtype`.

- Returns `Some(reqtype)` if a cast IS needed (caller inserts CPUI_CAST),
  or `None` if no cast is needed.

2026-09-23 identity 语义修正（MATCHURL-SETCASTS-337-0001）：签名改为
`&Arc<Datatype>`，返回值 `Arc::clone(reqtype)` 保留调用方传入的 interned
对象身份（Ghidra 返回同一 interned `Datatype*`，cast.cc:303/307/392）；
开头的 `curtype == reqtype` 与剥层后的 `curbase == reqbase`
（cast.cc:302/329）用 `Arc::ptr_eq` 镜像。旧实现把两侧参数包进
`Arc::new(reqtype.clone())` 新对象，恒不等，下游依赖 interned 身份的
比较（如 castOutput 的 token==outHigh 短路，coreaction.cc:2544）永远
失效。
- `care_uint_int` — if true, distinguish signed/unsigned (under pointers);
  if false, treat int/uint interchangeably (most arithmetic ops).
- `care_ptr_uint` — if true, casting a pointer to an integer needs a cast
  (e.g. STORE value slot); if false, it's implied.

Handles: pointer-layer peeling (cast.cc:310-324), void conversion,
size-change casts (cast.cc:333-337), and the TYPE_UINT/TYPE_INT
metatype-specific same-size rules (cast.cc:339-389). Rudra's Datatype
lacks typedef chains, variable-length arrays, and per-pointer AddrSpace;
those branches are faithful no-ops.

2026-09-23 partial 免 cast 五臂补齐（CAST-PARTIAL-REQ-NOCAST-0001）：
oracle `CastStrategyC::castStandard` 对 TYPE_PARTIALSTRUCT/
TYPE_PARTIALUNION 有五处免 cast 点，Rudra 此前一处都没有（SB-FINALCAST
的移植范围未覆盖 partial 臂）：

1. **req 侧免 cast**（cast.cc:341-343）：partial 作为 cast 请求类型直接
   `return 0`——"As they are ultimately stripped, treat partials as
   undefined"。可观测影响：STORE 值槽 `pointedToType` 为 partial 片时
   （TypeOpStore::getInputCast slot2，typeop.cc:554
   `castStandard(pointedToType,valueType,false,true)`）不再插
   `(undefined8)` 前缀——main 的 `glob._296_8_ = (undefined8)uVar32`
   → 裸（golden 792 `uVar29`）、
   `glob.pattern[8].content.Set.elements/_8_8_` 两行同消。
2. **curmeta 侧四点**：uint !care 臂（cast.cc:348-349）、int !care 臂
   （cast.cc:366-367）的宽容名单补 `PartialStruct|PartialUnion`；
   uint/int care 臂的 `isptr &&` 子臂（cast.cc:356-357/374-375，"Don't
   cast pointers to unknown"）从仅 `Unknown` 扩为
   `Unknown|PartialStruct|PartialUnion`。

注意 `CastStrategyJava::castStandard`（cast.cc:471 起）有同形 partial
臂，但 Rudra 只移植 C 策略（CastStrategyC），Java 侧不在写域。新增
`test_cast_standard_full_partial_no_cast` 锁五臂（req/!care×2/isptr×2/
size 门控制组/非指针 care 控制组）。

2026-09-23 enum 元类型规范化（SETCASTS-COPYINPUT-0001）：req/cur 两侧
metatype 先经 `ghidra_meta` 规范化——`Enum→Int`、`PartialEnum→Uint`。
Oracle 依据：Ghidra `TypeEnum` 的全部构造路径都把 metatype 强制存为
TYPE_INT/TYPE_UINT（内联构造器 type.hh:491-494
`metatype = (m==TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT`，decode 路径
type.cc:1475 同转），枚举性由 ENUMTYPE flag 携带；cast.cc:347/363 的
"meta can be TYPE_INT/UINT ... if typedef/enumerated" 注释即此呈现。
因此 cast.cc:339-389 的 switch 永远看不到独立的枚举 metatype，其
TYPE_INT/TYPE_UINT 宽容臂（`!care_uint_int` 下 UNKNOWN/INT/UINT/BOOL
免 cast）对枚举同样生效。Rudra 的独立 `Enum` metatype（有符号默认，
cf. `get_submeta` 的 IntEnum 映射）若不规范化会落进 default 臂恒判
"需 cast"——修复前 main 的 9 条 `glob.pattern[i].type =
(URLPatternType)…` 过cast 与 `(int)::config.httpreq & …` 前缀均源于
此（golden 两处均无 cast）。

## 2026-09-26：恒等短路改 findAdd 等价键（CURLCANON-BOOLCAST-IDENTITY-0001）

`cast_standard_full` 开头的 `curtype == reqtype`（cast.cc:304）与剥层后
的 `curbase == reqbase`（cast.cc:329）两个恒等短路，从裸 `Arc::ptr_eq`
改为 `findadd_equal`：Base 变体按 **(name, size, sub-metatype)** 比较，
其余变体保持 Arc 身份。

Oracle 依据（机制 E 亲读）：Ghidra 的指针恒等比较骑在
`TypeFactory::findAdd` 的驻留不变量上——name+id 命中且
`compareDependency` 相等（base 标量即 (submeta, size)，type.cc:227-233）
时 findAdd **返回既有工厂对象**（type.cc:3423-3427），所以反编译器内
两个 (name, size, sub-metatype) 全同的 Datatype 对象不可能相遇；
cast.cc:304/:329 的指针比较因此 ⟺ 结构等价。Rudra 的导入/种子层会在
工厂外铸造结构等价的 base 标量（实测：非核心 "bool"/"byte" 克隆经
ActionInferTypes 传播，`Varnode::update_type` 亲证 6277 处附着全部
`core=false`），裸 ptr_eq 镜像在两实例相遇时误插 oracle 不会产生的
cast。锁定 golden 见证（ghidra_curl_1204.c:1755/2115 vs 修复前 canon）：
`if (aliases[iVar15].extraparam != false)` / `*usedarg == false` /
`pbVar1 = buffer;` 的裸形态要求 LOAD 地址臂/比较臂/COPY 臂在
bool-克隆 vs 工厂-bool 相遇时判等；修复前印
`*(bool *)&aliases[V].extraparam` / `*(bool *)usedarg` / `(bool *)buffer`。

`findadd_equal` 的键即 findAdd 等价键：name 相等 ⟹ id（hashName）相等，
compareDependency=(submeta, size)；`base_submeta` 折叠 chartype/enum/UTF
flag，故 TypeChar("char") 与普通 Int("char") 的 submeta 不同、判不等
（findAdd 会拒绝改定义，type.cc:3428-3429），非 Base 变体保持 Arc 身份
（复合体的 oracle 指针比较）。新增
`test_findadd_equal_base_key`（键四臂：等价/异名/异 submeta/异尺寸）与
`test_cast_standard_structurally_equal_base_no_cast`（bool-克隆双向免
cast + 指针剥层免 cast + bool vs char 仍插 cast）。

铸造源头本身（ActionInferTypes 传播非正典 bool 克隆）登记
`COREACTION-BOOLMINT-FACTORY-UNIFY-0001`（coreaction 域，待并分支
释放后统一到工厂对象；本修复使 cast 决策对实例分裂不敏感，与 oracle
对每个可产生输入的行为等价）。


<!-- annotation-pass: 2026-07-04 -->

## 2026-09-22：int_promotion_type 可见性 pub（SB-ORD332-SETCASTS-0001）

`CastStrategyC::int_promotion_type`（cast.cc:178）可见性 private → pub：
coreaction.rs 的 ActionSetCasts::cast_input 新移植的 getInputCast 覆写臂
（TypeOpIntRight/Sright slot0 的 UNSIGNED/SIGNED_EXTENSION 门、TypeOpIntZext/
Sext 的 checkIntPromotionForExtension、TypeOpIntDiv/Sdiv/Rem/Srem 的同族门）
直接消费该扩展码，与 CastStrategyC 自家 checkIntPromotionForCompare_op 同一
访问层级。语义零改动（纯可见性）。
