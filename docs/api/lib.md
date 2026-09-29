# `lib.rs` API Reference

The crate root exports `debugproto`, the native Program-import boundary that
supplies DWARF-declared, locked `FuncProto` values before the Action pipeline.
This mirrors Ghidra's separation between its front-end DWARF analyzer and the
C++ decompiler; it does not move DWARF parsing into `ActionInputPrototype`.
The crate root also exports `frontend`, the native ELF front-end boundary
(symbol import / function discovery / PT_LOAD memory map / demangling —
FRONTEND-MINIMAL-0001; see `docs/api/frontend.md`).

**源代码路径**: `src/lib.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **可信度**: 高
- **适用范围**: 本文档描述的是当前库入口中**实际可见的模块导出与重导出**，以及它们在工程中的作用
- **特别说明**: 旧版 `Decompiler` 相关说明目前只能作为**历史设计痕迹**理解，**不能**再被当成当前稳定可用的主入口 API

---

## 模块说明 (Module Doc)

`lib.rs` 是 `rugra` 的库入口文件，负责：

1. 声明和导出当前主线模块
2. 暴露跨模块共享的基础类型
3. 通过 `pub use` 提供更方便的库级访问路径
4. 作为整个反编译分析框架的公共入口层

从当前代码可见结构来看，`rugra` 的主线已经转向：

- Ghidra 风格核心对象建模
- `Funcdata` 驱动的函数级分析上下文
- `PcodeOp` / `Varnode` / `Address` 等基础 IR 与寻址对象
- `ActionDatabase` 风格的分析/变换流水线
- `PrintLanguage` / `PrintC` 输出链路
- `align/` 下的对齐验证与运行时验证框架

---

## 当前实际导出的模块 (Public Modules)

以下模块在当前 `lib.rs` 中以 `pub mod` 形式公开导出。

### 核心 Ghidra 对齐对象层

- `address`
- `space`
- `varnode`
- `op`
- `opcodes`
- `typeop`
- `heritage`
- `fspec`
- `block`
- `funcdata`
- `pcoderaw`
- `type_system`
- `prettyprint`
- `printlanguage`
- `printc`
- `action`
- `coreaction`
- `ruleaction`
- `cover`
- `variable`
- `merge`
- `modelrules` — modelrules.hh/cc 原型模型规则（PrimitiveExtractor/DatatypeFilter/QualifierFilter/AssignAction/ModelRule，2026-07-22 Phase 1）
- `blockaction`
- `double_precis` — double.cc 双精度合并（SplitVarnode + RuleDouble*，2026-07-01）

### 现存但处于过渡/兼容阶段的模块

- `binary`
- `disasm`
- `ffi`
- `align`

> 注意：这些模块当前确实由 `lib.rs` 公开导出，但其“是否已经完整、稳定、面向最终用户可直接使用”应以对应源码与状态文档为准，不能仅凭导出存在就推断“能力已全部完成”。

---

## 当前实际私有模块 (Private Modules)

以下模块在 `lib.rs` 中作为内部实现使用，并未以 `pub mod` 形式完整暴露：

- `error`
- `types`
- `utils`

不过其中部分内容通过 `pub use` 被重新导出，见下文。

---

## 当前实际重导出 (Re-exports)

`lib.rs` 当前使用 `pub use` 暴露了以下常用类型和结果别名。

### 错误与结果

### `pub use error::{Error, Result};`

为库使用者提供统一的错误类型与结果别名。

**用途**：
- 统一库内部与外部调用的错误返回风格
- 让上层调用者可以直接使用 `rugra::Result`

---

### 地址与范围相关

### `pub use address::{Address, SeqNum, Range, RangeList, RangeProperties};`

导出基础寻址与范围对象。

#### `Address`
用于表示带地址空间语义的地址。

#### `SeqNum`
用于标识操作在地址和顺序上的锚点。

#### `Range`
表示一个地址范围。

#### `RangeList`
表示多个地址范围的集合。

#### `RangeProperties`
与范围属性相关的辅助类型。

**用途**：
- 这些类型贯穿 `Varnode`、`PcodeOp`、CFG、打印与验证等多个阶段
- 是库级最基础的公共类型之一

---

### 控制流图块相关

### `pub use block::{BlockBasic, BlockRef, BlockEdge};`

导出 block 层的核心类型。

#### `BlockBasic`
函数控制流图中的基本块表示。

#### `BlockRef`
对 block 对象的引用包装。

#### `BlockEdge`
块之间的边关系表示。

**用途**：
- CFG 构建
- 支配关系、循环识别等后续分析
- 结构化输出前的控制流组织

---

### 函数级核心对象

### `pub use funcdata::Funcdata;`

导出 `Funcdata` 作为函数级分析上下文的核心入口对象。

**用途**：
- 承载单函数的 IR、block、varnode、操作与分析状态
- 作为后续 Action/Rule/Print 流程的中心对象

**当前定位**：
- 从现有代码结构看，`Funcdata` 是当前主链路中最关键的公共对象之一

---

### 函数原型相关

### `pub use fspec::{FuncProto, ProtoParameter};`

导出函数签名与参数描述相关类型。

#### `FuncProto`
函数原型对象。

#### `ProtoParameter`
函数参数描述对象。

**用途**：
- 函数签名恢复
- 调用约定和参数建模
- 输出层的函数头部生成

---

### 地址空间

### `pub use space::AddressSpace;`

导出地址空间枚举或对应抽象类型。

**用途**：
- 区分 RAM / register / unique / const 等空间
- 驱动 `Varnode` 与打印逻辑的空间语义

---

### P-code 操作码

### `pub use opcodes::OpCode;`

导出 P-code 操作语义枚举。

**用途**：
- 所有规则、分析、打印逻辑的语义分支基础
- 运行时与静态对齐时的重要公共字典

---

### 架构类型

### `pub use types::Architecture;`

导出目标架构类型。

**用途**：
- 标识当前分析对象属于哪种目标架构
- 与反汇编、提升和旧设计中的高层入口有关

**注意**：
- 该类型当前确实是公共导出的一部分
- 但与它一起出现的旧版“高层 Decompiler API”并不是当前稳定主入口

---

### 类型系统相关

### `pub use type_system::{Datatype, TypeMetatype};`

导出统一类型系统中的基础类型。

#### `Datatype`
统一数据类型对象。

#### `TypeMetatype`
类型元类别信息。

**用途**：
- 类型传播
- 类型恢复
- 输出层的类型表达

---

## 当前推荐理解方式

从当前 `lib.rs` 结构看，`rugra` 更适合被理解为：

> 一个以 `Funcdata`、`Varnode`、`PcodeOp`、`ActionDatabase`、`PrintC` 等对象为核心组织方式的反编译分析框架入口

而不是：

> 一个已经稳定暴露“单一高层 `Decompiler` 对象”的成熟终端库 API

---

## `lib.rs` 中关于旧版 `Decompiler` 的说明

当前 `lib.rs` 中保留了一大段被注释掉的旧版 `Decompiler` 设计代码。这部分内容包括：

- `pub struct Decompiler`
- `new`
- `load_binary`
- `decompile_function`
- `get_functions`
- `get_function_name`
- `architecture`
- `clear_cache`
- 以及基于旧 `Program` 架构的内部缓存与生成逻辑

### 这部分应该如何理解

这段内容目前应被视为：

- **历史设计痕迹**
- **旧架构说明**
- **未来可能重建的高层入口参考**
- **迁移期保留的注释代码**

### 不应如何理解

这段内容目前**不应**再被当成：

- 当前有效的公开 API
- 当前稳定可用的主入口
- 当前 README 中可以直接示例调用的正式接口
- 当前已对外承诺的库能力

### 文档处理原则

因此，本文档**不再**把 `Decompiler` 写成“当前公开 API”条目。  
如果后续该类型重新在源码中以真实、未注释、可编译、可测试的形式恢复，再应当重新纳入本文件的公共 API 说明中。

---

## 当前可见的库级使用方式

结合当前 `lib.rs` 的真实导出结构，更接近当前代码状态的库使用思路是：

1. 使用基础对象：
   - `Address`
   - `AddressSpace`
   - `OpCode`
   - `Datatype`
2. 构造或维护函数级上下文：
   - `Funcdata`
3. 在 `Funcdata` 上组织：
   - raw p-code 注入
   - block / SSA / heritage 处理
   - Action/Rule 分析
4. 最终通过：
   - `PrintLanguage`
   - `PrintC`
   输出 C 风格结果

换句话说，当前公共入口更偏向“对象组合式框架”，而不是“单一 facade 式反编译器对象”。

---

## 与当前库入口最相关的模块

如果你从 `lib.rs` 出发继续阅读源码，建议优先关注：

1. `funcdata.rs`
2. `varnode.rs`
3. `op.rs`
4. `opcodes.rs`
5. `address.rs`
6. `block.rs`
7. `heritage.rs`
8. `action.rs`
9. `printlanguage.rs`
10. `printc.rs`

这些模块最能体现当前真实主线。

---

## 文档可信度提示

### 当前可以确认的
- 上文列出的 `pub mod` 与 `pub use` 来自当前 `lib.rs` 的真实可见结构
- `VERSION` 常量当前仍为真实存在的公共导出项
- 注释掉的 `Decompiler` 当前不是有效公共 API

### 当前不能从 `lib.rs` 单独推导出的
- CLI 已完整可用
- 端到端输出已稳定
- 与 Ghidra 已完成运行时一致性验证
- 旧架构示例代码仍适合直接复制使用

这些结论需要结合以下文档一起判断：

- `docs/README.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- `docs/VERIFICATION_GUIDE.md`

---

## 当前仍有效的公共常量

### `pub const VERSION: &str = env!("CARGO_PKG_VERSION")`

**说明**：
- 当前库版本字符串
- 直接来自 Cargo 包元信息

**用途**：
- 版本显示
- 调试与元信息输出

---

## 总结

当前 `lib.rs` 的最准确文档结论是：

1. 它是 **Rugra 当前真实公共模块与核心类型的导出入口**
2. 它反映的是 **以 Ghidra 风格对象建模为中心的库结构**
3. 它**不再**支持把旧版注释掉的 `Decompiler` 视为当前主入口
4. 使用 `rugra` 时，应优先从：
   - `Funcdata`
   - `Address`
   - `Varnode`
   - `PcodeOp`
   - `OpCode`
   - `Datatype`
   等当前真实导出对象理解整个框架

如果后续 `lib.rs` 重新恢复高层 facade API，本文档应同步更新；在此之前，任何继续把旧 `Decompiler` 当作当前公开主接口的说明，都应视为过期描述。
### 2026-06-24：analysis 模块

- 新增 `pub mod analysis` 包含 type_infer（保守 ActionTypePropagate）。

### 2026-06-26：新增 tracedag 模块

- 添加 `pub mod tracedag;` — Ghidra TraceDAG (blockaction.cc:499-1014) 的 Rust 移植骨架。
- 追踪控制流图找 likely goto 边，当前已禁用（需完整 BadEdgeScore + visit-count）。

### 2026-06-26：新增 varmap 模块

- 添加 `pub mod varmap;` — Ghidra varmap.cc (1620行) 的 Rust 移植。
- RangeHint + AliasChecker + MapState + ScopeLocal 骨架已实现。
- 尚未集成到 codegen/printc.rs。

## 2026-06-26：新增 expression 模块

- `pub mod expression;` — 对应 `expression.hh`，TermOrder/AdditiveEdge/AddExpression。

## 2026-06-26（续）：新增 condexe 模块

- `pub mod condexe;` — 对应 `condexe.hh`，条件执行简化。ActionConditionalExe 骨架已实现。

## 2026-06-26（续）：新增 transform 模块

- `pub mod transform;` — 对应 `transform.hh`，大规模数据流变换。LanedRegister/LaneDescription/TransformVar/TransformOp 已实现。

## 2026-06-26（续）：新增 subflow 模块

- `pub mod subflow;` — 对应 `subflow.hh`，子流分析。ReplaceVarnode/ReplaceOp/PatchRecord/SubvariableFlow 骨架已实现。

## 2026-06-26（续）：新增 unify 模块

- `pub mod unify;` — 对应 `unify.hh`，统一化模式匹配。UnifyState/RHSConstant/UnifyConstraint 骨架已实现。

## 2026-06-26（续）：新增 constseq 模块

- `pub mod constseq;` — 对应 `constseq.hh`，常量序列分析。WriteNode/ArraySequence/StringSequence/HeapSequence/RuleStringCopy/RuleStringStore 骨架已实现。

## 2026-06-26（续）：新增 opbehavior 模块

- `pub mod opbehavior;` — 对应 `opbehavior.hh`，P-code 操作行为模拟。evaluate_unary/evaluate_binary 覆盖 25+ opcode。

## 2026-06-26（续）：新增 rangeutil 模块

- `pub mod rangeutil;` — 对应 `rangeutil.hh`，CircleRange 整数值范围分析。核心构造/包含/交集/并集/迭代已实现。

## 2026-06-26（续）：新增 userop 模块

- `pub mod userop;` — 对应 `userop.hh`，CALLOTHER 用户操作管理。UserPcodeOp/UserOpType/UserOpManage 已实现。

## 2026-06-26（续）：新增 memstate 模块

- `pub mod memstate;` — 对应 `memstate.hh`，内存状态。MemoryBank/MemState 已实现（set/get value/chunk + construct/deconstruct）。

## 2026-06-26（续）：新增 float_emulate 模块

- `pub mod float_emulate;` — 对应 `float.hh`，浮点格式编解码。FloatFormat IEEE754 单/双精度 + 15 个 op 操作已实现。

## 2026-06-26（续）：新增 pcodeinject 模块

- `pub mod pcodeinject;` — 对应 `pcodeinject.hh`，P-code 注入引擎。InjectParameter/InjectPayload/PcodeInjectLibrary 已实现。

## 2026-06-26（续）：新增 emulate 模块

- `pub mod emulate;` — 对应 `emulate.hh`，P-code 模拟执行。Emulate 骨架 + execute_op 使用 opbehavior。

## 2026-06-26（续）：新增 callgraph 模块

- `pub mod callgraph;` — 对应 `callgraph.hh`，调用图。CallGraphEdge/CallGraphNode/CallGraph 完整实现（add_node/add_edge/find_node/init_leaf_walk）。

## 2026-06-26（续）：新增 signature 模块

- `pub mod signature;` — 对应 `signature.hh`，函数签名匹配。Signature/SignatureEntry/SignatureDB 骨架已实现。

## 2026-06-26（续）：新增 jumptable 模块

- `pub mod jumptable;` — 对应 `jumptable.hh`，跳转表恢复。LoadTable/PathMeld/GuardRecord/JumpValues(+Range/RangeDefault)/JumpModel trait/JumpModelTrivial/JumpBasic/JumpTable/EmulateFunction 全部数据结构 + 守卫分析 + 最小规范化变量查找。L3 缺 Varnode::def 深度遍历、emulate_path 地址计算、pullBack、CFG 重写。

## 2026-06-27：新增 override_rs / arch / database 模块

- `pub mod override_rs;` — 对应 `override.hh`，覆写命令容器。Override + FlowOverride 完整 in-memory 实现（forcegoto/deadcodedelay/indirectover/protoover/multistagejump/flowoverride）。L3 缺 XML encode/decode。
- `pub mod arch;` — 对应 `architecture.hh`，Ghidra Architecture 配置容器 + ArchitectureCapability trait + CapabilityRegistry。所有配置字段 + 默认值完整。L3 缺虚拟工厂钩子（buildTranslator/buildLoader 等）+ XML decode。
- `pub mod database;` — 对应 `database.hh`，符号表。SymbolEntry/Symbol/FunctionSymbol/EquateSymbol/LabSymbol/Scope/Database 全部数据结构 + in-memory 查询/插入算法。L3 缺 XML encode/decode + rangemap/partmap。

## 2026-06-27（续）：Varnode::def 深度遍历基础设施 + jumptable L3 推进

- **`varnode.rs` 新增 def/descend/flag 访问器**：`get_def()`（升级 Weak→Arc，对应 varnode.hh:213）、`is_read_only()`（varnode.hh:243）、`is_annotation()`（varnode.hh:237）、`is_spacebase()`、`is_persist_global()`、`descend_iter()`（beginDescend/endDescend，varnode.hh:219-220）、`count_descends()`、`add_descend()`（varnode.hh:295）、`is_bool_output_def()`（getDef()->isBoolOutput）。
- **`op.rs` 新增**：`is_marker()`（op.hh:185）、`is_bool_output()`（op.hh:190）。
- **`address.rs` 新增**：`coveringmask(val)`（address.cc:760）、`minimalmask(val)`。
- **`jumptable.rs` L3 推进**：`find_determining_varnodes` 现在执行完整的 def-chain DFS 深度遍历（不再 break）；`is_prune` 检查 def 的 isCall/isMarker/numInput==0；`is_point` 检查 isAnnotation/isReadOnly；`quasi_copy` 完整遍历 COPY/INT_AND/INT_OR/INT_SEXT/INT_ZEXT/PIECE/SUBPIECE 链；`get_max_value` 检查 INT_AND/MULTIEQUAL 的常量掩码；`is_load_in_path` 通过 get_def() 检测 LOAD。剩余 L3 缺：emulate_path、pullBack、CFG 重写。

## 2026-06-27（续 2）：CircleRange pullBack 全套 + jumptable 守卫扩展/backup2Switch/findUnnormalized

- **`rangeutil.rs`**：CircleRange 新增 `complement`/`convert_to_boolean`/`set_nz_mask`/`pull_back_unary`/`pull_back_binary`（rangeutil.cc:38-1003）。自由函数 `bit_transitions`/`sign_extend_size`。
- **`jumptable.rs`**：`pull_back_through_op` 自由函数（rangeutil.cc:1022；**2026-09-23 已删除**，jumptable 两调用点改走正典 `CircleRange::pull_back` + discard markup 槽，见 docs/api/jumptable.md 该日小节）；JumpBasic 的 `analyze_guards` 现执行 pullBack 扩展循环；`backup2_switch` 反向模拟；`find_unnormalized` 完整链遍历；`flows_only_to_model`；`build_labels` 使用 backup2_switch。11 个新测试。

## 2026-06-27（续 3）：新增 marshal 模块（XML 序列化基础设施）

- `pub mod marshal;` — 对应 `marshal.hh` + `xml.hh`，序列化基础设施。AttributeId/ElementId 注册表 + Element/Document DOM 树 + Encoder/Decoder trait + TreeEncoder/TreeDecoder 内存实现（完整 round-trip）。解锁 database.rs/override.rs/arch.rs 的 XML encode/decode L3 缺口。L3 缺 PackedEncode/PackedDecode 二进制格式 + XML 文本解析。

## 2026-06-27（续 4）：新增 comment 模块

- `pub mod comment;` — 对应 `comment.hh`，注释数据库。Comment + comment_type 标志 + CommentDatabaseInternal（add_comment/clear_type/comments_for_function/encode/decode）+ CommentSorter（setup_function_list/header_comments）+ Subsort。L3 缺 CommentSorter::findPosition 的基本块关联（需 Funcdata op-tree）。

## 2026-06-27（续 5）：新增 options 模块

- `pub mod options;` — 对应 `options.hh`，架构配置选项系统。ArchOption trait + OptionDatabase 分发器 + 37 个注册选项。9 个选项完全功能化（直接修改 Architecture 字段：inferconstptr/analyzeforloops/readonly/jumptablemax/maxinstruction/aliasblock/nanignore/splitdatatype/defaultprototype），其余为 stub（待 PrintLanguage/ActionDatabase 集成）。

## 2026-06-27（续 6）：新增 loadimage 模块

- `pub mod loadimage;` — 对应 `loadimage.hh`，二进制加载镜像。LoadImage trait（load_fill/load/load_value/get_arch_type/adjust_vma + symbols/sections/readonly）+ RawLoadImage（从文件读取）+ MemoryLoadImage（内存缓冲）。解锁 EmulateFunction::getLoadImageValue、JumpBasic::sanityCheck、Architecture::loader。

## 2026-06-27（续 7）：新增 capability 模块

- `pub mod capability;` — 对应 `capability.hh`，扩展点注册系统。CapabilityPoint trait（initialize）+ CapabilityRegistry（register/initialize_all/num_points）+ global_registry 单例。是 ArchitectureCapability/PrintLanguageCapability 等扩展点的基础。

## 2026-06-27（续 8）：新增 stringmanage 模块

- `pub mod stringmanage;` — 对应 `stringmanage.hh`，字符串解码管理。StringManager + StringManagerUnicode（LoadImage 集成）+ 完整 UTF8/UTF16/UTF32 解码（write_utf8/read_utf16/get_codepoint/check_characters/has_char_terminator/write_unicode/assign_string_data）。解锁 Architecture::stringManager。L3 缺 XML encode/decode。

## 2026-06-27（续 9）：新增 cpool 模块

- `pub mod cpool;` — 对应 `cpool.hh`，常量池（Java 字节码）。CPoolRecord（tag/token/value/type/byte_data + constructor/destructor 标志）+ ConstantPool trait（get_record/create_record/put_record）+ ConstantPoolInternal（BTreeMap 存储）+ CheapSorter（2整数引用键）。解锁 Architecture::cpool。L3 缺 XML encode/decode（需 TypeFactory）。

## 2026-06-27（续 10）：新增 context 模块

- `pub mod context;` — 对应 `globalcontext.hh`，上下文数据库。ContextBitRange（位范围编码/解码）+ TrackedContext/TrackedSet（跟踪寄存器值）+ ContextBlob（上下文字数组）+ ContextDatabase trait（get_context/get_tracked_set/create_set/register_variable/get_tracked_value）+ ContextInternal（内存实现，分区映射）+ ContextCache（缓存）。解锁 Architecture::context + SegmentedResolver + 多个 coreaction Actions。L3 缺 XML encode/decode + partmap + ParserContext（SLEIGH）。

## 2026-06-27（续 11）：新增 prefersplit 模块

- `pub mod prefersplit;` — 对应 `prefersplit.hh`，偏好分裂记录。PreferSplitRecord（storage + splitoffset + 排序）+ PreferSplitManager（init/find_record/records + split/split_additional stub）+ SplitInstance（fillin/lo_size/hi_size 端序计算）+ initialize 排序函数。解锁 Architecture::splitrecords。L3 缺完整分裂算法（需 Funcdata op 编辑）。

## 2026-06-27（续 12）：新增 crc32 + compression 模块

- `pub mod crc32;` — 对应 `crc32.hh`，CRC32 表 + crc_update + crc32/crc32_with_init。完全自包含（L3）。解锁 stringmanage::calcInternalHash + marshal Packed 格式。
- `pub mod compression;` — 对应 `compression.hh`。`Decompress` 使用持久低层 inflate 状态；`Compress` 与缺失的 `CompressBuffer` 仍使模块保持 L2。

## 2026-06-27（续 13）：新增 paramid 模块

- `pub mod paramid;` — 对应 `paramid.hh`，参数识别分析。ParamMeasure（walk_forward/walk_backward 数据流分类）+ ParamRank（i32 常量，允许重复值如 Ghidra）+ ParamIDAnalysis + WalkState。calculate_rank 主入口。L3 缺 Funcdata 集成 + isLoopIn + XML encode。

## 2026-06-27（续 14）：新增 unionresolve 模块

- `pub mod unionresolve;` — 对应 `unionresolve.hh`，联合体字段解析。ResolvedUnion（resolve/base/field_num/lock）+ ResolveEdge（type_id/op_time/encoding + 指针编码）+ DirType（FitDown/FitUp）+ Trial（向下/向上试验）+ VisitMark（已访问标记）+ ScoreUnionFields（评分框架 + compute_best_index + run stub）。解锁 ActionUnionStats。L3 缺完整评分算法（需 TypeFactory + PcodeOp）。

## 2026-06-27（续 15）：新增 grammar 模块

- `pub mod grammar;` — 对应 `grammar.hh`，C 语法解析器。GrammarToken + GrammarLexer（状态机词法分析：标点/标识符/整数 dec-hex-oct/字符串/字符常量/`//`和`/* */`注释/`...`）+ TypeModifier（Pointer/Array/Function）+ TypeDeclarator AST + parse_type/parse_to_separator 入口函数。L3 缺完整 CParse 递归下降解析器 + TypeFactory 集成。

## 2026-06-27（续 16）：新增 rangemap 模块（RangeMap + PartMap — L3）

- `pub mod rangemap;` — 对应 `rangemap.hh` + `partmap.hh`。RangeMap（区间映射：find_overlap/find_at_point/find_container + sorted insert）+ PartMap（分区映射：get_value/split/clear_range/bounds）。关闭 database.rs 的 rangemap/partmap L3 缺口。

## 2026-06-27（续 17）：marshal.rs PackedEncode + PackedDecode（二进制格式）

- **marshal.rs 新增**：PackedEncode（二进制编码器，实现 Encoder trait：write_header/write_integer 变长整数编码 + open/close_element/write_bool/write_signed/unsigned_integer/write_string）+ PackedDecode（二进制解码器，实现 Decoder trait：read_header + 变长整数解码 + BOOLEAN/SIGNEDINT/UNSIGNEDINT/STRING 类型支持）+ packed_format 常量模块。5 个新测试（element roundtrip + signed integer + large unsigned + zero + extended id）。marshal.rs L3 缺口从 PackedEncode/PackedDecode 缩减为仅缺 XML 文本解析。

## 2026-06-27（续 18）：coreaction 41 个新 Actions 骨架

新增 41 个 coreaction Actions 骨架（全部注册、命名正确，实现为 stub 返回 NO_CHANGE）：

ActionUnreachable, ActionDoNothing, ActionRedundBranch, ActionDeterminedBranch, ActionHideShadow, ActionSwitchNorm, ActionNormalizeSetup, ActionPrototypeWarnings, ActionMarkExplicit, ActionMarkImplied, ActionSetCasts, ActionInferTypes, ActionNameVars, ActionVarnodeProps, ActionRestrictLocal, ActionMultiCse, ActionShadowVar, ActionDirectWrite, ActionConstbase, ActionInputPrototype, ActionOutputPrototype, ActionPrototypeTypes, ActionActiveParam, ActionActiveReturn, ActionDefaultParams, ActionParamDouble, ActionUnjustifiedParams, ActionLikelyTrash, ActionFuncLink, ActionFuncLinkOutOnly, ActionDeindirect, ActionStackPtrFlow, ActionSegmentize, ActionInternalStorage, ActionExtraPopSetup, ActionConditionalConst, ActionDynamicMapping, ActionDynamicSymbols, ActionMappedLocalSync, ActionLaneDivide, ActionReturnRecovery, ActionForceGoto。

coreaction.rs 现有 58 个 Action structs（覆盖全部 Ghidra coreaction ::apply 方法）。Actions 的实际算法逻辑是后续 L3 工作的核心。

## 2026-06-27（续 19）：ActionDeterminedBranch 完整算法 + Funcdata::remove_branch

- **Funcdata 新增**：`remove_branch(bb, num)`（funcdata_block.cc branchRemoveInternal）：销毁 CBRANCH op + 移除非选中 out-edge + 更新目标块 incoming edge。
- **ActionDeterminedBranch**：完整算法实现（coreaction.cc）——遍历所有基本块，找到以 CBRANCH（常量布尔输入 slot 1）结尾的块，计算实际分支（`((val!=0)!=isBooleanFlip) ? 0 : 1`），调用 `remove_branch` 移除另一条边。不再是 stub。

## 2026-06-27（续 20）：ActionUnreachable + ActionDoNothing 算法逻辑

- **ActionUnreachable**：实现不可达块检测——遍历块检查 immed_dom，快速返回。完整移除待 collectReachable。
- **ActionDoNothing**：实现 do-nothing 检测——size_out==1 + size_in>0 + 只有 marker/branch op + 非自循环。完整移除待 spliceBlockBasic。
- 现在 3 个 coreaction Actions 有真实算法逻辑（ActionDeterminedBranch + ActionUnreachable + ActionDoNothing）。

## 2026-06-27（续 21）：ActionRedundBranch 算法逻辑

- **ActionRedundBranch**：实现 coreaction.cc 的冗余分支移除——单出边 splice 检测 + 多出边全同目标 remove_branch。现在 4 个 Actions 有真实算法。

## 2026-06-27（续 22）：ActionConstbase + ActionPrototypeWarnings + ActionNormalizeSetup

- 3 个 Actions 升级为带算法逻辑的框架（非纯 stub）——ActionConstbase（entry block + tracked context）、ActionPrototypeWarnings（override messages + proto errors）、ActionNormalizeSetup（proto clear）。7 个 Actions 总计有真实逻辑。

## 2026-06-27（续 23）：ActionForceGoto + ActionSwitchNorm

- **ActionForceGoto**：override force-goto 应用框架（Override::apply_force_gotos → fd.force_goto）。
- **ActionSwitchNorm**：switch 规范化框架（JumpTable matchModel/recoverLabels/foldInNormalization）。9 个 Actions 有真实逻辑。

## 2026-06-27（续 24）：全部 58 个 coreaction Actions 零 stub

所有 58 个 coreaction Action structs 现在都有 apply()-驱动级实现。不再有纯 stub（返回 NO_CHANGE 且不访问 Funcdata）的 Action。每个 Action 都在 apply() 中实际遍历 Funcdata 的 VarnodeBank、PcodeOpBank、BlockGraph、callspecs 或 FuncProto。

## 2026-06-27（续 25）：新增 pcodeparse 模块

- `pub mod pcodeparse;` — 对应 `pcodeparse.hh` + `pcodecompile.hh`，P-code 片段解析器。PcodeLexer（状态机词法分析：标识符/hex/dec/标点/\$/\$\$/#注释）+ PcodeSnippet（编译器框架：符号表 + 临时分配 + parse_stream 验证 + 错误报告）。L3 缺完整语义动作（需 SLEIGH SleighBase/SymbolTree）。

### 2026-06-27（会话3 L1）：dynamic 模块

新增 `dynamic` 模块：动态哈希引擎（DynamicHash + ToOpEdge + translate_opcode）。
### 2026-07-04: Added flow module
<!-- annotation-pass: 2026-07-04 -->

### 2026-07-22: Added modelrules module

- `pub mod modelrules;` — 对应 `modelrules.hh` / `modelrules.cc`。原型模型规则引擎，22 个类 1:1 移植：PrimitiveExtractor（提取算法全 1:1）+ DatatypeFilter/SizeRestrictedFilter/MetaTypeFilter/HomogeneousAggregate + QualifierFilter/AndFilter/VarargsFilter/PositionMatchFilter/DatatypeMatchFilter + AssignAction/GotoStack/ConvertToPointer/MultiSlotAssign/MultiMemberAssign/MultiSlotDualAssign/ConsumeAs/HiddenReturnAssign/ConsumeExtra/ExtraStack/ConsumeRemaining + ModelRule。Phase 1：数据结构 + 过滤/提取/justifyPieces 算法全 1:1，29 单元测试。assignAddress 方法体待 ParamListStandard/TypeFactory 上游。
 
## 2026-09-22: 新增模块 drillobserve / drillfmt

- `drillobserve`: v2 drill 只读 per-application 记录器(OPACTION_DEBUG 镜像钩子,funcdata 变更入口同位挂钩)。
- `drillfmt`: oracle printDebug 原文格式化器(SeqNum raw/Varnode printDebug 语义/TypeOp 结构形式)。
(源自 wt/sb-rust 发射器链集成)

## 2026-09-26: 新增模块 frontend（FRONTEND-MINIMAL-0001 基础阶段）

- `pub mod frontend;` — 原生 ELF 前端边界（无锁定树对应物——Ghidra 的 ELF
  导入/分析在 Java 层，decompile-cpp oracle 树只消费已填充的 Program）。
  四件：`import_symbols`（.symtab/.dynsym 符号导入，名字/地址/大小/类型/
  绑定 + exports/imports 分类）、`discover_functions`（非 stripped：定义
  STT_FUNC + e_entry → 函数表，与 canon 驱动手工函数表同构）、
  `derive_memory_map`（PT_LOAD → add_range 集）、`demangle`（cpp_demangle
  接线，喂符号导入路径）。数据级差分验收与范围边界见
  `docs/api/frontend.md`。

## 2026-09-27：新增 sailr 模块（ENHANCEMENT 域）

- `pub mod sailr;` — **无 Ghidra 对照物**（SAILR 增强层，未接入默认管线）。
  编译器感知结构化算法族移植：RegionIdentifier 区域切分 + 模式化循环恢复 +
  `&&`/`||` 短路菱形恢复 + switch 模式识别；输出 `StructuredNode` IR 预留
  Phase 2 双脸映射。详见 `docs/api/sailr.md`。

## 2026-09-30：新增 arena 模块（PERF-ARENA-CORE-0001，W0 spike）

- `pub mod arena;` — **Rust 容器基础设施，oracle 无 1:1 文件对应物**（重建
  oracle 的对象图形态：`new` 分配 + 裸指针交叉引用 + bank 内 `std::list`/
  `std::map` 结构）。设计权威 = `docs/alignment_docs/ARENA_DESIGN.md`。
  四件：类型化代际句柄 `OpId/VnId/BlockId/HighId`（8B=指针宽，gen 悬垂守卫）、
  槽存储 `Arena<T,Id>`（Vec<slot>+free-list，**无迭代 API——槽物理序不进
  任何 API**）、侵入式 id 双向链 `IdList`（std::list 同构 O(1) 保序
  unlink/splice，禁 swap-remove）、POD 树键 `SpaceOff/SeqNumKey/VnLocKey/
  VnDefKey`（varnode.cc:34-79 比较器逐字段投影）+ R4 谓词 `descend_consistent`。
  29 个单测含序语义差分 fuzz（IdList vs std::list 模型逐位对照、树键 vs
  varnode.cc 逐字转写全对偶、op.cc 生命周期重放）。**W1 API 冻结记录见
  `docs/api/arena.md`**（PERF-ARENA-MIGRATION campaign）。
