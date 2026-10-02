# `modelrules.rs` API Reference

**源代码路径**: `src/modelrules.rs`
**Ghidra 对应**: `modelrules.hh` (573行) / `modelrules.cc` (1711行)
**状态**: 🟢 **L2.5（2026-07-22 Phase 1 数据结构 + 核心算法 1:1 移植）**——22 个类/特质全部以 Rust 结构体/枚举/特质形式落地；`PrimitiveExtractor` 提取算法、`DatatypeFilter` / `QualifierFilter` 谓词逻辑、`AssignAction::justify_pieces` 截断算法 1:1 移植并有测试。`AssignAction::assign_address` 方法体依赖未移植上游（`ParamListStandard` / `ParameterPieces` / `TypeFactory` / `type_class`），目前是 stub，但完整 Ghidra 算法已逐行摘录在每个方法体内。

## 模块说明

原型模型规则：声明式规则，规定给定 data-type 在构造函数输入/输出参数列表时如何分配 Address（寄存器 / 栈槽 / join）。来自调用约定 `.proto` spec 的 `<modelrules>` XML。

对应 Ghidra 的 `modelrules.hh` / `modelrules.cc`。

## Ghidra 类 → Rust 类型映射

| Ghidra 类 (modelrules.hh) | Rust 类型 | 行 (modelrules.hh) | 行 (modelrules.cc) |
|---|---|---|---|
| `PrimitiveExtractor` | `struct PrimitiveExtractor` | 58-89 | 44-248 |
| `PrimitiveExtractor::Primitive` | `struct Primitive` | 68-73 | — |
| `DatatypeFilter` | `trait DatatypeFilter` | 95-116 | 252-272 |
| `SizeRestrictedFilter` | `struct SizeRestrictedFilter` | 123-137 | 277-364 |
| `MetaTypeFilter` | `struct MetaTypeFilter` | 142-151 | 366-389 |
| `HomogeneousAggregate` | `struct HomogeneousAggregate` | 156-166 | 391-445 |
| `QualifierFilter` | `trait QualifierFilter` | 172-193 | 451-466 |
| `AndFilter` | `struct AndFilter` | 199-207 | 470-500 |
| `VarargsFilter` | `struct VarargsFilter` | 220-229 | 502-523 |
| `PositionMatchFilter` | `struct PositionMatchFilter` | 235-242 | 525-537 |
| `DatatypeMatchFilter` | `struct DatatypeMatchFilter` | 247-256 | 539-577 |
| `AssignAction` | `trait AssignAction` + `enum AssignResponse` | 262-323 | 579-694 |
| `GotoStack` | `struct GotoStack` | 326-337 | 696-754 |
| `ConvertToPointer` | `struct ConvertToPointer` | 342-350 | 756-783 |
| `MultiSlotAssign` | `struct MultiSlotAssign` | 357-376 | 787-981 |
| `MultiMemberAssign` | `struct MultiMemberAssign` | 383-395 | 983-1061 |
| `MultiSlotDualAssign` | `struct MultiSlotDualAssign` | 401-427 | 1064-1330 |
| `ConsumeAs` | `struct ConsumeAs` | 433-443 | 1332-1372 |
| `HiddenReturnAssign` | `struct HiddenReturnAssign` | 457-466 | 1374-1408 |
| `ConsumeExtra` | `struct ConsumeExtra` | 475-488 | 1411-1468 |
| `ExtraStack` | `struct ExtraStack` | 496-509 | 1516-1588 |
| `ConsumeRemaining` | `struct ConsumeRemaining` | 517-529 | 1472-1514 |
| `ModelRule` | `struct ModelRule` | 537-554 | 1590-1709 |

## 导出的公共 API

### `pub struct PrimitiveExtractor` (modelrules.hh:58)
递归抽取复合 data-type 的基本元素（primitive），连同其 offset。抽取算法 1:1 对齐 Ghidra：`extract()` 按元类型 switch；struct 字段循环检测 unaligned / extra_space；union 通过 `commonRefinement` 求公共精炼。
- `new(dt, union_illegal, offset, max)` — 构造（对应 Ghidra 公有构造器 modelrules.cc:242）
- `size()` / `get(i)` / `is_valid()` / `contains_unknown()` / `is_aligned()` / `contains_holes()`

私有（crate-internal）方法：`extract` / `extract_struct` / `handle_union` / `common_refinement` / `check_overlap`。

### `pub struct Primitive` (modelrules.hh:68)
- `dt: Arc<Datatype>` / `offset: i64` / `new(dt, offset)`

### `pub mod primitive_flags`
位标志：`UNKNOWN_ELEMENT / UNALIGNED / EXTRA_SPACE / INVALID / UNION_INVALID`（modelrules.hh:59-65）。

### `pub trait DatatypeFilter` (modelrules.hh:95)
抽象基类（C++ `virtual`）。Rust trait object（`Box<dyn DatatypeFilter>`）。
- `clone_box(&self) -> Box<dyn DatatypeFilter>` — 对应 Ghidra `virtual clone()`
- `filter(&dt) -> bool` — modelrules.hh:108
- `decode(&mut self, &mut Decoder) -> Result<()>` — modelrules.hh:113（默认 no-op stub）

### `pub fn decode_datatype_filter(decoder)` (modelrules.hh:115)
对应 Ghidra 静态 `DatatypeFilter::decodeFilter`。Rust 用自由函数保持 trait object-safe。

### `pub struct SizeRestrictedFilter` (modelrules.hh:123)
按尺寸范围 / 枚举尺寸列表过滤。`sizes: BTreeSet<i32>` 保留 Ghidra `set<int4>` 的有序语义。
- `new()` / `with_bounds(min, max)` / `copy(op2)`
- `init_from_type_list(str)` — modelrules.cc:277 字符串解析（comma/space 分隔整数）
- `filter_on_size(dt)` — modelrules.cc:327

### `pub struct MetaTypeFilter` (modelrules.hh:142)
按单一 `type_metatype` 过滤（TYPE_STRUCT / TYPE_FLOAT 等），叠加尺寸限制。
- `new(meta)` / `with_bounds(meta, min, max)` / `copy(op2)`
- 字段：`size_filter: SizeRestrictedFilter` / `meta_type: TypeMetatype`

### `pub struct HomogeneousAggregate` (modelrules.hh:156)
齐次聚合过滤：所有 primitive 必须相同。`filter()` 调用 `PrimitiveExtractor` 检查对齐 / 无洞 / 同类型。
- `new(meta)` / `with_bounds(meta, max_prim, min_size, max_size)` / `copy(op2)`
- 字段：`size_filter` / `meta_type` / `max_primitives`

### `pub trait QualifierFilter` (modelrules.hh:172)
针对函数原型某方面的过滤。Rust trait object。
- `clone_box()` / `filter(proto, pos)` / `decode()`（默认 no-op）

### `pub fn decode_qualifier_filter(decoder)` (modelrules.hh:192)
对应静态 `QualifierFilter::decodeFilter`。

### `pub struct AndFilter` (modelrules.hh:199)
逻辑 AND 多个 `QualifierFilter`。字段 `sub_qualifiers: Vec<Box<dyn QualifierFilter>>`。

### `pub struct VarargsFilter` (modelrules.hh:220)
变参范围过滤。默认 `first_pos = i32::MIN` / `last_pos = i32::MAX`（对应 Ghidra `0x80000000` / `0x7fffffff`）。

### `pub struct PositionMatchFilter` (modelrules.hh:235)
匹配当前参数 position。

### `pub struct DatatypeMatchFilter` (modelrules.hh:247)
检查固定 position 处的 data-type（`position=-1` 表示 outtype）。

### `pub enum AssignResponse` (modelrules.hh:264)
`AssignAction::assignAddress` 返回码：`Success / Fail / NoAssignment / HiddenRetPtrParam / HiddenRetSpecialReg / HiddenRetSpecialRegVoid`。

### `pub trait AssignAction` (modelrules.hh:262)
分配 Address 的动作抽象基类。Rust trait object。
- `clone_box(new_resource)` — modelrules.hh:286
- `can_affect_fillin_output()` — modelrules.hh:278（默认 false）
- `assign_address(dt, proto, pos, tlist, status, res)` — modelrules.hh:304
- `fillin_output_map(active)` — modelrules.hh:313（默认 false）
- `decode(decoder)` — modelrules.hh:318

### `pub fn decode_action / decode_precondition / decode_sideeffect` (modelrules.hh:319-321)
对应 Ghidra 静态方法。Rust 自由函数以保持 trait object-safe。

### `pub fn justify_pieces(pieces, offset, is_big_endian, consume_most_sig, justify_right)` (modelrules.cc:683)
截断 tiling（modelrules.cc:683-694）。1:1 移植并经测试。亦可通过 `AssignActionStaticExt` 扩展特质以 `<dyn AssignAction>::justify_pieces(...)` 形式调用。

### `pub struct GotoStack` (modelrules.hh:326)
从下一个可用栈位置分配。
### `pub struct ConvertToPointer` (modelrules.hh:342)
转指针并分配指针存储。
### `pub struct MultiSlotAssign` (modelrules.hh:357)
消耗多个寄存器传递 data-type；可溢出到栈。含 `tiles: Vec<&ParamEntry>` 缓存。
### `pub struct MultiMemberAssign` (modelrules.hh:383)
每个 primitive 成员消耗一个寄存器。
### `pub struct MultiSlotDualAssign` (modelrules.hh:401)
跨存储类消耗寄存器（如 x86-64 SysV ABI 的 GP+FP 混合）。`get_first_unused` / `get_tile_class` 1:1 移植。
### `pub struct ConsumeAs` (modelrules.hh:433)
从指定资源列表消耗。
### `pub struct HiddenReturnAssign` (modelrules.hh:457)
返回 hidden return pointer 信号码。
### `pub struct ConsumeExtra` (modelrules.hh:475)
副作用：从备用资源列表消耗额外寄存器。
### `pub struct ExtraStack` (modelrules.hh:496)
副作用：消耗栈资源。
### `pub struct ConsumeRemaining` (modelrules.hh:517)
副作用：消耗资源列表中所有剩余寄存器。

### `pub struct ModelRule` (modelrules.hh:537)
绑定 filter + qualifier + assign + preconditions + sideeffects。
- `new()` / `copy(op2, res)` / `from_components(type_filter, action, res)`
- `assign_address(dt, proto, pos, tlist, status, res)` — modelrules.cc:1651（1:1 移植 tmp_status 回滚语义）
- `fillin_output_map(active)` / `can_affect_fillin_output()` — modelrules.hh:559 / 566 inline
- `decode(decoder, res)` — modelrules.cc:1676

## 前置桩（待上游移植后替换）

为保持 trait/struct 方法签名 1:1，本模块内声明了 Ghidra 上游尚未移植的类型桩，每处均标 `// TODO: depends on unported <X>`：

- `pub struct ParamListStandard`（fspec.hh:654）— 资源列表
- `pub enum ParamListType`（fspec.hh:435 的 `enum ParamList` 子集）
- `pub enum TypeClass`（fspec.hh:75 `type_class`）
- `pub struct ParameterPieces`（fspec.hh:451）+ `pub const INDIRECT_STORAGE`
- `pub struct PrototypePieces<'a>`（fspec.hh:445）
- `pub struct TypeFactory`（type.hh:1031）
- `pub struct VarnodeData`（types.hh:77）

## 测试

`modelrules::tests`：29 个单元测试，覆盖 PrimitiveExtractor（primitive / struct aligned / unaligned+holes / array / union illegal / union common refinement）、所有 DatatypeFilter 子类、QualifierFilter 子类（VarargsFilter / PositionMatchFilter / DatatypeMatchFilter / AndFilter）、AssignResponse 枚举、justify_pieces 截断算法（big/little endian × justify 分支）。

## 待办（Phase 2+）

1. `ParamListStandard` / `ParameterPieces` / `TypeFactory` / `type_class` 在 fspec / type_system 落地后，删除本模块前置桩并补齐所有 `AssignAction::assign_address` 方法体（每处已有逐行 Ghidra 源码摘录）。
2. marshal.rs 注册 modelrules 的 `AttributeId` / `ElementId`（`ELEM_DATATYPE` / `ELEM_CONSUME` / `ATTRIB_SIZES` 等，modelrules.cc:21-42）后，补齐所有 `decode()` XML 解析方法体。
3. 接入主管线（`ProtoModel` / `ParamListStandard::assignAddress` 的规则分发）。
<!-- annotation-pass: 2026-07-22 -->
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
