# type.cc 对齐审计 (2026-07-22)

函数级审计:Ghidra `type.hh`/`type.cc` (4677 行,~177 个类方法 + 5 个独立函数)
vs Rudra `src/type_system/`(`datatype.rs` 917 行、`typefactory.rs` 913 行、`cast.rs` 376 行、
`mod.rs` 16 行、`protomodel.rs` 315 行)。

## 覆盖率

| 子类区域 | Ghidra 方法数 | Rudra 已对齐 | 缺失 | 覆盖率 |
|---|---|---|---|---|
| Datatype 基类 | 27 | 14 | 13 | 52% |
| TypeField | 2 | 0 | 2 | 0% |
| TypeChar / TypeUnicode | 5 | 0(工厂代建) | 5 | 0% |
| TypeVoid | 2 | 0(工厂代建) | 2 | 0% |
| TypePointer | 14 | 4 | 10 | 29% |
| TypeArray | 11 | 3 | 8 | 27% |
| TypeEnum | 7 | 0(仅工厂建) | 7 | 0% |
| TypeStruct | 15 | 3 | 12 | 20% |
| TypeUnion | 11 | 0(仅工厂建) | 11 | 0% |
| TypePartialEnum | 8 | 0 | 8 | 0% |
| TypePartialStruct | 8 | 0 | 8 | 0% |
| TypePartialUnion | 10 | 0 | 10 | 0% |
| TypePointerRel | 8 | 0(工厂侧表代替) | 8 | 0% |
| TypeCode | 11 | 0(仅工厂建) | 11 | 0% |
| TypeSpacebase | 8 | 0(仅数据结构) | 8 | 0% |
| TypeFactory | 73 | 22 | 51 | 30% |
| 独立函数 | 5 | 0 | 5 | 0% |
| **总计** | **~215** | **46** | **169** | **21%** |

(覆盖率为"严格命名对齐"口径;Rudra 用单一 `Datatype` 枚举 + 工厂方法替代了 C++ 类层级,
许多 Ghidra 子类方法在 Rudra 由工厂或 `match` 分支部分实现 — 见"已对齐函数"表注释。)

## 已对齐函数

### Datatype 基类 (datatype.rs)
| Ghidra | Rudra | 备注 |
|---|---|---|
| `Datatype::getSize` | `Datatype::get_size` | 枚举 match |
| `Datatype::getMetatype` | `Datatype::get_metatype` | |
| `Datatype::getId` | `Datatype::get_id` | |
| `Datatype::getName` | `Datatype::get_name` | |
| `Datatype::getAlignment` | `Datatype::get_alignment` | 从 size 派生 |
| `Datatype::getAlignSize` | `Datatype::get_align_size` | |
| `Datatype::isCoreType` | `Datatype::is_coretype` | |
| `Datatype::isVariableLength` | `Datatype::is_variable_length` | |
| `Datatype::isCharPrint` | `Datatype::is_char_print` | |
| `Datatype::isEnumType` | `Datatype::is_enum_type` | |
| `Datatype::needsResolution` | `Datatype::needs_resolution` | |
| `Datatype::hasStripped` | `Datatype::has_stripped` | |
| `Datatype::isPieceStructured` | `Datatype::is_piece_structured` | |
| `Datatype::isPrimitiveWhole` | `Datatype::is_primitive_whole` | |
| `Datatype::printRaw` | `Datatype::print_raw` | 返回 String 而非流式 |
| `Datatype::printNameBase` | `Datatype::print_name_base` | |
| `Datatype::compare` | `Datatype::compare` | |
| `Datatype::compareDependency` | `Datatype::compare_dependency` | |
| `Datatype::typeOrder` | `Datatype::type_order` | |
| `Datatype::typeOrderBool` | `Datatype::type_order_bool` | |
| `Datatype::getSubType` | `Datatype::get_sub_type` | 部分实现(struct/union/array) |
| `Datatype::getHoleSize` | `Datatype::get_hole_size` | 部分实现 |
| `Datatype::getStripped` | `Datatype::get_stripped` | 返回 self(无 stripped 字段) |
| `Datatype::findResolve` | `Datatype::find_resolve` | 基类返回 self,无子类 override |
| `Datatype::calcAlignSize` | `calc_align_size`(自由函数) | |
| `setDefaultAlignmentMap` | `primitive_alignment`(自由函数) | 仅默认表 |

### TypeFactory (typefactory.rs)
| Ghidra | Rudra | 备注 |
|---|---|---|
| `TypeFactory(Architecture*)` | `TypeFactory::new(ptr_size)` | 无 Architecture 接入 |
| `clearNoncore` | `clear_non_core` | |
| `findByIdLocal` | `find_by_id_local` | |
| `findById` | `find_by_id` | |
| `findByName` | `find_by_name` | |
| `getBase` | `get_base` | 单签名(无命名重载) |
| `getTypeVoid` | `get_type_void` | |
| `getTypeChar` | `get_type_char` | 单参数 size |
| `getTypeUnicode` | `get_type_unicode` | |
| `getTypeCode` | `get_type_code` | |
| `getTypeEnum` | `get_type_enum` | |
| `getTypeUnion` | `get_type_union` | |
| `getTypePointerRel` | `get_type_pointer_rel` | 单签名;parent/offset 存侧表 |
| `getTypedef` | `get_typedef` | 无 id/format 参数 |
| `resizePointer` | `resize_pointer` | |
| `concretize` | `concretize` | |
| `getTypePointer` | `get_ptr` | 重命名为 get_ptr |
| `getTypeArray` | `get_array` | 重命名为 get_array |
| `setFields(Struct)` | `set_fields` | 单签名 |
| `setFields(Union)` | `set_union_fields` | |
| `setEnumValues` | `set_enum_values` | |
| `dependentOrder` + `orderRecurse` | `dependent_order` + `order_recurse` | |
| `hashSize` | `hash_size`(自由函数) | |

### Cast (cast.rs - 来自 cast.cc,见 FUNC_type_print.md)
已对齐:`cast_standard_full`、`is_subpiece_cast`、`is_subpiece_cast_endian`、`is_sext_cast`、
`is_zext_cast`、`check_int_promotion_for_*`。

## 缺失函数(按子类分组)

### Datatype 基类
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `Datatype::findTruncation` | L246 | 高 | 部分 slice→field 回退,被 print/varmap 使用 |
| `Datatype::nearestArrayedComponentForward` | L188 | 高 | base 返回 null(struct override 关键) |
| `Datatype::nearestArrayedComponentBackward` | L201 | 高 | 同上 |
| `Datatype::numDepend` / `getDepend` | L261/267 | 高 | 仅在 typefactory `depends_of` 内联实现 |
| `Datatype::encode` / `encodeBasic` / `encodeRef` / `encodeTypedef` | L438/451/479/519 | 高 | 全部 XML 序列化缺失 |
| `Datatype::decodeBasic` | L623 | 高 | XML 反序列化缺失 |
| `Datatype::isPtrsubMatching` | L551 | 中 | PTRSUB 规则匹配 |
| `Datatype::resolveInFlow` | L574 | 中 | 类型传播入口 |
| `Datatype::findCompatibleResolve` | L596 | 中 | |
| `Datatype::resolveTruncation` | L282 | 中 | 仅声明,无实现 |
| `Datatype::hashName` | L689 | 中 | id 生成 |
| `Datatype::encodeIntegerFormat` / `decodeIntegerFormat` | L728/749 | 低 | 显示格式编解码 |
| `Datatype::getInheritable` / `getDisplayFormat` / `setDisplayFormat` / `getUnsizedId` | 内联 | 低 | 标志位访问器 |
| `Datatype::hasSameVariableBase` / `isPointerToArray` / `isPointerRel` / `isFormalPointerRel` / `isASCII` / `isUTF16` / `isUTF32` / `isOpaqueString` / `isIncomplete` / `hasWarning` | 头文件内联 | 低 | 标志位访问器(部分在 `type_flags` 模块,无方法封装) |
| `Datatype::markComplete` | 头文件内联 | 低 | |

### TypeField
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeField::TypeField(Decoder&, TypeFactory&)` | L768 | 高 | XML 反序列化构造 |
| `TypeField::encode` | L798 | 高 | XML 序列化 |

### TypeChar / TypeUnicode / TypeVoid
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeChar::decode` / `encode` | L813/822 | 中 | 由工厂隐式构造 |
| `TypeUnicode::setflags` / `decode` / `encode` / 命名构造 | L837/851/862/869 | 中 | 由工厂隐式构造 |
| `TypeVoid::decode` / `encode` | L887/899 | 中 | 由工厂隐式构造 |

### TypePointer
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypePointer::printRaw` | L910 | 中 | `Datatype::print_raw` 已覆盖 |
| `TypePointer::getSubType` | L920 | 中 | `Datatype::get_sub_type` Pointer 分支返回 None |
| `TypePointer::compare` / `compareDependency` | L933/954 | 中 | 基类版本不比较 ptrto |
| `TypePointer::encode` | L969 | 高 | XML |
| `TypePointer::decode` | L1010 | 高 | XML |
| `TypePointer::calcSubmeta` | L1035 | 中 | SUB_PTR/SUB_PTR_STRUCT 等子分类 |
| `TypePointer::calcTruncate` | L1058 | 中 | 截断指针子组件 |
| `TypePointer::downChain` | L1084 | 中 | 相对指针链 |
| `TypePointer::isPtrsubMatching` | L1123 | 中 | |
| `TypePointer::resolveInFlow` / `findResolve` | L1177/1192 | 中 | |
| `TypePointer::testForArraySlack` | L990 | 中 | **已在 ruleaction.rs 内联**,非 Datatype 方法 |
| `getWordSize` / `getSpace` | 头文件内联 | 中 | `wordsize` 字段有,`spaceid` 缺失 |

### TypeArray
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeArray::printRaw` | L1204 | 中 | 已在 `print_raw` 覆盖 |
| `TypeArray::compare` / `compareDependency` | L1211/1225 | 中 | 不比较 arrayof |
| `TypeArray::getSubType` | L1234 | 中 | `get_sub_type` Array 分支已实现 |
| `TypeArray::getHoleSize` | L1243 | 中 | 已实现 |
| `TypeArray::getSubEntry` | L1257 | 中 | 字节范围→元素映射 |
| `TypeArray::encode` / `decode` | L1269/1323 | 高 | XML |
| `TypeArray::resolveInFlow` / `findResolve` / `findCompatibleResolve` | L1283/1298/1308 | 中 | |
| `getBase` / `numElements` | 头文件内联 | 低 | 字段直接访问 |

### TypeEnum
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeEnum::TypeEnum(copy ctor)` | L1346 | 低 | Rust Clone 替代 |
| `TypeEnum::hasNamedValue` | L1354 | 高 | 枚举值查找 |
| `TypeEnum::getMatches` | L1365 | 高 | Representation 还原(OR+complement+shift) |
| `TypeEnum::compare` / `compareDependency` | L1416/1422 | 中 | 比较 namemap |
| `TypeEnum::encode` / `decode` | L1447/1470 | 高 | XML |
| `TypeEnum::assignValues` (静态) | L1516 | 中 | 枚举值自动分配 |
| `beginEnum` / `endEnum` / `setNameMap` | 头文件内联 | 低 | Rust BTreeMap 迭代器替代 |

### TypeStruct
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeStruct::TypeStruct(copy ctor)` | L1551 | 低 | |
| `TypeStruct::setFields` | L1563 | 中 | 由工厂 `set_fields` 间接实现 |
| `TypeStruct::getFieldIter` | L1580 | 低 | 已有 `struct_get_field_iter` 私有 |
| `TypeStruct::getLowerBoundField` | L1604 | 中 | **已在 ruleaction.rs 内联** |
| `TypeStruct::findTruncation` | L521 头/缺 | 高 | |
| `TypeStruct::getSubType` | L1640 | 中 | 已在 `get_sub_type` 覆盖 |
| `TypeStruct::getHoleSize` | L1652 | 中 | 已在 `get_hole_size` 覆盖 |
| `TypeStruct::nearestArrayedComponentForward` | L1698 | 高 | **已在 ruleaction.rs 内联** |
| `TypeStruct::nearestArrayedComponentBackward` | L1669 | 高 | **已在 ruleaction.rs 内联** |
| `TypeStruct::compare` / `compareDependency` | L1742/1782 | 中 | 比较 field 列表 |
| `TypeStruct::encode` / `decodeFields` | L1809/1832 | 高 | XML |
| `TypeStruct::scoreSingleComponent` (静态) | L1893 | 高 | PTRSUB 适配打分 |
| `TypeStruct::resolveInFlow` / `findResolve` / `findCompatibleResolve` | L1929/1944/1954 | 中 | |
| `TypeStruct::assignFieldOffsets` (静态) | L1971 | 高 | 字段对齐填充计算 |
| `beginField` / `endField` | 头文件内联 | 低 | Vec 迭代器替代 |

### TypeUnion
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeUnion::TypeUnion(copy ctor)` | L2038 | 低 | |
| `TypeUnion::setFields` | L2002 | 中 | 由工厂 `set_union_fields` 间接实现 |
| `TypeUnion::decodeFields` | L2014 | 高 | XML |
| `TypeUnion::compare` / `compareDependency` | L2045/2084 | 中 | |
| `TypeUnion::encode` | L2109 | 高 | XML |
| `TypeUnion::resolveInFlow` / `findResolve` / `findCompatibleResolve` / `resolveTruncation` / `findTruncation` | L2125/2137/2201/564/553 | 中 | union 解析全套 |
| `TypeUnion::assignFieldOffsets` (静态) | L2223 | 中 | union 无对齐,但需要 size 推导 |
| `getField` | 头文件内联 | 低 | |

### TypePartialEnum (整个子类缺失)
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypePartialEnum::TypePartialEnum(copy ctor)` | L2247 | 低 | |
| `TypePartialEnum::TypePartialEnum(par,off,sz,strip)` | L2255 | 高 | 无 TypePartialEnum 变体 |
| `TypePartialEnum::printRaw` | L2264 | 中 | |
| `TypePartialEnum::hasNamedValue` / `getMatches` | L2271/2278 | 高 | 委托父枚举 |
| `TypePartialEnum::compare` / `compareDependency` | L2286/2302 | 中 | |
| `TypePartialEnum::encode` | L2312 | 高 | XML |
| `getOffset` / `getParent` / `getStripped` | 头文件内联 | 高 | |

### TypePartialStruct (整个子类缺失)
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypePartialStruct::TypePartialStruct(copy ctor)` | L2322 | 低 | |
| `TypePartialStruct::TypePartialStruct(contain,off,sz,strip)` | L2330 | 高 | 无变体 |
| `TypePartialStruct::getComponentForPtr` | L2345 | 高 | |
| `TypePartialStruct::printRaw` | L2356 | 中 | |
| `TypePartialStruct::getSubType` | L2363 | 中 | |
| `TypePartialStruct::getHoleSize` | L2379 | 中 | |
| `TypePartialStruct::compare` / `compareDependency` | L2390/2406 | 中 | |
| `getOffset` / `getParent` / `getStripped` | 头文件内联 | 高 | |

### TypePartialUnion (整个子类缺失)
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypePartialUnion::TypePartialUnion(copy ctor)` | L2416 | 低 | |
| `TypePartialUnion::TypePartialUnion(contain,off,sz,strip)` | L2424 | 高 | 无变体 |
| `TypePartialUnion::printRaw` | L2433 | 中 | |
| `TypePartialUnion::numDepend` / `getDepend` | L2446/2452 | 中 | |
| `TypePartialUnion::compare` / `compareDependency` | L2462/2478 | 中 | |
| `TypePartialUnion::encode` | L2488 | 高 | XML |
| `TypePartialUnion::findTruncation` / `resolveTruncation` | L628/639 | 中 | |
| `TypePartialUnion::resolveInFlow` / `findResolve` / `findCompatibleResolve` | L2498/2517/2536 | 中 | |
| `getOffset` / `getParentUnion` / `getStripped` | 头文件内联 | 高 | |

### TypePointerRel (作为类缺失;工厂用侧表替代)
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypePointerRel::decode` | L2552 | 高 | XML |
| `TypePointerRel::evaluateThruParent` | L2587 | 中 | |
| `TypePointerRel::printRaw` | L2597 | 中 | |
| `TypePointerRel::compare` / `compareDependency` | L2608/2628 | 中 | 不比较 parent/offset |
| `TypePointerRel::encode` | L2641 | 高 | XML |
| `TypePointerRel::downChain` | L2656 | 中 | |
| `TypePointerRel::isPtrsubMatching` | L2674 | 中 | |
| `TypePointerRel::getPtrToFromParent` (静态) | L2693 | 中 | |
| `getAddressOffset` / `getByteOffset` / `getParent` | 头文件内联 | 中 | 工厂侧表 `RelativePointer` 有 parent/offset |

### TypeCode
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeCode::setPrototype(tfact, sig, voidtype)` | L2713 | 高 | 函数指针原型 |
| `TypeCode::setPrototype(typegrp, fp)` | L2731 | 高 | |
| `TypeCode::TypeCode(copy)` / `TypeCode()` / `~TypeCode` | L2746/2757/2765 | 低 | Rust Clone/Drop 替代 |
| `TypeCode::printRaw` | L2772 | 中 | |
| `TypeCode::compareBasic` | L2788 | 中 | 表面比较 |
| `TypeCode::getSubType` | L2820 | 低 | 返回 null |
| `TypeCode::compare` / `compareDependency` | L2828/2860 | 中 | |
| `TypeCode::encode` | L2888 | 高 | XML |
| `TypeCode::decodeStub` / `decodePrototype` | L2903/2918 | 高 | XML |

### TypeSpacebase
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeSpacebase::getMap` | L2935 | 高 | 返回 Scope(symbol table) |
| `TypeSpacebase::getSubType` | L2947 | 高 | 从 Scope 推导类型 |
| `TypeSpacebase::nearestArrayedComponentForward` / `Backward` | L2971/3020 | 高 | |
| `TypeSpacebase::compare` / `compareDependency` | L3039/3045 | 中 | 比较 spaceid/frame |
| `TypeSpacebase::getAddress` | L3063 | 高 | off→Address 构造 |
| `TypeSpacebase::encode` / `decode` | L3073/3090 | 高 | XML |

### TypeFactory
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `TypeFactory::clearCache` | L3122 | 中 | |
| `TypeFactory::setupSizes` | L3137 | 高 | 从 Architecture 派生 sizeOfInt/Long/Char/WChar/Pointer |
| `TypeFactory::setCoreType` | L3178 | 高 | 注册核心类型 |
| `TypeFactory::cacheCoreTypes` | L3200 | 中 | typecache[9][8] 矩阵 |
| `TypeFactory::clear` | L3251 | 中 | |
| `~TypeFactory` | L3287 | 低 | Rust Drop |
| `TypeFactory::getAlignment` | L3296 | 中 | `primitive_alignment` 替代 |
| `TypeFactory::getPrimitiveAlignSize` | L3312 | 中 | |
| `TypeFactory::findNoName` | L3377 | 中 | |
| `TypeFactory::insert` | L3390 | 中 | |
| `TypeFactory::findAdd` | L3412 | 中 | 工厂方法已内联此模式 |
| `TypeFactory::setName` | L3445 | 中 | |
| `TypeFactory::setDisplayFormat` | L3466 | 低 | |
| `TypeFactory::setFields(Struct/Union,带 flags)` | L3479/3500 | 低 | Rudra 版无 flags 参数 |
| `TypeFactory::setPrototype` | L3518 | 高 | TypeCode 原型设置 |
| `TypeFactory::getTypeChar(name)` | L3593 | 中 | Rudra 仅按 size |
| `TypeFactory::getTypeChar(size)` | L3678 | 低 | 已有 |
| `TypeFactory::getBaseNoChar` | L3619 | 中 | |
| `TypeFactory::getBase(s,m,n)` | L3667 | 中 | 命名重载缺 |
| `TypeFactory::getTypeCode(name)` | L3707 | 中 | 命名 code |
| `TypeFactory::recalcPointerSubmeta` | L3724 | 中 | |
| `TypeFactory::insertWarning` / `removeWarning` | L3750/3761 | 中 | DatatypeWarning 缺失 |
| `TypeFactory::resolveIncompleteTypedefs` | L3777 | 中 | |
| `TypeFactory::getTypedef(ct,name,id,format)` | L3818 | 低 | Rudra 版无 id/format |
| `TypeFactory::getTypePointerStripArray` | L3849 | 高 | 剥离 ARRAY 层 |
| `TypeFactory::getTypePointer(s,pt,ws)` | L3867 | 中 | `get_ptr` 已有(无 size) |
| `TypeFactory::getTypePointer(s,pt,ws,n)` | L3885 | 中 | 命名重载缺 |
| `TypeFactory::getTypeArray(as,ao)` | L3902 | 低 | `get_array` 已有(无 size 参数) |
| `TypeFactory::getTypeStruct` | L3914 | 低 | `create_struct` 已有 |
| `TypeFactory::getTypePartialStruct` | L3929 | 高 | |
| `TypeFactory::getTypePartialUnion` | L3955 | 高 | |
| `TypeFactory::getTypePartialEnum` | L3980 | 高 | |
| `TypeFactory::getTypeSpacebase` | L3992 | 高 | |
| `TypeFactory::getTypeCode(PrototypePieces)` | L4002 | 高 | 函数 datatype |
| `TypeFactory::getTypePointerRel(parentPtr,ptrTo,off)` | L4016 | 中 | Rudra 仅 1 个重载 |
| `TypeFactory::getTypePointerRel(sz,parent,ptrTo,ws,off,nm)` | L4036 | 中 | 命名重载缺 |
| `TypeFactory::getTypePointerWithSpace` | L4055 | 高 | AddrSpace 关联指针 |
| `TypeFactory::getExactPiece` | L4090 | 高 | **已在 ruleaction.rs 内联** |
| `TypeFactory::destroyType` | L4122 | 中 | |
| `TypeFactory::decodeType` | L4155 | 高 | XML 主入口 |
| `TypeFactory::decodeTypeWithCodeFlags` | L4193 | 高 | XML |
| `TypeFactory::encode` | L4216 | 高 | XML |
| `TypeFactory::encodeCoreTypes` | L4240 | 高 | XML |
| `TypeFactory::decodeTypedef` | L4263 | 高 | XML |
| `TypeFactory::decodeEnum` | L4318 | 高 | XML |
| `TypeFactory::decodeStruct` | L4335 | 高 | XML |
| `TypeFactory::decodeUnion` | L4368 | 高 | XML |
| `TypeFactory::decodeCode` | L4401 | 高 | XML |
| `TypeFactory::decodeTypeNoRef` | L4436 | 高 | XML |
| `TypeFactory::decode` | L4553 | 高 | XML typegrp 元素 |
| `TypeFactory::decodeCoreTypes` | L4567 | 高 | XML |
| `TypeFactory::decodeDataOrganization` | L4583 | 高 | data_organization 元素 |
| `TypeFactory::decodeAlignmentMap` | L4619 | 中 | size_alignment_map |
| `TypeFactory::parseEnumConfig` | L4665 | 中 | enum 配置 |
| `getSizeOfInt/Long/Char/WChar/Pointer/AltPointer` | 头文件内联 | 中 | setupSizes 后存储 |
| `getArch` / `beginWarnings` / `endWarnings` | 头文件内联 | 低/中 | |

### 独立函数(自由函数)
| Ghidra 函数 | 行 | 优先级 | 说明 |
|---|---|---|---|
| `print_data` | L83 | 中 | 字节缓冲 hex dump |
| `metatype2string` | L238 | 中 | metatype↔string |
| `string2metatype` | L304 | 中 | |
| `string2typeclass` | L371 | 中 | type_class 转换 |
| `metatype2typeclass` | L420 | 中 | |

## 高优先级缺失清单(实施建议优先级)

按"对后续 decompiler 阶段阻塞程度"排序:

### P0 - 阻塞核心反编译流程
1. **TypePartialStruct / TypePartialEnum / TypePartialUnion 整个三个子类**
   — 被 `varmap.cc`、`printc.cc`、`ruleaction.cc` 大量用于"局部变量是某 struct/union/enum 的一片"的传播。
   Rudra 完全无对应变体,导致 partial 类型信息丢失。

2. **`TypeFactory::getExactPiece`** — 已在 `ruleaction.rs:11547` 内联,但应提升为 TypeFactory 方法。
   被 RulePtrsubUndo、varmap 用于"取出 struct/union 的精确片段类型"。

3. **`TypeStruct::nearestArrayedComponentForward/Backward` + `TypePointer::testForArraySlack`**
   — 已在 `ruleaction.rs:12718` 内联,但缺少 `getLowerBoundField` 正确语义。
   PTRSUB→数组下标还原依赖。

4. **`TypeSpacebase::getMap` / `getSubType` / `getAddress`** — TypeSpacebase 在 Rudra 仅是
   数据结构(有 `address`、`fd` 字段),完全无 Scope 集成。栈帧/全局变量类型传播阻塞。

### P1 - 阻塞 XML 持久化(类型归档加载/保存)
5. **整个 encode/decode XML 方法族**(Datatype::encode/decodeBasic、TypeField::encode/decode、
   各子类 encode/decode、TypeFactory::decodeType/encode/decodeCoreTypes/decodeDataOrganization
   等) — 约 25 个方法。Rudra 当前无任何类型 XML 序列化,无法加载 `.gpci`/程序类型归档。

6. **`TypeFactory::setupSizes` / `setCoreType` / `cacheCoreTypes`** — 核心类型矩阵
   `typecache[9][8]` 与 `charcache[5]` 缺失,导致 `getBase(s,m)` 性能退化到 BTreeMap 查找。

### P2 - 阻塞类型传播精度
7. **`TypeEnum::hasNamedValue` / `getMatches` / `assignValues`** — 枚举值打印与自动分配。
   `values: BTreeMap<u64,String>` 已有,但无 Representation 还原逻辑(OR/补码/移位)。

8. **`TypeStruct::assignFieldOffsets` / `scoreSingleComponent`** — 字段对齐计算与 PTRSUB 打分。
   Rudra `set_fields` 直接信任传入 offset,无对齐填充/size 重算。

9. **`TypeCode::setPrototype` (两个重载) + `TypeFactory::getTypeCode(PrototypePieces)`**
   — 函数指针原型绑定缺失。

10. **各子类 `compare` / `compareDependency`** — 当前 `Datatype::compare` 仅按 (metatype, size, name),
    不递归比较 ptrto/arrayof/fields/namemap,导致类型树去重错误。

### P3 - 完整性 / 标志访问器(易补)
11. **Datatype 标志位访问器集合**(`isASCII`/`isUTF16`/`isUTF32`/`isOpaqueString`/
    `isIncomplete`/`isPointerToArray`/`isPointerRel`/`isFormalPointerRel`/`hasWarning`/
    `getInheritable`/`getDisplayFormat`/`getUnsizedId`/`hasSameVariableBase`) —
    约 13 个一行函数,直接读 `type_flags` 位。

12. **`DatatypeWarning` 类 + `TypeFactory::insertWarning/removeWarning/beginWarnings/endWarnings`**
    — 类型警告机制完全缺失。

13. **独立函数 `print_data` / `metatype2string` / `string2metatype` / `string2typeclass` /
    `metatype2typeclass`** — 字符串互转,XML/print 都依赖。

## 备注

- **架构性差异**:Ghidra 用 C++ 类层级(Datatype 抽象基类 + 14 个子类)+ 虚函数分派;
  Rudra 用单一 `Datatype` 枚举 + `match` 分派 + 工厂方法。许多 Ghidra"子类方法"在 Rudra
  被合并到 `Datatype::impl` 的 match 分支或 `TypeFactory` 方法中。本审计按"是否存在语义等价
  实现"判定对齐,而非严格命名/签名匹配。

- **ruleaction.rs 内联实现**:`get_exact_piece`、`test_for_array_slack`、
  `nearest_arrayed_component_forward/backward`、`get_lower_bound_field` 在 `src/ruleaction.rs`
  (RulePtrsubUndo)中作为关联函数重新实现,服务于特定规则。应整合为 `Datatype` 方法或
  `TypeFactory` 方法以避免逻辑重复。

- **AddrSpace 集成缺失**:`TypePointer::spaceid`、`TypeSpacebase::spaceid`、
  `TypeFactory::getTypePointerWithSpace` 都依赖 AddrSpace,Rudra TypePointer 仅有 `wordsize`。

- **Architecture 接入缺失**:`TypeFactory::new(ptr_size)` 仅接受指针大小,无 Architecture
  对象,因此 `getArch`、`setupSizes`、Scope 查询等均无法实现。

- **protomodel.rs**:虽然位于 type_system 目录,但对应 Ghidra `fspec.hh` 的 ProtoModel,
  不属于 type.cc 审计范围(见 fspec 对齐审计)。
