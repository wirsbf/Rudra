# database 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 3430行 (`database.cc`) + 996行 (`database.hh`) / Rudra: 2702行 (`src/database.rs`) / 比率: 78%

Ghidra 头文件 `database.hh` 的内联访问器（`Symbol::getType/getId/getFlags/...`、`Scope::getName/getId/isGlobal/...`、`Database::getGlobalScope/getProperty/...`）一并纳入统计。

## 设计说明（重要架构偏差）
1. **Symbol 子类用独立 struct 而非继承**：Ghidra 的 `Symbol` 抽象基类派生 5 个子类（`FunctionSymbol`/`EquateSymbol`/`UnionFacetSymbol`/`LabSymbol`/`ExternRefSymbol`），每个子类有自己的 `encode`/`decode` 虚方法重载。Rudra 用 5 个独立 struct（`Symbol` + `FunctionSymbol` + `EquateSymbol` + `UnionFacetSymbol` + `LabSymbol` + `ExternRefSymbol`），**各自重复存储 scope_id/type 字段而不共享基类**，且子类之间无多态分发——`Scope::add_map_sym` 必须按 element name 手动 match 分发到对应子类的 decode（src/database.rs:1744）。
2. **Scope/ScopeInternal 合并为单一 Scope struct**：Ghidra 的 `Scope`（抽象基类，database.hh:462）+ `ScopeInternal`（具体实现，database.hh:798）是两层。Rudra 的 `Scope` struct（src/database.rs:1155）把两者合并，**跳过了所有纯虚方法的多态分发**（`buildSubScope`/`addSymbolInternal`/`addMapInternal`/`addDynamicMapInternal`/`findAddr`/...），直接用 BTreeMap 实现。这导致 Rudra 无法支持 Ghidra 的多后端 Scope（如 Database-backed Scope vs in-memory ScopeInternal）。
3. **Scope 不持有 `Architecture *glb`**：Ghidra 的 `Scope` 持有 `glb`，所以 `buildVariableName`/`buildUndefinedName`/`makeNameUnique`/`resolveExternalRefFunction`/`adjustCaches` 可访问 TypeFactory/Funcdata。Rudra 的 `Scope` 无 glb 句柄，所以这些方法要么缺失要么简化（`build_default_name` 是简化版，src/database.rs:1858）。
4. **MapIterator 缺失**：Ghidra 的 `MapIterator`（database.hh:379）+ `Scope::begin/end` 提供 SymbolEntry 的范围迭代器。Rudra 无 MapIterator 等价物，`begin/end/beginDynamic/endDynamic` 缺失，只能通过 `find_addr`/`find_container` 单点查询。
5. **Scope 静态栈查询方法缺失**：Ghidra 的 `Scope::stackAddr`/`stackContainer`/`stackClosestFit`/`stackFunction`/`stackExternalRef`/`stackCodeLabel`（database.cc:909-1095，6 个静态方法，约 190 行）是 `queryByAddr`/`queryContainer`/`queryFunction`/... 的底层，用于在两个候选 Scope 间仲裁。Rudra 完全缺失这 6 个方法，`query_by_name`/`query_function`/`query_by_addr`/`query_container`/`query_properties`/`query_function(addr)`/`query_external_ref_function`/`query_code_label` 全部缺失。
6. **Scope 的 ScopeCompare/SymbolCompareName/SymbolNameTree 缺失**：Ghidra 用 `SymbolNameTree`（基于 `SymbolCompareName`）维护按名排序的符号集，用于 `findByName`/`assignDefaultNames`/`findFirstByName`。Rudra 用 `BTreeMap<String, ...>` 按名索引，语义近似但**无 SymbolNameTree 的 dedup id 机制**（`nameDedup` 字段）。
7. **Symbol::wholeCount / mapentry 列表 缺失**：Ghidra 的 Symbol 持有 `wholeCount`（整 Symbol 映射数，判断 `isMultiEntry`）和 `mapentry`（SymbolEntry 指针向量，按地址排序），`getFirstWholeMap`/`getMapEntry(addr)`/`getMapEntry(i)`/`numEntries`/`getMapEntryPosition` 据此查找。Rudra 的 Symbol 无此字段——多映射（multi-entry）符号的入口查找在 Scope 侧用 Vec<SymbolEntry> 线性扫描。
8. **Scope::getResolutionDepth / depthScope / depthResolution 缺失**：Ghidra 的 Symbol 缓存 `depthScope`/`depthResolution`（database.hh:206-207），`getResolutionDepth(useScope)` 计算解析符号所需的作用域名层级数。Rudra 缺失此缓存与方法。

## 已对齐函数 (按类统计)

### SymbolEntry (18) — 覆盖完整
- `new_dynamic` (cc:68 构造), `new_static` (cc:50 构造), `is_piece`(hh:141), `is_dynamic`(hh:142), `is_invalid`(hh:143), `get_offset`(hh:154), `get_first`(cc:50), `get_last`(cc:50), `get_symbol`(hh:149), `get_addr`(cc:50), `get_hash`(hh:151), `get_size`(hh:152), `get_all_flags`(hh:144), `in_use`(cc:114), `get_use_limit`(cc:50 uselimit 字段), `set_use_limit`(hh:156), `is_addr_tied`(hh:157), `encode`(cc:187), `decode`(cc:206) ✅
- `encode_use_limit`/`decode_use_limit` — Rudra 私有辅助（cc:187/206 内部分支，合理拆分）

### Symbol (32) — 核心访问器齐全
- `new` (hh:960), `new_unnamed`(hh:979), `get_name`(hh), `get_display_name`(hh), `get_type_name`(Rudra 扩展), `get_type`(hh:224), `set_dtype`(hh), `get_id`(hh:225), `get_flags`(hh:226), `get_display_format`(hh:227), `get_category`(hh), `get_category_index`(hh), `is_type_locked`(hh:230), `is_name_locked`(hh:231), `is_name_undefined`(cc:246), `is_size_type_locked`(hh:232), `is_volatile`(hh:233), `is_this_pointer`(hh:234), `is_indirect_storage`(hh:235), `is_hidden_return`(hh:236), `is_multi_entry`(hh:238), `is_isolated`(hh:241), `set_display_format`(cc:550 类比 hh:194), `set_isolated`(cc:255), `set_this_pointer`(cc:235), `encode_header`(cc:363), `decode_header`(cc:394), `encode_body`(cc:466), `decode_body`(cc:473), `encode`(cc:481), `decode`(cc:492) ✅

### FunctionSymbol (5)
- `new` (cc:534/544), `get_bytes_consumed`(cc:294/508), `get_entry`(cc:557 类比), `encode`(cc:566), `decode`(cc:580) ✅

### EquateSymbol (4)
- `new` (cc:624), `encode`(cc:659), `decode`(cc:670) ✅
- (`is_value_close` cc:640 缺失，见下)

### LabSymbol (4)
- `new` (cc:736/745), `encode`(cc:751), `decode`(cc:759) ✅
- (`build_type` cc:728 缺失，见下)

### ExternRefSymbol (4)
- `new` (cc:789), `encode`(cc:796), `decode`(cc:805) ✅
- (`build_name_type` cc:768 缺失，见下)

### UnionFacetSymbol (4)
- `new` (cc:691 类比), `encode`(cc:698), `decode`(cc:708) ✅
- (`get_field_number` hh:324 内联访问器，字段公开，合理)

### Scope (33) — 基础查询/CRUD 完整
- `new`(hh:566), `get_name`(hh:745), `get_display_name`(hh:746), `get_id`(hh:747), `is_global`(hh:748) ✅
- `add_range`(cc:1105), `remove_range`(cc:1114), `in_scope`(hh:597) ✅
- `add_symbol`(cc:1510), `add_symbol_mapped`(hh:742 addSymbol 的 mapped 版), `allocate_id`(hh:557 setSymbolId 类比), `remove_symbol`(cc:2138), `rename_symbol`(cc:2152), `set_attribute`(cc:2200), `clear_attribute`(cc:2209) ✅
- `find_addr`(cc:2224), `find_container`(cc:2250), `find_overlap`(cc:2392), `find_by_name`(cc:2405), `is_name_used`(cc:2417) ✅
- `get_category_size`(cc:2806), `set_category`(cc:2824) ✅
- `clear`(cc:1977), `clear_unlocked`(cc:2042), `attach_child`(cc:857 attachScope), `detach_child`(cc:866 detachScope), `num_symbols`(hh 类比) ✅
- `encode`(cc:2616 ScopeInternal::encode), `rangetree_encode`(cc:2616 rangelist 分支), `encode_recursive`(cc:1371), `decode_hole`(cc:2667), `decode_collision_name`(cc:2695), `decode`(cc:2744 ScopeInternal::decode), `decode_rangelist`(cc:2744 rangelist 分支), `add_map_sym`(cc:1564), `assign_default_names`(cc:2850), `build_default_name`(cc:1756 简化版) ✅

### Database (22) — 主表层完整
- `new`(cc:2924), `default`(cc:2924), `get_global_scope`(hh:939), `get_global_scope_mut`(hh:939), `attach_scope`(cc:2946), `resolve_scope`(cc:3092), `resolve_scope_mut`(cc:3092), `find_create_scope`(cc:3078), `delete_scope`(cc:2985), `delete_sub_scopes`(cc:3003), `set_range`(cc:3036), `add_range`(cc:3050), `remove_range`(cc:3064), `get_property`(hh:946), `set_property_range`(cc:3220), `clear_property_range`(cc:3245), `map_scope`(cc:3185/3202), `num_scopes`(hh 类比) ✅
- `encode`(cc:3270), `encode_scope_recursive`(cc:1371), `parse_parent_tag`(cc:3300), `decode`(cc:3314), `decode_scope`(cc:3375), `decode_scope_path`(cc:3398) ✅
- `attach_scope_by_id`(RUDRA-GLUE 辅助，无 Ghidra 对应，合理)

## 缺失函数

### Scope — 静态栈查询（6 个静态方法，整段约 190 行，关键）
- `Scope::stackAddr` — Ghidra: database.cc:909 — 优先级: **高** — 在两个候选 Scope 间仲裁地址查询，是 `queryByAddr` 的底层。
- `Scope::stackContainer` — Ghidra: database.cc:943 — 优先级: **高** — `queryContainer` 的底层。
- `Scope::stackClosestFit` — Ghidra: database.cc:977 — 优先级: **高** — `queryClosestFit` 的底层。
- `Scope::stackFunction` — Ghidra: database.cc:1009 — 优先级: **高** — `queryFunction(addr)` 的底层。
- `Scope::stackExternalRef` — Ghidra: database.cc:1040 — 优先级: **高** — `queryExternalRefFunction` 的底层。
- `Scope::stackCodeLabel` — Ghidra: database.cc:1074 — 优先级: **高** — `queryCodeLabel` 的底层。

### Scope — 公共查询方法（8 个方法，全部依赖上面的 stack*）
- `Scope::queryByName` — Ghidra: database.cc:1198 — 优先级: **高** — 全局按名查询（遍历作用域栈）。Rudra `find_by_name` 只查当前 Scope。
- `Scope::queryFunction(string)` — Ghidra: database.cc:1212 — 优先级: **高** — 全局按名查函数。
- `Scope::queryByAddr` — Ghidra: database.cc:1231 — 优先级: **高** — 全局按地址查 Symbol。
- `Scope::queryContainer` — Ghidra: database.cc:1246 — 优先级: **高** — 全局查最小包含 Symbol。
- `Scope::queryProperties` — Ghidra: database.cc:1263 — 优先级: **高** — 全局查地址属性或 Symbol。
- `Scope::queryFunction(addr)` — Ghidra: database.cc:1287 — 优先级: **高** — 全局按地址查函数。
- `Scope::queryExternalRefFunction` — Ghidra: database.cc:1416 — 优先级: **高** — 经外部引用查函数。
- `Scope::queryCodeLabel` — Ghidra: database.cc:1301 — 优先级: **高** — 全局按地址查代码标签。

### Scope — 子作用域与命名（6 个方法）
- `Scope::resolveScope(string,bool)` — Ghidra: database.cc:1315 — 优先级: **高** — 按名查找子作用域（带 strategy 参数控制模糊匹配）。
- `Scope::discoverScope` — Ghidra: database.cc:1353 — 优先级: 中 — 发现地址所属作用域。
- `Scope::overrideSizeLockType` — Ghidra: database.cc:1387 — 优先级: 中 — 改写 size-locked 符号类型。
- `Scope::resetSizeLockType` — Ghidra: database.cc:1402 — 优先级: 中 — 清除 size-locked 类型。
- `Scope::isSubScope` — Ghidra: database.cc:1432 — 优先级: 中 — 判断子作用域关系。
- `Scope::getFullName` — Ghidra: database.cc:1443 — 优先级: 中 — 作用域全路径名。
- `Scope::getScopePath` — Ghidra: database.cc:1458 — 优先级: 中 — 作用域路径栈。
- `Scope::findDistinguishingScope` — Ghidra: database.cc:1481 — 优先级: 低 — 第一个非共享祖先。
- `Scope::isReadOnly` — Ghidra: database.cc:1796 — 优先级: 中 — 地址是否只读。

### Scope — 符号工厂方法（6 个方法，依赖 Architecture）
- `Scope::addSymbol(nm,ct)` — Ghidra: database.cc:1510 — 优先级: 中 — 不映射到地址的纯符号创建（Rudra `add_symbol(nm,type_name)` 用类型名字符串而非 Datatype 对象，语义偏差）。
- `Scope::addMapPoint` — Ghidra: database.cc:1548 — 优先级: 中 — 将符号映射到指定地址。
- `Scope::addFunction` — Ghidra: database.cc:1615 — 优先级: **高** — 创建 FunctionSymbol 并映射到函数地址。Rudra 缺失（FunctionSymbol 是独立 struct，无 Scope 集成入口）。
- `Scope::addExternalRef` — Ghidra: database.cc:1642 — 优先级: **高** — 创建 ExternRefSymbol。
- `Scope::addCodeLabel` — Ghidra: database.cc:1664 — 优先级: **高** — 创建 LabSymbol。
- `Scope::addDynamicSymbol` — Ghidra: database.cc:1690 — 优先级: **高** — 创建动态符号。
- `Scope::addEquateSymbol` — Ghidra: database.cc:1712 — 优先级: **高** — 创建 EquateSymbol。
- `Scope::addUnionFacetSymbol` — Ghidra: database.cc:1737 — 优先级: **高** — 创建 UnionFacetSymbol。
- `Scope::buildDefaultName` — Ghidra: database.cc:1756 — 优先级: 中 — Rudra `build_default_name` 是简化版（不查 Varnode/类型）。

### Scope — 名字生成（3 个方法，依赖 Architecture）
- `Scope::buildVariableName` — Ghidra: database.cc:2434 — 优先级: **高** — 根据地址/类型/flags 生成变量名（如 `i8i9i10` 栈偏移命名、`param_1` 参数命名）。Rudra 缺失，符号默认名生成能力受限。
- `Scope::buildUndefinedName` — Ghidra: database.cc:2520 — 优先级: 中 — 生成内部未定义名。
- `Scope::makeNameUnique` — Ghidra: database.cc:2553 — 优先级: 中 — 名字去重（带 dedup id）。

### Scope — 迭代器与多态虚方法（ScopeInternal，12 个方法）
- `ScopeInternal::buildSubScope` — Ghidra: database.cc:1804 — 优先级: **高** — 创建子作用域（纯虚实现）。
- `ScopeInternal::addSymbolInternal` — Ghidra: database.cc:1810 — 优先级: 中 — 内部符号添加。
- `ScopeInternal::addMapInternal` — Ghidra: database.cc:1843 — 优先级: **高** — 内部地址映射添加（核心）。
- `ScopeInternal::addDynamicMapInternal` — Ghidra: database.cc:1874 — 优先级: **高** — 动态映射添加。
- `ScopeInternal::begin/end` — Ghidra: database.cc:1889/1914 — 优先级: 中 — MapIterator 端点。
- `ScopeInternal::beginDynamic/endDynamic` — Ghidra: database.cc:1921-1939 — 优先级: 中 — 动态 SymbolEntry 迭代器。
- `ScopeInternal::categorySanity` — Ghidra: database.cc:1992 — 优先级: 低 — category 一致性检查。
- `ScopeInternal::clearCategory` — Ghidra: database.cc:2020 — 优先级: 中 — 清空某 category。
- `ScopeInternal::clearUnlockedCategory` — Ghidra: database.cc:2071 — 优先级: 中 — 清空某 category 的未锁定符号。
- `ScopeInternal::adjustCaches` — Ghidra: database.cc:2111 — 优先级: 低 — 配置完成后调整缓存。
- `ScopeInternal::removeSymbolMappings` — Ghidra: database.cc:2117 — 优先级: 中 — 仅移除映射保留 Symbol。
- `ScopeInternal::retypeSymbol` — Ghidra: database.cc:2166 — 优先级: **高** — 改类型并调整映射大小。
- `ScopeInternal::setDisplayFormat` — Ghidra: database.cc:2218 — 优先级: 低。
- `ScopeInternal::findClosestFit` — Ghidra: database.cc:2284 — 优先级: 中 — 最近匹配查找。
- `ScopeInternal::findFunction` — Ghidra: database.cc:2321 — 优先级: 中 — 按地址查 Funcdata。
- `ScopeInternal::findExternalRef` — Ghidra: database.cc:2342 — 优先级: 中 — 按地址查外部引用。
- `ScopeInternal::resolveExternalRefFunction` — Ghidra: database.cc:2362 — 优先级: 中 — 解析外部引用到 Funcdata。
- `ScopeInternal::findCodeLabel` — Ghidra: database.cc:2368 — 优先级: 中 — 按地址查代码标签。
- `ScopeInternal::findFirstByName` — Ghidra: database.cc:2733 — 优先级: 低 — SymbolNameTree 按名首查。
- `ScopeInternal::insertNameTree` — Ghidra: database.cc:2712 — 优先级: 低 — SymbolNameTree 插入。
- `ScopeInternal::printEntries` — Ghidra: database.cc:2791 — 优先级: 低 — 调试输出。
- `ScopeInternal::getCategorySymbol` — Ghidra: database.cc:2814 — 优先级: 中 — 按 cat+ind 查 Symbol。

### Scope — 辅助（2 个方法）
- `Scope::attachScope`/`detachScope` — Ghidra: database.cc:857/866 — 优先级: 低（私有，Rudra `attach_child`/`detach_child` 用 id 而非 Scope*，语义近似）。
- `Scope::hashScopeName` — Ghidra: database.cc:880 — 优先级: 低（静态，作用域 id 哈希；Rudra 用不同 id 分配策略）。
- `Scope::addMap` — Ghidra: database.cc:1126 — 优先级: 中 — 将 SymbolEntry 集成到范围映射（私有，Rudra 内联到 add_symbol_mapped）。
- `Scope::restrictScope` — Ghidra: database.cc:1096 — 优先级: 中 — 转为局部作用域（绑定 Funcdata）。
- `Scope::decodeWrappingAttributes` — Ghidra: database.hh:719 — 优先级: 低（虚，默认空实现）。

### Symbol — 缺失方法（7 个方法）
- `Symbol::checkSizeTypeLock` — Ghidra: database.cc:226 — 优先级: **高** — 计算 size_typelock 属性（在 setDisplayFormat/flags 变更后调用）。Rudra 缺失，size_typelock 状态可能不一致。
- `Symbol::getFirstWholeMap` — Ghidra: database.cc:268 — 优先级: **高** — 获取首个整映射 SymbolEntry。
- `Symbol::getMapEntry(addr)` — Ghidra: database.cc:280 — 优先级: **高** — 获取包含地址的 SymbolEntry。
- `Symbol::getMapEntryPosition` — Ghidra: database.cc:301 — 优先级: 中 — 多映射中位置。
- `Symbol::getResolutionDepth` — Ghidra: database.cc:323 — 优先级: 中 — 解析深度。
- `Symbol::getBytesConsumed` — Ghidra: database.cc:508 — 优先级: 中 — 虚方法（基类返回 0），Rudra 仅 FunctionSymbol 有。
- `Symbol::hasMergeProblems`/`setMergeProblems` — Ghidra: database.hh:239-240 — 优先级: 低（内联访问器，Rudra 无此字段）。

### SymbolEntry — 缺失方法（3 个方法）
- `SymbolEntry::getSubsort` — Ghidra: database.cc:97 — 优先级: 中 — 返回 subsorttype（用于范围映射排序键）。
- `SymbolEntry::getFirstUseAddress` — Ghidra: database.cc:122 — 优先级: 中 — 首个使用点地址。
- `SymbolEntry::updateType` — Ghidra: database.cc:135 — 优先级: **高** — 从 SymbolEntry 更新 Varnode 类型（typepropagation 核心入口）。
- `SymbolEntry::getSizedType` — Ghidra: database.cc:151 — 优先级: **高** — 获取指定地址+尺寸的子类型。
- `SymbolEntry::printEntry` — Ghidra: database.cc:166 — 优先级: 低 — 调试输出。
- `SymbolEntry::getAllFlags` — Ghidra: 已对齐（注意：Ghidra 此方法非内联，cc:145，Rudra 实现一致）。

### Symbol 子类 — 缺失辅助（3 个方法）
- `FunctionSymbol::buildType` — Ghidra: database.cc:514 — 优先级: 中 — 构建 FunctionSymbol 关联类型。
- `FunctionSymbol::getFunction` — Ghidra: database.cc:557 — 优先级: **高** — 获取关联 Funcdata 对象。Rudra FunctionSymbol 持有 entry: Address 而非 Funcdata*。
- `EquateSymbol::isValueClose` — Ghidra: database.cc:640 — 优先级: 中 — 判定 equate 值相似。
- `LabSymbol::buildType` — Ghidra: database.cc:728 — 优先级: 低 — 占位类型。
- `ExternRefSymbol::buildNameType` — Ghidra: database.cc:768 — 优先级: 中 — 构建名称+类型。

### MapIterator — 整类缺失
- `MapIterator::operator++`(前置) — Ghidra: database.cc:826 — 优先级: 中
- `MapIterator::operator++`(后置) — Ghidra: database.cc:841 — 优先级: 低
- `MapIterator::operator*`/`operator->` — Ghidra: database.hh:379-431 — 优先级: 中（内联）

### Database — 缺失方法（3 个方法）
- `Database::clearUnlocked` — Ghidra: database.cc:3020 — 优先级: 中 — 清空作用域未锁定符号。
- `Database::resolveScopeFromSymbolName` — Ghidra: database.cc:3113 — 优先级: 中 — 按符号全名解析作用域。
- `Database::findCreateScopeFromSymbolName` — Ghidra: database.cc:3151 — 优先级: 中 — 按符号全名查找/创建作用域。
- `Database::clearResolve`/`clearReferences`/`fillResolve` — Ghidra: database.cc:2870/2893/2908 — 优先级: 低（私有，resolvemap 维护）。
- `Database::adjustCaches` — Ghidra: database.cc:2975 — 优先级: 低。
- `Database::setProperties`/`getProperties` — Ghidra: database.hh:949-950 — 优先级: 低（flagbase 整体替换/获取）。
- `Database::getArch` — Ghidra: database.hh:930 — 优先级: 低（内联访问器）。

### ScopeMapper — 整类缺失
- `ScopeMapper` — Ghidra: database.hh:874 — 优先级: 低 — Database 与外部符号存储的桥接基类（虚 buildScope/buildFunctionType 等），Rudra 无外部存储后端。

## 高优先级缺失清单 (按影响排序)

### 作用域栈查询（最关键，整条链断裂）
1. **`Scope::stackAddr`/`stackContainer`/`stackClosestFit`/`stackFunction`/`stackExternalRef`/`stackCodeLabel`** (database.cc:909-1095) — 6 个静态仲裁方法缺失
2. **`Scope::queryByName`/`queryFunction(name)`/`queryByAddr`/`queryContainer`/`queryProperties`/`queryFunction(addr)`/`queryExternalRefFunction`/`queryCodeLabel`** (database.cc:1198-1416) — 8 个全局查询方法全部缺失（Rudra 的 find_* 只查当前 Scope，**无法跨作用域栈查询**）
3. **`Scope::resolveScope(string,bool)`** (database.cc:1315) — 按名解析子作用域

### 符号-类型联动（关键）
4. **`SymbolEntry::updateType`/`getSizedType`** (database.cc:135/151) — Varnode 类型传播入口缺失
5. **`Symbol::getFirstWholeMap`/`getMapEntry(addr)`** (database.cc:268/280) — 符号映射查找缺失
6. **`Symbol::checkSizeTypeLock`** (database.cc:226) — size_typelock 一致性缺失
7. **`ScopeInternal::retypeSymbol`** (database.cc:2166) — 改类型并调整映射大小

### 符号工厂（关键）
8. **`Scope::addFunction`/`addExternalRef`/`addCodeLabel`/`addDynamicSymbol`/`addEquateSymbol`/`addUnionFacetSymbol`** (database.cc:1615-1756) — 6 个符号工厂缺失，子类符号无法在 Scope 内创建
9. **`FunctionSymbol::getFunction`** (database.cc:557) — FunctionSymbol 无关联 Funcdata 对象
10. **`Scope::buildVariableName`** (database.cc:2434) — 默认变量名生成（栈偏移/参数序号）缺失

### 次要（架构依赖）
11. **`Scope`/`ScopeInternal` 分层** — 上述 stack* / 虚方法依赖抽象 Scope 基类；Rudra 合并实现需先重构为 trait + 多实现
12. **`Scope` 持有 `Architecture *glb`** — buildVariableName/makeNameUnique/resolveExternalRefFunction 依赖 glb
13. **MapIterator** — begin/end 范围迭代缺失，影响全局符号遍历
14. **SymbolNameTree/dedup id** — findFirstByName/assignDefaultNames 的去重机制简化为 BTreeMap

## 说明
- `Symbol` 子类（`FunctionSymbol`/`EquateSymbol`/`LabSymbol`/`ExternRefSymbol`/`UnionFacetSymbol`）的 encode/decode 在 Rudra 中**已完整对齐**，是 database.rs 中质量最高的部分；主要缺口在子类与 Scope 的集成入口（addFunction 等工厂方法）和与 Architecture/Funcdata 的联动。
- `Scope::decode`（src/database.rs:1634）已对齐 Ghidra `ScopeInternal::decode`（database.cc:2744），正确处理 `<parent>`/`<rangelist>`/`<rangeequalssymbols>`/`<symbollist>`/`<mapsym>`/`<hole>`/`<collision>` 子元素——`<parent>` 由 Database 侧应用，`<hole>`/`<collision>` 由 Scope 单独跳过。
- `Database::decode`/`decode_scope`/`decode_scope_path` 已对齐，正确处理 `<db>` → `<scope>` 递归 → `<parent>` 链接。
- `Database` 的 encode/decode 完整路径已对齐（src/database.rs:2103/2162），是 Database 集成测试 (`test_database_encode_decode_roundtrip`) 通过的基础。
- 当前 78% 覆盖率的主要损失点：(a) 6 个 stack* 静态方法 + 8 个 query* 全局查询（约 250 行）、(b) ScopeInternal 的虚方法集（约 400 行）、(c) 符号工厂方法（约 150 行）、(d) 名字生成与去重（约 200 行）。这些大多依赖 `Architecture *glb` 或抽象 Scope 基类，是 Architecture 集成阶段的延伸工作。
