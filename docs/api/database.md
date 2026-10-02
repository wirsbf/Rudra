# database.rs — Symbol database API

Rust symbol database corresponding to Ghidra's `database.hh` / `database.cc`.

## 2026-08-26：`set_symbol_flag` 驱动侧符号标志通道（MAINDIFF-STRCONST-0001）

`Scope::set_symbol_flag` / `Database::set_symbol_flag`（Ghidra 侧对应
`Symbol::decodeHeader` 的 XML 标志属性读取，database.cc:394-462）：设置/清除
Symbol 的单个 flag 位。平台分析器通过符号 XML 表达标志——ASCII 字符串分析器
的 defined Data 带锁定 char 数组类型（`ATTRIB_TYPELOCK` cc:439-442），只读
内存块中的全局量带 `Varnode::readonly`（`ATTRIB_READONLY` cc:435-438）。下游
消费：`Funcdata::spacebaseConstant` 读 `sym->isTypeLocked()`（funcdata.cc:416）
决定 PTRSUB 输出的 char 指针类型能否在后续类型传播中存活，
`Scope::queryProperties` 的 entry-hit 臂（database.cc:1273
`flags = res->getAllFlags()`）把符号位折进 readonly 答案，供
`RulePtrsubCharConstant`（ruleaction.cc:7372）与 `PrintC::pushPtrCharConstant`
（printc.cc:1709）消费。驱动侧（examples/curl_decompile.rs）对字符串地址
符号置 TYPELOCK、对 `.rodata` 全局量置 READONLY。

**Status:** L2. The 2026-08-11 locked audit rejects the prior L3 claim:
rangemap/usepoint selection, specialized Symbol identity, and
ScopeLocal-to-Funcdata property propagation are not equivalent.
2026-08-23 (DB-LOCALSCOPE-MAP-0001): the flagbase is now a faithful
`partmap<Address,uint4>` (`PartMap`), `Scope::addMap`'s flag rules
(persist / global-discovery uselimit clear / addrtied + flagbase property
fold, database.cc:1126-1155) run through `AddMapContext`, and
`symbol_flags` alias the Varnode bit values (database.hh:183 stores the
Varnode namespace on `Symbol::flags`); the threefold
`db_localscope_map_1204` oracle fixture pins the projections. All public
classes (`SymbolEntry`, `Symbol`, `FunctionSymbol`, `EquateSymbol`,
`LabSymbol`, `ExternRefSymbol`, `UnionFacetSymbol`, `Scope`, `Database`)
are present, but API presence and Rust-only round trips are not parity
evidence.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/database.{hh,cc}`.

## Constants & modules

| Name | Description |
|---|---|
| `ID_BASE` | Base of internal Symbol IDs (0x10). |
| `symbol_flags::*` | TYPELOCK, NAMELOCK, READONLY, EXTERNREF, ADDRTIED, PERSIST, VOLATIL, INDIRECTSTORAGE, HIDDENRETPARM — aliasing the Varnode bit values (varnode.hh:82-115) so `Symbol::flags` mixes with `extraflags` in one space, like `getAllFlags` (database.hh:271). |
| `display_flags::*` | FORCE_HEX/DEC/OCT/BIN/CHAR, SIZE_TYPELOCK, ISOLATE, MERGE_PROBLEMS, IS_THIS_PTR, FORMAT_MASK. |

## Enums

### `SymbolCategory`
- `NoCategory = -1`, `FunctionParameter = 0`, `Equate = 1`, `UnionFacet = 2`,
  `FakeInput = 3`.

## Structs

### `SymbolEntry`
A storage location for a particular Symbol. Faithful to `SymbolEntry`
(database.hh:75).
- `new_dynamic(symbol, extraflags, hash, offset, size, uselimit)`
- `new_static(symbol, extraflags, addr, offset, size, uselimit)`
- `is_piece()`, `is_dynamic()`, `is_invalid()`, `get_offset()`, `get_first()`,
  `get_last()`, `get_symbol()`, `get_addr()`, `get_hash()`, `get_size()`,
  `get_all_flags()`, `in_use(usepoint)`, `get_use_limit()`, `set_use_limit()`,
  `is_addr_tied()`.
- `encode(encoder)` (database.cc:187): emits `<addr>` (static) or `<hash>`
  (dynamic) + a `<rangelist>` uselimit. Pieces are skipped.
- `decode(decoder)` (database.cc:206): parses `<hash>` (dynamic) or `<addr>`
  (static), then the `<rangelist>` uselimit via `decode_use_limit`.
- `get_sized_type(type_factory, inaddr, sz)` (database.cc:151): offset =
  dynamic ? entry offset : `(inaddr - addr) + offset`，然后调用方传入的
  Architecture-owned TypeFactory 的 canonical `get_exact_piece`
  （database.cc:161 经 `symbol->getScope()->getArch()->types` 到达同一工厂；
  Rudra 的 Symbol 不持有 Scope owner，故工厂作为显式参数传入，不建局部/全局替身）。
  2026-08-24（TYPEFACTORY-EXACTPIECE-CALLERS-0001）移除旧的
  `Datatype::get_sub_type` 本地替代路径。
- `update_type(type_factory, vn_addr, vn_size)` (database.cc:135):
  TYPELOCK 门 + `get_sized_type` 投影（C++ 原型接收 `Varnode*` 并调
  `vn->updateType(dt,true,true)`；Rust 返回解析出的 Datatype 由调用方应用）。

### `Symbol`
The base class for a symbol. Faithful to `Symbol` (database.hh:172).
- `new(scope_id, name, type_name)`, `new_unnamed(scope_id)`.
- `get_name()`, `get_display_name()`, `get_type_name()`, `get_id()`,
  `get_flags()`, `get_display_format()`, `get_category()`,
  `get_category_index()`, `is_type_locked()`, `is_name_locked()`,
  `is_size_type_locked()`, `is_volatile()`, `is_this_pointer()`,
  `is_indirect_storage()`, `is_hidden_return()`, `is_multi_entry()`,
  `set_display_format(val)`, `set_isolated(val)`, `is_isolated()`,
  `set_this_pointer(val)`.

### `FunctionSymbol` / `EquateSymbol` / `LabSymbol` / `ExternRefSymbol` / `UnionFacetSymbol`
Specialized symbol types. Each wraps a base `Symbol` and now implements its own
XML encode/decode, faithful to the per-subclass methods in database.cc:
- `FunctionSymbol`: `encode`/`decode` (database.cc:566/580) — `<functionshell>`
  with header, entry `<addr>`, and consume-size.
- `EquateSymbol`: `encode`/`decode` (database.cc:659/670) — `<equatesymbol>`
  with header and a `<value>` child carrying the constant. `new` sets
  `category = equate` (database.cc:628) and `dispflags |= format`
  (cc:630) on the wrapped base Symbol, like the C++ constructor.
- `LabSymbol`: `encode`/`decode` (database.cc:751/759) — `<labelsym>` with
  header and the labelled `<addr>`.
- `ExternRefSymbol`: `encode`/`decode` (database.cc:796/805) —
  `<externrefsymbol>` with header and the reference `<addr>`.
- `UnionFacetSymbol`: `encode`/`decode` (database.cc:698/708) — `<facetsymbol>`
  with header and the `field` attribute giving the union field index.

### `Scope`
An in-memory implementation of the Scope interface. Faithful to `Scope`
(database.hh:462) + `ScopeInternal` (database.hh:798).
- `new(id, name, parent_id)`.
- `get_name()`, `get_display_name()`, `get_id()`, `is_global()`.
- `add_range(range)`, `remove_range(range)`, `in_scope(addr, size)`.
- `add_symbol(name, type) -> u64`, `add_symbol_mapped(name, type, addr, size) -> u64`.
- `remove_symbol(id)`, `rename_symbol(id, name)`.
- `set_attribute(id, attr)`, `clear_attribute(id, attr)`.
- `find_addr(addr)`, `find_container(addr, size)`, `find_overlap(addr, size)`,
  `find_by_name(name)`, `is_name_used(name)`.
- `get_category_size(cat)`, `get_category_symbol(cat, ind)`,
  `set_category(id, cat, ind)`.
- `add_dynamic_symbol(name, type_name, size, caddr, hash) -> u64`
- `add_map_point(symbol_id, addr, usepoint, size, ctx)` (database.cc:1548) —
  the whole-map static entry via `Scope::addMap`: persist for a global
  scope, global-discovery persist + uselimit CLEAR, then addrtied + the
  flagbase property fold at `addr` when the uselimit is empty
  (`apply_add_map_rules`, database.cc:1126-1155). `ctx: Option<&AddMapContext>`
  carries the Database lookups (`None` = standalone scope, no fold).
  (database.cc:1690) — dynamic hashed SymbolEntry.
- `add_equate_symbol(name, format, value, addr, hash) -> (EquateSymbol, u64)`
  (database.cc:1712) — builds the symbol with `category = equate`
  (database.cc:628), registers `value` on the symbol identity via
  `varnode::equate_symbol_registry::register_value` (the Rust stand-in for the
  C++ EquateSymbol subtype payload that `dynamic_cast<EquateSymbol*>`
  (varnode.cc:516) would read), runs the addSymbolInternal category-table
  registration (cc:1827-1836 via private
  `add_symbol_internal_category`, `catindex = list.size()` append), then
  pushes the 1-byte dynamic entry (database.cc:1722). Main-pipeline equates
  therefore reach `Varnode::copy_symbol_if_valid` with their value, and
  `get_category_size(equate)`/`get_category_symbol(equate, ind)` observe the
  same table state as the C++ scope.
- `clear()`, `clear_unlocked()`.
- `attach_child(id)`, `detach_child(id)`, `num_symbols()`.
- XML encode/decode (database.cc:2616/2744):
  - `encode(encoder)` — `<scope>` with name/id/label, optional `<parent>`,
    `<rangelist>`, and a `<symbollist>` of `<mapsym>` children (each carrying a
    symbol + its `<addr>`/`<hash>` mappings).
  - `encode_recursive(encoder, only_global)` (database.cc:1371) — encodes this
    scope; the Database drives the recursive descent over its child ids.
  - `decode(decoder)` (database.cc:2744) — standalone form: reads
    `<parent>` (skipped, applied by Database), `<rangelist>` /
    `<rangeequalssymbols>`, and a `<symbollist>` of
    `<mapsym>`/`<hole>`/`<collision>` children; `<hole>` properties are
    dropped and mappings install without the addMap flag rules (no
    Database side-channel).
  - `decode_with_ctx(decoder, flagbase, global_ranges)` (database.cc:2744,
    Database-integrated) — `<mapsym>` children install through the addMap
    rules with the LIVE flagbase property lookup + global discovery-range
    snapshot; `<hole>` children apply `setPropertyRange` IMMEDIATELY
    (database.cc:2778-2779 → 2683-2685) in document order — a `<hole>`
    BEFORE a `<mapsym>` feeds that mapsym's fold, one AFTER does not.
  - `add_map_sym(decoder, ctx)` (database.cc:1564) — parses one `<mapsym>`
    (symbol header + `<addr>`/`<hash>` mappings) and installs each mapping
    through `addMap(entry)` (database.cc:1602): the persist /
    global-discovery / addrtied + flagbase fold rules
    (`apply_add_map_rules`, database.cc:1126-1155) run per mapping with the
    flagbase state as of that document position; the installed entry
    carries `Varnode::mapped` extraflags (database.cc:1155/1147). For
    `<equatesymbol>` children the decode follows
    `EquateSymbol::decode` (database.cc:670-683): the `<value>` child is read
    (Rust `val`-attribute convention; an attribute-less `<value>` yields the
    database.hh:306 default 0) and the symbol identity is registered in
    `equate_symbol_registry` — mirroring the C++ `new EquateSymbol(owner)`
    (database.cc:1572-1573) whose object identity survives into
    `dynamic_cast<EquateSymbol*>`.
  - `decode_hole(decoder)` (database.cc:2667) — parses a `<hole>` element
    into a (Range, flags) pair (readonly/volatile bool attrs → the Varnode
    bits); the decode_with_ctx form forwards non-zero pairs to
    `PartMap::set_property_range` (database.cc:2683-2685).
  - `decode_collision_name(decoder)` (database.cc:2695) — parses a
    `<collision>` element's name.
  - `assign_default_names(base)` (database.cc:2850) — assigns default
    variable names to unnamed symbols via `build_default_name`.

### `Database`
A manager for symbol scopes for a whole executable. Faithful to `Database`
(database.hh:916).
- `new(id_by_name)`, `default()`.
- `get_global_scope()`, `get_global_scope_mut()`.
- `attach_scope(name, parent_id) -> u64`, `resolve_scope(id)`,
  `resolve_scope_mut(id)`, `find_create_scope(id, name, parent_id)`.
- `delete_scope(id)`, `delete_sub_scopes(id)`.
- `set_range(id, rlist)`, `add_range(id, range)`, `remove_range(id, range)`.
- `get_property(addr)` — `flagbase.getValue(addr)` (database.hh:946).
- `set_property_range(flags, range)` — database.cc:3220-3239: split at
  `getFirstAddr`/`getLastAddrOpen`, OR `flags` into every partition
  `[addr1, addr2)` — overlapping property ranges ACCUMULATE on the shared
  partitions.
- `clear_property_range(flags, range)` — database.cc:3245-3265: same walk,
  AND `!flags` into the partitions of the sub-range only.
- `flagbase: PartMap` — the `partmap<Address,uint4>` mirror (partmap.hh:50):
  `BTreeMap<Address, u32>` split points + a default value (0,
  database.cc:2929); `get_value` (partmap.hh:83), `split` (partmap.hh:119),
  `set_property_range`/`clear_property_range` (the database.cc walks).
  Key-form convention (FLAGBASE-CR-F2, 2026-09-27): keys and queries stay
  uniformly SPACELESS legacy `Address`es (the oracle's space-qualified
  ordering is projected to the RAM partition only — heritage.rs
  HERITAGE-FLAGBASE-SPACELESS-0001); enforced by
  `PartMap::debug_assert_spaceless_key_form` at the get_value/split
  boundary, which is `debug_assert!`-gated (zero release behavior —
  proven by byte-identical curl/httpd canon A/B and by the guard firing
  in a debug `should_panic` probe while a release probe does not panic).
  Switching either the producer side (loader readonly / SYMDB `<hole>`
  installs) or the consumer side (Ram consults) to `with_space`
  addresses alone would silently reorder the map (`Address::cmp` sorts
  `None` before every `Some(_)` tag); both sides must migrate to
  space-tagged keys together at the ADDRESS-0001 phase-3 merge.
- `AddMapContext` — RUDRA-GLUE carrier for the two `glb->symboltab` lookups
  `Scope::addMap` needs: the flagbase property at an address
  (`getProperty`, database.cc:1153) and the global-scope discovery-range
  test (`glbScope->inScope`, database.cc:1138).
- `map_scope(qpoint, addr) -> u64`, `num_scopes()`.
- XML encode/decode (database.cc:3270/3314):
  - `encode(encoder)` — `<db>` with optional `scopeidbyname` attribute,
    `<property_changepoint>` children, then the global scope and all its
    descendants via `encode_scope_recursive`.
  - `encode_scope_recursive(encoder, scope_id)` (database.cc:1371) —
    Database-driven recursive walk over the scope map.
  - `decode(decoder)` — reads `scopeidbyname`, property change-points, and
    one or more `<scope>` elements (parent resolved via `parse_parent_tag`,
    scope created via `find_create_scope`, contents filled by `Scope::decode`).
  - `parse_parent_tag(decoder)` (database.cc:3300) — parses a `<parent>`
    element, returning the parent scope id.
  - `decode_scope(decoder, new_scope_id)` (database.cc:3375) — registers and
    fills out a single Scope from a `<scope>` (or wrapping) element.
  - `attach_scope_by_id(scope_id, parent_id)` — RUDRA-GLUE helper mirroring
    `attachScope` (database.cc:3381) for `decode_scope`.
  - `decode_scope_path(decoder)` (database.cc:3398) — decodes a namespace
    path (`<val>` children) and ensures each namespace exists.

## L3 gaps
- `ScopeInternal` name-tree (`SymbolNameTree`) for ordered name lookup.
- `rangemap<SymbolEntry>` / `rangemap<ScopeMapper>` for address-keyed lookup
  (currently linear search).
- Full `Datatype` integration (type_name is currently a String placeholder).
- `Funcdata` ownership in `FunctionSymbol`.

## 2026-08-13: locked category table semantics (`SCOPE-CAT0-0001`)

`Scope` now represents Ghidra's `vector<vector<Symbol *>> category` with a
`CategoryList` that keeps indexed `NULL` holes and non-owning `Weak` symbol
references. The owning `symbols` name tree remains the only category-related
owner of each `Symbol`, matching `ScopeInternal`'s destructor and
`removeSymbol` behavior.

- `get_category_size(cat)` (`database.cc:2806`) returns zero for negative or
  absent categories and otherwise returns the physical vector length,
  including interior null holes.
- `get_category_symbol(cat, ind)` (`database.cc:2814`) returns no symbol for a
  negative/out-of-range category or index and for an interior null slot; a
  populated slot returns the same `Arc` allocation, preserving pointer
  identity.
- `set_category(id, cat, ind)` (`database.cc:2824`) clears only the symbol's
  former indexed slot and removes trailing nulls without compacting interior
  holes. Category 0 converts `ind: i32` to Ghidra's `uint2` index and places the
  symbol at that exact slot, padding with nulls. Categories greater than zero
  ignore `ind` and append. Negative categories update the symbol fields but do
  not create a category table.
- The outer table grows through all intermediate categories and never shrinks
  merely because an inner list becomes empty. Removing a symbol clears and
  trims its exact category list before releasing entries and the name-tree
  owner.

The locked direct oracle fixture is
`tests/oracle/scope_category_1204.{cc,rs,metadata.json}`, run by
`tools/run_scope_category_oracle.sh`. It records oracle tag/commit,
architecture/compiler/options, canonical input fingerprint, slot-by-slot
state, symbol `(category,index)`, exact identity, ownership, destruction count,
and pinned comparand hashes. Its proof is deliberately limited to these three
category functions plus the directly observed removal/ownership closure; it
does not promote the overall database module beyond L2.

## 2026-06-27：XML encode/decode（使用 marshal.rs 基础设施）

实现了完整的 XML 序列化，关闭 database.rs 的主要 L3 缺口：

**SymbolEntry**：
- `encode(encoder)`（database.cc:187）：编码地址/hash + uselimit（rangelist）。

**Symbol**：
- `encode_header(encoder)`（database.cc:363）：编码 name/id/namelock/typelock/readonly/volatile/indirectstorage/hiddenretparm/merge/thisptr/format/cat/index 属性。
- `decode_header(decoder)`（database.cc:394）：从属性解码（按 attribute_name 分发）。
- `encode_body(encoder)` / `decode_body(decoder)`（database.cc:466/473）：编码/解码 `<type>` 元素。
- `encode(encoder)` / `decode(decoder)`（database.cc:481/492）：完整 `<symbol>` 元素。

**Scope**：
- `encode_recursive(encoder, only_global)`（database.cc:1371）：递归编码 `<scope>` + 属性 + 子 scope + `<symbollist>`。
- `decode(decoder)`：解码 scope 的符号列表。

**Database**：
- `encode(encoder)`（database.cc:3270）：编码 `<db>` + property_changepoint + 全局 scope。
- `decode(decoder)`（database.cc:3314）：解码完整数据库（属性 + property_changepoint + scopes）。

**ID_BASE** 修正为 `0x4000_0000_0000_0000`（database.cc:45），匹配 Ghidra 的内部 ID 高位模式。

**marshal.rs Decoder trait 新增**：`attribute_name(id) -> Option<String>` + `element_name(id) -> Option<String>`，支持按名称分发的解码。

测试：新增 2 个（Symbol + Database encode/decode round-trip）。剩余 L3 缺：rangemap/partmap（目前用线性搜索/Vec 替代）。

### 2026-07-01：Symbol dtype 字段 + get_type/set_dtype
- Symbol 加 `dtype: Option<Arc<Datatype>>` 字段（database.hh `Symbol::type`）。
- `get_type() -> Option<Arc<Datatype>>`（database.hh:244）+ `set_dtype(dt)`。
<!-- annotation-pass: 2026-07-04 -->

## 2026-07-22：Full Symbol/Scope/Database XML port (L3 completion)

Ported the remaining Symbol/Scope/Database/SymbolEntry XML serialization from
database.cc, closing the last XML gap:

**SymbolEntry** (database.cc:187/206):
- `encode` fixed to emit the `offset` attribute on `<addr>` (was `space`).
- `decode` + private `decode_use_limit` — parse `<hash>`/`<addr>` + the
  `<rangelist>` uselimit.

**Symbol subclasses** — full encode/decode per subclass:
- `FunctionSymbol::encode`/`decode` (database.cc:566/580) — `<functionshell>`.
- `EquateSymbol::encode`/`decode` (database.cc:659/670) — `<equatesymbol>` +
  `<value>`.
- `LabSymbol::encode`/`decode` (database.cc:751/759) — `<labelsym>`.
- `ExternRefSymbol` (new struct) `encode`/`decode` (database.cc:796/805) —
  `<externrefsymbol>`.
- `UnionFacetSymbol` (new struct) `encode`/`decode` (database.cc:698/708) —
  `<facetsymbol>` + `field` attribute.

**Scope** (database.cc:2616/2744/1564/2850):
- `encode` — `<scope>` + `<parent>` + `<rangelist>` + `<symbollist>` of
  `<mapsym>` children (with `rangetree_encode` helper).
- `decode` — reads `<parent>`/`<rangelist>`/`<rangeequalssymbols>`/`<symbollist>`
  (dispatching `<mapsym>`/`<hole>`/`<collision>`), via `decode_rangelist`,
  `add_map_sym`, `decode_hole`, `decode_collision_name`.
- `add_map_sym` (database.cc:1564) — parse one `<mapsym>` (symbol + mappings).
- `assign_default_names` (database.cc:2850) + `build_default_name` — default
  variable naming.

**Database** (database.cc:3270/3314/3300/3375/3398):
- `encode` enhanced: emits `scopeidbyname` attribute + drives
  `encode_scope_recursive` over the scope map.
- `decode` enhanced: reads `scopeidbyname`, property change-points with
  `offset`/`val`, and resolves each `<scope>`'s parent via `parse_parent_tag`.
- `parse_parent_tag` (database.cc:3300), `decode_scope` (database.cc:3375),
  `attach_scope_by_id` (RUDRA-GLUE for `attachScope`, database.cc:3381),
  `decode_scope_path` (database.cc:3398).
- `id_by_name` field added to the struct + wired through `new`.

Each ported function carries a `// Ghidra: database.cc:<line> <func>` comment
(84 alignment comments total). The one RUDRA-GLUE method
(`attach_scope_by_id`) is marked accordingly.

Tests: 26 database tests pass (`cargo test --lib database::`), including the
Symbol and Database encode/decode round-trips. `cargo check --lib` is clean
(0 database.rs warnings/errors).

## 2026-08-23：equate 值注册表接线（DATABASE-EQUATE-VALUE-REGISTRY-0001）

- `EquateSymbol::new`（database.cc:624-631）补齐 cc:628
  `category = equate`：此前包装的 base `Symbol` 一直停留在 `NoCategory`，
  与 C++ 构造器状态不一致（varnodeeq 交付发现的残差）。
- `Scope::add_equate_symbol`（database.cc:1712-1724）：注册侧 base
  `Symbol` 现在设 `category = Equate`（cc:628），并在注册 `Arc` 身份上调用
  `varnode::equate_symbol_registry::register_value(&sym_arc, value)` ——
  C++ 中被注册对象本身就是携带 `uintb value` 的 EquateSymbol，
  `dynamic_cast<EquateSymbol*>`（varnode.cc:516）从同一对象身份读出
  payload；Rust 无子类型化，注册表条目即该 subtype payload 的替身，因此
  主管线（database::Scope 侧创建/解码的 equate）从此携带 value 到达
  `Varnode::copy_symbol_if_valid`。
- `Scope::add_map_sym`（database.cc:1564-1606）`<equatesymbol>` 腿：此前
  `<value>` 子元素被 `close_element_skipping` 整体跳过，解码出的 equate 既
  无值也无 equate 身份。现按 `EquateSymbol::decode`（database.cc:670-683）
  读取 `<value>`（Rust 编码侧 `val` 属性约定；无属性时取 database.hh:306
  解码构造器默认 0），并对该 `Arc` 注册 equate 身份，镜像 cc:1572-1573
  `new EquateSymbol(owner)` 的对象身份语义。真实 Ghidra XML 以元素文本
  （ATTRIB_CONTENT，`<value>66</value>`）携带值，Decoder trait 目前不暴露
  文本内容——属性化形式已覆盖 Rust 编码回环，文本形式登记为残差
  （需 marshal.rs ATTRIB_CONTENT 访问器，不在本租约 write-set）。
- 残差（如实登记）：`Funcdata::build_dynamic_symbol` 常量 equate 腿
  （funcdata.rs / funcdata_varnode.cc:1301）走 varmap ScopeLocal 模型，
  不经 `database::Scope::add_equate_symbol`，也不构造 varnode 级
  mapentry——funcdata.rs/varmap.rs 不在本租约 write-set，未接线。
- 验证：`cargo test --lib database` 59 绿（新增同值重复/跨 scope 隔离/
  XML 解码注册/copy_symbol_if_valid 通路 4 项）；oracle 行为门禁
  `tests/oracle/database_equatereg_1204`（pin-base schema2，
  `tools/run_database_equatereg_oracle.sh`）。

## 2026-08-23（补充）：addSymbolInternal 类别表注册接入 add_equate_symbol

- `Scope::add_symbol_internal_category`（私有，database.cc:1810
  `ScopeInternal::addSymbolInternal` 的类别块 cc:1827-1836）：`category >= 0`
  时按 cc:1828-1829 将外层类别向量扩张到该类别；`category > 0` 时
  `catindex = list.size()`（cc:1831-1832），类别 0 沿用符号现有 catindex 槽；
  cc:1833-1835 以 NULL 槽填充后放置 Weak 引用。
- `add_equate_symbol` 在 cc:1718 对应位置调用之：同值重复的第二个 equate
  `catindex=1`、`get_category_size(equate)=2` 与 C++ 可观察状态一致（此前
  Rust 完全不入类别表）。`add_union_facet_symbol` 存在同样缺口（本租约
  equate 限定，登记为后续 TODO）。

## 测试签名适配（2026-08-23，root）

equate-pipeline 测试随 VARNODE-COPYSYMBOL-HIGHBRANCH-0001 的关联函数签名（copy_symbol_if_valid(&Arc, &Varnode)）适配调用点，修复 opswitch 复核发现的 master lib-test 编译失败（生产代码零改动）。

## 2026-08-25：Database 级 query 通道入口 + resolvemap 分裂语义（B3-COREACTION-CONSTANTPTR-0001 a1）

- `Database::ancestor_stack(scope_id)`（database.cc:1251 的 `getParent()` 链
  物化）：从 `scope_id` 沿 `parent_id` 上溯到 global 的有序 `Vec<&Scope>`
  （`[0]` 最内层），带 parent 环护栏。这是静态 `Scope::query_*` 家族
  （`stack_container` 等）所需的「祖先栈」约定构造器——此前无生产调用方。
- `QueryContainerHit`：`queryContainer`/`queryProperties` 命中的可观察投影
  （scope_id/name、entry_addr/size/offset、symbol_id/name、`getAllFlags`、
  `type_metatype`、`base_is_char_print`、`symbol_type`）。携带
  ActionConstantPtr::isPointer（coreaction.cc:1151-1163）消费的全部字段：
  needexacthit 判据 `entry->getAddr() != rampoint`（经 `entry_addr`）与
  char-array 中部例外 `TYPE_ARRAY + base->isCharPrint()`（经
  `type_metatype`+`base_is_char_print`）。段(b) 新增 `symbol_type:
  Option<Arc<Datatype>>`（`entry->getSymbol()->getType()` 的共享句柄，
  spacebaseConstant 的 getTypePointerStripArray/typelock 折叠消费，
  funcdata.cc:413-419）；`PartialEq` derive 因 Datatype 无等价实现而移除
  （无既有相等比较调用方）。
- `Database::query_container(qpoint,addr,size,usepoint)`（database.cc:1246
  Database 级入口）：`map_scope(qpoint,addr)` 定位 base scope →
  `ancestor_stack` → 静态 `Scope::query_container` → 命中投影。
- `Database::query_properties(qpoint,...)`（database.cc:1263）：同一栈上的
  静态 `Scope::query_properties`，`flag_lookup` 直接接本库 `get_property`
  （flagbase）；三分支（entry getAllFlags / scope-only mapped|addrtied|persist|prop
  / property-only）不变。
- `Database::is_read_only(qpoint,...)`（database.cc:1796 `Scope::isReadOnly`）：
  `query_properties` 后测 `readonly` 位——ruleaction.cc:7372 /
  printc.cc:1709 的消费形态。
- `Database::query_by_name(qpoint,nm) -> Vec<QueryNameHit>`（database.cc:1198）。
- `Database::add_symbol_mapped(scope_id,nm,dtype,addr,size)`
  （database.hh:742 `Scope::addSymbol(nm,ct,addr,usepoint)` 的库级入口）：
  `AddMapContext` 接 LIVE flagbase + global 发现范围（与 `Database::decode`
  同一接线），走既有 `add_map_point`/`apply_add_map_rules` 完整 addMap 折叠
  （persist/addrtied/属性折入 symbol flags）。
- `add_map_point` 修正：整映射 entry 的 extraflags 从 0 改为
  `Varnode::mapped`（database.cc:1148-1149 `addMapInternal(symbol,
  Varnode::mapped,...)`），`getAllFlags` 现在包含 mapped 位。
- `add_range`/`remove_range` 重写为 `clearResolve`+`fillResolve` 语义
  （database.cc:3050-3077/:2871/:2897）：global scope 不入 resolvemap
  （cc:2873/:2901 早退；Rudra scope 无 fd 绑定，functional-scope 守卫为空，
  已注释）；namespace range 以 `resolve_insert_split`（ScopeResolve
  rangemap insert 的重叠分裂语义，database.hh:900）写入，新 range 接管与
  现有 owner 的重叠区，旧 owner 保留不相交余量。
- `map_scope` 修正回退语义：空 resolvemap 与未命中均回退 **qpoint**
  （database.cc:3188/:3195），不再是 global_scope_id。
- 验证：双侧 fixture `tests/oracle/cptr_query_channel_1204`（runner
  `tools/run_cptr_query_channel_oracle.sh`，oracle 12.0.4 真实执行）；
  `cargo test` 因 master 既有的 typeop.rs 测试目标编译错误在本分支同样
  不可用（本租约外），`cargo check --lib` 绿。

### 2026-08-26：findContainer 移植 + maptable 惰性索引（MAINDIFF-GLOBAL-0001）
- `Scope::find_container` 重写为 `ScopeInternal::findContainer`
  （database.cc:2250-2276）的忠实移植：签名加 `usepoint`（`inUse` 过滤在
  cc:2272 内部，stackContainer cc:952 依赖），返回值从 `Option<&SymbolEntry>`
  改为 `Option<usize>`（entries 下标，免除 stackContainer 的线性
  position 查找）。选择语义逐条对齐：窗口逆序走（cc:2267-2268
  `--res.second`）、`getLast() >= end` 包含判定（cc:2270）、严格更小
  `size < oldsize || oldsize == -1`（cc:2271）、`inUse(usepoint)`
  （cc:2272）、精确尺寸 break（cc:2274）。
- 新增 `addr_index: Mutex<AddrIndex>`：按 `(addr, 插入 seq)` 排序的
  maptable 等价物（database.hh:877-878 的 per-space rangemap）+ 前缀最大
  end 剪枝数组；所有 entries 变更点（add_map_internal/remove_symbol/
  decode/add_function_name 等）`invalidate_addr_index()` 置脏，查询时惰性
  重建——纯函数于 entries 的查询答案与 C++ 增量维护一致。`Scope` 的
  `Clone` 改手写（拷贝后脏索引，等价 C++ 拷贝构造逐条 addMap）。
- `Database::query_container_entry`（queryContainer 活入口形态）与
  `query_properties`/`discover_scope`（database.cc:1246/1263/1353）是
  `Funcdata::mapGlobals`（funcdata_varnode.cc:1701/1703）与
  `linkSymbol`（cc:1169）的查询通道。

## 2026-08-29（FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001）：inUse 三腿 + addMap 折叠接线 + same_storage_identity

- `SymbolEntry::in_use(usepoint)` 修正为 database.cc:114-120 全三腿：
  `isAddrTied()`（symbol 的 addrtied 位）恒 true；Ghidra-invalid usepoint
  （legacy spaceless Address 即 is_invalid）恒 false；否则
  `uselimit.in_range(usepoint)`。旧"空 uselimit = 全程有效"读法与 cc:118-119
  矛盾——空 uselimit 的 entry 只因 addMap 的 addrtied 折叠才有效。
- `SymbolEntry::same_storage_identity(other)`（RUDRA-GLUE）：C++
  `SymbolEntry*` 指针比较的稳定恒等代理（symbol Arc ptr_eq + addr + offset +
  size + hash），供 varnode.cc:415 `mapentry != entry` 使用。
- `Scope::add_symbol_mapped`（database.cc:1530 addSymbol 形态）与
  `Scope::add_code_label`（cc:1677 `addMapPoint(sym,addr,Address())`）都改经
  `apply_add_map_rules`（database.cc:1126-1155 addMap 折叠：persist /
  global-discovery uselimit 清空 / 空 uselimit → symbol ADDRTIED + flagbase
  property 折叠；label entry 的 extraflags 随 addMapInternal 取
  `Varnode::mapped`）。findCodeLabel 的 `inUse(addr)` 由 addrtied 腿放行。

## 2026-09-28（S2CODESTAR-DOWNCHAIN-0001）：函数符号 code 类型改工厂内驻实例

`FunctionSymbol::build_type` 与 `Scope::add_function` 的符号 `dtype` 此前为裸
`TypeCode::new()` 构造——`TYPE_INCOMPLETE` flag 残留（`get_type_code` 会清除它，
type.cc:3699）且每次调用产生**非内驻**实例。oracle 侧
`FunctionSymbol::buildType`（database.cc:514-520）用
`scope->getArch()->types->getTypeCode()`——**工厂内驻**实例。此前无消费者比较
符号类型与传播侧 code\* 型（同一工厂的 interned 实例），该偏差不载重；分析侧
符号通道（ActionConstantPtr→spacebaseConstant 的 code\* 铸造）落地后，
`pcVar4 == (code *)_ZN…D0Ev` 多余 cast 族（SetCasts 对两型判不等）暴露此缺口。
修复：双位点改 `TypeFactory::shared_default().get_type_code()`
（gen 驱动的 arch factory 即 shared_default，见 examples/gen_decompile.rs
build_architecture）。行为等价性由 canon 双语料恒等（curl 54/httpd 36）+
sq 镜面 −126 实测背书。

## 2026-09-24（HTTPD-CODEREF-SYMBOLIZE-0001）：add_function 补 FunctionSymbol::buildType + addMap 折叠旗标

`Scope::add_function`（database.cc:1615）此前只建 `type_name=="func"` 的
裸符号；函数符号的两段语义缺失使打印侧容器命中读不到 CODE metatype：

- **FunctionSymbol::buildType（database.cc:514-520）**：符号数据类型 =
  `TypeFactory::getTypeCode()` 的泛型 code 类型，且符号携带
  `namelock|typelock`。`add_function` 现在置 `dtype=Code` +
  `NAMELOCK|TYPELOCK`——`find_container` 命中透出 metatype，PrintC
  opPtrsub 的 spacebase 臂（printc.cc:1068-1069）据此对函数符号不打 `&`。
- **Scope::addMap 折叠（database.cc:1131-1133, 1147-1151）**：全局 scope
  上的整图点积分置 `persist`；合法地址 + 空 uselimit 置 `addrtied`（两
  旗标在 addMapInternal 前折进符号 flags）。`addrtied` 是
  `SymbolEntry::inUse`（database.cc:114-119）的载荷语义——地址绑定条目
  对任意 usepoint 有效，包括 linkSymbolReference 与打印侧 spacebase 查询
  携带的 invalid usepoint。与 2026-08-29 节的 `apply_add_map_rules` 同源
  语义，在 addFunction 的整图条目路径上内联。

消费方=examples/httpd_decompile.rs 打印期符号 DB（canon golden 的
analyzeHeadless 函数符号层）；门禁数据见 docs/api/printc.md 同日节。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 3 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

## 2026-09-26（MIGW1-DATABASE-0005）：真缺失 63 定义 Rust 化（wave MIGW1 phase 1）

来源=车道 DECOMP 未映射分解（`UNMAPPED_DECOMPOSITION_2026-09-26.md` §6，database
76 条真缺失中 MapIterator×9 + NullSubsort×4 共 13 条按结构吸收裁决，63 条逐定义
Rust 化）。本 phase 落地全部 63 条的 Rust 侧定义 + `// Ghidra:` 锚；B2 双侧
fixture 见 tests/oracle/ 四件套（`database_symface_1204` / `database_scope_tree_1204`
/ `database_scopeinternal_1204` / `database_scope_name_parse_1204`）。

### 新增函数（锚 = 锁定 oracle e40ed130 定义起始行）

| Rust | Ghidra 锚 | 说明 |
|---|---|---|
| `SymbolEntry::get_first_use_address` | database.cc:122 | 空 uselimit → invalid Address |
| `SymbolEntry::print_entry` | database.cc:166 | Ghidra 文本格式；`<space>:` 前缀仅在地址带空间时出现（legacy 无空间模型投影为裸 hex，B2 记 MISMATCH） |
| `EntrySubsort::{from_parts,earliest,from_bool,lt}` | database.hh:112/114/119/129 | 同地址 sub-sort（useindex,useoffset）字典序 |
| `Symbol::get_bytes_consumed` | database.cc:508 | dtype size；FunctionSymbol 覆写为 consume_size |
| `Symbol::get_map_entry_position` | database.cc:301 | 逐字保留 cc:309 计数器读**被查条目** size 的怪癖 |
| `Symbol::{depth_scope,depth_resolution}` 字段 | database.hh:190-191 | getResolutionDepth 的 memo 对 |
| `Database::get_resolution_depth` | database.cc:323 | 含 memo 短路（stale 返回 bug 兼容）+ isNameUsed 终止域 |
| `Database::is_name_used_terminating` | database.cc:2417 | op2 终止 + 永不进全局域 |
| `FunctionSymbol::build_type` | database.cc:514 | getTypeCode + namelock\|typelock；`new` 按构造序调用 |
| `FunctionSymbol::get_function_shell` | database.cc:557 | MIGRATION RULING：暴露惰性 Funcdata 构造参数四元组，Funcdata* 身份通道 UNTESTED（driver 层持有） |
| `LabSymbol::build_type` / `new_decode` | database.cc:728/745 | base(1,unknown)；"label" type-name 仍是子类判别通道 |
| `ExternRefSymbol::build_name_type` / `new` 调用 / `new_decode` / `get_ref_addr` | database.cc:768/789；hh:351/352 | code 指针类型 + `_exref` 名生成 + externref\|typelock；decode 末尾按 cc:821 接线 |
| `UnionFacetSymbol::{new,new_decode,get_field_number}`；`field_num: i32` | database.cc:691；hh:323/324 | fieldNum 为 int4（-1=整 union）；ctor 置 union_facet 类别 |
| `Scope::hash_scope_name` | database.cc:880 | crc 级联；名字字节 ≥0x80 按**有符号 char** 符号扩展进 uint4（cc:888） |
| `Scope::attach_child` / `detach_child`（锚更新） | database.cc:857/866 | 拆分实现：back-pointer=parent_id（Database 侧写）+ children 表 |
| `Scope::children_begin` / `children_end` | database.hh:765/766 | children 切片迭代器 |
| `Scope::decode_wrapping_attributes` | database.hh:719 | 基类 no-op 逐字 Rust 化 |
| `Scope::print_bounds` | database.hh:789 | rangetree printBounds（address.cc:588 格式；space-keyed 树每行带 `<space>: ` 前缀，Range::printBounds address.cc:283） |
| `ScopeRangeTree` / `ScopeRange` | address.hh:169/194 | CSPEC-GLOBAL-APPLY-0001：`Scope.rangetree` 的 space-keyed 形态（`set<Range>` 按 (space index, first) 序）；`insert_range`/`remove_range`/`in_range`/`print_bounds` 逐字移植 address.cc:383/417/468/588（与 address.rs `SpaceRangeList` 同 oracle 双子——DB 树键 IR-space enum，SpecQuery 流无 SpaceRegistry）；`Scope::add_range_spaced`/`remove_range_spaced`/`in_scope_spaced` 为 database.cc:1105/1114/hh:597 正形，旧 spaceless `add_range`/`remove_range`/`in_scope` 为 RAM 绑定委托（驱动 PT_LOAD/fixture 兼容）；`Database::add_range_spaced`=cc:3050 正形（clearResolve→addRange→fillResolve，resolvemap 只投影 RAM 分区）；rangetree encode 带 `space` 名属性、decode 读之（Range::encode/decode address.cc:292/300） |
| `Database::query_properties_spaced` | database.cc:1263 | CSPEC-GLOBAL-DB-0001（CSPEC-GLOBAL-APPLY-0001 B2）：space-carrying queryProperties 正形——mapScope（非 RAM 探针 fallthrough qpoint）+ stack walk（entry 臂仅 RAM entries=DB-LOCALSCOPE-MAP-0001 split 残差）+ in_scope_spaced 发现臂 + cc:1271-1279 三臂折叠；`get_property_spaced` 非 RAM 读 flagbase 默认分区；双侧 fixture 8 探针格（ram/register 窗内外/unique/OTHER/const）byte-identical MATCH |
| `Scope::override_size_lock_type` / `reset_size_lock_type` | database.cc:1387/1402 | LowlevelError 文本走 Err 通道；reset 恢复同尺寸 unknown 基类型 |
| `Scope::add_dynamic_map_internal` | database.cc:1874 | whole_count 计数 + multi-entry（whole_count>1 即集合成员） |
| `Scope::category_sanity` | database.cc:1992 | 内部 NULL 槽 → 整类清 no_category；先收集 id 再改（C++ 拷贝 list 等价） |
| `Scope::resolve_external_ref_function` | database.cc:2362 | `queryFunction(refAddr)` → find_function 层投影 |
| `Scope::print_entries` | database.cc:2791 | `Scope <name>` + 每条 printEntry；单空间插入序=maptable 序，跨空间 MISMATCH 记档 |
| `Scope::multi_entry_symbols` | database.hh:865-866 | multiEntrySet 迭代面；固定 symbol-id 序（C++ 指针序=分配噪声，B2 双侧归一化） |
| `Database::resolve_scope_by_name` | database.cc:1315 | 三分支逐字：hash+名验证 / 十进制直名（istringstream 语义）/ id 序线性扫 |
| `Database::is_sub_scope` / `get_full_name` / `get_scope_path` / `find_distinguishing_scope` | database.cc:1432/1443/1458/1481 | 含四快查 + 双 path 对比全部边界 |
| `Database::clear_references` | database.cc:2893 | 子树 idmap+resolvemap 清除；global 豁免 clearResolve；delete_scope 组合它 |
| `Database::adjust_caches` | database.cc:2975 | 按 id 序（=ScopeMap 序）逐 scope |
| `Database::resolve_scope_from_symbol_name` | database.cc:3113 | delim 解析 + 绝对路径（位置 0 delim）+ 失败 null |
| `Database::find_create_scope_from_symbol_name` | database.cc:3151 | !idByNameHash → Err("Scope name hashes not allowed")；hash id 链创建 |
| `SymbolCompareName::is_before` | database.hh:366 | name 字典序 + nameDedup tie-break |
| `DuplicateFunctionError::new` | database.hh:435 | 字段 address/function_name/message |

### 结构吸收/等价裁决（13+ 条，记录依据不硬移植）

- **MapIterator 全家 ×9**（hh:384/391/398/401/406/414/421 + cc:826/841）：C++
  手写双游标（EntryMap 表 + list 游标）跳空推进 = Rust `entries` 切片迭代；
  `ScopeInternal::begin/end/beginDynamic/endDynamic`（cc:1889/1914/1921/1927/1933/1939）
  的迭代器端点由 `Scope::begin_end`/`begin_end_dynamic` 切片投影承载。
- **NullSubsort ×4**（hh:879-882）：恒 false 比较器；Rust resolvemap
  （`Vec<(Range,u64)>`）无 sub-sort 维度，比较器语义恒 false 由"无该维度"承载。
- **ScopeMapper ctor+getter ×5**（hh:893-898）：`(Range, scope_id)` 元组的字段
  投影（first/last/scope）。
- **EntryInitData ctor**（hh:99-100）：`SymbolEntry::new_static` 的具名参数即
  initdata 载荷。EntrySubsort 拷贝构造（hh:124）= `#[derive(Copy)]`。
- **ctor/dtor**：`Scope` ctor（hh:566，现有 `Scope::new`）；`ScopeInternal` ctor×2
  （cc:1948/1955 — `maptable.resize(numSpaces)` 由惰性 AddrIndex 承载）；`~Scope`
  （cc:1182）/`~ScopeInternal`（cc:1962）/`~Database`（cc:2933）/`~FunctionSymbol`
  （cc:552）/`~ExternRefSymbol`（hh:348）= Rust 所有权模型（BTreeMap/Arc Drop），
  删除顺序（id 序）与 C++ 递归 children 删除的观察等价性由
  database_scope_ownership_1204 fixture 锚定。
- **Scope::restrictScope**（cc:1096）：`fd = f` 绑定在 Rust 模型中由 varmap.rs
  的 ScopeLocal（构造即持 Funcdata）承载——database::Scope 值模型无函数域角色；
  状态 UNTESTED（跨文件域界，移交 root 裁量是否开 varmap 侧票）。
- **turnOnDebug/turnOffDebug**（hh:562-563）：`#ifdef OPACTION_DEBUG` 门控；锁定
  oracle 编译不带该宏（fixture runner 的 make 无 -DOPACTION_DEBUG），双侧同不
  存在——按编译期等价裁决，不 Rust 化死代码。
- **ScopeInternal::buildSubScope**（cc:1804）：未附着中间 Scope 在 Rust 公共
  Database API 下不可观察；`findCreateScope`（buildSubScope+attachScope 复合）
  承载其可观察面。

### 与在案票据的交叉引用

- **CSPEC-GLOBAL-APPLY-0001**（P0）：范围=database.cc:1271-1277
  `Scope::queryProperties` 的 finalscope fold + 全局作用域 DB 写入。本票 63 条
  清单**不含** queryProperties——零重叠；本票不实现该写入路径。
- **VARMREKEY**：varmap.rs SymbolStore 稳定槽位；本票未触碰 varmap.rs。

## 2026-09-26（MIGW1-DATABASE-0005 phase 2）：Scope 查询面 B2 双侧 fixture + 工厂参数化裁决

### DATABASE-SCOPE-TREE-FIXTURE-0001（tests/oracle/database_scope_tree_1204.{cc,rs}）

双侧 fixture 覆盖 14 个清单函数（oracle 侧 = BfdArchitecture 生产环境 + 显式 id
scope 树；Rust 侧 = 生产 `Database`/`Scope`/`TypeFactory` 值模型，零 fixture 侧重复
实现）。50 case 全量 stdout 逐字节 **MATCH**（runner
`tools/run_database_scope_tree_oracle.sh`，registry
`database_scope_tree_1204`）：

| 函数 | Ghidra 锚 | fixture 覆盖面 |
|---|---|---|
| `Scope::hashScopeName` | database.cc:880 | crc 级联 4 输入（含 ≥0x80 字节有符号 char 符号扩展——双侧同字节序列 `\xc3\xbf`，见下裁决） |
| `Scope::resolveScope` | database.cc:1315 | 三分支：hash+名验证 / 十进制直名（istringstream 前缀解析）/ id 序线性扫 |
| `Scope::isSubScope` | database.cc:1432 | self/parent/global/reverse/反身 5 边界 |
| `Scope::getFullName` | database.cc:1443 | 嵌套名/全局空串 |
| `Scope::getScopePath` | database.cc:1458 | 含 global+self 的路径 |
| `Scope::findDistinguishingScope` | database.cc:1481 | 四快查 + 双 path 对比 8 边界 |
| `Symbol::getResolutionDepth` | database.cc:323 | same/null/ancestor/memo/collision/sibling 6 case |
| `ScopeInternal::isNameUsed` | database.cc:2417 | 终止域 + 永不进全局域（经 resdepth 碰撞/兄弟 case） |
| `Scope::overrideSizeLockType` | database.cc:1387 | 同尺寸成功/异尺寸/未锁三条 LowlevelError 文本 |
| `Scope::resetSizeLockType` | database.cc:1402 | 恢复同尺寸 unknown 基类型 + 幂等 no-op |
| `Scope::attachScope`/`detachScope` | database.cc:857/866 | 生产注册路径（Database::attachScope/deleteScope 复合）子数+父别名 |
| `Database::clearReferences` | database.cc:2893 | 子树递归 idmap+resolvemap 清除（deleteScope 投影） |
| `Database::adjustCaches` | database.cc:2975 | 全 idmap 扫描 no-throw + 成员不变 |

### 裁决 R1：`getBase(size,TYPE_UNKNOWN)` 工厂参数化（前次遗留脏改的收敛）

phase 1 提交时 `LabSymbol::build_type`/`Scope::reset_size_lock_type` 内联构造
`"undefined"` 命名的 unknown 基类型。fixture 对拍发现这是**环境依赖语义**：
Ghidra 的 `glb->types->getBase(size,TYPE_UNKNOWN)` 经 TypeFactory 核心类型表解析
——standalone SLEIGH 表（sleigh_arch.cc:229-232）产出 `xunknownN`，
ArchitectureGhidra 回退表（ghidra_arch.cc:349-352）产出 `undefinedN`，未注册尺寸
产出**无名** TypeBase（type.cc:3631 findAdd 规范化路径）。硬编码任一名字都在另一
环境错误。收敛为**工厂参数形态**：两函数签名增加
`types: &crate::type_system::typefactory::TypeFactory`（RUDRA-GLUE：C++ 经
`scope->getArch()->types` 取工厂，Rust 值模型 Scope 无 arch 句柄），调用生产
`TypeFactory::get_base`（type.cc:3631 的既有移植）。fixture 侧
`TypeFactory::new_flavor(8, CoreTypeFlavor::Standalone)` 镜像 oracle 的
BfdArchitecture 环境，双侧 `reset_sizelock|name=xunknown4` 一致。canon 管线零
影响：两函数无生产调用方（仅单测+fixture），canon 的 `undefinedN` 命名由
`CoreTypeFlavor::DataOrg` 工厂承载。

### 裁决 R2：有符号字节 case 的双侧可表达性

C++ `hashViaProduction(db, global, "\xff")` 喂单字节 0xFF；Rust 名字通道是 UTF-8
`&str`，孤立 0xFF 字节不可表达。双侧 fixture 统一改喂 `"\xc3\xbf"`（Rust
`"\u{ff}"` 的 UTF-8 编码，两个高位字节均触发符号扩展）——语义覆盖不减（两个符号
扩展字节强于一个），双侧字节序列恒等是 B2 对拍的先决条件。fixture 注释记录该约束。

### 残余 UNTESTED（诚实记账，不升 MATCH）

63 条清单中 fixture 未覆盖者维持 UNTESTED：`addDynamicMapInternal` whole-count、
`categorySanity`、`multi_entry_symbols`、`resolveExternalRefFunction`、
`decodeWrappingAttributes`、children 迭代器端点、`printEntries`（多空间聚合面）、
`Scope::decode` 族 encode/decode 残项。结构吸收裁决（MapIterator/NullSubsort 等
13 条）不在此列（裁决即交付物）。

## 2026-09-26（MIGW1-DATABASE-0005 phase 2 续）：Symbol 子类面第二双侧 fixture

### DATABASE-SYMBOL-SUBCLASS-FIXTURE-0001（tests/oracle/database_symbol_subclass_1204.{cc,rs}）

31 case 全量 stdout 逐字节 **MATCH**（runner
`tools/run_database_symbol_subclass_oracle.sh`，registry
`database_symbol_subclass_1204`），覆盖 18 个清单函数/载体：

| 函数/载体 | Ghidra 锚 | 覆盖面 |
|---|---|---|
| `FunctionSymbol::buildType` + 双 ctor | database.cc:514/534/545 | code 类型 size 1 + namelock\|typelock + 构造序（name 后置）+ consumeSize 覆写 |
| `LabSymbol::buildType` + 双 ctor | database.cc:728/736/745 | 工厂解析的 xunknown1 占位类型（裁决 R1 的双侧见证） |
| `ExternRefSymbol::buildNameType`/ctor/`getRefAddr` | database.cc:768/789；hh:351 | 自动名 `<shortcut><printRaw>_exref` + externref\|typelock + code 指针尺寸=refaddr 地址尺寸 |
| `UnionFacetSymbol` ctor 族 + `getFieldNumber` | database.cc:691；hh:323/324 | fieldNum i32（-1=整 union）+ union_facet 类别 |
| `Symbol::getBytesConsumed` | database.cc:508 | 类型尺寸通道 |
| `Symbol::getMapEntryPosition` | database.cc:301 | **cc:309 怪癖双侧钉死**：计数器条件读被查 entry 尺寸（非迭代项）——whole 被查项=全表索引、partial 被查项恒 0、缺席 -1 |
| `SymbolEntry::getFirstUseAddress` | database.cc:122 | 首用范围/空 uselimit 无效地址 |
| `SymbolEntry::printEntry` | database.cc:166 | 三形态逐字串：静态空 uselimit（`all`）/静态范围 uselimit（`ram: 4000-4fff`）/动态（`<dynamic>`） |
| `SymbolEntry::EntrySubsort` | database.hh:107-134 | earliest/latest 边界 + (useindex,useoffset) 字典序 + 相等 |
| `SymbolCompareName` | database.hh:366 | name 字典序 + nameDedup tie-break |
| `DuplicateFunctionError` | database.hh:435 | "Duplicate Function" 消息 + address/functionName 载体 |
| `Scope::printBounds` | database.hh:789 | rangetree 排序范围打印（CSPEC-GLOBAL-APPLY-0001 后经 `ScopeRangeTree::print_bounds`，行格式=address.cc:283 `space: first-last`） |

**载体裁决（fixture 注释+此处记录）**：① C++ `FunctionSymbol(Scope*,int4)` decode
ctor 的可观察状态（空名+consumeSize+code 类型+锁旗标）在 Rust 值模型经空名命名
ctor 等价到达（字段恒等，构造路径差）；② C++ Symbol 自持 `mapentry` 表，Rust
`get_map_entry_position` 以参数收表——fixture 以同插入序组装；③ 动态 entry 经
`SymbolEntry` 动态 ctor（hh:140）直接构造——`addMapInternal` 对无效地址解引用
space（C++ 同样崩溃路径），双侧一致不经过。

### 跨文件发现（报 root 裁量，非本票写域）：DATATYPE-PRINTRAW-0001

fixture 设计时亲读 type.cc 发现 `src/type_system/datatype.rs:1804 print_raw`
（锚 type.cc:139 Datatype::printRaw）的 Code/Union/Enum/Struct/Spacebase/Array
臂与锁定 oracle 偏差：

| 臂 | C++ 真值 | Rust 现值 |
|---|---|---|
| Code | `TypeCode::printRaw`（type.cc:2772）：`<name\|funcptr>()` | `code {name}` |
| Union/Enum/Struct/Spacebase | 无 override→`Datatype::printRaw`（type.cc:139）：`<name\|unkbyteN>` | `union {name}`/`enum {name}`/`struct{…}`/`spacebase {name}` |
| Array | `TypeArray::printRaw`（type.cc:1204）：`<elem> [N]`（空格） | `{elem}[{n}]` |
| Pointer | `TypePointer::printRaw`（type.cc:910）：`<ptrto> *` + spacebase 指针 `(<space>)` 臂 | `{ptr_to} *`（缺 spaceid 臂） |

本票 fixture 刻意用基类型（printRaw=纯名）避开该偏差面；修复属 datatype.rs
租约，建议 root 开票。

## 2026-09-26（MIGW1-DATABASE-0005 phase 3，wt/database7）：残余七项收尾

MIGW-DATABASE 终报第五节登记的七项 UNTESTED 残余逐项处置。三处顺序语义修正 +
一个双侧 fixture（19 case 字节恒等）+ 两项免修裁决 + 一项跨域移交。

### 残余七项逐项判定

| # | 残余项 | oracle 锚 | 判定 | 处置 |
|---|---|---|---|---|
| 1 | addDynamicMapInternal whole-count | database.cc:1874-1887 | 实现已忠实，缺双侧证据 | fixture 覆盖（whole×3/partial/reset/重加） |
| 2 | categorySanity | database.cc:1992-2018 | 实现已忠实（NULL 槽由 removeSymbol cc:2143-2145 留下） | fixture 覆盖（洞+整类清空+邻类不动） |
| 3 | multi_entry_symbols（multiEntrySet 面） | hh:813/865-866 + hh:366 | **真偏差已修**：`multiEntrySet` 是 `SymbolNameTree`（`(name, nameDedup)` 序），非指针序——原实现按 symbol-id 排序且注释错误归因"指针序噪声" | 改为 `(name, name_dedup)` 序；fixture 钉死（乱序插入+重名 dedup tie-break） |
| 4 | resolveExternalRefFunction | database.cc:2362-2366 | 实现已忠实（`queryFunction`→`mapScope` 空 resolvemap 时返回查询域自身 cc:3187-3188→`stackFunction` cc:1009→`findFunction` cc:2321 = 值模型的 `find_function` 委托） | fixture 覆盖（hit/miss；生产 BfdArchitecture + 空 resolvemap 双侧同构） |
| 5 | decodeWrappingAttributes | database.hh:714-719 | **免修裁决 R5**：数据库层基类体逐字 `{}`（无读、无状态突变），Rust 侧同为空体——无可分歧的观察面，fixture 无判别力 | 不修不测；唯一覆写 `ScopeLocal::decodeWrappingAttributes`（varmap.cc:479-486，读 ATTRIB_LOCK/ATTRIB_MAIN 置 rangeLocked/space）在 varmap.rs 无对应物——**移交 varmap 域**（TODO_BOARD 登记） |
| 6 | children 迭代器端点 | database.hh:765-766 + hh:439 | **真偏差已修**：`ScopeMap = map<uint8, Scope*>`，childrenBegin/End 迭代=uniqueId 升序；原实现保插入序（attach_scope_by_id 注释甚至自称"unique-id order"但实现不符） | `attach_child` 改排序插入（binary_search upsert：已知 id 位次不变=map 节点位次，新 id 落排序位）；fixture 钉死（105/101/103 乱序挂载→101,103,105；经 Database::attachScope 生产路径） |
| 7 | printEntries 聚合面（多空间序） | database.cc:2791-2804 + rangemap.hh:223-249 | **真偏差已修**（且比票面更深）：C++ 走 maptable（空间索引升序）×每空间 rangemap record 列表——**组内序是 splice 序非插入序**（`AddrRange` 按 `(last, subsort)` 比较 hh:88-91，新 record 接到首个 ≥ 键子范围所属 record 之前；oracle 实测 rom 组内 0x1000 条目先于 0x2000 条目）。原实现单 vector 插入序全错 | `print_entries` 重写：空间索引升序分组 + 组内 rangemap splice 重放（键=(full-range last, subsort)，等键取最早插入者=multiset lower_bound 语义）；**裁决 R4**：嵌套重叠（同空间内某 record 区间完全含于另一 record 内部）时 oracle 树键用分区子范围边界，可能与全 record 键重放差一位——此形状外（相离/等键/部分重叠）逐位重放一致；fixture 钉死相离+等键形状 |

### DATABASE-RESID7-FIXTURE-0001（tests/oracle/database_resid7_1204.{cc,rs}）

19 case 全量 stdout 逐字节 **MATCH**（runner `tools/run_database_resid7_oracle.sh`，
registry `database_resid7_1204`）。oracle 侧=生产 BfdArchitecture（x86:LE:64:default:gcc）
+ FixtureScope（ScopeInternal 子类暴露 addSymbolInternal/addDynamicMapInternal/
removeSymbolMappings）；Rust 侧=生产 Scope/Database 值模型，TypeFactory
Standalone 风味。空间=显式 index 3（ram）/4（rom）自定义 AddrSpace，双侧同构。

关键 case：
- `multientry_order|alpha#0,alpha#1,mid#0,zeta#0` — 乱序插入（zeta,alpha,mid,alpha2）
  + insertNameTree 自动 dedup（cc:2712-2727）→ 名字序见证；
- `printentries_multi` — ram/rom 交错插入，oracle 输出 m1,m3（ram 组）后 m4,m2
  （rom 组内 0x1000 先于 0x2000）——**组内 splice 序的直接见证**（插入序会得
  m2,m4）；
- `children_ids|101,103,105` — 乱序挂载经 Database::attachScope（cc:2946）；
- `resolve_hit|name=fn|addr=1000` — FunctionSymbol+ExternRefSymbol 链
  （FunctionSymbol::getFunction cc:557 惰性 Funcdata）；
- `dyn_readd|multi=0` — removeSymbolMappings 置 wholeCount=0（cc:2134）后重加
  仅回 1。

### 裁决（R4/R5，随 fixture 注释记录）

- **R4 printEntries 嵌套重叠窄化**：见上表 #7。原实现多空间全错；修后仅嵌套
  重叠形状存一位差（oracle 分区子范围键 vs 全 record 键），条件与方向已在
  `print_entries` doc 注释逐字记录。canon 双语料无此形状（curl/httpd 符号表
  无同空间嵌套区间静态 entry）。
- **R5 decodeWrappingAttributes 基类免修**：见上表 #5。ScopeLocal 覆写归
  varmap.rs 租约（VARMAP-DECODEWRAP-0001 登记）。

## 2026-09-27：Database::query_properties_entry（VARNODE-CALLOTHER-VOLATILEOUT-0001）

新增 `Database::query_properties_entry(qpoint_scope_id, addr, size, usepoint)
-> Option<SymbolEntry>`——database.cc:1263-1281 `Scope::queryProperties` 的
`SymbolEntry*` 返回形态（cc:1280），供 `VolatileReadOp::getOutputLocal`
（userop.cc:136-138）的 `entry->getSizedType(addr,size)` 消费；与既有投影
形态 `Database::query_properties` 同走 mapScope（cc:1267）+
stackContainer（cc:1268）栈，仅返回句柄而非 `QueryContainerHit` 投影。
`uint4 &flags` 出参丢弃：唯一生产消费者初始化为 0 且永不读回
（userop.cc:135-136）；flags 三臂（cc:1270/1273-1279）经投影形态仍可达。
