# grammar.rs — C grammar parser API

Faithful port of Ghidra's `grammar.hh` / `grammar.cc` (3338 lines).

**Status:** 🔧 **L2 / overall MISMATCH**. GrammarToken + GrammarLexer +
TypeModifier/TypeDeclarator + TypeSpecifiers/Enumerator + the CParse parser
framework and entry functions are present. Series C routes PointerModifier
through TypeFactory's canonical unnamed pointer tree, but Rudra still lacks
the `Architecture *glb` channel needed to observe a non-unit default-space
wordsize, and this changed projection remains `NO_ORACLE` until the series-D
bilateral fixture. Existing recursive-descent/bison gaps below also preclude
L3.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/grammar.{hh,cc}`.

## Module `token_type`
Token types (grammar.hh:26): OPEN_PAREN, CLOSE_PAREN, STAR, COMMA, SEMICOLON,
OPEN_BRACKET, CLOSE_BRACKET, OPEN_BRACE, CLOSE_BRACE, BAD_TOKEN, END_OF_FILE,
DOTDOTDOT, INTEGER, CHAR_CONSTANT, IDENTIFIER, STRING_VAL.

## Module `cparse_flags`
Storage-class / type-qualifier / specifier flag constants
(grammar.hh:204-216): `F_TYPEDEF, F_EXTERN, F_STATIC, F_AUTO, F_REGISTER,
F_CONST, F_RESTRICT, F_VOLATILE, F_INLINE, F_STRUCT, F_UNION, F_ENUM`. Also
re-exported as `CParse::F_*` associated constants to mirror the C++
`CParse::f_typedef` access form.

## Structs

### `GrammarToken`
A lexical token (grammar.hh:23).
- `new()`, `get_type()`, `get_integer()`, `get_string()`, `get_line_no()`,
  `get_col_no()`, `get_file_num()`, `set_position()`.

### `GrammarLexer`
Lexer for C declarations (grammar.hh:69).
- `new(max_buffer)`, `clear()`, `set_input(text)`, `get_error()`, `is_eof()`.
- `get_next_token() -> GrammarToken` — state-machine tokenization
  (grammar.hh:110). Handles: punctuation, identifiers, integers (dec/hex/oct),
  strings, char constants, `//` and `/* */` comments, `...`.

### `TypeModifier`
Type modifier enum: Pointer/Array/Function (grammar.hh:118). The `Function`
variant carries owned parameter declarators (`Vec<Option<TypeDeclarator>>`) and
a `dotdotdot` flag, mirroring `FunctionModifier` (grammar.hh:152).
- `kind() -> ModifierKind`, `is_valid() -> bool`.

### `TypeDeclarator`
C type declarator (grammar.hh:165). Carries `mods: Vec<TypeModifier>`,
`basetype: Option<Arc<Datatype>>`, `ident`, `model`, `flags`.
- `new()`, `with_name(name)`, `get_base_type()`, `num_modifiers()`,
  `get_identifier()`, `has_property(mask)`.
- `is_valid() -> bool` (grammar.cc:2548) — checks basetype present, no
  multiple storage classes, no multiple type qualifiers, all mods valid.
- `build_type(types: &mut TypeFactory) -> Option<Arc<Datatype>>`
  (grammar.cc:2493) — applies modifiers to the basetype in reverse order.
- `model_name() -> &str` (grammar.cc:2506) — name to look up for the prototype
  model.

### `TypeSpecifiers`
Accumulated specifiers (grammar.hh:186): `type_specifier`,
`function_specifier`, `flags`.

### `Enumerator`
A single enum constant (grammar.hh:193): `enum_constant`, `constant_assigned`,
`value`. `new(name)` and `with_value(name, val)` mirror the C++ constructors.

### `CParse`
The C parser (grammar.hh:201). Owns the lexer, the allocation arena, the
keyword table, the lookahead cache, and the most recent result/error. The
bison-driven `yyparse` (grammar.cc:3067) is replaced with a hand-written
recursive-descent driver because Rust has no in-tree bison equivalent.
- `new(max_buf)`, `clear()`, `get_error()`, `parse_stream(text, doctype)`.
- Specifier helpers: `convert_flag(str)`, `add_specifier(spec, str)`
  (grammar.cc:2673), `add_type_specifier(spec, tp)` (grammar.cc:2681),
  `add_func_specifier(spec, str)` (grammar.cc:2690).
- Declarator helpers: `merge_spec_dec_into(spec, dec)` / `merge_spec_dec(spec)`
  (grammar.cc:2624), `merge_spec_dec_vec(spec, declist)` (grammar.cc:2641),
  `merge_spec_dec_vec_single(spec)` (grammar.cc:2649), `merge_pointer(ptr, dec)`
  (grammar.cc:2706), `new_declarator()`, `new_declarator_name(str)`,
  `new_specifier()`, `new_vec_declarator()`, `new_pointer()`,
  `new_array(dec, flags, num)` (grammar.cc:2756), `new_func(dec, declist)`
  (grammar.cc:2764).
- Enumerator helpers: `new_enumerator_name(str)` (grammar.cc:2857),
  `new_enumerator_value(str, val)` (grammar.cc:2865), `new_vec_enumerator()`
  (grammar.cc:2873).
- Result plumbing: `set_result_declarations(vec)` (grammar.cc:278),
  `take_result_declarations() -> Option<Vec<TypeDeclarator>>` (grammar.cc:279),
  `set_error(msg)` (grammar.cc:3041), `clear_allocation()` (grammar.cc:2916).

### `DocType`
Document type requested from the parser (grammar.hh:217): `Declaration`,
`ParameterDeclaration`.

## Free functions
- `parse_type(text) -> Option<(String, String)>` — parse type+name
  (grammar.hh:282).
- `parse_to_separator(text) -> String` — parse up to separator
  (grammar.hh:288).
- `parse_toseparator_from(text) -> (String, usize)` (grammar.cc:3197) — slice
  version returning the word and bytes consumed.
- `parse_machaddr(text) -> Option<(Address, i32, usize)>` (grammar.cc:3257) —
  parse a machine address. Supports `[space,offset]`, `[space,offset,size]`,
  `{ joined }`, and shortcut-prefixed offsets.
- `parse_varnode(text) -> Option<(Address, i32, Address, u64, usize)>`
  (grammar.cc:3213) — parse `addr ( [pc] [:uniq] )`.
- `parse_op(text) -> Option<(Address, u64, usize)>` (grammar.cc:3244) — parse
  `addr : uniq`.

## Porting notes
- The bison grammar table (`grammar.y` → `grammar.cc`'s `yyparse`) is not
  ported verbatim; Rust has no in-tree bison toolchain. `CParse::run_parse`
  drives a hand-written recursive-descent replacement (`yyparse` /
  `parse_declarator` / `parse_direct_declarator` /
  `parse_parameter_declaration` / `parse_tag_specifier` /
  `parse_struct_declaration_list` / `parse_enumerator_list`) that reduces
  the grammar.y productions in bison order: `direct_declarator` suffixes
  (`[N]` / `(...)`) land in `dec.mods` first and the `pointer
  direct_declarator` stars append after them (`mergePointer`,
  grammar.y:151-153), the `'(' declarator ')'` grouping shares the inner
  `TypeDeclarator` (`$$ = $2`, grammar.y:158), and struct/union/enum
  specifiers commit through the `newStruct`/`newUnion`/`newEnum`/`old*`
  twins exactly as the bison actions do. `parse_stream_with_types`
  threads a `TypeFactory` through the driver (the Rust form of the C++
  `glb` handle) so `TYPE_NAME` specifiers resolve via `find_by_name` —
  the `lookupIdentifier` probe (grammar.cc:2972). The equivalence unit is
  the parser whole-face fixture `tests/oracle/grammar_parse_face_1204`
  (runner `tools/run_grammar_parse_face_oracle.sh`): 17 C-type-string /
  DWARF-declaration-string cases over `parse_type` / `parse_protopieces`,
  bilateral byte-identical against the locked bison oracle.
  The untyped legacy `parse_stream` keeps the unresolved-basetype path
  (documented subset limitation).
- Pointer/Array/Function modifier `modType` virtuals (grammar.cc:2403/2412/2465)
  are ported per-variant as the free functions `pointer_mod_type`,
  `array_mod_type`, and `function_mod_type` (each annotated to its own
  oracle definition), with the free `mod_type` acting as the enum-dispatch
  twin of the C++ virtual call sites (`TypeDeclarator::buildType`
  grammar.cc:2501 / `getPrototype` grammar.cc:2542). The dispatch consults
  Rudra's `TypeFactory` (`get_type_pointer_default` / `get_array` /
  `get_type_code`). PointerModifier no longer uses the legacy pointee-name
  cache: distinct anonymous array bases retain distinct pointer identities,
  and repeat construction aliases the direct canonical pointer. The wrapper
  uses the factory's default address size and Rudra's currently modelled
  default wordsize 1; until Architecture wires `setupSizes`, only its layout
  calculation uses TypeFactory's registered compatibility fallback.
  Arbitrary architecture wordsize remains `TYPE-0001`.
- The `FunctionModifier` constructor (grammar.cc:2419) is ported as
  `function_modifier_ctor`: the lone-`(void)` parameter clearing and the
  varargs flag live there; `CParse::new_func` (grammar.cc:2764) only detects
  and pops the varargs trailer before calling it.
- 2026-08-23 (TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001): the in-file tests
  that build base types for `mod_type` now use the faithful
  `get_base_result` twin; on the `TypeFactory::new` bootstrap the cached
  4-byte INT core type satisfies the same typecache fast path
  (type.cc:3635-3640) the lenient twin read, so the resolved `Arc` is
  identical.
- `CParse::newFunc`'s varargs trailer is encoded as a sentinel declarator with
  `flags == u32::MAX` (Rudra-private; flagged `RUDRA-GLUE`), since Rust cannot
  store a `null` slot in `Vec<TypeDeclarator>`.

## L3 gaps
- Full bison grammar table from `grammar.y`: the recursive-descent driver
  covers the production set the parser-face fixture pins (declarator
  ordering/grouping, parameter declarations, struct/union/enum
  definitions, varargs); remaining registered subset limitations are in
  the fixture metadata (`tests/oracle/grammar_parse_face_1204.metadata.json`).
- PointerModifier's exact default-data-space wordsize is unavailable without
  threading the Architecture handle into the Rust grammar/type-factory edge.
- `TypeFactory` integration for struct/union/enum construction is wired
  through `parse_tag_specifier` (typed driver path); the untyped legacy
  `parse_stream` path leaves composite specifiers unresolved.

## Annotation provenance

ANN-G maps the shared Rust constructor body `CParse::new_impl` to the locked
`CParse::CParse` definition at `grammar.cc:2585`. This is annotation-only and
does not change parser behavior or alignment status.
<!-- annotation-pass: 2026-07-22 -->

## 2026-08-28：FunctionModifier 返回类型身份

`PrototypePieces::out_type` 现在借用 `Arc<Datatype>`，因此
`FunctionModifier::modType` 把同一返回类型句柄交给模型分配，而不再深拷贝
Datatype。这里仅是跨模块 carrier identity 修正；没有新增 grammar 双侧
fixture，递归下降/bison 与 Architecture 残差不变，整体仍为 L2/MISMATCH。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
