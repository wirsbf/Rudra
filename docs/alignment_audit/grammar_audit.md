# grammar 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 3338行 (`grammar.cc`) + 294行 (`grammar.hh`) + 1592行 (`grammar.y`) / Rudra: 1982行 (`src/grammar.rs`) / 比率: 59%（按 grammar.cc+hh 计；若计入 grammar.y 的 bison 表则实际语义覆盖率显著更低）

Ghidra 头文件 `grammar.hh` 的内联访问器（`GrammarToken::getType/getInteger/...`、`GrammarLexer::getCurStream/getError/...`、`TypeDeclarator::getBaseType/numModifiers/...` 等）一并纳入统计。

## 设计说明（重要架构偏差 — 这是 59% 覆盖率的根因）
1. **bison 语法表整体未移植**：Ghidra 的 `grammar.y`（1592 行）通过 bison 生成 LALR(1) 语法表与 `yyparse` 驱动器；Rudra 因 Rust 无 in-tree bison 等价物，**用一段手写递归下降 `yyparse`（src/grammar.rs:1142-1225）替代，仅识别 bison 语法的极小子集**（声明/参数声明 + pointer/array/function 后缀）。bison 语法的 25 条产生式（`document`/`declaration`/`declaration_specifiers`/`init_declarator_list`/`type_specifier`/`struct_or_union_specifier`/`struct_declaration_list`/`struct_declaration`/`specifier_qualifier_list`/`struct_declarator_list`/`struct_declarator`/`enum_specifier`/`enumerator_list`/`enumerator`/`declarator`/`direct_declarator`/`pointer`/`type_qualifier_list`/`parameter_type_list`/`parameter_list`/`parameter_declaration`/`abstract_declarator`/`direct_abstract_declarator`/`assignment_expression`）仅少数被覆盖，且大多被简化。
2. **struct/union/enum 类型构建链路完全缺失**：Ghidra 的 `CParse::newStruct`/`newUnion`/`newEnum`/`oldStruct`/`oldUnion`/`oldEnum`（grammar.cc:2779-2914，约 135 行）调用 `TypeFactory::getTypeStruct/getTypeUnion/getTypeEnum` + `TypeStruct::assignFieldOffsets`/`TypeUnion::assignFieldOffsets`/`TypeEnum::assignValues` 来**在解析过程中创建复合类型**；Rudra 完全没有这 6 个方法，导致任何包含 `struct {...}`/`union {...}`/`enum {...}` 定义（而非仅引用）的 C 字符串都无法解析。
3. **`CParse` 不持有 `Architecture *glb`**：Ghidra 的 `CParse` 构造接收 `Architecture *g`，因此 `lookupIdentifier`/`newStruct` 等可查询 `glb->types`（TypeFactory）和 `glb->hasModel`。Rudra 的 `CParse::new` 只接收 `max_buf`，无 `Architecture` 句柄，所以 basetype 解析、模型查找、复合类型创建全部被截断或注释为"上游解析"。
4. **`GrammarLexer` 简化为单字符串输入**：Ghidra 的 `GrammarLexer` 持有 `filenamemap`/`streammap`/`filestack`/`in`（多文件流栈）+ `pushFile`/`popFile`/`writeLocation`/`writeTokenLocation`/`bumpLine`/`moveState`。Rudra 的 `GrammarLexer` 只持有一个 `Vec<char>` 输入，**多文件流栈完全缺失**，`moveState` 被内联到 `get_next_token` 的 `match state`。这导致 `parseFile`/位置诊断/`#line` 指令无法支持。
5. **`CParse::lex` 缺失，`yyparse` 改为基于 `peek_token`/`advance`**：Ghidra 的 `yyparse` 通过 `lex()` 拉取 bison token；Rudra 自实现单 token 前瞻缓存。这导致 `STORAGE_CLASS_SPECIFIER`/`TYPE_QUALIFIER`/`FUNCTION_SPECIFIER`/`TYPE_NAME`/`STRUCT`/`UNION`/`ENUM` 这 7 个 bison 复合 token 类别**不作为独立 token 暴露**——所有 IDENTIFIER 在 `yyparse` 内现场判定 keyword，而非经 `lookupIdentifier` 查 TypeFactory/Model 表。
6. **`parse_type` 改为简化版**：Ghidra 的 `parse_type`（grammar.cc:3112）驱动完整 `CParse` 解析后从结果 declarator 取 basetype+ident；Rudra 的 `parse_type`（src/grammar.rs:1436）只 lex 两个 token，**不走 CParse**，因此无法处理 `int * x`、`long x` 等带修饰符或复合类型名的输入。

## 已对齐函数 (按类统计)

### GrammarToken (7) — 内联访问器齐全
- `new` (cc:2025), `get_type`(hh:61), `get_integer`(hh:62), `get_string`(hh:63), `get_line_no`(hh:64), `get_col_no`(hh:65), `get_file_num`(hh:66), `set_position`(hh:58) ✅
- (`set(uint4 tp)` cc:1960 / `set(uint4 tp,char*,int4)` cc:1966 — 内部用于 lexer 建立 token，Rudra 内联到 `get_next_token`，合理省略)

### GrammarLexer (5)
- `new` (cc:2035), `clear`(cc:2305), `set_input`(cc:2035 类比 pushFile 的输入侧), `get_error`(hh:113), `is_eof`(cc:2035 类比 getCurStream), `get_next_token`(hh:110) ✅
- `peek`/`next_char`/`finalize_token` 为 Rudra 私有辅助（无 Ghidra 对应，因 Ghidra 用 `moveState`+`establishToken`，合理拆分）

### TypeModifier / TypeDeclarator (10)
- `TypeModifier::kind` (hh:128 getType) ✅, `TypeModifier::is_valid` (hh:129 isValid) ✅
- `PointerModifier`/`ArrayModifier`/`FunctionModifier` 的构造、`is_valid`、`mod_type` 通过 `mod_type` 辅助函数（src/grammar.rs:684）统一实现 ✅（架构上合理：Rust 用 enum 替代继承层级）
- `TypeDeclarator::new` (hh:173), `with_name`(hh:174), `get_base_type`(hh:176), `num_modifiers`(hh:177), `get_identifier`(hh:178), `has_property`(hh:181), `is_valid`(cc:2548), `build_type`(cc:2493), `model_name`(cc:2506 getModel 的名字版) ✅

### TypeSpecifiers / Enumerator (5)
- `TypeSpecifiers::new` (hh:190) ✅
- `Enumerator::new` (hh:197), `Enumerator::with_value` (hh:198) ✅
- `TypeSpecifiers` 的字段 `type_specifier`/`function_specifier`/`flags` 公开 ✅；`Enumerator` 的 `enum_constant`/`constant_assigned`/`value` 公开 ✅

### CParse 框架 (~22，含简化/stub)
- `new` (cc:2585), `clear`(cc:2614), `clear_allocation`(cc:2916), `set_error`(cc:3041), `get_error`(hh:277) ✅
- `set_result_declarations`(hh:278), `take_result_declarations`(hh:279 getResultDeclarations) ✅
- `merge_spec_dec_into`(cc:2624 mergeSpecDec(spec,dec)), `merge_spec_dec`(cc:2633 mergeSpecDec(spec)), `merge_spec_dec_vec`(cc:2641 mergeSpecDecVec(spec,declist)), `merge_spec_dec_vec_single`(cc:2649 mergeSpecDecVec(spec)) ✅
- `convert_flag`(cc:2661), `add_specifier`(cc:2673), `add_type_specifier`(cc:2681), `add_func_specifier`(cc:2690) ✅
- `merge_pointer`(cc:2706), `new_declarator_name`(cc:2716 newDeclarator(str)), `new_declarator`(cc:2724 newDeclarator(void)), `new_specifier`(cc:2732), `new_vec_declarator`(cc:2740), `new_pointer`(cc:2748), `new_array`(cc:2756), `new_func`(cc:2764) ✅
- `new_enumerator_name`(cc:2857 newEnumerator(ident)), `new_enumerator_value`(cc:2865 newEnumerator(ident,val)), `new_vec_enumerator`(cc:2873 newVecEnumerator) ✅
- `parse_stream`(cc:3091), `run_parse`(cc:3053 runParse) ⚠️（驱动器对齐但 `yyparse` 内部是简化递归下降）, `yyparse`(grammar.y 的 bison 表) ⚠️（手写子集替代）
- `peek_token`/`advance`/`parse_declarator`/`parse_parameter_declaration` — RUDRA-GLUE 私有辅助，无 Ghidra 1:1 对应

### 公共入口函数 (5)
- `parse_type`(cc:3112) ⚠️（简化为双 token lex，不走 CParse）
- `parse_to_separator`(cc:3197), `parse_toseparator_from`(cc:3197 stream 版本的 &str 变体) ✅
- `parse_machaddr`(cc:3257), `parse_varnode`(cc:3213), `parse_op`(cc:3244) ✅

## 缺失函数

### CParse — struct/union/enum 构建链路（关键，6 个方法，整段约 135 行）
- `CParse::newStruct` — Ghidra: grammar.cc:2779 — 优先级: **高** — 从 `struct ident { ... }` 定义创建 `TypeStruct`（调用 `TypeFactory::getTypeStruct` + `TypeStruct::assignFieldOffsets` + `TypeFactory::setFields`）。Rudra 完全缺失，无法解析结构体字面定义。
- `CParse::oldStruct` — Ghidra: grammar.cc:2809 — 优先级: **高** — 引用已存在的 struct（`TypeFactory::findByName` + 类型检查）。
- `CParse::newUnion` — Ghidra: grammar.cc:2818 — 优先级: **高** — 从 `union ident { ... }` 创建 `TypeUnion`（`TypeUnion::assignFieldOffsets`）。Rudra 缺失。
- `CParse::oldUnion` — Ghidra: grammar.cc:2848 — 优先级: **高**
- `CParse::newEnum` — Ghidra: grammar.cc:2881 — 优先级: **高** — 从 `enum ident { ... }` 创建 `TypeEnum`（`TypeEnum::assignValues` + `TypeFactory::setEnumValues`）。Rudra 缺失。
- `CParse::oldEnum` — Ghidra: grammar.cc:2907 — 优先级: **高**

### CParse — 词法/标识符解析（3 个方法）
- `CParse::lookupIdentifier` — Ghidra: grammar.cc:2961 — 优先级: **高** — 将 IDENTIFIER 映射到 bison 复合 token（STORAGE_CLASS_SPECIFIER/TYPE_QUALIFIER/FUNCTION_SPECIFIER/STRUCT/UNION/ENUM/TYPE_NAME），需查询 `glb->types->findByName` 和 `glb->hasModel`。Rudra 缺失（关键词在 yyparse 内现场判定，TYPE_NAME 路径丢失）。
- `CParse::lex` — Ghidra: grammar.cc:2999 — 优先级: **高** — bison 词法桥：将 `GrammarToken` 转为 bison token code 并填充 `yylval`。Rudra 用 `peek_token`/`advance` 替代，但语义不等价（无 STORAGE_CLASS_SPECIFIER 等复合 token）。
- `CParse::parseFile` — Ghidra: grammar.cc:3076 — 优先级: 中 — 从文件流解析（依赖 `pushFile`/`popFile`）。Rudra 缺失（无文件流栈）。

### FunctionModifier — 参数访问（2 个方法）
- `FunctionModifier::getInTypes` — Ghidra: grammar.cc:2434 — 优先级: **高** — 收集各参数的构建类型（`buildType`），供 `modType` 构建 `PrototypePieces.intypes`。Rudra `Function` 变体持 `params: Vec<Option<TypeDeclarator>>` 但无此访问器，导致函数指针类型无法完整构建（`mod_type` 的 Function 分支忽略 params，直接返回 `types.get_type_code()`）。
- `FunctionModifier::getInNames` — Ghidra: grammar.cc:2443 — 优先级: 中 — 收集各参数名。Rudra 缺失。

### TypeDeclarator — 原型提取（2 个方法）
- `TypeDeclarator::getModel` — Ghidra: grammar.cc:2506 — 优先级: 中 — 查找 ProtoModel（`glb->getModel(model)` 回退到 `glb->defaultfp`）。Rudra 只有返回字符串的 `model_name`，不解析为 ProtoModel 对象。
- `TypeDeclarator::getPrototype` — Ghidra: grammar.cc:2518 — 优先级: **高** — 从 declarator 提取 `PrototypePieces`（model + intypes + firstVarArgSlot + name），是 `parse_protopieces` 和函数指针类型构建的关键。Rudra 缺失。

### GrammarLexer — 多文件流栈与位置诊断（6 个方法）
- `GrammarLexer::pushFile` — Ghidra: grammar.cc:2339 — 优先级: 中 — 压入新文件流。
- `GrammarLexer::popFile` — Ghidra: grammar.cc:2350 — 优先级: 中 — 弹出文件流。
- `GrammarLexer::writeLocation` — Ghidra: grammar.cc:2320 — 优先级: 低 — 写入文件:行位置（诊断用）。
- `GrammarLexer::writeTokenLocation` — Ghidra: grammar.cc:2327 — 优先级: 低 — 写入行列位置（诊断用）。
- `GrammarLexer::bumpLine` — Ghidra: grammar.cc:2054 — 优先级: 低 — 内部行计数（Rudra 内联到 `next_char`）。
- `GrammarLexer::moveState` — Ghidra: grammar.cc:2062 — 优先级: 低 — 状态机核心（Rudra 内联到 `get_next_token` 的 match state，约 230 行 vs Ghidra 约 230 行，语义基本对齐）。
- `GrammarLexer::getCurStream` — Ghidra: hh:107 — 优先级: 低（内联访问器，Rudra 无 stream 概念）。
- `GrammarLexer::establishToken` — Ghidra: grammar.cc:2294 — 优先级: 低（内部辅助，Rudra 内联）。
- `GrammarLexer::~GrammarLexer` — Ghidra: grammar.cc:2048 — 优先级: 低（Rust Drop 自动处理）。

### 公共入口函数 — 缺失 2 个
- `parse_protopieces` — Ghidra: grammar.cc:3131 — 优先级: **高** — 从流解析函数原型到 `PrototypePieces`（依赖 `TypeDeclarator::getPrototype`）。Rudra 缺失，无法从 C 字符串恢复原型以驱动 ProtoModel 解析。
- `parse_C` — Ghidra: grammar.cc:3151 — 优先级: **高** — 解析整个 C 文档（多次 `parseStream(doc_declaration)` 循环），是 `decode` 序列化类型恢复路径的入口。Rudra 缺失。

### GrammarToken — 缺失 2 个内部辅助
- `GrammarToken::set(uint4 tp)` — Ghidra: grammar.cc:1960 — 优先级: 低（lexer 内部，Rudra 内联）。
- `GrammarToken::set(uint4 tp,char *ptr,int4 len)` — Ghidra: grammar.cc:1966 — 优先级: 低（lexer 内部，Rudra 内联）。

## 高优先级缺失清单 (按影响排序)

### 复合类型定义链路（最关键，整条链断裂）
1. **`CParse::newStruct`/`newUnion`/`newEnum`** (grammar.cc:2779/2818/2881) — 无法从 `struct/union/enum {...}` 字面定义创建类型
2. **`CParse::oldStruct`/`oldUnion`/`oldEnum`** (grammar.cc:2809/2848/2907) — 无法引用已存在复合类型
3. **`FunctionModifier::getInTypes`** (grammar.cc:2434) — 函数指针参数类型无法收集
4. **`TypeDeclarator::getPrototype`** (grammar.cc:2518) — 无法从 declarator 提取 PrototypePieces

### bison 语法表（结构性缺失）
5. **`yyparse` 的 25 条产生式** (grammar.y:61-208) — 25 条产生式中仅约 5 条被 Rudra 简化覆盖；struct_declaration_list / struct_or_union_specifier / enum_specifier / parameter_type_list / abstract_declarator / direct_abstract_declarator / assignment_expression 等完全缺失
6. **`CParse::lookupIdentifier`** (grammar.cc:2961) — IDENTIFIER → bison 复合 token 映射丢失（TYPE_NAME 路径无 TypeFactory 查询）
7. **`CParse::lex`** (grammar.cc:2999) — bison 词法桥缺失

### 公共入口（关键）
8. **`parse_protopieces`** (grammar.cc:3131) — 无法解析函数原型
9. **`parse_C`** (grammar.cc:3151) — 无法解析 C 文档
10. **`parse_type` 简化** (src/grammar.rs:1436) — 当前实现仅 lex 双 token，不走 CParse，无法处理修饰符/复合类型（应重构为走 CParse 的版本）

### 次要（架构依赖）
11. **`CParse` 持有 `Architecture *glb`** — 上述 newStruct/getModel/lookupIdentifier 均依赖 glb；Rudra 当前 `CParse::new` 无 glb 参数，需先扩展构造签名
12. **GrammarLexer 多文件流栈** (`pushFile`/`popFile`/`writeLocation`/`writeTokenLocation`) — 诊断与多文件解析受限，但单一字符串解析路径不受影响

## 说明
- `TypeModifier` 在 Rudra 用 `enum TypeModifier { Pointer, Array, Function }` 替代 Ghidra 的 `TypeModifier` 抽象基类 + `PointerModifier`/`ArrayModifier`/`FunctionModifier` 三个子类，结构合理但**丢失了 `struct_mod`/`enum_mod` 两个 mod 类型枚举值**（grammar.hh:124-125），因为 struct/enum 不作为 declarator modifier 而是直接在 newStruct/newEnum 创建 Datatype。
- `GrammarLexer` 的 `moveState` 状态机（grammar.cc:2062-2293，约 230 行）在 Rudra 被内联到 `get_next_token` 的 `match state`（src/grammar.rs:251-443），状态枚举与转移基本对齐，但**复用了 `Dot3` 状态来检测 C 注释结束**（src/grammar.rs:362-375）——这是一个值得复核的语义偏差，可能与 Ghidra 的 dot3（小数点第三位）状态冲突。
- `parse_machaddr`/`parse_varnode`/`parse_op` 的 Rudra 实现从 `istream &` 改为 `&str` 并返回 `bytes_consumed`，合理适配 Rust 无流式 I/O 的约束，格式覆盖基本对齐。
- 当前 `yyparse` 的简化实现（src/grammar.rs:1142-1225）在遇到 `struct`/`union`/`enum` 关键字时**仅消费 basetype 名称而不进入结构体/联合体/枚举定义体**（src/grammar.rs:1176-1189 的注释明确承认这一点），这是 59% 覆盖率的最大单点损失。
