# pcodeparse.rs — P-code snippet parser & `<op>`/`<varnode>` XML decode API

Partial port of Ghidra's `pcodeparse.hh` / `pcodeparse.cc` (3303 lines,
Bison-generated) + `pcodeparse.y` (805 lines, grammar source). This module
also ports the `<op>` / `<varnode>` XML decode path that Ghidra spreads across
`pcoderaw.cc` (`PcodeOpRaw::decode`, `VarnodeData::decode`) and `translate.cc`
(`PcodeEmit::decodeOp`), since those are the XML entry points that consume the
P-code emitted by this parser.

**Status:** L3 (2026-07-22 complete lexer + XML decode alignment). The full
Bison state-machine lexer (`moveState` + `getNextToken`) with all 57 token
kinds, the `IDENTREC_SIZE=46` keyword/operator table, and the `<op>` /
`<varnode>` XML decode path are all faithful to Ghidra. The ConstructTpl
assembly half of the parser (the Bison grammar's semantic actions) remains an
L3 gap that requires SLEIGH integration; the lexer, symbol table, error
reporting, temp allocation, and XML decode are complete. 43 unit tests.

Ghidra reference: `ghidra/.../cpp/pcodeparse.{hh,cc,y}`, `sleigh.hh`
(PcodeData), `pcoderaw.{hh,cc}`, `translate.cc`.

## Enums

### `PcodeTokenKind`
The full Bison `pcodetokentype` enum (pcodeparse.cc:152-211): 57 token kinds
mirroring the numeric ids 258-314. Variants cover:
- Multi-char operators: `BoolOr` (`||`), `BoolAnd` (`&&`), `Equal` (`==`),
  `NotEqual` (`!=`), `LessEqual` (`<=`), `GreatEqual` (`>=`), `Left` (`<<`),
  `Right` (`>>`), `BoolXor` (`^^`).
- Signed-family (`s<`, `s<=`, `s>`, `s>=`, `s>>`, `s/`, `s%`): `SLess`,
  `SLessEqual`, `SGreat`, `SGreatEqual`, `SRight`, `SDiv`, `SRem`.
- Float-family (`f+`, `f-`, `f*`, `f/`, `f==`, `f!=`, `f<`, `f>`, `f<=`,
  `f>=`): `FAdd`, `FSub`, `FMult`, `FDiv`, `FEqual`, `FNotEqual`, `FLess`,
  `FGreat`, `FLessEqual`, `FGreatEqual`.
- Builtins: `Zext`, `Carry`, `Borrow`, `Sext`, `SCarry`, `SBorrow`, `Nan`,
  `Abs`, `Sqrt`, `Ceil`, `Floor`, `Round`, `Int2Float`, `Float2Float`,
  `Trunc`, `New`.
- Keywords: `GotoKey`, `CallKey`, `ReturnKey`, `IfKey`, `LocalKey`.
- Literals/symbols: `Integer`, `BadInteger`, `String`, `SpaceSym`,
  `UserOpSym`, `VarSym`, `OperandSym`, `JumpSym`, `LabelSym`.
- `Punct(char)` — single-character punctuation carries the source char.
- `Illegal` — unclassifiable character (Bison's `0`/EOF).

Methods:
- `as_token_id() -> i32` (`const`) — Bison numeric id (258-314, or ASCII for
  `Punct`, or `0` for `Illegal`).
- `from_token_id(id) -> Option<PcodeTokenKind>` (`const`) — inverse lookup.

### `PcodeToken`
Coarse 14-variant projection retained for callers that only need the broad
category (Eof, Illegal, Identifier, HexNumber, DecNumber, LParen, RParen,
Comma, Semicolon, LBracket, RBracket, Assign, Dollar, DoubleDollars).
- `from_kind(kind) -> PcodeToken` — project a `PcodeTokenKind` down.

### `LexerState` (private)
The Bison lexer states (pcodeparse.hh:33-45): `Start`, `Special2`, `Special3`,
`Special32`, `Comment`, `Punctuation`, `Identifier`, `Hexstring`,
`Decstring`, `Endstream`, `Illegal`.

### `SleightSymbolKind`
Tagged enum mirroring the `SleighSymbol` type switch in
`PcodeSnippet::lex` (pcodeparse.y:730-758): `Space(AddressSpace)`,
`UserOp(u32)`, `Varnode(VarnodeData)`, `Operand(String, i32)`,
`JumpTarget(JumpTargetKind)`, `Label(String, u32)`.

The `UserOp` payload is the `UserOpSymbol::getIndex()` value, not the symbol
name. Both statement and expression forms place that value in the 4-byte
constant input 0 of `CPUI_CALLOTHER`, matching `createUserOpNoOut`
(`pcodecompile.cc:529`).

### `JumpTargetKind`
The five JUMPSYM `SpecificSymbol` subclasses folded into one tag
(slghsymbol.hh:359 `StartSymbol`, :376 `EndSymbol`, :393 `Next2Symbol`,
:410 `FlowDestSymbol`, :422 `FlowRefSymbol`): `InstStart` (`inst_start`),
`InstNext` (`inst_next`), `InstNext2` (`inst_next2`), `InstDest`
(`inst_dest`), `InstRef` (`inst_ref`). The class identity decides the
dynamic offset placeholder produced by `getVarnode()`
(slghsymbol.cc:1090/1155/1220/1276/1308):

- `get_varnode(self, const_space) -> VarnodeTpl` — `(spaceid const_space,
  j_start|j_next|j_next2|j_flowdest|j_flowref, real 0)` (the `sz_zero` of
  Ghidra's five overrides). The `jumpdest` grammar rule re-wraps the offset
  with `j_curspace`/`j_curspace_size` (pcodeparse.y:195); the
  `varnode`/`lhsvarnode` rules use it as-is (pcodeparse.y:202/212).

`inst_dest`/`inst_ref` are seeded into every `PcodeSnippet::new()` local
tree (pcodeparse.y:693-694); `inst_start`/`inst_next`/`inst_next2` live in
every `.sla` language table (slgh_compile.cc:1986-1991 predefinedSymbols,
kept by `SymbolTable::purge`) and reach the snippet compiler through the
language lookup.

### `ConstTpl` dynamic offset variants
`ConstTpl` carries the `j_start`/`j_next`/`j_next2`/`j_flowref`/
`j_flowdest` members of Ghidra's `const_type` (semantics.hh:36-38) as
`JStart`/`JNext`/`JNext2`/`JFlowRef`/`JFlowDest`. `j_flowref_size`(10) /
`j_flowdest_size`(12) are omitted: they have no snippet-compiler producer
(they only arise decoding `.sla` constructor templates, semantics.cc:412/
418).

### `PredefinedJumpSymbols<L>` (Host-side wrapper)
`SleighSymbolLookup` adapter layering the three predefined JUMPSYM
language symbols (`PREDEFINED_JUMP_SYMBOLS`: inst_start/inst_next/
inst_next2) over an inner lookup, standing in for the fact that a real
`SleighBase` always carries them (`SleighCompile::predefinedSymbols`,
slgh_compile.cc:1968-1996). The inner lookup keeps priority. Hosts that
install this wrapper expose the full JUMPSYM surface to callfixup /
jumpassist / executable-pcode snippet bodies exactly like the locked
oracle (see `tests/oracle/jumpdest_instsym_1204.*`).

`tools/run_userop_index_oracle.sh` compiles the locked Ghidra 12.0.4
`SleighCompile`/`PcodeCompile` implementation and verifies the observable
contract: user-op indices increase globally across declaration batches,
parameter expressions and inputs keep source order, input 0 is
`const/index/4`, and only the expression form has an output. The paired Rust
test exercises both parser paths with distinct non-zero indices.

## Structs

### `IdentRec` (pcodeparse.hh:26)
`{ name: &'static str, id: i32 }` — keyword/operator table entry.

### `PCODE_IDENTS` (static, `IDENTREC_SIZE = 46`)
Sorted table of p-code keywords/multi-char operators, faithful to
`PcodeLexer::idents[]` (pcodeparse.y:229-276). Lexicographically ordered so
`find_identifier`'s binary search matches Ghidra — except the oracle's own
single inversion (`"||"` before `"abs"`, the only strcmp-inverted pair),
which is mirrored deliberately so the binary search misses both entries
exactly like the oracle (KUNAUB-IDENTS-PIN-0001; do NOT reorder). Uses
inlined integer ids because Rust statics cannot call non-const fn; the
values are identical to `PcodeTokenKind::as_token_id`.

### `SleighSymbol`
`{ name: String, kind: SleightSymbolKind }` — a resolved SLEIGH symbol
produced by `PcodeSnippet::lex`.

### `PcodeLexer` (pcodeparse.hh:31)
The lookahead-2 state-machine lexer.
- `new()`, `initialize(text)`.
- `get_next_token() -> PcodeTokenKind` — drives `move_state`
  (pcodeparse.y:297) one char at a time, sliding the lookahead window
  (`curchar <- lookahead1 <- lookahead2 <- stream`), until a non-`Start`
  state is reported. Identifiers get keyword-resolved via `find_identifier`;
  hex/dec strings parse to `Integer` (or `BadInteger` on overflow).
- `get_identifier() -> &str`, `get_number() -> u64`.
- `tokenize_all(text) -> Vec<PcodeTokenKind>` — convenience helper.

Handles: all multi-char operators including the 3-char `s>>` / `f<=` family
(requires the full lookahead-2 buffer), `#` end-of-line comments, `0x`-prefixed
and bare hex/dec numbers.

### `PcodeData` (sleigh.hh:44)
Raw p-code op record: `{ opc: OpCode, outvar: Option<VarnodeData>, invar:
Vec<VarnodeData> }`.
- `new(opc)`, `set_output(vn)`, `add_input(vn)`, `clear_inputs()`,
  `num_input()`, `get_output()`.

### `PcodeSnippet` (pcodeparse.hh:72)
The snippet compiler.
- `new()`, `set_unique_base(val)`, `get_unique_base()`.
- `clear()` — drops non-space symbols, resets errors (pcodeparse.y:652).
- `has_errors()`, `get_error_message()`, `report_error(msg)`,
  `report_warning(msg)` (no-op, matching pcodeparse.hh:89).
- `allocate_temp() -> u64` — reserves 16 bytes of unique space per temp
  (pcodeparse.y:632).
- `add_symbol(sym)` — duplicate insertions report an error (pcodeparse.y:640).
- `lookup_symbol(name)`, `add_operand(name, index)` (pcodeparse.y:787).
- `lex() -> PcodeTokenKind` — full SLEIGH symbol resolution for STRING tokens
  (pcodeparse.y:717): maps hits to `SpaceSym`/`UserOpSym`/`VarSym`/
  `OperandSym`/`JumpSym`/`LabelSym`.
- `parse_stream(text) -> bool` — tokenize + validate (pcodeparse.y:770).
- `get_location(sym)` — always `None` (pcodeparse.hh:87).

## XML decode functions (the `<op>` / `<varnode>` path)

These port the decode half of `pcoderaw.cc` / `translate.cc` into this module
because they are the XML entry points for the P-code this parser emits.

### Element / attribute id helpers
`elem_op()` (ELEM_OP, translate.cc:25), `elem_varnode()` (ELEM_VARNODE,
address.cc:30), `elem_addr()`, `elem_register()`, `elem_void()`,
`elem_spaceid()`; `attrib_code()`, `attrib_size()`, `attrib_space()`,
`attrib_name()`, `attrib_offset()`.

### `parse_space_name(name) -> AddressSpace`
Resolve a space spelling (`ram`/`register`/`unique`/`const`/`stack`/`join`/
`iop`) to an `AddressSpace`. Mirrors `decoder.readSpace()`.

### `decode_varnode_from_attributes(decoder) -> VarnodeData`
Faithful to `VarnodeData::decodeFromAttributes` (pcoderaw.cc:33-55): dispatches
on `space=` (then `offset`/`size`) or `name=` (register lookup).

### `decode_varnode(decoder) -> VarnodeData`
Faithful to `VarnodeData::decode` (pcoderaw.cc:23): opens the `<addr>` /
`<register>` / `<varnode>` element, delegates, closes.

### `decode_pcode_op_raw(decoder, isize) -> Option<PcodeData>`
Faithful to `PcodeOpRaw::decode` (pcoderaw.cc:96-122): reads `code` attr as
opcode, handles `<void>` output, decodes `isize` inputs with special
`<spaceid>` handling.

### `decode_op(decoder) -> Option<PcodeData>`
Faithful to `PcodeEmit::decodeOp` (translate.cc:996-1016): opens `<op>`, reads
`size` attr, delegates to `decode_pcode_op_raw`, closes.

### `find_identifier(s) -> Option<usize>`
Binary search of `PCODE_IDENTS` (pcodeparse.y:278).

### KUNAUB-IDENTS-PIN-0001：`"||"`/`"abs"` 双 miss 正典钉死（2026-09-26，wt/kunaub2）

Oracle 表 `PcodeLexer::idents[]`（pcodeparse.y:229-276，自注 "Sorted list of
identifiers"）含唯一一处排序违规：索引 8 `"||"`（0x7C,0x7C）先于索引 9
`"abs"`（0x61..）——`'|'=124 > 'a'=97`，任何字节序语义下均逆序。
`findIdentifier`（pcodeparse.y:278-295）对该表做朴素二分，且
`getNextToken`（pcodeparse.y:579-586）对**一切** identifier 态 token 查表
（miss → 返回 STRING），因此 `"||"` 与 `"abs"` **双双 miss**：pcode snippet
里 `a || b` 与 `abs(x)` 无法用作关键字（降级为标识符 token）。

Rudra `PCODE_IDENTS` **逐字节镜像表序**（含该违规对），`find_identifier`
同二分算法 ⇒ 同样的双 miss，行为与 oracle 等价。**表序禁改**（"好心排序"
会制造分歧）；回归锁 = `test_find_identifier_canonical_double_miss`
（断言 `find_identifier("||") == None && find_identifier("abs") == None`）。
同批订正了 `test_find_identifier_hits` 的错误注释（原称 "abs 由状态机匹配、
lexer 从不查表"——与 pcodeparse.y:582 矛盾，真因是排序逆序导致的 miss）。

## L3 gaps
- SLEIGH integration (`SleighBase`/`SymbolTree`) for global symbol lookup
  beyond the local scope (host hook covers the snippet face).
- Register name resolution in `decode_varnode_from_attributes` (needs a
  `Translate`).
- 2026-09-27 update (PARSEADJ-PARSEFACE-PCODE-0001): the whole-parse face
  (lexer + statements + expressions + errors + size propagation + snippet
  lifecycle) is now pinned byte-identical against the locked oracle by the
  `pcode_snippet_face_1204` bilateral fixture (110 records, see below);
  `PARSER-0001`'s punctuation/failure-state parity concern is discharged
  for the face's case matrix. Known residual: the recursive-descent driver
  recovers to the next `;` after an action error where Bison aborts at the
  first error — invisible to the fixture's first-error projection, noted
  in the fixture metadata known-deltas.

## Annotation provenance

ANN-G records source provenance without changing behavior. `find_identifier`
maps to `PcodeLexer::findIdentifier` at locked `pcodeparse.cc:2776`; the four
decode entry points map to `pcoderaw.cc:23,33,96` and `translate.cc:996`.
Element/attribute constructors and recursive-descent token helpers are marked
as Rust glue because Ghidra uses file-scope IDs and generated Bison machinery.
ANN-O likewise marks `PcodeTokenKind::as_token_id`,
`PcodeTokenKind::from_token_id`, and `unary_prec` as Rust glue: Ghidra exposes
raw generated token constants and Bison parse tables, while Rudra needs typed
const conversions and a numeric Pratt-parser precedence floor. These
annotations do not change parser behavior or alignment status.
Known wire-ID, decoder/space-registry, and parser-lifecycle differences remain
owned by `MARSHAL-ID-0001`, `MARSHAL-PACKED-0001`, `SPACE-0001`, and
`PARSER-0001` respectively.

# 2026-08-16：SLEIGH lookup fallback + 声明语句 + ConstTpl::handle selector

- `SleighSymbolLookup` trait + `PcodeSnippet::set_sleigh_lookup`/`resolve_symbol`：
  `lex`/`lex_full` 在本地符号表 miss 后回落 SLEIGH 语言符号表
  （pcodeparse.cc:3215-3265 `sleigh->findSymbol`），命中符号缓存进本地表供
  语义动作按名再解析。
- `parse_assign_or_declare` 前置 STRING 分派：`STRING '=' expr ';'`（y:108
  newOutput(false)）与 `STRING ':' INTEGER '=' expr ';'`（y:110
  newOutput(true,size)），其余 STRING 走 lhsvarnode 错误（y:107/213）。
- `ConstTpl::Handle { index, select: HandleSelect, plus }`：v_field selector
  （semantics.hh:39 v_space/v_offset/v_size/v_offset_plus），operand varnode
  改为 `VarnodeTpl(hand,false)`（slghsymbol.cc:953-970 + semantics.cc:425-432，
  size 为 handle 引用而非 Real(0) 未解析哨兵）；assignBitRange 用 OffsetPlus。
- `ConstructTpl::delayslot` 默认 0（semantics.hh:174，原 -1 哨兵与 oracle
  encode 输出不一致）。
对拍：16 callfixup 模板 XML（含 `temp:1 = 0;` COPY@unique 与
`call [RBP];` CALLIND）逐字节 MATCH。

# 2026-08-17：JUMPSYM 语言符号 + 动态 offset ConstTpl（CSPEC-JUMPDEST-INSTSYM-0001）

- `SleightSymbolKind::JumpTarget(JumpTargetKind)` 类型化：五个 JUMPSYM
  `SpecificSymbol` 子类（StartSymbol/EndSymbol/Next2Symbol/FlowDestSymbol/
  FlowRefSymbol，slghsymbol.hh:359-434）的类身份决定 `getVarnode()` 产出的
  动态 offset 占位符（此前 JumpTarget 只带名字、语义动作硬编码 offset 0）。
- `ConstTpl` 新增 `JStart`/`JNext`/`JNext2`/`JFlowRef`/`JFlowDest`
  （semantics.hh:36-38 const_type 2/3/4/9/11；运行期解析语义在
  `ConstTpl::fix`，semantics.cc:122-139）。j_flowref_size/j_flowdest_size
  仅由 .sla decode 产生（semantics.cc:412/418），snippet 编译器无产生点，
  枚举省略并注释说明。
- `specific_symbol_varnode`（varnode/lhsvarnode 规则）JumpTarget 分支改为
  `(spaceid const, j_xxx, sz_zero)`（pcodeparse.y:202 `$$ = $1->getVarnode()`；
  slghsymbol.cc:1276/1308）；此前错误地输出 `(j_curspace, real 0,
  j_curspace_size)`（jumpdest 的形态）。
- `parse_jumpdest` JumpSym 分支改为重包装 offset：`(j_curspace, sym 获取的
  动态 offset, j_curspace_size)`（pcodeparse.y:195 逐字）；此前 offset 硬编码
  `Real(0)`，`goto inst_next` 会丢掉 j_next 占位符。
- Host 侧 `PredefinedJumpSymbols<L>` 组合器 + `PREDEFINED_JUMP_SYMBOLS`：
  inst_start/inst_next/inst_next2 是每个 SLEIGH 语言必然序列化的预定义符号
  （slgh_compile.cc:1986-1991；`SymbolTable::purge` default 臂放行），经
  `sleigh->findSymbol` 命中并映射为 JUMPSYM（pcodeparse.cc:3223-3252）。
  Rudra 无 SLEIGH 引擎，语言符号经 `SleighSymbolLookup` Host hook 注入，
  组合器把该语言不变量分层到任意内层 lookup 之上（inner 优先）。
- 新 fixture `tests/oracle/jumpdest_instsym_1204.{cc,rs}` + runner
  `tools/run_jumpdest_instsym_oracle.sh`：裸 SLEIGH 引擎（x86-64.sla，即
  parseInject 的 `const SleighBase*` 句柄）对拍 10 个 JUMPSYM snippet。
  双侧 byte-identical MATCH：SYM 投影（inst_start=start_symbol(9)/
  inst_next=end_symbol(10)/inst_next2=next2_symbol(11)；inst_dest/inst_ref/
  epsilon 在语言表 ABSENT——前二者 snippet 本地注入、EpsilonSymbol 被
  purge 删除）+ 全部 jumpdest/varnode 形态模板 XML + 两条 lexer 回落错误
  消息。

# 2026-09-27：整面双侧 fixture `pcode_snippet_face_1204`（PARSEADJ-PARSEFACE-PCODE-0001）

等价证明单位 = 解析器整面（generator_absorbed 12 成员：PcodeLexer
moveState/getNextToken/initialize + PcodeSnippet ctor/dtor/allocateTemp/
addSymbol/clear/reportError/parseStream/addOperand + pcodelex/pcodeerror shim，
GENERATOR_ABSORBED_2026-09-27.md §3/§4 口径）。fixture：SYM 20（x86-64.sla
findSymbol 宇宙：13 寄存器 varnode + cpuid(userop 44) + 3 预定义 JUMPSYM +
ram/OTHER/stack ABSENT）+ SNIP 77（空间种子/语句/表达式/词法/错误文本矩阵）
+ LF 10（生命周期探针）= 110 records，双侧 sha256
`1b30d20d…` 恒等。runner：`tools/run_pcode_snippet_face_oracle.sh`。

首轮差分钉出并修复的 12 缺口（g1-g12，全部 pcodeparse.rs 驱动层小件）：

- g1 ctor 空间种子改为 {const, OTHER, unique, ram, register}（y:686-692 的
  CONSTANT/PROCESSOR/SPACEBASE/INTERNAL 过滤器 + x86-64.sla 实测 5 空间；
  stack/iop 移除，OTHER 加入，`space_symbol_name(Other) = "OTHER"`）。
- g2 `add_op_list` 按 `CPUI_PTRADD`（=LABELBUILD，semantics.hh:30）计数
  `num_labels` → `<construct_tpl labels="N">` 属性（semantics.cc:748/875）。
- g3 `place_label` 的 placed-twice 状态以 `self.labels` 存储副本为权威并
  回写（C++ LabelSymbol 是符号树共享对象，clone 模型需显式同步）。
- g4 `parse_jumpdest` 补 `INTEGER '[' SPACESYM ']'` 形（y:198；size 取空间
  addrsize，如 register=4/ram=8）。
- g5 六个换向比较算子（`>`/`>=`/`s>`/`s>=`/`f>`/`f>=` → LESS 族）在
  precedence climbing 应用点交换操作数（y:134/136/138/140/161/163 的
  `createOp(opc,$3,$1)`）。
- g6 label jumpdest size 从 `size_of::<usize>()`(8) 改 `Real(4)`
  （y:199 `sizeof(uintm)`；types.h:27 `uintm = uint32_t`）。
- g7 `force_size` 实现跨 op 局部温度传播（cc:115-142：同 unique offset 的
  out/in 同步尺寸——ExprTree outvn 是 createOp 的快照拷贝，仅此机制回填）；
  `matchSize` hint 改为只扫当前 op 自身 out+inputs（cc:150-165，原实现误扫
  全 opvec）；`fillinZero` 各族（同尺寸/布尔输出/移位/SUBPIECE/CPOOLREF）
  逐臂对齐 cc:170-263（SUBPIECE 仅填 in1=4 的 oracle 行为由 ex14 钉死）。
- g8 `LOCAL specificsymbol '='` 重定义规则（y:111）：LOCAL 后跟符号 token 且
  下一个是 `=` → `Redefinition of symbol: X`；其余 → syntax error。
- g9 裸 STRING 语句错误文本改 `Unknown varnode parameter: X`（y:204
  varnode:STRING 规则胜出；y:213 lhsvarnode:STRING 是死规则——'=',
  lookahead 总先 shift 到声明形）。
- g10 纯语法错误统一为 bison 默认 `syntax error`（`YY_("syntax error")` 经
  pcodeerror；约 20 处自定义 Expected/Unexpected 文本改为该常量）。
- g11 新增 `hard_error` 通道镜像 `SleighError` 逃逸：buildTruncatedVarnode
  越界（cc:580 throw）与 force_size 局部温度尺寸冲突（cc:129/137）在 C++
  中异常直接穿透 parseStream（errorcount 不动、result 不设）；Rudra 以
  `get_hard_error()` 观察（fixture EXC 记录）。
- g12 语句边界 `refresh_lookahead_symbol()`：递归下降预取的 lookahead 在
  上一语句符号表突变（newOutput/newLocalDefinition/defineLabel）后重新解析
  ——bison 的 yylex 惰性调用保证动作后 lex（`local q; q = 1;` 的第二个 q
  必须解析为符号而非 STRING）。

配套更新：`test_snippet_new_seeds_spaces`（g1）与
`test_inject_execute_label_branch_snippet`（g6，8→4）两条旧断言改钉 oracle
真值；新增 9 条 face 回归测试（换向/force_size 传播/重定义/lookahead 刷新/
jumpdest 空间形/label size+labels 计数/EXC 通道/错误文本）。
`OpCode::name()` 与 Ghidra `get_opname` 表（opcodes.cc:29-48）在 7 个成员上
不同（PTRADD→LABEL、FLOAT_INT2FLOAT→INT2FLOAT、FLOAT_FLOAT2FLOAT→
FLOAT2FLOAT、FLOAT_TRUNC/CEIL/FLOOR/ROUND→TRUNC/CEIL/FLOOR/ROUND）——
fixture twin 以局部 canonical 表镜像编码通道，src 侧 `opcodes.rs` 更名属
共享表（print/opbehavior 面），超出本票写域，登记
PCODE-OPNAME-TABLE-0001 待裁决。opcodes 名义上 LABELBUILD=PTRADD 是语义别名
而非错误。
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
