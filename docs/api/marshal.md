# marshal.rs — Serialization / marshaling API

Serialization layer corresponding to Ghidra's `marshal.hh` / `marshal.cc` and
`xml.hh` / `xml.cc`.

**Status:** L2. `AttributeId`/`ElementId` use immutable process-wide tables with
the locked Ghidra 12.0.4 scope-0 name/ID assignments. Zero is reserved for
element/attribute traversal exhaustion; unknown names map to 159/289. This does
not lift the full module above L2: PackedDecode's single `pos+pending` model
still differs from the locked start/cur/end/attributeRead state machine, and
the Decoder trait still lacks Ghidra's error channel. See
`docs/alignment_audit/MARSHAL_PACKED_2026-08-11.md`.

2026-08-12 ANN-N 仅补 provenance：`AttributeId::new_static` 是 Rust const
占位胶水；它不能保留名称或执行 Ghidra 构造器的全局注册。本次未改变行为或模块状态。

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{marshal,xml}.{hh,cc}`.

## Constants

| Name | Value | Description |
|---|---|---|
| `ATTRIB_UNKNOWN` | 159 | Unrecognized scope-0 attribute name. |
| `ELEM_UNKNOWN` | 289 | Unrecognized scope-0 element name. |
| `ATTRIB_CONTENT` | 1 | Element text content attribute. |
| `ATTRIBUTE_ID_TABLE` | 146 pairs | Complete 12.0.4 source-manifest scope-0 attribute table. |
| `ELEMENT_ID_TABLE` | 274 pairs | Complete 12.0.4 source-manifest scope-0 element table. |

## Structs

### `AttributeId`
An annotation for a data element (marshal.hh:41).
- `new(name, id)`, `new_static(name, id)`, `get_name()`, `get_id()`.
- Equality by id.

### `ElementId`
An annotation for a collection of hierarchical data (marshal.hh:65).
- `new(name, id)`, `get_name()`, `get_id()`.
- Equality by id.

### `IdRegistry`
Immutable process-wide registry mirroring Ghidra's static scope-0 hashtables
(marshal.hh:42, 67). `new()` and repeated `initialize()` calls address the same
table and cannot allocate or renumber IDs.

- `find_attribute(name)` / `find_element(name)` return 159/289 for unknown names.
- `find_attribute_in_scope(name, scope)` / `find_element_in_scope(name, scope)`
  only reverse-map scope 0, as in locked Ghidra.
- `attribute_name(id)` / `element_name(id)` provide Rust reverse lookup over the
  exact table; ID 0 and numeric gaps return `None`.
- Legacy `register_attribute` / `register_element` are lookup-only compatibility
  methods. `register_*_with_id` validates a fixed pair and returns `bool`; none
  of these methods mutates the table.

The tables are a synthetic union of all 114 locked `.cc` source definitions:
146 attributes plus 274 elements. The standard `libdecomp.a` runtime closure
contains 136 plus 243 (379 total); 41 entries belong to alternate Ghidra/SLEIGH
front ends. The locked fixture records this projection explicitly and does not
claim that one standard runtime links every source-manifest object. Its C++
side uses the real standard 379-object registration and generates the remaining
41 same-name/same-ID objects from eight hash-locked source manifests. Fixture
ID-to-name output is an object-table scan of that source projection; locked
Ghidra exposes name-to-ID `find`, not a corresponding reverse-lookup API.
This linkage-dependent registration set remains a production `MISMATCH`:
those 41 names resolve to UNKNOWN in the standard locked runtime, while the
single Rust process table recognizes the full union.

### `Element`
An XML element — a DOM tree node (xml.hh:159).
- `new()`, `set_name(name)`, `add_content(s)`, `add_child(child)`,
  `add_attribute(name, value)`.
- `get_name()`, `get_content()`, `get_children()`,
  `get_attribute_value(name) -> Option<&str>`, `get_num_attributes()`,
  `get_attribute_name(i)`, `get_attribute_value_at(i)`.

### `Document`
A complete in-memory XML document (xml.hh:215).
- `new()`, `get_root() -> Option<&Arc<RwLock<Element>>>`, `set_root(root)`.

## Traits

### `Encoder`
Write structured data (marshal.hh). Methods:
- `open_element(elem_id)`, `close_element(elem_id)`.
- `write_bool(attrib_id, val)`, `write_signed_integer(attrib_id, val)`,
  `write_unsigned_integer(attrib_id, val)`, `write_string(attrib_id, val)`,
  `write_string_indexed(attrib_id, index, val)`.
- `write_space(attrib_id, spc)`（marshal.hh:368 纯虚；XML/树形态写空间名，
  marshal.cc:569；packed 形态写特殊空间类型字节或空间 index，
  marshal.cc:1193）。

### `Decoder`
Read structured data (marshal.hh:99). Methods:
- `peek_element() -> u32`, `open_element() -> u32`,
  `open_element_matching(elem_id) -> u32`, `close_element(id)`,
  `close_element_skipping(id)`.
- `next_attribute_id() -> u32`, `rewind_attributes()`.
- `get_indexed_attribute_id(attrib_id) -> u32`（marshal.hh:165；XML 侧按
  属性名十进制后缀重释为 `base_id+(val-1)`，marshal.cc:243；packed 侧恒返回
  ATTRIB_UNKNOWN，marshal.cc:825）。
- `read_space(spc_manager) -> Result<AddrSpace, String>`（XML 按名解析，
  未知名 `Unknown address space name: <nm>`，marshal.cc:400；packed 按
  index/特殊码解析，index 空 `Unknown address space index`、非 STACK/JOIN
  特殊码 `Cannot marshal special address space`、非空间属性
  `Expecting space attribute`，marshal.cc:997-1031。Ghidra 的 decoder 在构造时
  持有 `const AddrSpaceManager*`，Rust 按调用传参——同一对象）。
- `read_bool() -> bool`（marshal.hh:176；XML 侧值域 = `xml_readbool` 首字符
  大小写敏感解析（'t'/'1'/'y' 为真，xml.hh:391-400，XmlDecode::readBool
  marshal.cc:279-284）；packed 侧取类型字节 length-code 位
  （marshal.cc:831-842））。
- `read_bool_attr(attrib_id) -> bool`（marshal.hh:186；**MARSHAL-READBOOL-0001
  （2026-09-27）值域已 1:1 对齐**：= `xml_readbool` 首字符大小写敏感解析
  （legacy "yes" 为真、"True" 为假，xml.hh:391-400）；ATTRIB_CONTENT 伪属性读
  元素文本（marshal.cc:290-291）；packed 侧按 id 扫描 + 读取后扫描位回卷到
  元素起点（marshal.cc:844-851）。**登记残差**：缺失属性仍返回 false 而 oracle
  抛 `DecoderError`（XML `Attribute missing: <name>` marshal.cc:276 / packed
  `Attribute <name> is not present` marshal.cc:636）——bool 签名无错误通道，
  该抛错语义在生产摄入口 `ScopeLocal::decode_wrapping_attributes`
  （varmap.rs 按名扫描 + 逐字消息）建模，函数级通道归 PERSIST-0012 marshal
  票系后续。生产 encode 面恒写 "true"/"false"（writeBool，marshal.cc:508-510），
  分歧仅在 legacy/畸形流可达——双侧 fixture `tools/run_varmap_decodewrap_oracle.sh`
  三臂（"yes"/"True"/缺失 lock）钉）。
- `read_signed_integer()`,
  `read_signed_integer_attr(attrib_id)`, `read_unsigned_integer()`,
  `read_unsigned_integer_attr(attrib_id)`, `read_string()`,
  `read_string_attr(attrib_id)`.
- 自由函数 `xml_readbool(attr) -> bool`（xml.hh:391，pub）：空串假；首字符
  't'/'1'/'y' 真（xml.hh:398 "For backward compatibility" 的 legacy 'y'），
  其余（含 'T'/'Y'/'0'/'f'）假——大小写敏感。

## Implementations

### `TreeEncoder`
In-memory Encoder that builds an Element tree (equivalent of Ghidra's
TreeHandler).
- `new(registry)`, `into_document() -> Document`, `root()`.
- Implements `Encoder`.

### `TreeDecoder`
In-memory Decoder that reads from an Element tree (equivalent of Ghidra's
XmlDecode).
- `new(root, registry)`, `from_document(doc, registry)`.
- Implements `Decoder`.
- `peek_element()`, `open_element()`, and `next_attribute_id()` use `0` only for
  traversal exhaustion; unrecognized DOM names return 289/159 without ending
  traversal. Attribute and child order remain source order.

## L3 gaps
- Actual XML text serialization (writing the DOM back out as XML bytes) —
  ingestion is now covered (see MARSHAL-XML-TEXT-0001 below).
- `readOpcode`/`writeOpcode` (require OpCode integration);
  `readSpace`/`writeSpace` landed 2026-08-24 (see the packed/join section).
- `readSignedIntegerExpectString`.
- `TreeEncoder::write_space` 的 ATTRIB_CONTENT 文本值形态（marshal.cc:572-579）
  对树编码器不可达（树按名存属性，与 `write_string` 的处理一致）。

## MARSHAL-ID-0001 oracle status

The locked same-input fixture covers all 420 source-manifest pairs in both
directions, unknown names, nonzero scope fallback, repeated initialization,
`size=19`, `space=20`, and TreeDecoder end/unknown/order behavior. Its aggregate
status remains `MISMATCH`: the source-manifest ID observations match, while the
standard-runtime 379-versus-420 registration set and strict TreeDecoder
close/open error behavior remain registered residuals.

## MARSHAL-XML-TEXT-0001：XML 文本 ingestion（2026-08-16）

`src/marshal.rs` 新增 XML bytes → 有序 DOM 的完整解析链，1:1 移植 Ghidra
`xml.cc`/`xml.y`：

### `XmlScan`（xml.cc:111-177, 2080-2375）
- 4 字节环形 lookahead（`getxmlchar`/`next`），EOF 时补一个合成 `'\n'` 再产生
  `-1`（NUL 字节同样终止流）。
- 9 种 one-shot 扫描模式（CharData/CData/AttValue×2/Comment/CharRef/Name/SName/
  Single），`nexttoken` 派发后重置为 Single。
- `scanSName` 消费空白后无 Name 时返回字面 `' '` token（S 的物化）。

### 语法驱动（xml.y 141-219 的编译动作，xml.cc:1594-1845）
- 递归下降实现同一 LALR 文法；所有 mode 切换动作在 bison 中均为 default
  reduction（单完整项/唯一动作状态），故在"shift 最后一个 token 之后、读下一个
  token 之前"执行——parser 用 `tok_valid`+`ensure()` 的惰性单 lookahead 精确
  复现该时序。
- 关键忠实细节：尾随 root 的注释必然 syntax error（`document: element Misc`
  仅一个 Misc + 合成 `'\n'`）；`<!DOCTYPE` 首位不可达（plain syntax error），
  仅在 prologpre 非空后报 `DTD's not supported`；`<?` 一律 PI 错误（`<?xml`
  除外）；end tag 名不校验；纯空白 chardata/CDATA 经 `print_content` 走
  `ignorableWhitespace` 丢弃；注释文本丢弃；同名属性按源序全保留。

### `DecoderError`（xml.hh:297）
- `{ explain: String }`，消息与 Ghidra 逐字一致（`syntax error`、
  `Processing instructions are not supported`、`DTD's not supported`、
  `Unable to open xml document <name>`、`Unknown attribute: <nm>`）。

### `DocumentStorage`（xml.hh:258, xml.cc:2435-2477）
- `parse_document(&[u8]) -> Result<&Document, DecoderError>`：先追加 null slot
  再解析（失败时保留 null slot 的部分状态）。
- `open_document(filename)`、`register_tag`（同名覆盖）、`get_tag`。
- `doclist_len()` 为 RUDRA-GLUE 观察访问器（Ghidra doclist 私有无 API）。

### `xml_tree(&[u8]) -> Result<Document, DecoderError>`（xml.cc:2480）

### 已登记残余（fixture metadata）
1. MISMATCH：≥0x80 的数值字符引用与未知实体 `(char)0xFF` 标记——Ghidra 追加
   单字节，Rust String 以 UTF-8 编码（ASCII 域 byte-exact）。
2. UNTESTED：bison YYMAXDEPTH=10000 的 `memory exhausted` 深嵌套路径。

## 2026-06-27（续）：Decoder trait 新增 attribute_name/element_name

- `Decoder::attribute_name(id: u32) -> Option<String>`：按 id 查找属性名（通过 registry），支持按名称分发的解码（database.rs 的 decode_header 使用）。
- `Decoder::element_name(id: u32) -> Option<String>`：按 id 查找元素名，支持按名称匹配的元素解码。
- TreeDecoder 实现两者（通过内部 registry 的 read lock）。

## 2026-06-27（续）：PackedEncode + PackedDecode（二进制格式）

**packed_format 模块**（marshal.hh:480）：HEADER_MASK/ELEMENT_START/ELEMENT_END/ATTRIBUTE/HEADEREXTEND_MASK/ELEMENTID_MASK/RAWDATA_MASK/RAWDATA_MARKER/TYPECODE_* 常量。

### `PackedEncode`
二进制编码器，实现 Encoder trait（marshal.hh:579）。
- `new()`，`into_bytes() -> Vec<u8>`。
- open_element/close_element/write_bool/write_signed_integer/write_unsigned_integer/write_string/write_string_indexed。
- write_header（短/扩展 ID 编码）+ write_integer（长度编码变长整数）。

### `PackedDecode`
二进制解码器，实现 Decoder trait（marshal.hh:512）。
- `new(input, registry)`。
- open_element/close_element/peek_element/next_attribute_id/read_*/rewind_attributes。
- 支持 BOOLEAN/SIGNEDINT_POSITIVE/NEGATIVE/UNSIGNEDINT/STRING 类型解码。
<!-- annotation-pass: 2026-07-04 -->

# 2026-08-16：XmlDecode 整数属性 hex/octal 自动识别（CSPEC-TEXT-INGEST 复核 F3）

`TreeDecoder` 的 `read_unsigned_integer`/`read_unsigned_integer_attr`/
`read_signed_integer`/`read_signed_integer_attr` 原为十进制-only
`.parse()`，与 Ghidra `XmlDecode` 经 `istringstream` `unsetf(dec|hex|oct)`
的自动进制识别不符（生产 cspec `<localrange>` 的 `0x…` hex 偏移会被解为
0）。现按 marshal.cc:296-330/353-381 语义实现 `cpp_stream_unsigned`/
`cpp_stream_signed`（前导空白跳过、可选符号、`0x`/`0X` hex、前导 `0`
八进制、最长合法前缀、无数字→0=流失败初值、溢出饱和），四个函数标注
改为 `// Ghidra: marshal.cc:<line> XmlDecode::read…`（原 RUDRA-GLUE 注释
不实）。新增单元测试 `test_cpp_stream_integer_bases`。

# 2026-08-24：packed 特殊空间编解码 + Join piece 编解码（MARSHAL-XML-TEXT-0001）

R5 复核登记的两项残差就此落地（fixture
`tests/oracle/marshal_packed_join_1204.*`）：

## `PackedEncode::write_space`（marshal.cc:1193-1218）
属性头后按 `spc->getType()` 分派：FSPEC→`(TYPECODE_SPECIALSPACE<<4)|2`（0x62）、
IOP→0x63、JOIN→0x61；SPACEBASE 且 `isFormalStackSpace()`→0x60（STACK），否则
0x64（SPACEBASE，二级寄存器偏移空间）；其余走默认臂
`writeInteger(TYPECODE_ADDRESSSPACE<<4, spc->getIndex())`。

## `PackedDecode::read_space`（marshal.cc:997-1031）
- TYPECODE_ADDRESSSPACE：变长整数=index → `getSpace(index)`，空槽
  `DecoderError("Unknown address space index")`。
- TYPECODE_SPECIALSPACE：length 字段=特殊码——仅 STACK（`getStackSpace`）与
  JOIN（`getJoinSpace`）可解，其余（含 fspec=2/iop=3/spacebase=4）
  `DecoderError("Cannot marshal special address space")`（编码侧写、解码侧拒的
  非对称是 Ghidra 原文语义）。
- 其他类型：跳过剩余数据后 `DecoderError("Expecting space attribute")`。

## `TreeEncoder`（XmlEncode 形态）
- `write_string_indexed` 修正为 `{base}{index+1}`（marshal.cc:559-567 的 1-based
  无分隔符形态；原 `{base}_{index}` 为自创）。
- `write_space` = `write_string(name)`（marshal.cc:580）。
- `get_indexed_attribute_id`（marshal.cc:243-260）：游标越界/前缀不匹配→
  ATTRIB_UNKNOWN；十进制后缀解析 `base_id+(val-1)`；无数字
  `LowlevelError("Bad indexed attribute: " + nm)` panic。
- `read_space`（marshal.cc:400-409）：当前属性值按名 `get_space_by_name`，
  未知名 `Err("Unknown address space name: {nm}")`。

## 残差登记（fixture metadata coverage）
1. join piece 的寄存器名形态（无 `:`，space.cc:566-569 走
   `getTrans()->getRegister`）：register 表属 SPACE-0001，Rust 显式
   `Err("register-name join piece requires the Translate register table")`。
2. 未知名 piece 空间：C++ 赋 null 后靠 `JoinRecord::operator<` 的 size 先比较
   （translate.cc:172-191）不触空解引用而"成功"；Rust 非可选空间句柄在
   查名点 `Err("Unknown address space name: {nm}")` 拒绝。

## KUNAUB-CHARREF-0001：convert_char_ref 回绕语义钉死（2026-09-26，wt/kunaub2）

`convert_char_ref`（marshal.rs，镜像 xml.cc:2337-2360 `convertCharRef`）的
`int4 val` 累加器 `val *= mult; val += cur`（xml.cc:2356-2357）无位数上限、
无值域校验；scanner 域（xml.cc:2151-2179 `scanCharRef`）只保证 token 是
十六进制/十进制数字，长数字串（≥9 位十六进制，如 `&#x1111111111111;`）
在 C++ 侧是有符号 int 溢出 UB。锁定 oracle（x86-64 gcc/clang -O2）的 de
facto 行为=静默二进制回绕（imul/add），随后语法动作经
`string::operator+=(char)` 截断低字节进字符流。

**修复（裁决 (b)：oracle de facto 有确定行为而 Rust debug 分歧）**：
`val = val.wrapping_mul(mult); val = val.wrapping_add(cur);` —— debug 与
release 全 profile 回绕（=de facto C++），消除 debug-only 的 "multiply with
overflow" panic；release 语义零变化（对一切非溢出输入 wrapping 恒等于原生
`*`/`+`，主管线行为逐字节不变）。

**回归锁**（`marshal::tests`）：
- `test_convert_char_ref_wraparound_de_facto_cpp`：手工计算的 de facto 回绕
  值断言——十进制 2147483648→`i32::MIN`、4294967296→0、9999999999→1410065407；
  十六进制 x100000000→0、x1ffffffff→-1、x111111111→0x11111111。
- `test_convert_char_ref_overflow_push_truncates_low_byte`：回绕值经
  `push_reference_char` 低字节截断（x141→'A'）。

对抗输入来源=伪造 spec/XML/cpool 文件（非物理语料）；B2 状态=debug/release
同值锁定 + de facto 回绕值回归，oracle 侧无需 golden（无已定义标准行为，
de facto 行为由平台语义决定）。
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
