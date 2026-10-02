# `printlanguage.rs` API Reference

## 2026-09-27：PRINTC-PRINTLIST-WIRING-0001 — trait 虚面补齐 + per-Architecture printlist 注册表（Lane PCHOVER2）

**trait 虚面**（PRINTC0004 handover 收口）：`PrintLanguage` trait 新增两个
REQUIRED 方法——`get_name`（printlanguage.hh:448 基类 inline getter，`name`
字段 printlanguage.hh:261/构造 printlanguage.cc:69）与 `set_comment_style`
（printlanguage.hh:478 纯虚；oracle LowlevelError 以 `Err(String)` 同文承载）。
唯一实现者 `PrintC` 补齐三转发（get_name/set_comment_style/reset_defaults），
修复 `reset_defaults` 此前吃 trait 默认空体的虚分派缺口。

**per-Architecture printlist 注册表**（architecture.hh:205-206 print/printlist
的存储镜像；`Architecture` 侧 API 见 arch.md 同日节）：线程局部
identity-keyed（`ARCH_PRINTLISTS: HashMap<u64, PrintlistState>`，字段键
`Architecture::print_registry_key`），提供
`register_print_language`（architecture.cc:171-172/431 push-并-置-current）、
`printlist_current`（`glb->print` 读通道，options.cc:526 消费）、
`printlist_len`、`printlist_reset_defaults`（architecture.cc:1443-1444 循环体）、
`unpublish_printlist`（Drop 镜像，architecture.cc:200-201 teardown 半）。

**为何线程局部而非 struct 字段**（TFSINGLE 先例，typefactory.rs
CURRENT_ARCH_TYPES 同款约束）：funcdata.rs 的 canonical-Factory static
（`OnceLock<Arc<Architecture>>`）钉死 `Architecture: Send+Sync`，而一切 printer
天生 !Send（Rc 型共享 `AddrSpaceInner`/`JoinRecordTables`/`FspecEntryTable` +
`dyn Emit`，2026-09-27 probe 实证）；oracle 的裸指针 vector 字段进 struct 必须引
入 unsafe 或破坏 static。identity-keyed（非 last-publisher-wins）保证同线程两个
Architecture 各自 reset 恰好自己的 printer（oracle per-object vector 语义）。
共享句柄为 `Arc<RwLock<Box<dyn PrintLanguage>>>`：注册方留用同一对象做具体
PrintC 工作，option 施加方经 current 通道达之——与 `glb->print` 可观察等价。

## 2026-08-28：Atom 元数据直达 emitter

`rpn_emit_atom` 的 `VarToken` 分支现在把 `Atom` 中的 highlight、Varnode id 与 op id
完整传给 metadata-aware emitter，而不是把变量 id 固定为 0。
`PRINTLANGUAGE-ATOM-METADATA-0001` 以真实双侧 RPN 对象图锁定两次
`'\0'/ConstColor/同一 vn/同一 consuming op`，8 records / 678 bytes raw stdout
逐字节 `MATCH`。非恒量 vartoken producer 仍可能使用 storage offset 与 `op=-1`，
其他 Atom/pending/recurse/markup 分支继续绑定 `PRINT-RPN-0001`/`PRETTY-0001`，
因此完整 `pushAtom/emitAtom` 和模块仍为 `MISMATCH/UNTESTED`。

## 2026-08-26：RPN emit 改用带 id 的括号/空格原语（PRINTC-LINEWRAP-0001）

- `rpn_push_op` 的 postsurround/presurround 臂升级：
  `open_paren(&tok.print1)` 返回组 id 存 `entry.id2`，back token 用
  `close_paren(&tok.print2, entry.id2)`（printlanguage.cc:146-147/178-179
  的 `openParen(OPEN_PAREN)` / `closeParen(CLOSE_PAREN,id)` 完整形态）。
- binary/unary 臂的 `emit_spaces` 换 `emit.spaces(tok.spacing, tok.bump)`
  （printlanguage.cc:338-369）；`bump` 随调用传递，pretty printer 把它
  当折行缩进用。
- 兼容 shim `emit_spaces` 转发到 `Emit::spaces`。

**验证**：hugehelp 与 golden 逐字节一致；全量差分 defects=0/numbering=0。

## 文档状态

- **状态**: 🔧 **L2（2026-08-12）**——`PRINT-RPN-0001A` 已用锁定
  12.0.4 `PrintLanguage::pushOp/pushAtom` 运行时 fixture 证明 root unary/binary、
  无括号嵌套和必须括号嵌套的**可见纯文本**为 `MATCH`。token 表、完整递归、
  exact group ID/queue、真实 op/vn/type/highlight/field/case payload、namespace
  策略及多个虚方法仍为 `UNTESTED/MISMATCH`，模块保持 L2。

**源代码路径**: `src/printlanguage.rs`

## 模块说明 (Module Doc)

Base language printing interface — Reverse Polish Notation (RPN) engine.

对应 Ghidra 的 `printlanguage.hh` / `printlanguage.cc`。本模块移植了共享基类 `PrintLanguage` 的基础设施：RPN token 栈、运算符优先级/括号化算法、Atom/OpToken 数据类型，以及格式化工具。

Rudra 的 `PrintC` 目前为了输出质量直接通过 `Emit` 发射；本模块只提供了部分 Ghidra 基类算法接口：
1. 括号化算法（`parentheses()`）可作为 1:1 参考使用。
2. RPN 数据类型（`OpToken`/`ReversePolish`/`Atom`/`NodePending`）作为 Ghidra 对齐的规范定义存在。
3. 纯格式化工具可以针对 Ghidra 行为进行单元测试。

## Ghidra 对应关系

| Ghidra (printlanguage.cc/hh) | Rudra (printlanguage.rs) | 行号 |
|---|---|---|
| `PrintLanguage::modifiers` enum | `modifiers` mod (FORCE_HEX..PENDING_BRACE) | hh:144 |
| `PrintLanguage::tagtype` enum | `TagType` enum | hh:163 |
| `PrintLanguage::namespace_strategy` enum | `NamespaceStrategy` enum | hh:175 |
| `OpToken::tokentype` enum | `TokenType` enum | hh:87 |
| `EmitMarkup::syntax_highlight` enum | `SyntaxHighlight` enum | prettyprint.hh |
| `OpToken` class | `OpToken` struct + constructors | hh:84 |
| `PrintLanguage::ReversePolish` struct | `ReversePolish` struct | hh:182 |
| `PrintLanguage::NodePending` struct | `NodePending` struct | hh:195 |
| `PrintLanguage::Atom` struct | `Atom` struct + `AtomPayload` enum | hh:210 |
| `PrintLanguageCapability` class | `PrintLanguageCapability` struct | hh:42 |
| `PrintLanguage::parentheses` | `parentheses()` fn | cc:269 |
| `PrintLanguage::unicodeNeedsEscape` | `unicode_needs_escape()` fn | cc:411 |
| `PrintLanguage::mostNaturalBase` | `most_natural_base()` fn | cc:731 |
| `PrintLanguage::formatBinary` | `format_binary()` fn | cc:793 |
| `PrintLanguage::unnamedField` | `unnamed_field()` fn | cc:719 |
| `PrintLanguage::setIntegerFormat` | `apply_integer_format()` fn | cc:698 |
| `PrintLanguage::pushAtom` | `rpn_push_atom()` fn | cc:162 |
| `PrintLanguage::pushOp` | `rpn_push_op()` fn | cc:129 |
| `PrintLanguage::emitOp` | `rpn_emit_op()` fn | cc:328 |
| `PrintLanguage::emitAtom` | `rpn_emit_atom()` fn | cc:375 |
| `PrintLanguage::recurse` | `rpn_recurse()` fn | cc:514 |
| `PrintLanguage::pushVn` | `rpn_push_vn()` fn | cc:197 |
| `PrintLanguage::opBinary` | `rpn_op_binary()` fn | cc:546 |
| `PrintLanguage::opUnary` | `rpn_op_unary()` fn | cc:566 |
| `PrintLanguage::resetDefaultsInternal` | `reset_defaults_internal_state()` fn | cc:575 |
| `OPEN_PAREN`/`CLOSE_PAREN` consts | `OPEN_PAREN`/`CLOSE_PAREN` consts | cc:22 |

## 导出的公共 API (Public API)

### 枚举与常量

- `pub mod modifiers` — 打印修改标志位掩码（FORCE_HEX=1..PENDING_BRACE=0x8000）
- `pub enum TagType` — Atom 类型（Syntax/VarToken/FunToken/OpToken/TypeToken/FieldToken/CaseToken/BlankToken）
- `pub enum NamespaceStrategy` — 命名空间显示策略（Minimal/NoNamespaces/AllNamespaces）
- `pub enum TokenType` — 运算符 token 类型（Binary/UnaryPrefix/Postsurround/Presurround/Space/HiddenFunction）
- `pub enum SyntaxHighlight` — 语法高亮颜色标签
- `pub const OPEN_PAREN: &str = "("`
- `pub const CLOSE_PAREN: &str = ")"`

### 数据结构

- `pub struct OpToken` — 运算符 token（print1/print2/stage/precedence/associative/type_/spacing/bump/negate）+ 6 个构造器（`binary`/`unary_prefix`/`postsurround`/`presurround`/`space`/`hidden_function`）
- `pub struct ReversePolish` — RPN 栈条目（tok_index/visited/paren/op_index/id/id2）
- `pub struct NodePending` — 待处理数据流节点 + `NodePending::new()`
- `pub struct Atom` + `pub enum AtomPayload` — 非运算符 token + 7 个构造器（`new`/`with_type`/`with_field`/`with_op`/`with_op_vn`/`with_op_fd`/`with_op_vn_int`）
- `pub struct PrintLanguageCapability` — 语言能力注册对象 + `new()`/`get_name()`

### RPN 引擎函数

- `pub fn parentheses(top: &OpToken, stage: i32, op2: &OpToken, prev: Option<&OpToken>) -> bool` — 括号化判定（cc:269-323）。`prev` = `revpol[size-2].tok` 的 token（None 编码 `revpol.size()<=1`），仅 hiddenfunction 分支读取（cc:309-319，2026-08-17 审计修复：原硬编码 `true` 改为按祖父 token 类型/优先级精确判定）
- `pub fn rpn_push_op(...)` — 运算符入栈（cc:129）
- `pub fn rpn_push_atom(...)` — Atom 入栈（cc:162）
- `pub fn rpn_push_vn(...)` — 隐含 Varnode 入待处理列表（cc:197）
- `pub fn rpn_emit_op(...)` — 运算符发射（cc:328）
- `pub fn rpn_emit_atom(...)` — Atom 发射（cc:375）
- `pub fn rpn_recurse(...)` — RPN 递归发射（cc:514）
- `pub fn rpn_op_binary(...)` — 二元运算符推送（cc:546）
- `pub fn rpn_op_unary(...)` — 一元运算符推送（cc:566）

`rpn_push_op` 现在严格区分可见括号与不可见打印组：root 表达式及不需要
括号的子表达式调用 `Emit::open_group/close_group`，不会再把 Ghidra 的
`openGroup()` 错发成字符 `(`。需要保持求值顺序的子表达式仍调用
`open_paren/close_paren`。

### 12.0.4 oracle：`PRINT-RPN-0001A`

运行 `tools/run_printlanguage_group_oracle.sh` 会分别执行锁定 Ghidra 与 Rudra，
并对 stdout 做无规范化 direct diff。四个已覆盖结果为：

```text
root_unary=!x
root_binary=a + b
nested_invisible=a + b * c
nested_parenthesized=a * (b + c)
```

这些 case 的 visible-text 状态为 `MATCH`；fixture overall 仍是 `UNTESTED`，
因为 `EmitPrettyPrint` 的 TokenSplit 队列、exact group ID、换行和 markup payload
尚未观察。完整 provenance 位于
`tests/oracle/printlanguage_group_1204.metadata.json`。

### 格式化工具

- `pub fn unicode_needs_escape(codepoint: i32) -> bool` — Unicode 是否需要转义（cc:411）
- `pub fn most_natural_base(val: u64) -> i32` — 最自然进制选择（cc:731）
- `pub fn format_binary(val: u64) -> String` — 二进制格式化（cc:793）
- `pub fn unnamed_field(off: i32, size: i32) -> String` — 人工字段名生成（cc:719）
- `pub fn apply_integer_format(mods: &mut u32, nm: &str) -> Result<(), String>` — 整数格式修改器应用（cc:698）
- `pub fn reset_defaults_internal_state(...)` — 默认值重置（cc:575）
- `pub fn escape_character_data(buf: &[u8], charsize: usize) -> String` — 字符串转义（遗留兼容）

### 遗留 Trait

- `pub trait PrintLanguage` — 遗留 trait shim，保持 `printc.rs` 的 `impl PrintLanguage for PrintC` 编译。新代码应使用上述自由函数与数据类型。

<!-- annotation-pass: 2026-07-22 -->

### 2026-08-17：emitLineComment 全量移植落在 PrintC + resetDefaultsInternal 掩码勘误

- `PrintLanguage::emitLineComment`（printlanguage.cc:589-648）在 Rust 侧的
  完整移植落在 `impl PrintLanguage for PrintC`（`printc.rs`）——Ghidra 的
  该成员非虚函数，PrintC 直接继承基类实现；Rust trait 的默认体是 no-op，
  故实装放 PrintC。逐字节 token 循环、`line_commentindent=20`
  （printlanguage.cc:580）、负 indent 回退语义（cc:595-596）全部按 oracle；
  C 风格 `"/* "`/`" */"` 界定符是 PrintC `resetDefaultsPrintC`→
  `setCStyleComments()`（printc.cc:1594→printc.hh:242）的不变量。
- `resetDefaults_internal_state` 自由函数（本文件，cc:575-583 移植）原本
  只接管 mods/line_commentindent/namespc_strategy；本轮在 PrintC 构造器
  对调并修正了两个注释掩码的默认值引用：`head_comment_type =
  header|warningheader`（cc:579）、`instr_comment_type = user2|warning`
  （cc:582）——此前两值互换（详见 docs/api/printc.md 2026-08-17 节
  UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ③）。

## 2026-09-24: pushType 虚签名 Arc 化(RESIDMAP-PLTSTUB-EMITSHAPE-0001)

- trait `push_type` 的参数由 `&Datatype` 改为
  `&std::sync::Arc<Datatype>`——Rust 侧对 Ghidra 虚函数
  `pushType(const Datatype *ct)`(printlanguage.hh:319)的共享所有权等价
  (代码库类型一律以 Arc<Datatype> 流转)。实现(PrintC)同步声明符栈化
  (见 docs/api/printc.md 2026-09-24 节);调用侧仅
  emit_prototype_output/doc_variable_decl 两处,均已是 &Arc。
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
