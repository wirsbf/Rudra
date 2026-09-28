# `printc.rs` API Reference

## 2026-09-28：MAINMIXED-LABELPOS-0001 — discovery 账本解包 MultiGoto 包裹叶（switch 头 code_r 标签位，Lane MAINMIXED）

**现象**：canon httpd main 的 `if (iVar5 == 0) goto code_r0x0012ba77;` 标签贴
在 goto 紧后（`goto ...; code_r0x0012ba77: if ((iVar5 == 0x1117e) ...`），golden
贴在 switch 头（`exit(1); code_r0x0012ba77: switch(...)`）——LABEL-POS 2 行。

**根因（双侧钉死）**：机器 0x2ba6f `test/jne 2bf00`——jne 走错误路径（0x1117e
检查块 @0x12bf00），**直落 0x12ba77=switch dispatch 块**（`movzbl 0x33(%rsp)`…
`notrack jmp *%rax`）；golden/Rugra 结构树两侧同形（Rugra `#5 IFGOTO
target=0x12ba77(#6)`→尾部 `#6 Switch control=#6`），标签机制链完整——分歧在
RUGRA-GLUE 防御层：`emit_block_ops` 的 discovery 账本（GOTO-LABEL-UNPRINTED-
0001）只解包 `BlockGoto`（BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 先例），
switch 控制块是 **BlockMultiGoto** 包裹（block.hh:588 `BlockMultiGoto::emit =
getBlock(0)->emit`——emit_block_multigoto 以 MultiGoto arc 调 emit_block_ops，
arc 自身非 Basic/Copy，包裹叶 0x12ba77 不入账本）→ 真跑 pass 的
`emit_goto_statement` never-emitted 锚（printc.rs:16829 `!discovery_block_starts
.contains`）误 fire 于 goto 现场，吃掉 `printed_labels` 并压制 switch 控制块
自身（printc.cc:2685 emitLabelStatement 位）的打印。

**修复**：账本解包臂扩 `BlockType::MultiGoto`（与 Goto 臂同型：downcast 取
`wrapped`，filter Basic/Copy）。锚不再误 fire；标签经 emit_any_label_statement
的 pending 臂在 switch 控制块发射点打印（=oracle emitBlockBasic 的
emitLabelStatement 位）。

**验收**：canon httpd 30→**28**（main 9→**7**：LABEL-POS 2 行归零；标签与
golden 逐字节同位 `exit(1); code_r0x0012ba77: switch(`）；canon curl 42 零
漂移；镜面五面 PASS；bank 391/391。main 残 7=DECL-EXTRA 1（declfam 待并）+
STRDAT 6（strdatenv 待并）——三车道合流后 main 归零。关联票
BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001 的 httpd main 站点收口（curl `goto X; X:`
4 站点残量保持 OPEN——本修复模式可复用但其验收域在 w-scopeb）。

## 2026-09-28：MAINMIXED-WRAP-0001 — comma_separate 分隔符与 for 头子句分隔恢复双 token 发射（Lane MAINMIXED）

**现象**：canon httpd main for 头折点错位——Rugra 在 `(undefined *)0x0` 之后、`;`
之前断行（`...0x0\n    ; ppuVar15 = ppuVar15 + 1) {`），golden 断在逗号之后
（`...puVar1 = *ppuVar14,\n    puVar1 != ...`）；且 Rugra 断行处遗留行尾空格
（`", "` 整 token 后接合成 0 宽 tokenbreak）。curl 同族 2 处行尾空格
（:531/:2273）。

**根因（oracle 亲读）**：printc.cc:2707-2709 的 comma_separate 分隔符是
`emit->print(COMMA); emit->spaces(1);` **两次调用**——spaces(1) 是
EmitPrettyPrint 的 tokenbreak（Oppen 扫描在溢出时按 scanqueue 自底强制的
断行机会，prettyprint.cc:792-800）；emitForLoop 的两个子句分隔同理
（cc:2981-2982/2984-2985 `print(SEMICOLON); spaces(1)`）。Rugra 把 `", "` /
`"; "` 胶合成单次 `print`——断点消失，强制断行落到下一 token 前的合成 0 宽
分隔（checkstring，cc:819-828），产生行尾空格 + 错位折点。

**修复**：三处恢复双 token 序列——①`emit_block_ops` RPN 臂（cc:2708-2709）、
②legacy 镜像臂（同 cc 行）、③`emit_for_loop` 两个 `;`（cc:2981/2984）。
文本不变（非断行处 spaces(1) 印一个空格），断行处空格被换行吸收=oracle
字节形态。其余 `print(", ")` 位点（opCall 实参/原型/field 枚举等）对应
oracle 不同发射机制，不在本根范围。

**验收**：canon httpd 30 持平（本根为字节级修复：`&` 落位后折点已与 golden
重合，本修复消除行尾空格并锁定 token 流）；canon curl 42 持平（2 处行尾
空格消除=向 golden 字节收敛）；镜面五面 PASS（httpd 30≤36/sq 2720≤2724/
sqlite 6055≤6071 只降）；新增回归测试
`pretty_print_overflow_breaks_at_punct_spaces_token_no_trailing_space`
（src/prettyprint.rs，断点落在标点后 spaces(1)、行尾无空格）。关联票
CANON-LINEWRAP-CANONSITES-0001 的 main for 头站点收口（ap_fini 4 行残量
另属长表达式折点子根，票面保持 OPEN）。

## 2026-09-27：PRINTC-PRINTLIST-WIRING-0001 — resetDefaults emitter 半 + PrintLanguage 虚面收口（Lane PCHOVER2）

PRINTC0004 登记的两项 handover 本车道收口（写域延伸 `prettyprint.rs`/
`printlanguage.rs`/`arch.rs`/`options.rs`，均在 TODO 行与 commit 声明）：

**① resetDefaults 的 emitter 半**（printlanguage.cc:674 `emit->resetDefaults()`
→ `EmitPrettyPrint::resetDefaults` prettyprint.cc:1237-1242）：`PrintC::reset_defaults`
（printc.cc:2325 链）现以 `self.emit.reset_defaults()` 开头，经 `Emit` trait 虚分派
落到 `EmitPrettyPrint`（lowlevel 半结构性吸收——Rust `EmitNoMarkup` 无
`indentincrement` 字段；`indentincrement=2` + `setMaxLineSize(100)` 全量执行）。
旧"emitter 域 handover"注释已更正。

**② options→printer 接线 + printlist 结构**（architecture.hh:205-206
print/printlist）：`OptionCommentStyle::apply`（options.cc:523-527）现真正路由
`glb->print->setCommentStyle(p1)`——经 Architecture 的 printer 注册表
（`printlanguage` 模块线程局部 identity-keyed 存储，TFSINGLE 先例；成因=funcdata.rs
canonical-Factory static 钉死 `Architecture: Send+Sync` 而 PrintC 天生 !Send，
probe 实证）。`Architecture::reset_defaults` 补 architecture.cc:1443-1444
printlist 循环。配套：`PrintLanguage` trait 补 `get_name`（printlanguage.hh:448）
与 `set_comment_style`（:478 纯虚）两个 REQUIRED 方法；`PrintC` 落
`name` 字段（printlanguage.hh:261 基类态，"c-language"，printc.cc:111/118）并在
`impl PrintLanguage for PrintC` 补 `get_name`/`set_comment_style`/`reset_defaults`
三转发（此前 `reset_defaults` 吃 trait 默认空体=虚分派缺口）。

**B2 双侧 fixture**：`printc_printlist_wiring_1204`（8 case **字节恒等**，
runner `tools/run_printc_printlist_wiring_oracle.sh` + metadata 三件套）——
structure（printlist count/current name）、route 五例（cplusplus/c/"/*custom"/
"//custom"/badstyle 的 msg+threw+render 文本）、emit.before（width 60 突变）、
reset（`Architecture::resetDefaults` 后 width=100 + C 风格恢复=emitter 半 +
printlist 循环双锁）。oracle 侧 production `OptionCommentStyle::apply` +
`Architecture::resetDefaults` 直驱；Rust 侧同 production 体。
新增单测 ×4（prettyprint emitter 重置对、printc trait 虚分派、arch per-arch
隔离、options 路由全程）。
## 2026-09-27：checkAddressOfCast typedef 剥离环（Lane TYPEDEFIMM，wt/typedefimm）

`check_address_of_cast`（printc.cc:376-418）补齐 cc:390-393 的两条剥离环：
array 元素基（base0）与 dt1 pointee（base1）各自沿 per-type `typedef_imm`
通道（type.hh:196/244，工厂 `get_typedef` type.cc:3834 置位）走到根后再比
（cc:394-395）。此前该环被登记为"Rugra 无 typedef 链、恒等形态"（PRINTC0004
handover）；通道落地后为 1:1 行为。非 typedef 基型立即停步，与 oracle null
`typedefImm` 恒等。测试矩阵 `test_check_address_of_cast_matrix` 新增
(f) typedef 元素剥离正例（td(int) 元素 vs int pointee 仍渲染 `&`）与
(g) 不同 typedef 根负例（td_int vs td_uint 剥离后仍拒绝）。

## 2026-09-26：印前指针盖章加法输入臂整撤（CASTFUSE-C ZEXT 子族 / Lane VZEXT）

WIDTHOP（2026-09-24，见下条）收缩后的盖章域仍保留了"尺寸 8 且 def 不属
扩展/截断/CAST 族的 INT_ADD/INT_SUB 输入"这一**加法输入臂**。sq 语料
（sasquatch）仪器化实测证明该臂仍是元类型中毒源：全部 200 个失败 ZEXT
位点无一例外 `out=Pointer/sz8`——ZEXT **输出**的 HighVariable 并入了被此臂
盖成 `int *` 的成员（成员统计：`Pointer/MULTIEQUAL` 324、`Pointer/CALLIND`
12、`Pointer/INDIRECT` 6、`Pointer/CALL=strtol` 2 次），代表类型被指针夺走
→ `isZextCast`（cast.cc:463-477）的 out 元类型门（∈{UINT,INT}）判 false →
printc 三段式落 opFunc 兜底印 `ZEXT48(x)`（oracle 印 `(uint8)x` cast）。

根因不变式：给 INT_ADD/SUB 输入从加法**输出**的指针用途回灌类型，是
`TypeOpIntAdd::propagateType` 对**一切** def 族明文禁止的方向
（typeop.cc:1196-1197 `inslot == -1 → newtype = 0`），WIDTHOP/
PTRSTAMP-CAST-OVERWRITE 的 def 黑名单只是逐语料打补丁。本次整撤加法输入
臂：盖章域收缩为 **直接 LOAD/STORE 地址槽 varnode 单边**
（`TypeOpLoad::propagateType` typeop.cc:487-502 的合法 value→address 边），
命名消费面 `pointer_varnodes`（Hungarian `piVar` 前缀）集合原样保留。
真正对齐杠杆（ActionInferTypes 的地址槽传播）仍由
TYPEPROP-ADDRSLOT-PERSIST-0001 跟踪。

**验收**（基=master d0e27c14 干净 A/B 亲测，fast-release）：sq 镜面
ZEXT token **107→0**、骨架 7748→**7290**（−458，即 SQATTR 归因的
CASTFUSE-C ~451 行族收敛）、defects 0/numbering 7 不变、matched 805/810
不变；canon curl **字节恒等**（267/0/0，单行 ZEXT48→`(ulong)` cast 向
golden 收敛）、canon httpd 283→**263**/0/0（20 行 SEXT48→`(long)` cast 全
为 golden 方向）；镜面四面棘轮（275/460/55/22639）门禁全过；bank
391/391 MATCH。

## 2026-09-25：常量叶显式后缀 U/L 通道（PRINTC-INTSUFFIX-0001 / Lane STRLIT）

`PrintC::push_integer`（Ghidra: printc.cc:1288）的显式打印后缀补全——`force_unsigned_token = vn->isUnsignedPrint()` / `force_sized_token = vn->isLongPrint()`（cc:1296-1297，`vn != 0 && !isAnnotation()` 门内读取）与尾部 `t << 'U'` / `t << sizeSuffix`（cc:1362-1365）。旗标由 `ActionSetCasts` 经 `CastStrategy::markExplicitUnsigned`/`markExplicitLongSize`（cast.cc:38-108，coreaction.cc:2664-2665 调用）写入 varnode `addlflags`（Rugra 的 `UNSIGNED_PRINT`/`LONG_PRINT` 已在 coreaction 落地），此前打印侧从不读取——常量恒无后缀。

实现：

- `PrintC::constant_print_flags(vn)`（`// Ghidra: printc.cc:1296`）——annotation 守卫 + 旗标读取；
- `integer_text_with_mods` 增 `force_unsigned/force_sized` 参数——**cc:1319 语义**：`sign && displayFormat != force_char` 分支（符号两补数翻转 cc:1314-1318）收尾把 `force_unsigned_token` 复位 false（有符号渲染永不带 U），随后 match 尾部追加 `'U'` / `size_suffix`；
- `integer_text_flagged`（vn 承载形）+ `default_cast_constant_text_flagged`（cc:1814 default-cast 臂的 push_integer 同样携带 vn）；
- 接线点：RPN 叶片 `constant_leaf_text` 全臂（Uint/Int/Unknown/None-ct/default-cast）、直接发射 `push_constant_typed`（Option vn）、`push_varnode` 常量梯级与 `push_constant`（vn 恒在域）。无 vn 的 scalar 形（enum/char 臂与 `vn==0` 调用点，cast.cc:50-51 对 charPrint/enum 恒拒）保持 false——与 oracle 观测恒等。
- `size_suffix` 字段（`// Ghidra: printc.cc:2332`，`initializeFromArchitecture` cc:2336-2339）："LL" 当 sizeof(long)==sizeof(int)，否则 "L"；**PRINTC-UNMAP-SINGLETON-0001 起动态计算**——`initialize_from_architecture(types)` 在 doc_function 入口从 `fd.arch.types` 幂等求值（x86-64 语料 8≠4 → "L"，与旧构造器钉值字节恒等；castStrategy->setTypeFactory 半为结构 no-op：promote_size 已在 CastStrategyC::new 物化，cast.rs 无工厂句柄）。

**E2E（curl 124 / httpd 34，fast-release 亲测，基=master 5ec78f22 干净重建 A/B）**：curl 369→**361**/0/0（main 100→94、getparameter 45→43，其余 122 函数零变化）；`0x4000U/0x2004000U/0x10000400U/0x23U` 四位与 golden 清单逐一对应，Rugra U-行骨架无 golden 之外形态（0 处 overshoot）。httpd 872→**866**/0/0（六处 `iVar10 + 1U/2U`；golden 115 U-行中 Rugra 现 6——其余为 coreaction `mark_explicit_unsigned` 在 httpd 的点火不足，登记移交）；双跑 cmp 恒等；gcc 审计 curl 104/20、httpd 15/14 双侧恒等；bank 391/391；lib 1730P/1F==亲父集（nonzeromask 预存）。

## 2026-09-25：无名被调者两兜底的拼写/space 通道（PRINTC-FUN-PAD-0001 / PRINTC-OPCALL-ENTRYSPACE-0001 / Lane NAMFIX）

RPN `opCall`（Ghidra: printc.cc:593）的无名被调者兜底两处正确化，均为**未触发兜底**（现语料 golden 全有符号名或 driver 预拼 `FUN_{:08x}` 数据库名——curl_cur 0 处、httpd_cur 全 8 位，均不经此臂），双差分预期字节恒等：

1. **FUN_ 零填充**（PRINTC-FUN-PAD-0001，P3）：canon 兜底此前 `format!("FUN_{:x}", off)` 无填充，golden 拼写为 `FUN_00102020`（8 位）。CR-MIRROR2 核定 digit 规则 = oracle `AddrSpace::printRaw`（space.cc:206-222）的 `setw(2*sz)` 契约（`sz>4` 时 `offset>>32==0` 收缩 4、else `offset>>48==0` 收缩 6；`byteToAddress` 除 wordsize）。新 helper `PrintC::print_raw_zero_pad_digits(addr_size, word_size, offset)`（`// Ghidra: space.cc:206`，digit 核心——无 `0x` 前缀无 `+cut`，即 headless 数据库名 `FUN_<digits>` 的面）；与 `func_0x` 兜底同则不同前缀。单测钉拼写：`FUN_00102020`/`FUN_0012c520` 收缩宽 8、`0x123456789ab` 宽 12、wordsize 4 除法 + 传输面 `+cut`。
2. **opCall entry space 通道**（PRINTC-OPCALL-ENTRYSPACE-0001，P4）：`func_` 面此前硬编码 `AddressSpace::Ram`。oracle 链 = printc.cc:602 `fc->getEntryAddress()`（fspec.hh:1686）自带 space（fspec.cc:4934 ctor：CALL 注解化**前**的 in(0) varnode 完整地址）。Rugra 的 Iop 注解只镜像 offset（`new_varnode_call_specs` compatibility_offset），space 走 callspec 通道：`get_call_spec() → entry_addr`；锁序按 fspec.rs:2470-2477 快照式（varnode 守卫先释再锁 callspec）。新 helper `PrintC::entry_addr_dims(entry)`（`// Ghidra: fspec.hh:1686`）从 `Address::get_space()` registry 句柄取 `(addrsize, wordsize)`，spaceless legacy 形（`FuncCallSpecs::new_for_op` 现产 `Address::new(offset)`）回退 flat Ram 默认 (8,1)——当前语料全部路径等价。`addr_space_print_raw` base 臂重构为委托新 `addr_space_print_raw_dims`（同规则单一来源）。fspec 侧 space 填充为 fspec 车道工作（见 TODO_BOARD 该 ID 的 fspec 半项）。

休眠/恒等声明：两兜底在 curl/httpd 双语料 0 次触发（FUN_ 名全部由 driver 符号表预拼写 `FUN_{:08x}`，与 digit 规则对所有可达地址逐字节等价）；legacy 孪生 `FUN_{:08x}` 两处（emit 树 + `op_call`）不属两 ID 判例面且对语料地址域（<2³² 或 0x55xx… 自然 12 位）与规则输出恒等，不动。

## 2026-09-25：标签/注释换行走 `tag_line_indent`（PRINTC-EMIT-TAGLINE-ABS-0001）

`emitLabelStatement`（printc.cc:3198-3214）的 `emit->tagLine(0)` 是 Emit 的**带参
绝对** virtual（prettyprint.hh:180）：标签行 = endl + 0 空格，**列 0 顶格，与嵌套深度
无关**——canon curl 32 处（29 `LAB_` + 3 `switchD_…_caseD_…:`）全部顶格。Rugra 三个
标签调用点（`emit_label_statement` 平尾路径、`emit_any_label_statement` 结构臂与
pending_goto_labels 兜底臂）此前走合并入口 `tag_line(0)`→相对形（当前缩进级），标签
行带 2-8 空格缩进。现改走 `tag_line_indent(0)`（trait 绝对形，见 prettyprint.md 同日
条目）。`emit_line_comment` 的两处 fallback（非 EmitNoMarkup emitter）同步改
`tag_line_indent(indent)`——printlanguage.cc:597 同为带参绝对形（-1 先钳到
line_commentindent=20，cc:594-596；EmitNoMarkup downcast 臂字节已 oracle 精确，
不动）。验收：curl 标签族 32 行顶格 ==canon 逐字；httpd 34 行同收敛；双差分/bank/
gcc 审计零回退（证据见 TODO_BOARD 本行）。

## 2026-09-24：STORE 地址恢复单发射（PRINTC-STORE-DBLEMIT-0001 / Lane GI）

`PrintC` 的 STORE 发射块（`emit` 的 opStore 分支）在 merge 33418058
（75d51e03 × 4aee0d60）冲突解错后同时保留了**两条**地址发射路径：FQ 侧的手射
`tag_op("*")`+`rpn_push_in(...)` 与 FR 侧的 dereference token 协议路径
（`rpn_push_op(rpn_tok_dereference)`+`rpn_push_in(..., self.mods)`），导致每个
STORE 地址印两次（`*(cast)ADDR*(cast)ADDR = v`，全语料不可编译 C：httpd 140 行 /
curl 19 行拼接形）。

修复恢复 `PrintC::opStore`（printc.cc:500-517）的单发射语义：

- **deref 形**（`deref_form == true`）：仅 `rpn_push_op(rpn_tok_dereference)` 一次 +
  `rpn_push_in(op, 1, m)` —— 对应 cc:511 `pushOp(&dereference,op)`；token 协议的
  括号决策（printlanguage.cc:287-292，unary_prefix prec 62）保证
  `*(puVar4 + 3)` 形合法左值。
- **usearray 形**：不压任何 token，仅 `m |= print_store_value` —— 对应
  cc:508-509（`usearray && !isSet(force_pointer)` 时 `m |= print_store_value`），
  由隐式 PTRADD/PTRSUB def 自己发射 `p[i]`。修复前该形也被错误压了 token，
  且压的是 `self.mods` 而非带 flag 的 `m`。

验证（亲父 b5b949dd 前后对照，双侧亲测）：curl 门禁 1822/0/0 → **1744/0/0**、
httpd 1756/0/0 → **1700/0/0**（零回退：curl 14 fn 改善、httpd 9 fn 改善）；
gcc 审计 curl 104OK/20FAIL、httpd 23OK/6FAIL；双发射行两口径均清零；五投影
（RUGRA_MIRROR=1）与锁定 oracle projection 逐字节 MATCH。归因账本见
`docs/alignment_docs/MAIN_RESID_ATTRIBUTION_2026-09-24.md`。

## 2026-09-24：印前指针兜底盖章通道按 oracle 方向收缩（WIDTHOP 宽度算子族 / Lane GF）

`doc_function` 的印前指针盖章通道（`pointer_varnodes` 收集 + 兜底
`v_type` 盖章）此前对"LOAD/STORE 地址 **或** 喂给 LOAD 的 INT_ADD/INT_SUB
任一输入"的 `(space, offset)` 键**无差别盖章** `int *`（8 字节）。三处
偏离 oracle：

1. **方向禁令**：把 INT_ADD 输出侧的指针用途回灌进加法输入，正是
   `TypeOpIntAdd::propagateType` 明文禁止的方向（typeop.cc:1197
   `inslot == -1 → return 0`——"Don't propagate pointer types this
   direction"）。ZEXT/SEXT 输出（无 propagateType 覆写，typeop.cc:317
   默认 null）与 SUBPIECE 输出（仅 far/near 指针 + getSubType 尺寸游走，
   typeop.cc:2161-2186）被盖成 `int *` 后，`isZextCast`/`isSextCast`/
   `isSubpieceCast`（cast.cc:411-466）全数判 false，printc 的三段式
   （printc.cc:786-811 opIntZext/opIntSext、:843-878 opSubpiece）落进
   opFunc 兜底，印出功能算子 `SUB81(x,0)`/`ZEXT48(x)`/`SEXT14(x)`——而
   oracle 同位点印 `(char)x` cast / 隐没扩展（isExtensionCastImplied）。
2. **键碰撞**：`(space, offset)` 不是 varnode 身份——寄存器空间一族重叠
   varnode 共享一个 offset（RAX/EAX/AL 全在 register 0，SSA 每代重写同
   键），任何一条 LOAD 地址键会把整族亚寄存器与全部 SSA 代一起盖章
   （实证：getparameter `(Register,0)` 一键 27+ 个 4 字节对象 + 1 字节
   对象被盖 `int*`）。现改按 `create_index`（VarnodeBank 分配身份）入集
   `load_addr_direct`。
3. **尺寸盲**：兜底指针固定 8 字节。现按 `TypeOpLoad::propagateType` 的
   `propagateToPointer(..., outvn->getSize(), ws)`（typeop.cc:495-498）以
   地址 varnode 自身尺寸构型。

收缩后的盖章域 = **直接 LOAD/STORE 地址槽 varnode + 尺寸 8 且 def 不属于
扩展/截断族（ZEXT/SEXT/SUBPIECE/PIECE/INSERT）的加法输入**；命名消费面
`pointer_varnodes`（Hungarian `piVar` 前缀，`pointer_type_for`）保持原集合
不动。扩展/截断族作地址侧同样排除：oracle 的 out→地址槽传播要求对面边
（load 值）已有具体类型，本语料 golden 中扩展输出从不携带指针（全量 0 功能
ZEXT/SEXT 印记）。

> **2026-09-26 更新（Lane VZEXT）**：加法输入臂已**整撤**（sq 语料 200 失败
> ZEXT 位点全数 out=Pointer 中毒实测；out→in 方向对一切 def 族非法，
> typeop.cc:1196-1197）——盖章域现为直接 LOAD/STORE 地址槽单边，见本文件
> 顶部「2026-09-26」条目。**CR-VZEXT 勘正（同日 follow-up commit）**：直连
> 槽盖章残部的 `drop(vn);` 读守卫释放已恢复——探针周期误删致潜伏同线程
> read-hold-write 死锁（reviewer 同形最小复现 timeout 124 钉死；基线
> d0e27c14 原有该 drop）；禁向行号引用 1193-1195→**1196-1197** 勘正。
> 下文为收缩时点的历史记录。

**验收**（基线=亲父 b25bce7a 亲测）：curl 1995/0/0 → **1992/0/0**（−3：
glob_range 69→67、file2string 113→112）、httpd 2072/0/0 → **2068/0/0**
（−4：ap_getparents 109→105），逐函数零回退；功能宽度算子 token
curl 48→12 / httpd 50→16（清一色 cast/隐没形态）；gcc 审计 104OK/20FAIL +
8OK/21FAIL == 基线；四投影（next_url/match_url/myprogress/parseconfig）
stage 流与 MATCH 态逐字节恒等（仅 META producer tree-id 行异）；双跑字节
恒等；`cargo test --lib` 失败集=已知 flaky 族（printc:: 12/12、
type_system::cast 20/20 全绿）。残余 12+16 token 两亚族让渡：
①SUB 功能形态（out 高类型=undefined 基型）=setcasts `subpiece_output_token`
→updateType 应用域（FV2 81cdfa2b 后继，coreaction.rs）；②ZEXT/SEXT 功能
形态（out 落在含真指针实例的合并 high，代表类型为 `int *`）=varmap/Merge
代表性类型域。见 WIDTHOP 行（docs/TODO_BOARD.md）。

## 2026-09-24：sanitize_c_ident 放行 `:`——限定名保真（DRIVER-SWITCHD-DEFFN-0001）

> **2026-09-25 更新（Lane DOTFIX）**：`sanitize_c_ident` 已整体退役——
> 三站点全量直通原文（点号/冒号等一律保留），见本文件
> 「2026-09-25（Lane DOTFIX）」条目与 STUBLEAK-DOTNAME-SANITIZE-0001。
> 下文为历史记录。

`sanitize_c_ident`（RUGRA-GLUE，无 Ghidra 对应物）此前把一切非
`[A-Za-z0-9_]` 字符折叠为 `_`，包括命名空间分隔符 `::`。Ghidra 的打印器
对函数名**不做任何标识符消毒**：`PrintC::docFunction` 经
`emit->tagFuncName(fd->getDisplayName(), ...)`（printc.cc:1141 一带）原样
发射数据库送入的限定名，锁定 golden httpd 因此打印
`switchD_00154265::default(void)`（0x12b7fa/0x12b804/0x12b80e 三处分析器
命名函数）。现在 `:` 直接通过，`switchD_...::default` 不再被改写成
`switchD_...__default`。影响面封闭：三个调用点（符号表快照
`set_*_from_funcdata`、`doc_function` 的函数显示名、参数名）中，当前只有
函数显示名通道可能见到 `:`（符号/参数名均为普通标识符）；curl 语料零
`:` 名，E2E 输出与改动前逐字节相同；httpd 仅新增的三个 switchD default
处理函数变化。原始缺口与命名规则、驱动侧发现通道见
DRIVER-SWITCHD-DEFFN-0001（httpd 驱动，docs/TODO_BOARD.md）。

## 2026-09-23：emitBlockGoto 目标切换 target_dyn + emitLabel 取址链（PRINTC-GOTOPRINTS-0001 收官，joined_/dup_ 形态族）

`emit_block_goto` 的 goto 目标地址此前读 legacy 类型化投影
`BlockGoto::goto_target`（`Option<Arc<RwLock<BlockBasic>>>`，按字段文档恒为
`None`——结构树的叶是 dyn 化 BlockCopy，无法回出共享身份的类型化 Arc），产生
`addr=0`，再被 `emit_goto_statement` 的零地址防御吞掉：**结构树里存在 BlockGoto、
`compute_goto_prints` 也判 prints=true，但 goto 语句从不打印**，只剩目标块的
label 孤立输出（witness：curl my_get_token `joined_r0x001037b2:` 有 label 无
`goto joined_r0x001037b2;`，golden cc:1257 两者都有）。修复 = 切到
`target_dyn`（Ghidra `gototarget` 指针的活体捕获，block.hh:548）+
`flow_entry_address`（emitLabel 的 `getFrontLeaf→subBlock(0)→getEntryAddr`
链，printc.cc:3167-3170 的传输层），即字段文档预告的 PRINTC-GOTOPRINTS-0001
切换。joined_/dup_ 前缀判定本身（emitLabel cc:3173-3187 + EX2 的
`joined_label_addrs`/`dup_label_addrs` 投影）无需改动——f_joined_block 在
`node_join_create_block`（funcdata_block.cc:785）、f_duplicate_block 在
`node_split_block_edge`（cc:831）置位后沿 bblocks 存活到 print 时快照，链路
完整；缺口只在 goto 侧目标解析。

**验收**（基线=亲父 2a32802e 亲测）：curl 2381/0/0 → **2330/0/0**（−51）、
httpd 2238/0/0 → **2224/0/0**（−14）；label-without-goto 位点归零（curl 0/httpd 0，
修前至少 1+若干）；joined_ 形态族在对比域内收敛（curl 唯一 joined 对
my_get_token 0x1037b2 双行齐现；httpd golden 的 122 处 joined 全部位于 Rugra
29 函数语料之外，非对比域）。新暴露的结构族 goto（golden 以循环回边结构化而
Rugra 树为 BlockGoto：curl glob_set 0x104c20、httpd ap_parse_vhost_addrs
0x12cfcb / ap_pregsub 0x12e475 / ap_no2slash 0x12e87b）登记
PRINTC-GOTOSTRUCT-RESID-0001（blockaction 域）；switch-case 标号拼写族
（`switchD_.._caseD_..` vs `LAB_`/`code_r`）见 PRINTC-LABSPELL 残差清单。
三投影 next_url/match_url/parseconfig.constprop.0 MATCH×3 保持；printc 单测
12/12；gcc 审计 curl 82OK/25FAIL、httpd 6OK/23FAIL 均等于基线。

## 2026-09-23：emitLabel 三臂补全——code-label 符号层 + hasSpecialLabel 门 + printRaw 小写/基址（PRINTC-LABSPELL-LABSYMS-0001）

oracle `PrintC::emitLabel`（printc.cc:3164-3193）是三臂决策：①`hasSpecialLabel()`
（block.hh:291，`f_joined_block|f_duplicate_block`）命中 → 跳过符号查询，前缀
`joined_`/`dup_` + shortcut + printRaw；②`queryCodeLabel(addr)`（database.cc:1301，
经 ScopeGhidra 远端 `getCodeLabel`，database_ghidra.cc:308-325）命中 → LabSymbol 的
displayName 整体替换（前端 DB 的默认 `LAB_<image-based addr>` 标号符号，由反汇编器
flow reference 建立；函数入口处主符号是 FUNCTION 而非 LABEL → 返回空走泛型臂，
golden httpd witness `goto code_r0x001542b0;` = FUN_001542b0 自环）；③泛型臂
`code_` + shortcut + printRaw（space.cc:206-222，`<< hex` = **小写**零填充）。
Rugra 旧实现三处偏差：无符号层（恒走③）、joined/dup 未追踪（③ 前缀恒 `code_`）、
`{:0width$X}` 大写且无 image-base。修复：

- **新字段**：`code_labels: HashMap<u64,String>`（前端 DB LABEL 符号层替身——
  oracle 由本地 ScopeGhidra 缓存远端查询结果承载）、`code_label_base: u64`
  （前端加载基址差：analyzeHeadless 0x100000 / raw-BFD mirror 0——mirror 下
  ELF 相对地址 = oracle 单函数 harness 的 printRaw 输出，直接 runner witness
  `code_r0x0002b8c0`）、`joined_label_addrs`/`dup_label_addrs: HashSet<u64>`
  （f_joined_block/f_duplicate_block 状态的入口地址投影，doc_function 时从
  `fd.bblocks` 快照——Rugra 的 label 发射点是地址键控的，部分无块句柄）。
- **`code_label(addr)` 重写**：`display = addr + code_label_base` 后按
  display 选 sz（>>32/>>48 收缩），依次判 joined → `joined_r0x…`、dup →
  `dup_r0x…`、符号层命中 → 名字整体返回、否则 `code_r0x{:0width$x}`（小写）。
  所有 label 发射点（emit_label_statement / emit_any_label_statement 两臂 /
  push_goto_target / flat-tail goto / continue 改写 goto）共用此 helper。
- **驱动侧安装**（examples/curl_decompile.rs + httpd_decompile.rs，镜像
  PTR_/DAT_ 的 program-DB 层惯例）：后管线、前打印。参考集来源=**反汇编流
  引用**（每条直接分支 jmp/jcc 的静态目标——正是前端 DB 建 `LAB_` 符号的
  reference 集合），NOT lift 后的 pcode：管线阶段（condexe 合并/块手术）会把
  CBRANCH 目的地输入改写成 unique 空间临时量（实证：httpd
  ap_fini_vhost_config blk 0x2d0a2 outs=[0x2d175,0x2d0f0] 而 CBRANCH
  in(0)=(Unique,0x10000114)），pcode 级扫描结构性丢目标。排除自身入口与
  DB 符号占用地址（Java `getCodeLabel` 的 SymbolType==LABEL 过滤替身）；
  `LAB_{:08x}` 小写 8 位零填充（与 `ANALYZE_HEADLESS_IMAGE_BASE` 相加后的
  前端地址）。mirror（RUGRA_MIRROR）下不装层、base=0——raw-BFD oracle 无
  analyzer 标号、地址 ELF 相对。
- **验收**：curl skeleton 2511→**2381（−130）**、httpd 2282→**2238（−44）**，
  双门禁 defects=0/numbering=0；共享地址拼写错配双双归零
  （curl 30 地址 rugra 侧 `code_r↔LAB_` 残留 0、httpd 23 地址残留 0）；
  逐函数 diff 零回退（curl 10 函数改善 main −39/getparameter −50/
  parseconfig −15/next_url −9 等,httpd 7 函数改善 ap_getparents −13/
  ap_ht_time −9/ap_fini_vhost_config −6 等）；三投影（next_url/match_url/
  parseconfig.constprop.0，RUGRA_MIRROR=1 全家 env，stage_bisect v1.2）
  保持 **MATCH×3**（label 属打印期，投影只追踪 PcodeOp 级 action 流）；
  printc 单测 12/12；gcc 审计 curl 82OK/25FAIL==DY 基线。残差：joined/dup
  投影只覆盖 nodejoin 创建的 BlockBasic 自带 flag（结构器 BlockCopy 包裹链
  上 flag 传递依赖既有 blockaction 生命周期，0x1037b2 的 joined_ 形态由该域
  收官）；rugra-only/golden-only 标号地址（curl 5+5、httpd 5+~1120）属
  goto 目标结构差（块分裂点/未发射块），非拼写层可收敛。

## 2026-09-22：符号优先的叶子打印优先级 + partial-symbol 叶子形态 + `::` 遮蔽前缀（PRINTC-GLOBALSYM-LEAF-PRIORITY-0001）

oracle 的叶子名解析（`PrintLanguage::pushVnExplicit`，printlanguage.cc:218-230）只有
annotation → constant → `pushSymbolDetail`（printlanguage.cc:238-262）三级，**不存在任何
按地址查名字的代理**。Rugra 此前在两条生产叶子路径（RPN `make_atom_for_vn` →
`get_varnode_display_name_inner` 与 legacy `push_varnode`）都把 Ram/Const 的
`symbol_table` 地址代理放在 Priority 0——先于 `vn.high` 的符号解析直接 return，叠加
driver 对 `.data/.bss` 逐字节 span-盲播 DAT_ 名，main/gp/parseconfig 的
`DAT_00117[56]xx` 族（167 处 config 内部字节引用）全部落 DAT 代理名。本 commit 按
oracle 语义修复三件：

- ### 2026-09-23（VARGROUP-ABSORB-0001 §4-4）：push_symbol_detail_leaf 局部符号 partial 走向恢复
- 移除局部符号裸名降级（原注释以"bridge 符号尺寸近似"为由对 `!symbol_is_global` 直接返回 displayName）。oracle 的 pushSymbolDetail（printlanguage.cc:238-262）对局部/全局符号走同一 symboloff→bound check→partial/mismatch 阶梯——`glob.pattern[0].type`/`auVar24._0_4_`/`in_stack_..._80_24_` 全部产自局部符号。持久 ScopeLocal 符号层（见 varmap.md/coreaction.md）现已精确尺寸，bound check 与 `._off_sz_` 臂产出 oracle 形态；mismatch 臂（`_name`/unnamed-location，printc.cc:2067-2083）仍守超大读。

**①打印优先级（符号优先）**：新 `push_symbol_detail_leaf(&self, vn, allow_cast)
  -> Option<String>`（`// Ghidra: printlanguage.cc:238`）实现 sym!=null 臂的完整文本
  形态，插在两条叶子路径的**最前**：`symboloff==-1` 且类型不需 resolution →
  pushSymbol 形态（scope 前缀 + displayName，printc.cc:1905-1936）；
  `symboloff + vn.size <= sym.type.size` → `pushPartialSymbol`（printc.cc:1947-2065，
  `partial_symbol_text` 渲染 `name.field[idx]...`）；否则 `pushMismatchSymbol`
  （printc.cc:2067-2083：off==0 → `_name`，else `pushUnnamedLocation(vn 自身地址)`）。
  地址代理（`symbol_table`/`string_table`）降级为符号未命中时的回退（oracle 的
  sym==null 唯一臂是 pushUnnamedLocation；代理是 Rugra 对 oracle 全局 Data 符号的
  替身）。`allow_cast` = oracle 调用点的 `isRead`（读叶子 true，赋值 LHS false，
  printlanguage.cc:256-257），门控 walk 的 SUBPIECE-cast 臂。
  **两个 Rugra 桥接防御**（httpd 回归实证）：(a) Priority 0.4——Register 空间
  **is_input** varnode 的 `param_names` 查找先于符号分支：oracle 的 ScopeLocal
  param Symbol 与 FuncProto 同名（ActionParameterSymbols 同步），Rugra 桥接
  （`Funcdata::symbol_entry_for`）没有该同步（auto `in_register_...` 名），符号分支
  会把 `*param_2 + 0xa11b8` 打成 `*in_register_00000288 + ...`；(b) partial/
  mismatch 两臂**仅对全局符号**生效——Rugra 桥接的 entry 尺寸是近似值（1 字节
  entry 盖 8 字节读触发假 `_pcVar12`），oracle 的 restructure 逐 varnode 精确；
  局部符号一律取 pushSymbol 纯名形态（= 修复前可观测文本）。
- **②`::` 遮蔽前缀（MINIMAL_NAMESPACES）**：新 `symbol_scope_prefix(&self, sym,
  entry)`（`// Ghidra: printc.cc:202`）+ `local_scope_names: HashSet<String>` 字段。
  oracle 中 `Symbol::getResolutionDepth(curscope)`（database.cc:323-359）对局部
  nametree 内被同名的参数/局部/ActionNameVars 命名 high 占据（`ScopeInternal::
  isNameUsed`，database.cc:2417-2432）的全局符号返回深度 1，`pushSymbolScope` 打印
  全局 scope 的**空** display name + `::` 二元 scope 运算符（printc.cc:24，attachScope
  保证全局 scope 名为空，database.cc:2951）——`::config.outfile`。`local_scope_names`
  在 `doc_function` 一次性收集三通道：funcp 参数名、ScopeLocal 符号名、非全局符号
  backing 的 high 名（oracle 中每个 print-命名 high 都是局部 Symbol）。全局性判定用
  **DB 属主查询**而非 scope_id：ScopeLocal 桥接 Symbol（`Funcdata::symbol_entry_for`）
  硬编码 scope_id 0 与 worker Database 默认 global_scope_id 0 冲突，动态 uVarN 符号会
  自遮蔽误打 `::uVarN`；改用 `db.query_container(global_scope_id, entry.addr, 1, 空usepoint)`
  的命中名等于符号名判定（动态 entry 直接判局部；栈地址查询必 miss）。
- **③push_partial_symbol walk 抽取**：`partial_symbol_walk(&self, off, sz, ct,
  outtype, bigend, allow_cast) -> (Option<String>, Vec<String>)`（`// Ghidra:
  printc.cc:1947`）——原 `push_partial_symbol` 内联的 PartialSymbolEntry 类型树下钻
  （STRUCT/UNION findTruncation 字段 `.f`、ARRAY getSubEntry `[N]`、allowCast 的
  SUBPIECE-cast 臂、synthetic `._off_sz_`）抽为纯函数，emit 入口与新
  `partial_symbol_text`（单 atom 文本形态，`(<finalcast>)name.entries`）共用，
  行为逐行不变。
- **③b ARRAY 臂 getSubEntry 守卫（S2SELECT 2026-09-28）**：文本路径的数组臂
  曾用发散重实现 `array_sub_entry`（无视 `sz`、以 `get_size()` 为步长），而
  `TypeArray::getSubEntry`（type.cc:1257-1267）的 `noff+sz > alignSize` 守卫在
  访问跨多元素时返回 null——`xunknown1[16]` 上的 4 字节访问被错误分解为
  `[4]._0_4_`（store 形）或下钻 1 字节元素后命中 allowCast SUBPIECE 臂的
  `(xunknown4)sym[4]`（load 形；cast.cc:411-432 UNKNOWN→UNKNOWN offset 0 恒真），
  oracle 应落符号级 synthetic `._4_4_`（printc.cc:2030-2041）。修复=改调 1:1
  移植 `Datatype::array_get_sub_entry`（datatype.rs，与 RPN 孪生路径
  `rpn_push_partial_symbol` 共用），发散 helper 删除。回归钉
  `test_partial_symbol_array_multi_element_piece_falls_to_field`（跨元素→
  `._4_4_` 无 cast；元素内错位→`[1]._1_2_`；整元素→`[2]`）。

driver 侧（examples/curl_decompile.rs）配套：`.data/.bss` 逐字节 DAT 播种改为
**span 感知**——ELF symtab/dynsym 的 STT_OBJECT（st_value..st_value+st_size）区间内
字节不再播种 DAT_ 名（与 Database 侧 STRCONST-SPANNONOVERLAP 同款 skip 语义；
oracle 的 Program DB Data 严格不与具名 Symbol 重叠）。config(0x17520,304B) 内部
0x17521..0x1763f 的 `DAT_001175xx/6xx` 代理名全部消失。

**验证**（oracle=12.0.4 e40ed130，`tests/golden/ghidra_curl_1204.c`）：
`DAT_00117[56]xx` 167→0（仅余合法 `PTR_DAT_00117020`，golden:1678 同形）；
`::config.<field>` 0→192/234（残差为 gp/parseconfig 结构族既有差异，字段覆盖 37/39，
缺 `.configread/.nobuffer` 两个整字段族——该两族与 DAT 无关，是常量折叠/分支结构差
异的既有 gap）；`.rodata` 合法形态勿伤验证：`&DAT_00107180/001099a8/0010c1d8` 与
`DAT_00107178` 前后保留；`::` 无泄漏（仅 `::config`，无 `::uVar/::param`）；
curl 全量差分 defects=0/numbering=0/skeleton 3711→3637；gcc 审计 81 OK/26 FAIL
与基线持平；**httpd 前后逐字节 0 diff**（base b06d725 同一 worktree 家族构建对照，
`param_2`/`pcVar12` 形态不变）；printc 单测 12/12、varmap 45/45。
已知残差（非本域）：oracle 的 `my_get_token::save`/`next_url::beenhere` 函数命名空间
前缀族与 `::config.configread/.nobuffer` 两字段，均先于本 commit 存在。

## 2026-08-30：FuncProto-void 打印投影守卫（PRINTC-VOIDCALL-0001，POSTFIX-RETIRE-0001 W3）

oracle 的 void 调用语句形态由 IR 决定，不由 print 层拆分：
`ActionFuncLink::funcLinkOutput`（coreaction.cc:1521-1541）先 `opUnsetOutput`
拆除 CALL 输出，仅在 callspec **output-locked 且非 void** 时重建
（`newVarnodeOut`，cc:1540-1551）；`PrintC::emitExpression`（printc.cc:2471-2476）
以 `outvn != 0` 决定赋值 LHS（无输出 ⇒ 语句形态 `f(args);`），`opReturn`
（printc.cc:758-761）仅在 `numInput()>1` 时打印返回值（无值 ⇒ 裸 `return;`）。
Rugra 的 action 层已移植同判定（coreaction.rs `ActionFuncLink::func_link_output`
的 void 臂），但 print 层此前无投影：CALL 输出若幸存（action 顺序噪音）即渲染
非法 C `return free(p);`，靠 prettyprint 的 P13 硬编码 13-libc 表文本拆分兜底。

本 commit 在 print 层按 callspec 的 FuncProto 投影 oracle 无输出字节：

- **`void_callee_call_addrs: HashSet<u64>`**（新字段）：`doc_function` 快照阶段
  从 `fd.callspecs` 收集 `prototype.output_type_locked &&
  return_type.get_metatype()==Void` 的 CALL 指令地址（键 =
  `FuncCallSpecs::new_for_op` 存的 `op.get_addr()`）。解锁的 void-default
  proto **不**入集（oracle funcLinkOutput 只对 locked void 保持无输出，解锁
  输出归 trial 恢复裁决）。
- **`callee_returns_void(&self, op)`**：print 时判定（CALL + 地址在集）。
- **`emit_expression_rpn`**：LHS 守卫——void 调用不推 assignment token/atom
  （对齐 printc.cc:2471-2476 `outvn != 0`）；legacy 孪生 `op_call` 同守卫。
- **`dispatch_op_rpn` RETURN 臂 + legacy `op_return`**：in(1) 的 def 是
  void-callee CALL 时打印裸 `return`（对齐 cc:758-761 numInput()==1 形态）。
- **两个语句循环的 implied 跳过守卫**（`emit_block_basic_rpn` /
  `emit_block_ops`）：void-callee CALL 且其输出消费者全为 RETURN 时不按
  implied 跳过（oracle IR 中该 CALL 无输出、必然作为语句打印）；非 RETURN
  消费者保持 legacy 内联行为，避免调用打印两次。

**验证**：curl/httpd E2E 输出 sha256 与改动前逐字节一致（守卫 dormant——
现语料 void 调用输出已被 action 层移除）；差分 3091/0/0 + 2278/0/0 维持；
单测 `test_void_callee_call_prints_statement_and_bare_return`（构造
"输出幸存 + locked void callspec"形态）+ 负向对照
`test_nonvoid_locked_callee_keeps_assignment_lhs`。同 commit 删除
prettyprint P13（`POSTFIX_PASS_NAMES` 24→23）。

## 2026-08-30：goto 自指标 `goto X; X:` 清除（BLOCKACTION-SCOPEBREAK-GOTOTYPE-0001 / GOTO-LABEL-UNPRINTED-0001）

任务假设"`goto X; X:` = scopeBreak goto_type 缺失"被双侧证伪：next_url 的
`#19 If IFGOTO target=#20 goto_type=1`（GOTO_GOTO）是 **oracle 正确答案**——该
goto 跨两层循环作用域，block.cc:2872/3082 只把目标==最内层循环 exit 的 goto 转
成 `f_break_goto`，golden 12.0.4 next_url 同样保留 `goto LAB_001050e7;`（标号在
两循环之后 31 行处）。双侧 fixture
`tests/oracle/blockstruct_scopebreak_gototype_1204.{cc,rs}`（MATCH）锁定该语义。

真实根因（gdb 断点 `emit_label_statement` 全程仅 2 次命中，均来自
`emit_goto_statement` 的 never-emitted 锚点）：

- **发现账本缺口**：`discovery_block_starts` 只在 `emit_block_ops` 入口
  （printc.rs:3512-3522）记录发现遍（NullEmit 主发射器）发射的 Basic/Copy 叶。
  顶层结构上下文里的叶（如 next_url 位于 DoWhile 之后的 goto 目标块 #20）走
  `emit_flow_basic` → `emit_block_basic_rpn`（4016），**无记录器** → 锚点
  （`emit_goto_statement`:12366-12368 `!discovery_block_starts.contains`）误判
  "目标永不发射"，把标签锚在 goto 现场——既产生 `goto X; X:` 相邻对，又把跳转
  解析到 fall-through（**语义错位**：next_url 的跳转本应跳出两层循环），还先占
  `printed_labels` 压制目标自身位置 arm-1（UNSTRUCTURED_TARG）标签。
- **flat 尾锚过宽**：`emit_block_basic_rpn`/`emit_block_ops` 尾部
  `targets_to_label` 扫描的 `goto_targets.contains(&target) || needs_anchor`
  第一析取项是 c23d4f52 时代（当时无 pending/backpatch 机制）的全量锚，同样在
  goto 现场锚 emitted 目标。oracle 对应行为：`emitBlockBasic`（printc.cc:2685）
  只在块自身头打印自己的标签（`emitLabelStatement(bb)`，cc:3198-3214），**从不**
  在转移源打印转移目标的标签。

修复（本文件两处 + 一处收窄）：

1. `emit_flow_basic` 头部加与 `emit_block_ops` 同款 discovery 记录器（同门
   discovery_pass + 主 NullEmit id + Basic/Copy 叶 + `flow_entry_address`），
   使账本覆盖两条叶发射路径——oracle 的对应不变量是 `BlockGraph::emit` 全量性
   （树上每个块经虚 dispatch 恰好发射一次），Ghidra 用树本身回答"目标是活块吗"，
   账本只是把该完备性镜像到 Rugra 的双路径上。
2. 两处尾扫描收窄为仅 `needs_anchor`（pending 且不在 `discovery_block_starts`）
   ——真被发射的目标标签回到其自身发射点（arm-1/arm-2/backpatch），只有从未发射
   的目标（上游结构器丢弃，见 GOTO-NEVEREMITTED-TARGET-UPSTREAM-0001）才在
   goto 现场锚定（有效 C 的 fall-through 解析，保留原防御）。

**验收**：curl 3095/0/0 三项零劣化（skeleton 总数逐字节不变），自指标
`goto X; X:` **22→3**；httpd 2231/3/0 零劣化，自指标 **13→1**；audit_syntax
通过数与基线逐项相同；cargo test --lib 失败集与基线完全相同（17 个预存
funcdata 项，`--test-threads=1` 双向比对 IDENTICAL）。剩余 4 处自指标为上游
结构残差（见 commit Differential 块）。

## 2026-08-29：INT_NEGATE 一元 token 序（GLOBWORD-C4-INTNOT-TOKEN-0001）

`dispatch_op_rpn` 一元臂（INT_NEGATE/BOOL_NEGATE/INT_2COMP/FLOAT_NEG 等）此前
`emit.tag_op("~")` **dispatch 时刻直发**，违反 Ghidra `PrintLanguage::opUnary`
（printlanguage.cc:566-573：`pushOp(tok,op)` + `pushVn(in(0),op,mods)`，零直接
输出）。unary_prefix token 必须进 revpol 栈，由下一次 pushOp/pushAtom 入口的
`emitOp(revpol.back())`（printlanguage.cc:143/171）在 `visited==0`（cc:338-342）
打印——即操作数首个 atom 之前。nodepend 是 LIFO drain：二元 op 的右操作数
`AND(ADD(load,0xfefefeff), NEGATE(load))` 中 NEGATE 在左子树排空后才 dispatch，
直发的 `~` 落在左操作数常量之后、父 op 的 stage-1 ` & ` 之前——产出非法 C 形态
`0xfefefeff~ & *puVar10`（oracle/golden 为 `... & ~*puVar10`，ghidra_curl_1204.c:1309）。

- `build_rpn_token_table` 追加 `bitwise_not`（`~`，printc.cc:29）与 `unary_minus`
  （`-`，printc.cc:31），unary_prefix/stage=1/prec 62，追加在 binary 块之后
  （索引 31/32，`RPN_TOK_BINARY_BASE=11` 与 negate-id 算术保持稳定）；
  新增字段 `rpn_tok_bitwise_not`/`rpn_tok_unary_minus`。
- 一元臂改为 `rpn_push_op(tok)`：INT_NEGATE→bitwise_not（printc.hh:297）、
  INT_2COMP/FLOAT_NEG→unary_minus（printc.hh:296/322）、BOOL_NEGATE→boolean_not
  （printc.cc:814-825 else 臂；negatetoken/checkPrintNegation 短路尚未移植，
  现为该函数最终 else 的恒打 token 行为）。FLOAT_ABS/SQRT/CEIL/FLOOR/ROUND 在
  Ghidra 为 opFunc（printc.hh:323-327），Rugra 无函数调用形，不推 token 只排
  操作数——与旧行为逐字节一致。
- 括号决策：unary(62) 嵌于 binary(如 `&`34) 下走 `34<62 → false` 免括号，
  `~*p` 与 golden `& ~*puVar4` 形态逐字一致。
- **验收**：curl E2E `[0-9a-f]~` 非法形态 2→**0**；getparameter.constprop.0 的
  两条语句变为 `*puVar10 + 0xfefefeff & ~*puVar10`（=golden token 序）；
  全量 skeleton 2911→**2905**、defects 1（预存 empty-else，与本改无关）、
  numbering 0；cargo test --lib 1627/17/5 与基线逐项相同。
- **双侧 fixture（PRINTC-INTNOT-TOKEN-0001，`tests/oracle/printc_intnot_token_1204.*`）**：
  C++ 侧驱动真 PrintC::emitExpression（printc.cc:2468）于无输出顶层 op（跳过赋值臂，
  纯 token 序），Rust 侧驱动其移植 `emit_expression_rpn`（本 commit 起为 pub，同
  `op_subpiece_rpn` 的 fixture 再暴露惯例）。5 case：AND(ADD(LOAD,c),NEGATE(LOAD))/
  NEGATE(c)/INT_2COMP(c)/OR(NEG,ADD)/ADD(c,NEG)，常量叶 uint4 定型、子表达式输出
  implied。Runner `tools/run_printc_intnot_token_oracle.sh` 输出 **MATCH**（6/6 记录
  逐字节一致，expected_stdout_sha256 锁定）。注意：Rust 侧 `Varnode.def` 为 Weak，
  fixture 的 def op Arc 必须 `_op*` 绑定保活，否则递归 implied 升级失败静默丢弃。

## 2026-08-28：字符常量 read-facing 类型与条件极性

RPN 常量叶现在用 consuming op 的精确 input slot 查询 High read-facing type，并以
`vartoken + ConstColor + op/vn` 构造 Atom；GetStr 的零常量因此沿通用 char 路径打印为
`'\0'`。`emitBlockIf` 不再读取 Rust-only `BlockIf.negated` 或设置文本层
`NEGATETOKEN`；极性已由结构化阶段真实修改条件对象。完整 PrintC 常量族、legacy
direct emit 和 markup 仍保持 `MISMATCH/UNTESTED`。

## 2026-08-28：BlockCopy 入口地址解析

PrintC 的 label discovery、pending-label backpatch、graph code start、
`emit_any_label` 与 BlockIf goto-target 路径现通过 `flow_entry_address` 取得入口：
先沿 `front_leaf` 到 `BlockCopy`，再经 `subBlock(0)` 读取原始 Basic 的地址。
这恢复了真实 `BlockCopy` 上线后的入口地址语义，不再依赖过去的 Basic stand-in。

完整 `FlowBlock::getEntryAddr`、真实 parent/next-flow、BlockGoto/MultiGoto 和
异常路径仍未等价，当前状态为 `MISMATCH/UNTESTED`；该 helper 不是完整 PrintC
函数行为 `MATCH` 证明。当入口解析失败时，部分现有路径仍以
`unwrap_or(0)` 生成零地址 sentinel；残差继续绑定
`GOTO-LABEL-UNPRINTED-0001` / `PRINTC-GOTOPRINTS-0001`。

## 2026-09-22：label/goto 寻址切换为 getEntryAddr（SB-HERITAGE50-BLOCKCOVER-0001）

`flow_entry_address` 末步与 `block::front_leaf_start_addr` 现在都解析到
`BlockBasic::get_entry_addr()`（block.cc:2291 端口，见 docs/api/block.md
2026-09-22 节），对齐 printc.cc:3170 `emitLabel` 的取址：**label 永远用目标
块的入口地址**，而不是最低 cover 范围（getStart）或分支常量。拼接块
（多范围 cover）上 label 与 getStart 可以不同；next_url 实测 label=
0x50e7 块在 heritage 插入 MULTIEQUAL@getStart=0x2534 到块头后，入口
地址随之变为 0x2534（首 op 落在 0x2534 范围）——与 oracle accessor
语义逐字一致。残差：goto 抑制（`code_block_starts` 白名单）与 label
打印（UNSTRUCTURED_TARG 臂）之间的不对称现在可见——被抑制 goto 的
marked leaf 会打出无引用 label（curl GetStr 37B2 / httpd 2CB68×2，
合法 C，defects=0），登记 `PRINTC-LABEL-WITHOUT-GOTO-0001`。

## 2026-08-28：结构化条件按 FlowBlock 类型分派（GETSTR-PRINTC-STRUCTCOND-0001）

`emitBlockIf` 的 condition 不再抽取/拼接条件文本，而是像 Ghidra
`PrintC::emitBlockIf`（`printc.cc:2878-2949`）一样，对同一个 condition
对象先在 `no_branch` 下虚分派一次，再在 `only_branch` 下分派一次；body
同样按其真实结构类型递归发射。配套实现了当前 Rust trait-object 需要的
dispatcher，并按 `emitBlockBasic`（`:2678-2744`）、`emitBlockLs`
（`:2781-2834`）和 `emitBlockCondition`（`:2836-2870`）恢复 non-flat
路径的 modifier、语句分隔、遍历顺序和条件括号协议。旧的打印期
`capture_block_condition`/De Morgan 文本重写不再承担这条路径。

锁定 12.0.4 bilateral fixture
`PRINTC-STRUCTURED-IF-CONDITION-0001` 覆盖 Basic condition、condition
本身为 BlockIf、BlockCondition 和 GetStr 形 BlockList 四种 non-flat、
zero-edge、`EmitNoMarkup` 图。双方输出均为 5 records / 9284 bytes，SHA-256
`1440f27ef73ffc13d2dfcf319576f8d4dd17102c6fcc9a25911cf4657f129758`，raw
diff 为空；重复发射、CALL/STORE/comment 顺序、modifier 恢复和树快照在该
投影内 `MATCH`。完整结构发射状态为 `MISMATCH`：独立复核已确认
Graph/MultiGoto 分派、带 condition prelude 的 pending-brace else-if，以及
FLAT+NOFALLTHRU tail 三类确定残差；有出边的 `nextInFlow`、markup、普通
else/if-goto、异常和其余结构子类型还未由该夹具覆盖。PrintC 继续保持 L2。

fresh GetStr 六阶段 runner 已恢复真实 `BlockCondition`：Ghidra 与 Rugra 的
`04_structure` 都只有一个 root child，Rugra 的目标行逐字为
`if ((param_1 != (char *)0x0) && (*param_1 != '\0')) {`，锁定 Ghidra 对应行为
`param_2`。runner 只把 `03_action_ir` 已证明同为 `register:48:8` 的 producer-local
标识投影成 `value_pointer`；双方原始行、op/Varnode ID 与空白全部保留，没有做
文本合并、正则替换或字面量归一化。短路结构与字符 token 因而是聚焦 `MATCH`。
完整 GetStr 仍为 overall `MISMATCH`：五个 stage 非零差异，Heritage 边界为
`NO_ORACLE`，参数恢复、签名、未知类型 identity、FSPEC/地址空间及完整
PrintC/markup 闭包继续绑定 metadata 中的 residual IDs。

## 2026-08-27：CALLIND 函数指针形渲染（PRINTC-CALLIND-PTR-0001）

`CPUI_CALLIND` 已与 `CPUI_CALL` 分离：按 Ghidra `PrintC::opCallind`
（`printc.cc:637-672`）输出 `(*(code *)<target>)(args)`，target 通过正常
Varnode 表达式发射，保留 GOT 槽的 `PTR_<name>_<addr>` 符号；直接 CALL 仍按
`opCall` 的 callspec 名称路径输出。RPN 与 legacy inline 两条路径均保持该分派。

验证：oracle `e40ed13014025f82488b1f8f7bca566894ac376b`，x86-64 BFD curl；
全量 defects=0、numbering=0、skeleton=2637。CALLIND 形态已变为函数指针调用，
但当前整体 audit 仍受既有 `_IO_FILE` 声明与其他上游残差影响，详见 Differential。

## 2026-08-27：CALLIND 实测结果

重建后 PLT 样例已输出 `(*(code *)PTR_00116e80)()`（带 GOT 名称时为
`PTR_<name>_<addr>`）。`audit_syntax.py` 维持 28 OK/95 FAIL；全量差分仍为
 defects=0、numbering=0、124/124，skeleton=2678。嵌套 CALLIND 的错误 `= PTR_...`
已消失，剩余 audit 失败主要是返回值调用形（如 `lVar1(*(code *)PTR_...)`）及上游
`_IO_FILE`/声明问题，已在 TODO 保留为后续审查项。

## 2026-08-27：隐含表达式与类型化常量发射（TRI2-UNNAMED-VN-IMPLIED / TRI2-CALLOUT-RESID-0002）

- RPN 的 `rpn_recurse`、`rpn_op_func`、`CPUI_PTRADD` 与 `CPUI_PIECE` 臂已按
  `printlanguage.cc:197-211, 514-540` 和 `printc.cc:880-893, 424-442`
  保持 implied 输入的逆序入栈与递归内联；当前 master 已包含该链，本次复核未重复实现。
- `push_varnode` 的 Const 分支不再依据可打印 ASCII 猜测字符形。对传播类型为
  `TYPE_INT/TYPE_UINT` 且非 `isCharPrint()` 的常量，直接走
  `integer_text`，对应 `pushVnExplicit` 提供 read-facing 类型后由
  `pushConstant` 在 `printc.cc:1744-1764` 的整数分派；因此
  `progressbarinit` 的 `0x4f` 不会误发为 `'O'`。真正的 char-print 类型仍保留字符转义路径。

**验证**：oracle `e40ed13014025f82488b1f8f7bca566894ac376b`，x86-64 BFD / locked curl
fixture；全量 `defects=0`、`numbering=0`，`progressbarinit` 目标常量 `0x4f`。

## 2026-08-26：RPN opCall 接通 + pretty-printer 挂接（PRINTC-LINEWRAP-0001）

- `rpn_op_call`（Ghidra: printc.cc:593 PrintC::opCall）：RPN 路径的
  CALL/CALLIND 渲染替换直写拼串——`pushOp(&function_call)`、fspec 名
  atom（functoken/funcname_color）、`count-1` 个 comma token、参数
  varnode 逆序 `pushVnImplied`（LIFO 排空正序出），count==0 推空
  blank atom（cc:635-636）。postsurround token 的
  `spaces(0,bump) openParen spaces(0,bump) … closeParen` 布局是
  pretty printer 在参数组周围折行缩进的来源。
- `PrintC::new` 尾部 `emit.set_comment_fill("   ")`：resetDefaultsPrintC
  → setCStyleComments → setCommentDelimeter("/* "," */")（printc.cc:1594/
  printlanguage.cc:96-110）的空格填充宽度，武装注释块内强制折行的填充。
- `doc_function` 尾部改为 oracle 时序 `closeBraceIndent → tagLine →
  endFunction → flush`（printc.cc:2662-2665）；typedef 前言包进
  `beginDocument…endDocument…flush`（docAllGlobals 形态，printc.cc:2621-2629）。
  **2026-09-26（HERMETICITY-TYPEDEF-LATCH-0001）**：前言从进程级闩锁
  （旧 `static TYPEDEFS_EMITTED`）降为 **per-document** 作用域——每次
  `doc_function` 调用（=一份完整文档）顶部无条件发射；oracle 依据见
  下方 GENSMOKE-T1 附注更新。
- 所有 `open_paren()/close_paren()` 调用点升级为带括号串与组 id 的
  trait 新签名（`open_paren("(")` / `close_paren(")", id)`），为
  `EmitPrettyPrint` 的 openGroup/closeGroup 配对提供 id。

**验证**：hugehelp 与 golden 逐字节一致（含三个 `puts(\n      "..."\n
      );` 折行），全量差分 defects=0/numbering=0。

## 2026-08-26：RPN 常量臂接通完整 pushConstant 分派（MAINDIFF-STRCONST-0001）

RPN 叶片 `make_atom_for_vn` 的常量路径此前走自创 `format_constant_value`
（小值十进制 / 大值 `0x..  /* dec */` 注释 / `-1` 特判），既不查类型也不查
StringManager。本次替换为 `constant_leaf_text`（`&mut self`，持 vn/op），完整
移植 `PrintC::pushConstant` 的 metatype 分派（printc.cc:1749-1815）：

- `TYPE_UINT`/`TYPE_INT`：`isCharPrint()` → `char_constant_text`
  （pushCharConstant cc:1606-1654），`isEnumType()` → `enum_constant_text`
  （pushEnumConstant cc:1666-1687 的 exact-member 切片），否则
  `integer_text`（cc:1288-1368，signed 求补、hex/dec 自然底判定）。
- `TYPE_UNKNOWN` → `integer_text`（cc:1766-1768 纯整型，**无符号查询**——
  queryFunction 门是 TYPE_PTR→TYPE_CODE 专属 cc:1786-1788，
  PRINTC-UNTYPEDCONST-CODEQUERY-0001）；`TYPE_BOOL` → `true/false`
  （pushBoolConstant cc:1488-1495）。
- `TYPE_PTR`/`TYPE_PTRREL`（cc:1775-1790）：`option_NULL && val==0` →
  `NULL` token；ptr-to charPrint → `ptr_char_constant_text`
  （`pushPtrCharConstant` cc:1698-1719 文本核：非零值、默认数据空间
  resolveConstant、全局 scope readonly、`print_character_constant` 引号串）；
  ptr-to CODE → `ptr_code_constant_text`（cc:1730-1742，默认代码空间 +
  `queryFunction` 符号名）；未命中落入 default cast
  （`default_cast_constant_text` cc:1806-1815，可选 `(type)` cast + force_hex
  整数）。
- `TYPE_VOID`（cc:1772-1774）：oracle 是 `clear(); throw LowlevelError`；
  Rugra 双路径统一降级为 `/* void constant */` 标记（发射路径不 panic，与
  直接发射臂同形）。`TYPE_FLOAT`（cc:1791-1793 → `push_float`
  cc:1380-1424）：**全量移植**（PRINTC-UNMAP-SINGLETON-0001）——
  `push_float_text` 双路径共享文本核：`get_float_format`（translate.cc:962-970
  默认 4/8 字节 IEEE 754 形态，其余尺寸 → cc:1385-1387 的 FLOAT_UNKNOWN
  sentinel）；`get_host_float` 分类（infinity/nan 的 extractSign 符号臂
  cc:1391-1402）；`print_decimal`（float.cc:427-459 的 %g/%e 往返精度环，
  float_emulate.rs 移植 + `calc_precision` cc:217-223 的
  decimalMin/MaxPrecision 字段）；`.0` 后缀臂（cc:1407-1419 首个 '.'/'e'
  扫描）；`force_scinote` mod 臂（cc:1404-1406）。双侧 fixture
  `printc_singleton_emission_1204`（21 float case 字节恒等）。
- 其余 metatype → default cast。

直接发射 helper（`push_integer`/`push_char_constant_fmt`/
`emit_default_cast_constant`/`push_ptr_char_constant`）改为文本核的薄包装，
两条路径（RPN 叶片与直接发射）输出同一形态；`format_constant_value` 连同
`/* dec */` 自创注释删除。`print_unicode` 的逃逸判定由
`!(0x20..=0x7e).contains` 纠正为 `printlanguage::unicode_needs_escape`
（printlanguage.cc:411-487：C0 控制 + 可打印 ASCII 内的 `\\` `"` `'`），修复
字符串字面量内引号不逃逸。E2E（curl 124 函数）：hugehelp 三个字符串字面量
与 golden 逐字节一致（2132/2105/2139 字节含截断标记），progressbarinit
`curl_getenv("COLUMNS")`、my_fwrite `fopen(..., "wb")` 折叠，
`/* dec */` 清零，defects=0 / numbering=0。

**源代码路径**: `src/printc.rs`

## 2026-08-25：`find_partial_field` 半开区间边界修复（type.cc:1580-1638）

`find_partial_field` 的字段包含判定由闭区间 `off + sz <= f.offset + f_size`
改为 Ghidra `TypeStruct::findTruncation`（经 `getFieldIter`，
type.cc:1580-1602）的语义：包含区间是半开的 `[offset, offset+size)`
（`curfield.offset <= off && curfield.offset + size > off`），外加跨度检查
`noff + sz <= size`。旧闭上界使 offset 恰落在字段起点且 `sz == 0` 时命中
**前一个**字段（PTRSUB(bar,0x10) 渲染成 `bar->prev` 而非 `bar->point`）。
这是 STOP/PTRSUB 接线（VARNODE-STOPUP-FLAGS-0001）在 E2E 验收中暴露的
移植缺陷：`( )bar` 空 cast（coreaction getInputCast 旧启发式，另修）消除
后字段名仍偏早一格。

`PrintC::doc_function` now follows locked Ghidra 12.0.4
`PrintC::docFunction` at `printc.cc:2641-2676`: it delegates the declaration
exactly once to `emitFunctionDeclaration`. The former production-only `main`
special case, arbitrary RAX-write return heuristic, and empty-prototype SysV
register rescan have been removed. Return type, ordered fixed parameters,
varargs and names now come solely from the finalized `FuncProto`.

This closes the text-selection slice of `PRINT-SIGNATURE-0001`. Scope-backed
parameter `Symbol` markup and the stripped-binary recovery that produces the
prototype remain separate residuals; the module remains L2.

**源代码路径**: `src/printc.rs`

## 文档状态

- **状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——默认 RPN 把 invisible root group 发成未闭合 `(`；多数 op 绕过 RPN，terminal mask 被忽略，`doc_function` 又重发顶层循环。当前 11.3.2 最终 C golden 只作回归诊断，不能证明 12.0.4 token/markup parity。详见 `CONTROL_OUTPUT_PIPELINES_2026-08-11.md`。
- **2026-08-23 修复（`PIPE-ORDER-EMPTYELSE-0001` 空 else defect——legacy
  发射路径补 `is_dead` guard）**:
  `emit_block_ops` 与 `is_block_body_empty` 此前不跳过已销毁（`DEAD` flag）的
  PcodeOp——只有 RPN 路径 `emit_block_basic_rpn` 有该 guard。Ghidra 的不变式
  是 `Funcdata::opDestroy`（funcdata_op.cc:203-222）立即把 op 从所属
  BlockBasic 的 op 列表摘除，且结构图 `BlockGraph::buildCopy`
  （block.cc:1925-1936）用 `BlockCopy` 包**原始**块而非克隆，所以 oracle
  从不会迭代到已销毁 op。Rugra 的 `build_copy`（blockaction.rs:98）把 op
  列表快照进克隆块，快照之后销毁的 op（flags 含 `DEAD`）滞留在结构节点里；
  fullloop 尾部 `ActionDeadCode`（coreaction.cc:5682 槽位）销毁的 op 即属
  此类。后果：else 臂块（仅含 dead INT_ADD + implied LOAD/COPY）被
  `is_block_body_empty` 判为非空 → 打印 `} else { }`（E2E 唯一 defect，
  getparameter.constprop.0）。修复：两个函数的 per-op 循环头部加
  `if op.is_dead() { continue; }`，与 `emit_block_basic_rpn` 的既有 guard
  一致——在可观测边界恢复 oracle 的块列表不变式。E2E（curl_1204 golden）：
  defects 1→0、numbering=0、skeleton 2452→2083（28 个函数全部只降不升，
  `__libc_csu_fini`/`main_free` 达 identical）。
- **2026-08-17 修复（`PRINTC-BINARY-RPN-0001` 二元 op 接入 RPN token 流）**:
  `dispatch_op_rpn` 的二元算术/比较/逻辑臂此前 `emit.tag_op(" + ")` 直发，
  括号决策全靠 legacy 侧 `child_needs_parens` 的**倒置教科书启发式**（左操作数
  等优先级永不加括号），与 Ghidra `PrintLanguage::parentheses`
  （printlanguage.cc:269-323，binary 分支 277-286：等优先级且非 associative 即
  `return true`）相悖——输出残留 3 处 `(bool)x == y + 0 - z < 0` 形态
  （ADD 嵌 SUB 左槽 / SUB 嵌 ADD 右槽等优先级无括号；`+ 0 -` 裸形态）。修复：
  - `optoken` 模块重写为**逐字段 OpToken 注册表** `BINARY_TOKENS`（20 项，
    printc.cc:36-55 逐字：multiply `*`54assoc / divide `/`54 / modulo `%`54 /
    binary_plus `+`50assoc / binary_minus `-`50 / shift_left `<<`46 /
    shift_right|shift_sright `>>`46×2 / less_than `<`42 / less_equal `<=`42 /
    greater_than `>`42 / greater_equal `>=`42 / equal `==`38 / not_equal `!=`38 /
    bitwise_and `&`34assoc / bitwise_xor `^`30assoc / bitwise_or `|`26assoc /
    boolean_and `&&`22 / boolean_xor `^^`20 / boolean_or `||`18；全部
    spacing=1 bump=0，negate 按 printc.cc:129-134 翻转对），`binary_token(opc)`
    按 printc.hh:283-318 虚拟 dispatch 表解析 opcode→token（INT_LESS/SLESS/
    FLOAT_LESS 同 less_than 实例、INT_ADD/FLOAT_ADD 同 binary_plus 实例等，
    以 token id 表达 Ghidra 的 OpToken 指针同一性）。**修正既有失配**：
    BOOL_XOR 原映射 `^`@30 → Ghidra 为 boolean_xor `^^`@20（printc.cc:54）。
  - `build_rpn_token_table` 追加这 20 个 token（索引 9..=28，negate 存翻转
    token 的表索引）；新增 `rpn_tok_binary(opc)`（printlanguage.cc:539-545
    negatetoken 翻转前奏 + printc.hh dispatch 映射）。
  - `dispatch_op_rpn` 二元臂：`rpn_push_op(tok)` 接管操作符发射（emitOp 在
    printlanguage.cc:332-337 以 spacing=1 打印 ` op `，与旧直发文本逐字节一致）；
    INT_ADD 结构体字段短路改走 pointer_member token 流
    （`pushOp(->66)+pushVn(base)+field atom`，opPtrsub printc.cc:476-484 形态）。
  - **2026-08-23 操作数全面接通 pushVn/nodepend**（`PRINTC-UNLINKED-REF-0001`
    printc 域残差修复）：二元臂操作数由 `make_atom_for_vn` 叶子原子改为
    `rpn_push_in`（in1-先-in0 后的 nodepend 记录，printlanguage.cc:551-552）；
    一元臂、STORE 的 addr/value、CALL 参数、RETURN 值、CBRANCH 条件、PTRSUB
    变址回退与 INT_ADD 字段短路 base 同步改造（直发文本的臂用
    `rpn_push_in`+`rpn_recurse` 队列化排出，保持文本位置不变）。`rpn_recurse`
    的 implied 分支由此对全部操作数位生效——implied 高变量在表达式位内联
    def 表达式（printlanguage.cc:526-536），替代 GLUE 兜底独立命名
    （`get_varnode_display_name_inner` 的 `uVar_<hex>`/`uVar20` fallback），
    使 prettyprint `backfill_missing_locals` 不再为这些名字注入声明。
    新增 `rpn_def_inline_reachable` 守卫（RUGRA-GLUE）：Ghidra 的
    `TypeOp::push` 虚 dispatch 覆盖全部 opcode，Rugra `dispatch_op_rpn`
    partial（PRINT-RPN-0001），对无发射臂/缺输入/已 dead 的 def op 回退
    叶子原子，防止操作数文本被静默丢弃（MULTIEQUAL/INDIRECT 在 Ghidra
    同样空发射，printc.hh:331-332，保守取叶子直到 dispatch 表补全）。
    前序"队列化实测 numbering 0→16 已回退"的失败不复现：E2E
    defects=0/numbering=0/Matched 116 全保持，Unique-GLUE 声明行 117→45，
    含 GLUE 名函数 12→8（消除 GetStr/_start/glob_url/progressbarinit）。
  - `child_needs_parens` 重写为 parentheses() binary 分支的忠实移植
    （277/278/281/286 逐行；等优先级非 assoc 双侧都加括号=Ghidra 保守风格
    `(a - b) - c`；同 token 且 assoc 才免括号=`a + (b + c)`）；
    `emit_inline_expr` 与 `op_binary` 的操作符文本改由注册表生成（print1+
    spacing，含 BOOL_XOR `^^` 修正）；`emit_condition` Case-1/Case-2 操作数经
    `push_input_parenthesized`（父上下文参与括号决策——3 处残差的实际发射
    路径，emit_structured_condition→capture_block_condition→emit_condition 链，
    实证 [DBG2] 捕获）；BOOL_AND/OR 递归两侧经 `condition_side_needs_parens`
    （&&/|| 非 assoc，等优先级组合子互相嵌套加括号）。删除死代码
    `c_binary_op_str`。
  - 单元测试 `test_child_needs_parens_precedence` 重写为 277/278/281/286 语义
    （含 `(x==y)<0` 案例判别、`(a+b)-c`、`a&&(b&&c)`、XOR@20 共 20 断言）。
  - **验收**：`+ 0 -` 裸形态 grep 3→**0**；`(==|!=) … (<|<=…)` 无括号邻接
    0；3 处原残差站点现形 `(bool)uVar_20b == (bool)uVar_10 + (0 - …) < 0`
    （`0 - X` 已括号化=278/286 决策；外层 EQUAL(38)⊃SLESS(42) 嵌套按
    printlanguage.cc:278 `38<42 → false` 正确免括号——IR 树 EQUAL 为外层，
    [DBG3]/[DBG4] def 链实证）；Matched 123 不降、defects 0、numbering 0、
    gcc 106 OK/17 FAIL（=门禁上限）；cargo test --lib 1412/5（5 失败=
    comment/dynamic/funcdata×2/ruleaction 预存集）。
- **2026-08-12 `PRINTC-0001` display-format wire 修复**: `display_format` 现与锁定
  Ghidra `database.hh:199-204` / `type.cc:728-762` 一致：`DEFAULT=0`、
  `HEX=1`、`DEC=2`、`OCT=3`、`BIN=4`、`CHAR=5`。此前 Rugra 把
  `CHAR/OCT/BIN` 编成 `3/4/5`，会把持久化或跨层传入的 3、4、5 分别误解释为
  char、octal、binary。`tools/run_printc_display_oracle.sh` 从锁定 commit
  `e40ed13014025f82488b1f8f7bca566894ac376b` 编译真实 C++ `PrintC::push_integer`
  并与 Rust 同 schema stdout 直接 diff；覆盖 wire 常量与字符串 codec 的合法域映射
  （不覆盖 `Encoder/Decoder` marshal round-trip），以及 `65/u8`
  的 `0101`、`0b01000001`、`'A'` 和 `0xff/i8` 的 `-01`、
  `-0b00000001`、`'\\xff'`，结果为零差异。metadata 记录 oracle、架构、
  compiler spec、analysis options、输入 SHA-256、双端 fixture SHA-256 与输出
  SHA-256。此 `MATCH` 仅证明 display wire、codec 合法域观测和“已解析 format u32”
  的 scalar dispatch；C++ 端通过 `Datatype → Varnode → HighVariable` 解析格式，
  Rust 简化 helper 则直接接收 u32，两端对象图、alias 与状态并非同输入。
  因此完整 `push_integer` 及 Datatype/Varnode alias 路径仍为
  **MISMATCH/UNTESTED**；codec 的未知名称/数值错误类型、消息与状态同样未测。
  Rugra API 尚未观察 Ghidra 的 `tag/vn/op`、
  Symbol-vs-Datatype 优先级、equate 早退、unsigned/long suffix、markup 及主管线
  接入，`PRINT-RPN-0001` 未关闭，模块保持 L2。
- **2026-07-22 修复（cross-review printc.cc:2583 calling-convention）**: `emit_function_declaration` 的调用约定分支此前被注释掉且文档错误声称 `option_convention` 默认 false（实际默认 true，printc.cc:1584）。现已：新增 `PrintC.option_convention` 字段（默认 true）+ 取消注释分支 + 在 FuncProto 新增 `is_model_unknown()`/`print_model_in_decl()`（fspec.hh:1394-1395）。对 unknown 模型（curl 场景）`print_model_in_decl` 返回 false，不发射约定 token，与 Ghidra golden 一致（0 个约定 token）。
- **2026-07-22 修复（cross-review mostNaturalBase）**: `emit_integer_value` 的进制选择此前用 `val > 0x1000` 粗糙阈值，现改为调用 `printlanguage::most_natural_base()`（printlanguage.cc:731-788 的 digit-frequency 启发式）。影响枚举值/常量的 hex/dec 显示。
- **2026-07-16 修复（P4 register-var 编号顺序）**: 新增 `preallocate_register_compact_names`：在 doc_variable_decls 前扫描所有 op，收集 Register 空间 auto-local 输出 varnode 的 raw 名 + def-op 地址，按 def-op 地址排序（Ghidra nameDedup 创建顺序的近似），预填 compact_rename。使寄存器变量编号按 def-op 地址序确定，而非 op 遍历首次触及序。栈变量路径已对齐（doc_variable_decls 按 scope.symbols 顺序）。numbering=485 不变（defects=0，编号是外观差异）。
- **2026-07-16 修复（P7-overflow_syntax）**: while-do 循环当条件块 isComplex 时（BlockWhileDo.overflow_syntax 标志，对齐 hasOverflowSyntax block.hh:692，由 try_rule_while_do 的 bl.is_complex() 设置，cc:1538），emit_structured_whiledo 发射 `while(true){ <cond body> if(cond) break; <body> }` 而非 `while(cond){ body }`（对齐 emitBlockWhileDo cc:3017-3044）。新增 BlockWhileDo.overflow_syntax 字段。
- **2026-07-16 修复（P5 for-loop header comma_separate）**: for 循环头 `for(init;cond;iter)` 发射现包裹 `push_mod/set_mod(COMMA_SEPARATE)/pop_mod`，对齐 Ghidra `emitForLoop`（printc.cc:2973-2990）为 init/cond/iter 片段激活 comma_separate。配合 P10 的 `doc_statement` 按 `!is_set(COMMA_SEPARATE)` 条件输出 `;`，避免 for 头片段重复分号。init/iter 文本仍在检测时烘焙（ActionStructureTransform），非从 raw PcodeOp 重发——这是 P5 剩余保真细节，但 latent（curl 语料 0 个 for 循环）。
- **2026-07-16 修复（P9 else-if 链化）**: `emit_structured_if` 的 else 分支现检测 else_body 是否为 BlockIf——若是，发射 `else if (...)`（无外层大括号）而非 `else { if (...) }`（对齐 Ghidra emitBlockIf printc.cc:2928-2935 的 pending_brace 路径）。Rugra 无 PendingBrace/Emit 回调机制，故直接检测 else_body type==If 并递归 emit_structured_if，产生 `else if(cond){body}`。mod-stack（P10）就绪，PENDING_BRACE 常量保留供未来完整 PendingBrace 回调模型。
- **2026-07-16 修复（P8 复合条件 + P10 mod-stack）**: P10: 新增 `print_mods` 模块（NO_BRANCH/ONLY_BRANCH/COMMA_SEPARATE/FLAT/PENDING_BRACE，printlanguage.hh:144-161）+ PrintC.mods/mod_stack 字段 + is_set/push_mod/pop_mod/set_mod/unset_mod 辅助（hh:284-290）。`doc_statement` 的 `;` 现按 `!is_set(COMMA_SEPARATE)` 条件输出（对齐 emitStatement printc.cc:2291）。是 P5（for 循环头）和 P9（else if pending_brace）的前置。P8: `emit_structured_condition` 对顶层 BlockCondition 现发射合并条件 `if (left && right) {}`（对齐 emitBlockCondition printc.cc:2836），此前把两个子块作为独立语句发射丢失 &&/||。capture_block_condition 递归处理嵌套 BlockCondition。
- **2026-07-16 修复（P7 InfLoop emit）**: 新增 `emit_structured_infloop`（对齐 Ghidra `emitBlockInfLoop` printc.cc:3097-3122），输出 `do { <body> } while(true);`。`BlockType::InfLoop` 分发到该函数。此前 InfLoop 落入 `_ =>` basic 回退，输出裸 op + 无条件分支。配合 B3 的 `BlockInfLoop` struct + `try_rule_inf_loop` 工厂。
- **2026-07-16 修复（P1 括号化 — 最高潜在缺陷风险）**: 实现 OpToken 优先级引擎与括号化，对齐 Ghidra `printlanguage.cc:269 parentheses` + `printc.cc:23-76` OpToken 静态实例表。此前 `op_binary`/`op_unary`/`emit_inline_expr` 直接拼 infix 串无括号化，嵌套表达式如 `a + (b << c)`、`a == (b && c)`、`a - (b - c)` 会语义错误。新增：`optoken` 模块（`binary_precedence`/`binary_associative` 表镜像 printc.cc 的 precedence/associative 字段）+ `child_needs_parens(parent, child, is_right)`（镜像 parentheses 的优先级比较）+ `push_input_parenthesized`（递归时按需包裹括号）。接入 `emit_inline_expr` 与 `op_binary` 两处二元路径。新增单元测试 `test_child_needs_parens_precedence` 覆盖 10 个教科书用例。curl 语料不触发嵌套二元内联故 numbering 不变，但正确性已保证。
- **2026-07-16 修复（label 格式）**: goto 标签从自创的 `LAB_{:08x}` 改为 Ghidra `emitLabel`（printc.cc:3164）格式 `code_r0xXXXX`。新增 `code_label(addr)` helper，镜像 Ghidra：prefix `code_`（joined_/dup_ 块状态未追踪）+ shortcut `'r'`（RAM space，translate.cc:529-533 space 名首字母小写）+ printRaw（space.cc:206-222，`0x` + 按 addr>>32/>>48 收缩的零填充 hex）。两处标签发射点（块入口 printc.rs:592 + push_goto_target printc.rs:1322）已更新。curl 语料无 unstructured goto 故 numbering 不变，但对有 goto 的二进制正确性已保证。
- **历史记录（2026-07-02，已被上方 2026-08-11 状态取代）**：printc 依赖 `emitted: HashSet<usize>`（key=Arc 指针身份）做去重，是 CFT 树遍历尚未完成的临时补丁。完整修复需按 `beginBlock/endBlock` 迁移到 Ghidra 的 `emitBlockGraph` 单次树遍历并删除 emitted/fresh-emitted 补丁；方法名存在不代表行为已覆盖。
- **2026-08-23 修复（GETSTR-ZERODIFF-D 域，类型感知常量 + (bool) 抑制）**: ① `make_atom_for_vn`/push_varnode Const 臂加 `typed_constant_literal`（PrintC::pushConstant printc.cc:1744-1810 移植）：指针类型 0 值 → `({type})0x0`（默认臂 cc:1805-1809，C 无 null token）；char 打印类型 → 字符字面量（cc:1750-1752 pushCharConstant），转义表忠实 printUnicode（printc.cc:1426-1466：\\0 \\a \\b \\t \\n \\v \\f \\r \\" \\' \\\\ + 通用 hex）。② ActionSetCasts castOutput 的 token==high 短路由 Arc::ptr_eq 改为 Datatype::type_equal 结构比较（Ghidra 用 TypeFactory interned 指针比较，cc:2544-2551；Rugra 无 intern，Base 型按 name+size+metatype 等价），base_type_for 补 Bool→"bool" 映射（原落 "long"）——消除 CBRANCH 条件上的伪 `(bool)` cast。
- **历史记录（2026-08-23，已由 2026-08-28 结构化极性实现取代）**: 当时曾以
  `demorgan_negate_text` 和 Rust-only `BlockIf.negated` 在打印期补偿复合条件。
  这不是当前实现，也不是可接受的 Ghidra 等价机制；两者现已删除。当前极性由
  `BlockList/BlockCondition/BlockCopy::negateCondition` 虚派发及完整 reciprocal
  edge-slot 交换在结构化阶段原地完成，`BLOCK-STRUCTURED-NEGATE-0001` 的 13-case
  scoped stdout 已与锁定 oracle 逐字节一致；完整 CollapseStructure 仍保持
  `MISMATCH/UNTESTED`。
- **2026-07-02 修复（R50+R51）**: `op_multiequal`/`op_indirect` 改为 no-op（对齐 Ghidra printc.hh:331,332 `{}`，消除非 C 的 `phi(...)`/`(indirect)` 语句）；`op_cbranch`/`emit_block_condition` 增加条件输出捕获——当 `emit_condition` 产出无效条件（空串、` == `、`!()` 等缺操作数的垃圾）时回退为 `1`（always-true），消除 `if () goto ;`/`if () {`/`if (!())` 语法错误。curl 的 6 处语法错误全部清零。
- **可信度**: 高
- **对应源码**: 当前 `rugra/src/printc.rs`
- **文档目标**: 说明 `PrintC` 在当前 Rugra 架构中的职责、输入依赖与输出边界
- **可信边界**: 本文档描述的是**当前 C-like 输出层的责任分工**，不是“已经达到 Ghidra 等价输出质量”的证明

---

## 模块定位

`printc.rs` 是 Rugra 当前输出层中的核心模块之一，负责把已经进入函数级分析上下文的内部表示，转换为**更接近 C 语言风格**的文本输出。

它在整体链路中的位置更接近：

```text
raw semantics / P-code-like IR
 -> Funcdata
 -> Action / Heritage / CFG-related processing
 -> PrintLanguage
 -> PrintC
 -> C-like pseudocode text
```

因此，`PrintC` 的职责不是：

- 解析二进制
- 直接做反汇编
- 替代 SSA / CFG / 类型恢复本身
- 单独证明最终输出已经与 Ghidra 1:1 一致

而是：

- 消费前序阶段已经建立的函数级语义信息
- 组织输出文本
- 尽量用 C 风格形式表达现有语义
- 在无法恢复高级语义时做**保守降级输出**

---

## 当前职责概述

结合当前工程结构，`PrintC` 的主要责任可以概括为以下几类：

### 1. C-like 文本发射
将内部分析结果发射为伪 C / C 风格文本，而不是继续停留在底层 IR 展示层。

### 2. 输出阶段的语言特化
`PrintLanguage` 更像输出语言抽象层，`PrintC` 则是其中面向 C 风格语法的具体实现。

### 3. 函数级输出组织
围绕单个函数组织输出，包括但不限于：

- 函数头部
- 语句序列
- 表达式文本
- 变量显示形式
- 基本控制流结构的文本布局

### 4. 保守表达
当某些高层语义尚未完全恢复时，`PrintC` 应优先保持语义可追踪，而不是伪装成完整源码。

### 5. Symbol 驱动的局部变量声明 (PRINTC-SYMBOL-DECL-0001)
声明完全由 Action 阶段建立的 `ScopeLocal` 符号表驱动，逐符号发射
（对齐 `PrintC::emitLocalVarDecls`/`emitScopeVarDecls`/`emitVarDecl`，
printc.cc:2260/2518/2497）：
- **快照**：`doc_function` 通过 `snapshot_local_scope` 克隆 `fd.scope`
  （ActionRestructureVarnode 构建、ActionNameVars 命名完成的 ScopeLocal）。
  打印期不重构、不重命名、不重编号；无 scope 则无声明（无兜底）。
- **遍历序**（emitScopeVarDecls cc:2535-2572）：先地址 map 后 dynamic
  列表。地址序 = 空间序（`local_maptable_space_rank` 复现 x86-64
  maptable 序 Unique<Register<Stack，`grouped.sort_by_key` 对齐
  database.cc:1952 的 maptable 空间索引序）× 每空间
  `std::list<SymbolEntry>` 的 **rangemap 插入拼接序**——MapIterator
  解引用的是 per-space `begin_list()` 列表（database.hh:379-401/
  database.cc:1889-1919），不是排序好的 AddrRange 多重集；列表序由
  `rangemap::insert`（rangemap.hh:221-277）决定：每条新记录拼接到
  键（细化片含端 `last`，EntrySubsort）>= 其整域键 `(b, subsort)` 的
  首个 AddrRange 属主之前，无则追加到表尾。由
  `scope_rangemap_list_order`（含 `scope_rangemap_unzip` 的细化片
  分裂）逐条重放；EntrySubsort 投影 = addrtied 取最小 `(0,0)`，
  否则 `(1, 首用偏移)`（database.cc:97-109 getSubsort，局部 scope
  的 uselimit 共享代码空间故 useindex 折叠为常数）。在该语义下，
  重叠条目按含端先后访问（EAX[0,4) 先于 RAX[0,8)），等域条目按
  subsort；外扩条目的分裂片可捕获后续小条目，使列表序**并非**纯
  `(end, subsort)` 排序——此形态由
  `test_scope_rangemap_list_order_enclosing_piece_capture` 固化。
  dynamic 按插入序。过滤器：piece 跳过（Rugra 模型无 piece）、
  category != no_category 跳过（cc:2541，参数类 0 在签名里声明）、
  空名跳过（cc:2542）；FunctionSymbol/LabSymbol 与多 entry 去重
  在 Rugra 模型中结构性不可达。
  **注意**：map 分支没有 `$$undef` 过滤（那是 cc:2529 类别分支独有的）
  ——`$$undef` 名的 no-category 符号会被原样声明；生产中
  assignDefaultNames 在 Action 期（coreaction.cc:2998）保证这类名字不会
  存活到打印。
- **拼写**：`emit_local_symbol_decl` = begin_var_decl + push_type_start
  （sym.dtype 逐字）+ display_name + push_type_end + end_var_decl；语句层
  再加 tagLine 与 `;`（cc:2510-2516）。notempty 时块尾一个 tagLine
  （cc:2277-2278）。
- **打印期 renumbering 已删除**：`compact_name_for`/`compact_rename`/
  `compact_base`/`scope_naming_base`/`preallocate_register_compact_names`/
  `declaration_order`/`used_scope_symbols` 全部移除——oracle 没有任何打印
  期重编号路径，命名权威在 Action 阶段（FUNCDATA-LINKSYMBOL-TYPED-0001
  的 ActionNameVars + 符号→high 桥）。
- **删除的 GLUE**：`doc_variable_decls_from_funcdata`（used_varnode_types
  的 xunknown8 类型 + 硬编码 is_declarable 白名单 + long/int 兜底）、
  打印期 `restructure_varnode` 兜底与二次 `assign_default_names`。
  `used_varnode_names`/`used_varnode_types` 仍由 `mark_variable_used`
  记录（doc_function 的 extern 全局扫描消费端已于 2026-08-25 移除，
  MAIN-DATPOOL-0001）。
- fixture：`tests/oracle/printc_symbol_decl_1204`（cover_rebuild，
  pinned base=b6b61d5，overlay 含 LINKSYMBOL 4 文件 + printc.rs），
  4 case（typed temporaries / in_RCX / dynamic 符号 / $$undef+类别跳过）
  双侧逐字节 MATCH。

### vn_type_if_meaningful（2026-06-28 增强）
如果 varnode 是 LOAD op 的输出，返回基于 size 的类型（int/long/byte）而非指针。

### mark_varnode_used LOAD 检测（2026-06-28 新增）
如果 varnode 是 LOAD op 的输出，type_name 用 size-based（int/long/byte）而非 vn.v_type 的指针类型。这让 LOAD 结果声明为 `int piVar92` 而非 `int * piVar92`，**消除了 reconcile_pointer_arith** 的需要。

### push_varnode Priority 1.4 — 权威 HighVariable def inline（2026-06-29 新增）
`push_varnode` 在 Priority 1（用 HighVariable 名字）之后、Priority 1.5（基于自造 map 的 def 查找）之前，新增基于权威 HighVariable 的 def inline：若当前 varnode 无可用 def（def 缺失或 def op 已 dead），但同 HighVariable 的兄弟实例（`high.get_type_representative()`）有可用 def，则 inline 那个 def 表达式。前提是 merge 已在 dead-code 之后运行（action.rs 管线顺序），`high.instances` 为权威存活集。这是用 SSA 权威 HighVariable 替代自造 map 的第一步，保守且安全（仅对"当前实例无 def"生效，不影响正常命名读取）。

### 移除硬编码 RSP/RBP 名（2026-06-29 续）
- `get_varnode_name` 和 `push_varnode` Priority 1/2 不再保留 `name != "RSP"/"RBP"` 例外。Raw register 名统一转为 size-based 局部变量名（对齐 Ghidra `buildVariableName` 默认分支，database.cc:2501-2504）。
- Priority 2 fallback 不再 `match(offset,size) → "RSP"/"RBP"`，统一用 size-based 前缀命名。
- RSP 泄漏 137→0，RBP 泄漏 18→0。

### lhs 不内联修复（2026-06-30）
- **根因**：`push_varnode` 的 Priority 2 Unique-space fallback 在 `is_lhs=true`（赋值左值）时仍从 `inline_candidates` 取出 def 表达式并调用 `emit_inline_expr`，导致无 HighVariable 的 Unique 输出 varnode 在左值处内联了它自身的 def → 产生 `(a + 8) = a + 8;` 自赋值（gcc `lvalue required as left operand of assignment`）。
- **修复**：Priority 2 Unique 分支加 `!self.is_lhs` 守卫（对齐 Ghidra `pushSymbolDetail`/`pushUnnamedLocation`：赋值目标永远解析为命名位置，`recurse()` 内联只发生在读取侧）。Priority 2 Register 分支此前已有该守卫，Unique 分支遗漏，现已一致。
- **效果**：curl gcc 审计 9/24 → 17/24。剩余 6 个失败为独立输出 bug（地址含嵌套 CALL、void 返回值赋值、类型推断 `int *` 误用于位运算），非 lhs-inlining。

### is_raw_register_name 识别 SSA 后缀（2026-07-03）
- **根因**：`is_raw_register_name` 只精确匹配 `"RAX"`，但 `Merge::assign_names`（merge.rs:560-574）为同名寄存器的不同 SSA 版本生成 `RAX_7`、`RDI_6`、`EAX_13` 这类带 `_<digit>` 后缀的 HighVariable 名。`is_raw_register_name("RAX_7")` 返回 false → 原始 SSA 寄存器名直接泄漏进 C 输出（curl 全量 177 处：RAX_65、EAX_29、EDX_40、…）。
- **修复**：`is_raw_register_name` 先剥掉尾部 `_<digits>` SSA 消歧后缀（`rsplit_once('_')` + 全数字尾校验），再查寄存器名集合。`RAX_7`→`RAX`、`RAX_71`→`RAX`、`R8B`/`uVar12` 不受影响。剥后缀后路由到既有的 raw-register → `<prefix>_<offset>:hex` → `compact_name_for` 重编号链，与无后缀的 `RAX` 走同一条路径（对齐 Ghidra `buildVariableName` 局部分支 database.cc:2501-2504 + `assignDefaultNames` database.cc:2862 的单一共享 base）。
- **效果**：curl 寄存器名泄漏 177→0；defect 函数 17/24→7/24（剩余 7 个全是 empty-else body-collapse，独立根因）。

### 诊断桩清理（2026-07-03 续）
- 移除 body-collapse 诊断期间临时加入的 `[DBG-DISPATCH]`/`[DBG-BASICIF]`/`[DBG-IFEMPTY]`/`[DBG-EMITOP]` eprintln 桩（违反临时 TAG 铁律）。诊断证据已落入 coreaction.md 的 ActionDeadCode CALL 保护条目（body-collapse 真根因之一是 DCE 杀 CALL，非 printc）。

### is_block_body_empty 对齐 emit_block_ops 跳过逻辑（2026-07-03 续 2）
- **根因**：`is_block_body_empty` 与 `emit_block_ops` 的 op-跳过逻辑不一致。前者对"末尾 op 是 CBRANCH/BRANCH/RETURN/CALL"的块一律判为非空（提前 return false），但末尾分支是控制流转移，不是 body 语句——Ghidra 在 `emitBlockIf`（printc.cc:2895）用 `setMod(no_branch)` 抑制它。结果：只含 dead 计算 op + 末尾 CBRANCH 的块被判为"非空"，但 `emit_block_ops` 实际什么也不输出 → 产生 `if (cond) {} else {}` 空括号（Ghidra 永不产生此形式）。同时 is_block_body_empty 未检查 `is_implied()` 输出（emit_block_ops:334-338 跳过这些），进一步放大分歧。
- **修复**：删除"末尾分支 → 非空"的提前 return；改为逐 op 扫描，精确镜像 `emit_block_ops` 的跳过集——CBRANCH/BRANCH/BRANCHIND/COPY/MULTIEQUAL/INDIRECT（emit_block_ops:315-323）、`is_implied()` 输出（emit_block_ops:334-338）、RIP-relative、stack-setup、inlined_ops、dead-output 纯计算 op。CALL/CALLIND 不在跳过集里，所以真正含 call 的 body 仍正确判为非空。
- **效果**：curl defect 12（5/24 函数）→ 0（0/24 函数）；curl+httpd 空 else{} 均为 0；main defect 7→0、glob_word 2→0、getparameter/next_url/match_url 各 1→0。剩余 numbering/expression 问题是独立根因。

### RPN 路径 dispatch_op_rpn：PTRSUB/CAST + 隐式内联（2026-07-27 新增）

- **背景**：RPN 发射路径（`dispatch_op_rpn` / `emit_expression_rpn` / `emit_block_basic_rpn`）此前只实现了 COPY、二元/一元算术、LOAD、STORE、CALL、RETURN、CBRANCH；PTRSUB 与 CAST 落入 `_ => {}` 兜底分支不发射任何文本。Ghidra 对应实现是 `PrintC::opPtrsub`（printc.cc:929-1143，结构体字段 `ptr->field`）与 `PrintC::opTypeCast`（printc.cc:448-464，`(type)x`）。
- **本改动（faithful port）**：
  - 扩展 `build_rpn_token_table`，新增 4 个 OpToken（字段逐项对齐 printc.cc:25/26/33/35）：`pointer_member`（`->`，binary prec 66 assoc）、`object_member`（`.`，binary prec 66 assoc）、`typecast`（`(`/`)` presurround prec 62）、`addressof`（`&` unary prefix prec 62）。
  - 在 `dispatch_op_rpn` 新增 `CPUI_PTRSUB` 分支：忠实移植 opPtrsub 的 struct/union（`[&]ptr->field`）、array（`*ptr`）与无类型回退（`ptr->field_0x<hex>` / `ptr[off]`）发射形态；Rugra 无 TypePointerRel，`ptrel` 分支塌缩为 `ct = ptype->getPtrTo()`（与 legacy `op_ptrsub` 一致）。
- 2026-08-25（B3-COREACTION-CONSTANTPTR-0001 段(b)）：RPN 路径补齐 TYPE_SPACEBASE 臂（printc.cc:1057-1097，此前 RPN 恒落 `field_0x` 回退）。symbol 经 in(1) high 的 linkSymbolReference 附件（namerec 残留未接，打印侧替代为同一 queryContainer 通道：global scope + 空 usepoint）；ARRAY symbol 按 cc:1062-1070 弃 `&`；`!valueon` 发 `&name`；无 symbol 走 `0x<hex>` 无名位置；arrayvalue 后置 `[0]`。hugehelp 六别名经此臂渲染 `&DAT_00107180/…99a8/…c1d8`（与 golden 逐字节一致）。
  - **R-RAWQUAR F3 登记（2026-08-25；①已于 2026-09-24 解锁，见文末 HTTPD-CODEREF-SYMBOLIZE-0001 节）**：该臂两分支缺口登记 TODO 并入 ALIGNMENT_ROADMAP printc 行——①`PRINTC-SPACEBASE-TYPECODE-0001`（printc.cc:1068-1069 `TYPE_CODE → valueon=true`：函数符号不打 `&`；已随 driver 函数符号 DB 的 CODE 条目接通）；②`PRINTC-SPACEBASE-PARTIALSYM-0001`（printc.cc:1084-1093 `symbolOffset≠0 → pushPartialSymbol`：mid-symbol 命中打子字段；容器查询 stand-in 无 symbol-offset 通道且 ConstantPtr 路径 off 恒 0，现管线不可达；解锁依赖 FUNCDATA-LINKSYMBOL 的 high→symbol 附着通道）。
  - 在 `dispatch_op_rpn` 新增 `CPUI_CAST` 分支：忠实移植 opTypeCast 的 array-decay `&in0` 短路与 `(type)in0` 主路径；`typecast` 是 presurround，RPN emit 机制自动产生 `(typename)operand`。
- **隐式内联打通**：为让 PTRSUB/CAST（消费时一定是 implied）真正进入 dispatch，引入 `rpn_push_in(op_arc, op, slot, m)`——忠实 `PrintLanguage::pushVn`（printlanguage.cc:197）的 nodepend 记录语义。`COPY`/`LOAD`/`PTRSUB`/`CAST` 的操作数改为走 `rpn_push_in`，由 `rpn_recurse`（printlanguage.cc:514）按 implied 标志决定内联 def 或推叶子 atom。此前各 dispatch 分支直接 `make_atom_for_vn + rpn_push_atom`，等价于只走 `pushVnExplicit` 叶子路径，导致所有 implied def（含 PTRSUB/CAST）永不被内联。**2026-08-23 扩展**：二元/一元算术、STORE、CALL、RETURN、CBRANCH、PTRSUB 变址回退与 INT_ADD 字段短路的全部操作数位同步接通（见上文 PRINTC-UNLINKED-REF-0001 节），implied 内联覆盖所有表达式位。
- **当前生效限制（诚实声明）**：`CPUI_PTRSUB`/`CPUI_CAST` op 目前在 curl/httpd 中**不被产生**——Rugra 缺少 `RulePtrsub`（INT_ADD→PTRSUB 的创建规则，ruleaction.cc，仅移植了 `RulePtrsubUndo`/`RulePtrsubCharConstant`/`RulePtraddUndo` 这类消费现有 op 的规则），且 `ActionSetCasts::castInput` 的 PTRADD/PTRSUB pointer-fit 检查与 castOutput 延后（coreaction.rs:2893-2897 注释），故 CAST 创建对 curl 当前类型推断结果不触发（`cast_standard_full` 返回 None）。本 PR 的 dispatch 分支已就位且经过 Ghidra 行逐行核对，待上述底层 infra 补齐后即生效。
- **效果（curl diff 门禁）**：skeleton diff 2880→2873（轻微改善，来自 implied 算术 def 现在内联），defects 0→0，numbering 0→0，1287/1287 单元测试通过。无回归。

### RPN 表达式层畸形发射修复：notPrinted 过滤 + ZEXT/SEXT/SUBPIECE dispatch + 真 recurse 路由（2026-08-17，PRINTC-CAST-EXPR-0001）

- **背景**：`result/curl_cur.c` 出现 1168+ 处 `= (uVar28;` / `* = uVar20)))) = 0x3489;` 形态的畸形行。根因（纯发射层，非上游 IR）：
  1. `emit_block_basic_rpn` 缺 Ghidra `notPrinted()` 过滤（printc.cc:2696；op.hh:182 = `marker|nonprinting|noreturn`）。MULTIEQUAL/INDIRECT 的 TypeOp ctor 带 `marker`（typeop.cc:1947/1988），Ghidra 因此从不把它们作为语句打印；Rugra 放行后，`emit_expression_rpn` 已 push assignment token + LHS atom，而 dispatch 落入 no-op（`opMultiequal` 本身就是空实现，printc.hh:331）→ 语句结束时 `revpol` 残留 `assignment(visited=1 < stage=2)` 不完整条目，泄漏进下一语句的 `rpn_emit_op`，在错误位置输出 ` = ` / `(` / `)`——即全部 `= (` 行与 `))))` 连串。
  2. `INT_ZEXT`/`INT_SEXT`/`SUBPIECE` 同样落 `_ => {}`（Ghidra 是 printc.cc:786/799/843 的 cast-or-opFunc 双臂）。
  3. `rpn_push_op`/`rpn_push_atom` wrapper 把 printlanguage.cc:132-133/165-166 的 `recurse()` 委托给 printlanguage.rs 的 no-op 自由函数（无 op arena）——mid-expression push 时 pending 输入被静默丢弃。
  4. `hidden` token 表字段与 printc.cc:23 不符（应为 stage=1/prec 70，便捷 ctor 写死 stage=2/prec 0——同样残留 incomplete 条目）。
- **本改动（faithful port）**：
  - `emit_block_basic_rpn` 增加 notPrinted 过滤：`is_marker() || (flags & NONPRINTING) || (flags & NORETURN)`（flags 由 `opcode_flags` 在 op 创建时正确初始化，已核实）。
  - `dispatch_op_rpn` 新增 `CPUI_INT_ZEXT`/`CPUI_INT_SEXT`/`CPUI_SUBPIECE` 三臂：`cast_strategy.is_zext_cast/is_sext_cast/is_subpiece_cast` 命中 → `rpn_op_type_cast`；否则 `rpn_op_func`（`getOperatorName` = `"ZEXT/SEXT/SUB" + insize + outsize`，typeop.cc:1122/1148/2127）。SUBPIECE 的 `doesSpecialPrinting` 字段抽取分支（printc.cc:846-871）**可达**：SPECIAL_PRINT addlflag（op.rs ↔ op.hh:208）由 RuleSubRight（ruleaction.cc:7257，主管线已注册）设置，`is_piece_structured`（datatype.rs:443）对 Struct/Union/Array 为真；但字段抽取体（printc.cc:853-868 的 pushPartialSymbol/findTruncation+object_member 两臂）为继承 MISSING，RPN 路径落到 isSubpieceCast → opTypeCast / opFunc（与 legacy `op_subpiece` 同样 fall-through，行为非回归），降级登记 `PRINTC-SUBPIECE-FIELDEXTRACT-0001`（2026-08-17 事后审计修正，原文"Rugra 均无、不可达"失实）。
  - token 表新增 `function_call`（`(`/`)` postsurround prec 66 bump 10，printc.cc:28）与 `comma`（binary prec 2 assoc，printc.cc:55）；`hidden` 改为表内直构聚合 `{ "", "", 1, 70, … }`（printc.cc:23）。
  - `rpn_op_func`/`rpn_op_hidden_func`/`rpn_op_type_cast`（自 CAST 臂重构共享）/`rpn_operator_name_ext` 四个 helper；`readOp` 线穿 dispatch（`emit_expression_rpn` 传 `None` = printc.cc:2493 的字面 0；`rpn_recurse` 传读 op = printlanguage.cc:532；`isExtensionCastImplied` 对 `readOp==null` 返回 false，与 cast.cc:257 一致）。
  - `rpn_push_op`/`rpn_push_atom` wrapper 先走真 `self.rpn_recurse()`（单一 `if (pending < nodepend.size()) recurse();` 语义不变），再进自由函数——Ghidra 的 recurse 是虚调用真实现，此前路由到 no-op 等于丢操作数。
- **效果（干净 worktree = HEAD a301036 + 仅本 printc.rs overlay）**：`= (` 计数 1262→6 且 6 处全为合法 C（cast 赋值 / `== (bool)` 比较），真畸形 0；`))))` 连串 0；ZEXT/SEXT 按 oracle 的 opFunc 形态发射（`ZEXT48(x)`/`SEXT18(bVar1)`）；差分 skeleton 4724→3300、defects 0→0、numbering 0→0；gcc 审计 103 OK/20 FAIL → 105 OK/18 FAIL（GetStr+hugehelp 修复，其余 18 与基线同错同位）；124/124 75 decompiled/0 panic/1 timeout=基线；cargo test --lib 1373/5 失败集逐名一致。
- **当前生效限制（诚实声明）**：二元算术仍走 `emit.tag_op(" + ")` 直发不经 RPN token（嵌套优先级括号缺失，3 处 `== … + 0 - … < 0` 形残差）——binary token 化为后继 TODO（PRINTC-BINARY-RPN-0001 建议）；`uVara0` 类名字 use-registered 但声明缺失为 varmap 域既有残差。

### PRINTC-CAST-EXPR-0001 事后审计窄面修复（2026-08-17，F1/F2/F3）

- **F1 证据失实修正**：上文 198 行 SUBPIECE 分支"不可达"表述已就地改为"可达、字段抽取体为继承 MISSING、已登记降级"（见上）。`src/printc.rs` SUBPIECE 臂注释同步修正，并登记 `PRINTC-SUBPIECE-FIELDEXTRACT-0001`（三个邻接继承缺口：pushPartialSymbol/findTruncation 字段抽取体缺失；`is_piece_structured` 只匹配 Struct|Union|Array，窄于 Ghidra `metatype<=TYPE_ARRAY`（type.hh:929-934，含 enum/partial）；`is_subpiece_cast` 缺 PartialStruct/PartialUnion 输入臂（cast.cc:413-418 vs type_system/cast.rs:85-87））。
- **F2 parentheses hiddenfunction 分支精确移植**（printlanguage.cc:309-319）：top 为 hidden 且 stage==0 且 revpol 长度>1 时，读 `revpol[size-2].tok`（前一个未完成 token）——非 binary 且非 unary_prefix → false；其 precedence 严格小于 op2 → false；相等保留括号（防相邻 token 被当作 associative）。Rugra 侧 `parentheses()` 增 `prev: Option<&OpToken>` 参数（None 编码 `revpol.size()<=1`），`rpn_push_op` 调用点从 revpol 倒数第二项构造。原实现硬编码 `return true` 且注释引用不存在的 `parentheses_in_stack`——已删除。curl 语料 hidden 路径 0 触发，E2E 输出逐字节不变（预期，见 Differential）。
- **F2 附带注释修正**：`build_rpn_token_table` hidden 项 "precedence 70 (looser than function_call's 66…)" → "tighter"（高 precedence=绑更紧；70>66 使父 function_call 走 `topToken->prec < op2->prec` 免括号），并补全 parent 侧由 hiddenfunction 分支经祖父 token 决定的表述。
- **F3 markup 对齐**：`rpn_op_func` name atom 由 `FuncnameColor + op_index=-1` 改为 `NoColor + op 锚`（printc.cc:428-431 "don't markup the name as a normal function call"，`pushAtom(Atom(nm,optoken,EmitMarkup::no_color,op))`）。纯 markup 变更，无文本输出影响（text emitter 忽略颜色与锚）。

### PRINTC-SUBPIECE-FIELDEXTRACT-0001 三缺口实现收口（2026-08-17）

- **缺口 (a) RPN `opSubpiece` 字段抽取体（printc.cc:846-871）**：`dispatch_op_rpn` 的 `CPUI_SUBPIECE` 臂补齐 oracle 两臂——
  - 臂 (a)（printc.cc:853-861）：`vn.is_explicit()` 且 high 带 Symbol 时走 `rpn_push_partial_symbol`（`PrintC::pushPartialSymbol` printc.cc:1947-2065 的 RPN 全量移植）：从 **symbol 的类型**（非 facing 类型）出发的 bottom-up walk（STRUCT→`find_truncation` 字段下降 + object_member 条目；ARRAY→`array_get_sub_entry` 元素下降 + subscript 条目；UNION→无缓存解析时 break；其他 metatype→allowCast 的 `is_subpiece_cast_endian` 截断 cast；全部失败→`unnamedField(off,sz)`=`_off_sz_` 合成条目，printlanguage.cc:719-727），发射顺序 = finalcast 前缀 + 条目 token 逆序 + 基符号 atom + 条目 atom 正序（printc.cc:2044-2064）。`suboff>0` 时 `byteOff += suboff`；`slot = needs_resolution ? 1 : 0`（人工 slot）。
  - 臂 (b)（printc.cc:862-868）：无符号/非 explicit vn 时 `find_truncation(byteOff, outSize)`（slot=1）返回 `offset==0` 的形式字段 → `pushOp(object_member) + pushVn + Atom(field.name, fieldtoken)`。
  - `byteOff` 来自 `compute_byte_offset_for_composite`（typeop.cc:2195-2207 的忠实移植，含 big-endian 臂 `vn.size - outsize - lsb`）。
  - token 表新增 `subscript`（`[`/`]` postsurround prec 66，printc.cc:27，index 9；binary 块基址 9→10）。
  - 新公开入口 `op_subpiece_rpn`（镜像 Ghidra public virtual `PrintC::opSubpiece` printc.hh:334）供 oracle fixture 做 op 级观测；`cast_strategy` 字段转 pub（镜像 `PrintLanguage::getCastStrategy` printlanguage.hh:449）。legacy 直发 `op_subpiece` 同步补两臂（经 `push_partial_symbol`/`find_truncation`），并修正其合成字段名 `.field_X_Y`→`._X_Y_`（unnamedField 格式）。
- **缺口 (b) `is_piece_structured` 宽度（type.hh:929）**：见 docs/api/type_system/datatype.md——匹配集扩为 {Struct, Union, Array, PartialStruct, PartialUnion}；oracle 实测证实 enum/partialenum 因 TypeEnum 构造器 metatype 归一化（type.hh:489-494）报告 TYPE_UINT/TYPE_INT，**不属于** piece-structured（"含 enum" 的直觉表述被真 oracle 输出纠正）。
- **缺口 (c) `is_subpiece_cast` PartialStruct/PartialUnion 输入臂（cast.cc:413-418）**：见 docs/api/type_system/cast.md；附带 enum 输入/输出映射（Ghidra TypeEnum 归一化后以 UINT/INT 通过白名单，cast.rs 既有先例 186/197 行同约定）。
- **fixture**：`tests/oracle/printc_subpiece_fieldextract_1204.{cc,rs,metadata.json}` + `tools/run_printc_subpiece_fieldextract_oracle.sh`——22 条记录（10 piece sweep + 8 cast sweep + armA.field=`S.hi`/armA.array=`A.arr[0]`/armA.synthetic=`Y._2_4_`/armB.field=`B.lo`）与锁定 12.0.4 oracle **逐字节一致**（runner 输出 `records=22 MATCH`）。C++ 侧为真 Funcdata 图（type-locked ScopeLocal 符号 + `opMarkSpecialPrint`）；Rust 侧经 `op_subpiece_rpn` 同图构造。
- **Differential（curl 语料）**：输出与改前逐字节不变（`diff result/curl_cur.c` 前后 0 行）——语料中无 RuleSubRight 置位且输入为 piece-structured 的 SUBPIECE，亦无 offset-0 的 enum/partial SUBPIECE cast；门禁 defects=0/numbering=0 维持。

### PRINTC-SUBPIECE-FIELDEXTRACT-0001 审计返工（2026-08-17，三处 MISMATCH 修正）

- **REWORK #1 STRUCT 臂 findResolve**：原实现 `needs_resolution && size==sz` 时无条件 break——错误。oracle 的 `TypeStruct::findResolve` 有 override（type.cc:1944-1951）：**无缓存**返回 `field[0].type`（≠ct → 不 break，继续 findTruncation 下降），**有缓存**返回 `ResolvedUnion::getDatatype()`，仅 `==ct` 才 break（printc.cc:1969-1971）。修正：`rpn_push_partial_symbol` 查 `union_resolutions` 快照（PrintC 新字段，doc_function 时从 `fd.union_map` 克隆——Rugra 的 PcodeOp/block 无 Funcdata 反向指针，快照等价于 Ghidra 经 `op->getParent()->getFuncdata()` 的查询），无缓存回退 `field[0].type`，`Arc::ptr_eq` 判等。真 oracle 验证：`armA.nested=N.in.x`（fixture_inner 单字段填满 → 真 TypeFactory::setFields 置 needs_resolution，type.cc:1569-1871）。
- **REWORK #2 PartialEnum 白名单**：`TypePartialEnum` 构造器（type.cc:2255-2262）委托 TypeEnum 归一化为 TYPE_UINT → Ghidra 三白名单全过；Rugra 侧 `is_subpiece_cast` 三处白名单（in/out/PTR→int 特例）补 `TypeMetatype::PartialEnum`。真 oracle 验证：`cast.int_partialenum_0=1` / `cast.partialenum_out_0=1`。
- **REWORK #3 allowCast 臂实参**：Ghidra printc.cc:859 传 `op->getOut()`（**输出** varnode）——2019 行 `outtype = vn->getHigh()->getType()` 读输出 high 类型，2020-2022 的 space 回退同源；原实现传输入 vn → outtype 落输入类型 → 白名单恒拒 → finalcast 死代码。修正：dispatch 臂 (a) 传输出 varnode；符号 atom 的 vn 锚点同步取输出。真 oracle 验证：`armA.allowcast=(uint2)C.lo`（输出 typed uint2 → `(uint2)` 前缀可达）。
- **同批**：legacy `push_partial_symbol` 补 loop-top TYPE_PTR 豁免（printc.cc:1962 `(!needsResolution || metatype==TYPE_PTR)`）；C++ fixture 的 COPY/SUBPIECE 插入真实基本块（`const_cast<BlockGraph&>(fd.getBasicBlocks()).newBlockBasic` + `opInsertEnd`）使 `findResolve` 的 `op->getParent()->getFuncdata()` 可达。
- **衍生登记**：`TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001`（Rugra `TypeFactory::set_fields` 不置单字段 needs_resolution，type.cc:1569-1871——铁律 1.5 基础设施缺口；fixture Rust 侧手动置 flag 规避并注释指向 TODO）。
- **fixture 重钉**：runner 22→**26 records**（+`armA.nested=N.in.x`、+`cast.int_partialenum_0=1`、+`cast.partialenum_out_0=1`、+`armA.allowcast=(uint2)C.lo`，cast sweep 8→10），双侧逐字节 MATCH；E2E 复跑零回归（diff 0 行），门禁 defects=0/numbering=0；metadata 登记修正（`needs_resolution_struct_break` UNTESTED→MATCH，`union_resolution_cache` → 读侧已接线/写侧 UNTESTED，`pipeline_needs_resolution_production` → MISSING 指向 TYPEFACTORY TODO）。

### TYPEUNION-CACHE-READSIDE-0001——UNION 臂 findTruncation 缓存读侧接线（2026-08-18）

- **UNION 臂补上缺失的 findTruncation 调用**（printc.cc:2001-2016）：原 `rpn_push_partial_symbol` 的 Union 臂直接做 `size==sz` break（把"无缓存 miss"当成了唯一行为）。oracle 的 union 臂先 `ct->findTruncation(off,sz,op,slot,newoff)`（printc.cc:2003）——`TypeUnion::findTruncation`（type.cc:2185-2199）是 (parent,op,slot) 解析缓存的**只读**消费方（"No new scoring is done"）：命中且 `fieldNum>=0` → `newoff = off - field.offset`、跨字段拒绝（严格 `>`）后下降字段（object_member 条目，2004-2014）；miss/null → `size==sz` break（2015-2016）→ 否则合成条目。修正后 Union 臂与 Ghidra 同序。
- **find_truncation (op,slot) 参数化**（docs/api/type_system/datatype.md 详述）：union/partial-union 的 ct 现在能通过 `union_resolutions` 快照命中缓存；RPN `opSubpiece` 两臂（dispatch 的 findTruncation 字段 atom 臂 slot=1 与 `rpn_push_partial_symbol`）与 legacy `op_subpiece` 均传入 `(Some(op), slot, Some(&self.union_resolutions))`。
- **新公开方法 `snapshot_union_resolutions(&mut self, fd)`**（RUGRA-GLUE）：从 doc_function 提取的快照入口（doc_function 仍是主管线唯一安装点），供 op 级 fixture（不经完整 doc_function 直接 `op_subpiece_rpn` 渲染单 op）安装同一 (parent,op,slot) 键控通道。Ghidra 无对应物：其类型层经 `op->getParent()->getFuncdata()` 直达活 Funcdata（type.cc:2189）。
- **fixture 26→31 records**：新增 5 条 union 读侧记录（`armB.unionhit=U.b`/`armA.unionhit=V.b`/`armA.unionmiss=W`/`armA.unionspan=X`/`armA.unionsynth=Z._0_2_`），C++ 侧经真 `Funcdata::setUnionField`（funcdata.cc:937）+ `ResolvedUnion(altUnion,1,types)`（unionresolve.cc:40）注入缓存（artificial slot 1），Rust 侧镜像经 `Funcdata::set_union_field` 写端口 + `snapshot_union_resolutions` 读通道。双侧逐字节 MATCH（runner `records=31 MATCH`）。
- **Differential（curl 语料）**：隔离归因验证零影响——同一工作树上仅回退本改动的两文件（datatype.rs/printc.rs）重跑 curl，输出 diff 0 行；主管线 `fd.union_map` 当前无可被 SUBPIECE (op,slot=1) 边命中的条目（unionresolve 生产方未接入主管线），miss 路径与改前行为逐字节一致。门禁 defects=0/numbering=0 维持。

### PRINTC-PTRCONST-DAT-SYMBOL-0001——pushPtrCharConstant/printCharacterConstant 去桩 + TYPE_SPACEBASE `&DAT_*` 臂 + M4/M5 卫生（2026-08-24）

- **`push_ptr_char_constant` 全量移植**（printc.cc:1698-1719，替换 `"<str>"` 桩）：`val==0` 拒绝（1701）→ 默认数据空间的 `resolveConstant`（1702-1707；消费 op 地址作 point，无 `AddrSpaceManager` 时走 translate.cc:637-641 默认路径）→ 全局 scope `isReadOnly`（1709-1710，经 `Scope::query_properties` 的 database.cc:1796-1801 等价：symbol-entry flags 优先、否则 flagbase 属性）→ `print_character_constant`（1713-1715）→ 常量色 atom 直发（1717）。printc.cc:1708 的 `isInvalid` 臂在 Rust 侧为空转（transitional spaceless `Address::new` 即解析后的数据空间形态，与 rule 侧消费方同键形；失配 resolver 无 Rust 表示，SPACE-0001 残余）。
- **`print_character_constant` 移植**（printc.cc:1534-1553）：共享 manager（`fd.arch.string_manager` 的 doc_function 快照，与 cpool/userops 同款 B4 共享模型）`get_string_data` 取 UTF8；空 → false（1542-1543）；`L` 前缀（1543-1545，charsize>1 非 opaque，`doEmitWideCharPrefix()==true`）；`escape_character_data`（printlanguage.cc:498-511 的 1:1 移植，charsize 固定 1、`getCodepoint` 前进、NUL/-1 停）逐 codepoint 走 `print_unicode`；`isTrunc` → `...\" /* TRUNCATED STRING LITERAL */`（1548-1549）。同批移植 `push_ptr_code_constant`（printc.cc:1730-1742：默认代码空间 + `addressToByte` + 全局 scope `queryFunction` + 显示名 atom）。
- **`push_constant_typed` Pointer 臂接通分派**（printc.cc:1775-1790）：签名扩为 `(val, ct, vn: Option<&Varnode>, op: Option<&PcodeOp>)`（对齐 `pushConstant` 的 vn/op 形态，point 语义必需）；`option_NULL && val==0` → `NULL`；ptr-to-`isCharPrint()` → `push_ptr_char_constant`；ptr-to-CODE → `push_ptr_code_constant`；否则 default cast。生产调用点接线（make_atom_for_vn/legacy 路径改道 + driver string_table 退役）属 D3，本片后 E2E curl 输出不变。
- **`op_ptrsub` TYPE_SPACEBASE 臂移植**（printc.cc:1057-1097，替换 `field_0x` 回退）：in(1) HighVariable symbol（`updateSymbol` 的 mapentry 回退等价，variable.cc:419-432）；array/code symbol 类型改写 valueon/arrayvalue（1062-1069）；`!valueon` 发 `&`（1071-1072）；symbol 引用 offset==0 → `push_symbol`（`&DAT_xxx`），否则 `push_partial_symbol`（allowCast=false，1092）；无 symbol → `TypeSpacebase::getAddress` + `push_unnamed_location`（1078-1082）；arrayvalue → 后置 `[0]`（1095-1096）。
- **`push_unnamed_location` 格式修正**（printc.cc:1938-1945 + space.cc:206-218）：`{space name}` + `0x` + `byteToAddress(offset,wordsize)` 的 `2*sz` 位零填充十六进制（8 字节空间高位为零时收窄到 4/6 字节宽度）——`ram0x00002100` 形态（原 `ram2100` 非 Ghidra 形态）。
- **M5**：legacy `push_partial_symbol` 补 allowCast/finalcast 臂（printc.cc:2018-2029：outtype=消费 vn 的 HighVariable 类型 + `cast_strategy.is_subpiece_cast_endian`，命中则 `(outtype)` 前缀于整条 entry 链前，2044-2047），签名增 `outtype/out_space_bigend/allow_cast` 三参；`op_subpiece` 调用点传 `allow_cast=true`（printc.cc:859）。陈旧注释（"Rugra has no isSubpieceCastEndian"/"SUBPIECE-style cast is a TODO hook"）随重写消除。**M4**（cast.cc:27 promoteSize 路由）**已收尾（2026-08-25，agent/cast-promotesize）**：`CastStrategyC` 补 `get_promote_size()` 访问器（cast.hh:57 保护字段 `promoteSize` 的 Rust 可见性胶水——Ghidra 侧消费者都是 strategy 成员函数直接读字段，Rugra 的 `is_extension_cast_implied` 落在 printc.rs 故需跨模块读取），`is_extension_cast_implied` 的 cast.cc:284 比较改经 `self.cast_strategy.get_promote_size()`，字面量 4 残余消除；访问器由 `type_system::cast::tests::test_get_promote_size_matches_constructor` 钉住，行为与所有锁定语料等价（x86/x64 int==4）。
- **快照字段**：`string_manager`/`symboltab`（doc_function 从 `fd.arch` 克隆，cpool/userops 同款）；`spaceman`（`glb->resolveConstant` 的 AddrSpaceManager，Architecture 尚无所有者 SPACE-0001——生产 None 走默认路径，fixture/driver 经 `set_space_manager` 注入）。
- **双侧 fixture**（`tests/oracle/printc_ptrconst_1204.*` + `tools/run_printc_ptrconst_oracle.sh`）：14 渲染记录 + 5 read 计数——合法 ASCII×2（正缓存零重读）、0xAD 非法×2（负缓存零重读，hugehelp 0x7180/0x99a8/0xc1d8 的 print 侧规则）、>2048 截断（2048 字符 + TRUNCATED 标记的 2098 字符记录逐字节一致）、非只读（manager 零查询）、null、子串、上下文分辨（0x40@0x5000/0x5008 经真 AddressResolver）、`&DAT_00002100` 与 `&ram0x00002100`。manager 为声明式 GhidraStringManager/Java 契约（与 stringmanager_core_1204 同款子类）；输出 sha256 `315a0901…3585` 双侧一致。

### PRINTC-UNLINKED-REF-FAMILY B1——未符号化 varnode 兜底地址源统一到 high 的 name representative（2026-08-25）

- **Ghidra 语义**（printlanguage.cc:238-262 `PrintLanguage::pushSymbolDetail`）：sym==null 唯一臂调 `pushUnnamedLocation(high->getNameRepresentative()->getAddr(), vn, op)`（:244）——兜底标签的地址是 **high 名字代表的地址**（`HighVariable::getNameRepresentative`，variable.cc:492-511，compareName 评分 variable.cc:456-488：namelock > unaffected > persist > input > addrtied > protoPartial > 非 internal 空间 > written > 更早 def），不是当前实例的 offset。`PrintC::pushUnnamedLocation`（printc.cc:1938-1945）打印该地址的空間名 + printRaw。推论：**一个 HighVariable 无论持有多少实例、在多少站点被打印，都只产生一个标签**。`emitExpression` 的两侧输出臂（printc.cc:2475/2482）与 `pushVnExplicit`（printlanguage.cc:229）都汇入该单一路径。
- **Rugra 缺陷**（A35 审计类 (a)②）：三条空间阶梯（`get_varnode_display_name_inner` 尾部、`make_atom_for_vn` RPN 原子 fallback、`push_varnode` Priority 2 阶梯）+ `emit_inline_expr` 的 `_ =>` 臂 + raw-register 名转换臂，全部以 `vn.get_offset()`（当前实例）为地址源——同一 high 的 N 个实例碎片化为 N 个 `uVar_<offset>` 标签（A35 §1 的 my_get_line/next_url/glob_word 交换标签即其 E2E 放大面）。
- **B1 修复**：新增 `PrintC::unnamed_location_offset(vn)`（单一地址源 helper，`// Ghidra: printlanguage.cc:238`）：有 high 且有实例 → `get_name_representative().get_offset()`；否则保守退回实例自身 offset（Ghidra 打印期不会遇到无 high 的显式 varnode，纯 Rugra 形态）。上述全部兜底标签臂改经该 helper 取地址；标签形式（`uVar_`/`uVar` + hex、`local_`/`param_stack_`、`vn_`、`DAT_`）**不变**（形式统一属切片 A）。Stack/Ram addrtied 臂经 helper 后观测等价（HighVariable 从不合并不同地址的两个 addrtied 实例，且 compareName 偏好 addrtied 成员 → 代表地址 == 实例地址），走 helper 仅为与 Ghidra 单一路径同构。
- **不改变 inline 判定键**：`inline_candidates`/`value_def_map`/`def_map` 仍按当前实例 `(space, offset)` 键控（内联决策是逐实例的），只有发射标签的地址源移到代表。
- **验收**（`tests/oracle/printc_unnamed_1204` + `tools/run_printc_unnamed_oracle.sh`，基线重钉到 9bdd5e3 + `src/printc.rs` overlay）：`multi_instance_unnamed` site=b 行从 `uVar_10000008`（第二实例自身 offset）塌缩为 `uVar_10000000`（代表地址，与 site=a 同标签）——registered 表第 31 行重钉，碎片化轴闭合；行 7/23/30/31 的 `uVar_` 形式差异与行 2/3 的 typechar 差异保留（分别属切片 A 与类型系统域）。Rust 侧回归 `test_unnamed_fallback_collapses_to_name_representative`（合并双实例 high → 双站点同标签；无 high 孤儿 → 退回实例 offset）。

### PRINTC-UNLINKED-REF-FAMILY A——兜底 token 形式统一到 `PrintC::pushUnnamedLocation`（2026-08-25）

- **Ghidra 语义**（printc.cc:1938-1945 `PrintC::pushUnnamedLocation`）：`s << addr.getSpace()->getName(); addr.printRaw(s);` 后推 var 色 atom——**空間名 + printRaw**，打印点无任何空间分支。`printRaw` 是虚分派：base `AddrSpace::printRaw`（space.cc:206-222）= `"0x"` + `byteToAddress(offset,wordsize)`（**除法**，space.hh:523-525：byte 单位→可寻址单位）的 `2*sz` 位零填充十六进制（`setw` 最小宽度不截断），`sz=getAddrSize()` 仅当 >4 时按 `offset>>32==0→4`、`else if offset>>48==0→6` 收窄，wordsize>1 且 `offset%wordsize!=0` 时后缀 `+cut`（十进制）；`ConstantSpace::printRaw`（space.cc:372-376）与 `OtherSpace::printRaw`（space.cc:410-414）覆盖为无填充 plain hex；`JoinSpace::printRaw`（space.cc:590-609）/`IopSpace::printRaw`（op.cc:41-54）按记录表解码（打印期显式 varnode 不可达，Rugra 平面枚举无对应 registry → 保守走 base 形式，注释已记降级与修复路径）。unique 空间 addrsize=4（UniqueSpace::SIZE，space.cc:418）→ `unique0x10000000`；ram addrsize=8 高位零收窄 → `ram0x00023e00`。
- **Rugra 缺陷**（A35 审计类 (a)①③）：三条阶梯形式互不一致且全非 oracle 形式——`get_varnode_display_name_inner` 尾部（Register→`uVar<hex>`/Stack→`local_`|`param_stack_`/Unique→`uVar_<hex>`）、`make_atom_for_vn` RPN fallback（Register→`uVar<hex>`/else→`vn_<hex>`）、`push_varnode` Priority 2（Register→`<prefix>_<hex>` var_prefix 名/Stack/Ram→`DAT_<08hex>`/else→`v_<size>_<hex>`）+ `emit_inline_expr` 的 `_` 臂（`uVar_<hex>`）。Register 阶梯 `uVar{:x}` 直接吞 raw 负 offset（E2E `uVarffffffffffffff70`×3，result/curl_cur.c:1233/1323/1396）。
- **A 修复**：新增 `PrintC::addr_space_print_raw(space, offset)`（`// Ghidra: space.cc:206`，虚分派等价：Const/Other→plain hex，其余 base 形式含收窄/除法 byteToAddress/`+cut`）与 `PrintC::unnamed_location_token(space, offset)`（`// Ghidra: printc.cc:1938`，token 构造半部 = 空間名+printRaw）；三条阶梯 + `_` 臂的全部标签形式改走该单一 helper（param_names 前置检查与 inline-candidacy 守卫保留，inline 键仍按当前实例——B1 约定不变）；`push_varnode` Priority 2 Register 臂的 `var_prefix` 形式退役（Ghidra 打印期无 buildVariableName 路径——那是 symbol 命名域）。既有 `pub fn push_unnamed_location`（printc_symbol_decl 期移植）改为委托 token builder，并修正其 `byteToAddress` 方向 bug（原 `offset * wordsize` 是 `addressToByte`；x86-64 全 wordsize=1 故不可见，潜在 wordsize>1 分歧消除）。
- **验收**（同 fixture，runner 重钉 slice C+B1+A）：行 7/23/30/31 翻为双侧逐字节一致（`unique0x10000000 = 5/7/5/6;`）——registered 表 6→2 行（仅 typechar 行 2/3，类型系统域）；`multi_instance` site=a/b 同标签（B1 地址源 + A 形式）；Rust 单测断言更新 `uVar_10000000`→`unique0x10000000`。E2E 方向（root 全量收口）：残余 `uVar_*` 兜底族整体变形为 `unique0x…`（golden 0 兜底，仍为差异但已是 oracle 兜底形式；真值闭合属 B2 符号化到达）；`local_`/`param_stack_`→`stack0x…`、`DAT_<08hex>`→`ram0x…`、Register 阶梯负 offset 产物→`register0xffffffffffffff…` 形。

### PRINTC-IFGOTO-EMIT——emitBlockIf 的 goto 分支移植（emit_structured_if goto_target 臂 + goto-cascade 顺序回退臂）（2026-08-25）

- **Ghidra 语义**（printc.cc:2878-2949 `PrintC::emitBlockIf`，goto 分支 cc:2894-2916）：`pushMod(); setMod(no_branch); condBlock->emit(); popMod()`（cc:2894-2898）先发射条件块的**非分支语句**；`emitCommentBlockTree(condBlock)`；然后 cc:2905 `tagLine()`（else-if 的 pendingBrace 合并 cc:2900-2903 属父链职责）；cc:2907-2913 `tagOp(KEYWORD_IF)` + `spaces(1)` + `pushMod(); setMod(only_branch); condBlock->emit()`（走 `emitBlockBasic` 的 only_branch 臂 → `opCbranch` 打印条件表达式）；cc:2914-2916 `spaces(1) + emitGotoStatement(condBlock, bl->getGotoTarget(), bl->getGotoType())`。`emitGotoStatement`（printc.cc:2303-2322）= `beginStatement(bl->lastOp())` → keyword（f_break_goto→`break` / f_continue_goto→`continue` / f_goto_goto→`goto` + `emitLabel(exp_bl)`）→ `SEMICOLON` → `endStatement`——**函数体自身无 tagLine**，唯一行断点在调用点（emitBlockGoto cc:2775 的 tagLine；emitBlockIf 的 goto 臂是行中 `if (cond) ` 之后）。
- **Rugra 缺陷**（F1 47 处 discarded conditions 的 emit 侧形态之一）：`emit_structured_if` 的 `goto_target.is_some()` 臂以 `emit_block_ops(&condition, false)`（no_branch **未激活**）发射条件块——终端 CBRANCH 走到 `doc_statement` 被捕获成一条裸 `(cond);` 语句（多数被 produced-empty 过滤吞掉，即"条件被丢弃"），从不打印 `if`/`goto`，直接 return——结构化期 `try_rule_if_goto`（blockaction.rs，newBlockIfGoto cc:1799-1816）建出的每个 if-goto 包装在发射侧全部作废。goto-cascade 顺序回退臂（GOTO_EDGE_1 干跑检测命中后的顺序发射）同样以 `emit_block_ops(&condition, false)` 泄漏 CBRANCH。
- **修复**：goto_target 臂改为 ①`emit_block_ops(&condition, true)`（= cc:2894-2898 setMod(no_branch)；Rugra 的 skip_terminal 布尔是 no_branch 的传输载体）→ ②`tag_line(0)`（cc:2905）→ ③`if (` + `emit_block_condition(&condition)` + `)`（cc:2907-2913 的 only_branch 条件发射，`emit_block_condition_rpn` 已是 opCbranch pushVn(in(1))+recurse 的移植）→ ④`print(" ")` + `emit_goto_statement(target_addr, bt)`（cc:2914-2916）。goto_type 映射（block.hh:89-91 f_goto_goto/f_break_goto/f_continue_goto → op::branch_type）与 `emit_block_goto` 一致；Ghidra 直接把 `bl->getGotoType()` 透传给 emitGotoStatement，**从不改写 CBRANCH op**（旧实现的 branch_type 改写 hack 已删）。target_addr = `goto_target` 块的 `get_start_addr()`（结构块递归到首个 Basic 的 initial_range/start_addr，与 emitLabel 的 `getFrontLeaf→getEntryAddr`、UNSTRUCTURED_TARG 标记、`emit_any_label_statement` 同源）。顺序回退臂同型改造（目标/类型取自条件块自身 CBRANCH 的 in(0) offset + branch_type，flat-mode opCbranch 尾 printc.cc:574-579 的投影，经新增 helper `cbranch_goto_info`），随后仍发射 if_body。`emit_goto_statement` 移除函数内 `tag_line(0)`（cc:2303-2322 无 tagLine；调用点语义：emit_block_goto 自带 tag_line，if-goto 臂是行中——两处均忠实）。
- **验收**：curl E2E（HEAD `e17b4295` 干净树对照同构 fast-release 构建）：HEAD 输出 **0 个 goto**（16 处裸 `(cond);`/条件丢弃形态）→ 修复后 **22 个 `if (cond) goto <label>;`**（golden 61；缺口=flat opCbranch 完整移植（stash `flatcbr-prev-agent-diff` 中的 FLAT mod + op_cbranch_rpn 全臂，未含本轮）与结构化覆盖域）；skeleton 2927→2923、defects 0→0、numbering 1→1（唯一 match_url numbering 为既有存量，与本改动无关）；多次重跑输出字节一致（一次 main TIMEOUT 为 10s 上限的负载抖动，复跑恢复）。逐行 diff 确认全部变化均为裸条件语句 → if-goto 形态（含 2 处复合条件 `(A) || (B)` 合并恢复：match_url 与 my_get_token 的两条独立条件语句合并回单条复合 if-goto）。样本：`(piVar37 != 0);` → `if (piVar37 != 0) goto code_r0x00002728;`（result/curl_cur.c main）。
- **表示层残差**（如实登记）：①`if (` 文本直接 print（无 tagOp markup——Rugra EmitNoMarkup 无 markup 通道，文本等价）；②空体/畸形条件仍走 R50 `1` 回退；③goto 目标 label 与 golden 的 `LAB_` 符号名差异属 varmap 符号化域（golden 经 ScopeLocal queryCodeLabel，Rugra 的 `code_label` 已是 emitLabel 兜底形式 cc:3183-3192 的移植）；④golden 的 `file2string`/`parseconfig` 全体 goto 形态还依赖 flat 模式与结构化覆盖的后续 wave。

### PRINTC-PENDINGBRACE-IDENTITY——emit_structured_if 的 PendingBrace 身份门（SQATTR-PENDINGBRACE-IDENTITY-0001，2026-09-26）

- **Ghidra 语义**（printc.cc:2882-2949 `PrintC::emitBlockIf`）：`PendingBrace pendingBrace(option_brace_ifelse)` 是**本帧栈对象**（printc.hh:347-361，`indentId` ctor=-1，callback=cc:2872-2876 `openBraceIndent` 置位）；`isSet(pending_brace)` 时 `emit->setPendingPrint(&pendingBrace)`（cc:2884-2885）装槽；cc:2900 `hasPendingPrint(&pendingBrace)` **指针身份**判定——真则 `cancelPendingPrint()+spaces(1)`（else-if 合并），假则 `tagLine()`（brace 已中途触发或未安装）；cc:2946-2948 `pendingBrace.getIndentId() >= 0` 时**只有 owner 帧**补 `closeBraceIndent`。goto 臂（cc:2914-2917）**无 cancel**——cc:2900-2905 已保证本帧槽必先解决（触发即清槽 hh:1129-1137 / 取消即清槽 hh:451），不存在槽悬挂。
- **Rugra 缺陷**：旧实现的 `installed_pending_brace=继承 mod 旗标` + emitter 级全局 `pending_brace_fired` 粘性布尔（无人复位）→ 嵌套 else-if 子帧触发后，父帧尾部 `installed && fired()` 读到子帧残火多发一次 `close_brace_indent` → startIndent/stopIndent 21/22 失衡 → 尾部多余 `}` 弹空 indentstack → prettyprint.rs:3946 相对断行 unwrap panic（sq 609/620 + sqlite3 27 索引族；PFLUSH 车道逐 token 台账+双关闭签名仪器独立复钉，与 SQATTR FWDLOG/MiniOppen 归因收敛）。goto 臂多余的 `cancel_pending_print`（oracle 无）在全局槽时代是防悬挂补丁，身份化后按 oracle 删除。
- **修复**：install 持帧内 `Option<BraceId>`（`set_pending_brace` 返回新铸 id，oracle 栈对象身份的 Rust 化身）；cc:2900 合并门 → `has_pending_print_id(id)`；goto 臂/尾部关 → `pending_brace_fired_id(id)` + 删 cancel。emit 层状态模型详见 docs/api/prettyprint.md「SQATTR-PENDINGBRACE-IDENTITY-0001」节。
- **验收**：sq 609/620 rc=0、defects=0/numbering=0（残差=unaff 既有族 3 行）；sqlite3 27 panic 索引全清 0/0；五面 A/B 字节恒等（canon curl 267/0/0+httpd 285/0/0、镜面 curl 78/httpd 208/vsh 15 修复前后同数——非 panic 语料行为等价）；bank 391/391；gcc 审计 104/20、15/14 == 常驻基线。

---

## 设计边界

为了避免误解，下面明确 `PrintC` 的输入边界与输出边界。

### 输入依赖

`PrintC` 的有效工作依赖于前序阶段已经提供的内容，例如：

- `Funcdata`
- `PcodeOp` / `Varnode` 图关系
- 基本块与控制流信息
- 已恢复的部分变量语义
- 已恢复的部分类型信息
- 已知函数原型或调用信息
- 输出发射器（`Emit`）

如果这些输入不完整，`PrintC` 的输出质量也会受到限制。

### 输出产物

`PrintC` 的直接产物是：

- C 风格文本
- 近似伪代码
- 可读性优于裸 IR 的结构化输出

### 不应承担的责任

`PrintC` 不应自行承担以下职责：

- 推断不存在的高级类型事实
- 伪造不存在的变量来源
- 重写底层地址事实以迎合文本美观
- 单独决定 SSA / CFG 正确性
- 将“未恢复”伪装为“已恢复”

---

## 与其他模块的关系

### 与 `printlanguage.rs` 的关系
`PrintLanguage` 是更上层或更抽象的输出语言接口层；`PrintC` 是当前面向 C 风格输出的具体实现。

可以把两者理解为：

- `PrintLanguage
`: “如何组织一种输出语言”
- `PrintC`: “如何把当前语义尽量写成 C 风格”

### 与 `funcdata.rs` 的关系
`Funcdata` 是单函数分析上下文；`PrintC` 主要消费其中的结果，不负责替代 `Funcdata` 的建立过程。

### 与 `heritage.rs` / `action.rs` / `block.rs` 的关系
这些模块决定分析形态、图结构和中间语义稳定度；`PrintC` 建立在它们之上做展示，不应反向篡改核心事实。

### 与类型系统的关系
`PrintC` 可以利用已有类型信息改善输出，但不应把不可靠的类型猜测包装成确定类型结论。

---

## 导出的公共 API

## `pub struct PrintC`

### 作用
`PrintC` 是当前 Rugra 中面向 C 风格输出的打印器。

它对应的核心角色是：

- 管理 C 风格文本发射过程
- 驱动底层发射器写入缓冲内容
- 将函数级语义组织为更接近 C 的输出形式

### 当前职责理解
从当前架构角度，`PrintC` 更像：

- **输出层实现者**
- **文本结构组织者**
- **语义到 C-like 文本的映射器**

而不是：

- 独立分析器
- 独立 CFG 恢复器
- 独立类型恢复器
- 最终正确性证明器

---

## `pub fn new(emit: Box<dyn Emit>) -> Self`

### 作用
创建一个新的 `PrintC` 实例，并绑定一个输出发射器。

### 参数

- `emit`: 一个实现了 `Emit` 的发射器对象，用于接收 `PrintC` 最终产生的文本输出

### 使用语义
这个构造函数体现了当前输出层的一个关键设计点：

> `PrintC` 不直接把结果固定写到某个全局目标，而是通过可替换的 emitter 发射输出。

这意味着调用方可以：

- 把输出写入内存缓冲
- 收集输出文本
- 走无标记输出路径
- 以后扩展为其他输出后端

### 边界说明
`new()` 只是构造输出器，不代表：

- 当前函数已经可打印
- 所有语义都已恢复
- 最终输出质量已可接受

---

## `pub fn take_emit(self) -> Box<dyn Emit>`

### 作用
取回 `PrintC` 内部持有的发射器，同时消费当前打印器实例。

### 使用场景
该接口适合以下场景：

- 调用方在输出完成后，取回底层 emitter
- 从 emitter 中提取最终缓冲内容
- 将输出结果转成字符串或其他可消费形式
- 进行测试断言或结果归档

### 设计意义
这个接口说明 `PrintC` 的当前实现并不是直接返回一个“最终字符串”的最简单封装，而是通过 emitter 把输出过程与输出载体解耦。

这对当前 Rugra 很重要，因为它允许：

- 输出层与缓冲实现分离
- 更方便做测试和调试
- 后续兼容不同风格的输出后端

### 注意事项
调用 `take_emit()` 后，原 `PrintC` 实例被消费，不能继续使用。

---

## 当前实现应如何理解

从整个工程现状出发，当前 `PrintC` 的合理定位应该是：

> 一个正在持续演进中的 C-like 输出器，它已经承担 Rugra 输出链路中的关键角色，但它的最终表现高度依赖前序分析阶段的质量，不能单独被当作“完整反编译器输出质量”的证明。

换句话说：

- `PrintC` 存在且重要
- `PrintC` 是当前输出层主干之一
- `PrintC` 能表达 C 风格结果
- 但 `PrintC` 的存在不等于：
 - 输出已接近真实源码
 - 所有控制流都已结构化
 - 所有变量都已正确恢复
 - 与 Ghidra 输出已经一致

---

## 当前输出层的可信表述

后续文档中，关于 `PrintC` 建议使用以下表述。

### 推荐表述

- `PrintC` 是当前 Rugra 的 C 风格输出实现
- `PrintC` 负责把已有函数语义组织成可读文本
- `PrintC` 建立在 `Funcdata` 和前序分析结果之上
- `PrintC` 的输出质量依赖前序恢复结果
- `PrintC` 在无法恢复高级语义时应允许保守降级

### 不推荐表述

- `PrintC` 已生成与 Ghidra 完全一致的 C 输出
- `PrintC` 已经完整恢复所有高级控制流结构
- `PrintC` 可以单独代表端到端反编译质量
- `PrintC` 的存在证明 Rugra 已是完整成熟反编译产品

---

## 调用方应承担的责任

调用 `PrintC` 的上游代码，应尽量保证：

1. 已准备好待输出的函数上下文
2. 关键 IR 结构未损坏
3. 基本控制流和语义信息已进入可打印状态
4. 发射器的生命周期和结果提取方式已明确

否则，即使 `PrintC` 本身工作正常，最终文本仍可能：

- 很低层
- 不够结构化
- 命名贫弱
- 类型缺失
- 与理想 C 风格结果相差较大

---

## 维护建议

后续若继续维护 `printc.rs` 相关文档，建议重点同步以下信息：

- 是否新增了公开方法
- 是否改变了 emitter 交互方式
- 是否新增了函数级打印入口
- 是否改变了 C-like 输出的组织策略
- 是否引入了新的结构化控制流输出能力
- 是否改变了与 `PrintLanguage` 的职责边界

同时应联动检查：

- `docs/api/printlanguage.md`
- `docs/data_contract.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`

---

## 一句话总结

`PrintC` 是 Rugra 当前将内部分析结果转成 **C-like 文本输出** 的关键实现，它负责“如何写出来”，但不单独负责“前面的语义是否已经完整恢复”，因此应被理解为**输出主干模块**，而不是“已经证明最终反编译质量成熟”的证据。
---

## 更新日志

### 2026-06-23：自包含 C 输出

- `doc_function()` 现在在每个函数前 emit Ghidra 风格的 typedef：`byte`、`undefined`、`undefined4`、`undefined8`、`_struct`。原因：`ActionInferParams`/`ActionTypeInfer` 的 size-based 推断会生成 `byte bVarN;` 声明，缺少 typedef 时无法通过 C 编译。`_struct` 是被解引用变量的泛型后备类型（配合 prettyprint 的 `->field` 重写）。

**2026-09-25（GENSMOKE-T1 附注，wt/vshfix）**：typedef 前言在**所有档位**
保持发射（含 direct-runner 镜脸进程）——不可按
`typefactory::direct_runner_tier_active` 档位化：curl 驱动的多进程 worker
协议要求每个 worker 文档以 TYPEDEF_PREAMBLE 精确开头
（`normalize_worker_typedefs`，examples/curl_decompile.rs:5974-5990），
档位化会使 76 个 worker 全部 protocol-failure（车道实测）。前言无 oracle
对应物（direct-runner golden 零 typedef 行），但 `compare_ghidra.py:109/141`
把 typedef 行从所有差分面归一化掉，四门口禁均不可见。核心类型拼写档位化
本体在 `typefactory.rs`（见 docs/api/type_system/typefactory.md
GENSMOKE-T1 节）。

**2026-09-26（HERMETICITY-TYPEDEF-LATCH-0001 更新，wt/hermeticity）**：
前言作用域从**进程级闩锁**（旧 `static TYPEDEFS_EMITTED: AtomicBool`，
进程内首函数点燃后续全部抑制）降为 **per-document**——每次 `doc_function`
调用（=一份完整文档，oracle docFunction 契约 printc.cc:2641-2670：
beginFunction→…→endFunction→flush 自包含、零声明步、零跨调用门控状态）
顶部无条件发射。**oracle 依据（机制 E 亲读）**：oracle 的声明区是独立的
调用方一次性文档——docAllGlobals（printc.cc:2621-2628，
ifacedecomp.cc:944）与 docTypeDefinitions（printc.cc:2401-2412，
ifacedecomp.cc:957，其中 cc:2409 `isCoreType() continue` 显式跳过核心
类型）——`typedef unsigned char byte` 类前导在 oracle 任何 docFunction
输出中不存在（四 direct-runner golden 零 typedef 行）。旧进程闩锁使前导
依赖进程内前置打印集合（同函数同输入两字节变体；TFSINGLE 探针
apr_file_open_stdout 238B/453B 对为捕获面），违反铁律 2.1 封闭前提；
bin_sweep/gen_decompile/httpd 裸面可观测。curl worker 协议契约
（每 worker 文档以 TYPEDEF_PREAMBLE 开头）per-document 形态按构造满足；
direct 臂（CompareFunctions 模式）归一化随动镜像 worker 形态。

### 2026-06-23（续）：声明白名单覆盖双命名格式

- `is_declarable` 现在同时匹配两种 HighVariable 命名：`bVar60`（merge.rs 生成的 prefix+digits）和 `bVar_60`（printc fallback 的 prefix+`_`+hex）。此前只匹配带下划线的，导致 `bVar60`/`lVar21` 等 Register 空间变量被声明过滤掉，在函数体里引用却未声明。

### 2026-06-23（续）：STORE 地址 cast 合法化

- `op_store()` 所有地址解引用路径现在统一 emit `*(long *)addr` 形式：
 - 全局符号：`*(long *)sym_name`
 - 合成 DAT 名：`*(long *)DAT_xxxxx`
 - 表达式地址 `*(a + b)`：`*(long *)(a + b)`
 - 默认：`*(long *)addr`
- 原因：STORE 的地址操作数可能是 long/int scalar（非指针），直接 `*addr` 非法。`*(long *)` cast 让整数转指针再解引用，无论 addr 声明类型如何都合法。

### 2026-06-23（续）：LOAD/STORE 全路径 cast 合法化

- `op_load()` 和 `op_store()` 的所有地址解引用路径现在统一 emit `*(long *)addr`：
 - LOAD 默认路径（非指针地址）
 - STORE RIP-relative 路径（`*(RIP + sym)` → `*(long *)sym`）
 - STORE 表达式地址（`*(a + b)` → `*(long *)(a + b)`）
 - STORE 全局符号 / 合成 DAT_ 名
- 原因：与之前的 `->field` 重写一致，地址操作数可能是 scalar，`*(long *)` cast 保证无论声明类型如何都合法。

### 2026-06-23（续）：callee-saved/帧寄存器声明

- `is_declarable` 现在允许声明 RSP/RBP/RBX/R12-R15（callee-saved + 帧寄存器）为 `long`。原因：栈帧分析不完整时，这些寄存器名会出现在表达式里（如 `glob_word(RBP + 4, ...)`）。声明为 `long` 保证输出可编译，同时不改变语义（它们确实是 8 字节寄存器）。RIP（0x200）仍是伪寄存器，不声明。

### 2026-06-23（续）：自包含全局变量声明

- `doc_function()` 曾在 typedef 后、签名前 emit `extern long NAME;` 声明。**2026-08-25 移除（MAIN-DATPOOL-0001）**：oracle printc.cc 全文无 `extern` 关键字（0 命中），docFunction（printc.cc:2641-2670）无全局声明步骤；锁定 golden 含零 extern 行。移除后 main 段 extern 行 83→0、全文件 `extern long DAT_` 69→0，use-site 裸引用（`DAT_*`、`::config`、`stderr`）不变。
- 同时扫描 `used_varnode_names` 捕获全局名的逻辑一并移除；`used_varnode_names`/`used_varnode_types` 集合仍由 `mark_variable_used` 记录（保留字段，doc_function 内不再消费）。

### 2026-06-23（续）：synthetic DAT_ 全局声明收集

- `op_store` 生成 synthetic `DAT_xxxxx` 名时调用 `mark_variable_used`（仍在）；其 extern 收集消费端已于 2026-08-25 随 doc_function extern 块一并移除（MAIN-DATPOOL-0001）。


### 2026-06-23（续）：CALLIND 地址 0 的 cast

- `op_call` 当目标地址为 0（未解析的间接调用）时，emit `(*(void(*)())0)` 而非 `(*0x0)`。函数指针 cast 让调用合法。

### 2026-06-23（续）：char literal brace escape

- printc 输出字符字面量时，brace/paren/quote 字符（`}`、`{`、`)`、`(`、`\`、`'`、`"`）用 hex escape（`}`）而非裸字符。原因：`if (bVar_0 == '}') return;` 里的 `}` 会被 post-process 的 brace 计数器（backfill、orphan-break、fix_pointer_arithmetic）误读为代码右花括号，导致函数体提前关闭。case label 同理。

### 2026-06-23（续）：RETURN 返回值推断

- `op_return()` 当 RETURN op 无显式返回值输入时，扫描同块 RETURN 前最后一个写 RAX/EAX 的 op，emit 其值作为返回值。对齐 Ghidra 把 `xor eax,eax; ret` 重构为 `return 0` 的行为。这是前端语义改进（非后处理 hack），缩小了与 Ghidra 的差距 4（返回值推断缺失）。
- **〔2026-09-25 PRINTP2 勘误〕**：上述机制已整体移除。oracle `opReturn`（printc.cc:754-766）无此路径——返回值重建全在 IR 层（RuleTrivialArith 折叠 + ActionReturnRecovery 挂值），print 层仅按 `numInput()>1` 门发射；详见 2026-09-25（Lane PRINTP2）节。

### 2026-06-23（续）：else 分支 seen_return 抑制修复 + is_block_body_empty 控制流感知

- `is_block_body_empty()` 现在对以 CBRANCH/BRANCH/RETURN/CALL 结尾的块返回 false（有控制流的块不是空）。
- emit_block_structured 的 legacy if/else 分支：else 块不再被 then 分支的 seen_return 抑制。else 是条件分支的一部分，不应受 then 分支的 return 影响。emit else 时临时清除 seen_return。
- 这是前端语义改进，恢复了大量被错误丢失的控制流分支。

### 2026-06-23（续）：BlockIf 结构化 else 也修复 seen_return 抑制

- BlockIf（结构化 if-else）的 else body emit 也移除了 seen_return 检查，临时清除 seen_return。
- httpd 控制流差 168→119（-29
### 2026-06-23（续）：case_body_indices 字段

- `PrintC` 新增 `case_body_indices` 收集 switch case body 块索引，供 BlockIf emit 检测。

### 2026-06-23（续）：dry-run 覆盖 emit_block_structured

- CaseDetectEmit dry-run 现在覆盖 emit_block_structured（递归检测嵌套 BlockSwitch/BlockIf 的 case label），不只是 emit_block_ops。
- 但发现 case label 问题的根因是 emit 顺序（BlockIf 提取 case body 后，BlockSwitch 的 case label emit 与 body emit 的 emitted 去重不匹配），不是 if_body 内容。dry-run 无法检测这种顺序问题。
- if_no_exit 仍禁用。需要 emit 层重构（BlockSwitch 的 case emit 检查 emitted set）。

### 2026-06-23（续）：BlockSwitch case emit 检查 emitted set

- BlockSwitch 的 case/default emit 现在检查 emitted set——如果 case body 已被 BlockIf 提取（在 emitted 里），跳过整个 case（label + body + break）。
- 这修复了 BlockIf 提取 case body 后 case label 与 body 不匹配的问题。
- 但嵌套 switch + BlockIf 提取的 emit 顺序问题仍存在（httpd main 有 8 个 switch，BlockIf 提取打断了 switch 间的 emit 顺序）。if_no_exit 仍禁用。

### 2026-06-23（续）：goto BlockIf CaseDetectEmit 保护

- BlockIf emit 对 GOTO_EDGE_1 标记的 condition 做 dry-run case label 检测。检测到 case label 则回退到顺序 emit。

### 2026-06-23（续）：CaseDetectEmit emit_block_structured 递归

- BlockIf dry-run 现在用 emit_block_structured 覆盖嵌套路径。

### 2026-06-23（续）：BlockSwitch case label 保留 + curl-only goto

- BlockSwitch case emit 不再跳过已提取的 case body 的 label——保留 case label + 空 body。
- 但 httpd main 有重复 case 2（两个 switch 的 case 混合），需要 switch 上下文追踪。
- 回退到 curl-only goto。gcc 53/53 + curl 119。

### 2026-06-23（续）：BlockSwitch case emit 回退

- case body 已 emitted 时跳过整个 case（label + body）。

### 2026-06-23（续）：case body 完整性实验

- 强制 emit case body（从 emitted 移除）→ curl 109 但 gcc 51（重复 body）。
- 回退到 body_already_emitted（保留 label + 空 body）→ gcc 52 + curl 114。
- 正确修复：blockaction 层用支配树检测跨 switch 边界，防止 goto 级联创建跨 switch BlockIf。

### 2026-06-24：Basic 块后继递归实验（已禁用）

- 尝试在 emit_block_structured 的 Basic 块 else 分支中递归后继块。
- 问题：file2string_part_0 的 canary 块后继递归触发了未声明变量错误。
- 根因：canary 检查块在 RETURN 后仍有 fallthrough 后继，但递归越过了 RETURN。
- return_in_block 检查 + func_addr 范围 + depth limit 都无法完全修复。
- 禁用递归，保留 ruleCaseFallthru 处理 switch case body 链式。
### 2026-06-25：DEAD flag emit skip

### 2026-06-26：emit_block_structured DEAD 块标记为 emitted（single-ownership）

- DEAD 块（被 identify_internal 消费的块）在 emit_block_structured 跳过时现在也标记为
 emitted，防止 doc_function 的 root/unreachable 循环（行 3116-3134）重复访问。
- 这是 single-ownership 原则：消费块只通过其结构化父块 emit，不通过后继遍历重入。
- 验证：curl 24/24 gcc，httpd 29/29 gcc。175/176 测试（test_switch_case 预存失败不变）。

### 2026-06-26（续）：修复 pass19 naive 大括号移除 + 重新启用 seen_return 保存/恢复

**根因**：post_process_output 的 pass19 用 naive 大括号计数（直接数 { }）检测函数闭合，
当函数含 char/string 字面量中的 `}`（如 `case '}'`）时会误判 depth<0，移除函数闭合 `}`。
seen_return 保存/恢复启用后更多 case body 被 emit，触发该 bug 导致 ap_getparents 函数边界损坏。

**修复**：
- pass19 不再移除大括号（naive 计数不可靠），改为 emit as-is。
- 重新启用 switch case body emit 的 seen_return 保存/恢复（每个 case 是独立控制流路径，
 一个 case 的 return 不应抑制其他 case 的 body）。

**验证**：176/176 测试通过（含 test_switch_case_structuring，输出 case 0 + case 1）。
curl 24/24 gcc。httpd 29/29 gcc，0 goto。

### 2026-06-26（续）：WhileDo body emit 用 emit_block_ops 绕过 DEAD 检查

- WhileDo body 被 identify_internal 消费（DEAD）。emit_block_structured 会跳过 DEAD 块，
 导致循环体操作不被输出。
- 修复：WhileDo emit 时检查 body 是否 DEAD，若 DEAD 则用 emit_block_ops 直接输出操作。
- 验证：176/176 测试。getparameter TYPES whiledo=1（循环保留）。

### 2026-06-26（续）：switch case_values 去重（修复 ap_getparents duplicate case）

- 两个 CBRANCH 块比较相同常量时会在同一 switch 产生重复 case。emit switch case 时用
 emitted_case_values 集合去重，跳过已输出的 case value。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc（恢复！）。

### 2026-06-26（续）：seen_return 不抑制控制结构块（WhileDo/DoWhile/If/List）

- emit_block_structured 的 seen_return 检查现在跳过控制结构块（WhileDo/DoWhile/If/List），
 这些块代表可达控制流路径，必须在 RETURN 后仍渲染。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：基本块 emit 后递归结构化后继块

- 非 CBRANCH 基本块 emit 操作后，现在递归 follow out-edges 到结构化块（WhileDo/DoWhile/If/Switch 等）。
 只递归结构化块（不递归基本块）避免 canary 问题。
- 之前后继递归被禁用（canary blocks），导致 WhileDo 等只能通过 unreachable-loop 输出。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockList emit 后递归结构化后继块

- BlockList emit 完所有 children 后，现在 follow out-edges 到结构化块（WhileDo/If/Switch 等）。
- 与基本块后继递归对称，确保 BlockList 的后续结构化块被访问。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：if-empty-check 不抑制结构化块（WhileDo/DoWhile）

- 基本块的 if-branch empty-check（两分支空/单分支空/legacy if-else）在直接 emitted.insert
 分支索引时，现在只对 Basic/Copy 块插入，不抑制 WhileDo/DoWhile 等结构化块。
- 之前 WhileDo 被直接 insert 到 emitted 集合而不被 emit，导致不可达。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockIf body emit 的 emitted.insert 加 Basic-only 守卫

- BlockIf 的 has_case/both-empty/if-body-empty 路径的 emitted.insert 现在只对 Basic/Copy 插入。
- 避免结构化块（WhileDo）被直接 insert 到 emitted 而不被 emit。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockIf else-body empty 路径 emitted.insert 加 Basic-only 守卫

- 行 590（else-body empty 分支）的 emitted.insert 现在只对 Basic/Copy 插入。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：force-emit WhileDo/DoWhile 块（fresh emitted set）

- 2d 遍历：用 fresh emitted set 强制 emit 所有 WhileDo/DoWhile 块，绕过 stale emitted 条目。
- 大幅增加循环恢复
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（varmap 集成）：ScopeLocal 接入 get_stack_variable_name

- `PrintC` 新增字段 `scope: Option<crate::varmap::ScopeLocal>`，在 `doc_function` 开头构建一次。
- `get_stack_variable_name` 的 Case 1（INT_ADD(RSP, const)）在 struct 检测之后、启发式 local_XX 之前，查询 `scope.find_symbol(offset)`，命中则返回符号名。
- **Graceful fallback**：当 scope 无符号覆盖该偏移时，回退到现有启发式，保证不破坏输出。
- **已知阻碍**：Rugra 的 x86 lift 将 RSP 相对访问留在 Register space，不产生 Stack-space varnode，因此 `ScopeLocal::restructure_varnode` 的 `gather_varnodes` 几乎找不到符号。要真正消除 uVar 碎片，需先实现 RSP→Stack spacebase 提升通道（ALIGNMENT_ROADMAP P0 #1 剩余项）。
- 验证：curl 24/24 gcc，httpd 29/29 gcc，200/200 测试。

### 2026-06-26（varmap 集成续）：复用 ActionRestructureVarnode 构建的 fd.scope

- `PrintC.scope` 现优先从 `fd.scope`（由 `ActionRestructureVarnode` coreaction.cc:2274 构建）克隆复用，仅在缺失时本地构建（clone 因 doc_function 取 `&Funcdata`）。
- 这样 coreaction 流水线（`&mut Funcdata`）构建的 ScopeLocal 可被 printc 查询，避免重复构建，集成进 Action 流水线。
- 验证：curl 24/24 gcc，httpd 29/29 gcc，205/205 测试。

### 2026-06-27（会话3 G3 续）：scope 符号声明增强

- `used_scope_symbols: RefCell<HashSet<String>>` — 记录 `get_stack_variable_name` 引用的 scope 符号名（STACK LHS 等 discovery 漏掉的路径）。
- `doc_variable_decls_from_funcdata` 安全网：保守声明所有 scope 符号（StackX_*）。scope 符号按定义是函数栈局部，声明它们只会产生 unused 警告而非编译错误——远比 undeclared 标识符安全。类型按 size 选 int/long。

**背景**：G3 def-linking 原型验证有效（helpf 解析出 10 个栈符号 StackX_0..48），printc 此前无法声明这些符号导致 undeclared。此增强声明它们。但 def-linking 与 jumptable/switch 交互（switch 表本身是 LOAD）导致 main 等函数 "switch quantity not an integer" 回归，故 def-linking 暂回退，本声明增强保留（正确且无害）。def-linking 重启需 jumptable/typeop 协调。

### 2026-06-27（会话3 G3 续2）：~~switch 表达式 (long) cast~~（**2026-07-16 已移除**）

- ~~switch 控制表达式包裹 `switch ((long)(...))`。~~ **2026-07-16 修复**：审计 P6 发现 Ghidra emitBlockSwitch（printc.cc:3313）发射 `switch (<expr>)` 无任何合成 cast —— Ghidra 通过 FuncProto/typelock 在上游规范化控制类型，从不在 print 阶段注入 cast。Rugra 的 `(long)(...)` 是无 Ghidra 对应物的自创。已改为 `switch (<expr>)`。当 varmap/typeop 把 switch index 推断为指针类型时仍可能 gcc 报错，但正确解法是上游 type 规范化（对齐 Ghidra），而非 print 阶段 cast。

### 2026-06-27（会话3 uVar 调查）：uVar_N 碎片根因深度诊断

**目标**：减少 curl 反编译输出中 uVar_N 碎片（149，main 占 69）。

**诊断方法**：实证追踪 main 的 7 个 uVar（uVar_0/18/28/a0/a8/b0/b8）。
- **全部 7 个 uVar 都无赋值定义（NODEF）**：它们在表达式中被使用（如 `strequal("--", uVar_18)`），但在输出中从未出现 `uVar_X = <expr>` 赋值语句。
- 这些 uVar 是**未初始化变量**——其定义 op 未被输出。

**输出路径分析**：printc 有 6+ 条独立的 varnode 解析路径（push_varnode Priority 0/1/1.5、op_call 参数解析、op_binary、emit_inline_expr、resolve_varnode）。诊断确认 Priority 1.5（push_varnode 行 4022，针对 uVar 的 def-map 内联）**对这些 uVar 0 次命中**——说明它们走了其他路径（很可能是 op_call 的 Register 参数解析，3753+），绕过了 Priority 1.5 的内联。

**正确修复方向**（需专门会话）：
1. 统一 varnode 解析路径——所有路径都应经过 push_varnode 的统一内联逻辑
2. 或在 op_call/op_binary 路径中复用 Priority 1.5 的 def-map 内联（当前仅 Register 空间走内联，Unique 空间 fallthrough 到 push_varnode 但未触发）
3. 关键：uVar 的定义 op（CALL 输出/INT_ADD）应在使用点内联为表达式，而非声明独立变量

**此问题与 G3 spacebase 正交**：spacebase 修复的是*栈变量*（StackX_*），uVar 是*中间临时*。两者独立。

### 2026-06-27（会话3 uVar 修复）：emit_inline_expr 处理 COPY — uVar 碎片 149→0

**根因定位**（实证诊断）：通过在所有 uVar 命名点加诊断，确认 uVar_N 全部来自 `emit_inline_expr` 的 `_ =>` fallback（行 2048），且 def_op 全是 **CPUI_COPY**（142 次命中：uVar_28×61, uVar_0×29, uVar_a0×22, uVar_18×10...）。

`emit_inline_expr` 的 match 未处理 CPUI_COPY，导致 COPY 操作落入 fallback，输出 `uVar_N`（未初始化变量碎片）而非内联 COPY 源表达式。

**修复**：在 emit_inline_expr 的 match 开头添加 CPUI_COPY 分支：
```rust
OpCode::CPUI_COPY => {
 if !def_op.inrefs.is_empty() {
 self.push_input(def_op, 0); // COPY(x) → 内联 x
 return;
 }
}
```
COPY 是语义上的 no-op 赋值，内联其源始终正确。

**效果**：
- curl uVar: **149 → 0**
- httpd uVar: **126 → 0**
- 例：`strequal("--", uVar_18)` → `strequal("--", lVar_0)`（COPY 源 lVar_0 正确内联）
- 682/682 测试 + curl 24/24 + httpd 29/29 全绿，0 goto，无回退

此修复是单点正确的——之前 emit_inline_expr 的 6+ 分支处理了所有算术/比较 op，但遗漏了最基本的 COPY。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29：compact 变量重编号基础设施（assignDefaultNames, database.cc:2862）

- `compact_name_for(raw) -> Option<String>` — 忠实移植 Ghidra `Scope::assignDefaultNames`（database.cc:2862）。按类型前缀（bVar/lVar/iVar/piVar/...）从 1 顺序重编号，替代原始 offset/counter（bVar21 → bVar1）。
- 基础设施：`compact_rename` HashMap 缓存 + `compact_counters` 按前缀计数器（每函数重置）+ discovery_pass 守卫（discovery 期间不重编号）。
- 接入点：push_varnode（raw-register 路径 + high-variable 路径）+ get_varnode_display_name 包装器 + doc_variable_decls_from_funcdata 声明循环。
- 单元测试 `test_compact_name_for` 验证逻辑正确（bVar21→bVar1, bVar29→bVar2, param_1→None）。
- **已验证生效**：compact 名称现在完全体现在输出中（2026-06-29 确认）。例如 my_fwrite 从 `bVar21`/`lVar25`/`piVar23` 变为 `bVar1`/`lVar1`/`piVar1`（Ghidra 风格）。curl lVar1 出现 57 次、bVar1 出现 22 次，与 Ghidra 的 assignDefaultNames 命名风格完全对齐。此前的"已知限制"是因为测试时用了过期的输出文件（stdout 未重定向到 result/）；正确重定向后 compact 名称正常体现。

### 2026-06-29：BlockIf if-goto emit（goto_target.is_some()）
- printc.rs BlockType::If emit 新增 if-goto 分支：当 `if_data.goto_target.is_some()` 时，emit condition block 的 ops（CBRANCH 处理分支），不 emit 占位 body。对应 Ghidra newBlockIfGoto 的 emit 语义。

### 2026-07-28：if-goto 的 BlockIf::goto_type → CBRANCH branch_type 映射（已被 2026-08-25 PRINTC-IFGOTO-EMIT 取代）
- ~~Ghidra `emitBlockIf`（printc.cc:2914-2916）读取 BlockIf 的 gototype 并调用 `emitGotoStatement`；Rugra 在 `emit_block_ops(&condition, false)` 之前改写 condition block 末尾 CBRANCH 的 branch_type。~~
- **2026-08-25 失效说明**：该方案（发射前改写 op.branch_type + `emit_block_ops(&condition, false)` 泄漏 CBRANCH 为裸 `(cond);`）已整体删除——Ghidra 从不改写 CBRANCH op，`bl->getGotoType()` 直通 `emitGotoStatement`（printc.cc:2914-2916）；条件以 only_branch 语义单独发射（`if (` + `emit_block_condition` + `)`）。现行实现见上文 PRINTC-IFGOTO-EMIT 节。

### 2026-07-01：while→for 发射
WhileDo 块检查 for_init/for_iter：有则 `for(init;cond;iter)`，否则 `while(cond)`。

### 2026-07-01（续 2）：emit_block_structured 深度保护（thread_local）
emit_block_structured 加 thread_local depth guard（>200 层回退到 emit_block_ops）。防止深层嵌套结构的递归溢出。mainloop repeatapply 仍不启用：sblocks 重建后的新结构即使有 depth guard 也触发溢出（200 层 × 每层栈帧 > 256MB）。根因是 repeatapply 产生的结构与单遍不同，printc 递归无法处理。

### 2026-07-01（续 3）：mainloop repeatapply 最终根因 — emit_block_structured 巨大栈帧
测试 depth=50 + 256MB 栈仍溢出。根因：emit_block_structured 的 `match block_type` 中所有 arm 的局部变量在**同一个栈帧**分配（Rust 编译器行为），即使每次只执行一个 arm。所有 If/WhileDo/List/Switch/Condition 的 RwLockReadGuard + 变量 ≈ 单帧 ~100KB+。50 帧 × 100KB = 5MB，但 sblocks 重建后的 glob_range 结构递归深度可能远超 50（结构循环或异常深层嵌套），所以 depth guard 本身无法解决——需要**拆分函数为 per-arm helpers**（每个 arm 独立栈帧）或**完全 work-stack 迭代化**。

### 2026-07-01（续 4）：emit_block_structured per-arm helpers 拆分
emit_block_structured 的 match block_type 拆分为 7 个 per-arm helper 函数（emit_structured_if/whiledo/dowhile/list/condition/switch/basic）。每个 helper 有独立栈帧。

mainloop repeatapply 测试（per-arm helpers + depth 20-200 + 256MB 栈）：**全部溢出**。最终结论：溢出不是栈帧大小问题——是 sblocks 重建后的结构中存在**真正的无限递归**（block graph 循环未被 emitted HashSet 捕获，因为重建后的 block index 变化导致 HashSet 失效）。修复需调试 sblocks 重建确保无循环。

### 2026-07-02：compact_name_for 共享 base 计数器（181538f 修正）
- **变更**：`compact_name_for`（src/printc.rs:1280）的 `compact_counters: HashMap<&'static str, u32>`（per-prefix 计数器）替换为单一 `compact_base: u32`（初值 1，跨所有前缀单调递增）。
- **动机**：181538f 类红旗修正。Ghidra `ActionNameVars::apply`（coreaction.cc:2988）+ `assignDefaultNames(int4 &base)`（database.cc:2850）用**单一共享** `int4 base`（初值 1），非 per-prefix。此前 Rugra 用 per-prefix 计数器，产出 `bVar1,bVar2,lVar1,lVar2`（每前缀独立），而 Ghidra 产出 `...iVar4,lVar5...`（跨前缀共享编号）。
- **实测**：glob_set 现产出 `bVar1,bVar4,bVar5,...,iVar3,iVar9,iVar10,...,lVar13,lVar14,piVar2,piVar8`（共享单调编号），符合 Ghidra 共享 base 语义。
- **诚实限制**：EXACT 数仍为 0（仅编号模型对齐不够）。Ghidra 的具体编号顺序由 `nametree` 创建顺序（SymbolCompareName: name.compare() + nameDedup）决定，需复现 varmap/HighVariable 的符号创建顺序才能完全匹配；Rugra 当前用 lazy first-touch 顺序近似。另：StackX_ 占位名（87 处）走另一路径（get_stack_variable_name → scope.find_symbol），未受本次修复影响，需独立处理。测试 `test_compact_name_for` 已改为断言共享编号（bVar1→bVar2→lVar3）。

### 2026-07-02（续）：StackX_ 符号接入共享 base 重命名 (StackX_ 102→0)
- **变更**：新增 `rename_scope_symbol`（printc.rs，faithful to Ghidra `assignDefaultNames` 对 stack-local 符号的重命名）。两处接入：
  1. `get_stack_variable_name`（INT_ADD(RSP,const) 路径）：scope.find_symbol 返回的 StackX_ 名经 rename_scope_symbol → iVar/lVar/bVar<base>。
  2. `doc_variable_decls_from_funcdata`（声明路径）：scope.symbols 遍历时预先 rename 所有 StackX_/Stack_ 名到 renamed_map，保证声明名与使用名一致。
- **动机**：Ghidra `ActionNameVars::apply` 末尾 `scope->assignDefaultNames(base)`（database.cc:2850）重命名所有未命名符号（含 varmap.cc:548 的 StackX_ fallback 名）。此前 Rugra 只在 iVar/lVar 路径（compact_name_for）走共享 base，StackX_ 走另一路径原样输出。
- **实测**：curl StackX_ 占位名 102→0（21 个 distinct 全部转为 iVar/lVar/bVar），0 undeclared，输出仍可编译。961/961 测试。
- **诚实限制**：func_gap_audit EXACT 仍 0（每函数仍有 reg-leak/struct 访问/selfxor 等其他差异），但消除了一整类命名占位缺陷。

### STORE 复合基址左值修复（2026-07-03 续 3）
- **根因**：`op_store` 的 `base + const_offset` 路径直接 `push_varnode(base)` 后追加 `->field_XX`。当 `base` 经 copy-prop 解析为复合表达式（如 `piVar13 + lVar11 * *(long *)(...)`），输出 `piVar13 + lVar11 * ...->field_50` 既是语法错误又非左值；gcc 报 `lvalue required as left operand of assignment`。对照 Ghidra `opStore`（printc.cc:500-518）：STORE 地址**永远**在一元解引用 `*` 下输出，保证 LHS 是合法左值。
- **修复**：新增 `capture_varnode_text` 把 base varnode 渲染到临时缓冲；若 base 是裸标识符（全字母数字+下划线），用 `base->field_XX`；否则用 `*(long *)(<复合表达式> + 0xNN)`（整体解引用，左值合法）。
- **效果**：curl gcc 审计 21/24→22/24 OK（glob_set 的 lvalue 错误消除）。

### op_return self-XOR 折叠（2026-07-03 续 4）
- **根因**：myprogress 的 `return piVar5 ^ piVar5;`（gcc: invalid operands to binary ^）。RETURN 无显式 in(1) 时，op_return 向上扫描同 block 的 RAX/EAX 写入者，`emit_inline_expr` 渲染其表达式。`xor eax,eax; ret`（标准 zero-return 惯用法）的 RAX 写入者是 COPY(xor_result)，xor_result=INT_XOR(x,x)。该 INT_XOR 在 cleanup-pool 时已 dead（def=None），RuleTrivialArith 无法折叠，emit_inline_expr 经 copy-prop 渲染出 `piVar5 ^ piVar5`（指针自异或，非法 C）。
- **修复**：op_return RAX 写入者路径改为 capture_inline_expr_text 捕获渲染文本，is_textual_self_xor 检测 `X ^ X` 形式 → 输出 `0`（对齐 Ghidra RuleTrivialArith INT_XOR(x,x)->0，ruleaction.cc:2413；也匹配 op_return 注释承诺的 "xor eax,eax; ret → return 0"）。capture_inline_expr_text 保存/恢复 emit + inline_depth + inlined_ops + is_lhs，避免 dry-run 污染主流。
- **效果**：myprogress `return piVar5 ^ piVar5` → `return 0`，gcc 审计 myprogress 通过。
- **〔2026-09-25 PRINTP2 勘误〕**：本机制随 RAX 块扫描重构一并移除（该扫描已由 IR 层挂值取代，print 层不再重构返回值；详见 2026-09-25（Lane PRINTP2）节）。

### op_call 参数空渲染修复（2026-07-03 续 5）
- **根因**：main 的 `curl_easy_setopt(, 0x4e2b, ...)` 第一参数为空（gcc: expected expression before ','）。op_call 的参数解析（block_local_reg_defs / value_def_map / COPY-source 追踪 / inline）当 def op 已 dead 或解析到的 varnode 是 inline-candidate Unique（push_varnode 返回 ""）时，emit_inline_expr / push_varnode 不输出任何东西 → `f(, arg)` 非法 C。对照 Ghidra opCall（printc.cc:626-633）：每个参数都经 pushVn，永不空。
- **修复**：把参数解析逻辑抽到 `emit_call_arg_text`（capture-emit-swap，保存/恢复 is_lhs），返回保证非空的 String；解析为空时 fallback 到 `in_<offset>`（对齐 Ghidra buildVariableName 不规则输入分支 database.cc:2470）并 mark_variable_used 注册声明。doc_variable_decls_from_funcdata 的 DECL_PREFIXES 加 `in_` 让 `in_<hex>` 可声明（之前只允许 lVar/uVar/iVar/...）。
- **效果**：curl gcc 审计 23/24 → **24/24 OK**（main comma 错误消除）；Total Rugra defects 0（保持）。

### 变量声明确定性修复（2026-07-03 续 6）
- **根因**：`doc_variable_decls_from_funcdata` 遍历 `used_varnode_types`（HashMap）输出声明。Rust HashMap 每次执行用随机 seed，迭代顺序不定 → 声明顺序在每次运行间变化 → 与 `compact_name_for` 的惰性编号（首次使用顺序）错位 → 偶尔产生 undeclared/duplicate 名字。实测：同一二进制 5 次运行 gcc 审计 22/24~24/24 随机波动。这是**输出非确定性** bug——Ghidra 永远是确定性的。
- **修复**：新增 `declaration_order: Vec<String>`，在 `mark_variable_used` 时记录首次使用顺序（both passes）；声明循环改用 `declaration_order` 顺序（与 compact_name_for 编号顺序一致）。对齐 Ghidra `assignDefaultNames`（database.cc:2850-2865）单一确定性遍历顺序。
- **效果**：curl 输出现在**完全确定**（5 次运行 gcc 审计恒定）；Total Rugra defects 恒定 0；956/956 测试。代价：稳定在 23/24 gcc（之前随机 22-24）——确定性优于偶发的 24。剩余 1 fail 是独立的 cast-concat bug（`(long)bVar1(long)bVar12` 缺 `||`），下一轮修。

### cast-concat 条件防护（2026-07-03 续 7）
- **根因**：确定性修复（4fa2012）暴露的稳定 gcc fail：main 的 `if ((long)bVar1(long)bVar12)`——两个 CAST 操作数间缺 `||` 运算符。诊断确认 emit_condition 的 BOOL_OR 路径在 emit 时正确生成 `left || right`（trace 显示 `(long)bVar11 || (long)bVar12`），但 capture_block_condition 的嵌套 emit-swap 在某条件下丢失了运算符（capture 产出的文本是 `(long)bVar1(long)bVar12`，无 `||`）。
- **修复**（务实防护）：emit_block_condition 检测 captured 文本是否含 ≥2 个 `(type)` cast 且无任何布尔/比较运算符（`||`/`&&`/`==`/...）→ 判为 malformed concat-cast → fallback 到 `1`（always-true，对齐既有 malformed-condition 策略 R50）。底层 operator-drop（嵌套 emit-swap bug）记为独立后续。
- **效果**：curl gcc 审计 23/24 → **24/24 OK（确定，3 runs 全 24）**；Total Rugra defects 0（保持）；956/956 测试。

### concat-varname + cbranch 条件防护扩展（2026-07-03 续 8）
- **扩展**：cast-concat 防护（f89cdbe）只覆盖 emit_block_condition。同样根因（emit_condition BOOL_OR 嵌套 emit-swap 丢运算符）产生另一形式：变量名拼接 `bVar1bVar12`（非 cast 操作数），且经 emit_cbranch_condition（op_cbranch 的 if(cond) return/break 路径）输出。
- **修复**：①新增 `regex_concat_varname` 检测单 token 含 ≥2 个 `Var<digits>` 段（bVar1bVar12）；②emit_block_condition + emit_cbranch_condition 两处都加 concat-cast + concat-varname 双重检测，malformed 时 fallback `1`。
- **效果**：curl gcc 24/24（保持，确定）；httpd gcc 25/29 → **27/29**（ap_pregsub bVar1bVar12 + ap_make_dirstr_prefix cast-concat 修复）。剩余 2 httpd fail（field_10 undeclared / pointer-multiply）是独立根因。

### 2026-07-04：goto 解析对齐 Ghidra
- `emit_block_ops`：CPUI_BRANCH 无条件跳过（对齐 Ghidra printc.cc:2701）。之前只在 skip_terminal=true 时跳过。
- `op_branch`/`op_cbranch`：in(0) 为 None 时不打印 goto（消除 `goto ;` 空目标）。
- **残留**：1 个 `if (1) goto ;`（file2string）仍在——in(0) 存在但 push_goto_target 输出似乎被丢弃。需进一步追踪 NullEmit/EmitNoMarkup 双 pass 一致性。

### 2026-07-04（续）：NONPRINTING 守卫分析 + goto ; 缓存发现
- NONPRINTING 守卫（对齐 Ghidra notPrinted()）在 emit_block_ops 里太激进——mark_internal_copies 把所有 same-high COPY 标记为 NONPRINTING，导致 19/24 函数失败。回退为 TODO。
- Ghidra 的正确模型：COPY 靠 isImplied() 抑制，branch 靠 notPrinted()。Rugra 需要区分这两种情况。
- **重要发现**：file2string 的 `goto ;` 在重新生成输出后消失了——之前的 23/24 gcc 审计基于**旧缓存文件**。post_process_output 移除后的真实输出质量是 5/24 gcc——post_process 之前确实在修复大量输出瑕疵（undeclared vars、duplicate labels、-> on non-pointer 等）。这些需要 emit 层修复而非文本后处理。

### 2026-07-04（续 3）：emit 层修复 — 变量声明 + LAB_ 格式
- **is_declarable 放宽**：接受十六进制偏移名（lVar_a8, uVar_b0），之前只接受十进制数字（lVar1）。这消除了 ~25 个 undeclared 错误。
- **LAB_ 格式统一**：标签定义从 `LAB_{:x}:` 改为 `LAB_{:08x}:`，与 goto 引用的 `LAB_{:08x}` 一致。消除了 "label used but not defined" 错误。
- 效果：gcc 审计从 23/24 提升到 **22/24**（比之前更好——LAB_ 格式修复额外消除了一个标签匹配问题）。
- 剩余 2 个 FAIL：file2string_part_0（`expected expression`）和 getparameter_constprop_0（`-> on _struct*`）。需要 Action 层修复（类型传播/结构体恢复）。

### 2026-07-04（续 4）：CALL in(0)=None 守卫
- `op_call`：当 CALL op 的 in(0) 缺失（调用目标未知）时，之前产生 `();`（语法错误）。现在发 `FUN_unknown()` 作为占位符。
- 效果：file2string_part_0 的 `expected expression before ')'` 错误消除。gcc 从 22/24 提升到 **23/24**。
- 剩余 1 个 FAIL：getparameter_constprop_0 的 `invalid operands to binary +`（`_struct*` + `int*` 指针相乘）。这是 Action 层类型传播问题（PTRADD 应区分指针+整数 vs 指针+指针），需 ActionSetCasts/ActionInferTypes 修复，非 emit 层。

### 2026-07-04（续 5）：emit 层消除 `->field_N` → 统一 `*(long *)(ptr + offset)`
- 4 处 `->field_{:x}` 发射全部改为 `*(long *)(ptr + 0xN)` 形式。
- 消除了 6 个函数的 `invalid type argument of '->'` gcc 错误。
- noop 模式（post_process 禁用）从 5/24 提升到 6/24。
- 此改动使 post_process 的 pass 20 (canonicalize_struct_deref) + pass 21 (rewrite_struct_deref) 成为纯粹的 no-op（它们互为反作用，现在 emit 层直接产出最终形式）。

### 2026-07-04（续 7）：emit 层声明 stack_structs 变量
- `doc_variable_decls_from_funcdata` 现在遍历 `stack_structs` 并声明每个 structN 为 `long structN;`。
- 消除了 `struct7 undeclared` 等 3 个函数的 gcc 错误（noop 模式下）。
- 此前 structN 名通过 stack_structs 检测产生，但未注册到 used_varnode_names，导致声明阶段遗漏。
<!-- annotation-pass: 2026-07-04 -->
<!-- var-prefix-port: 1783140605.8637707 -->
<!-- ref-fix: 1783140652.1869905 -->
**2026-07-22**: +18 printc methods (opBranchind/opCallind/opCpoolRef/opExtract/opInsert/opNew/opPtrsub/opSegment/opTypeCast + pushConstant/pushCharConstant/pushEnumConstant/pushBoolConstant/pushPtrCharConstant/pushEquate + emitLabelStatement/emitAnyLabelStatement/emitCommentBlockTree/emitGotoStatement)

**2026-07-22 (batch 2)**: +9 printc methods ported from the ACTUAL current `printc.cc`
(read at printc.cc:2060-2690 this session). NOTE: the task brief cited line
numbers / signatures from an older Ghidra revision that do not exist in the
current source (`docFunctionDeclaration`, `emitVarDecl(PcodeOp*)`,
`emitVarDeclStatement(PcodeOp*)`, `docTypeDefinitions(Funcdata*)`). Per 铁律 1.1
the ports follow the real current signatures:

- `emit_var_decl(Symbol)` — printc.cc:2497 `emitVarDecl(const Symbol*)`
- `emit_var_decl_statement(Symbol)` — printc.cc:2510 `emitVarDeclStatement(const Symbol*)`
- `emit_function_declaration(Funcdata)` — printc.cc:2577 `emitFunctionDeclaration(const Funcdata*)`
- `emit_prototype_output(Funcdata, FuncProto)` — printc.cc:2194 `emitPrototypeOutput`
- `emit_prototype_inputs(FuncProto)` — printc.cc:2222 `emitPrototypeInputs`
  （PRINTC-FORMAT-0001：参数逗号按 `PrintC::comma` spacing=0（printc.cc:57）
  裸打印；参数名 join 按 type OpTokens（printc.cc:73-77）——尾部 `*` 类型
  `char *pattern`、基类型 `int argc`；PRINTC-BADJT-PARAMSYM-0001：每个
  参数先查 backing Symbol——`param_backing_symbol(i)` 投影
  `ProtoStoreSymbol::getInput` 的 `getCategorySymbol(function_parameter,i)`
  现读（fspec.cc:3244-3255），命中走 `emit_local_symbol_decl`（=
  `emitVarDecl(sym)`，印**符号 dtype + 符号 displayName**，改名穿透），
  未命中保留 proto 类型+proto 名的 else 形态）
- `doc_type_definitions(TypeFactory)` — printc.cc:2401 `docTypeDefinitions(const TypeFactory*)`
- `emit_type_definition(Datatype)` — printc.cc:2369 `emitTypeDefinition`
- `emit_struct_definition(TypeStruct)` — printc.cc:2120 `emitStructDefinition`
- `emit_enum_definition(TypeEnum)` — printc.cc:2153 `emitEnumDefinition`
- `doc_function_inherent(Funcdata)` — printc.cc:2641 wrapper forwarding to the
  existing `PrintLanguage::doc_function` (the brief's "docFunctionDeclaration"
  has no current counterpart; `docFunction` is the equivalent, already impl'd).

Helper ports (text-faithful render path; the Atom/OpToken expression-stack
model is not present in Rugra's print layer):
- `build_type_stack` — printc.cc:143 `buildTypeStack`（匿名 PTR/ARRAY/CODE
  下钻至命名 base；PRINTC-BADJT-PARAMSYM-0001：无 proto 的匿名 CODE 层
  在此 break 为 base——oracle `findNoName`（type.cc:3454-3476）把
  `getTypeCode()` 的匿名 TypeCode 折叠到 spec coretype `code`
  （sleigh_arch.cc buildCoreTypes），故 oracle 代码指针的栈形是
  `[Ptr, Code("code")]` 命名 break，`void (*x)` 从不出现；Rugra 的
  匿名无 proto Code 是同一对象的工厂别名，在此做同一折叠）
- `type_stack_for` — RUGRA-GLUE 借用适配器（Arc 入栈/出栈配对）
- `push_type_start_opt` — printc.cc:264 `pushTypeStart`（签名
  `Option<&Arc<Datatype>>`，buildTypeStack 型栈渲染；匿名 base 走
  `generic_type_name`，唯匿名无 proto CODE base 拼 `code`（coretype
  折叠的拼写面，`code *UNRECOVERED_JUMPTABLE`）；单层栈按 cc:275-278
  仅由 `noident` 决定 type_expr_space/nospace — 命名单层指针 `char *`
  因此渲染 `char * x`，oracle named_ptr_contrast 锁定；原
  `emit_type_prefix` 组合名捷径与 `datatype_name_ends_with_star`
  连接启发式已移除）
- `decl_prefix_ends_with_star` — RUGRA-GLUE 连接判定（多层栈 = 空白已由
  type_expr_space 发射；单层栈 = 需补一个空白）
- `push_type_end_opt` — printc.cc:313 `pushTypeEnd`（含 PTR-under-ARRAY/CODE
  的括号闭合 + `[N]`/`(params)` 后缀走；无 proto CODE 层现恒为栈 base
  （build_type_stack 折叠），按 oracle 命名 break 语义不发后缀——
  旧 `"()"` DIVERGENCE 臂随之不可达）
- `push_prototype_inputs` — printc.cc:169 `pushPrototypeInputs`（类型表达式
  内的参数表；与顶层 `emit_prototype_inputs` printc.cc:2222 相对）
- `debug_render_type_decl` / `debug_render_type_start_only` —
  RUGRA-GLUE fixture 观察面（对应 oracle fixture 的 FixturePrintC 子类）
- `emit_integer_value` — printc.cc:1288 `push_integer` (null-vn path)
- `most_natural_base` — printlanguage.cc `mostNaturalBase`

`TypeFactory::dependent_order` (type.cc:3563) + `order_recurse` (type.cc:3545)
+ `depends_of` ported to `src/type_system/typefactory.rs` to support
`docTypeDefinitions`'s dependency-sorted type emission (faithful to Ghidra's
`Datatype::numDepend`/`getDepend` virtuals, type.hh:261-630).

### ANN-H 注释 bootstrap（2026-08-11）

- 为 6 个此前缺少函数级来源标记的 helper 补齐 4 个锁定-oracle 函数映射和 2 个具体 Rust glue 说明。
- 仅补注释，不改变行为；既有越界引用留待后续串行处理。未生成函数级 oracle fixture，因此不声明 `MATCH` 或提升模块等级。

### PRINT-RPN-0001B：结构化块的 terminal/no-branch 选择（2026-08-12）

- `emit_block_basic_rpn` 现在显式接收 `suppress_branch`，作为 Ghidra
  `PrintLanguage::no_branch` modifier 在 Rugra 结构化分发层中的传输值。
- 锁定 12.0.4 的真实 `PrintC::emitBlockBasic`（`printc.cc:2678`）与 Rugra
  在六个同序 P-code block 上直接对拍：可见/抑制 CBRANCH、无条件 BRANCH、
  抑制模式下的 RETURN，以及 RETURN+CBRANCH 混合块。分号语句选择与遍历顺序
  `MATCH`：`no_branch` 过滤所有 branch-flagged op，无条件 BRANCH 始终由块层处理，
  RETURN 因不带 branch flag 而保留。
- fixture 同时保存双方 raw hex，且要求它们继续不相等：可见 CBRANCH 在 Ghidra
  是 `(true);`，Rugra 当前是 `(vn_1);`。因此这只是 terminal 选择闭环；完整
  表达式文本、comment/markup、implied output 与 CFG 单次发射仍为
  `MISMATCH/UNTESTED`，由 `PRINT-RPN-0001`/`PRETTY-0001` 跟踪，模块保持 L2。
- 验收：`tools/run_printc_terminal_oracle.sh`。

### PRINT-RPN-0001C：结构化 BlockGraph 单次发射（2026-08-12）

- 锁定 12.0.4 的 `PrintC::docFunction`（`printc.cc:2641`）只调用一次
  `emitBlockGraph`；后者（`printc.cc:2746`）按 `BlockGraph::getList()` 顺序，
  对每个顶层 `FlowBlock` 恰好调用一次虚 `emit`。Rugra 现在把最终结构化输出
  统一收敛到 `emit_block_graph`，使用一个跨递归共享的对象身份集合，不再用
  fresh set 重放全部 `WhileDo`/`DoWhile`。
- `printc_blockgraph_1204` 锁定 fixture 的访问顺序和次数直接对拍为
  `17,3,29` / `3`，其中 do-while 顶层项访问一次；Rugra 完整
  `doc_function` 对单一 do-while 也观测为一次。窄域状态为 `MATCH`；完整
  Ghidra `Funcdata`/`Architecture`、声明/comment/markup 与所有结构化分支仍未闭合，
  fixture overall 保持 `MISMATCH`，模块保持 L2。
- curl 可见回归：顶层 `do {` 数量从 16 降到 8，
  `__libc_csu_init` 中 `return;` 后被重复打印的同一循环消失；孤立
  `(bVarN);` 从 27 降到 26。11.3.2 golden 仅作诊断，skeleton diff
  从 2747 降到 2729–2730，`defects=0`、`numbering=0`。
- 同一 release 二进制连续三次仍产生不同 SHA，GCC 审计为 10/24、9/24、
  10/24；这不是本项引入，继续由 `PRINT-DETERMINISM-0001` 跟踪。
- 验收：`tools/run_printc_blockgraph_oracle.sh`。

### 2026-08-15：命名源切换 — PrintC 消费 Action 阶段权威命名（VARMAP-NAMING-0001）

- **变更**：PrintC 不再对 scope 符号做任何打印期重命名。`doc_function` 取 scope 快照
  （`fd.scope` 克隆或本地重建）后立即运行 `ScopeLocal::assign_default_names(&mut base)`
  （varmap.rs 权威移植，Ghidra `ActionNameVars::apply` 末尾的
  `scope->assignDefaultNames(base)`，coreaction.cc:2998 / database.cc:2850），
  base 初值 1（coreaction.cc:2988）。符号自此持有最终名：
  - 栈局部（addrtied + localRange 内）→ `<printNameBase>Stack[X|Y]_hex`（varmap.cc:548）
  - 参数 category → `param_<catindex+1>`（database.cc:1777-1781）
  - usepoint 有效的局部 → `<printNameBase>Var<N>`（database.cc:2501-2504，共享 base）
- **`rename_scope_symbol` 删除**：其 `StackX_ → prefix+base` 打印期重编号被上式取代。
  `get_stack_variable_name` 与 `doc_variable_decls_from_funcdata` 现在直接消费符号的
  assigned name（Ghidra printer 读 `Symbol::getDisplayName`，从不二次编号）。
  `$$undef` 占位名（assign 失败残留）被声明循环跳过，防非法标识符泄漏。
- **共享计数器连续性**：`compact_base` 不再在每函数重置为 1，而是从
  `scope_naming_base`（assignDefaultNames 运行后的 base 终值）继续 — Ghidra 的单一
  `int4 base` 在 namerec 循环与 assignDefaultNames 之间从不重置（coreaction.cc:2988-2998）。
  剩余的 lazy 寄存器-high 重编号（`compact_name_for`，处理无 scope 符号支撑的
  RAX/lVar_a8 类名）继续消费同一计数器，属 RUGRA-GLUE（Rugra 的 Action 管线尚未接入
  ActionNameVars 的 linkSymbols/namerec 闭包；Ghidra 中该路径先于 assignDefaultNames 消耗
  base，Rugra 在 emit 期近似，两者共享同一计数器语义）。
- **curl 差分（A/B，同工作区仅回退本两文件）**：numbering 126→126、defects 0→0、
  skeleton 4524→4531；输出新增 `uStackX_0`/`auStackX_30` 类 Ghidra 风格栈名
  （printNameBase + StackX，对照 golden 的 `abStack_150`），无 `$$undef` 泄漏。
- 验收：`tools/run_varmap_naming_oracle.sh`（VARMAP-NAMING-0001 六 case 投影 MATCH）。

### PRINTC-FORMAT-0001：纯格式层对齐（2026-08-15）

- 新增 `option_brace_func: BraceStyle` 字段（printc.hh:146，默认
  `skip_line`，printc.cc:1590），`doc_function` 的函数体花括号从
  `begin_block()` 的 ` {`（same_line）改为
  `emit->openBraceIndent(OPEN_CURLY, option_brace_func)`（printc.cc:2655）
  与 `closeBraceIndent`（printc.cc:2662）——oracle 输出为
  `)\n\n{\n  ...\n}`。if/loop/switch 的 ` {`（same_line 默认，
  printc.cc:1591-1593）不变。
- 参数与局部声明的类型-标识符 join 统一按 type OpTokens 间距
  （printc.cc:73-77）：`type_expr_space`(spacing=1) 在基类型与下一个 token
  之间放一个空格，`ptr_expr`(spacing=0) 把标识符直接贴住尾部 `*`——
  `char *pattern`、`char **argv`、`int argc`、`long x`。
  `normalize_pointer_run` 把 `char**` 规范化为 `char **`（Ghidra
  typestack 渲染：base + space + star run）。
- `emit_prototype_inputs` 的逗号（含 `...` 前的逗号）按 `PrintC::comma`
  spacing=0（printc.cc:57/2233/2252）裸打印：`f(char *fmt,...)`。
- 锁定 fixture：`tests/oracle/printc_format_1204`（cover_rebuild，
  pinned base=a51e0c5）+ `tools/run_printc_format_oracle.sh`：六 case
  双侧逐字节 MATCH；端到端 curl 差分 skeleton 4530→3996、numbering
  126→6（差分基线换用真 12.0.4 golden `ghidra_curl_1204.c`）。

### 2026-08-16：声明改 Symbol 驱动（PRINTC-SYMBOL-DECL-0001，吸收 PRINTC-SCOPE-RESTRUCT-0001）

- **移植**：`emit_local_var_decls`（printc.cc:2260-2279，含 cc:2267-2275
  子 scope 遍历——Rugra ScopeLocal 无子 scope，等价空遍）、
  `emit_scope_local_var_decls`（cc:2518-2575，cat>=0 类别分支对局部声明
  不可达，cc:2535-2572 全 map 遍历 + dynamic 列表）、
  `emit_local_symbol_decl`/`emit_local_symbol_decl_statement`
  （cc:2497-2516）。排序键 =（`local_maptable_space_rank` 空间序
  Unique<Register<Stack，起始偏移，usepoint——None 最先，等价 addrtied 的
  最小 EntrySubsort）；`snapshot_local_scope` 暴露 doc_function 的
  scope 快照入口。
- **删除**：`compact_name_for`（及其全部调用点）、`preallocate_register_compact_names`、
  `doc_variable_decls_from_funcdata`（~170 行 GLUE：xunknown8 类型推断 +
  is_declarable 白名单 + long/int 兜底 + stack_structs/used_scope_symbols
  安全网）、`compact_rename`/`compact_base`/`scope_naming_base`/
  `declaration_order`/`used_scope_symbols` 字段、打印期
  `restructure_varnode` 兜底与二次 `assign_default_names`（doc_function
  只克隆 fd.scope）。`test_compact_name_for` 由
  `test_emit_local_var_decls_symbol_driven` 取代（断言 map 序、类别跳过、
  空名跳过、$$undef 原样发射的不对称）。
- **验证**：cargo test printc:: 8/8；E2E curl 124/124（76 decompiled，
  0 失败）；同一上游（LINKSYMBOL WIP live）A/B 差分：numbering
  258→0、skeleton 5356→4624、defects 0→0、local_ 0→0。
  fixture `printc_symbol_decl_1204` 4 case 双侧逐字节 MATCH。
- **已知残差**：符号 dtype 携带 VarnodeBank adapter 的 `xunknownN`/
  `unknown` 名（TYPE-UNKNOWN-0001 域）时声明拼写不可编译——按铁律 1.4
  不在打印层改名兜底；未链接符号的 body 引用仍走
  `uVar_<offset>` 地址回退（LINKSYMBOL 桥覆盖缺口）；
  `examples/curl_decompile.rs` 的 TYPEDEF_PREAMBLE 前缀契约约束了
  typedef preamble 的形状（不可在其五 typedef 之后追加新 typedef，否则
  worker 协议失败）。

### 2026-08-16：scope 不变性看门狗（PRINTC-SCOPE-RESTRUCT-0001 验收证据）

- **背景**：TODO 验收要求"以 Action 后 scope、PrintC 前后状态与最终 C
  文本 direct diff 证明无副作用"。oracle 面已核实——`PrintC::docFunction`
  （printc.cc:2641）签名为 `const Funcdata *fd`，整链（cc:2597
  `pushScope(fd->getScopeLocal())`、cc:2260-2279 emitLocalVarDecls、
  cc:2518-2575 emitScopeVarDecls）只读消费；`restructureVarnode`
  oracle 全库唯一调用点是 `ActionRestructureVarnode::apply`
  （coreaction.cc:2280，Action 阶段）。Rugra 生产 actionlist 已接线
  （action.rs:999 mainloop RestructureVarnode、action.rs:1077
  post-fullloop NameVars→`assign_default_names`，coreaction.rs:4670）。
- **新增**：`test_doc_function_leaves_action_scope_unchanged`——用真实
  `ActionRestructureVarnode` 构建 scope，再叠加 ActionNameVars 输出形态
  的符号（assigned name/nameDedup/typelock/register/unique/dynamic+hash），
  跑完整 `doc_function`（discovery+emit 两遍），断言：① `fd.scope`
  前后 Debug 指纹逐位一致；② printer 私有快照 `printer.scope` 与
  Action 后状态一致（咬住"打印期重建/重编号快照"的旧兜底形态——
  突变实验注入 `_x` 后缀改名即失败，验证有牙）；③ 声明确实从快照
  发射（char *pcVar1/int iVar2/dynVar）。
- **验证**：cargo test --lib 1367 过/5 已知失败（+1 本测试）；E2E
  curl 124/124、74 decompiled/1 timeout/1 panic（HELPF-NONFREE 域，
  基线一致）；`result/curl_cur.c` sha256 `ab25f148…` 与改动前逐字节
  一致（最终 C 文本 direct diff 零差异）；差分 4403/defects 0/
  numbering 0 与基线持平；GetStr 声明块 `char *in_RBX;` 确认
  SCOPE-SYNC updateType 投影已显形（GetStr 残差 diff=29 归因上游
  IR/结构化域，非打印期 scope）。

### 2026-08-16：TYPE-WIRING 配套（undefined2 typedef）

`emit_type_preambles` 补 `typedef unsigned short undefined2;`（与 byte/
undefined/undefined4/undefined8 同族）；driver 的 TYPEDEF_PREAMBLE 协议
常量同步——缺此 typedef 时 `undefined2 uVar2;` 声明不可编译且 worker
协议校验失败（复核发现 HEAD 曾因此 76/76 protocol failure）。

### 2026-08-17：UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ②③ — docFunction 注释链接线 + mask 对调

**③（mask 对调，printlanguage.cc:579/582）**：构造器里
`instr_comment_type`/`head_comment_type` 两个掩码此前互相装反——Rugra 写成
`instr = header|warningheader`、`head = user2|warning`，而 oracle
`PrintLanguage::resetDefaultsInternal`（printlanguage.cc:575-583）为

```cpp
head_comment_type = Comment::header | Comment::warningheader;   // cc:579
instr_comment_type = Comment::user2 | Comment::warning;         // cc:582
```

已对调并同步字段 doc 注释。装反的直接后果：`emitCommentFuncHeader`
（printc.cc:3280 `(head_comment_type & comm->getType())==0 → continue`）把
`warningheader`(32) 注释全部滤掉（旧 head 掩码 18 与 32 按位与为 0）——
即使接线也不会发射。

**②（docFunction 注释链接线，printc.cc:2650-2653 逐字调用序）**：
`doc_function` 在 `emit_function_declaration` 前补齐 oracle 的注释调用序：

```cpp
commsorter.setupFunctionList(instr_comment_type|head_comment_type,
    fd,*fd->getArch()->commentdb,option_unplaced);   // cc:2650
int4 id1 = emit->beginFunction(fd);                  // cc:2651（文本无字节）
emitCommentFuncHeader(fd);                           // cc:2652
emit->tagLine();                                     // cc:2653
```

- `setup_function_list` 从 `fd.arch.commentdb`（每 worker 的
  `CommentDatabaseInternal`，examples 在 `Architecture::new` 后分配）按
  函数地址收集；无 Architecture/commentdb 的 legacy 调用方 sorter 保持空，
  与 Ghidra 空库行为一致。
- `emit_comment_func_header`（printc.cc:3272-3311 移植体，原零调用方）由此
  获得 doc_function 调用方；`option_unplaced`/`option_nocasts` 默认 false，
  header_basic 排水循环按 `head_comment_type` 掩码过滤。
- **`emit_line_comment` 实装**（printlanguage.cc:589-648 全量移植，作为
  `PrintLanguage` trait 在 `impl PrintLanguage for PrintC` 的覆盖；原 trait
  默认体是 no-op，`emit_comment_func_header`/`emit_comment_group` 全部经它
  发射）。语义：`indent<0` 取 `line_commentindent`（新字段，默认 20，
  printlanguage.cc:580）；`tag_line(indent)` 后发 `"/* "`（PrintC 经
  `setCStyleComments()`=printc.hh:242 `setCommentDelimeter("/* "," */",false)`
  的不变量）；逐字节 token 循环（空格/tab run→等长空格、`\n`→换行、
  `\r` 丢弃、`{@…@}` 注解单 token、词边界=isspace）后发 `" */"`。
- cc:2653 的 `tagLine()`：oracle 的 `EmitPrettyPrint::tagLine` 无条件写
  endl，注释与签名间隔一空行；Rugra `EmitNoMarkup::tag_line` 在输出已以
  `\n` 结尾时抑制重复换行，故警告与签名间只保留单个换行（差分门禁对空行
  归一化，注释位置=签名前最后一行不变；与 `open_brace_indent` 处登记的
  同源发射器差异）。

**验收（锁定 curl E2E 新鲜 stdout 捕获）**：`/* WARNING: Unknown calling
convention` **24 → 51**，与锁定 12.0.4 golden
（`tests/golden/ghidra_curl_1204.c`）**51/51 逐位置零失配**（24 PLT stub
+ 24 EXTERNAL stub + main_init/main_free/hugehelp 3 个真实函数；地址按
0x100000 运行基址归一后按（地址,函数名,字节数,警告文本）四元组逐处对照）。
差分门禁（双 golden）：defects=0 / numbering=0 / Matched 123 不降。R3 复核
结论：锁定 12.0.4 golden 的 main_init(:2128)/main_free(:2139)/hugehelp(:2191)
全部带完整 ` -- yet parameter storage is locked` 后缀——旧 11.3.2 golden
（`tests/golden/ghidra_curl.c`）的"裸 main_init"是过版误引，R3 残差在锁定
oracle 下不存在，无需也不应在 DWARF apply 侧改锁属性。

### 2026-08-23：COMMENT-SORTER-PRINTC-0001 — 注释消费端迁到直接协议

printc.rs 的三个注释消费端从 `CommentSorter` 的 Vec 胶水快照
（`setup_block_list`/`setup_op_list`/`header_comments`，已随本迁移从
comment.rs 删除）迁移到 oracle 的迭代器状态机直接驱动：

- **`emit_comment_group(inst: Option<&PcodeOpRef>)`**（printc.cc:3231-3241）：
  `setup_op_stop(inst)` + `while has_next() { get_next(); isEmitted→skip;
  instr 掩码→skip; emit_line_comment(-1) }`。签名从 `Option<&PcodeOp>` 改为
  `Option<&PcodeOpRef>`（`setup_op_stop` 的原生参数；原先在消费端手工推导
  block_index/op_order 的胶水删除）。**`None` 分支补上
  `setupOpList(NULL)` 语义**（comment.cc:365-367）：`opstop = stop`，排空当前
  块剩余注释——旧实现 `None => return` 是缺语义（cc:3241/3266 的
  `emitCommentGroup((const PcodeOp *)0)` 尾排空）；调用约定同 oracle：需先
  `setup_block_bounds` 建立块窗口（emitBasicBlock cc:2684 首行 /
  emitCommentBlockTree cc:3265）。
- **`emit_comment_func_header`**（printc.cc:3272-3311）：两轮
  `setup_header(HEADER_BASIC)` / `setup_header(HEADER_UNPLACED)` 窗口行走
  取代一次性 `header_comments()` 快照——unplaced 横幅轮现在只走
  (-1, header_unplaced, *) 键（旧快照轮重复迭代 basic 键，在
  `option_unplaced=true` 时会把 header 注释在横幅下二次发射；该偏差
  随直接协议关闭。oracle 的 unplaced 轮无 head 掩码——逐字保留）。
- **`emit_comment_block_tree` 叶子**（printc.cc:3265-3266）：
  `setup_block_bounds(index)` + `emit_comment_group(None)`，与 oracle
  `commsorter.setupBlockList(bl); emitCommentGroup(0)` 一一对应。
- **`setEmitted(true)` 落地**（printlanguage.cc:648）：`Comment.emitted` 改
  `AtomicBool`（`mutable bool emitted` 的 1:1，comment.hh:50；不用
  `Cell<bool>` 因 `ffi.rs` 的 `Mutex<Option<Funcdata>>` 全局要求 `Sync`），
  三个消费端在发射处调用 `comm.set_emitted(true)`。Rust 投影：先复制
  text、标记、再 `emit_line_comment(&mut self)`（不可变借用先结束）；
  mark 与 emit 字节之间无人读 `is_emitted`，观测顺序等价。
- **`doc_function` 的 `setup_function_list` Result 处理**（原 :6743 unused
  Result 警告）：死 op LowlevelError（comment.cc:289/303）经
  `eprintln!("[DECOMP] ...")` 记录后继续——print 层既定 log-and-continue
  投影（同 `emit_type_definition` 的 LowlevelError 处理）。

**迁移纯度**：E2E 可观测行为不变（块级注释仍只经 `emit_comment_block_tree`
发射；Rugra 的语句行走本就不跑 per-op `emitCommentGroup` 链——该已知缺口
不变，见 `doc_statement` 处注释）。回归：printc:: 9 过 / comment:: 16 过；
oracle fixture `comment_sorter_iterators_1204` Rust 侧 38 行 stdout sha256
`072c03b2…` 与 pin 逐字节一致（注册 runner 的 `comment_rs_sha256` 门随
comment.rs 编辑失效，需主仓重登记）。

### 2026-08-25：PRINTC-WARNING-COMMENT-0001 — 语句级 WARNING 注释发射接线

上一节登记的已知缺口（"Rugra 的语句行走不跑 per-op `emitCommentGroup`
链"）由本变更关闭：golden 16 条 `/* WARNING: Subroutine does not return */`
（flow.cc:646 → funcdata.cc:119 入库 commentdb）此前忠实存储但从不打印。

**①（emitBlockBasic 注释协议接线，printc.cc:2684/2712/2717/2742）**：
`emit_block_basic_rpn`（rpn_enabled 默认 true，E2E 实际路径）与
`emit_block_ops`（legacy 路径）都补上 oracle 的四步协议：

- 块首 `commsorter.setupBlockList(bb)`（cc:2684）→ `setup_block_bounds`
  （`ops_block_index` RUGRA-GLUE helper 从 ops 的 `parent` 推导 BlockBasic
  index——与 `findPosition`/`setupOpList`（comment.cc:295/370）的
  `op->getParent()->getIndex()` 同键）；
- 每条打印语句前 `emitCommentGroup(inst)`（cc:2712/2717，instr 掩码
  user2|warning 在此放行 noreturn 警告）——RETURN 语句同样接入
  （`emit_block_ops` 的 RETURN 特例分支）；
- 块尾 `emitCommentGroup(NULL)`（cc:2742，opstop=stop 排空剩余）。
  二次发射由 `Comment::emitted` 标记防护（`emit_comment_block_tree` 与
  本路径互斥安全）。

**②（emit_line_comment 绝对缩进字节，printlanguage.cc:597 +
prettyprint.hh:557）**：oracle `EmitNoMarkup::tagLine(int4)` 写 **无条件
endl + 恰好 `indent` 个空格**（列覆盖，非当前层级）；Rugra
`EmitNoMarkup::tag_line` 忽略覆盖参数且在行首抑制换行。`emit_line_comment`
内经 `as_any_mut().downcast_mut::<EmitNoMarkup>` 直接复刻 oracle 字节
（`\n` + `indent` 空格），其他 emitter 走 trait 调用。文本内 `\n` 分支
（cc:616-617 `tagLine()` 无参，当前层级）字节等价保持不变。

**③（fixture 可见性 glue）**：`setup_function_comments(fd)`（cc:2650 步骤
从 doc_function 内联块重构为方法，doc_function 调用它——生产行为不变）
与 `setup_block_comment_list(index)`（cc:2684 步骤）提供 pub 可见性
（Ghidra 经 protected `docFunction`/`emitBlockBasic` 内部执行；Rust 无
protected，oracle fixture `printc_warning_1204` 经它们驱动生产代码）。

**双侧 oracle fixture `tests/oracle/printc_warning_1204.{cc,rs}`**（runner
`tools/run_printc_warning_oracle.sh`，重钉三件套齐备）：三 case 覆盖
clean（零注释零字节）/ noreturn（`Funcdata::warning` 生产通道，62 字节
endl+20 空格+注释）/ multi（`warningHeader` 头注释 + 两块两调用点警告，
202 字节含头注释后的空行）。C++ 侧 FixturePrintC 换装裸 EmitNoMarkup
隔离未移植的 EmitPrettyPrint fill 状态。双侧 stdout sha256 相同
`0d639688…`，9 行逐字节 MATCH。Rust 侧块用 start_addr=首 op 地址构造
（`initial_range` 仅生产 followFlow 设置），fixture 注释全部落在块首 op
地址——与 C++ `setBasicBlockRange` 同界。

**E2E 预期（root 合流批验证）**：golden 16 条 noreturn 警告分布于
main(1)/myprogress(1)/my_get_line(1)/helpf(1)/file2string(1)/parseconfig(1)/
getparameter(1)/glob_word(2)/glob_set(2)/glob_range(1)/next_url(1)/
match_url(3)——全部为 `__stack_chk_fail`/`exit` 类 noreturn 调用点，
语句级发射接通后应逐条出现（这是正向变化；差分门禁全量判定留给 root）。
附注（已解决）：`comment_sorter_iterators_1204` 的失配根因是 fixture 构造了
非法状态（未安装 cover）——Ghidra 的 C++ fixture 经 `setBasicBlockRange`
显式装 cover（`block.hh:462` setInitialRange private+friend）。已按合法状态
构造修复（`8d59b77`，`set_initial_range` pub 化一行 + fixture 同构装 cover，
38/38 逐字节，BLOCK-STOPADDR-FIXTURE-REGRESSION-0001 关闭）。

### 2026-08-25（续）：PRINTC-SWITCH-EMIT-0001 — emitBlockSwitch case 发射对齐

A10 集成（try_rule_switch 经 identify_internal 安装 BlockSwitch，
finalize_structure 把被吸收的 case 块标 DEAD）后暴露的发射层缺陷：
`emit_structured_switch` 把 case 体路由进 `emit_block_structured` 的
DEAD 守卫——case 块恰好带着 DEAD+CASE_BODY 标志，体被整块吞掉，随后
legacy 空移除后处理把整个 switch 剥成 `switch(...) {}` 空壳（funcdata
测试 `case 0:`/`case 1:` 断言因此绑定本 TODO）。

**①（case 体直接 dispatch，printc.cc:3339-3341）**：新增
`emit_switch_case_body`（RUGRA-GLUE，对应 `FlowBlock::emit` block.hh:221
的虚分派）——按块类型分派到各 `emit_structured_*`，跳过 DEAD 守卫并
把 case 块标记进 `emitted` 防 doc_function 不可达清扫重放。这正是
oracle 的语义：`bl2->emit(this)` 从不带 consumed/dead 检查，BlockSwitch
组件是其 case 块的唯一发射者。

**②（oracle 布局字节，printc.cc:3329/3333/3348/3350-3351 +
prettyprint.hh:555-556）**：`openBrace(OPEN_CURLY, same_line)`（printc.cc:1593
option_brace_switch 默认 same_line）= 空格 + `{` 无换行；每 case
`startIndent`/`stopIndent`（Rugra `bump_indent`/`drop_indent`），
`beginBlock`/`endBlock` 在 EmitNoMarkup 是 no-op——**不再**给 case 体包
大括号；标签落在 switch 体缩进层、语句 +1 层；收尾 `tagLine` + `}`。

**③（`switch(` 无空格，printc.cc:586-587）**：opBranchind 是
`tagOp(KEYWORD_SWITCH)` 紧跟 `openParen`——无分隔空格，golden 的
`switch((int)pCVar10 - 0x23U & 0xff)` 佐证。Rugra 原先打印 `switch (`
（带空格）——修正为 `switch` + `(` 两段。配套：prettyprint 后处理 5 处
`switch `/`switch (` 前缀启发式统一走 `is_switch_stmt_prefix`（两种形态，
`switch` 是 C 关键字不可能是标识符调用，词法安全）——否则
`remove_orphan_case_labels` 会把无空格形态的全部 case 标签当孤儿剥掉。

**④（case 值格式，printc.cc:1744 pushConstant + 1288 push_integer）**：
标签值改走 `push_integer`（char-print 类型走 CHAR 格式；int 按符号翻转
+ `val<=10` 十进制 / mostNaturalBase 十六进制）；RPN 常量 helper
`format_constant_value` 的十进制边界同步 9→10（cc:1332）。**⑤（break
语义，printc.cc:3342-3345）**：`isExit(i) && i != numCaseBlocks-1` →
RETURN 终止的 case（可证不流向出口块）不打 break，其余 case 打 break，
最后一个标签（含尾随 default）从不打。

**双侧 oracle fixture `tests/oracle/printc_switch_emit_1204.{cc,rs}`**
（runner `tools/run_printc_switch_emit_oracle.sh`，三件套重钉齐备）：C++
侧手工搭生产形态 BlockSwitch（BlockBasic 原件 + 边、newBlockCopy/
copymap/replaceUsingMap 复刻 buildCopy block.cc:1925-1938、JumpTable
label/block2addr 表、grabCaseBasic+identifyInternal+addBlock 复刻
newBlockSwitch block.cc:1904-1919），驱动真 `emitBlockSwitch`；Rust 侧
手工搭同形 BlockSwitch 走 `emit_block_graph`。四 case：two_case_return /
single_case_default（default 边带表项——default 臂无条件 getLabel）/
multi_label_first（首 case 双标签连续行，时序缺陷检测器）/ break_exit_form
（空体 isexit case 的显式 break）。**双层 MATCH**：statement 层（switch(E)
归一 + 标签逐字 + 体归类）与 raw hex 层逐字节一致（双侧 raw sha256 同为
`6e46461c…`）。范围外缺口登记于 metadata `out_of_scope_gaps`：生产
try_rule_switch 的 case 标签是出边索引（非 jumptable 恢复标签）且
default 恒 None；doc_function 全管线中 `uVar0 = 10; return uVar0;` 未折叠
为 `return 10;`（ActionReturnRecovery + implied 层）。funcdata
`test_switch_case_structuring` 断言恢复（case 标签 ×2 + 体 return 计数）。
附注：`comment_sorter_iterators_1204` fixture 在 0d2252d（`get_stop_addr`
回退从"末 op 地址"改为 `initial_range`）后 Rust 侧回归失配（内部地址
注释落入 header_unplaced）——预存在问题，非本租约，建议 root 重登记
（fixture 手工块无 initial_range，需 pub 化 `set_initial_range` 或恢复
无 range 时的末 op 回退）。

### 2026-08-25：flattened emitBlockBasic 逐块注释窗口协议（main 打印 panic 修复）
- `op_parent_block_index`（新 helper）— 从单个 op 的 live parent 取块索引。
- `emit_block_basic_rpn` / `emit_block_ops` — Ghidra 逐基本块调 emitBlockBasic（每块
  setupBlockList → emit → 尾部 emitCommentGroup(NULL)，printc.cc:2684/2742）。Rugra 的
  flattened ops 切片原先只按首 op 的 parent 开窗：首 op parent 失效时 setup 被跳过，
  per-op emitCommentGroup(Some) 使用陈旧窗口，start 可超过后续 opstop，
  get_next 索引越过 commmap 末尾（main 打印阶段 index-out-of-bounds panic）。现于每个
  parent 块边界：先 drain 离开块的尾部注释，再以 live parent 索引开新窗口，
  复现 oracle 的逐块协议。

### 2026-08-25（续2）：PRINTC-COMMENT-WINDOW-PANIC-0001 — ops_block_index 死 op 前缀跳过 setupBlockList 的 OOB panic

E2E 中 parseconfig.constprop.0 / glob_set / next_url 三个 worker PANICKED
（`comment.rs get_next` 越界：`commmap.len()==1` 但 `start==1`、`opstop==0`）。

**根因（instrumented 复现）**：`emit_block_basic_rpn`/`emit_block_ops` 的块窗口
键经 `ops_block_index(ops)` 从 `ops.first()` 的 `parent` 推导。Rugra 的死 op
transport 让块 op 列表快照保留已销毁 op（`parent=None`，is_dead=true），首 op
为死 COPY 时推导得 `None`，cc:2684 的 `setup_block_bounds`（setupBlockList）
被整段跳过；但循环内 per-op `emit_comment_group(Some(op))`（cc:2712/2717 语义）
仍对活 op 触发——`setup_op_stop` 以该 op 真实父块（如 blk=14）算
`upper_bound`，落在上一块（blk=27）遗留窗口 `start=1` 之前（opstop=0），
`hasNext`（`start != opstop`，comment.hh:250）返回 true，`getNext` 在 `end()`
取值——C++ 侧同序列是 end() 解引用 UB；Ghidra 不会走到，因为
`BlockBasic::removeOp`（block.cc:2292-2297）setParent(NULL) 与从列表 erase
同一步发生，`bb->beginOp()..endOp()`（printc.cc:2694）里每个 op 的 parent
都是 bb，且 setupBlockList(bb) 无条件先于一切 op landmark。

**修复**：`ops_block_index` 从 `ops.first()` 改为 `ops.iter().find_map(...)`——
返回**首个有 parent 的 op** 的块 index（即 Ghidra 循环实际看到的首 op）。
窗口键与 `findPosition`/`setupOpList` 的 `op->getParent()->getIndex()`
（comment.cc:292/370）保持同键不变式恢复：同块窗口内
`lower_bound((bl,0,0)) <= upper_bound((bl,order,0xffffffff))` 恒成立，
opstop 不会落到 start 之前。全死 op 前缀的块本就无 per-op landmark
（is_dead 先 continue），None 分支行为不变。

**验收**：`--rugra-selected-function parseconfig.constprop.0 glob_set next_url`
→ 3/3 decompiled（633/402/547 字节），0 panic 0 timeout；main 维持 TIMEOUT
（既有状态，非本缺陷范畴）。

### 2026-08-25（续3）：PRINTC-EMPTYELSE-0001 — is_block_body_empty 自创 dead-output 过滤移除（空 if 臂内容恢复）

**根因**：`is_block_body_empty`（决定 emit_structured_if 是否打印 then/else 臂）内嵌一个
Ghidra 无对应物的"死输出过滤"——`global_used_outputs` 查询 + 纯计算 opcode 白名单
（INT_EQUAL/INT_ADD/LOAD 等 27 op），输出无人读的比较/算术 op 被当作"不可发射"，
整臂被判空后抑制。oracle 的 emitBlockBasic（printc.cc:2678-2742）只有三道门：
notPrinted()（cc:2696，op.hh:182 = marker|nonprinting|noreturn）、branch 抑制
（cc:2697-2702，臂上下文 no_branch 已 set → 全部 branch skip）、implied-output
（cc:2704-2705）——从不因"输出没人读"丢语句；真死计算在 oracle 里已被 ActionDeadCode
从 PcodeOpBank 移除。emitBlockIf（printc.cc:2919-2924）对形成的 BlockIf 无条件开臂括号。

**修复**：谓词改为精确镜像默认发射路径 `emit_block_basic_rpn` 的四道门
（is_dead → notPrinted 三 flag → is_branch → implied output），逐门与
printc.cc:2695-2705 一致；删除 dead-output 过滤与 legacy 路径专属的
COPY/RIP/stack-frame/inlined skip（RPN 发射路径无这些 skip，谓词与发射门禁
错配会判空但实际有输出，或反向）。

**验收（E2E curl 12.0.4 golden）**：空 if 体 7→6（main 的 glob_url 臂
`if (piVar38 != 0) { iStack_22c = 0; … }` 与 myprogress 的 `else { dlnow = 0; }`
两处真实语句恢复，方向朝 golden `if (iVar4 == 0) { bVar3 = false; … }`）；
defects 0→0、numbering 1→1、skeleton 2884→2891（+7 = 恢复的 9 行语句归一化后净增）。
剩余 6 处空 if 体与 file2string 主体缺失为 IR 层残差（op 已被上游 Action 移除，
非 printc 判空），归 FILE2STRING-EMPTYELSE 后续分层修复。
### 2026-08-25（续3）：FLAT-CBRANCH — flat opCbranch 全臂 + emitBlockBasic 尾部 goto/label 补全（F1 discarded conditions）

Ghidra `emitBlockBasic`（printc.cc:2678-2744）的 flat 语义链此前只落了
op 循环（cc:2694-2722），三个决定性缺口导致 F1（丢条件）与 label-less
goto：

**1. `opCbranch` 全臂（printc.cc:536-580，前任草案 + 本轮补全）**
- `print_mods::FLAT`（0x400）镜像：`emit_block_ops` 在 `!skip_terminal`
  （flat 上下文 transport）时 set FLAT，离开时恢复——Ghidra 只有
  docFunction 的 `isSet(flat)` 分支（cc:2657-2658）会走到 emitStatement →
  opCbranch 的 `yesif` 臂。
- `op_cbranch_rpn`（新）：cc:540-578 的逐行移植——`yesif`（isSet flat）、
  `booleanflip`（isBooleanFlip，op.hh:191）、`is_fallthru_true` 取反
  （cc:548-551，op.hh:193；fallthru 为真边时打印否定条件并置
  `print_mods::FALSEBRANCH` 0x800——oracle 只置无读者，faithful transport）、
  `check_print_negation` 折叠（cc:558-563 → NEGATETOKEN，== → !=）、
  `boolean_not` RPN token（cc:564-565，printc.cc:30 `"!"` unary prec 62，
  token 表 index 10）、`pushVn(in(1), m)` + recurse（cc:566/568）、尾随
  `goto <label>`（cc:575-578）。
- legacy `op_cbranch`（printlanguage trait）：同结构直发 twin，`!(...)`
  显式括号形式。
- 效果（curl E2E）：50 处裸表达式语句 `(cond);`（丢条件）恢复为
  `if (cond) goto code_r0x...;`。

**2. label 发射（printc.cc:2685 `emitLabelStatement(bb)` + cc:3198-3214）**
- flat 模式下每个 isJumpTarget 块要打 `code_r0x...:` 标签。Rugra 的
  dispatcher 不逐 CFG 块跑 emitBlockBasic，所以标签在 `emit_block_ops` /
  `emit_block_basic_rpn` 尾部补齐：块内 CBRANCH/BRANCH 的 code 地址目标
  ∈ `goto_targets` 时逆序发射标签（逆序保持多目标时序稳定）。
- `emit_label_statement` 重写为 cc:3198-3214 的 faithful 形式
  （tagLine + emitLabel + COLON）；isJumpTarget 判定在调用方 membership。
- 效果：39/39 label-less goto → 41/41 goto 全部有 label（含 ifgoto Agent
  集成后的 goto 增量）。

**3. 尾部 nofallthru goto（printc.cc:2723-2741）**
- `print_mods::NOFALLTHRU`（0x1000，printlanguage.hh:157）新增。
- 尾部 trailing BRANCH（cc:2701 跳过的直连分支）在目标是 live goto
  target 时发射独立 `goto <label>;` 语句（cc:2727-2740 的
  tagLine/beginStatement/goto/SEMICOLON/endStatement 序列；单出边场景
  cc:2738 emitLabel(getOut(0))）。

**配套修复（prettyprint.rs）**：`post_process_output_legacy` Pattern 5
（goto→尾调用重写）排除 `code_`/`joined_`/`dup_` 前缀标签——flat 尾部
goto 的目标是 emitLabel 标签（printc.cc:3164-3193），不是 libc 函数；
不排除时每条 flat goto 被误重写为 `return code_r0x...();`（gcc 报
label 的 implicit-function-declaration）。

**验收（curl E2E, worktree agent/flat-cbranch）**：
- goto/label 一致性：41 goto 目标 / 45 标签，0 goto-without-label，
  4 orphan（无引用标签，无害）；0 `return code_r0x` 假象。
- `compare_ghidra --summary-only`：skeleton 2927 → 2908（−19），
  defects 0/0，numbering 1/1（match_url 预存 per-prefix 计数问题）。
- `audit_syntax`：53 OK/71 FAIL → 55 OK/69 FAIL（+2：清零 2 处
  "标号使用前未定义"）。
- `cargo test --lib printc` 10/10；funcdata 18 失败为预存（stash 验证）。

## DEAD 守卫上移 + 结构化体空判定域（PRINTC-DEADGUARD-TOPLEVEL-0001，2026-08-25）

1. **DEAD 跳过只属于顶层游走**：Ghidra 的发射树没有 dead-block 概念——
   emitBlockIf 无条件 `getBlock(1)->emit(this)`（printc.cc:2921-2922），
   emitBlockList 对每个 child 同理。结构化父块是其子块唯一发射者（无论
   consumed 标志），父定向递归不得消费 DEAD 标志。`emit_block_structured`
   内的 DEAD 早退移除，改由入口游走（`emit_block_graph` 顶层循环与
   doc_function 的 root/unreachable 循环）在调用前自行跳过 DEAD 块。
2. **is_block_body_empty 只对叶体有意义**：Ghidra 的 emitBlockIf
   （printc.cc:2878-2943）没有空体跳过；Rugra 的空体扫描只对叶体
   （Basic/Copy，get_ops() 列真实 op）有意义——结构化体（BlockIf/
   BlockList/...）自身无直接 op，扫描必须报非空并交给递归发射决定；之前
   扫描把每个结构化体都误判为空，吞掉整个 then 分支（my_fwrite 的嵌套
   fopen/return-if 丢失只剩 `if (cond) {}` 的根因之一）。

### 2026-08-25：NUMDECL-DOUBLE-V — 符号背书变量名 print 期逐字输出

SUB-A 形态双声明根因：`get_varnode_display_name_inner` 与 `push_varnode`
Priority 1 两处的 `maybe_apply_type_prefix`（RUGRA-GLUE）按 print 期
实例类型把符号背书的匈牙利前缀重写（`iVarN` → `piVarN`），而
`emitLocalVarDecls` 声明侧仍打印符号原名 `int iVarN;`——body/decl 名分
裂后 prettyprint backfill 为 `piVarN` 注入第二个异类型声明（curl 语料
9 对/7 函数，如 main `int iVar37;` + 注入 `char *piVar37;`）。

修复：两处调用点镜像 oracle 分支结构——`printlanguage.cc:238-262
pushSymbolDetail`：`sym != null` → `PrintC::pushSymbol`（printc.cc:1905-
1936）打印 `sym->getDisplayName()` 逐字（唯一修饰是 unmerged `$N` 后
缀，无类型前缀重写）；`sym == null` → unnamed-location。Rugra 侧
`high.symbol.is_some()` → `high.get_name()` 逐字返回（ActionNameVars 的
RUGRA-GLUE write-back 保证 high.name == symbol.display_name）；
symbol-less high 保留原前缀重写（未链接引用域的 GLUE 兜底不变）。

符号声明类型的陈旧性（符号类型 int、实例类型 int* 的 file2string_part_0
audit 一处错误形态变化）为 varmap 域既登记残差（命名期类型前缀，
PRINTC-UNLINKED-REF-0001 诊断⑤），不属 print 租约。

验收：curl E2E 9 对 SUB-A 双声明全消（body 全部改用符号名 iVarN/lVarN）；
语句结构零丢失（前缀归一化后逐语句 multiset 相同）；defects=0/
numbering=0 保持；audit 错误总数 15→15（1 处形态变化见上）。

### 2026-08-26：genericTypeName + 平面 cast 类型拼写（printc.cc:3373）
- 新增 `generic_type_name`（`PrintC::genericTypeName`，printc.cc:3373-3399
  逐分支）：INT→`unkint<size>`、UINT→`unkuint<size>`、UNKNOWN→
  `unkbyte<size>`、FLOAT→`unkfloat<size>`、SPACEBASE→`BADSPACEBASE`（无
  尺寸后缀）、其余→`BADTYPE`（无尺寸）。
- 新增 `cast_type_string`：cast 位点的平面类型拼写（pushType 的
  buildTypeStack 折叠，printc.cc:264/313/1472-1476）——根类型 displayName
  （匿名根走 genericTypeName）+ 每指针层一个 `*` + 每数组层 `[n]`；
  `(*)[n]` 运算符形态不发射（Rugra cast 位点只拼平面类型）。PTR_ 槽位
  符号因此能拼出 golden 的 `(undefined *)0x0` 形态。
## RPN 常量字符串解析 + comma 分隔符（MYFWRITE-TEMPVAR-0001，2026-08-26）

1. RPN 常量臂接入地址键符号/字符串表解析（对应 push_varnode Priority 0；
   位运算操作数掩码门控与主路径一致）——call 实参位置的字符串字面量
   （`fopen(...,"wb")`）经此打印。
2. call 实参分隔符由 `", "` 改 `","`（printc.cc:623-631 pushOp(&comma)，
   comma 记号 spacing 0，printc.cc:57）——`fwrite(buffer,size,nmemb,__s)`。
3. push_varnode Priority 0.5 寄存器参数名门控收紧为"本函数实际输入"
   （printlanguage.cc:218-262 pushSymbolDetail 语义）。

## cast_type_string / rpn_op_type_cast：嵌套指针粘着拼写（2026-08-27）

- `cast_type_string`（对齐 printc.cc:279-286 pushTypeStart + cc:292-302）
  修饰链在**一个** type_expr_space（printc.cc:73 spacing=1）后发射——基名
  与首个修饰符间单一空格——随后每层 ptr_expr `*`（printc.cc:75
  unary_prefix spacing=0）或 array_expr `[n]`（printc.cc:78 postsurround
  spacing=1）。连续指针层粘着：Pointer(Pointer(char)) 打 `char **`，
  Pointer³ 打 `ushort ***`；旧逐层 `" *"` 产出非 oracle 的 `char * *`。
  buildTypeStack 的 named-layer 早断（printc.cc:150）不镜像：Rugra 解析的
  嵌套指针携带显示名而 oracle 语料类型为匿名工厂指针，named 层截断会
  重新引入 `char * *`。
- `rpn_op_type_cast` 的 pushType（printc.cc:2013）同样走结构化折叠：旧
  `dt.get_name()` 直读外层原始名（make_ptr 造的 pointer-to-pointer 外层名
  就是 `char * *`），在 `*(char * *)stream` 泄漏处 oracle 打
  `*(char **)stream`；现改走 cast_type_string 同一折叠。

### 2026-08-26：GOTO-LABEL-UNPRINTED-0001 — goto 标号四症状族

**症状族**（httpd 首暴露）：① goto 目标 `code_r0x...:` 标号未打印
（undefined-label gcc 错误）；② `goto code_r0x0` 零地址；③
`if (( = ...)` 畸形 CBRANCH 链；④ goto 超发（goto_prints 恒 true）。

- `emit_any_label_statement` 重写为 cc:3219-3226 faithful 形式：
  only_branch 早退（cc:3201）→ 前叶下降（cc:3223，block.rs
  front_leaf）→ f_unstructured_targ + Basic|Copy 门（cc:3207-3208
  isUnstructuredTarget/t_copy）→ tagLine(0)+emitLabel+COLON（cc:3211-
  3213）。Rugra 侧传输层差异（均注释记录）：printed_labels 地址键
  once-guard 是 f_label_bumpup（block.hh:99）的传输——Rugra 结构树共享
  Basic 叶（Ghidra 复制 BlockCopy 子树），带标叶可从多个构造入口到达，
  必须恰好打印一次；discovery_pass / main_emit_id 门排除 NullEmit 发现
  pass 与捕获缓冲（标号打印进丢弃缓冲会既消失又占用 once-guard）。
  addr==0 防御跳过（GOTO-ZERO-TARGET-UPSTREAM-0001）。
- `emit_block_ops` 顶部调用 emit_any_label_statement：Ghidra 在每个
  构造入口（emitBlockCopy cc:2762、emitBlockList/If/WhileDo/DoWhile
  cc:2965/3014/3076/3104）对其子树调用；Rugra 构造发射器直接经
  emit_block_ops 发射 Basic 体/条件，前叶检查在同一入口执行。
- `emit_goto_statement`（cc:2303-2323）：零地址与非 block-start 目标
  防御跳过（GOTO-ZERO/UNIQSPACE/NEVEREMITTED-TARGET-UPSTREAM-0001，
  oracle 的 emitGotoStatement 总是收到活 FlowBlock，此形态无 oracle 对
  应物；上游登记在 TODO_BOARD）；GOTO 臂后接 pending_goto_labels 账本
  ——目标块稍后发射时 backpatch 标号（oracle 位置：带标叶自身），
  discovery_block_starts 不含的目标（结构器丢块，上游域）在 goto 点
  锚定（落入 fall-through，合法 C）。
- 平面 goto 尾（op_branch / op_cbranch / op_cbranch_rpn 的
  cc:575-578 折叠）：`flat_goto_target_valid` 白名单门——in(0) offset
  必须非零且属于 code_block_starts（doc_function 2a.5 收集
  fd.bblocks+结构图全部块 start；unique-space 改写 0x10000008/
  0x1000011F 等与 0x0 退化链永不是块 start，而真代码 offset 一定是）；
  拒绝则整段 goto 文本不打印，语句级 `;` 收尾 `if (cond);`（合法 C）。
  空间不过滤：结构器可把 in(0) 改写进 unique space 而保留真代码 offset
  （httpd ap_fini_vhost_config 观察 0x2D53A）。
- `cbranch_goto_info` 移除 Const/Ram 空间过滤（同上：offset-vs-
  block-start 是精确判据）。
- PTRADD/PIECE RPN push 臂补齐（printc.cc:880-893 opPtradd：
  printval→subscript 否则 binary_plus，in(1) 先 in(0) 后；printc.hh:333
  opPiece→opFunc，CONCAT<sz0><sz1> 函数式）——此前缺失使 stage-2 token
  悬空不平衡（`if (( = ...)` 畸形链的一环）。

**发现 pass 预种子（续）**：目标块在 goto 语句**之前**发射时 backpatch
已错过——`pending_goto_labels` 必须**先于** pass 2 预填。

- 2a.5 账本（code_block_starts/goto_targets/三个 clear）**上移到 pass 1
  之前**：白名单是结构图静态属性，发现 pass 的 goto 决策
  （flat_goto_target_valid / emit_goto_statement）同样要查；空表会使
  pass 1 抑制所有 op 级 goto、无法预填 pending_goto_labels（观察：
  code_r0x0002E679 ap_getparents、code_r0x0002DB30 ap_update_vhost_
  given_ip——goto 从平面尾打印时目标块的唯一发射已过，标号悬空）。
  pending_goto_labels 在此处 clear 后**不在 pass 2 前重清**（种子存活）。
- `discovery_emit_id`：发现 pass 主发射器（NullEmit）的身份。pass 1 的
  `record_goto_label_pending` 只认 main_emit_id / discovery_emit_id 两个
  身份——丢弃上下文（CaseDetectEmit 干跑、捕获缓冲）在**任一** pass 都
  不记录，保持两 pass 的 goto 集合相等；discovery_block_starts 的插入
  同样仅限 NullEmit 主发射器（只进丢弃缓冲的块不算主输出发射，误计会
  错误抑制 never-emitted 锚）。
- `emit_any_label_statement` 新增 Basic|Copy 挂起臂：叶未带
  f_unstructured_targ（Rugra 结构器留下未包裹的 goto 边，oracle 中
  ruleBlockGoto blockaction.cc:1450 总会包裹）但 pending_goto_labels
  含其地址（pass 2 中**稍后**才打印的 goto 亦可——两 pass 决策相同）。
  这是 oracle 顺序无关性的地址键传输：标号在本块发射点打印，与 goto
  文本在前在后无关。addr==0 防御保持。
- 平面尾标号扫描（emit_block_ops 两处）新增 `needs_anchor`：目标在
  pending_goto_labels 且不在 discovery_block_starts——无块会携带其标号，
  在本块语句后锚定（与 emit_goto_statement 的 never-emitted 锚同位，
  合法 C：跳转落到 fall-through 语句）。已发射目标仍排除（其标号归
  目标块自身）。

## 2026-08-29:组合名指针的声明 join 恢复 golden 形态(DECL-SPACING-NAMEFLOW-0001)

集成 w-anondecl3 匿名声明渲染后 E2E 出现 `char * pcVar4` 形(golden 为 glued `char *pcVar1`)。
根因分层:Ghidra `TypePointer(s,pt,ws)` 构造名为空(type.hh:412),生产指针皆匿名 →
buildTypeStack 钻取为多层栈 → ptr_expr(spacing=0)与标识符 glue;Rugra 的 debugproto 导入器
两处本地 helper(src/debugproto.rs:696 深度循环/:1337 pointer_type)组合名 "char *" 绕过工厂
直建命名指针 → 单层栈走了 type_expr_space。修复(printc.rs):`decl_prefix_ends_with_star`
与 push_type_start_opt 单层分支对"尾随 `*` 的组合名"按 drilled 语义 glue 标识符。
效果:skeleton 2198→2114(优于集成前 2118),六函数 typeless 装声明保持 0。
残差:fixture `printc_anonymous_pointer_decl_1204` 的 named_ptr_contrast 记录(真实 oracle
直驱动命名单层指针输出 `char * x`)与本修复的组合名 glue 可能分歧——待 full runner 复核;
根治方向=让 debugproto 指针构造改走工厂匿名路径(需核对 Ghidra DWARF 类型名的 XML 流转),
登记 DECL-SPACING-NAMEFLOW-0001。

### 2026-08-29：WhileDo body 门固定为 legacy flatten 路径（BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 residual）

- 背景：`identify_internal`/序列合并不再对被消费组件置 `DEAD`（oracle
  `BlockGraph::identifyInternal` block.cc:940-963 不设任何 flag；Ghidra 全仓
  `setDead()` 仅 funcdata_block.cc:333/370 的死基本块删除），printc 的 whiledo
  body 门（emit_structured_whiledo 及 overflow 臂的 `body_is_dead`）失去判定来源。
- 语义事实：BlockWhileDo 的 body 恒为被消费组件——旧 `DEAD` 测试在打印期恒为
  true，structured 分支从未在验证基线中执行过；拍平路径（`emit_block_ops`）
  才是 2134/0/1 基线的实际行为。
- 修改：两处 `body_is_dead` 固定为 `true`（保留 structured 分支供后续切换），
  附 BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 residual 注释。
- A/B 证据（2026-08-29 w-identify3）：no-f_dead WIP + 本固定 → curl E2E 输出与
  merge-base（9dbaf51d）**逐字节相同**（2134/0/1，main 696）；若改走
  printc.cc:2994-2995 规定的结构化发射，main 残留未结构化组件以 raw goto 形态
  暴露（+404 skeleton、numbering 1→2，main 1100）——该区域与
  NONCONVERGE-GETPARAM-MATCHURL-0001 同族，属结构化既有缺口，修复后可切换回
  oracle 规定的结构化发射。
parent of 7c3df2ce (fix: composed-name pointer declarations glue identifiers to the star run)

## 2026-08-29:组合名 glue 兜底撤销(DECL-SPACING-NAMEFLOW-0001 闭环)

根治修复 e331a5c5(w-anondecl3,六处构造点匿名化:coreaction make_pointer_type/make_ptr/COPY-spacebase、
typeop propagate_to_pointer、debugproto parse_c_type/pointer_type/DWARF 数组,全部改走 3 参
getTypePointer 空名形态)落地后,渲染层 glue 兜底(7c3df2ce)不再必要——生产指针已匿名,
buildTypeStack 钻取多层栈走 ptr_expr 原生 glue;命名单层指针(仅显式具名构造)恢复 oracle 的
type_expr_space 形态(`char * x`),与 fixture named_ptr_contrast 记录重新一致。

测试 `printc::tests::test_doc_function_leaves_action_scope_unchanged` 的 pcVar1 构造改为工厂匿名
`TypePointer::new(8, char, 1)`(生产形态,匹配 e331a5c5 匿名化),断言的 glued 输出不变。

### 2026-08-30：MAIN-RC3-STRUCTURED-EMIT-0001 — WhileDo/For body 门翻转为 oracle 结构化发射

- **翻转**:2026-08-29 固定的两处 `body_is_dead = true`(emit_structured_whiledo
  的 body 门,含 overflow 臂;emit_for_loop 的 body 门)按 oracle 条件评估——
  printc.cc:3061-3062 / 2994-2995 规定 `setMod(no_branch); beginBlock(getBlock(1));
  getBlock(1)->emit(this)`,**无条件结构化虚派发,oracle 没有 flatten 旁臂**。
  两处改为无条件 `emit_block_structured`(seen_return 域作用域保持)。
- **触发时机**:RC2(BlockGoto wrapped,MAIN-RC2-BLOCKGOTO-WRAPPED-0001)+
  guard-lattice 落地后,2026-08-29 记录的暴露面(+404 skeleton、numbering 1→2、
  main 1100)缩小为 **+58 skeleton、numbering 0→1、main 838→926**。
- **emit_comment_block_tree 的 BlockGoto 子表修正**:Ghidra `BlockGoto :
  BlockGraph`(block.hh:547),cc:3257-3263 的非 basic 递归走 `subBlock(i)` =
  BlockGraph 列表 = identifyInternal(ret,[bl])(block.cc:1706-1708)移入的
  **wrapped 组件**;旧代码取 `goto_target`(legacy 投影,实践恒 None)——改为
  `wrapped`。goto TARGET 不参与子块遍历。
- **E2E 差分(curl 12.0.4 golden)**:defects=0 保持;numbering 0→1(main 的
  `iVar4 declared twice`,见下残差);skeleton 3104→3162。逐函数:
  main +88、file2string.part.0 −16、parseconfig.constprop.0 −14、my_get_token −2、
  next_url +2。main 的 URL-glob 区现在与 golden 1:1 结构形态(含 golden 自身的
  `goto LAB_0010282a` 反向边、`LAB_00102873:` 标签、if/else 嵌套链、for 循环);
  next_url +2 = golden 的 `if (glob->size <= (int)uVar8) goto LAB_001050e7;`
  循环守卫首次发射(Rugra 以 `==0 || <` 规范两行形态)。httpd:baseline 与翻转
  **逐字节相同**(2178/4/0,4 defects 均为 master 既有)。
- **残差登记**(不回退,新 TODO):
  - `PRINTC-STRUCTEMIT-MAIN-IVAR4-DUP-0001`:main 结构化暴露区内 mid-block
    `int iVar4;` 二次声明(numbering +1),伴随 `fopen(...); if (...)` 同行
    (缺 tagLine 断行)——声明发射/行断点在结构化路径的缺口。
  - main 的 for 头部畸形(`for (var_8; iVar11 != 0; ...)`,golden 为
    `for (lVar13 = 0x26; lVar13 != 0; lVar13 + -1)`)——varmap for-init/iterate
    数据侧残差,先前被 flatten 汤掩盖。

### 2026-08-30:GLOBWORD-C3 — carry 族 opFunc 打印(printc.rs)

- **根因**(w-x86carry 双侧证明,docs/alignment_docs/CARRY-PRINT-ROOTCAUSE-2026-08-30.md):
  SLEIGH 提升的 INT_CARRY 完整存活到最终 IR(输出 implied),但 printc 无
  CARRY/SCARRY/SBORROW 分支——RPN 侧 `rpn_def_inline_reachable` 无臂(不可内联,
  叶 atom 走未命名位置)、`dispatch_op_rpn` 无臂、legacy 侧 `emit_inline_expr`
  落 `_ =>` fallback,CF(:register:200)打成 `register0x00000200`(curl 5 处)。
- **修复**(5 处,全在 printc.rs):
  1. `dispatch_op_rpn` 新臂 → `rpn_op_func`(opFunc printc.cc:424-442 的既有
     RPN 端口);
  2. `rpn_def_inline_reachable` 同族 → `has(0)&&has(1)`;
  3. 新 `rpn_operator_name_carry`:`CARRY/SCARRY/SBORROW + dec(in0 size)`
     (typeop.cc:1340/1356/1372 getOperatorName 移植,产出 CARRY1/SCARRY4/SBORROW2,
     大写非 pcode 名);
  4. `emit_inline_expr` legacy 臂:函数式语法,逗号 token spacing=0
     (printc.cc:54,`,` 无空格);
  5. 语句级 `op_func`:carry 族名 + 逗号改 `,`(原 `", "` 偏离 spacing=0)。
- **E2E 判据**:泄漏 `register0x00000200` 5→0;`CARRY1(` ×3;skeleton
  3162→3164(+2 = file2string.part.0/my_get_line 各 +1);defects=0;numbering
  不变。+2 行为规格 §3.3 预告的 cast 链残差现形(原泄漏行位置):
  参数 `(int *)uVar6` vs oracle `(byte)uVar7`(heritage piece-split 域)、
  外包 `(0 - (int *)(bool)(long)CARRY1(...))` vs `-(ulong)CARRY1(...)`
  (cast 链域)。typeop.rs functional_binary_op push 路由 opFunc(规格 §3.2)
  与上述两域均在 printc 租约外,登记残差待相应 owner。

### 2026-08-30:MAIN-RC3-STRUCTURED-EMIT-0001 补充 — overflow 头字节对齐

emit_structured_whiledo 的 overflow 臂头序列按 printc.cc:3023-3028 逐调用
对齐:`tag_op("while") + open_paren + spaces(1) + print("true") + spaces(1)
+ close_paren`(id1 配对传递)= 紧凑 `while( true )`(原实现拼字面量
`while ( true)`,两侧空格均错)。空格走显式 space token(oracle spaces(1)),
遗留后处理层的配套承认见 docs/api/prettyprint.md 同日条目(` )` 修剪豁免 +
四处 loop-ctx 检测补紧凑形)。回归:curl `while( true )` ×3 逐字节匹配
golden,3 处 if-break 保持,httpd 逐字节不变。

### 2026-08-30：PRINTC-STRUCTEMIT-MAIN-IVAR4-DUP-0001 — PendingBrace 动态模型移植（else { vs else if 的判定根因）

**Oracle（printc.cc:2872-2948 + prettyprint.hh:102/443-457/1129-1137）**：`emitBlockIf` 在
`isSet(pending_brace)` 时 `emit->setPendingPrint(&pendingBrace)` 安装一个**可取消的延迟开括号**
（`PendingBrace::callback` = `openBraceIndent(OPEN_CURLY, option_brace_ifelse)`，
option_brace_ifelse 默认 same_line，printc.cc:1591）。该延迟括号在**下一次 `tagLine()`** 时触发
（`emitPending`，prettyprint.cc:920/930；EmitNoMarkup::tagLine hh:557 不触发），即条件块一旦
发射真实语句就在父级 `else` 后面补出 ` {`；条件块为空时 printc.cc:2900-2902 才
`cancelPendingPrint() + spaces(1)` 合并成 `else if(...)`。函数尾部 cc:2946-2948 仅当括号已
触发（`getIndentId() >= 0`）才补 `closeBraceIndent`。

**Rugra 缺陷**：静态模拟——`emit_structured_if` 入口一次读取 `PENDING_BRACE` mod 决定
`merge_else_if`，条件块发射语句后仍按合并路径打印 `space + if`，同时丢失括号与换行。
MAIN-RC3 翻门后 main 的 fopen 区域暴露：`p_Stack_210 = fopen(...); if (...) {` 同行 +
裸 `else`，prettyprint `backfill_missing_locals` 把该行误判为函数签名注入 `int iVar4;`
（numbering+1 的直接来源）。

**修复（本 commit）**：
- `prettyprint.rs` Emit trait 新增 4 方法：`set_pending_brace`/`cancel_pending_print`/
  `has_pending_print`/`pending_brace_fired`（hh:446/451/457 + printc.cc:2877-2879 对应）。
  状态是 **Emit 基类**语义：EmitNoMarkup 与 EmitPrettyPrint 都保存槽位；仅
  EmitPrettyPrint::tag_line 在 push 前调用私有 `emit_pending()`（cc:920/930 顺序：
  emitPending → checkbreak）触发 ` {`；EmitNoMarkup 不触发（hh:557），因此其路径
  恒走 cancel+spaces(1) 合并——与 oracle 字节一致。
- `printc.rs emit_structured_if`：入口按 cc:2884-2885 安装；条件发射 + 注释树后按
  cc:2900-2905 `has_pending_print ? (cancel + spaces(1)) : tag_line`；goto 臂与函数尾
  按 cc:2946-2948 在 `pending_brace_fired` 时补 `close_brace_indent`（goto 臂先
  防御性 cancel，oracle 该路径 PendPrint 悬垂无既定行为）。

**验收**：curl 3119/0/**0**（numbering 1→0；main fopen 区域与 golden 同构：
`else {` + 标号 + 语句 + 换行 `if`）；httpd 2211/5/0（skeleton -1、defects 持平，无回归）。
curl 全量 skeleton 变化（+9 净）逐处核对均为同一形态修复：8 处裸 `else`+同行 `if`
恢复为 golden 的 `else {` 块结构（main/parseconfig/GetStr/SetHTTPrequest/glob 系列），
`else if` 合并点 6→6 不变（合并臂行为保持）。

### PRINTC-NESTED-DOWHILE-EMIT——emitBlockDoWhile body / emitBlockGoto wrapped 的结构化递归（2026-08-30）

**Ghidra 语义**：
- `PrintC::emitBlockDoWhile`（printc.cc:3068-3095）：cc:3078 `print(KEYWORD_DO)` 是**裸关键字**
  （无尾随空格；` {` 由 same_line `openBraceIndent` 补出，plain-text 发射器上 `do {` 恰一个空格）；
  cc:3080-3083 `pushMod(); beginBlock(getBlock(0)); setMod(no_branch);
  getBlock(0)->emit(this)` —— **body 经虚拟派发结构化发射**（body 是 BlockList 时按子块序递归，
  BlockIf 子块渲染 if/else），latch CBRANCH 被 no_branch 抑制；cc:3088-3093 `while` 尾部来自
  body lastOp 的 CBRANCH only_branch 重发射。
- `PrintC::emitBlockGoto`（printc.cc:2766-2778）：cc:2770 `setMod(no_branch)` 后
  cc:2771 `bl->getBlock(0)->emit(this)` —— **wrapped 块经虚拟派发结构化发射**；Goto 包裹的
  List/If/DoWhile 复合体按结构渲染（嵌套 DoWhile 打印 `do { ... } while(...);`），绝无平铺
  op-walk 侧臂；cc:2775-2778 仅当 `gotoPrints()`（block.cc:2881-2890：父在场时
  `gototarget front leaf != parent nextFlowAfter(this)`，父缺席恒 false）才发射形式 goto 语句。

**Rugra 缺陷**：`emit_structured_dowhile` 的 body 走 `emit_block_ops(dowhile_arc, true)`
（聚合 op 平铺），`emit_block_goto` 的 wrapped 走 `emit_block_ops(goto_arc, true)`——两处都把
结构子块塌缩成单次迭代语句。w-dowhile 的规则级修复后 main 已有 5 个 DoWhile 结构
（=golden），但 else-if 臂的 `Goto(208)→List(208)→If(150){DoWhile@0x28ec,@0x28f7}` 复合体被
goto 平铺，两个嵌套 DoWhile 丢失 `do {`（main `do {` 计数 3 vs golden 5）；同时所有 do-while
body 内的 break-guard If（golden 的 `if (lVar13 == 0) break;`）被平铺吞掉。`do ` 带尾随空格在
EmitNoMarkup 上产生 `do  {`（双空格，oracle 单空格）。

**修复（本 commit，PRINTC-NESTED-DOWHILE-EMIT-0001）**：
- `emit_structured_dowhile`：`print("do")` 裸关键字；body 改为
  `push_mod(); set_mod(NO_BRANCH); emit_block_structured(&dowhile_data.condition)` —— 与
  whiledo 兄弟（MAIN-RC3-STRUCTURED-EMIT-0001）完全同型的结构化递归；Rugra `BlockDoWhile`
  的 `condition` 字段即 Ghidra `getBlock(0)`（唯一 body 子块，block.hh:727）。`while (cond)`
  尾部仍读 dowhile arc 聚合 ops 的 last CBRANCH in(1)（带 R50 malformed-guard，不变）。
- `emit_structured_infloop`：`print("do")` 裸关键字（cc:3106 同型）。
- `emit_block_goto`：签名加 `graph`/`emitted`；wrapped 为结构块（非 Basic/Copy）时
  `emit_block_structured(&inner, ...)`（cc:2771 结构化递归）；wrapped 为 Basic/Copy 保持
  `emit_block_ops(goto_arc, true)`（聚合 op 列表与叶子等价，且该通道承载
  GOTO-LABEL-UNPRINTED-0001 backpatch + discovery 记账）。gotoPrints 判定不变。
- 调用点 `emit_flow_block` Goto 臂传 `graph`/`emitted`。

**验收**：curl 3121/0/0（defects/numbering 双零保持；skeleton 3089→3121，+32 行全部为
新恢复的结构行——golden 有而旧平铺丢失的 break-guard if / do-while 头 / else-if 臂 if-goto，
逐函数：main 885→886、glob_set 98→96、my_get_token 63→61、next_url/glob_word/getparameter
+9/+10/+15 为 goto 包裹结构体首次结构化渲染）；main `do {` 计数 3→5 = golden（638→639 位移）；
corpus `do {` 17→23。双侧 fixture `printc_dowhile_goto_emit_1204`（statement+raw 字节 MATCH，
runner `tools/run_printc_dowhile_goto_emit_oracle.sh`）。cargo test --lib 17 failed =
基线一致（funcdata 测试间状态污染，与本改动无关）。残差：next_url/glob_word/getparameter
新暴露的自指标 `goto X; X:`（goto_type 判定属 blockaction scopeBreak 族，非 printc 发射层，
登记待 blockaction wave 认领）。

## 2026-09-22 追加（BLOCKSTRUCT-MULTIGOTO-0001 — MultiGoto 发射委托 + goto case 语句）

- 分派器（emit_block_structured）与 emit_switch_case_body 补 `BlockType::MultiGoto` arm→`emit_block_multigoto`:纯委托 wrapped（block.hh:588 `getBlock(0)->emit(lng)`,printc.cc 无 MultiGoto 分支）——结构化子块走 emit_block_structured,Basic/Copy 叶走 emit_block_ops;multigoto 自身不发 goto 语句（其剥除边属于外围 switch 的 goto case）。
- `emit_structured_switch` per-case gototype arm（printc.cc:3334-3337）:`case_gototypes[i]!=0` → 标签组 + `emit_goto_statement(front_leaf_start_addr(case), bt)`（GOTO→goto/BREAK→break）,无 body 无追加 break——语句即 case;default 槽同理（`default_gototype!=0` → `default:` + goto 语句）。目标块留在图中由顶层发射承载 LAB 标签（GOTO-LABEL-UNPRINTED-0001 的 pending label 机制接线）。

## 2026-09-22 追加（PRINTC-SWITCH-EMIT-0001 核心 — InfLoop 及同族 body 递归发射）

2026-08-29 的 PRINTC-NESTED-DOWHILE-EMIT-0001 修了 dowhile/whiledo/goto 的结构化递归，
但 `emit_structured_infloop` 的 body 仍是 `emit_block_ops(body, true)` 平铺——InfLoop 包裹的
一切结构（switch-in-do-while 拓扑的 Switch、嵌套循环、break-guard If）全部被拍平成裸语句。
oracle `emitBlockInfLoop` printc.cc:3109 是 `bl->getBlock(0)->emit(this)` 虚分派递归。
本轮同型排查（逐个对照 oracle 是否递归）后改动三处：

- `emit_structured_infloop`（printc.cc:3097-3122）：补齐 cc:3102-3103/3121 的完整 mod 协议
  （`push_mod` + `unset(NO_BRANCH|ONLY_BRANCH)` 入口、`pop_mod` 出口——即使外层是 cc:2919
  setMod(no_branch) 的 if-body 也不渗入循环体）；body 由 `emit_block_ops(body, true)` 改为
  `emit_block_structured(&body, ...)`（cc:3108-3110 beginBlock/emit/endBlock 递归虚分派），
  与 whiledo/dowhile/for 兄弟（cc:3062/3083/2995）同通道。
- `emit_structured_switch` 的 control 发射（printc.cc:3320-3323）：由
  `emit_block_ops(&control, true)` 改为 `push_mod + set_mod(NO_BRANCH) + insert-first +
  emit_flow_block(&control)` + `pop_mod`——cc:3322 `getSwitchBlock()->emit(this)` 递归虚分派
  （今日 control 是 BRANCHIND 基本块，叶子 walk 字节等价；分派通道对未来结构化 control 保持正确）。
  insert-first 镜像 emit_structured_if 的双访模式：本访持有发射权，不被 once-guard 跳过。
- `emit_structured_whiledo` 的 overflow 臂条件发射（printc.cc:3030-3033）：由
  `emit_block_ops(&condition, true)` 改为 `push_mod + set_mod(NO_BRANCH) + insert-first +
  emit_flow_block(&condition)` + `pop_mod`——cc:3032 `condBlock->emit(this)` 递归虚分派；
  其后 `if (cond) break;` 的条件重放仍走表达式通道（emit_block_condition，不查 once-guard）。

排查结论（未改动，如实记录）：
- `emit_structured_if`（cc:2897/2912/2922/2933/2939）、`emit_structured_list`（cc:2789-2832）、
  `emit_structured_condition`（cc:2842/2848/2865）、`emit_for_loop` body（cc:2995）、
  `emit_structured_dowhile` body（cc:3083）、`emit_structured_whiledo` body（cc:3062）、
  `emit_block_goto` 结构化 wrapped（cc:2771）、`emit_switch_case_body`（cc:3339-3341）
  ——均已递归，无需改动。
- whiledo 普通臂条件（cc:3053-3056 comma_separate 重放）与 dowhile 尾部条件（cc:3088-3092
  only_branch 重放）仍走 `emit_block_condition`/文本缓冲表达式通道——非 body 平铺（机制不同、
  影响面全语料），留待专门 lane 评估。
- `emit_block_goto`/`emit_block_multigoto` 的 Basic/Copy 叶保留 `emit_block_ops` 通道
  （承载 GOTO-LABEL-UNPRINTED-0001 backpatch + discovery 记账）——已登记的偏离，本轮不动。
- InfLoop body 走 emit_block_structured 后，Basic 叶经 emit_flow_basic（有 discovery 记账、
  无 pending_goto_labels backpatch）——与 whiledo/dowhile/for 兄弟的既有取舍一致；若差分
  出现 label 缺失型缺陷，需把 backpatch 迁到 emit_flow_basic（同机制迁移，另行登记）。

## 2026-09-22 追加（PRINTC-COND-REPLAY-0001 — whiledo/dowhile 条件重放通道分派化）

上节遗留的两处条件缓冲通道（BL 判定"非 body 平铺，影响全语料条件文本，需专用 lane"）本轮
裁决并转换。**裁决：两处均为真偏离**（非 BL 过严）：

- **oracle 形态核实**（printc.cc 完整读证）：①whiledo 普通臂条件（cc:3053-3056）是
  `pushMod + setMod(comma_separate) + condBlock->emit(this) + popMod` —— **块级虚分派重放**，
  emitBlockBasic（cc:2678）在 comma_separate 下遍历条件块**全部** printed op（逗号连接、无
  tagLine、语句无分号，cc:2706-2719/2291-2292），CBRANCH 经 opCbranch 的 `yesparen=false`
  （cc:541）不再加自身括号；BlockCondition 组合成 `(A && (B))`（cc:2846-2868，second 半边
  才置 comma_separate）。golden 实证：ghidra_curl_1204.c:1592 `while (line = my_get_line(...),
  line != (char *)0x0)`、:1601 `while (__ptr = nextarg, cVar2 == '-')`、:2523、:2115
  （BlockCondition+comma 复合形态）——**表达式重放通道结构性无法产生该形态**（丢失
  comma-joined 副作用语句、BlockCondition 括号形态错为 `(A) && (B)`、块级 "1" 折叠）。
  ②dowhile 尾部条件（cc:3088-3093）是 `setMod(only_branch) + getBlock(0)->emit(this) +
  print(SEMICOLON)` —— 同为块分派重放：emitBlockLs 收缩到末子块（cc:2787-2791），
  emitBlockBasic only_branch 路径 print lastOp 表达式（cc:2686-2690）→ opCbranch，
  **`while (cond)` 的括号来自 opCbranch yesparen（cc:554-555），emitBlockDoWhile 自身不开
  括号**。Rugra 原实现 = 取 dowhile 聚合 ops 的 last CBRANCH in(1) → 丢弃式文本缓冲 +
  legacy value-scan 发射器（RPN 模式下也不走 RPN！）+ 文本级 malformed-guard（R50 折叠）。

- **改动**（src/printc.rs emit_structured_whiledo / emit_structured_dowhile）：
  - whiledo：补齐 cc:3012-3013 入口 `push_mod + unset(NO_BRANCH|ONLY_BRANCH)`（for 早退
    cc:3007-3010 之后、overflow/normal 臂之前）与 cc:3065 出口 pop；普通臂改为
    `emit_comment_block_tree(cond)`（cc:3048）+ `tag_op("while")+spaces(1)+open_paren`
    （cc:3050-3052）+ `push_mod + set_mod(COMMA_SEPARATE) + insert-first +
    emit_flow_block(&condition) + pop_mod + close_paren`（cc:3053-3057）；overflow 臂
    `if (cond) break;` 重放改为 `tag_op("if")+spaces(1)+push_mod+set_mod(ONLY_BRANCH)+
    emit_flow_block(&condition)+pop_mod+spaces(1)+break;`（cc:3036-3043，括号由
    op_cbranch_rpn yesparen 供给）；body 前补 cc:3060 `set_mod(NO_BRANCH)`。
  - dowhile：补 cc:3074-3075 入口 push/unset 与 cc:3094 出口 pop；尾部由文本缓冲整段替换为
    `spaces(1)+tag_op("while")+spaces(1)+set_mod(ONLY_BRANCH)+emit_flow_block(&body)+
    print(";")`（cc:3087-3093）。原缓冲通道的块级 R50 文本折叠删除（缺 in(1) 场景由
    op_cbranch_rpn 的 op 层 R50 transport 承接）。
  - 两函数注释由 RUGRA-GLUE 升格为 `// Ghidra: printc.cc:3001 PrintC::emitBlockWhileDo` /
    `printc.cc:3068 PrintC::emitBlockDoWhile`（blockarm 拆分前身的溯源更正）。

- **差分影响**（e40ed130 golden，fresh 基线=BL final）：curl **defects=0 numbering=0**、
  skeleton 3648→3649；httpd **defects=0 numbering=0**、skeleton 2462→2459；gcc 审计失败集
  逐函数恒等（curl 81/26、httpd 7/22）；printc 单测 12/12。条件文本形态变化明细：
  - **golden 形态落地**：`while (line = my_get_line(fp), line != 0)` 族 comma-init（golden
    1592/1601/2523 同构）；getparameter break 条件 `'['`→`']'`（golden 2253 `== 0x5d` 修复，
    原 legacy 通道扫错比较对象）；next_url `glob->size` 符号解析（原 unique0x00009100 泄漏）+
    `( *)` 退化 cast 与 unique 空间声明泄漏清除（my_get_token/next_url/httpd 多处）。
  - **+2 波动（match_url 97→99、parseconfig 197→199）**：条件块内残留 junk COPY 语句
    （`glob = filename`、`uVar6 = uVar6`、`__ptr = __ptr` 自拷贝）现随 comma_separate 全量
    walk 一并打印——**通道行为正确（打印条件块全部 printed op），多余 op 是结构/SSA 层差异**
    （golden 条件块已消除这些 copy）。登记 `PRINTC-CONDBLOCK-JUNKOPS-0001`。
  - httpd：overflow 臂 `if (cond) break;` 条件由 legacy 扫描值变为真实 CBRANCH 条件
    （`iVar3 == 0x1117e && ...`），机制正确。
## 2026-09-22 追加（SWITCH-BRIDGE-DUP-0001 — switch 头的 ONLY_BRANCH 表达式通道）

gp（getparameter.constprop.0）的 switch#2 重复桥工件（48 空 case + 孤立 `if` + `} {` 孤儿块，
~121 行非法 C）根因：**emit_structured_switch 无视 ONLY_BRANCH 修饰符整只重放**。发射路径
（backtrace 实证）：`InfLoop body List → If → condition List（末位子块 = Switch）`。
`emit_structured_if`（printc.cc:2894-2913 emitBlockIf）对 condition 双访问——第一访 NO_BRANCH
（语句 + 完整 switch = 文本 switch#1），第二访 ONLY_BRANCH（应只打分支表达式，却重放了整个
switch 头+48 标签+default，case 体已被 `emitted` 压制 → 全空 case = 文本 switch#2）。

oracle 通道对照：
- printc.cc:2911-2913（emitBlockIf 第二访 `setMod(only_branch); condBlock->emit(this)`）+
  printc.cc:2790-2794（emitBlockLs only_branch 臂 = 只发末位子块）——Ghidra 结构器保证条件
  终结块是 CBRANCH 基本块，该通道只会遇到 opBranchind。
- printc.cc:582-591（opBranchind）：switch 分发作为**表达式**的形态 = `switch(<expr>)`——
  关键字+开括号+索引表达式+闭括号，无 brace、无 case 重放、无 tagLine（表达式槽以
  spaces 与 `if `/`while (` 前缀衔接，printc.cc:2909/3033）。

Rugra 侧拓扑缺口（本修复的防御面）：`new_block_switch` 清 f_switch_out（block.cc:1917，与
oracle 一致）后，已成形的 BlockSwitch 可被 cat/proper_if 吸收——gp 的 dispatcher 被卷入
If 条件 List 末位（oracle 中该函数经 jumptable guard 折叠，golden 无此 If）。Ghidra 若真遇到
此拓扑，emitBlockSwitch cc:3316 `unsetMod(no_branch|only_branch)` 也会整只重放；Rugra 选择
把 ONLY_BRANCH 路由进 opBranchind 表达式通道（头文本逐字节一致），因为完整重放在表达式槽
永远不是合法 C。

改动：
- `emit_structured_switch` 入口增 ONLY_BRANCH 早退：`switch(` + 表达式 + `)`，立即 return
  （不重发 control 语句、不打 brace/cases/default）。
- 头部表达式解析逻辑（index_varnode → inline_candidates/value_def_map COPY 追逐 →
  BRANCHIND in0 → CBRANCH 比较回退）原样提取为 `emit_switch_head_expr`（RUGRA-GLUE 纯重构），
  全量头通道与表达式通道共享同一渲染。

验证：gp 730→645 行、case 标签 96→48、switch#2 空 case 桥与 `} {` 孤儿块消除；curl 全量
skeleton 3751→3653（−98）、defects=0、numbering=0；printc 域单测 12/12。残留（拓扑域，另行
登记）：条件槽 `if switch(iVar31) {`（1 行非法 C，待 BO/guard-folding lane 消 If）、双
default-check（If body 侧）、SWITCH-CASE-TAIL-0001（0x23/0x35 尾语句蒸发，未动）。

## 2026-09-22 追加（PRINTC-SWITCH-EMIT-0001 残差收口 — default 位置族 + 头形态）

三源登记（CR-BO 条件②/GP978_TRIAGE §2/PRINTC-SWITCH-EMIT-0001 补证）的 gp switch 残差
~24 行中的两族在本轮收口；条件槽 `if switch(...)` 残迹（SWITCH-BRIDGE-DUP-0001 残留，拓扑
域）未动，如实保留。

**① 头形态（`switch(iVar31)` → `switch((int)config_00 - 0x23 & 0xff)`）**：

- oracle 通道（printc.cc:582-591 opBranchind）：`pushVn(op->getIn(0),op,mods)` 在**打印时**
  读 BRANCHIND 的**活输入**。switchnorm（coreaction.cc:5684，fullloop 尾）晚于
  ActionBlockStructure（cc:5676，mainloop）——oracle 结构层从不缓存 switch 索引 varnode，
  头表达式永远反映 foldInNormalization（jumptable.cc:1546-1553）改写后的最终 IR。
- Rugra 根因：`BlockSwitch::index_varnode` 在 blockaction 结构化时快照捕获；gp 终态 IR 实证
  （RUGRA_DUMP_FUNC）BRANCHIND 输入已是 `AND(SUB(SUBPIECE(config_00),0x23),0xff)`（全 implied，
  outimpl=true），但打印读的是结构化时刻的陈旧 varnode（被 varmap 命名 iVar31）→ 印裸名。
- 修复：`emit_switch_head_expr` 先解析 control 块的活 BRANCHIND op，取其当前 in(0) 走
  `push_varnode`（implied 内联/常量/符号通道，即 pushVn 等价物）；无活 op 时保留快照回退。
  附带收益：glob_set 头 `*(( *)unique0x00008f00)` → `cVar1`（活输入=被加载字符）。
- 配套：`emit_inline_expr` 补 SUBPIECE 臂（printc.cc:843/872-877 opSubpiece fall-thru：
  isSubpieceCast → `(int)` cast（opTypeCast cc:451-462 语义），否则 `SUB81(x,0)` opFunc——
  镜像 RPN 通道 cc:2244-2272 同款逻辑）。此前该臂缺失使归一化链叶子落 `_ =>` 无名位置
  回退印 `unique0x1000026e`。
- 头残余（登记族，非本层）：叶名 `config_00` vs `pCVar10`（varmap 命名族）；`0x23` vs
  `0x23U`（常量后缀族——scalar helper 无 U/L 后缀，push_integer 注释自认）；httpd main 头
  现印未归一化派发表达式（该表 Rugra foldInNormalization 未折基，jumptable 上游域）。

**② default 位置（末位 → label 排序位第二）**：

- oracle（block.cc:3556-3592 finalizePrinting + printc.cc:3331-3332/3140-3145）：default 是
  caseblocks 普通成员（addCase cc:3515 isdefault 标注），label 取其基本块**首个表索引**
  （cc:3573-3576 getIndexByBlock(basic,0)→getLabelByIndex），与全部 case 一起按
  `(label,depth)` 稳定排序（cc:3591, block.hh:903-908 compare）→ `default:` 印在 label
  秩位（golden gp: case 0 → default → case 0xf，ghidra_curl_1204.c:1765-1769）。
- Rugra 根因：default 存独立槽 `default_case`，发射恒在常规 case 之后（自认偏差），且从不
  参与 finalize_case_labels 的 label 计算/排序。
- 修复：`BlockSwitch` 增 `default_label: Option<u64>`（finalize_case_labels 末尾按 cc:3573-
  3576 同款配方计算——front_leaf→original 基本块 + 首个表索引 label；`case_order`/`cases`
  长度不一致或无表索引时 None=保持末位旧位）。`emit_structured_switch` 按 label 秩插入：
  `def_pos = case_order.filter(label < default_label).count()`，循环内该位先发 default，
  末位则循环后发。break 语义按 cc:3342-3345 `isExit(i)&&(i!=numCaseBlocks-1)`：default 的
  isExit=addCase cc:3514 `sizeOut()==1`（goto/return 出口=sizeOut!=1 → 无 break，匹配 gp
  golden default 尾 `goto LAB_0010404b` 无 break；httpd 0x12f92a default 中位带 break）。
  last-case 的 `is_last_label` 同步泛化：default 中位时末 case 即最终标签（无 break）。
- 已知角落（vs oracle，注释已记）：default 为 fall-thru 链非根时 oracle 继承链根 label
  （cc:3577-3584），Rugra default 槽无链路，按自身首索引排位；语料未见该形态。

**验证**：gp `--func` 887→878 skeleton（case 0 → default → case 0xf 逐位= golden；CB 修的
0x23/0x35 尾赋值+break 原样保持；default 体不变仅位移）；curl 全量 3607→3595 / defects=0 /
numbering=0；httpd 2456→2458（+2：main 头活输入暴露该表 foldInNormalization 未折基的上游
差，jumptable 域登记）/ defects=0 / numbering=0；httpd ap_vhost_iterate_given_conn 与 CB 基线
逐字节恒等（37 行= jumptable 不可恢复既有差，未回归）；gcc 审计 curl 81/26、httpd 7/22 与
CB 基线恒等；printc 单测 12/12 + switch 1/1；block:: 5/5、jumptable 36/36。

## 2026-09-23 Lane DY (wt/printres):打印阶段残差簇分类账 + InfLoop 尾距发射修正

**基线**:master 47c9ad79,curl 2614/0/0、httpd 2331/0/0。按函数分解量化 printc 写域四个
登记族的实际 skeleton 贡献(分类脚本 /dev/shm/rugra-tests/sb-printres/classify.txt 谱系):

| 族 | curl 行贡献 | httpd | 修域裁决 |
|---|---|---|---|
| EQLEAK(CALLIND 赋值 ` = ` 泄漏) | 44 | — | printc 协议修复**已就绪**但被 prettyprint P6 拦截(下述) |
| INFLOOP 尾距 `} while ( true);` | 4 | 6 | printc 发射已修(本 commit);文本层 trim 拦截(下述) |
| LABSPELL(`code_r0x` vs `LAB_xxxxxxxx`) | ≤128(64/75 次出现与 golden LAB_ 地址精确对应) | ≤76(38/45) | 数据域:driver/varmap 需注入前端 LAB_ 代码标号符号 |
| BARE_TRUE(`= 1` vs `= true`) | 38 | 30 | 类型域:常量 varnode 面向类型非 bool(push_constant_typed Bool 臂已在) |

**① emitBlockInfLoop 尾距(printc.rs,已修)**:oracle cc:3112-3120 的字节序列是
spaces(1)+`while`+openParen+spaces(1)+`true`+spaces(1)+closeParen+`;` = ` while( true );`
(while 与括号间**无**空格,`true` 两侧各一空格)。旧发射 `" while ("`+`" true"`+`");"` 两处
都偏(括号前多空格、`true` 后缺空格)。已改为逐字面镜像 cc:3112-3120(emit 层字节现与
oracle 完全一致)。**注**:最终输出仍呈 `} while( true);`,因 prettyprint.rs 空白归一化
pass 的 ` )`→`)` trim 豁免门只认 `starts_with("while(")` 行头,而尾式行以 `}` 开头
(`  } while( true );`)——登记 PRINTC-POSTFIX-WHILETAIL-TRIM-0001(prettyprint 写域,被占);
豁免门扩到 `} while(` 后该修复即兑现 4+6 行收益。

**② CALLIND 赋值 RPN 协议(分析闭环,代码保持旧传输层)**:thunk 语句根 = emit_expression_rpn
对有输出 op 先 push assignment token + LHS 原子(cc:2474-2475),旧 CALLIND 臂直接
`emit.print("(*(code *)...")` 绕过 RPN 栈,赋值 token 的 ` = ` 分隔符从
printlanguage.cc:142-148 的 emitOp 路径泄漏到下一语句——curl 22 处 `uVar1(*(code *)PTR_x)();`
+ `return = uVar1;` 双残差形态。协议化修复(pushOp(function_call)+pushOp(dereference)+cc:649-669
三分支 pushVn/pushAtom)已在隔离测试(EmitNoMarkup 与 EmitPrettyPrint 双验证)与 corpus
低层字节 dump 双证实:修复后低层缓冲即 `uVar1 = (*(code *)PTR_00116e98)();`+`return uVar1;`
(golden 同形)。**阻塞**:EmitNoMarkup::post_process 的 P6 单用变量内联(prettyprint.rs,
Rugra-only 补偿层)对修好的合法 `uVarN = <callind>();` 行按 count==3 内联+死代码消除,
把 thunk 体清空(净回归)。登记 PRINTC-CALLIND-RPN-ASSIGN-0001(修复就绪)+
PRINTC-CALLIND-P6-NULLIFY-0001(prettyprint P6 门,被占域)——P6 门解除后协议臂即可落地
(代码注释保留完整移植说明与臂位)。

**③ LABSPELL 量化(登记 PRINTC-LABSPELL-LABSYMS-0001)**:golden 的 `LAB_00xxxxxx` 来自
oracle emitLabel cc:3173-3181 的 queryCodeLabel 路径(Ghidra 前端在反汇编跳转目标建 LAB_
标号符号);Rugra 无此符号数据,恒走 cc:3183-3192 泛型 `code_r0x` 臂。地址级核对(curl 基址
0x100000/httpd 0x100000):curl 35 个 code_r 地址中 30 个(64/75 次出现)与 golden LAB_/
joined_r 地址**精确重合**,httpd 23 个中 19 个(38/45)重合——拼写对齐后每处消除 1A+1D
两行,潜在 curl ~128/httpd ~76 行。修域=examples driver 或 varmap 注入 LAB_ 符号
(地址集合=跳转目标=lift CFG 可得),非 printc。

**④ PRINTC-LABEL-WITHOUT-GOTO-0001 勘误(证据更新)**:my_get_token 0x37b2 等curl 7 处/
httpd 3 处 label-only(无 goto 消费者)经全 setter 插桩(BlockGoto 2856-2864 的 gotoPrints 门
/BlockIf 3067-3073/BlockSwitch 3603/mark_front_leaf 全量 trace)证实:**UNSTRUCTURED_TARG
从未经任何 markUnstructured 路径落位**——叶 BlockCopy flags=0x230020(0x20+0x2000+
0x200000),其 original 仅 0x30000;0x20 于 BlockCopy 创建后出现,且指向该地址的 goto 在
终态树中**从未到达 emit_block_goto**(0 trace)。修域=blockaction/block flags 生命周期
(被占);printc 消费侧(emit_any_label_statement flagged 臂)对旗标语义本身忠实。

**三门禁 + 双投影**:curl 2614/0/0(==基线,逐函数 diff 恒等零回退)、httpd 2331/0/0(==
基线)、next_url+match_url Phase 2 投影 **MATCH 保持**(stage_bisect --v1 vs
/dev/shm/rugra-tests/sb-oracle 钉板);printc 单测 12/12;gcc 审计 curl 82OK/25FAIL==基线;
lib 串行 1650/18(失败集=既有 flaky 家族)。

## 2026-09-24: CALLIND 协议臂启用 + pushType 声明符栈化(RESIDMAP-PLTSTUB-EMITSHAPE-0001)

- **`dispatch_op_rpn` 的 `CPUI_CALLIND` 臂由直印通道切换为 RPN 协议通道**
  (PRINTC-CALLIND-RPN-ASSIGN-0001 落地,解除 PRINTC-CALLIND-P6-NULLIFY-0001
  阻塞):逐字镜像 printc.cc:640-670——pushOp(function_call)+
  pushOp(dereference)+ 三分支(count>1: in0→count-1 个 comma→逆序实参;
  count==1: arg→in0;count==0: in0+EMPTY blank)。语句根
  emit_expression_rpn 的 assignment token 经 rpn_push_op 的
  emitOp(revpol.back()) 恰好在调用文本前发火 ` = ` 分隔符——修复
  `uVar1(*(code *)PTR_x)();` + `return = uVar1;` 泄漏形(curl 22 处)。
  `(code *)` 面向 cast 在 **rpn_recurse 的 calltarget 运输点**传输
  (PRINTC-CALLIND-CODECAST-0001 打印侧半):oracle 的 setcasts CAST 在
  pushVn(in0) 排空点经 opTypeCast(printc.cc:459-462)分派
  pushOp(typecast)+pushType(code*);Rugra IR 把 code* 类型直载在输入
  varnode 上,故同一对 push 在排空点(隐式/叶子两形都盖)镜像——
  `(*(code *)PTR_strcpy_00116e90)()` 与
  `(*(code *)*(BADTYPE **)(iVar1 * 8 + 0x16c48))(a,b,c)`(__libc_csu_init
  隐式 LOAD 目标)双形 canon 字节一致。
- **`push_type` 声明符栈化**:printc.cc:1472-1478 的 pushType =
  pushTypeStart(ct,true)+EMPTY 原子+pushTypeEnd(ct)——完整声明符栈渲染,
  而非裸 get_name()。工厂匿名指针类型(名字为空,如 libc 签名表的
  `char *` 返回)裸打印为零文本,即 PLT stub 签名丢失返回类型的根
  (` strcpy(...)` vs canon `char * strcpy(...)`,D 族①;
  next_url/match_url 的 DWARF 指针返回同根修复)。签名通道
  emit_prototype_output→push_type 不变,类型经
  push_type_start_opt/push_type_end_opt 渲染;printlanguage trait 的
  pushType 虚签名同步改 &Arc<Datatype>(Rust 侧 Ghidra `const Datatype*`
  的共享等价)。
- 门禁:curl 2005/0/0(−140,亲父 9458a61b);12 stub 函数
  strcpy/strchr/strrchr/fgets/memcpy/malloc/realloc/fopen/strcat/strdup/
  strstr/__ctype_b_loc diff 11→7(签名行+PTR 标签行+发射形已 MATCH;余
  7=①局部类型/`(char *)` cast(heritage 通道,登记
  RESIDMAP-PLTSTUB-VARTYPE-0001)②警告 3 行(PLTSTUB-WARNLOSS/JUMPTABLE
  域));free/puts 等 void stub 体 `(*(code *)PTR_free_00116e80)();` 全
  canon MATCH;gcc 审计 82→104 OK。
## RESIDMAP-NEGRIDX-PRINTFAMILY-0001（2026-09-24，wt/idxemit，基 3925922a）
A 族（FP top1 下标形缺失 ~41/~170）print 侧三件套落地：
**① checkArrayDeref 移植（printc.cc:353-369）**：`check_array_deref` —— 地址 vn 必须
implied+written，SEGMENTOP 解包到 in(2) 后 def 必须是 PTRSUB/PTRADD，其余形态（叶子
符号/CAST/算术）一律 `*(addr)` deref 形。opLoad（cc:487-498）/opStore（cc:500-518）
按 oracle 接线：`usearray && !force_pointer` → `m |= print_load_value/print_store_value`
（值 mod 下传），否则 pushOp(dereference)。值 mod 经 nodepend.vnmod → rpn_recurse →
dispatch_op_rpn 传递，由 CPUI_PTRADD 臂（cc:880-893 printval/subscript 分支）消费成
`p[i]` 下标形。实证：httpd main 正向偏移族 `*(puVar10 + 0xb)` → `puVar10[0xb]`、
curl `(&glob->literal)[SEXT48(i)]` 族全转下标；负向偏移族（~102 处
`*(undefined8 *)((int *)puVar10 - 8)`）维持 deref 形——直接 oracle（direct-runner
golden 3206-3217 行）同位同形 `*(xunknown8 *)((int8)piVar10 + -8)`，判据=该族 IR 是
CAST(undefined8*,INT_ADD(CAST(int*,X),-8))，checkArrayDeref 按 oracle 语义必须 false；
彻底转 `p[-1]` 需 ruleaction 域 INT_ADD→PTRADD 元素重标度（FV2/FW2/FS3 在飞，非本 lane
写域）。
**② opPtrsub STRUCT/UNION 臂 arrayvalue 补全（cc:1011-1016/1037-1038/1053-1054）**：
fieldtype 为 ARRAY 时 `arrayvalue = valueon; valueon = true`（`&` 抹除），valueon 路径
追加 `[0]` 后缀。实证：curl `*puVar18 = pUVar15->literal;` → `*puVar18 = pUVar15->literal[0];`
（canon 742 行同形）；next_url `(&glob->pattern)[SEXT48(iVar4)]->type` →
`glob->pattern[SEXT48(iVar4)]->type`（`(&glob->` 10→0；余距=SEXT48+`->`vs`.`，他族）。
**③ opPtrsub SPACEBASE 臂栈符号回查（cc:1057-1097 stand-in 扩展）**：oracle 的 symbol
来源是 linkSymbolReference 挂接（variable.cc:419-432，对 stack 引用查 fd->getScopeLocal）
——Rugra stand-in 原先只查全局容器（栈 PTRSUB 恒 miss → `&0xffffffffffffff38` 裸偏移形）。
补：spaceid==Some(Stack) 且全局 miss 时查 `self.scope`（snapshot_local_scope 的 ScopeLocal
快照）`find_container_entry(Stack, in1const, 1, None)`（Scope::findContainer 同构，
database.cc:2262-2282），仅整符号命中（entry.start==in1const && entry.offset==0，对应
cc:1084-1086 off==0 pushSymbol）打印符号名；mid-symbol 命中仍走 unnamed（partial-symbol
仍是 PRINTC-SPACEBASE-PARTIALSYM-0001 残差）。ARRAY 符号按 cc:1064-1067 抹 `&`。
实证：`puVar10 = (undefined8 *)&0xffffffffffffff38;` → `puVar10 = (undefined8 *)auStack_c8;`
（direct oracle 3198 行 `piVar10 = (int8 *)axStack_c8;` 同形）、httpd 17 处裸偏移全消。
**三门禁（亲父 3925922a 基线 curl 2147/httpd 2059/gcc 82-25）**：curl **2119/0/0**（−28）、
httpd **1899/0/0**（−160）、gcc 82OK/25FAIL 恒等；next_url 92/match_url 46/parseconfig 83
三投影 defects=0 numbering=0 保持；双跑字节恒等；printc 单测 12/12；lib 串行 1682/18
（失败集=FUNCDATA-TESTS-FLAKY-0001 既有集逐名相同）。
## 2026-09-24：RESIDMAP-PRINTBATCH —— 浮点转换三元组 RPN 发射 + 隐式内联可达表补齐
- `dispatch_op_rpn` 新增三个此前落入空 catch-all（静默丢操作数）的浮点转换臂：
  - `CPUI_FLOAT_INT2FLOAT` → 新 `rpn_op_float_int2float`（printc.cc:830-842
    `PrintC::opFloatInt2Float` 逐字镜像）：先做 `absorbZext`（typeop.cc:1864-1880
    ——in0 written+implied 且 def 为 INT_ZEXT 时打印穿透到 zext 的输入），再
    `pushOp(&typecast)+pushType(out 类型)` 后推入（可能穿透的）输入，输出
    `(float)x` 形；
  - `CPUI_FLOAT_FLOAT2FLOAT | CPUI_FLOAT_TRUNC` → 复用 `rpn_op_type_cast`
    （printc.hh:326-327 两虚函数均转发 `opTypeCast`——宽/窄浮点转换与浮点截断
    都是 C 可转型）。
- `rpn_def_inline_reachable`（RUGRA-GLUE 谓词，PRINT-RPN-0001 残留）补齐上述
  三 opcode（`has(0)` 单目臂）：此前隐式 FLOAT_INT2FLOAT 输出因谓词 false 走
  叶原子回退，无符号 High 落 `pushUnnamedLocation` 泄漏
  `register0x00001200/00001240`（XMM0_Qa/XMM1_Qa 浮点临时）。修复后按
  printlanguage.cc:526-533 `recurse` 的隐式分支内联 def op，curl myprogress 打出
  canon 同形 `fVar9 = (float)uVar7 / (float)(dltotal + ultotal);` 与
  `__sprintf_chk((double)fVar8,...)`。
- 差分门禁（机制 B，白名单文件）：curl **2131/0/0**（基线 2145/0/0，−14，唯一
  形变函数=myprogress）、httpd **2057/0/0**（==基线，字节恒等）；双跑 cmp 恒等；
  gcc 审计 curl 82OK/25FAIL（==基线——myprogress 残余 FAIL 为 uint8 typed 拼写
  族 EQ3 ⑤，非本域）/httpd 9OK/20FAIL（基线 21，−1=ap_make_dirstr_prefix）。
  register0x token 族：curl 9→0、httpd 4→2（残 2=main 未恢复跳表的 RAX 开关
  变量，I 族 JUMPTABLE-TABLEAPI 域）。

## 2026-09-24（HTTPD-CODEREF-SYMBOLIZE-0001）：常量叶片函数符号化 + opPtrsub TYPE_CODE 臂接通

httpd L1 破零车道（wt/l1zero）。canon golden（analyzeHeadless 产物）对
分析器发现的代码引用函数印 `FUN_0012dc80` 形（如
`apr_pool_cleanup_kill(param_1,param_2,FUN_0012dc80)`），Rugra 此前印
`0x2dc80`。oracle 的类型运输链 = Parameter ID 分析器把锁定函数指针类型
挂在参数上（typeop.cc:703-708 TypeOpCall::getInputLocal 的 locked-param
臂）→ ActionInferTypes 经 HighVariable 播类型（coreaction.cc:5016-5036）
→ pushConstant TYPE_PTR→TYPE_CODE 臂（printc.cc:1786-1788）→
`pushPtrCodeConstant`（cc:1730-1742：默认代码空间 + 全局 scope
`queryFunction` → displayName 原子）。Rugra 打印侧叶片追查绕过携带注解的
SSA varnode（legacy value_def_map 侧表），常量叶片可能无类型到达。三处落地：

- **`constant_leaf_text` 的 None/Unknown 臂**（PRINTC-UNTYPEDCONST-CODEQUERY-0001
  修订）：oracle 该两臂是**纯 `push_integer`**（printc.cc:1766-1768 TYPE_UNKNOWN /
  cc:1744-1816 无 None 形——`Funcdata::newConstant` 给每个常量
  TYPE_UNKNOWN 基型），**不做任何符号查询**；`queryFunction` 门是
  TYPE_PTR→TYPE_CODE 专属（cc:1786-1788 → `pushPtrCodeConstant`
  cc:1730-1742）。曾在此两臂接 `code_entry_constant_text`
  （HTTPD-CODEREF-SYMBOLIZE-0001 transport，RUGRA-GLUE 包装 sentinel
  `code*` 走 cc:1730 解析链）——GEN-CODEPTR-SYMBOLIZE-0001 装上 print-DB
  后揭出其为预存偏差：值与注册函数入口碰撞的整型常量被误印函数名（sq
  `write_file`: `mknod(V,0x6000,…)` mode 位 0x6000==`_init`@0x6000，golden
  印 `0x6000`）。已删除；read-facing high 缺答时回退咨询 `vn.v_type`
  （驱动参数锁注解的落点）保留。oracle 真值（locked-oracle 探针亲证，
  sqlite3FixInit）：LEA 派生的函数地址常量经 **ActionConstantPtr**
  （coreaction.cc:1070-1217 `isPointer`→`queryContainer`）→
  `Funcdata::spacebaseConstant`（funcdata.cc:360-462）改写为
  `PTRSUB(#0x0[spacebase* typelock], off)` 且 offset 常量的 high 携带
  FunctionSymbol → `op_ptrsub` TYPE_SPACEBASE 臂（printc.cc:1057-1097）
  `pushSymbol` 印裸名——**函数名从不经 pushConstant 无类型臂**；该链要求
  符号 DB 在 action 管线**之前**可用（gen 驱动 print-only 后装 DB 使
  ActionConstantPtr 恒 miss，见 GEN-CONSTPTR-ANALYSISDB-0001）。
- **`op_ptrsub` 的 TYPE_SPACEBASE 臂补 cc:1068-1069**
  （`PRINTC-SPACEBASE-TYPECODE-0001` 解锁）：容器命中符号的 metatype 为
  CODE 时 `valueon = true`——函数符号不打 `&`（canon
  `apr_pool_cleanup_kill(V,V,FUN_0012dc80)` 裸名实参形态）。解锁前提 =
  driver 侧符号 Database 的全局 scope 经 `Scope::add_function` 注册函数
  符号携带 Code 类型（database.cc:514-520 buildType），CODE 命中可达。
- 驱动层（examples/httpd_decompile.rs）：反汇编流 const 空间输入收割 +
  exec-range/已知入口/endbr64 三门验证为分析器函数发现面；打印期
  per-function Architecture 克隆挂只读符号 DB（action 侧查询通道保持
  channel-absent，canon 基线管线语义不变）；函数块间发射双空行分隔
  （golden emitter 布局，`}\n\n\n/* ----`）。

门禁（基线=亲父 b25bce7a）：httpd 门禁面 2072→**2070/0/0**（ap_pregfree
2→0，首个真代码函数体逐字节 MATCH）；httpd 全量 25997→25989/0/0，
**byte-exact 真代码 0→11**（ap_pregfree/ap_close_piped_log/
ap_create_request_config 等）；curl 1995/0/0 字节恒等；三投影
next_url/match_url/parseconfig MATCH 保持；getparameter ord351/
myprogress ord399/httpd main ord83 前沿不动。gcc 审计 8OK→7OK：
ap_pregfree 孤立块引用 `FUN_0012dc80` 无前向声明——canon golden 孤立块
同形（FUN_ 定义块在 golden:5034，Rugra 29 函数门禁面不含该块），非打印
缺陷。
## 2026-09-24：枚举元类型常量走成员名臂（Lane GG2）
`constant_leaf_text` 与 `push_constant_typed` 增 `TypeMetatype::Enum` 臂：
精确成员名，否则无符号整数（printc.cc:1666-1691 pushEnumConstant 的 no-match
else）。Ghidra 把枚举存为 TYPE_INT/TYPE_UINT + enumtype 旗标（TypeEnum::decode
type.cc:1475），故其 TYPE_UINT/TYPE_INT 臂可达 pushEnumConstant（cc:1756/1763）
——Rugra 的 Enum 元类型即该 enum-int/uint 折叠，取同一成员名路径。锁定见证：
`return CURLE_OK;`（main_init）、`*store != HTTPREQ_UNSPEC`（SetHTTPrequest）。
TYPE_PARTIALENUM 保持 Ghidra 的默认 cast 臂。同时移除 lane 前代遗留的
[DBGSTR] TEMP-DBG 块。
## 2026-09-24（Lane SMALLFIX 重钉）：Enum 元类型两臂自 GG 合并丢落后恢复
GG lane 手工并集（260a046c）保了 master 的 cast-先行路径，上述两处
`TypeMetatype::Enum` 臂（af6c5ee2/26109524 已交付）被丢回 `_` 默认 cast 臂——
`enum_match_text`/`enum_rep_text`（get_matches 全表示）与 datatype.rs 的
`TypeEnum::get_matches` 移植本体未丢，仅两处分派臂缺失，DWARF 枚举常量全量回退
`(HttpReq)0x...` 形。本 lane 按上述 GG2/CR29 原语义恢复两臂（常量叶
`constant_leaf_text` 与直发 `push_constant_typed`），见证回归：getparameter
`& ~HTTPREQ_HEAD) == HTTPREQ_UNSPEC`/`& ~HTTPREQ_SIMPLEPOST`（golden 1845/
1981）、main_init `return CURLE_OK;`、SetHTTPrequest `HTTPREQ_POST` 族；
TYPE_PARTIALENUM 仍走默认 cast（printc.cc:1801 break 表）。
## 2026-09-24：STORE 左值双打印修复 + MapIterator end 键（前代 WIP 收编核证）
opStore cc:500-518 端口修正：deref 形先 pushOp(dereference) 再单次
rpn_push_in(op,1,m)——旧实现 tag_op("*") + 未递归首推 + 二次输入推送使 RPN
栈残留重复左值（`*urlnum*urlnum = ...`）。maptable 静态序键增 end（rangemap.hh
:100-102 AddrRange (last,subsort) 序：同 start 先结束者先访问）。
## 2026-09-24（CR29 返工）：枚举常量渲染接 get_matches 全表示
datatype.rs:3223-3290 早已完整移植 `TypeEnum::getMatches`（type.cc:1365-1414，
两遍贪心+补码，a1bcaea6）——此前 enum 两臂（enum_constant_text /
push_enum_constant_named）走 BTreeMap 精确单名切片且注释误称"无 getMatches
移植"。修正：两臂共用 `enum_match_text`（get_matches → `enum_rep_text` 中缀
投影：`A`、`B|A`（贪心自最大命名值起，与 namemap 反向迭代同序）、`~A`、
`~(B|A)`、`>> n`（amount=4 字节无符号，printc.cc:1683）；无表示回退无符号
整数（cc:1684-1686，`false` 签参对 enum_int 同样硬编码）。括号决策随 token
协议：`|` 在一元 `~` 下或作 shift_right 左操作数时包裹，单名不包。新增
enum_match_text_renders_getmatches_representations +
enum_rep_text_covers_shift_forms 单测（shift 形态经 rep 直驱——getMatches
自身恒产 shiftAmount=0，同 type.cc:1370 构造默认）。
## 2026-09-24：枚举成员名臂与 MapIterator end 序键自 GG merge 丢失中恢复（Lane REGWIN）
260a046c（GG lane 集成）合并冲突解决取 mainline 侧 printc 重构时，静默丢失
GG2/CR29 三个 hunk，致 dc7a0d0a 起 main_init/glob_url/SetHTTPrequest.part.0
各回吐 2 行（INFRA-3 记分板"7 函数微回归窗"中的真实回退子集；其余 4 个
——_init 8/FUN_00102020 2/__cxa_finalize 2/progressbarinit 2——为窗口内
未动的存量残差）。恢复+强化：
1. `constant_leaf_text` 与 direct-emit 常量 match 的 `TypeMetatype::Enum` 臂
   （枚举成员名渲染，`return CURLE_OK;`/`HTTPREQ_UNSPEC`）两处恢复——
   oracle 依据 printc.cc:1750-1764 TYPE_UINT/TYPE_INT 臂 isEnumType() 分流 +
   TypeEnum 构造器/decode 把 metatype 归一为 INT/UINT（type.hh:487-491、
   type.cc:1475），Rugra Enum 元类型为该折叠的建模，落 `_` 兜底臂即成
   `(CURLcode)0x0` cast 形。
2. statics 排序键改为 (space rank, end, usepoint)——较丢失的 GG2 4 键
   (space, start, end, usepoint) 更贴 oracle：MapIterator 按 space 表序 ×
   空间内 AddrRange (last, subsort) 纯 end 序（database.hh:377-389、
   rangemap.hh:88-91），start 不参与键。glob_url 声明块（iVar1=EAX[0,4)
   先于 sVar2=RAX[0,8)）由 end 分量恢复。
E2E：curl 1438→1334（−104，3 目标函数归零，main 285→267、getparameter
433→385、next_url 65→57、match_url 40→32，零新增回退）；httpd 门禁面
1447→1441（−6）；双跑恒等；defects/numbering 双侧 0。已知代价：httpd
ap_fini_vhost_config 237→239（iVar7 声明移位，LCS 位置性 +2，函数存量
残差 237 行远未清零；登记 REGWIN-VHOST-DECLORDER-0001）。
## 2026-09-24：emitScopeVarDecls 遍历序钉死为 rangemap 插入拼接序（Lane VHOST / REGWIN-VHOST-DECLORDER-0001）
REGWIN 换 (space rank, end, usepoint) 纯序后 ap_fini_vhost_config 237→239，
本 lane 按 oracle 原文逐行核对排序语义完整体，结论：
**MapIterator 解引用的是 per-space `std::list<SymbolEntry>` 的列表序，不是
排序好的 AddrRange 多重集**（database.hh:379-401 `curiter` 为
`list<SymbolEntry>::const_iterator`；database.cc:1889-1919 `begin()` 从
`begin_list()` 起步）。列表序由 `rangemap::insert`（rangemap.hh:221-277）
的 splice 决定：每条新记录插到"键（细化片含端 last，EntrySubsort）>= 新
记录整域键 (b,subsort) 的首个 AddrRange 属主"之前，无则表尾追加；键来自
公共细化的**分裂片含端**，外扩记录的分裂片可充当 splice 靶，故列表序在
嵌套形态下**并非**纯 (end, subsort) 排序（P=[5,6) 先插、Q=[0,10) 追加、
N=[0,3) 落 Q 的 [0..4] 分裂片后 → P,N,Q，纯序为 N,P,Q——单测
`test_scope_rangemap_list_order_enclosing_piece_capture` 固化）。
实现替换为逐条重放：`scope_rangemap_list_order`（rangemap.hh:223 insert +
piece 循环 + 尾余片）+ `scope_rangemap_unzip`（rangemap.hh:196 边界分裂，
只动 first 不动键故属主位置稳定），EntrySubsort 投影 addrtied→(0,0)、
其余 (1, 首用偏移)（database.cc:97-109；局部 uselimit 共享代码空间），
等键多重集摆放按 C++ 语义（plain insert 排等键后、hint insert 等键时落
hint 前）。
验证（CARGO_TARGET_DIR=sb-vhost，基线 4a67708e 干净 worktree 亲测 A/B）：
curl 1329/0/0 与 httpd 1445/0/0 **双侧 stdout cmp 逐字节恒等**——即当前
语料（含 17 个同空间重叠 scope、ap_fini 的 [0,3)-in-[0,7)×5 与等域回收
形态）上纯序 == 拼接序，REGWIN 修复本就 oracle 精确；ap_fini_vhost_config
维持 239，其与 golden 的 +2 为 varmap 域符号集差异（extraout_RDX×3/
uVar15/in_RIP/unique 集形状）的 LCS 位置性残差，非 printc 排序缺陷
（残差移交 MAIN2 varmap/merge 车道）。10/10 投影 bank MATCH；cargo test
--lib 1708P/1F（唯一失败 test_nonzeromask_pipeline_wiring 为基线预存，
A/B 同败）。新增 3 个单测：vhost 寄存器块 17 条目手工追踪、外扩片捕获
形态、addrtied 最小 subsort。

## 2026-09-24 (Lane MAIN2) — cast render reads the def-facing type; PTRSTAMP stops overwriting finalized casts

三件修复（PRINTC-CASTDEF-0001 / PRINTC-PTRSTAMP-CAST-OVERWRITE-0001 / 附带 deref 装饰拼写）：

1. **CAST 内联臂改读 def-facing 高类型**（`emit_inline_expr` 的
   `OpCode::CPUI_CAST` 臂）：oracle `PrintC::opTypeCast`（printc.cc:448-464）
   读 `op->getOut()->getHighTypeDefFacing()` 并经 `pushType` 的结构化拼写
   渲染，从不读 varnode 的 v_type 原名。旧臂打印 `v_type.get_name()`，会把
   印刷期 fallback 戳的合成 `int *` 名泄漏成 `(int *)`。现走
   `cast_type_string`（与 RPN 臂 `rpn_op_type_cast` 同一拼写核心），无类型
   时保持 `long` 兜底。
2. **load_addr_direct 戳排除 CAST 定义**（两处收集臂：直连地址槽成员 +
   INT_ADD 输入成员）：ActionSetCasts 定型的 CAST 输出携带终态 cast 目标
   （coreaction.cc:2702-2712；Ghidra 在 setcasts 之后没有任何类型写者）。
   旧截记把 `long` 覆写成合成 `int *`，SP-alias 地址链印成
   `(int *)puVar10 - 8`（4× 偏移语义错误 + 非 oracle cast 形）。CAST def
   现与 ZEXT/SEXT/SUBPIECE/PIECE/INSERT 并列排除（INDPTR lane A/B 预验
   44 行方向）。修复后 httpd main 该族 44 行印
   `*(undefined8 *)((long)puVar10 + -8) = …`，与 canon
   `((long)plVar11 + -8)` 逐字同形（仅变量名/基址差）。
3. **typed dereference 装饰改用结构拼写**（legacy LOAD/STORE 地址装饰）：
   `cast_type_string` 替代 `get_name()`，对匿名工厂指针不再产出空名
   `*( *)` 形。

单测：printc 15/15。门禁见 lane 终报（httpd 1445→1405、curl 1329→1262，
defects/numbering 全 0，五投影 MATCH，逐函数零回退）。

## 2026-09-25（JTEDGE-FUSED-DEST-SPLIT-0001 / BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001）：case 出口语句的 oracle 语义恢复

flow 侧 case 目的地分裂（docs/api/flow.md 同日节）落地后，switch case
发射层的三个 oracle 缺口显形并修复：

- **`emit_switch_case_body` 补 `BlockType::Goto` 臂 → `emit_block_goto`**
  （printc.cc:3339-3341 `bl2->emit(this)` 的虚分派：t_goto case 组件必须
  走 emitBlockGoto——wrapped 体在 no_branch 下发射 + `gotoPrints()` 成立时
  的正式 goto/break 语句，printc.cc:2769-2778）。此前 Goto 组件落入
  `_` 臂的 flat 走查，wrapped If/List 复合体被平铺（与
  PRINTC-NESTED-DOWHILE-EMIT-0001 同类），goto 语句通道缺失。
- **cc:3342-3345 的 switch 级 break 判定**：由"非 RETURN 终结即 break"
  启发式改为 oracle `isExit(i)` 语义（block.hh:791 ← block.cc:3511-3514
  `gt!=0→false; else isexit=(sizeOut()==1)`），叠加
  BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 适配守卫：oracle 不变量是
  "每 case 的出口流恰表达一次"（组件自身语句 / 链式直落 / cc:3342 break），
  Rugra 结构化侧把多数 case 组件留成 Goto 包裹且 gototype 未受
  scopeBreak 晋升（block.cc:2866-2873/3613-3630 的域），故从发射侧重新
  推导：`case_exit_stmt_printed` 台账（`emit_block_goto` cc:2775 臂与
  gt!=0 语句臂置位）+ RETURN 终结豁免（无出边=oracle isexit false）+
  出口目标≠下一 case 入口（非链式直落，BlockSwitch::nextFlowAfter
  block.cc:3639-3663 的发射序语义）→ break。结构化侧 Goto 包裹补齐后
  本守卫应随 BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 一并退役。
- **gt!=0 语句臂置位台账**（printc.cc:3334-3337 语句即 case 的出口）。

观测：httpd main `case 0x4c:` 直落 `case 0x45:`（canon 形）、`case 0x53:`
break（canon 形）、`goto switchD_..._caseD_40` 形恢复；curl getparameter
383→381、glob_set 的 base 期语义错误 break（canon=直落 default 链）纠正为
`goto caseD_5e`（形态 +2）；mirror 面 main CMOV 位由 goto+label 平铺形转
clean if-block（向 direct-runner 纯库真值收敛 −9 行）。

## 2026-09-25（Lane PDOTFORM 三合一）：isValueFlexible 移植 + 未名位置空间名/rep 全址（PRINTC-C3FLEX-DOTFORM-0001 / PRINTC-C3-UNNAMED-SPACE-NAME-0001 / PRINTC-AFINI-UNIQUELOC-0001）

- **`is_value_flexible`**（`// Ghidra: printc.cc:895`，静态 helper）：implied+written
  varnode 的 def 为 PTRSUB/PTRADD（可经一层 implied+written 的 COPY 透传，
  cc:898-904 守卫序忠实——`!isWritten` 先 return 否则 `invn->getDef()` 空解引用）
  → flex=true。`dispatch_op_rpn` CPUI_PTRSUB 臂据此（cc:958）：
  - struct/union 臂四形态（cc:1018-1055 doc 表 cc:912-921）：flex 选
    object_member（`.`）且基座 `rpn_push_in(..., m | PRINT_LOAD_VALUE)`
    （cc:1039-1041/1047-1049）——基座自身的 spacebase PTRSUB 因此去 `&`、
    PTRADD 因此用下标；!valueon 前缀 addressof（`&( ).name` 形）。
  - array 臂四形态（cc:1098-1141）：flex 吸收解引用（无 `*` 前缀 + load 翻转），
    `valueon` 形尾部 `[0]`（canon `push_integer(0)` 的终位字面等价——field atom
    恒为最后一个 atom，postsurround 配对字节恒等）。
  - 基座 mods 从 `self.mods`（未剥离）改为 canon 剥离形 `m`（cc:957）/flex 翻转形，
    修复 load/store 位泄漏进非 flex 基座的形状差。
  - legacy `op_ptrsub` 同步：struct 臂 `.`/`->` 选择 + 基座
    `self.mods` save/flip/restore（该直发路径无逐推送 mods 通道，用临时位翻转
    表达 cc:1039-1041）；array 臂同步 flex 吸收。
- **spacebase 未名回退空间名**（PRINTC-C3-UNNAMED-SPACE-NAME-0001）：
  RPN 臂 `symbol.is_none()` 回退从裸 `0x{:x}` 改为
  `unnamed_location_token(sb.spaceid, in1const)`——cc:1078-1082
  `pushUnnamedLocation(sb->getAddress(in1const,...))`，`TypeSpacebase::
  getAddress`（type.cc:3063-3073）→ `resolveConstant`（translate.cc:628-642，
  spacebase 自身空间 + addressToByte/wrapOffset，x86-64 wordsize-1 空间为恒等）
  → `PrintC::pushUnnamedLocation`（printc.cc:1938-1945）空間名 + `printRaw`
  （space.cc:206-222 零填充）：`stack0xfffffffffffffc78` / `ram0x00023e00`。
  legacy 路径已走 `push_unnamed_location`（无需改）。
- **未名回退 rep 全址**（PRINTC-AFINI-UNIQUELOC-0001）：新增
  `unnamed_location_space_offset(vn)`（`// Ghidra: printlanguage.cc:238`）返回
  名字代表的（空间, 偏移）二元组；`make_atom_for_vn` 回退、RPN/legacy 两路
  display-name 阶梯的 Register/Stack/Unique/Ram/other 臂、RPN unknown-def
  兜底全部改取 rep 全址（canon `pushUnnamedLocation(rep->getAddr())`——空间
  半边此前随打印实例 `vn.get_space()`，UNIQUE 空间 COPY 输出与 RAM 空间代表
  分裂出 `unique0x<rep-off>` 形）。vn-空间键控的前置检查（param_names /
  inline_candidates 键）保持实例键控（逐实例内联决策，slice B1 域）；
  `pushMismatchSymbol` 臂（printc.cc:2082 vn 自身地址）不变。
- **配套**（写域延伸，src/prettyprint.rs）：backfill 声明注入对四个未名位置
  token 前缀（`unique0x`/`register0x`/`stack0x`/`ram0x`）跳过——canon 对这些
  token **零声明**（它们是表达式级存储槽标签而非 ScopeLocal 符号，
  emitLocalVarDecls（printc.cc:2260-2279）永不为其发声明；12.0.4 golden 中
  stack0x/unique0x 使用站点均无对应声明行）。

观测（curl 12.0.4 canon golden 差分）：767/0/0 → **727/0/0**；
match_url 28→22（`(&glob)->pattern[iVar5]->type` 族 → `glob.pattern[iVar5].type`
canon 形，`(&glob)` 7 处清零）、main 129→127、getparameter 275→261、
glob_range 51→43、glob_set 47→43、next_url 31→27、helpf 37→35；
`&stack0xfffffffffffffc78`/`&stack0x00000008` 空间名形态出现（与 canon 逐字一致）。
httpd：canon 1125→1123、direct-runner 2782→2780（零缺陷）。
httpd MIRROR 面 `unique0x<ram 偏移>` 形 8 处 → **0**（`ram0x000a0820`/
`ram0x000a0830`/`ram0x000a11b0`… rep 全址形）。
## 2026-09-25 追加（BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 — cc:3342 isexit 旗标化 + 守卫退役 + discovery 台账 Goto 弧）
1. **emit_structured_switch 的 cc:3342 判定**：`oracle_case_isexit` 从打印期
   `size_out()==1` 重导（组件消费后恒 0）改为读 `BlockSwitch::case_isexit`（oracle
   addCase 捕获传输，block.hh:763/791）；default 槽位 `def_isexit` 同改。
2. **needs_switch_break 守卫退役**：本 ID 的发射侧台账补偿块（ends_with_return/
   case_exit_target/next_case_start 三变量 + 判定）按 TODO 退役条件移除——A/B 实测
   守卫置死后 httpd/curl 双语料逐字节恒等；`case_exit_stmt_printed` 字段保留写入
   （gt!=0 臂与 emit_block_goto 的 discharge 记录），读者移除。
3. **emit_block_ops discovery 台账**：BlockGoto 弧（Goto 包裹的 switch case body 经
   emit_block_goto 的 Basic/Copy 臂进入本通道）发射的是 wrapped 叶的 ops——台账补记
   wrapped 叶起点（Basic/Copy）；否则 goto 语句的 never-emitted 锚对「树中实际发射
   的目标」误点火，吃掉 printed_labels 使 case 头部真标签被压掉（httpd main
   `switchD_0012ba94_caseD_3f:` 标签实证）。

## 2026-09-25（Lane SCOPEPFX）：spacebase 符号臂接通 `::` 遮蔽前缀（PRINTC-SPACEBASE-SCOPEPREFIX-0001）

RPN `dispatch_op_rpn` CPUI_PTRSUB 臂 TYPE_SPACEBASE 符号命中路径
（`query_container(global_scope_id, ...)` 替身）此前印**裸符号名**
（`&config` / `config.crlf`），漏掉 oracle `pushSymbol`（printc.cc:1086）
入口的 `pushSymbolScope`（cc:1919 → cc:202-228）：MINIMAL_NAMESPACES 下
`Symbol::getResolutionDepth(curscope)`（database.cc:323-359）对**局部
nametree 被同名占据**（`ScopeInternal::isNameUsed`，cc:2417-2432——参数、
restructure 局部、ActionNameVars 命名 high）的全局符号返回深度 1，
`pushSymbolScope` 打印全局 scope 的**空** display name + 二元 `::` scope
运算符（printc.cc:24）。REGSYM 判决（HEADLESS-BRIDGE-V1-REGSYM-0009 §14，
W5 参数改名消融）已实证该因果链：参数名 `config` 遮蔽全局 `config` 是
`::` 前缀的唯一触发器。

- **RPN 臂**：命中查询从 `query_container`（只要 name/metatype）改为
  `query_container_entry`（取 `(scope_id, Arc<SymbolEntry>)`），从 entry 的
  Symbol 读 name + dtype metatype（与 `container_hit` 逐字段同源：
  `symbol_name`=getName、Unknown≠Array/Code 折叠等价），并在 sym_atom
  组装处调用**已落地的** `symbol_scope_prefix(&sym, Some(&entry))`
  （PRINTC-GLOBALSYM-LEAF-PRIORITY-0001 ②，原仅 7169/7183/7196 叶优先路径
  接线）——遮蔽全局得 `::` 前缀，未遮蔽/`::` 预组合名（函数命名空间）/
  非全局得空串。栈 spacebase 的 ScopeLocal 回退路径不取前缀
  （database.cc:326：符号在自身 scope 内使用，深度 0）。
- **legacy `op_ptrsub` 同步**：spacebase 臂 pushSymbol/pushPartialSymbol
  两分支（cc:1086/1092 调用点）同样以 `symbol_scope_prefix(sym,
  in1 的 symbol_entry)` 前缀 display name（oracle 两路径入口都是
  pushSymbolScope）；`symbol_is_global` 的 DB 属主查询对栈局部命中
  （栈地址全局查询必 miss）自然得空前缀。

**验证**（oracle=12.0.4 e40ed130，canon `tests/golden/ghidra_curl_1204.c`）：
`&::config` 族收敛——`::config` 行数 getparameter 61→95、main 104→105、
parseconfig 3（==canon 逐函数 95/105/3；残留裸 `config` 仅签名/字符串字面量/
main 真·局部变量循环=canon 同形）；curl 全量 727/0/0→**635/0/0**
（getparameter 261→171、main 127→125；改动仅限这两函数、全部 config 行）；
httpd **1123/0/0 恒等**；投影 bank 391/391；gcc 审计 104 OK/20 FAIL
fail 名集与基线逐名相同；双跑 cmp 恒等；`::` 零泄漏（仅 `::config` 族）。

### 2026-09-25：PRINTC-COMMENTFILL-ARM — emit_line_comment 接通 start/stop_comment（注释 fill 解锁）

`emit_line_comment`（printlanguage.cc:589-648）此前在 cc:598/647 两处把
`emit->startComment()`/`emit->stopComment(id)` 误当"纯 markup 调用"省略——该判定只对
`EmitNoMarkup` 成立；对 oracle 管线唯一的 `PrintLanguage` 配置
`EmitPrettyPrint`（printlanguage.cc:69 `emit = new EmitPrettyPrint()`）不成立：
`startComment` 压入 begin_comment token，`print` 时置 `commentmode=true` 并把
`spaceremain` 压入 indentstack（prettyprint.cc:630-635）；此后注释体内每个强制断行
（cc:616-617 `\n` → `tagLine()`）在新缩进后追加 comment fill
（prettyprint.cc:689-693 `lowlevel->print(commentfill)`），`stopComment` 的
end_comment token 清 `commentmode` 并弹栈（cc:652-664）。PrintC 经
`setCStyleComments()`=printc.hh:242 → `setCommentDelimeter("/* "," */",false)` →
printlanguage.cc:98-110 以 start 定界符宽度生成全空格 fill（`"   "`，3 列）。

**两行接线**（src/printc.rs `emit_line_comment`）：`tag_line(indent)` 之后
`let comment_id = self.emit.start_comment();`，`" */"` 之后
`self.emit.stop_comment(comment_id);`。EmitNoMarkup 直连路径（非 oracle 的
PrintLanguage 配置）两调用为 trait no-op，绝对缩进字节复刻分支不受影响。

**可观测效果**：多行注释记录（单记录多变量 `\n` 连接）的续行从 20 列变为
**23 列（20 缩进 + 3 fill）= canon 形**；单行记录字节不变（首行 tagLine 时
commentmode 尚为 false，无 fill——与 oracle 时序一致）。

**配套驱动通道**（examples/curl_decompile.rs，`RUGRA_CMTSEED=<file>` 门）：
canon 的 `/* Unresolved local var: ... */` 记录族（analyzer 侧经程序 commentdb
进入，type=warning 由 instr_comment_type=user2|warning 放行，
printlanguage.cc:582）的锁定语料注入通道——`<hexaddr>\t<text>` 记录（`\n` 转义），
fad=目标入口、锚=记录地址按 [vaddr,vaddr+size) 过滤，经生产
`CommentDatabaseInternal::add_comment` 注入（与 SECSEED stage_cmt_diag oracle
harness 同契约）。锚校准：Rugra `find_position` 走 spaceless 精确匹配 backup 路径
（comment.rs，op.addr==comm.addr），入口/部分词法块首指令无存活 op——7 条记录按
canon 锚定语句的首个存活 op 校准（0x3729/0x3850/0x3c91/0x3f52/0x428d/0x44bb/0x522e），
e40ed130 oracle 复核 17 记录/45 行逐字节=canon（my_get_line 一条在 bare harness 环境
内差一语句=环境噪声，Rugra 侧 canon 精确）。

**验证**（oracle=12.0.4 e40ed130，canon `tests/golden/ghidra_curl_1204.c`）：
默认脸（无 env 门）curl E2E **577/0/0 与基线逐字节恒等**（零回归）；
RUGRA_CMTSEED 注入脸 Unresolved 注释族 **0→45 行/17 块全部字节=canon、全部落在
canon 锚定语句位**（9 块的 next-stmt 文本带预存语料残差——`pcVar11/pcVar12` 临时
编号、`fp/__stream`、`pFVar10/pCVar9(Configurable*)` 类型推断、`(const char*)`
cast 与 `my_get_token::save` 限定名，默认脸同位同文，非本改动引入）；
skeleton **577→520（−57）**、defects=0、numbering=0；投影 bank 391/391；
双跑 cmp 恒等。

## 2026-09-25（Lane BADJT）：PRINTC-BADJT-PARAMSYM-0001 —— 参数 backing-Symbol 渲染通道 + 匿名 code base 折叠

**根因**（UNREFFIX 双侧 fixture `tests/oracle/namevars_badjumptable_1204` 亲证）：
bad-jump-table 改名链（truncate→旗标→`lookForBadJumpTables` 改名
`UNRECOVERED_JUMPTABLE`）全活、双侧 ScopeLocal 存储键一致，断点在渲染层不读
改名后的后端符号。oracle 签名经 printc.cc:2222-2250 `emitPrototypeInputs` 的
`param->getSymbol()`→`emitVarDecl(sym)` 印**符号 dtype+符号 displayName**；
调用点经 `pushVnExplicit`→`pushSymbolDetail`（printlanguage.cc:218-262）的
whole-map `pushSymbol` 印符号 displayName。Rugra 两处印 proto 自带名/类型。

**四处改动**（判定序照 oracle）：

1. `param_backing_symbol(slot)` / `param_backing_symbol_for_vn(vn)`（新，
   RUGRA-GLUE）：print 侧投影 `ProtoStoreSymbol::getInput` 的
   `getCategorySymbol(function_parameter,i)` 现读（fspec.cc:3244-3255）。
   `emit_prototype_inputs` 命中走 `emit_local_symbol_decl`（emitVarDecl）；
   未命中保留 else 形态（proto 类型+名）。
2. `get_varnode_display_name_inner` P0.4 前插 category 门符号优先（**P0.4
   保留**为无符号/未同步流的回退）：Register INPUT 的 function_parameter
   category 符号（storage 全覆盖、非动态）先于 proto 名——category 门天然
   排除 linkSymbol 桥的 `in_register_` 未同步自动名（no_category 造物），
   P0.4 的补偿语义不受影响。
3. `build_type_stack`/`push_type_start_opt`/`push_type_end_opt`/
   `cast_type_string`：匿名无 proto CODE 层折叠为命名 base `code`——
   oracle `findNoName`（type.cc:3454-3476）把 `getTypeCode()` 折到 spec
   coretype `code`，代码指针栈形 `[Ptr, Code("code")]` 命名 break；
   `void (*x)()`/`(BADTYPE *)` 旧形态换成 `code *x`/`(code *)`。旧
   pushTypeEnd `"()"` DIVERGENCE 臂不可达化。
4. `op_callind` 直发/内联/RPN 三处的 `(code *)` cast transport 按
   `castStandard` 恒等判定门控（cast.cc:303）：target 读面类型已是代码
   指针（Pointer→无 proto Code）→ 印 `(*sym)(...)` 无 cast；其余
   （GOT-slot、LOAD 链）保留 `(*(code *)...)`。

**验证**（oracle=12.0.4 e40ed130）：ap_vhost_iterate_given_conn 签名位 2 +
两调用点 == canon（ghidra_httpd_1204.c:4914/:4927/:4934）与 direct-runner
（:4781 起）双 golden——函数块逐字节（除预存 Oppen 行尾空白 2 行）；
httpd **949→940**（−9 全为 `void (*pVarN)()`→`code *pVarN` 声明族 +
`(BADTYPE *)`→`(code *)` + UNRECOVERED 三点，canon 同形收敛）、
defects=0、numbering=0；curl **577/0/0**（`(BADTYPE *)` 双重 cast 1 行
转 canon 精确形，skeleton 不动）；bank 391/391；双跑 cmp 恒等；
cargo test --lib 1713 通过 + 1 预存 master 失败
（fspec::test_nonzeromask_pipeline_wiring，master 上同败，非本改动）。

### opPtrsub 联合体臂：getUnionField 消费（COREACT-C3-UNIONRES-0001，2026-09-25）

- **背景**：`dispatch_op_rpn` 的 `CPUI_PTRSUB` 臂与 legacy `op_ptrsub` 此前把
  TYPE_UNION 与 TYPE_STRUCT 合并走 `find_partial_field`（findTruncation 检索）。
  Ghidra 在 printc.cc:977-990 对联合体点设有**独立臂**：suboff 必须为 0（否则
  LowlevelError）；字段名/类型/ident 取自 Funcdata 联合体解析图——
  `fd->getUnionField(ptype, op, -1)`，键为**指针类型** + slot -1（即
  `ActionSetCasts::resolveUnion` 在 coreaction.cc:2509 attach 的边），
  从不 findTruncation。Rugra 联合体 PTRSUB 因此印成 `field_0x0` 或裸偏移——
  12.0 ResolvedUnion 机制的消费端缺口。
- **本改动（对齐移植）**：
  - RPN 路径（`dispatch_op_rpn` CPUI_PTRSUB）与 legacy（`op_ptrsub`）在
    `meta == Union` 时先查 `union_resolutions` 快照（doc_function 时
    `snapshot_union_resolutions` 安装），键构造与生产端完全一致
    （`ResolveEdge::new(ptype, op, -1)`——指针剥壳 + encoding 0x1000-1）；
    `field_num >= 0` 时从 `TypeUnion::fields[field_num]` 取 name/type。
    TYPE_STRUCT 保留原 find_partial_field 路径不动。
  - oracle 的两个 LowlevelError 臂（suboff≠0；解析缺失/负 fieldNum）在
    resolveUnion 门控插入的管线里不可达，且 Rugra 打印器无抛错通道
    （同 cc:943-946 非 pointer 臂的既有 accommodations），落
    `field_0x<hex>` 默认名。
  - 四形态发射（valueon×flex，cc:1018-1055）复用 PDOTFORM 车道落地的基础
    ——flex 臂 `.` + 基座 load-value 翻转直接适用于 `.content.Set` 形。
- **生产端前置（同 commit，debugproto.rs）**：DWARF 导入的联合体补
  `NEEDS_RESOLUTION` 旗标（Ghidra TypeUnion ctor type.hh:551；指针继承
  type.cc:1048 calcSubmeta）——没有它 `ActionInferTypes::propagateTypeEdge`
  的 always-resolve 臂（coreaction.cc:5081-5084）与 `resolveUnion`
  （coreaction.rs 既有移植）全部饿死，联合体臂永远查不到解析条目。
- **效果（curl 门禁）**：match_url `.content.Set`/`.content.NumRange` 字段名
  形落地（`lVar3 = *(long *)&glob.pattern[iVar5].content.Set;`）；curl
  577→575（glob_range 38→32）；httpd 940 不动；bank 391/391。
- **残余（登记 TODO，见对齐块）**：①`.Set` 后继偏移未规范化为
  PTRSUB(#c)（canon `.Set.size` vs Rugra `(long)&...content.Set + 8`）——
  oracle 在 rules 阶段经 `getTypeReadFacing` 的 findResolve 让 AddTree/
  RuleStructOffset0 看到 Set*，Rugra 的 varnode 侧 read-facing 仍是退化形
  （varnode.rs，HIGHCOV 并行域）；②per-edge 评分在"原始边"（canon 留
  `(int8)&...content + 8` 裸形的 sprintf 参数边）差一枚 +5：oracle 的
  union* 是 ephemeral TypePointerRel（propagateAddIn2Out 的 parent 记账，
  typeop.cc:1241），其 downChain 经 parent 再入返回非空 → 全联合体平局 →
  whole-union 胜出；Rugra 该指针为裸形（rel=false 实证）→ Set 胜出 →
  该边过度解析为 `.content.Set`（match_url 24/next_url 22 的 +2 来源）。

## 2026-09-25（Lane MIRROR2）：直接运行档被调名 `func_0x%.8x`（MIRROR2-S3-CALLEE-0001）

- **根因（GENSMOKE-S3 收口）**：oracle `PrintC::opCall` 未名被调臂
  （printc.cc:593-605）走 `genericFunctionName(fc->getEntryAddress())`
  （cc:3359-3366）= `"func_" + addr.printRaw()`——`AddrSpace::printRaw`
  （space.cc:206-222）零填充到 `2*addrsize`（offset<2^32 时 sz 缩 4），
  即直接运行档 golden 的 `func_0x00003190`。`FUN_%x` 是 headless
  **前端**数据库名（analyzeHeadless 符号管理器生成），反编译库自身从不
  产生——Rugra printc 的 `FUN_{:x}` 兜底只是 canon 档的巧合匹配。
- **修法**：opCall 兜底按档分派（`typefactory::direct_runner_tier_active`
  探针，MIRROR-ENVS-CANONICAL-0001 三驱动 env 包）：direct-runner 档 =
  `format!("func_{}", addr_space_print_raw(Ram, off))`（复用 printc 内
  已有的 space.cc:206 1:1 移植，含 wordsize cut 与 sz 缩减）；canon 档
  保持 `FUN_{:x}` 历史面。
- **效果**：vsh 镜 `FUN_3190`×2 → `func_0x00003190`×2（与 golden 逐字节
  一致，remoteGetUNIXSocket 7→3）；httpd 镜 −62（`FUN_2c520` 族）；
  canon 不回退（FUN_ 路径不变）。

## 2026-09-25（Lane DOTFIX）：符号/函数名直通与无类型常量整数形态（STUBLEAK 双残差收口）

- **根因①（STUBLEAK-DOTNAME-SANITIZE-0001）**：`doc_function` 的
  symbol_table 快照、`emit_function_declaration` 表头与
  `emit_prototype_inputs` 参数名三站点均过 `sanitize_c_ident`
  （RUGRA-GLUE 遗产），把 `.` 改写 `_`。oracle 发射名一律原文：
  表头 `emit->tagFuncName(fd->getDisplayName(),...)`（printc.cc:2592）、
  调用点经 FuncCallSpecs display name、参数名经 emitVarDecl(sym)
  （printc.cc:2240）——printc.cc 全文不存在任何 C 标识符清洗。镜面档
  裸 BFD 装载器递交 ELF 名 `parseconfig.constprop.0`（GCC clone 后缀），
  被改写为 `parseconfig_constprop_0` → 表头+调用点 14 行 vs golden 直印
  点号。canon 档 DWARF 拼写无点故从未暴露。
- **修法①**：三站点直通原文（快照 `v.clone()`、表头 `fd.get_name()`、
  参数名 `&param.name`）；`sanitize_c_ident` 删除（零调用方），其
  DRIVER-SWITCHD-DEFFN-0001 `::` 透传注释由全文透传取代（`::` 形
  httpd canon 1980-1998 三站点实测不变）。
- **根因②（STUBLEAK-CHARPRINT-LOOPCONST-0001）**：登记定位
  `push_constant` 无类型回退臂的 `sz==1 && printable → 'c'` 启发式；
  实测追迹发现 for 头初始化常量走 coreaction
  `for_header_const_text`（已按 push_integer 渲染 `0x26`），`'&'` 的
  真实生产源是 **prettyprint 第七趟文本改写**（`==/!=/= 0xNN` → `'c'`
  硬编码表，见 docs/api/prettyprint.md 本日条目）——登记的
  `push_constant` 臂为潜在路径，同 commit 一并修直。
- **修法②（printc 侧）**：`push_constant` 无类型（TYPE_UNKNOWN）臂改走
  `integer_text(val, sz, false, DEFAULT)`——printc.cc:1766-1768
  `TYPE_UNKNOWN → push_integer(val, ct->getSize(), false,...)`，
  0x26 经 mostNaturalBase（printlanguage.cc:731 countdec=0 → 16）印
  `0x26`；typed charPrint int/uint 臂保持字符字面量（cc:1749-1764 闸门）。
- **效果**：curl 镜 259→211（点名族 14 行 + 字符改写族连带）、
  httpd 镜 440→412、curl canon 396→388、httpd canon 896→872；
  defects=0/numbering=0 四档全零；bank 1729/1730（1 失败为 master 既有
  fspec `test_nonzeromask_pipeline_wiring`，pristine 复现，非本车道）。

## 2026-09-25（Lane PRINTP2）：签名 tokenbreak 双发恢复 + op_return 打印期 RAX 重构移除

- **根因①（MIRROR3-PROTOWRAP-PRINTC-0001，签名折行断点丢失）**：oracle
  `PrintC::emitFunctionDeclaration`（printc.cc:2594/2596）在函数名后与
  `(` 后各发一次 `emit->spaces(function_call.spacing=0, function_call.bump=10)`
  ——`function_call`（printc.cc:28）= postsurround token，spacing 0、bump 10。
  在 EmitPrettyPrint 语义下 `spaces(num,bump)` 不是"无空格可省略"：它是
  TokenSplit spac_t/tokenbreak（prettyprint.hh:914）——零强制空格 + 可选
  断行缩进 +bump 的**断点**。Rugra 移植时以 spacing==0 为由跳过两次调用，
  断点丢失后长签名折行退化为参数间 type_expr_space 断（5 参/行、续行缩进
  0），golden 形态为开括号列续行（my_get_line 19 列、4 参/行）。
- **修法①**：`emit_function_declaration` 恢复 `open_group`/`close_group(id1)`
  （cc:2590/2600）、名后 `spaces(fc.spacing, fc.bump)`（cc:2594）、括号后
  `spaces(0, fc_bump)`（cc:2596）、`close_paren(")", id2)` 传回真实组 id
  ——全部逐字照 cc 形态；spacing/bump 取自 RPN token 表
  `rpn_token_table[rpn_tok_function_call]`（printc.cc:28 的镜像条目）。EmitNoMarkup
  下 spaces(0,·) 仍折为零字节（prettyprint.cc:46），canon/mirror 两脸安全。
- **根因②（MIRROR3-RETURNVOID-PRINTC-0001，void return 未裁剪）**：oracle
  `PrintC::opReturn`（printc.cc:754-766）**没有**按输出类型裁剪的分支——
  返回值仅在 `op->numInput()>1` 时发射；void return 的裁剪发生在 IR 层
  （`ActionReturnRecovery::buildReturnOutput` 只保留 used trial，
  coreaction.cc:1836-1906；trial 裁决在 `ParamListStandardOut::fillinMap`，
  fspec.cc:1721-1758）。探针实证（RUGRA_PROBE_RET 构建）：httpd 镜
  ap_init_vhost_config 的 RETURN 到达 print 层时 `num_input=2`、in(1)=Register
  ——残值输入在 IR 中幸存，printc 两运输层（RPN 臂 cc 逐字镜像 + legacy
  孪生）均忠实打印 IR 给定的输入。**结论：printc 域无可修残差，残根在
  coreaction/fspec trial 裁决域（本票移交）**。
- **修法②（清理非 oracle 机制）**：legacy `op_return` 的 RAX/EAX 块扫描
  重构（commit 5542b507，print 期 IR 恢复，oracle 无对应物——Ghidra 的
  `xor eax,eax; ret`→`return 0` 全在 IR 层完成：RuleTrivialArith 折叠 +
  ActionReturnRecovery 挂值）整体移除；其专属 helper
  `capture_inline_expr_text`/`is_textual_self_xor` 一并退役（零其它调用方；
  全驱动走 RPN 运输层，legacy 臂探针 0 命中=死码，行为零变化）。本条取代
  2026-06-23"RETURN 返回值推断"与 2026-07-03 续 4"self-XOR 折叠"两节所述
  机制。
- **效果（本 worktree fast-release 亲测，基=master d9fa45a2 基线二进制 A/B）**：
  curl 镜 my_get_line/helpf 签名折行与 golden 逐字节一致（4 参/行、开括号列
  续行；my_get_line 45→38、helpf 10→6，残差为 typeprop/decl 族）；curl 镜 211→200；curl canon
  369→369（中性——canon 签名带 DWARF 类型普遍单行，折行不触发）；
  httpd 镜 412、httpd canon 872、vsh 镜 51 全部不变；defects=0/numbering=0
  五档全零；bank 391/391 MATCH；cargo test --lib 1730P/1F（唯一失败=
  test_nonzeromask_pipeline_wiring，VHOST 在案基线预存）。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 16 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
### 2026-09-26：MSTRUCT-WHILEDO-LABEL-PRINTC-0001 — 循环构造入口标号补发

**症状**（curl 镜 glob_word 亲证）：`goto code_r0x00004c20;`（×2）与
`goto code_r0x00004d0e;`（×2）引用的标号在函数内无定义（悬空 goto，gcc
不可编译形态）；golden 同位在 `while( true )` / `do {` 头**前**打印
`code_r0x00004c20:` / `code_r0x00004d0e:`。

- **根因（本 session 探针钉死）**：oracle 的
  `emitAnyLabelStatement(bl)` 调用位于**每个构造发射器自身入口**
  （emitBlockCopy cc:2762、emitForLoop cc:2965、emitBlockWhileDo cc:3014、
  emitBlockDoWhile cc:3076、emitBlockInfLoop cc:3104——虚分发 `emit` 的
  任何路径都会经过）。Rugra 把该调用集中到分发器
  `emit_block_structured`（对每个块先查后派发），但两条派发路径**绕过**
  分发器直达构造发射器：①`emit_structured_list`（cc:2795-2812 子块循环）
  经 `emit_flow_block` 派发 List 子块；②`emit_switch_case_body`
  （cc:3339-3341 `bl2->emit(this)` 的传输层）直接匹配类型调
  `emit_structured_whiledo/dowhile/infloop`。glob_word 的 whiledo
  （0x4c20，顶层 List 子块）与 infloop（0x4d0e，switch case 体）恰好
  各命中一条绕行路径——构造入口标号检查从未运行（探针
  RUGRA_DBG_LABELS 亲证：两构造的 self_type 从不出现在
  emit_any_label_statement 调用记录中，而其前叶 targ=true 已由
  blockaction.cc:2194 `markUnstructured` 链正确标记——block 侧无缺口）。
- **修法（oracle 逐位复刻）**：四个循环构造发射器入口、在
  `pushMod(); unsetMod(no_branch|only_branch)` 之后（oracle 调用序）补
  `emit_any_label_statement(block_arc)`：`emit_structured_whiledo`
  （cc:3014）、`emit_structured_dowhile`（cc:3076）、
  `emit_structured_infloop`（cc:3104）、`emit_for_loop`（cc:2965——签名
  加 `block_arc` 参数以携带 Arc；旧注释"dispatcher 已覆盖故跳过"的
  假设被两条绕行路径证伪，已删）。与分发器传输调用（GOTO-LABEL-
  UNPRINTED-0001 的 Basic/Goto/List/Switch 运输层）经 printed_labels
  once-guard 幂等：先到先打印，输出位置相同（构造首文本之前）。
  oracle 的 only_branch 语义同时修复：构造入口调用在 unset 之后运行，
  即使调用方带 only_branch（emitBlockLs cc:2810 尾块 only_branch 派发）
  标号也照印——与 oracle 一致。
- **效果（本 worktree fast-release 亲测，基=master 1414f6e3）**：glob_word
  两标号与 golden 逐字节同位（`code_r0x00004c20:` 在 `while( true )` 前、
  `code_r0x00004d0e:` 在 `do {` 前），悬空 goto 清零；curl 镜
  110→101（glob_word 13→5、glob_set 3→2，其余 72 函数逐函数零变化）；
  curl canon 269→267；httpd 镜 265、httpd canon 862、vsh 镜 15 全部
  不变；defects=0/numbering=0 全档；bank 391/391；cargo test --lib
  1735P/1F（nonzeromask 预存）。glob_word 剩余 5 行：xStack_40 多余
  声明（F-DECL 族）+2 行语句序差 + `break;` vs `goto code_r0x00004c20;`
  （switch-case 反向边 goto 类型分类，MSTRUCT-SWITCHGOTO-SELECTGOTO-0001
  族 block 侧残差，非 printc 域）。

### 2026-09-26：STRNCPY-PRINT-CALLOTHER-0001 — CALLOTHER 印刷臂接通（printc 侧交付）

**症状**（httpd 镜 ap_ht_time 亲证）：`builtin_strncpy(pcVar3,"+0000",5);`
语句印成裸 `;`（dispatch_op_rpn 无 CPUI_CALLOTHER 臂，落 `_ => {}`
no-op）；STRINGDATA 字面量臂硬编码 `"badstring"`。

- **修法①（RPN 臂）**：`dispatch_op_rpn` 补 `OpCode::CPUI_CALLOTHER =>`
  臂，新增 `rpn_op_callother`（printc.cc:673-715 的 RPN 运输层移植，
  与 rpn_op_call 同构）：display==0 功能语法 `name(in1,...)`（cc:678-692：
  function_call token + 名 atom（optoken/funcname_color，
  getOperatorName=TypeOpCallother typeop.cc:837-853 → UserPcodeOp 名）+
  numInput()-2 个 comma + in(1..) 逆序 push）；annotation_assignment
  （cc:693-697：assignment + in(2) + in(1) 逆序）；no_operator
  （cc:698-700：裸 in(1)）；display_string（cc:701-714：out 原始 v_type
  为 TYPE_PTR 时经 in(1) hash 常量地址查 string_manager
  （register_internal_string_data 键=Address(hash)，stringmanage.rs:817），
  失败/非指针落 `"badstring"`）。`rpn_def_inline_reachable` 补
  CALLOTHER=true（每个 display 臂都发射——STRINGDATA 输出内联为字面量
  而非泄漏 unique 临时名）。LHS 赋值由 emit_expression_rpn（cc:2471-2476）
  发，臂内不发——与 oracle 一致（opCallother 从不碰 out）。
- **修法②（legacy 臂）**：`op_callother` 的 DISPLAY_STRING 臂把硬编码
  `"badstring"` 换成同一 print_character_constant 读回链（双运输层同
  语义；legacy 臂经 typeop.rs TypeOpCallother::push 路由在案）。
- **效果（本 worktree fast-release 亲测，基=本 lane 票①后）**：ap_ht_time
  语句从裸 `;` 恢复为 `builtin_strncpy(pcVar3,(char *)"badstring",5);`
  （canon 同形恢复，gcc 可编译）；vsh 镜 15→14；curl 镜 101/httpd 镜
  265/curl canon 267/httpd canon 862 全部不变；defects=0/numbering=0
  全档；bank 391/391；lib 1735P/1F（nonzeromask 预存）。
- **验收残差（上游域，非 printc）**：golden 逐字节形
  `builtin_strncpy(pcVar3,"+0000",5);` 差两点——`(char *)` 前缀与
  `"badstring"` 字面量。根因=**castOutput 对 STRINGDATA 误发**：
  Rugra 的 CALLOTHER 输出 token 落 output_metatype 的 `_ => Int`
  兜底（int8），oracle 链=TypeOpCallother::getOutputLocal
  （typeop.cc:866-872）→ userOp->getOutputLocal：InternalStringOp
  返回 `op->getOut()->getType()`（userop.cc:361-364，即锁定 char*）→
  tokenct==outHighType → cc:2544 短路不发 CAST；Rugra int8≠char* →
  castOutput 插 CAST（偷走原 out 给 CAST、给 STRINGDATA 换 int8 新
  out）→ 打印侧忠实读 int8 → "badstring" + `(char *)`。登记
  `COREACTION-CALLOTHER-OUTTOKEN-0001`（coreaction.rs token 计算 +
  userop.rs InternalStringOp 特化；修后本票验收即达）。

### 2026-09-26：HTTPDMAIN-F3-DOUBLECAST-0001 — switch 头双重强转折叠+legacy CAST 操作数括号

**症状**（httpd canon main switch 头亲证）：
`switch(*((undefined1 *)(undefined1 *)(long)plVar12 + 0x33))` 发两层
`(undefined1 *)`，golden 同位 `switch(*(undefined1 *)((long)plVar12 + 0x33))`
恰一层；其余表达式无此病。

- **根因（本 session 探针钉死）**：switch 头经 `emit_switch_head_expr`
  → `push_varnode`（**legacy 直发通道**）渲染，语句体走 RPN 通道——两条
  运输层对 LOAD 的处理不同：RPN 的 LOAD 臂忠实（cc:486-498 只发
  dereference token，cast 全部来自内联 CAST op，每 op 恰一次
  printc.cc:448）；legacy 的 `emit_inline_expr` LOAD 臂自带
  `*((T *)` 类型化包装（Rugra 传输层发明，oracle 无对应物），叠加内联
  CAST 自己的 `(T *)` → 同型双层。地址输入即 CAST 输出 varnode，
  两处类型文本恒等（数据流保证）。
- **修法①（同型折叠）**：legacy LOAD 臂在地址输入为 implied 且 def 为
  CPUI_CAST 时省略自身包装，发 `*` + 输入（内联 CAST 已带同型 cast，
  `*(T *)expr` 合法 C）——oracle opLoad 从不发包装，cast 文本只来自
  CAST op。
- **修法②（操作数括号）**：legacy `emit_inline_expr` CAST 臂补
  printlanguage.cc:277 的嵌套规则——typecast presurround（prec 62，
  printc.cc:35）下的二元子表达式（binary token prec < 62）加操作数
  括号。RPN 通道由 token 机制免费获得（canon
  `apr_ctime((undefined1 *)((long)plVar12 + 0x60),...)` 亲证），
  legacy 通道此前缺失——修后 `(T *)((long)p + 0x33)` 形与 RPN/golden
  一致。
- **效果（本 worktree fast-release 亲测，基=本 lane 票②后）**：main
  switch 头与 golden 3757 行逐字节一致
  （`switch(*(undefined1 *)((long)plVar12 + 0x33))`）；httpd canon
  **862→860**、httpd 镜 **265→263**；curl canon 267/curl 镜 101/vsh 镜
  14 全部不变；defects=0/numbering=0 全档；bank 391/391；lib
  1735P/1F（nonzeromask 预存）。

### 2026-09-26：MIRATTR-F-ARRCAST-0001 — 数组指针 cast 声明器括号化

**症状**（httpd 镜亲证）：指针到数组 cast 印成非法 C
`(xunknown1 [16]*)`（flat `[N]*` 链），golden 同位
`(xunknown1 (*) [16])`（C 声明器括号化）；双指针形
`(xunknown1 (**) [16])`。

- **oracle 机制（本 session 亲读钉死）**：`pushType`（printc.cc:1472-1478）
  = pushTypeStart + **pushAtom(EMPTY_STRING)**（抽象声明器的标识符占位，
  cc:1477）+ pushTypeEnd（`[N]` 尺寸原子，cc:305-330）。pushTypeStart
  （cc:292-302）按 base 侧先推声明器 op（指针到数组=先 array_expr 后
  ptr_expr）；RPN 嵌套规则（printlanguage.cc:286 postsurround 臂——
  array_expr prec 66 > ptr_expr prec 62，printc.cc:75/78）在 `*` 推入
  而数组仍 pending 时开括号；连续第二层 `*` 走 unary_prefix 臂
  （cc:291-293）不加括号——**括号包住整段连续 `*` run**，closeParen
  在 run 完结（EMPTY 原子级联完成）时发射。发射文本：`t` ` `
  `(` `*`…`*` `)` ` [N]`。
- **修法**：`cast_type_string` 的层链渲染重写为 run 语义——最内层先
  遍历；连续 Pointer 层聚成 run；run 起点处有数组 pending（即 run
  外层包着数组）→ 整 run 括号化 `(**…)`；Array 层中断 run、追加
  ` [N]` 后缀（spacing=1）并置 pending。形态对照：
  Pointer(Array)→`t (*) [N]`；Pointer(Pointer(Array))→`t (**) [N]`；
  Pointer(Array(Pointer))→`t *(*) [N]`；Array(Pointer)→`t * [N]`；
  Pointer(Ptr)→`char **`（原行为保持）。
- **效果（本 worktree fast-release 亲测，基=本 lane 票③后）**：httpd 镜
  三处 cast 与 golden 逐字节一致（770/1033 `(xunknown1 (*) [16])`、
  1036 `(xunknown1 (**) [16])`）；httpd 镜 **263→253**
  （ap_parse_vhost_addrs 33→27、ap_set_name_virtual_host 14→10，其余
  函数逐函数零变化）；httpd canon 860/curl canon 267/curl 镜 101/vsh 镜
  14 全部不变；defects=0/numbering=0；bank 391/391；lib 1735P/1F
  （nonzeromask 预存）；gcc 审计 15OK/14FAIL==基线比率。

### 2026-09-26：UNIONRESOLVE-PKG-C-0001 — printc 29 站点换 snapshot-backed facing 孪生

**背景**（UNION_CONSUMER_AUDIT_2026-09-26 §一/§三 包 C）：oracle 的四个
facing 方法（varnode.cc:626-672 getTypeDefFacing/getTypeReadFacing/
getHighTypeDefFacing/getHighTypeReadFacing = `needsResolution() ?
findResolve(op,slot) : this`）在打印期经 `fd->unionMap` 活查询；Rugra 的
打印站点此前用 varnode.rs 退化形（consult 恒走 map-miss 臂 `return
this`）——union 分歧非潜伏（curl golden 含活 union
`anon_union_16_3_e2f18bb4_for_content`×8）。

- **新增 4 个 snapshot-backed helper**（printc.rs，
  `vn_type_read_facing_snap`/`vn_type_def_facing_snap`/
  `vn_high_type_read_facing_snap`/`vn_high_type_def_facing_snap`）+
  核心镜像 `find_resolve_snap`：unionresolve::find_resolve 的逐臂复刻
  （type.cc:1192-1202 Pointer-to-union/2137-2145 Union/1298-1306
  Array/1944-1952 Struct/2517-2534 PartialUnion/586-590 base），consult
  键=同一 ResolveEdge(parent, op-time, slot)，查询
  `self.union_resolutions`——**doc_function 入口快照**
  （snapshot_union_resolutions，printc.rs:10385 唯一调用点），语义等价
  打印期冻结的 fd.union_map（审计风险提示「快照时点提前会掩盖回归
  信号」——时点保持入口不变）。
- **29 处替换**（RPN/legacy 双运输层，每 oracle 行两处）：
  pushConstant 入口 read-facing（printlanguage.cc:227）、ZEXT/SEXT
  isZext/isSextCast 双读（cc:789/802）、SUBPIECE 特印臂+isSubpieceCast
  双读（cc:848/872-873）、PTRSUB in0（cc:942）、opTypeCast out+decay
  检查（cc:451）、opFloatInt2Float out（cc:835）、emit_inline_expr
  CAST/SUBPIECE 孪生、opConstructor/opNew 的 TYPE def-facing
  （cc:726/1246）、legacy op_ptrsub/op_type_cast/op_int_zext/
  op_int_sext/op_subpiece 全套、isExtensionCastImplied 双读
  （cast.cc:259/289）。CALLIND code\* 门三处（aligned-in-practice，
  审计在案）与 glue 兜名一处保持退化形。
- **效果（本 worktree fast-release 亲测，基=本 lane 票④后）**：五面全部
  恒等——curl 镜 101/httpd 镜 253/curl canon 267/httpd canon 860/vsh 镜
  14；defects=0/numbering=0；bank 391/391；lib 1735P/1F
  （nonzeromask 预存）。语料中性=当前语料的打印站点无 map-hit 臂触发
  （union 分歧的消费面在 coreaction 已对齐站点）；快照通道为后续 union
  语料提供 oracle 等价语义。

### 2026-09-26 — emit_for_loop 喂线：ops 通道 + RPN 表达式 + 条件虚分发（HTTPDMAIN-F8-FORLOOP-0001，Lane F8FOR）

- `emit_structured_whiledo` 分发（printc.cc:3007-3009 口径）扩为双通道：
  **主通道** `iterate_op`（block.rs 真端口设置）→ `emit_for_loop`；**legacy
  通道** `for_init/for_iter` 文本对（coreaction.rs 过渡渲染器；两通道检测
  互斥，理由见 block.md 同日节）。
- `emit_for_loop` 喂线落位（emit 本体骨架保留）：
  - init/iter 槽：ops 通道走 `emit_expression_rpn`（printc.cc:2468
    emitExpression 的忠实端口——赋值 LHS token cc:2470-2472 + 虚 op 分发 +
    recurse；CAST/PTRADD 通用形由此成文 `V = (t*)*V`）；legacy 通道保留文本
    直印。
  - 条件槽：`emit_block_condition` 直调改为 while 路同款虚分发
    （insert-first + `emit_flow_block`，= oracle `condBlock->emit(this)`
    cc:2983；基本块条件走语句级逗号串）。
  - `open_paren`/`close_paren` 配对 id 修正（丢弃 id + `close(0)` 会破坏
    EmitPrettyPrint 组栈）。
- `emit_expression` 补 PTRADD 路由（typeop.hh:823 `TypeOpPtradd::push →
  lng->opPtradd(op)`；typeop.rs 的 push 表缺该臂，落 `_ => op_binary` 印出
  字面 `" op "` 占位——表缺口登记归 typeop.rs owner）。

### 2026-09-26 — legacy/RPN 叶 partial-symbol 走 consult 门：union 下降仲裁（CURLCANON-UNIONSTORE-ARBITRATION-0001，Lane CURLD）

- **根因**：legacy 走查 `partial_symbol_walk`（= printc.cc:1954-2042 的
  partial_symbol_text/push_partial_symbol 双形态共享体）对 TYPE_UNION 用
  结构性 `find_partial_field`（首包含字段即下降）。oracle 的
  `TypeUnion::findTruncation`（type.cc:2185-2199）是**只读缓存 consult**：
  按 `(union, op, slot)` 解析缓存取字段（带 `newoff+sz>field.size` 跨界拒
  绝），miss 永不下降——整成员 vs 字段下降的站点仲裁全部由上游
  ScoreUnionFields/resolveInFlow 决定（setcasts castOutput 的 last-chance
  `resolveInFlow(op,-1)` cc:2551-2556 落键）。RPN 孪生
  `rpn_push_partial_symbol` 已是 consult 形;legacy 缺口使 curl main 的 9 个
  glob 初始化站点结构性下降 `.content.Set`（golden 8 站点整成员
  `content` + 1 站点 `content._8_8_`，同函数 golden:746 反例站点确应全下降
  `.content.Set.elements`——逐站点语义，非硬规则）。
- **修复**（全部 printc.rs）：
  - `partial_symbol_walk`/`partial_symbol_text`/`push_partial_symbol`/
    `push_symbol_detail_leaf` 增 `consult: Option<(&PcodeOp, i32)>` 参数;
    STRUCT 臂补 printc.cc:1966-1973 的 `needsResolution && size==sz →
    findResolve==ct → break` 前置（snapshot consult + field[0] 回退）,
    STRUCT/UNION 双臂统一走 `Datatype::find_truncation`（type.cc:1624
    structural / type.cc:2185 cache-consult + span 检查的既有移植）;
    UNION miss 且 `sz==union size` → break（cc:2015-2016 整成员停走）。
  - consult 键按 oracle 四个 pushPartialSymbol 调用点喂入:赋值 LHS
    （emit_expression_rpn 设 is_lhs + legacy push_varnode is_lhs 路径）=
    `(op,-1)`（printc.cc:2475 `pushSymbolDetail(outvn,op,false)` /
    printlanguage.cc:257 `inslot=-1`）;读叶 = `(op, op->getSlot(vn))`
    （op.hh:166 loop-exit= numInput 语义,`op_input_slot_of` 以
    (space,offset,size) 身份扫描）;PTRSUB spacebase 臂 = `(op,-1)`
    （cc:1092）;SUBPIECE 特殊打印 = `(op, needsResolution?1:0)`（cc:858）。
    `make_atom_for_vn → get_varnode_display_name(_inner)` 链路透传
    （RPN 叶名路径此前丢 op 上下文）。
  - 删 `find_partial_field`（被 Datatype::find_truncation 取代;两处
    op_ptrsub STRUCT 臂调用点同步转换,UNION 臂本就 consult map）。
- **效果（本 worktree fast-release 亲测,基=master 594d6982）**:curl canon
  246→244（main 85→83）——D 族 9 站点全部 golden 形态:8 站点
  `content = (union_5a7)V._8_16_`（整成员+RHS cast,cast 名残差=
  DWARF-ANON-TYPENAME-0001 登记票）+`content._8_8_`;反例 golden:746 站点
  `.content.Set.elements` 字节恒等（consult 命中 (union,COPY@t17136,-1)=
  field 0）。cast 名落地后 curl canon=200（sed 模拟亲证 244→200,即 D 族
  全额 −46,名字票面=−44 工具度量）。httpd/bank/镜面见 lane 报告。
  - 测试侧 3 处 `get_varnode_display_name` 裸调用补 `None` consult 参数
    （单测名诊断路径,无数据流边,语义=无 union consult）。

### 2026-09-26 — MIGW1-TYPEOP-0002 per-op virtual emitters（printc.hh:283-344 Rust 化）

- 新增 printc.hh:283-344 全部 53 个具名 per-op 虚方法（`op_int_equal`..
  `op_lzcount`，`_rpn` 后缀者为 printc.cc 真函数体族：opIntZext/opIntSext/
  opBoolNegate/opFloatInt2Float/opFloatFloat2Float/opFloatTrunc/opSubpiece/
  opPtradd），共享机制 `rpn_op_binary`（printlanguage.cc:546 opBinary：negatetoken
  翻转前奏 + pushOp + 反序 pushVn）与 `rpn_op_unary`（:566）。token 一律经
  optoken::BINARY_TOKENS 注册表 id 显式传入（oracle 静态 OpToken 实例身份）。
- `dispatch_op_rpn` 的 52+PTRADD 臂退役为 `crate::typeop::push_opcode_rpn`
  提前委托（typeop.rs 承载路由——oracle 的 TypeOp::push 层）；INT_ADD 结构
  字段恢复前检查随迁 `op_int_add`；SUBPIECE/PTRADD 臂体原样抽为
  `op_subpiece_rpn_full`/`op_ptradd_rpn`（行为零变化，canon A/B 逐字节恒等
  亲证）。
- opBoolNegate 完整三分支（printc.cc:814-828）首次落地：branch1 negatetoken
  消费直推 in0、branch2 checkPrintNegation 命中时 `mods|negatetoken` 骑 nodepend
  （rpn_op_binary 的翻转前奏消费——`!(a==b)`→`a!=b`，双重否定抵消）、branch3
  boolean_not token。B2 fixture 三 case 锁定。
- fixture 顺带暴露并修复 prettyprint.rs 补偿层 pass3 缺陷（见
  docs/api/prettyprint.md 同日节）；`rpn_def_inline_reachable` 补 FLOAT_NAN/
  POPCOUNT/LZCOUNT（printc.hh:317/343/344 opFunc 臂可达）。

## 2026-09-26（Lane F4WEBTYPE）— Priority-0 字符串字面量渲染加 oracle 类型门（HTTPDMAIN-F4-WEBTYPE-0001）

`push_varnode` 的 Priority 0 与 Case A（COPY-from-Const）字符串字面量渲染不再
按裸 `string_table` 地址命中发射：新增 `string_render_eligible`
（// Ghidra: printc.cc:1698 PrintC::pushPtrCharConstant 锚）只放行 oracle 的
两条同路径赋型通道——
- **Gate A**（printc.cc:1781-1782 `subtype->isCharPrint()`）：varnode 自身类型
  为 charPrint 指针（pushConstant TYPE_PTR 臂的原生条件）；
- **Gate B**（typeop.cc:687-716 `TypeOpCall::getInputLocal` 经
  varnode.cc:900-937 `getLocalType` + coreaction.cc:5043-5066 `writeBack` 的
  ActionInferTypes 通道）：CPUI_CALL 输入槽的 callspec 原型锁定 char\* 参数
  （CALLIND 的 callspec 需父 Funcdata 解析，PrintC 无 fd 通道，只走 Gate A）。

裸字符串地址常量（int 网中的 lea 常量）回落为普通常量渲染——oracle 的
`int iVar3 = 0x17a422` 形态（非 `pcVar4 = "ptemp"`）。canon 双语料 A/B 字节恒
等（类型层已在位时门零观察差；F4 主体修复在 arch.rs 的寄存器空间过滤，见
docs/api/arch.md 2026-09-26 节 + 双侧 fixture
coreaction_constptr_registerspace_1204）。单测
`test_string_render_eligible_oracle_gates`（回归-only 手写期望：B2 oracle 真
值由双侧 fixture 承担）。

## 2026-09-26：单例发射族 15 项（WORKPKG-UNMAP-PRINTC-0004 / PRINTC-UNMAP-SINGLETON-0001）

分诊 §P0 包规格逐项核验+处置（基=master 9ac04ade，oracle e40ed130 亲读）：

**真缺失 → 全量移植**：
- `push_float`（printc.cc:1380-1424）——`push_float_text` 双路径文本核 +
  float_emulate.rs `print_decimal`（float.cc:427-459 %g/%e 往返环）+
  `calc_precision`（float.cc:217-223，decimalMin/MaxPrecision 字段）+
  `get_float_format`（translate.cc:962-970 默认 4/8 IEEE 形态）。语料休眠
  （curl/httpd 零浮点常量），双侧 fixture 激活。
- `checkAddressOfCast`（printc.cc:376-418）——全量替换
  `rpn_op_type_cast`/`op_type_cast` 两处旧 in0-is-array 简化启发；typedef
  剥离环（cc:390-393）为恒等形态（Rugra 类型系统无 typedefImm 链，
  type_system 在飞租约 handover）；类型相等以 `Datatype::compare==0`
  （Ghidra 工厂驻留指针相等的非驻留等价）。单测五例矩阵
  `test_check_address_of_cast_matrix`；双侧全 IR fixture 登记
  PRINTC-SINGLETON-IRFIX-0001。
- `emitSymbolScope`（printc.cc:233-259）——`emit_symbol_scope`，函数自身
  符号的作用域前缀（emitFunctionDeclaration cc:2591 在 tagFuncName 前）；
  全局作用域深度 0 快路径 + 局部名影子 `::` 臂（symbol_scope_prefix 同规）。
- `setCommentStyle`（printc.cc:2350-2361）——`set_comment_style` +
  `set_c_style_comments`/`set_c_plus_plus_style_comments`（printc.hh:242-243）
  + `set_comment_delimeter`（printlanguage.cc:98-110）+ `commentstart`/
  `commentend` 字段（emit_line_comment 消费，cc:601/645-646）；options.rs
  OptionCommentStyle 接线为 handover（Architecture 无 printlist 字段）。
- `initializeFromArchitecture`（printc.cc:2332-2340）——doc_function 入口
  幂等求值 size_suffix（见上）。
- `adjustTypeOperators`（printc.cc:2342-2348）——文档化 no-op 端口：三件
  （scope.print1="::" / shift_right.print1=">>" / selectJavaOperators(false)）
  均为 Rugra 已固化的 C 默认。
- `resetDefaults`（printc.cc:2325-2330）——`reset_defaults` 链
  PrintLanguage::resetDefaultsInternal（printlanguage.cc:575-583 字段逐项）+
  resetDefaultsPrintC；emit 半为 emitter 域 handover（Rugra emitter 无跨文档
  选项）；Architecture printlist 循环保持既有结构缺口注记。
- `pushTypePointerRel`（printc.hh:365-370）+ opPtrsub ptrel 臂
  （cc:947-976/966/1023/1030/1042/1048/1109/1115/1124/1132）——RPN 生产
  路径全量：ptrel 解析（isFormalPointerRel=IS_PTRREL&&!HAS_STRIPPED +
  evaluateThruParent）、parent 再定基 suboff（+getAddressOffset 后
  calc_mask 折叠）、suboff==0 特例臂、四 struct/union 发射形与四 array
  发射形的 ADJ 前插。TypePointerRel 状态在 PointerRelState（datatype.rs）
  ——旧 "Rugra has no TypePointerRel" 注释已过期，同批更正。legacy
  direct-emit op_ptrsub 保持塌缩形（非生产路径注记）。
- `pushImpliedField`（printc.cc:2085-2116）——消费半
  `rpn_push_implied_field`（rpn_recurse 的 hasImpliedField 臂，
  printlanguage.cc:527-529）+ varnode.rs `has_implied_field`/
  `set_implied_field` 访问器（HAS_IMPLIED_FIELD 旗标已在位）；生产半
  （coreaction.cc:2519 setImpliedField）为 coreaction 在飞租约 handover。
  单测 `test_push_implied_field_union_arm`。
- `PrintCCapability`（printc.cc:108-119）——`capability()` 注册记录
  （name="c-language", isdefault=true）。

**已在（核验修正票面）**：`pushMismatchSymbol`（2067，partial_symbol_text
内 `_name`/unnamed-location 双臂）、`genericFunctionName`（3359，提取为
具名 `generic_function_name`——纯 oracle "func_"+printRaw 形；FUN_ 层适配
移至 opCall 未名被调臂调用点）、`emitSwitchCase`（3129，标签+default+goto+
break 四臂已在 emit_structured_switch；pushConstant→push_integer+CHAR 近似
修正为 char_constant_text(DEFAULT)——cc:1630-1640 的 vn=0 ≥0x80 回退整数
语义）、`doEmitWideCharPrefix`（1504，方法化 `do_emit_wide_char_prefix`，
三消费点接线）、`PendingBrace::callback`（2872，PENDINGBRACE 车道已处理——
emit_pending 即 open_brace_indent(style)，核验答案=是）。

**B2 双侧 fixture**：`printc_singleton_emission_1204`（36 case 字节恒等，
runner tools/run_printc_singleton_emission_oracle.sh + metadata 三件套）——
push_float 21 例（含 scinote/subnormal/往返精度）、setCommentStyle 5 例、
genericFunctionName 3 例（printRaw 位数规则 32/64 位）、emitSymbolScope 2 例
（BFD 函数符号深度 0）、pushMismatchSymbol 2 例、pushTypePointerRel 1 例
（ADJ(base)0 形）、wide-char 2 例。checkAddressOfCast/pushImpliedField 的
全 IR 双侧 fixture 登记 PRINTC-SINGLETON-IRFIX-0001（Rust 单测先行）。

**镜面杠杆（F-STRFOLD/F-PLTNAME）**：printc.rs 的 pushPtrCharConstant 链
（1698-1722）经探针核验**完整且行为正确**——F-STRFOLD 断点在驱动侧 readonly
通道：镜面 print_db 无 BfdArchitecture fillinReadOnlyFromLoader
（architecture.cc:1371-1381）装的 SEC_READONLY 属性范围，isReadOnly 门
（cc:1709）恒拒。httpd 驱动镜面 print_db 补装（SHF_ALLOC&&!SHF_WRITE 段，
20 范围）→ httpd 镜 156→**152**（pcVar19="0.0.0.0"/pcVar19="255.255.255.255"
两折叠点与 golden 逐字同形；golden 其余折叠点的常量在 Rugra IR 未获 char*
型=varmap/SSA merge 上游域残差，如实登记）。F-PLTNAME：curl 驱动镜面
bare-load 过滤器排除 .plt.got 槽（oracle registerPltStubs 只走 .rela.plt
JUMP_SLOT）→ curl 镜 52→**50**（`func_0x000022e0` 与 golden 逐字，
__do_global_dtors_aux diff=0）。

**验收（fast-release 亲测）**：canon curl 200/0/0、canon httpd 229/0/0
（双基线字节恒等）；镜面 curl 50·74 matched、httpd 152·29、vsh 15/16·71、
sq 4479/7500·810（sq 较基线 4481 又改善 2 行）、sqlite 见终报；bank
391/391；cargo test --lib **1808P/0F**（+3 新测）；三门禁绿。

### 2026-09-27 — PRINTC-NEGTOKEN-PATH-0001: legacy opCbranch 补 checkPrintNegation 快路径（Lane NEGTOKEN）

**缺口（APHTTRIAGE 分诊钉出）**：oracle `PrintC::opCbranch`（printc.cc:536-580）
在 cc:558-563 有一条 negatetoken 快路径——flip 存活时先问
`checkPrintNegation(op->getIn(1))`（printc.cc:2388-2398：implied+written+
`get_booleanflip` 可翻转集，opcodes.cc:94-135），可翻则 `m |= negatetoken;
booleanflip = false`，跳过 `pushOp(&boolean_not)`（cc:564-565），由
`pushVn(in(1), m)` 把修饰符送进 def op 虚 push：比较 op 走
`PrintLanguage::opBinary` 的 `tok = tok->negate` 前奏
（printlanguage.cc:549-554，六个 negate-set token printc.cc:129-134，
FLOAT 比较共用 printc.hh:313-316）；BOOL_NEGATE def 走 `opBoolNegate` 的
negatetoken 臂（printc.cc:817-819）双重否定抵消直印内层。Rugra 侧 RPN 生产
孪生 `op_cbranch_rpn` 已有该臂（14236-14248），**legacy direct-emit 孪生
`op_cbranch` 只有 `!(...)` 回退形**——潜在差预防票（七面零现行实例：Rugra
`if (!(` 计 0，golden 3 处均为不可翻 `!(bool)` 回退形）。

**修复（1:1 补齐）**：
- `op_cbranch`：cc:558-563 决策结构逐行移植——`booleanflip && in(1) 存在`
  时调 `check_print_negation`（既有忠实移植，printc.rs:19878），成功则
  `negate_token=true; booleanflip=false`；渲染三分支：fold 成功走
  `emit_cbranch_condition_negated`，存活 flip 走原 `!(...)` 形，否则原样。
  cc:554/570 的条件括号对三分支统一保留（oracle fold 不影响外层括号）。
- `emit_cbranch_condition_negated`（新，legacy 传输的 negatetoken 消费者）：
  ①BOOL_NEGATE def（≥1 输入）→ 双重否定抵消，标 inlined 后
  `emit_condition(inner)`；②可翻比较 def（EQUAL/NOTEQUAL/SLESS/SLESSEQUAL/
  LESS/LESSEQUAL/FLOAT_EQUAL/NOTEQUAL/LESS/LESSEQUAL，≥2 输入）→ 标 inlined
  后 `push_input_parenthesized(def,0) + 翻转 sym +
  push_input_parenthesized(def,1)`（flip token 与源 token 同优先级类
  equal↔not_equal 38 / less_than↔greater_equal 42，paren 决策等价——与
  emit_condition BOOL_NEGATE Case-1 同一论证）；③防御臂回退字节恒等的
  cc:564-565 形。翻转表=printc.cc:129-134 逐字：`==`↔`!=`、`<`→`>=`、
  `<=`→`>`（SLESS 族 `<`/`<=` 渲染、FLOAT 共用 token）。捕获文本过共享
  R50 谓词 `cbranch_condition_text_valid`（自 `emit_cbranch_condition`
  行为保持式提取），失败回退旧形，永不出裸残缺条件。
- 附带：`emit_cbranch_condition` 的 R50 判据提取为
  `cbranch_condition_text_valid`（纯重构，行为零变化）。

**影响面（诚实归因）**：改动仅 legacy 传输（`rpn_enabled=false` 通道）——
生产默认与全部 E2E 驱动（curl/httpd/gen 等）显式 `set_rpn_enabled(true)` 走
RPN 孪生（其 fold 臂已在位，MIGW1-TYPEOP-0002 交付）。canon A/B（亲父
2cce7b99 独立 worktree 双构建）curl/httpd **字节恒等**（96429B/63226B）；
镜面五面全 PASS 零回退。B2 状态：legacy 传输本征 NO_ORACLE（oracle 无第二
opCbranch 可隔离运行），决策结构以 4 个 Rust 单测钉死（fold 翻转/ftT 诱导
flip 折叠/BOOL_NEGATE 双重抵消/不可翻回退）；生产 RPN fold 臂的 oracle 行为
由 `tests/oracle/typeop_push_dispatch_1204` 的 BOOL_NEGATE 三分支链 fixture
（`!(a==b)`→`a!=b` 翻转 case）覆盖。negate 奇偶族站点（ap_ht_time/
sqlite3VdbeSorterRewind）的激活依赖 BLOCKACT-CONDNEGATE-PARITY-0001（P3）
先落地——彼票修复后 oracle 翻转奇偶对齐，若届时 Rugra 侧 flip 携可翻比较
存活到 legacy 打印则本路径接住。

**验收（fast-release 亲测）**：canon curl 124/157/0/0、canon httpd
34/141/0/0（=亲父，字节恒等）；镜面 curl 56/56·74/74、httpd 92/94·29/29、
vsh 15/16·71/71、sq 4227/7500·810/810、sqlite 26411/26411·1385/1385 全
PASS；bank 391/391 MATCH；cargo test --lib **1909P/0F**（=亲父 1905+本票
4 新测）；annotations/refs 三门禁绿。

**2026-09-27（PRETTYPRINT-SIGWRAP-0001）**：`emit_function_declaration`
的签名分隔 token 修正为 oracle 的 tokenbreak 形态。亲读
printc.cc:2577-2603 全函数体 + prettyprint.cc:541-1245 EmitPrettyPrint
全算法后钉根因：返回类型与函数名之间的 `emit->spaces(1)`（printc.cc:2582）
此前实现为 `emit.print(" ")`（内容 token），而 oracle 是 **tokenbreak**
（1 强制空格、bump 0，prettyprint.hh:914 `TokenSplit::spaces`）。在
EmitPrettyPrint 的 Oppen 级联（scan/advanceleft/print，prettyprint.cc:741-833）
里，内容空格会多压一个 checkstring 断点 + 一个 string token 进
tokqueue/scanqueue，使溢出级联在**返回类型之后**断行（镜面 SIG-WRAP 族：
`xunknown8 ⏎<name>⏎          (params)`，10 空格续行）；tokenbreak 形态下
该断点命中"省不了多少就不换行"豁免（cc:680-685 `val-spaceremain<10`），
级联落到函数名→`(` 的 `function_call` 断点（bump 10），产出 oracle 形
（返回类型与函数名同行、参数表次行 20 空格缩进）。同函数 calling-convention
臂的 `emit->spaces(1)`（cc:2587，镜面/canon 脸 `printModelInDecl`=false
死臂）同步对齐。EmitNoMarkup 脸构造性中性（spaces(1,0) 折叠=1 空格=原
字节）。验收：sq 镜面 skeleton 4197→**3953**（−244 行=75 hunk 全族收敛，
defects/numbering 双零）；`_ZThn16_..SetCoderProperties` thunk、
`initialise_threads`/`SkipMatchesSpec`/`LzmaEnc_MemPrepare` 逗号续行形
与 golden 逐字节一致；canon curl/httpd A/B 字节恒等（96429B/63214B）；
行级行为以 prettyprint.rs `linewrap_probe_tests` 两新测钉死。

## 2026-09-27：partial-symbol finalcast pushType 拼写 + LHS allowCast 门（TYPEFACTORY-UNKBYTE-EMPTYCAST-0001 ①②）

**根因（双侧对照钉死，sq 镜面 read_inode 族）**：golden
`uRam…._0_3_ = CONCAT12(…,(unkbyte3)uRam…)` vs Rugra
`()uRam… = CONCAT12(…,()uRam…)`——两处偏差：

1. **空 cast 拼写**（读侧 `(unkbyte3)` 位点）：oracle
   `PrintC::pushPartialSymbol`（printc.cc:1947-2065）的 allowCast 臂在
   cc:2025 存 `finalcast = outtype`（Datatype\*），**渲染**在 cc:2044-2046
   经 `pushOp(&typecast) + pushType(finalcast)` → `pushTypeStart`
   （cc:280-285）——匿名基型拼 `genericTypeName`（`unkbyte3`/`unkuint7`），
   非原始空名。Rugra `partial_symbol_walk`（printc.rs）在臂内直接
   `finalcast = Some(outtype.get_name())`——匿名类型名恒空 → 印 `()`。
   同型偏差在 RPN 孪生 `rpn_push_partial_symbol` 的 finalcast atom
   （`finalcast.get_name()` 原始名）。**修复**：两处均改走
   `cast_type_string`（printc.cc:1472-1476 pushType 的结构折叠拼写，
   含 buildTypeStack 指针/数组层与匿名 genericTypeName 回退）。
2. **LHS 整槽+cast vs 子槽条目**（赋值目标 `uRam…_0_4_` 位点）：oracle
   赋值 LHS 走 `emitExpression`（printc.cc:2468-2495）→
   `pushSymbolDetail(outvn,op,false)`（cc:2475，isRead=**false**）→
   `pushPartialSymbol(…, allowCast=false)`——cast 臂被门死，走合成条目
   `unnamedField(off,sz)`=`._off_sz_`（cc:2030-2041）。Rugra RPN 叶路径
   `make_atom_for_vn`→`get_varnode_display_name`→inner 的
   `push_symbol_detail_leaf(vn, true, …)` **硬编码 true**（读路径语义），
   emit_expression_rpn 虽在 LHS 原子构造窗外设了 `is_lhs=true`
   （consult slot=-1 半已对齐），allowCast 半漏接 → LHS 走 cast 臂印
   `(T)sym`/`()sym`。legacy 通道（push_varnode 行）本就 `!self.is_lhs` ✓。
   **修复**：inner 调用点改 `!self.is_lhs`（printlanguage.cc:256-257
   isRead 语义）。

**非本票残差（如实登记）**：③掩码/位移规范序（`(V & LIT) >> LIT` 折叠
形态）= ruleaction 域（RULEACTION-NEGCONST-FOLD-0001 邻接）；Rugra 镜面
`axStack_70[0]._0_4_` vs golden `axStack_70._0_4_` 的多余 `[N]` 元素下钻
= walk 所见符号类型为 ≥4 字节元素数组（`xunknown8 [1]` 形）而 golden 符号
类型为 1 字节元素（`xunknown1 [8]`）——varmap 域栈数组符号类型构造残差
（VARMAP-UNAFF-TYPEMAT-0001 租约）。

**验收（fast-release 亲测，基=master 48146429）**：镜面 sq
4197→**4141**（−56，defects 0/numbering 0，census 族归因 OPNAME-LEAK
183→143、CONDNEGATE 块内 −10、余为块内行替换；逐函数：read_inode_2
176→126/read_inode_1 80→76/LzmaEnc_CodeOneBlock.part.0 115→113，
read_inode_3 160 行数持平=行替换零净变（`()V`→`._0_N_` 形翻转））；
canon curl **157/0/0==MB23 钉值 + 与基线 result/curl_cur.c 字节恒等**、
httpd **139/0/0==钉值**（2 行形翻转在既有差异块内，已归因）；bank
391/391 MATCH；cargo test --lib **1919P/0F**（基线 1917+2 新测：
test_partial_symbol_finalcast_spells_pushType_form /
test_display_name_lhs_gates_partial_cast_arm）；annotations/refs/evidence
三门禁绿。

### 补遗（同日第二 commit）：legacy 传输三臂同根因收口

`emit_inline_expr` INT_ZEXT/INT_SEXT 臂、`op_unary` INT_ZEXT/INT_SEXT 臂、
SUBPIECE `isSubpieceCast` 臂的 cast 前缀由原始 `get_name()` 统一改
`cast_type_string`（printc.cc:786/799/872-875 → opTypeCast → pushType
cc:1472-1478 的同一折叠）——消除 legacy 通道匿名类型印 `()` 的同型位点。
构造性输出中性：生产驱动全走 RPN（`set_rpn_enabled(true)`），read_inode_2
单函数+canon curl 复跑与主修复态字节恒等；cargo test 1919P/0F。

### 2026-09-27：GA-2 SWITCHHEADUNIQUE — emit_switch_head_expr 走 opBranchind RPN 通道（8 位点 unique 泄漏收口）

**症状（GIANTS-DRILL 钉面）**：sqlite 镜面全语料 `unique0x` 恰 8 位点、全部是
switch 头——Pragma 簇 6 处 `switch(*((uint1 *)unique0x00008f00))` +
ExprCodeTarget 2 处 `switch(*(uint8 *)unique0x00008f00 & 0xffffffff)`；golden
0 处（印 `(uint1)puVar30[1]` / `*(uint8 *)(in_R11 + 2) & 0xffffffff`）。

**根因核验（前会话探针 + 本车道 oracle drill 双证，修正 GIANTS-DRILL 的推断）**：
- **jumptable fold-in 无辜**：`foldInNormalization`（jumptable.cc:1546-1553，只
  `opSetInput(indop,switchvn,0)`）Rugra 侧已 1:1——print 时 BRANCHIND 输入链
  **完整存活且 implied**（探针 FLAGS 亲证：`branchind@ad66a → LOAD@ad657 →
  PTRADD@ad657 → SUBPIECE@ad612` 全活全 implied）。GIANTS-DRILL "IR 里地址输入
  已无活定义" 是从输出文本反推的错误推断（报告内以 ⇒ 标注）。
- **真根因 = print 传输层**：`emit_switch_head_expr` 主路径走 legacy
  `push_varnode`/`emit_inline_expr` 通道，该通道**无 PTRADD/PTRSUB 臂**——
  implied PTRADD 输出落入 `_ =>` unnamed-location 回退（printc.rs
  `pushUnnamedLocation` 形），裸印 `unique0x00008f00`。
- **oracle 侧终态 IR 亲证**（stage_drill_1204 on sqlite3Pragma，OPACTION_DEBUG
  逐 Action 帧）：`switchnorm` 后 BRANCHIND 输入=1 字节 LOAD 输出
  （`u0x00023b00:1@ad657:447`）；`ptrarith` 把地址 INT_ADD(RAX,8) 转成
  PTRADD(RAX,#0x1(*#0x8))；`cleanup:expandload`（RuleExpandLoad，
  ruleaction.cc:10919——pointee uint8>1 字节走自然截断臂）把 LOAD:1 扩成
  LOAD:8 + SUBPIECE:1——**golden 的 `(uint1)` 前缀就是该 SUBPIECE 经
  opSubpiece→opTypeCast 印出的 cast**（printc.cc:869-885 isSubpieceCast 臂），
  `puVar30[1]` 是 opLoad checkArrayDeref 数组形 + opPtradd 下标形
  （printc.cc:487-497/880-893）。setcasts 全程未触及该链（无独立 CAST op）。

**修复（1:1）**：`emit_switch_head_expr` 主路径（活 BRANCHIND 输入）改走
`rpn_push_vn(vn, branchind, mods)` + `rpn_recurse()`——即 opBranchind
（printc.cc:582-591）的 `pushVn(op->getIn(0),op,mods); recurse();` 逐字通道，
switchvn 定义链经 per-op PrintC virtuals（opLoad/opPtradd/opTypeCast/
opSubpiece）渲染，与普通表达式完全同构。`rpn_enabled=false` 时保留 legacy
路径作回退（与 emit_block_condition 同一约定）。快照回退臂
（index_varnode/末位 BRANCHIND/CBRANCH 比较）原样保留——控制块无活
BRANCHIND 时 oracle 根本不会印 switch 头，属 Rugra 胶水面。

**结果（sqlite 镜面 A/B，基 e5fb3e54 双构建）**：
- 8/8 位点 unique 泄漏全消；ExprCodeTarget 2 位点与 golden **逐字恒等**
  （`switch(*(uint8 *)(in_R11 + 2) & 0xffffffff)`，含变量名）。
- Pragma 簇 6 位点印 `switch(puVar25[8])`——泄漏消除但距 golden
  `(uint1)puVar30[1]` 残三差：下标 `8` vs `1`（PTRADD 元素尺寸 1 vs 8）、
  缺 `(uint1)` cast（RuleExpandLoad 不触发）、变量编号（GA-1 级联域）。
  **三差同根 = 指针 pointee 类型分歧**：Rugra 把该链指针定型 `uint1 *`
  （golden `uint8 *`，sqlite3Pragma 参数面 uint1*×4 vs uint8*×3+int8），
  系 switchvn 字节 load 的反向类型传播（TypeOpLoad::propagateType out→ptr）
  在 Rugra 侧胜出、oracle 侧被正向证据压制——infertypes 域，已登记
  `GA2-SWITCHVN-POINTTEE-TYPE-0001` 移交，非本票写域。
- 新单测 `test_switch_head_expr_rpn_channel_ptradd_inline`：手搭
  BRANCHIND←LOAD←PTRADD(implied) 链，断言数组形 `[1]` 印出且
  `unique0x` 永不出现（钉死通道选择，防 legacy 回退回归）。
