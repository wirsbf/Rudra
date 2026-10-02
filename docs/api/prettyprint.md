# `prettyprint.rs` API Reference

## 2026-09-28：MAINMIXED-WRAP-0001 — 标点后 spaces(1) tokenbreak 的溢出断点回归测试（Lane MAINMIXED）

新增测试 `pretty_print_overflow_breaks_at_punct_spaces_token_no_trailing_space`
（tests 模块）：构造 100 列内唯一显式断点=标点（`,`/`;`）后 `spaces(1,0)` 的
token 流，断言溢出断行落在该 tokenbreak——标点保留在首行行尾（**无行尾空格**）、
续行接条件表达式。锁定的发射契约：printc 的 comma_separate 分隔符
（printc.cc:2708-2709）与 emitForLoop 子句分隔（cc:2981-2982/2984-2985）必须
保持 `print(punct)` + `spaces(1)` 双调用——胶合成单 token 会把强制断行推到
合成 0 宽分隔上（行尾空格 + 折点错位，canon httpd main :194 / curl :531/:2273
修复前实录）。Oppen 强制断行机制本身（scan/cc:792-800 `scanqueue.popbottom`
自底强制 + print/cc:672-699 tokenbreak 换行）未改动。

## 2026-09-27：PRINTC-PRINTLIST-WIRING-0001 — Emit::resetDefaults/getMaxLineSize 虚面（Lane PCHOVER2）

`Emit` trait 新增两方法（PRINTC0004 emitter-reset handover 的承接面）：

- `reset_defaults`（prettyprint.hh:424 基虚）：基语义=`resetDefaultsInternal`
  （`indentincrement=2`，hh:103）；Rust 纯文本 emitter 无跨文档打印选项（indent
  态为 per-document、由 `clear` 复位），默认实现=结构性 no-op。`EmitPrettyPrint`
  覆写（prettyprint.cc:1237-1242）：lowlevel 半吸收（Rust `EmitNoMarkup` 无
  `indentincrement` 字段）+ 自身 `indentincrement=2` +
  `resetDefaultsPrettyPrint`=`setMaxLineSize(100)`（hh:1066；连带重整
  scan/tok 队列与 `clear`，cc:1225-1234）。消费点=`PrintC::reset_defaults`
  首行（printlanguage.cc:674 `emit->resetDefaults();`）。
- `get_max_line_size`（hh:409 基虚返回 -1；`EmitPrettyPrint` 覆写 hh:1109 返回
  `maxlinesize`）。

另增 `EmitPrettyPrint::debug_lowlevel_output_ref`（RUDRA-GLUE 观测通道，
`EmitNoMarkup::debug_get_output_ref` 同族）：不消费 emitter 读 lowlevel 已提交
字节——活体 printer 的 fixture 观测面（printc_printlist_wiring_1204 render 通道）。

## 2026-09-26：GEN4-SQ-DUPDECL-NUMBERING-0001 — mirror 面整体跳过声明注入臂

`post_process_output_legacy` 的两个声明注入臂（`backfill_missing_locals` 的前缀猜型
注入与 `flush_func_remove_unused` 的 `int uVarN;` 补注/未用删除半臂）在 **direct-runner
（mirror）契约面整体早退**：新增 `EmitNoMarkup::mirror_face_active()`（`OnceLock` 惰性
探测一次），env 集 = `RUDRA_MIRROR`/`RUDRA_FLOW_MIRROR`/`RUDRA_GEN_MIRROR`，单一来源
`type_system::typefactory::direct_runner_tier_active`（MIRROR-ENVS-CANONICAL-0001）。
两个入口在 mirror 面直接 `return text.to_string()` / `out.extend(func_lines)`，canon 面
（无 env）行为逐字节不变。

**根因（SQATTR 发射流取证，fwd680.log 28483 条 Emit 调用）**：printc 作用域通道只发
一次且位置正确；sq GetOptimum（`--one 680`）函数体中部（do/if 块内）的 canon 档声明块
全部来自注入臂——其 declared 探测与签名启发式**只解析 canon 拼写**
（`int `/`long `/`char `/`undefinedN` 与 `legacy_never_type_evidence` 表），mirror 档的
`int4`/`xunknownN`/`code` 声明行全部不被识别：

- `backfill_missing_locals` 的 `sig_shape` 把携带 `(int8 *)` 强转型（内含 " *" 子串）、
  无 `;`/`=`/比较符的**多行条件续行**误判为函数签名（GetOptimum 三处：cast 续行
  `*(char *)(*(int8 *)…)+1))) {` 形），块内已声明符号全部读作 missing → 前缀猜型
  canon 重声明注入块内（`int iVar16; … char *piVar33; long uVar14; …`，base 实测
  761-776/841-863/1110-1112 三块 24 行，numbering=7 的全部来源）；
- `flush_func_remove_unused` 的 `type_ok` 表同因不识 mirror 拼写 → 声明收集为空 →
  body 内 uVarNNN 全部"missing"，`last_decl_idx` 回退 0（签名与 `{` 之间 K&R 位）。

**oracle 对照（机制 E 亲读，e40ed130）**：`docFunction`（printc.cc:2641-2676）全序列 =
beginFunction → 注释 → 签名 → openBraceIndent → `emitLocalVarDecls`（**唯一**声明点，
:2260-2279 → `emitScopeVarDecls` :2518-2575，每符号恰一次 `emitVarDeclStatement`）→
emitBlockGraph → closeBraceIndent → flush；`EmitPrettyPrint::flush`
（prettyprint.cc:1194-1211）是纯 token 队列排空，**零文本扫描/零注入**。direct-runner
goldens（`tests/golden/*_1204.direct-runner.c`）零注入声明行。两臂本是 canon 面
self-containment 补偿（POSTFIX-RETIRE-0001 W0 域），在 mirror 面跳过 = 清除自创层
误射方向（整层退役仍按 W1-WT 路线）。

**验收**：`--one 680` numbering 7→0（defects=0，注入三块消失，输出 1280→1256 行，
顶部 `char *pcVar34;` 与 golden:49904 同形）；sq 面官方 gate numbering=0 → 面转绿；
canon curl/httpd A/B 字节恒等；镜面四面棘轮 65/150/16/7500 未重钉全 PASS。

## 2026-09-25：PRINTC-EMIT-TAGLINE-ABS-0001 — `tagLine(int4)` 绝对形独立成 `tag_line_indent`

oracle 的 Emit 基类有两个**分离的**换行 virtual（prettyprint.hh:173/180）：无参
`tagLine()`（相对——当前缩进级：EmitNoMarkup 印 `indentlevel` 个空格，hh:557-558；
EmitPrettyPrint 发 bump_t 令牌，hh:918-920）与带参 `tagLine(int4 indent)`（**绝对**——
endl + 恰好 `indent` 个空格：EmitNoMarkup hh:559-560；EmitPrettyPrint 发 line_t 令牌，
hh:922-924，break 路径 cc:674-676 `spaceremain = maxlinesize - indentbump` 后
`lowlevel->tagLine(indentbump)`）。Rudra 的单一 `tag_line(indent)` 入口把两者合一：
`indent==0` 落相对形——而 printc.cc:3211 `emitLabelStatement` 的 `emit->tagLine(0)`
恰恰是**带参绝对形**（goto 标签 `LAB_…:`/`switchD_…_caseD_…:` 恒列 0 顶格，与嵌套
深度无关），导致 curl 32 处/httpd 34 处标签行带缩进、canon 全部顶格。

本提交按 oracle 结构拆分：`Emitter` trait 新增 `tag_line_indent(indent)`（带参绝对形，
默认 no-op 对应 stub emitter），`EmitNoMarkup` 实现为换行 + `indent.max(0)` 个单空格，
`EmitPrettyPrint` 实现为 emit_pending + checkbreak + line_t 令牌（cc:928-933 顺序）。
`tag_line(indent)` 收窄为纯相对形（遗留 `indent>0` 绝对臂删除；全部剩余调用点传 0 =
oracle 无参形态，debug_assert 钉死）。生产调用面：printc.rs 标签三调用点
（emit_label_statement/emit_any_label_statement 两臂）`tag_line_indent(0)`；
emit_line_comment 两处 fallback `tag_line_indent(indent)`（printlanguage.cc:597 亦带参
绝对形——EmitNoMarkup downcast 臂字节原样，非 NoMarkup emitter 走 trait 绝对形）。
后处理层（死区/P16 标签清除）全部基于 `trim()`，列不敏感，无需改动。

## 2026-09-25：P9 ` )` trim 豁免扩展到 BlockInfLoop 尾行（GENSMOKE-T6，wt/vshfix）

第九遍结构清理（P9）的引号外 `" )"`→`")"` trim 与双空格折叠自
MAIN-RC3-STRUCTURED-EMIT-0001 起豁免 `while(` 开头的行（紧凑 while-do 溢出
头 `while( true )`，printc.cc:3023-3028）。本提交把豁免扩到
`} while( true );` ——`PrintC::emitBlockInfLoop`（printc.cc:3111-3120）的
do-while 无限循环尾行：closeBraceIndent + spaces(1) + KEYWORD_WHILE +
openParen + spaces(1) + KEYWORD_TRUE + spaces(1) + closeParen + SEMICOLON，
`tagLine`/`closeBrace` 强制行界，trim 后恒行首；这是 Ghidra 发射序列中
**第二个也是仅剩的**字节含 ` )` 的形态。修复前 Rudra 尾行被 trim 成
`} while( true);`（vsh 镜脸 7 行、curl canon 2 行）。行为验证：vsh 镜脸
skeleton 549→55（T6 族归零）；curl canon 脸两行
`} while( true);`→`} while( true );` ==canon golden 1049/2362 行逐字节，
487→481/0/0。真实 do-while（`while (cond);`，printc.cc:3086-3093）不含
` )` 字节、不受豁免影响。

## 2026-09-24：DRIVER-SWITCHD-LABEL-0001 — P9 goto→尾调用改写排除 `switchD_` 标号族

驱动符号层（`examples/curl_decompile.rs`/`examples/httpd_decompile.rs` 的
code_labels 层，EX2 LAB_ 同机制）开始为 jumptable case 目标合成
`switchD_<dispatch 8位hex>_caseD_<case值hex>`/`switchD_<...>_default` 名
（headless DecompilerSwitchAnalysis 分析器行为：消费 jumptable.cc:2764-2791
`JumpTable::encode` 的 `<jumptable>` XML，在 case 目标建 LABEL 符号；
printc.cc:3164-3193 `emitLabel` 经 queryCodeLabel 命中打印全限定拼写）。
该族与 `LAB_`/`code_r0x…` 同类——goto 目标标号，永不是被调函数；golden 双语料
0 处 `return switchD`。P9 的"goto 已知 libc 名→`return f();` 尾调用"改写以
小写首字母+无 `code_`/`joined_`/`dup_` 前缀识别函数名,小写 `s` 开头的
`switchD_` 若不排除会整体改写成隐式声明调用 `return switchD_...();`（gcc
拒绝）。排除规则：`!func_name.starts_with("switchD_")`。

## 2026-09-22：WARN-EMIT2 R4 — 签名启发式排除比较运算符（glob_range 重复声明 0→6→0）

`backfill_missing_locals`（RUDRA-GLUE，无 oracle 对应）的签名形状启发式第四次
误命中：HERITAGE-PROMOTE-SYMBOLTAIL-0001 使 gp/glob 家族出现多行 if 条件续行
`iVar5 < *(int *)((int *)&((URLPattern *)(uVar4 + 0x50) + iVar8)->content + 4))) {`
——不以 `(` 开头（绕过 R3）、无分号（绕过 MAIN-IVAR4-DUP）、含 `(` 且含
`*`、以 `{` 结尾，被当作函数签名 → if 体被当嵌套函数，`int iVar5; … long
uVar4;` 六条重复声明注入块内（glob_range numbering 0→6）。R4 门：C 函数签名
永不含比较/逻辑运算符（`<` `>` `==` `!=` `&&` `||`；`>` 同时覆盖只出现在
表达式里的 `->` 字段链），全部排除出签名检测。

## 2026-08-30：POSTFIX-RETIRE-0001 W3 — P22 签名改写的词边界修复（glob_url 回归 golden）

W3 对 P22（`fix_unary_deref_declarations`）活跃突变的排查结论（curl 2/2、
httpd 2/2）：

- **glob_url（curl）= P22 自身缺陷**：体内合法解引用 `*glob` 使 `glob` 入
  derefed 集；签名内联改写的 `format!("{} {}", ty, name)` 模式（`int glob`）
  **子串命中了函数名区** `int glob_url(`，把返回类型改写成
  `char *glob_url(...)`——golden 保持 `int glob_url`，且 `return 0;` 随之
  变成从 char* 函数返回 int 的病态形态。修复：模式匹配加**词边界**（匹配
  前后字符均不得为 `[A-Za-z0-9_]`，前侧继续排除 `*`）——与
  `count_word_occurrences` 同一边界契约。修后 curl 输出恰一行变化
  （`char *glob_url(` → `int glob_url(`，与 golden 签名逐字节一致），
  curl 差分 3091→**3089**/0/0，httpd 字节不变；P22 计数 curl 2/2→**1/1**。
- **glob_set（curl）/ ap_stripprefix、ap_count_dirs（httpd）= 非 emit 层根因**
  （保留突变）：`int pos`→`char *pos`、`long param_1`→`char *param_1` 的根因
  是 FuncProto 参数类型为标量而 IR 有 `*param` 解引用（golden 中
  `ap_count_dirs(char *param_1)` 为指针类型）——归 varmap/类型传播域
  （W5，PTRARITH/TYPEOPFIX 族），printc emit 无对应判定点，本层不动。

## 2026-08-30：POSTFIX-RETIRE-0001 W3 — P13 void 拆分退役（PRINTC-VOIDCALL-0001 正解落地）

路线图 W3 节（FuncProto void + opReturn/opCall 形态 → P13）。P13（`return f();` →
`f(); return;` 文本拆分，**硬编码 13 个 libc 名**——机制 D 红旗）按 W1 计数器在
双语料双轮零突变，但其退役前必须把 void 判定迁回 oracle 真语义，否则表外任何
void 函数会静默产出非法 C（`return pthread_mutex_lock();` 类 gcc error）。

- **正解（本 commit，printc.rs 侧）**：oracle 中 void 调用语句形态来自 IR——
  `ActionFuncLink::funcLinkOutput`（coreaction.cc:1521-1541）对 **output-locked
  void** 被调方保持 CALL 无输出，`PrintC::emitExpression`（printc.cc:2471-2476）
  的 `outvn != 0` 测试随之不打印赋值 LHS（语句形态 `f(args);`），`opReturn`
  （printc.cc:758-761）对无值 RETURN 打印裸 `return;`。Rudra 在 print 层加
  FuncProto-void 投影守卫（详见 `docs/api/printc.md` 同日节）：callspec
  `prototype.output_type_locked && return_type==Void` 时投影无输出字节。
- **本文件改动**：删除 P13 拆分块（`void_funcs` 硬编码表 + 行改写循环），P14
  输入直接改接 P12 输出 `final_out`；计数器 `POSTFIX_PASS_NAMES` 24→23，
  `PF_P13` 删除（后续索引前移 P14..P27）。幸存名单：
  B1 P6 B2 P7 P8 P9 P10 P11 P12 P14 P15 P16c B3 P17 P18 B4 Pecase
  P22 P23 P24 P25 P26 P27。
- **验证**：curl `801614e0…`/httpd `e18b4503…` 与删除前**逐字节一致**（守卫在
  现语料上 dormant——`free`/`exit` 调用的输出已被 action 层的
  `func_link_output` 移除，黄金语料本就按语句形态渲染）；差分
  curl 3091/0/0 + httpd 2278/0/0 维持；计数器无漂移（P13 字段消失、其余相等）。
- **dormant 分支回归测试**：`printc.rs` 单测
  `test_void_callee_call_prints_statement_and_bare_return`（构造"CALL 输出幸存
  + callspec output-locked void"形态，断言语句形态 + 裸 return + 无
  `return f();`）与负向对照 `test_nonvoid_locked_callee_keeps_assignment_lhs`
  （locked 非 void 保留赋值 LHS）。oracle 侧真值锚点：锁定 golden 语料的
  `free(pcVar11);` 语句形态（`tests/golden/ghidra_curl_1204.c`）。

## 2026-08-30：POSTFIX-RETIRE-0001 W2 — A 队列零突变 pass 退役（尾部先行，一 pass 一 commit）

路线图 W2 节：W1 计数器实证 **A 队列 9 个 pass 双语料双轮零突变**
（LAB_ 族 P1/P1b/P2/P3/P4/P5/P16 + Pdl + P-wbfold），按管线**尾部先行**逐个删除。
每刀门禁：curl/httpd E2E 输出 sha256 与删除前**逐字节一致** + RUDRA_POSTFIX_STATS
计数器重跑（被删 pass 字段消失、其余 pass 计数不变，掩蔽检测）。oracle 依据：
`EmitNoMarkup`（prettyprint.hh:546-594）直写 emitter、`flush`
（prettyprint.cc:1193-1210）后零扫描、`docFunction`（printc.cc:2655-2666）以
flush 结尾——这些文本 pass 在 Ghidra 无对应物，删除即向 oracle 行为收敛。

- **刀 1（Pdl 重复 LAB_ 去重，管线 31/33）**：删除 `remove_duplicate_labels()`
  与其插桩点；P26（非法左值删除）输入改接 P25 输出。计数器
  `POSTFIX_PASS_NAMES` 33→32，`PF_PDL` 删除（后续索引前移）。
  验证：curl `c889d856…`/httpd `a67155de…` 与基线逐字节一致；计数器其余字段
  逐项不变（掩蔽零）。
- **刀 2（P-wbfold while→if 折叠，管线 25/33）**：删除 while-break 折叠 pass
  及其插桩点（B4 输出直供 P-ecase）；`POSTFIX_PASS_NAMES` 32→31。锁行为测试
  `pretty_print_while_break_fold_compact_prefix` 同 commit 改造为
  `pretty_print_while_break_compact_header_unfolded`——不再断言折叠结果
  `if (true) x = 1;`，改为锁定未折叠字节（紧凑头 `while( true ) {` 原样存活 +
  `!contains("if (true)")` 守卫退役事实）。PRINTC-WHILEIF-FOLD-PREFIX-0001 的
  切片逻辑随 pass 消失；MAIN-RC3 的 `while(` 豁免（P9/P17）保留。
  验证：双语料 sha256 与刀 1 后一致；计数器无漂移。
- **刀 3（P16 前向 goto→if 折叠，管线 19/33）**：删除 P16 折叠块与其插桩点，
  `negate_simple_condition()` helper 随之失去唯一调用点同 commit 删除；
  P16c（折叠后清理，**唯一活跃 LAB_ 族幸存者**，curl `main`=264 行）保留，
  输入直接改接 P15 输出（`pass15.join("\n")`）。`POSTFIX_PASS_NAMES` 31→30。
  验证：双语料 sha256 不变；P16c 计数仍 curl 277/3、httpd 0（掩蔽零——
  P16 零突变被删除后其下游 P16c 输入逐字节不变）。
- **刀 4（P5 未引用标签删除(2)，管线 7/33）**：删除 P5 块与其插桩点，
  `final_pass` 直接 move 自 P4 输出 `looped`。`POSTFIX_PASS_NAMES` 30→29。
  验证：双语料 sha256 不变；计数器无漂移（含索引完整性校验：数组序 ==
  PF_ 常量值）。
- **刀 5（P4 回边 goto→do/while 循环转换，管线 6/33）**：删除 P4 转换块
  （含 5 轮迭代收敛循环）与其插桩点，`looped` 直接 move 自 B1 输出
  `collapsed`。`POSTFIX_PASS_NAMES` 29→28。
  验证：双语料 sha256 不变；计数器无漂移；索引完整性 OK。
- **刀 6（P3 未引用标签删除(1)，管线 4/33）**：删除 P3 块与其插桩点
  （连同中间 `output_text`/`result_lines` 重 split），`final_result` 直接
  move 自首扫输出 `result`。`POSTFIX_PASS_NAMES` 28→27。
  验证：双语料 sha256 不变；计数器无漂移；索引完整性 OK。
- **刀 7（P2 条件出口 goto→if-break/return，首扫模式 2）**：删除 P2 模式块
  与其 bump 探针。`POSTFIX_PASS_NAMES` 27→26。`exit_labels` 预扫描暂留
  （P1b 仍消费，刀 8 一并退役）。
  验证：双语料 sha256 不变；计数器无漂移；索引完整性 OK。
- **刀 8（P1b 出口 goto→break/return，首扫模式 1b）**：删除 P1b 模式块与其
  bump 探针；**配套退役两件附属物**——① `exit_labels` 预扫描
  （goto_targets/defined_labels/exit_labels,P1b/P2 是其仅有消费者）；
  ② `has_enclosing_loop_ctx()` helper（P1b/P2 是其仅有调用点，oracle 中
  break/continue 由 FlowBlock::markUnstructured 结构化发射，从不扫描已发射
  文本）。`POSTFIX_PASS_NAMES` 26→25。
  验证：双语料 sha256 不变；计数器无漂移；索引完整性 OK。
- **刀 9（P1 冗余 goto 剥除，首扫模式 1；A 队列收官）**：删除 P1 模式块与其
  bump 探针后，首扫 while 循环退化为逐字拷贝——连同 `lines`/`result`/`i`
  声明整体删除，`final_result` 直接 `input.lines().map(to_string).collect()`
  构造（与原 `join("\n").lines()` 往返恒等）。`POSTFIX_PASS_NAMES` 25→24。
  至此 A 队列 9 pass 全部退役，幸存 pass 名单：
  B1 P6 B2 P7 P8 P9 P10 P11 P12 P13 P14 P15 P16c B3 P17 P18 B4 Pecase
  P22 P23 P24 P25 P26 P27。
  验证：双语料 sha256 不变；计数器无漂移；索引完整性 OK。

## 2026-08-30：POSTFIX-RETIRE-0001 W1 — 逐 pass 突变计数器（env 门控，零行为差）

路线图 W1 节（`/tmp/rudra-reports/w-postfix-2026-08-30.md` §5）：为 W0 后幸存的
全部 **33 个**后处理 pass 加突变计数器，作为 W2 零突变退役的判定依据。验收门禁：
curl/httpd E2E 输出与 master **sha256 逐字节一致**（`f6e35fcd…` / `5200602a…`），
`cargo test --lib` 17 失败全部为 funcdata 预存项。

- **新增 `PostfixStats` 诊断族**（全部 `// RUDRA-GLUE:`，Ghidra 无对应物——oracle
  `EmitNoMarkup`（prettyprint.hh:542-594）是无缓冲直写 emitter，发射路径以
  `flush`（prettyprint.cc:1194-1213）结束，无任何文本后处理）：
  - `RUDRA_POSTFIX_STATS` 环境变量设置时，`post_process_output_legacy` 每次调用
    向 stderr 输出一行 `[POSTFIX] pid=<pid> inv=<n> rpt=<0|1> fn=<name> lines=<n>
    P1=<d> … P27=<d>`（33 个 pass 的行级突变计数）；未设置时全部插桩点短路
    （不 clone、不比较、不打印），输出字节与未插桩版本完全一致。
  - 计数语义：等长输入逐行比较（改写型 pass 精确）；不等长输入先裁公共前后缀
    再计中间差异块（删除/插入型）。**零突变检测在两种度量下均精确**。
  - 熔合在首扫循环里的 P1/P1b/P2 无法取边界快照，在其三个改写点直接 `bump`
    （每次 = 删 1 行或改写 1 行）；其余 27 个 pass 在边界快照
    （`PostfixStats::snap`）→ 输出对比（`observe`/`observe_str`）。
  - `rpt=1` 标记双重执行（本次输入 == 上次调用的输出，DefaultHasher 指纹）；
    生产路径存在两类调用轮（curl 190 次调用中 84 次 rpt=1，httpd 102 中 33），
    W2 判定以 rpt=0（首轮）为准，rpt=1 计数作为幂等性信号。
- **双语料实证结果**（rpt=0 首轮）：**21/33 pass 双语料双轮全部零突变**
  （P1 P1b P2 P3 B1 P4 P5 P12 P13 P14 P15 P16 B3 P18 B4 Pwbfold Pecase P24
  P25 Pdl P26）——含整条 LAB_ goto 族（P16c 除外，curl 单函数 264 行突变）。
  P13（void 拆分,硬编码 libc 表）在双语料零突变,但按路线图仍须等
  PRINTC-VOIDCALL-0001 落地后退役。非零 pass 明细见 W1 报告
  （`/tmp/rudra-reports/w-w1-2026-08-30.md`）。

## 2026-08-30：POSTFIX-RETIRE-0001 W0 — 死代码清除（字节级零行为差）

路线图 `/tmp/rudra-reports/w-postfix-2026-08-30.md` W0 第一刀：删除全仓零引用的
死函数与 no-op scaffold，并改正伪造的 `// Ghidra: prettyprint.hh:547
EmitNoMarkup::<方法>` 注解（锁定 oracle 的 `EmitNoMarkup`（hh:547-594）只有
`Emit` 虚方法族，无任何 postProcess/文本 pass 方法）。验收门禁：curl/httpd E2E
输出与删除前 **sha256 逐字节一致**。

- 删除 `reconcile_pointer_arith()`（原 :255-320）：唯一调用点早在
  mark_varnode_used LOAD 检测修复后即被注释（原 :917），仅存自递归引用。
  第七 pass 区域的注释同步改为"已删除"记录。
- 删除 `recover_struct_fields_anon()`（原 :2105-2262，158 行）：2026-06-23
  匿名 struct 字段恢复实验的遗留物，实验当时即被判定需要 P-code 级类型传播
  （typedef 作用域非法、`->` 无 struct 布局不合法），全仓零调用点。
  其 `EmitNoMarkup::recoverStructFieldsAnon` 伪造注解随函数一并消失。
- 删除 struct-deref 三函数族（共 213 行）：`rewrite_struct_deref()`（原
  :3088-3145）与 `canonicalize_struct_deref()`（原 :3147-3258）是互逆变换对，
  pass 20+21 早已从管线移除（2026-07-04 续 6，净效果为零）；`try_convert_ptr_add()`
  （原 :3260-3305）仅被 canonicalize 调用。三者的
  `EmitNoMarkup::rewriteStructDeref/canonicalizeStructDeref/tryConvertPtrAdd`
  伪造注解随函数一并消失。
- 删除 pass 19 括号平衡 scaffold（原 :1785-1859，75 行）：自 2026-06-26 起
  其 `depth<0`/`else` 两臂均为逐行 verbatim 输出（读码证实恒等，naive 计数
  无法越过 char/string 字面量故从不改写）——事实 no-op。后续空行折叠
  （B4）改为直接消费 pass 18。
- **伪造 `// Ghidra:` 注解改正（机制 D 红旗清除，20 处）**：锁定 oracle 的
  `EmitNoMarkup`（prettyprint.hh:547-594）只有 `Emit` 虚方法族，以下注解
  引用了 oracle 根本不存在的方法，全部改标 `// RUDRA-GLUE:`（登记
  POSTFIX-RETIRE-0001 W0）：路线图点名的 16 处中，`rewriteStructDeref`/
  `canonicalizeStructDeref` 2 处随死函数删除，`postProcess`/
  `postProcessOutput`/`removeOrphanCaseLabels`/`removeIllegalLvalueAssignments`/
  `fixPointerArithmetic`/`tryFixOnePtrArith`/`removeOrphanBreaks`/
  `fixUnaryDerefDeclarations`/`negateSimpleCondition`/`flushFuncRemoveUnused`/
  `doIndent`/`isWordBoundary`/`countWordOccurrences`/`replaceWord` 14 处改标；
  另有 8 处同准则伪造注解一并处置（`recoverStructFieldsAnon`/
  `tryConvertPtrAdd` 随死函数删除；`debugCountWhile`/`debugGetOutputRef`/
  `getOutput`/`intoAny`/`asAnyMut` 5 处改标；`hasEnclosingLoopCtx` 是悬空
  残留行——真函数在 :3478 一带本就有 RUDRA-GLUE 注解——直接删除）。
  保留的 15 处 hh:547 注解（print/beginBlock/tagLine 等虚方法 + default/new
  →构造器 hh:550）均为 oracle 真实方法，不动。
- **`post_process_output_legacy` 误导标记清除**：其顶部
  "**DEAD CODE** — Do NOT call / 已被空操作替代 / `#[allow(dead_code)]`"
  注释是 2026-07-04 一次被放弃的退役尝试（改空操作→gcc 审计 23/24→5/24→
  回退）留下的脚手架，与事实矛盾——它是 `post_process_output` 的唯一实现
  并被其调用，是活链。改为如实状态注释 + RUDRA-GLUE 登记（oracle 发射
  路径零后处理的证据链：hh:547-594 无缓冲直写 emitter + printc.cc:2665
  docFunction 以 flush() 结束），`#[allow(dead_code)]` 一并移除（函数可达，
  属性本就无效）。退役仍按路线图 W1-WT 顺序推进。

## 2026-08-28：RPN variable metadata bridge

`Emit::tag_variable_with_metadata` 为 Ghidra
`tagVariable(name,highlight,vn,op)` 增加无损 Rust 边界：字符常量 Atom 的 highlight、
Varnode create-index 和 PcodeOp time 不再在 RPN→emitter 调用处被写死为 0。旧 emitter
可回退到文本/id API。`PRINTLANGUAGE-ATOM-METADATA-0001` 的 8 records / 678 bytes
双侧 stdout 已逐字节 `MATCH`（SHA-256
`d84d1ae86bad70fc570630ebbc8a65f172f97655d129a6b49b2faded09c9acbd`），覆盖两次
相同 vn/op identity 的 stage-1 hidden group 和 syntax control。该 fixture 在
metadata-aware Emit 边界结束；当前 `TokenSplit/EmitPrettyPrint` 仍会丢
highlight/vn/op，绑定 `PRETTY-0001`，完整 markup encoder 也未获全函数门禁。

## 2026-08-27：移除 `0x4f` 字符后处理 workaround（TRI2-CALLOUT-RESID-0002）

删除 `post_process_output_legacy` 第七趟中 `0x4f → 'O'` 的赋值替换。
该映射没有合法消费者：它对所有 `= 0x4f;` 赋值生效，而 Ghidra 的字符形由
`PrintC::pushConstant` 的 propagated read-facing 类型分派决定，不应由文本后处理
猜测。现在由 `src/printc.rs` 的 `TYPE_INT/TYPE_UINT + isCharPrint` 通道负责该决定。

验证记录：移除前 curl 输出有 3 个 `= '..';` 赋值（`config='&'`、
`myprogress='#'`、`progressbarinit='O'`），移除后为 2 个；仅
`progressbarinit` 受影响并收敛到 golden 的 `bar->width = 0x4f;`，其余两处与
golden 保持一致。

## 2026-08-26：`EmitPrettyPrint` Oppen 折行引擎 1:1 移植（PRINTC-LINEWRAP-0001）

Ghidra 反编译器的主输出走 `EmitPrettyPrint`（`printlanguage.cc:69`
`emit = new EmitPrettyPrint()`），即 Derek C. Oppen 令牌队列折行算法。
Rudra 此前只有 `EmitNoMarkup` 直写路径，长表达式永不折行（hugehelp
长字面量为单行，golden 为 `puts(\n      "..."\n      );` 三行）。

本提交补齐 emit 层行宽机制（prettyprint.cc:541-1243 / prettyprint.hh:609-1115）：

- `pub struct TokenSplit`（hh:609）——令牌/命令对象：`tagtype`（28 值
  `TagType`）+ `delimtype`（9 值 `PrintClass`）+ `tok`/`indentbump`/
  `numspaces`/`size`/`count`。每个 emitter 方法对应一个构造器
  （`begin_document`..`tag_line_indent`），`size` 为内容字符数或未提交
  组的负扫描偏移。
- `struct CircularQueue<T>`（hh:944）——环形缓冲，栈用法 `push/pop`、
  队列用法 `push/popbottom`，整型引用在 push/pop 后仍有效；
  `expand(amount)` 重分配并紧凑到引用 0（hh:1003-1027），
  `EmitPrettyPrint::expand`（cc:564-579）按
  `(ref + max - left) % max` 同步调整 scanqueue 引用。
- `pub struct EmitPrettyPrint`——scan/advanceleft/print/overflow 四函数
  心脏（cc:614-802）+ `checkstart/checkstring/checkend/checkbreak`（cc:806-856）
  + 全部 emitter 方法（cc:858-1192）。`open_paren` 自动开组（cc:1094-1103:
  `id = openGroup(); …; needbreak = true`），`close_paren` 关组；
  `flush`（cc:1194-1211）排空队列（未闭合组在 oracle 抛 LowlevelError，
  Rudra 记日志跳过——emit 层无错误通道的保守降级）；
  `set_max_line_size`（cc:1225-1235，20..=10000，`3*val` 队列容量）；
  `clear`（cc:1153-1166）。低层为 `EmitNoMarkup` 字节汇。
- `Emit` trait 变更：`open_paren(paren) -> i32` / `close_paren(paren, id)`
  （默认实现即打印括号、返回 0，cc:587-591）；`spaces(num, bump)`
  （cc:46-59 spacearray 折叠，默认实现打印 `num` 个空格；pretty printer
  里是 \e tokenbreak）；`start_comment/stop_comment/flush/set_comment_fill`
  空默认。
- 调用方（printc/printlanguage 的 RPN 路径）改用带 id 的
  open/close_paren 与 `spaces(spacing, bump)`（printlanguage.cc:146-179/
  338-369）；docFunction 尾部补 `tagLine→endFunction→flush`
  （printc.cc:2663-2665）；typedef 前言包进 `beginDocument..endDocument`
  （docAllGlobals 形态，printc.cc:2621-2629）；`PrintC::new` 设置
  comment fill `"   "`（setCommentDelimeter "/* " 宽度，printlanguage.cc:96-110）。
- 驱动（examples/curl_decompile.rs）换用 `EmitPrettyPrint`。

**验证**：hugehelp 函数体与 `tests/golden/ghidra_curl_1204.c` 逐字节一致
（`--func hugehelp` Skeleton identical）；全量差分 defects=0 /
numbering=0；总 skeleton 2824→2776（main -24、getparameter -26、
hugehelp -12；5 个函数 +14 行均为内容本已分叉的长表达式折行位置差）。
逐函数 oracle 行为差分状态仍按机制 B2 记 `UNTESTED`（分支/边界未全
覆盖），不得据此把模块升 L3；emit 层折行行为以 curl golden 为证据。

## 2026-08-27：死会话遗留两处收尾（PRINTC-LINEWRAP-0001 续）

- `EmitPrettyPrint::next_count`：C 的 `countbase++`（prettyprint.hh:685
  等 TokenSplit 构造器）是后置自增，表达式值为自增**前**的旧值；
  `AtomicI32::fetch_add(1)` 同样返回旧值——原实现 `fetch_add(1) + 1`
  把 id 整体偏移了 1。count 只用于 begin/end 配对（非 PRETTY_DEBUG
  构建不参与输出字节），修正为语义 1:1。
- `post_process` 移除 `RUDRA_DBG_NO_P3` 临时旁路（机制 D：`[DBG]`
  临时通道提交前必须删除）。
- 驱动（examples/curl_decompile.rs）STRCONST-SPANNONOVERLAP：字符串
  Data 严格非重叠注入（run+NUL 跨度内跳过 per-byte DAT、8 字节槽
  entry 裁剪到下一字符串起点），恢复 oracle Program DB 的
  findContainer 最小包含选择，使 ActionConstantPtr 字符串臂在字符串
  起点命中——回归 A（字面量退化为指针算术）的本 worktree 侧修复，
  供 hugehelp 折行形态 E2E 验证。

## 2026-08-26：`EmitNoMarkup` 空白折叠不进入字符串字面量（MAINDIFF-STRCONST-0001）

`get_output` 后处理的取消-清理段（cancel_patterns 之后的双空格折叠与
` )` 修剪）此前对整行盲做。反编译器的字符串常量合法包含多空格 run
（hugehelp 别名的 `\n   or specify` / 八空格缩进），盲折叠会改写字面量内容。
现折叠循环带引号状态机：`"`/`'` 开启的字面量区域逐字复制（反斜杠逃逸不翻转
引号态），折叠与修剪仅发生在字面量外。golden 中 hugehelp 三个
`puts("...")` 字面量（含连续空格与 `\n`）逐字节保持。

## 文档状态

- **状态**: 🔧 **L2（2026-08-12）**——`Emit::open_group/close_group` 已补齐，
  `PRINT-RPN-0001A` 对已覆盖 RPN case 的纯文本为 `MATCH`；但默认实现只保留
  plain-text 的不可见语义，尚未实现/观察 `TokenSplit`/Oppen scan queue、exact
  group ID、semantic object identity、spaces+bump 和 line-width break/indent，
  模块整体仍为 `UNTESTED/MISMATCH`。
- **对应源码**: 当前 `rudra/src/prettyprint.rs`

**源代码路径**: `src/prettyprint.rs`

## 模块说明 (Module Doc)

Pretty printing and token emission

Corresponds to Ghidra's `prettyprint.hh`

## 导出的公共 API (Public API)

### `pub enum BraceStyle` （2026-08-15 新增，PRINTC-FORMAT-0001）

对应 Ghidra `Emit::brace_style`（prettyprint.hh:124-129）：`SameLine = 0`
（`if/do/while/for/switch` 的 `{` 同行）、`NextLine = 1`（下一行）、
`SkipLine = 2`（空一行后，函数体默认样式）。

### `pub trait Emit`

Trait for emitting decompilation tokens

This provides a generic interface for "printing" decompiled code,
allowing for different output formats (plain text, XML, HTML with markup, etc.)

- `open_group() -> i32` / `close_group(id)` 对应 Ghidra
  `Emit::openGroup/closeGroup`。纯文本 emitter 的 group 不产生字符，默认 ID 为 0；
  它与会实际输出 `(`/`)` 的 `open_paren/close_paren` 是两套不同操作。
- `open_brace_indent(brace, style)` / `close_brace_indent(brace)` 对应
  `Emit::openBraceIndent`（prettyprint.cc:61-76）与
  `Emit::closeBraceIndent`（prettyprint.hh:481-483）。`EmitNoMarkup` 的
  覆写按 oracle 的无条件 `tagLine`（`\n` + indent，prettyprint.hh:557）
  语义发射：`SkipLine` 产生恰好两个换行（`)\n\n{`），`SameLine` 产生
  ` {`；close 为 stopIndent + 换行 + `}`。Rudra 的 `tag_line` 会吞掉重复
  换行，因此两个换行在覆写里直接写入以保证 oracle 字节格式。
  `bump_indent`/`drop_indent` 是 startIndent/stopIndent 的 indent 半边
  （indentincrement=2 空格/层）。
- 锁定 12.0.4 visible-text fixture：
  `tools/run_printlanguage_group_oracle.sh`。已覆盖 case 为 `MATCH`，exact
  PrettyPrint group queue/ID 仍归 `PRETTY-0001`，不得据此升级 L3。
- 锁定 12.0.4 纯格式 fixture（PRINTC-FORMAT-0001）：
  `tools/run_printc_format_oracle.sh`，六 case（函数头花括号 skip_line 布局、
  参数 `char *pattern`/`char **argv`/`int argc`/`...` join 间距、逗号无空格、
  2 空格缩进策略）双侧逐字节 `MATCH`。

### `pub struct EmitNoMarkup`

Simple emitter that produces plain text with no markup

### `pub fn new() -> Self`

创建并初始化一个不带任何标记的 `EmitNoMarkup` 纯文本发射器。

### `pub fn get_output(self) -> String`

获取发射器缓存的最终格式化 C 代码字符串，同时消费该发射器实例。
在该方法内部，发射器会对收集到的原始行序列进行**多达 15 趟的后处理 Pass** 以极大改善输出质量。包括：
- **死代码消除**：如删除 `return;`/`break;` 后的不可达代码。
- **孤立控制流清理**：如合并连续重复的 `goto`、移除空 `else` 代码块的空行、重写 `return void()` 表达式等。
- **双括号规范化 (Pass 15)**：在最后一趟后处理中，将函数调用多余的括号（如 `puts());`）规范化为 C 语言的标准形式 `puts();`。

### `pub fn debug_count_while(&self) -> (usize, usize)` （2026-06-28 新增，调试用）

返回 `(while_count, do_count)`——原始 output 中 "while" 和 "\ndo " 的出现次数。用于 `RUDRA_LOOP_DEBUG` 诊断跟踪循环渲染。标注 `allow(dead_code)`，无副作用。

### `pub fn debug_get_output_ref(&self) -> &str` （2026-06-28 新增，调试用）

借用原始 output 字符串供诊断检查。标注 `allow(dead_code)`。

### `fn reconcile_int_minus_pointer(line: &str) -> String` （2026-06-28）

post_process 第七 pass 调用。C 禁止 `int - pointer`。当行匹配 `<整数常量> - <指针前缀>Var` 时，把整数 cast 成指针类型使运算合法。**cast 类型根据前缀**：piVar→`(int *)`，pcVar→`(char *)`，psVar→`(struct _struct *)`，ppVar/pvVar→`(void *)`——确保 `ptr - ptr` 两边类型兼容。

**实现**：前向扫描（`find(" - ")`），i 只前进不回退。早期版本有回退 bug 导致死循环，已修复。

### `fn reconcile_pointer_arith(line: &str) -> String` （2026-06-28，**已删除**）

**已删除**（2026-08-30，POSTFIX-RETIRE-0001 W0）——mark_varnode_used 的 LOAD
结果检测让 LOAD 输出正确声明为 int/long（非指针）后，唯一调用点已被注释，
函数仅存自递归引用，属全仓零引用死代码。

### `fn reconcile_int_times_string(line: &str) -> String` （2026-06-28）

post_process 第七 pass 调用。C 禁止 `int * string-literal`。当行匹配 `X * "..."`（乘号后跟引号字符串）时，把字符串 cast 成 `(long)`。**只匹配引号字符串**，不匹配指针变量——避免破坏合法的 `ptr + N * element_size` 算术。触发于 copy propagation 把字符串地址错误内联到 MULT 操作数的情况。

### `*(_struct *) → *(long *)` 替换 （2026-06-28）

post_process 第七 pass。当行含 `*(_struct *)` 且是赋值语句时，替换为 `*(long *)`。修复 long 赋值给 _struct 解引用的类型不兼容。

### `pub struct NullEmit`

Emitter that discards all output (used for discovery pass)

### `pub fn new() -> Self`

创建一个静默发射器，所有的打印输入均会被丢弃。常用于 Discovery Pass (探测阶段) 以静默跑通反编译打印管线以搜集已使用的变量。

---

## 更新日志

### 2026-06-23：输出合法化与控制流规范化

- `get_output()` 现自动调用 `post_process()`，确保所有调用方（含 example）都得到规范化输出（此前 example 直接取原始 output，跳过了后处理）。
- 新增 `rewrite_struct_deref()`：将所有 `IDENT->field_N` 重写为 `*(long *)(IDENT + 0xN)`。原因：printc 多处 emit `ptr->field_N`，但我们不追踪具体 struct 布局，无法保证 `ptr` 指向匹配的 struct 类型。cast 形式无论 base 声明类型如何都合法。
- `try_convert_ptr_add()` 与 second pass 的 `*var + N` 模式同样改为 emit cast 形式。
- while-break 折叠 pass：`while(cond){stmt;break;}` → `if(cond) stmt`。
- 空 switch case 移除 pass：删除 `case N: { break; }` fallthrough 组。

### 2026-06-23（续）：一元解引用声明合法化

- 新增 `fix_unary_deref_declarations()`：扫描所有 `*IDENT` 一元解引用模式，把这些 IDENT 的声明从 scalar（long/int/byte）改成 `char *`。原因：printc 对 STORE/LOAD 发射 `*param_N = val`，若 param_N 被推断为 long/int 则非法。`char *` 既能解引用又能赋标量值。
- 参数签名同步重写：签名行里的 `long param_N` 若属于 derefed 集合，改为 `char * param_N`。
- 2026-09-28（LANE DECLFAM / DECLFAM-DEADSLOT-0001）：解引用收集器排除
  `*` 后随空白的形态（`next_is_space` 守卫）。printc 发射的解引用永远是
  紧贴形（`*pcVar9`/`(*x)`），而带空格的 `*` 是间隔二元运算符——典型如
  golden glob_set 的 `return iVar5 * sVar8;`（乘法）。旧行为把乘法操作数
  误收进 derefed 集合，将符号驱动的 `short sVar8;` 声明重写为
  `char *sVar8;`（golden 同函数保持 `short`）。

### 2026-06-23（续）：栈/局部变量声明兜底

- 新增 `backfill_missing_locals()` post-process pass：扫描每个函数 body 里使用但未声明的 `local_XX`/`lVar_XX`/`uVar_XX`/`iVar_XX` 等匈牙利前缀变量，按前缀推断类型（lVar/uVar→long, iVar/bVar/local_→int, piVar/pcVar→char*），在声明块末尾补声明。兜底覆盖 mark_variable_used 路径不完整导致的遗漏。



### 2026-06-23（续）：DCE 改进

- 空行不再重置 dead zone（它们不让后续死代码可达）。
- 同 indent 或更深的 `}` 保持 dead（它关闭 dead zone 内的块）。

### 2026-06-23（续）：orphan break/continue 移除

- 新增 `remove_orphan_breaks()` post-process pass：跟踪 brace 深度与 loop/switch 上下文栈，删除不在任何 loop/switch 内的 break/continue 语句。支持裸 `break;` 和内联 `if (cond) break;` 两种形式。内联形式移除 break 后若行变空则整行删除。

### 2026-06-23（续）：DAT_ 全局 backfill 恢复

- `backfill_missing_locals()` 重新加入 `DAT_` 前缀扫描。之前移除是因为可能把 extern 放函数中间，但现在的声明块检测逻辑能正确把 extern 放在声明块末尾。DAT_ 名声明为 `extern long DAT_xxxxx;`。**2026-08-25 改为跳过（MAIN-DATPOOL-0001）**：oracle printc.cc 零 `extern` 关键字、golden 零 extern 行，DAT_ 名不再注入任何声明，仅保留 use-site 裸引用。

### 2026-06-23（续）：orphan break context 继承改进

- `remove_orphan_breaks()` 的 context 栈改进：嵌套块（if/else/匿名）继承父块的 loop/switch context；函数签名行重置为 false；`} else {` 继承 parent。修复了 switch case 内嵌套 if 里的 break 被误删的问题。

### 2026-06-23（续）：orphan break 的 switch 范围追踪 + brace 双计修复

- 重写 `remove_orphan_breaks()`：用 brace 深度 + loop/switch 深度栈预扫描，标记每行是否在 loop/switch 体内。比行级 context 栈更可靠。
- 修复 `} else {` 的 brace 双计 bug：这类行既匹配 `endswith("{")` 又匹配 `starts_with("} else")`，导致 brace_depth 多 +1。现在 `endswith("{")` 排除以 `}` 开头的行。
- 函数签名行重置 brace_depth=1，防止跨函数累积。

### 2026-06-23（续）：backfill 扩展无下划线前缀 + struct

- `backfill_missing_locals()` 现在同时匹配带下划线（`bVar_592`）和无下划线（`bVar592`）两种匈牙利命名，以及 `struct3` 栈结构体名。类型推断：structN → int（占位），其余按原规则。

### 2026-06-23（续）：指针算术合法化

- 新增 `fix_pointer_arithmetic()` post-process pass：检测 `ptrA + ptrB` / `ptrA * ptrB`（两者都声明为指针类型），把右操作数 cast 成 `(long)`，使运算变为 pointer + integer。跳过赋值语句的 LHS。

### 2026-06-23（续）：非法 lvalue 赋值移除

- 新增 `remove_illegal_lvalue_assignments()` post-process pass：检测 LHS 含顶层二元运算符（`RSP + expr = val`）的非法赋值行并移除。这些来自 printc op_store 对复杂地址的错误渲染。

### 2026-06-23（续）：CaseDetectEmit + case_body_indices + dry-run 检测

- 新增 `CaseDetectEmit`（Emit 适配器），记录 emit 是否产生 `case`/`default:`/`tag_case_label`。
- `PrintC` 新增 `case_body_indices` 字段，在 doc_function 开始时从 BlockSwitch.cases/default + CASE_BODY flag 收集。
- 实现了 dry-run case-label 检测（临时替换 emit 为 CaseDetectEmit，emit if_body 检查）。
- 但 dry-run 只覆盖 emit_block_ops（不覆盖 emit_block_structured 的嵌套路径），漏掉部分 case label。
- if_no_exit 仍禁用。printc 的 CASE_BODY emit 保护已移除（破坏正常 BlockIf）。

### 2026-06-23（续）：orphan case label 移除（精确 switch depth 追踪）

- post-process 新增 `remove_orphan_case_labels()`：用 brace depth + switch body depth 栈精确追踪 switch 上下文，移除不在任何 switch 内的 case/default label。
- httpd main case label 问题解决！gcc 53/53。
- 但 test_bool_condition 又失败（goto 级联对非 switch 函数的影响）。

### 2026-06-23（续）：结构体字段恢复实验

- 实现了 recover_struct_fields：将 *(long *)(ptr + 0xN) 转换为 ptr->field_N。
- 恢复了 53 个字段访问（curl）。
- 但 -> 运算符要求左侧是 struct pointer 类型，而 Rudra 声明指针为 long/int。
- -> 在 long 类型上非法，gcc 从 53/53 降到 40/53。
- 禁用 recover_struct_fields —— 需要 struct 类型传播引擎才能正确使用 -> 运算符。
- Ghidra 能用 -> 是因为有类型库（FILE*, Configurable* 等）的 struct 定义。

### 2026-06-23（续）：struct 类型传播实验（-> 需要 DWARF 布局）

- 尝试了 struct 类型传播：将指针偏移访问的变量提升为 _struct * 并用 -> 访问字段。
- gcc 拒绝 ->field_N 即使使用 flexible array member（struct 需要已知成员定义）。
- 结论：-> 运算符需要类型库的 struct 布局定义。*(long *)(ptr + offset) 是正确的有效 C 表示。
- Ghidra 能用 -> 是因为有 DWARF/debug info 的 struct 定义。
- 禁用 struct field recovery，保持 *(long *)(ptr + offset) 格式。

### 2026-06-23（续）：struct 字段恢复 — 需要 P-code 级类型传播

- 尝试了匿名 struct typedef 注入（per-function post_process）。
- 问题：typedef 在函数体内（非法 C），-> 运算符需要 file-scope struct 定义。
- 根本结论：struct 字段恢复需要 P-code 级类型传播引擎（ActionTypePropagate），
 让 printc 在 emit 时知道变量是 struct pointer 类型。
 文本级 post-process 无法正确注入 struct 定义（作用域问题）。
- Ghidra 通过 DWARF 类型库 + P-code 类型传播实现。
- 保持 *(long *)(ptr + offset) 格式（有效 C）。

### 2026-06-23（续）：ActionTypePropagate 实验结论

- 实现了 ActionTypePropagate（P-code 级 struct pointer 类型传播）。
- ActionTypePropagate 标记所有 LOAD/STORE 地址中的 base varnode 为 _struct *。
- 问题：标记过于激进——所有参与指针算术的变量都被标记为 _struct *，
 导致 type conflict（_struct * 赋值给 long，gcc 拒绝）。
- 需要保守启发式：只有被 >=2 个不同小偏移（<256B）访问的变量才标记为 struct pointer。
- 结构体字段恢复（->field_N）需要：
 1. ActionTypePropagate 只标记真正的 struct pointer（保守启发式）
 2. printc 根据标记的 varnode 生成 per-function _struct typedef with fields
 3. printc LOAD/STORE emit 时检测 struct pointer varnode → 输出 ->field_N
- 当前所有 struct 相关实验已回退，保持 53/53。

### 2026-06-23（续）：struct_recover.py — 保守结构体字段恢复

- 新增 `tools/struct_recover.py`：后处理工具，从 *(long *)(var + 0xN) 模式恢复 struct 字段访问。
- 保守启发式：只转换被 ≥2 个不同 8 字节对齐小偏移（<256B）访问的变量。
- 生成 per-file _struct typedef with matching field members，写入 .struct.h 供 audit 使用。
- 重写变量声明为 _struct *，重写 *(long *)(var + 0xN) 为 var->field_N。
- audit_syntax.py 更新：读取 .struct.h 作为 stub，提供 _struct typedef for per-function compilation。
- 效果：curl 4 个、httpd 15 个 ->field_N 字段访问恢复。gcc 53/53。

### 2026-06-23（续）：rename_vars.py — DWARF 局部变量名恢复

- 新增 `tools/rename_vars.py`：从 DWARF debug_info 提取函数局部变量名（DW_TAG_variable + DW_OP_fbreg），映射到 Rudra 的 local_XX 栈变量。
- 效果：curl 12 个变量名恢复（errorbuffer, progressbar, outs, heads, buffer, size, nmemb, stream 等），httpd 同样有恢复。
- 与 struct_recover.py 串联使用：struct_recover → rename_vars → audit_syntax。

### 2026-06-26：pass19 不再移除大括号（naive 计数误删 case '}' 中的 }）

- pass19（Nineteenth pass: remove unmatched extra closing braces）原用 naive 大括号计数
 检测函数闭合，但当函数含 `case '}'` 等 char/string 字面量中的 `}` 时误判 depth<0，
 移除函数闭合 `}`，导致函数边界损坏（ap_getparents）。
- 改为 emit as-is（不移除大括号）。naive 计数不可靠，真正的平衡应由 emit 的
 begin_block/end_block 配对保证。

### 2026-06-26（续）：post_process pass10 不移除 while/do/for/switch 结构

- pass10（remove dead code after return）现在保留 while/do/for/switch 控制流结构，
 即使它们出现在 return 之后。这些是可达控制流，不是死代码。
- 之前 WhileDo 循环在 unreachable-loop 中 emit（return 之后）被 pass10 移除。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-07-04：移除 post_process_output 的 27+ 趟文本后处理
- `post_process_output` 从 1450 行的 27 趟文本后处理改为**忠实空操作**（`input.to_string()`），对齐 Ghidra `EmitMarkup`（prettyprint.cc）的零后处理设计。
- 全部 27 趟 pass（goto→break/return、goto→loop、变量内联、死代码移除、指针算术修正、struct deref 重写等）违反铁律 5.5（在 print 层做 Action 阶段的事），已移除。
- 旧代码保留为 `post_process_output_legacy`（标记 `#[allow(dead_code)]`），供参考。
- **验证**：移除后 curl 仍 24/24 反编译、23/24 gcc 审计——无回归。说明这些 pass 是净负债（处理的瑕疵要么不存在，要么重复）。

### 2026-07-04（续 2）：恢复 post_process_output（emit 层不完整的必要补偿）
- 之前将 post_process_output 改为空操作（input.to_string()），但**重新生成输出**后发现 gcc 审计从 23/24 降到 5/24——之前的 23/24 基于旧缓存。
- 恢复 post_process_output 调用 post_process_output_legacy（27 趟文本后处理）。
- 27 趟 pass 虽然违反铁律 5.5（在 print 层做 Action 的事），但在 Rudra 的 Action/emit 层完整前是必要补偿。
- **每个 pass 对应一个 Ghidra Action 机制**（见 ALIGNMENT_ROADMAP 的 post_process 缺口表）——待对应 Action 移植后逐个移除。
- 同时确认：之前的 printc BRANCH 无条件跳过 + None 守卫修复确实生效——`goto ;` 从 1 降到 **0**。

### 2026-07-04（续 5）：指针运算 + 重复标签修复 → gcc 24/24
- **指针运算 LHS 扫描**：`try_fix_one_ptr_arith` 从只扫描 RHS 改为扫描整行（LHS cast 表达式如 `*(long *)(ptrA + ptrB)` 中的 `ptr + ptr` 也被修复）。
- **重复标签移除**：新增 `remove_duplicate_labels` pass，移除 splice 残留导致的重复 `LAB_` 定义（保留首次出现）。
- 效果：gcc 审计从 23/24 提升到 **24/24**——所有函数通过 gcc 语法检查！

### 2026-07-04（续 6）：移除 post_process pass 20+21（net-zero 互为反作用）
- `canonicalize_struct_deref`（pass 20：`*(ptr+N)` → `ptr->field_N`）+ `rewrite_struct_deref`（pass 21：`ptr->field_N` → `*(long*)(ptr+N)`）已移除。
- 这两个 pass 互为反作用，净效果为零。emit 层现在直接产出 `*(long*)(ptr+N)`（不产生 `->field_N`），所以两个 pass 都是无用的文本变换。
- 移除后 post_process 从 27 趟降到 25 趟。gcc 24/24 不变。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-15：PRINTC-FORMAT-0001 — 纯格式层对齐 oracle（skip_line 花括号 / 指针 join / 逗号间距）

- 新增 `BraceStyle` 枚举与 `Emit::open_brace_indent`/`close_brace_indent`
  （prettyprint.cc:61-76、prettyprint.hh:481-483 的 1:1 移植）；
  `EmitNoMarkup` 覆写按 oracle 的无条件 tagLine 语义发射。
- post_process 第八趟格式修正：不再凭空在声明块后插入空行——保留发射器
  已产出的**缩进保留分隔行**（emitLocalVarDecls 尾 tagLine 的忠实渲染，
  printc.cc:2277-2278），无声明则无分隔行；旧版把每个无声明函数体 `{` 后
  插一个空行是纯格式 bug。
- post_process 各函数签名检测（pass 11/17/18/19、remove_orphan_breaks、
  backfill_missing_locals）统一经 `signature_opens_function_body` 识别
  oracle 的两行式函数头（`sig` + 独立 `{` 行，printc.cc:1590/2655），
  skip_line 布局下 `{` 行不重复计入 brace depth；backfill 的声明收集跳过
  独立 `{` 行（否则 declared 集为空导致全部变量重复声明——numbering
  126→6 的根因）。
- `fix_unary_deref_declarations`/`recover_struct_fields_anon`/backfill 的
  指针声明模板从 `char * name` 改为 oracle join `char *name`
  （printc.cc:73-77 ptr_expr spacing=0）。
- 锁定 fixture `tests/oracle/printc_format_1204`（cover_rebuild 模式，
  pinned base=a51e0c5）：六 case 双侧逐字节 MATCH。

### 2026-08-16：声明识别白名单扩展（TYPE-WIRING 配套）

`flush_func_remove_unused` 的声明匹配从 `type uVarN;` 扩展到指针形
（`char *uVarN;` / `void *uVarN;` / `undefinedN *uVarN;` 三 token 形），
变量名取尾部 token 去前导 `*`——与 printc 的 ptr_expr join
（printc.cc:73-77）两种拼写一致。避免符号驱动声明落地后指针形被误判
missing 而合成重复 `int uVarN;`（numbering 残差机制见
PRINTC-LEGACY-DECL-DUP-0001）。

### 2026-08-16：PRINTC-LEGACY-DECL-DUP-0001 — 符号驱动函数旁路合成声明 pass，消 20 处重复

前次的"三 token 指针形"白名单扩展**未生效**：printc 的 ptr_expr join
（printc.cc:73-77 spacing=0）产出的是 2-token 形 `char *uVarN;`
（`split_whitespace` → `["char","*uVarN"]`），三 token 分支
（`["char","*","uVarN"]`）从不命中，`char *uVar20;` 仍被判 missing →
`int uVar20;` 注入 → `fix_unary_deref_declarations` 重写为
`char *uVar20;` → 与符号声明重复（8 函数 20 处 `declared twice`）；无任何
uVar 声明被收集时 `last_decl_idx=0` 使注入落在签名与 `{` 之间（K&R
old-style，gcc 11 错）。

**修法（oracle 判断）**：Ghidra 打印期零声明合成/删除——
printc.cc:2656 `docFunction` 的全部函数局部声明来自
`emitLocalVarDecls`（printc.cc:2260，Action 期 Symbol），`EmitNoMarkup`
（prettyprint.hh:547）无任何 post-process。故符号驱动函数不再接受任何
**合成/改写声明**的文本 pass，而非继续扩白名单（per-name 过滤 hack
掩盖缺符号函数仍需 backfill 的事实，被 root 指令禁止）。实验数据决定了
保留边界：三 pass 全旁路时 gcc FAIL 24→25（未链接符号引用如实暴露为
undeclared，SetHTTPrequest 新增 FAIL）；旁路两个合成 pass、保留 backfill
（其 declared 收集本就正确处理两种指针拼写，只补真缺名）时 FAIL 24→19
且 numbering 同为 0——后者使缺符号函数（符号块外的 uVar_<offset> 引用，
PRINTC-UNLINKED-REF-0001 域）保持可编译，是任务要求的 backfill 保留语义。

- 新增 `has_symbol_driven_decls()`（RUDRA-GLUE）：保守判据 = 函数声明块
  非空且至少一行声明呈现 ①类型 token 以 `undefined` 开头
  （undefined1/2/4/8 核心类型拼写，legacy pass 只合成
  int/long/`char *`/float/double）或 ②名字 token 以 `in_` 开头
  （in_RAX/in_ram_*/in_register_* 寄存器/内存符号名）。两种拼写只能由
  `emit_local_var_decls` 产出。
- 新增 `symbol_driven_function_line_mask()`（RUDRA-GLUE）：整文本按
  `signature_opens_function_body` 分段（前缀集含 `undefinedN` 返回型），
  为 `fix_unary_deref_declarations` 的行级重写提供函数归属掩码。
  分段边界修正（MAIN-ARGC-PROTO）：skip_line 布局下签名行自身无花括号
  （depth=0），且 `open_brace_indent` SkipLine 在签名与体 `{` 之间产生一个
  **空行**——原深度循环在空行上立即 `depth<=0` break，"函数块"退化为
  [签名,空行] 两行，`has_symbol_driven_decls` 看不到任何声明，main 等
  DWARF 锁参函数不被掩码，`fix_unary_deref_declarations` 遂把签名中锁定的
  `int argc` 重写为 `char *argc`（body 中存在 `*argc` 解引用）。修正：深度
  走查前先向前推进到 `signature_opens_function_body` 前瞻已定位的 `{`
  （途中只允许空行；其他非空行 = 前瞻契约破坏，回退旧行为），随后从
  depth=1 起算跨越真实函数体。A/B（124 函数全量）字节级 delta 共 8 处且
  全部向 oracle 收敛：`int main(char *argc` → `int main(int argc`
  （=golden）、`glob_set(char *pattern,char *pos` → `(char *pattern,int pos`
  （=golden）、match_url `char *param_1`→`long param_1`、5 处
  `char *unique0x…`→`long unique0x…`（回退到未命名位置 fallback 的
  long 默认）；defects 0→0、numbering 1→1（match_url per-prefix，基线
  同值预存）。
- 两处旁路：`flush_func_remove_unused` 对符号驱动函数整块直通（不删
  unused、不注入 missing——Ghidra 无条件发射所有符号声明，
  printc.cc:2260；该 pass 的 type_ok 表识别不了 2-token join 形
  `char *uVarN;`，正是重复注入与 K&R 位置的源头）；
  `fix_unary_deref_declarations` 跳过符号驱动函数的行（不在符号标量
  声明上重写 `char *`，oracle 按符号 Datatype 逐字打印，
  printc.cc:2503-2506）。
- `backfill_missing_locals` **保留对所有函数运行**：其 declared 收集
  正确处理两种指针拼写，在两个重复源被旁路后只会注入符号块中**真缺**
  的名字（未链接符号 body 引用，PRINTC-UNLINKED-REF-0001 域），使这些
  函数保持可编译。验收（12.0.4 golden）：numbering **20→0**、
  defects 0→0、gcc 审计 FAIL **24→19**（old-style 7 错→0、redeclaration
  →0；FUN_00102020/SetHTTPrequest_part_0/_init/deregister_tm_clones/
  register_tm_clones 恢复 OK，零新增 FAIL）；skeleton 4368→4403（+35：
  backfill 注入组保留所致，重复声明行已消——对照实验：三 pass 全旁路
  时 skeleton 4052 但 gcc FAIL 25，未链接引用如实暴露为 undeclared）。

### 2026-08-17：WARN-EMIT2 R2 — backfill 签名启发式误匹配控制流行（重复声明根因）

`backfill_missing_locals` 的函数签名判定 `sig_shape` 含
`trimmed.contains(" *")` 臂（本意覆盖 `char *foo(...)` 这类前缀表外签名）。
该臂同时命中**带 `/* N */` 十六进制注解的控制流开行**：例如
`if ((bool)(piVar1 <= 0x1000 /* 4096 */)) {` ——含 `(`、含 `" *"`
（` /* 4096 */` 里的 ` */`）、以 `{` 结尾，三条件全真。pass 随即把 if 体
当作嵌套函数：declared 收集只看块内（函数顶声明不可见）→ 块内全部
匈牙利前缀名被判 missing → 五条声明**整组注入 if 体内**，与函数顶那组
逐字重复（glob_url 的 `piVar1`/`uVar0`/`uVar20`/`uVar_1000004a`/
`uVar_9100`，numbering 0→3 的直接来源；隔离复现：删干净双批后单次
`post_process_output` 即再生两批）。

修复：`sig_shape` 前置 `control_flow_opener` 排除
（`if (/while (/for (/switch (/do {/else/case /default:` 各带无空格变体），
只有真函数签名（首 token 为类型）能进入注入路径。验收：glob_url 单批注入
（保留 PRINTC-UNLINKED-REF-0001 兜底语义）；锁定 12.0.4 golden 差分
numbering 3→**0**、defects 0 不变、Matched 123 不降；11.3.2 回归 golden
同 0/0。诊断期临时插桩（RUDRA_DUMP_PRE_POSTPROCESS 等五处）已全部移除。

### 2026-08-25：PRINTC-SWITCH-EMIT-0001 配套 — switch 语句前缀谓词

`is_switch_stmt_prefix`（RUDRA-GLUE）：oracle 的 opBranchind
（printc.cc:586-587）发射无空格的 `switch(`（golden `switch((int)x…)`
佐证），而 legacy 文本后处理的 5 处前缀检查只认 `switch `/`switch (`
形态——printc 对齐该字节后，`remove_orphan_case_labels` 会把
`switch(...)` 的全部 case 标签当孤儿剥掉。谓词统一接受两种前缀；
`switch` 是 C 关键字，`switch(` 不可能是标识符调用，词法安全。改动点：
remove_orphan_case_labels（2052）、tenth-pass 死区豁免（1050）、
pass17 循环上下文（1447）、brace_depth 循环头判定（2357）、
scan_up_for_loop_header（3131）；2491 原本就双形态。

### 2026-08-25（续）：A69 配套 — backfill 前缀表识别 oracle 未命名位置兜底 token

A69（`a9351d26`，PRINTC-UNLINKED-REF-FAMILY slice A）把 print 侧三条兜底
命名阶梯合并为唯一 oracle 形式 `<spacename><printRaw>`
（printc.cc:1938-1945 `PrintC::pushUnnamedLocation` + space.cc:206-222
`AddrSpace::printRaw`：`"0x"` + 小写 hex，`setw(2*sz)` 零填充最小宽度）。
`uVar_`/`local_`/`param_stack_`/`vn_` 全族消灭后，body 里换出的
`unique0x…`/`register0x…`/`stack0x…`/`ram0x…` token 不再被
`backfill_missing_locals` 的前缀表（原 2582-2586）与类型推断识别：
未链接引用不注入声明（match_url 的 `unique0x00023b00` 等保持 undeclared），
且 hex 尾部若走十进制续读臂会在首个 a-f 数字处截断 token。

同步改动（src/prettyprint.rs）：

- 前缀表加入 `unique0x`/`register0x`/`stack0x`/`ram0x` 四前缀
  （const/join/iop/overlay 空间的 token 形态按 A69 记录不可达——const 走
  pushConstant，join/iop 在 print 前被 split/unify/注解吸收）。
- 续读扫描新增第三臂：前缀以 `0x` 结尾的走 `is_ascii_hexdigit`
  （printRaw 的 `hex` 流操纵符，space.cc:216），不再落入十进制臂。
- 类型推断为四形式加显式 `long` 臂（与被替换的 uVar 族缺省一致；此前
  落入兜底 else 同为 long，显式化便于 grep 与防未来缺省漂移）。
- 新增 `#[cfg(test)] mod tests`（4 例：四空间形式注入、hex 尾不截断、
  已声明不重注、legacy 前缀不回归），`cargo test --lib prettyprint::`
  4 passed。

已知边界（同 legacy uVar 拼写，非本片回归）：`*unique0x…`/`*register0x…`
一元解引用出现在 symbol-driven 函数时，注入的 `long` 声明不解引用
（`fix_unary_deref_declarations` 在 pass 22 先于 backfill 运行且对
symbol-driven 函数旁路，pre-A69 `*uVara0 = 0` 同类）；`ram0x` 名的
printc extern 路径（printc.rs used_varnode_types Ram/Const 臂）已于
2026-08-25 随 MAIN-DATPOOL-0001 移除，backfill 的局部 `long` 遮蔽
注入行为保持不变（C 合法，curl 语料 ram0x 出现为 0 行）。
symbol-driven 函数旁路，pre-A69 `*uVara0 = 0` 同类）；`ram0x` 名若已被
printc extern 路径（printc.rs used_varnode_types Ram/Const 臂）声明为
file-scope `extern long`，backfill 仍会注入局部 `long` 遮蔽（C 合法，
curl 语料 ram0x 出现为 0 行）。

### 2026-08-25（续2）：FLAT-CBRANCH 配套 — Pattern 5 尾调用重写排除 code_ 标签

`post_process_output_legacy` 的 Pattern 5（"goto func;" → "return func();"
尾调用重写）此前只检查"标识符形 + 小写首字母"。FLAT-CBRANCH 补全后
printc 发射 flat 尾部 `goto code_r0x...;`（printc.rs 对 printc.cc:2723-2741
的移植），`code_r0x000026A5` 恰好全 alphanumeric 且小写开头——16 处
flat goto 被误重写为 `return code_r0x000026A5();`，gcc 报"将标签隐式
声明为函数"。

修复：Pattern 5 谓词排除 `code_` / `joined_` / `dup_` 前缀——三者是
`PrintC::emitLabel`（printc.cc:3164-3193）的标签构造前缀
（code_ 常规 / joined_ 拼接块 / dup_ 复制块），goto 到它们是控制流
转移，不是尾调用。行为对 libc 尾调用路径（`puts` 等）无影响。

验收：curl E2E `return code_r0x` 假象 16 → 0；audit_syntax 53 → 55 OK
（71 → 69 FAIL，清零 2 处"标号使用前未定义"；其余失败为预存——
progressbarinit/hugehelp 等函数的提取体在两次输出中逐字节相同）。

### 2026-08-25（续3）：NUMDECL-DOUBLE-V — backfill 扫描器左词边界

`backfill_missing_locals()` 的标识符扫描器此前无左词边界检查：前缀表
不含 `plVar`/`pbVar` 等指针前缀，`plVar64` 在内部 `l` 位置匹配 `lVar`
前缀，制造幻影 "used local" `lVar64`，随后注入 `long lVar64;` 与符号
驱动声明 `long *plVar64;` 并存——同名异类型双声明（NUMDECL-DOUBLE-V
的 SUB-B 形态，curl 语料 18 处幻影/8 函数）。

修复：前缀匹配要求 p==0 或前一字节不是 `[A-Za-z0-9_]`（C 标识符字符
集）。C 标识符为 `[A-Za-z_][A-Za-z0-9_]*`，长 token 内部的前缀命中
不是短名的使用。同时修正函数注解：`Ghidra: prettyprint.hh:547
EmitNoMarkup::backfillMissingLocals` 为误引（锁定 oracle 的
prettyprint.hh:547 是 EmitNoMarkup 类声明，oracle 无任何 backfill
文本 pass），改为 `RUDRA-GLUE` 并记录保留理由（PRINTC-UNLINKED-REF-0001
未链接引用域的可编译性兜底，该域关闭时退役）。

验收：curl E2E 幻影声明 18→0；真未链接引用（glob_set piVar1、
register0x/unique0x token）注入保持；defects=0/numbering=0 保持。

### 2026-08-26：GOTO-LABEL — `code_r0x...:` 标号的死区保留

`post_process` 死代码消除中"被引用标号行"的判定从 `LAB_` 前缀扩展到
`code_` 前缀（PrintC::emitLabel 产出的 `code_r0x...:` 与 LAB_ 同为 goto
目标；跳入死区是合法 C，被引用的 code_ 标号必须存活，否则所有指向它的
goto 成为未定义标号 gcc 错误——httpd ap_update_vhost_given_ip /
ap_strchr 观察）。判据不变：整行 `标识符:` 且无空格，且全文存在
`goto <标识符>;` 引用。

## 2026-08-29：WARN-EMIT2 R3 + DUPDECL-uVar 边界 — glob_range 双重声明修复

两处 legacy GLUE 文本 pass 缺陷（oracle prettyprint 无对应物，见各 pass
头部注释的退役计划）：

1. **`backfill_missing_locals` 签名误判（WARN-EMIT2 R3）**：多行 if 条件的
   续行（如 `&& \n (SEXT14(...) < 0x1a)) {`）以 `(` 开头却经
   `contains(" *")`（解引用 `*(char *)` 文本）命中 `sig_shape`，被当成函数
   签名后其"声明块"walk 只覆盖片段本体，块内 auto 前缀名全判 missing，
   在 if 块内部重复注入 `int iVar1; int iVar3;`（glob_range
   numbering=1 的直接来源）。C 函数签名永不以 `(` 开头，新增
   `cond_continuation` 门禁。
2. **uVar 扫描缺左词界（DUPDECL-uVar）**：`ppuVar4` 内部子串 `uVar4` 被判
   为未声明并在签名与 `{` 之间注入游离 `int uVar4;`。补齐与
   NUMDECL-DOUBLE-V6 左边界一致的 identifier 字节检查。

验收：curl E2E numbering 1→0，glob_range diff 93→89，全量 skeleton
2134→2118 零回归。varmap 侧共享计数器不变式另由双侧 fixture
`varmap_dupdecl_1204`（MATCH）钉住。

### 2026-08-30：MAIN-RC3-STRUCTURED-EMIT-0001 — 紧凑 `while(` 头的四处后处理承认 + ` )` 修剪豁免

oracle 的 overflow whiledo 头是紧凑 `while( true )`(printc.cc:3023-3028:
tagOp(KEYWORD_WHILE)+openParen 之间无 spaces(1),`true` 两侧各 spaces(1))。
printc 侧已按该字节序列发射(显式空格 token);遗留文本后处理层需同步承认:

- **` )` 修剪豁免**(whitespace-normalization pass):该 pass 无条件折叠
  `"  "→" "` 并修剪 `" )"→")"` —— 会摧毁 `while( true )` 的尾空格
  (Ghidra 输出中唯一合法的 ` )` 形态)。现对 `while(` 开头的行整段豁免
  (`while` 是关键字,只有该形态以 `while(` 开头,词安全论证同
  is_switch_stmt_prefix)。
- **四处循环上下文检测补紧凑形**:`has_enclosing_loop_ctx`(:3410 一带)、
  dead-zone 结构行(:1198 一带)、pass17 loop-ctx(:1601 一带)、
  is_loop_hdr(:2531 一带)原先只认 `while (`;紧凑形下
  `if (cond) break;` 被当作无循环上下文的孤儿 break 剥除(E2E main 等
  3 处 if-break 消失)。四处均加 `starts_with("while(")`。
- while→if 折叠扫描(:1852 一带)同样补紧凑形(检测前提,路径本身未触发)。

回归测试 `pretty_print_overflow_whiledo_header_spaces`:按 oracle 调用序列
(tag_op/open_paren/spaces(1)/print("true")/spaces(1)/close_paren)发射,
断言最终输出同时含 `while( true ) {` 与 `if (c) break;`(两层都锁)。
E2E:curl `while( true )` ×3 与 golden 逐字节一致,3 处 if-break 保持,
3104→3162(翻转提交之后)/0/1 不变;httpd 与基线逐字节相同(2178/4/0)。

### 2026-08-30：PRINTC-STRUCTEMIT-MAIN-IVAR4-DUP-0001 配套 — PendPrint 槽 + backfill 签名 `;` 门 + while-if 折叠前缀

**PendPrint 槽（Emit trait 4 方法）**：`set_pending_brace`/`cancel_pending_print`/
`has_pending_print_id`/`pending_brace_fired_id`。oracle 的 PendPrint 槽是 **Emit 基类**状态
（prettyprint.hh:102/446-457），`emitPending` 触发只在 EmitPrettyPrint/EmitMarkup::tagLine
（prettyprint.cc:920/930/129/136）；EmitNoMarkup::tagLine（hh:557）不触发，故其路径恒为
"已安装未触发"→ printc.cc:2900-2902 cancel+spaces(1) 合并 else-if。Rudra 两侧均按此实现：
EmitNoMarkup 只存槽不触发；EmitPrettyPrint 在 tag_line push 前调用私有 `emit_pending()`
（`open_brace_indent("{", style)`，PendingBrace::callback printc.cc:2872-2876）。

### 2026-09-26：SQATTR-PENDINGBRACE-IDENTITY-0001 — PendPrint 槽身份化（BraceId）

**根因**（本 lane PFLUSH 仪器复钉，与 SQATTR 归因独立收敛）：oracle 的 `PendingBrace` 是
**每次 `emitBlockIf` 调用一枚栈对象**（printc.cc:2882，printc.hh:347-361，`indentId` 起始
-1、callback 置 >=0），装/查/关全走**指针身份**——`hasPendingPrint` 比较 `pendPrint == pend`
（prettyprint.hh:457），`cc:2946-2948` 只关**自己那枚**已触发 brace。Rudra 旧实现把
`pending_brace_fired` 做成 **emitter 级全局粘性布尔**（set 时清零、fire 时置位、无人复
位）：嵌套 else-if 子帧触发后，外层帧的 `installed && fired()` 读到子帧的残火 → 对未开
过 brace 的帧多发一次 `close_brace_indent` → 函数级 startIndent/stopIndent 计数 21/22 失
衡 → 尾部多余 `}` 弹掉 func_b 缩进级 → `print_token` 相对断行臂在空 indentstack 上
`unwrap()` panic（prettyprint.rs:3946 家族；sq 2 索引 + sqlite3 27 索引 3/3 轮确定性复现，
全部有 oracle golden=同输入跑通）。另证：printc.rs 文本捕获惯用法（temp NoMarkup 换
`self.emit`，如 :4536）会把 fire/cancel 拆到不同 emitter 对象上，全局布尔进一步失真——
身份化后每枚 emitter 的 id 空间自洽，该裂缝自然闭合。

**修法（1:1 身份模型）**：`pub type BraceId = u64` 顶替栈对象地址。`set_pending_brace` 铸
新 id 并入槽（`(BraceId, BraceStyle)`，oracle `pendPrint = pend`）；`has_pending_print_id`
= 槽内 id 相等（hh:457 指针相等）；EmitPrettyPrint 另置 `fired_braces: Vec<(BraceId,
bool)>` = 每 install 一行的触发记忆（= 栈对象 `indentId` 的 Rust 化身：ctor 行 push
`(id,false)`，`emit_pending` 清槽**先于** callback（hh:1129-1137 顺序）后翻位）；
`pending_brace_fired_id` 只答本 id（cc:2946 `getIndentId()>=0`）。`clear()`（cc:1153 无此
状态——oracle 状态在帧栈对象里，不可跨函数存活）重置槽+记忆+计数器。EmitNoMarkup 同槽
结构但无触发（hh:557），`pending_brace_fired_id` 恒 false=trait 默认。printc
`emit_structured_if` 四处改门：install 持帧内 `Option<BraceId>`、cc:2900 合并门按 id 查
槽、**goto 臂删掉 oracle 没有的 cancel**（cc:2914-2917 无此项——cc:2900-2905 已保证本帧
槽必先解决）、cc:2946 尾关按 id 查触发。

**验收**（差分门禁机制 B 全过，A/B 亲测=CARGO_TARGET_DIR 双 target 前后二进制对拍）：sq
609/620 rc=0 + vs golden defects=0/numbering=0（残差仅 `unaff_100000f8` 3 行=GENSMOKE-S4
既有族）；sqlite3 27/27 panic 索引全清 + 逐函数 defects=0/numbering=0（骨架差全部归入
CAST/UNAFF/OPNAME 既有登记族）；**五面 A/B 字节恒等**——canon curl 124/124 267/0/0、
canon httpd 34/34 285/0/0、镜面 curl 78/275、httpd 208/460、vsh 15/55（修复前后同数同
字节=非 panic 语料上身份门与旧全局旗标行为等价，唯一可观测变化=29 个 panic 函数转正；
旧记录 369/211/301 系 master 漂移非本修）；bank 391/391。

**backfill_missing_locals 签名 `;` 门（MAIN-IVAR4-DUP 第 2 层）**：MAIN-RC3 翻门暴露的
`stmt; if (...) {` 同行形态（`(_IO_FILE *)` 命中 `contains(" *")` 臂）曾被误判为函数签名，
decl 走查为空导致伪 body 内的 iVar4 被重复注入 `  int iVar4;`（numbering+1）。C 函数签名
行不含 `;`，`sig_shape` 增加 `!trimmed.contains(';')` 门。

**while→if 折叠前缀（PRINTC-WHILEIF-FOLD-PREFIX-0001）**：折叠 opener 识别同时接受
`while (` 与紧凑 `while(`（printc.cc:3023-3028），但条件切片硬编码 `"while ".len()`
前缀——紧凑形态的前缀吞掉开括号，配对 `)` 残留产出畸形 `if (true ))`。修复为按实际
匹配的前缀切片；紧凑形态（剩余无 `(` 前导）补剥尾部 `)`。语料 3 处紧凑 `while( true )`
均无 body 缩进裸 `break;`，该路径当前未触发；修复为潜伏缺陷封堵。

### 2026-08-30（续）：PRINTC-WHILEIF-FOLD-PREFIX-0001 回归测试 + fixture 重钉

`pretty_print_while_break_fold_compact_prefix`（prettyprint.rs tests）锁定两种头部
拼写的折叠条件切片：紧凑 `while( true )` 折叠为 `if (true) x = 1;`（无悬垂括号），
空格 `while (c)` 形态不变。双侧 fixture `printc_pending_brace_emit_1204` 的
`comparand_sha256.rudra_prettyprint` 随测试加入重钉（runner 重验 overall=MATCH）。

## 2026-09-22 追加（PRINTC-SWITCH-EMIT-0001 — P17 孤立 `} while` 判定的深度配对）

`emit_structured_infloop` body 改结构化递归发射（printc.rs，cc:3109 虚分派）后，
do-while 体恢复为完整结构（数百行的 switch 嵌套）。P17 的孤立 `} while (...)`
清除判定原是 30 行回看窗口找 `do {`——长体 do 的开括号在窗口外，trailer 被误删,
函数残留未闭合 `{`（curl gcc 审计提取 107→47 崩塌；getparameter/glob_word +
httpd main/ap_fini_vhost_config 受害）。

修复:窗口改为**深度感知反向配对**——从 trailer 行反向累计花括号增量（体内部
净 0）,首次达到 +1 的行即本块开行,判其是否 `do {`。计数器为**字面量感知**
（与 tools/audit_syntax.py::_brace_delta 同契约）:glob_set/glob_word 比较里的
`'{'`/`'}'` 字符字面量与 `//`、`/* */` 注释不扰动计数——裸计数在含 `'{'` 字面量
的函数里反向扫描永远到不了 +1,trailer 仍被删（第二层根因）。

验收:curl 124 函数花括号全部平衡,gcc 审计 81 OK/26 FAIL = master 基线逐位一致;
httpd 29 函数全部平衡（master 基线因 main 未闭合 brace 整文件提取失败 0 OK/1 FAIL,
本修复顺带解除）;差分 defects=numbering=0 双语料保持。

## 2026-09-22 追加（SWITCH-CASE-TAIL-0001 — P10 死区启动子误伤折行 if 臂 goto）

**现象**（Lane BW triage 定位，/dev/shm/rudra-tests/sb-switch/GP978_TRIAGE.md §3(a)）：
curl getparameter.constprop.0 的 switch 内 case 0x23/0x35 尾部
`::config.httpreq = HTTPREQ_POST/CUSTOM; break;` 整体蒸发（guard-goto 在场、
直落下一 case），是该 switch 唯一的真语义损失（≈10 行）。

**根因**（非发射层、非结构层——两层的证据链）：
- 结构层:RUDRA_BS_DUMP+case 树 dump 证明 case 0x23 的 BlockList 尾部
  `Copy idx=109 @0x42f0`(COPY@42f0 即赋值)在场,CaseOrder chain=-1 正确;
- 发射层:emit trace 证明语句 token 与 `break;` 全部进入 EmitPrettyPrint 的
  Oppen tokqueue 并经 print_token→low_print 落入 EmitNoMarkup.output
  (绕过 post_process 的对照输出完整含尾赋值);
- **真凶 = post_process_output_legacy 第十遍 "remove dead code after
  return/break/continue"**:该遍把 `goto …;` 行当作 return 类无条件终结符启动
  "死区"(其后同缩进语句全部删除直到 case 标签/浅层 `}`)。当 guard 条件足够长
  被 Oppen 折行时,`goto …;` 独占一行(行首=goto)即命中;单行形态
  `if (…) goto …;`(如 case 0x41)行首是 `if`,永不命中——故只有两个复合长条件
  case(0x23/0x35)受害。

**修复**:P10 的 goto 启动子增加折行 if 臂判别——`goto …;` 行的**前一非空行**
(trim 后)以 `)` 结尾(闭合的 if/while 条件)或等于/以 `else` 结尾时,该 goto 是
条件臂,其后语句是**活**的 fall-through 路径,不启动死区;其余 goto(前一非空行
以 `;`/`{`/`}`/`:` 结尾或无前行)仍视为无条件语句,保持原死区行为。新增
`prev_nonempty_trimmed` 追踪(仅非空行更新)。

**验收**:curl 全文 diff 恰好 +7 行且全部位于 getparameter.constprop.0
(case 0x23 恢复 3 行:`::config.httpreq = 3; uVar27 = uVar27; break;`;
case 0x35 恢复 4 行:`::config.httpreq = 5; uVar27 = uVar27; uVar32 = uVar32; break;`),
零其它函数变化;差分 curl 3661/0/0(base 3654/0/0,+7=恢复行本体,
golden 侧为 `= HTTPREQ_POST` 枚举名形态——已登记 varmap/符号残差族,非新增缺陷);
httpd 2459/0/0 与 sb-condreplay 记录基线恒等;gcc 审计 81/26、7/22 双语料不变;
SetHTTPrequest/parseconfig/my_get_token 逐函数 skeleton 恒等。该层属
POSTFIX-RETIRE-0001 补偿层(oracle prettyprint.cc 零文本后处理),本修复为层内
误伤封堵,不改变层的退役路线。

### 2026-09-23：VARMAP-DUPDECL-EXTRAOUT-0001 — 带括号声明行截断两个 GLUE pass 的声明块遍历（httpd numbering 16 的根因）

**背景**：DP 停车链（wt/sb-pushabsorb@764c3036，RC1 CALL 三 op + RC2 cspec +
RC3 analyzeExtraPop 写回合流后）httpd E2E 2137/0/**16**——numbering 16 全部为
同名双声明，集中在 ap_parse_vhost_addrs（7）/ap_set_name_virtual_host（6）/
ap_update_vhost_from_headers（3）。逐符号审计证明 varmap 侧清白：ScopeLocal
每名字恰一个符号（38 符号/50 输出行），printc `emit_scope_local_var_decls`
按 (space rank, start, usepoint) 每符号恰发射一次；16 处重复**全部**由本文件
两个无 oracle 对应物的 GLUE 文本 pass 制造。

**根因**（两 pass 同型缺陷）：printc 按 Symbol dtype 逐字发射的指针-数组/
函数指针声明形（`undefined1 (*pauVar7) [16];`、`void (*pVar4)();`，
printc.cc:2503-2506；oracle direct-runner golden 同形
`xunknown1 (*paxVar11) [16];`）含 `(`——而两个 pass 的声明块遍历把
`contains('(')` 当"非声明"信号提前 break：

- `has_symbol_driven_decls`（flush_func_remove_unused 的旁路判据）：在带括号
  声明处 break → 其后才出现的 `undefined*`/`in_*` 证据不可见 → 符号驱动
  chunk 被判 legacy → flush 的 missing-injection 半臂运行，其 type_ok 表不识
  别 `uint8`/`uint`/`uint1` 等拼写 → 注入 `int uVarN;` 重复（httpd 侧 9 处）。
- `backfill_missing_locals` 的 declared 收集：同处 break → 其后所有已声明名
  判 missing → 按前缀推断类型整组重注入（`long uVar10;`…`int bVar18;`，
  覆盖全部 16 处——单独旁路 flush 仍剩 9，单独旁路 backfill 归零，实测定位）。

**修复**（跨租约最小化两 hunk + 一 helper，printc.rs 未动）：

1. 新增 `has_symbol_driven_decls_walk_parens()`：同 acceptance 集
   （`ends_with(';')`、无 `return`、无 `=`）但去掉 `!contains('('')` 拒绝，
   带括号纯声明行 continue 而非 break。**仅**接入
   `flush_func_remove_unused` 的旁路（`||` 并联原判据，原判据命中集不减）。
   P22 掩码（`symbol_driven_function_line_mask` →
   `fix_unary_deref_declarations`）**刻意**保持原判据：若一并放宽，curl
   progressbarinit 等函数会新增旁路，丢失 `*param_N` 合法性修复的 legacy
   补偿（实测签名 `char *param_1`→`long param_1` 翻转、curl E2E 字节漂移；
   该补偿是 P22 fiction，oracle 为 `ProgressData *bar`，属 FuncProto 参数
  指针定型域另案）。
2. `backfill_missing_locals` 的 declared 收集新增带括号纯声明分支：行含
   `(*` 且无 `=`/`return` 时抽取括号内标识符（`(*pauVar7)` → `pauVar7`），
   continue 遍历；真 body 语句（含 `=`）仍在上方被拒，非声明形照常 break。

**验收**（fast-release + release 双口径，RUDRA_MIRROR，oracle e40ed130）：
httpd **2137/0/16 → 2104/0/0**（三目标函数 326/7→311/0、228/6→217/0、
219/3→212/0；`--func main` 两态均 TIMEOUT=已知
HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001 不变）；curl 与基**逐字节相同**
（4073/0/0，cmp 零差异）；gcc 审计 httpd 1/27、curl 101/19 均不变；
`cargo test --lib -- --test-threads=1 prettyprint varmap printc` 63/63，
全量 1650/18 与基逐测试同集（funcdata/heritage 18 失败=基分支预存）。
该层属 POSTFIX-RETIRE-0001 补偿层（oracle prettyprint.cc 零文本后处理），
本修复为层内误伤封堵，不改变退役路线。

## 2026-09-23（CHAINFIX lane EY2）：legacy_never_type_evidence 证据集扩宽

- 新增 `legacy_never_type_evidence()`（RUDRA-GLUE，`has_symbol_driven_decls`
  / `_walk_parens` 共用判据 helper）：原 `undefined*` 前缀之外补入
  `uint*`/`int1`/`int2`/`int8`/`ushort`/`ulong`/`longlong`/`__int*_t`——
  均为符号驱动发射器独有拼写（printc.cc:2260-2279 core-type dtype 逐字
  打印），legacy 文本 pass 只合成 int/long/bool/byte/short/char */void */
  float/double（flush_func_remove_unused 的 type_ok 表）。
  CHAINFIX-LEGACY-BYPASS-0001：ActionInputPrototype 的 function_parameter
  符号安装（本车道）退休了部分 chunk 唯一的 `in_` 名字证据后，这些 chunk
  落回 legacy pass，其收集器不识别符号拼写、把每个 uVarN 判"缺失"，在
  签名与 `{` 之间注入 `int uVarN;` K&R 式重复声明（httpd ap_getparents、
  curl glob_word）。扩宽后该误判消除（curl −5 行全为死声明删除）。plain
  `int` 不在集合内（legacy 合法拼写），判定方向保持保守。

## 2026-09-24（FULLEMPTY-ELSE lane FZ）：P6 声明删除谓词换用真声明行判据

HTTPD-FULLEMPTY-ELSE-0001 residual（FX 在 9458a61b 父链复现登记，本 lane 于
亲父 720551db 亲测归因收口）：httpd 全量 470 函数唯一 defect——
ap_get_server_name L21 空 `else {}`。

**根因（双探针钉死）**：printc 侧 else 臂结构/ops 全部健在（sblocks 树
If[cond BB2, then BB3, else BB4] 与 oracle 同形；BB4 的 CALL/STORE 活、
非 implied、parent 正确，主 pass 确实走到 emit_statement——RUDRA_FZRAW
原始文本层快照实证 else 臂**本已打印**两行：
`uVar5 = apr_pstrdup(*puVar2,…);` + `*puVar2 + 0xb = uVar5;`）。
凶手是 P6 单用内联的**声明删除谓词**：`contains(" uVar5;")` 把尾置裸变量的
使用行（`… = uVar5;`、`return uVar5;`）也判成声明——inline 臂同时删掉
赋值行与唯一使用行（decl 检查先于 replace_word 且 `continue` 短路），
双删后 else 臂残空。RUDRA_POSTFIX_STATS 实测该函数 P6=3 突变（31→30 行）。

**修复**：新增 `is_declaration_line(t, var_name)` 判据——`<类型头> uVarN;`
整行尾匹配 + 类型头字符集仅限 `[A-Za-z0-9_ *]` + 语句关键字黑名单
（return/goto/break/continue/case/default）；inline 与 dead-elim 两臂统一
换用。使用行不再被当声明清空，落入 `replace_word` 正常内联为
`*puVar2 + 0xb = apr_pstrdup(*puVar2,…);`（该地址拼写缺括号为 printc
STORE 臂既有骨架差，非 defect 类，另案）。

**验收**（fast-release，亲父 720551db 双 worktree 对照亲测）：httpd 全量
L2 vs direct-runner **38672/1/0 → 38726/0/0**（defects 1→0——空 else 消失；
skeleton +54 = **55 条被 P6 静默吞掉的真实语句恢复打印**（apr_pstrdup/
apr_array_make 调用、全局/指针 STORE、`x^x` 清零等，逐行 diff base/fix
核实全部为 restored-statement 类，11 行删除全为空白行），语句恢复方向与
golden 一致、文本形态仍异（缺括号 STORE 臂拼写=printc 既有骨架差另案）；
httpd 门禁面 29 fns **2698/0/0 == 基线恒等**（受影响函数均在门禁面外）；
curl E2E 与亲父基线**逐字节相同**（P6 谓词变更对 curl 语料零命中）；
gcc 审计 per-function OK/FAIL 集与基线恒等（101/369，int8 族预存）；
三投影 next_url/match_url/parseconfig.constprop.0(RUDRA_MIRROR=1)
stage_bisect --v1 **MATCH×3**。该修复为 POSTFIX-RETIRE-0001 补偿层内
误伤封堵，不改变退役路线（P6 整层退役时随之消失）。

## 2026-09-24 (Lane MAIN2) — 移除 `+ -N` → `- N` 后处理改写（PRINTC-PLUSNEGLIT-0001）

Ghidra 按位打印负加数：`push_integer`（printc.cc:1288-1368）把负号放进常量
atom（`-8`），binary_plus 保留 ` + ` 记号 → 输出 `X + -8`。canon golden 含
666 处 `+ -` 形、direct-runner golden 1096 处；本仓后处理把所有 `+ -N` 改写
成 `- N`，使 Rudra 侧为 0 处——每一行都是骨架差分。该"算术简化"非 Ghidra
行为（无 oracle 对应物），已删除。删除后 httpd 56 处、curl 相应恢复
`+ -N` 正典拼写。

## 声明回填 pass：后缀数组声明符识别（HEADLESS-BRIDGE-V1-TYPESEED，2026-09-25）

声明回填（backfill）收集已声明名时改为先剥掉尾部的 `[N]` 维度 token（及
 glued 形）再取名字。旧实现在 `long local_c8 [4];` 上把 `[4]` 当成"声明的
名字"，于是函数体里的 `local_c8` 使用被误判为未声明、回填注入了
`int local_c8;` 重复声明（printc.cc:2502 pushTypeStart/pushSymbol 的符号
声明后缀数组拼写是 C1 种子通道引入的常态形态）。默认路径无后缀数组局部
声明，输出 cmp 字节恒等亲父。

## 声明回填 pass：未名位置 token 零声明（PRINTC-C3-UNNAMED-SPACE-NAME-0001，2026-09-25，Lane PDOTFORM）

回填注入对四个未名位置 token 前缀（`unique0x`/`register0x`/`stack0x`/
`ram0x`）跳过。canon（12.0.4 golden）对这些 token **零声明**：它们是
`PrintC::pushUnnamedLocation`（printc.cc:1938-1945）的表达式级存储槽标签，
不是 ScopeLocal 符号，oracle 的 emitLocalVarDecls（printc.cc:2260-2279）只
遍历符号、永不为其发声明（golden 中 stack0x 使用站点 3 处、声明 0 处）。
printc 侧空间名形态接通后（`&stack0x00000008` canon 形），不跳过会注入
`long stack0x00000008;` 与 canon 文本分歧（_start 10→11 回退源）。

## 2026-09-25（Lane MIRROR2，merge 去重后与 TAGLINE 车道同条目）：标号绝对缩进统一到 `tag_line_indent`（MIRROR2-LABELINDENT-0001）

- **根因（镜面残差族=label 缩进）**：oracle 的 `PrintC::emitLabelStatement`
  （printc.cc:3211）调用 `emit->tagLine(0)`——这是与 `tagLine()` **不同的
  虚函数**（prettyprint.hh:180），token 形态为 `line_t`：触发时以
  `spaceremain = maxlinesize - indentbump` **绝对列**断行
  （prettyprint.cc:674-675），与缩进栈无关 → goto 标号恒在列 0
  （golden httpd 620/620、curl 47/47 全部 `^code_r` 列 0 实证）。
- **Rudra 旧缺陷**：`Emit` trait 的合并式 `tag_line(indent: i32)` 用
  `indent > 0` 分支区分两种形态，`tagLine(0)` 被路由到相对 `bump_t`
  （当前缩进层）→ 标号随嵌套缩进（httpd 42 处、curl 45 处 `^ *code_r`
  实证，golden 0 处）。语句层 `tag_line(0)`（=oracle 平凡 `tagLine()`）
  的传输约定不能改——`close_brace_indent`/`open_brace_indent` 等大量
  站点以 0 表示平凡形式。
- **修法与去重**：MIRROR2 原交付（7ced32ff）以 `tag_line_at` 独立 trait
  方法承载该虚函数；TAGLINE 车道（2e2997f4/cdd66875）独立同发现并以
  `tag_line_indent` 落地（实现逐行同语义：EmitNoMarkup=endl+`indent.max(0)`
  字面空格、EmitPrettyPrint=无条件 line_t token）。**merge master 后统一到
  `tag_line_indent` 单通道**——MIRROR2 的 `tag_line_at` trait 方法+双实现
  删除，标签站点全改调 `tag_line_indent(0)`；TAGLINE 额外覆盖
  printlanguage.cc:597/616-617 的注释续行两站点并给合并式 `tag_line` 加
  debug_assert（indent>0 断言）硬化，oracle 生产调用面（标号 3 站点+注释
  2 站点）全数走绝对形。
- **效果**：curl 镜 695→683、httpd 镜 1140→1076、vsh 镜 55→51、canon
  466==466 不回退（canon 标号面由 TAGLINE 同修覆盖）。
- **修法（历史记录，7ced32ff 原形）**：新增 trait 方法承载该虚函数
  （EmitPrettyPrint 覆写为无条件 `line_t` token——prettyprint.cc:927-934
  的逐行对齐；EmitNoMarkup 覆写为 `endl + indent 个字面空格`——
  prettyprint.hh:558-560），printc 三个标号发射站点（emit_label_statement
  与 emit_any_label_statement 两臂）改调绝对形。**merge master 后该方法已
  由 TAGLINE 的 `tag_line_indent` 统一取代**（见上「修法与去重」）。

## 2026-09-25（Lane DOTFIX）：第七趟字符常量文本改写退役（STUBLEAK-CHARPRINT-LOOPCONST-0001）

- **根因**：后处理第七趟持一张 28 项硬编码表，把 `== 0xNN` / `!= 0xNN` /
  `= 0xNN;` 文本改写为 `'c'` 字符字面量。oracle **不存在任何文本层常量
  改写**：字符 vs 整数形态由 `PrintC::pushConstant`（printc.cc:1744-1768）
  按 varnode **传播类型**决定——`isCharPrint()` 走 pushCharConstant，
  TYPE_UNKNOWN/普通 int/uint 走 push_integer（0x26 经 mostNaturalBase=16
  印 `0x26`，printc.cc:1325-1337）。文本表无法区分类型，把所有无类型/
  int 型可打印常量污染成字符字面量：canon golden curl:741 与 direct-runner
  golden:494 的 `for (lVar13/iVar12 = 0x26; ...)` 均被印成 `'&'`；
  httpd 镜 `uVar12 != 0x26`（golden:5326）被印成 `'&'`。
- **修法**：整表删除（连同三向 replace 循环）。typed-char 面
  （httpd canon golden 30275 `cVar2 != '&'`）是 printc
  `is_char_print` 类型传播的职责（typeprop 域，GENSMOKE-S2 族），不是
  后处理文本层的职责。
- **效果**：四档全降——curl 镜 259→211、httpd 镜 440→412、
  curl canon 396→388、httpd canon 896→872；defects/numbering 全零。
  已知连带：httpd canon 1543/1604 两行（ap_pregsub，golden 30275/30286
  `cVar2 != '&'` 为 typed-char 面）原先经该表印 `'&'`，现印 `0x26`——
  该两行变量名/结构本已与 golden 分叉，所属函数整体 45→41 仍净降；
  typed `'&'` 正道是 printc `is_char_print` 类型传播（typeprop 域，
  GENSMOKE-S2 族），非文本层职责。

### 2026-09-26 — 签名判据补 no_assignment 门（HTTPDMAIN-F8-FORLOOP-0001，Lane F8FOR）

`post_process_output_legacy` 的嵌套函数签名判据（补偿层，POSTFIX-RETIRE-0001
登记域）新增第五道语义门：候选行含 `=` 即非签名（C 函数签名永不含赋值
operator）。诱因：for 头超行宽折行后，续行形如
`    puVar11 = (undefined8 *)*puVar11) {` ——带收口 `) {`、赋值 `=`、cast 的
` *`、比较符留在首行（no_comparison 门不拦），全过旧四门被判为嵌套函数
签名 → 空声明遍历把循环体自动名局部全部"补声明"回灌（`  long uVar13;`
等 3 处）。与既有 MAIN-IVAR4-DUP（分号门）/WARN-EMIT2 R4（比较符门）同款
判据加固模式。canon httpd 293→277（−16 含本门 −8 行回灌）。


### 2026-09-26 — POSTFIX-BOOLFOLD-TOKEN-0001（MIGW1-TYPEOP-0002 fixture 暴露）

- 补偿层 pass3 `"1 || " → always true` 的朴素 `replacen` 命中数字 token 尾：
  `0x11 || x` 的 "1 || " 子串被剥，产出 `0x10x22`-族残缺 C（B2 fixture
  typeop_push_dispatch_1204 的 bin_bool_or case 双侧对比直接暴露；master
  亲证预存，非本 lane 引入）。修复 = `fold_standalone_one_or`：仅折叠独立
  token `1`（前行 ∈ {行首, `(`, 空白}），`0x11 || `/`a1 || ` 数字尾不触；
  UTF-8 char-wise 拷贝 helper `utf8_char_len`。真实 `if (1 || x)` 折叠语义
  保留。canon curl/httpd 与 master 逐字节恒等（语料无可达命中面）。本 lane
  写域越界 1 文件声明：B2 验收门硬依赖（BOOL_OR case），与 F8FOR 判据加固
  先例同款，请 root 裁量。

### 2026-09-27 — PRETTYPRINT-SIGWRAP-0001（签名断行族：emitter 契约钉死）

- **结论先行**：`EmitPrettyPrint` 核心（scan/print/advanceleft/overflow/
  checkstart/checkstring/checkend/checkbreak，cc:641-856）与 oracle 逐语义
  等价（外部 harness 喂 oracle token 流直接产出 golden 字节，MIRROR3 复核
  结论维持）；SIG-WRAP 族（sq ~244 行/75 hunk/40+ thunks）根因在**喂入的
  token 流**——printc.rs `emit_function_declaration` 把 cc:2582 的
  `emit->spaces(1)` tokenbreak 实现成 `print(" ")` 内容 token（修复见
  docs/api/printc.md 同日条目）。本文件零行为改动，新增
  `linewrap_probe_tests` 两测把断行契约钉死：
  - `signature_wrap_breaks_after_funcname_not_return_type`：thunk 形
    （返回类型+函数名同行，断点=函数名→`(` 的 bump-10 tokenbreak，参数表
    次行 20 空格缩进=indentstack.back()=80 处 `maxlinesize-80`），
    期望字节=ghidra_sq_1204.direct-runner.c `_ZThn16_..SetCoderProperties`
    逐字；
  - `signature_wrap_comma_opens_continuation_line`：参数表溢出子形——
    checkstring 零宽断点（cc:819-828）在逗号 token **之前**，续行由逗号
    开头、组内对齐缩进，期望字节=`initialise_threads` 14 参形逐字。
- **关键语义复核**（亲读 prettyprint.cc:584-709 print 的 tokenbreak 臂）：
  断行豁免 `(numSpaces <= spaceremain) && (val - spaceremain < 10)` 是
  该族分叉点——bump-0 的 1 空格断点在行尾必命中豁免（100-91=9<10）不换
  行，bump-10 的函数名断点（80-9=71≥10）必换行；`overflow()` 的 half-line
  抬升（cc:587-593）与本族无交互（无 >spaceremain 的单体 token）。

### 2026-09-28 — CASTFUSEB（GEN4-SQ-CASTFUSE-DEPTH-0001 子族 B：P25 指针名扫描误收 store 行）

- **结论先行**：子族 B（sq CAST-SHAPE `ptr + (long)idx` addend 加宽形）的
  主根因不在票面候选（ActionSetCasts/castStandard/RulePtrArith），而在本文件
  的 P25 文本补偿 pass `fix_pointer_arithmetic` —— 指针名收集扫描把
  **store-through-deref 语句行**误当声明行。修复 = 声明行判定追加
  `!t.contains('=')` 判别子（声明行永不含 `=`；被误扫的 store 行必含）。
- **机制链**（代表函数 `_ZN5NPat29CPatricia15GetLongestMatchEPj`
  `--one 611`，A/B 亲证 /dev/shm/rudra-tests/castfuseb/one611_{base,fix}.c）：
  `*piVar19 = iVar31 - uVar35;` 同样满足旧行判定（`;` 结尾 + 含 `*`（解引用
  前缀）+ 无 `(` + 无 `return`），其末 token `uVar35` 被误收进 ptr_names →
  P25 把合法的 `puVar26 = puVar13 + uVar35;`（Rudra 原始 emit 本就裸 idx，
  与 oracle opPtradd 非值上下文印法一致——printc.cc:880-893，:891
  `pushVn(op->getIn(1),op,m)` 裸推 index 操作数，机制 E 亲读）重写成
  `puVar13 + (long)uVar35` —— 即 sq CAST-SHAPE addend-widening 族与
  sqlite `+ (long)` R-only census（SQLCENSUS4 §S4 89 处）的主量。
- **oracle 侧亲证**：golden 同函数 0 处 `+ (long)`；裸形
  `puVar28 = puVar16 + uVar34;`（golden:41059 附近）与修复后 Rudra 输出
  同形；golden 内 28 条 `*piVarNN = …;` store-through-deref 行 = 误扫源
  全景（每条以标识符结尾者都是潜在假名）。
- **修复形态**：单判别子（declarations never contain `=`）+ 两测锁定
  （`fix_pointer_arithmetic_ignores_store_lines_in_name_scan`：store 行
  末 token 不入 ptr_names、`ptr + int` 保持裸；
  `fix_pointer_arithmetic_still_casts_real_ptr_plus_ptr`：真 ptr+ptr
  （C 非法操作数补偿目标）仍获 `(long)` 右操作数 cast）。
- **验收**：canon curl 68/0/0 + httpd 47/0/0（双红线的精确命中，零回退）；
  镜面 sq 3021→2935（−86）；bank 391/391；cargo test 1957P/0F（亲父
  1955P + 新 2）。prettyprint 属机制 B 门禁（差分已过：defects=0/
  numbering=0），非机制 C 白名单。

### 2026-10-01 — LONGADDEND（GEN4-SQ-CASTFUSE-DEPTH-0001 long-addend 族：P25 镜面面整臂跳过）

- **结论先行**：CASTFUSEB 修掉的是 P25 指针名收集的**假名**（store 行误扫），
  本道修掉的是真名命中下的**面错配**——P25 是 canon 拼写补偿（canon golden
  本身含 `(long)`：curl 55 处 / httpd 1165 处），但在 direct-runner（镜面）
  契约面 oracle 从不印 cast 于 PTRADD index 加数——`PrintC::opPtradd`
  （printc.cc:880-893）以裸 `pushVn(op->getIn(1),op,m)` 推 index（无 cast
  旗标），发射管线终点 `EmitPrettyPrint::flush`（prettyprint.cc:1194-1211）
  是纯 token 队列排空、零文本再扫描；五面 direct-runner golden 全部 0 处
  `(long)`。P25 在镜面面的每次点火 = 一行 skeleton diff。
- **双侧 IR 钉形**（代表位点 sq `_ZN10COutBuffer5FlushEv` @0x42553，oracle
  探针 castfuse2_probe probe 797——C 输出与 golden 逐字节恒等亲证）：
  双侧 op 链**恒等**——`PTRADD(R12, LOAD(piVar16+5×8), ×1)` + 输出侧
  `CAST(int8)`（`piVar16[5] = (int8)(pcVar20 + piVar16[5])` 的 `(int8)`
  是真 IR CAST），Rudra 同 varnode id（u0x8f00/u0xd500/u0x100013c8）。
  分歧**不在 IR**，纯粹是 P25 文本层把 `pcVar20 + piVar16[5]`（两操作数名
  均为指针声明）重写成 `pcVar20 + (long)piVar16[5]`。
- **修复形态**：`fix_pointer_arithmetic` 入口整臂 `mirror_face_active()`
  早退（与 GEN4-SQ-DUPDECL-NUMBERING-0001 的 backfill/flush 两臂同形）；
  canon 面 P25 逐字节保持运行。
- **验收**：镜面五面官方门禁 PASS——sq **324→280**（−44 == MC5 census
  long-addend sq 值精确燃尽：COutBuffer Flush/FlushPart 4+8 + NLZMA
  CodeOneBlock/.part.0/Flush 4+8+4 + NPat TestRemove 克隆 2×8，13 函数
  零回归）；sqlite **706→604**（−102 = trio 84 精确[vmprintf 46→16 /
  mprintf 44→16 / Pragma 39→13] + 同根邻位 18[VdbeExec −8 / PagerWrite
  −4 / BtreeTableMoveto −4 / EndTable −2]）；curl 13 / httpd 2 / vsh 0
  恰钉值恒等；defects=numbering=0 全面。canon 红线：curl md5 b7773087 /
  httpd md5 54f9b02c **字节恒等**（compare 0/0/0，124F+34F）。


## 2026-10-02：P9 双空格塌缩收窄到 "+N − N" 消除实际改写的行（READINODE3）

`post_process_output_legacy` 第九 pass 的 content 双空格塌缩（`"  " → " "`，
`" )"` trim 同块）原本无条件跑每一行。oracle 的 pushType 对匿名数组 cast
合法产出双空格——`type_expr_space`（spacing=1,printc.cc:73）+ `array_expr`
postsurround spacing（printc.cc:76）在无标识符位相邻叠加,golden 形如
`(xunknown1  [16])`（canon curl :2271 两位点、canon httpd 84 位点、sq 66、
sqlite 308）。无条件塌缩把每一处都吃成单空格——read_inode_3 函数体最后
10 行原始字节差即此形（skeleton 归一化不可见,语料字节面全量损伤）。

修复 = 该清理本为 `+N − N` 消除的碎片清理（自身注释声明）,现按行记录
`pre_cancellation` 快照,仅 `line != pre_cancellation`（消除真实发生）的行
执行塌缩/trim;`while(` / `} while( true );` 豁免保持不变。oracle 合法
`  ` 字节全部存活,消除碎片行仍清理。

**单测**（prettyprint.rs tests）: `postprocess_preserves_array_cast_double_space`
（数组 cast 双空格存活 + `+ 1 - 1` 碎片行仍塌缩双断言）;配套
printc.rs `cast_type_string_anonymous_array_double_space` 钉住拼写源头
（`xunknown1  [8]` 双空格,与 golden 逐字）。

**验收**: read_inode_3 函数体与 golden 逐字节恒等；canon curl **字节恒等 b7773087**
（零位移——golden curl 的 `  [` 命中系折行缩进伪形,P9 只触 content）,canon httpd
54f9b02c→cf316540 重钉（恰 2 位点 `(undefined1  [16])` 复原,行形态==golden;
defects/numbering 0/0 双面保持）；corpus 钉组 canon b6d76445/mirror d526070e
（+325B=317 行+8 双位点行,全 P9 形,73 函数/面,函数集恒等）;VdbeExec
20920e63/0668b234（各 39 行纯双空格形）；五面详见 LANE_READINODE3_2026-10-02.md。

### 2026-10-03：STRUCTAIL-POSTFIX-TAILKEEP-0001 — 四 GLUE pass 误吞 oracle-真结构尾（P10/P14/P16c/P24 各加窄守卫）

**背景**（Lane STRUCTAIL，TAILCENSUS 备靶序四「结构尾清扫 19 行」TC-F4+F9+F13 族）：
镜面 sqlite 残 28 中的 18 行 + sq 残 35 中的 2 行属结构尾族（goto-keep/empty-branch-keep/
G-only 块）。双侧钻定（RUDRA_DUMP_FUNC 树 dump + LOWPRINT 发射踪迹 + RUDRA_POSTFIX_STATS
逐 pass 计数）证明**发射层零缺陷**：全部受害函数的 pre-post_process 输出与 golden
**逐字节恒等**（InitCallback/InitOne/WalFrames/RecordCompare×2/ExprImplies/
ResolveSelectNames/session_changeset/Bitvec/GetVarintBounded/Fts3ExprParse + sq 面
read_super/GetLongestMatch 亲证）——残差 100% 产生于 `post_process_output_legacy`
补偿层四个 pass 的文本误吞（第十四例翻案谱系: census 预判「blockaction/condexe 结构
域」被证伪,真域=prettyprint 文本补偿层,oracle 侧 printc.cc:2641-2676 docFunction 止于
flush、prettyprint.cc:1194-1211 flush 为纯 token 队列排水,零文本后处理）。

**四个误吞位点**（同一公共根因的四个切面——行级启发式补偿 pass 无法区分「折行条件臂」
与「无条件终结语句」,oracle-真发射被当死码删除）:

1. **P10（remove dead code after return/break/continue）**: `while( true ) { ...
   if (长条件...) <折行> break;` 的 overflow 臂折行 `break;`（emitBlockWhileDo
   printc.cc:3035-3043,Oppen 在条件与臂之间断行）被当无条件 break 启动死区,吞掉
   其后全部同缩进语句直到浅层 `}` —— Fts3GetVarintBounded 循环闩 6 行
   （`iVar3=iVar3+7; puVar2=puVar2+1; if(iVar3==0x46){...return...}`）。
2. **P14（consecutive goto）**: 折行 if 臂 `goto A;`（前一行以 `)` 结尾=折行条件,
   emitBlockIf goto 臂 printc.cc:2914-2917）之后的外层块出口 `goto B;`
   （emitBlockGoto printc.cc:2766-2779）被当连续 goto 死码吞掉 —— golden
   VdbeRecordCompareWithSkip:124331-124333 双 goto 形 oracle 保留 —— 六函数各 1 行。
3. **P16c（empty if removal）**: `if (cond) {` + `}`（空 then-臂,后随 `else {`）
   被整对删除但 else 留存 → 裸 `else {`（非法 C）。oracle emitBlockIf
   printc.cc:2918-2925 对空体也发射 body 对象 —— InitCallback/InitOne 各 2 行。
4. **P24（orphan breaks）**: 行级 loop 头识别（行以 while/for/do/switch 开头**且**
   以 `{` 结尾）盲于折行 while 头（`while (cond,`/`cond,`/`...) {` 三行,
   emitBlockWhileDo cc:3053-3056 comma_separate 条件重放折行）→ 整个循环体失去
   保护 → `if (param_1 < (int4)uStack_44) break;` 的 break token 被摘、行以 `)`
   结尾整行删除 —— BitvecBuiltinTest 1 行。

**修复**（四窄守卫,全部限缩在既有 pass 设计补偿目标内,oracle 行为对齐方向）:

- P10/P14: SWITCH-CASE-TAIL-0001 的折行条件臂判据（前一非空行以 `)` 结尾或
  `else`）从 goto 启动子扩到 `break;`/`continue;`/`return;`（P10）与 prev_was_goto
  置位（P14）——折行臂后的语句是活 fall-through/出口,不启动死区。
- P16c: 空 if 块删除前检查闭 `}` 后一行——`else`/`else `跟随则保留该 if（删除会
  留孤儿 else 并丢分支结构）;无 else 的空 if 仍删（原行为）。
- P24: 预扫描加 `pending_loop_header` 追踪——行以 loop 关键字开头但不以 `{` 结尾
  时置 pending,后续携带 `{` 的行认领 opener（函数签名 reset 处同步清 pending）。

**验收**: 镜面五面 curl 0/74·httpd 0/29·vsh 0/71·sq 35→**33**/810·sqlite
28→**10**/1385 全 PASS defects=numbering=0（残 10=WindowCodeStep 5+Reindex 2+
Select 2+AddCheckConstraint 1 全 misc-tail 族;残 33=sq F1 29+F5 4 两在飞族）;
受害函数逐一对 golden 全等（compare --func skeleton=0 defects=0 numbering=0,
11+2 函数亲证）;canon 红线 curl f903372a·124/124 全零+httpd 3617ecc3·34/34
全零字节恒等;corpus A/B（vs MB82 钉 1fa47be4/dbe6f683）双面各恰 11 函数 11
hunks 纯 +18 行 golden 复原（canon +536B/mirror +540B）,其余 1374 函数字节
恒等,函数集差=∅;VdbeExec mirror b3f5b487/canon 606dd8c0 恒等;tests 2049P;
ratchet 同 commit 重钉（STRUCTAIL-REPIN-0001: sqlite 10+sq 33）。该层属
POSTFIX-RETIRE-0001 补偿层,本修复为层内误伤封堵,不改变层的退役路线。
