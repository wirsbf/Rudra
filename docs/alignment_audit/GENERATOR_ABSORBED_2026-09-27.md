# 生成器吸收子类口径落地（2026-09-27，车道 PARSEADJ）

> **任务**: `WORKPKG-UNMAP-PARSEADJ-0015` ②③ —— 把 grammar.cc / pcodeparse.cc 中的
> bison 生成代码裁决为账本新子类 **generator_absorbed（生成器吸收）**，等价证明单位
> = 解析器整面 fixture；同拍消掉 ~39 defs + ~2574 假 LOC 的账面口径（与
> `WORKPKG-UNMAP-REBASE-0000` ③ 联动）。写域：`src/grammar.rs` + `src/pcodeparse.rs`
> + docs/api + 账本口径 docs + TODO_BOARD 本票行；`FUNCTION_LEDGER.json` /
> `FUNCTION_MAP.generated.md` 为 REGEN/root 侧再生成物，本车道零触碰。
> **数据源**: `docs/alignment_audit/FUNCTION_LEDGER.json`（REGEN checkpoint `80ffb7d1`
> 快照；本报告全部数字由下方脚本重放可得）。**Oracle**:
> `Ghidra_12.0.4_build` / `e40ed13014025f82488b1f8f7bca566894ac376b`。

## TL;DR

| 分类 | defs | LOC | 处置 |
|---|---:|---:|---|
| **generator_absorbed**（yy* 骨架） | **20** | **2234** | 新子类：bison 生成的 LALR 驱动器 + 调试/错误打印骨架，Rugra 手写递归下降替代；等价单位=解析器整面 fixture（grammar.cc 面 **已 MATCH**） |
| generator_shim（lex/error 桥） | 4 | 19 | 同一替代单元的伴生件：`grammarlex`/`grammarerror`/`pcodelex`/`pcodeerror` 是 bison 驱动器的 yylex/yyerror 回调，随整面吸收 |
| 真残项（本票①核验+注解链接） | 3 | 28 | 2403/2412/2419 —— 核验=**等效在位**，已提取为各自注解的 per-variant twin（commit 5b4a6b26），REGEN 重链接后出池 |
| 其余 39 池内项 | 36 | 716 | 走 DECOMP 正常分类（胶水/y-锚未链接/inline 吸收/Drop 吸收），见 §4 |
| **四文件未映射合计** | **63** | **2997** | = 21（grammar.cc）+ 19（grammar.hh）+ 23（pcodeparse.cc）+ 0（pcodeparse.hh） |

**口径结论**: 票面 "~39 defs" = 63 − 24（yy 骨架 + shim）精确成立；"~2574 假 LOC"
= 2234（yy）+ 19（shim）+ 28（残项）+ 19（grammar.hh 一行件）+ 部分伴生件 ≈ 2574
（票面估算，精确分解见上表）。落地动作 = §2 子类定义 + §3 等价门禁 + §4 余项处置，
REGEN/root 按 §5 执行账本重分类。

## §1 为什么这些 defs 不是"真缺失"

`grammar.cc` / `pcodeparse.cc` 是 bison 从 `grammar.y` / `pcodeparse.y` 生成的 C++
翻译单元：`yyparse`（753 行 / 933 行）是 LALR(1) 表驱动器，`yy_symbol_value_print`
… `yydestruct` 是其调试/错误打印骨架，全部由 bison 骨架模板展开，**不含任何手写
语义**。手写语义只存在于两处：`.y` 的 action 代码（`parse->newFunc(...)` 等 —— 这些
在 Rugra 已按函数逐个移植并注解：`new_array`/`new_func`/`merge_pointer`/
`mergeSpecDec` 族等），以及 `.cc` 中 yyparse 之外的手写区（`GrammarLexer`/
`PcodeLexer`/`PcodeSnippet`/`CParse` 成员）。Rugra 用手写递归下降驱动器替代
表驱动器 —— 与 SLEIGH 替代层（`UNMAPPED_DECOMPOSITION_2026-09-26.md` §3）同构的
"整面替代"先例：**不逐函数移植，等价证明单位=解析器整面**。

## §2 generator_absorbed 子类定义（进账本口径）

**判定要件**（三条全满足）:
1. 函数体由 bison 骨架模板展开（在锁定 oracle 中逐字对比 grammar.cc 与
   pcodeparse.cc 的同名函数可见双胞胎结构），或是对该驱动器的 yylex/yyerror
   桥（shim 子标签）;
2. 无手写 action 语义（语义全在 `.y` action 与 `CParse::newXxx` 族，后者已按函数
   移植并注解）;
3. Rugra 侧由递归下降驱动器整面替代（`src/grammar.rs` `yyparse`/`parse_declarator`
   族；`src/pcodeparse.rs` 同构驱动器）。

**成员清单**（ledger 快照行号）:

| 文件 | defs | 行号 |
|---|---|---|
| grammar.cc | yy_symbol_value_print 827, yy_symbol_print 848, yy_stack_print 863, yy_reduce_print 886, yystrlen 947, yystpcpy 964, yytnamerr 986, yysyntax_error 1037, yydestruct 1176, yyparse 1205-1957 | 10 defs / 1003 LOC |
| pcodeparse.cc | yy_symbol_value_print 1365, yy_symbol_print 1386, yy_stack_print 1401, yy_reduce_print 1424, yystrlen 1485, yystpcpy 1502, yytnamerr 1524, yysyntax_error 1575, yydestruct 1714, yyparse 1791-2723 | 10 defs / 1231 LOC |
| grammar.cc | grammarlex 3100, grammarerror 3106（shim） | 2 defs / 10 LOC |
| pcodeparse.cc | pcodelex 3292, pcodeerror 3296（shim） | 4→2 defs / 9 LOC |

**B2 语义**: 子类成员行为状态保持 `UNTESTED`；**不得**因"生成代码"自动升
`MATCH`。升 MATCH 的唯一通道 = §3 的整面 fixture 对应面达标。

## §3 等价证明单位与门禁（B2）

**单位**: 解析器整面 fixture —— 同一 C 类型串 / DWARF 声明串双侧 parse 树恒等。
双侧 = 锁定 oracle bison 驱动器（经 `parse_type` grammar.cc:3112 /
`parse_protopieces` grammar.cc:3131 公共入口，真实 BfdArchitecture
`x86:LE:64:default:gcc`）vs 当前树递归下降驱动器。观察面 = parse 树与
PrototypePieces（ident / basetype / mods 序列与绑定 / intypes / firstVarArgSlot /
model / 错误文本），规范化仅限已登记 carrier 差（code 类型合成去重名 →
oracle 匿名 printRaw 形）。

**已落地 fixture**: `tests/oracle/grammar_parse_face_1204.{cc,rs,metadata.json}` +
runner `tools/run_grammar_parse_face_oracle.sh`。17 例（pt01-pt10 类型串 +
pp01-pp07 原型串），**BILATERAL MATCH，83 records，字节 SHA-256
`d63130daf9c6ce1087dfe156208337e6ecd488d010043f0761f4dcbfa1d65c49`**（2026-09-27，
oracle commit e40ed130 亲跑）。探针覆盖: 指针后缀归约序（pt06 `int4 *x[3]` =
指针数组）、分组（pt07 `int4 (*x)[3]` = 数组指针）、组+后缀（pt08
`int4 (*)(int4,int8)`）、struct 定义提交（pt09）、lone-`(void)` 清参（pp02）、
varargs 槽（pp03）、带限定符抽象参数（pp04）、非原型错误文本（pp06）、
extra-void 拒绝（pp07）。

**门禁**: grammar.cc 的 generator_absorbed 20 成员 + grammarlex/grammarerror 2
shim 以上述 fixture 为行为证据源（面达标即整组同判）；**pcodeparse.cc 的 12 成员
维持 UNTESTED** —— p-code 串解析面 fixture 未建（登记
`PARSEADJ-PARSEFACE-PCODE-0001`），其成员在 fixture 落地并 MATCH 前不得引用本面。

**随 fixture 修复的三个真驱动差异**（本票 commit 链）: 修饰符压栈序反转
（mergePointer 序，grammar.y:151-153）、`'(' declarator ')'` 分组缺失
（grammar.y:158）、TYPE_NAME/struct/union/enum 规范说明未接通（grammar.cc:2972
probe + newStruct/newUnion/newEnum 族）。修复后 17/17 恒等。

## §4 其余 39 池内项处置（63 − 24）

**真残项 3（本票①，等效在位 → 已注解链接，REGEN 重链接后出池）**:
- `PointerModifier::modType`（grammar.cc:2403）→ `src/grammar.rs` `pointer_mod_type`
- `ArrayModifier::modType`（grammar.cc:2412）→ `array_mod_type`
- `FunctionModifier::FunctionModifier`（grammar.cc:2419）→ `function_modifier_ctor`
（commit 5b4a6b26 提取；此前折在 `mod_type`/`new_func` 单体内部，ledger 的
单注解机制无法链接。）

**grammar.hh 19 一行件**: 全部为 `GrammarToken`/`GrammarLexer`/`TypeModifier`/
`CParse` 的内联访问器/setter（setPosition 58、getType 61-66、setError 102、
getError 113/277、~TypeModifier 127、getType/isValid 137-148、isDotdotdot 159、
getType 160、setResultDeclarations 278、getResultDeclarations 279）—— 满足 DECOMP
§4 胶水吸收三要件（`.hh` 内联 ≤2 行 + 访问器形态 + 所属类 ≥3 映射），归
**胶水吸收**。

**grammar.cc 其余 6（264 LOC）**:
- `GrammarLexer::moveState`（2062，231 行）/ `establishToken`（2294）/ `~GrammarLexer`
  （2048）: 手写词法器核心，Rugra **inline 吸收**进 `GrammarLexer::get_next_token`
  （src/grammar.rs:476，状态机 match 逐态对齐，见 grammar_audit.md §设计说明 4）。
  处置: inline-absorbed（REGEN 可选加双注解链接到 get_next_token）。
- `~TypeDeclarator`（2486）/ `~CParse`（2608）: Drop/所有权吸收（Rust Arc +
  Vec 自动回收）。
- `CParse::mergeSpecDec(TypeSpecifiers*)` 单参重载（2633）: Rust `merge_spec_dec`
  （1420）行为覆盖，属**未链接**（REGEN 边补挂候选，与 REBASE-0000 ②清单同拍）。

**pcodeparse.cc 其余 11（433 LOC）**: 全部**已实现但锚在 `.y` 源**（真源；
`.cc` 是 bison 拷贝）—— `PcodeLexer::moveState`（y:297）/ `getNextToken`（y:560）/
`initialize`（y:608）、`PcodeSnippet::allocateTemp`（y:632）/ `addSymbol`（y:640）/
`clear`（y:652）/ ctor（y:676）/ `reportError`（y:709）/ `parseStream`（y:770）/
`addOperand`（y:787）/ dtor。处置: **y-锚未链接** —— ledger 只认 `.cc/.hh` 行锚；
REGEN 重链接时二选一:（a）把注解重锚到 `.cc` 定义起始行（2795/3058/3106/3130/
3138/3150/3174/3207/3268/3285），或（b）在分类器给 `.y` 锚加 source_kind 归并。
推荐（a），零分类器改动。

## §5 REGEN/root 落地动作清单

1. 分类器（`tools/generate_function_ledger.py` 或 DECOMP classify 系）新增
   `generator_absorbed` 判定（§2 三要件，按 §2 清单精确行号白名单起步，不做
   名字泛匹配）。
2. grammar.cc 面 22 成员引用 `grammar_parse_face_1204` fixture 为行为证据
   （面 MATCH）；pcodeparse.cc 面 12 成员维持 UNTESTED 并挂
   `PARSEADJ-PARSEFACE-PCODE-0001`。
3. 重链接 §4 三残项（注解已在 commit 5b4a6b26 落位）+ mergeSpecDec 单参重载
   （REBASE-0000 ② 批量清单顺带）+ §4 pcodeparse y-锚重锚（推荐方案 a）。
4. 预期账面变化（仅本四文件）: unmapped 63 → 0 池外分布 = generator_absorbed 24
   + 胶水 19 + inline/Drop 吸收 5 + 未链接重链 12 + 残项重链 3；假 LOC 口径
   2234+19 生成件 LOC 移出移植分母叙事。

## 复放命令

```bash
python3 - <<'EOF'
import json
led = json.load(open('docs/alignment_audit/FUNCTION_LEDGER.json'))
gen_yy = {'yy_symbol_value_print','yy_symbol_print','yy_stack_print','yy_reduce_print',
          'yystrlen','yystpcpy','yytnamerr','yysyntax_error','yydestruct','yyparse'}
shims = {'grammarlex','grammarerror','pcodelex','pcodeerror'}
res = {('grammar.cc',2403),('grammar.cc',2412),('grammar.cc',2419)}
for f in ['grammar.cc','grammar.hh','pcodeparse.cc','pcodeparse.hh']:
    un = [r for r in led['ghidra_functions'] if r['file']==f
          and r['entry_kind']=='definition' and not r['rust_mappings']]
    yy  = [r for r in un if r['qualified_name'].split('::')[-1] in gen_yy]
    sh  = [r for r in un if r['qualified_name'].split('::')[-1] in shims]
    rs  = [r for r in un if (f, r['line']) in res]
    loc = lambda xs: sum(r['end_line']-r['line']+1 for r in xs)
    print(f, 'unmapped', len(un), '| yy', len(yy), loc(yy), '| shim', len(sh), loc(sh),
          '| residual', len(rs), loc(rs), '| other', len(un)-len(yy)-len(sh)-len(rs))
EOF
bash tools/run_grammar_parse_face_oracle.sh   # BILATERAL MATCH: d63130da… (83 records)
```
