# HEADLESS_BRIDGE_V1_DESIGN — headless 桥接建模 v1:加料通道归因与驱动侧设计

- Lane: BRIDGE1(wt/bridge1,自 master dc70528c)
- 日期: 2026-09-24
- 性质: 归因+设计车道(docs-only,零 src 改动)
- 语料: `tests/golden/ghidra_{curl,httpd}_1204.c`(headless 正典) vs `.direct-runner.c`(库级契约),双 golden 同源锁定 oracle(Ghidra 12.0.4 e40ed130,provenance 在库)
- 实验产物: `/dev/shm/rudra-tests/bridge1/`(parse_golden.py / diff_channels.py / diff_canon.py / diff_hunks.py + 4 份 JSON 结果)
- 结论先行: **未建模加料通道共 8 族,v1 主攻 C1 类型播种(committed local 层)** —— httpd 侧 5824 处 `local_` 引用 / 3173 行 typed 声明,是 direct-runner 完全没有的一整层,且已被 SPALIAS drill 证明单函数 oracle 无法从库内收敛得到。驱动侧等价实现 = golden 收割 manifest + worker 在 action 前向 `ScopeLocal` 播种 typed 符号(镜像 Ghidra `<localdb>` XML 协议,varmap.rs:1950 消费链已在位)。

---

## §0 为什么需要这个设计(三判例的战略前提)

FI 判决(sb-spillpair)已把口径钉死:**Rudra 库级输出 vs direct-runner golden 同形 = 正确终态;与 headless 正典 golden 的残差中,有一整族是"headless 环境输入"而非库缺陷**。DP 判决(sb-pushabsorb)同样明言:canonical 口径要达到"push 消失"必须先建模 headless 桥接输入(参数锁/栈帧/analyzer 传递),属新 lane。SPALIAS drill(VARMAP-SPALIAS-RETYPE-0001)则给出铁证:hermetic 单函数 oracle 与 Rudra 同收敛到 unknown 固定点 ⇒ golden 的 `long local_c8[4]` 种子在**库外**。GC 判例(sb-boollit):golden bool 声明 168 vs 库级 `'\x01'` = Java Data Type Propagation 层。

即:**headless golden = C++ 库 + Java 分析器栈的提交物回灌**。库忠实 ≠ 输出等同;要追平正典,必须把 Java 侧的"加料"在驱动侧等价重建 —— 照 EX2(LAB_)/GA(switchD)/GD2+GJ(coderef)/EP(FS canary) 已验证的"驱动侧加料,库保持纯净"模式。

## §1 两个 golden 的结构性差异(证据边界)

| 维度 | headless 正典 | direct-runner |
|---|---|---|
| 生成 | 单进程 analyzeHeadless:完整 Java 默认分析(loader/PLT/references/demangler/FID/DWARF,无选项覆盖)→ postScript 同 JVM 逐函数反编译(`tools/ghidra_decompile_all.py`,DecompInterface 默认选项) | `golden_dump_1204` fixture:BfdArchitecture + BFD/PLT 符号注册,逐函数 hermetic 进程,完整 universal action(FIXTURE_CPP,regen_ghidra_golden.py:153-402) |
| 函数集 | curl 124 / httpd 2010 | curl 74 / httpd 790(差集=analyzer 发现+plt.sec thunks) |
| 地址基 | 0x100000 | 0(PIE VMA) |
| provenance | `direct_runner_cross_check.equivalence_risks` 明列 6 条通道级差异(analyzer 栈/DWARF 原型/thunk 发现/名字剥离/导入符号/跨函数状态) | 同左 |

双 golden 即现成的差分对:**凡 headless 有而 direct-runner 无的形态,按定义是 headless-only 加料**(FI 判例口径);再用 curl(带 DWARF)vs httpd(stripped)对照区分 DWARF 源与 analyzer 源。

## §2 加料通道清单(量化 + 归因 + 现状)

量化口径:diff 为函数块级配对(74/790 对齐函数),hunk=SequenceMatcher 差异块(变量名归一后);grep 行数为全文件口径。`H`=headless 正典侧,`D`=direct-runner 侧。

| # | 通道 | curl 量化 | httpd 量化 | 归因(golden 知道什么/从哪知道) | 驱动桥现状 |
|---|---|---|---|---|---|
| C1 | **TYPE-SEED-LOCAL**(committed `local_*` 符号+类型层) | `local_` 引用 117,typed 声明 140 vs D undefined 326 | **`local_` 引用 5824(D=0),typed 声明 3173 vs D 4468**;TYPE-SEED hunk 316 | **【§19 消融改判】Java 分析器提交环 = "Stack" 分析器(StackVariableAnalyzer,建栈符号+local_ 偏移名,namelock=true/typelock=false/undefined 型)**,非 Decompiler Parameter ID(ELF 默认关)。证据:①httpd stripped 无 DWARF 仍有 typed locals ⇒ 非 DWARF;②SPALIAS drill:hermetic oracle 收敛 unknown ⇒ 库外种子;③`local_` 名 C++ 全树零生成点 ⇒ 名字来自 Java DB(SymbolUtilities.getDefaultLocalName);④消融:Stack 关→local_ 5824→0/117→0,Parameter ID 强开→偏离 canon(461 函数);⑤live `<localdb>`:local_* 全部 typelock=false(§19.4) | ❌ 未建模(SPALIAS/GC/FI/DP 四判例残差的上游总根) |
| C2 | **THUNK-GOT**(GOT 槽 `PTR_x` 符号化 + thunk 标记 + 导入函数签名) | PTR_ 50 vs pcRam 313;THUNK-PAIR hunk 73;locked-storage 警告 51(D=0);D jumptable 警告 46(H=0) | PTR_ 372 vs pcRam 1659;THUNK-PAIR hunk 495;locked 警告 124;D jumptable 警告 431 | headless ELF loader+分析器:建 GOT 引用符号(`PTR_<extname>_<addr>`、`code*` 型)、把 PLT/plt.sec 标记为 thunk(免 jumptable 恢复)、对导入函数套用库签名(锁定参数存储)。**【§19 消融改判】签名源="Apply Data Archives" 分析器(generic_clib_64 归档,ApplyFunctionDataTypesCmd)而非 FID**(FID 关=0 函数变化;archive 关=locked-warn 51→3/124→0,fopen 等导入失锁;live XML:sigaction 导入带 typelock 参数符号) **✅(curl=CURB/MAINDIFF/CALLSPEC + httpd=THUNKGOT §17.9):GOT PTR_(GLOB_DAT+JUMP_SLOT)+thunk 通道(FlowOverride.CALL_RETURN 传输/只读救援)+thunk 自身签名锁** |
| C3 | **SIG-LOCK 实函数**(原型锁定+参数名) | SIG hunk 22 + PARAM-NAME 26;`__x` 参数名 263 vs 72 | SIG hunk 418 + PARAM-NAME 146;`__x` 1562 vs 332 | curl=DWARF 函数原型(argc/argv/__stream/urls);httpd=analyzer 签名(FID/Parameter ID 提交)。与 C1 同机制不同载体(`<prototype>` 锁,fspec) | 部分:DWARF 自身+callsite 锁、24 libc 已桥(CALLSPEC-ENV-SCOPE-0001/GL);**导入面与 golden-harvest 面 ❌** || C4 | **STRUCT-FIELD**(DWARF 组合类型下的字段步进) | STRUCT-FIELD hunk 33 + GLOBAL-SYM hunk 119(`::config`/`outs.stream`/`stdin` 等 typed 全局) | STRUCT-FIELD hunk 26(归因开放:stripped 下疑 FID 套型) | curl=DWARF composite(Configurable/URLGlob/FILE);全局符号带类型 | 部分:TYPEDEF_PREAMBLE 文本级 hack(:4845);真组合类型 ❌ |
| C5 | STRSYM(字符串字面量实参) | H 43 vs D 0 | H 1681 vs D 10 | Java string/reference 分析器在 .rodata 建字符串数据 | ✅ 已桥(driver 字符串通道) |
| C6 | BOOL-LIT 残余(Data Type Propagation 族) | true/false 34 vs 18 | 499 vs 289 | GC 判例:Java Data Type Propagation 把 bool 语义播种到库级 char。**【§19 消融改判】"Data Type Propagation" 分析器在 12.0.4 不存在**(全树 NAME 盘点);curl 侧 bool 源=DWARF 导入器 char→bool 重映射(DWARF 关:34→7;capture 日志"DWARF data type remappings /char -> /bool";live:errorbuffer=typelocked bool[256]);httpd 侧 bool 对 Stack/FID/archive 消融全不敏感(499 恒定)=反编译器自身恢复,H499-vs-D289 差额属环境差(被调原型可得性),非 analyzer 播种通道 | 部分:DWARF typedef-bool 已修(boollit);**残余=库级恢复域 ❌** |
| C7 | NAME-NORM(GCC 后缀剥离) | H 后缀引用 0 vs D 10(`.constprop.0` 等) | 0/0 | headless demangler/分析器剥离 `.constprop/.isra/.cold` | ❌(小) |
| C8 | FUNC-DISC(函数发现) | H-only 50(1×FUN_ + 49×plt.sec) | H-only 1220(464 FUN_ + 756 named) | analyzer 发现无符号代码 + plt.sec 注册 | 部分:124-fn ledger 钉住门禁面;无需库侧桥 |
| C9 | PUSH-ABSORB | D 固定槽 push 29 行 | D 309 行 | DP 判例:headless 桥接层输入吸收;**预计随 C1/C3 落地自然收敛** | ❌(不单独建,跟踪 C1 效果) |
| C10 | SPILL-PAIR | D 19 行 | D 271 行 | FI 判例:**库级非缺陷**;headless 由 Java 分析器栈改变 merge/type-lock 输入所致,预计随 C1 落地观察 | 不单独建(FI 终局口径) |
| C11 | LABELS(LAB_/code_r) | H LAB_ 85 / D code_r 122 | H 2910 / D 1617 | Java DB 提供标号名 | ✅ EX2 |
| C12 | switchD 命名 | — | — | 同上 | ✅ GA/SMALLFIX |

已桥通道(C5/C11/C12 + C2 部分 + C3 部分)证明模式可行;**未建模主缺口 = C1(最大行质量)→ C2 → C3 → C4 → C6/C7(尾差)**。

## §3 通道归因的证据链(按 B2 口径)

每个通道的归因强度分三级:

1. **机制级(C++ 源码,锁定 oracle)** —— C1 的库内消费链已逐行核实:
   - `Funcdata::decode`(funcdata.cc:775-837):`<function>` 子元素 `<localdb>`(预填符号的 ScopeLocal)/`<override>`/`<prototype>`(锁定原型)/`<jumptablelist>`(预计算跳转表)—— **这就是 Java DecompInterface 与 C++ 库的全部接口**,驱动侧桥等价于在 Rust 侧重建同一协议的注入端。
   - `MapState::gatherSymbols`(varmap.cc:1044-1059):DB 符号以 `RangeHint::fixed` + typelock 进 restructure;Rudra 侧 varmap.rs:1950-1964 已逐行对应(本 lane 复核)。**播种 API 已在库内,缺的只是驱动侧喂数据。**
2. **差分级(双 golden)** —— §2 量化全部来自同源双 golden 对比;`local_` 0 vs 5824(direct vs headless)是 C1 存在性的直接观测。
3. **消融级(analyzer 开关)** —— **已完成（Lane HEADLESSDIST，2026-09-27，§19）**：headless dist 重建（官方发行版 zip，revision 逐字=锁定 commit，双 golden 字节复现）后跑受控重导入消融，C1/C6/C2 的 analyzer 级归因已由消融证据**改判**（原"最可能假设"三条全部被部分或全部证伪，修正结论见 §2 表内标注与 §19.3）：C1 的 `local_` 层来源=**"Stack" 分析器**（非 Decompiler Parameter ID——后者对 ELF 默认关闭）；C2 锁定警告/导入签名来源=**"Apply Data Archives"（generic_clib_64）**（非 FID——dist 无 FID 库且开关不敏感）；C6 的 curl 侧 bool 来源=**DWARF 导入器的 char→bool 重映射**（"Data Type Propagation" 分析器在 12.0.4 不存在）。

## §4 驱动侧通道设计(GD2/GJ 模式:数据从哪来/怎么注入/何时注入/怎么验证)

总原则(已验证先例的公共形态):**控制器(canon 模式)持有加料数据 → `DecompileRequest` 协议字段 → worker 在明确生命周期点安装 → mirror/bare 模式不加载(库级契约保持纯净)→ per-fn 差分门禁验收**。

### C1 TYPE-SEED-LOCAL(v1 主攻,详规见 §5)
- 数据从哪来: **golden 收割 manifest**(捕获侧,同 124-fn ledger 先例)—— 从 headless golden 的声明层收割每函数 committed locals(名字内嵌偏移 `local_c8`→-0xc8,类型串)。
- 怎么注入: worker 在 fd 构建后、`perform_action("decompile")` 前,经 `ScopeLocal::add_symbol_with_property`(varmap.rs:4041)安装 `(stack offset, name, type, typelock)`,类型经 `parse_c_type`(debugproto.rs,GL 已建,走 shared_default 工厂)。这是 **action 期种子**(区别于 GD2 的 print 期 DB):gather_symbols 在 NameVars/restructure 中段消费。
- 何时注入: action 前,一次性;镜像模式(投影/RUDRA_MIRROR)与 bare-load 不注入。
- 怎么验证: §5.5。

### C2 THUNK-GOT
- 数据: manifest 的导入函数签名表(name→proto)+ GOT 槽→`PTR_<name>_<addr>` 规则(.rela.plt 已有解析器,FIXTURE_CPP registerPltStubs 同源逻辑搬到 Rust 控制器——driver 已有 GOT PTR_ 标签半桥)。
- 注入: ①thunk 函数集:对 ledger 外的 PLT/plt.sec 条目按 `<prototype>` 锁等价路径锁 `funcp`(复用 C3 的 sig 安装);②thunk 标记→抑制 jumptable 恢复尝试:driver 侧对该地址集传 `jumptablelist` 等价物(空表+thunk flag)——若库侧无对应 seam 则登记 Rudra-GAP 评估最小接入点(预期在 flow/jumptable 查询入口加 DB 查询,属既有 `ACTION-SYMDB-DATASYM-0001` 同族)。
- 验证: httpd 431 条 jumptable 警告→0;`PTR_` 372 全量符号化;per-fn 恒等校验。

### C3 SIG-LOCK 实函数
- 数据: golden 签名层收割(参数名/型/返回型 per fn);与现有 DWARF/libc 锁合流(已锁不动,未锁用 manifest 补)。
- 注入: 复用 `link_call_specs` 的 locked_proto 构建器(CALLSPEC-ENV-SCOPE-0001 资产),扩为 self-sig manifest 源。
- 验证: SIG/PARAM-NAME hunk 归零路径上的 per-fn 下降;`__x` 参数名计数对齐。

### C4 STRUCT-FIELD
- 数据: curl=DWARF composite(debugproto 已有 DWARF 类型通道,需组合类型 struct/field 语法扩展);httpd=FID 套型表(归因未钉死,先 curl)。
- 注入: 类型工厂注册真组合类型,替换 TYPEDEF_PREAMBLE 文本 hack;全局符号带类型(driver 全局图已有 DWARF-typed 半桥,补 composite)。
- 验证: STRUCT-FIELD/GLOBAL-SYM hunk 收敛;gcc 审计 URLGlob 族 FAIL 减少。

### C6/C7 尾差
- C6 BOOL-DTP:随 C1 类型播种大概率一并覆盖(bool 型在 manifest 内);残差单测。
- C7 NAME-NORM:控制器符号表剥离 GCC 后缀(1 行级映射, golden 对照 `parseconfig.constprop.0→parseconfig`)。

## §5 v1 规格 —— C1 类型播种(可实施)

### 5.1 数据产物: `tests/golden/manifests/local_seed_httpd_1204.json`(及 curl 版)
```json
{
  "oracle_commit": "e40ed13014025f82488b1f8f7bca566894ac376b",
  "corpus": "httpd", "golden_sha256": "<文件哈希>",
  "harvest_rule": "decl-block lines matching '^\\s*(type)\\s+(local_[0-9a-f]+)(\\s*\\[\\d+\\])?;' before first statement; offset = -int(name[6:],16)",
  "functions": {
    "0x2ba90": { "name": "main", "locals": [
      {"offset": -0xd8, "name": "local_d8", "type": "long",  "typelock": true},
      {"offset": -0xd0, "name": "local_d0", "type": "long",  "typelock": true},
      {"offset": -0xc8, "name": "local_c8", "type": "long[4]", "typelock": true},
      {"offset": -0xa8, "name": "local_a8", "type": "undefined8 *", "typelock": true}
    ]}
  }
}
```
收割器 `tools/harvest_local_manifest.py`:解析 golden 函数块 → 首语句前声明块 → 正则取 `(type,name,array)`;只收 `local_[0-9a-f]+`(偏移内嵌,保守域);manifest 记录 oracle commit + golden sha256(机制 B2 口径)。**含 undefined-typed 的 committed locals 一并收割**(它们改变 restructure 分区与命名 auStack_→local_,是提交层的一部分);若 W1 门禁显示 undefined-typed 种子在 curl 引发回归,降级为 typed-only 子 manifest(决策门在验收内)。

### 5.2 协议: `DecompileRequest` 增 `committed_locals: Vec<CommittedLocal>`(`{offset: i64, name: String, type_expr: String}`)
canon 模式控制器从 manifest 装载(按 vaddr 匹配);mirror/bare 模式恒空。worker 协议版本号同步 bump(GJ 先例 v3→v4)。

### 5.3 worker 注入点(唯一 seam)
fd 构建完成(含现有 DWARF/模型锁)之后、`db.perform_action("decompile", &mut fd_write)`(curl_decompile.rs:4057)之前:
1. `parse_c_type` 逐条解析 `type_expr`(走 shared_default 工厂——GL 判例:类型身份域必须单一);
2. `fd.scope.add_symbol_with_property(stack 空间 offset, name, type, typelock=true)`(varmap.rs:4041;对应 C++ `decodeScope` 恢复的 symbol 随 `<localdb>` 入库);
3. 不触碰 funcp/寄存器参数(register 参数归 C3 域)。

库侧预期零改动:`gather_symbols`(varmap.rs:1950)与 restructure 消费链已对应 varmap.cc:1044/1260。若发现 Rust `add_symbol_with_property` 无法表达 EntryMap 预填(maptable 物化路径),允许 varmap.rs 最小 GLUE 补口(须 `// RUDRA-GLUE` 注释 + 机制 C 复核——varmap 是白名单模块)。

### 5.4 明确不做(边界)
- 不改 restructure/merge/type-lock 算法本体(SPALIAS 两 TODO 的"库内自举"路线让位于本桥:种子在库外,库保持与 direct-runner 契约)。
- 不播种寄存器参数/unaff_/extraout_(归 C3)。
- mirror 投影与五投影 bundle 必须字节恒等(不加载 manifest)。

### 5.5 验收门禁(v1)
1. **镜像纯净性**: RUDRA_MIRROR=1 五投影(next_url/match_url/parseconfig/getparameter/myprogress)字节恒等(MATCH×5 保持)。
2. **SPALIAS 定点**: httpd main 出现 `long local_c8 [4];` + `long local_d0; long local_d8;` 声明与 `plVar = local_c8` 直接符号形(SP 族 40 行残差显降,目标 ≤ 个位数;绑定 VARMAP-SPALIAS-RETYPE-0001 验收)。
3. **E2E**: curl/httpd 差分 defects=0/numbering=0 保持,skeleton 下降(httpd 预期 −500 以上量级:5824 引用层的声明/形态收敛),per-fn 零回退(允许改善)。
4. **确定性**: 双跑 byte-identical。
5. **机制 B2**: harvest manifest 内函数逐个与 golden decl 层 fixture 对拍(收割器自校验);Rudra seeded-run vs golden 块:decl 层目标 MATCH,body 层差异如实登记(归后续 C2/C3)。
6. gcc 审计 fail 集不新增。

### 5.6 风险与开放项
- **风险 R1**: committed locals 与 DWARF 自原型锁(param 溢出槽)的窗口重叠 → 验收 3 的 per-fn 门禁捕捉;必要时 manifest 收割时排除 param 槽区间(funcp local window 已有范围)。
- **风险 R2**: undefined-typed 种子引发 curl 回归 → §5.1 决策门(typed-only 降级)。
- **风险 R3**: analyzer 级归因 ~~未终局(W0 消融缺 headless dist)~~ **已由 W0 消融终局(§19.3:C1=Stack 分析器,manifest 语义仍是捕获侧真值)**;C6 已改判为非独立 analyzer 通道(§2 表 C6 标注)。
- **开放 O1**: httpd STRUCT-FIELD(26 hunk)在 stripped 下的类型来源(~~疑 FID 套型?~~ **已钉死:generic_clib_64 数据归档经 "Apply Data Archives" 分析器套型,非 FID——§19.3 O1 行**)。

## §6 分波排期

| 波 | 内容 | 前置 | 预期主收益 |
|---|---|---|---|
| **W0**(✅ 已交付 2026-09-27,§19) | HEADLESS-BRIDGE-ATTRIB-0004:重建 headless dist;analyzer 开关消融重导入 curl+httpd,钉 C1/C6/C2 analyzer 归因;抓 `<localdb>` XML 真值交叉验证 manifest | 无(纯捕获侧) | 归因 NO_ORACLE→消融证据(三条假设改判:Stack/Apply Data Archives/DWARF);manifest 交叉验证完成 |
| **W1(v1 核心)** | HEADLESS-BRIDGE-V1-TYPESEED-0001:harvester + manifest + 协议字段 + worker 播种 + §5.5 全门禁;httpd 先行(最大行质量+SPALIAS 既有判决) | 无(不依赖 W0) | httpd `local_` 层 5824 引用建模;SPALIAS 定点;C9/C10 观察 |
| W1b | curl roll-in(117 引用 + DWARF 名局部 `urls/urlnum` 同机制;含 NAME-NORM 顺带 3 hunk) | W1 | curl C1+C7 |
| W2 | C2 THUNK-GOT(导入签名 manifest + thunk 标记/警告抑制) | W1(复用 manifest 框架) | httpd 431 jumptable 警告→0;THUNK-PAIR 495 hunk |
| W3 | C3 SIG-LOCK 补全(real-fn 签名 manifest 合流 link_call_specs) | W1 | SIG 418 + PARAM-NAME 146 hunk(httpd) |
| W4 | C4 组合类型(替换 TYPEDEF_PREAMBLE hack)+ C6 残余 + O1 归因 | W0 | STRUCT-FIELD/GLOBAL-SYM hunk;gcc 审计 |

v1 交付判据 = W1(+W1b)全绿;每波独立 commit、独立 per-fn 零回退证明。

## §7 与既有登记的关系

- `VARMAP-SPALIAS-RETYPE-0001`:v1 验收直接绑定其验收点(`long local_c8[4]` 等);**路线变更**:库内自举(STORE 值反压/多轮往返)→ 驱动播种(种子已证在库外,SPALIAS drill)。lane GK 移交注记保留。
- `RULEACTION-SPALIAS-INDIRECTPTR-0002`:独立(INDIRECT 传型链),不随 v1 收口,维持排队。
- `MERGE-COPYNOISE-SPILLRESTORE-0001`(FI 终局)/`GOLDEN-CONTRACT-PUSHABSORB-0001`(DP):C10/C9 的观察哨——W1 落地后重测 spill 对/push 行是否随之收敛,并在各自 TODO 行回写结论。
- `ACTION-SYMDB-DATASYM-0001`(SMALLFIX ③):C2 的 jumptable/thunk DB 查询接入点同族,W2 时合并考量。

## §8 复现实验(本 lane 产物留档)

```bash
# 通道量化(全部产物在 /dev/shm/rudra-tests/bridge1/)
python3 /dev/shm/rudra-tests/bridge1/parse_golden.py tests/golden/ghidra_curl_1204.c tests/golden/ghidra_curl_1204.direct-runner.c 0x100000
python3 /dev/shm/rudra-tests/bridge1/diff_hunks.py tests/golden/ghidra_httpd_1204.c tests/golden/ghidra_httpd_1204.direct-runner.c 0x100000 /tmp/httpd_hunks.json
# 机制源码锚点:funcdata.cc:775-837(<function> 协议) / varmap.cc:1044-1059(gatherSymbols) / varmap.rs:1950,4024,4041(Rust 消费+播种 API)
# grep 口径行数:local_/PTR_/pcRam/LAB_/code_r/jumptable warn/locked warn/.constprop(见 §2 表)
```

---

## §9 W1 交付记录（Lane BRIDGE1，2026-09-25，基=亲父 b255cce9）

### 9.1 步骤① 通道内容 oracle 判定：**证实**

仪器化方法（复用 RANGEHINT lane 的 git-archive 锁定库构建链）：新增
`stage_seed_diag.cc`（/dev/shm/rudra-tests/bridge1/，构建=build_seed_diag.sh）——
BfdArchitecture 裸加载 + 在 fd 解析后、followFlow 前把种子 XML 喂给
`fd->getScopeLocal()->decode(decoder)`（**真实 `<localdb>` 协议链**：
ScopeInternal::decode → Scope::addMapSym → Symbol::decodeHeader(typelock/
namelock) + decodeType + SymbolEntry::decode(`<addr>`+`<rangelist>）→ addMap），
然后按 golden 生成器契约驱动 + PrintC docFunction。

锁定 oracle 库 + httpd main 种子（§5.1 收割清单）输出
（/dev/shm/rudra-tests/bridge1/oracle_main_seeded.c）：

- **声明层逐符号复现 canon**：`long local_d8; long local_d0; long[4] local_c8;
  undefined8 *local_a8; undefined8[2] local_80; long[6] local_70; undefined8
  local_40` + 未提交块 `axStack_9c [7]`——92B hermetic 整块被种子切成
  28B+16B+48B，分区与 canon 一致（RANGEHINT 判定的"1B 反馈环"被 fixed
  typelock hint 打破）。
- **下标形族复现**：133 处 `plVar11[-N] =`（canon main 134 处；
  hermetic 库为 0——`*(xunknown8*)((int8)p + -8)` 形）。
- **证伪边界**：canon 的 15 处 `local_d0 = <retaddr>;` 直接赋值拼写连
  seeded-oracle 也不产生（打印为 `plVar11[-1] = <retaddr>`，同一存储的
  别名指针形）⇒ 该族需要种子之外的 headless 状态，**超出 C1 v1 范围**，归
  HEAD 残差（W0 消融已跑：原归因候选"Parameter ID 早轮 IR/别名挂接差异"
  被排除——Parameter ID 对 ELF 默认关、canon 从未运行，强开反而 461 函数
  偏离 canon[HEADLESSDIST 终报 §2 r1/r1b]；真源未钉死，候选域=Stack 符号+
  归档锁输入下的恢复环境差，见 §16.1.1）。

### 9.2 as-built 与 §5.2/5.3 的偏差（按实测修正）

- 种子载体：`Funcdata::committed_locals: Vec<CommittedLocal>`
  （funcdata.rs，RUDRA-GLUE）而非 `DecompileRequest` 协议字段——httpd
  驱动是单进程线程模型，无 worker 协议可 bump；fd 字段即
  `<localdb>` 载体的 Rust 形态。
- 注入点：`ActionRestructureVarnode::apply` 的 scope 首次构造臂
  （coreaction.rs，平台参数符号安装之后）而非"驱动在 perform 前
  ScopeLocal::add_symbol"——Rudra 的 ScopeLocal 是首个 restructure
  pass 才惰性构造的（fd.scope=None），None 臂构造点正是 oracle
  "Funcdata 构造 → localdb decode → action" 生命周期的镜像位。
  类型解析走 `parse_c_type`（debugproto.rs，扩展数组声明符+C1 基
  类型表，shared_default 工厂保持类型身份域单一）。
- opt-in 门：`RUDRA_TYPESEED=1`（`RUDRA_TYPESEED_MANIFEST` 可覆写路径，
  默认 `tests/golden/manifests/local_seed_httpd_1204.json`，按
  vaddr+0x100000=canon 地址匹配）；mirror 门下恒不装载（五投影纯净
  性）。默认路径 committed_locals 恒空 ⇒ 输出与亲父 cmp 字节恒等。
- 附带修复：prettyprint 声明回填 pass 现在识别后缀数组声明符
  （`long local_c8 [4];` 旧实现在 declared 集里记下 `[4]` 而非
  `local_c8`，回填注入了 `int local_c8;` 重复声明）。
- v1 域收缩：收割器跳过结构体基类型种子（sigaction/sigset_t 各 1，
  C4 组合类型域）；curl 侧 W1b 未并入（curl golden 局部名以 DWARF
  语义名为主，local_ 保守域只收 4 函数/18 条，收益小，留 W1b 专项）。

### 9.3 W1 验收（亲测，基=亲父 b255cce9）

| 门禁 | 默认（无 env） | opt-in（RUDRA_TYPESEED=1） |
|---|---|---|
| httpd E2E canon | **1472/0/0**，cmp 亲父字节恒等 | **1360/0/0**（−112） |
| curl E2E canon | **1099/0/0**（=亲父） | n/a（httpd manifest） |
| 五投影银行 | **26/26 MATCH** | mirror 门恒不装载 |
| cargo test --lib | 1709P/1F（预存 VHOST） | 同 |
| 双跑确定性 | cmp 恒等 | cmp 恒等 |

逐函数（6 个被播种函数全部改善、0 回退）：main 694→668；
ap_parse_vhost_addrs 27→9；ap_fini_vhost_config 245→218；
ap_update_vhost_from_headers 92→71；ap_ht_time 17→13；
ap_os_is_path_absolute 23→7。

main 族前后（vs canon）：local_* 引用 0→11（canon 44；**seeded-oracle
同为 11**——C1 域内 Rudra==oracle）；auStack/uStack 命名 11→3（canon 4；
oracle-seeded 同 3）；下标形 119（canon 116，oracle-seeded 133——差 14
为既有库级 typeprop 域，非 C1 引入）；字符串族 0（canon 81）不动——
C5-邻域，非 C1 目标。SPALIAS 定点（§5.5-2）：`long local_c8 [4]`/
`local_d0`/`local_d8` 声明全量出现 ✓；`plVar = local_c8` 直接符号形 ✓
（canon 的 `local_d0 = retaddr` 15 处拼写族按 §9.1 证伪边界豁免）。

## §10 W1b 交付记录（Lane W1B，2026-09-25，基=亲父 1de6dd39=master TYPEFIX 后）

curl 语料卷入：manifest 入库 + curl 驱动 opt-in 门，**零 src/ 改动**
（BRIDGE1+TYPEFIX 后库侧通道在位，本波纯驱动/数据域）。

### 10.1 manifest（`tests/golden/manifests/local_seed_curl_1204.json`）

- harvest：BRIDGE1 方法原样（`tools/harvest_local_manifest.py` over
  `tests/golden/ghidra_curl_1204.c`，oracle commit e40ed130 + golden
  sha256 指纹齐备）——**3 函数 / 16 种子**：main 1（`int local_230`）、
  helpf 13（`undefined1 local_b8[8]` + 12×`undefined8 local_*`）、
  parseconfig 1（`char *local_160`）。
- KNOWN_BASES 剔除生效：getparameter 的 `Configurable *local_5b8` /
  `HttpPost *local_5a8`（结构体指针基，post-TYPEFIX parse_c_type
  no-fallback bail ⇒ 若入库即为死条目，harvest 同逻辑剔除）；golden
  内 18 个 distinct local_ 名全部归账（16 收 + 2 剔）。
- 域边界（与 §9.2 一致）：curl golden 的具名 local 以 DWARF 语义名为主
  （urlnum/urls/outs/heads/usedarg/filebuffer/ap(va_list) 等），名字不
  内嵌偏移 ⇒ 保守 local_ 域不收（DWARF-named 扩展 = 独立后续 lane，
  需 .debug_loc 位置表 fbreg→stack 偏移换算 + W0 `<localdb>` XML 交叉
  验证；getparameter 结构指针基依赖 C4 组合类型通道）。

### 10.2 驱动接线（`examples/curl_decompile.rs`，镜像 httpd 侧门）

- `RUDRA_TYPESEED=1`（`RUDRA_TYPESEED_MANIFEST` 覆写路径，默认
  `tests/golden/manifests/local_seed_curl_1204.json`）→ worker 进程
  `decompile_request` 在 fd 构建后、perform_action 前把 canon 地址键
  （vaddr+0x100000）的种子挂到 `fd.committed_locals`（`<localdb>`
  transport 位；worker 子进程继承控制器 env ⇒ 同门；原型 pre-pass
  永不播种——镜像 httpd 只在反编译线程播种的边界）。
- OnceLock 每进程一次装载；**默认路径构造性恒等**：env 未设 →
  无 manifest IO、committed_locals 恒空，亲父 cmp 字节恒等（实测）。
- 镜像门恒不装载：任一 mirror 分量（RUDRA_MIRROR/RUDRA_FLOW_MIRROR/
  RUDRA_BARE_LOAD/RUDRA_ORACLE_FIXTURE_DATA）在场即拒绝并告警；
  实测 RUDRA_MIRROR=1+TYPESEED=1 输出与纯 mirror 运行 cmp 恒等。

### 10.3 W1b 验收（亲测，基=亲父 1de6dd39）

| 门禁 | 默认（无 env） | opt-in（RUDRA_TYPESEED=1） |
|---|---|---|
| curl E2E canon | **1099/0/0**，cmp 亲父字节恒等 | **1054/0/0**（−45） |
| httpd E2E canon | **1472/0/0**（=亲父，例程未触碰） | **1360/0/0**（=BRIDGE1 见证复现） |
| 投影银行 | —（frozen 钉） | mirror 门恒不装载 |
| gcc 审计 | 103 OK/21 FAIL | fail 集逐名相同（零新增） |
| 双跑确定性 | cmp 恒等 | cmp 恒等 |

逐函数（全部改善、0 回退；121 个未播种函数字节恒等）：main 212→206、
helpf 75→50、parseconfig 73→59。播种函数零回退硬门 ✓。

−45 vs 目标 −50 的差额归因（域内无可收余量）：helpf 余 50 =
va_list ap typedef 族（DWARF-named 域）+ 寄存器溢出赋值吸收族
（库级 typeprop 域，与 §9.3 下标形残差同族）+ `&stack0x8` 拼写；
parseconfig 余 59 = usedarg/filebuffer（DWARF-named bool）+ 临时编号
偏移 + 字符串常量形（C5-邻域）；main 余 206 = urlnum/urls/outs/heads/
progressbar/fileinfo/errorbuffer（DWARF-named/结构体域）。

## §11 C2DWARF 交付记录（Lane C2DWARF，2026-09-25，基=亲父 36d5efb6）

W1b 差额归因指认的 DWARF-named 域（curl −45 的余额大头）落成：C1 通道的
DWARF 语义名扩展（名字来自 .debug_info，位置来自 inline DW_OP_fbreg，
经 `<localdb>` 种子运输）。**零 src/ 改动**（机制 C 工具/驱动域豁免：
tools/harvest_local_manifest.py 扩展 + manifest + examples 门）。

### 11.1 oracle 级预验证（先行，BRIDGE1 方法论照做）

仪器化：`stage_seed_diag`（锁定库 e40ed130，真 `<localdb>` decode 链）+
pyelftools 全量 DWARF 盘点（/dev/shm/rudra-tests/c2dwarf/，21 条
exprloc-fbreg 条目/9 函数）→ 按规则构造种子 XML → 逐函数 seeded/unseeded
对照 canon：

- **声明层逐名复现**：6 函数全部命中——main `int urlnum; bool[256]
  errorbuffer`、myprogress `char[40] format; bool[256] line; bool[256]
  outline`、my_get_line `bool[4096] buf`、file2string `bool[256] buffer`、
  parseconfig `bool usedarg; bool[256] filebuffer`、getparameter
  `time_t now`；下标形/`== true` 体形态同步复现。
- **fbreg→偏移换算钉死**：offset = fbreg(N)+8（frame_base=
  call_frame_cfa=CFA=RSP_entry+8，Ghidra stack 0=RSP_entry 槽）；机码级
  校准 urlnum fbreg(-0x22c)→`cmpl 0x34(%rsp)`→-0x224、errorbuffer
  fbreg(-0x150)→`lea 0x110(%rsp)`。
- **canon-committed typing 判决**：DWARF 说 char[256]/[4096]，canon 打印
  bool——char 种子（--dwarf-raw-types 形态）不匹配 canon decl，bool 种子
  匹配 ⇒ Java 分析器提交层把 boolean 用途的 char 数组重定型为 bool
  （C6 DTP 族交叠），manifest 取 canon-committed 形态。
- **sec_offset 域判决**：canon 从不为 loc-list 变量命名（main 的
  i/res/url/infd/... 全部无名）⇒ Ghidra DWARF importer 丢弃 loc-list，
  harvest 同域排除（防 over-seed）。
- **邻接吸收判决（file2string）**：仅 seed `buffer bool[256]` 时锁定
  oracle 也产出 `bool abStack_150[8]`（数组吸收未提交邻槽）——canon 保持
  `undefined8 uStack_150` 独立 ⇒ canon 的提交层含该合成槽（C1 无名提交）；
  buffer+uStack_150 双种子下 oracle 复现 canon 分区 ⇒ harvest 增加
  canon-decl 邻接采纳规则（source=canon-decl 标注）。
- **槽主规则**：main -504 槽首声明 progressbar（struct，C4 残差）⇒
  passarg（bool，后声明）canon 从不打印 ⇒ 首声明拥有槽，不可服务首声明
  连带遮蔽后续同槽可服务者。

### 11.2 manifest 与装载

- `tests/golden/manifests/local_seed_curl_1204_dwarf.json`：6 函数/11 种子
  （10 DWARF + 1 canon-decl 邻接守卫 uStack_150）+10 drops 全归账；指纹
  齐备（oracle e40ed130 + binary sha256 + golden sha256 aca37988 实测
  复核）；harvest_rule 全规则留档。
- `examples/curl_decompile.rs`：`RUDRA_DWARFSEED=1`（+
  `RUDRA_DWARFSEED_MANIFEST` 覆写，默认上述路径）独立门——与 W1b
  `RUDRA_TYPESEED` 门共享 `load_committed_local_manifest` 解码器但 env
  独立 ⇒ **TYPESEED=1 单开保持 W1b 见证字节恒等**（归因可分）；attach
  在 TYPESEED 之后 extend committed_locals（偏移碰撞 = manifest 缺陷，
  响亮告警）；mirror 四分量在场恒拒载（实测 RUDRA_MIRROR+双门输出与纯
  mirror cmp 恒等）；默认路径构造性恒等（无 manifest IO）。

### 11.3 C2DWARF 验收（亲测，基=亲父 36d5efb6）

| 门禁 | 默认（无 env） | TYPESEED=1 | TYPESEED=1+DWARFSEED=1 |
|---|---|---|---|
| curl E2E canon | **1099/0/0**，cmp 亲父字节恒等 | **1054/0/0**，cmp 亲父字节恒等（W1b 见证保持） | **944/0/0**（−110） |
| 投影银行 | 71/71 PASS（离线，frozen） | mirror 门恒闭 | mirror 门恒闭（实测拒载） |
| gcc 审计 | 103 OK/21 FAIL（=亲父） | 同 | **104 OK/20 FAIL**（my_get_line 修复，零新增） |
| 双跑确定性 | cmp 恒等 | cmp 恒等 | cmp 恒等 |

逐函数（TYPESEED→双门，**0 回退**硬门 ✓；118 未播种函数字节恒等）：
main 206→186、myprogress 33→15、my_get_line 30→16（gcc FAIL 同步修复）、
file2string 76→39（邻接守卫）、parseconfig 59→39、getparameter 385→384、
helpf 50→50（未触碰）。

### 11.4 残差登记（不可经本通道复现 → HEAD/C3/C4 域）

main `URLGlob *urls`（C4 pointee）/`OutStruct outs,heads`/`ProgressData
progressbar`（+passarg 槽遮蔽）/`stat fileinfo`/canon-only `URLGlob glob`
（inlined glob_url 参数，C3+C4）；helpf `va_list ap`（typedef→struct，C4）；
getparameter `stat statbuf`/`LongShort aliases[50]`（C4）；match_url
`URLGlob glob`（栈参数，C3）；全部 sec_offset loc-list 变量（Ghidra 自身
丢弃）。C4 组合类型（V4-W4）与 C3 签名锁（V3-W3）是这些残差的归属通道。

## §12 C3NEXT 交付记录（Lane C3NEXT，2026-09-25，基=亲父 5fff5592）

通道选择判决：§11.4 的 11 个不可复现族中 **8 个属 C4**（urls/outs/heads/
progressbar+passarg/fileinfo/ap/statbuf/aliases + canon-decl local_5b8/
local_5a8），仅 glob×2 属 C3；且 getparameter 384 与 main 186 残差主体为
结构体声明层+字段形族。**选 C4 STRUCT-SEED**。写域=tools/harvest_local_
manifest.py（--struct 模式）+tests/golden/manifests/local_seed_curl_1204_
struct.json+examples/curl_decompile.rs（RUDRA_STRUCTSEED 门，镜像 C2DWARF
形态）+docs；**src 触碰 1 处（声明）**：src/debugproto.rs（OUTSTRUCT-ID0
身份修复，独立 commit bcaaf396，机制 C 白名单外——debugproto 非
heritage/jumptable/blockaction/condexe/varmap/merge 域；printc.rs/varmap.rs
全程未触碰）。

### 12.1 oracle 级预验证（先行，BRIDGE1 方法论照做）

stage_seed_diag（锁定库 e40ed130，真 `<localdb>` decode 链）+ pyelftools
DWARF 盘点（/dev/shm/rudra-tests/c3next/：struct_inventory.py /
dwarf_types.py / gen_struct_seed_xml.py + seed_*.xml + oracle_*_seeded.c）：

- **DWARF 盘点**：结构体变量 9 条（main urls/outs/heads/progressbar/
  fileinfo+passarg 同槽、getparameter statbuf/aliases、helpf ap）+
  match_url glob 为 fbreg(0) 栈形参（C3 域，不收）。
- **声明层逐符号复现（3/3 函数全命中）**：main `URLGlob * urls; OutStruct
  outs; OutStruct heads; ProgressData progressbar; stat fileinfo;`；
  getparameter `Configurable * local_5b8; HttpPost * local_5a8; stat
  statbuf; LongShort[50] aliases;`；helpf `va_list ap;`。
- **字段形族复现**：`outs.stream/outs.filename/heads.stream/heads.filename`
  读写、`fileinfo.st_size`、`progressbar.total`、`glob_url(&urls,...)`/
  `next_url(urls)`、getparameter 别名环 `->letter/&->lname`。
- **va_list 域判决**：typedef 折叠为 struct 时 oracle 打印 `ap.field` 且
  按 `&ap` 传递；**数组形**（`__va_list_tag[1]` 命名 va_list）时打印
  `ap[0].field` 且按值传递 `ap`——canon 为数组形 ⇒ 种子必须以数组形
  运输（gen_struct_seed_xml 的 typedef→array 链修复即此判决）。
- **已知 harness 工件（非语义差异）**：种子态 oracle 打印抽象数组形
  `bool[256] errorbuffer`/指针间距 `URLGlob * urls`，canon 打印声明符形
  `bool errorbuffer [256]`/`URLGlob *urls`——C2DWARF 判例同款（Java 导入
  器构建的类型对象形态差异）；Rudra 侧独立以 canon 形输出（E2E 实证）。
- **指针型选举（getparameter 别名环）**：裸 oracle 里 LongShort* 胜出
  （`pLVar6->letter`），canon 为 Configurable*（`pCVar13->useragent`）；
  Rudra 全驱动（funcp 的 Configurable* 参数锁在场）落 canon 形 ✓。

### 12.2 实现形态

- **manifest** `tests/golden/manifests/local_seed_curl_1204_struct.json`：
  3 函数/10 种子（main 5 DWARF + helpf 1 + getparameter 2 canon-decl +
  2 DWARF）+12 drops 全归账 + residual_notes 5 条（glob×2/register var
  `Configurable *config`/sec_offset 域/Unresolved 注释族）；指纹齐备
  （oracle e40ed130 + binary sha256 + golden sha256）；harvest_rule 全
  规则留档。
- **harvester** `--struct` 模式：DWARF 复合体命名域（可直接命名的
  structure/union/enum + typedef over composite/array）为准入门（TYPEFIX
  规矩的 C4 等价物：未知命名基=工厂名树 None=死条目，剔除）；KNOWN_BASES
  域显式排除（C1/C2 通道属地，按构造不相交）；首声明槽主规则（progressbar
  遮蔽 passarg）延续；canon-decl 采纳=local_[hex] 声明 + 结构体指针基。
- **驱动门** `RUDRA_STRUCTSEED=1`（+`RUDRA_STRUCTSEED_MANIFEST` 覆写）：
  与 TYPESEED/DWARFSEED 同装载器、独立 env；attach 在 DWARFSEED 之后，
  偏移碰撞=响亮 manifest 缺陷告警；mirror 四分量在场恒拒载（实测
  RUDRA_MIRROR+三门输出与纯 mirror cmp 恒等）；默认路径构造性恒等。
- **src 前置（bcaaf396）**：intern_named 的 id=hashName 派生（type.cc:675
  镜像）+ 零尺寸不完整复合体守卫 + parse_c_type 名树 findByName 回退
  （grammar.cc:2989 镜像）——直接命名复合体（OutStruct/stat/...）此前
  从未进名树（id=0 被 find_add 拒绝后静默未注册），typedef 路径不受影响。

### 12.3 C3NEXT 验收（亲测，基=亲父 5fff5592 + bcaaf396）

| 门禁 | 默认（无 env） | TYPESEED=1 | TYPESEED+DWARFSEED | 三门全开 |
|---|---|---|---|---|
| curl E2E canon | **1096/0/0**（=bcaaf396 见证；亲父 5fff5592 为 1099，差额 −3 归因见 bcaaf396 Differential） | 1051/0/0 | **941/0/0** | **767/0/0**（−177 vs 亲父双门） |
| 投影银行 | 71/71 PASS（离线，frozen） | mirror 门恒闭 | mirror 门恒闭 | mirror 门恒闭（实测拒载+cmp 恒等） |
| gcc 审计 | 104 OK/20 FAIL | 同 | 104 OK/20 FAIL | **104 OK/20 FAIL**（fail 函数名集与双门态逐名相同，零新增） |
| 双跑确定性 | cmp 恒等 | cmp 恒等 | cmp 恒等 | cmp 恒等 |

逐函数（双门→三门，**0 回退**硬门 ✓；14 个未播种函数字节恒等）：
main 185→**129**（−56）、getparameter 382→**277**（−105）、helpf 50→**37**
（−13）。字段形实证：`outs.stream = stdout`/`outs.filename = ::config.outfile`/
`fileinfo.st_size`/`progressbar.total`/`ap[0].gp_offset`/`LongShort
aliases [50]`（canon 数组拼写形）全量出现；getparameter 别名环指针选举落
canon 形（`pCVar13 = (Configurable *)aliases; ... ->useragent`）。

### 12.4 残差登记（不可经本通道复现 → HEAD/C3 域）

- main `URLGlob glob` 槽位发现（canon-only inlined 参数，DWARF 无 location；
  双门态 decl 已在但槽位归属未钉）→ C3 域。
- match_url `URLGlob glob` 栈形参（fbreg(0) 正槽）→ C3 原型锁域。
- main `Configurable *config` 寄存器变量（无栈槽；canon decl 在场=驱动
  DWARF 层产物）→ localdb register-symbol 域（HEAD）。
- canon `/* Unresolved local var */` 注释块（Java 前端工件，decompile/cpp
  无该串；main 3 行+getparameter ~20 行）→ 注释通道域。
- getparameter/main 计数器分型（`for (var_8; ...)` vs `for (lVar11 =
  0x96; ...)`）与 canary 声明位/编号级联 → 库级 typeprop/merge 域
  （与 §9.3 下标形残差同族）。
- sec_offset loc-list 全域（Ghidra importer 自身丢弃，预登记）。

## §13 HSEED 交付记录（Lane HSEED，2026-09-25，基=亲父 33894226=master DFLIP 后）

任务原设：把 curl 已验证的 C2(DWARF 名)/C4(结构体) 种子公式复制到 httpd 语料。

### 13.1 语料判决：C2/C4 对 httpd **语料级不可用**（机器可复核）

- `examples/httpd`（sha256 `805f89cdbdce827f…`，与 golden provenance 钉值一致）为
  **stripped PIE——零 `.debug_*` 节**（`readelf -SW` 亲查；无 `.gnu_debuglink`）。
  C2/C4 公式的输入端（`.debug_info` 的变量名 + exprloc fbreg 偏移 + 命名复合体集）
  在该语料不存在。
- 机器证据：`harvest_local_manifest.py --dwarf/--struct` 对 httpd 实测
  **0 函数 / 0 种子 / 0 drops**；工具本轮加固——DWARF-less 语料显式
  `WARNING: … carries no .debug_info section`（manifest 字节不变，curl 重收割
  字节恒等复证，--struct residual_notes 按 corpus 参数化防跨语料残差串写）。
- canon 侧交叉验证：`ghidra_httpd_1204.c` 声明层为纯合成名（`local_*`/`*Stack_*`/
  `xVar*`，1046 条 local_ 全部 KNOWN_BASES——已尽收于 C1 manifest）；唯二结构体
  类型声明 `sigaction local_b8`@ap_fatal_signal_setup(0x14a1b0) 与
  `sigset_t local_c0`@ap_mpm_run(0x16ff30)（均带 C4 字段形用法：
  `local_b8.sa_mask`/`.__sigaction_handler.sa_handler`）被 --struct 的
  "base 必须存在于 DWARF 命名类型集" 规则正确丢弃——工厂名树
  （curl 侧由 `parse_type_names` DWARF 导入填充，httpd 驱动无此源）为空，
  parse_c_type 无回退 bail ⇒ 死条目。
- oracle 预验证（§12.1 方法论）：**N/A（空集）**——无种子可 stage，抽验无从抽取；
  空手写 manifest 或死门接线违反铁律 1.4（占位实现），故
  `examples/httpd_decompile.rs` 本轮**零改动**（DWARFSEED/STRUCTSEED 门不接线）。
- 解锁路径（root 级语料决策，TODO `HTTPD-CORPUS-DWARF-0001`）：①带 DWARF 的
  httpd 构建产物入库 + ②`tools/regen_golden.py` 重生成 canon golden（需 Ghidra
  headless 发行版，全量差分基线重置为预期行为）+ ③C1 manifest 重跑 + ④harvest
  两模式 + ⑤stage_seed_diag 预验证 ≥3 函数。

### 13.2 基线阶梯（SYMDB 默认脸 × TYPESEED 叠加态首次实测，亲测 @ 33894226）

| 阶梯 | env | skeleton/defects/numbering | 附加验证 |
|---|---|---|---|
| 新默认脸 | （无） | **1315/0/0** | ==DFLIP final 逐字节；双跑 cmp 恒等 |
| +TYPESEED | `RUDRA_TYPESEED=1` | **1197/0/0** | −118 全由 6 播种函数贡献（main 644→622、ap_fini_vhost_config 191→158、ap_update_vhost_from_headers 81→56、ap_parse_vhost_addrs 27→9、ap_os_is_path_absolute 23→7、ap_ht_time 17→13）；逐函数零回退；gcc 审计函数名集与默认脸逐名相同（14OK/15FAIL，pRam 未声明族=在账 PRINTC-AFINI-UNIQUELOC-0001 等预存项） |
| 逃生门+TYPESEED | `RUDRA_SYMDB=0 RUDRA_TYPESEED=1` | **1360/0/0** | ==BRIDGE1 历史 opt-in 见证（1472 基）精确复现：通道完整性再证 |
| mirror×TYPESEED | `RUDRA_MIRROR=1 RUDRA_TYPESEED=1` | — | 输出 cmp 恒等基线 mirror；`[TYPESEED] ignored under the mirror gate` 亲证：投影纯度在新默认脸保持 |

判决：SYMDB 默认脸与 TYPESEED 门**正交可叠加、严格收敛、零回退**
（组合语义=两通道各自收益相加：1315−118=1197，与旧脸 1472−112=1360 同构）。

### 13.3 残差登记

- httpd C2/C4 种子域=**空（语料性质）**，非通道缺陷；curl 侧两通道不受影响。
- `sigaction`/`sigset_t` 两 golden decl（C4 字段形在场）=语料解锁后的首批
  种子候选；当前无工厂名树不可服务。
## §13 C3GLOB 交付记录（Lane C3GLOB，2026-09-25，基=亲父 199b23b1）
通道判定：§12.4 的 C3 域残差（glob×2：main glob 槽位发现 + match_url
glob 栈形参）oracle 级预验证**双证 CONFIRMED**——但 Rudra 侧 C3 数据传输
通道**已在位**（master 的 DWARF 原型锁 + 平台参数符号安装 + callee 传播），
残差重新归属到**库消费/渲染域**；**v1 不设第四门**（committed_locals 载体
对参数槽实测有害，见 §13.3）。零 src/ 改动（docs/tools 域收口）。
### 13.1 oracle 级预验证判决（先行，BRIDGE1/C3NEXT 方法论照做）
仪器：`stage_c3_diag.cc`（锁定库 e40ed130，BRIDGE1 diag-build 对象链接；
`/dev/shm/rudra-tests/c3glob/`：harness + `gen_c3_seed_xml.py` + 两个
witness）——扩展 C1 harness 两处安装路径，均为真 funcdata.cc:789-810
decode 链：`STAGE_SEED_XML`（`<localdb>` 参数符号）与
`STAGE_CALLEE_PROTOS`（callee Funcdata 上的成对安装，供
ActionDefaultParams coreaction.cc:2322-2330 copy 传播）。
**协议发现（真传输形态）**：Java→C++ committed-signature 传输 =
①`<localdb>` **cat="0" index=N 参数符号**（名字/typelock/namelock/锁定
存储 `<addr>` + 全内联 `<type>` 图——ProtoStoreSymbol::getNumInputs 直读
scope 的 function_parameter 类别，fspec.hh:1283-1285）+ ②`<prototype>`
**仅 returnsym**（model+modellock；symbol-backed store 拒绝
`<internallist>`，fspec.cc:3302 "Do not decode symbol-backed prototype
through this interface"；返回值走 ProtoStoreSymbol::setOutput）。参数存储
无 `<addr>` 时走 ProtoStoreInternal::decode 的 addressesdetermined=false
臂（fspec.cc:3495-3520，model 从类型派生）——但该臂属 internal store，
live Funcdata 的 funcp（ProtoStoreSymbol，funcdata.cc:69 setScope）只能
收 localdb 符号路径。
**Q1 match_url 判决：CONFIRMED**（witness `oracle_match_url_seeded.c`）。
锁 `<localdb>`{filename cat=0 RDI char*、glob cat=0 stack+8[304] URLGlob
全图} + returnsym(char* RAX) 后，canon 签名与体字段形**逐形复现**：
`char * match_url(char * filename,URLGlob glob)`、
`glob.size/2<=iVar4`、`glob.pattern[iVar4].type`、
`.content.Set.elements/.Set.size/.Set.ptr_s/.NumRange.ptr_n`、
`UPTCharRange/UPTNumRange/UPTSet` 枚举名。消融判决（`cat="-1"` 变体
`oracle_match_url_nocat.c`）：**类别只管签名**（cat=-1 时签名退化单参），
**体字段形只需 typelocked 符号盖住 stack+8[304]**——与类别无关。
**Q2 main 判决：CONFIRMED，且槽位发现无需任何 main 侧种子**
（witness `oracle_main_c3.c`，仅 callee 安装、main 零 localdb）：
`URLGlob glob;` decl + **-0x388 槽**（= match_url 出栈区，rep movsq 目的
`&stack0xfffffffffffffc78` 逐字节复现）+ `glob.literal[0..9]`/
`glob.pattern[N].type/_4_4_/content` 族 + `glob._296_8_` + 计数器
`for (iVar9 = 0x26; ...)` 形 + `match_url(pcRam...,glob)` 调用形全量。
**glob 槽位/名字/类型的来源钉死**：结构=callee（match_url）DWARF 类型图
（URLGlob 304B：literal[10]@0/pattern[9]@80/size@296，readelf 盘点）；
槽位=**call 指令自身的出栈访问**（decompiler 自行派生 -0x388，非 DWARF
非 analyzer——main 的 DWARF 子树实测无 glob 变量，25 个实体盘点为零命中）；
名字=**callee 参数符号经 FuncProto::copy→ActionDefaultParams 传播**
（ProtoStoreSymbol::clone 保 callee scope 指针，fspec.cc:3280-3295）。
canon 的 in_stack 读/glob 写同区二元性（`glob.pattern[0].type =
axVar19._0_4_` + `axVar19 = in_stack_...fc78._80_24_`）oracle 同构复现。
### 13.2 Rudra 侧现状（探针证据，临时 DBG 后 revert）
- **match_url 传输已在位**：`[PREPASS] applied locked DWARF prototype:
  2 params`（默认态日志）→ set_pieces → model 派生 **Stack+0x8[304]**
  （临时 `[DBG-C3PROBE]` 探针实证 `param[1] glob space=Stack offset=0x8
  type=URLGlob size=304`）→ coreaction.rs:1509 平台参数符号臂安装
  （typelock/namelock/cat=0，与 oracle localdb 符号状态等价）。签名
  `char * match_url(char *filename,URLGlob glob)` 三门态已 canon 形。
- **main 传播已在位**：link_call_specs callee 半边（GETPARAM-CALLEE-DWARF
  判例资产）→ 三门态 main 已打印 `glob.pattern[8].content.Set.elements =
  (char **)in_stack_...fd90` 等字段族 + `match_url(::config.outfile,glob)`，
  与 canon 同构（§12.3 witness 内已实证，本车道复核确认）。
- **残差全部在消费/渲染域**（见 §13.4），不在 C3 数据通道。
### 13.3 为什么没有第四门（v1 边界判决）
C3GLOB 门原设计 = committed_locals 运输 match_url 的 glob@+8 种子。
探针（`probe_seed_matchurl.json` 经 RUDRA_TYPESEED_MANIFEST 覆写实测）
证明该载体对参数槽是**错误传输**：与 coreaction.rs:1509 平台参数符号
（同址 stack+8[304]）**重复**，实测 match_url 28→40 行——字段形退化为
raw offset 形（`*(long *)(&glob + lVar6 + 0x58)`）**且枚举名丢失**
（`iVar2 == 2` vs `UVar2 == UPTCharRange`）。正确传输（平台安装）已存在
⇒ 第四门 = no-op 或有害，不 ship。**"四门 767 下降"预期不成立于本域**：
预期建立在"C3 数据缺失"假设上；实测数据已在位，缺的是库消费（§13.4）。
C1 载体与参数域的构造不相交原则（C2DWARF "栈参数不收（C3）"）由此获得
正向证据：参数槽的正确运输者是原型锁路径，不是 localdb-locals 载体。
### 13.4 残差重归属（出本车道写域；登记 TODO `HEADLESS-BRIDGE-C3-CONSUME-0008`）
- **match_url 指针形字段访问**（三门态 28 行）：`(&glob)->pattern[iVar5]
  ->type` + `*(long *)&((&glob)->pattern+iVar5)->content` vs canon
  `glob.pattern[iVar5].type/.content.Set.elements`。同符号状态（typelock
  304B stack+8 cat=0）oracle 产 canon 形；Rudra **标量字段解析、变址
  数组字段读不解析**（`glob.size` ✓ vs `glob.pattern[i]` ✗）。域=
  restructure/typeprop/printc 的符号消费（varmap/printc 白名单模块）。
- **main `&0xfffffffffffffc78` 截断**（1 行）：canon `&stack0x...`（空间
  名前缀，Ghidra AddrSpace::printRaw space.cc:206 `name+"0x"+offset`）；
  Rudra 印裸 hex。print 域（printc.rs 地址常量渲染路径）。
- **union 名拼写**（main 9 行）：`union_5a7`（Rudra offset 命名）vs
  `anon_union_16_3_e2f18bb4_for_content`（Java DWARF 导入器合成名）。
  名字组件部分可观察（size=16/序数/hash/member 名）但 hash 算法在 Java
  侧（decompile/cpp 之外、本仓 ghidra/ 树无 Java）→ **不可推导登记**，
  除非引入 Java 侧证据（W0 消融时顺带钉）。
- 计数器分型/Unresolved 注释/`Configurable *config` 寄存器变量/
  sec_offset：§12.4 预归属不变。
### 13.5 验证（亲测，基=亲父 199b23b1）
| 门禁 | 默认（无 env） | 三门全开 |
|---|---|---|
| curl E2E canon | **1096/0/0**，cmp 亲父字节恒等（docs/tools-only，构造性恒等；临时探针 revert 后重建 cmp 实证） | **767/0/0**（=C3NEXT 见证复现） |
| gcc 审计 | — | **104 OK/20 FAIL**（=三门基线，fail 集不变） |
| 双跑确定性 | cmp 恒等 | cmp 恒等 |
src 零触碰（printc.rs/varmap.rs/debugproto.rs 全程只读；唯一临时 DBG
eprintln 已 revert，default 输出 cmp 恒等双证）。

### 13.6 消费域终局（Lane C3CONSUME，2026-09-25，基=master 8796274c SEEDFLIP 后，P-code 级归因）

任务：§13.4 ①② 的消费链断点定位（varmap 假设检验）。**判决：varmap
消费链无缺陷——断点全数在 printc 渲染 + coreaction/funcdata 联合体解析
基础设施；varmap 域零改动，①② 修域移交**。

**仪器**：`stage_c3_pcode.cc`（/dev/shm/rudra-tests/c3consume/，锁库
e40ed130 BRIDGE1 对象链接，stage_c3_diag 同驱动协议 + 终态 P-code 逐
op 转储：op 码/输入输出 varnode 的 high 类型/符号/符号偏移）。双
witness 复跑字节恒等（match_url seeded + main callee-only）。

**① match_url 28 行残差的 P-code 级分解**（oracle vs Rudra 同种子态）：

- **顶层链 op 形完全一致**：`PTRSUB(RSP,#8){常量挂 sym=glob/304B}` →
  `PTRSUB(·,#0x50)` → `PTRADD(·,sext(iVar),#0x18)` → `PTRSUB(·,#0)` →
  `LOAD`——两侧逐 op 同形（Rudra RUDRA_DUMP_FUNC 转储对照）。glob 符号
  挂接（linkSymbolReference 等价物）、字段名（pattern/type/content）、
  标量字段（`glob.size` ✓）、常量下标形（main 的 `glob.pattern[8].type`
  ✓）全部在位——**ScopeLocal/RangeHint 消费链工作正常**。
- **残差 A（`.` vs `->` 与 `glob` vs `(&glob)` 基形态）**：canon 点形由
  printc.cc:895-911 `isValueFlexible`（in0 隐式且 def=PTRSUB/PTRADD）+
  :1039-1044 flex 臂 `pushVn(in0, m|print_load_value)`（基座翻转为
  值形态，spacebase 臂 cc:1074 去掉 `&` 印 `glob`）产生。Rudra
  printc.rs PTRSUB 臂明确注释"Rudra has no isValueFlexible; we treat
  flex as false"（rpn 路径 printc.rs:2975 附近；legacy op_ptrsub
  printc.rs:13135 同缺）——恒箭头形+基座无翻转 → `(&glob)->pattern[i]
  ->type`。
- **残差 B（联合体内字段名 `.Set.elements/.Set.size/.NumRange.ptr_n/
  .Set.ptr_s`）**：oracle 走 12.0 ResolvedUnion 机制——coreaction.cc:
  2490 `ActionSetCasts::resolveUnion`（读联合体指针的 op 前插
  `PTRSUB(x,0)` 占位 + `Funcdata::setUnionField` 登记解析字段，
  funcdata.cc:917-950 unionMap）+ printc.cc:979-990 opPtrsub 联合体臂
  （`getUnionField` 取名）。**Rudra 无该机制**：内层偏移（content+2/
  +4/+8/+0xa）退化为 `CAST(ptr→int8)+INT_ADD(·,c)+CAST(→ptr)` 链
  （oracle 同位点为 `PTRSUB(·,#0:4)+PTRSUB(·,#c)` 规范式），LOAD 输出
  类型停在 raw long（canon 为 char**/short 经解析字段类型传播）——
  coreaction（resolveUnion+castOutput PTRSUB 规范化）+ funcdata
  （unionMap）+ printc（联合体臂）三域联合缺口。
- **残差 C（3 行 Unresolved 注释 + `&DAT_` vs 字面量 + LAB 缩进）**：
  §12.4 预归属不变（注释通道/常量渲染/标签发射域）。

**② main `&stack0x...fc78` 截断——判决：纯渲染，非 varmap 槽位分割**。
Rudra op 形=canon 同形 `PTRSUB(RSP-input,#0xfffffffffffffc78)`，两侧
符号解析**同样落空**（canon 也不挂 in_stack_...fc78 符号而印未名位
置）；唯一差异=未名位置文本：canon 走 AddrSpace::printRaw（space.cc:
206，`空间名+"0x"+offset` → `stack0xfffffffffffffc78`），Rudra
printc.rs spacebase 未名回退印裸 `format!("0x{:x}", in1const)`
（printc.rs:3121-3131 附近）→ `0xfffffffffffffc78`。

**移交清单**（新登记 `PRINTC-C3FLEX-DOTFORM-0001`、
`COREACT-C3-UNIONRES-0001`、`PRINTC-C3-UNNAMED-SPACE-NAME-0001`，
见 TODO_BOARD C3-CONSUME 行）：
1. printc.rs：isValueFlexible 移植 + flex 臂基座 `m|print_load_value`
   翻转（`.name` 形；`&` 消除）——预期收敛残差 A 全族（~14 行）。
2. coreaction.rs+funcdata.rs+printc.rs：ResolvedUnion（resolveUnion/
   unionMap/getUnionField 联合体臂）+ castOutput PTRSUB 规范化——预期
   收敛残差 B 全族（~10 行，含 decl 类型 char**/short 级联）。
3. printc.rs：未名位置 space 前缀（AddrSpace::printRaw 形态）——收敛
   main `&stack0x...` 族（1 行/处）。

**门禁（C3CONSUME 亲测，基=master 8796274c，src 零改动归因 lane）**：
默认脸（=SEEDFLIP 后种子态）curl **767/0/0**（main 129/match_url 28
复现）；投影银行 **71/71 PASS**；gcc 审计 **104 OK/20 FAIL**（=基线
fail 集）；双跑 cmp 恒等；witness 双复跑字节恒等。

## §14 REGSYM 交付记录（Lane REGSYM，2026-09-25，基=亲父 aa62f6c0）

任务原设：§12.4 登记的 `Configurable *config` 寄存器变量残差——判定 canon 的
config 参数寄存器形与 `&::config` 体引用族是否需要 localdb register-symbol
新传输（harvest+manifest+第四门）。

### 14.1 oracle 级预验证判决（先行；C3GLOB/BRIDGE1 方法论照做）

仪器：`stage_regsym_diag.cc`（锁定库 e40ed130，BRIDGE1 diag-build 对象链接；
`/dev/shm/rudra-reports/regsym-evidence/`：harness + `gen_regsym_seed_xml.py`
+ 五份传输文档 + 全部 runs）——C3GLOB harness 扩展一条真实解码链安装路径
`STAGE_GLOBAL_XML`（`ScopeInternal::decode` database.cc:2744 → addMapSym，
即 Program DB 全局符号传输；BFD loader 只载 FUNCTION 符号 loadimage_bfd.cc
advanceToNextSymbol，typed `config`@0x17520 必须走此路）。目标=
`getparameter.constprop.0`@0x3f00（.symtab 实名；canon Program DB 命名为
`getparameter`；`.constprop.0` 后缀=GCC 常量传播克隆，DWARF exprloc
`DW_OP_addr(0x17520); DW_OP_stack_value` 即被传播的常量 `&::config`）。

**传输分解矩阵**（CROSSBUILD 计数=终态 spacebase PTRSUB；opcodes.cc:28
`PTRSUB` 的 get_opname 字串在 12.0 是 "CROSSBUILD"）：

| witness | 参数符号(cat=0) | typed 全局 | GetStr callee | sb-PTRSUB | `&::config`/`::config.` |
|---|---|---|---|---|---|
| W0 裸 | — | — | — | 0 | 0/0 |
| W1 | ✓(config@RCX) | — | — | 0 | 0/0 |
| W2d | — | ✓ | — | 6 | 0/0（裸 `config.<f>`） |
| W3 | ✓ | ✓ | — | 25 | 全 `::config.` 族 |
| W4 | ✓ | ✓ | ✓ | 42 | **35/95 ≈ canon 34/94** |
| W5 消融 | ✓(改名 renamed_cfg) | ✓ | ✓ | 42 | **0/0** |

**判决（三段）**：

1. **寄存器参数形：载体=committed-signature 参数符号，模型存储 RCX**。
   W1 单独复现 canon 签名 `int getparameter(char *flag,char *nextarg,
   bool *usedarg,Configurable *config)`，config 参数在体内**死**
   （constprop 克隆里 RCX 从未被当 config 指针读；0x4229 实证 `COPY
   const:17520→RCX`，LEA 直接携带折叠常量）。DWARF exprloc 常量**不是**
   参数存储（canon 体内无 memory 形干扰=W1 同构）。Rudra 侧同构在位：
   签名逐字相同 + dump 实证 `config:register:38`(RCX) typelock 死参数。
2. **`&::config` 体引用族：载体=typed 全局符号 + 参数名遮蔽 + 类型传播**。
   W4 逐形复现 canon：`GetStr(&::config.useragent,(char *)x)`、
   `pCVar13 = &::config;`、`::config.crlf = '\x01'`、
   `GetStr(&::config.cert_passwd,nextarg)`。机制钉死：`::` 前缀来自
   `Symbol::getResolutionDepth`（database.cc:323-359）——参数符号名
   `config` 占据函数局部名树（`ScopeInternal::isNameUsed` database.cc:
   2417）→ 全局同名符号解析深度 1 → `PrintC::pushSymbolScope`
   （printc.cc:202）印全局 scope 空名+`::`。**W5 消融（参数改名）使
   `::` 全数消失（0/0）——因果链闭合**。空间基址 op 形两侧同构
   （oracle `PTRSUB(const:0[sb],0x175XX)` vs Rudra dump 同形）。
3. **无需任何新传输**：参数符号（coreaction.rs:1509 平台安装臂）、
   typed 全局（Rudra 已印 `::config.outfile` 于 LOAD/STORE 路径）、
   callee protos（link_call_specs）三载体全数在位 ⇒ 第四门=no-op，
   C3GLOB 判例式收口：**载体已在，残差在 printc 消费侧**。

### 14.2 残差重归属（出本车道写域；新登记 `PRINTC-SPACEBASE-SCOPEPREFIX-0001`）

- **`&config` vs `&::config`（35 行=getparameter 34+main 1）**：Rudra
  printc.rs spacebase 符号臂（~3145-3170）印符号名时**未调用已存在的
  `symbol_scope_prefix` helper**（PRINTC-GLOBALSYM-LEAF-PRIORITY-0001
  已落地该 helper，仅 7169/7183/7196 叶优先路径接线；oracle 对应
  printc.cc:1905 pushSymbol→pushSymbolScope 链）。修域=printc.rs，
  与 PDOTFORM 车道写域序列化。
- **`&(&config)->field` vs `&::config.field`（同 35 行内）**：spacebase
  mid-symbol 引用应走 `pushPartialSymbol`（printc.cc:2057，object_member
  `.` 形，基座=全局对象 lvalue）；Rudra 落指针基座+箭头形。已登记
  `PRINTC-SPACEBASE-PARTIALSYM-0001`（symbol-offset 通道缺口）+
  `PRINTC-C3FLEX-DOTFORM-0001`（flex 域）覆盖，本车道不重复登记。
- getparameter `::config.` 计数 61 vs canon 94 的差额=别名环/计数器分型
  族（§12.4 预归属不变，库级 typeprop 域）。

### 14.3 门禁（亲测，基=亲父 aa62f6c0，docs/tools-only 车道）

默认脸 curl E2E canon **767/0/0**（getparameter 275/main 129 骨架）；
投影银行 **391/391 PASS**；gcc 审计 **104 OK/20 FAIL**（=基线 fail 集）；
双跑 cmp 恒等。src/ 零触碰（printc.rs/varmap.rs/coreaction.rs 全程只读）。

### 14.4 复现

```bash
bash /dev/shm/rudra-reports/regsym-evidence/build_regsym_diag.sh   # 链 BRIDGE1 锁库
setarch -R env -i STAGE_DRILL_FUNC=getparameter.constprop.0 STAGE_DRILL_ADDR=0x3f00 \
  STAGE_SEED_XML=<seed_getparameter.xml> STAGE_PROTO_XML=<proto_getparameter.xml> \
  STAGE_GLOBAL_XML=<global_config_sym.xml> \
  STAGE_CALLEE_PROTOS="GetStr=<seed_getstr.xml>:<proto_getstr.xml>" \
  ./stage_regsym_diag sleigh_specs <repo>/examples/curl        # = W4
# W5 消融 = seed_getparameter_renamed.xml 替换 seed 后同跑（:: 全数消失）
```

## §15 SECSEED 交付记录（Lane SECSEED，2026-09-25，基=亲父 6aa8c2aa=master SCOPEPFX 后）

**任务**：W1B 预登记的 "sec_offset 全域"（harvest 丢弃的 DWARF sec_offset 形态条目回收）
终审。判定结果：**归因收口**（种子通道不可收；真身是注释通道，Rudra 侧一处
src 阻塞，登记 `PRINTC-COMMENTFILL-ARM` 解锁）。零 src/ 改动。

### 15.1 形态判决（任务①）

curl（DWARF-bearing，units v4）concrete subprogram 下的变量盘点（probe1_census.py，
pyelftools，/dev/shm/rudra-tests/secseed/）：

| 位置形态 | 条数 | canon 可见形 |
|---|---|---|
| `DW_FORM_sec_offset`（.debug_loc 位置表） | **67** | `/* Unresolved local var */` 注释 |
| `DW_FORM_exprloc`/block（现行 C2 通道） | 22 | 命名局部（已收割） |
| 无 location | 11 | 同注释通道（size/configbuffer 等） |

**sec_offset 不是 DWARF5 str_offsets/addr 表偏移形态**：`.debug_loclists`、
`.debug_str_offsets`、`.debug_addr` 三节全部缺席，unit version=4——是
DWAR4 `DW_AT_location` 指向 `.debug_loc` 位置列表（多区间、寄存器/表达式混合、
部分区间 fbreg）。

### 15.2 canon 可见形与种子通道判决（任务①续）

- **0/67 成为命名局部**：canon 从不以 DWARF 名提交这些变量（main 的 `url` 只作
  `::config.url` 成员出现；`letter`/`line` 为字符串/参数误命中，严格 decl 扫描为零）。
  种子通道（committed_locals 注入）会**新增**差异 ⇒ 不可收（RENUM 判例式归因）。
- 槽位重合三例（infilesize@-560≡`local_230`、home@-352≡`local_160`、
  parse@-1448≡`local_5a8`）已由 C1/C4 canon-decl 通道正确服务（canon 印的是
  合成名，不是 DWARF 名）。
- 真身：**commentdb warning 记录**。canon 45 行 / 8 函数（getparameter 20、
  parseconfig 7、my_get_token 4、file2string 4、main 3、match_url 3、
  myprogress 2、my_get_line 2）。httpd 剥离 DWARF ⇒ 0 行（通道 curl 专属）。
  main/myprogress 的函数域组在 canon 缺席（Java 侧创建条件未究——收割时以
  canon 文本门控 presence，不猜规则）。
- 组规则（canon+DWARF 实证）：同 scope 的未解析变量合并为一条注释记录
  （文本内 `\n` 连接）；**锚规则**=函数域组→function low_pc，词法域组→scope
  首区间 low_pc。

### 15.3 oracle 预验证（任务①"不可跳"项）

新 harness `stage_cmt_diag.cc`（bridge1 stage_seed_diag 的 commentdb 注入变体，
编译于锁定库 e40ed130 对象树 + libdecomp.a，build_cmt_diag.sh）：
`addComment(Comment::warning, fad, anchor, text)` 后按 golden 生成器契约驱动。

- my_get_line（entry 锚）：`/* Unresolved local var: char * nl@[???]\n... */`
  **逐字节复现 canon**（20 列 line_commentindent + 3 空格 comment fill 续行、
  单记录单块、decl 后首语句前位置）。
- getparameter：函数域组（entry 锚，敏感性扫描 0x3f00/0x3f07/0x3f27/…/0x3f52
  界定了窗口）+ fnam@0x40f0（词法块首区间）双双落 canon 位置（后者在
  `if (cVar1 == '-') {` 分支首语句前，与 canon 逐位对齐）。
- myprogress（prevblock/thisblock@0x3503）、parseconfig（line/tok1/tok2@0x3d35）
  同样落 canon 锚定语句（`if (dltotal+ultotal==0)` / `if (__stream != 0)` 前）。

### 15.4 Rudra 侧发射链实证与阻塞点（任务②判定）

驱动域注入探测（examples/curl_decompile.rs env 门，已回退）：commentdb →
CommentSorter（printc.rs:14812 setup_function_comments）→ emit_comment_group →
emit_line_comment **链路活着**——my_get_line 注入后位置/块形正确。两个发现：

1. **锚约束**：Rudra 侧 op 地址为 spaceless `Address::new(vaddr)`，而
   `block_basic_contains`（comment.rs:480）要求双方 space 均 `Some`——
   contains 主路径对 spaceless 恒 false，实际放置全走 `op.addr == comm.addr`
   的 backup 路径 ⇒ **锚必须精确等于一条存活 op 的地址**（工作注释
   "Subroutine does not return" 同此路径）。canon 锚（函数入口）在 Rudra 侧
   需校准到同语句的存活 op（如 my_get_line 0x3854）。
2. **阻塞点**：emit_line_comment（printc.rs:11032）**不调 start_comment/
   stop_comment**（注释称 "markup only"——对 EmitNoMarkup 成立，对
   EmitPrettyPrint 不成立：二者压 BeginComment/EndComment token 置
   commentmode，gate 续行 3 空格 fill，prettyprint.rs:3851/3929 已移植）。
   结果续行列 20 vs canon 23。**这是 src/printc.rs 一处两行量级的缺口**
   （`let id = self.emit.start_comment(); … self.emit.stop_comment(id);` 包住
   token 走查；EmitNoMarkup 默认实现已是无字节 no-op），出本车道写域
   （printc 在 GETPARAM 重审车道写域内），按铁律停下归因：
   **`PRINTC-COMMENTFILL-ARM`**（P2，write-set=src/printc.rs + docs/api/printc.md）。
   解锁后纯驱动域注释通道（harvest --cmt + RUDRA_CMTSEED 门 + manifest）
   即可收割，预期 −45 行（624 的 7.2%）。

### 15.5 验收与产物

- 默认 curl E2E **624/0/0**，探测回退后重建 cmp 亲父构建**字节恒等**。
- census 全归账：100 = 67 sec_offset + 22 exprloc + 11 no-location。
- 产物（/dev/shm/rudra-tests/secseed/，root 集成后按回收纪律处理）：
  probe1-6（census/loclist/slot/scope/firstbegins）、stage_cmt_diag.cc +
  build_cmt_diag.sh + 二进制、oracle_mygetline_cmt.c / oracle_getparam_cmt.c、
  curl_{default,cmtprobe,final}.c、cmt_*.txt。

---

## §16 V3SIG 交付记录（Lane V3SIG，2026-09-25，基=亲父 cf2e138f=master SHAPEFIX 后）

> HEADLESS-BRIDGE-V3-SIGLOCK-0003 的 httpd 形状族收口面：被调函数锁定原型通道
> （RUDRA_V3SIG=1 opt-in）。commit 与验收矩阵见 TODO_BOARD 行；证据
> /dev/shm/rudra-tests/v3sig/（保留至 root 集成）。

### 16.1 通道（SHAPEFIX 判决的运输层）

canon golden 的 `long *` 下标/8 字节 load/canary 槽下标族——**机制归因改判
（2026-09-27,Lane BRIDGEDOC）**：原主张"来自 analyzeHeadless **Decompiler
Parameter ID** 分析器提交到 Program DB 的被调函数锁定原型"**作废**（消融
负证据：Parameter ID 对 ELF 默认关、canon 从未运行，强开 461 函数偏离 canon；
live 协议亲证 canon DB 无内部被调提交签名——HEADLESSDIST 终报 §3/设计文档
§19，详注 16.1.1）。双向实验证明的是**输入→输出等价**：单条
ap_setup_prelinked_modules (long*)→long 锁定原型即把锁定 oracle 的 main 翻成
canon 形（env-flip 154/156——/dev/shm/rudra-reports/LANE_SHAPEFIX_2026-09-25.md）
——canon 以另一种输入状态（无被调提交原型的恢复环境）到达同一输出，锁定
原型注入因此是**输出等价运输层，非 canon DB 状态镜像**。Rudra 的
httpd 语料此前没有该通道：调用点全走 active recovery。本 lane 落地：

1. **harvest**（`tools/harvest_local_manifest.py --callee GOLDEN.c CORPUS
   ORACLE_COMMIT OUT.json`）：从 canon golden 的 main/ap_fini_vhost_config/
   ap_vhost_iterate_given_conn 调用点形态反推被调原型。**以调用点实参形态为准，
   不用被调自身 header**（canon 的
   ap_setup_prelinked_modules 自印 `char * f(undefined8 *)` 而调用点显形
   `(long*)→long`——原标签"Parameter ID 迭代漂移"废弃：Parameter ID 未运行，
   分歧=被调无提交原型时 header/调用点两侧独立恢复的自然结果，16.1.1）。证据规则（全部 canon 文本可观察）：元数=各调用点实参计数
   （不一致=varargs 弃收）；参数槽类型证据=裸局部（decl 类型，数组衰减指针）/
   `x[k]`（元素型）/`x+k`/`*x`/`&x`/字符串字面量（char *）/cast 目标
   （ActionSetCasts 恰把实参 cast 到调用点参数的 local type——`(char *)x` 即
   char* 证据）/常量与其他表达式（无证据，永不冲突）；两处拼写冲突杀槽
   （canon 以 long* 与 undefined8* 双型无 cast 传 apr_pool_create_ex param1 ⇒
   canon 未锁该槽）；**全槽证据齐才锁输入**（部分证据条目保持 active 元数恢复，
   仅锁返回）；返回锁=所有消费点无 cast 且消费变量类型一致（cast 存在或全未用
   ⇒不锁；未用≠void）；无参数名（canon 调用方变量保持 plVar/puVar 拼写——与
   SHAPEFIX harness 的 namelock 实验相反，namelock 会把 main 的变量改名 mod）。
   TYPEFIX 规矩沿用：KNOWN_BASES 之外的基名槽即死。
2. **manifest**（`tests/golden/manifests/callee_siglock_httpd_1204.json`，
   oracle_commit + golden sha256 指纹齐备）：60 被调（27 全输入锁，26 返回锁），
   3 drops（__printf_chk/ap_log_error/ap_run_post_config=元数冲突的 varargs/派生
   被调——canon 自身未锁，弃收即对齐方向）。
3. **装载**（`examples/httpd_decompile.rs`，RUDRA_V3SIG=1 opt-in +
   RUDRA_V3SIG_MANIFEST 路径覆盖）：inject 后、action 管线前，按 canon 地址键
   （entry+0x100000）把每条 manifest 原型装成锁定 FuncProto 挂到 fd.callspecs 的
   callspec 上——全部走库内既有公开面：`FuncProto::from_model_carrier`（defaultfp
   模型，set_arch 的 setScope 尾已绑）+ `update_all_types_from_pieces`（SYSV 存储
   分配，fspec.cc:3843 setPieces 同路）+ `set_input_lock/set_output_lock/
   set_model_lock`（镜像 SHAPEFIX proto_setup.xml 的 modellock/typelock 形态）。
   类型经 arch TypeFactory `find_by_name` 解析（FuncProto::decode 同源，
   grammar.cc:2989；"undefined" 是 data-org 唯一缺口，直接 1 字节 Unknown 核心
   构造）。消费链全在库内：TypeOpCall::getInputLocal（typeop.cc:687-718）锚定
   实参 typeprop、锁定输出臂（coreaction.cc:4637-4649）定型返回、ActionFuncLink
   inputlocked 臂挂参数、ActionDefaultParams 因 has_model 跳过 setInternal。
   **库侧无缺口——无需 src 改动、无移交**。switchD caseD 发射循环同位接线
   （canon 0x154470 `strcasecmp(unaff_R12,...)` 双参形）。
   门禁语义：mirror 恒拒（投影纯度，显式日志）；RUDRA_SEEDS=0 全局逃生；opt-in
   极性待 V3 验证轮后再评估转正。

#### 16.1.1 消融重归属注记（Lane BRIDGEDOC，2026-09-27，docs-only）

> 依据：HEADLESSDIST 车道 11 轮受控消融的负证据（终报
> /dev/shm/rudra-reports/LANE_HEADLESSDIST_2026-09-27.md；本文 §19 为其仓内
> 落账）。性质=机制叙述勘误——零 src、零行为改动、不删历史（原主张以行内
> 注记与本节保留）。

**被负证据推翻的前提（叙述层，本文已逐处修正）**：

1. **"Parameter ID 提交被调原型"**（§16.1 原首句；§17/§17.1 环语义；§17.7
   六内部包装"Parameter ID 提交域"；§2 C3 行 httpd 旧归因）：canon 配方下
   Decompiler Parameter ID 对 ELF 恒关（源码级 `getDefaultEnablement()=
   (<2MB)&&PE`），强开反而 461 函数偏离 canon（r1/r1b）；live 协议亲证内部
   被调（ap_setup_prelinked_modules）mapsym=`<prototype model="unknown">`
   +void 返回+空 localdb——**canon DB 没有内部函数提交签名**。
2. **"Parameter ID 迭代漂移"标签**（§16.1 harvest 规则、§17.1 项 2）：canon
   被调 header 自印（`char* f(undefined8*)`）与调用点形（`(long*)→long`）的
   分歧是真实文本事实，但成因不是 Parameter ID 多轮提交漂移——被调无提交
   原型时两侧各自独立恢复，分歧是自然结果。"以调用点实参形态为准"的 harvest
   规则作为数据实践不受影响（且更成立：canon 侧本就无提交原型可采）。
3. **§9.1 证伪边界的归因候选**（"Parameter ID 早轮 IR/别名挂接差异"）：同上
   排除；retaddr 直接赋值族真源未钉死（候选域=Stack 符号+归档锁输入下的恢复
   环境差），维持 HEAD 残差登记。

**不受影响的验收面（独立事实，全部维持）**：

- **V3SIG 交付本体**：manifest=canon 文本收割（数据层，与机制归因无关）；
  oracle env-flip 154/156 与 Rudra 脸 1141→951/0/0、零回退、双跑恒等——
  证明的是锁定原型注入的**输出等价性**，不依赖 canon DB 是否真有提交原型。
- **PARAMID/PARAMID2 自产环**：1038/1009/0/0、对拍精确率表、迭代不动点——
  工程语义=V3SIG 运输层的自宿主化（运行时自产锁表），交付行为与门禁数字
  均不预设 canon 存在 Parameter ID 提交层。
- **IMPORTSIG 交付（PARAMID 脸 999→753/0/0）**：独立事实；其归因"canon 导入锁
  来自签名通道而非 Parameter ID"被消融**正面证实**（r5：archive 关→
  locked-warn 124→0）——generic_clib_64 归档即签名通道本体。
- **CURLPARAM 三脸字节恒等、STRUCTB 判例**：与 Parameter ID 叙述无涉。

**修正后的定性与残余开放**：V3SIG/PARAMID 通道="canon 输出形的运输层"
（输入有效性由 env-flip 单独成立），而非"canon 输入状态（DB 提交层）的
复刻"。canon 侧 (long*) 族的**真实生成机制**（无提交原型条件下调用方恢复
如何到达该形）与 §17.7 六内部包装锁的子机制（归档按名套用 vs 传递
typeprop）均未逐项钉死——对桥接面无影响（输出等价已证、窗口内零可观测），
不派生实现票；若后续车道需要机制级解释（如 direct-runner 全量追平论证），
以本节为起点。

### 16.2 验收（opt-in 态 vs 基线 1141/0/0）

| 门 | 基线 | RUDRA_V3SIG=1 | 判定 |
|---|---|---|---|
| httpd 总量 | 1141/0/0 | **951/0/0**（−190） | defects/numbering 双零 |
| main | 613 | **505**（−108） | 形状族+返回消费族翻转 |
| ap_fini_vhost_config | 159 | **90**（−69） | void* __s1/undefined1* 族对齐 |
| ap_update_vhost_from_headers | 56 | **51**（−5） | |
| ap_matches_request_vhost | 6 | **2**（−4） | |
| caseD_0（0x154470） | 4 | **0** | canon 逐字节（strcasecmp 双参 unaff 形） |
| 其余 29 函数 | — | 恒等 | **零回退**（无任何函数 diff 上升） |
| 默认脸（env 全空） | — | cmp 基线字节恒等 | ✓（caseD 接线后复证） |
| mirror（含 RUDRA_V3SIG=1） | — | 恒拒 + 输出恒等 | ✓ |
| 投影银行 | 391/391 | 391/391 MATCH | ✓ |
| curl 默认 | 577/0/0 | 577/0/0（驱动未触） | ✓ |
| gcc 审计 | 14 OK/15 FAIL | 同基线同名集 | ✓ |
| 双跑 cmp | — | 恒等×2 | ✓ |

翻转普查（原始行）：main 738 + ap_fini 191 = 929 行（含编号级联放大；SHAPEFIX
oracle env-flip 154/156 为其子集——本通道额外收返回消费形 int 族与 (char*) cast
实参族）。

### 16.3 残差归因（951 的主族，均既有登记域）

1. **cf 结构**：canon 把 apr_app_initialize 失败分支重构进 `if (iVar3 == 0) {`
   嵌套，Rudra 保持 goto/while 形——该分支内消费变量 pcVar4 仍 char*（canon
   iVar3 int）。返回锁已到位（cast 存在即证调用输出≠char*），消费侧类型归属
   未重构 IR 的 typeprop 行为（GETPARAM-CVAR1-HOIST 同判域）。
2. **编号级联**：pcVar4 残留使 uVar/pcVar 序列整体偏移（~几十行）。
3. **undefined224* 伪影**：`&ap_prelinked_modules` 循环——ap_register_hooks
   (undefined*,long) 锁让实参流变 undefined*（canon ✓ 三处贴齐：裸 &、
   `(undefined *)0x0`、undefined* 实参），但 typeOrder 让 DB 符号的
   undefined224*（dynsym st_size=224）压过使用流，增量步进印成
   `(undefined224 *)((long)puVar15 + 8)`（canon `ppuVar14 + 1`）——
   typeprop/SYMDB 优先级域残差，登记 `V3SIG-UND224-TYPEORDER-0001`。
   **收口（2026-09-25 Lane UNDARR，§16.3 项 3 驱动侧根因关闭）**：
   TYPEORDER 判决（W0–W6 oracle 见证）确认该残差系驱动 DATASYM 输入捏造
   ——`undefined_t(st_size)` 造出 `TypeFactory::getBase` 结构上产不出的
   >10 字节 unknown 标量（type.cc:3652-3657 该尺寸恒产 `undefined[size]`
   数组）。两驱动 DATASYM 构造点已改为 oracle 真实输入形：整_extent 指针槽
   （reloc 标记或 NULL 尾零槽）→ `undefined*[N]`（W6 oracle 验证形，canon
   族形零 cast）；其余 8 整除 → `undefined8[N]`（W5 形）；非 8 整除 →
   `undefined[size]`；≤10 保持标量。main 四行族（decl/init/load/step）翻
   canon 族：`undefined **ppuVar15`/`*ppuVar15`（零 cast）/`+ 1`；
   `undefined224` 全文计数=0。
4. **varargs 3 drops** 与 **ap_run_post_config 元数冲突**：canon 未锁（站点
   元数不一致即证），弃收即对齐方向。
5. 间接调用拼写（`void(*V)()` vs `code *V`）、canary 物化（local_40 拆分）、
   &DAT vs 字符串字面量：既有他域登记，维持。

### 16.4 机制声明

- 机制 C：examples/tools 写域豁免（src 零触碰，git diff 亲父=examples/
  httpd_decompile.rs + tools/harvest_local_manifest.py + manifest + docs）。
- 机制 B：examples 非白名单模块，Differential 块按车道要求随 commit 提交
  （逐函数归因见 16.2/16.3）。
- curl 侧（SIG 418+PARAM-NAME 146 hunk、C7 NAME-NORM）与转正评估（opt-in →
  默认）维持 TODO 行排队，依赖本验证轮结论。

### 16.5 CURLPREP 交付记录（Lane CURLPREP，2026-09-25，基=亲父 59ce2cd3=master V3FLIP 后）

> curl 侧被调原型 harvest 预制（tools 域 only）：manifest + oracle 预验证 +
> 量化判决。**驱动接线（examples/curl_decompile.rs 的 V3SIG 装载）不在本车道**
> ——CMTFILL 释放 curl 驱动后另派（见 16.5.5 任务书）。

#### 16.5.1 量化（curl 577 的三族普查，skeleton 归一后行对分类）

curl 577/0/0 的函数级分布（本 lane 亲测）：getparameter 156、main 120、
glob_set 44、file2string 35、parseconfig 33、helpf 31、glob_range 38、
my_get_token 24、match_url 22、next_url 20、my_get_line 12、myprogress 11、
其余 7 函数 ≤10。三族（V3SIG 在 httpd 收掉的形状/返回消费/cast 实参）普查
（classify 工具按行对分类，/dev/shm/rudra-tests/curlprep/classify_curl.py）：
**cast 实参/返回消费 ≈45 行对（≈90 原始行）+ 形状 ≈5 行对（≈10 行）≈ 100/577
（17%）**；其余大族为 canon-only `/* Unresolved local var */` 注释块（45）、
cf/结构（29）、decl 层差（23）、DAT_LAB（6）、纯重编号与混合 OTHER（147）。
**判决：不满足 <30 行的降优先级条件，但依赖关系与 httpd 相反（见 16.5.3）**。

#### 16.5.2 harvest（curl 适配）

`tools/harvest_local_manifest.py --callee ... --dwarf-types BINARY`（curl 适配，
全部在 --dwarf-types 门后；缺省= httpd 形态逐字节不变）：

1. **cast 括号提取修复**：cast-结果站点 `x = (FILE *)fopen(a,b)` 的实参表
   起点此前取 cast 的开括号（argstr=`FILE *` → 元数 1）——改为匹配尾的
   被调开括号（`body.rfind("(", 0, m.end())`）。该缺陷同时潜伏于 httpd
   （再生成 diff：5 条目变化，apr_palloc 元数 1→2、apr_getopt_init/memcmp
   的假槽证据消失、apr_dynamic_fn_retrieve 新增 char* 锁——已提交的
   httpd manifest 未动，再生成+重验登记为后续项，不属本车道写域）。
2. **多星 cast 证据**：`(char **)0x0` 此前正则只收单星——`(\*+)` 保留星数。
3. **`_ptr_type`/`base_of` 多指针拼写修复**：`char **` 归一为 `char * *`，
   `base_of` 的 rstrip("*") 留内层星导致 servable-base 门误杀——改为全星
   剥离。
4. **--dwarf-types 证据域扩展**：servable 基名并入语料 DWARF 命名组合体/
   typedef 集（FILE/Configurable/URLGlob/...，= 驱动 parse_type_names 的
   find_by_name 面）；`::global` / `&::global.member` 实参形态从 DWARF
   文件域静态变量+一层成员表取证（GetStr 的 17 站点 `&::config.<char*域>`
   → char** 一致证据）。
5. **manifest**：`tests/golden/manifests/callee_siglock_curl_1204.json`
   （oracle_commit e40ed130 + golden sha256 + dwarf_types sha256 指纹齐备；
   双跑字节恒等）——**55 被调：30 全输入锁 + 26 返回锁**，7 drops
   （CARRY1/CONCAT44=伪 op 无 golden 头；__printf_chk/__fprintf_chk/
   __sprintf_chk/helpf/strequal=varargs 元数冲突——canon 自身未锁，弃收
   即方向）。GetStr(char**,char*)、getparameter(char*,char*,bool*,
   Configurable*)、parseconfig(char*,Configurable*)、fopen(char*,char*)、
   fclose(FILE*)、file2string(FILE*)、my_get_line(FILE*)、my_get_token(char*)
   等全输入锁；strtol/fgets/strchr 等槽证据不全（数字槽无证据）保持
   返回锁。

#### 16.5.3 oracle 预验证（锁定库 e40ed130 直跑，不可跳项）

stage_shape_diag harness 扩 `STAGE_CALLSITE_PROTOS=<hexaddr>=<doc>[,...]`
（followFlow 后、action 前，按入口地址把锁定 `<prototype>` decode 进
callspec——FuncProto::decode 需内部 store，经 scratch proto + FuncProto::copy
= coreaction.cc:2322-2330 的 queryCall 运输镜像；PLT 桩在 BFD harness 无
Funcdata，callspec 直装是唯一通路）。curl 内部静态符号带优化后缀
（parseconfig.constprop.0）——补地址查询回退。三函数 A0（种子+own 原型，
无被调原型）/ B（A0+manifest 全量 callsite 原型）双向实验：

| 实验 | my_get_token 空参 | GetStr 17 站点 | fgets 站点 |
|---|---|---|---|
| A0（无原型） | `my_get_token(0)` 裸 | `GetStr(0x175d0,nextarg)` 无 cast | `(&_Stack,0x100,p)` 裸 |
| B（manifest） | **`my_get_token((char *)0x0)` = canon 逐字** | **`GetStr((char **)0x17520,(char *)pCStack_5b8)`——(char*) 槽 cast 族全翻** | 返回锁 only，槽 cast 不出（证据保守） |
| C（canon 全真值上限） | — | — | **`(char *)&_Stack_148` 槽 cast 出现** |
| Rudra 现脸 | `(const char *)0x0`（DWARF const 漂移） | 无 cast | 无 cast |
| canon | `(char *)0x0` | `(&::config.useragent,(char *)local_5b8)` | `(char *,0x100,(FILE *)file)` |

A0→B 翻转普查：parseconfig 60 / getparameter 254 / file2string 55 原始行。
**判决：manifest 内容经锁定 oracle 验证有效（B 态的 cast 族=canon 形）；但
curl 的运输缺口与 httpd 相反**——curl 驱动的 link_call_specs 早已把 libc 表
+DWARF 原型装上 callspecs（getparameter 15 libc+28 DWARF 亲见 stderr），canon
cast 族在 Rudra 仍不显形，缺口在**消费侧**：`ActionSetCasts::cast_input` 的
opcode 分派表无 CALL 臂（src/coreaction.rs:5912 落 `input_metatype(opc)`→None
→reqtype=通用基型；Ghidra 的 TypeOp::getInputCast→`op->inputTypeLocal(slot)`
→TypeOpCall::getInputLocal（typeop.cc:687-718）→callspec 参型 typelock 锚，
cast.cc:310-337 指针剥层+尺寸差→cast 插入）。httpd 的 manifest 翻转经
implied 变量 typeprop 路线（strcmp((char*)plVar12[3])族）不触此臂；curl 的
主力族是**typelock 符号实参**（local_5b8: Configurable*）——必须走 cast_input
CALL 臂。**接线车道若只挂 manifest 不补该臂，curl cast 族近零翻转**。

#### 16.5.4 验证矩阵

| 门 | 结果 |
|---|---|
| harvest 双跑 | cmp 字节恒等 |
| manifest JSON | 有效；指纹=golden sha256 aca37988…/dwarf sha256 8af50bca… |
| curl 默认脸 | **577/0/0**（tools-only 构造性恒等，亲跑复证） |
| httpd 默认脸 | **951/0/0**（驱动未触，manifest 未装新面——callee_siglock_curl 仅 curl 键） |
| 投影银行 | **391/391 MATCH**（verify_projection_bank.sh exit 0 亲验） |
| src/ | 零触碰（git diff 亲父=tools+manifest+docs） |

#### 16.5.5 接线车道任务书要点（CURLWIRE，预留给下一车道）

1. **写域**：examples/curl_decompile.rs（CMTFILL 释放后）+ 可选 src/
   coreaction.rs cast_input CALL 臂。**顺序建议：先臂后 manifest**——臂单独
   即可翻 DWARF/libc 已在位的主族（GetStr 17 站点等）；manifest 的增量=
   const 漂移修正（my_get_token char* vs DWARF const char*）+ 无 DWARF/libc
   条目的被调 + canon 真值参型。
2. **cast_input CALL 臂移植**（铁律 1.2：先读 coreaction.cc:2655-2720 +
   typeop.cc:293-300 + typeop.cc:687-718 + cast.cc:300-390）：CALL 落
   TypeOp::getInputCast 基臂 = castStandard(getInputLocal(slot), highReadFacing,
   false, true)；机制 C 强制独立复核（coreaction 白名单）。
3. **manifest 装载**：照抄 httpd install_v3sig_callee_protos（canon 地址键
   entry+0x100000；resolve 用 find_by_name，FILE/Configurable 在 curl 驱动的
   parse_type_names 名树上）。转正评估（opt-out 极性）与 env 矩阵照抄
   V3FLIP 形态。
4. **httpd manifest 再生成**：括号修复后的 5 条目变化（16.5.2.1）需再生成
   +差分门禁重验（apr_getopt_init 假槽 int 消失、memcmp 假槽 long 消失、
   apr_dynamic_fn_retrieve 新增 char* 锁、apr_palloc 元数 2、
   apr_app_initialize slot2 undefined8**）——预期 httpd 脸无回退（变化条目
   原为 inert 或修复向），需亲测。
5. **PLT 全真值上限决策**：canon 的 PLT 桩头（golden 自印
   `char * fgets(char *__s,int __n,FILE *__stream)`）与调用点形一致
   （generic_clib 稳定源——原"无 Parameter ID 漂移"表述废弃：Parameter ID 未运行，一致性源于归档套用的稳定签名，见 16.1.1）——harvest 可选扩展：PLT
   被调接受桩头全参型（C 实验判决：`(FILE *)`/`(char *)` 槽 cast 族上限）。
   方法论注意：仅限 dynsym 导入桩（内部被调仍守调用点形规矩）。

#### 16.5.6 产物

- 证据：/dev/shm/rudra-tests/curlprep/（oracle_{parseconfig,getparameter,
  file2string}_{A0,B}.c/.err + oracle_file2string_C.c 上限证 + xml/ 全部
  种子/原型文档 + gen_curlprep_xml.py + run_curlprep_oracle.sh +
  classify_curl.py + callee_run2.json 确定性对照）。
- harness：stage_shape_diag.cc 增 STAGE_CALLSITE_PROTOS + 地址查询回退
  （/dev/shm/rudra-tests/shapefix/，随 lane 证据保留）。
- 回收：/dev/shm/rudra-targets/sb-curlprep 留 root 集成后回收。

### 16.6 MANIFREGEN 交付记录（Lane MANIFREGEN，2026-09-25，基=master 363c9cfd=CVRHOIST 后）

> HTTPD-MANIFEST-REGEN-0001：CURLPREP 的 harvester cast 括号修复（ba732be5）
> 对 httpd 侧 manifest 的下游重生成。写域=manifest+docs；src/examples/tools 零触碰。

#### 16.6.1 再生成 diff（5 条目，与 CURLPREP 预测逐条吻合）

harvest 命令：`python3 tools/harvest_local_manifest.py --callee
tests/golden/ghidra_httpd_1204.c httpd e40ed130… OUT.json`（缺省 targets=
main/ap_fini_vhost_config/ap_vhost_iterate_given_conn；httpd 形态不开
--dwarf-types 门）。golden sha256 与旧 manifest 逐字节同源（6b4c4f31…）。

| 条目（canon 键） | 旧 | 再生成 | 装载器效应 | 判决 |
|---|---|---|---|---|
| apr_palloc 0x12abc0 | 元数 1 无锁 | 元数 2 无锁 | 无（evidence-free 条目跳过；cast-result 括号误取根因） | inert |
| apr_app_initialize 0x12a6d0 | slot1 无证据 | slot1 `undefined8 * *` | 无（return-only 条目 params 不装载） | inert |
| apr_getopt_init 0x12a450 | 全锁 (long*,long,int,long) | 无锁 | 全锁→跳过 | 脸恒等（见 16.6.2） |
| memcmp 0x12acb0 | 全锁 (void*,undefined1*,long)→int | 仅返回锁 int | 输入锁消失 | **+7 回退→旧条目恢复** |
| apr_dynamic_fn_retrieve 0x12b070 | 无 | 新全锁 (char*) | 新锁装载 | Rudra 脸恒等；oracle 侧 canon 翻转亲证 |

净计数：27→26 全输入锁（−getopt−memcmp+dynfn）→ memcmp 恢复后回到
27 全输入锁 + 26 返回锁 + 3 drops（__printf_chk/ap_log_error/
ap_run_post_config，与旧恒等）。

#### 16.6.2 oracle 预验证（锁定库 e40ed130 直跑，stage_shape_diag
STAGE_CALLSITE_PROTOS；A0 与 SHAPEFIX oracle_main_seeded.c 字节恒等
=装置复刻亲证）

| 实验 | A0（种子 only） | B | canon | 判决 |
|---|---|---|---|---|
| main/dynfn | `func_0x0002b070(0x7a474)` 裸地址 | +char* 全锁→`(code *)func_0x0002b070("ap_signal_server")` | `apr_dynamic_fn_retrieve("ap_signal_server")` | **新锁=canon 翻转** ✓ |
| main/getopt | `(plVar11+10,plVar11[9],xVar1,xVar5)` | 旧假锁→`(plVar12+10,plVar12[9],iVar1,lVar2)`（canon-long 变量被重定型 int） | `(plVar12+10,plVar12[9],(int)lVar2,lVar9)` | 旧锁偏离 canon 变量定型；移除=修复向 ✓ |
| ap_fini/memcmp | `*(xunknown8 *)(…)` | 旧全锁→`*(void * *)(…)`+8 字节 cast==canon；return-only→退回 A0 形 | `*(void **)(…)`+`(long)` | **弱化丢 canon slot0 void\*\* 形** ✗ |

Rudra E2E 亲测与 oracle 预测一致：再生成为 manifest 时 ap_fini_vhost_config
80→87（+7：`*(void **)`→`*(undefined8 *)`、`pvVar5`→`lVar5` 重定型编号级联；
slot2 `(long)` cast 自然恢复保留=槽证据丢失本身脸中性）。恢复 memcmp 旧条目后
httpd 默认脸与基线**字节恒等**（908/0/0，env -i 本 worktree 口径；main 503/
ap_fini 80）。getopt 移除与 dynfn 新锁在 Rudra 脸均恒等（dynfn 字面量形
Rudra 自然恢复本就产出；新锁=oracle 侧正确的保守加固）。

#### 16.6.3 harvester 侧缺口登记（HARVEST-SCALARCAST-0001，tools 域别修）

CURLPREP ba732be5 把 `CALLEE_ARG_CAST` 的 `\*?` 改为 `\*+`——标量 cast
（`(int)x`/`(long)x`）不再构成槽证据。canon 调用点的标量 cast 恰是被提交参数
类型的直接强制证据（memcmp `(long)iVar6` = libc size_t 槽）；该缺口叠加
"全槽证据才锁输入"的 all-or-nothing 规则，使 memcmp 退化为 return-only 并
丢 canon slot0 void\*\* 形（16.6.2 第三行）。处置：本车道按"回退=剔除"恢复
memcmp 旧条目（oracle MOLD 实验=canon 形逐字），harvester 修复（标量 cast
证据恢复或部分槽锁策略）登记 TODO 另派 tools 车道。

#### 16.6.4 验证矩阵（manifest=再生+memcmp 旧条目）

| 门 | 基线（旧 manifest） | 本车道 | 判定 |
|---|---|---|---|
| httpd 默认脸 | 908/0/0 | **908/0/0 字节恒等** | ✓ |
| curl 默认脸 | 546/0/0 | **546/0/0 字节恒等**（curl 驱动不载 httpd manifest） | ✓ |
| 双跑确定性 | — | httpd stdout cmp 恒等 ×2 | ✓ |
| gcc 审计 | curl 104/20、httpd 15/14 | fail 集逐名恒等（tmp 路径除外） | ✓ |
| 投影银行 | 391/391 | **391/391 MATCH**（exit 0 亲验） | ✓ |
| manifest 指纹 | — | oracle_commit+golden_sha256 亲核 | ✓ |

## §18 CMTSEED 交付记录（Lane CMTSEED，2026-09-25，基=亲父 2dd4c813=master MANIFREGEN 后）

CMTFILL 移交件的 manifest 化+默认转正：注释通道从 /dev/shm 种子文件（opt-in
`RUDRA_CMTSEED=<tsv>`）升级为入库 manifest（harvester `--cmt` 模式一次性再生）+
驱动门反转（manifest 在库即默认装载）。

### 18.1 harvest --cmt 通道（tools/harvest_local_manifest.py 新模式，add-only）

`--cmt BINARY GOLDEN.c CORPUS ORACLE_COMMIT OUT.json`，方法=CMTFILL
build_cmt_seed.py 原样并入（独立函数，不触 --callee/--struct/--dwarf 既有代码）：

- **文本门控**：canon golden 的 `/* Unresolved local var: ... */` 块逐字提取
  （20 列 `/* ` 首行 / 23 列 commentfill 续行 / emitter 的 ` */` 尾剥除）——
  记录文本即 canon 自印文本，绝不从 DWARF 重拼类型拼写；
- **DWARF 锚**：函数域组→具体 subprogram low_pc；词法域组→scope low_pc，无
  low_pc 时 DW_AT_ranges 首区间 begin；组成员=location 为 DW_FORM_sec_offset
  或缺席的变量（exprloc 变量解析为命名局部，永不入注释记录）；
- **匹配**：逐函数按精确变量名序列、canon 顺序，一组一记录；
- **校准表**（curl 语料表入库+provenance）：CommentSorter::findPosition backup
  路径（comment.cc:298-306）要求 op.addr==comm.addr 精确命中——死代码化的入口
  prologue/落在指令中间的词法块起始锚没有存活 op，记录会被 excise。7 条 curl
  校准把 DWARF 锚重锚到 canon 锚定语句的首个存活 op（RUDRA_DUMP_FUNC dump；
  e40ed130 stage_cmt_diag oracle 复核=17 记录/45 行块逐字节==canon）；
- **产出**：canon 地址键（ELF vaddr+0x100000，与其他 manifest 同约定）、
  oracle_commit+binary/golden sha256 指纹齐备、harvest_rule 全文；非 curl 语料
  校准表为空表（原始 DWARF 锚直出，无 curl 数据继承——同 --struct 残差账本
  的语料隔离原则）。

### 18.2 manifest 与门反转（examples/curl_decompile.rs）

- `tests/golden/manifests/curl_cmt_1204.json`：8 函数/17 记录/45 行/7 校准/0
  drops；harvest 双跑 cmp 字节恒等；派生 (addr,text) 记录集与 CMTFILL
  /dev/shm 种子文件**逐字节恒等**（亲测 diff）。
- 门极性（SEEDFLIP 同式）：默认开（manifest 在库即装）→ `RUDRA_CMTSEED=0`
  单通道逃生 / `RUDRA_SEEDS=0` 全局裸脸逃生 / mirror 三组件恒拒（投影银行
  纯度）/ manifest 缺失或坏 JSON=loud no-op（任意无 manifest 二进制=裸脸）。
- `RUDRA_CMTSEED=<path>` 保留为 manifest 路径覆盖（JSON 形）；**CMTFILL 的
  TSV 种子文件形态退役**（被入库 manifest 取代；oracle harness stage_cmt_diag
  侧契约不受影响）。注意一处组合语义变化：旧 TSV 门不受 RUDRA_SEEDS 约束，
  现全局逃生优先于通道门（`RUDRA_SEEDS=0`+`RUDRA_CMTSEED=<path>`=不注入）。
- 注入语义不变：type=warning、fad=目标入口、[vaddr,vaddr+size) 窗过滤、
  生产 CommentDatabaseInternal::add_comment；manifest 地址为 canon 空间，
  插入前重基到 ELF 相对（op 树同空间）。

### 18.3 验证矩阵（亲测，基=亲父 2dd4c813，curl 546/httpd 908）

| 门 | 基线 | 本车道 | 判定 |
|---|---|---|---|
| curl 默认脸（=原注入脸） | 546/0/0（Matched 124） | **489/0/0**（−57=45 注释行+对齐回声；Matched 124 不降） | ✓ |
| 新默认脸 vs CMTFILL oracle 复核脸 | — | **cmp 字节恒等**（逐函数零回退由此继承） | ✓ |
| `RUDRA_CMTSEED=0` | — | **==基线默认脸 cmp 字节恒等** | ✓ |
| `RUDRA_SEEDS=0` | 基线全局裸脸 | ==旧驱动 `RUDRA_SEEDS=0` 脸 cmp 字节恒等（旧驱动 A/B 重建对照） | ✓ |
| mirror（match_url 单函数） | — | 旧/新驱动输出 cmp 字节恒等+stderr 仅"gate ignored"一行 | ✓ |
| httpd 默认脸 | 908/0/0 | **908/0/0 恒等**（stripped 语料,通道 no-op） | ✓ |
| gcc 审计 | 104 OK/20 FAIL | 同比,**逐名 verdict 恒等**（注释行不入 fail 集） | ✓ |
| 投影银行 | 391/391 | **391/391 MATCH**（exit 0 亲验） | ✓ |
| 双跑确定性 | — | 驱动 stdout cmp 恒等 ×2；harvest manifest cmp 恒等 ×2 | ✓ |
| Unresolved 行数 | canon 45 | **45==45** | ✓ |

机制 C：tools/examples 驱动域豁免（无 src/ 改动）；机制 B：examples 驱动不
在白名单模块,但按 B2 精神保留了与 CMTFILL oracle 复核脸的逐字节对照（上表
第二行）。
### 16.7 HARVESTFIX 交付记录（Lane HARVESTFIX，2026-09-25，基=master 2dd4c813=MANIFREGEN bridge 后）
HARVEST-SCALARCAST-0001（P2）收口：16.6.3 登记的 harvester 侧标量 cast 证据缺口
在 tools 域修复。
#### 16.7.1 修法（一句话）
`CALLEE_ARG_CAST` 的星号量词 `\*+` → `\**`（零或多星）——是 CURLPREP 前
`\*?`（0/1 星，标量 `(long)x` 是槽证据）与 CURLPREP `\*+`（1+ 星，
`(char **)0x0` 保留星数）的严格并集：标量 cast 证据恢复、多星增益保持、
零星路径落回 `\*?` 的既有语义（`_arg_evidence` 的 `return base` 分支本就在）。
#### 16.7.2 双 manifest 再生成组成对比
httpd（命令=16.6.1 形态，缺省 targets，不开 --dwarf-types）：
60 被调 = 28 全输入锁 + 26 返回锁 + 3 drops（drops 恒等）。与提交态的 diff
= 2 条目：
| 条目 | 提交态 | 再生成 | 处置 |
| memcmp 0x12acb0 | 全锁 (void*,undefined1*,long)→int | **逐字节恒等**（`(long)iVar6`/`(long)*(int *)` 标量证据自然恢复全锁） | 修复验证本体 ✓ |
| apr_getopt_init 0x12a450 | slot2 无证据（inert） | 全锁 (long*,long,int,long)（`(int)lVar2` 标量证据恢复=V3SIG 原始形） | **恢复提交态**（16.6.2 假锁判例，16.7.3 本车道 oracle 复判） |
getopt 条目恢复后再生成输出与提交 manifest **字节恒等**——httpd manifest
文件零改动（memcmp 旧条目从此由修复后的 harvester 自然可再生，不再依赖
手工恢复）。纯再生（getopt 带锁）的 httpd 脸亦字节恒等（A/B 亲测）——
假锁处置是 oracle 侧保守性，非脸必要性。
curl（命令=16.5 CURLPREP 形态：--dwarf-types=examples/curl + 全 17 targets）：
55 被调 = 30 全输入锁 + 26 返回锁 + 7 drops（计数与 drops 恒等；
golden/dwarf sha256 恒等；harvest_rule 文本随规则更新）。4 条目组成变化：
| 条目 | 旧 | 新 | 判定 |
| SetHTTPrequest 0x103c50 | 仅返回锁 int | 全锁 (HttpReq,HttpReq*)→int（`(HttpReq)pCVar13` 标量 cast 证据） | **新锁=canon 翻转**（16.7.3 oracle 亲证；且与 canon golden 头 `int SetHTTPrequest(HttpReq req,HttpReq *store)` 逐字一致） |
| malloc 0x102430 | 全锁 (size_t) | 无锁 | 真冲突弃收：canon 站点 `__n + 1`（size_t decl 证据）vs `(long)(iVar3 + 1)`（标量 cast 证据）冲突，conflict-sensitivity 按设计不锁 |
| realloc 0x102470 | slot1 无证据 | slot1 `long`（`(long)puVar9 +` 标量证据） | inert（input_lock=false 条目 params 不装载） |
| strnequal 0x102570 | slot2 无证据 | slot2 `long`（`(long)(int)sVar5` 标量证据） | inert（同上） |
#### 16.7.3 oracle 预验证（锁定库 e40ed130 直跑，stage_shape_diag
STAGE_CALLSITE_PROTOS；装置复刻：httpd main A0 与 SHAPEFIX
oracle_main_seeded.c 字节恒等、curl getparameter A0 与 CURLPREP
oracle_getparameter_A0.c 字节恒等）
| 实验 | A0 | +锁（MOLD） | canon | 判决 |
|---|---|---|---|---|
| httpd ap_fini/memcmp 全锁 | `*(xunknown8 *)(…)` | `*(void * *)(…)`（slot0 形恢复） | `*(void **)(…)` | **修复验证** ✓（=16.6.2 第三行复判） |
| httpd main/getopt 全锁 | `(…,xVar1,xVar5)` | `(…,iVar1,lVar2)`（canon-long 变量被重定型 int、无 cast） | `(…,(int)lVar2,lVar9)` | **假锁复判**：偏离 canon 变量定型 → 不采纳 ✓ |
| curl getparameter/SetHTTPrequest 全锁 | `SetHTTPrequest.part.0()`（无参形） | `SetHTTPrequest.part.0((HttpReq)flag,(HttpReq *)nextarg)` | `SetHTTPrequest((HttpReq)pCVar13,(HttpReq *)pCVar10)` | **新锁=canon 翻转**：实参 cast 形逐字 ✓（名/后缀属符号层与种子层，正交） |
#### 16.7.4 验证矩阵（httpd manifest 零改动 + curl manifest=纯再生）
| httpd 默认脸（env -i） | 908/0/0 | **908/0/0**（compare_ghidra 口径 908 skeleton/0 defects/0 numbering；双跑 cmp 恒等；纯再生 A/B 恒等） | ✓ |
| curl 默认脸（env -i） | 546/0/0 | **546/0/0**（双跑 cmp 恒等；新/旧 manifest 字节 A/B 恒等=驱动不载该文件亲证） | ✓ |
| gcc 审计 | curl 104/20、httpd 15/14 | 同计数 | ✓ |
| manifest 指纹 | — | oracle_commit+golden_sha256+dwarf_types_sha256 亲核恒等 | ✓ |
写域遵守：examples/ 零触碰（CMTSEED/PARAMID 并行车道租约）；
harvest_local_manifest.py 仅改 CALLEE_ARG_CAST 证据区与规则文本句
（CMTSEED 的 --cmt 模式函数未触，合并冲突由 root 并集解）。
## §17 PARAMID 交付记录（Lane PARAMID，2026-09-25，基=亲父 363c9cfd=master CVRHOIST 后）
> HEADLESS-BRIDGE-PARAMID-0001：Decompiler Parameter ID 自宿主迭代环（通道
> 命名沿用历史；机制叙述已改判[16.1.1]——canon 无 Parameter ID 提交层，环的
> 工程语义=V3SIG 运输层的自宿主化，验收面不受影响）——把
> V3SIG 通道的输入从 harvested manifest 换成运行时自产数据
> （`RUDRA_PARAMID=1` opt-in）。写域=`examples/httpd_decompile.rs`+docs；
> src/ 零触碰（判定标准=manifest 输出行为等价，编排层车道）。证据
> /dev/shm/rudra-tests/paramid/（保留至 root 集成）。
### 17.1 迭代环形态（一句话）
**round1 裸反编译（不装任何锁）→ 从管线终态按调用点收集证据（被调入口/机器元数/
槽位类型/返回消费类型——varnode 终态类型，非打印文本）→ 按 harvest 合并规则
构造与 manifest 同形的锁表 → round2 起以自产锁表复用 V3SIG 三锁装载臂
重跑 → 单调迭代至不动点或 3 轮 → 最终打印 pass 装最终自产表。**
关键设计决定（各带实验判决）：
1. **迭代宇宙** = 打印窗口（29 函数，同 ledger 同 skip filter）∪ 前端
   analyzer-discovered 调用目标（46 个 = call_targets∪code_ref，PLT 桩除外；
   extent=下一已知入口邻界，8192 封顶——前端邻居启发式镜像）。
   （宇宙边界原以"Parameter ID 只对反编译过的函数提交签名"类比论证——类比
   已废弃[16.1.1]，现语义=自产环固有的证据可得域：只对反编译过的函数能采
   调用点证据，与 canon 机制无关。）
2. **提交负载=调用点证据**（callee 侧 fd.funcp 方案被实验否决）：canon 自身
   的被调 header 与调用点形漂移（16.1 记录的
   ap_setup_prelinked_modules 自印 `char* f(undefined8*)` vs 调用点
   `(long*)→long`；原标签"Parameter ID 迭代漂移"废弃——成因=被调无提交
   原型下两侧独立恢复[16.1.1]）；直接锁 callee 侧恢复原型把脸打坏（1189 > 裸 1097，
   74 条全锁、精确率 5%/召回 11% 的实测）。调用点证据读的是与
   harvest 同义的信息：untyped varnode（undefined 族标量）=「无证据」形，
   指针型 varnode =「x[k]/&x/(T*)」形，活 CALL 输出=已消费返回形。
3. **合并规则=harvest 移植**：元数冲突弃收（varargs）；槽位证据冲突杀槽；
   undefined 族标量默认不算证据（strict——canon 文本里的裸 undefined8 局部
   是 analyzer 已提交的形态，而 Rudra 每个 untyped varnode 都是 undefined<N>，
   loose 模式（`RUDRA_PARAMID_EVIDENCE=loose`）作为召回量具保留）；
   全槽证据齐→input lock；活消费类型一致→return lock（无 cast 探针，为
   近似，实测返回侧零冲突）。
4. **锁定站点继续出证据**：typeprop 后其 arg varnode 类型=锁回声，迭代因此
   单调（锁→类型→证据→锁），实测 30→31→31 不动点（先前的跳过锁定站点
   版本在 65→3→64 振荡——Ghidra 的重推导语义是继续采证，提交因复得而持久）。
5. **PLT 槽条目整体弃收**：imported external location 不是被反编译函数，
   canon 对那些槽的锁来自 import-signature 通道（generic_clib），本车道不
   自宿主该通道。实测带 PLT 锁 1072（ap_update/ap_matches 族过锁 +21 回归）
   vs 弃收后 1038。
6. **门极性**：mirror 恒拒（投影纯度）→ RUDRA_SEEDS=0 全局逃生 →
   RUDRA_PARAMID=1 opt-in（接管 callee-siglock 通道，manifest 装载跳过并
   日志）；`RUDRA_PARAMID_ROUNDS`（默认 3，clamp 1..=3）；
   `RUDRA_PARAMID_DEBUG=1` 逐条 dump；`RUDRA_PARAMID_COMPARE=0` 关对拍。
### 17.2 对拍（自产锁 vs manifest 60 锁）
| 配置 | 表条目 | overlap | exact | shape-diff | manifest-only | self-only | 精确率(entry) | 召回率(entry) | 槽位 equal/diff/m-only/s-only | 返回 equal/diff |
|---|---|---|---|---|---|---|---|---|---|---|
| strict（默认） | 31 | 17 | 5 | 12 | 43 | 14 | 29.4% | 8.3% | 18/10/8/1 | 9/0 |
| loose（量具） | 58 | 24 | 10 | 14 | 36 | 34 | 41.7% | 16.7% | 26/15/0/5 | 13/0 |
- **返回锁零冲突**（strict 9/9、loose 13/13+2 diff）：活消费类型侧证据与
  canon 完全同形。
- **manifest-only 43 的构成**：33 条 PLT/import 域（import-signature 通道，
  车道边界外）+ 8 条槽位证据缺失（我们调用点 untyped：ap_getnameinfo/
  strncasecmp/ap_process_config_tree/ap_mpm_query 族——裸恢复里实参就是
  undefined 族标量）+ 2 条调用点属主在迭代宇宙外（strcasecmp 的唯一调用者
  = switchD caseD 发射环的 0x154470 处理器，不在 ledger/调用目标宇宙）。
- **shape-diff 主族=槽位内容差**（10 槽）：自产 `undefined8*` vs canon
  `long*`（ap_setup_prelinked_modules/ap_run_rewrite_args——pointee 无类型，
  typeprop 残差域）、自产 `undefined1*`/`int*` vs canon `long`（ap_fini/
  ap_mpm_run/FUN_12c8e0——深类型分歧）、`int*` vs `void*`（memcmp 槽 0）。
  全部为恢复质量域（typeprop/UND224/typeOrder，登记域 V3SIG-UND224
  -TYPEORDER-0001 同族），非迭代深度差（不动点已达成）。
### 17.3 验收矩阵
| 门 | 数字/结果 | 判定 |
|---|---|---|
| 默认脸（env 全空） | cmp 亲父基线字节恒等 | ✓（重构后复证） |
| RUDRA_V3SIG=0 | cmp 其亲父基线字节恒等 | ✓ |
| mirror（±RUDRA_PARAMID=1） | 恒拒（显式日志）+ 输出 cmp 恒等 | ✓ |
| RUDRA_SEEDS=0+PARAMID=1 | 门静默关闭（全局逃生） | ✓ |
| PARAMID=1 strict | **1038/0/0**（34 函数；裸 1097、manifest 908） | 收回 manifest 增益的 31%（−59/−189），零 defects/numbering |
| PARAMID=1 loose | 1071/0/0（过锁伤脸，量具态保留） | 记录 |
| PARAMID 双跑 | cmp 恒等 | ✓ |
| 迭代收敛 | 30→31→31 不动点（3 轮上限内） | ✓ |
| 投影银行 | 391/391 MATCH（exit 0） | ✓ |
| gcc 审计 | 15 OK/14 FAIL ==默认脸同名集 | ✓ |
| src/ | 零触碰（git diff=examples+docs） | ✓ |
| curl | 驱动与库未触（构造性不变） | ✓ |
**逐函数（vs 裸/manifest 态）**：ap_fini_vhost_config 148→**89**（manifest
80；void*/返回消费族大头）· main 611→**590**（manifest 503；long* 族未翻
=槽位内容差域）· ap_matches_request_vhost 6→13（+7 回归）·
ap_update_vhost_from_headers 56→70（+14 回归）——两处回归=自产锁内容差
（int*/undefined1* 锚进调用链）把裸态的自然 long 族改写，属同一恢复质量域；
其余 30 函数与裸态恒等。
### 17.4 差距归因（1038 vs 908 的 130 行）
1. **main 87 行**：manifest 的 (long*)→long/ap_run 族锚未自产——调用点
   实参在 Rudra 恢复里是 undefined8*/undefined 族（无 strict 证据或锁成
   undefined8*），canon 调用点显形 long* 靠其 typeprop 质量。迭代深度非因
   （不动点已到）。
2. **ap_update 族 21 行**：自产 int* 锁的级联（见 17.3 逐函数）。
3. **caseD 4 行**：strcasecmp 无自产条目（调用点属主在宇宙外）。
4. **其余 ~18 行**：ap_fini/ap_matches 的槽位差级联。
### 17.5 机制声明与移交
- 机制 C：examples 写域豁免（src 零触碰）。
- 机制 B：examples 非白名单；Differential 精确率表随 commit（17.2）。
- **移交排队**：①槽位内容差的根因在 typeprop/类型传播（src 域，
  V3SIG-UND224-TYPEORDER-0001 同族登记域）——自产环已把「差在哪」量化成
  逐槽表；②switchD caseD 处理器纳入迭代宇宙（当前 strcasecmp 类唯一调用
  者不在 ledger/调用目标面）；③loose 模式若要转正需先解决 undefined 族
  标量过锁（当前仅量具）。
- 回收：/dev/shm/rudra-targets/sb-paramid 留 root 集成后回收；lane 证据
  /dev/shm/rudra-tests/paramid/。

## §17.6 PARAMID2 交付记录（Lane PARAMID2，2026-09-25，基=亲父 09739f13=master PARAMID 后）
> HEADLESS-BRIDGE-PARAMID2-0001：自产签名提精度——差距分解驱动的四条
> strict 守卫 + 默认证据层翻转。写域=`examples/httpd_decompile.rs`+docs；
> src/ 零触碰。证据 /dev/shm/rudra-tests/paramid2/（保留至 root 集成）。

### 17.6.1 差距根因（逐条实证，RUDRA_PARAMID_SITES=1 逐站点 dump）
1. **回退根因（ap_matches +7 / ap_update_vhost +14）**：FUN_0012ce20 的
   slot0 在 round 1 是真冲突（ap_matches 站 `int *` vs ap_update 站
   `long`，合并正确杀槽）；round 1 的 ret=int 锁经 typeprop 涟漪改写
   ap_update 站点链上的 varnode 类型，round 2 两站都显 `int *`——
   逐轮新鲜合并把 round 1 的冲突"忘了"，毒锁落表并把 server_rec 链
   改写成 `piVar15` 形（`*(long*)(lVar14+0x80)`→`*(long*)(piVar15+0x20)`）。
2. **窄整型指针证据类**：canon 60 锁表 0 条 `int */uint */short */ushort *`
   （拼写普查：long 37/int 1/char* 12/long* 9/undefined8 9/undefined8* 5/
   undefined1* 3/undefined* 1/undefined4* 1/undefined8** 1/void* 1）；
   Rudra 把 canon 恢复为宽标量（long）的链 typeprop 成了窄整指针——
   两条回退 + strncmp/memcmp/ap_sockaddr_equal 毒锚全部同根。
3. **退化 0 元调用点**：main caseD 发射环的 `strcasecmp()`（bare 脸
   line 471；canon 同位 `strcasecmp((char *)__s1,"crit")`）——lift 丢参
   线，作为站点证据是伪 0 元数，按元数冲突规则杀死整条目。
4. **观测不全站点**：FUN_0012ce20 在 ap_matches 的站点（策略后）零贡献
   ——锁它=对未采样的调用者外推，实测把 ap_matches 自己的签名改型
   （头行 undefined8→int + param_2 undefined8→long，canon golden 从不
   如此）。

### 17.6.2 四条守卫 + 默认层翻转（全部实测判优）
| 策略 | 机制 | 判决 |
|---|---|---|
| **sticky 冲突记忆** | 槽/返回/元数在任一轮冲突→永久死（harvest 单遍语义=全部轮观测的并集；锁回声不得翻案） | 单独 1038→1018；被 ②吸收后无独立增量但保留（防御其他类） |
| **窄整指针降级** | `int */uint */short */ushort *` 在证据层=无证据（canon 0 条的 oracle 实测；根因是恢复残差不是策略差） | 1038→1016；回退主修 |
| **退化站点过滤** | 0 元数站点 vs 正元数共识=lift 伪迹（非 varargs；真 varargs 仍是正元数间冲突：__printf_chk 2/5/7） | 中性（PLT 关闭时 strcasecmp 不在域）；保留防御 |
| **静默站点否决**（sticky） | 多站点 callee 有一站零贡献（无槽证据+无活返回消费）→不提交（观测不全）；回声不算补证 | 1016→1015，ap_matches +1 清零 |
| **默认证据层=全形态** | undefined 族标量计证据（canon 自己锁 9×undefined8+5×undefined8*）；守卫齐备后实测反超 | **1015→1009**；精确率 18.8%→63.2%（§17 的 1071 是无守卫 loose——守卫才是缺件，不是准入规则） |
| 负结果：PLT 准入（RUDRA_PARAMID_PLT=1） | 36 条自证 PLT 锁 | 1019/1023 vs 1016——所有配置净负，维持整体弃收 |
| 负结果：分阶段层（RUDRA_PARAMID_ROUND1=strict） | r1 保守层采证 | 1015 vs 1009——保守层把 undefined8 读成"无证据"制造静默站点误触发否决；守卫必须与喂它的层同层 |

**机制注记（默认层为何反超）**：迭代回声不止单调——round 1 全形态锁
落表后，typeprop 把宽标量链重定型，round 2+ 的证据拼写成 `long *`
（ap_run_rewrite_args/ap_setup_prelinked_modules/ap_read_config slot0/
FUN_0012c550 从 `undefined8 *` 自举到 manifest 精确形）。§17.2 的
`undefined8 *` shape-diff 主族由此收敛。

### 17.6.3 对拍（自产 vs manifest 60 锁，默认=守卫全形态）
| 配置 | 条目 | overlap | exact | 精确率 | 召回率 | 槽位 eq/diff/m-only/s-only | 返回 |
|---|---|---|---|---|---|---|---|
| §17 基线 strict | 31 | 17 | 5 | 29.4% | 8.3% | 18/10/8/1 | 9/0 |
| **PARAMID2 默认** | **49** | **19** | **12** | **63.2%** | **20.0%** | **20/1/11/3** | **13/0** |
| 保守层（=strict 逃生门） | 28 | 16 | 3 | 18.8% | 5.0% | 10/9/15/1 | 9/0 |

manifest-only 43→41 = **33 导入域**（PLT/import-signature 数据通道，
binary stripped 无 DWARF 可读——`readelf -S` 仅 .dynsym；canon 的锁来自
generic_clib 签名库按名应用，自宿主需签名库数据通道，登记见 17.6.5）
+ **8 in-text**：4 条 inert（FUN_0012c520/ap_run_optional_fn_retrieve/
ap_show_directives/ap_show_modules——canon 通道也什么都不装，零脸差）
+ 3 条恢复残差槽冲突（ap_fini_vhost_config/ap_fixup_virtual_hosts
slot0 `undefined1*` vs `undefined8` 两站不一致；FUN_0012cbd0 slot1
`undefined8*` vs `long*`——sticky 杀，脸中性）+ 1 条降级代价
（FUN_0012c8e0 slot0 `int *` 被降级，manifest 是 `long`；实测不锁更好：
87 vs 89）。"2 窗外"旧分类修正：strcasecmp 的退化站点在 main 窗内
（caseD 发射环），属上述退化类，非窗外。

### 17.6.4 验收矩阵
| 门 | 数字/结果 | 判定 |
|---|---|---|
| 默认脸（env 全空） | cmp 亲父基线字节恒等 | ✓ |
| RUDRA_V3SIG=0 | cmp 亲父基线字节恒等 | ✓ |
| mirror（±RUDRA_PARAMID=1） | 恒拒（显式日志）+ 输出 cmp 恒等 | ✓ |
| RUDRA_SEEDS=0+PARAMID=1 | 门静默关闭 + 输出与纯 SEEDS=0 恒等 | ✓ |
| **PARAMID=1 默认（守卫全形态）** | **1009/0/0**（裸 1097、manifest 908；收回 88/189=**46.6%**，§17 为 59/189=31.2%） | 零 defects/numbering |
| 逐函数 vs 裸态 | ap_fini 148→87、main 611→584；**ap_matches 6→6、ap_update_vhost 56→56——回退清零**；其余恒等 | ✓ |
| 保守层逃生门（EVIDENCE=strict） | 1015/0/0（=守卫 strict 形） | ✓ |
| 迭代收敛 | 50→49→49 不动点（3 轮上限内） | ✓ |
| PARAMID 双跑 | cmp 恒等 | ✓ |
| 投影银行 | 391/391 MATCH（exit 0） | ✓ |
| gcc 审计 | 15 OK/14 FAIL==默认脸同名集 | ✓ |
| curl | 驱动与库未触（cargo check + E2E 差分，构造性不变） | ✓ |
| src/ | 零触碰（git diff=examples+docs） | ✓ |

### 17.6.5 剩余差距登记（101 行 = 1009 vs manifest 908 的逐函数构成）
1. **main 81 行**（584 vs 503）：long/long* 锚族的 var 级涟漪（typeprop
   域，V3SIG-UND224-TYPEORDER-0001 同族；自产环已把可自举的部分收敛，
   残余=canon typeprop 产 long 形而 Rudra 产 undefined 族形的点差）。
2. **导入域族 ~16 行**：ap_matches 4 + ap_update_vhost 5 + ap_fini 7
   （memcmp 全锁 [void*, undefined1*, long] slot0 的 void* 形——canon
   调用点带 cast；Rudra 无 void* 恢复）——全部经由 canon 的 33 条
   import-signature 锁（strcasecmp/strncmp/memcmp/apr_ctone 族）作用，
   binary stripped 无 DWARF 可直读（readelf -S 仅 .dynsym），自宿主需
   签名库数据通道（登记为数据通道缺口，驱动域不可自产）。
3. **caseD 4 行**：strcasecmp() 退化调用点的参数恢复缺陷（lift 丢参线，
   src 域登记；canon 的 arity-2 锁同位可物化参数——锁通道已证，缺的是
   参数恢复本身）。
- 回收：/dev/shm/rudra-targets/sb-paramid2 留 root 集成后回收；lane 证据
  /dev/shm/rudra-tests/paramid2/。

## §17.7 IMPORTSIG 交付记录（Lane IMPORTSIG，2026-09-25，基=亲父 7090eb8c）

**判决（车道首问：导入函数的原型是否已被 PARAMID 环用上）**：**未在**。
httpd 驱动从不查询任何导入签名源——callspec 状态只靠
`external_prototypes`（HashMap<u64,usize> 参数计数，唯一消费者是
ActionDeindirect 的存在性检查）+ inject-path qlst 注册
（CALLSPEC-DRIVER-0002）；PARAMID 环在合并步整体弃收 PLT 槽证据；
binary stripped 无 DWARF。46.6% 恢复内含导入锁为零，§17.6.5 的 ~16 行
残余正是该缺口。

**通道形态（IMPORTSIG-DRIVER-0001）**：generic_clib 数据等价物 =
`LibcSignatureTable`（库内 24 条 curl 导向表；httpd 交集 12 条经公共
`lookup` 消费——首个库表消费者）+ 驱动侧 httpd 扩展 47 条
（`HTTPD_IMPORT_SIGNATURES`，拼写=锁定 oracle golden 的 thunk 头逐字，
glibc `__` 保留名含）。数据判据=canon 对拍：golden 内 124 条
"Unknown calling convention" 横幅锁定 59 个唯一 libc thunk 签名
（每 thunk 双打印）；7 个导入 canon 不锁（__fprintf_chk/
__isoc99_sscanf/__printf_chk/__stack_chk_fail/__strncat_chk/__syslog_chk/
apu_version_string）——不在 ledger（锁它们=发明 canon 没有的签名）。
装载臂 `install_import_signatures` 与 V3SIG 同位（inject 后、action 管线
前），走库公开面 `FuncProto::from_model_carrier +
update_all_types_from_pieces`，完整复刻 `LibcSignatureTable::locked_proto`
的边界态（per-param NAME_LOCKED fspec.cc:3503-3506/:3564、
input/output/model 三锁、"unknown" 约定名）。结构基类型
（FILE/rlimit/sigaction/sigset_t/tms/group/passwd/__compar_fn_t）在
驱动 TypeFactory 无对应物→逐条跳过+日志（无一在打印窗口被调）。

**门控**：analyzer transport——`RUDRA_PARAMID=1` 时开（本车道验收脸）、
`RUDRA_IMPORTSIG=1` 独立量具、`RUDRA_IMPORTSIG=0` A/B 断路、mirror/
`RUDRA_SEEDS=0` 绝对优先。默认脸构造性不动（门全关=死代码）。

**数字（fast-release 亲测，A/B=HEAD 7090eb8c 二进制 cmp 逐字节）**：
- PARAMID 脸 **999→753/0/0**（−246）；默认脸 **898 字节恒等**；
  mirror/V3SIG=0/SEEDS=0 三门禁新旧二进制恒等；PARAMID 双跑恒等；
  `RUDRA_IMPORTSIG=0` 下 PARAMID 脸与改前字节恒等（−246 全归因本通道）。
- 逐函数 **0 回退**，11 函数改善：main −113、ap_update_vhost −34、
  ap_pregsub −20、ap_getword −18、ap_make_dirstr_parent −17、
  ap_fini −13、ap_field_noparam −12、ap_os_is_path_absolute −6、
  ap_strcasecmp_match −5、ap_matches −4（§17.6.5 登记的 4 行全收）、
  caseD −4（4→0——strcasecmp 锁使退化站点印出 canon 形）。
- PARAMID 自产表 49→51（导入锁的参数类型经 typeprop 改善内部 callee
  证据）；对拍 overlap 19→20/exact 13→14/precision 68.4%→70.0%/
  slots equal 21→23/different 0。PLT 槽仍从自产表弃收（归因不变且被消融
  正面证实[r5]：canon 的导入锁来自签名通道=Apply Data Archives/generic_clib_64
  而非 Parameter ID[ELF 下从未运行]，16.1.1）。
- bank 391/391 exit 0；cargo test --lib 1725P/1F（nonzeromask 预存，
  lib 未触碰）。

**残余归因更新（§17.6.5 的 16 行收口）**：导入域族 ~16 行**全收**；
ap_matches 剩 2 行=pRam code* 残差（非导入域）；ap_update 剩 22/
ap_fini 剩 70=typeprop/pRam 域（V3SIG-UND224-TYPEORDER-0001 同族）。
新登记 `IMPORTSIG-STRUCTBASES-0001`（P3）：9 条结构基类型 ledger 条目
惰性（freopen/qsort/sigaction/sigaddset/sigemptyset/times/getgrnam/
getpwnam/getpwuid/getrlimit——canon 锁、Rudra 工厂无名、窗口外零可观测）。
另：canon 对 ap_strchr/ap_strrchr/ap_strstr(±_c) 六个内部包装函数也带
锁+横幅（原归因"Parameter ID 提交域"已证伪——Parameter ID 未运行；该
横幅层经 r5 消融整体归 archive 域[locked-warn 124→0 含之，按名套用 vs
传递 typeprop 的子机制未逐项分解，16.1.1]——PARAMID 自产表覆盖范围，
非本车道缺口）。

证据=/dev/shm/rudra-tests/importsig/（含改前后 A/B 双二进制与全部门禁
输出）；target /dev/shm/rudra-targets/sb-importsig 留 root 集成后回收。

### 17.7.1 IMPORTSIG-STRUCTBASES-0001 收口（Lane STRUCTB，2026-09-25，判例）

**结论：补齐落地 + 实测收益 0 行（<5 行阈值）→ 判例收口。**
数据准则（canon 锁定普查）与脸收益不匹配时的诚实处理：census 数据
真实存在且补齐后通道行为与 canon 一致（11 个跳过点全部转正），
但打印窗口内零可观测——登记关闭，不宣称脸改善。

**盘点勘误**：原登记"9 条结构基类型条目"实列 **10 个名字**
（freopen/qsort/sigaction/sigaddset/sigemptyset/times/getgrnam/
getpwnam/getpwuid/getrlimit）；按基类型口径=9 条 struct 条目
（FILE/rlimit/sigaction/sigset_t/tms/group/passwd 分布于 9 个函数条目）
+qsort 的 `__compar_fn_t` 函数指针 typedef（+getrlimit 首参
`__rlimit_resource_t` enum typedef 同跳）。运行期唯一触发面=
**ap_mpm_run**（迭代宇宙成员、非打印窗口）：每次反编译 21 锁+11 跳
（sigaction×8/sigaddset×2/sigemptyset×1 首错位点）。

**census 数据源（锁定 golden tests/golden/ghidra_httpd_1204.c，oracle
e40ed130；stripped 无 DWARF → 硬数据入账本）**：
- `sigset_t`：ap_mpm_run `sigset_t local_c0;`（@-0xc0，下个 local
  @-0x40）→ **128 字节**；仅整体 `&` 使用（sigemptyset/sigaddset），
  无成员路径 → canon 形=不透明 128 字节。
- `sigaction`：ap_fatal_signal_setup `sigaction local_b8;`（@-0xb8，
  下个 @-0x20）→ **152 字节**；canon 成员路径 `.sa_mask`（整体 & 进
  sigemptyset→sigset_t 值成员）、`.sa_flags`（赋 -0x80000000→4 字节
  int）、`.__sigaction_handler.sa_handler`（赋 FUN_→code*；两级路径
  证明 union 成员）。glibc x86-64 位置：union@0(8)/sa_mask@8(128)/
  sa_flags@136(4)；sa_restorer@144 canon 未印不录，152 尺寸显式保留。
- `group`：canon 印 `->gr_gid`（ap_gname2id）→ oracle 侧为带字段的
  archive 形；成员=glibc grp.h x86-64（gr_name@0/gr_passwd@8/
  gr_gid@16 uint/gr_mem@24，size 32）。
- `passwd`：canon 印 `->pw_name`/`->pw_uid` → glibc pwd.h x86-64
  全形（pw_name@0..pw_shell@40，size 48）。
- `FILE`/`rlimit`/`tms`：canon **仅** thunk 头拼写（`FILE *` 等；六个
  FILE 指针声明、零字段路径、零值本地、零 extent）→ canon 形=仅名
  incomplete struct（构造带尺寸字段形=发明 canon 无数据）。
- `__compar_fn_t`=code* 的 typedef（8 字节）；`__rlimit_resource_t`
  =4 字节 uint 形 typedef（glibc enum）。

**实现**（examples/httpd_decompile.rs，库公开面 create_struct/
set_fields_sized/get_type_union/set_union_fields_sized/get_type_code/
get_typedef）：census 表 `CANON_GLIBC_STRUCT_BASES`（7 struct+1 union+
2 typedef）+ `intern_canon_glibc_struct_bases` 在 main 内
tracked_context_architecture 之后**单线程预注册**进共享工厂（工厂是
全线程共享的单一 Arc<RwLock>——若在每次调用的解析里惰性注册，竞态
窗口可能让某轮拿到 pointer-to-incomplete、后轮拿到完成形=跑跑不确定
性；预注册后 `resolve_import_type` 的 `other` 臂 find_by_name 直接命中，
解析路径零改动）。已有同名类型（未来 TYPESEED 等）优先保留、census
跳过并计数。

**验证（fast-release 亲测，A/B=HEAD 596fcd5f 双二进制 cmp 逐字节）**：
- 八脸全部**字节恒等**：默认 898/0/0、PARAMID 753/0/0（双跑恒等）、
  IMPORTSIG 独立 753、mirror、V3SIG=0、SEEDS=0、PARAMID+IMPORTSIG=0。
- bank 391/391 exit 0（mirror 脸字节恒等→银行捕获不变传递证明）。
- ap_mpm_run 装载 21+11 跳 → **32 锁 0 跳**；33 条跳过日志清零。
- **收益=0 行**：三重结构性原因——①打印窗口 34 函数对 10 个 struct
  导入的调用位点=0（golden 中 struct 使用者 ap_open_logs/ap_gname2id/
  ap_fatal_signal_setup/ap_mpm_run 全部在窗口与迭代宇宙外或仅宇宙内
  非打印）；②PARAMID 证据收割弃收 PLT 槽（struct 锁不进自产表）；
  ③**本树上整个导入通道已脸中性**：RUDRA_IMPORTSIG=0 与开=753 字节
  相同（IMPORTSIG 车道裁决树 7090eb8c 上 −246 的收益已被 TAGLINE
  printc 提交（2e2997f4/cdd66875）吸收同一残差族——通道开关在本树
  不再改变脸）。

**判例**：canon 数据普查驱动补齐的通道完整性工作，若其唯一消费者在
窗口外且证据通道弃收其位点，脸收益为结构性零——登记为判例收口
（补齐保留：canon 一致性成立、零脸风险、跳过日志清零；不宣称
PARAMID 态改善）。后续若打印窗口扩容到 ap_mpm_run/ap_fatal_signal_
setup（struct 使用函数），本 census 直接承重。

证据=/dev/shm/rudra-tests/structb/（A/B 双二进制+八脸输出+全门禁日志）。

## §17.8 CURLPARAM 交付记录（Lane CURLPARAM，2026-09-25，基=master 94276edf=BOOLMARK 后）

**任务形态**：httpd 侧已证自产+导入 753 < manifest 898（§17.7 数字）——curl 侧把
`RUDRA_PARAMID=1` 迭代环（§17.1 形态 + §17.6 四守卫）整套复制到 curl 驱动，
**去循环化的另一半**：curl 的 callee-siglock 通道输入从 harvested manifest 换成
二进制自身运行时回收的原型。curl 与 httpd 的结构差异全部保留：驱动是
**进程隔离 worker 协议**（每函数一个 `run_isolated_worker` 子进程，非线程闭包），
迭代环的每一轮 = 对窗口内每个函数跑一次与打印 pass **完全同构的 worker 请求**
（同一 `build_decompile_request` 构造点、同一二进制、同一超时隔离），只在请求上
加两件事：本轮锁表（`paramid_table: Some(entries)` 拥有该通道——manifest 读
整段跳过；round 1 空表=裸轮）与收割开关（worker 在 print 完成后从最终
varnode 状态抽证据——与 httpd `decompile_one_function` 的收割位同位——经新增
`WorkerPayload::DecompileHarvest` 返回）。**迭代窗口=124 全量语料减 48 个
EXTERNAL 桩投影**（76 个真函数体；主循环桩臂的同一 skip）。四守卫
（sticky 冲突记忆/窄整指针降级/退化站点过滤/静默站点否决）与全部仪器
（ROUNDS/EVIDENCE=strict/STICKY/NOINTPTR/PLT=1/Round1=strict/EVICT/SITES/
DEBUG/COMPARE）逐件带上；PLT 槽证据默认仍整表弃收（CURLPREP 判决：libc ABI
表+DWARF 原型已在 callspecs 上，导入账本在 curl 侧无需建——装载臂的
`has_model()` gap-fill 规则本来就跳过被覆盖位点）。证据策略（loose 层/
窄指针降级）由**请求字段**下发（父进程单源，杜绝父/worker env 漂移；
Round1=strict 分层仪器因此可只作用于第 1 轮）。

**运行形态（亲测）**：round 1 裸 → 76 函数 63 条站点记录 → 12 锁；
round 2 锁态 → 同 12 锁 → **round 2 不动点**（终表 12 = 4 全参锁 + 12 返回锁；
monotone 收敛与 httpd 同形）。PARAMID 脸耗时 1m51s（默认 37s）。

**三脸对照（硬门=自产 ≥ manifest + 零函数回退）——全等通过**：

| 脸 | skeleton | defects | numbering | 逐函数 vs manifest |
|---|---|---|---|---|
| manifest（默认） | **396** | 0 | 0 | 基准（与基线 result/curl_cur.c **字节恒等**） |
| 裸（RUDRA_V3SIG=0） | **396** | 0 | 0 | 与 manifest **字节恒等** |
| 自产（RUDRA_PARAMID=1） | **396** | 0 | 0 | 与 manifest **字节恒等**（零回退平凡成立） |

**结构性判决（本 lane 的核心发现，判例级）**：在 curl 树上 **callee-siglock
通道是脸中性的——两种输入形态都是**。manifest 态装载 13 个原型
（main 7 / parseconfig 1 / getparameter 2 / progressbarinit 1 / glob_range 2）
而脸输出与裸态字节恒等；自产态终表 12 条**装载 0 个**（12 条全部命中
`has_model()` DWARF-覆盖跳过——GetStr/my_get_line/parseconfig/getparameter/
glob_url/next_url/match_url 等内部 callee 都有 DWARF 模型在位）。机制归因：
CURLWIRE 的 src 侧 cast 臂（5e6aad2b）+ typeprop 已在 DWARF/libc 覆盖面把
canon 形复现，锁只是把恢复本来就到的答案钉死——与 §17.7.1 STRUCTB 判例
（"通道开关在本树不再改变脸"）同一形态，但更强：**输入自产化也不改变脸**。
PARAMID 自产环在 curl 上的价值=通道运输层完整可用（去 manifest 依赖的
half-looper 收口）+ 零风险（三脸全等），非脸改善——按判例诚实登记，不宣称
PARAMID 态改善。

**对拍（自产 12 vs manifest 55，RUDRA_PARAMID_COMPARE 默认开）**：
- entry 级：overlap 12（self-only=0）| exact 4 / shape-diff 8 / manifest-only
  43；precision(exact/overlap)=**33.3%**、recall=**7.3%**。
- **DWARF 优势直接可见**：overlap 域内**零拼写冲突**——param slots
  7 equal / **0 different**（httpd 同阶段 18 equal/10 diff）；returns
  10 equal / **0 different** / 0 manifest-only / 2 self-only。证据回声
  （link_call_specs 的 DWARF/libc 装载 → typeprop → arg varnode 类型）
  使每个提交拼写与 canon 一致——收敛的不是覆盖率而是准确率。
- manifest-only 43 分解：**40 = PLT/导入域**（策略弃收——libc/DWARF 通道
  属地，`_init` 计入此类）+ **3 = 内部**：progressbarinit
  （`ProgressData *` 结构拼写——KNOWN_BASES 准入门死证据，与 8 条
  shape-diff 的锁深度损失同类：FILE */URLGlob */Configurable */HttpReq/
  URLGlob/`int *`（glob_url slot2）等结构/窄指针槽位不进证据）、hugehelp
  （manifest 惰性条目——无锁可装，合并规则按 httpd 形态正确弃收）、
  GetStr（`char * *`/`char *` 均为已知基——见下节站点归因）。
- shape-diff 8 条全部为 lock-flag 类（自产退化为 return-only；返回拼写
  10/10 全对）。

**GetStr 站点归因（RUDRA_PARAMID_SITES=1 亲测，17 位点全查）**：全部
17 位点（caller 一律 getparameter）**零冲突、形态全同**——
`arity=2 slots=["-", "char *"] ret=None`：slot1 `char *` 全证据一致；
slot0（canon `char * *`）在**每一个**位点都无政策可采证据——打印脸该
槽是 `&::config.useragent` 全局字段地址族（spacebase 相对 address-of
形），槽 varnode 无类型/基名不在 KNOWN_BASES，运行时状态拼写通道看不
穿该形；GetStr 又无返回消费证据 → 满证据 input-lock 规则下只能退
return-only 而 ret=None → 惰性条目弃收。与 httpd §17.4 的
"missing slot evidence (untyped args)" 同类——manifest 从 canon 打印
文本 `&::config.X` 形读出 `char **`，运行时状态等价物需要全局字段
指针类型回填（typeprop/DWARF-globals 联合域，非本车道 write-set）。

**门禁（全过，亲测）**：默认脸与基线 result/curl_cur.c 字节恒等；mirror
（RUDRA_MIRROR=1）± PARAMID 输出恒等（gate 日志拒绝行在场）；RUDRA_SEEDS=0
± PARAMID 恒等（全局逃生门静默关）；RUDRA_V3SIG=0 恒等（单通道退）；
PARAMID 双跑 cmp 恒等；默认双跑 cmp 恒等；bank 391/391 exit 0；gcc 审计
104 OK/20 FAIL（PARAMID 脸=默认脸字节恒等→同名集平凡成立）；cargo test
--lib 1729P+1 预存败（test_nonzeromask_pipeline_wiring——BOOLMARK/LOCKFIX
行已档 master 干树同名同败，非本改动）；annotations/refs/gate-health 门禁
过。src/ 零触碰（全走库公开面：`fd.callspecs`/`find_call_op`/`get_in`/
`get_out`/`get_type`/`print_raw`）。

**移交**：①结构拼写证据类（KNOWN_BASES 无 DWARF 域名）=与 httpd
§17.6.5 typeprop 域同族的既有登记（C3 域），不新立 TODO；②GetStr 冲突族
若未来要收口，路径=httpd HARVESTFIX 同法（标量 cast 槽证据恢复），登记在
车道终报即可；③PLT 准入实验（RUDRA_PARAMID_PLT=1）在 curl 上未量测
（has_model 跳过使其结构性 no-op，与 httpd 的净负测量一致）。

证据=/dev/shm/rudra-tests/cparam/（三脸+双跑+全门禁输出+sites dump）；
终报=本节。target /dev/shm/rudra-targets/sb-cparam 留 root 集成后回收。

## §19 W0 交付记录（Lane HEADLESSDIST，2026-09-27，基=master 6a458387，零 src 改动归因车道）

> HEADLESS-BRIDGE-ATTRIB-HEADLESSDIST-0004：headless dist 重建 + curl/httpd 受控
> 消融重导入 + live `<localdb>` 协议抓取与 manifest 交叉验证 + O1 钉死。
> 写域=本文件 §2/§3/§5.6/§6 回写 + 本节 + TODO_BOARD 本票行；src/ 零触碰。
> 证据=/dev/shm/rudra-tests/headlessdist/（scripts/rounds/xml/metrics/dl）。

### 19.1 dist 重建与验证（任务①）

- **来源**：官方发行版 zip `ghidra_12.0.4_PUBLIC_20260303.zip`（GitHub releases
  tag Ghidra_12.0.4_build；直连 https，apt 代理不可用；sha256
  `c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120`）。
- **锁定证明**：zip 内 `Ghidra/application.properties`
  `application.revision.ghidra=e40ed13014025f82488b1f8f7bca566894ac376b`
  ——与锁定 oracle commit **逐字相等**。JDK=Temurin 21.0.12.1（Adoptium API
  直连）。运行时必须 `unset LD_PRELOAD`（proxychains 劫持 Java↔native 反编译
  器回环 IPC）。
- **行为验证**：canon 配方复刻（analyzeHeadless 默认分析 + postScript
  `ghidra_decompile_all.py` 逐字副本含 Jython coding 行）重导入双语料：
  - curl 124/124 函数,输出 sha256 `aca37988…` == canon golden 逐字节；
  - httpd 2010/2010 函数,sha256 `6b4c4f31…` == canon golden 逐字节；
  - 重复跑 byte-identical（确定性 1/1 复验）。
  ⇒ 官方 zip 与 canon 生成时所用的自建 dist 在本语料行为全等;**dist 档
  NO_ORACLE 已消除**（provenance `equivalence_notes` 所述自建路径与官方
  发行版在本语料等价）。配方留档 §19.6 + scripts/run_round.sh。

### 19.2 消融矩阵（任务②）

11 轮受控重导入（每轮=完整 canon 配方 + 单一 analyzer 开关,preScript
`setAnalysisOption`）。核心指标（口径=§2 grep 全文件口径;locked-warn=
"WARNING: Unknown calling convention";typed_decls=函数体首语句前声明行）:

| 轮 | 开关 | curl local_/typed/locked | httpd local_/typed/locked | 判定 |
|---|---|---|---|---|
| r0 基线 | 默认(=canon) | 117/242/51 | 5824/5245/124 | 双双 byte==canon |
| r1 | **Decompiler Parameter ID=true** | 117/242/51(0 函数变) | 5879/5698/124(**461 函数变**) | canon 无 Parameter ID:强开后偏离 canon |
| r1b | Parameter ID=true + Commit Data Types=false | 117/242/51(0 变) | — | 同上(锁名不锁型) |
| r2 | **Stack=false** | **117→0**/242/51 | **5824→0**/5245/124 | **C1 整层=Stack 分析器**;变化函数=httpd 226 个=manifest 收割域逐一对应 |
| r3 | **Function ID=false** | 117/242/51(**0 函数变**) | 5824/5245/124(**0 函数变**) | **FID 惰性**:dist 无 .fid 库(0.07s 空转) |
| r4 | DWARF=false(仅 curl) | 117→**245**/229/48;bool 34→**7** | n/a | DWARF 名遮蔽 local_ 命名(+128);**curl bool 源=DWARF** |
| r5 | **Apply Data Archives=false** | 114/222/**51→3** | 5842/5150/**124→0**;sigaction/sigset_t decl 2→0,字段形 3→0 | **C2 签名/locked-warn + O1 类型=generic_clib_64 归档** |

配套源码级事实（锁定 commit 亲读）:
- `DecompilerFunctionAnalyzer.getDefaultEnablement()` = `(numAddr < 2MB) &&
  PE_NAME.equals(format)` —— **对 ELF 恒 false**,canon 双语料均未跑过
  Parameter ID(r1 强开 461 函数偏离 canon 是直接证伪)。
- 全树 analyzer NAME 盘点（15138 .java）: **不存在 "Data Type Propagation"
  分析器**;票面假设三连(Parameter ID/Data Type Propagation/FID)中两条
  对 ELF 结构性不成立。C1 真源 `StackVariableAnalyzer`(NAME="Stack",
  "Creates stack variables for a function",默认开,0.2-0.6s)。
- live analyzer 面(r0 日志计时块):Stack/Function ID/DWARF/
  Apply Data Archives(generic_clib_64)/Call Convention ID/Demangler GNU/
  ASCII Strings/x86 Constant Reference 等在场;Parameter ID 不在场。

### 19.3 逐通道结论（每通道一行,analyzer 名+开/关计数对照）

| 通道 | 票面假设 | 消融判决 | 计数对照(开→关) |
|---|---|---|---|
| **C1 TYPE-SEED-LOCAL** | Decompiler Parameter ID(commit-locals) | **证伪 → "Stack" 分析器**(StackVariableAnalyzer 建栈符号;名=SymbolUtilities.getDefaultLocalName `local_`+hex;canon 打印的类型是 restructure 在锚定分区上恢复的,非 DB 提交型) | httpd local_ 5824→0 / curl 117→0(Stack 关);Parameter ID 强开反增 5879(≠canon 5824) |
| **C6 BOOL-LIT** | Data Type Propagation 分析器 | **归因不成立**(该分析器不存在)。curl=bool 源=DWARF 导入器 char→bool 重映射(capture 日志 "DWARF data type remappings: /char -> /bool" 直证);httpd=bool 499 对 Stack/FID/archive 消融恒定=反编译器自身恢复,H499-vs-D289 差额属环境差非播种通道 | curl bool 34→7(DWARF 关);httpd bool 499→500/499/495(Stack/FID/archive 关) |
| **C2 导入签名/locked-warn** | FID/外部签名库 | **FID 证伪 → "Apply Data Archives"**(generic_clib_64 归档,ApplyFunctionDataTypesCmd 套签名;FID 关=0 函数变化+dist 无 .fid 库) | curl locked-warn 51→3 / httpd 124→0(archive 关);PTR_ 50/372 不动(=ELF loader 域,与归档无关) |
| **O1 httpd STRUCT-FIELD** | 疑 FID 套型 | **证伪 → generic_clib_64 归档**:sigaction 导入签名(typelock 参数含 struct sigaction*)→typeprop 落在 Stack 层 local_b8/local_c0 槽上;live XML 亲见 sigaction mapsym 带 typelocked `__sig` 等参数符号 | httpd struct decl 2→0、字段形 3→0(archive 关或 Stack 关);FID 关 2/3 不变 |

**对 §16.1/V3SIG 假设的连带负证据**(登记,不属本车道收口):live 协议里
内部被调 ap_setup_prelinked_modules 的函数符号 mapsym 为
`<prototype model="unknown">` + 空 localdb + void 返回——**canon 的 DB 没有
该函数的提交签名**;"Parameter ID 提交被调原型"假设在 canon 配方下结构性
不成立(Parameter ID 未运行)。canon main 的 (long*) 调用形差异来源移交
V3SIG/PARAMID 车道重归属。

### 19.4 live `<localdb>` 协议抓取与 manifest 交叉验证(任务③)

仪器:`capture_localdb.py` postScript——`DecompInterface.enableDebug(File)`
逐函数武装,DecompileDebug.getMapped 记录**真实协议字节**(函数符号 mapsym
内嵌 `<function><localdb>`,即 funcdata.cc:804 消费的同一文档)。注意
enableDebug 的 shutdown 路径要求显式 `setOptions(DecompileOptions())`(朴素
openProgram 下 this.options=null 必 NPE——canon postScript 不走该路径故无恙)。

| manifest | 条目 | (offset,name) 精确命中 | 类型串 MATCH | 判定 |
|---|---|---|---|---|
| local_seed_httpd_1204(C1) | 1046 | **1046/1046** | —(见下) | 锚点层 100% 命中 |
| local_seed_curl_1204(C1) | 15 | 15/15 | — | 同上 |
| local_seed_curl_1204_dwarf(C2) | 11 | 10/10 | **10/10 逐串相等**(bool[256]/char[40]/time_t/int/bool…) | 全 MATCH;余 1=uStack_150 canon-emergent 合成槽(§11.1 已档,非 DB 符号,预期缺席) |
| local_seed_curl_1204_struct(C4) | 10 | 10/10 | 8/8(DWARP/struct 域:OutStruct/stat/URLGlob */va_list/LongShort[50]) | 2 条 canon-decl 采纳条目(local_5b8/local_5a8)属 Stack 层(见下) |

**锁态真值(manifest 协议状态修正,输出语义不变)**:
- **Stack 层(local_ 偏移名,含 httpd 全部 1046 条+curl 15 条+canon-decl 2 条)
  = namelock=true, typelock=false, 型=`<typeref name="undefined4/8">`**——
  manifest 的 `typelock:true`+恢复型是"输出等价但协议状态过强"的建模
  (oracle 播种实验证明能复现 canon 文本;live 真值是无型锁,canon 打印型
  来自 restructure 恢复)。
- **DWARF/struct 层(urlnum/urls/outs/…) = typelock=true + 真型**——与
  manifest 完全一致(含 char→bool 重映射后的 bool[256])。
- 参数符号 = cat="0"+index,typelock=true(DWARF/归档签名域);栈局部
  cat="-1"。
- 附:curl main localdb 含 35 个 scope(内联函数作用域,myprogress/
  getparameter 子树的 format/line/outline/now/aliases 等以独立 scope 出现)
  ——manifest 的函数域模型只覆盖函数自身 scope,交叉验证按
  (offset,name) 全域匹配故不受影响。

### 19.5 对 Rudra 侧的含义(移交,不在本车道实施)

1. C1 桥的类型锁极性:W1/W1b/HSEED 的 committed_locals 载体装
   typelock=true 在文本输出上已被 oracle 播种实验验证;live 真值(型不锁
   +undefined 基型)是更保守的等价形态。若未来出现"锁型 vs 恢复型"分叉
   的残差(如合并/分区差异),优先按 live 真值降级锁极性重验,而非新增
   通道。不构成当前 767/951 脸的回退证据。
2. C2/W2 导入签名 manifest:源=generic_clib_64(与 24 libc 手工桥同源
   语义),FID 路径可以放弃;O1 的 httpd 结构体类型在 W4 时走"归档类型
   表"而非 FID 表。
3. PARAMID 车道注意:canon 本身不含 Parameter ID 提交(r1 强开=461 函数
   偏离 canon)。自产签名环的目标语义应重新对表"Stack+归档+DWARF 后的
   DB 状态",而不是 Parameter ID 的输出。
4. §3 归因三级现在全部在位:机制级(funcdata.cc:804/varmap.cc:1044)+
   差分级(双 golden)+ **消融级(本节)**——C1/C2/C6/O1 四通道的
   analyzer 级归因从假设升为消融证据。

### 19.6 重建配方(可复现,直连 https)

```bash
# 0) 前置: unset LD_PRELOAD(否则 proxychains 劫持回环 IPC);磁盘>3GB
# 1) Ghidra 12.0.4 官方发行版(锁定 commit 的正式构建)
curl -fL -o ghidra_12.0.4_PUBLIC_20260303.zip \
  "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip"
# 校验: unzip -t 通过;sha256=c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120;
#       Ghidra/application.properties: application.revision.ghidra == e40ed13014025f82488b1f8f7bca566894ac376b
unzip -q ghidra_12.0.4_PUBLIC_20260303.zip -d dist
# 2) JDK 21(Adoptium)
curl -fL -o jdk21.tar.gz \
  "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
mkdir jdk21x && tar xzf jdk21.tar.gz -C jdk21x && mv jdk21x/jdk-21* jdk21
# 3) 基线验证(必须 byte==canon 才可做消融)
export JAVA_HOME=$PWD/jdk21
scripts/run_round.sh curl  r0_base            # → rounds/curl/r0_base.c
scripts/run_round.sh httpd r0_base            # → rounds/httpd/r0_base.c
cmp rounds/curl/r0_base.c  tests/golden/ghidra_curl_1204.c   # 恒等
cmp rounds/httpd/r0_base.c tests/golden/ghidra_httpd_1204.c  # 恒等
# 4) 消融轮(preScript set_analyzer.py 逐轮单开关)
scripts/run_round.sh httpd r2_stack_off   "Stack=false"
scripts/run_round.sh httpd r3_fid_off     "Function ID=false"
scripts/run_round.sh httpd r5_archive_off "Apply Data Archives=false"
scripts/run_round.sh httpd r1_paramid_on  "Decompiler Parameter ID=true"
scripts/run_round.sh curl  r4_dwarf_off   "DWARF=false"      # 仅 curl
# 5) live <localdb> 抓取 + 交叉验证
scripts/run_capture.sh curl;  scripts/run_capture.sh httpd
python3 scripts/xcheck_manifest.py tests/golden/manifests/local_seed_httpd_1204.json xml/httpd httpd
# 6) 汇总: python3 scripts/summarize.py(全轮指标表)
```

（脚本全部在 /dev/shm/rudra-tests/headlessdist/scripts/,随证据盘存活;
root 集成后按回收纪律处理,结论与配方已固化本节。）

## §17.9 THUNKGOT 交付记录（Lane THUNKGOT，2026-09-27，基=master 6a458387）

**票**：`HEADLESS-BRIDGE-V2-THUNKGOT-0002`（W2 = §6 的 C2 THUNK-GOT 波次；
① 导入签名 manifest ①=httpd 侧在 IMPORTSIG（§17.7）59 条台账上补 **thunk
自身签名锁**通道；② thunk 标记抑制 jumptable 恢复；③ GOT 槽 `PTR_x` 补全
（H 372 vs pcRam 1659 量化的 JUMP_SLOT 半边））。

**oracle 机制钉死（stage_thunk_diag harness，锁定库直测，证据=
/dev/shm/rudra-tests/thunkgot/）**：对 .plt.sec thunk 的
`endbr64; bnd jmp *[rip+GOT]`（lift = `tmp=LOAD ram(slot); BRANCHIND tmp`）：

- **裸库（direct-runner 形态）恒 fail_normal**——raw/zero/far 三种 GOT 槽
  字节值输出逐字节恒等（"Could not recover jumptable … Too many branches"
  + "Treating indirect jump as call" 两警告 + `(*pcRam…)()`；只读属性范围
  加持同样不变——httpd 的懒绑定槽值是近地址，sanityCheck 的 0xffff 距离
  规则不判 thunk，jumptable.cc:2302-2320 的 1-entry 通道到不了）。
  ⇒ **canon 的抑制不在内存，在传输**。
- **FlowOverride.CALL_RETURN 传输 = canon 通道**：Java 侧
  OperandReferenceAnalyzer.checkForExternalJump（引用解析进 EXTERNAL block
  的 jmp 一律 setFlowOverride(CALL_RETURN)），DecompInterface 的 getPcode
  经 InstructionPcodeOverride → PcodeEmit.dumpCallOverride BRANCHIND 臂
  （BRANCHIND→CALLIND + dumpNullReturn）在发射期改写；库内等价 =
  `Override::insertFlowOverride` → flow.cc:415-418/474-475 →
  Funcdata::overrideFlow（funcdata_op.cc:969-1020，BRANCHIND→CALLIND +
  死 RETURN 追加）。probe 亲证：该 override 下锁定库输出
  `(*PTR_…)(); return;` 零警告——canon 体逐字（`(code *)` cast 由
  ActionSetCasts castInput 的 CALLIND slot0 reqtype=code*（typeop.cc:745
  arm）对上 PTR 符号的 undefined* 锁型产生，canon main 的
  `PTR___gmon_start___ != (undefined *)0x0` 见证锁型）。
- **thunk 自身签名**：canon 对台账内 59 导入锁 thunk 头（`void * memset
  (void *__s,int __c,size_t __n)` + "Unknown calling convention" 横幅 =
  三锁+model_name "unknown" 组合，locked_proto 同构）；7 个 canon 不锁导
  入保持默认 void(void) 头。

**通道形态（examples/httpd_decompile.rs，三件）**：

1. **③ GOT JUMP_SLOT PTR_ 台账**：`build_action_data_symbol_db` 新增
   .rela.plt JUMP_SLOT 臂——`PTR_<extname>_<slotaddr>`、**typelocked
   pointer-to-undefined**（canon 面向型；锁型是 `(code *)` cast 的必要条
   件：无锁则 typeprop 把调用点输入推成 code* 而 cast 消失——A/B 实测）。
   GLOB_DAT 臂零改动（已对窗口 canon 恒等）。
2. **② RUDRA_THUNKS=1 thunk 反编译脸**（opt-in 量具，mirror/stage 脸恒
   拒；`RUDRA_THUNKS_RAW=1` = A/B 断路臂）：plt_imports 317 项，extent =
   终结分支停走（canon 头 (10 bytes) 逐项），lift 后把终结 jmp 地址经
   `FunctionTask.thunk_override_addrs` 带入 `decompile_one_function`，
   在 `inject_raw_ops` 前注册 `fd.localoverride.insert_flow_override(
   CallReturn)`——Rudra 的 `apply_flow_overrides_raw`（funcdata.rs，
   funcdata_op.cc:991-1020 镜像）在注入层做 BRANCHIND→CALLIND+RETURN 改
   写，**库零改动**（jumptable/flow 未触碰——机制 C 白名单无 CR 需求）。
3. **① thunk 自身签名**：`build_locked_import_proto`（install_import_
   signatures 的 proto 构建提取共享）+ `FunctionTask.thunk_import` 臂在
   importsig 同位（inject 后/action 前）把台账锁型装上 fd.funcp 自身。

**curl 侧判决：零改动**。curl 的同族通道已在 CURB（got_span 只读 +
fail_thunk 路线）+ MAINDIFF-GLOBAL（PTR_ 标签）+ CALLSPEC（thunk 签名）车
道落地——本票核验：canon 脸 124 块 0 jumptable 警告，47 个 PTR 体函数块
45/47 与 canon 逐字节恒等（2 差 = _init 返回传播/_start 参数名，非 thunk
域预存残差），真 thunk 45/45 全等（含 `int puts(char *__s)` 锁头+横幅）。
§2 的 curl THUNK-PAIR 73 hunk 自 CURB 已收敛，本票同向确认。

**验收数字（fast-release 亲测）**：
- **thunk 警告 318→0**：RAW 臂 318×"Could not recover jumptable"+
  318×"Treating indirect jump as call"（= direct-runner golden 431 中全部
  318 个 size≤16 携带者的完整家族复现；余 113 个 D 警告在窗口外真 switch
  函数上，驱动窗口内 1 个=canon 同位同文）→ canon 臂 0（唯一剩警告=
  main 窗 0x12daeb，canon golden 同位逐字）。
- **thunk 体 314/317 与 canon 逐字节恒等**（typedef 前导归一后；memset/
  __stack_chk_fail 两形态——锁头+横幅+`(void *)` 返回 cast 全对）；3 差
  =①apr_brigade_pflatten：canon 该槽名 `_DAT_0019c660`（canon DB 内
  '_'-global 重叠吞掉 PTR 名+overlap 横幅，1 例 DB 状态差）②getrlimit：
  canon 有 enum 值重名横幅（STRUCTBASES census 的 enum 命名警告通道）
  ③末块 comparator 伪差（summary 行）。登记残差不阻塞。
- **默认脸构造性恒等**：新 JUMP_SLOT 台账下 httpd 默认脸与基线 cmp 字节
  恒等（窗口零引用该槽集）；canon 基线 **httpd 311/0/0（Matched 34）/
  curl 157/0/0（Matched 124）** == 任务书基线,零回退平凡成立。
- 双跑确定性/镜面五面/bank 391/cargo test/三门禁：见终报
  LANE_THUNKGOT_2026-09-27.md 逐项。

**B2 证据等级**：通道四决定性观察（警告对/体形/锁头/横幅）在锁定库
probe（oracle 直测）+ canon golden（317 块对拍）双侧闭合；Rudra 侧输出
= oracle 输出（同输入=thunk 字节+headless 传输输入；同输出=C 文本块）。
库（jumptable.rs/flow.rs/funcdata.rs）零触碰，全部经公开面
（localoverride/DB/task 传输）。

证据=/dev/shm/rudra-tests/thunkgot/（probe 源+构建脚本+矩阵输出+
compare_thunks.py+三脸工件）；终报=/dev/shm/rudra-reports/
LANE_THUNKGOT_2026-09-27.md。

## §20 V4COMPOSITE 交付记录（Lane V4COMPOSITE 中车道，2026-09-27，基=master 01e9132d）

**票**: `HEADLESS-BRIDGE-V4-COMPOSITE-0005`（生产 typedef 触发面接线——manifest/
驱动/数据面；TYPEDEFIMM 终报移交节 item 2 的承接车道）。

### 20.1 oracle XML 语义（铁律 1.2 亲读，manifest 协议的 ground truth）

- **`<def>` 元素 = typedef 的运输形态**（`ELEM_DEF`，type.cc:50 id 43；
  `TypeFactory::decodeTypeNoRef` type.cc:4448-4451 分派到 `decodeTypedef`）。
- **`TypeFactory::decodeTypedef`**（type.cc:4263-4313）：读 `id`（缺省 →
  `hashName(name)`，type.cc:4283-4285 "Its possible the typedef is a builtin"）/
  `name`/`format` 属性 → **内联 decode 立即目标**（`decodeType(decoder)`，
  type.cc:4286）→ 递归 struct/union incomplete 去重（:4290-4311，指针同一性
  比较 `defedType != prev->getTypedef()` 不等即 throw）→ 尾部
  **`getTypedef(defedType, nm, id, format)`**（:4312）。
- **`TypeFactory::getTypedef`**（type.cc:3818-3840）：clone + 改名/改 id + 清
  coretype（:3833）+ **`res->typedefImm = ct`**（:3834，唯一置位点）+ insert +
  incomplete 入 `incompleteTypedef`（:3837-3838）；同名去重走通道
  指针比较（:3825-3826，非 typedef 同名物 → `LowlevelError` throw——**这是本
  车道安装次序约束的 oracle 依据**）。
- encode 侧守卫（`TypeChar::encode` type.cc:822-833 等 10 处 subclass）：`typedefImm
  != 0` → `encodeTypedef`（type.cc:519-529，`<def name id>` + 目标 `encodeRef`
  `<typeref>`）——本车道 manifest 条目形态（name + 立即目标）就是这对
  decode/encode 的 JSON 投影。

### 20.2 通道形态（manifest 协议扩展 + 驱动装种）

- **harvest**（`tools/harvest_local_manifest.py --typedef BINARY GOLDEN.c CORPUS
  ORACLE_COMMIT OUT.json`，add-only）：golden **声明层**（签名行 + decl 块类型位）
  引用名 ∩ DWARF `DW_TAG_typedef` 名集，typedef-of-typedef 链闭包；base 目标经
  **importer 自己的别名表**（`initBaseDataTypes` :499-548，Rudra
  `standard_base_alias` debugproto.rs:1776 镜像）映射到工厂核心拼写并携带
  (size, metatype)。三类分流：`typedefs[]`（可装：base / typedef-ref 目标，
  依赖序）／`deferred_typedefs[]`（composite/enum/array/pointer 目标——MB22
  联调域）／`harvest_drops[]`（conventional-bool［PRINTC-BOOLLITERAL-0001 核心
  bool 字面量通道，异常键在 typedef 名］、chartype、无名目标、被 deferred 阻
  断的链）。httpd 语料 stripped → `_warn_if_no_dwarf` 响亮零产（HSEED 判例），
  不船运 manifest。
- **manifest**: `tests/golden/manifests/typedef_seed_curl_1204.json`（3 装种
  条目 `__time_t→long`、`size_t→ulong`、`time_t→__time_t`；6 deferred；3 drops；
  含 oracle_commit + binary/golden sha256 溯源，机制 B2 口径同其它通道）。
- **驱动装种**（curl_decompile.rs / httpd_decompile.rs）：
  - **接口契约对接 TYPEDEFIMM 通道**（其分支待并 MB21/MB22，本车道基
    master 01e9132d 无 `typedef_imm`）：契约锚点 = `TypeFactory::get_typedef(
    name, ct)`（typefactory.rs:3010，master 与 MB22 分支**同签名**——master
    注册名字表 alias，MB22 同一调用置位 per-instance 通道并激活全部四个剥
    离环）。驱动侧只调该 pub API → 离线可对接成立，无需登记移交；MB22 合并
    后零驱动改动联调（见 20.5）。
  - **安装次序**（oracle 依据 20.1 的同名 throw）：decompile_request 顶部、
    任何 DWARF 库解析（DebugGlobalDatabase/DebugPrototypeDatabase 的
    `resolve_type` typedef 臂先物化**无通道**同名 alias）之前；OnceLock 每
    进程一次（shared TypeFactory 进程级）。之后 index 走查经 intern_named
    same-shape 去重落到已装 clone 上。
  - **目标解析**：kind=base → `get_base_named(size, metatype, spelling)`——
    与 `parse_c_type` 核心臂同一 interned 节点（`factory_named_base` 先查
    find_by_name），typedef 剥离落到管线无别名拼写持有的同一身份；kind=
    typedef → 已装 clone 集。
  - **门控**（V3SIG/PFLIP opt-in 判例——通道活跃即 canon 可见[typedef 形态
    cast/`&` 渲染]，且尚无树内锁定 oracle 见证）：`RUDRA_TYPEDEFSEED=1`
    opt-in；mirror 组件恒拒（五投影纯净）；`RUDRA_SEEDS=0` 全局裸脸逃生；
    `RUDRA_TYPEDEFSEED_MANIFEST=<path>` 覆盖；manifest 缺失/损坏 = 响亮
    no-op。**默认脸构造性恒等**：门关 = 零 manifest IO、零工厂突变、零
    get_typedef 调用。

### 20.3 触发验证（种子态剥离环激活计数观测）

驱动侧两级观测（观测不突变；门关则零开销）：

1. **index occupation**（curl，parse_type_names 后）：DWARF 名索引中 Arc 同一
   / 同名命中已装 typedef 的条目数——剥离环候选操作数的名索引面。
2. **strip surface**（双驱动，action pipeline 后）：fd 高变量类型名命中已装
   typedef 集合计数（逐函数 `[TYPEDEFSEED] <fn> strip surface: N high
   variables on typedef-layer types (...)`）——**四个剥离环
   （cast.cc:325-328 / printc.cc:390-393 / coreaction.cc:2476-2479 /
   typeop.cc:2337-2340）在本函数的可操作面**。master 上唯一活的环是
   isOpIdentical 的名字表孪生（coreaction.rs:6602）；环级逐次计数器属 MB22
   通道分支（其拥有那四行；master 侧加计数器必造合并冲突）——联调时随通道
   补齐，本车道以操作数面计数为收敛方向观测（canon 声明层 typedef 形态残
   差族沿 `size_t/ulong` 身份统一方向）。

### 20.4 验收矩阵（亲测，基=master 01e9132d vs 本车道分支，fast-release 双独立构建）

| 门禁 | 结果 |
|---|---|
| canon A/B 默认脸 | curl **96429B cmp 逐字节恒等**、httpd **64839B cmp 逐字节恒等**（==TYPEDEFIMM 车道记录值，master 侧无漂移） |
| 驱动门实测 | `=1`：installed 3（6 deferred/3 drops）+ index occupation 3 identity/3 name hits（53 entries）+ strip surface 计数 ✓；`RUDRA_MIRROR=1`+门：`ignored under the mirror gate` ✓；缺 manifest（路径覆盖 + httpd 无船运）：`cannot read manifest ... (seeding disabled)` 响亮 no-op ✓；unset/`=0`：stderr 零 TYPEDEFSEED 行（构造性惰性）✓ |
| 触发验证（种子态计数） | curl 全语料 gate-on：**19/76 函数非零 typedef 层占据，合计 41 个 high variables**（size_t 族 17 函数/time_t×2/__time_t×1；`main` 3 个 `(size_t, time_t)`、`getparameter` 3 个 `(time_t, size_t, __time_t)`、`myprogress` 5 个）；**gate-on 全语料输出 vs 默认脸 diff=0**——通道活跃但 master 名字表孪生环在该语料无可翻转比较对（与 TYPEDEFIMM §④ "构造性休眠"同因：canon 残差族在 composite/enum 半边与 MB22 四环） |
| 确定性 | gate-on 双跑 cmp 逐字节恒等 |
| projection bank | **391/391 OK** |
| 三门禁 | annotations 100 文件全注解 ✓ / refs --strict 全解析 ✓ / evidence 四类 4/4 ✓（src/ 零改动） |

### 20.5 MB22 联调移交（登记，非本车道写域）

1. **composite/enum/array typedef 装种**（FILE/_IO_FILE、URLGlob、CURLcode、
   va_list 三级链——manifest `deferred_typedefs[]` 已记账）：需要 DWARF 名
   索引先于装种可用，而 `parse_type_names` 的 alias 物化先占名（getTypedef
   同名 throw）→ 解法是**导入边界自身改调 get_typedef**（src/debugproto.rs
   resolve_type typedef 臂 → materialized_alias → alias_type 一线），属
   TYPEDEFIMM 消费域 src 改动。
2. **环级激活计数器**：四剥离环逐次计数（观测通道联调的量化面）。
3. **门极性复审**：联调产出锁定 oracle 见证后，评估 PFLIP→SEEDFLIP 翻转
   （默认脸装种）。

## §21 RETYPE 交付记录（Lane RETYPE，2026-09-27，基=master 48146429，复活续跑车道）

**票**: `CURLCANON-HEADLESS-RETYPE-0001`（BOOLCHAR 终报移交项：canon curl −10 行
的 per-field retype 桥接；前会话撞额度墙死亡，本会话续用其 worktree 半成品——
FIELDRETYPE 通道代码+manifest 已在位且编译通过，续用评估=代码全量保留、裁决重做）。
写域=examples 驱动桥接域 + manifests + 本节 + TODO_BOARD；src/ 零改动。

### 21.1 设计裁决（任务①核心：为何 remotefile char→bool，可推导否）

**机制（锁定 dist 12.0.4 字节码亲读 + DB ground truth 亲跑，非推断）**:

- `DWARFDataTypeImporter.makeDataTypeForTypedef`：typedef 的目标是
  `DW_TAG_base_type` 时**不建 typedef**，改走 `makeNamedBaseType(typedef 名,
  目标 base DIE)`。
- `makeNamedBaseType` → `DWARFDataTypeManager.getBaseType("bool", size=1,
  encoding=6)`：`baseDataTypes`（`initBaseDataTypes` 预置的标准 C 原语名表，
  含 "bool"→内建 bool）按名命中；`isEncodingCompatible(6, bool)` 走
  **default-true 臂**（只有 encoding 5/7 检查 signedness；char/boolean 编码
  与任意整型"兼容"）→ 返回**内建 bool**。
- 结果 DWARFDataType 挂**目标 base DIE 的 offset**（0x17f）→ `addDataType`
  把 offsetToDTP[0x17f] 从 /char 翻成 /bool（capture 日志
  "DWARF data type remappings: /char -> /bool" 即此行）。
- 之后**每个在文件序走查中晚于 typedef DIE <0x938> 才解析 <0x17f> 的类型**
  提交 bool；早于它的、走别 CU char DIE（<0x4049>/<0x4413>）的、或经跨 CU
  merge/.conflict 复合的，保持 char。

**DB ground truth**（`dump_field_types.py` postScript，canon 配方，锁定 dist）:

| 位点 | DB 提交 | 机制归因 |
|---|---|---|
| `Configurable.remotefile` | **/bool** | CU1 独有 struct（DIE 0xbc1>0x938），remap 后解析 |
| `Configurable.use_resume/showerror/configread/crlf/progressmode/nobuffer` | /bool | typedef-bool <0x938> 字段（187d9cd5 已桥接） |
| `URLPattern…CharRange.min_c/max_c/ptr_c` | **/char** | struct 在 main.c **和** urlglob.c 双定义，跨 CU merge 落 `…_for_CharRange.conflict` 保 char |
| `main.errorbuffer` / `myprogress.line/outline` | **/bool[256]** | 数组 DIE <0x214f>/<0x1148>… 晚于 typedef |
| `main.format` | **/char[40]** | 数组 DIE <0x428> **早于** typedef（§19.4 manifest 交叉验证 10/10 同证） |
| `glob_buffer` | **/char[4096]** | CU3 自有 char DIE <0x4413>，从未 remap |

**证伪记录（对"可推导通用规则"）**:

1. **同 DIE 异果**：remotefile 与 min_c/max_c/ptr_c 共享同一 char DIE
   <0x17f> 同 CU，DB 提交一 bool 一 char——分键是 importer 文件序位置 +
   跨 CU merge/.conflict，**非**类型身份、**非**用法（前会话 manifest 的
   "usage-shaped"假设被 .conflict 行**当场证伪**并已改写）。
2. **零布尔用法的 bool[N]**：errorbuffer/line/outline/buf 全是 sprintf/fgets
   字符串缓冲，零布尔用法却提交 bool[N]——用法不可能是分键。
3. 分键全部是 **Java importer 内部状态机**（文件序迭代位置、per-offset 缓存、
   DIEAggregate 跨 CU 合并、.conflict 解析），DWARF 图与反编译可见用法里均
   不可见。⇒ **无 (DWARF × usage) 决策函数可复现该面**；台账兜底成立
   （DWARFSEED canon-committed 先例形态），兜底性质如实登记。

**泛化路径（登记，非本车道实施）**: 在桥接层仿真 importer 状态机——
makeNamedBaseType 名键 remap + 文件序解析 + 跨 CU merge/.conflict——即
"Java DWARF importer 仿真器"，属独立车道；在其落地前，per-field 台账是唯一
诚实桥接形态。规则候选必须击败的判据即上表六行 ground truth。

### 21.2 通道形态（DWARFSEED/TYPEDEFSEED 先例）

- **manifest**: `tests/golden/manifests/field_retype_curl_1204.json`——
  oracle_commit + binary/golden sha256 溯源 + `adjudication` 裁决全文（21.1
  机制+证伪）+ entries[(struct, field)→retype target]（现役一条
  Configurable.remotefile→bool，5 行 golden witness 逐条列出）。
- **驱动装种**（curl_decompile.rs，httpd 无此通道——httpd stripped 无 DWARF，
  BOOLCHAR 家族 0 行亲证）：`install_field_retype_channel()` 于 main() 顶、
  任何 DWARF pass 之前——解析语料 DWARF 一次，把台账字段换成核心 bool，
  destroy_type + get_typedef 重占共享工厂名槽（TYPEDEFIMM 通道 API，
  type.cc:3818 clone-and-findAdd 漏斗；布局逐字节保留，仅字段类型身份变），
  intern_named 的 (variant,size,metatype) 去重让后续所有解析共享同一身份
  （= Java type manager remap 后的单身份状态，cast.cc:299 指针同一性比较
  无 cast）。**刻意不用 per-site 树改写**：第二身份会分裂 cast 引擎的指针
  同一性检查（getparameter local_5b8 实测出伪 cast）。
- **门控**（PFLIP opt-in 判例）：`RUDRA_FIELDRETYPE=1` opt-in；mirror 组件恒拒
  （五投影纯净，实测 101 条 ignored/0 installs）；`RUDRA_SEEDS=0` 全局裸脸
  逃生；`RUDRA_FIELDRETYPE_MANIFEST=<path>` 覆盖；manifest 缺失/损坏=响亮
  no-op。**默认脸构造性恒等**（门关=零 manifest IO、零语料读、零工厂突变）。

### 21.3 验收矩阵（亲测，基=master 48146429 vs 本车道，fast-release）

| 门禁 | 结果 |
|---|---|
| canon curl 门开态 | **skeleton 157→147（−10 兑现）**，defects=0，numbering=0，matched 124 不变；5 行 witness（main:695/712/738/1021+gp:1871）逐字节==golden，diff 恰 5 行无其他 |
| canon curl 默认脸 | 96429B **cmp 逐字节恒等亲父 48146429**（独立构建 A/B） |
| canon httpd | 63214B，34/139/0/0 ==亲父基线；`RUDRA_FIELDRETYPE=1` 下 stderr 零 FIELDRETYPE 行（通道 curl 驱动域限定） |
| mirror 纯净 | `RUDRA_MIRROR=1`+门开：101 ignored/0 installs；镜面五面 `verify_mirror_gate --corpus all` 全 PASS（curl 56/56·74/74、httpd 84/84·29/29、vsh 12/12·71/71、sq 4197/4197·810/810、sqlite 24091/24091·1385/1385） |
| projection bank | 391/391 OK |
| cargo test --lib | 全绿（=亲父，src/ 零改动） |
| 三门禁 | annotations --all ✓ / refs --all --strict ✓ / evidence（commit-msg 实跑）✓ |

### 21.4 移交（登记，非本车道写域）

1. **importer 仿真器车道**（21.1 泛化路径）：makeNamedBaseType 名键 remap +
   文件序解析 + 跨 CU merge/.conflict 状态机仿真，落地后可把 per-field 台账
   升级为机制推导面（任意二进制通用对齐的用户终极目标方向）。
2. **门极性复审**：若仿真器车道产出树内锁定 oracle 见证族，评估
   PFLIP→SEEDFLIP 翻转（默认脸装种）。

### 21.5 门极性翻转（Lane BOOLDRILL，2026-09-28，基=4df1e154）

§21.4(2) 移交项兑现（早于仿真器车道，判据改用台账 witness 本身）：
CANONCENSUS2 后 canon 成分剧变（54→42 时代），BOOLDRILL 重钻确认
remotefile 族 10 行现形与前波双证伪时代逐字节恒等——"Java headless
提交层改型非渲染缺陷"判决维持，CANON-BOOLCHAR-FIELDTYPE-0001 改判
数据传输域。翻转=FIELDRETYPE 通道 PFLIP opt-in（`RUDRA_FIELDRETYPE=1`）
→ **DFLIP canon 默认开**（SYMDB 转正先例形状）：canon 面默认装台账，
`RUDRA_FIELDRETYPE=0` 恢复 DWARF 字面（char）脸，mirror 组件恒拒
（五投影纯净），`RUDRA_SEEDS=0` 全局裸脸逃生，manifest 缺损响亮 no-op。

验收（亲测，detached 干净 worktree 双构建 A/B）：canon curl
**42→32/0/0**（−10 全额=main BOOLCHAR 8+getparameter 2；其余 122 函数
零漂移）；5 witness 行逐字节==golden；默认脸==旧门开脸 ccc05886；
`RUDRA_FIELDRETYPE=0`=8dafa799==亲父 canon；`RUDRA_SEEDS=0`=3bcc0129
双侧恒等。翻转后 §21.4(1) importer 仿真器车道仍开放（台账→机制推导面
的升级路径不变）。
