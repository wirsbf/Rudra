**日期**: 2026-10-01（STATUSREFRESH 大刷新——arena campaign W1 里程碑 + canon 零态全程保持 + 速度总账 −80.6% 入档；2026-09-29 及更早为历史快照族）
**版本**: 0.1.0
**状态**: 🟡 **核心库持续开发中；canon 双语料零残差态保持 + 镜面五面棘轮全 PASS + arena W1 落地（核心域 unsafe=0·锁面 −90.3%）；锁定 oracle 逐函数差分流水线运转中；全局完成度未证明**

## 2026-10-01 STATUSREFRESH 大刷新（当前事实源；master `4b1a4bbe` = origin，MB51 收官态）

> 数据源全部在案：波次账本 `.slim/deepwork/stage-bisect-e2e.md`（MB44~MB51 全序列）+
> 各 MB 终报（`/dev/shm/rugra-reports/LANE_MERGEBATCH4{4..9}_*` / `LANE_MERGEBATCH5{0a,0b,1}_*`）+
> arena campaign 族报告（LANE_ARENA{DESIGN,CORE,FIX}_* + LANE_ARENAFLIP_{a..g}_* +
> CR_ARENA{CORE,FLIP_*} 判决链）+ `tools/mirror_gate_baselines.tsv` 现钉值。本节为
> docs-only 汇编，数字与在案证据一致，**未跑新门禁**；口径不确定处逐条标注。
> canon/镜面口径沿 2026-09-29 节分界点①②；速度口径见里程碑③（旧语料 1385 fn 轨道与
> 替代语料 2813 fn 载体双轨如实并列，不可混）。

### 里程碑① canon 双语素零残差保持（MB38 归零后历批复验字节恒等——含 arena 31-commit 全库重构全程）

curl/httpd canon 面 skeleton/defects/numbering = **0/0/0·124/124 + 0/0/0·34/34**（158 函数
全数零残差）保持；输出 md5 双钉 curl `4ab1db2a177e854c6bddca2ecf413685`·96,616B /
httpd `7d5b9e7c3348ee8da1865df281ec05b9`·62,715B（vs `tests/golden/ghidra_{curl,httpd}_1204.c`）。
本刷新窗口（MB44~MB51）每批集成轮均无 mirror env 亲跑复验恒等——**arena W1 全库类型翻转
（31 commit/78 文件 +6437/−1902）期间逐段每 commit 树亲跑双 md5 恒等，零回退**。归零
轨迹与 campaign 总弧（curl 157→0 / httpd 311→0，MB34 冲刺→MB38 归零）见 2026-09-29 节。
窗口内全部镜面燃烧族（CASTSHAPE/CASE-CAST/CASTSUB23/FTSINCRMERGE/L1SURGERY/
SQLITEDUPLABEL）与 arena 重构均以 canon 恒等为伴随红线——质量改善与零态全程兼容。

### 里程碑② arena campaign W1 落地（项目史上最大单批；双目标兑现）

**campaign 判决**（ARENA_DESIGN `bffde202`，用户 2026-09-30 放行全库 arena/索引化重构）：
五道速度道终报共同结论=残差集中在**数据结构形态**（136.6M 空锁读/53.4M BlockEdge 克隆/
mark_dead O[n] retain 5.58s）而非算法；oracle 形态=Funcdata 属主+裸指针交叉引用+单线程
Action 域零锁。campaign 双目标=**同时消灭锁/克隆速度地板与裸指针 alias unsafe**；行为恒等
红线四重（canon 双 md5+镜面五面钉值+全语料 cmp+tests 计数，任何非恒等立即停——设计 D10）。

落地序列（W0→W1 七段，全部已并 master；MB51 merge `718a856f`+环棘轮重冻结 `49337e77`
+账本 `4b1a4bbe`）：

| 阶段 | commits | 内容 |
|---|---|---|
| W0 ARENACORE（MB50a `ab018960`） | `14fe708f`+`5bc6e3cb`+`df364395` | `src/arena.rs` 2648 行纯新增：typed 代际 id（OpId/VnId/BlockId/HighId，8B=oracle 指针宽）+Arena<T,Id>（Vec 槽+free-list+gen，无迭代 API——物理槽序永不可观测）+IdList 侵入式 id 双向链（O[1] 保序 unlink/splice_after=std::list 同构）+POD 树键（Ord≡varnode.cc:34-79）+29 测（op.cc 生命周期重放+fuzz 模型对差分+400 记录逐字转录）。CR-ARENACORE REJECT（F1 splice pos==last 边界新 UB 窗）→ARENAFIX `df364395` 窄域修复→CR delta APPROVE（MB50b `efbd8073` 合入）。microbench：IdList::unlink 43ns vs Vec::retain 52,137ns@32.6K=**1210×**；arena alloc 10.9ns vs Arc 53.5ns |
| W1 (a) 容器 | `b36822f0`+`c1a5e3a4`+`a829d4d9` | VarnodeBank 双树 POD 键化+存储迭代器 arena+op 树 BTreeMap<SeqNumKey,OpId>；消费层九文件零改动；两起红线事件当场闭环（SpaceOff::null 偏移携带修复/insert 死锁） |
| W1 (b) 链翻转 | `929c94cf`+`092b5f78`+`feb6d98d` | op 七条 Vec 链→冻结 IdList，O[1] markDead 兑现（VARMAPOPCREATE 5.58s retain 地板消灭）；flow 24 处消费迁 OpId 游标；镜面 sqlite 捕获 clear 槽回收序红线→七链先摘再回收闭环 |
| W1 (c) 影子游标 | `41c98b38`+`d7eb7681`+`55190960` | opcode 反规范化影子+ActionPool OpId 游标（**28,722,524 rule tries 的 per-try 锁读消灭**）+coreaction 七工作集 id 化零克隆；ACTIONSTATS 双二进制计数恒等=最强恒等证明 |
| W1 (d) 边值化 | `b8ca60f9`+`cc1c7ef2`+`9f8f70fa` | per-graph BlockBank（Arc::as_ptr 键身份映射+zombie 槽生命周期=oracle identifyInternal 同构）+BlockEdge.point_id 值孪生+set_block_index 单点影子 |
| W1 (e) point 本体 | 6 commits（tip `fc801822`） | BlockEdge.point **Arc→BlockId Copy 值形态**（oracle block.hh:57-65 的 12B 语义；53.4M 克隆地板源头）+11 concrete 块型 owner-bank Weak 回指+跨域 18 文件 ~360 读位随迁；CR-E 条件式（examples 5 错位）→(f) fixup `6367b43a` 兑现，--examples 0 error |
| W1 (f) COW 快照 | 6 commits（tip `b1b42145`） | BlockBank 翻 COW-Arc 快照（发布后不可变 table+epoch 失效；mint 与冻结 arena 双实现并行回放恒等单测钉死）+blockstructure 读相全迁共享视图——**per-read 锁面 392.8M→37.9M=−90.3%**（BANKSTATS 实测：read_index −99%/read_arc −80%/id_lookups −97%） |
| W1 (g) unsafe 收尾 | 5 commits（tip `613ca4ea`） | transform.rs+prefersplit.rs `*mut Funcdata`+`unsafe impl Send` 系**双系消灭**（生产管线最后一族 god-pointer 清零）+size/flags 守卫影子（peer 深读→bank 原子影子）+unsafe 全库盘点表 |

**CR 链 A-G 七链全 APPROVE**（CR-ARENAFLIP-A..G：各区间独立 oracle 亲读+独立 git archive
快照复跑，报告 /dev/shm/rugra-reports/CR_ARENAFLIP_*.md；G 判决块逐字嵌入 MB51 merge
commit，G_BLOCK_EMBED_VERBATIM=YES 字节恒等亲证）。环棘轮协议重冻结 `49337e77`：
FROZEN_SCC 24==24 恒等，**arena 仍 solo 不入 core-SCC=W1 形态核通过**（E7 族 +2 bank 存储
键逐边定性；4 冻结键随改善消失）。

**双目标兑现证据**：
- **反编译算法核心域 unsafe=0**（CR-G §4 独立复算，grep 全库逐位人工分类亲证）：
  transform/subflow/prefersplit/block/blockaction/heritage*/varmap/merge/printc/coreaction/
  ruleaction/condexe*/flow 全域 0；`*mut Funcdata` 全库残留=0。
- **per-read 锁面 −90.3%**：392.8M→37.9M（替代语料 VdbeExec BANKSTATS 实测=1.49M
  read_index+9.96M read_arc+22.13M view_holds+4.33M id_lookups 恰口径；CR-G §5 独立复跑
  逐位复现+MB51 集成轮三跑全同=计数器确定性；探针开启 md5 仍 `abbd0632`=零扰动）。
- **性能兑现**（B2 亲跑，同语料 A/B 交错两对四跑）：替代语料全量 2813 fn --jobs 32
  **user −19.0%（中位 2107.5→1706.2s）/wall −30.1%（186.1→130.0s），四输出 md5 `e2b98cc8`
  逐位相同**；VdbeExec 单极（--one 2415）user 中位 **114.4s=（f）基线 135.34s 的 −15.5%**
  （优于 ~118s 预期包络；load 16-23 如实记）。

### 里程碑③ 速度总账（session 累计；三口径对照表）

| 口径 | oracle | Rugra 现值 | 比值 |
|---|---|---|---|
| sqlite 全语料 wall（--jobs 32，旧 1385 fn 轨道=session 主账） | 17.77s（w=32） | **~31.0s**（W1 缩放推算，注①） | **1.74×**（session 起点 159.9s=**9.0×**） |
| VdbeExec 单极 | 8.80s（direct-runner，旧语料） | 替代语料 --one 2415 user **114.4s**（−15.5% vs (f) 135.34s；md5 `abbd0632` 双轮逐位相同）；旧语料终值 41.21s[MB49]=**4.7×**（二进制消失不可直测） | 口径切换如实并列（替代语料函数本体更大，不可直除 8.80s） |
| per-child 固定底（每函数一子进程） | 0.10-0.11s/38MB RSS（one 模式同构） | **0.10s×5 稳定**（SLEIGHSNAP 后 in-gate 实测） | **oracle-par**（FIXEDFLOOR 判决=对齐成本非可修常数，−10~20ms 固有差） |

> 注①（~31.0s 口径）：旧语料二进制（/usr/local/bin/sqlite3）已消失，W1 增益以**替代语料
> （2813 fn，/tmp/sqlite3）同语料 A/B** 实测（wall −30.1%），叠加 MB49 旧语料实测 44.31s
> 得缩放推算 44.31×0.699≈31.0s。session 累计 **159.9→31.0s=−80.6%**。
> 注②（全轨迹，每环输出字节恒等伴随）：全语料 wall 159.9→140.4[MB40]→130.0[MB41]→
> 82.1[MB42]→79.9[MB43]→64.7[MB45]→61.9[MB46]→53.7[MB47]→46.6[MB48]→44.3[MB49]→
> ~31.0[W1 arena]。VdbeExec 旧语料 159.2→41.21s[MB49 终值]；W1 段内（车道口径）45.92→
> 44.1[a]→36.7[b]→35.2[c]→~35.0[d/e]→(f) 配对 −2.94s→(g)→MB51 集成 114.4s（替代语料）。

### 现值总表（@ master `4b1a4bbe` = origin；MB51 收官亲测，全部溯源终报）

| 门禁 | 数字 | 说明 |
|---|---|---|
| canon curl | **0/0/0**·124/124 matched | md5 `4ab1db2a…`==MB38 归零态字节恒等（MB38~MB51 历批复验）；result/ 已回流 |
| canon httpd | **0/0/0**·34/34 matched | md5 `7d5b9e7c…` 同上恒等 |
| 镜面五面 | curl **13**/74 · httpd **2**/29 · vsh **0**/71[完美面] · sq **432**/810 · sqlite **785**/1385，全 PASS | defects=numbering=0 五面；stale-guard digest b59c653a·files=155（==CR-G 独立复跑指纹）；钉值行=MB41[curl/httpd]·MB39[vsh]·MB48[sq]·MB49[sqlite]，窗口内重钉链 MB44 `5c5beb0b`→MB47 `0fc55918`→MB48 `1fb179b2`→MB49 `fae5aade` |
| 镜面窗口燃烧 | sqlite 1655→**785**（MB44 −176/MB47 −634/MB49 −60）· sq 516→**432**（MB44 −2/MB47 −56/MB48 −26）· curl/httpd/vsh 恒等 | 燃烧族=CASTSHAPE+CASE-CAST/CASTSUB23+FTSINCRMERGE/L1SURGERY/SQLITEDUPLABEL（全部 canon 恒等伴随） |
| cargo test --lib | **2022P / 0F / 5I** | 1974[MB43]→2022（+48 逐道对账：MB44 +2/MB47 +4/MB48 +4/MB49 +3/W0 +29/ARENAFIX +1/W1-f +3/W1-g +4） |
| 投影银行（B2 钉板） | **391/391 MATCH** | 全批次共证（冻结投影 sha256 钉+mirror 裸径采集契约） |
| 速度 | 全语料 wall ~31.0s（W1 缩放口径）/替代语料 2813 fn 实测 130.0s；VdbeExec 替代语料 user 114.4s | 见里程碑③双轨口径 |
| unsafe 残量（(g) 段盘点表+CR-G §4 独立复算） | **核心域 0**；生产管线 9=compression 6[libz FFI 本征]+cover/funcdata Iop 解码 2[安全化实测 10×+ 墙钟回退阻断，修复路径=OpId codec 票]+sleigh_ffi 1[kuna Rc Send 契约]；豁免 7=ffi.rs 4+float_emulate libc 3[用户裁定] | `*mut Funcdata` 全库 0 |
| per-read 锁面 | **37.9M** | (f) 前基线 392.8M=−90.3%；BANKSTATS 计数器确定性三跑全同 |
| 三门禁+gate health+.sla+环棘轮+examples | annotations 101 文件/refs --all --strict/markers 0 violation（2 allowlisted）/evidence self-test 6 cases strict 4/4/gate health OK[oracle=e40ed130]/.sla 四 sha==钉值/FROZEN_SCC 24==24（arena solo）/build --examples 0 error 双 profile | 全绿（MB51 集成轮亲跑；CR-E 条件保持） |
| CI（alignment-gates） | 两 job 形态见 2026-09-29 节 | 本刷新 docs-only 未跑（纪律：不跑门禁） |

### 剩余工作地图（下一战场；票面全部在案）

| 战场 | 状态/票 | 说明 |
|---|---|---|
| **W2 重测** | 在飞（/dev/shm/rugra-worktrees/w2remeasure） | arena campaign 收尾 wave：SPEEDPROF 同口径五道复跑，W1 后残差重排（PERF-ARENA-MIGRATION-0001 W2 子票） |
| **镜面归零路径 v3** | 在飞（/dev/shm/rugra-worktrees/mcensus5） | 五面现值 13/2/0/432/785 口径再归因+归零路径表 v3（MIRRORCENSUS4 v2 后第三代） |
| 块存储翻转定界票 | OPEN（W2 后评估） | enum BlockKind arena 终态——全量=364 句柄引用+~2000 .read() 位跨 6+ 域外文件（printc/flow/heritage/jumptable/condexe）；(g) 段诚实定界缓置；view_holds 22.1M≈0.4s 残面连根收 |
| PERF-ARENA-CHOKE-0001 | OPEN（P2，MB51 随批登记） | CR-G NIT-1：非守卫位旗 ~17 机械直写位收 choke（size/flags 影子全字闭集化；或文档收窄二选一） |
| ARENA-UNSAFE-LEDGER-0001 | OPEN（P3，MB51 随批登记） | CR-G NIT-2：kuna-sleigh 2 生产 unsafe 位补录/盘点表口径收窄（核心域=0 结论不受影响） |
| W3 可选 Architecture 面 | 待 W2 数据决策 | qlst/jumpvec id 化（funcdata.hh:88-89 低频 churn）；SLEIGHSNAP 74ms 图物化地板同域（设计期已标注预期零改善） |
| 镜面残差续燃 | 各票在案 | sqlite 785（WhereCodeOneLoopStart 90 等 SWITCH-GOTO goto↔break 反转+index-cast 90+long-addend ~150+read_inode 簇 ~211+UNAFF 108）/sq 432（GOF-WHILEDOOVERFLOW P2 族表首位 fam=25+小残差）/curl 13（UNTYPEDCONST 9+NONALLOC-STRFOLD 2+尾量 2）/httpd 2（ap_fini decl-move=第三完美面最后一步） |
| try_rule_cat 64 帽/visit_count HashMap | 账本登记观察项（CR-G 移交） | 安全帽+FxHash 迭代序位点先在形态函数账本标注 |

### 可靠性评估（诚实计量）

1. **红线体系**（arena 设计 D10 四重行为恒等红线，全程运转零返工）：①canon 0/0 字节恒等
   ×全程（归零态 md5 双钉历批复验；W1 重构逐段每 commit 树亲跑双 md5，各段红线事件全部
   当场闭环）；②镜面钉值恰顶格（五面单向棘轮+stale-guard digest==CR 独立指纹）；③全语料
   A/B 四跑输出 md5 `e2b98cc8` 逐位相同；④tests 计数可归因（+48 逐道对账闭环）。伴随更强
   形态证据：ACTIONSTATS 双二进制计数恒等[（c）段]、BANKSTATS 计数器确定性三跑全同、
   COW mint 与冻结 arena 双实现并行回放恒等单测、W1 验收 §8 红线八条全绿兑现。
2. **CR 链**：本窗口（MB44~MB51）机制 C 独立复核判决 21 份，覆盖改动终态全链 APPROVE
   ——18 份直接 APPROVE（CR-CASTSHAPE/MERGEREQ/ACTIVEPARAM/HERITAGE/CASTSUB23/
   BLOCKSTRUCT/L1SURGERY/VARMAPOPCREATE/SPEEDPROF2/INFERTYPES/INTERSECTCACHE/
   ARENAFLIP-A..G）+2 起初判 REJECT 被独立复核真实拦下后窄域修复翻正（CR-FTSINCRMERGE；
   CR-ARENACORE→CR-ARENAFIX delta 覆盖）——REJECT 门槛非橡皮图章。
3. **覆盖边界**：canon 零态覆盖 curl+httpd 158 函数；镜面覆盖五面（sqlite 1385/sq 810/
   vsh 71/curl 74/httpd 29）；速度为 sqlite 语料域同机配对 A/B（负载各轮如实记录）。
   **全局完成度仍未证明**——权威判定=9494 分母逐函数 oracle 行为门禁（FUNCTION_MAP
   账本，默认 UNTESTED，仅锁定 fixture 同输入/同输出可升 MATCH）。canon/镜面零态、速度
   增益与 unsafe=0 **不构成模块或项目 L3 声明**。
4. **口径纪律**：速度双轨如实并列（旧语料轨道=session 累计账；替代语料=W1 A/B 实测载体）；
   VdbeExec 旧语料 md5 钉面随二进制消失不可恢复（车道勘定在案），替代语料 md5 `abbd0632`
   双轮逐位相同为新钉；canon 沿 F2B/PFLIP 分界后口径；镜面 curl 13 沿 COMPAREFIX 工具口径。
5. **已知未清项**：镜面残差五面 1232 行（13+2+0+432+785，归票见剩余工作地图）；unsafe
   生产管线 9 位（FFI 本征+Iop 解码 2 待 OpId codec 票）；速度域 W2 复测前残差清单待重排；
   httpd 语料 DWARF-less（HTTPD-CORPUS-DWARF-0001 在案）。

## 2026-09-29 STATUSREFRESH 大刷新（历史——MB43 收官态快照；数字被 2026-10-01 节取代）

> 数据源全部在案：波次账本 `.slim/deepwork/stage-bisect-e2e.md`（MB27~MB43 全序列 200+ 条）+
> 各 MB 终报（`/dev/shm/rugra-reports/LANE_MERGEBATCH3{5..9}_*` / `LANE_MERGEBATCH4{0..3}_*`）+
> `tools/mirror_gate_baselines.tsv` 现钉值。本节为 docs-only 汇编，数字与在案证据一致，**未跑新门禁**；
> 口径不确定处逐条标注。评测语义分界点①（PFLIP）②（F2B）见下方历史节——canon/httpd 数字
> 沿分界后口径，与更早谱系不可比；镜面沿 `--base 0` direct-runner golden 口径。

### 里程碑① canon 双语素零残差（评测最强证据态；MB38 达成后六批保持）

**curl 与 httpd 双语料 canon 面 skeleton/defects/numbering = 0/0/0，124+34 函数全数零残差**
（逐函数 ✗ 计数=0；输出 md5 双钉：curl `4ab1db2a177e854c6bddca2ecf413685`·96,616B /
httpd `7d5b9e7c3348ee8da1865df281ec05b9`·62,715B；vs `tests/golden/ghidra_{curl,httpd}_1204.c`）。

归零冲刺轨迹（每行=MB 收官态，逐函数精确归因在案）：

| 批次收官态 | curl | httpd | 主燃车道（归因） |
|---|---|---|---|
| MB34（冲刺起点） | 42 | 34 | displayrebase −12/−2（UNK 码标签传输，INT_TO_PTR 族全额；md5 8dafa799/2fbf13b1） |
| MB35 | 27 | 26 | booldrill −10 + declfam −5 / strdatenv −6 + declfam −2（curl main 首次清零） |
| MB36 | 8 | 14 | initprotofid −15 + s2select −4 / declorder −12（六站 [Skeleton] identical） |
| MB37 | 8 | **0**（首语料归零） | — / protorecover −8 + mainmixed −6（双函数+main 体字节==golden） |
| MB38 | **0** | 0（保持） | entryconv −5（_start 输出==golden 逐字节）+ strdatcurl −3（myprogress 62 行==golden） |
| MB39~43 | 0 | 0 | 零态红线字节恒等保持（md5 ==MB38 归零态，六连批复验） |

campaign 总轨迹：**curl 157→0 / httpd 311→0**（MB19 时代基线→MB38；归零冲刺段起点 42/34）。
残差清零机制谱系在案：PROTORECOVER / MAINMIXED / ENTRYCONV / STRDATCURL / INITPROTOFID /
DECLORDER / BOOLDRILL / DECLFAM / STRDATENV / S2SELECT / DISPLAYREBASE 等车道逐函数兑现，
核心算法白名单改动全部走机制 C 独立复核。canon-only 门控期间镜面恒等保持（MB38 零重钉亲证）。

### 里程碑② 镜面棘轮剧变（五面大收敛；MB34 钉值 → 现钉值）

| 面 | MB34 钉 | 现钉 | 变化 | 主燃根因（重钉票链） |
|---|---|---|---|---|
| curl | 21 | **13** | −38% | MB41 SWITCHBREAK −2（glob_word）+ COMPAREFIX 计量 −6（SetHTTPrequest 双胞胎幻差；新工具口径） |
| httpd | 36 | **2** | −94% | MB41 MAINTYPE −28（main 体 529 行==golden；xunknown-vs-int 单根族）+ MB37 PROTORECOVER −6 |
| vsh | 2 | **0** | 完美面 | MB39 ACTORDER（spacebase scope 装表燃掉最后一站 (code\*)；71/71 零残差） |
| sq | 2724 | **516** | −81% | MB36 selectgoto+s2select −1095 → MB37 −20 → MB39 ACTORDER −883 → MB43 CASTFUSE2 −210 |
| sqlite | 6071 | **1655** | −73% | MB36 −912 → MB37 −202 → MB39 −204 → MB41 SWITCHBREAK −237 → **MB42 STACKSLOT2 −1907（campaign 最大单笔）** → MB43 CASTFUSE2 −954 |

重钉序列（`tools/mirror_gate_baselines.tsv` 现钉；pinned_commit=测量树，repin commit 只改本表）：
MB36 `20819307` → MB37 `e124f9bf` → MB39 `128e4934` → MB41 `ffb7b819` → MB42 `8103c7c6` →
MB43 `61a08bce`。每轮强制重链（二进制 mtime>全部 merge commit）+ stale-guard 内容探针 +
五面 fresh PASS==钉值恰顶格后才收紧（单向棘轮，改善不失败）；现钉行=MB41（curl 13·74/
httpd 2·29）、MB39（vsh 0·71）、MB43（sq 516·810 / sqlite 1655·1385）。五面
defects=numbering=0，matched 满额 74/29/71/810/1385，health ok。

### 里程碑③ 速度减半（sqlite 语料域；vs oracle 三口径）

| 口径 | 优化前 | 现值 | 降幅 | vs oracle |
|---|---|---|---|---|
| sqlite 全语料 wall（--jobs 32，RUGRA_GEN_MIRROR 全量） | 159.9s | **79.9s**（ok 1385/1385，panic 0） | **−50%** | 9.0× → **4.5×**（oracle w=32 = 17.77s） |
| VdbeExec 单极（--one 1055 裸跑） | 159.2s | **71.1s**（中位；70.84/71.28 双跑，la-65 尖峰 79.21s 离群在案） | **−55%** | 18.1× → **8.1×**（oracle direct-runner = 8.80s；SPEEDPROF 首测 166.5s=18.9×） |
| per-child 固定底（每函数一子进程） | 0.12s | 0.12s | — | **oracle-par**（oracle one 模式 0.10-0.11s/38MB RSS 同构；FIXEDFLOOR 判决=对齐成本非可修常数，−10~20ms 固有差） |

速度优化链（每环伴随输出字节恒等链验证，行为零漂移）：

| 链环 | 落地批 | 增益 | 机制 |
|---|---|---|---|
| PAR-CHILDREN | MB35 | **5.76×**（harness 953.6→165.4s；落地 917.8→161.1-181.7s） | 函数级子进程池（默认 jobs=8；任意 --jobs stdout 与串行逐字节恒等，fail-closed） |
| GATEDIGEST | MB35 | **54×**（vsh 冷 14.52s→命中 0.27s；五面全暖重放 0.39s vs 串行 1476.8s） | 门禁 digest 缓存（六分量全内容 sha256 键，任一变即失效，fail-closed） |
| VDBEEXEC | MB40 | **−46.5%**（单极 159.2→85.2s；refresh_switch_cases 12701→11 调；collapse_internal 86.0→16.2s） | refresh 自创簿记移位 collapseAll 尾（oracle 无对应物，RUGRA-GLUE 残留清除；CR-VDBEEXEC） |
| OPPPOOL | MB42 | **−16%**（VdbeExec bare 92.3→74.9s） | per-op 规则池派发钻修（投影键缓存+miss 路径锁合并+lone_descend 免分配；CR-OPPPOOL） |
| OPTREE | MB43 | **−7.2%**（77.1→71.5s 车道口径；联合树中位 71.1s） | PcodeOpTree=BTreeMap<SeqNum,PcodeOpRef>＝oracle op.hh:280 原生同构（免锁下降） |
| （累计轨迹） | — | 全语料 159.9→140.4[MB40]→130.0[MB41]→82.1[MB42]→**79.9s**；单极 159.2→101.9[MB40 合并树]→92.3→74.9→**71.1s** | — |

### 现值总表（@ master `16851e20` = origin；MB43 收官亲测，全部溯源终报）

| 门禁 | 数字 | 说明 |
|---|---|---|
| canon curl | **0/0/0**·124/124 matched | md5 `4ab1db2a…`==MB38 归零态字节恒等（MB38~43 六批复验）；result/ 已回流 |
| canon httpd | **0/0/0**·34/34 matched | md5 `7d5b9e7c…` 同上六批恒等 |
| 镜面五面 | curl **13**/74 · httpd **2**/29 · vsh **0**/71 · sq **516**/810 · sqlite **1655**/1385，全 PASS | defects=numbering=0 五面；health ok；钉值行=MB41/MB39/MB43（见里程碑②） |
| 投影银行（B2 钉板） | **391/391 MATCH** | 全批次共证（冻结投影 sha256 钉 + mirror 裸径采集契约） |
| cargo test --lib | **1974P / 0F / 5I** | 1963P（MB34）→1974P（+11 逐道对账全绿：MB36 +6 / MB37 +3 / MB41 +1 / MB43 +1） |
| 三门禁 + gate health | annotations 100 文件 / refs --all --strict / markers 0 violation / evidence self-test 6 cases strict 4/4 | 全绿；oracle=e40ed130（锁定）；hooks=.githooks |
| .sla 三元 + 环棘轮 | sweep 146/146；CYCLE-RATCHET SCC≤24 | 全绿 |
| CI（alignment-gates） | 见历史节两 job 形态 | 本刷新 docs-only 未跑（纪律：不跑门禁） |

### 可靠性评估（诚实计量）

1. **证据强度分层**：canon 零态=函数体字节级恒等（md5 双钉，本项目最强局部证据形态）；
   镜面=单向棘轮 + digest-cache fail-closed + 强制重链/stale-guard 协议；速度=同机配对
   A/B + 输出字节恒等链伴随。三者均为**语料级差分证据**。
2. **覆盖边界**：canon 零态覆盖 curl+httpd 双语料 158 函数；镜面覆盖五面（sqlite 1385/
   sq 810/vsh 71 等）；**全局完成度仍未证明**——权威判定＝9494 分母逐函数 oracle 行为门禁
   （FUNCTION_MAP 账本，默认 UNTESTED，仅锁定 fixture 同输入/同输出可升 MATCH）。canon/
   镜面零态与速度增益**不构成模块或项目 L3 声明**。
3. **已知未清项**：镜面残差 sq 516 / sqlite 1655 / curl 13 / httpd 2（归零路径在案，见下）；
   速度域残余（PERF-GEN3839-VDBOVERHEAD-0001：MB38/39 gen 驱动新装通道每函数成本 +16.7s；
   blockstructure 残 18s / activeparam 10-15s / heritage 9-14s / mergerequired 6.3s；
   SPEEDPROF-SLEIGH-SNAPSHOT-0001 后续票）；httpd 语料 DWARF-less
   （HTTPD-CORPUS-DWARF-0001 在案）。
4. **口径纪律**：速度数字为共享机口径（MB43 实测 la 52-69 记录在案；OPTREE 车道 76.0s
   系更静主机口径，如实并列）；canon 数字沿 F2B/PFLIP 分界后口径；镜面 curl 13 为
   COMPAREFIX 后新工具口径（同二进制，配对修正；工具 sha 入 digest 键，era 切分 fail-closed）。

### 镜面归零终盘地图（MIRRORCENSUS3 census + MB41~43 战果更新；归零路径在案）

| 面 | 现值构成（在案归因） | 归票 / 路径 |
|---|---|---|
| curl 13 | typed code-ptr 符号化 **9**（main 6 + _start 3，8 符号位点） | PRINTC-UNTYPEDCONST-CURLMIRROR-RESIDUAL-0001（MB25 起路径明确＝分析期 DB typed 通道，GEN-CONSTPTR 家族） |
| | 非 ALLOC strfold 2 + decl-move 尾量 2 | MCENSUS3-CURLDRIVER-NONALLOC-STRFOLD-0001 + 尾随族 |
| httpd 2 | ap_fini decl-move 2 | 尾随族（canon 面已燃；镜面位点属 MIRATTR-F-WRAP-0001 域） |
| vsh 0 | 完美面（71/71 零残差） | — |
| sq 516 | CAST-SHAPE 残（census3 时代 290 − MB43 210）+ OTHER 148 + UNAFF-EXTRAOUT 96 + OPNAME-LEAK 67（read_inode 族）+ SWITCH-GOTO 40 + DECL-CHURN 37 + 尾量 48 | read_inode 族 213（29%）/ NLZMA 簇 ~362（50%）＝两大主簇；TYPEFACTORY 残差→VARMAP-UNAFF-TYPEMAT 租约 |
| sqlite 1655 | **CAST-SHAPE 634**/161F（`(uint4*)(uint8)` 207 处＝varmap/typeprop 邻域）+ SWITCHDISPATCH goto-label 族 + UNAFF-EXTRAOUT / DECL-CHURN / LOOPSHAPE 102 / CMP-ORIENT 85（ExprIsConstant×5 克隆）/ 尾量 | GEN4-SQ-CASTFUSE-DEPTH-0001 续作 + MIRROR-GIANTS-SWITCHDISPATCH-0001（sqlite ~345 + sq 34）+ GETLONGEST 续作（selectGoto/likelygoto） |

已燃核销（census 对账→现值，路径清晰度全部在案）：sq/sqlite (code\*) 族全燃（sq 131==golden
131 精确）；S1W2 trio 2035 在飞族全燃（MB42，vmprintf/mprintf/Pragma 696/696/643→58/58/55，
CONCAT88 287→0）；curl compare 配对伪差 6 燃（MB41 工具修正）；httpd main xunknown-vs-int
28 燃（MB41 MAINTYPE）；switch break-vs-goto 三面大半燃（MB41 −239）；GetLongestMatch 六克隆
656→1 燃（MB36）。叠加推演在 census zero_path 表：S1W2+CASTFUSE 落地后 sqlite 已自 ~4750
落至 1655；余路径全量兑现预估 sqlite →~700-1000、sq →~250-350、curl →~4、httpd →0。

### CR 体系与测试（本 session 机制 C 运转数据）

七项核心算法独立复核全 APPROVE（APPROVE 块逐字嵌入对应 merge commit）：CR-PROTORECOVER
（MB37 `998ac672`）/ CR-VDBEEXEC（MB40，61 行块）/ CR-MAINTYPE + CR-SWITCHBREAK（MB41，
25/13 行）/ CR-OPPPOOL + CR-STACKSLOT2（MB42，24/26 行）/ CR-CASTFUSE2（MB43 `61a08bce`，
判决全文+四类语义表+事件级钉形）。测试 1963P→**1974P**（+11 逐道对账，0F 全绿）。

### 下一战场（MB43 终报移交清单）

sqlite 1655 续燃（CAST-SHAPE 634 域 + goto-label 族）/ curl 残 13（UNTYPEDCONST 族）/
httpd 残 2（ap_fini decl-move）/ 速度域（blockstructure 18s + activeparam 10s + heritage
9-14s + PERF-GEN3839-VDBOVERHEAD-0001 归因 + miss 重读 ~0.5s 观察票 + SLEIGH-SNAPSHOT 票）。

## 2026-09-26 F2B 双驱动原生 0x100000 载入快照（历史——评测语义分界点②）

**canon 面原生 image base 载入**（Lane F2B，wt/f2b @ master 594d6982，用户拍板
HTTPDMAIN-F2-IMAGEBASE-DECISION-0001 方案 (b)；examples 双驱动，**零 src/ 改动**）：
httpd+curl 的 canon 反编译面以 analyzeHeadless 首选基 **0x100000 原生载入**
（ELF 真实 image base——oracle 直跑实证：canon golden=analyzeHeadless 0x100000 载入，
stage-projection oracle=BfdArchitecture 原始 vma base 0，故 mirror/bank 面恒等保持
base 0）。manifest 键本就 canon 数值（零重键），驱动侧查找直取。

**⚠ 评测语义分界点②（F2B commit=分界）**：分界后 canon 输出地址为 image-based
（`0x10xxxx/0x12xxxx` 形）。**raw-diff 与地址计数类指标与历史不可比**（F2 假差异族
从 raw 口径整体消失：httpd main base-0 常量 135→0、retaddr 行 14/14 字节恒等、
main raw diff 713→685、全窗 1747→1711 零回退；curl H 族值愈 `0x3af8`→`0x103af8`）。
compare 的 skeleton 口径因 hex→LIT 掩码对 F2 中性，**数字连续可比**
（httpd 34/255/0/0、curl 124/246/0/0，分界前后恒等）。

**门禁与钉板**: bank 391/391 PASS（冻结锚未动，镜像再捕获投影体字节恒等）；
mirror gate httpd PASS 138/150·29/29（==冻结基线，**bank/镜面基线均无需重钉**）；
五脸极性复验通过（默认 255 / PARAMID=0 255 / V3SIG=1 255 / IMPORTSIG=0 525 /
SEEDS=0 749，方向保持）；gcc 审计 httpd 15OK/14FAIL==基线。O5（MIRROORGATE-BASE-
ORAL-0001）随两面各同基收口。残差：curl `(undefined *)0x103af8` 常量 cast 半
（PRINTC-CONST-DISPLAYREBASE-0001 半残差，printc 域）与 F4 主体族（独立在账）。

## 2026-09-26 PFLIP 自产参数锁默认转正快照（历史——评测语义分界点①）

**自产 Parameter ID 模式默认转正**（Lane PFLIP，wt/pflip @ master efc28f4a，用户拍板
PARAMID-DEFAULT-FLIP-0001；examples 驱动层极性翻转，**零 src/ 改动**）：httpd+curl 双驱动的
`paramid_active` 默认 ON（`RUGRA_PARAMID=0` 逃生断路），callee-siglock manifest 通道退
opt-in（仅 `RUGRA_V3SIG=1` 显式开；`=0` 保持 kill 义）。优先链=mirror > `RUGRA_SEEDS=0` >
PARAMID（默认）> V3SIG（opt-in）。generic_clib 导入签名台账（59 条）保持默认开捆绑——
`RUGRA_IMPORTSIG=0` 断路将退无导入锚脸（亲测 285→537；PAB 口径 ~691 族同向），台账为默认脸
承重数据。转正判据=PAB A/B 复证（自产 ≥ manifest 严格成立+导入锚在场时锁源脸中性）。

**⚠ 评测语义分界点（PFLIP commit=分界）**：httpd 默认脸口径自本 commit 起为**自产口径**。
分界前数字谱系——908/898/862/590（纯 manifest 期，无导入锚）与 439/285（IMPORTFLIP 后
manifest+导入锚）——均属 manifest 口径，**与分界后数字不可比**。分界后基线=httpd 默认
**285/0/0**（与分界前 285 字节级仅差 7 行 typedef 序言——自产拼写避开 undefined 族，canon
golden 零 typedef 行→更贴 canon）；curl 默认 267/0/0 分界前后恒等（锁源脸中性），
`result/curl_cur.c` 无需回流。

| 门禁（fast-release 亲测，@ master efc28f4a + PFLIP） | 数字 | 说明 |
|---|---|---|
| httpd E2E（新默认脸=自产） | **285 / 0 / 0**（34 函数） | 双跑 cmp 恒等+并发负载复现恒等；函数体与 manifest 脸逐字节同（唯一差=7 行 typedef 序言）；vs `tests/golden/ghidra_httpd_1204.c` |
| httpd manifest 恢复（`RUGRA_PARAMID=0 RUGRA_V3SIG=1`） | **285 / 0 / 0** | ==翻转前默认脸 cmp **字节恒等**（回归证据）；manifest 文件与 harvest 工具链保留 |
| httpd `RUGRA_PARAMID=0` 单退 | **285 / 0 / 0** | ==manifest 脸字节恒等——@efc28f4a 自产/manifest/无锁三态在导入锚在场时脸中性（IMPORTFLIP 台账已吸收 manifest 历史贡献） |
| httpd `RUGRA_IMPORTSIG=0` 降级 | **537 / 0 / 0** | 断路实证（+252）；台账承重；A/B 仪器保留 |
| httpd `RUGRA_SEEDS=0` 逃生 | **785 / 0 / 0** | 裸脸（全局逃生门，一切播种通道静默关） |
| httpd gcc 审计（新默认脸） | 15 OK / 14 FAIL | fail 名集与 manifest 脸/翻转前默认**逐名恒等**（pRam 族=在账预存域） |
| curl E2E（新默认脸=自产） | **267 / 0 / 0**（124 函数） | sha `c0610164…` ==翻转前默认==manifest 恢复==`RUGRA_PARAMID=0` 单退（三脸等式维持，canon 零回退）；复现 10/10；首跑并发下一次字节离群（gate 同 267/0/0）→ TODO PARAMID-CURL-LOADDETERMINISM-0001 |
| 投影银行（B2 钉板） | **391/391 MATCH** | 冻结投影 sha256 钉+mirror 裸径契约→不受门极性影响（亲验） |
| 镜面棘轮 | curl 78/275、httpd 208/460、vsh 15/55 全 PASS | 上限未动（mirror 恒拒一切通道——极性翻转不变量亲验） |
| 三门禁（annotations/refs/evidence） | 全绿 | src/ 零改动（97 文件注解/引用不变量） |

**PARAMID 门 env 语义矩阵（PFLIP 后）**：

| env 形态 | 行为 |
|---|---|
| （无） | **自产迭代默认开**（httpd 主循环前迭代环+curl worker 表接管；curl 仅 DriverMode::All） |
| `RUGRA_PARAMID=0` | 单门退（自产迭代关；callee-siglock 通道落到 V3SIG 门——见下） |
| `RUGRA_V3SIG=1` | manifest 显式开（仅 `RUGRA_PARAMID=0` 时生效——PARAMID owns channel 优先） |
| `RUGRA_V3SIG=0`/unset | manifest 不装（manifest 通道 opt-in 形态） |
| `RUGRA_IMPORTSIG=0` | 导入锚断路（默认脸劣化——仪器用途，非逃生门） |
| `RUGRA_SEEDS=0` | **全局退**（PARAMID/V3SIG/IMPORTSIG/TYPESEED 等全关，裸脸） |
| mirror 分量在场 | 恒拒一切通道（projection purity，含显式 =1） |


## 2026-09-26 W-2026-09-26 波次快照（历史——车道谱系+质量数字；在飞车道另计；数字被 2026-09-29 节取代）

> 本节基点 = master **efc28f4a**（CI 全绿，见 §门禁与 CI）。已并入 master 的车道给终值；
> 尚在分支待 root 合并的车道（PRINTCS/SQNULLT/SQMERGE/GEN5/BRANAUDIT 等）单列
> "在飞待并"小节，数字为车道终报实测，**不代表 master 合成态**——叠加效果待 root 集成复测。
> 质量数字全部溯源车道终报（/dev/shm/rugra-reports/LANE_*_2026-09-2[56].md）。
> **MERGEBATCH 集成注记（root 2026-09-26）**：本节所述"在飞待并"车道已全部并入 master——PRINTCS `d0e27c14`、SQNULLT `59bf17bf`、SQMERGE `e54af07d`、BRANAUDIT `f62bef3a`、DOCSYNC `af526da5`、TESTFIX `a96e2480`、PFLIP 本合并 commit；GEN5（wt/gen5）仍在飞。下表数字仍为车道终报口径，master 合成态实测见 LANE_MERGEBATCH_2026-09-26.md。
> **MERGEBATCH2 集成注记（root 2026-09-26，九支串行零丢失并入 `b46e2a5e..5bf7afdb`）**：CURLATTR `f79659be`（docs，curl canon 267 残差 18 族归因+12 票）、DOCGUIDE `6fa155cc`（docs，手册刷新）、BRANHYG `2ee66159`（docs，分支清理收口）、FMAPRECON `8f24b79a`（docs，分母对账 9494+REGEN 票）、PERFAN `19109a14`（docs，性能深挖+6 票含 DIVCHAIN P0）、PANICSWEEP `ec03e660`（examples/bin_sweep.rs+记分板+3 新族票）、GLOBREPIN `36f9156c`（三打捞票收口+fixtures 重钉+runner 卫生）、CORESMALL `7be4d899`（typeop/coreaction 两票，CR-CORESMALL APPROVE+O-1/2/3 观察）、RASWEEP `5bf7afdb`（ruleaction 两票+散文重钉，CR-RASWEEP APPROVE+F1 UNTESTED-branch 限定/F2 行引勘正）。终态 fresh 实测：canon curl **266**/0/0（=267−coresmall _start 警告行，预期精确命中）+httpd **283**/0/0 恒等；镜面 curl **67**/275（=69−coresmall 警告面×2）+httpd **196**/460 精确+vsh **13**/55（=14−coresmall _start 面）全 PASS 零缺陷；sq 面承重态 ok **808/810**+matched **808≥805**+skeleton **9142≤22639**+defects 0+numbering 7=在案承重红（同 MERGEBATCH 态 9163→9142 改善向;PRETTYFLUSH 余 2 修复在 wt/pflush 未并）;bank **391/391**；cargo test --lib **1747P/0F**；三门禁+doc_sync 绿；flip 语义实证（[PARAMID] 85 行三轮默认+siglock manifest skip）。九支 worktree/分支/targets 已回收。终报=内存盘车道终报目录 LANE_MERGEBATCH2_2026-09-26.md。

> **MERGEBATCH3 集成注记（root 2026-09-26，五支串行零丢失并入 `46ffb6c2..d50168fc`）**：KUNAUB `69934c99`（docs，kuna UB 六项对照复检+4 票）、PFLUSH `4f6b9b20`（prettyprint/printc，PendingBrace BraceId 身份化，prettyprint.rs:3946 panic 族全灭）、DIVCHAIN `7080de6c`（ruleaction P0 非终止修复，CR-DIVCHAIN APPROVE=五复核点 5/5+终止性单调测度独立证明）、CURLE `92730a61`（debugproto delta-depth，canon curl E 族收敛）、VZEXT `c3768261`（printc ZEXT 子族收口，CR-VZEXT 窄域 REJECT 两条件已清免重审）+ B2 fixture 固化 `d50168fc`（PATHOSLOW-DIVCHAIN：sqlite3 idx55 双侧字节恒等 MATCH，oracle 纯净重建直跑+集成态 gen_decompile，tests/oracle/divchain_sqlite_bitvec_1204 四件套）。五支三点 diff 筛查零陈旧树病、零丢失。终态 fresh 实测：canon curl **247/0/0**（=266−19 E 族，精确命中）+httpd **263/0/0**（=283−20 SEXT48，精确命中）；镜面 curl **59/275**+httpd **172/460**+vsh **13/55** 三面 PASS 改善向（棘轮未重钉，实测供 root 参考）；sq 面 matched **810/810** health=ok（PRETTYFLUSH 余 2 panic 清零，MB2 808→810）+skeleton **8504**+defects 0+numbering 7=GetOptimum 预存承重红（SQFACE-NUMBERING-GETOPTIMUM-0001 在案）；bank **391/391**；cargo test --lib **1752P/0F**（1747+divchain 5）；三门禁+gate health 绿；flip 语义实证（PARAMID 三轮默认定点+V3SIG opt-in）。五支 worktree/分支/targets 已回收。终报=/dev/shm/rugra-reports/LANE_MERGEBATCH3_2026-09-26.md。

> **MERGEBATCH4 集成注记（root 2026-09-26，两支并入+一支 defer，区间 `e486fb18..`）**：F8FOR `c961ed8d`（block/blockaction/printc/prettyprint/coreaction，for 循环形成族 block.cc:3080-3488 六函数 1:1 落位；CR-F8FOR APPROVE=六函数族零 MISMATCH+放置偏差合规登记；同 commit 登记 F8FOR-FINALIZE-VISITED-0001（P2 MEDIUM 潜伏,finalize visited 守卫）+ROADMAP 两锚点补记；MSTRUCT-FORSPLIT-DECOMP-0001 SUPERSEDED）；JTDEST `7087a579`（jumptable 错误文本归真 flow.cc:133-137+gen_decompile 全空间范围；CR-JTDEST APPROVE=文本逐字等价+全空间契约亲证；同 commit 登记 JTDEST-FLOW-CATCH-ABORT-0001 P3）+F3 同修 `d7b5ad5a`（bin_sweep.rs 同款有界默认改全空间）。**SLOTDEEP defer**：重制 commit 4255fadb 父=7ac53771（stale d0e27c14 树）非声称的 46ffb6c2，树缺 MB3 的 divchain B2 fixture 四件+worktree 残留 staged +355 行回加已退役 resolver 层（重制会话失联现场）→按筛查红线 defer，worktree/分支/targets 保留 root 裁决。终态 fresh 实测（slotdeep 未并）：canon curl **247/0/0 与 pre-merge 基线字节恒等**（预期 −3 未转移：config-for 位点在 master 现 IR 不成形，属已登记 F8FOR-REJECT-RESIDUAL-0001 拒绝族；pre-merge 工作树 A/B diff=0 亲证零回退）+httpd **255/0/0**（=263−8，精确命中）；镜面 curl **61/275**（+2=拒绝族迁移残差,车道预告）+httpd **146/460**（−26=for-split 族精确兑现）+vsh **15/55**（+2 同族）全 PASS 棘轮未重钉；sq 面 matched **810/810**+health=ok+skeleton **8418**（=8504−86 f8for 增益;slotdeep 退役的 ~7250 降幅随 defer 未兑现）+defects 0+numbering 7=预存承重红；bank **391/391**；cargo test --lib **1752P/0F**；三门禁+gate health+self-test 绿；flip 语义实证（PARAMID 三轮默认定点+56 原型表+V3SIG opt-in）。F8FOR/JTDEST worktree/分支/targets 已回收；/home/ls/rugra-tmp-targets/vzext 磁盘遗留已清。终报=/dev/shm/rugra-reports/LANE_MERGEBATCH4_2026-09-26.md。

> **GEN5C 集成注记（root 2026-09-26，GEN5 车道收口，`0c353d5a..f183385c`）**：wt/gen5 `--no-ff` 合并（唯一冲突 TODO_BOARD union；golden 三件套零丢失：合并前后 git 侧 diff 空+sha256 `90950e1f…` 复核恒等；gen5 未触 src/examples，驱动以 ancestry 自动取 master 修复版）。**第五语料 sqlite3 终版全量（fresh 16 分片 172s 零重试）**：ok **1385/1385**（TIMEOUT 3→0/PANICKED 27→0，三修复分解=DIVCHAIN 11 非终止全灭+PFLUSH 27 panic 全转正+JTDEST 镜像面直接贡献 0）/defects **0**/numbering **0**/skeleton 31214（口径分解=旧 1355 基 −2036 窗口增益+新完成 30 函数 +15598）/骨架恒等 971；终版记分板=docs/alignment_audit/SQLITE3_SCOREBOARD_2026-09-26.md；GEN5 三票闭环（PATHOSLOW-BITVEC→DIVCHAIN 闭单指针/GOLDEN 落账/SHARD-EVIDENCE 实况注记）。**canon 双语料零扰动最强级亲证**：0c353d5a 干净 worktree 独立构建 vs 集成态 canon curl cmp 字节恒等（同 sha `638ffcb3…`）+httpd 与合并前档案字节恒等（255/0/0）；观察项=MB4 注记的 curl 247/"config-for 不成形"与本轮 3/3 次 246/config-for 成形相左，归 PARAMID-CURL-LOADDETERMINISM-0001 证据面。wt/gen5 worktree/分支/targets 已回收。终报=/dev/shm/rugra-reports/LANE_GEN5C_2026-09-26.md。


### 本 wave 落地清单（已并入 master efc28f4a）

| 车道 | 票 | master commit | 一句话交付 |
|---|---|---|---|
| **F5IF** | HTTPDMAIN-F5-IFELSE-RETEST-0001 | `58af028a`+`2ed48430` | ActionPreferComplement BFS 对 Goto/MultiGoto 包裹子树下降（structure_children 两臂补 `[wrapped]`，block.hh:547/573 单组件语义）；httpd canon **590→436**、main **232→78**，其余 33 函数字节恒等 |
| **F7NAME** | HTTPDMAIN-F7-NAMERECOMMEND-0001 | `09bc75fb`+`b2220069`+`f3d4f32d` | NameRecommend/DynamicRecommend/TypeRecommend 三存储+恢复链（varmap.cc:357/1507/1600/1574）+三接线（coreaction.cc:2984/476/5398）+IMPORTFLIP 数据半（59 条 generic_clib 台账默认装）；httpd canon **590→439**、main 232→196、ap_os_is_path_absolute 全函数字节恒等；CR 三修（entry-keyed first-use 地址/最终唯一名 remap/锚点勘正）+VARMAP-PARAMTYPERECOMM-0001 登记 |
| **PKGD** | UNIONRESOLVE-PKG-D-0001 | `961b332f`+`a308dbc8` | ruleaction 14 站点换 fd-aware 孪生（vn_type_read/def_facing，slot 键逐一对照 op->getSlot）；canon 双语料字节恒等（探针实证规则期 union map 无命中，map-hit 路径语义由 oracle consult 语义保证） |
| **REFSDEF** | TOOLS-REFS-DEFSTART-0001 | `9aa565ec`+`ba3f2dc8`+`84872cc2` | `// Ghidra:` 引用定义起始行门禁（check_ghidra_refs.py 解析 114 个 .cc 得 5549 defs；ADDRUNIT 修正模式）+全树 **288 处漂移全修**（白名单 86+非白名单 193）；canon A/B 字节恒等 |
| **PKGG** | UNIONRESOLVE-PKG-G-0001 | `e94c3640`+`efc28f4a` | ResolvedUnion::with_field 指针臂经 TypeFactory intern（type.cc:3867 findAdd 规范化，castStandard 恒等短路可达）+datatype.rs 死码孪生两枚删除；五面字节恒等 |
| （背景） | F1NORET/PIRAM/PIRAM2/PKA/DBLHI2/RESIDE/SWGOTO/ENVDAT/ADDRUNIT/STRLIT 等 | 见 git log `1414f6e3`..`efc28f4a` | 更早并入：httpd canon 862→590 的主链（F1 级联 ~272+SWGOTO/PIRAM2 面）、curl 镜 132→94（RESIDE F-RESIDE 清零+compare 第 4 探测去 6 幻影）等，数字见各车道节/终报 |

### 在飞待并（root 合并另计；数字=车道终报实测）

| 车道 | 分支 | 交付 | 数字 |
|---|---|---|---|
| **SQNULLT** | wt/sqnullt @ `948974df` | double_precis `set_opcode_and_inputs` 委托既有忠实件 `op_set_all_input`（funcdata_op.cc:276-278 逐槽 opUnsetInput=descend 唯一合法摘除点）；GEN4-SQ-NULLLOCALTYPE-0001 收口 | sq 面 **panic 4→2、ok/matched 808/810、skeleton 16250**（ceiling 22639 承重）；连带消除 MERGE-FORCEDINTERSECT 两 panic 的 repro；curl/httpd/vsh 六面字节恒等 |
| **SQMERGE** | wt/sqmerge @ `eaa30995`+`4cb7f45d` | S1/S2 引用勘正（merge.rs/cover.cc 定义起始行）+GEN4-SQ-MERGE-FORCEDINTERSECT-0001 **独立确认重复**（与 SQNULLT 收敛同根因，修复本体归 wt/sqnullt）；新票 GEN4-SQ-BYTELANE-STRUCT-0001（字节车道重构形态族） | src 零生产改动 |
| **PRINTCS** | wt/printcs @ 6 commits（`6ec4e705`..`4688115e`） | printc 六票：①WHILEDO 标签 DONE（curl 镜 110→101）②STRNCPY-CALLOTHER printc 侧交付（vsh 镜 15→14）③F3 双重 cast DONE ④ARRCAST run 语义 DONE（httpd 镜 265→253）⑤UNIONRESOLVE-PKG-C 29 站点快照 DONE（语料中性）⑥CODENAME 判定交付（零 src，移交 GENDRIVER-SYMTAB-DB-0001） | 基 1414f6e3：curl 镜 110→**101**、httpd 镜 265→**253**、vsh 镜 15→**14**、curl canon 269→267、httpd canon 862→860；bank 391/391 |
| **GEN5** | wt/gen5 @ `ff06b3c7`+`790faa0f` | 第五语料 libsqlite3.so.0（见下节）；记分板+PATHOSLOW P1 票+既有族证据归并 10 条 | — |
| **BRANAUDIT** | wt/branaudit @ `d4a6dac6` | 14 历史未合并分支复盘（21 个 `+` commit 逐个裁决：4 FORGOTTEN/15 LANDED-DIFFERENTLY/2 ABANDONED）+4 打捞票登记 | 零 src 改动 |

### 质量数字（efc28f4a 可声明面 + 在飞值，均溯源车道终报）

| 门禁 | 数字 | 说明 |
|---|---|---|
| curl canon（vs ghidra_curl_1204.c） | **267/0/0**（124 matched） | 多车道共证恒等值（F5IF/PKGD/PKGG/SQNULLT 各自 A/B 亲证） |
| httpd canon（vs ghidra_httpd_1204.c） | **590→436**（F5IF 后）；F7NAME 平行车道 590→439 | 两车道均基 641994a6 平行推进，master efc28f4a 已含双方——**叠加合成态未单独复测**（root 集成点） |
| curl 镜（ceiling 275 未重钉） | **94–110**（多车道基线时点） | RESIDE 终态 94（gate `--base 0` 按名配对口径 100=94+6 幻影，见票 MIRROORGATE-BASE-ORAL-0001）；PKGG/SQNULLT/SQMERGE@1f7fe30a 记 78；F5IF/F7NAME@641994a6 记 110；在飞 PRINTCS 终态 101 |
| httpd 镜（ceiling 460） | F5IF 后 **208**（main 117→67）；F7NAME 面 258 | vsh 镜（ceiling 55）**15** |
| sq 面（GEN4 第四语料，承重态） | master：ok **805**/810、skeleton 15889、numbering 7 | **在飞 SQNULLT 修复后：808/810、skeleton 16250≤22639、defects 0**；numbering=7+health 双红=在案承重（DUPDECL/PRETTYFLUSH 票） |
| 投影银行 | **391/391 MATCH** | 全部车道共证（BANK-GLOBSET-REPIN-0001 单点幽灵在账） |
| cargo test --lib | 1735–1746P / 1F | 唯一失败 `test_nonzeromask_pipeline_wiring`＝在案预存（BRANAUDIT 复核：fspec.rs:385 合成 fixture 缺 proto model，与 nzm 布线无关） |
| gcc 审计 | curl 104OK/20FAIL、httpd 15OK/14FAIL | fail 函数名集多车道逐名恒等 |

### 第五语料 sqlite3（GEN5，golden 入库待并）

- **靶** `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`（sha256 `f5a7fc23…`）：首个 stripped 共享库 profile（dynsym-only、库脸无 main、API 导出入口、导出互调图）；SQLite amalgamation 源系与四语料零重叠；sqlite3VdbeExec 3877 行=五语料最大单函数；oracle 自带压力面（327× jumptable 超限+1760× unreachable+12× typeprop 不收敛）Rugra 近 parity 复现（319/1613/10）。
- **golden**：`tests/golden/ghidra_sqlite_1204.direct-runner.c`（wt/gen5 `ff06b3c7`，1385/1385 OK 30.3s、determinism 12/12、provenance NO_ORACLE 缺项为零）+记分板 `docs/alignment_audit/GEN5_SQLITE_CORPUS_SCOREBOARD_2026-09-26.md`。
- **Rugra 首份成绩单**（mirror 臂并行分片）：ok **1355/1385**（27 PANICKED+3 TIMEOUT）、skeleton **17652**、defects **0**、numbering **0**（sq 曾破零=7，sqlite 复零）、骨架恒等 874/1355（64.4%）。
- **panic 族扩容**：27 panic 全部落 MIRROR3-PRETTYFLUSH-FAILCLOSED-0001（sq 2 站点→sqlite 27 站点，半径 ×13.5，含 VdbeExec/RunParser/mprintf 顶梁函数）——原票建议升至 P1/P2 头名。
- **新族 PATHOSLOW**：GEN5-SQLITE-PATHOSLOW-BITVEC-0001（**P1，首个性能级分歧族**）——sqlite3BitvecSet/Clear/TestNotNull 三函数 oracle 毫秒级 vs Rugra 单函数 100% CPU 燃烧至 600s 墙杀（Bitvec 位图散列子表递归三兄弟同根）。
- 残差分拣：CAST-SHAPE 3908/SWITCH-GOTO 3779/UNAFF-EXTRAOUT 2235/OPNAME-LEAK 1263/LOOPSHAPE 810 行全归并既有票；链表遍历 for 形 golden 31 处 vs Rugra 0 处（MSTRUCT-FORSPLIT 绝对缺席证据面）。

### 门禁体系四门 + CI（efc28f4a 实态）

| 门 | 入口 | 状态 |
|---|---|---|
| ① canon 差分 | `tools/compare_ghidra.py` vs `tests/golden/ghidra_{curl,httpd}_1204.c` | 双语料 defects/numbering 双零 |
| ② 镜面棘轮 | `tools/verify_mirror_gate.sh` 四面（curl/httpd/vsh/sq）+`mirror_gate_baselines.tsv` ceiling/floor 钉 | 三面 PASS+sq 承重 FAIL（在案四票）；**口径票 MIRROORGATE-BASE-ORAL-0001 在账**（--base 0 vs 0x100000，94+6=100 按名配对幻影差） |
| ③ 投影银行 | `tools/verify_projection_bank.sh` | 391/391 MATCH |
| ④ refs 定义起始行 | `tools/check_ghidra_refs.py --all --strict`（REFSDEF 升级后=定义起始行验证，非仅行存在性） | 全树 0 漂移（3772 checked/823 exempt） |

**CI（GitHub Actions `alignment-gates`）**：两 job——`locked-oracle-gates`（gate health/doc-sync/annotations/refs --strict/corpus-markers/evidence self-test 六检查）+`mirror-gate`（锁定 oracle 树 fetch→三驱动 fast-release 构建→镜面门禁+self-test）。`gh run list`：**近 8 run 全绿**；efc28f4a=run `36153938481` completed success（4m6s）、REFSDEF 工具升级笔 adf0a394=run `36153248512` success。

> 全局完成度仍未证明（函数账本分母重建未完成、在飞车道未并、镜面 sq 承重未清）；本节数字为局部差分证据，不构成模块或项目 L3 声明。

## 2026-09-25 V3FLIP 被调原型通道默认转正快照（历史，httpd 数字被 PFLIP 节取代）

**callee-siglock 通道默认转正**（Lane V3FLIP，wt/curlsig @ master 535dd91f）：httpd 驱动的
被调锁定原型通道（HEADLESS-BRIDGE-V3-SIGLOCK-0003，manifest
`tests/golden/manifests/callee_siglock_httpd_1204.json`——60 被调 = 27 全输入锁 + 26 返回锁）
自本快照起为**默认行为**（转正判据：V3SIG opt-in 轮全量验证过——**−190 skeleton 零回退/默认脸
字节恒等/mirror 恒拒/bank 391**，f9b3f1bf 终报 + 用户既定模式"实际性错误解决就默认开" +
DFLIP/SEEDFLIP 门反转形态先例）。**新默认脸 == 原 opt-in 态逐字节**（httpd 951 ==
RUGRA_V3SIG=1 态，cmp 恒等亲测）；curl 驱动未触、**577/0/0 不变**（cmp 字节恒等亲证）。
门极性 = **opt-out 三段判定**（mirror 左短路恒拒 → `RUGRA_SEEDS=0` 全局退 →
`RUGRA_V3SIG=0` 单门退 → 默认装）；任意二进制无 manifest 优雅 no-op（非致命告警 + 裸脸）。

| 门禁（fast-release 亲测，@ master 535dd91f + V3FLIP） | 数字 | 说明 |
|---|---|---|
| httpd E2E（新默认脸） | **951 / 0 / 0**（skeleton/defects/numbering，34 函数） | vs `tests/golden/ghidra_httpd_1204.c`；==原 opt-in 态（RUGRA_V3SIG=1）逐字节；双跑 cmp 恒等；per-fn 表承 V3SIG 终报（main 613→505 / ap_fini 159→90 / ap_update_vhost_from_headers 56→51 / ap_matches 6→2 / caseD_0@0x154470 4→0 canon 逐字节，其余 29 函数恒等零回退） |
| httpd 单门退 RUGRA_V3SIG=0 | **1141 / 0 / 0** | ==转正前默认脸 cmp 逐字节恒等（TYPESEED 保持默认开——单门退不牵连） |
| httpd 全局逃生门 RUGRA_SEEDS=0 | **1234 / 0 / 0** | ==转正前 SEEDS=0 脸逐字节（分层退出：TYPESEED+V3SIG 同退）；`RUGRA_SEEDS=0 RUGRA_V3SIG=1` 仍全退（层级压制亲测 cmp 恒等） |
| httpd 显式开 RUGRA_V3SIG=1 | **951 / 0 / 0** | ==新默认脸 cmp 恒等（历史 opt-in 见证形态保留） |
| httpd mirror（RUGRA_MIRROR=1，含 +V3SIG=1） | 输出 cmp 恒等基线 mirror | 恒拒（左短路 "projection purity"，压制含显式 =1） |
| httpd 无 manifest（RUGRA_V3SIG_MANIFEST→缺失路径） | **1141 / 0 / 0** ==旧默认 | 优雅 no-op（"cannot read manifest … (gate disabled)" 非致命告警）；任意二进制语义 |
| curl E2E（默认脸） | **577 / 0 / 0**（124 函数） | curl 驱动未触；cmp 字节恒等基线（亲证）；curl 侧 siglock 通道另行立项（V3SIG 终报剩余面） |
| httpd gcc 审计（新默认脸） | 14 OK / 15 FAIL | fail 函数名集与原 opt-in 态**逐名相同**（亲验；pRam 未声明族=在账 PRINTC-AFINI-UNIQUELOC-0001 等登记项，非本次引入） |
| 投影银行（B2 钉板） | **391/391 MATCH** | 冻结投影 sha256 钉 + mirror 裸径采集契约 → 不受门极性影响（亲验） |
| cargo test --lib | 1713 passed / 1 failed | 唯一失败 `test_nonzeromask_pipeline_wiring` 预存（多车道共证）；本 lane 零 src 触碰 |

**V3SIG 门 env 语义矩阵（转正后）**：

| env 形态 | 行为 |
|---|---|
| （无） | **装**（新默认；manifest 在库即装） |
| `RUGRA_V3SIG=1` | 显式开——与默认等效（历史 opt-in 见证形态保留） |
| `RUGRA_V3SIG=0` | 单门退（仅 V3SIG 关；TYPESEED 保持默认开，SEEDFLIP 语义不动） |
| `RUGRA_SEEDS=0` | **全局退**——种子族全关（httpd TYPESEED+V3SIG 同退；curl 三门同语义），拿回裸脸（逃生门；在层级上压制含 `RUGRA_V3SIG=1` 的显式开——分层退出语义亲测） |
| mirror 分量在场（RUGRA_MIRROR/RUGRA_FLOW_MIRROR/…） | 恒拒——压制一切 V3SIG 形态（含显式 =1），判定短路左侧 |

注意：`RUGRA_V3SIG=0` 在转正前语义为"任意值=开"（`is_ok()` 判定），转正后按字面意义改为单门退——
仓库内无任何脚本/测试依赖旧语义（grep 亲查，仅历史文档描述）；需要历史等价形态用 `=1`。

## 2026-09-25 CURLSYM curl 侧 SYMDB 移植快照（历史，httpd 数字被 V3FLIP 节取代）

**curl worker 的 action 侧符号库三件**（Lane CURLSYM，wt/curlsym @ master bdf2bd7f）：httpd
DFLIP 已转正的 `build_action_data_symbol_db` 形态复制到 curl 驱动——①**R-only PT_LOAD 段范围**
（loader 派生 readonly：属性区间+段内符号旗标；含 RX text 段、`.eh_frame_hdr/.eh_frame` 尾段
与头段——闭 FLAGBASE-CR-F3 的 curl 半边）②**四类符号 + 段派生 READONLY 旗标**（dynsym
OBJECT/GOT PTR_/rodata char[]/DAT_ 引用标签早已在库；OBJECT 臂补 mark_readonly 形态）③
**FunctionSymbol 层进 ACTION DB** + spacebase scope source 解析面（PREGFREE 通道形态；print
swap 降级为历史脸回退，httpd `mirror_fn || !action_db_attached` 同款门）。**默认开**；
`RUGRA_SYMDB=0` 逃生门拿回历史 fold-only 脸；mirror 分量恒压制（含显式 =1）。

**实测结论（诚实计量，"以亲测为准"）**：curl 默认脸 **767/0/0 不变**（输出与基线 **cmp 字节
恒等**；逐函数零回退=平凡成立）。根因＝派单前提已被历史车道超越——curl worker 早已通过
B3-COREACTION-CONSTANTPTR-0001(b)/MAINDIFF-GLOBAL-0001/STRCONST-SPANNONOVERLAP/
PLTSTUB-THUNKRELRO-0001 等车道携带 DB 实质（四类符号+readonly+scope source），打印侧
fn 符号层（CURL-CODEREF-SYMBOLIZE-0001）已覆盖 code-ref 渲染通道；本次补齐的 httpd 形态
三件在本语料上可证惰性（无 PTRSUB-函数地址查询点→fn 符号 action 侧通道无消费者；
`.eh_frame`/头段无反编译引用；curl 定义 OBJECT 全在 RW 段→段旗标形式 no-op）。结构性价值：
两驱动 SYMDB 形态对齐（默认开+逃生门+mirror 恒裸），后续通道扩展（如 getSubType 命中面
扩大）无需再动驱动装配。

| 门禁（fast-release 亲测，@ master bdf2bd7f + CURLSYM） | 数字 | 说明 |
|---|---|---|
| curl E2E（默认脸） | **767 / 0 / 0**（124 函数） | ==基线 cmp 字节恒等；双跑 cmp 恒等；SYMDB 层装 3 R-only 段区间 + 76 action 侧函数符号/函数（亲见 stderr 日志） |
| curl 逃生门 RUGRA_SYMDB=0 | **767 / 0 / 0** | ==旧默认脸 cmp 字节恒等（层跳过，print swap 恢复历史通道） |
| curl mirror（RUGRA_MIRROR=1） | 输出 cmp 恒等基线 mirror | 层零安装（mirror 分量短路左侧）；裸库真值通道不受影响 |
| curl gcc 审计（默认脸） | 104 OK / 20 FAIL | ==基线 fail 函数名集逐名相同（字节恒等的直接推论，亲验） |
| 投影银行（B2+HBANK2 钉板） | **391/391 MATCH** | sha 钉板 + mirror 裸径采集契约 → 不受本层影响（亲验） |
| httpd E2E（默认脸） | **1125 / 0 / 0**（34 函数） | curl 驱动单文件改动，httpd 驱动未触；@bdf2bd7f 本 lane 亲跑（优于派单快照 1243 与 SEEDFLIP 快照 1197——基线间提交所致，非本 lane 贡献） |

## 2026-09-25 SEEDFLIP 种子门默认转正快照（数字被 CURLSYM 节继承）

**种子门默认转正**（Lane SEEDFLIP，wt/seedflip @ master 898a975b）：committed-local 种子门
（curl 的 TYPESEED/DWARFSEED/STRUCTSEED 三门 + httpd 的 TYPESEED 门）自本快照起为**默认行为**
（转正判据：三门零已知错误 + 全量零回退验证——C2DWARF/C3NEXT 逐函数 0 回退 + HSEED 正交
叠加判决 + DFLIP 门反转形态先例；manifest 在库 `tests/golden/manifests/`）。**新默认脸 ==
原叠加态逐字节**（curl 767 == 三门态、httpd 1197 == TYPESEED 态，亲测 cmp 恒等）；任意二进制
**无 manifest 优雅 no-op = 裸脸**（"cannot read manifest … (seeding disabled)" 非致命告警，
stripped 兼容已由 HSEED 判决背书——无 DWARF 语料的 DWARF/STRUCT 通道天然空转）。

| 门禁（fast-release 亲测，@ master 898a975b + SEEDFLIP） | 数字 | 说明 |
|---|---|---|
| curl E2E（新默认脸） | **767 / 0 / 0**（skeleton/defects/numbering，124 函数） | vs `tests/golden/ghidra_curl_1204.c`；==原三门叠加态（RUGRA_TYPESEED=1 DWARFSEED=1 STRUCTSEED=1）逐字节；双跑 cmp 恒等 |
| httpd E2E（新默认脸） | **1197 / 0 / 0**（34 函数） | vs `tests/golden/ghidra_httpd_1204.c`；==原 TYPESEED 门控态逐字节；双跑 cmp 恒等 |
| 全局逃生门 RUGRA_SEEDS=0 | curl **1096/0/0**、httpd **1315/0/0** | ==转正前默认脸逐字节（裸种子脸，未删除）；两驱动同语义 |
| 单门退（如 RUGRA_TYPESEED=0） | curl ==双门态逐字节 | 各门独立退；旧 =1 显式形态继续等效（==新默认） |
| mirror（RUGRA_MIRROR=1，含 +显式=1） | 输出 cmp 恒等基线 mirror | mirror 分量在场 → 拒装一切种子（转正前后同契约） |
| 无 manifest（任意二进制） | ==裸脸逐字节 | 优雅 no-op（两驱动亲测，_MANIFEST 指向缺失路径） |
| curl gcc 审计（新默认脸） | 104 OK / 20 FAIL | fail 函数名集与三门叠加态**逐名相同**（真子集不回退判据的更强形态） |
| 投影银行（B2 钉板） | **71/71 MATCH** | 全部 curl 语料 + mirror 裸径采集契约 → 不受种子门转正影响（亲验） |
| cargo test --lib | 1712 passed / 1 failed | 唯一失败 `test_nonzeromask_pipeline_wiring` 预存（多车道共证） |

**种子门 env 语义矩阵（转正后，单门 X ∈ {TYPESEED, DWARFSEED, STRUCTSEED}）**：

| env 形态 | 行为 |
|---|---|
| （无） | **种子门全开**（新默认；manifest 在库即装） |
| `RUGRA_X=1` | 显式开——与默认等效（历史 opt-in 见证形态保留） |
| `RUGRA_X=0` | 单门退（仅 X 关；curl 其余门保持默认开） |
| `RUGRA_SEEDS=0` | **全局退**——一切种子门关，拿回裸脸（逃生门） |
| mirror 分量在场（RUGRA_MIRROR/RUGRA_FLOW_MIRROR/…） | 恒裸——压制一切种子形态（含显式 =1），判定短路左侧 |

注意：`RUGRA_X=0` 在转正前语义为"任意值=开"（`is_ok()` 判定），转正后按字面意义改为单门退——
仓库内无任何脚本/测试依赖旧语义（grep 亲查）；需要历史等价形态用 `=1`。

## 2026-09-25 DFLIP 默认脸快照（历史，数字被本节取代）

**SYMDB 默认转正**（Lane DFLIP，wt/dflip）：httpd 驱动的 action 侧符号 Database 建库+attach+
spacebase scope source 装配与 canon 装配 emitter（EmitPrettyPrint，Oppen 100 列）自本快照起为
**默认行为**（转正判据：功能残差清单清空 + 门控 1315 ≤ 默认 1472，CURB2→DATASYMS→PREGFREE
车道链终报，归档 /dev/shm/rugra-reports/LANE_*_2026-09-25.md）。**默认新脸 == 原门控态逐字节**
（亲测 cmp 恒等）；**逃生门 `RUGRA_SYMDB=0`** 拿回旧 fold-only 脸（1472/0/0，同样逐字节恒等，
旧脸为 opt-out 未删除）；**mirror 路径恒裸**（RUGRA_MIRROR 任何分量在场 → 不建库不 attach 不换
emitter，纯库真值通道）。

| 门禁（fast-release 亲测，@ master a600826e + DFLIP） | 数字 | 说明 |
|---|---|---|
| httpd E2E（默认脸） | **1315 / 0 / 0**（skeleton/defects/numbering，34 函数） | vs `tests/golden/ghidra_httpd_1204.c`；双跑 cmp 恒等；==原 RUGRA_SYMDB=1 门控态逐字节 |
| httpd 逃生门 RUGRA_SYMDB=0 | **1472 / 0 / 0** | ==原默认脸逐字节（fold-only + EmitNoMarkup） |
| httpd mirror（RUGRA_MIRROR=1） | 输出 cmp 恒等亲父 | 裸库真值通道不受转正影响；SYMDB=1 显式开也被 mirror 压制 |
| curl E2E（默认） | **1096 / 0 / 0**（124 函数） | vs `tests/golden/ghidra_curl_1204.c`；curl 驱动未触（curl 的 SYMDB 化另行立项） |
| httpd gcc 审计（默认脸） | 14 OK / 15 FAIL | 旧默认脸 13/16 → +1（DATASYMS readonly 旗标通道随 DB 默认开自动生效） |
| 投影银行（B2 钉板） | **71/71 MATCH** | 全部 curl 语料 + mirror 裸径采集契约 → 不受 emitter/DB 转正影响（亲验） |
| cargo test --lib | 1712 passed / 1 failed | 唯一失败 `test_nonzeromask_pipeline_wiring` 预存（多车道共证） |

**Opt-in 阶梯表（转正后）**：

| 通道 | 环境变量 | 状态 | 语料 |
|---|---|---|---|
| action 侧符号 DB + EmitPrettyPrint | `RUGRA_SYMDB` | **默认开**（`RUGRA_SYMDB=0` opt-out 拿回旧脸） | httpd |
| TYPESEED 提交局部类型种子 | `RUGRA_TYPESEED`(+`_MANIFEST`) | manifest 驱动 opt-in，维持（→ 同日 SEEDFLIP 转正默认开，见上节） | httpd/curl |
| DWARFSEED 原型种子 | `RUGRA_DWARFSEED`(+`_MANIFEST`) | manifest 驱动 opt-in，维持（→ 同日 SEEDFLIP 转正默认开，见上节） | curl |
| STRUCTSEED 结构复合种子 | `RUGRA_STRUCTSEED`(+`_MANIFEST`) | manifest 驱动 opt-in，维持（→ 同日 SEEDFLIP 转正默认开，见上节） | curl |
| mirror 裸库真值 | `RUGRA_MIRROR`/`RUGRA_FLOW_MIRROR` | 在场即恒裸（压制一切 SYMDB 形态），维持 | httpd/curl |

**2026-09-25 HSEED 阶梯补充（Lane HSEED，wt/hseed @ master 33894226 亲测）**——SYMDB 默认脸 ×
TYPESEED 的叠加态首次实测：

| 阶梯（httpd E2E canon） | env | skeleton/defects/numbering |
|---|---|---|
| 新默认脸 | （无） | **1315/0/0**（==DFLIP final 逐字节；双跑 cmp 恒等） |
| +TYPESEED | `RUGRA_TYPESEED=1` | **1197/0/0**（−118 全部由 6 个播种函数贡献：main 644→622、ap_fini_vhost_config 191→158、ap_update_vhost_from_headers 81→56、ap_parse_vhost_addrs 27→9、ap_os_is_path_absolute 23→7、ap_ht_time 17→13；逐函数零回退；gcc 审计函数名集与默认脸逐名相同 14OK/15FAIL） |
| 逃生门+TYPESEED | `RUGRA_SYMDB=0 RUGRA_TYPESEED=1` | **1360/0/0**（==BRIDGE1 历史 opt-in 见证精确复现，通道完整性再证） |
| mirror×TYPESEED | `RUGRA_MIRROR=1 RUGRA_TYPESEED=1` | 输出 cmp 恒等基线 mirror（门在 mirror 下正确拒载；新默认脸下投影纯度保持） |
| +DWARFSEED/+STRUCTSEED | — | **语料级不可用**（见下） |

**httpd 语料事实（HSEED 判决，机器可复核）**：`examples/httpd`（sha256 `805f89cd…`，与 golden
provenance 钉值一致）为 **stripped 二进制——零 `.debug_*` 节**，curl 的 C2(DWARF 名)/C4(结构体)
种子公式输入端（`.debug_info`）在 httpd 语料不存在；`tools/harvest_local_manifest.py --dwarf/--struct`
对 httpd 实测产出 **0 函数 / 0 种子 / 0 drops**（工具已加固：DWARF-less 语料显式 WARNING，不再静默
空收）。canon golden 声明层为纯合成名（`local_*`/`*Stack_*`/`xVar*`），唯二结构体类型声明
（`sigaction local_b8`@ap_fatal_signal_setup、`sigset_t local_c0`@ap_mpm_run）因 DWARF 命名类型集
为空被 --struct 规则正确丢弃（工厂名树无源，parse_c_type 无回退 bail=死条目）。解锁路径=引入带
DWARF 的 httpd 语料 + 重生成 canon golden（root 级语料决策，登记 TODO `HTTPD-CORPUS-DWARF-0001`）；
curl 侧两通道不受影响（重收割字节恒等复证）。


文本级钉板重钉清单（emitter 转正影响面亲查）：**空**——银行 71 项全部 curl 语料且采集命令带
`RUGRA_MIRROR=1`（裸径，转正不改其再生成契约）；`tests/golden/` 为 oracle 侧输出；
`tests/oracle/*.c` 为独立 oracle harness fixture，非驱动产物；tests/ 内无 rugra 侧 httpd 文本钉板。

## 2026-08-28 PTRSUB 正式输出快照

PTRSUB formal working-tree artifact 的 release curl 正式门禁共处理 124/124 个函数，76 个成功反编译，
0 empty/timeout/panic/worker/protocol failure。两次独立 stdout 与当前
`result/curl_cur.c` 三份逐字节一致：SHA-256
`f04dee502dc0131b27b41acb5ec412c0e413515aecf3f29e0e2532b304912a73`，
59995 bytes、2281 行。确定性结论只覆盖 stdout；两次 stderr byte-different（含记录
顺序差异），故不宣称 stderr 一致或全运行确定性。

锁定 Ghidra 12.0.4 golden 的正式 compare 为 skeleton=2820、defects=0、numbering=0；
`progressbarinit` 函数级 skeleton=13，字段清零已恢复为
`*(undefined4 *)&bar->field_0x1c = 0;`。相对 2026-08-27 pre-PTRSUB baseline
（stdout SHA-256 `4404af6da658cc912b84070acb6354073c4649f3b266751e1be6cb81bd1bdc8e`，
skeleton=2822、progressbarinit=15），`diff -U3` 为 12 grouped hunks/7 functions；
`diff -U0` 为 33 atomic hunks、42-/42+。只有 progressbarinit 的 golden skeleton
收敛；其余六个函数的函数级 skeleton 不变，raw 类型/命名 token 有扩散。

gcc 审计仍为 28/123 OK、95 FAIL，诊断类别由 baseline
`{other:1101, undeclared:75, syntax:73}` 变为
`{other:1113, undeclared:79, syntax:73}`。main/getparameter/glob_word/glob_set/
next_url/match_url 出现六个无类型 concrete-pointer 声明，已登记
`PTRSUB-TYPED-DECL-RESIDUAL-0001`；`glob_set` 新增 cast churn 另登记
`PTRSUB-SWITCH-CAST-RESIDUAL-0001`。fixture overall 仍为 MISMATCH，production
closure 不得据 skeleton 净减 2 升级。完整残差与依赖见 `docs/TODO_BOARD.md` 顶部。

`cargo test --lib -- --test-threads=1` 为 1618 passed / 17 failed / 5 ignored；
full suite 仍 FAIL，但 17 个失败名与 2026-08-27 归档基线完全相同，本候选新增失败=0。
首个为既有 funcdata CONTINUE 断言，其后 16 个为锁中毒后的 `PoisonError` 级联。

## 关键指标增量（2026-08-25 第二批，master `ef26eb24`，89 项集成）

> 第一批增量见下节。本批为同日后续 wave（触发词：三函数收敛 + 函数体差距分诊）。

| 维度 | 第一批末 | 本批末 | 说明 |
|---|---|---|---|
| curl 差分 skeleton | 2012（口径含 6 timeout 隐藏） | **2849**（124 函数全输出、main 恢复后真差异显形；超时/panic 清零使隐藏 diff 显形，同口径逐函数净账 21 改善−380 vs 2 回归+6） | goto 0→22、裸条件 50→0、extern DAT 69→0、->literal 175→0、in_register 裸名≈清零、空 if 体 7→6 |
| defects / numbering | 0 / 0 | **0 / 0** | numbering 由 isComplex 集成顺带归零（match_url 合法 \|\| 折叠恢复） |
| 三函数严格字节 | 0/3 | **0/3**（结构大幅收敛） | my_fwrite 守卫+fwrite+return 恢复（剩 21 行 TEMPVAR 在途）；progressbarinit `__nptr` 达成 golden 同名（13 函数获 DWARF 推荐命名）；hugehelp 六 puts 结构就绪等 CPTR |
| main 状态 | 1 TIMEOUT | **0 TIMEOUT（30s 对齐 oracle）**，894 行 diff 已分诊 6 桶（结构化 373/命名 171/全局 162/常量字符串 181/死存储 105/调用原型 52） | argc 原型 `int main(int argc,char **argv)` 逐字节=golden |
| httpd 语料 | 未测 | 首回归跑：timeout 全消、21 函数净 −53；暴露 2 P0 panic（已钉死引入 commit，修复在途）+ goto 三缺陷家族（curl 零覆盖路径） | 报告 /tmp/rugra-reports/HTTPD-GATE-c1e3733d.md |
| 复核闭环 | — | 本批 5 复核：4 APPROVE（含 mutation 实证）+1 REJECT（回走双步，C++ 复刻实证）→ 返修中 | 机制 C 运转正常 |

## 关键指标增量（2026-08-25 第一批，W-2026-08-24-TRIFUNC-GAP wave 进行中）

> 本节为 wave 期间增量快照；上节 2026-08-21 数据为 wave 前基线。任务明细见 `docs/TODO_BOARD.md` 活跃 wave 段，
> 过程证据链见 `docs/alignment_docs/WAVE_STATUS_2026-08-25*.md` 与 `docs/alignment_audit/REVIEW_*` 系列。

| 维度 | wave 前（f7b3c31） | 当前 | 说明 |
|---|---|---|---|
| curl 差分 skeleton | 2409 | **2012**（noreturn 全链后干净树测量；master 另有 merge-panic 三函数修复在途，合测后为正式值） | flow 尾调用修复 −32 → varmap 窗口交互 +28 → noreturn 全链 −393 |
| defects / numbering | 2 / 1 | **0 / 0**（同上测量） | file2string 全 MATCH；helpf 缺陷清除 |
| wave 集成数 | — | **33 项实现 + 8 项独立复核批准 + 2 项 REJECT→返修→APPROVE 闭环** | 全部带双侧 oracle fixture 或差分门禁 |
| 逐字节全 MATCH 函数 | 4/75 真实内部 | file2string.part.0 新增（143→0） | my_get_line 160→83、glob_word 144→81、helpf 137→86 持续收敛 |
| merge-panic 回归 | 0 | 3 函数（my_get_line/helpf/file2string）worker panic @merge.rs:916 | 修复中（A36）；1958/0/1 的中间测量因此无效 |
| cargo test --lib | 可用 | 可用（E0423 已修 `b55ef7f`） | 3 个预存失败在板（comment/funcdata×2） |

**wave 机制运行数据**：≥10 并发子 Agent 持续维持（峰值 14）；独立复核 13 轮（R1-R13，含 2 次 REJECT 均抓到 fixture 抓不住的真缺陷）；
三函数根因链全部进入实现/集成态（hugehelp 四环节、progressbarinit 双方案、my_fwrite exact-piece→SPLITDATATYPE）。

## 关键指标（2026-08-21，HEAD `5dc86ba`）

| 指标 | 当前 | 核实方式 |
|---|---|---|
| 单元测试 (`cargo test --lib --locked --offline`) | **1453 通过 / 2 失败 / 3 ignored** | 从 HEAD + staged datatype 补丁隔离构建；仅余 `funcdata::test_type_propagation` 与 `test_infer_params_and_return_type`，均绑定 `ACTIONTYPEINFER-VTYPE-0001` 依赖链 |
| curl E2E | **124/124 处理，75 反编译 / 1 timeout / 0 panic / 48 import stubs** | 从 HEAD + datatype 补丁隔离 release 重生成，stdout/stderr 分离 |
| 12.0.4 差分 | **skeleton 2762 / defects 0 / numbering 0 / Matched 123/124** | 对本轮重生成输出与 canonical `tests/golden/ghidra_curl_1204.c` 复核 |
| xunknown/xVar | **0**（TYPE-WIRING 双轨消除） | grep 归零 |
| FUN_ 未解析调用 | **5**（起点 64；CALLSPEC 接线） | grep |
| 逐字节一致函数 | **52/123：48 个外部桩 + 4/75 个真实内部函数** | 2026-08-24 词法函数边界原始字节复核；详见下节，旧值 50/122 已废止 |
| gcc 审计 | **107 OK / 16 FAIL**（畸形 cast 1262→0、`+ 0 -` 3→0 后余量=varmap/typedef 域） | audit_syntax |
| 确定性 | 20×全语料 + 20×compare main 字节一致 | check_determinism.py |
| oracle fixture | **registry 88 个** | `jq '.fixtures | length' tests/oracle/fixture_registry.json` |

> 全局完成度仍未证明：逐函数账本分母与旧报告尚未完成生成器重建核对，且账本仍含 `MISSING/MISMATCH/NO_ORACLE/UNTESTED`。本页的局部 MATCH 不代表模块或项目 L3。

### 2026-08-24 严格函数字节审计

对 2026-08-24 当时捕获的 `result/curl_cur.c`（SHA-256 `41aec0b7ddd8cdaddb0571f88320d811ee9530d447ace631e0d96afac61a812e`）与锁定 12.0.4 golden（SHA-256 `aca3798881fddc2ce541c3e731b88f9fcf4736451db98fdd9247366f78b6097f`）按地址配对，严格比较从函数签名首字节到词法匹配闭合 `}` 的原始字节。函数内部的空格、空行与换行全部保留；函数外 header、warning、分隔空行和 summary 不计入函数体：

- 该快照输出 123 个函数块，golden 124 个；可比较 123 个，全部按 `Ghidra地址 - 0x100000` 命中，golden 的 `main` 在该快照输出无对应成功函数体。
- 严格函数体逐字节相同为 **52/123**：48/48 个 synthetic/import bad-instruction 桩，以及 **4/75 个真实内部函数**。
- 四个真实内部函数为 `GetStr`、`main_free`、`__libc_csu_fini`、`_fini`；若以 golden 的全部内部函数为分母，则是 4/76，缺失的 `main` 记 `MISSING`。
- `tools/audit_syntax.py` 的独立函数解析器复现相同的 52 项结果。旧的 47/123、内部 0/75 是错误的分段口径：它把函数外空行/warning 混入四个内部函数，并让最后一个外部桩吞入 summary。

因此在该 2026-08-24 快照中，对“有多少真实函数体逐字节完全一致”的答案是 **4**。这仍只是当时的最终 C 文本证据，不自动把对应全算法调用闭包提升为 B2 `MATCH` 或模块 L3。

### 2026-08-20 当前 wave 落地

- 基线失败从 5 项收敛到 2 项：Comment 地址/XML content codec（`20cc7b2`）、DynamicHash op-tree 顺序（`a29f5b7`）、RuleAddUnsigned 类型前提测试（`c97ac93`）均有锁定 12.0.4 双侧 fixture。
- 高扇出地基已原子化：RangeMap common refinement 与稳定 cursor（`8ec6bee`，43/43 MATCH、独立复核 APPROVE）、TypeFactory ordered local cache（`a4a2fe9`，99-record 投影 MATCH、整体 MISMATCH）、typed UserOp metadata（`128a127`，61-record 投影 MATCH）、typed CPoolRecord（`973efbf`，16/16 覆盖投影 MATCH、整体 MISMATCH）。
- Merge 的固定名称启发式已替换为 canonical no-char 类型身份（`e15b91b`，29/29 覆盖投影 MATCH、整体 MISMATCH，窄面独立复核 APPROVE）。
- 独立复核阻止了多次虚假收口：pipeline tree、旧 varmap 查询实现和 datatype type-order R1/R2 均为 REJECT；前两项保持未提交，datatype R3 已以 `5fb36f0` 落地（78 records：72 投影 MATCH、6 TypeFactory MISMATCH，scoped Cross-Review APPROVE）。
- 剩余两项全量测试失败不能用 `None`/fallback 快修；正确依赖链为 `DATATYPE-TYPEORDER → TYPEOP-LOCALTYPE-DISPATCH → VARNODE-LOCALTYPE-RESOLUTION → ACTION-INFERTYPES-DISPATCH`。

### 终局指标（2026-08-17 收官）：warning 51/51=golden、`=` ( 畸形 1262→0、INDIRECT UnknownEffect −73%、stderr 风暴 48→0、11+ 轮机制 C（4 轮 REJECT 拦截真实分叉/误引）

### 本 session（2026-08-15~17）落地摘要

**Heritage 全链收官**（全部机制 C APPROVE，历经 1-4 轮复核）：
OWNERSHIP(0618b1c) → CALLGUARD(126b56f) → ADT-RENAME(c96f699，含确定性根修 df HashSet) → DRIVER-SWITCH(c309130，canonical 单 pass 生产切换)。

**typed-decl 链收官**：①LINKSYMBOL(0e4c6f4，local_ 106→0) → ②SCOPE-SYNC(3888124，8/8 MATCH + 补复核 APPROVE) → ③PRINTC-SYMBOL-DECL(df0da85，numbering 259→0)。

**地基与外围**：ADDRESS 空间句柄(ff3f8c8) / SPACE registry(fb9458e) / undefinedN 双 flavor(b96e6f9) / TYPE-WIRING(38af1fd，xunknown/xVar 归零) / CALLSPEC(a4dcfdf，FUN_ 64→5) / EXTERNAL-STUB(83360f48→0) / SUBCANCEL 死锁修(03ec065，7 函数解锁) / INPLACE-MUTATION(3cee3ac) / merge 持久化+门(7046998/543db17) / 五项 merge 门 / copy_shadow / FinalStructure / get_inheritable coretype 修正 / 六 fixture 重 pin 全绿。

**工具链**：12.0.4 真 headless golden(0c912e9) / 确定性双跑 CI 门禁 / audit_syntax 修复 / oracle registry 治理 / reducer schema-2 / registry ID scheme-2 迁移（STALE/REKEY/UNMAPPABLE 归零）。

### 2026-08-15 wave 落地摘要（20 提交，全部带真实 oracle 门禁或独立复核）

- **ee29a32** Cover 自锁根因修复（root-identity 快照重建，8/8 MATCH + Cross-Review APPROVE）；E2E parseconfig TIMEOUT→数秒
- **91b4774** makeFree 身份删除（Ghidra 存储迭代器语义，4/4 MATCH；单测 11→6 失败）
- **18f3ab4** `BlockGraph::findSpanningTree` RPO index 完整移植（8/8 MATCH）
- **d124392** RangeProperties marshal 重 pin（11/11 MATCH，真实 TreeDecoder 未注册名→159）
- **192e894** varmap 权威命名（共享 base 计数器 + SymbolNameTree，6/6 MATCH + Cross-Review APPROVE）
- **121c429** Subflow outvn 收敛 + 死锁 + 2 语义偏差（15/15 MATCH；my_get_token panic 消除）
- **e034f80** SLEIGH const 空间相对分支→内部 p-code 边（81 ops/33 relatives/34 blocks/49 edges MATCH）
- **763d564** totalReplace 单程 + opUnsetInput 幂等（glob_range 120s→1.1s，WARN 1454→0，E2E 24/24）
- **138dd24** post-cleanup 动作顺序对齐 coreaction.cc:5714-5738（28/29 一致 + Cross-Review APPROVE）
- **0d38e6e** ActionReturnRecovery 生命周期（mainloop ABA 消除，match_url 120s→102ms；B2 记 UNTESTED）
- **0618b1c** Heritage 显式所有权边界（3/3 MATCH + Cross-Review APPROVE；未切生产 Action）
- **2dfc91b** 函数 ID scheme 2 + 账本重生产物
- 工具链：07efbff reducer schema-2、d099737 oracle cache 三重加固

### 后继队列（均已登记 TODO_BOARD）

高扇出地基：`BLOCK-INDEX-WIRE-0001`（接线公共 RPO）/ `BLKACT-FINALSTRUCT-COUNT-0001`（删一行即 28/29→MATCH）/ `MERGE-PERSISTENT-STATE-0001` / `HERITAGE-CALLGUARD+ADT-RENAME+DRIVER-SWITCH`（生产切换链）/ `ORACLE-REGISTRY-0001`（registry 45 RG-F + 7 GH12-F 迁移，依赖已满足）/ `UPSTREAM-OUTVN-DEADWIRE-0001`（340 free-varnode WARN 归因）/ `COVER-TWOPIECE-RESIDUAL-0001` / `BASE-EXPLICIT-GAPS-0001` 等，详见看板。

### 2026-08 工具链与验证地基（摘要）

锁定 oracle 差分流水线已工业化：逐函数账本（scheme 2 稳定 ID）、内容寻址 oracle cache（环境/TOCTOU/闭包三重加固）、edit/commit/wave/nightly 四级门禁、changed-function→fixture 选择器、stage 快照首差异定位、deterministic reducer（schema-2 签名合同）、不可变 fd runner（空环境重建锁定 Ghidra + 校验和隔离 vendor 的 Rust snapshot）。详见 `docs/TODO_BOARD.md` DONE 行。

---

## 以下为历史记录（2026-06/07 口径与 2026-08-15 早间数据，部分数值已被上方覆盖）

## 关键指标（2026-07-02 重新核实）

| 指标 | 当前 | 核实方式 |
|---|---|---|
| 单元测试 (`cargo test --lib`) | **736/736 通过** | 2026-06-28 实跑 |
| curl gcc 审计 | **24/24 OK 0 FAIL** | `python tools/audit_syntax.py result/curl_cur.c` |
| httpd gcc 审计 | **29/29 OK 0 FAIL** | 同上 |
| curl 结构缺陷 | **17/24 函数有缺陷**（空 else / 寄存器泄漏 / 调用丢失） | `python tools/compare_ghidra.py --summary-only` |
| curl 变量编号问题 | **0 个**（checker 修复后；详见下方 2026-07-27 备注） | 同上 |
| goto | **0**（curl + httpd） | 实测 |
| uVar 碎片 | **0** | 实测 |

> ⚠️ **旧 while/if 计数 KPI 已废弃**（2026-07-02）。计数相同 ≠ 结构对齐（for↔while 等价变换），且检测不到真实缺陷。详见 `tools/compare_ghidra.py`（重写为结构骨架 diff + 编号连续性检查）和 AGENTS.md 铁律 11。

### 2026-07-27 numbering checker 修复（numbering 749 → 0）

`tools/compare_ghidra.py` 的 `check_numbering_continuity` 旧实现用 `VARDECL_RE` 扫整个函数体，把每一次变量**使用**当成**声明**计数（`return pcVar1;` / `if (bVar5)` / `bVar3 = ...` 全被计入）。这导致 fc6fd1f 引入类型前缀命名后，numbering 从 3 暴涨到 749——而其中**全部都是误报**：连 Ghidra 自己的正确黄金输出（`tests/golden/ghidra_curl.c`）也被同一 checker 报 995 个问题。

修复：改为只统计**声明行**（`^[ \t]+<C 类型>...<Var 名>(;|=)`，要求 Var 名前是真正的 C 类型关键字而非 `return`/语句关键字），并用**共享计数器不变量**替换被声明字母序干扰的 per-prefix 文本序单调性检查——直接抓 181538f 类 per-prefix 计数器 bug（max(num) << 声明总数）。修复后 Rugra 与 Ghidra 黄金输出 numbering 均为 0。详见 `tools/compare_ghidra.py` 注释。


### 2026-06-28 双重突破（历史记录，数值已被后续覆盖）

**突破 1：CFG 基本块划分修复**（commit 2bcfcde）
- 根因：`build_blocks_from_ops` 不在跳转目标地址处分裂块，导致回边丢失
- 修复：忠实移植 Ghidra 块划分（terminator + 跳转目标分裂点）
- 效果：循环回边检测恢复（旧计数显示 curl 循环数大幅提升，但该计数已不作为 KPI）

**突破 2：identify_internal RwLock 死锁修复**（commit e581dbc）
- 根因：identify_internal 持有 write guard 时对自环边的 point 调 read，write+read 同一 RwLock 死锁
- 修复：4 处 `e.point.read().unwrap()` → `try_read()`，失败跳过
- 影响：httpd 从"卡在第 8 个函数"变成"完成全部 29 函数"

**类型修复链**（commits 7a9b359/89bf0d4/1e67ae6/73f2581/3aa2fe7）：reconcile int-pointer 减法/除法 + 死循环修复 + 指针类型匹配 cast + discovery pass 不可达块遍历 → curl 审计 24/24。

## 已接入且实际生效的模块（curl/httpd 验证）

| 模块 | 效果 |
|---|---|
| **ActionConditionalExe** | 接入主管线，curl 无匹配模式正确返回 NO_CHANGE |
| **ActionPool (44 Rule)** | 接入 ActionSimplify 之后，Rule 真实触发（main 28 pass_changes） |
| **ActionRestructureVarnode** | 接入 DeadCode 后，构建 scope + sync_varnodes_with_symbols |
| **RuleOrPredicate** | 接入 ActionSimplify，扫描 INT_OR/INT_XOR |
| **LoopBody pipeline** | parseconfig 检测嵌套循环 (depths=1,0)；orderLoopBodies 全 pipeline 运行 |
| **TraceDAG + goto cascade** | 176 条 goto 候选边处理；selectGoto + emitLikelyEdges 集成 |
| **uVar 内联 (printc)** | emit_inline_expr COPY 内联，uVar 149→0 |
| **spacebase 解析** | resolve_rsp_offset_via_bank，helpf 栈符号 5→9 |
| **switch cast (long)** | switch 表达式 (long) cast 保证整数性 |

## 已实现但需 example 层接线才能触发的模块

| 模块 | 状态 | 未触发原因 |
|---|---|---|
| **ActionFuncLink** | ✅ apply 完整+接入管线 | curl_decompile.rs 不创建 FuncCallSpecs |
| **ActionActiveParam** | ✅ ProtoModel.fillinMap 驱动 | 同上 |
| **ActionActiveReturn** | ✅ output trial recovery | 同上 |
| **ActionDeindirect** | ✅ 常量目标解析 | 同上 |
| **ActionReturnRecovery** | ✅ RETURN 扫描 | 需 FuncProto active_output |

**修复方法**：在 curl_decompile.rs 的 lift 阶段为每个 CALL/CALLIND 创建 FuncCallSpecs。

## 已实现但未接入主管线的模块

| 模块 | 状态 | 未接入原因 |
|---|---|---|
| **ActionUnreachable** | ✅ apply 完整 + remove_unreachable_blocks | 接入导致回归 (curl 24→11) |
| **ActionDoNothing** | ✅ apply 完整 + splice_block_basic | 同上（staged structurer 依赖被删块） |
| **ActionRedundBranch** | ✅ apply 完整 (case1 splice + case2 remove_branch) | 同上 |
| **ActionDeterminedBranch** | ✅ apply 完整 | 同上 |

**修复方法**：需 staged→collapseInternal 架构迁移（G4 可选优化）。

## 本会话移植的核心 Ghidra 算法（按源文件）

### ✅ condexe.cc — 全部移植（L3）
- ConditionalExecution 18 方法（testIBlock/findInitPre/verifySameCondition/doReplacement/pullbackOp/execute 全部）
- RuleOrPredicate 7 方法（MultiPredicate 4 + getOpList/checkSingle/applyOp）
- BooleanMatch/BooleanExpressionMatch（expression.cc:57-232）
- 底层原语：replace_edges_thru / remove_from_flow_split / find_common_block / compare_order

### ✅ blockaction.cc — LoopBody + selectGoto（L2 核心完成）
- LoopBody 完整类（find_base/extend/find_exit/order_tails/label_exit_edges/label_containments/merge_identical_heads/emit_likely_edges）
- orderLoopBodies pipeline
- apply_loop_exit_marks（setExitMarks）
- TraceDAG isLoopDAGOut 集成
- FlowBlock 标记原语（mark/visit_count/loop_exit/goto_in/out）
- edge_flags 新增 F_LOOP_EXIT_EDGE/F_BACK_EDGE/F_IRREDUCIBLE_EDGE

### ✅ emulate.cc — execute() 主循环（L2 核心完成）
- execute_current_op（executeCurrentOp, emulate.cc:143-216 全 opcode dispatch）
- execute() 主循环
- get_value/set_value（值解析，非仅常量）
- execute_unary/binary/load/store

### 🔧 coreaction.cc — 8+ Action apply()（L2 进展）
- ActionDeindirect（常量目标解析 + COPY 链追踪）
- ActionFuncLink/FuncLinkOutOnly（funcLinkInput/funcLinkOutput）
- ActionActiveParam（ProtoModel.fillinMap 驱动）
- ActionActiveReturn（output trial recovery）
- ActionReturnRecovery（RETURN 扫描）
- ActionRestructureVarnode（sync_varnodes_with_symbols）
- ActionUnreachable/DoNothing/RedundBranch/DeterminedBranch（apply 完整，未接入）
- ActionPool Rule 调度器（44 Rule 接入主管线）

### 🔧 fspec.cc — 参数恢复完整闭环（L2 进展）
- ParamTrial（30+ 方法，fspec.hh:210-273）
- ParamActive（15+ 方法，fspec.hh:285-380）
- ProtoModel/ParamEntry（type_system/protomodel.rs）
- checkInputTrialUse（ProtoModel.possible_input_param 驱动）
- deriveInputMap（ProtoModel.fillin_input_map）
- buildInputFromTrials（参数恢复最终输出）
- FuncCallSpecs: active_input/active_output/proto_model 字段

### 🔧 subflow.cc — SubvariableFlow 完整三段式（L2 进展）
- doesOrSet/doesAndClear（mask 分析原语）
- doTrace（worklist 驱动入口）
- traceForward（~286行，全 opcode 模式匹配）
- traceBackward（~196行，定义 op 反向追踪）
- doReplacement（替换执行引擎）

### 🔧 constseq.cc — 核心算法（L2 进展）
- interfereBetween（干扰检测）
- checkInterference（序列收集）
- RuleStringCopy applyOp（字符串序列检测）

### 🔧 userop.cc — 专用子类（L2 进展）
- DatatypeUserOp/VolatileReadOp/VolatileWriteOp
- SegmentOp/JumpAssistOp/InternalStringOp

### 🔧 unify.cc — 约束系统（L2 进展）
- 16 个约束类型（OpCode/OpEqual/VarnodeEqual/OpOutput/OpInput 等）
- evaluate/evaluate_mut（只读/动作约束评估）

### 📋 dynamic.cc — DynamicHash（L1 从零创建）
- ToOpEdge + translate_opcode + DynamicHash
- calc_hash_vn/calc_hash_op（CRC 哈希计算）
- 5 个单元测试

### 🔧 printc.cc — uVar 消除 + scope声明（L2 进展）
- emit_inline_expr COPY 内联（uVar 149→0）
- switch (long) cast
- scope 符号保守声明
- used_scope_symbols RefCell

### 🔧 varmap.cc — spacebase 解析（L2 进展）
- resolve_rsp_offset_via_bank（只读 def 桥接）
- ActionRestructureVarnode 接入

### 🔧 funcdata.rs — 新增原语
- remove_unreachable_blocks / splice_block_basic
- sync_varnodes_with_symbols
- structure_reset

### 🔧 block.rs — 新增原语
- replace_edges_thru / half_delete_in/out_edge
- remove_block_arc / remove_edge_blocks / find_common_block
- FlowBlock: set_mark/clear_mark/visit_count/set_loop_exit/is_goto_in/out

## 剩余工作

### P0（影响输出质量/接入）
- curl_decompile.rs 为 CALL/CALLIND 创建 FuncCallSpecs → 解锁 FuncLink/ActiveParam/ActiveReturn/Deindirect
- staged→collapseInternal 迁移 → 解锁 Unreachable/DoNothing/RedundBranch 接入

### P1（L1 模块核心算法）
- dynamic.cc 完整 BFS 多层扩展
- constseq.cc transform（CALLOTHER 替换）
- subflow.cc RuleSubvarAnd/RuleSubvarSubpiece applyOp

### P2（简化版→完整版）
- ActionFuncLink opStackLoad pcode 注入
- ActionActiveParam AncestorRealistic/ancestorOpUse
- ActionReturnRecovery 完整 RETURN 分析

### P3（L1 模块从零）
- G7 BreakTable/EmulateFunction
- 其他 L1 模块

---

## 当前反编译质量(2026-07-02 19:29 实测 `result/curl_cur.c` + `result/httpd_cur.c`)

> 本节从 AGENTS.md 迁移而来(2026-07-05),避免数据在 AGENTS.md 里过期。AGENTS.md 是规则文档,不放易过期的数据。

### curl(`curl_cur.c`,1281 行)
- `while`=39 / `for`=0 / `if`=149 / `switch`=0 ✅(`0fc0806` 把过度 switch 化从 18 降到 0)
- `goto`=2 ❌(仍是 `if (1) goto ;` 空目标**语法错误**)
- `uVar_<hex>`=0 ✅(07-02 差距报告里的 215 已修)
- `StackX_*`=98 次(19 个去重,仍残留)
- `param_N`=74 次(5 个去重)
- `memcpy`=0 ❌
- 结构骨架 diff 详见 `docs/archive/dated/QUALITY_GAP_2026-07-02.md`

### httpd(`httpd_cur.c`,Jun 30,1459 行)
- `while`=58 / `for`=0 / `switch`=15 / `goto`=0
- `uVar_<hex>`=**262 次(56 个去重)❌**(质量明显比 curl 差,此前文档「0 uVar」对 httpd 错误)
- `StackX_*`=49 / `param_N`=73

### 测试
**952/952 通过**(`cargo test --lib`,2026-07-05 核实)。`cargo test` 默认含 examples,需先 `cargo build --examples`。

### 已完成的核心移植(历史日志,2026-07-02)
identifyInternal/selfIdentify, ruleBlockCat chain, ruleBlockGoto+clipExtraRoots, TraceDAG(BadEdgeScore+visit-count), structure_loops_first, Datatype get_align_size/get_sub_type/get_hole_size/type_order, varmap RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐 + printc 集成 + Stack-spacebase, Varnode flag 访问器 + get_nz_mask + lone_descend/has_no_descend + get_consume/set_consume/get_nzm/set_nzm + is_boolean_value, PcodeOp::is_calculated_bool, Funcdata op-edit API, get_booleanflip, bit helpers signbit_negative/calc_mask/leastsigbit_set/mostsigbit_set + functional_equality, expression.rs: TermOrder/AdditiveEdge/AddExpression, ActionRestructureVarnode, ~100 个 Rule struct, L1 模块骨架(14): condexe/transform/subflow/unify/constseq/opbehavior/rangeutil/userop/mem-state/float_emulate/pcodeinject/emulate/callgraph/signature, jumptable.rs L1→L2, override_rs.rs L1→L2, arch.rs L1→L2, database.rs L1→L2, findSpanningTree DFS 边分类 + F_BACK_EDGE 循环回边检测 + 回边保护, CFG 基本块划分修复(curl while 4→26).

### 2026-07-05 对齐审计(6 个并行 agent)
`docs/alignment_audit/INDEX.md` 汇总 8 个核心算法模块的 cross-review:73 MISMATCH / 68 PARTIAL / 36+ MISSING / 14 GLUE-UNJUSTIFIED / ~91 CITED-LINE-DRIFT。已修复 5 个 P0(参见 git log `10679d0`/`0c7ad89`/`8e11b3b`/`86c8e04`/`7eea43c`)。

> 注:旧 while/if 计数 KPI 已废弃(见 AGENTS.md 机制 B)。模块级算法对齐状态以 `ALIGNMENT_ROADMAP.md` 为准(其「最后核实」标注时效)。
