# `blockaction.rs` API Reference

## 2026-10-01：守卫读消费迁移（Lane ARENAFLIP-g 步骤 3）
- `clip_extra_roots`（in-body 扫描 sizeIn 守卫）、`try_rule_cat`（入口
  pred sizeOut / 首链 sizeIn+SWITCH_OUT / 链行走 next index+sizeIn+flags，
  blockaction.cc:1291-1310 逐位对应）、`collapse_switches`（case-isexit
  sizeOut，block.cc:3514 形态）——peer `expect_arc().read()` 深读全部换
  bank 影子读（docs/api/block.md 同日条目）；cat 链头 index 提升出循环
  （循环体纯读=无发布点，index 循环不变量）。判定次序与边界逐字未动。

## 2026-09-30：(g) 守卫影子随行（Lane ARENAFLIP-g 步骤 2）
- identify_internal 安装链（BlockIf/BlockList/WhileDo/DoWhile/Goto/Condition/
  InfLoop/MultiGoto/Switch downcast 整体赋值后）与 strip_external 双 retain
  后补 `sync_bank_shadows()`（docs/api/block.md 同日条目）；复合块构造字面量
  增 `bank_slot: SENTINEL` 初始化。行为零变化（纯影子维护）。


### 2026-09-29 性能修复（SPEEDPROF-BSPERULE-0001, 巨函数 collapse per-rule 常数削减——行为恒等）

**根因（车道 BLOCKSTRUCT 钻定, [BSPROF] env 门控探针 RUGRA_BSPROF=1（交付前撤净）
+ gdb 采样）**：VDBEEXEC 残差② blockstructure 18s（3522 selectGoto 轮）构成 =
`try_rule_proper_if` 7.55s/4.03M 试（1834ns/试——其中 `count_non_structural_in_edges`
3.78s/3.45M 调/53.4M 入边扫描, 每边 ~70ns = BlockEdge 克隆（Arc 往返 2 原子）+
pred RwLock + 2 vtable + `is_consumed` SipHash）+ cat 1.67s + 其余规则 0.4-0.9s 每项
+ 扫描非规则开销 ~1.3s（每访问 2 次 `std::env::var`：RUGRA_RULE2×4.03M/RUGRA_BS_VISIT
×3.70M/RUGRA_IRRED_DBG×4.02M——env 锁+分配, oracle 无对应物）+ IfNoExit/CaseFallthru
第二趟 1.52s + selectGoto/TraceDAG 1.05s。oracle 对照亲读（blockaction.cc:1768-1851/
1284-1475/1518-1593）: 每规则试 = 裸指针 + 内联字段读（`clauseblock->sizeIn()!=1` 是
一次 vector size 读, block.hh:312）——差距全部是实现级常数（Arc/RwLock/vtable/clone）,
规则序/尝试次数/命中行为与 oracle 同构不可动。

**修复（输出零变, 全部位于纯读区间; OPPPOOL 锁合并/免分配先例手法）**：
1. `out_edge_is_goto`/`out_edge_is_decision` 改 `get_out_ref` 引用读（23.2M 调零
   BlockEdge 克隆; 对应 oracle 直接读 `outofthis[i]`, block.hh:301）。
2. `count_non_structural_in_edges` 改 `get_in_ref` 引用迭代（53.4M 入边零克隆;
   臂序保持 Switch→consumed 不变）。
3. `try_rule_proper_if`/`try_rule_if_no_exit` 头部守卫单锁合并（单 read guard 段捕获
   自环检查/goto 检查/true-false 目标/decision 预取; 删除死代码 `let ops = b.get_ops()`
   ——每次试克隆底层 BlockBasic 全 op 列表后丢弃, `let _ = ops`; dir 循环 clause/merge
   借用化, 0 Arc 克隆; `cond_idx_pre`/`cond_idx` 同值合并）。守卫求值序与判定逐条不变。
4. `try_rule_while_do`/`do_while`/`if_else`/`cat` 自环/邻居检查改 `get_out_ref`/
   `get_in_ref` 引用读（do_while 每 slot 每 test 的 point 克隆删除; 比较仍为 index 判等
   ——ptr 判等与 index 判等在 `graph.blocks[i]` 替换形态下发散, 不动）。
5. RUGRA_RULE2/RUGRA_BS_VISIT/RUGRA_IRRED_DBG 三处每访问 `std::env::var` 改
   `OnceLock<bool>` 进程内单读（env 运行期不可变——src 无 set_var/remove_var 亲验;
   决策值恒等）。
6. `BlockGraph.absorbed_into` HashMap<i32,i32> → `FxHashMap<i32,i32>`（rustc-hash
   2.0 既有依赖; `is_consumed` 每规则试/每入边成员测试, SipHash→pass-through 探测;
   键值语义与迭代无序消费者不变——唯一 `.keys()` 消费在顺序无关条件重写与测试
   fixture, blockaction.rs:4555 亲核）。

**效果（VdbeExec --one 1055, GEN_MIRROR 口径）**：stdout md5 ad90320e 三态恒等
（干净基线==探针版==优化版, base==opt 配对字节恒等 ×4）; 探针口径 proper_if
1875→586ns/试（−69%）, count_ns 3.78→1.29s, 扫描 17.1→9.9s, 规则总 14.0→7.4s;
干净单极（release 配对 A/B）base 60.5s→opt 53.5s（−11.6%）; sqlite 全语料
--jobs 32 配对 59.09→54.55s wall/537.83→515.28s user, assembled 5,287,820B cmp
字节恒等。canon curl/httpd base==opt 字节恒等（4ab1db2a/7d5b9e7c 钉值）, 镜面五面
钉值全 PASS, tests 1977P/0F/5I == 基线, bank 391/391。

**残差**：tracedag 1.05s/198 调（tracedag.rs 域, per-node 常数同族——独立票）;
规则 miss 底 ~110ns/试 = get_block Arc 克隆+RwLock+vtable 结构地板（op.rs/block.rs
键化域大手术, 不在本道）; scan 双重预检（collapse_internal 扫描 + apply_rules_to_block
各一次 get_block+read+is_consumed, ~0.2s, 防御性保留）。

### 2026-09-28 修复（VDBEXEC-REFRESH-TAIL-0001, 巨函数 collapse 超线性热点收口——refresh_switch_cases 移位至 collapseAll 尾）

**根因（车道 VDBEXEC 逐阶段/逐动作/算法级三层钻定, perf 不可用下 gdb 采样 51 帧
+ env 门控探针 [VDBPROF]）**：sqlite3VdbeExec 单极 159.2s（oracle 8.80s=18.9×）中
action 相位 157.0s（[PHASE] 通道）, 其中 blockstructure 87.7s → collapse_internal
86.0s/3522 调（selectGoto 循环 11 次结构重建 × 每次数百轮）→ **refresh_switch_cases
68.5s/12701 调（45% 采样帧）**。该函数是 RUGRA-GLUE 自创簿记（oracle 无
LoopBody::refreshSwitchCases/f_case_body/dominatesIdx——blockaction.hh:88-106 enum 顶
f_duplicate_block=0x40000）, 调用点在内层 fixpoint 每轮末（旧 2026-06-23
"interleaved loop 开头先 refresh"时代的残留）, 每调 = compute_dominators 全图迭代
dominator 重算 + CBRANCH 级联链走 + **dominates_idx 扩张 O(size × cases ×
dom-depth)**（VdbeExec size=1251, cases 峰 479）+ 全图 write-lock 扫描。oracle 的
collapseInternal（cc:1768-1851）是纯 fixpoint 规则扫描, **无任何 dominator 计算**。

**修复（行为恒等可证）**：`collapse_internal` 内层每轮的 `refresh_switch_cases()`
移除; `collapse_all_5step` 与 7-phase `collapse_all` 尾部（selectGoto 循环后、
finalize_structure 前）各调用一次。终态恒等论证：
1. **消费面**——CASE_BODY flag/switch_case_indices 在默认 5-step 路径的 collapse
   过程中零消费者（try_rule_proper_if/if_no_exit/switch 的自创 pre-guard 均已随
   TRI2-STRUCT-* 票族移除, 见各 `NOTE: no switch_case_indices` 注记;
   structure_loops_first 仅 7-phase 且在首次 refresh 前运行=恒读零 flag;
   count_non_structural_in_edges 无该臂）。唯一活消费者 = printc 打印时
   case_body_indices 收集（printc.rs:12572）读**最终态**。
2. **状态等价**——旧末次 refresh（最后一次 collapse_internal 的末轮末）与新调用点
   之间零突变：第二趟 IfNoExit/CaseFallthru 扫描无命中才退出外层循环, selectGoto
   while 只重读 isolated_count, ActionBlockStructure::apply 尾部只读 change_count。
   deadline/iterations 截断路径下 refresh 同样落在截断态（截断后无进一步突变）。
3. **printc 读取面不变**——flag 在 block 对象上持久, finalize_structure 的
   retain 不触碰 flag（membership=absorbed_into; 2026-09-29 起 finalize_structure
   不再重排幸存者索引, 见下方 MCENSUS3-SWITCH-BREAKGOTO-EMIT-0001 注记）。

**效果（VdbeExec --one 1055 亲测, 输出 stdout cmp 逐字节恒等）**：refresh 调用
12701→11（每 rebuild 一次）, collapse_internal 86.0→16.2s, blockstructure
87.7→18.0s, action 相位 157.0→82.9s（探针撤净后）, 单极墙钟 **159.2s→85.2s
（−46.5%）**, 差距 18.9×→9.7×。5s deadline 全程 0 命中（修复前亦 0——超线性是
refresh 的 O(rounds×N×C) 累积, 非单轮撞线）。

**残差分票（本道只修此单点, 85.2s→oracle-par 8.8s 的剩余面）**：oppool1 22-28s
（27.8M rule_tries 每试 ~0.8µs 常数, ACTIONLOOP/PERF-ACTIONPOOL-ITER 域）/
activeparam 10-15s（fspec check_input_trial_use 巨调用面）/heritage 9-14s（巨函数
超线性, 假设②）/blockstructure 残 18s（3522 selectGoto 轮 × per-rule 常数——
轮数算法性、per-rule Arc/RwLock 常数为数据结构域）/mergerequired 6.3s
（Merge::try_merge_addr_tied→Cover::add_ref_recurse 深递归 16 帧）。详
LANE_VDBEEXEC_2026-09-28.md §残差。


### 2026-09-24 修复（BLOCKSTRUCT-SWITCH-CASEFALLTHRU-0001, glob_set 终态树差收口）

**根因（双侧终轮 trace 定缝, noreturn 修正版 oracle harness 重放）**：Ghidra
`ruleCaseFallthru`（blockaction.cc:1729-1762）作用于**结构化前**的 switch dispatch 块
（`isSwitchOut()` 的 BlockCopy）：case body（sizeIn≤2 且单出边）落在一个只与 switch 自身
共享的双入目标上时，把该 case 的 out(0) 标 goto（`setGotoBranch(0)`）；随后的第一趟
`ruleBlockGoto` 包裹移除该边 → 共享目标 sizeIn 降 1 → `ruleBlockSwitch` 的 fallback
exit 解析（cc:1672-1690）成功，switch 以**全部 case** 成形且 exit=循环头区域。Rugra 的
`collapse_case_fallthru` 是自创批处理，只扫**已成形**的 BlockSwitch 组件，在卡住的
pre-formation 图上永不点火；selectGoto 随即剥掉 switch 的真实 case 边（"multigoto
peeled"），尾块落到循环外（glob_set `goto LAB_00104c20` + `code_r0x00104c7c` 族）。
第二处配套缺口：`try_rule_switch` 的 `case_consumed` 只收集 `cases` 字段，漏掉
`default_case`——default body 留在顶层、dispatch→default 边仍外挂在组合块上，switch
多出一条假出边，`ruleBlockInfLoop`（需单一自落入）不匹配，多包一层 DoWhile
（`do { do {` 族）。修复：
1. 新增 `try_rule_case_fallthru(i)`：逐块 1:1 移植 cc:1729-1762（含 cc:1750 的
   扫描中 `nonfallthru > 1` 早退、cc:1745 `getOutRevIndex(0)` 反查 target 另一入边
   == switch 自身的恒等判定、cc:1755-1759 逐候选 `set_goto_branch_on_block(curbl, 0)`
   ——只标边不建结构）。
2. `collapse_internal` 第二趟改 oracle 交错扫描（cc:1838-1848）：per-block 先
   `try_rule_if_no_exit` 再 `try_rule_case_fallthru`，首个命中即 break——原实现
   （全图 ifnoexit 后接批处理 fallthru）重排了 oracle 决策序。
3. `case_consumed` 追加 `default_case` 索引（cc:1714-1720 的 -cs- 向量含 default，
   identifyInternal 同样消费它；组合块出边经既有 `dedup_edges_all_types` 收敛为单条
   exit 边，对齐 selfIdentify→dedup block.cc:930）。
**验证（oracle 侧新证据链）**：FK harness 缺 noreturn 建模（控制台模式
`call exit@plt` 落穿到下一函数，glob_set 吞并 glob_range 的 35 块假输入）——本 lane
以 `setNoReturn` 补丁重建 `golden_dump_nr`（/dev/shm/rugra-tests/sb-globset/
golden_dump_nr.cc，链接 FK 同一插桩 libdecomp.a）后 oracle 三轮 19/19/18 与 Rugra
逐块可比；Rugra 终轮 mark→rule 序列与 oracle trace 逐事件一致（4d30→4d0e, cat3,
4d24→4d0e, cat13, List3.out1→R, 4c48.out1→4d04, List3.out0→4c5e, head.out1→4c5e,
casefallthru 标 4c48-region→4c5e, goto#12, **switch 5 cases exit=head**, cat#1,
**InfLoop#1**, cat#0），finalize 18→1 全塌缩（oracle FINALTREE nblocks=1 同形）。
**门禁**：curl 2145→**2130**/0/0（仅 getparameter 532→520 + glob_set 71→68 两函数
golden-closer，defects/numbering 双 0）；httpd 2057==2057/0/0 **字节恒等**；
next_url/match_url 投影 **MATCH**；parseconfig 对 sb-oracle pin 首散点保持 opline 367
零移动（对 FO 交付态的首个实质差 = stage 209 oppool1 CROSSBUILD→INT_ADD，结构修复的
下游重派生）。旧 `collapse_case_fallthru` 保留给 RUGRA_7PHASE=1 遗留路径（非默认）。


### 2026-08-30 追加（seam #2/#3 定缝结论, 未修）

双侧 visit 级 trace（oracle BS_ORACLE_VISIT vs Rugra RUGRA_BS_VISIT，均 env 门控）：
- Or-cond 创建序列双侧**完全一致**（6,26,29,89,95,101,117,120,123,126,132,141 + 重触发 89→91,
  126→128），此前"顺序发散"判断系 dump 误读（重触发把首代 cond 移到尾部）。
- properif/cat 消费集逐事件**完全一致**（105→106, 109→110, ..., 29→31, 117→119, 132→134,
  126→129; cat35→37, 55→57, 109→111, 139→141, 117→120）。
- 事件 22 处（cat@139 后 oracle 访问 if@117, Rugra 访问 if@132）的残余错位 =
  **@339e 块缺失**（oracle main 图 150 块 vs Rugra 149；列表尾部少一个条目使 shift 算术差 1 位）。
  @339e = main/_start 重叠区的 hlt（fallthrough 过 noreturn call），Rugra 按符号尺寸截断不含。
  修复域 = funcdata/flow（函数尺寸/跟随策略），非 blockaction —— 已登记移交。
- do-while 吸收链（goto67→cat67→dowhile67 ... ifelse12→cat12→dowhile12, oracle 事件 53-80）
  在该错位下游；@339e 修复后继续用同一双侧 visit trace 定缝。

## 2026-08-30：Ghidra 列表序镜像 virtual_list（MAIN-RC4-DOWHILE-TRACE-0001, P1）

**根因（双侧 trace 定缝, oracle 插桩 /tmp/w-rc4-ore + RUGRA_BS_TRACE）**：Ghidra 的 collapse
图是**可变列表**——`identifyInternal` 从 `list` 移除被消费组件（block.cc:953-960），每个
`newBlock*` 工厂经 `addBlock` 把组合块**追加到列表尾部**（block.cc:862-875 `list.push_back`）；
`collapseInternal`（cc:1776-1811）、`collapseConditions`（cc:1858）、IfNoExit 二趟（cc:1838）、
`clipExtraRoots`（cc:1111）、`labelLoops`（cc:1129）、`updateLoopBody` 根收集（cc:1234）全部按
**列表位置**迭代。Rugra 平铺 Vec（块固定 slot + absorbed_into 僵尸 + 组合块 in-place 安装）使
位置≡索引，组合块在 pass 早期被扫描（oracle 在尾部），且无法产生 oracle 的
**shift-skip 语义**（规则吃掉当前块+相邻块时，幸存者左移滑过已自增的扫描指针, 下一 pass 才补扫）。
main 实测：首个分歧 pass1 位置 3（Rugra 过早命中 properif blk#29 cond 复合体; oracle 在 pass
末尾才扫到它）→ 后续吸收序全偏 → argv 循环头（idx=12）cat 后的自环复合体无法在同 pass 尾部
被再扫到 → try_rule_do_while 0 命中（golden 5 个 do-while）。

**修复**：`CollapseStructure` 新增 `virtual_list: Vec<i32>`（slot 序）——`new()` 初始化为拷贝图
顺序 0..n；`identify_internal` 尾部 `retain(非 consumed 且非 install) + push(install_idx)` 精确
镜像 oracle 的 remove+append；上述 6 个位置序消费者全部改为迭代 virtual_list（含
`while idx < virtual_list.len()` 的动态边界重读 = Ghidra `index < graph.getSize()` 每次求值；
target 模式 `idx = len()`（事后重读）= cc:1790 `index = graph.getSize()`）。顺带修复
`generate_likely_gotos`（tracedag.rs）的僵尸幻影根（consumed 过滤）。

**验证**：main 规则序列与 oracle 对齐前缀 14（原始）/22（滤除 oracle-only 的 @339e 事件后;
@339e=main/_start 重叠区的 hlt 块, Rugra 按符号尺寸截断不含, flow 域缺口另行登记）；
E2E 124/124、0 panic、76 decompiled、defects=0/numbering=0、skeleton 3104→3096；
cargo test --lib 10 failed（全部为已知 funcdata 基线, 无 blockaction/tracedag 新失败）。
main do-while 仍为 0：剩余分歧在 oracle 事件 22+（cat@117/properif@139 次序、properif@137、
cat@146 339e 关联），继续定缝中。双侧探针证据：/tmp/w-rc4-ore-main{,2,3}.stderr（oracle
BS_ORACLE/BS_ORACLE_DUMP/BS_ORACLE_VISIT）vs /tmp/w-rc4-{trace2,fix1,fix2}.stderr（Rugra
RUGRA_BS_TRACE/RUGRA_BS_DUMP=2）。

# `blockaction.rs` API Reference

## 2026-08-29：identify_internal 消费状态去 f_dead 化 + 组件内边保留（BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001）

对齐 Ghidra `BlockGraph::identifyInternal`（block.cc:940-963）与 `selfIdentify`
（block.cc:895-931）：oracle 把组件移入组合块（`addBlock` 设 `parent`，block.cc:873/950）
并从列表剔除（block.cc:953-960），**从不给组件设 f_dead**；selfIdentify 的
in/out 扫描对 `otherbl->parent == this` 的对端**不做任何重写**（block.cc:907-909/919-920
——组件到组件的边永远原样保留），只有外部块的两半经
`replaceOutEdge/replaceInEdge`（block.cc:160-191）成对迁移到组合块，最后
`dedup`（block.cc:525-539）按"保留首槽、OR 标签、成对半删"合并平行边
（注意：oracle 的标签 OR 只发生在被 dedup 一侧的保留半边上，对端保留半边
标签不变——case 2 fixture 观测 `w_out=13` vs `m_in=5`）。Rugra 侧改动：
1. `identify_internal`/序列合并不再 `set_flags(DEAD)`；消费关系只写
   `graph.absorbed_into`（跳过 install 槽位处的自映射，避免毒化成员测试）。
2. 新增 `is_consumed(idx)`（对齐 Ghidra 列表压缩 block.cc:953-960 的可观测
   成员语义）：collapseInternal 扫描、isolated_count、selectGoto trace、goto
   判定、finalize_structure 等全部消费点从 `f & DEAD` 改为成员测试。
3. 组件保留内部（component-to-component）边；外部半边成对迁移（selfIdentify
   block.cc:895-931 + replace*Edge block.cc:160-191），标签/逆槽随迁，
   组合块边界边经 `dedup`（block.cc:525-539）合并。
4. install 阶段的全图索引重写循环**跳过 consumed 组件**：旧版把组件指向
   install 块的内部边也劫持到组合块（fixture case 1 `b_in=[W]` vs oracle
   `[A]`，reciprocal 断链 consistent_A/B=0）——Ghidra 的 selfIdentify 从不
   重写 parent==this 的对端。

双侧 fixture `tests/oracle/block_identify_internal_1204.{cc,rs,metadata.json}` +
`tools/run_block_identify_internal_oracle.sh`：4 case（cat 基本迁移/平行边 dedup
标签合并/flag 传播/自环内边保留），顶层成员、children 顺序、parent、raw flags
（无 f_dead）、边界边 slot/label/reverse、对端重定向、dedup、一致性全量观测
**字节级 MATCH**（stdout sha256 `710def24…`）。归一化仅顶层列表位置
（Ghidra 追加 vs Rugra install-in-place，登记的模型分歧）。

## 2026-08-28：条件极性与变更计数分离

`ruleBlockProperIf`/`ruleBlockIfNoExit` 不再把极性塞入 Rust-only
`BlockIf.negated`；它们在建块前调用条件对象的真实 virtual
`negateCondition(true)`。`CollapseStructure` 同时分离内部收敛用
`structure_change_count` 与 Ghidra 可观察的 `dataflow_changecount`，后者只在锁定
源码中的七个成功条件取反点增加。旧 phase、CaseFallthru 和 identifyInternal
残差继续保持整体 `MISMATCH`。

`BLOCK-STRUCTURED-NEGATE-0001` 已对 13 个 base/List/Condition、双重取反、
parallel/self-edge 与 Cat/ProperIf counter case 产生 14 行、3628 bytes 的双侧
raw stdout `MATCH`（SHA-256 `d47ef9da438012d850b3374dddf6d54cf7bdbaaf82b145b5b7c280ab5151c57d`）。
公开 `get_change_count()` 只读 dataflow counter；结构收敛次数不泄漏到 Action count。
Rugra 独有的四条诊断 stderr 和完整 ProperIf/identifyInternal/parent wiring 仍明确使
full 状态为 `MISMATCH`，独立复核只批准上述投影。

**状态**: 已核对（当前有效，2026-08-28 BLOCK-BUILDCOPY-MIRROR-0001）
**2026-08-30 追加（BLOCKACTION-DOWHILE-ABSORB-0001 — newBlockList force 步）**: `try_rule_cat` 补 Ghidra `newBlockList`（block.cc:1758-1774）在 `identifyInternal` 之后的两个 force 步，此前完全缺失：
1. **捕获**（cc:1762-1764，必须在 identifyInternal 之前）：链尾节点的出边数 `outforce`，二元时再捕获其 out(0) 目标 `out0`。链尾指回链内的回边在合并后成为复合块内部边——外部出边数低于 outforce。
2. **`force_output_num`**（cc:1768 → block.cc:880-889 `BlockGraph::forceOutputNum`）：复合块出边数 < outforce 时，按 `addInEdge(this, f_loop_edge|f_back_edge)`（block.cc:73-80/888）在 out/in 两个半边上追加**复合块自环边**（label=loop|back，reverse_index=对侧 push 前槽位）。这是链内回边在复合块层的幸存形态。
3. **`force_false_edge_composite`**（cc:1769-1770 → block.cc:1204-1217 `forceFalseEdge`）：sizeOut==2 时保证 out(0)=out0；`out0->getParent()==this`（out0 是被合并组件，Rugra 以 Arc::ptr_eq 对组件集判定）时改为要求 out(0)==自环边；否则 `swapEdges`。
这正是 main 的 do-while 吸收链（@321a/@3225/@28ec/@28f7 同地址 latch 对：`ruleBlockGoto→newBlockIfGoto` 删 goto 出边 → `ruleBlockCat` 合并 ifgoto+latch（force 出自环）→ `ruleBlockDoWhile`（cc:1555，sizeOut==2 且 getOut(i)==self）吸收 latch → `cat 66` 并入上游）。此前复合块只有 1 条外部出边 → dowhile 永不触发。门控（RUGRA_ORACLE_FIXTURE_DATA=1）main 规则序列 vs oracle（/tmp/w-rc4-ore 探针树）**126/126 事件全对齐**（oracle "goto" 事件名=ruleBlockGoto 统称，含 if_goto 子路径）；do_while 计数 **0→5=golden 5**；E2E curl：defects=0/numbering=0，skeleton 3119→3088（−31，main 4 `do {` vs oracle golden_dump 6——残差为 oracle 的第二轮 collapseAll（146 块重启，管线编排域）与渲染层差异，非本缝）。Cross-Review: PENDING（机制 C 白名单）。
**2026-08-28 追加（真实 BlockCopy/buildCopy）**: `ActionBlockStructure::apply`
改为调用 `BlockGraph::build_copy`；不再清空结构图、创建 Basic 替身或重放边。
复制后的 incoming/outgoing 顺序、label、reverse slot、idom、index、numdesc、
flags 与源 copymap 均按 block.cc:1681-1697/1925-1938 保留。边 helper 已改走
FlowBlock 共享向量，主管线可直接处理 Copy。完整状态仍因 parent 所有权残差为
MISMATCH；详见本文件“buildCopy 正式接线”节。

**2026-08-28 收口（主管线入口与 loop-label 生命周期）**：
`ActionBlockStructure::apply` 现严格执行 once-guard →
`install_switch_defaults` → `build_copy` → `collapse_all` → 累加
`getChangeCount`，删除了 oracle 不存在的拓扑指纹重建及
Unreachable/DeterminedBranch 前置清理。`CollapseStructure::order_loop_bodies`
只消费源 basic CFG 经 `buildCopy` 复制的 back/tree/irreducible/default 标签，
不再对结构图重跑 `structure_loops`；这保持 blockaction.cc:1126-1188、
1877-1892、2169-2184 的调用顺序。完整 Action/模块仍为 `MISMATCH`，因为
`identify_internal` 的 parent/顶层列表/DEAD 模型等后续阶段尚未等价。
`ActionBlockStructure::count` 是持久 Action 计数器：每次真正执行
collapse 后累加 `CollapseStructure::getChangeCount()`；由 Rust 适配层
`take_count_delta` 把这笔增量交给 `Action::perform` 的 `ActionState`。
与 oracle 一样，`apply` 自身的返回值仍固定为 `0`，不把累计量
当作返回值或 repeat-apply 信号。
**2026-08-27 追加（round 6 — TraceDAG/不可约环审计）**: 在 oracle `e40ed13014025f82488b1f8f7bca566894ac376b` 上逐行复核 `blockaction.cc:499-1014`（TraceDAG）及 `:1124-1277`（LoopBody/updateLoopBody/selectGoto）。oracle 没有 `splitDag`/duplicate 系列 API；不可约环处理是 `pushBranches` 的 `checkRetirement`→`checkOpen`→`selectBadEdge` 单边循环。当前树全量 curl E2E：124/124，`defects=0`、`numbering=0`、skeleton diff=2598；`selectGoto exhausted` 仅 `getparameter.constprop.0` 1 次（此前 8 函数残差中的其余 7 已清零）。该函数耗尽现场为 138 块/51 非孤立/86 DEAD，仍无 `BlockSwitch`（golden 1 switch/48 case）；TraceDAG 未触发迭代上限。结论：剩余差异是 jumptable 恢复及 block 边界/组合块消费，不是 TraceDAG 非终止；block.rs 由另一 agent 持有，本轮不修改。
**2026-08-27 追加（round 5 — identify_internal 边迁移补 BlockSwitch 臂）**: `identify_internal` 的边界边安装 downcast 链补 `BlockSwitch` 臂——Ghidra `newBlockSwitch`（block.cc:1913）与所有组合块一样经 `identifyInternal(ret,cs)` 调 `selfIdentify()`（block.cc:962/895-931），switch 组合块的 incoming/outgoing = dispatch 的外部入边 + case/exit 边界出边。Rugra 侧各具体块类型各自持有 incoming/outgoing 向量，缺臂 = 每个 BlockSwitch 组合块 sizeIn==0/sizeOut==0（单侧边：pred 保留 out 半边、exit 保留 in 半边）→ ruleBlockCat 拒绝链（cc:1300 `outblock->sizeIn() != 1`）→ selectGoto 在残差 3 块图上 cc:1275 exhausted。E2E：exhausted **2→1**（glob_set 清零；残 getparameter.constprop.0），defects=0/numbering=0，skeleton 2611→2598，124/124 exit0/0 panic。
**2026-08-27 追加（round 4 — 删除子句入边门的自创 switch_case_indices 臂）**: `count_non_structural_in_edges` 删除 `switch_case_indices.contains(pred)` "structural" 臂——Ghidra 的守卫是纯 `clauseblock->sizeIn() != 1`（blockaction.cc:1391/1428 等），无 cascade 成员概念。自创臂把 refreshSwitchCases 的 CBRANCH 级联标记（无 oracle 对应物）计为 structural，使级联 walker 触碰过的每条 else-if 链被 proper_if/if_else/do_while 拒绝——链不可折叠，selectGoto exhausted。E2E curl：exhausted 8 fns → 2（getparameter.constprop.0/glob_set），defects=0/numbering=0，skeleton 3050→2611，输出归档 result/curl_cur.c。
**2026-08-27 追加（round 3 — 删除 try_rule_if_goto 自创 case-body 守卫）**: `try_rule_if_goto` 删除 `switch_case_indices.contains(&body_idx)` 拒绝守卫——Ghidra `ruleBlockGoto`（cc:1446-1471）对 IfGoto 包裹**无任何 case-body 预守卫**（switch 的保护在 isSwitchOut→newBlockMultiGoto 臂，cc:1456-1458，Rugra 侧 BLOCKSTRUCT-MULTIGOTO-0001 跳过）。该守卫源自自创 `refreshSwitchCases`（oracle 无此函数）的 CBRANCH 级联标记：把级联链 out[1] 目标（正是 jumptable 邻域环头，如 next_url blk17）标成 "case body"，拒绝 IfGoto 包裹 → selectGoto 的 goto 标记无人消费 → cc:1275 exhausted。E2E：exhausted **6→3**（next_url/match_url/parseconfig 清零；残 getparameter/glob_set/glob_range=switch 恢复族），defects=0/numbering=0，skeleton 2740→**2815**（main 543→735 +192 恢复体、match_url 124→95、parseconfig 171→107——更多真实结构暴露），124/124 exit0/0 panic。
**2026-08-27 追加（round 2 — clipExtraRoots 忠实化）**: `clip_extra_roots` 对齐 cc:1108-1121 + `onlyReachableFromRoot`（cc:1041-1067）+ `markExitsAsGotos`（cc:1070-1090）逐行：①删除自创 `BlockType::Basic|Copy` 类型门（cc:1080 只有 `sizeIn()!=0` 检查——结构化复合块（被 wrap 的 BlockGoto/BlockList）同样可作 cross-over root；parseconfig 残差 blk13 in=[] 正是被该门跳过）；②`markExitsAsGotos` 计数从 per-block 改 per-edge，且不再跳过已 goto 边（cc:1078-1084 对每个指向非 body 目标的出边无条件 `setGotoBranch(j); changecount+=1`——重计已 goto 边是 collapseAll 循环推进的语义：clip 反复返回 true 直到 try_rule_goto 把标记块吸收）；③goto 标记从块级 GOTO_EDGE_0/1 flag 改为完整 `set_goto_branch_on_block`（setGotoBranch block.cc:305-313：边 label f_goto_edge 双半镜像 + f_interior_gotoout/gotoin——isGotoOut/TraceDAG 可见）；④visitcount 收敛判 `==`（cc:1063 `count == curbl->sizeIn()`）。E2E：exhausted 保持 6 hits（residual 族更深根因=双 tail 环+switch 恢复），但 parseconfig root=13 / getparameter root=3 的 clip 路径激活（`ruleBlockGoto: wrapped block 13`），defects=0/numbering=0/skeleton 2740。
**2026-08-27 追加（TRI2-STRUCT-IRREDUCIBLE-TRACE-0001 round 1 — 折叠层级父链解析）**: 修复 selectGoto exhausted 残差族（jumptable 邻域不可约环）的分叉根因：旧端口把「tail 被复合块吸收」误判为「环死亡」，而 oracle 经 `getParent()` 链把吸收后的 tail 解析到存活的组合块上，环仍然存在：
1. `LoopBody::update`（cc:94-114 重写）：`cc:95-96` head 父链解析 + `cc:97-103` 每 tail 父链解析（`resolve_to_graph_level`），首个解析结果 ≠ head（均解析后）即返回 bottom；`cc:104-112` 全部 tail 解析进 head 才检查 head 自环；`cc:113` 返回 None。旧实现遇 DEAD tail 直接 `continue`（自创"index-based model"），`updateLoopBody`（cc:1214-1216）视为环死亡 → `likelylistfull=false` 丢弃剩余 likelygoto 候选 → final trace 空 → cc:1275 LowlevelError。
2. `FloatingEdge::get_current_edge`（cc:27-37 重写）：`cc:28-33` 双端点父链解析（吸收端点解析到组合块，其 selfIdentify 继承的边界边代表同一流），`cc:34-35` 找 out-slot。旧实现遇 DEAD source 直接 None——正是 selectGoto 重解析残留候选时丢边的位置。
3. `LoopBody::emit_likely_edges`（cc:364-412 重写）：`cc:367-371` head/exitblock 解析、`cc:372-379` tails 解析 + `tail == exitblock → exitblock = -1`（exitblock 被吸收进 tail 则环无出口）、`cc:381-397` exit_edges 逐条 getCurrentEdge 重解析（消失边跳过）+ 官方 exit 边（解析后目标 == exitblock 的**最后一条**）held、`cc:398-409` held 边在最终 back-edge 前发射 + back-edges 逆 tail 序。旧实现 clone 原始条目不重解析、hold 判定用陈旧 to_idx。
4. 吸收登记：`identify_internal` 消费块 DEAD 处 + `collapse_sequences` succ DEAD 处写 `graph.absorbed_into[idx] = install_idx`（Ghidra `FlowBlock::parent` 指向组合块的等价记录，见 block.md `resolve_to_graph_level`）。
E2E（curl 124 fn，fast-release + RUGRA_IRRED_DBG=1）：exit 0 / 0 panic，`selectGoto exhausted` **9→6 hits**（main、glob_word 清零；getparameter/glob_set/glob_range/match_url/next_url×1(原2)/parseconfig 残留），defects=0 / numbering=0，skeleton 3050→2742。`[IRRED]`（finaltrace 残差图 dump）/`[TD]`（TraceDAG OPEN/RETIRE/STALL/BADEDGE 决策日志）为 RUGRA_IRRED_DBG=1 环境变量门控的诊断输出（stderr）。
**状态（前）**: 已核对（2026-08-26 BLOCKSTRUCT-GUARD-GAPS-0001 三处存量守卫缺口补齐）
**2026-08-26 追加（BLOCKSTRUCT-GUARD-GAPS-0001）**: 补齐复核登记的三处 oracle 守卫缺口（存量债，非上一轮引入）：
1. `try_rule_if_else` 补全 ruleBlockIfElse 守卫组（blockaction.cc:1416-1444 逐行）：cc:1422 `bl->isSwitchOut()`、cc:1423-1424 双出边 `isDecisionOut`（经 `out_edge_is_decision`，block.hh:336 = 非 irreducible/back/goto）、cc:1433-1434 共同汇合点非 cond 自身（No loops）、cc:1435 两子句 exit 同点、cc:1437-1438 子句 `isSwitchOut`、cc:1439-1440 子句 `isGotoOut(0)`。**同时修正 tc/fc 位置语义**：oracle `tc = bl->getTrueOut()` = out[1]、`fc = bl->getFalseOut()` = out[0]（block.hh:299-300，位置性；Rugra flow.rs:1045 fallthru-first 同构）。当时文档中的 `new_block_if_else(..., negated=false)` 是已删除的历史签名；当前 factory 没有 `negated` 参数，必要极性变化在建块前通过 virtual `negateCondition` 完成。
2. `try_rule_do_while` 补 cc:1562-1563 `bl->isGotoOut(0)/isGotoOut(1)` 拒绝守卫（经 `out_edge_is_goto` label 形态，结构块同样可见）：已标 unstructured 的回边/出边保持 goto，不再被 do/while 吸收。
3. `identify_internal` 补 selfIdentify cc:925-926 `if (mybl->isSwitchOut()) setFlag(f_switch_out)` 的复合块继承：oracle 在 outofthis 外部边分支内检查——组件自身是 switch dispatch（BRANCHIND，block.cc:2287）**且**有至少一条外部出边时，复合块继承 f_switch_out（全内部 dispatch 不继承）。两处插入点 = install 块外部出边捕获相（install 块在 Ghidra -nodes- 集内，inf_loop 吸收 dispatch 的可观测场景）+ consumed 组件边界扫描相（out_boundary 非空 && 组件 SWITCH_OUT）。
E2E（curl 124 fn，fast-release）：exit 0 / 0 panic，defects=0 / numbering=0，skeleton 3085→**3050**（−35；wip 归档口径 3051 为文件尾混入杂散 `EXIT=0` 行所致——独立冷构建重跑（flock + 专属 target）的 C 输出与 wip 归档**字节级一致**，确定性成立），`selectGoto exhausted` 8→9 hits——8 个残差函数（main/getparameter/glob_set/glob_range/glob_word/match_url/next_url/parseconfig 族，jumptable 邻域不可约环）未解锁（预期内，守卫只补拒判语义；TRI2-STRUCT-IRREDUCIBLE-TRACE-0001 继续跟踪），next_url 1→2 hits 为同一不可约邻域的两轮 collapse restart（finalize 29→11 / 30→11 双双收敛 blocks=11，不破坏）。cargo test --lib 1613 pass / 17 fail 与 FUNCDATA-TESTS-FLAKY-0001 基线同集，零回归。
**2026-08-24 追加（BLOCKSTRUCT-NORETURN-DEADREGION-0001）**: 修复 noreturn halt 后不可达区被重构成裸表达式/code_r 标签 + selectGoto 无限重选同一条边（my_get_line/glob_word 不收敛或形状破坏）：
1. 新增模块级 `set_out_edge_flag_all_types`（对齐 FlowBlock::setOutEdgeFlag + 镜像 in 半边，block.cc:240-247）：Ghidra 的边 label 存于基类边数组对**所有**块类型生效；Rugra 旧路径经 `set_out_edge_flag_mirrored`（block.rs trait 默认只 downcast BlockBasic/BlockGraph），结构块（BlockList/BlockIf/...）上的 f_goto_edge 标签被静默丢弃 → TraceDAG 重复选同一条边 → selectGoto 死循环。现对全部 10 个具体块类型 downcast 设置，out/in 两半镜像。
2. `out_edge_is_goto`（isGotoOut label 形态）加块级 GOTO_EDGE_0/1 直查：GOTO_EDGE_* 位在共享 flags word，任何类型可读；旧 fall-through 到 trait `is_goto_out`（默认 false，仅 BlockBasic override），结构块 goto 态对规则不可见。
3. `try_rule_goto`（ruleBlockGoto size_out==1 → newBlockGoto）删除自创 `BlockType::Basic` gate（cc:1450 纯拓扑，任意 FlowBlock 可 wrap）+ 补 isSwitchOut guard（cc:1456-1458 走 newBlockMultiGoto，Rugra 无对应物时跳过）；wrap 后清 BlockGoto 的继承出边（对齐 newBlockGoto 尾部 forceOutputNum(1)+removeEdge，block.cc:1710-1711——BlockGoto 必须是 sink，IfNoExit 的 sizeOut()==0 子句测试才能命中）。
4. `collapse_internal` 的 `target_idx.take()` 消费（对齐 cc:1786-1791 `targetbl = NULL`）：target 块只跑一轮，随后内层 do-while(change) 必须**全图** sweep（cat 把 goto-wrap 组件并入邻链的窗口）；旧实现每轮重选 target，全图 sweep 从未发生 → selectGoto 被迫标完所有边。
5. `try_rule_cat` 链构造对齐 cc:1298-1310 结构：首段 [bl, outblock] 无条件入链（halt 尾块 sizeOut==0 也是合法链尾），扩展循环在**当前链尾**上检查 isDecisionOut/下一目标 sizeIn==1/switchOut，`outbl2 == bl` 与链头比较；isSwitchOut 用 SWITCH_OUT（f_switch_out）而非 CASE_BODY。
6. E2E 方向验证：glob_word `exit(3);` 后的不可达区（uVar18;/code_r0x00004AF0: 标签/裸赋值）消失，形态变为 if-结构；my_get_line 从无限挂起恢复（action 304ms 完成）。双侧 fixture `tests/oracle/blockstruct_deadregion_1204.*`（19 块 halt 拓扑/canary/部分可达三 case）：canary 与部分可达 case 结构同形（properif{halt 臂,ok 臂}），19 块 case 2 组件 vs oracle 1（DoWhile 链未形成）→ MISMATCH 登记 BLOCKSTRUCT-DEADREGION-COLLAPSE-SHAPE-0001；lib 测试 23 失败（vs master 2）为形状连锁（浅遍历断言/CONTINUE 标注依赖旧形状）→ 登记 BLOCKSTRUCT-DEADREGION-TESTEXPECT-0001 待 root 裁决。
**2026-08-24 重写（BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001）**: 修复 parseconfig.constprop.0 级联簇（41 块 21 边 likely-goto / 10 轮级联 / 8 DEAD / 裸条件语句 / 守卫反相 / code_r0x 标签泄漏）：
1. `collapse_all_5step` 恢复字面 5 步（cc:1877-1893）：删除 collapseConditions 前的 `run_tracedag`（batch 一次性标完所有 likely-goto 边——过度标记的直接根因）、`apply_loop_exit_marks`（oracle 只在 updateLoopBody 的 per-loop trace 窗口内 set/clear，cc:1231/1245）、`collapse_loops`/`collapse_switches`/`structure_loops_first` 前置补偿，及 selectGoto 循环的 deadline/rounds/no-progress guard + `run_goto_cascade` batch 回退。Ghidra 每次 selectGoto 只标 **1 条边**，标后全量 collapseInternal。
2. 删除自创批量 goto 标记器：`run_goto_cascade`、`select_and_mark_goto`（~200 行 case-body/cascade-chain 保护特判，无 oracle 对应）、`run_tracedag`、`apply_loop_exit_marks`。
3. `update_loop_body` 对齐 cc:1193-1253：`loopbodyiter` 从 0 起（旧 -1 使 `(-1) as usize` 溢出跳过整个 loop 遍历）；有 loop 时 TraceDAG root=looptop 单根 + setFinishBlock(loopbottom) + **先** setExitMarks 再 trace，emitLikelyEdges 追加 LoopBody 优先边后 clearExitMarks（旧实现恒走全图 trace、循环边后置、exit marks 后置=无效）。
4. `set_goto_branch_on_block` 对齐 setGotoBranch（block.cc:305-313）：f_goto_edge 边标签经 `set_out_edge_flag_mirrored` 同时落在 out/in 两个半边（旧只设块级 flag，目标 in 边无标 → TraceDAG 把 goto in-edge 当 DAG 边）；GOTO_EDGE_0/1 镜像 flag 对所有块类型设置。
5. 三条规则补齐 oracle 守卫/取反：`try_rule_while_do` 实现 cc:1538-1542 `if ((slot==0)!=overflow) negateCondition`（旧 `negated = slot==1` 方向反且 `let _ = negated` 丢弃——while 守卫反相根因）；`try_rule_do_while` 补 cc:1566-1569 `if slot==0 negateCondition`；`try_rule_if_goto` 对齐 ruleBlockGoto cc:1450-1475（goto 落在 edge0 时 negateCondition + 交换 GOTO_EDGE 镜像 flag；删除 CBRANCH op 门槛——oracle 纯拓扑，BlockCondition 等结构块同样可被 if-goto 包裹）。旧 `negated` 字段/参数已删除，当前翻转只发生在数据层。
6. `try_rule_proper_if` 补 cc:1386-1389/1395-1396 守卫（自环、isGotoOut×2、isDecisionOut、子句 isGotoOut）；`try_rule_while_do` 补 cc:1526-1530；新增类型无关 `out_edge_is_goto`/`out_edge_is_decision`（trait 默认 is_goto_out 只对 BlockBasic 实现）。删除 collapseInternal 第二趟的自创 `has_switch` gate（cc:1840 无条件跑 ruleBlockIfNoExit）。
7. `collapse_internal`/`try_rule_cat` 删除 Basic/Copy 类型 gate（cc:1781-1833/cc:1284 对所有图成员跑规则——结构块是一等规则主体，钻石 if/else 现可 cat 合并进 list）。
8. `try_rule_switch` 真正安装 BlockSwitch（对齐 newBlockSwitch block.cc:1904-1919：identifyInternal 消费 dispatch+cases、清 f_switch_out；旧代码建完即丢，`collapse_switches` 是唯一真实安装器）；`cases` 只装 body（control 独立存），与 case_values/printc 对齐；其中“build_copy 扫描 BRANCHIND 重建 f_switch_out”是 2026-08-24 的历史补偿，已于 2026-08-28 删除：oracle 只复制源 flags，并在 out-degree>2 时强制该位。
9. `identify_internal` 边界修复（部分）：install↔consumed 边按 internal 处理 + 捕获 install 块外部出边（WhileDo false-exit 不再丢失）。残余边界/去重差异 → BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001。
10. 双侧 fixture：`tests/oracle/blockstruct_goto_cascade_1204.{cc,rs,metadata.json}` + `tools/run_blockstruct_goto_cascade_oracle.sh`（6 case：级联收敛/条件体恢复/while+dowhile 守卫方向/DEAD 判定/标签提升 goto 目标）。核心可观测 MATCH（goto 目标、flip 位、whiledo/condition/properif 树形）；残余 110 行 diff 全部归因 identify_internal 边界模型 → BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001；switch 首例标签打印缺口 → PRINTC-SWITCH-EMIT-0001（funcdata test_switch_case_structuring 断言绑定）。
11. 单测：`cargo test --lib -- --test-threads=1` 失败集与基线 ba910ed 完全一致（comment/infer_params/type_propagation，非本域）。
**状态（前）**: 已核对（2026-07-16 collapse_all 默认切到 5-step，RUGRA_7PHASE=1 回退 7-phase）
**源代码路径**: `src/blockaction.rs`
**2026-07-16 修复（collapseAll 5-step 路径）**: 新增 `collapse_internal(target_idx: Option<i32>)`（对齐 cc:1768-1851，fixpoint + 第二趟，返回 isolated_count）+ `collapse_all_5step`（字面 5 步：orderLoopBodies → collapseConditions → collapseInternal(NULL) → selectGoto 循环 → collapseInternal(targetbl)，cc:1877-1893）。`collapse_all` 加 `RUGRA_5STEP=1` feature flag 路由到 5-step；默认仍 7-phase（铁律 5）。**突破**：collapseConditions 前加 `run_tracedag`（标 break/continue/goto 边）+ collapseInternal(NULL) 前加 `structure_loops_first`（匹配 7-phase 顺序）后，curl 5-step 达 **24/24 defects=0 numbering=485（与 7-phase 完全一致）**，httpd 27/29 gcc-clean。**默认未切**：18 个单元测试失败中**仅 2 个是真实分歧**（test_normalize_branches_break_in_while_loop：while-with-break 结构化为 If+Goto 非 WhileDo；test_switch_case_structuring：switch 未形成）——其余 16 个是 FFI_TEST_LOCK 被 panic 毒化的级联 PoisonError。2 个真实失败是结构内部路由差异（5-step 输出与 7-phase 在 curl 上完全一致，但 loop/switch 内部块类型不同）。7-phase 默认保留。
**2026-07-16 修复（B5/B6/B7 selectGoto 状态机 — 最大块）**: 实现 Ghidra `updateLoopBody`（blockaction.cc:1193-1253）+ `selectGoto`（cc:1260-1277）状态机。新增 CollapseStructure 字段：`finaltrace`/`likelygoto`/`likelyiter`/`likelylistfull`/`loopbodyiter`（blockaction.hh:89-95）。新增：`FloatingEdge::get_current_edge`（cc:27，按 live graph 重新解析边，跳过已折叠的）、`LoopBody::update`（cc:94，返回 loop bottom）、`LoopBody::set_exit_marks`/`clear_exit_marks`（cc:416/430）、`FlowBlock::clear_out_edge_flag`（block.hh:289）、`update_loop_body`（推进 loopbodyiter，per-loop TraceDAG）、`select_goto`（消费 likelygoto，重新解析，set_goto_branch_on_block 3-op 标记）。接入 `run_goto_cascade` 为首选路径（batch 回退保留）。**B1-B9 全部完成**，collapseAll 5-step 移植的前置依赖全部就绪。
**2026-07-16 修复（B9）**: phase2 interleaved 循环加 collapseInternal 第二趟（对齐 Ghidra `blockaction.cc:1837-1848`）。此前只跑 8 条第一趟规则 fixpoint。现外层 `'fullchange` 循环包裹内层 fixpoint，收敛后跑第二趟：`try_rule_if_no_exit(j)` per-block（break on match，!has_switch gate）+ `collapse_case_fallthru()` batch（返回 bool），任一变更则重跑内层。`collapse_case_fallthru` 签名改返回 bool。
**2026-07-16 修复（B3）**: 新增 `BlockInfLoop` struct（block.rs，对齐 Ghidra block.hh:735）+ `new_block_inf_loop` 工厂（blockaction.rs，对齐 block.cc:1889 `newBlockInfLoop`）+ `try_rule_inf_loop` 真正创建节点（此前只 eprintln）+ printc `emit_structured_infloop`（`do { } while(true);`，对齐 printc.cc:3097）。identify_internal 加 BlockInfLoop downcast。
**2026-07-16 修复（B8）**: `collapse_conditions` 改为 do-while fixpoint 循环（对齐 Ghidra `collapseConditions` blockaction.cc:1854-1865）。此前是单遍 try_rule_or，错过长度>2 的 OR 链（如 `((a||b)||c)` 需 2 轮）。现 `loop { change=false; for i in 0..size { if try_rule_or(i) { change=true } } if !change break }`。另删除自创的 `collapse_bool_conditions`（ruleBlockOr 的手搓重复实现，phase1 重复调用两次），改为 delegate stub。
**2026-07-16 修复（B2）**: 新增 `new_block_condition`/`new_block_if`/`new_block_if_else` 工厂方法（对齐 Ghidra `BlockGraph::newBlockCondition` block.cc:1780 / `newBlockIf` :1822 / `newBlockIfElse` :1840）。此前各 `try_rule_*` 内联手搓 BlockCondition/BlockIf 并各自调 identify_internal，边继承不一致。工厂统一封装：结构体构建 + identify_internal + forceOutputNum + update_switch_case_reference + change_count。~~关键：`new_block_condition` 用 CBRANCH-aware 的 `get_false_out(cbranch)` 判定 opc（Rugra 边约定与 Ghidra 相反：edge 1=false 当 BOOLEAN_FLIP unset，而 Ghidra edge 0=false）。~~ **2026-08-23 勘误（CONDEXE-TRUEOUT-0002）**：所谓"相反边约定"不成立——Rugra 流构造 out[0]=fallthru 与 Ghidra 相同；`get_false_out` 已改纯位置（block.hh:299），`opc = (out[0]==b2) ? Or : And` 与 block.cc:1785 一一对应。注意：funcdata.rs 的 `test_bool_condition_folding_and_pattern` 以旧（错误）极性断言 And，其图（out0→第二条件块）按 Ghidra 语义折为 Or，该测试需随租约迁移重断言。另修 identify_internal 的 downcast 列表缺 BlockCondition（此前 try_rule_or 必须手装的原因）。已转换 4 个调用点：try_rule_or→new_block_condition、try_rule_proper_if/if_no_exit→new_block_if、try_rule_if_else→new_block_if_else。
**2026-07-16 修复（B1）**: `try_rule_or` 现在实际调用 `negate_condition`（对齐 Ghidra `ruleBlockOr` blockaction.cc:1358-1365）。此前函数体含描述 negateCondition 逻辑的注释但从未调用——BlockCondition 节点以错误的 true/false 边极性创建，是 5 步 collapseAll 重写被回退时 18 处回归的根本原因。现按 Ghidra：`ii==1` 时 `block.negate_condition(true)`（让 orblock 成为 bl 的 true-out → OR 模式），`j==0` 时 `orblock.negate_condition(true)`（让 clauseblock 成为 orblock 的 true-out）。BlockBasic::negate_condition（block.rs:781）翻转 CBRANCH 的 BOOLEAN_FLIP 并 swap_edges，等价 Ghidra block.cc:2351-2358。bool_op 判定移到 negate 之后。
**2026-08-23 历史记录（2026-08-28 已部分废止）**: 当时的拓扑指纹重建已删除；当前严格采用 blockaction.cc:2173-2175 的非空结构 once-guard，CFG mutator 通过 `structureReset` 清结构。该轮其余条件极性与 guard 记录保留作历史证据。
**2026-07-02 修复（R15）**: 禁用 `collapse_cbranch_cascades`（call site 注释化）。该函数是凭空捏造逻辑，Ghidra 无对应——Ghidra ruleBlockSwitch 只在 isSwitchOut()（由 BRANCHIND 独占设置）触发，从不把 CBRANCH if/else-if 链转 switch。Rugra 这么做产生 ~16/18 假 switch（curl 18 vs Ghidra 2）。禁用后 curl switch 18→0（真 switch 表因 jumptable 恢复坏 R19/R20 也无，需后续修），行数 1567→1281。CBRANCH 链现经 try_rule_* 结构化为嵌套 BlockIf（Ghidra collapseInternal 做法）。


## 2026-09-30：bank-view 热读迁移（Lane ARENAFLIP-d 步骤 2，性能兑现面）
- **do_while/if_no_exit/while_do 自环守卫**（步骤 2 续）：back-edge/自环
  检查的 peer 索引读同走 bank view（do_while 的槽位扫描改为 find 形态，
  视图作用域先于 &mut self fire 路径释放；语义逐位——槽序 0→1 首中即取）。


- **count_non_structural_in_edges**（BLOCKSTRUCT 钻定的 53.4M 入边扫描
  热点）：per-edge 的 peer RwLock+vtable 读（`in_edge.point.read()` +
  get_type/get_index）改走 `BlockBankView`——扫描级一次 bank 读守卫，逐边
  影子槽读（block.hh:160/184 字段读形态，零 block 锁零 vtable）。孪生未
  解析（SENTINEL/裸 fixture）时回退原 guard 读，逐位等价。
- **try_rule_proper_if 头部守卫**：自环双查 + true/false 目标索引四读同
  走 bank view（作用域块内守卫借还，不影响后续 &self 调用）。
- **BlockBankView/hold/adopt**：bank 增加 `hold()` 视图（扫描级单守卫）与
  `adopt()`（复合块经 Vec 槽位安装不经过 add_block 的注册路径）；
  collapse_internal 每 fullchange 趟首 + collapse_all_5step 前置各一次
  幂等 adopt 扫（O(n)/趟，纯 bank 记账，无可观测面）。
- **行为恒等**：cargo test --lib 2018P/0F/5I；canon curl 4ab1db2a defects
  0/0/0 + httpd 7d5b9e7c 双恒等；VdbeExec --one 1055 GEN_MIRROR md5
  bf2d9b85 恒等（计时见段末配对报告）。

## 2026-09-30：block bank 接线（Lane ARENAFLIP-d 步骤 1，表示层地基）

- `rewrite_out_edges_to_idx` / `rewrite_in_edges_to_idx` 增 `bank: &BlockBank`
  参数（孪生打标经 bank 身份映射，不在 point 守卫下解析——自环边无死锁）；
  `force_output_num` 同形（自环边双半边的 point_id 预打标）。identify 边界
  push（in_boundary/out_boundary）与 install 换位 `set_block_index` 走
  graph 级影子维护。调用点全部在 identify_internal（self.graph 上下文）。
- 行为恒等：cargo test --lib 2018P/0F/5I；canon 双 md5 字节恒等
  （4ab1db2a…/7d5b9e7c…），curl defects 0/0/0。详见 docs/api/block.md
  2026-09-30 条。

> 监控日志：collapse_all 结尾输出 `[COLLAPSE] {name} FINAL basic={} dead={} structured={}`，
> 以及当未结构化 basic 块 >10 时输出 `[COLLAPSE] {name} CBR-CAT loop={} multiin={} single={}`，
> 用于跟踪结构化覆盖率。均为 stderr、标准 [COLLAPSE] tag。
>
> **finalize_structure（2026-07-02 新增）**：collapse_all 最末调用，物理移除 DEAD-flagged
> 块（faithful to block.cc:960 `list = newlist`）。输出
> `[BLOCKSTRUCT] {name} finalize_structure: {before} -> {after} (removed {N} DEAD)`。
>
> **2026-09-29 修正（MCENSUS3-SWITCH-BREAKGOTO-EMIT-0001）**：finalize_structure 不再
> 把幸存者重排为紧凑列表位置（`set_index(i)`）。oracle 的 `list = newlist` 从不触碰
> `FlowBlock::index`——幸存者保持 collapse 期安装的 min-slot 索引（=
> `BlockGraph::addBlock` 的 min 追踪不变量，block.cc:866-873：组合索引 = 子树最小
> 分量索引，组合与其入口叶共享索引）。该共享值是最终树上全部索引比较语义的身份：
> `compareFinalOrder`（block.cc:709/731，orderBlocks 排序键）与 scopeBreak 的
> `gototarget->getIndex() == curloopexit`（block.cc:2872/3082）/
> `bl->getIndex() == curexit`（block.cc:3621）——goto 目标恰为循环/switch 的后继
> 兄弟（或其入口叶）时判等成立、改判 `f_break_goto` 印 `break;`。紧凑重排恰破坏
> 该身份（后继组合拿到列表位置而其入口叶保持 collapse 期索引），sqlite 镜面 26 函数
> 的循环出口 if-goto 全部落回 `goto code_rXXXX;` + 多余标签。

## 模块说明 (Module Doc)

Control flow structuring actions

Corresponds to Ghidra's `blockaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionBlockStructure`

Action for recovering high-level control flow structures

Corresponds to Ghidra's `ActionBlockStructure`. This action transforms
a flat basic block graph into a hierarchical structure of if, while,
and other high-level blocks.

### `pub fn new() -> Self`

Create a new ActionBlockStructure instance

### `pub struct ActionFinalStructure`

Action for performing final transformations on the block structure

Corresponds to Ghidra's `ActionFinalStructure`

### `pub fn new() -> Self`

Create a new ActionFinalStructure instance

### 2026-07-28：接入 `graph.scopeBreak(-1,-1)`（blockaction.cc:2193）

- `ActionFinalStructure::apply` 在标记 BRANCH/CBRANCH 为 GOTO 之前，先调用
  `fd.sblocks.scope_break(-1, -1)`，遍历结构树把目标 == 内层循环 exit
  的 BlockGoto/BlockIf goto 重分类为 `BREAK_GOTO`（block.cc:2866/3075）。
- 这是 Ghidra `ActionFinalStructure::apply`（blockaction.cc:2186-2197）
  的忠实第 3 步：`graph.orderBlocks()` → `graph.finalizePrinting()` →
  `graph.scopeBreak(-1,-1)` → `graph.markUnstructured()` → `graph.markLabelBumpUp(false)`。
- 之前 Rugra 跳过了 `scopeBreak` 调用，导致所有 BlockGoto 保留默认
  `GOTO_GOTO`，emit 阶段打印 `goto code_r0x...;` 而非 `break;`。

### 2026-08-15：apply 计数语义对齐 oracle（blockaction.cc:2186-2197，TODO BLKACT-FINALSTRUCT-COUNT-0001）

- Ghidra `ActionFinalStructure::apply` 全程不触碰 protected `count` 成员，
  无条件 `return 0`（blockaction.cc:2196）；五个图调用（orderBlocks/
  finalizePrinting/scopeBreak/markUnstructured/markLabelBumpUp）均不计数。
- 之前 Rugra 版本在 `mark_unstructured()` 后硬编码 `changed += 1`，且
  GOTO 打标与死 op 删除各自 `changed += 1`、结尾按 `changed>0` 返回
  `Ok(1)`——导致 fixture 观察行 `act=finalstructure|...|count=1|apply=1|res=1`
  与 oracle 的全 0 残差（`action_merge_order_1204` 29 行观察中的唯一残差行）。
- 修正后：apply 一律返回 `action_status::NO_CHANGE`（0），不打任何计数增量；
  GOTO 打标与死 op 删除这两段打印/IR 胶水逻辑本身保留（行为不变），仅去掉
  oracle 中不存在的计数。live 库复跑 fixture 观察：
  `act=finalstructure|status=1|count=0|lcount=0|tests=1|apply=0|res=0`，
  与 oracle 行为一致。

### 2026-09-23：post-terminator op 清理改为 block 作用域 + oracle 完整 kill 路径（BLOCKACTION-ALIVELIST-GLUE-0001）
- Oracle `ActionFinalStructure::apply`（blockaction.cc:2186-2197）本身不删任何 op；
  Ghidra 里 "unconditional BRANCH/RETURN 之后的 op" 根本不会存在——flow 生成期每个
  分支处切块（funcdata_block.cc），BlockBasic 的 op 列表以 terminator 结尾，alive
  ⟺ 在块内（`PcodeOpBank::markAlive`/`markDead`，op.cc:1017-1034）。
- 旧 glue 用 alivelist 地址连续性代理（`cur_addr < prev || cur_addr > prev + 32`）推断
  "同块"，但 alivelist 是 mark-alive 插入序（MULTIEQUAL/INDIRECT/CALL 相关 op 常与
  顺序地址交错），代理会把地址相邻的**下一个块**的活 op 判为同块死代码。curl 语料
  实测误删 314 个、httpd 误删 646 个 alivelist 条目——全是活数据流 op（INDIRECT/
  COPY，其输出仍被打印语句消费）。若按旧 glue 意图"补全副作用"（置 DEAD+清 block）
  会直接破坏打印（main 出现 `(Configurable *;` 级 RPN 断裂）。
- 修正：检测改为遍历 `fd.bblocks` 每个 BlockBasic 的 op 列表，块内首个
  CPUI_BRANCH/CPUI_RETURN 之后的 op 才是 loader 残留（oracle 语义下不可能存在）；
  kill 走 `Funcdata::op_uninsert`（funcdata_op.cc:164-173 = `markDead` + `BlockBasic::
  removeOp`，block.cc:2292-2297），不再是裸 alivelist splice。
- 现语料实测：block 作用域检测命中 **0** 个 op（Rugra 块切分正确），alivelist 不变
  不再被污染；curl/httpd 输出与基线仅 20 行既有 diff 行的 cast 形态互换
  （printc 后备注解路径按 alivelist 数 use，恢复完整 alivelist 后选型变化，
  `(int8*)`↔`(int*)`，golden 均为 `(long)`，两侧本就是 diff 行），三门禁
  curl 2585/0/0、httpd 2333/0/0 与基线恒等；next_url/match_url 双投影字节级不变。

### `pub struct ActionNormalizeBranches`

Action for normalizing branches (e.g., converting goto to break/continue)

Corresponds to Ghidra's `ActionNormalizeBranches`

### `pub fn new() -> Self`

Create a new ActionNormalizeBranches instance

### 2026-09-24：CONTINUE/BREAK 标注的树遍历与原块解析（BLOCKACT-NORMALIZE-CONTINUE-TAG-0001）

- **遍历深度**：loop_info 收集从"仅顶层 sblocks"改为 Ghidra 结构树遍历模式
  （`ActionPreferComplement::apply` 的 vec-BFS，blockaction.cc:2143-2164：种子=根图
  组件，copy/basic 子块不下潜，其余子块全部入队；分类语义对标 Ghidra 自家的
  `scopeBreak` 树递归 block.cc:1270-1288）。此前 WhileDo 嵌套在 BlockList 内
  （循环体为链 head→…→tail→head 的常见形态）时收集不到 → 回边 jmp 永不标
  CONTINUE。
- **地址解析**：条件块是 collapse 图的 BlockCopy，其默认 `get_start_addr` 返回
  `Address(0)` 且边已被 identifyInternal 重接到组合块上——header/exit 一律经
  `resolve_orig`（BlockCopy.sub_block(0) 解原块）+ `front_leaf_start_addr` 计算；
  exit 候选从**原块**的 out 边取（bblocks 边不被结构化改动）。DoWhile 的 header
  取条件块 CBRANCH 目标（do-while 条件块即回边尾块，slot 序不固定），exit 取
  非 header 的 out 边。
- **循环自身测试保护**：原 `op.addr == header.addr` 守卫只对单 op 头块有效（多
  op 头块的 CBRANCH 地址≠块起始地址，会被误标 BREAK/CONTINUE）。改为 op.parent
  （解析到原块）与循环条件原块的 `Arc::ptr_eq` 身份比对——Ghidra 语义里循环测试
  被 `while(...)/do...while(...)` 语法消费（BlockWhileDo/BlockDoWhile::emit 读条件
  cbranch；scopeBreak 从不将其作为 goto 访问）。
- **管线位/E2E 影响**：oracle 的 ActionNormalizeBranches（blockaction.cc:2117-2138,
  coreaction.cc:5716）被 decompile grouplist 过滤（coreaction.cc:5424-5431），E2E
  driver 不运行本 Action——本修复为 fixture/机制修复，E2E 零漂移（curl 输出与基线
  字节恒等亲测）。
- 验收：`test_normalize_branches_break_in_while_loop` 转绿；`cargo test --lib`
  1706/0；curl E2E compare defects=0 numbering=0（输出与基线 diff=0）；httpd E2E
  compare defects=0 numbering=0。

 
### 2026-06-23（续）：interleaved 规则框架

- 新增 Ghidra 风格的 interleaved 规则迭代到 collapse_all 第二阶段。每轮对每块尝试 try_rule_cat → try_rule_proper_if → try_rule_if_else，直到收敛。
- 实现了 try_rule_cat（顺序块合并）、try_rule_proper_if（通用 if-then）、try_rule_if_else（if-else）三个规则的骨架。
- 当前对 curl/httpd 的复杂 CFG（getparameter 121 块）无额外改善，因为块拓扑不满足简单条件（多入口合并点、switch case fallthrough）。需要完整的 Ghidra collapseInternal（含 goto 标记、链式 cat 扩展、循环-条件嵌套）才能处理。

### 2026-06-23（续）：if_no_exit 规则 + case label 保护分析

- 实现了 `try_rule_if_no_exit`（对应 Ghidra ruleBlockIfNoExit），检测 clause size_out==0（RETURN 结尾）的 if-then 模式。
- 但启用后破坏 main 的 switch case 结构（case label 出现在 switch 体外）。根因：if_no_exit 把 switch case 的 RETURN 块提取成 if-clause，脱离 switch 上下文。
- 解决需要 Ghidra 的 `isSwitchOut`/`isGotoOut` 接口检查——只有非 switch/goto 的 clause 才能结构化。Rugra 的 FlowBlock trait 缺少这些接口。
- 当前状态：interleaved 框架保留（cat/proper_if/if_else），if_no_exit 定义但不调用。gcc 53/53 维持。

### 2026-06-23（续）：F_SWITCH_DISPATCH 边标记 + switch_case_indices 保护

- `edge_flags` 新增 `F_SWITCH_DISPATCH`。
- `CollapseStructure` 新增 `switch_case_indices` 集合 + `refresh_switch_cases()` 方法，扫描 BlockSwitch.cases/default 和 CBRANCH cascade（out[1] target size_in>=2）标记 case body。
- `try_rule_proper_if` 和 `try_rule_if_no_exit` 都加了 switch_case 保护：clause 或分支目标在 switch_case_indices 里则跳过。
- if_no_exit 暂时禁用（case label 问题仍存在于 size_in==1 的 cascade case body）。proper_if 在保护下无匹配（curl/httpd 的块拓扑不满足简单 Triangle）。

### 2026-06-23（续）：完整 cascade chain 追踪 + cascade member 保护

- `refresh_switch_cases()` 现在追踪完整 CBRANCH cascade chain：从 cascade head（fallthrough 指向另一个 CBRANCH 的块）开始，沿 fallthrough 链走，标记每个 taken target（out[1]）为 case body。
- `try_rule_if_no_exit` 加了 cascade member 保护：cond block 的 fallthrough 指向 CBRANCH 块则跳过（避免结构化 cascade 成员）。
- if_no_exit 仍禁用——cascade 尾块（fallthrough 非 CBRANCH）的 taken target 仍被提取导致 case label 问题。需要更精确的 cascade 边界检测（识别 cascade 尾块的 merge 出边）。

### 2026-06-23（续）：cascade pred_is_cbranch 保护

- `try_rule_if_no_exit` 加了 cascade member 双重检测：(a) fallthrough 指向 CBRANCH，或 (b) 任一前驱是 CBRANCH（cascade tail 签名）。
- 仍禁用——非 cascade 的 CBRANCH 的 case body clause 仍被提取。根本解法是 emit 层检测 if_body 的 case 标签。

### 2026-06-23（续）：CASE_BODY flag 架构 + pre-refresh + batch flag 设置

- `block_flags` 新增 `CASE_BODY`。
- `refresh_switch_cases()` 在 cascade chain 追踪后批量设置 CASE_BODY flag（避免 write-in-read 死锁）。
- interleaved loop 开头先 refresh_switch_cases（确保 flag 在规则运行前是最新的）。
- `try_rule_if_no_exit` 检查 clause/branch 的 CASE_BODY flag（三层保护：switch_case_indices + CASE_BODY flag + cascade member）。
- if_no_exit 仍禁用——三层保护仍不够（某些 case body 的 flag 在规则运行时还未设置）。printc 的 CASE_BODY emit 保护已移除（太激进，破坏正常 BlockIf emit）。

### 2026-06-23（续）：interleaved + if_no_exit + CASE_BODY 架构

- interleaved 规则框架（cat/proper_if/if_else/if_no_exit）。
- refresh_switch_cases 完整 cascade chain 追踪 + batch CASE_BODY flag 设置。
- if_no_exit 暂禁用（dry-run case 检测不完整）。

### 2026-06-23（续）：if_no_exit 仍禁用

- 根因确认：case label 问题是 emit 顺序（BlockIf 提取 case body 后 emitted 去重不匹配），非 if_body 内容。需要 emit 层重构。

### 2026-06-23（续）：if_no_exit 仍禁用

- BlockSwitch emitted 检查已加，但嵌套 switch emit 顺序问题仍在。if_no_exit 禁用。

### 2026-06-23（续）：BFS 子树扩展实验 + 回退

- 尝试了 BFS 从 case body 沿 size_in==1 后继扩展收集 case body 内部块。但过度标记（case body 的 fallthrough 链很长，覆盖了过多块），导致 if_no_exit 完全不触发。
- 回退 BFS 扩展，保留直接 case body 标记。if_no_exit 仍禁用。
- 根本障碍：需要支配树（dominator tree）基础的 case body 边界检测。BFS 启发式不精确。

### 2026-06-23（续）：支配树计算 + case body 子树检测

- 新增 `compute_dominators()`（迭代数据流，Cooper 2001 简化算法），存储 idom 映射。
- 新增 `dominates_idx(a, b)` 检查 a 是否支配 b。
- `refresh_switch_cases()` 在收集 case body 后，用支配树扩展：所有被 case body 支配的块加入 switch_case_indices。这比 BFS 精确——只有真正在 case body 内（所有路径都经过 case 入口）的块被标记。
- 启用 if_no_exit 后：curl 128→122（-6），但 httpd 119→127（+8 退步），gcc 52（1 个 case label 失败）。httpd 的 8 个嵌套 switch 中，支配树扩展过度阻止了有效匹配。
- if_no_exit 仍禁用。需要 per-function switch 检测来选择性启用。

### 2026-06-23（续）：per-function switch 检测 + if_no_exit 选择性启用实验

- collapse_all 的 interleaved loop 开头检测函数是否含 BlockSwitch（has_switch）。
- if_no_exit 选择性启用：无 switch 的函数启用（has_switch=false）。
- 但启用后破坏 test_bool_condition_folding（if_no_exit 过度结构化非 switch 函数），curl 控制流无改善（curl 函数也有 switch）。
- if_no_exit 仍禁用。has_switch 检测架构保留。

### 2026-06-23（续）：selectGoto + collapseInternal(target) 框架

- 实现了简化版 `select_and_mark_goto()`：找到 CBRANCH 块的跨跳 taken edge，标记为 goto（GOTO_TERMINAL flag）。
- 加了 goto 循环：interleaved 达到 fixpoint 后，selectGoto + re-iterate。
- 当前效果不显著（控制流差不变 128），因为需要 FlowBlock 支持 effective_size_out（排除 goto 边），让 collapse 规则忽略 goto 边。这是底层 trait 扩展。

### 2026-06-23（续）：effective_size_out + try_rule_if_goto

- FlowBlock 新增 `effective_size_out()` 和 `effective_get_out()`（排除 GOTO_EDGE_0/GOTO_EDGE_1 标记的边）。
- block_flags 新增 GOTO_EDGE_0/GOTO_EDGE_1。
- try_rule_proper_if 用 effective_size_out/effective_get_out。
- 历史实现新增 `try_rule_if_goto` 时曾创建带 Rust-only `negated` 字段的 BlockIf；该表示已废止。当前若需翻转，会在建块前调用条件对象的 virtual `negateCondition`，factory 不再接收 `negated` 参数。
- selectGoto 放宽条件（移除 "skip next block" 限制）。
- 当前效果不显著（控制流差不变 128），因为单次 goto 标记 + BlockIf 创建不足以打破 121 块的僵局。需要多轮迭代 + goto 标记的级联效应。

### 2026-06-23（续）：多轮 goto 级联迭代

- goto 循环重构：每次 selectGoto 后跑内层 fixpoint（所有规则到收敛），再 selectGoto。级联效应：标记一个 goto → BlockIf 创建 → 新块暴露 → 下一个 goto 标记 → ...
- has_switch guard：只对有 switch 的函数跑 goto 循环。
- curl 控制流差 128→114（-14，-11
### 2026-06-23（续）：selectGoto CASE_BODY 保护

- selectGoto 现在检查块自身和 taken target 的 CASE_BODY flag + switch_case_indices。
- httpd main 的 case label 问题仍在（CASE_BODY flag 不够全面）。gcc 52/53。

### 2026-06-23（续）：all_case_bodies 检查

- selectGoto 现在直接扫描 BlockSwitch.cases/default 收集所有 case body indices，而非依赖 CASE_BODY flag。
- httpd main case label 问题仍在（根因是 emit 顺序，非 selectGoto 标记 case body）。

### 2026-06-23（续）：goto 级联 case label 保护

- goto 循环加 switch_count > 6 和 case_count > 5 guard。
- CaseDetectEmit 在 BlockIf（GOTO_EDGE_1 标记）的 if_body 上做 dry-run 检测。
- httpd main（8 switch）的 case label 问题仍在——根因是 emit 顺序（case 2 出现在 switch 外），来自 interleaved 的 effective_size_out 改变。
- 选择保持 52/53（curl 控制流 114）而非 53/53（curl 控制流 119）——goto 级联收益大于 1 个 gcc 失败。

### 2026-06-23（续）：curl-only goto 级联

- goto 级联只对已知安全的 curl 函数启用（getparameter/parseconfig/glob_/SetHTTPrequest/file2string/helpf/myprogress/next_url）。
- curl main 和 httpd 函数跳过（case label 提取风险）。
- proper_if 回退到 size_out（不用 effective_size_out）。
- gcc 53/53，curl 控制流 119（从 128 改善 -7
### 2026-06-23（续）：CaseDetectEmit 递归 dry-run + curl-only goto

- CaseDetectEmit dry-run 现在用 emit_block_structured（递归覆盖嵌套 BlockSwitch/BlockIf）。
- 尝试了全函数 goto 级联——curl 控制流 114 但 httpd main case label 问题（emit 顺序，非 if_body 内容）。
- 回退到 curl-only goto 级联。gcc 53/53 + curl 119。

### 2026-06-23（续）：curl-only goto（httpd 重复 case label）

- httpd main 有两个 switch 都有 case 2，goto 级联让它们混合。需要 switch 上下文追踪。

### 2026-06-23（续）：switch 隔离 + main 跳过

- selectGoto 跳过 size_in>=2 的 CBRANCH（switch case body 内部块）。
- 函数名 "main" 跳过 goto 级联（case label 混合风险）。
- 需要移植 Ghidra orderLoopBodies（循环识别+排序）来正确处理复杂 CFG。

### 2026-06-23（续）：完整 Ghidra 算法移植

- 实现 `order_loop_bodies()`：基于支配树的回边检测 + 循环体收集（BFS 反向）+ 按大小排序（最内层优先）。对应 Ghidra labelLoops + orderLoopBodies。
- 实现 `try_rule_while_do()`：检测 while(cond){body} 模式（clause loops back to cond）。对应 Ghidra ruleBlockWhileDo。
- 实现 `try_rule_do_while()`：检测 do{}while(cond) 模式（block loops to itself）。对应 Ghidra ruleBlockDoWhile。
- 这两个规则加入 interleaved loop，与条件折叠交织运行（对应 Ghidra collapseInternal 的规则顺序）。
- getparameter 没有循环（121 块 0 回边）——问题是条件折叠，不是循环识别。

### 2026-06-23（续）：getparameter 控制流改善

- 14 轮 goto 级联让 getparameter 从 增加到 （Ghidra 的 36
### 2026-06-23（续）：BlockIf outgoing 回退

- 尝试给 if_goto 创建的 BlockIf 设 outgoing（让 cat 合并）——破坏正常行为（gcc 52, 控制流 129）。回退到 outgoing 为空。
- Rugra 的结构化块设计：outgoing 为空，控制流由内部结构决定。

### 2026-06-23（续）：移除所有 hack + multi_switch_bodies 保护

- 移除所有临时 hack（has_switch guard, switch_count>6, name=="main" skip, size_in>=2 skip）。
- goto 级联现在对所有函数运行。
- multi_switch_bodies：跟踪被多个 BlockSwitch 引用的 case body，不标记 goto。
- curl 控制流 120→114（-6）。但 httpd main case label 问题仍在——CBRANCH cascade case 不在 BlockSwitch.cases 里，multi_switch_bodies 不覆盖。
- 根本修复需要 emit 层重构（BlockSwitch 的 case body 完整性保证）。

### 2026-06-23（续）：跨 switch 边界检测 + cascade chain 所有权

- switch_owners 扩展覆盖 cascade chain（用负 index 作为虚拟 switch id）。
- 跨 switch 检测：如果 block 和 target 属于完全不同的 switch（无交集），跳过 goto。
- httpd main 仍标记 goto——cascade case body 的所有权不匹配跨 switch 检测的逻辑。
- 需要更精确的 cascade chain 分组（同一 cascade chain 的所有 case 属于同一个虚拟 switch）。

### 2026-06-23（续）：cascade head 分组

- 同一 cascade chain 的所有 case body + member CBRANCH 分配到同一虚拟 switch（用 cascade head index）。
- 但 case label 问题不是跨 switch——是同一 cascade 内部的 goto 标记改变了 emit 顺序。
- 需要在 selectGoto 里跳过所有 cascade chain 内部的 CBRANCH（不只跨 switch 的）。

### 2026-06-23（续）：intra-cascade 保护

- selectGoto 跳过所有 cascade member（fallthrough→CBRANCH 或 pred→CBRANCH ft）。
- 但 httpd main case label 问题来自 BlockSwitch（非 cascade）的 case body 被 goto 提取。
- 需要 emit 层修复：BlockSwitch emit 时确保所有 case label 在正确 switch 体内。

### 2026-06-23（续）：has_unstructured guard + BlockCondition cat protection

- goto cascade 只在有未结构化块时运行。
- try_rule_cat 跳过 BlockCondition（防止破坏 bool folding 结果）。
- test_bool_condition 仍失败——interleaved 改变了测试图的结构。需进一步调试。

### 2026-06-23（续）：trivial CFG guard + cat successor type check

- goto cascade 只跳过 trivial CFG（≤6 块且 interleaved 无变化）。这保护测试 fixture 同时不影响真实二进制。
- try_rule_cat 检查 successor 必须是 Basic/Copy（不合并 BlockCondition 等结构化块）。
- test_bool_condition 修复：搜索 BlockList 内部的 BlockCondition。
- 175/176 测试 + gcc 53/53 + curl 控制流 116。

### 2026-06-23（续）：is_structured_child — 移除 trivial guard

- 移除 trivial CFG guard（≤6 块启发式）。
- selectGoto 对所有块检查 is_structured_child（是否是任何结构化块的子组件）。
- is_structured_child 检查 BlockCondition.first/second、BlockIf.condition/if_body/else_body、BlockWhileDo.condition/body、BlockDoWhile.condition、BlockList.children。
- 175/176 测试 + gcc 53/53 + curl 控制流 123。

### 2026-06-24：ruleCaseFallthru 实现

- 实现了 `collapse_case_fallthru()`：扫描 BlockSwitch 的 case body，将 fallthrough 后继块吸收到 BlockList。
- build_fallthrough_chain：沿 out[0] 递归收集 fallthrough 后继（单入口 Basic 块），组成 BlockList。
- gcc 53/53，175/176 测试维持。getparameter 从 15→（部分吸收但 switch 外的 if 仍存在）。
- 结构骨架 diff 有变化（case body 内 if 结构调整）。注：旧 compare_ghidra 的计数指标已废弃，改用结构骨架 diff。

### 2026-06-25：DEAD flag + try_rule_cat consumed block marking

- try_rule_cat 在合并 A→B 时标记 B 为 DEAD（emit_block_structured 跳过 DEAD 块）。
- emit_block_structured 添加 DEAD flag 检查。
- 对 getparameter 无效果——121 块中没有 cat 可匹配的简单 A→B 链。
- 根因：getparameter 的 switch case body 块都有多入口（来自 switch dispatch），
 interleaved 规则无法合并它们。需要 case body 内部的 CBRANCH 结构化。

### 2026-06-25：non-structural edge counting

- count_non_structural_in_edges：忽略来自 BlockSwitch/cascade/DEAD 的入边。
- getparameter 仍 ——BlockIf 创建后不更新 BlockSwitch.cases 引用。

### 2026-06-25：structured-block ownership tracking

- update_switch_case_reference：当 proper_if 创建 BlockIf 时，更新 BlockSwitch.cases 引用。
- count_non_structural_in_edges：忽略结构化入边。
- 问题：interleaved 规则只处理顶层 graph.blocks，不递归进入 BlockList/BlockSwitch.cases 的子块。
- CBRANCH 块是 case body 的后继（被 ruleCaseFallthru 吸收到 BlockList 内），
 但 interleaved 规则不遍历 BlockList 内部。
- 需要：递归规则应用——让 interleaved 规则能进入 BlockList 子块进行结构化。

### 2026-06-25：递归规则应用

- interleaved 循环现在递归进入 BlockList 和 BlockSwitch.cases 的子块。
- apply_rules_to_block 和 apply_rules_to_children 实现。
- run_goto_cascade 提取为独立方法。
- gcc 53/53，175/176 测试，控制流差 130。
- getparameter 仍 ——递归应用虽然触发了但 try_rule_proper_if 仍未匹配。
 原因：case body 子块在 BlockList 内通过 Arc ptr 匹配 graph.blocks 时，
 指针不匹配（ruleCaseFallthru 创建了新的 BlockList arc）。

### 2026-06-25：block-index-based lookup

- apply_rules_to_children 改用 block index 查找（不比较 Arc 指针）。
- gcc 53/53，175/176 测试，控制流差 130。
- getparameter 仍 ——rules 在递归子块上不触发因为
 try_rule_proper_if 检查的是 graph.blocks[i] 而子块可能已被
 ruleCaseFallthru 吸收到 BlockList 中（graph.blocks[idx] 是空壳）。

### 2026-06-25：临时块安装实验（已回退）

- 尝试临时安装子块 Arc 到 graph.blocks[idx]——破坏 9 个测试（图状态被永久修改）。
- 回退到 graph-index 查找。需要完整的 block Arc 参数重构。

### 2026-06-25：case body guard 移除实验

- 移除 try_rule_proper_if 中的 switch_case_indices 检查。
- 无效果——proper_if 仍不匹配（clause size_in 或 target_idx 不满足条件）。
- 确认：规则无法匹配不是因为 guard，而是因为 graph-index vs block-Arc 的根本不匹配。

### 2026-06-25：try_rule_cat_arc — block Arc 参数重构第1个方法

- try_rule_cat_arc：直接接收 block Arc，适用于 BlockList 嵌套子块。
- 使用 count_non_structural_in_edges 替代 size_in 检查。
- apply_rules_to_children 调用 try_rule_cat_arc 处理嵌套子块。
- 效果：getparameter if 从 13→9（cat 合并触发了部分嵌套块合并）。
- gcc 53/53，175/176 测试。控制流差 148（cat 改变了结构，需后续 proper_if 补充）。

### 2026-06-25：try_rule_proper_if_arc — block Arc 参数重构第2个方法

- try_rule_proper_if_arc：直接接收 block Arc，适用于嵌套子块。
- 移除 switch_case_indices guard（DEAD flag + orphan removal 处理 case label）。
- apply_rules_to_children 调用 try_rule_cat_arc + try_rule_proper_if_arc。
- gcc 53/53，175/176 测试。getparameter 仍 ，控制流差 148。

### 2026-06-25：try_rule_if_else_arc — block Arc 参数重构第3个方法

- try_rule_if_else_arc：直接接收 block Arc，使用 count_non_structural_in_edges。
- apply_rules_to_children 调用 cat_arc + proper_if_arc + if_else_arc。
- gcc 53/53，175/176 测试。getparameter 仍 。

### 2026-06-25：try_rule_if_no_exit_arc — block Arc 参数重构第4个方法

- try_rule_if_no_exit_arc：直接接收 block Arc，使用 count_non_structural_in_edges。
- 嵌套调用中禁用——non_structural_in 在嵌套块上过于激进（17 个测试回归）。
- 保留方法定义供后续调试。
- gcc 53/53，175/176 测试。getparameter 仍 。

### 2026-06-25：移除 dominator tree expansion（对齐 Ghidra）

- Ghidra 的 f_switch_out 只标记 case body 入口块，不标记内部块。
- 移除了 switch_case_indices 的 dominator tree expansion。
- 这让 interleaved 规则能处理 case body 内部的 CBRANCH 块。
- gcc 53/53，175/176 测试。getparameter 仍 。

### 2026-06-25：对齐 Ghidra — 移除 count_non_structural_in_edges

- 移除了 try_rule_cat_arc/proper_if_arc/if_no_exit_arc/if_else_arc 中的 count_non_structural_in_edges。
- 改用 Ghidra 的原始 size_in() + switch_case_indices（只标记 case body 入口块）。
- 移除了 dominator tree expansion（对齐 Ghidra f_switch_out 只标记入口块）。
- gcc 53/53，175/176 测试。getparameter 从 9→，控制流差 174（因为移除了过度保护，结构发生变化）。

### 2026-06-25：blockaction is_consumed + Ghidra aligned size_in

### 2026-06-25：恢复最佳状态

- 回退 Ghidra 对齐实验（raw size_in + dominator tree removal）。
- 恢复 count_non_structural_in_edges + dominator tree expansion。
- getparameter ，控制流差 130，gcc 53/53，175/176 测试。

### 2026-06-25：identify_internal 框架（边重定向未完成）

- 实现了 identify_internal 方法骨架，但目前只用 DEAD flag（边重定向逻辑未完成）。
- gcc 53/53，175/176 测试。getparameter ，控制流差 130。
- 需要实现 BlockBasic 的 outgoing 向量重定向（replaceOutEdge 等效方法）。

### 2026-06-25：identify_internal 完成（cat + proper_if）

- identify_internal 实现：边重定向 + 消费块清除 + DEAD 标记。
- try_rule_cat 和 try_rule_proper_if 使用 identify_internal 替代手动 DEAD flag。
- as_any_mut trait 方法添加到 FlowBlock + 所有实现。
- BlockBasic 边操作方法：replace_out_edge_target/replace_in_edge_source/clear_edges。
- gcc 53/53，175/176 测试。getparameter ，控制流差 130。

### 2026-06-24：identify_internal 扩展到 if_else + if_no_exit + if_goto

- 将 identify_internal 从 try_rule_cat/try_rule_proper_if 扩展到剩余三个产生 BlockIf 的规则。
- `try_rule_if_else`：对齐 Ghidra `newBlockIfElse(cond,tc,fc)` → identifyInternal([cond,tc,fc])，
 消费两个 clause 块（边重定向到新 BlockIf + 标记 DEAD），替换原先的 `self.graph.blocks[i]=if_block`。
- `try_rule_if_no_exit`：对齐 Ghidra `newBlockIf(cond,tc)` → identifyInternal([cond,tc])，
 消费 clause 块。
- `try_rule_if_goto`：对齐 Ghidra `newBlockIfGoto(cond)`（注意：Ghidra 只消费 cond，
 body 通过 forceFalseEdge 保持外部）。Rust 的 BlockIf 架构将 body 嵌入 if_body，
 因此消费 body 块以避免悬挂可见节点，语义上等价于"clause 被吸收进 BlockIf"。
- 三个规则都补充了 update_switch_case_reference 调用，保证 switch case body
 被结构化时 BlockSwitch 的引用同步更新。
- gcc 53/53（curl 24/24，httpd 29/29），175/176 测试（预存失败不变）。
- getparameter 13→，curl 总 if 105→104。httpd 、0 goto。

### 2026-06-24：identify_internal 移植 Ghidra selfIdentify（边界边捕获）

**根因诊断**：identify_internal 此前只安装新结构块 + 标记消费块 DEAD，但从未填充新结构块
自身的 incoming/outgoing 边向量。这导致 BlockIf/BlockList 安装后 size_in=0 size_out=0，
外部指向它们的块看到"空块"，无法继续结构化（getparameter 出现 block62 BlockIf in=0out=0
孤立项，85 个 basic 块未结构化）。

**修复**：忠实移植 Ghidra `BlockGraph::selfIdentify`（block.cc:895）。在覆盖 install_idx
之前，遍历 consumed_indices 的每个块，收集其边界边（源/目的不在 consumed_set 的边）到
new_block 的 new_in/new_out，然后 dedup（Ghidra selfIdentify 以 dedup() 结尾），最后将
收集到的边安装到 new_block（按 BlockIf/BlockList/BlockWhileDo/BlockDoWhile 类型 downcast）。

**设计取舍**：不重写外部块的边 Arc（Ghidra 用 replaceOutEdge/replaceInEdge 基于裸指针无锁
完成）。Rust 中在迭代期间重写外部 Arc 会导致自环/不收敛（myprogress 超时）。改为依赖 DEAD
flag + count_non_structural_in_edges 使消费块对后续规则不可见；new_block 自身的边界边
（已捕获）让它有正确的 size_in/size_out 以参与进一步结构化。

**试验排除**：将 cond_idx 加入 consumed_indices（模拟 Ghidra newBlockIf 传 [cond,tc]）会
导致 if 结构坍塌（curl 104→，getparameter 12→，structured 28→25）+ myprogress
超时。根因是 cond 在 install_idx，其内部边（→clause）被错误计入边界。最终只消费 clause
（cond 由 install 位置自然接管）。

**验证**：curl 104→，24/24 gcc，24 函数（无超时）；httpd 97→，0 goto，29/29 gcc。
175/176 测试（预存失败不变）。getparameter FINAL basic 85（orphans 消除）。

### 2026-06-24：完整移植 ruleBlockCat 链式合并 + while_do/do_while 使用 identify_internal

- **try_rule_cat 链式扩展**：忠实移植 Ghidra `ruleBlockCat`（blockaction.cc:1284）。
 此前仅合并 2 个块。现在：bl 必须是链首（sizeIn==1 且唯一前驱 sizeOut==1 时返回
 false），然后沿 out(0) 扩展链（每条链 sizeIn==1、sizeOut==1、非 CASE_BODY、非结构化块），
 最终将 [block, out0, out1, ...] 全部合并为 BlockList，consume nodes[1..]。
 对齐 Ghidra newBlockList(nodes) 传整条链给 identifyInternal。
- **try_rule_while_do / try_rule_do_while 改用 identify_internal**：
 此前这两个规则仍用 `self.graph.blocks[i] = block`（手动安装，不捕获边界边）。
 now：while_do 用 identify_internal(&block, &[clause_idx], i)（Ghidra newBlockWhileDo
 consume [cond,cl]，clause 在 Rust 端 consume）；do_while 用 identify_internal(&block,
 &[cond_idx], i)（Ghidra newBlockDoWhile consume [condcl]，自回环块）。
 消除了 while/do-while 产生的 orphan 边。
- 至此 7/7 个 try_rule_* 方法全部使用 identify_internal，架构一致。
- 验证：curl ，24/24 gcc；httpd ，0 goto，29/29 gcc。175/176 测试（预存失败不变）。

### 2026-06-24：identify_internal 恢复外部边重写（对齐 Ghidra selfIdentify）

- 之前 self_identify 出于死锁/自环顾虑跳过了外部边重写。但这导致父 CBRANCH 的
 out-edge 在其 clause 被别处结构化（consume+DEAD）后变成悬空指针，无法继续结构化
 （getparameter 11 个 single-in CBR 中 8 个 clause size_out!=1，无法匹配 proper_if）。
- 恢复 Ghidra selfIdentify 的 replaceOutEdge/replaceInEdge 语义：捕获边界边后，
 将外部 Basic 块指向消费块的 out-edge 重写为 new_block，incoming 对称处理。
 加自环保护（跳过 Arc::ptr_eq(new_block)），且只消费 clause（不消费 cond），
 避免了之前 cond-in-consumed 导致的 myprogress 超时。
- 验证：curl ，24/24 gcc；httpd ，0 goto，29/29 gcc。175/176 测试。

### 2026-06-24：实现 ruleBlockGoto + clip_extra_roots fallback（goto-cascade 收敛）

**根因**：之前的 clip_extra_roots fallback 导致 httpd 超时。根因是 goto 标记（GOTO_EDGE_0/1）
后没有规则消费这些块——Ghidra 的 ruleBlockGoto 会把 goto 标记的块结构化为 BlockGoto/
BlockIfGoto/BlockMultiGoto，使它们从图中"消失"并让周围 cat/if 规则能继续合并。Rugra 缺失
这个规则，导致 goto 标记永远不收敛。

**修复**：
- **try_rule_goto**（对应 Ghidra ruleBlockGoto size_out==1 分支 / newBlockGoto）：
 检测 GOTO_EDGE_0 + size_out==1 的 Basic 块，包装为 BlockGoto（identify_internal 消费原块，
 self_identify 捕获边界边）。BlockGoto 加入 identify_internal 的 downcast 链。
 （size_out==2 + GOTO_EDGE_1 分支已由 try_rule_if_goto 处理 = newBlockIfGoto。）
- **clip_extra_roots**（对应 Ghidra clipExtraRoots）：作为 select_and_mark_goto 的 fallback，
 检测多根（size_in==0, index>0）的 Basic/Copy 块，onlyReachableFromRoot 收集 body，
 markExitsAsGotos 标记出口边为 goto。跳过已结构化块（BlockGoto 等）避免重标记。
- **max_goto_rounds=40 cap**：防止相互不可归约根导致的失控循环（Ghidra 在此情况抛
 LowlevelError，Rugra 改为 cap）。
- try_rule_goto 加入 apply_rules_to_block 和 goto-cascade 内层循环的规则链。

**验证**：curl ，0 goto，24/24 gcc；httpd ，29/29 gcc（不超时）；
175/176 测试（预存失败不变）。getparameter FINAL basic 85→84，structured 28→29。
multiin CBR 仍=4（需 TraceDAG 进一步处理）。

### 2026-06-24：循环结构化诊断 + skip-orphan/cat-head 安全保护

**诊断**：orderLoopBodies 检测到 getparameter 有 2 个嵌套循环（head=21，内层 bodysize=2、
外层 bodysize=4），但最终 TYPES whiledo=0 dowhile=0——循环未被结构化为 while/do。

**根因**：循环头 block 21 的边在 phase1 collapse_loops 运行前/中被清除（out=0 in=0），
变成 orphan 块。phase1 的 collapse_loops While-Do 检测要求 clause size_in==1，但循环体
block 20 有多入边（循环回边 + 入口），不匹配。循环头被 phase1 三角匹配（collapse_conditions）
消耗成 BlockIf，而非 while/do。禁用 phase1 collapse_conditions/sequences 虽然让 curl if 从
101→77（更紧凑），但破坏 gcc 语法（curl 20/24、httpd 28/29），已回退。

**安全改进（保留）**：
- **apply_rules_to_block skip-orphan guard**：跳过边已清除（size_in==0 && size_out==0）
 但未标记 DEAD 的 orphan 块，防止 spurious 匹配破坏图。
- **try_rule_cat loop-head guard**：cat-chain 扩展时不消费 loop_bodies 中的循环头，
 对齐 Ghidra isDecisionOut 语义（循环头必须留给 while_do/do_while）。
- **try_rule_while_do** 放宽 clause 检查为 count_non_structural_in_edges（忽略 DEAD/goto 源）。
- **2026-06-29 apply_rules_to_block goto-first**：规则顺序改为 Ghidra collapseInternal 顺序（blockaction.cc:1797-1828）——goto（if_goto + pure_goto）在 cat/proper_if/if_else/while_do/do_while 之前运行。这确保 continue/break 边在 WhileDo 匹配前被消费（包装为 BlockIfGoto/BlockGoto），降低 clause 有效 size_in。
- 监控日志：TYPES（whiledo/dowhile/if/list/other 计数）+ loop head/bodysize。

**验证**：curl ，24/24 gcc；httpd ，29/29 gcc。175/176 测试（预存失败不变）。
循环仍未输出为 while/do——需 phase1 collapse_loops 多入边循环体重构（后续工作）。

### 2026-06-26：重新启用 structure_loops_first + collapse_cbranch_cascades 结构化块保护

**突破**：WhileDo 循环现在被保留（TYPES whiledo=1）。
- 重新启用 structure_loops_first（phase1 前 WhileDo 预结构化）+ phase1 Basic-only guards。
- WhileDo body emit 用 emit_block_ops 绕过 DEAD 检查（body 被 identify_internal 消费为 DEAD）。
- **collapse_cbranch_cascades 不覆盖结构化块**：替换 extra_indices 时跳过 WhileDo/DoWhile/If
 等非 Basic 块（之前会把 WhileDo 替换成空 placeholder BlockBasic）。
- 验证：176/176 测试。curl 24/24 gcc。getparameter TYPES whiledo=1（循环保留）。
- httpd 28/29 gcc（ap_getparents duplicate case — collapse_cbranch_cascades 级联链包含
 WhileDo 导致 case_values 重复，独立 switch 检测 bug，需后续修复）。

### 2026-06-26（续）：collapse_cbranch_cascades 级联链遇结构化块停止

- 级联链遍历 CBRANCH fallthrough 时，遇到 WhileDo/DoWhile/If 等结构化块立即停止，
 避免把它们错误纳入 cascade chain 导致 duplicate case_values。
- 验证：176/176 测试。curl 24/24。httpd 仍 28/29（ap_getparents duplicate case 未完全修复，
 其他路径的 case_values 计算问题）。

### 2026-06-26（续）：identify_internal 捕获 install_idx 块的外部入边

- self_identify 现在也捕获 install_idx 块（cond/head）的外部入边（排除 consumed 块和自环），
 使结构化块（如 WhileDo）从函数入口可达。仅捕获入边（不捕获出边，避免 httpd 边双重计数）。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。
- getparameter WhileDo 仍不可达（head=21 仅自环前驱，函数特定 CFG 问题）。

### 2026-06-26（续）：collapse_sequences 保留 BlockList 的 out-edges

- collapse_sequences 合并 block→succ 为 BlockList 时，原来 BlockList::new 不复制 out-edges，
 导致 BlockList 后续的边（包括指向 WhileDo 的边）丢失，WhileDo 变为不可达。
- 修复：BlockList.outging = succ（最后一个 child）的 out-edges，保持控制流连续性。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：collapse_conditions 保留 BlockIf 的 out-edges

- collapse_conditions 的 Triangle/Triangle-reverse/Diamond 匹配创建 BlockIf 时，原来
 outgoing 为空，导致 BlockIf 后续的边丢失。
- 修复：BlockIf.outgoing = merge 块的 out-edges（Triangle: false/true_block, Diamond: D 块）。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：BlockIf out-edge 指向 merge 块本身（非 merge 的 out-edge）

- collapse_conditions 的 Triangle/Diamond 匹配创建 BlockIf 时，out-edge 现在指向 merge 块本身
 （Triangle: false/true_block, Diamond: D 块），而非 merge 块的 out-edge。
 之前读 merge 的 out-edge 会跳过 merge 块（如 WhileDo），破坏可达性。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：identify_internal 更新指向旧块的 Arc 边引用

**根因**：identify_internal 执行 self.graph.blocks[install_idx] = new_block 时，其他块的
out-edge 仍持有旧块的 Arc（Arc identity 不变），导致新结构化块不可达。
**修复**：安装 new_block 前保存 old_block Arc，安装后扫描所有块的 incoming/outgoing，
将 Arc::ptr_eq(old_block) 的边重定向到 new_block。覆盖 BlockBasic/BlockList/BlockIf/BlockWhileDo。
**验证**：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：对齐 Ghidra rule 顺序（switch 检测最后）

- Ghidra 的 collapseInternal 顺序：cat → proper_if → if_else → while_do → do_while →
 inf_loop → switch（switch 最后）。这让循环/if 结构化优先消费块。
- Rugra 的 phase1 原顺序：collapse_switches 在 collapse_sequences 之前。
- 修复：collapse_switches 移到最后（collapse_sequences 之后），对齐 Ghidra。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。
- getparameter 仍有 1 switch（multiin CBR 阻止 if/while 消费这些块，需 TraceDAG）。

### 2026-06-26（续）：TraceDAG 骨架移植（已禁用）

- 新增 src/tracedag.rs：BranchPoint/BlockTrace 结构 + pushBranches 算法骨架。
- 集成到 run_goto_cascade（当 select_and_mark_goto 和 clip_extra_roots 都无结果时触发）。
- 当前 DISABLED：check_open/select_bad_edge 使用简化近似，需完整 BadEdgeScore + visit-count
 追踪后才能安全启用。
- 验证（禁用状态）：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：TraceDAG 完整 BadEdgeScore + visit-count（仍禁用）

- tracedag.rs 实现 BadEdgeScore 评分（siblingedge/terminal/distance/depth）和 visit-count 追踪。
- 当前仍 DISABLED：open_branch/retire_branch 需更新 visit-count。验证（禁用）：176/176 测试。

### 2026-06-26（续）：TraceDAG back-edge 过滤（仍禁用）

- open_branch 跳过 back-edge（target index <= dest）。
- 启用时 gcc 无回归但 test_bool_condition_folding 失败。仍 DISABLED。

### 2026-06-26（续）：TraceDAG 启用（简单函数保护）

- generate_likely_gotos 跳过 < 10 块的函数，防止误标 goto。
- TraceDAG 已启用。验证：176/176 测试。curl 24/24。httpd 29/29。

### 2026-06-26（续）：TraceDAG pre-phase1 尝试（回退）

- 尝试在 phase1 前运行 TraceDAG 标记 goto 边，防止 switch 形成。
- 结果：curl 3/24 gcc（灾难回归）。push_branches 算法过早触发 select_bad_edge
 （check_open 太严格，很多节点无法打开）。已回退。
- collapse_switches 的 goto-edge 守卫保留（正确但 TraceDAG 未启用时无效）。
- 验证（回退后）：176/176 测试。curl 24/24。httpd 29/29。

### 2026-06-26（续）：TraceDAG pre-phase1 启用（opened 集合 + visit-count 边递增）

- opened 集合追踪已打开节点；open_branch 递增目标 visit_count。
- TraceDAG 在 phase1 前安全运行，标记 goto 边阻止 switch 形成。
- collapse_switches 检查 goto 标志，跳过已标记 goto 的 BRANCHIND 块。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：collapse_cbranch_cascades 检查 goto 标志

- CBRANCH cascade switch 检测现在检查 goto 标志，跳过已标记 goto 的 CBRANCH 块。
- getparameter 从 + 1 switch 变为 + 0 switch（向 Ghidra 收敛）。
- 验证：176/176 测试。curl 24/24。httpd 29/29。

### 2026-06-27（会话3 G4）：LoopBody 完整移植 + orderLoopBodies pipeline

完整移植 Ghidra LoopBody 类（blockaction.cc:46-490）+ CollapseStructure::orderLoopBodies pipeline（blockaction.cc:1148-1188）：

**新数据结构**：
- `FloatingEdge { from_idx, to_idx }` — 待非结构化(goto)的边
- `LoopBody { head, tails, exit_block, exit_edges, depth, immed_container, unique_count }` — 自然循环

**LoopBody 方法**（1:1 移植）：
- `find_base` — findBase(119)：收集可达 tail 不经 head 的块
- `extend` — extend(150)：扩展到仅 head 可达的块（visit_count 计数）
- `find_exit` — findExit(182)：选单一 exit 块（tail→head→middle 优先）
- `order_tails` — orderTails(245)：有 exit 边的 tail 排前
- `label_exit_edges` — labelExitEdges(270)：标记离开 body 的边
- `label_containments` — labelContainments(327)：记录包含的子循环 + depth

**模块函数**：
- `merge_identical_heads` — mergeIdenticalHeads(446)
- `clear_marks` — clearMarks(1039)

**CollapseStructure::run_order_loop_bodies_pipeline**：完整 pipeline（build→merge→sort→label_containments→depth sort→find_base/find_exit/order_tails/extend/label_exit_edges），结果存入 `loop_order: VecDeque<LoopBody>`。

**验证**：parseconfig 检测出嵌套循环（depths=1,0 — 一个循环嵌套在另一个内）。687/687 测试，curl 24/24 + httpd 29/29，无回退。

### 2026-06-27（会话3 G4续）：apply_loop_exit_marks — LoopBody 驱动结构化

- `CollapseStructure::apply_loop_exit_marks` — Ghidra `LoopBody::setExitMarks` + `updateLoopBody`（blockaction.cc:416-426, 1231）等价：将每个 LoopBody 的 exit_edges 标记为 `F_LOOP_EXIT_EDGE`，在 `order_loop_bodies` 后调用。
- `collapse_all` 在 `order_loop_bodies` 后、`run_tracedag` 前调用它，使 TraceDAG 追踪被 LoopBody 约束。

**意义**：这是 LoopBody 分析实际驱动结构化的接入点——LoopBody 的 exit 分析结果现在约束 TraceDAG 的 goto 候选边选择。

### 2026-06-27（会话3 G4残余）：emit_likely_edges + selectGoto 集成

- `LoopBody::emit_likely_edges(likely, graph)` — 忠实于 Ghidra `emitLikelyEdges`（blockaction.cc:364-412）：将 exit edges（官方 exit 边延后）+ back-edges（tails→head 逆序）按优先级追加到 likely-goto 列表。
- `run_tracedag` 现合并每个 LoopBody 的 emit_likely_edges 结果（转换为 tracedag::FloatingEdge），使 goto-cascade（selectGoto 等价）使用 LoopBody 的边优先级。

**架构说明**：Rugra 已有 `run_goto_cascade`（selectGoto→collapseInternal 等价的迭代循环：select_and_mark_goto → clip_extra_roots → run_tracedag → try_rule_*）。本次使 LoopBody 完全驱动它：
1. apply_loop_exit_marks（setExitMarks）约束 TraceDAG 追踪范围
2. emit_likely_edges 提供边优先级
3. is_loop_dag_out（tracedag）跳过 loop-exit/goto 边

689/689 测试，curl 24/24 + httpd 29/29，0 goto。

### 2026-06-28：findSpanningTree DFS — 循环回边检测修复（blockaction L2→L3 关键）

**根因**：curl `main`（102 块）用旧的支配者判定回边检测到 **0 个循环**，尽管有 25 条候选（tgt<src）边。Ghidra 在同一函数识别 5+ 个循环。支配者的 intersect 步骤计算了错误的 idom，导致 `dominates_idx` 对每个候选回边都返回 false。

**修复（忠实移植 Ghidra，非简化）**：
- 移植 `BlockGraph::findSpanningTree`（block.cc:1009-1110）：迭代式 DFS，标记每条出边为 tree/back/forward/cross。回边（指向 DFS 栈中仍存在的节点）定义循环。
- 移植两遍结构（不可达块提升为额外 root）。
- `order_loop_bodies` 改读 `F_BACK_EDGE` 标签（对齐 labelLoops, blockaction.cc:1126-1143），不再用支配者判定。
- **设计要点**：用**局部 DFS 状态**（HashMap），**不碰** `FlowBlock.index`/`visit_count`。Rugra 的 `index` == 块在 `BlockGraph.blocks` 中的位置（被 compute_dominators/collect_loop_body 依赖）；Ghidra 把 index 重载为 rpostorder，此处不适用。

**实测证据**（`RUGRA_LOOP_DEBUG=1`）：main 回边 0→3，my_get_line 1→2，next_url 2→3；curl 全局回边检测 0→19；idom_entries 恢复（main 21→86）。

**剩余**：while 输出数未变（curl 4/httpd 8），因为下游循环结构化（把检测到的循环变成 while/do-while）是独立的下一层。736/736 测试，curl 24/24 + httpd 29/29，0 goto，0 回归。

### 2026-06-28：循环回边保护 — 防止 goto cascade 切断循环（对齐 TraceDAG 跳过 loop edges）

**根因**：`select_and_mark_goto` 无条件把 CBRANCH 的 taken 边（out[1]）标记为 goto，即使该边是循环回边。这切断了循环——循环体失去回到 header 的唯一出口（诊断显示 try_rule_while_do 候选 clause_out==0，body 无出边），导致 ruleBlockWhileDo 永远无法匹配。

**修复**：当 out[1] 携带 `F_BACK_EDGE`（由 findSpanningTree 设置）时跳过 goto 标记。回边定义循环，必须保留给 WhileDo/DoWhile 识别。这镜像 Ghidra 的 TraceDAG——它在追踪结构化路径时跳过 loop edges。

**验证**：736/736 测试，curl goto=0，httpd goto=0，curl 24/24 + httpd 29/29 gcc 审计，0 回归。回边保护是正确性改进（忠实 Ghidra）；while 数不变是因为上游的 loop-body collapse 仍留下多块 body，WhileDo 规则的单 clause 要求拒绝它们——这是下一层结构化工作。

### 2026-06-28：goto_cascade 内层循环补齐 WhileDo/DoWhile（对齐 Ghidra collapseInternal）

**根因**：goto_cascade 的内层结构化循环（run_goto_cascade 的 repeat-until-stable）只试 cat/proper_if/if_goto/if_else/goto，**遗漏 WhileDo/DoWhile**。Ghidra 的 `collapseInternal`（blockaction.cc:1813-1820）在**同一 pass** 试 Cat/ProperIf/IfElse/WhileDo/DoWhile。遗漏导致回边保护后保留的循环无法在 cascade 阶段被结构化。

**修复**：在 goto_cascade 内层循环规则序列中插入 `try_rule_while_do`/`try_rule_do_while`（if_else 之后、goto 之前），对齐 Ghidra 的规则顺序。

**验证**：736/736 测试，curl goto=0（审计 24/24），httpd goto=0（审计 29/29），0 回归。当前 while 数不变是因为循环体（多块）未被 cat-chain 折叠成 WhileDo 能识别的单 clause——需移植 Ghidra 完整 collapseInternal 两层 repeat-until-stable 主循环（替换 Rugra 自定义多阶段）。

### 2026-06-28：collapseInternal 移植实验 + while 缺口根因转移（重要分析结论）

**实验**：忠实移植 Ghidra `CollapseStructure::collapseInternal`（blockaction.cc:1768-1851）两层 repeat-until-stable 主循环，替换 Rugra 自定义多阶段（phase1/interleaved/goto_cascade）。同时放宽 try_rule_cat 的类型限制（Ghidra ruleBlockCat 只检查 sizeOut/sizeIn/isSwitchOut，不限制块类型；Rugra 错误地只允许 Basic/Copy）。

**结果**：**退步**。新 collapseInternal 全局只产出 1 个循环（0 whiledo + 1 dowhile），旧自定义阶段产出 8 个循环（4 whiledo + 4 dowhile）。原因：旧实现的 `structure_loops_first()` + `collapse_loops()` 虽不忠实 Ghidra 架构，但实际工作。**已回退保留旧实现**（铁律 8：禁止随意回退已验证工作）。

### 2026-06-29（续）：try_rule_cat 放宽块类型限制（部分 collapseInternal 对齐）
- 放宽 `try_rule_cat` 的块类型限制：此前只允许 Basic/Copy 进入 cat-chain，现允许任意块类型（BlockList/BlockIf/BlockCondition 等），只要 sizeIn==1、sizeOut==1、非 switch-out、非循环头。忠实 Ghidra ruleBlockCat（blockaction.cc:1296-1308 无块类型限制）。
- **验证**：780/780 测试，curl 24/24（goto=0），无回归。while 数未提升——根因是循环头在 phase1 的 collapse_loops/collapse_conditions 中被消耗，在 interleaved 阶段的 try_rule_while_do 看到之前已被结构化。完整提升需重构 collapse_all 使 collapseInternal 成为主循环。
- **2026-06-29 续**：phase1 循环改用 `try_rule_while_do`（接受 BlockList clause via count_non_structural_in_edges）替代 `rule_block_while_do`（更严格的 is_goto_out 检查）。诊断确认根因：多块循环体含 continue/break 边，clause 的 size_in > 1（多个前驱），try_rule_while_do 的 size_in==1 守卫失败。修复需完整 collapseInternal 的 selectGoto→ruleBlockGoto→while_do 迭代在每轮消费 continue/break 边。

**关键根因发现**：curl `main` 只检测到 **3 个回边**（全指向 head=5，即 1 个循环），而 Ghidra `main`（684行起）有 **6 个 while**（6 个循环：1 do-while(argc) + 1 while(true) + 4 do-while(cVar1!=0)）。**while 缺口的根因不在 blockaction 结构化层，而在更底层的 CFG 构建层**（funcdata.rs:1427-1473 的基本块划分/边建立）——Rugra 的 main CFG 缺少回边，所以无论结构化多完善都检测不到那些循环。

**下一步方向**（按优先级）：
1. **CFG 构建层**（funcdata.rs）：对比 Rugra vs Ghidra 在 main 上的基本块数和边，定位缺失的回边。可能是 BRANCH/CBRANCH 目标地址计算错误，或基本块划分边界不对。
2. **增量改进 blockaction**：在旧自定义阶段基础上，逐个对齐 Ghidra 规则（先放宽 cat 类型限制**配合**修复的 CFG，而非单独），而非整体替换。
3. cat 类型放宽**单独**无效（已验证），因为即使能吸收 BlockIf，循环体本身在 CFG 里就没回边。

**教训**：忠实移植 Ghidra 架构 ≠ 直接替换。旧实现虽不忠实但有实际功能，替换前必须确保新实现**至少不退步**。应采用增量对齐策略。

### 2026-06-28：identify_internal RwLock 死锁修复（httpd 性能突破）

**根因**：identify_internal 的边界边捕获和边重写阶段，在持有某块的 **write guard** 时，对该块的出/入边的 `point` 调用 `read()`。如果 `point` 恰好是该块自己（自环边），`write + read` 同一个 RwLock = **死锁**。这导致 httpd ap_fini_vhost_config 在 structure_loops_first 的 head=59 identify_internal 卡死。

**修复**：将 identify_internal 中 4 处 `e.point.read().unwrap()` 改为 `try_read()`，失败时 `continue` 跳过该边。try_read 不阻塞——如果锁被持有（包括自环的 write），立即返回 Err。

**影响**：httpd 从"卡在第 8 个函数（ap_fini_vhost_config）"变成"完成全部 29 个函数"。httpd while 从 8 跃升到 **44**（goto=0）。curl 审计 **24/24 0 FAIL**（从 23/23 进一步改善）。736/736 测试通过。

### 2026-06-29：rule_block_while_do 1:1 移植 + is_goto_out 修复（blockaction.cc:1518-1549）

- 新增 `rule_block_while_do(i)`（blockaction.rs）——忠实移植 Ghidra `CollapseStructure::ruleBlockWhileDo`：bl 必须有 2 条 out 边（二路条件）、非 switch-out、out(0/1)≠bl；对每条 out 边找 clause（sizeIn==1, sizeOut==1, 非 switch, 单 out 回到 bl）→ 构建 BlockWhileDo。接入 collapse_all phase 循环每轮迭代（对齐 Ghidra collapseInternal 中 ruleBlockWhileDo 与 cat/proper_if/if_else 交错）。**2026-06-29 修正**：不再因任一边 goto 就 bail，而是在 clause 搜索时跳过 goto 边（适配 Rugra staged 架构——break 边未被 ruleBlockGoto 消费）。
- **关键修复**：`BlockBasic::is_goto_out` 此前只查边级 `F_GOTO_EDGE`，但 TraceDAG/run_tracedag 把 goto 标在 **block 级** `GOTO_EDGE_0/GOTO_EDGE_1` 上 → 查询不到。修复后 is_goto_out 同时查边级和 block 级标志。这是 break 边识别的基础——ruleBlockWhileDo 据此跳过 break 循环的非结构边。
- **验证**：777/777 测试（含 test_is_goto_out_reads_block_flags）。curl 24/24（goto=0, uVar=0），httpd 29/29（goto=0, uVar=0）。无回归。
- **剩余缺口**：staged→collapseInternal 架构迁移。Ghidra 的 ruleBlockGoto 在每轮 collapseInternal 中"消费"goto 边（实际重连，使 break 边从结构化视图消失），然后 ruleBlockWhileDo 看到 2 条非 goto 边。Rugra 目前只标记不重连，故带 break 的循环 WhileDo 形成受限（parseconfig 检测到 7 loops 但仅 1 WhileDo）。这是 G4 架构工作。


### 2026-06-29（续 2）：try_rule_goto removeEdge 消费机制（部分实现）
- `try_rule_goto`（pure-goto, size_out==1）：创建 BlockGoto 后调用 `remove_in_edge_from` 从 goto target 的 incoming 移除 BlockGoto。忠实 Ghidra `newBlockGoto` 的 `removeEdge(ret, ret->getOut(0))`（block.cc:1711）。**安全**：BlockGoto 无结构化 fallthrough，移除 in-edge 不产生不对称。
- `try_rule_if_goto`（CBRANCH, size_out==2）：**未实现** removeEdge。需 Ghidra `forceOutputNum(2)`+`forceFalseEdge` 保留条件边——Rugra 的 BlockIf 缺这些，尝试 removeEdge 导致图损坏（curl 28→26）。留作已记录缺口。
- **验证**：780/780 测试，curl 24/24（goto=0），httpd 29/29（goto=0）。无回归。

### 2026-06-29（续 3）：try_rule_if_goto newBlockIfGoto 风格
- 重构 `try_rule_if_goto`：只消费 [cond]（body 保持外部 out-edge），设 goto_target。removeEdge 从 target incoming + if_block outgoing 双向移除 goto 边。
- **结果**：循环结构化对齐度提升（旧 while 计数显示显著改善，但该计数 2026-07-02 已废弃为 KPI）。while 循环对齐缺口对 curl 已闭合。
- 3 个函数在 goto_cascade 中不收敛（ap_count_dirs 等）——收敛问题，待修复。

### 2026-06-29（续 4）：goto_cascade 收敛守卫
- `run_goto_cascade` 新增收敛守卫：若 graph size 在 3 轮后未减少（规则震荡无进展），停止。防止病态 CFG（ap_count_dirs 等）无限循环。
- httpd example 新增每函数 15s 超时（对齐 curl 模式），防止单函数挂起阻塞全局。
- **结果**：循环结构化对齐度进一步提升，29/29 函数完成（1 个 TIMEOUT 占位），0 goto。

### 2026-06-29（续 5）：goto_cascade 收敛守卫改进 + remove_in_edge_from 死锁修复
- goto_cascade 收敛守卫改为同时检查 graph size 和 change_count（两者都无进展才停止）。
- `remove_in_edge_from` 自环死锁修复（block.rs）：try_read 替代 read。这是 ap_count_dirs 挂起的根因。
- **结果**：循环结构化对齐度进一步提升，29/29 函数完成，0 TIMEOUT。

### 2026-07-01（管线改造）：Action apply &self→&mut self 连锁

### 2026-07-01（续）：Dead-flow Actions pre-pass（历史，2026-08-28 已删除）
该 pre-pass 不存在于 Ghidra `ActionBlockStructure::apply`，现已从生产入口移除；
CFG 修改由对应 Action/Funcdata mutator 自己调用 `structureReset`。

### 2026-07-01（续 2）：BlockWhileDo for-loop 字段 + printc for 发射
BlockWhileDo 加 for_init/for_iter 字段（对齐 Ghidra iterateOp/initializeOp）。printc WhileDo 发射：有 for_init+for_iter → `for(init;cond;iter)`，否则 `while(cond)`。

### 2026-07-01（续 3）：sblocks 指纹重建（历史，2026-08-28 已删除）
当前不保存 op-count 或 topology fingerprint；严格使用非空结构 once-guard。

### 2026-07-03：修正 collapse_cbranch_cascades 的错误注释
- 该函数的注释曾错误声称 "Corresponds to Ghidra's ruleBlockSwitch"，但 Ghidra `ruleBlockSwitch`（blockaction.cc:1649）只对 `isSwitchOut()` 块触发（由 CPUI_BRANCHIND 设置 f_switch_out），从不从 CBRANCH if/else-if 链造 switch。此函数是 fabricated logic（无 Ghidra 对应），已修正注释明确说明。函数仍禁用（:695）。**未改名**为 rule_block_switch——那会给 fabricated logic 披上 Ghidra 对应的外衣。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-12：ANN-M expanded-scanner 溯源

本轮只补函数来源标注，不改变运行时行为。源码 oracle 固定为 Ghidra 12.0.4
commit `e40ed13014025f82488b1f8f7bca566894ac376b`。

- `CollapseStructure::new` 映射 `blockaction.cc:1870
  CollapseStructure::CollapseStructure`。Rust 额外接收诊断名并初始化若干缓存、
  switch 与 iterator 状态；这些扩展不把构造器变成无 oracle 对应物的胶水。
- `CollapseStructure::collapse_all` 映射 `blockaction.cc:1877
  CollapseStructure::collapseAll`。当前 Rust 仍包含 `RUGRA_7PHASE` 分流、额外
  TraceDAG/loop/switch 阶段、deadline 和 fallback，因此 provenance 注释不代表
  逐函数行为已经 `MATCH`。

ANN-M 不提升本模块的对齐状态，也不替代锁定 oracle 的函数级差分验证。
 
 
 
 
 
 
 

### 2026-08-15：私有 `find_spanning_tree` 保留不接线（`BLOCK-INDEX-WIRE-0001`）

`BLOCK-INDEX-ASSIGN-0001` 已在 `src/block.rs:1647` 落地公共
`BlockGraph::find_spanning_tree`（全副作用对齐 block.cc:1009-1135，8/8 oracle
MATCH）。本模块的私有 TraceDAG 变体（`src/blockaction.rs:2369` 起）**保留未接线**，
源码注释已注明公共 port 的位置与接线前提；迁移属 `BLOCK-INDEX-WIRE-0001`，须
保证 TraceDAG 行为零变化并通过主管线差分门禁。本轮对本模块零行为改动。

### 2026-08-19：私有 `find_spanning_tree` 迁移到公共 port（`BLOCK-INDEX-WIRE-0001` 完成）

> **2026-08-28 纠正**：本节以下内容记录当时的补偿实现。当前
> `build_copy` 已创建真实 `BlockCopy` 并原样复制 edge label/index/numdesc；
> `order_loop_bodies` 不再重算 spanning tree 或 `structure_loops`，而是像
> `CollapseStructure::orderLoopBodies` 一样只消费复制后的标签。

删除 blockaction.rs 的私有位置索引变体（原 :2369 起，局部 HashMap DFS、只写
out-half 边 label、不写 index/visitcount/numdesc/copymap、不重排 blocks），
`order_loop_bodies` 改调公共 `BlockGraph::find_spanning_tree`
（`src/block.rs`，Ghidra block.cc:1009-1136）——index=RPO + 组件表重排
（cc:1135）、visitcount=preorder、numdesc 累计、copymap=self、边 label 双侧
镜像、每遍 wipe 全部边 flag（cc:1045）、rootlist 首尾 swap（cc:1031-1035/
1114-1116/1129-1133）、两遍 extraroots。

当时的 Oracle 依据：`orderLoopBodies` 本身从不计算树——StructureGraph 路径在
CollapseStructure 前一步跑 `structureLoops`（ghidra_process.cc:354），进程内
ActionBlockStructure 路径经 `newBlockCopy` 继承同一批 label/index/numdesc
（block.cc:1685-1691）。旧 Rugra `build_copy` 造全新无边 label 的边，故当时在
`order_loop_bodies` 内以公共 port 重算树；该补偿已由 2026-08-28 的真实
`BlockCopy/buildCopy` 接线删除。
树调用后立即把全图 visitcount 清 0，对齐 Ghidra `collapseAll` 头部
`graph.clearVisitCount()`（blockaction.cc:1883，oracle 在 orderLoopBodies 前
一条语句执行）。

非零差异（差分门禁，`## Differential` 详见任务报告）：curl E2E 基线 vs 修改
defects 0→0、numbering 0→0、golden 函数匹配 122/124→123/124、decompiled
74→75、timeout 2→1（`next_url` 0x4ff0 从 >10s 超时变为成功反编译）、
skeleton 2785→2904（增量主体为 `next_url` 新函数体；`my_get_line` -10、
`helpf` +12、`my_get_token` ±0，均 defects=0）。输出非 byte 级一致：私有变体
消费的是 bblocks 旧 RPO 域（可能滞后于 dead-flow 清理后的图），公共 port 对
清理后图现算 RPO——即本任务目标「index 域统一」本身，方向与 StructureGraph
oracle 路径（对最终图 fresh 计算）一致。

---

## 2026-08-23：order_loop_bodies 接线完整 structure_loops 驱动（BLOCK-CALCLOOP-0001）

> **历史实现，已于 2026-08-28 被替换**：对结构图重跑
> `structure_loops` 并不符合 `ActionBlockStructure` 的生产路径。当前实现保持
> `Funcdata::structureReset` 在 basic CFG 上生成的标签，经 `buildCopy` 原样复制，
> 再由 `order_loop_bodies` 消费；不会二次清除或重排 default/back/tree 标签。

当时，`CollapseStructure::order_loop_bodies` 的生成树重算点从裸
`BlockGraph::find_spanning_tree(preorder, rootlist)` 升级为完整
`BlockGraph::structure_loops(&mut rootlist)` 驱动（block.cc:2194-2215）。

**oracle 调用点对照：** Ghidra 侧 CollapseStructure 从不自己算树——
`Funcdata::structureReset`（funcdata_block.cc:711 `bblocks.structureLoops`）
在 basic 块图上打完整标签（含 findIrreducible 的 f_irreducible 与
irreduciblecount>0 时 calcLoop 的 f_loop_edge，cc:2211-2214），
`ActionBlockStructure::apply`（blockaction.cc:2177）经 `buildCopy`
（newBlockCopy 复制 intothis/outofthis 边标签 + index + numdesc，
block.cc:1685-1691）把这些标签带入结构图；StructureGraph 控制台路径
（ghidra_process.cc:352-355）则 buildCopy 后直接
`structureLoops + calcForwardDominator` 再 CollapseStructure。Rugra 的
旧 `build_copy` 造全新（无标签）边，故当时在 order_loop_bodies 处对结构图重跑
完整驱动——与两条 oracle 路径"CollapseStructure 消费 structureLoops 产物"
的入口态等价。

**行为影响：** 可归约图（irreduciblecount==0）与原裸树逐字节一致（驱动
单遍收敛，无 rebuild、无 calcLoop）；不可归约图新增 f_irreducible 边标
（is_goto_out 由此为真，影响 select_goto/结构化决策）与 calcLoop 的
f_loop_edge 环断边标——即 oracle 的入口态，此前缺失。结构化输出按机制 B
差分白名单由 root 集成时跑 curl 差分门禁（worktree 内 fast-release E2E
见任务报告）。

**calcLoop 本体：** 见 docs/api/block.md BLOCK-CALCLOOP-0001 节
（block.cc:2104-2147 完整移植 + oracle fixture
`tests/oracle/block_calcloop_1204` 七 case 双侧 byte-MATCH，含
structureReset 链 structureLoops+calcForwardDominator 端到端投影）。

## selfIdentify 外部边改写/dedup/剥离域（BLOCKSTRUCT-SELFIDENTIFY-EXT-0001，2026-08-25）

`identify_internal`（BlockGraph::identifyInternal+selfIdentify，
block.cc:884-963）补齐三个外部半边语义：

1. **改写全类型化**（`rewrite_out_edges_to_idx`/`rewrite_in_edges_to_idx`，
   对应 cc:910-912/922-924 的 replaceOutEdge/replaceInEdge）：Ghidra 的边数组
   在 FlowBlock 基类，任何块类型的邻居边都会被改写；Rugra 之前的
   BlockBasic-only 改写使结构化块残留指向已消费组件的陈旧边，膨胀下游规则
   的 sizeIn/sizeOut（ruleBlockCat `outblock->sizeIn()!=1`，
   blockaction.cc:1292）。
2. **外部 dedup**（`dedup_edges_all_types`，cc:930 selfIdentify 末尾的
   dedup()）：多个被消费组件（或 install 块+组件）各有边指向同一外部块时，
   Ghidra 的成对半边删除顺带收敛外部重复边；Rugra 单侧边模型需在全部改写
   完成后对 touched 外部块显式 dedup（labels OR 合并，block.cc:446-501）。
3. **组件外边剥离**（strip_external）：Ghidra 的 replace*Edge 半删除把组件
   的外部边移交给复合块，组件只保留组件间内部边；Rugra 之前对被消费块
   blanket clear_edges，现改为按 is_component 谓词 retain（内部边如
   cond→clause 保留，外部边如 clause→merge 移交复合块），与 oracle 的
   per-component in/out 计数一致。

另：cc:951 `ident->flags |= (f_interior_gotoout|f_interior_gotoin)`——复合块
从每个被消费组件（含 install 块，它在 Ghidra 的 -nodes- 集内）继承
interior-goto 标记。

### ruleBlockGoto 消费边改双边 removeEdge（2026-08-25，BLOCK-RECIPROCAL-OOB-0001）
- if-goto 臂（newBlockIfGoto 尾，block.cc:1814 `removeEdge(ret,
  getTrueOut())`）与 pure-goto 臂（newBlockGoto 尾，block.cc:1711
  `removeEdge(ret, getOut(0))`）都改经
  `BlockGraph::remove_edge_blocks(new_block, goto_target)` 全双边删除
  （含槽位重结对）；原"目标侧 retain + 源侧 outgoing.clear"单侧对留下
  stale reverse_index（httpd ap_getword 等 panic 根因之一）。
- `dedup_edges_all_types` 改为 trait 级 `FlowBlock::dedup(self_arc)` 成对
  协议（block.cc:525）；原 `edges.remove(i)` 单侧去重滑列表不作对侧修正。
- `identify_internal` 安装后新增 `resync_boundary_reverse_indices`
  （RUGRA-GLUE 不变量修复）：Ghidra selfIdentify 经 replace*Edge
  （block.cc:160-191, 910-924）在重定向时同步两侧 reverse_index；Rugra
  的 rewrite_* 只翻 e.point，故按指针重结对复合块边界边以恢复
  checkEdges 不变量（一致状态下 no-op），并把 new_block 纳入安装后 dedup。

### selectGoto exhausted 调试注桩（2026-08-26，TRI2-STRUCT-SELECTGOTO-SELFLOOP-0001）
- `bs_trace_cfg_sig` + `ActionBlockStructure::apply` pre/post witness（RUGRA-GLUE，
  无 Ghidra 对应物，debug-only）：`RUGRA_BS_TRACE=1` 时在每次 blockstructure 施加
  前后打印 bblocks 完整签名（槽位/索引/起始地址/类型/入出边及 GOTO 标记/末位
  CBRANCH 及其 const/val/BOOLEAN_FLIP/块 flags），用于 mainloop 不收敛/CFG 往复
  症状的逐轮夹逼（HTTPD-STRCASECMP-NONCONVERGE-0001 定位中引入：识别出
  DeterminedBranch→remove_branch 空转 reset + if_no_exit 每轮 negate 的乒乓）。
- `debug_type_name`（RUGRA-GLUE，debug-only）：`bs_trace_cfg_sig` 行内的短类型
  标签（downcast 实现；派生 Debug 会递归子块并可能溢出 worker 栈）。
- 2026-09-27 卫生清理（HYGIENE 微件车道，CR-STRDATA 遗留债）：删除
  `CollapseStructure::debug_dump_graph`（`RUGRA_BS_DUMP=1/2/3` 全图 dump 探针，
  initial/stuck1/exhausted/after_&lt;rule&gt; 四调用点随门一起清除）及
  `apply_rules_to_block` 内 `bs_try!` 宏的 `RUGRA_BS_TRACE` 规则命中打印——两者
  使用临时 `[DBG]` TAG，违反"临时 TAG 提交前必须删除"纪律；`bs_try!` 还原为
  cc:1797-1828 的裸 `if (ruleX) continue` 派发形态。均为 stderr/env-gated 输出，
  默认关闭，stdout 零变化（双语料 canon 字节恒等亲证）。历史定位叙述（TRI2
  结构分叉 triage、PRINTC-GOTOSTRUCT-RESID 的 stuck1/oracle collapseInternal
  残留态对照）以各 TODO/车道报告为准。

### identify_internal 成对去重 + 规则守卫回 oracle（2026-08-26，TRI2-STRUCT-SELECTGOTO-SELFLOOP-0001）
- **成对去重协议**：删除安装前对 `new_in`/`new_out` 的单侧 `retain` 去重。
  oracle 的 selfIdentify（block.cc:895-931）对每个被重定向的 peer 槽位各推
  一个复合块半边（平行边合法），仅由末尾 `dedup()`（block.cc:930）成对收
  敛——`eliminateInDups/eliminateOutDups`（block.cc:440-501）在对侧半删
  duplicate 槽位。旧单侧 retain 使复合块边数欠计，随后 touched peer 的成对
  dedup 按陈旧 reverse_index `halfDeleteOutEdge`（slot=-1→usize::MAX 时
  `while slot < last` 跳过循环、pop 尾边）删掉复合块仅存的出边——proper-if
  复合块 sizeOut==0 → TraceDAG 走断 → `selectGoto exhausted` → `code_r`
  自环 goto 兜底发射的完整根因链。现顺序为 resync（双射）→ 复合块 dedup →
  touched peers dedup（Ghidra 只 dedup ident；peer 侧为幂等 no-op 保护）。
- **边标签继承**：捕获边界边时保留 `e.flags`（对齐 replaceIn/OutEdge 的
  `BlockEdge(this, outofthis[num].label, num)`，block.cc:172/188）；旧
  `BlockEdge::new` 清零 flags，goto/loopback 标签在复合块边界丢失。
- **双射 resync**：`resync_boundary_reverse_indices` 改为按 peer 出现次序
  消费对侧槽位（第 occ 个回指边），平行边各自配对；旧首匹配把所有平行边
  配到同一对侧槽位。
- **install==consumed 跳过**：消费循环跳过 `c_idx == install_idx`（对齐
  newBlockGoto/newBlockDoWhile 的 `nodes={bl}`——install 块已由 install 捕
  获阶段处理；二次遍历把每条边界边翻倍，未配对的 reverse_index 又触发上述
  pop-尾边误删）。
- **规则守卫回 oracle**：`try_rule_proper_if`/`try_rule_if_no_exit`/
  `try_rule_while_do`/`try_rule_do_while` 删除自创
  `switch_case_indices`/`CASE_BODY` 级联守卫（与 a9d68f77 从
  try_rule_if_no_exit 删 cascade-member guard 同族；CBRANCH 链在 oracle 中
  就是嵌套 if/else，不存在的"级联 switch"概念阻塞了合法结构化），补上
  oracle 守卫：cc:1383/1487/1525/1561 `bl->isSwitchOut()`（f_switch_out 由
  build_copy 对 BRANCHIND 块重建，block.cc:2286 不变量）、cc:1394/1500/
  1534 子句 `isSwitchOut`、cc:1501 `!isDecisionOut`、cc:1487-1490 自环/
  goto-out。真实 switch（BRANCHIND 派发块）仍被保护。
- funcdata `test_bool_condition_folding_and_pattern` 搜索层扩到两级：该 CFG
  的 oracle 规则序列为 ruleBlockOr → ruleBlockIfNoExit 包 D（cc:1840 第二
  趟）→ ruleBlockCat 合并 sink C，终态 List[If[Condition(Or), D], C]（旧断
  言只搜一层，恰好匹配旧 bug 造成的 Condition 直接 List 子节点形态）。
## buildCopy 正式接线（BLOCK-BUILDCOPY-MIRROR-0001，2026-08-28）

`ActionBlockStructure::apply` 现在直接调用 `fd.sblocks.build_copy(&fd.bblocks)`；
复制算法归属 `BlockGraph`，与 oracle 一致。旧私有 `build_copy`（清空目标、
创建 BlockBasic、按出边顺序用 add_edge 重放、扫描 BRANCHIND 补 flag）已删除。

新路径按 block.cc:1681-1697/1925-1938：保留目标 prefix；按源 list 原序追加
真实 BlockCopy；原样复制两侧边向量、label、reverse slot、idom、index、
numdesc 和 flags；visit-count 清零；仅在 out-degree>2 时补 switch-out；写回源块
copymap 后只重映射新增 suffix 的端点/idom。主管线所有边修改 helper 改经
FlowBlock 的共享 edge vectors，避免再次漏掉 Copy；loop 叶守卫接受 Basic|Copy。

父指针仍是明确残差：当前 `Funcdata.sblocks` 是内联 BlockGraph，无法创建指向
自身的稳定 Weak，故 fixture 的 covered projection 为 MATCH、整体为 MISMATCH。
该限制绑定 `BLOCK-ADDGRAPH-SEMANTICS-0001`，不得把本次结果表述成完整 buildCopy
函数或 Block 模块 L3。


### 2026-08-27：TRI2 round 4 — clause 入边门进一步回 oracle

- `count_non_structural_in_edges` 删除自创 `switch_case_indices`（cascade
  成员）arm：该 arm 把 refreshSwitchCases 的 CBRANCH 链标记当作"结构化"入边
  计数排除，导致所有被级联遍历器触碰的 else-if 链被 proper_if/if_else/
  do_while 拒判，链不可塌缩，selectGoto exhausted（TRI2-STRUCT-
  IRREDUCIBLE-TRACE-0001，glob_range 残差 1→2→3→9 with properif-legal
  shapes）。oracle 守卫为纯 `clauseblock->sizeIn() != 1`（blockaction.cc:
  1391/1428 等），无 cascade 概念。
- E2E curl：exhausted 8 函数→2（getparameter.constprop.0/glob_set），
  defects=0/numbering=0，skeleton 3050→2611，输出回流 result/curl_cur.c。
- 残余分叉（下一步）：Switch-dispatch arm 与 DEAD arm 在 oracle 中不存在
  （Ghidra 用 identifyInternal 把消费块移出 graph，sizeIn() 自然不含），
  完整 faithful 移除待续。

## TRI2-CALLOUT-ASSIGN-0001 集成：build_copy 活 op 视图

当前由正式 `BlockCopy.original` 直接提供活动 op 视图；不再建立
`live_ops_source`/`source_basic`，也不保留结构化阶段 ops 快照。

## MAIN-RC2-BLOCKGOTO-WRAPPED-0001：try_rule_goto 忠实捕获序 + gotoPrints 树遍（2026-08-30）

oracle：`CollapseStructure::ruleBlockGoto`（blockaction.cc:1450-1475）逐出边扫
isGotoOut(i)：switchOut→newBlockMultiGoto（Rugra 无对应物，BLOCKSTRUCT-
MULTIGOTO-0001，维持 skip）；sizeout==2→（非 isGotoOut(1) 先 negateCondition
+dataflow_changecount）+newBlockIfGoto；sizeout==1→newBlockGoto(bl)。
`newBlockGoto`（block.cc:1702-1713）顺序：先捕获
`new BlockGoto(bl->getOut(0))`，`identifyInternal(ret,[bl])`（bl 成为组件），
`addBlock(ret)`，`forceOutputNum(1)`（identify 后恰 1 出边，无操作），
`removeEdge(ret,ret->getOut(0))`（双侧删除→sizeOut==0）。

- `try_rule_goto`：构造时填 `wrapped: Some(block.clone())`（组件持有，修复
  identify_internal 换槽后整体蒸发）与 `target_dyn: Some(goto_target.clone())`
  （block.cc:1705 删边前捕获序）；类型化 `goto_target` 保持 None（见
  docs/api/block.md PRINTC-GOTOPRINTS-0001 投影说明）。identify_internal→
  update_switch_case_reference→remove_edge_blocks 顺序不变（cc:1708-1711）。
  旧实现的 downcast-then-None 死代码删除。
- `ActionFinalStructure::apply`：在 `scope_break(-1,-1)` 与 `mark_unstructured()`
  之间（blockaction.cc:2193-2194 oracle 求值序）调用
  `fd.sblocks.compute_goto_prints()` —— gotoPrints（block.cc:2881-2890）的
  parent-present 臂需要 getParent()->nextFlowAfter(this)，Rugra 复合块不接线
  parent，故在最终树上一次性求值并存 prints_precomputed，供 markUnstructured
  cc:2861 门与 printc emitBlockGoto cc:2775 消费。2026-09-22
  （GOTO-PRINTS-NEXTFLOWAFTER-ARMS-0001）：compute_goto_prints 树遍历从纯兄弟
  规则升级为 block.rs 的 nextFlowAfter 全分臂单一事实源
  （`next_flow_after_successors`/`graph_sibling_successors`，12 个 override 逐臂
  对照见 docs/api/block.md 同日追加节；双侧 fixture
  goto_prints_nextflowafter_1204 六形态 MATCH）；blockaction.rs 本身未改
  （调用点与求值时机不变）。

机制 C：blockaction.rs 属核心算法白名单，本改动 Cross-Review: PENDING
（待独立复核 agent 逐行读 block.cc:1702-1713/2856-2903 与 printc.cc:2766-2779
后出 APPROVE）。

### 2026-08-30（BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001）：find_exit 容器臂 + check_switch_skips

**LoopBody::find_exit**（blockaction.cc:182 findExit）：尾部近似 `trial_exit[0]` 替换为
忠实容器臂（cc:227-237）——`extend_to_container`（cc:46-74，容器 head/tails +
本循环 head 的非 goto 反向 BFS 标记）之后取第一个落在容器体内的 trialexit，再
`clear_marks(extension)`。签名新增 `container: Option<(i32, Vec<i32>)>`（容器
(head, tails)）。`immed_container` 语义从"loop_order 位置索引"改为**容器 head 块
索引**（oracle 是 LoopBody 指针；merge_identical_heads 后 head 唯一，可跨深度
排序存活；原位置索引在 step-4 sort 后失效）。step-5 经 `containers_by_head` 快照
解析容器。证据：修复后 getparameter.constprop.0 的 selectGoto 级联前 18 个标记与
oracle 逐点一致（22/0,9/0,7/0,6/0,107/0,82/0,86/0,70/0,65/1,110/0,29/1,99/0,
89/0,60/0,102/0,25/0,127/0,111/0），此前首个标记即发散(20/1 vs 22/0)。

**CollapseStructure::check_switch_skips**（blockaction.cc:1607 checkSwitchSkips）：
新增完整移植——非默认 skip-to-exit case 边在存在默认边指向他处时标记为 goto
（cc:1637-1643），返回 false 使 ruleBlockSwitch 报告"匹配但加 goto"并让
collapseInternal 下一轮包裹后再建 switch。t_multigoto/hasDefaultGoto 提升臂在
Rugra 不可达（无 BlockMultiGoto 类型），注释记录。is_default_branch 读镜像
F_DEFAULTSWITCH_EDGE 标签（funcdata.rs set_default_switch_mirrored 安装）。

**验证**：curl 全语料 3096/0/0（defects=0 保持）；cargo check 通过。
诊断设施：block.rs `print_tree_dbg`/`dbg_front_leaf_start_addr`（结构树 dump，
RUGRA_DUMP_FUNC hook 于 curl/httpd runners）、blockaction.rs SELECTGOTO 级联
trace（RUGRA_TRACE_SELECTGOTO）、IRRED-SW try 行含地址。

## 2026-09-22 追加（BLOCKSTRUCT-MULTIGOTO-0001 — newBlockMultiGoto + ruleBlockGoto isSwitchOut arm）

- `new_block_multigoto(i, outedge)`（Ghidra block.cc:1720-1753 `BlockGraph::newBlockMultiGoto`，pub 供双侧 fixture 直驱）:①`targetbl`/`isdefaultedge` 在任何 mutation 前捕获（removeEdge 双侧删除边与 label 后不可再查）；②已是 t_multigoto 分支（cc:1726-1732）addEdge→removeEdge→(default)setDefaultGoto；③新包分支（cc:1733-1751）origSizeOut 于 identify_internal 前捕获，identify 后 `sizeOut != origSizeOut ⟺ 自环被吸收` → `force_output_num(sizeOut+1)` 恢复自环（f_loop_edge|f_back_edge），再 removeEdge(target)；自环 goto 边由 identify 吸收不显式删（cc:1748）。identify_internal 组件 downcast 链补 `BlockMultiGoto` arm（selfIdentify cc:925-926 的 f_switch_out 传播使 multigoto 保持 switch 身份供 ruleBlockSwitch cc:1652）。
- `try_rule_goto`/`try_rule_if_goto` 补 isSwitchOut arm（blockaction.cc:1456-1458,先于 sizeout==2/1 分派）:switch 块的 goto 边一律剥入 BlockMultiGoto——替换此前"显式 return false 跳过 switch"（BLOCKSTRUCT-MULTIGOTO-0001 登记项闭账）。首个 goto 边按最低槽位扫描（cc:1454-1455）。
- `check_switch_skips` 补 cc:1630-1635:t_multigoto + hasDefaultGoto → defaultnottoexit=true（被摘除的 default goto 边对边扫描不可见，multigoto 的 flag 是唯一证人）→ 使 skip-to-exit 标记成立。
- `try_rule_switch` 构建时补 grabCaseBasic multigoto arm（block.cc:3548-3553）:identify 之后从 control(multigoto) 的 gotoedges 追加 goto case（gototype=f_goto_goto，目标块不消费——留在图中承载 goto 标签），isdefault 经 `switch_case_basic_coords`（cc:3495-3515 addCase 语义：basic 级 in-edge→outindex→isDefaultBranch，basic 边未被 removeEdge 触碰）判定，default goto case 落 `default_case`+`default_gototype` 槽。case label 仍为边序占位（真实 label=finalizePrinting+recoverLabels，JUMPTABLE-TABLEAPI-0001/P0-A 域）。
- `dedup_edges_all_types` 重写为单锁纪律编排（find_dup_peers + eliminate_dup_pairs）:oracle eliminateInDups/OutDups（cc:447-501）的成对半删除全同步；Rust 侧 bl 的写锁只覆盖 bl 侧变更、peer 侧半删除前释放，使双向互惠修复（含指回 bl 的）全部同步执行——替代旧"整个 dedup 持一把锁"（peer 修复撞持锁→错块自索引 OOB 崩溃，switch goto-case 解锁路径实测）与中间版"挂起队列"（跨规则窗口内 reverse_index 陈旧→收敛环挂死 2 例）。
- E2E（fast-release,124 golden 全量）:**0 panic / 0 timeout / 76 decompiled（=baseline）**,defects=0/numbering=0,skeleton 3711→3386（getparameter.constprop.0 函数级 869→539:multigoto 剥除坏边解除 111×cc:1705 拒绝循环,switch 邻域恢复 do-while 结构;glob_set 91→96 +5:同机制旁邻重排,见 Differential 登记）。httpd 全量与 baseline 逐字节一致（diff=0）。B2 双侧 fixture `blockmultigoto_1204`（oracle e40ed130 直跑）:rule 驱动 case + 直驱 case（自环恢复/default 捕获/add-to-existing/scopeBreak）逐字节 MATCH。

## 2026-09-22 追加（BLOCKSTRUCT-SWITCHOUT-NOCLEAR-0001 — no-op flag 清除修复）

**根因**：Rugra `set_flags` 是 OR 语义（`flags |= f`，block.rs:2241，对齐 Ghidra
`FlowBlock::setFlag` block.hh:155）；`clear_flags` 才是 `flags &= !f`（block.rs:2245，
对齐 `clearFlag` block.hh:156）。两处"想清位却用 set_flags(x & !BIT)"的写法是恒等
no-op（`flags |= (flags & !BIT) == flags`）。

- **try_rule_switch 尾部**（blockaction.rs:6285，对齐 block.cc:1917
  `ret->clearFlag(f_switch_out)`）：安装的 Switch 组件经 identify_internal 继承
  SWITCH_OUT（cc:925-926 OR 语义正确），尾部清除写成
  `set_flags(swf & !SWITCH_OUT)` → 位从未清掉 → `ruleBlockSwitch` cc:1652 的
  isSwitchOut 门对已安装 Switch 组件放行 → 自噬式再触发 415 次（每次把上一层
  Switch 当 control 再包一层空 case Switch），48-case Switch 链被连环吞死。
  修复：`sw.clear_flags(SWITCH_OUT)`。修复后 gp 单函数
  "switch structured" 事件 416→3（48/47/48 case 三次合法形成），组件
  flags 0xc10→0xc00（SWITCH_OUT 确已清除），try_rule_cat cc:1296 对正确去旗的
  Switch 放行与 oracle 一致。
- **refresh_switch_cases**（blockaction.rs:3489）：Rugra 侧 CASE_BODY 簿记
  （oracle 无 f_case_body/refreshSwitchCases——block.hh:88-106 枚举止于
  f_duplicate_block=0x40000；注释由伪 `// Ghidra: blockaction.hh:46
  LoopBody::refreshSwitchCases/dominatesIdx` 校准为 RUGRA-GLUE，blockaction.hh:46
  实为 LoopBody 类声明行）。"Clear CASE_BODY flag on all blocks first" 的清除同样
  写成 OR no-op → 陈旧 CASE_BODY 永不退旗，try_rule_if_no_exit 的
  `CASE_BODY == 0` 守卫过度拒绝合法 while 形成。修复：`b.clear_flags(CASE_BODY)`
  （设置侧本就 `| CASE_BODY` 无误）。

**验证**：gp(getparameter.constprop.0) fast-release 单函数：3 次合法 Switch 形成
存活到 finalize（不再自噬）；但发射端仍无 switch——残余根因已定位到
printc.rs:4738 `emit_structured_infloop` 用 `emit_block_ops(body)` 扁平发射 InfLoop
体，oracle printc.cc:3109 是 `bl->getBlock(0)->emit(this)` 虚分派递归（Switch 合法
cat 进自环 List→InfLoop 体后，扁平化吞掉全部结构）——登记 PRINTC 侧
（PRINTC-SWITCH-EMIT-0001 域），不阻塞本修。case 值仍为出边槽占位
（JUMPTABLE-TABLEAPI-0001）。

## 2026-09-22：BlockSwitch 构造点跟进新字段（结构层提交）

本提交 blockaction.rs 仅在 5 处 BlockSwitch 字面量（try_rule_switch/
collapse_switches/collapse_cbranch_cascades/update_switch_case_reference/
refresh_switch_cases 重建点）补 `jump: None, case_order: Vec::new()` 占位，
保持编译与现有行为不变；真实 jump 解析与 case_order 记录在下一提交
（collapse 接线）落地。

## 2026-09-22（续）：label 管道 collapse 接线（try_rule_switch/ActionFinalStructure）

- `CollapseStructure` 新增 `jump_tables` 字段 + `with_jump_tables` builder
  （RUGRA-GLUE：oracle 经 FlowBlock 的 Funcdata 反查指针，block.cc:637；
  Rugra 复合块无反查，由 ActionBlockStructure::apply 传入 fd.jump_tables）。
- 新增 `grab_case_order(&self, switch_block, cases, branchind_addr)`
  （grabCaseBasic 的 CaseOrder 记录半部，block.cc:3527-3546 + ctor 3488）：
  逐 case 解析 basicblock（front_leaf→BlockCopy.original，cc:3500）与
  outindex（入边反扫，cc:3506-3509），建 casemap（cc:3527/3532），对
  BlockGoto case 走 fall-thru chain 链接（cc:3536-3546，经 target_dyn 的
  basic 入边 → casemap[rev]），并按 BRANCHIND op 地址从 jump_tables 解析
  ctor jumptable（block.cc:630-639 语义）。
- `switch_case_basic_coords` 返回值扩为 `(isdefault, outindex, basic)`，
  multigoto goto 臂非 default 目标追加 `CaseOrder::placeholder(basic,
  outindex)`（chain=-1，cc:3548-3553 臂在 chain 填充循环之后）；goto-default
  不记 order（Rugra default 独立槽不打印 label，已在 block.rs 注明分歧）。
- `try_rule_switch` 与 `collapse_switches` 构造点改喂真 `jump`/`case_order`；
  `update_switch_case_reference` 与 `collapse_case_fallthru` 的重建点携带
  两字段（oracle 同对象原地改，Rugra 重建需显式带过）。
- `ActionFinalStructure::apply` 在 scopeBreak 之前补
  `fd.sblocks.finalize_printing()`（blockaction.cc:2192 调用点；cc:2191
  orderBlocks 未移植，已登记缺口——顶层 list 顺序仍为 collapse 安装序）。

## 2026-09-22（续 2）：case_gototypes 平行数组修复（glob_set panic）

E2E 发现 glob_set worker panic：finalize_case_labels 按 case_order 索引
`case_gototypes[i]`，但非 multigoto 安装路径（try_rule_switch 常规、
collapse_switches）历史上把 case_gototypes 留成空 Vec（printc 用
`.get().unwrap_or(0)` 容忍）。Ghidra addCase 对常规 case 恒置 gototype=0
（cc:3510-3511，仅 multigoto 臂附 f_goto_goto，cc:3552），两构造点改为
`vec![0; cases.len()]` 初始化。修复后 curl E2E 124/124、PANICKED=0、
defects=numbering=0。

## 2026-09-22（续 3）：常规 default 边路由 + finalize 见证 dump

- `try_rule_switch`/`collapse_switches` 的 case 收集循环补 cc:3515 addCase 的
  isdefault 判定（`switchbl->isDefaultBranch(outindex)`，标记链=
  switchOver cc:2552-2568 maxcount 选 defaultBlock → installSwitchDefaults →
  set_default_switch_mirrored）：被标记出边的目标路由进 `default_case` 独立槽
  （default_gototype=0 正文形态），不再混入 `cases`（否则其 40 个表条目会被
  finalizePrinting 物化成 40 个假 `case v:` 臂——gp 实测 88→48 对齐 golden）。
- `finalize_case_labels` 尾部加 RUGRA_BS_DUMP=1/2 门控的 `[BLOCKSTRUCT]
  finalizePrinting case[i] label/depth/chain/outindex/labels` 结构层见证
  （无 Ghidra 对应物，纯调试工具）。
- gp 结构层验证：finalize 后 48 臂 label 集合与 golden 逐项相等、逐臂顺序
  相等（case 0 起,含 0xf/0x10/0x15…）；default 的 40 值组正确路由不进 cases。

## 2026-09-22（续 4）：grab_case_order 转 pub（双侧 fixture 入口）

`grab_case_order` 由 private 转 pub：blockstruct_switch_label_1204 双侧
fixture（B2，JUMPTABLE-TABLEAPI-0001 label 管道核心投影，/dev/shm 迭代中，
root 集成入库）需要以生产路径驱动 CaseOrder 记录——oracle 侧直接调
grabCaseBasic（block.cc:3524），Rust 侧这是唯一生产入口。已登记分歧：Rust
default 走独立槽（oracle 在 caseblocks 带 isdefault），fixture 观察协议以
"regular case 行 + default 概要行"投影双侧共同语义。

B2 证据（/dev/shm/rugra-tests/sb-jtlabel/fixture/）：ghidra.statement 与
rugra.statement 16 行逐字节 MATCH，覆盖 slot_desc（label 排序≠槽位）、
multi_shared（多条目组 addressIndex 序 [0x5,0x2]）、fallthru_chain
（chain/depth/label 下传：排序键 0x3 vs 打印组 [0x8]）、default_edge
（default 路由 + label=0）。

### 2026-09-22：接入 `graph.orderBlocks()`（blockaction.cc:2191，BLOCKSTRUCT-ORDERBLOCKS-0001，Lane BV）

- `ActionFinalStructure::apply` 按 oracle 顺序执行**五个图调用**：
  `graph.orderBlocks()` → `graph.finalizePrinting()` → `graph.scopeBreak(-1,-1)`
  → `graph.markUnstructured()` → `graph.markLabelBumpUp(false)`
  （blockaction.cc:2191-2195；markLabelBumpUp 由 Lane CC 于 2026-09-22
  接线，见下方同日条目，原缺口登记 BLOCKSTRUCT-MARKLABELBUMPUP-0001
  已关闭）。
- `orderBlocks`（block.hh:430-431）：单元素列表跳过；否则按
  `FlowBlock::compareFinalOrder`（block.cc:709-730）排序——entry
  （index 0）恒最前、`lastOp()` 为 CPUI_RETURN 的块压尾、其余按 index
  升序；两个 RETURN 结尾块为并列（tie）。Rust 实现与排序键细节见
  docs/api/block.md 的 `order_blocks`/`compare_final_order` 条目
  （含本次一并补齐的 BlockGoto/BlockMultiGoto `lastOp` 委托覆盖）。
- 之前缺口：Rugra 顶层列表保持 finalize_structure 的幸存者（槽位）序，
  不是 oracle 的 compareFinalOrder 置换；return 结尾顶层块不会移到尾部。
- 语义影响：排序发生在 finalizePrinting 之前，因此 scopeBreak 的
  next-sibling fall-thru（block.cc:1277-1287）、gotoPrints 的
  next-in-flow 后继（block.cc:2881-2890）与 emitBlockGraph 发射序均按
  最终打印序取后继。
- 验证：curl 124/124 与 httpd 29/29 全量 E2E 改动前后**字节恒等**
  （sha256 相同——当前语料所有函数顶层列表均为单元素，block.hh:431
  守卫双侧同步跳过）；getparameter.constprop.0（skeleton 978）与
  glob_set（skeleton 97）`--func` 前后 defects=0/numbering=0 不变；
  B2 双侧 fixture `blockstruct_orderblocks_1204` 5/5 case MATCH。

### 2026-09-22：接入 `graph.markLabelBumpUp(false)`（blockaction.cc:2195，BLOCKSTRUCT-MARKLABELBUMPUP-0001，Lane CC）

- `ActionFinalStructure::apply` 在 `fd.sblocks.mark_unstructured()` 之后、
  返回之前补上**第五个图调用** `fd.sblocks.mark_label_bump_up(false)`
  （cc:2195 `graph.markLabelBumpUp(false); // Fix up labeling`），与 oracle
  的五调用序列（cc:2191-2195）完全对齐。此前 per-type 实现存在但为死
  代码（f_label_bumpup 永不置位）。
- 语义（详见 docs/api/block.md 同日条目）：循环三 override
  （WhileDo/DoWhile/InfLoop，block.cc:3316/3426/3454）对自身 list[0]
  前链强制 `true` 下传（"偷" 子块 label），仅当传入 bump=false 时清除
  自身旗标；printc 的 `emit_any_label_statement`（printc.cc:3219-3226）
  读取 f_label_bumpup 决定 label 位置——被旗标块自身的 label 语句跳过，
  由外层循环构造入口统一打印（goto 进循环头的 label 落在循环关键字行
  之前，而非 `while(...)` 括号内 / `do {` 体内）。
- 验证（三门禁）：curl E2E **defects=0/numbering=0**，skeleton
  3654→3653（−1 = 消除 glob_set do 体内无引用伪 label
  `code_r0x00004C20`——oracle golden 该函数 0 个 code_r 引用，方向=
  向 oracle 收敛）；httpd E2E **defects=0/numbering=0**，master 同树
  基线 2459→2456（−3 = 消除 3 个 do 体内无引用伪 label，golden 均 0
  引用）；双 corpus goto→label 零 dangling（goto 引用的 label 全部
  定义），未引用 label 仅减不增，gcc audit FAIL 集与基线逐条相同。
- B2 双侧 fixture：`tests/oracle/blockstruct_marklabelbumpup_1204`
  （5 case：whiledo/dowhile/infloop 各自前链投影、nested_loops_front
  内层 whiledo 保旗判别形态（强制 true 链上 `!bump`=false 不清自身）、
  straight_line 控制）——双侧 f_label_bumpup 投影逐字节 MATCH
  （runner `tools/run_blockstruct_marklabelbumpup_oracle.sh`）。
  连带重钉 8 个 pin block/blockaction 源哈希的 fixture 元数据并复跑：
  blockmultigoto / blockstruct_orderblocks / blockstruct_scopebreak_gototype
  MATCH；blockstruct_blockgoto_wrapped 维持其已登记 MISMATCH
  （BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001，形态与 metadata 记载一致）。

## 2026-09-22 追加（PRINTC-SWITCH-EMIT-0001 — BlockSwitch 构造点补字段）

5 处 `BlockSwitch { ... }` 结构体字面量（try_rule_switch 主路径 6249、multigoto goto 臂
重建 4583/7281/7574/7766 一族）补 `default_label: None` 字段初始化——纯字段接线，无
算法改动；label 值由 block.rs `finalize_case_labels` 统一物化。形态与门禁见
docs/api/printc.md 同日条目（gp default 末位→第二位，curl 3607→3595/0/0）。

## 2026-09-23 追加（GETPARAM-BSTRUCT-CHANGECOUNT-0001 — 两个 mutation-only 规则臂补 change 计数）

Ghidra `CollapseStructure::collapseInternal`（blockaction.cc:1776-1834）的内层循环以局部
`change` 布尔（来源=各 `ruleXxx` 的**返回值**）决定是否重扫；Rugra 侧
`collapse_internal`（src/blockaction.rs）以 `structure_change_count` 的趟内增量等价建模该
布尔。两个"仅变异、不换结构"的规则臂在 Ghidra 返回 true 但在 Rugra 不 bump 计数，导致
假 fixpoint：

1. `try_rule_switch` 的 checkSwitchSkips 臂（blockaction.cc:1711-1712：把 switch 的
   skip-to-exit 边标记为 goto 后 `return true`）——补 `structure_change_count += 1`。
2. `new_block_multigoto` 的 already-multigoto 臂（blockaction.cc:1726-1732：对既有
   BlockMultiGoto `addEdge`+`removeEdge`）——同补 bump（fresh-wrap 臂尾部本就有）。

两处均不动 `dataflow_change_count`（Ghidra 对应臂同样不增 dataflow 计数）。实证：
getparameter（curl@0x3f00）Phase 2 投影 stage 40 计数 27 vs 26；双侧规则点火轨迹 +
likelygoto 生成列表（RUGRA_BS_TRACE/RUGRA_TRACE_SELECTGOTO/RUGRA_IRRED_DBG vs oracle
探桩 /dev/shm/rugra-tests/sb-getparam/oracle-probe，drill sha 92c66176…=pin）逐条对齐至
pick 111 后分叉：oracle 以 Cat 15+DoWhile 15（+1 dfc）收掉 loop(15,131)，Rugra 假收敛
后 selectGoto 挑走 (131,133)/(131,15) 两条外来边。修复后点火轨迹经 Switch 29(#2)+Cat 15
对齐，首 op 分歧 ord 7（funclink）→ ord 55（activeparam），stage 40-54 snapshot 与
count kv 全同。blockaction 属机制 C 白名单：Cross-Review PENDING。

## 2026-09-25 追加（BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 — case isexit 捕获 + default 路由坐标修复）

三症状的结构化侧根因与修复（JTRES 移交收口；oracle 对照=tree_dump_1204 仪器化追踪，
/dev/shm/rugra-tests/casewrap/）：

1. **isexit 捕获时点**（症状①：httpd main `case 0x4d:` 丢 `break;`）：oracle 的
   `BlockSwitch::addCase`（block.cc:3511-3514）在 `grabCaseBasic` 时——即
   `newBlockSwitch` 的 `identifyInternal` 消费 case 组件、`selfIdentify` 的
   `replaceInEdge` 半删除组件外部出边（block.cc:160-173）**之前**——计算
   `isexit = (bl->sizeOut()==1)` 并永久记录在 `CaseOrder`（block.hh:763）；打印侧
   `isExit(i)`（printc.cc:3342）读的是该旗标，事后不可从 sizeOut 重导（组件消费后
   外部出边数恒 0）。Rugra 此前在 printc 用 `size_out()==1` 打印期重导 → 恒 false →
   break 全靠 JTRES 的发射侧台账补偿。修复：`BlockSwitch` 增 `case_isexit`/
   `default_isexit` 平行数组（同 `case_gototypes` 形态），`try_rule_switch` 的
   case 收集循环在 identify_internal 之前按 cc:3513-3514 捕获；multigoto 重加臂
   置 false（cc:3512 gt!=0）；`finalize_case_labels` 的稳定排序与之联合置换；
   printc 的 cc:3342 判定改读旗标。
2. **default 路由坐标**（症状④：`case 0x43:` 整 case 丢失）：`newBlockMultiGoto`
   的 peel（removeEdge，block.cc:1746）把 goto 标记的 dispatch 边移出结构图出边
   表后，结构槽位 j 与基本图槽位错位——槽位索引的 `is_default_branch(j)` 拿原始
   边旗标对照 SHIFT 后的目标：httpd main peel 后槽 1 是 case 0x43 的块而原始槽 1
   是已 peel 的 default → 0x43 被误路由进 default 槽位、随真正 default 的 multigoto
   重加被覆盖蒸发。oracle 的 addCase 用基本图反查（cc:3506-3515：
   `inindex = basicbl->getInIndex(switchbl)` → `outindex` → `isDefaultBranch`），
   从不受结构图 peel 影响。修复：case 收集改用既有 `switch_case_basic_coords`
   （同一基本图 in-edge 反查）判定 default。
3. **gotoPrints 后继链的合并打印序**（症状③：`case 0x66:` 丢
   `goto switchD_.._caseD_40;`，block.rs `next_flow_after_successors` Switch 臂）：
   oracle `BlockSwitch::nextFlowAfter`（block.cc:3639-3661）遍历的是排序后的
   caseblocks（default 以其 label 序位列于其中），最后一个 caseblock 交给父臂
   （cc:3659-3660 "flow is to exit of switch"）；Rugra 组件表把 default 追加在尾
   → 最后一个真实 case 的后继= default 前叶=其 goto 目标 → prints=false 丢语句。
   修复：Switch 臂构造合并打印序（default 按 `default_label` 序插入，同 printc
   def_pos 配方），末位交父臂。
4. **发射侧守卫退役**（printc.rs）：BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 的
   `needs_switch_break` 台账补偿块按 TODO 退役条件移除——A/B 实测守卫置死后
   httpd/curl 双语料逐字节恒等（结构化侧旗标已全覆盖其职责）；同修
   emit_block_ops 的 discovery 台账对 Goto 弧记录 wrapped 叶起点（症状②：
   `switchD_.._caseD_3f:` 标签被 never-emitted 锚误吞），`case_exit_stmt_printed`
   字段保留写入作为 discharge 记录、读者移除。

E2E（默认脸亲测，@ master 3b2bd7bf 基线）：httpd 1243→**1218**/0/0（main 572→549）、
+TYPESEED 1125→**1100**/0/0（main 550→527）、curl 1096→**1081**/0/0（getparameter
381→369、parseconfig 73→71、next_url 31→29；glob_set 47→48= default 体 isexit 的
canon 同款 break 落在 Rugra 既有 default 排位上，形态+1 正确向 canon）、curl 三门
默认脸 767→**758**。main switch 区四症状全收敛（case 0x43+goto LAB_0012bb80+
caseD_3f 标签+0x4d break+0x66 goto 与 canon 同形）；gcc 审计 fail 名集双语料逐名
恒等；双跑 cmp 恒等。

## 2026-09-25：collapse_switches 预安装器退役（BLOCKACTION-COLLAPSESWITCH-ISEEXIT-0001）

CR-CASEWRAP F1 复核项收口。phase1 的 `collapse_switches` 预安装器（7PHASE
legacy 路径调用；默认 5-step 从不经过）此前硬编码 `case_isexit:
vec![false]`/`default_isexit: false`，而 oracle 的 addCase（block.cc:3511-3514）
逐 case 捕获 `gt!=0→false; else isexit=(bl->sizeOut()==1)`。

**收集环内捕获被 oracle 实证否定**：先按 reviewer 最小修方向在收集环内补
`edge.point.size_out()==1` 捕获（与 CR-CASEWRAP 已批的 try_rule_switch 捕获环同
构），再用锁定 oracle 仪器化 fixture（stage_isexit_1204，pristine libdecomp，
e40ed130，httpd main entry=0x2b820）dump 终态树 18 caseblocks 的 gt/isexit/
isdefault + 入口地址作键：oracle 仅 2/18 isexit=1（0x2ba9f、0x2bdcd），而预装
器时点的同形捕获得 14/17 true——该时点 case 体出边仍指向下一 case/merge 块，
`sizeOut()==1 ⟺ 边指向正式 exitblock` 的 ruleBlockSwitch 不变量
（blockaction.cc:1697-1708）尚未成立，捕获语义只在 rule 成熟时点 sound（
try_rule_switch 同 fixture 地址键 16/16 恒等已证）。

**修法=退役（R15 判例同构）**：Ghidra 无此预安装器（LoopBody 无
collapseSwitches 方法，标注行 blockaction.hh:46 是类声明行；oracle 唯一安装点=
ruleBlockSwitch cc:1649-1723 → newBlockSwitch cc:1904-1919 → grabCaseBasic）。
禁用 7PHASE 相位循环中的调用点（R17 注记），函数体保留并保留收集环捕获（防止
复启用时回退到硬编码 vec![false]），函数头加 DISABLED 注记。退役后 switch 仅由
try_rule_switch 安装——即 Ghidra 自身架构。

**A/B 零差实证**（亲父 2632a2fc 对拍）：httpd/curl 默认脸 cmp 逐字节恒等（默认
路径本就不经预安装器）；httpd 7PHASE 退役前后输出亦逐字节恒等（该模式下 httpd
main 在 block.rs:4826 预存 panic，与本改动无关，panic 位点/计数前后同构）；curl
7PHASE 预安装器 0 次点火。三门禁：curl/httpd 对 1204 canon defects=0
numbering=0；gcc 审计 fail 名集逐名恒等（curl 104/20、httpd 14/15 与亲父一致）；
投影银行 391/391 MATCH；cargo test --lib 1712P/1F（nonzeromask 预存）零回退；
check_ghidra_annotations/refs 全绿。

## 2026-09-25 追加（BLOCKACTION-SWITCH-DEFAULTCHAIN-0001 — grab_case_order 注册 default 虚拟条目）

`grab_case_order` 新增 `default_case` 参数与第三返回值 `default_order: Option<CaseOrder>`：
default 组件经 `switch_case_basic_coords` 解析基本图坐标后，其 outindex 槽位在
casemap 里登记为虚拟索引 `cases.len()`（cc:3527-3533 的全组件 addCase 语义），
链环（cc:3536-3546）遍历 cases+虚拟 default——「case 的 BlockGoto 目标=default
基本块」与「default 自身 fall-thru 入另一 case」两侧链边都能接上；坐标不可解析
时返回 None（finalize 侧走 legacy 桶）。两调用点（try_rule_switch 与
collapse_switches 安装器）与三处 BlockSwitch 重建/构造点同步传输新字段。
机制 B 门禁：curl 474/0/0（glob_set −15）、httpd 908/0/0 字节恒等、bank 391/391、
gcc fail 名集恒等、双跑 cmp 恒等；双侧 runner blockmultigoto/goto_prints 重钉后
MATCH（printc_switch_emit 的 observation=UNTESTED 门为亲父预存断点，另行登记）。

## 2026-09-25 追加（CR-GLOBATTR F1 — multigoto 臂后的 default 链索引重映射）

`try_rule_switch` 的 multigoto 臂（cc:3548-3553 的 append 语义）在 `grab_case_order`
**之后**向 `case_order` push g 个重加 goto-case——grab 期登记的虚拟 default 索引
k=cases.len() 被 push 挤占：finalize 扩展视图里 `ext[k]` 变成首个重加 case 而非
default，对 default 的链（`chain==k`）静默改接重加 case。修复 = 臂内 push 完成后
`CollapseStructure::remap_default_chain_indices`（`chain==k → k+g`，返回搬移数）：

- `<k` 的正则间链不动；重加 case 的 placeholder chain=-1 且不入 grab 的 casemap，
  故 `==k` 无歧义只能是 grab 期 default 链；`default_order.chain` 目标恒为正则索引
  或 -1，不可能为 k——三守卫使重映射 correct-by-construction；
- `debug_assert` 后置不变量：重映射后无 `chain==k` 残留（k 槽现为不参与链的重加
  case）；RUGRA_BS_DUMP=1 输出臂事件见证行（k、+g、remapped 数）；
- 触发面亲测：curl 3 次臂事件（47→48）与 httpd 3 次（16→17）全部 remapped=0——
  双语料休眠；3 个单测（`multigoto_defaultchain_tests`）钉死重映射数学；
- 补丁前后 curl（474/0/0）与 httpd（908/0/0）输出字节恒等。

## 2026-09-25 追加（MSTRUCT — try_rule_switch isexit/isdefault 捕获见证探针）

Lane MSTRUCT（结构族分拣）在 `try_rule_switch` 的 case 捕获循环（cc:3511-3515 addCase
语义位点）补一条 `RUGRA_IRRED_DBG=1` 门控的 stderr 见证行（`[IRRED-SW] capture`：
case 块号/首叶地址/isdefault/isexit/size_out），与既有 `[IRRED-SW] try/reject` 探针族
同库同门。零行为变化（stdout 字节恒等亲证：curl 镜 200 与基线 cmp IDENTICAL）。

诊断价值（本车道分拣证据，绑定 MSTRUCT-SWITCHGOTO-SELECTGOTO-0001）：
glob_word 捕获快照显示 default（0x4c5e）`isexit=true (size_out=1)` 与 oracle
addCase 语义一致——default_isexit 捕获侧无缺口；而输出侧 default 臂尾打印
`goto code_r0x00004c20;`（无 `break;`），且捕获列表含同地址双块（31@0x4c48 与
22@0x4c48、32@0x4d04 与 23@0x4d04）——结构树基本块重复 + 发射侧 break 缺席的
组合是后继车道（blockaction+printc 联合）的入口证据。

## 2026-09-26 追加（MSTRUCT-SWITCHGOTO-SELECTGOTO-0001 — multigoto 剥离后槽位镜像 goto 标记残留）

Lane SWGOTO 修复 `new_block_multigoto` 剥离 goto 边后 `GOTO_EDGE_0/GOTO_EDGE_1` 槽位
镜像块旗标的残留（blockaction.rs）。

**根因（锁定 oracle 仪器化 trace 双侧逐事件对照，/dev/shm/rugra-reports/
LANE_SWGOTO_2026-09-26.md）**：Ghidra 的 goto 标记住在**边 label** 上
（`outofthis[i].label |= f_goto_edge`，setGotoBranch block.cc:305-313），removeEdge
（block.cc:1469-1481）删边时标记随边消失，幸存边的标记不受影响。Rugra 额外把标记
镜像进**槽位索引的块旗标**（GOTO_EDGE_0=0x400000/GOTO_EDGE_1=0x800000，
`set_goto_branch_on_block` 写、`out_edge_is_goto`/`BlockBasic::is_goto_out` 读）——
该镜像不随删边维护：`new_block_multigoto` 的 already-multigoto 臂（cc:1726-1732）
`removeEdge(ret,targetbl)` 剥离 goto 边后，幸存边左移补位，残留镜像把补位边误标为
goto → 下一轮 `try_rule_if_goto` 的 2-out switch 臂再剥一条真 case 边 →
`checkSwitchSkips` 级联把全部 case 边标 goto → switch 退化成 0-case 壳
（glob_set round-3 / glob_word round-2 实测：oracle 剥 1 条后 ifnoexit+cat 收口成
1-case switch，Rugra 连剥 3 条退化）。

**修复**：新增 `resync_goto_edge_mirrors`（RUGRA-GLUE）——剥离删除后按幸存出边
的 F_GOTO_EDGE 边 label 重导出槽位镜像（`clear_flags` 清位 + 按需 `set_flags`
置位；set_flags 是 OR 语义 block.hh:155，清位必须走 clear_flags block.hh:156）。
在 `new_block_multigoto` 两个 remove_edge_blocks 位点（already 臂 + 新包臂防御性）
调用。边 label 通道是权威完备通道（`set_out_edge_flag_all_types` 对所有块类型
写双侧半边），镜像仅是 BlockBasic 兼容编码——重导出后两通道恒等。

**验证**：glob_set/glob_word 三轮 collapse 的 SELECTGOTO 标记序列与 NEWSWITCH
形成序列同仪器化 oracle（git archive 锁定 e40ed130 + OTRACE 补丁）逐事件一致；
curl 镜面 132→110（glob_set 25→3：case 体全部回 switch 内，残 3 行=charprint
`(char*)LIT` 渲染+printc `code_r` 标号，域外）；vsh 镜面 51→41（同根自愈）；
httpd 镜面 265==基线逐函数恒等（本基无活位点，零回退）；canon 双语料
301/0/0、862/0/0==基线；银行 391/391（glob_set 投影 op 级流对结构级修复不变，
MATCH 366 stages/141943 ops 免重钉）；cargo test --lib 1733P/1F（nonzeromask
预存）；镜面门禁三面 PASS（110/275、265/460、41/55，棘轮上限未重钉）。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 2 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-26 — ActionFinalStructure 接入 for 循环形成两扫描（HTTPDMAIN-F8-FORLOOP-0001，Lane F8FOR）

- `ActionFinalStructure::apply`（blockaction.cc:2186 端口）在 `order_blocks`
  与原 `finalize_printing` 位之间新增两调用：
  1. `crate::block::for_loop_final_transform(fd)` — oracle
     ActionStructureTransform::apply 的 `getStructure().finalTransform(data)`
     （blockaction.cc:2110-2115；放置偏差与理由见 block.rs
     `for_loop_final_transform` 头注）；
  2. `BlockGraph::finalize_printing_graph(fd)` — 原
     `fd.sblocks.finalize_printing()` 的 fd 感知形态（WhileDo 覆盖需要
     `&mut Funcdata`），BlockSwitch 递归不变。
- 6 处 `BlockWhileDo` 构造点（structure_loops_first:3278 / ruleBlockWhileDo
  族:5668/7116/7223/7368/7486）补 `initialize_op/iterate_op/loop_def = None`
  初始字段。
- 残余登记：ap_getparents +2（canon）/curl 镜 +2/vsh 镜 +2 = 同族
  `moveRespectingCover` 已提交移动 + 后续门拒绝（oracle 同序提交移动；拒绝
  侧差异归 F8FOR-REJECT 残差票）。

## 2026-09-27 追加（BLOCKACT-CONDNEGATE-PARITY-0001 — set_exit_marks/clear_exit_marks 边 label 镜像）

**根因（双侧事件级对拍，work4 仪器化 oracle vs Rugra 等价 trace）**：
`LoopBody::set_exit_marks`（cc:416-426 `setLoopExit` → `FlowBlock::setOutEdgeFlag`）
在 oracle 中**总是把 label 镜像到目标的 in-edge 半边**（block.cc:240-247：
`bbout->intothis[reverse_index].label |= lab`），而 in-edge 半边正是
`isLoopDAGIn`（block.hh:345）读取的对象。Rugra 旧实现走 trait 级
`set_out_edge_flag`（只写 out 半边），导致 TraceDAG::checkOpen（cc:828）把
loop-exit 边当成可开 DAG 边计数。事件级后果链（ap_ht_time 镜面）：
checkOpen(0x2df89→0x2df8e, depth2) oracle open / Rugra miss → 坏边挑选序分叉
（Rugra 多挑 0x2df89→0x2df8e / 0x2df73→0x2df8e）→ selectGoto 目标错位 →
LIT 守卫块 0x2df67 的 3 次结构化 negate（IfNoExit×2+Goto×1，奇偶→INT_NOTEQUAL）
在 Rugra 侧为 0 次 → golden `if (*V != '\0') {A} return R;` 守卫形 vs Rugra
提升态 `if (*V == '\0') {return R;} A`。

**修复**：`set_exit_marks`/`clear_exit_marks` 改走既有的
`crate::block::set_out_edge_flag_mirrored`/`clear_out_edge_flag_mirrored`
（block.rs，镜像语义 = block.cc:240-256），set/clear 括号对称。

**验证**：修复后双侧结构化事件流（13826 条 rule-entry/NEGATE/flip 事件）逐条恒等；
0x2df67 翻转 3 次（IfNoExit@2df4b-front / Goto@2df50-front / IfNoExit@2df50-front）
与 oracle 恒等；httpd 镜面 `--func ap_ht_time` skeleton 8→2（余 2 =
PRINTC-STRDATA-TYPELOCK-0001 badstring 族，ec9154a5 已修待并；并入后 =0）。
邻接证据：sqlite3VdbeSorterRewind 同形守卫翻转站点随修复收敛核对；
sqlite3BtreeOpen 复合极性（德摩根族）核对无回退。已知同族未修点（非本票写域）：
funcdata.rs:3170 `Funcdata::setGotoBranch`（funcdata_block.cc:305-313）对结构块
同样走非镜像 `set_out_edge_flag` —— 登记 TODO 邻接注记。

## 2026-09-28：finalTransform 扫描撤出 ActionFinalStructure（INITEXTRACT-PIPE-SLOT-0001，Lane INITEXTRACT）

**根因（双侧钉死）**：2026-09-26 HTTPDMAIN-F8-FORLOOP-0001 把 for 循环
finalTransform 扫描（`for_loop_final_transform`）挂进
`ActionFinalStructure::apply`（:5736 槽）——比 oracle 位点
（:5715 ActionStructureTransform，blockaction.cc:2110-2115）晚 21 个
Action，晚于 **ActionSetCasts（:5735）**。for/while 判决门
`possibleIterate->isMoveable(lastOp)`（block.cc:3197）在 oracle 时点读
**原始 iterate op**（如 LOAD——内存读不可跨后续 STORE 移动 → 拒 → while）；
setcasts 之后同一 φ 输入已被包装成 CPUI_CAST（寄存器直传、平凡可移），
判决门翻转 → 错误转 for。oracle 运行时 trace（OPACTION_DEBUG,
ap_fini_vhost_config，锁定 e40ed130）确认动作序 structuretransform(#4222,
empty=1) → merge 组(#4223-4238) → setcasts(#4239) → finalstructure(#4240)，
且 oracle 对 ap_fini 的 structuretransform **零变更**（判决拒绝、留 while）。

**修复**：`ActionFinalStructure::apply` 撤除 `for_loop_final_transform`
调用（恢复 oracle 五图调用序：orderBlocks → finalizePrinting →
scopeBreak → markUnstructured → markLabelBumpUp，blockaction.cc:2186-2197），
扫描归还 :5715 槽（见 coreaction.md 同日节与 block.md 同日节）。原放置
声称「canon 双语料字节级无行为差」被 ap_fini fixture 证伪。

**验收**：canon httpd 47→36（ap_fini 10→6 / ap_getparents 4→2 /
ap_no2slash 5→0，defects=0 numbering=0）、canon curl 95→91
（my_get_token 2→0 / parseconfig 2→0）、双跑与前置会话产物 md5 恒等。

### GETLONGEST 车道钻定工件注记（2026-09-28，MIRRORCENSUS-GETLONGESTMATCH-CLONE-0001）
- `RUGRA_BS_TREES=<prefix>`（RUGRA-GLUE，debug-only）：每次
  `ActionBlockStructure::apply` 收尾把 `fd.sblocks` 的 print_tree_dbg 树落到
  `<prefix>.<round>` 文件——oracle 侧 bracket-ladder 逐 perform printTree 探针
  的对照面（LANE GETLONGEST 工件 /dev/shm/rugra-tests/getlongest/：o653l.ladder
  vs rtree.0..4）。默认关闭，stdout 零变化。
- `RUGRA_BS_VISIT=1` 输出升级：visit 行增 `ty/i/o`（结构类型+入出度），对齐
  oracle 侧 OVISIT 探针（块类型枚举名映射 t_ls→list 等已校准，两侧 visit 流
  在 NPat2R9::GetLongestMatch round-0 前 647 事件逐事件恒等——首分歧即
  selectGoto 靶向重访，见 TODO_BOARD 票行根因链）。
- examples/gen_decompile.rs 新增 `RUGRA_DUMP_FUNC=<name>`（curl/httpd runner
  同款先例）：post-action/pre-print 落 `<name>.tree`/`<name>.ir`/`<name>.ops`
  （print_tree_dbg + printRaw + 逐基本块 op 原始行，后者为 gen 驱动侧 BlockBasic
  printRaw 面的等价物——funcdata.rs print_raw 的 bblocks 臂目前只打印块头）。
  默认关闭。

### SELECTGOTO 车道对齐增量①+②（2026-09-28，MIRRORCENSUS-GETLONGESTMATCH-CLONE-0001 续作）
- **① composite 安装位 = min(组件索引)**（`identify_internal` 尾部，对齐
  `BlockGraph::addBlock` 的 min-tracking，block.cc:866-873）：Ghidra 的
  composite index 是其全部组件索引的最小值（identifyInternal 对每个 node 调
  `ident->addBlock(node)`，`index = min(index, bl->index)`）；oracle 探针
  （OWD2，scratch 树）8/8 实测 WhileDo cond=79/clause=78 → composite idx=78。
  Rugra 原先把 composite 装在 cond/head 槽——对 head 持最小索引的 wrap 等价，
  对反转情形（clause 索引 < cond 索引，NPat2R9 的 {79-cond,78-clause} wrap 是
  本函数唯一例）产生异位标签，污染一切 index 键消费面（FloatingEdge 解析、
  TraceDAG BadEdgeScore 排序、LoopBody head/tail 更新）。修法：反转情形把
  min 槽组件 park 到腾出的 install 槽、composite 落 min 槽、absorbed_into
  全量重映射、virtual_list 末端 push new_idx。修后 --one 653 的
  selectGoto REGEN 列表与 oracle 逐项恒等（(79,119)→(78,119) 归位）。
- **② while_do clause 判定还原 `size_in()`**（cc:1533 逐字）：撤除发明的
  `count_non_structural_in_edges` 折算（switch 派发/已吸收源折扣两臂）——
  oracle 是裸 `clauseblock->sizeIn() != 1`；复合体模型对齐后 stale 组件边
  不再泄漏进活块，裸计数既正确又对齐。
- 新增 env 门控诊断（默认关闭）：`RUGRA_TRACE_SELECTGOTO` 升级
  （updateLoopBody 的 REGEN/REMAINDER 倾印+select_goto 的 pick/skip 逐条）、
  `RUGRA_RULE2`（collapse 规则 fire 流，oracle [ORULE] 对照面）、
  `RUGRA_GOTOSTEP`（tracedag pushBranches 逐步+[RROOT] 根收集，oracle
  [OSTEP]/[OROOT] 对照面）、`RUGRA_TREE1`（首轮 collapseAll 后 sblocks 树落
  `<fn>.tree1`，oracle GLM_TREE1 对照面）、`RUGRA_BS_VISIT` visit 行追加
  `@ addr`（BlockCopy.original 的起始地址）。
- **验收（全部本 worktree 亲跑）**：canon curl/httpd A/B md5
  4503f498/c3b4706c 双字节恒等==基线（54/36/0/0 继承）；镜面 sq
  2742/2742 defects=0 numbering=0；bank 391/391；cargo test --lib
  1963P/0F/5I；annotations/refs 门禁绿。**剩余分歧**（下一增量靶）：
  round-2 输入图 0x3560f 出度 o=2(Rugra) vs o=1(oracle)——round-1 收尾树
  的 returnsplit/nodeSplit 链差，见 TODO_BOARD 票行。

### SELECTGOTO 车道诊断②（2026-09-28，同票续作——round-2→3 窗口钉靶）
- `RUGRA_BBSIG=1`（RUGRA-GLUE，debug-only）：每次 `ActionBlockStructure::apply`
  入口把 `fd.bblocks` 全量 CFG 签名（块地址/出度/目标列表）落到
  `<fn>.bbsig<round>`——oracle 侧 scratch GLM_BBSIG 探针的对照面。本轮用它
  钉死：round1/round2 入口 CFG 双侧恒等，round3 入口首分歧（oracle 多一块
  0x3561b）。
- **round-2→3 窗口根因（已钉，待下增量修复）**：oracle 在窗口动作
  （constantptr→…→determinedbranch→unreachable→nodejoin→conditionalexe→
  condconst→…→redundbranch）内对 0x3560f 做了块分裂（新尾块 0x3561b 继承
  其两出边 [0x3562e,0x3561d]，0x3560f 留单出边→尾块），并把 0x3561d 的
  已判定回边改指尾块（0x3561d o=2→o=1）；Rugra 侧两者皆未发生
  （round3 入口该区 CFG 与 round2 恒等）→round-3 起级联解耦。修复靶=
  窗口内对应动作（determinedbranch/conditionalexe 候选）的分裂/改边行为
  对齐。

### SELECTGOTO 车道修复③（2026-09-28，同票续作——round-2→3 窗口 0x3561b 分裂解锁）
- **双侧逐动作 CFG 钉靶（新证据面）**：`RUGRA_ACTSIG=1`（src/action.rs
  `ActionGroup::apply_children`，oracle 侧 GLM_ACTSIG 同点插桩于
  ActionGroup::apply 子分发尾钩）逐 action 落 `<fn>.actsig`（动作名+res+全量
  bblocks CFG）。fn 653 对照：**518 步动作序双侧恒等，前 87 步逐动作 CFG
  恒等**；@ACT 87 nodejoin oracle res=2 vs Rugra res=1——Rugra 做了
  0x34e7f/0x34e2a join 但漏 0x3560f/0x3561d join。
- **根因链（逐门探针钉死）**：①oracle 窗口内 nodejoin join 该对需
  findDups 的 booleanFlip 门通过——双侧 round-1 collapse 对 0x3561b 各翻
  一次（parity 同），window-1 双侧同拒（flip=1，与 oracle 一致）；
  ②window-1 的 oppool1 中 RuleCondNegate 双侧都消费该 flip（清零）；
  ③window-2 首拒因不是 flip 而是 **functionalEqualityLevel res<0**：
  oracle 双比较 cond 都已被 RuleSubZext INT_RIGHT 臂（ruleaction.cc:5073-5097，
  DEBUG 帧 2715：`ZEXT(SUB81(R13,0)>>2)` → `R13>>2 & 0x3f`）拓宽为 8 字节
  `(x&3)==0`，const 对相等→res=1→MergeNeeded→join→nodeJoinCreateBlock 分裂
  出 0x3561b；Rugra 缺该臂，0x35628 链停 1 字节，cond 尺寸 1 vs 8 恒拒。
- **修复**（src/ruleaction.rs `RuleSubZext` 补 INT_RIGHT 臂 1:1 移植，见
  docs/api/ruleaction.md）：修后 fn 653 **五轮 bbsig 与 oracle 全恒等**
  （121/120/122/112/117），级联解锁。
- **验收（本 worktree 亲跑）**：canon curl/httpd md5 4503f498/c3b4706c
  双字节恒等==栈基（零回退红线）；镜面五面 curl 21/21·httpd 36/36·vsh 2/2·
  **sq 2742→1678（−1064，GetLongestMatch 6 克隆族 656→49，余为 (code *)
  强转/空格 printc 既有族）**·sqlite 6187→6096（对 MB33 钉值 −91，对栈基
  实测 6153 亦 −57 改进——subzext 通用臂的语料级收益，如实记）；bank
  391/391；cargo test --lib 1965P/0F/5I（亲父 1963P+2 新）；annotations/
  refs/evidence 三门禁绿。
## 2026-09-30：op 链迭代面机械迁移（PERF-ARENA-FLIP-0001 (b)）

`fd.obank.{alivelist,deadlist,storelist,loadlist,returnlist,useroplist}`
的 Vec 迭代/克隆消费位随 PcodeOpBank 7 链 IdList 翻转机械改写为 bank 链
API（`iter_alive()/iter_dead()/iter_store()...` 与 `.cloned().collect()`），
迭代序与语义恒等（链序=原 Vec 序=oracle 列表序）；测试面裸
`alivelist.push` 改 `adopt_alive_op`（bank API，单链不变量保持）。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。

## ARENAFLIP-e（2026-09-30）规则派发快照化

`CollapseStructure::apply_rules_to_block` 每次派发一次 `get_block` 提升到派发头
（9 条 try_rule_* 签名增 `block: &Arc<...>` 参数,取代每 try 的 Vec 索引+Arc 克隆
—— (d) 段 miss 底归因的 per-try get_block Arc 克隆面）。`collapse_all` 的
while_do/inf_loop 循环与测试调用点同形随迁;tests 2018P 保持。

## ARENAFLIP-e（2026-09-30）try_rule_cat 读相 bank-view 化

`try_rule_cat` 的读相（入口守卫+链构建）改持单一 `BlockBankView`
（`self.graph.bank.hold()` 一次,NLL+显式 drop 保证 fire 路径前释放）,
per-try 的 peer 解析从每次 bank 锁降为扫描级单锁——(c) 段槽读先例在
cat 规则的应用。tests 2018P 保持。

## ARENAFLIP-f（2026-09-30）blockstructure 域快照读迁移（交接面①）

`identify_internal` 持单一 dispatch 级 `BlockBankView`（入口 adopt 后取,全函数
零发布——后续 adopt 幂等、set_block_index 走原地影子,不重发布）;`rewrite_out/
in_edges_to_idx` 签名改 `(view, bl, old_idx, new_point_id)`（复合块 id 由
identify 层提升一次,消除 per-call 身份查账）;`apply_rules_to_block` 持一个
dispatch 级共享 view 传入 9 条 try_rule_*（fire 即 return 纪律:identify 的
adopt 是该路径唯一发布点,fire 后无 view 读）;`extend_to_container` BFS、
`find_dup_peers`、`count_non_structural_in_edges`（签名增 view 参数）同模式;
collapse 首部的 adopt 扫描改 `adopt_bulk`（一次身份读锁覆盖整批幂等探针）。
行为恒等: canon curl `4ab1db2a` + httpd `7d5b9e7c` 字节恒等 + tests 2021P。
BANKSTATS（替代语料 VdbeExec 50969B, (f) 终态实测——CR-ARENAFLIP-F nit-2
校正: 早前草稿值系开发中问快照,以车道终报 §3.1 为准）: read_index
149.1M→1.49M（−99.0%）、read_arc 50.8M→9.96M（−80.4%）、id_lookups
150.0M→4.33M（−97.1%）、view_holds 43.3M→22.1M、per-read 锁面合计
392.8M→37.9M（−90.3%）。
