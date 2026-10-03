# CYCLE-RATCHET — 生产 types 图环棘轮（HHMIRROR A2.5 落地）

> 车道: CYCLERATCHET（工具域,零 src 改动）· 2026-09-26 ·
> 权威来源: `docs/alignment_docs/LANE_HHMIRROR_2026-09-26.md`（§1 方法/§2 E1-E16 边分类表/
> §5 决定性实测/§7.2-7.4 A2 条件与设计——"环棘轮可执法"是其条件 3,本文档即其落地件）。
> 工具: `tools/cycle_ratchet.py`（扫描+断言）+ `tools/verify_cycle_ratchet.sh`（CI 门禁 wrapper）。
> 冻结基线: HHMIRROR 实测树 = master `9ac04ade`（本车道 worktree 基,含 HHMIRROR 归档 commit）。

---

## 0. 一句话

把 HHMIRROR 压测实测的"24 模块冻结核心 SCC + 74 solo（每文件粒度）"从一次性测量变成
**CI 可执法的棘轮**: SCC 成员只许出不许进、环边只许消不许增、solo 模块不许掉进环——
新增任何环边必须先过 HHMIRROR 式逐边定性才能入白名单。

## 1. 断言语义（`tools/cycle_ratchet.py`,退出码 0=PASS / 1=FAIL / 2=内部错误）

| 断言 | 语义 | FAIL 条件 |
|---|---|---|
| (a) SCC 成员棘轮 | 每个多模块 SCC 的成员集 ⊆ 冻结 24 模块集 | 新模块入环（SCC 变大或新 SCC 出现）;列出见证边 file:line |
| (b) 环边白名单 | SCC 内每条边（含自环）的每条证据键 `form\|item\|anchor` 必须在冻结清单内 | 白名单外环边证据——**锚级精度**: 同一边对上新增字段/新 trait 签名同样 FAIL（变异 M4 亲证） |
| (c) solo 基线棘轮 | 冻结 solo 集（56 模块,折叠粒度）∩ 多模块 SCC = ∅ | solo 模块掉进环;列出拖它入环的边 |

改善方向（SCC 变小/冻结边消失/模块出环/solo 自环）**不 FAIL**,打 `[INFO]` 提示复核后
`--emit-freeze` 重新冻结——棘轮只防倒退,不挡破环。

## 2. 口径（复刻 HHMIRROR v3 FINAL,两个已记录的 refinement）

逐项复刻（`/dev/shm/hhmirror_tmp/type_deps3.py`,内存盘工具,方法已全部内嵌本档）:

1. **生产/测试切割**: 每文件在首个行首 `#[cfg(test)]` 截断（v1 教训: 测试内
   `struct OwnershipGraph { fd: Funcdata }` 曾误计为生产边）。本车道变异测试 M1 追加型
   探针落在 cfg(test) 后即被切掉,反向亲证切割有效。
2. **导入解析**: `use crate::/super::/self::` 裸名解析（v2 教训: `re.M` 缺失导致
   `PcodeOp.output→Varnode` 等边不可见——本车道落地时**再次踩中同坑**（USE_LINE 丢
   re.M → SCC 掉到 16）,修复后 24 复现;此坑已写死在工具注释）。
3. **模块名归一**: 子目录折叠到 crate 路径首段（v3: `type_system::datatype → type_system`,
   消灭幻影节点）。
4. **sink 图语义**: struct/enum/union 字段依赖 + **被持有** trait（`dyn X` 字段持有）的
   签名依赖拉入持有者;无人持有的 trait/分析器 struct/类型别名/impl 块浮动不算边
   （= A2 "types 下沉 + impl 浮顶" 的图投影）。
5. **Tarjan SCC**,只看多模块 SCC;自环=模块内类型互指,非分层事件（solo 自环记 INFO）。

**Refinement R1（depth-0 item 提取）**: 函数体/trait 默认方法体内的局部类型不算 types 层
边。HHMIRROR 原工具无深度过滤,把 heritage.rs 的 fn-local `enum InsertAnchor`(:4929) 与
`enum WorkItem`(:6434/:6788,均在函数体内) 误计为 `heritage→block` 边。按 A2 语义 fn-local
类型属 impl 浮顶层,剔除是语义正确化。**SCC 24 成员恒等**（heritage 经 `StackWalkNode.vn→
varnode`/`LoadGuard.op→op` 路径留环）,intra-SCC 边对 87→86,唯一差异即该 fn-local 伪边。

**Refinement R2（lib.rs 再导出归位）**: `use crate::X;` 根级裸名（X 为 lib.rs `pub use`
再导出,如 `crate::AddressSpace`）解析回真实模块（space）。HHMIRROR 原工具此处留幻影节点
（'AddressSpace' 曾出现在闭包输出里）,归位后消失。

**粒度 reconciliation（防未来困惑）**: HHMIRROR 报告 §5 的 `solo: 74/98` 是 **v2 每文件
粒度**（98 个 .rs 文件）;权威 24-SCC 来自 **v3 折叠粒度**（98 文件 → 80 模块）。本棘轮
全链采用 v3 折叠粒度: **24 SCC + 56 solo = 80 模块**。两套数字并存只是粒度差,不是矛盾;
任务书的"74 solo 基线"按此 reconciliation 落为 56（v3 口径）+ 74（v2 口径,文档记录）。

## 3. 冻结基线指纹（2026-09-26 @ master 9ac04ade）

- **FROZEN_SCC（24）**: action arch block cover cpool database drillobserve fspec funcdata
  heritage jumptable merge op options pcodeinject pcodeparse prefersplit transform
  type_system unionresolve userop variable varmap varnode
- **FROZEN_SOLO（56）**: address align analysis bin binary blockaction callgraph capability
  comment compression condexe constseq context coreaction crc32 debugproto disasm
  double_precis drillfmt dynamic emulate error expression ffi float_emulate flow frontend
  grammar graph lib loadimage marshal memstate modelrules opbehavior opcodes override_rs
  paramid pcoderaw prettyprint printc printlanguage rangemap rangeutil ruleaction signature
  sleigh_ffi space stringmanage subflow tracedag translate typeop types unify utils
- **intra-SCC 边对**: 86 对 / 证据键 186 个（`form|item|anchor` 粒度,行号不进键——行号会
  漂移,边形态才是身份）。
- solo 自环 8 个（INFO 面）: capability context modelrules opbehavior stringmanage
  translate typeop unify。

## 4. E1-E16 白名单账本（逐边编码;机器判定=FROZEN_EDGES,本表由冻结数据程序化导出）

形态类: **a**=可解（types 下沉/impl 浮动消解）· **b**=伪影 · **c**=真互持/锁死
（trait 签名环/字段互持/反转环）· **glue**=RUGRA-GLUE 偏离。

<!-- ledger-begin (generated from tools/cycle_ratchet.py FROZEN_EDGES+PAIR_TAGS; regenerate:
     python3 -c "import sys; sys.path.insert(0,'tools'); import cycle_ratchet as cr; ..." 见
     docs 生成配方在 tools/cycle_ratchet.py --emit-freeze 与本车道报告) -->
| # | 环边(from→to) | 分类 | 机器判定载体(FROZEN_EDGES 键族) | 形态摘要 |
|---|---|---|---|---|
| E13 | `action→action` | c | 3 键(dyn-hold×3) | ActionGroup/ActionPool/ActionDatabase 持 dyn Action/Rule（族内） |
| E12 | `action→drillobserve` | glue | 1 键(held-trait-sig×1) | Action trait 默认方法体调 drillobserve::activate（HHMIRROR: 需移出默认体） |
| E13 | `action→funcdata` | c | 2 键(held-trait-sig×2) | Action/Rule 签名 fd: &mut Funcdata（action.hh:102/120 fwd-decl 承载） |
| E13 | `action→op` | c | 2 键(field×1, held-trait-sig×1) | Rule 签名 op 参数 + ActionPool.op_state |
| E9-ARCH | `arch→action` | a | 1 键(field×1) | Architecture.allacts（E13 持有链的持有侧） |
| E9-ARCH | `arch→arch` | a | 1 键(dyn-hold×1) | CapabilityRegistry 持 dyn ArchitectureCapability（族内） |
| E9-ARCH | `arch→cpool` | a | 1 键(field×1) | Architecture.cpool |
| E9-ARCH | `arch→database` | a | 1 键(field×1) | Architecture.symboltab |
| E9-ARCH | `arch→fspec` | a | 5 键(field×5) | Architecture.defaultfp/evalfp*/TrackedRegister.loc |
| E14 | `arch→options` | c | 1 键(field×1) | Architecture.options_db（E14 持有侧） |
| E9-ARCH | `arch→pcodeinject` | a | 1 键(field×1) | Architecture.pcodeinjectlib |
| E9-ARCH | `arch→prefersplit` | a | 1 键(field×1) | Architecture.split_records |
| E9-ARCH | `arch→transform` | a | 1 键(field×1) | Architecture.lane_records |
| E16-1 | `arch→type_system` | c | 1 键(field×1) | Architecture.types: TypeFactory（3-环闭包边） |
| E9-ARCH | `arch→userop` | a | 1 键(field×1) | Architecture.userops |
| E7 | `block→block` | c | 15 键(dyn-hold×15) | Block* struct 族持 dyn FlowBlock（族内互持;2026-10-01 MB51 重冻结: BlockEdge point→BlockId 值化[(e) 段]退出 1 键,BlockBank 存储位 BankTable/BlockCell 入 2 键——block.hh:365-366 `BlockGraph{vector<FlowBlock*> list}` 图属主持有的 id/arena 形态,族内同形态;2026-10-01 MB54 §5.2: BlockKind 枚举单表化,存储位证据自 BankTable/BlockCell 两键并入 `dyn-hold\|enum BlockKind\|FlowBlock` 一键——同一句柄的表示层移位,E7 同族） |
| SCC-BASE | `block→jumptable` | a | 1 键(field×1) | BlockSwitch.jump（block.hh:462-473 同构） |
| E7 | `block→op` | c | 5 键(field×4, held-trait-sig×1) | BlockBasic.ops + BlockWhileDo ops 字段 + FlowBlock 签名族 |
| SCC-BASE | `block→varnode` | a | 1 键(field×1) | BlockSwitch.index_varnode |
| TRAIT-SIG | `cover→cover` | c | 1 键(dyn-hold×1) | PcodeOpSet 持 dyn PcodeOpSetImpl（族内） |
| TRAIT-SIG | `cover→op` | c | 1 键(held-trait-sig×1) | PcodeOpSetImpl 签名 op: &PcodeOp |
| TRAIT-SIG | `cover→varnode` | c | 1 键(held-trait-sig×1) | PcodeOpSetImpl 签名 vn: &Varnode |
| SCC-BASE | `cpool→type_system` | a | 1 键(field×1) | CPoolRecord.data_type |
| SCC-BASE | `database→type_system` | a | 3 键(field×3) | Symbol.dtype/QueryContainerHit（database.hh 同构） |
| E12 | `drillobserve→arch` | a | 1 键(field×1) | Recorder.arch（drill 双件浮顶后消解） |
| E12 | `drillobserve→op` | a | 1 键(field×1) | Recorder.modify_list |
| SCC-BASE | `fspec→op` | a | 1 键(field×1) | FuncCallSpecs.op: Weak<PcodeOp> |
| E16-2 | `fspec→type_system` | c | 6 键(field×6) | FuncCallSpecs.proto_model: ProtoModel（2-环闭包边;另有 Datatype 字段族） |
| E9 | `funcdata→arch` | a | 1 键(field×1) | Funcdata.arch（funcdata.hh:22-27 include 面同构） |
| E9 | `funcdata→block` | a | 2 键(field×2) | Funcdata.bblocks/sblocks |
| E9 | `funcdata→database` | a | 1 键(field×1) | Funcdata.symbol_entry_cache |
| E9 | `funcdata→fspec` | a | 3 键(field×3) | Funcdata.funcp/callspecs/active_output |
| E9 | `funcdata→heritage` | a | 1 键(field×1) | Funcdata.heritage（旗舰案例: 卫星 types 干净可沉） |
| E15 | `funcdata→jumptable` | c | 1 键(field×1) | Funcdata.jump_tables（E15 持有侧） |
| E9 | `funcdata→merge` | a | 1 键(field×1) | Funcdata.merge_state |
| E9 | `funcdata→op` | a | 2 键(field×2) | Funcdata.modify_list/obank |
| E9 | `funcdata→transform` | a | 1 键(field×1) | Funcdata 内联字段（LanedRegister 容器） |
| E9 | `funcdata→type_system` | a | 1 键(field×1) | Funcdata.global_struct_ptrs |
| E9 | `funcdata→unionresolve` | a | 1 键(field×1) | Funcdata.union_map（ResolvedUnion/ResolveEdge 干净可沉） |
| E9 | `funcdata→varmap` | a | 1 键(field×1) | Funcdata.scope |
| E9 | `funcdata→varnode` | a | 1 键(field×1) | Funcdata.vbank |
| E9 | `heritage→op` | a | 2 键(field×2) | 卫星内部: LoadGuard.op/Heritage.load_copy_ops |
| E9 | `heritage→varnode` | a | 1 键(field×1) | 卫星内部: StackWalkNode.vn |
| E15 | `jumptable→funcdata` | c | 2 键(field×1, held-trait-sig×1) | JumpModel 7 签名族 recover_model(fd)（jumptable.hh:249-260）+ EmulateFunction.fd |
| E15 | `jumptable→jumptable` | c | 2 键(dyn-hold×2) | JumpTable 持 dyn JumpModel/JumpBasic 持 dyn JumpValues（族内） |
| E15 | `jumptable→op` | c | 15 键(field×13, held-trait-sig×2) | JumpModel 签名 indop + Jump* 字段族 |
| E15 | `jumptable→varnode` | c | 11 键(field×9, held-trait-sig×2) | JumpModel/JumpValues 签名 + Jump* 字段族 |
| E9 | `merge→op` | a | 4 键(field×4) | 卫星内部: Merge*/MergePersistentState 字段 |
| E9 | `merge→type_system` | a | 2 键(field×2) | 卫星内部: LocalTypeKey(TypeMetatype) |
| E9 | `merge→varnode` | a | 2 键(field×2) | 卫星内部: AddrTiedLocRange/BlockVarnode |
| E7 | `op→block` | c | 2 键(dyn-hold×1, field×1) | PcodeOp.parent: Weak<dyn FlowBlock> |
| E7 | `op→op` | c | 1 键(held-trait-sig×1) | FlowBlock 签名拉入（get_ops/first_op 族） |
| E7 | `op→varnode` | c | 2 键(field×2) | PcodeOp.output/inrefs ↔ Varnode.def/descend 互持 |
| E14 | `options→arch` | c | 1 键(held-trait-sig×1) | ArchOption::apply 签名 arch: &mut Architecture（options.hh:27 fwd-decl） |
| E14 | `options→options` | c | 1 键(dyn-hold×1) | OptionDatabase 持 dyn ArchOption（族内） |
| TRAIT-SIG | `pcodeinject→pcodeparse` | c | 3 键(dyn-hold×1, field×2) | 持 dyn SleighSymbolLookup + InjectPayload.tpl: ConstructTpl |
| TRAIT-SIG | `pcodeparse→pcodeparse` | c | 1 键(dyn-hold×1) | PcodeSnippet 持 dyn SleighSymbolLookup（族内） |
| SCC-BASE | `pcodeparse→varnode` | a | 3 键(field×3) | VarnodeData 字段（SleightSymbolKind/PcodeData） |
| SCC-BASE | `prefersplit→funcdata` | a | 1 键(field×1) | PreferSplitManager.data: *mut Funcdata（oracle 指针字段） |
| SCC-BASE | `prefersplit→op` | a | 1 键(field×1) | PreferSplitManager.tempsplits |
| SCC-BASE | `prefersplit→varnode` | a | 3 键(field×3) | SplitInstance.vn/hi/lo |
| SCC-BASE | `transform→funcdata` | a | 1 键(field×1) | TransformManager.fd: *mut Funcdata（oracle 指针字段） |
| SCC-BASE | `transform→op` | a | 2 键(field×2) | TransformOp.op/replacement |
| SCC-BASE | `transform→varnode` | a | 3 键(field×3) | TransformVar.vn/replacement |
| SCC-BASE | `type_system→database` | a | 4 键(field×4) | TypeSpacebase.scope/TypeFactory.symboltab（type.hh:725/database.hh 同构） |
| E16-2 | `type_system→fspec` | c | 1 键(field×1) | TypeCode.proto: FuncProto（type.hh:696） |
| E16-1 | `type_system→varmap` | c | 4 键(field×4) | TypeSpacebase.fd: ScopeLocal + TypeFactory.live_local_scopes（type.hh:725 同构） |
| GLUE | `unionresolve→funcdata` | glue | 1 键(field×1) | ScoreUnionFields.fd: &Funcdata（Ghidra 从 op->getParent()->getFuncdata() 派生,Rust 穿参） |
| E9 | `unionresolve→op` | a | 1 键(field×1) | 卫星内部: Trial.op |
| E9 | `unionresolve→type_system` | a | 5 键(field×5) | 卫星内部: ResolvedUnion/Trial/ScoreUnionFields Datatype 字段 |
| E9 | `unionresolve→varnode` | a | 1 键(field×1) | 卫星内部: Trial.vn |
| SCC-BASE | `userop→fspec` | a | 1 键(field×1) | SegmentOp.constresolve: VarnodeData |
| SCC-BASE | `userop→type_system` | a | 3 键(field×3) | UserPcodeOp local types/enum 判别值 |
| SCC-BASE | `variable→cover` | a | 2 键(field×2) | HighVariable/VariablePiece.cover |
| SCC-BASE | `variable→database` | a | 1 键(field×1) | HighVariable.symbol |
| SCC-BASE | `variable→type_system` | a | 1 键(field×1) | TypeCell(pub RwLock<Arc<Datatype>>) |
| E7 | `variable→varnode` | c | 2 键(field×2) | HighVariable.instances/name_representative |
| E16-1 | `varmap→arch` | c | 1 键(field×1) | ScopeLocal.arch_lookup: Architecture |
| E9 | `varmap→database` | a | 1 键(field×1) | ScopeLocal.live_symbols: Arc<RwLock<BTreeMap<usize, Arc<RwLock<Symbol>>>>>（OUTSTREAM 2ab140a6 引入;Ghidra include 面同构: varmap.hh:22 `#include "database.hh"` + :212 `class ScopeLocal : public ScopeInternal`——继承本体即 varmap→database 边;live_symbols=ScopeInternal 符号表活句柄 memo 的 Rust 物化[setSymbolProperties 链 database.cc:135-144,CR-OUTSTREAM3 APPROVE];anchor=std 的 Arc/RwLock=堆 `Symbol*` 身份存活的 Rust 生命周期胶水;与 E9 `funcdata→database`.symbol_entry_cache 同族卫星缓存形态,Phase A types-sink 可解。MB31 集成定性: MB30 并入后环棘轮首跑显形,逐边定性后入账[规程 §5 步骤 2-3]） |
| SCC-BASE | `varmap→type_system` | a | 4 键(field×4) | RangeHint/MapState/LocalSymbol/TypeRecommend dtype |
| SCC-BASE | `varmap→varnode` | a | 2 键(field×2) | AddBase.base/index |
| SCC-BASE | `varnode→cover` | a | 1 键(field×1) | Varnode.cover（varnode.hh:143-150 同构） |
| SCC-BASE | `varnode→database` | a | 1 键(field×1) | Varnode.mapentry |
| GLUE | `varnode→fspec` | glue | 1 键(field×1) | Varnode.call_spec: Weak<FuncCallSpecs>（Ghidra 编码在 IPTR_FSPEC 整数,varnode L7 < fspec L12 倒置） |
| E7 | `varnode→op` | c | 2 键(field×2) | Varnode.def/descend: Weak<PcodeOp> |
| SCC-BASE | `varnode→type_system` | a | 2 键(field×2) | Varnode.v_type/VarnodeBank.type_factory |
| E7 | `varnode→variable` | c | 1 键(field×1) | Varnode.high ↔ HighVariable.instances |

**impl 级边（E1-E12 中不构成 sink 图边者——预期缺席,物化即 FAIL）**:

| # | 环边 | 分类 | 预期缺席理由 |
|---|---|---|---|
| E1 | typeop→printlanguage | a | TypeOp trait 签名/impl 引用;TypeOpManager 无人持有 → typeop 整体浮动,边不落 types 层 |
| E2 | typeop→printc | a | as_printc_mut 自由函数（impl 层） |
| E3 | varnode→funcdata | a | get_use_point 方法签名（impl 块,非 struct 字段） |
| E4 | block→funcdata | a | finalize_printing_graph 等 5+ 自由函数 |
| E5 | address→varnode | b | functional_equality level-0 副本（自由函数,伪影;正主 expression.rs:732;唯一仍需的蓝图 C 票） |
| E6 | typeop→op | a | TypeOp trait 签名收 &PcodeOp;trait 无人持有 |
| E8 | marshal→space | a | Decoder/Encoder trait 无人以字段持有（全库仅 `&mut dyn` 方法参数） |
| E9r | 卫星→funcdata（反向） | a | heritage.rs:7/merge.rs:7 use 仅出现在方法体 |
| E10 | varmap→heritage / fspec→varmap / fspec→heritage | a | 全部 impl 级（签名/方法体） |
| E11 | action→analysis | a | impl Action for ActionTypePropagate 内调用 |
| E12i | drillfmt↔drillobserve（impl 边） | a | drillobserve.rs:92/159/191→drillfmt、drillfmt.rs:192→drillobserve 均 impl 级调用（drillfmt 保持 solo 是 E12 家族"双件浮顶可解"的直接证据） |
<!-- ledger-end -->

标签族说明: `SCC-BASE`=HHMIRROR §5 冻结 SCC 的 oracle 本体字段边（.hh include 序合法
下行,字段物化;类 a）· `TRAIT-SIG`=与 E13/E14/E15 同款"被持有 trait 签名"机制但未列入
E 表的家族（PcodeOpSetImpl/SleighSymbolLookup/FlowBlock;类 c）· `E9-ARCH`=Architecture
枢纽持有面（architecture.hh:21-35 include 面同构）· `GLUE`=RUGRA-GLUE 偏离（HHMIRROR
§2 尾注 call_spec + §3 ScoreUnionFields.fd）。

## 5. 白名单维护规程（只进不漏）

1. **新环边出现 → 门禁 FAIL → 禁止直接改 FROZEN_\* 常量塞边**。
2. 按 HHMIRROR §2 方法**逐边定性**: 亲核 Rust 侧精确形态（哪个 struct 字段/trait 签名,
   file:line）+ Ghidra 侧对应（.hh 前置声明/include/同构 include 面）,给出 a/b/c/glue
   分类与处置方案（下沉/浮动/trait 反转/GLUE 修复/字段重构）。
3. 定性结论登记进本文件 §4 账本（新行 + PAIR_TAGS 注记）,commit 说明引用 HHMIRROR 对应
   E-族或新 E-号。
4. `python3 tools/cycle_ratchet.py --emit-freeze --accept-new` 重新生成冻结字面量,人工
   核对 diff（只应出现已定性的新键）后回填 `tools/cycle_ratchet.py`。
5. 破环（改善）方向: 门禁打 `[INFO]`,复核后同法重冻结（白名单缩容是允许的棘轮回退方向）。

### 5.1 重冻结记录 — 2026-10-01（MB51 W1 arena campaign 合入后）

触发: wt/arenaflip（PERF-ARENA-FLIP-0001 七段）合入 master（merge 718a856f）后,
断言 (b) 对 2 个新证据键 FAIL。逐边定性（协议步骤 2,亲核双侧行）:

| 证据键 | Rust 侧 | Ghidra 侧 | 分类 | 处置 |
|---|---|---|---|---|
| `dyn-hold\|struct BankTable\|FlowBlock`（新增） | block.rs:3484-3485 `BankTable.arcs: Vec<Option<Arc<RwLock<dyn FlowBlock…>>>>`——(d)/(f) 段 BlockBank 的 COW 快照表,图属主块存储 | block.hh:365-366 `class BlockGraph : public FlowBlock { vector<FlowBlock *> list; }`——图属主持有块对象表的 id/arena 形态 | c（族内互持,E7 同族） | 入白名单（E7 行已更新） |
| `dyn-hold\|struct BlockCell\|FlowBlock`（新增） | block.rs:3387-3389 `BlockCell.arc: Arc<RwLock<dyn FlowBlock…>>`——bank 槽位持有块句柄+影子 | 同上（槽=存储迭代器形态） | c（族内互持,E7 同族） | 入白名单（E7 行已更新） |

同时消失的 4 个冻结键（全部为改善方向,协议步骤 5,复核后随重冻结吸收）:
- `dyn-hold|struct BlockEdge|FlowBlock`——(e) 段 BlockEdge.point: Arc→BlockId 值化
  （block.hh:57-65 12B Copy 值形态,环边消解）;
- `field|struct ActionPool|op_state`——(c) 段游标 OpId 化（原持 op 句柄字段消失）;
- `field|struct TransformManager|fd`——(g) 段 `*mut Funcdata` 消灭（fd 逐调用穿透）;
- `field|struct PreferSplitManager|data`——(g) 段同族消灭。
边对层面 `prefersplit→funcdata`/`transform→funcdata` 整对消失（[INFO] improvement,环破）。

`--emit-freeze` 重冻结 diff 人工核对: FROZEN_SCC 24==24 恒等（arena 仍 solo 不入环,
**W1 形态核通过**）;FROZEN_SOLO 吸收 arena（+1,58 项）;证据键 180→178（+2 已定性/−4
改善）。重冻结后 `verify_cycle_ratchet.sh` 三断言全 PASS。

### 5.2 白名单增补记录 — 2026-10-01（MB54 blockflipw1 合入后）

触发: wt/blockflipw1（PERF-BLOCKSTORAGE-FLIP-0001 wave 1,merge 33a5ab65）合入
master 后,断言 (b) 对 1 个新证据键 FAIL。逐边定性（协议步骤 2,亲核双侧行）:

| 证据键 | Rust 侧 | Ghidra 侧 | 分类 | 处置 |
|---|---|---|---|---|
| `dyn-hold\|enum BlockKind\|FlowBlock`（新增） | block.rs:3400-3431 `enum BlockKind` 13 变体各持 `Arc<RwLock<dyn FlowBlock…>>`——wave 1 单表化: 原 BankTable.arcs/BlockCell.arc 双存储位的块句柄并入枚举变体载荷（RUGRA-GLUE 注释锚 block.hh:77-80 block_type 闭集存储形态） | block.hh:365-366 `class BlockGraph : public FlowBlock { vector<FlowBlock *> list; }`——图属主持有块对象表（MB51 §5.1 BankTable/BlockCell 同一 oracle 对应物,句柄未变只换表示位） | c（族内互持,E7 同族） | 入白名单（E7 行已更新） |

同时消失的 2 个冻结键（表示层移位吸收,非破环——句柄仍在,证据键随存储位移入枚举）:
- `dyn-hold|struct BankTable|FlowBlock`——BankTable.kinds: Vec<Option<BlockKind>>,
  不再直持 dyn 字段（sink 链经枚举）;
- `dyn-hold|struct BlockCell|FlowBlock`——BlockCell.kind: BlockKind,同上。

`--emit-freeze --accept-new` 增补 diff 人工核对: FROZEN_SCC 24==24 恒等;
FROZEN_SOLO 58==58 恒等（**无成员变化,无新分层事件,纯表示层证据键移位**）;
block→block 证据键 16→15（+1 已定性/−2 移位吸收）。增补后
`verify_cycle_ratchet.sh` 三断言全 PASS。CR-BLOCKFLIPW1 §5 已核
消费层零改动+BANKSTATS 十计数器恒等——本增补是其 SCC 面的机械后果。

### 5.3 白名单增补记录 — 2026-10-03（MB95 perf3 合入后）

触发: wt/perf3（PERF-ALLOCFLOOR-0001 session 3,merge 0038b515）合入 master
后,断言 (b) 对 2 个新证据键 FAIL。逐边定性（协议步骤 2,亲核双侧行）:

| 证据键 | Rust 侧 | Ghidra 侧 | 分类 | 处置 |
|---|---|---|---|---|
| `field\|struct RebuildScratch\|descendants`（新增,cover→op） | cover.rs:554 `RebuildScratch.descendants: Vec<Arc<RwLock<PcodeOp>>>`——PERF3 件② 跨调用保留的 per-level descendants 缓冲（rebuild_worklist 每入口 clear,仅容量跨调用存活;RUDRA-GLUE 注释锚在结构体 doc 注释） | cover.cc:477-496 rebuild——oracle 每级后代经 `beginDescend()` 迭代器在**调用栈**上走查,PcodeOp 引用仅作局部 `const PcodeOp *ref`（cc:565 addRefPoint 参数域）,Cover 结构无任何字段存储 | a（字段持 op 句柄,SCC-BASE 同族;存储位=GLUE 跨调用保留域） | 入白名单 |
| `field\|struct RebuildScratch\|path`（新增,cover→varnode） | cover.rs:552 `RebuildScratch.path: Vec<Arc<RwLock<Varnode>>>`——implied-output path 缓冲,同上保留语义 | cover.cc:480 `vector<const Varnode*> path(1,vn)`——oracle 把 path 保持为 rebuild 的**单栈向量局部**;Rudra 迭代 DFS 将同元素序列提升入保留 scratch（每调用内容==全新 Vec,容量跨调用） | a（字段持 varnode 句柄,SCC-BASE 同族;存储位=GLUE 跨调用保留域） | 入白名单 |

无消失键。`--emit-freeze --accept-new` 增补 diff 人工核对: FROZEN_SCC
24==24 恒等（cover/op/varnode 均为冻结成员,断言 (a) PASS 亲证无成员变化）;
FROZEN_SOLO 58==58 恒等;cover→op/cover→varnode 证据键各 +1（纯新增,无
表示层移位）。增补后 `verify_cycle_ratchet.sh` 三断言全 PASS。缓冲保留
语义（跨调用等值性/五缓冲独立性/线程局部重入/早退路径）已经 CR-PERF3
决定性问题 B 逐缓冲独立裁定（/dev/shm/rudra-reports/CR_PERF3_2026-10-03.md）
——本增补是其 types 图投影面的机械后果。

### 5.4 成员准入重冻结记录 — 2026-10-04（MB101 matchapply 合入后;首次 solo→SCC 成员准入）

触发: wt/matchapply（merge MB101,单 commit `10a4154a`,CR-MATCHAPPLY3 终判 APPROVE）
合入后三断言全 FAIL: 断言 (a)/(c) `ruleaction`（冻结 solo 模块）入环,断言 (b) 12 个
白名单外证据键。**环闭合者恰一条新边**: `action→ruleaction`（held-trait-sig,
MATCHAPPLY seam 签名）;其余 11 键为成员资格浮出的**既有** solo→SCC 字段边
（此前方向合法不入白名单,入环后需入账）。逐边定性（协议步骤 2,亲核双侧行;
Rust 侧行号为合并树实测,Ghidra 侧亲读）:

| 证据键 | Rust 侧 | Ghidra 侧 | 分类 | 处置 |
|---|---|---|---|---|
| `held-trait-sig\|via dyn Rule sig\|Rule`（新增,action→ruleaction,环闭合者） | action.rs:620 `Rule::as_propagate_copy(&self) -> Option<&crate::ruleaction::RulePropagateCopy>`——MATCHAPPLY 混凝土类型 seam（被持有 dyn Rule trait 的默认方法签名引用 ruleaction 具体类型=types 层边;默认 None,RulePropagateCopy 覆写 Some(self);当前零生产调用方——试点窗机器不交付,seam 为复活条件基础设施） | **无对应物**——action.hh:246 单一虚函数 `virtual int4 applyOp(PcodeOp*,Funcdata&) { return 0; }`,基类默认 return 0,oracle 从不对 Rule 做 concrete 下转型（CR-MATCHAPPLY3 问题 A 亲读核实） | glue（RUDRA-GLUE 偏离: Rudra 并行化基础设施） | 准入+入白名单。替代处置「重构 seam 签名保 ruleaction solo」（extension trait 移 ruleaction.rs 或调用点 fn-local 下转型,per R1 不落 types 层）**本批拒绝**: CR-MATCHAPPLY3 APPROVE 覆盖 10a4154a 字节精确,root 集成不改车道 src（机制 C: 实现变更后旧批准自动失效）——seam 复活（per-op 纪元+无锁读+草稿重定位）落地时**必须**把具体类型引用移出被持有 trait 签名,ruleaction 可再出环（A2 types-sink 方向,改善方向允许） |
| `field\|struct AddTreeState\|data` 等 10 键（既有,ruleaction→{funcdata,op,type_system,varnode},成员浮出） | ruleaction.rs:19535-19564 `AddTreeState{data:&'a mut Funcdata, base_op, ptr, ct, base_type, p_rel, multiple, nonmult, distribute_op}` + ruleaction.rs:14916 `PieceNode.op`——全部先于本批存在（MB101 前为 solo→SCC 合法方向边） | ruleaction.hh:44-63 `class AddTreeState{Funcdata &data; PcodeOp *baseOp; Varnode *ptr; const TypePointer *ct; const Datatype *baseType; const TypePointerRel *pRelType; ... vector<Varnode*> multiple; vector<Varnode*> nonmult; PcodeOp *distributeOp;}` + ruleaction.cc PieceNode——字段级同构（.hh include 面: ruleaction.hh:28 `#include "action.hh"` 承载） | a（oracle 本体字段边,SCC-BASE 族;表示层=Arc/RwLock 句柄物化） | 入白名单（成员资格机械后果） |
| `field\|struct PropagateCopyHit\|invn`（新增,ruleaction→varnode） | ruleaction.rs:227 `PropagateCopyHit.invvn: Arc<RwLock<Varnode>>`——MB101 把旧单体 fn-local `candidate: Option<(usize, Arc<RwLock<Varnode>>)>` 载荷命名物化为 pub struct（R1: fn-local 类型不落 types 层,命名后物化该边;载荷逐 token 等价——CR-MATCHAPPLY3 问题 A 机械对照亲证） | 无对应物（oracle 无该命名结构——cc:3929-3952 匹配段的局部候选即载荷本体） | glue（载荷命名物化,零行为） | 入白名单 |

`--emit-freeze --accept-new` 重冻结 diff 人工核对（结构性 diff,非文本亲核）:
FROZEN_SCC 24→**25**（+ruleaction,唯成员变化——**首次 solo→SCC 准入**）;
FROZEN_SOLO 58→**57**（−ruleaction）;FROZEN_EDGES 键 85→90（+5 键/12 证据值,
零删除零漂移: action→ruleaction×1+ruleaction→funcdata×1+ruleaction→op×3+
ruleaction→type_system×3+ruleaction→varnode×4）;PAIR_TAGS 增 5 行账本注记。
重冻结后 `verify_cycle_ratchet.sh` 三断言全 PASS。**披露**: 本准入使核心 SCC
自冻结以来首次扩大（24→25,glue 边驱动,非 oracle 同构新增）;退出路径已在
上表第一行登记（seam 复活时移签名引用出被持有 trait/extension trait 下沉,
或 A2 types-sink 整体推进）——A2 执行者应把 ruleaction 出环列为候选改善项。

## 6. CI 接入（Phase A/A2 执行时启用;当前入库+文档化,不强制）

```bash
tools/verify_cycle_ratchet.sh                 # 退出码即门禁（0/1/2 透传）
tools/verify_cycle_ratchet.sh --json out.json # 机器可读报告
```

A2.5 验收门禁（HHMIRROR §7.3 表）即本脚本;建议接入点=版本化 CI 与机制 F 门禁健康自检
（`tools/check_gate_health.py` 邻位）。**当前阶段（Phase A/A2 未执行）不接入强制门禁**——
避免在分层重构开始前对正常开发产生误伤;A2.0 预检步启用。

## 7. 变异测试证据（2026-09-26,变异树全部在 /dev/shm 拷贝,worktree 零污染）

| # | 变异 | 预期 | 实测 |
|---|---|---|---|
| M0 | 现树（master 9ac04ade） | PASS | ✅ PASS: SCC=24 精确、86 对/186 键白名单全中、56 solo 保持 |
| M1 | memstate↔printlanguage 互持（两个 solo） | FAIL (a)(b)(c) | ✅ rc=1,三断言全 FAIL,见证边 file:line:2+anchor=peer 精确报出 |
| M2 | memstate 持 Varnode + Varnode 持 memstate（拖入冻结 SCC） | FAIL (a)(b)(c) | ✅ rc=1,SCC 24→25 检出,new_members=[memstate],双向边+anchor 报出 |
| M3 | Varnode 新增 arch 字段（SCC 内白名单外新边对） | FAIL 仅(b) | ✅ rc=1,`varnode->arch:field\|struct Varnode\|ratchet_probe_arch` |
| M4 | PcodeOp 新增第二个 Varnode 字段（白名单边对上的新 anchor） | FAIL 仅(b) | ✅ rc=1,`op->varnode:field\|struct PcodeOp\|ratchet_probe_vn`——锚级精度亲证 |
| M5 | 删 Varnode.call_spec（破环改善） | PASS + INFO | ✅ rc=0,`[INFO] improvement: varnode->fspec` 提示重冻结 |

M1 附带亲证: 探针 struct 追加在文件尾（cfg(test) 之后）时不产生边——生产切割反向验证。

## 8. 与 HHMIRROR 终判的条件对应

- §7.2 条件 1（目标表述: 压缩无环图 + 冻结核心 SCC + 环棘轮）→ 本工具是其"环棘轮"件。
- §7.2 条件 4（4 项 trait 反转 C6-C8 默认不排期）→ 若执行,SCC 24→~15,门禁将以
  `[INFO] improvement` 放行并提示重冻结。
- §7.4 A2.5 步（棘轮工具进 CI,复跑 type_deps3 逻辑 + 冻结清单 diff）→ 本工具+wrapper。
