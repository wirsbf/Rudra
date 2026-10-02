# BLOCKSTRUCT-MULTIGOTO-0001 M1 — Ghidra 原文四类决定性语义核对表

日期: 2026-09-22 | Lane AD | oracle = Ghidra 12.0.4 e40ed130
范围: newBlockMultiGoto + ruleBlockGoto isSwitchOut arm + 消费者(checkSwitchSkips /
grabCaseBasic / scopeBreak / markUnstructured / emitBlockSwitch)。
上游报告: /dev/shm/rudra-tests/sb-switch/GP_SWITCH_ROOTCAUSE.md §4 P0-B。

## A. BlockGraph::newBlockMultiGoto (block.cc:1720-1753)

签名逐字: `BlockMultiGoto *BlockGraph::newBlockMultiGoto(FlowBlock *bl,int4 outedge)`

- **引用/输出参数**: `bl` 指针 = 共享图节点(被 identifyInternal 消费,graph slot 被 ret
  替换);返回 `BlockMultiGoto*`(已存在时 = bl 本身,新建时 = 新节点)。
  `targetbl = bl->getOut(outedge)` 与 `isdefaultedge = bl->isDefaultBranch(outedge)`
  均在**任何 mutation 之前捕获**(cc:1724-1725);removeEdge 会双侧删除该边,label 随边
  消失,之后不可再查。`addEdge(targetbl)` 存指针 → gotoedges 持有活对象引用。
- **循环边界/遍历顺序**: 无循环;顺序敏感步骤链。
  - 已是 t_multigoto 分支(cc:1726-1732): addEdge → removeEdge → (isdefaultedge)→setDefaultGoto。
  - 新建分支(cc:1733-1751): new BlockMultiGoto(bl) → **origSizeOut 在 identifyInternal
    前捕获**(cc:1735) → identifyInternal(ret,[bl]) → addBlock(ret) → addEdge(targetbl)
    → `if (targetbl != bl)` { `if (ret->sizeOut() != origSizeOut)` forceOutputNum(
    ret->sizeOut()+1); removeEdge(ret,targetbl) } → (isdefaultedge)→setDefaultGoto。
    targetbl==bl(goto 目标是自环)时边由 identifyInternal 吸收,注释明确不 remove(cc:1748)。
- **计数器/累加器**: 无计数器;`origSizeOut` 一次捕获;forceOutputNum 参数是
  `sizeOut()+1`(恢复被吸收的自环,不是恢复到 origSizeOut)。
- **排序/比较键**: 类型键 `bl->getType()==t_multigoto`;自环键 `targetbl != bl`(指针);
  自环坍缩键 `ret->sizeOut() != origSizeOut`;默认键 `isDefaultBranch(outedge)`
  (edge label & f_defaultswitch_edge)。
- **flag 传播**: selfIdentify cc:925-926 — composite 继承出边时若组件 isSwitchOut 则
  `setFlag(f_switch_out)` ⇒ multigoto 保持 switch 身份,ruleBlockSwitch cc:1652 才能继续。

## B. CollapseStructure::ruleBlockGoto (blockaction.cc:1450-1475)

签名逐字: `bool CollapseStructure::ruleBlockGoto(FlowBlock *bl)`

- **引用/输出参数**: bl 指针;graph.newBlockMultiGoto(bl,i)/newBlockIfGoto(bl)/
  newBlockGoto(bl) 直接变换图;返回 bool(结构已应用)。
- **循环边界/遍历顺序**: `for(int4 i=0;i<sizeout;++i)` — sizeout 循环前捕获;
  **首个 isGotoOut(i) 的 i** 决定路径;三分支顺序: **isSwitchOut → sizeout==2 →
  sizeout==1**(isSwitchOut 最高优先,不看 sizeout);sizeout>2 且非 switch → 无 arm
  匹配,循环继续,最终 return false。
- **计数器/累加器**: 无;`dataflow_changecount += 1` 仅在 sizeout==2 arm 的
  negateCondition(true) 返回 true 时。
- **排序/比较键**: isGotoOut(i) = (label & (f_irreducible|f_goto_edge)) != 0;
  isSwitchOut = (flags & f_switch_out) != 0。

## C. BlockMultiGoto 类方法 (block.hh:573-593, block.cc:2918-2951)

- 构造 `BlockMultiGoto(FlowBlock *bl) { defaultswitch = false; }` — **bl 参数未存**
  (组件由 identifyInternal 挂入 list;getBlock(0)=wrapped)。
- `addEdge(bl)`: gotoedges.push_back — 纯 vector append,**不建图边**。
- `setDefaultGoto()`/`hasDefaultGoto()`: defaultswitch bool。
- scopeBreak(cc:2918-2922): `getBlock(0)->scopeBreak(-1,curloopexit)` — **curexit 被
  丢弃换 -1**,curloopexit 透传;不查 gotoedges。
- nextFlowAfter(cc:2931-2936): 恒返回 `(FlowBlock*)0`(注释:child 不可能是 BlockGoto)。
- printHeader(cc:2924): "Multi goto block "。
- emit(block.hh:588): `getBlock(0)->emit(lng)` — **委托 wrapped,printc.cc 无
  MultiGoto 分支**(grep 证实 printc.cc 零 MultiGoto)。
- markUnstructured: 无覆写 ⇒ BlockGraph::markUnstructured(cc:1249-1256) 纯递归组件。
- encodeBody(cc:2938-2951): 每 gotoedge 一个 TARGET(front leaf index + depth)。

## D. checkSwitchSkips 的 t_multigoto arm (blockaction.cc:1607-1644, arm cc:1630-1635)

- **引用**: switchbl 只读。
- **遍历**: 两次 `for(edgenum=0;edgenum<sizeout;++edgenum)`(扫描/标记),sizeout 捕获。
- **计数器**: defaultnottoexit/anyskiptoexit 是 bool flag。
- **键**: `(!defaultnottoexit) && (switchbl->getType()==t_multigoto)` 且
  `multibl->hasDefaultGoto()` → defaultnottoexit=true — 恢复"被摘除的 default goto 边
  也算 default 未去 exit"语义,使 cc:1637-1642 标记 skip-to-exit 边成立。

## E. BlockSwitch::grabCaseBasic multigoto arm (block.cc:3524-3554, arm cc:3548-3553)

- **引用**: `gotoedgeblock = (BlockMultiGoto*)cs[0]`;getGoto(i) 指针 → addCase。
- **遍历**: 常规 cases 先加(cs[1..],即 ruleBlockSwitch cc:1716-1720 的 out-blocks
  去 exit),**goto cases 后加**;`for(i=0;i<numgoto;++i)`,numgoto 循环前捕获。
- **计数器**: 无。
- **键/坐标**: `addCase(switchbl, gotoedgeblock->getGoto(i), f_goto_goto)` — gt 参数
  固定 f_goto_goto;addCase 内(cc:3495-3516):
  - `basicbl = bl->getFrontLeaf()->subBlock(0)`(case 的底层 basic block);
  - `inindex = basicbl->getInIndex(switchbl)` — **basic 级边查询**(newBlockSwitch
    cc:1912 传入的 switchbl 是 `leafbl->subBlock(0)` = switch 的底层 basic block,不是
    multigoto);basic 级边**未被 removeEdge 触碰**(remove 只动结构 copy 图)⇒ 不会
    LowlevelError("detached");
  - `outindex = basicbl->getInRevIndex(inindex)`(basic 级出边槽);
  - `isdefault = switchbl->isDefaultBranch(outindex)` — 读 **basic 边 label**
    (installSwitchDefaults funcdata_block.cc:687 落在 basic 图,buildCopy 复制 label
    进 copy 图,两边一致);
  - `gototype != 0 ⇒ isexit=false`;否则 `isexit = (bl->sizeOut()==1)`。

## F. BlockSwitch::scopeBreak/markUnstructured (block.cc:3603-3630)

- scopeBreak cc:3618-3629: `if (caseblocks[i].gototype != 0) { if (bl->getIndex()==curexit)
  gototype = f_break_goto; } else { bl->scopeBreak(curexit,curexit); }` — goto case 落在
  switch exit 上时提升为 break("empty break");常规 case 递归 curexit 双传。
- markUnstructured cc:3607-3610: `gototype == f_goto_goto → markCopyBlock(
  caseblocks[i].block, f_unstructured_targ)` — scopeBreak 先跑,已提升为 break 的不标。

## G. PrintC::emitBlockSwitch goto case (printc.cc:3313-3353, arm cc:3334-3337)

- `for(i=0;i<getNumCaseBlocks();++i)`: emitSwitchCase(i,bl) 打标签组 → `if
  (getGotoType(i)!=0) { emit->tagLine(); emitGotoStatement(getBlock(0),getCaseBlock(i),
  getGotoType(i)); } else { body; isExit(i)&&i!=last → break; }` — goto case 无 body、
  无追加 break;标签来自 finalizePrinting(cc:3556-3591,按 label 排序,依赖 jump 表
  label 恢复 = JUMPTABLE-TABLEAPI-0001 / P0-A 范围)。

## TraceDAG goto 标记到达路径(背景确认,scope.cc 不存在 — TraceDAG 在 blockaction.cc)

1. TraceDAG(blockaction.cc:951)在 updateLoopBody(cc:1193-1253)里构建,产出 likelygoto
   FloatingEdge 列表;selectGoto(cc:1260-1277)取一条 → `startbl->setGotoBranch(outedge)`
   (cc:1269)→ 返回 startbl → collapseInternal 以 targetbl 优先重访(cc:1787)。
2. setGotoBranch(block.cc:305-314): edge label |= f_goto_edge;bl |= f_interior_gotoout;
   target |= f_interior_gotoin。
3. ruleBlockGoto 看到 isGotoOut(i) && isSwitchOut() → newBlockMultiGoto。
4. 其他 setGotoBranch 源: clipExtraRoots→markExitsAsGotos(cc:1083-1099,每个未 mark
   出边);checkSwitchSkips(cc:1640,skip-to-exit 表条目);cc:1758(ruleBlockGoto 邻域)。

## Rudra 落点(write-set)

| Ghidra | Rudra |
|---|---|
| block.hh:573-593 BlockMultiGoto 类 | block.rs 新 struct + FlowBlock impl |
| block.cc:1720 newBlockMultiGoto | blockaction.rs new_block_multigoto(CollapseStructure 方法,同 new_block_goto 惯例) |
| blockaction.cc:1456-1458 isSwitchOut arm | blockaction.rs try_rule_goto(先于 sizeout 判定)+ try_rule_if_goto 前置守卫(分派序 if_goto 在 goto 前) |
| blockaction.cc:1630-1635 checkSwitchSkips arm | blockaction.rs check_switch_skips |
| block.cc:3548-3553 grabCaseBasic arm | blockaction.rs try_rule_switch 构建 cases 时追加 gotoedges + BlockSwitch.cases 记 gototype/isdefault |
| block.cc:3613-3630 scopeBreak gototype arm | block.rs BlockSwitch::scope_break_break_cases |
| block.cc:3603-3611 markUnstructured | block.rs BlockSwitch::mark_unstructured_targets |
| printc.cc:3334-3337 goto case 发射 | printc.rs emit_structured_switch 每 case gototype arm |
| block.hh:588 emit 委托 | printc.rs 分派器 MultiGoto → wrapped 委托 |
| identifyInternal 组件类型 | blockaction.rs identify_internal downcast 链 += BlockMultiGoto |

## 已知耦合(非本 lane)

- switch case 真实 label(finalizePrinting 按 label 排序 + recoverLabels)=
  JUMPTABLE-TABLEAPI-0001(P0-A,wt/sb-switchnorm)。Rudra 现状 case_values 为边序占位
  [j];本 lane 的 goto case 同样以 basic 级出边槽占位,不发明 label。
- oracle gp 的 default case 是**常规 case**(body 内部以 BlockGoto 结尾);default 边被
  goto 摘除时按 E 节语义成为 `default:` + goto 语句(无 body)的形态——两种都按原文支持。
