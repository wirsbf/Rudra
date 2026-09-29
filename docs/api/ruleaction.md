# `ruleaction.rs` API Reference

## 2026-09-29：PERF-OPPOOL-0001 规则池派发邻域 miss 路径锁合并（性能恒等重排）

[OPPROF] 钻探（VdbeExec `--one 1055`）将 oppool1 22-28s 残差分解到规则后，
对 miss 路径（>99% 的派发是"试了不改"的纯扫描——正是 oracle 算法形态，
action.cc:836-846 每 op×每 rule 尝试）做**读锁合并**，判定序与判定值逐调用不变
（合并区间内零突变，读锁合并可交换；oracle 对应字段是裸读）：

- `RuleCollectTerms::get_mult_coeff`（ruleaction.cc:82-97）— `isWritten`+`def`
  单次 Varnode 锁；系数 `is_constant`+`get_offset` 单次锁。短路序与返回值不变。
- `RuleCollectTerms::apply_op` 相位 1（cc:122-152）— 前一项的 `(base, coef)`
  跨迭代携带（oracle 每 step 对两成员各调一次 getMultCoeff，但 miss 间零突变，
  携带值≡重读值）；`Arc::ptr_eq` 合并判定与 combine 分支行为不变。
- `RuleMultiCollapse::apply_op` miss 路径（cc:3234-3300）— heritage 预检
  （cc:3243-3244）与 matchlist 构建（cc:3247）合并为单次 op 快照单趟扫描；
  首个非 MULTIEQUAL 分支查找、defining 分支 `nofunc` 判定（cc:3262-3269
  `!written || multiequal` 语义逐字保留）、非匹配分支 MULTIEQUAL 扩展
  （cc:3280-3300）均改单锁批量读。expand 推入序（cc:3290 `push` 序）不变。
- `RuleIndirectCollapse::apply_op`（cc:3191-3192）— `isDead`+`opcode` 合并单次
  indop 读锁。
- `RulePiecePathology::is_pathology`（cc:10434 起）— `isInput`/`isPersist`/`def`
  单次 Varnode 锁；worklist 内 op 的 `opcode`+MARK 标志单次锁（写标志仍独立
  写锁）。worklist/mark 语义不变。

实测：collect_terms 13.7µs/try → 0.89µs/try（−93.5%），multicollapse
2257→1864ns/try。VdbeExec `--one 1055` stdout 字节恒等 + canon/镜面门禁见
车道 OPPPOOL 报告。

## 2026-09-26：ruleaction 14 处 union facing 退化读换 fd-aware 孪生（UNIONRESOLVE-PKG-D-0001）

审计底稿 `docs/alignment_audit/UNION_CONSUMER_AUDIT_2026-09-26.md` §一 ruleaction 表判定的
14 处 divergent 消费点全部换 `crate::unionresolve` 的 fd-aware 孪生
（`vn_type_read_facing`/`vn_type_def_facing`，unionresolve.rs:1898-1929，consult
`fd.union_map`）。oracle 依据 = varnode.cc:626-672 四 facing 方法
（`needsResolution() ? findResolve(op,slot) : this`）+ type.cc findResolve 虚分派
（Pointer/Union map-miss 返 this；**Array 返 element、Struct 返 field[0]、PartialUnion
返 stripped**——零参退化形 varnode.rs:1547 恒返 raw `v_type`，连 needsResolution 检查都无）。

逐站点（slot 键逐一对照 oracle `op->getSlot(this)`）：

- `RuleAddUnsigned::apply_op`（cc:7188）——op 读 constvn（op->getIn(1)）slot 1；
  **12760-63 注释陈述错误一并修正**（原文称零参形"returns the varnode's resolved
  base type"——实为 raw；现读孪生后注释改为描述 consult 语义）；
- `RuleSubRight::apply_op` isPieceStructured 门（cc:7256）——slot 0，SPECIAL_PRINT 标记；
- `RulePtrsubCharConstant::apply_op` 双读（cc:7358/7366）——sb slot 0 read-facing +
  outvn def-facing（`_fd` 参数更名 `fd` 以供孪生穿参）；
- `RuleExpandLoad::apply_op` 三读+outVn（cc:10937/10940/10943/10964）——**defOp 与 op
  两键分派**：10937 用 defOp 读 real_root（=def->getIn(0)）slot 0，10940/10943 用
  LOAD op 读 root_ptr（=op->getIn(1)）slot 1，10964 outVn def-facing。**2026-09-26
  （RASWEEP 车道，RULEACTION-EXPANDLOAD-NONCONST-0001；行引勘正 CR-RASWEEP F2——
  合取 if 语句实际位于 cc:10930，cc:10927 是 `Datatype *elType;` 声明行）**：arm 门
  对齐 cc:10930 合取条件 `defOp->code()==CPUI_INT_ADD && defOp->getIn(1)->isConstant()`
  ——defOp 为 INT_ADD 但 in(1) 非常量时不再提前 `NO_CHANGE`，而是落入 else 臂：
  addOp=None、offset=0、elType 以 LOAD op 键从原 root_ptr 读取（cc:10940/10943
  路径），规则仍可触发；
- `RulePushPtr::apply_op`（cc:6854）——op 读 in(s) slot s；
- `RulePtrArith::verify_preferred_pointer`（cc:6548/6550）——preOp 读 in(preslot)
  slot preslot，**加 fd 参数**；
- `RulePtrArith::evaluate_pointer_expression`（cc:6576/6588）——op 读 in(1-slot)
  slot other_slot + decOp 读 otherVn slot other_idx，**加 fd 参数**（调用点
  RulePushPtr/RulePtrArith apply_op 及 4 个单测同步穿参）；
- `RulePtrArith::apply_op` 输入扫描（cc:6645）——op 读 in(s) slot s；
- `AddTreeState::build_degenerate` 双读（cc:6426/6430）——wordsize 改读 **ctor 缓存的
  `self.ct`**（cc 侧读 `ct` 成员，其来源=cc:6025 consult；Rust ctor 已走孪生，消除了
  原实现 ctor-consult vs buildDegenerate-raw 的不一致）+ out 门换
  `vn_type_def_facing`（原为裸 `v_type`）。

**验证（CARGO_TARGET_DIR=/dev/shm/rugra-targets/pkgd，基=master 46db1767 亲测 A/B）**：
canon curl（3154 行）与 httpd（2026 行）双语料 **字节恒等**（cmp=0；compare
curl 267/0/0、httpd 862/0/0 == 基线，零回退）；镜面棘轮三面 PASS
（curl 110/275、httpd 258/460、vsh 15/55，defects=0/numbering=0，matched 74/29/71，
无重钉）；投影银行 391/391；gcc 审计 104OK/20FAIL、15OK/14FAIL == 常驻基线；
cargo test --lib 1735P/1F（1F=nonzeromask 预存）。**零行为变化的实证机理**：临时
[DBG-PKGD] 探针（20 个孪生调用点全量埋点，提交前剥离）在 httpd 全程记录到
**0 次**孪生结果 ≠ raw 型的 consult——规则期 union map 在活语料的这 14 个站点无
命中（审计"规则期 map 稀疏"预判的实证）；行为等价由 A/B 字节恒等钉死，map-hit
路径（resolved field 型改判 PTR/UINT/piece-structured 门）由 oracle 行为对齐保证。
sq 面（GEN4 第四语料，票外）numbering=7 经真基 A/B 证实为 46db1767 **预存漂移**
（非本车道引入），登记移交 GEN4-GATE4-SQFACE-0001 归因。

机制 C：ruleaction.rs = 主管线 Rule 白名单模块，本改动**待独立复核**（reviewer 须亲读
varnode.cc:626-672、type.cc:586/1192/1298/1944/2137/2517 findResolve 虚分派、
ruleaction.cc 上述九函数，再对四类决定性语义独立核对）。

## 2026-09-23：RuleSubRight lump 臂改用 `fd.op_unlink`（RULEACTION-SUBRIGHT-UNLINK-0001 / ER）

`RuleSubRight::apply_op` 的 lump 臂（ruleaction.rs `// Ghidra: ruleaction.cc:7269` 函数内，
对应 oracle ruleaction.cc:7285 `data.opUnlink(op)`）此前误用
`fd.op_unset_input(op, 0)` —— 只清 slot0、op 仍活、output 未摘，双重偏离
opUnlink（funcdata_op.cc:179-193 = opUnsetOutput + 全部 opUnsetInput + opUninsert，op 死亡）。
被肢解的 SUBPIECE（槽0=共享 `null_slot_sentinel`）保持活态可再被 ActionPool 匹配，
二次落入时 sentinel 被当真 varnode 装入新 op；SetCasts 阶段对该 size-0 free varnode
插 CAST 形成第二读者，触发 `varnode.rs add_descend` panic（=Ghidra varnode.cc:336
throw 的忠实断言，断言无罪）。修复一行：`fd.op_unlink(&PcodeOpRef(op_arc.clone()))`
（载体 funcdata.rs `op_unlink`，注释 `// Ghidra: funcdata_op.cc:179`）替代该
unset；其余不动（bf3f5064 正控：`Free varnode` panic 0 次，未修基线 3/3 必现，
见 /dev/shm/rugra-reports/sb-pcrepanic/LANE_REPORT_EJ.md）。

**附带 RUGRA-GLUE（锁卫生，语义无变化）**：lump 臂入口的
`if let Some(lone) = outvn.read().unwrap().lone_descend()` 的 scrutinee 临时读守卫
在 Rust ≤2024 语义下活到整个 if-let 体结束，而 `op_unlink → op_unset_output →
make_free_prevalidated` 会对同一 outvn 取写锁——同线程 RwLock 非重入即死锁
（确定性单测钉死；EJ 正控的 httpd 15s 超时机制曾掩盖此形态为 TIMEOUT）。守卫提升
为 `let lone_desc = outvn.read().unwrap().lone_descend();` 后落下，`lone_descend`
返回 owned `Option<Arc<_>>`，提前 drop 不可观测。

**单测**（ruleaction.rs tests）：`test_rule_subright_lump_unlinks_original_subpiece`
构造 SUBPIECE(c=4, outvn size 4, a size 8, lone=INT_RIGHT const-shift 8) 命中 lump 臂，
断言 apply 后原 op DEAD（不在 alivelist、output=None、全槽 sentinel）且存活 op
（原 lone→SUBPIECE、新 shiftop）无 null 槽残留。

## 2026-09-23：RulePieceStructure 叶 COPY 的 union 分辨率继承（UNIONRESOLVE-PIPELINE-WIRING-0001 / EN2）

`RulePieceStructure::apply` 存储 walk 的叶 COPY 臂（ruleaction.cc:7661-7681）补上
此前标注 "not modelled in Rugra" 的两行 union 记账：

- **cc:7673-7676**：`vn.getType()` needsResolution 时 `inherit_resolution(vn.type,
  copyOp, 0, node.op, node.slot)` —— PIECE 读边的分辨率继承到新 COPY 的读边
  （vn 的实例类型在 Rust 侧因 `op_set_input` 移动语义提前读取，值语义等价）。
- **cc:7677-7678**：`newType`（getExactPiece 产物或 vn.type 回退）needsResolution
  时 `crate::unionresolve::resolve_in_flow(fd, newType, copyOp, -1)` —— 新 COPY
  的 def 边 last-chance 评分入 `fd.union_map`（piece 代表 union 一部分时解析）。

**验证**：全语料 A/B（亲父 dd22aba5 pristine worktree 重跑）124 curl 函数仅 main
变化（②行 `(char **)`，union 接线本体），29 httpd 函数字节级恒等；RulePieceStructure
路径（glob_set/glob_range/match_url 等 PIECE 梯函数）零行变化；
next_url+match_url 投影 MATCH 保持。

## 2026-09-22：RulePieceStructure 存储地址保留根地址空间（VARGROUP-ABSORB-0001 / PIECESTRUCT-SPACE-0001）

`RulePieceStructure::apply` 的重定位寻址（ruleaction.cc:7643-7695）改为携带根 varnode 的
地址空间：`baseAddr = outvn->getAddr() - baseOffset` 的减法在 Ghidra 保持空间（唯一空间
根 → 所有重定位件仍在唯一空间）；Rugra 此前用无空间 `Address::new(offset)` +
`new_varnode_out` 的 Register 钉死，使 concat 梯的叶子 COPY 与中间件全部落进
Register 空间的唯一式偏移（r0x10000b2e 等），进而触发 splitcopy 二次拆分在寄存器域
重建。现在：地址相等判据按（空间,偏移）双元组（对齐 Ghidra 的全 Address 比较）；
叶 COPY 走 `new_varnode_out_full(size, root_space, addr, op)`；非叶替换走
`new_varnode_in_space`。curl main 实测：0x30d6 调用点 304B 实参梯恢复 oracle 形态
（件落栈地址 fc78..fd8c + 唯一空间梯腿 + setcasts CAST 链）。


## 2026-09-22：VARGROUP-ABSORB-0001 车道探针剥离（无 API 变更）

剥离车道私有 `[DBG]` 诊断探针（wip 1cd9f682/d3755452 声明的临时探针清单含本文件），
源码恢复至车道 f7348207 状态（与 merge-base 36f26db3 同树）。探针结论已记录于
`docs/alignment_docs/VARGROUP_ABSORB_MECHANISM_2026-09-22.md`，无接口/语义变化。


## 2026-08-28：RuleEarlyRemoval 六守卫与 typed dispatch

`RuleEarlyRemoval::apply_op` 按 `ruleaction.cc:25-44` 顺序执行 call、indirect-source、
output、descend、autolive、deadcode-delay 六个守卫，成功后调用完整 `op_destroy`。
`get_opcodes` 覆盖数值 1..73 中全部 72 个 Rust 可表示 live opcode。锁定双侧 fixture
的 14 个 covered records MATCH；Ghidra raw 0/45 bucket、销毁后 NULL input slot 和
完整 Heritage manager 保持 overall `MISMATCH`。

## 2026-08-26：`RulePtrsubCharConstant` 完整守护链接通（MAINDIFF-STRCONST-0001）

此前实现以 `Funcdata::string_table` 命中代理 `Scope::isReadOnly` +
`StringManager::isString`，且无条件把 PTRSUB 转 COPY（跳过 pushConstFurther
传播半段）。本次对齐 `RulePtrsubCharConstant::applyOp`
（ruleaction.cc:7354-7403）与 `pushConstFurther`（cc:7323-7340）的完整语义：

- 守护链：spacebase 输入（cc:7357-7361）→ 常量偏移（cc:7363-7364）→
  输出 `getTypeDefFacing` 为 TYPE_PTR 且 ptr-to `isCharPrint()`
  （cc:7366-7369）→ `Funcdata::is_scope_read_only(symaddr,1,op_addr)`
  （Database 属性区间通道，cc:7372）→ 共享
  `Architecture.string_manager.is_string_typed(symaddr, charsize, opaque)`
  （cc:7375，charsize/opaque 按 stringmanage.cc:166 虚调用投影 basetype）。
  规则与 `PrintC::pushPtrCharConstant`（printc.cc:1698）读同一个
  Address-keyed StringManager，一次正/负缓存两处同答案。
- 传播半段（cc:7378-7391）：非 addr-force 输出先给每个 descendant 一次
  `push_const_further`（PTRADD 槽 0 常量增量折叠，`addval *= in(2)`），全部
  传播成功才 `op_destroy` PTRSUB；任一失败或 addr-force 走 COPY 转换
  （cc:7395-7400，char* 类型随常量携带）。
- descendant 快照对应 oracle 迭代器先 `++iter` 再变换的遍历健壮性。
- （2026-09-22，SB-ORD159-NULLSLOT-0001）回归测试
  `test_rule_ptrsub_char_constant_string_manager_confirms` 的销毁后断言改为
  忠实后置条件：`op_destroy`（cc:7392-7393）逐槽 clearInput（op.cc:98）
  置 NULL 保留槽数——post-destroy `numInput()==2`、两槽均为共享 null 哨兵
  （旧断言 `inrefs.is_empty()` 编码了已修复的 nullable 表示缺口）。

E2E：hugehelp 三个合法字符串地址（0x10ea40/0x111270/0x113ad0）折叠为
字面量，三个非法 UTF-8 地址保持 `&DAT_*` 形态（isString 负缓存拒绝），
与 golden 逐字节一致。

**源代码路径**: `src/ruleaction.rs`

## 2026-08-24：112 个 Rule 名对齐锁定 oracle 构造器字符串

`impl Rule for X` 的 `get_name` 字面量全部改为 oracle ctor 精确名
（如 `trivial_arith→trivialarith`、`mult_neg_one→multnegone`，
ruleaction.hh 各类内联 ctor）。这些名字是 `ActionPool::getSubRule`/
`disableRule`/`print` 的可观察输入；注册序与数量本就一致（oppool1=134 /
oppool2=5 / cleanup=15）。对拍证据：`tests/oracle/action_break_pool_1204`
的 raw universal 树投影（154 Rule + 78 Action 名双侧逐字节一致）。


**状态**: 已核对（当前有效）  
**源代码路径**: `src/ruleaction.rs`
**2026-07-02 修复（R9）**: `RuleTrivialArith` 重写为忠实移植 Ghidra ruleaction.cc:2370-2433——同输入坍缩（`x^x→0`/`x==x→1`/`x!=x→0`/`x^^x→0`/`x&&x→x` 等），输入须 Arc::ptr_eq 或 is_cse_match。原 Rugra 实现做了 `RuleIdentityEl` 的活（`x+0→x`），从不执行同输入坍缩 → `x^x` 残留。getOpList 改为 Ghidra 16 opcode。3 个旧测试（add_zero/mult_one/sub_zero）重定向到 `RuleIdentityEl`（其本应处理），3 个新测试覆盖 x^x→0/x==x→1/distinct-no-change。

## 2026-08-27：`RulePullsubMulti::buildSubpiece` JoinRecord 归属（RULE-PULLSUB-NEWVNODEOUT-0001）

`buildSubpiece` 对齐 `ruleaction.cc:776-839`：join 基底在 `numPieces()>1` 时从最高索引向下扫描 piece 表，按 `skipleft` 消耗片段；只有请求范围完整落在单片内才按该片端序计算地址并创建对应空间的 `newVarnodeOut`。跨片、单片浮点扩展或缺失 JoinRecord 均保留 `newUniqueOut`；非 join 仍按基底空间端序计算。输出创建同步 `assignHigh`、laned-register 检查和属性设置。

**源代码路径**: `src/ruleaction.rs`
**Oracle**: Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`

Rule-based transformations for P-code operations

Corresponds to Ghidra's `ruleaction.hh`. Rules are small, local
transformations that target specific opcodes to simplify the IR.

## 2026-08-13：RuleCollectTerms 定宽系数与常量归并

`RuleCollectTerms::apply_op` 现在按锁定 Ghidra 12.0.4
`ruleaction.cc:107-176` 执行两种定宽加法：相同项系数使用 64 位无符号
`wrapping_add` 后再以项的 storage size mask 截断；常量项也先按 `uintb`
回绕、再按常量 Varnode 的 size 截断。因此 1-byte 的 `0xff + 2` 与 8-byte
的 `UINT64_MAX + 2` 都得到 `1`，不会在 Rust overflow-check 构建中 panic。

常量归并严格从排好序的尾部倒序扫描。`lastconst` 最终指向排序后第一个
非零常量边；该边接收总和，所有后续、未被外层乘法包裹的常量边按原顺序
替换为零。这修复了原正序扫描留下多个非零常量、且选择错误输入槽的问题。

锁定 oracle fixture `tests/oracle/rule_collect_terms_1204.{cc,rs}` 对七组同输入
IR 逐字节比较，包括非溢出、storage-mask 回绕、`uintb` 固定 64 位回绕和结果
为零的相同项系数，以及三组常量归并。目标相关的结构观察保留
block/alive/dead 顺序、parent/SeqNum order、每个输入槽与输出、所有 fixture
追踪和变换新建 Varnode 的 SSA 分类、def 和有序 descendants；仅规范化
allocation-only unique-space offset。这个窄 fixture 不声称观察 PcodeOp/Varnode
的所有非目标 flags、type/symbol/high 状态，也不能消除 `OPBANK-0001`
中 nullable input slot 被 Rugra 临时 sentinel Varnode 代替的 whole-bank 差异。root guard、
`distributeIntMultAdd` 两分支和无可归并项的 NO_CHANGE 路径仍单列为
`UNTESTED`。其他未覆盖路径还包括 helper 的三种系数回退、all-constant 根、
初始零和多于两个常量、multiplier constant-edge skip 与共享 ADD 边界；
多个 `termOrder == 0` 的等价项还需对拍 Ghidra `std::sort` 的 tie 重排顺序；
不能据此把整个 Rule 升为 L3。
因此 runner 的合格结论仅为七个目标结构投影 `PARTIAL_MATCH`，不是逐函数
B2 `MATCH`；整个 Funcdata/VarnodeBank 仍受 `OPBANK-0001` 阻断。
另外，完整架构服务图仍受 `ARCH-0001` 阻断，新建 Varnode 的 TypeFactory 类型身份
仍属 `TYPE-UNKNOWN-0001` 未验证依赖。

## 2026-08-11：FLOAT_INT2FLOAT 零扩展宽度

`RuleUnsigned2Float::apply_op` 和 `RuleInt2FloatCollapse::apply_op` 不再维护局部
宽度近似；两者现在与 Ghidra `ruleaction.cc:9822/9888` 一样调用
`TypeOpFloatInt2Float::preferred_zext_size`。这修正了 1 字节输入（旧值 2、正确值 4）
和 8 字节输入（旧值 8、正确值 9），并由直接编译 Ghidra 12.0.4
`typeop.cc` 的 oracle fixture 验证。此次只确认共享宽度语义；两个 Rule 的完整
CFG/IR 变换仍按各自既有状态管理，不能由本项单独升级为 L3。

## 2026-08-11：Ghidra 12.0.4 引用 bootstrap

`GATE-REF-RULEACTION` 使用锁定 oracle commit
`e40ed13014025f82488b1f8f7bca566894ac376b` 重新核对
`RuleTransformCpool::applyOp`，并将 `ruleaction.rs` 唯一越界的源码引用修正为
实际对应的 `RuleExpandLoad::applyOp` 定义起始行 `ruleaction.cc:10919`。本次只修复
12.0.4 源码引用元数据，不改变 Rust 行为，不产生函数 oracle `MATCH`，也不升级
模块状态。

## 导出的公共 API (Public API)

### `pub struct RuleCollapseConstants`

Rule for collapsing constant expressions

Corresponds to Ghidra's `RuleCollapseConstants` (ruleaction.hh:703-712,
ruleaction.cc:3852-3882)

### `pub fn new() -> Self`

*暂无代码注释*

`impl Rule for RuleCollapseConstants` 关键行为（2026-08-23 对齐重写，租约
RULE-PORT-COLLAPSECONSTANTS-0001）：

- `get_opcodes()` 返回**全部** opcode（`(1..74).filter_map(OpCode::from_i32)`，
  72 个 live 值，slot 45 未用）——Ghidra 该类不覆写 `getOpList`，经基类
  （action.cc:706-713）注册到每个 opcode；与 `RulePropagateCopy` 同形。
- `apply_op()` 忠实移植 ruleaction.cc:3854-3882：
  1. `isCollapsible` 守卫（op.cc:115-125：nocollapse 标志 / isAssignment /
     ≥1 输入 / 全常量 / 输出 ≤ 8 字节）；
  2. `PcodeOp::collapse()`（op.rs，经 `typeop::evaluate_unary/binary` 桥）
     折叠一切一元/二元常量 op，包括 INT_SDIV/SDIV/SREM/REM/LEFT/RIGHT/
     SRIGHT/SUBPIECE/PIECE/BOOL_*/FLOAT_*/2COMP/NEGATE/POPCOUNT/LZCOUNT；
     `None`（C++ LowlevelError/EvaluationError：除零、ternary/special 求值
     型、缺浮点格式）→ `fd.op_mark_no_collapse` + 返回 NO_CHANGE
     （cc:3867-3870 错误路径）；
  3. `fd.new_constant(out_size, val)` 生成折叠常量（cc:3872 newVarnode）；
     markedInput → `collapse_constant_symbol`（op.cc:503-540，须在解链前）；
  4. 倒序 `op_remove_input` 到 slot 1、`op_set_input(vn,0)`、
     `op_set_opcode(COPY)`（cc:3876-3879，经 Funcdata 记账路径）。

### `pub struct RuleTrivialBool`

Rule for simplifying trivial boolean identities (e.g., x && true -> x)

Corresponds to Ghidra's `RuleTrivialBool`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RulePropagateCopy`

Rule for propagating copies

Corresponds to Ghidra's `RulePropagateCopy`

### `pub fn new() -> Self`

*暂无代码注释*

### `impl Rule for RulePropagateCopy`

#### `fn apply_op(&self, op_arc, fd) -> Result<i32>`

1:1 port of `RulePropagateCopy::applyOp` (ruleaction.cc:3926-3957, RULE-PROPAGATECOPY-DRIFT-0001)。
Dispatched on the READER op (registered for all opcodes via base `Rule::getOpList`,
action.cc:706-713): scans input slots ascending, takes the FIRST slot whose input is
written by a COPY and passes the guards — `isReturnCopy` skip (cc:3933), `isWritten`
(cc:3936), COPY opcode (cc:3939), `isHeritageKnown` (cc:3943, don't propagate free's
away from their first use), self-defined throw `LowlevelError("Self-defined varnode")`
(cc:3944-3945, mapped to `Error::Lowlevel`), and marker sub-guards (cc:3946-3952: no
constants into markers / no addrforce outputs / no merging of different addrtieds) —
then replaces exactly that ONE slot via `Funcdata::op_set_input` (funcdata_op.cc:104:
early-out, constant-single-descendant dedup, descend erase+add) and returns 1.
Convergence to "all readers" is the pool's repeat-apply loop. The former drift
(COPY-op dispatch, redirect-all-readers with raw `inrefs[i]` writes + raw
`descend.push`, no guards, stale descend on the COPY's output) is superseded.

Oracle evidence (RULE-PROPCOPY-BOOKKEEP-0001): `tests/oracle/rule_propcopy_1204.{cc,rs}`
+ `tools/run_rule_propcopy_oracle.sh` — 19 records / 9 cases against the locked
12.0.4 oracle (reader-trigger hit, slot-scan unwritten/non-COPY-def skips,
`isHeritageKnown` free-input guard, `return_copy` short-circuit, marker-constant
guard, two-reader descend erase+add bookkeeping, opSetInput constant-dedup fresh
constant, `Self-defined varnode` throw path). Overall PARTIAL_MATCH (OPBANK-0001 /
ARCH-0001 / TYPE-UNKNOWN-0001); the nine target projections are
TARGET_STRUCTURAL_MATCH byte-identical.

#### `fn get_name(&self) -> &str`

`"propagatecopy"` (name literal from the Ghidra ctor, ruleaction.hh:725).

#### `fn get_opcodes(&self) -> Vec<OpCode>`

Base-class default: `(1..74).filter_map(OpCode::from_i32)` — all live opcodes
(Ghidra pushes `0..CPUI_MAX`; the 12.0.4 enum starts at `CPUI_COPY=1`,
`CPUI_MAX=74` is a sentinel never assigned to a live PcodeOp).

### `pub struct RuleZextEliminate`

Eliminate INT_ZEXT in comparisons: `zext(V) == c => V == c`

Corresponds to Ghidra's `RuleZextEliminate` (ruleaction.cc:2471-2526, RULE-BEHAVIORAL-FIVE-0001 M1 重写)
- `get_opcodes`：`[INT_EQUAL, INT_NOTEQUAL, INT_LESS, INT_LESSEQUAL]`（cc:2479-2485，dispatch 的是比较 op，不是 zext）
- `apply_op`：比较的一侧由 INT_ZEXT 写出、另一侧是常量、zext 输出 loneDescend、zext 输入 heritage-known、
  且 `val >> (8*smallsize) == 0`（常量在小尺寸下无高位损失，cc:2516）时，把比较输入替换为
  `zext->getIn(0)` 与 resize 后的常量（`copySymbolIfValid` 继承符号，cc:2517-2521）。
  zext 在 slot 0/1 均可（cc:2501-2506 swap）。旧实现 dispatch INT_ZEXT 做 same-size zext→COPY，
  属 Ghidra 此 Rule 从不执行的算法，已删除。

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleSextEliminate` — 已删除（PIPE-POOL-LOCAL-RULES-0001，2026-08-23）

**struct 连同注册一并删除。** 锁定 oracle（e40ed130）全源码树中不存在任何名为
`RuleSextEliminate` 的类——它是 Rugra 自创并在 oppool1 末尾注册的规则（铁律 1.4
存量违例）。注册与其 struct 定义（原含"same-size INT_SEXT → COPY"折叠逻辑）已删除；
oracle 池序 fixture `tests/oracle/pool_purity_1204` 证明删除后 oppool1 与 oracle
逐条一致。同类 same-size SEXT 场景若 oracle 有处理，应由 oracle 真实规则承担。

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleTrivialArith`

Rule for simplifying trivial arithmetic identities

Corresponds to Ghidra's `RuleTrivialArith`.
Simplifies: `x + 0 → x`, `x - 0 → x`, `x * 1 → x`,
`x ^ 0 → x`, `x | 0 → x`.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleShiftBitops`

Shifting away all non-zero bits of one side of a logical/arithmetic op

Corresponds to Ghidra's `RuleShiftBitops` (ruleaction.cc:476-566, RULE-BEHAVIORAL-FIVE-0001 M4 重写)
- `get_opcodes`：`[INT_LEFT, INT_RIGHT, SUBPIECE, INT_MULT]`（cc:481-488；旧注册含 INT_SRIGHT 且只做
  shift-by-0→COPY，已对齐）。shift-by-0→COPY 是 RuleTrivialShift（cc:3496-3522）的职责。
- `apply_op`：常量移位（LEFT/RIGHT 直接取值、SUBPIECE 按 `offset*8` 字节、MULT 按
  `leastsigbit_set`，cc:501-522）作用于 INT_AND/OR/XOR（任方向）或 INT_ADD/INT_MULT（仅左移，
  cc:525-536）的结果时，逐 bitop 输入检查 `getNZMask << sa & calc_mask(outsize)`，某侧可能非零位
  全被移走（cc:539-548）则：AND/MULT → 输入0 换 `#0`（结果必为 0）；ADD/XOR/OR → 输入0 换另一侧
  （该侧贡献为零，需 heritage-known，cc:549-564）。
- 本模块新增 `pcode_left`/`pcode_right`（address.hh:505/514）。nzm 读取经
  `Varnode::get_nzm()`/`get_nz_mask()`（varnode.hh:231，直接返回 `nzm` 字段）：字段由构造函数
  初始化（varnode.cc:590-606：常量=offset、其他=~0），并由 `Funcdata::calcNZMask`
  （funcdata_varnode.cc:856-927）前向精化——主管线中 `ActionNonzeroMask`（coreaction.cc:5507）
  每轮先于规则池运行，故本 Rule 在主管线读到的是传播后的 nzm
  （例：`(X + (W & 0x80)) << 7` 于 1 字节值因 AND 输出 nzm=0x80 而触发）。
  曾内联的 `nz_mask_exact`（"nzm 仅构造函数写入"的错误前提）已随 REJECT 复核删除。

### `pub fn new() -> Self`

*暂无代码注释*

 
## 2026-06-26：新增 RuleNegateIdentity（ruleaction.cc:444-474）

### `pub struct RuleNegateIdentity`
应用 INT_NEGATE 恒等式：`V & ~V => #0`，`V | ~V => #-1`，`V ^ ~V => #-1`。
忠实移植 Ghidra `RuleNegateIdentity`。

- `apply_op`：当 `INT_NOT(V)` 的输出被一个 `INT_AND`/`INT_OR`/`INT_XOR` 读取，且该逻辑 op 的另一输入正是 V 时，将该逻辑 op 折叠为 `COPY(0)`（AND）或 `COPY(all-ones)`（OR/XOR）。
- `get_opcodes`：`[CPUI_INT_NOT]`（注意：Rugra `CPUI_INT_NOT` == Ghidra `INT_NEGATE`；Rugra `CPUI_INT_NEG` == Ghidra `INT_2COMP`）。

测试：ruleaction::tests 3 个新增（AND→0、OR→全1、无匹配→NO_CHANGE）。

### 2026-06-26（续）：Funcdata op-edit API + RuleNotDistribute

#### Funcdata op-edit API（解锁创建/改写 P-code 的 Rule）
见 docs/api/funcdata.md。

#### `pub struct RuleNotDistribute`（ruleaction.cc:1139-1183）
德摩根律：`!(V && W) => !V || !W`，`!(V || W) => !V && !W`。
- `apply_op`：BOOL_NOT(BOOL_AND/OR(V,W)) → 创建两个 BOOL_NOT(V)/BOOL_NOT(W)，
  原 op 改写为对偶逻辑 op（AND↔OR）。
- `get_opcodes`：`[CPUI_BOOL_NOT]`（Rugra CPUI_BOOL_NOT == Ghidra BOOL_NEGATE）。

测试：ruleaction::tests +2（AND→OR、非 bool 内层 NO_CHANGE）+ Funcdata API +3。

### 2026-06-26（续）：RuleConcatZero + RuleXorCollapse

#### `pub struct RuleConcatZero`（ruleaction.cc:4977）
`concat(V, 0) => zext(V) << c`。当 PIECE 的低位(in1)是全 0 常量时，
改写为 INT_LEFT(INT_ZEXT(V), 8*low_size)。用 Funcdata op-edit API 创建 ZEXT op。

#### `pub struct RuleXorCollapse`（ruleaction.cc:4058）
消除比较中的 XOR：
- `(V ^ c) == d => V == (c^d)`（常量项折叠）
- `(V ^ W) == 0 => V == W`（移项）
- 要求 xor 输出为 lone descend（loneDescend）。

测试：ruleaction::tests +4（ConcatZero 折叠/非零不变；XorCollapse 常量折叠/移项）。

### 2026-06-26（续）：RuleAddMultCollapse

#### `pub struct RuleAddMultCollapse`（ruleaction.cc:4099-4183）
折叠加法/乘法中的常量：
- `((V + c) + d)  =>  V + (c+d)`
- `((V * c) * d)  =>  V * (c*d)`
主形式：当 op(in0=sub, in1=const) 且 sub 由同 op-code 定义且其 in1 也是常量时，
折叠两常量。spacebase 子情形（4131-4169）待 isSpacebase/isInput 跟踪后补。

测试：ruleaction::tests +2（双加折叠、双乘折叠）。

### 2026-06-26（续）：RuleLess2Zero + RuleLessEqual2Zero

#### `pub struct RuleLess2Zero`（ruleaction.cc:5557-5603）
INT_LESS 与极值常量（0 或全1）的简化：
- `0 < V  => 0 != V`；`V < 0 => false`；`ffff < V => false`；`V < ffff => V != ffff`

#### `pub struct RuleLessEqual2Zero`（ruleaction.cc:5605-5651）
INT_LESSEQUAL 与极值常量的简化：
- `0 <= V => true`；`V <= 0 => V == 0`；`ffff <= V => ffff == V`；`V <= ffff => true`

辅助：`fn calc_mask(size)` 对应 Ghidra calc_mask。

测试：ruleaction::tests +4（Less2Zero 两态、LessEqual2Zero 两态）。

### 2026-06-26（续）：RuleBoolNegate + get_booleanflip + op_swap_input

#### `pub fn get_booleanflip(opc, &mut reorder) -> OpCode`（opcodes.cc:94-135）
比较 op 的互补翻转表。EQUAL↔NOTEQUAL（不换序）；LESS↔LESSEQUAL、SLESS↔SLESSEQUAL（换序）；BOOL_NOT→COPY；FLOAT_* 同理。非可翻 op 返回 CPUI_MAX。

#### `Funcdata::op_swap_input(op, slot1, slot2)`（funcdata.hh）
交换两输入操作数（用于 RuleBoolNegate 翻转比较时的换序）。

#### `pub struct RuleBoolNegate`（ruleaction.cc:5516-5555）
将 BOOL_NOT 推过比较 op：
- `!!V => V`（内层 BOOL_NOT → COPY，外层也 → COPY）
- `!(V == W) => V != W`；`!(V < W) => W <= V`（换序）；`!(V <= W) => W < V`；`!(V != W) => V == W`
要求比较输出仅被 BOOL_NOT 消费（ALL descendants must be negates）。

测试：ruleaction::tests +3（双否定塌缩、LESS→LESSEQUAL 换序、非 BOOL 后代 NO_CHANGE）。

### 2026-06-26（续）：RuleOrMask + RuleAndOrLump

#### `pub struct RuleOrMask`（ruleaction.cc:276-300）
`V | 0xffff => COPY(0xffff)`。当 OR 的常量覆盖输出 size 的所有位时，
结果就是该常量 → COPY。size=0 或 >8 时跳过（uintb 精度）。

#### `pub struct RuleAndOrLump`（ruleaction.cc:403-442）
折叠逻辑表达式的常量：
- `(V & c) & d => V & (c & d)`
- `(V | c) | d => V | (c | d)`
- `(V ^ c) ^ d => V ^ (c ^ d)`
模式同 AddMultCollapse，但用于 AND/OR/XOR。

测试：ruleaction::tests +4（OrMask 全掩码/部分不变；AndOrLump 双 AND/双 OR）。

### 2026-06-26（续）：RulePiece2Zext + RulePiece2Sext + RuleBxor2NotEqual

#### `pub struct RulePiece2Zext`（ruleaction.cc:207-230）
`concat(0, V) => zext(V)`。PIECE 的高位(in0)为常量 0 时，塌缩为 INT_ZEXT。

#### `pub struct RulePiece2Sext`（ruleaction.cc:232-259）
`concat(V s>> (8*size-1), V) => sext(V)`。PIECE 高位是低位的符号位算术右移时，塌缩为 INT_SEXT。

#### `pub struct RuleBxor2NotEqual`（ruleaction.cc:261-274）
`V ^^ W => V != W`。布尔 XOR 等价于布尔不等。

测试：ruleaction::tests +3（Piece2Zext、Piece2Sext、Bxor2NotEqual）。

### 2026-06-26（续）：RuleTermOrder + RuleShift2Mult

#### `pub struct RuleTermOrder`（ruleaction.cc:645-674）
交换交换律 op 的输入，使常量在 slot 1（`INT_ADD(5,V) => INT_ADD(V,5)`），消除表达式组合爆炸。

#### `pub struct RuleShift2Mult`（ruleaction.cc:3704-3751）
将参与算术（INT_ADD/SUB/MULT）或其输入由算术定义的常量左移转为乘法：
`(V << c) => V * (1<<c)`，c<32。**oplist 仅 INT_LEFT**（cc:3708-3712；
RULE-BEHAVIORAL-FIVE-0001 M5 修复：旧注册含 INT_RIGHT，会把 `V >> c` 错改写为
`V * 2^c`，属 Ghidra 不可能产生的语义反转，已移除）。

测试：ruleaction::tests +2（oplist 仅 LEFT、INT_RIGHT 不 dispatch）。

测试：ruleaction::tests +4（TermOrder 交换/已序不变；Shift2Mult 喂入 ADD 转乘/非算术不变）。

### 2026-06-26（续）：RuleDoubleSub + RuleTrivialShift

#### `pub struct RuleDoubleSub`（ruleaction.cc:1796-1823）
`sub(sub(V,a),b) => sub(V, a+b)`。链式 SUBPIECE 折叠，跳过中间层。

#### `pub struct RuleTrivialShift`（ruleaction.cc:3515-3542）
平凡移位简化：
- `V << 0 => COPY(V)`
- `V << c (c >= 8*size, 逻辑移位) => COPY(0)`
- INT_SRIGHT 超 size 不变（无法预测符号位）

测试：ruleaction::tests +4（DoubleSub 折叠；TrivialShift 移0/超size归零/sright超size不变）。

### 2026-06-26（续）：bit helpers + get_nz_mask + RuleSlessToLess

#### Bit 助手（address.rs，对应 address.cc:641-745）
- `signbit_negative(val, size)` — address.cc:641，符号位是否为负
- `calc_mask(size)` — address.hh:577，全1掩码
- `leastsigbit_set(val)` — address.cc:714，最低有效位索引（-1 若 0）
- `mostsigbit_set(val)` — address.cc:735，最高有效位索引

#### `Varnode::get_nz_mask()`（varnode.hh:231）
非零掩码，直接返回 `nzm` 字段（FUNCDATA-CALCNZM-0003）。字段由构造函数初始化
（varnode.cc:590-606：常量=offset、其他=~0）并由 `Funcdata::calcNZMask`
（funcdata_varnode.cc:856-927）前向精化（DFS `getNZMaskLocal` 赋输出 + MULTIEQUAL
worklist）；主管线 `ActionNonzeroMask`（coreaction.cc:5507）每轮 mainloop 先于规则池运行。
此前记录的"nzm 仅在构造函数设置、从不被 refine"是错误前提（独立复核证伪），已更正。

#### `pub struct RuleSlessToLess`（ruleaction.cc:2548-2573）
当两操作数的 NZMask 表明符号位为 0（均为已知非负）时，将 INT_SLESS→INT_LESS、INT_SLESSEQUAL→INT_LESSEQUAL。

测试：address.rs +4（signbit_negative/calc_mask/leastsigbit/mostsigbit）；ruleaction::tests +3（SlessToLess 正常/负不变/Slessequal）。

### 2026-06-26（续）：RuleOrCollapse + RuleConcatLeftShift

#### `pub struct RuleOrCollapse`（ruleaction.cc:373-401）
`V | c => c` 当 NZM(V)|c == c（V 能置位的位都已被 c 覆盖）→ COPY。用 get_nz_mask。

#### `pub struct RuleConcatLeftShift`（ruleaction.cc:5004-5042）
`concat(V, zext(W) << c) => concat(concat(V, W), 0)`。当 PIECE 低位是 zext(W) 的对齐左移（c 为 8 倍数且移到最高有效边界）时，重构为两级 PIECE。用 op-edit API 创建新 PIECE op。

测试：ruleaction::tests +3（OrCollapse 覆盖/部分不变；ConcatLeftShift 重构）。

### 2026-06-26（续）：RuleDoubleShift + lone_descend/has_no_descend

#### `Varnode::lone_descend()` / `has_no_descend()`（varnode.hh）
单后代 / 无后代查询，解锁 RuleDoubleShift/RuleSubZext 等需独占使用检查的 Rule。

#### `pub struct RuleDoubleShift`（ruleaction.cc:1825-1941）
链式移位简化：
- 同向：`(V<<c)<<d => V<<(c+d)`；`(V>>c)>>d => V>>(c+d)`
- 反向（等量）：`(V<<c)>>c => V & mask`；`(V>>c)<<c => V & mask`
- INT_MULT 乘 2 的幂视为左移（leastsigbit_set）
- 移位 ≥ size 时归零为 COPY(0)

测试：ruleaction::tests +2（同向合并 2+3=5；反向抵消 LEFT4/RIGHT4 → AND 0x0fffffff）。

### 2026-08-23：RuleIdentityEl opcode dispatch / raw name

#### `pub struct RuleIdentityEl`（ruleaction.cc:3668-3702）
锁定 Ghidra 12.0.4 仅将该 Rule 注册到 `INT_ADD`/`INT_XOR`/`INT_OR`/
`BOOL_XOR`/`BOOL_OR`/`INT_MULT`，顺序与 `getOpList` 完全一致。旧实现错把
`INT_SUB` 和 `INT_AND` 放进派发集，同时漏了两个 BOOL opcode；现已纠正。

通过 ActionPool 的可见转换是：
- `V + 0 / V ^ 0 / V | 0 / V ^^ 0 / V || 0 => COPY(V)`
- `V * 1 => COPY(V)`；`V * 0 => COPY(0)`
- `V - 0` 与 `V & 0` 不会被该 Rule 派发，因此保持原样。

Rule 的 raw name 也按 `ruleaction.hh:675` 从 `identity_el` 修正为
`identityel`，用于 ActionPool 子 Rule 查找和统计/警告标识。锁定 oracle fixture
`tests/oracle/rule_identityel_opcodeset_1204.{cc,rs}` 通过真实 ActionPool
观察 opcode 派发、输入身份、Varnode descendant 顺序和 Rule/Action 计数。
Rust ActionPool 尚未提供 Ghidra `getSubRule` 的生产 API，因此整体状态保持
`MISMATCH`，绑定 `ACTION-EXECUTOR-BREAKPOOL-0001`；其余 111 个 Rule raw-name 差异归
`PIPE-RULE-RAW-NAMES-0001`，本窄批不扩展修改。

### 2026-06-26（历史）：RuleSignShift

#### `pub struct RuleSignShift`（ruleaction.cc:3544-3600）
符号位提取规范化：`V >> 0x1f => (V s>> 0x1f) * -1`。当逻辑右移符号位参与算术（INT_ADD/MULT）或常量比较时，转为算术右移乘全1。

测试：ruleaction::tests +5（IdentityEl 加0/乘1/乘0；SignShift 算术触发/COPY不变）。

### 2026-06-26（续）：RuleSubZext + op_set_output

#### `Funcdata::op_set_output(op, vn)`（funcdata.hh）
设置/替换 op 的输出 varnode（标记 WRITTEN、设 def 链）。

#### `pub struct RuleSubZext`（ruleaction.cc:5044-5100）
简化 ZEXT(SUBPIECE)：
- `zext(sub(V, 0)) => V & mask`（偏移0，绕过截断）
- `zext(sub(V, c)) => (V >> c*8) & mask`（中间偏移，需 sub 输出为 lone descend）
- `zext(sub(V, off) >> sa) => (V >> (off*8+sa)) & (mask_of_subsize >> sa)`
  （INT_RIGHT 臂，ruleaction.cc:5073-5097：移位改读全宽基值、组合移位量
  `off*8+sa`，ZEXT 变 AND 掩码 `calc_mask(subsize)>>sa`；mid（SUBPIECE 输出）
  须为 shift 的 loneDescend、shift 输出须为 ZEXT 的 loneDescend；新移位常量
  保持原移位常量尺寸（cc:5092）。**2026-09-28 补齐（SELECTGOTO2 车道，
  wt/selectgoto）**：旧移植只带主 SUBPIECE 臂，本臂缺失使
  `shr $2,%r13b` 型字节移位链无法拓宽回全宽——sq NPat2R9 GetLongestMatch
  的 round-2→3 窗口 nodejoin join 对（0x3560f/0x3561d）在
  functionalEqualityLevel 因 cond 尺寸 1 vs 8 恒拒，级联 6 克隆族 sq 阻塞；
  补齐后五轮 bbsig 与 oracle 恒等、6 克隆族 656→49 行。）

测试：ruleaction::tests +2（偏移0 绕过→AND；中间偏移→SUBPIECE 改 RIGHT(32)）；
+2（2026-09-28：INT_RIGHT 臂 off=0/sa=2 → `V>>2 & 0x3f` 与 shift 直读全宽基值；
中间偏移 off=4/sa=2 → `V>>34 & 0x3fffffff` 组合移位量）。

### 2026-06-26（续）：RuleConcatShift

#### `pub struct RuleConcatShift`（ruleaction.cc:1969-2014）
移位连接的变换：当右移位（有符号/无符号）把 PIECE 的最低有效片段整体移走时，
`(concat(main, least) >> sa) => zext/sext(main) >> (sa - leastbits)`。
精确抵消时退化为 zext/sext(main)。

**2026-09-27 修正（GEN4-SQ-CASTFUSE-DEPTH-0001，Lane CASTFUSE-DEPTH）**：
对齐 oracle `getOpList`（ruleaction.cc:1952-1957）——**只注册
`CPUI_INT_RIGHT`/`CPUI_INT_SRIGHT`，不注册 `CPUI_INT_LEFT`**。左移永远无法把
最低有效片段移走（`INT_LEFT(PIECE(hi,lo),sa≥8|lo|)` 的 lo 字节仍留在低位），
旧实现对 INT_LEFT 的重写是**改值**的（canonical 站点 CodeSpec@0x23478：
golden `iVar9 << 8` vs Rugra `(int)(int3)uVar4`，丢 xVar7 且 hi 位移错）。
移除后 INT_LEFT 保持读 4B CONCAT 输出 → PIECE 保住第二读者 → explicit
命名 temp（fusion-depth 分歧根因，sq CAST-SHAPE 1176 pair 族主体）。
同函数次要对齐：`sa2 != 0` 分支的新移位常量尺寸取原移位常量尺寸
（`op->getIn(1)->getSize()`，ruleaction.cc:1990），不再硬编码 4。

测试：ruleaction::tests +3（精确抵消→ZEXT；部分不移完→NO_CHANGE；
左移不注册 dispatch 列表恒等 `[INT_RIGHT, INT_SRIGHT]`）。

### 2026-06-26（续）：RuleShiftCompare

#### `pub struct RuleShiftCompare`（ruleaction.cc:2064-2168）
移位比较变换：将比较一侧的常量移位移到另一侧。
- `V >> c == d => V == (d << c)`（右移需 loneDescend）
- `V << c == d => V == (d >> c)`
- INT_MULT/INT_DIV 乘除 2 的幂视为移位（leastsigbit_set）
当 NZM 表明移位丢信息时不转换（AND-mask 子形式暂缓）。

测试：ruleaction::tests +2（左移丢高位不变；右移寄存器丢低位不变——记录保守 NZM 行为，待 Heritage 提供 NZM 后可触发）。

### 2026-06-26（续）：RuleAndCompare

#### `pub struct RuleAndCompare`（ruleaction.cc:1729-1796）
AND-比较变换，把 AND 推到更大的定义域：
- `(sub(V,c) & mask) == 0 => (V & (mask << c*8)) == 0`
- `(zext(V) & mask) == 0 => (V & mask) == 0`
当 AND 常量 != calc_mask（非退化）且 basevn 非 free 时，创建新的 INT_AND(basevn, adjusted_mask) 并改写比较。

测试：ruleaction::tests +1（zext 推送：in1 归零到 base size）。

### 2026-06-26（续）：RuleTestSign

#### `pub struct RuleTestSign`（ruleaction.cc:3602-3677）
符号位测试转有符号比较：
- `(V s>> 0x1f) != 0 => V s< 0`
- `(V s>> 0x1f) == 0 => V s<= 0`
- `(V s>> 0x1f) == -1 => V s< 0`（互补域）
遍历 SRIGHT 输出的后代比较，改写为 INT_SLESS/INT_SLESSEQUAL vs 0。

测试：ruleaction::tests +2（NOTEQUAL→SLESS；EQUAL→SLESSEQUAL）。

### 2026-06-26（续）：RuleEquality + functional_equality

#### `fn functional_equality(vn1, vn2) -> bool`（expression.cc:520, level-0:404）
判断两 varnode 是否持有相同值（立即层）：同指针或同常量。深层 functionalEqualityLevel 待补。

#### `pub struct RuleEquality`（ruleaction.cc:619-643）
`f(V,W) == f(V,W) => true`，`f(V,W) != f(V,W) => false`。两输入功能相等时塌缩为 COPY(1/0)。

测试：ruleaction::tests +3（同 varnode→COPY(1)；同常量 NOTEQUAL→COPY(0)；异常量不变）。

**2026-08-23 注册移除（PIPE-POOL-LOCAL-RULES-0001）**：锁定 oracle 定义了该类
（ruleaction.hh:243-250，方法体 ruleaction.cc:624/631）但**从未实例化**——全树无
`new RuleEquality`，coreaction.cc 的 buildUniversalAction 也不在任何池注册它（oracle
死代码）。Rugra 已从 oppool1 移除其注册；struct 与 3 个单测保留为未注册存档
（"oracle 死代码，仅存档"），与 oracle 自身的死代码状态 1:1。字面语义注记：oracle
applyOp 在 `opSetOpcode(op,CPUI_COPY)` **之后**才读 `op->code()`
（ruleaction.cc:638/640），常量表达式恒为 0；Rugra 移植在变更前捕获 opcode
（实现文档化意图）。因 oracle 类为死代码，该差异不可观测。

### 2026-06-26（续）：RuleLessNotEqual

#### `pub struct RuleLessNotEqual`（ruleaction.cc:2310-2357）
`(s)lessequal AND notequal`（同操作数对）折叠为 `(s)less`：
`V <= W && V != W => V < W`。用 functional_equality 验操作数匹配。

测试：ruleaction::tests +1（LE+NE 同操作数→LESS）。

### 2026-06-26（续）：RuleLessEqual

#### `pub struct RuleLessEqual`（ruleaction.cc:2247-2308）
`(s)less OR equal`（同操作数对）折叠为 `(s)lessequal`：
- `V < W || V == W => V <= W`
- `V < W || V != W => COPY(NOTEQUAL 输出)`（NOTEQUAL 占优）

测试：ruleaction::tests +1（LESS+EQUAL 同操作数→LESSEQUAL）。

### 2026-06-26（续）：RuleRightShiftAnd + RuleHighOrderAnd

#### `pub struct RuleRightShiftAnd`（ruleaction.cc:575-600）
`(V & mask) >> sa` 当 mask==full>>sa 时绕过 AND：`(V & full) >> sa => V >> sa`。

#### `pub struct RuleHighOrderAnd`（ruleaction.cc:1185-1250）
对齐 INT_ADD 的 INT_AND 简化（mask 形如 11110000）：
`(V + c) & 0xfff0 => V + (c & 0xfff0)`，要求 addend 的 NZM 高位为零。移植了常量 addend 主分支。

测试：ruleaction::tests +2（RightShiftAnd 绕过；HighOrderAnd 寄存器 NZM=full→正确 NO_CHANGE）。

### 2026-06-26（续）：RuleAndZext

#### `pub struct RuleAndZext`（ruleaction.cc:1697-1732）
`sext(V) & mask => zext(V)` 与 `concat(a, V) & mask => zext(V)`，当 mask 恰为根值的 full mask 时。AND 冗余等价于零扩展。

测试：ruleaction::tests +1（sext 全掩码→zext）。

### 2026-06-26（续）：RuleZextSless

#### `pub struct RuleZextSless`（ruleaction.cc:2575-2618）
`zext(V) s< c => V < c` 当 c 足够小（高位全0，V 的符号位必为 0）时，去掉零扩展，转为无符号比较。常量缩减到 small size。

测试：ruleaction::tests +2（小常量→LESS；大常量符号位风险→NO_CHANGE）。

### 2026-06-26（续）：RuleScarry + RuleSborrow（trivial 分支）

#### `pub struct RuleScarry`（ruleaction.cc:3430-3493，全量）
#### `pub struct RuleSborrow`（ruleaction.cc:3361-3412，全量）

**2026-08-25（MAINDIFF-UNIQLEAK-0001）补齐 AddExpression 深形式**（此前仅 trivial 分支）：

- trivial：`scarry(V,0)/scarry(0,V)/sborrow(V,0) => COPY(0)`。
- SBORROW 深形式（ruleaction.cc:3376-3410）：遍历 SBORROW 输出的后代，找
  `INT_EQUAL/INT_NOTEQUAL`，其另一输入是 `INT_SLESS(x, 0)`；用
  `AddExpression::gather_two_terms_subtract(avn, bvn)` 与
  `gather_two_terms_root(xvn)` 比对，等价则折叠：
  - `sborrow(V,W) != (V-W s< 0)  =>  V s< W`（compop→INT_SLESS）
  - `sborrow(V,W) == (V-W s< 0)  =>  W s<= V`（compop→INT_SLESSEQUAL）
- SCARRY 深形式（ruleaction.cc:3447-3492）：常量侧归一化（slot0 常量则交换
  avn/bvn），排除整型最小值（signbit mask）；`gather_two_terms_add` 比对；
  折叠时把比较常量换成 `-W & mask` 的 newConstant：
  - `scarry(V,#W) != (V+#W s< 0)  =>  V s< -#W` 等 4 形式。

实现依托 `src/expression.rs` 已有 `AddExpression`/`functional_equality`
（expression.cc:299-526）。E2E 效果：curl main 的 gcc 循环守卫模式
`sborrow(argc,1) != (argc-1 s< 0)` 折叠为 `argc < 2`（与 12.0.4 golden 一致），
消除 implied flag varnode 走 `pushUnnamedLocation`（printc.cc:1938）打印
`register0x…` 裸名并被文本回填声明的泄漏类。

测试：ruleaction::tests 3 个（Scarry 零→COPY(0)；Sborrow 零→COPY(0)（fixture
补 output 以镜像 oracle `op->getOut()` 不变量）；Sborrow 非零不变）。

### 2026-06-26（续）：RuleAndDistribute

#### `pub struct RuleAndDistribute`（ruleaction.cc:1252-1314）
当分配 INT_AND 过 INT_OR 能简化时执行：
`(A | B) & C => (A & C) | (B & C)`，当某 OR 分支的 NZM 与 C 的 mask 无重叠（分配后该分支被取消）或（常量 C 时）被完全覆盖。用 get_nz_mask 判断，op-edit API 创建两个新 AND。

测试：ruleaction::tests +1（A=0xf0/B=0xff/C=0x0f，NZM 无重叠→分配→OR）。

### 2026-06-26（续）：RuleLessOne

#### `pub struct RuleLessOne`（ruleaction.cc:1316-1339）
`V < 1 => V == 0`，`V <= 0 => V == 0`。极值比较转等式。

测试：ruleaction::tests +3（V<1→EQUAL 0；V<=0→EQUAL；V<5 不变）。

### 2026-06-26（续）：RuleAndPiece

#### `pub struct RuleAndPiece`（ruleaction.cc:1630-1694）
INT_AND 与 PIECE 简化：当 AND mask 清零某半时：
- `concat(H, L) & C`（C 清零 H）→ `zext(L)`
- `concat(H, L) & C`（C 清零 L）→ `concat(H, 0)`
用 get_nz_mask 判断哪半被清零，op-edit 创建 ZEXT/PIECE 替换。

测试：ruleaction::tests +1（H 被清零→ZEXT(L)）。

### 2026-06-26（续）：RuleAndCommute

#### `pub struct RuleAndCommute`（ruleaction.cc:1519-1626）
将移位穿过 AND 交换，使 AND 作用于移位前的值：
`(V >> c) & mask => (V & (mask << c)) >> c`，`(V << c) & mask => (V & (mask >> c)) << c`。
用 get_nz_mask 判断是否有益；LEFT+常量需 loneDescend 或 OR/PIECE 子情形。op-edit 创建新 shift + AND。

测试：ruleaction::tests +1（RIGHT 路径常量 mask 交换）。

**2026-09-23（MYPROGRESS-ANDCOMMUTE-GATE-0001）重写收益门（cc:1532-1626 全结构 1:1）**：
- 唯一无条件短路 = LEFT + othervn 常量 + `shiftvn->loneDescend()==op`（cc:1573-1580），其余情形**必须**过 cc:1582-1603 收益门：`orvn.is_written()` 且 `orvn.def ∈ {INT_OR, PIECE}`，INT_OR 需 `(ormask1&othermask)==0`/`(ormask2&othermask)==0`（+常量时 `==ormask1/2` 两补门），PIECE 低半=in(1) nzmask、高半=in(0) nzmask `<< in(1).size*8`，否则 `continue`（LOAD 输出等不得 commute——myprogress ord28 `AND(RIGHT(load,10),0xffffffff)` 首分歧根因）。
- 补 cc:1556 `othervn->isHeritageKnown()` 守卫;`othermask==0/fullmask` 检查移到移位调整**之后**（cc:1569-1570）。
- cc:1566 `(fullmask<<sa)&&fullmask` 按 Ghidra 源码字面移植：`&&` 是逻辑与（0/1），非按位 `&`——门值恒 1（fullmask 非零、wrap 后非零），故仅在 `othermask==1` 时拒绝。移位一律 `wrapping_*`（对齐 C++ uintb 环绕）。
测试重写：+3（收益门拒 LOAD 型 orvn=NO_CHANGE / LEFT+常量+loneDescend 快路径=CHANGE / INT_OR disjoint 臂=CHANGE）。

### 2026-06-26（续）：RuleOrConsume + get_consume/set_consume/get_nzm/set_nzm

#### Varnode consume/nzm 访问器（varnode.hh:205-206）
`get_consume/set_consume`（dead-code 维护的 consumed 掩码）、`get_nzm/set_nzm`（Heritage 维护的 nzm 字段）。Rugra Varnode 已有字段，此前无访问器。

#### `pub struct RuleOrConsume`（ruleaction.cc:344-371）
`V = A | B => COPY(B)` 当 nzm(A) & consume(V) == 0（A 贡献的位均未被消费）。也处理 XOR。

测试：ruleaction::tests +1（consume=0 → A 丢弃 → COPY(B)）。

### 2026-06-26（续）：RuleEarlyRemoval + opDestroy/opUnsetInput

#### Funcdata::op_destroy / op_unset_input（funcdata_op.cc:203, 263）
opDestroy 销毁未用 op（清输出 def、断输入 descend 链、markDead）；opUnsetInput 断某输入 descend 链。解锁 RuleEarlyRemoval。

#### `pub struct RuleEarlyRemoval`（ruleaction.cc:23-44）
删除输出无后代的 op（非 CALL/INDIRECT）。doesDeadcode/autoLive 检查保守跳过。

测试：ruleaction::tests +1（INT_ADD 无后代→destroy）。

### 2026-06-26（续）：RuleBooleanNegate + RuleLogic2Bool + is_boolean_value/is_calculated_bool

#### Varnode::is_boolean_value(use_annotation) / PcodeOp::is_calculated_bool（varnode.cc:942, op.hh:211）
判断 varnode 是否为布尔值（由 calculated_bool 标志的 op 定义），解锁 RuleBooleanNegate/RuleLogic2Bool。

#### `pub struct RuleBooleanNegate`（ruleaction.cc:2969-2999）
布尔值与常量 0/1 比较：`boolval != 0 => boolval`、`boolval == 0 => !boolval` 等，塌缩为 COPY/BOOL_NOT。

#### `pub struct RuleLogic2Bool`（ruleaction.cc:3128-3167）
当两输入均为布尔值时，INT_AND→BOOL_AND、INT_OR→BOOL_OR、INT_XOR→BOOL_XOR。

测试：ruleaction::tests +2（布尔 == 0→BOOL_NOT；INT_AND(less,less)→BOOL_AND）。

### 2026-06-26（续）：RuleLeftRight + op_unset_output/new_varnode_out

#### Funcdata::op_unset_output / new_varnode_out（funcdata_op.cc/funcdata.hh）
opUnsetOutput 断开 op 输出；newVarnodeOut 创建新输出 varnode 并关联。解锁 RuleLeftRight。

#### `pub struct RuleLeftRight`（ruleaction.cc:2016-2062）
`(V << c) >> c => zext(sub(V, 0))`，`(V << c) s>> c => sext(sub(V, 0))`。当右移恰好抵消左移（同字节对齐量），pair 塌缩为零/符号扩展的 SUBPIECE。要求 shiftin 为 loneDescend。

测试：ruleaction::tests +1（<<8 >>8 cancel → ZEXT + SUBPIECE）。

### 2026-06-26（续）：RuleIntLessEqual + Funcdata::replace_lessequal

#### Funcdata::replace_lessequal (funcdata_op.cc:1029)
`V <= c => V < c+1`：调整常量并改 opcode，带溢出保护。

#### `pub struct RuleIntLessEqual`（ruleaction.cc:611-617）
委托 replace_lessequal。将 INT_LESSEQUAL/INT_SLESSEQUAL 转为 INT_LESS/INT_SLESS。

测试：ruleaction::tests +2（V<=5→V<6；V<=0xffffffff 不变）。

### 2026-06-26（续）：expression.rs — TermOrder/AdditiveEdge/AddExpression

新增 `src/expression.rs` 模块（对应 `expression.hh`/`expression.cc`）：

- `AdditiveEdge`：加法表达式中的项（op + slot + vn + 可选 mult op）
- `TermOrder`：从 INT_ADD 树收集所有项，按项排序。`collect()` 遍历 ADD/MULT 链收集项；`sort_terms()` 排序。
- `AddExpression`：轻量级加法表达式匹配（最多 2 项 + 常量）。`gather_two_terms_subtract/add/root` + `is_equivalent`。

解锁：RuleCollectTerms、RuleScarry/RuleSborrow 深层形式。

测试：expression::tests 2 个（常量折叠、等价匹配）。

### 2026-06-26（续）：RuleCollectTerms

#### `pub struct RuleCollectTerms`（ruleaction.cc:94-176）
在加法表达式中折叠常量与合并同类项：
- `(V + 3) + 5 => V + 8`（常量折叠）
- `V*2 + V*3 => V*5`（合并同类项，非乘法系数场景）
使用 `expression.rs` 的 `TermOrder` 收集/排序所有项。

测试：ruleaction::tests +1（常量折叠 3+5→8）。

### 2026-06-26（续）：RuleCollectTerms 完整形式

更新 RuleCollectTerms 使用 `distribute_int_mult_add` 处理 INT_MULT 系数场景（ruleaction.cc:130-133）。
该路径尚未经锁定 oracle fixture 覆盖，不作完整对齐声明。

### 2026-06-26（续）：RuleBitUndistribute

#### `pub struct RuleBitUndistribute`（ruleaction.cc:2620-2695）
逆向分配位运算：
- `zext(V) & zext(W) => zext(V & W)`
- `(V >> X) | (W >> X) => (V | W) >> X`
当两输入到 INT_AND/OR/XOR 是同一扩展/移位操作时，提取公共操作。

测试：ruleaction::tests +1（zext & zext → zext(and)）。

### 2026-06-26（续）：RuleBooleanDedup

#### `pub struct RuleBooleanDedup`（ruleaction.cc:2840-2955）
布尔表达式去重：
- `(A && B) && (A && C) => A && (B && C)`
- `(A || B) || (A || C) => A || (B || C)`
当两个 BOOL_AND/BOOL_OR 共享一个公共布尔子表达式时，提取公共因子。
当前移植了直接匹配形式（Ghidra 的 BooleanMatch::evaluate 互补形式待补）。

测试：ruleaction::tests +1（A&&B && A&&C → A && (B&&C)）。

### 2026-06-26（续）：测试修复

旧测试曾宽松接受未折叠值；2026-08-13 对齐工作已将此改为精确槽位和常量值断言。

## 2026-06-27（续）：RuleRangeMeld 完整移植

- **RuleRangeMeld**：完整忠实移植 ruleaction.cc:1346-1437。合并范围条件 `(V < W)||(V == W) => V <= W` 等：
  1. 从两个 bool 比较子 op（INT_LESS/INT_EQUAL/INT_NOTEQUAL/INT_LESSEQUAL 等）pullBack CircleRange。
  2. 如果子 op 是 BOOL_NOT，额外 pullBack 一层。
  3. 验证两个 pullBack 根 varnode 功能等价（必要时再 pullBack 调整大小差异）。
  4. BOOL_AND → intersect，BOOL_OR → union。
  5. 根据结果类型：translate_to_op（INT_LESS/INT_LESSEQUAL）或 COPY(#1)（always true）或 COPY(#0)（always false）。
  - 新增辅助函数 `pull_back_op(range, op)` — 简化版 pullBack（unary/binary 分发，不跟踪 constMarkup/usenzmask）。
    （2026-09-23 已删除：RuleRangeMeld 切换到正典 `CircleRange::pull_back(op, usenzmask, &mut markup)`，
    见下文 RULEMELD-FIDELITY-RESIDUE-0001 节。）
  - 修复 CircleRange::union 返回码语义对齐 Ghidra circleUnion（0=single, 1=two pieces, 2=full）+ 相邻范围合并。
  - 测试：`(V<5)||(V==5) => V<6`（语义等价 V<=5）。

## 2026-09-23：RuleRangeMeld restype 映射精确化（RANGEUTIL-VSEMPTY-0001 配套 + CR8 M-A 返工）

- **restype 码流对齐 ruleaction.cc:1403-1437**：`CircleRange::intersect` 忠实化
  （委托 `circle_intersect`，0=空/1=单区间/2=两段）后，调用点映射改为
  BOOL_AND 臂 `0→3(always false)/1→0(try translate)/2→2(cannot)`；
  **BOOL_OR 臂（CR8 M-A 返工）改接忠实版 `circle_union`**（cc:360-444 完整
  'a'-'g' 合并臂，含 wrapping/stride 适配），映射 `{0→0, 非零→2}`——满覆盖
  情形（'g' 臂返 0 且 left==right）经 `translate_to_op→Err(1)→COPY(1)` 恰为
  cc:1412-1430 原文路径；legacy 简化 `union` 包装（wrapping 一律两片）已从
  该路径隔离并加注禁用。`translate_to_op` 为 `Result<(OpCode,u64,i32), i32>`
  （镜像 `translate2Op` cc:1424-1467 的 0/1/2/3 码），非零 Err 码落入
  always-true/cannot-represent/always-false 臂。
- 测试：`(V<5)||(V==5) => V<6` 语义等价保持 + CR8 M-A 回归
  `(200<s V)||(250<s V) => 200<s V`（INT_SLESS 单区间重写）。
- E2E 影响经三门禁验证：curl 2563/0/0 与 httpd 2333/0/0 均与返工前字节
  恒等（修复对当前语料不可见——潜伏语义雷类）。

## 2026-06-27（续 2）：RuleFloatRange 完整移植

- **RuleFloatRange**：完整忠实移植 ruleaction.cc:1439-1518。合并浮点范围条件：
  - `(V f< W)||(V f== W) => V f<= W`（FLOAT_LESS + FLOAT_EQUAL via BOOL_OR → FLOAT_LESSEQUAL）
  - `(V f<= W)&&(V f!= W) => V f< W`（FLOAT_LESSEQUAL + FLOAT_NOTEQUAL via BOOL_AND → FLOAT_LESS）
  - 算法：识别 cmp1（LESS/LESSEQUAL）+ cmp2（other），验证两个比较操作数一致（nvn1 + cvn1），合并为单一比较 op。
  - 测试：`(V f< 5.0)||(V f== 5.0) => V f<= 5.0`。

## 2026-06-27（续 3）：RulePullsubMulti 完整移植

- **RulePullsubMulti**：完整忠实移植 ruleaction.cc:678-952。将 SUBPIECE 拉过 MULTIEQUAL：
  - `min_max_use(vn)` — 计算 vn 的实际使用字节范围（遍历后代 SUBPIECE，非 SUBPIECE 后代→全范围）
  - `acceptable_size(size)` — 检查截断大小是否合法（1/2/4/8 或 >=8）
  - `replace_descendants(orig_vn, new_vn, max_byte, min_byte)` — 用更窄的 new_vn 替换 orig_vn 的所有后代 SUBPIECE（转换为 COPY 或调整截断偏移）
  - `find_subpiece(base_vn, out_size, shift)` — 搜索预存的 SUBPIECE。
    **2026-09-28 修正（CANON-LOOPFORM-GETPARENTS-INVERT-0001 根因）**：此前跳过了 oracle 的
    同块约束（注释自认 "may find a SUBPIECE from a different block"）——findSubpiece
    (ruleaction.cc:849-870) 逐后代按序检查：cc:859 input 基底只匹配 block 0 内的 SUBPIECE、
    cc:860 非写非 input 基底永不匹配、**cc:861 要求 prevop 与基底 definer 同块**
    （`basevn->getDef()->getParent() != prevop->getParent()` 指针比较）、cc:863-865 形式匹配
    （in0 指针同 + outsize + shift）。缺省同块门时，canon httpd `ap_getparents` 的
    pullsub 复用了外层 latch 块的 EAX 截断而非在循环头 φ 之后新建 SUBPIECE
    （buildSubpiece cc:837 `opInsertAfter(new_op, basevn->getDef())`），循环头块因此少了
    一条 isComplex 语句（block.cc:2388 计数），ruleBlockWhileDo 的 overflow 形判定
    （blockaction.cc:1538 `bool overflow = bl->isComplex()`）被翻转为 `while(cond)`
    形——golden 为 `while( true ) { …; if(…) break; }`。补齐后 canon httpd
    ap_getparents 19→4（剩余 4 行=声明序+单语句位，异根另票）。
  - `build_subpiece(fd, base_vn, out_size, shift) -> Result<Varnode>` — 创建新 SUBPIECE op（ruleaction.cc:776-839）。
    **2026-08-27 修正（VARMAP-ORPHAN-DECL-0001 根因）**：此前仅在 `is_written` 时 `op_insert_after`，
    input 基底的新 SUBPIECE 从未插入任何 block，滞留 dead 列表；opDeadAndGone（funcdata.hh:476
    `obank.destroy(op)`，与 opDestroy 不同**不销毁输出**）销毁 op 后，输出 Varnode 带 WRITTEN flag
    滞留 vank，被 ActionNameVars::linkSymbols（coreaction.cc:2954 isFree 跳过不适用于它）铸成
    零读 ScopeLocal 符号 → 孤儿声明（progressbarinit `int iVar1;`、my_get_token `int iVar2;`）。
    现按 oracle 无条件插入：input 基底 `op_insert_begin`（block 0 头部，cc:834-835），
    written 基底 `op_insert_after`（definer 之后，cc:836-837）；既非 input 也非 written 返回
    `Err("Undefined pullsub")` 镜像 cc:788 `throw LowlevelError`。两调用点
    （RulePullsubMulti::applyOp / RulePullsubIndirect::applyOp）`?` 传播等价 Ghidra 异常上抛。
  - `apply_op` — 主算法：检查 SUBPIECE(MULTIEQUAL)，计算使用范围，检查各分支 consume，为每个分支创建/查找 SUBPIECE，构建新的窄 MULTIEQUAL，替换后代
  - **2026-09-22 修正（ordinal-28 快照 BUILD/MULTIEQUAL 输出空间差）**：新 MULTIEQUAL 输出
    从 `new_unique_out` 改为 cc:921-940 的地址保持路径——`smalladdr2 = vn.addr+minByte`（小端）
    / `vn.addr+(size-maxByte-1)`（大端）后 `renormalize(newSize)`（join 空间经
    AddrSpaceManager::renormalizeJoinAddress，translate.cc:870-916；登记
    `RULE-PULLSUBMULTI-JOINRENORM-0001`，Architecture 尚无活体 AddrSpaceManager，寄存器/
    文件/unique 空间为无操作精确）再 `newVarnodeOut`，保持原空间（寄存器文件中的合并窗口
    保持寄存器 varnode，如 `EAX(5020:736) = EAX ? EAX`，而不再落到 `u:10000081`）。
    插入从 `op_insert_before(mult)` 改回 cc:943 `opInsertBegin(new_multi, mult->getParent())`
    （MULTIEQUAL 排块首，保持 SeqNum order 语义）。补 cc:889 `isPrecisLo||isPrecisHi`
    双精度守卫（此前注释声称缺基础设施，实际 varnode.rs:1286 已有）。
  - 已知限制：hasLoopIn 需 FlowBlock loop-in 标记（block.cc loop coats），登记
    `RULE-PULLSUBMULTI-LOOPIN-0001`（保守允许）；join 基底 renormalize 登记
    `RULE-PULLSUBMULTI-JOINRENORM-0001`（寄存器/unique 空间无影响，debug_assert 拦截
    join 命中）

## 2026-06-27（续 4）：RuleAndMask 完整移植

- **RuleAndMask**：完整忠实移植 ruleaction.cc:300-342。折叠不必要的 INT_AND：
  - `V = A & B`，计算 NZM(A) ∩ NZM(B)。
  - 如果交集为 0（AND 结果总为 0）→ COPY(#0)
  - 如果 consumed bits 全为 0 → COPY(#0)
  - 如果交集 == NZM(A) 且 input(1) 是常量 → COPY(A)
  - 否则不做变换
  - isHeritageKnown：常量视为 known（Rugra 常量无 INPUT/WRITTEN flag 但仍 known）。
  - 测试：`V = A & #0`（NZM(A)=0）→ COPY(#0)。

## 2026-06-27（续 5）：RuleBooleanUndistribute 完整移植

- **RuleBooleanUndistribute**：完整忠实移植 ruleaction.cc:2700-2810。分布/反分布布尔表达式：
  - `(A == B) && (A != C) => A == (B && C)` — 提取公共布尔子表达式
  - `(A || B) && (A || C) => A || (B && C)` — De Morgan 定律
  - 使用 `BooleanMatch::evaluate` 查找相关布尔子表达式（same/complementary）
  - `is_match(left, right)` — 包装 BooleanMatch::evaluate，返回 `Some(is_flip)`
  - 算法：收集 4 个输入，用 isMatch 查找匹配对，处理 BOOL_OR flip（De Morgan），构建新比较 op + combine op
  - 依赖：BooleanMatch::evaluate ✅、op_bool_negate ✅

## 2026-06-27（续 6）：RuleBoolZext 完整移植

- **RuleBoolZext**：完整忠实移植 ruleaction.cc:3000-3124。将零扩展布尔值上的操作转换为布尔操作：
  - 检测 INT_ZEXT(bool) → INT_MULT(*-1) → actionop 链
  - INT_ADD(#1)：`zext(b) * -1 + 1` → `zext(!b)`（BOOL_NEGATE + COPY 传播）
  - INT_EQUAL/INT_NOTEQUAL：将扩展布尔与 0/-1 比较改为未扩展布尔与 0/1 比较
  - INT_AND/OR/XOR：两侧都是扩展布尔时，先做布尔运算再扩展
  - 依赖：is_boolean_value ✅、is_type_recovery_on ✅、op_bool_negate ✅、lone_descend ✅

## 2026-06-27（续 7）：RulePushMulti 完整移植

- **RulePushMulti**：完整忠实移植 ruleaction.cc:1060-1137。简化两分支 MULTIEQUAL，其中两个输入以功能等价方式构造：
  - 检测 `MULTIEQUAL(op1_out, op2_out)` 其中 op1/op2 功能等价
  - COPY 特殊情况：MERGE of 2 shadowing varnodes → findSubstitute + totalReplace
  - 通用情况：验证 loneDescend，移动 op1 的输出到 MULTIEQUAL 输出（unify），op_uninsert + op_insert_before 重新定位
  - `find_substitute(fd, in1, in2, bb, earliest)` — 搜索**同块**已存在的 MULTIEQUAL[in1,in2] 或 CSE
  - 依赖：functional_equality_level ✅、total_replace ✅、op_destroy ✅、op_uninsert ✅、op_insert_before ✅

### 2026-09-24：findSubstitute 块过滤 + earliest 约束（RULEACTION-FINDSUB-BBFILTER-0001，wt/p3batch）

对齐 ruleaction.cc:1031-1060 的两处缺失：

- **cc:1040 块过滤**：`if (op->getParent() != bb) continue` —— MULTIEQUAL 后代扫描
  原先跨全部块，搜索网偏宽。现带块限定（裸指针不等式语义：null `bb` 仅匹配无
  parent 的 op，扁平 bank 单测保持原有可达域）。
- **cc:1056 earliest 约束**：CSE 臂原为内联「同 opcode+全输入 ptr-eq」扫描（无块、
  无序约束，且判据本身与 oracle 不同）；现委托正典 `Funcdata::cseFindInBlock`
  （funcdata.rs `cse_find_in_block`，funcdata_op.cc:1324-1345：块成员 + earliest
  `SeqNum::order` 上界 + 输出非空 + depth-0 功能等价）。
- `applyOp` 补 cc:1094-1095 的 `bl = op->getParent()` + `earliest =
  bl->earliestUse(op->getOut())`，且**前移**到 COPY 特例之前（Ghidra 两臂共用）。
- 新增 `earliest_use_in_block`（`// Ghidra: block.cc:2778 BlockBasic::earliestUse`，
  RulePushMulti 私有 helper，ruleaction 写域内落位）：后代扫描限同块，`<`-only
  比较（平局不替换=先见者胜）。

## 2026-06-27（续 8）：RuleSelectCse 完整移植

- **RuleSelectCse**：完整忠实移植 ruleaction.cc:178-209。在 SUBPIECE/INT_SRIGHT 的 input(0) 后代中查找公共子表达式：
  - 收集与给定 op 相同 opcode 且 CSE hash 非零的后代 ops
  - 调用 `Funcdata::cse_eliminate_list` 进行排序+匹配+消除
  - 依赖：get_cse_hash ✅、is_cse_match ✅、cse_eliminate_list ✅、cse_elimination ✅

## 2026-06-27（续 9）：清理规则移植

- **RuleMultNegOne**：完整移植 ruleaction.cc:7171-7190。`V * -1 => -V`（INT_MULT + all-ones → INT_NEG）。
- **RuleSub2Add**：完整移植 ruleaction.cc:4030-4056。`V - W => V + (W * -1)`（INT_SUB → INT_ADD + INT_MULT(*-1)）。使加法项重排规则能匹配。
- **RuleSubExtComm**：完整移植 ruleaction.cc:4410-4461。SUBPIECE 穿过 INT_ZEXT/INT_SEXT：
  - SUBPIECE 不触及扩展位 → COPY/直接替换
  - 否则创建中间 SUBPIECE + 重写为 zext/sext

## 2026-06-27（续 10）：更多清理规则移植

- **Rule2Comp2Mult**：完整移植 ruleaction.cc:3980-3995。`-V => V * -1`（INT_NEG → INT_MULT + 插入 -1 输入）。
- **Rule2Comp2Sub**：完整移植 ruleaction.cc:7236-7256。`-V => 0 - V`（INT_NEG → INT_SUB + 插入 0 输入）。
- **RuleCarryElim**：完整移植 ruleaction.cc:3997-4030。`carry(V,c) => -c <= V`（INT_CARRY + 常量 → INT_LESSEQUAL）；`carry(V,0) => false`。

## 2026-06-27（续 11）：Zext 交换/简化规则

- **RuleConcatZext**：完整移植 ruleaction.cc:4806-4842。`concat(zext(V), W) => zext(concat(V, W))`（PIECE + ZEXT → 新 PIECE + ZEXT）。
- **RuleZextCommute**：完整移植 ruleaction.cc:4844-4875。`zext(V) >> W => zext(V >> W)`（INT_RIGHT + ZEXT → 新 INT_RIGHT + ZEXT）。
- **RuleZextShiftZext**：完整移植 ruleaction.cc:4877-4919。简化多重 ZEXT：
  - `zext(zext(V)) => zext(V)`（loneDescend 验证）
  - `zext(zext(V) << c) => zext(V) << c`（检查 shift 不丢失扩展位）

## 2026-06-27（续 12）：SUBPIECE/PIECE 简化规则

- **RuleShiftSub**：完整移植 ruleaction.cc:5201-5230。`sub(V << 8*k, c) => sub(V, c-k)`（SUBPIECE + INT_LEFT → 调整截断偏移）。
- **RuleHumptyDumpty**：完整移植 ruleaction.cc:5232-5281。合并拆分+重组：
  - `concat(sub(V,c), sub(V,0)) => V`（完整重组）
  - `concat(sub(V,c), sub(V,d)) => sub(V,d)`（部分重组）
- **RuleDumptyHump**：完整移植 ruleaction.cc:5283-5337。简化连接+拆分：
  - `sub(concat(V,W), 0) => W`（完整消除）
  - `sub(concat(V,W), c) => sub(W,c)` 或 `sub(V,c-k)`（部分消除）

## 2026-06-27（续 13）：SUBPIECE 消除 + OR 重组规则

- **RuleSubCancel**：完整移植 ruleaction.cc:5115-5199。SUBPIECE 应用于扩展运算的消除：
  - INT_AND + 掩码：`sub(V & mask, 0) => V`（当 mask == calc_mask(outsize)）
  - INT_ZEXT/INT_SEXT：`sub(zext(V), 0)` → COPY（完全消除）或 SUBPIECE（部分）
  - INT_ZEXT + 高偏移：`sub(zext(V), c)` 当 c >= insize → COPY(#0)
- **RuleSubCancel 锁形重构（RULE-SUBCANCEL-RWLOCK-0001，2026-08-16）**：`apply_op` 重构为
  两阶段——阶段一在 `op_arc.read()` 读锁作用域内只收集 owned 值
  （`ext_code/extop/offset/out_size/in_size/far_in_size`），阶段二在锁全部释放后才调
  `fd.op_set_input`（INT_AND 掩码消除分支）或 `fd.op_set_opcode/op_set_input/op_remove_input`
  （ZEXT/SEXT 路径）。原因：`op_set_input`（funcdata.rs opSetInput）对同一 PcodeOp 取写锁，
  RwLock 非重入 → 旧实现 INT_AND 分支在块作用域读锁存活期直接 mutate 造成永久 futex
  自死锁（Ghidra ruleaction.cc:5119-5181 无锁概念，cc:5141/5175-5179 直接 opSetInput）。
  可观测行为不变：检查顺序与判定完全同 Ghidra。同文件 137 个 `apply_op` 已机械审计
  （named read guard 存活期 × fd.op_* 同 op 写接口），唯一真实命中即本处，其余 0 命中；
  4 处 `fd.total_replace`（RulePushMulti/RuleMultiCollapse×2/RuleIndirectCollapse）为隐藏
  写目标（写锁 vn 的全部后代 op），已加注释守卫标注。
- **RuleHumptyOr**：完整移植 ruleaction.cc:5339-5420。简化掩码 OR 重组：
  - `(V & ff00) | (V & 00ff) => V`（所有位覆盖 → COPY）
  - `(V & W) | (V & X) => V & (W|X)`（部分覆盖 → AND）
  - 非常量掩码：创建 INT_OR(b,c) + INT_AND(a,result)，检查 NZMask 防止 RuleAndDistribute 反转

## 2026-06-27（续 14）：比较简化规则

- **RuleEqual2Zero**：完整移植 ruleaction.cc:5850-5906。简化与 0 的比较：
  - `0 == V + W * -1 => V == W`（乘以 -1 的形式）
  - `0 == V + c => V == -c`（常量偏移形式）
  - 验证 addvn 的所有后代都是布尔比较（isBoolOutput）
  - **2026-09-22 修正（ordinal-28 oppool1 count 863→826 差 37 的主根因）**：MULT 分支的
    else-if 阶梯被倒置——旧版在 `vn` written 但非 INT_MULT 时提前 return，永远不会检查
    `vn2`（cc:5884-5893 的 else-if 语义是第一个输入仅在 *written 且 MULT* 时占用 negvn 槽，
    否则落到第二输入）；恢复阶梯语义后 next_url 首oppool1 窗口 equal2zero 13→7 的 −6
    连锁（earlyremoval −22 等）全部回收。同时补齐 cc:5900-5901 的
    `isHeritageKnown` 双守卫（insert|constant|annotation flags）与 cc:5880
    `copySymbolIfValid`（equate markup 传播，varnode.cc:510-522）。常量分支的
    `uintb_negate(c-1,size)` = `~(c-1)&mask` = `(-c)&mask`（address.cc:654）按位精确移植。

## 2026-06-27（续 15）：移位消除 + 条件翻转规则

- **RuleShiftAnd**：完整移植 ruleaction.cc:4921-4975。消除被移位丢弃的 INT_AND：
  - `(V & mask) >> sa => V >> sa`（当移位后的 mask 覆盖所有 NZM 位）
  - 支持 INT_RIGHT/INT_LEFT/INT_MULT（2 的幂）
- **RuleCondNegate**：完整移植 ruleaction.cc:5478-5510。翻转带 boolean_flip 标志的 CBRANCH：
  - 插入 BOOL_NOT 取反条件，调用 op_flip_condition 清除标志
  - 依赖：is_boolean_flip ✅、op_bool_negate ✅、op_flip_condition ✅（新增）

## 2026-06-27（续 16）：XOR/比较简化规则

- **RuleXorSwap**：完整移植 ruleaction.cc:10614-10650。`(V ^ W) ^ V => W`（XOR 链简化）。
- **RuleEqual2Constant**：完整移植 ruleaction.cc:5926-5990。简化算术表达式与常量的比较：
  - `(V + c) == d => V == (d - c)`（加法常量偏移）
  - `(V * -1) == d => V == -d`（乘 -1）
  - 验证 lhs 的所有后代都是比较
  - 跳过 INT_NEGATE 情况（Rugra 缺少此 opcode）
- **RuleOrCompare**：完整移植 ruleaction.cc:10808-10872。分配 INT_OR 到比较：
  - `(V | W) == 0 => V == 0 && W == 0`（INT_EQUAL → BOOL_AND）
  - `(V | W) != 0 => V != 0 || W != 0`（INT_NOTEQUAL → BOOL_OR）

## 2026-06-27（续 17）：ConcatCommute 规则

- **RuleConcatCommute**：完整移植 ruleaction.cc:4675-4748。逻辑运算与拼接的交换：
  - `concat(V, W) | c => concat(V | c_hi, W) | c_lo`（INT_OR/INT_XOR 交换进 PIECE）
  - `concat(V, W) & c => concat(V & c_hi, W & c_lo)`（INT_AND 交换进 PIECE）
  - 常量值根据高低位偏移调整

## 2026-06-27（续 18）：LZCOUNT 简化规则

- **RuleLzcountShiftBool**：完整移植 ruleaction.cc:10660-10712。简化使用 lzcount 的相等检查：
  - `lzcount(X) >> c => X == 0`（当 X 大小为 2^c 字节时，lzcount 的最高位指示是否为 0）
  - 仅对 2 的幂大小生效（popcount(max_return) == 1）
  - 将移位后代替换为 INT_EQUAL + COPY/ZEXT

## 2026-06-27（续 19）：ThreeWayCompare 规则

- **RuleThreeWayCompare**：完整移植 ruleaction.cc:9949-10263（~230 行）。简化三方比较表达式：
  - 三方比较 = `zext(V < W) + zext(V <= W) - 1`，结果为 -1/0/1
  - `detect_three_way(addop)` — 检测 INT_ADD(zext(cmp1), zext(cmp2)) 模式
  - `test_compare_equivalence(lessop, lessequalop)` — 验证两个比较操作等价
  - 对 24 种 form 组合（const 值 × 位置 × 比较类型）分别重写为直接比较
  - 包括：always true/false、a<b、a<=b、a>b、a>=b、a==b、a!=b

**2026-08-23 诊断名修正（PIPE-POOL-LOCAL-RULES-0001）**：`get_name()` 由
`"three_way_compare"` 改为 oracle 精确串 `"threewaycomp"`（ruleaction.hh:1504
`Rule(g, 0, "threewaycomp")`——oracle 用的是截断名）。池纯净度 fixture
（pool_purity_1204）首次将该名字纳入 oracle 观察时暴露此缺陷。

## 2026-06-27（续 20）：MultiCollapse 规则

- **RuleMultiCollapse**：对应锁定 12.0.4 `ruleaction.cc:3234-3343`。折叠所有输入追溯到相同值的 MULTIEQUAL：
  - 入口要求每个输入均 `isHeritageKnown()`，不能用“非 free”近似
  - 使用 functional_equality_level 检查输入是否绝对等价或功能等价
  - 处理嵌套 MULTIEQUAL：将非匹配的 MULTIEQUAL 输入展开到匹配列表
  - 循环构造检测：is_mark 表示值在循环中递归（跳过处理）
  - `skiplist` 的第一项就是根输出；成功时必须处理根，不能在零突变时返回 CHANGE
  - 绝对等价：对根及嵌套项逐个 `total_replace + op_destroy`
  - 功能等价：按同块最早读取边界调用 `cse_find_in_block`；命中时替换并销毁，未命中时把原 MULTIEQUAL 原位改成模板表达式，并重新插到前导 MULTIEQUAL 之后
  - `func_eq` 对整个 skiplist 保持 sticky，所有项复用同一 defining-branch 模板；每项处理前清 mark

`RULE-MULTICOLLAPSE-0001` 的直接 fixture 同时观察返回值、root/nested
identity、mark、def-use、alive/dead bank、基本块顺序和 `Funcdata::opDestroy`
调用闭包。Rust 的非 nullable `Vec<Arc<Varnode>>` 仍不能保留 Ghidra dead op
中的 NULL input slots；该 dead-object 表示差异保持 `MISMATCH`，不能由主管线
收敛结果推导为完整 B2 `MATCH`。

## 2026-06-27（续 21）：除法优化规则

- **RuleSignDiv2**：完整移植 ruleaction.cc:8357-8408。`(V + -1*(V s>> 31)) s>> 1 => V s/ 2`（有符号除以 2 的编译器惯用法简化）。
- **RuleDivChain**：完整移植 ruleaction.cc:8401-8443（PATHOSLOW-DIVCHAIN-0001 重写，
  修复旧版丢失 oracle 5 项语义导致的 oppool1 非终止）。折叠连续除法：
  - `(x / c1) / c2 => x / (c1*c2)`（相同符号 INT_DIV/INT_SDIV）
  - `(x >> c1) / c2 => x / (2^c1 * c2)`（无符号 INT_RIGHT + INT_DIV，cc:8423-8425 `val1 = 1 << sa`）
  - 中间结果必须 loneDescend（仅在此处使用，cc:8417）
  - **5 项决定性语义（cc:8427-8441，逐行对齐）**：
    ① `baseVn = divOp->getIn(0)` 的 isFree 守卫（cc:8428）；
    ② `resval = (val1*val2) & calc_mask(sz)` 零积守卫（cc:8431-8432，sz 取自 `vn->getSize()` cc:8429）；
    ③ signbit_negative 归一——val1/val2 各自取绝对值 `(~v+1)&mask`（cc:8433-8436）；
    ④ bitcount 溢出守卫 `mostsigbit_set(val1)+mostsigbit_set(val2)+2`，INT_DIV `> sz*8`、
    INT_SDIV `> sz*8-2` 拒绝（cc:8437-8439）；
    ⑤ **`opSetInput(op,baseVn,0)` in(0) 基数替换**（cc:8440）+ in(1)=newConstant(sz,resval)
    （cc:8441）——中间结果失去唯一后代，模式不可再命中，链每 pass 短一层直至溢出守卫
    终止；oracle 从不改写 op 的 opcode（旧版多出的 INT_RIGHT→INT_DIV op_set_opcode 已删）。

## 2026-06-27（续 22）：符号提取归一化规则

- **RuleSignForm**：完整移植 ruleaction.cc:8445-8474（RULE-BEHAVIORAL-FIVE-0001 M2 重写）。
  **dispatch SUBPIECE**（cc:8447-8451；旧实现 dispatch INT_SRIGHT 是错误触发模式）：
  `sub(sext(V), c) => V s>> (8*|V|-1)`，要求 c >= |V|（cc:8465-8466）且 V 非 free；
  移位常量为 4 字节（cc:8471）。
- **RuleSignForm2**：完整移植 ruleaction.cc:8476-8531。`sub(sext(V) * small, c) s>> 31 => V s>> 31`（当 small 是小的正整数且不溢出到符号位时）。

## 2026-06-27（续 23）：除法/移位优化规则

- **RulePositiveDiv**：完整移植 ruleaction.cc:7803-7830。当两个输入保证非负时，将 INT_SDIV→INT_DIV / INT_SREM→INT_REM（检查 NZMask 符号位）。
- **RuleDoubleArithShift**：完整移植 ruleaction.cc:1930-1964。`(V s>> c) s>> d => V s>> (c+d)`（合并连续有符号右移，饱和到最大移位）。
- **RuleSignNearMult**：完整移植 ruleaction.cc:8533-8592（RULE-BEHAVIORAL-FIVE-0001 M3 重写）。
  **dispatch INT_AND**（cc:8535-8539；旧实现 dispatch INT_MULT 改写已存在的乘法，结构映射倒置）：
  `(V + (V s>> (8|V|-1)) >> (8|V|-n)) & (-1<<n) => (V s/ 2^n) * 2^n`。mask 校验
  `(calc_mask<<n)&calc_mask == AND 常量`（cc:8567-8569）后，插入 `INT_SDIV(V, 2^n)` 并把 AND 改写为
  `INT_MULT(sdiv, 2^n)`（cc:8579-8591）。

## 2026-06-27（续 24）：浮点转换简化

- **RuleFloatCast**：完整移植 ruleaction.cc:9545-9602。简化冗余浮点转换链：
  - `float2float(float2float(V)) => float2float(V)`（当外层冗余时）
  - `float2float(int2float(V)) => int2float(V)`（整数直接转最终浮点大小）
  - `trunc(float2float(V)) => trunc(V)`（浮点直接转最终整数大小）

## 2026-06-27（续 25）：SUBPIECE 归一化

- **RuleSubNormal**：完整移植 ruleaction.cc:7700-7803。归一化 SUBPIECE 应用于移位结果：
  - `sub(V >> n, c) => V >> n'`（合并移位+截断，字节对齐时消除多余移位）
  - 处理溢出情况：当截断超出输入大小时，创建额外扩展（ZEXT/SEXT）
  - 饱和移位：当剩余移位超过输出大小时，饱和到最大值

## 2026-06-27（续 26）：有符号模运算优化

- **RuleSignMod2nOpt**：完整移植 ruleaction.cc:8650-8769。将有符号模运算惯用法转换为 INT_SREM：
  - `(V + (sign >> (64-n)) & (2^n-1)) - (sign >> (64-n)) => V s% 2^n`
  - `sign = V s>> (size*8-1)`（符号提取）
  - 支持截断形式（INT_ZEXT 介入 INT_AND 后）
  - 辅助函数 `check_sign_extraction(out_vn)` — 验证 `V s>> (size*8-1)` 模式，返回 V
  - 遍历 correct_vn 的后代，检测完整的 mult(-1) → add → and(mask) → add(V, shift(sign)) 链

### 2026-06-27（会话2 续）：RuleDivOpt

- `RuleDivOpt` — `RuleDivOpt`（ruleaction.cc:8051-8337）：除法乘法编码还原。`sub(ext(V)*c, d) >> e` / `sub(ext(V)*c) >> e` / `(ext(V)*c) >> n` → `V / divisor`。
  - `find_form` — `findForm`（8069）：检测 shift→subpiece→mult→zext/sext 链，返回 (in_vn, n, y128, xsize, ext_opc)
  - `calc_divisor` — `calcDivisor`（8157）：从乘法编码 c 反推除数（u128 运算）
  - `check_form_overlap` — `checkFormOverlap`（8260）：检测 SUBPIECE 形式是否被上级 shift 形式包含
  - `apply_op` — `applyOp`（8295）：三种尺寸分支（需扩展/需截断/同尺寸）转换

**注**：此前误记"缺第二变体 ruleaction.cc:8010-8046"——核实后确认该段是**独立的 RuleDivTermAdd2**（另一个 Rule），非 RuleDivOpt 的一部分。RuleDivOpt 本身完整对应 8295-8355。
### 2026-06-27（续；2026-08-28 已由新证据取代）：RuleEarlyRemoval 六守卫
- “空间门只允许 CONSTANT”是历史实现，当前已删除。权威口径是顶部
  `RULE-PORT-EARLYREMOVAL-0001` 的 14/14 covered MATCH：六守卫、严格 pass/delay、
  writemask/autolive、OTHER policy 与 typed-opcode dispatch。完整 Rule/Heritage/
  OpBank 生命周期仍为 MISMATCH/UNTESTED。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29：RuleSubCommute（ruleaction.cc:4443-4653）

- `RuleSubCommute` — SUBPIECE 与二元算术的 commute：`SUBPIECE(INT_ADD(a,b), 0) → INT_ADD(SUBPIECE(a,0), SUBPIECE(b,0))`。把截断推进算术内部，使操作数能用更小宽度类型化。
- 触发于 CPUI_SUBPIECE；支持的 longform op：INT_ADD/INT_MULT/INT_NEGATE/INT_XOR/INT_AND/INT_OR（offset 任意）、INT_LEFT/INT_DIV/INT_REM（offset==0）、INT_SDIV/INT_SREM（offset==0，双侧 SEXT 或常量除数符号适配，cc:4570-4602——2026-09-26 补齐，见下）。
- 守卫：base 必须 loneDescend == op（cc:4621）；INT_LEFT 的 in(0) 必须是 ZEXT/PIECE；INT_DIV/INT_REM 的输入必须是 ZEXT；INT_SDIV/INT_SREM 的 in(0) 必须 SEXT、in(1) 写则 SEXT（任一 sext 输入 > outvn 走 cancelExtensions 部分抵销 cc:4583-4589）、in(1) 常量则 sign_extend(smallval, outvn, insize) == val 符号适配（cc:4592-4597）。
- 2 单元测试：test_rule_sub_commute_add（验证转换）+ test_rule_sub_commute_no_lone_descend（验证守卫）。注册进 oppool1（5577）。
- 实测 curl/httpd 未触发（curl 的 P-code 已被前置简化），但模式匹配时正确生效。
- 2026-08-15（VARNODE-INPLACE-MUTATION-SITES-0001）：尾部换绑改为 `fd.op_set_output(longform, outvn)`（cc:4650，funcdata_op.cc:70-87）——先对 longform 旧输出走 `makeFree`、把 outvn 从旧 SUBPIECE 解绑，再 `VarnodeBank::setDef` 重键；替换旧手写 `old_out.def=None` + `outvn` 原地 WRITTEN/def 突变（不还树造成 def 树残留死键）。随后 `op_destroy`（cc:4651）。

### 2026-09-26：RuleSubCommute SDIV/SREM 臂补齐（RULEACTION-SUBCOMMUTE-SDIV-SEXT16-0001）

- KUNASDIV 车道双侧实证的真缺口：Rugra 对 INT_SDIV/INT_SREM 臂树内 deferred（"need sign_extend helper"），16 字节除法成语不重写、折叠永不发生——g_div 100/-7 oracle 折成常量 `0xfffffffffffffff2`，Rugra 留 `SUB168(SEXT816(100)/SEXT816(-7),0)`；INT64_MIN/-1 的 E2E panic 被此缺口屏蔽。
- 补齐（ruleaction.rs `RuleSubCommute::apply_op` SEXT 臂，逐字对齐 cc:4570-4602）：①offset==0 才 commute；②in(0) 必须 INT_SEXT（cc:4575-4578）；③in(1) 写则 def 必须 SEXT，任一 sext 输入尺寸 > outvn → `cancel_extensions` 部分抵销（SUBPIECE 保留，cc:4583-4589）；④in(1) 常量且 sext0In ≤ outvn 时 `sign_extend_size(val & calc_mask(outvn), outvn, insize) == val` 符号适配校验（cc:4592-4597，helper=rangeutil::sign_extend_size，address.cc:666 的忠实镜像）；⑤否则 return 0。
- 新增两个 1:1 helper：`shorten_extension`（cc:4463-4472，extension 输出缩到 maxSize，BE 空间保最高位字节，保空间 new_varnode_out_full）与 `cancel_extensions`（cc:4483-4512：longform 输出 loneDescend==subOp 守卫、等尺寸双侧 isFree 守卫、不等尺寸侧 shortenExtension+loneDescend 守卫、opUnsetOutput→newUniqueOut(maxSize)→三处 opSetInput 重绑）。isFree 语义双侧同体（constants 无 INPUT/WRITTEN flag → free，varnode.cc:578）。
- **INT64_MIN/-1 零守卫保持**（KUNAUB-SDIV-0001 裁决 (a)）：commute 后的 8 字节 SDIV/SREM 经 RuleSubCancel→RulePropagateCopy→RuleCollapseConstants 直通 opbehavior 除法——oracle SIGFPE（rc 136）/Rugra panic（opbehavior.rs:195/:212），无 golden、形态锁定。
- B2 双侧 fixture `tests/oracle/rule_subcommute_sdiv_1204.{cc,rs}`：16 例（双侧 SEXT 常量/寄存器输入、正/负除数、SEXT4/8→16 宽度边界、常量符号适配 fit/mismatch/high-bits、offset!=0、in0 ZEXT、in1 COPY、in1 寄存器输入、cancelExtensions 等尺寸/不等尺寸/常量-isFree 守卫、SREM 镜像例）normal 模式 **字节恒等**（oracle 直跑 vs Rust 镜像，sha 28d3bcd1…，含 unique 空间偏移全等）；trap_sdiv/trap_srem 模式双侧记崩溃形态（oracle SIGFPE rc=136/0 字节 stdout vs Rugra rc=101 panic）。
- 7 个新单元测试（sdiv_written/const_fit/const_sign_mismatch/offset_nonzero/zext_reject/partial_equal/partial_unequal）。
- 发现并另行登记的邻臂缺口（非本票域）：`RULEACTION-SUBCOMMUTE-ZEXT-PARTIAL-0001`（ZEXT 臂 written-in1 部分抵销仍 deferred）与 `RULEACTION-SUBCOMMUTE-SUBZEXT-OVERLAP-0001`（cc:4623-4629 RuleSubZext 重叠检查缺失）——**后者已由 BINSWEEPFIX 车道关闭（2026-09-26，见下节）**。

### 2026-09-26：RuleSubCommute 尾段 opSetInput 顺序修复 + RuleSubZext 重叠检查补齐（BINSWEEP-SUBCOMMUTE-FREEVARNODE-0001）

- CR-SUBCOMMUTE 发现③钉死的 P1：Rugra 尾段 commute 循环（ruleaction.rs `RuleSubCommute::apply_op` 尾段）把 oracle 的语句顺序反置——`newsub 先取 vn`（newsub slot 0 attach 在前）`longform 后释放`（slot i 换绑在后），而 oracle cc:4640-4641 是 **先 `opSetInput(longform,newVn,i)` 释放 vn、后 `opSetInput(newsub,vn,0)` 接入**（cc:4641 原注释逐字："vn may be free, so set as input after setting newVn"）。顺序承载语义，因为：
  - `Varnode::addDescend`（varnode.cc:334-336）对 free varnode（无 INPUT/WRITTEN flag）的第二个后代直接 `throw LowlevelError("Free varnode has multiple descendants")`——反置顺序下 vn 尚挂 longform 时被接入 newsub，非 const 自由 varnode 直撞 Rugra 忠实镜像 panic（varnode.rs:2716）：ip 语料 3 函数（print_addrinfo@0x13820/do_iptunnel/print_neigh）确定性 rc=101（master 亲证 561/7671/788ms）。
  - `Funcdata::opSetInput`（funcdata_op.cc:108-115）对仍被读取的常量做 dedup **副本**替换——反置顺序下 newsub 读到的是副本而非原 varnode（身份偏离 oracle；C 输出不可观测，良性但偏离）。
- 修复：尾段按 oracle cc:4637-4643 逐语句重排（newOp→opSetOpcode(SUBPIECE)→newUniqueOut(outvn 尺寸)→**opSetInput(longform,newVn,i) 释放**→**op_set_input(newsub,vn,0) 接入**→newConstant(4,offset) 在 slot-1 时点内联创建（不再前提，vbank create 顺序与 oracle 对齐）→opInsertBefore）；顺带消除 const 副本偏离（释放后 `has_no_descend` 为真→不触发 dedup 拷贝，newsub 直读原 varnode）。
- **顺带关闭 `RULEACTION-SUBCOMMUTE-SUBZEXT-OVERLAP-0001`（P3）**：本票双侧 fixture 的 add_free_zext_overlap 例暴露 Rugra 仍缺 cc:4623-4629 RuleSubZext 重叠前置检查（offset==0 且 outvn 的 loneDescend 是 INT_ZEXT 且其输出尺寸==insize → return 0）；同 commit 补齐（loneDescend 守卫之后、尾段循环之前）。补齐后 fixture 例从 sub_apply=1（Rugra 过触发）对齐到 sub_apply=0==oracle。
- E2E 亲证（双树 A/B）：ip 206/246/248 三函数 master=panic rc=101（varnode.rs:2716）→ 修复树 rc=0 + 非空 C（9774B/192383B/25951B），`bin_sweep --sweep-one` 三函数 `status ok`（1979ms/149834ms/3118ms）。
- B2 双侧 fixture `tests/oracle/rule_subcommute_freevn_1204.{cc,rs,oracle.out,metadata.json}`：13 例 normal **字节恒等**（free/free ADD panic 形态、free/const 双向、const/const、MULT/AND/OR16/NEGATE 单输入/XOR offset=4、same-written-vn dup-reuse 臂恰好一个新 SUBPIECE、ZEXT-overlap 拒绝、双读者拒绝；keep 行用指针身份锁常量不被 dedup 副本替换——readers/descends 双 1）；trap_dupfree 模式锁崩溃形态对（同一 free varnode 双槽：oracle LowlevelError rc=1 vs Rust panic rc=101 varnode.rs:2716，同文案——varnode.cc:336 不变量双侧保持，无 golden）。fixture 判别力亲证：master lib 跑 normal 模式第一例即 panic（rc=101, 0 行输出）。
- 门禁：canon curl 200/0/0（Matched 124）md5 `c33052a3…` + httpd 255/0/0（Matched 34）md5 `6923d6c1…` 双语料与 master 档案**字节恒等**（修复 canon 中性）；镜面四面 PASS 未重钉（curl 58/65·74/74+httpd 124/150·29/29+vsh 15/16·71/71+sq 6778/7500·810/810·numbering=0==现态）；bank 391/391；cargo test --lib 1783P/0F/5I==基线精确命中；rule_subcommute_sdiv_1204 双侧 fixture 复跑 16/16 MATCH 不回退。

### 2026-06-29：RuleFloatSign（ruleaction.cc:10714 + typeop.cc:153）
- `RuleFloatSign` — 检测浮点符号位操作并转换为 FLOAT_ABS/FLOAT_NEG：`x & 0x7fffffff => FLOAT_ABS(x)`，`x ^ 0x80000000 => FLOAT_NEG(x)`。辅助函数 `float_sign_manipulation` 对应 Ghidra `TypeOp::floatSignManipulation`（typeop.cc:153-176）。
- 触发于所有 FLOAT_ opcodes（18 个）。注册进 oppool1（5619）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续）：RuleSLess2Zero（ruleaction.cc:5693 + getHiBit 5641）
- `RuleSLess2Zero` — 简化 INT_SLESS 与 0/-1 的比较。形式包括：`-1 s< SUB(V,hi) => -1 s< V`、`~V s< 0 => -1 s< V`、`-1 s< CONCAT(V,W) => -1 s< V` 等。辅助函数 `get_hi_bit` 对应 Ghidra `getHiBit`（ruleaction.cc:5641-5664）。
- 触发于 CPUI_INT_SLESS。注册进 oppool1（5558）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 2）：RulePopcountBoolXor（ruleaction.cc:10258 + getBooleanResult 10317）
- `RulePopcountBoolXor` — 简化通过 POPCOUNT 组合的布尔表达式：`popcount((b1 << 6) | (b2 << 2)) & 1 => b1 ^ b2`。辅助函数 `get_boolean_result` 对应 Ghidra `getBooleanResult`（ruleaction.cc:10317-10402），追踪 INT_AND/XOR/OR/ZEXT/SEXT/LEFT 链提取布尔源。
- 触发于 CPUI_POPCOUNT。注册进 oppool1（5616）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 3）：RuleModOpt（ruleaction.cc:8612）
- `RuleModOpt` — 简化 INT_DIV/INT_SDIV 的模运算表达式：`x/d * (-d) + x => x%d`。检测 div2 是 div 的二补数（常量或 INT_2COMP）。
- 指针守卫：若任一输入是指针类型则跳过（防止指针算术被误匹配）。
- 触发于 CPUI_INT_DIV/CPUI_INT_SDIV。注册进 oppool1（5602）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 4）：RuleDivTermAdd（ruleaction.cc:7830 + findSubshift 7910）
- `RuleDivTermAdd` — 简化优化的除法表达式：`sub(ext(V)*c,b)>>d + V => sub((ext(V)*(c+2^n))>>n, 0)`，其中 n=d+b*8。
- 使用 Rust 原生 `u128` 替代 Ghidra 的 128 位多精度算术（set_u128/leftshift128/add128）。`is_constant_extended` 已存在（varnode.rs），`new_extended_constant` 新增到 funcdata.rs（funcdata_varnode.cc:462 忠实移植）。
- 辅助函数 `find_subshift` 对应 Ghidra `findSubshift`（ruleaction.cc:7910-7935）。
- 触发于 CPUI_SUBPIECE/INT_RIGHT/INT_SRIGHT。注册进 oppool1（5594）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 5）：RuleDivTermAdd2（ruleaction.cc:7955）
- `RuleDivTermAdd2` — 简化优化的除法表达式变体：`W+((V-W)>>1) => sub((zext(V)*(c+2^n))>>(n+1), 0)`，其中 W=sub(zext(V)*c,d)，n=d*8。使用 Rust 原生 u128。
- 指针守卫：若输入是指针类型则跳过。
- 触发于 CPUI_INT_RIGHT（shift==1）。注册进 oppool1（5595）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 6）：RuleSignMod2nOpt2（ruleaction.cc:8867）
- `RuleSignMod2nOpt2` — 转换 INT_SREM 形式：`V - (Vadj & ~(2^n-1)) => V s% 2^n`。
- 实现了 `check_sign_ext_form` 路径（INT_ADD，CDQ 风格符号扩展，ruleaction.cc:8910-8934）。
- MULTIEQUAL 路径（`checkMultiequalForm`）需块结构访问（getParent/getIn/getTrueOut），deferred。
- 触发于 CPUI_INT_MULT。注册进 oppool1（5604）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 7）：RuleSignMod2nOpt 去重确认
- `RuleSignMod2nOpt`（ruleaction.cc:8673）此前已完整实现并注册（oppool1 5603）。本轮清理了意外添加的重复定义。现有实现含 `check_sign_extraction` 辅助函数 + 完整模式匹配（含 trunc_size/ZEXT/SUBPIECE 变体）。

### 2026-06-29（续 8）：RuleSignMod2Opt（ruleaction.cc:8794）
- `RuleSignMod2Opt` — 转换 INT_SREM 特殊形式：`(V-sign)&1+sign => V s% 2`（sign = V s>> 63）。是 RuleSignMod2nOpt 的 mod-2 特化。
- 复用 `check_sign_extraction` 辅助函数。支持 SUBPIECE 截断变体。
- 触发于 CPUI_INT_AND。注册进 oppool1（5605）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 9）：RuleShiftPiece（ruleaction.cc:3791）
- `RuleShiftPiece` — 检测 `(zext(V) << #sa) | zext(V)` 并转换为 PIECE。也处理 CDQ 特殊情况（INT_SRIGHT 形成高位 → INT_SEXT）。两条路径均为纯数据流，无需块结构。
- 触发于 CPUI_INT_OR/INT_XOR/INT_ADD。注册进 oppool1（5549）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-07-01：oppool1 + cleanup 池大批补缺 Rule（21 条 + DivOpt 修复）

**Bug 修复**：
- `RuleDivOpt`（ruleaction.cc:8295）：补上 signed-division 路径缺失的 `moveSignBitExtraction` 调用（Ghidra ruleaction.cc:8335）。忠实移植 `moveSignBitExtraction`(8210-8253) 为 `move_sign_bit_extraction` + 辅助 `resolve_shift_const`。

**cleanup 池新增（coreaction.cc:5696-5708）**：
- `RuleAddUnsigned`(7182) — INT_ADD，`V+0xff..⇒V-0x00..`；仅锁定 fixture 覆盖的基础 UINT/UNKNOWN 路径已对拍，完整函数仍为 PARTIAL_MATCH。
- `RuleSubRight`(7269) — INT_SUB，sub right 规范化（含 lone-shift lump）
- `RuleFloatSignCleanup`(10789) — floatSignManipulation 1:1；TYPE_FLOAT 硬门精确对齐（ruleaction.cc:10774 `getMetatype() != TYPE_FLOAT → return 0`——未定型 varnode 默认 `getBase(s,TYPE_UNKNOWN)`（funcdata_varnode.cc:107/132），非 float 即不改写；2026-09-29 CASTSHAPE 车道移除 Rust 侧 size∈{4,8} 启发式放行，sqlite 镜面 CAST-SHAPE ABS 族 58 站点全量复原 `& 0x7fffffff`/`^ 0x8000000000000000` 形）
- `RuleExpandLoad`(10937) — helpers(checkAndComparison/modifyAndComparison) 1:1；applyOp 标 TODO（需 pointer datatype）
- `RulePtrsubCharConstant`(7372) — pushConstFurther helper 1:1；applyOp 标 TODO（需 TYPE_SPACEBASE/Scope/stringManager）
- `RuleExtensionPush`(7435) — descendant-count guard 1:1；duplicateNeed 标 TODO
- `RulePieceStructure`(7625) — helpers(determineDatatype/spanningRange/convertZextToPiece) 1:1；applyOp 全量(setPartialRoot cc:7642 → storage walk → 叶 COPY/非叶换存储 + setProtoPartial →
  `!anyAddrTied` 时 `registerProtoPartialRoot(outvn)` cc:7697-7698, 注册入 Funcdata 挂载的
  MergePersistentState 供 ActionMergeRequired groupPartials 分组; SB-IMPLIEDWAVE-0001)

**oppool1 独立族新增**：
- `RulePullsubIndirect`(962) — 可触发非 creation 分支（复用 RulePullsubMulti helpers）；indirect-creation/iop 分支标 TODO
- `RuleIndirectCollapse`(3177) — 标 TODO（需 iop-space coderef + characterizeOverlap）
- `RuleTransformCpool`(3915) — 标 TODO（Funcdata 无 get_arch/cpool accessor）
- `RuleSwitchSingle`(5430) — 标 TODO（需 findJumpTable/getStructure）
- `RuleNegateNegate`(9258) — **完全可触发**（`~~V⇒V`）
- `RuleConditionalMove`(9390) — checkBoolean helper 1:1；applyOp 标 TODO（需 block graph）
- `RuleFuncPtrEncoding`(9926) — 标 TODO（Funcdata 无 get_arch/funcptr_align）
- `RuleIgnoreNan`(9740) — 标 TODO（需 nan_ignore_all + block 查询）
- `RuleUnsigned2Float`(9795) — **可触发**（pattern+变换 1:1）
- `RuleInt2FloatCollapse`(9863) — 标 TODO（需 FlowBlock::findCondition）
- `RulePtraddUndo`(6927) — 标 TODO（需 hasTypeRecoveryStarted + opUndoPtradd）
- `RulePtrsubUndo`(7146) — **4 helper(getConstOffsetBack/getExtraOffset/removeLocalAddRecurse/removeLocalAdds) 1:1 完全移植**；applyOp 标 TODO（需 isPtrsubMatching）
- `RuleSegment`(9013) — 标 TODO（需 SegmentOp/userops）
- `RulePiecePathology`(10560) — INDIRECT case wired via `fd.get_op_from_const` + `is_call()` (对齐 ruleaction.cc:10507-10513). 标 TODO（bytes-consumed API for tracePathologyForward）

验证：832/832 测试（新增 13），curl 24/24 无回归。

**基础设施缺口（TODO 清单，均已在代码注释标注，未绕过）**：
1. Varnode 数据类型系统（get_type_read_facing/TYPE_UINT/TYPE_FLOAT/isCharPrint 等）
2. Funcdata 无 `get_arch()` 访问器（影响 TransformCpool/FuncPtrEncoding/IgnoreNan）
3. iop-space / coderef 解析缺失（影响 IndirectCollapse/PullsubIndirect）
4. block graph 访问（影响 ConditionalMove/Int2FloatCollapse/IgnoreNan 的 CBRANCH 路径）
5. Varnode flag/overlap API（isAddrForce/isTypeLock/isPrecisLo/Hi 等）
6. Funcdata 高级 op API（opUndoPtradd/newIndirectCreation/newVarnodeIop 等）

### 2026-07-01（续 2）：Layer-3 TODO 替换 — 接入基础设施让 Rule 生效
11 个 Rule 的 TODO 占位替换为真实基础设施调用：
- **RuleExtensionPush**(7435): is_addr_force/is_type_lock/is_name_lock + duplicate_need
- **RulePtraddUndo**(6927): has_type_recovery_started + op_undo_ptradd + type guard
- **RuleTransformCpool**(3915): get_arch().cpool + op_mark_cpool_transformed + CPoolRecord
- **RuleFuncPtrEncoding**(9926): get_arch().funcptr_align + mask compare
- **RuleIgnoreNan**(9740): get_arch().nan_ignore_all + find_condition
- **RuleInt2FloatCollapse**(9863): find_condition + cbranch flip
- **RuleIndirectCollapse**(3177): characterize_overlap/contains_storage + get_op_from_const + total_replace
- **RuleExpandLoad**(10937): space from_id + get_type/get_sub_type
- **RulePullsubIndirect**(962): is_addr_force/is_precis_lo/hi + new_varnode_iop/get_op_from_const
- **RulePtrsubUndo**(7146): is_ptrsub_matching + remove_local_adds(op->getOut())
  - 2026-08-25（B3-COREACTION-CONSTANTPTR-0001 段(b)）：`is_ptrsub_matching`
    的 Spacebase 分支修复为虚分发到 `TypeSpacebase::get_sub_type`
    （type.cc:2947-2969 的 override——借用的 `Datatype::get_sub_type` 无法
    暴露 scope 持有的 Arc，此前 Spacebase 臂恒走 base 行为返回 (None, off)
    导致 isPtrsubMatching 恒 false、PTRSUB 被误翻回 INT_ADD/常量）。
  - 2026-09-22（TYPE-SPACEBASE-SUBTYPE-DISPATCH-0001）：`Datatype::get_sub_type`
    签名改为 `(Option<Arc<Datatype>>, i64)`（虚返回 `Datatype*` 的所有权镜像），
    Spacebase 臂在**通用分派**内路由到覆写；本规则的 Struct 臂 `get_sub_type`
    walk、`RulePieceStructure::determine_datatype/spanning_range/convert_zext_to_piece`
    与 `AddTreeState::calc_subtype` 的 walk 改持 canonical component Arc
    （不再深拷贝，`Arc::new(st.clone())` → `st`），语义与 Ghidra
    factory-owned `Datatype*` 一致。消费链 `ActionSetCasts`（coreaction.rs 经
    `pointer_is_ptrsub_matching`）与 `TypePointerRel` 委托同享该路由。
- **RuleConditionalMove**(9390): get_true_out/get_false_out (bool-const-const path)

仍保留为 guard+no-op（需更深基础设施）：RulePtrsubCharConstant(需 stringManager)、RulePieceStructure(需 PieceNode/gatherPieces)、RuleIgnoreNan 深度路径、RuleConditionalMove 非 const 路径、RuleIndirectCollapse 创建/空间库分支。每处 TODO 精确标注缺失项。

### 2026-07-01（续 3）：Layer-5 TODO 替换 — update_type/new_indirect_creation/find_jump_table/get_store_guard
- RulePtrsubCharConstant: push_const_further 加 outtype 参数 + update_type（cc:7351）
- RuleExpandLoad: modify_and_comparison 加 dt 参数 + update_type ×2（cc:10915）
- RuleExpandLoad apply: new_out update_type（cc:10994）
- RuleAddUnsigned: copy_symbol（cc:7211）——2026-09-26（RASWEEP 车道，RULEACTION-ADDUNSIGNED-COPYSYMBOL-HIGH-0001，取材 wt/globvars 1a04cbec 按内容重放）升级为 copy_symbol_arc 完整移植：含 varnode.cc:500-504 high 记账（typeDirty/setSymbol(this)），原字段半拷贝在 cvn 已挂 HighVariable 时漏掉 high 侧同步（注：b61eb3f0 散文重钉曾意外覆写本注记与上条 ExpandLoad 注记，root 集成侧按 CR-RASWEEP F2 恢复并勘正行引）
- RulePullsubIndirect: indirect-creation 分支完整移植 new_indirect_creation（cc:998-1002）
- RuleIndirectCollapse: STORE guard 完整移植 get_store_guard + is_guarded（cc:3223-3236）
- RuleSwitchSingle: 完整 applyOp（find_jump_table + jt 判断 + BRANCH 改写 + remove_jump_table + structure clear，cc:5430-5477）

### 2026-07-01（续 4）：Layer-6 剩余 TODO 填补（12 处）
RuleAddUnsigned: get_type_read_facing + TYPE_UINT/!is_char_print 守卫（cc:7188-7190）。RuleSubRight: does_special_printing + is_piece_structured + is_addr_tied + get_base_type(Uint/Int)+update_type。RuleFloatSignCleanup: TYPE_FLOAT 判断。RuleExpandLoad: get_base_type(Uint) 重写。RuleIndirectCollapse: has_no_local_alias + no_indirect_collapse + INDIRECT_CREATION。RuleSwitchSingle: warning_header 替换 eprintln。RulePtrsubUndo: clear_stop_type_propagation + op_undo_ptradd 完整接入。RuleSegment: userops.get_segment_op 接入 + contiguous_test/findContiguousWhole 移植。RuleTransformCpool: tf.find_by_name(rec.type_name) + update_type_lock。剩余 10 处 TODO 每处精确标注缺失 API（SymbolEntry/resolveConstant/PieceNode/CloneBlockOps/functionalEquality/SegmentOp.execute）。

### 2026-07-01（续 5）：determine_datatype partial path + RulePtrsubCharConstant full transform
- determine_datatype（ruleaction.cc:7463-7492）：partial 路径用 get_structured_type + get_symbol_entry + SymbolEntry::get_addr/get_offset + get_sub_type walk 实现。不再对 partial 返回 None。
- RulePtrsubCharConstant（ruleaction.cc:7372-7421）：完整 transform。用 Funcdata::string_table 做 read-only+string 检查（symaddr=vn1 offset，spacebase base=0）。PTRSUB→COPY of constant pointer + update_type。删除 resolveConstant/isReadOnly TODO（退化 via string_table）。

### 2026-07-01（续 6）：oppool2 完整移植（5 条 Rule，0%→100%）
- RuleLoadVarnode（ruleaction.cc:4277 applyOp / 4271 getOpList）+ correct_spacebase（4173）/vn_spacebase（4194）/check_spacebase（4236）helper — LOAD→COPY 栈变量化。2026-08-18（PRINTC-INPUTREG-DEADSTORE-0001）：correct_spacebase 非常量 spacebase-input 腿接通——签名加 `glb`（对应 oracle `Architecture *glb`；Rust 侧为 `Option<&Architecture>`，因 Rugra Funcdata 可在 set_arch 前存在；const 腿不咨询 glb，与 oracle 一致）→ `Architecture::get_space_by_spacebase`（architecture.cc:264-282）+ `get_contain()==Some(spc)`（base space.hh:505，SpacebaseSpace override translate.hh:187）；三个 helper 与两个 applyOp 全部穿传 glb（cc:4285/4326 checkSpacebase(data.getArch(),...)）。oracle fixture：tests/oracle/rule_store_varnode_spacebase_1204（registry 观察 + 8 rule-call case，双侧逐字节一致）。
- RuleStoreVarnode（4319）— STORE→COPY 栈变量化。2026-08-15（VARNODE-INPLACE-MUTATION-SITES-0001）：输出创建改为 `vbank.create_def_with_space`（对应 `Funcdata::newVarnodeOut` funcdata_varnode.cc:104-122 → `VarnodeBank::createDef` varnode.cc:1411-1418，cc:4331-4332）——以最终 (space,offset) def 键直接创建已 WRITTEN varnode + op 输出接线 + `set_varnode_properties`；替换旧的 free 创建后原地 WRITTEN/def 突变。2026-08-18（PRINTC-INPUTREG-DEADSTORE-0001）：spacebase 链（`INT_ADD(RSP_input, const)`，含交换操作数序）现在命中并重写为 stack COPY + setStackStore（cc:4333）——此前该族 STORE 存活到 printc（curl E2E 29 处/11 函数 `= in_R` 序言 store；修复后 push 家族 `*uVar20 = in_RBP` 归零，残余 14 处集中在 3 函数——my_get_line 11、glob_word 2、glob_set 1——全部是 `*uVar20`/`*uVar_9d00` 指针链 STORE，即地址操作数非裸 spacebase/`INT_ADD(RSP_input,const)` 形态，oracle vnSpacebase（cc:4194-4227）同款守卫同样拒绝；其归一化/删除依赖 varmap local_XX 命名与死存储消除域的既有缺口，非本租约）。
- RulePtrArith（6629）+ AddTreeState 状态机 + verify_preferred_pointer/evaluate_pointer_expression — INT_ADD/MULT→PTRADD/PTRSUB。
- RulePushPtr（6852）+ build_varnode_out/collect_duplicate_needs/duplicate_need — 指针 push 到使用点。
- RuleStructOffset0（6678）— struct offset 0 下钻 PTRSUB。
20 新测试。

### 2026-07-01（续 7）：3 条缺失 Rule 实现 + 注册
- RulePtrFlow（ruleaction.cc:9050-9251）：指针流传播+截断。trialSetPtrFlow/propagateFlowToDef/Reads/truncatePointer。注册 oppool1:5624。has_truncations 默认 false（Rugra 无 isTruncated 空间）。
- RuleDumptyHumpLate（subflow.cc:3006-3064）：SUBPIECE(PIECE) 回溯。注册 cleanup:5699。
- RuleOrPredicate（condexe.cc:509-635）：impl Rule trait（包装现有 apply_op）。注册 oppool1:5631。
13 新测试。

### 2026-07-01（续 8）：PieceStructure piece 重组引擎 + Segment 常量折叠
- PieceStructure：PieceNode struct + is_leaf_node + gather_pieces（op.cc:801-876）+ convert_zext_to_piece（cc:7543）+ find_replace_zext + separate_symbol + apply_op 真正变换（cc:7607-7700）。4 新测试。
- 2026-08-24（TYPEFACTORY-EXACTPIECE-CALLERS-0001）：删除本地 `get_exact_piece` 副本（其 `Arc::new(ct.clone())` 丢失 canonical identity，且无 partial 构造）。apply_op 的 leaf 类型改从 Architecture-owned TypeFactory 的 canonical `get_exact_piece`（ruleaction.cc:7665 `data.getArch()->types->getExactPiece`）获取，null 时回退 `vn->getType()`（cc:7666-7667）；Architecture 未接线时 fail-closed 回退 leaf 旧类型，不查任何全局替身工厂。双侧门禁 `tests/oracle/exactpiece_callers_1204`。
- `RulePieceStructure::apply_op` 在替换非叶 Varnode 后显式传播 `VarnodeBank::destroy_varnode` 的失败；这对应 Ghidra `data.deleteVarnode(vn)` 对仍集成 Varnode 抛出的 `LowlevelError`，不会吞掉结构不变量错误。该错误路径未纳入本次 RuleCollectTerms fixture，状态仍为 `UNTESTED`，不属于下述七个目标结构投影的批准范围。
- Segment：SegmentOp::execute（userop.cc:218）+ supports_far_pointer/has_far_pointer_support。RuleSegment::apply_op 常量折叠分支（cc:9024）+ far-pointer 分支（cc:9034）+ contiguous_test/find_contiguous_whole helper。4 新测试。

### 2026-07-01（续 9）：PiecePathology + IgnoreNan 深度路径
- PiecePathology：isPathology（ruleaction.cc:10427-10505）递归 def 链遍历 + tracePathologyForward（10506-10559）前向 descend 追踪到 CALL/RETURN 记 bytes_consumed。apply_op 双路径（SUBPIECE + INDIRECT）。
- IgnoreNan 深度路径：checkBackForCompare（9604-9639）+ isAnotherNan（9646-9659）+ testForComparison（9678-9720）三种合并路径 + CBRANCH 保护。nan_ignore_all=false 时真正执行 NaN 数据流移除。
- fspec.rs：FuncProto +return_bytes_consumed + FuncCallSpecs +input_consume Vec + getter/setter。

### 2026-07-01（续 10）：4 条 stub/partial Rule 补全
- SubfloatConvert：常量折叠路径（subflow.cc:3394-3403）。非 const 保持 NO_CHANGE（完整 SubfloatFlow 精度追踪 TODO）。
- ConditionalMove 非 const 路径：gather_expression + construct_bool（ruleaction.cc:9287-9341）。值在分支前形成的非 const 情况能产生 BOOL_OR/AND。
- RuleEarlyRemoval：本行“6 guard 全对齐”是旧的代码形似结论；2026-08-28 锁定
  fixture 只批准 14/14 covered projection。IOP/FSPEC manager、nullable input、
  reset/clear/propagateCopyAway 与完整 OpBank/错误路径仍未闭合。
- AddTreeState distribute/collapse：while 循环补全（ruleaction.cc:6475-6491）+ collapse_int_mult_mult。

### 2026-07-01（续 11）：PtrsubUndo testForArraySlack + PtrsubCharConstant stringManager
PtrsubUndo：test_for_array_slack（type.cc:990-1005）+ nearest_arrayed_component_forward/backward + get_lower_bound_field。数组 slack 现在允许 PTRSUB。
PtrsubCharConstant：stringManager.is_string 精确守卫（ruleaction.cc:7393）。string_table + is_string 双重确认。6 新测试。

### 2026-07-01（续 12）：empty pairs guard
RulePushMulti find_substitute 对空 pairs 防越界。

### 2026-07-01（续 13）：RulePtrFlow has_truncations=false 是正确行为（非缺陷）
Ghidra 的 `hasTruncations` 检查 `glb->getDefaultDataSpace()->isTruncated()`。`isTruncated` 是地址空间属性（space.hh:94），仅在 16-bit x86 等有段截断的架构上为 true。x86-64 没有截断空间，所以 `has_truncations=false` 对 x86-64 是**正确**的——RulePtrFlow 应该在该架构上不触发。**非缺陷，无需修复**。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- 调用点 `v1.contains_storage(&v2)` → `v1.contains(&v2)`（配合 varnode.rs 的 `contains_storage`→`contains` 重命名，对齐 `Varnode::contains`）。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-15：RuleMultiCollapse 常量值等价走 absolute 路径（RULE-MULTICOLLAPSE-ABORT-0001）

`RuleMultiCollapse::apply_op` 的 while 匹配循环在 `functional_equality_level`
之前新增常量值同一性检查：defining branch 与待匹配分支均为常量且
(size, offset) 相等时，视作 absolute 匹配 `continue`，不置 `func_eq`。

依据（锁定 12.0.4 e40ed130）：
- `ruleaction.cc:3279` `else if (defcopyr == copyr) continue;`——指针同一性
  走 absolute 路径；对常量而言值同一性即指针同一性的语义等价
  （`expression.cc:407` 指针相等、`expression.cc:409-412` 同值常量对均返回
  level-0 码 0）。
- `ruleaction.cc:3306` `newop = defcopyr->getDef()` 是无条件解引用；当
  defcopyr 是未 written 常量时为 null。实证：锁定 oracle 对
  `MULTIEQUAL(c0a, c0b)`（两个同值不同对象的常量分支）在 applyOp 内
  SIGSEGV（fixture `rule_multi_collapse_abort_1204` 以 fork 子进程复现并
  记录）。因此 Ghidra 自身在该形状下 func_eq 分支不可存活，其意图语义由
  `ruleaction.cc:3334` 的 absolute totalReplace 给出。
- 修复后不变量：`func_eq == true` ⇒ defcopyr 已 written 且 def 存活——
  与 cc:3306 假设一致；7519 处的 Lowlevel 错误保留为真不变量守卫。

该形状曾使 curl 的 main/glob_word/glob_set 三函数管线中止于
`RuleMultiCollapse functional branch has no definition`（scope=None、
HighVariable=0、sblocks=0）；修复后三函数完整产出结构。

## 测试区维护（2026-08-17）

`test_rule_sub_commute_add` / `test_rule_sub_right_basic` 的 harness 修正
（VARNODE-ADDDESCEND-THROW-0001 前置件）：被规则代码重读的 free 寄存器
varnode 经 `VarnodeBank::set_input`（varnode.cc:1358 setInput 映射）登记为
INPUT，消除 addDescend throw 会触发的 Ghidra 不可达 harness 态；断言与
规则分支路径（is_written/is_addr_tied 保持 false）零变化，生产代码未动。
<!-- annotation-pass: 2026-08-17 -->

### 2026-08-20：RuleAddUnsigned 类型前置条件与真实 oracle（RULE-ADDUNSIGNED-TYPEPRECOND-0001）

`RuleAddUnsigned::applyOp`（锁定 12.0.4 `ruleaction.cc:7182-7214`）先读取
slot 1 常量的 read-facing 类型，并在位模式判断前要求 `TYPE_UINT`。因此
`Funcdata::newConstant` 产生的 canonical `TYPE_UNKNOWN`（
`funcdata_varnode.cc:66-75`）不是可触发输入。旧的两个单元测试现在显式使用
同一 `TypeFactory` 的 canonical `TYPE_UINT`；另加默认 UNKNOWN 拒绝回归，
生产 `apply_op` 守卫未放宽。

锁定 fixture `rule_addunsigned_typeprecond_1204` 覆盖 `getOpList` 以及
`unknown_ff`、`uint_ff`、`uint_7f` 三例，逐字节比较 7 行：返回值、opcode、
输入/输出身份、新常量值与 create-index、canonical 类型身份、type/name lock、
SymbolEntry 链接、def-use、alive/dead/block 状态均为 `MATCH`。整体状态保持
`PARTIAL_MATCH`：Rust-only `None` 路径、op-aware union resolution、char-print、
真实 named equate、enum named-value、规则名 `add_unsigned`/`addunsigned` 以及
pool repeat 尚未闭合，全部继续绑定 `RULE-ADDUNSIGNED-TYPEPRECOND-0001`。

## equate 门控连带测试修正（2026-08-23，root）

`collapse_constants_symbol_propagation_via_marked_input` 随 VARNODE-COPYSYMBOL-EQUATE-0001 忠实化更新：测试侧注册 equate 值须与 **collapse 后输出** value-close（0x33333333），注册原始输入值（0x11111111）会被 isValueClose 正确拒绝——这是 oracle 语义而非回归。

## CALLSPEC-IDENTITY-D0 RulePiecePathology 接线（2026-08-24）

`RulePiecePathology::find_call_spec_for_op` 现在先用
`Funcdata::get_call_specs_of_op` 解析 exact owner，再用 `Arc::ptr_eq` 恢复 qlst
索引；已删除 `op_addr`/数值地址回退。因此同一机器地址上的不同 CALL 不会共享
bytes-consumed 状态，裸 offset 相同但无 typed FSPEC handle 的 constant 不能仅凭
该整数命中；若 op 本身已精确绑定，仍可走 oracle 的 exact-op fallback。规则先在
read guard 内快照可更新条件，再释放 guard 后取得 write guard
修改 `input_consume`，保持 Ghidra 的槽遍历与计数时机，同时避免 Rust 锁重入。

该接线只覆盖 callspec identity/guard 生命周期，RuleAction 整体仍为
`MISMATCH`。Rugra 继续以 `AddressSpace::Iop` 暂代专用 `IPTR_FSPEC`
（`TYPEOP-FSPEC-SPACE-0001`），且本阶段不接 TypeOp getter、PrintC、
StringManager 或其它既有 Rule/callspec 残差。

`RuleLoadVarnode::apply_op` 的 spacebase-placeholder 尾部仍未调用
`FuncCallSpecs::resolveSpacebaseRelative`。D0 已解除 exact owner lookup 前置件，
但该方法与状态突变尚未建模、也未由双侧 fixture 执行，因此保持 `UNTESTED` 并
绑定 `CALLSPEC-0001`；不能再把残差描述成“callspec 尚不存在”。

## RuleLoadVarnode placeholder 解析尾巴（ruleaction.cc:4294-4303，本次新增）

LOAD→COPY 转换后：若 `refvn = op->getOut()` 带 spacebase_placeholder 标记，
清除标记、取 `loneDescend` 为 CALL、`getCallSpecs(placeOp)` 后调用
`resolve_spacebase_relative` 记录该 call 点的 stackoffset（并可能
abort placeholder）。闭合 CALLSPEC-0001 中登记的
"resolveSpacebaseRelative is still absent" 残差。

## RulePtrArith/AddTreeState 类型链补齐 + RulePieceStructure 再入闸门（RULE-PTRARITH-ADDTREE-0001，本次新增）

- `AddTreeState::assign_propagated_type`（ruleaction.cc:6342
  `AddTreeState::assignPropagatedType`）：PTRADD/PTRSUB 新建 op 的输出类型
  由指针输入经 opcode `propagateType`（→ `propagateAddIn2Out` downChain）
  推导；`build_tree` 在 `data.isTypeRecoveryExceeded()` 时于 PTRADD 段与
  PTRSUB 段各调用一次（ruleaction.cc:6502/6514）——传播循环已停时由
  规则自身盖章。此前该链完全缺失。
- `AddTreeState::build_tree` 的 PTRSUB 段 `setStopTypePropagation` 现在仅在
  `size != 0` 时设置（ruleaction.cc:6516-6517）；此前无条件设置。
- `RulePieceStructure::apply_op` 补上 `op->isPartialRoot()` 再入闸门与
  `op->setPartialRoot()`（ruleaction.cc:7610/7642，flag = PcodeOp
  addlflags `concat_root` 0x100，见 op.rs `is_partial_root`/`set_partial_root`）。
  缺失时 cleanup 池对同一 CONCAT 根每轮重走并返回 change，
  universal 尾部永不收敛（main 全量超时的根因）。
- 双侧 fixture：`tests/oracle/ptrarith_addtree_1204.{cc,rs}` + runner
  `tools/run_ptrarith_addtree_oracle.sh`，5 用例（PTRADD 多倍数路 /
  PTRSUB 子类型路 / 非倍数 valid=false / 未类型化基座 / 未启动 type
  recovery）10 条记录与锁定 12.0.4 oracle 逐字节一致。

## 2026-09-23：AddTreeState calc_subtype SPACEBASE 臂 miss 回退接通（SB-MATCHURL-ORD191-0001，TYPE-SPACEBASE-MISSFALLBACK-0001 关闭）

- 根因（锁定 oracle e40ed130 双侧 drill 实证）：match_url Phase 2 首分歧
  ordinal 191 `universal:fullloop:mainloop:oppool2`（oracle result/count
  23/23 vs rugra 15/15）——oracle 在 0x52b0~0x5390 窗口对 `RSP(i)+#const`
  与 pushptr 产物 `RSP(i)+(RAX+#const)` 触发 RulePtrArith/AddTreeState，
  产出 PTRSUB（opcode_name 表显示名 CROSSBUILD）+ INT_ADD 常量折叠链
  （`7d7=RSP->#0x68`、`7d6=#-0x68+t`、`7d8=7d7+7d6`）；rugra 的 pushptr
  七连发后 calc_subtype 在 TYPE_SPACEBASE 臂因 `TypeSpacebase::get_sub_type`
  miss 返回 None 而 `valid=false`，ptrarith 一发未响（差 15 fire；
  AddTreeState walk 本身与 oracle 逐字段一致：size=0/offset=0x68/
  nonmultsum=0x68/nonmult=1）。
- 修复在类型层而非规则层：`TypeSpacebase::get_sub_type` 的 miss/无 scope
  路径改为 type.cc:2964-2966 的 `getBase(1,TYPE_UNKNOWN)`+`newoff=0` 语义
  （见 docs/api/type_system/datatype.md）；`calc_subtype` SPACEBASE 臂
  注释更新为引用 6296-6310 的 offsetbytes/hasMatchingSubType 结构与
  arrayHint!=0 时 nearestArrayedComponent*（未建模，无容器栈状态下两条
  臂在 oracle 侧同为 extra=0）的等价性说明。
- 验证：双侧 drill path layer 104 条共享路径计数全部相等
  （oppool2:ptrarith 23=23）；match_url 投影 ops 80385=80385，首分歧
  191→317（`universal:prefercomplement`，oracle 1 vs rugra 0，新域移交）；
  fixture `tests/oracle/type_spacebase_subtype_1204` 10/10 记录 MATCH
  （ghidra/rugra stdout sha256 相同）。

## 2026-08-27：RulePullsubMulti 非 join 输出空间（RULE-PULLSUB-NEWVNODEOUT-0001）

`RulePullsubMulti::build_subpiece` 对照 `ruleaction.cc:776-839`：非 join 基底按
`cc:816-821` 的端序计算 `smalladdr1`，并在 `cc:828-829` 的 renormalize 后以
`newVarnodeOut` 建立输出，因此输出保留基底的地址空间（Ram/Register/Stack 等），不再
无条件落入 Unique。Rugra 当前 Address 是标量，renormalize 等价为空操作；本实现仅在
`AddressSpace::Join` 仍使用 Unique fallback，因为 JoinRecord 基础设施尚未存在。该 join
臂绑定本 TODO，不能据此宣称 RulePullsubMulti 完整 MATCH。

## 2026-08-29：五个 Rule 的输入改写接入 descend 簿记（VARNODE-DESCEND-BOOKKEEPING-0001）

直接 `op.inrefs` 写点绕过 `op_set_input`/`op_remove_input` 的 descend/coverdirty 簿记，
在 Varnode 上留下悬空 descend 条目（w-newvarnode 审计：curl 全语料 49 条，全部为
Const/4@0x0 悬挂在 INT_ZEXT(43)/INT_AND/INT_RIGHT 上）。悬空条目使
`ActionInferTypes::build_localtypes` 的忠实 descendant 折叠抛
`Lowlevel("NULL local type")`、10 个函数管线中止，并且在此前就静默腐蚀一切基于
descend 的下游逻辑（getparameter 非法嵌套 else 即其下游）。逐 Rule 修复（全部镜像
Ghidra 的簿记 API 调用序）：

- `RulePiece2Zext::apply_op`（ruleaction.cc:227-228）：`opRemoveInput(op,0)`+
  `opSetOpcode(ZEXT)`——原直接 `inrefs.remove(0)` 是 43/49 悬空条目的来源。
- `RulePiece2Sext::apply_op`（ruleaction.cc:256-257）：同上（SEXT）。
- `RuleTrivialBool::apply_op`（ruleaction.cc:2431-2469）：完整六分支移植——常量仅从
  slot 1 读（Ghidra 不检查 slot 0），`V&&0→#0`、`V||1→#1`、`V^^1→NEGATE` 三分支补齐；
  改写序 `opRemoveInput(op,1)`→`opSetOpcode`→`opSetInput(op,vn,0)`。
- `RuleNegateIdentity::apply_op`（ruleaction.cc:468-470）：`newConstant` 后经
  `opSetInput(logic,const,0)`+`opRemoveInput(logic,1)`+`opSetOpcode(COPY)` 改写；
  常量创建从 `vbank.create_constant` 改为 `fd.new_constant`（镜像 `data.newConstant`
  的 assignHigh）。
- `RuleNotDistribute::apply_op`（ruleaction.cc:1179-1181）：`opSetInput(op,newout1,0)`+
  `opInsertInput(op,newout2,1)` 替代直接重建 inrefs。

E2E（3fb97c11+本修复，`/dev/shm/rugra-descendfix-curl.c`）：管线中止 10→0；
raw `register0x|unique0x` 命名 1077→16；defects 2→0（getparameter/glob_word 的
else 缺陷随悬空清除消失）；skeleton 3528→2134（优于 2d78b5af 健康基线 2881）；
glob_range 新出现 1 个重复声明 `iVar3`（numbering，登记
VARMAP-GLOBRANGE-DUPDECL-0001 待查）；`cargo test --lib -- --test-threads=1` 失败集
与已知 17 个逐项相同，零新增。

## 2026-08-29:RuleNegateIdentity 的 calc_mask 边界修正(RULE-NEGATEIDENTITY-CALCMASK-BOUNDARY-0001)

机制 C 独立复核(R-DESCEND-CROSSREVIEW-2026-08-29.md,APPROVE)发现:f91eb0265(06-26)起
`RuleNegateIdentity::apply_op` 的 OR/XOR 折叠值用手写 `size >= 64` 饱和边界(bits/bytes 混淆),
Ghidra `calc_mask`(address.hh:499,经 ruleaction.cc:467 调用)阈值是 **8 字节**——size∈[8,63] 时
release 下 `(1u64 << (size*8)) - 1` 移位溢出为错值(应全 1)。修正为调用本模块已有的忠实
`calc_mask`(ruleaction.rs:1346 镜像)。curl 语料未命中该 corner,属未覆盖分支修复。

## 2026-08-30:RuleLoadVarnode 补符号尾(RULE-LOADVARNODE-SYMBOLTAIL-0001)

w-typeflow 根因③落地:ruleaction.rs RuleLoadVarnode::apply_op 的 create_with_space 裸建全局地址
varnode 丢掉了 oracle newVarnode(funcdata_varnode.cc:148-172)的符号尾(queryProperties→
setSymbolProperties→updateType,typelock 门控);同文件 RuleStoreVarnode(:17080)本就正确。
补 `fd.set_varnode_properties(&newvn)`(A/B 预验证补丁)。

## 2026-08-30:RulePullsubIndirect 恢复寄存器空间(RULEACTION-PULLSUB-SPACE-0001)

w-rc5 双侧实证:Ghidra ruleaction.cc:996-1002 的 smalladdr2 是带空间全 Address,经
newIndirectCreation(funcdata_op.cc:710)输出落 register:0;Rugra 用无空间 Address 调 legacy
new_indirect_creation(硬编码 Unique)→ which_trial_in_space 同空间匹配(fspec.cc:1982)永不命中 →
trial 失活 → CALL 无 output → varmap 忠实产出 extraout_var_00。patch(w-rc5 fixsim 预验证):
改调 new_indirect_creation_in_space 传 vn 空间。效果:main 与 golden 逐 token 同形
(`iVar4 = strnequal("--",pCVar6,2); if ((iVar4 == 0) && ...`),3 个 extraout_var* 全消,
skeleton 3108→3068。

## 2026-08-30:Rule2Comp2Sub 重写为忠实形态(RULEACTION-NEGATION-FORM-0001)

w-printc2 C3 残差落地:此前 Rugra 的 Rule2Comp2Sub 把**每个** INT_2COMP 无条件改写成
`INT_SUB(0, V)`(2comp→sub+插 0),而 oracle(ruleaction.cc:7224-7237)只在 2COMP 输出
有**唯一** INT_ADD 父时触发:把该 ADD 原地改写成 `V - W`(槽 0 是 2COMP 输出时先交换),
并 `opDestroy` 彻底删除 2COMP;无 ADD 父的 2COMP 保留一元 `-V` 形。错误改写使 curl 输出
产生 30 处 `x + (0 - y)`(golden 应为 `x - y`/`-y`)。修正后 Rule2Comp2Sub::apply_op
逐行对齐 loneDescend 门 + 槽交换 + opDestroy。双侧 fixture:
tests/oracle/rule_2comp2sub_1204.{cc,rs} + tools/run_rule_2comp2sub_oracle.sh
(五形态:两种改写方向 + 非 ADD/无后代/双后代三拒绝,MATCH)。curl 门禁 3119→3115,
defects/numbering 保持 0,`(0 - ` 残留 30→0。

## 2026-09-23：addmultcollapse spacebase 臂 + pullsub_multi loop-in 守卫（Phase 2 ordinal 28）

1. **RuleAddMultCollapse spacebase 臂移植**（ruleaction.cc:4122-4169）：
   `((stackbase + c1) + othervn) + c0 => (stackbase + (c0+c1)) + othervn`。
   旧码在 c[1] 非常量时直接返回（自认"deferred"）；match_url ordinal 28 的
   −3 addmultcollapse（52f1:10f/52f5:113 `u0x8f00 = u0x9500 + #const`，
   u0x9500=`RSP(i)+RAX` 形）即此臂缺失。守卫链逐条同 oracle：othervn
   非常量非 free、sub2 written 且 def=INT_ADD、baseop slot1 常量、
   basevn `is_spacebase() && is_input()`（"because this adds a new add
   operation"）；创建序=newConstant(+copySymbolIfValid c0/c1)→newOp(2,
   op->getAddr())→INT_ADD→newUniqueOut→双输入→opInsertBefore(op)→
   op 改写 (newout, othervn)。
2. **RulePullsubMulti cc:883 守卫接入**：`mult->getParent()->hasLoopIn()`
   拒绝循环头 phi（见 docs/api/block.md 同日条目）；parent 缺失（悬空
   MULTIEQUAL，oracle 不可达形态）保守放行 false。
验收：match_url Phase 2 ordinal 28（oppool1 861=861）→29（lanedivide 2=2，
见 docs/api/arch.md）连续两级对齐；curl/httpd E2E defects=numbering=0。

## 2026-09-23：RuleRangeMeld 残差三件 + RuleSubRight lump 地址源（RULEMELD-FIDELITY-RESIDUE-0001 / EZ + CR11 O-1）

- **RuleSubRight lump 臂 shiftop 地址源（CR11 O-1）**：cc:7299
  `data.newOp(2,op->getAddr())` 的 `op` 在 cc:7286 已重绑为 `lone`（幸存的
  INT_RIGHT/INT_SRIGHT），shift op 必须继承 **lone 的地址**，不是被 unlink 的
  原 SUBPIECE 地址。ruleaction.rs 修复为从 `working_op_ref`（镜像重绑后 `op`
  的 Rust 变量）取地址；`op_insert_before`/`op_set_input` 早已走同一变量。
  行为锁：`test_rule_subright_lump_unlinks_original_subpiece` 现给 lone 独立
  地址 0x2000 并断言 shiftop.get_addr()==0x2000。
- **RuleRangeMeld markup 传播（cc:1414-1417）**：重建比较 op 时
  `newConst->copySymbolIfValid(markup)` 此前缺失。现在 apply_op 持有单个共享
  `markup: Option<Arc<RwLock<Varnode>>>`（cc:1377 语义：跨全部 pullBack、从不
  清零、cc:1069-1070 每次符号常量覆盖=最后写者胜），translate 成功臂对
  `fd.new_constant` 产物调用 `Varnode::copy_symbol_if_valid`。
- **cc:1401 isHeritageKnown 真判定**：`if (!A1->isHeritageKnown()) return 0`
  是 varnode.hh:298 的 flag 检查（`flags & (insert|constant|annotation)`），
  此前用 `is_free()` 代理（双向偏差：INPUT-only 无 INSERT 的形态被放行，
  bank 注册未写 varnode（INSERT 置位但 free）被拒）。现接
  `Varnode::is_heritage_known`（varnode.rs 既有忠实实现）。三个既有 meld
  fixture 同步改走 `fd.vbank.set_input`（真实输入路径=setInput→xref→INSERT，
  varnode.cc:1306），不再手拼 INPUT flag。行为锁：
  `test_rule_range_meld_heritage_unknown_varnode_bails`（INPUT-only 无 INSERT
  → NO_CHANGE）。
- **pull_back_op 删除（TODO ③ 的另一半）**：简化版 pullBack（无 constMarkup、
  无 cc:1053-1065 SUBPIECE nzmask 补救臂、无 cc:1075-1082 nzmask 尾交集）已
  删除，6 个调用点全部切到正典 `CircleRange::pull_back(op, usenzmask,
  &mut markup)`（rangeutil.rs 全量版）。RangeMeld 路径 usenzmask=false 与
  oracle 一致（SUBPIECE 补救臂对该规则为死路，同 Ghidra）；markup 出参见
  docs/api/rangeutil.md 同日条目。
- 测试：markup 传播端到端锁
  `test_rule_range_meld_markup_propagates_to_new_constant`（`(V<5)||(V==5)`
  合并常量 6 携带 c5 的 equate SymbolEntry）。

## 2026-09-24：AddTreeState pRelType 机制补全（MYPROGRESS-OPPOOL2-CONSTSPLIT-0001 归因交付，ruleaction.cc:5992-6069/6236-6241/6314-6336）

- 归因（锁定 oracle e40ed130 双侧 drill + 作用域 dump 实证）：myprogress 首分歧
  ord 150 `mainloop:oppool2` 的互补 ±1 常量拆分定位到
  `AddTreeState::calc_subtype` TYPE_SPACEBASE 臂的 `hasMatchingSubType`
  `extra`——oracle 对 `RSP(i)+(RCX+#-55)` 答出 extra=1（PTRSUB `#-0x38` +
  INT_ADD `#0x238`），rugra 恒答 extra=0（`#-0x37`+`#0x237`）。parseconfig
  ord 186 同族（`#-0x4e8`+`#0x4e8` vs `#-0x4f0`+`#0x4f0`，extra=8 vs 0）。
  rugra 恒 0 的两层原因：①`TypeSpacebase.scope` 装的是 typefactory 创建期
  的全局 scope 克隆（typefactory.rs:1966-1973），从不查活跃 ScopeLocal——
  ord150 时活跃映射为 `$$undef2[-0x138,-0x30)` 264 字节数组（吞并 oracle
  outline[-0x138,-0x38) 256 与 [-0x38,-0x30) 8 的边界）+`$$undef3[-0x30,-0x28)`
  8B，与 oracle 边界不同（varmap restructure 域）；②Ghidra 的 extra 还有
  TypePointerRel 路径（ctor 6032-6037 以 `getAddressOffset()` 播种
  nonmultsum）——Rugra facing type 实测为 plain `Pointer→Spacebase`
  （`IS_PTRREL=false`），该路径 dormant。两层喂入端均不在本 write-set。
- 本次交付（ruleaction.cc 逐行对照）：`AddTreeState` 补 `ct`/`p_rel` 字段与
  pRelType 全机制——ctor 6032-6037（formal 相对指针：baseType=parent、
  nonmultsum=getAddressOffset()&ptrmask 播种）、`clear` 5980-5983 重播种、
  `init_alternate_form` 5999-6016 完整体（弃相对解释→baseType/size/
  isDegenerate 按 ptrTo 重导+preventDistribution 复位+clear）、
  `span_add_tree` 6236-6241（multsum!=0 ‖ nonmultsum>=size(无符号比) ‖
  multiple 非空 → valid=false）、calc_subtype STRUCT 臂 6314-6320
  （offset==getAddressOffset() 时 `pointer_rel_evaluate_thru_parent(0)`
  失败→valid=false 走 basic 形态）与尾部 6332-6336（offset/correct 各减
  ptrOff）。Rugra 相对指针为 TypePointer 扁平态（`IS_PTRREL`+
  `base.pointer_rel{offset,parent}`），`ptr_rel_state` 即
  `isFormalPointerRel()`+getAddressOffset/getParent 的所有权镜像。
- 行为验证：当前管线 facing type 无 rel 指针 → 全路径 dormant，四个投影
  （myprogress ord150 不变/next_url MATCH/match_url MATCH/parseconfig
  ord186 不变）与 curl/httpd E2E 输出字节级不变；pRelType 路径的行为对齐
  状态为 UNTESTED（喂入端 typeop 传播/`get_type_read_facing` 的
  findResolve（现 identity）补齐前无 oracle 可跑），绑定
  MYPROGRESS-OPPOOL2-CONSTSPLIT-0001 的后继 TODO（varmap 边界+spacebase
  活跃 scope 接线+hasMatchingSubType arrayHint 路径）。

## 2026-09-23：RuleLoadVarnode/RuleStoreVarnode 栈 varnode 创建走 newVarnode/newVarnodeOut 符号尾（file2string ord 76）
file2string.part.0 Phase 2 首分歧（ordinal 76 blockstructure count 1v4）根因链：
① 旧 RuleLoadVarnode 用 `vbank.create_with_space + set_varnode_properties` 自创组合，
而 oracle（ruleaction.cc:4290）用 `data.newVarnode(size, baseoff, offoff)`——其符号尾
`localmap->queryProperties(m, s, Address(), vflags)`（funcdata_varnode.cc:161-166）经
database.cc:1268 stackContainer **先走 ScopeLocal**：符号命中→entry flags，in-scope→
`mapped|addrtied`。② `set_varnode_properties` 镜像（funcdata.rs:4963）只走 Ram/全局
父通道，**栈空间永不进 ScopeLocal 腿**→RuleLoadVarnode 产出的栈 varnode（如
stack:0x…feb8:1）永远缺 addrtied。③ `BlockBasic::isComplex`（block.cc:2419）以
isAddrTied 判定 SUBPIECE 计算是否算语句：oracle 块@3ad5（SUBPIECE+STORE）stmt=3→complex
→`ruleBlockOr` 的 `orblock->isComplex()` 守卫拒绝 OR 折叠；Rugra stmt=2→放行→pass-2
多折叠 3 个条件（negate 4 vs 1）→blockstructure dataflow_changecount 4 vs 1→结构化
路径分叉（skeleton ~130 主因族）。修复：RuleLoadVarnode 改走
`new_varnode_in_space`（=create+assignHigh+laned+完整符号尾，usepoint=invalid，
与 cc:148-169 逐段对应）；RuleStoreVarnode（cc:4331-4332 `newVarnodeOut(size,addr,op)`）
补 assignHigh+laned 步 + ScopeLocal 腿 query_properties_ex（usepoint=op addr，
fold=`getAllFlags() & ~typelock`，varnode.cc:410-424），其 MAPPED 位同时让后续
set_varnode_properties 的 isMapped 门短路（栈路径单查询=oracle）。
双侧探针实证（/dev/shm/rugra-tests/sb-f2string/，oracle RAM 副本 stderr 补丁
NEGPROBE/ORTRACE/ICPROBE3/VNWATCH vs rugra 同款）：修后 feb8:1 varnode 逐 stage
flags 与 oracle 逐字相同（0x1208000=mapped|addrtied|coverdirty），negate census
10/10 逐 site 全等；首分歧 76→**178**（stackstall:oppool1 SNAP 多一条
3aa2:541 SP INT_ADD，登记 SB-F2STRING-ORD178-0001）。

## 2026-09-24：AddTreeState hasMatchingSubType 全量落地 + calc_subtype SPACEBASE/STRUCT 臂接 live map（RULEARITH-SPACEBASE-ARRAYSNAP-0001）

- `AddTreeState::has_matching_sub_type`（ruleaction.cc:6064
  `AddTreeState::hasMatchingSubType`）首次完整移植：arrayHint==0 直查
  getSubType；否则 backward（offBefore∈[0,sizeAddr) 且 elSize 兼容直接
  命中，sizeAddr=byteToAddressInt(size, ct wordsize)）→forward→双 miss 回
  getSubType→单 miss 直取→距离比较（|off|，elSize≠hint 各 +0x1000，tie 取
  backward）。uint8 biggestNonMultCoeff→uint4 形参的 32 位截断保留。
- `AddTreeState::spacebase_map`（RUGRA-GLUE）：Ghidra
  `TypeSpacebase::getMap`（type.cc:2935-2945）每次查询经 Architecture 动态
  解析 queryFunction(localframe)→fd->getScopeLocal()；Rugra 的 spacebase
  类型内无法触达 Funcdata，故由持 `data: &mut Funcdata` 的 AddTreeState 在
  查询点解析（fd 入口==localframe 时取活跃 `fd.scope`，帧不匹配=queryFunction
  miss 回退全局 scope），以 `SpacebaseMap` 传入 datatype.rs 的
  `*_in_map` 查询族——localframe 查询从此不再读构造期全局快照。
- calc_subtype SPACEBASE 臂（ruleaction.cc:6286-6298）：offsetbytes=
  addressToByteInt(offset, ct wordsize)（uint8→int8 重解释 ×ws），extra 回转
  byteToAddress（÷ws，space.hh:523/541 方向：addressToByte 乘、byteToAddress
  除）；STRUCT 臂（6299-6313）同构接 hint 路径，边界检查按字节比较。

## 2026-09-24：biggestNonMultCoeff u32 化 + 三处截断时点镜像（wt/postadsorb，R1）

- 勘误：上文"uint8 biggestNonMultCoeff→uint4 形参的 32 位截断保留"引用的
  字段宽度有误——oracle 字段本就是 `uint4 biggestNonMultCoeff`
  （ruleaction.hh:54），形参也是 `uint4 coeff`（ruleaction.cc:6064），
  调用点（cc:6290/6304）在 oracle 中**不发生任何截断**。
- 字段 `biggest_non_mult_coeff` 由 u64 改为 u32；截断镜像三处：
  ① check_mult_term（cc:6146-6147）`uint4 vncoeff=(sval<0)?(uint4)-sval:
  (uint4)sval` —— 转换发生在**比较之前**，|sval|≥2^32 先回绕（可能为 0）
  再参与竞争；②③ check_mult_term 尾/check_term 尾（cc:6158-6159/6210-6211）
  —— `treeCoeff`（uint8）按 64 位宽与字段（uint4 提升后）比较，**store 时**
  截断到 32 位。`!=0` 消费点（cc:6271）与 hasMatchingSubType 形参读取的
  均为已截断存储值。`has_matching_sub_type` 形参改 u32，删除入口处
  自造的 `as u32` 截断（现由字段宽度天然承载）。
- 可达性：|sval|/treeCoeff ≥ 2^32 需 8 字节常量或 INT_MULT 系数累积；
  当前语料不可达（E2E curl/httpd 双语素逐字节不变），登记为 CR24-R1
  修复、ws=1/小系数域下 corpus-neutral。
- 此前状态：两臂只建模 arrayHint==0 的 getSubType 直查（注释自认
  nearestArrayedComponent* 未建模），ord186 getparameter/ord186 parseconfig/
  ord150 myprogress 三处 oppool2 ptrarith 常量差 8 族（FG 归因
  LANE_FG_TABLEADDR_2026-09-23.md：oracle 对 aliases[].letter 链 -0x4f0
  向前吸附 -0x4e8 数组符号 extra=-8，Rugra 全 miss extra=0）。

## 2026-09-24：AddTreeState 累加器宽度镜像 + SPACEBASE 臂无符号除（RULEARITH-ADDTREE-NUMWIDTH-0001，CR24 R1/R2）

- **R1 累加器截断时点**（CR24 R1）：`biggest_non_mult_coeff` 字段
  u64→u32，镜像 ruleaction.hh:54 的 `uint4 biggestNonMultCoeff`。三站点
  分别镜像 oracle 的混合截断时点：
  - cc:6145（checkMultTerm vncoeff 站点）`uint4 vncoeff = (sval < 0) ?
    (uint4)-sval : (uint4)sval;` ——幅度**先截断到 uint4 再比较**
    （`sval.wrapping_neg() as u32` 后 u32 比较）；
  - cc:6158-6159/6210-6211（checkMultTerm 不常数 fallthrough 与
    checkTerm fallthrough 的 treeCoeff 站点）`if (treeCoeff >
    biggestNonMultCoeff) biggestNonMultCoeff = treeCoeff;` ——uint4 字段
    提升到 uint8 **全宽比较，存储时截断回 uint4**
    （`tree_coeff > field as u64` 后 `tree_coeff as u32`）。
  - cc:6132-6137 的 `val >= size` 门给出结构性保护：size≠0 时
    |sval|≥2³² 到不了累加器，病理输入仅在 size==0（变长基类型）可达；
    行为锁单测用 0x100000003 后跟 5 的终值=5（u64 全宽实现会永驻
    0x100000003）。
  - `has_matching_sub_type` 两调用点 arrayHint 实参补 `as u64`
    （uint4 字段→uint4 形参，低 32 位结构性存活）。
- **R2 SPACEBASE 臂无符号除**（CR24 R2）：calc_subtype SPACEBASE 臂
  extra 回转换用 cc:6294 的 `AddrSpace::byteToAddress(extra, ws)` ——
  **uintb 重载按位模式无符号除**（space.hh:523-525 `return val/ws;`），
  旧实现为 i64 wrapping_div（有符号，byteToAddressInt 语义）。仅
  extra<0 且 ws>1 时分叉（当前全部空间 ws=1，属 latent）；STRUCT 臂
  cc:6311 的 `byteToAddressInt`（有符号）保持不动。行为锁单测：
  ScopeLocal 播种 int[8]@0x2000，offset 0xFF8（ws=2→offsetbytes
  0x1FF0），forward walk 探 +32 命中数组符号，extra=-16 →
  0xFFFFFFFFFFFFFFF0/2=0x7FFFFFFFFFFFFFF8（有符号会得 -8），断言
  offset=0x8000000000001000、correct=0x8000000000000008。
- **验收**（基线=亲父 781046c2 并集树 pristine worktree 亲测）：
  curl E2E 2145/0/0、httpd E2E 2057/0/0，双侧 cmp 字节恒等；gcc 审计
  82OK/25FAIL==亲父；六投影方向（getparameter/myprogress/next_url/
  match_url/parseconfig/main）defects=0 numbering=0 且逐名==亲父；
  cargo test --lib 18 失败==亲父失败集（+3 过=新单测）。两修均为
  latent 输入行为差异，语料内不可达 ⇒ 输出恒等即预期。

- 2026-09-24 (CR25 unlock A+B): calc_subtype SPACEBASE arm extra conversion switched to unsigned divide per ruleaction.cc:6294 (byteToAddress, space.hh:523-525); STRUCT arm keeps signed byteToAddressInt per cc:6311. Three behavior-lock tests added; ten test helpers annotated.

- 2026-09-24: two test helpers (make_copy_written_vnterm, make_varlen_add_tree_state) joined the behavior locks from the sibling branch.

## 2026-09-24：AddTreeState calc_subtype 头部比较改无符号（RULE-SPINDEX-UNSIGN-0001，GK lane）

- 根因（httpd main SP 下标族差分定位）：`calc_subtype` 开头
  `tmpoff < size` 的比较，Ghidra（ruleaction.cc:6256）是
  `uint8 tmpoff < int4 size` —— C++ 常规算术转换把两侧提升为 uint8，
  **无符号比较**；Rugra 此前写成 `(tmpoff as i64) < size` 有符号比较。
  对向下生长栈的 SP-alias 加法（multsum=0xfff..f8 即 -8 字节），
  oracle 走模除路径（offset=0、multsum 保留 -8 → PTRADD 生成），
  Rugra 走 `offset = tmpoff` 分支把 multsum 清零，随后
  `nonmult 空 && multsum==0 && multiple 空` 判 `valid=false` ——
  整个 INT_ADD→PTRADD 改写对负偏移 SP-alias 全灭（httpd main
  `*(undefined8 *)((int *)puVar10 - 8) = X` 印 101 行）。
- 修复一行：`tmpoff < self.size as u64`（size 恒 ≥0，正数域行为不变；
  仅高位为 1 的 tmpoff 即负字节和改走 oracle 同款模除路径）。
- 验证：httpd E2E 1698→**1628**（main 715→645，SP-cast 形 101→40、
  下标形 33→94 向 canon 136/152 收敛）；curl 1744→1745（main 413→414
  唯一 +1 = `for (var_8; …; var_8 = var_8 + 18446744073709551615)` 破损
  单行变 oracle 同构 while 两行，质量向 golden 靠拢）；双门禁
  defects/numbering 0/0；逐函数零回退；gcc 审计两口径与亲父基线
  逐函数相同（curl 104/20、httpd 21/8，GI2 §6 的 23/6 为 b5b949dd 期
  旧数）；五投影 MATCH ×5 保持；
  `tools/run_ptrarith_addtree_oracle.sh` 5 用例在修复后 crate 上
  双侧重跑 MATCH（本机 g++ 11.4 vs pin 16.2.1 的 host-compiler 钉板
  漂移为亲父已存在环境缺口，scratch 重跑仅豁免身份钉、输出口径钉
  全保持）。
- 残余（登记 TODO）：varmap 侧 SP-alias 符号类型固定点（auStack_c8
  `undefined1[32]` vs oracle `long local_c8[4]`）+ 后续 restructure 轮
  alias 链经 phi/INDIRECT 重路由后 -0xd0/-0xd8 open hint 消失
  （oracle 有 local_d0/local_d8）+ main 残余 40 行 SP-cast 中 1 处
  phi（INDIRECT 输入 long 整型化）未获指针型 —— 见 TODO_BOARD
  VARMAP-SPALIAS-RETYPE-0001 / RULEACTION-SPALIAS-INDIRECTPTR-0002。

## 2026-09-24：RulePushMulti 替代 MULTIEQUAL 输出保留共享存储地址（PM-GLOBWORD lane）

res==1 新建替代 MULTIEQUAL 的分支（ruleaction.cc:1116-1131）此前无条件
`new_unique_out`，且把新 op 与统一 op 都插在被销毁 MULTIEQUAL 之前。
oracle 语义逐行镜像补齐：

- 输出地址保留（cc:1121-1124）：`buf1[0]->getAddr() == buf2[0]->getAddr()`
  且 `!buf1[0]->isAddrTied()` 时走 `newVarnodeOut(size, buf1[0]->getAddr(),
  substitute)`（Rugra `new_varnode_out_full`，含 assignHigh/laned/符号尾
  全序列）；否则保持 `newUniqueOut`。glob_word 首分歧（stage 28 oppool1
  op 35）即此：两输入同 SLEIGH 临时槽 u:23b00 时 oracle 输出沿用原地址，
  旧实现造出 u:100002c5。
- 插入位置（cc:1127/1130/1133）：替代 MULTIEQUAL 走 `opInsertBegin(sub,
  bl)`（MULTIEQUAL 感知的前导组跳过），统一 op1 走 `opInsertAfter(op1,
  substitute)`；res==0 走 `opInsertBegin(op1, bl)`。无块隶属的扁平单测
  fixture 保留旧相对插入兜底（RUGRA-GLUE，仅测试可达）。
- 删除非正典的 "substitute 无输出" 兜底——oracle 的 substitute（已有
  MULTIEQUAL 或 CSE op）恒带输出；缺失按契约外处理（NO_CHANGE）。
- `slot1` 仍在创建前由 `op_get_slot(op1, buf1)` 求值（cc:1114）。

验证：glob_word 双投影 MATCH（u:23b00 族 4 个替代 MULTIEQUAL 与 oracle
逐字节一致）；五银行投影 MATCH 保持；curl/httpd 门禁见 lane 终报。

## 2026-09-25：ruleaction 四位点构造源空间限定（RUFOUR lane，FAMILY-AUDIT-SPACELESS-SITES-0001 第四波）

FAMAUDIT 第三波登记的 ruleaction×4 位点（ruleaction.cc:2035/1011/6770/9151）逐处
对照 12.0.4 oracle 判决并修复。同族先例（XCORSS/OPZERO/SPACEFIX/FAMAUDIT）同构修法：
`new_varnode_out`（Register 钉死）→ `new_varnode_out_full`（构造源 varnode 自身空间），
但每处独立核对 size/space 取值语义：

1. **RuleLeftRight::apply_op**（ruleaction.cc:2029-2035）：新 SUBPIECE 输出地址
   `addr = shiftin->getAddr()` —— shiftin **自身完整存储地址**（cc:2029 在 unset 前
   捕获；BE 时 cc:2031 `+isa`；cc:2034 `renormalize(tsz)` 仅 join 空间生效，
   address.cc:191-194，Rugra 无 JoinRecord 存储=degraded glue）。旧代码钉死
   Register@0x1000（空间与偏移双错）。→ `new_varnode_out_full(tsz, shiftin_space,
   newaddr)`。
2. **RulePullsubIndirect::apply_op**（ruleaction.cc:993-996/1011）：`smalladdr2 =
   vn->getAddr()+minByte`（LE）—— **INDIRECT 输出 vn 自身空间**；与 creation 分支
   （`new_indirect_creation_in_space` 已传 vn_space）同源。→ `new_varnode_out_full(
   new_size, vn_space, smalladdr2)`。
3. **RulePushPtr::build_varnode_out**（ruleaction.cc:6765-6771）：守卫
   `vn->getSpace()->getType() == IPTR_INTERNAL` = **Unique** 空间（旧代码误测
   `AddressSpace::Iop` = IPTR_IOP，2e63227a 移植笔误；ZEXT/SEXT/2COMP/MULT 的
   duplicated 输出几乎全在 unique 空间，误走 new_varnode_out 会造 Register@unique
   偏移伪 varnode）；构造臂 `newVarnodeOut(vn->getSize(), vn->getAddr(), op)` =
   vn 自身空间。→ 守卫 `space.is_unique()` + `new_varnode_out_full(size, space,
   addr)`。
4. **RulePtrFlow::truncate_pointer**（ruleaction.cc:9146-9152）：截断指针输出
   `addr = vn->getAddr()` = vn 自身空间；**cc:9148 `addr.isBigEndian()` 读的是
   addr 携带空间（=vn 空间）的端序**，旧代码误读指针目标空间 `spc`（源错误；
   Rugra AddressSpace 端序谓词当前为 LE 枚举 stub，x86-64 oracle 全 LE=行为
   等价）；`renormalize(addrSize)` 同 join-only。→ `new_varnode_out_full(
   addr_size, vn_space, addr_val)` + BE 源改 `vn_space`。

注解漂移顺带纠正（触碰函数内）：RuleLeftRight::applyOp cc:2030→**2010**（定义
起始行）、RulePushPtr::buildVarnodeOut cc:6783→**6765**、RulePtrFlow::
truncatePointer cc:9154→**9136**。邻接登记（本 lane 不动）：duplicate_need 注解
`ruleaction.cc:7469` 事实错误（真定义 6809，P4 LINEREF，wave-4 编辑域外）；
coreaction 三位点（cc:699/1551/1451）为 CSPEC2 并行车道登记项。

验证（亲父 aa4fa7d4 A/B，release 亲测）：curl 探针触发 26 次
（18×Unique 走守卫翻正的新 fresh-unique 分支 + 8×Register 构造臂=旧钉同值），
httpd 0 次；位点 1/2/4 双语料休眠。双语料默认态输出与亲父 cmp **字节恒等**
（=触发位点等价性实证，非休眠）+ 双跑确定性；curl/httpd canon golden 双零；
三门禁+bank 391/391+cargo test --lib 亲父谱系同败——见 lane 终报
（/dev/shm/rugra-reports/LANE_RUFOUR_2026-09-25.md）。

## 2026-09-25：`buildSubpiece` join 臂 usetmp 结构镜像（Lane PJOINS，SPACEFIX-CR-F6 收口）

`RulePullsubMulti::build_subpiece`（ruleaction.cc:776-839）join 臂重构为
oracle 的 `usetmp` 决策形态（cc:791-830）：join 基底进入即 `usetmp=true`，
`numPieces()>1` 时倒序扫描 piece 表，仅当请求范围完整落于单片才取该片
端序地址并 `usetmp=false`；**join 空间 offset 本身不再走
`base_addr.offset(shift)` 的普通偏移算术**（旧 None 回退虽经 `else if
is_join` 臂最终落到 unique、hash 偏移计算为死值，但结构性违背 cc:793-815
——F6 登记项）。`findJoin` miss（translate.cc:746-762 LowlevelError）按
HERITAGE-PJOINS-UNLINKED-0001 降级：响亮 log + 保持 unique 输出（=oracle
无覆盖片行为 cc:825-826）。非 join 基底 `plain_addr` 计算保持 cc:816-821
端序分支不变。行为验收：httpd/curl 与亲父 cmp 字节恒等（join 臂两语料
零触发——Rugra 生产者仅 httpd ap_init_vhost_config 铸 join 且不流经
MULTIEQUAL→SUBPIECE）。

## 2026-09-25：AddTreeState::ptr_rel_state 正式形闸门（UNIONRES-RELPTR-SCOREPARITY-0001 配套，wt/unionf2）

`AddTreeState` 构造器（ruleaction.cc:6033）对相对指针的 parent/offset 记账
以 `ct->isFormalPointerRel()`（type.hh:228：
`(is_ptrrel|has_stripped)==is_ptrrel`）为闸门 —— **临时** rel 形
（`markEphemeral` type.cc:4020 置 `has_stripped`）被排除，其 parent/offset
簿记归类型传播层所有；Rugra 的 `ptr_rel_state` 只查 `IS_PTRREL` 位，把临时
形也计入 `baseType=parent`/`nonmultsum=offset` 记账。

该缺口此前不可见：`canonicalize_temp_type` 把 temp 里的临时 rel 剥成 plain，
AddTree 从未见过 rel 形。上游保形修复（见 docs/api/coreaction.md 同日条目）
落地后它立即显形为 RulePtrArith/AddTree 的**无限重写环** —— match_url 单函数
>180s 不收敛（AddTree 对自己产出的 PTRSUB 后继反复重写，`op_insert_before`
Vec 搬移为热点，投影卡 401+ stage 不终）。修复：`ptr_rel_state` 头部加正式形判定
（`IS_PTRREL|HAS_STRIPPED` 组合等于 `IS_PTRREL` 才入记账），临时形落默认
plain 臂。修复后 match_url 1.1s 收敛，投影终态 340 stage/172 ops ==
oracle 投影终态（tests/fixtures/projections/curl_match_url 同数）。

## 2026-09-26：AddTree/RS0/PtrsubUndo/PtraddUndo 联合体读面咨询（UNIONRES-FIELDOFF-PTRSUBNORM-0001，Lane FIELDOFF）

union_map 逐边解析落地后的消费者接线（oracle 的 `getTypeReadFacing(op)` =
`findResolve(op,slot)` 只读咨询,Rugra 镜像为 unionresolve.rs 自由函数）:

- **AddTreeState 构造器 ct**（ruleaction.cc:6037 `ct = ptr->getTypeReadFacing(op)`）:
  此前零参退化形。map 命中时 ct = 解析出的字段指针（如 `URLGlob.content` →
  `.Set` struct16 指针）,baseType 走 STRUCT 臂 → 产出 canon 形
  PTRSUB(#field-off)。
- **assignPropagatedType inType**（ruleaction.cc:6346）:同上,isTypeRecoveryExceeded
  态下的超界 stamping 也用解析形。
- **buildTree 两处 inheritResolution**（ruleaction.cc:6500-6501/6512-6513）:
  新建 PTRADD/PTRSUB 后把 baseOp 边的解析记录复制到新 op 的 slot 0 —— 此前
  注释"Rugra 无逐边 union resolution"已过时。RS0 的 PTRSUB(#0) 重写同样补上
  （ruleaction.cc:6751-6752）。
- **RulePtrsubUndo applyOp**（ruleaction.cc:7138 `basevn->getTypeReadFacing(op)
  ->isPtrsubMatching(val,extra,multiplier)`）:此前读裸 `get_type()` —— 这是
  AddTree↔PtrsubUndo 无限重写环的第二半:AddTree 用解析形建 PTRSUB,PtrsubUndo
  用 whole union 指针判 isPtrsubMatching(union)=false（type.cc:1167-1171 对
  union 恒 false）→ 降级回 INT_ADD → 循环（探针:同址 build_tree 3720-11691 次,
  PTRSUB→INT_ADD 67915 次,glob_set/glob_range/next_url/match_url 4 函数 >8s
  超时）。咨询后解析形 `Set*`（struct pointee）走 Struct 臂 offset 匹配 → 不降级。
- **RulePtraddUndo applyOp**（ruleaction.cc:6915/6918）:同型修复 +
  alignSize 比较改 oracle 精确形
  `addressToByteInt(size, wordsize)`（wordsize>1 时不再失配）。
- **RuleStructOffset0 ct**（ruleaction.cc:6691）:LOAD/STORE 的 in(1) 读面咨询。

前后（亲父 master 93195bca → 本车道,默认态）:curl 369→309（glob_set 16→3 /
glob_range 19→1 / next_url 22→7 / match_url 19→5,字段偏移族全收敛,残差归
字符串常量族+换行）;httpd 872 字节恒等;0 not-settling/0 超时。

## 2026-09-26：AddTreeState 相对指针偏移单位换算（RULEACTION-ADDRUNIT-0001）

`AddTreeState::ptr_rel_state`（`isFormalPointerRel()` 闸门 + `TypePointerRel`
访问器的所有权镜像）此前把存储的**字节**偏移（`base.pointer_rel.offset` =
`TypePointerRel::offset`，type.hh:652；`getByteOffset` type.hh:675）直接当
`getAddressOffset()` 的返回值消费。oracle 的 `getAddressOffset()`
（type.hh:670）是 `AddrSpace::byteToAddressInt(offset, wordsize)`
（space.hh:541 `val/ws`）——**地址单位**；ruleaction.cc 四个消费位点全取
地址单位：

- ctor 6035-6036：`nonmultsum = pRelType->getAddressOffset(); nonmultsum &= ptrmask;`
- `clear` 5981-5982：同款重播种；
- `calcSubtype` STRUCT 臂 6314：`offset == pRelType->getAddressOffset()`；
- `calcSubtype` 尾部 6333-6335：`offset`/`correct` 各减 `getAddressOffset()`。

修复：`ptr_rel_state` 返回五元组 `(addr_off, byte_off, parent, ptr_to,
wordsize)`——`addr_off = byte_to_address_int(rel.offset, wordsize)`
（getAddressOffset 镜像），`byte_off` 透传原始字节偏移（getByteOffset 镜像），
供 STRUCT 臂 `pointer_rel_evaluate_thru_parent` 的 `offset` 形参使用
（type.cc:2593 `byteOff + offset` 在字节域折叠——该形参此前恰好拿的就是
字节值，本次修复保持）。四个消费位点相应改读 `addr_off`；wordsize 沿用
`.max(1)` 钳制（FIELDOFF-CR-F6 已记录的形式性偏差：oracle 裸
`getWordSize()`，ws=0 在 C++ 是 UB、在 Rust 是除零 panic）。

**可观测性**：wordsize==1 时 `byte_to_address_int(x,1)==x`，两单位恒等
——x86 双语料（curl/httpd，1 字节寻址）构造性不可观测，A/B 亲测字节恒等；
wordsize>1 架构 formal rel 的 nonmultsum 此前偏大 wordsize 倍，现按
oracle 地址单位播种。单测 `test_add_tree_ptr_rel_state_address_unit_offset`
钉死：wordsize 2、字节偏移 8 → addr_off 4 / byte_off 8；ctor nonmultsum
播种 4（地址单位）、size=byteToAddressInt(32,2)=16、baseType=parent、
isDegenerate=false；clear 重播种 4；wordsize 1 恒等臂；HAS_STRIPPED
（ephemeral）闸门排除臂。

同车道一并收口（各见独立 commit）：RULEACTION-RS0-RELGATE-0001（RS0 缺口
注释补 TODO ID + 修过时陈述）、RULEACTION-ANNO-DRIFT-0001（`// Ghidra:`
起始行批量纠偏 221 处，零行为变化）。

## 2026-09-26：RuleStructOffset0 缺口注释补登记（RULEACTION-RS0-RELGATE-0001 注释卫生半项）

`RuleStructOffset0` 两处缺口陈述过时（"Rugra has no TypePointerRel"——rel 基础
设施已由 FIELDOFF/ADDRUNIT 车道落地：`AddTreeState::ptr_rel_state`、
`pointer_rel_evaluate_thru_parent` 均在库内）且无 TODO ID。本次改为准确陈述：
oracle ruleaction.cc:6695-6725 的 formal 相对指针臂（isFormalPointerRel &&
evaluateThruParent(0) → parent PTRSUB walk：getByteOffset + getSubType +
byteToAddress(newoff, wordsize) + PTRSUB(#-newoff) + INT_ADD 回补 +
inheritResolution + setStopTypePropagation）**仍缺**，引用 TODO
RULEACTION-RS0-RELGATE-0001（臂实现残项继续跟踪，owner 待认领）；plain
STRUCT/ARRAY 路径（6726-6755）保持忠实。连带区域行号勘误：
6678-6774→6660-6756、6693-6774→6675-6756、6713-6743→6695-6725、
6744-6767→6726-6755。零行为变化（注释-only）。

## 2026-09-26：`// Ghidra:` 起始行批量纠偏（RULEACTION-ANNO-DRIFT-0001）

票面三处（6927→6909 / 7146→7128 / 6036→6018）经全文件扫描为两族系统性漂移
（+18 族与 +20 族，旧 oracle 版本行差）的样本，另有 5 处错域引用
（RulePullsubMulti minMaxUse/acceptableSize/replaceDescendants 引到调用点
977/981/1017、RulePushPtr::duplicateNeed 引到 RuleExtensionPush 区 7469、
RulePtrArith::evaluatePointerExpression 引到 6876）与 RuleDoubleShift +1
两处。修法：对每个 `// Ghidra: ruleaction.cc:N FN` 解析 FN 在锁定 oracle
e40ed130 的真实定义行替换 N（类名无 `::` 的代表性行引用不动），共 **221
处**；修后复核脚本验证 584 个函数引用 0 漂移，`check_ghidra_refs --all
--strict` 绿。注释-only：零行为变化。

## 2026-09-26：ANNO 残留修正 + 验证声明勘误（RULEACTION-ANNO-DRIFT-RESIDUAL-0001）

CR-ADDRUNIT 终判指出上一节的完整性声明不实：纠偏脚本的 oracle 定义行解析器
只匹配标量返回类型（`Varnode \*\s+` 要求星号后空白，而 oracle 实际风格是
`Varnode *Foo::bar(` 星号紧贴函数名），**13 处指针返回型方法注释漏网**，另
**2 处错域**（RuleIgnoreNan::testForComparison 引 9722=applyOp 定义行、
RulePullsubMulti::findSubpiece 引 1005=调用点）；"584 个函数引用 0 漂移"
实为 584 = 339 函数级 + 245 类名级行次的总和，函数级验证本身带同一解析器
缺口——声明作废。本 commit 修正 15 处（reviewer 亲验真值表，本车道逐行
复核 oracle 定义起始行后替换）：

getHiBit 5659→5641 / getBooleanResult 10335→10317 / detectThreeWay
10035→10017 / checkSignExtraction 8776→8758 / findForm 8069→8051 /
checkSignExtForm 8928→8910 / findSubshift 7928→7910 / determineDatatype
7481→7463 / checkBoolean 9277→9259 / constructBool 9346→9328 /
testForComparison 9696→9678 与 9722→9678 / buildMultiples 6374→6356 /
buildExtra 6408→6390 / findSubpiece 1005→849。

解析器缺口登记 TOOLS-REFS-DEFSTART-0001（定义行正则须接受
`Type \*Class::fn(` 星号贴名形 + 裸构造函数形，且防贪婪回溯误配）；类名级
（无 `::`）代表性行引用豁免维持 RULEACTION-ANNO-CLASSNAME-0001（reviewer
计 174；本车道复计口径 245 行次/127 唯一 (行,名) 对，计数口径差登记于该
票）。修正后复验（解析器已修）：函数级 339 处 0 漂移，唯一未解析=
AddrSpace::byteToAddress（跨文件 space.hh 定义、引 ruleaction.cc:6294 调用
点，既有风格，checker 有效）；`check_ghidra_refs --all --strict` 绿。
注释-only 15 行，函数体零改动。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-27 — WORKPKG-UNMAP-RULEADJ-0013 实移植半：RuleBooleanDedup::isMatch + RuleSignMod2nOpt2::checkMultiequalForm

- **`RuleBooleanDedup::is_match`**（`ruleaction.cc:2817-2831` 1:1 移植）：
  私有 helper，包装 `BooleanMatch::evaluate`（expression.cc:111-216，Rust 侧
  `crate::expression::boolean_match_evaluate`，depth=1），返回
  `Some(false)`=same / `Some(true)`=complementary / `None`=uncorrelated。
- **`RuleBooleanDedup::apply_op` 匹配块重写为 oracle 形态**（cc:2856-2922）：
  ①四对配对 `(0,2)(0,3)(1,2)(1,3)` 依序经 isMatch（含互补匹配——修复旧版
  仅 Arc::ptr_eq 直接匹配且 **rightO 槽位索引错误**（`4-bi` 对 bi∈{2,3} 恒错，
  应为 `5-bi`）两个缺陷）；②isflipped 臂新增三形态：
  `(A&&B)&&(!A&&C)`→`COPY(#0)`（opSetOpcode COPY→opRemoveInput(1)→
  opSetInput(newConstant(1,0),0) 顺序逐字）、`(A||B)||(!A||C)`→`COPY(#1)`、
  `(A||B)||(!A&&C)`→`finalA=(opc0==OR)?leftA:rightA` + OR/OR；③非 flipped
  双形态保持（central==both→(central,central)；opc0==opc1≠central→
  (opc0,central)）；④finalA 区分（旧版恒 leftA，仅非 flip 等价）。
- **`RuleSignMod2nOpt2::check_multiequal_form`**（`ruleaction.cc:8941-8985`
  45 行 1:1 移植）：MULTIEQUAL 路径 `V = (V s< 0) ? V + 2^n-1 : V` 识别——
  ①`npow -= 1` 后槽位扫描：输入为 `INT_ADD(base, 2^n-1)` 且对侧输入==base
  （C++ `for` + break + 事后 `slot > 1` 全扫描拒绝，Rust 以 `found_slot:
  Option<usize>` 等价表达，continue 增量语义由 for-range 保证）；②块结构：
  `op.parent`（merge 块）首条 in 边 sizeIn==1&&sizeOut==1 者为 inner 块
  （否则试 slot 1，再失败拒绝）；③diamond join：inner 唯一 in 边与 merge
  另一条 in 边必须同为 decision 块（Arc::ptr_eq）；④decision 尾 op 必须
  CBRANCH，布尔输入 written 且 def 为 `INT_SLESS(x, #0)`；⑤负分支槽位：
  `isBooleanFlip() ? getFalseOut() : getTrueOut()`（block.hh:299-300 位置
  约定 out[0]=false/out[1]=true，Rust trait 同构）指向 inner 时 negSlot=
  innerSlot 否则 1-innerSlot，须等于 INT_ADD 槽位。返回 base。
- **`RuleSignMod2nOpt2::apply_op`** 补 cc:8892-8893 MULTIEQUAL 分支接线
  （`adj_opc == CPUI_MULTIEQUAL` → `check_multiequal_form(adj_op, npow)`），
  SREM 重写尾（INT_ADD 后代搜索 + `slot==0 时先 opSetInput(base,0)` +
  `newConstant(size, npow)` 至槽 1 + INT_SREM）不变。
- **`RuleSubCommute::cancel_extensions`**（cc:4483-4512）：SUBCOMMUTE 车道已
  移植（ruleaction.rs `fn cancel_extensions`），本票核验通过——loneDescend
  守卫/等尺寸双侧 isFree/短侧 shortenExtension+长形 loneDescend 守卫/
  opUnsetOutput→newUniqueOut(maxSize)→三 opSetInput 全对齐，无重写。本票
  B2 fixture 补双侧行为证据（见 tests/oracle/rule_subcommute_cancelext_1204*）。
- 单元测试基线保持 1829P/0F。

### 2026-09-27（续）— WORKPKG-UNMAP-RULEADJ-0013 B2 双侧 fixture 半 + npow 前缀缺陷 + ZEXT 臂补接线

- **`RuleSignMod2nOpt2::apply_op` npow 计算前缀缺陷修复**（cc:8883）：
  oracle `uintb npow = (~constVn->getOffset() + 1) & mask` 是二补数取负
  （先按位取反再 +1）；Rust 旧代码 `!x.wrapping_add(1)` 因方法调用结合律
  实为 `!(x+1)`，对 AND 常量 0xfc 错算出 2 而非 4——该缺陷使
  RuleSignMod2nOpt2 两条路径（checkSignExtForm/checkMultiequalForm）在
  Rust 侧对所有输入静默失效。B2 multiequal fixture 首跑即暴露
  （oracle apply=1 vs Rust apply=0），修正为
  `((!x).wrapping_add(1)) & mask` 后 12/12 字节恒等。
- **`RuleSubCommute::apply_op` DIV/REM（ZEXT 无符号）臂 oracle 结构重写**
  （cc:4542-4568，闭单 `RULEACTION-SUBCOMMUTE-ZEXT-PARTIAL-0001`）：
  ①先查 in(1)——written ZEXT 且任一 zext 输入 > outvn 时走
  `cancel_extensions` 部分抵销（返回 CHANGE 保留 SUBPIECE，绝不到达
  cc:4621/4623 通用路径检查）；②written 非 ZEXT 在任何尺寸问题前拒绝；
  ③常量 in(1) 要求 `zext0In <= outvn` 且值适配 outvn 掩码；④旧 Rust 在
  zext0In>outvn 时无条件 NO_CHANGE（部分抵销形态从不触发）。
- **B2 三族 fixture**（GEN5 archive 形态，tests/oracle/ + tools/run_*）：
  - `rule_signmod2nopt2_multiequal_1204`（12 例）：diamond CFG 全语义
    （M.in 边序 [N,D]/[D,N] 决定 innerSlot；D.out 边序 × boolean_flip 决定
    negSlot；正例 slot0/slot1 × noflip/flip；oracle 宽松性例——cc:8975-8982
    从不校验 lessOp in(0)==base；拒绝例 8 种含 3 输入 MULTIEQUAL）。
  - `rule_booleandedup_ismatch_1204`（12 例）：同值/分布/互补折叠/
    混合 flip 双向/De Morgan 配对/pair-(0,3) 与 pair-(1,2) 槽位选择
    （旧 `4-bi` 缺陷见证例）/双拒绝。
  - `rule_subcommute_cancelext_1204`（9 例）：等尺寸/不等尺寸双侧
    shortenExtension/DIV+SDIV+SREM 各臂/helper 三拒绝（cc:4488 输出第二
    读者、cc:4489-4493 等臂自由输入、cc:4499 缩短侧 loneDescend）/
    全 commute 对照例。
  三族均与锁定 oracle（e40ed130 现场直跑归档）**字节恒等**；判别力亲证=
  multiequal 首跑暴露 npow 前缀缺陷。
- fixture_registry.json 追加 3 条（227→230）；cargo test --lib 1829P/0F；
  canon curl 157/0/0、httpd 311/0/0 不回退。

## 2026-09-27：RS0 formal 相对指针臂落地 + ConditionalMove 跨臂克隆接线（Lane RULEADJ2，RULEACTION-RS0-RELGATE-0001 臂实现残项 + RULEACTION-CLONEBLOCKOPS-0001）

**① RuleStructOffset0 formal rel 臂**（ruleaction.cc:6695-6725，src/ruleaction.rs
`RuleStructOffset0::apply_op`）：`isFormalPointerRel() && evaluateThruParent(0)`
门（复用 `AddTreeState::ptr_rel_state` 的 formal=IS_PTRREL 无 HAS_STRIPPED 判定
+ `pointer_rel_evaluate_thru_parent(ptrto, parent, ws, byteOff, ctSize, 0)`）→
baseType 重赋值为 rel parent（cc:6696-6697，臂内拒绝直接 return 0 不落
plain 路径）→ STRUCT 门 → `getByteOffset() >= parent size` 拒 → parent <
movesize 拒 → `getSubType(offset,&newoff)` null/小于 movesize 拒 →
`newoff = AddrSpace::byteToAddress(newoff, wordsize)`（space.hh:523 无符号除，
**byte→address 单位换算**）→ `PTRSUB(ptr, #(-newoff & calc_mask(ptrSize)))`
（newOpBefore 形：newOp(numInput=2, follow addr) + 尺寸取自 in1=ptr）→
`inheritResolution`（needsResolution 门）→ `setStopTypePropagation` →
newoff≠0 时 `INT_ADD(ptrsubOut, #newoff)` 回补且 LOAD/STORE in(1) 指向
INT_ADD 输出（cc:6716-6720），否则直连 PTRSUB 输出（cc:6721-6722）。

**B2 双侧 fixture**（GEN5 archive 形态，registry 230→232）：
- `rule_structoffset0_relptr_1204`（7 例）：field-start 直连重接（newoff=0）/
  interior INT_ADD 回补（#-2 & mask + #2）/ ws=2 换算（#-1 & mask + #1）/
  STORE 形（movesize 取 in(2)）/ evaluateThruParent 门拒（ptrto=struct →
  plain 路径对照）/ subtype 过小拒 / offset 折叠出 parent 拒。
两族均与锁定 oracle（e40ed130 现场直跑归档）**字节恒等**，双跑确定性亲证。

残差如实登记：cloneExpression 的 MULTIEQUAL→COPY 边改写与 INDIRECT/CALL
throw 臂对本消费者不可达（gatherExpression 不收集）；annotation 输入
newCodeRef 复制在 Rust 克隆器为共享 varnode（nodeSplit 域既有决定，布尔
表达式输入不可达）——均记入 metadata coverage UNTESTED 臂，不冒充覆盖。

**② RuleConditionalMove::compareOp + cloneExpression 接线**
（ruleaction.hh:1433 / ruleaction.cc:9328-9341 / funcdata_block.cc:1024-1040）：
`compare_op` 1:1 移植（`SeqNum::get_order` 严格弱序，仅块内执行序而非创建
time）；`construct_bool` 从"ops 非空返回 None"改写为 oracle 形态——原位
sort（`&mut [..]`，镜像 C++ 非 const vector&）→ `CloneBlockOps::cloneExpression`
（**该克隆器已由 nodeSplit 车道落在 src/funcdata.rs:18906（私有）**，票面
"未移植"陈述被推翻；经 6 行 pub 桥 `Funcdata::clone_block_expression`
暴露——Ghidra 侧 funcdata.hh:630 类本就是 public，ruleaction.cc:9334 直接
实例化，pub 桥是 Rust 模块边界的同面镜像）→ 返回末位克隆输出；
`LowlevelError("No expression to clone")` 以 `Err` 经 `?` 上抛 = oracle throw
路径。六处调用点同步 `&mut` + `?`。B2 fixture
`rule_condmove_cloneexpr_1204`（5 例：root==inblock0 克隆臂/BOOL_NEGATE
翻转臂/root==inblock1 镜像臂/分支前形成无克隆对照/无 CBRANCH 拒）与锁定
oracle 字节恒等，双跑确定性亲证；registry 231→232。

残差如实登记：cloneExpression 的 MULTIEQUAL→COPY 边改写与 INDIRECT/CALL
throw 臂对本消费者不可达（gatherExpression 不收集）；annotation 输入
newCodeRef 复制在 Rust 克隆器为共享 varnode（nodeSplit 域既有决定，布尔
表达式输入不可达）——均记入 metadata coverage UNTESTED 臂，不冒充覆盖。

## join 基建接线（SQLCENSUS-STACKSLOT-GROUP-0001 第一波，2026-09-28）

- 本文件对应源码的改动均为 join 空间基建（translate.cc:817
  constructJoinAddress / :671 findAddJoin 的 1:1 移植，详见 docs/api/arch.md
  与 docs/api/space.md 条目）的接线/适配面：CALL 侧 join 闭包 whole 落
  Join 空间注册地址；RETURN 侧 return_join_address 委托 Architecture；
  double_precis create_joined_whole 消费空间限定结果；process_joins /
  build_subpiece 经 RwLock 读 join_db。无独立新语义。
