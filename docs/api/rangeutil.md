# `rangeutil.rs` API Reference

**源代码路径**: `src/rangeutil.rs`
**Ghidra 对应**: `rangeutil.hh` / `rangeutil.cc` (3015行)
**状态**: 🔧 **L2**——CircleRange 全方法 + ValueSetSolver 填充/迭代主链路实跑
（RANGEUTIL-VSEMPTY-0001 修复，2026-09-23）+ 约束生成族全量
（RANGEUTIL-CONSTGEN-0001，2026-09-23：applyConstraints/constraintsFromPath/
constraintsFromCBranch/generateConstraints/generateRelativeConstraint/
CircleRange::pullBack(PcodeOp*)）（差分门禁口径：改动经
curl/httpd E2E + gp/next_url/match_url/parseconfig 投影验证）。54 单元测试
（2026-09-23 CR8 返工 +2：operator== 双空语义 / circle_union wrapping 合并；
RANGEUTIL-CONSTGEN-0001 +3）。

## 模块说明

整数值范围分析工具。对应 Ghidra 的 `rangeutil.hh`。
`CircleRange` 表示模 2^n 上的半开区间 [left, right)，带可选步长。

## 导出的公共 API

### `pub struct CircleRange`
模运算整数范围。对应 Ghidra `CircleRange`（rangeutil.hh:50）。
- `empty()` / `full(size)` / `single(val, size)` / `new(left, right, size, step)` / `boolean(val)` — 构造方法
- `is_empty()` / `is_full()` / `is_single()` — 状态查询
- `contains_val(val)` — 包含检查
- `intersect(op2)` / `union(op2)` — 集合操作
- `next(val)` — 范围内迭代（`val.wrapping_add(step) & mask`，2026-08-24 对齐
  C++ uintb 回绕；getNext 仅内联定义于 rangeutil.hh:82，2026-08-25 R12 建议 A
  修正 src 注释引用行 cc:179→hh:82）
- `get_size()` — 范围大小（2026-08-24 逐字移植 rangeutil.cc:263-273 含 overflow
  "lie by one" 分支：`val=(mask-(left-right)+step)/step`，结果为 0 时返回
  `mask`（step>1 再 `mask/step+1`）；8 字节满幅 domain 依赖 uintb 回绕，
  jumptable 的 size>maxtablesize 拒绝路径依赖该值）

测试：rangeutil::tests 6 个。

## 2026-06-26（续）：rangeutil.rs CircleRange 完善

新增 CircleRange 方法（对应 rangeutil.cc 完整 API）：
- `invert()` — 转互补范围（rangeutil.hh:89）
- `set_full(size)` — 设置全范围
- `push_forward_unary(opc, in1, in_size, out_size)` — 通过一元操作前推（rangeutil.hh:94）
- `push_forward_binary(opc, in1, in2, in_size, out_size, max_step)` — 通过二元操作前推（rangeutil.hh:95）
- `translate_to_op()` — 范围→比较操作转换（rangeutil.hh:99）

测试：新增 4 个（invert/push_forward_add/push_forward_copy/translate_to_op）。

## 2026-06-27：CircleRange 守卫扩展（pullBack）基础设施

新增 `CircleRange::pullBack` 所需全套方法，解锁 JumpBasic::analyzeGuards 的守卫范围扩展：

**CircleRange 方法**：
- `complement()`（rangeutil.cc:38）：取补集（仅 step==1）。
- `convert_to_boolean() -> bool`（rangeutil.cc:63）：转为布尔范围 [0,2)/[0,1)/[1,2)/空，返回是否含 0 和 1。
- `set_nz_mask(nzmask, size) -> Option<CircleRange>`（rangeutil.cc:672）：从 NZ 掩码构建范围，bit_transitions>2 返回 None。
- `pull_back_unary(opc, in_size, out_size) -> bool`（rangeutil.cc:728）：通过一元操作（COPY/INT_NEG/INT_NOT/INT_ZEXT/INT_SEXT/BOOL_NOT）反向。
- `pull_back_binary(opc, val, slot, in_size, out_size) -> bool`（rangeutil.cc:807）：通过二元操作（INT_EQUAL/NOTEQUAL/LESS/LESSEQUAL/ADD/SUB/RIGHT）反向。

**自由函数**：
- `bit_transitions(val, size) -> i32`（address.cc:818）：计算位转换次数。
- `sign_extend_size(in_val, size_in, size_out) -> u64`（address.cc:666）：字节间符号扩展。

测试：新增 11 个（complement/convert_to_boolean/set_nz_mask/pull_back_unary/pull_back_binary_add/pull_back_binary_less/bit_transitions/sign_extend_size）。

## 2026-07-16：expand_mask + pullBack SUBPIECE usenzmask 完整化

- `expand_mask(size)`（rangeutil.cc:1060 内联）：设置 mask = calc_mask(size)，供 pullBack SUBPIECE 特殊情况使用。
- `pull_back_through_op`（jumptable.rs）的 SUBPIECE usenzmask 特殊情况（rangeutil.cc:1053-1064）已补齐：当 pullBackBinary 对 SUBPIECE val==0 失败时，检查 NZMask 确认截断的字节是否为零，是则保留范围并扩展 mask。此前保守返回 None。
  **2026-09-23 更新**：该 jumptable.rs 自由包装已删除，SUBPIECE 补救臂仅存于
  正典 `CircleRange::pull_back`（cc:1022-1084 镜像）；jumptable 两调用点
  （cc:1106/cc:1366）改传 `&mut None` discard markup 槽，与 oracle 两处
  "Throw away markup information" 局部一致。

## 2026-06-27（续）：union 返回码修复

- **CircleRange::union** 返回码对齐 Ghidra circleUnion 语义：0=single range（在 self 中），1=two pieces（无法表示），2=full（覆盖全部）。
- 新增相邻范围合并逻辑：`op2.left == self.right` 或 `self.left == op2.right` 时合并为单一范围。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
<!-- annotation-pass: 2026-07-04 -->
**2026-07-22**: +5 CircleRange methods (newStride/newDomain/setRange)

## 2026-07-22：ValueSet / ValueSetSolver / Widener 完整移植

新增 rangeutil.hh:106-327 + rangeutil.cc:1494-2604 的数据流值集分析层。1:1 移植，每个方法附 `// Ghidra: rangeutil.cc:<line> <fn>` 注释。

**CircleRange 补齐的集合运算（faithful 版，供 ValueSet::iterate 使用）**：
- `encode_range_overlaps(op1l, op1r, op2l, op2r) -> char`（rangeutil.hh:358）：6 种归一化重叠类别编码，索引 `ARRANGE` 表。
- `ARRANGE` 常量（rangeutil.cc:21）：64 项 char 表，逐字符核对 Ghidra 源串。
- `circle_union(op2) -> i32`（rangeutil.cc:360）：faithful circleUnion，返回 0=单区间、2=两段。
- `circle_intersect(op2) -> i32`（rangeutil.cc:549）：faithful intersect，返回 0=有效、2=两段。内含 newStride/newDomain 静态辅助（cc:103/143）。
- `minimal_container(op2, max_step) -> bool`（rangeutil.cc:454）：构造包含两者的最小范围。
- `get_min()` / `get_max_value()` / `get_end()`（rangeutil.hh:74）：getMin/getMax/getEnd 内联镜像。

**`pub struct ValueSet`**（rangeutil.hh:113）——附在 Varnode 上的值集，兼作数据流子图节点。
- `new()` — 默认构造（替代 C++ `list<ValueSet>::emplace_back`）。
- `set_varnode(vn, t_code)`（cc:1503）——初始化；written 分支经 `get_def()` 读
  defining op（2026-09-23 接通）。
- `add_equation(slot, type, range)`（cc:1549）/ `add_landmark(type, range)`（hh:146）——按 slot 有序插入约束。
- `does_equation_apply(num, slot) -> bool`（hh:143）/ `get_land_mark() -> Option<&CircleRange>`（cc:1742）。
- `compute_type_code_with(input_type_codes) -> bool`（cc:1567）——绝对/相对判定，不可判定返回 true。
- 求解器侧 `ValueSetSolver::iterate_node(cur, widener)`（cc:1611）——核心迭代（2026-09-23 arena 活读版，见下节）。
- 访问器：`get_count/get_type_code/get_varnode/get_range/is_left_stable/is_right_stable`。
- `print_raw() -> String`（cc:1756）。

**`pub struct Equation`**（rangeutil.hh:121）：`(slot, type_code, range)` 约束三元组。

**`pub struct ValueSetRead`**（rangeutil.hh:178）——读点处的值集，主迭代后计算。
- `set_pcode_op(op, slot)`（cc:1781）/ `add_equation(slt, type, range)`（cc:1793）/ `compute(src_value_set)`（cc:1804）/ `print_raw()`（cc:1821）。

**`pub struct Partition`**（rangeutil.hh:161）——弱拓扑排序的节点组。`start_node/stop_node` 用 arena id（`Option<VsId>`）替代 C++ `ValueSet *`。

**`pub trait Widener`**（rangeutil.hh:204）+ 两个实现：
- `WidenerFull`（hh:236）：`widen_iteration=2, full_iteration=5`；landmark 引导的受控 widening。
- `WidenerNone`（hh:254）：`freeze_iteration=3`，提前冻结以加速收敛。

**`pub struct ValueSetSolver`**（hh:274）——Bourdoncle 弱拓扑排序 + chaotic iteration。
- arena 模型：`value_nodes: Vec<ValueSet>` + `VsId = usize` 替代 `list<ValueSet>` 与裸 `ValueSet *` 指针。
- `new_value_set(vn, t_code) -> VsId`（cc:1953）。
- `visit(vertex, part) -> i32`（cc:1991）/ `component(vertex, part)`（cc:1974）/ `establish_topological_order()`（cc:2042）——Bourdoncle 算法，DFS 编号 + 头节点 0x7fffffff + 回路边重置 0。
- `partition_prepend_vertex_in_arena` / `partition_prepend_head_in_arena`（hh:389/400）——arena 化的 partition 前插。
- `solve(max, widener)`（cc:2524）——主迭代循环，component 栈 + isDirty 重启 + widener 重置。
- `establish_value_sets(sinks, reads, stack_reg, indirect_as_copy)`（cc:2416）——构建数据流系统（2026-09-23 全量 worklist 扩展接通）。
- `generate_true_equation` / `generate_false_equation`（cc:2066/2084）。
- `apply_constraints(vn, type_code, range, cbranch)`（cc:2105）——2026-09-23 全量（RANGEUTIL-CONSTGEN-0001）：splitPoint/boolean-flip 真假出边、restrictedByConditional、MULTIEQUAL landmark（addLandmark@numParams）、descend 遍历 + MULTIEQUAL 精确边槽位限制 + 支配链上溯生成真假方程。
- `constraints_from_path(type_code, lift, start_vn, end_vn, cbranch)`（cc:2185）——2026-09-23 全量：`CircleRange::pull_back(PcodeOp*)` 回拉至系统 varnode 后沿 def 链 apply_constraints。
- `constraints_from_cbranch(cbranch)`（cc:2210）——2026-09-23 全量：条件链回溯（unwritten/call/marker/numInput∉{1,2} 截断）、双非常量输入转 generate_relative_constraint、boolean(true) lift 起步。
- `generate_constraints(worklist, reads)`（cc:2248）——2026-09-23 全量：系统块支配链收集（MULTIEQUAL 全入块）、读点块链、blockList 清标后扫入边找 2 出边 CBRANCH splitPoint、finalList 去重清标。
- `check_relative_constant(vn, &mut type_code, &mut value)`（cc:2316）。
- `generate_relative_constraint(comp_op, cbranch)`（cc:2351）——2026-09-23 全量：INT_LESS/LESSEQUAL→SLESS/SLESSEQUAL 重映射、checkRelativeConstant 两侧判定、COPY/PTRSUB/INT_ADD(const in1) 链回溯后 constraintsFromPath(typeCode)。
- `CircleRange::pull_back(op, usenzmask)`（cc:1022）——2026-09-23 新增（RANGEUTIL-CONSTGEN-0001）：op 级回拉（一元/二元非常量槽位、SUBPIECE nzmask 补救臂 cc:1053-1064、末尾 setNZMask 交集 cc:1075-1082）；**同日（RULEMELD-FIDELITY-RESIDUE-0001 / EZ）签名扩为 `pull_back(op, usenzmask, const_markup: &mut Option<Arc<RwLock<Varnode>>>)`**：cc:1069-1070 的 `constMarkup` 出参落地——二元臂回拉成功且常量携带 SymbolEntry 时写出（最后写者胜、从不清零，镜像 C++ 共享出参语义）；约束族调用方传 `&mut None` 丢弃槽，RuleRangeMeld 传入自己的 markup 并在 cc:1414-1417 消费（`copy_symbol_if_valid`）。
- `ValueSetEdge`（hh:281）——出边迭代器，预收集后继 id。

**`pub struct ValueSetInput`**（RUDRA-GLUE，**2026-09-23 移除**）——旧的 `iterate`
输入暂存被 arena 活读替代（见下节）。

## 2026-09-23：RANGEUTIL-VSEMPTY-0001——求解器填充/迭代主链路实跑

**根因**：`establish_value_sets` 的 worklist 扩展循环是 TODO 占位（sink 的
defining-op 输入从不进系统），且 `ValueSet::iterate` 依赖的输入暂存
（`set_iterate_inputs`）无任何调用方——求解器对全部 guard sink 返回 empty
range，LoadGuard 停在 establish 全窗臂。

**修复**（全部对照 rangeutil.cc 锁定 oracle 行为）：
- `set_varnode` written 分支（cc:1516-1527）：经 `Varnode::get_def()` 读取
  defining op，opCode/numParams 忠实初始化（INDIRECT→COPY, numParams=1）；
  删除 `set_defining_op` 注入胶水。
- `establish_value_sets`（cc:2450-2498）：全量 worklist 扩展——INDIRECT
  （indirectAsCopy||isIndirectStore → 扩展 in0；否则 setFull+root）、
  CALL/CALLIND/CALLOTHER/LOAD/NEW/SEGMENTOP/CPOOLREF/FLOAT_*（setFull+root）、
  default（全部输入 newValueSet+mark+入列，annotation 跳过）。同时在扩展时为
  每个 written ValueSet 暂存 `input_ids`/`input_sizes`/`out_size`
  （RUDRA-GLUE：替代 C++ `op->getIn(i)->getValueSet()` 活链）。
- `ValueSetSolver::iterate_node(cur, widener)`（cc:1611-1737）：核心迭代改为
  arena 级活读——输入 range/稳定性/type_code 每次 iterate 从 arena 快照读取
  （与 C++ 活读语义一致，id 稳定）；count==0 → computeTypeCode；MULTIEQUAL
  circleUnion 折叠 / 1-2-3 参 push-forward；res==range 不变判定；partHead 成员
  走 doWidening（失败 setFull）。`solve`（cc:2524）两个调用点改接
  `iterate_node`；移除 `iterate`/`iterate_with`/`set_iterate_inputs` 暂存层。
- `push_forward_unary`（cc:1093-1167）全量忠实化：CAST/COPY 恒等、INT_ZEXT/
  INT_SEXT 的 full 与 2-pieces 臂、INT_2COMP/INT_NEGATE（+normalize）、
  BOOL_NEGATE/FLOAT_NAN → [0,2)。
- `push_forward_binary`（cc:1180-1367）全量忠实化：PTRSUB 并入 INT_ADD（含
  step/min/sizenew<size1 covered-everything 臂）、INT_MULT（step 增长 +
  getMaxInfo>wholeSize 折叠 + 负数乘法臂）、INT_LEFT、SUBPIECE、INT_RIGHT、
  INT_SRIGHT（sign_extend_bits 按 address.hh:543 位式符号扩展）、布尔输出族
  → [0,2)。
- `pull_back_unary` ZEXT/SEXT（cc:754-794）忠实化（含 SEXT 的
  `left & step` 位与怪癖与"交集须为空才成功"上游行为）；`pull_back_binary`
  补 SLESS/SLESSEQUAL/CARRY/SRIGHT（cc:878-998）。
- `intersect`（cc:549）：改为 faithful `circle_intersect` 的包装（保留
  0=空/1=单区间/2=两段 的旧返回码契约），获得 step/newStride/newDomain/回绕
  语义（此前 step!=1 时直接保守放弃）。
- `union`（**2026-09-23 CR8 M-A 隔离**）：legacy 简化包装——wrapping/混合/
  step≠1 一律两片、满覆盖显式返 2——**不得用于对齐语义路径**（上游
  `circleUnion` 满覆盖返 0+left==right，恒真判决在 translate2Op）；已加
  禁用注记，RuleRangeMeld OR 臂改接忠实版 `circle_union`。
- `==`（**2026-09-23 CR8 M-B**）：删除 `derive(PartialEq)`，手写
  `impl PartialEq` 逐字镜像 `operator==`（hh:331-336）——isempty 不等→
  false；双空→true（不比残留 mask/step/left/right——`iterate` 的
  `res==range` 不变判定依赖此语义）；否则比 left/right/mask/step。
- `set_stride`（cc:707-722，**2026-09-23 CR8 obs② 逐字重写**）：补
  `newStep==step` early-return、`right-step`（旧步长）快照、
  `!iseverything && left==right→isempty` 塌缩（旧实现自称 faithful 实为
  异构：除法取整改写边界+mask 回写，无塌缩）。
- 成员版 `new_stride`/`new_domain`（CR8 obs①）：死代码删除——生产路径为
  静态 `new_stride_owned`/`new_domain_owned`（`circle_intersect` 调用），
  原地留 tombstone 注记防再引入成员镜像。
- `contains_range`（cc:301-329）：重叠码 'c'/'b' 忠实判定替代边界近似；
  `WidenerFull::do_widening`（cc:1859-1870）landmark 检查改用
  `contains_range`。
- `invert`（cc:533-540）：忠实化（step 置 1 后 complement，返回原 step），
  `generate_false_equation` 的补约束由此获得正确语义。
- `translate_to_op`（cc:1424-1467）：全量忠实化（EQUAL/NOTEQUAL/SLESS 臂 +
  1/2/3 码），返回 `Result<(OpCode,u64,i32), i32>`；ruleaction RuleRangeMeld
  调用点改为 cc:1403-1437 的精确 restype 映射。
- 移位 Panic 安全：`<< val`/`>> val` 全部 `wrapping_shl/shr(val as u32)`
  （C++ UB 位点，x86 语义 = 掩 6 位）。

**测试**：+2（translate_to_op 码表；solver 端到端
`test_solver_fills_sink_range_through_int_add`——stackreg{0}+0x40 常量经
INT_ADD 收敛 [0x40,0x41) type=1，read 节点镜像）；test_push_forward_add 期望
修为 C++ 公式值 [5,24)。

**验证**：rangeutil 54/54（CR8 返工 + RANGEUTIL-CONSTGEN-0001 后）；curl/httpd E2E 差分、getparameter/next_url/
match_url/parseconfig 双投影 bisect（见 TODO_BOARD RANGEUTIL-VSEMPTY-0001 行）。

## 2026-09-23：RANGEUTIL-CONSTGEN-0001——约束生成族全量移植

**根因**：EI 之后 establish/iterate 真实，但 finalize（WidenerFull）对 load 守卫
爆窗（size≈0x2fffffb70 vs oracle 窄窗）——landmark/equation 只能来自约束生成
族，而 applyConstraints/constraintsFromPath/constraintsFromCBranch/
generateConstraints/generateRelativeConstraint 全为结构壳，前置缺口=
CircleRange::pullBack(PcodeOp*) op 级回拉。

**修复**（全部对照 rangeutil.cc 锁定 oracle 逐行）：
- `CircleRange::pull_back(op, usenzmask[, const_markup])`（cc:1022-1084）：一元臂/二元槽位臂/
  SUBPIECE nzmask 补救（mostsigbit_set(nzm)+8)/8 与 outSize 比较、mask 扩展）/
  setNZMask 集合交集（2 段失败保留原范围仍算成功）；constMarkup 出参
  （cc:1069-1070）同日 EZ 车道补齐（见上文 2026-09-23 CONSTGEN 条目更新）。
- `apply_constraints`（cc:2105-2173）：boolean-flip 真假出边对调、
  restrictedByConditional 双侧、MULTIEQUAL ValueSet 加 landmark
  （addLandmark=equation@slot numParams）、descend 顺序遍历、read-site
  （op mark）旁路 outVn 检查、MULTIEQUAL 真假块精确入边槽位限制、
  getImmedDom 支配链上溯（null/splitPoint 终止）。
- `constraints_from_path`（cc:2185-2203）：while startVn!=endVn pullBack 回拉 +
  for(;;) apply/def 前进（isCall/isMarker/pullBack 失败/unmark 终止）。
- `constraints_from_cbranch`（cc:2210-2238）：条件链 while(!isMark) 回溯
  （in(0) 常量换 in(1)；双非常量 → generate_relative_constraint 提前返回），
  命中系统后 CircleRange(true) lift + constraintsFromPath(0,...)。
- `generate_constraints`（cc:2248-2307）：worklist def 块（MULTIEQUAL 遍历全部
  入块）+ reads 块的支配链 mark 收集 → blockList；清标后对 blockList 每块每
  入边找未标、2 出边、lastOp==CBRANCH 的 splitPoint（mark 去重）→
  constraintsFromCBranch；finalList 清标。
- `generate_relative_constraint`（cc:2351-2406）：比较码重映射
  （INT_LESS→SLESS 等）、checkRelativeConstant 两侧（先 in0 后 in1）、
  pullBackBinary(slot 对侧, outSize=1)、COPY/PTRSUB/INT_ADD(常量 in1) 链回溯
  至标记 varnode、constraintsFromPath(typeCode)。
- heritage.rs `analyze_new_load_guards` 的 "Known residual" 注释同步为已实现。

**测试**：+3（`test_circle_range_pull_back_binary_less`——真臂 [0,5)/slot 换位
[6,0)/双常量 None；`test_circle_range_pull_back_subpiece_salvage`——无
usenzmask 失败/usenzmask 补救+8 字节 mask+nzm 集交；`test_generate_constraints_
true_branch_equation`——四块图 CBRANCH 真块 LOAD 读点方程 [0,5)@4 全链 + solve
后读范围收窄）。

## 已知基础设施缺口
- `Varnode::getValueSet()` 反向指针未实现 → solver 用 arena 扫描
  （`find_value_set_by_vn`）替代。
- `CircleRange::pullBack` 的 `constMarkup` 出参省略（RUDRA-GLUE）：本路径
  调用方（constraintsFromPath/generateRelativeConstraint）从不读回；
  消费者在 jumptable.cc 与 RuleRangeMeld 的 copySymbolIfValid（域外）。
- FlowBlock trait 的 mark 方法默认 no-op，仅 BlockBasic/BlockCopy 覆写——
  求解器运行的未结构化图中全部为 BlockBasic（Ghidra cc:2294 的
  `(BlockBasic*)bl->getIn(j)` 未检查转型同构），无观测差异。

测试：新增 21 个（rangeutil::value_set_tests），覆盖 Equation/ValueSet 构造与访问器、add_equation 有序性、does_equation_apply、compute_type_code、WidenerFull/WidenerNone、ValueSetRead::compute/add_equation、circle_union/circle_intersect/minimal_container、print_range_raw、encode_range_overlaps。全部通过（1026/1026）。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
