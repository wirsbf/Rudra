# `transform.rs` API Reference

**源代码路径**: `src/transform.rs`
**Ghidra 对应**: `transform.hh` / `transform.cc` (767 行)
**状态**: 🔧 L2 — `TransformManager` 五阶段与全部 API 已实现；fixture
`TRANSFORM-MULTIEQUAL-INSERT-0001` 十一项 coverage 全部 12.0.4 oracle `MATCH`
（含原六个 UNTESTED 残差分支），模块内其余外围函数（`parseSizes`/`getPiece`
的 throw 严格性等）残差见「已知限制」与 fixture `out_of_scope_observations`。

## 模块说明

大规模数据流变换基础设施。对应 Ghidra 的 `transform.hh` / `transform.cc`。
用于 lane splitting（将大寄存器操作分解为小的逻辑通道）和 Dolphin 变换。

## Rust 适配设计

Ghidra 使用原始 `TransformVar*` / `TransformOp*` 指针指向 `TransformManager`
拥有的 `list<TransformVar>` / `list<TransformOp>`。Rugra 采用 arena 风格 ID 索引：
`TransformManager` 拥有 `Vec<TransformVar>` 和 `Vec<TransformOp>`，引用使用稳定
的 `usize` 索引。Split 数组（Ghidra 的 `new TransformVar[n]`）存储为连续的 run，
其起始索引记录在 `piece_map` 中。

NULL input slot 建模：Ghidra 的 `PcodeOp` 构造函数（op.cc:71，`inrefs(s)`）
把输入槽预置为 NULL，`TransformOp::createReplacement` 的 grow 循环
（transform.cc:236）也插入 NULL 槽，直到 `placeInputs` 逐槽覆写。Rugra 的
`inrefs` 是非可选 `Vec<Arc<RwLock<Varnode>>>`，因此用 `null_slot_sentinel()`
（脱离 bank、size-0 的 Varnode）表示 NULL 槽：不经 `VarnodeBank` 创建（无
create-index/计数副作用）、不带 descendant、在观察投影中按 NULL 处理。
（2026-09-22，SB-ORD159-NULLSLOT-0001：本文件私有 `null_slot_sentinel` 改为
委托 `crate::op::null_slot_sentinel()` 的进程级共享实例——两个 NULL 槽之间
`Arc::ptr_eq` 恒 true，匹配 Ghidra 指针相等；`createReplacement` 的
逐槽 unset 循环不再需要手动补写哨兵，`op_unset_input` 自带 clearInput。）

## 导出的公共 API

### `LanedRegister` (transform.hh:93)
描述寄存器存储位置及其可分割的 lane 尺寸。
- `with_sizes(sz, mask)` / `default()`
- `add_lane_size(size)` / `allowed_lane(size)` / `lane_sizes()`
- `parse_sizes(register_size, lane_sizes)` — 解析逗号分隔的尺寸列表 (transform.cc:300)
- `get_whole_size()` / `get_size_bit_mask()`

### `LaneDescription` (transform.hh:132)
大 Varnode 内的逻辑 lane 布局。
- `uniform(orig_size, sz)` — 均匀分割 (transform.cc:35)
- `two_lane(orig_size, lo, hi)` — 两 lane (transform.cc:53)
- `subset(lsb_offset, size)` — 裁剪到子范围 (transform.cc:72)
- `get_boundary(byte_pos)` — 字节位置→lane 索引（二分搜索）(transform.cc:100)
- `restriction(num, skip, pos, size) -> Option<(num, skip)>` — 截断检查 (transform.cc:133)
- `extension(num, skip, pos, size) -> Option<(num, skip)>` — 扩展检查 (transform.cc:158)
- `get_num_lanes()` / `get_size(i)` / `get_position(i)` / `get_whole_size()`

### `TransformVarType` (transform.hh:36)
枚举：Piece(1)/Preexisting(2)/NormalTemp(3)/PieceTemp(4)/Constant(5)/ConstantIop(6)。

### `transform_var_flags` (transform.hh:45)
常量：`SPLIT_TERMINATOR`(1) / `INPUT_DUPLICATE`(2)。

### `TransformVar` (transform.hh:34)
变换后的 Varnode 占位符。
- `initialize(type, vn, bits, bytes, value)` — 原始初始化 (transform.hh:203)
- `create_replacement(fd, def_op)` — 创建实际 Varnode (transform.cc:175)；
  `piece` 类型 bit 未字节对齐时 `panic!("Varnode piece is not byte aligned")`
  （cc:197-198 LowlevelError 的 panic 映射，同 funcdata.rs 既有惯例）；
  piece 臂地址 **vn 自身空间限定**（2026-09-25 FAMILY-AUDIT-SPACELESS-SITES-0001：
  cc:202 `Address addr = vn->getAddr() + bytePos` 保留 vn 的空间，cc:207
  newVarnodeOut 收完整 (space,offset)——def 分支改
  `new_varnode_out_full(byte_size, vn_space, addr, def)`，unique 临时/栈/ram
  piece 不再钉死寄存器空间；free 分支 `vbank.create_with_space(vn_space,…)`
  空间本就正确——其 raw-create 形态与 cc:205 `newVarnode` 完整尾
  （assignHigh/laned/queryProperties）的差异属邻接适配面观察，已登记未改）；
  `constant_iop` 分支 (cc:211-215) 经模块私有 `get_op_from_const_offset`
  把占位符 `val` 解码回受影响 PcodeOp（op.hh:249 静态 `getOpFromConst` 的
  按 offset 形态），再 `Funcdata::new_varnode_iop` 物化 iop 空间注记；
  `val == 0` 时解码为 `None`（Ghidra `(PcodeOp*)(uintp)0 == NULL` 的 Rust
  非空 Arc 映射），直接按 `newVarnodeIop(NULL)` 语义物化 offset 0 的
  iop 空间注记 varnode（funcdata_varnode.cc:176-184；annotation 标志由
  Varnode 构造器自动置位 varnode.cc:599-601）
- 字段：`vn` / `replacement` / `var_type` / `flags` / `byte_size` / `bit_size` /
  `val` / `def`

### `get_op_from_const_offset` (op.hh:249)
模块私有自由函数：把 iop 空间 offset 解码回 `PcodeOpRef`（`Arc::from_raw` +
clone + forget，同 `Funcdata::get_op_from_const` funcdata.rs:3325 的重建契约，
但按裸 offset 取参、无空间校验 — 与 Ghidra 静态方法的无条件指针重解释对齐）。
返回 `Option<PcodeOpRef>`：`offset == 0` 返回 `None`（Ghidra 的 NULL
`PcodeOp*`，可传递、从不解引用）；非零 offset 才走 Arc 重建 — Rust `Arc`
非空，`Arc::from_raw(null)` 是 UB（nightly `NonNull::new_unchecked` 前置
检查即 SUBFLOW-SPLITFLOW-SIGABRT-0001 的崩溃点）。

### `transform_op_special` (transform.hh:70)
常量：`OP_REPLACEMENT`(1) / `OP_PREEXISTING`(2) / `INDIRECT_CREATION`(4) /
`INDIRECT_CREATION_POSSIBLE_OUT`(8)。

### `TransformOp` (transform.hh:63)
变换后的 PcodeOp 占位符。
- `attempt_insertion(fd, ops)` — follow 已落块后完成延迟插入；`MULTIEQUAL`
  使用 `op_insert_begin`，其他 opcode 使用 `op_insert_before` (transform.cc:254)
- `inherit_indirect(ind_op)` — 继承 INDIRECT 标记 (transform.cc:273-282)：
  源 op 带 `PcodeOp::indirect_creation` 时，按 in(0) 的 `is_indirect_zero`
  （`indirect_creation|constant` 双标志，varnode.hh:271）分派
  `INDIRECT_CREATION` 或 `INDIRECT_CREATION_POSSIBLE_OUT`
- 字段：`op` / `replacement` / `opc` / `special` / `output` / `input` / `follow`

### `TransformManager` (transform.hh:156)
orchestrates 变换生命周期。
- `new()` / `default()` / `init(fd)`
- `preserve_address(vn, bit_size, lsb_offset)` — 是否保留地址 (transform.cc:348)。
  这是 Ghidra 的虚函数分派点（transform.hh:171；`SubfloatFlow::preserveAddress`
  subflow.cc:3451 覆写返回 `vn->isInput()`）；Rust 用
  `preserve_address_override` 钩子镜像 vtable 槽，`None` 走基类逻辑
- `set_preserve_address_override(f)` — 安装上述覆写钩子（RUDRA-GLUE）
- `clear_varnode_marks()` — 清除所有占位符 Varnode 的 mark (transform.cc:356)
- 字段：`preserve_address_override`（pub，虚分派镜像）

**占位符创建**（transform.cc:370-575）：
- `new_preexisting_varnode(vn)` / `new_unique(size)` / `new_constant(size, lsb, val)`
- `new_iop(vn)` / `new_piece(vn, bit_size, lsb)`
- `new_split(vn, description)` / `new_split_subset(vn, desc, num, start)`
- `new_op_replace(num, opc, replace)` / `new_op(num, opc, follow)`
- `new_preexisting_op(num, opc, original)`

**占位符查找**（transform.cc:581-649）：
- `get_preexisting_varnode(vn)` / `get_piece(vn, bit_size, lsb)`
- `get_split(vn, desc)` / `get_split_subset(vn, desc, num, start)`

**输入/输出设置**（transform.hh:219-253）：
- `op_set_input(rop, rvn, slot)` / `op_set_output(rop, rvn)`
- `preexisting_guard(slot, rvn)` — 是否应创建 preexisting op

**apply 生命周期**（transform.cc:651-765）：
- `apply(fd)` — 完整应用变换（createOps→createVarnodes→removeOld→
  transformInputVarnodes→placeInputs）；`createVarnodes` 中 piece 未对齐会
  panic 并保留异常前部分状态
- 私有（P6 形态，2026-09-30 起）：`create_op_replacement(fd, op_idx)` /
  `create_ops(fd)` / `create_varnodes(fd, input_list)` / `remove_old(fd)` /
  `transform_input_varnodes(fd, input_list)` / `place_inputs(fd)` /
  `special_handling(fd, rop)` — oracle `Funcdata *fd` 成员
  （transform.hh:157）不再以 `*mut Funcdata` 存储，fd 逐调用线程化
  （ARENA_DESIGN §3.2 P6；`unsafe impl Send` 随之删除，自动 Send+Sync）。
  `init(fd)` 保留 oracle 构造绑定签名（transform.hh:169），仅重置占位符
  存储。`get_op_from_const_offset(fd, offset)`（iop 解码，op.hh:249 形态）
  改为 bank 身份搜索（optree+deadandgone），不再 `Arc::from_raw` 重建。

**`create_op_replacement` 分支**（transform.cc:225-250）：
- `op_preexisting` 臂：原 op 原地改 opcode；`while input.len() < numInput()`
  从末尾 `op_remove_input` 收缩；逐槽 `op_unset_input` 清空（槽置 NULL 哨兵）；
  `while numInput() < input.len()` 在 `numInput()-1` 槽位插入 NULL 哨兵
  （Ghidra `opInsertInput(op,(Varnode*)0,slot)` 中 `opSetInput` 对新鲜 NULL 槽
  cc:107 早退，净效果即裸槽插入，不产生 bank Varnode）；不重新插入、不被
  removeOld 销毁
- 新 op 臂：`fd.new_op(input.len(), addr)` 后预填 NULL 哨兵槽（对齐 op.cc:71
  `inrefs(s)` 的预置语义，弥补 op.rs `create` 只 reserve 的缺口）；
  `output == None` 时不物化输出 Varnode（cc:241-242）

**`special_handling`**（transform.cc:654-660）：`INDIRECT_CREATION` →
`fd.mark_indirect_creation(replacement, false)`，`INDIRECT_CREATION_POSSIBLE_OUT`
→ `mark_indirect_creation(replacement, true)`（funcdata_op.cc:736-748 在
replacement op/out/(非 possible-out 时) in(0) 上置标志）。

## 已知限制
- ~~`transferVarnodeProperties`（transform.cc:208）尚未实现 — Rugra 的 Varnode 未暴露
  完整的属性转移 API~~ — 2026-10-01（READINODE2，TRANSFORM-PIECE-FLAGTRANSFER-0001）
  已接线：`create_replacement` 的 `Piece` 臂现在调用
  `Funcdata::transfer_varnode_properties`（src/funcdata.rs，funcdata_varnode.cc:614-629
  1:1 移植），在地址保持 piece 上保留 `directwrite|addrforce` 标志与移位后的
  consume 掩码。缺此调用时，被守卫位置（全局的 persist return-copy、addrforce
  的栈槽）经 RuleSplitFlow/SplitFlow 拆分后丢失 addrforce →
  RuleEarlyRemoval/ActionDeadCode 吞掉写回格（READINODE2 drill：
  read_super xRam156858 的 6 字节 return-copy oracle 于 earlyremoval 6785
  存活[isAutoLive]，Rugra 旧码 6257 即亡）。测试覆盖（CR-READINODE2 §5-2
  整改补齐）：原三断言（addrforce/directwrite 转移、lsb 6 高 lane fill_bits、
  零标志零 consume 对照）+ 2026-10-02 补 `lsb_offset>=8` 守卫假分支
  （funcdata_varnode.cc:618 false → newConsume 保持 `~0` 初值、不落
  calc_mask 截断）与 `def==None` 路（transform.cc:204-205 newVarnode 分支
  同样到达 cc:208 transfer）两断言。
- `Funcdata::mark_indirect_creation`（src/funcdata.rs）对 in(0) 非常量走
  eprintln 而非 Ghidra 的 LowlevelError throw（funcdata_op.cc:743-744）；
  fixture 只覆盖常量 in(0) 路径（FUNCDATA-MARKINDIRECT-STRICT-0001）。
- `PcodeOpBank::create`（src/op.rs）只 reserve 输入槽，不预置 NULL 槽
  （Ghidra op.cc:71 预置）；transform.rs 以 detached 哨兵补偿
  （OP-BANK-CREATE-NULL-SLOTS-0001）。
- `parse_sizes` 非法尺寸走日志跳过而非 throw（transform.cc:323-324，
  TRANSFORM-PARSESIZES-STRICT-0001）；`get_piece` 重复 piece 冲突同样
  （transform.cc:607，TRANSFORM-GETPIECE-DUP-THROW-0001）。
- ~~`ConstantIop` 类型使用常量 fallback（Rugra 无 iop space）~~ — 2026-08-23
  （TRANSFORM-CONSTANT-IOP-SPACE-0001）已按 cc:211-215 接入：`create_replacement`
  经私有 `get_op_from_const_offset`（op.hh:249 `PcodeOp::getOpFromConst` 的按
  offset 重载，镜像 transform.cc:213 直接从占位符值构造 Address 的调用形态）
  解析出受影响 op，再经 `Funcdata::new_varnode_iop` 物化为 iop 空间注记
  varnode（非常量）。lanedivide_infra_1204 的 indirect 投影已去规范化，
  `si/k0` 分类由真实空间类型驱动，const 空间回归会使字节门禁失败。
- ~~`deleteVarnode` / `setInputVarnode` 未暴露~~ — 2026-08-15
  （VARNODE-INPLACE-MUTATION-SITES-0001）已接入：`transform_input_varnodes` 对旧
  输入走 `fd.delete_varnode`（cc:734-735，funcdata.hh:294），新输入走
  `fd.set_input_varnode`（cc:736，funcdata_varnode.cc:340-373 → `VarnodeBank::setInput`
  varnode.cc:1358 身份删除+INPUT 重键），canonical 返回值存回 `replacement` 供
  placeInputs 接线；不再原地 set_flags(INPUT) 突变树驻留 varnode。
- ~~`inherit_indirect` 保守假设 possible-out~~ / ~~`special_handling` no-op~~ —
  2026-08-23（TRANSFORM-MULTIEQUAL-INSERT-RESIDUAL-0001）已按 cc:273-282 /
  cc:654-660 接入双臂分派与 `mark_indirect_creation` 调用。

## 测试
20 个单元测试覆盖 LanedRegister（basic/parse_sizes）、LaneDescription（uniform/
two_lane/get_boundary/subset/restriction/extension）、TransformVar（initialize）、
TransformManager（preexisting/unique/constant/constant-shift/split/op-replace/
op-set-input-output/preexisting-guard/constant-getpiece）。

### 2026-07-01（续）：TransformManager::apply 确认完整
TransformManager::apply（transform.cc:756-765）：create_ops→create_varnodes→remove_old→place_inputs→transform_input_varnodes。SplitFlow 委托此方法。

### 2026-08-21：TRANSFORM-MULTIEQUAL-INSERT-0001

`TransformOp::createReplacement` 的 immediate 分支和 `attemptInsertion` 的 follow
分支现在都保留锁定 Ghidra 的 opcode 特判：新 `MULTIEQUAL` 总是通过
`Funcdata::op_insert_begin` 插到基本块开头，其他新 op 仍紧邻原 op/follow 之前。
连续创建两个 PHI 时，第二个创建的 op 因再次插到 block begin 而排在第一个之前；
COPY 等非 PHI 保持创建顺序。对应单测同时覆盖 immediate/follow 两条路径及
PHI/non-PHI 四种组合；锁定 12.0.4 fixture 对比完整 op/varnode identity、
SeqNum time/order、def-use、块内顺序和 bank 计数。

### 2026-08-23：TRANSFORM-MULTIEQUAL-INSERT-RESIDUAL-0001 六分支补齐

六个 UNTESTED 分支双侧补到 `MATCH`，fixture 由 4 记录扩到 11 记录：

- `preexisting_ops`：`op_preexisting` 臂（cc:228-237）— opcode 原地重定向、
  输入收缩 3→1（末尾 removeInput + 逐槽 unset）、增长 1→3（`numInput()-1`
  槽位 NULL 插入，placeInputs 全覆写）、identity/位置/输出保持、不销毁；
- `nested_follow`：top(COPY)→mid(MULTIEQUAL)→follow 两跳链，mid 先落 block
  begin、top 再插到 mid 的 replacement 之前（`follow->replacement` 二跳间接
  可观察）；公有 `newOp` API 下 do-while retry 体不可达（创建序不变式，
  CREATEOPS-RETRY-UNREACHABLE-0001）；
- `indirect_zero` / `indirect_possible`：`inheritIndirect` 双臂 +
  `specialHandling`→`markIndirectCreation(false/true)` 的 op/out/in(0) 标志投影
  （`I`/`x` 位），并覆盖 `opInsertBefore` 跳过前置 INDIRECT 臂与非跳过臂；
- `piece_error`：`preserveAddress` 覆写（cf. SubfloatFlow）强制 misaligned
  `piece`，apply 在 createVarnodes 中抛出/panic
  `Varnode piece is not byte aligned`，双侧对比异常前部分状态（op 已建已插、
  输出已物化、NULL 输入槽 `_,_`、removeOld 未跑、anchor 存活）；
- `output_null`：`output == nullptr` 臂 — 0 输入 COPY 与 2 输入 MULTIEQUAL
  replacement 无输出物化；
- `seqnum_renumber`：25 个 MULTIEQUAL begin 插入耗尽 `ordbefore=2` 的 midpoint
  阶梯，`BlockBasic::setOrder`（block.cc:2638-2651，25-op 块 step=171798690）
  中途整块重排后 midpoint 恢复 — 全 r 向量可观察。

证据状态：`projection_status=MATCH`、`overall_status=MATCH`、residual_todo_ids
为空；runner fail-closed 校验同步收紧（coverage 状态集必须为 `{MATCH}`、
不得残留 `residual_union`、`out_of_scope_observations` 逐条校验）。fixture
metadata schema 2 的每个 coverage 项仍为 `{status, covers, residual_todo_ids}`。
<!-- annotation-pass: 2026-07-04 -->

- 2026-09-25 (FAMAUDIT integration): constructor sites merged to master; this note records the integration commit touching the module.
