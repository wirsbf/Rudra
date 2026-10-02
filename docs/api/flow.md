# flow.rs — Reachability-based control flow tracking

## 2026-09-30：(g) 守卫影子随行（Lane ARENAFLIP-g 步骤 2）
- splitBasic 系 SWITCH_OUT 直写改 `set_flags/clear_flags`（block.hh:155/156
  形态）；`mem::take(&mut pbb.outgoing)` 后与 `tbb.outgoing = parent_outgoing`
  后补 `sync_bank_shadows()`。值语义逐位不变（|= / &= ! 同型）。

## 2026-09-30：splitBasic tail 边重定向补孪生（Lane ARENAFLIP-d 步骤 1）
- case-destination split（flow.cc:1021-1037 connectBasic 域）的入边半
  `.point = tail` 写点同步打 `point_id` 值孪生（`fd.bblocks.bank` 预解析，
  无 point 守卫——孪生是纯表示字段，语义逐位不变）。详见
  docs/api/block.md 2026-09-30 条。

## 2026-08-26：GOTO-LABEL-UNPRINTED-0001 收尾验证
- `FlowInfo::generate_ops` 的控制流恢复继续遵循 `flow.cc:785-822` 的阶段顺序；尾调用/流覆盖传输在原始 p-code 层完成后，标签发现可消费稳定的 branch/call 形态。
- 本轮移除仅用于诊断的 `[DBG]` 原始 op/CFG 探针，避免污染 stderr；生产路径不依赖环境变量。
- httpd（Ghidra 12.0.4 oracle `e40ed13014025f82488b1f8f7bca566894ac376b`, x86:LE:64:default）实测 29/29 函数完成，goto 未定义目标为 0，`LAB_00000000` 为 0；curl 回归 defects=0、numbering=0。

## 2026-07-04：新建 src/flow.rs — FlowInfo Phase 1（可达性流追踪核心）
- 新建 `src/flow.rs`，实现 `FlowInfo` struct（对齐 flow.hh:58-169 FlowInfo）。
- `generate_ops(entry)`：addrlist 工作列表驱动的指令解码主循环（对齐 flow.cc:785-822）。
- `fallthru()`：顺序解码内循环（对齐 flow.cc:545-580）。
- `set_fallthru_bound()`：边界检测 + visited 去重（对齐 flow.cc:489-513）。
- `process_instruction(addr)`：单指令解码 → lift → inject_raw_ops_single（对齐 flow.cc:383-482）。
- `xref_control_flow()`：控制流分析，BRANCH/CBRANCH/RETURN/CALL 分类（对齐 flow.cc:264-372）。
- `follow_flow()` 入口函数（对齐 funcdata_op.cc:756 followFlow）。
- Funcdata 新增 `inject_raw_ops_single`（单指令注入，不建块）+ `build_blocks_from_alive`（流追踪后建块）。
- **Phase 1 完成**（可达性流追踪核心）。Phase 2（跳转表恢复/inline/truncatedFlow）待后续。
- **BRANCHIND 限制**：间接跳转在流追踪中被标记为 non-fallthru（流停止），需要后续补 x86_lift.rs 的 BRANCHIND 发射 + jumptable 恢复。
git add src/flow.rs src/funcdata.rs src/lib.rs docs/api/flow.md && git commit -q -F - <<'EOF'
core(flow): new src/flow.rs — FlowInfo Phase 1 (reachability flow tracking)

New src/flow.rs implementing Ghidra's FlowInfo reachability-based flow
tracking (flow.hh:58-169, flow.cc:785-822). This is the core of the
L1 gap: replaces Rudra's linear scan with address-list-driven decoding.

## Components

FlowInfo struct (flow.hh:58-169):
- addrlist: Vec<Address> (LIFO work-list, flow.hh:82)
- visited: BTreeMap<u64, VisitStat> (flow.hh:84, for dedup + range query)
- insn_count/insn_max (flow.hh:95-96)
- baddr/eaddr/minaddr/maxaddr (flow.hh:97-100)

Methods:
- generate_ops(entry): addrlist-driven decode loop (flow.cc:785-822)
- fallthru(): sequential decode inner loop (flow.cc:545-580)
- set_fallthru_bound(): boundary detection + visited dedup (flow.cc:489-513)
- process_instruction(addr): decode one instruction, lift, inject (flow.cc:383-482)
- xref_control_flow(): classify BRANCH/CBRANCH/RETURN/CALL (flow.cc:264-372)

Funcdata additions:
- inject_raw_ops_single: inject single instruction's P-code (no block building)
- build_blocks_from_alive: build CFG after all flow tracking completes

follow_flow() entry point (funcdata_op.cc:756 followFlow).

Ghidra: flow.cc:785 generateOps, :545 fallthru, :489 setFallthruBound,
:383 processInstruction, :264 xrefControlFlow.

Phase 1 complete. Phase 2 (jump-table recovery, inline, truncatedFlow) TODO.
BRANCHIND targets are not followed (flow stops) — needs x86_lift.rs fix.

Verification: 952/952 tests pass, curl 24/24 gcc (unchanged — flow.rs
not yet wired into main.rs; existing linear scan still active).

### 2026-07-04（续）：BRANCHIND 发射 + Phase 1 无回归确认
- x86_lift.rs 的 `jmp` 分支现在处理非 Immediate 操作数（Register/Memory）→ 发射 CPUI_BRANCHIND。
- curl 的 24 个函数中无 switch/间接跳转（BRANCHIND count = 0），所以 Phase 2 跳转表恢复不会影响 curl 输出。
- FlowInfo Phase 1 的 BRANCHIND 处理：当前标记为 non-fallthru（流停止），Phase 2 将添加跳转表恢复。

### 2026-07-04（续 2）：FlowInfo Phase 2 — 跳转表恢复循环
- `generate_ops` 新增 Phase 2：BRANCHIND 收集 → try_recover 跳转表恢复 → 地址推入 addrlist → fallthru 追踪（对齐 flow.cc:796-821）。
- 新增 `collect_branchinds`（扫描 alive ops 找 BRANCHIND）+ `new_address`（范围检查 + visited 去重后推入 addrlist）。
- 跳转表恢复使用现有 jumptable.rs::try_recover（已移植）。
- 多阶段检测：如果新 BRANCHIND 出现，循环继续（flow.cc:814 checkMultistageJumptables）。
- curl 无间接跳转，无回归。Phase 2 对 switch/间接跳转函数生效。
<!-- annotation-pass: 2026-07-04 -->

<!-- sleigh-lift-pipeline: 1783181897.3074532 -->
 
**2026-07-22**: 23 missing flow.cc methods added (11→34 functions, +361 lines)

## 2026-08-11：ANN-B 注释 provenance 审计

- Oracle 固定为 Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`；完整读取 `flow.cc` 与 `flow.hh` 后分类。
- 为 `FuncCallSpecsExt` 的 8 个 trait 声明和 8 个 Rust 实现补充具体 `RUDRA-GLUE: ANN-B`：这些是 flow-local 适配层，不是 Ghidra `FlowInfo` 函数。缺失的 callspec 状态/身份分别仍由 `CALLSPEC-0001` 与 `INJECT-0001` 跟踪。
- `address_space_as_u32` 是 Rust `AddressSpace` 到临时注入元组的适配；`find_callspec_for_op` 是 callspec 指针身份尚未落地时的线性扫描回退，二者均无可诚实引用的 Ghidra 函数体。
- 本轮仅补对齐来源注释，不改行为，也不产生逐函数 oracle `MATCH` 或 L3 证明。

## 2026-07-22（续）：FlowInfo 跳转表细节补齐 — Phase 2 完整化

补齐 Ghidra `flow.cc` 中缺失的跳转表（jump-table）分析与基本块生成方法。每个
移植方法均带 `// Ghidra: flow.cc:<行号> FlowInfo::<函数名>` 注释，Rust 胶水
标 `// RUDRA-GLUE: <理由>`。

### 新增方法（src/flow.rs，+403 行，778→1181）

| Rust 方法 | Ghidra flow.cc | 说明 |
|---|---|---|
| `recover_jump_tables` | :1427 recoverJumpTables | BRANCHIND 跳转表恢复主入口；partial Funcdata（`@@jump@` 命名、共享 Architecture/loader）+ `Funcdata::recover_jump_table` 分级恢复 + notreached 延迟列表 + partial/complete 分支；LowlevelError 经 `Result` 上抛同 C++ throw 通道 |
| `check_multistage_jumptables` | :1408 checkMultistageJumptables | 多阶段跳转表检测；`JumpTable::check_for_multistage` 已移植（JUMPTABLE-PIPELINE-0001），被 override 提升的单条目表间接 op 推回 `tablelist` |
| `xref_inlined_branch` | :1053 xrefInlinedBranch | 内联注入的 CALL/CALLIND/BRANCHIND 交叉引用；BRANCHIND 走 find_jump_table |
| `find_unprocessed` | :850 findUnprocessed | addrlist 剩余地址 → unprocessed |
| `dedup_unprocessed` | :866 dedupUnprocessed | 排序 + 去重（Address: Ord） |
| `fillin_branch_stubs` | :889 fillinBranchStubs | 为 unprocessed 地址生成 artificial_halt(MISSING) + STARTBASIC/STARTMARK |
| `collect_edges` | :906 collectEdges | 收集 (src,targ) 边对；BRANCH/CBRANCH/BRANCHIND(jumptable 条目)/fallthru |
| `split_basic` | :983 splitBasic | 委托 build_blocks_from_alive；保留入口块不变量 |
| `connect_basic` | :1021 connectBasic | 按 collectEdges 的原始顺序清空并重放边，保留正反向 slot |
| `generate_blocks` | :824 generateBlocks | fillinBranchStubs → collectEdges → splitBasic → connectBasic → removeUnreachableBlocks |

辅助方法（`// RUDRA-GLUE`）：
- `target_op_for_branch` — `collect_edges` 的内部适配名，委托完整
  `branch_target`/`target`，包括目标指令无 P-code 时沿 visited 前进的路径
- `target_op_by_addr` — 地址 → 首个 alive op（Ghidra target() 地址回退循环）
- `fallthru_op` — 顺序下一个 alive op（Ghidra fallthruOp 的近似）

### 已知缺口（RUDRA-GLUE 标注）

- **partial Funcdata 克隆**（已关闭，JUMPTABLE-PIPELINE-0001）：`recover_jump_tables`
  现构建 `@<fn>@@jump@<addr>` 命名的 partial Funcdata 并共享源函数的
  Architecture（含 loader），经 `Funcdata::recover_jump_table` → `stage_jump_table`
  → `truncated_flow` + "jumptable" 策略组完整分级恢复；不再走原地 `try_recover`。
- **JumpTable::checkForMultistage**（已关闭，JUMPTABLE-PIPELINE-0001）：
  `check_for_multistage` 已移植，`check_multistage_jumptables` 按 flow.cc:1414-1415
  将被提升表的间接 op 推回 `tablelist`。
- **Funcdata::linkJumpTable**：未移植，`xref_inlined_branch` 用 `find_jump_table`
  近似。
- **FuncCallSpecs 管线**：`FlowInfo::setup_call_specs`/`setup_callind_specs` 的 stable
  owner、typed annotation 与 exact op identity 生命周期已接通；override/prototype/query
  及 `truncate_indirect_jump`/`xref_inlined_branch` 对这些 helper 的调用 consumer 仍为
  `CALLSPEC-0001`/`UNTESTED`。
- **opMarkStartInstruction**：`fillin_branch_stubs` 直接设置 STARTMARK；正常指令由
  `process_instruction` 设置。`opMarkStartBasic` 不再推迟给 block builder：work-list
  目标边界必须在 `new_address`、`set_fallthru_bound`、`fallthru` 和
  `find_unprocessed` 的 Ghidra 对应位置即时设置 STARTBASIC。

### 验证

- `cargo check --lib`：flow.rs 零错误（唯一的 E0502 在 grammar.rs，与本任务无关的
  并发改动）。
- flow.rs 仅 3 个 pre-existing 警告（unused `Instruction` import / `stat` / `inst`）。
- 新增方法无新增警告。

## Alignment Evidence

- 源文件：`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/flow.cc`（1460 行）
  + `flow.hh`（172 行）。
- 目标文件：`src/flow.rs`（778 → 1181 行，+403 行）。
- 每个移植方法上方有 `// Ghidra: flow.cc:<行号> FlowInfo::<名>` 注释。
- `cargo check --lib` 通过（flow.rs 零错误）。

## 2026-08-13：`PIPE-REACH-0001` 可达指令闭环

锁定 oracle 为 Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。本轮重新完整读取
`FlowInfo::processInstruction`、`xrefControlFlow`、`setFallthruBound`、`fallthru`、
`generateOps` 和 `Funcdata::followFlow` 后，将 canonical CLI/curl 路径改为：

1. 为所属 ELF section 创建一个 owned `SleighLifter`；
2. 从函数入口用 LIFO 地址工作表追踪；
3. 每条指令一次性取得 `Sleigh::oneInstruction` 的 step 与全部 P-code；
4. 根据 BRANCH/CBRANCH/RETURN 推进可达地址，再从 alive ops 构造 CFG；
5. CALL/CALLIND 在 flow 阶段创建 `FuncCallSpecs`，直接 CALL 的 input(0) 改成
   synthetic call-spec annotation。

真实 `GetStr` 六层 fixture 的直接结果：旧 Rudra 在 RETURN 后仍线性提升的
`0x3702` 对齐 NOP 已消失；两侧 raw P-code 均为 103 ops / 272 Varnodes、CFG 均为
6 blocks，并且全部 103 条 op 的 `(address, opcode, input_count, has_output)` 顺序一致。
两次 Rudra release 运行的六层 JSON 逐字节相同。

这只是 `PIPE-REACH-0001` 的窄闭环，`flow.rs` 仍是 **L2 / MISMATCH**：

- raw Varnode 的初始 unknown type、COVERDIRTY/其他状态尚未与 Ghidra 一致；
- CALL annotation 的动态 Fspec space 被固定枚举中的 Iop space 代替；
- `xrefControlFlow` 的 relative internal branch、`maxtime`、删除尾部 ops、CALLOTHER
  injection、override、noreturn 与完整 jump-table 流程未闭合；
- `generateBlocks` 仍委托 `build_blocks_from_alive` 做块划分；入口身份、边重放及
  回边入口的 synthetic front 已对齐，剩余块 range cover 和特殊边属性另行跟踪；
- DataUnavail、BadData、Unimpl 和 instruction-limit 的异常/状态路径尚未逐分支 MATCH。

这些残差继续由 `SLEIGH-FLOW-0001`、`CALLSPEC-0001`、`ADDR-0001`、
`SLEIGH-0002C`/`D` 跟踪，不能沿用本文件早期“Phase 完成”文字推断 L3。

## 2026-08-13：`BLOCK-ENTRY-0001` 入口块与边顺序

锁定 oracle：Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。生产 `follow_flow` 现在调用完整的
`FlowInfo::generate_blocks`，不再直接绕到 `build_blocks_from_alive`。该阶段按
Ghidra `flow.cc:824-845`、`:906-1037` 与 `block.cc:1627-1645` 执行：

1. 在拆块前保存 `collectEdges` 的 `(source op,target op)` 插入顺序；
2. `split_basic` 将首块登记为唯一 `ENTRY_POINT (0x200)`；
3. 清除 builder 的临时边，按保存顺序重放边及 reverse slot；
4. 若首块存在入边，创建空前置块、追加 `newfront -> old entry`，再把前置块移到
   `list[0]` 并转移 `ENTRY_POINT`；
5. 分支目标指令本身无 P-code（例如 ENDBR64）时，通过 visited 顺序推进到该指令
   的首个实际 P-code，与 Ghidra `target()` 一致。

真实行为门禁 `tools/run_block_entry_oracle.sh` 用同一个无 PIE x86-64 fixture 分别
运行锁定的 Ghidra 与 Rudra，完整对比普通 RETURN 与入口自环两条路径的块顺序、
入口对象身份/数量/flags、op 数、归一化地址范围、正反向边及 reverse slot。当前
结果为 `MATCH`。这证明上述窄行为，不代表整个 FlowInfo 或 CFG 模块 L3；
multiple roots、unreachable pruning、BRANCHIND 和 Action 后 index 仍未覆盖。

## 2026-08-13：`FLOW-TARGET-BOUND-0001` 已访问目标边界

独立复核发现，清除 provisional builder 边后，`GetStr` 中 CALL@`0x36e4` 到已访问
汇合点 `0x36e9` 的 fallthrough 丢失。根因不在 `connect_basic`：Ghidra 的
`collectEdges` 本来就只依赖拆块前的 STARTBASIC；差异来自更早的地址工作表。

当前实现按 locked `flow.cc:219-235`、`:489-513`、`:545-580` 恢复以下时序：

1. `new_address` 遇到已访问目标，立即通过 `target(addr)` 找到首个实际 P-code 并
   设置 STARTBASIC；否则保持 LIFO push。
2. `set_fallthru_bound` 用 `visited.upper_bound(addr)` 的语义找 predecessor。若
   predecessor 与待处理地址相等，先设置 STARTBASIC，再丢弃重复 work item。
3. `fallthru` 在整段顺序解码期间保留同一个 `bound`，不随 work-list 栈顶变化而
   重算；精确命中已访问 bound 时，只有持久的 `startbasic` 为真才设置标志。
4. `find_unprocessed` 对仍留在工作表且已经访问的目标执行相同标记。

真实门禁 `tools/run_flow_target_boundary_oracle.sh` 同时逐字节差分：

- 最小 `CBRANCH → CALL → visited join` 三块函数；
- Git commit `86ffa7bcaba0100cdd32b55a619bb07e31af84ad` 中
  `examples/curl` blob 物化的 ELF 里，`GetStr` 的六块完整 CFG，
  包括唯一 CALL fallthrough `1→2`；
- 每块 flags、op 数、地址范围，以及所有有序 in/out peer ordinal 和 reverse slot。

结果为 `MATCH`。原 `tools/run_block_entry_oracle.sh` 的 RETURN 与 synthetic-front
self-loop 也继续 `MATCH`。此闭环不扩展到 off-cut/reinterpreted 错误模式、
out-of-bounds stub、BRANCHIND 或 intra-instruction relative branch 残差。

## 2026-08-13：`SLEIGH-FLOW-REL-0001` 只读设计与 locked fixture

本节是源码租约释放前的设计草案，当前状态仍为 **UNTESTED**。锁定 oracle：Ghidra
12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。本轮完整重读
`FlowInfo::{findRelTarget,xrefControlFlow,processInstruction}`、`PcodeEmitFd::dump` 和
SLEIGH relative label resolution 全链。

必须落地的边界如下：

- `findRelTarget` 以 source op 的 immutable `SeqNum::time` 加 Const offset，先精确找
  同 address/time 的 op；缺失时只检查 `time - 1` 的 next-instruction boundary，并通过
  out address 返回 machine fallthrough。不得用 Varnode offset 做 machine-address lookup。
- `xrefControlFlow` 对 Const BRANCH/CBRANCH 只标记 internal target 为 basic start 并更新
  `maxtime`；不得把它加入 machine-address work list。非 Const target 才调用
  `newAddress`。
- 无条件 BRANCH 仅在其 time 不小于当前最深 forward relative target 时删除同一条
  instruction 的剩余 ops；CBRANCH 同时保留 internal branch edge 与 p-code fallthrough。
- `processInstruction` 在 xref 前记录 instruction size 和首 op 的 immutable SeqNum，
  并且 machine fallthrough 只入队一次。
- 初始 basic-block 插入必须保留两个 SeqNum 维度：immutable time 用于 relative lookup；
  mutable order 按 locked `BlockBasic::insert` 的执行顺序赋值。Rust 当前单字段模型由
  flow-local post-emission snapshot 保存 time，不把 SLEIGH ABI identity 当作对象 identity。

对应 oracle 使用真实 `0f a2 c3`（CPUID; RET），完整观察 81 ops、186 Varnodes、
33 relative resolutions、49 raw/final edges、34 blocks 和 visited
`ram:0 size=2 first_time=0`、`ram:2 size=1 first_time=78`。计划中的
`FlowInfoSnapshot` 只克隆 post-emission op/edge 引用与值状态，供独立 Rust fixture
序列化；它不缓存 callback `VarnodeData*`，也不改变生产 CFG。runner 已按 immutable
fd、锁定 git archive、isolated Cargo.lock vendor 和 byte diff 起草，但 metadata 的
`PENDING_*` 会 fail closed，直到三份共享源码完成并重算闭包。

## 2026-08-15：`SLEIGH-FLOW-REL-0001` 落地 — relative 分支 → FlowInfo 内部 p-code 边

锁定 oracle：Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。本轮
完整重读 `flow.cc:88-107/115-138/149-179/187-199/204-212/219-248/264-372/383-482/
545-580/785-845/906-1037`、`op.cc:355-372/941-1150`、`block.cc:2258-2289/2625-2631`
与 `flow.hh:58-169` 后，完成如下对齐（替换此前 `UNTESTED` 设计稿）：

- **`VisitStat` 恢复 SeqNum 模型**：`{ first_seq: Option<SeqNum>, size }` 等价
  Ghidra `{ SeqNum seqnum; int4 size; }`（flow.hh:77-80）。`processInstruction`
  在发射后记录首 op 的完整 SeqNum（地址+immutable time，flow.cc:472），
  `target()` 经 `PcodeOpBank::findOp(SeqNum)` 精确解析并按 no-op 指令回退，
  `updateTarget` 用 time-only 等价（address.hh:148 operator==）比较。
- **`findRelTarget` 忠实移植**（flow.cc:149-179）：目标时间 = 源 op 的
  immutable `SeqNum::time` + Const 偏移（uintm wrapping）；先精确查找同地址同
  time 的 op；缺失时只查 `time-1`（branch-to-next-instruction），经
  `visited` 上界回退得到机器 fallthrough 地址并检查 `op_addr < res`；否则报
  "Bad relative branch"。不再用 Varnode offset 做机器地址查找。
- **`xrefControlFlow` 忠实移植**（flow.cc:264-372）：per-instruction `maxtime`
  追踪最深 forward relative 目标；Const 空间 BRANCH/CBRANCH 只把内部目标
  `opMarkStartBasic` 并更新 `maxtime`（不进机器 worklist），relative-to-end 置
  `isfallthru`；非 Const 目标才 `newAddress`。BRANCH/BRANCHIND/RETURN 在
  `getTime() >= maxtime` 时 `deleteRemainingOps`（`opDestroyRaw` 语义，连同
  Varnode 一并销毁）。每个分支后 `startbasic = true`。CALL/CALLIND 的
  noreturn halt 插入后按 Ghidra 的 `--oiter` 重新 xref（插入位置即下一迭代
  索引）。`isfallthru` 终判按最后一个 op 的 opcode。
- **`processInstruction` 忠实移植**（flow.cc:383-482）：发射（`inject_raw_ops_
  single` = `PcodeEmitFd::dump`）→ 记录 VisitStat/首 op SeqNum/STARTMARK →
  xref（可能删尾）→ 仅当 fallthru 时把机器后继入队一次。
- **`fallthruOp` 忠实移植**（flow.cc:88-107）：同指令下一 op（无 STARTMARK）
  优先，否则定位所属指令并 `target(下一条指令)`。
- **`splitBasic` 忠实移植**（flow.cc:983-1017）：按 STARTBASIC 切块、首块注册
  官方入口；每个 op 按 `BlockBasic::insert`（block.cc:2258-2289）的 midpoint
  公式赋 mutable `SeqNum::order`（首 op `2 → 2+0x1000000` 中点 `0x800002`，
  之后每步 +0x800000）；块地址范围按 `setBasicBlockRange`（funcdata.hh:556 →
  block.cc:2625 `setInitialRange`）语义记录。此处现保留完整 `Address`
  空间身份，`stop` 按 `Address::operator<` 扫描块内所有非起始 op 取最大值，
  不再降为 `u64` 或使用最后 op 近似。
- **`collectEdges` 修正**：CBRANCH 先 fallthru 后 branch 边（flow.cc:961-966）；
  BRANCHIND 的 setMark 去重后按 flow.cc:947-956 只清除本次设置的 mark。
- **`generateOps`** 头部补 `clearProperties()`（flow.cc:790）。
- **新增 `FlowInfoSnapshot`**（`snapshot()`）：为 oracle fixture 克隆 post-
  emission 的 op/time、VisitStat 值、relative 解析与 raw edge Arc；不缓存
  SLEIGH callback `VarnodeData*` 身份，不改变生产 CFG。2026-09-25
  （CURLWIRE-CR-F1-A1，LOCKFIX 修法）：relative 遍历的 opcode 过滤与
  `inrefs[0]` 提升收进单一短守卫块，守卫在 `find_rel_target`（内部再锁
  同一 op）之前释放——std RwLock 读读重入不对写者公平；同输入同输出，
  双语料字节恒等验证。

真实 `0f a2 c3`（CPUID; RET）门禁结果：`tools/run_sleigh_flow_relative_oracle.sh`
差分 Rust 与锁定 Ghidra capture（sha256 `7490edf5…`）**逐字节一致**（81 ops /
186 Varnodes / 33 relative 全 internal / 34 blocks / 49 边 / visited 2）。
该门禁只证明本 fixture 的观察闭包；错误路径（BadData/Unimpl/越界/指令上限）、
跳转表恢复、inline/injection 与 SeqNum 残差仍属 `SLEIGH-FLOW-0001`/`INJECT-0001`
等 TODO，flow.rs 整体保持 L2/MISMATCH。

## 2026-08-23：`FLOW-CONTAINEDCALL-0001` checkContainedCall 移植

锁定 oracle 为 Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。完整读取 `FlowInfo::checkContainedCall`
（flow.cc:1357-1405）、其唯一调用点 `generateOps`（flow.cc:813，do-while 循环体内、
jumptable 内循环之后）、`setPossibleUnreachable` 的设置点 `inlineSubFunction`
（flow.cc:1274）与消费点 `generateBlocks`（flow.cc:843-844）后移植：

- **`check_contained_call`**（flow.cc:1361-1405）：逐 spec 扫描 `fd.callspecs`
  （= Ghidra Funcdata 持有、FlowInfo 以引用持有的 `qlst`）：
  - callee 已解析为 Funcdata → 跳过（flow.cc:1367-1368；2026-08-25 起
    `query_call` 经 `fd.symbol_table` 解析并以 FlowInfo 侧 `resolved_funcdata`
    集合（按 spec 的 `op_addr` 键控）承载该判定，见下方
    `FLOW-TAILCALL-OVERTRACE-0001` 节）；
  - 非 `CPUI_CALL`（按 op 当前 opcode）→ 跳过（flow.cc:1369-1370）；
  - visited 覆盖判定用 `BTreeMap::range(..=addr).next_back()` 精确复刻
    `upper_bound` + 前移一步：无 ≤addr 的表项（flow.cc:1375）或
    `start+size <= addr`（flow.cc:1377-1378）→ 跳过；
  - 恰为 visited 指令起点（flow.cc:1379）：`Possible PIC construction` header
    warning → `op_set_opcode(BRANCH)` → `target(addr)` 与 call 后继 op 打
    STARTBASIC（`opMarkStartBasic` = funcdata.hh:480 置位 startbasic）→
    `new_code_ref` 恢复 input(0) → 从 callspecs 删除该 spec；
  - 落在已访问指令中间（flow.cc:1400-1402）：仅
    `Call to offcut address within same function` warning。
- **erase-后继跳过 quirk**：Ghidra 的 `iter = qlst.erase(iter); if (iter ==
  qlst.end()) break;` 加 for 头部 `++iter` 意味着紧随被转换 spec 之后的
  spec 在本轮**不被检查**。Rudra 以相同索引步进复刻（fixture `multi` case
  锁定该行为）。
- **`generate_ops` 接线**（flow.cc:796-821）：重构为 do-while 形状——jumptable
  内循环（`!branchinds.is_empty()`）之后无条件执行 `check_contained_call()`，
  即使首轮无 BRANCHIND 也运行一次，对齐 Ghidra 至少执行一次的 do-while 语义；
  退出条件保持既有 multistage 近似（`checkMultistageJumptables` 仍未移植）。
- **possible_unreachable 消费端**（跨域）：`setPossibleUnreachable` 由
  `inlineSubFunction`（flow.cc:1274）设置、`generateBlocks`（flow.cc:843-844）
  消费 `data.removeUnreachableBlocks(false,true)`。Rudra 的
  `generate_blocks` 已有 `has_possible_unreachable → remove_unreachable_blocks`
  接线；`remove_unreachable_blocks` 本体在 funcdata.rs 的对齐深度属 flow 审计
  另一项（见报告登记的 TODO 建议），本租约未触碰。

验证：`cargo test --lib flow` 57/57 全绿；全量 --lib 除两个预存在失败
（`test_infer_params_and_return_type`/`test_type_propagation`，基线 e959d08
同样失败，类型推断子系统，与本改动无关）。逐函数 oracle 差分见
`tools/run_flow_containedcall_oracle.sh`。

### 2026-08-23（续）：erase-后继跳过的单一自增修正

修正 `check_contained_call` 首版的一个移植缺陷：erase 后多写了一个
`iter += 1`，使每次转换前进两步、索引越过表尾（fixture `multi` case 直接
panic）。Ghidra 每个循环体执行**恰好一次**自增（for 头部 `++iter`，
flow.cc:1365），该唯一自增本身就是"跳过被删元素后继"的实现。修正后
`tools/run_flow_containedcall_oracle.sh` 11/11 MATCH（`multi` 双侧第二个
call 均保留为 CPUI_CALL + callspec）。

## 2026-08-23：`FLOW-INJECT-WIRING-0001` P-code 注入接线

锁定 oracle Ghidra 12.0.4 commit `e40ed130…`。完整读取 `FlowInfo::doInjection`
（flow.cc:1177-1208）、`injectUserOp`（1212-1236）、`injectSubFunction`
（1284-1303）、`injectPcode`（1327-1355）、`generateOps` 两处 `hasInject()`
门（794-795/819-820）、`xrefControlFlow` 的 CALLOTHER 臂（344-348）、
`checkForFlowModification`（639-640）以及 emit 桥 `PcodeEmitFd::dump`
（funcdata.cc:878-908）后接线：

- **`xref_control_flow` CALLOTHER 臂**（flow.cc:344-348）：
  `arch.userops.get_op(in(0) 常量).is_injected()` → `injectlist.push`。
  Ghidra 裸解引用 getOp；Rudra 对 Option 缺失按"非注入"守卫。
  `xref_control_flow_at` 扩展为返回（最后处理 op, isfallthru）并透传
  `inject_fc`（Ghidra fc 参数，供 setupCallSpecs/setupCallindSpecs 的注入
  循环检查，flow.cc:337/341）。
- **`generate_ops` 两处接线**（flow.cc:794-795/819-820）：phase-1 fallthru
  扫尾后与 do-while 体内（checkMultistageJumptables/tablelist 回填之后、
  循环条件之前）各 `if hasInject() inject_pcode()`。
- **`do_injection` 真实 emit 桥**（flow.cc:1177-1208）：签名改为
  `(payload, icontext, op, inject_fc)`；`payload->inject(icontext, emitter)`
  → `InjectPayload::inject`（pcodeinject.rs）+ `inject_raw_ops_single`
  （= `PcodeEmitFd::dump`，每个注入 op 带 baseaddr，对齐
  `cacher.emit(con.baseaddr,…)`）。xref 复用完整 `xref_control_flow_at`；
  startbasic 后继标记改用 dead-list 直接后继（`++getInsertIter()`，
  非 fallthruOp）；`markIncidentalCopy`/`moveSequenceDead` 由 payload 的
  incidentalCopy 属性守卫并改走流期容器（`move_sequence_flow`/
  `mark_incidental_copy_flow`——op.rs 版本作用于 action 期 deadlist，
  流期为空表，见 PcodeOpBank::create 注）；最后 updateTarget+opDestroyRaw。
- **`inject_user_op`**（flow.cc:1212-1236）：userop 索引（in(0) 常量）→
  `UserOpManage` Injected 描述 → inject_id → `PcodeInjectLibrary` payload；
  icontext 按 op 地址与 in[1..]/output 填充后 doInjection(fc=null)。
- **`inject_sub_function`**（flow.cc:1284-1303）：icontext 带
  calladdr=entry；doInjection(fc)；paramshift≠0 → `qlst.back()`（= callspecs
  末位）set_paramshift。
- **`inject_pcode`**（flow.cc:1327-1355）：自足签名 `(&mut self)`；逐槽
  nullify；CALLOTHER→injectUserOp；CALL/CALLIND→callspec（typed annotation / exact
  PcodeOp owner lookup）→ isInline → injectId≥0：injectSubFunction+
  `Function: <name> replaced with injection: <fixup>` warningHeader+
  deleteCallSpec（inline/query/name/error-channel consumer 仍为 `CALLSPEC-0001`；
  Rudra callspec 无名时 warning 以 entry 地址拼写）；
  否则 inlineSubFunction+`Inlined function`+deleteCallSpec；收尾
  injectlist.clear()。
- **`fixture_queue_inject`**（RUDRA-GLUE，snapshot() 同类 fixture 观察 API）：
  锁定的 x86-64 SLEIGH 声明无 userop，双侧都无法用真实指令发射 CALLOTHER；
  C++ fixture 直写私有 injectlist，Rust fixture 经此钩子镜像。

残差（2026-08-25 更新）：`query_call` 已实现 queryFunction 解析切片
（`fd.symbol_table` + `set_funcdata` + `resolved_funcdata` 集合，见
`FLOW-TAILCALL-OVERTRACE-0001` 节），但 `copyFlowEffects` 的 inline/noreturn
旗标拷贝仍无数据源（FLOW-NORETURN-DATA-0001：CALLFIXUP 经真实 flow 触发
仍不可达，只能 CALLOTHER 路径）；
`inline_sub_function` 实克隆仍 TODO（inlineFlow）；wrapOffset/JCurSpaceSize
见 pcodeinject.md。测试：`cargo test --lib flow pcodeinject` 28 绿
（subflow 既有崩溃与 base 6ee34dc 相同，非本租约）。

### 2026-08-23（续）：`flow_inject_1204` oracle 门禁 MATCH

`tools/run_flow_inject_oracle.sh`（pin-base schema 2，oracle 锁定 commit
`e40ed130…`，Rudra 源 pin `835456b` + flow.rs/pcodeinject.rs 双 overlay）
三 case 双侧 stdout 逐字节一致（sha256 `6effd232…`，stderr 空，diff 空）：

- `inject_cpuid`：真实生产路径——x86-64 SLEIGH 对 `cpuid` 指令发射
  CALLOTHER(44)，经公开 `UserOpManage::manualCallOtherFixup` 注册 fixup 后
  `followFlow` 即可让 **xrefControlFlow CALLOTHER 臂（flow.cc:344-348）在双侧
  自行排队并展开**（无需 fixture 种子）；81 op 流中 CALLOTHER(44) 被销毁、
  注入 COPY 就位、其余 CALLOTHER(45+) 保留；
- `inject_add`：种子路径（合成索引 2001，越过引擎 1756 项 userop 表），
  INT_ADD 替换（const 掩码 + 操作数替换 + moveSequenceDead 落位）；
- `inject_label`：带内部条件分支的 payload（label 相对解析
  `labels[id]-calling_index`、注入后 xref 的 block 拆分、多 op move）。

LOAD/STORE 空间引用常量按 containedcall fixture 同规则投影为 `spc:<name>`。
覆盖率 6/9 MATCH；残差 `CALLSPEC-0001`（queryCall→copyFlowEffects 缺位，
CALLFIXUP 触发不可达）与 `INJECT-0001`（inlineFlow 克隆）登记于
`flow_inject_1204.metadata.json`。发现并登记：containedcall runner 的
spec pin `34a3febf…` 在本仓库不可解析（本 fixture 改 pin 已核实的
identical-asset commit `87aaef2`）。

## 2026-08-25：`FLOW-TAILCALL-OVERTRACE-0001` queryCall 解析与 PIC 误发

锁定 oracle 为 Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。
完整读取 `FlowInfo::queryCall`（flow.cc:656-672）、`checkContainedCall`
（flow.cc:1361-1405）、`checkForFlowModification`（flow.cc:636-651）、
`Funcdata::followFlow` 的全程无函数体边界语义（funcdata.cc:161-163 以
space 全域 baddr/eaddr 调用）后修复 curl `glob_word` 5 处
`Possible PIC construction` 误发（golden 0 处）：

**根因**（双侧行号）：Ghidra flow **没有函数体边界**——尾跳（curl 中
`0x4b4c jmp glob_range`/`0x4b7b jmp glob_set`）被忠实跟进被调函数体，
`visited` 因此含被调者入口与函数体，这是正确行为；Ghidra 不误发的机制是
`setupCallSpecs` → `queryCall`（flow.cc:660 `queryFunction(entry)` → 662
`setFuncdata`）解析出 callee Funcdata，使 `checkContainedCall` 的
`fd != 0 continue`（flow.cc:1367-1368）跳过这些调用。Rudra 的
`query_call`（flow.rs）此前是 CALLSPEC-0001 no-op、扩展 trait
`has_funcdata` 恒 false，该守卫从不触发——尾跳污染进 visited 的合法调用
（`call glob_word` 递归 ×3、override 转换出的 CALL ×2）全部误判为 PIC，
CALL→BRANCH、callspec 被删，引发 10 级指针链与返回地址常量 store。

**修复**（仅 src/flow.rs）：

- `query_call` 实现 queryFunction 切片：`fd.symbol_table`（驱动侧
  CALLSPEC-DRIVER-0001 确立的 queryFunction 前端等价物，与 `link_call_specs`
  同一边界）命中即 `set_funcdata(name, entry)`（fspec.cc:4949-4960 可观察
  切片：入口 + 显示名）；
- FlowInfo 新增 `resolved_funcdata: BTreeSet<u64>`（按 spec `op_addr` 键控）
  承载"已解析"观察，`check_contained_call` 以集合成员测试实现
  flow.cc:1367-1368 守卫（RUDRA-GLUE：Rudra FuncCallSpecs 无 per-spec
  callee Funcdata 存储，fspec 侧缺口；集合仅在 query_call 写入、
  同一 FlowInfo 生命周期内消费，与 Ghidra spec 内指针同寿）；
- 扩展 trait `is_inline`/`is_no_return` 从硬编码 false 改为委托
  `FuncProto::is_inline()`/`is_no_return()`（fspec.hh:1348/1349）；
  删除死掉的 `has_funcdata` 适配器。

**残差**（FLOW-NORETURN-DATA-0001，登记于 fixture metadata）：Ghidra 的
"Non-Returning Functions - Known" 分析器按名字把 `exit` 类函数标 no-return，
`copyFlowEffects` 拷贝后 `checkForFlowModification`（flow.cc:641-647）插
artificialHalt 截断 fall-through；Rudra 前端尚无该数据源，函数体以
`call exit` 结尾时仍会顺序流进下一函数体（curl glob_word 344 vs golden
323 字节的过度追踪来源）。flow.rs 侧 is_no_return 委托已就位，等驱动侧
喂数即生效。`copyFlowEffects` 的 inline 旗标拷贝同属该数据缺口。

**双侧 fixture**：`tests/oracle/flow_tailcall_overtrace_1204.{cc,rs}` +
`tools/run_flow_tailcall_overtrace_oracle.sh`（bfd 头/库 sha 锁定同
containedcall）。case `tailjmp_symbol`（A 条件尾跳进 B + B 递归 call A +
A 直接 call B，双侧经真实 ELF 符号解析）锁定 fd 守卫跳过：2 spec 存活、
0 警告、被调体作为 caller 的块/ops 可见（visited 污染本身是忠实行为）；
case `tailjmp_offcut_control`（call 到已访问非符号内部起点）锁定
CALL→BRANCH + `pic:6` 转换仍会触发。双侧 61 行 stdout 逐字节一致
（`expected_stdout_sha256 f9153a94…`）；对 pre-fix 树该 fixture 判
MISMATCH（calls=1 + pic:15 误发），证明其锁定本修复。

**语料验证**（真 A/B：同树 ba910ed ± 本 patch，全量 curl 124 函数）：
`Possible PIC` 5→0；`glob_word` skeleton diff 176→144；全量 skeleton
2409→2377；defects 2→2（helpf/file2string.part.0 不变）、numbering 1→1
（match_url 预存在）——零新增缺陷。
## 2026-08-23：`FLOW-TRUNCATED-0001` FlowInfo 克隆与 raw-op 生命周期

新增 `TruncatedFlowState`，作为 Rust 借用边界上的值快照；它保存锁定
`FlowInfo` clone constructor（`flow.cc:52-76`）实际读取的
`unprocessed`、`addrlist`、`visited`、instruction 计数/上限、range、flags、
inline head/base。`FlowInfo::from_truncated_state` 保持这些容器原顺序，按目标
Funcdata base 重置 min/max，重新查询目标 override 的 flow-override 状态；存在
inline head 时，recursion 集合指向克隆后的 inline-base 内容。lifter 改为可选，
因为 partial clone 只消费既有 raw p-code，不解码新机器指令。

raw flow 现在在 block 生成前统一停留于 `PcodeOpBank::deadlist`。控制流交叉引用、
edge 收集、injection 序列移动和 branchind 收集都读取该容器；
`split_basic` 按 dead-list 顺序逐 op 调用 `mark_alive`，紧接着插入当前
`BlockBasic` 并赋 block order。这一点对应 `flow.cc:983-1017` 中每次循环的
`data.opInsert`，没有在 `generate_blocks` 入口批量激活的额外阶段。

`split_basic` 与 `generate_blocks` 返回 `crate::error::Result<()>`。后者在
`fillin_branch_stubs`、`collect_edges`、block 创建和 dead→alive 转换之前，以只读
方式验证 `fillinBranchStubs` 结束时首 op 是否会带 `STARTBASIC`；不满足时传播精确
`Lowlevel("First op not marked as entry point")`。直接调用 `split_basic` 也保留同一
守卫。因此错误路径不会产生 block、parent/order、alive-list 或 edge 突变；公开
`follow_flow` 同步返回并传播该 `Result`。

`truncated_flow_1204` 已证明 clone 后 op/tree/list/block 的投影及首 op 缺少
`STARTBASIC` 的异常文本/错误后生命周期状态与锁定 oracle 逐字节相同。异常仍保留
Oracle 在进入 `generateBlocks` 前已经完成的 raw clone，但不会开始 block 生命周期，
且目标不会误置 `BLOCKS_GENERATED`。clone constructor 的全部地址状态、inline
recursion 与 injection 分支尚未逐分支驱动，仍标 `UNTESTED`；FlowInfo 模块保持
L2，不沿用本文早期“Phase 完成”文字推断全模块对齐。

2026-08-24 的切片 B 另增单块地址序列 `[0,64,32]`：Ghidra 与
Rudra 都保留默认 code space 身份，范围为闭区间 `[0,64]`，
从而同时锁定完整 `Address` 传递、遍历边界与“块内最大值而非最后
op”。`BlockBasic` 多范围 copy/merge/marshal 仍归 `BLOCKBASIC-COVER-0001`，
本 fixture 对该部分保持 `UNTESTED`。

## 2026-08-24：FLOW-SHAREDRETURN-0001 — lift 后、xref 前消费 FlowOverride

锁定 oracle 为 Ghidra 12.0.4 `e40ed130…`：`FlowInfo` 两个构造器在
`flow.cc:26-42/52-76` 缓存 `Override::hasFlowOverride()`；
`processInstruction` 在 `flow.cc:407-418` 记录新 op 边界并查询当前指令地址，
在 lift 完成后由 `flow.cc:466-477` 标记首 op、调用
`Funcdata::overrideFlow`，随后才进入 `xrefControlFlow`。Rust 现在保持相同
生产顺序：

- `FlowInfo::new` 与 partial-clone constructor 都在构造时缓存
  `localoverride.has_flow_override()`；
- `process_instruction` 在 lift 前做精确地址查询；
- 新 raw op 仍处于 dead-list 时调用 `override_flow`，然后 xref 才据改写后的
  CALL/RETURN 建 callspec、终止流并决定是否排队原跳转目标；
- `generate_ops`、`fallthru`、`process_instruction` 现在传播
  `crate::error::Result`，因此 `overrideFlow` 的 LowlevelError 不再被吞掉；
- instruction-limit 分支保留 oracle 的统一 tail：先插入 artificial RETURN，
  再记录 dead-list 边界、查询 override、继续 lift。该边界已按源码实现，但专属
  fixture 尚未驱动，覆盖状态仍为 `UNTESTED`。

元数据来源分开记录，不互相冒充：

- Program 路径由 Java `SharedReturnAnalysisCmd` 写 Instruction flow override；
  仓库既有 `program_flow_metadata_1204` fixture 是该来源的真实 Program 证据；
- standalone curl 路径从 ELF STT_FUNC entry/body、relocation-derived PLT entry
  与 iced-x86 direct unconditional near jump 构造“唯一 ELF owner + 已知目标入口”
  子集。它不实现 Java 的 contiguous-function discovery、ownerless/discontiguous
  Program body、Program-added multi-flow reference、已有 Program override 或
  conditional-option=true 分支。

`flow_sharedreturn_process_1204` 双侧 fixture 的数值/op-identity 投影覆盖：

- `hugehelp@0x4a4f -> 0x2320` 与
  `progressbarinit@0x49e7 -> 0x22f0`：原 BRANCH 对象/SeqNum 保持身份，改为
  CALL；其后紧邻 RETURN(const size=1,value=0)；原目标不访问，OOB/unprocessed
  均为 0；
- `myprogress@0x365e -> 0x3539`：map 非空但 site query 为 NONE，普通函数内
  BRANCH 保持，目标仍访问；两侧同时保留该函数另一个既有尾边界
  `oob=1/unprocessed=1`。

curl 小范围 A/B 的生产收益是：`hugehelp` callspec/puts `5 -> 6`，
`progressbarinit` callspec `2 -> 3`、`free` `0 -> 1`，两个 shared-return site
的 OOB 警告消失。函数级 `compare_ghidra` 为 defects=0、numbering=0；字符串
呈现与类型/结构传播仍有 skeleton 残差。

状态保持 `MISMATCH`，且 runner 不归一化两类决定性差异：

- C++ fixture 的指令/override/op 地址带 default RAM `AddrSpace`，Rust
  fixture 与当前 driver 的 `Address::new` 是 null-base；地址空间属于输入和对象
  状态，因此 `site_space=ram` 对 `site_space=null` 由
  `ADDRESS-PHASE2-CLOSURE-0001` 跟踪；
- callspec identity 切片现在由 annotation 的 typed `Weak` 找回 qlst 中同一个 owner，
  再以 callspec → exact op 的 `Weak` 和 `Arc::ptr_eq` 核对 CALL；raw diff 的
  `pointer_identity/callspec_same_op` 已为 `MATCH`。这只关闭身份切片，完整 fixture
  仍受上述地址域差异及 `FLOW-SHAREDRETURN-0001` 约束。

仅数值地址、primary object/SeqNum、dead-list 顺序与流状态的选择性投影相同；不得
据此宣称完整 FlowInfo、地址域或 Program producer 已 MATCH。

### 2026-08-24：CALLSPEC-IDENTITY-D0 setup/delete identity

- direct `setup_call_specs` 先以 exact `PcodeOpRef` 构造 callspec，建立稳定
  `Arc<RwLock<_>>` owner，再把携带 typed `Weak` 的 FSPEC annotation 安装到
  CALL input(0)，最后把同一个 owner 放入 qlst。构造器因此能在替换 input(0)
  前捕获原始直接目标；不会用 vector index 或指令地址重建身份。
- indirect setup 同样保存 callspec → exact CALLIND 的 `Weak`；只有 override
  确实把它转成 direct CALL 时才用 typed FSPEC annotation 替换 input(0)。
  deindirect 及后续流处理都保留同一个 owner。
- injection/contained-flow 删除现在携带 owner `Arc` 并以 `Arc::ptr_eq` 在 qlst
  中定位；vector 位移不会误删相邻 callspec。成功删除路径的身份与突变相同；找不到
  owner 时，Ghidra 抛 `LowlevelError("Misplaced callspec")`，Rust 当前是同文本
  `panic!`，专用 fixture 未覆盖该错误分支，因此它仍是 `CALLSPEC-0001` 的
  `MISMATCH/UNTESTED`，不能宣称异常通道相同。所有 lookup 统一走 typed annotation
  快路径或 callspec → exact op 回退，不再按 `op_addr`。
- 下游读取通过短生命周期 read/write guard 或字段快照完成，避免 guard 跨越
  Funcdata 突变。`callspec_identity_lifecycle_1204` 覆盖 D0 身份投影；模块仍为
  `MISMATCH`：`AddressSpace::Iop` 暂代 `IPTR_FSPEC`
  （`TYPEOP-FSPEC-SPACE-0001`），本阶段不接 TypeOp getter、PrintC typed
  callspec consumer、StringManager；entry-offset shadow 仅保住 legacy PrintC
  消费者，并不关闭 codec 差异。既有地址空间和 FlowInfo 残差也不升级。上文历史
  `pointer_identity/address_lookup` 差异由本地基修正，但不使旧 fixture 的完整
  对象投影自动成为 MATCH。

### 2026-08-25：CALLSPEC-NORETURN-WIRE-0001 段(b) flow 侧 noreturn/inline 接线

四个接线点（仅 src/flow.rs，oracle 全文核对 flow.cc:636-772）：

- **query_call 的 copyFlowEffects**（flow.cc:660-664 完整形态）：queryFunction
  （`fd.symbol_table`）→ `set_funcdata`（flow.cc:662）→
  `if (!fc.has_model() || callee_proto.is_inline()) fc.copy_flow_effects(proto)`
  （flow.cc:663-664，one-way 旗标覆写）。callee `FuncProto` 来自新 FlowInfo 字段
  `callee_func_protos: BTreeMap<u64, FuncProto>`（按 callee 入口地址键控）——
  Ghidra 侧该数据在符号库 Funcdata.funcp 里（"Non-Returning Functions - Known"
  分析器生产）；Rudra 流时无 per-callee Funcdata，驱动侧经
  `follow_flow_with_callee_protos`（`follow_flow` 以空表委托）喂数，
  生产数据源归 FLOW-NORETURN-DATA-0001。表经 `TruncatedFlowState` 随克隆传递
  （Ghidra 的克隆共享同一符号库）。
- **check_for_flow_modification 的 halt 插入改为 dead-list**：原实现误用
  `fd.op_insert_after`（funcdata_op.cc:373 的 alive `opInsertAfter`），halt 被
  mark_alive 拉出 deadlist，xref 的 `--oiter`（flow.cc:337）取不到它，指令尾
  fall-through 判定仍看到 CALL → fall-through 照常入队，noreturn 截流失效。
  改为 `fd.obank.insert_after_dead`（funcdata.hh:460 `opDeadInsertAfter` 薄包装
  的逐行镜像）；`truncate_indirect_jump` 的 artificialHalt 同改（flow.cc:767）。
  该缺陷由双侧 fixture case 1 锁定（Ghidra 删除 addr=5 的 RET ops，Rudra 修复前
  仍过度追踪）。
- **truncate_indirect_jump 重塑为 Ghidra 原形**：参数从自创 `fail_mode: u8`
  重编码改回 `jumptable::RecoveryMode`（消除 `FailNormal as u8 = 1` 误落
  fail_callother 臂的映射 bug）；四臂与 flow.cc:730-756 一致；先
  `setup_callind_specs(op, None)`（flow.cc:736）建立 callspec，fail_callother 臂
  `fc.set_no_return(true)`（flow.cc:747）+ "Does not return" warning
  （flow.cc:748）；三条 warning 从 eprintln! 改 `fd.warning`（commentdb，与
  Ghidra data.warning 同通道）。noParams 臂 setInternal/defaultfp
  （flow.cc:757-762）已由 FTSINCRMERGE 车道接线（2026-09-29，见下节）；
  setBadJumpTable（flow.cc:754）已由
  FLOWSET 车道接线（见 2026-09-25 节），输出消费者归 coreaction 车道。
- **恒 false stub 清理**：扩展 trait `is_inline`/`is_no_return` 删除（fspec.rs
  继承面已提供同名 inherent 委托，原实现已被遮蔽为死代码），过时 RUDRA-GLUE
  注释一并修正；`test_hard_inline_restrictions` 的
  `let inline_noreturn = false; // TODO` 改为
  `inlinefd.get_func_proto().is_no_return()`（flow.cc:1136，无内部 caller，
  生产不可达）。

`check_for_flow_modification` 通路确认激活：`xref_control_flow_at` CALL/CALLIND 臂
→ `setup_call_specs`/`setup_callind_specs` → `query_call` +
`check_for_flow_modification`（flow.cc:336-342），halt 落在 call 索引处由下一轮
迭代处理（Ghidra `--oiter`）。

**双侧 fixture**：`tests/oracle/noreturn_wire_b_1204.{cc,rs,metadata.json}` +
`tools/run_noreturn_wire_b_oracle.sh`（锁定 oracle 身份 + Rudra base 快照 +
src/flow.rs overlay 三件套钉扎）。5 case 双侧 41 行 stdout 逐字节一致
（`expected ghidra_stdout_sha256 ebf3c910…`）：noreturn callee → spec 位传播 +
halt 0x1000000 插入 + "Subroutine does not return" + 下游 RET 指令不再访问；
inline 自调用 → inline 位传播 + injectlist 入队 + 自递归拒绝
"Could not inline here"（spec 存活，避开未移植的 inlineFlow 克隆机）；
plain callee → 全 0 无 halt 无 warning；truncate fail_callother → CALLIND 改写 +
callspec noret=1 + "Does not return" + noreturn halt；copy_flow_effects 单向
覆写生命周期四阶段。C++ 侧 callee 旗标经
`queryFunction(name)->getFuncProto().setNoReturn/setInline` 直接置位（分析器生产
通道的 fixture 等价物）；truncate/copy case 经显式模板实例化窃取私有成员
（C++11 [temp.explicit]/12）直接驱动 `FlowInfo::truncateIndirectJump`。

**生产影响**：生产路径无任何 callee proto 喂入（表恒空）且
`truncate_indirect_jump` 在 curl 语料 0 次触发（旧诊断 eprintln 0 命中），curl
E2E 零变化。hasModel（truncate case 的 setInternal 分歧）与 spec name
（Ghidra CALLIND spec 名按地址派生 vs Rudra 继承 caller funcp 名，既有
`setup_call_specs` 构造 quirk）在 fixture 中显式不投影并在 metadata 登记。

### truncate_indirect_jump noParams 臂补全 + early_jump_table_fail 死表窗口（2026-09-29，FTSINCRMERGE 车道）

MCENSUS4-SQLITE-FTSTYPING-0001 修复的两个 src 侧改动（第三处在 userop.rs/
gen 驱动，见对应文档）：

- **`Funcdata::early_jump_table_fail`（funcdata.rs）改走 deadlist**：原实现
  用 `obank.alivelist` 定位 BRANCHIND 的回溯起点，而 oracle 的
  `iter = op->insertiter; startiter = beginOpDead()`
  （funcdata_block.cc:564-565）是 **dead 表窗口**——recoverJumpTables 时刻
  （FlowInfo::generateOps，flow.cc:792-814；splitBasic 的 markAlive 在
  flow.cc:1013 之后）所有 lift op 都在 deadlist 里。Rudra 的 flow 阶段以
  "recovery-time dead-cycle" 复现了同一生命周期，但本函数却查 alivelist →
  `position()` 恒 None → `unwrap_or(0)` → 窗口为空 → 恒返回 Success。
  后果：`ud2`（SLEIGH 语义 `uniq = CALLOTHER invalidInstructionException();
  goto [uniq]`，.sla 原生形态）的 BRANCHIND 永远进 fail_normal
  （"Too many branches"）而非 fail_callother，truncate 走 badjumptable 臂
  （CALLIND 带 RAX 返回值 + UNRECOVERED_JUMPTABLE 命名），函数返回型被
  CALLIND 的 uint8 RAX 污染（golden=int4）。修复=按 Ghidra 原形查 deadlist。
- **`truncate_indirect_jump` noParams 臂（flow.rs）补全**：flow.cc:757-763
  的 `fc->setInternal(glb->defaultfp, void) + setInputLock/setOutputLock`
  从 TODO(CALLSPEC-0001) 落地为实装（`prototype.set_internal(defaultfp,
  void)` + 双锁；`set_internal` 自带 `if model==0 setModel(m)` 守卫保持
  预绑模型不动）。该臂使 func_link_output 的 locked-void 门
  （coreaction.cc:1540-1542）不给 CALLIND 建输出 varnode、
  ActionActiveReturn 的 isOutputActive 检查跳过 trial 恢复——CALLIND 无
  返回值 + noreturn halt，函数返回型回到真实 `return` 路径（int4）。

**A/B（sqlite 镜面，基 f3ae64e3）**：sqlite3Fts3Incrmerge 129→3（−126）；
同族连带 sqlite3Insert 14→4 / sqlite3ColumnsFromExprList 12→0 /
sqlite3GenerateColumnNames 12→0 / sqlite3MemoryBarrier 4→0；全语料
1479→1315（−164），1385/1385 matched，零回退。残差 3 行 =
func_0x0006a390/0x0006a150 调用输出宽度（Rudra RAX-8+SUB84 物化 vs
golden EAX-4 直出，heritage 输出 trial 宽度仲裁域，归
MCENSUS4-CASTSHAPE-RESID-FIVE-0001 注记，语料内同形 13 站点）。

### generateBlocks 的 removeUnreachableBlocks 参数（2026-08-25）
- 调用改为 `remove_unreachable_blocks(false, true)`（issuewarning=false，
  checkexistence=true 主动扫描），对齐 flow.cc:844。

## 2026-08-26（TRI2-CALLOUT-ASSIGN-0001）：callspec 播种改为 FuncProto 默认构造态

- `setup_call_specs`/`setup_callind_specs` 不再 `fd.funcp.clone()` 播种新
  callspec，改用 `default_call_spec_proto()`：镜像 C++ `new FuncCallSpecs(op)`
  的基类默认构造（fspec.cc:4924-4925 → FuncProto::FuncProto() fspec.cc:3778-3786，
  flags=0——无 input/output/model 锁、model=null、空参数表）。
- 根因：继承 caller 的（可能 DWARF/输出锁定的）`fd.funcp` 使每个未知 callee
  误得 output-lock，`ActionFuncLink::funcLinkOutput` 走 locked 分支
  （coreaction.cc:1538）跳过 `initActiveOutput()`（:1571-1572），active return
  recovery 被压制——progressbarinit `curl_getenv` 因此丢输出成裸语句形。
  真实签名后续经程序库边界到达（driver locked-signature 安装 /
  `ActionDefaultParams` coreaction.cc:2311）。
- 既有登记的 "CALLIND spec 名继承 caller funcp 名" 构造 quirk 随本修复消解
  （默认构造 name 为空，setFuncdata/queryCall 边界另案 CALLSPEC-0001）。
- 2026-08-30 CALLSPEC-DRIVER-0001：`default_call_spec_proto()` 提升为 `pub(crate)`——
  `Funcdata::inject_raw_ops` 的 linear-scan driver 路径 flow-time callspec 锚定
  （见 docs/api/funcdata.md 的 inject_raw_ops 条目）复用同一默认构造态，避免出现
  第二份 FuncProto::new 副本漂移。

## 2026-09-22（RUGRA-FLOW-MIRROR-0001）：`follow_flow_range` 完整形参入口

- 新增 `pub fn follow_flow_range(fd, lifter, baddr, eaddr, callee_protos)`：
  镜像 `Funcdata::followFlow` 的完整 `(baddr, eaddr)` 形参形态
  （funcdata_op.cc:756-783）——调用方给出约束范围，walk 本身永远从函数自身
  entry 播种（flow.cc:791 `addrlist.push_back(data.getAddress()`），
  baddr 只约束 `new_address` 目标（flow.cc:222）。oracle 单函数 harness 与
  regen_ghidra_golden.py:388 传 `(code:0, code:highest)`——x86-64 默认 ram
  space 即 `(0, u64::MAX)`——尾跳进低地址 code space 区（PLT）被跟入函数,
  随后 BRANCHIND 经 fail_thunk 路径（jumptable.cc:2304-2320 → flow.cc:727/735）
  截断为 CALLIND + artificial halt。
- `follow_flow_with_callee_protos` 保留原签名并委托
  `follow_flow_range(baddr=entry)`：历史驱动有界形态,既有调用点
  （curl_decompile 默认路径、getstr_stage_snapshot）行为逐字节不变。
- 消费方:curl driver 在 `RUDRA_FLOW_MIRROR=1` 时走
  `follow_flow_range(0, u64::MAX)`（examples 级 env 门控,默认 off）;
  stage projection 的 META `load_mode` 在同一门下发 `single_function_bfd`
  （STAGE_BISECT_SPEC_1204.md D10）。

## 2026-09-22：follow_flow_range 尾部接线 switchOverJumpTables

- `follow_flow_range` 在 `flow.generate_blocks()` 成功后调用
  `Funcdata::switch_over_jump_tables(&*flow.fd, &flow)`（funcdata_op.cc:777-778：
  `flags |= blocks_generated; switchOverJumpTables(flow);` 同位同序）。恢复出的
  跳表地址→出边槽映射（block2addr）在 FlowInfo 借用结束前完成；此后
  ActionSwitchNorm 的 default_block 派生、BlockStruct 阶段的
  `switch_case_basic_coords` isdefault 判定与 label 管道
  （BlockSwitch::finalizePrinting）均消费该数据。

## 2026-09-24：RESIDMAP-PRINTBATCH —— PIC 警告 printRaw 拼写 + partial 克隆基址继承

- flow.cc:1380-1384 的 "Possible PIC construction at <opaddr>: Changing call
  to branch" 警告：op 地址改经 `Funcdata::print_raw_code_addr` 渲染
  （oracle `Address::printRaw`，space.cc:206），替换旧的 spaceless Display
  十六进制形；经 `display_image_base` 传输 canon 驱动的 0x100000 基址差。
- `FlowInfo::clone_function`（partial 克隆）继承源函数的 `display_image_base`：
  partial 的 jumptable LowlevelError 文本（recover_addresses_classified，
  jumptable.cc:2629）与父函数保持同一 oracle printRaw 拼写。

## 2026-09-24（HTTPD-MAIN-WARNUNREACH-JTEDGE-0001）：`recover_jump_tables_injected` —— 线性注入库的后置跳表恢复

- 新增 `pub fn recover_jump_tables_injected(fd) -> Result<usize>`（Ghidra:
  flow.cc:785 `FlowInfo::generateOps`）：为"批量线性注入整库后建块"的驱动
  路径（`Funcdata::inject_raw_ops` + `build_blocks_from_ops`）补上
  followFlow 在 oracle 里内联完成的 generateOps 第二阶段——跳表恢复
  （flow.cc:796-821）以及融合加载无法产生的两个 generateBlocks 尾部可观
  测：BRANCHIND 的逐 case 出边（collectEdges BRANCHIND 臂，flow.cc:933-957）
  与 switchOver 映射（funcdata_op.cc:777-778 → jumptable.cc:2528）。
- 适配差异（全部源自调用方预提升的线性库，逐条注明在函数 doc 注释）：
  - 恢复前把 op 库 mark_dead 进 dead list、恢复后按 dead list 顺序
    mark_alive 复原——`Funcdata::truncatedFlow` 以 `obank.beginDead()` 为
    partial 克隆源（funcdata.cc:797-799），oracle 恢复时点全部 raw p-code
    在 dead list、alivelist 为空；
  - 各基本块首 op 补 STARTBASIC（xref 走查的终态，flow.cc:469-477/570-572；
    `clone_op` 复制该旗标，funcdata_op.cc:621-622），partial 克隆的
    generateBlocks 得以复现源分区；
  - `newAddress`/`fallthru` 提升为 no-op（case 体已在线性库中；oracle 由
    flow.cc:804-809 后置提升）；
  - 恢复 partial 挂载 commentdb 剥离的 Architecture 克隆：coreaction.cc:5490
    把首个 `ActionUnreachable("base")` 注册进 base 组（"jumptable" 组也含
    base），oracle 的 partial 不含 case 体（恢复先于提升）故该动作从不触发；
    线性库的 partial 携带孤儿 case 体，其删块警告会经共享 commentdb（同
    入口地址）泄漏进真实函数输出——剥离恰好中和这一适配伪影通道；真实 fd
    警告（truncateIndirectJump 等）仍走真实 arch；
  - truncateIndirectJump 的人工 halt 以 dead list 位置（insert_after_dead
    的落点）补插进前驱 CALLIND 所在块尾——oracle 由 splitBasic
    （flow.cc:996-1013）完成的块归属；
  - 表目的地无 p-code（越出符号窗）时跳过该出边并整表跳过 switchOver
    （oracle 不可达形态：恢复后目的地必然在库）。
- 新增私有构造 `FlowInfo::from_injected`（lifter=None，同截断克隆构造形态；
  visited 由 op 库合成，baddr/eaddr=(0,u64::MAX) 为 oracle harness 的
  followFlow(code:0, code:highest) 契约）。
- 驱动接线：`examples/httpd_decompile.rs` 默认路径在 `inject_raw_ops` 后、
  action 管线前调用（httpd main 警告 30→0，switch case 体恢复）；MIRROR
  路径与其余驱动不变（curl 字节恒等实测）。

## 2026-09-25（JTEDGE-FUSED-DEST-SPLIT-0001）：case 目的地块中分裂 —— `split_block_at_case_dest`

- 新增私有 `fn split_block_at_case_dest(fd, targ_op, switch_block)`（Ghidra:
  flow.cc:219 `FlowInfo::newAddress`）：`recover_jump_tables_injected` 的
  collectEdges 等价段在逐 case 出边前，对落点不在块首的目的地 op 执行
  oracle 的 newAddress→splitBasic 等价块外科——
  - 目的地 op 补 STARTBASIC（flow.cc:230 `data.opMarkStartBasic(op)`）；
  - `[targ_op..]` 移入新尾块（`create_new_block`，即 `newBlockBasic`），
    尾块 cover=`[dest_addr..尾 op 地址]`、父块 cover 收缩到
    `[原 start..保留尾 op 地址]`（splitBasic 的 per-block range，flow.cc:
    999-1016）；
  - 父块 out-edges 整体移交尾块，配对 incoming 半边原地改指（slot/顺序
    全保——connectBasic 对 oracle 边表的等价终态，flow.cc:1021-1037）；
  - 尾块插到父块后一位保持块表地址序（splitBasic 的 dead-list walk 序）；
  - 出边顺序：先 switch→尾（BRANCHIND 臂表序），后 父→尾 fall-through
    （collectEdges nextstart 臂在死表走查中晚于 BRANCHIND，flow.cc:952-956）；
  - 去重从 per-block 改为 per-op（flow.cc:941-946 的 setMark 语义；分裂后
    每目的地 op 即块首，两级去重等价）。
- 观测（默认脸，本 worktree）：httpd main 的 5 个块中目的地
  （0x2ba9f/0x2bafc/0x2bb0b/0x2bdbe/0x2bdf7）全部分裂，`case 0x45:` 空
  标签消失、case 体与 canon 同形（0x4c 直落 0x45 族见 printc 侧）；其余
  函数零分裂（默认驱动语料）。curl/mirror 不经此路径（0 分裂实测）。
- 修订注记:本节初版提交的 doc 恢复脚本曾引入 follow_flow_range 尾部的
  重复片段(纯注释性死码,同 commit 内已清除;可执行语义零变化——双语料
  输出 cmp 恒等复证)。

## 2026-09-25（FLOWSET / CALLSPEC-0001 移交项 (b)）：truncate `_` 臂 setBadJumpTable 接线

- **Ghidra 锚点**：`FlowInfo::truncateIndirectJump`（flow.cc:727-769）`else`
  默认臂（捕获 `fail_normal`，jumptable.hh:545）在 warning 前执行
  `fc->setBadJumpTable(true)`（flow.cc:754）——"Consider using special name
  for switch variable"。`fc` 来自 flow.cc:736-737 的
  `setupCallindSpecs(op,0)` + `getCallSpecs(op)`，与本函数 Rust 形既有的
  `setup_callind_specs(op, None)` + `find_callspec_for_op` 链同源。
- **接线形态**（src/flow.rs `truncate_indirect_jump` `_` 臂）：`fc_owner`
  解析 `Some` 时 `fc.write().set_bad_jump_table(true)`，随后照 Ghidra
  754→755 顺序发 warning；`None` 守卫沿用 fail_callother 臂先例（Rudra
  Option owner 形态的等价守卫，oracle 侧 fc 经 736 行必然存在）。字段/
  访问器/ctor 初值/clone 携带四件 = CALLSPEC 车道 fspec 数据面
  （fspec.hh:1660/1701-1702、fspec.cc:4945/4974，commit deb2b09b）。
- **触发实证**（httpd 默认脸 MAX_FUNCS=30，基 2008b8e0）：`[JUMPTABLE]
  recovery failed at 0x2daeb mode=FailNormal → truncate`（ap_vhost_
  iterate_given_conn 内 BRANCHIND）→ 临时探针亲证 callspec 解析 `Some`
  且 flag 置位成功后移除；stdout 恰 1 条 "Treating indirect jump as call"
  warning。curl 语料 0 次触发（`Lowlevel` 失败族缺席）。
- **行为面**：`isbadjumptable` 在主管线暂无读者——唯一消费者
  `ActionNameVars::lookForBadJumpTables`（coreaction.cc:2779-2803，
  UNRECOVERED_JUMPTABLE 命名）归 coreaction 域并行车道。故本接线为
  数据流打通件：httpd/curl E2E cmp 亲基线字节恒等（1141/0/0 与
  577/0/0 保持，双跑确定性）、投影银行 391/391、cargo test 1712P/1F
  预存同败、annotations/refs 绿、gcc 审计 104OK/20FAIL=基线。
- **CALLSPEC-0001 ② 桶状态**：ap_vhost 站点（0x2da50 函数、0x2daeb 跳转）
  的 `void(*)()param_2` → canon `code *UNRECOVERED_JUMPTABLE` 改名链现在
  只差 coreaction 消费者（lookForBadJumpTables 读 `isBadJumpTable()`）。

## 2026-09-25（BLOCKSTRUCT-TRUNC-SWITCHEMPTY-0001）：truncate 后重算残块 SWITCH_OUT —— 恢复 oracle 建序终态

- **根因**：oracle 契约里 `truncateIndirectJump`（flow.cc:727-769，跑在
  generateOps 内）**先于** `generateBlocks`，故 splitBasic 的
  `BlockBasic::insert`（block.cc:2285-2288）看到的是截断后 opcode
  （CALLIND/RETURN）——`f_switch_out` 从未置位。结构化期
  `ruleBlockSwitch` 的 cc:1652 `isSwitchOut()` 门拒绝该块，
  `ruleBlockIfNoExit`（cc:1481-1512，子句门 cc:1497 通过）把它吸收为
  无出口 if 子句——canon 因此印 `if (c) { …; return; }` 而无 switch 骨架
  （**机制=容器未建**，非建后清除）。线性注入路径（inject_raw_ops +
  build_blocks_from_ops）先建块后恢复：`insert_op`（block.rs，镜像
  block.cc:2258）在 op 仍为 BRANCHIND 时置位 SWITCH_OUT，truncate 的
  `op_set_opcode`（与 oracle 的 changeOpcode 一样）不触块旗标——残旗标
  存活到 build_copy，`try_rule_switch` 对 sizeout==0 的 Copy 块构造空
  BlockSwitch，打印侧漏出 `switch() {\n}` 空残片（httpd 默认脸唯一站点
  = ap_vhost_iterate_given_conn 0x2da50/0x2daeb，curl 0 触发）。
- **接线形态**（src/flow.rs `recover_jump_tables_injected` truncate 臂后，
  即 2026-09-24 节适配差异清单的新增一条）：truncate 返回后按块内**当前**
  opcode 重算父块 SWITCH_OUT（块内仍有 BRANCHIND → 置位；否则清除）——
  与 `split_block_at_case_dest` 的分裂后重算同形。oracle 语义锚点 =
  block.cc:2285-2288 建序时点读数：mirror 路径（follow_flow_range）截断
  先于建块，本重算不改变其终态（无父块=天然 no-op）；仅注入路径的顺序
  倒置由该重算补偿。
- **验收**（默认脸，基=master c18a4110 亲测）：残片行 `switch() {` 计数
  1→**0**（ap_vhost 函数体 == canon 同形，`--func` 骨架 9→7，余 7 行全为
  PRINTC-BADJT-PARAMSYM-0001 渲染族+while 花括号形态，零 switch 行）；
  httpd **1141→1139**/0/0（−2=残片两行）；curl **577/0/0 字节恒等**（0
  触发路径）；httpd/curl 双跑 stdout cmp 恒等；bank 391/391；cargo test
  --lib 与预存基线同集；annotations/refs 绿。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 2 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-28 — SQLCENSUS-CHARSCAN-BREAKGUARD-0001：block_insert_at_end 补 BlockBasic::insert 的 BRANCHIND 旗标臂

- **根因**：`BlockBasic::insert`（block.cc:2286-2292 尾臂）每次插入 BRANCHIND op 都
  `setFlag(f_switch_out)`。Rudra 的两个插入路径中 `funcdata.rs insert_op` 有该臂，而
  follow_flow_range 建块主路径的 end-append 克隆 `block_insert_at_end`（flow.rs，cc:2258
  注解锚）**漏了**——jumptable 派发 bblock 无 f_switch_out。下游两处消费者穿透：
  `BlockBasic::isDoNothing`（block.cc:2604-2613）的 switch-target 守卫（入边来自多出边
  switch 块且出目标是 join → 不删）读到 isSwitchOut=false → ActionDoNothing 删掉了带真实
  op 的 switch case 臂块（sqlite3VdbeChangeP4 的 e43c0 `mov %rdx,%rsi; jmp sqlite3DbFree`，
  出目标 974d4 双入边 join）。拓扑损失传导：case 边直达 join → 返回分叉后重建
  （ActionReturnSplit nodeSplit → structureReset → blockstructure）图上 switch 提前成
  sink → 迟相 IfNoExit 吞并循环头 H 的出口子句 → 体无法 single-out → ruleBlockWhileDo
  永不触发 → 自环收尾成 BlockInfLoop（`} while( true );` + switch 内嵌守卫）——即
  SQLCENSUS4 §3-S5 的 602 行双孪生 break-guard 族（golden 为 `while( true ){ … break; }`
  溢出语法 whiledo，printc.cc:3001 emitBlockWhileDo 的 hasOverflowSyntax 路径）。
- **接线形态**（src/flow.rs `block_insert_at_end`，ops.push 后）：
  插入 op `is_branch() && opcode==CPUI_BRANCHIND` 时置块 `f_switch_out`——与
  funcdata.rs `insert_op` 的既有臂、以及 2026-09-25 truncate 重算同源同锚
  （block.cc:2286-2292 建序时点读数）。
- **验证**（本道亲测，worktree wt/s5breakguard @ 基 5eff829f）：oracle 侧
  OPACTION_DEBUG harness（锁定 e40ed130 对象树）416 括号全树 dump 证明 oracle 在
  returnsplit 后重建（bracket 278）仍产 Whiledo(overflow)，且 oracle 重建图保有
  e43c0（Rudra 缺）；修复后两孪生 sqlite3VdbeChangeP4/sqlite3VdbeExplain 均呈
  `while( true ) { … break;` golden 形（--func 骨架 401→262，残量=跨族命名/类型）；
  canon curl **54/0/0** / httpd **36/0/0**（=MB30 钉值零回退，httpd md5 c3b4706c
  字节恒等）；镜面五面/bank/tests 见车道终报
  （/dev/shm/rudra-reports/LANE_S5BREAKGUARD_2026-09-28.md）。

## 2026-09-30：dead-list 消费迁 OpId marker（PERF-ARENA-FLIP-0001 (b)）

flow.rs 的 deadlist/alivelist 消费位（deadlist 22 处+alivelist 2 处）从
Vec 形态迁 bank 链 API：`process_instruction`/`do_injection` 的
`num_ops_before`/`first_index` 边界索引改 `Option<OpId>` marker（预注入
dead 链尾 id——oracle 存储迭代器形态，flow.cc:407/1180-1183）；
`xref_control_flow(_at)` 的 usize 索引循环改 OpId 游标链游走（尾臂截断 =
`delete_remaining_ops_after(Some(id))`，flow.cc:240 `oiter`→endDead 形态）；
`dead_list_next`/`fallthru_op` 改 O(1) 存储链前后驱（`dead_next`/
`in_dead`）；flow 本地 `move_sequence_flow`/`mark_incidental_copy_flow`
drain/splice 适配副本删除，委派 bank 单实现（op.cc:1056-1083，
splice_after 退化守卫随冻结原语）。快照消费（collect_edges 等）保持
Vec 快照形态，仅采集面换 `iter_dead()`。canon 双 md5 字节恒等亲证。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。


## BLOCKFLIPW3（2026-10-01）edge-shadow 维护 choke（批 1 配套）

splitBasic 的三处边变异补影子 sync（wave 3, 见 docs/api/block.md）：
mem::take 父块 out 向量后 `sync_out_edge_shadow`；继承块 wholesale 赋值旁
`sync_out_edge_shadow`；逐 target 的 in-half re-point（tail_id）在
target 守卫内 `sync_in_edge_shadow`。零读位迁移（本批）。
