# jumptable.rs — Jump-table recovery API

对应 Ghidra `jumptable.hh` / `jumptable.cc`。**当前状态：🔧 L2
（2026-08-11 锁定 12.0.4 审计）**。Override 的 start-op/trial normalization、
PathMeld 的 SeqNum 归并截断、EmulateFunction loader/LOAD、Basic/Basic2/Assisted
model selection（`JUMPTABLE-SELECTION-0001`）与 SwitchNorm/production
consumption（`JUMPTABLE-PIPELINE-0001`）调用闭包均未闭合；模块仍为 L2，
本专项 overall 为 `MISMATCH`；24-case 双侧已于 2026-08-25 执行
（`BILATERAL_24_CASE_BYTE_IDENTICAL`，covered projection=MATCH，
R2 独立复核 APPROVE）。

## 2026-09-22：JUMPTABLE-PARENTFACTS-0001 — jt_parentfacts 双侧 fixture 衍生的两处移植缺陷修复

`tests/oracle/jt_parentfacts_1204.{cc,rs}`（JumpParentFacts 两通道 B2 fixture，
M1 multistage/usenezmask + P1/P0 兄弟 BRANCHIND 身份）实证两处缺陷：

1. `JumpBasic::find_determining_varnodes` 空点回退（jumptable.cc:586-590）：
   Ghidra 用原始 `op`/`slot` 参数构造单点 meld；Rust 旧实现读
   `path.first().unwrap()`，DFS 栈弹空（全常量叶子树，P1/P0 形态）时 panic。
   修复为克隆原始 `op`（`root_op`）。
2. `JumpBasic::sanity_check` 计数器起点（jumptable.cc:1581）：Ghidra for-init
   `i=1`（entry 0 已由 first!=0 验证）；Rust 旧实现 i=0 起步、循环体内才赋值，
   单条目表（size==1）误判 `return false`（M1 stage1 形态实证）。修复为
   进入循环前置 `i=1`，break 不改 i（此时 i==j 即 Ghidra break 语义）。

验证：双侧 fixture 46/46 记录 byte-identical；`cargo test --lib jumptable`
36/36。检测力：把 JumpParentFacts 快照临时改为 pre-fix dummy（partial=false/
indirect=None）后，M1.stage2 guards 3≠2、P1 guards 3≠6，两通道均被捕获。

## 2026-08-24：JUMPTABLE-PIPELINE-0001 段1 — 模型选择链 / find_normalized 委托 / EMULFN

- **模型选择链（`JUMPTABLE-SELECTION-0001` 关闭）**：`JumpTable::recover_model`
  逐字对齐 jumptable.cc:2254-2285 —— override 重跑（matchsize=0）→ 输入 def 为
  CALLOTHER 时尝试 `JumpAssisted`（matchsize=`addresstable.len()`）→ `JumpBasic`
  → `JumpBasic2`（`initialize_start` 接住 Basic 失败的 pathMeld）。旧的
  Basic→Trivial 回退已删除（Ghidra 的 recoverModel 链里没有 Trivial）。
  返回值改为 `Result<bool, JumpTableRecoveryError>`：`Err` = Ghidra 的
  LowlevelError 从 recoverModel 穿透（不尝试下一模型），`Ok(false)` = 模型拒绝。
- **`JumpBasic::recover_model` 委托 `find_normalized`**（cc:1427 调用形态）：
  `find_normalized(fd, indop.parent, -1, matchsize, maxtablesize)`；readonly
  单入口救援（cc:1212-1231）经 loader `load_value` 真读 LoadImage，
  `DataUnavailError` 按 Ghidra 语义沿 `Lowlevel` 通道上抛。
  **调用契约**（段2 stageJumpTable 落地前的显式假设）：`indop.parent` 必须存在
  且 def 链经 "jumptable" 策略简化——缺块环境 fail-closed 返回 `Ok(false)`，
  不再静默走无守卫 smallest-normal（Ghidra 在该环境是空指针崩溃，从不运行）。
- **`EmulateFunction` 全重写（`JUMPTABLE-EMULFN-0001` 关闭）**：持 `fd` →
  Architecture → loader 桥；`get_varnode_value` fallback 真调
  `getLoadImageValue`（8 字节读 + mask，emulateutil.cc:47），未读过的非 constant
  varnode 缺 loader 时走 typed `DataUnavail`，禁止静默归零；`last_op` 前驱 +
  `execute_multiequal` 按 lastOp 块选入边（emulateutil.cc:100-105）；dispatch
  逐字对齐 `Emulate::executeCurrentOp`（LOAD/STORE/BRANCH/CBRANCH/BRANCHIND/
  RETURN/CALL*/CALLOTHER/MULTIEQUAL/INDIRECT/SEGMENTOP/CPOOLREF/NEW/unary/binary）；
  `emulate_path` 捕获 DataUnavail 转
  `"Could not emulate address calculation at <addr>"`（cc:246-250），BRANCH/
  BRANCHIND/MULTIEQUAL 的 LowlevelError 原文穿透。
- **`JumpModel::recover_model`/`build_addresses` trait 签名改为返回
  `Result`**：`build_addresses` 的 emulate 失败 `?` 传播（`None => 0` 入表已删）；
  `JumpTable::recover_addresses_classified` 的 maxtablesize 改读
  `Architecture::max_jumptable_size`（cc:2626 经 glb->max_jumptable_size）。
- **`JumpTable::set_override`**（cc:2466-2478）新增：override-first 分支的挂接点。
- **`find_smallest_normal` 原地更新 jrange**（cc:1186-1189 语义）：经
  `JumpValues::as_range_base_mut` 基视图改写，`JumpValuesRangeDefault` 的
  extra 机制不再被 take/重装箱抹掉（Basic2 路径的前提）。
- **`JumpAssisted::recover_model` 形状判定对齐**（cc:2095-2110）：去掉发明的
  COPY 链回溯，直接 def==CALLOTHER、numInput>=3、userop 类型==jumpassist、
  其余输入全常量；`JumpAssistOp` 载荷未移植，保守 fail-closed。
- **`JumpBasic::sanity_check` loadFill 语义**（cc:1588-1598）：diff>0xffff 的
  目标先经 loader `load_fill(4)` 验证，可读则继续（旧实现无条件截断 = INVENTED）。
- B2：`tests/oracle/jtpipeline_s1_1204.{cc,rs,metadata.json}` +
  `tools/run_jtpipeline_s1_1204_oracle.sh`（真实双侧执行，8/8 观察行逐字节
  一致，stderr 双空）。模块 projection 保持 `MISMATCH`：stageJumpTable
  partial 环境 / generate_ops 接线为段2/3（`JUMPTABLE-PIPELINE-0001`）。

## 2026-08-24：JUMPTABLE-THUNK-CLASSIFY-0001 — typed recovery failure

- `JumpTableRecoveryError` 保留 Ghidra 的两个异常通道及原始文本：
  `Thunk { message: "Likely thunk" }` 对应 `JumptableThunkError`，
  `Lowlevel { message }` 对应普通 `LowlevelError`；`recovery_mode()` 只把前者
  映射为 `FailThunk`，后者映射为 `FailNormal`，不再把所有恢复失败归成 thunk。
- `JumpTable::sanity_check` 严格按 jumptable.cc:2295-2329 排序：override
  立即成功返回；保存原表长；不可达只置 `partial_table`；仅在地址表恰有一个
  target 时检查 `target == 0` 或 `abs(target - indirect.address) > 0xffff`；随后
  才调用 model sanity；model 返回 false 时抛带精确地址文本的 `Lowlevel`；只有
  model sanity 成功后才比较表长并发出 truncation warning。故 `0xffff` 不抛，
  `0x10000` 抛，多 target（即使含 0 或远地址）不走 table-level thunk 判定。
- `recover_addresses_classified` 对齐 jumptable.cc:2623-2649：直接把
  `build_addresses` 的输出写入成员 `addresstable/loadpoints`，异常前的部分突变
  保持可见；`collect_loads` 只在 sanity 成功后执行 `collapse_table`，失败路径
  保留未折叠 loadpoints。`recover_addresses -> bool` 与
  `try_recover -> Option<JumpTable>` 暂作兼容适配；`try_recover` 已移除
  `catch_unwind`，panic 不再冒充普通恢复失败。
- B2：`tests/oracle/jt_thunk_classify_1204.{cc,rs,metadata.json}` 与
  `tools/run_jt_thunk_classify_oracle.sh` 定义了锁定 12.0.4 的 24 个逐 case
  参数/IR 同构场景：
  zero / near / `0xffff` / `0x10000` / multi；isReachable 的单层 false、
  两层 parent 更新、boolean flip、非零常量、`sizeOut != 2`、非 CBRANCH、
  非常量；override；recoverModel fail / tableSize 0 / collectloads=false /
  recover thunk；success truncate / model reject；同址 3/16/17 项排序边界；
  1-byte 地址空间 wrap 与 multi-space 排序。`model_reject`
  真正经 `recoverAddresses` 驱动并观察 `recover>build>sanity` 后异常、未 collapse
  的 loadpoints；`success_truncate` 观察完整
  `recover>build>sanity>collapse`、表长 warning 及成功 collapse；所有 recover
  case 输出内部 loadcounts 和 build 时两个可选输出指针是否存在。事件中的
  `collapse` 只在 `collectloads=true` 且 `recoverAddresses` 成功返回时记录，并由
  返回后的 loadpoints 证明内部 collapse 已完成；异常与 collectloads=false 路径
  均无 marker。锁定 C++ 输出已生成，当前 Rust source 也通过 31 个 focused
  jumptable tests。历史 runner 曾在 Cargo 成功后、Rust fixture 链接前因
  artifact selector 误匹配 25 个 dependency `root-output` 而停止（已修复为
  depth-2 + `rugra-*` 过滤 + 唯一性断言）。2026-08-25 起 24-case 双侧真实
  执行：stdout 逐字节一致（sha `c4cc2b35…`）、raw.diff 为空、双侧 stderr 空，
  10 个双侧覆盖组 `MATCH`（R2 独立复核含一次完整重跑复现）。
- 双侧现都经 production XML decoder 建立并选中
  `<prototype name="fixture" extrapop="0"><input/><output/></prototype>`，Rust
  fixture 同时把 `max_basetype_size=16`、stack pointer `register:0/8` 钉到
  C++ synthetic Architecture 的值。仍不能把整个 compiler-spec/Architecture
  全局状态称作同输入：Rugra 的 `ProtoModelFull.output` 仍是输入型
  `ParamListStandard`，而 locked Ghidra 使用 `ParamListStandardOut`
（`FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001`）；两侧未被本 24-case 消费的
TypeFactory/instruction registry/symbol scope 也不是同构对象。该输入表示债务
（非执行缺失）限制 fixture 投影不得升级为整函数 MATCH。
- `LoadTable::collapse_table` 的排序比较键只含 `addr`，对应
  jumptable.hh:59 的 `return addr < op2.addr`；`size/num` 不作 tie-break。比较与
  `nextaddr` 都保留完整 `Address`：先按 address-space index、再按 offset 排序，
  地址加法经对应 space 的 `wrapOffset`。fixture 以 index 3/8 的混合地址及
  1-byte space 的 `0xfc + 4 == 0` 固定这两项语义。
- 锁定 oracle 使用 GCC 16.2.1/libstdc++。C++ 标准不规定等价键的 `std::sort`
  排列，而 collapse 后续又读取 `size`，所以排列可见：16 项同址、size 4/8
  交替时走 insertion-sort 边界；17 项时 introsort 的等价组排列会让一项被
  collapse 丢弃。Rust 实现以该锁定 libstdc++ 的 median/partition/introsort/
  heap fallback/final insertion 分支为目标，没有按元素数特判；当前保留的
  fixture 只覆盖 16/17 项阈值和可见等价组排列，heap fallback 仍未有
  独立双侧证据。runner 固定 g++、libstdc++ 二进制及相关 STL headers
  的 SHA-256。
- 生产构造链审计：fresh `recoverAddresses` 中只有
  `JumpBasic::buildAddresses -> EmulateFunction::executeLoad` 产生 load records，
  两参数构造器令每项 `num=1`；同址异 size 仍可由 PathMeld 中不同宽度的 LOAD
  产生。故 16/17 项反例保持生产前置条件（`num` 全为 1），不以任意私有 vector
  冒充生产输入；`num>1` 仅在 collapse 或 decode/clone 后存在。
- runner 只捕获一次 `HEAD` commit/tree，并要求六个租约文件相对该 HEAD clean、tree
  与 stage-0 index mode/OID 一致，再以单次 `O_NOFOLLOW` FD 读取前/后独立
  核对 worktree mode/bytes；原子 comparand 身份是 captured commit blobs，不宣称六个
  live path 存在一个跨文件原子瞬间。metadata、双侧 fixture、jumptable
  overlay、API 文档与 runner 全从捕获的 `commit:path` blob 物化到私有快照，编译
  阶段不再读取 live comparand。runner 的 point-in-time 内容先经独立 FD
  核对，再从该 FD 在外层 cleanup supervisor 下重新执行；这里的信任边界包含
  runner 初始入口、内核与本机 root-owned 工具，不声称抵抗可改写同一 FD inode
  的恶意同 UID 进程。metadata 明示不能
  自我认证，最终 commit/tree/六 blob OID 由 root 与独立 reviewer 作外部 anchor。
  base/Ghidra archive 解包内容逐 blob 回验；snapshot comparands、runner FD、
  compiler 子程序、Make 使用的 shell/uname/sed/mkdir/rm、Rust
  driver/LLVM 与 target-libdir tree（另钉 sysroot path）、GCC/libstdc++/系统
  headers、Python stdlib 语义树、枚举的
  CRT/linker-script/archive、zlib link/runtime 输入及动态库闭包的路径/内容均在
  comparand 前后重验。外层 supervisor 在 spawn 前先记录 pending signal，以
  pinned GNU `env --default-signal` 恢复异步 child 继承的 disposition，再由 pinned
  `setsid --wait` 建独立进程组；只有 child 写入并通过 PID/PGID/SID handshake 后才
  重放/转发 HUP/INT/QUIT/TERM，wait/reap 后仍以首个请求的 `128+signal` 退出。
  cleanup 期间屏蔽后续 signal，成功主体若 cleanup 拒绝或删除失败也返回非零。Cargo
  build/test 只调用一次并持全局 flock（前后另以
  `cargo --version` 作只读指纹探测）；runner 按 captured `Cargo.lock`
  checksum 单次读取本机 `.crate`，拒绝歧义、路径逃逸与非 regular archive member，
  物化为只读 snapshot vendor，并使用空的 run-local `CARGO_HOME` 与本次
  `$oracle_tmp/cargo-target`；`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`
  明确钉到已哈希的 `/usr/bin/gcc`，不经 clean PATH 隐式选择 `/usr/bin/cc`。
  `LIBZ_SYS_STATIC=1` 令 `libz-sys` 从该已认证 vendor
  构建 bundled zlib，不查询 pkg-config。`root-output` 只在 build 目录深度 2 搜索并以直接
  父目录 basename `rugra-*` 过滤，不读取共享 target 的 latest 产物。
  direct-rustc 前后还绑定 dependency/native 两个完整输入树（含根目录、所有
  regular file bytes 与目录 mode），最终重验两个 fixture executable；Ghidra
  冷构建输出严格限制为两个 dependency 文件、locked Makefile 独立展开的 79 个
  `com_opt` object、两个 0700 build 目录及 `libdecomp.a`，并逐项核对 archive
  member 顺序、重复性与 member/object bytes，拒绝额外或变型 filesystem node。
- 剩余 `MISMATCH`（`JUMPTABLE-PIPELINE-0001`）：本租约禁止修改 flow/funcdata，
  因而生产调用闭包仍通过 bool/Option 兼容层丢失 typed mode。另一个
  独立的可见差异是 `RecoveryMode` 的 Ghidra/Rust 判别值均为
  normal=1/thunk=2/return=3/callother=4，而 `flow.rs::truncate_indirect_jump`
  的旧 `u8` 协议却把 0/1/2/other 解释为 thunk/callother/return/default；直接
  cast 会把 `FailNormal=1` 错当 no-return callother。在生产 `stageJumpTable`
  消费 typed error，并向 truncate 传递同一 `RecoveryMode` 域前，不得将模块或
  fixture overall 状态提升为 MATCH/L3。
- 剩余 `MISMATCH`（`JUMPTABLE-SORT-TOOLCHAIN-0001`）：当前只证明锁定
  GCC16/libstdc++ 的预期可观察等价组排列；24-case 已双侧执行且字节一致，但
  heap fallback 分支仍未入 fixture，且其他合法 STL/toolchain 可能不同。生产若
  需要跨 toolchain 等价，必须固定 oracle toolchain 或另行定义并双侧验证稳定契约。
- 剩余 `MISMATCH`（`JUMPTABLE-EMULFN-0001`）：locked
  `EmulateFunction::executeLoad` 在成功求出 LOAD 地址后，仅当 `loadpoints`
  非空时先追加 record，再由基类读取 payload；只有 `emulatePath`
  循环内 `executeCurrentOp` 抛出的 `DataUnavailError` 才转成带当前 op
  地址的 `LowlevelError`，最后结果 varnode 的读取位于该 catch 之外。起始
  MULTIEQUAL 无法解析、坏 start-op、普通 MULTIEQUAL 无法用 `lastOp`
  所在前驱选中输入，以及 BRANCH/BRANCHIND 均有各自精确的 Lowlevel
  文本和异常时序。其中坏 start 明确指 non-MULTIEQUAL start op 不在 PathMeld，
  并非泛化所有找不到的起点。Rust 当前没有 loader callback 或 `lastOp` 前驱状态，
  `get_varnode_value` 回退 0，`execute_op/emulate_path` 用 bool/Option 表示失败，
  `JumpBasic::build_addresses` 又把 `None` 或缺 start 静默写成 target 0。此缺口
  不能归入 typed stage 的 `JUMPTABLE-PIPELINE-0001`，且本租约不扩
  EmulateFunction 接口修复它。
- 上述 PIPELINE/EMULFN 为 locked-source audit 已知差异，SORT 为跨 toolchain
  contract residual；它们都不是 24-case fixture 的双侧观察结果（已执行部分的观察面见上文 2026-08-25 记录）。

## 2026-08-23：JUMPTABLE-GUARDS-0001 — analyzeGuards 完整移植 + valueMatch 补全 + checkUnrolledGuard 接线

- `analyze_guards(bl, pathout)`（jumptable.cc:1046-1112）：完整重写。
  ① `pathout>=0 && sizeOut==2` 首轮步进语义：prevbl=当前块、bl=out(pathout)、
  indpath=pathout、pathout 消耗为 -1，第一轮即分析步进块自身的 CBRANCH
  （JumpBasic2 传入 pathout 时守卫不再为空）；② 步进/回走任一分支后
  `bl = prevbl` 逐轮上移；③ 回走循环遇 `sizeIn != 1`：`sizeIn > 1` 时调
  `check_unrolled_guard`（cc:1069-1070），随后无条件 return；④ `i != 0` 的
  other-switch 保护（cc:1083-1091）：第二条 CBRANCH 的旁路出边终点若为
  BRANCHIND 且不是本表 `get_indirect_op()` 则 break；⑤ `indpathstore =
  prevbl.getFlipPath() ? 1-indpath : indpath`（cc:1100-1101）；⑥ pullBack
  循环（j=0..1）按 cc:1103-1111 顺序 break/push。
- `value_match(vn2, base_vn2, bits_preserved2)`（jumptable.cc:637-680）：补全
  `oneOffMatch == 1 → 1` 分支与 LOAD 等价 `→ 2` 分支（in(0) 空间偏移相等 +
  指针相同 或 双方 INT_ADD 同基址同常量偏移）。
- `check_unrolled_guard`（jumptable.cc:1338-1370）：GuardRecord 改经
  `GuardRecord::new`（构造器内 quasiCopy 填 base_vn/bits_preserved），并保持
  oracle 内层 `PcodeOp *readOp = vn->getDef();` 对外层 readOp 的遮蔽 —— 所有
  push 的 readOp 恒为 cbranch。
- `find_multiequal`（block.cc:2753-2772）：补上缺失的 `parent == bl` 检查
  （cc:2761）。
- `quasi_copy` / `pull_back_through_op`：改读原始 `nzm` 字段
  （`Varnode::get_nzm`，对应 varnode.hh:231 的 inline `getNZMask` 字段读），
  不再用按 size 截断的近似。（`pull_back_through_op` 后已于 2026-09-23 删除，
  jumptable 调用点改走正典 `CircleRange::pull_back`，见该日小节。）
- 门禁：`tools/run_jt_guards_oracle.sh` + `tests/oracle/jt_guards_1204.*`
  （FX-GUARD，oracle 12.0.4 e40ed130 双侧）：sc2_unrolled/sc4_other_switch/
  sc5_pathout MATCH；sc1/sc3 MISMATCH = `JUMPTABLE-GUARDS-RESIDUAL-0001`
  （rangeutil.rs `pull_back_binary` 缺 INT_SLESS/INT_SLESSEQUAL，oracle
  rangeutil.cc:882-917，不在本租约 write-set）；sc6 MISMATCH =
  `JUMPTABLE-GUARDS-RESIDUAL-0002`（funcdata.rs `calc_nz_mask` 简化，未做
  unwritten 输入 nzm 初始化，oracle funcdata_varnode.cc:889-893）。

## 2026-07-16：checkUnrolledGuard + checkCommonCbranch + findMultiequal

- `check_unrolled_guard(bl, max_pullback, use_nzmask)`（jumptable.cc:1338-1370）：检测跨多块展开的守卫。使用 checkCommonCbranch + CircleRange pullBack + liftVerifyUnroll + duplicateVarnodes + findMultiequal 创建 GuardRecord。所有依赖（getFlipPath b661e5e、liftVerifyUnroll b661e5e、pullBack a962f29）已完成。2026-08-23 起由 analyzeGuards 的 sizeIn>1 回走分支真正接线（此前为死代码）。
- `check_common_cbranch(var_array, bl)`（jumptable.cc:1305-1327）：验证所有 in-edge 来自相同 boolean-flip/out-slot 的 CBRANCH 块，收集 boolean 输入 varnode。
- `find_multiequal(bl, var_array)`（block.cc:2753-2772）：查找输入匹配 varArray 的 MULTIEQUAL op（须位于 bl 内）。

**Status:** L2. Public class coverage does not establish behavior parity; the
data-flow and CFG-rewriting algorithms still depend on broken Address,
Varnode/PcodeOp, Block, Range, injection, and emulation foundations.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.{hh,cc}`.

## Constants

| Name | Type | Description |
|---|---|---|
| `NO_LABEL` | `u64` | Sentinel (`0xBAD1_ABE1_BAD1_ABE1`) for an unlabelled jump-table entry. |
| `MARK_FLAG` | `u32` | `addlflags` bit mirroring `PcodeOp::setMark`. |

## Enums

### `RecoveryMode`
Recovery status of a `JumpTable` — faithful to `JumpTable::RecoveryMode`
(jumptable.hh:544).
- `Success = 0`, `FailNormal = 1`, `FailThunk = 2`, `FailReturn = 3`,
  `FailCallother = 4`.

### `JumpTableRecoveryError`

Typed equivalent of Ghidra's two exception catches around jump-table
recovery. `Thunk { message }` and `Lowlevel { message }` retain the exact
`explain` string. `message()` borrows it and `recovery_mode()` returns
`FailThunk` or `FailNormal` respectively.

## Structs

### `LoadTable`
A description of where and how data was loaded from memory
(jumptable.hh:50).

| Field | Type | Description |
|---|---|---|
| `addr` | `Address` | Starting address of the table. |
| `size` | `i32` | Size of each table entry. |
| `num` | `i32` | Number of entries. |

**Methods:**
- `single(addr, size) -> Self` — single-entry table.
- `new(addr, size, num) -> Self` — full table.
- `collapse_table(&mut Vec<LoadTable>)` — sort and merge contiguous entries
  (jumptable.cc:60). The sort key is the full `Address` only
  (jumptable.hh:59); equal addresses do not compare `size` or `num`.
  `nextaddr` uses address-space wrapping. Equivalent-key permutation mirrors
  the fixture-pinned GCC 16.2.1 libstdc++ implementation; portability remains
  `JUMPTABLE-SORT-TOOLCHAIN-0001`.

### `PcodeOpNode`
A data-flow path edge (op + input slot).

### `PathMeld`
All paths from a putative switch variable to the BRANCHIND (jumptable.hh:72).

| Method | Description |
|---|---|
| `num_common_varnode()` / `num_ops()` / `empty()` | Container sizes. |
| `get_varnode(i)` / `get_op(i)` / `get_op_parent(i)` | Element accessors. |
| `get_earliest_op(pos)` | Earliest op using the i-th common varnode. |
| `is_load_in_path(i)` | True if a LOAD precedes position `i`. |
| `set_from(&PathMeld)` | Copy paths. |
| `set_path(&[PcodeOpNode])` | Initialise to a single path. |
| `set_single(op, vn)` | Initialise to a single-node path. |
| `append(&PathMeld)` | Append a new set of paths. |
| `meld(&mut Vec<PcodeOpNode>)` | Meld a new path in (jumptable.cc:968). |
| `mark_paths(val, start_varnode)` | Mark/unmark ops from a start varnode. |
| `clear()` | Empty the container. |

### `GuardRecord`
A switch-variable Varnode and a constraint imposed by a CBRANCH
(jumptable.hh:138).

| Field | Type | Description |
|---|---|---|
| `cbranch` | `Option<Arc<RwLock<PcodeOp>>>` | CBRANCH guarding the switch. |
| `read_op` | `Option<Arc<RwLock<PcodeOp>>>` | Op causing the restriction. |
| `vn` | `Option<Arc<RwLock<Varnode>>>` | The restricted varnode. |
| `base_vn` | `Option<Arc<RwLock<Varnode>>>` | Quasi-copy source. |
| `indpath` | `i32` | CBRANCH path to the switch. |
| `bits_preserved` | `i32` | Bits copied (others zero). |
| `range` | `CircleRange` | Range taking the switch path. |
| `unrolled` | `bool` | Duplicated across blocks. |

**Methods:** `new`, `is_unrolled`, `get_branch`, `get_read_op`, `get_path`,
`get_range`, `clear`, `value_match`.

### Free functions
- `quasi_copy(vn) -> (Option<Arc<RwLock<Varnode>>>, i32)` — quasi-COPY chain
  source (jumptable.cc:719); bits derive from the raw `nzm` field.
- `one_off_match(op1, op2) -> i32` — 1 if two ops produce the same value
  (jumptable.cc:684).

## Traits

### `JumpValues`
Iterator over values a switch variable can take (jumptable.hh:166).
- `truncate(nm)`, `get_size()`, `contains(val)`, `initialize_for_reading()`,
  `next()`, `get_value()`, `get_start_varnode()`, `get_start_op()`,
  `is_reversible()`, `clone_boxed()`.

### `JumpModel`
A jump-table execution model (jumptable.hh:243).
- `is_override()`, `get_table_size()`,
- `recover_model(fd, indop, matchsize, maxtablesize, parent) -> bool`,
- `build_addresses(fd, indop, addresstable, loadpoints, loadcounts)`,
- `find_unnormalized(maxaddsub, maxleftright, maxext)`,
- `build_labels(fd, addresstable, label, orig)`,
- `fold_in_normalization(fd, indop) -> Option<Varnode>`,
- `fold_in_guards(fd, jump) -> bool`,
- `sanity_check(fd, indop, addresstable, loadpoints, loadcounts) -> bool`,
- `clone_model() -> Box<dyn JumpModel>`, `clear()`.
- `as_any() -> &dyn Any` (RUGRA-GLUE，Ghidra 侧对应物是调用方对
  `JumpModel*` 做 `dynamic_cast<JumpBasic*>` 读 `selectguards`；Rust trait
  object 需要 `Any` 出口，五个模型实现均返回 `self`)。

## `JumpValuesRange` / `JumpValuesRangeDefault`
Implementations of `JumpValues` for a single-entry range / a range plus an
extra default value (jumptable.hh:188 / 214).
**2026-07-05 修正**：`curval`/`lastvalue` 改为 `AtomicU64`/`AtomicBool`（对应
Ghidra `mutable curval`/`mutable bool lastvalue`），使 `&self` 的
`initialize_for_reading` 能像 Ghidra `const` 方法一样产生设置 curval 的副作用
（jumptable.cc:289 / 341-353）。Default 变体之前两分支都返回 true 且不设
`curval`/`lastvalue`，现已按 Ghidra cc:344-352 正确分支。手动 `Clone` impl
（Atomic 类型非 Clone）。

## Model implementations

### `JumpModelTrivial`
The BRANCHIND input is the switch variable (jumptable.hh:350).
Constructor: `new(jt)`.

### `JumpBasic`
The basic switch model (jumptable.hh:374). Notable methods:
- `new(jt)`, `get_path_meld()`, `get_value_range()`.
- `is_prune(Varnode)`, `is_point(Varnode)`, `get_stride(Varnode)`,
  `get_max_value(Varnode)`, `duplicate_varnodes(&[Varnode])`.
- `find_determining_varnodes(op, slot)` (jumptable.cc:554).
- `calc_range(vn, &mut CircleRange)` (jumptable.cc:1120). **2026-08-23 修正
  (JUMPTABLE-CALCRANGE-0001)**：初始 range 按 oracle 三分支派发——constant 取
  single(offset,size) 且**不再提前 return**（继续走守卫交集与 positive 截断）；
  `is_written() && def.is_bool_output()`（op.hh:184，经 `set_opcode_flags` 缓存的
  BOOLOUTPUT 位）取 `CircleRange(0,2,1,1)`；否则 getMaxValue/getStride 初始
  range（stride 仅此分支更新，constant/布尔分支保持 1）。守卫循环
  `rng.intersect(guard.range)` **就地写回**（cc:1144），`valueMatch!=0` 即应用；
  size>0x10000 时尝试 positive 半区截断（cc:1150-1155）。
- `find_smallest_normal(matchsize)` (jumptable.cc:1165).
- `mark_foldable_guards()` (jumptable.cc:1239).
- `mark_model(val)` (jumptable.cc:1254). **2026-08-23 修正
  (JUMPTABLE-CALCRANGE-0001 / JUMPTABLE-MARKMODEL-0001)**：先取
  `guard.get_branch()`，为 None（被 `mark_foldable_guards` 清除的守卫）则
  continue **跳过 readOp 标记**（cc:1259-1260），不再以 `get_read_op()` 判空。
- `analyze_guards(bl, pathout)` (jumptable.cc:1046).

### JT-CALCRANGE-1204 fixture
`tests/oracle/jt_calcrange_1204.{cc,rs,metadata.json}` +
`tools/run_jt_calcrange_oracle.sh`：锁定 12.0.4 双侧差分（base f6fd4ea +
jumptable.rs overlay，pin-base schema2）。三个场景（无符号守卫链 /
constant 输入 / markModel skip）投影全 MATCH，residuals 为空；sc2 的
constant-空交集判别力受 rangeutil `intersect` 保守实现限制（RANGE-0001）。

## `JumpTable`
A map from values to control-flow targets within a function
(jumptable.hh:541).

| Field | Type | Description |
|---|---|---|
| `jmodel` | `Option<Box<dyn JumpModel>>` | Current model. |
| `origmodel` | `Option<Box<dyn JumpModel>>` | Saved model. |
| `addresstable` | `Vec<Address>` | Raw addresses. |
| `block2addr` | `Vec<IndexPair>` | Block→address-index map. |
| `label` | `Vec<u64>` | Case labels. |
| `loadpoints` | `Vec<LoadTable>` | In-memory model data. |
| `opaddress` | `Address` | BRANCHIND address. |
| `indirect` | `Option<Arc<RwLock<PcodeOp>>>` | BRANCHIND op. |
| `switch_var_consume` | `u64` | Switch-var bits consumed. |
| `default_block` | `i32` | Default out-edge (-1 = undef). |
| `last_block` | `i32` | Out-edge of last table entry. |
| `norm_max` | `NormMax` | Normalisation restrictions. |
| `partial_table` / `collect_loads` / `default_is_folded` | `bool` | Flags. |

**Methods (selected):** `new(opaddress)`, `is_recovered`, `is_labelled`,
`is_override`, `is_partial`, `mark_complete`, `num_entries`,
`get_switch_var_consume`, `get_default_block`, `get_op_address`,
`get_indirect_op`, `set_indirect_op`, `set_norm_max`, `get_address_by_index`,
`set_last_as_default`, `set_default_block`, `set_load_collect`,
`set_folded_default`, `has_folded_default`, `get_label_by_index`,
`add_block_to_switch`, `save_model`, `restore_saved_model`,
`clear_saved_model`, `clear`, `sanity_check`,
`recover_addresses_classified`, `recover_addresses`.

`try_recover_classified(indop, fd)` is the typed free-function entry point.
The legacy `try_recover(indop, fd)` converts typed failure to `None` without
catching panics.

### `IndexPair`
Block-position / address-index pair (jumptable.hh:553).
`new(pos, index)`, `less_than(&Self)`, `compare_by_position(&Self, &Self)`.

### `NormMax`
Normalisation restrictions `{ addsub, leftright, ext }`.

### `EmulateFunction`
Light-weight emulator for switch targets (jumptable.hh:110).
- `new()`, `set_load_collect(Option<Vec<LoadTable>>)`,
  `get_varnode_value(vn)`, `set_varnode_value(vn, val)`.

## L3 gaps (documented in source)
- ~~`Varnode::def` traversal~~ — **DONE**: `find_determining_varnodes` now does
  full def-chain DFS; `quasi_copy` walks COPY/INT_AND/INT_OR/SEXT/ZEXT/PIECE/
  SUBPIECE chains; `get_max_value` inspects INT_AND/MULTIEQUAL; `isLoadInPath`
  detects LOAD via `get_def()`.
- `EmulateFunction::emulate_path` per-value address computation.
- `CircleRange::pullBack` integration for guard expansion.
- CFG-rewriting (`foldInOneGuard`, `switchOver`, branch editing via
  `Funcdata::pushBranch`).
- `backup2Switch` reverse emulation for case-label recovery.

## 2026-06-27（续）：pullBack 守卫扩展 + backup2Switch + findUnnormalized

**新增自由函数**：
- `pull_back_through_op(rng, op, usenzmask) -> Option<Varnode>`（rangeutil.cc:1022）：通过 PcodeOp 反向范围，返回未知输入 varnode。处理一元/二元操作 + NZ 掩码交集 + SUBPIECE usenzmask 特殊情况（2026-07-16 补齐 rangeutil.cc:1053-1064）。
  **2026-09-23 更新**：该自由包装已删除；`analyze_guards`（cc:1106）与
  `check_unrolled_guard`（cc:1366）两调用点改走 `rangeutil.rs` 正典
  `CircleRange::pull_back(op, usenzmask, &mut None)`——discard 槽镜像
  oracle 两处的 `Varnode *markup; // Throw away markup information`
  （12.0.4 jumptable 路径从不读取 markup，唯一消费者是 RuleRangeMeld
  cc:1416，EZ 车道已接）。

**JumpBasic 新增/升级方法**：
- `analyze_guards`：现执行完整 pullBack 扩展循环（jumptable.cc:1119），从布尔 varnode 反向最多 2 步，每步创建新 GuardRecord。
- `backup2_switch(output, outvn, invn) -> Option<u64>`（jumptable.cc:472）：从规范化值反向模拟到未规范化值，使用 opbehavior::recover_input_unary/binary。
- `find_unnormalized`：现执行完整 ADD/SUB/ZEXT/SEXT 链遍历（jumptable.cc:1484），计数 addsub/ext 限制。
- `flows_only_to_model(vn, trail_op) -> bool`（jumptable.cc:1293）：检查 varnode 是否仅流向模型。
- `build_labels`：现使用 backup2_switch 恢复 case 标签（jumptable.cc:1528），不再全部发 NO_LABEL。

剩余 L3 缺：emulate_path 地址计算、CFG 重写（foldInGuards/switchOver）。

## 2026-06-27（续 3）：emulate_path 历史局部实现（完成结论已撤回）

**EmulateFunction 新增方法**：
- `execute_op(op) -> bool`：只覆盖可由
  `opbehavior::evaluate_unary/binary/ternary` 计算的子集。代码中的 LOAD
  record 分支位于 evaluate 成功后，而当前 `CPUI_LOAD` evaluate 返回
  `None`，因此该分支不可达，不等价于 locked `executeLoad`。
- `emulate_path(val, path_meld, startop, startvn) -> Option<u64>`（jumptable.cc:218）：
  能驱动上述通用运算子集并识别部分起始 MULTIEQUAL 形状；但仍缺
  loader/DataUnavail 异常通道、普通 MULTIEQUAL 的 `lastOp` 前驱选择、
  BRANCH 异常语义及精确 Lowlevel 文本，失败被压成 `None`。

**JumpBasic::build_addresses**：成功时使用 `emulate_path` 计算目标；
但 `None` 或缺 start op/varnode 仍会写入 0，因此现阶段仍存在可见占位回退。
**2026-07-05 修正**：jumptable.cc:1465-1469 的 `funcptr_align` 掩码之前被硬编码为 `u64::MAX`（无对齐），与 Ghidra 在任何 `funcptr_align != 0` 的架构上分歧；并补上 jumptable.cc:1475 的 `AddrSpace::addressToByte(addr, spc->getWordSize())`（Rugra 单空间模型下 `wordSize==1`，no-op，已显式标注）。同时把 `loadcounts` 改为 Ghidra 的累计语义（`loadpoints->size()` 而非 per-iter 局部计数）。`curval` 重置（jumptable.cc:289 `mutable curval`）改为在 `build_addresses` 内重置克隆的迭代器，对齐 Ghidra 的 `initializeForReading` 副作用。

测试：历史上新增 2 个 Rust 回归（emulate_path INT_ADD + COPY）；它们不是
loader/MULTIEQUAL/BRANCH/lastOp/Lowlevel 通道的双侧 oracle 证据。

剩余 L3 缺：`JUMPTABLE-EMULFN-0001` 中的上述仿真/异常语义，以及 CFG
重写（foldInGuards/switchOver via Funcdata::pushBranch）。

## 2026-06-27 历史实现记录（“达到 L3”结论已于 2026-08-11 撤回）

**Funcdata 新增方法**（funcdata_block.cc）：
- `push_branch(bb, slot, bbnew)`（funcdata_block.cc:404）：将 CBRANCH 转为 BRANCH，重定向 out-edge 到 BRANCHIND 块。
- `force_goto(pcop, pcdest) -> bool`（funcdata_block.cc:752）：标记指定分支为非结构化 goto。
- `set_goto_branch(bl, j)`：标记 out-edge j 为 goto（使用 GOTO_EDGE_0/1 标志）。
- `move_out_edge(bb, slot, bbnew)`：重定向 out-edge（BlockGraph::moveOutEdge）。

**JumpBasic 新增方法**：
- `fold_in_one_guard(fd, guard, jump) -> bool`（jumptable.cc:1392）：消除单个守卫——或将 CBRANCH 条件设为常量，或通过 push_branch 将分支推入 switch。
- `fold_in_guards`：现使用 fold_in_one_guard 处理每个守卫（jumptable.cc:1577）。

**Override 新增方法**：
- `apply_force_gotos(fd) -> usize`（override.cc:204）：将所有 force-goto 覆写推入函数。

测试：新增 2 个（set_goto_branch 标志 + apply_force_gotos）。“jumptable.rs
所有算法 L3 缺口已关闭”为历史误判；已于 2026-08-11 撤回，当前以文档顶部
L2 状态及已登记 residual 为准。

### 2026-07-01：JumpTable 接入 Funcdata
recover_model/recover_addresses/try_recover/recover_jump_tables。ActionSwitchNorm 调用 recover_jump_tables。jump_tables 现可被填充，find_jump_table 返回非 None。
<!-- annotation-pass: 2026-07-04 -->
<!-- ref-fix2: 1783141346.3299575 -->
 

### 2026-07-05: JumpValues trait 多态 + JumpBasic2 修复 + find_normalized
- `JumpBasic.jrange` 改 `Option<Box<dyn JumpValues>>`(Ghidra `JumpValues*` 多态)。
- `JumpValues::clone_boxed_any_range` trait 辅助。
- `JumpValuesRangeDefault::new/Default`。
- `JumpBasic::find_normalized`(cc:1223)提取为独立方法。
- `JumpBasic2` 修复 check_normal_dominance/find_unnormalized/recover_model 类型错误,recover_model 对齐 cc:1698-1734。

## 注释行号勘误（2026-08-23，root）

复核发现的 annotation 漂移已修正：`JumpTable::clear` 引用 jumptable.cc:2739（原误 2761，那行是 encode 的 doc）；`clearSavedModel` 引用 jumptable.cc:2243（原误 2265）。行为零改动。

## calcRange/markModel 集成与注释行号勘误（2026-08-23，root）

dbcc9cb 集成：守卫交集就地写回、isBoolOutput 分支、常量无 early-return、markModel branch 判空跳过。复核域外 4 处既有注释行号漂移已修正（recoverModel 1437→1418、1453→1434、1484→1462、1293→1274）。

## recoverMultistage/checkForMultistage 移植（2026-08-25，JUMPTABLE-PIPELINE-0001 段2）

- `JumpTable::recover_multistage(fd)`（jumptable.cc:2653-2675）：saveModel → 暂存旧
  addresstable → loadpoints.clear → recover_addresses_classified；两类异常
  （JumptableThunkError/LowlevelError）同一恢复体（restoreSavedModel + 还原地址表 +
  "Second-stage recovery error" 警告）；无论成败 `partial_table=false` +
  clearSavedModel。loadpoints 失败时**不**还原（cc:2659 清空后无还原语句）。
- `JumpTable::check_for_multistage(fd)`（jumptable.cc:2847-2860）：三条前置
  （单条目/非 partial/indirect 已链接）+ `Override::query_multistage_jumptable`
  命中时置 `partial_table=true` 并返回 true。
- `FlowInfo::check_multistage_jumptables`（flow.cc:1408-1417）随之从结构占位升级为
  完整移植：被提升表间接 op 推回 `tablelist`（JUMPTABLE-MULTISTAGE 缺口关闭）。
- `Funcdata::stage_jump_table` isPartial 分支改走 recover_multistage（此前
  RUGRA-GAP 注释声称未移植）。

## 2026-09-22：JUMPTABLE-TABLEAPI-0001 P0-A — SwitchNorm 表级 API + foldIn* 语义修正

**JumpTable 新增表级方法**（cc 行号=锁定 12.0.4 e40ed130）：
- `match_model(fd)`（jumptable.cc:2683-2708）：isRecovered 前置 → 非 override
  存 saveModel / override 清 savedModel+警告 → recoverModel(maxtablesize=
  arch.max_jumptable_size) → 表尺寸不匹配时（单条目且模型>1）insertMultistageJump+
  setRestartPending 早退，否则警告。
- `recover_labels(fd)`（jumptable.cc:2714-2735）：jmodel 在场 → findUnnormalized+
  buildLabels（origmodel 为空/零表时 orig=jmodel 自身）；jmodel 缺席 →
  JumpModelTrivial 兜底（recoverModel/buildAddresses/trivialSwitchOver/
  buildLabels）；全路径收尾 clearSavedModel。trivialSwitchOver 的尺寸不匹配
  LowlevelError 经 `JumpTableRecoveryError::Lowlevel` 穿透。
- `trivial_switch_over()`（jumptable.cc:2594-2609）：block2addr=(i,i) 全对、
  lastBlock=sizeOut-1、defaultBlock=-1。
- `fold_in_normalization(fd)`（jumptable.cc:2574-2591）：jmodel->
  foldInNormalization 后按 minimalmask(NZMask) 设 switch_var_consume，全覆盖时
  对 INT_SEXT def 退化为 calc_mask(输入尺寸)。（2026-09-22 sb-foldinnorm：minimalmask
  修正为 address.hh:525 整字节阶梯真身后，本调用点语义方才与 oracle 一致——
  修正前 coveringmask 别名系统性低估 consumed 位，见 docs/api/address.md 同日节。）
- `fold_in_guards(fd)`（jumptable.hh:615 inline）：委托 jmodel->foldInGuards
  （Rust 以 take/put-back 表达 C++ 的 this 别名，无实现读 jt.jmodel）。

**foldIn* 家族语义修正（对齐 12.0.4，修复旧近似）**：
- `JumpBasic::fold_in_one_guard`（cc:1373-1409）：补 cc:1391 `hasFoldedDefault&&
  getDefaultBlock!=pos` 单折叠目标守卫（pos 含 not-found==sizeOut 语义）、补
  cc:1394 `noInterveningStatement` 守卫、GOTO_EDGE_1 近似换 `getFlipPath()`
  （block.hh:297）、常量值补 `isBooleanFlip` 异或（cc:1402）。
- `JumpBasic::fold_in_guards`（cc:1555-1570）：null cbranch=continue（不 clear），
  dead cbranch=clear+continue（旧版两者合并）。
- `JumpBasic::fold_in_normalization`（cc:1546-1553）：改走 `fd.op_set_input`
  （维持 Varnode descend 记账；旧版裸写 inrefs 丢 bookkeeping）。
- `JumpBasic2`：结构改为忠实形态——`fold_in_one_guard`（cc:1634-1649，
  setLastAsDefault+clear+true）为 override，`fold_in_guards` 继承 JumpBasic 循环
  并虚派发到该 override（旧版整体 clear+恒 true，空守卫集时返回值错误）。
- `JumpAssisted::fold_in_normalization`（cc:2193-2206）：真实实现——assist op
  出边全部后代 opSetInput(slot0=switchvn)（先快照后代再改，因 op_set_input 会
  切断 outvn descend）+ opDestroy(assistOp)；旧版仅返回 indop 输入。
- `JumpAssisted::fold_in_guards`（cc:2208-2214）：origVal 记录→setLastAsDefault→
  比较返回（旧版恒 true）。
- `JumpBasicOverride::fold_in_normalization`（hh:485）：删除 INVENTED 的
  is_trivial 分支，纯继承 JumpBasic。
- `JumpTable::add_block_to_switch`（cc:2535-2543）：lastBlock 改
  `indirect->parent->size_out()`（旧版用 addresstable.len() 近似，截断表上错位）；
  test_jump_table_add_block 相应改为真实 indirect+双出边夹具。

Annotation 修正（机制 D cited-line-drift）：foldInOneGuard 1392→1373、
foldInNormalization 1568→1546、foldInGuards 1577→1555、JumpAssisted foldIn*
补 cc:2193/2208。ActionSwitchNorm 消费接线见 docs/api/coreaction.md；
noInterveningStatement 见 docs/api/block.md。

## 2026-09-22（返修）：机制 C 复核 REJECT 修复 — 模型父表状态真值下传

复核实证的两处行为分歧（dummy parent Arc）已修：
- 通道① `analyze_guards` 的 `usenzmask`（cc:1052 `!jt->isPartial()`）：改读
  `JumpParentFacts::partial_table` 快照——multistage 表(partialTable=true)
  不再被空 dummy 恒 false 误判。
- 通道② 守卫回走 i>0 的兄弟 BRANCHIND 身份检查（cc:1083-1090
  `jt->getIndirectOp()`）：改用 `JumpParentFacts::indirect` 真实 indirect op
  ——同 switch 的兄弟边守卫继续收集，只有别的 switch 才 break。

设计（`JumpParentFacts`，RUGRA-GLUE）：恢复全程在表自身 RwLock 写锁下
（stageJumpTable/ActionSwitchNorm 均经 `Arc::write()` 进入），模型内锁真父
Arc=同线程重入死锁;模型存强 Arc=与 `JumpTable::jmodel` 成环泄漏;故
`JumpTable::recover_model` 在 `&mut self` 上直接快照 `partial_table` 与
`indirect` 两个纯值,经 `JumpModel::recover_model` trait 参数下传至
`find_normalized`→`analyze_guards` 两处使用。模型结构体不再持有
`jumptable` 父字段（Trivial/Basic/Assisted 删除,构造器与 `clone_model`
去 jt 参数,funcdata.rs 流程克隆调用点同步）。

验证：curl 全量输出与返修前逐字节相同（sha256 3a1dadf2…，3705/0/0）；
gp 864/0/0、glob_set 90/0/0 保持；httpd 与基线逐字节相同；单线程
cargo test 17 failed 与 FUNCDATA-TESTS-FLAKY-0001 已知集相同（复核抽测
单测隔离全过）,新增=0。

## 2026-09-22：switchOver + block→index 查询四件（JUMPTABLE-TABLEAPI-0001 数据层）

label 管道数据层落地（wt/sb-jtlabel）：
- `switch_over(&mut self, flow: &FlowInfo)`（jumptable.cc:2528-2569）：addresstable
  逐地址经 `FlowInfo::target` 解析目标 op→基本块，在 switch 基本块出边里找槽位，
  填 `block2addr: Vec<IndexPair>`；`last_block`=末条目槽位；按
  `IndexPair::operator<`（hh:628, position→addressIndex）排序；defaultBlock 扫描
  取重复条目数>1 的槽位。目标未链接 → `JumpTableRecoveryError::Lowlevel`
  （"Jumptable destination not linked"，cc:2545-2546 同语义传播）。
- `block2_position(&self, bl)`（jumptable.cc:2337-2349，private）：bl 的入边里找
  indirect op 父块，返回 reverse_index（switch 出边槽）。Ghidra throw 处 Rust 返回
  None，两个查询调用方据此降级为 0 indices（构造期入边恒在）。
- `num_indices_by_block(&self, bl)`（jumptable.cc:2438-2445）：equal_range
  （compareByPosition）宽度，`partition_point` 双侧实现。
- `get_index_by_block(&self, bl, i)`（jumptable.cc:2485-2500）：lower_bound 起顺序
  扫描计数，返回 addressIndex；Ghidra throw（cc:2499）处返回 None。

调用接线：`Funcdata::switch_over_jump_tables`（funcdata_block.cc:678）由
`follow_flow_range` 在 `generate_blocks()` 后调用（funcdata_op.cc:777-778 同位），
见 docs/api/funcdata.md 与 docs/api/flow.md。后续 finalizePrinting 消费链见
docs/api/block.md / blockaction.md。

## 2026-09-23：JUMPTABLE-MARKUP-CONSUMER 接线 — 正典 pullBack 调用形态（Lane FB）

**oracle 事实核对（12.0.4 e40ed130，逐行读过 jumptable.cc:1046-1112/1338-1371）**：
- cc:1103（analyzeGuards）与 cc:1362（checkUnrolledGuard）两处均为
  `Varnode *markup; // Throw away markup information`，声明后传入
  `rng.pullBack(readOp,&markup,usenzmask)`（cc:1106/cc:1366）但**从不读取**。
- jumptable.cc 全文无 `copySymbolIfValid`/`copySymbol` 调用；12.0.4 中
  pullBack markup 的唯一消费者是 RuleRangeMeld（ruleaction.cc:1416，
  EZ 车道 0d4e1602 已接）。车道前提"jumptable.cc:1106/1366 消费 markup"
  对本 oracle 不成立——不存在"恢复路径 EquateSymbol 标注"链路可接。

**实际改动**（wt/jtmarkup）：
- 删除 jumptable.rs 本地自由包装 `pull_back_through_op`（与 EZ 在 ruleaction
  侧删除 `pull_back_op` 简化版同型：重复实现 + 非正典调用形态 + 行为微差
  ——包装对 missing out 用 `unwrap_or(in_size)` 续算，正典按"Ghidra 必然
  解引用 getOut()"语义返回 None）。
- `analyze_guards`（cc:1106 镜像）与 `check_unrolled_guard`（cc:1366 镜像）
  两调用点切正典 `rng.pull_back(&op, usenzmask, &mut None)`——discard 槽
  逐字镜像 oracle 的 throw-away 局部；`usenzmask` 仍为
  `!parent.partial_table`（cc:1052）/参数透传（cc:1337）。
- 顺带修正两调用点周围 cc 行号注释漂移（1365→1366 等 8 处，CR14 注册的
  annotation-drift 尾巴，限本 write-set 内）。
- `nzm` 读取无行为差：`get_nzm()` 与 `get_nz_mask()` 均返回裸字段
  （varnode.hh:231 inline），包装的"raw nzm"注释与正典实现等价。

## 2026-09-24：RESIDMAP-PRINTBATCH —— 恢复失败消息的 opaddress printRaw 拼写

- `recover_addresses_classified`（cc:2626-2640 镜像）三处错误消息
  （"Could not recover jumptable at {}. Too many branches" ×2 与 "Jumptable with
  0 entries at {}"）中的 `opaddress` 改经 `fd.print_raw_code_addr` 渲染
  （oracle 对 `opaddress` 流式输出走 `Address::printRaw`，space.cc:206），
  携带 `display_image_base` 的 canon 基址差；行为语义（LowlevelError 通道、
  触发条件、table size 判零）零改动。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 61 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-26 — JTDEST 错误路径归真（BINSWEEP-JTDEST-UNLINKED-0001）

- `switch_over`（jumptable.cc:2528-2569）目的地解析失败路径归真：oracle 的
  `FlowInfo::target`（flow.cc:115-138）对未解码地址**抛出** `"Could not find op
  at target address: (<spc>,<printRaw>)"`（space.cc:206-216 的 0x+2*addrSize
  零填充、按 >>32/>>48 前导零裁剪，wordsize=1 恒等映射），而 cc:2545-2546 的
  `"Jumptable destination not linked"` 只覆盖出边扫描失配。Rugra 侧此前把
  `flow.target()==None`（未解码地址）也折叠进 not-linked 文本，两条件混淆。
  现未解码地址按 oracle 原文（含空间名 + printRaw 形态）单独上报；site1/3/4
  （间接 op 无父块 / 目标 op 无父块 / 出边失配）仍走 not-linked。
- 本路径仅在跳表目的地从未生成 p-code 时可达（有界流范围契约下）；(0, MAX)
  oracle 契约下不可达。错误文本 change 是唯一行为差（通道/触发条件零改动）。
- 根因修复在驱动层：examples/gen_decompile.rs 默认臂改 follow_flow_range(0,
  u64::MAX)（funcdata.cc:163 startProcessing 恒全空间界），见该文件注释与
  TODO_BOARD BINSWEEP-JTDEST-UNLINKED-0001 行。

### 2026-09-27：GA-2 SWITCHHEADUNIQUE 核验注记 — fold_in_normalization 无辜（零代码改动）

GIANTS-GA2-SWITCHHEADUNIQUE-0001 票面曾假设 8 处
`switch(*(uint1 *)unique0x00008f00)` 泄漏源于 fold-in 后死码清理杀掉
switchvn 定义链（写域预测=src/jumptable.rs）。**本车道核验证伪该假设**：

- 探针（前会话遗留 examples/ga2_probe.rs，FLAGS 链走）亲证 print 时
  BRANCHIND 输入链完整存活且 implied：`branchind@ad66a → LOAD@ad657 →
  PTRADD@ad657 → SUBPIECE@ad612`（ExprCodeTarget 位点同形：
  `branchind@4c317 → INT_AND → LOAD@4c2f3 → CAST@4c2f3 → PTRADD@4c2f3`）。
- oracle 侧 stage_drill_1204（sqlite3Pragma）终态帧同构：
  `switch u0x00023b00:1(ad657:447)` ← `*(ram,u0x00008f00(f244))` ←
  `RAX + #0x1(*#0x8)`——`foldInNormalization`（cc:1546-1553）只置
  BRANCHIND 输入，switchvn 自身 load+地址链两侧同活。Rugra 的
  `fold_in_normalization`（cc:1546-1553 移植，见上节）行为已对齐，**本票
  jumptable.rs 零改动**。
- 真根因=printc.rs `emit_switch_head_expr` legacy 传输缺 PTRADD 臂（详见
  docs/api/printc.md 2026-09-27 节）；修复后 8/8 位点泄漏全消，ExprCodeTarget
  2 位点 golden 逐字。Pragma 簇 6 位点残差（下标 8 vs 1、缺 (uint1) cast）=
  指针 pointee 类型分歧（uint1* vs uint8*，RuleExpandLoad 触发条件被断），
  已登记 `GA2-SWITCHVN-POINTTEE-TYPE-0001`（infertypes 域），与本文件无关。
## 2026-09-30：op 链迭代面机械迁移（PERF-ARENA-FLIP-0001 (b)）

`fd.obank.{alivelist,deadlist,storelist,loadlist,returnlist,useroplist}`
的 Vec 迭代/克隆消费位随 PcodeOpBank 7 链 IdList 翻转机械改写为 bank 链
API（`iter_alive()/iter_dead()/iter_store()...` 与 `.cloned().collect()`），
迭代序与语义恒等（链序=原 Vec 序=oracle 列表序）；测试面裸
`alivelist.push` 改 `adopt_alive_op`（bank API，单链不变量保持）。
