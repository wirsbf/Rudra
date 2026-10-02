# FLOW-MIRROR-0001 — 驱动层流跟随镜像设计(M1,RUDRA_FLOW_MIRROR=1)

> Lane AQ / wt/sb-rust,基线 6ad21c4。oracle = Ghidra 12.0.4 `e40ed130`
> (AGENTS.md 锁定)。依据:D10(STAGE_BISECT_SPEC_1204.md 增补 v1.2.2)、
> Lane AL ATTRIBUTION_V2.md §1(R1/R1a 实证)。

## 1. 根因(两个驱动层分歧,均在 oracle raw-native 单函数 BFD harness 中不存在)

### D-range — 流范围 marshaling 差

- oracle 正典(regen_ghidra_golden.py:388 ≡ oracle harness:315):
  `fd->followFlow(Address(codeSpace, 0), Address(codeSpace, getHighest()))`
  — funcdata_op.cc:756-783,FlowInfo ctor 默认 `baddr=(space,0)`、
  `eaddr=(space,~0)`(flow.cc:28-29),followFlow 形参收窄。
- Rudra 现状:examples/curl_decompile.rs:3582 传
  `follow_flow_with_callee_protos(fd, lifter, Address::new(entry), u64::MAX, …)`,
  src/flow.rs:3331 硬编码 `baddr = entry.as_u64()`。
- 后果:curl 二进制 `.plt@0x2xxx < .text@0x4f90`,一切 `.text` 函数的尾跳
  `jmp strdup@plt`(如 next_url 0x50fa → 0x2530)目标 < entry → 出界 →
  `new_address` OOB → unprocessed → `fillin_branch_stubs` 补 missing halt
  (flow.cc:889-901;Rudra flow.rs:957-972 忠实移植),PLT 体不入函数。

### D-shared-return — Java Shared Return Calls analyzer 仿真

- examples/curl_decompile.rs:215 `collect_known_entry_shared_return_overrides`
  仿真 Java `SharedReturnAnalysisCmd`(直接 jmp → 已知函数入口 ⇒ CALL_RETURN
  override),经 worker :3392-3415 注入 `fd.localoverride`,flow 期
  flow.rs:3065 `override_flow`(funcdata_op.cc:969-1021 忠实移植)把
  BRANCH@0x50fa 改写 CALL@0x50fa:53 + RETURN@:54(drill 签名:uniq 连续)。
- oracle harness 是裸 BFD 加载,无任何 Java analyzer ⇒ 无 override。
  已有 A/B 门 `RUDRA_DISABLE_SHARED_RETURN`(controller :4849)。

## 2. 镜像语义(RUDRA_FLOW_MIRROR=1,默认 off,默认 E2E 逐字节不变)

1. **controller**(:4849 区域):mirror 时 `flow_override_entries = []`
   (与 RUDRA_DISABLE_SHARED_RETURN 同效,日志区分)。
2. **worker**(:3582 区域):mirror 时改调
   `rudra::flow::follow_flow_range(fd, lifter, /*baddr*/ 0, /*eaddr*/ u64::MAX, &callee_protos)`
   — 新 src 入口,镜像 followFlow 完整 (baddr,eaddr) 形参语义
   (funcdata_op.cc:756);entry 取 `fd.get_address()`(flow.cc:791
   `addrlist.push_back(data.getAddress())`)。
   x86-64 ram space `getHighest()` = 2^64-1 = u64::MAX。
   `follow_flow_with_callee_protos` 保留原签名并委托(baddr=entry),
   getstr_stage_snapshot 等既有调用点零改动。
3. **PLT 内联后的 op 生成**(全部为已移植机制的首次驱动层启用,
   无新 src 语义):BRANCH@0x50fa 目标 0x2530 界内 → SLEIGH(real .sla,
   sleigh_lift.rs)翻译 `endbr64`(零 op)+ `bnd jmp *[rip+X]`@0x2534 →
   BRANCHIND → tablelist → `recover_jump_tables`(flow.cc:1427)→
   partial-clone `stage_jump_table` → `recover_addresses` →
   `sanity_check`(jumptable.cc:2304-2320;Rudra jumptable.rs:4597-4605,
   1 表项且 |target−site|>0xffff 或 target==0 → Thunk)→
   FailThunk(funcdata_block.cc:539-541 catch 的移植)→
   `truncate_indirect_jump`(flow.cc:727-769;Rudra flow.rs:720-778)
   → **CALLIND@0x2534 + artificial RETURN@+1** — 与 oracle drill L94 一致。
4. **META load_mode**(emit_stage_projection :2702):mirror 时发
   `single_function_bfd`(D10 镜像落地条件满足),否则 `single_function_flow`。

## 3. M3 — RUDRA_BARE_LOAD=1(裸 BFD 等价,默认 off)

ACTIVEPARAM-COUNT-9V2-0001 RCA-1 药方:worker :3435
`libc_signatures = LibcSignatureTable::empty()`(新增 glue 空表构造)⇒
(a) PLT-import 签名覆盖(:3475)与 (b) link_call_specs 的 libc 台账
解析(:881)自然变 no-op — 裸 BFD 无 generic_clib 签名数据。
`libc_import_signature`(:657,外部 stub 渲染)不动:不属单函数加载路径。

## 4. 改动清单(行号对照)

| 文件 | 函数 | 动作 | Ghidra 对照 |
|---|---|---|---|
| src/flow.rs | 新 `follow_flow_range` | 新增(完整 baddr/eaddr 形参入口) | funcdata_op.cc:756 followFlow |
| src/flow.rs | `follow_flow_with_callee_protos` | 委托 follow_flow_range(baddr=entry) | 同上(收窄调用形态) |
| src/debugproto.rs | 新 `LibcSignatureTable::empty` | 新增空表 ctor | RUDRA-GLUE(平台侧数据源) |
| examples/curl_decompile.rs | controller :4849 | mirror ⇒ 跳过 shared-return 收集 | — |
| examples/curl_decompile.rs | worker :3435/:3582 | bare-load 空表 / mirror 走 follow_flow_range | — |
| examples/curl_decompile.rs | emit_stage_projection :2702 | load_mode 双态 | STAGE_BISECT_SPEC D10 |
| docs/api/flow.md, docs/api/debugproto.md | — | 同步 | — |

## 5. 验证链(M2/M4)

- `cargo check --lib` → `cargo build --profile fast-release`(example)。
- env 全 off:改前/改后 curl E2E 输出字节一致(防回归门)。
- M4:`RUDRA_STAGE_PROJ=1 RUDRA_STAGE_FUNC=next_url RUDRA_FLOW_MIRROR=1
  RUDRA_BARE_LOAD=1` 重产投影,load_mode=single_function_bfd;
  master 消费端记录新首分歧层(预期 0x2534 CALLIND/RETURN 对消失,
  D9 事件数 335vs479 与 op 集 96457vs129745 显著收窄,如实报告)。
- mirror E2E 全量(curl/httpd)信息性跑,如实记录 skeleton 变化(非门禁)。

---

## 6. M4 验证结果(2026-09-22,wt/sb-rust @ e54fcda)

命令:`RUDRA_STAGE_PROJ=1 RUDRA_STAGE_FUNC=next_url RUDRA_STAGE_PROJ_OUT=…
RUDRA_FLOW_MIRROR=1 RUDRA_BARE_LOAD=1(±RUDRA_ORACLE_FIXTURE_DATA=1)`。

### 投影身份与首分歧(master 消费端 tools/stage_bisect.py --v1)

- META load_mode=`single_function_bfd`(镜像落地,D10 条件满足),身份键全过,
  消费端进入真实逐层比较(此前 V1_META_MISMATCH 硬挡)。
- **PLT 对消失**:oracle 投影首 op `2534:54 CALLIND in=n:ram:16fa0:8` 与人工
  `2534:2cc RETURN` 在 rudra 侧逐字节出现(镜像前 rudra 银行从 `4ff4:0` 开始,
  PLT 对整体缺失,首分歧=完成序 ordinal 1 / op-idx 0)。
- **+RUDRA_ORACLE_FIXTURE_DATA=1**(裸环境第三门,关 FLOW-NORETURN-DATA-0001
  两段):完成序前缀 **0 → 4 个 stage 全字节匹配**;新首分歧 = ordinal 5
  (seq 6 `universal:prototypetypes`,两侧 727 ops)op-idx 1:人工 RETURN
  `2534:2cc` rudra 侧多出第二输入 `n:register:0:8`(RAX 挂上 halt RETURN;
  oracle 侧该值经 INDIRECT `[create]` 群表达,drill L1500-1501)。
  flow 完成 op 数 717 = oracle 717。
- 不加 ORACLE_FIXTURE_DATA(任务最小集):首分歧回到 ordinal 2
  (`universal:start`)——(a) rudra-only `50b8:ab RETURN`(known-no-return
  仿真 halt,raw BFD 无此 analyzer);(b) 5040/506d 块发现顺序旋转
  (SeqNum time 顺序差,noreturn 截流改变 addrlist 演化所致)。

### 数字(如实)

| 指标 | oracle | rudra 镜像前(L2) | rudra MIRROR+BARE | +FIXTURE_DATA |
|---|---|---|---|---|
| 事件数(@BEGIN) | 335 | 479 | 479 | 479 |
| 全 SNAP op 行合计 | 96457 | 129745 | 146770 | 152809 |
| flow 完成 raw ops | 717* | 717* | 718 | **717 = oracle** |
| 完成序全匹配前缀 | — | 0 stage | 0 stage(PLT 对已现,序旋转) | **4 stages** |
| 首分歧 | — | ord 1 / op-idx 0(PLT 缺失) | ord 2(50b8 halt+序旋转) | ord 5 seq 6 prototypetypes(RAX 挂 RETURN) |

*镜像前 flow op 数含出界改写 CALL 对,与 oracle 的 717 同数但集合不同。

op 合计未收窄(96457→152809)的解释:该口径=Σ(每 SNAP 全银行),rudra 后段
银行仍被既有下游分歧(R0 opStackLoad/heritage 族)放大;镜像改变的输入构造层
已收敛(前 4 stage 全等,PLT 对逐字节等)。事件数 335vs479 属 Action 树应用计数
层,不在本 lane 范围。

### E2E(env off / mirror)

- env 全 off:改前/改后全语料 E2E 输出字节一致(cmp 通过,两次,最终二进制复验)。
- RUDRA_FLOW_MIRROR=1 全语料 E2E(信息性,见 /dev/shm/rudra-tests/sb-rust/
  mirror_e2e.c):数字见 commit message;默认门禁不受影响(root 依据 E2E 影响
  数据再裁默认翻转)。
- httpd_decompile 走 inject_raw_ops 线性扫描路径,不读该 env,mirror 不适用。

### E2E 实测数字(信息性,vs tests/golden/ghidra_curl_1204.c)

- env off(默认):skeleton **3711** / defects 0 / numbering 0;改前基线字节一致。
- RUDRA_FLOW_MIRROR=1:skeleton **3824**(+113)/ defects 0 / numbering 0;124/124。
- +113 的主形态:共享返回 override 关闭后,尾跳 PLT 站点按 CALLIND 渲染为
  `(*(code *)PTR_…)(x)`(失去按名解析,如 free/puts;golden 生成环境含
  PLT-thunk analyzer,raw BFD 语义本就无名字层)+ frame_dummy 返回恢复
  (void→long)与少量文本平移。镜像模式下这些站点的名字层属后续消费侧课题。

---

## 7. M5 — MIRROR-ENVS-CANONICAL-0001:RUDRA_MIRROR 一键 bundle + 目标 DWARF 锁抑制(2026-09-22,wt/sb-rust @ c5a8992+)

### 7.1 动机

镜像态此前需要三个 env 精确组合(`RUDRA_FLOW_MIRROR=1 RUDRA_BARE_LOAD=1
RUDRA_ORACLE_FIXTURE_DATA=1`,DELTA_V2 §0/§6),且仍残留一处观测阻断:
驱动在反编译前把**目标函数自身**的 DWARF 锁定原型装入
(`debug_db.apply(&mut fd)`,set_pieces 三锁 input+output+model)→
`ActionPrototypeTypes` 走锁定臂(coreaction.cc:4637-4649)在 prototypetypes
阶段给每个人工 RETURN 提前挂自由 RAX 读;oracle 裸 BFD harness 无任何
签名源,走 `initActiveOutput`(coreaction.cc:4651),RAX/RDX 迟至 heritage
guardReturns 才挂、returnrecovery 裁 RDX。终态双侧逐字节等价,但过程表达
差把消费端首分歧钉死在 prototypetypes(RETURN-ARTIFICIAL-RAX-0001,
RAX_RETURN.md §3.1 实证链:mirror_drill.stderr:118)。

### 7.2 RUDRA_MIRROR 语义(单一真源 = examples/curl_decompile.rs 四访问器)

| 访问器 | 展开 | 生效点 |
|---|---|---|
| `mirror_bundle_enabled()` | `RUDRA_MIRROR`(presence) | 目标 DWARF 原型抑制(§7.3) |
| `mirror_flow_enabled()` | bundle ∨ `RUDRA_FLOW_MIRROR` | 全段 SLEIGH 镜像、follow_flow_range(0,u64::MAX)、controller shared-return 跳过、load_mode=single_function_bfd |
| `mirror_bare_load_enabled()` | bundle ∨ `RUDRA_BARE_LOAD` | libc 签名台账清空(PLT-import 覆盖与 link_call_specs 解析变 no-op);**program-DB 数据符号层抑制**(SB-ORD185-CONSTANTPTR-0001:worker 侧 rodata DAT/ELF OBJECT/DWARF globals 不装库,仅留 cspec `<global>` range + loader readonly range,镜像 oracle `readLoaderSymbols` 全 `addFunction` 的裸 BFD 环境) |
| `mirror_fixture_data_enabled()` | bundle ∨ `RUDRA_ORACLE_FIXTURE_DATA` | known-no-return 两段(函数属性位 + flow callee 表)关闭 |

- `RUDRA_MIRROR=1` = 三组件全集 + 目标 DWARF 抑制,一键即镜像态。
- 旧三 env 保留组件级 A/B 兼容:单独设置时语义与 c5a8992 **逐字节不变**
  (三 env 齐设重产投影与旧 mirror 投影 sha 全等 `f7acbff2…`,stderr 仍打
  `applied locked DWARF prototype: 1 params`)。
  **erratum(SB-ORD185-CONSTANTPTR-0001, 2026-09-22)**:`RUDRA_BARE_LOAD`
  单独语义自本修复起**扩展**——追 ordinal 185(constantptr 0vs4)根因时发现
  bare-BFD 数据环境还包含"loader 符号全注册为函数"(architecture.cc:346-359),
  即全局 scope 零数据 SymbolEntry,`queryContainer`(coreaction.cc:1151)恒
  NULL;故 BARE_LOAD 现同时关闭 program-DB 数据符号层(默认 E2E 路径零变化,
  curl/httpd skeleton 与基线逐字节相等)。旧行为(数据层保留)本身是
  pre-existing 分歧源,不属于"组件语义"。
- worker 子进程经 `Command::new` 继承环境,无需传递。

### 7.3 目标 DWARF 锁抑制(仅 bundle 键)

mirror bundle 下跳过 `debug_db.apply(&mut fd)`(目标函数自身原型);
stderr 打 `[PREPASS] <fn> mirror: target DWARF prototype lock suppressed`。
callee 侧无需处理:BARE_LOAD 已清 libc 表,next_url 的 9 个 callee 全是
import(`locked_callsite_proto` 贡献恒 0)。非 mirror 路径(默认 E2E 与
任一 legacy env 单独)行为零变化。

### 7.4 验证(全部产物 /dev/shm/rudra-tests/sb-rust/m5/)

| 门 | 结果 |
|---|---|
| env 全 off 字节一致 | pre/post 全语料 E2E sha `023d6ab5…` 全等(=历史 envoff 基线) |
| RUDRA_MIRROR=1 投影身份 | META load_mode=single_function_bfd,master `stage_bisect.py --v1` 身份键全过(仅 producer/unique_base 非阻断 warning) |
| **新首分歧** | **stage ordinal 7 / seq 7 `universal:funclink` op-idx 4**:`2534:2e8 LOAD` oracle `in=s:ram,u:10000048:8` vs rudra `in=c:5:1,u:10000048:8` —— FUNCDATA-SPACEID-WIDTH-0001 族(DELTA_V2 punch list #8),从 ordinal 6/seq 6 prototypetypes 后移 |
| RAX 挂载路径(AV 预期) | prototypetypes 零提前挂载(仅 `return(RIP(free))→return(#0x0)` indicator 剥离,drill @BEGIN 5);**heritage(seq 12)挂 RAX+RDX 双输入**;**returnrecovery(seq 128)裁 RDX**;终态 `c:1:4,n:register:0:8` 不变 |
| returnrecovery 域点亮 | @BEGIN returnrecovery=12 / activereturn=4 / starttypes=4 次调用,@END seq 19/128 `result=1 count=1 apply=1` |
| ΣSNAP | 152809 → 148723(−4086);@BEGIN 479 不变(树遍历结构未变) |

### 7.5 遗留(不在本 lane)

- 首分歧现落于 FUNCDATA-SPACEID-WIDTH-0001(LOAD spaceid `c:5:1` vs
  `s:ram`),修复归 funcdata+root 归因(punch list #8)。
- 事件数 479 vs 335 未变:mainloop 12 pass / COPY churn(H1/H2)不属
  本项;activeparam 重燃相位(D14 RCA-2)待 fspec 探针。
