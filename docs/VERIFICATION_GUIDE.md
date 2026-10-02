# Rudra-Ghid
ra 验证指南

> **
状态声明**：截至当前仓库可见代码与文档状态，
Rudra 的验证体系仍处于
**未完成**阶段。  
> 已经具备一部分静态对齐测试与运行时验证框架代码，但**不能据
此宣称**已经完成了与 Ghidra 的端到端一致性验证，也**不能宣称**当前输出与 Ghidra 100% 等价。

本文档用于说明：

1. 当前已经具备哪些验证能力
2. 哪些关键验证
仍未真正落地
3. 如何区分“静态对齐”与“运行时
对拍”
4. 当前阶段建议采用什么验证路径
5.
 5. 阅读和更新本文件时应避免哪些失真表述
 6. 如何为验证类结论补充证据来源

> 机器门禁入口与本文件较早的历史说明并存时，以
> `tests/oracle/fixture_registry.json`、`tools/select_fixtures.py` 和生成式
> `docs/alignment_audit/FUNCTION_LEDGER.json` 为准。未登记 fixture 的源码改动不是
> “无需测试”，而是 coverage gap。

### 差分诊断工具链后续计划（2026-08-14）

详细实施方案见
[`docs/alignment_audit/DIFFERENTIAL_ALIGNMENT_TOOLING_PLAN_2026-08-14.md`](alignment_audit/DIFFERENTIAL_ALIGNMENT_TOOLING_PLAN_2026-08-14.md)。
计划已拆入 `docs/TODO_BOARD.md` 的稳定 ID。下图表示硬依赖；互不相连的分支可以并行，
不是一条强制串行链：

```text
稳定函数 ID → registry/schema → metadata 四态迁移 → strict gate/CI → 函数 evidence
cache hardening ───────────────┐
registry/schema ───────────────┴→ 标准 oracle result
标准 oracle result + strict gate/CI → runner 全量迁移
标准 oracle result → IR invariant → Action/Rule trace → hang triage
函数 evidence + oracle result → P-code/CFG DSL → fuzz → reducer → corpus promotion
reducer hardening ────────────────────────────────────────┘

既有 `PIPE-TREE-0001` 是 Action trace 的已满足前置，`RUNTIME-TIMEOUT-0001` 是 hang triage
的已满足前置；精确 DAG 以计划文档和 TODO 行为准。
```

审计基线显示工作树可见 32 套 metadata/runner，但正式 registry 只登记 12 套；现有
`stage_diff.py` 主要定位到阶段 hash，现有 `reduce_fixture.py` 也只做删除式 JSON/hex ddmin。
因此近期优先目标是统一事实源并自动定位首个错误 mutation，而不是直接扩大完整二进制 fuzz。
顶层 fixture 状态继续严格采用 B2 的 `MATCH/MISMATCH/NO_ORACLE/UNTESTED`；局部已匹配部分
只能记为 observation 级证据，不能以 `PARTIAL_MATCH` 冒充新的顶层状态。迁移旧
`PARTIAL_MATCH` 时必须逐 fixture 判定：已有双侧差异记 `MISMATCH`，双侧已测部分相等但
覆盖不完整记 `UNTESTED`，缺少合法同输入双侧 oracle 记 `NO_ORACLE`；不得一刀切。

### 机器化四级入口（2026-08-12）

日常验证统一通过以下入口，避免每次人工拼接一整套命令：

```bash
python3 tools/rudra_gate.py edit
python3 tools/rudra_gate.py commit --staged
python3 tools/rudra_gate.py wave
python3 tools/rudra_gate.py nightly
```

`edit` 只做秒级反馈；`commit` 增加全静态检查、生成账本检查和受影响的真实 oracle
fixture；`wave` 运行全部 fixture、全目标测试和 curl/httpd 回归；`nightly` 再加入
fresh-target canonical release 构建。每一级都可用 `--report` 保存结构化 JSON。

门禁不会因 selector 未找到 fixture 而静默跳过：`commit` 以上层级对 coverage gap
返回 2。`--dry-run` 可审计将执行的命令，但不能作为通过证据。

昂贵 fixture 和 pipeline stage 可通过 `tools/oracle_cache.py` 内容寻址复用。cache key
必须包含锁定 commit、architecture、compiler spec、analysis options、输入、runner 和
两侧 comparand 的真实 hash；cache hit 仍重新验证 provenance 和 artifact hash。缓存只减少
重复编译/执行，不改变 `MATCH/MISMATCH/NO_ORACLE/UNTESTED` 的判定，也不能补齐未覆盖分支。

端到端输出不同时，先用 `tools/stage_diff.py snapshot` 保存两侧同一输入的有序阶段 artifact，
再用 `compare` 定位第一个差异。原始 stage hash 是诊断索引，不是行为证明；只有该阶段完整
观察结果及其所有状态突变同输入零差异时，映射函数才可记 `MATCH`。

`GetStr` 已有历史六层 fixture，但截至 2026-08-14 **不能作为当前源码可直接运行的证据**。
metadata 固定的 Rust comparand SHA 为 `bfcadc80…`，当前文件为 `8e74e438…`，因此以下命令会在
provenance 预检阶段 fail-closed，而不是产出当前诊断：

```bash
tools/run_getstr_pipeline_oracle.sh
```

历史结果写入 `result/pipeline_snapshots/getstr/`：`ghidra/`、`rudra/` 和
`rudra-repeat/` 分别保存 raw P-code、CFG、Heritage/SSA、完整 Action IR、结构树和 C 文本；
`comparison.json` 保存每层首个 JSON 路径差异，`README.md` 给出紧凑摘要，`ghidra.c`、
`rudra.c` 与 `rudra-repeat.c` 可阅读。历史报告为 `MISMATCH`，不是 golden；它曾记录两侧
103 ops / 272 Varnodes / 6 CFG blocks，但审计确认旧 runner 实际没有比较其声明中的
`has_output`，并且 `zip` 未检查尾部长度，因此这些字段不能继续作为完整同输出证明。

历史 raw 层也不是 `MATCH`：第一个 op-storage 差异位于 direct CALL，Ghidra 用动态 Fspec
space index 5，Rudra 因固定 `AddressSpace` 模型只能用 synthetic Iop index 7；第一个
Varnode-state 差异是 Ghidra 已附 unknown datatype/COVERDIRTY，而 Rudra 尚未附这些状态。
此外 Ghidra 侧实际载入完整 gcc cspec，而当前 Rust companion 没有消费同一 cspec；新的
`00_effective_configuration` preflight 在这一差异关闭前必须报告 `NO_ORACLE`，不得继续解释
后续 IR 差异。`ORACLE-RESULT-0001` 将拆分 `--verify-recorded`、`--diagnose-current` 和审核后的
`--accept`，在该任务完成前不要把旧 runner 的失败描述成“最新反编译结果”。

历史 fixture 使用 release profile。debug Action 路径会暴露
`VARMAP-GATHEROFFSET-0001` 与 `RULE-COLLECTTERMS-0001` 两个核心无符号边界缺陷；因为它们
尚未完成独立核心复核，本 snapshot 不把 release 成功冒充对应分支 `MATCH`。

Ghidra 的 Heritage 快照来自真实 `decompile` Action 在 `paramdouble` 前的 breakpoint；Rudra
目前只能直接重放 `ActionHeritage`，所以该层明确是 `NO_ORACLE` 诊断边界。只有补齐同一
Action-tree 观察点并在完整状态上零差异，才能将该层改记 `MATCH`。

首差异定位后，可用 `tools/reduce_fixture.py` 缩减输入。predicate 必须运行真实两侧 fixture，
并以结构化 `predicate_signature` 区分同一故障、不同故障、非法 candidate 与 harness error；
不能只看 exit code，也不得把手写 expected 当 oracle。reducer trace 是诊断证据，最终最小 case
仍须补齐 commit/arch/cspec/options/input 指纹并进入 B2 runner。

---

## 1
. 验证目标

Rudra 的验证工作不是单一测试，而是分层目标：

- **结构层验证**：核心数据结构是否与 Ghidra 的概念模型基本对齐
- **算法层验证**：P-code、SSA、CFG、类型传播等核心算法行为是否一致
- **输出层验证**：最终伪 C 输出在语义上是否接近或等价
- **回归层验证**：修改后是否破坏现有行为

当前项目**已在结构层迈出了一部分**，但**算法层与输出层仍未完成**。

---

## 2. 当前可确认的真实状态

结合当前代码与文档，项目验证现状应按以下方式理解。

### 2.1 已具备的部分

#### A. 静态对齐测试存在
`src/align/` 下已经存在若干面向 Ghidra 核心概念的对齐模块，例如：

- `address.rs`
- `varnode.rs`
- `pcodeop.rs`
- `datatype.rs`
- `range.rs`
- `heritage.rs`
- `block.rs`
- `action.rs`

这些模块说明项目已经围绕 Ghidra 的概念模型开展了映射与验证工作。

#### B. 运行时验证框架代码存在
`src/align/runtime_verify.rs` 已经存在，说明项目已经开始设计运行时比对框架，框架中可见的目标包括：

- 常量求值比对
- P-code 生成比对
- SSA 版本验证
- CFG 结构验证
- 差异记录与统计

但这只能说明“**框架方向存在**”，**不能直接等价于验证已经完成**。  
按当前最近一次最小样本推进记录看，`mov rbx, rax` 这条样本已经从“框架级真实运行记录”进一步推进到：比较入口能够接收 **真实 opcode、真实 output、真实 input 列表**，并由 `verify_pcode_generation(...)` 基于结构化本地比较结果返回 `Match` 或 `Mismatch(...)`，不再无条件返回 `Match`。  
进一步地，当前比较入口也已经不再只是 stdout 日志副作用：`rudra_compare_pcode(...)` 现在会返回结构化比较状态，调用侧可以区分 `match`、`opcode mismatch`、`output mismatch`、`input count mismatch`、`input mismatch`、`missing Rudra op` 等结果类型。

#### C. FFI 相关代码存在
仓库中存在 `src/ffi.rs`，且运行时验证框架中引用了 FFI 接口。这说明项目确实计划走“Rust 实现 ↔ Ghidra/相关原生能力”的跨边界验证路线。

---

### 2.2 明确未完成的部分

以下事项目前**不能**视为已完成：

#### A. 不能确认运行时对拍已经全面打通
虽然有 `runtime_verify.rs`，但从可见代码来看，若干逻辑仍处于框架、占位、简化比较或待环境集成状态，不能视为“已稳定可用的完整运行时验证体系”。

#### B. 不能确认 Ghidra FFI 集成已经形成稳定工作流
当前仓库有相关接口与文档描述，但不能据此断言：

- 已完成全部链接配置
- 已在本地/CI 中稳定运行
- 已有大规模真实样本验证结果
- 已得到可靠的一致性统计

#### C. 不能确认 SSA / CFG / P-code 已与 Ghidra 严格一致
这些是反编译器的核心语义层。  
除非存在真实运行结果、稳定测试样本和明确统计，否则不能写成“已保障一致性”。

#### D. 不能确认端到端输出验证已完成
当前不能把“能够生成某些 C 风格输出”表述为：

- 已完成与 Ghidra 输出对比
- 已经语义等价
- 已达到 1:1 对齐
- 已达到生产级完全可信

---

## 3. 验证层级划分

为了避免文档失真，项目中的“验证”应严格分层描述。

### Level 1：静态结构对齐
目标：验证 Rust 中的数据结构、字段语义、基本行为与 Ghidra 概念模型相近。

典型对象：

- `Address`
- `SeqNum`
- `Varnode`
- `PcodeOp`
- `DataType`
- `Range`
- `RangeList`

这一层能说明：

- 模型命名和字段组织较接近
- 某些基础行为有单元测试覆盖
- 为后续算法对齐提供了基础

这一层**不能说明**：

- 算法行为已一致
- 反编译输出已一致
- 整体系统已经通过对拍

---

### Level 2：运行时局部对拍
目标：在受控输入下，对某一局部行为做比较。

可能包括：

- 常量折叠结果
- 单条指令的 P-code 序列
- 单个函数的 SSA 版本分配
- 单个函数的基本块划分

这一层如果未来真正落地，才有资格讨论：

- 哪些局部行为一致
- 哪些局部行为存在偏差
- 差异集中在哪个算法阶段

当前这一层已经不再只是纯占位框架：至少在第一条最小样本 `mov rbx, rax` 上，Rudra 侧已经能够把真实的 opcode / output / input 元数据送入比较层，比较入口也已经能够返回结构化状态码，随后再由 `verify_pcode_generation(...)` 汇总为 `VerifyResult`。  
但这一层**仍然不能被表述为已完成**，因为当前比较虽然已经具备“结构化返回路径”，参考数据仍主要来自 Rudra 侧本地构造与当前程序态，并不等价于“已接入稳定、完整、可信的 Ghidra 参考侧逐字段结果”。

---

### Level 3：端到端语义验证
目标：针对真实二进制，比较整个函数或程序的反编译结果。

可能比较内容：

- 控制流结构是否接近
- 调用参数与返回值恢复是否接近
- 变量恢复是否合理
- 伪 C 代码语义是否等价

这一层是最难的，也最接近用户真实感知质量。  
**当前不能宣称这一层已经完成。**

---

### Level 4：持续回归验证
目标：每次改动后快速发现回归。

理想形态包括：

- `cargo test`
- 指定模块测试
- 对齐模块测试
- 示例样本回归
- 未来可能加入的 FFI/样本级验证

这一层是项目走向稳定工程化的关键，但当前仍应视为**持续建设中**。

#### Level 4 已落地资产：投影 fixture 银行（2026-09-25 扩至 391 条）

`tests/fixtures/projections/` 固化了 71 个函数的锁 oracle / Rudra 双侧
stage projection（v1.2），每函数一个目录（oracle.projection +
rudra.projection + manifest.toml，记录 oracle commit e40ed130、capture
命令、日期、sha256 pin 与验证状态）。门禁入口：

```bash
tools/verify_projection_bank.sh        # 全部条目；sha256 完整性 + run_stage_bisect --v1 全 MATCH 才退出 0
```

当前条目：next_url / match_url / parseconfig.constprop.0 / myprogress /
getparameter.constprop.0 / glob_set / glob_word / file2string.part.0 /
my_get_token / glob_range（前 10 条逐 lane 入库），HARVEST 级联收割
批 15 条：main_free / main_init / SetHTTPrequest.part.0 / SetHTTPrequest /
glob_url / frame_dummy / __do_global_dtors_aux / _init / _fini /
__libc_csu_fini / __libc_csu_init / deregister_tm_clones /
register_tm_clones / GetStr / my_fwrite，helpf（PM-HF），以及 ADDRARM2
（2026-09-25）经 oracle harness **地址-only 臂**收割的 PLT-thunk 全量
45 条（PLT0 + .plt.got + 43 个 .plt.sec 桩，runner 函数名位置传 `-`，
fixture 按控制台 `load <addr>` 语义在入口注册函数；全部首验即 MATCH；
首分歧残差与地址臂机制见银行 README）。结构、重捕获 recipe 与新增条目
流程见 `tests/fixtures/projections/README.md`。

httpd 侧同族 PLT-thunk 总群已于 2026-09-25 全量入库（lane HBANK 盘点
+ oracle 侧 320 条捕获，lane HBANK2 解锁驱动并批量入库）：320 条
（PLT0 @0x29020 + 2 个 .plt.got + 317 个 .plt.sec，形态同 curl——
186/742 桩与 191/1240 PLT0）**全部首验即 MATCH**，银行 71→391。
解锁形态 = 驱动 stage 门内 PLT-thunk 账本臂（`HBANK-DRIVER-STAGELEDGER-
0001` 已收口，commit 534f9802）：.plt 头 PLT0（golden 拼写
`FUN_00129020`）+ .plt.got 槽位 GOT-tail 解码（bnd/plain 两种拼写，
httpd 为 plain `ff 25`）+ .plt.sec 槽 i 对第 i 条 .rela.plt JUMP_SLOT，
账本 793 = 473 dynsym + 320 thunk；地址形 selector
`RUDRA_STAGE_FUNC=0x<entry>` 可选 thunk。臂仅扩 selector 面：stage 门内
生效、落在所有其他账本消费者之后，env 全 unset 的默认 E2E 输出与亲父
构建 cmp 字节恒等（stderr 唯一差异是亲父自身两次运行也出现的
`[INJECT]` 日志交错序，非本改动引入）。详见银行 README httpd 节。

#### Level 4 补充资产：varmap gatheropen/guard 双侧 fixture 的 untyped 臂（2026-09-25，RANGEHINT-CR-F1）

`tests/oracle/varmap_gatheropen_guard_1204.{cc,rs}` 是 MapState::addGuard /
gatherSymbols / deriveBoundaries / annotateRawStackPtr / checkUnaliasedReturn
的双侧函数级 fixture（R23 复核在案：hermetic runner 与 metadata.json 缺失，
重钉义务仍在）。2026-09-25（Lane F1FIX）补第 7/8 两 case，把 Rust 侧
add_guard 的 **None-ct 臂**（untyped 地址 varnode，v_type 不设类型）从
UNTESTED 升为锁定 oracle 对照 MATCH：

- `case=guard_untyped_hints`：untyped 地址输入的 LOAD/STORE 锁场景走生产
  restructureVarnode 路径，产出 `unk2[16]@-0xe0`（32B）/ `unk4[16]@-0xc0`
  （64B）/ `unk8[16]@-0x80`（128B）；outSize>step 的 LOAD 仍被拒绝且无痕
  （varmap.cc:1020-1023 门在 None 臂上不失效）。
- `case=guard_untyped_dump`：同四 guard 直喂手工构造的 MapState（镜像
  varmap.cc:1260-1261 构造 + param-range 扣除），按 gatherOpen 插入序
  （先 loadGuard 后 storeGuard）逐字段 dump RangeHint：start/sstart/size/
  flags/rangeType/highind/类型 token。锁定输出：
  `ffffffffffffff80:-128:8:0:1:15:unk8;ffffffffffffff40:-192:4:0:1:3:unk4;ffffffffffffff20:-224:2:0:1:3:unk2`
  —— `unk8` 即 None 臂代入的工厂 unknown 基（宽=地址 varnode 宽 8，
  funcdata_varnode.cc:83-93 的 oracle 值），在 step==元素宽时无替换存活
  （highind=0x80/8-1=15）；`unk4/unk2` 为 outSize 整除重定宽 + step 替换臂
  （highind=3）。

判定：8 case 全量 stdout **双侧字节恒等**（sha256 =
`1511c6a41deb001da19bdf706d1b783bc98b0ae35675e6d6e44a6ab505e5640b`，双侧
各双跑恒等）；前 7 行（envelope + 原 6 case）仍等于 R23 复核钉的
`3b5e1b652697a3102edfad14df2211e6adb9c9cdb3e768faf9c1e76261b97494`
（aliasyes=true 编译刷新零行为位移）。建模假设（登记）：**Rust
`v_type=None` ⟺ oracle untyped varnode**（newUnique 无 updateType 时工厂
`getBase(s,TYPE_UNKNOWN)` 恒带类型；类型传播 parity 前属有界严格减损分歧）。
类型 token（`unkN` = metatype + 元素宽）规避双侧工厂对 unknown 基的不同拼写
（oracle fixture `xunknownN` vs Rust 工厂 `undefinedN`）。复现配方：oracle 侧
git-archive 锁定 commit 干净重编 libdecomp.a（勿复用带 `-DOPACTION_DEBUG` 的
对象树）后按 varmap_localwindow runner 同款 g++ 命令链接；Rudra 侧
`cargo build --lib` 后 rustc 挂 librudra.rlib 编译 .rs；证据归档
`/dev/shm/rudra-tests/f1fix/`。

---

## 4. 当前建议采用的验证策略

在运行时对拍尚未完全落地前，建议使用“**保守、分层、可复现**”的验证路线。

### 第一步：先保证普通 Rust 测试可运行
优先确保基础测试不退化：

```text
cargo test
```

如果某次改动只影响某个局部模块，应优先运行该模块相关测试。

---

### 第二步：运行对齐相关测试
针对 `align` 相关模块运行聚焦测试，确认结构层行为未退化。

可按实际测试命名运行类似：

```text
cargo test --lib align::
```

或更细粒度地针对具体子模块执行。

> 注意：是否能够直接使用某条命令，取决于当前工程内测试命名、feature 和平台环境。  
> 文档中不应把“可能可运行”写成“已经稳定跑通”。

---

### 第三步：检查运行时验证框架是否仍可编译
当修改了 `src/align/runtime_verify.rs`、`src/ffi.rs` 或对齐模块时，至少应确认：

- 代码仍然可编译
- 接口没有失配
- 没有因为签名变更导致框架彻底失效

如果运行时验证尚未可执行，也应至少保持“框架不被进一步破坏”。

---

### 第四步：先用最小样本维持局部验证链路

在端到端样本恢复之前，建议优先维护“单条指令 / 小型指令序列”的最小验证记录，例如：

- `mov rbx, rax`
- `add rax, 1`
- `sub rax, 8`

这类样本的价值在于：

- 可以稳定复现输入字节与预期 lifting 结果
- 可以把问题限定在 `disasm -> x86_lift -> pcoderaw -> funcdata -> runtime_verify -> ffi` 的最小链路
- 可以更清楚地区分：
  - 入口是否可执行
  - 比较参数是否真实
  - 结果是否被结构化回传
  - 当前差异究竟来自 Rudra 侧实现，还是参考侧数据仍未真正接入

> 这类最小样本属于 **Level 2：运行时局部对拍** 的基础建设。  
> 即使某条样本通过，也**不能**直接外推出“更大范围样本已完成一致性验证”。

---

### 第五步：针对示例和样本做人工审阅
对于当前阶段，人工审阅仍然重要。可结合：

- `examples/`
- 反编译输出样本
- `CURRENT_STATUS.md`
- `GAP_ANALYSIS.md`

重点确认：

- 输出是否明显退化
- 控制流是否出现明显错误
- 是否引入新的无意义变量碎片
- 是否出现明显错误的调用恢复

这类检查属于“人工质量审阅”，**不能冒充自动一致性验证**。

---

## 4.1 第一条最小 P-code 样本记录：`mov rbx, rax`

为了把“最小 P-code 对拍重入计划”从草案推进到真实记录，当前已经补入第一条最小样本的可执行记录口径。

### 样本信息

- **样本 ID**：`PCode-Min-001`
- **目标层级**：`Level 2：运行时局部对拍`
- **机器码**：`48 89 c3`
- **汇编文本**：`mov rbx, rax`
- **Rudra 入口链路**：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`

  ### 当前可确认的真实结果

  基于当前仓库中的最小测试链路，这条样本已经能够完成以下步骤：

  1. 反汇编得到单条 `mov rbx, rax`
  2. `X86Lifter` 生成 1 条 raw P-code
  3. 该 raw P-code 的 opcode 为 `CPUI_COPY`
  4. 输出 varnode 为寄存器空间 `rbx`
     - offset: `0x18`
     - size: `8`
  5. 输入 varnode 为寄存器空间 `rax`
     - offset: `0x00`
     - size: `8`
  6. `Funcdata::inject_raw_ops(...)` 后：
     - op 数量为 `1`
     - basic block 数量为 `1`
  7. `verify_pcode_generation(...)` 在给定 `ghidra_op_count = 1` 时返回 `Match`

  ### 当前仍需明确区分的限制

这条记录**不能**被解读为“已经与 Ghidra 完整对齐”，但它也已经不再停留在最早的纯占位比较阶段。当前更准确的边界是：

- 当前不再只是 op 数量比较，比较入口已能消费：
  - opcode
  - output varnode
  - input varnode 列表
- 当前比较入口已能返回结构化状态，而不只是打印日志
- 当前 `verify_pcode_generation(...)` 已会消费该结构化状态，并据此生成 `Match` / `Mismatch(...)`

但以下限制仍然存在：

- 当前参考信息仍主要来自 Rudra 侧本地构造，而不是 Ghidra 独立返回的结构化结果
- 当前还没有形成“Ghidra 参考侧结果 -> 结构化返回 -> 统一差异报告”的完整双边闭环
- 当前仍不能把最小样本的本地结构化通过，外推出更大范围的真实 parity 结论

因此，这条样本当前更准确的结论是：

> **Rudra 已经具备第一条最小 `mov reg, reg` 样本的本地可执行验证记录，**
> **并已具备结构化 FFI 比较返回路径，**
> **但目前仍处于“局部结构化验证已建立、真实 Ghidra 侧独立参考尚未完整接入”的阶段。**

### 当前差异分类

建议把这条样本当前归类为：

- `已可运行`
- `已形成真实记录`
- `比较入口已触发`
- `已具备结构化 FFI 返回路径`
- `尚未形成真实 Ghidra 侧逐字段对拍`

### 证据来源

- 代码入口：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`
- 当前最小样本测试：
  - `src/funcdata.rs` 中新增的 `test_mov_reg_reg_minimal_alignment_path`
- 本地测试现象：
  - 测试通过
  - 同时输出一条比较入口日志，表明当前 FFI 比较仍在使用占位参考信息

### 下一步最小动作

围绕这条样本，后续最优先的动作应是：

1. 让比较入口返回的不只是状态码，还能携带更细粒度的结构化差异信息
2. 让 `verify_pcode_generation(...)` 消费来自参考侧的独立结果，而不是主要依赖 Rudra 本地构造数据
3. 将当前“已具备结构化返回路径”的状态，推进到真正的双边逐字段比较
4. 在完成后，再复制同样流程到：
   - `add rax, 1`
   - `sub rax, 8`

---

## 4.2 第二条最小 P-code 样本记录：`add rax, 1`

在继续推进最小 P-code 对拍重入计划时，当前已经补入第二条样本 `add rax, 1` 的失败记录。  
这条记录的价值不在于“验证通过”，而在于它第一次把算术类 opcode 的最小链路差异明确暴露出来。

### 样本信息

- **样本 ID**：`PCode-Min-002`
- **目标层级**：`Level 2：运行时局部对拍`
- **机器码**：`48 83 c0 01`
- **汇编文本**：`add rax, 1`
- **Rudra 入口链路**：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`

### 当前可确认的真实结果

基于当前仓库中的最小测试链路，这条样本已经能够完成以下步骤：

1. 反汇编得到单条 `add rax, 1`
2. `X86Lifter` 当前为其生成 `2` 条 raw P-code
3. 第一条 raw P-code 为：
   - opcode = `CPUI_INT_ADD`
   - output = unique 临时 varnode
   - inputs = `rax` 与常量 `1`
4. 第二条 raw P-code 为：
   - opcode = `CPUI_COPY`
   - output = `rax`
   - input = 上一步的 unique 临时 varnode
5. `Funcdata::inject_raw_ops(...)` 后：
   - op 数量为 `2`
   - basic block 数量为 `1`

### 当前失败现象

这条样本当前**尚未通过**最小局部验证。  
按最近一次测试记录，运行时日志中已经出现了两类明确差异：

1. 第一条 op 地址处出现 opcode mismatch：
   - `Opcode mismatch. Ghidra Op: 4`
2. 第二条 op 地址处出现输入比较失败：
   - `Input mismatch at index 0`
   - 当前日志中表现为 unique 输入在空间/偏移比较上与参考侧口径未对齐

对应地，最小测试当前返回失败，而不是 `VerifyResult::Match`。

### 当前最准确的结论

这条样本当前应被描述为：

- `已可运行`
- `已形成失败记录`
- `已暴露算术类 opcode 路径中的局部比较错位`
- `尚未形成局部对拍通过记录`

换句话说：

> `add rax, 1` 已从“计划样本”推进为“真实失败样本记录”，  
> 但当前结果表明 Rudra 侧 lifting 产物、FFI 比较口径或参考数据组织之间仍存在错位，尚不能写成局部 parity 已建立。

### 当前差异分类

建议把这条样本当前归类为：

- `已可运行`
- `已形成真实失败记录`
- `算术类 opcode 已进入最小验证范围`
- `当前存在 opcode 比较错位`
- `当前存在 unique 输入比较错位`
- `尚未形成真实 Ghidra 侧逐字段对拍通过结果`

### 证据来源

- 代码入口：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`
- 当前最小样本测试：
  - `src/funcdata.rs` 中新增的 `test_add_rax_imm_minimal_alignment_path`
- 本地测试现象：
  - `Opcode mismatch. Ghidra Op: 4`
  - `Input mismatch at index 0`
  - 最终测试失败

### 下一步最小动作

围绕这条样本，后续最优先的动作应是：

1. 先确认当前 `add rax, 1` 的两条 op 是否就是 Rudra 侧期望的最小表示
2. 继续检查 opcode 比较错位为何表现为 `Ghidra Op: 4`
3. 继续检查 unique 输入在 FFI 比较中的空间 ID / 偏移口径
4. 先把该样本从“失败记录”推进到“局部结构化比较可通过”
5. 再继续推进：
   - `sub rax, 8`

---

## 5. 验证结论的证据来源规则

为了避免把“计划中”“框架存在”“局部观察”写成既成事实，后续更新本文件时，所有高风险验证结论都应尽量附带**证据来源**。  
这里的“证据来源”不是要求写成长篇证明，而是要求让读者能够追溯：

- 该结论依据了哪类文件或结果
- 该结论属于结构层、局部运行时对拍，还是端到端观察
- 该结论是“已验证”“待验证”还是“仅有框架/入口”

### 5.1 哪些结论必须补证据来源
以下类型的表述，后续都应尽量补充证据来源说明：

- “某验证已完成”
- “某行为已与 Ghidra 一致”
- “某项运行时对拍已通过”
- “某条最小样本已形成真实记录”
- “某条样本只达到框架级比较”
- “某个输出质量已提升”
- “某项 FFI 验证已打通”
- “某项差异已定位/已消除”
- “某命令可以稳定复现某结果”

如果暂时无法给出证据来源，应该降级表述为：

- “当前仓库可见代码表明……”
- “已存在相关框架/入口，但尚待实测……”
- “按现有文档与代码判断……”
- “尚缺可复现的运行结果支撑……”

### 5.2 可接受的证据来源类型
可作为验证结论依据的材料包括：

- **源码文件**
  - 例如 `src/align/runtime_verify.rs`
  - 例如 `src/ffi.rs`
  - 例如 `src/align/*.rs`
- **测试**
  - 单元测试
  - 集成测试
  - `cargo test` 的可复现结果
- **示例 / 样本**
  - `examples/` 下的样本运行
  - 指定真实二进制样本的实验记录
- **文档化实验记录**
  - `docs/archive/agentlog/`
  - `docs/experiments/`
  - 未来的差异报告或验证记录
- **人工审阅结果**
  - 仅可用于说明“观察到某现象”
  - 不应冒充自动化运行时一致性验证

### 5.3 推荐写法
后续若需要在本文件中写入验证结论，建议尽量采用类似格式：

- **结论**：当前已存在 SSA 运行时验证框架入口  
  **证据来源**：`src/align/runtime_verify.rs`、`src/ffi.rs`

- **结论**：当前仅能确认静态结构对齐已建立，尚不能确认运行时一致  
  **证据来源**：`src/align/address.rs`、`src/align/varnode.rs`、`ALIGNMENT_PROGRESS.md`

- **结论**：某示例输出在人工审阅下看起来更接近 C 风格  
  **证据来源**：`examples/` 运行结果、对应会话日志、人工审阅记录  
  **说明**：这不等于已完成端到端语义等价验证

### 5.4 不可接受的写法
以下写法在没有明确证据来源时应避免：

- “已经完全验证”
- “已经 100% 一致”
- “所有对拍都已通过”
- “输出已经达到 Ghidra 水平”
- “FFI 已稳定打通”
- “验证体系已完成闭环”

除非同时能指出：

- 对应代码入口
- 可执行路径
- 样本或测试结果
- 差异是否仍存在

### 5.5 最低要求
即使不补完整的“证据来源”小节，后续至少也应做到：

1. 能指出相关代码文件  
2. 能说明属于哪个验证层级  
3. 能明确是“框架存在”还是“结果已验证”  
4. 能区分自动验证与人工观察

---

## 6. `runtime_verify.rs` 应如何被正确描述

当前对 `src/align/runtime_verify.rs` 的正确表述应是：

> 它是一个**运行时验证框架草案/早期实现**，用于承载 Rudra 与外部参考实现之间的行为比对逻辑。  
> 它表明项目正在建设运行时一致性验证能力，并且现在已经具备“比较入口返回结构化状态 -> 调用侧消费状态 -> 统一映射到 `VerifyResult`”这一基础返回路径，  
> 但**并不代表所有验证路径都已打通，也不代表这些验证已被持续执行**。

换句话说，它可以被描述为：

- 已存在的验证基础设施
- 正在建设的比对框架
- 已开始具备结构化返回路径的局部验证入口
- 后续对拍工作的入口

但**不应被描述为**：

- 已完成的完整验证系统
- 已证明一致性的证据本身
- 已投入稳定生产使用的验证平台

---

## 6. 当前文档允许使用的表述

为了修复文档失真，后续文档和日志请尽量使用下面这类表述。

### 推荐表述
- “已实现静态结构对齐的部分测试”
- “已建立运行时验证框架”
- “尚未完成 Ghidra FFI 的稳定集成验证”
- “当前不能宣称与 Ghidra 100% 一致”
- “已具备对拍方向，但仍缺少稳定的端到端结果”
- “按当前仓库可见状态，运行时一致性仍待验证”

### 禁止或不推荐表述
- “已保障一致性”
- “与 Ghidra 完全一致”
- “运行时验证已完成”
- “端到端输出已完成对拍”
- “SSA 已确认 100% 一致”
- “所有验证能力已具备并可稳定运行”

---

## 7. 已知风险区域

在没有完整运行时验证前，以下区域都应被视为高风险区。

### 7.1 P-code 生成
风险点：

- 单条指令的 P-code 序列可能与 Ghidra 不同
- 临时变量 / unique 空间策略可能不同
- 部分架构语义边界条件可能未覆盖

### 7.2 SSA 构建
风险点：

- Phi 节点放置位置
- 变量重命名顺序
- 版本号分配
- 某些边界控制流下的合流处理

这是高优先级风险，因为一旦偏离，会影响后续大量分析结果。

### 7.3 CFG 结构恢复
风险点：

- 基本块划分
- 边关系
- 支配关系
- 循环识别

CFG 偏差会进一步放大到 SSA、变量恢复与控制流结构化。

### 7.4 类型传播与变量恢复
风险点：

- 类型传播方向不稳定
- 对调用约定的理解不充分
- 栈变量/寄存器变量恢复策略偏差
- 高层变量合并不足

### 7.5 最终输出层
风险点：

- 结构化程度不足
- 命名质量不稳定
- 局部语义正确但全局可读性差
- 与 Ghidra 输出风格差异很大

---

## 8. 推荐的近期验证里程碑

为了让验证体系真正走向可信，建议近期按以下顺序推进。

### Milestone 1：清理文档失真
先统一修正文档中的夸大结论，确保所有地方都承认：

- 运行时验证未完成
- 端到端一致性未证明
- 当前结论以真实代码和测试为准

### Milestone 2：固定一组最小验证样本
选择少量、稳定、可重复的目标：

- 简单算术函数
- 分支函数
- 循环函数
- 简单调用函数

针对这些样本建立最小对拍集合。

### Milestone 3：让运行时验证至少覆盖一个真实闭环
先打通一个最小闭环，例如：

- 常量求值对拍  
或
- 单条指令 P-code 对拍  
或
- 小函数 SSA 对拍

当前最小 `mov rbx, rax` 样本已经把闭环推进到“结构化 FFI 返回路径已建立”的阶段；后续真正要补齐的，是让该返回路径接入独立参考侧数据，并沉淀出可复核的差异分类。  
同时，`add rax, 1` 已经进入“真实失败样本记录”阶段，这说明最小闭环不再只是停留在单一 `mov` 指令，而是已经开始暴露算术类 opcode 的实际差异点。  
只要有一个闭环真实跑通，就比泛泛而谈“全部都在做”更可信。

### Milestone 4：沉淀差异报告格式
当出现不一致时，需要明确记录：

- 测试对象
- 地址/函数
- Rudra 输出
- 参考输出
- 差异类别
- 初步原因判断

### Milestone 5：再谈端到端样本验证
在局部行为没有验证清楚前，不应过早把主要精力放在“大样本最终输出比较”上。

---

## 9. 与其他文档的关系

本文件应与以下文档保持一致：

- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- `GAP_ANALYSIS.md`
- `docs/TODO_BOARD.md`
- `docs/PROJECT_STRUCTURE.md`

同步原则：

- 如果本文件说“运行时验证未完成”，其他总控文档不能再写“已保障一致性”
- 如果本文件说“CLI 当前不可作为稳定对拍入口”，其他文档不能把 CLI 写成完整可用产品
- 如果本文件说“端到端对拍未完成”，状态文档不能写成“已完成 Ghidra 质量对齐”

---

## 10. 当前结论

截至当前仓库可见状态，Rudra 的验证工作应当被准确描述为：

- **静态对齐：已有一部分基础**
- **运行时验证：已有框架，但未完成**
- **FFI 对拍：有方向与接口，但未形成可信闭环**
- **端到端一致性：尚未证明**
- **最终质量结论：应保持审慎，不可夸大**

因此，当前最准确的总述是：

> Rudra 已经开始建设面向 Ghidra 的多层验证体系，但现阶段仍处于“结构层已有进展、运行时与端到端层面尚未完成”的状态。任何关于“已完全对齐”或“已保障一致性”的表述都应视为失真，后续文档与日志应统一回到这一真实基线之上。

---

## 11. CSPEC2-CR-N2 fixture：bad-jump-table 改名链的双侧实跑协议（2026-09-25）

`tests/oracle/namevars_badjumptable_1204.cc` + `.metadata.json` 是 CALLSPEC-0001 (b)+(c)
合流后的触发路径 fixture：httpd `ap_vhost_iterate_given_conn`（BFD VMA `0x2da50`）内
`0x2daeb` BRANCHIND 跳表恢复失败（Too many branches，FailNormal）→
`flow.cc:754 setBadJumpTable(true)` → `coreaction.cc:2779 lookForBadJumpTables` →
`renameSymbol(UNRECOVERED_JUMPTABLE)` → 打印。

### 11.1 oracle 侧（锁定库 e40ed130）

```bash
# 构建（锁定对象由 BRIDGE1 lane 预备，stamp 必须等于 e40ed130…）
bash /dev/shm/rudra-tests/unreffix/build_namevars_badjt.sh \
     FIXTURE=$PWD/tests/oracle/namevars_badjumptable_1204.cc
# 运行（目标函数/入口有默认值，可省 env）
/dev/shm/rudra-tests/unreffix/namevars_badjumptable_1204 sleight_specs examples/httpd \
     >oracle.out 2>oracle.err
```

载入契约 = direct-runner golden 生成器（BfdArchitecture + readLoaderSymbols + dynsym
函数注册 + 全域 followFlow + universal action + PrintC docFunction）；自证：渲染出的 C
函数体与 `tests/golden/ghidra_httpd_1204.direct-runner.c` 的 `0x2da50` 块逐字节相同。
观察面：stderr `[CALLSPEC-BADJT]`（注册序逐 callspec 的 badjt 旗标）+
`[SYMDUMP-FINAL]`（改名后的 ScopeLocal map tree）+ stdout C 渲染。

### 11.2 Rudra 侧（生产驱动，零 fixture 侧重复实现）

```bash
RUDRA_DUMP_FUNC=ap_vhost_iterate_given_conn MAX_FUNCS=30 \
RUDRA_SEEDS=0 RUDRA_SYMDB=0 \
<target>/fast-release/examples/httpd_decompile >rudra.out 2>rudra.err
```

`RUDRA_SEEDS=0 RUDRA_SYMDB=0` 是 direct-runner 等价 bare 脸；观察面：stderr
`[JUMPTABLE] recovery failed at 0x2daeb mode=FailNormal → truncate`（生产者）、
`[DUMP] sym#…`（RUDRA_DUMP_FUNC 符号倾泻）+ stdout C 渲染。确定性口径：stdout 必须逐
字节恒等；stderr 只比对 `[DUMP]`/`[JUMPTABLE]` 观察行（`[INJECT]` 为并行线程顺序噪音，
机制 B 已注记的噪声类）。

### 11.3 结论（2026-09-25，本 lane 实跑）

- 生产者（truncate 失败臂）双侧 MATCH；旗标只落在被截断的 `0x2daeb` CALLIND
  （oracle `[CALLSPEC-BADJT] i=0 badjt=1`，`0x2daa5` 真·间接调用 badjt=0）；
- **改名点火成功**：双侧 ScopeLocal 均出现 `UNRECOVERED_JUMPTABLE`，存储键一致
  （oracle `u0x00000030:8` == rudra `[DUMP] sym#1 start=0x30 size=8`）——root 复测的
  “最终 C 文本 UNRECOVERED 计数=0”不是链条未点火，而是**渲染层不读改名后的符号**；
- 渲染层 MISMATCH 两处（→ `PRINTC-BADJT-PARAMSYM-0001`）：签名位 2 oracle
  `code *UNRECOVERED_JUMPTABLE`（printc.cc:2222-2250 经 `param->getSymbol()`→
  `emitVarDecl(sym)` 印后端符号）vs Rudra `void (*)()param_2`（printc.rs
  `emit_prototype_inputs` 印 ProtoParameter 自带名，后端符号通道缺失）；调用点 oracle
  `(*UNRECOVERED_JUMPTABLE)(…)` vs Rudra `(*(code *)param_2)(…)`
  （`get_varnode_display_name_inner` P0.4 register-input 前置 proto 名，先于符号分支）；
- 附带 `switch() {}` 空骨架残片（→ `BLOCKSTRUCT-TRUNC-SWITCHEMPTY-0001`）。

---

## 12. 门禁与协议手册刷新（2026-09-26，Lane DOCGUIDE）

> 本节收录 2026-09-26 wave 的门禁与协议扩容：第四门禁（镜面棘轮）、refs 定义起始行
> 语义、第五语料 sqlite3 协议、五脸 env 矩阵、投影银行跑法与重钉三件套形态。所有
> 命令均在本车道（wt/docguide，基 master `d0e27c14`）**亲测可复制执行**；参数与
> `tools/` 脚本实际实现逐一核对（脚本头与函数体亲读，非转述车道报告）。凡引用尚未
> 合入 master 的车道产物，均标注所在分支与 commit——root 集成后本节措辞按 commit
> 引用自动成立，不需要改写。

### 12.1 第四门禁：镜面棘轮（tools/verify_mirror_gate.sh）

**契约**（Ghidra 12.0.4 `e40ed130` direct-runner golden，`tests/golden/*_1204.direct-runner.c`）：

| 面 | 驱动 | golden |
|---|---|---|
| curl | `RUDRA_MIRROR=1 examples/curl_decompile` | `ghidra_curl_1204.direct-runner.c` |
| httpd | `RUDRA_MIRROR=1 examples/httpd_decompile` | `ghidra_httpd_1204.direct-runner.c` |
| vsh | `RUDRA_GEN_MIRROR=1 examples/gen_decompile /usr/bin/virt-ssh-helper` | `ghidra_vsh_1204.direct-runner.c` |
| sq | `RUDRA_GEN_MIRROR=1 examples/gen_decompile /usr/local/bin/sasquatch` | `ghidra_sq_1204.direct-runner.c`（GEN4 第四语料棘轮面） |

compare 统一 `--base 0 --summary-only`。vsh/sq 的语料二进制是宿主特定资产：缺失时该面
显式 **SKIP**（exit 0，输出 SKIP 行），curl/httpd 两面照常门禁（CI 形态）。`VSH_BINARY`/
`SQ_BINARY` env 可覆盖默认路径。

**判定（阶段一：单向棘轮上限）**——基线台账 `tools/mirror_gate_baselines.tsv`，列 =
`corpus  ceiling  floor  todo_id  pinned_commit  measured_at`：

- `skeleton > ceiling` → FAIL（漂移报警：新残差族或既有族回归）；
- `defects > 0` 或 `numbering > 0` → FAIL（**硬断言**，与 ceiling 无关，不写在表里，
  runner 内写死）；
- `matched < floor` → FAIL（函数覆盖丢失）；
- 健康信号（curl 面的 timeout/panic/worker-failure/protocol-failure 汇总行、httpd 面
  的 `TIMEOUT (>` 标记计数、vsh/sq 面的 `[GEN] ok=N/N` 行）非零或缺失 → FAIL；
- `skeleton ≤ ceiling` 即 PASS——**改善（低于上限）不失败**；收紧上限须先登记 TODO。

当前冻结基线（tsv 实值）：curl `275/74`、httpd `460/29`、vsh `55/71`、sq `22639/805`
（ceiling/floor；sq 行绑 `GEN4-SQ-CEILING-REPIN-0001` @ `7a39afad`）。

**棘轮纪律（改善报 root 重钉，禁自钉）**：

1. 单向性只罚回归：车道把 skeleton 从 275 修到 110（F7NAME 实测）不失败、也不自动
   收紧——改善值**报 root**，由 root 决定是否重钉；车道不得为通过门禁自行放宽
   ceiling，也不得未经 root 把改善值私自钉进 tsv（`--update-baseline` 不写文件，见
   下）。
2. 收紧/移动基线必须挂 TODO 票：脚本强制 `--update-baseline <TODO_ID>` 形态（缺 ID
   exit 2），且它**只打印实测值与手改指引、不落盘**——
   ```bash
   tools/verify_mirror_gate.sh --update-baseline GEN4-SQ-CEILING-REPIN-0001
   # 输出: baseline re-pin writes are done by hand with review; measured values printed below.
   #       (edit tools/mirror_gate_baselines.tsv: ceiling=measured skeleton, floor=measured matched, todo=...)
   ```
   实际改表是带 review 的手工编辑（DBLHI 车道收紧 sq 行的 `GEN4-SQ-CEILING-REPIN-0001`
   是登记在案的先例形态：ceiling=实测 skeleton + 非 ok 函数 golden 行数 worst-case
   上界，floor=实测 matched）。
3. **sq 面承重红口径**：sq 面**恒 FAIL 是预期承重状态**，不是门禁误报——health 红
   （ok=805/810，5 非 ok）绑定 `MIRROR3-PRETTYFLUSH-FAILCLOSED-0001` +
   `GEN4-SQ-MERGE-FORCEDINTERSECT-0001` + `GEN4-SQ-NULLLOCALTYPE-0001`，numbering
   硬断言红（=7）绑定 `GEN4-SQ-DUPDECL-NUMBERING-0001`。四票收口前修复车道**不得
   绕过**该面（不得 SKIP、不得改 ceiling 掩盖、不得降 health 断言）；FAIL 本身就是
   棘轮承重信号。

**陈旧二进制守卫**：`curl_decompile`/`httpd_decompile` 早于 HEAD commit 时间戳即
FAIL（2026-09-25 事故形态：pre-tier 二进制在 mirror env 下打出 canon 脸静默爆 diff）。
重构建：

```bash
CARGO_TARGET_DIR=<dir> cargo build --profile fast-release --examples
```

**canon 门禁 env 卫生（CR-TRIGFACE F-4 操作规程，2026-09-26）**：
`RUDRA_MIRROR`/`RUDRA_FLOW_MIRROR`/`RUDRA_GEN_MIRROR` 是**存在性开关**——驱动侧
判定为 `env::var(...).is_ok()`/`.ok()`（curl_decompile.rs:41、httpd_decompile.rs:87、
gen_decompile.rs:663 亲核），**置空串（`RUDRA_MIRROR=`）也切换输出形态到镜面脸**。
canon 门禁（默认脸差分）运行前必须显式
`unset RUDRA_MIRROR RUDRA_FLOW_MIRROR RUDRA_GEN_MIRROR`——继承环境里残留的空值
变量足以让 canon 跑出镜面脸静默爆 diff（与上方 2026-09-25 事故同族；CR-TRIGFACE
终判发现项 F-4，root 波次账本 2026-09-26 在案）。

**用法**（亲测）：

```bash
tools/verify_mirror_gate.sh --self-test          # 无二进制自检（解析/断言/fail-closed 逻辑）
tools/verify_mirror_gate.sh                       # 全四面前提：BIN_DIR 有 example 二进制
tools/verify_mirror_gate.sh --corpus curl        # 单面
tools/verify_mirror_gate.sh --corpus sq --keep-dir DIR   # 保留诊断工件
```

`--bin-dir DIR` 覆盖默认 `$REPO_ROOT/target/fast-release/examples`。本车道亲测
`--self-test` 输出 `SELF-TEST PASS`（rc=0）。CI 形态见
`.github/workflows/`（先 fetch 锁定 oracle 树再构建，commit `44be2b0e`）。

### 12.2 refs 定义起始行门禁（REFSDEF：check_ghidra_refs.py --all --strict 新语义）

`TOOLS-REFS-DEFSTART-0001`（Lane REFSDEF，commits `9aa565ec`+`ba3f2dc8`）之后，
`tools/check_ghidra_refs.py` 的 commit/CI 兜底从“行号在文件内”升级为两段语义：

1. **存在性检查（legacy，覆盖所有引用形态）**：任何注释里的
   `<file>.cc|hh|h :<digits>` 引用，文件必须存在于锁定 oracle cpp 树且行号不越界。
2. **定义起始行检查（def-start，只针对头注解）**：形如
   `// Ghidra: <file>.cc:<line> <fn>` 的头注解，若 `<fn>` 在锁定 oracle 的 `<file>`
   定义表中**可解析**，则 cited line 必须是 `<fn>` 的**函数定义起始行**。漂移
   （引用行落在调用点/旧 oracle 行/函数体中部）→ 报
   `def-start drift: cites file:line for 'fn' but locked oracle defines it at line(s) …`。

**豁免口径**（按既有惯例，脚本计数不阻塞）：

- `.hh`/`.h` 引用只做存在性检查（声明/内联文档惯例较松，不做 def-start）；
- `<fn>` 在被引文件定义表中**未解析**（类名级代表行引用、.hh 内联访问器、跨文件
  调用点引用如 `AddrSpace::byteToAddress` 引在 ruleaction.cc）→ 计入 `unresolved`
  豁免桶，不是 drift。

**解析器形态**（ADDRUNIT 修正模式，任何未来 citation 批量工具必须带上）：返回类型与
限定名之间强制分隔符 `(?:\s*[*&]\s*|\s+)`（指针星号贴类名或贴类型均可，且杀死
`e::AddTreeState` 类贪婪回溯伪类型）；裸构造 `Class::Class(` 独立分支（先查）；
析构 `Class::~Class(`；operator 重载；模板前缀；排除调用行（行尾 `;`）、doc 行
（`//`/`/*`/`*` 起）、关键字返回类型（`return`/`if`/…）。

**用法与输出语义**（亲测）：

```bash
python3 tools/check_ghidra_refs.py --staged            # 只查 staged .rs
python3 tools/check_ghidra_refs.py src/foo.rs          # 单文件
python3 tools/check_ghidra_refs.py --all --strict      # 全库（pre-commit/CI 形态，破即 exit 1）
python3 tools/check_ghidra_refs.py --all --strict --defstart-report   # 摸底普查形态
```

- `--strict` 决定阻塞（有破引 exit 1）；无 `--strict` 为 advisory（exit 0）。版本化
  `.githooks/pre-commit` 固定 `--all --strict`。
- `--defstart-report` 在两种结论下都附普查块。本车道亲测（2026-09-26，基
  `d0e27c14`）：
  ```text
  check_ghidra_refs: OK (97 file(s), all // Ghidra refs resolve)
  ── def-start survey (TOOLS-REFS-DEFSTART-0001) ──
    existence problems : 0
    def-start checked  : 3782
    def-start ok       : 3782
    def-start DRIFT    : 0
    unresolved (exempt): 823
  ```
  REFDEF 车道交付时全量摸底为 3772 checked / 288 drift 全修 / 823 豁免（见
  `LANE_REFSDEF_2026-09-26.md`）；此后新增注解使 checked 增至 3782，DRIFT 保持 0。
  手册使用时应以自己现场跑出的数字为准，本段数字是“健康树长相”示例。
- **该工具没有 `--help`**（不认识的参数会被忽略后直接执行检查——只有 `.rs` 结尾的
  参数被当作文件）——查参数请读脚本头 docstring，不要指望 `--help` 输出。

### 12.3 第五语料 sqlite3 协议（GEN5：golden 溯源三件套 + 镜像发现一致性 + 分片跑法）

第五泛化语料 = `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`
（sha256 `f5a7fc236f80f3185608d14e9f4dea3e3fd647582e123e8a00f253629fe16830`，
Ubuntu libsqlite3-0 3.37.2-2ubuntu0.8）：**首个 stripped 共享库 profile**——dynsym-only
契约（1339 导出 FUNC 真身 + 46 PLT 桩 = 1385 单元，无 .symtab、无 DWARF、库脸无
main/_start）。golden 在 wt/gen5（commit `ff06b3c7`，记分板 `790faa0f`），
root 集成后以下路径直接成立。

**golden 溯源三件套**（同 commit 入库，缺一即按机制 B2 记 `NO_ORACLE`）：

1. `tests/golden/ghidra_sqlite_1204.direct-runner.c` —— golden C 文本（sha256
   `90950e1f…`，143012 行，含 sqlite3VdbeExec 3877 行巨型 switch）；
2. `tests/golden/ghidra_sqlite_1204.provenance.json` —— oracle commit/tag/arch=
   `x86:LE:64:default`/cspec=gcc/分析选项/输入 sha/逐函数 ledger/runner 构建指纹/
   determinism 全记录（NO_ORACLE 缺项为零；canon headless 档 NO_ORACLE 已记在 tier
   字段，重建入口 `tools/build_ghidra_1204_headless.sh`）；
3. `tests/golden/README.md` 的 sqlite 行。

oracle 真值：1385/1385 OK、30.3s、determinism 12/12 字节恒等（hermetic one-mode ×12
workers，600s/函数）。重生成复用 `tools/regen_ghidra_golden.py`（preflight 需锁定
oracle 树 `e40ed130` + BFD 2.38 `/tmp/rudra-ghidra-bfd-2.38`——内存盘 oracle 环境，
机器重启即丢，重建用直连 https 拉 binutils-dev deb 解包）。

**镜像发现一致性（同输入前提）**：Rudra gen 驱动对同一 .so 发现 1385/1385 单元与
oracle **逐名逐址一致**，才允许进入 mirror 对拍——发现面（单元数/地址/名）不一致时
先修发现层，不做文本对比。镜像臂成绩单（首期）：ok=1355/1385（27 PANICKED +
3 TIMEOUT）、skeleton 17652、defects 0、numbering 0、874/1355 骨架字节恒等；新票
`GEN5-SQLITE-PATHOSLOW-BITVEC-0001`（P1，首个性能级分歧族）。族归因与全部面级对照
见 `docs/alignment_audit/GEN5_SQLITE_CORPUS_SCOREBOARD_2026-09-26.md`。

**分片跑法**：`gen_decompile` all-mode 是串行逐函数；sqlite 单函数病态慢可达 600s 墙，
全量串行不可行。车道形态 = **并行分片驱动**（16 分片 × 顺序 `--one <i>` 子进程 =
与 all-mode 完全相同的 hermetic 逐函数语义的并行化包装，失败重试 3 轮），795s 完成。
注意：分片脚本 `mirror_shard_sqlite.py` 与 `capture_oracle_gen5.py` 是车道证据脚本，
归档于内存盘 `/dev/shm/rudra-reports/gen5-evidence/`（重启即丢，未版本化——债务已
登记 `DOCGUIDE-GEN5-SHARD-EVIDENCE-0001`）。

**复现配方**（记分板 §7 原文形态）：

```bash
# oracle 真值（已入库，重生成用）
python3 /dev/shm/rudra-reports/gen5-evidence/capture_oracle_gen5.py   # 需 worktree 内 tools/regen_ghidra_golden.py
# Rudra 镜像（并行分片 = hermetic --one 语义并行化，重试 3 轮）
python3 /dev/shm/rudra-reports/gen5-evidence/mirror_shard_sqlite.py 1385
# 单函数病态复现（PATHOSLOW 族）
RUDRA_GEN_MIRROR=1 <gen_decompile> /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 --one 55   # 57/114 同形
# 对拍
python3 tools/compare_ghidra.py <mirror_out>.c tests/golden/ghidra_sqlite_1204.direct-runner.c --base 0 --summary-only
```

**车道终报归位**：所有车道终报统一在内存盘 `/dev/shm/rudra-reports/`
（`LANE_<NAME>_<date>.md` 形态；如 `LANE_DWARDBASE_2026-09-26.md`、
`LANE_F7NAME_2026-09-26.md`）。内存盘重启即丢——未集成的证据由车道自行负责及时
归档；按机制 B2 必须固化的双侧回归 fixture 只在 root 集成阶段挑拣入库。

### 12.4 五脸 env 矩阵（PFLIP 后）

`PARAMID-DEFAULT-FLIP-0001`（用户拍板 2026-09-26；Lane PFLIP，wt/pflip commit
`f6817509`，examples 层极性翻转，src 零改动）落地后，两个 example 驱动的 env 矩阵：

**httpd_decompile**：

| 脸 | 形态 |
|---|---|
| 默认脸（无 env） | PARAMID 自产迭代环 **默认开** + generic_clib 导入台账（59 条）默认开 |
| `RUDRA_PARAMID=0` | 断路自产迭代 → 无通道脸 |
| `RUDRA_V3SIG=1` | 恢复 callee-siglock manifest 锁通道（退化为显式 opt-in；`=0` 无附加语义） |
| `RUDRA_IMPORTSIG=0` | 断路导入台账 → **默认脸降级**（实测 285→537；PAB 消融族 ~691，劣于 manifest 时代 ~590 基线）——台账是默认脸的**承重数据**，不是可选增强 |
| `RUDRA_SEEDS=0` | 全局逃生 → bare 脸（分层退出：`SEEDS=0` 压制其余所有门） |
| `RUDRA_MIRROR=1` | 镜面门**绝对优先**，恒拒所有通道（投影纯度） |

**curl_decompile**（同族翻转）：manifest 装载器 opt-in only，All 模式迭代门默认开；
`RUDRA_PARAMID=0` 单退 = 无通道脸，`RUDRA_PARAMID=0` + `RUDRA_V3SIG=1` = manifest 脸。

**优先级链**（PFLIP commit 原文）：mirror > `RUDRA_SEEDS=0` > PARAMID（默认） >
V3SIG（opt-in）。

**评测语义分界（跨口径禁比）**：翻转后**默认脸 = 自产口径**。历史 manifest 时代的
httpd 默认脸骨架数链（908 V3FLIP → 898 IMPORTSIG 时代 → 862 → 590 F7NAME 基线）与
翻转后数字**不可比**——口径切换点已在本节与 TODO `PARAMID-DEFAULT-FLIP-0001` 标注。
任何跨口径结论（改善/回退判定、记分板对比）必须用同一 env 矩阵重跑双侧再比；引用
历史数字时须注明口径与当时 env 矩阵。

### 12.5 投影银行跑法与重钉三件套形态

**跑法**（机制 B2 固化 fixture 门禁，亲测）：

```bash
tools/verify_projection_bank.sh                    # 全部条目（391）
tools/verify_projection_bank.sh curl_next_url      # 单条目 triage 形态
```

每条目三步：①条目完整（manifest.toml + oracle.projection + rudra.projection）；
②冻结锚自身 sha256 仍与 manifest 钉值一致（锚漂移=门禁失败，与比对结论无关）；
③`run_stage_bisect.sh`（stage_bisect.py --v1，strict offsets）报 `kind: MATCH`
（exit 0）。本车道亲测单条目：`PASS curl_next_url curl/next_url MATCH (335 stages,
96457 ops)`（rc=0）。新条目入库流程见 `tests/fixtures/projections/README.md`
（五步：双采+双跑确定性 → bisect MATCH → 建 manifest → 登记 README → 全量门禁）。

**重钉三件套**（fixture 因 src 变更失效时；AGENTS「pin 重钉双形态」的展开，DBLHI
车道 `GEN4-SQ-CEILING-REPIN-0001` 是在案实例）：

1. **runner 身份变量（rev-parse 形态）**：commit / tree / 关键文件 git blob id
   （DBLHI 实例：commit `7a39afad`/tree `42a47b46`/`src/double_precis.rs` blob
   `c6834d59`/sq golden blob `0c6c0c96`/baselines tsv blob `1a446a50`）；
2. **metadata comparand（sha256sum 形态）**：live 文件的 sha256
   （DBLHI 实例：`src/double_precis.rs`=`fc587e71…`、`docs/api/double_precis.md`=
   `31e840c6…`）；
3. **overlays 失效面**：引用了变更文件的 fixture pin 清单（DBLHI 实例：
   varnode_init_1204 的 rs+doc pin、condexe_trueout_1204 的 overlay sha + base
   blob、action_break_pool_1204 的 overlay sha，另 63 个 crate-tree runner 的
   `rust_crate_tree_sha256` 随批重钉）。

**双形态勿混**：`rev-parse` 校验用 **git blob id**，`sha256sum` 校验用**文件哈希**——
两种值对同一文件不相等，校验器各认各的形态，混用即假 mismatch。

**DBLHI2 教训——hash 对终态现取**：哈希必须在**全部编辑完成后的终态**上取。DBLHI
车道在 runner 变量里记录了 doc blob `ad354249`，随后同一 commit 又向该 doc 追加了
结果附记（blob 变为 `3ca7f834`）——记录值在提交瞬间即自漂移陈旧。规则：

- 先做完所有编辑（包括记录结果的那份 doc / TODO 行），**再**取 blob id / sha256
  写入记录；
- 若记录值必须写进被哈希的文件本身，则该值永远无法自洽——把 pin 值写到**另一个**
  文件（TODO 行 / 车道终报 / metadata），或终态取值后再追加一个登记 commit；
- 集成期批量重钉（root）一律对合并后的终树现取哈希，不采信车道在中间态报的值
  （DBLHI 已登记的 overlay 目标值即按“基线时已陈旧、以 post-DBLHI 终态为准”处置）。

