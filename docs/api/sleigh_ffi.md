# sleigh_ffi.rs

SLEIGH p-code 引擎的进程内门面。Phase2 退役后形态（SLEIGH-RUSTIFY-PHASE2-0001）:
`SleighCtx` 直接驱动 vendored `kuna-sleigh` 运行时（crates/kuna-sleigh,32,687 行,
Phase1 vendor）,`RustSleighEngine`/`RustPcodeCollector` 逐条镜像已退役的
`sleigh_shim` C ABI 语义（loadFill 模减/补零、pool 槽位 identity、LOAD/STORE
space-id 规范化、decode_started 冻结、错误分型映射）。

历史:C++ 链（build.rs 编 21 .cc + sleigh_shim C ABI + `#[cfg(has_sleigh)]`
cpp_backend）在 Phase2 双链期并存,门禁全过（op-for-op 698,605 decodes/
5,550,599 ops 零差 + 五语料 E2E 字节恒等 + `cargo test --lib` 1777P/0F 双引擎
恒等 + bank 391/391）后于退役 commit 删除。证据 =
`docs/alignment_docs/SLEIGH_PHASE2_SWAP_2026-09-26.md`;双引擎差分仪器
（examples/sleigh_engine_diff.rs）随 C++ 链退役,存档于退役前 commit
（cfeb30c6）供复现。

## SLEIGH-0002B 动态结果协议

`SleighCtx::one_instruction` 是本层的严格入口：

- 单次引擎调用同时返回真实 `step` 与全部 p-code，避免第二次解析改变
  context/缓存状态；
- op 按 `PcodeCacher::issued` 顺序、input 按 slot 顺序返回，无 64-op 或
  16-input 固定上限；
- `OK + step > 0 + ops.is_empty()` 保留合法 zero-op 指令，不能与异常混淆；
- output 可空；公开 DTO 用 `has_output==0` 表示空，此时 `output` 只是必须
  完全忽略的 default sentinel（其 identity 可与真实 ID 重合）。每个
  varnode 在一次指令内按"逐 op，先 output、再 inputs"首次出现顺序获得
  identity（kuna pool 槽位地址,与 C++ `VarnodeData*` 池指针别名语义守恒——
  发射发生在整指令 build 完成后,sleigh.cc:776 同序），保留跨 op 别名关系
  但不泄漏进程指针；
- LOAD/STORE 的 space-id input 规范化为 address-space index（kuna LOSS-015
  本就存 manager index;C++ 侧曾存空间指针、由 shim 反查 index,退役前
  双引擎 wire 值恒等亲证）；候选值非法时返回 typed error，绝不解引用任意
  整数。普通 constant（包括相对 p-code branch）不改写；
- `UnimplError`、`BadDataError`、`DataUnavailError`、`SleighError`、
  `LowlevelError`、`DecoderError` 保持分型。kuna 的 Recov/Parse/Evaluation/
  ParamUnassigned/JumptableThunk/Java 变体按上游继承关系（全部 derive 自
  `LowlevelError`）折叠为 Lowlevel,与退役 shim 的 C++ catch 序一致。message
  先按原始 bytes 保存，只有展示时才做 lossy UTF-8；只有 `UnimplError`
  携带 `instruction_length`，数值 0 仍表示字段存在。

`SharedLoadImage` 在 `try_set_image` 返回前完整复制调用方 bytes。相对偏移按
锁定 `RawLoadImage::loadFill` 的无符号 `start - vma` 做 64 位模减；模减结果
不在 image 时抛 `DataUnavailError`（message 字节与 C++ 侧逐字节一致——
op-for-op 57,817 错误对亲证），在 image 内但固定 16-byte fetch 跨过尾部时
复制有效前缀并补零。首次 decode 或 `instruction_length` 后冻结 image/context
（`decode_started` → `InvalidState`,镜像退役 shim 行为）。这是 `RUGRA-GLUE`
生命周期策略，不是 Ghidra 行为等价结论。包括首次失败后替换 image 再重试
在内的精确 mutable-loader/cache 语义归 `SLEIGH-0002D`，必须以锁定
`Sleigh::reset` / `Sleigh::oneInstruction` fixture 判定，不能预设需要重建
translator 或重放 spec。

`decode() -> Vec<PcodeOpC>`、`set_image()` 与 `set_context()` 仅是旧 lifter
的兼容桥：它们仍会折叠严格错误，不能用于 oracle 证据。生产调用链改用
严格结果、移除 lifter 内二次 input cap，并采用 SLEIGH step，分别属于
`SLEIGH-0002D` 与 `SLEIGH-FLOW-0001`。legacy `instruction_length()` 为
`&mut self`（冻结语义所需）。

## 尚未闭合的边界

- `load_pspec` / `simple_xml_find` / `get_attr` 是
  `SLEIGH-0002C/MISMATCH` 临时兼容层。它只扫 raw `<set>` tag，丢失
  `ContextInternal::decodeFromSpec` 的地址范围、explicit mask、tracked
  register 与子节点顺序，绝不构成行为等价证明。
- `new() -> Option`、legacy `instruction_length() -> Option` 仍会压缩部分
  创建/metadata 错误，未纳入本批次 MATCH 范围。
- 锁定 x86-64 SLA 的 alignment 为 1 且没有 null-template constructor，无法
  自然触发 `UnimplError`；该分支实现了 typed transport，但保持 `UNTESTED`。
- 单 op 超过 16 个 input、delay-slot `step`、OOM/标准/未知异常、
  `InvalidState` 与析构 fault injection 分支仍为 `UNTESTED`；动态协议已移除
  旧容量上限，但这些分支不能据实现形状升级 MATCH。
- 首次 decode（包括失败）后替换 image/context 会保守返回 `InvalidState`；
  真实 Ghidra mutable loader 的 error→replace→retry 生命周期留给
  `SLEIGH-0002D`，不属于本批 MATCH。
- 完整 pspec/cspec、长生命周期 parser cache、Flow 异常策略、space/opcode
  映射与最终反编译输出均不属于本层的窄域 raw ABI 结论。

## PERF-DUAL-SLEIGH-INIT-0001 单次加载契约与加载计数

oracle 形态：`SleighArchitecture` 维护 `static map<int4,Sleigh> translators`
（sleigh_arch.hh:109），`buildTranslator`（sleigh_arch.cc:174-187）对同
languageindex 复用已建实例（注释原文"try to reuse the previous Sleigh
object, so we don't reload the .sla file"）；`Architecture::restoreFromSpec`
（architecture.cc:624-641）只 `initialize` 一次并安装为 `translate`，寄存器
目录（`SleighBase::getAllRegisters` → `varnode_xref`，sleighbase.cc:182-186）
与全部解码共用这一个实例——即 **每个 Architecture 恰好一次 .sla 反序列化**。

修复前 Rugra 侧同一线程内 `SleighCtx::new()` 建两个独立引擎（驱动
build_architecture 寄存器目录枚举一个 + `SleighLifter::new()` 解码一个），
hermetic 每子进程反序列化 `x86-64.sla` 两次（PERFBENCH gdb/strace 钉死，
固定开销 ≈430–480ms/子 vs oracle 85–180ms）。修复后驱动经
`SleighLifter::from_ctx`（docs/api/disasm/sleigh_lift.md）领养目录枚举用的
同一引擎实例，恢复 oracle 单实例形态；枚举腿只读
（`num_registers`/`register_info`），被领养引擎处于与全新构造完全一致的
no-image/no-context/never-decoded 状态，`configure_x86_64` 观察零差异。

本层提供的观测面：`ENGINE_LOADS`（进程级原子计数，仅统计
`initialize_from_sla` 成功完成的构造）+ `engine_load_count()` 读取器。
hermetic 单函数子进程期望值为 1；`gen_decompile --one` 在
`RUGRA_SLEIGH_LOAD_REPORT=1` 时打印 `[GEN] sleigh engine loads=N`
（默认静默，不改变任何协议输出）。亲证（2026-09-26，本车道）：
修复前 strace openat `x86-64.sla` ×2 + 计数 N/A → 修复后 openat ×1 +
计数 `loads=1`；canon curl/httpd E2E 输出字节恒等。

## 锁定 oracle 验证

```bash
tools/run_debugproto_unknown_model_oracle.sh   # 纯 Rust 引擎树上的 B2 fixture（MATCH）
cargo test --offline --lib sleigh_ffi::tests -- --nocapture
cargo run --offline --example sleigh_test
```

Phase2 证据链（退役前双引擎形态,cursor=cfeb30c6 可复现）：
`examples/sleigh_engine_diff`（36 面 698,605 decodes/5,550,599 ops/
decode_divergences=0 catalog_divergences=0,含全部错误路径 message 字节恒等）
+ 五语料 A/B 字节恒等（curl 95,842B/httpd 56,219B/vsh 49,584B/sq 2,416,424B/
sqlite3 233,520B）。

`tools/run_sleigh_decode_oracle.sh` fixture（12 case,oracle 侧=锁定树 C++
重建）在基线 d4347cd 即已红（预存 pin 漂移,GLOBREPIN 族,亲测 rc=1）,退役后
还需 runner 手术（快照 live build.rs/sleigh_shim/C++ link 胶水）,归
SLEIGH-RETIREE-FLEET-REPIN-0001 族票;Rust 引擎对该 fixture 族的等价性由
op-for-op 零差传递闭包覆盖。oracle runner 使用锁定 commit
`e40ed13014025f82488b1f8f7bca566894ac376b` 的真实 CORE + SLEIGH 源码，
与 Rust 侧对同一 SLA、显式 context、image/base/offset 运行同 schema
stdout direct diff。12 个 manifest case 覆盖 CPUID 78 ops/134 inputs、三种
zero-op NOP（含单字节尾部补零与 `UINT64_MAX -> 0` 模减回绕）、动态内存
MOV 的跨 op pointer alias、BadData、三种 DataUnavail、owned source mutation
以及成功后错误不泄漏；额外 reachability record 证明锁定 x86-64 无法触发
`UnimplError`。runner 对 12 个已覆盖 case 为 `MATCH`；因
`Unimpl` 及上列剩余分支仍为 `UNTESTED`，fixture overall status 是
`PARTIAL_MATCH`，模块继续保持 L2。


## 2026-09-26 SLEIGH-RUSTIFY-PHASE3-0001: assembly_mnemonic

`SleighCtx::assembly_mnemonic(offset)` probes the engine's `printAssembly` mnemonic
(`translate.hh:442` / `sleigh.cc:722`) for one instruction. The linear driver walks use it
to classify no-effect padding by the .sla's own constructor table (the `:NOP rm32`
constructors carry empty templates but their rm operands' attached address semantics make
the engine emit operand pcode; Ghidra's flow-following pipeline never lifts unreachable
padding, so a linear walk filters NOP-classified ops to keep the oracle's effective IR).

## 2026-09-29 SPEEDPROF-SLEIGH-SNAPSHOT-0001: 引擎表快照缓存

`RustSleighEngine::new` 先查 **引擎表快照缓存**，miss 才走冷 `.sla`
解码（之后 best-effort 回写快照）。机制（SPEEDPROF-SLEIGH-SNAPSHOT-0001，oracle
无对应物——锁定 oracle 的 golden 生成器每子同样全量冷解码；这是 Rugra 的工程
超越点，契约是**行为恒等**）：

- **负载**：`Sleigh::snapshot_payload()` = 既有 `SleighBase::encode` 全图遍历
  （WS5 round-trip 已测的写入器）落在 `kuna_enginesnap::FlatEncode`（打包协议的
  定宽紧凑镜像：u8 id + 定宽整数码字，读为 memcpy 而非 varint 循环）。
- **装载**：`Sleigh::initialize_from_snapshot()` = 既有 `SleighBase::decode`
  构建代码（decodeSlaSpaces → SymbolTable::decode → buildXrefs）走
  `FlatDecode` 传输——**与冷路径同一构建代码路径**，恒等由构造保证；单测
  `snapshot_load_is_graph_identical_to_cold_build` 以冷/快照引擎双侧
  PackedEncode 再编码逐字节相等 + 实指令解码 op-for-op 相等钉死。
- **缓存键/文件**：`/dev/shm/rugra-sleigh-snapshots/`（或
  `$RUGRA_SLEIGH_SNAPSHOT_DIR`）下 `<sla FNV64>-<kuna 构建摘要>.v2.snap`；
  kuna 构建摘要由 `crates/kuna-sleigh/build.rs` 对 kuna-base/kuna-num/
  kuna-sleigh 源树内容计算并在编译期嵌入（`kuna_sleigh::BUILD_DIGEST`）——任何
  引擎解码/编码源码变更自动失效旧快照。写入 = tmp + `rename(2)` 原子发布，
  并发首子竞争幂等。
- **失败策略**：性能 fail-open（任何 miss/损坏/解码错误→冷路径+重写），
  行为 fail-closed（部分解码引擎永不泄出——解码失败的引擎整体丢弃重建）。
- **开关**：`RUGRA_SLEIGH_SNAPSHOT=0` 全禁用（A/B 恒等证明用）；
  `RUGRA_SLEIGH_SNAPSHOT_REPORT=1` 输出 `[SNAP] miss/hit/read/decode/write`
  stderr 观察行（默认全静默——stdout 是输出契约面）。
- **性能注记（本道钻定）**：快照削减的是 ingest(zlib 13ms)+传输层；剩余
  ~74ms 为**图物化本体**（~1.5-2M 次小分配 + 首触缺页 + 首跑指令缓存），
  任何重装载形态（含手写 arena 直载，实测分配地板 ~50ns/次）都无法绕过——
  该结构性下界使"子进程重装载"与 oracle 冷解码同成本量级；快照机制的全部
  可得收益 ≈ 引擎相位 0.096→0.080s。进一步收益需分配器/形态级机制
  （后续票证据在案）。

## 2026-09-29：`user_op_names`（MCENSUS4-SQLITE-FTSTYPING-0001，Lane FTSINCRMERGE）

- **`SleighCtx::user_op_names() -> Vec<Vec<u8>>`** / 引擎侧
  `RustSleighEngine::user_op_names` — C++ `Translate::getUserOpNames` /
  `SleighBase::getUserOpNames` 通道：.sla `userop` 名表按 CALLOTHER-index
  序返回（kuna `SleighBase::get_user_op_names` 的 `&[Vec<u8>]` 视图克隆）。
  消费者=`UserOpManage::initialize`（userop.cc:392-403，经 gen 驱动
  architecture.cc:635 位置接线）。
