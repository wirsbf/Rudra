# `examples/gen_decompile.rs` — hermetic 单函数/全量反编译门禁驱动

Source: `examples/gen_decompile.rs`（GENSMOKE 谱系 gen 面；本档首次登记于车道
CODEPTR / `GEN-CODEPTR-SYMBOLIZE-0001`，2026-09-27）。

## 定位

镜面 gen 面的**正典驱动**：BFD 函数发现（静态 `.symtab` FUNC → `.dynsym` FUNC →
PLT JUMP_SLOT 桩，按地址 `or_insert_with` 首胜去重）+ PT_LOAD 内存镜像 + bare
Architecture + 全默认 action 管线 + `PrintC::doc_function`。两种运行形态：

- `--one <index>`：单进程单函数（大栈线程内）；
- all-mode（默认）：每函数一个隔离子进程，`RUGRA_GEN_TIMEOUT_SECS` 逐函数
  超时帽（默认 60s），`RUGRA_GEN_MIRROR=1` 对齐 golden direct-runner 契约。

对照 oracle = `tools/regen_ghidra_golden.py` 的 "one"/全量模式（BfdArchitecture
init → followFlow(code:0, code:highest) → universal action → PrintC docFunction），
golden = `tests/golden/ghidra_{sq,sqlite}_1204.direct-runner.c`。

## 符号通道（GEN-CODEPTR-SYMBOLIZE-0001 / S2CODESTAR-DOWNCHAIN-0001）

驱动持有**三条**函数符号通道，对齐 golden harness 的层次结构：

1. **名字代理**（既有）：`fd.add_symbol(vaddr, name)` → `fd.symbol_table`
   （`Funcdata::addSymbol`，funcdata.cc:34 的驱动侧形态）。call-site 命名、
   PTRSUB 符号化等按地址直查该表。
2. **analysis-DB 通道**（2026-09-28 补，S2CODESTAR-DOWNCHAIN-0001 根因一）：
   `build_architecture` 之后、flow/action 之前，构造 `Database::new(false)` 并
   对全局 scope 逐 GenFunction `add_function(Address::new(vaddr), name, 1)`，
   克隆 Architecture `set_symboltab` 后作为**分析侧** `fd.arch`。这是 oracle
   golden harness 的 `registerFunctionSymbol`（regen_ghidra_golden.py:219-231 →
   `scope->addFunction`；生产同面 = `BfdArchitecture::init` readLoaderSymbols）
   的 1:1 对应：`ActionConstantPtr::isPointer` 的容器查询（coreaction.cc:1151
   `queryContainer`，Rugra 侧 `Funcdata::query_container_parent_scope`）自此能
   命中函数地址常量，`Funcdata::spacebaseConstant`（funcdata.cc:360-461）把
   LEA 派生常量换形 `PTRSUB(spacebase-0, symaddr)` 并将输出定型为
   ptr-to-符号类型——函数符号类型 = `TypeCode`（database.cc
   FunctionSymbol::buildType），即 typeprop 的 **code\* 铸造种子**。
   此前该查询通道恒 None，镜面 arm 的 code* 种子恒零。
3. **print-DB 通道**（2026-09-27 补）：action 管线之后、`PrintC::new` 之前，
   构造同内容 `Database`，克隆 Architecture `set_symboltab` 后换入 `fd.arch`。
   `doc_function` 起点快照 `fd.arch.symboltab`（printc.rs，对应
   `glb->symboltab`），使 `PrintC::push_ptr_code_constant`
   （printc.cc:1730-1742）的 `queryFunction(Address(code,val))` 命中后经
   名字代理印函数显示名——先例 = curl 驱动 CURL-CODEREF-SYMBOLIZE-0001
   print-DB（curl_decompile.rs:6894-6924）。

**契约要点**：

- analysis-DB 先于 flow/action 安装（oracle 的符号自 Architecture init 起即在）；
  analysis 相位的 symboltab 消费者由此可命中：`ActionConstantPtr::isPointer`、
  spacebase 容器查询、CALLIND 常量目标 deindirect 等。
- print swap 仍是 print-only 语义；DB 含 FunctionSymbol + **readonly 属性范围**
  （2026-09-28 补，见下节；无数据符号），其它 symboltab 消费者在代码地址外
  不命中，与 golden 同 DB 内容同命中语义。
- 去重契约：`discover_functions` 地址唯一（static → dynamic → PLT 首胜），
  对齐 golden `registerFunctionSymbol`（regen_ghidra_golden.py:219-231）的
  `queryFunction` 先注册胜语义；ELF 裸符号名无 `::`，全局 scope + 全名即
  `findCreateScopeFromSymbolName` 的退化形态。
- 残差注记：CODEPTR-TYPE 形态②（`code *pcStack` vs `int8 iStack`）、
  CODEPTR-DECL 形态③（`code *unaff_R12` vs `xunknown1 *`）与 7 星指针戳链
  （`uint4 *******`）的深层根因 = varmap↔downChain 反馈环 runaway
  （SQLCENSUS-CODESTAR-DOWNCHAIN-0001 根因二，事件级已钉死、src 修复待续，
  见 /dev/shm/rugra-reports/LANE_S2CODESTAR_2026-09-28.md）。

## 只读装表与段链字节（MIRRORCENSUS-GEN-READONLY-STRFOLD-0001，2026-09-28 车道 GENREADONLY）

**动机（MIRRORCENSUS2 §3-H 新钉族）**：oracle golden 的字符串常量折叠
（`unaff_R12 = "LIT"`，sqlite 镜面 120 行 + sq 18 行）在 Rugra 侧永不发生——
`PrintC::pushPtrCharConstant` 的 isReadOnly 门（printc.cc:1709）恒拒。链路：

- oracle：`LoadImageBfd::getReadonly`（loadimage_bfd.cc:286-303）遍历 BFD 段链
  装每个 `SEC_READONLY` 段范围 → `Architecture::fillinReadOnlyFromLoader`
  （architecture.cc:1371-1381）`setPropertyRange(Varnode::readonly)` OR 进
  symboltab flagbase。**BFD 的 ELF 后端映射 `!SHF_WRITE → SEC_READONLY` 无
  SHF_ALLOC 前提**（真 BFD 2.38 探针实证，FSTRFOLDUP 车道），故非 ALLOC 段
  （.comment/.gnu_debuglink/.debug_\*）以裸 VMA 入表。
- gen 驱动此前**零 readonly 代码**（curl 驱动有 .rodata 范围、httpd 已由
  FSTRFOLDUP 装表——本票先例照抄对象）。

**修复（双件，均 examples 胶水）**：

1. **readonly 范围装表**（print-DB install 块）：ELF 段表过滤
   `sh_size>0 && !(sh_flags & SHF_WRITE)`，BFD 吸收段同构排除（SHT_SYMTAB /
   名 `.strtab` 的 SHT_STRTAB / `e_shstrndx` 段）——1:1 复现 BFD 段链
   SEC_READONLY 段集；`Database::set_property_range(READONLY, Range)` 逐段
   装入 print-DB。**print-DB only**：analysis-DB 保持纯函数符号面（swap 在
   perform_action 之后），action 管线通道缺失态不变，零 action 相位漂移。
2. **`overlay_bfd_nonalloc_sections`**：`LoadImageBfd::loadFill` 是**段链**
   服务（loadimage_bfd.cc:124-179，`findSection` 首段命中即供
   `bfd_get_section_contents(vma 偏移)`），非 PT_LOAD 内存像——把每个暴露的
   非 ALLOC PROGBITS 段文件字节叠到其 VMA。**重叠 VMA（sasquatch 的
   .comment+.debug_\* 全在 vma 0，.debug_info 尺寸 0x28a6a 与 .text
   [0x6d40,0x42bee) 相交）按 findSection 首段命中语义消解：claim 区间
   算术——段表序（=bfd 链序）遍历，ALLOC 段只 claim 不写（PT_LOAD 像内
   字节已精确），非 ALLOC 段只写未被更早链段 claim 的子区间**。首版盲拷
   覆写 .text 代码字节把 sq 面炸到 57020（镜面门禁当场拦截），claim 版
   修复后 .text 字节不动、debug 字节只落 header 区/段间空隙——与 oracle
   `findSection` 逐地址同供字节。NOBITS 无文件字节（仍 claim，.bss 零保持）。

**验收语义**：vsh/sq/sqlite 三面共享本驱动（`verify_mirror_gate.sh` 臂）；
sqlite/sq 镜面 strfold 族收敛（sqlite −~120 / sq −~18 方向）、vsh 零回退
（golden 侧 0 折叠点）；canon 面（curl/httpd 驱动）构造性零触及。

## 陈旧二进制自检（INFRA-EXAMPLES-STALELINK-0001，2026-09-28 车道 INFRASTALE）

**动机（两口实录）**：cargo 增量/缓存复用可让 `target/*/examples/*` 陈旧不重链——
MB29 集成用陈旧 gen_decompile 测出"五面全恒等"，漏检 r3merge 的 sq −86/sqlite −138
镜面效应；CASTFUSEB 车道把同两值错归因到无关 commit（CR-CASTFUSEB 净基 A/B 证伪
两口）。守卫双层落地：

1. **运行时内容自检（权威层）**：`build.rs` 在构建期把守卫域
   （`src/**/*.rs` + `examples/gen_decompile.rs` +
   `examples/common/stale_guard_hash.rs` + `build.rs`——守卫自身构建输入也是域锚点，
   系车道红/绿自测中发现并补上的盲区）的 FNV-1a-64 内容摘要嵌入
   `RUGRA_BUILD_SOURCE_DIGEST`；驱动启动时重算比对，**不符/缺指纹/树不可读一律
   exit 2 fail-fast**（消息含"陈旧二进制"+ 重链命令），**新鲜时完全静默**
   （stdout/stderr 零字节）——canon/镜面输出与无守卫驱动逐字节恒等。
   摘要算法的单点事实源 = `examples/common/stale_guard_hash.rs`，
   `build.rs`（`include!`）与本驱动（`#[path] mod`）逐字共享，双侧不可能漂移。
   内容级设计：与 mtime 无关（touch 不改内容不判陈旧）；检出位置无关
   （相对路径框架，两个内容全等的 checkout 互认 fresh）。
2. **脚本守卫（兜底层）**：`tools/verify_mirror_gate.sh` mtime 检查自
   curl/httpd 扩展到 gen_decompile（二进制早于 HEAD commit 即 FAIL），
   并新增 `--stale-guard-probe` 内容探针（门禁跑前调 `gen_decompile
   --stale-guard-probe`，exit 0/2）。

**运行形态**：

| 场景 | 行为 |
|---|---|
| `--stale-guard-probe` | 只跑自检：fresh → stdout 一行 `STALE-GUARD OK digest=… files=…` exit 0；否则 [GEN-STALE] 块 + exit 2（忽略 inherited 标记，探针必须真探） |
| 正常启动（coordinator/probe 之外） | 静默校验，陈旧即 exit 2（先于一切语料工作，stdout 零输出） |
| all-mode `--one` 子进程 | 继承 `RUGRA_GEN_STALE_GUARD_INHERITED=1`（coordinator 启动时已验同一 exe，子进程免重算——sq 810/sqlite 1385 个子进程不再逐一重扫源码树） |

红/绿自测（19 项全绿）：新鲜 probe/list 双绿静默；内容漂移不重链 → probe 与正常
运行双 exit 2（消息含陈旧二进制+重链命令，stdout 空）；错误 CWD → 源码树不可读
fail-closed；脚本 mtime 层与内容层独立红；`--self-test` 不受扰。
零扰动：vsh 镜面面 base（5eff829f 净快照二进制）≡ head 逐字节恒等（md5 8ca194a4，
ok=71/71）；canon curl/httpd 双语素 base≡head 字节恒等且对 golden 54/0/0·124 与
36/0/0·34 精确命中 MB30 钉值。

## all-mode 函数级子进程池（SPEEDPROF-PAR-CHILDREN-0001，2026-09-28 车道 PARCHILDREN）

**动机（车道 SPEEDPROF 实测，证据 /dev/shm/rugra-tests/speedprof/）**：all-mode
coordinator 原为逐函数串行子进程循环——镜面门禁循环里 vsh/sq/sqlite 三面合计
~24 分钟串行 wall（sqlite 单面 953.6s、sq 393.7s 干净串行锚）。jobs=32 子进程池
harness 实测 sqlite **953.6→165.4s（5.76×，wall==Amdahl 尾界=VdbeExec 166.5s 单极）**、
sq **393.7→43.5s（9.05×）**，且三方字节恒等链在案（官方串行==harness 串行==
harness 并行；sqlite 5,289,364B + sq 全量 cmp）。本票把该形态收编进驱动本体。

**形态（全部 examples 胶水，无 src 触碰）**：

- **worker 隔离 = 每函数一个 `--one <index>` 子进程**（一 Architecture + 一 DB
  per child，CR-S1 已证的隔离形态；不做进程内并行——PAREVAL-DETERM-HERMETICITY-0001
  前置保持）。协调器侧是 `--jobs N` 个有界 worker **线程**，每线程循环领取槽位、
  构造同一 `timeout --kill-after=30s {T}s <exe> <bin> --one i` 子命令（同 env
  镜像态 + `RUGRA_GEN_STALE_GUARD_INHERITED=1`）、经 `run_capped_output`
  （GEN-DRIVER-STALL-0001 监督）收集。
- **输出序恒 = 函数 index 序**：块文本按槽位收集（`child_block` = 历史串行
  四分类 ok/TIMEOUT/PANICKED/ERROR 逐字抽出，含 STALL 臂），池排干后按 index
  序一次性拼接输出——stdout 在任意 `--jobs` 下与历史串行 coordinator
  **逐字节恒等**；完成序只进 stderr 进度行（`[GEN-PAR]`，仅 jobs>1 时发）。
- **enqueue 序**：jobs>1 时最大函数优先（负载均衡，让 sqlite VdbeExec ~166s
  巨物先起跑；调度序不进输出）；jobs==1 时 index 序 = 精确历史串行形态。
- **默认 `--jobs 8`**（共享 112 核宿主保守值；实测 32 安全，8 留余量），
  `--jobs N` / `--jobs=N` 覆盖；非法值 exit 1（fail-closed）。
- **fail-closed**：子进程 spawn 失败（非 STALL 臂）→ 记录首错、池排空、
  exit 1 不发拼装输出；worker 线程 panic → join 失败 → exit 1；槽位空缺
  （理论不可达）→ exit 1。健康线 `[GEN] ok=N/M functions`（stderr）语义不变，
  镜面门禁健康检查零改动兼容。

**验收**：并行 vs 串行全量 cmp 字节恒等（sq+sqlite 双语料三方链复现）；
canon 双语素 md5 恒等（gen 驱动无 canon 面）；镜面五面 PASS；bank/tests 零回退。
性能（本机共享负载，如实记）：见车道终报
/dev/shm/rugra-reports/LANE_PARCHILDREN_2026-09-28.md。

## 逐相位计时通道（SPEEDPROF-FIXEDFLOOR-0001，2026-09-28 车道 FIXEDFLOOR）

**动机（车道钻定，证据 /dev/shm/rugra-tests/fixedfloor/）**：镜面门禁 gen 三面的
每个 `--one` 子进程都要从零装配一套 Architecture——SPEEDPROF 实测每子固定底
≈0.12s（16B 函数子进程 wall），1225/1385 个 sqlite 函数 <0.5s，固定底支配了
串行口径的 ~25% 面墙。本通道把该固定底的构成做成可复现的事件级测量，是
gen 面的 [STEP] 等价物（curl 驱动已有 flow/action/print 通道；SPEEDPROF 终报
将"gen 驱动无 [STEP] 通道"记为画像缺口）。

**用法与形态（全部 examples 胶水，env 门控，默认完全静默）**：

```bash
# 任一模式前置 env（--one 子进程内生效）：
RUGRA_GEN_PHASE_TIMING=1 \
  target/fast-release/examples/gen_decompile <binary> --one <index>
```

- stderr 逐相位 `[PHASE] <label> <delta>s` 行；首行附 `(since process start)`
  腿（进程启动→main 链路含 exec/动态链接/runtime 初始化）。相位切分：
  `discovery`（读取+goblin 解析+符号发现）→ `reparse`/`image_overlay` →
  `build_architecture` 内部（`asm_cspec_read` / `asm_sleigh_engine`＝x86-64.sla
  反序列化 / `asm_register_enum` / `asm_cspec_parse` / `asm_pspec_read_parse` /
  `asm_compiler_config` / `asm_string_manager`）→ `symbols_analysis_db` /
  `fd_symbols` / `lifter_configure` → `flow` → `action` → `print_db_install` /
  `print`。
- **观察中性**：仅当 env 置位时输出，stdout 块/退出码/健康线零触及——canon/
  镜面协议零扰动（`[GEN-PAR]` 进度行先例：stderr 非输出契约面）。
- **钻定结论（本道实测，oracle 侧对照在案）**：每子固定底 0.12s 中
  **SLEIGH 引擎表构建（`asm_sleigh_engine`）=0.096s≈80%**，其余装配
  ≈0.010s，进程启动 ≈0.015s；C++ oracle（golden_dump_1204 "one" 模式，
  同 hermetic 逐函数形态）每子 0.10–0.11s，gdb 采样同形
  （DecisionNode/SymbolTable/PackedDecode 主导两侧）——**固定底是
  oracle 同构的对齐成本**（golden 契约 = 逐函数 hermetic 进程，
  provenance "mode: one, parallel_workers: 12"）。详见车道终报
  /dev/shm/rugra-reports/LANE_FIXEDFLOOR_2026-09-28.md。

## 门禁用法

```bash
# 单函数（stderr 出 --list 索引）
target/fast-release/examples/gen_decompile /usr/local/bin/sasquatch --one 391

# 镜面全量（cwd=worktree 根，sleigh_specs CWD 相对；--jobs 默认 8，
# --jobs 1 = 精确历史串行形态；任意 jobs 输出序恒 = 函数 index 序）
RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=600 \
  target/fast-release/examples/gen_decompile /usr/local/bin/sasquatch \
  [--jobs 8] \
  > /dev/shm/.../sq_mirror.c 2> /dev/shm/.../sq_mirror.err

python3 tools/compare_ghidra.py <mirror.c> tests/golden/ghidra_sq_1204.direct-runner.c \
  --base 0 --summary-only
python3 /dev/shm/rugra-tests/mirrortriage/mirror_family_census.py <mirror.c> <golden.c> \
  --clusters 25 --samples <face>_census.json
```

关联：`docs/api/examples/parallel_decompile.md`（同 face 的线程形态驱动）；
MIRRORTRIAGE 终报 §3.1（/dev/shm/rugra-reports/LANE_MIRRORTRIAGE_2026-09-27.md）。
