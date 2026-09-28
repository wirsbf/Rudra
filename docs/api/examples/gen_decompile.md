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

## 符号通道（GEN-CODEPTR-SYMBOLIZE-0001）

驱动持有**两条**函数符号通道，对齐 golden harness 的两层结构：

1. **名字代理**（既有）：`fd.add_symbol(vaddr, name)` → `fd.symbol_table`
   （`Funcdata::addSymbol`，funcdata.cc:34 的驱动侧形态）。call-site 命名、
   PTRSUB 符号化等按地址直查该表。
2. **print-DB 通道**（2026-09-27 补）：action 管线之后、`PrintC::new` 之前，
   构造 `Database::new(false)` 并对全局 scope 逐 GenFunction
   `add_function(Address::new(vaddr), name, 1)`（consume size 1 =
   `glb->min_funcsymbol_size` 默认），克隆 Architecture `set_symboltab` 后换入
   `fd.arch`。`doc_function` 起点快照 `fd.arch.symboltab`（printc.rs，
   对应 `glb->symboltab`），使 `PrintC::push_ptr_code_constant`
   （printc.cc:1730-1742）的 `queryFunction(Address(code,val))` 命中后经
   名字代理印函数显示名——先例 = curl 驱动 CURL-CODEREF-SYMBOLIZE-0001
   print-DB（curl_decompile.rs:6894-6924）。

**契约要点**：

- swap 是 print-only：action 相位在原 arch（无 DB）上先行完成，零 action 相位
  漂移；DB 只含 FunctionSymbol（无数据符号/只读区间），print 侧其它 symboltab
  消费者（spacebase 臂容器查询、readonly 检查）在代码地址外不命中，与 golden
  同 DB 内容同命中语义。
- 去重契约：`discover_functions` 地址唯一（static → dynamic → PLT 首胜），
  对齐 golden `registerFunctionSymbol`（regen_ghidra_golden.py:219-231）的
  `queryFunction` 先注册胜语义；ELF 裸符号名无 `::`，全局 scope + 全名即
  `findCreateScopeFromSymbolName` 的退化形态。
- 残差注记：CODEPTR-TYPE 形态②（`code *pcStack` vs `int8 iStack`）与
  CODEPTR-DECL 形态③（`code *unaff_R12` vs `xunknown1 *`）含 typeprop code*
  元类型传播深层根因，print-DB 通道修复后残余另行分诊（票行注记）。

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

## 门禁用法

```bash
# 单函数（stderr 出 --list 索引）
target/fast-release/examples/gen_decompile /usr/local/bin/sasquatch --one 391

# 镜面全量（cwd=worktree 根，sleigh_specs CWD 相对）
RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=600 \
  target/fast-release/examples/gen_decompile /usr/local/bin/sasquatch \
  > /dev/shm/.../sq_mirror.c 2> /dev/shm/.../sq_mirror.err

python3 tools/compare_ghidra.py <mirror.c> tests/golden/ghidra_sq_1204.direct-runner.c \
  --base 0 --summary-only
python3 /dev/shm/rugra-tests/mirrortriage/mirror_family_census.py <mirror.c> <golden.c> \
  --clusters 25 --samples <face>_census.json
```

关联：`docs/api/examples/parallel_decompile.md`（同 face 的线程形态驱动）；
MIRRORTRIAGE 终报 §3.1（/dev/shm/rugra-reports/LANE_MIRRORTRIAGE_2026-09-27.md）。
