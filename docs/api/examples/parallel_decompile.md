# `examples/parallel_decompile.rs` — 生产多函数并行反编译驱动

Source: `examples/parallel_decompile.rs`（PHASE1-LAND 车道，票
`PAREVAL-PHASE1-LAND-0001`；PoC 前身 = `examples/pareval_poc.rs`，设计 =
`docs/alignment_docs/PARALLELIZATION_DESIGN_2026-09-26.md` §2）。

## 定位

bin_sweep / gen_decompile 族的**线程形态**生产驱动：同一 bare-native face
（GENSMOKE-0001：BFD 函数发现 + PT_LOAD image + import 重定位 + bare
Architecture + 全默认 action 管线 + PrintC），把整函数作业分发到 K 个
256MB 栈 worker 线程。`--jobs 1` 即串行形态退化（单 worker，index 序，
同一代码路径）——并行驱动在 N=1 时**就是**串行驱动。

bin_sweep 的进程级隔离形态（每函数一子进程 + timeout）保留为硬超时与
病态语料（已知非终止函数族）的兜底；本驱动无跨线程 kill，只有作业间
协作检查。

## 并行模型（设计文档 §2.1 契约）

- **作业不可迁移**：一个函数的 Architecture / Funcdata / SLEIGH lifter /
  Address 空间 tag 全部在单线程内生成消费（SPACE-0001 线程域纪律，
  thread_local SPACE_TAG_TABLE 不能跨线程解析）。跨线程只传
  `(vaddr, name, size)` 入参和 `String` C 文本出参。
- **每函数新建 Architecture**（含 commentdb）：复用会串函数 warning 注释
  （设计文档 §1.3#3）。
- **动态队列**（largest-first 选集后按地址序入队）：天然负载均衡；完成序
  与作业序解耦由结果按 idx 重排吸收。
- **TypeFactory = 进程单例 `shared_default()`**：与 bin_sweep / gen_decompile
  生产形态一致（PAREVAL-TF-SINGLETON-WIRING-0001 落地前保持同工厂域，
  并行 vs 串行比较才是同口径）。

## 输出布局（确定性，逐函数可比）

```
<out-dir>/<run-name>/
  f<NNN>_<name>.c        每函数一个 C 文件，NNN=零填充函数索引（地址序）
  typedef_preamble.c     run 级 typedef 前导（每进程恰好一次，见下）
  manifest.jsonl         每函数记录：idx/name/vaddr/size/status/signature/
                         bytes/md5/wall_us
  run.json               run 级记录：corpus/jobs/workers/计数/墙钟/commit
```

### typedef 前导剥离（进程级 artifact 处置）

`printc.rs` 的 `TYPEDEFS_EMITTED` 是进程级 AtomicBool（"once per decompiled
file"，多函数单进程运行中进程即文件）：每进程恰好一个函数的打印文本带
215 字节固定 typedef 前导块，**载体由打印序决定**（串行=首 idx；并行=首
完成）。四个正典门禁早已把它归一化（compare_ghidra.py:109/141）。本驱动
剥离精确 215 字节（边界=前导自身收尾 tag_line；docFunction cc:2653 的
`emit->tagLine()` 前导换行属**每个**函数文档，不属前导），落盘
`typedef_preamble.c` 一次，函数文件 = 纯函数文档（统一 `\n` + 函数体），
门禁恢复纯字节 cmp。

## CLI

```
cargo run --profile fast-release --example parallel_decompile -- \
    <binary> [--jobs N] [--max-funcs N|all] [--skip 1,2] \
    [--out-dir DIR] [--name RUN] [--quiet]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--jobs N` / `-j` | 1（或 env `RUDRA_PAR_JOBS`） | worker 线程数；1=串行形态 |
| `--max-funcs N\|all` | 24 | 最大函数选集（largest-first，地址 tie-break）；`all`=全量 |
| `--skip 1,2` | 无 | 选集后索引跳过表（病态函数筛除口径） |
| `--out-dir DIR` | /dev/shm/rudra-tests/phaseland/parallel-out | 输出根 |
| `--name RUN` | `<image>_j<N>` | run 子目录名 |
| `--quiet` | 关 | 抑制 stdout 摘要行 |

退出码：`0`=全部 Ok；`1`=存在 err/panic 函数（语料属性，非驱动失败）；
`2`=驱动/环境错误。

## 确定性门禁

`tools/verify_parallel_determinism.sh [--corpus curl|httpd|sqlite3|all]
[--jobs N] [--bin-dir DIR] [--keep-dir] [--self-test]`

- 协议："并行=观察中性"（设计文档 §2.2）——serial（jobs=1）与
  parallel（jobs=N）**跨进程**逐函数字节 cmp（强于 PoC 同进程三臂），
  非 Ok 结果按 status+signature 恒等判。
- 语料面：curl 31 全量 / httpd 34 全量 / sqlite3 45（48 最大筛 3 病态，
  skip 8,24,30 = PoC 口径）；语料二进制缺失显式 SKIP。
- exit 0=GREEN，1=RED（差异），2=驱动/环境失败。

## 已知边界

- 无跨线程硬超时：病态函数（PATHOSLOW-DIVCHAIN-0001 残差慢尾）会拖住
  一个 worker；硬超时需求用 bin_sweep 进程形态。
- sqlite3 全量 1385 函数的扩量验证与 workers 缩放曲线见车道终报
  （`/dev/shm/rudra-reports/LANE_PHASE1LAND_2026-09-26.md`）。
