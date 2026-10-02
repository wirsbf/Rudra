# `tools/verify_mirror_gate.sh` — 第四门禁（镜面三口径）runner

Source: `tools/verify_mirror_gate.sh`. 台账: `tools/mirror_gate_baselines.tsv`。

## 用法

```bash
tools/verify_mirror_gate.sh [--corpus curl|httpd|vsh|sq|sqlite|all] [--bin-dir DIR] [--keep-dir]
                            [--jobs N]      # N>1: 五面并发(SPEEDPROF-PAR-FACES-0001), 默认 1=串行
                            [--no-cache]    # 禁用 digest 缓存(等价 RUDRA_GATE_CACHE=0)
tools/verify_mirror_gate.sh --update-baseline <TODO_ID>
tools/verify_mirror_gate.sh --self-test
```

五面契约（Ghidra 12.0.4 e40ed130 direct-runner golden，`tests/golden/*_1204.direct-runner.c`）:
`RUDRA_MIRROR=1` 的 curl/httpd 驱动 + `RUDRA_GEN_MIRROR=1` 的 gen 驱动三宿主语料
（vsh/sq/sqlite；宿主资产缺失时该面显式 SKIP）。判定 = 冻结基线单向棘轮
（skeleton>ceiling / defects>0 / numbering>0 / matched<floor / 健康信号非零 → FAIL）。

## 陈旧守卫（INFRA-EXAMPLES-STALELINK-0001，双层，每轮无条件先行）

- mtime 层: 驱动二进制早于 HEAD commit 时间戳 → FAIL。
- 内容层: `gen_decompile --stale-guard-probe`，build.rs 嵌入源码指纹运行时重算比对
  （cargo 增量/缓存复用未重链的权威判定）。

## digest 缓存（GATE-DIGEST-CACHE-0001，2026-09-28）

重复验收轮（同二进制+同语料+同 golden → 同结果）免全量重跑，每面独立:

- **键** = sha256(schema, corpus, 驱动二进制, 语料输入二进制, golden,
  baselines 台账, `compare_ghidra.py`, `sleigh_specs/{x86-64-gcc.cspec,x86-64.pspec}`)
  全部取文件内容 sha256。驱动运行期读取的全部磁盘输入均入键
  （curl/httpd 语料与 cspec/pspec 是运行时 `fs::read`，非编译期嵌入）；
  env-gated 种子清单在镜面态被驱动显式忽略，不入键。
  **任一分量变 → 键变 → 失效全量重跑（fail-closed）**。
- **值** = verdict 块 + `mirror.c`/`mirror.err`/`compare.txt`；manifest 记录每件产物
  sha256，命中时逐件重算校验，校验不过视为未命中（fail-closed）。
  重放时产物物化回当轮 WORK_DIR，verdict 块做 WORK_DIR 路径替换后 stdout
  与冷轮**字节恒等**；命中 provenance 走 stderr。
- **只缓存 PASS 轮**——FAIL 轮永远全量重跑（诊断新鲜性，不缓存瞬时噪声）。
- **守卫协同**: stale-guard（mtime+内容探针）每轮照常先行，缓存只跳过 face 执行；
  键含二进制内容 digest，与 stale-guard 无冲突面。
- **并发安全**: 条目目录 = `<corpus>-<64hex>`，整备于 tmp 目录后原子 rename；
  `--jobs N` 并行 dispatcher 下各面独立键互不干扰；写入只发生在未命中之后
  （条目缺失或校验不过），无条件替换目标条目——同键全量重跑产物确定性恒等，
  竞态覆盖无害，且损坏条目在下一次 PASS 全量轮自动自愈。

### 缓存目录管理

- 位置: `${RUDRA_GATE_CACHE_DIR:-/tmp/rudra-gate-cache}`。
- 容量: 默认上限 40 条（`RUDRA_GATE_CACHE_MAX`），写入后按 mtime LRU 淘汰，
  只删除匹配 `<corpus>-<64hex>` 的条目目录。
- 禁用: `--no-cache` 或 `RUDRA_GATE_CACHE=0`；目录不可用时自动降级为不缓存并告警。

## 自检

`--self-test` 无需真实二进制，覆盖: compare 摘要解析、fail-closed 缺省计数、
baseline 读取、键确定性、键分量敏感性（驱动/golden 内容变→键变）、缺输入→无键、
条目完整性校验、产物篡改检测、非 PASS/键失配条目拒验、LRU 淘汰。
