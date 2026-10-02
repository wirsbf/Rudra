# FULL-CORPUS-0001 — curl 驱动函数发现层（RUDRA_DISCOV）

状态：DISCOV lane（wt/discov）。首次落地 2026-09-25。
写域：`examples/curl_decompile.rs`（驱动分析层）+ 本文档 + TODO 看板。

## 1. 问题

curl 驱动的反编译语料来自 `GOLDEN_CORPUS_LEDGER`——锁定 12.0.4 oracle
（e40ed130）analyzeHeadless run 的 124 条 provenance 硬清单。这是把
Ghidra Java 前端（loader/PLT/entry analyzer + 调用跟随）的**函数发现**
整个外置成了一张静态表：换任何一个二进制，驱动就没有函数宇宙可用。
本层把这根拐杖拔掉：`RUDRA_DISCOV=1`（opt-in）时，语料全集改由驱动
自己从二进制里**发现**，ledger 只留作对拍基准。

## 2. 判据

锁定 ghidra 树只有 decompile C++ 源（无 Java），因此本层的判定标准
**不是**逐行 Java 对应，而是**发现集合 vs ledger/canon 窗的对拍**：

- 召回率 = |发现集 ∩ ledger| / |ledger|（漏 = 哪些类别没发现到）
- 精确率 = |发现集 ∩ ledger| / |发现集|（多 = 什么来源的误报）

## 3. 发现层形态（`discover_function_corpus`）

### 3.1 种子

| 来源 | 语义 | 本 fixture 的产出 |
|---|---|---|
| ELF entry（`e_entry`） | 入口点函数（ELF 导入器 + EntryPointAnalyzer） | `_start` 0x3370 |
| 定义型 STT_FUNC 符号（.symtab ∪ .dynsym，落在可执行段） | loader 的符号函数；stripped 二进制只剩 .dynsym 这一路 | 31 条（main、21 个内部函数、crt 桩、`__libc_csu_init/fini`、`_init`/`_fini`） |
| `.plt` 首槽（PLT0） | canon 见证 `FUN_00102020` @0x2020 | 1 条 |
| `.plt.sec` 槽（16 字节步长；无 .plt.sec 时退回 `.plt` PLT0 后的 lazy 槽） | 重定位背书的 PLT thunk | 43 条 |
| `.plt.got` 槽（8 字节步长，`endbr64; bnd jmp *disp32(%rip)` 编码校验——驱动 PLT 解析同款扫描） | GLOB_DAT 背书的 thunk | 1 条（`__cxa_finalize` 0x22e0） |
| EXTERNAL 块槽（每个 UND .dynsym 符号 8 字节，`external_block_base` 起） | `getNextExternalBlockEntryAddress` 分配序；`EXTERNAL-STUB-SUPPORT-0001` 渲染 halt_baddata 桩 | 48 条（0x19000..0x19178） |

BIND_NOW + 存在 `.plt.sec` 时 lazy `.plt` 槽（0x2030..0x22d0）**不是**
函数：没有任何调用到达它们，canon ledger 也一条未记。

### 3.2 调用图跟随（迭代至不动点）

每个有体的种子（EXTERNAL 槽除外）线性解码（iced-x86，与 Shared Return
Calls 前置pass同款），每条**直接 CALL** 目标：

- 落在可执行段内；
- 不在已知入口表里；
- 不落在另一个**有尺寸**已知函数体内部（函数中段调用 ≠ 新入口）；

→ 成为新函数（`FUN_` + image-based 地址命名，与 httpd 驱动的
`analyze_headless_function_symbol_name` 通道同源——即 PARAMID 迭代宇宙
的 "analyzer-discovered callees" 来源）。新函数入队再扫，直到一轮零
新增。

CALLIND 位置在发现期没有常量目标（Ghidra 在**反编译期**经 thunk/
jumptable 机制解析——worker 已移植该机制），故只有直接 CALL 目标入队。
本 fixture 上不动点在首轮后达成（零新增：全部直接调用目标要么是
symtab 符号要么是 PLT 桩）。

### 3.3 体尺寸

- `st_size>0` 符号：取 st_size；
- PLT 槽：段步长（16/8）；EXTERNAL 槽：1（BadDataError step，
  flow.cc:446-456）；
- `st_size==0` 符号（`_init`/`_fini`、crt 桩）、entry 种子、调用图新增：
  取 `[entry, 下一个发现入口)`，尾部以段末封顶——这是**工作界**而非
  Ghidra 的流式分析体。worker 的流走查以 entry 播种、范围不设上界，
  界内 padding 永远活不成代码；可见残差只有 Funcdata 尺寸元数据
  （ledger 已知地址的 canon 头照旧打印 ledger 尺寸，语料面不变）。

### 3.4 接线

- `RUDRA_DISCOV=1`：语料循环以发现集为源；共享返回 CALL_RETURN 前置
  pass 的分析体表（`analysis_bodies`）同样换发现集界（保持自持）；
  DWARF 名先验、ELF 符号名/尺寸优先、ELF-backed origin 校验等合并
  规则与 ledger 路径完全同源。
- 默认（env 未设）：走 ledger，逐字节旧面（发现层为死代码）。

## 4. 对拍结果（锁定 fixture，commit 见 TODO 行）

见 `report_discovery_vs_ledger` 的 `[DISCOV]` stderr 输出；数字以
lane 报告为准（/dev/shm/rudra-reports/ 与 TODO_BOARD 行内证据）。

## 5. 边界与后续

- 发现层是**驱动分析层**实现（写域约束）；若要上升为库能力
  （src 载体），须另立 TODO 并按 B2 机制出 oracle fixture。
- 代码引用跟随（lea 代码指针、switchD 默认处理器）是 httpd 驱动
  已有的通道；本 fixture 上全部回调目标都有 symtab 符号，故未启用，
  stripped 语料上需要时按 HTTPD-CODEPTR-LEA-0001 形态接入。
