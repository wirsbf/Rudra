# AGENTS.md — Rudra AI 开发铁律

> Rudra 是 Ghidra 的 Rust 重写版,目标是**完整、1:1 对齐 Ghidra 反编译器的所有算法**。

## 架构流水线

`二进制解析 → 汇编提升(iced-x86/SLEIGH) → P-code IR → SSA/Heritage → 控制流结构化 → C 代码生成`

Ghidra 源码位于 `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`。项目的唯一源码 oracle 锁定为
**Ghidra 12.0.4** tag `Ghidra_12.0.4_build`，commit
`e40ed13014025f82488b1f8f7bca566894ac376b`(114 个 `.cc` 文件)。不得用 `master`、其他 tag
或网页最新行号与该 oracle 混用。

## 对齐 Oracle 与唯一完成定义

- 所有 golden、函数 fixture、差分报告和 Alignment Evidence 必须记录 oracle commit、架构、
  compiler spec、analysis options 与输入指纹。任一项缺失即为 `NO_ORACLE`。
- `docs/alignment_audit/FUNCTION_MAP.md` 是逐函数账本入口；每个 Ghidra `.cc/.hh` 函数必须有
  稳定 ID、完整签名、Rudra 对应物、状态和行为证据。分母冲突已裁决并关闭（FMAPRECON 车道,
  `docs/alignment_audit/FUNCTION_MAP_RECONCILE_2026-09-26.md`）: `~2055` = 手写计划子集估算、
  `~5200+` = 归档手审部分文件集计数、`5549` = 解析器唯一名粒度——均非全量分母。**唯一权威
  完成分母 = 9494**（5691 `.cc` + 3803 `.hh` inline，机器账本 15811 条 raw 记录 1:1 全等，
  缺失 0/多余 0）。REGEN 车道（2026-09-26）已在 master 锚点重生成四件套并通过 `--check`
  （checkpoint `80ffb7d1`，Rust 侧 11007 条，解析器旁证 `--cross-check` 5549/5530 恒等）:
  注解映射 4538 / 未映射 4956——映射只证明来源指向，未映射含真缺失、SLEIGH 替代层与未链接
  三类，待后续分解；**完成度判定以逐函数 oracle 行为门禁为准**（全部 9494 默认 `UNTESTED`，
  仅锁定 oracle fixture 完整同输入/同输出可升 `MATCH`）。
- “替代实现”或“战略排除”不会自动算对齐。除纯 UI/控制台桥接外，必须证明同一可观测输入下
  行为等价，否则记 `MISSING`、`MISMATCH` 或 `UNTESTED`。
- 全局完成的唯一判定：函数账本无 `MISSING/MISMATCH/NO_ORACLE/UNTESTED`，所有映射函数
  通过真实 Ghidra oracle 行为门禁，主管线与回归语料零未解释差异。

---

## 🔴 核心铁律(违反即失败)

### 铁律 1 — Ghidra 源码先行,禁止任何简易实现

**(1.1) 移植任何模块前,必须先读对应 `.cc` + `.hh`。禁止凭记忆/猜测/经验实现。**

**(1.2) 修改任何 `src/*.rs` 函数前,本 session 内必须重新读过该函数对应的 Ghidra 函数代码全貌**(不止签名行,要读完整个函数体)。PreToolUse hook (`.zcode/align_gate.py`) 通过 `.alignment_receipts.json` 回执强制此规则。

**(1.3) 每个 `src/*.rs` 非测试函数上方必须有一行 `// Ghidra: <file>:<line> <ghidraFn>` 注释**(指向 Ghidra 函数定义的起始行)或 `// RUDRA-GLUE: <为何 Ghidra 没有对应物>`(纯 Rust 语言结构胶水:构造器/访问器/trait impl/借用安全 helper)。无注释 = 自创函数 = 违反对齐。`tools/check_ghidra_annotations.py` 在 commit 时强制。

**(1.4) 禁止任何形式的简易实现**。包括但不限于:
- ❌ "先用简化版,以后再对齐" / "差不多就行" / "这个我看不懂,跳过"
- ❌ 把 Ghidra 有的东西标 `// TODO` / `// simplified` 而无 `ALIGNMENT_ROADMAP.md` 记录
- ❌ 因 Rudra 缺基础设施(缺 op / 缺 flag / 缺数据结构)就在上层绕过 — 必须**从底向上补齐**
- ❌ 凭记忆猜 flag/字段/边界语义 — 必须读 Ghidra 行确认
- ✅ 复杂度高时,**兴奋**地读 Ghidra,拆小片段,画数据流图,直到懂

**(1.5) 禁止移除/禁用 Ghidra 有的 Rule/Action/算法**。Rudra 侧出 bug 时,默认假设是**移植缺陷**(守卫缺失/算法不完整/基础设施缺口),去读 Ghidra 源码修。只有核实 Ghidra 确实没有该机制时,才考虑保守降级(必须注释说明降级理由 + 修复路径)。

**(1.6) P-code 必须完整**。缺失的 op / 不完整的 op 语义必须补齐 P-code 层,禁止让上层 Action/Rule 适配/绕过。

### 铁律 2 — 遇 bug 先看 Ghidra 怎么做

任何 bug / 失败 / 非收敛 / 输出错误,**第一步是读 Ghidra 对应源码看它怎么处理,第二步才是改 Rudra**。Ghidra 能跑就有解法,找不到说明读得不够细。

### 铁律 2.1 — 逐函数同输入同输出

- “同输入”包括参数、引用对象/别名关系、全局与 `Architecture` 状态、地址空间、选项、
  初始 IR/CFG/SSA、随机种子和错误注入条件。
- “同输出”包括返回值/异常、所有输出参数及对象突变、创建/删除/重排的
  Varnode/PcodeOp/边、flags/type/symbol 状态、迭代顺序以及最终文本/字节。
- 只允许规范化已证明无语义的临时 ID；规范化不得删除顺序、别名、控制流或状态差异。
- 每个被修改的映射函数必须用同一 fixture 分别运行 Ghidra oracle 与 Rudra，对比完整观察结果。
  仅 Rust 自测、手写 expected、代码形似或 curl 单样本通过，均不能证明函数对齐。

### 铁律 3 — 原子化提交 + 文档同步

- 每个逻辑自洽的改动单元立即 `git commit`。禁止积累未提交改动。
- `src/*.rs` 改动 → 同 commit 更新 `docs/api/*.md`(pre-commit hook 强制)。
- 模块状态变更 → 同 commit 更新 `ALIGNMENT_ROADMAP.md`(L1→L2→L3)。
- `docs/TODO_BOARD.md` 是活动任务队列，`ALIGNMENT_ROADMAP.md` 是模块状态账本，二者不得混用。
- 任一缺口被发现、认领、阻塞、解锁、送审或验证完成时，当轮立即更新 TODO；
  代码状态变化必须同 commit 更新。
- 每项 TODO 必须包含稳定 ID、Ghidra/Rudra 函数、状态、owner agent、依赖、精确 write-set、
  验收命令、证据 commit 和最后更新时间。
- 代码中的 `TODO/stub/placeholder/simplified/no-op` 必须引用 TODO ID；未登记缺口禁止存在。
- 差分非零可提交修复进度，但每个剩余差异必须绑定 TODO ID，模块最高保持 L2，禁止宣称已对齐。

### 铁律 4 — 禁止空轮

每轮对话必须产出以下之一:✅ 新代码 commit / ✅ Ghidra 源码深度分析(记录到 `ALIGNMENT_ROADMAP.md` 或 `docs/alignment_docs/`)/ ✅ Bug 根因定位(记录修复方案)/ ✅ 测试验证证据(gcc 审计、Ghidra 结构骨架 diff、输出对比)。❌ 禁止纯"目标尚未完成"声明。遇难题禁止说"多会话项目",继续读 Ghidra 找答案。

### 铁律 5 — 禁止随意回退已验证的工作

已通过 build + 测试 + curl/httpd 验证的改动,禁止因后续步骤受阻就 `git checkout`/回退。已验证成果必须立即原子化提交锁定(铁律 3)。**并发 agent 协作警示**:后台 agent 可能跑 `git restore`/`checkout` 清工作区 — 同一文件的 edit 必须串行,关键编辑后立即 build + commit。

### 铁律 6 — 依赖图驱动的并行开发

- 主 Agent 先根据函数账本构建依赖 DAG，优先修复高扇出地基，再启动上层 wave；吞吐指标是
  “本 wave 新增真实 oracle 验证通过函数数”，不是 LOC、commit 数或 Rust 测试总数。
- Agent 编辑前必须在 TODO 看板认领稳定 ID、精确函数和 write-set。同一文件同一时刻只能有
  一个 writer，`src/foo.rs` 与 `docs/api/foo.md` 视为同一租约。
- 只有 write-set 无重叠且依赖已满足的任务才能并行。源码审计、独立模块实现、golden 生成、
  文档和只读复核可并行。
- reviewer 必须是独立 Agent，自己打开并逐行读 Ghidra 函数；复核期间只读。实现变更后旧批准
  自动失效，必须重审。
- 每个 Agent 交付必须包含 commit hash、改动文件、验证命令结果、剩余差异 ID 与 TODO 更新。
- 提交只允许显式 `git add <owned files>`；提交前核对 staged 文件，禁止 `git add -A`、
  `restore/checkout/stash` 干扰其他 Agent。
- 每个 wave 结束由主 Agent 串行集成 commit、运行全量与差分门禁，再更新下一 wave。

---

## 🛡 防漏机制

### 机制 A — 对齐证据块(Alignment Evidence)

**任何 commit message 出现 `align`/`port`/`对齐`/`faithful` 字样时,message 体必须包含 `## Alignment Evidence` 块。** pre-commit hook 扫 message,缺块拒绝提交。

块必须逐条核对**四类决定性语义**(在读 Ghidra 行时逐项确认,缺一项即为未读够):

1. **引用/输出参数**(`&` / `*` / 返回值 / out 参数)——是否跨调用共享状态?是拷贝还是引用?
2. **循环边界与遍历顺序**——`begin()/end()` 是什么容器?排序键是什么?边界 `<` 还是 `<=`?
3. **计数器/累加器的初值、增量时机、作用域**——per-X 独立还是全局共享?何时重置?
4. **排序/比较键**——`operator()` / `compare()` 比的是什么字段?相等时 tie-break?

块格式:

```
## Alignment Evidence
Ghidra: <file>:<line> <函数签名逐字摘录>
  关键决定性语义（四类，逐条核对）:
  - 引用/输出参数: ...
  - 循环边界/遍历顺序: ...
  - 计数器/累加器: ...
  - 排序/比较键: ...
Rudra: <file>:<line> <对应函数>
  - <逐条对应, 注明如何对齐上述每一类>
四类决定性语义核对: [x]引用参数 [x]遍历顺序 [x]计数器 [x]排序键
```

### 机制 B — 差分测试门禁(Differential Test Gate)

**凡改动影响"可见输出"的模块,单元测试全绿不等于对齐。必须跑 Ghidra 黄金输出差分测试。**

白名单模块(改动这些文件时触发门禁):
- `src/printc.rs`、`src/prettyprint.rs`(C 文本输出)
- `src/varmap.rs`(变量命名/符号)
- `src/blockaction.rs`、`src/coreaction.rs`(控制流结构化、Actions 影响输出)
- `src/ruleaction.rs`(Rules 影响 IR 形态)

```bash
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func <改动函数> -v
```

**判定**:
- `defects=0 + numbering=0`:可提交。
- `defects>0 或 numbering>0`:commit message 必须含 `## Differential` 块,逐处解释每个缺陷(对齐缺陷 / 已知限制 / 待修)。**未解释的缺陷 = 不可提交。**
- `skeleton diff>0`:不一定是对齐缺陷(for↔while 等价变换),但需在 `## Differential` 块说明。

> 正典 golden 是 `tests/golden/ghidra_curl_1204.c`(12.0.4,与源码 oracle 同版)。
> `ghidra_curl.c`(11.3.2)仅作历史回归信号。**注意**:compare 的全量 skeleton 数字
> 受日志噪音影响(stderr 的 `[SYM]`/`[STEP]` 行勿混入 stdout);函数级结论以
> `--func` 或函数体提取对比为准。

### 机制 B2 — 逐函数行为差分门禁

任何 `src/*.rs` 映射函数的行为改动都必须产生一个以锁定 oracle 运行的函数 fixture，状态只能是：

| 状态 | 含义 | 是否允许 L3 |
|---|---|---|
| `MATCH` | 完整观察结果零差异 | 是 |
| `MISMATCH` | 已有真实 oracle，仍有已登记差异 | 否 |
| `NO_ORACLE` | 没有真实 Ghidra 运行结果或版本/选项不同 | 否 |
| `UNTESTED` | 分支、边界、错误路径或状态突变未覆盖 | 否 |

低层函数改动还必须验证受影响调用闭包与端到端语料。手写 expected 只能作为 Rudra 回归测试，
不能将 `NO_ORACLE/UNTESTED` 升为 `MATCH`。

### 机制 C — 强制独立复核(Cross-Review)

**核心算法模块的"对齐"改动,单 agent 自检不可信,必须由另一个 agent 独立复核。**

核心算法白名单(高价值、紧耦合、错了扩散面大):
- `src/heritage*.rs` / `src/jumptable.rs` / `src/blockaction.rs` / `src/condexe*.rs`
- `src/varmap.rs` 核心算法层(RangeHint/AliasChecker/MapState/ScopeLocal)
- `src/merge.rs`
- 任何被标注为"主管线 Action/Rule"的改动

复核 Agent 必须:
- 自己打开 Ghidra 源码读对应行,**不得直接采信实现 Agent 的 Alignment Evidence 块**(那只是声明,不是证据)。
- 独立列出四类语义清单再对比,发现任一 MISMATCH → REJECT,指出 Rudra 行号 + Ghidra 行号 + 修正方向。
- 在 commit message 加 `## Cross-Review: APPROVE` 块。

**判定准则**:核心算法白名单模块的 commit,若无 `## Cross-Review: APPROVE` 块,不得合并到主管线分支。

### 机制 D — Red Flags 自查(命中即停)

**commit message 或代码出现以下信号时,作者必须立即停下手,回去重读 Ghidra 对应行的决定性语义。不得"先提交再说"。**

🚩 commit message:`faithful port`/`对齐`/`aligns with` 但**没贴** Ghidra 关键行的逐字签名摘录;`Known limitation:` 后跟**作者自己归因**;`scheme matches, only X differs`;引用行号但**没引用那一行的语义细节**;测试只列 `N/N pass` **没有 Ghidra 输出对比**。

🚩 代码:`HashMap<&str, u32>` 当计数器而 Ghidra 是单一 `int4 base`;`per-prefix`/`each X`/`各自` 等暗示独立计数;写死字符串列表而 Ghidra 用 `virtual` 动态派发;`print`/`emit` 阶段做 Ghidra 在 `Action` 阶段做的事;`discovery_pass`/两阶段 guard 而 Ghidra 单阶段确定性。

🚩 流程:"这个先做,那个以后再对齐";`// TODO`/`// simplified` 无 ALIGNMENT_ROADMAP 记录;测试通过就提交,没问"Ghidra 跑同输入会一样吗"。

### 机制 E — 编辑前重读 Ghidra(hook 强制)

铁律 1.2 的机器强制版。详见 `docs/alignment_docs/HOOK_GUIDE.md`:
- **PreToolUse hook** (`.zcode/align_gate.py`):每次 Edit/Write/MultiEdit 拦截 `src/*.rs`,要求 `.alignment_receipts.json` 里有该 Ghidra 文件**本 session 内**的 read 回执。无回执 → deny。
- **PostToolUse hook** (`.zcode/record_receipt.py`):agent 每读 `ghidra/.../cpp/*.cc|*.hh`,自动写回执。
- **commit 兜底** (`tools/check_ghidra_refs.py`):校验所有 `// Ghidra:` 引用的 `file:line` 真实存在。
- **手动补回执**:`python .zcode/record_receipt.py <ghidra_file> <line_start> <line_end>`。
- **紧急逃生** `ZCODE_ALIGN_GATE=0`(必须记录理由)。⚠ 配置仅在新 session 加载,中途改不生效。

### 机制 F — 门禁健康自检

每个 session 首次编辑前必须验证：

1. `ghidra/` 存在且 HEAD 等于锁定 oracle commit。
2. `git config core.hooksPath` 指向版本化 hook 目录，`pre-commit` 与 `commit-msg` 存在且可执行。
3. hook 使用当前 repo root 与 `python3`，不得硬编码 Windows/子目录路径。
4. `check_ghidra_annotations.py --all`、`check_ghidra_refs.py --all --strict` 与
   `check_alignment_evidence.py` 四类语义 dry-run 全部通过。

任一项失败时，不得宣称该门禁“强制”或任何模块 L3；必须立即登记 P0 基础设施 TODO 并优先修复。
本地 hook 不是最终信任边界；同样检查必须进入版本化 CI。

---

## 📋 L1/L2/L3 路线图

详见 `ALIGNMENT_ROADMAP.md`。状态变更必须当场更新路线图。

| 级别 | 含义 |
|---|---|
| ✅ L3 | 账本内所有函数/分支/状态影响完整实现 + 接入主管线 + 12.0.4 oracle `MATCH` |
| 🟢 L2.5 | 核心算法 1:1 移植完成 + 有测试,但未接入主管线 |
| 🔧 L2 | 核心算法缺失/未对齐 |
| 📋 L1 | 完全缺失,需从零实现 |

模块级逐行状态以 `ALIGNMENT_ROADMAP.md` 为准(该文件头部「最后核实」日期标注时效)。

---

## 📁 文档归属

| 文档 | 内容 |
|---|---|
| `ALIGNMENT_ROADMAP.md` | L1/L2/L3 全量模块对齐路线图(〇节=114 文件架构分类) |
| `docs/TODO_BOARD.md` | 当前 wave 活动任务、owner/write-set/依赖/验收证据 |
| `docs/HANDOVER_2026-08-24.md` | **交接文档**:基线验证命令、根因图(RC-A~F 带双侧行号)、salvage 清单、操作套路与坑 |
| `docs/alignment_docs/PIPELINE_STAGES_1204.md` | **反编译管线完整架构**:78 节点 Action 树、循环/restart/断点机制、稳定切点、阶段投影 |
| `docs/alignment_docs/HOOK_GUIDE.md` | 机制 E 的 hook 配置与回执操作 |
| `docs/alignment_audit/FUNCTION_MAP.md` | 锁定 oracle 的逐函数权威账本入口 |
| `docs/alignment_audit/*_GAPS_*.md` | 6 份跨模块深度审计(jumptable/coreaction/condexe/ruleaction/fspec/flow),逐函数对照+依赖 DAG |
| `CURRENT_STATUS.md` | 项目整体状态、可靠性评估、当前反编译质量数据 |
| `GAP_ANALYSIS.md` | 功能鸿沟对比 |
| `ALIGNMENT_PROGRESS.md` | 类/算法层面的 Ghidra 映射进度 |
| `docs/VERIFICATION_GUIDE.md` | 对拍验证实操手册(oracle 环境搭建、fixture 跑法) |
| `docs/alignment_docs/` | 硬核对齐规则(寄存器映射、P-code 对照等)与历史专项报告 |
| `docs/api/` | 与 `src/` 1:1 映射的 API 参考文档 |
| `ghidra/.../cpp/*.hh` | **Ghidra 自带的权威架构文档**:每个 .hh 头部 doxygen 注释即该子系统的架构描述(铁律 1 的必读物) |

---

## ⚙️ 构建与验证

```bash
cargo check --lib                                  # 日常类型/借用快速反馈
cargo build --profile fast-release --lib           # 日常优化库构建
cargo build --release                              # wave 收尾正式构建
cargo test --lib                                   # 单元测试
cargo run --release --example curl_decompile       # curl 正式反编译门禁
cargo run --release --example httpd_decompile      # httpd 正式反编译门禁
python tools/audit_syntax.py result/curl_cur.c      # gcc 语法审计
python tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl.c --summary-only  # 差分门禁
```

### 编译反馈效率（Agent 执行规范）

- Agent 按验证目的选择最小 Cargo target：源码编辑首轮使用 `cargo check --lib`，需要优化库产物时使用 `cargo build --profile fast-release --lib`，E2E 验证精确选择对应 example。
- 主 Agent 在 wave 收尾、主管线集成和发布验证阶段集中执行正式 `cargo build --release`、全量测试与 oracle 门禁。
- 编译性能实验使用固定源码快照、固定 toolchain、固定 target 冷热状态与固定后台负载；每个候选至少记录 wall/user/sys、峰值 RSS、Cargo timing 报告和退出状态。
- nightly 并行前端实验依次测量 `-Zthreads=4/8/16`，codegen 实验依次测量 `codegen-units=16/32/64`，Cargo 调度实验依次测量物理核附近的 jobs 值；Agent 以重复测量中位数选择本机默认值。
- 多 Agent 并发构建为每个 writer 分配独立源码快照；使用共享编译缓存时为各 Agent 分配独立 `CARGO_TARGET_DIR`，使用共享 target 时由主 Agent 调度构建时段。
- Agent 保留可复用的 Cargo 依赖与增量缓存；临时 benchmark target 使用明确的任务专属路径，并在证据归档后清理该路径。
- 编译配置优化提交同步记录基线、候选、收益比例、缓存命中条件和正式 release 回归结果；正式 release 与 oracle 差分结果作为语义验收终点。

### 实操坑位备忘(hook/提交/度量)

- **commit message 红词**:`align`/`port`/`对齐`/`faithful` 子串即触发机制 A(连 `RULE-PORT-xxx` 这类 ID 也算);docs-only 提交措辞避开即可,不必硬凑 Evidence 块。
- **pin 重钉双形态**:fixture 因 src 变更失效时,重钉三件套 = runner shell 变量(commit/tree/**git blob id**)+ metadata comparand(**文件 sha256**)+ overlays 表。`rev-parse` 校验用 blob id、`sha256sum` 校验用文件哈希,两种形态别混。
- **result/ 回流约定**:每次 E2E 后 `cp /tmp/<run>.log result/curl_cur.c`(gitignored 存档),防陈旧事故。
- **worktree 惯例**:runner 需 `ghidra -> 主仓/ghidra` symlink(gitignored);GIT_DIR 劫持已修(tools/check_gate_health.py 清环境变量),worktree 提交无需 --no-verify。
- **worktree 内禁用 `git stash`**(2026-08-30 三起事故):stash 栈是 repo 级共享(~170 worktree),并发 agent 交错 push/pop 会弹错分支致改动丢失;一律 per-worktree commit(wip checkpoint --no-verify)。
- **分支修复测试代码放内存盘**(2026-09-21 用户指令;**2026-09-23 扩展到 worktree**):
  agent 在分支/worktree 上修复时产生的测试代码(探针脚本、调试 harness、临时 fixture 草稿、A/B 对拍驱动)一律写入内存盘 **`/dev/shm/rudra-tests/<branch>/`**;**新 worktree 一律建在
  `/dev/shm/rudra-worktrees/<name>`**(commit 对象存于主仓 .git 对象库=重启安全,工作区易失可由 wip 纪律覆盖)。
  在飞车道完成前不迁移其 worktree;空闲的旧 `/home/ls/Rugra-wt-*` 在下次认领时迁移。
  **回收纪律(2026-09-23 用户指令)**: 车道交付并集成后立即回收其内存盘资源
  (`rm -rf /dev/shm/rudra-targets/<lane>` 与已合并 worktree 的 `target/`);root 在每次
  merge 后执行清扫,agent 在 lane 收尾时自清自己的 /dev/shm 产物目录(保留 LANE_REPORT
  等结论文件可归档至 /dev/shm/rudra-reports/)。
  例外:按机制 B2 必须固化的双侧回归 fixture,只在 root 集成阶段挑拣入库,分支上仍先在内存盘迭代。内存盘重启即丢,未集成的证据自行负责及时归档。
- **oracle 环境**:`/tmp/rudra-ghidra-bfd-2.38` 机器重启即丢;重建用直连 https 拉 binutils-dev deb 解包(**apt 代理不可用**)。

当前反编译质量数据见 `CURRENT_STATUS.md`(不再放 AGENTS.md,避免数据过期)。

---

## 🛠 代码规范

- **不可变性优先**(`let` 而非 `let mut`,借用而非拷贝)
- **卫语句**(Early Returns,降低圈复杂度)
- **`anyhow::Result`** 错误处理(不 `.unwrap()`)
- **精准英文命名**(`snake_case` / `PascalCase` / `SCREAMING_SNAKE_CASE`)
- **`// Ghidra:` 注释必须指向函数定义起始行**,不是类声明行/构造函数行(否则触发机制 D 的 cited-line-drift Red Flag)
- **调试输出**:用 `eprintln!`(stderr),不用 `println!`(污染 stdout 的 C 输出)。标准 TAG:`[ACTION]` `[STEP]` `[INJECT]` `[COLLAPSE]` `[BLOCKSTRUCT]` `[DECOMP]` `[PREPASS]` `[PTRSTAMP]`。临时 TAG(`[DBG]` `[DEBUG]`)提交前必须删除。

---

## 💡 Commit Style

```text
align: port varmap.cc RangeHint/AliasChecker/MapState to Rust
core: implement ActionCast in coreaction pipeline
fix: emit_block_structured preserves while loops after return
```

含 `align`/`port`/`对齐`/`faithful` 关键词的 commit 必须附 `## Alignment Evidence` 块(机制 A)。核心算法白名单模块的 commit 必须附 `## Cross-Review: APPROVE` 块(机制 C)。
