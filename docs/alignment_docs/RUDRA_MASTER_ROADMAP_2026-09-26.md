# Rugra 总路线图（2026-09-26 制定）

> 终局目标：赢过所有反编译器（Ghidra/kuna/Binary Ninja/angr）。
> 路径：Ghidra 12.0.4 完全体（1:1）→ 通用化（任意二进制）→ 增强层（逐函数择优）→ 实测登顶。
> 本文档为跨 wave 纲领；活动任务以 `docs/TODO_BOARD.md` 为准，模块状态以 `ALIGNMENT_ROADMAP.md` 为准。

## Phase 0 — 对齐冲刺（当前；预计 1-2 周收敛）

**目标**：五语料"零未解释差异"；defects/numbering 全零保持；fixture 账本持续扩容。

| 项 | 状态（2026-09-26） |
|---|---|
| canon curl 200 / httpd 255 残差族 | 在飞/在账：F4-WEBTYPE（printc 域）、typing 族、A/B/C/F/G 族、A/G iced 族 57 行（待 Phase3 iced 退役） |
| CSPEC-GLOBAL-APPLY-0001（P0 符号 DB） | 已交付待 CR+合并：sq 镜面 −2288、httpd +32（棘轮重钉随合并） |
| SLEIGH Phase2 运行时换装（32,687 行） | 在飞：op-for-op+E2E 字节恒等门禁，未过禁删 C++ 链 |
| 重启链②GENWIRE（libsqlite3 3 函数 ~272 行验收面） | 在飞 |
| FSPEC-DEINDIRECT / BINSWEEPFIX / 双 CR | 在飞 |
| PERF-ACTIONPOOL-ITER / database 残余 7 项 / GLOBREPIN 族 | 排队（域空闲滚动派） |

**里程碑判据**：canon 双语料逐行差异要么清零、要么有锁定 oracle 证明的非语义归因（"零未解释差异"口径）。

## Phase 1 — 并行化落地（Phase 0 收敛后立即；~1 周）

- **PHASE1-LAND**：多函数并行进生产驱动（PoC 已证 sqlite3 6.28×@8w + 字节恒等；arch 重建=串行 46% 为最大杠杆）
- **TFSINGLE step2**（PAREVAL-TF-PERARCH-WIRING-0002）：9 调用点全量穿参去 shim（step1 已落：per-Architecture 解析，工厂模式效应=0 实证）
- 判据：并行输出与串行字节恒等进 verify 脚本（观察中性门禁常设化）

## Phase 2 — 通用化（与 Phase 1 并行；~2-3 周 + 决策点）

- **FRONTEND-MINIMAL-0001（P1）**：最小前端——BFD 符号表导入+函数发现+DWARF 全量导入+demangling（现成 crate）+字符串/引用分析；预播种通道保留为 override
- **前端质量分级（诚实评估）**：符号/DWARF/demangle/入口点=便宜且高影响（覆盖全部非 stripped 场景）；**stripped 二进制的函数发现=致命且昂贵**——决定"有没有得反编译"，是 Ghidra analyzer 套件存在的理由，也是 kuna #299（假入口 2100 个）翻车的地方
- **决策点（Phase 3 实测后）**：若目标语料/基准以非 stripped 为主，最小前端即够；若 stripped 场景是胜负面，则开 STRIPPED-DISCOVERY 工作包（analyzer 级函数发现——借鉴 Ghidra 思路但不做 1:1 移植，该层无锁定 oracle 约束）
- **SLEIGH Phase3**：iced-x86 退役切换门（4 处侧用换 SLEIGH 基；A/G 残差族 57 行预测只改善）
- 验收：端到端差分（前端自动播种输出 ≡ 手工 canon 播种输出，同二进制）+ bin_sweep 66 面泛化回归
- 判据：任意二进制零手工播种可跑；stripped 面按 Phase 3 数据定投入

## Phase 3 — 实测对比（超越 kuna Phase B；~1 周）

- **PERFBENCH**（在飞）：Rugra vs Ghidra 同口径对拍（锁定 oracle stage-projection runner；user CPU 为主指标抗本机负载噪）
- **DecBench 头对头三方**（Rugra/Ghidra/kuna）：default 轨（≈Ghidra 基线 + 逐函数 diff=0 自证对齐）+ enhanced 轨
- **mpengine 级大二进制实测**：kuna #510 反例战场（其公开最差案例 29m54s+2 panic vs Ghidra 约一半）
- **kuna 开放 issue triage**：#299（i386 PE 假入口 2100 个）/#261（C++ 类弱/无 struct 识别）——免费胜利清单
- 判据：三方数字表 + Rugra 相对 Ghidra 速度倍率 + 差距归因

## Phase 4 — 增强层（超越 kuna Phase C；~3-6 周）

- **best-of-N 选择器**（核心胜负手）：重编译 byte-match 硬门禁 + goto/label 软排序 + **arity 检查**（kuna 自认 GED 对 arity 盲）；默认路径永远 oracle 字节恒等，增强按函数择优
- **SAILR 级结构化变体**（option-gated 三档）：reducible 恒等 / irreducible 回退增强 / edge 排序（kuna 实测语义为参照）
- **ML 类型/命名层**（打 kuna 空白维度）：DIRTY 语料=Ghidra 输出零适配；命名层语义安全先行，类型层 gated+重编译验证；LLM 永不进确定性核心
- 判据：DecBench enhanced 轨 Union > 41.06% 且 type_match > Ghidra（7.56%）

## Phase 5 — 工程化（穿插进行）

- **crate 化**（对齐收敛后）：lifter（Phase2 免费给出）→ pcode → types → struct → print → actions → driver；每步抽取用 canon cmp 字节恒等证中性
- **门禁 CI 化**（机制 F 要求）：本地 hook 同款检查进版本化 CI
- wave 收尾例程：镜面棘轮重钉 / registry continuity checkpoint 推进 / GLOBREPIN 清理 / CURRENT_STATUS 刷新

## 三护城河（贯穿所有 Phase）

1. **逐函数活 oracle 门禁**——kuna 2026-06-20 已删其真 oracle（此后无逐函数活 Ghidra 对拍）；Rugra 的 216+ 双侧 fixture registry 持续复利
2. **重编译选择器闭环**——kuna roadmap 16.4 未做项（accept-or-rollback 只有计量半边）
3. **ML 类型层**——kuna roadmap #261 无任何 ML 计划

## 禁宣传项（非差异点）

Rust 语言本身 / SLEIGH 来源（同一上游 vendor，双方同码）/ datatests 语料 / GED 指标 / BTreeMap 确定性。
