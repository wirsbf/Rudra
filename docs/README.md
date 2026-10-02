# Rudra 文档索引

`docs/` 的统一入口。原则:**热点文档少而准,历史材料进 archive,工具引用的路径不动**。

## 顶层导航(按用途)

| 你想做什么 | 去哪里 |
|---|---|
| 续作/接手开发 | [`HANDOVER_2026-08-24.md`](HANDOVER_2026-08-24.md) — 基线验证命令、根因图、salvage 清单、踩坑备忘 |
| 认领任务 | [`TODO_BOARD.md`](TODO_BOARD.md) — 活动 wave 看板(owner/write-set/验收证据) |
| 查某模块对齐状态 | [`../ALIGNMENT_ROADMAP.md`](../ALIGNMENT_ROADMAP.md) — 114 文件架构分类 + L1/L2/L3 账本 |
| 理解反编译管线架构 | [`alignment_docs/PIPELINE_STAGES_1204.md`](alignment_docs/PIPELINE_STAGES_1204.md) — 78 节点 Action 树/循环机制/切点 |
| 查某 Ghidra 函数的账 | [`alignment_audit/FUNCTION_MAP.md`](alignment_audit/FUNCTION_MAP.md) → `FUNC_*.md` / `FUNCTION_LEDGER.json` |
| 查某模块的深度差距 | [`alignment_audit/`](alignment_audit/) 的 `*_GAPS_*.md`(jumptable/coreaction/condexe/ruleaction/fspec/flow) |
| 搭 oracle 对拍环境 | [`VERIFICATION_GUIDE.md`](VERIFICATION_GUIDE.md) |
| 查 Rust API | [`api/`](api/) — 与 `src/` 1:1 |
| 开发规则与门禁 | [`../AGENTS.md`](../AGENTS.md)(铁律+机制 A-F+坑位备忘) |
| 当前质量数据 | [`../CURRENT_STATUS.md`](../CURRENT_STATUS.md) |

## 目录结构

```
docs/
├── HANDOVER_2026-08-24.md   # 交接文档(自包含)
├── TODO_BOARD.md            # 活动任务看板(唯一当前优先级来源)
├── VERIFICATION_GUIDE.md    # oracle 环境与 fixture 实操
├── PROJECT_STRUCTURE.md     # 工程结构说明
├── data_contract.md
├── api/                     # Rust API 参考,与 src/ 1:1(api/align、api/bin 等子树对应)
├── alignment_docs/          # 硬核对齐知识
│   ├── PIPELINE_STAGES_1204.md   # ★ 管线完整架构(78 节点树+断点/续跑+稳定切点)
│   ├── HOOK_GUIDE.md             # 机制 E hook 配置
│   ├── ADDRESS_SPACE_PHASES.md   # 地址空间模型
│   ├── blueprints/               # 管线迁移/SSA phi/类型格 设计蓝图
│   ├── checklists/               # x86-64 调用约定等核对单
│   └── handoff/                  # 历史交接补丁(如 cspec slices)
├── alignment_audit/         # 逐函数账本 + 审计(勿改动 JSON——被 tools/ 引用)
│   ├── FUNCTION_MAP.md / FUNCTION_LEDGER.json / DEPENDENCY_DAG.json  # 账本三件套(工具引用)
│   ├── FUNC_*.md            # 按 Ghidra 文件域分组的逐函数对照
│   ├── *_GAPS_2026-08-2*.md # 6 份深度差距审计(带根因图)
│   ├── *_audit.md           # 早期单模块审计(action/cover/database/grammar…)
│   └── *_2026-08-1*.md      # 基础设施专题(FOUNDATION/CORE_FOUNDATIONS/MARSHAL/PARAM_BIND…)
├── method/                  # 方法论快照格式、实现手法
├── workflow/ decisions/ experiments/ branches/ src_ref/  # 工作流模板/决策记录/实验留档
└── archive/                 # ★ 历史材料(只读考古,不再维护)
    ├── agentlog/            # 2025-04~2026-04 的 25+ 篇工程进度日志
    ├── dated/               # 已过时的日期性报告(2026-06-29~07-02 专题)
    └── function_audit/      # 早期 BATCH1-6 函数审计(被 FUNCTION_LEDGER 取代)
```

## 规则

1. **日期性报告**完成后即移入 `archive/dated/`(含日期的文件名天然适合归档)。
2. `alignment_audit/*.json` 与 `FUNCTION_MAP.md` 被 `tools/oracle_registry.py`、
   `generate_function_ledger.py` 引用,**路径不可动**。
3. 文档冲突时的采信顺序:与锁定 oracle/当前代码一致的 > 更新的 > 结论更克制的;
   发现失真修文档,不沿用旧说法。
