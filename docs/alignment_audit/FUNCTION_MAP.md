# Ghidra 12.0.4 ↔ Rudra 函数账本入口

本目录的权威机器账本由 `tools/generate_function_ledger.py` 从锁定 oracle 与当前
Rust 源码生成：

- `FUNCTION_LEDGER.json`：每个 C++ definition/declaration 与 Rust function 的稳定 ID、
  完整 Ctags 签名、源码 span、annotation 映射种类和行为状态。
- `FUNCTION_MAP.generated.md`：按 oracle 文件汇总 definition 映射覆盖率。
- `PROTOCOL_TABLE.json`：C++/Rust 协议敏感常量的原始观察与跨语言候选组；同名不代表等价。
- `DEPENDENCY_DAG.json`：Rust module、Ghidra include 和 TODO 依赖边。

```bash
python3 tools/generate_function_ledger.py
python3 tools/generate_function_ledger.py --check
python3 tools/generate_function_ledger.py --reconcile-continuity --check
python3 tools/generate_function_ledger.py --cross-check
```

## 当前唯一分母

锁定 `Ghidra_12.0.4_build` / `e40ed13014025f82488b1f8f7bca566894ac376b`
的 Universal Ctags 6.2.0 口径是：

| 类别 | 数量 | 完成度用途 |
|---|---:|---|
| `.cc` definitions | 5691 | 行为分母 |
| `.hh` inline definitions | 3803 | 行为分母 |
| **behavior definitions 合计** | **9494** | 唯一函数级完成分母 |
| `.cc` prototypes | 101 | declaration 参考 |
| `.hh` prototypes | 6216 | declaration 参考 |
| raw function records | 15811 | definitions + declarations |

旧手工文档的 `~2055` 只覆盖少量文件，保留为历史审计笔记，不再作为完成度分母。

> **分母对账已收口（2026-09-26）**: `~2055` / `~5200+` / `9494` / `5549` 四口径冲突已裁决
> （四个不同度量，互不矛盾；9494 为唯一完成分母），9494 已双方法独立复现，机器账本
> 15811/15811 记录全新枚举 1:1 全等。裁决依据与复现命令见
> `FUNCTION_MAP_RECONCILE_2026-09-26.md`；root 侧账本重生成票 `FMAPRECON-REGEN-0001`。
>
> **账本四件套已在 master 锚点重生成（2026-09-26，REGEN 车道收口）**: continuity
> checkpoint 推进到分支线锚 `80ffb7d1`（^1=registry 线 b382a54f，master 侧 e486fb18；
> first-parent 437 commits，Rust 记录 10581 → 11007），窗口定性 119 reviewed
> transitions + 66 tombstones + 492 introduced（逐 token origin 钉定，ambiguous=0/
> collisions=0）；`--check` 与 `--reconcile-continuity --check` 均 rc=0，新增解析器旁证
> `--cross-check`（5549/5530/122/103 恒等）。当前映射口径：注解映射 4538 / 未映射 4956
> （映射=来源指向，行为状态全部默认 `UNTESTED`）。

## 状态解释

- `exact_definition_start` 只证明 Rust 注释指向定义起始行。
- `inside_function_body` 表示引用漂移或多函数合并，必须人工审计。
- `UNTESTED` 是所有 definition 的默认行为状态。
- 只有记录 oracle commit、架构、compiler spec、analysis options、输入指纹，并对完整
  可观察状态做同输入 direct diff 的 fixture，才能把对应 definition 改成 `MATCH`。
- annotation、代码形似、Rust 单测或旧 11.3.2 golden 都不能提升行为状态。

`FUNC_*.md` 文件仍可用于阅读上下文，但不能覆盖生成账本中的稳定 ID、状态或分母。
