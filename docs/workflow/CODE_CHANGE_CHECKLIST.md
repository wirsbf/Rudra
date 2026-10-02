# 代码变更→文档同步检查清单

当你修改 `rudra/src/` 下的代码时，必须按以下清单检查是否需要同步更新文档。  
本清单是 Phase C（维护流程固化）的核心交付物。

---

## 必查项

### 1. 新增 / 删除 / 重命名源文件

| 变更类型 | 必须同步更新的文档 |
|---------|------------------|
| 新增 `.rs` 文件 | `docs/PROJECT_STRUCTURE.md`（模块清单）; 评估是否需要新增 `docs/api/` 对应文档 |
| 删除 `.rs` 文件 | `docs/PROJECT_STRUCTURE.md`; 标记或删除 `docs/api/` 中对应文档 |
| 重命名 `.rs` 文件 | `docs/PROJECT_STRUCTURE.md`; 更新 `docs/api/` 中的文件引用 |

### 2. 公共接口变更（pub fn / pub struct / pub enum / pub trait）

| 变更类型 | 必须同步更新的文档 |
|---------|------------------|
| 新增公共接口 | 对应的 `docs/api/*.md` |
| 删除公共接口 | 对应的 `docs/api/*.md`（标记为已移除或删除整个文档） |
| 修改公共签名 | 对应的 `docs/api/*.md`（更新签名和语义说明） |
| 修改 `lib.rs` 的 `pub mod` / `pub use` | `docs/api/lib.md`; `docs/api/README.md` |

### 3. 模块职责变化

| 变更类型 | 必须同步更新的文档 |
|---------|------------------|
| 模块职责扩展或收缩 | `docs/PROJECT_STRUCTURE.md`; 对应 `docs/api/*.md` |
| 模块间依赖关系变化 | `docs/data_contract.md`（如涉及主链路数据流） |

### 4. CLI / 使用方式变化

| 变更类型 | 必须同步更新的文档 |
|---------|------------------|
| CLI 命令变化 | `README.md`; `docs/api/bin/rudra.md` |
| 示例代码变化 | `README.md`; 对应 `docs/api/*.md` |

### 5. 测试 / 验证流程变化

| 变更类型 | 必须同步更新的文档 |
|---------|------------------|
| 新增测试用例 | `docs/VERIFICATION_GUIDE.md`（如属于验证链路） |
| 对拍样本新增 / 修正 | `ALIGNMENT_PROGRESS.md`; `docs/TODO_BOARD.md` |
| 测试框架变化 | `docs/VERIFICATION_GUIDE.md` |

### 6. 项目阶段 / 状态变化

| 变更类型 | 必须同步更新的文档 |
|---------|------------------|
| 能力边界变化 | `CURRENT_STATUS.md` |
| 对齐验证结论变化 | `ALIGNMENT_PROGRESS.md` |
| 项目结构重组 | `docs/PROJECT_STRUCTURE.md`; `README.md` |

---

## 证据来源规则

状态类文档（`CURRENT_STATUS.md`、`ALIGNMENT_PROGRESS.md`、`docs/VERIFICATION_GUIDE.md`）中的每个关键结论必须附带证据来源，格式为：

```
**证据来源**: `cargo test <test_name>` 通过 (2026-04-24)
**证据来源**: `src/align/varnode.rs:verify_varnode()` 实现中明确跳过 unique offset 比较
**证据来源**: 见 `docs/archive/agentlog/engineering_progress_2026-04-24_*.md`
```

### 证据类型优先级

1. **测试通过记录**（最强）：`cargo test <name>` + 日期
2. **代码引用**：具体文件路径 + 函数名 + 关键逻辑
3. **示例运行记录**：输入 → 输出 + 日期
4. **工程日志引用**：`docs/archive/agentlog/<file>.md` 中的具体段落
5. **设计决策引用**：`docs/decisions/<file>.md`

### 禁止的证据形式

- ❌ "经过充分测试"（没有具体测试名）
- ❌ "已验证一致"（没有对比方法和数据）
- ❌ "按计划完成"（没有实际执行证据）

---

## 会话结束检查清单

每次会话结束前，确认以下项已完成：

- [ ] `docs/archive/agentlog/` 已新增本次会话的工程日志
- [ ] `docs/TODO_BOARD.md` 已更新（包括完成项标记、新增待办项、下一步建议）
- [ ] 如有结构变化：`docs/PROJECT_STRUCTURE.md` 已更新
- [ ] 如有 README 涉及的变化：`README.md` 已更新
- [ ] 如有新规范约定：`AGENTS.md` 已更新
- [ ] 如有对齐验证变化：`ALIGNMENT_PROGRESS.md` 已更新，且附带证据来源
