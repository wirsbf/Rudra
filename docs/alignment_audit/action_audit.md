# action 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 1163行 (`action.cc`) / Rudra: 1023行 (`src/action.rs`) / 比率: 87%

Ghidra 头文件 `action.hh` 声明的内联方法（`getName`/`getGroup`/`getStatus`/`getNumTests`/`Rule::setBreak` 等）一并纳入审计。

## 设计说明（重要架构偏差）
Ghidra 的 `Action` 是抽象基类，状态字段（`count`/`lcount`/`status`/`breakpoint`/`flags`/`count_tests`/`count_apply`/`name`/`basegroup`）内嵌于对象；Rudra 用 `Action` trait + 外挂的 `ActionState` 结构分离"行为"与"状态"，并把 Ghidra 的内联 `getName`/`getStatus`/`getNumTests` 等改为 trait 方法 `get_name`/`get_flags`。所有 Rudra 入口均标注 `RUDRA-GLUE`（合法，因 trait 形式无 1:1 Ghidra 对应）。本审计以"语义是否覆盖 Ghidra 方法"判定对齐，而非"同名"。

## 已对齐函数 (18个)

### Action (基类 / trait，含 ActionGroup/ActionPool/ActionRestartGroup 的实现)
- `Action::apply` — Ghidra: action.hh:130, action.cc (各子类 apply) ✅ (trait 必填方法；ActionGroup/ActionPool/ActionRestartGroup/ActionTypePropagate 均实现)
- `Action::get_name` — Ghidra: action.hh:108 `Action::getName` ✅ (trait 方法；各子类均实现)
- `Action::reset` — Ghidra: action.cc:100 `Action::reset` ✅ (trait 默认方法；ActionGroup/ActionPool/ActionRestartGroup 各有覆盖)
- `Action::get_flags` — Ghidra: `Action::flags` 字段访问器 (action.hh:84) ✅ (非同名，语义对齐 repeatapply/onceperfunc)
- `Action::perform` — Ghidra: action.cc:298 `Action::perform` ✅ (trait 默认方法，驱动 repeatapply/onceperfunc 状态机；ActionGroup 另有覆盖以委托子 Action)

### ActionGroup
- `ActionGroup::new` / `with_flags` — Ghidra: action.hh:148 `ActionGroup::ActionGroup` ✅
- `ActionGroup::add_action` — Ghidra: action.cc:376 `ActionGroup::addAction` ✅
- `ActionGroup::get_name_str` — Ghidra: action.hh:108 `getName` ✅
- `ActionGroup::num_actions` — 辅助 (RUDRA-GLUE)
- `ActionGroup::apply` — Ghidra: action.cc:506 `ActionGroup::apply` ✅
- `ActionGroup::reset` — Ghidra: action.cc:408 `ActionGroup::reset` ✅
- `ActionGroup::perform` — Ghidra: action.cc:298 `Action::perform` (子类覆盖) ✅

### ActionRestartGroup
- `ActionRestartGroup::new` — Ghidra: action.hh:177 `ActionRestartGroup::ActionRestartGroup` ✅
- `ActionRestartGroup::add_action` — 继承 ActionGroup ✅
- `ActionRestartGroup::apply` — Ghidra: action.cc:554 `ActionRestartGroup::apply` ✅ (含 maxrestarts/curstart 重启循环)
- `ActionRestartGroup::reset` — Ghidra: action.cc:547 `ActionRestartGroup::reset` ✅

### ActionPool
- `ActionPool::new` — Ghidra: action.hh:269 `ActionPool::ActionPool` ✅
- `ActionPool::add_rule` — Ghidra: action.cc:741 `ActionPool::addRule` ✅
- `ActionPool::apply` — Ghidra: action.cc:878 `ActionPool::apply` + action.cc:823 `processOp` ✅ (含 opcode-change 重派发)
- `ActionPool::reset` — Ghidra: action.cc:917 `ActionPool::reset` ✅
- `ActionPool::get_name` / `get_flags` — 同 Action 基类 ✅

### ActionDatabase
- `ActionDatabase::new` — Ghidra: action.hh:310 `ActionDatabase::ActionDatabase` ✅
- `ActionDatabase::register_action` — Ghidra: action.cc:1127 `ActionDatabase::registerAction` ✅ (Ghidra 为 protected/private；Rudra 公开)
- `ActionDatabase::get_action` / `get_action_mut` — Ghidra: action.hh:307 `getAction` ✅
- `ActionDatabase::apply_all` — 辅助 (RUDRA-GLUE)：驱动 root action 的 reset+perform
- `ActionDatabase::set_default_actions` — Ghidra: `universalAction` (coreaction.cc:5462) ✅ (注：实际对应在 coreaction.cc 而非 action.cc，但语义对齐)

### ActionState (Rudra 特有，承载 Ghidra Action 的状态字段)
- `ActionState::new` / `get_flags_val` — 承载 Ghidra `Action::lcount/count/status/flags/count_tests/count_apply` 字段 ✅

### ActionTypePropagate (Rudra 辅助 Action)
- `ActionTypePropagate::apply` — Ghidra: `ActionTypePropagate` (coreaction.cc，非 action.cc) ✅ (跨文件对齐)

## 缺失函数 (24个)

### Action 基类 — 缺失 12 个
- `Action::issueWarning` — Ghidra: action.cc:41 — 优先级: 低 — 受规则触发时打印警告（依赖 `rule_warnings_on`/`warnings_given` 标志）。Rudra 无警告机制。
- `Action::checkStartBreak` — Ghidra: action.cc:52 — 优先级: 中 — 检查 start 断点（`break_start`/`tmpbreak_start`），perform() 状态机入口。Rudra `perform` 完全省略断点分支。
- `Action::checkActionBreak` — Ghidra: action.cc:117 — 优先级: 中 — 检查 action 断点。Rudra 省略。
- `Action::turnOnDebug` / `turnOffDebug` — Ghidra: action.cc:67 / action.cc:80 — 优先级: 低 — 调试开关（OPACTION_DEBUG 编译期条件）。Rudra 用 `RUDRA_RULE_STATS` 环境变量替代，但无 per-action debug 入口。
- `Action::printStatistics` — Ghidra: action.cc:93 — 优先级: 低 — 打印 count_tests/count_apply 统计。Rudra 在 ActionPool 内联打印，基类无统一入口。
- `Action::resetStats` — Ghidra: action.cc:108 — 优先级: 低 — 清零统计计数。Rudra `reset` 顺带清零，无独立方法。
- `Action::setBreakPoint` — Ghidra: action.cc:171 — 优先级: 中 — 按名设置断点。Rudra 无断点 API。
- `Action::clearBreakPoints` — Ghidra: action.hh:104 (虚) — 优先级: 中 — 清除断点。Rudra 无。
- `Action::setWarning` — Ghidra: action.cc:199 — 优先级: 低 — 按名开关警告。
- `Action::disableRule` / `enableRule` — Ghidra: action.cc:226 / action.cc:242 — 优先级: **高** — 按名禁用/启用子 Rule（用于用户配置 `rule="..."` 关闭特定优化）。Rudra 完全缺失，导致无法按规则名禁用优化，调试/差分分析困难。
- `Action::print` — Ghidra: action.cc:132 — 优先级: 低 — 打印 Action 树（缩进）。Rudra 无 Action 树可视化。
- `Action::printState` — Ghidra: action.cc:148 — 优先级: 低 — 打印当前执行状态。
- `Action::getSubAction` / `getSubRule` — Ghidra: action.hh:133/134 — 优先级: 中 — 按路径名查找子 Action/Rule（断点/禁用用）。Rudra 无层级名查询。
- `Action::clone` — Ghidra: action.hh:119 (纯虚) — 优先级: 中 — 按 grouplist 克隆 Action 树。Rudra 用 `Box<dyn Action>` 无 clone，无法动态派生 root action。
- `Action::getGroup` / `getStatus` / `getNumTests` / `getNumApply` — Ghidra: action.hh:109-112 (内联) — 优先级: 低 — 字段访问器。Rudra 状态外挂到 ActionState，无 trait 方法暴露。

### ActionGroup — 缺失 5 个
- `ActionGroup::clearBreakPoints` — Ghidra: action.cc:382 — 优先级: 中 — 递归清子 Action 断点。
- `ActionGroup::resetStats` — Ghidra: action.cc:418 — 优先级: 低
- `ActionGroup::print` — Ghidra: action.cc:428 — 优先级: 低
- `ActionGroup::printState` — Ghidra: action.cc:444 — 优先级: 低
- `ActionGroup::printStatistics` — Ghidra: action.cc:611 — 优先级: 低
- `ActionGroup::getSubAction` / `getSubRule` — Ghidra: action.hh:158/159 — 优先级: 中
- `ActionGroup::turnOnDebug` / `turnOffDebug` — Ghidra: action.cc:586/598 — 优先级: 低
- `ActionGroup::clone` — Ghidra: action.hh:152 — 优先级: 中

### ActionRestartGroup — 缺失 1 个
- `ActionRestartGroup::clone` — Ghidra: action.hh:179 — 优先级: 中

### Rule 基类 — 缺失 9 个
- `Rule::Rule` (构造) — Ghidra: action.cc (隐式) — 优先级: 低 — Rudra Rule trait 无构造，各 Rule 自行 `new()`
- `Rule::issueWarning` — Ghidra: action.cc:639 — 优先级: 低
- `Rule::reset` — Ghidra: action.cc:651 — 优先级: 低 — Rudra Rule trait 无 reset（无状态 Rule 不需要，有状态的需自管）
- `Rule::resetStats` — Ghidra: action.cc:659 — 优先级: 低
- `Rule::turnOnDebug` / `turnOffDebug` — Ghidra: action.cc:670/683 — 优先级: 低
- `Rule::printStatistics` — Ghidra: action.cc:698 — 优先级: 低
- `Rule::getOpList` — Ghidra: action.cc:707 — 优先级: 低 — Rudra 用 trait 方法 `get_opcodes` 替代（返回 Vec 而非 out-param），语义对齐。
- `Rule::checkActionBreak` — Ghidra: action.cc:719 — 优先级: 中
- `Rule::clone` — Ghidra: action.hh:236 (纯虚) — 优先级: 中
- `Rule::getName/getGroup/getNumTests/getNumApply/setBreak/clearBreak/clearBreakPoints/turnOnWarnings/turnOffWarnings/isDisabled/setDisable/clearDisable/getBreakPoint` — Ghidra: action.hh:215-228 (内联) — 优先级: 中 — 一整套按名/标志管理 Rule 的访问器与禁用开关。Rudra Rule trait 仅暴露 `get_name`，其余缺失，无法在运行时禁用单条 Rule。

### ActionPool — 缺失 5 个
- `ActionPool::processOp` — Ghidra: action.cc:823 — 优先级: 低 — Rudra 已内联进 `ActionPool::apply`，语义对齐。
- `ActionPool::clearBreakPoints` — Ghidra: action.cc:891 — 优先级: 中
- `ActionPool::print` — Ghidra: action.cc:754 — 优先级: 低
- `ActionPool::printState` — Ghidra: action.cc:778 — 优先级: 低
- `ActionPool::printStatistics` — Ghidra: action.cc:965 — 优先级: 低
- `ActionPool::getSubRule` — Ghidra: action.hh:279 — 优先级: 中
- `ActionPool::clone` — Ghidra: action.hh:273 — 优先级: 中

### ActionDatabase — 缺失 7 个
- `ActionDatabase::resetDefaults` — Ghidra: action.cc:987 — 优先级: 中 — 重建默认 group 配置。Rudra `set_default_actions` 直接重建，无独立 reset 入口。
- `ActionDatabase::setGroup` — Ghidra: action.cc:1060 — 优先级: **高** — 按用户提供的 argv 建立/派生 root action（命令行 `-trigger`/`-actionpath` 的核心）。Rudra 缺失，无法运行时配置 action 组合。
- `ActionDatabase::cloneGroup` — Ghidra: action.cc:1078 — 优先级: 中 — 克隆已有 group 为新 root。
- `ActionDatabase::addToGroup` — Ghidra: action.cc:1091 — 优先级: 中 — 向 root 追加一个 basegroup。
- `ActionDatabase::removeFromGroup` — Ghidra: action.cc:1104 — 优先级: 中 — 从 root 移除一个 basegroup。
- `ActionDatabase::getCurrent` / `getCurrentName` — Ghidra: action.hh:313/314 (内联) — 优先级: 中 — 取当前 root action。Rudra `current_group` 字段未暴露访问器。
- `ActionDatabase::getGroup` (grouplist) — Ghidra: action.hh:315 — 优先级: 中
- `ActionDatabase::setCurrent` — Ghidra: action.hh:316 — 优先级: 中 — 切换当前 root。
- `ActionDatabase::toggleAction` — Ghidra: action.hh:317 — 优先级: 中 — 按 val 开关一组 Action。
- `ActionDatabase::deriveAction` — Ghidra: action.hh:308 — 优先级: 中 — 派生 root。
- `ActionDatabase::buildDefaultGroups` — Ghidra: action.hh:306 — 优先级: 中 — 建立预置 group 描述（`universal`/`decompile`/`normalize`/`register` 等）。Rudra `set_default_actions` 硬编码一棵树，无可查询的 group 表。
- `ActionGroupList::contains` — Ghidra: action.hh:39 (内联) — 优先级: 低

## 高优先级缺失清单 (3个)
1. `Action::disableRule` / `enableRule` (action.cc:226/242) — 无法按规则名禁用优化，严重阻碍差分调试与回归定位
2. `ActionDatabase::setGroup` (action.cc:1060) — 缺少运行时 action 组合配置，无法支持命令行 `-trigger` 等选项
3. `Action::setBreakPoint` / `clearBreakPoints` / `checkStartBreak` / `checkActionBreak` (action.cc:52/117/171) — 整套断点机制缺失，无法在指定 Action/Rule 处暂停逐步调试

## 说明
- Ghidra 的断点（`break_start`/`break_action`）、警告（`warnings_on`）、统计打印（`printStatistics`/`print`/`printState`）、按名克隆（`clone`）四类机制在 Rudra 中整体缺失，属于"调试/可观测性"缺口，对正确性无影响，但显著降低差分调试能力。
- `Rule::getOpList` 在 Rudra 中以 `get_opcodes: Vec<OpCode>` 替代（返回 Vec 而非 out-param），属合理的 Rust 适配，不算缺失。
- `processOp` 已内联进 `ActionPool::apply`，不再单列。
- 大量 Ghidra 内联访问器（`getName`/`getStatus`/`getNumTests` 等）在 Rudra 由 `ActionState` 字段直接承担，未逐一列为缺失，仅在基类段汇总。
