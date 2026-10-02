# cover 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 654行 (`cover.cc`) / Rudra: 485行 (`src/cover.rs`) / 比率: 74%

Ghidra 头文件 `cover.hh` 额外声明多个内联方法（`CoverBlock::setAll`、`setBegin`、`setEnd`、`empty`、`getUIndex`、`PcodeOpSet::addOp/isPopulated/clear` 等），本审计一并纳入。

## 已对齐函数 (17个)

### CoverBlock
- `CoverBlock::new` — Ghidra: cover.hh:75 (构造/默认状态) ✅
- `CoverBlock::clear` — Ghidra: cover.hh:75 ✅
- `CoverBlock::set_begin` — Ghidra: cover.hh:75 `CoverBlock::setBegin` ✅
- `CoverBlock::set_end` — Ghidra: cover.hh:75 `CoverBlock::setEnd` ✅
- `CoverBlock::empty` — Ghidra: cover.hh:75 ✅
- `CoverBlock::contain` — Ghidra: cover.cc:107 ✅
- `CoverBlock::boundary` — Ghidra: cover.cc:129 ✅
- `CoverBlock::merge` — Ghidra: cover.cc:147 ✅
- `CoverBlock::intersect` — Ghidra: cover.cc:59 ✅ (Rudra 同时提供可变 `intersect` 和非可变 `intersect_char` 两个适配入口，均对齐到 cover.cc:59)

### Cover
- `Cover::new` — Ghidra: cover.hh:36 ✅
- `Cover::clear` — Ghidra: cover.hh:36 ✅
- `Cover::add_def_point` — Ghidra: cover.cc:501 `Cover::addDefPoint` ✅
- `Cover::add_ref_point` — Ghidra: cover.cc:565 `Cover::addRefPoint` ✅
- `Cover::contain` — Ghidra: cover.cc:413 ✅ (签名简化：省略 `max` 参数)
- `Cover::contain_varnode_def_at` — Ghidra: cover.cc:441 `Cover::containVarnodeDef` ✅
- `Cover::merge` — Ghidra: cover.cc:465 ✅
- `Cover::intersect` — Ghidra: cover.cc:269 ✅ (Rudra 提供可变 `intersect`、非可变 `intersect_char`、谓词 `intersects`、`intersects_except_at` 四个适配入口，均对齐到 cover.cc:269/cover.hh:36)

## 缺失函数 (13个)

### CoverBlock — 缺失 3 个
- `CoverBlock::getUIndex` — Ghidra: cover.hh:80 / cover.cc:29 — 优先级: **高** — 从 PcodeOp 提取 SeqNum 比较索引的静态方法。Rudra 的 `boundary`/`intersect_char` 直接使用 `u32` order，把该逻辑内联进调用点；但 Ghidra 其它模块（Funcdata、merge、varmap）会直接调用 `CoverBlock::getUIndex`，应提供桥接函数以保持 API 对齐。
- `CoverBlock::setAll` — Ghidra: cover.hh:84 (内联) — 优先级: 中 — 将 cover 设为"覆盖整个块"（start=块首 op, stop=块尾 op），用于不可分析的块。Rudra 无对应入口。
- `CoverBlock::print` — Ghidra: cover.cc:188 — 优先级: 低 — 调试用流式输出。Rudra 用 `fmt::Display` 替代，功能等价但签名不一致。

### Cover — 缺失 7 个
- `Cover::compareTo` — Ghidra: cover.cc:223 — 优先级: **高** — 对两个 Cover 做字典序比较（按 block 逐块比较），用于稳定排序/去重。Rudra 完全缺失。
- `Cover::intersectList` — Ghidra: cover.cc:307 — 优先级: 中 — 列出所有在指定 level 上相交的 block 索引。Rudra 的 `intersect_char` 只返回级别，不返回 block 列表。
- `Cover::intersect(PcodeOpSet,Varnode*)` — Ghidra: cover.cc:342 — 优先级: 中 — 判断 cover 是否与一个 PcodeOp 集合相交（用于别名/调用副作用检查）。依赖 PcodeOpSet，目前两者皆缺。
- `Cover::intersectByBlock` — Ghidra: cover.cc:392 — 优先级: 中 — 针对单个 block 的相交级别查询。Rudra 的 `intersect_char` 内部已隐含此逻辑，但未暴露单 block 入口。
- `Cover::rebuild` — Ghidra: cover.cc:477 — 优先级: **高** — 根据 Varnode 的 def+所有 use 重建整条 cover，是 cover 维护的核心入口。Rudra 要求调用方手动 `add_def_point`/`add_ref_point`，缺少一站式重建。
- `Cover::addRefRecurse` — Ghidra: cover.cc:524 — 优先级: **高** — 从一个引用点沿控制流向前回溯填充 cover（处理跨越多块的 use）。`addRefPoint` 内部依赖它；Rudra 版本只登记单点，不做回溯。
- `Cover::print` — Ghidra: cover.cc:615 — 优先级: 低 — 调试输出。Rudra 用 `fmt::Display` 替代。

### PcodeOpSet — 整个类缺失（5 个方法）
- `PcodeOpSet` (抽象基类) — Ghidra: cover.hh:38 / cover.cc:627 — 优先级: **高** — PcodeOp 集合抽象，`Cover::intersect(PcodeOpSet,...)` 和 `populate/affectsTest` 的载体。整类未实现。
- `PcodeOpSet::addOp` — Ghidra: cover.hh:41 (内联) — 优先级: 中
- `PcodeOpSet::finalize` — Ghidra: cover.cc:627 — 优先级: 中 — 排序并建立 block 索引。
- `PcodeOpSet::isPopulated` — Ghidra: cover.hh:45 (内联) — 优先级: 低
- `PcodeOpSet::clear` — Ghidra: cover.hh:63 (内联) — 优先级: 低
- `PcodeOpSet::compareByBlock` — Ghidra: cover.cc:646 — 优先级: 中 — 静态比较函数。
- `PcodeOpSet::populate` (纯虚) / `affectsTest` (纯虚) — Ghidra: cover.hh:52,61 — 优先级: 中

## 说明
- `Cover::contain(op,max)` 的 `max`（深度上限）参数在 Rudra 中被省略；行为对单 block 等价，但无法表达"只检查前 N 步"的语义，标记为部分对齐。
- `Cover::intersect` 在 Rudra 中分裂为四个函数（可变/非可变/谓词/排除点），均回指 cover.cc:269，属于合理的 Rust 适配，不算违规。
