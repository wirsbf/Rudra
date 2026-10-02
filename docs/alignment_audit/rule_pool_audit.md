# Rule Pool 审计 (2026-07-22)

对比 `src/action.rs` 的 `build_simplify_pool()` / `build_oppool2()` / `build_cleanup_pool()`
与 Ghidra `coreaction.cc:5511-5711` 的 Rule 注册。

## 汇总

| Pool | Ghidra Rule 数 | Rudra 已注册 | 对齐情况 |
|------|---------------|-------------|---------|
| oppool1 (simplify) | 134 | 134 | **完全对齐**（另含 2 个 Rudra-local 规则） |
| oppool2 | 5 | 5 | **完全对齐**（Ghidra 第 6 个 `RuleIndirectConcat` 在源码中被注释掉，实际未注册） |
| cleanup | 15 | 15 | **完全对齐**（另含 1 个 Rudra-local 规则） |

**结论**：三个 pool 在 Rule 名称/数量上均已与 Ghidra 对齐。没有"缺失的 Rule"。
唯一的结构性 gap 是 **oppool1 末尾的 CPU-specific `extra_pool_rules` 注入点**
（Ghidra coreaction.cc:5647-5649）——Rudra 当前未实现该机制。

---

## oppool1 (simplify pool)

对应 `src/action.rs:545-704` 的 `build_simplify_pool()`，Ghidra
`coreaction.cc:5511-5646`（`actprop = new ActionPool(...,"oppool1")`，挂在
`stackstall` 下）。

### 已注册 (134 个 — 与 Ghidra 一一对应)

按 Ghidra 顺序列出（行号为 coreaction.cc）：

| # | Rule | 行号 |
|---|------|-----|
| 1 | RuleEarlyRemoval | 5512 |
| 2 | RuleTermOrder | 5513 |
| 3 | RuleSelectCse | 5514 |
| 4 | RuleCollectTerms | 5515 |
| 5 | RulePullsubMulti | 5516 |
| 6 | RulePullsubIndirect | 5517 |
| 7 | RulePushMulti | 5518 |
| 8 | RuleSborrow | 5519 |
| 9 | RuleScarry | 5520 |
| 10 | RuleIntLessEqual | 5521 |
| 11 | RuleTrivialArith | 5522 |
| 12 | RuleTrivialBool | 5523 |
| 13 | RuleTrivialShift | 5524 |
| 14 | RuleSignShift | 5525 |
| 15 | RuleTestSign | 5526 |
| 16 | RuleIdentityEl | 5527 |
| 17 | RuleOrMask | 5528 |
| 18 | RuleAndMask | 5529 |
| 19 | RuleOrConsume | 5530 |
| 20 | RuleOrCollapse | 5531 |
| 21 | RuleAndOrLump | 5532 |
| 22 | RuleShiftBitops | 5533 |
| 23 | RuleRightShiftAnd | 5534 |
| 24 | RuleNotDistribute | 5535 |
| 25 | RuleHighOrderAnd | 5536 |
| 26 | RuleAndDistribute | 5537 |
| 27 | RuleAndCommute | 5538 |
| 28 | RuleAndPiece | 5539 |
| 29 | RuleAndZext | 5540 |
| 30 | RuleAndCompare | 5541 |
| 31 | RuleDoubleSub | 5542 |
| 32 | RuleDoubleShift | 5543 |
| 33 | RuleDoubleArithShift | 5544 |
| 34 | RuleConcatShift | 5545 |
| 35 | RuleLeftRight | 5546 |
| 36 | RuleShiftCompare | 5547 |
| 37 | RuleShift2Mult | 5548 |
| 38 | RuleShiftPiece | 5549 |
| 39 | RuleMultiCollapse | 5550 |
| 40 | RuleIndirectCollapse | 5551 |
| 41 | Rule2Comp2Mult | 5552 |
| 42 | RuleSub2Add | 5553 |
| 43 | RuleCarryElim | 5554 |
| 44 | RuleBxor2NotEqual | 5555 |
| 45 | RuleLess2Zero | 5556 |
| 46 | RuleLessEqual2Zero | 5557 |
| 47 | RuleSLess2Zero | 5558 |
| 48 | RuleEqual2Zero | 5559 |
| 49 | RuleEqual2Constant | 5560 |
| 50 | RuleThreeWayCompare | 5561 |
| 51 | RuleXorCollapse | 5562 |
| 52 | RuleAddMultCollapse | 5563 |
| 53 | RuleCollapseConstants | 5564 |
| 54 | RuleTransformCpool | 5565 |
| 55 | RulePropagateCopy | 5566 |
| 56 | RuleZextEliminate | 5567 |
| 57 | RuleSlessToLess | 5568 |
| 58 | RuleZextSless | 5569 |
| 59 | RuleBitUndistribute | 5570 |
| 60 | RuleBooleanUndistribute | 5571 |
| 61 | RuleBooleanDedup | 5572 |
| 62 | RuleBoolZext | 5573 |
| 63 | RuleBooleanNegate | 5574 |
| 64 | RuleLogic2Bool | 5575 |
| 65 | RuleSubExtComm | 5576 |
| 66 | RuleSubCommute | 5577 |
| 67 | RuleConcatCommute | 5578 |
| 68 | RuleConcatZext | 5579 |
| 69 | RuleZextCommute | 5580 |
| 70 | RuleZextShiftZext | 5581 |
| 71 | RuleShiftAnd | 5582 |
| 72 | RuleConcatZero | 5583 |
| 73 | RuleConcatLeftShift | 5584 |
| 74 | RuleSubZext | 5585 |
| 75 | RuleSubCancel | 5586 |
| 76 | RuleShiftSub | 5587 |
| 77 | RuleHumptyDumpty | 5588 |
| 78 | RuleDumptyHump | 5589 |
| 79 | RuleHumptyOr | 5590 |
| 80 | RuleNegateIdentity | 5591 |
| 81 | RuleSubNormal | 5592 |
| 82 | RulePositiveDiv | 5593 |
| 83 | RuleDivTermAdd | 5594 |
| 84 | RuleDivTermAdd2 | 5595 |
| 85 | RuleDivOpt | 5596 |
| 86 | RuleSignForm | 5597 |
| 87 | RuleSignForm2 | 5598 |
| 88 | RuleSignDiv2 | 5599 |
| 89 | RuleDivChain | 5600 |
| 90 | RuleSignNearMult | 5601 |
| 91 | RuleModOpt | 5602 |
| 92 | RuleSignMod2nOpt | 5603 |
| 93 | RuleSignMod2nOpt2 | 5604 |
| 94 | RuleSignMod2Opt | 5605 |
| 95 | RuleSwitchSingle | 5606 |
| 96 | RuleCondNegate | 5607 |
| 97 | RuleBoolNegate | 5608 |
| 98 | RuleLessEqual | 5609 |
| 99 | RuleLessNotEqual | 5610 |
| 100 | RuleLessOne | 5611 |
| 101 | RuleRangeMeld | 5612 |
| 102 | RuleFloatRange | 5613 |
| 103 | RulePiece2Zext | 5614 |
| 104 | RulePiece2Sext | 5615 |
| 105 | RulePopcountBoolXor | 5616 |
| 106 | RuleXorSwap | 5617 |
| 107 | RuleLzcountShiftBool | 5618 |
| 108 | RuleFloatSign | 5619 |
| 109 | RuleOrCompare | 5620 |
| 110 | RuleSubvarAnd | 5621 |
| 111 | RuleSubvarSubpiece | 5622 |
| 112 | RuleSplitFlow | 5623 |
| 113 | RulePtrFlow | 5624 |
| 114 | RuleSubvarCompZero | 5625 |
| 115 | RuleSubvarShift | 5626 |
| 116 | RuleSubvarZext | 5627 |
| 117 | RuleSubvarSext | 5628 |
| 118 | RuleNegateNegate | 5629 |
| 119 | RuleConditionalMove | 5630 |
| 120 | RuleOrPredicate | 5631 |
| 121 | RuleFuncPtrEncoding | 5632 |
| 122 | RuleSubfloatConvert | 5633 |
| 123 | RuleFloatCast | 5634 |
| 124 | RuleIgnoreNan | 5635 |
| 125 | RuleUnsigned2Float | 5636 |
| 126 | RuleInt2FloatCollapse | 5637 |
| 127 | RulePtraddUndo | 5638 |
| 128 | RulePtrsubUndo | 5639 |
| 129 | RuleSegment | 5640 |
| 130 | RulePiecePathology | 5641 |
| 131 | RuleDoubleLoad | 5643 |
| 132 | RuleDoubleStore | 5644 |
| 133 | RuleDoubleIn | 5645 |
| 134 | RuleDoubleOut | 5646 |

（Ghidra 行号 5642 是注释/gap，非 Rule —— Rudra `action.rs:684` 已正确跳过。）

### 缺失 (0 个 — 名称层面无缺失)

无。134 个 Ghidra Rule 全部注册。

### Rudra-local 额外规则 (2 个，非 Ghidra)

`src/action.rs:695-696` 在 Ghidra 列表末尾额外追加：

- `RuleSextEliminate`（ruleaction.rs:290）— Rudra-specific，消除冗余 sign-extend
- `RuleEquality`（ruleaction.rs:2937）— 对应 Ghidra `ruleaction.cc:619` 的 RuleEquality 语义（两输入均为常量时折叠 INT_EQUAL/NOTEQUAL）

> **注**：`RuleMultNegOne` / `Rule2Comp2Sub` 有意不放在 oppool1，而是放到
> cleanup pool，以避免与 `Rule2Comp2Mult` (5552) 形成无限 ping-pong。
> Ghidra 通过 phase 分离避免该问题（main pool 先收敛，cleanup pool 后运行）。
> 见 `action.rs:697-702` 的 NOTE 说明。

### 结构性 gap（机制层面，非 Rule 名称）

- **CPU-specific `extra_pool_rules` 未实现**：Ghidra 在 oppool1 末尾
  (coreaction.cc:5647-5649) 通过 `conf->extra_pool_rules` 注入架构相关 Rule
  （由 `Architecture::registerPcodeRules` 等填充），随后清空该容器。
  Rudra 全代码库无 `extra_pool_rules` 字段（已确认：grep 无命中）。
  - 影响：依赖 `extra_pool_rules` 的架构（如 x86 的 carry-flag Rule、ARM 的
    shift-carry Rule）将缺少这些 Rule。当前 Rudra 目标架构若不需要，
    则无实际影响。
  - 优先级：中（仅在引入新架构支持时成为阻塞项）

---

## oppool2

对应 `src/action.rs:755-764` 的 `build_oppool2()`，Ghidra
`coreaction.cc:5662-5670`（`actprop2 = new ActionPool(...,"oppool2")`）。

### 已注册 (5 个)

| # | Rule | Ghidra 行号 |
|---|------|------------|
| 1 | RulePushPtr | 5664 |
| 2 | RuleStructOffset0 | 5665 |
| 3 | RulePtrArith | 5666 |
| 4 | RuleLoadVarnode | 5668 |
| 5 | RuleStoreVarnode | 5669 |

### 缺失 (0 个)

无。

> **关于 `RuleIndirectConcat`**：Ghidra coreaction.cc:5667 该行是**被注释掉的**
> (`//	actprop2->addRule( new RuleIndirectConcat("analysis") );`)，实际未注册。
> 因此 Rudra 不注册它是正确的对齐行为，不算缺失。

---

## cleanup pool

对应 `src/action.rs:713-743` 的 `build_cleanup_pool()`，Ghidra
`coreaction.cc:5694-5710`（`actcleanup = new ActionPool(...,"cleanup")`）。

### 已注册 (15 个)

| # | Rule | Ghidra 行号 |
|---|------|------------|
| 1 | RuleMultNegOne | 5696 |
| 2 | RuleAddUnsigned | 5697 |
| 3 | Rule2Comp2Sub | 5698 |
| 4 | RuleDumptyHumpLate | 5699 |
| 5 | RuleSubRight | 5700 |
| 6 | RuleFloatSignCleanup | 5701 |
| 7 | RuleExpandLoad | 5702 |
| 8 | RulePtrsubCharConstant | 5703 |
| 9 | RuleExtensionPush | 5704 |
| 10 | RulePieceStructure | 5705 |
| 11 | RuleSplitCopy | 5706 |
| 12 | RuleSplitLoad | 5707 |
| 13 | RuleSplitStore | 5708 |
| 14 | RuleStringCopy | 5709 |
| 15 | RuleStringStore | 5710 |

### 缺失 (0 个)

无。

### Rudra-local 额外规则 (1 个)

`src/action.rs:741` 在 cleanup pool 末尾额外追加：

- `RuleTrivialArith` — 复用 oppool1 的同款 Rule，用于折叠 type-recovery /
  copy-prop / structuring 等**晚于** simplifypool 运行的 pass 所产生的平凡算术
  （如 `x^x → 0`）。Ghidra 的 mainloop 以 `repeatapply` 多轮运行 actprop，
  能自动重简化这些晚到的 op；Rudra 的 simplifypool 在 stackstall 内只跑一次，
  故在此补一次清理。理由见 `action.rs:734-740` 的注释。

### 待办（实现深度，非注册层面）

`action.rs:729-731` 注：`RuleStringCopy` / `RuleStringStore` 已注册，但当前仅
**检测阶段**完成；transform 阶段依赖 CALLOTHER/userop 基础设施（Ghidra
constseq.cc:954-1002），仍为 follow-up。这是实现完成度问题，不影响 pool 注册对齐。

---

## 高优先级缺失 Rule 清单

**无**。三个 pool 的 Rule 注册与 Ghidra 完全一致（oppool1 134/134、oppool2 5/5、
cleanup 15/15）。

唯一值得后续跟踪的项（均非 Rule 名称缺失）：

1. **`extra_pool_rules` 注入机制**（中优先级）— oppool1 末尾 CPU-specific Rule
   的注册通道尚未实现。当前架构无影响，引入新架构时需补齐
   `Architecture::registerPcodeRules` 对应逻辑。
2. **`RuleStringCopy` / `RuleStringStore` transform 阶段**（低优先级）—
   注册已就位，但 transform 需 CALLOTHER 基础设施。

相关文件：
- `D:/ghidra/rudra/src/action.rs:545-764`（三个 pool builder）
- `D:/ghidra/rudra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc:5511-5711`
- `D:/ghidra/rudra/src/ruleaction.rs`（Rule 实现主体）
