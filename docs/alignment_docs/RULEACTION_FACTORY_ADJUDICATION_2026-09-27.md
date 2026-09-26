# ruleaction.hh 工厂形态（clone/ctor）类级裁决登记表 — WORKPKG-UNMAP-RULEADJ-0013 裁决半

> **生成**: 2026-09-27，车道 RULEADJ（wt/ruleadj，基 master 6a458387）。
> **数据源**: docs/alignment_audit/FUNCTION_LEDGER.json（REGEN checkpoint 80ffb7d1 重生成版，
> definitions=9494）。脚本重放：按 qualified_name 过滤 ruleaction.hh 未映射条目中无 .cc 孪生者，
> 逐类解析 `pub struct Rule<Class>`（src/ruleaction.rs）与 `register_rule!(pool, "<group>", Box::new(Rule<Class>::new()))`（src/action.rs）。
> **Oracle**: Ghidra_12.0.4_build / e40ed13014025f82488b1f8f7bca566894ac376b。

## 1. 裁决结论（不冒充移植完成）

| 类别 | 条数 | 处置 | 依据 |
|---|---:|---|---|
| `RuleX::clone(const ActionGroupList&)` 内联定义（ruleaction.hh） | 136 | **工厂形态类级吸收（RUGRA-GLUE）**：Rust 无逐类 clone 方法；grouplist 过滤语义由注册槽 basegroup 字符串 + `ActionPool::clone`（action.rs，镜像 action.cc:899-914）在派生树构建时统一执行 | 机制等价证据=ACTION-EXECUTOR-BREAKPOOL-0001 fixture：154 个 Rule 名逐字节恒等 + per-Rule 派生根 clone 过滤（含整池空汰）MATCH |
| `RuleX::RuleX(const string&)` 构造内联定义（ruleaction.hh 无 .cc 孪生） | 121 | **同上（ctor 半）**：group 字符串存于注册槽而非结构体；Rust unit struct + `new()` + 注册工厂吸收 | 同上 |
| `RuleX::RuleX` .hh 声明（有 .cc 孪生且已映射） | 2 | **hh 孪生**→REGEN 机械链接口袋，非本表裁决对象 | T-twin 规则（DECOMP §1） |
| `RuleConditionalMove::compareOp`（hh:1433 内联） | 1 | **真缺口**：仅被 `constructBool` 的 `sort(ops,compareOp)`（ruleaction.cc:9333）消费；Rust `construct_bool` 在 ops 非空时返回 None（CloneBlockOps::cloneExpression 未移植）→ 登记票 `RULEACTION-CLONEBLOCKOPS-0001` | ruleaction.cc:9333/9346 + ruleaction.rs:17133 stub |
| `RuleEquality::clone/ctor`（hh:245-246） | 2 | **oracle 死类**：锁定树无任何 `new RuleEquality` 实例化点；Rust 已移植类本体（ruleaction.rs:3500）但**有意不注册**（PIPE-POOL-LOCAL-RULES-0001 裁决） | coreaction.cc 全文无实例化 |

**合计 261 = 136 clone + 121 ctor(hh-only) + 2 ctor(hh孪生) + 1 compareOp + 1 RuleEquality 对（clone+ctor 计 2 条）**。
（DECOMP 分诊报告口径 235=136 clone+99 ctor：其 classifier 将 ≥3 映射类的单行 .hh ctor 判入"胶水吸收 383"口袋，
本表按 REGEN 账本原始粒度重算为 121+2；两口径无冲突，均为工厂形态，非逐函数移植对象。）

## 2. 吸收机制（oracle 侧语义 → Rust 侧结构）

Oracle 每个 Rule 类的 ctor+clone 内联体只有两个可观测行为：
1. `Rule(g, flags, name)` 基类构造（group/flags/名字注册）；
2. `clone(grouplist)`：`grouplist.contains(getGroup()) ? new RuleX(getGroup()) : 0`。

Rust 侧吸收点：
- **注册槽** `register_rule!(pool, "<group>", Box::new(RuleX::new()))`（src/action.rs build_oppool1/build_cleanup_pool 等，
  逐槽保留 oracle coreaction.cc:5511-5739 注册序的 basegroup 字符串——等价于 ctor 的 group 实参与注册位点；
- **`ActionPool::clone`**（src/action.rs，镜像 action.cc:899-914）：派生树构建时按 grouplist 过滤规则槽，
  幸存槽经工厂闭包重新实例化——等价于全部 136 个 clone 方法体的联合行为；
- **unit struct + `new()`**（src/ruleaction.rs 逐类）：flags/name 经 `Rule` trait 的 get_name/get_opcodes 保留。

**行为等价证据链**（非代码形似）：tests/oracle/action_break_pool_1204（ACTION-EXECUTOR-BREAKPOOL-0001）
已双侧锁定：①76 Action+154 Rule 注册名逐字节恒等；②派生根 per-Rule clone 过滤（含"无幸存则整池省略"）MATCH。
本表不将任何条目升格为 per-fn `MATCH`——逐函数行为门禁仍以各 Rule 的 applyOp B2 fixture 为准（本车道补齐三族，
其余 Rule 的 fixture 覆盖由既有/后续票承载）。

## 3. REGEN 边联动口径

- 本表 259 条（136 clone + 121 ctor + RuleEquality 2 条特殊处置）建议 REGEN 以**类级边**挂到对应注册槽注释
  `// Ghidra: coreaction.cc:<reg_line 相邻注释锚>` 或类定义 `// Ghidra: ruleaction.hh:<hh_line> Rule<Class>`，
  **禁止**逐条链接到 `new()`（会虚增 per-fn 映射计数）；
- 340 条 .hh 孪生声明（.cc 定义已映射）沿用 T-twin 机械链接口袋，不经过本表；
- compareOp 单条归 `RULEACTION-CLONEBLOCKOPS-0001`（真移植缺口），不在工厂口袋内。

## 4. 逐类登记表（257 行，按 ruleaction.hh 行序）

| hh:line | 类 | 形态 | Rust struct（ruleaction.rs） | 注册槽（action.rs） | group |
|---|---|---|---|---|---|
| hh:89 | RuleEarlyRemoval | clone | ruleaction.rs:4838 | action.rs:1694 | deadcode |
| hh:106 | RuleCollectTerms | clone | ruleaction.rs:5148 | action.rs:1697 | analysis |
| hh:115 | RuleSelectCse | ctor | ruleaction.rs:6458 | action.rs:1696 | analysis |
| hh:116 | RuleSelectCse | clone | ruleaction.rs:6458 | action.rs:1696 | analysis |
| hh:125 | RulePiece2Zext | ctor | ruleaction.rs:1849 | action.rs:1796 | analysis |
| hh:126 | RulePiece2Zext | clone | ruleaction.rs:1849 | action.rs:1796 | analysis |
| hh:135 | RulePiece2Sext | ctor | ruleaction.rs:1902 | action.rs:1797 | analysis |
| hh:136 | RulePiece2Sext | clone | ruleaction.rs:1902 | action.rs:1797 | analysis |
| hh:145 | RuleBxor2NotEqual | ctor | ruleaction.rs:1985 | action.rs:1737 | analysis |
| hh:146 | RuleBxor2NotEqual | clone | ruleaction.rs:1985 | action.rs:1737 | analysis |
| hh:155 | RuleOrMask | ctor | ruleaction.rs:1691 | action.rs:1710 | analysis |
| hh:156 | RuleOrMask | clone | ruleaction.rs:1691 | action.rs:1710 | analysis |
| hh:165 | RuleAndMask | ctor | ruleaction.rs:5636 | action.rs:1711 | analysis |
| hh:166 | RuleAndMask | clone | ruleaction.rs:5636 | action.rs:1711 | analysis |
| hh:175 | RuleOrConsume | ctor | ruleaction.rs:4779 | action.rs:1712 | analysis |
| hh:176 | RuleOrConsume | clone | ruleaction.rs:4779 | action.rs:1712 | analysis |
| hh:185 | RuleOrCollapse | ctor | ruleaction.rs:2394 | action.rs:1713 | analysis |
| hh:186 | RuleOrCollapse | clone | ruleaction.rs:2394 | action.rs:1713 | analysis |
| hh:195 | RuleAndOrLump | ctor | ruleaction.rs:1752 | action.rs:1714 | analysis |
| hh:196 | RuleAndOrLump | clone | ruleaction.rs:1752 | action.rs:1714 | analysis |
| hh:205 | RuleNegateIdentity | ctor | ruleaction.rs:853 | action.rs:1773 | analysis |
| hh:206 | RuleNegateIdentity | clone | ruleaction.rs:853 | action.rs:1773 | analysis |
| hh:216 | RuleShiftBitops | clone | ruleaction.rs:688 | action.rs:1715 | analysis |
| hh:225 | RuleRightShiftAnd | ctor | ruleaction.rs:3763 | action.rs:1716 | analysis |
| hh:226 | RuleRightShiftAnd | clone | ruleaction.rs:3763 | action.rs:1716 | analysis |
| hh:235 | RuleIntLessEqual | ctor | ruleaction.rs:5116 | action.rs:1703 | analysis |
| hh:236 | RuleIntLessEqual | clone | ruleaction.rs:5116 | action.rs:1703 | analysis |
| hh:245 | RuleEquality | ctor | ruleaction.rs:3500 | 不注册（oracle 死类，PIPE-POOL-LOCAL-RULES-0001） | — |
| hh:246 | RuleEquality | clone | ruleaction.rs:3500 | 不注册（oracle 死类，PIPE-POOL-LOCAL-RULES-0001） | — |
| hh:256 | RuleTermOrder | ctor | ruleaction.rs:2019 | action.rs:1695 | analysis |
| hh:257 | RuleTermOrder | clone | ruleaction.rs:2019 | action.rs:1695 | analysis |
| hh:266 | RulePullsubMulti | ctor | ruleaction.rs:12731 | action.rs:1698 | analysis |
| hh:267 | RulePullsubMulti | clone | ruleaction.rs:12731 | action.rs:1698 | analysis |
| hh:281 | RulePullsubIndirect | ctor | ruleaction.rs:14829 | action.rs:1699 | analysis |
| hh:282 | RulePullsubIndirect | clone | ruleaction.rs:14829 | action.rs:1699 | analysis |
| hh:292 | RulePushMulti | ctor | ruleaction.rs:6108 | action.rs:1700 | nodejoin |
| hh:293 | RulePushMulti | clone | ruleaction.rs:6108 | action.rs:1700 | nodejoin |
| hh:302 | RuleNotDistribute | ctor | ruleaction.rs:970 | action.rs:1717 | analysis |
| hh:303 | RuleNotDistribute | clone | ruleaction.rs:970 | action.rs:1717 | analysis |
| hh:312 | RuleHighOrderAnd | ctor | ruleaction.rs:3825 | action.rs:1718 | analysis |
| hh:313 | RuleHighOrderAnd | clone | ruleaction.rs:3825 | action.rs:1718 | analysis |
| hh:322 | RuleAndDistribute | ctor | ruleaction.rs:4332 | action.rs:1719 | analysis |
| hh:323 | RuleAndDistribute | clone | ruleaction.rs:4332 | action.rs:1719 | analysis |
| hh:332 | RuleLessOne | ctor | ruleaction.rs:4443 | action.rs:1793 | analysis |
| hh:333 | RuleLessOne | clone | ruleaction.rs:4443 | action.rs:1793 | analysis |
| hh:342 | RuleRangeMeld | ctor | ruleaction.rs:12205 | action.rs:1794 | analysis |
| hh:343 | RuleRangeMeld | clone | ruleaction.rs:12205 | action.rs:1794 | analysis |
| hh:352 | RuleFloatRange | ctor | ruleaction.rs:12424 | action.rs:1795 | analysis |
| hh:353 | RuleFloatRange | clone | ruleaction.rs:12424 | action.rs:1795 | analysis |
| hh:362 | RuleAndCommute | ctor | ruleaction.rs:4599 | action.rs:1720 | analysis |
| hh:363 | RuleAndCommute | clone | ruleaction.rs:4599 | action.rs:1720 | analysis |
| hh:372 | RuleAndPiece | ctor | ruleaction.rs:4492 | action.rs:1721 | analysis |
| hh:373 | RuleAndPiece | clone | ruleaction.rs:4492 | action.rs:1721 | analysis |
| hh:382 | RuleAndZext | ctor | ruleaction.rs:3893 | action.rs:1722 | analysis |
| hh:383 | RuleAndZext | clone | ruleaction.rs:3893 | action.rs:1722 | analysis |
| hh:392 | RuleAndCompare | ctor | ruleaction.rs:3249 | action.rs:1723 | analysis |
| hh:393 | RuleAndCompare | clone | ruleaction.rs:3249 | action.rs:1723 | analysis |
| hh:402 | RuleDoubleSub | ctor | ruleaction.rs:2178 | action.rs:1724 | analysis |
| hh:403 | RuleDoubleSub | clone | ruleaction.rs:2178 | action.rs:1724 | analysis |
| hh:412 | RuleDoubleShift | ctor | ruleaction.rs:2581 | action.rs:1725 | analysis |
| hh:413 | RuleDoubleShift | clone | ruleaction.rs:2581 | action.rs:1725 | analysis |
| hh:422 | RuleDoubleArithShift | ctor | ruleaction.rs:9927 | action.rs:1726 | analysis |
| hh:423 | RuleDoubleArithShift | clone | ruleaction.rs:9927 | action.rs:1726 | analysis |
| hh:432 | RuleConcatShift | ctor | ruleaction.rs:3015 | action.rs:1727 | analysis |
| hh:433 | RuleConcatShift | clone | ruleaction.rs:3015 | action.rs:1727 | analysis |
| hh:442 | RuleLeftRight | ctor | ruleaction.rs:5010 | action.rs:1728 | analysis |
| hh:443 | RuleLeftRight | clone | ruleaction.rs:5010 | action.rs:1728 | analysis |
| hh:452 | RuleShiftCompare | ctor | ruleaction.rs:3118 | action.rs:1729 | analysis |
| hh:453 | RuleShiftCompare | clone | ruleaction.rs:3118 | action.rs:1729 | analysis |
| hh:472 | RuleLessEqual | ctor | ruleaction.rs:1531 | action.rs:1791 | analysis |
| hh:473 | RuleLessEqual | clone | ruleaction.rs:1531 | action.rs:1791 | analysis |
| hh:482 | RuleLessNotEqual | ctor | ruleaction.rs:3556 | action.rs:1792 | analysis |
| hh:483 | RuleLessNotEqual | clone | ruleaction.rs:3556 | action.rs:1792 | analysis |
| hh:492 | RuleTrivialArith | ctor | ruleaction.rs:498 | action.rs:1704 | analysis |
| hh:493 | RuleTrivialArith | clone | ruleaction.rs:498 | action.rs:1704 | analysis |
| hh:502 | RuleTrivialBool | ctor | ruleaction.rs:112 | action.rs:1705 | analysis |
| hh:503 | RuleTrivialBool | clone | ruleaction.rs:112 | action.rs:1705 | analysis |
| hh:513 | RuleZextEliminate | clone | ruleaction.rs:357 | action.rs:1749 | analysis |
| hh:522 | RuleSlessToLess | ctor | ruleaction.rs:2322 | action.rs:1750 | analysis |
| hh:523 | RuleSlessToLess | clone | ruleaction.rs:2322 | action.rs:1750 | analysis |
| hh:532 | RuleZextSless | ctor | ruleaction.rs:3954 | action.rs:1751 | analysis |
| hh:533 | RuleZextSless | clone | ruleaction.rs:3954 | action.rs:1751 | analysis |
| hh:542 | RuleBitUndistribute | ctor | ruleaction.rs:5347 | action.rs:1752 | analysis |
| hh:543 | RuleBitUndistribute | clone | ruleaction.rs:5347 | action.rs:1752 | analysis |
| hh:553 | RuleBooleanUndistribute | ctor | ruleaction.rs:5731 | action.rs:1753 | analysis |
| hh:554 | RuleBooleanUndistribute | clone | ruleaction.rs:5731 | action.rs:1753 | analysis |
| hh:564 | RuleBooleanDedup | ctor | ruleaction.rs:5456 | action.rs:1754 | analysis |
| hh:565 | RuleBooleanDedup | clone | ruleaction.rs:5456 | action.rs:1754 | analysis |
| hh:574 | RuleBooleanNegate | ctor | ruleaction.rs:4895 | action.rs:1756 | analysis |
| hh:575 | RuleBooleanNegate | clone | ruleaction.rs:4895 | action.rs:1756 | analysis |
| hh:584 | RuleBoolZext | ctor | ruleaction.rs:5905 | action.rs:1755 | analysis |
| hh:585 | RuleBoolZext | clone | ruleaction.rs:5905 | action.rs:1755 | analysis |
| hh:594 | RuleLogic2Bool | ctor | ruleaction.rs:4947 | action.rs:1757 | analysis |
| hh:595 | RuleLogic2Bool | clone | ruleaction.rs:4947 | action.rs:1757 | analysis |
| hh:604 | RuleIndirectCollapse | ctor | ruleaction.rs:14998 | action.rs:1733 | analysis |
| hh:605 | RuleIndirectCollapse | clone | ruleaction.rs:14998 | action.rs:1733 | analysis |
| hh:615 | RuleMultiCollapse | clone | ruleaction.rs:9275 | action.rs:1732 | analysis |
| hh:624 | RuleSborrow | ctor | ruleaction.rs:4198 | action.rs:1701 | analysis |
| hh:625 | RuleSborrow | clone | ruleaction.rs:4198 | action.rs:1701 | analysis |
| hh:634 | RuleScarry | ctor | ruleaction.rs:4033 | action.rs:1702 | analysis |
| hh:635 | RuleScarry | clone | ruleaction.rs:4033 | action.rs:1702 | analysis |
| hh:644 | RuleTrivialShift | ctor | ruleaction.rs:2257 | action.rs:1706 | analysis |
| hh:645 | RuleTrivialShift | clone | ruleaction.rs:2257 | action.rs:1706 | analysis |
| hh:654 | RuleSignShift | ctor | ruleaction.rs:2797 | action.rs:1707 | analysis |
| hh:655 | RuleSignShift | clone | ruleaction.rs:2797 | action.rs:1707 | analysis |
| hh:665 | RuleTestSign | ctor | ruleaction.rs:3379 | action.rs:1708 | analysis |
| hh:666 | RuleTestSign | clone | ruleaction.rs:3379 | action.rs:1708 | analysis |
| hh:676 | RuleIdentityEl | clone | ruleaction.rs:2727 | action.rs:1709 | analysis |
| hh:686 | RuleShift2Mult | clone | ruleaction.rs:2084 | action.rs:1730 | analysis |
| hh:695 | RuleShiftPiece | ctor | ruleaction.rs:10745 | action.rs:1731 | analysis |
| hh:696 | RuleShiftPiece | clone | ruleaction.rs:10745 | action.rs:1731 | analysis |
| hh:706 | RuleCollapseConstants | clone | ruleaction.rs:16 | action.rs:1746 | analysis |
| hh:715 | RuleTransformCpool | ctor | ruleaction.rs:15163 | action.rs:1747 | analysis |
| hh:716 | RuleTransformCpool | clone | ruleaction.rs:15163 | action.rs:1747 | analysis |
| hh:726 | RulePropagateCopy | clone | ruleaction.rs:206 | action.rs:1748 | analysis |
| hh:735 | Rule2Comp2Mult | ctor | ruleaction.rs:6689 | action.rs:1734 | analysis |
| hh:736 | Rule2Comp2Mult | clone | ruleaction.rs:6689 | action.rs:1734 | analysis |
| hh:745 | RuleCarryElim | ctor | ruleaction.rs:6797 | action.rs:1736 | analysis |
| hh:746 | RuleCarryElim | clone | ruleaction.rs:6797 | action.rs:1736 | analysis |
| hh:755 | RuleSub2Add | ctor | ruleaction.rs:6556 | action.rs:1735 | analysis |
| hh:756 | RuleSub2Add | clone | ruleaction.rs:6556 | action.rs:1735 | analysis |
| hh:765 | RuleXorCollapse | ctor | ruleaction.rs:1139 | action.rs:1744 | analysis |
| hh:766 | RuleXorCollapse | clone | ruleaction.rs:1139 | action.rs:1744 | analysis |
| hh:775 | RuleAddMultCollapse | ctor | ruleaction.rs:1252 | action.rs:1745 | analysis |
| hh:776 | RuleAddMultCollapse | clone | ruleaction.rs:1252 | action.rs:1745 | analysis |
| hh:799 | RuleLoadVarnode | ctor | ruleaction.rs:17781 | action.rs:2032 | stackvars |
| hh:800 | RuleLoadVarnode | clone | ruleaction.rs:17781 | action.rs:2032 | stackvars |
| hh:809 | RuleStoreVarnode | ctor | ruleaction.rs:18050 | action.rs:2033 | stackvars |
| hh:810 | RuleStoreVarnode | clone | ruleaction.rs:18050 | action.rs:2033 | stackvars |
| hh:829 | RuleSubExtComm | ctor | ruleaction.rs:6603 | action.rs:1758 | analysis |
| hh:830 | RuleSubExtComm | clone | ruleaction.rs:6603 | action.rs:1758 | analysis |
| hh:839 | RuleSubCommute | ctor | ruleaction.rs:8484 | action.rs:1759 | analysis |
| hh:840 | RuleSubCommute | clone | ruleaction.rs:8484 | action.rs:1759 | analysis |
| hh:851 | RuleConcatCommute | ctor | ruleaction.rs:8384 | action.rs:1760 | analysis |
| hh:852 | RuleConcatCommute | clone | ruleaction.rs:8384 | action.rs:1760 | analysis |
| hh:871 | RuleConcatZext | ctor | ruleaction.rs:6851 | action.rs:1761 | analysis |
| hh:872 | RuleConcatZext | clone | ruleaction.rs:6851 | action.rs:1761 | analysis |
| hh:881 | RuleZextCommute | ctor | ruleaction.rs:6907 | action.rs:1762 | analysis |
| hh:882 | RuleZextCommute | clone | ruleaction.rs:6907 | action.rs:1762 | analysis |
| hh:891 | RuleZextShiftZext | ctor | ruleaction.rs:6964 | action.rs:1763 | analysis |
| hh:892 | RuleZextShiftZext | clone | ruleaction.rs:6964 | action.rs:1763 | analysis |
| hh:901 | RuleShiftAnd | ctor | ruleaction.rs:8024 | action.rs:1764 | analysis |
| hh:902 | RuleShiftAnd | clone | ruleaction.rs:8024 | action.rs:1764 | analysis |
| hh:911 | RuleConcatZero | ctor | ruleaction.rs:1061 | action.rs:1765 | analysis |
| hh:912 | RuleConcatZero | clone | ruleaction.rs:1061 | action.rs:1765 | analysis |
| hh:921 | RuleConcatLeftShift | ctor | ruleaction.rs:2457 | action.rs:1766 | analysis |
| hh:922 | RuleConcatLeftShift | clone | ruleaction.rs:2457 | action.rs:1766 | analysis |
| hh:931 | RuleSubZext | ctor | ruleaction.rs:2900 | action.rs:1767 | analysis |
| hh:932 | RuleSubZext | clone | ruleaction.rs:2900 | action.rs:1767 | analysis |
| hh:941 | RuleSubCancel | ctor | ruleaction.rs:7303 | action.rs:1768 | analysis |
| hh:942 | RuleSubCancel | clone | ruleaction.rs:7303 | action.rs:1768 | analysis |
| hh:951 | RuleShiftSub | ctor | ruleaction.rs:7077 | action.rs:1769 | analysis |
| hh:952 | RuleShiftSub | clone | ruleaction.rs:7077 | action.rs:1769 | analysis |
| hh:961 | RuleHumptyDumpty | ctor | ruleaction.rs:7141 | action.rs:1770 | analysis |
| hh:962 | RuleHumptyDumpty | clone | ruleaction.rs:7141 | action.rs:1770 | analysis |
| hh:971 | RuleDumptyHump | ctor | ruleaction.rs:7221 | action.rs:1771 | analysis |
| hh:972 | RuleDumptyHump | clone | ruleaction.rs:7221 | action.rs:1771 | analysis |
| hh:981 | RuleHumptyOr | ctor | ruleaction.rs:7432 | action.rs:1772 | analysis |
| hh:982 | RuleHumptyOr | clone | ruleaction.rs:7432 | action.rs:1772 | analysis |
| hh:991 | RuleSwitchSingle | ctor | ruleaction.rs:15264 | action.rs:1788 | analysis |
| hh:992 | RuleSwitchSingle | clone | ruleaction.rs:15264 | action.rs:1788 | analysis |
| hh:1001 | RuleCondNegate | ctor | ruleaction.rs:8115 | action.rs:1789 | analysis |
| hh:1002 | RuleCondNegate | clone | ruleaction.rs:8115 | action.rs:1789 | analysis |
| hh:1011 | RuleBoolNegate | ctor | ruleaction.rs:1614 | action.rs:1790 | analysis |
| hh:1012 | RuleBoolNegate | clone | ruleaction.rs:1614 | action.rs:1790 | analysis |
| hh:1021 | RuleLess2Zero | ctor | ruleaction.rs:1451 | action.rs:1738 | analysis |
| hh:1022 | RuleLess2Zero | clone | ruleaction.rs:1451 | action.rs:1738 | analysis |
| hh:1031 | RuleLessEqual2Zero | ctor | ruleaction.rs:1531 | action.rs:1739 | analysis |
| hh:1032 | RuleLessEqual2Zero | clone | ruleaction.rs:1531 | action.rs:1739 | analysis |
| hh:1042 | RuleSLess2Zero | ctor | ruleaction.rs:7542 | action.rs:1740 | analysis |
| hh:1043 | RuleSLess2Zero | clone | ruleaction.rs:7542 | action.rs:1740 | analysis |
| hh:1052 | RuleEqual2Zero | ctor | ruleaction.rs:7902 | action.rs:1741 | analysis |
| hh:1053 | RuleEqual2Zero | clone | ruleaction.rs:7902 | action.rs:1741 | analysis |
| hh:1062 | RuleEqual2Constant | ctor | ruleaction.rs:8221 | action.rs:1742 | analysis |
| hh:1063 | RuleEqual2Constant | clone | ruleaction.rs:8221 | action.rs:1742 | analysis |
| hh:1073 | RulePtrArith | ctor | ruleaction.rs:18477 | action.rs:2031 | typerecovery |
| hh:1074 | RulePtrArith | clone | ruleaction.rs:18477 | action.rs:2031 | typerecovery |
| hh:1084 | RuleStructOffset0 | ctor | ruleaction.rs:19943 | action.rs:2030 | typerecovery |
| hh:1085 | RuleStructOffset0 | clone | ruleaction.rs:19943 | action.rs:2030 | typerecovery |
| hh:1096 | RulePushPtr | ctor | ruleaction.rs:18190 | action.rs:2029 | typerecovery |
| hh:1097 | RulePushPtr | clone | ruleaction.rs:18190 | action.rs:2029 | typerecovery |
| hh:1107 | RulePtraddUndo | ctor | ruleaction.rs:15753 | action.rs:1839 | typerecovery |
| hh:1108 | RulePtraddUndo | clone | ruleaction.rs:15753 | action.rs:1839 | typerecovery |
| hh:1122 | RulePtrsubUndo | ctor | ruleaction.rs:15839 | action.rs:1840 | typerecovery |
| hh:1123 | RulePtrsubUndo | clone | ruleaction.rs:15839 | action.rs:1840 | typerecovery |
| hh:1134 | RuleMultNegOne | ctor | ruleaction.rs:6513 | action.rs:1888 | cleanup |
| hh:1135 | RuleMultNegOne | clone | ruleaction.rs:6513 | action.rs:1888 | cleanup |
| hh:1146 | RuleAddUnsigned | clone | ruleaction.rs:13234 | action.rs:1889 | cleanup |
| hh:1156 | Rule2Comp2Sub | ctor | ruleaction.rs:6730 | action.rs:1890 | cleanup |
| hh:1157 | Rule2Comp2Sub | clone | ruleaction.rs:6730 | action.rs:1890 | cleanup |
| hh:1167 | RuleSubRight | ctor | ruleaction.rs:13322 | action.rs:1894 | cleanup |
| hh:1168 | RuleSubRight | clone | ruleaction.rs:13322 | action.rs:1894 | cleanup |
| hh:1179 | RulePtrsubCharConstant | ctor | ruleaction.rs:13606 | action.rs:1897 | cleanup |
| hh:1180 | RulePtrsubCharConstant | clone | ruleaction.rs:13606 | action.rs:1897 | cleanup |
| hh:1190 | RuleExtensionPush | ctor | ruleaction.rs:13805 | action.rs:1898 | cleanup |
| hh:1191 | RuleExtensionPush | clone | ruleaction.rs:13805 | action.rs:1898 | cleanup |
| hh:1207 | RulePieceStructure | ctor | ruleaction.rs:14363 | action.rs:1899 | cleanup |
| hh:1208 | RulePieceStructure | clone | ruleaction.rs:14363 | action.rs:1899 | cleanup |
| hh:1218 | RuleSubNormal | ctor | ruleaction.rs:10261 | action.rs:1774 | analysis |
| hh:1219 | RuleSubNormal | clone | ruleaction.rs:10261 | action.rs:1774 | analysis |
| hh:1240 | RulePositiveDiv | ctor | ruleaction.rs:9878 | action.rs:1775 | analysis |
| hh:1241 | RulePositiveDiv | clone | ruleaction.rs:9878 | action.rs:1775 | analysis |
| hh:1251 | RuleDivTermAdd | ctor | ruleaction.rs:11789 | action.rs:1776 | analysis |
| hh:1252 | RuleDivTermAdd | clone | ruleaction.rs:11789 | action.rs:1776 | analysis |
| hh:1263 | RuleDivTermAdd2 | ctor | ruleaction.rs:11973 | action.rs:1777 | analysis |
| hh:1264 | RuleDivTermAdd2 | clone | ruleaction.rs:11973 | action.rs:1777 | analysis |
| hh:1277 | RuleDivOpt | ctor | ruleaction.rs:10930 | action.rs:1778 | analysis |
| hh:1278 | RuleDivOpt | clone | ruleaction.rs:10930 | action.rs:1778 | analysis |
| hh:1289 | RuleSignDiv2 | ctor | ruleaction.rs:9531 | action.rs:1781 | analysis |
| hh:1290 | RuleSignDiv2 | clone | ruleaction.rs:9531 | action.rs:1781 | analysis |
| hh:1300 | RuleDivChain | ctor | ruleaction.rs:9609 | action.rs:1782 | analysis |
| hh:1301 | RuleDivChain | clone | ruleaction.rs:9609 | action.rs:1782 | analysis |
| hh:1312 | RuleSignForm | clone | ruleaction.rs:9714 | action.rs:1779 | analysis |
| hh:1322 | RuleSignForm2 | ctor | ruleaction.rs:9788 | action.rs:1780 | analysis |
| hh:1323 | RuleSignForm2 | clone | ruleaction.rs:9788 | action.rs:1780 | analysis |
| hh:1334 | RuleSignNearMult | clone | ruleaction.rs:10004 | action.rs:1783 | analysis |
| hh:1344 | RuleModOpt | ctor | ruleaction.rs:11341 | action.rs:1784 | analysis |
| hh:1345 | RuleModOpt | clone | ruleaction.rs:11341 | action.rs:1784 | analysis |
| hh:1355 | RuleSignMod2nOpt | ctor | ruleaction.rs:10403 | action.rs:1785 | analysis |
| hh:1356 | RuleSignMod2nOpt | clone | ruleaction.rs:10403 | action.rs:1785 | analysis |
| hh:1367 | RuleSignMod2Opt | ctor | ruleaction.rs:10573 | action.rs:1787 | analysis |
| hh:1368 | RuleSignMod2Opt | clone | ruleaction.rs:10573 | action.rs:1787 | analysis |
| hh:1380 | RuleSignMod2nOpt2 | ctor | ruleaction.rs:11480 | action.rs:1786 | analysis |
| hh:1381 | RuleSignMod2nOpt2 | clone | ruleaction.rs:11480 | action.rs:1786 | analysis |
| hh:1391 | RuleSegment | ctor | ruleaction.rs:16439 | action.rs:1841 | segment |
| hh:1392 | RuleSegment | clone | ruleaction.rs:16439 | action.rs:1841 | segment |
| hh:1409 | RulePtrFlow | clone | ruleaction.rs:20115 | action.rs:1813 | subvar |
| hh:1419 | RuleNegateNegate | ctor | ruleaction.rs:13466 | action.rs:1826 | analysis |
| hh:1420 | RuleNegateNegate | clone | ruleaction.rs:13466 | action.rs:1826 | analysis |
| hh:1435 | RuleConditionalMove | ctor | ruleaction.rs:17013 | action.rs:1827 | conditionalexe |
| hh:1436 | RuleConditionalMove | clone | ruleaction.rs:17013 | action.rs:1827 | conditionalexe |
| hh:1446 | RuleFloatCast | ctor | ruleaction.rs:10181 | action.rs:1835 | floatprecision |
| hh:1447 | RuleFloatCast | clone | ruleaction.rs:10181 | action.rs:1835 | floatprecision |
| hh:1460 | RuleIgnoreNan | ctor | ruleaction.rs:17414 | action.rs:1836 | floatprecision |
| hh:1461 | RuleIgnoreNan | clone | ruleaction.rs:17414 | action.rs:1836 | floatprecision |
| hh:1472 | RuleUnsigned2Float | clone | ruleaction.rs:15446 | action.rs:1837 | analysis |
| hh:1483 | RuleInt2FloatCollapse | clone | ruleaction.rs:15598 | action.rs:1838 | analysis |
| hh:1493 | RuleFuncPtrEncoding | ctor | ruleaction.rs:15387 | action.rs:1831 | analysis |
| hh:1494 | RuleFuncPtrEncoding | clone | ruleaction.rs:15387 | action.rs:1831 | analysis |
| hh:1504 | RuleThreeWayCompare | ctor | ruleaction.rs:9041 | action.rs:1743 | analysis |
| hh:1505 | RuleThreeWayCompare | clone | ruleaction.rs:9041 | action.rs:1743 | analysis |
| hh:1517 | RulePopcountBoolXor | ctor | ruleaction.rs:7740 | action.rs:1798 | analysis |
| hh:1518 | RulePopcountBoolXor | clone | ruleaction.rs:7740 | action.rs:1798 | analysis |
| hh:1531 | RulePiecePathology | ctor | ruleaction.rs:16633 | action.rs:1842 | protorecovery |
| hh:1532 | RulePiecePathology | clone | ruleaction.rs:16633 | action.rs:1842 | protorecovery |
| hh:1542 | RuleXorSwap | ctor | ruleaction.rs:8157 | action.rs:1799 | analysis |
| hh:1543 | RuleXorSwap | clone | ruleaction.rs:8157 | action.rs:1799 | analysis |
| hh:1553 | RuleLzcountShiftBool | ctor | ruleaction.rs:8954 | action.rs:1800 | analysis |
| hh:1554 | RuleLzcountShiftBool | clone | ruleaction.rs:8954 | action.rs:1800 | analysis |
| hh:1564 | RuleFloatSign | ctor | ruleaction.rs:12582 | action.rs:1801 | analysis |
| hh:1565 | RuleFloatSign | clone | ruleaction.rs:12582 | action.rs:1801 | analysis |
| hh:1575 | RuleFloatSignCleanup | ctor | ruleaction.rs:13515 | action.rs:1895 | cleanup |
| hh:1576 | RuleFloatSignCleanup | clone | ruleaction.rs:13515 | action.rs:1895 | cleanup |
| hh:1586 | RuleOrCompare | ctor | ruleaction.rs:8298 | action.rs:1802 | analysis |
| hh:1587 | RuleOrCompare | clone | ruleaction.rs:8298 | action.rs:1802 | analysis |
| hh:1599 | RuleExpandLoad | ctor | ruleaction.rs:13947 | action.rs:1896 | cleanup |
| hh:1600 | RuleExpandLoad | clone | ruleaction.rs:13947 | action.rs:1896 | cleanup |

compareOp：hh:1433 | RuleConditionalMove | compareOp | 归 RULEACTION-CLONEBLOCKOPS-0001（construct_bool stub，ops 非空即 None，排序体在其内）。

