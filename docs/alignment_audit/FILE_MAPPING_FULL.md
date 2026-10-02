# Rudra ↔ Ghidra 完整文件映射文档

> 由 5 个子 Agent 并行审计生成（2026-07-21）
> 总计：Ghidra 114 个 .cc 文件，Rudra 67 个 .rs 文件

---

## 一、模块组总览

| 模块组 | Ghidra 文件数 | Ghidra 行数 | Ghidra 函数 | Rudra 文件数 | Rudra 函数 | `// Ghidra:` 注释 |
|---|---|---|---|---|---|---|
| Core IR | 4 | 7041 | 396 | 5 | 473 | 450 |
| Pipeline + SSA | 8 | 27380 | 784 | 8 | 1520 | 1297 |
| Structuring + Output | 10 | 18522 | 857 | 10 | 749 | 573 |
| Funcdata + Infra + Other | 34 | 38634 | 1523 | 34 | 2615 | 1866 |
| SLEIGH + Type + Arch | ~25 | ~30000 | ~1200 | ~10 | ~350 | ~80 |
| **合计** | **~81** | **~121577** | **~4760** | **~67** | **~5707** | **~4266** |

---

## 二、Core IR 模块组

| Ghidra 文件 | 行数 | 函数 | Rudra 文件 | 函数 | 注释 | 状态 |
|---|---|---|---|---|---|---|
| op.cc | 1213 | 47 | op.rs | 94 | 93 | ✅ 强对齐 |
| varnode.cc | 2053 | 88 | varnode.rs | 210 | 203 | ✅ 强对齐 |
| variable.cc | 1203 | 51 | variable.rs | 29 | 25 | ⚠️ 弱对齐（VariableGroup/VariablePiece/HighIntersectTest 未移植） |
| typeop.cc | 2572 | 210 | typeop.rs | 179 | 154 | ⚠️ 部分对齐（~52/73 TypeOp 子类未移植为 struct） |
| opcodes.cc | 137 | (enum) | opcodes.rs | 6 | (header) | ✅ 1:1 |

**关键缺失**：
- variable.rs：VariableGroup、VariablePiece、HighIntersectTest 三个类完全缺失
- typeop.rs：算术/位运算/布尔/浮点 TypeOp 子类未移植为独立 struct（功能通过 opcode_flags 表替代）

---

## 三、Pipeline + SSA 模块组

| Ghidra 文件 | 行数 | 函数 | Rudra 文件 | 函数 | 注释 | 状态 |
|---|---|---|---|---|---|---|
| action.cc | 1163 | 68 | action.rs | 44 | 5 | ⚠️ 部分（54/68 方法，多为生命周期辅助） |
| coreaction.cc | 5741 | 125 | coreaction.rs | 327 | 248 | ✅ 强对齐（40/125 缺失，大 Action 子方法） |
| ruleaction.cc | 11016 | 340 | ruleaction.rs | 810 | 678 | ✅ 基本完整（8/340 缺失） |
| heritage.cc | 2886 | 74 | heritage.rs | 106 | 164 | ✅ 强对齐（12/74 缺失，主流程零 TODO） |
| merge.cc | 1695 | 48 | merge.rs | 65 | 76 | ✅ 强对齐 |
| varmap.cc | 1620 | 48 | varmap.rs | 74 | 63 | ✅ 对齐（22/48 缺失，多为 ScopeLocal 细节方法） |
| cover.cc | 654 | 21 | cover.rs | 30 | 25 | ✅ 对齐 |
| rangeutil.cc | 2605 | 60 | rangeutil.rs | 64 | 38 | ⚠️ 部分（45/60 缺失，CircleRange 构造器/setter 不足） |

**关键缺失**：
- rangeutil.rs：ValueSetSolver 未移植（~600 行），CircleRange newStride/newDomain/setRange/contains 缺失
- action.rs：Action 生命周期方法（issueWarning/turnOnDebug 等）
- varmap.rs：ScopeLocal collectNameRecs/annotateRawStackPtr/checkUnaliasedReturn

---

## 四、Structuring + Output 模块组

| Ghidra 文件 | 行数 | 函数 | Rudra 文件 | 函数 | 注释 | 状态 |
|---|---|---|---|---|---|---|
| block.cc | 3723 | 204 | block.rs | 248 | 198 | ✅ 强对齐 |
| blockaction.cc | 2366 | 83 | blockaction.rs | 69 | 87 | ✅ 强对齐 |
| condexe.cc | 712 | 27 | condexe.rs | 42 | 43 | ✅ 强对齐 |
| jumptable.cc | 2883 | 133 | jumptable.rs | 139 | 207 | ✅ 强对齐 |
| graph.cc | 502 | 17 | (无) | 0 | 0 | ❌ 完全缺失（17 个 graphviz/DOT dump 函数） |
| printc.cc | 3401 | 182 | printc.rs | 83 | 42 | ⚠️ 部分（~46%，缺 emit*/push*Constant/op* emitter） |
| printlanguage.cc | 820 | 34 | printlanguage.rs | 27 | 1 | ⚠️ 弱对齐（trait 默认空实现） |
| prettyprint.cc | 1245 | 87 | prettyprint.rs | 104 | 43 | ⚠️ 部分（EmitMarkup + 行换行内部缺失） |
| grammar.cc | 3338 | 61 | grammar.rs | 23 | 30 | ⚠️ 部分（yacc/lex 生成代码，解析器部分 stub） |
| expression.cc | 562 | 14 | expression.rs | 13 | 22 | ✅ 对齐 |

**关键缺失**：
- graph.rs：完全缺失（graphviz DOT dump，非核心功能，可后补）
- printc.rs：emitFunctionDeclaration/docTypeDefinitions/emitStructDefinition + 多个 op emitter
- printlanguage.rs：RPN 引擎（pushOp/pushAtom/recurse/parentheses）仅 trait 壳

---

## 五、Funcdata + Infra + Other 模块组

### 已匹配文件（34 个）

| Ghidra 文件 | 行数 | 函数 | Rudra 文件 | 函数 | 注释 |
|---|---|---|---|---|---|
| funcdata.cc | 1122 | 42 | funcdata.rs | 165 | 135 |
| fspec.cc | 5976 | 239 | fspec.rs | 122 | 116 |
| address.cc | 836 | 30 | address.rs | 84 | 62 |
| space.cc | 682 | 39 | space.rs | 62 | 40 |
| memstate.cc | 738 | 28 | memstate.rs | 40 | 23 |
| database.cc | 3430 | 167 | database.rs | 131 | 105 |
| marshal.cc | 1273 | 83 | marshal.rs | 136 | 43 |
| subflow.cc | 4130 | 111 | subflow.rs | 155 | 118 |
| flow.cc | 1460 | 46 | flow.rs | 11 | 9 |
| emulate.cc | 462 | 33 | emulate.rs | 20 | 13 |
| userop.cc | 648 | 37 | userop.rs | 64 | 52 |
| dynamic.cc | 773 | 28 | dynamic.rs | 29 | 23 |
| constseq.cc | 1004 | 33 | constseq.rs | 27 | 21 |
| transform.cc | 767 | 35 | transform.rs | 71 | 52 |
| typeop.cc | 2572 | 209 | typeop.rs | 179 | 154 |
| signature.cc | 1148 | 47 | signature.rs | 24 | 12 |
| cpool.cc | 245 | 10 | cpool.rs | 41 | 29 |
| comment.cc | 406 | 21 | comment.rs | 45 | 36 |
| context.cc | 239 | 11 | context.rs | 53 | 31 |
| options.cc | 1063 | 45 | options.rs | 51 | 35 |
| pcodeinject.cc | 361 | 16 | pcodeinject.rs | 36 | 23 |
| pcodeparse.cc | 3303 | 12 | pcodeparse.rs | 44 | 29 |
| pcoderaw.cc | 124 | 5 | pcoderaw.rs | 36 | 16 |
| override.cc | 435 | 21 | override_rs.rs | 43 | 28 |
| paramid.cc | 284 | 8 | paramid.rs | 27 | 7 |
| compression.cc | 165 | 10 | compression.rs | 18 | 0 |
| crc32.cc | 74 | 0 | crc32.rs | 3 | 1 |
| stringmanage.cc | 477 | 15 | stringmanage.rs | 37 | 19 |
| loadimage.cc | 116 | 6 | loadimage.rs | 36 | 21 |
| capability.cc | 51 | 3 | capability.rs | 13 | 0 |
| callgraph.cc | 468 | 26 | callgraph.rs | 34 | 26 |
| double.cc | 3647 | 109 | double_precis.rs | 191 | 127 |
| unionresolve.cc | 1110 | 24 | unionresolve.rs | 31 | 18 |
| unify.cc | 1647 | 136 | unify.rs | 433 | 389 |

### 未匹配文件（已合并到其他 .rs）

| Ghidra 文件 | 行数 | 合并到 |
|---|---|---|
| funcdata_op.cc | 1502 | funcdata.rs |
| funcdata_block.cc | 1106 | funcdata.rs |
| funcdata_varnode.cc | 2239 | funcdata.rs + varnode.rs |
| xml.cc | 2510 | marshal.rs + database.rs |

**关键缺失**：
- flow.rs：仅 11 函数（Ghidra 46），大部分逻辑可能在 subflow.rs/tracedag.rs
- fspec.rs：122 vs 239（Rust 约一半）
- signature.rs：24 vs 47（部分实现）

---

## 六、SLEIGH + Type + Arch 模块组

### 战略排除（文档记录）

| 类别 | Ghidra 文件 | 原因 |
|---|---|---|
| SLEIGH 编译器 | slgh_compile/slghparse/slghscan/slghsymbol/slghpatexpress/slghpattern/semantics.cc | Rudra 不编译 .sleigh 规格，加载预编译 .sla |
| SLEIGH 运行时引擎 | sleigh.cc/sleighbase.cc/slaformat.cc | 通过 FFI shim 包装 Ghidra C++ 引擎 |
| Ghidra GUI/进程桥 | ghidra_arch/ghidra_process/ghidra_translate/ghidra_context.cc | Rudra 独立运行，不做 Ghidra 子进程 |

### 已移植/部分移植

| Ghidra 文件 | 行数 | 状态 | Rust 文件 |
|---|---|---|---|
| type.cc | 4677 | ⚠️ 部分（228 方法中约 97 已移植） | type_system/datatype.rs + type_system/typefactory.rs |
| cast.cc | 546 | ✅ 完整 | type_system/cast.rs |
| modelrules.cc | 1711 | ❌ 缺失（89 方法，零 Rust 引用） | (应并入 type_system/protomodel.rs) |
| architecture.cc | 1570 | ✅ L3 完整 | arch.rs |
| globalcontext.cc | 618 | ✅ L3 完整 | context.rs |
| translate.cc | 1018 | ⚠️ 部分（join records + iced-x86 lifter） | arch.rs (partial) + disasm/ |
| pcodecompile.cc + pcodeparse.cc | 4084 | ✅ L2.5 | pcodeparse.rs |
| inject_sleigh.cc + inject_ghidra.cc | 756 | ⚠️ 部分 | pcodeinject.rs |
| sleigh_arch.cc | 632 | ❌ 跳过（bootstrap 内联在 sleigh_ffi.rs） | sleigh_ffi.rs (FFI) |

---

## 七、对齐状态汇总

### ✅ 强对齐（可直接验证对齐质量）

| 模块 | 文件 | 对齐度 |
|---|---|---|
| Core IR | op.rs, varnode.rs, opcodes.rs | ~95% |
| Pipeline | ruleaction.rs | ~98% |
| Pipeline | coreaction.rs, heritage.rs, merge.rs | ~85-90% |
| Structuring | block.rs, blockaction.rs, condexe.rs, jumptable.rs | ~90% |
| Funcdata | funcdata.rs, unify.rs, double_precis.rs, subflow.rs | ~85% |
| Infra | address.rs, space.rs, database.rs, context.rs, arch.rs | ~85% |

### ⚠️ 部分对齐（有实现但缺关键子方法）

| 模块 | 文件 | 主要缺口 |
|---|---|---|
| Core IR | variable.rs | VariableGroup/VariablePiece/HighIntersectTest 全缺 |
| Core IR | typeop.rs | ~52 个 TypeOp 子类未移植为 struct |
| Pipeline | rangeutil.rs | ValueSetSolver 未移植，CircleRange API 不足 |
| Pipeline | varmap.rs | ScopeLocal 名称恢复方法部分缺失 |
| Pipeline | action.rs | Action 生命周期辅助方法 |
| Output | printc.rs | emit*/push*Constant/op* emitter ~50% 缺失 |
| Output | printlanguage.rs | RPN 引擎仅 trait 壳 |
| Output | prettyprint.rs | EmitMarkup + 行换行内部 |
| Funcdata | flow.rs | 仅 11 函数（Ghidra 46） |
| Funcdata | fspec.rs | 122 vs 239 函数 |
| Funcdata | signature.rs | 24 vs 47 函数 |
| Type | type.cc → type_system/ | 228 方法中约 97 已移植 |

### ❌ 完全缺失/战略排除

| 文件 | 原因 |
|---|---|
| graph.cc (17 函数) | graphviz DOT dump，非核心 |
| modelrules.cc (89 函数) | ProtoModel 动态选择规则，真实缺口 |
| slgh_compile/slghparse/slghscan/slghsymbol/slghpatexpress/slghpattern/semantics.cc | SLEIGH 编译器，战略排除 |
| sleigh.cc/sleighbase.cc/slaformat.cc | SLEIGH 运行时，FFI 包装 |
| ghidra_arch/ghidra_process/ghidra_translate/ghidra_context.cc | Ghidra GUI 桥，战略排除 |

---

## 八、Rudra 独有文件（Ghidra 无直接对应物）

| Rust 文件 | 说明 |
|---|---|
| sleigh_ffi.rs | SLEIGH FFI 包装层（替代 Ghidra Translate 类层次） |
| disasm/sleigh_lift.rs | SLEIGH 提升（调用 FFI） |
| disasm/x86_lift.rs | iced-x86 原生 x86 提升 |
| ffi.rs | 通用 FFI 入口 |
| error.rs | anyhow 错误处理 |
| utils.rs | 工具函数 |
| types.rs | Rudra 标量类型（非 type.cc 对应物） |
| float_emulate.rs | 浮点模拟 |
| grammar.rs | C 语法解析（替代 grammar.cc 的 yacc/lex） |
| expression.rs | 表达式等价分析 |
| override_rs.rs | 文件名带 _rs 后缀（Ghidra override.cc） |
| constseq.rs | 常量序列分析 |
| opbehavior.rs | 操作行为模拟 |
| rangemap.rs | 范围映射 |
| prefersplit.rs | 偏好拆分管理器 |
| tracedag.rs | 追踪 DAG（Ghidra 中在 blockaction.cc 内） |
| printc.rs 中的 optoken/print_mods | OpToken 优先级引擎（Ghidra 在 printlanguage.cc 内） |

---

*文档生成时间：2026-07-21*
*审计方法：5 个子 Agent 并行扫描，逐文件对比函数计数 + `// Ghidra:` 注释覆盖率*
