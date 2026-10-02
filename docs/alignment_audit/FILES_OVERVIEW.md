# Ghidra ↔ Rudra 文件级总览清单

**用途**:覆盖全部 114 个 Ghidra `.cc` 文件,标注每个的 Rudra 对应、范围判定、优先级。这是 `FUNCTION_MAP.md`(函数级清单)的索引 —— 每个文件核对函数前,先在此确认范围。

**范围判定**:
- **核心**:Rudra 必须 1:1 移植(反编译器算法)
- **集成**:Ghidra-app 集成层(Rudra 用自己的 loader/arch/ffi,不直接移植,但语义要等价)
- **SLEIGH**:SLEIGH 编译器(Rudra 通过 sleigh_shim 调用,不移植)
- **测试/接口/控制台**:Ghidra 内部测试与命令行(Rudra 不需要)
- **不移植**:明显不在 Rudra 范围(如 bfd/xml/特定平台 arch)

**优先级**(只对"核心"标注):
- P0 地基 — 数据结构 + op/var 编辑原语(所有上层都依赖)
- P1 核心算法 — SSA/合并/变量/跳转表/结构化
- P2 主管线 — Actions/Rules
- P3 输出 — 类型/C 代码生成
- P4 外围 — emulate/cover/comment 等

---

## A. 核心反编译器(必须 1:1 移植)

### P0 地基(数据结构 + 原语)

| Ghidra .cc | Rudra 模块 | 函数清单状态 |
|---|---|---|
| `address.cc` | `address.rs` | 🔍 待列 |
| `space.cc` | `space.rs` | 🔍 待列 |
| `varnode.cc` | `varnode.rs` | 🔍 待列 |
| `op.cc` | `op.rs` | 🔍 待列 |
| `opcodes.cc` | `opcodes.rs` | ✅ 已对齐(commit 413e0cf) |
| `pcoderaw.cc` | `pcoderaw.rs` | 🔍 待列 |
| `funcdata_op.cc` | `funcdata.rs` | 📋 已列 47 函数(FUNCTION_MAP.md) |
| `funcdata_varnode.cc` | `funcdata.rs` + `varnode.rs` | 🔍 待列 |
| `funcdata_block.cc` | `funcdata.rs` + `block.rs` | 🔍 待列 |
| `funcdata.cc` | `funcdata.rs` | 🔍 待列 |
| `block.cc` | `block.rs` | 🔍 待列 |

### P1 核心算法

| Ghidra .cc | Rudra 模块 | 函数清单状态 |
|---|---|---|
| `heritage.cc` | `heritage.rs` | ⚠️ 部分审(INDEX.md P0) |
| `merge.cc` | `merge.rs` | ⚠️ 部分审(INDEX.md) |
| `varmap.cc` | `varmap.rs` | ⚠️ 部分审(INDEX.md) |
| `jumptable.cc` | `jumptable.rs` | ⚠️ 部分审(INDEX.md) |
| `condexe.cc` | `condexe.rs` | ⚠️ 部分审(INDEX.md) |
| `blockaction.cc` | `blockaction.rs` | ⚠️ 部分审(INDEX.md) |
| `cover.cc` | `cover.rs` | 🔍 待列 |
| `rangeutil.cc` | `rangeutil.rs` | 🔍 待列 |
| `expression.cc` | `expression.rs` | 🔍 待列 |
| `database.cc` | `database.rs` | 🔍 待列 |
| `variable.cc` | `variable.rs` | 🔍 待列 |
| `transform.cc` | `transform.rs` | 🔍 待列 |
| `subflow.cc` | `subflow.rs` | 🔍 待列 |
| `prefersplit.cc` | `prefersplit.rs` | 🔍 待列 |
| `dynamic.cc` | `dynamic.rs` | 🔍 待列 |
| `constseq.cc` | `constseq.rs` | 🔍 待列 |
| `double.cc` | `double_precis.rs` | 🔍 待列 |
| `unionresolve.cc` | `unionresolve.rs` | 🔍 待列 |
| `unify.cc` | `unify.rs` | 🔍 待列 |
| `userop.cc` | `userop.rs` | 🔍 待列 |
| `float.cc` | `float_emulate.rs` | 🔍 待列 |
| `emulate.cc` | `emulate.rs` | 🔍 待列 |
| `emulateutil.cc` | `emulate.rs`? | 🔍 待列 |
| `flow.cc` | `flow.rs` | 🔍 待列 |
| `fspec.cc` | `fspec.rs` | 🔍 待列 |
| `modelrules.cc` | `fspec.rs`? | 🔍 待列 |
| `signature.cc` | `signature.rs` | 🔍 待列 |
| `paramid.cc` | `paramid.rs` | 🔍 待列 |
| `override.cc` | `override_rs.rs` | 🔍 待列 |

### P2 主管线(Actions/Rules)

| Ghidra .cc | Rudra 模块 | 函数清单状态 |
|---|---|---|
| `action.cc` | `action.rs` | 🔍 待列 |
| `coreaction.cc` | `coreaction.rs` | ⚠️ 部分审(INDEX.md) |
| `ruleaction.cc` | `ruleaction.rs` | ⚠️ 部分审(INDEX.md) |
| `cast.cc` | ?(`type_system` 或新模块) | 🔍 待列 |
| `typeop.cc` | `typeop.rs` | 🔍 待列 |

### P3 类型 + 输出

| Ghidra .cc | Rudra 模块 | 函数清单状态 |
|---|---|---|
| `type.cc` | `type_system.rs` | 🔍 待列 |
| `printc.cc` | `printc.rs` | 🔍 待列 |
| `prettyprint.cc` | `prettyprint.rs` | 🔍 待列 |
| `printlanguage.cc` | `printlanguage.rs` | 🔍 待列 |
| `comment.cc` | `comment.rs` | 🔍 待列 |
| `stringmanage.cc` | `stringmanage.rs` | 🔍 待列 |

### P4 外围(基础设施)

| Ghidra .cc | Rudra 模块 | 函数清单状态 |
|---|---|---|
| `architecture.cc` | `arch.rs` | 🔍 待列 |
| `capability.cc` | `capability.rs` | 🔍 待列 |
| `memstate.cc` | `memstate.rs` | 🔍 待列 |
| `loadimage.cc` | `loadimage.rs` | 🔍 待列 |
| `translate.cc` | ?(`disasm`) | 🔍 待列 |
| `opbehavior.cc` | `opbehavior.rs` | 🔍 待列 |
| `options.cc` | `options.rs` | 🔍 待列 |
| `globalcontext.cc` | `context.rs` | 🔍 待列 |
| `cpool.cc` | `cpool.rs` | 🔍 待列 |
| `callgraph.cc` | `callgraph.rs` | 🔍 待列 |
| `grammar.cc` | `grammar.rs` | 🔍 待列 |
| `crc32.cc` | `crc32.rs` | ✅ 已对齐 |
| `compression.cc` | `compression.rs` | 🔍 待列 |
| `graph.cc` | ? | 🔍 待列 |
| `codedata.cc` | ? | 🔍 待列 |
| `multiprecision.cc` | ?(`utils`) | 🔍 待列 |
| `marshal.cc` | `marshal.rs` | 🔍 待列 |
| `pcodeinject.cc` | `pcodeinject.rs` | 🔍 待列 |
| `pcodeparse.cc` | `pcodeparse.rs` | 🔍 待列 |
| `pcodecompile.cc` | `pcodeparse.rs`? | 🔍 待列 |

---

## B. SLEIGH 编译器(不移植,Rudra 通过 sleigh_shim 调用)

| Ghidra .cc | 处理 |
|---|---|
| `sleigh.cc` | 不移植(sleigh_shim) |
| `sleighbase.cc` | 不移植 |
| `sleigh_arch.cc` | 不移植 |
| `sleighexample.cc` | 不移植 |
| `slgh_compile.cc` | 不移植 |
| `slghparse.cc` | 不移植 |
| `slghpatexpress.cc` | 不移植 |
| `slghpattern.cc` | 不移植 |
| `slghscan.cc` | 不移植 |
| `slghsymbol.cc` | 不移植 |
| `semantics.cc` | 不移植 |
| `pcodecompile.cc`(部分) | 不移植 |
| `inject_sleigh.cc` | 不移植 |
| `slaformat.cc` | 不移植 |

---

## C. Ghidra-app 集成层(不直接移植,Rudra 用自己的实现)

| Ghidra .cc | Rudra 替代 | 备注 |
|---|---|---|
| `ghidra_arch.cc` | `arch.rs` | Rudra 自己的 arch 配置 |
| `ghidra_context.cc` | `context.rs` |  |
| `ghidra_process.cc` | — | Ghidra 进程协议,Rudra 不需要 |
| `ghidra_translate.cc` | `disasm/` | Rudra 用 SLEIGH shim |
| `comment_ghidra.cc` | `comment.rs` |  |
| `database_ghidra.cc` | `database.rs` |  |
| `cpool_ghidra.cc` | `cpool.rs` |  |
| `inject_ghidra.cc` | `pcodeinject.rs` |  |
| `loadimage_ghidra.cc` | `loadimage.rs` |  |
| `signature_ghidra.cc` | `signature.rs` |  |
| `string_ghidra.cc` | `stringmanage.rs` |  |
| `typegrp_ghidra.cc` | `type_system` |  |
| `xml_arch.cc` | `marshal.rs` |  |

---

## D. Loader / 平台 arch(Rudra 用 goblin/iced,不移植 Ghidra 的)

| Ghidra .cc | 处理 |
|---|---|
| `bfd_arch.cc` | 不移植(bfd) |
| `loadimage_bfd.cc` | 不移植 |
| `loadimage_xml.cc` | 不移植 |
| `raw_arch.cc` | 不移植 |
| `xml_arch.cc` | 不移植 |

---

## E. 测试 / 控制台 / 接口 / 工具(不移植)

| Ghidra .cc | 处理 |
|---|---|
| `test.cc` | 不移植 |
| `testfunction.cc` | 不移植 |
| `ifacedecomp.cc` | 不移植 |
| `ifaceterm.cc` | 不移植 |
| `interface.cc` | 不移植 |
| `consolemain.cc` | 不移植 |
| `libdecomp.cc` | 不移植 |
| `filemanage.cc` | 不移植 |
| `analyzesigs.cc` | 不移植 |

---

## F. XML / 序列化(部分移植到 marshal.rs)

| Ghidra .cc | 处理 |
|---|---|
| `xml.cc` | 部分移植(`marshal.rs`,Rudra 用 serde 替代大部分) |

---

## 统计

| 类别 | 文件数 |
|---|---|
| A. 核心(必须 1:1 移植) | ~75 |
| B. SLEIGH(不移植) | ~14 |
| C. Ghidra-app 集成(替代实现) | ~13 |
| D. Loader/平台(不移植) | ~5 |
| E. 测试/控制台(不移植) | ~9 |
| F. XML(部分移植) | 1 |
| **总计** | **~117**(含 .cc 实际约 114) |

**核对范围**:核心 75 个文件需逐函数对照。其余 ~40 个要么不移植,要么用 Rust 替代实现(语义等价即可)。

---

## 核对进度

| 优先级 | 文件数 | 已列函数清单 | 已对齐 |
|---|---|---|---|
| P0 地基 | 11 | 1(funcdata_op.cc) | 部分 |
| P1 核心算法 | 29 | 5(部分,INDEX.md) | 部分 |
| P2 主管线 | 5 | 2(部分,INDEX.md) | 部分 |
| P3 输出 | 6 | 0 | 0 |
| P4 外围 | 21 | 1(crc32) | 1 |
| **合计核心** | **72** | **~9** | **~2** |

**下一步**:继续 P0 地基的函数清单 —— `address.cc` → `space.cc` → `varnode.cc` → `op.cc` → `funcdata_op.cc`(已在 FUNCTION_MAP.md)→ `funcdata_varnode.cc` → `funcdata_block.cc` → `funcdata.cc` → `block.cc`。每个文件列完函数后,逐个核对四类语义。
