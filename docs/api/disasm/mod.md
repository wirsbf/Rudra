# `disasm/mod.rs` API Reference

**源代码路径**: `src/disasm/mod.rs`

## 文档状态

- **状态**: 已核对（当前有效，2026-09-26 SLEIGH-RUSTIFY-PHASE3-0001 重写）
- **可信度**: 高
- **文档目标**: 说明 Phase3 之后 Rudra 反汇编/P-code 发射层的角色、边界与公开接口
- **重要提醒**: iced-x86 引导解码器与手写 `X86Lifter` 已于本车道退役删除；
  本文档不再描述 `Instruction` / `Operand` / `Disassembler` trait /
  `create_disassembler` 等已删除接口（历史版本见 git 历史）。

---

## 模块定位

`disasm/` 现在只包含一个子模块 `sleigh_lift`——锁定 `.sla` 的 P-code 发射桥。
机器码不再经过“反汇编成指令对象再手写提升”的两段式路径，而是与 Ghidra 同构：
单一解码器（SLEIGH 引擎）直接从字节产出 P-code（`Translate::oneInstruction`，
translate.hh:419；`Sleigh::oneInstruction`，sleigh.cc:741）。

```text
binary bytes
  -> binary loading / section mapping
  -> disasm::sleigh_lift (SLEIGH oneInstruction -> PcodeOpRaw)
  -> Funcdata / PcodeOp / Varnode graph
  -> Action / Heritage / PrintC
```

### 与 Ghidra 架构的对应关系

Ghidra 反编译器只有一个解码入口：`Translate::oneInstruction` 按流跟随逐指令
发射 P-code（flow.cc:421 的调用点）。Rudra Phase3 之后同样只有一个解码器
（kuna-sleigh 引擎 + 锁定 `sleigh_specs/x86-64.sla`），不再保留第二套
x86 语义实现。

---

## 当前公开接口

模块本身只重导出子模块：

```rust
pub mod sleigh_lift;
```

全部能力在 `docs/api/disasm/sleigh_lift.md` 逐项说明，要点：

- `SleighLifter::configure_x86_64(image, base)`：为一个函数流配置独立
  translator（pspec 兼容路径 + 镜像加载）。
- `SleighLifter::lift_instruction(addr)`：一次严格 `oneInstruction`，原子
  返回 `(step, ops)`；每个 op 自带 `SeqNum(addr, 0)`。
- `SleighLifter::lift_instruction_skip_nops(addr)`：同上，但丢弃 `.sla`
  自身分类为 `NOP` 的 no-effect padding 的引擎操作数 pcode（canon httpd
  驱动线性 walk 的契约，见 sleigh_lift.md 的 Phase3 节）。
- `SleighLifter::assembly_mnemonic(addr)`：`Translate::printAssembly`
  （translate.hh:442）助记符探针，调试器列表打印用。
- 自由函数 `sleigh_raw_ops(code, base)` / `sleigh_raw_ops_skip_nops(code, base)`：
  线性 walk 胶水（Ghidra 无线性解码器，flow-following 是它唯一契约），
  驱动器/测试的 raw-op 构造入口；后者带 canon 驱动的 padding 过滤。

---

## 已删除接口（2026-09-26，SLEIGH-RUSTIFY-PHASE3-0001）

| 已删除 | 原角色 | 替代物 |
|---|---|---|
| `X86_64Disassembler`（iced-x86 封装） | 指令级线性反汇编 | `sleigh_lift` 线性 walk / 流跟随 |
| `X86Lifter`（手写 x86→P-code） | 指令对象→PcodeOpRaw 提升 | SLEIGH 引擎发射 |
| `Instruction` / `Operand` / `InstructionMetadata` | iced 指令表示 | 无——P-code 直接产出，不再有中间指令对象 |
| `Disassembler` trait / `create_disassembler` | 多架构分发抽象 | 单解码器架构（Ghidra 同构） |
| `binary::disassemble_function` | binary→disasm 桥接 | 已是死代码（仅注释态 `Decompiler` 旧壳引用），随桥一并删除 |

删除依据：canon curl 换装后字节恒等（md5 与基线一致）、num_params A/B 30 函数
0 差异、DAT 候选 840==840、call targets 479==479；canon httpd 的残差全部
归因到持有域管线分歧（见 TODO_BOARD 票面）。完整证据链见
`/dev/shm/rudra-reports/LANE_SLEIGHP3_2026-09-26.md`（root 集成后归档）。

---

## 风险与限制提示

### 1. 线性 walk 是 Rudra 胶水，不是 Ghidra 契约
Ghidra 只有 flow-following 解码；`sleigh_raw_ops*` 的线性 walk 是驱动器
构造 raw-op 的胶水，其“不可解码字节跳 1 字节”契约沿袭退役 iced walk。

### 2. padding 过滤依赖 `.sla` 自身分类
`lift_instruction_skip_nops` 用 `printAssembly` 助记符判定 NOP；换 `.sla`
版本时该分类随构造器表变化（ia.sinc:4136-4137 的 `:NOP rm32` 空模板 +
rm 操作数附着语义是当前锁定 `.sla` 的实测行为）。

### 3. 模块整体状态仍是 L2/MISMATCH
`ContextInternal` pspec 全量、Fspec 动态空间等缺口见 `SLEIGH-0002C/D`、
`ADDR-0001`；状态以 `ALIGNMENT_ROADMAP.md` 为准。

---

## 与其他文档的关系

- `docs/api/disasm/sleigh_lift.md`：本模块唯一子模块的逐 API 参考
- `docs/api/funcdata.md`：22 个测试站点的 `sleigh_raw_ops` 迁移记录
- `docs/api/binary/mod.md`：`disassemble_function` 桥接删除记录
- `ALIGNMENT_ROADMAP.md`：模块级 L1/L2/L3 状态账本
