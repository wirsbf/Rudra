# 核心对齐规则与实现鸿沟文档总线 (Alignment Docs)

本目录（`docs/alignment_docs/`）专门用于**严格归档并跟踪记录 Rudra 和 Ghidra (标杆) 之间的所有算法、架构、与反编译中间表示（IR）层面的对齐规则**。

由于反编译引擎是对精度有着极端苛求的系统工程，每一条指令的寄存器分配、标志位还原，甚至于 `PcodeOp` 下的一个特殊 Flag 位偏差，都可能在后端 AST 化时引发灾难性雪崩。因此，**“无档不对齐，有档必核验”**是开发铁规。

---

## 目录索引与存放规范

*   **`TEMPLATE.md`**: 所有放入此目录下的对齐文档**必须**继承并遵循此模板格式。
*   **`blueprints/`**: (蓝图区) 用于存放对于某个大子系统（如：变量恢复引擎，或结构体布局还原算法）的长期对齐规划和长篇技术散文。
*   **`checklists/`**: (检查清单区) 最核心的区域。用于沉淀微观层级的、随时可以转化为 Issue 或 TODO 的短篇对齐核查表。譬如：“`x86_64` 的 `LEA` 指令特判对齐清单”、“浮点运算 (`FLOAT_*`) Flag 推导清单”。

## 当前遗留的 TODO 与补齐进度板 (Action Board)

以下是当前系统急需完善或核对的底层对齐项目，请依据优先级挑选认领，并在工作结束时更新对应链接的状态。

*(注：开发人员应通过复制 `TEMPLATE.md` 来新建下列任务的详情页页说明！)*

### 高优先级 (P0) —— 影响控制流网生成的命脉
- [ ] **TODO**: 撰写 `checklists/x86_64_calling_convention.md`
  - *说明*: Ghidra 内部存在极其复杂的参数栈寻址启发式推演，当前 Rudra 在解析诸如 `stdcall`, `fastcall` 等调用约定上尚未对齐。
- [ ] **TODO**: 撰写 `checklists/branch_indirect_recovery.md`
  - *说明*: 针对 `OpCode::BRANCHIND` (Switch 表跳或函数指针) 的目标推算机制，需要深挖 `Ghidra` 的 JumpTable 模型并向 Rust 端搬运。

### 中优先级 (P1) —— 影响局部数据流与 AST 美观度
- [ ] **TODO**: 撰写 `blueprints/ssa_phi_placement_rules.md`
  - *说明*: 详述 Ghidra 基于支配边界 (Dominance Frontier) 插入 `MULTIEQUAL` (Phi) 节点的特例（比如死循环或者非收敛点强插机制），这关系到数据流的干净程度。
- [ ] **TODO**: 撰写 `checklists/subpiece_algebra_folding.md`
  - *说明*: 代数化简层，记录关于 `PIECE` (拼接) 和 `SUBPIECE` (提取) 在遇见 `INT_ADD` 时如何被安全抵消压缩的 Rule 表对齐进度。

### 低优先级 (P2) —— 长效与边角
- [ ] **TODO**: 撰写 `checklists/floating_point_ops.md`
  - *说明*: `FLOAT_NAN` 等特殊比较标志位与 FPU 栈虚拟化对齐。
- [ ] **TODO**: 撰写 `blueprints/high_variable_naming.md`
  - *说明*: Ghidra 生成 `iVar1`, `uVar2`, `piVar3` 的类型绑定与命名法则推算逻辑。

---

> **给 AI 助手的指示**: 当执行对齐开发时，随时从上方挑选 TODO，生成实体 `.md` 文件，并在完成代码与验证后，在此主控板上将其打勾 `[x]` 并链接至对应的文档相对路径！
