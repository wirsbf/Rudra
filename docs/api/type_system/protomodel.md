# `type_system/protomodel.rs` API Reference

**源代码路径**: `src/type_system/protomodel.rs`
**Ghidra 对应**: `fspec.hh` ProtoModel (748-1100) + ParamEntry (84-155) + ParamList (425-588)

## 模块说明

调用约定原型模型。定义参数传递方式（寄存器 vs 栈、顺序、对齐、扩展）。
是参数恢复引擎（checkInputTrialUse/resolveModel/deriveInputMap）的核心依赖。

## 导出的公共 API

### `pub struct ParamEntry`
参数存储位置（寄存器或栈）。
- `contains(addr, sz) -> bool` — 是否包含给定范围
- `intersects(addr, sz) -> bool` — 是否与给定范围相交
- `is_exclusion() -> bool` — 是否独占（alignment==0）

### `pub struct ProtoModel`
调用约定模型。
- `default_x86_64()` — x86-64 System V ABI 默认模型（RDI=0x38/RSI=0x30/RDX=0x10/RCX=0x8/R8=0x80/R9=0x88 + 栈 + RAX=0x0 返回）。offset 与 x86_lift.rs 寄存器编码及 SYSV_ARG_REGS（coreaction.rs）一致。2026-06-29 修正：此前 RDI/RCX/RDX offset 错误（RDI=0x8, RCX=0x10, RDX=0x38），现已统一。
- `fillin_input_map(active)` — fillinMap 参数推导算法
- `derive_input_map(active)` — 调用 fillin_input_map
- `derive_output_map(active)` — 至多标记 1 个输出试验为 USED
- `possible_input_param(addr, sz, space)` — 是否可能是输入参数
- `characterize_as_input_param(addr, sz, space)` — 参数包含关系分类
- `check_input_split(addr, sz, splitpoint, space)` — 是否可分割

## 2026-06-27 移植状态

5 个单元测试。**剩余**：ParamListRegister/Merged 变体、XML decode、JoinRecord。

## ParamActive 模型回归测试（2026-08-24）

输入/输出模型测试通过 `register_trial_in_space(AddressSpace::Register, ...)`
构造完整 trial，不再用无空间 tag 的 `Address` 暗示寄存器。测试仍只覆盖当前
硬编码 x86-64 模型；它不扩大 `ProtoModel` 的生产对齐声明。
<!-- annotation-pass: 2026-07-04 -->
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
