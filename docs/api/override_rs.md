# override_rs.rs — Override commands API

Faithful port of Ghidra's `override.hh` / `override.cc` (435 lines).

**Status:** L1 → L2. Complete in-memory implementation; XML encode/decode is an
L3 gap pending the Encoder/Decoder infrastructure.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/override.{hh,cc}`.

## Enums

### `FlowOverride`
Flow-override type enumeration. Faithful to the `Override` enum
(override.hh:53).
- `None = 0`, `Branch = 1`, `Call = 2`, `CallReturn = 3`, `Return = 4`.
- `to_string(self) -> &'static str` — name (override.cc:405).
- `from_string(&str) -> Self` — parse (override.cc:421).

## Structs

### `Override`
A container of commands that override the decompiler's default behavior for a
single function. Faithful to `Override` (override.hh:50).

| Method | Description |
|---|---|
| `new()` | Empty override set. |
| `clear()` | Clear all overrides (override.cc:29). |
| `insert_force_goto(target, dest)` | Force-goto override (override.cc:66). |
| `insert_deadcode_delay(space_index, delay)` | Dead-code delay (override.cc:79). |
| `has_deadcode_delay(space_index, current_delay) -> bool` | Check (override.cc:92). |
| `insert_indirect_override(callpoint, directcall)` | Indirect→direct (override.cc:109). |
| `insert_proto_override(callpoint)` | Prototype override marker (override.cc:121). |
| `insert_multistage_jump(addr)` | Multistage flag (override.cc:137). |
| `insert_flow_override(addr, type)` | Flow override (override.cc:148). |
| `query_force_goto(target) -> Option<Address>` | Look up forced goto. |
| `force_gotos() -> impl Iterator` | All force-gotos. |
| `apply_indirect(callpoint) -> Option<Address>` | Indirect override (override.cc:177). |
| `apply_prototype(callpoint) -> bool` | Proto override (override.cc:160). |
| `query_multistage_jumptable(addr) -> bool` | Multistage check (override.cc:191). |
| `get_deadcode_delay(space_index) -> i32` | Delay or -1 (override.cc:217). |
| `deadcode_delays() -> impl Iterator` | (space_index, delay) pairs. |
| `has_flow_override() -> bool` | Any flow overrides (override.hh:84). |
| `get_flow_override(addr) -> FlowOverride` | Flow type (override.cc:233). |
| `flow_overrides() -> impl Iterator` | All flow overrides. |
| `is_empty() -> bool` | Any overrides at all. |
| `generate_deadcode_delay_message(space_name) -> String` | (override.cc:51). |
| `generate_override_messages(space_names) -> Vec<String>` | (override.cc:279). |
| `print_raw(space_names) -> Vec<String>` | Debug dump (override.cc:248). |

## L3 gaps
- XML `encode`/`decode` of the `<override>` element (override.cc:294, 356) —
  pending Encoder/Decoder infrastructure.
- FuncProto ownership in `insertProtoOverride` — pending fspec integration.

## 2026-06-27（续）：apply_force_gotos CFG 集成

- `apply_force_gotos(fd: &mut Funcdata) -> usize`（override.cc:204）：将所有 force-goto 覆写推入函数，调用 `fd.force_goto`。返回成功应用的覆写数。解锁 jumptable.rs 的 CFG 重写 L3 缺口。

## 2026-06-27（续 2）：XML encode/decode 完成 — override.rs 达到 L3

**Override 新增方法**：
- `encode(encoder)`（override.cc:294）：编码 `<override>` 根元素 + 所有子命令：
  - `<forcegoto>` + 两个 `<addr>` 子元素
  - `<deadcodedelay>` + space/delay 属性
  - `<indirectoverride>` + 两个 `<addr>` 子元素
  - `<protooverride>` + `<addr>` 子元素
  - `<multistagejump>` + `<addr>` 子元素
  - `<flow type="...">` + `<addr>` 子元素
- `decode(decoder)`（override.cc:356）：解码完整 `<override>` 元素（按 element_name 分发）。
- 空覆写不写入任何内容（与 Ghidra 一致）。

辅助函数：`read_one_addr(decoder) -> Option<Address>` + `read_two_addrs(decoder)`。

测试：新增 2 个（encode/decode round-trip + empty encode）。override.rs 所有 L3 缺口已关闭。
<!-- annotation-pass: 2026-07-04 -->

## 2026-08-24：FlowOverride worker transport

`FlowOverride` 增加 serde 编解码，用于隔离 worker 的 out-of-band 元数据；新增
`FlowOverrideRecord { function_address, override_address, flow_type }`。该记录是锁定
`Architecture::decodeFlowOverride`（`architecture.cc:451-469`）中每条
`<flowoverridelist>` 的标量地址投影：函数入口、override 指令地址、类型。当前
worker 协议只传数值 offset，接收端仍用 `Address::new` 物化为 null-base，并未重新
附着 Ghidra 的 RAM space（`ADDRESS-PHASE2-CLOSURE-0001`）。写入
`Funcdata::localoverride` 前会强制 `function_address == target.entry`、拒绝 NONE、
保留同值重复并拒绝异值冲突。

来源必须显式区分：Program 中的记录由 Java Shared Return Calls analyzer 持久化；
standalone curl driver 只生成地址驱动的唯一 ELF owner/direct-known-entry 子集。
`FlowOverrideRecord` 不表示完整 Program Reference/Function body/analysis options，也
不扩展 `Override` 本身的语义。`flow_sharedreturn_process_1204` metadata/runner 将完整
Program producer 分支记为 `UNTESTED`，并因 callspec 指针身份残差保持 overall
`MISMATCH`；本文早期的模块级 L3 表述不能覆盖这些新接入的生产行为。
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
