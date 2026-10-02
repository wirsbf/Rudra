# options.rs — Architecture configuration options API

## 2026-09-27：PRINTC-PRINTLIST-WIRING-0001 — OptionCommentStyle 接通真路由（Lane PCHOVER2）

`OptionCommentStyle::apply`（options.cc:523-527）此前只返回确认消息不触
printer（PRINTC0004 登记 handover：Architecture 无 printlist）。现忠实路由
options.cc:526 `glb->print->setCommentStyle(p1)`：经
`Architecture::print_language_current()`（architecture.hh:205/206 存储镜像，
见 arch.md/printlanguage.md 同日节）取当前 printer 施加。

- 成功：`"Comment style set to {p1}"`（options.cc:527 逐字）。
- 未知风格：`"LowlevelError: Unknown comment style. Use \"c\" or \"cplusplus\""`
  （printc.cc:2359-2360 的 throw 以本文件既定前缀约定承载）。
- 未注册 printer（oracle ctor 建有 printer、此态 Ghidra 不可表）：
  `"LowlevelError: no print language registered with the architecture"`——
  如实上报结构性状态，不静默成功。

B2：`printc_printlist_wiring_1204`（8 case 字节恒等，oracle/Rust 同 production
apply 体；msg/threw/render 三投影）。

Partial port of Ghidra's `options.hh` / `options.cc` (1063 lines).

**Status:** L2 / `MISMATCH` and `NO_ORACLE`. The `ArchOption` trait and an
`OptionDatabase` dispatcher exist, but the 2026-08-11 audit found protocol,
validation, registration-order, and state-mutation differences.
Every option carries per-function `// Ghidra: options.hh/options.cc:<line>`
mapping comments.
Some options mutate Rugra `Architecture` state. Options targeting missing
subsystems generally return a confirmation string without performing the
corresponding Ghidra state transition.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/options.{hh,cc}`.

> **ANN-A annotation audit (2026-08-11):** This pass only added source-mapping
> comments for the 44 functions reported by the annotation checker. It made no
> runtime behavior change, produced no oracle `MATCH` evidence, and does not
> upgrade or independently validate the module's alignment status.

## Free functions
- `on_or_off(p) -> bool` — parse "on"/"off"/empty string. Empty defaults to
  true, but Rugra currently accepts other values while Ghidra throws
  `ParseError` (`OPTIONS-0001`).
- `parse_int_any_base(s) -> Option<i64>` — replicate `std::istringstream`
  basefield-reset semantics: `0x..`→hex, leading `0`→octal, else decimal.
  Sign aware. `// RUDRA-GLUE` (no Ghidra counterpart; C++ uses streams).
- `parse_uint_any_base(s) -> Option<u64>` — unsigned variant.
- `alias_block_flag(name) -> Option<i32>` — Rugra symbolic token → bit mask.
  This accepts tokens and combinations not present in Ghidra's four-level
  `none/struct/array/all` model (`OPTIONS-0001`).
- `get_option_bit(val) -> Result<u32, String>` — translate a split-datatype
  option token to its configuration bit, faithful to
  `OptionSplitDatatypes::getOptionBit` (options.cc:982-990): `""`→0,
  `"struct"`→1, `"array"`→2, `"pointer"`→4; any other token is
  `LowlevelError("Unknown data-type split option: <val>")`, carried as `Err`
  with the same message text.
- `split_action_toggles(config) -> (bool, bool)` — the (splitcopy,
  splitpointer) on/off pair that `OptionSplitDatatypes::apply` passes to
  `ActionDatabase::toggleAction` (options.cc:1007-1016): both off unless the
  struct or array bit is set; otherwise splitcopy on and splitpointer =
  pointer bit. `// RUDRA-GLUE` decomposition of Ghidra's inline if/else;
  since OPTIONS-SPLITDATATYPE-WIRING-0003 (2026-08-25) `apply` forwards the
  pair through `arch.allacts.toggle_action(get_current_name(), ...)`
  directly — `getCurrentName()` is snapshotted once because `toggleAction`
  never renames the current root (action.cc:1049/1024).

## Module `elem_ids`
`<optionslist>` XML element ids. Rugra currently holds private `u32` values;
these do not match the locked wire IDs and depend on `MARSHAL-ID-0001`.
- `ELEM_OPTIONSBODY = 174`, `ELEM_OPTIONSHEAD = 175`, `ELEM_OPTIONSLIST = 176`,
  `ELEM_PARAM1 = 177`, `ELEM_PARAM2 = 178`, `ELEM_PARAM3 = 179`.

## Trait `ArchOption`
Base trait for options (options.hh:75).
- `name() -> &str`
- `apply(arch, p1, p2, p3) -> String` — modify Architecture, return message.

## `OptionDatabase`
Dispatcher for ArchOption commands (options.hh:106). The C++ class keys its
map by element id (`uint4`); rugra keys by name string because the `Decoder`
trait resolves element ids to names.
- `new()` / `default()` — register all 38 built-in options in the order
  Ghidra's constructor uses (options.cc:96-133).
- `register<O: ArchOption>(opt)` — insert one option. Mirrors
  `registerOption` (options.cc:84).
- `set(arch, name, p1, p2, p3) -> Option<String>` — execute an option
  command. Returns `None` for unknown options, whereas Ghidra throws
  `ParseError` (`OPTIONS-0001`).
- `try_set(...) -> Result<String, String>` — non-panicking variant
  (`// RUDRA-GLUE`).
- `has_option(name) -> bool`, `num_options() -> usize`,
  `option_names() -> Vec<String>` (`// RUDRA-GLUE`).
- `decode_one(arch, decoder) -> Result<(), String>` — decode one
  `<optionslist>` entry. Faithful to `OptionDatabase::decodeOne`
  (options.cc:163). Linearly scans `ELEM_PARAM1`/`ELEM_PARAM2`/`ELEM_PARAM3`
  children as Ghidra does.
- `decode(arch, decoder) -> Result<(), String>` — decode the
  `<optionslist>` block. Faithful to `OptionDatabase::decode`
  (options.cc:192).

## Implemented option surfaces (not oracle-verified)
| Option | Field | Effect |
|---|---|---|
| `inferconstptr` | `infer_pointers` | Toggle pointer inference |
| `analyzeforloops` | `analyze_for_loops` | Toggle for-loop recovery |
| `readonly` | `readonlypropagate` | Toggle readonly propagation |
| `jumptablemax` | `max_jumptable_size` | Set max jumptable entries |
| `maxinstruction` | `max_instructions` | Set max instructions/function |
| `aliasblock` | `alias_block_level` | Set alias blocking (none/struct/array/.../all) |
| `nanignore` | `nan_ignore_all`/`nan_ignore_compare` | Set NaN ignore mode (all/none/compare/input) |
| `splitdatatype` | `split_datatype_config` | OR struct(1)/array(2)/pointer(4) bits from up to 3 params; toggles splitcopy/splitpointer groups (options.cc:999-1022) |
| `defaultprototype` | `defaultfp_name` | Set default proto model via `set_default_model` |
| `protoeval` | `evalfp_current_name` | Set prototype eval model ("default" resets) |
| `ignoreunimplemented` | `flowoptions & IGNORE_UNIMPLEMENTED` | Toggle flow flag |
| `errorunimplemented` | `flowoptions & ERROR_UNIMPLEMENTED` | Toggle flow flag |
| `errorreinterpreted` | `flowoptions & ERROR_REINTERPRETED` | Toggle flow flag |
| `errortoomanyinstructions` | `flowoptions & ERROR_TOOMANYINSTRUCTIONS` | Toggle flow flag |
| `jumpload` | `flowoptions & RECORD_JUMPLOADS` | Toggle flow flag |
| `extrapop` | (deferred) | Parses int / "unknown"; ProtoModelEntry lacks extrapop field |

## Message-only options (target subsystems not yet ported)
These return a confirmation string but do not yet perform all Ghidra state
mutations. They remain gaps tracked by `OPTIONS-0001`.

- **PrintLanguage options** (require emitter integration):
  `nullprinting`, `inplaceops`, `conventionprinting`, `nocastprinting`,
  `hideextensions`, `maxlinewidth`, `indentincrement`, `commentindent`,
  `commentstyle`, `commentheader`, `commentinstruction`, `integerformat`,
  `braceformat`, `setlanguage`, `namespacestrategy`.
- **ActionDatabase options** (require `setCurrent`/`enableSubRule`):
  `setaction`, `currentaction`, `togglerule`, `warning`.
- **ContextDatabase option** (require `ContextCache::allowSet`):
  `allowcontextset`.
- **Function-property options** (require `queryFunction`): `inline`,
  `noreturn`.

## Tests
26 unit tests under `options::tests` covering: default registry contents,
every flow-flag toggle, alias-block combination, split-datatype config,
NaN-ignore modes, integer-format/brace-format messages, set/current/toggle
action messages, allowcontextset, protoeval unknown/default, unknown-option
rejection, and `parse_int_any_base`/`parse_uint_any_base` hex/octal/decimal
parsing. Run with `cargo test --lib options::`.

## Coverage status

The previous L3 claim is withdrawn. No locked 12.0.4 same-input fixture covers
the dispatcher, XML protocol, validation failures, registration order, or all
state mutations. Passing Rust unit tests therefore remains regression evidence,
not parity evidence.

## Remaining gaps
- `OptionExtraPop` parses its parameter but cannot store it —
  `ProtoModelEntry` has no `extrapop` field.
- PrintLanguage / ActionDatabase / ContextCache / function-lookup hooks.
- `nullprinting` name differs from Rugra's registered spelling; the option
  element IDs and registration set/order differ elsewhere (`OPTIONS-0001`).
- Invalid toggles, numeric bounds, alias levels, NaN rule toggles, and
  `decode_one` error propagation differ from Ghidra (`OPTIONS-0001`).
- `OptionSplitDatatypes` (fixed 2026-08-24, `OPTIONS-SPLITDATATYPE-SEMANTICS-0001`):
  bit semantics struct/array/pointer (1/2/4), singular option name, p1-assign
  p2/p3-OR evaluation order, partial-mutation-on-error, return messages, and
  the toggleAction decision logic are ported and oracle-verified via
  `tests/oracle/options_splitdatatype_1204.*`; the (splitcopy, splitpointer)
  pair is now applied to the current root's `ActionGroupList` through
  `arch.allacts.toggle_action` inside `apply` (OPTIONS-SPLITDATATYPE-WIRING-0003,
  2026-08-25; oracle-verified by `tests/oracle/options_wiring_1204.*` whose
  comparand is a direct production `apply` call). Residual:
  `LowlevelError` on unknown tokens is carried as the returned message string
  rather than a thrown error (`ArchOption::apply` returns `String`), and a
  `None` `allacts` (pre-`build_action` Architecture, unrepresentable in
  Ghidra) skips the toggles.
<!-- annotation-pass: 2026-08-11 (ANN-A, mapping comments only) -->


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 15 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
