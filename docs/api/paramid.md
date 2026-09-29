# paramid.rs — Parameter identification API

Faithful port of Ghidra's `paramid.hh` / `paramid.cc` (284 lines).

**Status:** L1 → L2. Complete ParamMeasure + ParamRank + ParamIDAnalysis with
forward/backward data-flow walks. L3 gap: full Funcdata integration (prototype
parameter extraction, RETURN op iteration) + isLoopIn check for MULTIEQUAL.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/paramid.{hh,cc}`.

## Structs

### `ParamRank(pub i32)`
Parameter rank (paramid.hh:33). Uses i32 to allow duplicate ranks as in Ghidra.
- Constants: `BEST(1)`, `DIRECT_WRITE_WITHOUT_READ(1)`, `DIRECT_READ(2)`,
  `DIRECT_WRITE_WITH_READ(2)`, `DIRECT_WRITE_UNKNOWN_READ(3)`,
  `SUB_FN_PARAM(4)`, `THIS_FN_PARAM(4)`, `SUB_FN_RETURN(5)`,
  `THIS_FN_RETURN(5)`, `INDIRECT(6)`, `WORST(7)`.
- `as_i32() -> i32`.

### `ParamIdIo`
- `Input = 0`, `Output = 1`.

### `WalkState`
- Fields: `best`, `depth`, `terminal_rank`.

### `ParamMeasure`
Measure of parameter likelihood (paramid.hh:27).
- `new(addr, space, sz, type_name, io)`.
- `walk_forward(state, ignore_op, vn)` — classify input usage (paramid.cc:37).
- `walk_backward(state, ignore_op, vn)` — classify output usage (paramid.cc:90).
- `calculate_rank(best, base_vn, ignore_op)` — main entry (paramid.cc:141).
- `get_measure() -> i32`.

### `ParamIDAnalysis`
Parameter ID analysis for a function (paramid.hh:70).
- `new()`, `add_input(pm)`, `add_output(pm)`, `num_inputs()`, `num_outputs()`.
- `save_pretty() -> String` (paramid.cc:264).

## L3 gaps
- Funcdata integration: prototype parameter extraction, RETURN op iteration.
- `isLoopIn` check for MULTIEQUAL loops in walk_forward/walk_backward.
- XML encode (`<parammeasures>`/`<proto>`/`<rank>`).

## 2026-06-27（续）：ParamIDAnalysis::analyze — Funcdata 集成

- **ParamIDAnalysis::analyze(fd)**：完整 Funcdata 集成——遍历 VarnodeBank 输入 Varnodes，为每个创建 ParamMeasure 并调用 calculate_rank 进行数据流分类。同时扫描 RETURN ops 的返回值创建 output ParamMeasure。不再是纯数据结构——现在可以在实际函数上执行参数识别分析。
<!-- annotation-pass: 2026-07-04 -->
## 2026-09-30：op 链迭代面机械迁移（PERF-ARENA-FLIP-0001 (b)）

`fd.obank.{alivelist,deadlist,storelist,loadlist,returnlist,useroplist}`
的 Vec 迭代/克隆消费位随 PcodeOpBank 7 链 IdList 翻转机械改写为 bank 链
API（`iter_alive()/iter_dead()/iter_store()...` 与 `.cloned().collect()`），
迭代序与语义恒等（链序=原 Vec 序=oracle 列表序）；测试面裸
`alivelist.push` 改 `adopt_alive_op`（bank API，单链不变量保持）。
