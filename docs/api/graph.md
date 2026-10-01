# `graph.rs` API Reference

**状态**: 已核对（当前有效）
**源代码路径**: `src/graph.rs`

## 模块说明 (Module Doc)

Renoir-format graph serialization.

This module corresponds to Ghidra's `graph.cc` / `graph.hh`. Despite its
name, it is **not** a generic graph-algorithm module (there is no
`NodeID`/`Edge`/topological-sort/SCC/DFS/BFS here — those live in
`callgraph` and `block`). It is a thin **serializer** that dumps the
data-flow graph, control-flow graph, and dominator graph of a function in
the command language understood by the Renoir graph viewer (see the note at
the top of `graph.cc`: *"Serializes graphs in format used by Renoir"*).

All output is written to a `std::fmt::Write` sink, matching Ghidra's use of
`ostream &s`. The text format (columnar `*CMD=*COLUMNAR_INPUT` blocks,
`DefineAttribute` / `AlterLocalPreferences` commands, vertex/edge records)
is reproduced byte-for-byte so output stays consumable by the same tooling.

Corresponds to Ghidra's `graph.hh` / `graph.cc`

## 导出的公共 API (Public API)

### `pub fn dump_dataflow_graph(data: &Funcdata, s: &mut dyn Write)`

Serialize a function's data-flow graph in Renoir format.

Corresponds to Ghidra `dump_dataflow_graph` (graph.cc:195-296). Emits the
`NewGraphWindow` / `*NEXUS` preamble, the AutomaticArrangement /
VertexColors / VertexIcons / VertexLabels preference blocks, the
`DefineAttribute` / `SetKeyAttribute` declarations, and finally the
varnode vertices, op vertices, and edges.

### `pub fn dump_controlflow_graph(name: &str, graph: &BlockGraph, s: &mut dyn Write)`

Serialize a function's control-flow graph in Renoir format.

Corresponds to Ghidra `dump_controlflow_graph` (graph.cc:474-483): emits the
`NewGraphWindow` / `*NEXUS` preamble using `name`, then the shared
properties/attributes and the block vertices (with `falsenode=false`) and
edges.

### `pub fn dump_dom_graph(name: &str, graph: &BlockGraph, s: &mut dyn Write)`

Serialize a function's dominator graph in Renoir format.

Corresponds to Ghidra `dump_dom_graph` (graph.cc:485-500). Computes whether a
synthetic "false node" is needed: if more than one block has no immediate
dominator, the false node (`-1`) is used as a shared root so every block is
reachable from some source.

### `pub fn dump_dataflow_graph_string(data: &Funcdata) -> String`

Convenience wrapper around `dump_dataflow_graph` that returns a `String`.

### `pub fn dump_controlflow_graph_string(name: &str, graph: &BlockGraph) -> String`

RUGRA-GLUE：Ghidra 通过 `ostream` 接收结果；此函数只新建 `String` sink 并
原样转发给 `dump_controlflow_graph`。

### `pub fn dump_dom_graph_string(name: &str, graph: &BlockGraph) -> String`

RUGRA-GLUE：Ghidra 通过 `ostream` 接收结果；此函数只新建 `String` sink 并
原样转发给 `dump_dom_graph`。

## 内部辅助函数 (Private Helpers)

以下函数与 Ghidra `graph.cc` 中的 `static` 辅助函数一一对应，行号标注在源码注释中：

| Rust 函数                  | Ghidra (graph.cc)           | 说明                                  |
|----------------------------|-----------------------------|---------------------------------------|
| `print_varnode_vertex`     | :21 `print_varnode_vertex`  | 单个 varnode 顶点记录                 |
| `print_op_vertex`          | :47 `print_op_vertex`       | 单个 PcodeOp 顶点记录                 |
| `op_input_window`          | (重构自 :89-103/:150-164)   | 按操作码计算输入槽位窗口 `(start,stop)`|
| `dump_varnode_vertex`      | :68 `dump_varnode_vertex`   | 所有 varnode 顶点                     |
| `dump_op_vertex`           | :117 `dump_op_vertex`       | 所有 PcodeOp 顶点                     |
| `print_edges`              | :141 `print_edges`          | 单个 PcodeOp 的数据流边               |
| `dump_edges`               | :173 `dump_edges`           | 所有数据流边                          |
| `print_block_vertex`       | :298 `print_block_vertex`   | 单个基本块顶点记录                     |
| `print_block_edge`         | :309 `print_block_edge`     | 单个基本块入边                         |
| `dump_block_vertex`        | :316 `dump_block_vertex`    | 所有基本块顶点（含可选 false node）    |
| `dump_block_edges`         | :337 `dump_block_edges`     | 所有控制流边                           |
| `print_dom_edge`           | :352 `print_dom_edge`       | 单个基本块的支配边                     |
| `dump_dom_edges`           | :363 `dump_dom_edges`       | 所有支配边                             |
| `dump_block_attributes`    | :378 `dump_block_attributes`| `DefineAttribute`/`SetKeyAttribute` 声明 |
| `dump_block_properties`    | :412 `dump_block_properties`| AutomaticArrangement/VertexColors 等偏好 |
| `is_fspec_space`           | (RUGRA-GLUE)                | `IPTR_FSPEC` 占位：Rugra 未建模 Fspec 空间，恒返回 `false` |
| `block_stop_addr`          | (RUGRA-GLUE)                | `FlowBlock::getStop()` 近似：`BlockBasic` 用真实 stop，否则用 start |

## 类型映射 (Mapping Notes)

| Ghidra (graph.cc)               | Rugra                                    |
|---------------------------------|------------------------------------------|
| `ostream &s`                    | `&mut dyn std::fmt::Write`               |
| `vn->isMark()` / `setMark()`    | `Varnode::is_mark()` / `set_mark()`      |
| `spc->getType()` vs `IPTR_*`    | `AddressSpace` enum + `is_iop()`/etc.    |
| `op->getTime()`                 | `PcodeOp::get_time()`                    |
| `op->getAddr().getOffset()`     | `PcodeOp::get_addr().as_u64()`           |
| `vn->getCreateIndex()`          | `Varnode::get_create_index()`            |
| `vn->printRawNoMarkup(s)`       | `Varnode::print_raw_no_markup()`         |
| `graph.getSize()` / `getBlock`  | `BlockGraph::get_size()` / `get_block()` |
| `bl->getImmedDom()`             | `FlowBlock::get_immed_dom()`             |
| `data.beginOpAlive()/endOpAlive()` | `Funcdata::obank.alivelist`           |

## 注意事项 (Caveats)

- **`IPTR_FSPEC` 未建模**：Rugra 的 `AddressSpace` 没有 Fspec 变体（见
  `space.rs`），因此 `is_fspec_space()` 恒返回 `false`。这只影响 Renoir
  顶点的过滤（跳过 FSPEC 空间的 varnode），对实际数据流无影响。
- **`FlowBlock::getStop()` 近似**：`FlowBlock` trait 未暴露 stop 地址，
  `block_stop_addr()` 对 `BlockBasic` downcast 取真实 stop，其余结构化块
  回退到 start 地址（Ghidra 基类 `getStop()` 本就会抛错）。仅影响顶点
  标签，不影响控制流。

## 测试 (Tests)

模块内含单元测试（`#[cfg(test)]`）：

- `test_dump_block_attributes_renders_verbatim` — 验证属性声明文本逐字渲染
- `test_dump_block_properties_renders_verbatim` — 验证偏好块文本逐字渲染
- `test_op_input_window` — 验证 LOAD/STORE/BRANCH/CALL/INDIRECT 的输入窗口
- `test_is_fspec_space_is_false` — 验证 FSPEC 占位始终为 false

<!-- annotation-pass: 2026-07-22 -->
## 2026-09-30：op 链迭代面机械迁移（PERF-ARENA-FLIP-0001 (b)）

`fd.obank.{alivelist,deadlist,storelist,loadlist,returnlist,useroplist}`
的 Vec 迭代/克隆消费位随 PcodeOpBank 7 链 IdList 翻转机械改写为 bank 链
API（`iter_alive()/iter_dead()/iter_store()...` 与 `.cloned().collect()`），
迭代序与语义恒等（链序=原 Vec 序=oracle 列表序）；测试面裸
`alivelist.push` 改 `adopt_alive_op`（bank API，单链不变量保持）。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。
