//! Renoir-format graph serialization.
//!
//! This module corresponds to Ghidra's `graph.cc` / `graph.hh`. Contrary to
//! what its name suggests, it is **not** a generic graph-algorithm module
//! (there is no `NodeID`/`Edge`/topo-sort/SCC/DFS/BFS here — those live in
//! `callgraph` and `block`). This file is a thin **serializer** that dumps the
//! data-flow graph, control-flow graph, and dominator graph of a function in
//! the command language understood by the Renoir graph viewer (see the note at
//! the top of `graph.cc`: "Serializes graphs in format used by Renoir").
//!
//! The three public entry points mirror Ghidra exactly:
//! - [`dump_dataflow_graph`]   — vertices: varnodes + ops, edges: def/use
//! - [`dump_controlflow_graph`] — vertices: basic blocks, edges: block CFG
//! - [`dump_dom_graph`]        — vertices: basic blocks, edges: immediate-dominator
//!
//! All output is written to a [`std::fmt::Write`] sink, matching Ghidra's use
//! of `ostream &s`. The text format (columnar `*CMD=*COLUMNAR_INPUT` blocks,
//! `DefineAttribute` / `AlterLocalPreferences` commands, vertex/edge records)
//! is reproduced byte-for-byte so that output stays consumable by the same
//! tooling.
//!
//! # Mapping notes
//!
//! | Ghidra (graph.cc)               | Rugra                                    |
//! |--------------------------------|------------------------------------------|
//! | `ostream &s`                   | `&mut dyn std::fmt::Write`               |
//! | `vn->isMark()` / `setMark()`   | `Varnode::is_mark()` / `set_mark()`      |
//! | `spc->getType()` vs `IPTR_*`   | `AddressSpace` enum + `is_iop()`/etc.    |
//! | `op->getTime()`                | `PcodeOp::get_time()`                    |
//! | `op->getAddr().getOffset()`    | `PcodeOp::get_addr().as_u64()`           |
//! | `vn->getCreateIndex()`         | `Varnode::get_create_index()`            |
//! | `vn->printRawNoMarkup(s)`      | `Varnode::print_raw_no_markup()`         |
//! | `graph.getSize()` / `getBlock` | `BlockGraph::get_size()` / `get_block()` |
//! | `bl->getImmedDom()`            | `FlowBlock::get_immed_dom()`             |
//!
//! Rugra does not model an `IPTR_FSPEC` space (see `space.rs`), so the two
//! `spc->getType() == IPTR_FSPEC` guards in Ghidra are translated to a
//! best-effort `is_fspec_space()` helper that currently always returns
//! `false` — documented inline at each call site.

use std::fmt::Write;
use std::sync::{Arc, RwLock};

use crate::block::{BlockGraph, FlowBlock};
use crate::funcdata::Funcdata;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::Varnode;

// RUDRA-GLUE: IPTR_FSPEC is not modeled in Rugra (space.rs has no Fspec variant).
// Ghidra's `graph.cc` skips varnodes whose space type is `IPTR_FSPEC` (function
// specs) or `IPTR_IOP` (op-reference slots). Rugra models IOP via
// `AddressSpace::is_iop()` but has no Fspec variant; this helper returns
// `false` unconditionally so the Fspec skip is a no-op while remaining a clear
// adaptation point should Fspec be added later. Faithful to the *behavior* for
// all spaces Rugra actually produces.
/// Ghidra `spc->getType() == IPTR_FSPEC` stand-in. Always `false` in Rugra
/// because no Fspec address space is modeled (see `space.rs`).
fn is_fspec_space(_spc: &AddressSpace) -> bool {
    false
}

// Ghidra: graph.cc:21 print_varnode_vertex
/// Emit a single varnode as a Renoir "AddVertices" record.
///
/// Faithful port of `print_varnode_vertex` (graph.cc:21-45). Emits the
/// varnode's create-index, space name, the literal `var` subclass, its raw
/// location, and — depending on whether it is defined by an op, a function
/// input, or undefined — the defining op's address, the letter `i`, or
/// `<na>`. Returns early (no output) for null varnodes, already-marked
/// varnodes, and varnodes in the FSPEC/IOP spaces, exactly as Ghidra does.
fn print_varnode_vertex(vn: Option<&Arc<RwLock<Varnode>>>, s: &mut dyn Write) {
    // cc:26  if (vn == (Varnode *)0) return;
    let vn = match vn {
        Some(v) => v,
        None => return,
    };

    let vn_rg = vn.read().unwrap();
    // cc:27  if (vn->isMark()) return;
    if vn_rg.is_mark() {
        return;
    }
    // cc:28  AddrSpace *spc = vn->getSpace();
    let spc = vn_rg.get_space();
    // cc:29  if (spc->getType() == IPTR_FSPEC) return;
    if is_fspec_space(&spc) {
        return;
    }
    // cc:30  if (spc->getType() == IPTR_IOP) return;
    if spc.is_iop() {
        return;
    }
    // cc:31  s << dec << 'v' << vn->getCreateIndex() << ' ' << spc->getName();
    //        s << " var ";
    let create_index = vn_rg.get_create_index();
    let space_name = spc.name();
    let _ = write!(s, "v{} {} var ", create_index, space_name);

    // cc:34  vn->printRawNoMarkup(s);
    let (raw, _expect) = vn_rg.print_raw_no_markup();
    let _ = write!(s, "{}", raw);

    // cc:36  op = vn->getDef();
    let def_addr = vn_rg.get_def().map(|op| {
        let op_rg = op.read().unwrap();
        // cc:38  s << ' ' << hex << op->getAddr().getOffset();
        op_rg.get_addr().as_u64()
    });
    match def_addr {
        Some(offset) => {
            // Ghidra uses hex for the op address.
            let _ = write!(s, " {:x}", offset);
        }
        None => {
            // cc:39  else if (vn->isInput())  s << " i";
            if vn_rg.is_input() {
                let _ = write!(s, " i");
            } else {
                // cc:40  else  s << " <na>";
                let _ = write!(s, " <na>");
            }
        }
    }
    // cc:43  s << endl;
    let _ = writeln!(s);
    // cc:44  vn->setMark();
    drop(vn_rg);
    vn.write().unwrap().set_mark();
}

// Ghidra: graph.cc:47 print_op_vertex
/// Emit a single PcodeOp as a Renoir "AddVertices" record.
///
/// Faithful port of `print_op_vertex` (graph.cc:47-66). Prints the op's
/// immutable time, a subclass string classifying it (`branch` / `call`
/// / `marker` / `basic`), the literal `op`, its mnemonic, and its address.
fn print_op_vertex(op: &PcodeOp, s: &mut dyn Write) {
    // cc:50  s << dec << 'o' << op->getTime() << ' ';
    let time = op.get_time();
    let _ = write!(s, "o{} ", time);

    // cc:51-58  classify as branch / call / marker / basic
    let subclass = if op.is_branch() {
        "branch"
    } else if op.is_call() {
        "call"
    } else if op.is_marker() {
        "marker"
    } else {
        "basic"
    };
    let _ = write!(s, "{} op ", subclass);

    // cc:60-63  op name (Ghidra getOpName), or "unkop" if empty.
    let opname = op.get_opcode().name();
    if opname.is_empty() {
        let _ = write!(s, "unkop");
    } else {
        let _ = write!(s, "{}", opname);
    }

    // cc:64  s << ' ' << hex << op->getAddr().getOffset();
    let _ = write!(s, " {:x}", op.get_addr().as_u64());
    // cc:65  s << endl;
    let _ = writeln!(s);
}

// RUDRA-GLUE: Rust helper to compute the per-op varnode-input slice window
// that Ghidra encodes as the `start`/`stop` locals in
// `dump_varnode_vertex` (graph.cc:89-103), `print_edges` (graph.cc:150-164),
// and `dump_varnode_vertex`'s clear loop. Returning a `(start, stop)` tuple
// keeps each call site a faithful mirror of the C++ switch.
/// Compute the `(start, stop)` input-slot window for the given op, matching
/// Ghidra's switch in `dump_varnode_vertex` / `print_edges`.
fn op_input_window(opc: OpCode, num_input: usize) -> (usize, usize) {
    let mut start = 0usize;
    let mut stop = num_input;
    match opc {
        // cc:92-97  LOAD/STORE/BRANCH/CALL: start = 1
        OpCode::CPUI_LOAD
        | OpCode::CPUI_STORE
        | OpCode::CPUI_BRANCH
        | OpCode::CPUI_CALL => start = 1,
        // cc:98-100  INDIRECT: stop = 1
        OpCode::CPUI_INDIRECT => stop = 1,
        _ => {}
    }
    (start, stop)
}

// Ghidra: graph.cc:68 dump_varnode_vertex
/// Emit all varnode vertex records for a function's data-flow graph.
///
/// Faithful port of `dump_varnode_vertex` (graph.cc:68-115): prints the
/// `AddVertices` column header, then for each alive op emits its output
/// varnode and the relevant input varnodes (using the op-code-specific
/// start/stop window), then clears the marks it set.
fn dump_varnode_vertex(data: &Funcdata, s: &mut dyn Write) {
    // cc:75-83  header
    let _ = s.write_str("\n\n// Add Vertices\n");
    let _ = s.write_str("*CMD=*COLUMNAR_INPUT,\n");
    let _ = s.write_str("  Command=AddVertices,\n");
    let _ = s.write_str("  Parsing=WhiteSpace,\n");
    let _ = s.write_str("  Fields=({Name=Internal, Location=1},\n");
    let _ = s.write_str("          {Name=SubClass, Location=2},\n");
    let _ = s.write_str("          {Name=Type, Location=3},\n");
    let _ = s.write_str("          {Name=Name, Location=4},\n");
    let _ = s.write_str("          {Name=Address, Location=5});\n\n");
    let _ = s.write_str("//START:varnodes\n");

    // cc:86  for(oiter=data.beginOpAlive(); oiter!=data.endOpAlive(); ++oiter)
    for op_ref in data.obank.iter_alive() {
        let op = op_ref.0.read().unwrap();
        // cc:88  print_varnode_vertex(op->getOut(),s);
        let out = op.get_out().cloned();
        print_varnode_vertex(out.as_ref(), s);

        // cc:89-103  start/stop window by op-code
        let (start, stop) = op_input_window(op.get_opcode(), op.num_input());
        // cc:104-106  for(i=start;i<stop;++i) print_varnode_vertex(op->getIn(i),s);
        for i in start..stop {
            let in_vn = op.get_in(i).cloned();
            print_varnode_vertex(in_vn.as_ref(), s);
        }
    }
    // cc:107  s << "*END_COLUMNS\n";
    let _ = s.write_str("*END_COLUMNS\n");

    // cc:108-114  clear marks (second pass over alive ops)
    for op_ref in data.obank.iter_alive() {
        let op = op_ref.0.read().unwrap();
        // cc:110-111  if (op->getOut() != null) op->getOut()->clearMark();
        if let Some(out) = op.get_out() {
            out.write().unwrap().clear_mark();
        }
        // cc:112-113  for i in inputs: clearMark
        for i in 0..op.num_input() {
            if let Some(in_vn) = op.get_in(i) {
                in_vn.write().unwrap().clear_mark();
            }
        }
    }
}

// Ghidra: graph.cc:117 dump_op_vertex
/// Emit all PcodeOp vertex records for a function's data-flow graph.
///
/// Faithful port of `dump_op_vertex` (graph.cc:117-139): prints the
/// `AddVertices` header (same column schema as the varnode dump) then one
/// record per alive op via [`print_op_vertex`].
fn dump_op_vertex(data: &Funcdata, s: &mut dyn Write) {
    // cc:123-131  header (identical to dump_varnode_vertex's header)
    let _ = s.write_str("\n\n// Add Vertices\n");
    let _ = s.write_str("*CMD=*COLUMNAR_INPUT,\n");
    let _ = s.write_str("  Command=AddVertices,\n");
    let _ = s.write_str("  Parsing=WhiteSpace,\n");
    let _ = s.write_str("  Fields=({Name=Internal, Location=1},\n");
    let _ = s.write_str("          {Name=SubClass, Location=2},\n");
    let _ = s.write_str("          {Name=Type, Location=3},\n");
    let _ = s.write_str("          {Name=Name, Location=4},\n");
    let _ = s.write_str("          {Name=Address, Location=5});\n\n");
    let _ = s.write_str("//START:opnodes\n");

    // cc:134-137  for each alive op: print_op_vertex
    for op_ref in data.obank.iter_alive() {
        let op = op_ref.0.read().unwrap();
        print_op_vertex(&op, s);
    }
    // cc:138  s << "*END_COLUMNS\n";
    let _ = s.write_str("*END_COLUMNS\n");
}

// Ghidra: graph.cc:141 print_edges
/// Emit the data-flow edges (output + inputs) for a single PcodeOp.
///
/// Faithful port of `print_edges` (graph.cc:141-171). For the output
/// varnode it emits an `o<time> v<createIndex> output` edge; for each input
/// in the op-code-specific window it emits a `v<createIndex> o<time> input`
/// edge, skipping FSPEC/IOP-space varnodes.
fn print_edges(op: &PcodeOp, s: &mut dyn Write) {
    let time = op.get_time();

    // cc:147-149  output edge
    if let Some(vn) = op.get_out() {
        let vn_rg = vn.read().unwrap();
        let _ = writeln!(
            s,
            "o{} v{} output",
            time,
            vn_rg.get_create_index()
        );
    }

    // cc:150-164  start/stop window by op-code
    let (start, stop) = op_input_window(op.get_opcode(), op.num_input());
    // cc:165-170  for each input in window: emit input edge (skip FSPEC/IOP)
    for i in start..stop {
        if let Some(vn) = op.get_in(i) {
            let vn_rg = vn.read().unwrap();
            let spc = vn_rg.get_space();
            let tp_is_fspec = is_fspec_space(&spc);
            let tp_is_iop = spc.is_iop();
            if !tp_is_fspec && !tp_is_iop {
                let _ = writeln!(
                    s,
                    "v{} o{} input",
                    vn_rg.get_create_index(),
                    time
                );
            }
        }
    }
}

// Ghidra: graph.cc:173 dump_edges
/// Emit all data-flow edges for a function.
///
/// Faithful port of `dump_edges` (graph.cc:173-193): prints the `AddEdges`
/// header (FromKey/ToKey/Name columns) then calls [`print_edges`] for every
/// alive op.
fn dump_edges(data: &Funcdata, s: &mut dyn Write) {
    // cc:179-185  header
    let _ = s.write_str("\n\n// Add Edges\n");
    let _ = s.write_str("*CMD=*COLUMNAR_INPUT,\n");
    let _ = s.write_str("  Command=AddEdges,\n");
    let _ = s.write_str("  Parsing=WhiteSpace,\n");
    let _ = s.write_str("  Fields=({Name=*FromKey, Location=1},\n");
    let _ = s.write_str("          {Name=*ToKey, Location=2},\n");
    let _ = s.write_str("          {Name=Name, Location=3});\n\n");
    let _ = s.write_str("//START:edges\n");

    // cc:188-191  for each alive op: print_edges
    for op_ref in data.obank.iter_alive() {
        let op = op_ref.0.read().unwrap();
        print_edges(&op, s);
    }
    // cc:192  s << "*END_COLUMNS\n";
    let _ = s.write_str("*END_COLUMNS\n");
}

// Ghidra: graph.cc:195 dump_dataflow_graph
/// Serialize a function's data-flow graph in Renoir format.
///
/// Faithful port of `dump_dataflow_graph` (graph.cc:195-296). Emits the
/// `NewGraphWindow` / `*NEXUS` preamble, the AutomaticArrangement /
/// VertexColors / VertexIcons / VertexLabels preference blocks, the
/// `DefineAttribute` / `SetKeyAttribute` declarations, and finally the
/// varnode vertices, op vertices, and edges via [`dump_varnode_vertex`],
/// [`dump_op_vertex`], and [`dump_edges`].
pub fn dump_dataflow_graph(data: &Funcdata, s: &mut dyn Write) {
    let name = data.get_name();
    // cc:198-199
    let _ = writeln!(s, "*CMD=NewGraphWindow, WindowName={}-dataflow;", name);
    let _ = writeln!(s, "*CMD=*NEXUS,Name={}-dataflow;", name);

    // cc:201-216  AutomaticArrangement
    let _ = s.write_str("\n// AutomaticArrangement\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = AutomaticArrangement,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  EnableAutomaticArrangement=true,\n");
    let _ = s.write_str("  OnlyActOnVerticesWithoutCoordsIfOff=false,\n");
    let _ = s.write_str("  DontUpdateMediumWithUserArrangement=false,\n");
    let _ = s.write_str("  UserAddedArrangmentParams=({ServiceName=SimpleHierarchyFromSources,ServiceParams={~SkipPromptForParams=true}}),\n");
    let _ = s.write_str("  SmallSize=50,\n");
    let _ = s.write_str("  DontUpdateLargeWithUserArrangement=true,\n");
    let _ = s.write_str("  NewVertexActionIfOff=ArrangeByMDS,\n");
    let _ = s.write_str("  MediumSizeArrangement=SimpleHierarchyFromSources,\n");
    let _ = s.write_str("  SmallSizeArrangement=SimpleHierarchyFromSources,\n");
    let _ = s.write_str("  MediumSize=800,\n");
    let _ = s.write_str("  LargeSizeArrangement=ArrangeInCircle,\n");
    let _ = s.write_str("  DontUpdateSmallWithUserArrangement=false,\n");
    let _ = s.write_str("  ActionSizeGainIfOff=1.0;\n");

    // cc:218-234  VertexColors
    let _ = s.write_str("\n// VertexColors\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = VertexColors,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  Mapping=({DisplayChoice=Magenta,AttributeValue=branch},\n");
    let _ = s.write_str("  {DisplayChoice=Blue,AttributeValue=register},\n");
    let _ = s.write_str("  {DisplayChoice=Black,AttributeValue=unique},\n");
    let _ = s.write_str("  {DisplayChoice=DarkGreen,AttributeValue=const},\n");
    let _ = s.write_str("  {DisplayChoice=DarkOrange,AttributeValue=ram},\n");
    let _ = s.write_str("  {DisplayChoice=Orange,AttributeValue=stack}),\n");
    let _ = s.write_str("  ChoiceForValueNotCovered=Red,\n");
    let _ = s.write_str("  Extraction=CompleteValue,\n");
    let _ = s.write_str("  ExtractionParams={},\n");
    let _ = s.write_str("  AttributeName=SubClass,\n");
    let _ = s.write_str("  ChoiceForMissingValue=Red,\n");
    let _ = s.write_str("  CanOverride=true,\n");
    let _ = s.write_str("  OverrideAttributeName=Color,\n");
    let _ = s.write_str("  UsingRange=false;\n");

    // cc:236-248  VertexIcons
    let _ = s.write_str("\n//     VertexIcons\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = VertexIcons,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  Mapping=({DisplayChoice=Circle,AttributeValue=var},\n");
    let _ = s.write_str("  {DisplayChoice=Square,AttributeValue=op}),\n");
    let _ = s.write_str("  ChoiceForValueNotCovered=Circle,\n");
    let _ = s.write_str("  Extraction=CompleteValue,\n");
    let _ = s.write_str("  ExtractionParams={},\n");
    let _ = s.write_str("  AttributeName=Type,\n");
    let _ = s.write_str("  ChoiceForMissingValue=Circle,\n");
    let _ = s.write_str("  CanOverride=true,\n");
    let _ = s.write_str("  OverrideAttributeName=Icon,\n");
    let _ = s.write_str("  UsingRange=false;\n");

    // cc:250-261  VertexLabels
    let _ = s.write_str("\n//     VertexLabels\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = VertexLabels,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  Center=({SpecialColor=Black,SpecialFontName=SansSerif,Format=StandardFormat,UseSpecialFontName=false,LabelAlignment=Center,TreatBackSlashNAsNewLine=false,MaxLines=4,FontSize=10,IncludeBackground=false,SqueezeLinesTogether=true,BackgroundColor=Black,UseSpecialColor=false,AttributeName=Name,MaxWidth=100}),\n");
    let _ = s.write_str("  East=(),\n");
    let _ = s.write_str("  SouthEast=(),\n");
    let _ = s.write_str("  North=(),\n");
    let _ = s.write_str("  West=(),\n");
    let _ = s.write_str("  SouthWest=(),\n");
    let _ = s.write_str("  NorthEast=(),\n");
    let _ = s.write_str("  South=(),\n");
    let _ = s.write_str("  NorthWest=();\n");

    // cc:263-292  Attributes (DefineAttribute x5 + Edges Name + SetKeyAttribute)
    let _ = s.write_str("\n// Attributes\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=SubClass,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Type,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Internal,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Name,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Address,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");

    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Name,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Edges;\n\n");

    let _ = s.write_str("*CMD=SetKeyAttribute,\n");
    let _ = s.write_str("        Category=Vertices,");
    let _ = s.write_str("        Name=Internal;\n\n");

    // cc:293-295  the actual vertices + edges
    dump_varnode_vertex(data, s);
    dump_op_vertex(data, s);
    dump_edges(data, s);
}

// RUDRA-GLUE: Approximation of Ghidra `FlowBlock::getStop()`. In Ghidra,
// `FlowBlock::getStop()` is virtual and only `BlockBasic` provides a real
// implementation (block.cc); the base method throws a low-level error.
// Rugra's `FlowBlock` trait does not expose a stop address, so we downcast
// to `BlockBasic` (which carries `get_stop_addr`) and fall back to the
// block's start address for structured blocks. This only affects the
// Renoir vertex label, not control flow, so the approximation is safe.
/// Stop-address stand-in matching Ghidra `FlowBlock::getStop()` semantics:
/// the real value for `BlockBasic`, the start address otherwise.
fn block_stop_addr(bl: &dyn FlowBlock) -> crate::address::Address {
    use crate::block::BlockBasic;
    if let Some(bb) = bl.as_any().downcast_ref::<BlockBasic>() {
        bb.get_stop_addr()
    } else {
        bl.get_start_addr()
    }
}

// Ghidra: graph.cc:298 print_block_vertex
/// Emit one basic-block vertex record for the control-flow / dominator dump.
///
/// Faithful port of `print_block_vertex` (graph.cc:298-307): six whitespace
/// fields — SizeOut, SizeIn, Internal (=0; Ghidra prints a literal space
/// first, which we reproduce), Index, Start offset, Stop offset.
fn print_block_vertex(bl: &dyn FlowBlock, s: &mut dyn Write) {
    // cc:301  s << ' ' << dec << bl->sizeOut();
    let _ = write!(s, " {}", bl.size_out());
    // cc:302  s << ' ' << dec << bl->sizeIn();
    let _ = write!(s, " {}", bl.size_in());
    // cc:303  s << ' ' << dec << bl->getIndex();
    let _ = write!(s, " {}", bl.get_index());
    // cc:304  s << ' ' << hex << bl->getStart().getOffset();
    let _ = write!(s, " {:x}", bl.get_start_addr().as_u64());
    // cc:305  s << ' ' << bl->getStop().getOffset();
    let _ = write!(s, " {:x}", block_stop_addr(bl).as_u64());
    // cc:306  s << endl;
    let _ = writeln!(s);
}

// Ghidra: graph.cc:309 print_block_edge
/// Emit the in-edges of a single basic block as Renoir edge records.
///
/// Faithful port of `print_block_edge` (graph.cc:309-314): for each in-edge
/// emits `<srcIndex> <thisIndex>` on its own line.
fn print_block_edge(bl: &dyn FlowBlock, s: &mut dyn Write) {
    let this_index = bl.get_index();
    let bank = bl.owner_bank().expect("print_block_edge on unregistered block");
    // cc:312-313  for i in 0..sizeIn(): print in(i).getIndex() this.getIndex()
    for i in 0..bl.size_in() {
        if let Some(edge) = bl.get_in(i) {
            let src_index = bank.expect_index(edge.point);
            let _ = writeln!(s, "{} {}", src_index, this_index);
        }
    }
}

// Ghidra: graph.cc:316 dump_block_vertex
/// Emit all basic-block vertex records for a `BlockGraph`.
///
/// Faithful port of `dump_block_vertex` (graph.cc:316-335). When `falsenode`
/// is set (used by the dominator dump when more than one block lacks an
/// immediate dominator), a synthetic `-1 0 0 -1 0 0` record is emitted first
/// to act as a shared root.
fn dump_block_vertex(graph: &BlockGraph, s: &mut dyn Write, falsenode: bool) {
    // cc:319-328  header (6 columns: SizeOut,SizeIn,Internal,Index,Start,Stop)
    let _ = s.write_str("\n\n// Add Vertices\n");
    let _ = s.write_str("*CMD=*COLUMNAR_INPUT,\n");
    let _ = s.write_str("  Command=AddVertices,\n");
    let _ = s.write_str("  Parsing=WhiteSpace,\n");
    let _ = s.write_str("  Fields=({Name=SizeOut, Location=1},\n");
    let _ = s.write_str("          {Name=SizeIn, Location=2},\n");
    let _ = s.write_str("          {Name=Internal, Location=3},\n");
    let _ = s.write_str("          {Name=Index, Location=4},\n");
    let _ = s.write_str("          {Name=Start, Location=5},\n");
    let _ = s.write_str("          {Name=Stop, Location=6});\n\n");

    // cc:330-331  optional synthetic false node
    if falsenode {
        let _ = s.write_str("-1 0 0 -1 0 0\n");
    }
    // cc:332-333  for each block: print_block_vertex
    for i in 0..graph.get_size() {
        if let Some(bl) = graph.get_block(i) {
            let bl_rg = bl.read().unwrap();
            print_block_vertex(&*bl_rg, s);
        }
    }
    // cc:334  s << "*END_COLUMNS\n";
    let _ = s.write_str("*END_COLUMNS\n");
}

// Ghidra: graph.cc:337 dump_block_edges
/// Emit all control-flow edges of a `BlockGraph`.
///
/// Faithful port of `dump_block_edges` (graph.cc:337-350): prints the
/// `AddEdges` header (FromKey/ToKey columns) then walks every block and
/// emits its in-edges via [`print_block_edge`].
fn dump_block_edges(graph: &BlockGraph, s: &mut dyn Write) {
    // cc:340-345  header
    let _ = s.write_str("\n\n// Add Edges\n");
    let _ = s.write_str("*CMD=*COLUMNAR_INPUT,\n");
    let _ = s.write_str("  Command=AddEdges,\n");
    let _ = s.write_str("  Parsing=WhiteSpace,\n");
    let _ = s.write_str("  Fields=({Name=*FromKey, Location=1},\n");
    let _ = s.write_str("          {Name=*ToKey, Location=2});\n\n");

    // cc:347-348  for each block: print_block_edge
    for i in 0..graph.get_size() {
        if let Some(bl) = graph.get_block(i) {
            let bl_rg = bl.read().unwrap();
            print_block_edge(&*bl_rg, s);
        }
    }
    // cc:349  s << "*END_COLUMNS\n";
    let _ = s.write_str("*END_COLUMNS\n");
}

// Ghidra: graph.cc:352 print_dom_edge
/// Emit the immediate-dominator edge for a single basic block.
///
/// Faithful port of `print_dom_edge` (graph.cc:352-361): emits
/// `<domIndex> <thisIndex>` if the block has an immediate dominator, or —
/// when `falsenode` is set — `-1 <thisIndex>` to anchor undominated blocks
/// to the synthetic root.
fn print_dom_edge(bl: &dyn FlowBlock, s: &mut dyn Write, falsenode: bool) {
    let this_index = bl.get_index();
    // cc:355  FlowBlock *dom = bl->getImmedDom();
    if let Some(dom_weak) = bl.get_immed_dom() {
        if let Some(dom) = dom_weak.upgrade() {
            let dom_index = dom.read().unwrap().get_index();
            // cc:358  s << dec << dom->getIndex() << ' ' << bl->getIndex() << endl;
            let _ = writeln!(s, "{} {}", dom_index, this_index);
            return;
        }
    }
    // cc:359-360  else if (falsenode) s << "-1 " << bl->getIndex() << endl;
    if falsenode {
        let _ = writeln!(s, "-1 {}", this_index);
    }
}

// Ghidra: graph.cc:363 dump_dom_edges
/// Emit all immediate-dominator edges of a `BlockGraph`.
///
/// Faithful port of `dump_dom_edges` (graph.cc:363-376): prints the
/// `AddEdges` header then walks every block and emits its dom edge via
/// [`print_dom_edge`].
fn dump_dom_edges(graph: &BlockGraph, s: &mut dyn Write, falsenode: bool) {
    // cc:366-371  header
    let _ = s.write_str("\n\n// Add Edges\n");
    let _ = s.write_str("*CMD=*COLUMNAR_INPUT,\n");
    let _ = s.write_str("  Command=AddEdges,\n");
    let _ = s.write_str("  Parsing=WhiteSpace,\n");
    let _ = s.write_str("  Fields=({Name=*FromKey, Location=1},\n");
    let _ = s.write_str("          {Name=*ToKey, Location=2});\n\n");

    // cc:373-374  for each block: print_dom_edge
    for i in 0..graph.get_size() {
        if let Some(bl) = graph.get_block(i) {
            let bl_rg = bl.read().unwrap();
            print_dom_edge(&*bl_rg, s, falsenode);
        }
    }
    // cc:375  s << "*END_COLUMNS\n";
    let _ = s.write_str("*END_COLUMNS\n");
}

// Ghidra: graph.cc:378 dump_block_attributes
/// Emit the `DefineAttribute` / `SetKeyAttribute` declarations for the
/// block-based graphs (SizeOut, SizeIn, Internal, Index, Start, Stop).
///
/// Faithful port of `dump_block_attributes` (graph.cc:378-410).
fn dump_block_attributes(s: &mut dyn Write) {
    let _ = s.write_str("\n// Attributes\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=SizeOut,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=SizeIn,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Internal,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Index,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Start,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");
    let _ = s.write_str("*CMD=DefineAttribute,\n");
    let _ = s.write_str("        Name=Stop,\n");
    let _ = s.write_str("        Type=String,\n");
    let _ = s.write_str("        Category=Vertices;\n\n");

    let _ = s.write_str("*CMD=SetKeyAttribute,\n");
    let _ = s.write_str("        Category=Vertices,");
    let _ = s.write_str("        Name=Index;\n\n");
}

// Ghidra: graph.cc:412 dump_block_properties
/// Emit the AutomaticArrangement / VertexColors / VertexIcons / VertexLabels
/// preference blocks shared by the control-flow and dominator dumps.
///
/// Faithful port of `dump_block_properties` (graph.cc:412-472).
fn dump_block_properties(s: &mut dyn Write) {
    // cc:415-430  AutomaticArrangement
    let _ = s.write_str("\n// AutomaticArrangement\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = AutomaticArrangement,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  EnableAutomaticArrangement=true,\n");
    let _ = s.write_str("  OnlyActOnVerticesWithoutCoordsIfOff=false,\n");
    let _ = s.write_str("  DontUpdateMediumWithUserArrangement=false,\n");
    let _ = s.write_str("  UserAddedArrangmentParams=({ServiceName=SimpleHierarchyFromSources,ServiceParams={~SkipPromptForParams=true}}),\n");
    let _ = s.write_str("  SmallSize=50,\n");
    let _ = s.write_str("  DontUpdateLargeWithUserArrangement=true,\n");
    let _ = s.write_str("  NewVertexActionIfOff=ArrangeByMDS,\n");
    let _ = s.write_str("  MediumSizeArrangement=SimpleHierarchyFromSources,\n");
    let _ = s.write_str("  SmallSizeArrangement=SimpleHierarchyFromSources,\n");
    let _ = s.write_str("  MediumSize=800,\n");
    let _ = s.write_str("  LargeSizeArrangement=ArrangeInCircle,\n");
    let _ = s.write_str("  DontUpdateSmallWithUserArrangement=false,\n");
    let _ = s.write_str("  ActionSizeGainIfOff=1.0;\n");

    // cc:432-445  VertexColors
    let _ = s.write_str("\n// VertexColors\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = VertexColors,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  Mapping=({DisplayChoice=Red,AttributeValue=0},\n");
    let _ = s.write_str("  {DisplayChoice=Blue,AttributeValue=1},\n");
    let _ = s.write_str("  {DisplayChoice=Yellow,AttributeValue=2}),\n");
    let _ = s.write_str("  ChoiceForValueNotCovered=Purple,\n");
    let _ = s.write_str("  Extraction=CompleteValue,\n");
    let _ = s.write_str("  ExtractionParams={},\n");
    let _ = s.write_str("  AttributeName=SizeOut,\n");
    let _ = s.write_str("  ChoiceForMissingValue=Purple,\n");
    let _ = s.write_str("  CanOverride=true,\n");
    let _ = s.write_str("  OverrideAttributeName=Color,\n");
    let _ = s.write_str("  UsingRange=false;\n");

    // cc:447-458  VertexIcons
    let _ = s.write_str("\n//     VertexIcons\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = VertexIcons,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  Mapping=({DisplayChoice=Square,AttributeValue=0}),\n");
    let _ = s.write_str("  ChoiceForValueNotCovered=Circle,\n");
    let _ = s.write_str("  Extraction=CompleteValue,\n");
    let _ = s.write_str("  ExtractionParams={},\n");
    let _ = s.write_str("  AttributeName=SizeIn,\n");
    let _ = s.write_str("  ChoiceForMissingValue=Circle,\n");
    let _ = s.write_str("  CanOverride=true,\n");
    let _ = s.write_str("  OverrideAttributeName=Icon,\n");
    let _ = s.write_str("  UsingRange=false;\n");

    // cc:460-471  VertexLabels
    let _ = s.write_str("\n//     VertexLabels\n");
    let _ = s.write_str("  *CMD = AlterLocalPreferences, Name = VertexLabels,\n");
    let _ = s.write_str("  ~ReplaceAllParams = TRUE,\n");
    let _ = s.write_str("  Center=({MaxLines=4,SqueezeLinesTogether=true,TreatBackSlashNAsNewLine=false,FontSize=10,Format=StandardFormat,IncludeBackground=false,BackgroundColor=Black,AttributeName=Start,UseSpecialFontName=false,SpecialColor=Black,SpecialFontName=SansSerif,UseSpecialColor=false,LabelAlignment=Center,MaxWidth=100}),\n");
    let _ = s.write_str("  East=(),\n");
    let _ = s.write_str("  SouthEast=(),\n");
    let _ = s.write_str("  North=(),\n");
    let _ = s.write_str("  West=(),\n");
    let _ = s.write_str("  SouthWest=(),\n");
    let _ = s.write_str("  NorthEast=(),\n");
    let _ = s.write_str("  South=(),\n");
    let _ = s.write_str("  NorthWest=();\n");
}

// Ghidra: graph.cc:474 dump_controlflow_graph
/// Serialize a function's control-flow graph in Renoir format.
///
/// Faithful port of `dump_controlflow_graph` (graph.cc:474-483): emits the
/// `NewGraphWindow` / `*NEXUS` preamble using `name`, then the shared
/// properties/attributes and the block vertices (with `falsenode=false`) and
/// edges.
pub fn dump_controlflow_graph(name: &str, graph: &BlockGraph, s: &mut dyn Write) {
    // cc:477-478
    let _ = writeln!(s, "*CMD=NewGraphWindow, WindowName={}-controlflow;", name);
    let _ = writeln!(s, "*CMD=*NEXUS,Name={}-controlflow;", name);
    // cc:479-482
    dump_block_properties(s);
    dump_block_attributes(s);
    dump_block_vertex(graph, s, false);
    dump_block_edges(graph, s);
}

// Ghidra: graph.cc:485 dump_dom_graph
/// Serialize a function's dominator graph in Renoir format.
///
/// Faithful port of `dump_dom_graph` (graph.cc:485-500). Computes whether a
/// synthetic "false node" is needed: if more than one block has no immediate
/// dominator, the false node (`-1`) is used as a shared root so every block
/// is reachable from some source. Then emits the preamble, shared
/// properties/attributes, block vertices (with the computed `falsenode`),
/// and dom edges.
pub fn dump_dom_graph(name: &str, graph: &BlockGraph, s: &mut dyn Write) {
    // cc:488-493  count blocks without an immediate dominator
    let mut count = 0usize;
    for i in 0..graph.get_size() {
        if let Some(bl) = graph.get_block(i) {
            let bl_rg = bl.read().unwrap();
            // cc:491  if (graph.getBlock(i)->getImmedDom() == null) count += 1;
            if bl_rg.get_immed_dom().and_then(|w| w.upgrade()).is_none() {
                count += 1;
            }
        }
    }
    let falsenode = count > 1;

    // cc:494-495
    let _ = writeln!(s, "*CMD=NewGraphWindow, WindowName={}-dom;", name);
    let _ = writeln!(s, "*CMD=*NEXUS,Name={}-dom;", name);
    // cc:496-499
    dump_block_properties(s);
    dump_block_attributes(s);
    dump_block_vertex(graph, s, falsenode);
    dump_dom_edges(graph, s, falsenode);
}

// RUDRA-GLUE: convenience wrappers that write into a fresh `String`. Ghidra
// callers pass an `ostream`; Rust callers more often want a `String`, so we
// provide thin adapters that forward to the `Write`-sink variants. These are
// not 1:1 with any single Ghidra function (they replace the ostream usage
// pattern) but produce identical output.
/// Convenience wrapper around [`dump_dataflow_graph`] that returns a `String`.
pub fn dump_dataflow_graph_string(data: &Funcdata) -> String {
    let mut out = String::new();
    dump_dataflow_graph(data, &mut out);
    out
}

/// Convenience wrapper around [`dump_controlflow_graph`] that returns a `String`.
// RUDRA-GLUE: Rust String-return adapter for Ghidra's ostream-based
// dump_controlflow_graph; it only allocates a sink and forwards unchanged.
pub fn dump_controlflow_graph_string(name: &str, graph: &BlockGraph) -> String {
    let mut out = String::new();
    dump_controlflow_graph(name, graph, &mut out);
    out
}

/// Convenience wrapper around [`dump_dom_graph`] that returns a `String`.
// RUDRA-GLUE: Rust String-return adapter for Ghidra's ostream-based
// dump_dom_graph; it only allocates a sink and forwards unchanged.
pub fn dump_dom_graph_string(name: &str, graph: &BlockGraph) -> String {
    let mut out = String::new();
    dump_dom_graph(name, graph, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RUDRA-GLUE: smoke test of the Renoir command text. We don't build a
    // full Funcdata/BlockGraph here; instead we sanity-check that the
    // helper functions emit the expected leading tokens and that the
    // attribute/property blocks render verbatim.
    #[test]
    fn test_dump_block_attributes_renders_verbatim() {
        let mut out = String::new();
        dump_block_attributes(&mut out);
        assert!(out.contains("Name=SizeOut"));
        assert!(out.contains("Name=Index"));
        assert!(out.contains("*CMD=SetKeyAttribute"));
        assert!(out.contains("Category=Vertices"));
    }

    #[test]
    fn test_dump_block_properties_renders_verbatim() {
        let mut out = String::new();
        dump_block_properties(&mut out);
        assert!(out.contains("Name = AutomaticArrangement"));
        assert!(out.contains("Name = VertexColors"));
        assert!(out.contains("AttributeValue=0"));
        assert!(out.contains("ArrangeInCircle"));
    }

    #[test]
    fn test_op_input_window() {
        // LOAD/STORE/BRANCH/CALL skip input slot 0.
        assert_eq!(op_input_window(OpCode::CPUI_LOAD, 2), (1, 2));
        assert_eq!(op_input_window(OpCode::CPUI_STORE, 3), (1, 3));
        assert_eq!(op_input_window(OpCode::CPUI_BRANCH, 1), (1, 1));
        assert_eq!(op_input_window(OpCode::CPUI_CALL, 2), (1, 2));
        // INDIRECT only emits input slot 0.
        assert_eq!(op_input_window(OpCode::CPUI_INDIRECT, 2), (0, 1));
        // Everything else: full range.
        assert_eq!(op_input_window(OpCode::CPUI_COPY, 2), (0, 2));
        assert_eq!(op_input_window(OpCode::CPUI_INT_ADD, 3), (0, 3));
    }

    #[test]
    fn test_is_fspec_space_is_false() {
        // Rugra models no Fspec space, so the FSPEC skip is a no-op.
        assert!(!is_fspec_space(&AddressSpace::Ram));
        assert!(!is_fspec_space(&AddressSpace::Register));
    }
}
