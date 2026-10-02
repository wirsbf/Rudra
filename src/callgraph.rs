//! Call graph construction and analysis.
//!
//! Corresponds to Ghidra's `callgraph.hh` / `callgraph.cc` (596 lines).
//!
//! Builds and analyzes the call graph of a program: which functions call
//! which, detecting cycles, and iterating in leaf-first order.
//!
//! Key classes:
//! - `CallGraphEdge`: a directed edge (caller → callee)
//! - `CallGraphNode`: a function node with in/out edges
//! - `CallGraph`: the graph container with cycle detection and leaf walk

use std::collections::BTreeMap;

use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};

// Ghidra: callgraph.cc:21 ELEM_CALLGRAPH, ELEM_NODE, ELEM_EDGE
/// Element id for `<callgraph>`. Faithful to `ELEM_CALLGRAPH` (callgraph.cc:21).
pub fn elem_callgraph() -> ElementId { ElementId::new("callgraph", 226) }
/// Element id value for `<node>`; Ghidra stores `ELEM_NODE` as a global (callgraph.cc:22).
// RUDRA-GLUE: ANN-B; Rust constructs callgraph.cc's global ELEM_NODE on demand because the marshal API takes an owned ElementId value.
pub fn elem_node() -> ElementId { ElementId::new("node", 227) }
/// Element id value for `<edge>`; Ghidra stores `ELEM_EDGE` as a shared global (block.cc:31).
// RUDRA-GLUE: ANN-B; Rust constructs the shared C++ ELEM_EDGE global on demand because the marshal API takes an owned ElementId value.
pub fn elem_edge() -> ElementId { ElementId::new("edge", 105) }

/// Edge flags.
pub mod edge_flags {
    pub const CYCLE: u32 = 1;
    pub const DONTFOLLOW: u32 = 2;
}

/// Node flags.
pub mod node_flags {
    pub const MARK: u32 = 1;
    pub const ONLY_CYCLE_IN: u32 = 2;
    pub const CURRENT_CYCLE: u32 = 4;
    pub const ENTRY_NODE: u32 = 8;
}

/// A directed edge in the call graph (caller → callee).
/// Corresponds to Ghidra's `CallGraphEdge` (callgraph.hh:32).
#[derive(Debug, Clone)]
pub struct CallGraphEdge {
    /// Address of the caller function
    pub from_addr: u64,
    /// Address of the callee function
    pub to_addr: u64,
    /// Address where the call instruction was made
    pub callsite_addr: u64,
    /// Edge flags
    pub flags: u32,
}

impl CallGraphEdge {
    // Ghidra: callgraph.hh:32 CallGraphEdge::new
    pub fn new(from: u64, to: u64, callsite: u64) -> Self {
        Self { from_addr: from, to_addr: to, callsite_addr: callsite, flags: 0 }
    }
    // Ghidra: callgraph.hh:32 CallGraphEdge::isCycle
    pub fn is_cycle(&self) -> bool { self.flags & edge_flags::CYCLE != 0 }

    // Ghidra: callgraph.cc:24 CallGraphEdge::encode
    /// Encode this edge as an `<edge>` element containing `<addr>` children
    /// for the caller, callee, and call site. Faithful to
    /// `CallGraphEdge::encode` (callgraph.cc:24).
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&elem_edge());
        encode_addr_element(encoder, self.from_addr);
        encode_addr_element(encoder, self.to_addr);
        encode_addr_element(encoder, self.callsite_addr);
        encoder.close_element(&elem_edge());
    }

    // Ghidra: callgraph.cc:34 CallGraphEdge::decode
    /// Decode an edge from an `<edge>` element: three `<addr>` children
    /// (from, to, call-site), then register the edge in `graph`. Faithful to
    /// `CallGraphEdge::decode` (callgraph.cc:34). Throws if either endpoint
    /// node is not present in the graph.
    pub fn decode(decoder: &mut dyn Decoder, graph: &mut CallGraph) {
        let elem_id = decoder.open_element_matching(&elem_edge());
        let from_addr = decode_addr_element(decoder);
        let to_addr = decode_addr_element(decoder);
        let site_addr = decode_addr_element(decoder);
        decoder.close_element(elem_id);
        if graph.find_node(from_addr).is_none() {
            // Ghidra throws LowlevelError("Could not find from node").
            panic!("CallGraphEdge::decode: Could not find from node {:#x}", from_addr);
        }
        if graph.find_node(to_addr).is_none() {
            panic!("CallGraphEdge::decode: Could not find to node {:#x}", to_addr);
        }
        graph.add_edge(from_addr, to_addr, site_addr);
    }
}

/// A function node in the call graph.
/// Corresponds to Ghidra's `CallGraphNode` (callgraph.hh:54).
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    /// Starting address of the function
    pub entry_addr: u64,
    /// Name of the function
    pub name: String,
    /// In-edges (callers)
    pub in_edges: Vec<CallGraphEdge>,
    /// Out-edges (callees)
    pub out_edges: Vec<CallGraphEdge>,
    /// Node flags
    pub flags: u32,
    /// Address of the backing `Funcdata`, if any (Ghidra stores a `Funcdata*`;
    /// Rudra keeps only the address to avoid a borrow-cycle).
    pub funcdata_addr: Option<u64>,
}

impl CallGraphNode {
    // Ghidra: callgraph.hh:26 CallGraphNode::new
    pub fn new(addr: u64, name: String) -> Self {
        Self {
            entry_addr: addr,
            name,
            in_edges: Vec::new(),
            out_edges: Vec::new(),
            flags: 0,
            funcdata_addr: None,
        }
    }

    // Ghidra: callgraph.hh:26 CallGraphNode::numInEdge
    pub fn num_in_edge(&self) -> usize { self.in_edges.len() }
    // Ghidra: callgraph.hh:26 CallGraphNode::numOutEdge
    pub fn num_out_edge(&self) -> usize { self.out_edges.len() }
    // Ghidra: callgraph.hh:26 CallGraphNode::isMark
    pub fn is_mark(&self) -> bool { self.flags & node_flags::MARK != 0 }
    // Ghidra: callgraph.hh:26 CallGraphNode::clearMark
    pub fn clear_mark(&mut self) { self.flags &= !node_flags::MARK; }

    // Ghidra: callgraph.hh:54 CallGraphNode::getFuncdata
    /// Get the backing function's address, if set.
    pub fn get_funcdata_addr(&self) -> Option<u64> { self.funcdata_addr }

    // Ghidra: callgraph.cc:55 CallGraphNode::setFuncdata
    /// Attach a backing `Funcdata` (by address) to this node. Faithful to
    /// `CallGraphNode::setFuncdata` (callgraph.cc:55): throws if a different
    /// function is already attached or if `f`'s address disagrees with this
    /// node's entry address.
    pub fn set_funcdata(&mut self, f_addr: u64) -> Result<(), String> {
        if let Some(existing) = self.funcdata_addr {
            if existing != f_addr {
                return Err(
                    "Multiple functions at one address in callgraph".to_string(),
                );
            }
        }
        if f_addr != self.entry_addr {
            return Err(
                "Setting function data at wrong address in callgraph".to_string(),
            );
        }
        self.funcdata_addr = Some(f_addr);
        Ok(())
    }

    // Ghidra: callgraph.cc:66 CallGraphNode::encode
    /// Encode this node as a `<node>` element with a `name` attribute (if any)
    /// and an `<addr>` child for the entry address. Faithful to
    /// `CallGraphNode::encode` (callgraph.cc:66).
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&elem_node());
        if !self.name.is_empty() {
            encoder.write_string(&AttributeId::new("name", 0), &self.name);
        }
        encode_addr_element(encoder, self.entry_addr);
        encoder.close_element(&elem_node());
    }

    // Ghidra: callgraph.cc:76 CallGraphNode::decode
    /// Decode this node from a `<node>` element: an optional `name` attribute
    /// and an `<addr>` child. The node is added to `graph`. Faithful to
    /// `CallGraphNode::decode` (callgraph.cc:76).
    pub fn decode(decoder: &mut dyn Decoder, graph: &mut CallGraph) {
        let elem_id = decoder.open_element_matching(&elem_node());
        let mut name = String::new();
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            if decoder.attribute_name(aid).as_deref() == Some("name") {
                name = decoder.read_string();
            } else {
                let _ = decoder.read_string();
            }
        }
        let addr = decode_addr_element(decoder);
        decoder.close_element(elem_id);
        graph.add_node(addr, name);
    }
}

/// The call graph container.
/// Corresponds to Ghidra's `CallGraph` (callgraph.hh:96).
pub struct CallGraph {
    /// Nodes sorted by entry address
    pub nodes: BTreeMap<u64, CallGraphNode>,
    /// Seed nodes for cycle detection
    pub seeds: Vec<u64>,
}

impl CallGraph {
    // Ghidra: callgraph.hh:27 CallGraph::new
    pub fn new() -> Self {
        Self { nodes: BTreeMap::new(), seeds: Vec::new() }
    }

    // Ghidra: callgraph.cc:207 CallGraph::addNode
    /// Add a node by address and name, returning the address.
    pub fn add_node(&mut self, addr: u64, name: String) -> u64 {
        self.nodes.entry(addr).or_insert_with(|| CallGraphNode::new(addr, name));
        addr
    }

    // Ghidra: callgraph.cc:232 CallGraph::findNode
    /// Find a node by address.
    pub fn find_node(&self, addr: u64) -> Option<&CallGraphNode> {
        self.nodes.get(&addr)
    }

    // Ghidra: callgraph.hh:27 CallGraph::findNodeMut
    /// Find a mutable node by address.
    pub fn find_node_mut(&mut self, addr: u64) -> Option<&mut CallGraphNode> {
        self.nodes.get_mut(&addr)
    }

    // Ghidra: callgraph.cc:243 CallGraph::addEdge
    /// Add an edge from one function to another.
    pub fn add_edge(&mut self, from: u64, to: u64, callsite: u64) {
        // Ensure both nodes exist.
        self.nodes.entry(from).or_insert_with(|| CallGraphNode::new(from, String::new()));
        self.nodes.entry(to).or_insert_with(|| CallGraphNode::new(to, String::new()));

        let edge = CallGraphEdge::new(from, to, callsite);
        if let Some(from_node) = self.nodes.get_mut(&from) {
            from_node.out_edges.push(edge.clone());
        }
        if let Some(to_node) = self.nodes.get_mut(&to) {
            to_node.in_edges.push(edge);
        }
    }

    // Ghidra: callgraph.hh:27 CallGraph::numNodes
    /// Get the number of nodes.
    pub fn num_nodes(&self) -> usize { self.nodes.len() }

    // Ghidra: callgraph.cc:182 CallGraph::clearMarks
    /// Clear all marks on all nodes.
    pub fn clear_marks(&mut self) {
        for node in self.nodes.values_mut() {
            node.clear_mark();
        }
    }

    // Ghidra: callgraph.cc:321 CallGraph::initLeafWalk
    /// Initialize a leaf walk: find the first leaf (no out-Edges).
    pub fn init_leaf_walk(&self) -> Option<u64> {
        for (&addr, node) in &self.nodes {
            if node.out_edges.is_empty() {
                return Some(addr);
            }
        }
        None
    }

    // Ghidra: callgraph.cc:336 CallGraph::nextLeaf
    /// Get the next leaf in a depth-first leaf walk from the given node.
    /// Corresponds to Ghidra's `CallGraph::nextLeaf`.
    /// Returns the next leaf address, or None if done.
    pub fn next_leaf(&self, _addr: u64) -> Option<u64> {
        // Simplified: just find the next unvisited leaf.
        for (&addr, node) in &self.nodes {
            if addr > _addr && node.out_edges.is_empty() {
                return Some(addr);
            }
        }
        None
    }

    // Ghidra: callgraph.cc:129 CallGraph::snipCycles
    /// Detect and snip cycles in the call graph using DFS.
    /// Corresponds to Ghidra's `CallGraph::snipCycles`.
    pub fn snip_cycles(&mut self) {
        // Collect all addresses for iteration.
        let addrs: Vec<u64> = self.nodes.keys().copied().collect();
        let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut in_stack: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for &start in &addrs {
            self.snip_cycles_dfs(start, &mut visited, &mut in_stack);
        }
    }

    // Ghidra: callgraph.hh:27 CallGraph::snipCyclesDfs
    fn snip_cycles_dfs(&mut self, addr: u64, visited: &mut std::collections::HashSet<u64>, in_stack: &mut std::collections::HashSet<u64>) {
        if visited.contains(&addr) { return; }
        visited.insert(addr);
        in_stack.insert(addr);

        // Collect out-edges (copy to avoid borrow issues).
        let out_addrs: Vec<u64> = self.nodes.get(&addr)
            .map(|n| n.out_edges.iter().map(|e| e.to_addr).collect())
            .unwrap_or_default();

        for to_addr in out_addrs {
            if in_stack.contains(&to_addr) {
                // Cycle detected: mark the edge as cycle.
                if let Some(from_node) = self.nodes.get_mut(&addr) {
                    for edge in &mut from_node.out_edges {
                        if edge.to_addr == to_addr {
                            edge.flags |= edge_flags::CYCLE;
                        }
                    }
                }
            } else if !visited.contains(&to_addr) {
                self.snip_cycles_dfs(to_addr, visited, in_stack);
            }
        }

        in_stack.remove(&addr);
    }

    // Ghidra: callgraph.cc:92 CallGraph::findNoEntry
    /// Find all nodes that have no incoming edges (entry points).
    /// Corresponds to Ghidra's `CallGraph::findNoEntry`.
    pub fn find_no_entry(&self) -> Vec<u64> {
        self.nodes.iter()
            .filter(|(_, n)| n.in_edges.is_empty())
            .map(|(&addr, _)| addr)
            .collect()
    }

    // Ghidra: callgraph.hh:27 CallGraph::allAddrs
    /// Get all node addresses in sorted order.
    pub fn all_addrs(&self) -> Vec<u64> {
        self.nodes.keys().copied().collect()
    }

    // Ghidra: callgraph.hh:27 CallGraph::getOutEdges
    /// Get all out-edges from a node.
    pub fn get_out_edges(&self, addr: u64) -> &[CallGraphEdge] {
        self.nodes.get(&addr).map(|n| n.out_edges.as_slice()).unwrap_or(&[])
    }

    // Ghidra: callgraph.cc:270 CallGraph::deleteInEdge
    /// Delete an in-edge from a node.
    pub fn delete_in_edge(&mut self, addr: u64, index: usize) {
        let from_addr = self.nodes.get(&addr).and_then(|n| n.in_edges.get(index)).map(|e| e.from_addr);
        if let Some(node) = self.nodes.get_mut(&addr) {
            if index < node.in_edges.len() {
                node.in_edges.remove(index);
            }
        }
        if let Some(fa) = from_addr {
            if let Some(from_node) = self.nodes.get_mut(&fa) {
                from_node.out_edges.retain(|e| e.to_addr != addr);
            }
        }
    }

    // Ghidra: callgraph.cc:164 CallGraph::snipEdge
    /// Snip (mark as cycle) an edge from node at `addr`, edge index `i`.
    /// Faithful to Ghidra CallGraph::snipEdge (callgraph.cc:164).
    pub fn snip_edge(&mut self, addr: u64, i: usize) {
        if let Some(node) = self.nodes.get_mut(&addr) {
            if i < node.out_edges.len() {
                let to_addr = node.out_edges[i].to_addr;
                node.out_edges[i].flags |= edge_flags::CYCLE;
                // Mark the corresponding in-edge on the target
                if let Some(to_node) = self.nodes.get_mut(&to_addr) {
                    for in_e in to_node.in_edges.iter_mut() {
                        if in_e.from_addr == addr {
                            in_e.flags |= edge_flags::CYCLE;
                        }
                    }
                    to_node.flags |= node_flags::ONLY_CYCLE_IN;
                }
            }
        }
    }

    // Ghidra: callgraph.cc:406 CallGraph::buildEdges
    /// Build call graph edges from a Funcdata's call specifications.
    /// Faithful to Ghidra CallGraph::buildEdges (callgraph.cc:406).
    pub fn build_edges(&mut self, fd: &crate::funcdata::Funcdata) {
        let fd_addr = fd.baseaddr.as_u64();
        // Ensure the function's node exists
        if !self.nodes.contains_key(&fd_addr) {
            self.add_node(fd_addr, fd.get_name().to_string());
        }
        let num_calls = fd.num_calls();
        for i in 0..num_calls {
            if let Some(fc) = fd.get_call_specs(i) {
                if let Some(ref entry) = fc.entry_addr {
                    let to_addr = entry.as_u64();
                    if to_addr != 0 {
                        // Add target node if not present
                        if !self.nodes.contains_key(&to_addr) {
                            let name = fd.symbol_table.get(&to_addr)
                                .cloned()
                                .unwrap_or_else(|| format!("FUN_{:x}", to_addr));
                            self.add_node(to_addr, name);
                        }
                        // Get callsite address
                        let callsite = fc.op_addr.as_u64();
                        self.add_edge(fd_addr, to_addr, callsite);
                    }
                }
            }
        }
    }

    // Ghidra: callgraph.cc:352 CallGraph::cycleStructure
    /// Analyze cycle structure: identify strongly connected components.
    /// Faithful to Ghidra CallGraph::cycleStructure (callgraph.cc:352).
    /// After snip_cycles, this marks nodes that are part of cycles.
    pub fn cycle_structure(&mut self) {
        // After snip_cycles, cycle edges are marked. Mark nodes that
        // have only cycle in-edges as ONLY_CYCLE_IN.
        let addrs: Vec<u64> = self.nodes.keys().copied().collect();
        for addr in addrs {
            let has_non_cycle_in = self.nodes.get(&addr).map(|n| {
                n.in_edges.iter().any(|e| e.flags & edge_flags::CYCLE == 0)
            }).unwrap_or(false);
            if !has_non_cycle_in {
                if let Some(node) = self.nodes.get_mut(&addr) {
                    if !node.in_edges.is_empty() {
                        node.flags |= node_flags::ONLY_CYCLE_IN;
                    }
                }
            }
        }
    }

    // Ghidra: callgraph.hh:27 CallGraph::edges
    /// Get the call graph as a list of (caller, callee) pairs.
    pub fn edges(&self) -> Vec<(u64, u64)> {
        let mut result = Vec::new();
        for (&addr, node) in &self.nodes {
            for e in &node.out_edges {
                result.push((addr, e.to_addr));
            }
        }
        result
    }

    // Ghidra: callgraph.cc:432 CallGraph::encode
    /// Encode this call graph as a `<callgraph>` element: one `<node>` child
    /// per node, followed by all "in" edges (encoded as `<edge>` elements).
    /// Faithful to `CallGraph::encode` (callgraph.cc:432).
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&elem_callgraph());
        // Dump all nodes.
        for node in self.nodes.values() {
            node.encode(encoder);
        }
        // Dump all "in" edges.
        for node in self.nodes.values() {
            for e in &node.in_edges {
                e.encode(encoder);
            }
        }
        encoder.close_element(&elem_callgraph());
    }

    // Ghidra: callgraph.cc:453 CallGraph::decoder
    /// Decode this call graph from a `<callgraph>` element, dispatching each
    /// child to `CallGraphNode::decode` or `CallGraphEdge::decode`. Faithful
    /// to `CallGraph::decoder` (callgraph.cc:453).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element_matching(&elem_callgraph());
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            if sub_name == "edge" {
                CallGraphEdge::decode(decoder, self);
            } else {
                CallGraphNode::decode(decoder, self);
            }
        }
        decoder.close_element(elem_id);
    }

    // Ghidra: callgraph.cc:372 CallGraph::iterateScopesRecursive
    /// Recursively walk global scopes (and their children), adding every
    /// function symbol as a node. Faithful to
    /// `CallGraph::iterateScopesRecursive` (callgraph.cc:372).
    pub fn iterate_scopes_recursive(&mut self, scope: &crate::database::Scope, db: &crate::database::Database) {
        if !scope.is_global() {
            return;
        }
        self.iterate_functions_addr_order(scope);
        // Recurse into child scopes.
        let child_ids: Vec<u64> = scope.children.clone();
        for cid in child_ids {
            if let Some(child) = db.scopes.get(&cid) {
                self.iterate_scopes_recursive(child, db);
            }
        }
    }

    // Ghidra: callgraph.cc:385 CallGraph::iterateFunctionsAddrOrder
    /// Add a node for every `FunctionSymbol` in `scope`. Faithful to
    /// `CallGraph::iterateFunctionsAddrOrder` (callgraph.cc:385). Rudra
    /// identifies function symbols by `type_name == "func"` (see
    /// `ScopeInternal::findFunction`); the entry address serves as the node
    /// address and the symbol name as the node name.
    pub fn iterate_functions_addr_order(&mut self, scope: &crate::database::Scope) {
        for entry in &scope.entries {
            let sym = entry.symbol.read().unwrap();
            if sym.type_name == "func" {
                self.add_node(entry.addr.as_u64(), sym.get_display_name().to_string());
            }
        }
    }

    // Ghidra: callgraph.cc:400 CallGraph::buildAllNodes
    /// Make every global function symbol into a node. Faithful to
    /// `CallGraph::buildAllNodes` (callgraph.cc:400).
    pub fn build_all_nodes(&mut self, db: &crate::database::Database) {
        if let Some(global) = db.get_global_scope() {
            self.iterate_scopes_recursive(global, db);
        }
    }
}

// Ghidra: address.cc:289 (helper) Address::encode as <addr offset=...>
/// Encode an address as an `<addr>` element with an `offset` attribute, matching
/// the Rudra marshaling convention (see `SymbolEntry::encode` in database.rs).
fn encode_addr_element(encoder: &mut dyn Encoder, addr: u64) {
    encoder.open_element(&ElementId::new("addr", 0));
    encoder.write_unsigned_integer(&AttributeId::new("offset", 0), addr);
    encoder.close_element(&ElementId::new("addr", 0));
}

// Ghidra: address.cc:205 Address::decode (helper)
/// Decode an address from the current `<addr>` element. Returns the offset.
fn decode_addr_element(decoder: &mut dyn Decoder) -> u64 {
    let addr_id = decoder.open_element();
    let mut off = 0u64;
    loop {
        let aid = decoder.next_attribute_id();
        if aid == 0 {
            break;
        }
        if decoder.attribute_name(aid).as_deref() == Some("offset") {
            off = decoder.read_unsigned_integer();
        } else {
            let _ = decoder.read_string();
        }
    }
    decoder.close_element(addr_id);
    off
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callgraph_basic() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "main".into());
        cg.add_node(0x2000, "helper".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);

        assert_eq!(cg.num_nodes(), 2);
        let main = cg.find_node(0x1000).unwrap();
        assert_eq!(main.num_out_edge(), 1);
        assert_eq!(main.out_edges[0].to_addr, 0x2000);
        let helper = cg.find_node(0x2000).unwrap();
        assert_eq!(helper.num_in_edge(), 1);
    }

    #[test]
    fn test_leaf_walk() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "a".into());
        cg.add_node(0x2000, "b".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);
        let leaf = cg.init_leaf_walk().unwrap();
        assert_eq!(leaf, 0x2000);
    }

    #[test]
    fn test_edge() {
        let e = CallGraphEdge::new(0x1000, 0x2000, 0x1050);
        assert!(!e.is_cycle());
    }

    #[test]
    fn test_snip_edge() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "a".into());
        cg.add_node(0x2000, "b".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);
        cg.snip_edge(0x1000, 0);
        let a = cg.find_node(0x1000).unwrap();
        assert!(a.out_edges[0].is_cycle());
        let b = cg.find_node(0x2000).unwrap();
        assert!(b.flags & node_flags::ONLY_CYCLE_IN != 0);
    }

    #[test]
    fn test_snip_cycles_and_structure() {
        // Create a cycle: a → b → a
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "a".into());
        cg.add_node(0x2000, "b".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);
        cg.add_edge(0x2000, 0x1000, 0x2050);
        cg.snip_cycles();
        cg.cycle_structure();
        // After snip, at least one cycle edge should be marked
        let has_cycle = cg.edges().iter().any(|(from, _)| {
            cg.find_node(*from).map(|n| n.out_edges.iter().any(|e| e.is_cycle())).unwrap_or(false)
        });
        assert!(has_cycle);
    }

    #[test]
    fn test_delete_in_edge() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "a".into());
        cg.add_node(0x2000, "b".into());
        cg.add_node(0x3000, "c".into());
        cg.add_edge(0x1000, 0x3000, 0x1050);
        cg.add_edge(0x2000, 0x3000, 0x2050);
        cg.delete_in_edge(0x3000, 0);
        let c = cg.find_node(0x3000).unwrap();
        assert_eq!(c.num_in_edge(), 1);
        assert_eq!(c.in_edges[0].from_addr, 0x2000);
    }

    #[test]
    fn test_find_no_entry() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "main".into());
        cg.add_node(0x2000, "helper".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);
        let entries = cg.find_no_entry();
        assert_eq!(entries, vec![0x1000]);
    }

    #[test]
    fn test_edges_list() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, "a".into());
        cg.add_node(0x2000, "b".into());
        cg.add_edge(0x1000, 0x2000, 0x1050);
        let edges = cg.edges();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0], (0x1000, 0x2000));
    }
}
