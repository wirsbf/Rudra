// BLOCK-HALFDELETE-REVIDX-0001 Rust comparand for locked Ghidra 12.0.4.
use rudra::address::Address;
use rudra::block::{BlockBasic, BlockEdge, BlockGraph, FlowBlock};
use std::sync::{Arc, RwLock};

type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

struct CaseGraph {
    graph: BlockGraph,
    blocks: Vec<BlockArc>,
}

impl CaseGraph {
    fn new() -> Self {
        Self {
            graph: BlockGraph::new(),
            blocks: Vec::new(),
        }
    }

    fn make(&mut self) -> BlockArc {
        let ordinal = self.blocks.len();
        let block: BlockArc = Arc::new(RwLock::new(BlockBasic::new(
            ordinal as i32,
            Address::new(0x1000 + ordinal as u64 * 0x10),
        )));
        self.graph.add_block(block.clone());
        self.blocks.push(block.clone());
        block
    }

    fn name(&self, block: &BlockArc) -> String {
        self.blocks
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, block))
            .map_or_else(|| "?".to_string(), |ordinal| format!("b{ordinal}"))
    }

    fn edge(&mut self, source: &BlockArc, target: &BlockArc, label: u32) {
        let out_slot = source.read().expect("source read").size_out();
        let in_slot = target.read().expect("target read").size_in();
        self.graph.add_edge(source.clone(), target.clone());
        if Arc::ptr_eq(source, target) {
            let mut block = source.write().expect("self edge write");
            let basic = block
                .as_any_mut()
                .downcast_mut::<BlockBasic>()
                .expect("BlockBasic");
            basic.outgoing[out_slot].flags = label;
            basic.incoming[in_slot].flags = label;
        } else {
            let mut source_guard = source.write().expect("source write");
            source_guard
                .as_any_mut()
                .downcast_mut::<BlockBasic>()
                .expect("BlockBasic")
                .outgoing[out_slot]
                .flags = label;
            drop(source_guard);
            target
                .write()
                .expect("target write")
                .as_any_mut()
                .downcast_mut::<BlockBasic>()
                .expect("BlockBasic")
                .incoming[in_slot]
                .flags = label;
        }
    }

    fn edge_list(&self, block: &BlockArc, outgoing: bool) -> String {
        let guard = block.read().expect("block read");
        let edges = if outgoing {
            (0..guard.size_out())
                .map(|slot| guard.get_out(slot).expect("out edge"))
                .collect::<Vec<_>>()
        } else {
            (0..guard.size_in())
                .map(|slot| guard.get_in(slot).expect("in edge"))
                .collect::<Vec<_>>()
        };
        drop(guard);
        format!(
            "[{}]",
            edges
                .iter()
                .map(|edge| format!(
                    "{}:{}:{}",
                    self.name(&edge.point),
                    edge.reverse_index,
                    edge.flags
                ))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    fn reciprocal(&self, block: &BlockArc, outgoing: bool) -> bool {
        let edges = {
            let guard = block.read().expect("focus read");
            let count = if outgoing {
                guard.size_out()
            } else {
                guard.size_in()
            };
            (0..count)
                .map(|slot| {
                    if outgoing {
                        guard.get_out(slot).expect("out edge")
                    } else {
                        guard.get_in(slot).expect("in edge")
                    }
                })
                .collect::<Vec<BlockEdge>>()
        };
        for (slot, edge) in edges.iter().enumerate() {
            if edge.reverse_index < 0 {
                return false;
            }
            let reverse = {
                let peer = edge.point.read().expect("peer read");
                if outgoing {
                    peer.get_in(edge.reverse_index as usize)
                } else {
                    peer.get_out(edge.reverse_index as usize)
                }
            };
            let Some(reverse) = reverse else {
                return false;
            };
            if !Arc::ptr_eq(&reverse.point, block)
                || reverse.reverse_index != slot as i32
                || reverse.flags != edge.flags
            {
                return false;
            }
        }
        true
    }

    fn observe(&self, case_name: &str, phase: &str, focus: &BlockArc, phi: &[&str]) {
        let blocks = self
            .blocks
            .iter()
            .map(|block| {
                format!(
                    "{}{{in={},out={}}}",
                    self.name(block),
                    self.edge_list(block, false),
                    self.edge_list(block, true)
                )
            })
            .collect::<Vec<_>>()
            .join(";");
        let incoming = {
            let focus = focus.read().expect("focus read");
            (0..focus.size_in())
                .map(|slot| focus.get_in(slot).expect("focus in edge"))
                .collect::<Vec<_>>()
        };
        let phi = phi
            .iter()
            .enumerate()
            .map(|(slot, token)| format!("{}:{token}", self.name(&incoming[slot].point)))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "case={case_name}|phase={phase}|blocks=[{blocks}]|focus_in_ok={}|focus_out_ok={}|phi=[{phi}]",
            i32::from(self.reciprocal(focus, false)),
            i32::from(self.reciprocal(focus, true))
        );
    }
}

fn half_delete_in(block: &BlockArc, slot: usize) {
    block
        .write()
        .expect("block write")
        .as_any_mut()
        .downcast_mut::<BlockBasic>()
        .expect("BlockBasic")
        .half_delete_in_edge(slot);
}

fn half_delete_out(block: &BlockArc, slot: usize) {
    block
        .write()
        .expect("block write")
        .as_any_mut()
        .downcast_mut::<BlockBasic>()
        .expect("BlockBasic")
        .half_delete_out_edge(slot);
}

fn in_nonlast_phi() {
    let mut fixture = CaseGraph::new();
    let s0 = fixture.make();
    let s1 = fixture.make();
    let s2 = fixture.make();
    let s3 = fixture.make();
    let target = fixture.make();
    fixture.edge(&s0, &target, 10);
    fixture.edge(&s1, &target, 20);
    fixture.edge(&s2, &target, 30);
    fixture.edge(&s3, &target, 40);
    let mut phi = vec!["v0", "v1", "v2", "v3"];
    fixture.observe("in_nonlast_phi", "before", &target, &phi);
    half_delete_in(&target, 1);
    phi.remove(1);
    fixture.observe("in_nonlast_phi", "after", &target, &phi);
}

fn out_nonlast_ordered() {
    let mut fixture = CaseGraph::new();
    let source = fixture.make();
    let t0 = fixture.make();
    let t1 = fixture.make();
    let t2 = fixture.make();
    let t3 = fixture.make();
    fixture.edge(&source, &t0, 11);
    fixture.edge(&source, &t1, 21);
    fixture.edge(&source, &t2, 31);
    fixture.edge(&source, &t3, 41);
    fixture.observe("out_nonlast_ordered", "before", &source, &[]);
    half_delete_out(&source, 1);
    fixture.observe("out_nonlast_ordered", "after", &source, &[]);
}

fn consecutive_in_phi() {
    let mut fixture = CaseGraph::new();
    let s0 = fixture.make();
    let s1 = fixture.make();
    let s2 = fixture.make();
    let s3 = fixture.make();
    let s4 = fixture.make();
    let target = fixture.make();
    fixture.edge(&s0, &target, 12);
    fixture.edge(&s1, &target, 22);
    fixture.edge(&s2, &target, 32);
    fixture.edge(&s3, &target, 42);
    fixture.edge(&s4, &target, 52);
    let mut phi = vec!["p0", "p1", "p2", "p3", "p4"];
    fixture.observe("consecutive_in_phi", "before", &target, &phi);
    half_delete_in(&target, 1);
    phi.remove(1);
    fixture.observe("consecutive_in_phi", "after_first", &target, &phi);
    half_delete_in(&target, 1);
    phi.remove(1);
    fixture.observe("consecutive_in_phi", "after_second", &target, &phi);
}

fn self_parallel_in() {
    let mut fixture = CaseGraph::new();
    let focus = fixture.make();
    let left = fixture.make();
    let right = fixture.make();
    fixture.edge(&focus, &focus, 13);
    fixture.edge(&left, &focus, 23);
    fixture.edge(&focus, &focus, 33);
    fixture.edge(&right, &focus, 43);
    fixture.observe("self_parallel_in", "before", &focus, &[]);
    half_delete_in(&focus, 0);
    fixture.observe("self_parallel_in", "after", &focus, &[]);
}

fn self_parallel_out() {
    let mut fixture = CaseGraph::new();
    let focus = fixture.make();
    let left = fixture.make();
    let right = fixture.make();
    fixture.edge(&focus, &focus, 14);
    fixture.edge(&focus, &left, 24);
    fixture.edge(&focus, &focus, 34);
    fixture.edge(&focus, &right, 44);
    fixture.observe("self_parallel_out", "before", &focus, &[]);
    half_delete_out(&focus, 0);
    fixture.observe("self_parallel_out", "after", &focus, &[]);
}

fn bidirectional_ordered() {
    let mut fixture = CaseGraph::new();
    let a = fixture.make();
    let b = fixture.make();
    let c = fixture.make();
    fixture.edge(&a, &b, 15);
    fixture.edge(&b, &a, 25);
    fixture.edge(&a, &c, 35);
    fixture.edge(&c, &a, 45);
    fixture.edge(&a, &b, 55);
    fixture.edge(&b, &a, 65);
    let mut phi = vec!["ba0", "ca", "ba1"];
    fixture.observe("bidirectional_ordered", "before", &a, &phi);
    half_delete_in(&a, 1);
    phi.remove(1);
    fixture.observe("bidirectional_ordered", "after_in", &a, &phi);
    half_delete_out(&a, 1);
    fixture.observe("bidirectional_ordered", "after_out", &a, &phi);
}

fn valid_boundary_slots() {
    {
        let mut fixture = CaseGraph::new();
        let source = fixture.make();
        let target = fixture.make();
        fixture.edge(&source, &target, 16);
        fixture.observe("single_out_slot", "before", &source, &[]);
        half_delete_out(&source, 0);
        fixture.observe("single_out_slot", "after", &source, &[]);
    }
    {
        let mut fixture = CaseGraph::new();
        let s0 = fixture.make();
        let s1 = fixture.make();
        let target = fixture.make();
        fixture.edge(&s0, &target, 26);
        fixture.edge(&s1, &target, 36);
        let mut phi = vec!["q0", "q1"];
        fixture.observe("last_in_slot", "before", &target, &phi);
        half_delete_in(&target, 1);
        phi.pop();
        fixture.observe("last_in_slot", "after", &target, &phi);
    }
}

fn main() {
    println!(
        "schema=1|fixture=BLOCK-HALFDELETE-REVIDX-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    in_nonlast_phi();
    out_nonlast_ordered();
    consecutive_in_phi();
    self_parallel_in();
    self_parallel_out();
    bidirectional_ordered();
    valid_boundary_slots();
}
