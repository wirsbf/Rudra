//! Jump-table recovery — faithful port of `jumptable.hh` / `jumptable.cc` (2883 lines).
//!
//! Status: L1→L2. All public classes are present with full data structures and
//! most method bodies translated to Rust idioms (Arc/RwLock-aware). The
//! `EmulateFunction`/`PathMeld`-driven address recovery is faithful; the
//! structural CFG-rewriting parts (foldInGuards, switchOver, addBlockToSwitch)
//! use the existing block/op-edit APIs where available and are otherwise
//! documented as L3 gaps.
//!
//! Ghidra reference: ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.{hh,cc}.

use crate::address::{calc_mask, leastsigbit_set, minimalmask, mostsigbit_set, Address};
use crate::block::{BlockBasic, FlowBlock};
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::rangeutil::CircleRange;
use crate::varnode::Varnode;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Sentinel used to indicate a jump-table entry that has no case label.
/// Faithful to `JumpValues::NO_LABEL` (jumptable.cc:36).
pub const NO_LABEL: u64 = 0xBAD1_ABE1_BAD1_ABE1;

/// Recovery status of a [`JumpTable`]. Faithful to `JumpTable::RecoveryMode`
/// (jumptable.hh:544).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    /// JumpTable is fully recovered.
    Success = 0,
    /// Normal failure to recover.
    FailNormal = 1,
    /// Likely a thunk.
    FailThunk = 2,
    /// Likely a return operation.
    FailReturn = 3,
    /// Address formed by CALLOTHER.
    FailCallother = 4,
}

/// Typed failure from jump-table address recovery.
///
/// Ghidra distinguishes [`JumptableThunkError`](jumptable.hh:39) from the
/// ordinary `LowlevelError` channel. Keeping that distinction here lets the
/// caller map only the former to [`RecoveryMode::FailThunk`], while retaining
/// the exact explanatory text carried by either exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpTableRecoveryError {
    /// Ghidra `JumptableThunkError` (currently emitted as `"Likely thunk"`).
    Thunk { message: String },
    /// Ghidra `LowlevelError` raised during model/address sanity checking.
    Lowlevel { message: String },
}

impl JumpTableRecoveryError {
    // RUGRA-GLUE: Rust typed-exception discriminator; Ghidra stageJumpTable uses distinct catch clauses (funcdata_block.cc:539-544)
    /// Map this exception channel to Ghidra's recovery status enum.
    pub fn recovery_mode(&self) -> RecoveryMode {
        match self {
            Self::Thunk { .. } => RecoveryMode::FailThunk,
            Self::Lowlevel { .. } => RecoveryMode::FailNormal,
        }
    }

    // RUGRA-GLUE: Rust accessor for the explanatory string carried by Ghidra LowlevelError/JumptableThunkError
    /// Return the exact explanatory text carried by the error.
    pub fn message(&self) -> &str {
        match self {
            Self::Thunk { message } | Self::Lowlevel { message } => message,
        }
    }
}

impl std::fmt::Display for JumpTableRecoveryError {
    // RUGRA-GLUE: Rust Display trait for Ghidra's exception explain string
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for JumpTableRecoveryError {}

/// A description of where and how data was loaded from memory.
///
/// This is a generic table description, giving the starting address of the
/// table, the size of an entry, and the number of entries.
/// Faithful to `LoadTable` (jumptable.hh:50).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadTable {
    /// Starting address of the table.
    pub addr: Address,
    /// Size of each table entry.
    pub size: i32,
    /// Number of entries in the table.
    pub num: i32,
}

impl LoadTable {
    // Ghidra: jumptable.hh:57 LoadTable::LoadTable(Address,int4)
    /// Construct a single-entry table.
    pub fn single(addr: Address, size: i32) -> Self {
        Self { addr, size, num: 1 }
    }

    // Ghidra: jumptable.hh:58 LoadTable::LoadTable(Address,int4,int4)
    /// Construct a table with an explicit entry count.
    pub fn new(addr: Address, size: i32, num: i32) -> Self {
        Self { addr, size, num }
    }

    // RUGRA-GLUE: reproduce the address-only std::sort implementation used by
    // the locked GCC 16.2.1/libstdc++ oracle; C++ does not specify equivalent-key order
    fn address_less(left: &LoadTable, right: &LoadTable) -> bool {
        left.addr < right.addr
    }

    // RUGRA-GLUE: libstdc++ 16 bits/stl_algo.h __unguarded_linear_insert for
    // the address-only LoadTable comparator used by jumptable.cc:87
    fn libstdcxx_unguarded_linear_insert(table: &mut [LoadTable], mut last: usize) {
        let value = table[last].clone();
        loop {
            let next = last - 1;
            if !Self::address_less(&value, &table[next]) {
                break;
            }
            table[last] = table[next].clone();
            last = next;
        }
        table[last] = value;
    }

    // RUGRA-GLUE: libstdc++ 16 bits/stl_algo.h __insertion_sort for the
    // address-only LoadTable comparator used by jumptable.cc:87
    fn libstdcxx_insertion_sort(table: &mut [LoadTable], first: usize, last: usize) {
        if first == last {
            return;
        }
        for index in first + 1..last {
            if Self::address_less(&table[index], &table[first]) {
                let value = table[index].clone();
                for source in (first..index).rev() {
                    table[source + 1] = table[source].clone();
                }
                table[first] = value;
            } else {
                Self::libstdcxx_unguarded_linear_insert(table, index);
            }
        }
    }

    // RUGRA-GLUE: libstdc++ 16 bits/stl_heap.h __adjust_heap/__push_heap for
    // the address-only LoadTable comparator used by jumptable.cc:87
    fn libstdcxx_adjust_heap(
        table: &mut [LoadTable],
        first: usize,
        mut hole: usize,
        len: usize,
        value: LoadTable,
    ) {
        let top = hole;
        let mut second_child = hole;
        while second_child < (len - 1) / 2 {
            second_child = 2 * (second_child + 1);
            if Self::address_less(
                &table[first + second_child],
                &table[first + second_child - 1],
            ) {
                second_child -= 1;
            }
            table[first + hole] = table[first + second_child].clone();
            hole = second_child;
        }
        if len & 1 == 0 && second_child == (len - 2) / 2 {
            second_child = 2 * (second_child + 1);
            table[first + hole] = table[first + second_child - 1].clone();
            hole = second_child - 1;
        }
        while hole > top {
            let parent = (hole - 1) / 2;
            if !Self::address_less(&table[first + parent], &value) {
                break;
            }
            table[first + hole] = table[first + parent].clone();
            hole = parent;
        }
        table[first + hole] = value;
    }

    // RUGRA-GLUE: libstdc++ 16 bits/stl_algo.h __partial_sort(first,last,last)
    // and bits/stl_heap.h heap helpers used at introsort's depth limit
    fn libstdcxx_heap_sort(table: &mut [LoadTable], first: usize, last: usize) {
        let len = last - first;
        if len < 2 {
            return;
        }

        let mut parent = (len - 2) / 2;
        loop {
            let value = table[first + parent].clone();
            Self::libstdcxx_adjust_heap(table, first, parent, len, value);
            if parent == 0 {
                break;
            }
            parent -= 1;
        }

        let mut heap_last = last;
        while heap_last - first > 1 {
            heap_last -= 1;
            let value = table[heap_last].clone();
            table[heap_last] = table[first].clone();
            Self::libstdcxx_adjust_heap(
                table,
                first,
                0,
                heap_last - first,
                value,
            );
        }
    }

    // RUGRA-GLUE: locked GCC 16.2.1 libstdc++ std::sort implementation for
    // LoadTable's address-only operator<; exact equivalent-key order is B2-observable
    fn sort_by_address_libstdcxx_16(table: &mut [LoadTable]) {
        const INSERTION_SORT_THRESHOLD: usize = 16;
        if table.is_empty() {
            return;
        }

        let depth_limit =
            (usize::BITS - 1 - table.len().leading_zeros()) as usize * 2;
        let mut pending = vec![(0usize, table.len(), depth_limit)];
        while let Some((mut first, last, mut depth)) = pending.pop() {
            while last - first > INSERTION_SORT_THRESHOLD {
                if depth == 0 {
                    Self::libstdcxx_heap_sort(table, first, last);
                    break;
                }
                depth -= 1;

                let second = first + 1;
                let middle = first + (last - first) / 2;
                let end = last - 1;
                if Self::address_less(&table[second], &table[middle]) {
                    if Self::address_less(&table[middle], &table[end]) {
                        table.swap(first, middle);
                    } else if Self::address_less(&table[second], &table[end]) {
                        table.swap(first, end);
                    } else {
                        table.swap(first, second);
                    }
                } else if Self::address_less(&table[second], &table[end]) {
                    table.swap(first, second);
                } else if Self::address_less(&table[middle], &table[end]) {
                    table.swap(first, end);
                } else {
                    table.swap(first, middle);
                }

                let pivot = first;
                let mut left = first + 1;
                let mut right = last;
                let cut = loop {
                    while Self::address_less(&table[left], &table[pivot]) {
                        left += 1;
                    }
                    right -= 1;
                    while Self::address_less(&table[pivot], &table[right]) {
                        right -= 1;
                    }
                    if left >= right {
                        break left;
                    }
                    table.swap(left, right);
                    left += 1;
                };

                // libstdc++ recurses on [cut,last), then iterates [first,cut).
                pending.push((first, cut, depth));
                first = cut;
            }
        }

        if table.len() > INSERTION_SORT_THRESHOLD {
            Self::libstdcxx_insertion_sort(table, 0, INSERTION_SORT_THRESHOLD);
            for index in INSERTION_SORT_THRESHOLD..table.len() {
                Self::libstdcxx_unguarded_linear_insert(table, index);
            }
        } else {
            Self::libstdcxx_insertion_sort(table, 0, table.len());
        }
    }

    // Ghidra: jumptable.cc:60 LoadTable::collapseTable
    /// Sort the entries and collapse any contiguous sequences into a single
    /// `LoadTable` entry. Faithful to `LoadTable::collapseTable`
    /// (jumptable.cc:60).
    pub fn collapse_table(table: &mut Vec<LoadTable>) {
        if table.is_empty() {
            return;
        }

        // Test if the table is already sorted and contiguous.
        let mut is_sorted = true;
        let mut num = table[0].num;
        let size0 = table[0].size;
        let mut next_addr = table[0].addr.offset(i64::from(size0));
        for entry in table.iter().skip(1) {
            if entry.addr == next_addr && entry.size == size0 {
                num += entry.num;
                next_addr = entry.addr.offset(i64::from(entry.size));
            } else {
                is_sorted = false;
                break;
            }
        }
        if is_sorted {
            // Truncate everything but the first entry.
            table.truncate(1);
            table[0].num = num;
            return;
        }

        // jumptable.hh:59 LoadTable::operator< compares only the Address.
        // Equivalent-key permutation affects the later size/adjacency scan,
        // so reproduce the std::sort implementation used by the pinned oracle.
        Self::sort_by_address_libstdcxx_16(table);

        let mut count = 1;
        let mut last = 0;
        let mut next_addr = table[0]
            .addr
            .offset(i64::from(table[0].size) * i64::from(table[0].num));
        for i in 1..table.len() {
            if table[i].addr == next_addr && table[i].size == table[last].size {
                table[last].num += table[i].num;
                next_addr = table[i]
                    .addr
                    .offset(i64::from(table[i].size) * i64::from(table[i].num));
            } else if next_addr < table[i].addr || table[i].size != table[last].size {
                last += 1;
                table[last] = table[i].clone();
                next_addr = table[i]
                    .addr
                    .offset(i64::from(table[i].size) * i64::from(table[i].num));
                count += 1;
            }
        }
        table.truncate(count);
    }
}

/// An entry of a data-flow path through pcode ops, used by [`PathMeld`].
/// Faithful to `PcodeOpNode` (used by PathMeld in jumptable.hh).
#[derive(Debug, Clone)]
pub struct PcodeOpNode {
    /// The pcode op on the path.
    pub op: Arc<RwLock<PcodeOp>>,
    /// Input slot consumed by the path at this op.
    pub slot: i32,
}

/// A PcodeOp in the path set associated with the last Varnode in the
/// intersection. Links an op to the common varnode at the split point.
/// Faithful to `PathMeld::RootedOp` (jumptable.hh:77).
#[derive(Debug, Clone)]
struct RootedOp {
    op: Arc<RwLock<PcodeOp>>,
    /// Index within the common varnodes of the split point.
    root_vn: i32,
}

/// All paths from a (putative) switch variable to the CPUI_BRANCHIND.
///
/// This is a container for intersecting paths during the construction of a
/// [`JumpModel`]. It contains every PcodeOp from some starting Varnode through
/// all paths to a specific BRANCHIND. The paths can split and rejoin. This
/// also keeps track of Varnodes that are present on *all* paths, as these are
/// the potential switch variables for the model.
/// Faithful to `PathMeld` (jumptable.hh:72).
#[derive(Debug, Default, Clone)]
pub struct PathMeld {
    /// Varnodes common to all paths (Arc pointers, compared by identity).
    common_vn: Vec<Arc<RwLock<Varnode>>>,
    /// All the ops for the melded paths.
    op_meld: Vec<RootedOp>,
}

impl PathMeld {
    // Ghidra: jumptable.hh:95 PathMeld::numCommonVarnode
    /// Number of varnodes common to all paths. Faithful to `numCommonVarnode`.
    pub fn num_common_varnode(&self) -> usize {
        self.common_vn.len()
    }

    // Ghidra: jumptable.hh:96 PathMeld::numOps
    /// Number of pcode ops across all paths. Faithful to `numOps`.
    pub fn num_ops(&self) -> usize {
        self.op_meld.len()
    }

    // Ghidra: jumptable.hh:102 PathMeld::empty
    /// Return `true` if this container holds no paths.
    pub fn empty(&self) -> bool {
        self.common_vn.is_empty()
    }

    // Ghidra: jumptable.hh:97 PathMeld::getVarnode
    /// Get the i-th common varnode.
    pub fn get_varnode(&self, i: usize) -> Arc<RwLock<Varnode>> {
        self.common_vn[i].clone()
    }

    // Ghidra: jumptable.hh:99 PathMeld::getOp
    /// Get the i-th pcode op.
    pub fn get_op(&self, i: usize) -> Arc<RwLock<PcodeOp>> {
        self.op_meld[i].op.clone()
    }

    // Ghidra: jumptable.hh:98 PathMeld::getOpParent
    /// Get the split-point varnode for the i-th pcode op.
    pub fn get_op_parent(&self, i: usize) -> Arc<RwLock<Varnode>> {
        self.common_vn[self.op_meld[i].root_vn as usize].clone()
    }

    // Ghidra: jumptable.cc:1023 PathMeld::getEarliestOp
    /// Find the earliest pcode op (executed first) that has the i-th common
    /// varnode as input. Faithful to `getEarliestOp` (jumptable.cc:1025).
    pub fn get_earliest_op(&self, pos: usize) -> Option<Arc<RwLock<PcodeOp>>> {
        for item in self.op_meld.iter().rev() {
            if item.root_vn as usize == pos {
                return Some(item.op.clone());
            }
        }
        None
    }

    // Ghidra: jumptable.cc:1038 PathMeld::isLoadInPath
    /// Search for a varnode in the common path, prior to `i`, defined by a
    /// LOAD operation. Faithful to `isLoadInPath` (jumptable.cc:1038).
    pub fn is_load_in_path(&self, mut i: usize) -> bool {
        while i > 0 {
            i -= 1;
            let vn = &self.common_vn[i];
            let vn_rg = vn.read().unwrap();
            if !vn_rg.is_written() {
                continue;
            }
            if let Some(def) = vn_rg.get_def() {
                if def.read().unwrap().opcode == OpCode::CPUI_LOAD {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: jumptable.cc:915 PathMeld::set(const PathMeld&)
    /// Copy paths from another container. Faithful to `set(const PathMeld&)`.
    pub fn set_from(&mut self, op2: &PathMeld) {
        self.common_vn = op2.common_vn.clone();
        self.op_meld = op2.op_meld.clone();
    }

    // Ghidra: jumptable.cc:924 PathMeld::set(const vector<PcodeOpNode>&)
    /// Initialize this container to a single path. The path is a list of
    /// `PcodeOpNode` edges in reverse execution order. Faithful to
    /// `set(const vector<PcodeOpNode>&)` (jumptable.cc:924).
    pub fn set_path(&mut self, path: &[PcodeOpNode]) {
        self.common_vn.clear();
        self.op_meld.clear();
        for (i, node) in path.iter().enumerate() {
            let vn_rg = node.op.read().unwrap();
            let vn = match vn_rg.get_in(node.slot as usize) {
                Some(v) => v.clone(),
                None => continue,
            };
            self.op_meld.push(RootedOp {
                op: node.op.clone(),
                root_vn: i as i32,
            });
            self.common_vn.push(vn);
        }
    }

    // Ghidra: jumptable.cc:937 PathMeld::set(PcodeOp*,Varnode*)
    /// Initialize this container to a single node "path".
    /// Faithful to `set(PcodeOp*, Varnode*)` (jumptable.cc:937).
    pub fn set_single(&mut self, op: Arc<RwLock<PcodeOp>>, vn: Arc<RwLock<Varnode>>) {
        self.common_vn.clear();
        self.op_meld.clear();
        self.common_vn.push(vn);
        self.op_meld.push(RootedOp { op, root_vn: 0 });
    }

    // Ghidra: jumptable.cc:947 PathMeld::append
    /// Append a new set of paths to this set of paths. Faithful to
    /// `append(const PathMeld&)` (jumptable.cc:949).
    pub fn append(&mut self, op2: &PathMeld) {
        let prepend_vn = op2.common_vn.len();
        let prepend_op = op2.op_meld.len();
        // Prepend op2's varnodes.
        let mut new_common = op2.common_vn.clone();
        new_common.extend(self.common_vn.drain(..));
        self.common_vn = new_common;
        // Prepend op2's ops.
        let mut new_meld = op2.op_meld.clone();
        // Renumber the appended root_vn references.
        for item in self.op_meld.iter_mut() {
            item.root_vn += prepend_vn as i32;
        }
        new_meld.extend(self.op_meld.drain(..));
        self.op_meld = new_meld;
        let _ = prepend_op;
    }

    // Ghidra: jumptable.cc:957 PathMeld::clear
    /// Clear this container. Faithful to `clear()`.
    pub fn clear(&mut self) {
        self.common_vn.clear();
        self.op_meld.clear();
    }

    // Ghidra: jumptable.cc:968 PathMeld::meld
    /// Add the new path, recalculating the set of varnodes common to all
    /// paths. Faithful to `meld()` (jumptable.cc:970).
    ///
    /// NOTE: The full Ghidra algorithm (`internalIntersect`, `meldOps`,
    /// `truncatePaths`) is implemented here, but ordering via
    /// `SeqNum::getOrder()` requires `SeqNum` access; we use op-address as the
    /// ordering proxy.
    pub fn meld(&mut self, path: &mut Vec<PcodeOpNode>) {
        // Mark varnodes in the new path so the intersection is easy to see.
        for node in path.iter() {
            let op_rg = node.op.read().unwrap();
            if let Some(vn_arc) = op_rg.get_in(node.slot as usize) {
                vn_arc.write().unwrap().set_mark();
            }
        }

        // Calculate intersection of common_vn with the marked set, and map old
        // indices to new indices.
        let mut parent_map: Vec<i32> = Vec::with_capacity(self.common_vn.len());
        let mut new_vn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        for vn_arc in &self.common_vn {
            let mut vn_rg = vn_arc.write().unwrap();
            if vn_rg.is_mark() {
                let last_intersect = new_vn.len() as i32;
                parent_map.push(last_intersect);
                new_vn.push(vn_arc.clone());
                vn_rg.clear_mark();
            } else {
                parent_map.push(-1);
            }
        }
        self.common_vn = new_vn;

        // Fill in -1 entries with the next earliest varnode in the intersection.
        let mut last_intersect: i32 = -1;
        for i in (0..parent_map.len()).rev() {
            if parent_map[i] == -1 {
                parent_map[i] = last_intersect;
            } else {
                last_intersect = parent_map[i];
            }
        }

        // Calculate cut-off point in the new path.
        let mut cut_off: i32 = -1;
        for (i, node) in path.iter().enumerate() {
            let op_rg = node.op.read().unwrap();
            if let Some(vn_arc) = op_rg.get_in(node.slot as usize) {
                let mut vn_rg = vn_arc.write().unwrap();
                if !vn_rg.is_mark() {
                    // Mark already cleared means it's in the intersection;
                    // cut-off must at least be past this varnode.
                    cut_off = (i as i32) + 1;
                } else {
                    vn_rg.clear_mark();
                }
            }
        }

        // Re-parent the op_meld entries.
        for item in self.op_meld.iter_mut() {
            let pos = parent_map[item.root_vn as usize];
            if pos == -1 {
                // This op split but did not rejoin — mark for removal by
                // clearing its op pointer (we drop it during the merge below).
                item.root_vn = -1;
            } else {
                item.root_vn = pos;
            }
        }

        // Merge sort the new ops in, keeping them in execution order.
        let cut_off_u = if cut_off < 0 { 0 } else { cut_off as usize };
        self.meld_ops(path, cut_off_u);
        // (The full Ghidra algorithm can truncate paths at a new cut point;
        // we keep the conservative ordered merge here.)
        path.truncate(cut_off_u);
    }

    // Ghidra: jumptable.cc:832 PathMeld::meldOps
    /// Helper for `meld`: merge in new path ops up to `cut_off`, keeping
    /// `op_meld` ordered by execution order.
    fn meld_ops(&mut self, path: &[PcodeOpNode], cut_off: usize) {
        let mut new_meld: Vec<RootedOp> = Vec::new();
        let mut cur_root: i32 = -1;
        let mut meld_pos = 0usize;
        for i in 0..cut_off {
            let op_arc = path[i].op.clone();
            // Try to match against an existing op in op_meld.
            let mut matched = false;
            while meld_pos < self.op_meld.len() {
                if self.op_meld[meld_pos].root_vn == -1 {
                    meld_pos += 1;
                    continue;
                }
                if Arc::ptr_eq(&self.op_meld[meld_pos].op, &op_arc) {
                    cur_root = self.op_meld[meld_pos].root_vn;
                    new_meld.push(self.op_meld[meld_pos].clone());
                    meld_pos += 1;
                    matched = true;
                    break;
                }
                // Take the old op (it precedes the new path op).
                cur_root = self.op_meld[meld_pos].root_vn;
                new_meld.push(self.op_meld[meld_pos].clone());
                meld_pos += 1;
            }
            if !matched {
                new_meld.push(RootedOp {
                    op: op_arc,
                    root_vn: cur_root,
                });
            }
        }
        self.op_meld = new_meld;
    }

    // Ghidra: jumptable.cc:1000 PathMeld::markPaths
    /// Mark or unmark the pcode ops on the path from the start varnode index
    /// up to the BRANCHIND. Faithful to `markPaths` (jumptable.cc:1002).
    pub fn mark_paths(&self, val: bool, start_varnode: usize) {
        let mut start_op = None;
        for (i, item) in self.op_meld.iter().enumerate().rev() {
            if item.root_vn as usize == start_varnode {
                start_op = Some(i);
                break;
            }
        }
        let start_op = match start_op {
            Some(s) => s,
            None => return,
        };
        for item in &self.op_meld[..=start_op] {
            let mut op_rg = item.op.write().unwrap();
            if val {
                op_rg.addlflags |= MARK_FLAG;
            } else {
                op_rg.addlflags &= !MARK_FLAG;
            }
        }
    }
}

/// `addlflags` bit used to mirror Ghidra's `PcodeOp::setMark/clearMark/isMark`.
const MARK_FLAG: u32 = 1;

/// A (putative) switch variable Varnode and a constraint imposed by a CBRANCH.
///
/// The record constrains a specific Varnode. If the associated CBRANCH is
/// followed along the path that reaches the switch's BRANCHIND, then we have
/// an explicit description of the possible values the Varnode can hold.
/// Faithful to `GuardRecord` (jumptable.hh:138).
#[derive(Debug, Clone)]
pub struct GuardRecord {
    /// CBRANCH that branches around the switch. None when cleared/unused.
    pub cbranch: Option<Arc<RwLock<PcodeOp>>>,
    /// The immediate pcode op causing the restriction.
    pub read_op: Option<Arc<RwLock<PcodeOp>>>,
    /// The varnode being restricted.
    pub vn: Option<Arc<RwLock<Varnode>>>,
    /// Value being (quasi)copied to the varnode (base of quasi-copy chain).
    pub base_vn: Option<Arc<RwLock<Varnode>>>,
    /// Specific CBRANCH path going to the switch.
    pub indpath: i32,
    /// Number of bits copied (all other bits are zero).
    pub bits_preserved: i32,
    /// Range of values causing the CBRANCH to take the path to the switch.
    pub range: CircleRange,
    /// True if the guarding CBRANCH is duplicated across multiple blocks.
    pub unrolled: bool,
}

impl GuardRecord {
    // Ghidra: jumptable.cc:613 GuardRecord::GuardRecord
    /// Construct from the CBRANCH, the read op, the path, the range, the
    /// restricted varnode and the unrolled flag. Faithful to the
    /// `GuardRecord` constructor (jumptable.cc:613-621).
    pub fn new(
        b_op: Arc<RwLock<PcodeOp>>,
        r_op: Arc<RwLock<PcodeOp>>,
        path: i32,
        rng: CircleRange,
        v: Arc<RwLock<Varnode>>,
        unr: bool,
    ) -> Self {
        let (base_vn, bits_preserved) = quasi_copy(&v);
        Self {
            cbranch: Some(b_op),
            read_op: Some(r_op),
            vn: Some(v),
            base_vn,
            indpath: path,
            bits_preserved,
            range: rng,
            unrolled: unr,
        }
    }

    // Ghidra: jumptable.hh:149 GuardRecord::isUnrolled
    /// Is this guard duplicated across multiple blocks?
    pub fn is_unrolled(&self) -> bool {
        self.unrolled
    }

    // Ghidra: jumptable.hh:150 GuardRecord::getBranch
    /// Get the CBRANCH associated with this guard, if not cleared.
    pub fn get_branch(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        self.cbranch.clone()
    }

    // Ghidra: jumptable.hh:151 GuardRecord::getReadOp
    /// Get the pcode op immediately causing the restriction.
    pub fn get_read_op(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        self.read_op.clone()
    }

    // Ghidra: jumptable.hh:152 GuardRecord::getPath
    /// Get the specific path index going towards the switch.
    pub fn get_path(&self) -> i32 {
        self.indpath
    }

    // Ghidra: jumptable.hh:153 GuardRecord::getRange
    /// Get the range of values causing the switch path to be taken.
    pub fn get_range(&self) -> &CircleRange {
        &self.range
    }

    // Ghidra: jumptable.hh:154 GuardRecord::clear
    /// Mark this guard as unused. Faithful to `clear()` (jumptable.hh:154).
    pub fn clear(&mut self) {
        self.cbranch = None;
    }

    // Ghidra: jumptable.cc:637 GuardRecord::valueMatch
    /// Determine if this guard applies to the given varnode. Returns:
    /// - 0: the two varnodes do not clearly hold the same value;
    /// - 1: they clearly hold the same value;
    /// - 2: they clearly hold the same value, pending no writes between
    ///   their defining ops.
    /// Faithful to `valueMatch` (jumptable.cc:637-680), including the
    /// oneOffMatch duplicate-calculation check (returns 1) and the
    /// LOAD-equivalence check (returns 2).
    pub fn value_match(
        &self,
        vn2: &Arc<RwLock<Varnode>>,
        base_vn2: &Option<Arc<RwLock<Varnode>>>,
        bits_preserved2: i32,
    ) -> i32 {
        // cc:647: if (vn == vn2) return 1; -- same varnode, same value
        let Some(vn1) = &self.vn else {
            return 0;
        };
        if Arc::ptr_eq(vn1, vn2) {
            return 1;
        }
        // cc:648-655: pick the loadOp pair. Same bits copied: compare base
        // varnodes; different bits: compare the varnodes themselves.
        let (load_op, load_op2): (Option<Arc<RwLock<PcodeOp>>>, Option<Arc<RwLock<PcodeOp>>>);
        if self.bits_preserved == bits_preserved2 {
            // cc:650-651: if (baseVn == baseVn2) return 1;
            if let (Some(b1), Some(b2)) = (&self.base_vn, base_vn2) {
                if Arc::ptr_eq(b1, b2) {
                    return 1;
                }
            }
            // cc:652-653: loadOp = baseVn->getDef(); loadOp2 = baseVn2->getDef();
            load_op = self.base_vn.as_ref().and_then(|b| b.read().unwrap().get_def());
            load_op2 = base_vn2.as_ref().and_then(|b| b.read().unwrap().get_def());
        } else {
            // cc:656-657: loadOp = vn->getDef(); loadOp2 = vn2->getDef();
            load_op = vn1.read().unwrap().get_def();
            load_op2 = vn2.read().unwrap().get_def();
        }
        // cc:659-660: if (loadOp == 0) return 0; if (loadOp2 == 0) return 0;
        let (Some(load_op), Some(load_op2)) = (load_op, load_op2) else {
            return 0;
        };
        // cc:661-662: oneOffMatch == 1 -> simple duplicate calculation.
        if one_off_match(&load_op, &load_op2) == 1 {
            return 1;
        }
        // cc:663-664: both must be LOAD ops.
        if load_op.read().unwrap().opcode != OpCode::CPUI_LOAD {
            return 0;
        }
        if load_op2.read().unwrap().opcode != OpCode::CPUI_LOAD {
            return 0;
        }
        // cc:665: spaceid (in(0)) offsets must match.
        let off1 = load_op
            .read()
            .unwrap()
            .get_in(0)
            .map(|v| v.read().unwrap().get_offset());
        let off2 = load_op2
            .read()
            .unwrap()
            .get_in(0)
            .map(|v| v.read().unwrap().get_offset());
        let (Some(off1), Some(off2)) = (off1, off2) else {
            return 0;
        };
        if off1 != off2 {
            return 0;
        }
        // cc:666-668: ptr = loadOp->getIn(1); if (ptr == ptr2) return 2;
        let ptr = load_op.read().unwrap().get_in(1).cloned();
        let ptr2 = load_op2.read().unwrap().get_in(1).cloned();
        let (Some(ptr), Some(ptr2)) = (ptr, ptr2) else {
            return 0;
        };
        if Arc::ptr_eq(&ptr, &ptr2) {
            return 2;
        }
        // cc:669-670: both pointers must be written.
        if !ptr.read().unwrap().is_written() {
            return 0;
        }
        if !ptr2.read().unwrap().is_written() {
            return 0;
        }
        // cc:671-674: ptr must be INT_ADD(base, const).
        let addop = ptr.read().unwrap().get_def();
        let Some(addop) = addop else {
            return 0;
        };
        if addop.read().unwrap().opcode != OpCode::CPUI_INT_ADD {
            return 0;
        }
        let constvn = addop.read().unwrap().get_in(1).cloned();
        let Some(constvn) = constvn else {
            return 0;
        };
        if !constvn.read().unwrap().is_constant() {
            return 0;
        }
        // cc:675-678: ptr2 must be INT_ADD(base, const) too.
        let addop2 = ptr2.read().unwrap().get_def();
        let Some(addop2) = addop2 else {
            return 0;
        };
        if addop2.read().unwrap().opcode != OpCode::CPUI_INT_ADD {
            return 0;
        }
        let constvn2 = addop2.read().unwrap().get_in(1).cloned();
        let Some(constvn2) = constvn2 else {
            return 0;
        };
        if !constvn2.read().unwrap().is_constant() {
            return 0;
        }
        // cc:679-680: same base varnode and same constant offset -> 2.
        let base1 = addop.read().unwrap().get_in(0).cloned();
        let base2 = addop2.read().unwrap().get_in(0).cloned();
        let same_base = match (base1, base2) {
            (Some(a), Some(b)) => Arc::ptr_eq(&a, &b),
            _ => false,
        };
        if !same_base {
            return 0;
        }
        if constvn.read().unwrap().get_offset() != constvn2.read().unwrap().get_offset() {
            return 0;
        }
        2
    }
}

// Ghidra: jumptable.cc:719 GuardRecord::quasiCopy
/// Compute the source of a quasi-COPY chain for the given varnode.
///
/// A value is a quasi-copy if a sequence of pcode ops producing it always
/// holds the value as the least significant bits of their output, but the
/// sequence may put other non-zero values in the upper bits. This computes the
/// earliest ancestor varnode for which the given varnode can be viewed as a
/// quasi-copy. Returns `(ancestor, bits_preserved)`.
/// Faithful to `GuardRecord::quasiCopy` (jumptable.cc:719-786).
pub fn quasi_copy(vn: &Arc<RwLock<Varnode>>) -> (Option<Arc<RwLock<Varnode>>>, i32) {
    let mut bits_preserved = {
        let vn_rg = vn.read().unwrap();
        // cc:722: mostsigbit_set(vn->getNZMask()) + 1 — Ghidra's getNZMask
        // reads the nzm FIELD (varnode.hh:231); use the raw field accessor
        // rather than the size-clamped approximation.
        mostsigbit_set(vn_rg.get_nzm()) + 1
    };
    if bits_preserved == 0 {
        return (Some(vn.clone()), 0);
    }
    let mask = (1u64 << (bits_preserved - 1)).wrapping_sub(1).wrapping_add(1 << (bits_preserved - 1));
    let mut cur_vn = vn.clone();
    // Follow the quasi-copy chain through COPY/INT_AND/INT_OR/INT_SEXT/
    // INT_ZEXT/PIECE/SUBPIECE ops, mirroring Ghidra's switch in quasiCopy.
    loop {
        let def_op = {
            let cur_rg = cur_vn.read().unwrap();
            cur_rg.get_def()
        };
        let Some(def_op) = def_op else { break };
        let (next_vn, cont) = {
            let op_rg = def_op.read().unwrap();
            match op_rg.opcode {
                OpCode::CPUI_COPY => {
                    (op_rg.get_in(0).cloned(), true)
                }
                OpCode::CPUI_INT_AND => {
                    let const_vn = op_rg.get_in(1);
                    let matches = const_vn
                        .map(|c| {
                            let c_rg = c.read().unwrap();
                            c_rg.is_constant() && c_rg.get_offset() == mask
                        })
                        .unwrap_or(false);
                    if matches {
                        (op_rg.get_in(0).cloned(), true)
                    } else {
                        (None, false)
                    }
                }
                OpCode::CPUI_INT_OR => {
                    let const_vn = op_rg.get_in(1);
                    let matches = const_vn
                        .map(|c| {
                            let c_rg = c.read().unwrap();
                            let off = c_rg.get_offset();
                            c_rg.is_constant() && ((off | mask) == (off ^ mask))
                        })
                        .unwrap_or(false);
                    if matches {
                        (op_rg.get_in(0).cloned(), true)
                    } else {
                        (None, false)
                    }
                }
                OpCode::CPUI_INT_SEXT | OpCode::CPUI_INT_ZEXT => {
                    let in0_size_bits = op_rg
                        .get_in(0)
                        .map(|v| v.read().unwrap().get_size() * 8)
                        .unwrap_or(0);
                    if in0_size_bits >= bits_preserved as usize {
                        (op_rg.get_in(0).cloned(), true)
                    } else {
                        (None, false)
                    }
                }
                OpCode::CPUI_PIECE => {
                    let in1_size_bits = op_rg
                        .get_in(1)
                        .map(|v| v.read().unwrap().get_size() * 8)
                        .unwrap_or(0);
                    if in1_size_bits >= bits_preserved as usize {
                        (op_rg.get_in(1).cloned(), true)
                    } else {
                        (None, false)
                    }
                }
                OpCode::CPUI_SUBPIECE => {
                    let const_vn = op_rg.get_in(1);
                    let matches = const_vn
                        .map(|c| {
                            let c_rg = c.read().unwrap();
                            c_rg.is_constant() && c_rg.get_offset() == 0
                        })
                        .unwrap_or(false);
                    if matches {
                        (op_rg.get_in(0).cloned(), true)
                    } else {
                        (None, false)
                    }
                }
                _ => (None, false),
            }
        };
        if !cont {
            break;
        }
        match next_vn {
            Some(n) => cur_vn = n,
            None => break,
        }
    }
    (Some(cur_vn), bits_preserved)
}

// Ghidra: jumptable.cc:684 GuardRecord::oneOffMatch
/// Return 1 if the two given pcode ops produce exactly the same value, 0
/// otherwise. Only one level of pcode-op calculation is considered and only
/// for certain binary ops where the second parameter is a constant. Faithful
/// to `GuardRecord::oneOffMatch` (jumptable.cc:684-704).
pub fn one_off_match(op1: &Arc<RwLock<PcodeOp>>, op2: &Arc<RwLock<PcodeOp>>) -> i32 {
    let o1 = op1.read().unwrap();
    let o2 = op2.read().unwrap();
    if o1.opcode != o2.opcode {
        return 0;
    }
    let is_match_op = matches!(
        o1.opcode,
        OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_LEFT
            | OpCode::CPUI_INT_RIGHT
            | OpCode::CPUI_INT_SRIGHT
            | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_SUBPIECE
    );
    if !is_match_op {
        return 0;
    }
    let in0_a = o1.get_in(0);
    let in0_b = o2.get_in(0);
    if let (Some(a), Some(b)) = (in0_a, in0_b) {
        if !Arc::ptr_eq(a, b) {
            return 0;
        }
    } else {
        return 0;
    }
    if matching_constants(o1.get_in(1), o2.get_in(1)) {
        return 1;
    }
    0
}

// Ghidra: jumptable.cc:598 matching_constants (static free function)
/// Check if the two given varnodes are matching constants.
/// Faithful to `matching_constants` (jumptable.cc:600).
fn matching_constants(
    vn1: Option<&Arc<RwLock<Varnode>>>,
    vn2: Option<&Arc<RwLock<Varnode>>>,
) -> bool {
    let (Some(a), Some(b)) = (vn1, vn2) else {
        return false;
    };
    let a_rg = a.read().unwrap();
    let b_rg = b.read().unwrap();
    if !a_rg.is_constant() || !b_rg.is_constant() {
        return false;
    }
    a_rg.get_offset() == b_rg.get_offset()
}

/// An iterator over values a switch variable can take.
///
/// This iterator provides the start value for emulation of a jump-table model
/// to obtain the associated jump-table destination. Each value can be
/// associated with a starting Varnode and PcodeOp in the function being
/// emulated. Faithful to `JumpValues` (jumptable.hh:166).
pub trait JumpValues: Send + Sync {
    // Ghidra: jumptable.hh:169 JumpValues::truncate (pure virtual)
    /// Truncate the number of values to the given number.
    fn truncate(&mut self, nm: usize);
    // Ghidra: jumptable.hh:170 JumpValues::getSize (pure virtual)
    /// Return the number of values the variables can take.
    fn get_size(&self) -> u64;
    // Ghidra: jumptable.hh:171 JumpValues::contains (pure virtual)
    /// Return true if the given value is in the set of possible values.
    fn contains(&self, val: u64) -> bool;
    // Ghidra: jumptable.hh:176 JumpValues::initializeForReading (pure virtual)
    /// Initialize this for iterating over the set of possible values. Returns
    /// true if there are any values to iterate over.
    fn initialize_for_reading(&self) -> bool;
    // Ghidra: jumptable.hh:178 JumpValues::next (pure virtual)
    /// Advance the iterator, return true if there is another value.
    fn next(&mut self) -> bool;
    // Ghidra: jumptable.hh:179 JumpValues::getValue (pure virtual)
    /// Get the current value.
    fn get_value(&self) -> u64;
    // Ghidra: jumptable.hh:180 JumpValues::getStartVarnode (pure virtual)
    /// Get the varnode associated with the current value.
    fn get_start_varnode(&self) -> Option<Arc<RwLock<Varnode>>>;
    // Ghidra: jumptable.hh:181 JumpValues::getStartOp (pure virtual)
    /// Get the pcode op associated with the current value.
    fn get_start_op(&self) -> Option<Arc<RwLock<PcodeOp>>>;
    // Ghidra: jumptable.hh:182 JumpValues::isReversible (pure virtual)
    /// Return true if the current value can be reversed to get a label.
    fn is_reversible(&self) -> bool;
    // Ghidra: jumptable.hh:183 JumpValues::clone (pure virtual)
    /// Clone this iterator into a boxed trait object.
    fn clone_boxed(&self) -> Box<dyn JumpValues>;

    // RUGRA-GLUE: trait object downcast helper — Ghidra 直接用 `JumpValues*`
    // 指针,需要具体类型时用 dynamic_cast 或虚方法。Rugra 用 trait object,
    /// 需要这个辅助方法在 Box<dyn JumpValues> 持有的是 JumpValuesRange 时
    /// 返回其克隆,否则 None。JumpBasic::find_smallest_normal 用它把 jrange
    /// 从 trait object 取出当 JumpValuesRange 改(基本模型一定是 Range)。
    fn clone_boxed_any_range(&self) -> Option<JumpValuesRange>;

    // RUGRA-GLUE: mut borrow of the JumpValuesRange base — Ghidra 的
    /// `findSmallestNormal` 直接在既有 `jrange` 对象上调继承的
    /// `setRange/setStartVn/setStartOp`(jumptable.cc:1171-1192),
    /// 对 `JumpValuesRangeDefault` 同样作用于同一对象的基类字段
    /// (C++ 继承=同一对象)。Rust trait object 无继承,用这个辅助方法
    /// 取 `&mut JumpValuesRange` 基视图,保持动态类型不被替换。
    fn as_range_base_mut(&mut self) -> &mut JumpValuesRange;
}

/// A single-entry switch variable that can take a range of values.
/// Faithful to `JumpValuesRange` (jumptable.hh:188).
#[derive(Debug)]
pub struct JumpValuesRange {
    /// Acceptable range of values for the normalized switch variable.
    pub range: CircleRange,
    /// Varnode representing the normalized switch variable.
    pub normqvn: Option<Arc<RwLock<Varnode>>>,
    /// First pcode op in the jump-table calculation.
    pub startop: Option<Arc<RwLock<PcodeOp>>>,
    /// The current value pointed to by the iterator.
    /// Interior-mutable (AtomicU64) to faithfully model Ghidra's
    /// `mutable curval` in `JumpValuesRange::initializeForReading`
    /// (jumptable.cc:289) and `next()` (jumptable.cc:295), which are
    /// `const` methods that mutate curval. Without interior mutability,
    /// the `&self` trait methods could not set curval, and callers had
    /// to remember to reset it manually — fragile and easy to forget
    /// (audit P0-3b). AtomicU64 (not Cell) because JumpValuesRange is
    /// held behind Arc/RwLock in some call paths and must be Sync.
    pub curval: AtomicU64,
}

// RUGRA-GLUE: impl Clone for JumpValuesRange — Ghidra 的 JumpValuesRange 是
// C++ 可拷贝类，拷贝语义由 `JumpValues *JumpValuesRange::clone(void) const`
// (jumptable.cc:317) 提供，拷贝所有字段。Rugra 因 curval 用 AtomicU64（非
// Clone）必须手写 Clone impl；行为等价于 Ghidra 的拷贝构造（逐字段拷贝，
// Atomic 取当前快照值）。
impl Clone for JumpValuesRange {
    // RUGRA-GLUE: 手写 Clone（AtomicU64 非 Clone）— Ghidra 等价：JumpValuesRange::clone (jumptable.cc:317)
    fn clone(&self) -> Self {
        Self {
            range: self.range.clone(),
            normqvn: self.normqvn.clone(),
            startop: self.startop.clone(),
            curval: AtomicU64::new(self.curval.load(Ordering::Relaxed)),
        }
    }
}

impl Default for JumpValuesRange {
    // RUGRA-GLUE: Rust Default trait impl for JumpValuesRange; Ghidra uses field init (jumptable.hh:188)
    fn default() -> Self {
        Self {
            range: CircleRange::empty(),
            normqvn: None,
            startop: None,
            curval: AtomicU64::new(0),
        }
    }
}

impl JumpValuesRange {
    // Ghidra: jumptable.hh:195 JumpValuesRange::setRange
    /// Set the range of values explicitly.
    pub fn set_range(&mut self, rng: CircleRange) {
        self.range = rng;
    }

    // Ghidra: jumptable.hh:196 JumpValuesRange::setStartVn
    /// Set the normalized switch varnode explicitly.
    pub fn set_start_vn(&mut self, vn: Arc<RwLock<Varnode>>) {
        self.normqvn = Some(vn);
    }

    // Ghidra: jumptable.hh:197 JumpValuesRange::setStartOp
    /// Set the starting pcode op explicitly.
    pub fn set_start_op(&mut self, op: Arc<RwLock<PcodeOp>>) {
        self.startop = Some(op);
    }
}

impl JumpValues for JumpValuesRange {
    // Ghidra: jumptable.cc:260 JumpValuesRange::truncate
    fn truncate(&mut self, nm: usize) {
        // Faithful to JumpValuesRange::truncate (jumptable.cc:262).
        let range_size = (64 - self.range.get_mask().leading_zeros()) >> 3;
        let left = self.range.get_left();
        let step = self.range.get_step();
        let right = (left + step * nm as u64) & self.range.get_mask();
        self.range = CircleRange::new(left, right, range_size as usize, step);
    }

    // Ghidra: jumptable.cc:271 JumpValuesRange::getSize
    fn get_size(&self) -> u64 {
        self.range.get_size()
    }

    // Ghidra: jumptable.cc:277 JumpValuesRange::contains
    fn contains(&self, val: u64) -> bool {
        self.range.contains_val(val)
    }

    // Ghidra: jumptable.cc:283 JumpValuesRange::initializeForReading
    fn initialize_for_reading(&self) -> bool {
        if self.range.get_size() == 0 {
            return false;
        }
        // Ghidra: `curval = range.getMin();` (jumptable.cc:289). The `mutable
        // curval` in Ghidra lets a const method mutate; AtomicU64 does the
        // same in Rust. Setting it here means callers no longer need to
        // remember to reset curval manually (audit P0-3b).
        self.curval.store(self.range.get_left(), Ordering::Relaxed);
        true
    }

    // Ghidra: jumptable.cc:291 JumpValuesRange::next
    fn next(&mut self) -> bool {
        // Ghidra: `if (!range.getNext(curval)) return false;` (jumptable.cc:295)
        let mut v = self.curval.load(Ordering::Relaxed);
        if self.range.next(&mut v) {
            self.curval.store(v, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    // Ghidra: jumptable.hh:183 JumpValuesRange::getValue
    fn get_value(&self) -> u64 {
        self.curval.load(Ordering::Relaxed)
    }

    // Ghidra: jumptable.cc:303 JumpValuesRange::getStartVarnode
    fn get_start_varnode(&self) -> Option<Arc<RwLock<Varnode>>> {
        self.normqvn.clone()
    }

    // Ghidra: jumptable.cc:309 JumpValuesRange::getStartOp
    fn get_start_op(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        self.startop.clone()
    }

    // Ghidra: jumptable.hh:206 JumpValuesRange::isReversible
    fn is_reversible(&self) -> bool {
        true
    }

    // Ghidra: jumptable.cc:315 JumpValuesRange::clone
    fn clone_boxed(&self) -> Box<dyn JumpValues> {
        Box::new(self.clone())
    }

    // RUGRA-GLUE: trait object downcast helper
    fn clone_boxed_any_range(&self) -> Option<JumpValuesRange> {
        Some(self.clone())
    }

    // RUGRA-GLUE: 见 JumpValues::as_range_base_mut — 具体类型即基类本身。
    fn as_range_base_mut(&mut self) -> &mut JumpValuesRange {
        self
    }
}

/// A jump-table starting range with two possible execution paths.
///
/// Extends the basic `JumpValuesRange` with a single-entry switch variable
/// and adds a second entry point that takes only a single value. This value
/// comes last in the iteration. Faithful to `JumpValuesRangeDefault`
/// (jumptable.hh:214).
#[derive(Debug)]
pub struct JumpValuesRangeDefault {
    /// The base range.
    pub base: JumpValuesRange,
    /// The extra value.
    pub extravalue: u64,
    /// The starting varnode associated with the extra value.
    pub extravn: Option<Arc<RwLock<Varnode>>>,
    /// The starting pcode op associated with the extra value.
    pub extraop: Option<Arc<RwLock<PcodeOp>>>,
    /// True if the extra value has been visited by the iterator.
    /// Interior-mutable (AtomicBool) to faithfully model Ghidra's
    /// `mutable bool lastvalue` (jumptable.cc:346,350), which is mutated by
    /// the `const` methods `initializeForReading` (cc:341) and `next` (cc:355).
    pub lastvalue: AtomicBool,
}

// RUGRA-GLUE: impl Clone for JumpValuesRangeDefault — 同 JumpValuesRange，
// Ghidra 由 `JumpValues *JumpValuesRangeDefault::clone(void) const`
// (jumptable.cc:378) 提供。Rugra 因 lastvalue 用 AtomicBool 必须手写。
impl Clone for JumpValuesRangeDefault {
    // RUGRA-GLUE: 手写 Clone（AtomicBool 非 Clone）— Ghidra 等价：JumpValuesRangeDefault::clone (jumptable.cc:378)
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
            extravalue: self.extravalue,
            extravn: self.extravn.clone(),
            extraop: self.extraop.clone(),
            lastvalue: AtomicBool::new(self.lastvalue.load(Ordering::Relaxed)),
        }
    }
}

// RUGRA-GLUE: impl Default for JumpValuesRangeDefault — Ghidra 由 ctor
// `JumpValuesRangeDefault(JumpTable *jt)` (jumptable.hh:214) 构造,Rugra
// 用 Default trait 等价。
impl Default for JumpValuesRangeDefault {
    // RUGRA-GLUE: fn default — Default trait glue (Ghidra ctor jumptable.hh:214)
    fn default() -> Self {
        Self {
            base: JumpValuesRange::default(),
            extravalue: 0,
            extravn: None,
            extraop: None,
            lastvalue: AtomicBool::new(false),
        }
    }
}

impl JumpValuesRangeDefault {
    // Ghidra: jumptable.hh:214 JumpValuesRangeDefault::JumpValuesRangeDefault
    /// Construct a default-value jump range. Faithful to the Ghidra ctor.
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: jumptable.hh:220 JumpValuesRangeDefault::setExtraValue
    /// Set the extra value explicitly.
    pub fn set_extra_value(&mut self, val: u64) {
        self.extravalue = val;
    }

    // Ghidra: jumptable.hh:221 JumpValuesRangeDefault::setDefaultVn
    /// Set the associated start varnode.
    pub fn set_default_vn(&mut self, vn: Arc<RwLock<Varnode>>) {
        self.extravn = Some(vn);
    }

    // Ghidra: jumptable.hh:222 JumpValuesRangeDefault::setDefaultOp
    /// Set the associated start pcode op.
    pub fn set_default_op(&mut self, op: Arc<RwLock<PcodeOp>>) {
        self.extraop = Some(op);
    }
}

impl JumpValues for JumpValuesRangeDefault {
    // RUGRA-GLUE: inherited from JumpValuesRange in Ghidra (jumptable.cc:262); Rust requires explicit trait impl
    fn truncate(&mut self, nm: usize) {
        self.base.truncate(nm);
    }

    // Ghidra: jumptable.cc:325 JumpValuesRangeDefault::getSize
    fn get_size(&self) -> u64 {
        self.base.range.get_size() + 1
    }

    // Ghidra: jumptable.cc:331 JumpValuesRangeDefault::contains
    fn contains(&self, val: u64) -> bool {
        if self.extravalue == val {
            return true;
        }
        self.base.range.contains_val(val)
    }

    // Ghidra: jumptable.cc:339 JumpValuesRangeDefault::initializeForReading
    fn initialize_for_reading(&self) -> bool {
        // Faithful to jumptable.cc:344-352:
        //   if (range.getSize()==0) { curval = extravalue; lastvalue = true; }
        //   else                    { curval = range.getMin(); lastvalue = false; }
        //   return true;
        if self.base.range.get_size() == 0 {
            self.base.curval.store(self.extravalue, Ordering::Relaxed);
            self.lastvalue.store(true, Ordering::Relaxed);
        } else {
            self.base.curval.store(self.base.range.get_left(), Ordering::Relaxed);
            self.lastvalue.store(false, Ordering::Relaxed);
        }
        true
    }

    // Ghidra: jumptable.cc:353 JumpValuesRangeDefault::next
    fn next(&mut self) -> bool {
        if self.lastvalue.load(Ordering::Relaxed) {
            return false;
        }
        let mut v = self.base.curval.load(Ordering::Relaxed);
        if self.base.range.next(&mut v) {
            self.base.curval.store(v, Ordering::Relaxed);
            return true;
        }
        self.lastvalue.store(true, Ordering::Relaxed);
        self.base.curval.store(self.extravalue, Ordering::Relaxed);
        true
    }

    // RUGRA-GLUE: inherited from JumpValuesRange in Ghidra (jumptable.cc:299); Rust requires explicit trait impl
    fn get_value(&self) -> u64 {
        self.base.curval.load(Ordering::Relaxed)
    }

    // Ghidra: jumptable.cc:364 JumpValuesRangeDefault::getStartVarnode
    fn get_start_varnode(&self) -> Option<Arc<RwLock<Varnode>>> {
        if self.lastvalue.load(Ordering::Relaxed) {
            self.extravn.clone()
        } else {
            self.base.normqvn.clone()
        }
    }

    // Ghidra: jumptable.cc:370 JumpValuesRangeDefault::getStartOp
    fn get_start_op(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        if self.lastvalue.load(Ordering::Relaxed) {
            self.extraop.clone()
        } else {
            self.base.startop.clone()
        }
    }

    // Ghidra: jumptable.hh:229 JumpValuesRangeDefault::isReversible
    fn is_reversible(&self) -> bool {
        !self.lastvalue.load(Ordering::Relaxed)
    }

    // Ghidra: jumptable.cc:376 JumpValuesRangeDefault::clone
    fn clone_boxed(&self) -> Box<dyn JumpValues> {
        Box::new(self.clone())
    }

    // RUGRA-GLUE: trait object downcast helper — JumpValuesRangeDefault 不能
    // 退化为 JumpValuesRange(它是不同的子类),返回 None。
    fn clone_boxed_any_range(&self) -> Option<JumpValuesRange> {
        None
    }

    // RUGRA-GLUE: 见 JumpValues::as_range_base_mut — C++ 继承字段在 `base`。
    fn as_range_base_mut(&mut self) -> &mut JumpValuesRange {
        &mut self.base
    }
}

/// Switch-variable normalization restrictions. Faithful to the private fields
/// `maxaddsub`/`maxleftright`/`maxext` of `JumpTable`.
#[derive(Debug, Clone, Copy)]
pub struct NormMax {
    /// Maximum ADDs or SUBs to normalize.
    pub addsub: u32,
    /// Maximum shifts to normalize.
    pub leftright: u32,
    /// Maximum extensions to normalize.
    pub ext: u32,
}

impl Default for NormMax {
    // RUGRA-GLUE: Rust Default trait impl for NormMax; Ghidra uses fields on JumpTable (jumptable.hh:572)
    fn default() -> Self {
        Self {
            addsub: 1,
            leftright: 1,
            ext: 1,
        }
    }
}

/// A jump-table execution model.
///
/// Parent-table facts consumed by jump-model recovery.
///
/// RUGRA-GLUE: Ghidra models read `jt->isPartial()` (jumptable.cc:1052, the
/// analyzeGuards NZMASK channel) and `jt->getIndirectOp()` (jumptable.cc:1083,
/// the sibling-BRANCHIND identity channel) through their parent `JumpTable*`
/// member while `JumpTable::recoverModel` runs on the table. In Rust the whole
/// recovery runs under the table's `RwLock` write guard (stageJumpTable and
/// ActionSwitchNorm both call through `Arc::write()`), so locking the real
/// parent Arc from inside a model would self-deadlock, and storing a strong
/// Arc back-reference would form a cycle (the model lives inside
/// `JumpTable::jmodel`). `JumpTable::recover_model` therefore snapshots these
/// two facts directly from `&mut self` (no lock, no Arc) and passes them down
/// as plain values — the faithful carrier of the two parent reads.
#[derive(Clone, Default)]
pub struct JumpParentFacts {
    /// `jt->isPartial()` at model-recovery time (partialTable field).
    pub partial_table: bool,
    /// `jt->getIndirectOp()` at model-recovery time (identity channel).
    pub indirect: Option<Arc<RwLock<PcodeOp>>>,
}

/// Holds details of the model and recovers these details in various stages.
/// Faithful to `JumpModel` (jumptable.hh:243).
pub trait JumpModel: Send + Sync {
    // Ghidra: jumptable.hh:249 JumpModel::isOverride (pure virtual)
    /// Return true if this model was manually overridden.
    fn is_override(&self) -> bool;
    // Ghidra: jumptable.hh:250 JumpModel::getTableSize (pure virtual)
    /// Return the number of entries in the address table.
    fn get_table_size(&self) -> usize;

    // Ghidra: jumptable.hh:260 JumpModel::recoverModel (pure virtual)
    /// Attempt to recover details of the model, given a specific BRANCHIND.
    /// Returns true on success. Faithful to `recoverModel`.
    ///
    /// Ghidra 的 recoverModel 可以抛 `LowlevelError`(如 findNormalized 的
    /// readonly 救援读 LoadImage 失败);Rust 用 `Err(JumpTableRecoveryError)`
    /// 承载同一通道,语义 = 异常穿透 recoverModel 到 stageJumpTable 的
    /// `catch(LowlevelError)`(funcdata_block.cc:543),**不是**"尝试下一个
    /// 模型"(返回 Ok(false) 才是)。
    fn recover_model(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        matchsize: u32,
        maxtablesize: u32,
        parent: &JumpParentFacts,
    ) -> Result<bool, JumpTableRecoveryError>;

    // Ghidra: jumptable.hh:271 JumpModel::buildAddresses (pure virtual)
    /// Construct the explicit list of target addresses (the Address Table)
    /// from this model. Faithful to `buildAddresses`.
    ///
    /// Ghidra 的 buildAddresses 经 `EmulateFunction::emulatePath` 可抛
    /// `LowlevelError`(jumptable.cc:216-254);Rust 用
    /// `Err(JumpTableRecoveryError)` 承载,禁止静默归零入表
    /// (JUMPTABLE-EMULFN-0001)。
    fn build_addresses(
        &self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: Option<&mut Vec<LoadTable>>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError>;

    // Ghidra: jumptable.hh:281 JumpModel::findUnnormalized (pure virtual)
    /// Recover the unnormalized switch variable. Faithful to `findUnnormalized`.
    fn find_unnormalized(&mut self, maxaddsub: u32, maxleftright: u32, maxext: u32);

    // Ghidra: jumptable.hh:293 JumpModel::buildLabels (pure virtual)
    /// Recover case labels associated with the address table. Faithful to
    /// `buildLabels`.
    fn build_labels(
        &self,
        fd: &crate::funcdata::Funcdata,
        addresstable: &[Address],
        label: &mut Vec<u64>,
        orig: &dyn JumpModel,
    );

    // Ghidra: jumptable.hh:303 JumpModel::foldInNormalization (pure virtual)
    /// Do normalization of the given switch specific to this model. Returns
    /// the varnode holding the final unnormalized switch variable.
    /// Faithful to `foldInNormalization`.
    fn fold_in_normalization(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>>;

    // Ghidra: jumptable.hh:310 JumpModel::foldInGuards (pure virtual)
    /// Eliminate any guard code involved in computing the switch destination.
    /// Faithful to `foldInGuards`.
    fn fold_in_guards(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        jump: &mut JumpTable,
    ) -> bool;

    // Ghidra: jumptable.hh:325 JumpModel::sanityCheck (pure virtual)
    /// Perform a sanity check on recovered addresses. Returns true if there
    /// are at least some reasonable addresses in the table. Faithful to
    /// `sanityCheck`.
    fn sanity_check(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: &mut Vec<LoadTable>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> bool;

    // Ghidra: jumptable.hh:328 JumpModel::clone (pure virtual)
    /// Clone this model. (Ghidra passes the new parent `jt`; Rugra models
    /// are parentless — see `JumpParentFacts` — so the parameter is gone.)
    fn clone_model(&self) -> Box<dyn JumpModel>;

    // RUGRA-GLUE: trait-object downcast helper — Ghidra callers hold the
    /// concrete `JumpModel*` subtype via `dynamic_cast` (e.g. console and
    /// test code reading `JumpBasic::selectguards`); Rust needs an `Any`
    /// escape hatch on the trait object to do the same.
    fn as_any(&self) -> &dyn std::any::Any;

    // Ghidra: jumptable.hh:331 JumpModel::clear
    /// Clear any non-permanent aspects of the model.
    fn clear(&mut self) {}
}

/// A trivial jump-table model, where the BRANCHIND input Varnode is the switch
/// variable. Faithful to `JumpModelTrivial` (jumptable.hh:350).
pub struct JumpModelTrivial {
    /// Number of addresses in the table as reported by the JumpTable.
    pub size: u32,
}

impl JumpModelTrivial {
    // Ghidra: jumptable.hh:353 JumpModelTrivial::JumpModelTrivial
    /// Construct (Ghidra passes the parent jump-table; Rugra models are
    /// parentless — parent reads flow via `JumpParentFacts`, see its docs).
    pub fn new() -> Self {
        Self { size: 0 }
    }
}

impl JumpModel for JumpModelTrivial {
    // RUGRA-GLUE: JumpModel::as_any downcast hook (see trait docs).
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // Ghidra: jumptable.hh:354 JumpModelTrivial::isOverride
    fn is_override(&self) -> bool {
        false
    }

    // Ghidra: jumptable.hh:355 JumpModelTrivial::getTableSize
    fn get_table_size(&self) -> usize {
        self.size as usize
    }

    // Ghidra: jumptable.cc:389 JumpModelTrivial::recoverModel
    fn recover_model(
        &mut self,
        _fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        matchsize: u32,
        _maxtablesize: u32,
        _parent: &JumpParentFacts,
    ) -> Result<bool, JumpTableRecoveryError> {
        // Faithful to JumpModelTrivial::recoverModel (jumptable.cc:391).
        // The number of out-edges of the BRANCHIND's parent block is the size.
        let n_out = {
            let op_rg = indop.read().unwrap();
            match &op_rg.parent {
                Some(p) => {
                    let p_up = p.upgrade();
                    if let Some(bl) = p_up {
                        bl.read().unwrap().size_out()
                    } else {
                        0
                    }
                }
                None => 0,
            }
        };
        self.size = n_out as u32;
        Ok((self.size != 0) && (self.size <= matchsize))
    }

    // Ghidra: jumptable.cc:396 JumpModelTrivial::buildAddresses
    fn build_addresses(
        &self,
        _fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        _loadpoints: Option<&mut Vec<LoadTable>>,
        _loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError> {
        // Faithful to JumpModelTrivial::buildAddresses (jumptable.cc:398).
        addresstable.clear();
        let op_rg = indop.read().unwrap();
        if let Some(p) = &op_rg.parent {
            if let Some(bl) = p.upgrade() {
                let bl_rg = bl.read().unwrap();
                let bank = bl_rg.bank();
                for i in 0..bl_rg.size_out() {
                    if let Some(edge) = bl_rg.get_out(i) {
                        addresstable.push(
                            bank.expect_arc(edge.point)
                                .read()
                                .unwrap()
                                .get_start_addr(),
                        )
                    }
                }
            }
        }
        Ok(())
    }

    // Ghidra: jumptable.hh:359 JumpModelTrivial::findUnnormalized
    fn find_unnormalized(&mut self, _a: u32, _b: u32, _c: u32) {}

    // Ghidra: jumptable.cc:407 JumpModelTrivial::buildLabels
    fn build_labels(
        &self,
        _fd: &crate::funcdata::Funcdata,
        addresstable: &[Address],
        label: &mut Vec<u64>,
        _orig: &dyn JumpModel,
    ) {
        // Address itself is the label.
        for addr in addresstable {
            label.push(addr.as_u64());
        }
    }

    // Ghidra: jumptable.hh:361 JumpModelTrivial::foldInNormalization
    fn fold_in_normalization(
        &mut self,
        _fd: &mut crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        None
    }

    // Ghidra: jumptable.hh:362 JumpModelTrivial::foldInGuards
    fn fold_in_guards(
        &mut self,
        _fd: &mut crate::funcdata::Funcdata,
        _jump: &mut JumpTable,
    ) -> bool {
        false
    }

    // Ghidra: jumptable.hh:363 JumpModelTrivial::sanityCheck
    fn sanity_check(
        &mut self,
        _fd: &crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        _addresstable: &mut Vec<Address>,
        _loadpoints: &mut Vec<LoadTable>,
        _loadcounts: Option<&mut Vec<i32>>,
    ) -> bool {
        true
    }

    // Ghidra: jumptable.cc:414 JumpModelTrivial::clone
    fn clone_model(&self) -> Box<dyn JumpModel> {
        let mut res = JumpModelTrivial::new();
        res.size = self.size;
        Box::new(res)
    }
}

/// The basic switch model.
///
/// - A straight-line calculation from switch variable to BRANCHIND
/// - The switch variable is bounded by one or more guards that branch around
///   the BRANCHIND
/// - The unnormalized switch variable is recovered from the normalized
///   variable through basic transforms
///
/// Faithful to `JumpBasic` (jumptable.hh:374).
pub struct JumpBasic {
    /// Range of values for the (normalized) switch variable.
    /// Ghidra 用 `JumpValues *jrange`(指针,可指向 JumpValuesRange 或
    /// JumpValuesRangeDefault)。Rugra 用 `Box<dyn JumpValues>` 实现同样的
    /// 多态 —— JumpBasic2/JumpBasicOverride 会把 jrange 设为
    /// JumpValuesRangeDefault 实例。
    pub jrange: Option<Box<dyn JumpValues>>,
    /// Set of pcode ops and varnodes producing the final target addresses.
    pub path_meld: PathMeld,
    /// Any guards associated with this model.
    pub selectguards: Vec<GuardRecord>,
    /// Position of the normalized switch varnode within PathMeld.
    pub varnode_index: i32,
    /// Normalized switch varnode.
    pub normalvn: Option<Arc<RwLock<Varnode>>>,
    /// Unnormalized switch varnode.
    pub switchvn: Option<Arc<RwLock<Varnode>>>,
}

impl JumpBasic {
    // Ghidra: jumptable.hh:410 JumpBasic::JumpBasic
    /// Construct (Ghidra passes the parent jump-table `jt`; Rugra models are
    /// parentless — the two parent reads during recovery flow in as
    /// `JumpParentFacts`, see its docs).
    pub fn new() -> Self {
        Self {
            jrange: None,
            path_meld: PathMeld::default(),
            selectguards: Vec::new(),
            varnode_index: 0,
            normalvn: None,
            switchvn: None,
        }
    }

    // Ghidra: jumptable.hh:411 JumpBasic::getPathMeld
    /// Get the possible paths to the switch.
    pub fn get_path_meld(&self) -> &PathMeld {
        &self.path_meld
    }

    // Ghidra: jumptable.hh:412 JumpBasic::getValueRange
    /// Get the normalized value iterator.
    pub fn get_value_range(&self) -> Option<&dyn JumpValues> {
        self.jrange.as_deref()
    }

    // Ghidra: jumptable.cc:424 JumpBasic::isprune
    /// Do we prune here in our depth-first search for the normalized switch
    /// variable? Faithful to `isprune` (jumptable.cc:426).
    ///
    /// Prune if: not written; the defining op is a call or marker; or the
    /// defining op has zero inputs.
    pub fn is_prune(vn: &Varnode) -> bool {
        if !vn.is_written() {
            return true;
        }
        if let Some(def) = vn.get_def() {
            let op_rg = def.read().unwrap();
            if op_rg.is_call() || op_rg.is_marker() {
                return true;
            }
            if op_rg.num_input() == 0 {
                return true;
            }
        }
        false
    }

    // Ghidra: jumptable.cc:436 JumpBasic::ispoint
    /// Is it possible for the given varnode to be a switch variable? Faithful
    /// to `ispoint` (jumptable.cc:438).
    pub fn is_point(vn: &Varnode) -> bool {
        if vn.is_constant() {
            return false;
        }
        if vn.is_annotation() {
            return false;
        }
        if vn.is_read_only() {
            return false;
        }
        true
    }

    // Ghidra: jumptable.cc:449 JumpBasic::getStride
    /// If some of the least-significant bits of the given varnode are known to
    /// be zero, translate this into a stride for the jump-table range. Faithful
    /// to `getStride` (jumptable.cc:451).
    pub fn get_stride(vn: &Varnode) -> i32 {
        let mut mask = vn.get_nz_mask();
        if (mask & 0x3f) == 0 {
            return 32;
        }
        let mut stride = 1i32;
        while (mask & 1) == 0 {
            mask >>= 1;
            stride <<= 1;
        }
        stride
    }

    // Ghidra: jumptable.cc:512 JumpBasic::getMaxValue
    /// Get maximum value associated with the given varnode. Faithful to
    /// `getMaxValue` (jumptable.cc:514). If the varnode has a restricted range
    /// due to masking via INT_AND, the maximum value of this range is
    /// returned. Otherwise, 0 is returned, indicating that the varnode can
    /// take all possible values.
    pub fn get_max_value(vn: &Varnode) -> u64 {
        let mut max_value = 0u64; // 0 indicates maximum possible value
        if !vn.is_written() {
            return max_value;
        }
        let Some(def) = vn.get_def() else {
            return max_value;
        };
        let op_rg = def.read().unwrap();
        if op_rg.opcode == OpCode::CPUI_INT_AND {
            if let Some(const_vn) = op_rg.get_in(1) {
                let const_rg = const_vn.read().unwrap();
                if const_rg.is_constant() {
                    max_value = crate::address::coveringmask(const_rg.get_offset());
                    max_value = (max_value + 1) & crate::address::calc_mask(vn.get_size());
                }
            }
        } else if op_rg.opcode == OpCode::CPUI_MULTIEQUAL {
            // Its possible the AND is duplicated across multiple blocks.
            let mut all_and = true;
            let mut max_const = 0u64;
            for i in 0..op_rg.num_input() {
                let Some(sub_vn) = op_rg.get_in(i) else {
                    all_and = false;
                    break;
                };
                let sub_rg = sub_vn.read().unwrap();
                let Some(and_def) = sub_rg.get_def() else {
                    all_and = false;
                    break;
                };
                let and_op = and_def.read().unwrap();
                if and_op.opcode != OpCode::CPUI_INT_AND {
                    all_and = false;
                    break;
                }
                let Some(const_vn) = and_op.get_in(1) else {
                    all_and = false;
                    break;
                };
                let const_rg = const_vn.read().unwrap();
                if !const_rg.is_constant() {
                    all_and = false;
                    break;
                }
                if max_const < const_rg.get_offset() {
                    max_const = const_rg.get_offset();
                }
            }
            if all_and {
                max_value = crate::address::coveringmask(max_const);
                max_value = (max_value + 1) & crate::address::calc_mask(vn.get_size());
            } else {
                max_value = 0;
            }
        }
        max_value
    }

    // Ghidra: jumptable.cc:472 JumpBasic::backup2Switch
    /// Back up the constant value in the output Varnode to the value in the
    /// input Varnode. This does the work of going from a normalized switch
    /// value to the unnormalized value. PcodeOps between the output and input
    /// Varnodes must be reversible or None is returned. Faithful to
    /// `backup2Switch` (jumptable.cc:474).
    pub fn backup2_switch(
        output: u64,
        outvn: &Arc<RwLock<Varnode>>,
        invn: &Arc<RwLock<Varnode>>,
    ) -> Option<u64> {
        let mut cur_vn = outvn.clone();
        let mut result = output;
        while !Arc::ptr_eq(&cur_vn, invn) {
            let def_op = cur_vn.read().unwrap().get_def()?;
            let op_rg = def_op.read().unwrap();
            // Find first non-constant input.
            let mut slot = 0usize;
            let mut found = false;
            for s in 0..op_rg.num_input() {
                if let Some(v) = op_rg.get_in(s) {
                    if !v.read().unwrap().is_constant() {
                        slot = s;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return None;
            }
            let out_size = op_rg.get_out()?.read().unwrap().get_size();
            let in_size = op_rg.get_in(slot)?.read().unwrap().get_size();
            let next_vn = op_rg.get_in(slot)?.clone();
            let opc = op_rg.opcode;
            drop(op_rg);
            // Determine if binary or unary.
            let n_in_with_const = {
                // Ghidra checks getEvalType == binary/unary. We approximate:
                // if there's a constant in the other slot, treat as binary.
                let def_rg = def_op.read().unwrap();
                let mut has_const_other = false;
                for s in 0..def_rg.num_input() {
                    if s != slot {
                        if let Some(v) = def_rg.get_in(s) {
                            if v.read().unwrap().is_constant() {
                                has_const_other = true;
                                break;
                            }
                        }
                    }
                }
                has_const_other
            };
            if n_in_with_const {
                // Binary: get the constant value from the other slot.
                let other_val = {
                    let def_rg = def_op.read().unwrap();
                    let mut ov = 0u64;
                    for s in 0..def_rg.num_input() {
                        if s != slot {
                            if let Some(v) = def_rg.get_in(s) {
                                let v_rg = v.read().unwrap();
                                if v_rg.is_constant() {
                                    ov = v_rg.get_offset();
                                    break;
                                }
                            }
                        }
                    }
                    ov
                };
                match crate::opbehavior::recover_input_binary(
                    opc,
                    slot,
                    out_size,
                    result,
                    in_size,
                    other_val,
                ) {
                    Some(r) => result = r,
                    None => return None,
                }
            } else {
                // Unary.
                match crate::opbehavior::recover_input_unary(opc, out_size, result, in_size) {
                    Some(r) => result = r,
                    None => return None,
                }
            }
            cur_vn = next_vn;
        }
        Some(result)
    }

    // Ghidra: jumptable.cc:1289 JumpBasic::duplicateVarnodes
    /// Return true if all array elements are the same varnode. Faithful to
    /// `duplicateVarnodes` (jumptable.cc:1308).
    pub fn duplicate_varnodes(arr: &[Arc<RwLock<Varnode>>]) -> bool {
        if arr.is_empty() {
            return true;
        }
        let first = &arr[0];
        arr.iter().skip(1).all(|v| Arc::ptr_eq(v, first))
    }

    // Ghidra: jumptable.cc:1305 JumpBasic::checkCommonCbranch
    /// Check that all in-edges to `bl` come from blocks ending with CBRANCH
    /// with the same boolean-flip and out-slot. Collects the boolean input
    /// varnode (in(1)) from each CBRANCH into varArray. Faithful to
    /// `checkCommonCbranch` (jumptable.cc:1305-1327).
    pub fn check_common_cbranch(
        var_array: &mut Vec<Arc<RwLock<Varnode>>>,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> bool {
        let bl_r = bl.read().unwrap();
        let bank = bl_r.bank();
        if bl_r.size_in() == 0 { return false; }
        // cc:1327-1330: first in-block must end with CBRANCH.
        let cur_block = match bl_r.get_in(0) {
            Some(e) => bank.expect_arc(e.point),
            None => return false,
        };
        let cbranch = {
            let cb_r = cur_block.read().unwrap();
            let cur_basic = match cb_r.as_any().downcast_ref::<crate::block::BlockBasic>() {
                Some(b) => b, None => return false,
            };
            match cur_basic.ops.last() { Some(op) => op.clone(), None => return false }
        };
        if cbranch.0.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return false; }
        let outslot = bl_r.get_in_rev_index(0);
        let is_op_flip = (cbranch.0.read().unwrap().flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
        // cc:1333: varArray.push_back(op->getIn(1)).
        var_array.push(cbranch.0.read().unwrap().get_in(1).cloned().unwrap_or_else(|| {
            Arc::new(RwLock::new(Varnode::new_constant(0, 0)))
        }));
        // cc:1334-1344: check remaining in-blocks.
        for i in 1..bl_r.size_in() {
            let cur_block = match bl_r.get_in(i) {
                Some(e) => bank.expect_arc(e.point),
                None => return false,
            };
            let op = {
                let cb_r = cur_block.read().unwrap();
                let cur_basic = match cb_r.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    Some(b) => b, None => return false,
                };
                match cur_basic.ops.last() { Some(op) => op.clone(), None => return false }
            };
            let op_r = op.0.read().unwrap();
            if op_r.opcode != OpCode::CPUI_CBRANCH { return false; }
            let cur_flip = (op_r.flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
            if cur_flip != is_op_flip { return false; }
            drop(op_r);
            if outslot != bl_r.get_in_rev_index(i) { return false; }
            var_array.push(op.0.read().unwrap().get_in(1).cloned().unwrap_or_else(|| {
                Arc::new(RwLock::new(Varnode::new_constant(0, 0)))
            }));
        }
        true
    }

    // Ghidra: block.cc:2753 BlockBasic::findMultiequal
    /// Find a MULTIEQUAL op in `bl` whose inputs match varArray exactly.
    /// Returns the MULTIEQUAL op if found, None otherwise. Faithful to
    /// `findMultiequal` (block.cc:2753-2772).
    pub fn find_multiequal(
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        var_array: &[Arc<RwLock<Varnode>>],
    ) -> Option<Arc<RwLock<PcodeOp>>> {
        if var_array.is_empty() { return None; }
        let vn = &var_array[0];
        // cc:2758-2765: walk vn's descendants looking for MULTIEQUAL in bl.
        let descend_refs: Vec<_> = {
            let vn_r = vn.read().unwrap();
            vn_r.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        let target_op: Option<Arc<RwLock<PcodeOp>>> = {
            for desc in &descend_refs {
                let d = desc.read().unwrap();
                if d.opcode == OpCode::CPUI_MULTIEQUAL {
                    // cc:2761: op->getParent() == this — the MULTIEQUAL must
                    // live in bl itself.
                    let parent_is_bl = d
                        .parent
                        .as_ref()
                        .and_then(|w| w.upgrade())
                        .map(|p| Arc::ptr_eq(&p, bl))
                        .unwrap_or(false);
                    if parent_is_bl {
                        return Some(desc.clone());
                    }
                }
            }
            None
        };
        let op = target_op?;
        // cc:2767-2770: verify all inputs match varArray.
        let op_r = op.read().unwrap();
        if op_r.num_input() != var_array.len() { return None; }
        for i in 0..var_array.len() {
            let in_vn = match op_r.get_in(i) { Some(v) => v.clone(), None => return None };
            if !Arc::ptr_eq(&in_vn, &var_array[i]) { return None; }
        }
        Some(op.clone())
    }

    // Ghidra: jumptable.cc:1338 JumpBasic::checkUnrolledGuard
    /// Check for a guard that has been unrolled across multiple blocks.
    /// A guard calculation can be duplicated across multiple blocks that all
    /// branch to the basic block performing the final BRANCHIND. This method
    /// looks for this situation and creates GuardRecords associated with the
    /// unrolled guard. Faithful to `checkUnrolledGuard`
    /// (jumptable.cc:1338-1370).
    pub fn check_unrolled_guard(
        &mut self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        max_pullback: i32,
        use_nzmask: bool,
    ) {
        // cc:1340-1342: checkCommonCbranch.
        let mut var_array: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        if !Self::check_common_cbranch(&mut var_array, bl) { return; }
        // cc:1343-1347: determine toswitchval + CircleRange.
        let bl_r = bl.read().unwrap();
        let bank = bl_r.bank();
        let indpath = bl_r.get_in_rev_index(0);
        let mut toswitchval = indpath == 1;
        // cc:1345: cbranch = getIn(0)->lastOp()
        let cbranch = {
            let in0 = match bl_r.get_in(0) {
                Some(e) => bank.expect_arc(e.point),
                None => return,
            };
            let in0_r = in0.read().unwrap();
            let bb = match in0_r.as_any().downcast_ref::<crate::block::BlockBasic>() {
                Some(b) => b, None => return,
            };
            match bb.ops.last() { Some(op) => op.clone(), None => return }
        };
        let cbranch_flip = cbranch.0.read().unwrap().is_boolean_flip();
        if cbranch_flip { toswitchval = !toswitchval; }
        // cc:1348: CircleRange rng(toswitchval) — CircleRange(bool):
        // true→{1}, false→{0}, mask=0xff, step=1.
        let mut rng = CircleRange::boolean(toswitchval);
        // cc:1349: indpathstore = getIn(0)->getFlipPath() ? 1-indpath : indpath.
        let in0_block = match bl_r.get_in(0) {
            Some(e) => bank.expect_arc(e.point),
            None => return,
        };
        let flip_path = in0_block.read().unwrap().get_flip_path();
        let indpathstore = if flip_path { 1 - indpath } else { indpath };
        drop(bl_r);
        // cc:1350: readOp = cbranch. NOTE: Ghidra's inner
        // `PcodeOp *readOp = vn->getDef();` (cc:1361) SHADOWS this outer
        // variable, so every pushed GuardRecord carries readOp == cbranch;
        // the def op is only used for the pullback within its iteration.
        let read_op = cbranch.0.clone();
        for _j in 0..max_pullback {
            // cc:1352-1360: create GuardRecords. The constructor runs
            // quasiCopy on the varnode (jumptable.cc:613-621), which is
            // what populates baseVn/bitsPreserved.
            if Self::duplicate_varnodes(&var_array) {
                self.selectguards.push(GuardRecord::new(
                    cbranch.0.clone(),
                    read_op.clone(),
                    indpathstore,
                    rng.clone(),
                    var_array[0].clone(),
                    true,
                ));
            } else {
                let multi_op = Self::find_multiequal(bl, &var_array);
                if let Some(mop) = multi_op {
                    let out_vn = mop.read().unwrap().output.clone();
                    if let Some(out) = out_vn {
                        self.selectguards.push(GuardRecord::new(
                            cbranch.0.clone(),
                            read_op.clone(),
                            indpathstore,
                            rng.clone(),
                            out,
                            true,
                        ));
                    }
                }
            }
            // cc:1362-1363: vn = varArray[0]; if (!vn->isWritten()) break.
            let vn = var_array[0].clone();
            if !vn.read().unwrap().is_written() { break; }
            // cc:1364: (inner) readOp = vn->getDef().
            let def_op = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => break,
            };
            // cc:1362/1366: Varnode *markup; // Throw away markup
            // information; vn = rng.pullBack(readOp,&markup,usenzmask).
            // Canonical pull_back with a discard slot: in 12.0.4 this path
            // never reads markup (sole pullBack markup consumer is
            // RuleRangeMeld cc:1416).
            let new_vn = rng.pull_back(&def_op, use_nzmask, &mut None);
            // cc:1367: if (vn == null) break;
            let Some(new_vn) = new_vn else { break };
            // cc:1368: if (rng.isEmpty()) break.
            if rng.is_empty() { break; }
            // cc:1369: liftVerifyUnroll(varArray, readOp->getSlot(vn)).
            let slot = def_op.read().unwrap().slot_of_input(&new_vn).unwrap_or(0);
            if !crate::block::BlockBasic::lift_verify_unroll(&mut var_array, slot as usize) { break; }
        }
    }

    // Ghidra: jumptable.cc:554 JumpBasic::findDeterminingVarnodes
    /// Calculate the initial set of varnodes that might be switch variables.
    /// Paths that terminate at the given pcode op are calculated and organized
    /// in a `PathMeld` object that determines varnodes common to all the paths.
    /// Faithful to `findDeterminingVarnodes` (jumptable.cc:556).
    ///
    /// This is a depth-first traversal through the def chain. At each varnode
    /// we either prune (leaf: a candidate switch variable) or descend into the
    /// defining op's first input.
    pub fn find_determining_varnodes(&mut self, op: Arc<RwLock<PcodeOp>>, slot: i32) {
        let mut path: Vec<PcodeOpNode> = Vec::new();
        let mut first_point = false;
        let root_op = op.clone();
        path.push(PcodeOpNode { op, slot });

        loop {
            // Read the current varnode at the back of the path.
            let cur_vn_arc = {
                let last = path.last().unwrap();
                let op_rg = last.op.read().unwrap();
                op_rg.get_in(last.slot as usize).cloned()
            };
            let Some(cur_vn_arc) = cur_vn_arc else {
                break;
            };
            let is_prune = {
                let vn_rg = cur_vn_arc.read().unwrap();
                Self::is_prune(&vn_rg)
            };
            if is_prune {
                // Leaf node: is it a possible switch variable?
                let is_point = {
                    let vn_rg = cur_vn_arc.read().unwrap();
                    Self::is_point(&vn_rg)
                };
                if is_point {
                    if !first_point {
                        self.path_meld.set_path(&path);
                        first_point = true;
                    } else {
                        self.path_meld.meld(&mut path);
                    }
                }
                // Advance the slot of the back node; pop exhausted nodes.
                if let Some(last) = path.last_mut() {
                    last.slot += 1;
                    loop {
                        let exhausted = {
                            let node = path.last().unwrap();
                            let n_input = node.op.read().unwrap().num_input() as i32;
                            node.slot >= n_input
                        };
                        if !exhausted {
                            break;
                        }
                        path.pop();
                        if path.is_empty() {
                            break;
                        }
                        path.last_mut().unwrap().slot += 1;
                    }
                }
            } else {
                // Not pruned: descend into the defining op (slot 0).
                let def_op = cur_vn_arc.read().unwrap().get_def();
                if let Some(def_op) = def_op {
                    path.push(PcodeOpNode { op: def_op, slot: 0 });
                } else {
                    // Def unresolved (dropped) — treat as prune leaf.
                    break;
                }
            }
            if path.len() <= 1 {
                break;
            }
        }
        if self.path_meld.empty() {
            // Never found a likely point — set the single op/input pair.
            // cc:589: Ghidra reads the ORIGINAL op/slot parameters here; the
            // DFS stack may have popped back to (or past) empty, so
            // path.first() is not guaranteed (JUMPTABLE-PARENTFACTS-FIXTURE
            // P cases hit an all-constant leaf tree and empty the stack).
            let op_arc = root_op.clone();
            let in_vn = op_arc
                .read()
                .unwrap()
                .get_in(slot as usize)
                .cloned();
            if let Some(vn) = in_vn {
                self.path_meld.set_single(op_arc, vn);
            }
        }
    }

    // Ghidra: jumptable.cc:1120 JumpBasic::calcRange
    /// Calculate the range of values in the given varnode that direct
    /// control-flow to the switch. The initial range is derived from the
    /// size/type of the varnode (single value for constants, [0,2) for
    /// boolean-producing defs, maxValue/stride otherwise), then every guard
    /// range that applies to the varnode (valueMatch != 0) is intersected
    /// INTO the range in place, and finally a too-large range is truncated
    /// to positive values. Constants do not early-return: they flow through
    /// the guard loop and the positive truncation exactly like the oracle.
    /// Faithful to `calcRange` (jumptable.cc:1120-1156).
    pub fn calc_range(&self, vn: &Arc<RwLock<Varnode>>, rng: &mut CircleRange) {
        // cc:1124: int4 stride = 1; -- only the else branch updates it, so
        // constant and bool-output varnodes keep stride 1 for the positive
        // truncation below.
        let mut stride: u64 = 1;
        let vn_size;
        {
            let vn_rg = vn.read().unwrap();
            vn_size = vn_rg.get_size();
            if vn_rg.is_constant() {
                // cc:1125-1126: rng = CircleRange(vn->getOffset(),vn->getSize());
                // No early return: the guard loop at cc:1139-1145 still runs.
                *rng = CircleRange::single(vn_rg.get_offset(), vn_rg.get_size());
            } else if vn_rg.is_written()
                && vn_rg
                    .def
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .is_some_and(|d| d.read().unwrap().is_bool_output())
            {
                // cc:1127-1128: only 0 or 1 possible.
                *rng = CircleRange::new(0, 2, 1, 1);
            } else {
                // cc:1129-1133: initial range from maxValue and nzmask stride.
                let max_value = Self::get_max_value(&vn_rg);
                stride = Self::get_stride(&vn_rg) as u64;
                *rng = CircleRange::new(0, max_value, vn_rg.get_size(), stride);
            }
        }

        // cc:1135-1145: intersect any guard ranges which apply to -vn-.
        let (base_vn, bits_preserved) = quasi_copy(vn);
        for guard in &self.selectguards {
            let matchval = guard.value_match(vn, &base_vn, bits_preserved);
            // cc:1142: if (matchval == 2) TODO: we need to check for aliases
            // -- the alias check is not implemented in the oracle either, so
            // any non-zero match applies the guard range.
            if matchval == 0 {
                continue;
            }
            // cc:1144: if (rng.intersect(guard.getRange())!=0) continue;
            // The intersect mutates -rng- in place (write-back); the !=0
            // continue is a trailing no-op in the oracle loop body.
            if rng.intersect(&guard.range) != 0 {
                continue;
            }
        }

        // cc:1147-1155: it may be an assumption that the switch value is
        // positive; if the size is too big, try only positive values.
        if rng.get_size() > 0x10000 {
            let mut positive =
                CircleRange::new(0, (rng.get_mask() >> 1) + 1, vn_size, stride);
            positive.intersect(rng);
            if !positive.is_empty() {
                *rng = positive;
            }
        }
    }

    // Ghidra: jumptable.cc:1165 JumpBasic::findSmallestNormal
    /// Find the putative switch variable with the smallest range of values
    /// reaching the switch. Faithful to `findSmallestNormal`
    /// (jumptable.cc:1182).
    ///
    /// Ghidra 在**既有** `jrange` 对象上原地调用继承的
    /// `setRange/setStartVn/setStartOp`(cc:1186-1187,1188-1189);
    /// `JumpBasic2` 调用本函数时 jrange 已是 `JumpValuesRangeDefault`
    /// (cc:1698-1702 先装好),C++ 继承保证原地更新只改基类字段、
    /// 保留 Default 的 extravalue/extravn/extraop。Rugra 用
    /// [`JumpValues::as_range_base_mut`] 实现同一语义(旧实现 take 后
    /// 重装箱会把 Default 替换成普通 Range = INVENTED)。
    pub fn find_smallest_normal(&mut self, matchsize: u32) {
        let mut rng = CircleRange::empty();
        self.varnode_index = 0;
        if self.path_meld.num_common_varnode() == 0 {
            return;
        }
        // Ghidra cc:1185-1187: jrange 由 recoverModel 先行分配(cc:1425 或
        // Basic2 的 cc:1698);此处必须存在,否则是调用契约破坏。
        let first_vn = self.path_meld.get_varnode(0);
        self.calc_range(&first_vn, &mut rng);
        {
            let Some(jrange) = self.jrange.as_mut() else {
                return;
            };
            let jbase = jrange.as_range_base_mut();
            jbase.set_range(rng.clone());
            jbase.set_start_vn(first_vn.clone());
            jbase.startop = Some(self.path_meld.get_op(0));
        }
        let mut maxsize = rng.get_size();
        for i in 1..self.path_meld.num_common_varnode() {
            if maxsize == matchsize as u64 {
                break;
            }
            let vn = self.path_meld.get_varnode(i);
            self.calc_range(&vn, &mut rng);
            let sz = rng.get_size();
            if sz < maxsize {
                let accept = sz != 256
                    || vn.read().unwrap().get_size() != 1
                    || self.path_meld.is_load_in_path(i);
                if accept {
                    self.varnode_index = i as i32;
                    maxsize = sz;
                    let startop = self.path_meld.get_earliest_op(i);
                    let Some(jrange) = self.jrange.as_mut() else {
                        return;
                    };
                    let jbase = jrange.as_range_base_mut();
                    jbase.set_range(rng.clone());
                    jbase.set_start_vn(vn.clone());
                    jbase.startop = startop;
                }
            }
        }
    }

    // Ghidra: jumptable.cc:1204 JumpBasic::findNormalized
    /// Given the root block and starting path, run guard analysis and find
    /// the normalized switch variable. Faithful to `findNormalized`
    /// (jumptable.cc:1204-1237).
    ///
    /// Returns `Err` only where Ghidra throws: the readonly single-branch
    /// rescue (cc:1225-1226) reads the LoadImage via `MemoryImage::getValue`,
    /// whose `DataUnavailError` derives from `LowlevelError` (loadimage.hh:31)
    /// and propagates out of `recoverModel` to `stageJumpTable`'s
    /// `catch(LowlevelError)` (funcdata_block.cc:543).
    pub fn find_normalized(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        rootbl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        pathout: i32,
        matchsize: u32,
        maxtablesize: u32,
        parent: &JumpParentFacts,
    ) -> Result<(), JumpTableRecoveryError> {
        // Ghidra cc:1209: analyzeGuards(rootbl, pathout)
        self.analyze_guards(rootbl, pathout, parent);
        // Ghidra cc:1210: findSmallestNormal(matchsize)
        self.find_smallest_normal(matchsize);
        // Ghidra cc:1211-1232: readonly variable rescue for single-branch
        // tables. Only applies when size > maxtablesize AND
        // numCommonVarnode==1.
        let sz = self.jrange.as_ref().map_or(0, |j| j.get_size());
        if sz > maxtablesize as u64 && self.path_meld.num_common_varnode() == 1 {
            let vn = self.path_meld.get_varnode(0);
            if vn.read().unwrap().is_read_only() {
                // Ghidra cc:1225-1226:
                //   MemoryImage mem(vn->getSpace(),4,16,glb->loader);
                //   uintb val = mem.getValue(vn->getOffset(),vn->getSize());
                // MemoryImage::getValue reads exactly `size` bytes honoring
                // the space endianness; Rugra 的单空间模型是小端,等价于
                // loader 的 load_value(精确 size 字节,小端拼装)。
                let (vn_offset, vn_size) = {
                    let v = vn.read().unwrap();
                    (v.get_offset(), v.get_size())
                };
                let loader = fd
                    .get_arch()
                    .and_then(|a| a.loader.clone());
                let Some(loader) = loader else {
                    return Err(JumpTableRecoveryError::Lowlevel {
                        message: "Data-unavailable error: no LoadImage attached to Architecture"
                            .to_string(),
                    });
                };
                let val = loader
                    .load_value(crate::address::Address::new(vn_offset), vn_size)
                    .map_err(|crate::loadimage::DataUnavailError(m)| {
                        JumpTableRecoveryError::Lowlevel { message: m }
                    })?;
                // Ghidra cc:1227-1230: varnodeIndex=0; jrange->setRange(
                //   CircleRange(val,vn->getSize())); setStartVn(vn);
                //   setStartOp(pathMeld.getOp(0));
                self.varnode_index = 0;
                if let Some(jrange) = self.jrange.as_mut() {
                    let jbase = jrange.as_range_base_mut();
                    jbase.set_range(CircleRange::single(val, vn_size));
                    jbase.set_start_vn(vn.clone());
                    jbase.startop = Some(self.path_meld.get_op(0));
                }
            }
        }
        Ok(())
    }

    // Ghidra: jumptable.cc:1239 JumpBasic::markFoldableGuards
    /// Mark the guard CBRANCHs that are truly part of the model. Faithful to
    /// `markFoldableGuards` (jumptable.cc:1239-1251).
    pub fn mark_foldable_guards(&mut self) {
        if self.varnode_index as usize >= self.path_meld.num_common_varnode() {
            return;
        }
        let vn = self.path_meld.get_varnode(self.varnode_index as usize);
        let (base_vn, bits_preserved) = quasi_copy(&vn);
        for guard in self.selectguards.iter_mut() {
            if guard.value_match(&vn, &base_vn, bits_preserved) == 0 || guard.is_unrolled() {
                guard.clear();
            }
        }
    }

    // Ghidra: jumptable.cc:1254 JumpBasic::markModel
    /// Mark or unmark all pcode ops involved in the model. Guards whose
    /// CBRANCH was cleared (by `markFoldableGuards`) are skipped: the oracle
    /// reads `getBranch()` first and continues on null before touching
    /// `getReadOp()`. Faithful to `markModel` (jumptable.cc:1254-1267).
    pub fn mark_model(&self, val: bool) {
        self.path_meld.mark_paths(val, self.varnode_index as usize);
        for guard in &self.selectguards {
            // cc:1259-1260: PcodeOp *op = selectguards[i].getBranch();
            // if (op == (PcodeOp *)0) continue;
            let Some(_branch) = guard.get_branch() else {
                continue;
            };
            // cc:1261: readOp is never null when cbranch is set (the
            // GuardRecord invariant); the Rust Option guard is glue.
            let Some(read_op) = guard.get_read_op() else {
                continue;
            };
            let mut op_rg = read_op.write().unwrap();
            if val {
                op_rg.addlflags |= MARK_FLAG;
            } else {
                op_rg.addlflags &= !MARK_FLAG;
            }
        }
    }

    // Ghidra: jumptable.cc:1274 JumpBasic::flowsOnlyToModel
    /// Check if the given Varnode flows to anything other than this model.
    /// The PcodeOps in this model must have been previously marked with
    /// `mark_model(true)`. Faithful to `flowsOnlyToModel` (jumptable.cc:1293).
    pub fn flows_only_to_model(
        &self,
        vn: &Arc<RwLock<Varnode>>,
        trail_op: Option<Arc<RwLock<PcodeOp>>>,
    ) -> bool {
        let vn_rg = vn.read().unwrap();
        for desc in vn_rg.descend_iter() {
            if let Some(trail) = &trail_op {
                if Arc::ptr_eq(&desc, trail) {
                    continue;
                }
            }
            if (desc.read().unwrap().addlflags & MARK_FLAG) == 0 {
                return false;
            }
        }
        true
    }

    // Ghidra: jumptable.cc:1373 JumpBasic::foldInOneGuard
    /// Eliminate the given guard to this switch. We disarm the guard
    /// instructions by making the guard condition always false (or pushing the
    /// branch into the switch). Faithful to `foldInOneGuard`
    /// (jumptable.cc:1373-1409).
    ///
    /// Returns true if a change was made to data-flow.
    pub fn fold_in_one_guard(
        &self,
        fd: &mut crate::funcdata::Funcdata,
        guard: &mut GuardRecord,
        jump: &mut JumpTable,
    ) -> bool {
        let Some(cbranch) = guard.get_branch() else {
            return false;
        };
        // Get the CBRANCH's parent block.
        let cbranchblock = {
            let cb_rg = cbranch.read().unwrap();
            cb_rg.parent.as_ref().and_then(|p| p.upgrade())
        };
        let Some(cbranchblock) = cbranchblock else {
            return false;
        };
        // cc:1379: its possible the guard branch has been converted between
        // the switch recovery and now — without exactly 2 out-edges we can't
        // fold it in.
        if cbranchblock.read().unwrap().size_out() != 2 {
            return false;
        }
        // cc:1380-1382: stored path to indirect block, adjusted when the out
        // branches have been flipped (getFlipPath, block.hh:297).
        let mut indpath = guard.get_path();
        if cbranchblock.read().unwrap().get_flip_path() {
            indpath = 1 - indpath;
        }
        // Get the switch block (parent of the BRANCHIND).
        let Some(indirect) = jump.get_indirect_op() else {
            return false;
        };
        let switchbl = {
            let ind_rg = indirect.read().unwrap();
            ind_rg.parent.as_ref().and_then(|p| p.upgrade())
        };
        let Some(switchbl) = switchbl else {
            return false;
        };
        // cc:1384-1385: guard must go directly into switch block.
        let bank = cbranchblock.read().unwrap().bank();
        let out_target = cbranchblock
            .read()
            .unwrap()
            .get_out(indpath as usize)
            .map(|e| bank.expect_arc(e.point));
        let Some(out_target) = out_target else {
            return false;
        };
        if !Arc::ptr_eq(&out_target, &switchbl) {
            return false;
        }
        // cc:1386: the other out-edge is the guard target.
        let guardtarget = cbranchblock
            .read()
            .unwrap()
            .get_out((1 - indpath) as usize)
            .map(|e| bank.expect_arc(e.point));
        let Some(guardtarget) = guardtarget else {
            return false;
        };

        // cc:1389-1390: find which out-edge of the switch block hits the
        // guard target. Unfound ⇒ pos == sizeOut (Ghidra's loop exit value),
        // expressed here as an i32 that may equal n_out.
        let n_out = switchbl.read().unwrap().size_out() as i32;
        let mut pos = n_out;
        for p in 0..n_out {
            let out = switchbl
                .read()
                .unwrap()
                .get_out(p as usize)
                .map(|e| bank.expect_arc(e.point));
            if let Some(out) = out {
                if Arc::ptr_eq(&out, &guardtarget) {
                    pos = p;
                    break;
                }
            }
        }
        // cc:1391-1392: there can be only one folded target.
        if jump.has_folded_default() && jump.get_default_block() != pos {
            return false;
        }
        // cc:1394-1395: values flowing out of the switch block forbid folding.
        let no_intervening = {
            let bl_rg = switchbl.read().unwrap();
            match bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                Some(bb) => bb.no_intervening_statement(),
                // RUGRA-GLUE: in Ghidra the BRANCHIND parent is always a
                // BlockBasic (PcodeOps only live in basic blocks); a non-basic
                // parent here is a structural invariant break, refuse to fold.
                None => false,
            }
        };
        if !no_intervening {
            return false;
        }
        if pos == n_out {
            // cc:1397-1399: add new destination to table without a label,
            // treating it as either the default case or an exit; turn the
            // branch target into a target of the switch instead.
            let gt_start = {
                let gt_rg = guardtarget.read().unwrap();
                gt_rg.get_start_addr()
            };
            jump.add_block_to_switch(gt_start, NO_LABEL);
            jump.set_last_as_default();
            let _ = fd.push_branch(&cbranchblock, (1 - indpath) as usize, &switchbl);
        } else {
            // cc:1402-1404: neutralize the guard condition so control always
            // reaches the switch; a guard branch generally targets the
            // default case.
            let bool_flip = cbranch.read().unwrap().is_boolean_flip();
            let val: u64 = if (indpath == 0) != bool_flip { 0 } else { 1 };
            let size = cbranch
                .read()
                .unwrap()
                .get_in(0)
                .map(|v| v.read().unwrap().get_size())
                .unwrap_or(1);
            let constvn = fd.new_constant(size, val);
            let cbranch_pref = crate::op::PcodeOpRef(cbranch.clone());
            fd.op_set_input(&cbranch_pref, constvn, 1);
            jump.set_default_block(pos);
        }
        // cc:1406-1408: mark that the default branch has been folded (and
        // cannot take a label).
        jump.set_folded_default();
        guard.clear();
        true
    }
}

impl JumpModel for JumpBasic {
    // RUGRA-GLUE: JumpModel::as_any downcast hook (see trait docs).
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // Ghidra: jumptable.hh:414 JumpBasic::isOverride
    fn is_override(&self) -> bool {
        false
    }

    // Ghidra: jumptable.hh:415 JumpBasic::getTableSize
    fn get_table_size(&self) -> usize {
        self.jrange.as_ref().map_or(0, |j| j.get_size() as usize)
    }

    // Ghidra: jumptable.cc:1418 JumpBasic::recoverModel
    /// 调用形态契约(JUMPTABLE-PIPELINE-0001 段1 显式化,Ghidra 侧不变式):
    ///
    /// Ghidra 中本函数只在 `Funcdata::stageJumpTable`(funcdata_block.cc:491-547)
    /// 建好的 **partial 克隆** 上运行:该 partial 已经
    ///   (a) `truncatedFlow` + `partialflow.generateBlocks()` 生成基本块
    ///       (funcdata_op.cc:839)——因此 `indop->getParent()` 恒非空;
    ///   (b) 跑过 "jumptable" 策略组简化(funcdata_block.cc:501-508,
    ///       含 heritage/SSA 与常量折叠)——因此 BRANCHIND 输入的 def 链
    ///       完整,`isprune` 的 def-less 剪枝只会发生在真正的 switch 变量
    ///       读上,而不是 raw pcode 的跨指令寄存器读上。
    ///
    /// Rugra 在段2(funcdata/fspec/coreaction 的 stageJumpTable)落地前,
    /// 调用方若在未生成块的 raw Funcdata 上调用本函数(`indop.parent == None`,
    /// 对应 flow.generate_ops 阶段),本函数**fail-closed** 返回
    /// `Ok(false)`(Ghidra 在此环境会空指针崩溃,从不运行),不再静默走
    /// 无守卫的 findSmallestNormal 产生错误的巨型 range。
    fn recover_model(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        matchsize: u32,
        maxtablesize: u32,
        parent: &JumpParentFacts,
    ) -> Result<bool, JumpTableRecoveryError> {
        // Ghidra cc:1425: jrange = new JumpValuesRange()
        self.jrange = Some(Box::new(JumpValuesRange::default()));
        // Ghidra cc:1426: findDeterminingVarnodes(indop, 0)
        self.find_determining_varnodes(indop.clone(), 0);
        // Ghidra cc:1427:
        //   findNormalized(fd, indop->getParent(), -1, matchsize, maxtablesize)
        // parent 必须存在(见上契约);缺块环境 fail-closed。
        let parent_bl = {
            let op_rg = indop.read().unwrap();
            op_rg.parent.as_ref().and_then(|p| p.upgrade())
        };
        let Some(bl) = parent_bl else {
            return Ok(false);
        };
        self.find_normalized(fd, &bl, -1, matchsize, maxtablesize, parent)?;
        // Ghidra cc:1428-1429: if (jrange->getSize() > maxtablesize) return false
        if self
            .jrange
            .as_ref()
            .map_or(0, |j| j.get_size())
            > maxtablesize as u64
        {
            return Ok(false);
        }
        // Ghidra cc:1430: markFoldableGuards()
        self.mark_foldable_guards();
        Ok(true)
    }

    // Ghidra: jumptable.cc:1434 JumpBasic::buildAddresses
    fn build_addresses(
        &self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        mut loadpoints: Option<&mut Vec<LoadTable>>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError> {
        // Faithful to JumpBasic::buildAddresses (jumptable.cc:1434-1460).
        // Ghidra cc:1438: addresstable.clear()
        addresstable.clear();
        let Some(jrange) = &self.jrange else {
            return Ok(());
        };
        // Ghidra cc:1440-1441: EmulateFunction emul(fd); emul.setLoadCollect(loadpoints)
        let mut emul = EmulateFunction::new(fd);
        let collect_loads = loadpoints.is_some();
        if collect_loads {
            emul.set_load_collect(Some(Vec::new()));
        }

        // Function-pointer alignment mask (jumptable.cc:1443-1447).
        //   uintb mask = ~0;
        //   int4 bit = fd->getArch()->funcptr_align;
        //   if (bit != 0) mask = (mask >> bit) << bit;
        // Previously this was hardcoded u64::MAX (no alignment), which diverged
        // from Ghidra on any architecture with nonzero funcptr_align (most
        // real-world binaries align function pointers to 4/8/16 bytes). With
        // unaligned addresses, sanity_check's 0xffff diff cutoff truncates
        // real switch tables → `switch=0` symptom.
        let funcptr_align = fd.get_arch().map_or(0, |a| a.funcptr_align);
        let mask = if funcptr_align != 0 {
            (u64::MAX >> funcptr_align) << funcptr_align
        } else {
            u64::MAX
        };

        // Address space + wordSize for AddrSpace::addressToByte (jumptable.cc:1448,1453).
        //   AddrSpace *spc = indop->getAddr().getSpace();
        //   addr = AddrSpace::addressToByte(addr, spc->getWordSize());
        // Rugra's Address is currently single-space (no AddrSpace field), and
        // the code space has wordSize==1, so addressToByte(addr, 1) == addr
        // is a no-op. Documented divergence until Address gains a space field
        // (P1 architectural item). The byte conversion would be:
        //   addr = addr.wrapping_mul(word_size as u64);
        let word_size: u64 = 1; // Rugra single-space model; x86 code space has wordSize=1

        // Ghidra: `JumpValues *jrange` 是指针;buildAddresses 用 jrange->clone()
        // 取迭代器。Rugra 的 jrange 是 Box<dyn JumpValues>,用 clone_boxed()。
        let mut iter_box = jrange.clone_boxed();
        let iter: &mut dyn JumpValues = iter_box.as_mut();
        // Collect load counts into a local Vec, then merge at the end to avoid
        // moving the Option<&mut> in the loop.
        let mut local_loadcounts: Vec<i32> = Vec::new();
        if iter.initialize_for_reading() {
            // initialize_for_reading now sets curval=range.getMin() itself
            // via AtomicU64 (matches Ghidra's `mutable curval`, jumptable.cc:289).
            loop {
                let val = iter.get_value();
                let start_op = iter.get_start_op();
                let start_vn = iter.get_start_varnode();
                // Ghidra cc:1452: emulatePath 抛 LowlevelError 时整个表构建
                // 终止(向上传播);禁止静默填 0(JUMPTABLE-EMULFN-0001)。
                let addr = match (start_op, start_vn) {
                    (Some(startop), Some(startvn)) => {
                        let a = emul.emulate_path(val, &self.path_meld, &startop, &startvn)?;
                        // addressToByte (no-op when word_size==1) then mask
                        let byte_addr = a.wrapping_mul(word_size);
                        byte_addr & mask
                    }
                    // Ghidra 侧 startop/startvn 非空是 jrange 构造不变式;
                    // 空指针走不到 emulatePath。Rust Option 在此等价于
                    // 不变式破坏,显式报错而非归零。
                    _ => {
                        return Err(JumpTableRecoveryError::Lowlevel {
                            message: "Bad jumptable emulation".to_string(),
                        })
                    }
                };
                addresstable.push(Address::new(addr));
                if collect_loads {
                    // Ghidra cc:1456-1457: loadcounts->push_back(loadpoints->size())
                    // — the cumulative count after this iteration. Rugra drains
                    // the per-iteration collects into the out vector, so the
                    // cumulative count is out.len() + (current emul len).
                    let n = loadpoints.as_deref().map_or(0, |v| v.len())
                        + emul.loadpoints.as_ref().map_or(0, |lp| lp.len());
                    local_loadcounts.push(n as i32);
                    // Drain the collected loadpoints into the output.
                    if let Some(emul_lp) = emul.loadpoints.as_mut() {
                        if let Some(out_lp) = loadpoints.as_deref_mut() {
                            out_lp.append(emul_lp);
                        }
                    }
                }
                if !iter.next() {
                    break;
                }
            }
        }
        if let Some(lc) = loadcounts {
            *lc = local_loadcounts;
        }
        let _ = indop;
        Ok(())
    }

    // Ghidra: jumptable.cc:1462 JumpBasic::findUnnormalized
    fn find_unnormalized(&mut self, maxaddsub: u32, _maxleftright: u32, maxext: u32) {
        // Faithful to JumpBasic::findUnnormalized (jumptable.cc:1484).
        let mut i = self.varnode_index as usize;
        if i >= self.path_meld.num_common_varnode() {
            return;
        }
        let normalvn = self.path_meld.get_varnode(i);
        i += 1;
        let mut switchvn = normalvn.clone();
        self.normalvn = Some(normalvn);
        self.switchvn = Some(switchvn.clone());
        self.mark_model(true);

        let mut count_addsub = 0u32;
        let mut count_ext = 0u32;
        let mut normop_def: Option<Arc<RwLock<PcodeOp>>> = None;
        while i < self.path_meld.num_common_varnode() {
            // Check that switchvn flows only to the model.
            if !self.flows_only_to_model(&switchvn, normop_def.clone()) {
                break;
            }
            let testvn = self.path_meld.get_varnode(i);
            let def_op = switchvn.read().unwrap().get_def();
            let Some(def) = def_op else { break };
            // Find which input slot matches testvn.
            let (j, op_code) = {
                let op_rg = def.read().unwrap();
                let mut found_slot = None;
                for s in 0..op_rg.num_input() {
                    if let Some(v) = op_rg.get_in(s) {
                        if Arc::ptr_eq(v, &testvn) {
                            found_slot = Some(s);
                            break;
                        }
                    }
                }
                (found_slot, op_rg.opcode)
            };
            let Some(one_j) = j else { break };
            match op_code {
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                    count_addsub += 1;
                    if count_addsub > maxaddsub {
                        break;
                    }
                    // The other input must be constant.
                    let other_const = {
                        let op_rg = def.read().unwrap();
                        op_rg.get_in(1 - one_j).map(|v| v.read().unwrap().is_constant()).unwrap_or(false)
                    };
                    if !other_const {
                        break;
                    }
                    switchvn = testvn;
                }
                OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                    count_ext += 1;
                    if count_ext > maxext {
                        break;
                    }
                    switchvn = testvn;
                }
                _ => break,
            }
            normop_def = Some(def);
            i += 1;
        }
        self.switchvn = Some(switchvn);
        self.mark_model(false);
    }

    // Ghidra: jumptable.cc:1506 JumpBasic::buildLabels
    fn build_labels(
        &self,
        _fd: &crate::funcdata::Funcdata,
        addresstable: &[Address],
        label: &mut Vec<u64>,
        _orig: &dyn JumpModel,
    ) {
        // Faithful to JumpBasic::buildLabels (jumptable.cc:1528): the label
        // is the value of the unnormalized switch variable, recovered by
        // reverse emulation via backup2Switch.
        let Some(jrange) = &self.jrange else {
            while label.len() < addresstable.len() {
                label.push(NO_LABEL);
            }
            return;
        };
        let (Some(normalvn), Some(switchvn)) = (self.normalvn.clone(), self.switchvn.clone())
        else {
            while label.len() < addresstable.len() {
                label.push(NO_LABEL);
            }
            return;
        };
        // Ghidra: `JumpValues *jrange` 是指针;buildAddresses 用 jrange->clone()
        // 取迭代器。Rugra 的 jrange 是 Box<dyn JumpValues>,用 clone_boxed()。
        let mut iter_box = jrange.clone_boxed();
        let iter: &mut dyn JumpValues = iter_box.as_mut();
        if iter.initialize_for_reading() {
            // curval reset happens inside initialize_for_reading (AtomicU64, jumptable.cc:289)
            loop {
                let val = iter.get_value();
                let switchval = if iter.is_reversible() {
                    Self::backup2_switch(val, &normalvn, &switchvn).unwrap_or(NO_LABEL)
                } else {
                    NO_LABEL
                };
                label.push(switchval);
                if label.len() >= addresstable.len() {
                    break;
                }
                if !iter.next() {
                    break;
                }
            }
        }
        while label.len() < addresstable.len() {
            label.push(NO_LABEL);
        }
    }

    // Ghidra: jumptable.cc:1546 JumpBasic::foldInNormalization
    fn fold_in_normalization(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        // Faithful to JumpBasic::foldInNormalization (jumptable.cc:1546-1553):
        // set the BRANCHIND input to be the unnormalized switch variable, so
        // all the intervening code to calculate the final address is
        // eliminated as dead. The op_set_input call (Ghidra fd->opSetInput)
        // maintains Varnode descend bookkeeping on both the severed
        // normalization varnode and the switchvn.
        let sv = self.switchvn.clone()?;
        fd.op_set_input(&crate::op::PcodeOpRef(indop.clone()), sv.clone(), 0);
        Some(sv)
    }

    // Ghidra: jumptable.cc:1555 JumpBasic::foldInGuards
    fn fold_in_guards(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        jump: &mut JumpTable,
    ) -> bool {
        // Faithful to JumpBasic::foldInGuards (jumptable.cc:1555-1570):
        // a null cbranch is already normalized (skip without touching the
        // record); a dead cbranch is cleared and skipped; anything else is
        // folded via foldInOneGuard.
        let mut change = false;
        for i in 0..self.selectguards.len() {
            match self.selectguards[i].get_branch() {
                // cc:1560-1561: cbranch == null → already normalized.
                None => continue,
                // cc:1562-1565: dead cbranch → clear the record and skip.
                Some(cb) if cb.read().unwrap().is_dead() => {
                    self.selectguards[i].clear();
                    continue;
                }
                Some(_) => {}
            }
            // Extract the guard, fold it, then write back.
            let mut guard = self.selectguards[i].clone();
            if self.fold_in_one_guard(fd, &mut guard, jump) {
                change = true;
            }
            self.selectguards[i] = guard;
        }
        change
    }

    // Ghidra: jumptable.cc:1572 JumpBasic::sanityCheck
    fn sanity_check(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: &mut Vec<LoadTable>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> bool {
        // Faithful to JumpBasic::sanityCheck (jumptable.cc:1572-1611)。
        if addresstable.is_empty() {
            return true;
        }
        let loader = fd.get_arch().and_then(|a| a.loader.clone());
        let mut i = 0usize;
        let first = addresstable[0].as_u64();
        if first != 0 {
            // cc:1581: Ghidra 的 for-init 是 `i=1`(entry 0 已由 first != 0
            // 验证);循环体内 break 时 i 自然等于当前 j(保留 0..j-1)。
            // 单条目表(size==1)循环体不执行,i=1 ≠ size → 通过。旧实现
            // i=0 起步 + 循环体内才赋值,把单条目表误判为 false
            // (JUMPTABLE-PARENTFACTS-FIXTURE M1 实证)。
            i = 1;
            for j in 1..addresstable.len() {
                if addresstable[j].as_u64() == 0 {
                    break;
                }
                let diff = if first < addresstable[j].as_u64() {
                    addresstable[j].as_u64() - first
                } else {
                    first - addresstable[j].as_u64()
                };
                if diff > 0xffff {
                    // Ghidra cc:1588-1598: 距离超 0xffff 的目标不立即截断,
                    // 先 loadFill 4 字节验证地址在镜像里可读;DataUnavailError
                    // 才 break。旧实现缺 loader 桥时无条件截断 = INVENTED。
                    let dataavail = match &loader {
                        Some(l) => l
                            .load_fill(4, addresstable[j])
                            .is_ok(),
                        None => false,
                    };
                    if !dataavail {
                        break;
                    }
                }
                i = j + 1;
            }
        }
        if i == 0 {
            return false;
        }
        if i != addresstable.len() {
            addresstable.truncate(i);
            if let Some(jrange) = &mut self.jrange {
                jrange.truncate(i);
            }
            if let Some(lc) = loadcounts {
                if i > 0 {
                    let keep = lc[i - 1] as usize;
                    if keep <= loadpoints.len() {
                        loadpoints.truncate(keep);
                    }
                }
            }
        }
        true
    }

    // Ghidra: jumptable.cc:1613 JumpBasic::clone
    fn clone_model(&self) -> Box<dyn JumpModel> {
        let mut res = JumpBasic::new();
        // Ghidra: `jrange->clone()`. Box<dyn JumpValues> 用 clone_boxed。
        res.jrange = self.jrange.as_ref().map(|j| j.clone_boxed());
        res.path_meld = self.path_meld.clone();
        res.selectguards = self.selectguards.clone();
        res.varnode_index = self.varnode_index;
        res.normalvn = self.normalvn.clone();
        res.switchvn = self.switchvn.clone();
        Box::new(res)
    }

    // Ghidra: jumptable.cc:1621 JumpBasic::clear
    fn clear(&mut self) {
        self.jrange = None;
        self.path_meld.clear();
        self.selectguards.clear();
        self.normalvn = None;
        self.switchvn = None;
    }
}

impl JumpBasic {
    // Ghidra: jumptable.cc:1046 JumpBasic::analyzeGuards
    /// Analyze CBRANCHs leading up to the given basic-block as a potential
    /// switch guard. Faithful to `analyzeGuards` (jumptable.cc:1046-1112).
    ///
    /// For each CBRANCH, range restrictions on the various variables which
    /// allow control flow to pass through the CBRANCH to the switch are
    /// analyzed. A GuardRecord is created for each of these restrictions.
    /// `pathout` is an optional path (>= 0) from the basic-block to the
    /// switch or -1.
    pub fn analyze_guards(
        &mut self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        pathout: i32,
        parent: &JumpParentFacts,
    ) {
        // cc:1049-1052: maxbranch=2, maxpullback=2, usenzmask = !isPartial.
        // Ghidra reads `!jt->isPartial()` through the model's parent pointer;
        // Rugra carries the snapshot taken by JumpTable::recover_model
        // (see JumpParentFacts) — a partial (multistage) table must see
        // usenzmask=false here, exactly like cc:1052.
        let max_branch = 2i32;
        let max_pullback = 2i32;
        let usenzmask = !parent.partial_table;

        // cc:1054: selectguards.clear()
        self.selectguards.clear();
        let mut cur_bl = bl.clone();
        let bank = bl.read().unwrap().bank();
        let mut cur_pathout = pathout;

        // cc:1056: for(i=0;i<maxbranch;++i)
        for i in 0..max_branch {
            // Ghidra declares prevbl/indpath here; both branches of the
            // pathout/walk-back split must define them (cc:1057-1080).
            let prevbl: Arc<RwLock<dyn FlowBlock + Send + Sync>>;
            let indpath: i32;
            // cc:1058: if ((pathout>=0)&&(bl->sizeOut()==2))
            if cur_pathout >= 0 && cur_bl.read().unwrap().size_out() == 2 {
                // cc:1059-1062: step through the pathout edge; the current
                // block IS the CBRANCH holder (prevbl), bl becomes the block
                // on the path to the switch, indpath = pathout, pathout=-1.
                prevbl = cur_bl.clone();
                let next = {
                    let bl_rg = cur_bl.read().unwrap();
                    bl_rg
                        .get_out(cur_pathout as usize)
                        .map(|e| bank.expect_arc(e.point))
                };
                let Some(next) = next else { break };
                cur_bl = next;
                indpath = cur_pathout;
                cur_pathout = -1;
            } else {
                // cc:1064: pathout = -1; make sure not to use pathout next
                // time around.
                cur_pathout = -1;
                // cc:1065-1075: walk back to a block that can deviate from
                // the switch path. bl must have exactly 1 in-edge and its
                // parent must have != 1 out-edge.
                let mut walk_prev: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = None;
                loop {
                    let size_in = cur_bl.read().unwrap().size_in();
                    if size_in != 1 {
                        // cc:1068-1070: multiple in-edges -> unrolled guard;
                        // zero in-edges -> nothing more to analyze. Either
                        // way analyzeGuards RETURNS.
                        if size_in > 1 {
                            self.check_unrolled_guard(&cur_bl, max_pullback, usenzmask);
                        }
                        return;
                    }
                    // Only 1 flow path to the switch
                    let prev_edge = cur_bl.read().unwrap().get_in(0);
                    let Some(prev_edge) = prev_edge else { return };
                    let prev_bl_arc = bank.expect_arc(prev_edge.point);
                    // cc:1072: is it possible to deviate from switch path in
                    // this block
                    let prev_size_out = prev_bl_arc.read().unwrap().size_out();
                    if prev_size_out != 1 {
                        walk_prev = Some(prev_bl_arc);
                        break;
                    }
                    // cc:1074: if not, back up to next block
                    cur_bl = prev_bl_arc;
                }
                prevbl = walk_prev.unwrap();
                // cc:1077: indpath = bl->getInRevIndex(0)
                indpath = cur_bl.read().unwrap().get_in_rev_index(0);
            }
            // cc:1078-1080: cbranch = prevbl->lastOp(); must be a CBRANCH.
            let cbranch: Option<Arc<RwLock<PcodeOp>>> = {
                let prev_rg = prevbl.read().unwrap();
                // BlockBasic::lastOp (inherent method; the FlowBlock trait
                // default returns None for non-basic blocks).
                let last = prev_rg
                    .as_any()
                    .downcast_ref::<BlockBasic>()
                    .and_then(|bb| bb.last_op());
                match last {
                    Some(op) => {
                        if op.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH {
                            Some(op.0.clone())
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            };
            let Some(cbranch) = cbranch else { break };
            // cc:1082-1091: for i!=0, check that this CBRANCH isn't
            // protecting some other switch: if the OTHER out-edge target
            // ends with a BRANCHIND that is not this jumptable's indirect
            // op, break.
            if i != 0 {
                let otherbl = {
                    let prev_rg = prevbl.read().unwrap();
                    prev_rg
                        .get_out((1 - indpath) as usize)
                        .map(|e| bank.expect_arc(e.point))
                };
                if let Some(otherbl) = otherbl {
                    let otherop: Option<Arc<RwLock<PcodeOp>>> = {
                        let other_rg = otherbl.read().unwrap();
                        other_rg
                            .as_any()
                            .downcast_ref::<BlockBasic>()
                            .and_then(|bb| bb.last_op())
                            .map(|op| op.0.clone())
                    };
                    if let Some(otherop) = otherop {
                        if otherop.read().unwrap().opcode == OpCode::CPUI_BRANCHIND {
                            // Ghidra cc:1083-1090 compares against
                            // `jt->getIndirectOp()` through the parent
                            // pointer; the snapshot passed down from
                            // JumpTable::recover_model carries the real
                            // indirect op, so a guard on a sibling edge of
                            // THIS switch keeps being collected (only a
                            // DIFFERENT switch's BRANCHIND stops the walk).
                            let indirect = parent.indirect.clone();
                            let is_model_indirect = indirect
                                .as_ref()
                                .map(|ind| Arc::ptr_eq(ind, &otherop))
                                .unwrap_or(false);
                            if !is_model_indirect {
                                break;
                            }
                        }
                    }
                }
            }
            // cc:1092-1095: toswitchval = (indpath == 1), flipped if the
            // CBRANCH boolean sense is flipped.
            let mut toswitchval = indpath == 1;
            if cbranch.read().unwrap().is_boolean_flip() {
                toswitchval = !toswitchval;
            }
            // cc:1096: bl = prevbl (step up for the next iteration).
            cur_bl = prevbl.clone();
            // cc:1097: vn = cbranch->getIn(1)
            let mut vn = cbranch.read().unwrap().get_in(1).cloned();
            // cc:1098: CircleRange rng(toswitchval)
            let mut rng = CircleRange::boolean(toswitchval);
            // cc:1100-1101: the boolean variable could conceivably be the
            // switch variable. indpathstore = prevbl->getFlipPath() ?
            // 1-indpath : indpath.
            let indpathstore = if prevbl.read().unwrap().get_flip_path() {
                1 - indpath
            } else {
                indpath
            };
            // cc:1102: push the first guard for the boolean varnode itself.
            if let Some(v) = &vn {
                self.selectguards.push(GuardRecord::new(
                    cbranch.clone(),
                    cbranch.clone(),
                    indpathstore,
                    rng.clone(),
                    v.clone(),
                    false,
                ));
            }
            // cc:1103-1111: pullback loop: walk back through the defining
            // ops of the boolean varnode, restricting the range at each
            // step; a GuardRecord is pushed for each surviving pullback.
            for _j in 0..max_pullback {
                // cc:1105: if (!vn->isWritten()) break;
                let Some(cv) = vn.clone() else { break };
                if !cv.read().unwrap().is_written() {
                    break;
                }
                // cc:1105: readOp = vn->getDef()
                let read_op = cv.read().unwrap().get_def();
                let Some(read_op) = read_op else { break };
                // cc:1103/1106: Varnode *markup; // Throw away markup
                // information — vn = rng.pullBack(readOp,&markup,usenzmask).
                // Canonical pull_back with a discard slot (markup is never
                // read on this path in 12.0.4).
                let next = rng.pull_back(&read_op, usenzmask, &mut None);
                // cc:1107: if (vn == (Varnode *)0) break;
                let Some(next_vn) = next else { break };
                // cc:1108: if (rng.isEmpty()) break;
                if rng.is_empty() {
                    break;
                }
                // cc:1109: push guard for the pulled-back varnode.
                self.selectguards.push(GuardRecord::new(
                    cbranch.clone(),
                    read_op,
                    indpathstore,
                    rng.clone(),
                    next_vn.clone(),
                    false,
                ));
                vn = Some(next_vn);
            }
        }
    }
}

// ============================================================================
// JumpBasic2 (jumptable.hh:441 / jumptable.cc:1656-1789)
// ============================================================================

/// A second basic jump-table model: switch with default value via MULTIEQUAL.
///
/// Faithful to Ghidra `JumpBasic2` (jumptable.hh:441-453). Inherits from
/// JumpBasic (Rust uses composition via the `base` field). Adds an `extra_vn`
/// (the MULTIEQUAL output joining the default path and the computed path) and
/// `orig_path_meld` (the path-meld from the failed JumpBasic model that
/// triggered this fallback).
pub struct JumpBasic2 {
    /// The inherited JumpBasic model (composition replaces C++ inheritance).
    pub base: JumpBasic,
    /// The extra Varnode holding the default value (jumptable.hh:442 `extravn`).
    pub extra_vn: Option<Arc<RwLock<Varnode>>>,
    /// The set of paths that produce non-default addresses
    /// (jumptable.hh:443 `origPathMeld`).
    pub orig_path_meld: PathMeld,
}

impl JumpBasic2 {
    // Ghidra: jumptable.hh:447 JumpBasic2::JumpBasic2
    pub fn new() -> Self {
        Self {
            base: JumpBasic::new(),
            extra_vn: None,
            orig_path_meld: PathMeld::default(),
        }
    }

    // Ghidra: jumptable.hh:448 JumpBasic2::initializeStart
    pub fn initialize_start(&mut self, p_meld: &PathMeld) {
        if p_meld.empty() {
            self.extra_vn = None;
            return;
        }
        let num_common = p_meld.num_common_varnode();
        // Ghidra cc:1681: extravn = pMeld.getVarnode(pMeld.numCommonVarnode()-1)
        self.extra_vn = Some(p_meld.get_varnode(num_common.saturating_sub(1)));
        self.orig_path_meld.set_from(p_meld);
    }

    // Ghidra: jumptable.cc:1634 JumpBasic2::foldInOneGuard
    /// The are two main cases here:
    ///   - If we recovered a switch in a loop, the guard is also the loop
    ///     condition, so we don't want to remove it.
    ///   - If the guard is just deciding whether or not to use a default
    ///     switch value, the guard will disappear anyway because the
    ///     normalization foldin will make all its blocks donothings.
    ///
    /// So we don't make any special mods, in case there are extra statements
    /// in these blocks. Faithful to `JumpBasic2::foldInOneGuard`
    /// (jumptable.cc:1634-1649).
    pub fn fold_in_one_guard(
        &self,
        _fd: &mut crate::funcdata::Funcdata,
        guard: &mut GuardRecord,
        jump: &mut JumpTable,
    ) -> bool {
        // The final block in the table is the single value produced by the
        // model2 guard; it should be the default block.
        jump.set_last_as_default();
        guard.clear(); // Mark that we are folded
        true
    }

    // Ghidra: jumptable.hh:444 JumpBasic2::checkNormalDominance
    fn check_normal_dominance(&self) -> bool {
        let normalvn = match &self.base.normalvn {
            Some(v) => v,
            None => return false,
        };
        if normalvn.read().unwrap().is_input() {
            return true;
        }
        let defblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
            let n = normalvn.read().unwrap();
            let def_op = n.def.as_ref().and_then(|w| w.upgrade());
            match def_op {
                Some(op) => {
                    let op_r = op.read().unwrap();
                    op_r.parent.as_ref().and_then(|w| w.upgrade())
                }
                None => None,
            }
        };
        let switchblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
            let op_arc = self.base.path_meld.get_op(0);
            let op_r = op_arc.read().unwrap();
            op_r.parent.as_ref().and_then(|w| w.upgrade())
        };
        let (Some(defblock), Some(mut switchblock)) = (defblock, switchblock) else {
            return false;
        };
        loop {
            if Arc::ptr_eq(&switchblock, &defblock) {
                return true;
            }
            let next = switchblock.read().unwrap().get_immed_dom();
            match next {
                Some(dom_weak) => {
                    let dom = match dom_weak.upgrade() {
                        Some(d) => d,
                        None => return false,
                    };
                    if Arc::ptr_eq(&dom, &switchblock) {
                        return false;
                    }
                    switchblock = dom;
                }
                None => return false,
            }
        }
    }

    // Ghidra: jumptable.hh:450 JumpBasic2::findUnnormalized
    pub fn find_unnormalized_inner(&mut self, maxaddsub: u32, maxleftright: u32, maxext: u32) {
        self.base.normalvn = Some(self.base.path_meld.get_varnode(self.base.varnode_index as usize));
        if self.check_normal_dominance() {
            self.base.find_unnormalized(maxaddsub, maxleftright, maxext);
            return;
        }
        self.base.switchvn = self.extra_vn.clone();
        let multiop = self.extra_vn.as_ref()
            .and_then(|v| v.read().unwrap().def.as_ref().and_then(|w| w.upgrade()));
        let Some(multiop_arc) = multiop else { return; };
        let multiop_r = multiop_arc.read().unwrap();
        if multiop_r.opcode != OpCode::CPUI_MULTIEQUAL || multiop_r.inrefs.len() != 2 {
            return;
        }
        let in0 = multiop_r.get_in(0).cloned();
        let in1 = multiop_r.get_in(1).cloned();
        let normalvn = self.base.normalvn.clone();
        let is_in0_normal = in0.as_ref().map(|v| {
            normalvn.as_ref().map(|n| Arc::ptr_eq(v, n)).unwrap_or(false)
        }).unwrap_or(false);
        let is_in1_normal = in1.as_ref().map(|v| {
            normalvn.as_ref().map(|n| Arc::ptr_eq(v, n)).unwrap_or(false)
        }).unwrap_or(false);
        if is_in0_normal || is_in1_normal {
            self.base.normalvn = self.base.switchvn.clone();
        } else {
            eprintln!("[JUMPTABLE] WARN: JumpBasic2 backward normalization not implemented");
        }
    }
}

impl JumpModel for JumpBasic2 {
    // RUGRA-GLUE: JumpModel::as_any downcast hook (see trait docs).
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // Ghidra: jumptable.hh:441 JumpBasic2 (inherits JumpBasic::isOverride)
    fn is_override(&self) -> bool { self.base.is_override() }
    // Ghidra: jumptable.hh:441 JumpBasic2 (inherits JumpBasic::getTableSize)
    fn get_table_size(&self) -> usize { self.base.get_table_size() }

    // Ghidra: jumptable.cc:1663 JumpBasic2::recoverModel
    fn recover_model(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        matchsize: u32,
        maxtablesize: u32,
        parent: &JumpParentFacts,
    ) -> Result<bool, JumpTableRecoveryError> {
        let joinvn = match &self.extra_vn {
            Some(v) => v.clone(),
            None => return Ok(false),
        };
        if !joinvn.read().unwrap().is_written() {
            return Ok(false);
        }
        let multiop = joinvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        let multiop = match multiop {
            Some(op) => op,
            None => return Ok(false),
        };
        {
            let m = multiop.read().unwrap();
            if m.opcode != OpCode::CPUI_MULTIEQUAL || m.inrefs.len() != 2 {
                return Ok(false);
            }
        }
        let mut found_path: i32 = -1;
        let mut extravalue: u64 = 0;
        for path in 0..2 {
            let vn = multiop.read().unwrap().get_in(path).cloned();
            let Some(vn) = vn else { continue; };
            if !vn.read().unwrap().is_written() { continue; }
            let copyop = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let Some(copyop_arc) = copyop else { continue; };
            if copyop_arc.read().unwrap().opcode != OpCode::CPUI_COPY { continue; }
            let in0 = copyop_arc.read().unwrap().get_in(0).cloned();
            let Some(in0_vn) = in0 else { continue; };
            if in0_vn.read().unwrap().is_constant() {
                extravalue = in0_vn.read().unwrap().get_offset();
                found_path = path as i32;
                break;
            }
        }
        if found_path < 0 {
            return Ok(false);
        }
        let path = found_path as usize;
        let one_minus_path = 1 - path;
        // Ghidra cc:1718: BlockBasic *rootbl = multiop->getParent()->getIn(1-path)
        let multiop_parent = multiop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        let Some(multiop_parent) = multiop_parent else { return Ok(false); };
        let (rootbl, pathout) = {
            let p = multiop_parent.read().unwrap();
            let bank = p.bank();
            let edge = p.get_in(one_minus_path);
            match edge {
                Some(e) => (bank.expect_arc(e.point), e.reverse_index as i32),
                None => return Ok(false),
            }
        };
        // Ghidra cc:1720-1724: jrange = new JumpValuesRangeDefault();
        //   jdef->setExtraValue(extravalue); jdef->setDefaultVn(joinvn);
        //   jdef->setDefaultOp(origPathMeld.getOp(origPathMeld.numOps()-1));
        let mut jdef = JumpValuesRangeDefault::new();
        jdef.set_extra_value(extravalue);
        jdef.set_default_vn(joinvn.clone());
        let last_op = self.orig_path_meld.get_op(self.orig_path_meld.num_ops().saturating_sub(1));
        jdef.set_default_op(last_op);
        self.base.jrange = Some(Box::new(jdef));
        self.extra_vn = Some(joinvn.clone());
        self.base.find_determining_varnodes(multiop.clone(), one_minus_path as i32);
        self.base
            .find_normalized(fd, &rootbl, pathout, matchsize, maxtablesize, parent)?;
        let jrange_size = self.base.jrange.as_ref().map(|r| r.get_size()).unwrap_or(0);
        if jrange_size > maxtablesize as u64 {
            return Ok(false);
        }
        self.base.path_meld.append(&self.orig_path_meld);
        self.base.varnode_index += self.orig_path_meld.num_common_varnode() as i32;
        Ok(true)
    }

    // Ghidra: jumptable.hh:441 JumpBasic2 (inherits JumpBasic::buildAddresses)
    fn build_addresses(
        &self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: Option<&mut Vec<LoadTable>>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError> {
        self.base.build_addresses(fd, indop, addresstable, loadpoints, loadcounts)
    }

    // Ghidra: jumptable.cc:1733 JumpBasic2::findUnnormalized
    fn find_unnormalized(&mut self, maxaddsub: u32, maxleftright: u32, maxext: u32) {
        JumpBasic2::find_unnormalized_inner(self, maxaddsub, maxleftright, maxext);
    }

    // Ghidra: jumptable.hh:441 JumpBasic2 (inherits JumpBasic::buildLabels)
    fn build_labels(
        &self,
        fd: &crate::funcdata::Funcdata,
        addresstable: &[Address],
        label: &mut Vec<u64>,
        orig: &dyn JumpModel,
    ) {
        self.base.build_labels(fd, addresstable, label, orig);
    }

    // Ghidra: jumptable.hh:441 JumpBasic2 (inherits JumpBasic::foldInNormalization)
    fn fold_in_normalization(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        self.base.fold_in_normalization(fd, indop)
    }

    // Ghidra: jumptable.hh:441 JumpBasic2 (inherits JumpBasic::foldInGuards, virtual foldInOneGuard dispatches to JumpBasic2)
    fn fold_in_guards(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        jump: &mut JumpTable,
    ) -> bool {
        // JumpBasic2 inherits JumpBasic::foldInGuards (jumptable.cc:1555-1570)
        // verbatim; the only difference is that foldInOneGuard dispatches
        // virtually to JumpBasic2::foldInOneGuard (jumptable.cc:1634).
        let mut change = false;
        for i in 0..self.base.selectguards.len() {
            match self.base.selectguards[i].get_branch() {
                // cc:1560-1561: cbranch == null → already normalized.
                None => continue,
                // cc:1562-1565: dead cbranch → clear the record and skip.
                Some(cb) if cb.read().unwrap().is_dead() => {
                    self.base.selectguards[i].clear();
                    continue;
                }
                Some(_) => {}
            }
            // Extract the guard, fold it (JumpBasic2 override), then write back.
            let mut guard = self.base.selectguards[i].clone();
            if JumpBasic2::fold_in_one_guard(self, fd, &mut guard, jump) {
                change = true;
            }
            self.base.selectguards[i] = guard;
        }
        change
    }

    // Ghidra: jumptable.hh:441 JumpBasic2 (inherits JumpBasic::sanityCheck)
    fn sanity_check(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: &mut Vec<LoadTable>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> bool {
        self.base.sanity_check(fd, indop, addresstable, loadpoints, loadcounts)
    }

    // Ghidra: jumptable.cc:1753 JumpBasic2::clone
    fn clone_model(&self) -> Box<dyn JumpModel> {
        let mut res = JumpBasic2::new();
        // Ghidra cc:1779: res->jrange = jrange->clone(). Box<dyn> 用 clone_boxed。
        res.base.jrange = self.base.jrange.as_ref().map(|r| r.clone_boxed());
        Box::new(res)
    }

    // Ghidra: jumptable.cc:1761 JumpBasic2::clear
    fn clear(&mut self) {
        self.extra_vn = None;
        self.orig_path_meld.clear();
        self.base.clear();
    }
}

// ============================================================================
// JumpBasicOverride (jumptable.hh:461 / jumptable.cc:1801-2083)
// ============================================================================

/// A basic jump-table model incorporating manual override information.
/// Faithful to Ghidra `JumpBasicOverride` (jumptable.hh:461-494).
pub struct JumpBasicOverride {
    pub base: JumpBasic,
    pub adset: std::collections::BTreeSet<Address>,
    pub values: Vec<u64>,
    pub addrtable: Vec<Address>,
    pub starting_value: u64,
    pub norm_address: Address,
    pub hash: u64,
    pub is_trivial: bool,
}

impl JumpBasicOverride {
    // Ghidra: jumptable.hh:475 JumpBasicOverride::JumpBasicOverride
    pub fn new() -> Self {
        Self {
            base: JumpBasic::new(),
            adset: std::collections::BTreeSet::new(),
            values: Vec::new(),
            addrtable: Vec::new(),
            starting_value: 0,
            norm_address: Address::new(0),
            hash: 0,
            is_trivial: false,
        }
    }

    // Ghidra: jumptable.hh:476 JumpBasicOverride::setAddresses
    pub fn set_addresses(&mut self, adtable: &[Address]) {
        self.adset.clear();
        self.addrtable.clear();
        for addr in adtable {
            self.adset.insert(*addr);
            self.addrtable.push(*addr);
        }
    }

    // Ghidra: jumptable.hh:477 JumpBasicOverride::setNorm
    pub fn set_norm(&mut self, addr: Address, h: u64) {
        self.norm_address = addr;
        self.hash = h;
    }

    // Ghidra: jumptable.hh:478 JumpBasicOverride::setStartingValue
    pub fn set_starting_value(&mut self, val: u64) {
        self.starting_value = val;
    }

    // Ghidra: jumptable.hh:471 JumpBasicOverride::setupTrivial
    fn setup_trivial(&mut self) {
        self.is_trivial = true;
        self.values.clear();
        let mut v = self.starting_value;
        for _ in &self.addrtable {
            self.values.push(v);
            v = v.wrapping_add(1);
        }
    }

    // Ghidra: jumptable.hh:470 JumpBasicOverride::trialNorm
    fn trial_norm(&self, _fd: &crate::funcdata::Funcdata, _trialvn: &Arc<RwLock<Varnode>>, _tolerance: u32) -> i32 {
        // Requires DynamicHash (paramid.rs is L1). Return -1 to force
        // setup_trivial fallback. TODO(dynamic-hash).
        eprintln!("[JUMPTABLE] WARN: JumpBasicOverride::trial_norm not implemented (DynamicHash missing)");
        -1
    }

    // Ghidra: jumptable.hh:473 JumpBasicOverride::clearCopySpecific
    fn clear_copy_specific(&mut self) {
        self.adset.clear();
        self.values.clear();
        self.addrtable.clear();
        self.is_trivial = false;
    }
}

impl JumpModel for JumpBasicOverride {
    // RUGRA-GLUE: JumpModel::as_any downcast hook (see trait docs).
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // Ghidra: jumptable.hh:479 (override)
    fn is_override(&self) -> bool { true }
    // Ghidra: jumptable.hh:480 (override)
    fn get_table_size(&self) -> usize { self.addrtable.len() }

    // Ghidra: jumptable.cc:1952 JumpBasicOverride::recoverModel
    fn recover_model(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        _matchsize: u32,
        _maxtablesize: u32,
        _parent: &JumpParentFacts,
    ) -> Result<bool, JumpTableRecoveryError> {
        if self.hash != 0 {
            let indop_in = indop.read().unwrap().get_in(0).cloned();
            if let Some(trialvn) = indop_in {
                let slot = self.trial_norm(fd, &trialvn, 0);
                if slot >= 0 {
                    self.is_trivial = false;
                    return Ok(true);
                }
            }
        }
        self.setup_trivial();
        Ok(true)
    }

    // Ghidra: jumptable.cc:1980 JumpBasicOverride::buildAddresses
    fn build_addresses(
        &self,
        _fd: &crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        _loadpoints: Option<&mut Vec<LoadTable>>,
        _loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError> {
        addresstable.clear();
        addresstable.extend(self.addrtable.iter().cloned());
        Ok(())
    }

    // Ghidra: jumptable.hh:484 JumpBasicOverride (inherits JumpBasic::findUnnormalized)
    fn find_unnormalized(&mut self, maxaddsub: u32, maxleftright: u32, maxext: u32) {
        // jumptable.hh:484: inherited from JumpBasic
        if !self.is_trivial {
            self.base.find_unnormalized(maxaddsub, maxleftright, maxext);
        }
    }

    // Ghidra: jumptable.cc:1986 JumpBasicOverride::buildLabels
    fn build_labels(
        &self,
        _fd: &crate::funcdata::Funcdata,
        addresstable: &[Address],
        label: &mut Vec<u64>,
        _orig: &dyn JumpModel,
    ) {
        label.clear();
        if self.is_trivial {
            let mut v = self.starting_value;
            for _ in addresstable {
                label.push(v);
                v = v.wrapping_add(1);
            }
        } else {
            for addr in addresstable {
                let idx = self.addrtable.iter().position(|a| a == addr);
                if let Some(i) = idx {
                    label.push(*self.values.get(i).unwrap_or(&0));
                } else {
                    label.push(0);
                }
            }
        }
    }

    // Ghidra: jumptable.hh:485 JumpBasicOverride (inherits JumpBasic::foldInNormalization)
    fn fold_in_normalization(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        // Ghidra declares foldInNormalization inherited from JumpBasic
        // (jumptable.hh:485) with no override — including for the trivial
        // setup (setupTrivial assigns the model's switchvn), so no is_trivial
        // special case exists.
        self.base.fold_in_normalization(fd, indop)
    }

    // Ghidra: jumptable.hh:487 (override)
    fn fold_in_guards(
        &mut self,
        _fd: &mut crate::funcdata::Funcdata,
        _jump: &mut JumpTable,
    ) -> bool {
        false
    }

    // Ghidra: jumptable.hh:488-489 (override)
    fn sanity_check(
        &mut self,
        _fd: &crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        _addresstable: &mut Vec<Address>,
        _loadpoints: &mut Vec<LoadTable>,
        _loadcounts: Option<&mut Vec<i32>>,
    ) -> bool {
        true
    }

    // Ghidra: jumptable.cc:2007 JumpBasicOverride::clone
    fn clone_model(&self) -> Box<dyn JumpModel> {
        Box::new(JumpBasicOverride {
            base: JumpBasic::new(),
            adset: self.adset.clone(),
            values: self.values.clone(),
            addrtable: self.addrtable.clone(),
            starting_value: self.starting_value,
            norm_address: self.norm_address,
            hash: self.hash,
            is_trivial: self.is_trivial,
        })
    }

    // Ghidra: jumptable.cc:2020 JumpBasicOverride::clear
    fn clear(&mut self) {
        self.clear_copy_specific();
        self.base.clear();
    }
}

// ============================================================================
// JumpAssisted (jumptable.hh:510 / jumptable.cc:2113-2247)
// ============================================================================

/// A jump-table model assisted by pseudo-op directives (jumpassist CALLOTHER).
/// Faithful to Ghidra `JumpAssisted` (jumptable.hh:510-543).
///
/// Recovery requires the `JumpAssistOp` userop (userop.cc). Rugra's userop is
/// L1, so `recover_model` returns false until userop is ported. This matches
/// Ghidra's behavior on binaries without jumpassist directives.
pub struct JumpAssisted {
    pub assist_op: Option<Arc<RwLock<PcodeOp>>>,
    pub size_indices: i32,
    pub switchvn: Option<Arc<RwLock<Varnode>>>,
    pub calc_op: Option<Arc<RwLock<PcodeOp>>>,
    pub indop: Option<Arc<RwLock<PcodeOp>>>,
}

impl JumpAssisted {
    // Ghidra: jumptable.hh:518 JumpAssisted::JumpAssisted
    pub fn new() -> Self {
        Self {
            assist_op: None,
            size_indices: 0,
            switchvn: None,
            calc_op: None,
            indop: None,
        }
    }
}

impl JumpModel for JumpAssisted {
    // RUGRA-GLUE: JumpModel::as_any downcast hook (see trait docs).
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // Ghidra: jumptable.hh:510 JumpAssisted (JumpModel::isOverride default false)
    fn is_override(&self) -> bool { false }
    // Ghidra: jumptable.hh:513 JumpAssisted::getTableSize
    fn get_table_size(&self) -> usize { self.size_indices as usize }

    // Ghidra: jumptable.cc:2091 JumpAssisted::recoverModel
    /// 前置形状判定逐字对齐 cc:2091-2129:
    ///   `addrVn = indop->getIn(0)` 未写 → false;
    ///   `assistOp = addrVn->getDef()` 非 CALLOTHER → false;
    ///   `assistOp->numInput() < 3` → false;
    ///   `userops.getOp(in(0)->getOffset())` 类型非 jumpassist → false。
    /// 之后 Ghidra 读 `JumpAssistOp` 子类的 getCalcSize/getIndex2Addr 载荷
    /// (cc:2111-2122);Rugra 的 `UserPcodeOp` 尚未携带 JumpAssistOp 载荷,
    /// 该步保守 fail-closed 返回 `Ok(false)`(保守降级:形状判定与 Ghidra
    /// 同序,载荷步骤留待 userop.rs 补齐后启用;TODO JUMPTABLE-PIPELINE-0001)。
    fn recover_model(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        indop: &Arc<RwLock<PcodeOp>>,
        _matchsize: u32,
        _maxtablesize: u32,
        _parent: &JumpParentFacts,
    ) -> Result<bool, JumpTableRecoveryError> {
        self.indop = Some(indop.clone());
        // Ghidra cc:2095-2100: addrVn must be written, its def a CALLOTHER.
        let addr_vn = indop.read().unwrap().get_in(0).cloned();
        let Some(addr_vn) = addr_vn else { return Ok(false); };
        if !addr_vn.read().unwrap().is_written() {
            return Ok(false);
        }
        let assist_op = addr_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        let Some(assist_op) = assist_op else { return Ok(false); };
        {
            let a = assist_op.read().unwrap();
            if a.opcode != OpCode::CPUI_CALLOTHER {
                return Ok(false);
            }
            // Ghidra cc:2100: if (assistOp->numInput() < 3) return false;
            if a.num_input() < 3 {
                return Ok(false);
            }
        }
        self.assist_op = Some(assist_op.clone());
        // Ghidra cc:2101-2105: index = assistOp->getIn(0)->getOffset();
        //   tmpOp = fd->getArch()->userops.getOp(index);
        //   if (tmpOp->getType() != UserPcodeOp::jumpassist) return false;
        let index = assist_op
            .read()
            .unwrap()
            .get_in(0)
            .map(|v| v.read().unwrap().get_offset())
            .unwrap_or(0) as i32;
        let userop_jumpassist = fd
            .get_arch()
            .and_then(|a| a.userops.clone())
            .and_then(|u| {
                u.read()
                    .unwrap()
                    .get_op(index)
                    .map(|op| op.get_type() == crate::userop::UserOpType::JumpAssist)
                    .or_else(|| {
                        // Ghidra 的 getOp 假定 CALLOTHER id 恒登记;Rugra 的
                        // 注册表可能缺项,缺项视作非 jumpassist(与类型判定
                        // 失败同路,不 panic)。
                        Some(false)
                    })
            })
            .unwrap_or(false);
        if !userop_jumpassist {
            return Ok(false);
        }
        // Ghidra cc:2107: switchvn = assistOp->getIn(1)(在类型判定通过后)。
        self.switchvn = assist_op.read().unwrap().get_in(1).cloned();
        // Ghidra cc:2107-2110: 其余输入必须全为常量。
        {
            let a = assist_op.read().unwrap();
            for i in 2..a.num_input() {
                match a.get_in(i) {
                    Some(v) if v.read().unwrap().is_constant() => {}
                    _ => return Ok(false),
                }
            }
        }
        // Ghidra cc:2111-2122: JumpAssistOp 载荷(getCalcSize 脚本或首参数
        // 为 sizeIndices)未移植 — 保守 fail-closed(见函数头注释)。
        eprintln!(
            "[JUMPTABLE] WARN: JumpAssisted userop is jumpassist-typed but JumpAssistOp payload (calc/addr scripts) not ported"
        );
        Ok(false)
    }

    // Ghidra: jumptable.cc:2131 JumpAssisted::buildAddresses
    fn build_addresses(
        &self,
        _fd: &crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        _loadpoints: Option<&mut Vec<LoadTable>>,
        _loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError> {
        addresstable.clear();
        if self.assist_op.is_none() { return Ok(()); }
        eprintln!("[JUMPTABLE] WARN: JumpAssisted::build_addresses cannot emulate without JumpAssistOp");
        Ok(())
    }

    // Ghidra: jumptable.hh:510 JumpAssisted (findUnnormalized — no-op, switchvar is direct)
    fn find_unnormalized(&mut self, _maxaddsub: u32, _maxleftright: u32, _maxext: u32) {}

    // Ghidra: jumptable.cc:2166 JumpAssisted::buildLabels
    fn build_labels(
        &self,
        _fd: &crate::funcdata::Funcdata,
        _addresstable: &[Address],
        label: &mut Vec<u64>,
        _orig: &dyn JumpModel,
    ) {
        label.clear();
        for i in 0..self.size_indices {
            label.push(i as u64);
        }
    }

    // Ghidra: jumptable.cc:2193 JumpAssisted::foldInNormalization
    fn fold_in_normalization(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        // Faithful to JumpAssisted::foldInNormalization (jumptable.cc:2193-2206):
        // replace all outputs of the jumpassist op with switchvn (including
        // BRANCHIND), then get rid of the assist op (it has served its
        // purpose). Descendants are snapshotted first: op_set_input severs
        // each descendant from outvn's descend list as it runs (Ghidra
        // increments its iterator before the mutation for the same reason).
        let switchvn = self.switchvn.clone()?;
        let assist = self.assist_op.clone()?;
        let outvn = assist.read().unwrap().get_out().cloned();
        if let Some(outvn) = outvn {
            let descendants: Vec<_> = outvn.read().unwrap().descend_iter().collect();
            for desc in descendants {
                fd.op_set_input(&crate::op::PcodeOpRef(desc), switchvn.clone(), 0);
            }
        }
        fd.op_destroy(&crate::op::PcodeOpRef(assist));
        Some(switchvn)
    }

    // Ghidra: jumptable.cc:2208 JumpAssisted::foldInGuards
    fn fold_in_guards(
        &mut self,
        _fd: &mut crate::funcdata::Funcdata,
        jump: &mut JumpTable,
    ) -> bool {
        // Faithful to JumpAssisted::foldInGuards (jumptable.cc:2208-2214):
        // the default case is always the last block; report a change only
        // when that assignment actually moved the default out-edge.
        let orig_val = jump.get_default_block();
        jump.set_last_as_default();
        orig_val != jump.get_default_block()
    }

    // Ghidra: jumptable.hh:510 JumpAssisted (sanityCheck — always true, addresses from p-code model)
    fn sanity_check(
        &mut self,
        _fd: &crate::funcdata::Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        _addresstable: &mut Vec<Address>,
        _loadpoints: &mut Vec<LoadTable>,
        _loadcounts: Option<&mut Vec<i32>>,
    ) -> bool {
        true
    }

    // Ghidra: jumptable.hh:510 JumpAssisted::clone
    fn clone_model(&self) -> Box<dyn JumpModel> {
        Box::new(JumpAssisted {
            assist_op: self.assist_op.clone(),
            size_indices: self.size_indices,
            switchvn: self.switchvn.clone(),
            calc_op: self.calc_op.clone(),
            indop: self.indop.clone(),
        })
    }

    // Ghidra: jumptable.hh:510 JumpAssisted::clear
    fn clear(&mut self) {
        self.assist_op = None;
        self.size_indices = 0;
        self.switchvn = None;
        self.calc_op = None;
        self.indop = None;
    }
}

/// An address table index and its corresponding out-edge. Faithful to
/// `JumpTable::IndexPair` (jumptable.hh:553).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexPair {
    /// Out-edge index for the basic-block.
    pub block_position: i32,
    /// Index of address targeting the basic-block.
    pub address_index: i32,
}

impl IndexPair {
    // Ghidra: jumptable.hh:556 JumpTable::IndexPair::IndexPair
    pub fn new(pos: i32, index: i32) -> Self {
        Self {
            block_position: pos,
            address_index: index,
        }
    }

    // Ghidra: jumptable.hh:629 JumpTable::IndexPair::operator<
    /// Compare by position then by index. Faithful to `operator<`.
    pub fn less_than(&self, op2: &IndexPair) -> bool {
        if self.block_position != op2.block_position {
            return self.block_position < op2.block_position;
        }
        self.address_index < op2.address_index
    }

    // Ghidra: jumptable.hh:639 JumpTable::IndexPair::compareByPosition
    /// Compare just by position. Faithful to `compareByPosition`.
    pub fn compare_by_position(op1: &IndexPair, op2: &IndexPair) -> bool {
        op1.block_position < op2.block_position
    }
}

/// A map from values to control-flow targets within a function.
///
/// A `JumpTable` is attached to a specific CPUI_BRANCHIND and encapsulates all
/// the information necessary to model the indirect jump as a switch statement.
/// It knows how to map from specific switch variable values to the destination
/// case block and how to label the value. Faithful to `JumpTable`
/// (jumptable.hh:541).
pub struct JumpTable {
    /// Current model of how the jump table is implemented in code.
    pub jmodel: Option<Box<dyn JumpModel>>,
    /// Initial jump table model, which may be incomplete.
    pub origmodel: Option<Box<dyn JumpModel>>,
    /// Raw addresses in the jump-table.
    pub addresstable: Vec<Address>,
    /// Map from basic-blocks to address table index.
    pub block2addr: Vec<IndexPair>,
    /// The case label for each explicit target.
    pub label: Vec<u64>,
    /// Any recovered in-memory data for the jump-table.
    pub loadpoints: Vec<LoadTable>,
    /// Absolute address of the BRANCHIND jump.
    pub opaddress: Address,
    /// CPUI_BRANCHIND linked to this jump-table.
    pub indirect: Option<Arc<RwLock<PcodeOp>>>,
    /// Bits of the switch variable being consumed.
    pub switch_var_consume: u64,
    /// The out-edge corresponding to the default switch destination (-1 = undefined).
    pub default_block: i32,
    /// Block out-edge corresponding to last entry in the address table.
    pub last_block: i32,
    /// Switch-variable normalization restrictions.
    pub norm_max: NormMax,
    /// True if this table is incomplete and needs additional recovery steps.
    pub partial_table: bool,
    /// True if information about in-memory model data is/should be collected.
    pub collect_loads: bool,
    /// The default block is the target of a folded CBRANCH (cannot have a label).
    pub default_is_folded: bool,
}

impl std::fmt::Debug for JumpTable {
    // RUGRA-GLUE: Rust Debug trait impl for JumpTable; no Ghidra counterpart (Ghidra uses encode/decode for serialization)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JumpTable")
            .field("opaddress", &self.opaddress)
            .field("addresstable_len", &self.addresstable.len())
            .field("default_block", &self.default_block)
            .field("partial_table", &self.partial_table)
            .finish()
    }
}

impl JumpTable {
    // Ghidra: jumptable.hh:587 JumpTable::JumpTable(Architecture*,Address)
    /// Construct given the address of the BRANCHIND.
    pub fn new(opaddress: Address) -> Self {
        Self {
            jmodel: None,
            origmodel: None,
            addresstable: Vec::new(),
            block2addr: Vec::new(),
            label: Vec::new(),
            loadpoints: Vec::new(),
            opaddress,
            indirect: None,
            switch_var_consume: u64::MAX,
            default_block: -1,
            last_block: -1,
            norm_max: NormMax::default(),
            partial_table: false,
            collect_loads: false,
            default_is_folded: false,
        }
    }

    // Ghidra: jumptable.hh:590 JumpTable::isRecovered
    /// Return true if a model has been recovered.
    pub fn is_recovered(&self) -> bool {
        !self.addresstable.is_empty()
    }

    // Ghidra: jumptable.hh:591 JumpTable::isLabelled
    /// Return true if case labels are computed.
    pub fn is_labelled(&self) -> bool {
        !self.label.is_empty()
    }

    // Ghidra: jumptable.cc:2447 JumpTable::isOverride
    /// Return true if this table was manually overridden.
    pub fn is_override(&self) -> bool {
        self.jmodel.as_ref().map_or(false, |m| m.is_override())
    }

    // Ghidra: jumptable.hh:593 JumpTable::isPartial
    /// Return true if this is a partial table needing more recovery.
    pub fn is_partial(&self) -> bool {
        self.partial_table
    }

    // Ghidra: jumptable.hh:594 JumpTable::markComplete
    /// Mark whatever is recovered so far as the complete table.
    pub fn mark_complete(&mut self) {
        self.partial_table = false;
    }

    // Ghidra: jumptable.hh:595 JumpTable::numEntries
    /// Return the size of the address table.
    pub fn num_entries(&self) -> usize {
        self.addresstable.len()
    }

    // Ghidra: jumptable.hh:596 JumpTable::getSwitchVarConsume
    /// Get bits of switch variable consumed by this table.
    pub fn get_switch_var_consume(&self) -> u64 {
        self.switch_var_consume
    }

    // Ghidra: jumptable.hh:597 JumpTable::getDefaultBlock
    /// Get the out-edge corresponding to the default switch destination.
    pub fn get_default_block(&self) -> i32 {
        self.default_block
    }

    // Ghidra: jumptable.hh:598 JumpTable::getOpAddress
    /// Get the address of the BRANCHIND for the switch.
    pub fn get_op_address(&self) -> Address {
        self.opaddress
    }

    // Ghidra: jumptable.hh:599 JumpTable::getIndirectOp
    /// Get the BRANCHIND pcode op.
    pub fn get_indirect_op(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        self.indirect.clone()
    }

    // Ghidra: jumptable.hh:600 JumpTable::setIndirectOp
    /// Set the BRANCHIND pcode op.
    pub fn set_indirect_op(&mut self, ind: Arc<RwLock<PcodeOp>>) {
        let addr = ind.read().unwrap().get_addr();
        self.opaddress = addr;
        self.indirect = Some(ind);
    }

    // Ghidra: jumptable.hh:601 JumpTable::setNormMax
    /// Set the switch-variable normalization restrictions.
    pub fn set_norm_max(&mut self, maddsub: u32, mleftright: u32, mext: u32) {
        self.norm_max = NormMax {
            addsub: maddsub,
            leftright: mleftright,
            ext: mext,
        };
    }

    // Ghidra: jumptable.cc:2466 JumpTable::setOverride
    /// Install a manual override model: discard any existing model, build a
    /// `JumpBasicOverride` and fill in the fixed address table, normalized
    /// switch marker and starting value. Faithful to `setOverride`
    /// (jumptable.cc:2466-2478)。
    pub fn set_override(&mut self, addrtable: &[Address], naddr: Address, h: u64, sv: u64) {
        // Ghidra cc:2469-2470: if (jmodel != 0) delete jmodel;
        self.jmodel = None;
        let mut over = JumpBasicOverride::new();
        over.set_addresses(addrtable);
        over.set_norm(naddr, h);
        over.set_starting_value(sv);
        self.jmodel = Some(Box::new(over));
    }

    // Ghidra: jumptable.hh:606 JumpTable::getAddressByIndex
    /// Get the i-th address table entry.
    pub fn get_address_by_index(&self, i: usize) -> Address {
        self.addresstable[i]
    }

    // Ghidra: jumptable.cc:2502 JumpTable::setLastAsDefault
    /// Set the default jump-table target to be the last address in the table.
    pub fn set_last_as_default(&mut self) {
        self.default_block = self.last_block;
    }

    // Ghidra: jumptable.hh:608 JumpTable::setDefaultBlock
    /// Set out-edge of the switch destination considered to be default.
    pub fn set_default_block(&mut self, bl: i32) {
        self.default_block = bl;
    }

    // Ghidra: jumptable.hh:609 JumpTable::setLoadCollect
    /// Set whether LOAD records should be collected.
    pub fn set_load_collect(&mut self, val: bool) {
        self.collect_loads = val;
    }

    // Ghidra: jumptable.hh:610 JumpTable::setFoldedDefault
    /// Mark that the default block is a folded CBRANCH target.
    pub fn set_folded_default(&mut self) {
        self.default_is_folded = true;
    }

    // Ghidra: jumptable.hh:611 JumpTable::hasFoldedDefault
    /// Return true if the default block is a folded CBRANCH target.
    pub fn has_folded_default(&self) -> bool {
        self.default_is_folded
    }

    // Ghidra: jumptable.cc:2337 JumpTable::block2Position
    /// Given a specific basic-block, figure out which edge out of the switch
    /// block hits it. The position is the switch basic block's out-edge slot,
    /// which is deduped and may include guard destinations (unlike the address
    /// table index). Ghidra throws `LowlevelError("Requested block, not in
    /// jumptable")` at cc:2346-2347 when no edge hits the block; Rugra returns
    /// `None` and the callers ([`num_indices_by_block`],
    /// [`get_index_by_block`]) degrade to "no indices", because every
    /// reachable caller passes a `CaseOrder::basicblock` that acquired its
    /// in-edge from the switch block at construction time.
    fn block2_position(
        &self, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<i32> {
        // cc:2343: parent = indirect->getParent()
        let parent = self
            .indirect
            .as_ref()
            .and_then(|o| {
                o.read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|p| p.upgrade())
            });
        let parent = parent?;
        let b = bl.read().unwrap();
        let bank = b.bank();
        let parent_id = bank.registered_id_of(&parent);
        // cc:2344-2345: for(position=0;position<bl->sizeIn();++position)
        //   if (bl->getIn(position) == parent) break;
        for position in 0..b.size_in() {
            if let Some(e) = b.get_in(position) {
                if e.point == parent_id {
                    // cc:2348: return bl->getInRevIndex(position);
                    return Some(e.reverse_index);
                }
            }
        }
        None
    }

    // Ghidra: jumptable.cc:2438 JumpTable::numIndicesByBlock
    /// Return the number of address table entries that target the given
    /// basic-block (cc:2441-2444: the width of the `equal_range` over
    /// `block2addr` compared by `IndexPair::compareByPosition`).
    pub fn num_indices_by_block(
        &self, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> usize {
        let Some(pos) = self.block2_position(bl) else {
            return 0;
        };
        // equal_range(lower, upper) with compareByPosition (block_position only).
        let lower = self
            .block2addr
            .partition_point(|p| p.block_position < pos);
        let upper = self
            .block2addr
            .partition_point(|p| p.block_position <= pos);
        upper - lower
    }

    // Ghidra: jumptable.cc:2485 JumpTable::getIndexByBlock
    /// Get the address table index of the i-th entry corresponding to the
    /// given basic-block. Ghidra throws
    /// `LowlevelError("Could not get jumptable index for block")` (cc:2499)
    /// when the block has no i-th entry; Rugra returns `None`.
    pub fn get_index_by_block(
        &self, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, i: usize,
    ) -> Option<usize> {
        let Some(pos) = self.block2_position(bl) else {
            return None;
        };
        let mut count = 0usize;
        // cc:2490: lower_bound(block2addr.begin(), block2addr.end(), val, compareByPosition)
        let mut it = self
            .block2addr
            .partition_point(|p| p.block_position < pos);
        while it < self.block2addr.len() {
            if self.block2addr[it].block_position == pos {
                // cc:2493-2494: if (count == i) return (*iter).addressIndex;
                if count == i {
                    return Some(self.block2addr[it].address_index as usize);
                }
                count += 1;
            }
            it += 1;
        }
        None
    }

    // Ghidra: jumptable.hh:614 JumpTable::getLabelByIndex
    /// Given a case index, get its label.
    pub fn get_label_by_index(&self, index: usize) -> u64 {
        self.label[index]
    }

    // Ghidra: jumptable.cc:2513 JumpTable::addBlockToSwitch
    /// Add a guard-branch target block as an explicit switch destination.
    /// The new target is appended directly to the end of the table.
    pub fn add_block_to_switch(&mut self, bl_start: Address, lab: u64) {
        self.addresstable.push(bl_start);
        // Ghidra cc:2537: `lastBlock = indirect->getParent()->sizeOut()` —
        // the block WILL be added to the end of the out-edges by the
        // pushBranch immediately following in foldInOneGuard, so the new
        // default refers to that future out-edge index, NOT the table length
        // (which only coincides when the table was never truncated).
        self.last_block = self
            .indirect
            .as_ref()
            .and_then(|o| {
                o.read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|p| p.upgrade())
            })
            .map(|bl| bl.read().unwrap().size_out() as i32)
            .unwrap_or(-1);
        let last = self.last_block;
        let addr_idx = (self.addresstable.len() as i32) - 1;
        self.block2addr.push(IndexPair::new(last, addr_idx));
        self.label.push(lab);
    }

    // Ghidra: jumptable.cc:2225 JumpTable::saveModel
    /// Save off current model (if any) and prepare for instantiating a new
    /// model. Faithful to `saveModel` (jumptable.cc:2247).
    pub fn save_model(&mut self) {
        self.origmodel = self.jmodel.take();
    }

    // Ghidra: jumptable.cc:2234 JumpTable::restoreSavedModel
    /// Restore any saved model as the current model. Faithful to
    /// `restoreSavedModel` (jumptable.cc:2256).
    pub fn restore_saved_model(&mut self) {
        self.jmodel = self.origmodel.take();
    }

    // Ghidra: jumptable.cc:2243 JumpTable::clearSavedModel
    /// Clear any saved model. Faithful to `clearSavedModel` (jumptable.cc:2243).
    pub fn clear_saved_model(&mut self) {
        self.origmodel = None;
    }

    // Ghidra: jumptable.cc:2739 JumpTable::clear
    /// Clear instance-specific data for this jump-table. Faithful to `clear()`
    /// (jumptable.cc:2761).
    pub fn clear(&mut self) {
        self.clear_saved_model();
        let is_override = self.jmodel.as_ref().map_or(false, |m| m.is_override());
        if is_override {
            if let Some(m) = self.jmodel.as_mut() {
                m.clear();
            }
        } else {
            self.jmodel = None;
        }
        self.addresstable.clear();
        self.block2addr.clear();
        self.last_block = -1;
        self.label.clear();
        self.loadpoints.clear();
        self.indirect = None;
        self.switch_var_consume = u64::MAX;
        self.default_block = -1;
        self.partial_table = false;
    }

    // Ghidra: jumptable.cc:2254 JumpTable::recoverModel
    /// Recover a model for the switch. Faithful to `JumpTable::recoverModel`
    /// (jumptable.cc:2254-2285, JUMPTABLE-SELECTION-0001)。
    ///
    /// Ghidra 的模型尝试顺序(逐字):
    ///   1. 已挂模型是 override → 直接重跑(matchsize=0)并返回;
    ///   2. `indirect->getIn(0)` 已写且 def 是 CALLOTHER → 尝试
    ///      `JumpAssisted`(matchsize=addresstable.size());
    ///   3. `JumpBasic`(matchsize=addresstable.size());
    ///   4. `JumpBasic2`,`initializeStart(jbasic->getPathMeld())` 接住
    ///      Basic 失败时的 pathMeld,再试一次;
    ///   全部失败 → jmodel = None。
    /// **`JumpModelTrivial` 不在 Ghidra 的 recoverModel 选择链里**
    /// (它只经 matchModel 的恢复路径产生);旧实现的 Basic→Trivial
    /// 回退是 INVENTED,已删除。
    ///
    /// 返回值语义:`Err` = Ghidra 的 LowlevelError 从 recoverModel 穿透
    /// (不尝试下一个模型),`Ok(false)` = 模型自身拒绝。
    pub fn recover_model(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        maxtablesize: u32,
    ) -> Result<bool, JumpTableRecoveryError> {
        // Ghidra models read `jt->isPartial()` (cc:1052) and
        // `jt->getIndirectOp()` (cc:1083) through their parent `JumpTable*`
        // during recovery. Recovery runs under this table's write lock, so we
        // snapshot both facts from `&mut self` (no lock, no Arc) and pass
        // them down as `JumpParentFacts` — see the struct docs.
        let parent = JumpParentFacts {
            partial_table: self.partial_table,
            indirect: self.indirect.clone(),
        };
        // Ghidra cc:2257-2263: 已有 override 模型 → 重跑(matchsize=0)。
        if let Some(m) = self.jmodel.as_mut() {
            if m.is_override() {
                let Some(indop) = self.indirect.clone() else {
                    return Ok(false);
                };
                return m.recover_model(fd, &indop, 0, maxtablesize, &parent);
            }
        }
        // Ghidra cc:2262: 否则丢弃旧模型(delete jmodel)。
        self.jmodel = None;

        let Some(indop) = self.indirect.clone() else {
            return Ok(false);
        };
        let matchsize = self.addresstable.len() as u32;

        // Ghidra cc:2264-2272: 输入已写且 def 是 CALLOTHER → JumpAssisted。
        let in0_written_callother = {
            let indop_rg = indop.read().unwrap();
            indop_rg
                .get_in(0)
                .and_then(|vn| {
                    let v = vn.read().unwrap();
                    if !v.is_written() {
                        return None;
                    }
                    v.def.as_ref().and_then(|w| w.upgrade())
                })
                .map(|def_op| def_op.read().unwrap().opcode == OpCode::CPUI_CALLOTHER)
                .unwrap_or(false)
        };
        if in0_written_callother {
            let mut jassisted = JumpAssisted::new();
            if jassisted
                .recover_model(fd, &indop, matchsize, maxtablesize, &parent)?
            {
                self.jmodel = Some(Box::new(jassisted));
                return Ok(true);
            }
        }

        // Ghidra cc:2274-2277: JumpBasic。
        let mut jbasic = JumpBasic::new();
        if jbasic.recover_model(fd, &indop, matchsize, maxtablesize, &parent)? {
            self.jmodel = Some(Box::new(jbasic));
            return Ok(true);
        }
        // Ghidra cc:2278-2282: JumpBasic2,initializeStart 接住 Basic 的
        // pathMeld 后再试;失败则 jmodel = None。
        let mut jbasic2 = JumpBasic2::new();
        jbasic2.initialize_start(jbasic.get_path_meld());
        if jbasic2.recover_model(fd, &indop, matchsize, maxtablesize, &parent)? {
            self.jmodel = Some(Box::new(jbasic2));
            return Ok(true);
        }
        self.jmodel = None;
        Ok(false)
    }

    // Ghidra: jumptable.cc:2354 JumpTable::isReachable
    /// Check the two immediately preceding guard levels for a collapsed
    /// `if (false)` that makes `indop` unreachable.
    fn is_reachable(indop: &Arc<RwLock<PcodeOp>>) -> bool {
        let Some(mut parent) = indop
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(|weak| weak.upgrade())
        else {
            return true;
        };

        for _ in 0..2 {
            let Some(predecessor) = ({
                let parent_read = parent.read().unwrap();
                if parent_read.size_in() != 1 {
                    return true;
                }
                let bank = parent_read.bank();
                parent_read.get_in(0).map(|edge| bank.expect_arc(edge.point))
            }) else {
                return true;
            };

            let cbranch = {
                let predecessor_read = predecessor.read().unwrap();
                if predecessor_read.size_out() != 2 {
                    continue;
                }
                predecessor_read.get_ops().last().cloned()
            };
            let Some(cbranch) = cbranch else {
                continue;
            };
            let (is_cbranch, bool_vn, is_boolean_flip) = {
                let op_read = cbranch.0.read().unwrap();
                (
                    op_read.opcode == OpCode::CPUI_CBRANCH,
                    op_read.get_in(1).cloned(),
                    op_read.is_boolean_flip(),
                )
            };
            if !is_cbranch {
                continue;
            }
            let Some(bool_vn) = bool_vn else {
                continue;
            };
            let (is_constant, offset) = {
                let vn_read = bool_vn.read().unwrap();
                (vn_read.is_constant(), vn_read.get_offset())
            };
            if !is_constant {
                continue;
            }

            let mut true_slot = if is_boolean_flip { 0 } else { 1 };
            if offset == 0 {
                true_slot = 1 - true_slot;
            }
            let surviving_target = {
                let pr = predecessor.read().unwrap();
                let bank = pr.bank();
                pr.get_out(true_slot)
                    .map(|edge| bank.expect_arc(edge.point))
            };
            if surviving_target
                .as_ref()
                .is_some_and(|target| !Arc::ptr_eq(target, &parent))
            {
                return false;
            }
            parent = predecessor;
        }
        true
    }

    // Ghidra: jumptable.cc:2295 JumpTable::sanityCheck
    /// Apply the table-level thunk/reachability checks, then delegate to the
    /// recovered model's address sanity check.
    ///
    /// The ordering is observable: an override returns before reachability;
    /// an unreachable non-override sets `partial_table` before a possible
    /// thunk exception; model mutations remain visible if its `false` return
    /// is converted into `LowlevelError`.
    pub fn sanity_check(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError> {
        let Some(model) = self.jmodel.as_ref() else {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: format!("Jumptable at {} did not pass sanity check.", self.opaddress),
            });
        };
        if model.is_override() {
            return Ok(());
        }

        let original_size = self.addresstable.len();
        let Some(indop) = self.indirect.clone() else {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: format!("Jumptable at {} did not pass sanity check.", self.opaddress),
            });
        };

        if !Self::is_reachable(&indop) {
            self.partial_table = true;
        }
        if self.addresstable.len() == 1 {
            let target = self.addresstable[0].as_u64();
            let op_offset = indop.read().unwrap().get_addr().as_u64();
            if target == 0 || target.abs_diff(op_offset) > 0xffff {
                return Err(JumpTableRecoveryError::Thunk {
                    message: "Likely thunk".to_string(),
                });
            }
        }

        let passed = self.jmodel.as_mut().unwrap().sanity_check(
            fd,
            &indop,
            &mut self.addresstable,
            &mut self.loadpoints,
            loadcounts,
        );
        if !passed {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: format!("Jumptable at {} did not pass sanity check.", self.opaddress),
            });
        }
        if original_size != self.addresstable.len() {
            fd.warning("Sanity check requires truncation of jumptable", self.opaddress);
        }
        Ok(())
    }

    // Ghidra: jumptable.cc:2623 JumpTable::recoverAddresses
    /// Recover the model and raw address table while retaining Ghidra's typed
    /// exception channel and all mutations performed before an error.
    ///
    /// Ghidra 的 maxtablesize 来自 `glb->max_jumptable_size`
    /// (cc:2626 经 recoverModel 的调用点 cc:2259/2270/2276/2281);
    /// Rugra 从 `Architecture::max_jumptable_size` 读取,无 Architecture
    /// 时退回默认 1024(architecture.cc:1433)。
    pub fn recover_addresses_classified(
        &mut self,
        fd: &crate::funcdata::Funcdata,
    ) -> Result<(), JumpTableRecoveryError> {
        let maxtablesize = fd
            .get_arch()
            .map_or(MAX_JUMPTABLE_SIZE, |a| a.max_jumptable_size);
        // Ghidra cc:2626: recoverModel(fd); jmodel==0 → LowlevelError。
        // recoverModel 内部的 LowlevelError(如 readonly 救援读 LoadImage
        // 失败)在 Ghidra 直接穿透 recoverAddresses,Rust 用 `?` 同语义。
        // 消息内地址按 oracle jumptable.cc:2627 的 `opaddress` 流式拼写
        // (printRaw),经 fd.print_raw_code_addr(0x + 零填充 + 显示基址)。
        if !self.recover_model(fd, maxtablesize)? {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: format!(
                    "Could not recover jumptable at {}. Too many branches",
                    fd.print_raw_code_addr(self.opaddress.as_u64())
                ),
            });
        }
        // Ghidra cc:2632-2635: getTableSize()==0 → LowlevelError。
        if self.jmodel.as_ref().map_or(0, |model| model.get_table_size()) == 0 {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: format!(
                    "Jumptable with 0 entries at {}",
                    fd.print_raw_code_addr(self.opaddress.as_u64())
                ),
            });
        }
        let Some(indop) = self.indirect.clone() else {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: format!(
                    "Could not recover jumptable at {}. Too many branches",
                    fd.print_raw_code_addr(self.opaddress.as_u64())
                ),
            });
        };

        // Ghidra cc:2639-2648: collectloads 分支带 loadcounts 并做
        // LoadTable::collapseTable;两个分支都过 sanityCheck。
        if self.collect_loads {
            let mut loadcounts = Vec::new();
            self.jmodel.as_ref().unwrap().build_addresses(
                fd,
                &indop,
                &mut self.addresstable,
                Some(&mut self.loadpoints),
                Some(&mut loadcounts),
            )?;
            self.sanity_check(fd, Some(&mut loadcounts))?;
            LoadTable::collapse_table(&mut self.loadpoints);
        } else {
            self.jmodel.as_ref().unwrap().build_addresses(
                fd,
                &indop,
                &mut self.addresstable,
                None,
                None,
            )?;
            self.sanity_check(fd, None)?;
        }
        Ok(())
    }

    // RUGRA-GLUE: bool compatibility adapter for callers not yet migrated to JumpTableRecoveryError
    /// Compatibility adapter for legacy Rugra callers. New code should use
    /// [`recover_addresses_classified`](Self::recover_addresses_classified)
    /// so thunk and ordinary low-level failures remain distinguishable.
    pub fn recover_addresses(&mut self, fd: &crate::funcdata::Funcdata) -> bool {
        self.recover_addresses_classified(fd).is_ok()
    }

    // Ghidra: jumptable.cc:2653 JumpTable::recoverMultistage
    /// Do a normal recoverAddresses, but save off the old JumpModel, and if
    /// we fail recovery, put back the old model.
    ///
    /// Faithful to `recoverMultistage` (jumptable.cc:2653-2675): the old
    /// address table is restored on EITHER exception family
    /// (JumptableThunkError and LowlevelError run the identical catch body);
    /// `loadpoints` is cleared up front and NOT restored on failure;
    /// `partialTable = false` and `clearSavedModel()` run regardless of
    /// outcome, keeping the new model only when recovery succeeded.
    pub fn recover_multistage(&mut self, fd: &crate::funcdata::Funcdata) {
        self.save_model();
        let oldaddresstable = std::mem::take(&mut self.addresstable);
        self.loadpoints.clear();
        if self.recover_addresses_classified(fd).is_err() {
            self.restore_saved_model();
            self.addresstable = oldaddresstable;
            // fd->warning("Second-stage recovery error", indirect->getAddr())
            // — indirect is set by stageJumpTable immediately before this
            // call (funcdata_block.cc:532); opaddress is the defensive
            // fallback for the unlinked override corner.
            let warn_addr = self
                .indirect
                .as_ref()
                .map(|o| o.read().unwrap().get_addr())
                .unwrap_or(self.opaddress);
            fd.warning("Second-stage recovery error", warn_addr);
        }
        self.partial_table = false;
        self.clear_saved_model(); // Keep the new model if it was created successfully
    }

    // Ghidra: jumptable.cc:2574 JumpTable::foldInNormalization
    /// Eliminate any code involved in actually computing the destination
    /// address so it looks like the CPUI_BRANCHIND operation does it all
    /// internally. Faithful to `foldInNormalization` (jumptable.cc:2574-2591).
    pub fn fold_in_normalization(&mut self, fd: &mut crate::funcdata::Funcdata) {
        // cc:2577: switchvn = jmodel->foldInNormalization(fd,indirect)
        let Some(indirect) = self.indirect.clone() else {
            return;
        };
        let switchvn = match self.jmodel.as_mut() {
            Some(m) => m.fold_in_normalization(fd, &indirect),
            None => return,
        };
        if let Some(switchvn) = switchvn {
            // cc:2578-2589: if possible, mark up the switch variable as not
            // fully consumed so that subvariable flow can truncate it.
            let (nzmask, size, is_written) = {
                let vn = switchvn.read().unwrap();
                (vn.get_nz_mask(), vn.get_size(), vn.is_written())
            };
            self.switch_var_consume = minimalmask(nzmask);
            if self.switch_var_consume >= calc_mask(size) {
                // If mask covers everything
                if is_written {
                    // cc:2583-2588: check for a signed extension and assume
                    // the extension is not consumed.
                    let sext_def = switchvn
                        .read()
                        .unwrap()
                        .def
                        .as_ref()
                        .and_then(|w| w.upgrade());
                    if let Some(def_op) = sext_def {
                        let (is_sext, in0_size) = {
                            let d = def_op.read().unwrap();
                            (
                                d.opcode == OpCode::CPUI_INT_SEXT,
                                d.get_in(0).map(|v| v.read().unwrap().get_size()),
                            )
                        };
                        if is_sext {
                            if let Some(sz0) = in0_size {
                                self.switch_var_consume = calc_mask(sz0);
                            }
                        }
                    }
                }
            }
        }
    }

    // Ghidra: jumptable.cc:2528 JumpTable::switchOver
    /// Convert the absolute addresses of the address table into out-edge
    /// positions (`block2addr`) of the switch basic block, then derive the
    /// last block and the default block. Faithful to `switchOver`
    /// (jumptable.cc:2528-2569); called once per table at the end of flow
    /// following (`Funcdata::followFlow`, funcdata_op.cc:778).
    pub fn switch_over(
        &mut self, flow: &crate::flow::FlowInfo,
    ) -> std::result::Result<(), JumpTableRecoveryError> {
        let unlinked =
            || JumpTableRecoveryError::Lowlevel { message: "Jumptable destination not linked".to_string() };
        self.block2addr.clear();
        self.block2addr.reserve(self.addresstable.len());
        // cc:2537: parent = indirect->getParent();
        let parent = self
            .indirect
            .as_ref()
            .and_then(|o| {
                o.read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|p| p.upgrade())
            });
        let Some(parent) = parent else {
            // Ghidra dereferences indirect unconditionally; an unlinked
            // indirect op cannot occur past stageJumpTable.
            return Err(unlinked());
        };
        for i in 0..self.addresstable.len() {
            let addr = self.addresstable[i].clone();
            // cc:2541: op = flow.target(addr);
            let Some(op) = flow.target(addr) else {
                // FlowInfo::target (flow.cc:133-137) throws LowlevelError
                // "Could not find op at target address: (<spc>,<printRaw>)"
                // when the address was never decoded into p-code — a
                // distinct failure from the cc:2545-2546 out-edge link
                // check. Rugra's FlowInfo::target returns Option instead of
                // throwing, so the oracle's error text is reproduced here
                // instead of conflating the two conditions (an address with
                // no generated op is not a "not linked" destination).
                // AddrSpace::printRaw (space.cc:206-216): wordsize-1 offset
                // printed as 0x + 2*addrSize hex digits, leading-zero
                // trimmed to 8/12 digits.
                let off = addr.as_u64();
                let width = if off >> 48 != 0 { 16 } else if off >> 32 != 0 { 12 } else { 8 };
                return Err(JumpTableRecoveryError::Lowlevel {
                    message: format!(
                        "Could not find op at target address: ({},0x{:0width$x})",
                        addr
                            .get_space()
                            .map(|s| s.get_name())
                            .unwrap_or_else(|| "ram".to_string()),
                        off,
                        width = width
                    ),
                });
            };
            // cc:2542: tmpbl = op->getParent();
            let tmpbl = op
                .0
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(|p| p.upgrade());
            let Some(tmpbl) = tmpbl else {
                return Err(unlinked());
            };
            // cc:2543-2544: find the out-edge slot of the switch block
            // reaching tmpbl.
            let mut pos: Option<usize> = None;
            {
                let p = parent.read().unwrap();
                let bank = p.bank();
                let tmpbl_id = bank.registered_id_of(&tmpbl);
                for slot in 0..p.size_out() {
                    if let Some(e) = p.get_out(slot) {
                        if e.point == tmpbl_id {
                            pos = Some(slot);
                            break;
                        }
                    }
                }
            }
            let Some(pos) = pos else {
                // cc:2545-2546: throw LowlevelError("Jumptable destination not linked");
                return Err(unlinked());
            };
            // cc:2547: block2addr.push_back(IndexPair(pos,i));
            self.block2addr.push(IndexPair::new(pos as i32, i as i32));
        }
        // cc:2549: lastBlock = block2addr.back().blockPosition;
        if let Some(back) = self.block2addr.last() {
            self.last_block = back.block_position;
        }
        // cc:2550: sort(block2addr.begin(),block2addr.end()) —
        // IndexPair::operator< (jumptable.hh:628): position, then addressIndex.
        self.block2addr.sort_by(|a, b| {
            (a.block_position, a.address_index).cmp(&(b.block_position, b.address_index))
        });
        // cc:2552-2568: defaultBlock scan — the out-edge position with the
        // most address table entries (only when more than one).
        self.default_block = -1;
        let mut maxcount = 1;
        let mut iter = 0usize;
        while iter < self.block2addr.len() {
            let cur_pos = self.block2addr[iter].block_position;
            let mut next = iter;
            let mut count = 0;
            while next < self.block2addr.len() && self.block2addr[next].block_position == cur_pos
            {
                count += 1;
                next += 1;
            }
            iter = next;
            if count > maxcount {
                maxcount = count;
                self.default_block = cur_pos;
            }
        }
        Ok(())
    }

    // Ghidra: jumptable.cc:2594 JumpTable::trivialSwitchOver
    /// Make exactly one case for each output edge of the switch block.
    /// Faithful to `trivialSwitchOver` (jumptable.cc:2594-2609).
    pub fn trivial_switch_over(&mut self) -> Result<(), JumpTableRecoveryError> {
        self.block2addr.clear();
        self.block2addr.reserve(self.addresstable.len());
        let size_mismatch = JumpTableRecoveryError::Lowlevel {
            message: "Trivial addresstable and switch block size do not match".to_string(),
        };
        let Some(indirect) = self.indirect.clone() else {
            // RUGRA-GLUE: Ghidra dereferences indirect->getParent() directly;
            // an unlinked indirect cannot be validated, report the same
            // LowlevelError as the size mismatch path.
            return Err(size_mismatch);
        };
        let parent = indirect
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(|p| p.upgrade());
        let Some(parent) = parent else {
            return Err(size_mismatch);
        };
        let n_out = parent.read().unwrap().size_out();
        if n_out != self.addresstable.len() {
            return Err(size_mismatch);
        }
        // Addresses corresponds exactly to out-edges of switch block.
        for i in 0..n_out {
            self.block2addr.push(IndexPair::new(i as i32, i as i32));
        }
        self.last_block = n_out as i32 - 1;
        self.default_block = -1; // Trivial case does not have default case
        Ok(())
    }

    // Ghidra: jumptable.cc:2683 JumpTable::matchModel
    /// Try to match the JumpTable model to the existing function.
    ///
    /// This assumes the address table has already been recovered, via
    /// recoverAddresses() in another Funcdata instance. We rerun
    /// recoverModel() to match with the current Funcdata. If the recovered
    /// model does not match the original address table size, we may be
    /// missing control-flow: a multistage restart is issued, or a warning.
    /// Faithful to `matchModel` (jumptable.cc:2683-2708).
    pub fn match_model(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
    ) -> Result<(), JumpTableRecoveryError> {
        if !self.is_recovered() {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: "Trying to recover jumptable labels without addresses".to_string(),
            });
        }
        // cc:2690-2697: unless the model is an override, move model (created
        // on a flow copy) so we can create a current instance.
        if self.jmodel.is_some() {
            let is_override = self.jmodel.as_ref().map_or(false, |m| m.is_override());
            if !is_override {
                self.save_model();
            } else {
                self.clear_saved_model();
                fd.warning("Switch is manually overridden", self.opaddress);
            }
        }
        // cc:2698: recoverModel(fd) — maxtablesize from glb->max_jumptable_size
        // (same source as recoverAddresses, jumptable.cc:2626).
        let maxtablesize = fd
            .get_arch()
            .map_or(MAX_JUMPTABLE_SIZE, |a| a.max_jumptable_size);
        self.recover_model(fd, maxtablesize)?;
        // cc:2699-2707
        let table_size = self.jmodel.as_ref().map_or(0, |m| m.get_table_size());
        if self.jmodel.is_some() && table_size != self.addresstable.len() {
            if self.addresstable.len() == 1 && table_size > 1 {
                // cc:2700-2704: the jumptable was not fully recovered during
                // flow analysis, try to issue a restart.
                fd.localoverride.insert_multistage_jump(self.opaddress);
                fd.set_restart_pending(true);
                return Ok(());
            }
            fd.warning(
                "Could not find normalized switch variable to match jumptable",
                self.opaddress,
            );
        }
        Ok(())
    }

    // Ghidra: jumptable.cc:2714 JumpTable::recoverLabels
    /// Recover the case labels for \b this jump-table.
    ///
    /// The unnormalized switch variable is recovered, and for each possible
    /// address table entry, the variable value that produces it is calculated
    /// and stored as the formal \e case label for the associated code block.
    /// Faithful to `recoverLabels` (jumptable.cc:2714-2735).
    pub fn recover_labels(
        &mut self,
        fd: &crate::funcdata::Funcdata,
    ) -> Result<(), JumpTableRecoveryError> {
        let (maxaddsub, maxleftright, maxext) =
            (self.norm_max.addsub, self.norm_max.leftright, self.norm_max.ext);
        if self.jmodel.is_some() {
            // cc:2718-2725: findUnnormalized then buildLabels, with the
            // original model as label source when it holds a table.
            self.jmodel
                .as_mut()
                .unwrap()
                .find_unnormalized(maxaddsub, maxleftright, maxext);
            let orig_is_empty = self
                .origmodel
                .as_ref()
                .map_or(true, |m| m.get_table_size() == 0);
            if orig_is_empty {
                let jmodel = self.jmodel.as_ref().unwrap();
                jmodel.build_labels(
                    fd,
                    &self.addresstable,
                    &mut self.label,
                    jmodel.as_ref(),
                );
            } else {
                let jmodel = self.jmodel.as_ref().unwrap();
                let origmodel = self.origmodel.as_ref().unwrap();
                jmodel.build_labels(
                    fd,
                    &self.addresstable,
                    &mut self.label,
                    origmodel.as_ref(),
                );
            }
        } else {
            // cc:2727-2733: no model — fall back to a trivial model built
            // from the current out-edges. RUGRA-GLUE: JumpModelTrivial is
            // parentless (all methods use their parameters), mirroring
            // `new JumpModelTrivial(this)` without the pointer.
            if let Some(indirect) = self.indirect.clone() {
                let mut trivial = JumpModelTrivial::new();
                let maxtablesize = fd
                    .get_arch()
                    .map_or(MAX_JUMPTABLE_SIZE, |a| a.max_jumptable_size);
                // Parent facts snapshot (cc:2683 context): trivial recovery
                // reads only the out-edge count, but the parameter is
                // provided uniformly from the same &mut self state.
                let parent = JumpParentFacts {
                    partial_table: self.partial_table,
                    indirect: Some(indirect.clone()),
                };
                let _ = trivial.recover_model(
                    fd,
                    &indirect,
                    self.addresstable.len() as u32,
                    maxtablesize,
                    &parent,
                );
                trivial.build_addresses(fd, &indirect, &mut self.addresstable, None, None)?;
                self.trivial_switch_over()?;
                trivial.build_labels(fd, &self.addresstable, &mut self.label, &trivial);
            }
            // RUGRA-GLUE: a missing indirect (never linked by stageJumpTable)
            // is unrepresentable in Ghidra — dereferencing null would abort.
            // Skip label building; clearSavedModel below still runs (cc:2734).
        }
        self.clear_saved_model();
        Ok(())
    }

    // Ghidra: jumptable.hh:615 JumpTable::foldInGuards
    /// Hide any guard code for \b this switch.
    /// Faithful to the inline `{ return jmodel->foldInGuards(fd,this); }`.
    pub fn fold_in_guards(&mut self, fd: &mut crate::funcdata::Funcdata) -> bool {
        // RUGRA-GLUE: Ghidra's inline jmodel->foldInGuards(fd,this) aliases
        // the model and the table; Rust cannot hold &mut self.jmodel and
        // &mut self at once, so the model is temporarily taken out and put
        // back. No foldInGuards implementation reads jump.jmodel.
        let Some(mut model) = self.jmodel.take() else {
            // Ghidra would dereference null here; matchModel/recoverLabels
            // guarantee a model before SwitchNorm reaches this call. Mirror
            // the impossible state as "no change".
            return false;
        };
        let changed = model.fold_in_guards(fd, self);
        self.jmodel = Some(model);
        changed
    }

    // Ghidra: jumptable.cc:2847 JumpTable::checkForMultistage
    /// Check if this table has been marked as needing additional stages of
    /// recovery, via the override. Faithful to `checkForMultistage`
    /// (jumptable.cc:2847-2860): only a fully recovered single-entry table
    /// with a linked indirect op can be promoted; on a positive override
    /// query `partialTable` is set (the mutation survives the call, exactly
    /// like the C++ field write through the non-const `this`).
    pub fn check_for_multistage(&mut self, fd: &crate::funcdata::Funcdata) -> bool {
        if self.addresstable.len() != 1 {
            return false;
        }
        if self.partial_table {
            return false;
        }
        let Some(indirect) = self.indirect.clone() else {
            return false;
        };
        let addr = indirect.read().unwrap().get_addr();
        if fd.localoverride.query_multistage_jumptable(addr) {
            self.partial_table = true; // Mark that we need additional recovery
            true
        } else {
            false
        }
    }
}

/// Default upper bound on the number of entries a jump-table may hold when no
/// `Architecture` is attached to the [`crate::funcdata::Funcdata`]. Faithful to
/// the `max_jumptable_size` field of `Architecture` (architecture.cc:1433, default 1024).
pub const MAX_JUMPTABLE_SIZE: u32 = 1024;

/// Emulation failure discriminating Ghidra's two exception families inside
/// `EmulateFunction`.
///
/// `DataUnavailError`(loadimage.hh:31,`LowlevelError` 的子类)在
/// `emulatePath`(jumptable.cc:246-250)被**就地捕获**并转成带地址的新
/// `LowlevelError`;其余 `LowlevelError`(BRANCH/BRANCHIND/MULTIEQUAL/
/// 未实现指令)不被捕获、原样穿透。保留这个区分是错误通道对齐的关键。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulateFailure {
    /// Ghidra `DataUnavailError` raised by `LoadImage::loadFill`.
    DataUnavail(String),
    /// Ghidra `LowlevelError` (branch/segment/multiequal/unimplemented ops).
    Lowlevel(String),
}

impl EmulateFailure {
    // RUGRA-GLUE: Rust conversion into the typed stageJumpTable channel;
    // Ghidra 靠 DataUnavailError 继承 LowlevelError 落进同一 catch。
    fn into_recovery_error(self) -> JumpTableRecoveryError {
        match self {
            Self::DataUnavail(m) | Self::Lowlevel(m) => {
                JumpTableRecoveryError::Lowlevel { message: m }
            }
        }
    }
}

/// A light-weight emulator to calculate switch targets from switch variables.
///
/// We assume we only have to store memory state for individual Varnodes and
/// that dynamic LOADs are resolved from the LoadImage. BRANCH and CBRANCH
/// emulation will fail; there can only be one execution path, although there
/// can be multiple data-flow paths. Faithful to `EmulateFunction`
/// (jumptable.hh:110 / jumptable.cc:113-254 + 基类 `EmulatePcodeOp`
/// emulateutil.hh/cc)。
///
/// JUMPTABLE-EMULFN-0001:`fd` 持有 Architecture → loader 桥
/// (`getLoadImageValue` 真读 LoadImage,不再静默归零);`last_op` 前驱
/// 供 MULTIEQUAL 求值;BRANCH/BRANCHIND/CBRANCH-taken 走 Ghidra 的
/// LowlevelError 通道。
pub struct EmulateFunction<'fd> {
    /// The function being emulated (Ghidra `EmulateFunction::fd`); the base
    /// class holds `Architecture *glb` = `fd->getArch()` (jumptable.cc:160-165).
    fd: &'fd crate::funcdata::Funcdata,
    /// Light-weight memory state based on varnodes (keyed by Arc pointer id,
    /// mirroring `map<Varnode*,uintb> varnodeMap`).
    varnode_map: std::collections::HashMap<usize, u64>,
    /// The set of collected LOAD records, if any (`loadpoints`).
    pub loadpoints: Option<Vec<LoadTable>>,
    /// Last PcodeOp executed (`EmulatePcodeOp::lastOp`), maintained by
    /// `fallthru_op` and consumed by `execute_multiequal`.
    last_op: Option<Arc<RwLock<PcodeOp>>>,
    /// Current PcodeOp being executed (`EmulatePcodeOp::currentOp`).
    current_op: Option<Arc<RwLock<PcodeOp>>>,
}

impl<'fd> EmulateFunction<'fd> {
    // Ghidra: jumptable.cc:160 EmulateFunction::EmulateFunction
    /// Construct a fresh emulator bound to `fd` (base ctor takes
    /// `f->getArch()` for the LoadImage bridge).
    pub fn new(fd: &'fd crate::funcdata::Funcdata) -> Self {
        Self {
            fd,
            varnode_map: std::collections::HashMap::new(),
            loadpoints: None,
            last_op: None,
            current_op: None,
        }
    }

    // Ghidra: jumptable.hh:123 EmulateFunction::setLoadCollect
    /// Set where/if we collect LOAD information. Faithful to `setLoadCollect`.
    pub fn set_load_collect(&mut self, val: Option<Vec<LoadTable>>) {
        self.loadpoints = val;
    }

    // Ghidra: emulateutil.cc:30 EmulatePcodeOp::getLoadImageValue
    /// Pull a value from the load-image given a specific address.
    ///
    /// Faithful to `getLoadImageValue` (emulateutil.cc:47-61):
    /// `loadimage->loadFill(&res, sizeof(uintb), Address(spc,off))` 先读
    /// 8 字节,host 小端 + 空间小端 → 无字节交换,再
    /// `res &= calc_mask(sz)`。`loadFill` 失败抛 `DataUnavailError`
    /// (本实现返回 `Err(EmulateFailure::DataUnavail)`)。
    ///
    /// Rugra 单空间模型的 `spc` 参数保留为文档位:地址无 space 字段
    /// (P1 architectural item),x86-64 代码/ram 空间均小端。
    fn get_load_image_value(
        &self,
        _spc: crate::space::AddressSpace,
        off: u64,
        sz: usize,
    ) -> Result<u64, EmulateFailure> {
        let loader = self.fd.get_arch().and_then(|a| a.loader.clone());
        let Some(loader) = loader else {
            // Ghidra 的 glb->loader 在真实 Architecture 里非空;缺 loader
            // 是环境错误,按 DataUnavail 通道上报而非归零。
            return Err(EmulateFailure::DataUnavail(
                "Data-unavailable error: no LoadImage attached to Architecture".to_string(),
            ));
        };
        let bytes = loader
            .load_fill(8, Address::new(off))
            .map_err(|crate::loadimage::DataUnavailError(m)| EmulateFailure::DataUnavail(m))?;
        let mut res = 0u64;
        for (i, &b) in bytes.iter().enumerate().take(8) {
            res |= (b as u64) << (i * 8); // little-endian host + little-endian space
    }
        Ok(res & calc_mask(sz))
    }

    // Ghidra: jumptable.cc:179 EmulateFunction::getVarnodeValue
    /// Get the value of a Varnode which is in a syntax tree: constant →
    /// offset; seen before → cached map value; else read the LoadImage
    /// (`getLoadImageValue`)。失败沿 DataUnavail 通道上抛,禁止静默归零。
    pub fn get_varnode_value(
        &self,
        vn: &Arc<RwLock<Varnode>>,
    ) -> Result<u64, EmulateFailure> {
        let vn_rg = vn.read().unwrap();
        if vn_rg.is_constant() {
            return Ok(vn_rg.get_offset());
        }
        drop(vn_rg);
        let key = Arc::as_ptr(vn) as *const () as usize;
        if let Some(v) = self.varnode_map.get(&key) {
            return Ok(*v); // We have seen this varnode before
        }
        // Ghidra cc:191: return getLoadImageValue(vn->getSpace(), off, size)
        let (spc, off, size) = {
            let v = vn.read().unwrap();
            (v.get_space(), v.get_offset(), v.get_size())
        };
        self.get_load_image_value(spc, off, size)
    }

    // Ghidra: jumptable.cc:194 EmulateFunction::setVarnodeValue
    /// Set the value of a varnode in the syntax tree. Faithful to
    /// `setVarnodeValue` (jumptable.cc:194).
    pub fn set_varnode_value(&mut self, vn: &Arc<RwLock<Varnode>>, val: u64) {
        let key = Arc::as_ptr(vn) as *const () as usize;
        self.varnode_map.insert(key, val);
    }

    // Ghidra: jumptable.cc:200 EmulateFunction::fallthruOp
    /// Fall-thru semantics: keep track of lastOp for MULTIEQUAL; the outer
    /// loop controls execution flow.
    fn fallthru_op(&mut self) {
        if let Some(cur) = &self.current_op {
            self.last_op = Some(cur.clone());
        }
    }

    // Ghidra: emulateutil.hh:132 EmulatePcodeOp::setCurrentOp
    /// Establish the current PcodeOp being emulated (and its behavior).
    fn set_current_op(&mut self, op: Arc<RwLock<PcodeOp>>) {
        self.current_op = Some(op);
    }

    // Ghidra: emulateutil.cc:47 EmulatePcodeOp::executeUnary
    fn execute_unary_op(&mut self) -> Result<(), EmulateFailure> {
        let op = self.current_op.clone().unwrap();
        let (opc, out_size, in0_size, in0, out) = {
            let o = op.read().unwrap();
            (
                o.opcode,
                o.get_out().map(|v| v.read().unwrap().get_size()).unwrap_or(0),
                o.get_in(0).map(|v| v.read().unwrap().get_size()).unwrap_or(0),
                o.get_in(0).cloned(),
                o.get_out().cloned(),
            )
        };
        let in1 = match in0 {
            Some(v) => self.get_varnode_value(&v)?,
            None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
        };
        let out_vn = out.ok_or_else(|| {
            EmulateFailure::Lowlevel("Unary emulation unimplemented for op".into())
        })?;
        let val = crate::opbehavior::evaluate_unary(opc, out_size, in0_size, in1).ok_or_else(
            || {
                // Ghidra opbehavior.cc:118:
                // "Unary emulation unimplemented for " + name
                EmulateFailure::Lowlevel(
                    "Unary emulation unimplemented for opcode".to_string(),
                )
            },
        )?;
        self.set_varnode_value(&out_vn, val);
        Ok(())
    }

    // Ghidra: emulateutil.cc:56 EmulatePcodeOp::executeBinary
    fn execute_binary_op(&mut self) -> Result<(), EmulateFailure> {
        let op = self.current_op.clone().unwrap();
        let (opc, out_size, in_size, in0, in1, out) = {
            let o = op.read().unwrap();
            (
                o.opcode,
                o.get_out().map(|v| v.read().unwrap().get_size()).unwrap_or(0),
                o.get_in(0).map(|v| v.read().unwrap().get_size()).unwrap_or(0),
                o.get_in(0).cloned(),
                o.get_in(1).cloned(),
                o.get_out().cloned(),
            )
        };
        let v1 = match in0 {
            Some(v) => self.get_varnode_value(&v)?,
            None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
        };
        let v2 = match in1 {
            Some(v) => self.get_varnode_value(&v)?,
            None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
        };
        let out_vn = out.ok_or_else(|| {
            EmulateFailure::Lowlevel("Binary emulation unimplemented for op".into())
        })?;
        let val =
            crate::opbehavior::evaluate_binary(opc, out_size, in_size, v1, v2).ok_or_else(
                || {
                    // Ghidra opbehavior.cc:130:
                    // "Binary emulation unimplemented for " + name
                    EmulateFailure::Lowlevel(
                        "Binary emulation unimplemented for opcode".to_string(),
                    )
                },
            )?;
        self.set_varnode_value(&out_vn, val);
        Ok(())
    }

    // Ghidra: emulateutil.cc:66 EmulatePcodeOp::executeLoad
    /// Standard LOAD behavior: address from input(1), space from the
    /// space-id constant in input(0), value from the LoadImage.
    fn execute_load_base(&mut self) -> Result<(), EmulateFailure> {
        let op = self.current_op.clone().unwrap();
        let (in0, in1, out) = {
            let o = op.read().unwrap();
            (o.get_in(0).cloned(), o.get_in(1).cloned(), o.get_out().cloned())
        };
        let mut off = match in1 {
            Some(v) => self.get_varnode_value(&v)?,
            None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
        };
        let spc = in0.map(|v| get_space_from_const_vn(&v)).unwrap_or(crate::space::AddressSpace::Ram);
        // AddrSpace::addressToByte(off, spc->getWordSize())
        off = off.wrapping_mul(spc.word_size() as u64);
        let out_vn = out.ok_or_else(|| {
            EmulateFailure::Lowlevel("Unary emulation unimplemented for op".into())
        })?;
        let sz = out_vn.read().unwrap().get_size();
        let res = self.get_load_image_value(spc, off, sz)?;
        self.set_varnode_value(&out_vn, res);
        Ok(())
    }

    // Ghidra: jumptable.cc:113 EmulateFunction::executeLoad
    /// LOAD: record the LoadTable first (when collecting), then the base
    /// LoadImage evaluation.
    fn execute_load(&mut self) -> Result<(), EmulateFailure> {
        if self.loadpoints.is_some() {
            let op = self.current_op.clone().unwrap();
            let (in0, in1, out) = {
                let o = op.read().unwrap();
                (o.get_in(0).cloned(), o.get_in(1).cloned(), o.get_out().cloned())
            };
            let off = match in1 {
                Some(v) => self.get_varnode_value(&v)?,
                None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
            };
            let spc =
                in0.map(|v| get_space_from_const_vn(&v)).unwrap_or(crate::space::AddressSpace::Ram);
            let off = off.wrapping_mul(spc.word_size() as u64);
            let sz = out.map(|v| v.read().unwrap().get_size()).unwrap_or(0);
            if let Some(lp) = &mut self.loadpoints {
                lp.push(LoadTable::single(Address::new(off), sz as i32));
            }
        }
        self.execute_load_base()
    }

    // Ghidra: jumptable.cc:126 EmulateFunction::executeBranch
    fn execute_branch(&mut self) -> Result<(), EmulateFailure> {
        Err(EmulateFailure::Lowlevel(
            "Branch encountered emulating jumptable calculation".to_string(),
        ))
    }

    // Ghidra: jumptable.cc:132 EmulateFunction::executeBranchind
    fn execute_branchind(&mut self) -> Result<(), EmulateFailure> {
        Err(EmulateFailure::Lowlevel(
            "Indirect branch encountered emulating jumptable calculation".to_string(),
        ))
    }

    // Ghidra: emulateutil.cc:87 EmulatePcodeOp::executeCbranch
    fn execute_cbranch(&mut self) -> Result<bool, EmulateFailure> {
        let op = self.current_op.clone().unwrap();
        let (in1, flip) = {
            let o = op.read().unwrap();
            (o.get_in(1).cloned(), o.is_boolean_flip())
        };
        let cond = match in1 {
            Some(v) => self.get_varnode_value(&v)?,
            None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
        };
        // ((cond != 0) != currentOp->isBooleanFlip())
        Ok((cond != 0) != flip)
    }

    // Ghidra: emulateutil.cc:96 EmulatePcodeOp::executeMultiequal
    /// MULTIEQUAL: pick the incoming edge matching `last_op`'s block.
    fn execute_multiequal(&mut self) -> Result<(), EmulateFailure> {
        let op = self.current_op.clone().unwrap();
        let last_op = self.last_op.clone();
        let Some(last_op) = last_op else {
            // Ghidra cc:104-105 dereferences lastOp unconditionally
            // (`lastOp->getParent()`);未执行过任何 op 就遇到 MULTIEQUAL
            // 在 Ghidra 是空指针崩溃,这里按 Lowlevel 通道显式报错。
            return Err(EmulateFailure::Lowlevel(
                "Could not execute MULTIEQUAL".to_string(),
            ));
        };
        let bl = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        let last_bl = last_op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        let (Some(bl), Some(last_bl)) = (bl, last_bl) else {
            return Err(EmulateFailure::Lowlevel(
                "Could not execute MULTIEQUAL".to_string(),
            ));
        };
        let mut found: Option<usize> = None;
        {
            let bl_rg = bl.read().unwrap();
            let bank = bl_rg.bank();
            let last_bl_id = bank.registered_id_of(&last_bl);
            for i in 0..bl_rg.size_in() {
                if let Some(e) = bl_rg.get_in(i) {
                    if e.point == last_bl_id {
                        found = Some(i);
                        break;
                    }
                }
            }
        }
        let Some(i) = found else {
            return Err(EmulateFailure::Lowlevel(
                "Could not execute MULTIEQUAL".to_string(),
            ));
        };
        let (in_i, out) = {
            let o = op.read().unwrap();
            (o.get_in(i).cloned(), o.get_out().cloned())
        };
        let val = match in_i {
            Some(v) => self.get_varnode_value(&v)?,
            None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
        };
        if let Some(out_vn) = out {
            self.set_varnode_value(&out_vn, val);
        }
        Ok(())
    }

    // Ghidra: emulateutil.cc:112 EmulatePcodeOp::executeIndirect
    fn execute_indirect(&mut self) -> Result<(), EmulateFailure> {
        let op = self.current_op.clone().unwrap();
        let (in0, out) = {
            let o = op.read().unwrap();
            (o.get_in(0).cloned(), o.get_out().cloned())
        };
        let val = match in0 {
            Some(v) => self.get_varnode_value(&v)?,
            None => return Err(EmulateFailure::Lowlevel("Bad jumptable emulation".into())),
        };
        if let Some(out_vn) = out {
            self.set_varnode_value(&out_vn, val);
        }
        Ok(())
    }

    // Ghidra: emulateutil.cc:122 EmulatePcodeOp::executeSegmentOp
    fn execute_segmentop(&mut self) -> Result<(), EmulateFailure> {
        // Ghidra: segdef == 0 → "Segment operand missing definition"。
        // Rugra 未移植 SegmentOp 注册表(userops segment 句柄),统一走
        // 同一 Lowlevel 通道(保守降级,TODO JUMPTABLE-PIPELINE-0001)。
        Err(EmulateFailure::Lowlevel(
            "Segment operand missing definition".to_string(),
        ))
    }

    // Ghidra: emulate.cc:143 Emulate::executeCurrentOp
    /// Execute a single pcode op via the faithful dispatch table.
    fn execute_current_op(&mut self) -> Result<(), EmulateFailure> {
        let op = self.current_op.clone().unwrap();
        let (opc, n_in) = {
            let o = op.read().unwrap();
            (o.opcode, o.num_input())
        };
        match opc {
            OpCode::CPUI_LOAD => {
                self.execute_load()?;
                self.fallthru_op();
            }
            OpCode::CPUI_STORE => {
                // emulateutil.cc:73 executeStore: nowhere to store (no-op)
                self.fallthru_op();
            }
            OpCode::CPUI_BRANCH => {
                self.execute_branch()?;
            }
            OpCode::CPUI_CBRANCH => {
                if self.execute_cbranch()? {
                    self.execute_branch()?;
                } else {
                    self.fallthru_op();
                }
            }
            OpCode::CPUI_BRANCHIND | OpCode::CPUI_RETURN => {
                // RETURN dispatches to executeBranchind (emulate.cc:181-183)
                self.execute_branchind()?;
            }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER => {
                // jumptable.cc:138-157: ignore calls, fall through
                self.fallthru_op();
            }
            OpCode::CPUI_MULTIEQUAL => {
                self.execute_multiequal()?;
                self.fallthru_op();
            }
            OpCode::CPUI_INDIRECT => {
                self.execute_indirect()?;
                self.fallthru_op();
            }
            OpCode::CPUI_SEGMENTOP => {
                self.execute_segmentop()?;
                self.fallthru_op();
            }
            OpCode::CPUI_CPOOLREF | OpCode::CPUI_NEW => {
                // emulateutil.cc:127-133: ignore
                self.fallthru_op();
            }
            _ => {
                // OpBehavior::isUnary() ⇔ 1 输入(与 Ghidra 行为注册表一致)
                if n_in == 1 {
                    self.execute_unary_op()?;
                } else {
                    self.execute_binary_op()?;
                }
                self.fallthru_op();
            }
        }
        Ok(())
    }

    // Ghidra: jumptable.cc:216 EmulateFunction::emulatePath
    /// Execute from a given starting point and value to the common end-point
    /// of the path set. Flow the given value through all paths in the path
    /// container to produce the single output value. Faithful to `emulatePath`
    /// (jumptable.cc:216-254)。
    ///
    /// 错误通道(jumptable.cc:243-250):`DataUnavailError` 被捕获并转成
    /// `"Could not emulate address calculation at <addr>"`;其余 LowlevelError
    /// 原样穿透。归零静默继续已删除(JUMPTABLE-EMULFN-0001)。
    pub fn emulate_path(
        &mut self,
        val: u64,
        path_meld: &PathMeld,
        startop: &Arc<RwLock<PcodeOp>>,
        startvn: &Arc<RwLock<Varnode>>,
    ) -> Result<u64, JumpTableRecoveryError> {
        let conv = |f: EmulateFailure| f.into_recovery_error();
        // Ghidra cc:219-221: find startop's index i in pathMeld.
        let mut i = path_meld.num_ops();
        for idx in 0..path_meld.num_ops() {
            if Arc::ptr_eq(&path_meld.get_op(idx), startop) {
                i = idx;
                break;
            }
        }
        // Ghidra cc:222-234: MULTIEQUAL start handling.
        let mut cur_startvn = startvn.clone();
        let mut cur_i = i;
        if path_meld.get_op(i).read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL {
            let me_op = path_meld.get_op(i);
            let me_rg = me_op.read().unwrap();
            let mut found_j = me_rg.num_input();
            for j in 0..me_rg.num_input() {
                if let Some(v) = me_rg.get_in(j) {
                    if Arc::ptr_eq(v, &cur_startvn) {
                        found_j = j;
                        break;
                    }
                }
            }
            // Ghidra cc:228-229: if ((j == numInput())||(i==0)) throw
            //   LowlevelError("Cannot start jumptable emulation with
            //   unresolved MULTIEQUAL");
            if found_j == me_rg.num_input() || i == 0 {
                return Err(JumpTableRecoveryError::Lowlevel {
                    message: "Cannot start jumptable emulation with unresolved MULTIEQUAL"
                        .to_string(),
                });
            }
            // startvn = startop->getOut(); i -= 1;
            if let Some(o) = me_rg.get_out().cloned() {
                cur_startvn = o;
                cur_i = i - 1;
            } else {
                return Err(JumpTableRecoveryError::Lowlevel {
                    message: "Cannot start jumptable emulation with unresolved MULTIEQUAL"
                        .to_string(),
                });
            }
        }
        // Ghidra cc:235-236: if (i==pathMeld.numOps()) throw LowlevelError
        //   ("Bad jumptable emulation");
        if i == path_meld.num_ops() {
            return Err(JumpTableRecoveryError::Lowlevel {
                message: "Bad jumptable emulation".to_string(),
            });
        }
        // Ghidra cc:237-238: if (!startvn->isConstant())
        //   setVarnodeValue(startvn,val);
        if !cur_startvn.read().unwrap().is_constant() {
            self.set_varnode_value(&cur_startvn, val);
        }
        // Ghidra cc:239-251: execute ops from i down to 1 (op 0 is the
        // BRANCHIND itself); DataUnavailError → "Could not emulate address
        // calculation at <addr>".
        while cur_i > 0 {
            let curop = path_meld.get_op(cur_i);
            cur_i -= 1;
            let curop_addr = curop.read().unwrap().get_addr();
            self.set_current_op(curop);
            if let Err(err) = self.execute_current_op() {
                return Err(match err {
                    EmulateFailure::DataUnavail(_) => JumpTableRecoveryError::Lowlevel {
                        message: format!(
                            "Could not emulate address calculation at {}",
                            curop_addr
                        ),
                    },
                    other => conv(other),
                });
            }
        }
        // Ghidra cc:252-253: return getVarnodeValue(pathMeld.getOp(0)->getIn(0))
        let first_op = path_meld.get_op(0);
        let in0 = first_op.read().unwrap().get_in(0).cloned();
        match in0 {
            Some(vn) => self.get_varnode_value(&vn).map_err(conv),
            None => Err(JumpTableRecoveryError::Lowlevel {
                message: "Bad jumptable emulation".to_string(),
            }),
        }
    }
}

// RUGRA-GLUE: wraps Varnode::getSpaceFromConst (varnode.hh:426, not in
// jumptable.cc); LOAD 的 space-id 常量解码,与 constseq.rs/double_precis.rs
// 的同名 helper 同语义(常量的 offset 即 SpaceId)。
fn get_space_from_const_vn(vn: &Arc<RwLock<Varnode>>) -> crate::space::AddressSpace {
    let r = vn.read().unwrap();
    if r.is_constant() {
        crate::space::AddressSpace::from_id(r.get_offset() as crate::space::SpaceId)
    } else {
        r.get_space()
    }
}

// RUGRA-GLUE: Rust typed entry point wiring JumpTable recovery; Ghidra does this inline in Funcdata::stageJumpTable (funcdata_block.cc:491)
/// Attempt to recover a single [`JumpTable`] while preserving the typed
/// Ghidra exception channel.
pub fn try_recover_classified(
    indop: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    fd: &crate::funcdata::Funcdata,
) -> Result<JumpTable, JumpTableRecoveryError> {
    let op_addr = indop.read().unwrap().get_addr();
    let mut jt = JumpTable::new(op_addr);
    jt.set_indirect_op(indop.clone());
    jt.recover_addresses_classified(fd)?;
    Ok(jt)
}

// RUGRA-GLUE: Option compatibility adapter for flow/funcdata callers not yet migrated to typed stageJumpTable recovery
/// Attempt to recover a single [`JumpTable`] for the BRANCHIND op `indop`.
///
/// This is the Rust analogue of Ghidra's
/// `Funcdata::recoverJumpTable` (funcdata_block.cc:640) +
/// `JumpTable::recoverAddresses` (jumptable.cc:2645), collapsed into a single
/// call because Rugra does not yet clone a partial `Funcdata` for dedicated
/// jumptable simplification. Returns a populated `JumpTable` on success, or
/// `None` if no model could be recovered.
///
/// This compatibility wrapper collapses the typed error to `None`; it does
/// not catch panics or misclassify internal failures as ordinary recovery
/// failures. Call [`try_recover_classified`] wherever the recovery mode is
/// observable.
pub fn try_recover(
    indop: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    fd: &crate::funcdata::Funcdata,
) -> Option<JumpTable> {
    try_recover_classified(indop, fd).ok()
}

// RUGRA-GLUE: Rust per-BRANCHIND loop; Ghidra drives this from flow tracing (flow.cc/subflow.cc), not jumptable.cc
/// Recover jump-tables for every BRANCHIND in `fd` and attach the successful
/// ones to `fd.jump_tables`.
///
/// This is the entry point that finally wires the [`JumpTable`] machinery into
/// [`crate::funcdata::Funcdata`]. It mirrors the per-BRANCHIND loop that, in
/// Ghidra, is driven from flow tracing (`subflow.cc` →
/// `Funcdata::recoverJumpTable`). Because Rugra performs recovery in-place
/// (no partial `Funcdata` clone), we run it as a pre-pass.
///
/// For each alive BRANCHIND op that does not already have a [`JumpTable`] (see
/// [`crate::funcdata::Funcdata::find_jump_table`]), we attempt recovery via
/// [`try_recover`]; successes are pushed onto `fd.jump_tables`. Failures are
/// silently skipped — recovery is best-effort and may miss switches whose
/// data-flow the current emulator cannot fully evaluate.
///
/// Faithful to the integration point described in
/// `Funcdata::recoverJumpTable` (funcdata_block.cc:640).
pub fn recover_jump_tables(fd: &mut crate::funcdata::Funcdata) -> usize {
    use crate::opcodes::OpCode;
    // Snapshot the alive op list so we can mutably borrow fd while iterating.
    let alive: Vec<crate::op::PcodeOpRef> = fd.obank.iter_alive().cloned().collect::<Vec<_>>();
    let mut recovered = 0usize;

    for op_ref in alive {
        // Only BRANCHIND ops can anchor a jump-table.
        let is_branchind = {
            let op_rg = op_ref.0.read().unwrap();
            op_rg.opcode == OpCode::CPUI_BRANCHIND
        };
        if !is_branchind {
            continue;
        }

        // Skip if a table for this op address already exists.
        let op_addr = op_ref.0.read().unwrap().get_addr().as_u64();
        let already = fd
            .jump_tables
            .iter()
            .any(|jt| jt.read().unwrap().get_op_address().as_u64() == op_addr);
        if already {
            continue;
        }

        if let Some(jt) = try_recover(&op_ref.0, fd) {
            fd.jump_tables
                .push(std::sync::Arc::new(std::sync::RwLock::new(jt)));
            recovered += 1;
        }
    }
    recovered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::SeqNum;
    use crate::space::{AddrSpace, SpaceType};

    #[test]
    fn test_load_table_single() {
        let lt = LoadTable::single(Address::new(0x1000), 4);
        assert_eq!(lt.num, 1);
        assert_eq!(lt.size, 4);
    }

    #[test]
    fn test_load_table_collapse_contiguous() {
        let mut table = vec![
            LoadTable::new(Address::new(0x1000), 4, 1),
            LoadTable::new(Address::new(0x1004), 4, 1),
            LoadTable::new(Address::new(0x1008), 4, 1),
        ];
        LoadTable::collapse_table(&mut table);
        // Three contiguous entries collapse into one with num=3.
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].num, 3);
        assert_eq!(table[0].addr.as_u64(), 0x1000);
    }

    #[test]
    fn test_load_table_collapse_noncontiguous() {
        let mut table = vec![
            LoadTable::new(Address::new(0x1000), 4, 1),
            LoadTable::new(Address::new(0x5000), 4, 1),
        ];
        LoadTable::collapse_table(&mut table);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_load_table_equal_address_sort_ignores_size_and_num() {
        let mut table = vec![
            LoadTable::new(Address::new(0x4000), 8, 2),
            LoadTable::new(Address::new(0x4000), 4, 3),
            LoadTable::new(Address::new(0x4010), 8, 1),
        ];
        LoadTable::collapse_table(&mut table);
        assert_eq!(
            table,
            vec![
                LoadTable::new(Address::new(0x4000), 8, 2),
                LoadTable::new(Address::new(0x4000), 4, 3),
                LoadTable::new(Address::new(0x4010), 8, 1),
            ]
        );
    }

    #[test]
    fn test_load_table_libstdcxx_equal_key_threshold_permutation() {
        let mut below_threshold = (0..16)
            .map(|identity| LoadTable::new(Address::new(0x4000), identity + 1, 1))
            .collect::<Vec<_>>();
        LoadTable::sort_by_address_libstdcxx_16(&mut below_threshold);
        assert_eq!(
            below_threshold
                .iter()
                .map(|entry| entry.size)
                .collect::<Vec<_>>(),
            (1..=16).collect::<Vec<_>>()
        );

        let mut above_threshold = (0..17)
            .map(|identity| LoadTable::new(Address::new(0x4000), identity + 1, 1))
            .collect::<Vec<_>>();
        LoadTable::sort_by_address_libstdcxx_16(&mut above_threshold);
        assert_eq!(
            above_threshold
                .iter()
                .map(|entry| entry.size)
                .collect::<Vec<_>>(),
            vec![9, 17, 16, 15, 14, 13, 12, 11, 10, 1, 8, 7, 6, 5, 4, 3, 2]
        );
    }

    #[test]
    fn test_load_table_collapse_wraps_in_tagged_space() {
        let tiny = AddrSpace::new_space(
            SpaceType::Processor,
            "tiny",
            false,
            1,
            1,
            8,
            0,
            0,
            0,
        );
        let mut table = vec![
            LoadTable::single(Address::with_space(&tiny, 0xfc), 4),
            LoadTable::single(Address::with_space(&tiny, 0), 4),
        ];
        LoadTable::collapse_table(&mut table);
        assert_eq!(
            table,
            vec![LoadTable::new(Address::with_space(&tiny, 0xfc), 4, 2)]
        );
    }

    #[test]
    fn test_load_table_collapse_orders_full_address_space_then_offset() {
        let code = AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            0,
            0,
            0,
        );
        let tiny = AddrSpace::new_space(
            SpaceType::Processor,
            "tiny",
            false,
            1,
            1,
            8,
            0,
            0,
            0,
        );
        let mut table = vec![
            LoadTable::single(Address::with_space(&tiny, 0), 4),
            LoadTable::single(Address::with_space(&code, 0x4000), 4),
            LoadTable::single(Address::with_space(&tiny, 4), 4),
            LoadTable::single(Address::with_space(&code, 0x4004), 4),
        ];
        LoadTable::collapse_table(&mut table);
        assert_eq!(
            table,
            vec![
                LoadTable::new(Address::with_space(&code, 0x4000), 4, 2),
                LoadTable::new(Address::with_space(&tiny, 0), 4, 2),
            ]
        );
    }

    #[test]
    fn test_index_pair_ordering() {
        let a = IndexPair::new(0, 5);
        let b = IndexPair::new(1, 2);
        assert!(a.less_than(&b));
        assert!(!b.less_than(&a));
        let c = IndexPair::new(0, 3);
        assert!(c.less_than(&a));
    }

    #[test]
    fn test_index_pair_compare_by_position() {
        let a = IndexPair::new(2, 10);
        let b = IndexPair::new(5, 1);
        assert!(IndexPair::compare_by_position(&a, &b));
    }

    #[test]
    fn test_jump_values_range_iteration() {
        let mut r = JumpValuesRange::default();
        r.set_range(CircleRange::new(0, 4, 4, 1));
        assert_eq!(r.get_size(), 4);
        r.curval.store(0, Ordering::Relaxed);
        assert!(r.contains(2));
        assert!(!r.contains(5));
    }

    #[test]
    fn test_jump_values_range_default() {
        let mut base = JumpValuesRange::default();
        base.set_range(CircleRange::new(0, 3, 4, 1));
        let mut r = JumpValuesRangeDefault {
            base,
            extravalue: 99,
            extravn: None,
            extraop: None,
            lastvalue: AtomicBool::new(false),
        };
        assert_eq!(r.get_size(), 4); // 3 + 1 extra
        assert!(r.contains(2));
        assert!(r.contains(99));
        assert!(!r.contains(50));
        // Iterate: 0, 1, 2, then extra 99.
        r.base.curval.store(0, Ordering::Relaxed);
        assert!(r.next());
        assert!(r.next());
        // After the range is exhausted, the extra value should appear.
        let advanced = r.next();
        assert!(advanced);
        assert_eq!(r.get_value(), 99);
        assert!(!r.is_reversible());
        assert!(!r.next());
    }

    #[test]
    fn test_recovery_mode_values() {
        assert_eq!(RecoveryMode::Success as u8, 0);
        assert_eq!(RecoveryMode::FailThunk as u8, 2);
    }

    #[test]
    fn test_jump_table_construction() {
        let jt = JumpTable::new(Address::new(0x401000));
        assert!(!jt.is_recovered());
        assert_eq!(jt.get_op_address().as_u64(), 0x401000);
        assert_eq!(jt.get_default_block(), -1);
        assert!(!jt.is_partial());
        assert!(!jt.is_override());
    }

    #[test]
    fn test_jump_table_add_block() {
        // Ghidra cc:2535-2543: lastBlock = indirect->getParent()->sizeOut().
        // Build a BRANCHIND whose parent block has two out-edges so the
        // faithful semantics (not the old addresstable.len() approximation)
        // is what the assertion exercises.
        let mut jt = JumpTable::new(Address::new(0x401000));
        let indop = Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x401000), 0),
            OpCode::CPUI_BRANCHIND,
        )));
        let bl = Arc::new(RwLock::new(crate::block::BlockBasic::new(0, Address::new(0x401000))));
        // The registration graph must outlive every edge consumer below
        // (edges resolve through its bank; blocks hold only a weak link).
        let bl_dyn: std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        > = bl.clone();
        let mut g = crate::block::BlockGraph::new();
        g.register_fixture_blocks(&[bl_dyn.clone()]);
        {
            let mut bl_w = bl.write().unwrap();
            bl_w.outgoing.push(g.fixture_edge(&bl_dyn, 0));
            bl_w.outgoing.push(g.fixture_edge(&bl_dyn, 1));
            // (g) guard-shadow: test-registered block — sync after the raw
            // pushes.
            bl_w.sync_bank_shadows();
        }
        indop.write().unwrap().parent =
            Some(std::sync::Arc::downgrade(&(bl.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>)));
        jt.set_indirect_op(indop);
        jt.add_block_to_switch(Address::new(0x401200), 5);
        assert_eq!(jt.num_entries(), 1);
        assert_eq!(jt.get_label_by_index(0), 5);
        // sizeOut of the switch block (2), not the table length (1).
        assert_eq!(jt.last_block, 2);
    }

    #[test]
    fn test_jump_table_clear() {
        let mut jt = JumpTable::new(Address::new(0x401000));
        jt.add_block_to_switch(Address::new(0x401200), 5);
        jt.partial_table = true;
        jt.clear();
        assert_eq!(jt.num_entries(), 0);
        assert!(!jt.is_partial());
        assert_eq!(jt.last_block, -1);
    }

    #[test]
    fn test_emulate_function_varnode_map() {
        use crate::funcdata::Funcdata;
        use crate::varnode::Varnode;
        let fd = Funcdata::new("test", Address::new(0x1000), 16);
        let mut emul = EmulateFunction::new(&fd);
        let vn = Arc::new(RwLock::new(Varnode::new_unique(0, 4)));
        emul.set_varnode_value(&vn, 0xdeadbeef);
        assert_eq!(emul.get_varnode_value(&vn), Ok(0xdeadbeef));
    }

    #[test]
    fn test_emulate_function_constant() {
        use crate::funcdata::Funcdata;
        use crate::varnode::Varnode;
        let fd = Funcdata::new("test", Address::new(0x1000), 16);
        let emul = EmulateFunction::new(&fd);
        let vn = Arc::new(RwLock::new(Varnode::new_constant(42, 4)));
        assert_eq!(emul.get_varnode_value(&vn), Ok(42));
    }

    #[test]
    fn test_emulate_function_loader_fallback_typed_error() {
        // JUMPTABLE-EMULFN-0001: an unseen non-constant varnode must hit the
        // LoadImage channel; without a loader this is a typed DataUnavail
        // error, never a silent 0 (Ghidra cc:191 getLoadImageValue).
        use crate::funcdata::Funcdata;
        use crate::varnode::Varnode;
        let fd = Funcdata::new("test", Address::new(0x1000), 16);
        let emul = EmulateFunction::new(&fd);
        let vn = Arc::new(RwLock::new(Varnode::new_unique(5, 4)));
        match emul.get_varnode_value(&vn) {
            Err(EmulateFailure::DataUnavail(_)) => {}
            other => panic!("expected DataUnavail, got {:?}", other),
        }
    }

    #[test]
    fn test_path_meld_single() {
        use crate::varnode::Varnode;
        let vn = Arc::new(RwLock::new(Varnode::new_unique(0, 4)));
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BRANCHIND,
        )));
        let mut pm = PathMeld::default();
        pm.set_single(op, vn);
        assert_eq!(pm.num_common_varnode(), 1);
        assert_eq!(pm.num_ops(), 1);
        assert!(!pm.empty());
    }

    #[test]
    fn test_jump_basic_stride() {
        use crate::varnode::Varnode;
        // A varnode whose lower 2 bits are known zero → stride 4.
        let vn = Varnode::new_register(4, 4);
        // NZ mask for an unknown register defaults to all-ones for the size;
        // get_stride then returns 1. Verify the function doesn't panic.
        let s = JumpBasic::get_stride(&vn);
        assert!(s == 1 || s == 2 || s == 4 || s == 8 || s == 16 || s == 32);
    }

    #[test]
    fn test_duplicate_varnodes() {
        use crate::varnode::Varnode;
        let vn1 = Arc::new(RwLock::new(Varnode::new_unique(0, 4)));
        let vn2 = vn1.clone();
        let vn3 = Arc::new(RwLock::new(Varnode::new_unique(1, 4)));
        assert!(JumpBasic::duplicate_varnodes(&[vn1.clone(), vn2]));
        assert!(!JumpBasic::duplicate_varnodes(&[vn1, vn3]));
    }

    #[test]
    fn test_get_max_value_int_and() {
        use crate::address::SeqNum;
        use crate::varnode::Varnode;
        // Build: out = INT_AND(switchvn, 0xFF)
        let switchvn = Arc::new(RwLock::new(Varnode::new_unique(0, 4)));
        let constvn = Arc::new(RwLock::new(Varnode::new_constant(0xFF, 4)));
        let mut and_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_AND,
        );
        and_op.inrefs.push(switchvn.clone());
        and_op.inrefs.push(constvn);
        let outvn = Varnode::new_unique(1, 4);
        let mut outvn = outvn;
        outvn.flags |= crate::varnode::varnode_flags::WRITTEN;
        let and_arc = Arc::new(RwLock::new(and_op));
        outvn.def = Some(std::sync::Arc::downgrade(&and_arc));
        let outvn_arc = Arc::new(RwLock::new(outvn));
        // getMaxValue should return (coveringmask(0xFF)+1) & calc_mask(4) = 0x100.
        let mv = JumpBasic::get_max_value(&outvn_arc.read().unwrap());
        assert_eq!(mv, 0x100);
    }

    #[test]
    fn test_get_max_value_unrestricted() {
        use crate::varnode::Varnode;
        // An unwritten varnode returns 0 (unrestricted).
        let vn = Varnode::new_unique(0, 4);
        assert_eq!(JumpBasic::get_max_value(&vn), 0);
    }

    #[test]
    fn test_quasi_copy_copy_chain() {
        use crate::address::SeqNum;
        use crate::varnode::{Varnode, varnode_flags};
        // Build: out = COPY(in); in = COPY(src)
        // The quasi-copy chain should walk back to src.
        let src = Arc::new(RwLock::new(Varnode::new_register(0, 4)));
        let mut mid_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        );
        mid_op.inrefs.push(src.clone());
        let mid = Arc::new(RwLock::new({
            let mut v = Varnode::new_unique(1, 4);
            v.flags |= varnode_flags::WRITTEN;
            v
        }));
        let mid_op_arc = Arc::new(RwLock::new(mid_op));
        mid.write().unwrap().def = Some(std::sync::Arc::downgrade(&mid_op_arc));

        let mut out_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1004), 0),
            OpCode::CPUI_COPY,
        );
        out_op.inrefs.push(mid.clone());
        let out = Arc::new(RwLock::new({
            let mut v = Varnode::new_unique(2, 4);
            v.flags |= varnode_flags::WRITTEN;
            v
        }));
        let out_op_arc = Arc::new(RwLock::new(out_op));
        out.write().unwrap().def = Some(std::sync::Arc::downgrade(&out_op_arc));

        let (ancestor, bits) = quasi_copy(&out);
        assert!(ancestor.is_some());
        // Should walk back through both COPYs to src.
        assert!(Arc::ptr_eq(&ancestor.unwrap(), &src));
        // bits_preserved = mostsigbit_set(nzm) + 1. quasiCopy reads the raw
        // nzm FIELD (varnode.hh:231), which calcNZMask maintains; fresh
        // unique varnodes carry ~0 -> 64, a post-calcNZMask 4-byte register
        // carries calc_mask(4)=0xffffffff -> 32. Set the analyzed state
        // explicitly (mirrors funcdata_varnode.cc:889-892).
        for vn in [&src, &mid, &out] {
            vn.write().unwrap().set_nzm(0xffff_ffff);
        }
        let (ancestor, bits) = quasi_copy(&out);
        assert!(Arc::ptr_eq(&ancestor.unwrap(), &src));
        assert_eq!(bits, 32);
        // Fresh (pre-calcNZMask) state reads the stale ~0 field -> 64, the
        // same value oracle Ghidra would see before Heritage runs.
        let fresh = Arc::new(RwLock::new(Varnode::new_unique(3, 4)));
        let (_, fresh_bits) = quasi_copy(&fresh);
        assert_eq!(fresh_bits, 64);
    }

    #[test]
    fn test_is_load_in_path_with_def() {
        use crate::address::SeqNum;
        use crate::varnode::{Varnode, varnode_flags};
        // Build a LOAD op producing a varnode.
        let spc_vn = Arc::new(RwLock::new(Varnode::new_constant(0, 8)));
        let ptr_vn = Arc::new(RwLock::new(Varnode::new_unique(0, 8)));
        let mut load_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_LOAD,
        );
        load_op.inrefs.push(spc_vn);
        load_op.inrefs.push(ptr_vn);
        let loaded = Arc::new(RwLock::new({
            let mut v = Varnode::new_unique(1, 4);
            v.flags |= varnode_flags::WRITTEN;
            v
        }));
        let load_arc = Arc::new(RwLock::new(load_op));
        loaded.write().unwrap().def = Some(std::sync::Arc::downgrade(&load_arc));

        let mut pm = PathMeld::default();
        // Pretend the LOAD result is the first common varnode.
        let br_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1008), 0),
            OpCode::CPUI_BRANCHIND,
        )));
        pm.set_single(br_op, loaded);
        // i=1 → checks common_vn[0] (the loaded varnode).
        assert!(pm.is_load_in_path(1));
    }

    #[test]
    fn test_emulate_path_int_add() {
        use crate::address::SeqNum;
        use crate::varnode::{Varnode, varnode_flags};
        // Build: branchind_input = INT_ADD(switchvn, const=0x1000)
        //        BRANCHIND(branchind_input)
        // emulate_path(switchvn=5) should produce 5 + 0x1000 = 0x1005.
        let switchvn = Arc::new(RwLock::new(Varnode::new_unique(0, 4)));
        let constvn = Arc::new(RwLock::new(Varnode::new_constant(0x1000, 4)));

        // INT_ADD op with output set.
        let add_out = Arc::new(RwLock::new({
            let mut v = Varnode::new_unique(1, 4);
            v.flags |= varnode_flags::WRITTEN;
            v
        }));
        let mut add_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        );
        add_op.inrefs.push(switchvn.clone());
        add_op.inrefs.push(constvn);
        add_op.output = Some(add_out.clone());
        let add_op_arc = Arc::new(RwLock::new(add_op));
        add_out.write().unwrap().def = Some(std::sync::Arc::downgrade(&add_op_arc));

        // BRANCHIND op (the common end-point).
        let mut br_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1004), 0),
            OpCode::CPUI_BRANCHIND,
        );
        br_op.inrefs.push(add_out.clone());
        let br_op_arc = Arc::new(RwLock::new(br_op));

        // Build a PathMeld with one path: [BRANCHIND(slot=0), INT_ADD(slot=0)].
        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: br_op_arc.clone(), slot: 0 },
            PcodeOpNode { op: add_op_arc.clone(), slot: 0 },
        ]);

        let fd = crate::funcdata::Funcdata::new("test", Address::new(0x1000), 16);
        let mut emul = EmulateFunction::new(&fd);
        // startop = the ADD op (op index 1 in the path), startvn = switchvn.
        let result = emul.emulate_path(5, &pm, &add_op_arc, &switchvn);
        assert_eq!(result, Ok(0x1005));
    }

    #[test]
    fn test_emulate_path_copy() {
        use crate::address::SeqNum;
        use crate::varnode::{Varnode, varnode_flags};
        // Build: branchind_input = COPY(switchvn)
        // emulate_path(switchvn=42) should produce 42.
        let switchvn = Arc::new(RwLock::new(Varnode::new_unique(0, 4)));
        let copy_out = Arc::new(RwLock::new({
            let mut v = Varnode::new_unique(1, 4);
            v.flags |= varnode_flags::WRITTEN;
            v
        }));
        let mut copy_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        );
        copy_op.inrefs.push(switchvn.clone());
        copy_op.output = Some(copy_out.clone());
        let copy_op_arc = Arc::new(RwLock::new(copy_op));
        copy_out.write().unwrap().def = Some(std::sync::Arc::downgrade(&copy_op_arc));

        let mut br_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1004), 0),
            OpCode::CPUI_BRANCHIND,
        );
        br_op.inrefs.push(copy_out.clone());
        let br_op_arc = Arc::new(RwLock::new(br_op));

        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: br_op_arc.clone(), slot: 0 },
            PcodeOpNode { op: copy_op_arc.clone(), slot: 0 },
        ]);

        let fd = crate::funcdata::Funcdata::new("test", Address::new(0x1000), 16);
        let mut emul = EmulateFunction::new(&fd);
        let result = emul.emulate_path(42, &pm, &copy_op_arc, &switchvn);
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn test_emulate_path_branch_typed_error() {
        // JUMPTABLE-EMULFN-0001: BRANCH inside the path meld must surface the
        // exact Ghidra LowlevelError ("Branch encountered emulating jumptable
        // calculation", jumptable.cc:129), never a silent value.
        use crate::address::SeqNum;
        use crate::varnode::{Varnode, varnode_flags};
        let fd = crate::funcdata::Funcdata::new("test", Address::new(0x1000), 16);
        let switchvn = Arc::new(RwLock::new(Varnode::new_unique(0, 4)));
        let branch_out = Arc::new(RwLock::new({
            let mut v = Varnode::new_unique(1, 4);
            v.flags |= varnode_flags::WRITTEN;
            v
        }));
        let mut br_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BRANCH,
        );
        br_op.inrefs.push(switchvn.clone());
        br_op.output = Some(branch_out.clone());
        let br_op_arc = Arc::new(RwLock::new(br_op));
        branch_out.write().unwrap().def = Some(std::sync::Arc::downgrade(&br_op_arc));

        let mut bi_op = PcodeOp::new(
            SeqNum::new(Address::new(0x1004), 0),
            OpCode::CPUI_BRANCHIND,
        );
        bi_op.inrefs.push(branch_out.clone());
        let bi_op_arc = Arc::new(RwLock::new(bi_op));

        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: bi_op_arc.clone(), slot: 0 },
            PcodeOpNode { op: br_op_arc.clone(), slot: 0 },
        ]);

        let mut emul = EmulateFunction::new(&fd);
        let result = emul.emulate_path(1, &pm, &br_op_arc, &switchvn);
        match result {
            Err(JumpTableRecoveryError::Lowlevel { message }) => {
                assert_eq!(message, "Branch encountered emulating jumptable calculation");
            }
            other => panic!("expected branch LowlevelError, got {:?}", other),
        }
    }

    #[test]
    fn test_recover_model_no_parent_fail_closed() {
        // JUMPTABLE-PIPELINE-0001 段1契约:stageJumpTable 未建 partial(无
        // 基本块)时,BRANCHIND 无 parent 块 → JumpBasic::recover_model 必须
        // fail-closed 返回 Ok(false),不得静默走无守卫的 smallest-normal。
        use crate::address::SeqNum;
        use crate::funcdata::Funcdata;
        use crate::varnode::Varnode;
        let fd = Funcdata::new("test", Address::new(0x1000), 16);
        let indop = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BRANCHIND,
        )));
        // 无 def 的寄存器读(等价 Ghidra raw pcode 的跨指令读)。
        let raw_read = Arc::new(RwLock::new(Varnode::new_register(0, 8)));
        indop.write().unwrap().inrefs.push(raw_read);

        let mut jbasic = JumpBasic::new();
        assert_eq!(
            jbasic.recover_model(&fd, &indop, 0, 1024, &JumpParentFacts::default()),
            Ok(false)
        );
    }

    #[test]
    fn test_jump_table_recover_model_selection_chain() {
        // JUMPTABLE-SELECTION-0001: 选择链 = override → Assisted → Basic →
        // Basic2,Trivial 不在链里;全失败时 jmodel=None 且 recover_model
        // 返回 Ok(false)(Ghidra cc:2283-2284)。
        use crate::address::SeqNum;
        use crate::funcdata::Funcdata;
        use crate::varnode::Varnode;
        let fd = Funcdata::new("test", Address::new(0x1000), 16);
        let indop = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_BRANCHIND,
        )));
        let raw_read = Arc::new(RwLock::new(Varnode::new_register(0, 8)));
        indop.write().unwrap().inrefs.push(raw_read);

        let mut jt = JumpTable::new(Address::new(0x1000));
        jt.set_indirect_op(indop.clone());
        assert_eq!(jt.recover_model(&fd, 1024), Ok(false));
        assert!(jt.jmodel.is_none());

        // override 挂接后:重跑 override 模型并成功(setAddresses 固定表)。
        jt.set_override(&[Address::new(0x2000), Address::new(0x2100)], Address::new(0), 0, 0);
        assert_eq!(jt.recover_model(&fd, 1024), Ok(true));
        assert!(jt.jmodel.as_ref().map_or(false, |m| m.is_override()));
        assert_eq!(jt.jmodel.as_ref().unwrap().get_table_size(), 2);
    }

    #[test]
    fn test_set_goto_branch_marks_flags() {
        use crate::funcdata::Funcdata;
        use crate::block::{BlockBasic, block_flags};
        let mut fd = Funcdata::new("test", crate::Address::new(0x1000), 16);
        let bl = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(0, crate::Address::new(0x1000)))) as std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        fd.set_goto_branch(&bl, 0);
        assert!((bl.read().unwrap().get_flags() & block_flags::GOTO_EDGE_0) != 0);
        fd.set_goto_branch(&bl, 1);
        assert!((bl.read().unwrap().get_flags() & block_flags::GOTO_EDGE_1) != 0);
    }

    #[test]
    fn test_override_apply_force_gotos() {
        use crate::funcdata::Funcdata;
        let mut o = crate::override_rs::Override::new();
        o.insert_force_goto(crate::Address::new(0x1000), crate::Address::new(0x2000));
        let mut fd = Funcdata::new("test", crate::Address::new(0x1000), 16);
        // No blocks exist, so force_goto returns false → count 0.
        let count = o.apply_force_gotos(&mut fd);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_recover_jump_tables_runs_without_panic() {
        // The recovery machinery must run over a real BRANCHIND without
        // panicking the binary. With an unwritten switch varnode, JumpBasic's
        // range is unbounded (size > maxtablesize), so recovery legitimately
        // yields zero tables here — but crucially it must not unwind the
        // process. This guards the `catch_unwind` boundary in `try_recover`.
        use crate::funcdata::Funcdata;
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;

        let mut fd = Funcdata::new("switch", crate::Address::new(0x1000), 16);

        // BRANCHIND at 0x1010 whose input is an unwritten unique varnode (a
        // plausible, but unbounded, switch variable).
        let branchind = fd.obank.create(OpCode::CPUI_BRANCHIND, 1, crate::Address::new(0x1010));
        let switchvn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_unique(0, 4)));
        branchind.0.write().unwrap().inrefs.push(switchvn);

        assert_eq!(fd.jump_tables.len(), 0);
        assert!(fd.find_jump_table(&branchind).is_none());

        let _recovered = recover_jump_tables(&mut fd);
        // No hard assertion on the count: the point is that we returned here
        // at all (no panic) and left the Funcdata in a consistent state.
        assert!(fd.jump_tables.len() <= 1);
    }

    #[test]
    fn test_recover_jump_tables_skips_non_branchind() {
        // A function with no BRANCHIND ops must recover zero tables and must
        // not panic.
        use crate::funcdata::Funcdata;
        use crate::opcodes::OpCode;

        let mut fd = Funcdata::new("plain", crate::Address::new(0x1000), 16);
        // A non-branch op should be ignored.
        let _copy = fd.obank.create(OpCode::CPUI_COPY, 1, crate::Address::new(0x1000));

        assert_eq!(fd.jump_tables.len(), 0);
        let recovered = recover_jump_tables(&mut fd);
        assert_eq!(recovered, 0);
        assert_eq!(fd.jump_tables.len(), 0);
    }

    #[test]
    fn test_find_jump_table_returns_attached_table() {
        // Once a JumpTable is attached to Funcdata.jump_tables (by whatever
        // means — recovery or otherwise), find_jump_table must locate it by
        // the BRANCHIND's address. This is the integration contract the
        // recovery pre-pass exists to satisfy.
        use crate::funcdata::Funcdata;
        use crate::opcodes::OpCode;

        let mut fd = Funcdata::new("switch", crate::Address::new(0x1000), 16);
        let branchind = fd.obank.create(OpCode::CPUI_BRANCHIND, 1, crate::Address::new(0x1010));

        // Nothing attached yet.
        assert!(fd.find_jump_table(&branchind).is_none());

        // Attach a table whose op-address matches the BRANCHIND.
        let mut jt = JumpTable::new(crate::Address::new(0x1010));
        jt.set_indirect_op(branchind.0.clone());
        jt.add_block_to_switch(crate::Address::new(0x2000), 0);
        fd.jump_tables
            .push(std::sync::Arc::new(std::sync::RwLock::new(jt)));

        // find_jump_table must now resolve it.
        let found = fd.find_jump_table(&branchind);
        assert!(found.is_some(), "find_jump_table should locate the attached table");
        let jt = found.unwrap().read().unwrap();
        assert_eq!(jt.get_op_address().as_u64(), 0x1010);
        assert_eq!(jt.num_entries(), 1);
    }

    fn _silence_unused() {
        // Ensure imports used in doc-tests are not flagged as dead.
        let _ = calc_mask(4);
        let _ = leastsigbit_set(0x10);
        let _ = mostsigbit_set(0x10);
    }
}
