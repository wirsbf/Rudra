//! Oracle-faithful raw debug formatting for the stage drill emitter
//! (stage-bisect v2). This module exists ONLY to render Rugra IR in the
//! exact text spelling of Ghidra's console debug primitives; it never
//! feeds anything back into the pipeline.
//!
//! Every formatter cites the locked oracle (Ghidra 12.0.4, e40ed130) line
//! it mirrors:
//!   - SeqNum `operator<<` (address.cc:32-38): `pc.printRaw()` then `':'`
//!     then `uniq`. `AddrSpace::printRaw` (space.cc:206-221) emits
//!     `"0x" << setfill('0') << setw(2*sz) << hex`, which leaves the stream
//!     in hex state, so the following `uniq` prints HEX too (oracle lines
//!     like `0x00004ff4:2cd`). Address width sz shrinks 8->6->4 bytes when
//!     the high bits are zero.
//!   - `ConstantSpace::printRaw` (space.cc:372-376): `0x` + unpadded hex.
//!   - `Varnode::printRawNoMarkup`/`printRaw` (varnode.cc:711-756):
//!     register name (with `+off` for sub-register offsets) else
//!     `<shortcut><offset>`; `:size` when the size differs from the
//!     expected (register size or translate default); `(i)` input marker;
//!     `(<def-seqnum>)` for written varnodes; `(free)` when neither
//!     inserted nor constant.
//!   - `PcodeOp::printDebug` (op.cc:376-385): `<seqnum>: ` then `**` for
//!     dead/unattached ops, else `printRaw`.
//!   - Null Varnode slots render `<null>` via the static wrapper
//!     `Varnode::printRaw(ostream&,const Varnode*)` (varnode.cc:1207-1214).
//!   - `TypeOp*::printRaw` structural forms (typeop.cc:335-343 binary,
//!     357-363 unary, 377-389 func, 425-431 copy, 502-509 load, 572-580
//!     store, 590-601 branch, 621-636 cbranch, 882-900 return, 1967-1983
//!     multiequal, 2022-2033 indirect, 2283+ ptradd, 2380+ ptrsub,
//!     668-684 call, 791+ callind) with operator names from the Ghidra
//!     constructors and `getOperatorName` overrides (typeop.cc; the same
//!     names are registered in Rugra's src/typeop.rs).
//!
//! RUGRA-GLUE: no single Ghidra counterpart — this is a formatting-only
//! projection of the primitives above, owned by the drill emitter.

use crate::arch::Architecture;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::{varnode_flags, Varnode};
use std::sync::RwLock;

/// Default operand size for the x86-64 translate (`getDefaultSize`),
/// used as the "expected" size for non-register varnodes.
const DEFAULT_SIZE: usize = 8;

// Ghidra: translate.cc:517 AddrSpaceManager::assignShortcut
// Shortcut characters per the oracle's assignShortcut switch, keyed on
// Rugra's canonical space names (space.rs name(): "const", "register",
// "unique", "stack", "join", "iop", "ram"): IPTR_CONSTANT '#' (cc:524-526),
// IPTR_PROCESSOR named "register" '%' else name[0] (cc:527-533, so
// "ram" -> 'r'), IPTR_SPACEBASE 's' (cc:535-537), IPTR_INTERNAL 'u'
// (cc:538-540), IPTR_JOIN 'j' (cc:543-545), IPTR_IOP 'i' (cc:546-548),
// default 'x' (cc:550-552). Uppercase name[0] lowercases (cc:558-559);
// "ram"/"register" are already lowercase. Real-oracle cross-check: the x86-64
// symbol dumps (regsym-evidence raw_pcode.err) show code symbols in RAM as
// `r0x00000000:1` and register-space storages as `%0x00000000:4`.
fn space_shortcut(space: AddressSpace) -> char {
    match space {
        AddressSpace::Const => '#',
        AddressSpace::Unique => 'u',
        AddressSpace::Stack => 's',
        AddressSpace::Register => '%',
        AddressSpace::Ram => 'r',
        AddressSpace::Iop => 'i',
        AddressSpace::Join => 'j',
        _ => 'x',
    }
}

/// Address-space print width in BYTES (space.cc:208-215: sz>4 shrinks to
/// 4/6 when the high bits are zero; x86-64 ram/stack are 8-byte spaces,
/// unique is 4).
// Ghidra: space.cc:206 AddrSpace::printRaw (address-size shrink logic)
fn raw_width(addr_size: usize, offset: u64) -> usize {
    let mut sz = addr_size;
    if sz > 4 {
        if (offset >> 32) == 0 {
            sz = 4;
        } else if (offset >> 48) == 0 {
            sz = 6;
        }
    }
    sz
}

// Ghidra: space.cc:206 AddrSpace::printRaw
fn print_raw_offset(addr_size: usize, offset: u64) -> String {
    let width = 2 * raw_width(addr_size, offset);
    format!("0x{:0width$x}", offset, width = width)
}

/// space address sizes: ram/stack 8, register 8, unique 4, const 0.
// RUGRA-GLUE: per-space getAddrSize() table; Rugra AddressSpace carries no address-size field.
fn space_addr_size(space: AddressSpace) -> usize {
    match space {
        AddressSpace::Ram | AddressSpace::Stack | AddressSpace::Register => 8,
        AddressSpace::Unique => 4,
        _ => 8,
    }
}

/// SeqNum raw text: `<pc.printRaw>:<uniq-hex>` (address.cc:32-38 + the hex
/// state left by AddrSpace::printRaw, space.cc:206-221).
// Ghidra: address.cc:32 operator<<(ostream&, const SeqNum&)
pub fn seqnum_raw(pc: u64, uniq: u32) -> String {
    let mut s = print_raw_offset(8, pc);
    s.push(':');
    s.push_str(&format!("{uniq:x}"));
    s
}

/// One drill formatter bound to an Architecture (for register names).
pub struct DrillFmt {
    pub arch: std::sync::Arc<Architecture>,
}

impl DrillFmt {
    // RUGRA-GLUE: register symbol lookup combining
    // SleighBase::getRegisterName (sleighbase.cc:147-167) and
    // Translate::getRegister — returns (name, point.offset, point.size) so
    // the caller can render the `+off` sub-register suffix of
    // printRawNoMarkup (varnode.cc:719-727). Returns None when no
    /// register covers the varnode.
    fn register_symbol(
        &self,
        space: AddressSpace,
        off: u64,
        size: usize,
    ) -> Option<(String, u64, usize)> {
        let probe = (space.space_id() as i32, off, -(size as i32));
        let mut walker = self.arch.register_xref.range(..=probe);
        let (prev_key, prev_name) = match walker.next_back() {
            Some(entry) => (*entry.0, entry.1.clone()),
            None => return None,
        };
        let (prev_space, prev_off, neg_prev_size) = prev_key;
        let prev_size = (-neg_prev_size) as usize;
        if AddressSpace::from_id(prev_space as u8) != space {
            return None;
        }
        if prev_off.wrapping_add(prev_size as u64) >= off.wrapping_add(size as u64) {
            return Some((prev_name, prev_off, prev_size));
        }
        // cc:160-166 back-walk: one predecessor per step, same space and
        // same base offset, until a covering entry or failure.
        let mut current = prev_key;
        loop {
            let mut walker = self.arch.register_xref.range(..current);
            match walker.next_back() {
                None => return None,
                Some((next_key, next_name)) => {
                    let (next_space, next_off, neg_next_size) = *next_key;
                    let next_size = (-neg_next_size) as usize;
                    if AddressSpace::from_id(next_space as u8) != space || next_off != prev_off {
                        return None;
                    }
                    if next_off.wrapping_add(next_size as u64) >= off.wrapping_add(size as u64) {
                        return Some((next_name.clone(), next_off, next_size));
                    }
                    current = *next_key;
                }
            }
        }
    }

    /// Varnode raw text (varnode.cc:741-756). `def_seq` is a callback the
    /// caller supplies to render a defining op's SeqNum without the
    /// formatter borrowing the op graph.
    // Ghidra: varnode.cc:741 Varnode::printRaw
    pub fn varnode_raw<F: Fn(&Varnode) -> Option<String>>(&self, vn: &Varnode, def_seq: F) -> String {
        // printRawNoMarkup (varnode.cc:711-734)
        let (base, expect) = if let Some((name, point_off, point_size)) =
            self.register_symbol(vn.address_space, vn.loc.as_u64(), vn.size)
        {
            let mut s = name;
            let off = vn.loc.as_u64().wrapping_sub(point_off);
            if off != 0 {
                s.push_str(&format!("+{off}"));
            }
            (s, point_size)
        } else {
            let mut s = String::new();
            s.push(space_shortcut(vn.address_space));
            match vn.address_space {
                // ConstantSpace::printRaw (space.cc:372-376): unpadded hex
                AddressSpace::Const => s.push_str(&format!("{:#x}", vn.loc.as_u64())),
                // IopSpace::printRaw (op.cc:41-47): the referenced op's
                // SeqNum (non-branch form); unresolved/dead references fall
                // back to the raw offset.
                AddressSpace::Iop => {
                    match crate::drillobserve::resolve_iop_seq(vn.loc.as_u64()) {
                        Some(seq) => s.push_str(&seq),
                        None => s.push_str(&format!("{:#x}", vn.loc.as_u64())),
                    }
                }
                _ => s.push_str(&print_raw_offset(
                    space_addr_size(vn.address_space),
                    vn.loc.as_u64(),
                )),
            }
            (s, DEFAULT_SIZE)
        };
        let mut s = base;
        if expect != vn.size {
            s.push_str(&format!(":{}", vn.size));
        }
        if (vn.flags & varnode_flags::INPUT) != 0 {
            s.push_str("(i)");
        }
        if vn.is_written() {
            if let Some(seq) = def_seq(vn) {
                s.push('(');
                s.push_str(&seq);
                s.push(')');
            }
        }
        if (vn.flags & (varnode_flags::INSERT | varnode_flags::CONSTANT)) == 0 {
            s.push_str("(free)");
        }
        s
    }

    /// PcodeOp::printDebug (op.cc:376-385): `<seqnum>: ` + `**` for
    /// dead/unattached ops, else printRaw.
    // Ghidra: op.cc:376 PcodeOp::printDebug
    pub fn op_print_debug(&self, op: &PcodeOp) -> String {
        let mut s = seqnum_raw(op.get_addr().as_u64(), op.get_time());
        s.push_str(": ");
        if op.is_dead() || op.parent.is_none() {
            s.push_str("**");
        } else {
            s.push_str(&self.op_raw(op));
        }
        s
    }

    // RUGRA-GLUE: Arc<RwLock<Varnode>> adapter over Varnode::printRaw (varnode.cc:741); Ghidra passes raw pointers.
    fn vn_of(&self, vn: &std::sync::Arc<RwLock<Varnode>>) -> String {
        let guard = vn.read().unwrap();
        let def = guard.get_def();
        self.varnode_raw(&guard, |gvn| {
            let _ = gvn;
            def.as_ref().map(|def_op| {
                let d = def_op.read().unwrap();
                seqnum_raw(d.get_addr().as_u64(), d.get_time())
            })
        })
    }

    /// The structural `printRaw` forms (typeop.cc; see module docs). Every
    /// Varnode slot render goes through the null-safe static wrapper
    /// `Varnode::printRaw(ostream&, const Varnode*)` (varnode.cc:1207-1214):
    /// a null slot prints `<null>`. Ghidra ops reserve null input slots at
    /// creation (`PcodeOp::PcodeOp(int4,s)` op.cc:71-84 sizes `inrefs(s)`
    /// with nulls), while Rugra's `inrefs` only holds SET inputs, so absent
    /// slots render as `<null>` here.
    // Ghidra: op.cc:385 PcodeOp::printRaw (TypeOp dispatch)
    pub fn op_raw(&self, op: &PcodeOp) -> String {
        let out = op.get_out().map(|v| self.vn_of(v));
        let inputs: Vec<String> = op.inrefs.iter().map(|v| self.vn_of(v)).collect();
        // varnode.cc:1207-1214: null slot -> "<null>"
        let null_raw = || "<null>".to_string();
        let slot = |v: Option<&String>| -> String {
            v.cloned().unwrap_or_else(null_raw)
        };
        let name_of = |opc: OpCode| -> &'static str { operator_name(opc) };
        match op.opcode {
            OpCode::CPUI_COPY => {
                // typeop.cc:425-431: out = in0 (both null-safe)
                format!("{} = {}", out.unwrap_or_else(null_raw), slot(inputs.first()))
            }
            OpCode::CPUI_LOAD => format!(
                "{} = *({},{})",
                out.unwrap_or_else(null_raw),
                load_store_space_name(op, &inputs),
                slot(inputs.get(1))
            ),
            OpCode::CPUI_STORE => format!(
                "*({},{}) = {}",
                load_store_space_name(op, &inputs),
                slot(inputs.first()),
                slot(inputs.get(2))
            ),
            OpCode::CPUI_RETURN => {
                // typeop.cc:882-900: `return` + `(in0)` when numInput()>=1;
                // when >1: ' ' + in1, then ',' + each further input.
                let mut s = String::from("return");
                if !inputs.is_empty() {
                    s.push('(');
                    s.push_str(&inputs[0]);
                    s.push(')');
                }
                if inputs.len() > 1 {
                    s.push(' ');
                    s.push_str(&inputs[1]);
                    for input in inputs.iter().skip(2) {
                        s.push(',');
                        s.push_str(input);
                    }
                }
                s
            }
            OpCode::CPUI_CALL => {
                let mut s = String::new();
                if let Some(out) = &out {
                    s.push_str(out);
                    s.push_str(" = ");
                }
                s.push_str("call ");
                s.push_str(&call_target_raw(self, op, &inputs));
                if inputs.len() > 1 {
                    s.push('(');
                    s.push_str(&inputs[1..].join(","));
                    s.push(')');
                }
                s
            }
            OpCode::CPUI_CALLIND => {
                // typeop.cc:791-807: out prefix is conditional; `s << name`
                // is NOT followed by a space (unlike CALL's `name << ' '`).
                let mut s = String::new();
                if let Some(out) = &out {
                    s.push_str(out);
                    s.push_str(" = ");
                }
                s.push_str("callind");
                s.push_str(&slot(inputs.first()));
                if inputs.len() > 1 {
                    s.push('(');
                    s.push_str(&inputs[1..].join(","));
                    s.push(')');
                }
                s
            }
            OpCode::CPUI_BRANCH => format!(
                "goto {}",
                branch_dest_raw(op, &inputs)
            ),
            OpCode::CPUI_CBRANCH => {
                let mut s = format!("goto {}", branch_dest_raw(op, &inputs));
                s.push_str(" if (");
                s.push_str(&slot(inputs.get(1)));
                s.push_str(if op.is_boolean_flip() { " == 0)" } else { " != 0)" });
                s
            }
            OpCode::CPUI_MULTIEQUAL => {
                let mut s = format!(
                    "{} = {}",
                    out.unwrap_or_else(null_raw),
                    slot(inputs.first())
                );
                for input in inputs.iter().skip(1) {
                    s.push_str(" ? ");
                    s.push_str(input);
                }
                s
            }
            OpCode::CPUI_INDIRECT => {
                // typeop.cc:2022-2033: `[create]` replaces the input-0 leg
                // when the op is an indirect creation.
                if op.is_indirect_creation() {
                    format!(
                        "{} = [create] {}",
                        out.unwrap_or_else(null_raw),
                        slot(inputs.get(1))
                    )
                } else {
                    format!(
                        "{} = {} [] {}",
                        out.unwrap_or_else(null_raw),
                        slot(inputs.first()),
                        slot(inputs.get(1))
                    )
                }
            }
            OpCode::CPUI_PTRADD => format!(
                "{} = {} + {}(*{})",
                out.unwrap_or_else(null_raw),
                slot(inputs.first()),
                slot(inputs.get(1)),
                slot(inputs.get(2))
            ),
            OpCode::CPUI_PTRSUB => format!(
                "{} = {} -> {}",
                out.unwrap_or_else(null_raw),
                slot(inputs.first()),
                slot(inputs.get(1))
            ),
            OpCode::CPUI_SUBPIECE => {
                // typeop.cc:2127-2135: getOperatorName is dynamic —
                // "SUB" + <in0 size><out size> (e.g. SUB84); func form
                // (typeop.cc:377-388).
                let in0_size = op
                    .get_in(0)
                    .map(|v| v.read().unwrap().size)
                    .unwrap_or(0);
                let out_size = op.get_out().map(|v| v.read().unwrap().size).unwrap_or(0);
                format!(
                    "{} = SUB{in0_size}{out_size}({})",
                    out.unwrap_or_else(null_raw),
                    inputs.join(",")
                )
            }
            opc if is_binary(opc) => format!(
                "{} = {} {} {}",
                out.unwrap_or_else(null_raw),
                slot(inputs.first()),
                name_of(opc),
                slot(inputs.get(1))
            ),
            opc if is_unary(opc) => format!(
                "{} = {} {}",
                out.unwrap_or_else(null_raw),
                name_of(opc),
                slot(inputs.first())
            ),
            opc => format!(
                "{} = {}({})",
                out.unwrap_or_else(null_raw),
                name_of(opc),
                inputs.join(",")
            ),
        }
    }
}

// RUGRA-GLUE: LOAD/STORE print the target space NAME from the constant in
// input 0 (typeop.cc:462-475 `getSpaceFromConst`). Rugra encodes the same
// constant space id; map it back to the name. If input 0 is not (yet) a
// constant the oracle would dereference garbage, so the drill prints the
// varnode raw text as a visible placeholder.
fn load_store_space_name(op: &PcodeOp, inputs: &[String]) -> String {
    if let Some(in0) = op.get_in(0) {
        let vn = in0.read().unwrap();
        if vn.is_constant() {
            return AddressSpace::from_id(vn.loc.as_u64() as u8)
                .name()
                .to_string();
        }
        let _ = inputs;
    }
    "?space".to_string()
}

// RUGRA-GLUE: CALL input 0 is the call-target encoding. Ghidra renders it
// through FspecSpace::printRaw as the callee's NAME (ffunc_<addr> for
// symbol-less functions); Rugra has no fspec space, so the drill uses the
// ffunc_<addr> form derived from the constant. Named callees differ from
// the oracle here (tracked as SB-DRILL-FSPEC-NAME).
fn call_target_raw(fmt: &DrillFmt, op: &PcodeOp, inputs: &[String]) -> String {
    if let Some(in0) = op.get_in(0) {
        let vn = in0.read().unwrap();
        if vn.is_constant() {
            let addr = vn.loc.as_u64();
            return format!("ffunc_{addr:#010x}(free)");
        }
        let _ = (fmt, inputs);
    }
    inputs.first().cloned().unwrap_or_default()
}

// RUGRA-GLUE: branch destination (typeop.cc:583-629): with an unambiguous
// out edge the destination is the out block's printShortHeader
// (`Block_<index>:<start>`), else the raw input varnode. Rugra block
// indices live on the BlockBasic; fall back to the varnode form when the
// parent graph is unavailable.
fn branch_dest_raw(op: &PcodeOp, inputs: &[String]) -> String {
    if let Some(parent) = op.parent.as_ref().and_then(std::sync::Weak::upgrade) {
        let block = parent.read().unwrap();
        let bank = block.bank();
        let out_count = block.size_out();
        if out_count == 1 {
            if let Some(edge_point) = block.get_out(0).map(|edge| bank.expect_arc(edge.point)) {
                let dest_block = edge_point.read().unwrap();
                let start = dest_block.get_start_addr();
                return format!(
                    "Block_{}:{}",
                    dest_block.get_index(),
                    print_raw_offset(8, start.as_u64())
                );
            }
        }
    }
    inputs.first().cloned().unwrap_or_default()
}

// RUGRA-GLUE: opcode-class table for the TypeOpBinary::printRaw structure (typeop.cc:335); Rugra has no flags query on the table.
fn is_binary(opc: OpCode) -> bool {
    matches!(
        opc,
        OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_DIV
            | OpCode::CPUI_INT_SDIV
            | OpCode::CPUI_INT_REM
            | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_LEFT
            | OpCode::CPUI_INT_RIGHT
            | OpCode::CPUI_INT_SRIGHT
            | OpCode::CPUI_INT_EQUAL
            | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_LESS
            | OpCode::CPUI_INT_SLESS
            | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_CARRY
            | OpCode::CPUI_INT_SCARRY
            | OpCode::CPUI_INT_SBORROW
            | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_BOOL_XOR
            | OpCode::CPUI_FLOAT_ADD
            | OpCode::CPUI_FLOAT_SUB
            | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_FLOAT_EQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS
            | OpCode::CPUI_FLOAT_LESSEQUAL
    )
}

// RUGRA-GLUE: opcode-class table for the TypeOpUnary::printRaw structure (typeop.cc:357).
fn is_unary(opc: OpCode) -> bool {
    matches!(
        opc,
        OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_INT_ZEXT
            | OpCode::CPUI_INT_SEXT
            | OpCode::CPUI_POPCOUNT
            | OpCode::CPUI_LZCOUNT
            | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT
            | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR
            | OpCode::CPUI_FLOAT_ROUND
            | OpCode::CPUI_FLOAT_TRUNC
            | OpCode::CPUI_FLOAT_FLOAT2FLOAT
            | OpCode::CPUI_FLOAT_INT2FLOAT
            | OpCode::CPUI_FLOAT_NAN
    )
}

/// printRaw operator names: Ghidra constructor names plus the
/// `getOperatorName` overrides (typeop.cc; identical strings are
/// registered in Rugra's src/typeop.rs binary_op!/unary_op! tables).
// RUGRA-GLUE: static getOperatorName table (typeop.cc constructors + overrides; same strings as src/typeop.rs registrations).
fn operator_name(opc: OpCode) -> &'static str {
    match opc {
        OpCode::CPUI_INT_ADD => "+",
        OpCode::CPUI_INT_SUB => "-",
        OpCode::CPUI_INT_MULT => "*",
        OpCode::CPUI_INT_DIV => "/",
        OpCode::CPUI_INT_SDIV => "s/",
        OpCode::CPUI_INT_REM => "%",
        OpCode::CPUI_INT_SREM => "s%",
        OpCode::CPUI_INT_AND => "&",
        OpCode::CPUI_INT_OR => "|",
        OpCode::CPUI_INT_XOR => "^",
        OpCode::CPUI_INT_LEFT => "<<",
        OpCode::CPUI_INT_RIGHT => ">>",
        OpCode::CPUI_INT_SRIGHT => ">>",
        OpCode::CPUI_INT_EQUAL => "==",
        OpCode::CPUI_INT_NOTEQUAL => "!=",
        OpCode::CPUI_INT_LESS => "<",
        OpCode::CPUI_INT_SLESS => "<",
        OpCode::CPUI_INT_LESSEQUAL => "<=",
        OpCode::CPUI_INT_SLESSEQUAL => "<=",
        OpCode::CPUI_INT_CARRY => "carry",
        OpCode::CPUI_INT_SCARRY => "scarry",
        OpCode::CPUI_INT_SBORROW => "sborrow",
        OpCode::CPUI_INT_2COMP => "-",
        OpCode::CPUI_INT_NEGATE => "~",
        OpCode::CPUI_BOOL_AND => "&&",
        OpCode::CPUI_BOOL_OR => "||",
        OpCode::CPUI_BOOL_XOR => "^^",
        OpCode::CPUI_BOOL_NEGATE => "!",
        OpCode::CPUI_INT_ZEXT => "zext",
        OpCode::CPUI_INT_SEXT => "sext",
        OpCode::CPUI_POPCOUNT => "popcount",
        OpCode::CPUI_LZCOUNT => "lzcount",
        OpCode::CPUI_FLOAT_ADD => "f+",
        OpCode::CPUI_FLOAT_SUB => "f-",
        OpCode::CPUI_FLOAT_MULT => "f*",
        OpCode::CPUI_FLOAT_DIV => "f/",
        OpCode::CPUI_FLOAT_EQUAL => "f==",
        OpCode::CPUI_FLOAT_NOTEQUAL => "f!=",
        OpCode::CPUI_FLOAT_LESS => "f<",
        OpCode::CPUI_FLOAT_LESSEQUAL => "f<=",
        OpCode::CPUI_FLOAT_NEG => "f-",
        OpCode::CPUI_FLOAT_ABS => "fabs",
        OpCode::CPUI_FLOAT_SQRT => "fsqrt",
        OpCode::CPUI_FLOAT_CEIL => "fceil",
        OpCode::CPUI_FLOAT_FLOOR => "ffloor",
        OpCode::CPUI_FLOAT_ROUND => "fround",
        OpCode::CPUI_FLOAT_TRUNC => "ftrunc",
        OpCode::CPUI_FLOAT_FLOAT2FLOAT => "f2f",
        OpCode::CPUI_FLOAT_INT2FLOAT => "i2f",
        OpCode::CPUI_FLOAT_NAN => "isnan",
        OpCode::CPUI_PIECE => "concat",
        OpCode::CPUI_SUBPIECE => "subpiece",
        _ => opc.name(),
    }
}
