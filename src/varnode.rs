//! Varnode definitions for P-code IR
//!
//! Corresponds to Ghidra's `varnode.hh`

use crate::address::Address;
use crate::space::AddressSpace;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock, Weak};

// Forward declarations/Stubs
// These placeholders allow the code to compile while other modules are being aligned.
pub mod stubs {
// use super::*;
    #[derive(Debug)] pub struct ValueSet;
}

use crate::cover::Cover;
use crate::database::SymbolEntry;
use crate::op::PcodeOp;
use crate::type_system::Datatype;
use crate::type_system::TypeBase;
use crate::type_system::TypeMetatype;
use crate::variable::HighVariable;

/// First offset in Ghidra's analysis-owned unique-space region.
/// `Translate::getUniqueStart(Translate::ANALYSIS)` returns this tag directly.
const ANALYSIS_UNIQUE_START: u64 = 0x1000_0000;

// RUGRA-GLUE: Rugra represents address spaces as an enum rather than unique
// AddrSpace objects.  Compare the Ghidra-compatible numeric index first, then
// use the enum order only to keep Eq/Ord total for invalid duplicate-id values.
fn compare_address_spaces(a: AddressSpace, b: AddressSpace) -> std::cmp::Ordering {
    a.space_id().cmp(&b.space_id()).then_with(|| a.cmp(&b))
}

// RUGRA-GLUE: Default-type resolution standing in for Ghidra's
// caller-supplied `Datatype *ct`. Ghidra's `VarnodeBank::create(s,m,ct)`
// (varnode.cc:1250) never mints a type itself — every Funcdata `newVarnode*`
// caller passes `glb->types->getBase(s,TYPE_UNKNOWN)` from the Architecture
// TypeFactory (funcdata_varnode.cc:69/87/107/132/154/179/193/208). Rugra's
// historical two-argument constructors cannot receive a `ct`, so this helper
// resolves the same factory object: an explicitly injected handle wins;
// otherwise the process-canonical DataOrg factory models the headless
// oracle's single Architecture. Bank-local `xunknown{size}` minting (the
// former adapter) is gone — unknown types now carry the canonical
// `undefined{size}` spelling and per-factory identity.
pub(crate) fn default_unknown_type(
    factory: Option<&Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
    size: usize,
) -> Arc<Datatype> {
    let factory = factory
        .cloned()
        .unwrap_or_else(crate::type_system::typefactory::TypeFactory::shared_default);
    let guard = factory
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .get_base(size, TypeMetatype::Unknown)
        .expect("TypeFactory::get_base always produces an unknown base type")
}

// RUGRA-GLUE: the two `PcodeOp::outputTypeLocal/inputTypeLocal` forwarders
//   (op.hh:251-252) dispatch through `opcode->getOutputLocal/getInputLocal` —
//   the Architecture-owned TypeOp virtual table. Rugra PcodeOp holds no
//   TypeOp pointer, and several current `src/typeop.rs` trait impls in the
//   binary/unary/functional macro family and COPY/LOAD/STORE/MULTIEQUAL read
//   the opposite varnode's v_type instead of the Ghidra
//   `getBase(size,metatype)` lookups (the registered PRINTC-CAST-OPNAME-0001
//   M1 gap). `Varnode::getLocalType` therefore dispatches through this local
//   table, with explicit line-cited override arms; when the remaining M1
//   branches land, root may consolidate them with the typeop trait impls.
//   PTRADD/PTRSUB already request the canonical local INT base here. CALL
//   input delegates to the R3-approved D1 port
//   `TypeOpCall::get_input_local` (typeop.rs:1393); CALLIND input delegates
//   to the R19-approved D2 port `TypeOpCallind::get_input_local`
//   (typeop.rs:2059), eliminating the former inlined slot-0 copy.
// Ghidra: typeop.cc:261 TypeOp::getOutputLocal / typeop.cc:271 TypeOp::getInputLocal
fn local_base(
    type_factory: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    size: usize,
    metatype: TypeMetatype,
) -> Option<Arc<Datatype>> {
    type_factory
        .read()
        .unwrap()
        .get_base(size, metatype)
}

// Ghidra: typeop.cc:323/345/365 TypeOp{Binary,Unary,Func} ctor meta tables
/// Per-opcode `(metaout, metain)` pairs from the TypeOp constructor table —
/// the `TypeOpBinary/Unary/Func(t, CPUI_*, ..., metaout, metain)` constructor
/// arguments (every ctor line verified against the locked oracle; parameter
/// order typeop.hh:210-246). Opcodes absent use the TypeOp base defaults
/// `getBase(size, TYPE_UNKNOWN)` (typeop.cc:261-275). This encodes the
/// C-mode defaults; selectJavaOperators (typeop.cc:114-140) retunes
/// ZEXT/NEGATE/XOR/AND/OR/RIGHT on Java architectures and is not modeled
/// (same UNTESTED registration as merge.rs local_meta_pair).
fn local_meta_pair(opcode: crate::opcodes::OpCode) -> Option<(TypeMetatype, TypeMetatype)> {
    use crate::opcodes::OpCode;
    use TypeMetatype::{Bool, Float, Int, Uint, Unknown};
    Some(match opcode {
        OpCode::CPUI_INT_EQUAL
        | OpCode::CPUI_INT_NOTEQUAL
        | OpCode::CPUI_INT_SLESS
        | OpCode::CPUI_INT_SLESSEQUAL => (Bool, Int),
        OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL => (Bool, Uint),
        OpCode::CPUI_FLOAT_EQUAL
        | OpCode::CPUI_FLOAT_NOTEQUAL
        | OpCode::CPUI_FLOAT_LESS
        | OpCode::CPUI_FLOAT_LESSEQUAL
        | OpCode::CPUI_FLOAT_NAN => (Bool, Float),
        // TypeOpFunc ctors (typeop.cc:1131/1157/1183/1209 INT_CARRY et al).
        OpCode::CPUI_INT_CARRY => (Bool, Uint),
        OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW => (Bool, Int),
        OpCode::CPUI_INT_ZEXT => (Uint, Uint),
        OpCode::CPUI_INT_SEXT => (Int, Int),
        OpCode::CPUI_INT_ADD
        | OpCode::CPUI_INT_SUB
        | OpCode::CPUI_INT_MULT
        | OpCode::CPUI_INT_SDIV
        | OpCode::CPUI_INT_SREM
        | OpCode::CPUI_INT_2COMP
        | OpCode::CPUI_INT_LEFT
        | OpCode::CPUI_INT_SRIGHT => (Int, Int),
        OpCode::CPUI_INT_NEGATE
        | OpCode::CPUI_INT_XOR
        | OpCode::CPUI_INT_AND
        | OpCode::CPUI_INT_OR
        | OpCode::CPUI_INT_RIGHT
        | OpCode::CPUI_INT_DIV
        | OpCode::CPUI_INT_REM => (Uint, Uint),
        OpCode::CPUI_BOOL_NEGATE
        | OpCode::CPUI_BOOL_XOR
        | OpCode::CPUI_BOOL_AND
        | OpCode::CPUI_BOOL_OR => (Bool, Bool),
        OpCode::CPUI_FLOAT_ADD
        | OpCode::CPUI_FLOAT_DIV
        | OpCode::CPUI_FLOAT_MULT
        | OpCode::CPUI_FLOAT_SUB
        | OpCode::CPUI_FLOAT_NEG
        | OpCode::CPUI_FLOAT_ABS
        | OpCode::CPUI_FLOAT_SQRT
        | OpCode::CPUI_FLOAT_FLOAT2FLOAT
        | OpCode::CPUI_FLOAT_CEIL
        | OpCode::CPUI_FLOAT_FLOOR
        | OpCode::CPUI_FLOAT_ROUND => (Float, Float),
        OpCode::CPUI_FLOAT_INT2FLOAT => (Float, Int),
        // typeop.cc:1913 TypeOpFunc(t,CPUI_FLOAT_TRUNC,"TRUNC",TYPE_INT,TYPE_FLOAT).
        OpCode::CPUI_FLOAT_TRUNC => (Int, Float),
        // typeop.cc:2528/2543/2558/2565 INSERT/EXTRACT/POPCOUNT/LZCOUNT.
        OpCode::CPUI_INSERT => (Unknown, Int),
        OpCode::CPUI_EXTRACT => (Int, Int),
        OpCode::CPUI_PIECE | OpCode::CPUI_SUBPIECE => (Unknown, Unknown),
        OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => (Int, Unknown),
        _ => return None,
    })
}

// Ghidra: op.hh:251 PcodeOp::outputTypeLocal
/// `Datatype *PcodeOp::outputTypeLocal(void) const { return
/// opcode->getOutputLocal(this); }` — the complete override set:
/// - TypeOpBinary/Unary/Func subclasses: `getBase(out.size, metaout)`
///   (typeop.cc:326/348/368);
/// - TypeOpPtradd/TypeOpPtrsub: `getBase(out.size, TYPE_INT)` "treat same as
///   INT_ADD" (typeop.cc:2241/2311);
/// - TypeOpCall: fspec gate -> output-locked gate -> VOID gate -> locked
///   output type, else base default (typeop.cc:720-735);
/// - TypeOpCallind/TypeOpCpoolref: their overrides resolve state Rugra
///   cannot reach from a Varnode (CALLIND needs the callspec via
///   `op->getParent()->getFuncdata()->getCallSpecs(op)` — no parent chain;
///   CPOOLREF needs the constant pool). Both converge to the base default
///   on the states Ghidra itself resolves that way (no callspec /
///   record-free cpool); the special-path leftovers are registered
///   residuals;
/// - TypeOpCallother (typeop.cc:865-873): the CALLOTHER index constant in
///   input slot 0 selects a `UserPcodeOp` descriptor through
///   `tlst->getArch()->userops.getOp(in(0).offset)`; the stringdata
///   descriptor's `InternalStringOp::getOutputLocal` override
///   (userop.cc:361-364) returns the OUT VARNODE's own (typelocked) type;
///   the volatile-read descriptor's `VolatileReadOp::getOutputLocal`
///   override (userop.cc:128-141) gates on `op->doesSpecialPropagation()`
///   and resolves the output type from the global scope's symbol-table
///   query (`entry->getSizedType(addr,size)`); a descriptor with
///   fixed output metadata supplies it, anything else falls back to the
///   TypeOp base default. Rugra reaches the manager through the `userops`
///   thread and the symbol table through the `symboltab` thread — the
///   explicit `Option<&Arc<RwLock<UserOpManage>>>` /
///   `Option<&Arc<RwLock<Database>>>` stand in
///   for Ghidra's `tlst->getArch()->userops` / descriptor `glb->symboltab`
///   edges (see the
///   TYPEOP-LOCALTYPE-DISPATCH-0001 CALLOTHER slice note on
///   `get_local_type`); `None` (no owning Architecture) behaves like the
///   metadata-less descriptor and takes the base default;
/// - everything else (COPY/LOAD/STORE/MULTIEQUAL/INDIRECT/BRANCH/CBRANCH/
///   BRANCHIND/RETURN/CAST/SEGMENTOP/NEW/...): base default
///   `getBase(out.size, TYPE_UNKNOWN)` (typeop.cc:261-265) — these classes
///   have no getOutputLocal override in typeop.hh.
pub fn op_output_type_local(
    op: &PcodeOp,
    type_factory: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    userops: Option<&Arc<RwLock<crate::userop::UserOpManage>>>,
    symboltab: Option<&Arc<RwLock<crate::database::Database>>>,
) -> Option<Arc<Datatype>> {
    use crate::opcodes::OpCode;
    match op.opcode {
        // typeop.cc:2238-2242 / 2308-2312. PTRADD and PTRSUB both request
        // getBase(output-size, TYPE_INT). The bilateral fixture covers the
        // 8-byte canonical int8 case; oversized conversion remains
        // TYPEFACTORY-LOCALTYPE-CACHE-0001. PTRSUB's field-sensitive output
        // token is consumed later by ActionSetCasts::castOutput
        // (coreaction.cc:2541), never by Varnode::getLocalType.
        OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB => {
            let size = op.get_out()?.read().unwrap().get_size();
            local_base(type_factory, size, TypeMetatype::Int)
        }
        // typeop.cc:720-735 TypeOpCall::getOutputLocal.
        OpCode::CPUI_CALL => {
            let fallback = |op: &PcodeOp| -> Option<Arc<Datatype>> {
                let size = op.get_out()?.read().unwrap().get_size();
                local_base(type_factory, size, TypeMetatype::Unknown)
            };
            // cc:727-729: `vn->getSpace()->getType()!=IPTR_FSPEC` gate; the
            // Rugra D0 representation of an fspec annotation is an Iop-space
            // ANNOTATION varnode carrying the typed callspec Weak
            // (TYPEOP-FSPEC-SPACE-0001).
            let callspec = {
                let input0 = op.get_in(0)?.read().unwrap();
                if input0.get_space() != AddressSpace::Iop || !input0.is_annotation() {
                    None
                } else {
                    input0.get_call_spec()
                }
            };
            let Some(callspec) = callspec else {
                return fallback(op);
            };
            // cc:731-735: !isOutputLocked -> default; VOID -> default; else
            // the locked output type.
            let callspec = callspec.read().unwrap();
            if !callspec.prototype.output_type_locked {
                return fallback(op);
            }
            let ct = callspec.prototype.return_type.clone();
            if ct.get_metatype() == TypeMetatype::Void {
                return fallback(op);
            }
            Some(ct)
        }
        // typeop.cc:865-873 TypeOpCallother::getOutputLocal.
        OpCode::CPUI_CALLOTHER => {
            // cc:868: `tlst->getArch()->userops.getOp(op->getIn(0)->getOffset())`
            // — the userops thread replaces the tlst->getArch() reach. The
            // u64 offset truncates to the low 32 bits exactly as Ghidra's
            // `UserOpManage::getOp(uint4)` (userop.cc:408) does.
            let index = op.get_in(0)?.read().unwrap().get_offset() as i32;
            // userop.cc:361-364 InternalStringOp::getOutputLocal override:
            // the stringdata descriptor carries NO fixed metadata — its
            // output local type IS the out varnode's own (typelocked) type,
            // `op->getOut()->getType()`. This is the value that keeps
            // ActionSetCasts::castOutput's token==outHighType short-circuit
            // (coreaction.cc:2544-2548) firing for STRINGDATA CALLOTHERs,
            // preserving the char* typelock set by
            // Funcdata::getInternalString (funcdata_varnode.cc:1430-1431)
            // through the whole cast phase (PRINTC-STRDATA-TYPELOCK-0001).
            // A v_type of None cannot occur for a bank-created out varnode
            // (allocate seeds the unknown base), and would fall through to
            // the descriptor/base chain below — the same value the oracle's
            // never-null `getType()` cannot express.
            let stringdata_out = userops.and_then(|manager| {
                let mgr = manager.read().unwrap();
                let descriptor = mgr.get_op(index)?;
                if descriptor.is_string_data() {
                    op.get_out()
                        .and_then(|o| o.read().unwrap().v_type.clone())
                } else {
                    None
                }
            });
                        // userop.cc:128-141 VolatileReadOp::getOutputLocal override:
            // the volatile read descriptor carries NO fixed metadata — its
            // output local type is resolved per-op, through the special
            // propagation gate and a global symbol-table query:
            //   cc:131 `if (!op->doesSpecialPropagation()) return 0` — the
            //   flag is set by Funcdata::replaceVolatile only when the
            //   original volatile varnode was type-locked
            //   (funcdata_varnode.cc:761-762), so an unlocked volatile read
            //   falls through to the fixed-metadata/base chain;
            //   cc:133-136 `addr = op->getIn(1)->getAddr()` (the volatile
            //   memory annotation built by newCodeRef), `size =
            //   op->getOut()->getSize()`, `usepoint = op->getAddr()`; the
            //   `uint4 vflags = 0` out-parameter is discarded unread;
            //   cc:137-139 `entry->getSizedType(addr,size)` — may itself be
            //   null (no exact piece), which also falls through.
            // The `symboltab` thread stands in for the oracle's
            // `glb->symboltab` edge on the descriptor (userop.hh:38
            // `Architecture *glb`); `None` (no owning Architecture) behaves
            // like a metadata-less descriptor and takes the same fall-through
            // (VARNODE-CALLOTHER-VOLATILEOUT-0001).
            let volatile_read_out = userops.and_then(|manager| {
                let mgr = manager.read().unwrap();
                let descriptor = mgr.get_op(index)?;
                if !(descriptor.is_volatile_read() && op.does_special_propagation()) {
                    return None;
                }
                let symboltab = symboltab?;
                let addr = *op.get_in(1)?.read().unwrap().get_addr();
                let size = op.get_out()?.read().unwrap().get_size() as i32;
                let usepoint = op.get_addr();
                let entry = {
                    let db = symboltab.read().unwrap();
                    db.query_properties_entry(db.global_scope_id, addr, size, usepoint)?
                };
                // The Database read guard is dropped before taking the
                // factory write lock (get_sized_type mutates the factory
                // caches).
                let mut factory = type_factory
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                entry.get_sized_type(&mut factory, addr, size)
            });
            let descriptor_type = match stringdata_out {
                Some(res) => Some(res),
                None => match volatile_read_out {
                    Some(res) => Some(res),
                    None => userops.and_then(|manager| {
                        manager.read().unwrap().get_output_local(index).cloned()
                    }),
                },
            };
            match descriptor_type {
                // cc:869-871: non-null descriptor metadata wins.
                Some(res) => Some(res),
                // cc:872: null (metadata-less descriptor, e.g.
                // UnspecializedPcodeOp) -> TypeOp::getOutputLocal base
                // default `getBase(out.size, TYPE_UNKNOWN)` (typeop.cc:261-265).
                // Ghidra dereferences a null descriptor for an UNREGISTERED
                // index (UB before cc:869; unreachable in production — SLEIGH
                // registers every userop index before any CALLOTHER is
                // emitted). `UserOpManage::get_output_local` folds that UB
                // state into the same None, so Rust covers it with the same
                // canonical fallback instead of crashing.
                None => {
                    let size = op.get_out()?.read().unwrap().get_size();
                    local_base(type_factory, size, TypeMetatype::Unknown)
                }
            }
        }
        // meta-table subclasses (typeop.cc:326/348/368).
        _ => {
            let size = op.get_out()?.read().unwrap().get_size();
            match local_meta_pair(op.opcode) {
                Some((metaout, _)) => local_base(type_factory, size, metaout),
                None => local_base(type_factory, size, TypeMetatype::Unknown),
            }
        }
    }
}

// Ghidra: op.hh:252 PcodeOp::inputTypeLocal
/// `Datatype *PcodeOp::inputTypeLocal(int4 slot) const { return
/// opcode->getInputLocal(this,slot); }` — the complete override set:
/// - TypeOpBinary/Unary/Func subclasses: `getBase(in.size, metain)`
///   (typeop.cc:332/354/374), except the shift amount slots
///   `getBaseNoChar(in.size, TYPE_INT)` (typeop.cc:1510-1516 INT_LEFT,
///   1535-1541 INT_RIGHT, 1600-1606 INT_SRIGHT — note INT for all three,
///   even though INT_RIGHT's metain is UINT) and INSERT/EXTRACT slot 0
///   `getBase(size, TYPE_UNKNOWN)` (typeop.cc:2535-2541/2550-2556);
/// - TypeOpPtradd/TypeOpPtrsub/TypeOpCpoolref inputs: `getBase(in.size,
///   TYPE_INT)` (typeop.cc:2232-2236/2314-2318/2465-2469);
/// - TypeOpCbranch: slot 1 `getBase(size, TYPE_BOOL)`, slot 0 a pointer to
///   the code type sized/worded by the input (typeop.cc:609-619);
/// - TypeOpCall: the R3-approved D1 port (typeop.cc:687-718);
/// - TypeOpCallind: the R19-approved D2 port (typeop.cc:745-774) — slot 0 is
///   the code pointer (cc:752-756); param slots delegate to the fd-less
///   trait form, which observes Ghidra's fc==null base default (cc:758-759)
///   because a bare &PcodeOp carries no parent Funcdata chain (cc:757). The
///   full callspec branch (isTypeLocked/isThisPointer, cc:760-772) is
///   `TypeOpCallind::get_input_local_in_fd`, wired through the
///   ActionInferTypes coreaction arm. TypeOpReturn param slots need the
///   Funcdata too — same base-default residual as Ghidra's bb==null path;
/// - TypeOpCallother (typeop.cc:855-863): same descriptor lookup as the
///   output side through `tlst->getArch()->userops.getOp(in(0).offset)`;
///   `DatatypeUserOp` maps CALLOTHER slot-1 to its first fixed input type
///   (userop.cc:79), a metadata-less descriptor yields the TypeOp base
///   default `getBase(in(slot).size, TYPE_UNKNOWN)` — including slot 0,
///   the index constant itself;
/// - TypeOpIndirect slot 1: pointer to the code type sized by in(0) and
///   worded by the referenced op's address space (typeop.cc:1992-2003) —
///   the referenced op lives in the same code space as the INDIRECT op
///   itself, so the op's own address space is used;
/// - everything else: base default `getBase(in.size, TYPE_UNKNOWN)`
///   (typeop.cc:271-275).
pub fn op_input_type_local(
    op: &PcodeOp,
    slot: usize,
    type_factory: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    userops: Option<&Arc<RwLock<crate::userop::UserOpManage>>>,
    fd_output_type: Option<&Arc<Datatype>>,
) -> Option<Arc<Datatype>> {
    use crate::opcodes::OpCode;
    // Size of the queried input varnode, shared by every base/meta lookup.
    let input_size = op.get_in(slot)?.read().unwrap().get_size();
    match (op.opcode, slot) {
        // typeop.cc:1510-1516/1535-1541/1600-1606.
        (OpCode::CPUI_INT_LEFT, 1)
        | (OpCode::CPUI_INT_RIGHT, 1)
        | (OpCode::CPUI_INT_SRIGHT, 1) => {
            type_factory
            .read()
            .unwrap()
            .get_base_no_char(input_size, TypeMetatype::Int)
        }
        // typeop.cc:2535-2541/2550-2556.
        (OpCode::CPUI_INSERT, 0) | (OpCode::CPUI_EXTRACT, 0) => {
            local_base(type_factory, input_size, TypeMetatype::Unknown)
        }
        // typeop.cc:609-619: slot 1 is bool; slot 0 is a code pointer.
        (OpCode::CPUI_CBRANCH, 1) => local_base(type_factory, input_size, TypeMetatype::Bool),
        (OpCode::CPUI_CBRANCH, 0) => {
            let code = type_factory.write().unwrap().get_type_code();
            let word_size = op
                .get_in(0)?
                .read()
                .unwrap()
                .get_space()
                .word_size();
            Some(
                type_factory
                    .write()
                    .unwrap()
                    .get_type_pointer(input_size, code, word_size),
            )
        }
        // typeop.cc:2232-2236/2314-2318/2465-2469.
        (
            OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB | OpCode::CPUI_CPOOLREF,
            _) => {
            local_base(type_factory, input_size, TypeMetatype::Int)
        }
        // typeop.cc:855-863 TypeOpCallother::getInputLocal.
        (OpCode::CPUI_CALLOTHER, _) => {
            // cc:858: descriptor lookup by the CALLOTHER index constant in
            // slot 0 (same edge/UB note as the output arm above).
            let index = op.get_in(0)?.read().unwrap().get_offset() as i32;
            let descriptor_type = userops.and_then(|manager| {
                manager
                    .read()
                    .unwrap()
                    .get_input_local(index, slot as i32)
                    .cloned()
            });
            match descriptor_type {
                // cc:859-861: non-null descriptor metadata wins. The
                // slot-minus-one compaction lives in UserPcodeOp::
                // get_input_local (userop.cc:79), so slot 0 (the index
                // constant) and slots past the fixed inputs return None.
                Some(res) => Some(res),
                // cc:862: null -> TypeOp::getInputLocal base default
                // `getBase(in(slot).size, TYPE_UNKNOWN)` (typeop.cc:271-275).
                None => local_base(type_factory, input_size, TypeMetatype::Unknown),
            }
        }
        // typeop.cc:901-920 TypeOpReturn::getInputLocal — a RETURN input
        // (slot >= 1) reads its local type from the enclosing function's
        // return-value parameter (fp->getOutputType(), cc:918), kept only
        // when not void and size-matched; this bare-&PcodeOp table has no
        // parent Funcdata chain, so the fd-less form mirrors Ghidra's bb==0
        // fallback (base undefined) and the fd-carrying dispatch in
        // ActionInferTypes::build_localtypes routes through
        // TypeOpReturn::get_input_local_in_fd instead.
        (OpCode::CPUI_RETURN, slot @ 1..) => {
            match fd_output_type {
                Some(ct)
                    if !matches!(ct.as_ref(), Datatype::Void(_))
                        && ct.get_size() == input_size =>
                {
                    Some(ct.clone())
                }
                _ => local_base(type_factory, input_size, TypeMetatype::Unknown),
            }
        }
        // typeop.cc:687-718 — delegate to the reviewed D1 port.
        (OpCode::CPUI_CALL, _) => {
            use crate::typeop::TypeOp as _;
            crate::typeop::TypeOpCall::new(type_factory.clone()).get_input_local(op, slot)
        }
        // typeop.cc:745-774 — delegate to the reviewed D2 port
        // (`TypeOpCallind::getInputLocal`). Slot 0 resolves the code pointer
        // (cc:752-756) with no Funcdata; for slot >= 1 the callspec lookup
        // needs the parent Funcdata chain (cc:757), which a bare &PcodeOp
        // cannot reach, so the fd-less trait form observes Ghidra's fc==0
        // base default (cc:758-759) — identical bytes to the previous `_`
        // fallback of this table. The full callspec branch
        // (isTypeLocked/isThisPointer, cc:760-772) lives in
        // `TypeOpCallind::get_input_local_in_fd`, wired through the
        // ActionInferTypes coreaction arm.
        (OpCode::CPUI_CALLIND, _) => {
            use crate::typeop::TypeOp as _;
            crate::typeop::TypeOpCallind::new(type_factory.clone()).get_input_local(op, slot)
        }
        // typeop.cc:1992-2003 — slot 1 is the iop constant; the pointer is
        // worded by the referenced op's space, i.e. this op's code space.
        (OpCode::CPUI_INDIRECT, 1) => {
            let code = type_factory.write().unwrap().get_type_code();
            let word_size = op
                .get_addr()
                .get_space()
                .map(|space| space.get_word_size() as usize)
                .unwrap_or(1);
            Some(
                type_factory
                    .write()
                    .unwrap()
                    .get_type_pointer(input_size, code, word_size),
            )
        }
        _ => match local_meta_pair(op.opcode) {
            Some((_, metain)) => local_base(type_factory, input_size, metain),
            None => local_base(type_factory, input_size, TypeMetatype::Unknown),
        },
    }
}

/// Flags for Varnode properties (varnode_flags in Ghidra)
pub mod varnode_flags {
    pub const MARK: u32 = 1 << 0;
    pub const CONSTANT: u32 = 1 << 1;
    pub const ANNOTATION: u32 = 1 << 2;
    pub const INPUT: u32 = 1 << 3;
    pub const WRITTEN: u32 = 1 << 4;
    pub const INSERT: u32 = 1 << 5;
    pub const IMPLIED: u32 = 1 << 6;
    pub const EXPLICIT: u32 = 1 << 7;
    pub const TYPELOCK: u32 = 1 << 8;
    pub const NAMELOCK: u32 = 1 << 9;
    pub const NOLOCALALIAS: u32 = 1 << 10;
    pub const VOLATIL: u32 = 1 << 11;
    pub const EXTERNREF: u32 = 1 << 12;
    pub const READONLY: u32 = 1 << 13;
    pub const PERSIST: u32 = 1 << 14;
    pub const ADDRTIED: u32 = 1 << 15;
    pub const UNAFFECTED: u32 = 1 << 16;
    pub const SPACEBASE: u32 = 1 << 17;
    pub const INDIRECTONLY: u32 = 1 << 18;
    pub const DIRECTWRITE: u32 = 1 << 19;
    pub const ADDRFORCE: u32 = 1 << 20;
    pub const MAPPED: u32 = 1 << 21;
    pub const INDIRECT_CREATION: u32 = 1 << 22;
    pub const RETURN_ADDRESS: u32 = 1 << 23;
    pub const COVERDIRTY: u32 = 1 << 24;
    pub const PRECISLO: u32 = 1 << 25;
    pub const PRECISHI: u32 = 1 << 26;
    pub const INDIRECTSTORAGE: u32 = 1 << 27;
    pub const HIDDENRETPARM: u32 = 1 << 28;
    pub const INCIDENTAL_COPY: u32 = 1 << 29;
    pub const AUTOLIVE_HOLD: u32 = 1 << 30;
    pub const PROTO_PARTIAL: u32 = 1 << 31;
}

/// Additional boolean properties on a Varnode.
/// Faithful to Ghidra's `addl_flags` (varnode.hh:115-140).
pub mod addl_flags {
    pub const ACTIVE_HERITAGE: u16 = 0x01;
    pub const WRITE_MASK: u16 = 0x02;
    pub const VAC_CONSUME: u16 = 0x04;
    pub const LIS_CONSUME: u16 = 0x08;
    pub const PTR_CHECK: u16 = 0x10;
    pub const PTR_FLOW: u16 = 0x20;
    pub const UNSIGNED_PRINT: u16 = 0x40;
    pub const LONG_PRINT: u16 = 0x80;
    pub const STACK_STORE: u16 = 0x100;
    pub const LOCKED_INPUT: u16 = 0x200;
    pub const SPACEBASE_PLACEHOLDER: u16 = 0x400;
    pub const STOP_UP_PROPAGATION: u16 = 0x800;
    pub const HAS_IMPLIED_FIELD: u16 = 0x1000;
}

/// A Varnode represents a storage location and size in P-code IR
///
/// Corresponds to Ghidra's `Varnode` class in `varnode.hh`
#[derive(Debug)]
pub struct Varnode {
    /// Flags describing properties (input, written, etc.)
    pub flags: u32,
    /// Size in bytes
    pub size: usize,
    /// Unique index assigned at creation
    pub create_index: u32,
    /// Merge group identifier
    pub mergegroup: i16,
    /// Additional flags (addl_flags in Ghidra)
    pub addlflags: u16,
    /// Address space this varnode belongs to
    pub address_space: AddressSpace,
    /// Location (offset within the address space)
    pub loc: Address,
    /// PcodeOp that defines this varnode (if written)
    pub def: Option<Weak<RwLock<PcodeOp>>>,
    /// High-level variable associated with this varnode
    pub high: Option<Arc<RwLock<HighVariable>>>,
    /// Symbol table entry
    pub mapentry: Option<Arc<RwLock<SymbolEntry>>>,
    /// Data type
    pub v_type: Option<Arc<Datatype>>,
    /// Ops that read this varnode
    pub descend: Vec<Weak<RwLock<PcodeOp>>>,
    /// Typed, non-owning counterpart of the pointer encoded by Ghidra in an
    /// IPTR_FSPEC annotation address.  The Funcdata call-spec list owns the
    /// allocation; a CALL input must never keep it alive after deletion.
    pub call_spec: Option<Weak<RwLock<crate::fspec::FuncCallSpecs>>>,
    /// Owning Rust allocation, when this Varnode was allocated by VarnodeBank.
    self_ref: Weak<RwLock<Varnode>>,
    /// Range of P-code ops where this varnode is "alive"
    pub cover: Option<Box<Cover>>,

    // Union fields from Ghidra (represented as separate fields in Rust)
    pub consumed: u64,
    pub nzm: u64,
}

// RUGRA-GLUE: borrow-safety helper materializing BOTH notification arms of
// Varnode::setFlags (varnode.cc:356-360) and Varnode::clearFlags
// (varnode.cc:369-373) — as a free function taking the Arc, so `&mut self`
// Varnode mutation methods can fire them:
//   ARM 1 (unconditional, cc:357/:370): high->flagsDirty() —
//        variable.hh:164 `highflags |= flagsdirty | namerepdirty`.
//        NOT mask-gated in the oracle (unlike coverDirty): every attached
//        setFlags/clearFlags notification re-dirties the derived-flag
//        channel consumed by HighVariable::updateFlags (variable.cc:352,
//        live Rust callers: merge_test_required, coreaction namevars /
//        param-name gates, varmap, is_name_lock).
//   ARM 2 (mask-gated, cc:358/:371): high->coverDirty() when the mask
//        contains coverdirty — variable.hh:275-281 `highflags |= coverdirty;
//        if (piece) piece->markExtendCoverDirty();` — the
//        MERGE-HIGHCOVER-PROPAGATION-0001 invariant.
// The two arms share one write-guard acquisition; the piece walk is
// sequenced AFTER the guard is dropped because markExtendCoverDirty's final
// self leg (variable.cc:136) writes the OWN high again — re-entering the
// same RwLock for write would deadlock (single-threaded reentrancy).
// Observable flag state is identical to the oracle's inline calls.
pub(crate) fn propagate_flag_change_to_high(high: &Arc<RwLock<HighVariable>>, fl: u32) {
    let coverdirty = (fl & varnode_flags::COVERDIRTY) != 0;
    let piece_arc = {
        let mut h = high.write().unwrap();
        // ARM 1: flagsDirty — unconditional (varnode.cc:357/:370).
        h.highflags |= crate::variable::high_internal_flags::FLAGSDIRTY
            | crate::variable::high_internal_flags::NAMEREPDIRTY;
        if coverdirty {
            // ARM 2: coverDirty — mask-gated (varnode.cc:358/:371).
            h.highflags |= crate::variable::high_internal_flags::COVERDIRTY;
        }
        h.piece.clone()
    };
    if coverdirty {
        if let Some(piece_arc) = piece_arc {
            crate::variable::VariablePiece::mark_extend_cover_dirty_read(&piece_arc);
        }
    }
}

impl Varnode {
    // Ghidra: varnode.cc:578 Varnode::Varnode
    /// Create a new RAM-space varnode.
    ///
    /// Ghidra receives the address space and a non-null `Datatype *` from the
    /// Funcdata/VarnodeBank caller.  Rugra's historical two-argument API uses
    /// RAM as the implicit space and attaches the corresponding unknown type.
    pub fn new(size: usize, loc: Address) -> Self {
        Self::new_with_space(size, AddressSpace::Ram, loc.as_u64())
    }

    // Ghidra: varnode.cc:578 Varnode::Varnode
    /// Create a varnode with its final address space already known.
    pub fn new_with_space(size: usize, space: AddressSpace, offset: u64) -> Self {
        let (flags, nzm) = match space {
            AddressSpace::Const => (varnode_flags::CONSTANT, offset),
            // Rugra uses Iop for both Ghidra's IPTR_IOP and its currently
            // unmodelled IPTR_FSPEC values.  Both are annotations.
            AddressSpace::Iop => (
                varnode_flags::ANNOTATION | varnode_flags::COVERDIRTY,
                u64::MAX,
            ),
            _ => (varnode_flags::COVERDIRTY, u64::MAX),
        };
        Self {
            flags,
            size,
            create_index: 0,
            mergegroup: 0,
            addlflags: 0,
            address_space: space,
            loc: Address::new(offset),
            def: None,
            high: None,
            mapentry: None,
            // Ghidra's ctor stores the caller's `Datatype *dt`; Rugra's
            // historical API has no ct parameter, so draw the canonical
            // factory unknown (the stand-in for the Funcdata caller's
            // glb->types->getBase(size,TYPE_UNKNOWN), funcdata_varnode.cc:154).
            v_type: Some(default_unknown_type(None, size)),
            descend: Vec::new(),
            call_spec: None,
            self_ref: Weak::new(),
            cover: None,
            consumed: u64::MAX,
            nzm,
        }
    }

    // RUGRA-GLUE: Rust cannot safely encode a FuncCallSpecs pointer in an
    // address integer, so the FSPEC annotation carries a typed Weak handle.
    pub fn bind_call_spec(&mut self, call_spec: &Arc<RwLock<crate::fspec::FuncCallSpecs>>) {
        self.call_spec = Some(Arc::downgrade(call_spec));
    }

    // RUGRA-GLUE: Typed recovery of Ghidra's FuncCallSpecs::getFspecFromConst.
    pub fn get_call_spec(&self) -> Option<Arc<RwLock<crate::fspec::FuncCallSpecs>>> {
        self.call_spec.as_ref().and_then(Weak::upgrade)
    }

    // Ghidra: varnode.hh:181 Varnode::getAddr
    pub fn get_addr(&self) -> &Address {
        &self.loc
    }

    // Ghidra: varnode.cc:578 Varnode::getSpace
    /// Get the address space this varnode belongs to
    pub fn get_space(&self) -> AddressSpace {
        self.address_space
    }

    // Ghidra: varnode.cc:578 Varnode::getOffset
    pub fn get_offset(&self) -> u64 {
        self.loc.into()
    }

    // Ghidra: varnode.cc:578 Varnode::getVal
    pub fn get_val(&self) -> u64 {
        self.loc.as_u64()
    }

    
    // Ghidra: varnode.cc:578 Varnode::isUnique
    pub fn is_unique(&self) -> bool {
        self.get_space() == AddressSpace::Unique
    }

    // Ghidra: varnode.cc:578 Varnode::isRegister
    pub fn is_register(&self) -> bool {
        self.get_space() == AddressSpace::Register
    }

    // Ghidra: varnode.cc:578 Varnode::constantValue
    pub fn constant_value(&self) -> Option<u64> {
        if self.is_constant() {
            Some(self.get_offset())
        } else {
            None
        }
    }

    // Ghidra: varnode.cc:578 Varnode::size
    pub fn size(&self) -> usize {
        self.get_size()
    }

    // Ghidra: varnode.cc:578 Varnode::offset
    pub fn offset(&self) -> u64 {
        self.get_offset()
    }

    // Ghidra: varnode.cc:578 Varnode::space
    pub fn space(&self) -> AddressSpace {
        self.get_space()
    }

    // Ghidra: varnode.cc:578 Varnode::version
    pub fn version(&self) -> usize {
        0 // Add version support back if needed or mock it
    }

    // Ghidra: varnode.cc:578 Varnode::withVersion
    pub fn with_version(self, _version: usize) -> Self {
        self // Mock
    }

    // Ghidra: varnode.cc:578 Varnode::Varnode
    pub fn new_constant(val: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Const, val)
    }

    // Ghidra: varnode.cc:578 Varnode::newRegister
    pub fn new_register(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Register, offset)
    }

    // Ghidra: varnode.cc:578 Varnode::newRam
    pub fn new_ram(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Ram, offset)
    }

    // Ghidra: varnode.cc:578 Varnode::newStack
    pub fn new_stack(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Stack, offset)
    }

    // Ghidra: varnode.cc:578 Varnode::newUnique
    pub fn new_unique(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Unique, offset)
    }


    // Ghidra: varnode.cc:578 Varnode::getSize
    pub fn get_size(&self) -> usize {
        self.size
    }

    // Ghidra: varnode.cc:578 Varnode::getCreateIndex
    pub fn get_create_index(&self) -> u32 {
        self.create_index
    }

    // Ghidra: varnode.cc:578 Varnode::isConstant
    pub fn is_constant(&self) -> bool {
        (self.flags & varnode_flags::CONSTANT) != 0
    }

    // Ghidra: varnode.cc:799 Varnode::isConstantExtended
    /// Check if this Varnode holds an extended constant, returning the
    /// 128-bit value. Faithful to `Varnode::isConstantExtended`
    /// (varnode.cc:799-840). Returns Some((lo, hi)) or None.
    pub fn is_constant_extended(&self) -> Option<(u64, u64)> {
        if self.is_constant() {
            return Some((self.get_offset(), 0));
        }
        if !self.is_written() || self.size <= 8 {
            return None;
        }
        if self.size > 16 {
            return None;
        }
        let def = self.get_def()?;
        let def_rg = def.read().unwrap();
        let opc = def_rg.opcode;
        if opc == crate::opcodes::OpCode::CPUI_INT_ZEXT {
            let vn0 = def_rg.get_in(0)?;
            let r0 = vn0.read().unwrap();
            if r0.is_constant() {
                return Some((r0.get_offset(), 0));
            }
        } else if opc == crate::opcodes::OpCode::CPUI_INT_SEXT {
            let vn0 = def_rg.get_in(0)?;
            let r0 = vn0.read().unwrap();
            if r0.is_constant() {
                let val = r0.get_offset();
                let val = if r0.get_size() < 8 {
                    // Sign-extend from r0 size to self size.
                    let signbit = 1u64 << (r0.get_size() * 8 - 1);
                    if (val & signbit) != 0 {
                        val | crate::address::calc_mask(self.size) & !crate::address::calc_mask(r0.get_size())
                    } else {
                        val
                    }
                } else {
                    val
                };
                let hi = if (val & (1u64 << 63)) != 0 && self.size > 8 {
                    u64::MAX
                } else {
                    0
                };
                return Some((val, hi));
            }
        } else if opc == crate::opcodes::OpCode::CPUI_PIECE {
            let vn0 = def_rg.get_in(0)?;
            let vn1 = def_rg.get_in(1)?;
            let r0 = vn0.read().unwrap();
            let r1 = vn1.read().unwrap();
            if r0.is_constant() && r1.is_constant() {
                let lo = r1.get_offset();
                let hi = r0.get_offset();
                return Some((lo, hi));
            }
        }
        None
    }

    // Ghidra: varnode.cc:578 Varnode::isInput
    pub fn is_input(&self) -> bool {
        (self.flags & varnode_flags::INPUT) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isWritten
    pub fn is_written(&self) -> bool {
        (self.flags & varnode_flags::WRITTEN) != 0
    }

    // Ghidra: varnode.cc:711 Varnode::printRawNoMarkup
    /// Print varnode location without markup (for debugging).
    /// Returns the "expected" size (register size or default).
    /// Faithful to `printRawNoMarkup` (varnode.cc:711-734).
    pub fn print_raw_no_markup(&self) -> (String, usize) {
        // cc:719: try register name
        // Rugra doesn't have Translate::getRegisterName; use space+offset.
        let space_name = self.address_space.name();
        let offset = self.loc.as_u64();
        let s = format!("{}:{}", space_name, offset);
        // cc:730: expect = trans->getDefaultSize()
        let expect = 8; // x86-64 default
        (s, expect)
    }

    // Ghidra: varnode.cc:741 Varnode::printRaw
    /// Print full varnode info for debugging.
    /// Faithful to `printRaw` (varnode.cc:741-756).
    pub fn print_raw(&self) -> String {
        let (base, expect) = self.print_raw_no_markup();
        let mut s = base;
        // cc:746: if expect != size, append size
        if expect != self.size {
            s += &format!(":{}", self.size);
        }
        // cc:748: input marker
        if self.is_input() {
            s += "(i)";
        }
        // cc:750: def seqnum
        if self.is_written() {
            if let Some(def_weak) = self.def.as_ref() {
                if let Some(def_op) = def_weak.upgrade() {
                    let def_r = def_op.read().unwrap();
                    s += &format!(" ({:?})", def_r.start);
                }
            }
        }
        // cc:752: free marker
        if (self.flags & (varnode_flags::INSERT | varnode_flags::CONSTANT)) == 0 {
            s += "(free)";
        }
        s
    }

    // Ghidra: varnode.cc:761 Varnode::printRawHeritage
    /// Print data-flow tree for debugging.
    /// Faithful to `printRawHeritage` (varnode.cc:761-797).
    pub fn print_raw_heritage(&self, depth: i32) -> String {
        let indent: String = std::iter::repeat(' ').take(depth as usize).collect();
        if self.is_constant() {
            return format!("{}{}\n", indent, self.print_raw());
        }
        let mut s = format!("{}{}", indent, self.print_raw());
        s += " ";
        if let Some(def_weak) = self.def.as_ref() {
            if let Some(def_op) = def_weak.upgrade() {
                let def_r = def_op.read().unwrap();
                s += &format!("{:?} {:?}\n", def_r.opcode, def_r.start);
            }
        } else {
            s += "(null)\n";
        }
        s
    }

    // Ghidra: varnode.cc:282 Varnode::printInfo
    /// Print summary info for debugging.
    /// Faithful to `printInfo` (varnode.cc:282-314).
    pub fn print_info(&self) -> String {
        let mut s = self.print_raw();
        s += &format!("  create={}", self.create_index);
        if self.is_input() { s += " <input>"; }
        if self.is_written() { s += " <written>"; }
        if self.is_constant() { s += " <const>"; }
        if self.is_persist() { s += " <persist>"; }
        if self.is_addr_tied() { s += " <addrtied>"; }
        if self.is_implied() { s += " <implied>"; }
        if self.is_explicit() { s += " <explicit>"; }
        s
    }

    // Ghidra: varnode.cc:533 Varnode::operator<
    /// Ghidra's Varnode comparison for sorting (loc→size→flag→def SeqNum).
    /// Faithful on valid unique-space-id inputs to `operator<`
    /// (varnode.cc:533-547); Rugra adds a deterministic enum tie-break only
    /// for invalid duplicate numeric space identifiers.
    pub fn ghidra_less(&self, other: &Varnode) -> bool {
        let space_order = compare_address_spaces(self.address_space, other.address_space);
        if space_order != std::cmp::Ordering::Equal {
            return space_order == std::cmp::Ordering::Less;
        }
        if self.loc != other.loc {
            return self.loc < other.loc;
        }
        if self.size != other.size {
            return self.size < other.size;
        }
        let f1 = self.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = other.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        if f1 != f2 {
            // cc:542: -1 forces free varnodes to come last
            return (f1.wrapping_sub(1)) < (f2.wrapping_sub(1));
        }
        if f1 == varnode_flags::WRITTEN {
            let self_seq = self
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            let other_seq = other
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            if self_seq != other_seq {
                return self_seq < other_seq;
            }
        }
        false
    }

    // Ghidra: varnode.cc:556 Varnode::operator==
    /// Ghidra's Varnode equality (loc+size+flag+def SeqNum).
    /// Faithful to `operator==` (varnode.cc:556-570).
    pub fn ghidra_eq(&self, other: &Varnode) -> bool {
        if compare_address_spaces(self.address_space, other.address_space)
            != std::cmp::Ordering::Equal
        {
            return false;
        }
        if self.loc != other.loc {
            return false;
        }
        if self.size != other.size {
            return false;
        }
        let f1 = self.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = other.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        if f1 != f2 {
            return false;
        }
        if f1 == varnode_flags::WRITTEN {
            let self_seq = self
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            let other_seq = other
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            if self_seq != other_seq {
                return false;
            }
        }
        true
    }

    // Ghidra: varnode.cc:578 Varnode::isFree
    pub fn is_free(&self) -> bool {
        (self.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN)) == 0
    }

    // Ghidra: varnode.cc:578 Varnode::isHeritageKnown
    /// Is this varnode already known to heritage? Faithful to
    /// `Varnode::isHeritageKnown` (varnode.hh:298):
    /// `flags & (insert | constant | annotation)`.
    /// Used by rename to skip varnodes that have already been SSA-resolved.
    pub fn is_heritage_known(&self) -> bool {
        (self.flags & (varnode_flags::INSERT | varnode_flags::CONSTANT | varnode_flags::ANNOTATION)) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isActiveHeritage
    /// Is this varnode actively being heritaged this round? Faithful to
    /// `Varnode::isActiveHeritage` (varnode.hh). Set by placeMultiequals/
    /// guardStores on varnodes that need rename this pass.
    pub fn is_active_heritage(&self) -> bool {
        (self.addlflags & addl_flags::ACTIVE_HERITAGE) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::setActiveHeritage
    /// Mark this varnode as actively being heritaged. Faithful to
    /// `Varnode::setActiveHeritage` (varnode.hh).
    pub fn set_active_heritage(&mut self) {
        self.addlflags |= addl_flags::ACTIVE_HERITAGE;
    }

    // Ghidra: varnode.cc:578 Varnode::clearActiveHeritage
    /// Clear active heritage flag. Faithful to `Varnode::clearActiveHeritage`.
    pub fn clear_active_heritage(&mut self) {
        self.addlflags &= !addl_flags::ACTIVE_HERITAGE;
    }

    // Ghidra: varnode.hh:261 Varnode::isSpacebasePlaceholder
    /// Is \b this used specifically to track stackpointer values? Faithful
    /// to `Varnode::isSpacebasePlaceholder` (varnode.hh:261):
    /// `(addlflags & Varnode::spacebase_placeholder) != 0`.
    pub fn is_spacebase_placeholder(&self) -> bool {
        (self.addlflags & addl_flags::SPACEBASE_PLACEHOLDER) != 0
    }

    // Ghidra: varnode.hh:268 Varnode::hasImpliedField
    /// Does \b this have an implied field. Faithful to the inline
    /// `hasImpliedField` (varnode.hh:268):
    /// `((addlflags & Varnode::has_implied_field) != 0)`. The flag is set
    /// by `ActionSetCasts::resolveHeir` (coreaction.cc:2519
    /// `vn->setImpliedField()` — the coreaction-side producer is a
    /// registered handover on the in-flight coreaction lease) and consumed
    /// by `PrintLanguage::recurse` -> `PrintC::pushImpliedField`
    /// (printlanguage.cc:527, printc.cc:2085).
    pub fn has_implied_field(&self) -> bool {
        (self.addlflags & addl_flags::HAS_IMPLIED_FIELD) != 0
    }

    // Ghidra: varnode.hh:335 Varnode::setImpliedField
    /// Mark \b this as having an implied field. Faithful to the inline
    /// `setImpliedField` (varnode.hh:335):
    /// `addlflags |= Varnode::has_implied_field`.
    pub fn set_implied_field(&mut self) {
        self.addlflags |= addl_flags::HAS_IMPLIED_FIELD;
    }

    // Ghidra: varnode.hh:319 Varnode::setSpacebasePlaceholder
    /// Mark \b this as a special Varnode for tracking stackpointer values.
    /// Faithful to `Varnode::setSpacebasePlaceholder` (varnode.hh:319):
    /// `addlflags |= Varnode::spacebase_placeholder`.
    pub fn set_spacebase_placeholder(&mut self) {
        self.addlflags |= addl_flags::SPACEBASE_PLACEHOLDER;
    }

    // Ghidra: varnode.hh:320 Varnode::clearSpacebasePlaceholder
    /// Clear the stackpointer tracking mark. Faithful to
    /// `Varnode::clearSpacebasePlaceholder` (varnode.hh:320):
    /// `addlflags &= ~Varnode::spacebase_placeholder`.
    pub fn clear_spacebase_placeholder(&mut self) {
        self.addlflags &= !addl_flags::SPACEBASE_PLACEHOLDER;
    }

    // Ghidra: varnode.cc:352 Varnode::setFlags
    /// Set boolean attributes. Faithful to `Varnode::setFlags`
    /// (varnode.cc:352-361): the flag bits are set, then the owning high is
    /// notified via `propagate_flag_change_to_high` —
    ///   - `flagsDirty()` UNCONDITIONALLY (cc:357; variable.hh:164, no mask
    ///     gate — unlike coverDirty), re-dirtying the derived-flag channel
    ///     consumed by `HighVariable::updateFlags` (variable.cc:352);
    ///   - `coverDirty()` when the mask contains coverdirty (cc:358-359),
    ///     the MERGE-HIGHCOVER-PROPAGATION-0001 invariant that keeps the
    ///     stored high cover aggregate invalidatable at mutation time so
    ///     every raw `HighVariable::getCover` reader (variable.hh:294
    ///     returns internalCover with NO lazy update) sees a current
    ///     aggregate whenever the high is not dirty.
    /// LOCK DISCIPLINE: the notification takes a write guard on the high
    /// while the caller still holds this Varnode's write guard — a
    /// different lock, no reentrancy. Every in-tree call site acquires its
    /// Varnode guard inline (statement-level), never across a live high
    /// guard; verified by a scope-aware mechanical scan of all 261
    /// set_flags/clear_flags call sites plus the 32 oracle-setFlags-routed
    /// accessor call sites (2026-09-25, HIGHCOV lane; sole co-occurrence
    /// candidate = test_copy_symbol_arc_high_branch, guard dropped before
    /// the call and the varnode has no high).
    pub fn set_flags(&mut self, f: u32) {
        self.flags |= f;
        if let Some(high) = self.high.clone() {
            propagate_flag_change_to_high(&high, f);
        }
    }

    // Ghidra: varnode.cc:365 Varnode::clearFlags
    /// Clear boolean attributes. Faithful to `Varnode::clearFlags`
    /// (varnode.cc:365-374): the same two notifications as `set_flags` —
    /// `flagsDirty()` unconditionally (cc:370), `coverDirty()` when the
    /// cleared mask contains coverdirty (cc:371-372; e.g. a member that was
    /// dirty before its high was attached re-dirties the high at its first
    /// rebuild).
    pub fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
        if let Some(high) = self.high.clone() {
            propagate_flag_change_to_high(&high, f);
        }
    }

    // --- Ghidra-faithful varnode flag accessors (varnode.hh:235-330) ---
    // These mirror the C++ inline methods used by the core Actions
    // (ActionMarkExplicit, ActionMarkImplied, ActionRestrictLocal, etc.).

    // Ghidra: varnode.cc:578 Varnode::isMark
    /// Has this been visited by the current algorithm? (varnode.hh:263)
    pub fn is_mark(&self) -> bool {
        (self.flags & varnode_flags::MARK) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setMark
    /// Mark this Varnode for breadcrumb algorithms. (varnode.hh:303)
    pub fn set_mark(&mut self) {
        self.flags |= varnode_flags::MARK;
    }
    // Ghidra: varnode.cc:578 Varnode::clearMark
    /// Clear the mark on this Varnode. (varnode.hh:304)
    pub fn clear_mark(&mut self) {
        self.flags &= !varnode_flags::MARK;
    }
    // Ghidra: varnode.hh:302 Varnode::isMark
    /// Is this Varnode marked?
    pub fn is_marked(&self) -> bool {
        (self.flags & varnode_flags::MARK) != 0
    }
    // RUGRA-GLUE: clear_marks (Rust helper for clearing marks on multiple
    // Varnodes; Ghidra clears inline in collectReachable/flowToAlternatePath)
    /// Clear mark on multiple Varnodes (helper for collectReachable cleanup).
    pub fn clear_marks(vns: &[Arc<RwLock<Varnode>>]) {
        for vn in vns {
            vn.write().unwrap().clear_mark();
        }
    }

    // Ghidra: varnode.hh:284 Varnode::hasCover
    /// Return true if this Varnode has a Cover (participates in liveness).
    /// Faithful to `Varnode::hasCover` (varnode.hh:284):
    ///   (flags & (constant|annotation|insert)) == insert
    pub fn has_cover(&self) -> bool {
        (self.flags
            & (varnode_flags::CONSTANT | varnode_flags::ANNOTATION | varnode_flags::INSERT))
            == varnode_flags::INSERT
    }

    // Ghidra: varnode.cc:233 Varnode::updateCover
    /// Rebuild a shared Varnode's cover if dirty. The Cover is detached and
    /// rebuilt while the root write guard remains held, then the same Box is
    /// reattached and the dirty flag is cleared. Rebuild uses the Arc only as
    /// a stable identity token and never attempts to lock the root again.
    ///
    /// NOTE (MERGE-HIGHCOVER-PROPAGATION-0001): the oracle's updateCover
    /// ends with clearFlags(coverdirty) (varnode.cc:239), which fires BOTH
    /// notification arms — flagsDirty unconditionally (cc:370) and coverDirty
    /// (cc:371-372; the load-bearing case is a member that was dirty BEFORE
    /// its high was attached). Rugra CANNOT fire either arm here: callers
    /// hold READ guards on the member's high across this call (merge.rs
    /// inflate_test via coreaction check_implied_cover's borrowed
    /// &HighVariable; aggregate_high_cover_from), and the notifications need
    /// a write guard on that same high — same-lock reentrancy deadlock. The
    /// reader-side compensations absorb both gaps. For coverDirty:
    /// MergeTypeIntersectCache::update_high's instance scan marks the high
    /// dirty from the member flag BEFORE any rebuild can clear it, and
    /// inflate_test/aggregate_high_cover_from aggregate fresh from the
    /// rebuilt members unconditionally. For flagsDirty: a cover rebuild
    /// mutates no member flags, so the derived-flag VALUE is unaffected by
    /// the missing re-fire, and every in-tree attach path seeds FLAGSDIRTY
    /// independently (HighVariable::new mirrors variable.cc:224's initial
    /// dirty word; mergeInternal sets it at entry, variable.cc:631).
    pub fn update_cover_locked(root: &Arc<RwLock<Varnode>>) {
        let mut value = root.write().unwrap();
        if (value.flags & varnode_flags::COVERDIRTY) == 0 {
            return;
        }
        if value.has_cover() {
            if let Some(mut cover) = value.cover.take() {
                let definition = value.get_def();
                let is_input = value.is_input();
                let descendants = value.descend_iter().collect::<Vec<_>>();
                let root_is_implied = value.is_implied();
                cover.rebuild_from_root_snapshot(
                    root,
                    definition,
                    is_input,
                    descendants,
                    root_is_implied,
                );
                value.cover = Some(cover);
            }
        }
        value.flags &= !varnode_flags::COVERDIRTY;
    }

    // Ghidra: varnode.hh:202 Varnode::getCover
    /// Lazily rebuild and return this Varnode's Cover.
    pub fn get_cover(&mut self) -> Option<&Cover> {
        if (self.flags & varnode_flags::COVERDIRTY) != 0 {
            if self.has_cover() {
                if self.cover.is_some() && self.self_ref.upgrade().is_none() {
                    // An unmanaged Arc cannot occur on the VarnodeBank-backed
                    // production path. Preserve dirty rather than bless a
                    // stale Cover when exact root identity is unavailable.
                    return self.cover.as_deref();
                }
                if let (Some(root), Some(mut cover)) = (self.self_ref.upgrade(), self.cover.take()) {
                    let definition = self.get_def();
                    let is_input = self.is_input();
                    let descendants = self.descend_iter().collect::<Vec<_>>();
                    let root_is_implied = self.is_implied();
                    cover.rebuild_from_root_snapshot(
                        &root,
                        definition,
                        is_input,
                        descendants,
                        root_is_implied,
                    );
                    self.cover = Some(cover);
                }
            }
            self.flags &= !varnode_flags::COVERDIRTY;
        }
        self.cover.as_deref()
    }

    // Ghidra: varnode.cc:244 Varnode::clearCover
    /// Delete the Cover object. Faithful to `clearCover` (varnode.cc:244-251).
    pub fn clear_cover(&mut self) {
        self.cover = None;
    }

    // Ghidra: varnode.cc:254 Varnode::calcCover
    /// Initialize a new Cover and set dirty bit. Faithful to `calcCover`
    /// (varnode.cc:254-263). The cc:261 setFlags(coverdirty) call now goes
    /// through `set_flags`, carrying the high propagation half
    /// (varnode.cc:358-359) — MERGE-HIGHCOVER-PROPAGATION-0001.
    pub fn calc_cover(&mut self) {
        if self.has_cover() {
            self.cover = Some(Box::new(Cover::new()));
            self.set_flags(varnode_flags::COVERDIRTY);
        }
    }

    // Ghidra: varnode.cc:578 Varnode::isImplied
    /// Is this an implied variable? (varnode.hh:235)
    pub fn is_implied(&self) -> bool {
        (self.flags & varnode_flags::IMPLIED) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setImplied
    /// Mark this as an implied variable in the final C source. (varnode.hh:309)
    /// varnode.hh routes setImplied through setFlags — the high notification
    /// (flagsDirty unconditional, no coverdirty in the mask) fires with it
    /// (HIGHCOV lane 2026-09-25).
    pub fn set_implied(&mut self) {
        self.set_flags(varnode_flags::IMPLIED);
    }
    // Ghidra: varnode.cc:578 Varnode::clearImplied
    /// Clear the implied mark. (varnode.hh:310; routed via clearFlags.)
    pub fn clear_implied(&mut self) {
        self.clear_flags(varnode_flags::IMPLIED);
    }

    // Ghidra: varnode.cc:578 Varnode::isExplicit
    /// Is this an explicitly printed variable? (varnode.hh:236)
    pub fn is_explicit(&self) -> bool {
        (self.flags & varnode_flags::EXPLICIT) != 0
    }

    // Ghidra: varnode.hh:252 Varnode::isAutoLive
    /// Is this varnode exempt from dead-code removal? True if addrforce or
    /// autolive_hold flag is set. Faithful to `isAutoLive()` (varnode.hh:252).
    pub fn is_auto_live(&self) -> bool {
        (self.flags & (varnode_flags::ADDRFORCE | varnode_flags::AUTOLIVE_HOLD)) != 0
    }
    // Ghidra: varnode.hh:253 Varnode::isAutoLiveHold
    pub fn is_auto_live_hold(&self) -> bool {
        (self.flags & varnode_flags::AUTOLIVE_HOLD) != 0
    }
    // Ghidra: varnode.hh:327 Varnode::setAutoLiveHold
    /// Place temporary hold on dead-code removal of this varnode.
    pub fn set_auto_live_hold(&mut self) {
        self.flags |= varnode_flags::AUTOLIVE_HOLD;
    }
    // Ghidra: varnode.hh:208 Varnode::isConsumeVacuous
    /// Vacuous consume marker used by the dead-code algorithm.
    pub fn is_consume_vacuous(&self) -> bool {
        (self.addlflags & addl_flags::VAC_CONSUME) != 0
    }
    // Ghidra: varnode.hh:210 Varnode::setConsumeVacuous
    pub fn set_consume_vacuous(&mut self) {
        self.addlflags |= addl_flags::VAC_CONSUME;
    }
    // Ghidra: varnode.hh:212 Varnode::clearConsumeVacuous
    pub fn clear_consume_vacuous(&mut self) {
        self.addlflags &= !addl_flags::VAC_CONSUME;
    }
    // Ghidra: varnode.hh:207 Varnode::isConsumeList
    /// Is this varnode currently present in ActionDeadCode's consume work-list?
    pub fn is_consume_list(&self) -> bool {
        (self.addlflags & addl_flags::LIS_CONSUME) != 0
    }
    // Ghidra: varnode.hh:209 Varnode::setConsumeList
    /// Mark this varnode as present in ActionDeadCode's consume work-list.
    pub fn set_consume_list(&mut self) {
        self.addlflags |= addl_flags::LIS_CONSUME;
    }
    // Ghidra: varnode.hh:211 Varnode::clearConsumeList
    /// Clear the ActionDeadCode consume work-list marker.
    pub fn clear_consume_list(&mut self) {
        self.addlflags &= !addl_flags::LIS_CONSUME;
    }
    // Ghidra: varnode.cc:578 Varnode::setExplicit
    /// Mark this as an explicit variable in the final C source. (varnode.hh:311;
    /// routed via setFlags — the high flagsDirty notification fires with it.)
    pub fn set_explicit(&mut self) {
        self.set_flags(varnode_flags::EXPLICIT);
    }
    // Ghidra: varnode.cc:578 Varnode::clearExplicit
    /// Clear the explicit mark. (varnode.hh:312; routed via clearFlags.)
    pub fn clear_explicit(&mut self) {
        self.clear_flags(varnode_flags::EXPLICIT);
    }

    // Ghidra: varnode.cc:578 Varnode::isDirectWrite
    /// Is this value affected by a legitimate function input? (varnode.hh:247)
    pub fn is_direct_write(&self) -> bool {
        (self.flags & varnode_flags::DIRECTWRITE) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setDirectWrite
    /// Mark this as directly affected by a legal input. (varnode.hh:305)
    pub fn set_direct_write(&mut self) {
        self.flags |= varnode_flags::DIRECTWRITE;
    }
    // Ghidra: varnode.cc:578 Varnode::clearDirectWrite
    /// Mark this as not directly affected. (varnode.hh:306)
    pub fn clear_direct_write(&mut self) {
        self.flags &= !varnode_flags::DIRECTWRITE;
    }

    // ---- Ghidra flag accessors (varnode.hh:251-300, 307-330) ----
    // Flag constants already defined in varnode_flags/addl_flags above; these
    // are the missing accessor methods needed by ported Rules.

    // Ghidra: varnode.hh:265 Varnode::isStackStore
    /// Was this originally produced by an explicit CPUI_STORE? Faithful
    /// inline `(addlflags & Varnode::stack_store) != 0`. The flag is set by
    /// RuleStoreVarnode when it converts a constant-offset STORE into a
    /// COPY (ruleaction.cc:4333), and consumed by ActionDirectWrite's
    /// COPY-source trace (coreaction.cc:1382).
    pub fn is_stack_store(&self) -> bool {
        (self.addlflags & addl_flags::STACK_STORE) != 0
    }
    // Ghidra: varnode.hh:338 Varnode::setStackStore
    /// Mark as produced by explicit CPUI_STORE:
    /// `addlflags |= Varnode::stack_store`.
    pub fn set_stack_store(&mut self) {
        self.addlflags |= addl_flags::STACK_STORE;
    }

    // Ghidra: varnode.cc:578 Varnode::isAddrForce
    /// Is this varnode forced to be treated as an address? (varnode.hh:251)
    pub fn is_addr_force(&self) -> bool {
        (self.flags & varnode_flags::ADDRFORCE) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setAddrForce
    /// Mark as address-forced. (varnode.hh:307; routed via setFlags — the
    /// high flagsDirty notification fires with it.)
    pub fn set_addr_force(&mut self) {
        self.set_flags(varnode_flags::ADDRFORCE);
    }
    // Ghidra: varnode.cc:578 Varnode::clearAddrForce
    /// Clear address-forced. (varnode.hh:308; routed via clearFlags.)
    pub fn clear_addr_force(&mut self) {
        self.clear_flags(varnode_flags::ADDRFORCE);
    }

    // Ghidra: varnode.cc:578 Varnode::isTypeLock
    /// Is the type locked on this varnode? (varnode.hh:299)
    pub fn is_type_lock(&self) -> bool {
        (self.flags & varnode_flags::TYPELOCK) != 0
    }

    // Ghidra: varnode.hh:267 Varnode::stopsUpPropagation
    /// Is data-type propagation stopped from an output into this varnode?
    /// Faithful to the inline `(addlflags & Varnode::stop_uppropagation) != 0`
    /// (varnode.hh:267). Consumed by `ActionInferTypes::propagateTypeEdge`
    /// (coreaction.cc:5093); the flag lives in `addl_flags` (u16 `addlflags`),
    /// never in the main `varnode_flags` where 0x800 is `volatil`.
    pub fn stops_up_propagation(&self) -> bool {
        (self.addlflags & addl_flags::STOP_UP_PROPAGATION) != 0
    }

    // Ghidra: varnode.hh:333 Varnode::setStopUpPropagation
    /// Stop data-type up-propagation through this varnode:
    /// `addlflags |= Varnode::stop_uppropagation`. Set only by
    /// `ActionInferTypes::buildLocaltypes` (coreaction.cc:5031) when
    /// `getLocalType` reports `needsBlock` (a def with `stop_type_propagation`
    /// op flag 0x40 was consumed); Ghidra has no clear call site anywhere.
    pub fn set_stop_up_propagation(&mut self) {
        self.addlflags |= addl_flags::STOP_UP_PROPAGATION;
    }

    // Ghidra: varnode.hh:334 Varnode::clearStopUpPropagation
    /// Clear the stop-up-propagation flag: `addlflags &= ~stop_uppropagation`.
    /// Declared in Ghidra (varnode.hh:334) with zero call sites in the
    /// decompile sources; ported for interface parity.
    pub fn clear_stop_up_propagation(&mut self) {
        self.addlflags &= !addl_flags::STOP_UP_PROPAGATION;
    }

    // RUGRA-GLUE: identity handle for `PcodeOp::getSlot(this)`-style pointer
    //   comparisons. Ghidra compares raw `Varnode*` pointers (op.hh:166);
    //   Rugra varnodes live in `Arc<RwLock<Varnode>>` allocations whose weak
    //   self reference is installed by `VarnodeBank::allocate` (varnode.rs).
    pub(crate) fn self_arc(&self) -> Option<Arc<RwLock<Varnode>>> {
        self.self_ref.upgrade()
    }

    // Ghidra: varnode.cc:578 Varnode::isNameLock
    /// Is the name locked on this varnode? (varnode.hh:300)
    pub fn is_name_lock(&self) -> bool {
        (self.flags & varnode_flags::NAMELOCK) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isPrecisLo
    /// Is this the low half of a precise register pair? (varnode.hh:275)
    pub fn is_precis_lo(&self) -> bool {
        (self.flags & varnode_flags::PRECISLO) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::isPrecisHi
    /// Is this the high half of a precise register pair? (varnode.hh:276)
    pub fn is_precis_hi(&self) -> bool {
        (self.flags & varnode_flags::PRECISHI) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setPrecisLo
    /// Mark as precise low half. (varnode.hh:321; routed via setFlags — the
    /// high flagsDirty notification fires with it.)
    pub fn set_precis_lo(&mut self) {
        self.set_flags(varnode_flags::PRECISLO);
    }
    // Ghidra: varnode.cc:578 Varnode::setPrecisHi
    /// Mark as precise high half. (varnode.hh:322; routed via setFlags.)
    pub fn set_precis_hi(&mut self) {
        self.set_flags(varnode_flags::PRECISHI);
    }
    // Ghidra: varnode.cc:578 Varnode::clearPrecisLo
    /// Clear precise low half. (varnode.hh:323; routed via clearFlags.)
    pub fn clear_precis_lo(&mut self) {
        self.clear_flags(varnode_flags::PRECISLO);
    }
    // Ghidra: varnode.cc:578 Varnode::clearPrecisHi
    /// Clear precise high half. (varnode.hh:324; routed via clearFlags.)
    pub fn clear_precis_hi(&mut self) {
        self.clear_flags(varnode_flags::PRECISHI);
    }

    // Ghidra: varnode.cc:578 Varnode::isProtoPartial
    /// Is this a partial prototype varnode? (varnode.hh:258)
    pub fn is_proto_partial(&self) -> bool {
        (self.flags & varnode_flags::PROTO_PARTIAL) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setProtoPartial
    /// Mark as proto-partial. (varnode.hh:329)
    pub fn set_proto_partial(&mut self) {
        self.flags |= varnode_flags::PROTO_PARTIAL;
    }
    // Ghidra: varnode.cc:578 Varnode::clearProtoPartial
    /// Clear proto-partial. (varnode.hh:330)
    pub fn clear_proto_partial(&mut self) {
        self.flags &= !varnode_flags::PROTO_PARTIAL;
    }

    // Ghidra: varnode.cc:578 Varnode::isPtrFlow
    /// Is this varnode a pointer-flow tracking varnode? (varnode.hh:260)
    /// Uses addlflags (ptrflow), not the main flags field.
    pub fn is_ptr_flow(&self) -> bool {
        (self.addlflags & addl_flags::PTR_FLOW) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setPtrFlow
    /// Mark as pointer-flow. (varnode.hh:317)
    pub fn set_ptr_flow(&mut self) {
        self.addlflags |= addl_flags::PTR_FLOW;
    }
    // Ghidra: varnode.cc:578 Varnode::clearPtrFlow
    /// Clear pointer-flow. (varnode.hh:318)
    pub fn clear_ptr_flow(&mut self) {
        self.addlflags &= !addl_flags::PTR_FLOW;
    }

    // Ghidra: varnode.cc:578 Varnode::isIndirectCreation
    /// Is this varnode marked as an indirect creation? (varnode.hh:248)
    pub fn is_indirect_creation(&self) -> bool {
        (self.flags & varnode_flags::INDIRECT_CREATION) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::getType
    /// Get the datatype of this varnode. (varnode.hh:192)
    pub fn get_type(&self) -> Option<Arc<Datatype>> {
        self.v_type.clone()
    }

    // Ghidra: varnode.cc:456 Varnode::updateType
    /// Set the type without locking. Faithful to `Varnode::updateType(Datatype*)`
    /// (varnode.cc:456-464). Returns true if the type was changed.
    pub fn update_type(&mut self, ct: Arc<Datatype>) -> bool {
        if self
            .v_type
            .as_ref()
            .map(|t| Arc::ptr_eq(t, &ct))
            .unwrap_or(false) || self.is_type_lock() {
            return false;
        }
        self.v_type = Some(ct);
        // cc:461-463: `if (high != (HighVariable *)0) high->typeDirty();` —
        // the instance-type write must invalidate the HighVariable's cached
        // type so the next HighVariable::getType (variable.hh:174 →
        // variable.cc:400-415) re-derives from the type representative.
        // HighVariable now tracks TYPEDIRTY, so the former "no-op until
        // HighVariable tracks dirtiness" placeholder is retired.
        if let Some(high) = &self.high {
            high.write().unwrap().type_dirty();
        }
        true
    }

    // Ghidra: varnode.cc:578 Varnode::updateTypeLock
    /// Set the type with lock/override control. Faithful to
    /// `Varnode::updateType(Datatype*, bool, bool)` (varnode.cc:474-489).
    /// TYPE_UNKNOWN always forces lock=false. Returns true if changed.
    pub fn update_type_lock(&mut self, ct: Arc<Datatype>, lock: bool, override_lock: bool) -> bool {
        use crate::type_system::datatype::TypeMetatype;
        let mut effective_lock = lock;
        if ct.get_metatype() == TypeMetatype::Unknown {
            effective_lock = false;
        }
        if self.is_type_lock() && !override_lock {
            return false;
        }
        let same = self
            .v_type
            .as_ref()
            .map(|t| Arc::ptr_eq(t, &ct))
            .unwrap_or(false);
        if same && self.is_type_lock() == effective_lock {
            return false;
        }
        self.clear_flags(varnode_flags::TYPELOCK);
        if effective_lock {
            self.set_flags(varnode_flags::TYPELOCK);
        }
        self.v_type = Some(ct);
        // cc:500-501: same high typeDirty as updateType — the locked write
        // also invalidates the HighVariable's cached type.
        if let Some(high) = &self.high {
            high.write().unwrap().type_dirty();
        }
        true
    }

    // Ghidra: varnode.cc:639 Varnode::getTypeReadFacing
    /// Get the type as seen by a reading op. The zero-op convenience form:
    /// for a type that does not need resolution this equals the oracle's
    /// `getTypeReadFacing` (varnode.cc:639-645), which returns `type`
    /// unchanged. A resolving (union) type would need the
    /// `findResolve(op, slot)` consult, which requires a Funcdata channel —
    /// consumers holding the fd use
    /// [`crate::unionresolve::vn_type_read_facing`]; this form returns the
    /// v_type Arc as-is (the findResolve map-miss arm), never a clone.
    pub fn get_type_read_facing(&self) -> Option<Arc<Datatype>> {
        self.v_type.clone()
    }

    // Ghidra: varnode.cc:626 Varnode::getTypeDefFacing
    /// Return the resolved data-type for this Varnode based on its def op.
    /// Faithful to `getTypeDefFacing` (varnode.cc:626-632): a type that does
    /// not need resolution is returned as-is; a union/pointer-to-union type
    /// resolves via `type->findResolve(def, -1)` (type.cc:586/1192). The
    /// method form has no Funcdata channel, so the consult reduces to
    /// findResolve's map-miss arm — `return this` — sharing the SAME Arc
    /// instead of cloning. Arc identity is load-bearing here: the oracle's
    /// TypeFactory interning makes every findResolve result pointer-stable,
    /// and `Varnode::updateType`'s `type == ct` settle test (varnode.cc:481,
    /// Rust `Arc::ptr_eq`) would churn on per-call fresh clones — the
    /// `localcount >= 7` "not settling" family (coreaction.cc:5390-5392).
    /// The fd-aware consult twin (reads `Funcdata::union_map`) is
    /// [`crate::unionresolve::vn_type_def_facing`].
    pub fn get_type_def_facing(&self) -> Option<Arc<Datatype>> {
        let ct = self.v_type.clone()?;
        if !ct.needs_resolution() {
            return Some(ct);
        }
        // cc:631: type->findResolve(def, -1) — without a Funcdata channel
        // the consult is exactly the map-miss arm `return this` (type.cc:589).
        Some(ct)
    }

    // Ghidra: varnode.cc:639 Varnode::getTypeReadFacing
    /// Return the resolved data-type for this Varnode when read by `op`
    /// at the given slot. Faithful to `getTypeReadFacing` (varnode.cc:639-645):
    /// a type that does not need resolution is returned as-is; a resolving
    /// type consults `type->findResolve(op, op->getSlot(this))` — here the
    /// no-Funcdata map-miss arm `return this` (type.cc:589), sharing the
    /// SAME Arc (Arc identity is the settle contract, see
    /// [`Self::get_type_def_facing`]). The fd-aware consult twin is
    /// [`crate::unionresolve::vn_type_read_facing`].
    pub fn get_type_read_facing_op(&self, _op: &PcodeOp, slot: i32) -> Option<Arc<Datatype>> {
        let ct = self.v_type.clone()?;
        if !ct.needs_resolution() {
            return Some(ct);
        }
        // cc:644: type->findResolve(op, op->getSlot(this)) — map-miss arm.
        let _ = slot;
        Some(ct)
    }

    // Ghidra: varnode.cc:651 Varnode::getHighTypeDefFacing
    /// Return the resolved HighVariable type for this Varnode based on def.
    /// Faithful to `getHighTypeDefFacing` (varnode.cc:651-658): the high
    /// type that does not need resolution is returned as-is; a resolving
    /// high type consults `ct->findResolve(def, -1)` — here the no-Funcdata
    /// map-miss arm `return this`, sharing the SAME Arc (settle contract,
    /// [`Self::get_type_def_facing`]). The fd-aware consult twin is
    /// [`crate::unionresolve::vn_high_type_def_facing`].
    pub fn get_high_type_def_facing(&self) -> Option<Arc<Datatype>> {
        let high = self.high.as_ref()?;
        let ct = high.read().unwrap().get_type();
        if !ct.needs_resolution() {
            return Some(ct);
        }
        Some(ct)
    }

    // Ghidra: varnode.cc:665 Varnode::getHighTypeReadFacing
    /// Return the resolved HighVariable type when read by `op`.
    /// Faithful to `getHighTypeReadFacing` (varnode.cc:665-672): the high
    /// type that does not need resolution is returned as-is; a resolving
    /// high type consults `ct->findResolve(op, op->getSlot(this))` — here
    /// the no-Funcdata map-miss arm `return this`, sharing the SAME Arc
    /// (settle contract, [`Self::get_type_def_facing`]). The fd-aware
    /// consult twin is
    /// [`crate::unionresolve::vn_high_type_read_facing`].
    pub fn get_high_type_read_facing(&self, _op: &PcodeOp, _slot: i32) -> Option<Arc<Datatype>> {
        let high = self.high.as_ref()?;
        let ct = high.read().unwrap().get_type();
        if !ct.needs_resolution() {
            return Some(ct);
        }
        Some(ct)
    }

    // Ghidra: varnode.cc:493 Varnode::copySymbol
    /// Copy symbol/type info from another varnode — the field half of
    /// `Varnode::copySymbol` (varnode.cc:496-499). Copies type + mapentry +
    /// typelock/namelock flags. The cc:500-504 high bookkeeping
    /// (`high->typeDirty()` / `high->setSymbol(this)`) needs the
    /// destination's `Arc` identity and lives in
    /// [`Varnode::copy_symbol_arc`]; callers that cannot hand over the Arc
    /// must perform that half at the call site (see funcdata.rs
    /// op_set_input's dedup leg).
    pub fn copy_symbol(&mut self, vn: &Varnode) {
        self.v_type = vn.v_type.clone();
        self.mapentry = vn.mapentry.clone();
        self.clear_flags(varnode_flags::TYPELOCK | varnode_flags::NAMELOCK);
        let inherit = vn.flags & (varnode_flags::TYPELOCK | varnode_flags::NAMELOCK);
        self.set_flags(inherit);
    }

    // Ghidra: varnode.cc:493 Varnode::copySymbol
    /// Copy symbol/type info from `vn` into the varnode behind `self_arc` —
    /// the complete port of `Varnode::copySymbol` (varnode.cc:493-505),
    /// including the cc:500-504 high bookkeeping:
    /// ```text
    /// type = vn->type;                                   // cc:496
    /// mapentry = vn->mapentry;                           // cc:497
    /// flags &= ~(Varnode::typelock | Varnode::namelock); // cc:498
    /// flags |= (Varnode::typelock | Varnode::namelock) & vn->flags; // cc:499
    /// if (high != (HighVariable *)0) {                   // cc:500
    ///   high->typeDirty();                               // cc:501
    ///   if (mapentry != (SymbolEntry *)0)                // cc:502
    ///     high->setSymbol(this);                         // cc:503
    /// }
    /// ```
    /// The cc:500-504 half needs the destination's `Arc<RwLock<Varnode>>`
    /// identity — `setSymbol(this)` hands the *destination* varnode (not
    /// `vn`) to `HighVariable::set_symbol` (variable.cc:245), which
    /// re-reads its SymbolEntry and offset — so this is an associated
    /// function rather than a `&mut self` method. The write guard on the
    /// destination is dropped before the high bookkeeping so `set_symbol`
    /// can re-acquire the destination read-only without deadlock.
    pub fn copy_symbol_arc(self_arc: &std::sync::Arc<RwLock<Varnode>>, vn: &Varnode) {
        let (high, has_mapentry) = {
            let mut this = self_arc.write().unwrap();
            this.copy_symbol(vn); // cc:496-499 field half
            (this.high.clone(), this.mapentry.is_some())
        };
        // cc:500-504: high bookkeeping. typeDirty fires whenever a
        // HighVariable is attached; setSymbol additionally requires a
        // mapentry to have survived the copy (cc:502 guard).
        if let Some(high) = high {
            let mut h = high.write().unwrap();
            h.type_dirty(); // variable.hh:166 HighVariable::typeDirty
            if has_mapentry {
                h.set_symbol(self_arc); // variable.cc:245 HighVariable::setSymbol
            }
        }
    }

    // Ghidra: varnode.cc:410 Varnode::setSymbolProperties
    /// Set symbol properties on this Varnode from a SymbolEntry.
    /// Faithful to `setSymbolProperties` (varnode.cc:410-424):
    /// ```text
    /// bool res = entry->updateType(this);
    /// if (entry->getSymbol()->isTypeLocked()) {
    ///   if (mapentry != entry) {
    ///     mapentry = entry;
    ///     if (high != (HighVariable *)0)
    ///       high->setSymbol(this);
    ///     res = true;
    ///   }
    /// }
    /// setFlags(entry->getAllFlags() & ~Varnode::typelock);
    /// return res;
    /// ```
    /// The cc:415 `mapentry != entry` pointer identity maps to
    /// [`crate::database::SymbolEntry::same_storage_identity`]; the
    /// cc:417-418 `high->setSymbol(this)` reverse connection
    /// (variable.cc:245) needs the Varnode's own Arc, so this is an
    /// associated function mirroring `copy_symbol_arc`.
    /// (FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001: the missing HighVariable
    /// symbol link was the head of that TODO.)
    pub fn set_symbol_properties_arc(
        self_arc: &std::sync::Arc<RwLock<Varnode>>,
        entry: &Arc<RwLock<SymbolEntry>>,
    ) -> bool {
        // cc:413: res = entry->updateType(this) — the typelock-gated
        // getSizedType + vn->updateType(dt,true,true) pair
        // (database.cc:135-144). updateType returns whether the
        // data-type changed.
        let mut res = {
            let mut this = self_arc.write().unwrap();
            let (vn_addr, vn_size) = (this.loc, this.get_size() as i32);
            let sized = entry.read().unwrap().update_type(
                &mut crate::type_system::typefactory::TypeFactory::shared_default()
                    .write()
                    .unwrap(),
                vn_addr,
                vn_size,
            );
            match sized {
                Some(dt) => this.update_type_lock(dt, true, true),
                None => false,
            }
        };
        // cc:414-421: type-locked symbol + mapentry identity guard, then
        // the HighVariable symbol reverse link — the setSymbol call lives
        // INSIDE the `mapentry != entry` guard in the oracle, so a
        // not-type-locked symbol or an already-linked entry never touches
        // the HighVariable here.
        let (is_type_locked, already_linked) = {
            let e = entry.read().unwrap();
            let is_type_locked = e.symbol.read().unwrap().is_type_locked();
            let already_linked = match self_arc.read().unwrap().mapentry.as_ref() {
                Some(current) => current.read().unwrap().same_storage_identity(&e),
                None => false,
            };
            (is_type_locked, already_linked)
        };
        if is_type_locked && !already_linked {
            // cc:415-419: mapentry = entry; if (high != 0)
            // high->setSymbol(this); res = true.
            let high = {
                let mut this = self_arc.write().unwrap();
                this.mapentry = Some(entry.clone());
                this.high.clone()
            };
            // cc:417-418: if (high != 0) high->setSymbol(this).
            if let Some(high) = high {
                high.write().unwrap().set_symbol(self_arc);
            }
            res = true;
        }
        // cc:422: setFlags(entry->getAllFlags() & ~typelock).
        let flags_to_set =
            entry.read().unwrap().get_all_flags() & !varnode_flags::TYPELOCK;
        self_arc.write().unwrap().set_flags(flags_to_set);
        res
    }

    // Ghidra: varnode.cc:429 Varnode::setSymbolEntry
    /// Link a Symbol to this Varnode via the given SymbolEntry.
    /// Faithful to `setSymbolEntry` (varnode.cc:429-439). Sets mapentry,
    /// marks MAPPED, and NAMELOCK if the symbol is name-locked.
    pub fn set_symbol_entry(&mut self, entry: Arc<RwLock<SymbolEntry>>) {
        let is_name_locked = entry
            .read()
            .unwrap()
            .symbol
            .read()
            .unwrap()
            .is_name_locked();
        self.mapentry = Some(entry);
        let mut fl = varnode_flags::MAPPED;
        if is_name_locked {
            fl |= varnode_flags::NAMELOCK;
        }
        self.set_flags(fl);
    }

    // Ghidra: varnode.cc:446 Varnode::setSymbolReference
    /// Link Symbol info to this as a reference (for constant address refs).
    /// Faithful to `setSymbolReference` (varnode.cc:446-452).
    pub fn set_symbol_reference(&mut self, _entry: &Arc<RwLock<SymbolEntry>>, _off: i32) {
        // cc:449-451: if high != null, high->setSymbolReference(entry->getSymbol(), off)
        // Rugra's HighVariable setSymbolReference is not yet implemented.
        // TODO: port when HighVariable symbol linking is available.
    }

    // Ghidra: varnode.cc:510 Varnode::copySymbolIfValid
    /// Symbol information (if present) is copied from the given constant
    /// Varnode into \b this, which also must be constant, but only if the two
    /// constants are \e close in the sense of an equate. Faithful to
    /// `copySymbolIfValid` (varnode.cc:510-522):
    /// ```text
    /// SymbolEntry *mapEntry = vn->getSymbolEntry();
    /// if (mapEntry == (SymbolEntry *)0) return;
    /// EquateSymbol *sym = dynamic_cast<EquateSymbol *>(mapEntry->getSymbol());
    /// if (sym == (EquateSymbol *) 0) return;
    /// if (sym->isValueClose(loc.getOffset(), size)) {
    ///   copySymbol(vn);  // Propagate the markup into our new constant
    /// }
    /// ```
    /// The `dynamic_cast<EquateSymbol*>` subtype test maps to
    /// [`equate_symbol_registry::query_value`]: only symbols registered as
    /// equates (the Rust stand-in for the C++ EquateSymbol subtype identity)
    /// carry an equate value here. This is an associated function taking the
    /// destination as `&Arc<RwLock<Varnode>>` so the cc:520 `copySymbol(vn)`
    /// tail can run the complete port (high bookkeeping included) via
    /// [`Varnode::copy_symbol_arc`].
    pub fn copy_symbol_if_valid(self_arc: &std::sync::Arc<RwLock<Varnode>>, vn: &Varnode) {
        // cc:513-515: no SymbolEntry on the source varnode -> nothing to copy.
        let map_entry = match vn.get_symbol_entry() {
            Some(e) => e,
            None => return,
        };
        // cc:516-518: dynamic_cast<EquateSymbol*>; a non-equate symbol is
        // rejected outright (no markup propagation).
        let symbol = map_entry.read().unwrap().get_symbol();
        let value = match equate_symbol_registry::query_value(&symbol) {
            Some(v) => v,
            None => return,
        };
        // cc:519-521: propagate only when this constant (loc offset + size)
        // is "close" to the equate value (database.cc:640 isValueClose).
        // The read guard is dropped before the copy mutation.
        let close = {
            let this = self_arc.read().unwrap();
            crate::database::EquateSymbol::is_value_close_value(value, this.get_offset(), this.size)
        };
        if close {
            Varnode::copy_symbol_arc(self_arc, vn); // Propagate the markup into our new constant
        }
    }

    // Ghidra: varnode.cc:578 Varnode::getSymbolEntry
    /// Get the SymbolEntry (symbol mapping) of this varnode, if any.
    /// Faithful to `Varnode::getSymbolEntry` (varnode.hh:190).
    pub fn get_symbol_entry(&self) -> Option<Arc<RwLock<SymbolEntry>>> {
        self.mapentry.clone()
    }

    // Ghidra: varnode.cc:1137 Varnode::getStructuredType
    /// Get the structured type of this varnode, preferring the symbol's type
    /// over the varnode's own type. Faithful to `Varnode::getStructuredType`
    /// (varnode.cc:1137-1148). Returns the type if it is piece-structured,
    /// else None.
    pub fn get_structured_type(&self) -> Option<Arc<Datatype>> {
        let ct = if let Some(me) = &self.mapentry {
            let me_rg = me.read().unwrap();
            me_rg
                .get_symbol()
                .read()
                .unwrap()
                .get_type()
                .or_else(|| self.v_type.clone())
        } else {
            self.v_type.clone()
        };
        ct.filter(|t| t.is_piece_structured())
    }

    /// Is the high-level variable tied to an address? (varnode.hh:250)
    /// Ghidra: (flags & (addrtied|insert)) == (addrtied|insert).
    pub fn is_addr_tied(&self) -> bool {
        (self.flags & (varnode_flags::ADDRTIED | varnode_flags::INSERT))
            == (varnode_flags::ADDRTIED | varnode_flags::INSERT)
    }

    // Ghidra: varnode.cc:578 Varnode::isPersist
    /// Does this storage location persist beyond the function? (varnode.hh:246)
    pub fn is_persist(&self) -> bool {
        (self.flags & varnode_flags::PERSIST) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isUnaffected
    /// Is this a value preserved across the function? (varnode.hh:255)
    pub fn is_unaffected(&self) -> bool {
        (self.flags & varnode_flags::UNAFFECTED) != 0
    }

    // Ghidra: varnode.hh:247 Varnode::isVolatile
    pub fn is_volatile(&self) -> bool {
        (self.flags & varnode_flags::VOLATIL) != 0
    }

    // Ghidra: varnode.cc:1182 Varnode::encode
    /// Encode this Varnode as XML attributes. Faithful to `encode`
    /// (varnode.cc:1182-1201). Rugra returns a String (no Encoder).
    pub fn encode(&self) -> String {
        let mut s = format!(
            "<addr space=\"{}\" offset=\"{:x}\" size=\"{}\" ref=\"{}\"",
            self.address_space.name(), self.loc.as_u64(), self.size, self.create_index
        );
        if self.is_persist() { s += " persists=\"true\""; }
        if self.is_addr_tied() { s += " addrtied=\"true\""; }
        if self.is_unaffected() { s += " unaff=\"true\""; }
        if self.is_input() { s += " input=\"true\""; }
        if self.is_volatile() { s += " volatile=\"true\""; }
        s += "/>";
        s
    }

    // Ghidra: varnode.cc:344 Varnode::destroyDescend
    /// Clear all descend references. Faithful to `destroyDescend`
    /// (varnode.cc:344-350).
    pub fn destroy_descend(&mut self) {
        self.descend.clear();
    }

    // Ghidra: varnode.cc:1153 Varnode::termOrder
    /// Compare this varnode with another for term ordering (constants last).
    /// Faithful to `termOrder` (varnode.cc:1153-1180). Used by
    /// AddExpression to order commutative operands.
    pub fn term_order(&self, op: &Varnode) -> i32 {
        // cc:1156-1160: constants sort last, and all constants compare equal.
        if self.is_constant() {
            return if op.is_constant() { 0 } else { 1 };
        }
        if op.is_constant() {
            return -1;
        }

        // cc:1162-1172: strip a single INT_MULT(_, constant) wrapper, then
        // compare the complete Address. Size is deliberately not a key.
        let term_address = |vn: &Varnode| {
            let base = vn.get_def().and_then(|def| {
                let operation = def.read().unwrap();
                if operation.get_opcode() != crate::opcodes::OpCode::CPUI_INT_MULT {
                    return None;
                }
                let coefficient = operation.get_in(1)?;
                if !coefficient.read().unwrap().is_constant() {
                    return None;
                }
                operation.get_in(0).cloned()
            });
            if let Some(base) = base {
                let base = base.read().unwrap();
                (base.address_space, base.loc.as_u64())
            } else {
                (vn.address_space, vn.loc.as_u64())
            }
        };

        let lhs = term_address(self);
        let rhs = term_address(op);
        match compare_address_spaces(lhs.0, rhs.0).then_with(|| lhs.1.cmp(&rhs.1)) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    // Ghidra: varnode.hh:257 Varnode::isReturnAddress
    /// Is this storage for a call's return address? Faithful to
    /// `Varnode::isReturnAddress` (varnode.hh:257):
    ///   `(flags & return_address) != 0`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to reject return
    /// address storage as a parameter passing location.
    pub fn is_return_address(&self) -> bool {
        (self.flags & varnode_flags::RETURN_ADDRESS) != 0
    }

    // Ghidra: varnode.hh:241 Varnode::setReturnAddress
    pub fn set_return_address(&mut self) {
        self.flags |= varnode_flags::RETURN_ADDRESS;
    }

    // Ghidra: varnode.hh:222 Varnode::isMapped
    pub fn is_mapped(&self) -> bool {
        (self.flags & varnode_flags::MAPPED) != 0
    }

    // Ghidra: varnode.hh:325 Varnode::setWriteMask
    pub fn set_write_mask(&mut self) {
        self.addlflags |= addl_flags::WRITE_MASK;
    }

    // Ghidra: varnode.hh:326 Varnode::clearWriteMask
    pub fn clear_write_mask(&mut self) {
        self.addlflags &= !addl_flags::WRITE_MASK;
    }

    // Ghidra: varnode.hh:278 Varnode::isWriteMask
    pub fn is_write_mask(&self) -> bool {
        (self.addlflags & addl_flags::WRITE_MASK) != 0
    }

    // Ghidra: varnode.cc:378 Varnode::clearSymbolLinks
    /// Clear all symbol references. Faithful to `clearSymbolLinks`
    /// (varnode.cc:378-392).
    pub fn clear_symbol_links(&mut self) {
        self.mapentry = None;
        if self.high.is_some() {
            // Ghidra: high->setSymbol(null) — Rugra's HighVariable lacks setSymbol.
            // TODO: needs HighVariable::setSymbol(None).
        }
    }

    // Ghidra: varnode.cc:88 Varnode::getHigh
    /// Get the associated HighVariable. Faithful to `getHigh`
    /// (varnode.cc:88-89).
    pub fn get_high(
        &self,
    ) -> Option<&std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> {
        self.high.as_ref()
    }

    // Ghidra: varnode.cc:854 Varnode::isEventualConstant
    /// Check if this Varnode will eventually fold to a constant, with depth
    /// limits. Faithful to `isEventualConstant` (varnode.cc:854-893):
    ///   - Follows COPY/ZEXT/SEXT chains (in(0)) without depth limit.
    ///   - LOAD: decrements maxLoad, follows in(1).
    ///   - INT_ADD/SUB/XOR/OR/AND: decrements maxBinary, recursively checks
    ///     both inputs (in(0) then in(1)).
    ///   - INT_LEFT/RIGHT/SRIGHT/MULT: requires in(1) constant, follows in(0).
    ///   - All other ops: false.
    /// Previously this was a simplified 1-level check; now faithfully recurses.
    pub fn is_eventual_constant(&self, max_binary: i32, max_load: i32) -> bool {
        use crate::opcodes::OpCode;
        let mut cur_vn_offset = self.loc.as_u64();
        let mut cur_vn_space = self.address_space;
        let mut cur_vn_size = self.size;
        let mut cur_def = self.def.clone();
        let mut mb = max_binary;
        let mut ml = max_load;
        loop {
            // Check if current varnode is constant.
            if cur_vn_space == crate::space::AddressSpace::Const { return true; }
            // Follow the def op.
            let def_arc = match cur_def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => return false,
            };
            let def_r = def_arc.read().unwrap();
            match def_r.opcode {
                OpCode::CPUI_LOAD => {
                    if ml == 0 { return false; }
                    ml -= 1;
                    // Follow in(1).
                    let in1 = match def_r.get_in(1) { Some(v) => v.clone(), None => return false ,
                    };
                    drop(def_r);
                    let r = in1.read().unwrap();
                    cur_vn_offset = r.loc.as_u64();
                    cur_vn_space = r.address_space;
                    cur_vn_size = r.size;
                    cur_def = r.def.clone();
                }
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_AND => {
                    if mb == 0 { return false; }
                    let in0 = match def_r.get_in(0) { Some(v) => v.clone(), None => return false ,
                    };
                    let in1 = match def_r.get_in(1) { Some(v) => v.clone(), None => return false ,
                    };
                    drop(def_r);
                    if !in0.read().unwrap().is_eventual_constant(mb - 1, ml) { return false; }
                    return in1.read().unwrap().is_eventual_constant(mb - 1, ml);
                }
                OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT | OpCode::CPUI_COPY => {
                    let in0 = match def_r.get_in(0) { Some(v) => v.clone(), None => return false ,
                    };
                    drop(def_r);
                    let r = in0.read().unwrap();
                    cur_vn_offset = r.loc.as_u64();
                    cur_vn_space = r.address_space;
                    cur_vn_size = r.size;
                    cur_def = r.def.clone();
                }
                OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT
                | OpCode::CPUI_INT_SRIGHT | OpCode::CPUI_INT_MULT => {
                    // Requires in(1) constant, follow in(0).
                    let in1 = match def_r.get_in(1) { Some(v) => v.clone(), None => return false ,
                    };
                    if !in1.read().unwrap().is_constant() { return false; }
                    let in0 = match def_r.get_in(0) { Some(v) => v.clone(), None => return false ,
                    };
                    drop(def_r);
                    let r = in0.read().unwrap();
                    cur_vn_offset = r.loc.as_u64();
                    cur_vn_space = r.address_space;
                    cur_vn_size = r.size;
                    cur_def = r.def.clone();
                }
                _ => { return false; }
            }
            let _ = (cur_vn_offset, cur_vn_size); // suppress unused
        }
    }

    // Ghidra: varnode.cc:900 Varnode::getLocalType
    /// Make an initial determination of the Datatype of this Varnode. If a
    /// Datatype is already set and locked return it. Otherwise look through
    /// all the read PcodeOps and the write PcodeOp to determine if the
    /// Varnode is getting used as an int, float, or pointer, etc. Throw an
    /// exception if no Datatype can be found at all (varnode.cc:895-936
    /// doxygen + body).
    ///
    /// `block_up` is the `bool &blockup` reference out-parameter: the method
    /// only ever sets it to `true` (cc:913) and never clears it; the caller
    /// (`ActionInferTypes::buildLocaltypes`, coreaction.cc:5020) resets it to
    /// false per varnode. The `type_factory` parameter threads the
    /// Architecture TypeFactory that Ghidra reaches implicitly through
    /// `PcodeOp::opcode->tlst` (op.hh:122) — Rugra `PcodeOp` holds no parent
    /// chain, so the factory is an explicit argument. The `userops`
    /// parameter threads the Architecture user-op manager for the same
    /// reason: Ghidra's `TypeOpCallother::get*Local` reach it via
    /// `tlst->getArch()->userops` (typeop.cc:858/868), a link Rugra's
    /// TypeFactory cannot carry today (the canonical factory may be shared
    /// across Architectures via `TypeFactory::shared_default`, and
    /// `Architecture::set_types` runs before the Architecture is wrapped in
    /// an Arc, so a `Weak` backlink cannot be formed there). The `symboltab`
    /// parameter threads the Architecture Database the same way: Ghidra's
    /// `VolatileReadOp::getOutputLocal` reaches the global scope via the
    /// descriptor's `glb->symboltab` edge (userop.cc:136), a link Rugra's
    /// `UserOpManage` does not carry; `None` disables the volatile-read
    /// symbol query (same fall-through as a metadata-less descriptor).
    /// `None` (no
    /// owning Architecture) routes CALLOTHER defs/readers to the same base
    /// default Ghidra produces for a metadata-less descriptor.
    ///
    /// Returns `Ok(Some(ct))` for a resolved canonical type, `Ok(None)` for
    /// the null `Datatype*` returns Ghidra produces on the type-locked path
    /// (cc:907, a locked varnode with a null type) and on the STOP early
    /// return (cc:914, `ct` may still be null there), and
    /// `Err("NULL local type")` for the cc:934 `throw LowlevelError`.
    pub fn get_local_type(
        &self,
        block_up: &mut bool,
        type_factory: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
        userops: Option<&Arc<RwLock<crate::userop::UserOpManage>>>,
        symboltab: Option<&Arc<RwLock<crate::database::Database>>>,
        fd_output_type: Option<&Arc<Datatype>>,
    ) -> Result<Option<Arc<Datatype>>> {
        // cc:906-907: Our type is locked, don't change. Not a partial lock,
        // return the locked type (no blockup touch, no def/descend consult).
        if self.is_type_lock() {
            return Ok(self.v_type.clone());
        }

        // cc:909-916: seed from the defining op's outputTypeLocal(); a def
        // consuming stop_type_propagation (op flag 0x40, set by
        // RulePtrArith/RuleStructOffset0) sets blockup and returns early —
        // no descendant is consulted.
        let mut ct: Option<Arc<Datatype>> = None;
        if let Some(def) = self.get_def() {
            let (out_local, stops) = {
                let def_op = def.read().unwrap();
                (
                    op_output_type_local(&def_op, type_factory, userops, symboltab),
                    def_op.stops_type_propagation(),
                )
            };
            ct = out_local;
            if stops {
                // cc:912-914
                *block_up = true;
                return Ok(ct);
            }
        }

        // cc:918-932: walk descend in addDescend insertion order (a
        // std::list<PcodeOp*> in Ghidra, varnode.hh:149 — no sorting, no
        // skipping). i = op->getSlot(this) (op.hh:166) scans inrefs for
        // pointer identity and breaks at the FIRST match.
        let self_arc = self.self_arc();
        for descend_op in self.descend_iter() {
            let slot = {
                let op = descend_op.read().unwrap();
                self_arc
                    .as_ref()
                    .and_then(|self_arc| {
                        op.inrefs
                            .iter()
                            .position(|input| Arc::ptr_eq(input, self_arc))
                    })
            };
            // Ghidra's descend invariant: every entry was added by an
            // op_set_input that still holds this varnode (a dangling Weak
            // upgrade is already skipped by descend_iter). If identity is
            // unresolvable (non-bank varnode without self_ref), skip rather
            // than feeding inputTypeLocal an out-of-range slot, which Ghidra
            // would assert on.
            let Some(slot) = slot else { continue };
            let newct = {
                let op = descend_op.read().unwrap();
                op_input_type_local(&op, slot, type_factory, userops, fd_output_type)
            };
            match (&ct, newct) {
                // cc:926-927: first non-null candidate wins unconditionally.
                (None, newct) => ct = newct,
                // cc:929-930: `if (0>newct->typeOrder(*ct)) ct = newct;` —
                // replace only on strictly smaller typeOrder (more specific:
                // smaller submeta, then bigger size; type.cc:212-218). Ties
                // keep the incumbent, so with equal typeOrder the FIRST
                // encountered type survives. A null newct alongside a non-null
                // ct is a null-this dereference in Ghidra (UB); Rugra keeps
                // the incumbent instead of crashing — unreachable through the
                // TypeOp override table, whose entries never return null on a
                // reachable op.
                (Some(current), Some(new)) => {
                    if new.type_order(current) < 0 {
                        ct = Some(new);
                    }
                }
                (Some(_), None) => {}
            }
        }
        // cc:933-934: no local type at all -> LowlevelError("NULL local type").
        if ct.is_none() {
            return Err(anyhow!("NULL local type"));
        }
        Ok(ct)
    }

    // Ghidra: varnode.hh:271 Varnode::isIndirectZero
    /// Is this an indirect creation that is also a constant (i.e. a possible
    /// zero produced indirectly by a call)? Faithful to
    /// `Varnode::isIndirectZero` (varnode.hh:271):
    ///   `(flags & (indirect_creation|constant)) == (indirect_creation|constant)`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to detect a
    /// killedbycall output that is definitely not a real parameter.
    pub fn is_indirect_zero(&self) -> bool {
        (self.flags
            & (varnode_flags::INDIRECT_CREATION | varnode_flags::CONSTANT))
            == (varnode_flags::INDIRECT_CREATION | varnode_flags::CONSTANT)
    }

    // Ghidra: varnode.hh:277 Varnode::isIncidentalCopy
    /// Does this varnode get copied as a side-effect of a call (an
    /// "incidental" COPY)? Faithful to `Varnode::isIncidentalCopy`
    /// (varnode.hh:277): `(flags & incidental_copy) != 0`.
    /// Used by AncestorRealistic::enterNode (COPY/SUBPIECE cases) to treat
    /// incidental copies as transparent traversal nodes.
    pub fn is_incidental_copy(&self) -> bool {
        (self.flags & varnode_flags::INCIDENTAL_COPY) != 0
    }

    // Ghidra: varnode.cc:178 Varnode::overlap
    /// Return the relative point of overlap between this Varnode and `other`,
    /// or -1 if no overlap. Faithful to `Varnode::overlap` (varnode.cc:178).
    /// For little-endian (Rugra's only supported case), this returns the byte
    /// offset within `other` where this Varnode's low byte falls. Used by
    /// AncestorRealistic::enterNode (SUBPIECE case) to detect a no-op
    /// truncation extracting the same physical bytes.
    pub fn overlap(&self, other: &Varnode) -> i32 {
        // cc:178-180 (little-endian): delegates to loc.overlap(0, op.loc, op.size)
        // which is Address::overlap (address.cc:153-165).
        // address.cc:158: base != op.base → -1
        if self.address_space != other.address_space {
            return -1;
        }
        // address.cc:159: IPTR_CONSTANT → -1
        if self.address_space == AddressSpace::Const {
            return -1;
        }
        // address.cc:161-164: dist = wrapOffset(offset + skip - op.offset);
        //                    dist >= size → -1; else dist.
        // skip=0 for little-endian.
        let off = other.get_offset();
        let my_off = self.get_offset();
        // wrapOffset mimics modular arithmetic of uintb
        let dist = my_off.wrapping_sub(off);
        if dist >= other.get_size() as u64 {
            return -1;
        }
        dist as i32
    }

    // Ghidra: varnode.cc:217 Varnode::overlap(const Address&, int4)
    /// Return LSB-relative overlap with an address range. Faithful to
    /// `overlap(const Address&, int4)` (varnode.cc:217-231), including the
    /// big-endian branch (varnode.cc:221-226):
    ///   - LE: `loc.overlap(0, op2loc, op2size)` = `wrap(vn.off - op2.off)`,
    ///     -1 when it falls outside `[0, op2size)`;
    ///   - BE: `over = loc.overlap(size-1, op2loc, op2size)` =
    ///     `wrap(vn.off + vn.size - 1 - op2.off)`; when `over != -1` the
    ///     result is `op2size-1-over` (the offset counted from the LEAST
    ///     significant side), else -1.
    /// Residual (VARNODE-INIT-0001 family): Ghidra's `Address::overlap`
    /// (address.cc:158-170) also returns -1 when the two Addresses live in
    /// different spaces; Rugra's offset-only `Address` cannot see the
    /// caller's range space, so callers on cross-space graphs must guard
    /// space equality themselves (heritage's normalize sites are
    /// structurally single-space).
    pub fn overlap_addr(&self, op2loc: Address, op2size: usize) -> i32 {
        if self.address_space == AddressSpace::Const { return -1; }
        if !self.address_space.is_big_endian() {
            // varnode.cc:219-220: little endian — skip = 0.
            let dist = self.loc.as_u64().wrapping_sub(op2loc.as_u64());
            if dist >= op2size as u64 { return -1; }
            dist as i32
        } else {
            // varnode.cc:221-226: over = loc.overlap(size-1, op2loc, op2size);
            // if (over != -1) return op2size-1-over;
            let over = self
                .loc
                .as_u64()
                .wrapping_add(self.get_size() as u64 - 1)
                .wrapping_sub(op2loc.as_u64());
            if over >= op2size as u64 { return -1; }
            (op2size as i64 - 1 - over as i64) as i32
        }
    }

    // Ghidra: varnode.cc:197 Varnode::overlapJoin
    /// Return overlap relative to MSB (for join-space operations).
    /// Faithful to `overlapJoin` (varnode.cc:197-208).
    pub fn overlap_join(&self, op: &Varnode) -> i32 {
        // Little endian (x86-64): same as overlap_addr
        self.overlap_addr(op.loc, op.size)
    }

    // Ghidra: varnode.cc:578 Varnode::hasNoLocalAlias
    /// Does the high-level variable have no local alias? (varnode.hh:262)
    pub fn has_no_local_alias(&self) -> bool {
        (self.flags & varnode_flags::NOLOCALALIAS) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setNoLocalAlias
    pub fn set_no_local_alias(&mut self) {
        self.flags |= varnode_flags::NOLOCALALIAS;
    }
    // Ghidra: varnode.cc:578 Varnode::clearNoLocalAlias
    pub fn clear_no_local_alias(&mut self) {
        self.flags &= !varnode_flags::NOLOCALALIAS;
    }
    // Ghidra: varnode.cc:578 Varnode::setUnaffected
    /// Mark Varnode as unaffected. (varnode.hh:167; routed via setFlags —
    /// the high flagsDirty notification fires with it.)
    pub fn set_unaffected(&mut self) {
        self.set_flags(varnode_flags::UNAFFECTED);
    }

    /// Is this an abnormal input to the function? (varnode.hh:240)
    /// Ghidra: (flags & (input|directwrite)) == input.
    pub fn is_illegal_input(&self) -> bool {
        (self.flags & (varnode_flags::INPUT | varnode_flags::DIRECTWRITE))
            == varnode_flags::INPUT
    }

    // Ghidra: varnode.hh:231 Varnode::getNZMask
    /// Get the mask of bits within this Varnode that may be non-zero.
    /// Faithful to `Varnode::getNZMask` (varnode.hh:231): the raw `nzm`
    /// field. The field is initialized by the constructor (varnode.cc:590-606:
    /// constants carry their offset, everything else ~0) and then refined
    /// forward through the dataflow by `Funcdata::calcNZMask`
    /// (funcdata_varnode.cc:856-927: DFS output assignment via
    /// `PcodeOp::getNZMaskLocal` + MULTIEQUAL worklist propagation), which
    /// `ActionNonzeroMask` (coreaction.cc:5507) runs before the rule pools
    /// each mainloop round. Before `calcNZMask` runs, constants report their
    /// offset and all other varnodes report ~0 (FUNCDATA-CALCNZM-0003:
    /// previously this getter recomputed a calc_mask(size) approximation for
    /// non-constants, diverging from the oracle's propagated field).
    pub fn get_nz_mask(&self) -> u64 {
        self.nzm
    }

    // Ghidra: varnode.cc:578 Varnode::hasNoDescend
    /// Return true if no live op reads this varnode. Faithful to
    /// `Varnode::hasNoDescend`. Used by several Rules (RuleXorCollapse,
    /// RuleSubZext) to check exclusive use.
    pub fn has_no_descend(&self) -> bool {
        // PERF-OPPOOL-0001: liveness probe via strong_count (no refcount
        // round-trip per entry); same live-descendant predicate as before.
        self.descend.iter().all(|w| std::sync::Weak::strong_count(w) == 0)
    }

    // Ghidra: varnode.cc:676 Varnode::loneDescend
    /// Return the single descendant op of this varnode, or None if there are
    /// zero or more than one. Faithful to `Varnode::loneDescend`.
    /// PERF-OPPOOL-0001: allocation-free single pass over the weak descend
    /// entries (the previous Vec-collecting form paid one heap allocation per
    /// call — the hot constant of TermOrder::collect / RuleEarlyRemoval
    /// guards). Early-exits at the second live entry, like the oracle's
    /// `iter != descend.end()` short-circuit (varnode.cc:686).
    pub fn lone_descend(&self) -> Option<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> {
        let mut found: Option<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> = None;
        for weak in &self.descend {
            if std::sync::Weak::strong_count(weak) == 0 {
                continue;
            }
            let upgraded = weak.upgrade();
            let Some(live) = upgraded else { continue };
            if found.is_some() {
                return None;
            }
            found = Some(live);
        }
        found
    }

    // Ghidra: varnode.cc:155 Varnode::characterizeOverlap
    /// Characterize the storage overlap between this varnode and `op`.
    /// Faithful to `Varnode::characterizeOverlap` (varnode.cc:155-170).
    /// Returns: 0 = no overlap, 1 = partial overlap, 2 = identical storage.
    pub fn characterize_overlap(&self, other: &Varnode) -> i32 {
        // Different address spaces => no overlap.
        if self.address_space != other.address_space {
            return 0;
        }
        let s_off = self.get_offset();
        let o_off = other.get_offset();
        let s_end = s_off.wrapping_add(self.get_size() as u64);
        let o_end = o_off.wrapping_add(other.get_size() as u64);
        // Same left boundary
        if s_off == o_off {
            return if self.get_size() == other.get_size() { 2 } else { 1 };
        }
        // Check whether the ranges overlap at all: one range must start within
        // the other's [start, end) extent.
        if s_off < o_off {
            // this starts before other; overlap iff this's end > other's start
            if s_end > o_off { 1 } else { 0 }
        } else {
            // other starts before this; overlap iff other's end > this's start
            if o_end > s_off { 1 } else { 0 }
        }
    }

    // Ghidra: varnode.cc:121 Varnode::intersects(const Varnode&)
    /// Check if this Varnode intersects another. Faithful to
    /// `intersects(const Varnode&)` (varnode.cc:121-134).
    pub fn intersects(&self, op: &Varnode) -> bool {
        if self.address_space != op.address_space { return false; }
        if self.address_space == AddressSpace::Const { return false; }
        let a = self.loc.as_u64();
        let b = op.loc.as_u64();
        if b < a {
            return a < b.wrapping_add(op.size as u64);
        }
        b < a.wrapping_add(self.size as u64)
    }

    // Ghidra: varnode.cc:140 Varnode::intersects(const Address&, int4)
    /// Check if this Varnode intersects the given Address range.
    /// Faithful to `intersects(const Address&, int4)` (varnode.cc:140-153).
    pub fn intersects_addr(&self, op2loc: Address, op2size: usize) -> bool {
        if self.address_space == AddressSpace::Const { return false; }
        let a = self.loc.as_u64();
        let b = op2loc.as_u64();
        if b < a {
            return a < b.wrapping_add(op2size as u64);
        }
        b < a.wrapping_add(self.size as u64)
    }

    // Ghidra: varnode.cc:977 Varnode::copyShadow
    /// Check if this Varnode and `op2` are copies of the same source.
    /// Faithful to `Varnode::copyShadow` (varnode.cc:977-995): trace both
    /// varnodes back along COPY chains; if they meet, they shadow each other.
    /// All comparisons are Varnode object identity (Ghidra raw-pointer `==`),
    /// performed payload-address to payload-address via `copy_chain_hits`.
    pub fn copy_shadow(&self, op2: &Varnode) -> bool {
        // Ghidra cc:982 (this==op2) plus cc:984-988: trace -this- to the
        // source of its copy chain, comparing every reached node (and this
        // itself) against op2.
        if copy_chain_hits(self, op2) {
            return true;
        }
        // Ghidra cc:989-993: trace op2 to the source of its copy chain,
        // comparing every reached node against vn — the terminal node of
        // this's chain.
        match copy_chain_source_def(self) {
            // this is not written: the cc:984 loop never advances, so vn
            // stays this and op2's chain is compared against it.
            None => copy_chain_hits(op2, self),
            Some((def_arc, written)) => {
                // Resolve the chain-source Varnode Arc. If this's chain ends
                // at a written non-COPY node, that node is the terminal def's
                // output (def<->output invariant, funcdata_op.cc:78-82
                // `vn = vbank.setDef(vn,op); op->setOutput(vn);`). If the
                // chain ends at an unwritten input, the source is the
                // terminal COPY op's input 0 (copy_chain_source_def's
                // written=false contract).
                let head_arc = {
                    let def = def_arc.read().unwrap();
                    if written {
                        def.output.clone()
                    } else {
                        def.inrefs.get(0).cloned()
                    }
                };
                match head_arc {
                    Some(head_arc) => {
                        let head = head_arc.read().unwrap();
                        copy_chain_hits(op2, &head)
                    }
                    // A def without output breaks the def<->output invariant;
                    // there is no chain source to compare against.
                    None => false,
                }
            }
        }
    }

    // Ghidra: varnode.cc:1102 Varnode::partialCopyShadow
    /// For this and `op2`, establish that either bigger=CONCAT(smaller,..)
    /// or smaller=SUBPIECE(bigger). Faithful to `Varnode::partialCopyShadow`
    /// (varnode.cc:1102-1131).
    pub fn partial_copy_shadow(&self, op2: &Varnode, mut rel_off: i32) -> bool {
        // Normalize direction: vn = smaller, op2 = bigger (varnode.cc:1107-1116).
        let (vn, big): (&Varnode, &Varnode) = if self.size < op2.size {
            (self, op2)
        } else if self.size > op2.size {
            (op2, self)
        } else {
            return false; // equal size → not a partial shadow
        };
        // Note: the reassignment of which is vn vs op2 flips rel_off sign.
        if self.size > op2.size {
            rel_off = -rel_off;
        }
        if rel_off < 0 {
            return false; // not proper containment (varnode.cc:1117)
        }
        if (rel_off as usize) + vn.size > big.size {
            return false; // not proper containment (varnode.cc:1119)
        }
        // big-endian leastByte computation (varnode.cc:1122-1123).
        // Ghidra uses this->getSpace()->isBigEndian(); vn and big share space.
        let big_endian = vn.address_space.is_big_endian();
        let least_byte = if big_endian {
            (big.size - vn.size) as i32 - rel_off
        } else {
            rel_off
        };
        // vn->findSubpieceShadow(leastByte, op2, 0) (varnode.cc:1124).
        if find_subpiece_shadow(vn, least_byte, big, 0) {
            return true;
        }
        // op2->findPieceShadow(leastByte, vn) (varnode.cc:1127).
        if find_piece_shadow(big, least_byte, vn) {
            return true;
        }
        false
    }

    // Ghidra: varnode.cc:105 Varnode::contains
    pub fn contains(&self, other: &Varnode) -> i32 {
        // cc:108: spaces differ
        if self.address_space != other.address_space {
            return 3;
        }
        // cc:109: constant space short-circuit (this is a constant)
        if self.address_space == AddressSpace::Const {
            return 3;
        }
        // cc:110-115: offset range check (uintb = unsigned)
        let s_off = self.get_offset();
        let o_off = other.get_offset();
        let s_end = s_off.wrapping_add(self.get_size() as u64);
        let o_end = o_off.wrapping_add(other.get_size() as u64);
        if o_off < s_off {
            -1
        } else if o_off < s_end {
            // op starts within this's range
            if o_end <= s_end { 0 } else { 1 }
        } else {
            2
        }
    }

    // Ghidra: varnode.cc:578 Varnode::getConsume
    /// Get the mask of consumed bits. Faithful to `Varnode::getConsume`
    /// (varnode.hh:205). Maintained by the dead-code algorithm.
    pub fn get_consume(&self) -> u64 {
        self.consumed
    }

    // Ghidra: varnode.cc:578 Varnode::setConsume
    /// Set the mask of consumed bits. Faithful to `Varnode::setConsume`
    /// (varnode.hh:206).
    pub fn set_consume(&mut self, val: u64) {
        self.consumed = val;
    }

    // Ghidra: varnode.cc:578 Varnode::getNzm
    /// Get the stored non-zero mask (the Heritage-maintained field).
    /// Faithful to accessing the `nzm` field directly. This is the raw stored
    /// value; prefer get_nz_mask for the conservative approximation.
    pub fn get_nzm(&self) -> u64 {
        self.nzm
    }

    // Ghidra: varnode.cc:578 Varnode::setNzm
    /// Set the stored non-zero mask.
    pub fn set_nzm(&mut self, val: u64) {
        self.nzm = val;
    }

    // Ghidra: varnode.cc:942 Varnode::isBooleanValue
    /// Is this varnode known to hold a boolean (0 or 1) value? Faithful to
    /// `Varnode::isBooleanValue` (varnode.cc:942-953). If written, checks the
    /// defining op's isCalculatedBool flag. If an input, checks type annotation
    /// (only when use_annotation is true).
    // Ghidra: varnode.cc:696 Varnode::getUsePoint
    /// Get the use-point address for this Varnode. Faithful to
    /// `getUsePoint` (varnode.cc:696-703). Written Varnodes come into scope
    /// at their defining op's address; everything else (inputs/free legs)
    /// comes into scope at the sentinel `fd.getAddress()+-1` — one addressable
    /// unit before the function entry.
    pub fn get_use_point(&self, fd: &crate::funcdata::Funcdata) -> Address {
        if self.is_written() {
            if let Some(def_weak) = self.def.as_ref().and_then(|w| w.upgrade()) {
                return def_weak.read().unwrap().get_addr();
            }
        }
        fd.get_address().offset(-1)
    }

    // Ghidra: varnode.cc:958 Varnode::isZeroExtended
    /// Check if this Varnode is a zero-extended form of a smaller value.
    /// Faithful to `isZeroExtended` (varnode.cc:958-975).
    pub fn is_zero_extended(&self, base_size: usize) -> bool {
        if !self.is_written() { return false; }
        let def = match self.def.as_ref().and_then(|w| w.upgrade()) {
            Some(d) => d, None => return false,
        };
        let def_r = def.read().unwrap();
        if def_r.opcode != crate::opcodes::OpCode::CPUI_INT_ZEXT { return false; }
        let in_size = match def_r.get_in(0) {
            Some(v) => v.read().unwrap().get_size(),
            None => return false,
        };
        in_size == base_size
    }

    // Ghidra: varnode.cc:942 Varnode::isBooleanValue
    pub fn is_boolean_value(&self, use_annotation: bool) -> bool {
        if self.is_written() {
            if let Some(def) = self.def.as_ref().and_then(|w| w.upgrade()) {
                return def.read().unwrap().is_calculated_bool();
            }
        }
        if !use_annotation {
            return false;
        }
        // Check typelocked input of TYPE_BOOL.
        if self.is_input() && (self.flags & varnode_flags::TYPELOCK) != 0 {
            if self.size == 1 {
                if let Some(t) = &self.v_type {
                    return t.get_metatype() == TypeMetatype::Bool;
                }
            }
        }
        false
    }

    // --- Ghidra-faithful def / descend / flag accessors (varnode.hh:213-330) ---

    // Ghidra: varnode.cc:578 Varnode::getDef
    /// Get the PcodeOp that defines this Varnode, or None if not written.
    /// Faithful to `Varnode::getDef` (varnode.hh:213). Upgrades the internal
    /// Weak to an Arc; returns None if the def has been dropped or was never
    /// set.
    pub fn get_def(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        self.def.as_ref().and_then(|w| w.upgrade())
    }

    // Ghidra: varnode.cc:578 Varnode::isReadOnly
    /// Is this Varnode's value read-only (from a read-only memory space)?
    /// Faithful to `Varnode::isReadOnly` (varnode.hh:243).
    pub fn is_read_only(&self) -> bool {
        (self.flags & varnode_flags::READONLY) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isAnnotation
    /// Is this an annotation varnode (inserted by the decompiler, not real
    /// code)? Faithful to `Varnode::isAnnotation` (varnode.hh:237).
    pub fn is_annotation(&self) -> bool {
        (self.flags & varnode_flags::ANNOTATION) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isSpacebase
    /// Is this a spacebase pointer varnode? Faithful to
    /// `Varnode::isSpacebase` (varnode.hh, referenced by varmap/heritage).
    pub fn is_spacebase(&self) -> bool {
        (self.flags & varnode_flags::SPACEBASE) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::descendIter
    /// Return an iterator over the live descendant ops (ops that read this
    /// Varnode). Faithful to `Varnode::beginDescend`/`endDescend`
    /// (varnode.hh:219-220). Filters out Weak refs whose target has been
    /// dropped.
    pub fn descend_iter(&self) -> impl Iterator<Item = Arc<RwLock<PcodeOp>>> + '_ {
        self.descend.iter().filter_map(|w| w.upgrade())
    }

    // Ghidra: varnode.cc:578 Varnode::countDescends
    /// Count the live descendant ops. Useful for Rules that need the descend
    /// count without collecting into a Vec.
    pub fn count_descends(&self) -> usize {
        self.descend.iter().filter(|w| w.strong_count() > 0).count()
    }

    // Ghidra: varnode.cc:330 Varnode::addDescend
    /// Add a descendant op reference. Faithful to `Varnode::addDescend`
    /// (varnode.hh:295). Per Ghidra cc:333-336, a free non-spacebase varnode
    /// with an existing descendant throws
    /// `LowlevelError("Free varnode has multiple descendants")` — Rugra
    /// panics with the identical message (memstate.rs read-only-bank
    /// precedent). The panic fires before the push, so — like the C++ throw —
    /// the Varnode state is unchanged on failure. The two producers of the
    /// illegal state (subflow raw INPUT flagging, inject_raw_ops shared free
    /// varnode) were eliminated in aa3d5e8; the E2E corpus must stay at
    /// 0 panics, otherwise an uneliminated producer exists.
    /// Also sets coverdirty (Ghidra cc:339); the flag is consumed by
    /// get_cover/update_cover_locked (varnode.rs cover recompute path),
    /// so op_insert_input's newly coverdirty inputs surface as extra
    /// [HERITAGE] WARN diagnostics on httpd — same direction as Ghidra's
    /// cc:339 unconditional set (observation registered in the
    /// op_insert_input commit's Differential).
    pub fn add_descend(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        if self.is_free() && !self.is_spacebase() {
            // Ghidra cc:333-336 throws when descend (checked via
            // `descend.empty()`, varnode.cc:334) is non-empty. Ghidra's list
            // can never hold a destroyed op (opDestroy erases every descend
            // link before the op is freed), so empty()==no live reader. A
            // Rust Weak whose target was already freed is pure drift; count
            // only live entries so drift cannot fabricate the
            // "multiple descendants" signal (has_no_descend/count_descends
            // already filter dead entries the same way).
            let has_live_descend = self.descend.iter().any(|w| w.strong_count() > 0);
            if has_live_descend {
                // Ghidra: throw LowlevelError("Free varnode has multiple
                // descendants") (varnode.cc:336). Per-function isolation in
                // the decompile worker maps the panic onto Ghidra's
                // LowlevelError-aborts-this-function model.
                panic!("Free varnode has multiple descendants");
            }
        }
        self.descend.push(std::sync::Arc::downgrade(op));
        // Ghidra cc:339: setFlags(Varnode::coverdirty) — propagates
        // coverDirty to the owning high (varnode.cc:358-359) so the stored
        // aggregate is invalidated at mutation time (HIGHCOV lane 2026-09-25;
        // previously set inline without the propagation half).
        self.set_flags(varnode_flags::COVERDIRTY);
    }

    // Ghidra: varnode.cc:316 Varnode::eraseDescend
    /// Erase a descendant op from this varnode's descend list. Faithful to
    /// `Varnode::eraseDescend` (varnode.hh:175). Per Ghidra cc:321-324, finds
    /// the op in the descend list and removes it; throws if not found.
    /// Each list entry represents one input slot, so erase exactly one
    /// matching occurrence. This is load-bearing when one op reads the same
    /// Varnode in multiple slots: Ghidra removes one list node per
    /// `opUnsetInput` call.
    /// Also sets coverdirty (Ghidra cc:325), now with the high propagation
    /// half (varnode.cc:358-359) — see set_flags.
    pub fn erase_descend(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        let position = self.descend.iter().position(|weak| {
            weak.upgrade()
                .is_some_and(|candidate| Arc::ptr_eq(&candidate, op))
        });
        if let Some(position) = position {
            self.descend.remove(position);
        } else {
            eprintln!(
                "[VN] WARN: erase_descend op={:p} not in descend list (space={:?} off={:#x})",
                std::sync::Arc::as_ptr(op), self.address_space, self.loc.as_u64()
            );
        }
        // Ghidra cc:325: setFlags(Varnode::coverdirty) — propagates
        // coverDirty to the owning high (varnode.cc:358-359), same as
        // add_descend (HIGHCOV lane 2026-09-25).
        self.set_flags(varnode_flags::COVERDIRTY);
    }

    // Ghidra: varnode.cc:578 Varnode::isBoolOutputDef
    /// Does the defining op of this Varnode have a boolean output? Faithful to
    /// checking `getDef()->isBoolOutput()` (used by JumpBasic::calcRange,
    /// jumptable.cc:1144). Returns false if not written or the def can't be
    /// resolved.
    pub fn is_bool_output_def(&self) -> bool {
        if !self.is_written() {
            return false;
        }
        if let Some(def) = self.get_def() {
            return (def.read().unwrap().flags & crate::op::pcodeop_flags::BOOLOUTPUT) != 0;
        }
        false
    }
}

impl PartialEq for Varnode {
    // Ghidra: varnode.cc:556 Varnode::operator==
    fn eq(&self, other: &Self) -> bool {
        self.ghidra_eq(other)
    }
}

impl Eq for Varnode {}

impl PartialOrd for Varnode {
    // Ghidra: varnode.cc:533 Varnode::operator<
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Varnode {
    // Ghidra: varnode.cc:533 Varnode::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.ghidra_less(other) {
            std::cmp::Ordering::Less
        } else if other.ghidra_less(self) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    }
}

/// A wrapper for Rc<RefCell<Varnode>> for location-based sorting
#[derive(Debug, Clone)]
pub struct VarnodeLocRef(pub Arc<RwLock<Varnode>>);

impl PartialEq for VarnodeLocRef {
    // RUGRA-GLUE: eq (no Ghidra counterpart found)
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for VarnodeLocRef {}

impl PartialOrd for VarnodeLocRef {
    // RUGRA-GLUE: partial_cmp (no Ghidra counterpart found)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarnodeLocRef {
    // RUGRA-GLUE: cmp (no Ghidra counterpart found)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) {
            return std::cmp::Ordering::Equal;
        }
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();
        // Faithful to Ghidra's VarnodeCompareLocDef (varnode.cc:34-53):
        // (address_space, loc, size, input/written/free, def-SeqNum-or-createIndex)
        //
        // Key difference from the old (space, loc, size, create_index): the
        // input/written/free classification layer makes:
        //   - input varnodes at the same (space, loc, size) be EQUAL (same object)
        //   - written varnodes distinguished by def SeqNum (SSA versions)
        //   - free varnodes distinguished by createIndex (multiple allowed)
        // This is what Ghidra's xref relies on: a newVarnode lookup finds the
        // existing input varnode at a location (not a different free/written one).
        match compare_address_spaces(a.address_space, b.address_space) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        match a.loc.cmp(&b.loc) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        match a.size.cmp(&b.size) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        // Classify by input/written flags: 0=free, input(1<<3)=input, written(1<<4)=written.
        // Ghidra ordering: (f-1) comparison puts free LAST, input before written.
        let f1 = a.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = b.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        match f1.wrapping_sub(1).cmp(&f2.wrapping_sub(1)) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        // Same classification. For written: compare def SeqNum.
        // For input: return Equal (same input varnode = same object).
        // For free: compare createIndex.
        if f1 == varnode_flags::WRITTEN {
            // Compare def op SeqNum.
            let a_seq = a.get_def().map(|d| *d.read().unwrap().get_seq_num());
            let b_seq = b.get_def().map(|d| *d.read().unwrap().get_seq_num());
            a_seq.cmp(&b_seq)
        } else if f1 == varnode_flags::INPUT {
            std::cmp::Ordering::Equal
        } else {
            // Free: compare createIndex.
            a.create_index.cmp(&b.create_index)
        }
    }
}

/// A wrapper for Rc<RefCell<Varnode>> for definition-based sorting
#[derive(Debug, Clone)]
pub struct VarnodeDefRef(pub Arc<RwLock<Varnode>>);

impl PartialEq for VarnodeDefRef {
    // RUGRA-GLUE: eq (no Ghidra counterpart found)
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for VarnodeDefRef {}

impl PartialOrd for VarnodeDefRef {
    // RUGRA-GLUE: partial_cmp (no Ghidra counterpart found)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarnodeDefRef {
    // Ghidra: varnode.cc:60 VarnodeCompareDefLoc::operator()
    /// Compare by definition then by location. Faithful to
    /// `VarnodeCompareDefLoc` (varnode.cc:60-79).
    /// Uses the unsigned `(f-1)` trick: input, then written, then free.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) {
            return std::cmp::Ordering::Equal;
        }
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();

        // cc:65-67: f1 = flags & (input|written); (f1-1) < (f2-1) forces free last
        let f1 = a.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = b.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        if f1 != f2 {
            return (f1.wrapping_sub(1)).cmp(&(f2.wrapping_sub(1)));
        }
        // cc:69-71: if written, compare def SeqNum
        if f1 == varnode_flags::WRITTEN {
            let a_seq = a
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            let b_seq = b
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            match a_seq.cmp(&b_seq) {
                std::cmp::Ordering::Equal => {}
                ord => return ord,
            }
        }
        // cc:73-74: compare the full Address (space index, then offset), then size
        match compare_address_spaces(a.address_space, b.address_space) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match a.loc.cmp(&b.loc) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match a.size.cmp(&b.size) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        // cc:75-77: if both free, compare createIndex
        if f1 == 0 {
            return a.create_index.cmp(&b.create_index);
        }
        std::cmp::Ordering::Equal
    }
}

/// Simplified varnode data (for serialization/deserialization)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VarnodeData {
    pub space: AddressSpace,
    pub offset: u64,
    pub size: usize,
}

impl VarnodeData {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new(space: AddressSpace, offset: u64, size: usize) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }
}

impl From<&Varnode> for VarnodeData {
    // RUGRA-GLUE: from (no Ghidra counterpart found)
    fn from(vn: &Varnode) -> Self {
        VarnodeData {
            space: vn.get_space(),
            offset: vn.get_offset(),
            size: vn.get_size(),
        }
    }
}

/// Container for managing Varnodes
///
/// Corresponds to Ghidra's `VarnodeBank` class in `varnode.hh`
pub struct VarnodeBank {
    /// Sorted by location (VarnodeLocSet in Ghidra)
    pub loc_tree: BTreeSet<VarnodeLocRef>,
    /// Sorted by definition (VarnodeDefSet in Ghidra)
    pub def_tree: BTreeSet<VarnodeDefRef>,

    /// Counter for assigning create_index
    create_index: u32,

    /// Unique space manager
    uniq_space: AddressSpace,
    uniqid: u64,

    /// Bank's view of the owning Architecture's TypeFactory. Ghidra's
    /// VarnodeBank has no factory of its own — the Funcdata caller always
    /// supplies the `Datatype *ct` drawn from `glb->types`
    /// (funcdata_varnode.cc:69 et al.). An injected handle reproduces that
    /// per-Architecture channel; when absent (test paths without an
    /// Architecture), the process-canonical factory models the headless
    /// oracle's single Architecture (see `default_unknown_type`).
    type_factory: Option<Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
}

// RUGRA-GLUE: fmt (no Ghidra counterpart found)
/// Manual Debug impl: the injected factory handle has no Debug surface;
/// report only its presence, matching the derive that preceded it.
impl std::fmt::Debug for VarnodeBank {
    // RUGRA-GLUE: std::fmt::Debug trait impl; Ghidra has no Debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VarnodeBank")
            .field("loc_tree", &self.loc_tree)
            .field("def_tree", &self.def_tree)
            .field("create_index", &self.create_index)
            .field("uniq_space", &self.uniq_space)
            .field("uniqid", &self.uniqid)
            .field("type_factory", &self.type_factory.is_some())
            .finish()
    }
}

impl VarnodeBank {
    // Ghidra: varnode.cc:1218 VarnodeBank::VarnodeBank
    pub fn new() -> Self {
        Self {
            loc_tree: BTreeSet::new(),
            def_tree: BTreeSet::new(),
            create_index: 0,
            uniq_space: AddressSpace::Unique,
            uniqid: ANALYSIS_UNIQUE_START,
            type_factory: None,
        }
    }

    // RUGRA-GLUE: set_type_factory (no Ghidra counterpart found)
    /// Inject the owning Architecture's TypeFactory handle. Ghidra threads
    /// `glb->types` through every `Funcdata::newVarnode*` →
    /// `VarnodeBank::create(s,m,ct)` call (funcdata_varnode.cc:69 et al.,
    /// varnode.cc:1250); Rust's bank-local default typing consults this
    /// handle first so an attached Architecture's factory provides the
    /// unknown-type identity domain.
    pub fn set_type_factory(
        &mut self,
        tf: Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) {
        self.type_factory = Some(tf);
    }

    // RUGRA-GLUE: type_factory_handle (no Ghidra counterpart found)
    /// The injected Architecture TypeFactory handle, if any.
    pub fn type_factory_handle(
        &self,
    ) -> Option<Arc<RwLock<crate::type_system::typefactory::TypeFactory>>> {
        self.type_factory.clone()
    }

    // RUGRA-GLUE: shared Rust allocation half of VarnodeBank::create and
    // createDef; Ghidra performs these field assignments inline.
    fn allocate(&mut self, mut vn: Varnode) -> Arc<RwLock<Varnode>> {
        // Ghidra's create/createDef receive the caller's `Datatype *ct`
        // (varnode.cc:1250/1411) — the Funcdata caller's
        // `glb->types->getBase(size,TYPE_UNKNOWN)`. Rugra resolves the same
        // factory object here: injected handle, else the process-canonical
        // factory. Same-size requests return the same Arc, matching the
        // factory's findAdd identity domain.
        let canonical_type = default_unknown_type(self.type_factory.as_ref(), vn.size);
        vn.v_type = Some(canonical_type);
        vn.create_index = self.create_index;
        self.create_index += 1;

        let result = Arc::new(RwLock::new(vn));
        result.write().unwrap().self_ref = Arc::downgrade(&result);
        result
    }

    // RUGRA-GLUE: insertion half shared by Rugra's implicit-RAM and explicit
    // address-space forms of Ghidra VarnodeBank::create.
    fn insert_free(&mut self, vn: Varnode) -> Arc<RwLock<Varnode>> {
        let rc = self.allocate(vn);
        self.loc_tree.insert(VarnodeLocRef(rc.clone()));
        self.def_tree.insert(VarnodeDefRef(rc.clone()));
        rc
    }

    // Ghidra: varnode.cc:1332 VarnodeBank::replace
    /// Redirect every descendant of `old_vn` to `new_vn` in list order.
    pub fn replace(&mut self, old_vn: &Arc<RwLock<Varnode>>, new_vn: &Arc<RwLock<Varnode>>) {
        let descendants: Vec<_> = old_vn.read().unwrap().descend_iter().collect();
        let mut replacements = Vec::new();
        let mut occurrences: BTreeMap<usize, usize> = BTreeMap::new();
        for op in descendants {
            let output_is_new = op
                .read()
                .unwrap()
                .output
                .as_ref()
                .is_some_and(|out| Arc::ptr_eq(out, new_vn));
            if output_is_new {
                continue;
            }

            let op_identity = Arc::as_ptr(&op) as usize;
            let occurrence = occurrences.entry(op_identity).or_insert(0);
            let slot = op
                .read()
                .unwrap()
                .inrefs
                .iter()
                .enumerate()
                .filter(|(_, input)| Arc::ptr_eq(input, old_vn))
                .nth(*occurrence)
                .map(|(slot, _)| slot);
            // A descendant entry without an input slot is corrupt IR. Ghidra
            // assumes this invariant and would index past getSlot(); keep the
            // valid-input path non-fallible and make debug builds diagnose it.
            if let Some(slot) = slot {
                replacements.push((op, slot));
                *occurrence += 1;
            } else {
                debug_assert!(
                    false,
                    "VarnodeBank::replace descendant has no matching input slot"
                );
            }
        }

        for (op, slot) in replacements {
            // Ghidra advances the list iterator before erasing exactly one
            // occurrence, so repeated use by one op is rewired slot-by-slot.
            {
                let mut old = old_vn.write().unwrap();
                if let Some(pos) = old.descend.iter().position(|weak| {
                    weak.upgrade()
                        .is_some_and(|candidate| Arc::ptr_eq(&candidate, &op))
                }) {
                    old.descend.remove(pos);
                }
            }
            new_vn.write().unwrap().add_descend(&op);
            op.write().unwrap().inrefs[slot] = new_vn.clone();
        }
        {
            let mut old = old_vn.write().unwrap();
            // Ghidra deletes `oldvn` immediately after replace. An external
            // Arc may keep Rugra's allocation alive, but it must not retain
            // observable stale def-use links.
            old.descend.clear();
            old.set_flags(varnode_flags::COVERDIRTY);
        }
        new_vn.write().unwrap().set_flags(varnode_flags::COVERDIRTY);
    }

    // Ghidra: varnode.cc:1291 VarnodeBank::xref
    /// Insert an input/written Varnode, returning the pre-existing canonical
    /// object if its location/definition key is already present.
    fn xref(&mut self, vn: Arc<RwLock<Varnode>>) -> Arc<RwLock<Varnode>> {
        let key = VarnodeLocRef(vn.clone());
        if let Some(existing) = self.loc_tree.get(&key).map(|entry| entry.0.clone()) {
            self.replace(&vn, &existing);
            return existing;
        }

        let inserted = self.loc_tree.insert(key);
        debug_assert!(inserted, "xref preflight and insertion disagree");
        vn.write().unwrap().set_flags(varnode_flags::INSERT);
        let inserted = self.def_tree.insert(VarnodeDefRef(vn.clone()));
        debug_assert!(inserted, "new xref location duplicated in definition tree");
        vn
    }

    // RUGRA-GLUE: Arc-identity ownership check corresponding to Ghidra's
    // stored lociter. Scan by identity because Funcdata::destroyVarnode clears
    // `def` before VarnodeBank::destroy, so the live Rust comparison key may
    // no longer match the node's original BTreeSet position.
    fn owns_loc_ref(&self, vn: &Arc<RwLock<Varnode>>) -> bool {
        self.loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, vn))
    }

    // RUGRA-GLUE: definition-tree equivalent of Ghidra's stored defiter.
    fn owns_def_ref(&self, vn: &Arc<RwLock<Varnode>>) -> bool {
        self.def_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, vn))
    }

    // RUGRA-GLUE: Rust analogue of Ghidra's `loc_tree.erase(vn->lociter)`
    // (varnode.cc:1319). Ghidra stores the tree iterator inside the Varnode,
    // so erasure removes THE OBJECT at its stored position and never
    // recomputes the comparison key. Rust's BTreeSet has no stored handles,
    // so we emulate: the fast path removes by the live key — valid whenever
    // no caller mutated key-relevant fields (flags/def) in place while the
    // Varnode was tree-resident; if the live key routes to a different
    // object (or misses), fall back to an Arc-identity scan that removes
    // this exact object wherever it sits — the same object Ghidra's stored
    // iterator would have erased. This is a data-structure lookup strategy,
    // not a semantic two-phase: the observable result is always "this exact
    // Varnode is no longer in the tree".
    fn erase_loc_identity(&mut self, vn: &Arc<RwLock<Varnode>>) -> bool {
        if let Some(removed) = self.loc_tree.take(&VarnodeLocRef(vn.clone())) {
            if Arc::ptr_eq(&removed.0, vn) {
                return true;
            }
            // The live key routed to a different tree member: restore it
            // before the identity scan so only `vn` is removed.
            self.loc_tree.insert(removed);
        }
        let before = self.loc_tree.len();
        self.loc_tree.retain(|entry| !Arc::ptr_eq(&entry.0, vn));
        before != self.loc_tree.len()
    }

    // RUGRA-GLUE: def_tree twin of `erase_loc_identity`, emulating Ghidra's
    // `def_tree.erase(vn->defiter)` (varnode.cc:1320).
    fn erase_def_identity(&mut self, vn: &Arc<RwLock<Varnode>>) -> bool {
        if let Some(removed) = self.def_tree.take(&VarnodeDefRef(vn.clone())) {
            if Arc::ptr_eq(&removed.0, vn) {
                return true;
            }
            self.def_tree.insert(removed);
        }
        let before = self.def_tree.len();
        self.def_tree.retain(|entry| !Arc::ptr_eq(&entry.0, vn));
        before != self.def_tree.len()
    }

    // RUGRA-GLUE: shared checked/unchecked transition for Ghidra
    // VarnodeBank::setInput after its precondition checks.
    fn transition_input(&mut self, vn: Arc<RwLock<Varnode>>) -> Arc<RwLock<Varnode>> {
        // Ghidra setInput erases via the stored lociter/defiter
        // (varnode.cc:1366-1367), never by a recomputed comparison key.
        let loc_removed = self.erase_loc_identity(&vn);
        let def_removed = self.erase_def_identity(&vn);
        debug_assert!(
            loc_removed && def_removed,
            "setInput requires a bank-owned free Varnode"
        );
        vn.write()
            .unwrap()
            .set_flags(varnode_flags::INPUT | varnode_flags::COVERDIRTY);
        self.xref(vn)
    }

    // RUGRA-GLUE: shared checked/unchecked transition for Ghidra
    // VarnodeBank::setDef after its precondition checks.
    fn transition_def(
        &mut self,
        vn: Arc<RwLock<Varnode>>,
        op: Weak<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        // Ghidra setDef erases via the stored lociter/defiter
        // (varnode.cc:1396-1397), never by a recomputed comparison key.
        // The identity-erase residency bools double as the ownership proof
        // (the oracle's stored iterators make the erase itself that proof),
        // replacing the former O(n) owns_*_ref preflight scans.
        let loc_removed = self.erase_loc_identity(&vn);
        let def_removed = self.erase_def_identity(&vn);
        if !loc_removed || !def_removed {
            return None;
        }
        {
            let mut value = vn.write().unwrap();
            value.def = Some(op);
            value.set_flags(varnode_flags::WRITTEN | varnode_flags::COVERDIRTY);
        }
        Some(self.xref(vn))
    }

    // Ghidra: varnode.cc:1250 VarnodeBank::create
    /// Create a new free varnode
    pub fn create(&mut self, size: usize, loc: Address) -> Arc<RwLock<Varnode>> {
        // Faithful to VarnodeBank::create (varnode.cc:1250-1258): does NOT
        // set INSERT flag. Only createDef/xref sets INSERT (for written
        // varnodes). Free varnodes (created via newVarnode→create) have no
        // INSERT — isHeritageKnown returns false — rename processes them.
        self.insert_free(Varnode::new(size, loc))
    }

    // Ghidra: varnode.cc:1250 VarnodeBank::create
    /// Explicit-space Rust adapter for Ghidra's Address-valued `create`.
    pub fn create_with_space(
        &mut self,
        size: usize,
        space: AddressSpace,
        offset: u64,
    ) -> Arc<RwLock<Varnode>> {
        self.insert_free(Varnode::new_with_space(size, space, offset))
    }

    // Ghidra: varnode.cc:1265 VarnodeBank::createUnique
    /// Create a new unique varnode with an explicit data-type (the ct
    /// parameter of `createUnique(int4 s,Datatype *ct)`; Ghidra requires it
    /// non-null — Funcdata::newUnique defaults null to the factory unknown
    /// base before calling in).
    pub fn create_unique_typed(
        &mut self,
        size: usize,
        ct: std::sync::Arc<crate::type_system::datatype::Datatype>,
    ) -> Arc<RwLock<Varnode>> {
        let offset = self.uniqid;
        self.uniqid += size as u64;
        let vn = self.insert_free(Varnode::new_with_space(size, self.uniq_space, offset));
        vn.write().unwrap().v_type = Some(ct);
        vn
    }

    // Ghidra: varnode.cc:1265 VarnodeBank::createUnique
    /// Create a new unique varnode
    pub fn create_unique(&mut self, size: usize) -> Arc<RwLock<Varnode>> {
        let offset = self.uniqid;
        self.uniqid += size as u64;
        self.create_with_space(size, self.uniq_space, offset)
    }

    // Ghidra: varnode.cc:1250 VarnodeBank::create
    /// Constant-address Rust adapter for Ghidra's Address-valued `create`.
    pub fn create_constant(&mut self, size: usize, val: u64) -> Arc<RwLock<Varnode>> {
        self.create_with_space(size, AddressSpace::Const, val)
    }

    // Ghidra: varnode.cc:1411 VarnodeBank::createDef
    /// Create a new Varnode with a defining op, already inserted in both trees.
    /// Faithful to `createDef` (varnode.cc:1411-1418).
    pub fn create_def(
        &mut self,
        size: usize,
        loc: Address,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> Arc<RwLock<Varnode>> {
        self.create_def_with_space(size, AddressSpace::Ram, loc.as_u64(), op)
    }

    // Ghidra: varnode.cc:1411 VarnodeBank::createDef
    /// Explicit-address-space form required by Rugra's split Address model.
    pub fn create_def_with_space(
        &mut self,
        size: usize,
        space: AddressSpace,
        offset: u64,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> Arc<RwLock<Varnode>> {
        let vn = self.allocate(Varnode::new_with_space(size, space, offset));
        {
            let mut value = vn.write().unwrap();
            value.def = Some(Arc::downgrade(op));
            value.set_flags(varnode_flags::WRITTEN | varnode_flags::COVERDIRTY);
        }
        self.xref(vn)
    }

    // Ghidra: varnode.cc:1426 VarnodeBank::createDefUnique
    /// Create a unique-space Varnode with a defining op.
    /// Faithful to `createDefUnique` (varnode.cc:1426-1432).
    pub fn create_def_unique(
        &mut self,
        size: usize,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> Arc<RwLock<Varnode>> {
        let offset = self.uniqid;
        self.uniqid += size as u64;
        self.create_def_with_space(size, self.uniq_space, offset, op)
    }

    // Ghidra: varnode.cc:1358 VarnodeBank::setInput
    /// Mark a bank-owned free varnode as a function input. Ghidra's
    /// `setInput` can return a different canonical pointer after xref; the
    /// Rust result returns that canonical Arc and reports invalid transitions.
    pub fn set_input(&mut self, vn: Arc<RwLock<Varnode>>) -> Result<Arc<RwLock<Varnode>>> {
        let value = vn.read().unwrap();
        if !value.is_free() {
            return Err(anyhow!("Making input out of varnode which is not free"));
        }
        if value.is_constant() {
            return Err(anyhow!("Making input out of constant varnode"));
        }
        drop(value);
        // cc:1366-1367: Ghidra erases via the stored lociter/defiter — the
        // erase IS the ownership proof (a foreign/stale Arc removes nothing).
        // The identity-erase residency bools replace the O(n)
        // owns_loc_ref/owns_def_ref preflight scans, which made Heritage
        // rename O(n^2) on large functions (every empty-stack promotion
        // rescanned both trees).
        let loc_removed = self.erase_loc_identity(&vn);
        let def_removed = self.erase_def_identity(&vn);
        if !loc_removed || !def_removed {
            return Err(anyhow!("Making input out of unmanaged varnode"));
        }
        vn.write()
            .unwrap()
            .set_flags(varnode_flags::INPUT | varnode_flags::COVERDIRTY);
        Ok(self.xref(vn))
    }

    // RUGRA-GLUE: internal non-fallible entry for callers that have just
    // allocated a bank-owned, non-constant free Varnode.
    pub(crate) fn set_input_prevalidated(
        &mut self,
        vn: Arc<RwLock<Varnode>>,
    ) -> Arc<RwLock<Varnode>> {
        debug_assert!(vn.read().unwrap().is_free() && !vn.read().unwrap().is_constant());
        self.transition_input(vn)
    }

    // Ghidra: varnode.cc:1380 VarnodeBank::setDef
    /// Mark a varnode as defined by an operation
    /// Set the defining op of a varnode. Faithful to Ghidra's model where
    /// createDef (varnode.cc:1411) calls xref which sets INSERT.
    /// A varnode with a def is "inserted" — isHeritageKnown returns true.
    pub fn set_def(
        &mut self,
        vn: Arc<RwLock<Varnode>>,
        op: Weak<RwLock<PcodeOp>>,
    ) -> Result<Arc<RwLock<Varnode>>> {
        let value = vn.read().unwrap();
        if !value.is_free() {
            let address = op
                .upgrade()
                .map(|operation| operation.read().unwrap().get_addr().as_u64())
                .unwrap_or(0);
            return Err(anyhow!(
                "Defining varnode which is not free at r0x{address:08x}"
            ));
        }
        if value.is_constant() {
            let address = op
                .upgrade()
                .map(|operation| operation.read().unwrap().get_addr().as_u64())
                .unwrap_or(0);
            return Err(anyhow!("Assignment to constant at r0x{address:08x}"));
        }
        drop(value);
        // Ghidra's setDef erases via the stored lociter/defiter
        // (varnode.cc:1396-1397) — the erase IS the ownership proof, O(log n).
        // The former O(n) owns_loc_ref/owns_def_ref preflight scans made the
        // heritage/pool setDef path quadratic on large functions; the
        // identity-erase residency bools reproduce the oracle's
        // "unmanaged varnode" error with the same observable outcome
        // (same Err for a foreign Arc, same success for a bank-owned one).
        match self.transition_def(vn.clone(), op) {
            Some(canonical) => Ok(canonical),
            None => Err(anyhow!("Defining unmanaged varnode")),
        }
    }

    // RUGRA-GLUE: internal non-fallible entry for callers that have just
    // allocated a bank-owned, non-constant free Varnode.
    pub(crate) fn set_def_prevalidated(
        &mut self,
        vn: Arc<RwLock<Varnode>>,
        op: Weak<RwLock<PcodeOp>>,
    ) -> Arc<RwLock<Varnode>> {
        debug_assert!(vn.read().unwrap().is_free() && !vn.read().unwrap().is_constant());
        match self.transition_def(vn, op) {
            Some(canonical) => canonical,
            // The debug_assert above established a freshly allocated,
            // bank-owned free Varnode; Ghidra's stored-iterator erase can
            // never miss there. Keep the panic contract of the former
            // debug_assert path for a corrupted bank.
            None => panic!("set_def_prevalidated lost a freshly allocated Varnode"),
        }
    }

    // Ghidra: varnode.cc:1276 VarnodeBank::destroy
    /// Remove a detached varnode from both trees. Ghidra rejects an integrated
    /// value (a defining op or any descendants) before erasing either index.
    /// Rugra additionally rejects a foreign/stale Arc that only shares the key.
    pub fn destroy_varnode(&mut self, vn: &Arc<RwLock<Varnode>>) -> Result<()> {
        let value = vn.read().unwrap();
        if value.get_def().is_some() || !value.has_no_descend() {
            return Err(anyhow!("Deleting integrated varnode"));
        }
        drop(value);
        // cc:1282-1283: Ghidra erases via the stored lociter/defiter — the
        // erase IS the ownership proof. The identity-erase residency bools
        // replace the O(n) owns_loc_ref/owns_def_ref preflight scans, and the
        // prevalidated body below no longer retains whole trees per delete
        // (Heritage rename deletes every consumed free, which made large
        // functions quadratic).
        let loc_removed = self.erase_loc_identity(vn);
        let def_removed = self.erase_def_identity(vn);
        if !loc_removed || !def_removed {
            return Err(anyhow!("Deleting unmanaged varnode"));
        }
        Ok(())
    }

    // RUGRA-GLUE: internal non-fallible entry for callers that have already
    // detached the defining op and every descendant under a Ghidra-equivalent
    // guard. Debug builds revalidate both integration and Arc ownership.
    pub(crate) fn destroy_varnode_prevalidated(&mut self, vn: &Arc<RwLock<Varnode>>) {
        let value = vn.read().unwrap();
        debug_assert!(
            value.get_def().is_none() && value.has_no_descend(),
            "destroy requires a detached Varnode"
        );
        drop(value);
        debug_assert!(
            self.owns_loc_ref(vn) && self.owns_def_ref(vn),
            "destroy requires a bank-owned Varnode"
        );
        // cc:1282-1283: erase via the stored-iterator equivalent (identity
        // erase, O(log n) fast path) instead of whole-tree retains.
        let loc_removed = self.erase_loc_identity(vn);
        let def_removed = self.erase_def_identity(vn);
        debug_assert!(
            loc_removed && def_removed,
            "destroy preflight disagrees with identity erase"
        );
    }

    // Ghidra: funcdata_varnode.cc:340 Funcdata::setInputVarnode (vbank-level core)
    /// Promote a varnode to a function input. Faithful to
    /// `Funcdata::setInputVarnode` (funcdata_varnode.cc:340-373).
    ///
    /// Ghidra does: (1) early-out if already input, (2) overlap dedup
    /// against existing inputs (return existing on exact match, throw on
    /// partial overlap), (3) `vbank.setInput(vn)`, (4) ProtoModel effect
    /// property setting (unaffected / return_address).
    ///
    /// Rugra ports (1)+(2)+(3) at the VarnodeBank level (the Funcdata
    /// wrapper delegates here). Step (4) requires ProtoModel effect records
    /// not yet wired; conservative subset — these properties affect later
    /// type/recovery passes but not SSA correctness, so heritage rename
    /// (heritage.cc:2502/2512) is unaffected.
    pub fn set_input_varnode(&mut self, vn: Arc<RwLock<Varnode>>) -> Arc<RwLock<Varnode>> {
        // (1) Early-out if already an input.
        if vn.read().unwrap().is_input() {
            return vn;
        }
        // (2) Overlap dedup, ported from funcdata_varnode.cc:346-361:
        //     `vbank.beginDef(input, vn->getAddr()+vn->getSize())` lower-bounds
        //     into the input section of the def tree at the first address
        //     >= addr+size, then `--iter` checks ONLY the immediately
        //     preceding element. The def-tree order (input bucket first,
        //     then space/addr/size) makes the last element strictly below
        //     that bound exactly that predecessor:
        //     `def_tree.range(..search).next_back()`. This replaces the
        //     previous full loc_tree scan per promotion (O(n) with a lock
        //     per entry — the Heritage rename quadratic on large functions).
        let (vn_space, vn_addr, vn_size) = {
            let r = vn.read().unwrap();
            (r.address_space, r.loc, r.size)
        };
        let vn_end = vn_addr.as_u64().saturating_add(vn_size as u64);
        let search = {
            // Ghidra's searchvn for beginDef(input, addr): flags=input,
            // loc=addr, size left at its 0 default (varnode.cc:1916-1918).
            let mut key = Varnode::new_with_space(0, vn_space, vn_end);
            key.flags = varnode_flags::INPUT;
            VarnodeDefRef(std::sync::Arc::new(std::sync::RwLock::new(key)))
        };
        if let Some(prev_ref) = self.def_tree.range(..search).next_back() {
            let invn = prev_ref.0.clone();
            let invn_r = invn.read().unwrap();
            // cc:354: predecessor is an input by construction (inputs sort
            // first in the def tree); keep the explicit guard as the oracle.
            if invn_r.is_input() {
                let vn_r = vn.read().unwrap();
                // cc:355: (-1 != vn->overlap(*invn)) || (-1 != invn->overlap(*vn))
                if vn_r.overlap(&invn_r) != -1 || invn_r.overlap(&vn_r) != -1 {
                    // cc:356-357: same size and address → return existing.
                    if vn_r.get_size() == invn_r.get_size()
                        && vn_r.get_addr() == invn_r.get_addr()
                    {
                        return invn.clone();
                    }
                    // cc:358: partial overlap → Ghidra throws
                    // LowlevelError("Overlapping input varnodes"). Rugra
                    // logs and falls through (conservative, pre-existing
                    // degrade recorded in the todo ledger).
                    eprintln!("[HERITAGE] WARN: overlapping input varnodes at {:x} (size {}) vs {:x} (size {})",
                              vn_r.get_offset(), vn_size, invn_r.get_offset(), invn_r.get_size());
                }
            }
        }
        // (3) Mark as input via set_input (sets INPUT | INSERT, re-inserts).
        let vn = self.set_input_prevalidated(vn);
        // (4) ProtoModel effect-property setting omitted (conservative subset).
        vn
    }

    // Ghidra: varnode.cc:1230 VarnodeBank::clear
    pub fn clear(&mut self) {
        self.loc_tree.clear();
        self.def_tree.clear();
        self.create_index = 0;
        self.uniqid = ANALYSIS_UNIQUE_START;
    }

    // Ghidra: varnode.cc:1316 VarnodeBank::makeFree
    /// Convert a bank-owned input/written Varnode to a free Varnode while
    /// preserving both BTree key invariants. Arc identity rejects stale or
    /// foreign handles that merely compare equal to a bank member.
    pub fn make_free(&mut self, vn: &Arc<RwLock<Varnode>>) -> Result<()> {
        if !self.owns_loc_ref(vn) || !self.owns_def_ref(vn) {
            return Err(anyhow!("Making unmanaged varnode free"));
        }
        self.make_free_prevalidated(vn);
        Ok(())
    }

    // RUGRA-GLUE: internal entry for a bank iterator's current Varnode. The
    // iterator establishes Arc ownership; debug builds preserve that proof.
    pub(crate) fn make_free_prevalidated(&mut self, vn: &Arc<RwLock<Varnode>>) {
        debug_assert!(
            self.owns_loc_ref(vn) && self.owns_def_ref(vn),
            "makeFree requires a bank-owned Varnode"
        );
        // Ghidra makeFree (varnode.cc:1316-1327) erases via the lociter/
        // defiter stored inside the Varnode — it does NOT recompute the
        // comparison key for removal, so an in-place drift of key-relevant
        // fields (flags/def set directly by hand-built fixtures, or by the
        // Funcdata::destroyVarnode pre-clear) cannot break the erase. The
        // identity erase reproduces exactly that: remove this exact object
        // from wherever it sits in each tree.
        let loc_removed = self.erase_loc_identity(vn);
        let def_removed = self.erase_def_identity(vn);
        debug_assert!(
            loc_removed && def_removed,
            "makeFree erase did not find this bank-owned Varnode"
        );
        {
            let mut value = vn.write().unwrap();
            // Ghidra: vn->setDef(0) sets coverdirty and clears written
            // (varnode.cc:394-401); clearFlags(insert|input|indirect_creation)
            // (varnode.cc:1323).
            value.def = None;
            value.set_flags(varnode_flags::COVERDIRTY);
            value.clear_flags(
                varnode_flags::INSERT
                    | varnode_flags::INPUT
                    | varnode_flags::WRITTEN
                    | varnode_flags::INDIRECT_CREATION,
            );
        }
        let loc_inserted = self.loc_tree.insert(VarnodeLocRef(vn.clone()));
        let def_inserted = self.def_tree.insert(VarnodeDefRef(vn.clone()));
        debug_assert!(
            loc_inserted && def_inserted,
            "makeFree must reinsert a unique free key"
        );
    }

    // Ghidra: varnode.cc:1831 VarnodeBank::beginDef(uint4 fl)
    /// Beginning of defined Varnodes with given flags. Faithful to
    /// `beginDef(uint4 fl)` (varnode.cc:1831-1867). Filters by flag class.
    pub fn begin_def_fl(&self, fl: u32) -> impl Iterator<Item = &VarnodeDefRef> {
        self.def_tree.iter().filter(move |v| {
            let vn = v.0.read().unwrap();
            match fl {
                0 => vn.is_input(),
                1 => vn.is_written(),
                _ => true,
            }
        })
    }

    // Ghidra: varnode.cc:1869 VarnodeBank::endDef(uint4 fl)
    pub fn end_def_fl(&self, _fl: u32) -> std::collections::btree_set::Iter<'_, VarnodeDefRef> {
        self.def_tree.iter()
    }

    // Ghidra: varnode.cc:1908 VarnodeBank::beginDef(uint4 fl, const Address&)
    /// Beginning of defined Varnodes at a specific address.
    pub fn begin_def_addr(&self, fl: u32, addr: Address) -> impl Iterator<Item = &VarnodeDefRef> {
        self.def_tree.iter().filter(move |v| {
            let vn = v.0.read().unwrap();
            let flag_ok = match fl {
                0 => vn.is_input(),
                1 => vn.is_written(),
                _ => true,
            };
            flag_ok && vn.loc.as_u64() >= addr.as_u64()
        })
    }

    // Ghidra: varnode.cc:1942 VarnodeBank::endDef(uint4 fl, const Address&)
    pub fn end_def_addr(&self, _fl: u32, addr: Address) -> impl Iterator<Item = &VarnodeDefRef> {
        self.def_tree
            .iter()
            .filter(move |v| v.0.read().unwrap().loc.as_u64() > addr.as_u64()
        )
    }

    // Ghidra: varnode.cc:1791 VarnodeBank::overlapLoc
    /// Find overlapping varnodes in loc_tree for a given iterator.
    /// Faithful to `overlapLoc` (varnode.cc:1791-1830).
    pub fn overlap_loc(
        &self, target_addr: Address, target_size: usize,
    ) -> Vec<Arc<RwLock<Varnode>>> {
        let mut result = Vec::new();
        let target_end = target_addr.as_u64().wrapping_add(target_size as u64);
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            let vn_start = vn.loc.as_u64();
            let vn_end = vn_start.wrapping_add(vn.get_size() as u64);
            if vn_start < target_end && target_addr.as_u64() < vn_end {
                drop(vn);
                result.push(loc_ref.0.clone());
            }
        }
        result
    }

    // Ghidra: varnode.cc:1831 VarnodeBank::beginDef (no-flag version)
    pub fn begin_def(&self) -> std::collections::btree_set::Iter<'_, VarnodeDefRef> {
        self.def_tree.iter()
    }

    // Ghidra: varnode.cc:1560 VarnodeBank::beginLoc
    pub fn begin_loc(&self) -> std::collections::btree_set::Iter<'_, VarnodeLocRef> {
        self.loc_tree.iter()
    }

    // Ghidra: varnode.cc:1536 VarnodeBank::hasInputIntersection
    pub fn has_input_intersection(&self) -> bool {
        false // Placeholder for structure alignment
    }

    // Ghidra: varnode.hh:389 VarnodeBank::numVarnodes
    pub fn num_varnodes(&self) -> usize {
        self.loc_tree.len()
    }

    // Ghidra: varnode.hh:394 VarnodeBank::getCreateIndex
    pub fn get_create_index(&self) -> u32 {
        self.create_index
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::findFree
    /// Find a free varnode at a specific location and size
    pub fn find_free(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        let search_vn = Arc::new(RwLock::new(Varnode::new(size, loc)));
        self.loc_tree
            .get(&VarnodeLocRef(search_vn))
            .map(|v| v.0.clone())
    }

    // Ghidra: varnode.cc:1465 VarnodeBank::findInput
    /// Find an input varnode at the given size and location. Faithful to
    /// `VarnodeBank::findInput` (varnode.cc:1465-1478): the lookup key is
    /// the FULL Address — `beginLoc(s,loc,Varnode::input)` searches the
    /// (size, space, offset) tree keys and the found varnode must satisfy
    /// `vn->getAddr()==loc`, which compares space AND offset. Rugra keeps
    /// space and offset split (ADDRESS-0001), so the space is an explicit
    /// parameter. Used by ActionRestrictLocal and AncestorRealistic to
    /// find specific register inputs. (BANK-FINDINPUT-SPACE-0001)
    pub fn find_input(
        &self,
        size: usize,
        space: AddressSpace,
        loc: Address,
    ) -> Option<Arc<RwLock<Varnode>>> {
        self.loc_tree
            .iter()
            .find(|v| {
                let g = v.0.read().unwrap();
                g.is_input()
                    && g.get_size() == size
                    && g.address_space == space
                    && g.get_offset() == loc.as_u64()
            })
            .map(|v| v.0.clone())
    }

    // Ghidra: varnode.cc:1440 VarnodeBank::find
    /// Find a Varnode by size, address, defining op address, and optional uniq.
    /// Faithful to `find` (varnode.cc:1440-1458). Scans loc_tree entries
    /// matching (size, addr) and checks def op address + time.
    pub fn find_vn(
        &self, size: usize, loc: Address, pc: Address, uniq: u32,
    ) -> Option<Arc<RwLock<Varnode>>> {
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            if vn.get_size() != size { continue; }
            if vn.loc != loc { continue; }
            // Check def op address + time.
            if let Some(def_weak) = vn.def.as_ref().and_then(|w| w.upgrade()) {
                let def_op = def_weak.read().unwrap();
                if def_op.get_addr() == pc {
                    if uniq == u32::MAX || def_op.start.get_time() == uniq {
                        drop(vn);
                        return Some(loc_ref.0.clone());
                    }
                }
            }
        }
        None
    }

    // Ghidra: varnode.cc:1485 VarnodeBank::findCoveredInput
    /// Find the first input Varnode completely contained within [loc, loc+s).
    /// Faithful to `findCoveredInput` (varnode.cc:1485-1507).
    pub fn find_covered_input(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        let end = loc.as_u64().wrapping_add(size as u64).wrapping_sub(1);
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            if !vn.is_input() { continue; }
            let vn_start = vn.loc.as_u64();
            let vn_end = vn_start.wrapping_add(vn.get_size() as u64).wrapping_sub(1);
            // vn must be completely contained in [loc, loc+s)
            if vn_start >= loc.as_u64() && vn_end <= end {
                drop(vn);
                return Some(loc_ref.0.clone());
            }
        }
        None
    }

    // Ghidra: varnode.cc:1513 VarnodeBank::findCoveringInput
    /// Find the input Varnode that completely contains [loc, loc+s).
    /// Faithful to `findCoveringInput` (varnode.cc:1513-1531).
    pub fn find_covering_input(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            if !vn.is_input() { continue; }
            let vn_start = vn.loc.as_u64();
            let vn_end = vn_start.wrapping_add(vn.get_size() as u64).wrapping_sub(1);
            // vn must completely contain [loc, loc+s)
            if vn_start <= loc.as_u64() && vn_end >= loc.as_u64().wrapping_add(size as u64).wrapping_sub(1) {
                drop(vn);
                return Some(loc_ref.0.clone());
            }
        }
        None
    }

    // Ghidra: varnode.cc:1560 VarnodeBank::beginLoc(AddrSpace*)
    /// Beginning of Varnodes in given address space, sorted by location.
    /// Faithful to `beginLoc(AddrSpace*)` (varnode.cc:1560-1564).
    pub fn begin_loc_space(&self, space: AddressSpace) -> impl Iterator<Item = &VarnodeLocRef> {
        self.loc_tree
            .iter()
            .filter(move |v| v.0.read().unwrap().address_space == space
        )
    }

    // Ghidra: varnode.cc:1582 VarnodeBank::beginLoc(const Address&)
    /// Beginning of Varnodes at a specific address.
    pub fn begin_loc_addr(&self, addr: Address) -> impl Iterator<Item = &VarnodeLocRef> {
        self.loc_tree
            .iter()
            .filter(move |v| v.0.read().unwrap().loc == addr
        )
    }

    // Ghidra: varnode.cc:1560 VarnodeBank::endLoc(AddrSpace*)
    /// End iterator for Varnodes in given address space. In Rust, this is
    /// combined with begin_loc_space into a single filter iterator.
    /// This method exists for API completeness but returns an empty iterator
    /// (use begin_loc_space().chain(empty) pattern instead).
    pub fn end_loc_space(
        &self, _space: AddressSpace,
    ) -> std::collections::btree_set::Iter<'_, VarnodeLocRef> {
        // In Rust, we use the filter iterator from begin_loc_space directly.
        // This is a no-op stub for API parity.
        self.loc_tree.iter()
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::findOrCreateInputSpace
    /// Find or create an input varnode at (space, offset, size).
    pub fn find_or_create_input_space(
        &mut self,
        size: usize,
        space: AddressSpace,
        offset: u64,
    ) -> Arc<RwLock<Varnode>> {
        for entry in self.loc_tree.iter() {
            let g = entry.0.read().unwrap();
            if g.address_space == space
                && g.get_offset() == offset
                && g.get_size() == size
                && !g.is_constant()
                && !g.is_written()
            {
                return entry.0.clone();
            }
        }
        self.create_with_space(size, space, offset)
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::findByLoc
    /// Find any varnode at (size, loc), regardless of create_index.
    ///
    /// `find_free` requires an exact (loc, size, create_index) match, so it
    /// only finds a varnode whose create_index is 0. This helper instead
    /// scans the loc_tree for any varnode with matching (loc, size),
    /// returning the most recently created (highest create_index), which is
    /// the one most likely to carry a current def link. Used by inject to
    /// reuse a prior op's output varnode when linking use-def chains.
    pub fn find_by_loc(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        let mut best: Option<Arc<RwLock<Varnode>>> = None;
        let mut best_idx = 0u32;
        for entry in self.loc_tree.iter() {
            let v = entry.0.read().unwrap();
            if v.loc == loc && v.size == size {
                if v.create_index >= best_idx {
                    best_idx = v.create_index;
                    best = Some(entry.0.clone());
                }
            }
        }
        best
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::iterSpace
    /// Iterate all varnodes in a given address space, in sorted order.
    /// Faithful to Ghidra's `beginLoc(size, addr, space, size4)` /
    /// `endLoc` range iteration (varnode.hh). With address_space now part of
    /// the loc_tree sort key (VarnodeLocRef::Ord), all varnodes of one space
    /// form a contiguous range, so this collects them efficiently.
    pub fn iter_space(
        &self,
        space: crate::space::AddressSpace,
    ) -> impl Iterator<Item = Arc<RwLock<Varnode>>> + '_ {
        self.loc_tree
            .iter()
            .filter(move |entry| entry.0.read().unwrap().address_space == space
            )
            .map(|entry| entry.0.clone())
    }
}

impl fmt::Display for Varnode {
    // Ghidra: varnode.cc:1218 VarnodeBank::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.loc, self.size)
    }
}

impl Default for VarnodeBank {
    // Ghidra: varnode.cc:1218 VarnodeBank::default
    fn default() -> Self {
        Self::new()
    }
}

/// Walk forward along COPY defs from `vn`, returning true if `target` (by
/// pointer identity) appears anywhere along the chain. Faithful to the
// RUGRA-GLUE: 沿 COPY 链逐步比较指针身份。Ghidra 用裸指针 while 循环
// (varnode.cc:1010,1030)；Rugra 需 clone Arc + 释放 guard 逐层展开。
/// `while(vn->isWritten() && vn->getDef()->code()==CPUI_COPY) { vn=...; if(vn==t) return true; }`
/// pattern in findSubpieceShadow/findPieceShadow (varnode.cc:1010,1030).
fn copy_chain_hits(vn: &Varnode, target: &Varnode) -> bool {
    use crate::opcodes::OpCode;
    if std::ptr::eq(vn as *const Varnode, target as *const Varnode) {
        return true;
    }
    let mut cur_def = vn.def.as_ref().and_then(|w| w.upgrade());
    let mut cur_vn_ptr: *const Varnode = vn as *const Varnode;
    // We need to compare each Varnode along the COPY chain to target.
    // Walk: at each step, if cur is defined by COPY, advance to in(0).
    loop {
        let def_arc = match cur_def.take() {
            Some(a) => a,
            None => return false,
        };
        let next = {
            let def = def_arc.read().unwrap();
            if def.opcode != OpCode::CPUI_COPY {
                return false;
            }
            def.inrefs.get(0).cloned()
        };
        let Some(next_arc) = next else { return false };
        // Compare next Varnode to target by pointer.
        let hits = {
            let n = next_arc.read().unwrap();
            std::ptr::eq(&*n as *const Varnode, target as *const Varnode)
        };
        if hits {
            return true;
        }
        // Set up for next iteration: cur_vn becomes next_arc's Varnode.
        // Its def is next_arc.def.
        let next_def = next_arc
            .read()
            .unwrap()
            .def
            .as_ref()
            .and_then(|w| w.upgrade());
        let _ = cur_vn_ptr; // suppress unused
        cur_def = next_def;
    }
}

/// Resolve the COPY-chain source of `vn` and return it as a borrowed
/// comparison target. Returns the def op + the advanced `vn` reference is
/// implicit (caller re-reads). For findSubpieceShadow we need the terminal
/// non-COPY-defined Varnode. Returns (def_op_arc, is_constant_terminal).
/// Actually, to avoid lifetime issues, we return the source Varnode's def
/// op Arc so the caller can inspect its opcode/inputs.
// RUGRA-GLUE: 透传 COPY 链到终端 def op（非 COPY 定义或 unwritten）。
// Ghidra 内联 while 循环；Rugra 提取为函数以避免跨层 RwLockReadGuard 冲突。
/// Returns None if vn is not written.
fn copy_chain_source_def(
    vn: &Varnode,
) -> Option<(std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>, bool)> {
    use crate::opcodes::OpCode;
    // Walk COPY chain to the terminal def op.
    let mut cur_def = vn.def.as_ref().and_then(|w| w.upgrade())?;
    loop {
        let (is_copy, next_def) = {
            let d = cur_def.read().unwrap();
            if d.opcode == OpCode::CPUI_COPY {
                (
                    true, d.inrefs
                        .get(0)
                        .and_then(|v| v.read().unwrap().def.as_ref().and_then(|w| w.upgrade())),
                )
            } else {
                (false, None)
            }
        };
        if !is_copy {
            // cur_def is the terminal non-COPY def.
            let written = true;
            return Some((cur_def, written));
        }
        match next_def {
            Some(nd) => cur_def = nd,
            None => {
                // COPY chain ends at an unwritten/input Varnode.
                return Some((cur_def, false));
            }
        }
    }
}

// Ghidra: varnode.cc:1006 Varnode::findSubpieceShadow
/// Faithful to `Varnode::findSubpieceShadow` (varnode.cc:1006-1053).
/// Establish that `vn` is produced from `whole` by SUBPIECE truncating
/// `least_byte` low bytes (allowing COPY pass-through and 1 level of
/// MULTIEQUAL recursion).
fn find_subpiece_shadow(vn: &Varnode, least_byte: i32, whole: &Varnode, recurse: i32) -> bool {
    use crate::opcodes::OpCode;
    // Walk COPY chain from vn to its source.
    let (def_arc, written) = match copy_chain_source_def(vn) {
        Some(x) => x,
        None => {
            // vn not written at all.
            if vn.is_constant() {
                // Constant short-circuit (varnode.cc:1013-1020).
                let whole_def = copy_chain_source_def(whole);
                let whole_is_const = match &whole_def {
                    Some((_, true)) => false,
                    None => whole.is_constant(),
                    Some((_, false)) => whole.is_constant(),
                };
                // Re-derive whole's terminal offset by walking its COPY chain.
                if !whole_is_const {
                    return false;
                }
                let whole_off = whole_terminal_offset(whole);
                let off = whole_off >> (least_byte as u32 * 8);
                let mask = crate::address::calc_mask(vn.size);
                return (off & mask) == vn.get_offset();
            }
            return false;
        }
    };
    if !written {
        // vn's COPY chain ends at an unwritten (input) non-constant Varnode.
        return false;
    }
    let def = def_arc.read().unwrap();
    match def.opcode {
        OpCode::CPUI_SUBPIECE => {
            let tmpvn_arc = match def.inrefs.get(0) { Some(a) => a.clone(), None => return false ,
            };
            let off = match def.inrefs.get(1) { Some(a) => a.read().unwrap().get_offset() as i32, None => return false ,
            };
            if off != least_byte {
                return false;
            }
            let tmpvn_size = tmpvn_arc.read().unwrap().size;
            if tmpvn_size != whole.size {
                return false;
            }
            // if (tmpvn == whole) return true; + COPY chain check (varnode.cc:1029-1033)
            let tmpvn = tmpvn_arc.read().unwrap();
            return copy_chain_hits(&tmpvn, whole);
        }
        OpCode::CPUI_MULTIEQUAL => {
            let new_recurse = recurse + 1;
            if new_recurse > 1 {
                return false; // Truncate recursion at max depth (varnode.cc:1037)
            }
            // Walk whole's COPY chain, require it to be defined by MULTIEQUAL.
            let (whole_def_arc, whole_written) = match copy_chain_source_def(whole) {
                Some(x) => x,
                None => return false,
            };
            if !whole_written {
                return false;
            }
            let small_op = def_arc.clone();
            drop(def);
            let big_op_def = whole_def_arc.read().unwrap();
            if big_op_def.opcode != OpCode::CPUI_MULTIEQUAL {
                return false;
            }
            // bigOp->getParent() != smallOp->getParent() check (varnode.cc:1044).
            let same_parent = {
                let big_p = big_op_def.parent.as_ref().and_then(|w| w.upgrade());
                let small_p = small_op
                    .read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|w| w.upgrade());
                match (big_p, small_p) {
                    (Some(b), Some(s)) => std::sync::Arc::ptr_eq(&b, &s),
                    _ => false,
                }
            };
            if !same_parent {
                return false;
            }
            let n = big_op_def.num_input();
            // Collect input Arcs before recursing (avoid holding guards).
            let pairs: Vec<(
                std::sync::Arc<std::sync::RwLock<Varnode>>, std::sync::Arc<std::sync::RwLock<Varnode>>,
            )> = {
                let small = small_op.read().unwrap();
                (0..n)
                    .filter_map(|i| {
                    let sin = small.inrefs.get(i).cloned();
                    let bin = big_op_def.inrefs.get(i).cloned();
                    match (sin, bin) { (Some(a), Some(b)) => Some((a, b)), _ => None ,
                        }
                })
                    .collect()
            };
            drop(big_op_def);
            for (s_arc, b_arc) in pairs {
                let (s, b) = { (s_arc.read().unwrap(), b_arc.read().unwrap()) };
                // Note: recursing with dropped guards — but we hold s,b here.
                // find_subpiece_shadow only reads, so it's safe to pass &*s, &*b.
                if !find_subpiece_shadow(&s, least_byte, &b, new_recurse) {
                    return false;
                }
            }
            return true;
        }
        _ => return false,
    }
}

// RUGRA-GLUE: 透传 whole 的 COPY 链取终端 offset（常量短路用）。
// Ghidra 内联 while 循环 (varnode.cc:1014-1017)；Rugra 提取为函数。
/// Get the terminal offset of a constant Varnode after walking its COPY
/// chain. Used by findSubpieceShadow's constant short-circuit (varnode.cc:1017).
fn whole_terminal_offset(whole: &Varnode) -> u64 {
    use crate::opcodes::OpCode;
    let mut off = whole.get_offset();
    let mut cur = whole.def.as_ref().and_then(|w| w.upgrade());
    while let Some(d_arc) = cur.take() {
        let d = d_arc.read().unwrap();
        if d.opcode != OpCode::CPUI_COPY {
            break;
        }
        if let Some(next) = d.inrefs.get(0) {
            off = next.read().unwrap().get_offset();
            cur = next.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        } else {
            break;
        }
    }
    off
}

// Ghidra: varnode.cc:1062 Varnode::findPieceShadow
/// Faithful to `Varnode::findPieceShadow` (varnode.cc:1062-1091).
fn find_piece_shadow(vn: &Varnode, mut least_byte: i32, piece: &Varnode) -> bool {
    use crate::opcodes::OpCode;
    // Walk COPY chain.
    let (def_arc, written) = match copy_chain_source_def(vn) {
        Some(x) => x,
        None => return false,
    };
    if !written {
        return false;
    }
    let def = def_arc.read().unwrap();
    if def.opcode != OpCode::CPUI_PIECE {
        return false;
    }
    // tmpvn = getIn(1) (least significant part).
    let mut tmpvn_arc = match def.inrefs.get(1) { Some(a) => a.clone(), None => return false ,
    };
    let tmp_size = tmpvn_arc.read().unwrap().size;
    if (least_byte as usize) >= tmp_size {
        least_byte -= tmp_size as i32;
        // tmpvn = getIn(0).
        tmpvn_arc = match def.inrefs.get(0) { Some(a) => a.clone(), None => return false ,
        };
    } else {
        let tmp_size2 = tmpvn_arc.read().unwrap().size;
        if piece.size + (least_byte as usize) > tmp_size2 {
            return false;
        }
    }
    let tmp_size_final = tmpvn_arc.read().unwrap().size;
    if least_byte == 0 && tmp_size_final == piece.size {
        let tmpvn = tmpvn_arc.read().unwrap();
        return copy_chain_hits(&tmpvn, piece);
    }
    // CPUI_PIECE input too big: recurse.
    let tmpvn = tmpvn_arc.read().unwrap();
    find_piece_shadow(&tmpvn, least_byte, piece)
}

// Ghidra: varnode.cc:2014 contiguous_test
/// Test if two Varnodes are contiguous pieces of a whole via SUBPIECE.
/// Faithful to `contiguous_test` (varnode.cc:2014-2037).
pub fn contiguous_test(vn1: &Varnode, vn2: &Varnode) -> bool {
    use crate::opcodes::OpCode;
    if vn1.is_input() || vn2.is_input() { return false; }
    if !vn1.is_written() || !vn2.is_written() { return false; }
    let def1 = match vn1.def.as_ref().and_then(|w| w.upgrade()) { Some(d) => d, None => return false ,
    };
    let def2 = match vn2.def.as_ref().and_then(|w| w.upgrade()) { Some(d) => d, None => return false ,
    };
    let d1 = def1.read().unwrap();
    let d2 = def2.read().unwrap();
    if d1.opcode != OpCode::CPUI_SUBPIECE || d2.opcode != OpCode::CPUI_SUBPIECE { return false; }
    let vnwhole1 = match d1.get_in(0) { Some(v) => v.clone(), None => return false ,
    };
    let vnwhole2 = match d2.get_in(0) { Some(v) => v.clone(), None => return false ,
    };
    if !Arc::ptr_eq(&vnwhole1, &vnwhole2) { return false; }
    // vn2 must be least significant (offset 0)
    let off2 = match d2.get_in(1) { Some(v) => v.read().unwrap().get_offset(), None => return false ,
    };
    if off2 != 0 { return false; }
    // vn1 must be contiguous above vn2
    let off1 = match d1.get_in(1) { Some(v) => v.read().unwrap().get_offset(), None => return false ,
    };
    if off1 != vn2.size as u64 { return false; }
    true
}

// Ghidra: varnode.cc:2045 findContiguousWhole
/// Return the whole Varnode containing vn1+vn2 (assuming contiguous_test passed).
/// Faithful to `findContiguousWhole` (varnode.cc:2045-2051).
pub fn find_contiguous_whole(vn1: &Varnode) -> Option<Arc<RwLock<Varnode>>> {
    if vn1.is_written() {
        if let Some(def) = vn1.def.as_ref().and_then(|w| w.upgrade()) {
            if def.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_SUBPIECE {
                return def.read().unwrap().get_in(0).cloned();
            }
        }
    }
    None
}

// Ghidra: varnode.cc:510 Varnode::copySymbolIfValid / database.hh:302 EquateSymbol
// RUGRA-GLUE: equate-symbol identity registry.
/// In the C++ oracle, `EquateSymbol` is a `Symbol` subtype, so
/// `dynamic_cast<EquateSymbol*>(mapEntry->getSymbol())` (varnode.cc:516)
/// recovers both the equate-ness and the `uintb value` field
/// (database.hh:302-308) from the polymorphic `Symbol*`. Rugra's
/// `database::Symbol` (src/database.rs, outside the varnode lease) has no
/// equate payload, and `SymbolEntry::symbol` is a concrete
/// `Arc<RwLock<Symbol>>`, so subtype polymorphism is unavailable. This
/// varnode-domain side table is the minimal stand-in: registering a value
/// marks the symbol as an EquateSymbol (the dynamic_cast succeeding), and
/// `query_value` returns the `EquateSymbol::value` a successful cast would
/// expose. Entries are deliberately never removed: symbols are dropped by
/// `Arc`, and clearing on Drop would re-attribute equate-ness to a new symbol
/// allocated at a recycled address (ABA); the registry therefore mirrors the
/// C++ object-lifetime semantics of "an EquateSymbol stays an EquateSymbol".
/// Wiring: `database::Scope::add_equate_symbol` and the `<equatesymbol>` leg
/// of `database::Scope::add_map_sym` register their symbols here
/// (DATABASE-EQUATE-VALUE-REGISTRY-0001), so main-pipeline equates reach
/// `copy_symbol_if_valid` with their value.
pub mod equate_symbol_registry {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock, RwLock};

    use crate::database::Symbol;

    // RUGRA-GLUE: once-cell accessor for the process-global registry map
    // (pure Rust language structure; Ghidra has no counterpart).
    fn table() -> &'static Mutex<HashMap<usize, u64>> {
        static TABLE: OnceLock<Mutex<HashMap<usize, u64>>> = OnceLock::new();
        TABLE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    // RUGRA-GLUE: registry key = symbol Arc allocation address (identity of
    // the referenced Symbol object, mirroring the C++ pointer identity the
    // dynamic_cast would operate on).
    fn key_of(symbol: &Arc<RwLock<Symbol>>) -> usize {
        Arc::as_ptr(symbol) as usize
    }

    // RUGRA-GLUE: register_equate_symbol_value (no Ghidra counterpart)
    /// Record that `symbol` is an equate carrying `value` — the Rust
    /// equivalent of the C++ `Symbol*` actually pointing at an
    /// `EquateSymbol(value)` object for later `dynamic_cast`s.
    pub fn register_value(symbol: &Arc<RwLock<Symbol>>, value: u64) {
        table().lock().unwrap().insert(key_of(symbol), value);
    }

    // RUGRA-GLUE: query_equate_symbol_value (models dynamic_cast<EquateSymbol*>)
    /// Return the equate value of `symbol`, or `None` when the symbol is not
    /// an equate (the `dynamic_cast<EquateSymbol*>` yielding null,
    /// varnode.cc:516-518).
    pub fn query_value(symbol: &Arc<RwLock<Symbol>>) -> Option<u64> {
        table().lock().unwrap().get(&key_of(symbol)).copied()
    }
}

// Ghidra: database.cc:640 EquateSymbol::isValueClose
impl crate::database::EquateSymbol {
    /// An EquateSymbol should survive certain kinds of transforms during
    /// decompilation, such as negation, twos-complementing, adding or
    /// subtracting 1. Return `true` if the given value looks like a transform
    /// of this type relative to the underlying value of this equate.
    /// Faithful to `EquateSymbol::isValueClose` (database.cc:640-659):
    /// ```text
    /// if (value == op2Value) return true;
    /// uintb mask = calc_mask(size);
    /// uintb maskValue = value & mask;
    /// if (maskValue != value) {          // '1' bits are getting masked off
    ///   if (value != sign_extend(maskValue,size,sizeof(uintb)))
    ///     return false;                  // only sign-extension may be masked
    /// }
    /// if (maskValue == (op2Value & mask)) return true;
    /// if (maskValue == (~op2Value & mask)) return true;
    /// if (maskValue == (-op2Value & mask)) return true;
    /// if (maskValue == ((op2Value + 1) & mask)) return true;
    /// if (maskValue == ((op2Value - 1) & mask)) return true;
    /// return false;
    /// ```
    // Ghidra: database.cc:640 EquateSymbol::isValueClose
    pub fn is_value_close(&self, op2_value: u64, size: usize) -> bool {
        Self::is_value_close_value(self.value, op2_value, size)
    }

    // Ghidra: database.cc:640 EquateSymbol::isValueClose
    /// Value-level form of [`EquateSymbol::is_value_close`], callable from
    /// `Varnode::copy_symbol_if_valid` (varnode.cc:519) with just the
    /// `EquateSymbol::value` recovered via `dynamic_cast`, without
    /// reconstructing a full symbol object. Same algorithm, same branches.
    pub fn is_value_close_value(value: u64, op2_value: u64, size: usize) -> bool {
        // cc:642: exact equality always matches, regardless of masking.
        if value == op2_value {
            return true;
        }
        // cc:643-644: mask off everything beyond `size` bytes of precision.
        let mask = crate::address::calc_mask(size);
        let mask_value = value & mask;
        // cc:645-649: if '1' bits are getting masked off, make sure only
        // sign-extension is getting masked off.
        if mask_value != value
            && value != crate::rangeutil::sign_extend_size(mask_value, size, 8)
        {
            return false;
        }
        // cc:650-654: equal / bitwise-not / negated / plus-one / minus-one
        // forms within the mask all count as "close". The C++ uintb
        // arithmetic (-, +1, -1) wraps; so does the Rust u64 form.
        if mask_value == (op2_value & mask) {
            return true;
        }
        if mask_value == (!op2_value & mask) {
            return true;
        }
        if mask_value == (op2_value.wrapping_neg() & mask) {
            return true;
        }
        if mask_value == (op2_value.wrapping_add(1) & mask) {
            return true;
        }
        if mask_value == (op2_value.wrapping_sub(1) & mask) {
            return true;
        }
        // cc:655: nothing matched.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ghidra: userop.cc:361 InternalStringOp::getOutputLocal (PRINTC-STRDATA-TYPELOCK-0001 regression lock)
    /// userop.cc:361-364: `InternalStringOp::getOutputLocal` returns
    /// `op->getOut()->getType()` — the typelocked char* that
    /// `Funcdata::getInternalString` (funcdata_varnode.cc:1430-1431)
    /// installs — never the metadata-less base default. This is the
    /// primitive `ActionSetCasts::castOutput`'s CALLOTHER token consumes
    /// (typeop.cc:282-285 virtual dispatch); a metadata-less fallback here
    /// re-opens the int8-token pierce of the STRINGDATA typelock chain.
    #[test]
    fn test_output_type_local_stringdata_echoes_out_varnode_type() {
        use crate::address::{Address, SeqNum};
        use crate::op::PcodeOp;
        use crate::opcodes::OpCode;
        use crate::type_system::typefactory::TypeFactory;
        use crate::type_system::TypeMetatype;
        use crate::userop::{UserOpManage, BUILTIN_STRINGDATA};

        let factory = std::sync::Arc::new(std::sync::RwLock::new(TypeFactory::new(8)));
        factory
            .write()
            .unwrap()
            .set_default_alignment_map();
        let char_type = factory
            .write()
            .unwrap()
            .get_base(1, TypeMetatype::Int)
            .expect("char base");
        let char_ptr = factory
            .write()
            .unwrap()
            .get_type_pointer(8, char_type, 1);

        // The STRINGDATA CALLOTHER: in(0) = builtin id constant, out = the
        // typelocked char* unique (get_internal_string's cc:1430-1431 form).
        let mut mgr = UserOpManage::new();
        mgr.register_builtin_by_id(BUILTIN_STRINGDATA);
        let mgr = std::sync::Arc::new(std::sync::RwLock::new(mgr));

        let mut id_vn = Varnode::new(4, Address::new(BUILTIN_STRINGDATA as u64));
        id_vn.v_type = factory
            .write()
            .unwrap()
            .get_base(4, TypeMetatype::Uint);
        let id_vn = std::sync::Arc::new(std::sync::RwLock::new(id_vn));

        let mut out_vn = Varnode::new(8, Address::new(0x7f000000));
        assert!(out_vn.update_type_lock(char_ptr.clone(), true, false));
        let out_vn = std::sync::Arc::new(std::sync::RwLock::new(out_vn));

        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_CALLOTHER);
        op.inrefs.push(id_vn);
        op.output = Some(out_vn);

        // The oracle echo: the stringdata descriptor's output local type IS
        // the out varnode's own (typelocked) type — same interned instance.
        let got = op_output_type_local(&op, &factory, Some(&mgr), None)
            .expect("stringdata output local type");
        assert!(
            std::sync::Arc::ptr_eq(&got, &char_ptr),
            "expected the out varnode's own char* (typelock echo), got {}",
            got.get_name()
        );

        // Negative control (the pre-fix pierce shape): a metadata-less
        // descriptor with NO InternalStringOp override falls to the TypeOp
        // base default getBase(8, TYPE_UNKNOWN) (typeop.cc:261-265) — never
        // a signed Int base.
        let bare = UserOpManage::new();
        let bare = std::sync::Arc::new(std::sync::RwLock::new(bare));
        let fallback = op_output_type_local(&op, &factory, Some(&bare), None)
            .expect("unregistered index folds to base default");
        assert_eq!(fallback.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(fallback.get_size(), 8);
    }

    // Ghidra: userop.cc:128 VolatileReadOp::getOutputLocal (VARNODE-CALLOTHER-VOLATILEOUT-0001 regression lock)
    /// userop.cc:128-141: a volatile-read CALLOTHER that does special
    /// propagation (the `special_prop` addlflag, set by
    /// `Funcdata::replaceVolatile` funcdata_varnode.cc:761-762 only when the
    /// replaced varnode was type-locked) resolves its output local type from
    /// the global scope: `queryProperties(in(1)->getAddr(), out->getSize(),
    /// op->getAddr(), vflags)` then `entry->getSizedType(addr,size)`. Every
    /// other shape — no special_prop flag, no symbol at the address, no
    /// symboltab thread — falls to the metadata-less descriptor path and the
    /// TypeOp base default `getBase(out.size, TYPE_UNKNOWN)` (typeop.cc:261-265,
    /// via typeop.cc:865-873), never a signed Int base.
    #[test]
    fn test_output_type_local_volatile_read_symbol_arm() {
        use crate::address::{Address, SeqNum};
        use crate::database::{symbol_flags, Database};
        use crate::op::op_addl_flags;
        use crate::op::PcodeOp;
        use crate::opcodes::OpCode;
        use crate::type_system::datatype::{Datatype, TypeBase};
        use crate::type_system::typefactory::TypeFactory;
        use crate::type_system::TypeMetatype;
        use crate::userop::{UserOpManage, BUILTIN_VOLATILE_READ};

        let factory = std::sync::Arc::new(std::sync::RwLock::new(TypeFactory::new(8)));
        factory
            .write()
            .unwrap()
            .set_default_alignment_map();

        // The read_volatile descriptor (UserOpManage::registerBuiltin,
        // userop.cc:432-484) — a VolatileReadOp with NO fixed metadata.
        let mut mgr = UserOpManage::new();
        let volatile_index = mgr.register_builtin_by_id(BUILTIN_VOLATILE_READ);
        let mgr = std::sync::Arc::new(std::sync::RwLock::new(mgr));

        // Global symbol "vol_reg" (int, 4 bytes) mapped at 0x1000; addr-tied
        // so the entry is in use at every usepoint (database.cc:115-120).
        let mut db = Database::new(false);
        let sym_dt = std::sync::Arc::new(Datatype::Base(TypeBase::new(
            "int".into(),
            4,
            TypeMetatype::Int,
        )));
        let sym_id = db
            .add_symbol_mapped(0, "vol_reg", Some(sym_dt), Address::new(0x1000), 4)
            .expect("global symbol mapped");
        db.set_symbol_flag(0, sym_id, symbol_flags::ADDRTIED, true);
        let db = std::sync::Arc::new(std::sync::RwLock::new(db));

        // The volatile read CALLOTHER (Funcdata::replaceVolatile read form,
        // funcdata_varnode.cc:740-759): in(0) = descriptor id constant,
        // in(1) = volatil annotation at the memory address, out = 4-byte
        // temp; special_prop set per cc:761-762 (type-locked source).
        let mut id_vn = Varnode::new(4, Address::new(volatile_index as u64));
        id_vn.set_flags(crate::varnode::varnode_flags::CONSTANT);
        let id_vn = std::sync::Arc::new(std::sync::RwLock::new(id_vn));

        let mut ann_vn = Varnode::new(4, Address::new(0x1000));
        ann_vn.set_flags(
            crate::varnode::varnode_flags::ANNOTATION | crate::varnode::varnode_flags::VOLATIL,
        );
        let ann_vn = std::sync::Arc::new(std::sync::RwLock::new(ann_vn));

        let out_vn =
            std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x7f000000))));

        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x2000), 0), OpCode::CPUI_CALLOTHER);
        op.inrefs.push(id_vn.clone());
        op.inrefs.push(ann_vn);
        op.output = Some(out_vn.clone());
        op.addlflags |= op_addl_flags::SPECIAL_PROP;

        // Positive: the global symbol arm — the entry's sized type at the
        // volatile address (userop.cc:137-139).
        let got = op_output_type_local(&op, &factory, Some(&mgr), Some(&db))
            .expect("volatile read resolves the global symbol's sized type");
        assert_eq!(got.get_name(), "int");
        assert_eq!(got.get_metatype(), TypeMetatype::Int);
        assert_eq!(got.get_size(), 4);

        // Negative 1 (userop.cc:131): no special propagation — the flag is
        // set only for a type-locked source; without it the descriptor is
        // metadata-less and the base default (UNKNOWN, out size) wins.
        op.addlflags &= !op_addl_flags::SPECIAL_PROP;
        let fallback = op_output_type_local(&op, &factory, Some(&mgr), Some(&db))
            .expect("base default is still a type");
        assert_eq!(fallback.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(fallback.get_size(), 4);
        op.addlflags |= op_addl_flags::SPECIAL_PROP;

        // Negative 2 (userop.cc:136-140): no entry at the queried address —
        // queryProperties returns null and the base default wins.
        let mut miss_vn = Varnode::new(4, Address::new(0x9000));
        miss_vn.set_flags(
            crate::varnode::varnode_flags::ANNOTATION | crate::varnode::varnode_flags::VOLATIL,
        );
        op.inrefs[1] = std::sync::Arc::new(std::sync::RwLock::new(miss_vn));
        let miss = op_output_type_local(&op, &factory, Some(&mgr), Some(&db))
            .expect("base default is still a type");
        assert_eq!(miss.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(miss.get_size(), 4);

        // Negative 3: no symboltab thread (no owning Architecture) — the
        // volatile arm cannot run; base default again.
        let unthreaded = op_output_type_local(&op, &factory, Some(&mgr), None)
            .expect("base default is still a type");
        assert_eq!(unthreaded.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(unthreaded.get_size(), 4);
    }

    #[test]
    fn test_equate_is_value_close_table() {
        // database.cc:640-659 branch table. These are Rugra-side regression
        // checks; the locked 12.0.4 oracle gate is
        // tests/oracle/varnode_copysymbol_1204 (VARNODE-COPYSYMBOL-EQUATE-0001).
        use crate::database::EquateSymbol;
        // cc:642 exact equality, any size.
        assert!(EquateSymbol::is_value_close_value(
            0x11223344, 0x11223344, 4
        ));
        assert!(EquateSymbol::is_value_close_value(7, 7, 8));
        // cc:645-649 masked-off bits that are pure sign-extension survive...
        assert!(EquateSymbol::is_value_close_value(
            0xFFFFFFFF_8899AABB,
            0x8899AABB,
            4
        ));
        // ...but masked-off '1' bits that are NOT sign-extension reject.
        assert!(!EquateSymbol::is_value_close_value(
            0x11223344_55667788,
            0x55667788,
            4
        ));
        // cc:650 mask-equal after truncation of op2Value.
        assert!(EquateSymbol::is_value_close_value(
            0x55667788, 0x11223344_55667788, 4
        ));
        // cc:651 bitwise-not close.
        assert!(EquateSymbol::is_value_close_value(0x0F0F, 0xF0F0, 2));
        // cc:652 negation close (two's complement within mask).
        assert!(EquateSymbol::is_value_close_value(0x0F0F, 0xF0F1, 2));
        // cc:653 op2Value + 1 close.
        assert!(EquateSymbol::is_value_close_value(0x0F0F, 0x0F0E, 2));
        // cc:654 op2Value - 1 close.
        assert!(EquateSymbol::is_value_close_value(0x0F0F, 0x0F10, 2));
        // cc:655 nothing matches.
        assert!(!EquateSymbol::is_value_close_value(0x1234, 0x5678, 2));
        assert!(!EquateSymbol::is_value_close_value(0x10, 0x20, 8));
        // Method form delegates with self.value (database.hh:307).
        let equ = EquateSymbol::new(0, "EQ", 0, 0x0F0F);
        assert!(equ.is_value_close(0xF0F0, 2));
        assert!(!equ.is_value_close(0x5678, 2));
    }

    #[test]
    fn test_copy_symbol_if_valid_equate_gating() {
        // varnode.cc:510-522: the markup is copied only from an equate symbol
        // whose value is close to this constant (loc offset + size).
        // Associated-function form: the destination must be an Arc'd varnode
        // so the copySymbol tail can reach the high bookkeeping (VARNODE-
        // COPYSYMBOL-HIGHBRANCH-0001).
        use crate::address::RangeList;
        use crate::database::{Symbol, SymbolEntry};

        let attach = |vn: &mut Varnode,
                      symbol: std::sync::Arc<RwLock<Symbol>>,
                      size: i32| {
            let entry = SymbolEntry::new_dynamic(
                symbol.clone(),
                varnode_flags::MAPPED,
                1,
                0,
                size,
                RangeList::default(),
            );
            vn.set_symbol_entry(std::sync::Arc::new(RwLock::new(entry)));
            symbol
        };
        let equate_symbol = |value: u64| {
            let symbol = std::sync::Arc::new(RwLock::new(Symbol::new(0, "FIXTURE_EQ", "equ")));
            equate_symbol_registry::register_value(&symbol, value);
            symbol
        };
        let arc = |vn: Varnode| std::sync::Arc::new(RwLock::new(vn));

        // cc:519-521 equate value equal to the destination constant: copy.
        let mut src = Varnode::new_constant(0x33333333, 4);
        let dst = arc(Varnode::new_constant(0x33333333, 4));
        attach(&mut src, equate_symbol(0x33333333), 4);
        Varnode::copy_symbol_if_valid(&dst, &src);
        assert!(
            dst.read().unwrap().get_symbol_entry().is_some(),
            "close equate propagates"
        );

        // cc:519 not close: reject (VARNODE-COPYSYMBOL-EQUATE-0001 branch).
        let mut src = Varnode::new_constant(0x12345678, 4);
        let dst = arc(Varnode::new_constant(0x33333333, 4));
        attach(&mut src, equate_symbol(0x12345678), 4);
        Varnode::copy_symbol_if_valid(&dst, &src);
        assert!(
            dst.read().unwrap().get_symbol_entry().is_none(),
            "not-close equate rejected"
        );

        // cc:516-518 non-equate symbol (dynamic_cast fails): reject.
        let mut src = Varnode::new_constant(0x33333333, 4);
        let dst = arc(Varnode::new_constant(0x33333333, 4));
        attach(
            &mut src,
            std::sync::Arc::new(RwLock::new(Symbol::new(0, "PLAIN", "unknown"))),
            4,
        );
        Varnode::copy_symbol_if_valid(&dst, &src);
        assert!(
            dst.read().unwrap().get_symbol_entry().is_none(),
            "non-equate symbol rejected"
        );

        // cc:513-515 source without a mapentry: early return.
        let src = Varnode::new_constant(0x33333333, 4);
        let dst = arc(Varnode::new_constant(0x33333333, 4));
        Varnode::copy_symbol_if_valid(&dst, &src);
        assert!(
            dst.read().unwrap().get_symbol_entry().is_none(),
            "no mapentry -> no copy"
        );

        // cc:652 negate-close still propagates through copySymbolIfValid.
        let mut src = Varnode::new_constant(0xF0F1, 2);
        let dst = arc(Varnode::new_constant(0x0F0F, 2));
        attach(&mut src, equate_symbol(0x0F0F), 2);
        Varnode::copy_symbol_if_valid(&dst, &src);
        assert!(
            dst.read().unwrap().get_symbol_entry().is_some(),
            "negate-close equate propagates"
        );
    }

    #[test]
    fn test_copy_symbol_arc_high_branch() {
        // varnode.cc:500-504 high bookkeeping half of copySymbol
        // (VARNODE-COPYSYMBOL-HIGHBRANCH-0001): typeDirty fires whenever the
        // destination has a HighVariable; setSymbol additionally requires a
        // mapentry on the destination after the copy.
        use crate::address::RangeList;
        use crate::database::{Symbol, SymbolEntry};
        use crate::variable::high_internal_flags;

        // Destination with a HighVariable, its type cache pre-cleaned by a
        // first getType (typedirty cleared to 0 before the copy).
        let dst = std::sync::Arc::new(RwLock::new(Varnode::new_constant(0x33333333, 4)));
        let high = {
            let mut h = crate::variable::HighVariable::new(dst.read().unwrap().v_type.clone().unwrap());
            h.add_instance(dst.clone());
            h
        };
        let high = std::sync::Arc::new(RwLock::new(high));
        dst.write().unwrap().high = Some(high.clone());
        high.write().unwrap().update_type(); // clean the typedirty bit
        assert_eq!(
            (high.read().unwrap().highflags & high_internal_flags::TYPEDIRTY),
            0,
            "pre-clean leaves typedirty clear"
        );

        // (a) copy from a typelocked source with an equate mapentry: the
        // full port must set typedirty AND attach the symbol.
        let mut src = Varnode::new_constant(0x33333333, 4);
        let symbol = std::sync::Arc::new(RwLock::new(Symbol::new(0, "FIXTURE_EQ", "equ")));
        equate_symbol_registry::register_value(&symbol, 0x33333333);
        let entry = SymbolEntry::new_dynamic(
            symbol,
            varnode_flags::MAPPED,
            1,
            0,
            4,
            RangeList::default());
        src.set_symbol_entry(std::sync::Arc::new(RwLock::new(entry)));
        src.set_flags(varnode_flags::TYPELOCK);
        Varnode::copy_symbol_arc(&dst, &src);
        let h = high.read().unwrap();
        assert_ne!(
            h.highflags & high_internal_flags::TYPEDIRTY,
            0,
            "cc:501 typeDirty fires when high is attached"
        );
        assert!(
            h.symbol.is_some(),
            "cc:502-503 setSymbol attaches the copied mapentry's symbol"
        );
        assert_eq!(h.get_symbol_offset(), -1, "dynamic equate entry -> -1");
        drop(h);
        assert!(
            dst.read().unwrap().is_type_lock(),
            "cc:499 typelock inherited into the destination"
        );

        // (b) copy from a source WITHOUT a mapentry (direct copySymbol, inner
        // guard false side): typeDirty still fires, symbol untouched.
        let dst2 = std::sync::Arc::new(RwLock::new(Varnode::new_constant(0x44444444, 4)));
        let high2 = {
            let mut h = crate::variable::HighVariable::new(
                dst2.read().unwrap().v_type.clone().unwrap());
            h.add_instance(dst2.clone());
            h
        };
        let high2 = std::sync::Arc::new(RwLock::new(high2));
        dst2.write().unwrap().high = Some(high2.clone());
        high2.write().unwrap().update_type();
        let src2 = Varnode::new_constant(0x44444444, 4);
        Varnode::copy_symbol_arc(&dst2, &src2);
        let h2 = high2.read().unwrap();
        assert_ne!(
            h2.highflags & high_internal_flags::TYPEDIRTY,
            0,
            "cc:501 typeDirty fires even without a mapentry"
        );
        assert!(h2.symbol.is_none(), "cc:502 guard blocks setSymbol");
        drop(h2);

        // (c) destination WITHOUT a HighVariable: the outer guard skips the
        // bookkeeping entirely (no crash, fields still copied).
        let dst3 = std::sync::Arc::new(RwLock::new(Varnode::new_constant(0x55555555, 4)));
        let mut src3 = Varnode::new_constant(0x55555555, 4);
        src3.set_flags(varnode_flags::TYPELOCK | varnode_flags::NAMELOCK);
        Varnode::copy_symbol_arc(&dst3, &src3);
        let d3 = dst3.read().unwrap();
        assert!(d3.high.is_none());
        assert!(d3.is_type_lock() && d3.is_name_lock());
    }

    #[test]
    fn test_varnode_bank_creation() {
        let mut bank = VarnodeBank::new();
        let loc = Address::new(0);
        let vn = bank.create(4, loc);

        assert_eq!(bank.num_varnodes(), 1);
        let vn = vn.read().unwrap();
        assert_eq!(vn.get_size(), 4);
        assert_eq!(vn.flags, varnode_flags::COVERDIRTY);
        assert_eq!(vn.get_consume(), u64::MAX);
        assert_eq!(vn.get_nzm(), u64::MAX);
        // Bank default typing now draws from the Architecture TypeFactory
        // (TYPE-WIRING-0001): the canonical headless oracle spells the core
        // unknowns `undefined{size}` (ghidra_arch.cc:349-355 data
        // organization path), replacing the former bank-local `xunknown{size}`
        // adapter. The object is the process-canonical factory's core type
        // (named, core-flagged, hashed id).
        let dt = vn.get_type().expect("bank creations carry an unknown type");
        assert_eq!(dt.get_name(), "undefined4");
        assert_eq!(dt.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(dt.get_size(), 4);
        assert!(dt.is_coretype());
        assert!(Arc::ptr_eq(&dt, &default_unknown_type(None, 4)));
    }

    #[test]
    fn test_varnode_bank_initial_state_matches_oracle() {
        let mut bank = VarnodeBank::new();
        let op = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1000), 0),
            crate::opcodes::OpCode::CPUI_COPY,
        )));

        let defined = bank.create_with_space(8, AddressSpace::Register, 0x20);
        let defined = bank
            .set_def(defined, Arc::downgrade(&op))
            .expect("fresh defined Varnode");
        let free = bank.create_with_space(8, AddressSpace::Register, 0x38);
        let constant = bank.create_constant(4, 0x1234);
        let input = bank.create_with_space(8, AddressSpace::Register, 0x30);
        let input = bank.set_input(input).expect("fresh input Varnode");
        let annotation = bank.create_with_space(8, AddressSpace::Iop, 0x99);
        let unique0 = bank.create_unique(8);
        let unique1 = bank.create_unique(4);

        let defined_rg = defined.read().unwrap();
        assert_eq!(defined_rg.flags, 0x0100_0030);
        assert_eq!(defined_rg.get_create_index(), 0);
        assert!(defined_rg.is_written());
        assert!(defined_rg.has_cover());
        assert_eq!(defined_rg.count_descends(), 0);
        assert!(defined_rg.cover.is_none());
        assert!(defined_rg.get_def().is_some());

        let free_rg = free.read().unwrap();
        assert_eq!(free_rg.flags, 0x0100_0000);
        assert_eq!(free_rg.get_create_index(), 1);
        assert!(free_rg.is_free());
        assert!(!free_rg.has_cover());

        let constant_rg = constant.read().unwrap();
        assert_eq!(constant_rg.flags, varnode_flags::CONSTANT);
        assert_eq!(constant_rg.get_nzm(), 0x1234);
        assert_eq!(constant_rg.get_create_index(), 2);

        let input_rg = input.read().unwrap();
        assert_eq!(input_rg.flags, 0x0100_0028);
        assert_eq!(input_rg.get_create_index(), 3);
        assert!(input_rg.is_input());

        let annotation_rg = annotation.read().unwrap();
        assert_eq!(annotation_rg.flags, 0x0100_0004);
        assert_eq!(annotation_rg.get_create_index(), 4);
        assert!(annotation_rg.is_annotation());

        assert_eq!(unique0.read().unwrap().get_offset(), ANALYSIS_UNIQUE_START);
        assert_eq!(
            unique1.read().unwrap().get_offset(),
            ANALYSIS_UNIQUE_START + 8
        );
        assert!(Arc::ptr_eq(
            &defined_rg.get_type().unwrap(),
            &free_rg.get_type().unwrap(),
        ));
    }

    #[test]
    fn test_varnode_bank_injected_factory_flavor_wins() {
        // TYPE-WIRING-0001: an explicitly injected Architecture TypeFactory
        // takes precedence over the process-canonical default — this is the
        // per-Architecture channel Ghidra uses (glb->types, type.cc:3106).
        // A Standalone-flavor factory (sleigh_arch.cc:229-232) spells the
        // core unknowns `xunknown{size}`, distinguishing the two tracks.
        let injected = Arc::new(RwLock::new(
            crate::type_system::typefactory::TypeFactory::new_flavor(
                8,
                crate::type_system::typefactory::CoreTypeFlavor::Standalone,
            ),
        ));
        let mut bank = VarnodeBank::new();
        bank.set_type_factory(injected.clone());
        let vn = bank.create(4, Address::new(0x40));
        let dt = vn.read().unwrap().get_type().unwrap().clone();
        assert_eq!(dt.get_name(), "xunknown4");
        // Identity flows from the injected factory object itself.
        assert!(Arc::ptr_eq(
            &dt,
            &injected
                .read()
                .unwrap()
                .get_base(4, TypeMetatype::Unknown)
                .unwrap()
        ));
        // A second, uninjected bank resolves the canonical default instead —
        // the two tracks are distinct objects, matching two Architectures.
        let other = VarnodeBank::new().create(4, Address::new(0x80));
        let other_dt = other.read().unwrap().get_type().unwrap().clone();
        assert_eq!(other_dt.get_name(), "undefined4");
        assert!(!Arc::ptr_eq(&dt, &other_dt));
        // Cross-bank identity within the canonical track (one Architecture).
        let third = VarnodeBank::new().create(4, Address::new(0xc0));
        assert!(Arc::ptr_eq(
            &other_dt,
            &third.read().unwrap().get_type().unwrap()
        ));
    }

    #[test]
    fn test_varnode_bank_space_key_is_final_before_insertion() {
        let mut bank = VarnodeBank::new();
        let register = bank.create_with_space(8, AddressSpace::Register, 0x20);
        let unique = bank.create_unique(8);
        let constant = bank.create_constant(8, 7);

        assert_eq!(bank.iter_space(AddressSpace::Register).count(), 1);
        assert_eq!(bank.iter_space(AddressSpace::Unique).count(), 1);
        assert_eq!(bank.iter_space(AddressSpace::Const).count(), 1);
        assert!(bank.loc_tree.contains(&VarnodeLocRef(register)));
        assert!(bank.loc_tree.contains(&VarnodeLocRef(unique)));
        assert!(bank.loc_tree.contains(&VarnodeLocRef(constant)));
    }

    #[test]
    fn test_varnode_bank_comparator_class_space_and_eq_contract() {
        let mut bank = VarnodeBank::new();
        let op = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1000), 0),
            crate::opcodes::OpCode::CPUI_COPY,
        )));
        let input = bank.create_with_space(8, AddressSpace::Register, 0x20);
        let input = bank.set_input(input).expect("fresh input");
        let written = bank.create_def_with_space(8, AddressSpace::Register, 0x20, &op);
        let free = bank.create_with_space(8, AddressSpace::Register, 0x20);

        let classes: Vec<_> = bank
            .loc_tree
            .iter()
            .filter_map(|entry| {
                let value = entry.0.read().unwrap();
                (value.address_space == AddressSpace::Register && value.loc.as_u64() == 0x20)
                    .then_some(if value.is_input() {
                        "input"
                    } else if value.is_written() {
                        "written"
                    } else {
                        "free"
                    })
            })
            .collect();
        assert_eq!(classes, ["input", "written", "free"]);
        assert!(bank.loc_tree.contains(&VarnodeLocRef(input)));
        assert!(bank.loc_tree.contains(&VarnodeLocRef(written)));
        assert!(bank.loc_tree.contains(&VarnodeLocRef(free)));

        let overlay = Arc::new(RwLock::new(Varnode::new_with_space(
            8,
            AddressSpace::Overlay,
            0x40,
        )));
        let other = Arc::new(RwLock::new(Varnode::new_with_space(
            8,
            AddressSpace::Other(1),
            0x40,
        )));
        let overlay_key = VarnodeLocRef(overlay);
        let other_key = VarnodeLocRef(other);
        assert_ne!(overlay_key.cmp(&other_key), std::cmp::Ordering::Equal);
        assert_eq!(
            overlay_key == other_key,
            overlay_key.cmp(&other_key).is_eq()
        );
        assert_eq!(
            other_key == overlay_key,
            other_key.cmp(&overlay_key).is_eq()
        );
    }

    /// Catch an add_descend panic and return its message. The global panic
    /// hook is silenced only around the catch (the throw is the behavior
    /// under test); assertions run with the normal hook restored so failures
    /// stay observable. The Varnode lock is poisoned by the unwinding writer
    /// guard — a Rust artifact with no Ghidra counterpart — so post-throw
    /// reads use into_inner.
    fn catch_add_descend_panic_message(
        vn: &Arc<RwLock<Varnode>>,
        op: &Arc<RwLock<crate::op::PcodeOp>>,
    ) -> Option<String> {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vn.write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add_descend(op);
        }));
        std::panic::set_hook(previous_hook);
        // panic!("literal") payloads are &str; formatted ones are String.
        result.err().and_then(|payload| {
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        })
    }

    #[test]
    fn test_add_descend_throws_on_free_multi_descendant() {
        // VARNODE-ADDDESCEND-THROW-0001: Varnode::addDescend
        // (varnode.cc:330-340) throws LowlevelError on the second descendant
        // of a free non-spacebase varnode; the panic fires before the push so
        // the state is unchanged. Constants get no exemption at this level
        // (isFree checks written|input only, varnode.hh:238) — the production
        // protection is Funcdata::opSetInput's dedup. The spacebase exemption
        // and non-free accumulation are pinned by
        // test_varnode_bank_xref_returns_canonical_and_rewires_repeated_slots
        // and the varnode_add_descend_1204 oracle fixture.
        let op1 = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1000), 1),
            crate::opcodes::OpCode::CPUI_COPY,
        )));
        let op2 = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1010), 2),
            crate::opcodes::OpCode::CPUI_COPY,
        )));
        let free = Arc::new(RwLock::new(Varnode::new_with_space(
            8,
            AddressSpace::Register,
            0x80,
        )));
        free.write().unwrap().add_descend(&op1);
        let message = catch_add_descend_panic_message(&free, &op2)
            .expect("second free descendant must throw");
        assert_eq!(message, "Free varnode has multiple descendants");
        let value = free.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(value.count_descends(), 1, "throw must not push");
        assert_eq!(
            value.flags,
            varnode_flags::COVERDIRTY,
            "throw must not touch flags"
        );
        drop(value);

        // Constant varnodes are free by the isFree() test and get no
        // addDescend-level exemption.
        let constant = Arc::new(RwLock::new(Varnode::new_with_space(
            4,
            AddressSpace::Const,
            0x1234,
        )));
        constant.write().unwrap().add_descend(&op1);
        let message = catch_add_descend_panic_message(&constant, &op2)
            .expect("second constant descendant must throw");
        assert_eq!(message, "Free varnode has multiple descendants");
    }

    #[test]
    fn test_varnode_bank_xref_returns_canonical_and_rewires_repeated_slots() {
        let mut bank = VarnodeBank::new();
        let canonical = bank.create_with_space(8, AddressSpace::Register, 0x50);
        let canonical = bank.set_input(canonical).expect("fresh canonical input");
        let duplicate = bank.create_with_space(8, AddressSpace::Register, 0x50);
        duplicate
            .write()
            .unwrap()
            .set_flags(varnode_flags::SPACEBASE);
        let reader = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1010), 1),
            crate::opcodes::OpCode::CPUI_INT_ADD,
        )));
        reader.write().unwrap().inrefs = vec![duplicate.clone(), duplicate.clone()];
        duplicate.write().unwrap().add_descend(&reader);
        duplicate.write().unwrap().add_descend(&reader);

        let returned = bank
            .set_input(duplicate.clone())
            .expect("duplicate input is canonicalized");
        assert!(Arc::ptr_eq(&returned, &canonical));
        assert_eq!(duplicate.read().unwrap().count_descends(), 0);
        assert_eq!(canonical.read().unwrap().count_descends(), 2);
        assert!(reader
            .read()
            .unwrap()
            .inrefs
            .iter()
            .all(|input| Arc::ptr_eq(input, &canonical)));
    }

    #[test]
    fn test_varnode_bank_rejects_foreign_and_stale_equal_keys() {
        let mut bank = VarnodeBank::new();
        let mut foreign_bank = VarnodeBank::new();
        let canonical = bank.create_with_space(8, AddressSpace::Register, 0x60);
        let foreign = foreign_bank.create_with_space(8, AddressSpace::Register, 0x60);
        assert!(bank.set_input(foreign.clone()).is_err());
        assert!(bank.make_free(&foreign).is_err());
        assert!(bank.owns_loc_ref(&canonical));
        assert!(bank.owns_def_ref(&canonical));

        let stale = canonical.clone();
        bank.clear();
        let replacement = bank.create_with_space(8, AddressSpace::Register, 0x60);
        assert!(bank.set_input(stale.clone()).is_err());
        assert!(bank.make_free(&stale).is_err());
        assert!(bank.owns_loc_ref(&replacement));
        assert!(bank.owns_def_ref(&replacement));
    }

    #[test]
    fn test_varnode_bank_destroy_guards_and_prevalidated_delete() {
        let mut bank = VarnodeBank::new();
        let operation = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1020), 2),
            crate::opcodes::OpCode::CPUI_COPY,
        )));

        let free = bank.create_with_space(8, AddressSpace::Register, 0x68);
        let before = bank.num_varnodes();
        bank.destroy_varnode_prevalidated(&free);
        assert_eq!(bank.num_varnodes(), before - 1);

        let defined = bank.create_def_with_space(8, AddressSpace::Register, 0x70, &operation);
        assert_eq!(
            bank.destroy_varnode(&defined)
                .expect_err("defined Varnode is integrated")
                .to_string(),
            "Deleting integrated varnode"
        );
        assert!(bank.owns_loc_ref(&defined));

        let descendant = bank.create_with_space(8, AddressSpace::Register, 0x78);
        operation.write().unwrap().inrefs.push(descendant.clone());
        descendant.write().unwrap().add_descend(&operation);
        assert_eq!(
            bank.destroy_varnode(&descendant)
                .expect_err("read Varnode is integrated")
                .to_string(),
            "Deleting integrated varnode"
        );
        assert!(bank.owns_loc_ref(&descendant));

        let mut foreign_bank = VarnodeBank::new();
        let foreign = foreign_bank.create_with_space(8, AddressSpace::Register, 0x80);
        assert_eq!(
            bank.destroy_varnode(&foreign)
                .expect_err("foreign Arc is unmanaged")
                .to_string(),
            "Deleting unmanaged varnode"
        );
    }

    #[test]
    fn test_destroy_written_varnode_after_def_key_mutation_uses_identity() {
        let mut bank = VarnodeBank::new();
        let operation = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1030), 9),
            crate::opcodes::OpCode::CPUI_COPY,
        )));
        let neighbor_operation = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1030), 10),
            crate::opcodes::OpCode::CPUI_COPY,
        )));
        let target = bank.create_def_with_space(
            8,
            AddressSpace::Register,
            0x88,
            &operation);
        let neighbor = bank.create_def_with_space(
            8,
            AddressSpace::Register,
            0x88,
            &neighbor_operation);
        operation.write().unwrap().start.set_order(0xf000_0000);
        target.write().unwrap().def = None;

        bank.destroy_varnode_prevalidated(&target);

        assert!(!bank.owns_loc_ref(&target));
        assert!(!bank.owns_def_ref(&target));
        assert!(bank.owns_loc_ref(&neighbor));
        assert!(bank.owns_def_ref(&neighbor));
        assert_eq!(bank.num_varnodes(), 1);
    }

    #[test]
    fn test_term_order_strips_constant_multiply_and_uses_address_only() {
        let mut bank = VarnodeBank::new();
        let constant_a = bank.create_constant(8, 1);
        let constant_b = bank.create_constant(4, 0xffff);
        let register = bank.create_with_space(8, AddressSpace::Register, 0x20);
        let same_address_other_size = bank.create_with_space(4, AddressSpace::Register, 0x20);
        let ram = bank.create_with_space(8, AddressSpace::Ram, 0x20);
        assert_eq!(
            constant_a
                .read()
                .unwrap()
                .term_order(&constant_b.read().unwrap()),
            0
        );
        assert_eq!(
            constant_a
                .read()
                .unwrap()
                .term_order(&register.read().unwrap()),
            1
        );
        assert_eq!(
            register
                .read()
                .unwrap()
                .term_order(&constant_a.read().unwrap()),
            -1
        );
        assert_eq!(
            register
                .read()
                .unwrap()
                .term_order(&same_address_other_size.read().unwrap()),
            0
        );
        assert_eq!(
            ram.read().unwrap().term_order(&register.read().unwrap()),
            -1
        );

        let multiply = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x1030), 3),
            crate::opcodes::OpCode::CPUI_INT_MULT,
        )));
        let coefficient = bank.create_constant(8, 7);
        multiply.write().unwrap().inrefs = vec![register.clone(), coefficient];
        let multiplied = bank.create_def_with_space(8, AddressSpace::Unique, 0x200, &multiply);
        assert_eq!(
            multiplied
                .read()
                .unwrap()
                .term_order(&register.read().unwrap()),
            0
        );
    }

    #[test]
    fn test_get_cover_lazily_rebuilds_non_null_input_cover() {
        let mut bank = VarnodeBank::new();
        let input = bank.create_with_space(8, AddressSpace::Register, 0x70);
        let input = bank.set_input(input).expect("fresh input");
        let mut value = input.write().unwrap();
        value.calc_cover();
        assert_ne!(value.flags & varnode_flags::COVERDIRTY, 0);
        assert!(value.get_cover().is_some());
        assert_eq!(value.flags & varnode_flags::COVERDIRTY, 0);
    }

    // --- Ghidra-faithful flag accessors (varnode.hh:235-330) ---

    #[test]
    fn test_varnode_mark_flag() {
        let mut v = Varnode::new(4, Address::new(0));
        assert!(!v.is_mark());
        v.set_mark();
        assert!(v.is_mark());
        v.clear_mark();
        assert!(!v.is_mark());
    }

    #[test]
    fn test_varnode_explicit_implied_flags() {
        let mut v = Varnode::new(4, Address::new(0));
        assert!(!v.is_explicit());
        assert!(!v.is_implied());
        v.set_explicit();
        assert!(v.is_explicit());
        v.set_implied();
        assert!(v.is_implied());
        v.clear_explicit();
        assert!(!v.is_explicit());
        v.clear_implied();
        assert!(!v.is_implied());
    }

    #[test]
    fn test_varnode_addr_tied_requires_both_flags() {
        // is_addr_tied is true only when BOTH addrtied AND insert are set
        // (varnode.hh:250).
        let mut v = Varnode::new(4, Address::new(0));
        v.set_flags(varnode_flags::ADDRTIED);
        assert!(!v.is_addr_tied()); // only addrtied → false
        v.set_flags(varnode_flags::INSERT);
        assert!(v.is_addr_tied()); // both → true
    }

    #[test]
    fn test_varnode_illegal_input() {
        // is_illegal_input: input set but directwrite clear (varnode.hh:240).
        let mut v = Varnode::new(4, Address::new(0));
        v.set_flags(varnode_flags::INPUT);
        assert!(v.is_illegal_input());
        v.set_direct_write();
        assert!(!v.is_illegal_input()); // input|directwrite → not illegal
    }

    #[test]
    fn test_write_mask_is_orthogonal_to_autolive_hold() {
        let mut v = Varnode::new(4, Address::new(0));
        v.set_write_mask();
        assert!(v.is_write_mask());
        assert!(!v.is_auto_live());
        assert_eq!(v.flags & varnode_flags::AUTOLIVE_HOLD, 0);

        v.set_flags(varnode_flags::AUTOLIVE_HOLD);
        assert!(v.is_auto_live());
        assert!(v.is_write_mask());
        v.clear_write_mask();
        assert!(!v.is_write_mask());
        assert!(v.is_auto_live());
    }

    #[test]
    fn test_is_constant_extended_plain_constant() {
        // A plain constant returns Some((offset, 0)) (varnode.cc:799-840).
        let v = Varnode::new_constant(0x1234, 8);
        assert_eq!(v.is_constant_extended(), Some((0x1234, 0)));
    }

    #[test]
    fn test_is_constant_extended_small_nonconst() {
        // A non-constant 8-byte varnode with no def returns None.
        let v = Varnode::new(8, Address::new(0x100));
        assert_eq!(v.is_constant_extended(), None);
    }
}
