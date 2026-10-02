// PRINTC-PTRCONST-DAT-SYMBOL-0001 Rudra comparand for the locked Ghidra
// 12.0.4 PrintC::pushConstant -> pushPtrCharConstant path. Mirrors the C++
// fixture tests/oracle/printc_ptrconst_1204.cc record-for-record: the
// Architecture-owned Java-contract StringManager (fd.arch.string_manager),
// the symboltab readonly property map, a contextual AddressResolver on the
// ram data space, and the TYPE_SPACEBASE arm of op_ptrsub run against one
// attempt-counting loadimage, with the rendered text and read counts
// observed per record.

use rudra::address::{Address, SeqNum};
use rudra::database::{Database, Symbol};
use rudra::funcdata::Funcdata;
use rudra::loadimage::LoadImage;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::printlanguage::PrintLanguage;
use rudra::space::AddressSpace;
use rudra::stringmanage::StringManager;
use rudra::translate::{AddressResolver, AddrSpaceManager};
use rudra::type_system::datatype::{
    Datatype, TypeBase, TypeMetatype, TypePointer, TypeSpacebase,
};
use rudra::variable::HighVariable;
use rudra::varnode::{varnode_flags, Varnode};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

struct Region {
    start: u64,
    bytes: Vec<u8>,
}

struct FixtureLoader {
    regions: Vec<Region>,
    // Attempt counts keyed by read start offset; failed attempts (which
    // return DataUnavailError) would be counted too.
    attempts: Mutex<BTreeMap<u64, usize>>,
}

impl FixtureLoader {
    fn new() -> Arc<Self> {
        fn region(start: u64, contents: &[u8], padded: usize) -> Region {
            let mut bytes = vec![0u8; padded];
            bytes[..contents.len()].copy_from_slice(contents);
            Region { start, bytes }
        }
        // 2050 'A's then the NUL: under the declared Java contract the
        // detection is unbounded, the return truncates at 2048 chars with
        // isTruncated set.
        let mut long_string = vec![b'A'; 2050];
        long_string.push(0);
        Arc::new(Self {
            regions: vec![
                region(0x2000, b"alpha\0", 0x100),
                region(0x2100, &[b'b', 0xad, 0], 0x100),
                region(0x2200, b"writable\0", 0x100),
                region(0x2300, b"prefix\0", 0x100),
                region(0x2400, &long_string, 0xc00),
            ],
            attempts: Mutex::new(BTreeMap::new()),
        })
    }

    fn attempt_count(&self, address: u64) -> usize {
        *self.attempts.lock().unwrap().get(&address).unwrap_or(&0)
    }
}

impl LoadImage for FixtureLoader {
    fn get_filename(&self) -> &str {
        "printc-ptrconst-1204"
    }

    fn load_fill(
        &self,
        size: usize,
        addr: Address,
    ) -> Result<Vec<u8>, rudra::loadimage::DataUnavailError> {
        *self
            .attempts
            .lock()
            .unwrap()
            .entry(addr.as_u64())
            .or_insert(0) += 1;
        let start = addr.as_u64();
        let end = start + size as u64;
        for region in &self.regions {
            if start >= region.start && end <= region.start + region.bytes.len() as u64 {
                let off = (start - region.start) as usize;
                return Ok(region.bytes[off..off + size].to_vec());
            }
        }
        Err(rudra::loadimage::DataUnavailError(format!(
            "Unable to load {size} bytes at {addr:#x}"
        )))
    }

    fn get_arch_type(&self) -> String {
        "fixture:x86:LE:64".to_string()
    }

    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// The contextual resolver of the C++ fixture: value 0x40 resolves by the
/// consuming op's address (translate.cc:628-641 dispatch).
struct ContextResolver;

impl AddressResolver for ContextResolver {
    fn resolve(
        &mut self,
        value: u64,
        size: i32,
        point: Address,
        full_encoding: &mut u64,
    ) -> Address {
        assert!(size == 8 || size == -1, "ptrconst fixture expected an 8-byte pointer");
        let resolved = match (value, point.as_u64()) {
            (0x40, 0x5000) => 0x2000,
            (0x40, 0x5008) => 0x2303,
            _ => value,
        };
        *full_encoding = resolved;
        Address::new(resolved)
    }
}

fn char_pointer_type() -> Arc<Datatype> {
    // The C++ fixture's types->getTypePointer(8, getTypeChar(1), 1) names the
    // pointer "char *"; same input here (the name renders in cast records).
    let character = Arc::new(Datatype::Base(TypeBase::new_char(
        "char".to_string(),
        TypeMetatype::Int,
    )));
    let mut pointer = TypePointer::new(8, character, 1);
    pointer.base.name = "char *".to_string();
    Arc::new(Datatype::Pointer(pointer))
}

fn spacebase_pointer_type() -> Arc<Datatype> {
    let spacebase = TypeSpacebase::new_global(Address::new(0));
    Arc::new(Datatype::Pointer(TypePointer::new(
        8,
        Arc::new(Datatype::Spacebase(spacebase)),
        1,
    )))
}

fn typed_constant(value: u64, pointer: &Arc<Datatype>) -> Arc<RwLock<Varnode>> {
    let mut varnode = Varnode::new_with_space(8, AddressSpace::Const, value);
    varnode.update_type(pointer.clone());
    let varnode = Arc::new(RwLock::new(varnode));
    let mut high = HighVariable::new(pointer.clone());
    high.add_instance(varnode.clone());
    varnode.write().unwrap().high = Some(Arc::new(RwLock::new(high)));
    varnode
}

fn call_op(input: Arc<RwLock<Varnode>>, usepoint: u64, time: u32) -> Arc<RwLock<PcodeOp>> {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(usepoint), time), OpCode::CPUI_CALL);
    op.set_opcode_flags(OpCode::CPUI_CALL);
    op.inrefs.push(Arc::new(RwLock::new(Varnode::new_with_space(
        8,
        AddressSpace::Const,
        0,
    ))));
    op.inrefs.push(input);
    Arc::new(RwLock::new(op))
}

/// PTRSUB(spacebase-pointer, constant) with the constant's HighVariable
/// optionally carrying the DAT Symbol as a constant-address reference at
/// offset 0 (variable.cc:283-289), mirroring the C++ fixture's
/// HighVariable::setSymbolReference.
fn spacebase_ptrsub(
    spacebase_pointer: &Arc<Datatype>,
    dat_symbol: Option<Arc<RwLock<Symbol>>>,
    offset: u64,
    usepoint: u64,
    time: u32,
) -> Arc<RwLock<PcodeOp>> {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(usepoint), time), OpCode::CPUI_PTRSUB);
    op.set_opcode_flags(OpCode::CPUI_PTRSUB);
    let base = typed_constant(0, spacebase_pointer);
    op.inrefs.push(base);
    let off = {
        let varnode = Arc::new(RwLock::new(Varnode::new_with_space(
            8,
            AddressSpace::Const,
            offset,
        )));
        let mut high = HighVariable::new(Arc::new(Datatype::Base(TypeBase::new(
            String::new(),
            8,
            TypeMetatype::Unknown,
        ))));
        high.add_instance(varnode.clone());
        if let Some(sym) = dat_symbol {
            high.set_symbol_reference(sym, 0);
        }
        varnode.write().unwrap().high = Some(Arc::new(RwLock::new(high)));
        varnode
    };
    op.inrefs.push(off);
    Arc::new(RwLock::new(op))
}

fn render_constant(
    printer: &mut PrintC,
    label: &str,
    value: u64,
    pointer: &Arc<Datatype>,
    varnode: &Arc<RwLock<Varnode>>,
    op: &Arc<RwLock<PcodeOp>>,
) {
    printer.get_emit().print(label);
    printer.get_emit().print("=");
    printer.push_constant_typed(
        value,
        pointer,
        Some(&varnode.read().unwrap()),
        Some(&op.read().unwrap()),
    );
    printer.get_emit().print("\n");
}

fn main() {
    let loader = FixtureLoader::new();
    let pointer = char_pointer_type();

    // The Architecture-owned shared manager (fd.arch.string_manager) and the
    // symboltab readonly property map, as in the C++ fixture.
    let mut arch = rudra::arch::Architecture::new();
    arch.set_string_manager(Arc::new(RwLock::new(StringManager::new_ghidra_contract(
        loader.clone(),
        2048,
    ))));
    let mut db = Database::new(false);
    for (first, last) in [(0x2000u64, 0x21ffu64), (0x2300, 0x23ff), (0x2400, 0x2fff)] {
        if let Some(range) = rudra::address::Range::new(Address::new(first), Address::new(last)) {
            db.set_property_range(varnode_flags::READONLY, range);
        }
    }
    arch.symboltab = Some(Arc::new(RwLock::new(db)));

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));

    // Load the snapshots through the production doc_function entry on a
    // Funcdata carrying the Architecture (string_manager + symboltab), then
    // discard the function document and swap in the recording emitter.
    let mut symbols = Funcdata::new("ptrconst_fixture", Address::new(0x1000), 0x10);
    symbols.set_arch(Arc::new(arch));
    printer.doc_function_inherent(&symbols);
    printer.set_emit(Box::new(EmitNoMarkup::new()));

    // The contextual resolver manager (glb->resolveConstant's AddrSpaceManager)
    // with ram as both default code and default data space.
    let mut spaceman = AddrSpaceManager::new();
    spaceman.insert_space(AddressSpace::Const);
    spaceman.insert_space(AddressSpace::Ram);
    let ram_index = spaceman
        .base_list
        .iter()
        .position(|s| matches!(s, Some(AddressSpace::Ram)))
        .expect("ram space inserted");
    spaceman.set_default_code_space(ram_index);
    spaceman.set_default_data_space(ram_index);
    while spaceman.resolve_list.len() <= ram_index {
        spaceman.resolve_list.push(None);
    }
    spaceman.resolve_list[ram_index] = Some(Box::new(ContextResolver));
    printer.set_space_manager(Arc::new(RwLock::new(spaceman)));

    let valid = typed_constant(0x2000, &pointer);
    render_constant(&mut printer, "valid_ascii", 0x2000, &pointer, &valid,
                    &call_op(valid.clone(), 0x4000, 1));
    let valid_repeat = typed_constant(0x2000, &pointer);
    render_constant(&mut printer, "valid_ascii_repeat", 0x2000, &pointer, &valid_repeat,
                    &call_op(valid_repeat.clone(), 0x4008, 2));

    let invalid = typed_constant(0x2100, &pointer);
    render_constant(&mut printer, "invalid_constant", 0x2100, &pointer, &invalid,
                    &call_op(invalid.clone(), 0x4010, 3));
    let invalid_repeat = typed_constant(0x2100, &pointer);
    render_constant(&mut printer, "invalid_constant_repeat", 0x2100, &pointer, &invalid_repeat,
                    &call_op(invalid_repeat.clone(), 0x4018, 4));

    let truncated = typed_constant(0x2400, &pointer);
    render_constant(&mut printer, "trunc_literal", 0x2400, &pointer, &truncated,
                    &call_op(truncated.clone(), 0x4020, 5));

    let writable = typed_constant(0x2200, &pointer);
    render_constant(&mut printer, "nonreadonly", 0x2200, &pointer, &writable,
                    &call_op(writable.clone(), 0x4028, 6));

    let null_pointer = typed_constant(0, &pointer);
    render_constant(&mut printer, "null", 0, &pointer, &null_pointer,
                    &call_op(null_pointer.clone(), 0x4030, 7));

    let substring = typed_constant(0x2303, &pointer);
    render_constant(&mut printer, "substring", 0x2303, &pointer, &substring,
                    &call_op(substring.clone(), 0x4038, 8));

    let context_a = typed_constant(0x40, &pointer);
    render_constant(&mut printer, "context_a", 0x40, &pointer, &context_a,
                    &call_op(context_a.clone(), 0x5000, 9));
    let context_b = typed_constant(0x40, &pointer);
    render_constant(&mut printer, "context_b", 0x40, &pointer, &context_b,
                    &call_op(context_b.clone(), 0x5008, 10));

    // The &DAT_* form (printc.cc:1057-1097): PTRSUB off the global spacebase
    // whose offset constant carries the DAT symbol reference, and the same
    // PTRSUB without a symbol (pushUnnamedLocation).
    let spacebase_pointer = spacebase_pointer_type();
    let dat_symbol = Arc::new(RwLock::new(Symbol::new(0, "DAT_00002100", "char")));
    printer.get_emit().print("dat_symbol=");
    printer.op_ptrsub(&spacebase_ptrsub(&spacebase_pointer, Some(dat_symbol), 0x2100, 0x4040, 11)
        .read().unwrap());
    printer.get_emit().print("\n");
    printer.get_emit().print("dat_symbol_unnamed=");
    printer.op_ptrsub(&spacebase_ptrsub(&spacebase_pointer, None, 0x2100, 0x4048, 12)
        .read().unwrap());
    printer.get_emit().print("\n");

    printer.get_emit().print(&format!(
        "reads.2000={}\nreads.2100={}\nreads.2200={}\nreads.2303={}\nreads.2400={}\n",
        loader.attempt_count(0x2000),
        loader.attempt_count(0x2100),
        loader.attempt_count(0x2200),
        loader.attempt_count(0x2303),
        loader.attempt_count(0x2400),
    ));

    let emitter = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC ptrconst fixture emitter type");
    let output = emitter.get_output();
    print!("{output}");
    if !output.ends_with('\n') {
        println!();
    }
}
