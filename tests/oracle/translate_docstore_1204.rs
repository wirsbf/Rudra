//! Translate::initialize / DocumentStorage oracle fixture
//! (TRANSLATE-DOCSTORE-UNIFY-0001).
//!
//! Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//!
//! Mirrors `translate_docstore_1204.cc` record for record. Rudra has no
//! production Translate engine yet, so this fixture defines a local probe
//! implementor of `rudra::translate::Translate` whose `initialize` mirrors
//! the DocumentStorage consumption prologue of `Sleigh::initialize`
//! (sleigh.cc:558-565): `getTag("sleigh")` miss panics with the exact
//! LowlevelError message, and a registered `<sleigh>` element's content is
//! used as the .sla path whose failed open surfaces verbatim in the panic
//! message. The unified concrete `rudra::marshal::DocumentStorage`
//! (xml.cc:2435-2478) is the store type, exactly like the C++
//! `initialize(DocumentStorage &store)` parameter (translate.hh:332).
//! Panics stand in for LowlevelError per the translate.rs convention; the
//! runner diffs both outputs byte for byte.

use rudra::address::Address;
use rudra::float_emulate::FloatFormat;
use rudra::marshal::DocumentStorage;
use rudra::space::{AddressSpace, VarnodeData};
use rudra::translate::{AddrSpaceManager, AssemblyEmit, PcodeEmit, Translate};
use std::collections::HashMap;

/// Fixture-local probe engine. Only `initialize` carries observable
/// behavior (the DocumentStorage contract under test); every other trait
/// method is an inert stub and is never invoked by this fixture.
struct SleighInitProbe {
    manager: AddrSpaceManager,
}

impl SleighInitProbe {
    fn new() -> Self {
        SleighInitProbe {
            manager: AddrSpaceManager::new(),
        }
    }
}

impl Translate for SleighInitProbe {
    // Fixture stub: composition base, not under test.
    fn manager(&self) -> &AddrSpaceManager {
        &self.manager
    }
    // Fixture stub: composition base, not under test.
    fn manager_mut(&mut self) -> &mut AddrSpaceManager {
        &mut self.manager
    }
    // Fixture stub: not under test.
    fn is_big_endian(&self) -> bool {
        false
    }
    // Fixture stub: not under test.
    fn get_alignment(&self) -> i32 {
        1
    }
    // Fixture stub: not under test.
    fn get_unique_base(&self) -> u32 {
        0
    }
    // Fixture stub: not under test.
    fn get_float_format(&self, _size: usize) -> Option<&FloatFormat> {
        None
    }

    // Ghidra: sleigh.cc:555 Sleigh::initialize — DocumentStorage prologue
    /// Mirrors sleigh.cc:558-565 exactly up to (not including) .sla ingest:
    /// `getTag("sleigh")` miss -> LowlevelError "Could not find sleigh tag";
    /// element content is the .sla path; failed open ->
    /// "Could not open .sla file: <content>".
    fn initialize(&mut self, store: &mut DocumentStorage) {
        // const Element *el = store.getTag("sleigh");
        // if (el == (const Element *)0) throw LowlevelError(...);
        let el = match store.get_tag("sleigh") {
            Some(el) => el.clone(),
            None => panic!("Could not find sleigh tag"),
        };
        // ifstream s(el->getContent(), std::ios_base::binary);
        // if (!s) throw LowlevelError("Could not open .sla file: " + content);
        let slafile = el
            .read()
            .expect("element lock poisoned")
            .get_content()
            .to_string();
        if std::fs::File::open(&slafile).is_err() {
            panic!("Could not open .sla file: {}", slafile);
        }
        // sla::FormatDecode ingest + Sleigh::decode are the SLEIGH engine
        // domain; this fixture never registers an openable .sla path.
        unreachable!("sla ingest is not exercised by this fixture");
    }

    // Fixture stub: not under test.
    fn get_register(&self, _nm: &str) -> VarnodeData {
        unreachable!("not exercised by this fixture")
    }
    // Fixture stub: not under test.
    fn get_register_name(&self, _base: AddressSpace, _off: u64, _size: usize) -> String {
        String::new()
    }
    // Fixture stub: not under test.
    fn get_exact_register_name(
        &self,
        _base: AddressSpace,
        _off: u64,
        _size: usize,
    ) -> String {
        String::new()
    }
    // Fixture stub: not under test.
    fn get_all_registers(&self, _reglist: &mut HashMap<VarnodeData, String>) {}
    // Fixture stub: not under test.
    fn get_user_op_names(&self, _res: &mut Vec<String>) {}
    // Fixture stub: not under test.
    fn instruction_length(&self, _baseaddr: Address) -> i32 {
        0
    }
    // Fixture stub: not under test.
    fn one_instruction(&mut self, _emit: &mut dyn PcodeEmit, _baseaddr: Address) -> i32 {
        0
    }
    // Fixture stub: not under test.
    fn print_assembly(&mut self, _emit: &mut dyn AssemblyEmit, _baseaddr: Address) -> i32 {
        0
    }
}

/// Drive the probe exactly like the C++ harness drives `Sleigh::initialize`,
/// catching the LowlevelError-equivalent panic and printing `I|label|msg`.
fn run_initialize(label: &str, trans: &mut SleighInitProbe, store: &mut DocumentStorage) {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        trans.initialize(store);
    }));
    std::panic::set_hook(prev_hook);
    match result {
        Ok(()) => println!("I|{}|UNEXPECTED_OK", label),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "UNKNOWN_PANIC".to_string()
            };
            println!("I|{}|{}", label, msg);
        }
    }
}

fn parse_and_register(store: &mut DocumentStorage, text: &[u8]) {
    let doc = store.parse_document(text).expect("fixture parse");
    let root = doc.get_root().expect("fixture root").clone();
    store.register_tag(&root);
}

fn main() {
    // -- case 1: empty store -> getTag miss -> exact message ----------------
    {
        let mut trans = SleighInitProbe::new();
        let mut store = DocumentStorage::new();
        run_initialize("no_tag", &mut trans, &mut store);
    }

    // -- case 2: only a differently-named tag is registered -----------------
    {
        let mut trans = SleighInitProbe::new();
        let mut store = DocumentStorage::new();
        parse_and_register(&mut store, b"<processor_spec><programcounter/></processor_spec>");
        run_initialize("wrong_name", &mut trans, &mut store);
    }

    // -- case 3: registered <sleigh> tag, nonexistent .sla path -------------
    {
        let mut trans = SleighInitProbe::new();
        let mut store = DocumentStorage::new();
        parse_and_register(
            &mut store,
            b"<sleigh>/nonexistent/translate/docstore/first.sla</sleigh>",
        );
        run_initialize("bad_path", &mut trans, &mut store);
    }

    // -- case 4: same-name overwrite: second registration wins --------------
    {
        let mut trans = SleighInitProbe::new();
        let mut store = DocumentStorage::new();
        parse_and_register(
            &mut store,
            b"<sleigh>/nonexistent/translate/docstore/first.sla</sleigh>",
        );
        parse_and_register(
            &mut store,
            b"<sleigh>/nonexistent/translate/docstore/second.sla</sleigh>",
        );
        run_initialize("overwrite", &mut trans, &mut store);
    }

    // -- case 5: multi-tag store, name-keyed lookup isolation ---------------
    {
        let mut trans = SleighInitProbe::new();
        let mut store = DocumentStorage::new();
        parse_and_register(&mut store, b"<compiler_spec><default_proto/></compiler_spec>");
        parse_and_register(
            &mut store,
            b"<sleigh>/nonexistent/translate/docstore/multi.sla</sleigh>",
        );
        println!(
            "I|multi_siblings|{}",
            store.get_tag("compiler_spec").is_some() as u8
        );
        run_initialize("multi", &mut trans, &mut store);
    }

    println!("S|DONE");
}
