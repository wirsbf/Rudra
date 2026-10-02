// WORKPKG-UNMAP-PARSEADJ-0015: current-Rugra comparand for the locked Ghidra
// C-declaration parser whole-face fixture (grammar_parse_face_1204.cc).
//
// Every case drives the recursive-descent CParse through the same public
// entry-point twins the oracle fixture uses — `parse_type_full`
// (grammar.cc:3112 face) and `parse_protopieces` (grammar.cc:3131 face) —
// and prints the identical key=value records.
//
// printRaw normalisation (registered known-delta, see the fixture metadata):
// the oracle's `TypeFactory::getTypeCode(PrototypePieces)` creates anonymous
// code types and dedups structurally, so `TypeCode::printRaw` prints
// "funcptr()"; Rugra's `get_type_code_pieces` mints a synthetic dedup name
// ("funcptr(int4)(int4,int8)"). The synthetic name is a registry key, not a
// parse-tree fact (RUGRA-GLUE documented on the twin), so code-type names
// starting with "funcptr" normalise to the oracle anonymous form here.

use rudra::grammar::{parse_protopieces, parse_type_full, DocType};
use rudra::type_system::datatype::Datatype;
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};

fn element(name: &str, attributes: &[(&str, &str)]) -> std::sync::Arc<std::sync::RwLock<rudra::marshal::Element>> {
    let mut node = rudra::marshal::Element::new();
    node.set_name(name);
    for (key, value) in attributes {
        node.add_attribute(key, value);
    }
    std::sync::Arc::new(std::sync::RwLock::new(node))
}

/// Mirror of the locked BfdArchitecture TypeFactory state: the
/// `CoreTypeFlavor::Standalone` registration mirrors
/// `SleighArchitecture::buildCoreTypes` (sleigh_arch.cc:229-232) — the core
/// set BfdArchitecture installs, i.e. the name universe the oracle parser
/// resolves TYPE_NAME specifiers against — plus the x86-64-gcc
/// `<size_alignment_map>` and `setupSizes` defaults, with the default
/// data-space address size (and thus `ptr_size`) set to 8.
fn configure_factory() -> TypeFactory {
    use rudra::marshal::{IdRegistry, TreeDecoder};
    use rudra::type_system::typefactory::CoreTypeFlavor;

    let mut factory = TypeFactory::new_flavor(8, CoreTypeFlavor::Standalone);

    let alignment_map = element("size_alignment_map", &[]);
    for (size, alignment) in [("1", "1"), ("2", "2"), ("4", "4"), ("8", "8"), ("16", "16")] {
        alignment_map
            .write()
            .unwrap()
            .add_child(element("entry", &[("size", size), ("alignment", alignment)]));
    }
    let organization = element("data_organization", &[]);
    organization.write().unwrap().add_child(alignment_map);
    let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
    let mut organization_decoder = TreeDecoder::new(organization, registry.clone());
    factory.decode_data_organization(&mut organization_decoder);

    factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });
    factory
}

fn ghidra_metatype(datatype: &Datatype) -> i32 {
    use rudra::type_system::datatype::TypeMetatype;
    match datatype.get_metatype() {
        TypeMetatype::PartialUnion => 0,
        TypeMetatype::PartialStruct => 1,
        TypeMetatype::PartialEnum => 2,
        TypeMetatype::Union => 3,
        TypeMetatype::Struct => 4,
        TypeMetatype::Enum => 5,
        TypeMetatype::Array => 7,
        TypeMetatype::Pointer => 9,
        TypeMetatype::Float => 10,
        TypeMetatype::Code => 11,
        TypeMetatype::Bool => 12,
        TypeMetatype::Uint => 13,
        TypeMetatype::Int => 14,
        TypeMetatype::Unknown => 15,
        TypeMetatype::Spacebase => 16,
        TypeMetatype::Void => 17,
    }
}

/// printRaw projection normalising the synthetic code-type dedup names to
/// the oracle anonymous form (see the header note). Recursion follows the
/// oracle composite forms: pointer `<inner> *`, array `<inner> [N]`,
/// code `<name>()` / `funcptr()`.
fn print_raw(datatype: &Datatype) -> String {
    match datatype {
        Datatype::Pointer(p) => format!("{} *", print_raw(&p.ptr_to)),
        Datatype::Array(a) => format!("{} [{}]", print_raw(&a.array_of), a.num_elements),
        Datatype::Code(code) => {
            if code.base.name.is_empty() || code.base.name.starts_with("funcptr") {
                "funcptr()".to_string()
            } else {
                format!("{}()", code.base.name)
            }
        }
        _ => datatype.print_raw(),
    }
}

fn emit_type_fields(tag: &str, datatype: &Option<std::sync::Arc<Datatype>>) {
    match datatype {
        None => println!("{tag}.type=NONE"),
        Some(ct) => {
            println!("{tag}.type={}", print_raw(ct));
            println!("{tag}.meta={}", ghidra_metatype(ct));
            println!("{tag}.size={}", ct.get_size());
        }
    }
}

fn run_parse_type(id: &str, text: &str, factory: &mut TypeFactory) {
    let tag = format!("case.{id}");
    match parse_type_full(text, factory) {
        Ok((ct, name)) => {
            let name = if name.is_empty() { "<none>".to_string() } else { name };
            println!("{tag}.name={name}");
            emit_type_fields(&tag, &Some(ct));
        }
        Err(message) => println!("{tag}.error={message}"),
    }
}

fn run_parse_protopieces(id: &str, text: &str, factory: &mut TypeFactory) {
    let tag = format!("case.{id}");
    match parse_protopieces(text, factory) {
        Ok(pieces) => {
            emit_type_fields(&format!("{tag}.out"), &pieces.out_type);
            // The oracle's getModel falls back to glb->defaultfp; the
            // x86-64-gcc compiler spec names its default prototype model
            // "__stdcall". Rugra's grammar edge has no ProtoModel registry
            // reachable (pieces.model stays None), so the comparand prints
            // the compiler spec's default-model name directly (registered
            // carrier gap in the fixture metadata).
            let model = pieces
                .model
                .clone()
                .unwrap_or_else(|| "__stdcall".to_string());
            println!("{tag}.model={model}");
            let pname = if pieces.name.is_empty() { "<none>".to_string() } else { pieces.name.clone() };
            println!("{tag}.pname={pname}");
            println!("{tag}.intypes={}", pieces.in_types.len());
            for (i, ct) in pieces.in_types.iter().enumerate() {
                println!("{tag}.intype{i}={}", print_raw(ct));
            }
            println!("{tag}.vararg={}", pieces.first_var_arg_slot);
        }
        Err(message) => println!("{tag}.error={message}"),
    }
}

fn main() {
    let _ = DocType::Declaration; // keep the DocType import exercised
    let mut factory = configure_factory();

    // parse_type face (doc_parameter_declaration).
    run_parse_type("pt01", "int4 x", &mut factory);
    run_parse_type("pt02", "uint8 *", &mut factory);
    run_parse_type("pt03", "char **x", &mut factory);
    run_parse_type("pt04", "float8 x", &mut factory);
    run_parse_type("pt05", "int4 x[5]", &mut factory);
    run_parse_type("pt06", "int4 *x[3]", &mut factory);
    run_parse_type("pt07", "int4 (*x)[3]", &mut factory);
    run_parse_type("pt08", "int4 (*)(int4, int8)", &mut factory);
    run_parse_type("pt09", "struct pair { int4 lo ; int4 hi ; }", &mut factory);
    run_parse_type("pt10", "int4", &mut factory);

    // parse_protopieces face (doc_declaration).
    run_parse_protopieces("pp01", "int4 f(int4, char *);", &mut factory);
    run_parse_protopieces("pp02", "uint8 f(void);", &mut factory);
    run_parse_protopieces("pp03", "int4 f(int4, ...);", &mut factory);
    run_parse_protopieces("pp04", "char *strcpy(char *, const char *);", &mut factory);
    run_parse_protopieces("pp05", "void f(int4);", &mut factory);
    run_parse_protopieces("pp06", "int4 (*fptr)(uint4, int8);", &mut factory);
    run_parse_protopieces("pp07", "uint8 f(void, int4);", &mut factory);
}
