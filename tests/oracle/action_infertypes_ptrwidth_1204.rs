use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::FlowBlock;
use rudra::coreaction::ActionInferTypes;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct};
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

struct Cell {
    label: &'static str,
    width: usize,
    is_load: bool,
    op: PcodeOpRef,
    space: VarnodeRef,
    target: VarnodeRef,
    before_type: Arc<Datatype>,
    before_flags: u32,
}

fn meta_name(datatype: &Datatype) -> String {
    format!("{:?}", datatype.get_metatype()).to_ascii_lowercase()
}

fn normalized_type(cell: &Cell, progress: &Arc<Datatype>) -> String {
    let target = cell.target.read().unwrap();
    let datatype = target.v_type.as_ref().expect("production varnode type");
    if Arc::ptr_eq(datatype, progress) {
        return "S32".to_string();
    }
    if datatype.get_size() == cell.width
        && matches!(
            datatype.get_metatype(),
            TypeMetatype::Unknown | TypeMetatype::Array
        )
    {
        return format!("U{}", cell.width);
    }
    format!("{}{}", meta_name(datatype), datatype.get_size())
}

fn operation_label<'a>(cells: &'a [Cell], operation: &PcodeOpRef) -> &'a str {
    cells
        .iter()
        .find(|cell| Arc::ptr_eq(&cell.op.0, &operation.0))
        .map(|cell| cell.label)
        .unwrap_or("?")
}

fn operation_order(cells: &[Cell], operations: &[PcodeOpRef]) -> String {
    operations
        .iter()
        .map(|operation| operation_label(cells, operation))
        .collect::<Vec<_>>()
        .join(",")
}

fn block_order(cells: &[Cell], block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> String {
    operation_order(cells, &block.read().unwrap().get_ops())
}

fn descendant_order(cells: &[Cell], source: &VarnodeRef) -> String {
    source
        .read()
        .unwrap()
        .descend_iter()
        .map(|operation| operation_label(cells, &PcodeOpRef(operation)))
        .collect::<Vec<_>>()
        .join(",")
}

fn target_descendant_shape(cell: &Cell) -> bool {
    let target = cell.target.read().unwrap();
    let descendants = target.descend_iter().collect::<Vec<_>>();
    if cell.is_load {
        descendants.is_empty()
    } else {
        descendants.len() == 1 && Arc::ptr_eq(&descendants[0], &cell.op.0)
    }
}

fn type_snapshot(cells: &[Cell], progress: &Arc<Datatype>) -> String {
    cells
        .iter()
        .map(|cell| {
            let target = cell.target.read().unwrap();
            let datatype = target.v_type.as_ref().expect("production varnode type");
            format!(
                "{}:{}/raw={}/size={}/same_before={}/same_progress={}/flags={}/descendants={}/desc_shape={}",
                cell.label,
                normalized_type(cell, progress),
                meta_name(datatype),
                datatype.get_size(),
                u8::from(Arc::ptr_eq(datatype, &cell.before_type)),
                u8::from(Arc::ptr_eq(datatype, progress)),
                target.flags,
                target.count_descends(),
                u8::from(target_descendant_shape(cell)),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn topology_stable(
    cells: &[Cell],
    source: &VarnodeRef,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
) -> bool {
    {
        let source = source.read().unwrap();
        if !source.is_input()
            || source.is_written()
            || !source.is_type_lock()
            || source.is_mark()
            || source.addlflags != 0
        {
            return false;
        }
    }
    cells.iter().enumerate().all(|(index, cell)| {
        let operation = cell.op.0.read().unwrap();
        let space = cell.space.read().unwrap();
        let target = cell.target.read().unwrap();
        let parent_matches = operation
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|parent| Arc::ptr_eq(&parent, block));
        let common = Arc::ptr_eq(&operation.inrefs[1], source)
            && Arc::ptr_eq(&operation.inrefs[0], &cell.space)
            && space.is_constant()
            && parent_matches
            && !operation.is_dead()
            && !Arc::ptr_eq(&cell.target, source)
            && target.flags == cell.before_flags
            && !target.is_type_lock()
            && !target.is_mark()
            && target.addlflags == 0
            && target_descendant_shape(cell);
        if !common {
            return false;
        }
        if cells[..index].iter().any(|other| {
            Arc::ptr_eq(&cell.op.0, &other.op.0)
                || Arc::ptr_eq(&cell.space, &other.space)
                || Arc::ptr_eq(&cell.target, &other.target)
        }) {
            return false;
        }
        if cell.is_load {
            let def_matches = target
                .get_def()
                .is_some_and(|def| Arc::ptr_eq(&def, &cell.op.0));
            operation.opcode == OpCode::CPUI_LOAD
                && operation
                    .output
                    .as_ref()
                    .is_some_and(|output| Arc::ptr_eq(output, &cell.target))
                && target.is_written()
                && !target.is_input()
                && def_matches
        } else {
            operation.opcode == OpCode::CPUI_STORE
                && Arc::ptr_eq(&operation.inrefs[2], &cell.target)
                && !target.is_written()
                && !target.is_input()
                && target.get_def().is_none()
        }
    })
}

fn main() {
    println!(
        "schema=1|fixture=ACTION-INFERTYPES-PTRWIDTH-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    let (progress, progress_pointer) = {
        let mut factory = type_factory.write().unwrap();
        let long_type = factory
            .get_base(8, TypeMetatype::Int)
            .expect("canonical int8");
        let int_type = factory
            .get_base(4, TypeMetatype::Int)
            .expect("canonical int4");
        let progress = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("ProgressData".into(), 32, TypeMetatype::Struct),
            fields: vec![
                TypeField {
                    name: "total".into(),
                    offset: 0,
                    type_ptr: long_type.clone(),
                },
                TypeField {
                    name: "prev".into(),
                    offset: 8,
                    type_ptr: long_type.clone(),
                },
                TypeField {
                    name: "point".into(),
                    offset: 16,
                    type_ptr: long_type,
                },
                TypeField {
                    name: "width".into(),
                    offset: 24,
                    type_ptr: int_type,
                },
            ],
        }));
        let pointer = factory.get_type_pointer(8, progress.clone(), 1);
        (progress, pointer)
    };

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());
    let mut fd = Funcdata::new("action_ptrwidth", Address::new(0x5000), 0x40);
    fd.vbank.set_type_factory(type_factory);
    fd.set_arch(Arc::new(architecture));
    let block = fd.create_new_block();

    let source = fd.vbank.create_with_space(8, AddressSpace::Register, 0x100);
    let source = fd.set_input_varnode(source);
    source
        .write()
        .unwrap()
        .update_type_lock(progress_pointer.clone(), true, false);
    let source_type = source
        .read()
        .unwrap()
        .v_type
        .clone()
        .expect("locked source type");
    let source_flags = source.read().unwrap().flags;

    let cases = [
        ("L16", 16_usize, true),
        ("L4", 4, true),
        ("L32", 32, true),
        ("S16", 16, false),
        ("S4", 4, false),
        ("S32", 32, false),
    ];
    let mut cells = Vec::new();
    for (index, (label, width, is_load)) in cases.into_iter().enumerate() {
        let operation = fd.new_op(
            if is_load { 2 } else { 3 },
            Address::new(0x5000 + index as u64),
        );
        fd.op_set_opcode(
            &operation,
            if is_load {
                OpCode::CPUI_LOAD
            } else {
                OpCode::CPUI_STORE
            },
        );
        let space = fd.new_constant(4, AddressSpace::Ram.space_id() as u64);
        fd.op_set_input(&operation, space.clone(), 0);
        fd.op_set_input(&operation, source.clone(), 1);
        let target = if is_load {
            fd.new_unique_out(width, &operation)
        } else {
            let target = fd.vbank.create_with_space(
                width,
                AddressSpace::Register,
                0x200 + index as u64 * 0x40,
            );
            fd.op_set_input(&operation, target.clone(), 2);
            target
        };
        fd.op_insert_end(&operation, &block);
        let (before_type, before_flags) = {
            let target = target.read().unwrap();
            (
                target.v_type.clone().expect("production target type"),
                target.flags,
            )
        };
        cells.push(Cell {
            label,
            width,
            is_load,
            op: operation,
            space,
            target,
            before_type,
            before_flags,
        });
    }

    let order = block_order(&cells, &block);
    let descendants = descendant_order(&cells, &source);
    println!(
        "pre|types={}|block_order={order}|pointer_desc_order={descendants}|source_type_identity={}|source_flags={source_flags}|source_descendants={}|topology={}",
        type_snapshot(&cells, &progress),
        u8::from(Arc::ptr_eq(
            source.read().unwrap().v_type.as_ref().unwrap(),
            &source_type,
        )),
        source.read().unwrap().count_descends(),
        u8::from(topology_stable(&cells, &source, &block)),
    );
    io::stdout().flush().expect("flush pre-action state");

    fd.start_type_recovery();
    let mut action = ActionInferTypes::new();
    action.reset(&mut fd);
    let first_result = catch_unwind(AssertUnwindSafe(|| action.apply(&mut fd)));
    let first_return = match first_result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            println!("exception|phase=after_pre|what={error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("exception|phase=after_pre|what=panic");
            std::process::exit(1);
        }
    };
    let first_types = cells
        .iter()
        .map(|cell| cell.target.read().unwrap().v_type.clone().unwrap())
        .collect::<Vec<_>>();
    println!(
        "pass1|return={first_return}|exception=none|types={}|source_type_identity={}|source_flags_stable={}|block_order_stable={}|pointer_desc_order_stable={}|topology={}",
        type_snapshot(&cells, &progress),
        u8::from(Arc::ptr_eq(
            source.read().unwrap().v_type.as_ref().unwrap(),
            &source_type,
        )),
        u8::from(source.read().unwrap().flags == source_flags),
        u8::from(block_order(&cells, &block) == order),
        u8::from(descendant_order(&cells, &source) == descendants),
        u8::from(topology_stable(&cells, &source, &block)),
    );

    let second_result = catch_unwind(AssertUnwindSafe(|| action.apply(&mut fd)));
    let second_return = match second_result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            println!("exception|phase=after_pass1|what={error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("exception|phase=after_pass1|what=panic");
            std::process::exit(1);
        }
    };
    let types_stable = cells.iter().zip(first_types.iter()).all(|(cell, first)| {
        cell.target
            .read()
            .unwrap()
            .v_type
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, first))
    });
    println!(
        "pass2|return={second_return}|exception=none|types_stable={}|source_type_identity={}|source_flags_stable={}|block_order_stable={}|pointer_desc_order_stable={}|topology={}",
        u8::from(types_stable),
        u8::from(Arc::ptr_eq(
            source.read().unwrap().v_type.as_ref().unwrap(),
            &source_type,
        )),
        u8::from(source.read().unwrap().flags == source_flags),
        u8::from(block_order(&cells, &block) == order),
        u8::from(descendant_order(&cells, &source) == descendants),
        u8::from(topology_stable(&cells, &source, &block)),
    );
}
