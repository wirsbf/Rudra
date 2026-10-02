use rudra::opcodes::OpCode;
use rudra::sleigh_ffi::{
    set_sla_path, DecodedInstruction, PcodeOpC, SleighCtx, SleighDecodeError, SleighErrorKind,
    VarnodeC,
};
use std::fmt::Write as _;

const IMAGE_BASE: u64 = 0x1000;
const ARCHITECTURE: &str = "x86:LE:64:default";
const COMPILER_SPEC: &str = "gcc";
const LOADER_POLICY: &str = "raw-uint64-modulo-start-tail-zero-fill";
const CONTEXT_SETTINGS: [(&str, i32); 4] = [
    ("addrsize", 2),
    ("opsize", 1),
    ("rexprefix", 0),
    ("longMode", 1),
];

struct CaseInput {
    id: &'static str,
    image: Vec<u8>,
    image_sha256: &'static str,
    base: u64,
    offset: u64,
    setup: &'static str,
    source_after_hex: Option<&'static str>,
}

enum Observation {
    Success(DecodedInstruction),
    Error(SleighDecodeError),
}

#[derive(Clone)]
struct SpaceRecord {
    index: i32,
    type_: i32,
    name: String,
}

fn json_escape_bytes(bytes: &[u8]) -> String {
    let mut escaped = String::new();
    for &byte in bytes {
        match byte {
            b'"' => escaped.push_str("\\\""),
            b'\\' => escaped.push_str("\\\\"),
            b'\x08' => escaped.push_str("\\b"),
            b'\x0c' => escaped.push_str("\\f"),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            0x20..=0x7e => escaped.push(char::from(byte)),
            _ => write!(&mut escaped, "\\u{byte:04x}").expect("write to String"),
        }
    }
    escaped
}

fn json_escape(value: &str) -> String {
    json_escape_bytes(value.as_bytes())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("write to String");
    }
    result
}

fn padded(prefix: &[u8], size: usize) -> Vec<u8> {
    let mut result = vec![0; size];
    result[..prefix.len()].copy_from_slice(prefix);
    result
}

fn create_engine() -> Result<SleighCtx, String> {
    let mut engine = SleighCtx::new().ok_or_else(|| "SleighCtx::new failed".to_string())?;
    for (name, value) in CONTEXT_SETTINGS {
        engine
            .try_set_context(name, value)
            .map_err(|error| format!("try_set_context({name}) failed: {error:?}"))?;
    }
    Ok(engine)
}

fn set_image(engine: &mut SleighCtx, image: &[u8], base: u64) -> Result<(), String> {
    engine
        .try_set_image(image, base)
        .map_err(|error| format!("try_set_image failed: {error:?}"))
}

fn observe(engine: &mut SleighCtx, offset: u64) -> Observation {
    match engine.one_instruction(offset) {
        Ok(instruction) => Observation::Success(instruction),
        Err(error) => Observation::Error(error),
    }
}

fn resolve_space(engine: &SleighCtx, index: i32) -> Result<SpaceRecord, String> {
    if index < 0 {
        return Err(format!("negative address-space index {index}"));
    }
    let (type_, name) = engine
        .space_info(index as usize)
        .ok_or_else(|| format!("missing address-space index {index}"))?;
    Ok(SpaceRecord { index, type_, name })
}

fn push_space(output: &mut String, space: &SpaceRecord) {
    write!(
        output,
        "{{\"index\":{},\"name\":\"{}\",\"type\":{}}}",
        space.index,
        json_escape(&space.name),
        space.type_
    )
    .expect("write to String");
}

fn push_varnode(output: &mut String, engine: &SleighCtx, varnode: &VarnodeC) -> Result<(), String> {
    let container = resolve_space(engine, varnode.space)?;
    if varnode.space_ref >= 0 {
        let target = resolve_space(engine, varnode.space_ref)?;
        write!(
            output,
            "{{\"alias_key\":\"spaceid:{}:{}\",\"container_space\":",
            target.index, varnode.size
        )
        .expect("write to String");
        push_space(output, &container);
        write!(
            output,
            ",\"identity\":{},\"kind\":\"spaceid\",\"size\":{},\"target_space\":",
            varnode.identity, varnode.size
        )
        .expect("write to String");
        push_space(output, &target);
        output.push('}');
        return Ok(());
    }

    write!(
        output,
        "{{\"alias_key\":\"varnode:{}:0x{:016x}:{}\",\"identity\":{},\"kind\":\"varnode\",\"offset\":\"0x{:016x}\",\"size\":{},\"space\":",
        container.index,
        varnode.offset,
        varnode.size,
        varnode.identity,
        varnode.offset,
        varnode.size
    )
    .expect("write to String");
    push_space(output, &container);
    output.push('}');
    Ok(())
}

fn opcode_name(raw: i32) -> Result<&'static str, String> {
    OpCode::from_i32(raw)
        .map(|opcode| opcode.name())
        .ok_or_else(|| format!("invalid p-code opcode {raw}"))
}

fn push_operation(
    output: &mut String,
    engine: &SleighCtx,
    operation: &PcodeOpC,
    index: usize,
) -> Result<(), String> {
    if operation.num_inputs < 0 || operation.num_inputs as usize != operation.inputs.len() {
        return Err(format!(
            "operation {index} declared {} inputs but owns {}",
            operation.num_inputs,
            operation.inputs.len()
        ));
    }
    if operation.has_output != 0 && operation.has_output != 1 {
        return Err(format!(
            "operation {index} has invalid has_output {}",
            operation.has_output
        ));
    }

    let address_space = resolve_space(engine, operation.address_space)?;
    write!(
        output,
        "{{\"address\":{{\"offset\":\"0x{:016x}\",\"space\":",
        operation.address_offset
    )
    .expect("write to String");
    push_space(output, &address_space);
    write!(
        output,
        "}},\"declared_input_count\":{},\"index\":{},\"inputs\":[",
        operation.num_inputs, index
    )
    .expect("write to String");
    for (input_index, input) in operation.inputs.iter().enumerate() {
        if input_index != 0 {
            output.push(',');
        }
        push_varnode(output, engine, input)?;
    }
    write!(
        output,
        "],\"opcode\":{{\"name\":\"{}\",\"value\":{}}},\"output\":",
        opcode_name(operation.opcode)?,
        operation.opcode
    )
    .expect("write to String");
    if operation.has_output == 0 {
        output.push_str("null");
    } else {
        push_varnode(output, engine, &operation.output)?;
    }
    output.push('}');
    Ok(())
}

fn status_name(kind: &SleighErrorKind) -> &'static str {
    match kind {
        SleighErrorKind::Unimplemented => "UNIMPL",
        SleighErrorKind::BadData => "BAD_DATA",
        SleighErrorKind::DataUnavailable => "DATA_UNAVAILABLE",
        _ => "OTHER",
    }
}

fn render_case(
    engine: &SleighCtx,
    input: &CaseInput,
    observation: &Observation,
) -> Result<String, String> {
    let mut output = String::new();
    write!(
        &mut output,
        "{{\"architecture\":\"{ARCHITECTURE}\",\"case\":\"{}\",\"compiler_spec\":\"{COMPILER_SPEC}\",\"input\":{{\"base\":\"0x{:016x}\",\"context\":[",
        json_escape(input.id),
        input.base
    )
    .expect("write to String");
    for (index, (name, value)) in CONTEXT_SETTINGS.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            &mut output,
            "{{\"name\":\"{}\",\"value\":{}}}",
            json_escape(name),
            value
        )
        .expect("write to String");
    }
    write!(
        &mut output,
        "],\"image_hex\":\"{}\",\"image_sha256\":\"{}\",\"loader_policy\":\"{LOADER_POLICY}\",\"offset\":\"0x{:016x}\",\"setup\":\"{}\",\"source_after_hex\":",
        hex_bytes(&input.image),
        input.image_sha256,
        input.offset,
        json_escape(input.setup)
    )
    .expect("write to String");
    match input.source_after_hex {
        Some(value) => write!(&mut output, "\"{}\"", json_escape(value)).expect("write to String"),
        None => output.push_str("null"),
    }
    output.push_str("},\"result\":{");

    match observation {
        Observation::Success(instruction) => {
            write!(
                &mut output,
                "\"explain\":null,\"instruction_length\":null,\"op_count\":{},\"ops\":[",
                instruction.ops.len()
            )
            .expect("write to String");
            for (index, operation) in instruction.ops.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                push_operation(&mut output, engine, operation, index)?;
            }
            write!(
                &mut output,
                "],\"status\":\"OK\",\"step\":{}",
                instruction.step
            )
            .expect("write to String");
        }
        Observation::Error(error) => {
            write!(
                &mut output,
                "\"explain\":\"{}\",\"instruction_length\":",
                json_escape_bytes(&error.message)
            )
            .expect("write to String");
            match error.instruction_length {
                Some(length) => write!(&mut output, "{length}").expect("write to String"),
                None => output.push_str("null"),
            }
            write!(
                &mut output,
                ",\"op_count\":0,\"ops\":[],\"status\":\"{}\",\"step\":null",
                status_name(&error.kind)
            )
            .expect("write to String");
        }
    }
    output.push_str("},\"schema\":1}");
    Ok(output)
}

fn run_fresh_case(input: CaseInput) -> Result<(), String> {
    let mut engine = create_engine()?;
    set_image(&mut engine, &input.image, input.base)?;
    let observation = observe(&mut engine, input.offset);
    println!("{}", render_case(&engine, &input, &observation)?);
    Ok(())
}

fn main() -> Result<(), String> {
    let sla_path = std::env::args()
        .nth(1)
        .ok_or_else(|| "usage: sleigh_decode_1204 <x86-64.sla>".to_string())?;
    set_sla_path(&sla_path);

    run_fresh_case(CaseInput {
        id: "cpuid_78_ops",
        image: padded(&[0x0f, 0xa2], 32),
        image_sha256: "14ccfec470ee23093cc1f8d012600da47d772d4914cfbd1b21e4d0f46898bf7a",
        base: IMAGE_BASE,
        offset: IMAGE_BASE,
        setup: "fresh-owned-image",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "nop_zero_ops",
        image: padded(&[0x90], 32),
        image_sha256: "a3a2808c37da4f9cab6a51e07ddfc6c34f725988fe2486199d6a190c1be473a4",
        base: IMAGE_BASE,
        offset: IMAGE_BASE,
        setup: "fresh-owned-image",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "jmp_short_one_byte_tail_zero_fill",
        image: vec![0xeb],
        image_sha256: "f8d20e598df20877e4d826246fc31ffb4615cbc059aec9ec8e5b28951d844a3f",
        base: IMAGE_BASE,
        offset: IMAGE_BASE,
        setup: "fresh-owned-image-tail-zero-fill",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "nop_uint64_modulo_wrap",
        image: vec![0x06, 0x90],
        image_sha256: "b54d7f43052bd9abe02ed4947f9c2c22cf2de16b1e20b5539b891dbfaea26571",
        base: u64::MAX,
        offset: 0,
        setup: "fresh-owned-image-uint64-modulo-wrap",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "mov_rax_ptr_rbx_pointer_alias",
        image: padded(&[0x48, 0x8b, 0x03], 32),
        image_sha256: "5d2820090d89afc6a0c12333ec23d6a40bb6d63b0dd8829d9153fc45dd8b3a30",
        base: IMAGE_BASE,
        offset: IMAGE_BASE,
        setup: "fresh-owned-image-pointer-alias",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "bad_data",
        image: padded(&[0x0f, 0x04], 32),
        image_sha256: "5804d1599a661578dbf83f3e674619c04e71d36df54c5172d75ecd8df992f2b9",
        base: IMAGE_BASE,
        offset: IMAGE_BASE,
        setup: "fresh-owned-image",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "data_unavailable_empty_image",
        image: Vec::new(),
        image_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        base: IMAGE_BASE,
        offset: IMAGE_BASE,
        setup: "fresh-owned-empty-image",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "data_unavailable_below_base",
        image: vec![0x90],
        image_sha256: "9e076ceaf246b6003d9c2680a2b4cf0bffd069805902b0b5edeebf49039fe4bd",
        base: IMAGE_BASE,
        offset: IMAGE_BASE - 1,
        setup: "fresh-owned-image-decode-below-base",
        source_after_hex: None,
    })?;

    run_fresh_case(CaseInput {
        id: "data_unavailable_at_end",
        image: vec![0x90],
        image_sha256: "9e076ceaf246b6003d9c2680a2b4cf0bffd069805902b0b5edeebf49039fe4bd",
        base: IMAGE_BASE,
        offset: IMAGE_BASE + 1,
        setup: "fresh-owned-image-decode-at-end",
        source_after_hex: None,
    })?;

    {
        let mut source = vec![0x90];
        let mut engine = create_engine()?;
        set_image(&mut engine, &source, IMAGE_BASE)?;
        source[0] = 0x06;
        source.clear();
        source.shrink_to_fit();
        let input = CaseInput {
            id: "owned_source_mutation",
            image: vec![0x90],
            image_sha256: "9e076ceaf246b6003d9c2680a2b4cf0bffd069805902b0b5edeebf49039fe4bd",
            base: IMAGE_BASE,
            offset: IMAGE_BASE,
            setup: "RUDRA-GLUE owned copy; caller mutates 90 to 06 then releases source",
            source_after_hex: Some("06"),
        };
        let observation = observe(&mut engine, input.offset);
        println!("{}", render_case(&engine, &input, &observation)?);
    }

    {
        let mut sequence_image = vec![0; 64];
        sequence_image[0..3].copy_from_slice(&[0x48, 0x89, 0xf8]);
        sequence_image[32..34].copy_from_slice(&[0x0f, 0x04]);
        let mut engine = create_engine()?;
        set_image(&mut engine, &sequence_image, IMAGE_BASE)?;
        let success = CaseInput {
            id: "success_then_error_0_success",
            image: sequence_image.clone(),
            image_sha256: "308f821b209c6665e83718770fe5117e2d270fae4f9f3bf39111ba7f06c58290",
            base: IMAGE_BASE,
            offset: IMAGE_BASE,
            setup: "shared-engine-sequence-step-0",
            source_after_hex: None,
        };
        let observation = observe(&mut engine, success.offset);
        println!("{}", render_case(&engine, &success, &observation)?);

        let error = CaseInput {
            id: "success_then_error_1_error",
            image: sequence_image,
            image_sha256: "308f821b209c6665e83718770fe5117e2d270fae4f9f3bf39111ba7f06c58290",
            base: IMAGE_BASE,
            offset: IMAGE_BASE + 32,
            setup: "shared-engine-sequence-step-1; error result must publish zero ops",
            source_after_hex: None,
        };
        let observation = observe(&mut engine, error.offset);
        println!("{}", render_case(&engine, &error, &observation)?);
    }

    println!(
        "{{\"architecture\":\"x86:LE:64:default\",\"case\":\"unimpl_x86_reachability\",\"compiler_spec\":\"gcc\",\"coverage\":{{\"alignment\":1,\"constructors\":5707,\"null_templates\":0,\"reason\":\"locked x86-64 SLA has no reachable UnimplError path\",\"status\":\"UNTESTED\",\"subtables\":236}},\"schema\":1}}"
    );
    Ok(())
}
