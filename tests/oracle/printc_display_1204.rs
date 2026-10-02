use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::{display_format, PrintC};
use rudra::type_system::datatype::Datatype;

fn render(value: u64, size: usize, is_signed: bool, format: u32) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.push_integer(value, size, is_signed, format);
    let emitter = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture emitter type");
    emitter.get_output()
}

fn print_wire(name: &str, expected: u32) {
    let value = Datatype::encode_integer_format(name).expect("valid display format name");
    assert_eq!(value, expected);
    let decoded = Datatype::decode_integer_format(value).expect("valid display format value");
    println!("wire.{name}={value}:decode={decoded}");
}

fn main() {
    println!("wire.default={}", display_format::DEFAULT);
    print_wire("hex", display_format::HEX);
    print_wire("dec", display_format::DEC);
    print_wire("oct", display_format::OCT);
    print_wire("bin", display_format::BIN);
    print_wire("char", display_format::CHAR);

    println!("format.hex={}", render(65, 1, false, display_format::HEX));
    println!("format.dec={}", render(65, 1, false, display_format::DEC));
    println!("format.oct={}", render(65, 1, false, display_format::OCT));
    println!("format.bin={}", render(65, 1, false, display_format::BIN));
    println!("format.char={}", render(65, 1, false, display_format::CHAR));
    println!(
        "format.char_signed={}",
        render(0xff, 1, true, display_format::CHAR)
    );
    println!(
        "format.oct_signed={}",
        render(0xff, 1, true, display_format::OCT)
    );
    println!(
        "format.bin_signed={}",
        render(0xff, 1, true, display_format::BIN)
    );
}
