use rudra::compression::Decompress;
use std::ffi::CStr;

const HELLO_ZLIB: [u8; 13] = [
    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
];
const WORLD_ZLIB: [u8; 13] = [
    0x78, 0x9c, 0x2b, 0xcf, 0x2f, 0xca, 0x49, 0x01, 0x00, 0x06, 0xa6, 0x02, 0x29,
];

fn truth(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: zlibVersion returns a process-lifetime NUL-terminated string.
    let version = unsafe { CStr::from_ptr(libz_sys::zlibVersion()) }.to_str()?;
    println!("zlib.version={version}");

    {
        let mut stream = Decompress::new()?;
        let mut output = [0u8; 8];
        // SAFETY: output is writable for the declared size; no input is live.
        let remaining = unsafe { stream.inflate(output.as_mut_ptr(), output.len() as i32)? };
        println!(
            "no_input.remaining={remaining}:finished={}",
            truth(stream.is_finished())
        );
    }

    {
        let mut hello = HELLO_ZLIB;
        let mut world = WORLD_ZLIB;
        let mut stream = Decompress::new()?;
        // SAFETY: both fixed arrays remain live and stable through their use.
        unsafe { stream.input(hello.as_mut_ptr(), hello.len() as i32) };
        let mut first = [0u8; 1];
        // SAFETY: hello and first remain valid and do not overlap.
        let first_remaining = unsafe { stream.inflate(first.as_mut_ptr(), first.len() as i32)? };
        // SAFETY: world remains live and stable through the next inflate call.
        unsafe { stream.input(world.as_mut_ptr(), world.len() as i32) };
        let mut second = [0u8; 64];
        // SAFETY: world and second remain valid and do not overlap.
        let second_remaining = unsafe { stream.inflate(second.as_mut_ptr(), second.len() as i32)? };
        println!(
            "midstream_replace.first_remaining={first_remaining}:second_remaining={second_remaining}:finished={}:hex={}",
            truth(stream.is_finished()),
            hex(&second[..second.len() - second_remaining as usize])
        );
    }

    {
        let mut hello = HELLO_ZLIB;
        let mut stream = Decompress::new()?;
        // SAFETY: hello remains live and stable; mutation happens between calls.
        unsafe { stream.input(hello.as_mut_ptr(), hello.len() as i32) };
        hello[0] = 0;
        debug_assert_eq!(hello[0], 0);
        let mut output = [0u8; 8];
        // SAFETY: both buffers remain valid and do not overlap during the call.
        match unsafe { stream.inflate(output.as_mut_ptr(), output.len() as i32) } {
            Ok(_) => println!("alias_mutation.error=none"),
            Err(error) => println!("alias_mutation.error={error}"),
        }
    }

    {
        let mut buffer = [0u8; 64];
        buffer[..HELLO_ZLIB.len()].copy_from_slice(&HELLO_ZLIB);
        let pointer = buffer.as_mut_ptr();
        let mut stream = Decompress::new()?;
        // SAFETY: the 64-byte allocation remains stable; zlib receives the
        // same valid 13-byte range as both input and output.
        let remaining = unsafe {
            stream.input(pointer, HELLO_ZLIB.len() as i32);
            stream.inflate(pointer, HELLO_ZLIB.len() as i32)?
        };
        println!(
            "same_address.remaining={remaining}:finished={}:hex={}",
            truth(stream.is_finished()),
            hex(&buffer[..HELLO_ZLIB.len() - remaining as usize])
        );
    }

    {
        let mut hello = HELLO_ZLIB;
        let mut stream = Decompress::new()?;
        // SAFETY: hello remains live and stable until it is fully consumed.
        unsafe { stream.input(hello.as_mut_ptr(), hello.len() as i32) };
        let mut first = [0u8; 1];
        // SAFETY: hello and first remain valid and do not overlap.
        let first_remaining = unsafe { stream.inflate(first.as_mut_ptr(), first.len() as i32)? };
        println!(
            "stream.first={}:remaining={first_remaining}:finished={}",
            String::from_utf8_lossy(&first),
            truth(stream.is_finished())
        );
        let mut second = [0u8; 64];
        // SAFETY: the unconsumed input and second remain valid and do not overlap.
        let second_remaining = unsafe { stream.inflate(second.as_mut_ptr(), second.len() as i32)? };
        println!(
            "stream.second={}:remaining={second_remaining}:finished={}",
            String::from_utf8_lossy(&second[..second.len() - second_remaining as usize]),
            truth(stream.is_finished())
        );
    }

    {
        let mut invalid = [0xde, 0xad, 0xbe, 0xef];
        let mut stream = Decompress::new()?;
        // SAFETY: invalid remains live and stable through the inflate call.
        unsafe { stream.input(invalid.as_mut_ptr(), invalid.len() as i32) };
        let mut output = [0u8; 8];
        // SAFETY: invalid and output remain valid and do not overlap.
        match unsafe { stream.inflate(output.as_mut_ptr(), output.len() as i32) } {
            Ok(_) => println!("invalid.error=none"),
            Err(error) => println!(
                "invalid.error={error}:finished={}",
                truth(stream.is_finished())
            ),
        }
    }

    {
        let mut hello = HELLO_ZLIB;
        let mut world = WORLD_ZLIB;
        let mut stream = Decompress::new()?;
        // SAFETY: each fixed array remains live and stable; the second call
        // replaces the first pointer before zlib observes it.
        unsafe {
            stream.input(hello.as_mut_ptr(), hello.len() as i32);
            stream.input(world.as_mut_ptr(), world.len() as i32);
        }
        let mut output = [0u8; 64];
        // SAFETY: world and output remain valid and do not overlap.
        let remaining = unsafe { stream.inflate(output.as_mut_ptr(), output.len() as i32)? };
        println!(
            "replacement.output={}:remaining={remaining}:finished={}",
            String::from_utf8_lossy(&output[..output.len() - remaining as usize]),
            truth(stream.is_finished())
        );
    }

    Ok(())
}
