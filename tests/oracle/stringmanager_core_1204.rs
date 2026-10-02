// STRINGMANAGER-CORE-JAVACONTRACT-0001 Rugra comparand for the locked
// Ghidra 12.0.4 StringManager core. Mirrors the C++ fixture
// tests/oracle/stringmanager_core_1204.cc record-for-record: the native
// 1:1 StringManagerUnicode reader (2048-byte search clamp) and the declared
// GhidraStringManager/Java contract reader (unbounded detection, 2048-char
// return truncation + isTrunc) run against one attempt-counting loadimage,
// with the negative-cache occupancy, byteData content, truncation flags and
// read counts observed per case.

use rudra::address::Address;
use rudra::loadimage::{DataUnavailError, LoadImage};
use rudra::stringmanage::StringManager;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

struct Region {
    start: u64,
    bytes: Vec<u8>,
}

struct FixtureLoader {
    regions: Vec<Region>,
    // Attempt counts keyed by read start offset; failed attempts (which
    // return DataUnavailError) are counted too, so cached-query proofs can
    // show that zero further attempts were made.
    attempts: Mutex<BTreeMap<u64, usize>>,
}

impl FixtureLoader {
    fn new() -> Arc<Self> {
        fn region(start: u64, contents: &[u8], padded_size: usize) -> Region {
            let mut bytes = vec![0u8; padded_size];
            bytes[..contents.len()].copy_from_slice(contents);
            Region { start, bytes }
        }
        let mut long_string = vec![b'A'; 2050];
        long_string.push(0);
        Arc::new(Self {
            regions: vec![
                region(0x2000, b"alpha\0", 0x100),
                region(0x2100, &[b'b', 0xad, 0], 0x100),
                region(0x2400, &long_string, 2050 + 1 + 0x40),
                // No-NUL region, deliberately ABOVE the 0x2400 region's end
                // (0x2C41) so the unbounded contract search cannot spill
                // into the long-string bytes.
                region(0x2E00, &vec![b'X'; 64], 64),
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
        "stringmanager-core-1204"
    }

    fn load_fill(&self, size: usize, addr: Address) -> Result<Vec<u8>, DataUnavailError> {
        let start = addr.as_u64();
        *self.attempts.lock().unwrap().entry(start).or_insert(0) += 1;
        let end = start + size as u64;
        for region in &self.regions {
            if start >= region.start && end <= region.start + region.bytes.len() as u64 {
                let offset = (start - region.start) as usize;
                return Ok(region.bytes[offset..offset + size].to_vec());
            }
        }
        Err(DataUnavailError(format!(
            "stringmanager fixture read outside a region: {size} bytes at {start:#x}"
        )))
    }

    fn get_arch_type(&self) -> String {
        "fixture:x86:LE:64".to_string()
    }

    fn adjust_vma(&mut self, _adjust: i64) {}
}

fn hex_head(bytes: &[u8], count: usize) -> String {
    bytes.iter().take(count).map(|b| format!("{b:02x}")).collect()
}

fn hex_tail(bytes: &[u8], count: usize) -> String {
    if bytes.len() < count {
        return hex_head(bytes, count);
    }
    bytes[bytes.len() - count..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Observe one get_string_data query and print the record line, mirroring
/// the C++ fixture's record order (data query, isString probe, entry
/// occupancy, hex head/tail, loader attempts).
fn query(
    output: &mut String,
    label: &str,
    manager: &StringManager,
    addr: Address,
    charsize: i32,
    opaque: bool,
    loader: &FixtureLoader,
    attempt_address: u64,
) {
    let mut is_trunc = true;
    let bytes = manager.get_string_data(addr, charsize, opaque, &mut is_trunc);
    let is_str = manager.is_string_typed(addr, charsize, opaque);
    let entry = manager.has_entry(addr);
    let head = hex_head(&bytes, 6);
    let tail = hex_tail(&bytes, 4);
    let attempts = loader.attempt_count(attempt_address);
    output.push_str(&format!(
        "{label}.len={}.trunc={}.isstr={}.entry={}.head={head}.tail={tail}.attempts={attempts}\n",
        bytes.len(),
        if is_trunc { 1 } else { 0 },
        if is_str { 1 } else { 0 },
        if entry { 1 } else { 0 },
    ));
}

fn main() {
    let loader = FixtureLoader::new();
    let native = StringManager::new_unicode(loader.clone(), 2048);
    let contract = StringManager::new_ghidra_contract(loader.clone(), 2048);

    let mut output = String::new();

    // C1: pure ASCII positive cache — byteData carries the whole first
    // 32-byte block verbatim (stringmanage.cc:69-72).
    query(&mut output, "c1.ascii.native", &native, Address::new(0x2000), 1,
          false, &loader, 0x2000);
    query(&mut output, "c1.ascii.contract", &contract, Address::new(0x2000), 1,
          false, &loader, 0x2000);

    // C2: repeat query on the positive cache: zero further reads.
    query(&mut output, "c2.ascii_repeat.native", &native, Address::new(0x2000),
          1, false, &loader, 0x2000);
    query(&mut output, "c2.ascii_repeat.contract", &contract,
          Address::new(0x2000), 1, false, &loader, 0x2000);

    // C3: 0xAD illegal UTF-8 — negative cache: entry occupied, byteData
    // empty.
    query(&mut output, "c3.invalid_0xad.native", &native, Address::new(0x2100),
          1, false, &loader, 0x2100);
    query(&mut output, "c3.invalid_0xad.contract", &contract,
          Address::new(0x2100), 1, false, &loader, 0x2100);

    // C4: repeat query on the NEGATIVE cache: zero further reads.
    query(&mut output, "c4.invalid_repeat.native", &native, Address::new(0x2100),
          1, false, &loader, 0x2100);
    query(&mut output, "c4.invalid_repeat.contract", &contract,
          Address::new(0x2100), 1, false, &loader, 0x2100);

    // C5: >2048 long string — native clamp (empty) vs Java contract
    // (2048 'A' + NUL, truncated).
    query(&mut output, "c5.long.native", &native, Address::new(0x2400), 1,
          false, &loader, 0x2400);
    query(&mut output, "c5.long.contract", &contract, Address::new(0x2400), 1,
          false, &loader, 0x2400);

    // C6: two consumers share one manager (rule-side isString at
    // ruleaction.cc:7375, then print-side getStringData at printc.cc:1537).
    {
        let shared = StringManager::new_ghidra_contract(loader.clone(), 2048);
        let rule_guard = shared.is_string_typed(Address::new(0x2000), 1, false);
        let attempts_after_rule = loader.attempt_count(0x2000);
        let mut is_trunc = true;
        let bytes = shared.get_string_data(Address::new(0x2000), 1, false, &mut is_trunc);
        let attempts_after_print = loader.attempt_count(0x2000);
        output.push_str(&format!(
            "c6.shared.rule_guard={}.attempts_after_rule={}.print_len={}.print_trunc={}.attempts_after_print={}\n",
            if rule_guard { 1 } else { 0 },
            attempts_after_rule,
            bytes.len(),
            if is_trunc { 1 } else { 0 },
            attempts_after_print,
        ));
    }

    // C7: DataUnavailError (0x3000 outside every region).
    query(&mut output, "c7.data_unavail.contract", &contract,
          Address::new(0x3000), 1, false, &loader, 0x3000);
    query(&mut output, "c7.data_unavail_repeat.contract", &contract,
          Address::new(0x3000), 1, false, &loader, 0x3000);

    // C8: no terminator before the image ends (64 'X' bytes, region ends at
    // 0x2E40).
    query(&mut output, "c8.no_terminator.contract", &contract,
          Address::new(0x2E00), 1, false, &loader, 0x2E00);
    query(&mut output, "c8.no_terminator_repeat.contract", &contract,
          Address::new(0x2E00), 1, false, &loader, 0x2E00);

    // C9: opaque string data-type — early exit caches the empty entry with
    // zero image attempts. Address 0x2080 was never queried.
    query(&mut output, "c9.opaque.contract", &contract, Address::new(0x2080), 1,
          true, &loader, 0x2080);

    // C10: registerInternalStringData — legal bytes hash + cache at the
    // constant hash address; illegal 0xAD bytes return 0.
    {
        let internal: &[u8] = b"internal\0";
        let hash = contract.register_internal_string_data(
            Address::new(0x1000),
            internal,
            1,
        );
        let bad: [u8; 3] = [b'b', 0xad, 0];
        let bad_hash = contract.register_internal_string_data(
            Address::new(0x1000),
            &bad,
            1,
        );
        let const_addr = Address::new(hash);
        let mut is_trunc = true;
        let bytes = contract.get_string_data(const_addr, 1, false, &mut is_trunc);
        let entry = contract.has_entry(const_addr);
        output.push_str(&format!(
            "c10.internal.hash_nonzero={}.bad_hash_zero={}.entry={}.len={}.head={}\n",
            if hash != 0 { 1 } else { 0 },
            if bad_hash == 0 { 1 } else { 0 },
            if entry { 1 } else { 0 },
            bytes.len(),
            hex_head(&bytes, 9),
        ));
    }

    // C11: internal-string hash determinism (calcInternalHash,
    // stringmanage.cc:95-105).
    {
        let internal: &[u8] = b"internal\0";
        let expected = StringManager::calc_internal_hash(&Address::new(0x1000), internal);
        output.push_str(&format!("c11.internal_hash.value={expected:x}\n"));
    }

    output.push_str(&format!(
        "entries.native={}.contract={}\n",
        native.num_strings(),
        contract.num_strings(),
    ));
    print!("{output}");
}
