# cpool.rs — Constant pool API

Partial port of Ghidra's `cpool.hh` / `cpool.cc`; the covered typed-record
projection is matched, while the residuals below keep the module at L2.

**Status:** L2 / `MISMATCH`. Typed records, ordered storage, non-code-flags
decode, and exception partial state are implemented. L3 remains blocked by
`TYPEFACTORY-CODEFLAGS-DECODE-0001`; packed wire identity also inherits the
registered `MARSHAL-ID-0001` / `MARSHAL-PACKED-0001` gaps.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cpool.{hh,cc}`.

## Modules

### `cpool_tag`
Constant pool tag types (cpool.hh:59):
- `PRIMITIVE = 0`, `STRING_LITERAL = 1`, `CLASS_REFERENCE = 2`,
  `POINTER_METHOD = 3`, `POINTER_FIELD = 4`, `ARRAY_LENGTH = 5`,
  `INSTANCE_OF = 6`, `CHECK_CAST = 7`.

### `cpool_flags`
- `IS_CONSTRUCTOR = 0x1`, `IS_DESTRUCTOR = 0x2`.

## Structs

### `CPoolRecord`
A description of a byte-code object referenced by a constant (cpool.hh:56).

- `data_type: Option<Arc<Datatype>>` is the authoritative equivalent of
  Ghidra's factory-owned `Datatype *type`. `get_type()` returns the same Arc;
  callers must not reconstruct a type by name.
- `type_name` is compatibility display state only. `set_type()` derives it
  from the canonical Arc so legacy printers keep working.
- `new()`, `get_tag()`, `get_token()`, `get_byte_data()`,
  `get_byte_data_length()`, `get_type()`, `get_type_name()`, `get_value()`,
  `is_constructor()`, `is_destructor()`.
- `tag_to_string(tag)` / `string_to_tag(s)` — tag↔string conversion.
- `encode(encoder) -> Result<(), String>` writes tag, flags, primitive value,
  token or byte data, and finally `Datatype::encode_ref`, in source order.
- `decode(decoder, type_factory) -> Result<(), String>` resolves and retains
  the TypeFactory canonical Arc. Mutations occur in Ghidra order, so errors
  preserve the already-written tag/value/flags/token/data prefix.

### `CheapSorter`
Efficient 2-integer reference placeholder (cpool.hh:175).
- `from_refs(refs)`, `apply() -> Vec<u64>`.
- `encode(encoder)`, `decode(decoder)` use locked IDs `ref=111`, `a=80`,
  `b=81`.
- Derives `Ord` for BTreeMap keying.
- Like Ghidra, only `(refs[0], refs[1] or 0)` participates in identity; later
  reference components are ignored and a one-component `[a]` aliases
  `[a, 0]`.

## Trait `ConstantPool`
Interface to the constant pool (cpool.hh:104).
- `get_record(refs) -> Option<&CPoolRecord>`.
- `create_record(refs) -> Result<&mut CPoolRecord, String>`.
- `put_record(refs, tag, tok, Arc<Datatype>) -> Result<(), String>` propagates
  duplicate-entry errors and never replaces the existing record.
- `decode_record(refs, decoder, type_factory)` inserts first and decodes
  second; a decode exception therefore leaves the partial record in the map.
- `is_empty() -> bool`, `clear()`.

## `ConstantPoolInternal`
In-memory implementation (cpool.hh:165).
- `new()`, `num_records()`, `records()`.
- Implements `ConstantPool`.
- `BTreeMap<CheapSorter, CPoolRecord>` preserves Ghidra's lexicographic
  `(a,b)` iteration and encode order.

## 2026-08-20：CPOOL-TYPED-RECORD-0001

- `ConstantPoolInternal::encode` serializes every ordered `<ref>` /
  `<cpoolrec>` pair and propagates missing-type errors.
- `ConstantPoolInternal::decode` no longer skips unexpected children or
  overwrites duplicates. It follows `createRecord → CPoolRecord::decode`, so
  duplicate, missing string data, and type-resolution exceptions retain the
  same map prefix as Ghidra.
- The locked 12.0.4 fixture covers all eight tags plus the unknown-tag
  primitive default, canonical type identity, `instance_of` storage, misses,
  reference projection/order, duplicate rejection, clear-and-recreate, full
  packed bytes, and two exception partial-state paths.
- Its runner builds a complete archive of Rudra base commit `128a127`, mounts
  the Ghidra C++ tree from the locked oracle commit, and overlays only the
  hash-checked `src/cpool.rs`. Both fixture sources are copied outside the
  workspace before compilation; live TypeFactory/Datatype/UserOp sources are
  never consumed.

Known residuals:

- When constructor/destructor flags are present, Ghidra calls
  `TypeFactory::decodeTypeWithCodeFlags`; Rudra currently calls the generic
  canonical decoder and cannot inject those flags into `TypeCode`. This is an
  explicit fixture `MISMATCH` owned by `TYPEFACTORY-CODEFLAGS-DECODE-0001`.
- `Datatype::encode_ref` still uses its private dynamic ID table, so the
  enclosing cpool fields match but complete packed bytes differ from locked
  IDs. This remains under `MARSHAL-ID-0001` / `MARSHAL-PACKED-0001`; the
  fixture preserves the raw differing bytes and performs no normalization.
- Ghidra streams `uint1` byte data as a padded raw character. Rudra matches
  this byte-for-byte for the fixture's `0x00..0x10` domain; arbitrary
  `>=0x80` byte strings remain constrained by the current UTF-8 `Encoder`
  interface and are not claimed as `MATCH`.
- 2026-08-23 (TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001): the in-file test
  fixture helper `fixture_type` now registers core types through the faithful
  `set_core_type_result` twin (panicking with the oracle LowlevelError text,
  the exact throw semantics of type.cc:3178) instead of the legacy
  `set_core_type` Arc wrapper. Fixture behavior is unchanged; the runner's
  Rudra snapshot base is re-pinned to 71971b2 (whose TypeFactory provides the
  Result twins) with comparand hashes re-recorded.
<!-- annotation-pass: 2026-07-04 -->
