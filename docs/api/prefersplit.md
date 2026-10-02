# prefersplit.rs — Prefer-split records API

Faithful port of Ghidra's `prefersplit.hh` / `prefersplit.cc` (631 lines).

## 2026-10-01：`*mut Funcdata` 成员消灭（Lane ARENAFLIP-g 步骤 4）

- `PreferSplitManager.data: Option<*mut Funcdata>` 字段与 `unsafe impl Send`
  shim 删除（P6——与 transform.rs e7b15887 同族收尾）：fd 逐调用穿透
  `fillin_instance/create_copy_ops/split_defining_copy/split_reading_copy/
  split_zext/split_piece/split_subpiece/split_load/split_store/
  split_varnode/split_record/split_temporary`（prefer­split.cc:33-527 的
  `data->` 成员访问等价形态）。
- `init(_fd, rec)`（cc:529 `data = fd; records = rec;`）保留签名但不再
  存储 fd——fd 行为由 `split`/`split_additional` 逐调用承载；调用面
  （heritage.rs 5870/5871/6049）零改动。src/prefersplit.rs 现在
  unsafe-free 且自动 Send+Sync。

**Status:** ✅ L3 — full algorithm ported & verified. All 18 private helpers
(`fillinInstance`, `createCopyOps`, `testDefiningCopy`/`splitDefiningCopy`,
`testReadingCopy`/`splitReadingCopy`, `testZext`/`splitZext`,
`testPiece`/`splitPiece`, `testSubpiece`/`splitSubpiece`,
`testLoad`/`splitLoad`, `testStore`/`splitStore`), the public `split`/`splitAdditional`,
and the `splitVarnode`/`splitRecord`/`testTemporary`/`splitTemporary` drivers
are implemented with Funcdata op-editing.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/prefersplit.{hh,cc}`.

## Structs

### `PreferSplitRecord`
A record indicating a storage location should be split (prefersplit.hh:27).
- `new(offset, space, size, splitoffset)`.
- `less_than(&other) -> bool` — ordering by space, size (desc), offset
  (prefersplit.cc:23-31).
- Fields: `storage_offset`, `storage_space`, `storage_size`, `splitoffset`.

### `SplitInstance`
An instance of a split varnode being processed (prefersplit.hh:34-42). Mirrors
the private nested class — holds the original `vn` plus filled-in `hi`/`lo`
piece varnodes.
- `new(vn: Arc<RwLock<Varnode>>, splitoffset)`.
- Fields: `vn`, `hi`, `lo`, `splitoffset`.

## Free function
- `initialize(records)` — sort records via `PreferSplitRecord::less_than`
  (prefersplit.cc:552-556 `PreferSplitManager::initialize`).

## `PreferSplitManager`
Manages splitting based on records (prefersplit.hh:33-72).
- `new()`, `default()`.
- `init(fd, records)` — bind to Funcdata + set sorted records
  (prefersplit.cc:529-534).
- `set_records(records)` — replace records list (sorted).
- `num_records()`, `records()`.
- `find_record(space, size, offset) -> Option<&PreferSplitRecord>` — binary
  search lookup (prefersplit.cc:536-550 `findRecord`).
- `find_record_vn(vn) -> Option<&PreferSplitRecord>` — lookup by Varnode.
- `split(fd)` — main entry; applies every split record in turn
  (prefersplit.cc:558-563). Clears `tempsplits` first.
- `split_additional(fd)` — split temporaries linked to the COPYs created by
  `split` (prefersplit.cc:565-629).

## Private split helpers (all ported)
| Ghidra method | Rust method | Lines |
|---|---|---|
| `fillinInstance` | `fillin_instance` | 33-67 |
| `createCopyOps` | `create_copy_ops` | 69-87 |
| `testDefiningCopy` | `test_defining_copy` | 89-105 |
| `splitDefiningCopy` | `split_defining_copy` | 107-116 |
| `testReadingCopy` | `test_reading_copy` | 118-131 |
| `splitReadingCopy` | `split_reading_copy` | 133-142 |
| `testZext` | `test_zext` | 144-158 |
| `splitZext` | `split_zext` | 160-188 |
| `testPiece` | `test_piece` | 190-200 |
| `splitPiece` | `split_piece` | 202-227 |
| `testSubpiece` | `test_subpiece` | 229-246 |
| `splitSubpiece` | `split_subpiece` | 248-263 |
| `testLoad` | `test_load` | 265-269 |
| `splitLoad` | `split_load` | 271-314 |
| `testStore` | `test_store` | 316-320 |
| `splitStore` | `split_store` | 322-365 |
| `splitVarnode` | `split_varnode` | 367-428 |
| `splitRecord` | `split_record` | 430-449 |
| `testTemporary` | `test_temporary` | 451-491 |
| `splitTemporary` | `split_temporary` | 493-527 |

## Internal helper
- `recreate_if_free(fd, ptrvn)` — mirrors Ghidra's
  `if (ptrvn->isFree()) ptrvn = data->newVarnode(...)` in splitLoad/splitStore
  (prefersplit.cc:303-304, 355-356). Uses `VarnodeBank::create_with_space` for
  free varnodes; returns the original otherwise.

## Funcdata additions
- `Funcdata::op_insert_after(op, follow)` — added to support split transforms
  that insert new ops adjacent to the original (prefersplit.cc insertAfter
  calls). Faithful to `Funcdata::opInsertAfter` (funcdata.hh:456).

## Algorithm notes
- **splitVarnode** dispatches on whether the Varnode is written or not.
  Written Varnodes must have `hasNoDescend` and be defined by COPY/PIECE/LOAD/
  INT_ZEXT; unwritten Varnodes must be free with a single descendant (loneDescend)
  that is a COPY/SUBPIECE/STORE.
- **splitRecord** re-iterates `loc_tree` after each successful split (Rudra
  loops until no matches remain), matching Ghidra's iterator regeneration.
- **splitAdditional** scans `tempsplits` for SUBPIECE inputs / PIECE outputs in
  Unique space, then runs `testTemporary` + `splitTemporary` on each candidate.
- **Endianness** is read from the Varnode's space (`is_big_endian`); Rudra's
  `AddressSpace::is_big_endian` currently returns false (little-endian default).
<!-- annotation-pass: 2026-07-04 -->
