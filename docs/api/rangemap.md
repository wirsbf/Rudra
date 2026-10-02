# rangemap.rs — Interval map + partition map API

Faithful port of Ghidra's `rangemap.hh` (426 lines) + `partmap.hh` (233 lines).

**Status:** L2.5. `RangeMap` common-refinement behavior is implemented and
covered by a locked 12.0.4 direct-template oracle; production
`SymbolEntry`/`ParamEntryRange`/`ScopeMapper` consumers are tracked
separately. `PartMap` is not part of this fixture.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/rangemap.hh, partmap.hh`.

## Trait `RangeRecord`
A record in a RangeMap occupying `[first, last]`.

- Associated `Subsort: RangeSubsort` is the secondary ordering key used when
  records share a refined partition.
- `first() -> u64`, `last() -> u64`, `subsort() -> Subsort`.

## Trait `RangeSubsort`

Models Ghidra's `subsorttype(false)` and `subsorttype(true)` sentinels.

- `minimum()` must sort before every real record sub-sort.
- `maximum()` must sort after every real record sub-sort.
- Primitive integer types and `()` have convenience implementations; consumer
  types with narrower sentinel contracts can implement the trait directly.

## `RangeMap<R: RangeRecord>`
Interval map container for overlapping records (`rangemap.hh:65`). It stores
the common refinement of all ranges in a comparator-equivalent multiset:
the only ordering key is `(sub-range last, record subsort)`. Equal keys retain
multiplicity and the hinted/unhinted insertion positions observed in Ghidra;
`first` is deliberately not an artificial tie-break.

- `new()`, `is_empty()`, `clear()`, `len()`.
- `insert(record) -> RangeMapId` — performs left/right `unzip` refinements,
  inserts every covered partition, preserves Ghidra record-list order, and
  returns stable record identity (`rangemap.hh:223-277`).
- `erase(id) -> Option<R>` / `erase_at(cursor) -> Option<R>` — removes every
  partition belonging to the record and `zip`s boundaries no longer required
  by another range (`rangemap.hh:281-326`).
- `find(point) -> RangeMapIter<R>` — exact intersecting partition domain in
  ascending `(last, subsort)` multiset order (`rangemap.hh:332-347`).
- `find_with_subsort(point, low, high) -> RangeMapIter<R>` — reproduces the
  two-key `lower_bound`/`upper_bound` overload (`rangemap.hh:355-369`).
- `find_begin(point) -> RangeMapCursor`, `find_end(point) -> RangeMapCursor`,
  and `iter_between(begin, end)` — represent the public `PartIterator` range
  used for bounded ordered walks (`rangemap.hh:375-404`). A cursor stores the
  owning map generation and stable internal part identity, not a current
  ordinal: unrelated insertions, equivalent-key hinted/unhinted insertions,
  and `unzip` preserve it exactly as `std::multiset` preserves iterators.
  `erase` invalidates cursors to the erased record's parts; `zip` additionally
  invalidates only the left partition parts it removes while cursors to the
  right parts extended in place remain live.
- `next_cursor()` / `previous_cursor()` implement `PartIterator` movement;
  `record_at_cursor()` safely dereferences a live non-end cursor and
  `cursor_is_valid()` exposes the Rust-side validity contract. A cursor from a
  different map is rejected. The owning map's end cursor remains end across
  insertion and targeted erasure.
- `find_overlap(point, end) -> Option<&R>` — returns the record attached to the
  first intersecting refined sub-range, including the first unit after a gap
  (`rangemap.hh:411-423`).
- `iter()` walks all refined sub-ranges, so a record can appear multiple times;
  `records()` walks the internal record list exactly once per record.
- `find_at_point()` and `find_container()` are Rust compatibility adapters over
  the exact partition iterator.

Behavior evidence:

- `tests/oracle/rangemap_common_refinement_1204.{cc,rs,metadata.json}`
- `tools/run_rangemap_common_refinement_oracle.sh`
- 43 byte-compared observations cover equal ranges/equal sub-sorts,
  comparator-equivalent insertion positions, wide/narrow insertion in both
  orders, left/right boundary split and erase sewing, gap overlap, bounded
  iteration, record-list order, full ordered walks, cursor-stable insertion
  before/after/equivalent positions and `unzip`, the canonical insert-before
  counterexample, and the exact `erase`/`zip` cursor-invalidation matrix.

## `PartMap<V: Clone>`
Partition map from linear space to values (partmap.hh:49).
- `new(default_value)`.
- `get_value(pnt) -> &V` — lookup (partmap.hh:82).
- `get_value_mut(pnt) -> &mut V`.
- `split(pnt) -> &mut V` — introduce split point, copies previous value
  (partmap.hh:117).
- `clear_range(pnt1, pnt2)` — clear intermediate split points (partmap.hh:144).
- `bounds(pnt) -> (&V, before, after, valid_code)` — value + bounds (partmap.hh:172).
  - valid: 0=both, 1=no lower, 2=no upper, 3=neither.
- `default_value()`, `default_value_mut()`, `clear()`, `is_empty()`,
  `num_splits()`, `splits()`.
<!-- annotation-pass: 2026-07-04 -->
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
