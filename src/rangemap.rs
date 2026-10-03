//! Range and partition maps — faithful port of `rangemap.hh` (426 lines) and
//! `partmap.hh` (233 lines).
//!
//! Generic interval map containers used by the symbol database (SymbolEntry
//! lookup) and the context database (property flag partition).
//!
//! # RangeMap
//! A container for records occupying (possibly overlapping) intervals. Records
//! are stored in a sorted list of disjoint sub-ranges forming the common
//! refinement of all record ranges. Find operations use binary search on the
//! sub-range boundaries.
//!
//! # PartMap
//! A map from a linear space to value objects. The linear space is partitioned
//! at split points; each partition maps to a value. The default value applies
//! before the first split point.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/rangemap.{hh},
//! partmap.hh.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

// ---------------------------------------------------------------------------
// RangeMap — interval map for overlapping records
// ---------------------------------------------------------------------------

/// Sub-sort values used by [`RangeMap`].
///
/// Ghidra requires `subsorttype(false)` and `subsorttype(true)` to construct
/// values before and after every real sub-sort respectively
/// (`rangemap.hh:50-55`).  Custom Rust sub-sort types express that contract
/// explicitly through this trait.
pub trait RangeSubsort: Ord + Clone {
    // RUDRA-GLUE: Rust trait spelling of rangemap.hh's subsorttype(false) contract.
    fn minimum() -> Self;

    // RUDRA-GLUE: Rust trait spelling of rangemap.hh's subsorttype(true) contract.
    fn maximum() -> Self;
}

impl RangeSubsort for () {
    // RUDRA-GLUE: Unit is the Rust analogue of ScopeMapper::NullSubsort.
    fn minimum() -> Self {}

    // RUDRA-GLUE: Unit is the Rust analogue of ScopeMapper::NullSubsort.
    fn maximum() -> Self {}
}

macro_rules! impl_numeric_range_subsort {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl RangeSubsort for $ty {
                // RUDRA-GLUE: Primitive convenience implementation for a Rust record sub-sort.
                fn minimum() -> Self { <$ty>::MIN }

                // RUDRA-GLUE: Primitive convenience implementation for a Rust record sub-sort.
                fn maximum() -> Self { <$ty>::MAX }
            }
        )+
    };
}

impl_numeric_range_subsort!(i8, i16, i32, i64, i128, isize);
impl_numeric_range_subsort!(u8, u16, u32, u64, u128, usize);

/// A record in a [`RangeMap`], occupying the inclusive interval
/// `[first, last]`.
pub trait RangeRecord {
    type Subsort: RangeSubsort;

    // RUDRA-GLUE: first (no Ghidra counterpart found)
    /// The start of the record's range.
    fn first(&self) -> u64;

    // RUDRA-GLUE: last (no Ghidra counterpart found)
    /// The end of the record's range (inclusive).
    fn last(&self) -> u64;

    // RUDRA-GLUE: Rust trait spelling of recordtype::getSubsort required by rangemap.hh:36.
    /// Return the value used to order records sharing one refined partition.
    fn subsort(&self) -> Self::Subsort;
}

/// Stable identity for a record stored in a [`RangeMap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RangeMapId(u64);

static NEXT_RANGE_MAP_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Opaque stable iterator into the ordered sub-range multiset.
///
/// The cursor identifies one `AddrRange`-equivalent part by identity rather
/// than by its current ordinal.  Like `std::multiset` iterators, unrelated
/// insertions do not invalidate it; erasing that specific part does.  `None`
/// represents the owning map's past-the-end iterator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeMapCursor {
    owner_generation: u64,
    part_serial: Option<u64>,
}

/// Iterator over records attached to refined sub-ranges.
///
/// PERF-ALLOCFLOOR-0001: oracle form (rangemap.hh:330-346 find) returns a
/// lazy `std::multiset` iterator pair — zero allocation per query. The prior
/// Rudra form materialized a `Vec<&SubRange>` (all buckets) plus a `Vec<&R>`
/// (window records) per query. This iterator walks the BTreeMap buckets
/// lazily in both directions, skipping to the flattened window bounds, and
/// resolves records through the O(1) id index — same multiset order, no
/// per-query allocation.
pub struct RangeMapIter<'a, R: RangeRecord> {
    map: &'a RangeMap<R>,
    fwd: std::collections::btree_map::Iter<'a, RangeKey<R::Subsort>, Vec<SubRange<R::Subsort>>>,
    rev: std::collections::btree_map::Iter<'a, RangeKey<R::Subsort>, Vec<SubRange<R::Subsort>>>,
    /// Current front bucket and offset into it (fwd not yet started when None).
    fwd_cur: Option<(&'a Vec<SubRange<R::Subsort>>, usize)>,
    /// Current back bucket and exclusive end offset (rev not yet started when None).
    rev_cur: Option<(&'a Vec<SubRange<R::Subsort>>, usize)>,
    /// Flattened elements to skip before the window's first part.
    fwd_skip: usize,
    /// Flattened elements after the window's last part.
    rev_skip: usize,
    /// Total parts remaining in the window.
    remaining: usize,
}

impl<'a, R: RangeRecord> RangeMapIter<'a, R> {
    // RUDRA-GLUE: lazy flattened window [start, end) over the bucket multiset.
    fn window(map: &'a RangeMap<R>, start: usize, end: usize) -> Self {
        let total = map.tree.total_parts();
        let start = start.min(end).min(total);
        let end = end.min(total);
        Self {
            map,
            fwd: map.tree.buckets.iter(),
            rev: map.tree.buckets.iter(),
            fwd_cur: None,
            rev_cur: None,
            fwd_skip: start,
            rev_skip: total - end,
            remaining: end - start,
        }
    }
}

impl<'a, R: RangeRecord> Iterator for RangeMapIter<'a, R> {
    type Item = &'a R;

    // Ghidra: rangemap.hh:107 PartIterator &operator++(void)
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        loop {
            if self.fwd_cur.is_none() {
                self.fwd_cur = self.fwd.next().map(|(_key, bucket)| (bucket, 0usize));
                if self.fwd_cur.is_none() {
                    return None; // bucket multiset exhausted (window exhausted)
                }
            }
            let (bucket, idx) = *self.fwd_cur.as_ref().unwrap();
            if self.fwd_skip > 0 {
                // Bucket-wise skip — never walks skipped elements one by one.
                let take = self.fwd_skip.min(bucket.len() - idx);
                self.fwd_skip -= take;
                let next_idx = idx + take;
                self.fwd_cur = if next_idx == bucket.len() {
                    None
                } else {
                    Some((bucket, next_idx))
                };
                continue;
            }
            if idx >= bucket.len() {
                self.fwd_cur = None;
                continue;
            }
            self.fwd_cur = if idx + 1 == bucket.len() {
                None
            } else {
                Some((bucket, idx + 1))
            };
            self.remaining -= 1;
            let map: &'a RangeMap<R> = self.map;
            return Some(map.record_by_id(bucket[idx].record_id));
        }
    }

    // RUDRA-GLUE: forwards the remaining-window count.
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<R: RangeRecord> DoubleEndedIterator for RangeMapIter<'_, R> {
    // Ghidra: rangemap.hh:110 PartIterator &operator--(void)
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        loop {
            if self.rev_cur.is_none() {
                self.rev_cur = self
                    .rev
                    .next_back()
                    .map(|(_key, bucket)| (bucket, bucket.len()));
                if self.rev_cur.is_none() {
                    return None; // bucket multiset exhausted (window exhausted)
                }
            }
            let (bucket, end_idx) = *self.rev_cur.as_ref().unwrap();
            if self.rev_skip > 0 {
                // Bucket-wise skip from the back.
                let take = self.rev_skip.min(end_idx);
                self.rev_skip -= take;
                let next_end = end_idx - take;
                self.rev_cur = if next_end == 0 {
                    None
                } else {
                    Some((bucket, next_end))
                };
                continue;
            }
            if end_idx == 0 {
                self.rev_cur = None;
                continue;
            }
            self.rev_cur = if end_idx - 1 == 0 {
                None
            } else {
                Some((bucket, end_idx - 1))
            };
            self.remaining -= 1;
            let map: &RangeMap<R> = self.map;
            return Some(map.record_by_id(bucket[end_idx - 1].record_id));
        }
    }
}

impl<R: RangeRecord> ExactSizeIterator for RangeMapIter<'_, R> {
    // RUDRA-GLUE: ExactSizeIterator exposure for the lazy window domain.
    fn len(&self) -> usize {
        self.remaining
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RangeKey<S: RangeSubsort> {
    last: u64,
    subsort: S,
}

/// A sub-range entry in the internal common refinement.
#[derive(Clone)]
struct SubRange<S: RangeSubsort> {
    serial: u64,
    first: u64,
    last: u64,
    full_first: u64,
    full_last: u64,
    subsort: S,
    record_id: RangeMapId,
}

struct StoredRecord<R> {
    id: RangeMapId,
    value: R,
}

/// Exact `std::multiset<AddrRange>` model.
///
/// The B-tree key is precisely Ghidra's `AddrRange::operator<` key:
/// `(last, subsort)`.  The vector in a bucket is not an extra tie-break; it is
/// the ordered multiplicity of comparator-equivalent multiset elements.
struct RangeTree<S: RangeSubsort> {
    buckets: BTreeMap<RangeKey<S>, Vec<SubRange<S>>>,
}

impl<S: RangeSubsort> Default for RangeTree<S> {
    // RUDRA-GLUE: constructs the Rust backing store for std::multiset<AddrRange>.
    fn default() -> Self {
        Self {
            buckets: BTreeMap::new(),
        }
    }
}

impl<S: RangeSubsort> RangeTree<S> {
    // RUDRA-GLUE: materializes multiset order while retaining equivalent-element order.
    fn ordered_parts(&self) -> Vec<SubRange<S>> {
        self.buckets
            .values()
            .flat_map(|bucket| bucket.iter().cloned())
            .collect()
    }

    // RUDRA-GLUE: rebuilds exact comparator-equivalence buckets after mutation.
    fn replace_ordered_parts(&mut self, parts: Vec<SubRange<S>>) {
        self.buckets.clear();
        for part in parts {
            let key = RangeKey {
                last: part.last,
                subsort: part.subsort.clone(),
            };
            self.buckets.entry(key).or_default().push(part);
        }
    }

    // RUDRA-GLUE: exposes immutable flattened multiset positions to Rust cursors.
    // PERF-ALLOCFLOOR-0001: the query paths no longer materialize the flattened
    // Vec; these bucket-walk helpers implement the same flattened position
    // domain with zero allocation (oracle walks its multiset in place).
    fn total_parts(&self) -> usize {
        self.buckets.values().map(|bucket| bucket.len()).sum()
    }

    // RUDRA-GLUE: partition_point over the flattened multiset for a strict key
    // bound — the predicate is uniform within a bucket (it depends only on the
    // bucket key), so the count is the sum of strictly-below bucket lengths.
    fn count_parts_below(&self, key: &RangeKey<S>) -> usize {
        self.buckets.range(..key).map(|(_k, b)| b.len()).sum()
    }

    // RUDRA-GLUE: partition_point over the flattened multiset for an inclusive
    // key bound (subsort-maximum semantics), summing bucket lengths.
    fn count_parts_at_most(&self, key: &RangeKey<S>) -> usize {
        self.buckets.range(..=key).map(|(_k, b)| b.len()).sum()
    }

    // RUDRA-GLUE: first bucket whose key is at or after `key` (lower_bound).
    fn first_bucket_at_or_after(
        &self,
        key: &RangeKey<S>,
    ) -> Option<(&RangeKey<S>, &Vec<SubRange<S>>)> {
        self.buckets.range(key..).next()
    }

    // RUDRA-GLUE: part at a flattened multiset position, bucket-wise walk.
    fn part_at_flattened(&self, position: usize) -> Option<&SubRange<S>> {
        let mut position = position;
        for bucket in self.buckets.values() {
            if position < bucket.len() {
                return Some(&bucket[position]);
            }
            position -= bucket.len();
        }
        None
    }

    // RUDRA-GLUE: flattened multiset position of a part serial, bucket-wise walk.
    fn position_of_serial(&self, serial: u64) -> Option<usize> {
        let mut base = 0usize;
        for bucket in self.buckets.values() {
            if let Some(offset) = bucket.iter().position(|part| part.serial == serial) {
                return Some(base + offset);
            }
            base += bucket.len();
        }
        None
    }
}

/// An interval map container. Records can overlap; the container maintains a
/// multiset of disjoint sub-ranges forming the common refinement of all record
/// ranges.  Ordering and multiplicity follow Ghidra's `rangemap<>` exactly:
/// sub-range end first, then record sub-sort, with comparator-equivalent
/// entries retained in multiset order.
pub struct RangeMap<R: RangeRecord> {
    tree: RangeTree<R::Subsort>,
    records: Vec<StoredRecord<R>>,
    /// O(1) record id -> `records` position. PERF-ALLOCFLOOR-0001: the oracle
    /// stores the record list iterator directly in each AddrRange
    /// (rangemap.hh:60-62 `value`), so record access is a pointer deref; the
    /// prior Rust linear scan over `records` per resolved part had no oracle
    /// counterpart. Ids stay unique across erase (monotonic counter), so this
    /// side index is exact for every live record.
    record_index: std::collections::HashMap<RangeMapId, usize>,
    owner_generation: u64,
    next_record_id: u64,
    next_part_serial: u64,
}

impl<R: RangeRecord> Default for RangeMap<R> {
    // RUDRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

impl<R: RangeRecord> RangeMap<R> {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Create an empty range map.
    pub fn new() -> Self {
        Self {
            tree: RangeTree::default(),
            records: Vec::new(),
            record_index: std::collections::HashMap::new(),
            owner_generation: NEXT_RANGE_MAP_GENERATION.fetch_add(1, AtomicOrdering::Relaxed),
            next_record_id: 0,
            next_part_serial: 0,
        }
    }

    // Ghidra: rangemap.hh:135 bool empty(void) const
    /// Is the container empty? Faithful to `empty`.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    // Ghidra: rangemap.hh:136 void clear(void)
    /// Clear all records. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.tree.buckets.clear();
        self.records.clear();
        self.record_index.clear();
    }

    // RUDRA-GLUE: len (no Ghidra counterpart found)
    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    // RUDRA-GLUE: comparison helper implementing AddrRange::operator< without an artificial tie-break.
    fn compare_part_to_key(part: &SubRange<R::Subsort>, key: &RangeKey<R::Subsort>) -> Ordering {
        part.last
            .cmp(&key.last)
            .then_with(|| part.subsort.cmp(&key.subsort))
    }

    // RUDRA-GLUE: std::multiset::lower_bound adapter over an ordered mutation snapshot.
    fn lower_bound(parts: &[SubRange<R::Subsort>], key: &RangeKey<R::Subsort>) -> usize {
        parts.partition_point(|part| Self::compare_part_to_key(part, key) == Ordering::Less)
    }

    // RUDRA-GLUE: std::multiset::upper_bound adapter over an ordered mutation snapshot.
    fn upper_bound(parts: &[SubRange<R::Subsort>], key: &RangeKey<R::Subsort>) -> usize {
        parts.partition_point(|part| Self::compare_part_to_key(part, key) != Ordering::Greater)
    }

    // RUDRA-GLUE: allocates internal identity needed to preserve C++ iterator identity across Vec snapshots.
    fn allocate_part(
        &mut self,
        first: u64,
        last: u64,
        full_first: u64,
        full_last: u64,
        subsort: R::Subsort,
        record_id: RangeMapId,
    ) -> SubRange<R::Subsort> {
        let serial = self.next_part_serial;
        self.next_part_serial = self.next_part_serial.wrapping_add(1);
        SubRange {
            serial,
            first,
            last,
            full_first,
            full_last,
            subsort,
            record_id,
        }
    }

    // RUDRA-GLUE: finds a stable internal iterator after multiset insertion.
    fn index_of_serial(parts: &[SubRange<R::Subsort>], serial: u64) -> usize {
        parts
            .iter()
            .position(|part| part.serial == serial)
            .expect("internal rangemap iterator must remain present")
    }

    // RUDRA-GLUE: exact std::multiset hinted insertion, including insertion before an equivalent hint.
    fn insert_hinted(
        parts: &mut Vec<SubRange<R::Subsort>>,
        hint_serial: u64,
        part: SubRange<R::Subsort>,
    ) -> usize {
        let hint = Self::index_of_serial(parts, hint_serial);
        let key = RangeKey {
            last: part.last,
            subsort: part.subsort.clone(),
        };
        let fits_before_hint = (hint == 0
            || Self::compare_part_to_key(&parts[hint - 1], &key) != Ordering::Greater)
            && Self::compare_part_to_key(&parts[hint], &key) != Ordering::Less;
        let fits_after_hint = hint + 1 == parts.len()
            || (Self::compare_part_to_key(&parts[hint], &key) != Ordering::Greater
                && Self::compare_part_to_key(&parts[hint + 1], &key) != Ordering::Less);
        let position = if fits_before_hint {
            hint
        } else if fits_after_hint {
            hint + 1
        } else {
            Self::lower_bound(parts, &key)
        };
        parts.insert(position, part);
        Self::index_of_serial(parts, hint_serial)
    }

    // RUDRA-GLUE: std::multiset::insert places an unhinted equivalent after existing equivalents.
    fn insert_unhinted(parts: &mut Vec<SubRange<R::Subsort>>, part: SubRange<R::Subsort>) {
        let key = RangeKey {
            last: part.last,
            subsort: part.subsort.clone(),
        };
        let position = Self::upper_bound(parts, &key);
        parts.insert(position, part);
    }

    // Ghidra: rangemap.hh:177 void rangemap<_recordtype>::zip(linetype i,typename std::multiset<AddrRange>::iterator iter)
    fn zip(parts: &mut Vec<SubRange<R::Subsort>>, mut boundary: u64, iter: usize) {
        let first = parts[iter].first;
        while iter < parts.len() && parts[iter].last == boundary {
            parts.remove(iter);
        }
        boundary = boundary.wrapping_add(1);
        let mut cursor = iter;
        while cursor < parts.len() && parts[cursor].first == boundary {
            parts[cursor].first = first;
            cursor += 1;
        }
    }

    // Ghidra: rangemap.hh:196 void rangemap<_recordtype>::unzip(linetype i,typename std::multiset<AddrRange>::iterator iter)
    fn unzip(
        &mut self,
        parts: &mut Vec<SubRange<R::Subsort>>,
        boundary: u64,
        iter: usize,
    ) -> usize {
        let hint_serial = parts[iter].serial;
        if parts[iter].last == boundary {
            return iter;
        }
        let plus_one = boundary.wrapping_add(1);
        let mut current_serial = Some(hint_serial);
        while let Some(serial) = current_serial {
            let current = Self::index_of_serial(parts, serial);
            if parts[current].first > boundary {
                break;
            }
            let next = parts.get(current + 1).map(|part| part.serial);
            let old_first = parts[current].first;
            parts[current].first = plus_one;
            let left = self.allocate_part(
                old_first,
                boundary,
                parts[current].full_first,
                parts[current].full_last,
                parts[current].subsort.clone(),
                parts[current].record_id,
            );
            Self::insert_hinted(parts, hint_serial, left);
            current_serial = next;
        }
        Self::index_of_serial(parts, hint_serial)
    }

    // Ghidra: rangemap.hh:223 typename std::list<_recordtype>::iterator rangemap<_recordtype>::insert(const inittype &data,linetype a,linetype b)
    /// Insert a record and return its stable identity.
    pub fn insert(&mut self, record: R) -> RangeMapId {
        let a = record.first();
        let b = record.last();
        let subsort = record.subsort();
        let mut parts = self.tree.ordered_parts();
        let low_key = RangeKey {
            last: a,
            subsort: R::Subsort::minimum(),
        };
        let mut low = Self::lower_bound(&parts, &low_key);
        if low < parts.len() && parts[low].first < a {
            low = self.unzip(&mut parts, a.wrapping_sub(1), low);
        }

        let id = RangeMapId(self.next_record_id);
        self.next_record_id = self.next_record_id.wrapping_add(1);
        let spot_key = RangeKey {
            last: b,
            subsort: subsort.clone(),
        };
        let spot = Self::lower_bound(&parts, &spot_key);
        let record_position = parts
            .get(spot)
            .and_then(|part| self.record_index.get(&part.record_id).copied())
            .unwrap_or(self.records.len());
        self.records
            .insert(record_position, StoredRecord { id, value: record });
        // PERF-ALLOCFLOOR-0001: maintain the id side index alongside the
        // record list insertion (positions at or after the insert shift).
        for position in self.record_index.values_mut() {
            if *position >= record_position {
                *position += 1;
            }
        }
        self.record_index.insert(id, record_position);

        let mut first = a;
        while low < parts.len() && parts[low].first <= b {
            if first <= parts[low].last {
                if first < parts[low].first {
                    let existing_first = parts[low].first;
                    let hint_serial = parts[low].serial;
                    let gap = self.allocate_part(
                        first,
                        existing_first.wrapping_sub(1),
                        a,
                        b,
                        subsort.clone(),
                        id,
                    );
                    low = Self::insert_hinted(&mut parts, hint_serial, gap);
                    first = existing_first;
                }
                if parts[low].last <= b {
                    let partition_last = parts[low].last;
                    let hint_serial = parts[low].serial;
                    let overlap =
                        self.allocate_part(first, partition_last, a, b, subsort.clone(), id);
                    low = Self::insert_hinted(&mut parts, hint_serial, overlap);
                    if partition_last == b {
                        break;
                    }
                    first = partition_last.wrapping_add(1);
                } else if b < parts[low].last {
                    self.unzip(&mut parts, b, low);
                    break;
                }
            }
            low += 1;
        }
        if first <= b {
            let tail = self.allocate_part(first, b, a, b, subsort, id);
            Self::insert_unhinted(&mut parts, tail);
        }
        self.tree.replace_ordered_parts(parts);
        id
    }

    // Ghidra: rangemap.hh:281 void rangemap<_recordtype>::erase(typename std::list<_recordtype>::iterator v)
    /// Erase one record and sew partition boundaries no longer required by
    /// any remaining record.
    pub fn erase(&mut self, id: RangeMapId) -> Option<R> {
        let record_position = self.record_index.get(&id).copied()?;
        let a = self.records[record_position].value.first();
        let b = self.records[record_position].value.last();
        let mut parts = self.tree.ordered_parts();
        let low_key = RangeKey {
            last: a,
            subsort: R::Subsort::minimum(),
        };
        let mut low = Self::lower_bound(&parts, &low_key);
        let mut upper_low = low;
        let mut left_sew = true;
        let mut right_sew = true;
        let mut right_overlap = false;
        let mut left_overlap = false;
        let a_minus_one = a.wrapping_sub(1);
        while upper_low != 0 {
            upper_low -= 1;
            if parts[upper_low].last != a_minus_one {
                break;
            }
            if parts[upper_low].full_last == a_minus_one {
                left_sew = false;
                break;
            }
        }
        while low < parts.len() {
            if parts[low].record_id == id {
                parts.remove(low);
            } else {
                if parts[low].full_first < a {
                    left_overlap = true;
                } else if parts[low].full_first == a {
                    left_sew = false;
                }
                if b < parts[low].full_last {
                    right_overlap = true;
                } else if parts[low].full_last == b {
                    right_sew = false;
                }
                low += 1;
            }
            if low == parts.len() || parts[low].first > b {
                break;
            }
        }
        if low < parts.len() && parts[low].full_first.wrapping_sub(1) == b {
            right_sew = false;
        }
        if left_sew && left_overlap {
            let key = RangeKey {
                last: a_minus_one,
                subsort: R::Subsort::minimum(),
            };
            let iter = Self::lower_bound(&parts, &key);
            Self::zip(&mut parts, a_minus_one, iter);
        }
        if right_sew && right_overlap {
            let key = RangeKey {
                last: b,
                subsort: R::Subsort::minimum(),
            };
            let iter = Self::lower_bound(&parts, &key);
            Self::zip(&mut parts, b, iter);
        }
        self.tree.replace_ordered_parts(parts);
        let value = self.records.remove(record_position).value;
        // PERF-ALLOCFLOOR-0001: maintain the id side index alongside the
        // record list removal (positions after the removal shift down).
        self.record_index.remove(&id);
        for position in self.record_index.values_mut() {
            if *position > record_position {
                *position -= 1;
            }
        }
        Some(value)
    }

    // Ghidra: rangemap.hh:168 void erase(const_iterator iter)
    /// Erase the record referenced by a sub-range cursor.
    pub fn erase_at(&mut self, cursor: RangeMapCursor) -> Option<R> {
        let position = self.resolve_cursor(cursor)?;
        let id = self
            .tree
            .part_at_flattened(position)
            .map(|part| part.record_id)?;
        self.erase(id)
    }

    // RUDRA-GLUE: resolves stable PartIterator identity after non-invalidating tree mutations.
    fn resolve_cursor(&self, cursor: RangeMapCursor) -> Option<usize> {
        if cursor.owner_generation != self.owner_generation {
            return None;
        }
        match cursor.part_serial {
            Some(serial) => self.tree.position_of_serial(serial),
            None => Some(self.tree.total_parts()),
        }
    }

    // RUDRA-GLUE: constructs a stable Rust cursor from a current multiset ordinal.
    fn cursor_at_flattened(&self, position: usize) -> RangeMapCursor {
        RangeMapCursor {
            owner_generation: self.owner_generation,
            part_serial: self.tree.part_at_flattened(position).map(|part| part.serial),
        }
    }

    // RUDRA-GLUE: safe validity observation for C++ iterator-invalidating operations.
    /// Return whether a cursor still denotes a live part or this map's end.
    pub fn cursor_is_valid(&self, cursor: RangeMapCursor) -> bool {
        self.resolve_cursor(cursor).is_some()
    }

    // Ghidra: rangemap.hh:106 _recordtype &operator*(void)
    /// Return the record referenced by a live non-end cursor.
    pub fn record_at_cursor(&self, cursor: RangeMapCursor) -> Option<&R> {
        let position = self.resolve_cursor(cursor)?;
        let part = self.tree.part_at_flattened(position)?;
        Some(self.record_by_id(part.record_id))
    }

    // Ghidra: rangemap.hh:107 PartIterator &operator++(void)
    /// Advance a live non-end cursor to the following part (possibly end).
    pub fn next_cursor(&self, cursor: RangeMapCursor) -> Option<RangeMapCursor> {
        let position = self.resolve_cursor(cursor)?;
        if self.tree.part_at_flattened(position).is_none() {
            return None; // position denotes this map's end
        }
        Some(self.cursor_at_flattened(position + 1))
    }

    // Ghidra: rangemap.hh:110 PartIterator &operator--(void)
    /// Move a live cursor to the preceding part; end moves to the final part.
    pub fn previous_cursor(&self, cursor: RangeMapCursor) -> Option<RangeMapCursor> {
        let position = self.resolve_cursor(cursor)?;
        if position == 0 {
            return None;
        }
        Some(self.cursor_at_flattened(position - 1))
    }

    // RUDRA-GLUE: resolves stable record identity to a Rust reference.
    // PERF-ALLOCFLOOR-0001: O(1) via the id side index — the oracle's AddrRange
    // carries the record list iterator directly (rangemap.hh:60-62), so the
    // prior linear scan over all records per resolved part was pure Rust-side
    // overhead.
    fn record_by_id(&self, id: RangeMapId) -> &R {
        let position = *self
            .record_index
            .get(&id)
            .expect("rangemap partition must reference a live record");
        &self.records[position].value
    }

    // RUDRA-GLUE: materializes a Rust iterator from the opaque PartIterator index domain.
    // PERF-ALLOCFLOOR-0001: lazy bucket walk over the flattened window — no
    // per-query Vec (oracle returns a lazy multiset iterator pair,
    // rangemap.hh:330-346).
    fn iterator_for_bounds(&self, start: usize, end: usize) -> RangeMapIter<'_, R> {
        RangeMapIter::window(self, start, end)
    }

    // Ghidra: rangemap.hh:332 rangemap<_recordtype>::find(linetype point) const
    /// Iterate over every sub-range intersecting `point` in ascending sub-sort
    /// and comparator-equivalent multiset order.
    pub fn find(&self, point: u64) -> RangeMapIter<'_, R> {
        let start_key = RangeKey {
            last: point,
            subsort: R::Subsort::minimum(),
        };
        let start = self.tree.count_parts_below(&start_key);
        // The part at flattened position `start` is the first element of the
        // first bucket at or after `start_key` (same check as the oracle's
        // `iter1 == tree.end() || point < (*iter1).first`, rangemap.hh:340).
        let Some((bucket_key, bucket)) = self.tree.first_bucket_at_or_after(&start_key) else {
            return self.iterator_for_bounds(start, start);
        };
        if point < bucket[0].first {
            return self.iterator_for_bounds(start, start);
        }
        let end_key = RangeKey {
            last: bucket_key.last,
            subsort: R::Subsort::maximum(),
        };
        let end = self.tree.count_parts_at_most(&end_key);
        self.iterator_for_bounds(start, end)
    }

    // Ghidra: rangemap.hh:355 rangemap<_recordtype>::find(linetype point,const subsorttype &sub1,const subsorttype &sub2) const
    /// Iterate over intersecting sub-ranges bounded by Ghidra's sub-sort
    /// lower/upper keys.
    pub fn find_with_subsort(
        &self,
        point: u64,
        subsort1: &R::Subsort,
        subsort2: &R::Subsort,
    ) -> RangeMapIter<'_, R> {
        let start_key = RangeKey {
            last: point,
            subsort: subsort1.clone(),
        };
        let start = self.tree.count_parts_below(&start_key);
        let Some((bucket_key, bucket)) = self.tree.first_bucket_at_or_after(&start_key) else {
            return self.iterator_for_bounds(start, start);
        };
        if point < bucket[0].first {
            return self.iterator_for_bounds(start, start);
        }
        let end_key = RangeKey {
            last: bucket_key.last,
            subsort: subsort2.clone(),
        };
        let end = self.tree.count_parts_at_most(&end_key);
        self.iterator_for_bounds(start, end)
    }

    // Ghidra: rangemap.hh:375 typename rangemap<_recordtype>::const_iterator rangemap<_recordtype>::find_begin(linetype point) const
    /// Return the first multiset position whose ending boundary is at or after
    /// `point`.
    pub fn find_begin(&self, point: u64) -> RangeMapCursor {
        let key = RangeKey {
            last: point,
            subsort: R::Subsort::minimum(),
        };
        let position = self.tree.count_parts_below(&key);
        self.cursor_at_flattened(position)
    }

    // Ghidra: rangemap.hh:389 typename rangemap<_recordtype>::const_iterator rangemap<_recordtype>::find_end(linetype point) const
    /// Return the first position after the partition containing `point`, or
    /// the first position beyond `point` if it lies in a gap.
    pub fn find_end(&self, point: u64) -> RangeMapCursor {
        let bound = RangeKey {
            last: point,
            subsort: R::Subsort::maximum(),
        };
        let position = self.tree.count_parts_at_most(&bound);
        let Some(part) = self.tree.part_at_flattened(position) else {
            return self.cursor_at_flattened(position);
        };
        if point < part.first {
            return self.cursor_at_flattened(position);
        }
        // `point` is contained in the sub-range at `position`; the oracle
        // returns the first position after that whole containing partition
        // (rangemap.hh:402-403).
        let containing_bound = RangeKey {
            last: part.last,
            subsort: R::Subsort::maximum(),
        };
        let end = self.tree.count_parts_at_most(&containing_bound);
        self.cursor_at_flattened(end)
    }

    // RUDRA-GLUE: Rust range adapter for two Ghidra PartIterator cursors.
    /// Iterate between two cursors returned by this map.
    pub fn iter_between(&self, begin: RangeMapCursor, end: RangeMapCursor) -> RangeMapIter<'_, R> {
        let Some(begin) = self.resolve_cursor(begin) else {
            return self.iterator_for_bounds(0, 0);
        };
        let Some(end) = self.resolve_cursor(end) else {
            return self.iterator_for_bounds(0, 0);
        };
        self.iterator_for_bounds(begin, end)
    }

    // Ghidra: rangemap.hh:411 typename rangemap<_recordtype>::const_iterator rangemap<_recordtype>::find_overlap(linetype point,linetype end) const
    /// Find the first record overlapping the given interval [point, end].
    /// This is the first sub-range in `(last, subsort)` multiset order, which
    /// can begin after `point` when the query starts in a gap.
    pub fn find_overlap(&self, point: u64, end: u64) -> Option<&R> {
        let key = RangeKey {
            last: point,
            subsort: R::Subsort::minimum(),
        };
        let position = self.tree.count_parts_below(&key);
        let part = self.tree.part_at_flattened(position)?;
        if part.first <= end {
            return Some(self.record_by_id(part.record_id));
        }
        None
    }

    // RUDRA-GLUE: compatibility collector over Ghidra rangemap::find.
    /// Collect all sub-range records intersecting `point`.
    pub fn find_at_point(&self, point: u64) -> Vec<&R> {
        self.find(point).collect()
    }

    // RUDRA-GLUE: Scope-style smallest-container query retained for existing Rust consumers.
    /// Find the smallest containing record for [point, size).
    /// Used by Scope::findContainer.
    pub fn find_container(&self, point: u64, size: u64) -> Option<&R> {
        let end = point.wrapping_add(size).wrapping_sub(1);
        let mut best: Option<&R> = None;
        let mut best_span = u64::MAX;
        for record in self.find(point).rev() {
            if record.first() <= point && end <= record.last() {
                let span = record.last().wrapping_sub(record.first()).wrapping_add(1);
                if span < best_span {
                    best_span = span;
                    best = Some(record);
                }
            }
        }
        best
    }

    // Ghidra: rangemap.hh:137 typename std::list<_recordtype>::const_iterator begin_list(void) const
    /// Iterate once over each record in Ghidra's internal list order.
    pub fn records(&self) -> impl DoubleEndedIterator<Item = &R> {
        self.records.iter().map(|stored| &stored.value)
    }

    // Ghidra: rangemap.hh:142 const_iterator begin(void) const
    /// Iterate over the complete refined sub-range multiset.  Records appear
    /// once per stored sub-range and may therefore repeat.
    pub fn iter(&self) -> RangeMapIter<'_, R> {
        let len = self.tree.total_parts();
        self.iterator_for_bounds(0, len)
    }
}

// ---------------------------------------------------------------------------
// PartMap — partition map for address-keyed values
// ---------------------------------------------------------------------------

/// A map from a linear space to value objects. Faithful to `partmap<>`
/// (partmap.hh:49).
///
/// The linear space is partitioned at split points; each partition maps to a
/// value. The default value applies before the first split point.
#[derive(Clone)]
pub struct PartMap<V: Clone> {
    /// Map from split points to value objects.
    database: BTreeMap<u64, V>,
    /// The value before the first split point.
    default_value: V,
}

impl<V: Clone> PartMap<V> {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Construct with a default value.
    pub fn new(default_value: V) -> Self {
        Self {
            database: BTreeMap::new(),
            default_value,
        }
    }

    // RUDRA-GLUE: get_value (no Ghidra counterpart found)
    /// Get the value at a point. Faithful to `getValue` (partmap.hh:82).
    /// Looks up the first split point <= pnt.
    pub fn get_value(&self, pnt: u64) -> &V {
        match self.database.range(..=pnt).next_back() {
            Some((_, v)) => v,
            None => &self.default_value,
        }
    }

    // RUDRA-GLUE: get_value_mut (no Ghidra counterpart found)
    /// Get a mutable reference to the value at a point.
    pub fn get_value_mut(&mut self, pnt: u64) -> &mut V {
        // We need to handle the borrow checker carefully.
        let has_key = self
            .database
            .range(..=pnt)
            .next_back()
            .map(|(k, _)| *k)
            .is_some();
        if has_key {
            let key = self
                .database
                .range(..=pnt)
                .next_back()
                .map(|(k, _)| *k)
                .unwrap();
            self.database.get_mut(&key).unwrap()
        } else {
            &mut self.default_value
        }
    }

    // RUDRA-GLUE: split (no Ghidra counterpart found)
    /// Introduce a new split point. Faithful to `split` (partmap.hh:117).
    /// Copies the current value at pnt into the new partition.
    pub fn split(&mut self, pnt: u64) -> &mut V {
        if self.database.contains_key(&pnt) {
            return self.database.get_mut(&pnt).unwrap();
        }
        // Copy the current value at this point.
        let val = match self.database.range(..pnt).next_back() {
            Some((_, v)) => v.clone(),
            None => self.default_value.clone(),
        };
        self.database.entry(pnt).or_insert(val)
    }

    // RUDRA-GLUE: clear_range (no Ghidra counterpart found)
    /// Clear split points in a range. Faithful to `clearRange`
    /// (partmap.hh:144).
    /// Splits at pnt1 and pnt2, then removes all split points in between.
    pub fn clear_range(&mut self, pnt1: u64, pnt2: u64) {
        self.split(pnt1);
        self.split(pnt2);
        // Remove keys in (pnt1, pnt2).
        let keys_to_remove: Vec<u64> = self
            .database
            .range((
                std::ops::Bound::Excluded(pnt1),
                std::ops::Bound::Excluded(pnt2),
            ))
            .map(|(k, _)| *k)
            .collect();
        for k in keys_to_remove {
            self.database.remove(&k);
        }
    }

    // RUDRA-GLUE: default_value (no Ghidra counterpart found)
    /// Get the default value. Faithful to `defaultValue`.
    pub fn default_value(&self) -> &V {
        &self.default_value
    }

    // RUDRA-GLUE: default_value_mut (no Ghidra counterpart found)
    /// Get a mutable reference to the default value.
    pub fn default_value_mut(&mut self) -> &mut V {
        &mut self.default_value
    }

    // RUDRA-GLUE: clear (no Ghidra counterpart found)
    /// Clear all split points. Faithful to `clear`.
    pub fn clear(&mut self) {
        self.database.clear();
    }

    // RUDRA-GLUE: is_empty (no Ghidra counterpart found)
    /// Is the partition map empty of split points? Faithful to `empty`.
    pub fn is_empty(&self) -> bool {
        self.database.is_empty()
    }

    // RUDRA-GLUE: num_splits (no Ghidra counterpart found)
    /// Number of split points.
    pub fn num_splits(&self) -> usize {
        self.database.len()
    }

    // RUDRA-GLUE: bounds (no Ghidra counterpart found)
    /// Get the value and bounds at a point. Faithful to `bounds`
    /// (partmap.hh:172). Returns (value, before, after, valid_code):
    /// - 0 = both bounds apply
    /// - 1 = no lower bound
    /// - 2 = no upper bound
    /// - 3 = neither bound
    pub fn bounds(&self, pnt: u64) -> (&V, u64, u64, i32) {
        if self.database.is_empty() {
            return (&self.default_value, 0, 0, 3);
        }
        // Find the split point <= pnt.
        let lower = self.database.range(..=pnt).next_back();
        let upper = self
            .database
            .range((std::ops::Bound::Excluded(pnt), std::ops::Bound::Unbounded))
            .next();

        match (lower, upper) {
            (Some((lo_k, lo_v)), Some((hi_k, _))) => (lo_v, *lo_k, *hi_k, 0),
            (Some((lo_k, lo_v)), None) => (lo_v, *lo_k, 0, 2),
            (None, Some((hi_k, _))) => (&self.default_value, 0, *hi_k, 1),
            (None, None) => (&self.default_value, 0, 0, 3),
        }
    }

    // RUDRA-GLUE: splits (no Ghidra counterpart found)
    /// Iterate over all split points.
    pub fn splits(&self) -> impl Iterator<Item = (&u64, &V)> {
        self.database.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct TestRecord {
        first: u64,
        last: u64,
        name: &'static str,
    }

    impl RangeRecord for TestRecord {
        type Subsort = i32;

        fn first(&self) -> u64 {
            self.first
        }

        fn last(&self) -> u64 {
            self.last
        }

        fn subsort(&self) -> Self::Subsort {
            0
        }
    }

    #[derive(Debug, PartialEq)]
    struct OrderedRecord {
        first: u64,
        last: u64,
        subsort: i32,
        name: &'static str,
    }

    impl RangeRecord for OrderedRecord {
        type Subsort = i32;

        fn first(&self) -> u64 {
            self.first
        }

        fn last(&self) -> u64 {
            self.last
        }

        fn subsort(&self) -> Self::Subsort {
            self.subsort
        }
    }

    fn ordered_record(name: &'static str, subsort: i32, first: u64, last: u64) -> OrderedRecord {
        OrderedRecord {
            first,
            last,
            subsort,
            name,
        }
    }

    #[test]
    fn test_rangemap_empty() {
        let rm: RangeMap<TestRecord> = RangeMap::new();
        assert!(rm.is_empty());
        assert_eq!(rm.len(), 0);
    }

    #[test]
    fn test_rangemap_insert_find_overlap() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord {
            first: 100,
            last: 199,
            name: "A",
        });
        rm.insert(TestRecord {
            first: 300,
            last: 399,
            name: "B",
        });

        let r = rm.find_overlap(150, 160).unwrap();
        assert_eq!(r.name, "A");

        let r = rm.find_overlap(350, 360).unwrap();
        assert_eq!(r.name, "B");

        assert!(rm.find_overlap(200, 299).is_none());
    }

    #[test]
    fn test_rangemap_find_at_point() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord {
            first: 100,
            last: 199,
            name: "A",
        });
        rm.insert(TestRecord {
            first: 150,
            last: 250,
            name: "B",
        });

        let results = rm.find_at_point(175);
        assert_eq!(results.len(), 2); // Both A and B overlap at 175.
    }

    #[test]
    fn test_rangemap_find_container() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord {
            first: 100,
            last: 399,
            name: "big",
        });
        rm.insert(TestRecord {
            first: 100,
            last: 199,
            name: "small",
        });

        let r = rm.find_container(150, 10).unwrap();
        assert_eq!(r.name, "small"); // Smaller container wins.
    }

    #[test]
    fn test_rangemap_records() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord {
            first: 0,
            last: 10,
            name: "X",
        });
        rm.insert(TestRecord {
            first: 20,
            last: 30,
            name: "Y",
        });
        assert_eq!(rm.len(), 2);
        let names = rm.records().map(|record| record.name).collect::<Vec<_>>();
        assert_eq!(names, vec!["X", "Y"]);
    }

    #[test]
    fn test_rangemap_clear() {
        let mut rm = RangeMap::new();
        rm.insert(TestRecord {
            first: 0,
            last: 10,
            name: "X",
        });
        rm.clear();
        assert!(rm.is_empty());
    }

    #[test]
    fn test_rangemap_common_refinement_and_equivalent_multiset_order() {
        let mut map = RangeMap::new();
        map.insert(ordered_record("eq_a", 5, 10, 20));
        map.insert(ordered_record("eq_b", 5, 10, 20));
        map.insert(ordered_record("sub_hi", 9, 10, 20));
        map.insert(ordered_record("sub_lo", 1, 10, 20));

        let walk = map.iter().map(|record| record.name).collect::<Vec<_>>();
        assert_eq!(
            walk,
            vec!["sub_lo", "sub_lo", "eq_b", "eq_a", "eq_b", "sub_hi", "sub_hi"]
        );
        let list = map.records().map(|record| record.name).collect::<Vec<_>>();
        assert_eq!(list, vec!["sub_lo", "eq_b", "eq_a", "sub_hi"]);
    }

    #[test]
    fn test_rangemap_erase_sews_obsolete_boundaries() {
        let mut map = RangeMap::new();
        map.insert(ordered_record("outer", 5, 200, 240));
        let inner = map.insert(ordered_record("inner", 3, 210, 230));
        let right = map.insert(ordered_record("right", 7, 220, 250));

        map.erase(inner);
        assert_eq!(
            map.iter().map(|record| record.name).collect::<Vec<_>>(),
            vec!["outer", "outer", "right", "right"]
        );
        map.erase(right);
        assert_eq!(
            map.iter().map(|record| record.name).collect::<Vec<_>>(),
            vec!["outer"]
        );
    }

    #[test]
    fn test_rangemap_cursor_survives_insert_before_and_erases_original_record() {
        let mut map = RangeMap::new();
        map.insert(ordered_record("A", 5, 100, 110));
        let cursor = map.find_begin(100);
        map.insert(ordered_record("B", 5, 50, 60));

        assert_eq!(map.record_at_cursor(cursor).unwrap().name, "A");
        let mut other_map = RangeMap::new();
        other_map.insert(ordered_record("foreign", 5, 100, 110));
        assert!(!other_map.cursor_is_valid(cursor));
        assert_eq!(map.erase_at(cursor).unwrap().name, "A");
        assert!(!map.cursor_is_valid(cursor));
        assert_eq!(
            map.records().map(|record| record.name).collect::<Vec<_>>(),
            vec!["B"]
        );
    }

    #[test]
    fn test_rangemap_cursor_identity_and_precise_invalidation() {
        let mut map = RangeMap::new();
        let end_before_insert = map.find_begin(0);
        map.insert(ordered_record("outer", 5, 200, 240));
        let original_outer = map.find_begin(220);
        let inner_id = map.insert(ordered_record("inner", 3, 210, 230));

        let left_outer = map.find_begin(205);
        let inner_middle = map.find_begin(220);
        let middle_outer = map.next_cursor(inner_middle).unwrap();
        let right_outer = map.find_begin(235);

        assert!(map.cursor_is_valid(end_before_insert));
        assert!(map.record_at_cursor(end_before_insert).is_none());
        assert!(map.cursor_is_valid(original_outer));
        assert_eq!(map.record_at_cursor(original_outer).unwrap().name, "outer");

        map.erase(inner_id);
        assert!(!map.cursor_is_valid(left_outer));
        assert!(!map.cursor_is_valid(inner_middle));
        assert!(!map.cursor_is_valid(middle_outer));
        assert!(map.cursor_is_valid(right_outer));
        assert_eq!(map.record_at_cursor(right_outer).unwrap().name, "outer");
        assert!(map.cursor_is_valid(end_before_insert));
    }

    #[test]
    fn test_rangemap_cursor_survives_equivalent_and_unzip_insertions() {
        let mut equivalent = RangeMap::new();
        equivalent.insert(ordered_record("eq_a", 5, 10, 20));
        let eq_a_cursor = equivalent.find_begin(15);
        equivalent.insert(ordered_record("eq_b", 5, 10, 20));
        assert_eq!(
            equivalent.record_at_cursor(eq_a_cursor).unwrap().name,
            "eq_a"
        );

        let mut split = RangeMap::new();
        split.insert(ordered_record("wide", 5, 100, 140));
        let original_wide = split.find_begin(120);
        split.insert(ordered_record("narrow", 2, 110, 120));
        assert!(split.cursor_is_valid(original_wide));
        assert_eq!(split.record_at_cursor(original_wide).unwrap().name, "wide");
    }

    // PartMap tests

    #[test]
    fn test_partmap_default() {
        let pm: PartMap<u32> = PartMap::new(0);
        assert_eq!(*pm.get_value(100), 0);
        assert!(pm.is_empty());
    }

    #[test]
    fn test_partmap_split_and_get() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 5;
        *pm.split(20) = 99;

        assert_eq!(*pm.get_value(5), 0); // Before first split → default.
        assert_eq!(*pm.get_value(10), 5); // At split 10.
        assert_eq!(*pm.get_value(15), 5); // Between 10 and 20.
        assert_eq!(*pm.get_value(20), 99); // At split 20.
        assert_eq!(*pm.get_value(100), 99); // After last split.
    }

    #[test]
    fn test_partmap_split_copies_previous() {
        let mut pm: PartMap<u32> = PartMap::new(42);
        *pm.split(10) = 10;
        // Split at 20 should copy value from partition at 15 (which is 10).
        let val = pm.split(20);
        assert_eq!(*val, 10); // Copied from partition [10, 20).
    }

    #[test]
    fn test_partmap_split_exact() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 5;
        *pm.split(10) = 99; // Split at same point → overwrite.
        assert_eq!(*pm.get_value(10), 99);
    }

    #[test]
    fn test_partmap_clear_range() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 1;
        *pm.split(20) = 2;
        *pm.split(30) = 3;
        pm.clear_range(10, 30);
        // Should have splits at 10 and 30, with 20 removed.
        assert_eq!(pm.num_splits(), 2);
        assert_eq!(*pm.get_value(15), 1);
        assert_eq!(*pm.get_value(35), 3);
    }

    #[test]
    fn test_partmap_bounds() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.split(10) = 5;
        *pm.split(20) = 10;

        let (val, before, after, valid) = pm.bounds(15);
        assert_eq!(*val, 5);
        assert_eq!(before, 10);
        assert_eq!(after, 20);
        assert_eq!(valid, 0); // Both bounds.

        let (val, _, _, valid) = pm.bounds(5);
        assert_eq!(*val, 0); // Default.
        assert_eq!(valid, 1); // No lower bound.

        let (val, _, _, valid) = pm.bounds(100);
        assert_eq!(*val, 10);
        assert_eq!(valid, 2); // No upper bound.
    }

    #[test]
    fn test_partmap_bounds_empty() {
        let pm: PartMap<u32> = PartMap::new(42);
        let (val, _, _, valid) = pm.bounds(100);
        assert_eq!(*val, 42);
        assert_eq!(valid, 3); // Neither bound.
    }

    #[test]
    fn test_partmap_default_value_mut() {
        let mut pm: PartMap<u32> = PartMap::new(0);
        *pm.default_value_mut() = 77;
        assert_eq!(*pm.get_value(100), 77);
    }
}
