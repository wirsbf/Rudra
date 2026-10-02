// Locked Ghidra 12.0.4 rangemap<> oracle for
// RANGEMAP-COMMON-REFINEMENT-0001 (Rust comparand).

use rudra::rangemap::{RangeMap, RangeMapIter, RangeRecord, RangeSubsort};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Subsort(i32);

impl RangeSubsort for Subsort {
    fn minimum() -> Self {
        Self(0)
    }

    fn maximum() -> Self {
        Self(1_000_000)
    }
}

#[derive(Debug)]
struct TestRecord {
    name: &'static str,
    first: u64,
    last: u64,
    subsort: Subsort,
}

impl TestRecord {
    fn new(name: &'static str, subsort: i32, first: u64, last: u64) -> Self {
        Self {
            name,
            first,
            last,
            subsort: Subsort(subsort),
        }
    }
}

impl RangeRecord for TestRecord {
    type Subsort = Subsort;

    fn first(&self) -> u64 {
        self.first
    }

    fn last(&self) -> u64 {
        self.last
    }

    fn subsort(&self) -> Self::Subsort {
        self.subsort.clone()
    }
}

fn names<'a>(records: impl Iterator<Item = &'a TestRecord>) -> String {
    records
        .map(|record| record.name)
        .collect::<Vec<_>>()
        .join(",")
}

fn dump_find(label: &str, map: &RangeMap<TestRecord>, point: u64) {
    println!(
        "case={label}|find={point}|records={}",
        names(map.find(point))
    );
}

fn dump_find_subsort(label: &str, map: &RangeMap<TestRecord>, point: u64, low: i32, high: i32) {
    println!(
        "case={label}|find_sub={point}:{low}:{high}|records={}",
        names(map.find_with_subsort(point, &Subsort(low), &Subsort(high)))
    );
}

fn dump_walk(label: &str, map: &RangeMap<TestRecord>) {
    println!(
        "case={label}|walk={}|list={}",
        names(map.iter()),
        names(map.records())
    );
}

fn dump_overlap(label: &str, map: &RangeMap<TestRecord>, point: u64, end: u64) {
    let record = map
        .find_overlap(point, end)
        .map_or("null", |record| record.name);
    println!("case={label}|overlap={point}:{end}|record={record}");
}

fn dump_cursor(label: &str, map: &RangeMap<TestRecord>, cursor: rudra::rangemap::RangeMapCursor) {
    let record = map
        .record_at_cursor(cursor)
        .map_or("end", |record| record.name);
    println!("case={label}|cursor={record}");
}

fn equal_range_cases() {
    let mut map = RangeMap::new();
    map.insert(TestRecord::new("eq_a", 5, 10, 20));
    dump_walk("equal_after_a", &map);
    map.insert(TestRecord::new("eq_b", 5, 10, 20));
    dump_walk("equal_after_b", &map);
    map.insert(TestRecord::new("sub_hi", 9, 10, 20));
    dump_walk("equal_after_hi", &map);
    map.insert(TestRecord::new("sub_lo", 1, 10, 20));
    dump_walk("equal_after_lo", &map);
    dump_find("equal_range", &map, 15);
    dump_find_subsort("equal_subsort_window", &map, 15, 5, 5);
    dump_walk("equal_ordered_walk", &map);
}

fn wide_narrow_cases() {
    let mut wide_first = RangeMap::new();
    wide_first.insert(TestRecord::new("wide", 5, 100, 140));
    wide_first.insert(TestRecord::new("narrow", 2, 110, 120));
    dump_find("wide_first_left", &wide_first, 105);
    dump_find("wide_first_middle", &wide_first, 115);
    dump_find("wide_first_right", &wide_first, 130);
    dump_walk("wide_first_walk", &wide_first);

    let mut narrow_first = RangeMap::new();
    narrow_first.insert(TestRecord::new("narrow", 2, 110, 120));
    narrow_first.insert(TestRecord::new("wide", 5, 100, 140));
    dump_find("narrow_first_left", &narrow_first, 105);
    dump_find("narrow_first_middle", &narrow_first, 115);
    dump_find("narrow_first_right", &narrow_first, 130);
    dump_walk("narrow_first_walk", &narrow_first);
}

fn split_erase_cases() {
    let mut map = RangeMap::new();
    map.insert(TestRecord::new("outer", 5, 200, 240));
    let inner = map.insert(TestRecord::new("inner", 3, 210, 230));
    let right = map.insert(TestRecord::new("right", 7, 220, 250));
    dump_walk("split_before_erase", &map);
    dump_find("split_three_way", &map, 225);

    map.erase(inner);
    dump_walk("erase_inner_zip_left", &map);
    dump_find("erase_inner_middle", &map, 215);
    dump_find("erase_inner_overlap", &map, 225);

    map.erase(right);
    dump_walk("erase_right_zip_both", &map);
    dump_find("erase_right_outer", &map, 225);
}

fn overlap_and_range_walk_cases() {
    let mut map = RangeMap::new();
    map.insert(TestRecord::new("left", 4, 300, 305));
    map.insert(TestRecord::new("right_hi", 8, 310, 320));
    map.insert(TestRecord::new("right_lo", 2, 310, 315));
    dump_overlap("gap_hit", &map, 306, 312);
    dump_overlap("gap_miss", &map, 306, 309);
    dump_overlap("inside_order", &map, 312, 312);
    let begin = map.find_begin(304);
    let end = map.find_end(316);
    let bounded: RangeMapIter<'_, TestRecord> = map.iter_between(begin, end);
    println!("case=bounded_walk|range=304:316|records={}", names(bounded));
}

fn equivalent_split_cases() {
    let mut map = RangeMap::new();
    map.insert(TestRecord::new("same_a", 5, 400, 440));
    let same_b = map.insert(TestRecord::new("same_b", 5, 400, 440));
    let cut = map.insert(TestRecord::new("cut", 5, 410, 420));
    dump_walk("equivalent_split", &map);
    dump_find("equivalent_split_middle", &map, 415);
    map.erase(cut);
    dump_walk("equivalent_erase_cut", &map);
    map.erase(same_b);
    dump_walk("equivalent_erase_peer", &map);
}

fn stable_cursor_cases() {
    let mut before = RangeMap::new();
    before.insert(TestRecord::new("A", 5, 100, 110));
    let before_cursor = before.find_begin(100);
    dump_cursor("cursor_insert_before_initial", &before, before_cursor);
    before.insert(TestRecord::new("B", 5, 50, 60));
    dump_cursor("cursor_insert_before_after", &before, before_cursor);
    before.erase_at(before_cursor);
    dump_walk("cursor_insert_before_erase", &before);

    let mut after = RangeMap::new();
    after.insert(TestRecord::new("A", 5, 100, 110));
    let after_cursor = after.find_begin(100);
    after.insert(TestRecord::new("C", 5, 150, 160));
    dump_cursor("cursor_insert_after", &after, after_cursor);
    after.erase_at(after_cursor);
    dump_walk("cursor_insert_after_erase", &after);

    let mut equivalent = RangeMap::new();
    equivalent.insert(TestRecord::new("eq_a", 5, 10, 20));
    let equivalent_cursor = equivalent.find_begin(15);
    equivalent.insert(TestRecord::new("eq_b", 5, 10, 20));
    dump_cursor("cursor_equivalent_after", &equivalent, equivalent_cursor);
    equivalent.erase_at(equivalent_cursor);
    dump_walk("cursor_equivalent_erase", &equivalent);

    let mut split = RangeMap::new();
    split.insert(TestRecord::new("wide", 5, 100, 140));
    let split_cursor = split.find_begin(120);
    split.insert(TestRecord::new("narrow", 2, 110, 120));
    dump_cursor("cursor_unzip_after", &split, split_cursor);
    split.erase_at(split_cursor);
    dump_walk("cursor_unzip_erase", &split);

    let mut end_map = RangeMap::new();
    let old_end = end_map.find_begin(0);
    end_map.insert(TestRecord::new("only", 5, 1, 2));
    println!(
        "case=cursor_end_insert|same={}",
        if end_map.cursor_is_valid(old_end) && end_map.record_at_cursor(old_end).is_none() {
            1
        } else {
            0
        }
    );
}

fn cursor_invalidation_matrix() {
    let mut map = RangeMap::new();
    map.insert(TestRecord::new("outer", 5, 200, 240));
    let inner_id = map.insert(TestRecord::new("inner", 3, 210, 230));
    let left_outer = map.find_begin(205);
    let inner_middle = map.find_begin(220);
    let middle_outer = map.next_cursor(inner_middle).unwrap();
    let right_outer = map.find_begin(235);
    let old_end = map.find_end(u64::MAX);

    println!(
        "case=cursor_matrix_before|left={}|inner={}|middle={}|right={}",
        map.record_at_cursor(left_outer).unwrap().name,
        map.record_at_cursor(inner_middle).unwrap().name,
        map.record_at_cursor(middle_outer).unwrap().name,
        map.record_at_cursor(right_outer).unwrap().name
    );
    map.erase(inner_id);
    println!(
        "case=cursor_matrix_after|left={}|inner={}|middle={}|right={}|end_same={}",
        if map.cursor_is_valid(left_outer) {
            "valid"
        } else {
            "invalid"
        },
        if map.cursor_is_valid(inner_middle) {
            "valid"
        } else {
            "invalid"
        },
        if map.cursor_is_valid(middle_outer) {
            "valid"
        } else {
            "invalid"
        },
        map.record_at_cursor(right_outer).unwrap().name,
        if map.cursor_is_valid(old_end) && map.record_at_cursor(old_end).is_none() {
            1
        } else {
            0
        }
    );
    map.erase_at(right_outer);
    dump_walk("cursor_matrix_right_erase", &map);
}

fn main() {
    equal_range_cases();
    wide_narrow_cases();
    split_erase_cases();
    overlap_and_range_walk_cases();
    equivalent_split_cases();
    stable_cursor_cases();
    cursor_invalidation_matrix();
}
