//! Benchmarks for Rudra decompiler
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rudra::varnode::Varnode;
use rudra::{Address, Architecture, OpCode};

fn benchmark_architecture_queries(c: &mut Criterion) {
    c.bench_function("query_architecture", |b| {
        b.iter(|| {
            let arch = black_box(Architecture::X86_64);
            black_box((arch.pointer_size(), arch.pointer_bits(), arch.is_64bit()))
        })
    });
}

fn benchmark_address_creation(c: &mut Criterion) {
    c.bench_function("create_address", |b| {
        b.iter(|| black_box(Address::new(0x1000)));
    });
}

fn benchmark_pcode_operations(c: &mut Criterion) {
    c.bench_function("create_varnode", |b| {
        b.iter(|| black_box(Varnode::new_register(0, 4)));
    });

    c.bench_function("check_opcode_properties", |b| {
        b.iter(|| {
            let opcode = black_box(OpCode::CPUI_INT_ADD);
            black_box((opcode.is_commutative(), opcode.is_commutative_or_pure()))
        });
    });
}

criterion_group!(
    benches,
    benchmark_architecture_queries,
    benchmark_address_creation,
    benchmark_pcode_operations
);
criterion_main!(benches);
