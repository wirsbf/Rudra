// FLOAT-OPINT2FLOAT-SIGN-0001: Rugra comparand for the locked Ghidra 12.0.4
// FloatFormat::opInt2Float / opFloat2Float oracle.
//
// Mirrors tests/oracle/float_int2float_sign_1204.cc case-for-case with the
// same inputs (value + input byte width + output format size) in the same
// order; each line prints `case=<name>|res=0x<16 uppercase hex>` and must
// byte-match the C++ side.

use rudra::float_emulate::FloatFormat;

fn i2f(name: &str, fmt: &FloatFormat, a: u64, size_in: usize) {
    println!("case={name}|res=0x{:016X}", fmt.op_int2float(a, size_in));
}

fn f2f(name: &str, formin: &FloatFormat, a: u64, outformat: &FloatFormat) {
    println!("case={name}|res=0x{:016X}", formin.op_float2_float(a, outformat));
}

fn main() {
    println!("schema=1|fixture=FLOAT-OPINT2FLOAT-SIGN-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    let fmt4 = FloatFormat::new(4);
    let fmt8 = FloatFormat::new(8);

    // ---- FLOAT_INT2FLOAT: signed reading, widths, boundaries ----
    i2f("i2f4_pos7", &fmt4, 0x00000007, 4);
    i2f("i2f8_pos7", &fmt8, 0x00000007, 4);
    i2f("i2f4_zero", &fmt4, 0x00000000, 4);
    i2f("i2f4_neg7", &fmt4, 0xFFFFFFF9, 4);
    i2f("i2f8_neg7", &fmt8, 0xFFFFFFF9, 4);
    i2f("i2f4_neg7_size1", &fmt4, 0xF9, 1);
    i2f("i2f4_neg9_size2", &fmt4, 0xFFF7, 2);
    i2f("i2f4_neg7_size8", &fmt4, 0xFFFFFFFFFFFFFFF9, 8);
    i2f("i2f8_neg1", &fmt8, 0xFFFFFFFF, 4);
    i2f("i2f8_neg7_junk", &fmt8, 0xABCDFFFFFFF9, 4);
    i2f("i2f4_int32_min", &fmt4, 0x80000000, 4);
    i2f("i2f4_int32_max", &fmt4, 0x7FFFFFFF, 4);
    i2f("i2f4_2p24p1", &fmt4, 0x01000001, 4);
    i2f("i2f8_int64_min", &fmt8, 0x8000000000000000, 8);
    i2f("i2f8_int64_min1", &fmt8, 0x8000000000000001, 8);
    i2f("i2f8_int64_max", &fmt8, 0x7FFFFFFFFFFFFFFF, 8);

    // ---- FLOAT_FLOAT2FLOAT: convertEncoding ladder ----
    f2f("f2f_4to8_onefive", &fmt4, 0x3FC00000, &fmt8);
    f2f("f2f_4to8_neg1", &fmt4, 0xBF800000, &fmt8);
    f2f("f2f_4to8_negzero", &fmt4, 0x80000000, &fmt8);
    f2f("f2f_4to8_nan", &fmt4, 0x7FC00000, &fmt8);
    f2f("f2f_4to8_negnan", &fmt4, 0xFFC00000, &fmt8);
    f2f("f2f_4to8_posinf", &fmt4, 0x7F800000, &fmt8);
    f2f("f2f_4to8_sub_min", &fmt4, 0x00000001, &fmt8);
    f2f("f2f_4to8_sub_max", &fmt4, 0x007FFFFF, &fmt8);
    f2f("f2f_8to4_neg1", &fmt8, 0xBFF0000000000000, &fmt4);
    f2f("f2f_8to4_negthird", &fmt8, 0xBFD5555555555555, &fmt4);
    f2f("f2f_8to4_tie_even", &fmt8, 0x3FF0000010000000, &fmt4);
    f2f("f2f_8to4_above_tie", &fmt8, 0x3FF0000018000000, &fmt4);
    f2f("f2f_8to4_negtie", &fmt8, 0xBFF0000010000000, &fmt4);
    f2f("f2f_8to4_sub_out", &fmt8, 0x3800000000000000, &fmt4);
    f2f("f2f_8to4_too_small", &fmt8, 0x2100000000000000, &fmt4);
    f2f("f2f_8to4_dbl_max", &fmt8, 0x7FEFFFFFFFFFFFFF, &fmt4);
    f2f("f2f_8to4_negdbl_max", &fmt8, 0xFFEFFFFFFFFFFFFF, &fmt4);
    f2f("f2f_8to4_negnan", &fmt8, 0xFFF8000000000000, &fmt4);
    f2f("f2f_8to4_neginf", &fmt8, 0xFFF0000000000000, &fmt4);
    f2f("f2f_8to4_negzero", &fmt8, 0x8000000000000000, &fmt4);
}
