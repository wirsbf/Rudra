// FLOAT-FMT-STRUCT-0001: Rugra comparand for the locked Ghidra 12.0.4
// FloatFormat structural oracle (top-aligned fractional code convention +
// createFloat/extractExpSig bit ladders).
//
// Mirrors tests/oracle/float_fmt_struct_1204.cc case-for-case with the same
// inputs in the same order; every line must byte-match the C++ side. The
// private statics/members the C++ fixture reaches via its access hack are
// pub in float_emulate.rs (create_float/extract_exp_sig/
// round_to_nearest_even/set_*), so both sides drive the same functions.

use rudra::float_emulate::{FloatClass, FloatFormat};

fn fields(name: &str, fmt: &FloatFormat) {
    println!(
        "case={name}|size={}|signbit_pos={}|exp_pos={}|exp_size={}|frac_pos={}|frac_size={}|bias={}|maxexp={}|jbitimplied={}",
        fmt.size, fmt.signbit_pos, fmt.exp_pos, fmt.exp_size, fmt.frac_pos, fmt.frac_size,
        fmt.bias, fmt.max_exponent, fmt.jbit_implied as i32
    );
}

fn esig(name: &str, x: f64) {
    // Sentinels prove the zero/infinity/NaN early returns leave the out
    // params untouched (float.cc:95-97 return before any write).
    let mut sgn = false;
    let mut signif: u64 = 0xAAAAAAAAAAAAAAAA;
    let mut exp: i32 = -559038737;
    let cls = FloatFormat::extract_exp_sig(x, &mut sgn, &mut signif, &mut exp);
    println!("case={name}|cls={}|sgn={}|signif=0x{:016X}|exp={}", cls as i32, sgn as i32, signif, exp);
}

fn rtne(name: &str, mut signif: u64, lowbitpos: i32) {
    let up = FloatFormat::round_to_nearest_even(&mut signif, lowbitpos);
    println!("case={name}|up={}|signif=0x{:016X}", up as i32, signif);
}

fn ghf(name: &str, fmt: &FloatFormat, encoding: u64) {
    let mut type_ = FloatClass::Normalized;
    let val = fmt.get_host_float(encoding, &mut type_);
    println!("case={name}|cls={}|val=0x{:016X}", type_ as i32, val.to_bits());
}

fn genc(name: &str, fmt: &FloatFormat, host: f64) {
    println!("case={name}|res=0x{:016X}", fmt.get_encoding(host));
}

fn i2f(name: &str, fmt: &FloatFormat, a: u64, size_in: usize) {
    println!("case={name}|res=0x{:016X}", fmt.op_int2float(a, size_in));
}

fn f2f(name: &str, formin: &FloatFormat, a: u64, outformat: &FloatFormat) {
    println!("case={name}|res=0x{:016X}", formin.op_float2_float(a, outformat));
}

fn trunc(name: &str, fmt: &FloatFormat, a: u64, size_out: usize) {
    println!("case={name}|res=0x{:016X}", fmt.op_trunc(a, size_out));
}

fn ldexp(x: f64, e: i32) -> f64 {
    // Fixture-local helper only: the value under test (getEncoding) uses the
    // libm ladder inside the library; this constructs exact power-of-two
    // inputs the same way the C++ fixture's ldexp(1.0, e) does.
    x * 2f64.powi(e)
}

fn main() {
    println!("schema=1|fixture=FLOAT-FMT-STRUCT-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    let fmt4 = FloatFormat::new(4);
    let fmt8 = FloatFormat::new(8);

    // ---- FloatFormat field initialization (float.cc:36-61) ----
    fields("fields4", &fmt4);
    fields("fields8", &fmt8);

    // ---- top-aligned field extraction (float.cc:113-139) ----
    println!("case=xfrac4_minfrac|res=0x{:016X}", fmt4.extract_fractional_code(0x00800001));
    println!("case=xfrac4_maxfrac|res=0x{:016X}", fmt4.extract_fractional_code(0x007FFFFF));
    println!("case=xfrac4_3fc00001|res=0x{:016X}", fmt4.extract_fractional_code(0x3FC00001));
    println!("case=xfrac8_one_ulp|res=0x{:016X}", fmt8.extract_fractional_code(0x3FF0000000000001));
    println!("case=xfrac8_maxsub|res=0x{:016X}", fmt8.extract_fractional_code(0x000FFFFFFFFFFFFF));
    println!("case=xsign4_pos|res={}", fmt4.extract_sign(0x3FC00000) as i32);
    println!("case=xsign4_neg|res={}", fmt4.extract_sign(0xFF800000) as i32);
    println!("case=xsign8_neg|res={}", fmt8.extract_sign(0xFFF0000000000000) as i32);
    println!("case=xexp4_onefive|res={}", fmt4.extract_exponent_code(0x3FC00000));
    println!("case=xexp4_inf|res={}", fmt4.extract_exponent_code(0x7F800000));
    println!("case=xexp4_sub|res={}", fmt4.extract_exponent_code(0x00000001));
    println!("case=xexp8_max|res={}", fmt8.extract_exponent_code(0x7FEFFFFFFFFFFFFF));

    // ---- OR-style setters (float.cc:144-177) ----
    println!("case=sfrac4_into_zero|res=0x{:016X}", fmt4.set_fractional_code(0, 0xC000000000000000));
    println!("case=sfrac4_or_dirty|res=0x{:016X}", fmt4.set_fractional_code(0x3F800000, 0xC000000000000000));
    println!("case=sfrac8_into_zero|res=0x{:016X}", fmt8.set_fractional_code(0, 0x8000000000000000));
    println!("case=sfrac8_or_dirty|res=0x{:016X}", fmt8.set_fractional_code(0x3FF0000000000000, 0x8000000000000000));
    println!("case=ssign4_set|res=0x{:016X}", fmt4.set_sign(0x7F800000, true));
    println!("case=ssign4_identity|res=0x{:016X}", fmt4.set_sign(0xFF800000, false));
    println!("case=sexp4_or|res=0x{:016X}", fmt4.set_exponent_code(0x007FFFFF, 1));
    println!("case=sexp4_into_zero|res=0x{:016X}", fmt4.set_exponent_code(0, 129));

    // ---- zero/infinity/nan encodings (float.cc:181-215) ----
    println!("case=z4_pos|res=0x{:016X}", fmt4.get_zero_encoding(false));
    println!("case=z4_neg|res=0x{:016X}", fmt4.get_zero_encoding(true));
    println!("case=inf4_pos|res=0x{:016X}", fmt4.get_infinity_encoding(false));
    println!("case=inf4_neg|res=0x{:016X}", fmt4.get_infinity_encoding(true));
    println!("case=nan4_pos|res=0x{:016X}", fmt4.get_nan_encoding(false));
    println!("case=nan4_neg|res=0x{:016X}", fmt4.get_nan_encoding(true));
    println!("case=z8_pos|res=0x{:016X}", fmt8.get_zero_encoding(false));
    println!("case=z8_neg|res=0x{:016X}", fmt8.get_zero_encoding(true));
    println!("case=inf8_pos|res=0x{:016X}", fmt8.get_infinity_encoding(false));
    println!("case=inf8_neg|res=0x{:016X}", fmt8.get_infinity_encoding(true));
    println!("case=nan8_pos|res=0x{:016X}", fmt8.get_nan_encoding(false));
    println!("case=nan8_neg|res=0x{:016X}", fmt8.get_nan_encoding(true));

    // ---- static createFloat ldexp ladder (float.cc:67-80) ----
    println!("case=cf_pos7|res=0x{:016X}", FloatFormat::create_float(false, 0xE000000000000000, 2).to_bits());
    println!("case=cf_neg7|res=0x{:016X}", FloatFormat::create_float(true, 0xE000000000000000, 2).to_bits());
    println!("case=cf_onefive|res=0x{:016X}", FloatFormat::create_float(false, 0xC000000000000000, 0).to_bits());
    println!("case=cf_min_denorm|res=0x{:016X}", FloatFormat::create_float(false, 0x8000000000000000, -1074).to_bits());
    println!("case=cf_half_below|res=0x{:016X}", FloatFormat::create_float(false, 0x8000000000000000, -1075).to_bits());
    println!("case=cf_tie_even|res=0x{:016X}", FloatFormat::create_float(false, 0xC000000000000000, -1074).to_bits());
    println!("case=cf_overflow|res=0x{:016X}", FloatFormat::create_float(false, 0x8000000000000000, 1024).to_bits());
    println!("case=cf_neg_overflow|res=0x{:016X}", FloatFormat::create_float(true, 0x8000000000000000, 1024).to_bits());

    // ---- static extractExpSig frexp/ldexp ladder (float.cc:89-109) ----
    esig("esig_7", 7.0);
    esig("esig_neg7", -7.0);
    esig("esig_half", 0.5);
    esig("esig_onefive", 1.5);
    esig("esig_min_denorm", f64::from_bits(0x0000000000000001));
    esig("esig_max_normal", f64::from_bits(0x7FEFFFFFFFFFFFFF));
    esig("esig_zero", 0.0);
    esig("esig_negzero", f64::from_bits(0x8000000000000000));
    esig("esig_inf", f64::INFINITY);
    esig("esig_neginf", f64::NEG_INFINITY);
    esig("esig_nan", f64::NAN);
    esig("esig_negnan", f64::from_bits(0xFFF8000000000000));

    // ---- static roundToNearestEven (float.cc:276-288) ----
    rtne("rtne_even_stay", 0b1010, 2);
    rtne("rtne_odd_carry", 0b1110, 2);
    rtne("rtne_eps_carry", 0b1011, 2);
    rtne("rtne_wrap", u64::MAX, 2);
    rtne("rtne_lowbit64_wrap", 0x8000000000000003, 64);
    rtne("rtne_lowbit64_stay", 0x8000000000000000, 64);

    // ---- convertEncoding subnormal-normalize intermediate (float.cc:368-376,
    //      count_leading_zeros at address.cc:773) ----
    {
        let signif = fmt4.extract_fractional_code(0x00000001);
        let lz = signif.leading_zeros() as i32;
        println!("case=lz4_min|lz={}|normsignif=0x{:016X}|exp={}", lz, signif << lz, -fmt4.bias - lz);
    }
    {
        let signif = fmt4.extract_fractional_code(0x00000002);
        let lz = signif.leading_zeros() as i32;
        println!("case=lz4_two|lz={}|normsignif=0x{:016X}|exp={}", lz, signif << lz, -fmt4.bias - lz);
    }
    {
        let signif = fmt4.extract_fractional_code(0x007FFFFF);
        let lz = signif.leading_zeros() as i32;
        println!("case=lz4_max|lz={}|normsignif=0x{:016X}|exp={}", lz, signif << lz, -fmt4.bias - lz);
    }
    println!("case=lz4_zero|lz={}", 0u64.leading_zeros());

    // ---- getHostFloat bit ladder (float.cc:228-268) ----
    ghf("gh4_onefive", &fmt4, 0x3FC00000);
    ghf("gh4_neg7", &fmt4, 0xC0E00000);
    ghf("gh4_denorm_min", &fmt4, 0x00000001);
    ghf("gh4_denorm_max", &fmt4, 0x007FFFFF);
    ghf("gh4_zero_pos", &fmt4, 0x00000000);
    ghf("gh4_zero_neg", &fmt4, 0x80000000);
    ghf("gh4_inf_pos", &fmt4, 0x7F800000);
    ghf("gh4_inf_neg", &fmt4, 0xFF800000);
    ghf("gh4_nan_pos", &fmt4, 0x7FC00000);
    ghf("gh4_nan_neg", &fmt4, 0xFFC00000);
    ghf("gh8_one", &fmt8, 0x3FF0000000000000);
    ghf("gh8_denorm_min", &fmt8, 0x0000000000000001);
    ghf("gh8_denorm_max", &fmt8, 0x000FFFFFFFFFFFFF);
    ghf("gh8_zero_neg", &fmt8, 0x8000000000000000);
    ghf("gh8_nan_neg", &fmt8, 0xFFF8000000000000);

    // ---- getEncoding bit ladder (float.cc:293-346) ----
    genc("ge4_pos7", &fmt4, 7.0);
    genc("ge4_neg7", &fmt4, -7.0);
    genc("ge4_tie_even", &fmt4, f64::from_bits(0x3FF0000010000000));
    genc("ge4_above_tie", &fmt4, f64::from_bits(0x3FF0000018000000));
    genc("ge4_min_denorm", &fmt4, ldexp(1.0, -149));
    genc("ge4_half_denorm", &fmt4, ldexp(1.0, -150));
    genc("ge4_tie_denorm", &fmt4, 1.5 * ldexp(1.0, -149));
    genc("ge4_exp_zero", &fmt4, ldexp(1.0, -127));
    genc("ge4_too_small", &fmt4, ldexp(1.0, -151));
    genc("ge4_overflow", &fmt4, ldexp(1.0, 128));
    genc("ge4_dbl_max", &fmt4, f64::MAX);
    genc("ge4_snan", &fmt4, f64::from_bits(0x7FF0000000000001));
    genc("ge4_negsnan", &fmt4, f64::from_bits(0xFFF0000000000001));
    genc("ge4_zero", &fmt4, 0.0);
    genc("ge4_negzero", &fmt4, f64::from_bits(0x8000000000000000));
    genc("ge4_inf", &fmt4, f64::INFINITY);
    genc("ge8_pi", &fmt8, 3.14);
    genc("ge8_neg7", &fmt8, -7.0);
    genc("ge8_min_denorm", &fmt8, f64::from_bits(0x0000000000000001));

    // ---- FLOAT-OPINT2FLOAT-SIGN-0001 36-case value regression ----
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

    // ---- FLOAT-OPTRUNC-OOB-0001: opTrunc (intb) cast + calc_mask(sizeout)
    //      (float.cc:631-640). (intb) val on this x86-64 oracle host is
    //      cvttsd2si: NaN/Inf/magnitude >= 2^63 convert to the integer
    //      indefinite INT64_MIN, then calc_mask(sizeout) (address.hh:499)
    //      applies — the low bytes of 0x8000000000000000 are zero for
    //      sizeout < 8. Three tiers: normal, large out-of-range, NaN/Inf.
    // normal tier (mask keeps low bytes of the two's complement word)
    trunc("tr4_pos7_sz4", &fmt4, 0x40E00000, 4);                 // 7.0f
    trunc("tr4_neg7_sz4", &fmt4, 0xC0E00000, 4);                 // -7.0f
    trunc("tr4_neg7_sz1", &fmt4, 0xC0E00000, 1);                 // -7 & 0xff
    trunc("tr8_frac_sz8", &fmt8, 0x40091EB851EB851F, 8);         // 3.14
    trunc("tr8_neg300_sz2", &fmt8, 0xC072C00000000000, 2);       // -300 & 0xffff
    trunc("tr4_negzero_sz4", &fmt4, 0x80000000, 4);              // -0.0
    trunc("tr4_denorm_sz1", &fmt4, 0x00000001, 1);               // 2^-149 -> 0
    trunc("tr8_maxi64_sz4", &fmt8, 0x43DFFFFFFFFFFFFF, 4);       // max < 2^63
    // large out-of-range tier (integer indefinite then masked)
    trunc("tr4_max_sz4", &fmt4, 0x7F7FFFFF, 4);                  // FLT_MAX
    trunc("tr4_max_sz8", &fmt4, 0x7F7FFFFF, 8);
    trunc("tr4_negmax_sz4", &fmt4, 0xFF7FFFFF, 4);               // -FLT_MAX
    trunc("tr8_1e300_sz8", &fmt8, 0x7E37E43C8800759C, 8);        // 1e300
    trunc("tr8_1e300_sz2", &fmt8, 0x7E37E43C8800759C, 2);
    trunc("tr8_2p63_sz8", &fmt8, 0x43E0000000000000, 8);         // 2^63 boundary
    // NaN/Inf tier (same integer-indefinite semantics)
    trunc("tr4_nan_sz4", &fmt4, 0x7FC00000, 4);
    trunc("tr8_nan_sz8", &fmt8, 0x7FF8000000000000, 8);
    trunc("tr8_nan_sz4", &fmt8, 0x7FF8000000000000, 4);
    trunc("tr8_inf_sz8", &fmt8, 0x7FF0000000000000, 8);
    trunc("tr8_neginf_sz4", &fmt8, 0xFFF0000000000000, 4);
}
