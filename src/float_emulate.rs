//! Floating-point format encoding/decoding and emulation.
//!
//! Corresponds to Ghidra's `float.hh` / `float.cc` (673 lines).
//!
//! FloatFormat supports IEEE754 single/double precision encoding/decoding
//! and floating-point operation emulation (opAdd/opMult/opDiv/etc.).
//!
//! # Status
//! Core FloatFormat with IEEE754 single/double construction, host float
//! conversion, and basic operations. The host conversions run the oracle's
//! bit ladder end to end: `getHostFloat` extracts the **top-aligned**
//! fraction (`extractFractionalCode`, float.cc:113-119), re-derives the
//! signif via the jbit room (`frac >>= 1; frac |= 1<<63`, float.cc:261-266)
//! and composes through the static `createFloat` ldexp ladder
//! (float.cc:67-80); `getEncoding` decomposes through the static
//! `extractExpSig` frexp ladder (float.cc:89-109) and packs via
//! `roundToNearestEven` + the top-aligned `setFractionalCode`/
//! `setExponentCode`/`setSign` primitives (float.cc:144-177).
//! opInt2Float sign-extends its integer input from `size_in` bytes
//! (float.cc:611-617) and opFloat2Float delegates to the bit-level
//! convertEncoding port (float.cc:276-288/352-419).
//!
//! Structural oracle proof: `tests/oracle/float_fmt_struct_1204`
//! (runner `tools/run_float_fmt_struct_oracle.sh`); value-level int2float /
//! float2float regression: `tests/oracle/float_int2float_sign_1204`.

// RUDRA-GLUE: float.cc binds the host libm routines through `using
// std::ldexp; using std::frexp;` (float.cc:25-26). Rust std exposes no
// stable equivalents, so the same host libm symbols the C++ oracle links
// against are bound here. This matters for parity: ldexp(x, e) scales by
// 2^e with correct gradual underflow/overflow saturation, which a plain
// `x * 2f64.powi(e)` cannot reproduce once the power itself over/underflows
// (e.g. createFloat for the smallest f64 denormal computes
// ldexp(2^11, -1085) == 2^-1074, while 2f64.powi(-1085) already flushes
// to 0). These declarations have no bodies (FFI), hence the glue comment.
extern "C" {
    // RUDRA-GLUE: FFI declaration (no body) for the host libm ldexp the
    // oracle calls at float.cc:76.
    fn ldexp(x: f64, exp: i32) -> f64;
    // RUDRA-GLUE: FFI declaration (no body) for the host libm frexp the
    // oracle calls at float.cc:100.
    fn frexp(x: f64, exp: *mut i32) -> f64;
}

/// The various classes of floating-point encodings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FloatClass {
    Normalized = 0,
    Infinity = 1,
    Zero = 2,
    Nan = 3,
    Denormalized = 4,
}

/// Encoding information for a single floating-point format.
/// Corresponds to Ghidra's `FloatFormat` (float.hh:32).
#[derive(Debug, Clone)]
pub struct FloatFormat {
    /// Size of float in bytes
    pub size: usize,
    /// Bit position of sign bit
    pub signbit_pos: u32,
    /// (lowest) bit position of fractional part
    pub frac_pos: u32,
    /// Number of bits in fractional part
    pub frac_size: u32,
    /// (lowest) bit position of exponent
    pub exp_pos: u32,
    /// Number of bits in exponent
    pub exp_size: u32,
    /// Bias to add to real exponent to get encoding
    pub bias: i32,
    /// Maximum possible exponent
    pub max_exponent: i32,
    /// Whether the integer bit (jbit) is implied
    pub jbit_implied: bool,
    /// Minimum decimal digits of precision guaranteed by the format
    /// (float.hh:51 `decimalMinPrecision`, set by `calcPrecision`
    /// float.cc:219-223).
    pub decimal_min_precision: i32,
    /// Maximum decimal digits of precision needed to uniquely represent
    /// value (float.hh:52 `decimalMaxPrecision`).
    pub decimal_max_precision: i32,
}

impl FloatFormat {
    // Ghidra: float.cc:36 FloatFormat::new
    /// Construct default IEEE 754 standard settings for the given byte size.
    /// Supports size=4 (single) and size=8 (double).
    pub fn new(size: usize) -> Self {
        let mut fmt = match size {
            4 => Self {
                size: 4,
                signbit_pos: 31,
                frac_pos: 0,
                frac_size: 23,
                exp_pos: 23,
                exp_size: 8,
                bias: 127,
                max_exponent: 255, // (1<<exp_size)-1 — float.cc:59
                jbit_implied: true,
                decimal_min_precision: 0,
                decimal_max_precision: 0,
            },
            8 => Self {
                size: 8,
                signbit_pos: 63,
                frac_pos: 0,
                frac_size: 52,
                exp_pos: 52,
                exp_size: 11,
                bias: 1023,
                max_exponent: 2047, // (1<<exp_size)-1 — float.cc:59
                jbit_implied: true,
                decimal_min_precision: 0,
                decimal_max_precision: 0,
            },
            _ => panic!("Unsupported float size: {}", size),
        };
        // float.cc:66: the constructor tail calls calcPrecision().
        fmt.calc_precision();
        fmt
    }

    // Ghidra: float.cc:217 FloatFormat::calcPrecision
    /// Set the decimal precision bounds. Faithful to `calcPrecision`
    /// (float.cc:218-223): `decimalMinPrecision = floor(frac_size *
    /// 0.30103)` (log10(2) truncated), and `decimalMaxPrecision =
    /// ceil((frac_size + 1) * 0.30103) + 1` — the precision needed to
    /// guarantee an IEEE 754 binary -> decimal -> binary round trip.
    fn calc_precision(&mut self) {
        // float.cc:220
        self.decimal_min_precision = (self.frac_size as f64 * 0.30103).floor() as i32;
        // float.cc:222
        self.decimal_max_precision = ((self.frac_size as f64 + 1.0) * 0.30103).ceil() as i32 + 1;
    }

    // Ghidra: float.hh:66 FloatFormat::getSize
    /// Get the size of the encoding in bytes.
    pub fn get_size(&self) -> usize { self.size }

    // Ghidra: float.cc:67 FloatFormat::createFloat
    /// Create a double given sign, fractional, and exponent.
    /// Faithful to Ghidra FloatFormat::createFloat (float.cc:67-80, static
    /// per float.hh:54): `signif` arrives **top-aligned** (bit 63 = MSB of
    /// the fraction field); the function drops 1 bit of precision
    /// (`signif >>= 1`, a by-value parameter copy in the oracle) so the
    /// remaining word fits exactly in a double, then scales by
    /// `exp - precis + 1` through ldexp (gradual underflow / overflow
    /// saturation, not a powi product) and applies the sign last.
    pub fn create_float(sign: bool, signif: u64, exp: i32) -> f64 {
        let signif = signif >> 1; // Throw away 1 bit of precision we will
        // lose anyway, to make sure highbit is 0
        let precis = 8 * std::mem::size_of::<u64>() as i32 - 1; // fullword - 1 we threw away
        let mut res = signif as f64;
        let expchange = exp - precis + 1; // change in exponent is precis - 1 integer bit
        res = unsafe { ldexp(res, expchange) };
        if sign {
            res = res * -1.0;
        }
        res
    }

    // Ghidra: float.cc:89 FloatFormat::extractExpSig
    /// Extract the sign, fractional, and exponent from a given
    /// floating-point value. Faithful to Ghidra
    /// FloatFormat::extractExpSig (float.cc:89-109, static per
    /// float.hh:55): `signbit` is read first (observable on NaN), the
    /// zero/infinity/NaN early returns come before any normalization, the
    /// magnitude is forced positive, then frexp normalizes to [1/2, 1) and
    /// ldexp scales to [2^62, 2^63) before the exact `(uintb)` truncation
    /// (no rounding: norm's 53-bit significand sits at bits 62..10).
    /// `*signif` comes out **top-aligned** with bit 63 set; the exponent is
    /// rebased to the [1, 2) normalization (`e -= 1`).
    pub fn extract_exp_sig(x: f64, sgn: &mut bool, signif: &mut u64, exp: &mut i32) -> FloatClass {
        *sgn = x.is_sign_negative();
        if x == 0.0 {
            return FloatClass::Zero;
        }
        if x.is_infinite() {
            return FloatClass::Infinity;
        }
        if x.is_nan() {
            return FloatClass::Nan;
        }
        let mut x = x;
        if *sgn {
            x = -x;
        }
        let mut e: i32 = 0;
        let mut norm = unsafe { frexp(x, &mut e) }; // norm is between 1/2 and 1
        norm = unsafe { ldexp(norm, 8 * std::mem::size_of::<u64>() as i32 - 1) }; // norm between 2^62 and 2^63

        *signif = norm as u64; // Convert to normalized integer
        *signif <<= 1;

        e -= 1; // Consider normalization between 1 and 2
        *exp = e;
        FloatClass::Normalized
    }

    // Ghidra: float.cc:228 FloatFormat::getHostFloat
    /// Convert an encoding into the host's f64.
    /// Faithful to Ghidra FloatFormat::getHostFloat (float.cc:228-268): the
    /// sign/fraction/exponent fields are extracted in the oracle's
    /// declaration order with the fraction **top-aligned**
    /// (`extractFractionalCode`, float.cc:113-119); zero / denormalized /
    /// infinity / NaN early returns key off the raw exponent code (0 vs
    /// maxexponent); the true exponent is `exp - bias` for every
    /// non-early-return path; the jbit room (`frac >>= 1; frac |= 1<<63`)
    /// applies only when `normal && jbitimplied`; the value is finally
    /// composed through the static `createFloat` ldexp ladder — no
    /// f32/f64 bit-cast and no powi product.
    pub fn get_host_float(&self, encoding: u64, ftype: &mut FloatClass) -> f64 {
        let sgn = self.extract_sign(encoding);
        let mut frac = self.extract_fractional_code(encoding);
        let mut exp = self.extract_exponent_code(encoding) as i32;
        let mut normal = true;

        if exp == 0 {
            if frac == 0 {
                // Floating point zero
                *ftype = FloatClass::Zero;
                return if sgn { -0.0 } else { 0.0 };
            }
            *ftype = FloatClass::Denormalized;
            // Number is denormalized
            normal = false;
        } else if exp == self.max_exponent {
            if frac == 0 {
                // Floating point infinity
                *ftype = FloatClass::Infinity;
                let infinity = f64::INFINITY;
                return if sgn { -infinity } else { infinity };
            }
            *ftype = FloatClass::Nan;
            // encoding is "Not a Number" NaN
            let nan = f64::NAN;
            return if sgn { -nan } else { nan }; // Sign is usually ignored
        } else {
            *ftype = FloatClass::Normalized;
        }

        // Get "true" exponent and fractional
        exp -= self.bias;
        if normal && self.jbit_implied {
            frac >>= 1; // Make room for 1 jbit
            let highbit = 1u64 << 63;
            frac |= highbit; // Stick bit in at top
        }
        Self::create_float(sgn, frac, exp)
    }

    // Ghidra: float.cc:293 FloatFormat::getEncoding
    /// Convert the host's f64 into this encoding.
    /// Faithful to Ghidra FloatFormat::getEncoding (float.cc:293-346): the
    /// decomposition runs through the static `extractExpSig` frexp ladder
    /// (**top-aligned** signif with bit 63 set), zero/infinity/NaN map to
    /// their dedicated encodings (NaN payloads are dropped — only the quiet
    /// bit survives via `getNaNEncoding`), `exp += bias` precedes the
    /// `-frac_size` / `< 1` / `>= maxexponent` range gates, denormalized
    /// outputs re-round at `64 - frac_size - exp` and shift the top-aligned
    /// signif down by `-exp` before packing, the normal path rounds at
    /// `64 - frac_size - 1` with the uintb wrap-carry rebalance, and the
    /// final pack is the top-aligned setFractionalCode + setExponentCode +
    /// setSign ladder with the jbitimplied `<<= 1` cut. No host f32/f64
    /// bit-cast is involved.
    pub fn get_encoding(&self, host: f64) -> u64 {
        let mut signif: u64 = 0;
        let mut exp: i32 = 0;
        let mut sgn = false;
        let ftype = Self::extract_exp_sig(host, &mut sgn, &mut signif, &mut exp);

        if ftype == FloatClass::Zero {
            return self.get_zero_encoding(sgn);
        } else if ftype == FloatClass::Infinity {
            return self.get_infinity_encoding(sgn);
        } else if ftype == FloatClass::Nan {
            return self.get_nan_encoding(sgn);
        }

        // convert exponent and fractional to their encodings
        exp += self.bias;

        if exp < -(self.frac_size as i32) {
            // Exponent is too small to represent
            return self.get_zero_encoding(sgn); // TODO handle round to non-zero
        }

        if exp < 1 {
            // Must be denormalized
            if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size as i32 - exp) {
                // TODO handle round to normal case
                if (signif >> 63) == 0 {
                    signif = 1u64 << 63;
                    exp += 1;
                }
            }
            let res = self.get_zero_encoding(sgn);
            return self.set_fractional_code(res, signif >> (-exp));
        }

        if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size as i32 - 1) {
            // if high bit is clear, then the add overflowed. Increase exp and set
            // signif to 1.
            if (signif >> 63) == 0 {
                signif = 1u64 << 63;
                exp += 1;
            }
        }

        if exp >= self.max_exponent {
            // Exponent is too big to represent
            return self.get_infinity_encoding(sgn);
        }

        if self.jbit_implied && exp != 0 {
            signif <<= 1; // Cut off top bit (which should be 1)
        }

        let mut res: u64 = 0;
        res = self.set_fractional_code(res, signif);
        res = self.set_exponent_code(res, exp as u32);
        self.set_sign(res, sgn)
    }

    // Ghidra: float.cc:276 FloatFormat::roundToNearestEven
    /// Round a floating point value to the nearest even.
    /// Faithful to Ghidra FloatFormat::roundToNearestEven (float.cc:276-288,
    /// static private per float.hh:56): `signif` is mutated in place
    /// (reference parameter, so it must stay callable from the oracle
    /// fixture), and `lowbitpos` indexes the least-significant retained
    /// bit; returns whether rounding carried up.
    pub fn round_to_nearest_even(signif: &mut u64, lowbitpos: i32) -> bool {
        let lowbitmask = if lowbitpos < 64 { 1u64 << lowbitpos } else { 0 };
        let midbitmask = 1u64 << (lowbitpos - 1);
        let epsmask = midbitmask - 1;
        let odd = (*signif & lowbitmask) != 0;
        if (*signif & midbitmask) != 0 && ((*signif & epsmask) != 0 || odd) {
            // uintb wrap-around carry: the caller detects the overflow via
            // (signif >> 63) == 0 and rebalances (float.cc:391/403).
            *signif = signif.wrapping_add(midbitmask);
            return true;
        }
        false
    }

    // Ghidra: float.cc:352 FloatFormat::convertEncoding
    /// Convert between two different formats: `encoding` is a value in
    /// `formin`, returned as the equivalent value in `self` (the output
    /// format). Faithful to Ghidra FloatFormat::convertEncoding
    /// (float.cc:352-419): sign/fraction/exponent are extracted from
    /// `formin` bit-level (fraction **top-aligned** via
    /// `extractFractionalCode`, float.cc:113-119), NaN/Infinity map through
    /// the *output* format's maxexponent, subnormal inputs are normalized
    /// via count_leading_zeros (address.cc:773) with the rebased exponent
    /// `exp = -formin->bias - lz`, and too-small/too-large exponents clamp
    /// to zero/infinity encodings — never an intermediate host double. The
    /// whole ladder (normalize `<<lz`, jbit room `(1<<63)|(signif>>1)` —
    /// keyed on the *output* format's jbitimplied, float.cc:379,
    /// roundToNearestEven positions, final `<<1` cut, packing) runs in the
    /// top-aligned convention through the shared setters.
    pub fn convert_encoding(&self, encoding: u64, formin: &FloatFormat) -> u64 {
        let mut signif = formin.extract_fractional_code(encoding);
        let sgn = formin.extract_sign(encoding);
        let mut exp = formin.extract_exponent_code(encoding) as i32;

        if exp == formin.max_exponent {
            // NaN or INFINITY encoding
            if signif != 0 {
                return self.get_nan_encoding(sgn);
            }
            return self.get_infinity_encoding(sgn);
        }

        if exp == 0 {
            // incoming is subnormal
            if signif == 0 {
                return self.get_zero_encoding(sgn);
            }
            // normalize
            let lz = signif.leading_zeros() as i32;
            signif <<= lz;
            exp = -formin.bias - lz;
        } else {
            // incoming is normal
            exp -= formin.bias;
            // Oracle float.cc:379 tests the *output* format's jbitimplied.
            if self.jbit_implied {
                signif = (1u64 << 63) | (signif >> 1);
            }
        }

        exp += self.bias;

        if exp < -(self.frac_size as i32) {
            // Exponent is too small to represent
            return self.get_zero_encoding(sgn); // TODO handle round to non-zero
        }

        if exp < 1 {
            // Must be denormalized
            if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size as i32 - exp) {
                // TODO handle carry to normal case
                if (signif >> 63) == 0 {
                    signif = 1u64 << 63;
                    exp += 1;
                }
            }
            let res = self.get_zero_encoding(sgn);
            return self.set_fractional_code(res, signif >> (-exp));
        }

        if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size as i32 - 1) {
            // if high bit is clear, then the add overflowed. Increase exp and
            // set signif to 1.
            if (signif >> 63) == 0 {
                signif = 1u64 << 63;
                exp += 1;
            }
        }

        if exp >= self.max_exponent {
            // Exponent is too big to represent
            return self.get_infinity_encoding(sgn);
        }

        if self.jbit_implied && exp != 0 {
            signif <<= 1; // Cut off top bit (which should be 1)
        }

        let mut res: u64 = 0;
        res = self.set_fractional_code(res, signif);
        res = self.set_exponent_code(res, exp as u32);
        self.set_sign(res, sgn)
    }

    // Ghidra: float.cc:113 FloatFormat::extractFractionalCode
    /// Extract the fractional part of the encoding, **aligned to the top of
    /// the 64-bit word** (float.cc:111-119: `x >>= frac_pos;` then
    /// `x <<= 8*sizeof(uintb) - frac_size`). The MSB of the fraction field
    /// lands in bit 63; bits of the exponent/sign above it are shifted out,
    /// no mask is needed.
    pub fn extract_fractional_code(&self, x: u64) -> u64 {
        let mut x = x;
        x >>= self.frac_pos; // Eliminate bits below
        x <<= 64 - self.frac_size; // Align with top of word
        x
    }

    // Ghidra: float.cc:123 FloatFormat::extractSign
    /// Extract the sign bit from the encoding.
    pub fn extract_sign(&self, x: u64) -> bool {
        (x >> self.signbit_pos) & 1 != 0
    }

    // Ghidra: float.cc:427 FloatFormat::printDecimal
    /// Print the given value as a decimal string with the minimum number
    /// of digits that uniquely specify the underlying binary value.
    /// Faithful to `printDecimal` (float.cc:427-459): iterate `prec` from
    /// `decimalMinPrecision` upward, formatting the host double and
    /// re-parsing it (through `f32` when the TARGET format is <= 4 bytes,
    /// `f64` otherwise — float.cc:451-457) until the round trip is exact,
    /// returning at `decimalMaxPrecision` regardless.
    ///
    /// Formatting semantics: the C++ `ostringstream` with
    /// `unsetf(ios::floatfield)` + `precision(prec)` is exactly printf
    /// `%.*g` (libstdc++ `num_put::do_put(double)`), and
    /// `setf(ios::scientific)` + `precision(prec-1)` is `%.*e` — the
    /// scientific count excludes the first digit (float.cc:435-436).
    /// Rust's `{:.*}`/`{:.*e}` formatters are correctly-rounded like
    /// printf, so the two forms are reproduced directly, with the %g
    /// exponent test and trailing-zero strip implemented here (printf
    /// strips trailing zeros in the significand unless the `#` flag is
    /// given).
    ///
    /// Four decisive semantics (printc.cc:1380's consumer contract):
    /// - References: none — pure string/value returns.
    /// - Loop bounds: `prec` from `decimalMinPrecision` (inclusive) with
    ///   no upper test in the loop head; the ONLY exit at
    ///   `prec == decimalMaxPrecision` returns the CURRENT string
    ///   (float.cc:442-443), the round-trip exit returns the same
    ///   iteration's string.
    /// - Counters: `prec` increments by 1 per iteration AFTER the
    ///   round-trip check fails.
    /// - Comparison keys: the round-trip equality `roundtrip == host`
    ///   (f32-widened for size<=4), never a string comparison.
    pub fn print_decimal(&self, host: f64, forcesci: bool) -> String {
        // float.cc:431: for(int4 prec=decimalMinPrecision;;++prec)
        let mut prec = self.decimal_min_precision;
        loop {
            // float.cc:432-440: the two ostringstream configurations.
            let s = if forcesci {
                // s.setf(ios::scientific); s.precision(prec-1) — C's %.*e
                // spells the exponent `e±<2+ digits>`; Rust's LowerExp
                // prints `e<exp>` — normalize the tail (printf_g does the
                // same for the %g path).
                let raw = format!("{:.*e}", (prec as usize).saturating_sub(1), host);
                let epos = raw.rfind(['e', 'E']).expect("LowerExp always emits 'e'");
                let exp: i32 = raw[epos + 1..]
                    .parse()
                    .expect("LowerExp exponent is a plain integer");
                let tail = if exp < 0 {
                    format!("e-{:02}", -exp)
                } else {
                    format!("e+{:02}", exp)
                };
                format!("{}{tail}", &raw[..epos])
            } else {
                // s.unsetf(ios::floatfield); s.precision(prec) == %.*g
                printf_g(prec as usize, host)
            };
            // float.cc:442-443: the max-precision exit returns the
            // current string (res is not consulted).
            if prec == self.decimal_max_precision {
                return s;
            }
            // float.cc:445-457: round-trip parse — f32 for target
            // formats of at most 4 bytes, f64 otherwise. A failed parse
            // (should be impossible for our formatter's output) compares
            // unequal and continues.
            let roundtrip = if self.size <= 4 {
                s.parse::<f32>().map(|v| v as f64).unwrap_or(f64::NAN)
            } else {
                s.parse::<f64>().unwrap_or(f64::NAN)
            };
            // float.cc:458-459: if (roundtrip == host) break; return res;
            if roundtrip == host {
                return s;
            }
            prec += 1;
        }
    }

    // Ghidra: float.cc:132 FloatFormat::extractExponentCode
    /// Extract the exponent from the encoding.
    pub fn extract_exponent_code(&self, x: u64) -> u32 {
        ((x >> self.exp_pos) & ((1u64 << self.exp_size) - 1)) as u32
    }

    // Ghidra: float.cc:144 FloatFormat::setFractionalCode
    /// Set the fractional code bits in the encoding.
    /// Faithful to Ghidra FloatFormat::setFractionalCode (float.cc:144-153):
    /// `code` arrives **top-aligned**; it is shifted right by
    /// `64 - frac_size` (aligning with the bottom of the word, dropping the
    /// bits of precision there is no room for) then shifted into place by
    /// `frac_pos` and OR-ed in. The oracle does NOT mask `x` — the caller
    /// contract (float.cc:141) is that the fraction field of `x` is already
    /// zero.
    pub fn set_fractional_code(&self, x: u64, code: u64) -> u64 {
        let code = code >> (64 - self.frac_size); // Align with bottom of word, also drops
        // bits of precision we don't have room for
        let code = code << self.frac_pos; // Move bits into position
        x | code
    }

    // Ghidra: float.cc:158 FloatFormat::setSign
    /// Set the sign bit in the encoding.
    /// Faithful to Ghidra FloatFormat::setSign (float.cc:158-166): a false
    /// sign is an **identity** — the bit is assumed already zero and `x` is
    /// returned unchanged (the oracle never clears a set sign bit); a true
    /// sign OR-s the mask in.
    pub fn set_sign(&self, x: u64, sign: bool) -> u64 {
        if !sign {
            return x; // Assume bit is already zero
        }
        let mask = 1u64 << self.signbit_pos;
        x | mask // Stick in the bit
    }

    // Ghidra: float.cc:171 FloatFormat::setExponentCode
    /// Set the exponent bits in the encoding.
    /// Faithful to Ghidra FloatFormat::setExponentCode (float.cc:171-177):
    /// the code is shifted into position by `exp_pos` and OR-ed in. The
    /// oracle does NOT mask `x` — the caller contract (float.cc:168) is
    /// that the exponent field of `x` is already zero.
    pub fn set_exponent_code(&self, x: u64, code: u32) -> u64 {
        let code = (code as u64) << self.exp_pos; // Move bits into position
        x | code
    }

    // Ghidra: float.cc:181 FloatFormat::getZeroEncoding
    /// Get the encoding for zero (positive or negative).
    /// Faithful to Ghidra FloatFormat::getZeroEncoding (float.cc:181-189):
    /// builds through the three setters — setFractionalCode(0),
    /// setExponentCode(0), setSign — per the IEEE 754 standard zero
    /// encoding.
    pub fn get_zero_encoding(&self, sgn: bool) -> u64 {
        let mut res: u64 = 0;
        // Use IEEE 754 standard for zero encoding
        res = self.set_fractional_code(res, 0);
        res = self.set_exponent_code(res, 0);
        self.set_sign(res, sgn)
    }

    // Ghidra: float.cc:193 FloatFormat::getInfinityEncoding
    /// Get the encoding for infinity (positive or negative).
    /// Faithful to Ghidra FloatFormat::getInfinityEncoding
    /// (float.cc:193-201): builds through setFractionalCode(0) +
    /// setExponentCode(maxexponent) + setSign per the IEEE 754 standard
    /// infinity encoding.
    pub fn get_infinity_encoding(&self, sgn: bool) -> u64 {
        let mut res: u64 = 0;
        // Use IEEE 754 standard for infinity encoding
        res = self.set_fractional_code(res, 0);
        res = self.set_exponent_code(res, self.max_exponent as u32);
        self.set_sign(res, sgn)
    }

    // Ghidra: float.cc:205 FloatFormat::getNaNEncoding
    /// Get the encoding for NaN (positive or negative).
    /// Faithful to Ghidra FloatFormat::getNaNEncoding (float.cc:205-215):
    /// the quiet-NaN bit is created **top-aligned** (`mask <<= 63`) and
    /// lowered into the fraction field by setFractionalCode — landing on
    /// the fraction MSB (`frac_size - 1`) — then the exponent field is set
    /// to maxexponent and the sign applied. Payload bits do not exist.
    pub fn get_nan_encoding(&self, sgn: bool) -> u64 {
        let mut res: u64 = 0;
        // Use IEEE 754 standard for NaN encoding
        let mask = 1u64 << 63; // Create "quiet" NaN
        res = self.set_fractional_code(res, mask);
        res = self.set_exponent_code(res, self.max_exponent as u32);
        self.set_sign(res, sgn)
    }

    // Ghidra: float.cc:483 FloatFormat::opNotEqual
    /// Inequality comparison (!=)
    pub fn op_not_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va != vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:496 FloatFormat::opLess
    /// Less-than comparison (<)
    pub fn op_less(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va < vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:509 FloatFormat::opLessEqual
    /// Less-than-or-equal comparison (<=)
    pub fn op_less_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va <= vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:631 FloatFormat::opTrunc
    /// Convert floating-point to integer (truncate toward zero)
    pub fn op_trunc(&self, a: u64, size_out: usize) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        // (intb) val (float.cc:636) on the x86-64 oracle host compiles to
        // cvttsd2si: NaN, +/-Inf, and any magnitude >= 2^63 convert to the
        // integer-indefinite value INT64_MIN (0x8000000000000000). Rust's
        // float `as` saturates instead (NaN -> 0, +overflow -> i64::MAX,
        // -overflow -> i64::MIN), so the conversion range is tested
        // explicitly. In-range doubles truncate toward zero in both.
        // -2^63 itself falls into the indefinite branch and is its own
        // correct conversion; the bounds are the two exactly representable
        // doubles +/-2^63.
        let ival: i64 = if va > -9223372036854775808.0 && va < 9223372036854775808.0 {
            va as i64
        } else {
            i64::MIN // x86-64 cvttsd2si integer indefinite
        };
        let res = ival as u64;
        // res &= calc_mask(sizeout) (float.cc:638; inline at address.hh:499
        // with the uintbmasks table at address.cc:631-634).
        res & crate::address::calc_mask(size_out)
    }

    // Ghidra: float.cc:664 FloatFormat::opRound
    /// Round to nearest integer
    pub fn op_round(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.round())
    }

    // Ghidra: float.cc:622 FloatFormat::opFloat2Float
    /// Convert between floating-point precisions.
    /// Faithful to Ghidra float.cc:625 `return outformat.convertEncoding(a,
    /// this);` — the bit-level converter runs on the *output* format with
    /// `this` as the input format (no host-double intermediate).
    pub fn op_float2_float(&self, a: u64, outformat: &FloatFormat) -> u64 {
        outformat.convert_encoding(a, self)
    }

    // Ghidra: float.cc:470 FloatFormat::opEqual
    /// Equality comparison (==)
    pub fn op_equal(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        if va == vb { 1 } else { 0 }
    }

    // Ghidra: float.cc:533 FloatFormat::opAdd
    /// Addition (+)
    pub fn op_add(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va + vb)
    }

    // Ghidra: float.cc:569 FloatFormat::opSub
    /// Subtraction (-)
    pub fn op_sub(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va - vb)
    }

    // Ghidra: float.cc:557 FloatFormat::opMult
    /// Multiplication (*)
    pub fn op_mult(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va * vb)
    }

    // Ghidra: float.cc:545 FloatFormat::opDiv
    /// Division (/)
    pub fn op_div(&self, a: u64, b: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let mut tb = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        let vb = self.get_host_float(b, &mut tb);
        self.get_encoding(va / vb)
    }

    // Ghidra: float.cc:580 FloatFormat::opNeg
    /// Unary negate
    pub fn op_neg(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(-va)
    }

    // Ghidra: float.cc:590 FloatFormat::opAbs
    /// Absolute value (abs)
    pub fn op_abs(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.abs())
    }

    // Ghidra: float.cc:600 FloatFormat::opSqrt
    /// Square root (sqrt)
    pub fn op_sqrt(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.sqrt())
    }

    // Ghidra: float.cc:654 FloatFormat::opFloor
    /// Floor
    pub fn op_floor(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.floor())
    }

    // Ghidra: float.cc:644 FloatFormat::opCeil
    /// Ceiling (ceil)
    pub fn op_ceil(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        let va = self.get_host_float(a, &mut ta);
        self.get_encoding(va.ceil())
    }

    // Ghidra: float.cc:521 FloatFormat::opNan
    /// Test if Not-a-Number (NaN)
    pub fn op_nan(&self, a: u64) -> u64 {
        let mut ta = FloatClass::Zero;
        self.get_host_float(a, &mut ta);
        if ta == FloatClass::Nan { 1 } else { 0 }
    }

    // Ghidra: float.cc:611 FloatFormat::opInt2Float
    /// Convert integer to floating-point.
    /// Faithful to Ghidra float.cc:611-617: the input is a *signed* integer
    /// of `size_in` bytes — `sign_extend(a, 8*sizein-1)` (address.hh:543)
    /// discards bits above the size_in sign bit and sign-extends before the
    /// `(double)` cast; the cast rounds to nearest even in both languages.
    pub fn op_int2float(&self, a: u64, size_in: usize) -> u64 {
        // address.hh:543 sign_extend(val, bit): sa = 64 - (bit + 1);
        // (val << sa) >> sa with an arithmetic right shift on intb.
        // size_in == 8 yields sa == 0 (identity on intb); 1..=7 discard the
        // high bytes and restore the sign from bit 8*size_in-1.
        let sa = 64 - 8 * size_in as u32;
        let ival = ((a << sa) as i64) >> sa;
        self.get_encoding(ival as f64)
    }
}

// RUDRA-GLUE: printf_g — the `%.*g` formatting the C++ ostringstream
// performs for `s << double` under the default floatfield
// (libstdc++ num_put::do_put(double) defers to snprintf "%.*g"). Rust's
// std::fmt has no %g mode, so the printf algorithm is reproduced:
//   1. Format the value in `%e` style with `p-1` digits after the point
//      (p = precision, with printf's "precision 0 is taken as 1" rule)
//      to obtain the decimal exponent.
//   2. If exponent < -4 or exponent >= p, keep the `%e` style; otherwise
//      re-format in `%f` style with `p-1-exponent` decimals.
//   3. Strip trailing zeros of the significand (and a bare trailing '.'),
//      in both styles — the %g default (no '#' flag).
// Special values pass through printf's spelling ("inf"/"nan"), which the
// caller (FloatFormat::print_decimal) never sees — push_float intercepts
// infinity/nan first (printc.cc:1391-1402).
fn printf_g(prec: usize, host: f64) -> String {
    let p = if prec == 0 { 1 } else { prec };
    if !host.is_finite() {
        // printf spells these; unreachable from print_decimal's callers.
        return if host.is_nan() {
            (if host.is_sign_negative() { "-nan" } else { "nan" }).to_string()
        } else if host.is_sign_negative() {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    // Step 1: %.*e with p-1 digits after the point, to read the exponent.
    // Rust's LowerExp prints `e<exp>` (no sign, no padding); C's %e spells
    // `e±<2+ digits>` — normalize the exponent tail to the C form so the
    // round-trip parse and the emitted bytes both match the oracle.
    let e_str = format!("{:.*e}", p - 1, host);
    let epos = e_str.rfind(['e', 'E']).expect("LowerExp always emits 'e'");
    let exp: i32 = e_str[epos + 1..]
        .parse()
        .expect("LowerExp exponent is a plain integer");
    let c_exp_tail = if exp < 0 {
        format!("e-{:02}", -exp)
    } else {
        format!("e+{:02}", exp)
    };
    // Step 2: style selection.
    if exp < -4 || exp >= p as i32 {
        // %e style: strip trailing zeros in the mantissa only, keeping the
        // (normalized) exponent tail.
        let mantissa = strip_g_zeros(&e_str[..epos], epos);
        format!("{mantissa}{c_exp_tail}")
    } else {
        // %f style with p-1-exp decimals.
        let decimals = (p as i32 - 1 - exp).max(0) as usize;
        let f_str = format!("{:.*}", decimals, host);
        strip_g_zeros(&f_str, f_str.len())
    }
}

// RUDRA-GLUE: strip_g_zeros — the %g trailing-zero removal: cut '0's
// directly before `keep` (the mantissa end), then a bare trailing '.'.
fn strip_g_zeros(s: &str, keep: usize) -> String {
    let mut end = keep;
    let bytes = s.as_bytes();
    while end > 0 && bytes[end - 1] == b'0' {
        end -= 1;
    }
    if end > 0 && bytes[end - 1] == b'.' {
        end -= 1;
    }
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float_format_double() {
        let fmt = FloatFormat::new(8);
        assert_eq!(fmt.get_size(), 8);
        let encoding = fmt.get_encoding(3.14);
        let mut fc = FloatClass::Zero;
        let val = fmt.get_host_float(encoding, &mut fc);
        assert!((val - 3.14).abs() < 1e-10);
        assert_eq!(fc, FloatClass::Normalized);
    }

    #[test]
    fn test_float_format_single() {
        let fmt = FloatFormat::new(4);
        let encoding = fmt.get_encoding(1.5);
        let mut fc = FloatClass::Zero;
        let val = fmt.get_host_float(encoding, &mut fc);
        assert!((val - 1.5).abs() < 1e-6);
    }

    // Regression for the FLOAT-FMT-STRUCT-0001 structural port
    // (float.cc:67-109/113-153/228-346): the host conversions run the oracle
    // bit ladder — top-aligned fraction convention, createFloat/extractExpSig
    // statics, ldexp gradual underflow, denormalized createFloat path, NaN
    // canonicalization through getNaNEncoding, setSign identity on false, and
    // the OR-style setters. Oracle proof lives in
    // tests/oracle/float_fmt_struct_1204 (runner
    // tools/run_float_fmt_struct_oracle.sh); these asserts pin the Rust side
    // against drift.
    #[test]
    fn test_top_aligned_fraction_convention() {
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        // float.cc:113-119: x >>= frac_pos then x <<= 64 - frac_size.
        assert_eq!(fmt4.extract_fractional_code(0x00800001), 1u64 << 41);
        assert_eq!(fmt4.extract_fractional_code(0x007FFFFF), 0xFFFFFE0000000000);
        assert_eq!(fmt8.extract_fractional_code(0x3FF0000000000001), 1u64 << 12);
        // float.cc:144-153: top-aligned code is dropped into the field via
        // >>= 64 - frac_size, <<= frac_pos, OR (x fraction bits assumed 0).
        assert_eq!(fmt4.set_fractional_code(0x3F800000, 0xC000000000000000), 0x3F800000 | 0x600000);
        assert_eq!(fmt8.set_fractional_code(0, 0x8000000000000000), 0x0008000000000000);
        // float.cc:158-166: setSign(false) is an identity — never clears.
        assert_eq!(fmt4.set_sign(0xFF800000, false), 0xFF800000);
        assert_eq!(fmt4.set_sign(0x7F800000, true), 0xFF800000);
        // float.cc:171-177: exponent OR-ed in, no masking.
        assert_eq!(fmt4.set_exponent_code(0x007FFFFF, 1), 0x00FFFFFF);
    }

    #[test]
    fn test_extract_exp_sig_top_aligned() {
        // Static (float.cc:89, float.hh:55) — no format instance involved.
        let mut sgn = false;
        let mut signif: u64 = 0;
        let mut exp: i32 = 0;
        // 7.0 = 1.75 * 2^2 -> frexp norm 0.875, e=3 -> exp 2, signif = 111b << 61.
        assert_eq!(
            FloatFormat::extract_exp_sig(7.0, &mut sgn, &mut signif, &mut exp),
            FloatClass::Normalized
        );
        assert!(!sgn);
        assert_eq!(signif, 0xE000000000000000);
        assert_eq!(exp, 2);
        // -7.0 shares the magnitude signif; only sgn flips.
        FloatFormat::extract_exp_sig(-7.0, &mut sgn, &mut signif, &mut exp);
        assert!(sgn);
        assert_eq!(signif, 0xE000000000000000);
        // 0.5 normalizes to [1,2) with exp -1.
        FloatFormat::extract_exp_sig(0.5, &mut sgn, &mut signif, &mut exp);
        assert_eq!((signif, exp), (0x8000000000000000, -1));
        // Classes: zero/-zero/inf/-inf/NaN/-NaN. The zero/inf/NaN early
        // returns never write signif/exp (they keep the 0.5 call's values).
        assert_eq!(FloatFormat::extract_exp_sig(0.0, &mut sgn, &mut signif, &mut exp), FloatClass::Zero);
        assert!(!sgn);
        FloatFormat::extract_exp_sig(-0.0, &mut sgn, &mut signif, &mut exp);
        assert_eq!(sgn, true);
        assert_eq!((signif, exp), (0x8000000000000000, -1));
        assert_eq!(FloatFormat::extract_exp_sig(f64::INFINITY, &mut sgn, &mut signif, &mut exp), FloatClass::Infinity);
        assert_eq!(FloatFormat::extract_exp_sig(f64::NAN, &mut sgn, &mut signif, &mut exp), FloatClass::Nan);
        FloatFormat::extract_exp_sig(-f64::NAN, &mut sgn, &mut signif, &mut exp);
        assert!(sgn);
    }

    #[test]
    fn test_host_float_denormal_bit_ladder() {
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        let mut fc = FloatClass::Zero;
        // Min f32 denormal 0x00000001 == 2^-149 through createFloat/ldexp
        // (previously value-broken: powi product returned 2^-126).
        let val = fmt4.get_host_float(0x00000001, &mut fc);
        assert_eq!(fc, FloatClass::Denormalized);
        assert_eq!(val.to_bits(), (2f64.powi(-149)).to_bits());
        // Max f32 denormal = (2^23-1) * 2^-149.
        let val = fmt4.get_host_float(0x007FFFFF, &mut fc);
        assert_eq!(val.to_bits(), (((1u64 << 23) - 1) as f64 * 2f64.powi(-149)).to_bits());
        // Min f64 denormal 2^-1074 exercises ldexp(2^11, -1085): the naive
        // powi factor flushes to zero, the libm ladder saturates exactly.
        let val = fmt8.get_host_float(0x0000000000000001, &mut fc);
        assert_eq!(fc, FloatClass::Denormalized);
        assert_eq!(val.to_bits(), 1); // f64 bits of 2^-1074
        // Normal path keeps exactness: 1.5f.
        let val = fmt4.get_host_float(0x3FC00000, &mut fc);
        assert_eq!(fc, FloatClass::Normalized);
        assert_eq!(val, 1.5);
    }

    #[test]
    fn test_get_encoding_bit_ladder() {
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        // RNE ties on the f32 fraction (getEncoding ladder, float.cc:293-346).
        assert_eq!(fmt4.get_encoding(f64::from_bits(0x3FF0000010000000)), 0x3F800000);
        assert_eq!(fmt4.get_encoding(f64::from_bits(0x3FF0000018000000)), 0x3F800001);
        // Denormalized outputs (exp < 1 branch).
        assert_eq!(fmt4.get_encoding(2f64.powi(-149)), 0x00000001);
        assert_eq!(fmt4.get_encoding(2f64.powi(-150)), 0x00000000); // half-tie -> even 0
        assert_eq!(fmt4.get_encoding(1.5 * 2f64.powi(-149)), 0x00000002); // tie -> even mantissa 2
        assert_eq!(fmt4.get_encoding(2f64.powi(-127)), 0x00400000); // exp==0 boundary
        // Underflow (< -frac_size) and overflow.
        assert_eq!(fmt4.get_encoding(2f64.powi(-151)), 0x00000000);
        assert_eq!(fmt4.get_encoding(2f64.powi(128)), 0x7F800000);
        assert_eq!(fmt4.get_encoding(f64::MAX), 0x7F800000);
        // NaN inputs canonicalize to the quiet bit only (payload dropped,
        // sign preserved) — float.cc:301-307 -> getNaNEncoding.
        assert_eq!(fmt4.get_encoding(f64::from_bits(0x7FF0000000000001)), 0x7FC00000);
        assert_eq!(fmt4.get_encoding(f64::from_bits(0xFFF0000000000001)), 0xFFC00000);
        // +/-0, +/-inf.
        assert_eq!(fmt4.get_encoding(0.0), 0x00000000);
        assert_eq!(fmt4.get_encoding(-0.0), 0x80000000);
        assert_eq!(fmt4.get_encoding(f64::INFINITY), 0x7F800000);
        assert_eq!(fmt4.get_encoding(f64::NEG_INFINITY), 0xFF800000);
        // f64 target round-trips exact doubles.
        assert_eq!(fmt8.get_encoding(3.14), 3.14f64.to_bits());
        assert_eq!(fmt8.get_encoding(-7.0), 0xC01C000000000000);
    }

    #[test]
    fn test_create_float_ldexp_saturation() {
        // createFloat(sgn, signif, exp) = (signif>>1) * 2^(exp-62), sign last.
        assert_eq!(FloatFormat::create_float(false, 0xE000000000000000, 2), 7.0);
        assert_eq!(FloatFormat::create_float(true, 0xE000000000000000, 2), -7.0);
        // Gradual underflow through ldexp: 2^62 * 2^-1136 == 2^-1074 exactly.
        assert_eq!(FloatFormat::create_float(false, 0x8000000000000000, -1074).to_bits(), 1);
        // One deeper: 2^-1075 is the exact half of the min denormal ->
        // round-to-even flushes to +0.
        assert_eq!(FloatFormat::create_float(false, 0x8000000000000000, -1075), 0.0);
        // 1.5 * 2^-1074 ties between 1x (mantissa 1, odd) and 2x (even) ->
        // ties-to-even keeps 2x min denormal (bits == 2).
        assert_eq!(
            FloatFormat::create_float(false, 0xC000000000000000, -1074).to_bits(),
            2
        );
        // Overflow saturates to infinity.
        assert_eq!(FloatFormat::create_float(false, 0x8000000000000000, 1024), f64::INFINITY);
    }

    #[test]
    fn test_round_to_nearest_even_direct() {
        // float.cc:276-288 driven directly, including the uintb wrap carry.
        let mut signif: u64 = 0b1010; // even, exact tie at lowbitpos=2 -> stays
        assert!(!FloatFormat::round_to_nearest_even(&mut signif, 2));
        assert_eq!(signif, 0b1010);
        let mut signif: u64 = 0b1110; // odd, exact tie -> carries up
        assert!(FloatFormat::round_to_nearest_even(&mut signif, 2));
        assert_eq!(signif, 0b10000);
        let mut signif: u64 = 0b1011; // below-tie bits set (eps!=0) -> carries up
        assert!(FloatFormat::round_to_nearest_even(&mut signif, 2));
        assert_eq!(signif, 0b1101);
        let mut signif: u64 = u64::MAX; // wrap-around carry: signif becomes 1
        assert!(FloatFormat::round_to_nearest_even(&mut signif, 2));
        assert_eq!(signif, 1);
        // lowbitpos == 64: lowbitmask is 0 (odd=false), only mid/eps decide.
        let mut signif: u64 = 0x8000000000000003;
        assert!(FloatFormat::round_to_nearest_even(&mut signif, 64));
        assert_eq!(signif, 3);
    }

    #[test]
    fn test_float_zero() {
        let fmt = FloatFormat::new(8);
        let encoding = fmt.get_encoding(0.0);
        let mut fc = FloatClass::Zero;
        let _ = fmt.get_host_float(encoding, &mut fc);
        assert_eq!(fc, FloatClass::Zero);
    }

    #[test]
    fn test_float_add() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(2.5);
        let b = fmt.get_encoding(3.5);
        let result = fmt.op_add(a, b);
        let mut fc = FloatClass::Zero;
        assert!((fmt.get_host_float(result, &mut fc) - 6.0).abs() < 1e-10);
    }

    #[test]
    fn test_float_mult() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(4.0);
        let b = fmt.get_encoding(0.5);
        let result = fmt.op_mult(a, b);
        let mut fc = FloatClass::Zero;
        assert!((fmt.get_host_float(result, &mut fc) - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_float_div() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(6.0);
        let b = fmt.get_encoding(3.0);
        let result = fmt.op_div(a, b);
        let mut fc = FloatClass::Zero;
        assert!((fmt.get_host_float(result, &mut fc) - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_float_not_equal() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(1.0);
        let b = fmt.get_encoding(2.0);
        assert_eq!(fmt.op_not_equal(a, b), 1);
        assert_eq!(fmt.op_not_equal(a, a), 0);
    }

    #[test]
    fn test_float_less_equal() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(1.0);
        let b = fmt.get_encoding(2.0);
        assert_eq!(fmt.op_less_equal(a, b), 1);
        assert_eq!(fmt.op_less_equal(a, a), 1);
        assert_eq!(fmt.op_less_equal(b, a), 0);
    }

    #[test]
    fn test_float_trunc() {
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(3.7);
        let result = fmt.op_trunc(a, 4);
        assert_eq!(result & 0xffffffff, 3);
    }

    #[test]
    fn test_float_trunc_oob_and_mask() {
        // FLOAT-OPTRUNC-OOB-0001: (intb) val on the x86-64 oracle host is
        // cvttsd2si — NaN/Inf/magnitude >= 2^63 become the integer
        // indefinite INT64_MIN, then calc_mask(sizeout) applies
        // (float.cc:636-638).
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        // normal tier: mask keeps low bytes of the two's complement word
        assert_eq!(fmt4.op_trunc(0x40E00000, 4), 7); // 7.0f
        assert_eq!(fmt4.op_trunc(0xC0E00000, 4), 0xFFFFFFF9); // -7.0f
        assert_eq!(fmt4.op_trunc(0xC0E00000, 1), 0xF9); // -7 & 0xff
        assert_eq!(fmt8.op_trunc(0xC072C00000000000, 2), 0xFED4); // -300 & 0xffff
        assert_eq!(fmt8.op_trunc(0x43DFFFFFFFFFFFFF, 4), 0xFFFFFC00); // max < 2^63
        // large tier: integer indefinite then masked (low bytes of
        // 0x8000000000000000 are zero for sizeout < 8)
        assert_eq!(fmt4.op_trunc(0x7F7FFFFF, 4), 0); // FLT_MAX, sizeout 4
        assert_eq!(fmt4.op_trunc(0x7F7FFFFF, 8), 0x8000000000000000);
        assert_eq!(fmt8.op_trunc(0x7E37E43C8800759C, 8), 0x8000000000000000); // 1e300
        assert_eq!(fmt8.op_trunc(0x7E37E43C8800759C, 2), 0);
        assert_eq!(fmt8.op_trunc(0x43E0000000000000, 8), 0x8000000000000000); // 2^63 boundary
        // NaN/Inf tier: same integer-indefinite semantics
        assert_eq!(fmt4.op_trunc(0x7FC00000, 4), 0);
        assert_eq!(fmt8.op_trunc(0x7FF8000000000000, 8), 0x8000000000000000);
        assert_eq!(fmt8.op_trunc(0x7FF0000000000000, 8), 0x8000000000000000); // +Inf
        assert_eq!(fmt8.op_trunc(0xFFF0000000000000, 4), 0); // -Inf
    }

    #[test]
    fn test_float2float() {
        let fmt8 = FloatFormat::new(8);
        let fmt4 = FloatFormat::new(4);
        let a = fmt8.get_encoding(1.5);
        let result = fmt8.op_float2_float(a, &fmt4);
        let mut fc = FloatClass::Zero;
        assert!((fmt4.get_host_float(result, &mut fc) - 1.5).abs() < 1e-6);
    }

    #[test]
    fn test_set_get_encoding_ops() {
        let fmt = FloatFormat::new(8);
        let x = fmt.get_encoding(1.5);
        // extract_fractional_code is TOP-ALIGNED (float.cc:113-119): the
        // fraction MSB lands in bit 63.
        let frac = fmt.extract_fractional_code(x);
        assert_ne!(frac, 0x8000000000000); // right-aligned would be this
        assert_eq!(frac, 0x8000000000000000); // 1.5 => frac MSB only, top word
        let exp = fmt.extract_exponent_code(x);
        let sign = fmt.extract_sign(x);
        let y = fmt.set_fractional_code(0, frac);
        let y = fmt.set_exponent_code(y, exp);
        let y = fmt.set_sign(y, sign);
        assert_eq!(x, y);
    }

    #[test]
    fn test_zero_infinity_nan_encoding() {
        let fmt = FloatFormat::new(8);
        let pos_zero = fmt.get_zero_encoding(false);
        let neg_zero = fmt.get_zero_encoding(true);
        assert_eq!(pos_zero, 0);
        assert_ne!(pos_zero, neg_zero);
        let pos_inf = fmt.get_infinity_encoding(false);
        assert_eq!(fmt.extract_exponent_code(pos_inf), (1 << fmt.exp_size) - 1);
        assert_eq!(fmt.extract_fractional_code(pos_inf), 0);
        let nan = fmt.get_nan_encoding(false);
        assert_eq!(fmt.extract_exponent_code(nan), (1 << fmt.exp_size) - 1);
        assert_ne!(fmt.extract_fractional_code(nan), 0);
    }

    // Regression for FLOAT-OPINT2FLOAT-SIGN-0001 (Ghidra float.cc:611-617):
    // opInt2Float sign-extends the integer from size_in bytes. Oracle proof
    // lives in tests/oracle/float_int2float_sign_1204 (runner
    // tools/run_float_int2float_sign_oracle.sh); these asserts only pin the
    // Rust side against drift.
    #[test]
    fn test_int2float_sign_extend() {
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        // -7 as a 4-byte two's complement integer -> -7.0 encodings.
        assert_eq!(fmt4.op_int2float(0xFFFFFFF9, 4), 0xC0E00000);
        assert_eq!(fmt8.op_int2float(0xFFFFFFF9, 4), 0xC01C000000000000);
        // -7 as a 1-byte integer.
        assert_eq!(fmt4.op_int2float(0xF9, 1), 0xC0E00000);
        // -9 as a 2-byte integer -> -9.0f.
        assert_eq!(fmt4.op_int2float(0xFFF7, 2), 0xC1100000);
        // INT32_MIN -> -2^31 exactly.
        assert_eq!(fmt4.op_int2float(0x80000000, 4), 0xCF000000);
        // INT32_MAX rounds to nearest even to 2^31 in f32.
        assert_eq!(fmt4.op_int2float(0x7FFFFFFF, 4), 0x4F000000);
        // Bits above the size_in sign bit are discarded by sign_extend.
        assert_eq!(fmt8.op_int2float(0xABCDFFFFFFF9, 4), 0xC01C000000000000);
        // i64::MIN converts exactly; i64::MIN+1/i64::MAX round to +-2^63.
        assert_eq!(fmt8.op_int2float(0x8000000000000000, 8), 0xC3E0000000000000);
        assert_eq!(fmt8.op_int2float(0x8000000000000001, 8), 0xC3E0000000000000);
        assert_eq!(fmt8.op_int2float(0x7FFFFFFFFFFFFFFF, 8), 0x43E0000000000000);
    }

    // Regression for the opFloat2Float bit-level convertEncoding port
    // (Ghidra float.cc:622-626/352-419). Oracle proof lives in
    // tests/oracle/float_int2float_sign_1204.
    #[test]
    fn test_float2float_convert_encoding() {
        let fmt4 = FloatFormat::new(4);
        let fmt8 = FloatFormat::new(8);
        // Widening keeps negatives and the NaN sign bit.
        assert_eq!(fmt4.op_float2_float(0xBF800000, &fmt8), 0xBFF0000000000000);
        assert_eq!(fmt4.op_float2_float(0x80000000, &fmt8), 0x8000000000000000);
        assert_eq!(fmt4.op_float2_float(0xFFC00000, &fmt8), 0xFFF8000000000000);
        // Subnormal single -> normal double (normalize branch).
        assert_eq!(fmt4.op_float2_float(0x00000001, &fmt8), 0x36A0000000000000);
        // Narrowing with round-to-nearest-even at the tie.
        assert_eq!(fmt8.op_float2_float(0xBFF0000000000000, &fmt4), 0xBF800000);
        // 1+2^-24 is the exact tie between 1.0f and nextafter(1.0f): ties to
        // even keep 1.0f; 1+2^-24+2^-25 is above half and rounds up.
        assert_eq!(fmt8.op_float2_float(0x3FF0000010000000, &fmt4), 0x3F800000);
        assert_eq!(fmt8.op_float2_float(0x3FF0000018000000, &fmt4), 0x3F800001);
        assert_eq!(fmt8.op_float2_float(0xBFF0000010000000, &fmt4), 0xBF800000);
        // Denormalized output branch and clamps.
        assert_eq!(fmt8.op_float2_float(0x3800000000000000, &fmt4), 0x00400000);
        assert_eq!(fmt8.op_float2_float(0x2100000000000000, &fmt4), 0x00000000);
        assert_eq!(fmt8.op_float2_float(0x7FEFFFFFFFFFFFFF, &fmt4), 0x7F800000);
        assert_eq!(fmt8.op_float2_float(0xFFEFFFFFFFFFFFFF, &fmt4), 0xFF800000);
        assert_eq!(fmt8.op_float2_float(0xFFF8000000000000, &fmt4), 0xFFC00000);
        assert_eq!(fmt8.op_float2_float(0x8000000000000000, &fmt4), 0x80000000);
    }
}
