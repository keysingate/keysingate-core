//! Arithmetic in GF(2^8), the field the sharing is built over.
//!
//! The AES field: reduction polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11B`).
//! Chosen because it is the most reviewed byte field there is, not because the
//! sharing needs anything particular of it.
//!
//! # Everything here is table-free on purpose
//!
//! A lookup table indexed by a secret byte leaks that byte through the cache.
//! It is the classic break of table-driven AES, and it applies here for the
//! same reason: the multiplications below run on the secret and on the
//! polynomial's coefficients. So multiplication is a loop of eight steps that
//! always runs eight times, and the inverse is an exponentiation with a fixed
//! chain. Both are slower than a table and neither depends on the value.
//!
//! No branch in this module looks at a value. `mask` turns a bit into `0x00` or
//! `0xFF` and the work happens under it.

/// Multiplies in GF(2^8). Constant time.
#[must_use]
pub const fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p: u8 = 0;
    let mut i = 0;
    while i < 8 {
        // `b & 1` as a full mask, so the add is unconditional.
        let take = (b & 1).wrapping_neg();
        p ^= a & take;
        // xtime: shift, and reduce when the top bit was set.
        let carry = ((a >> 7) & 1).wrapping_neg();
        a <<= 1;
        a ^= 0x1b & carry;
        b >>= 1;
        i += 1;
    }
    p
}

/// The multiplicative inverse. `inv(0)` is defined as `0`.
///
/// By Fermat: in GF(2^8) every non-zero `a` has `a^254 = a^-1`. The chain below
/// is fixed, so the time does not depend on the value.
#[must_use]
pub const fn inv(a: u8) -> u8 {
    // a^254 = a^(2+4+8+16+32+64+128), built by repeated squaring.
    let a2 = mul(a, a);
    let a4 = mul(a2, a2);
    let a8 = mul(a4, a4);
    let a16 = mul(a8, a8);
    let a32 = mul(a16, a16);
    let a64 = mul(a32, a32);
    let a128 = mul(a64, a64);

    let mut r = a2;
    r = mul(r, a4);
    r = mul(r, a8);
    r = mul(r, a16);
    r = mul(r, a32);
    r = mul(r, a64);
    mul(r, a128)
}

/// Divides in GF(2^8). Division by zero yields `0`; the caller is responsible
/// for never needing that — here the divisor is a difference of two distinct
/// share indices and cannot be zero.
#[must_use]
pub const fn div(a: u8, b: u8) -> u8 {
    mul(a, inv(b))
}
