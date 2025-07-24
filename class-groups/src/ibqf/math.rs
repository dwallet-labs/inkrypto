// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::cmp::max;
use std::mem;
use std::ops::Sub;

use crypto_bigint::subtle::{ConstantTimeGreater, CtOption};
use crypto_bigint::{
    CheckedAdd, CheckedMul, CheckedSub, Concat, ConstantTimeSelect, Int, NonZero, Split, Uint, I64,
    U64,
};

use matrix::Matrix;

use crate::helpers::vartime_mul::CheckedMulVartime;
use crate::Error;

mod matrix;

/// Lehmer's extended GCD algorithm, computing only the Bézout coefficient for the first argument.
///
/// Given `(a, b)` returns `(g, x, b/gcd)` s.t. `ax = g mod b` with `g = gcd(a, b)`.
///
/// This implementation is a copy of `ruint`'s `gcd_extended` algorithm, licensed under MIT,
/// adapted to
/// 1) operate on `crypto_bigint::Uint`s and,
/// 2) only compute the Bézout coefficient for the first argument.
///
/// Ref: [ruint](https://github.com/recmo/uint/blob/898a955/src/algorithms/gcd/mod.rs#L64).
///
/// Note that this algorithm executes in variable time with respect to both input parameters.
///
/// # Algorithm
///
/// A variation of Euclids algorithm where repeated 64-bit approximations are
/// used to make rapid progress on.
///
/// See Jebelean (1994) "A Double-Digit Lehmer-Euclid Algorithm for Finding the
/// GCD of Long Integers".
///
/// See also `mpn_gcdext_lehmer_n` in GMP.
/// <https://gmplib.org/repo/gmp-6.1/file/tip/mpn/generic/gcdext_lehmer.c#l146>
#[inline]
#[must_use]
pub fn half_xgcd_vartime<const LIMBS: usize>(
    mut a: Uint<LIMBS>,
    b: NonZero<Uint<LIMBS>>,
) -> (NonZero<Uint<LIMBS>>, Int<LIMBS>, NonZero<Uint<LIMBS>>) {
    let mut b = *b;

    let (mut s0, mut s1) = (Uint::ONE, Uint::ZERO);
    let mut negate_s1 = true;

    if a < b {
        mem::swap(&mut a, &mut b);
        mem::swap(&mut s0, &mut s1);
        negate_s1 = !negate_s1;
    }

    while b != Uint::ZERO {
        debug_assert!(a >= b);
        let m = Matrix::from(&a, &b);
        if m == Matrix::IDENTITY {
            // Lehmer step failed to find a factor, which happens when
            // the factor is very large. We do a regular Euclidean step, which
            // will make a lot of progress since `q` will be large.

            let b_nz = b.to_nz().expect("b is non-zero by loop invariant");
            let q;
            (q, a) = a.div_rem_vartime(&b_nz);
            s0 = s0.wrapping_sub(&q.wrapping_mul(&s1));

            mem::swap(&mut a, &mut b);
            mem::swap(&mut s0, &mut s1);
            negate_s1 = !negate_s1;
        } else {
            m.apply(&mut a, &mut b);
            m.apply(&mut s0, &mut s1);
            negate_s1 = negate_s1 == m.has_positive_determinant();
        }
    }

    let gcd = a.to_nz().expect("gcd of a non-zero value is non-zero");
    let x = *s0.as_int();
    let b_div_gcd = if negate_s1 { s1.wrapping_neg() } else { s1 }
        .to_nz()
        .expect("proper division of a non-zero value is non-zero");

    (gcd, x, b_div_gcd)
}

/// Variation to [half_xgcd_vartime] that accepts `a` to be an [Int].
#[inline]
#[must_use]
pub fn half_int_xgcd_vartime<const LIMBS: usize>(
    a: Int<LIMBS>,
    b: NonZero<Uint<LIMBS>>,
) -> (NonZero<Uint<LIMBS>>, Int<LIMBS>, NonZero<Uint<LIMBS>>) {
    let (a_abs, a_sgn) = a.abs_sign();
    let (gcd_a_b, mut u, b_div_gcd) = half_xgcd_vartime(a_abs, b);

    // Account for the fact that `a` might have been negative.
    u = *u.as_uint().wrapping_neg_if(a_sgn).as_int();

    (gcd_a_b, u, b_div_gcd)
}

/// Variation to [xgcd_vartime] that accepts `b` to be an [Int].
///
/// Executes in variable time w.r.t. both `a` and `b`.
#[inline]
#[must_use]
pub fn int_xgcd_vartime<const LIMBS: usize>(
    a: NonZero<Uint<LIMBS>>,
    b: Int<LIMBS>,
) -> (
    NonZero<Uint<LIMBS>>,
    Int<LIMBS>,
    Int<LIMBS>,
    NonZero<Uint<LIMBS>>,
    Int<LIMBS>,
) {
    let (b_abs, b_sgn) = b.abs_sign();
    let (gcd_a_b, u, mut v, a_div_gcd, abs_b_div_gcd) = xgcd_vartime(a, b_abs);

    // Account for the fact that `b` might have been negative.
    v = *v.as_uint().wrapping_neg_if(b_sgn).as_int();
    let b_div_gcd = *abs_b_div_gcd.wrapping_neg_if(b_sgn).as_int();

    (gcd_a_b, u, v, a_div_gcd, b_div_gcd)
}

/// The subroutine used by `xgcd`-esque operations.
#[inline]
fn xgcd_subroutine<const LIMBS: usize, const MATRIX_LIMBS: usize>(
    a: &mut Uint<LIMBS>,
    b: &mut Uint<LIMBS>,
    state_matrix: &mut Matrix<MATRIX_LIMBS>,
) {
    debug_assert!(a >= b);
    let m = Matrix::from(a, b);
    if m == Matrix::IDENTITY {
        // Lehmer step failed to find a factor, which happens when
        // the factor is very large. We do a regular Euclidean step, which
        // will make a lot of progress since `q` will be large.

        // safe to unwrap; b is non-zero by loop invariant.
        let q;
        (q, *a) = a.div_rem_vartime(&b.to_nz().unwrap());
        mem::swap(a, b);

        state_matrix.left_mul_upper_triangular(q);
        state_matrix.swap_rows();
    } else {
        m.apply(a, b);
        m.mul(state_matrix);
    }
}

/// Given an `xgcd` state matrix such that `matrix * (a, b) = (gcd, 0)`, extract the Bézout
/// coefficients `x, y` s.t. `ax + by = gcd`.
///
/// This operation executes in variable time with respect to `matrix`.
#[inline]
fn bezout_coefficients_from_matrix_vartime<const LIMBS: usize>(
    matrix: &Matrix<LIMBS>,
) -> (Int<LIMBS>, Int<LIMBS>) {
    let (mut x, mut y) = (matrix.0, matrix.1);
    if matrix.4 {
        y = y.wrapping_neg();
    } else {
        x = x.wrapping_neg();
    }
    (*x.as_int(), *y.as_int())
}

/// Given an `xgcd` state matrix such that `matrix * (a, b) = (gcd, 0)`, extract the quotients
/// `a/gcd` and `b/gcd`.
#[inline]
fn quotients_from_matrix<const LIMBS: usize>(matrix: &Matrix<LIMBS>) -> (Uint<LIMBS>, Uint<LIMBS>) {
    (matrix.3, matrix.2)
}

/// Lehmer's extended GCD algorithm.
///
/// Given `(a, b)`, return `(g, x, y, a/g, b/g)` s.t. `ax + by = g = gcd(a, b)`.
///
/// This implementation is a copy of `ruint`'s `gcd_extended` algorithm, licensed under MIT,
/// adapted to operate on `crypto_bigint::Uint`s.
///
/// Ref: [ruint](https://github.com/recmo/uint/blob/898a955/src/algorithms/gcd/mod.rs#L64).
///
/// # Algorithm
///
/// A variation of Euclids algorithm where repeated 64-bit approximations are
/// used to make rapid progress on.
///
/// See Jebelean (1994) "A Double-Digit Lehmer-Euclid Algorithm for Finding the
/// GCD of Long Integers".
///
/// See also `mpn_gcdext_lehmer_n` in GMP.
/// <https://gmplib.org/repo/gmp-6.1/file/tip/mpn/generic/gcdext_lehmer.c#l146>
#[inline]
#[must_use]
pub fn xgcd_vartime<const LIMBS: usize>(
    a: NonZero<Uint<LIMBS>>,
    mut b: Uint<LIMBS>,
) -> (
    NonZero<Uint<LIMBS>>,
    Int<LIMBS>,
    Int<LIMBS>,
    NonZero<Uint<LIMBS>>,
    Uint<LIMBS>,
) {
    let mut a = *a;
    let mut state_matrix = Matrix::IDENTITY;

    if a < b {
        mem::swap(&mut a, &mut b);
        state_matrix.swap_rows();
    }

    while b != Uint::ZERO {
        xgcd_subroutine(&mut a, &mut b, &mut state_matrix)
    }

    let gcd = a.to_nz().expect("gcd of a non-zero element is non-zero");
    let (x, y) = bezout_coefficients_from_matrix_vartime(&state_matrix);
    let (a_div_gcd, b_div_gcd) = quotients_from_matrix(&state_matrix);
    let a_div_gcd = a_div_gcd
        .to_nz()
        .expect("proper division of a non-zero element yields a non-zero element");

    (gcd, x, y, a_div_gcd, b_div_gcd)
}

/// The values returned by [`partial_xgcd_vartime`] do not always have a bit size exactly equal to
/// `reduction_bits_bound`; the bit sizes of the values lie in the interval
/// `[reduction_bits_bound - spread, reduction_bits_bound]`.
/// This `spread` parameter is captured in this constant.
///
/// See [`partial_xgcd_vartime`] for more detail.
pub(crate) const PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD: u32 = 32;

/// A partial application of Lehmer's extended GCD algorithm.
///
/// Given `(a, b)` return `(m, a', b')` s.t.
/// 1. `gcd(a', b') = gcd(a, b)`,
/// 2. `a'.bits()` in interval `[reduction_bits_bound - PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD, reduction_bits_bound]`.
/// 2. `b'.bits() <= a'.bits()`,
/// 3. `M * (a', b') = (a, b)`, and
/// 4. `det(M) = 1`.
///
/// This implementation is an adaptation of [xgcd_vartime].
#[inline]
#[must_use]
pub fn partial_xgcd_vartime<const LIMBS: usize>(
    mut a: Uint<LIMBS>,
    mut b: Uint<LIMBS>,
    reduction_bits_bound: u32,
) -> (
    (Uint<LIMBS>, Uint<LIMBS>, Uint<LIMBS>, Uint<LIMBS>),
    Uint<LIMBS>,
    Uint<LIMBS>,
) {
    let mut state = Matrix::IDENTITY;

    if a < b {
        mem::swap(&mut a, &mut b);
        state.swap_rows();
    }

    while a.bits_vartime() >= reduction_bits_bound {
        xgcd_subroutine(&mut a, &mut b, &mut state);
    }

    if !state.has_positive_determinant() {
        mem::swap(&mut a, &mut b);
        state.swap_rows();
    }
    debug_assert!(state.has_positive_determinant());

    let (abs_adjoint, all_values_are_non_negative) = state.adjoint();
    debug_assert!(all_values_are_non_negative);

    (abs_adjoint, a, b)
}

/// Given `a`, `b` and `m`, compute `a * b % m`, contained in interval `[0, m)`.
/// TODO: deprecate in favor of Uint.mul_mod? Only odd `m` are currently supported there.
pub(crate) fn mul_mod<const LIMBS: usize, const WIDE_LIMBS: usize>(
    a: &Uint<LIMBS>,
    b: &Uint<LIMBS>,
    m: &NonZero<Uint<LIMBS>>,
) -> Uint<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    // TODO: get rid of resize using Uint::split_mul and Uint::rem_wide_vartime?
    // safe to unwrap: upscale of non-zero value.
    let resized_m = m.resize::<WIDE_LIMBS>().to_nz().unwrap();
    let a_mul_b_mod_m = a.concatenating_mul(b).rem(&resized_m);

    // safe to resize: result is smaller than `m`, which fits in `Uint<LIMBS>`
    a_mul_b_mod_m.resize::<LIMBS>()
}

/// Given `(ax, ay, bx, by)` compute `(axbx, axby + aybx, ayby)`.
/// Uses only three multiplications to achieve this.
///
/// Note: requires the absolute value of all four variables to be smaller than `Int::MAX/2`; the
/// extra bit is required for the additions.
pub(crate) fn three_way_mul<const LIMBS: usize>(
    ax: Int<LIMBS>,
    ay: Int<LIMBS>,
    bx: CtOption<Int<LIMBS>>,
    by: CtOption<Int<LIMBS>>,
) -> (
    CtOption<Int<LIMBS>>,
    CtOption<Int<LIMBS>>,
    CtOption<Int<LIMBS>>,
) {
    let axbx = bx.and_then(|bx| ax.checked_mul(&bx));
    let ayby = by.and_then(|by| ay.checked_mul(&by));
    let ax_plus_ay = CtOption::from(ax.checked_add(&ay));
    let bx_plus_by = bx.and_then(|bx| by.and_then(|by| bx.checked_add(&by).into()));
    let axbx_axby_aybx_ayby = ax_plus_ay.and_then(|ax_plus_ay| {
        bx_plus_by.and_then(|bx_plus_by| ax_plus_ay.checked_mul(&bx_plus_by))
    });
    let axbx_axby_aybx = axbx_axby_aybx_ayby.and_then(|axbx_axby_aybx_ayby| {
        ayby.and_then(|ayby| axbx_axby_aybx_ayby.checked_sub(&ayby))
    });
    let axby_aybx = axbx_axby_aybx
        .and_then(|axbx_axby_aybx| axbx.and_then(|axbx| axbx_axby_aybx.checked_sub(&axbx)));

    (axbx, axby_aybx, ayby)
}

/// Variation to [three_way_mul] that accepts [Uint]s as its first two parameters.
pub(crate) fn three_way_mul_uint<const LHS_LIMBS: usize, const RHS_LIMBS: usize>(
    ax: Uint<LHS_LIMBS>,
    ay: Uint<LHS_LIMBS>,
    bx: CtOption<Int<RHS_LIMBS>>,
    by: CtOption<Int<RHS_LIMBS>>,
) -> (
    CtOption<Int<RHS_LIMBS>>,
    CtOption<Int<RHS_LIMBS>>,
    CtOption<Int<RHS_LIMBS>>,
) {
    let axbx = bx.and_then(|bx| bx.checked_mul(&ax));
    let ayby = by.and_then(|by| by.checked_mul(&ay));
    let ax_plus_ay = ax.checked_add(&ay);
    let bx_plus_by = bx.and_then(|bx| by.and_then(|by| bx.checked_add(&by).into()));
    let axbx_axby_aybx_ayby = ax_plus_ay.and_then(|ax_plus_ay| {
        bx_plus_by.and_then(|bx_plus_by| bx_plus_by.checked_mul(&ax_plus_ay))
    });
    let axbx_axby_aybx = axbx_axby_aybx_ayby.and_then(|axbx_axby_aybx_ayby| {
        ayby.and_then(|ayby| axbx_axby_aybx_ayby.checked_sub(&ayby))
    });
    let axby_aybx = axbx_axby_aybx
        .and_then(|axbx_axby_aybx| axbx.and_then(|axbx| axbx_axby_aybx.checked_sub(&axbx)));

    (axbx, axby_aybx, ayby)
}

/// Variable time equivalent of [three_way_mul].
pub(crate) fn three_way_mul_vartime<const LHS_LIMBS: usize, const RHS_LIMBS: usize>(
    ax: Int<LHS_LIMBS>,
    ay: Int<LHS_LIMBS>,
    bx: Int<RHS_LIMBS>,
    by: Int<RHS_LIMBS>,
) -> Result<(Int<LHS_LIMBS>, Int<LHS_LIMBS>, Int<LHS_LIMBS>), Error> {
    // Compute AxDx, AyDy and AxDy + AyDx using only three multiplications.
    let axbx = ax
        .checked_mul_vartime(&bx)
        .into_option()
        .ok_or(Error::InternalError)?;
    let ayby = ay
        .checked_mul_vartime(&by)
        .into_option()
        .ok_or(Error::InternalError)?;
    let axby_bxay = CtOption::from(ax.checked_add(&ay))
        .and_then(|ax_ay| {
            CtOption::from(bx.checked_add(&by)).and_then(|bx_by| ax_ay.checked_mul_vartime(&bx_by))
        })
        .and_then(|axbx_axby_aybx_ayby| axbx_axby_aybx_ayby.checked_sub(&axbx))
        .and_then(|axby_aybx_ayby| axby_aybx_ayby.checked_sub(&ayby))
        .into_option()
        .ok_or(Error::InternalError)?;

    Ok((axbx, axby_bxay, ayby))
}

/// Compute `num / denom`. Assumes the result fits in no more than 31 bits.
///
/// ## Panics
/// May panic whenever `num / denom` is larger than 31 bits.
///
/// ## Vartime
/// Runs in variable time w.r.t. both `num` and `denom`.
pub(crate) fn bounded_div_rem_vartime<const LIMBS: usize>(
    num: &Int<LIMBS>,
    denom: &Uint<LIMBS>,
) -> (I64, Int<LIMBS>) {
    let (abs_num, sgn_num) = num.abs_sign();

    // Get an approximation for the division. It might have overshot by one.
    let approx = approx_bounded_div_vartime(&abs_num, denom);
    let (mut q, potential_overshoot) = match approx {
        DivApproximation::Exact(q) => (U64::from(q), false),
        DivApproximation::PotentialOvershoot(approx_q) => (U64::from(approx_q), true),
    };

    let mut prod = denom.checked_mul_vartime(&q).expect("no overflow");

    // Correct for potential overshoot
    if potential_overshoot {
        let did_overshoot = prod.ct_gt(&abs_num);
        q = U64::ct_select(&q, &q.saturating_sub(&U64::ONE), did_overshoot);
        prod = Uint::ct_select(&prod, &prod.saturating_sub(denom), did_overshoot);
    }

    let q = I64::new_from_abs_sign(q, sgn_num).unwrap();
    let rem = Int::new_from_abs_sign(abs_num.sub(&prod), sgn_num).unwrap();
    (q, rem)
}

pub(crate) enum DivApproximation<T> {
    Exact(T),
    PotentialOvershoot(T),
}

/// Approximate `num / div`. Assumes the result fits in no more than 31 bits.
///
/// Runs in time variable in the values of `num` and `denom`.
///
/// Ref: [gmplib](https://gmplib.org/manual/Small-Quotient-Division).
pub(crate) fn approx_bounded_div_vartime<const LIMBS: usize>(
    num: &Uint<LIMBS>,
    denom: &Uint<LIMBS>,
) -> DivApproximation<u64> {
    // Compute the bit sizes of the numerator and denominator
    let numerator_bits = num.bits_vartime();
    let denominator_bits = denom.bits_vartime();

    // For the division result to be close enough, the numerator should be fewer than 31 bits
    // larger than the denominator.
    debug_assert!(numerator_bits.saturating_sub(denominator_bits) <= 31);

    // Word-align to the 64 most significant bits of the largest of numerator/denominator.
    let bitsize_largest = max(numerator_bits, denominator_bits);
    let shift = bitsize_largest.saturating_sub(U64::BITS);
    let shifted_num = num.shr_vartime(shift);
    let shifted_denom = denom.shr_vartime(shift);

    // Shrink the representations to 64 bits
    let num_most_significant_word: u64 = U64::from(&shifted_num).into();
    let denom_most_significant_word: u64 = U64::from(&shifted_denom).into();

    // Approximate the division; it might overshoot by one.
    let q = num_most_significant_word / denom_most_significant_word;
    let r = num_most_significant_word % denom_most_significant_word;

    if r > q {
        DivApproximation::Exact(q)
    } else {
        DivApproximation::PotentialOvershoot(q)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::{Add, Deref, Div, Sub};

    use crypto_bigint::{
        ConcatMixed, Random, RandomMod, I1024, I128, I2048, I256, U1024, U128, U1536, U2048, U256,
    };

    use group::OsCsRng;

    use super::*;

    /// Test the correctness of [half_xgcd_vartime].
    ///   i. gcd(a, b) = g
    ///  ii. ax mod b = g
    /// iii. b_div_gcd = b / g
    fn half_xgcd_test<const LIMBS: usize, const DOUBLE: usize>(
        a: Uint<LIMBS>,
        b: NonZero<Uint<LIMBS>>,
    ) where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        let (g, x, b_div_gcd) = half_xgcd_vartime(a, b);

        // Test correct gcd value
        assert_eq!(*g, a.bingcd(&b));

        // Test correct quotient
        assert_eq!(*b_div_gcd, b.div(&g));

        // test that `ax = gcd mod b` if a != 0 mod b, and zero otherwise
        if a.rem(&b.to_nz().unwrap()) == Uint::ZERO {
            assert_eq!(x, Int::ZERO);
        } else {
            assert_eq!(
                x.concatenating_mul_uint(&a)
                    .normalized_rem(&b.to_nz().unwrap()),
                g.get()
            );
        }
    }

    fn half_xgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
    where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        half_xgcd_test(Uint::ZERO, NonZero::ONE);
        half_xgcd_test(Uint::ZERO, NonZero::MAX);
        half_xgcd_test(Uint::ONE, NonZero::ONE);
        half_xgcd_test(Uint::ONE, NonZero::MAX);
        half_xgcd_test(Uint::MAX, NonZero::ONE);
        half_xgcd_test(Uint::MAX, NonZero::MAX);

        for _ in 0..100 {
            let a = Uint::<LIMBS>::random(&mut OsCsRng);
            let b = Uint::<LIMBS>::random(&mut OsCsRng)
                .bitor(&Uint::ONE)
                .to_nz()
                .unwrap();
            half_xgcd_test(a, b);
        }
    }

    #[test]
    fn test_half_xgcd() {
        half_xgcd_tests::<1, 2>();
        half_xgcd_tests::<2, 4>();
        half_xgcd_tests::<3, 6>();
        half_xgcd_tests::<4, 8>();
        half_xgcd_tests::<5, 10>();
        half_xgcd_tests::<6, 12>();
        half_xgcd_tests::<7, 14>();
        half_xgcd_tests::<8, 16>();
        half_xgcd_tests::<16, 32>();
        half_xgcd_tests::<32, 64>();
    }

    fn xgcd_test<const LIMBS: usize, const DOUBLE: usize>(a: Uint<LIMBS>, b: Uint<LIMBS>)
    where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        let (g, x, y, a_div_gcd, b_div_gcd) = xgcd_vartime(a.to_nz().unwrap(), b);

        // Test correct gcd value
        assert_eq!(*g, a.bingcd(&b));

        // Test correctness of quotients
        assert_eq!(*a_div_gcd, a.div(&g));
        assert_eq!(b_div_gcd, b.div(&g));

        // test that `ax + by = gcd`
        assert_eq!(
            x.concatenating_mul_uint(&a) + y.concatenating_mul_uint(&b),
            *g.resize().as_int()
        );
    }

    fn xgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
    where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        xgcd_test(Uint::ONE, Uint::ZERO);
        xgcd_test(Uint::ONE, Uint::ONE);
        xgcd_test(Uint::ONE, Uint::MAX);
        xgcd_test(Uint::MAX, Uint::ZERO);
        xgcd_test(Uint::MAX, Uint::ONE);
        xgcd_test(Uint::MAX, Uint::MAX);

        for _ in 0..100 {
            let a = Uint::random(&mut OsCsRng).bitor(&Uint::ONE);
            let b = Uint::random(&mut OsCsRng);
            xgcd_test(a, b)
        }
    }

    #[test]
    fn test_xgcd() {
        xgcd_tests::<1, 2>();
        xgcd_tests::<2, 4>();
        xgcd_tests::<3, 6>();
        xgcd_tests::<4, 8>();
        xgcd_tests::<5, 10>();
        xgcd_tests::<6, 12>();
        xgcd_tests::<7, 14>();
        xgcd_tests::<8, 16>();
        xgcd_tests::<16, 32>();
        xgcd_tests::<32, 64>();
    }

    fn int_xgcd_test<const LIMBS: usize, const DOUBLE: usize>(a: Uint<LIMBS>, b: Int<LIMBS>)
    where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        let (g, x, y, a_div_gcd, b_div_gcd) = int_xgcd_vartime(a.to_nz().unwrap(), b);

        // Test correct gcd value
        assert_eq!(*g, a.bingcd(&b.abs()));

        // Test correctness of quotients
        assert_eq!(*a_div_gcd, a.div(&g));
        assert_eq!(b_div_gcd, b.div(&g));

        // test that `ax + by = gcd`
        assert_eq!(
            x.concatenating_mul_uint(&a) + y.concatenating_mul(&b),
            *g.resize().as_int()
        );
    }

    fn int_xgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
    where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        int_xgcd_test(Uint::ONE, Int::MIN);
        int_xgcd_test(Uint::ONE, Int::MINUS_ONE);
        int_xgcd_test(Uint::ONE, Int::ZERO);
        int_xgcd_test(Uint::ONE, Int::ONE);
        int_xgcd_test(Uint::ONE, Int::MAX);
        int_xgcd_test(Uint::MAX, Int::MIN);
        int_xgcd_test(Uint::MAX, Int::MINUS_ONE);
        int_xgcd_test(Uint::MAX, Int::ZERO);
        int_xgcd_test(Uint::MAX, Int::ONE);
        int_xgcd_test(Uint::MAX, Int::MAX);

        for _ in 0..100 {
            let a = Uint::<LIMBS>::random(&mut OsCsRng).bitor(&Uint::ONE);
            let b = Int::<LIMBS>::random(&mut OsCsRng);
            int_xgcd_test(a, b);
        }
    }

    #[test]
    fn test_int_xgcd() {
        int_xgcd_tests::<1, 2>();
        int_xgcd_tests::<2, 4>();
        int_xgcd_tests::<3, 6>();
        int_xgcd_tests::<4, 8>();
        int_xgcd_tests::<5, 10>();
        int_xgcd_tests::<6, 12>();
        int_xgcd_tests::<7, 14>();
        int_xgcd_tests::<8, 16>();
        int_xgcd_tests::<16, 32>();
        int_xgcd_tests::<32, 64>();
    }

    fn partial_xgcd_test<const LIMBS: usize, const DOUBLE: usize>(
        a: Uint<LIMBS>,
        b: Uint<LIMBS>,
        reduction_bound: u32,
    ) where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        let (m, partial_a, partial_b) = partial_xgcd_vartime(a, b, reduction_bound);

        // Test requirement 1:
        // the partials still have the same gcd as the full values.
        assert_eq!(partial_a.bingcd(&partial_b), a.bingcd(&b));

        // Test requirement 2:
        // the partials are smaller than the reduction bound.
        assert!(partial_a.bits_vartime() <= reduction_bound);
        assert!(partial_b.bits_vartime() <= reduction_bound);

        // Test requirement 3:
        // the matrix multiplies back to the original input.
        let (m00, m01, m10, m11) = m;
        assert_eq!(m00 * partial_a + m01 * partial_b, a);
        assert_eq!(m10 * partial_a + m11 * partial_b, b);

        // Test requirement 4:
        // the returned matrix has determinant =  1
        let det = m00.concatenating_mul(&m11) - m01.concatenating_mul(&m10);
        assert_eq!(det, Uint::ONE);
    }

    #[test]
    fn test_partial_xgcd() {
        const COUNT: usize = 50;
        const REDUCTION_BOUND: u32 = 1024;

        let modulus = U1536::MAX.resize::<{ U2048::LIMBS }>().to_nz().unwrap();

        for _ in 0..COUNT {
            let a = U2048::random_mod(&mut OsCsRng, &modulus);
            let b = U2048::random_mod(&mut OsCsRng, &modulus);
            partial_xgcd_test(a, b, REDUCTION_BOUND);
        }
    }

    /// Regression test.
    /// These cases specifically triggers the MATRIX::IDENTITY statement.
    #[test]
    fn test_partial_xgcd_regression_identity_clause() {
        let x = U1024::from_be_hex(concat![
            "0000000000000000000000006E929396BD5A6FFE8B1BBED68520D855CFD03E67",
            "68EFC3BEE9407F787B4B8FA8E0750B7DDD690A1284EA3E48C346647478EAA0BB",
            "7C1407FCBBF22F366394146FB265F3510F6AFC9375B6DB44420CFC208D5720BC",
            "DDC06FDC0F6F6C6FAC30B5F2168E4BAF080653DBED94DBCA513E46C4F98818D7"
        ]);
        let y = U1024::from_be_hex(concat![
            "00000000000000000000000149496622110E26E5B53BC20111D740F063B7D718",
            "161C7A7EC058E5FD84B9D1CEFD43EEB8C7A4E7578A7A1E6106B13F10AD7EE07D",
            "1F5315DA10D9FA531AB0F3DF8DF5B20228752ECC38643E36C8D8617F5E1E4DA8",
            "A51A7E5B5EE6CC0E2FBAC062F15D3CC0022C8C16317985F53F61FCC866938ABD"
        ]);
        partial_xgcd_test(x, y, 512);

        let x = U1024::from_be_hex(concat![
            "00000000000000000000000015E8D61D81C2A1D2AD2374C130816A9B182585CC",
            "10972C22222F91EF798F70B39D0ED98E8D675A94E059ADCFF2E83CA3911B0A1A",
            "CB582E90728762152BA84E73558C9FB18D91A8DC290E14A70D09F08E67B3DA5D",
            "5E961D69368CFFAA193A0B2B812604916B7E2A81C4BACCA345ABD68F798EFE2C"
        ]);
        let y = U1024::from_be_hex(concat![
            "0000000000000000000000012F1509F735D4E3C5057E051EE982C8448B999AAF",
            "4BCDA52721F23029BE8A883F500BB72EB21A5A5685555BA439B2C799027AD7AB",
            "157259A912F4013406C9897463735A22480BDE16B86F936DAE1BC44BD0C13A54",
            "7A4A30A1F4482EB9AFBF4580732B634E170F582D09A80672438F3EDE9DF1BBAD"
        ]);
        partial_xgcd_test(x, y, 512);
    }

    #[test]
    fn test_three_way_mul() {
        const COUNT: u32 = 50;
        let modulus = I1024::MAX.shr_vartime(1).as_uint().to_nz().unwrap();
        for _ in 0..COUNT {
            let ax = U1024::random_mod(&mut OsCsRng, &modulus)
                .as_int()
                .resize::<{ I2048::LIMBS }>();
            let ay = U1024::random_mod(&mut OsCsRng, &modulus)
                .as_int()
                .resize::<{ I2048::LIMBS }>();
            let bx = *U1024::random_mod(&mut OsCsRng, &modulus).as_int();
            let by = *U1024::random_mod(&mut OsCsRng, &modulus).as_int();

            let (axbx, axby_aybx, ayby) = three_way_mul_vartime(ax, ay, bx, by).unwrap();
            assert_eq!(axbx, ax * bx);
            assert_eq!(axby_aybx, ax * by + ay * bx);
            assert_eq!(ayby, ay * by);
        }
    }

    #[inline]
    fn bounded_div_test<const LIMBS: usize>(a: NonZero<Int<LIMBS>>, b: NonZero<Uint<LIMBS>>) {
        let (q, r) = a.get().div_rem_uint(&b);
        let (comp_q, comp_r) = bounded_div_rem_vartime(a.deref(), b.deref());
        assert_eq!(comp_q, q.resize());
        assert_eq!(comp_r, r);

        let approx = approx_bounded_div_vartime(&a.abs(), b.deref());
        match approx {
            DivApproximation::Exact(approx_q) => assert_eq!(q.abs().as_words()[0], approx_q),
            DivApproximation::PotentialOvershoot(approx_q) => {
                assert!(approx_q - q.abs().as_words()[0] < 2)
            }
        }
    }

    #[test]
    fn test_approx_bounded_div() {
        for _ in 0..50000 {
            let a = I256::random(&mut OsCsRng).abs().as_int().to_nz().unwrap();
            let b = U256::random(&mut OsCsRng).to_nz().unwrap();
            bounded_div_test(a, b)
        }

        // test edge cases, where denominator is 1 too large for proper division.
        let modulus = Uint::ONE.shl(31).to_nz().unwrap();
        for _ in 0..50000 {
            let l = I128::random(&mut OsCsRng).abs().as_int().to_nz().unwrap();
            let r = U128::random_mod(&mut OsCsRng, &modulus).to_nz().unwrap();

            let a = l.concatenating_mul_uint(&r).to_nz().unwrap();
            let b = l
                .as_uint()
                .resize()
                .saturating_add(&Uint::ONE)
                .to_nz()
                .unwrap();
            bounded_div_test(a, b)
        }
    }

    #[test]
    fn test_approx_bounded_div_individual_cases() {
        // (2^2047 - 1) / (2^2016 - 1)
        let a = I2048::MAX.to_nz().unwrap();
        let b = a.shr(31).abs().to_nz().unwrap();
        bounded_div_test(a, b);

        // (2^2047 - 1) / 2^2016
        let a = I2048::MAX.to_nz().unwrap();
        let b = U2048::ONE.shl_vartime(2016).to_nz().unwrap();
        bounded_div_test(a, b);

        // 2^2046 / (2^2015 - 1)
        let a = I2048::ONE.shl_vartime(2045).to_nz().unwrap();
        let b = U2048::ONE.shl_vartime(2015).sub(Uint::ONE).to_nz().unwrap();
        bounded_div_test(a, b);

        // 2^2046 / 2^2015
        let a = I2048::ONE.shl_vartime(2046).to_nz().unwrap();
        let b = U2048::ONE.shl_vartime(2015).to_nz().unwrap();
        bounded_div_test(a, b);

        // 2^2046 / (2^2016 + 2^216)
        let a = I2048::ONE.shl_vartime(2046).to_nz().unwrap();
        let b = U2048::ONE
            .shl_vartime(1800)
            .add(Uint::ONE)
            .shl_vartime(216)
            .to_nz()
            .unwrap();
        bounded_div_test(a, b);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::hint::black_box;
    use std::ops::Div;
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{BatchSize, BenchmarkGroup, Criterion};
    use crypto_bigint::{Random, I1024, I2048, U1024, U2048, U768};

    use group::OsCsRng;

    use crate::ibqf::math::{approx_bounded_div_vartime, bounded_div_rem_vartime, mul_mod};

    fn benchmark_mulmod(g: &mut BenchmarkGroup<WallTime>) {
        g.bench_function("mulmod U768", |b| {
            b.iter_batched(
                || {
                    (
                        U768::random(&mut OsCsRng),
                        U768::random(&mut OsCsRng),
                        U768::random(&mut OsCsRng),
                    )
                },
                |(x, y, z)| black_box(mul_mod(&x, &y, &z.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });
        g.bench_function("mulmod U1024", |b| {
            b.iter_batched(
                || {
                    (
                        U1024::random(&mut OsCsRng),
                        U1024::random(&mut OsCsRng),
                        U1024::random(&mut OsCsRng),
                    )
                },
                |(x, y, z)| black_box(mul_mod(&x, &y, &z.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });
        g.bench_function("mulmod U2048", |b| {
            b.iter_batched(
                || {
                    (
                        U2048::random(&mut OsCsRng),
                        U2048::random(&mut OsCsRng),
                        U2048::random(&mut OsCsRng),
                    )
                },
                |(x, y, z)| black_box(mul_mod(&x, &y, &z.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });
    }

    fn benchmark_div(g: &mut BenchmarkGroup<WallTime>) {
        g.bench_function("div (U1024, ct)", |b| {
            b.iter_batched(
                || (I1024::random(&mut OsCsRng), U1024::random(&mut OsCsRng)),
                |(x, y)| black_box(x.div(&y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });

        g.bench_function("div (U1024, vt)", |b| {
            b.iter_batched(
                || (I1024::random(&mut OsCsRng), U1024::random(&mut OsCsRng)),
                |(x, y)| black_box(x.div_uint_vartime(&y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });

        g.bench_function("bounded_div (U1024, vt)", |b| {
            b.iter_batched(
                || (I1024::random(&mut OsCsRng), U1024::random(&mut OsCsRng)),
                |(x, y)| black_box(bounded_div_rem_vartime(&x, &y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });

        g.bench_function("approx bounded_div (U1024, vt)", |b| {
            b.iter_batched(
                || (U1024::random(&mut OsCsRng), U1024::random(&mut OsCsRng)),
                |(x, y)| black_box(approx_bounded_div_vartime(&x, &y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });

        g.bench_function("div (U2048, ct)", |b| {
            b.iter_batched(
                || (I2048::random(&mut OsCsRng), U2048::random(&mut OsCsRng)),
                |(x, y)| black_box(x.div(&y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });

        g.bench_function("div (U2048, vt)", |b| {
            b.iter_batched(
                || (I2048::random(&mut OsCsRng), U2048::random(&mut OsCsRng)),
                |(x, y)| black_box(x.div_uint_vartime(&y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });

        g.bench_function("bounded_div (U2048, vt)", |b| {
            b.iter_batched(
                || (I2048::random(&mut OsCsRng), U2048::random(&mut OsCsRng)),
                |(x, y)| black_box(bounded_div_rem_vartime(&x, &y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });

        g.bench_function("approx bounded_div (U2048, vt)", |b| {
            b.iter_batched(
                || (U2048::random(&mut OsCsRng), U2048::random(&mut OsCsRng)),
                |(x, y)| black_box(approx_bounded_div_vartime(&x, &y.to_nz().unwrap())),
                BatchSize::SmallInput,
            )
        });
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let mut group = _c.benchmark_group("ibqf::math");
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        benchmark_div(&mut group);
        benchmark_mulmod(&mut group);
    }
}
