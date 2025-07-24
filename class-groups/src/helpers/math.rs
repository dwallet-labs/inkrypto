// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::ops::Div;

use crypto_bigint::subtle::CtOption;
use crypto_bigint::{
    CheckedAdd, Concat, ConstantTimeSelect, Int, Integer, Limb, NonZero, Split, Uint, Zero, U64,
};
use crypto_primes::Flavor;

use group::CsRng;

use crate::Error;

pub(crate) const FIRST_100_PRIMES: [u64; 100] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
];

/// Computes the Legendre symbol.
/// Assumes `p >= 3` is prime; may return an error if this is not the case.
///
/// -----
/// ### Legendre symbol
/// The Legendre Symbol is as follows:
///
/// $( n | p ) =$
/// - $0$ if $n ≡ 0 mod p$,
/// - $1$ if $n ≠ 0 mod p$ and $n$ is a quadratic residue,
/// - $-1$ if $n ≠ 0 mod p$ and $n$ is a quadratic non-residue.
///
/// Source: [Legendre symbol](https://en.wikipedia.org/wiki/Legendre_symbol).
///
/// -----
pub(crate) fn legendre_symbol<const LIMBS: usize, const WIDE_LIMBS: usize>(
    n: &Int<LIMBS>,
    p: &NonZero<Uint<LIMBS>>,
) -> Result<i8, Error>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    if p.get() <= Uint::from(2u32) {
        return Err(Error::PIsNotAnOddPrime);
    }

    let n_mod_p = n.normalized_rem(p);
    if n_mod_p == Uint::ZERO {
        Ok(0)
    } else if is_a_quadratic_residue(&n_mod_p, p)? {
        Ok(1)
    } else {
        Ok(-1)
    }
}

/// The kronecker extension of the Legendre Symbol.
/// Ref: [Kronecker Symbol](https://en.wikipedia.org/wiki/Kronecker_symbol).
/// Assumes `p` is a prime.
pub(crate) fn kronecker_extension_of_legendre_symbol<const LIMBS: usize, const WIDE_LIMBS: usize>(
    a: &Int<LIMBS>,
    p: &NonZero<Uint<LIMBS>>,
) -> Result<i8, Error>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    let two = Uint::from(2u32).to_nz().unwrap();
    if p == &two {
        // safe to unwrap; unwrapping on non-zero constants
        let a_mod_2 = a.normalized_rem(&two);
        let a_mod_8 = a.normalized_rem(&U64::from(8u32).to_nz().unwrap());

        if a_mod_2 == Uint::ZERO {
            Ok(0i8)
        } else if a_mod_8 == Uint::ONE || a_mod_8 == Uint::from(7u32) {
            Ok(1i8)
        } else if a_mod_8 == Uint::from(3u32) || a_mod_8 == Uint::from(5u32) {
            Ok(-1i8)
        } else {
            // impossible; it must be one of the other three cases.
            Err(Error::NoQuadraticNonResidueMod2)
        }
    } else {
        legendre_symbol(a, p)
    }
}

/// Checks whether $n$ is a _quadratic residue_ $mod p$,
/// i.e., checks whether there exists an $x$ s.t. $x^2 ≡ n mod p$.
/// Assumes $p$ is a prime and $0 <= n < p$; may return an error otherwise.
///
/// ---
/// ### Euler's criterion
/// [Euler's Criterion](https://en.wikipedia.org/wiki/Euler's_criterion)
/// states that for an odd prime $p$, $n^{(p-1)/2} ≡$
/// - $1 mod p$ if $n$ is a quadratic residue, or
/// - $-1 mod p$ if $n$ is a quadratic non-residue.
/// ---
pub(crate) fn is_a_quadratic_residue<const LIMBS: usize, const WIDE_LIMBS: usize>(
    n: &Uint<LIMBS>,
    p: &NonZero<Uint<LIMBS>>,
) -> Result<bool, Error>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    if p.get() <= Uint::from(2u32) {
        return Err(Error::PIsNotAnOddPrime);
    }
    if !bool::from(p.is_odd()) {
        return Err(Error::PIsNotAnOddPrime);
    }

    // safe; p is a non-zero unsigned integer.
    let p_min_1 = p.wrapping_sub(&Uint::ONE);
    let p_min_1_on_two = &p_min_1.wrapping_shr(1);
    let n_exp_p_min_1_on_two = modpow_vartime(n, p_min_1_on_two, p);

    if n_exp_p_min_1_on_two == Uint::ONE {
        Ok(true)
    } else if n_exp_p_min_1_on_two == p_min_1 {
        Ok(false)
    } else {
        // should never be touched; it suggests `p` was not prime, which was assumed.
        Err(Error::PIsNotPrime)
    }
}

/// Compute the smallest quadratic non-residue mod $p$,
/// i.e., find the smallest $n$ for which there exists no $r$ s.t. $r^2 ≡ n mod p$.
/// Assumes `p` is an odd prime, may return an error otherwise.
pub(crate) fn smallest_quadratic_non_residue<const LIMBS: usize, const WIDE_LIMBS: usize>(
    p: &NonZero<Uint<LIMBS>>,
) -> Result<Uint<LIMBS>, Error>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    if p.get() <= Uint::from(2u32) {
        return Err(Error::NoQuadraticNonResidueMod2);
    }

    let mut z = Uint::from(2u32);
    while is_a_quadratic_residue(&z, p)? {
        z = z
            .checked_add(&Uint::ONE)
            .into_option()
            .ok_or(Error::InternalError)?;
    }
    Ok(z)
}

/// Compute the square root of $n mod p$, i.e., finds $r$ s.t. $r^2 ≡ n mod p$.
/// Assumes that p is a prime, and that $n$ has a square root.
/// Returns an error if either is not the case.
///
/// Employs the [Tonelli-Shanks Algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm#The_algorithm).
pub(crate) fn sqrt_mod<const LIMBS: usize, const WIDE_LIMBS: usize>(
    n: &Uint<LIMBS>,
    p: &NonZero<Uint<LIMBS>>,
) -> Result<Uint<LIMBS>, Error>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    let two = Uint::from(2u32);
    // safe to unwrap; constant 2 is non-zero.
    let two_nz = two.to_nz().unwrap();

    // Deal with the case that $p = 2$.
    if p == &two_nz {
        return Ok(n.rem(&two_nz));
    }

    // Step 1: factor p - 1 into Q * 2^m
    // safe to wrap; p is assumed to be a prime >= 3 at this point.
    let p_min_1 = p.wrapping_sub(&Uint::ONE);
    let mut m = p_min_1.trailing_zeros();
    // safe to unwrap; if two_exp_m is some, it is non-zero.
    let two_exp_m = CtOption::from(Uint::<LIMBS>::ONE.overflowing_shl(m))
        .into_option()
        .ok_or(Error::InternalError)?
        .to_nz()
        .unwrap();
    let q = p_min_1.div(&two_exp_m);

    // Step 2: find a quadratic non-residue
    let z = smallest_quadratic_non_residue(p)?;

    // Step 3: set initial values
    let mut c = modpow_vartime(&z, &q, p);
    let mut t = modpow_vartime(n, &q, p);
    // safe to wrapping_add; q + 1 <= p, which fits in Uint.
    let q_plus_1_on_2 = q.wrapping_add(&Uint::ONE).wrapping_shr_vartime(1u32);
    let mut r = modpow_vartime(n, &q_plus_1_on_2, p);

    // Step 4: find the root
    loop {
        if t == Uint::ZERO {
            return Ok(Uint::ZERO);
        }
        if t == Uint::ONE {
            return Ok(r);
        }

        // Find smallest i, s.t. t^{2^i} = 1 mod p
        let mut i = 1;
        let mut t_exp_2_exp_i = modpow_vartime(&t, &two, p);
        while t_exp_2_exp_i != Uint::ONE && i < m {
            i += 1;
            t_exp_2_exp_i = t_exp_2_exp_i.mul_mod(&t_exp_2_exp_i, p);
        }

        if i == m {
            return Err(Error::QuadraticNonResidueHasNoSqrt);
        }

        // Compute b
        let exp = CtOption::from(Uint::ONE.overflowing_shl(m - i - 1))
            .into_option()
            .ok_or(Error::InternalError)?;
        let b = modpow_vartime(&c, &exp, p);

        m = i;
        let b_squared = b.mul_mod(&b, p);
        t = (t * b_squared) % p;
        c = b_squared;
        r = (r * b) % p;
    }
}

/// Find the smallest prime $p$ s.t. the Kronecker Symbol $(n | p) = 1$.
///
/// Since this function only accepts positive primes for $n$ and finds the smallest positive
/// prime $p$, the Kronecker symbol equals the Kronecker extension of the Legendre Symbol.
pub(crate) fn smallest_kronecker_prime<const LIMBS: usize, const WIDE_LIMBS: usize>(
    n: &Int<LIMBS>,
) -> Result<u64, Error>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    for p in FIRST_100_PRIMES.into_iter() {
        // safe to unwrap; FIRST_100_PRIMES contains non-zero constants only.
        let p_ = Uint::from(p).to_nz().unwrap();

        // Note: using the kronecker extension of the legendre symbol suffices here (instead of
        // using the full Kronecker Symbol), since we know $p$ to be prime.
        if kronecker_extension_of_legendre_symbol(n, &p_)? == 1i8 {
            return Ok(p);
        }
    }
    Err(Error::NoSolutionAmongSmallPrimes)
}

/// Construct a prime `p` of given `bit_size` s.t. the Kronecker Symbol `(n | p) = 1`.
///
/// This function uses `rng` to repeatedly sample primes until a prime satisfying the
/// constraints is found. If after the given number of `max_attempts` no satisfying prime is found,
/// the function returns `None`. Heuristically, for large enough `max_attempts`, this function
/// should fail with probability 1/2^max_attempts: for a random prime `p`, the probability that
/// `Δ_qk` is a square mod `p` is ~1/2, and we repeat `max_attempts` times.
///
/// Note: since this function only accepts positive primes for $n$ and finds a positive prime $p$,
/// the Kronecker symbol equals the Kronecker extension of the Legendre Symbol.
pub(crate) fn random_kronecker_prime<
    const LIMBS: usize,
    const WIDE_LIMBS: usize,
    const OUT_LIMBS: usize,
>(
    n: &Int<LIMBS>,
    rng: &mut impl CsRng,
    bit_length: u32,
    max_attempts: u32,
) -> Option<NonZero<Uint<OUT_LIMBS>>>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    assert!(OUT_LIMBS <= LIMBS);

    let mut attempts = 0;
    let mut p = None;

    while p.is_none() && attempts < max_attempts {
        let sample =
            crypto_primes::random_prime::<Uint<OUT_LIMBS>, _>(rng, Flavor::Any, bit_length)
                .to_nz()
                .expect("a prime is non-zero");

        // Note: using the kronecker extension of the legendre symbol suffices here (instead of
        // using the full Kronecker Symbol), since we know `sample` to be prime.
        let is_kronecker_prime = match kronecker_extension_of_legendre_symbol(
            n,
            &sample.resize::<LIMBS>().to_nz().unwrap(),
        ) {
            Ok(kronecker_symbol) => kronecker_symbol == 1i8,
            Err(_) => false,
        };

        if is_kronecker_prime {
            p = Some(sample);
        }

        attempts += 1;
    }

    p
}

/// Given `(numerator, divisor)`, returns `(factor, exponent)` s.t.
/// $numerator = factor * divisor^{exponent}$, `factor` integral, and `exponent` maximal.
/// In other words, count all factors of `divisor` in `numerator`, remove them and
/// return the remainder as well as the count.
/// The multiplicative equivalent to the `div_mod` function.
///
/// Executes in time variable in the size of `divisor`.
pub(crate) fn factor_mod_vartime<const LIMBS: usize>(
    mut numerator: Int<LIMBS>,
    divisor: &NonZero<Uint<LIMBS>>,
) -> (Int<LIMBS>, u32) {
    // The result of dividing an x-bit numerator by a y-bit denominator can be represented
    // using at most x - y + 1 bits. Thus, exponent is upper bounded by x / (y - 1).
    let exponent_upper_bound = Uint::<LIMBS>::BITS / (divisor.bits() - 1);

    let mut exponent = 0;
    for _ in 0..exponent_upper_bound {
        let (q, r) = numerator.div_rem_uint(divisor);

        let zero_remainder = r.is_zero();
        numerator = Int::ct_select(&numerator, &q, zero_remainder);
        exponent = u32::ct_select(&exponent, &(exponent + 1), zero_remainder);
    }

    // safe to unwrap: result is not larger than `numerator`, which fit.
    (numerator, exponent)
}

/// Compute `x^e`
pub(crate) fn pow_vartime<const LIMBS: usize, const WIDE_LIMBS: usize>(
    x: &Uint<LIMBS>,
    e: u32,
) -> Result<Uint<LIMBS>, Error>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
{
    let mut res = Uint::ONE;
    let mut overflow;

    let exponent_bits = u32::BITS - e.leading_zeros();
    for exponent_bit in (0..exponent_bits).rev().map(|n| (e >> n) & 1) {
        (res, overflow) = res.square_wide();
        if overflow != Uint::ZERO {
            return Err(Error::InternalError);
        }

        if exponent_bit == 1 {
            (res, overflow) = res.widening_mul(x);
            if overflow != Uint::ZERO {
                return Err(Error::InternalError);
            }
        }
    }
    Ok(res)
}

/// Compute `x^e mod m`.
pub(crate) fn modpow_vartime<const LIMBS: usize, const WIDE_LIMBS: usize>(
    x: &Uint<LIMBS>,
    e: &Uint<LIMBS>,
    m: &NonZero<Uint<LIMBS>>,
) -> Uint<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>>,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    let mut res = *x;
    let exponent_bits = Uint::<LIMBS>::BITS - e.leading_zeros() - 1;
    for exponent_bit in (0..exponent_bits)
        .rev()
        .map(|n| (e >> n).to_limbs()[0] & Limb::ONE)
    {
        res = res.mul_mod(&res, m);
        if exponent_bit == Limb::ONE {
            res = res.mul_mod(x, m);
        }
    }
    res
}

/// Given `x` in `(-m, m)`, return the value of `x mod m` in `[0, m)`.
///
/// Assumes `x` already in `(-m, m)`. Undefined behaviour otherwise.
pub(crate) fn representative_mod<const LIMBS: usize>(
    x: &Int<LIMBS>,
    m: &NonZero<Uint<LIMBS>>,
) -> Uint<LIMBS> {
    let (x_abs, x_sgn) = x.abs_sign();
    Uint::ct_select(&x_abs, &m.wrapping_sub(&x_abs), x_sgn.into())
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Int, Uint, U128};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::helpers::math::{
        factor_mod_vartime, is_a_quadratic_residue, kronecker_extension_of_legendre_symbol,
        legendre_symbol, modpow_vartime, random_kronecker_prime, smallest_kronecker_prime,
        smallest_quadratic_non_residue, sqrt_mod,
    };

    const LIMBS: usize = 1;

    #[test]
    fn test_legendre_0() {
        let n = Int::<LIMBS>::from(1623i32);
        let p = Uint::from(541u32).to_nz().unwrap();

        // 1623 mod 541 = 0 mod 541
        assert_eq!(legendre_symbol(&n, &p).unwrap(), 0);
    }

    #[test]
    fn test_legendre_1() {
        let n = Int::<LIMBS>::from(2i32);
        let p = Uint::from(7u32).to_nz().unwrap();

        // 3² mod 7 = 9 mod 7 = 2 mod 9
        // thus, 2 is a quadratic residue mod 7.
        assert_eq!(legendre_symbol(&n, &p).unwrap(), 1);
    }

    #[test]
    fn test_legendre_minus_1() {
        let n = Int::<LIMBS>::from(5i32);
        let p = Uint::from(17u32).to_nz().unwrap();

        // 5⁸ mod 17 = 16 mod 17 = -1 mod 17
        // thus, 5 not a quadratic residue mod 17.
        assert_eq!(legendre_symbol(&n, &p).unwrap(), -1);
    }

    #[test]
    fn test_legendre_negative() {
        let n = Int::<LIMBS>::from(-5i32);
        let p = Uint::from(19u32).to_nz().unwrap();

        // (-5)⁹ mod 19 = 18 mod 19 = -1 mod 19
        // thus, 5 is not a quadratic residue mod 19.
        assert_eq!(legendre_symbol(&n, &p).unwrap(), -1);
    }

    #[test]
    fn test_kronecker_extension_0() {
        let a = Int::<LIMBS>::from(2i8);
        let p = Uint::from(2u8).to_nz().unwrap();
        assert_eq!(kronecker_extension_of_legendre_symbol(&a, &p).unwrap(), 0);
    }

    #[test]
    fn test_kronecker_extension_1() {
        let a = Int::<LIMBS>::from(7i8);
        let p = Uint::from(2u8).to_nz().unwrap();
        assert_eq!(kronecker_extension_of_legendre_symbol(&a, &p).unwrap(), 1);
    }

    #[test]
    fn test_kronecker_extension_minus_1() {
        let a = Int::<LIMBS>::from(3i8);
        let p = Uint::from(2u8).to_nz().unwrap();
        assert_eq!(kronecker_extension_of_legendre_symbol(&a, &p).unwrap(), -1);
    }

    #[test]
    fn test_is_a_quadratic_residue_err() {
        let n = Uint::<LIMBS>::from(1u32);
        let p = Uint::<LIMBS>::from(2u32).to_nz().unwrap();

        // p should be at least three
        assert!(is_a_quadratic_residue(&n, &p).is_err());
    }

    #[test]
    fn test_is_a_quadratic_residue_true() {
        let n = Uint::<LIMBS>::from(2u32);
        let p = Uint::<LIMBS>::from(7u32).to_nz().unwrap();

        // 3² mod 7 = 9 mod 7 = 2 mod 9
        // thus, 2 is a quadratic residue mod 7.
        assert!(is_a_quadratic_residue(&n, &p).unwrap());
    }

    #[test]
    fn test_is_a_quadratic_residue_false() {
        let n = Uint::<LIMBS>::from(5u32);
        let p = Uint::<LIMBS>::from(17u32).to_nz().unwrap();

        // 5³ mod 17 = 16 mod 17 = -1 mod 17
        // thus, 5 not a quadratic residue mod 17
        assert!(!is_a_quadratic_residue(&n, &p).unwrap());
    }

    #[test]
    fn test_is_a_quadratic_residue_error() {
        let n = Uint::<LIMBS>::from(5u32);
        let p = Uint::from(18u32).to_nz().unwrap();

        // 18 is not a prime. Should return an error.
        assert!(is_a_quadratic_residue(&n, &p).is_err());
    }

    #[test]
    fn test_smallest_quadratic_non_residue() {
        let p = Uint::<LIMBS>::from(37u32).to_nz().unwrap();
        let n = smallest_quadratic_non_residue(&p).unwrap();

        assert!(!is_a_quadratic_residue(&n, &p).unwrap());
        assert_eq!(n, Uint::from(2u32));
    }

    #[test]
    fn test_smallest_quadratic_non_residue_mod_2() {
        let p = Uint::<LIMBS>::from(2u32).to_nz().unwrap();
        assert!(smallest_quadratic_non_residue(&p).is_err());
    }

    #[test]
    fn test_sqrt_mod() {
        let p = Uint::from(37u32).to_nz().unwrap();
        let n = Uint::<LIMBS>::from(3u32);

        assert_eq!(legendre_symbol(n.as_int(), &p).unwrap(), 1);
        assert!(is_a_quadratic_residue(&n, &p).unwrap());

        let r = sqrt_mod(&n, &p).unwrap();
        assert_eq!(r.mul_mod(&r, &p), n)
    }

    #[test]
    fn test_sqrt_mod_2() {
        let p = Uint::<LIMBS>::from(2u32).to_nz().unwrap();

        let zero = Uint::<LIMBS>::ZERO;
        assert_eq!(sqrt_mod(&zero, &p).unwrap(), zero);

        let one = Uint::<LIMBS>::from(1u32);
        assert_eq!(sqrt_mod(&one, &p).unwrap(), one);

        let n = Uint::<LIMBS>::from(37u32);
        assert_eq!(sqrt_mod(&n, &p).unwrap(), one);
    }

    #[test]
    fn test_sqrt_mod_3() {
        let p = Uint::<LIMBS>::from(3u32).to_nz().unwrap();

        let zero = Uint::<LIMBS>::ZERO;
        assert_eq!(sqrt_mod(&zero, &p).unwrap(), zero);

        let one = Uint::<LIMBS>::from(1u32);
        assert_eq!(sqrt_mod(&one, &p).unwrap(), one);

        let two = Uint::<LIMBS>::from(2u32);
        assert!(sqrt_mod(&two, &p).is_err());
    }

    #[test]
    fn test_smallest_kronecker_prime_37() {
        let n = Int::<LIMBS>::from(37i32);
        let p = smallest_kronecker_prime(&n).unwrap();
        // (37|2) = -1
        // (37|3) =  1
        assert_eq!(p, 3u64);
    }

    #[test]
    fn test_random_kronecker_prime_73() {
        let n = Int::<2>::from(73i32);
        let mut rng = ChaChaRng::seed_from_u64(73);
        let target = Uint::from(6491u64).to_nz().unwrap();

        // Illustrate that target is a valid value
        assert_eq!(
            kronecker_extension_of_legendre_symbol(&n, &target).unwrap(),
            1i8
        );

        let p = random_kronecker_prime(&n, &mut rng, 13, 1);
        assert_eq!(p.unwrap(), target);
    }

    #[test]
    fn test_random_kronecker_prime_509() {
        let n = Int::<2>::from(509i32);
        let mut rng = ChaChaRng::seed_from_u64(37);
        let target = Uint::from(4903u64).to_nz().unwrap();

        // Illustrate that target is a valid value
        assert_eq!(
            kronecker_extension_of_legendre_symbol(&n, &target).unwrap(),
            1i8
        );

        // Does not find anything the first iteration
        let p = random_kronecker_prime::<2, 4, 2>(&n, &mut rng, 13, 1);
        assert!(p.is_none());

        let p = random_kronecker_prime(&n, &mut rng, 13, 1);
        assert_eq!(p.unwrap(), target);
    }

    #[test]
    fn test_smallest_kronecker_prime_53() {
        let n = Int::<LIMBS>::from(53i32);
        let p = smallest_kronecker_prime(&n).unwrap();
        // (53|2) = -1
        // (53|3) = -1
        // (53|5) = -1
        // (53|7) =  1
        assert_eq!(p, 7u64);
    }

    #[test]
    fn test_factor_mod() {
        let numerator = Int::<LIMBS>::from(-47455841832i64); // = -7^{11} * 24
        let divisor = Uint::<LIMBS>::from(7u64).to_nz().unwrap();
        assert_eq!(
            factor_mod_vartime(numerator, &divisor),
            (Int::from(-24i32), 11)
        )
    }

    #[test]
    fn test_modpow() {
        assert_eq!(
            modpow_vartime(&U128::ONE, &U128::from(55u32), &U128::MAX.to_nz().unwrap()),
            U128::ONE
        );
        assert_eq!(
            modpow_vartime(
                &U128::from(2u32),
                &U128::from(55u32),
                &U128::MAX.to_nz().unwrap(),
            ),
            U128::ONE.shl(55)
        );
        assert_eq!(
            modpow_vartime(
                &U128::from(5u32),
                &U128::from(55u32),
                &U128::MAX.to_nz().unwrap(),
            ),
            U128::from_be_hex("D0CF4B50CFE20765FFF4B4E3F741CF6D")
        );
    }
}
