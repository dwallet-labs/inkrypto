// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{BitAnd, Shr};

use crypto_bigint::subtle::Choice;
use crypto_bigint::{Concat, ConstantTimeSelect, Encoding, Int, Limb, Split, Uint, Word};

use crate::helpers::CtMinMax;
use crate::ibqf::Ibqf;

impl<const HALF: usize, const LIMBS: usize, const DOUBLE: usize> Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<LIMBS>>,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    /// Compute `self^exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    pub(crate) fn nupow<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        self.nupow_with_base(self.unit(), exponent)
    }

    /// Compute `base^{2^b} * self^exponent` with `b = Uint::<EXPONENT_LIMBS>::BITS`.
    ///
    /// ### Panics
    /// May panic if `self` and `base` have a different discriminant.
    pub(crate) fn nupow_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        let mut res = base;
        for limb in exponent.to_words().into_iter().rev() {
            res = self.pow_and_mul(res, limb, Word::BITS);
        }
        res
    }

    /// Compute `self^exponent`.
    ///
    /// Executes in variable time w.r.t. both `self` and `exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    pub(crate) fn nupow_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        self.nupow_with_base_vartime(self.unit(), exponent)
    }

    /// Compute `base^{2^b} * self^exponent`, with `b = exponent.bits()`.
    ///
    /// Executes in variable time w.r.t. `self`, `base` and `exponent`.
    ///
    /// ### Panics
    /// May panic if `self` and `base` have a different discriminant.
    pub(crate) fn nupow_with_base_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        let exponent_bits = exponent.bits_vartime();

        let (full_limb_count, leading_bit_count) =
            div_rem_2k_vartime_divisor(exponent_bits, Word::BITS);
        let full_limb_count: usize = full_limb_count
            .try_into()
            .expect("safe to cast; value ≤ EXPONENT_LIMBS which is usize");
        let scalar_words = exponent.to_words();

        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul_vartime(res, leading_word, leading_bit_count);
        }

        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul_vartime(res, *limb, Word::BITS);
        }

        res
    }

    /// Compute `self^{2^k}`.
    ///
    /// Executes in variable time w.r.t. both `self` and `k`.
    pub(crate) fn nupow2k_vartime(&self, k: u32) -> Self {
        let mut res = *self;
        for _ in 0..k {
            res = res.nudupl_vartime();
        }
        res
    }

    /// Variation to [Ibqf::nupow2k_vartime] that assumes `self` to be a random form. In particular,
    /// this means that
    /// - the bit lengths of their `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - significantly fewer iterations are required to reduce the output form.
    pub(crate) fn nupow2k_randomized(&self, k: u32) -> Self {
        let mut res = *self;
        for _ in 0..k {
            res = res.nudupl_randomized();
        }
        res
    }

    /// Compute `self^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    pub(crate) fn nupow_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Self {
        self.nupow_bounded_with_base(self.unit(), exponent, exponent_bits)
    }

    /// Compute `base^{2^b} * self^e`, with `e` the integer represented by the
    /// `b = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS)` least significant bits of `exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    ///
    /// ### Panics
    /// May panic if `self` and `base` have a different discriminant.
    pub(crate) fn nupow_bounded_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
        mut exponent_bits: u32,
    ) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Uint::<EXPONENT_LIMBS>::BITS);

        let (full_limb_count, leading_bit_count) =
            div_rem_2k_vartime_divisor(exponent_bits, Word::BITS);
        let full_limb_count: usize = full_limb_count
            .try_into()
            .expect("safe to cast; value ≤ EXPONENT_LIMBS which is usize");
        let scalar_words = exponent.to_words();

        // leading bits from most significant limb.
        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul(res, leading_word, leading_bit_count);
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul(res, *limb, Word::BITS);
        }

        res
    }

    /// Compute `self^e`
    ///
    /// ### Randomized
    /// Variation to [Ibqf::nupow_bounded] that assumes `self` to be a random form. In particular,
    /// this means that
    /// - the bit lengths of its `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - significantly fewer iterations are required to reduce the output form.
    pub(crate) fn nupow_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        self.nupow_bounded_randomized(exponent, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Compute `self^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`.
    ///
    /// ### Randomized
    /// Variation to [Ibqf::nupow_bounded] that assumes `self` to be a random form. In particular,
    /// this means that
    /// - the bit lengths of its `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - significantly fewer iterations are required to reduce the output form.
    pub(crate) fn nupow_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Self {
        self.nupow_bounded_randomized_with_base(self.unit(), exponent, exponent_bits)
    }

    /// Compute `base^{2^b} * self^e`, with `e` the integer represented by the
    /// `b = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS)` least significant bits of `exponent`.
    ///
    /// ### Randomized
    /// Variation to [Ibqf::nupow_bounded_with_base] that assumes `self` and `base` to be random
    /// forms. In particular, this means that
    /// - the bit lengths of their `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - significantly fewer iterations are required to reduce the output form.
    ///
    /// ### Panics
    /// May panic
    /// - if `self` and `base` have a different discriminant,
    /// - if either form is not randomized, or
    /// - `self = base` and `base ≠ unit`.
    pub(crate) fn nupow_bounded_randomized_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
        mut exponent_bits: u32,
    ) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Uint::<EXPONENT_LIMBS>::BITS);

        let (full_limb_count, leading_bit_count) =
            div_rem_2k_vartime_divisor(exponent_bits, Word::BITS);
        let full_limb_count: usize = full_limb_count
            .try_into()
            .expect("safe to cast; value ≤ EXPONENT_LIMBS which is usize");
        let scalar_words = exponent.to_words();

        // leading bits from most significant limb.
        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul_randomized_pair(res, leading_word, leading_bit_count);
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul_randomized_pair(res, *limb, Word::BITS);
        }

        res
    }

    /// Compute `self^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. all input variables.
    pub(crate) fn nupow_bounded_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Self {
        let mask = Uint::MAX
            .wrapping_shr_vartime(Uint::<EXPONENT_LIMBS>::BITS.saturating_sub(exponent_bits));
        let exponent = exponent.bitand(&mask);
        let exponent_bits = exponent.bits_vartime();

        self.nupow_bounded_with_base_vartime_ibqf_and_exponent(
            self.unit(),
            &exponent,
            exponent_bits,
        )
    }

    /// Compute `base^{2^b} * self^e`, with `e` the integer represented by the
    /// `b = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS)` least significant bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. `exponent`, `self`, `base` and all other intermediate
    /// [Ibqf] values, but, importantly, not `exponent_bits`.
    ///
    /// ### Panics
    /// May panic if `self` and `base` have a different discriminant.
    pub(crate) fn nupow_bounded_with_base_vartime_ibqf_and_exponent<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
        mut exponent_bits: u32,
    ) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Uint::<EXPONENT_LIMBS>::BITS);

        let (full_limb_count, leading_bit_count) =
            div_rem_2k_vartime_divisor(exponent_bits, Word::BITS);
        let full_limb_count: usize = full_limb_count
            .try_into()
            .expect("safe to cast; value ≤ EXPONENT_LIMBS which is usize");
        let scalar_words = exponent.to_words();

        // leading bits from most significant limb.
        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul_vartime(res, leading_word, leading_bit_count);
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul_vartime(res, *limb, Word::BITS);
        }

        res
    }

    /// Raise `self^exponent * unit^c`, with `c` the binary complement of `exponent`.
    ///
    /// ### With complement
    /// In each iteration of the square-and-multiply algorithm, the state is multiplied by either
    /// `1` or `base`, depending on the selected exponent bit. Since multiplying by `1` is a no-op,
    /// this operation is often skipped for efficiency.
    ///
    /// This variation to [Self::nupow_vartime] allows the caller to pass in a custom "complement"
    /// element, which is multiplied in every iteration in which the exponent bit is zero.
    /// Note that passing in `self.unit()` yields the standard [Self::nupow_vartime] algorithm.
    /// (Note: using [Self::nupow_vartime] is faster in this case!)
    ///
    /// ### Variable-Time — Safe Only Against Naive Timing Attacks
    /// Executes in variable time w.r.t. `self` and `complement`, but not `exponent`.
    ///
    /// Because this function is constant time in `exponent`, it can be safely leveraged in
    /// situations that only need to defend against naive timing attacks. Specifically, the total
    /// execution time for two different exponents, `T(mask * self, exponent₀)` and
    /// `T(mask * self, exponent₁)`, is indistinguishable to an adversary who does not know the
    /// value of the `mask`.
    /// This implies that, provided that `mask` is sampled correctly and the adversary only observes
    /// the total computation time, the operation is safe under certain assumptions about class
    /// groups. See [`docs/Bounds on information leakage in class groups encryption.md`]
    /// for further details.
    ///
    /// ### Panics
    /// May panic if `self` and `complement` have a different discriminant.
    pub(crate) fn nupow_with_complement_vartime_ibqf<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        complement: &Self,
    ) -> Self {
        self.nupow_bounded_with_complement_vartime_ibqf(
            exponent,
            Uint::<EXPONENT_LIMBS>::BITS,
            complement,
        )
    }

    /// Raise `self^e * complement^c`, where `e` is the integer represented by the `exponent_bits`
    /// least significant bits of `exponent` and `c` the binary complement of `e`.
    ///
    /// ### With complement
    /// In each iteration of the square-and-multiply algorithm, the state is multiplied by either
    /// `1` or `base`, depending on the selected exponent bit. Since multiplying by `1` is a no-op,
    /// this operation is often skipped for efficiency.
    ///
    /// This variation to [Self::nupow_bounded_vartime] allows the caller to pass in a custom
    /// "complement" element, which is multiplied in every iteration in which the exponent bit
    /// is **zero**.
    /// Note that passing in `self.unit()` yields the standard [Self::nupow_bounded_vartime]
    /// algorithm. (Note: using [Self::nupow_bounded_vartime] is faster in this case!)
    ///
    /// ### Variable-Time — Safe Only Against Naive Timing Attacks
    /// Executes in variable time w.r.t. `self`, `complement` and `exponent_bits`, but not
    /// `exponent`.
    ///
    /// Because this function is constant time in `exponent`, it can be safely leveraged in
    /// situations that only need to defend against naive timing attacks. Specifically, the total
    /// execution time for two different exponents, `T(mask * self, exponent₀)` and
    /// `T(mask * self, exponent₁)`, is indistinguishable to an adversary who does not know the
    /// value of the `mask`.
    /// This implies that, provided that `mask` is sampled correctly and the adversary only observes
    /// the total computation time, the operation is safe under certain assumptions about class
    /// groups. See [`docs/Bounds on information leakage in class groups encryption.md`]
    /// for further details.
    ///
    /// ### Panics
    /// May panic if `self` and `complement` have a different discriminant.
    pub(crate) fn nupow_bounded_with_complement_vartime_ibqf<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        mut exponent_bits: u32,
        complement: &Self,
    ) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Uint::<EXPONENT_LIMBS>::BITS);
        if exponent_bits == 0 {
            return self.unit();
        }

        // Apply square-and-multiply step for most significant bit.
        exponent_bits -= 1;
        let msb = exponent.bit(exponent_bits);
        let mut res = Self::ct_select(complement, self, msb.into());

        let full_limb_count = usize::try_from(exponent_bits / Word::BITS)
            .expect("safe to cast; value ≤ EXPONENT_LIMBS which is usize");
        let leading_bit_count = exponent_bits % Word::BITS;

        // leading bits from most significant limb.
        let scalar_words = exponent.to_words();
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul_with_complement_vartime(
                res,
                leading_word,
                leading_bit_count,
                complement,
            );
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul_with_complement_vartime(res, *limb, Word::BITS, complement);
        }

        res
    }

    /// Compute `base^{2^b} * self^e`, with `e` the value represented by the
    /// `b = min(exponent_bits, Word::BITS)` least significant bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. all parameters.
    ///
    /// ### Panics
    /// May panic if `self` and `base` have a different discriminant
    #[inline]
    fn pow_and_mul_vartime(
        &self,
        mut base: Self,
        mut exponent: Word,
        mut exponent_bits: u32,
    ) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Word::BITS);
        exponent = exponent.reverse_bits() >> Word::BITS.saturating_sub(exponent_bits);

        for _ in 0..exponent_bits {
            base = base.nudupl_vartime();
            if exponent & 1 == 1 {
                base = base.nucomp_vartime(*self);
            }
            exponent >>= 1;
        }
        base
    }

    /// Maps `(base, self, complement)` to `base^{2^b} * self^e * complement^c`, with `e`
    /// the value represented by the `b = min(exponent_bits, Word::BITS)` least significant bits of
    /// `exponent`, and `c` the binary complement of `e`.
    ///
    /// ### Variable-Time — Safe Only Against Naive Timing Attacks
    /// Executes in variable time w.r.t. `self`, `base`, `complement` and `exponent_bits`, but not
    /// `exponent`.
    ///
    /// Because this function is constant time in `exponent`, it can be safely leveraged in
    /// situations that only need to defend against naive timing attacks. Specifically, the total
    /// execution time for two different exponents, `T(mask * self, exponent₀)` and
    /// `T(mask * self, exponent₁)`, is indistinguishable to an adversary who does not know the
    /// value of the `mask`.
    /// This implies that, provided that `mask` is sampled correctly and the adversary only observes
    /// the total computation time, the operation is safe under certain assumptions about class
    /// groups. See [`docs/Bounds on information leakage in class groups encryption.md`]
    /// for further details.
    ///
    /// ### Panics
    /// May panic if `self`, `base` and `complement` do not have the same discriminant.
    #[inline]
    fn pow_and_mul_with_complement_vartime(
        &self,
        mut base: Self,
        mut exponent: Word,
        mut exponent_bits: u32,
        complement: &Self,
    ) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Word::BITS);
        exponent = exponent.reverse_bits() >> (Word::BITS - exponent_bits);

        for _ in 0..exponent_bits {
            base = base.nudupl_vartime();

            let bit = Limb(exponent).is_odd();
            base = Self::ct_select(
                &base.nucomp_vartime(*complement),
                &base.nucomp_vartime(*self),
                bit,
            );
            exponent >>= 1;
        }
        base
    }

    /// Compute `base^{2^b} * self^e`, with `e` the value represented by the
    /// `b = min(exponent_bits, Word::BITS)` least significant bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. `exponent_bits`.
    ///
    /// ### Panics
    /// May panic if `self` and `base` have a different discriminant.
    #[inline]
    fn pow_and_mul(&self, base: Self, mut exponent: Word, mut exponent_bits: u32) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Word::BITS);
        exponent = exponent.reverse_bits() >> Word::BITS.saturating_sub(exponent_bits);

        let mut res = base;
        for _ in 0..exponent_bits {
            let exponent_bit = Choice::from((exponent & 1) as u8);
            res = res.nudupl();
            res = Self::ct_select(&res, &res.nucomp(*self), exponent_bit);

            exponent >>= 1;
        }
        res
    }

    /// Compute `base^{2^b} * self^e`, with `e` the value represented by the
    /// `b = min(exponent_bits, Word::BITS)` least significant bits of `exponent`.
    ///
    /// ### Randomized Pair
    /// Variation to [Ibqf::pow_and_mul] that assumes `self` and `base` to be random forms that are
    /// not the same. In particular, this means that
    /// - the bit lengths of their `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - significantly fewer iterations are required to reduce the output form.
    ///
    /// ### Panics
    /// May panic if
    /// - `self` and `base` have a different discriminant, or
    /// - `self = base` and `base ≠ unit`.
    #[inline]
    fn pow_and_mul_randomized_pair(
        &self,
        base: Self,
        mut exponent: Word,
        mut exponent_bits: u32,
    ) -> Self {
        exponent_bits = u32::ct_min(&exponent_bits, &Word::BITS);
        exponent = exponent.reverse_bits() >> Word::BITS.saturating_sub(exponent_bits);

        let mut res = base;
        for _ in 0..exponent_bits {
            let exponent_bit = Choice::from((exponent & 1) as u8);

            res = res.nudupl_randomized();
            res = Self::ct_select(&res, &res.nucomp_randomized_pair(*self), exponent_bit);

            exponent >>= 1;
        }
        res
    }
}

/// Compute `a / power_of_two` and `a % power_of_two`.
///
/// Executes in variable time in `power_of_two` only.
fn div_rem_2k_vartime_divisor(a: u32, power_of_two: u32) -> (u32, u32) {
    let sub_one = power_of_two.saturating_sub(1);
    let shift = u32::BITS - sub_one.leading_zeros();
    let div = a.shr(shift);
    let rem = a.bitand(sub_one);
    (div, rem)
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Random, Uint, U128, U256, U64};

    use group::OsCsRng;

    use crate::ibqf::test_helpers::{get_deterministic_secp256k1_form, Ibqf128};

    use super::div_rem_2k_vartime_divisor;

    #[test]
    fn test_div_rem_2k_vartime_divisor() {
        assert_eq!(div_rem_2k_vartime_divisor(17, 4), (4, 1));
        assert_eq!(div_rem_2k_vartime_divisor(21, 4), (5, 1));
        assert_eq!(div_rem_2k_vartime_divisor(17, 8), (2, 1));
        assert_eq!(div_rem_2k_vartime_divisor(21, 8), (2, 5));
    }

    #[test]
    fn test_nupow2k_ct_vs_vartime() {
        let form = get_deterministic_secp256k1_form();
        assert_eq!(form.nupow2k_vartime(77), form.nupow2k_randomized(77))
    }

    #[test]
    fn test_nupow_relative_to_nudupl_and_nucomp() {
        let f = Ibqf128::new_reduced_64(11, 16, -2868).unwrap();

        assert_eq!(f.nudupl(), f.nupow(&Uint::<1>::from(2u64)));
        assert_eq!(f.nudupl().nudupl(), f.nupow(&Uint::<1>::from(4u64)));
        assert_eq!(
            f.nudupl().nudupl().nudupl(),
            f.nupow(&Uint::<1>::from(8u64))
        );
        assert_eq!(
            f.nudupl() // 2
                .nucomp(f) // 3
                .nudupl() // 6
                .nudupl() // 12
                .nucomp(f) // 13
                .nudupl() // 26
                .nucomp(f), // 27
            f.nupow(&Uint::<1>::from(27u64))
        );

        let two_exp_63 = Uint::<1>::ONE << 63; // = 2^{63}
        let f2 = f.nupow(&two_exp_63).nudupl(); // = f^{2^32}
        let two_exp_64 = Uint::<2>::ONE << 64; // = 2^64
        let f3 = f.nupow(&two_exp_64);
        assert_eq!(f2, f3);

        let f2 = f.nupow(&two_exp_63).nupow(&two_exp_63).nupow(&two_exp_63);
        let f3 = f.nupow(&(Uint::<3>::ONE << 189));
        assert_eq!(f2, f3);
    }

    #[test]
    fn test_nupow_ct_vs_vartime() {
        let form = get_deterministic_secp256k1_form();
        let exp = U256::random(&mut OsCsRng);
        assert_eq!(form.nupow(&exp), form.nupow_vartime(&exp));
    }

    #[test]
    fn test_nupow_bounded_vartime() {
        let form = get_deterministic_secp256k1_form();
        let exp = U64::random(&mut OsCsRng);

        assert_eq!(
            form.nupow_bounded(&exp, 35),
            form.nupow_bounded_vartime(&exp, 35)
        );
    }

    #[test]
    fn test_nupow_with_base() {
        let form = get_deterministic_secp256k1_form();
        let base = form.nupow_vartime(&U64::from(5u64));

        let exp = U64::random(&mut OsCsRng);
        assert_eq!(
            form.nupow_with_base(base, &exp),
            form.nupow(&exp).nucomp(base.nupow(&U128::ONE.shl(64)))
        );
    }

    #[test]
    fn test_nupow_with_base_vartime() {
        let form = get_deterministic_secp256k1_form();
        let base = form.nupow_vartime(&U64::from(5u64));

        let exp = U64::random(&mut OsCsRng);
        assert_eq!(
            form.nupow_with_base_vartime(base, &exp),
            form.nupow_vartime(&exp)
                .nucomp(base.nupow_vartime(&U128::ONE.shl(exp.bits())))
        );
    }

    #[test]
    fn test_nupow_bounded_with_base() {
        let form = get_deterministic_secp256k1_form();
        let base = form.nupow_vartime(&U64::from(5u64));

        // Small bound
        let exp = U64::random(&mut OsCsRng);
        let bound = 35;
        assert_eq!(
            form.nupow_bounded_with_base(base, &exp, bound),
            form.nupow_bounded(&exp, bound)
                .nucomp(base.nupow(&U64::ONE.shl(bound)))
        );

        // Excessively large bound; exponentation should cap at 64
        let exp = U64::random(&mut OsCsRng);
        let bound = 73;
        assert_eq!(
            form.nupow_bounded_with_base(base, &exp, bound),
            form.nupow_bounded(&exp, bound)
                .nucomp(base.nupow(&U128::ONE.shl(U64::BITS)))
        );
    }

    #[test]
    fn test_nupow_randomized() {
        let form = get_deterministic_secp256k1_form();
        let exp = U64::random(&mut OsCsRng);
        assert_eq!(form.nupow_randomized(&exp), form.nupow_vartime(&exp));
    }

    #[test]
    fn test_nupow_bounded_randomized() {
        let form = get_deterministic_secp256k1_form();

        // Small bound
        let exp = U64::random(&mut OsCsRng);
        let bound = 35;
        assert_eq!(
            form.nupow_bounded_vartime(&exp, bound),
            form.nupow_bounded_randomized(&exp, bound)
        );

        // Excessively large bound; exponentation should cap at 64
        let exp = U64::random(&mut OsCsRng);
        let bound = 73;
        assert_eq!(
            form.nupow_bounded_vartime(&exp, bound),
            form.nupow_bounded(&exp, bound)
        );
    }

    #[test]
    fn test_nupow_bounded_with_base_vartime() {
        let form = get_deterministic_secp256k1_form();
        let base = form.nupow_vartime(&U64::from(5u64));

        // Small bound
        let exp = U64::random(&mut OsCsRng);
        let bound = 35;
        assert_eq!(
            form.nupow_bounded_with_base_vartime_ibqf_and_exponent(base, &exp, bound),
            form.nupow_bounded_vartime(&exp, bound)
                .nucomp(base.nupow_vartime(&U64::ONE.shl(bound)))
        );

        // Excessively large bound; exponentation should cap at 64
        let exp = U64::random(&mut OsCsRng);
        let bound = 73;
        assert_eq!(
            form.nupow_bounded_with_base_vartime_ibqf_and_exponent(base, &exp, bound),
            form.nupow_bounded_vartime(&exp, bound)
                .nucomp(base.nupow_vartime(&U128::ONE.shl(U64::BITS)))
        );
    }

    #[test]
    fn test_nupow_with_complement_vartime() {
        let form = get_deterministic_secp256k1_form();

        // base case
        let exp = U64::from_be_hex("3097DF498543FF73");
        let target = form.nupow_vartime(&exp);
        let res = form.nupow_with_complement_vartime_ibqf(&exp, &form.unit());
        assert_eq!(res, target);

        // advanced case
        let complement = exp.not();
        let base = form.nupow_vartime(&U64::from(1273u64));
        let unit = form.nupow_vartime(&U64::from(55u64));

        let base_exp = base.nupow_vartime(&exp);
        let unit_compl = unit.nupow_vartime(&complement);
        let target = base_exp.nucomp(unit_compl);

        let res = base.nupow_with_complement_vartime_ibqf(&exp, &unit);
        assert_eq!(res, target);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::measurement::WallTime;
    use criterion::BenchmarkGroup;
    use crypto_bigint::{Concat, Encoding, Int, Random, Split, Uint, U1024, U2048, U256, U512};

    use group::OsCsRng;

    use crate::EquivalenceClass;

    pub(crate) fn benchmark_nupow<const HALF: usize, const LIMBS: usize, const DOUBLE: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        form: EquivalenceClass<LIMBS>,
    ) where
        Int<LIMBS>: Encoding,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        let mut form = *form.representative();

        let exp = U256::random(&mut OsCsRng);
        g.bench_function("nupow U256 (ct)", |b| b.iter(|| form = form.nupow(&exp)));
        g.bench_function("nupow U256 (rt)", |b| {
            b.iter(|| form = form.nupow_randomized(&exp))
        });
        g.bench_function("nupow U256 (vt)", |b| {
            b.iter(|| form = form.nupow_vartime(&exp))
        });

        let exp = U512::random(&mut OsCsRng);
        g.bench_function("nupow U512 (ct)", |b| b.iter(|| form = form.nupow(&exp)));
        g.bench_function("nupow U512 (rt)", |b| {
            b.iter(|| form = form.nupow_randomized(&exp))
        });
        g.bench_function("nupow U512 (vt)", |b| {
            b.iter(|| form = form.nupow_vartime(&exp))
        });

        let exp = U1024::random(&mut OsCsRng);
        g.bench_function("nupow U1024 (ct)", |b| b.iter(|| form = form.nupow(&exp)));
        g.bench_function("nupow U1024 (rt)", |b| {
            b.iter(|| form = form.nupow_randomized(&exp))
        });
        g.bench_function("nupow U1024 (vt)", |b| {
            b.iter(|| form = form.nupow_vartime(&exp))
        });

        let exp = U2048::random(&mut OsCsRng);
        g.bench_function("nupow U2048 (ct)", |b| b.iter(|| form = form.nupow(&exp)));
        g.bench_function("nupow U2048 (rt)", |b| {
            b.iter(|| form = form.nupow_randomized(&exp))
        });
        g.bench_function("nupow U2048 (vt)", |b| {
            b.iter(|| form = form.nupow_vartime(&exp))
        });
    }
}
