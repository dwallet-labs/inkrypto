// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::cmp::min;
use std::ops::Not;

use crypto_bigint::subtle::{ConstantTimeGreater, CtOption};
use crypto_bigint::{Concat, Encoding, Int, RandomMod, Split, Uint};

use group::CsRng;

use crate::discriminant::Discriminant;
use crate::helpers::CtMinMax;
use crate::{EquivalenceClass, Error, RandomnessSpacePublicParameters};

/// A triple of [EquivalenceClass]es that can be used in fast constant-time scaling untrusted
/// [EquivalenceClass]es with a secret exponent, without leaking information through exponentation
/// failures.
///
/// Specifically, given secret exponent `e` whose bit size is at most `scalar_bits_bound`, this
/// object contains two random forms `m1` and `m2`, and `m3 = m2^{2^scalar_bits_bound} * m1^e`.
///
/// With this in place, one can then compute `x^e` as `m2^{2^b} * (m1*x)^e / m3`, where
/// `m2^{2^b} * (m1*x)^e` is the result of raising `m1*x` to the `e` with `m2` as the starting
/// element (rather than `unit`).
///
/// Note that this technique is only efficient whenever `e` is known in advance and/or repurposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalingRandomizer<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    pub(crate) m1: EquivalenceClass<LIMBS>,
    pub(crate) m2: EquivalenceClass<LIMBS>,
    pub(crate) m3: EquivalenceClass<LIMBS>,
    pub(crate) scalar_bits_bound: u32,
}

impl<const DISCRIMINANT_LIMBS: usize> ScalingRandomizer<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    /// Read-only access to this randomizer's discriminant.
    #[allow(dead_code)]
    pub(crate) fn discriminant(&self) -> &Discriminant<DISCRIMINANT_LIMBS> {
        self.m3.discriminant()
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize>
    ScalingRandomizer<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Construct a new masking triple `(m1, m2, m3)` where `m1` and `m2` are random forms,
    /// `m3 = m2^{2^b} * m1^exponent` with `b = exponent_bits_bound` an upper bound on the bit
    /// size of `exponent`.
    pub(crate) fn new<const EXPONENT_LIMBS: usize, const RANDOMNESS_LIMBS: usize>(
        base_class: EquivalenceClass<DISCRIMINANT_LIMBS>,
        exponent: Uint<EXPONENT_LIMBS>,
        exponent_bits_bound: u32,
        randomness_public_parameters: &RandomnessSpacePublicParameters<RANDOMNESS_LIMBS>,
        rng: &mut impl CsRng,
    ) -> Result<Self, Error>
    where
        Uint<EXPONENT_LIMBS>: Encoding,
        Uint<RANDOMNESS_LIMBS>: Encoding,
    {
        let exponent_bits_bound = min(exponent_bits_bound, Uint::<EXPONENT_LIMBS>::BITS);

        let randomness_bits = randomness_public_parameters.sample_bits;
        let m1 = random_element::<HALF, DISCRIMINANT_LIMBS, DOUBLE, RANDOMNESS_LIMBS>(
            base_class,
            randomness_bits,
            rng,
        )
        .into_option()
        .ok_or(Error::InternalError)?;
        let m2 = random_element::<HALF, DISCRIMINANT_LIMBS, DOUBLE, RANDOMNESS_LIMBS>(
            base_class,
            randomness_bits,
            rng,
        )
        .into_option()
        .ok_or(Error::InternalError)?;
        let m3 = m1
            .pow_bounded_with_base_randomized(m2, &exponent, exponent_bits_bound)
            .expect("successful; m1 and m2 have the same discriminant");

        Ok(Self {
            m1,
            m2,
            m3,
            scalar_bits_bound: exponent_bits_bound,
        })
    }

    /// Variation to [Self::new] that supports [Int] exponents.
    ///
    /// Construct a new masking triple `(m1, m2, m3)` where
    /// - `m1` and `m2` are random forms, and
    /// - `m3 = m2^{±b} * m1^exponent` with `b = 2^exponent_bits_bound` and sign `±` is the same as
    ///   identical to the sign of `exponent`.
    #[allow(dead_code)]
    pub(crate) fn new_for_int<const EXPONENT_LIMBS: usize, const RANDOMNESS_LIMBS: usize>(
        base_class: EquivalenceClass<DISCRIMINANT_LIMBS>,
        exponent: Int<EXPONENT_LIMBS>,
        exponent_bits_bound: u32,
        randomness_public_parameters: &RandomnessSpacePublicParameters<RANDOMNESS_LIMBS>,
        rng: &mut impl CsRng,
    ) -> Result<Self, Error>
    where
        Uint<EXPONENT_LIMBS>: Encoding,
        Uint<RANDOMNESS_LIMBS>: Encoding,
    {
        let exponent_bits_bound = min(exponent_bits_bound, Uint::<EXPONENT_LIMBS>::BITS);

        let randomness_bits = randomness_public_parameters.sample_bits;
        let m1 = random_element::<HALF, DISCRIMINANT_LIMBS, DOUBLE, RANDOMNESS_LIMBS>(
            base_class,
            randomness_bits,
            rng,
        )
        .into_option()
        .ok_or(Error::InternalError)?;
        let m2 = random_element::<HALF, DISCRIMINANT_LIMBS, DOUBLE, RANDOMNESS_LIMBS>(
            base_class,
            randomness_bits,
            rng,
        )
        .into_option()
        .ok_or(Error::InternalError)?;
        let m3 = m1
            .pow_bounded_int_randomized_with_base(m2, &exponent, exponent_bits_bound)
            .expect("successful; m1 and m2 have the same discriminant");

        Ok(Self {
            m1,
            m2,
            m3,
            scalar_bits_bound: exponent_bits_bound,
        })
    }
}

/// A tuple of [EquivalenceClass]es that can be used in fast constant-time scaling trusted
/// [EquivalenceClass]es with a secret exponent, without leaking information through exponentation
/// failures.
///
/// Specifically, given secret exponent `e` whose bit size is at most `scalar_bits_bound`, this
/// object contains a base form `m1` and `m2 = m1^{2^scalar_bits_bound}`.
///
/// With this in place, one can then compute `x^e` as `m1^{2^b} * x^e / m2`, where
/// `m1^{2^b} * x^e` is the result of raising `x` to the `e` with `m1` as the starting element
/// (rather than `unit`).
///
/// Note that this technique is only efficient whenever `scalar_bits_bound` is known in advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalingBase<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    pub(crate) m1: EquivalenceClass<LIMBS>,
    pub(crate) m2: EquivalenceClass<LIMBS>,
    pub(crate) scalar_bits_bound: u32,
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > ScalingBase<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Construct a new [ScalingBase].
    ///
    /// Executes in variable time w.r.t. `base` and `exponent_bit_size`.
    #[allow(dead_code)]
    pub(crate) fn new_vartime(
        base: EquivalenceClass<DISCRIMINANT_LIMBS>,
        exponent_bit_size: u32,
    ) -> Self {
        Self {
            m1: base,
            m2: base.pow_2k_vartime(exponent_bit_size),
            scalar_bits_bound: exponent_bit_size,
        }
    }
}

/// A tuple of [EquivalenceClass]es that can be used in fast constant-time scaling trusted
/// [EquivalenceClass]es with a secret exponent, without leaking information through exponentation
/// failures.
///
/// `m1` and `m2` are random elements, `m3 = m1^{2^exponent_bits-1} * m2^exponent`
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct ExponentWithFormMask<const DISCRIMINANT_LIMBS: usize, const EXPONENT_LIMBS: usize>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    pub(crate) m1: EquivalenceClass<DISCRIMINANT_LIMBS>,
    pub(crate) m2: EquivalenceClass<DISCRIMINANT_LIMBS>,
    pub(crate) m3: EquivalenceClass<DISCRIMINANT_LIMBS>,
    pub(crate) exponent: Uint<EXPONENT_LIMBS>,
    pub(crate) exponent_bits: u32,
}

impl<const DISCRIMINANT_LIMBS: usize, const EXPONENT_LIMBS: usize>
    ExponentWithFormMask<DISCRIMINANT_LIMBS, EXPONENT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    /// Read-only access to this randomizer's discriminant.
    #[allow(dead_code)]
    pub(crate) fn discriminant(&self) -> &Discriminant<DISCRIMINANT_LIMBS> {
        self.m3.discriminant()
    }
}

impl<
        const HALF: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE: usize,
        const EXPONENT_LIMBS: usize,
    > ExponentWithFormMask<DISCRIMINANT_LIMBS, EXPONENT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    #[allow(dead_code)]
    pub(crate) fn new<const RANDOMNESS_LIMBS: usize>(
        randomization_base: EquivalenceClass<DISCRIMINANT_LIMBS>,
        randomness_bits: u32,
        exponent: Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<Self, Error> {
        let exponent_bits = u32::ct_min(&exponent_bits, &Uint::<EXPONENT_LIMBS>::BITS);

        let m1 = random_element::<HALF, DISCRIMINANT_LIMBS, DOUBLE, RANDOMNESS_LIMBS>(
            randomization_base,
            randomness_bits,
            rng,
        )
        .into_option()
        .ok_or(Error::InternalError)?;
        let m2 = random_element::<HALF, DISCRIMINANT_LIMBS, DOUBLE, RANDOMNESS_LIMBS>(
            randomization_base,
            randomness_bits,
            rng,
        )
        .into_option()
        .ok_or(Error::InternalError)?;

        let m3 = m2
            .pow_bounded_with_base_randomized(m1, &exponent, exponent_bits)
            .expect("successful; m1 and m2 have the same discriminant")
            .div(&m1)
            .expect("successful; same discriminant");

        Ok(Self {
            m1,
            m2,
            m3,
            exponent,
            exponent_bits,
        })
    }
}

fn random_element<
    const HALF: usize,
    const DISCRIMINANT_LIMBS: usize,
    const DOUBLE: usize,
    const RANDOMNESS_LIMBS: usize,
>(
    base: EquivalenceClass<DISCRIMINANT_LIMBS>,
    randomness_bits: u32,
    rng: &mut impl CsRng,
) -> CtOption<EquivalenceClass<DISCRIMINANT_LIMBS>>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    let valid_bit_size = randomness_bits.ct_gt(&Uint::<RANDOMNESS_LIMBS>::BITS).not();

    let modulus = Uint::<RANDOMNESS_LIMBS>::MAX
        .shr(Uint::<RANDOMNESS_LIMBS>::BITS.saturating_sub(randomness_bits))
        .saturating_add(&Uint::ONE)
        .to_nz()
        .expect("is non-zero");
    let r = Uint::<RANDOMNESS_LIMBS>::random_mod(rng, &modulus);

    let res = base.pow_bounded(&r, randomness_bits);
    CtOption::new(res, valid_bit_size)
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use crypto_bigint::subtle::Choice;
    use crypto_bigint::{I128, U128, U2048, U256};

    use group::OsCsRng;
    use homomorphic_encryption::GroupsPublicParametersAccessors;

    use crate::randomizer::{ExponentWithFormMask, ScalingBase, ScalingRandomizer};
    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };

    #[test]
    fn test_new_decryption_mask() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let base_class = setup_parameters.h;
        let pp = setup_parameters.randomness_space_public_parameters();

        // Expected input
        let exponent = U128::from_be_hex("3131846151adeee35f1d3684116843aa");
        let bits = exponent.bits();
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new(base_class, exponent, bits, pp, &mut OsCsRng).unwrap();
        assert_eq!(scalar_bits_bound, bits);
        assert_eq!(
            m3.div_vartime(&m1.pow_vartime(&exponent)).unwrap(),
            m2.pow_vartime(&U128::ONE.shl(bits))
        );

        // Max exponent_bits_bound
        let bits = U128::BITS;
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new(base_class, exponent, bits, pp, &mut OsCsRng).unwrap();
        assert_eq!(scalar_bits_bound, bits);
        assert_eq!(
            m3.div_vartime(&m1.pow_vartime(&exponent)).unwrap(),
            m2.pow_vartime(&U256::ONE.shl(bits))
        );

        // Excessively large bits_bound; should cap `scalar_bits_bound` at 128
        let bits = U128::BITS + 10;
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new(base_class, exponent, bits, pp, &mut OsCsRng).unwrap();
        assert_eq!(scalar_bits_bound, U128::BITS);
        assert_eq!(
            m3.div_vartime(&m1.pow_vartime(&exponent)).unwrap(),
            m2.pow_vartime(&U256::ONE.shl(U128::BITS))
        );
    }

    #[test]
    fn test_scaling_randomizer_new_for_int() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let base_class = setup_parameters.h;
        let pp = setup_parameters.randomness_space_public_parameters();

        // Expected input
        let exponent = I128::from_be_hex("d131846151adeee35f1d3684116843aa");
        let bits = exponent.abs().bits();
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new_for_int(base_class, exponent, bits, pp, &mut OsCsRng).unwrap();
        assert_eq!(scalar_bits_bound, bits);

        let (abs_exp, exp_sgn) = exponent.abs_sign();
        let m1_exp = m1.pow_vartime(&abs_exp);
        let target = if bool::from(Choice::from(exp_sgn)) {
            m3.mul_vartime(&m1_exp).unwrap().neg()
        } else {
            m3.div_vartime(&m1_exp).unwrap()
        };
        assert_eq!(m2.pow_vartime(&U128::ONE.shl(bits)), target);

        // Max exponent_bits_bound
        let bits = U128::BITS;
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new_for_int(base_class, exponent, bits, pp, &mut OsCsRng).unwrap();
        assert_eq!(scalar_bits_bound, bits);

        let (abs_exp, exp_sgn) = exponent.abs_sign();
        let m1_exp = m1.pow_vartime(&abs_exp);
        let target = if bool::from(Choice::from(exp_sgn)) {
            m3.mul_vartime(&m1_exp).unwrap().neg()
        } else {
            m3.div_vartime(&m1_exp).unwrap()
        };
        assert_eq!(m2.pow_vartime(&U256::ONE.shl(bits)), target);

        // Excessively large bits_bound; should cap `scalar_bits_bound` at 128
        let bits = U128::BITS + 10;
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new_for_int(base_class, exponent, bits, pp, &mut OsCsRng).unwrap();
        assert_eq!(scalar_bits_bound, U128::BITS);

        let (abs_exp, exp_sgn) = exponent.abs_sign();
        let m1_exp = m1.pow_vartime(&abs_exp);
        let target = if bool::from(Choice::from(exp_sgn)) {
            m3.mul_vartime(&m1_exp).unwrap().neg()
        } else {
            m3.div_vartime(&m1_exp).unwrap()
        };
        assert_eq!(m2.pow_vartime(&U256::ONE.shl(U128::BITS)), target);
    }

    #[test]
    fn test_new_scaling_base() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let base = setup_parameters.h;
        let exponent_bit_size = setup_parameters
            .randomness_space_public_parameters()
            .sample_bits;

        let ScalingBase {
            m1,
            m2,
            scalar_bits_bound,
        } = ScalingBase::new_vartime(base, exponent_bit_size);
        assert_eq!(m1, base);
        assert_eq!(scalar_bits_bound, exponent_bit_size);
        assert_eq!(m2, base.pow_vartime(&U2048::ONE.shl(exponent_bit_size)));
    }

    #[test]
    fn test_new_exponent_with_mask() {
        let sp = get_setup_parameters_ristretto_112_bits_deterministic();
        let base = sp.h;
        let exp = U128::from_be_hex("90C9947BD43929034FE9106359A920F9");
        let me = ExponentWithFormMask::new::<3>(base, 73, exp, 677, &mut OsCsRng).unwrap();

        let ExponentWithFormMask {
            m1,
            m2,
            m3,
            exponent,
            exponent_bits,
        } = me;

        let m1_2k_min_1 = m1.pow_2k_vartime(exponent_bits).div(&m1).unwrap();
        let m3_div_m1_2k_min_1 = m3.div(&m1_2k_min_1).unwrap();
        let m2_exp = m2.pow_bounded_vartime(&exponent, exponent_bits);
        assert_eq!(m3_div_m1_2k_min_1, m2_exp);
    }
}
