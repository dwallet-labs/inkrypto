// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::cmp::min;

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{Concat, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};

use group::{GroupElement, Samplable};

use crate::{
    EquivalenceClass, Error, RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};

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
{
    pub(crate) m1: EquivalenceClass<LIMBS>,
    pub(crate) m2: EquivalenceClass<LIMBS>,
    pub(crate) m3: EquivalenceClass<LIMBS>,
    pub(crate) scalar_bits_bound: u32,
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > ScalingRandomizer<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Construct a new masking triple `(m1, m2, m3)` where `m1` and `m2` are random forms,
    /// `m3 = m2^{2^b} * m1^exponent` with `b = exponent_bits_bound` an upper bound on the bit
    /// size of `exponent`.
    pub(crate) fn new<const EXPONENT_LIMBS: usize, const RANDOMNESS_LIMBS: usize>(
        base_class: EquivalenceClass<DISCRIMINANT_LIMBS>,
        exponent: Uint<EXPONENT_LIMBS>,
        exponent_bits_bound: u32,
        randomness_public_parameters: &RandomnessSpacePublicParameters<RANDOMNESS_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error>
    where
        Uint<EXPONENT_LIMBS>: Encoding,
        Uint<RANDOMNESS_LIMBS>: Encoding,
    {
        let exponent_bits_bound = min(exponent_bits_bound, Uint::<EXPONENT_LIMBS>::BITS);

        let m1 = Self::random_class_element(base_class, randomness_public_parameters, rng)?;
        let m2 = Self::random_class_element(base_class, randomness_public_parameters, rng)?;
        let m3 = m1.pow_randomized_bounded_with_base(m2, &exponent, exponent_bits_bound)?;

        Ok(Self {
            m1,
            m2,
            m3,
            scalar_bits_bound: exponent_bits_bound,
        })
    }

    /// Generate a random element by computing `base^r` with `r` a fresh randomness sampled
    /// according to the `randomness_public_parameters`.
    fn random_class_element<const RANDOMNESS_LIMBS: usize>(
        base: EquivalenceClass<DISCRIMINANT_LIMBS>,
        randomness_public_parameters: &RandomnessSpacePublicParameters<RANDOMNESS_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<EquivalenceClass<DISCRIMINANT_LIMBS>, Error>
    where
        Uint<RANDOMNESS_LIMBS>: Encoding,
    {
        let randomness = RandomnessSpaceGroupElement::sample(randomness_public_parameters, rng)?;
        Ok(base.pow_bounded(
            &randomness.value(),
            randomness_public_parameters.sample_bits,
        ))
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
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Construct a new [ScalingBase].
    ///
    /// Executes in variable time w.r.t. `base` and `exponent_bit_size`.
    #[allow(dead_code)]
    pub(crate) fn new_vartime(
        base: EquivalenceClass<DISCRIMINANT_LIMBS>,
        exponent_bit_size: u32,
    ) -> Result<Self, Error> {
        Ok(Self {
            m1: base,
            m2: base.pow_2k_vartime(exponent_bit_size)?,
            scalar_bits_bound: exponent_bit_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use crypto_bigint::{U128, U2048, U256};
    use rand_core::OsRng;

    use homomorphic_encryption::GroupsPublicParametersAccessors;

    use crate::randomizer::{ScalingBase, ScalingRandomizer};
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;

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
        } = ScalingRandomizer::new(base_class, exponent, bits, pp, &mut OsRng).unwrap();
        assert_eq!(scalar_bits_bound, bits);
        assert_eq!(
            m3.mul_vartime(&m1.pow_vartime(&exponent).neg()).unwrap(),
            m2.pow_vartime(&U128::ONE.shl(bits))
        );

        // Max exponent_bits_bound
        let bits = U128::BITS;
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new(base_class, exponent, bits, pp, &mut OsRng).unwrap();
        assert_eq!(scalar_bits_bound, bits);
        assert_eq!(
            m3.mul_vartime(&m1.pow_vartime(&exponent).neg()).unwrap(),
            m2.pow_vartime(&U256::ONE.shl(bits))
        );

        // Excessively large bits_bound; should cap `scalar_bits_bound` at 128
        let bits = U128::BITS + 10;
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = ScalingRandomizer::new(base_class, exponent, bits, pp, &mut OsRng).unwrap();
        assert_eq!(scalar_bits_bound, U128::BITS);
        assert_eq!(
            m3.mul_vartime(&m1.pow_vartime(&exponent).neg()).unwrap(),
            m2.pow_vartime(&U256::ONE.shl(U128::BITS))
        );
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
        } = ScalingBase::new_vartime(base, exponent_bit_size).unwrap();
        assert_eq!(m1, base);
        assert_eq!(scalar_bits_bound, exponent_bit_size);
        assert_eq!(m2, base.pow_vartime(&U2048::ONE.shl(exponent_bit_size)));
    }
}
