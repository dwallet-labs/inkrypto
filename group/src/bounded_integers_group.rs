// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, BitAnd, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Int, NonZero, RandomMod, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::bounded_natural_numbers_group::{
    MAURER_PROOFS_DIFF_UPPER_BOUND_BITS, MAURER_RANDOMIZER_DIFF_BITS,
};
use crate::linear_combination::linearly_combine_bounded_or_scale;
use crate::{
    BoundedGroupElement, CyclicGroupElement, Error, GroupElement as _, LinearlyCombinable,
    MulByGenerator, Result, Samplable,
};

/// An element of the additive group of integers for a power-of-two modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<const LIMBS: usize> {
    value: Int<LIMBS>,
    // The number of bits to sample
    pub sample_bits: u32,
    // The number of bits that should never be overflown, used for computations like `scale_bounded`.
    pub upper_bound_bits: u32,
}

/// The public parameters of the additive group of integers modulo `n = 2^order_bits`
/// $\mathbb{Z}_n^+$.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
{
    order_bits: u32,
    // The number of bits to sample
    pub sample_bits: u32,
    // The number of bits that should never be overflown, used for computations like `scale_bounded`.
    pub upper_bound_bits: u32,
}

impl<const LIMBS: usize> PublicParameters<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    pub fn new(sample_bits: u32, upper_bound_bits: u32) -> Result<Self> {
        let order_bits = Int::<LIMBS>::BITS;

        if order_bits <= sample_bits
            || order_bits <= upper_bound_bits
            || upper_bound_bits <= sample_bits
        {
            return Err(Error::InvalidPublicParameters);
        }

        Ok(Self {
            order_bits,
            sample_bits,
            upper_bound_bits,
        })
    }

    pub fn new_with_randomizer_upper_bound(sample_bits: u32) -> Result<Self> {
        let upper_bound_bits = sample_bits
            .checked_add(MAURER_PROOFS_DIFF_UPPER_BOUND_BITS)
            .ok_or(Error::InvalidPublicParameters)?;

        Self::new(sample_bits, upper_bound_bits)
    }
}

impl<const LIMBS: usize> Samplable for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        let upper_bound =
            NonZero::new(Uint::<LIMBS>::ONE << public_parameters.sample_bits).unwrap();

        loop {
            if let Some(value) = Uint::<LIMBS>::random_mod(rng, &upper_bound).to_int().into() {
                return Ok(Self {
                    value,
                    sample_bits: public_parameters.sample_bits,
                    upper_bound_bits: public_parameters.upper_bound_bits,
                });
            }
        }
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        let randomizer_bits = public_parameters
            .sample_bits
            .checked_add(MAURER_RANDOMIZER_DIFF_BITS)
            .ok_or(Error::InvalidPublicParameters)?;

        if public_parameters.upper_bound_bits <= randomizer_bits {
            return Err(Error::InvalidPublicParameters);
        }

        let upper_bound = NonZero::new(Uint::<LIMBS>::ONE << randomizer_bits).unwrap();

        loop {
            if let Some(value) = Uint::<LIMBS>::random_mod(rng, &upper_bound).to_int().into() {
                return Ok(Self {
                    value,
                    sample_bits: public_parameters.sample_bits,
                    upper_bound_bits: public_parameters.upper_bound_bits,
                });
            }
        }
    }
}

impl<const LIMBS: usize> LinearlyCombinable for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self> {
        linearly_combine_bounded_or_scale(bases_and_multiplicands, exponent_bits, true)
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> Result<Self> {
        linearly_combine_bounded_or_scale(bases_and_multiplicands, exponent_bits, false)
    }
}

impl<const LIMBS: usize> crate::GroupElement for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Value = Int<LIMBS>;
    type PublicParameters = PublicParameters<LIMBS>;

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        Ok(Self {
            value,
            sample_bits: public_parameters.sample_bits,
            upper_bound_bits: public_parameters.upper_bound_bits,
        })
    }

    fn neutral(&self) -> Self {
        Self {
            value: Int::<LIMBS>::ZERO,
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self {
            value: Int::<LIMBS>::ZERO,
            sample_bits: public_parameters.sample_bits,
            upper_bound_bits: public_parameters.upper_bound_bits,
        })
    }

    fn scale<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        Self {
            value: self.value.mul(scalar),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }

    fn scale_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        crate::scale_bounded(self, scalar, scalar_bits)
    }

    fn double(&self) -> Self {
        Self {
            value: self.value + self.value,
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for PublicParameters<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        // Safe to `unwrap` here, as `value` was constructed after `new()` succeeded for the same values.
        PublicParameters::new(value.sample_bits, value.upper_bound_bits).unwrap()
    }
}

impl<const LIMBS: usize> Neg for GroupElement<LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            value: self.value.checked_neg().unwrap_or(Int::ZERO),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> Add<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value.add(rhs.value),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<'r, const LIMBS: usize> Add<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self {
            value: self.value.add(rhs.value),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> Sub<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value.sub(rhs.value),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<'r, const LIMBS: usize> Sub<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self {
            value: self.value.sub(rhs.value),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> AddAssign<Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        self.value.add_assign(rhs.value)
    }
}

impl<'r, const LIMBS: usize> AddAssign<&'r Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.value.add_assign(rhs.value)
    }
}

impl<const LIMBS: usize> SubAssign<Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: Self) {
        self.value = self.value - rhs.value
    }
}

impl<'r, const LIMBS: usize> SubAssign<&'r Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.value = self.value - rhs.value
    }
}

impl<const LIMBS: usize> MulByGenerator<Int<LIMBS>> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Int<LIMBS>) -> Self {
        self.mul_by_generator(&scalar)
    }
}

impl<const LIMBS: usize> MulByGenerator<&Int<LIMBS>> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: &Int<LIMBS>) -> Self {
        // In the additive group, the generator is 1 and multiplication by it is simply returning
        // the same number modulu the order.
        Self {
            value: *scalar,
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<'r, const LIMBS: usize> Mul<Self> for &'r GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Self) -> Self::Output {
        GroupElement::<LIMBS> {
            value: self.value.mul(rhs.value),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<'r, const LIMBS: usize> Mul<&'r Self> for &'r GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        GroupElement::<LIMBS> {
            value: self.value.mul(rhs.value),
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<Int<RHS_LIMBS>> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
    Int<RHS_LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: Int<RHS_LIMBS>) -> Self::Output {
        self.scale_integer(&rhs)
    }
}

impl<'r, const LIMBS: usize, const RHS_LIMBS: usize> Mul<&'r Int<RHS_LIMBS>> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
    Int<RHS_LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: &'r Int<RHS_LIMBS>) -> Self::Output {
        self.scale_integer(rhs)
    }
}

impl<'r, const LIMBS: usize, const RHS_LIMBS: usize> Mul<Int<RHS_LIMBS>> for &'r GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
    Int<RHS_LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Int<RHS_LIMBS>) -> Self::Output {
        self.scale_integer(&rhs)
    }
}

impl<'r, const LIMBS: usize, const RHS_LIMBS: usize> Mul<&'r Int<RHS_LIMBS>>
    for &'r GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
    Int<RHS_LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &'r Int<RHS_LIMBS>) -> Self::Output {
        self.scale_integer(rhs)
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for Int<LIMBS> {
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.value
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for Int<LIMBS> {
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.value
    }
}

impl<const LIMBS: usize> ConstantTimeEq for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value
            .ct_eq(&other.value)
            .bitand(self.sample_bits.ct_eq(&other.sample_bits))
            .bitand(self.upper_bound_bits.ct_eq(&other.upper_bound_bits))
    }
}

impl<const LIMBS: usize> ConditionallySelectable for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            value: <Int<LIMBS> as ConditionallySelectable>::conditional_select(
                &a.value, &b.value, choice,
            ),
            sample_bits: <u32 as ConditionallySelectable>::conditional_select(
                &a.sample_bits,
                &b.sample_bits,
                choice,
            ),
            upper_bound_bits: <u32 as ConditionallySelectable>::conditional_select(
                &a.upper_bound_bits,
                &b.upper_bound_bits,
                choice,
            ),
        }
    }
}

impl<const LIMBS: usize> CyclicGroupElement for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn generator(&self) -> Self {
        Self {
            value: Int::<LIMBS>::ONE,
            sample_bits: self.sample_bits,
            upper_bound_bits: self.upper_bound_bits,
        }
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Int::<LIMBS>::ONE
    }
}

impl<const LIMBS: usize, T: crate::GroupElement> Mul<T> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Output = T;

    fn mul(self, rhs: T) -> Self::Output {
        rhs.scale_integer_bounded(&self.value, self.upper_bound_bits)
    }
}

impl<const LIMBS: usize> BoundedGroupElement<LIMBS> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn lower_bound(_public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
        todo!()
    }
}
