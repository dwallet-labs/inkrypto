// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, BitAnd, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{Encoding, Int, NonZero, RandomMod, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::bounded_natural_numbers_group::{
    MAURER_PROOFS_DIFF_UPPER_BOUND_BITS, MAURER_RANDOMIZER_DIFF_BITS, MAURER_RESPONSE_DIFF_BITS,
};
use crate::linear_combination::linearly_combine_bounded_or_scale;
use crate::{
    BoundedGroupElement, CsRng, CyclicGroupElement, Error, GroupElement as _, LinearlyCombinable,
    MulByGenerator, Result, Samplable, Transcribeable,
};

/// An element of the additive group of integers for a power-of-two modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<const LIMBS: usize> {
    value: Int<LIMBS>,
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

impl<const LIMBS: usize> Transcribeable for PublicParameters<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type CanonicalRepresentation = Self;
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
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        let upper_bound =
            NonZero::new(Uint::<LIMBS>::ONE << public_parameters.sample_bits).unwrap();

        loop {
            if let Some(value) = Uint::<LIMBS>::random_mod(rng, &upper_bound)
                .try_into_int()
                .into()
            {
                return Ok(Self {
                    value,
                    upper_bound_bits: public_parameters.upper_bound_bits,
                });
            }
        }
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
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
            if let Some(value) = Uint::<LIMBS>::random_mod(rng, &upper_bound)
                .try_into_int()
                .into()
            {
                return Ok(Self {
                    value,
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
        // Make sure that the value is lesser or equal than a Maurer response.
        // This ensures that no overflow will ever occur in the group operations
        // (which will panic if it does occur in the case of a bug) as Maurer batch verification is
        // the largest supported sequence of group operations with this type.
        let response_upper_bound = public_parameters.sample_bits + MAURER_RESPONSE_DIFF_BITS;
        if value.abs().bits() > response_upper_bound {
            return Err(Error::InvalidGroupElement);
        }

        Ok(Self {
            value,
            upper_bound_bits: public_parameters.upper_bound_bits,
        })
    }

    fn neutral(&self) -> Self {
        Self {
            value: Int::<LIMBS>::ZERO,
            upper_bound_bits: self.upper_bound_bits,
        }
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self {
            value: Int::<LIMBS>::ZERO,
            upper_bound_bits: public_parameters.upper_bound_bits,
        })
    }

    fn scale<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        let value = self.value.mul(scalar);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        Self {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }

    fn scale_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        assert!(scalar.bits() <= scalar_bits);

        crate::scale_bounded(self, scalar, scalar_bits)
    }

    fn scale_bounded_vartime<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits)
    }

    fn add_randomized(self, other: &Self) -> Self {
        self + other
    }

    fn add_vartime(self, other: &Self) -> Self {
        self + other
    }

    fn sub_randomized(self, other: &Self) -> Self {
        self - other
    }

    fn sub_vartime(self, other: &Self) -> Self {
        self - other
    }

    fn double(&self) -> Self {
        let value = self.value + self.value;
        assert!(value.abs().bits() <= self.upper_bound_bits);

        Self {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }

    fn double_vartime(&self) -> Self {
        self.double()
    }
}

impl<const LIMBS: usize> Neg for GroupElement<LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let value = self.value.checked_neg().unwrap_or(Int::ZERO);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        Self {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> Add<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let value = self.value.add(rhs.value);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        Self {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<'r, const LIMBS: usize> Add<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        let value = self.value.add(rhs.value);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        Self {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> Sub<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let value = self.value.sub(rhs.value);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        Self {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<'r, const LIMBS: usize> Sub<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        let value = self.value.sub(rhs.value);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        Self {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> AddAssign<Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        self.value.add_assign(rhs.value);

        assert!(self.value.abs().bits() <= self.upper_bound_bits);
    }
}

impl<'r, const LIMBS: usize> AddAssign<&'r Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.value.add_assign(rhs.value);

        assert!(self.value.abs().bits() <= self.upper_bound_bits);
    }
}

impl<const LIMBS: usize> SubAssign<Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: Self) {
        self.value = self.value - rhs.value;

        assert!(self.value.abs().bits() <= self.upper_bound_bits);
    }
}

impl<'r, const LIMBS: usize> SubAssign<&'r Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.value = self.value - rhs.value;

        assert!(self.value.abs().bits() <= self.upper_bound_bits);
    }
}

impl<const LIMBS: usize> MulByGenerator<Int<LIMBS>> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Int<LIMBS>) -> Self {
        let res = self.mul_by_generator(&scalar);

        assert!(res.value.abs().bits() <= self.upper_bound_bits);

        res
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
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<const LIMBS: usize> Mul<Self> for &GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Self) -> Self::Output {
        let value = self.value.mul(rhs.value);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        GroupElement::<LIMBS> {
            value,
            upper_bound_bits: self.upper_bound_bits,
        }
    }
}

impl<'r, const LIMBS: usize> Mul<&'r Self> for &'r GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        let value = self.value.mul(rhs.value);
        assert!(value.abs().bits() <= self.upper_bound_bits);

        GroupElement::<LIMBS> {
            value,
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
        let res = self.scale_integer(&rhs);

        assert!(res.value.abs().bits() <= self.upper_bound_bits);

        res
    }
}

impl<'r, const LIMBS: usize, const RHS_LIMBS: usize> Mul<&'r Int<RHS_LIMBS>> for GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
    Int<RHS_LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: &'r Int<RHS_LIMBS>) -> Self::Output {
        let res = self.scale_integer(rhs);

        assert!(res.value.abs().bits() <= self.upper_bound_bits);

        res
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> Mul<Int<RHS_LIMBS>> for &GroupElement<LIMBS>
where
    Int<LIMBS>: Encoding,
    Int<RHS_LIMBS>: Encoding,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Int<RHS_LIMBS>) -> Self::Output {
        let res = self.scale_integer(&rhs);

        assert!(res.value.abs().bits() <= self.upper_bound_bits);

        res
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
        let res = self.scale_integer(rhs);

        assert!(res.value.abs().bits() <= self.upper_bound_bits);

        res
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
