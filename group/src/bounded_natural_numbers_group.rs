// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::{Encoding, Int, NonZero, RandomMod, Uint, U64};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::{
    const_additive, BoundedGroupElement, ComputationalSecuritySizedNumber, CsRng,
    CyclicGroupElement, Error, ErrorKind, MulByGenerator, PartyID, Result, Samplable,
    StatisticalSecuritySizedNumber, Transcribeable,
};

/// An element of the additive group of integers for a power-of-two modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GroupElement<const LIMBS: usize> {
    value: Uint<LIMBS>,
}

/// The number of bits to add when sampling a randomizer
/// on top of the sampling bits of an over-the-integers witness of a Maurer proof.
///
/// In an over-the-integers Maurer Proof the response $z = e\cdot x+r$ is sent over the integers thus $r$ must statistical hide $e\cdot x$.
/// For computational soundness $e$ must have $\kappa$ bits and as such $r$ must have $\log_{2}(x)+\kappa+\sigma$ bits to statistically hide.
pub const MAURER_RANDOMIZER_DIFF_BITS: u32 =
    StatisticalSecuritySizedNumber::BITS + ComputationalSecuritySizedNumber::BITS;

/// An upper bound of the extra bits (on top of the sampling bits)
/// for storing a Maurer response of an over-the-integers bounded group element.
///
/// When computing the response during a Maurer proof,
/// we mask the witness multiplied by the challenge for which we add `MAURER_RANDOMIZER_DELTA_BITS` bits.
/// Next we account for adding the masked witness by adding a single (`1`) bit.
/// On that we add `PartyID::BITS` to account for aggregation of responses.
pub const MAURER_RESPONSE_DIFF_BITS: u32 = MAURER_RANDOMIZER_DIFF_BITS + 1 + PartyID::BITS;

/// An upper bound of the extra bits (on top of the sampling bits)
/// for storing an over-the-integers bounded group element
/// that accounts for all computations within a Maurer proof such that no overflow occurs.
///
/// This upper bound is reached in batch verification, so we add `ComputationalSecuritySizedNumber::BITS` + `U64::BITS` to the response diff `MAURER_RESPONSE_DIFF_BITS`
/// (2^64 is the maximum vector size in Rust, and in batch verification we randomize responses by computational challenges).
pub const MAURER_PROOFS_DIFF_UPPER_BOUND_BITS: u32 = MAURER_RESPONSE_DIFF_BITS
    + ComputationalSecuritySizedNumber::BITS
    + ComputationalSecuritySizedNumber::BITS
    + U64::BITS;

/// The public parameters of the additive group of integers modulo `n = 2^order_bits`
/// $\mathbb{Z}_n^+$.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    order_bits: u32,
    // The number of bits to sample
    pub sample_bits: u32,
    // The number of bits that should never be overflown, used for computations like `scale_bounded`.
    pub upper_bound_bits: u32,
}

impl<const LIMBS: usize> Transcribeable for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type CanonicalRepresentation = Self;
}

impl<const LIMBS: usize> PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub fn new(sample_bits: u32, upper_bound_bits: u32) -> Result<Self> {
        let order_bits = Uint::<LIMBS>::BITS;

        if order_bits <= sample_bits
            || order_bits <= upper_bound_bits
            || upper_bound_bits <= sample_bits
        {
            return Err(Error::from(ErrorKind::InvalidPublicParameters));
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
            .ok_or_else(|| Error::from(ErrorKind::InvalidPublicParameters))?;

        Self::new(sample_bits, upper_bound_bits)
    }
}

impl<const LIMBS: usize> Samplable for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        let upper_bound =
            NonZero::new(Uint::<LIMBS>::ONE << public_parameters.sample_bits).unwrap();

        Ok(Self {
            value: Uint::<LIMBS>::random_mod(rng, &upper_bound),
        })
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        let randomizer_bits = public_parameters
            .sample_bits
            .checked_add(MAURER_RANDOMIZER_DIFF_BITS)
            .ok_or_else(|| Error::from(ErrorKind::InvalidPublicParameters))?;

        if public_parameters.upper_bound_bits <= randomizer_bits {
            return Err(Error::from(ErrorKind::InvalidPublicParameters));
        }

        let upper_bound = NonZero::new(Uint::<LIMBS>::ONE << randomizer_bits).unwrap();

        Ok(Self {
            value: Uint::<LIMBS>::random_mod(rng, &upper_bound),
        })
    }
}

impl<const LIMBS: usize> crate::GroupElement for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Uint<LIMBS>;
    type PublicParameters = PublicParameters<LIMBS>;

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        // Make sure that the value is lesser or equal than a Maurer response.
        // This ensures that no overflow will ever occur in the group operations
        // (which will panic if it does occur in the case of a bug) as Maurer batch verification is
        // the largest supported sequence of group operations with this type.
        let response_upper_bound = public_parameters.sample_bits + MAURER_RESPONSE_DIFF_BITS;
        if value.bits() > response_upper_bound {
            return Err(Error::from(ErrorKind::InvalidGroupElement));
        }

        Ok(Self { value })
    }

    fn neutral(&self) -> Self {
        Self {
            value: Uint::<LIMBS>::ZERO,
        }
    }

    fn neutral_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self {
            value: Uint::<LIMBS>::ZERO,
        })
    }

    fn add_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        let result = *self + *other;
        assert!(result.value.bits() <= public_parameters.upper_bound_bits);
        result
    }

    fn sub_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        let result = *self - *other;
        assert!(result.value.bits() <= public_parameters.upper_bound_bits);
        result
    }

    fn neg_constant_time(&self, _public_parameters: &Self::PublicParameters) -> Self {
        (*self).neg()
    }

    fn scale<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let value = self.value * scalar;
        assert!(value.bits() <= public_parameters.upper_bound_bits);

        Self { value }
    }

    fn scale_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let result = crate::scale_bounded(self, scalar, scalar_bits, true, public_parameters);
        debug_assert!(result.value.bits() <= public_parameters.upper_bound_bits);
        result
    }

    fn scale_bounded_vartime<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_bounded(self, scalar, scalar_bits, false, public_parameters)
    }

    fn scale_integer_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let result = crate::scale_integer_bounded(self, integer, scalar_bits, public_parameters);
        debug_assert!(result.value.bits() <= public_parameters.upper_bound_bits);
        result
    }

    fn scale_integer<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded(integer, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_vartime<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded_vartime(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn scale_integer_vartime<const RHS_LIMBS: usize>(
        &self,
        scalar: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded_vartime(scalar, scalar.abs().bits_vartime(), public_parameters)
    }

    fn scale_vartime_scalar<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn scale_public_base<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_integer_public_base<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_public_base_bounded(integer, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_public_base_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_randomized<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_randomized_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_randomized_public_base<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_randomized_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_integer_randomized<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_bounded(integer, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_randomized_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_randomized_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_integer_randomized_public_base<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_public_base_bounded(
            integer,
            Uint::<RHS_LIMBS>::BITS,
            public_parameters,
        )
    }

    fn scale_integer_randomized_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_randomized_public_base_bounded(
            self,
            integer,
            scalar_bits,
            public_parameters,
        )
    }

    fn scale_randomized_vartime_scalar<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn add_randomized(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self + other
    }

    fn add_vartime(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self + other
    }

    fn sub_randomized(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self - other
    }

    fn sub_vartime(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self - other
    }

    fn double(&self, public_parameters: &Self::PublicParameters) -> Self {
        let value = self.value + self.value;
        assert!(value.bits() <= public_parameters.upper_bound_bits);

        Self { value }
    }

    fn double_vartime(&self, _public_parameters: &Self::PublicParameters) -> Self {
        self.double(_public_parameters)
    }

    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        crate::linear_combination::linearly_combine_bounded_or_scale(
            bases_and_multiplicands,
            exponent_bits,
            true,
            public_parameters,
        )
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        crate::linear_combination::linearly_combine_bounded_or_scale(
            bases_and_multiplicands,
            exponent_bits,
            false,
            public_parameters,
        )
    }
}

impl<const LIMBS: usize> Neg for GroupElement<LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<const LIMBS: usize> Add<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let value = self.value.add(rhs.value);

        Self { value }
    }
}

impl<'r, const LIMBS: usize> Add<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        let value = self.value.add(rhs.value);

        Self { value }
    }
}

impl<const LIMBS: usize> Sub<Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let value = self.value.sub(rhs.value);

        Self { value }
    }
}

impl<'r, const LIMBS: usize> Sub<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        let value = self.value.sub(rhs.value);

        Self { value }
    }
}

impl<const LIMBS: usize> AddAssign<Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        self.value.add_assign(rhs.value);
    }
}

impl<'r, const LIMBS: usize> AddAssign<&'r Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.value.add_assign(rhs.value);
    }
}

impl<const LIMBS: usize> SubAssign<Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: Self) {
        self.value = self.value - rhs.value;
    }
}

impl<'r, const LIMBS: usize> SubAssign<&'r Self> for GroupElement<LIMBS> {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.value = self.value - rhs.value;
    }
}

impl<const LIMBS: usize> MulByGenerator<Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Uint<LIMBS>) -> Self {
        self.mul_by_generator(&scalar)
    }
}

impl<const LIMBS: usize> MulByGenerator<&Uint<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: &Uint<LIMBS>) -> Self {
        // In the additive group, the generator is 1 and multiplication by it is simply returning
        // the same number modulu the order.
        Self { value: *scalar }
    }
}

impl<const LIMBS: usize> Mul<Self> for &GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Self) -> Self::Output {
        let value = self.value.mul(rhs.value);
        GroupElement::<LIMBS> { value }
    }
}

impl<'r, const LIMBS: usize> Mul<&'r Self> for &'r GroupElement<LIMBS> {
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        let value = self.value.mul(rhs.value);
        GroupElement::<LIMBS> { value }
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.value
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.value
    }
}

impl<MOD: ConstMontyParams<RHS_LIMBS>, const LIMBS: usize, const RHS_LIMBS: usize>
    From<GroupElement<LIMBS>> for const_additive::GroupElement<MOD, RHS_LIMBS>
where
    Uint<RHS_LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        Self::from(Uint::<LIMBS>::from(value))
    }
}

impl<'r, MOD: ConstMontyParams<RHS_LIMBS>, const LIMBS: usize, const RHS_LIMBS: usize>
    From<&'r GroupElement<LIMBS>> for const_additive::GroupElement<MOD, RHS_LIMBS>
where
    Uint<RHS_LIMBS>: Encoding,
{
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        Self::from(Uint::<LIMBS>::from(value))
    }
}

impl<const LIMBS: usize> ConstantTimeEq for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            value: <Uint<LIMBS> as ConditionallySelectable>::conditional_select(
                &a.value, &b.value, choice,
            ),
        }
    }
}

impl<const LIMBS: usize> CyclicGroupElement for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn generator(&self) -> Self {
        Self {
            value: Uint::<LIMBS>::ONE,
        }
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Uint::<LIMBS>::ONE
    }
}

impl<const LIMBS: usize> BoundedGroupElement<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn lower_bound(_public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
        todo!()
    }
}
