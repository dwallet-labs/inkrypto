// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{Int, NonZero, Uint, U256};
use p256::elliptic_curve::ff::BatchInvert;
use p256::elliptic_curve::{scalar::FromUintUnchecked, Field};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::{
    secp256r1::ORDER, BoundedGroupElement, CsRng, CyclicGroupElement, GroupElement as _, Invert,
    KnownOrderGroupElement, KnownOrderScalar, MulByGenerator, PrimeGroupElement, Reduce, Samplable,
    Scale, Transcribeable,
};

use super::{GroupElement, SCALAR_LIMBS};

/// A Scalar of the prime field $\mathbb{Z}_p$ over which the secp256r1 prime group is
/// defined.
#[derive(PartialEq, PartialOrd, Eq, Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Scalar(pub(super) p256::Scalar);

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(p256::Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl Samplable for Scalar {
    fn sample(
        _public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        Ok(Self(p256::Scalar::random(rng)))
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        Self::sample(public_parameters, rng)
    }
}

/// The public parameters of the secp256r1 scalar field.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    order: U256,
    generator: Scalar,
}

impl Transcribeable for PublicParameters {
    type CanonicalRepresentation = Self;
}

impl Default for PublicParameters {
    fn default() -> Self {
        PublicParameters {
            name: "The finite field of integers modulo prime q $\\mathbb{Z}_q$".to_string(),
            order: ORDER,
            generator: Scalar(p256::Scalar::ONE),
        }
    }
}

impl crate::GroupElement for Scalar {
    type Value = Self;

    fn value(&self) -> Self::Value {
        *self
    }

    type PublicParameters = PublicParameters;

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        // Since `p256::Scalar` assures deserialized values are valid, this is always safe.
        Ok(value)
    }

    fn neutral(&self) -> Self {
        Self(p256::Scalar::ZERO)
    }

    fn neutral_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self(p256::Scalar::ZERO))
    }

    fn scale<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self * Self::from(scalar)
    }

    fn scale_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_bounded(self, scalar, scalar_bits, true, public_parameters)
    }

    fn scale_bounded_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_bounded(self, scalar, scalar_bits, false, public_parameters)
    }

    fn scale_integer_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_integer<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded(integer, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded_vartime(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn scale_integer_vartime<const LIMBS: usize>(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded_vartime(scalar, scalar.abs().bits_vartime(), public_parameters)
    }

    fn scale_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn scale_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_integer_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_public_base_bounded(integer, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_public_base_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_randomized<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_randomized_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_randomized_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_integer_randomized<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_bounded(integer, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_randomized_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_randomized_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_integer_randomized_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_public_base_bounded(
            integer,
            Uint::<LIMBS>::BITS,
            public_parameters,
        )
    }

    fn scale_integer_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
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

    fn scale_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
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

    fn double(&self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(<p256::Scalar as Field>::double(&self.0))
    }

    fn double_vartime(&self, _public_parameters: &Self::PublicParameters) -> Self {
        self.double(_public_parameters)
    }

    fn add_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self + *other
    }

    fn sub_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self - *other
    }

    fn neg_constant_time(&self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0.neg())
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

impl From<Scalar> for PublicParameters {
    fn from(_value: Scalar) -> Self {
        Self::default()
    }
}

impl BoundedGroupElement<SCALAR_LIMBS> for Scalar {
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<SCALAR_LIMBS> {
        Self::order_from_public_parameters(public_parameters)
    }
}

impl<const LIMBS: usize> From<Uint<LIMBS>> for Scalar {
    fn from(value: Uint<LIMBS>) -> Self {
        let value = if LIMBS < SCALAR_LIMBS {
            (&value).into()
        } else {
            value.reduce(&NonZero::new(ORDER).unwrap())
        };

        Self(p256::Scalar::from_uint_unchecked(value))
    }
}

impl<const LIMBS: usize> From<&Uint<LIMBS>> for Scalar {
    fn from(value: &Uint<LIMBS>) -> Self {
        Self::from(*value)
    }
}

impl From<Scalar> for U256 {
    fn from(value: Scalar) -> Self {
        value.0.into()
    }
}

impl From<&Scalar> for U256 {
    fn from(value: &Scalar) -> Self {
        value.0.into()
    }
}

impl From<Scalar> for p256::Scalar {
    fn from(value: Scalar) -> Self {
        value.0
    }
}

impl From<p256::Scalar> for Scalar {
    fn from(value: p256::Scalar) -> Self {
        // Since `p256::Scalar` assures deserialized values are valid, this is always safe.
        Self(value)
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Add<Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'r> Add<&'r Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl Sub<Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'r> Sub<&'r Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl AddAssign<Self> for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<'r> AddAssign<&'r Self> for Scalar {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(&rhs.0)
    }
}

impl SubAssign<Self> for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<'r> SubAssign<&'r Self> for Scalar {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(&rhs.0)
    }
}

impl Mul<Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'r> Mul<&'r Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Mul<Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0.mul(&rhs.0))
    }
}

impl<'r> Mul<&'r Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: &'r Scalar) -> Self::Output {
        Scalar(self.0.mul(&rhs.0))
    }
}

impl Mul<GroupElement> for Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl<'r> Mul<&'r GroupElement> for Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: &'r GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl Mul<GroupElement> for &Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl<'r> Mul<&'r GroupElement> for &'r Scalar {
    type Output = GroupElement;

    fn mul(self, rhs: &'r GroupElement) -> Self::Output {
        GroupElement(rhs.0.mul(self.0))
    }
}

impl MulByGenerator<U256> for Scalar {
    fn mul_by_generator(&self, scalar: U256) -> Self {
        // In the additive scalar group, our generator is 1 and multiplying a group element by it
        // results in that same element. However, a `U256` might be bigger than the field
        // order, so we must first reduce it by the modulus to get a valid element.
        Self(p256::Scalar::from_uint_unchecked(
            scalar.reduce(&NonZero::new(ORDER).unwrap()),
        ))
    }
}

impl<'r> MulByGenerator<&'r U256> for Scalar {
    fn mul_by_generator(&self, scalar: &'r U256) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl CyclicGroupElement for Scalar {
    fn generator(&self) -> Self {
        Scalar(p256::Scalar::ONE)
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Scalar(p256::Scalar::ONE)
    }
}

impl Invert for Scalar {
    fn invert(&self) -> CtOption<Self> {
        <p256::Scalar as p256::elliptic_curve::ops::Invert>::invert(&self.0).map(Self)
    }

    fn batch_invert(elements: &mut [Self]) {
        let mut inner: Vec<p256::Scalar> = elements.iter().map(|s| s.0).collect();
        let _product = BatchInvert::batch_invert(inner.iter_mut());
        for (element, inverted) in elements.iter_mut().zip(inner) {
            *element = Self(inverted);
        }
    }
}

impl Reduce<SCALAR_LIMBS> for Scalar {
    fn reduce(&self, modulus: &NonZero<Uint<SCALAR_LIMBS>>) -> Uint<SCALAR_LIMBS> {
        Uint::from(self).reduce(modulus)
    }
}

impl KnownOrderScalar<SCALAR_LIMBS> for Scalar {}

impl KnownOrderGroupElement<SCALAR_LIMBS> for Scalar {
    type Scalar = Self;

    fn order_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        ORDER
    }
}

impl MulByGenerator<Scalar> for Scalar {
    fn mul_by_generator(&self, scalar: Scalar) -> Self {
        // In the additive scalar group, our generator is 1 and multiplying a group element by it
        // results in that same element.
        scalar
    }
}

impl<'r> MulByGenerator<&'r Scalar> for Scalar {
    fn mul_by_generator(&self, scalar: &'r Scalar) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl Scale<Self> for Scalar {
    fn scale_by(&self, scalar: &Self, public_parameters: &Self::PublicParameters) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale(&scalar_uint, public_parameters)
    }

    fn scale_vartime_by(&self, scalar: &Self, public_parameters: &Self::PublicParameters) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_vartime(&scalar_uint, public_parameters)
    }

    fn scale_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_bounded(&scalar_uint, scalar_bits, public_parameters)
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_bounded_vartime(&scalar_uint, scalar_bits, public_parameters)
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_vartime_scalar(&scalar_uint, public_parameters)
    }

    fn scale_public_base_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_public_base(&scalar_uint, public_parameters)
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_public_base_bounded(&scalar_uint, scalar_bits, public_parameters)
    }

    fn scale_randomized_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_randomized(&scalar_uint, public_parameters)
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_randomized_bounded(&scalar_uint, scalar_bits, public_parameters)
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_randomized_vartime_scalar(&scalar_uint, public_parameters)
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_randomized_public_base(&scalar_uint, public_parameters)
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_uint = U256::from(*scalar);
        self.scale_randomized_public_base_bounded(&scalar_uint, scalar_bits, public_parameters)
    }
}

impl PrimeGroupElement<SCALAR_LIMBS> for Scalar {}
