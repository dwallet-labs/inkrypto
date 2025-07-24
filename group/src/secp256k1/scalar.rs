// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, NonZero, Uint, U256};
use k256::elliptic_curve::{scalar::FromUintUnchecked, Field};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::linear_combination::linearly_combine_bounded_or_scale;
use crate::{
    secp256k1::ORDER, BoundedGroupElement, CyclicGroupElement, GroupElement as _, Invert,
    KnownOrderGroupElement, KnownOrderScalar, LinearlyCombinable, MulByGenerator,
    PrimeGroupElement, Reduce, Samplable, Scale,
};

use super::{GroupElement, SCALAR_LIMBS};

/// A Scalar of the prime field $\mathbb{Z}_p$ over which the secp256k1 prime group is
/// defined.
#[derive(PartialEq, PartialOrd, Eq, Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Scalar(pub(super) k256::Scalar);

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(k256::Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl Samplable for Scalar {
    fn sample(
        _public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        Ok(Self(k256::Scalar::random(rng)))
    }
}

impl LinearlyCombinable for Scalar {
    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self> {
        linearly_combine_bounded_or_scale(bases_and_multiplicands, exponent_bits, true)
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self> {
        linearly_combine_bounded_or_scale(bases_and_multiplicands, exponent_bits, false)
    }
}

/// The public parameters of the secp256k1 scalar field.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    order: U256,
    generator: Scalar,
}

impl Default for PublicParameters {
    fn default() -> Self {
        PublicParameters {
            name: "The finite field of integers modulo prime q $\\mathbb{Z}_q$".to_string(),
            order: ORDER,
            generator: Scalar(k256::Scalar::ONE),
        }
    }
}

impl crate::GroupElement for Scalar {
    type Value = Self;

    fn value(&self) -> Self::Value {
        *self
    }

    type PublicParameters = PublicParameters;

    fn public_parameters(&self) -> Self::PublicParameters {
        PublicParameters::default()
    }

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        // Since `k256::Scalar` assures deserialized values are valid, this is always safe.
        Ok(value)
    }

    fn neutral(&self) -> Self {
        Self(k256::Scalar::ZERO)
    }

    fn neutral_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self(k256::Scalar::ZERO))
    }

    fn scale<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        self * Self::from(scalar)
    }

    fn scale_bounded<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>, scalar_bits: u32) -> Self {
        crate::scale_bounded(self, scalar, scalar_bits)
    }

    fn double(&self) -> Self {
        Self(<k256::Scalar as Field>::double(&self.0))
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

        Self(k256::Scalar::from_uint_unchecked(value))
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

impl From<Scalar> for k256::Scalar {
    fn from(value: Scalar) -> Self {
        value.0
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

impl<'r> Mul<GroupElement> for &'r Scalar {
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
        Self(k256::Scalar::from_uint_unchecked(
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
        Scalar(k256::Scalar::ONE)
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Scalar(k256::Scalar::ONE)
    }
}

impl Invert for Scalar {
    fn invert(&self) -> CtOption<Self> {
        <k256::Scalar as k256::elliptic_curve::ops::Invert>::invert(&self.0).map(Self)
    }
}

impl Scale<Self> for Scalar {
    fn scale_generic(&self, scalar: &Self) -> Self {
        scalar * self
    }

    fn scale_bounded_generic(&self, scalar: &Self, scalar_bits: u32) -> Self {
        self.scale_bounded(&scalar.into(), scalar_bits)
    }

    fn scale_bounded_vartime_generic(&self, scalar: &Self, scalar_bits: u32) -> Self {
        self.scale_bounded_vartime(&scalar.into(), scalar_bits)
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
    fn order(&self) -> Uint<SCALAR_LIMBS> {
        ORDER
    }

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

impl PrimeGroupElement<SCALAR_LIMBS> for Scalar {}
