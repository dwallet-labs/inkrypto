// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

use crypto_bigint::{Int, Uint, U256};
use hash2curve::ExpandMsgXmd;
use p256::{
    elliptic_curve::{group::prime::PrimeCurveAffine, BatchNormalize as _, Group},
    AffinePoint, NistP256, ProjectivePoint,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::linear_combination::linearly_combine_bounded_or_scale;
use crate::{
    secp256r1::{scalar::Scalar, CURVE_EQUATION_A, CURVE_EQUATION_B, MODULUS, ORDER},
    BoundedGroupElement, CyclicGroupElement, HashToGroup, KnownOrderGroupElement, MulByGenerator,
    PrimeGroupElement, Scale, Transcribeable,
};

use super::SCALAR_LIMBS;

/// An element of the secp256r1 prime group.
#[derive(PartialEq, Eq, Clone, Debug, Default, Copy)]
pub struct GroupElement(pub(super) ProjectivePoint);

/// The public parameters of the secp256r1 group.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    curve_type: String,
    pub order: U256,
    pub modulus: U256,
    pub generator: Value,
    pub curve_equation_a: U256,
    pub curve_equation_b: U256,
}

impl Transcribeable for PublicParameters {
    type CanonicalRepresentation = Self;
}

impl Default for PublicParameters {
    fn default() -> Self {
        Self {
            name: "secp256r1".to_string(),
            curve_type: "Weierstrass".to_string(),
            order: ORDER,
            modulus: MODULUS,
            generator: Value(AffinePoint::GENERATOR),
            curve_equation_a: CURVE_EQUATION_A,
            curve_equation_b: CURVE_EQUATION_B,
        }
    }
}

/// The value of the secp256r1 group used for serialization.
///
/// This is a `newtype` around `AffinePoint` used to control instantiation;
/// the only way to instantiate this type from outside this module is through deserialization,
/// which in turn will invoke `AffinePoint`'s deserialization which assures the point is on curve.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Default, Serialize, Deserialize)]
pub struct Value(AffinePoint);

impl ConstantTimeEq for Value {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Value {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(AffinePoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for GroupElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for GroupElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ProjectivePoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl From<Value> for AffinePoint {
    fn from(value: Value) -> Self {
        value.0
    }
}

impl crate::GroupElement for GroupElement {
    type Value = Value;

    fn value(&self) -> Self::Value {
        // As this group element is valid, it's safe to instantiate a `Value`
        // from the valid affine representation.
        Value(self.0.to_affine())
    }

    fn batch_normalize(group_elements: Vec<Self>) -> Vec<Self::Value> {
        let projective_points: Vec<_> = group_elements
            .into_iter()
            .map(|group_element| group_element.0)
            .collect();

        p256::ProjectivePoint::batch_normalize(projective_points.as_slice())
            .into_iter()
            .map(Value)
            .collect()
    }

    fn batch_normalize_const_generic<const N: usize>(
        group_elements: [Self; N],
    ) -> [Self::Value; N] {
        let projective_points = group_elements.map(|group_element| group_element.0);
        // default to a trivial implementation.
        p256::ProjectivePoint::batch_normalize(&projective_points).map(Value)
    }

    type PublicParameters = PublicParameters;

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        // `p256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization, so
        // this is always safe.
        Ok(Self(value.0.to_curve()))
    }

    fn neutral(&self) -> Self {
        Self(ProjectivePoint::IDENTITY)
    }

    fn neutral_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self(ProjectivePoint::IDENTITY))
    }

    fn scale<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        Scalar::from(scalar) * self
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
        Self(<ProjectivePoint as Group>::double(&self.0))
    }

    fn double_vartime(&self, _public_parameters: &Self::PublicParameters) -> Self {
        self.double(_public_parameters)
    }

    fn add_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0 + other.0)
    }

    fn sub_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0 - other.0)
    }

    fn neg_constant_time(&self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0.neg())
    }

    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        linearly_combine_bounded_or_scale(
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
        linearly_combine_bounded_or_scale(
            bases_and_multiplicands,
            exponent_bits,
            false,
            public_parameters,
        )
    }
}

impl From<GroupElement> for Value {
    fn from(value: GroupElement) -> Self {
        // As this group element is valid, it's safe to instantiate a `Value`
        // from the valid affine representation.
        Self(value.0.to_affine())
    }
}

impl From<GroupElement> for PublicParameters {
    fn from(_value: GroupElement) -> Self {
        Self::default()
    }
}

impl Neg for GroupElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Add<Self> for GroupElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl<'r> Add<&'r Self> for GroupElement {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl Sub<Self> for GroupElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl<'r> Sub<&'r Self> for GroupElement {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl AddAssign<Self> for GroupElement {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<'r> AddAssign<&'r Self> for GroupElement {
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(rhs.0)
    }
}

impl SubAssign<Self> for GroupElement {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<'r> SubAssign<&'r Self> for GroupElement {
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl MulByGenerator<U256> for GroupElement {
    fn mul_by_generator(&self, scalar: U256) -> Self {
        self.mul_by_generator(Scalar::from(scalar))
    }
}

impl<'r> MulByGenerator<&'r U256> for GroupElement {
    fn mul_by_generator(&self, scalar: &'r U256) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl CyclicGroupElement for GroupElement {
    fn generator(&self) -> Self {
        Self(ProjectivePoint::GENERATOR)
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Value(AffinePoint::GENERATOR)
    }
}

impl BoundedGroupElement<SCALAR_LIMBS> for GroupElement {
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<SCALAR_LIMBS> {
        Self::order_from_public_parameters(public_parameters)
    }
}

impl KnownOrderGroupElement<SCALAR_LIMBS> for GroupElement {
    type Scalar = Scalar;

    fn order_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        ORDER
    }
}

impl MulByGenerator<Scalar> for GroupElement {
    fn mul_by_generator(&self, scalar: Scalar) -> Self {
        GroupElement(ProjectivePoint::mul_by_generator(&scalar.0))
    }
}

impl<'r> MulByGenerator<&'r Scalar> for GroupElement {
    fn mul_by_generator(&self, scalar: &'r Scalar) -> Self {
        self.mul_by_generator(*scalar)
    }
}

impl Scale<Scalar> for GroupElement {
    fn scale_by(&self, scalar: &Scalar, _public_parameters: &Self::PublicParameters) -> Self {
        scalar * self
    }

    fn scale_vartime_by(
        &self,
        scalar: &Scalar,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_bounded_by(
        &self,
        scalar: &Scalar,
        _scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &Scalar,
        _scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &Scalar,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_public_base_by(
        &self,
        scalar: &Scalar,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &Scalar,
        _scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_randomized_by(
        &self,
        scalar: &Scalar,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &Scalar,
        _scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &Scalar,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &Scalar,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &Scalar,
        _scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        scalar * self
    }
}

impl Scale<crate::scalar::Value<Scalar>> for GroupElement {
    fn scale_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_by(&scalar.0, public_parameters)
    }

    fn scale_vartime_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_vartime_by(&scalar.0, public_parameters)
    }

    fn scale_bounded_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded_by(&scalar.0, scalar_bits, public_parameters)
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded_vartime_by(&scalar.0, scalar_bits, public_parameters)
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_vartime_scalar_by(&scalar.0, public_parameters)
    }

    fn scale_public_base_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_public_base_by(&scalar.0, public_parameters)
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_public_base_bounded_by(&scalar.0, scalar_bits, public_parameters)
    }

    fn scale_randomized_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_by(&scalar.0, public_parameters)
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_bounded_by(&scalar.0, scalar_bits, public_parameters)
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_vartime_scalar_by(&scalar.0, public_parameters)
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_public_base_by(&scalar.0, public_parameters)
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &crate::scalar::Value<Scalar>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_public_base_bounded_by(&scalar.0, scalar_bits, public_parameters)
    }
}

impl PrimeGroupElement<SCALAR_LIMBS> for GroupElement {}

impl HashToGroup for GroupElement {
    fn hash_to_group(bytes: &[u8]) -> crate::Result<Self> {
        hash2curve::hash_from_bytes::<NistP256, ExpandMsgXmd<Sha256>>(
            &[bytes],
            &[b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"],
        )
        .map_err(|_| crate::Error::from(crate::ErrorKind::HashToGroup))
        .map(Self)
    }
}
