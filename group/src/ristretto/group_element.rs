// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

use crypto_bigint::{Int, Uint, U256};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::Identity,
};
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::linear_combination::linearly_combine_bounded_or_scale;
use crate::{
    ristretto::{scalar::Scalar, CURVE_EQUATION_A, CURVE_EQUATION_B, MODULUS, ORDER},
    BoundedGroupElement, CyclicGroupElement, HashToGroup, KnownOrderGroupElement, MulByGenerator,
    PrimeGroupElement, Scale, Transcribeable,
};

use super::SCALAR_LIMBS;

/// An element of the ristretto prime group.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct GroupElement(pub(super) RistrettoPoint);

/// The public parameters of the ristretto group.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    name: String,
    curve_type: String,
    pub order: U256,
    pub modulus: U256,
    pub generator: GroupElement,
    pub curve_equation_a: U256,
    pub curve_equation_b: U256,
}

impl Transcribeable for PublicParameters {
    type CanonicalRepresentation = Self;
}

impl Default for PublicParameters {
    fn default() -> Self {
        Self {
            name: "Ristretto".to_string(),
            curve_type: "Montgomery".to_string(),
            order: ORDER,
            modulus: MODULUS,
            generator: GroupElement(RISTRETTO_BASEPOINT_POINT),
            curve_equation_a: CURVE_EQUATION_A,
            curve_equation_b: CURVE_EQUATION_B,
        }
    }
}

impl ConstantTimeEq for GroupElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        RistrettoPoint::ct_eq(&self.0, &other.0)
    }
}

impl ConditionallySelectable for GroupElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(RistrettoPoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl crate::GroupElement for GroupElement {
    type Value = Self;

    fn value(&self) -> Self::Value {
        *self
    }

    type PublicParameters = PublicParameters;

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        // `RistrettoPoint` assures deserialized values are on a curve,
        // and `Self` can only be instantiated through deserialization, so
        // this is always safe.
        Ok(value)
    }

    fn neutral(&self) -> Self {
        Self(RistrettoPoint::identity())
    }

    fn neutral_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self(RistrettoPoint::identity()))
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
        Self(self.0 + self.0)
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

impl From<GroupElement> for PublicParameters {
    fn from(_value: GroupElement) -> Self {
        Self::default()
    }
}

impl TryFrom<CompressedRistretto> for GroupElement {
    type Error = crate::Error;

    fn try_from(value: CompressedRistretto) -> Result<Self, Self::Error> {
        // `decompress()` ensures the point is on a curve.
        // From the documentation: "Return * Some(RistrettoPoint) if self was the canonical encoding
        // of a point; *
        // None if self was not the canonical encoding of a point."
        value
            .decompress()
            .map(Self)
            .ok_or_else(|| crate::Error::from(crate::ErrorKind::InvalidGroupElement))
    }
}

impl From<GroupElement> for RistrettoPoint {
    fn from(value: GroupElement) -> Self {
        value.0
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
        Self(RISTRETTO_BASEPOINT_POINT)
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Self(RISTRETTO_BASEPOINT_POINT)
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
        scalar * self
    }
}

impl<'r> MulByGenerator<&'r Scalar> for GroupElement {
    fn mul_by_generator(&self, scalar: &'r Scalar) -> Self {
        scalar * self
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
        Ok(Self(RistrettoPoint::hash_from_bytes::<Sha3_512>(bytes)))
    }
}
