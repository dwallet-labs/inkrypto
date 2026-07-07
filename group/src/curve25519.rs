// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use crate::linear_combination::linearly_combine_bounded_or_scale;
use crate::{
    BoundedGroupElement, CyclicGroupElement, Error, ErrorKind, HashToGroup, KnownOrderGroupElement,
    MulByGenerator, PrimeGroupElement, Scale, Transcribeable,
};
use crypto_bigint::{Int, Uint, U256};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::EdwardsPoint;
use k256::elliptic_curve::Group;
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// Re-export all curve constants from `ristretto` as they are the same
// They also use the same `Scalar` field.
pub use crate::ristretto::{
    scalar, Scalar, CURVE_EQUATION_A, CURVE_EQUATION_B, MODULUS, ORDER, SCALAR_LIMBS,
};

/// The serializable value type for Curve25519 group elements.
///
/// This is a newtype wrapper around `EdwardsPoint` that provides serialization.
/// Unlike `GroupElement`, this type does NOT guarantee the point is in the prime subgroup.
/// Use `GroupElement::new()` to validate and convert to a `GroupElement`.
///
/// # Security
///
/// This separation ensures that deserialized points must go through `new()` validation
/// before being used in cryptographic operations, preventing small-subgroup attacks
/// from torsion points.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Value(pub(super) EdwardsPoint);

impl ConstantTimeEq for Value {
    fn ct_eq(&self, other: &Self) -> Choice {
        EdwardsPoint::ct_eq(&self.0, &other.0)
    }
}

impl ConditionallySelectable for Value {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(EdwardsPoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl From<GroupElement> for Value {
    fn from(value: GroupElement) -> Self {
        Value(value.0)
    }
}

impl From<Value> for EdwardsPoint {
    fn from(value: Value) -> Self {
        value.0
    }
}

impl From<EdwardsPoint> for Value {
    fn from(value: EdwardsPoint) -> Self {
        Value(value)
    }
}

/// An element of the Curve25519 prime subgroup.
///
/// This type guarantees the point is torsion-free (in the prime-order subgroup).
/// It intentionally does NOT implement `Serialize`/`Deserialize` directly - use
/// `value()` to get a serializable `Value`, and `new()` to validate and convert back.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub struct GroupElement(pub(super) EdwardsPoint);

/// The public parameters of the Curve25519 prime subgroup.
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
            name: "Curve25519".to_string(),
            curve_type: "Montgomery".to_string(),
            order: ORDER,
            modulus: MODULUS,
            generator: Value(ED25519_BASEPOINT_POINT),
            curve_equation_a: CURVE_EQUATION_A,
            curve_equation_b: CURVE_EQUATION_B,
        }
    }
}

impl ConstantTimeEq for GroupElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        EdwardsPoint::ct_eq(&self.0, &other.0)
    }
}

impl ConditionallySelectable for GroupElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(EdwardsPoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl crate::GroupElement for GroupElement {
    type Value = Value;

    fn value(&self) -> Self::Value {
        Value(self.0)
    }

    type PublicParameters = PublicParameters;

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        // Check that the element is a part of the prime subgroup.
        if value.0.is_torsion_free() {
            Ok(GroupElement(value.0))
        } else {
            Err(Error::from(ErrorKind::InvalidGroupElement))
        }
    }

    fn new_unchecked(
        value: Self::Value,
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        // Skip the check that the element is a part of the prime subgroup, for optimization purposes.
        Ok(GroupElement(value.0))
    }

    fn neutral(&self) -> Self {
        Self(EdwardsPoint::identity())
    }

    fn neutral_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self(EdwardsPoint::identity()))
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

    fn add_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0 + other.0)
    }

    fn sub_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0 - other.0)
    }

    fn neg_constant_time(&self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0.neg())
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
        Self(ED25519_BASEPOINT_POINT)
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Value(ED25519_BASEPOINT_POINT)
    }
}

impl BoundedGroupElement<SCALAR_LIMBS> for GroupElement {
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<SCALAR_LIMBS> {
        Self::order_from_public_parameters(public_parameters)
    }
}

impl From<GroupElement> for EdwardsPoint {
    fn from(value: GroupElement) -> Self {
        value.0
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
        Ok(Self(EdwardsPoint::hash_to_curve::<sha2::Sha512>(
            &[bytes],
            &[b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_"],
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GroupElement as _;

    /// Test that valid prime-order points can be serialized via Value and deserialized.
    #[test]
    fn test_serialize_deserialize_valid_point() {
        let generator = GroupElement(ED25519_BASEPOINT_POINT);

        // Serialize via Value
        let value = generator.value();
        let serialized = serde_json::to_string(&value).unwrap();

        // Deserialize to Value
        let deserialized_value: Value = serde_json::from_str(&serialized).unwrap();

        // Convert back to GroupElement via new() - this validates torsion-free
        let group_params = PublicParameters::default();
        let deserialized = GroupElement::new(deserialized_value, &group_params).unwrap();

        assert_eq!(generator, deserialized);
    }

    /// Test that torsion points are rejected when calling new().
    #[test]
    fn test_torsion_point_rejected_by_new() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        // Get one of the 8 torsion points (non-identity)
        let torsion_point = EIGHT_TORSION[1];

        // Verify this point is indeed not torsion-free
        assert!(
            !torsion_point.is_torsion_free(),
            "Test setup error: point should not be torsion-free"
        );

        // Create a Value from the torsion point
        let torsion_value = Value(torsion_point);

        // Attempting to create a GroupElement should fail
        let group_params = PublicParameters::default();
        let result = GroupElement::new(torsion_value, &group_params);

        assert!(
            result.is_err(),
            "Creating GroupElement from torsion point should fail"
        );
    }

    /// Test that torsion points can be deserialized as Value but fail when converting to GroupElement.
    #[test]
    fn test_torsion_point_deserialization_then_validation() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        // Get a torsion point
        let torsion_point = EIGHT_TORSION[1];
        let torsion_value = Value(torsion_point);

        // Serialize the torsion Value
        let serialized = serde_json::to_string(&torsion_value).unwrap();

        // Deserialize as Value - this should succeed (Value doesn't validate)
        let deserialized_value: Value = serde_json::from_str(&serialized).unwrap();

        // But converting to GroupElement should fail
        let group_params = PublicParameters::default();
        let result = GroupElement::new(deserialized_value, &group_params);

        assert!(
            result.is_err(),
            "Converting torsion Value to GroupElement should fail"
        );
    }

    /// Test that the generator point validates successfully.
    #[test]
    fn test_generator_validates() {
        let generator_value = Value(ED25519_BASEPOINT_POINT);
        let group_params = PublicParameters::default();
        let result = GroupElement::new(generator_value, &group_params);

        assert!(result.is_ok(), "Generator should validate successfully");
    }
}
