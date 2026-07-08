// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, BitAnd, Neg, Sub, SubAssign};

use crypto_bigint::{Int, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::CsRng;
use crate::{Samplable, Transcribeable};

/// An element of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct GroupElement<FirstGroupElement, SecondGroupElement>(
    FirstGroupElement,
    SecondGroupElement,
);

pub type ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement> =
    GroupElement<GroupElement<FirstGroupElement, SecondGroupElement>, ThirdGroupElement>;

pub type FourWayGroupElement<
    FirstGroupElement,
    SecondGroupElement,
    ThirdGroupElement,
    FourthGroupElement,
> = GroupElement<
    GroupElement<GroupElement<FirstGroupElement, SecondGroupElement>, ThirdGroupElement>,
    FourthGroupElement,
>;

impl<
        FirstGroupElement: crate::GroupElement + Samplable,
        SecondGroupElement: crate::GroupElement + Samplable,
    > Samplable for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        Ok(Self(
            FirstGroupElement::sample(&public_parameters.0, rng)?,
            SecondGroupElement::sample(&public_parameters.1, rng)?,
        ))
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        Ok(Self(
            FirstGroupElement::sample_randomizer(&public_parameters.0, rng)?,
            SecondGroupElement::sample_randomizer(&public_parameters.1, rng)?,
        ))
    }
}

/// The public parameters of the Direct Product of the two Groups `FirstGroupElement` and
/// `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>(
    pub FirstGroupPublicParameters,
    pub SecondGroupPublicParameters,
);

/// The canonical representation of the public parameters of the Direct Product of the two Groups `FirstGroupElement` and
/// `SecondGroupElement`.
#[derive(Serialize)]
pub struct CanonicalPublicParameters<
    FirstGroupPublicParameters: Transcribeable,
    SecondGroupPublicParameters: Transcribeable,
>(
    FirstGroupPublicParameters::CanonicalRepresentation,
    SecondGroupPublicParameters::CanonicalRepresentation,
);

impl<FirstGroupPublicParameters: Transcribeable, SecondGroupPublicParameters: Transcribeable>
    From<PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>>
    for CanonicalPublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>
{
    fn from(
        value: PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>,
    ) -> Self {
        Self(value.0.into(), value.1.into())
    }
}

impl<FirstGroupPublicParameters: Transcribeable, SecondGroupPublicParameters: Transcribeable>
    Transcribeable for PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>
{
    type CanonicalRepresentation =
        CanonicalPublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>;
}

pub type ThreeWayPublicParameters<
    FirstGroupPublicParameters,
    SecondGroupPublicParameters,
    ThirdGroupPublicParameters,
> = PublicParameters<
    PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>,
    ThirdGroupPublicParameters,
>;

pub type FourWayPublicParameters<
    FirstGroupPublicParameters,
    SecondGroupPublicParameters,
    ThirdGroupPublicParameters,
    FourthGroupPublicParameters,
> = PublicParameters<
    ThreeWayPublicParameters<
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
    >,
    FourthGroupPublicParameters,
>;

/// The value of the Direct Product of the two Groups `FirstGroupElement` and `SecondGroupElement`.
#[derive(PartialEq, Eq, Clone, Debug, Default, Hash, Serialize, Deserialize, Copy)]
pub struct Value<FirstGroupElementValue, SecondGroupElementValue>(
    FirstGroupElementValue,
    SecondGroupElementValue,
);

impl<
        FirstGroupElementValue: ConditionallySelectable,
        SecondGroupElementValue: ConditionallySelectable,
    > ConditionallySelectable for Value<FirstGroupElementValue, SecondGroupElementValue>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(
            FirstGroupElementValue::conditional_select(&a.0, &b.0, choice),
            SecondGroupElementValue::conditional_select(&a.1, &b.1, choice),
        )
    }
}

impl<FirstGroupElementValue: ConstantTimeEq, SecondGroupElementValue: ConstantTimeEq> ConstantTimeEq
    for Value<FirstGroupElementValue, SecondGroupElementValue>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<
        FirstGroupElementValue: ConditionallySelectable,
        SecondGroupElementValue: ConditionallySelectable,
    > ConditionallySelectable for GroupElement<FirstGroupElementValue, SecondGroupElementValue>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(
            FirstGroupElementValue::conditional_select(&a.0, &b.0, choice),
            SecondGroupElementValue::conditional_select(&a.1, &b.1, choice),
        )
    }
}

impl<FirstGroupElementValue: ConstantTimeEq, SecondGroupElementValue: ConstantTimeEq> ConstantTimeEq
    for GroupElement<FirstGroupElementValue, SecondGroupElementValue>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<FirstGroupElementValue: Default, SecondGroupElementValue: Default> Default
    for GroupElement<FirstGroupElementValue, SecondGroupElementValue>
{
    fn default() -> Self {
        Self(
            FirstGroupElementValue::default(),
            SecondGroupElementValue::default(),
        )
    }
}

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    crate::GroupElement for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Value = Value<FirstGroupElement::Value, SecondGroupElement::Value>;

    type PublicParameters =
        PublicParameters<FirstGroupElement::PublicParameters, SecondGroupElement::PublicParameters>;

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        Ok(Self(
            FirstGroupElement::new(value.0, &public_parameters.0)?,
            SecondGroupElement::new(value.1, &public_parameters.1)?,
        ))
    }

    fn neutral(&self) -> Self {
        Self(
            FirstGroupElement::neutral(&self.0),
            SecondGroupElement::neutral(&self.1),
        )
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self(
            FirstGroupElement::neutral_from_public_parameters(&public_parameters.0)?,
            SecondGroupElement::neutral_from_public_parameters(&public_parameters.1)?,
        ))
    }

    fn add_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.add_constant_time(&other.0, &public_parameters.0),
            self.1.add_constant_time(&other.1, &public_parameters.1),
        )
    }

    fn sub_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.sub_constant_time(&other.0, &public_parameters.0),
            self.1.sub_constant_time(&other.1, &public_parameters.1),
        )
    }

    fn neg_constant_time(&self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.neg_constant_time(&public_parameters.0),
            self.1.neg_constant_time(&public_parameters.1),
        )
    }

    fn scale<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale(scalar, &public_parameters.0),
            self.1.scale(scalar, &public_parameters.1),
        )
    }

    fn scale_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_bounded(scalar, scalar_bits, &public_parameters.0),
            self.1
                .scale_bounded(scalar, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_bounded_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_bounded_vartime(scalar, scalar_bits, &public_parameters.0),
            self.1
                .scale_bounded_vartime(scalar, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_integer_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_bounded(integer, scalar_bits, &public_parameters.0),
            self.1
                .scale_integer_bounded(integer, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_integer<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale_integer(integer, &public_parameters.0),
            self.1.scale_integer(integer, &public_parameters.1),
        )
    }

    fn scale_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale_vartime(scalar, &public_parameters.0),
            self.1.scale_vartime(scalar, &public_parameters.1),
        )
    }

    fn scale_integer_vartime<const LIMBS: usize>(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale_integer_vartime(scalar, &public_parameters.0),
            self.1.scale_integer_vartime(scalar, &public_parameters.1),
        )
    }

    fn scale_integer_bounded_vartime<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_bounded_vartime(integer, scalar_bits, &public_parameters.0),
            self.1
                .scale_integer_bounded_vartime(integer, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale_vartime_scalar(scalar, &public_parameters.0),
            self.1.scale_vartime_scalar(scalar, &public_parameters.1),
        )
    }

    fn scale_integer_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_vartime_scalar(integer, &public_parameters.0),
            self.1
                .scale_integer_vartime_scalar(integer, &public_parameters.1),
        )
    }

    fn scale_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale_public_base(scalar, &public_parameters.0),
            self.1.scale_public_base(scalar, &public_parameters.1),
        )
    }

    fn scale_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_public_base_bounded(scalar, scalar_bits, &public_parameters.0),
            self.1
                .scale_public_base_bounded(scalar, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_integer_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_public_base(integer, &public_parameters.0),
            self.1
                .scale_integer_public_base(integer, &public_parameters.1),
        )
    }

    fn scale_integer_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_public_base_bounded(integer, scalar_bits, &public_parameters.0),
            self.1
                .scale_integer_public_base_bounded(integer, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_randomized<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale_randomized(scalar, &public_parameters.0),
            self.1.scale_randomized(scalar, &public_parameters.1),
        )
    }

    fn scale_randomized_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_randomized_bounded(scalar, scalar_bits, &public_parameters.0),
            self.1
                .scale_randomized_bounded(scalar, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_randomized_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_randomized_public_base(scalar, &public_parameters.0),
            self.1
                .scale_randomized_public_base(scalar, &public_parameters.1),
        )
    }

    fn scale_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_randomized_public_base_bounded(scalar, scalar_bits, &public_parameters.0),
            self.1
                .scale_randomized_public_base_bounded(scalar, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_integer_randomized<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_randomized(integer, &public_parameters.0),
            self.1
                .scale_integer_randomized(integer, &public_parameters.1),
        )
    }

    fn scale_integer_randomized_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_randomized_bounded(integer, scalar_bits, &public_parameters.0),
            self.1
                .scale_integer_randomized_bounded(integer, scalar_bits, &public_parameters.1),
        )
    }

    fn scale_integer_randomized_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_randomized_public_base(integer, &public_parameters.0),
            self.1
                .scale_integer_randomized_public_base(integer, &public_parameters.1),
        )
    }

    fn scale_integer_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.scale_integer_randomized_public_base_bounded(
                integer,
                scalar_bits,
                &public_parameters.0,
            ),
            self.1.scale_integer_randomized_public_base_bounded(
                integer,
                scalar_bits,
                &public_parameters.1,
            ),
        )
    }

    fn scale_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_randomized_vartime_scalar(scalar, &public_parameters.0),
            self.1
                .scale_randomized_vartime_scalar(scalar, &public_parameters.1),
        )
    }

    fn scale_integer_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .scale_integer_randomized_vartime_scalar(integer, &public_parameters.0),
            self.1
                .scale_integer_randomized_vartime_scalar(integer, &public_parameters.1),
        )
    }

    fn add_randomized(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.add_randomized(&other.0, &public_parameters.0),
            self.1.add_randomized(&other.1, &public_parameters.1),
        )
    }

    fn add_vartime(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.add_vartime(&other.0, &public_parameters.0),
            self.1.add_vartime(&other.1, &public_parameters.1),
        )
    }

    fn sub_randomized(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.sub_randomized(&other.0, &public_parameters.0),
            self.1.sub_randomized(&other.1, &public_parameters.1),
        )
    }

    fn sub_vartime(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.sub_vartime(&other.0, &public_parameters.0),
            self.1.sub_vartime(&other.1, &public_parameters.1),
        )
    }

    fn double(&self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.double(&public_parameters.0),
            self.1.double(&public_parameters.1),
        )
    }

    fn double_vartime(&self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0.double_vartime(&public_parameters.0),
            self.1.double_vartime(&public_parameters.1),
        )
    }

    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        let (first_bases_and_multiplicands, second_bases_and_multiplicands): (Vec<_>, Vec<_>) =
            bases_and_multiplicands
                .into_iter()
                .map(|(base, multiplicand)| ((base.0, multiplicand), (base.1, multiplicand)))
                .unzip();
        Ok(Self(
            FirstGroupElement::linearly_combine_bounded(
                first_bases_and_multiplicands,
                exponent_bits,
                &public_parameters.0,
            )?,
            SecondGroupElement::linearly_combine_bounded(
                second_bases_and_multiplicands,
                exponent_bits,
                &public_parameters.1,
            )?,
        ))
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        let (first_bases_and_multiplicands, second_bases_and_multiplicands): (Vec<_>, Vec<_>) =
            bases_and_multiplicands
                .into_iter()
                .map(|(base, multiplicand)| ((base.0, multiplicand), (base.1, multiplicand)))
                .unzip();
        Ok(Self(
            FirstGroupElement::linearly_combine_bounded_vartime(
                first_bases_and_multiplicands,
                exponent_bits,
                &public_parameters.0,
            )?,
            SecondGroupElement::linearly_combine_bounded_vartime(
                second_bases_and_multiplicands,
                exponent_bits,
                &public_parameters.1,
            )?,
        ))
    }
}

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    From<GroupElement<FirstGroupElement, SecondGroupElement>>
    for Value<FirstGroupElement::Value, SecondGroupElement::Value>
{
    fn from(value: GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        Self(value.0.into(), value.1.into())
    }
}

impl<
        FirstGroupElement: crate::GroupElement + Neg<Output = FirstGroupElement>,
        SecondGroupElement: crate::GroupElement + Neg<Output = SecondGroupElement>,
    > Neg for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg(), self.1.neg())
    }
}

impl<
        FirstGroupElement: crate::GroupElement + for<'a> Add<&'a FirstGroupElement, Output = FirstGroupElement>,
        SecondGroupElement: crate::GroupElement
            + Add<SecondGroupElement, Output = SecondGroupElement>
            + for<'a> Add<&'a SecondGroupElement, Output = SecondGroupElement>,
    > Add<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(rhs.1))
    }
}

impl<
        'r,
        FirstGroupElement: crate::GroupElement + for<'a> Add<&'a FirstGroupElement, Output = FirstGroupElement>,
        SecondGroupElement: crate::GroupElement + for<'a> Add<&'a SecondGroupElement, Output = SecondGroupElement>,
    > Add<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(&rhs.1))
    }
}

impl<
        FirstGroupElement: crate::GroupElement + for<'a> Sub<&'a FirstGroupElement, Output = FirstGroupElement>,
        SecondGroupElement: crate::GroupElement
            + Sub<SecondGroupElement, Output = SecondGroupElement>
            + for<'a> Sub<&'a SecondGroupElement, Output = SecondGroupElement>,
    > Sub<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(rhs.1))
    }
}

impl<
        'r,
        FirstGroupElement: crate::GroupElement + for<'a> Sub<&'a FirstGroupElement, Output = FirstGroupElement>,
        SecondGroupElement: crate::GroupElement + for<'a> Sub<&'a SecondGroupElement, Output = SecondGroupElement>,
    > Sub<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(&rhs.1))
    }
}

impl<
        FirstGroupElement: crate::GroupElement + for<'a> AddAssign<&'a FirstGroupElement>,
        SecondGroupElement: crate::GroupElement
            + AddAssign<SecondGroupElement>
            + for<'a> AddAssign<&'a SecondGroupElement>,
    > AddAssign<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(rhs.1);
    }
}

impl<
        'r,
        FirstGroupElement: crate::GroupElement + for<'a> AddAssign<&'a FirstGroupElement>,
        SecondGroupElement: crate::GroupElement + for<'a> AddAssign<&'a SecondGroupElement>,
    > AddAssign<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(&rhs.1);
    }
}

impl<
        FirstGroupElement: crate::GroupElement + for<'a> SubAssign<&'a FirstGroupElement>,
        SecondGroupElement: crate::GroupElement
            + SubAssign<SecondGroupElement>
            + for<'a> SubAssign<&'a SecondGroupElement>,
    > SubAssign<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(rhs.1);
    }
}

impl<
        'r,
        FirstGroupElement: crate::GroupElement + for<'a> SubAssign<&'a FirstGroupElement>,
        SecondGroupElement: crate::GroupElement + for<'a> SubAssign<&'a SecondGroupElement>,
    > SubAssign<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(&rhs.1);
    }
}

impl<FirstGroupElement, SecondGroupElement>
    From<GroupElement<FirstGroupElement, SecondGroupElement>>
    for (FirstGroupElement, SecondGroupElement)
{
    fn from(value: GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        (value.0, value.1)
    }
}

impl<'r, FirstGroupElement, SecondGroupElement>
    From<&'r GroupElement<FirstGroupElement, SecondGroupElement>>
    for (&'r FirstGroupElement, &'r SecondGroupElement)
{
    fn from(value: &'r GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        (&value.0, &value.1)
    }
}

impl<FirstGroupElement, SecondGroupElement> From<(FirstGroupElement, SecondGroupElement)>
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn from(value: (FirstGroupElement, SecondGroupElement)) -> Self {
        Self(value.0, value.1)
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters>
    From<PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>>
    for (FirstGroupPublicParameters, SecondGroupPublicParameters)
{
    fn from(
        value: PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>,
    ) -> Self {
        (value.0, value.1)
    }
}

impl<FirstValue, SecondValue> From<Value<FirstValue, SecondValue>> for (FirstValue, SecondValue) {
    fn from(value: Value<FirstValue, SecondValue>) -> Self {
        (value.0, value.1)
    }
}

impl<'r, FirstValue, SecondValue> From<&'r Value<FirstValue, SecondValue>>
    for (&'r FirstValue, &'r SecondValue)
{
    fn from(value: &'r Value<FirstValue, SecondValue>) -> Self {
        (&value.0, &value.1)
    }
}

impl<FirstValue, SecondValue> From<(FirstValue, SecondValue)> for Value<FirstValue, SecondValue> {
    fn from(value: (FirstValue, SecondValue)) -> Self {
        Self(value.0, value.1)
    }
}

impl<'r, FirstGroupPublicParameters, SecondGroupPublicParameters>
    From<&'r PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>>
    for (
        &'r FirstGroupPublicParameters,
        &'r SecondGroupPublicParameters,
    )
{
    fn from(
        value: &'r PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>,
    ) -> Self {
        (&value.0, &value.1)
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters>
    From<(FirstGroupPublicParameters, SecondGroupPublicParameters)>
    for PublicParameters<FirstGroupPublicParameters, SecondGroupPublicParameters>
{
    fn from(value: (FirstGroupPublicParameters, SecondGroupPublicParameters)) -> Self {
        Self(value.0, value.1)
    }
}

impl<FirstGroupElement, SecondGroupElement, ThirdGroupElement>
    From<(FirstGroupElement, SecondGroupElement, ThirdGroupElement)>
    for ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>
{
    fn from(value: (FirstGroupElement, SecondGroupElement, ThirdGroupElement)) -> Self {
        let (first_element, second_element, third_element) = value;

        GroupElement(GroupElement(first_element, second_element), third_element)
    }
}

impl<FirstValue, SecondValue, ThirdValue> From<(FirstValue, SecondValue, ThirdValue)>
    for Value<Value<FirstValue, SecondValue>, ThirdValue>
{
    fn from(value: (FirstValue, SecondValue, ThirdValue)) -> Self {
        let (first_value, second_value, third_value) = value;

        Value(Value(first_value, second_value), third_value)
    }
}

impl<FirstValue, SecondValue, ThirdValue> From<Value<Value<FirstValue, SecondValue>, ThirdValue>>
    for (FirstValue, SecondValue, ThirdValue)
{
    fn from(value: Value<Value<FirstValue, SecondValue>, ThirdValue>) -> Self {
        (value.0 .0, value.0 .1, value.1)
    }
}

impl<FirstGroupElement, SecondGroupElement, ThirdGroupElement>
    From<ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>>
    for (FirstGroupElement, SecondGroupElement, ThirdGroupElement)
{
    fn from(
        value: ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>,
    ) -> Self {
        let (first_by_second_element, third_element) = value.into();
        let (first_element, second_element) = first_by_second_element.into();

        (first_element, second_element, third_element)
    }
}

impl<'r, FirstGroupElement, SecondGroupElement, ThirdGroupElement>
    From<&'r ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>>
    for (
        &'r FirstGroupElement,
        &'r SecondGroupElement,
        &'r ThirdGroupElement,
    )
{
    fn from(
        value: &'r ThreeWayGroupElement<FirstGroupElement, SecondGroupElement, ThirdGroupElement>,
    ) -> Self {
        let (first_by_second_element, third_element) = value.into();
        let (first_element, second_element) = first_by_second_element.into();

        (first_element, second_element, third_element)
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters, ThirdGroupPublicParameters>
    From<(
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
    )>
    for ThreeWayPublicParameters<
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
    >
{
    fn from(
        value: (
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        ),
    ) -> Self {
        let (first_public_parameters, second_public_parameters, third_public_parameters) = value;

        PublicParameters(
            PublicParameters(first_public_parameters, second_public_parameters),
            third_public_parameters,
        )
    }
}

impl<FirstGroupPublicParameters, SecondGroupPublicParameters, ThirdGroupPublicParameters>
    From<
        ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    >
    for (
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
    )
{
    fn from(
        value: ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    ) -> Self {
        let (first_by_second_public_parameters, third_public_parameters) = value.into();
        let (first_public_parameters, second_public_parameters) =
            first_by_second_public_parameters.into();

        (
            first_public_parameters,
            second_public_parameters,
            third_public_parameters,
        )
    }
}

impl<'r, FirstGroupPublicParameters, SecondGroupPublicParameters, ThirdGroupPublicParameters>
    From<
        &'r ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    >
    for (
        &'r FirstGroupPublicParameters,
        &'r SecondGroupPublicParameters,
        &'r ThirdGroupPublicParameters,
    )
{
    fn from(
        value: &'r ThreeWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
        >,
    ) -> Self {
        let (first_by_second_public_parameters, third_public_parameters) = value.into();
        let (first_public_parameters, second_public_parameters) =
            first_by_second_public_parameters.into();

        (
            first_public_parameters,
            second_public_parameters,
            third_public_parameters,
        )
    }
}

impl<FirstGroupElement, SecondGroupElement, ThirdGroupElement, FourthGroupElement>
    From<(
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    )>
    for FourWayGroupElement<
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    >
{
    fn from(
        value: (
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        ),
    ) -> Self {
        let (first_element, second_element, third_element, fourth_element) = value;

        GroupElement(
            GroupElement(GroupElement(first_element, second_element), third_element),
            fourth_element,
        )
    }
}

impl<FirstGroupElement, SecondGroupElement, ThirdGroupElement, FourthGroupElement>
    From<
        FourWayGroupElement<
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    >
    for (
        FirstGroupElement,
        SecondGroupElement,
        ThirdGroupElement,
        FourthGroupElement,
    )
{
    fn from(
        value: FourWayGroupElement<
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    ) -> Self {
        let (first_by_second_by_third_element, fourth_element) = value.into();
        let (first_element, second_element, third_element) =
            first_by_second_by_third_element.into();

        (first_element, second_element, third_element, fourth_element)
    }
}

impl<'r, FirstGroupElement, SecondGroupElement, ThirdGroupElement, FourthGroupElement>
    From<
        &'r FourWayGroupElement<
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    >
    for (
        &'r FirstGroupElement,
        &'r SecondGroupElement,
        &'r ThirdGroupElement,
        &'r FourthGroupElement,
    )
{
    fn from(
        value: &'r FourWayGroupElement<
            FirstGroupElement,
            SecondGroupElement,
            ThirdGroupElement,
            FourthGroupElement,
        >,
    ) -> Self {
        let (first_by_second_by_third_element, fourth_element) = value.into();
        let (first_element, second_element, third_element) =
            first_by_second_by_third_element.into();

        (first_element, second_element, third_element, fourth_element)
    }
}

impl<
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
        FourthGroupPublicParameters,
    >
    From<(
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
        FourthGroupPublicParameters,
    )>
    for FourWayPublicParameters<
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
        FourthGroupPublicParameters,
    >
{
    fn from(
        value: (
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
            FourthGroupPublicParameters,
        ),
    ) -> Self {
        let (
            first_public_parameters,
            second_public_parameters,
            third_public_parameters,
            fourth_public_parameters,
        ) = value;

        PublicParameters(
            PublicParameters(
                PublicParameters(first_public_parameters, second_public_parameters),
                third_public_parameters,
            ),
            fourth_public_parameters,
        )
    }
}

impl<
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
        FourthGroupPublicParameters,
    >
    From<
        FourWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
            FourthGroupPublicParameters,
        >,
    >
    for (
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
        FourthGroupPublicParameters,
    )
{
    fn from(
        value: FourWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
            FourthGroupPublicParameters,
        >,
    ) -> Self {
        let (first_by_second_by_third_public_parameters, fourth_public_parameters) = value.into();
        let (first_public_parameters, second_public_parameters, third_public_parameters) =
            first_by_second_by_third_public_parameters.into();

        (
            first_public_parameters,
            second_public_parameters,
            third_public_parameters,
            fourth_public_parameters,
        )
    }
}

impl<
        'r,
        FirstGroupPublicParameters,
        SecondGroupPublicParameters,
        ThirdGroupPublicParameters,
        FourthGroupPublicParameters,
    >
    From<
        &'r FourWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
            FourthGroupPublicParameters,
        >,
    >
    for (
        &'r FirstGroupPublicParameters,
        &'r SecondGroupPublicParameters,
        &'r ThirdGroupPublicParameters,
        &'r FourthGroupPublicParameters,
    )
{
    fn from(
        value: &'r FourWayPublicParameters<
            FirstGroupPublicParameters,
            SecondGroupPublicParameters,
            ThirdGroupPublicParameters,
            FourthGroupPublicParameters,
        >,
    ) -> Self {
        let (first_by_second_by_third_public_parameters, fourth_public_parameters) = value.into();
        let (first_public_parameters, second_public_parameters, third_public_parameters) =
            first_by_second_by_third_public_parameters.into();

        (
            first_public_parameters,
            second_public_parameters,
            third_public_parameters,
            fourth_public_parameters,
        )
    }
}
