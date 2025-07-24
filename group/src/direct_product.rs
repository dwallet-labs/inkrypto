// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, BitAnd, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Int, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::{
    bounded_integers_group, bounded_natural_numbers_group, GroupElement as _, LinearlyCombinable,
    Samplable,
};

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
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        Ok(Self(
            FirstGroupElement::sample(&public_parameters.0, rng)?,
            SecondGroupElement::sample(&public_parameters.1, rng)?,
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
#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize, Deserialize, Copy)]
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
    LinearlyCombinable for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self> {
        let (first_bases_and_multiplicands, second_bases_and_multiplicands): (Vec<_>, Vec<_>) =
            bases_and_multiplicands
                .into_iter()
                .map(|(base, multiplicand)| ((base.0, multiplicand), (base.1, multiplicand)))
                .unzip();
        let first_linear_combination = FirstGroupElement::linearly_combine_bounded(
            first_bases_and_multiplicands,
            exponent_bits,
        )?;
        let second_linear_combination = SecondGroupElement::linearly_combine_bounded(
            second_bases_and_multiplicands,
            exponent_bits,
        )?;

        Ok(Self(first_linear_combination, second_linear_combination))
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self> {
        let (first_bases_and_multiplicands, second_bases_and_multiplicands): (Vec<_>, Vec<_>) =
            bases_and_multiplicands
                .into_iter()
                .map(|(base, multiplicand)| ((base.0, multiplicand), (base.1, multiplicand)))
                .unzip();
        let first_linear_combination = FirstGroupElement::linearly_combine_bounded_vartime(
            first_bases_and_multiplicands,
            exponent_bits,
        )?;
        let second_linear_combination = SecondGroupElement::linearly_combine_bounded_vartime(
            second_bases_and_multiplicands,
            exponent_bits,
        )?;

        Ok(Self(first_linear_combination, second_linear_combination))
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

    fn scale<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        Self(self.0.scale(scalar), self.1.scale(scalar))
    }

    fn scale_bounded<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>, scalar_bits: u32) -> Self {
        Self(
            self.0.scale_bounded(scalar, scalar_bits),
            self.1.scale_bounded(scalar, scalar_bits),
        )
    }

    fn double(&self) -> Self {
        Self(self.0.double(), self.1.double())
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

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    From<GroupElement<FirstGroupElement, SecondGroupElement>>
    for PublicParameters<FirstGroupElement::PublicParameters, SecondGroupElement::PublicParameters>
{
    fn from(value: GroupElement<FirstGroupElement, SecondGroupElement>) -> Self {
        Self(value.0.into(), value.1.into())
    }
}

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement> Neg
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg(), self.1.neg())
    }
}

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement> Add<Self>
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(rhs.1))
    }
}

impl<'r, FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    Add<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0), self.1.add(&rhs.1))
    }
}

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement> Sub<Self>
    for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(rhs.1))
    }
}

impl<'r, FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    Sub<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0), self.1.sub(&rhs.1))
    }
}

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    AddAssign<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(rhs.1);
    }
}

impl<'r, FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    AddAssign<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(&rhs.0);
        self.1.add_assign(&rhs.1);
    }
}

impl<FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    SubAssign<Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(rhs.1);
    }
}

impl<'r, FirstGroupElement: crate::GroupElement, SecondGroupElement: crate::GroupElement>
    SubAssign<&'r Self> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(&rhs.0);
        self.1.sub_assign(&rhs.1);
    }
}

impl<
        const LIMBS: usize,
        FirstGroupElement: crate::GroupElement,
        SecondGroupElement: crate::GroupElement,
    > Mul<Uint<LIMBS>> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scale(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: crate::GroupElement,
        SecondGroupElement: crate::GroupElement,
    > Mul<&'r GroupElement<FirstGroupElement, SecondGroupElement>>
    for bounded_natural_numbers_group::GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<FirstGroupElement, SecondGroupElement>;

    fn mul(self, rhs: &'r GroupElement<FirstGroupElement, SecondGroupElement>) -> Self::Output {
        rhs.scale_bounded(&self.value(), self.upper_bound_bits)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: crate::GroupElement,
        SecondGroupElement: crate::GroupElement,
    > Mul<&'r GroupElement<FirstGroupElement, SecondGroupElement>>
    for bounded_integers_group::GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
    Int<LIMBS>: Encoding,
{
    type Output = GroupElement<FirstGroupElement, SecondGroupElement>;

    fn mul(self, rhs: &'r GroupElement<FirstGroupElement, SecondGroupElement>) -> Self::Output {
        rhs.scale_integer_bounded(&self.value(), self.upper_bound_bits)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: crate::GroupElement,
        SecondGroupElement: crate::GroupElement,
    > Mul<&'r Uint<LIMBS>> for GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = Self;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scale(rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: crate::GroupElement,
        SecondGroupElement: crate::GroupElement,
    > Mul<Uint<LIMBS>> for &'r GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = GroupElement<FirstGroupElement, SecondGroupElement>;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scale(&rhs)
    }
}

impl<
        'r,
        const LIMBS: usize,
        FirstGroupElement: crate::GroupElement,
        SecondGroupElement: crate::GroupElement,
    > Mul<&'r Uint<LIMBS>> for &'r GroupElement<FirstGroupElement, SecondGroupElement>
{
    type Output = GroupElement<FirstGroupElement, SecondGroupElement>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scale(rhs)
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
