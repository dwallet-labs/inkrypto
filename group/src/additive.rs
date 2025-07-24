// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

/// An element of the additive group of integers for an odd modulo `n = modulus`
/// $\mathbb{Z}_n^+$.
pub type GroupElement<const LIMBS: usize> = private::GroupElement<LIMBS, 0>;

/// The public parameters of the additive group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$.
pub type PublicParameters<const LIMBS: usize> = private::PublicParameters<LIMBS, 0>;

/// An element of the additive group of integers for a prime modulo `p = modulus`
/// $\mathbb{Z}_p^+$.
pub type PrimeGroupElement<const LIMBS: usize> = private::GroupElement<LIMBS, 1>;

/// The public parameters of the additive group of integers modulo a prime `p = modulus`
/// $\mathbb{Z}_p^+$.
pub type PrimePublicParameters<const LIMBS: usize> = private::PublicParameters<LIMBS, 1>;

mod private {
    use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

    use crypto_bigint::modular::SafeGcdInverter;
    use crypto_bigint::{
        modular::{MontyForm, MontyParams},
        Concat, Encoding, NonZero, Odd, PrecomputeInverter, RandomMod, Split, Uint,
    };
    use serde::{Deserialize, Serialize};
    use subtle::ConditionallySelectable;
    use subtle::{Choice, ConstantTimeEq, CtOption};

    use crate::linear_combination::linearly_combine_bounded_or_scale;
    use crate::{
        BoundedGroupElement, CsRng, CyclicGroupElement, Error, GroupElement as _, Invert,
        KnownOrderGroupElement, KnownOrderScalar, LinearlyCombinable, MulByGenerator,
        PrimeGroupElement, Reduce, Samplable, Scale, Transcribeable,
    };

    #[derive(PartialEq, Eq, Clone, Debug, Copy)]
    pub struct GroupElement<const LIMBS: usize, const IS_PRIME: usize>(pub MontyForm<LIMBS>);

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> Samplable
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn sample(
            public_parameters: &Self::PublicParameters,
            rng: &mut impl CsRng,
        ) -> crate::Result<Self> {
            Self::new(
                Uint::<LIMBS>::random_mod(rng, &NonZero::new(*public_parameters.modulus).unwrap()),
                public_parameters,
            )
        }

        fn sample_randomizer(
            public_parameters: &Self::PublicParameters,
            rng: &mut impl CsRng,
        ) -> crate::Result<Self> {
            Self::sample(public_parameters, rng)
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> LinearlyCombinable
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
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
        ) -> crate::Result<Self> {
            linearly_combine_bounded_or_scale(bases_and_multiplicands, exponent_bits, false)
        }
    }

    #[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
    pub struct PublicParameters<const LIMBS: usize, const IS_PRIME: usize>
    where
        Uint<LIMBS>: Encoding,
    {
        pub modulus: Odd<Uint<LIMBS>>,
        is_prime: bool,
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> Transcribeable for PublicParameters<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Encoding,
    {
        type CanonicalRepresentation = Self;
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> PublicParameters<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Encoding,
    {
        pub fn new(modulus: Uint<LIMBS>) -> crate::Result<Self> {
            let modulus = Odd::new(modulus)
                .into_option()
                .ok_or(Error::InvalidPublicParameters)?;
            let is_prime = IS_PRIME == 1;

            Ok(Self { modulus, is_prime })
        }
    }

    impl<const LIMBS: usize> From<Odd<Uint<LIMBS>>> for PublicParameters<LIMBS, 0>
    where
        Uint<LIMBS>: Encoding,
    {
        fn from(modulus: Odd<Uint<LIMBS>>) -> Self {
            Self {
                modulus,
                is_prime: false,
            }
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> crate::GroupElement
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        type Value = Uint<LIMBS>;

        fn value(&self) -> Self::Value {
            self.0.retrieve()
        }

        type PublicParameters = PublicParameters<LIMBS, IS_PRIME>;

        fn new(
            value: Self::Value,
            public_parameters: &Self::PublicParameters,
        ) -> crate::Result<Self> {
            Ok(Self(MontyForm::<LIMBS>::new(
                &value,
                MontyParams::<LIMBS>::new(public_parameters.modulus),
            )))
        }

        fn neutral(&self) -> Self {
            Self(MontyForm::<LIMBS>::zero(*self.0.params()))
        }

        fn neutral_from_public_parameters(
            public_parameters: &Self::PublicParameters,
        ) -> crate::Result<Self> {
            Ok(Self(MontyForm::<LIMBS>::zero(MontyParams::<LIMBS>::new(
                public_parameters.modulus,
            ))))
        }

        fn scale<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
            let scalar = MontyForm::new(
                &scalar.reduce(&NonZero::new(**self.0.params().modulus()).unwrap()),
                *self.0.params(),
            );

            Self(self.0 * scalar)
        }

        fn scale_bounded<const RHS_LIMBS: usize>(
            &self,
            scalar: &Uint<RHS_LIMBS>,
            scalar_bits: u32,
        ) -> Self {
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

        fn double(&self) -> Self {
            Self(self.0 + self.0)
        }

        fn double_vartime(&self) -> Self {
            self.double()
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> ConstantTimeEq
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn ct_eq(&self, other: &Self) -> Choice {
            self.0.ct_eq(&other.0)
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> ConditionallySelectable
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
            Self(
                <MontyForm<LIMBS> as ConditionallySelectable>::conditional_select(
                    &a.0, &b.0, choice,
                ),
            )
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize>
        From<GroupElement<LIMBS, IS_PRIME>> for PublicParameters<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn from(value: GroupElement<LIMBS, IS_PRIME>) -> Self {
            PublicParameters {
                modulus: *value.0.params().modulus(),
                is_prime: IS_PRIME == 1,
            }
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> Neg for GroupElement<LIMBS, IS_PRIME> {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self(self.0.neg())
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> Add<Self> for GroupElement<LIMBS, IS_PRIME> {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Self(self.0.add(&rhs.0))
        }
    }

    impl<'r, const LIMBS: usize, const IS_PRIME: usize> Add<&'r Self>
        for GroupElement<LIMBS, IS_PRIME>
    {
        type Output = Self;

        fn add(self, rhs: &'r Self) -> Self::Output {
            Self(self.0.add(&rhs.0))
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> Sub<Self> for GroupElement<LIMBS, IS_PRIME> {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output {
            Self(self.0.sub(&rhs.0))
        }
    }

    impl<'r, const LIMBS: usize, const IS_PRIME: usize> Sub<&'r Self>
        for GroupElement<LIMBS, IS_PRIME>
    {
        type Output = Self;

        fn sub(self, rhs: &'r Self) -> Self::Output {
            Self(self.0.sub(&rhs.0))
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> AddAssign<Self> for GroupElement<LIMBS, IS_PRIME> {
        fn add_assign(&mut self, rhs: Self) {
            self.0.add_assign(rhs.0)
        }
    }

    impl<'r, const LIMBS: usize, const IS_PRIME: usize> AddAssign<&'r Self>
        for GroupElement<LIMBS, IS_PRIME>
    {
        fn add_assign(&mut self, rhs: &'r Self) {
            self.0.add_assign(rhs.0)
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> SubAssign<Self> for GroupElement<LIMBS, IS_PRIME> {
        fn sub_assign(&mut self, rhs: Self) {
            self.0.sub_assign(rhs.0)
        }
    }

    impl<'r, const LIMBS: usize, const IS_PRIME: usize> SubAssign<&'r Self>
        for GroupElement<LIMBS, IS_PRIME>
    {
        fn sub_assign(&mut self, rhs: &'r Self) {
            self.0.sub_assign(rhs.0)
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize>
        MulByGenerator<Uint<LIMBS>> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn mul_by_generator(&self, scalar: Uint<LIMBS>) -> Self {
            self.mul_by_generator(&scalar)
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize>
        MulByGenerator<&Uint<LIMBS>> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn mul_by_generator(&self, scalar: &Uint<LIMBS>) -> Self {
            // In the additive group, the generator is 1 and multiplication by it is simply returning
            // the same number modulu the order (which is taken care of in `DynResidue`).
            Self(MontyForm::new(scalar, *self.0.params()))
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize>
        BoundedGroupElement<LIMBS> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
            *public_parameters.modulus
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> CyclicGroupElement
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn generator(&self) -> Self {
            Self(MontyForm::<LIMBS>::one(*self.0.params()))
        }

        fn generator_value_from_public_parameters(
            _public_parameters: &Self::PublicParameters,
        ) -> Self::Value {
            Uint::<LIMBS>::ONE
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> Mul<Self> for GroupElement<LIMBS, IS_PRIME> {
        type Output = Self;

        fn mul(self, rhs: Self) -> Self::Output {
            Self(self.0.mul(&rhs.0))
        }
    }

    impl<'r, const LIMBS: usize, const IS_PRIME: usize> Mul<&'r Self>
        for GroupElement<LIMBS, IS_PRIME>
    {
        type Output = Self;

        fn mul(self, rhs: &'r Self) -> Self::Output {
            Self(self.0.mul(&rhs.0))
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> Mul<Self> for &GroupElement<LIMBS, IS_PRIME> {
        type Output = GroupElement<LIMBS, IS_PRIME>;

        fn mul(self, rhs: Self) -> Self::Output {
            GroupElement(self.0.mul(&rhs.0))
        }
    }

    impl<'r, const LIMBS: usize, const IS_PRIME: usize> Mul<&'r Self>
        for &'r GroupElement<LIMBS, IS_PRIME>
    {
        type Output = GroupElement<LIMBS, IS_PRIME>;

        fn mul(self, rhs: &'r Self) -> Self::Output {
            GroupElement(self.0.mul(&rhs.0))
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> Mul<Uint<LIMBS>>
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        type Output = Self;

        fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
            self.scale(&rhs)
        }
    }

    impl<'r, const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize>
        Mul<&'r Uint<LIMBS>> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        type Output = Self;

        fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
            self.scale(rhs)
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> Mul<Uint<LIMBS>>
        for &GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        type Output = GroupElement<LIMBS, IS_PRIME>;

        fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
            self.scale(&rhs)
        }
    }

    impl<'r, const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize>
        Mul<&'r Uint<LIMBS>> for &'r GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        type Output = GroupElement<LIMBS, IS_PRIME>;

        fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
            self.scale(rhs)
        }
    }

    impl<const LIMBS: usize, const IS_PRIME: usize> From<GroupElement<LIMBS, IS_PRIME>>
        for Uint<LIMBS>
    {
        fn from(value: GroupElement<LIMBS, IS_PRIME>) -> Self {
            value.0.retrieve()
        }
    }

    impl<'r, const LIMBS: usize, const IS_PRIME: usize> From<&'r GroupElement<LIMBS, IS_PRIME>>
        for Uint<LIMBS>
    {
        fn from(value: &'r GroupElement<LIMBS, IS_PRIME>) -> Self {
            value.0.retrieve()
        }
    }

    impl<
            const LIMBS: usize,
            const WIDE_LIMBS: usize,
            const UNSAT_LIMBS: usize,
            const IS_PRIME: usize,
        > Invert for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>,
            Output = Uint<LIMBS>,
        >,
    {
        fn invert(&self) -> CtOption<Self> {
            let inv = <MontyForm<LIMBS> as crypto_bigint::Invert>::invert(&self.0);
            let default = self.neutral().0;

            CtOption::new(Self(inv.unwrap_or(default)), inv.is_some())
        }
    }

    impl<
            const LIMBS: usize,
            const WIDE_LIMBS: usize,
            const UNSAT_LIMBS: usize,
            const IS_PRIME: usize,
        > Scale<Self> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>,
            Output = Uint<LIMBS>,
        >,
    {
        fn scale_randomized_accelerated(
            &self,
            scalar: &Self,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
            scalar * self
        }

        fn scale_vartime_accelerated(
            &self,
            scalar: &Self,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_vartime(&scalar.value())
        }

        fn scale_randomized_bounded_accelerated(
            &self,
            scalar: &Self,
            _public_parameters: &Self::PublicParameters,
            scalar_bits: u32,
        ) -> Self {
            self.scale_bounded(&scalar.value(), scalar_bits)
        }

        fn scale_bounded_vartime_accelerated(
            &self,
            scalar: &Self,
            _public_parameters: &Self::PublicParameters,
            scalar_bits: u32,
        ) -> Self {
            self.scale_bounded_vartime(&scalar.value(), scalar_bits)
        }
    }

    impl<
            const LIMBS: usize,
            const WIDE_LIMBS: usize,
            const UNSAT_LIMBS: usize,
            const IS_PRIME: usize,
        > Scale<Uint<LIMBS>> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>,
            Output = Uint<LIMBS>,
        >,
    {
        fn scale_randomized_accelerated(
            &self,
            scalar: &Uint<LIMBS>,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale(scalar)
        }

        fn scale_vartime_accelerated(
            &self,
            scalar: &Uint<LIMBS>,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_vartime(scalar)
        }

        fn scale_randomized_bounded_accelerated(
            &self,
            scalar: &Uint<LIMBS>,
            _public_parameters: &Self::PublicParameters,
            scalar_bits: u32,
        ) -> Self {
            self.scale_bounded(scalar, scalar_bits)
        }

        fn scale_bounded_vartime_accelerated(
            &self,
            scalar: &Uint<LIMBS>,
            _public_parameters: &Self::PublicParameters,
            scalar_bits: u32,
        ) -> Self {
            self.scale_bounded_vartime(scalar, scalar_bits)
        }
    }

    impl<
            const LIMBS: usize,
            const WIDE_LIMBS: usize,
            const UNSAT_LIMBS: usize,
            const IS_PRIME: usize,
        > KnownOrderScalar<LIMBS> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>,
            Output = Uint<LIMBS>,
        >,
    {
    }

    impl<
            const LIMBS: usize,
            const WIDE_LIMBS: usize,
            const UNSAT_LIMBS: usize,
            const IS_PRIME: usize,
        > KnownOrderGroupElement<LIMBS> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>,
            Output = Uint<LIMBS>,
        >,
    {
        type Scalar = Self;

        fn order_from_public_parameters(public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
            *public_parameters.modulus
        }
    }

    impl<const LIMBS: usize> MulByGenerator<Self> for GroupElement<LIMBS, 1>
    where
        Uint<LIMBS>: Encoding,
    {
        fn mul_by_generator(&self, scalar: Self) -> Self {
            scalar
        }
    }

    impl<'a, const LIMBS: usize> MulByGenerator<&'a Self> for GroupElement<LIMBS, 1>
    where
        Uint<LIMBS>: Encoding,
    {
        fn mul_by_generator(&self, scalar: &'a Self) -> Self {
            *scalar
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
        PrimeGroupElement<LIMBS> for GroupElement<LIMBS, 1>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
        Odd<Uint<LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>,
            Output = Uint<LIMBS>,
        >,
    {
    }
}
