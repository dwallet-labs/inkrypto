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

    use crypto_bigint::{
        modular::{MontyForm, MontyParams},
        Concat, Encoding, Int, NonZero, Odd, RandomMod, Split, Uint,
    };
    use serde::{Deserialize, Serialize};
    use subtle::ConditionallySelectable;
    use subtle::{Choice, ConstantTimeEq, CtOption};

    use crate::linear_combination::linearly_combine_bounded;
    use crate::{
        BoundedGroupElement, CsRng, CyclicGroupElement, Error, ErrorKind, GroupElement as _,
        Invert, KnownOrderGroupElement, KnownOrderScalar, MulByGenerator, PrimeGroupElement,
        Reduce, Samplable, Scale, Transcribeable,
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
                .ok_or_else(|| Error::from(ErrorKind::InvalidPublicParameters))?;
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

        fn scale<const RHS_LIMBS: usize>(
            &self,
            scalar: &Uint<RHS_LIMBS>,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
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
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            crate::scale_bounded(self, scalar, scalar_bits, true, public_parameters)
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
            crate::scale_integer_bounded(self, integer, scalar_bits, public_parameters)
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
            self.scale_integer_bounded_vartime(
                scalar,
                scalar.abs().bits_vartime(),
                public_parameters,
            )
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
            self.scale_integer_public_base_bounded(
                integer,
                Uint::<RHS_LIMBS>::BITS,
                public_parameters,
            )
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
            self.scale_integer_randomized_bounded(
                integer,
                Uint::<RHS_LIMBS>::BITS,
                public_parameters,
            )
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

        fn add_randomized(
            &self,
            other: &Self,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
            *self + other
        }

        fn add_vartime(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
            *self + other
        }

        fn sub_randomized(
            &self,
            other: &Self,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
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

        fn add_constant_time(
            &self,
            other: &Self,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
            Self(self.0.add(&other.0))
        }

        fn sub_constant_time(
            &self,
            other: &Self,
            _public_parameters: &Self::PublicParameters,
        ) -> Self {
            Self(self.0.sub(&other.0))
        }

        fn neg_constant_time(&self, _public_parameters: &Self::PublicParameters) -> Self {
            Self(self.0.neg())
        }

        fn linearly_combine_bounded<const RHS_LIMBS: usize>(
            bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
            exponent_bits: u32,
            public_parameters: &Self::PublicParameters,
        ) -> crate::Result<Self> {
            linearly_combine_bounded(
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
            linearly_combine_bounded(
                bases_and_multiplicands,
                exponent_bits,
                false,
                public_parameters,
            )
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
            let rhs = MontyForm::new(
                &rhs.reduce(&NonZero::new(**self.0.params().modulus()).unwrap()),
                *self.0.params(),
            );
            Self(self.0 * rhs)
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
            let rhs = MontyForm::new(
                &rhs.reduce(&NonZero::new(**self.0.params().modulus()).unwrap()),
                *self.0.params(),
            );
            Self(self.0 * rhs)
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
            let rhs = MontyForm::new(
                &rhs.reduce(&NonZero::new(**self.0.params().modulus()).unwrap()),
                *self.0.params(),
            );
            GroupElement(self.0 * rhs)
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
            let rhs = MontyForm::new(
                &rhs.reduce(&NonZero::new(**self.0.params().modulus()).unwrap()),
                *self.0.params(),
            );
            GroupElement(self.0 * rhs)
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

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> Invert
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn invert(&self) -> CtOption<Self> {
            let inv = <MontyForm<LIMBS> as crypto_bigint::Invert>::invert(&self.0);
            let default = self.neutral().0;

            CtOption::new(Self(inv.unwrap_or(default)), inv.is_some())
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> Scale<Self>
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        fn scale_by(&self, scalar: &Self, public_parameters: &Self::PublicParameters) -> Self {
            self.scale(&scalar.value(), public_parameters)
        }

        fn scale_vartime_by(
            &self,
            scalar: &Self,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_vartime(&scalar.value(), public_parameters)
        }

        fn scale_bounded_by(
            &self,
            scalar: &Self,
            scalar_bits: u32,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_bounded(&scalar.value(), scalar_bits, public_parameters)
        }

        fn scale_bounded_vartime_by(
            &self,
            scalar: &Self,
            scalar_bits: u32,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_bounded_vartime(&scalar.value(), scalar_bits, public_parameters)
        }

        fn scale_vartime_scalar_by(
            &self,
            scalar: &Self,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_vartime_scalar(&scalar.value(), public_parameters)
        }

        fn scale_public_base_by(
            &self,
            scalar: &Self,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_public_base(&scalar.value(), public_parameters)
        }

        fn scale_public_base_bounded_by(
            &self,
            scalar: &Self,
            scalar_bits: u32,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_public_base_bounded(&scalar.value(), scalar_bits, public_parameters)
        }

        fn scale_randomized_by(
            &self,
            scalar: &Self,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_randomized(&scalar.value(), public_parameters)
        }

        fn scale_randomized_bounded_by(
            &self,
            scalar: &Self,
            scalar_bits: u32,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_randomized_bounded(&scalar.value(), scalar_bits, public_parameters)
        }

        fn scale_randomized_vartime_scalar_by(
            &self,
            scalar: &Self,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_randomized_vartime_scalar(&scalar.value(), public_parameters)
        }

        fn scale_randomized_public_base_by(
            &self,
            scalar: &Self,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_randomized_public_base(&scalar.value(), public_parameters)
        }

        fn scale_randomized_public_base_bounded_by(
            &self,
            scalar: &Self,
            scalar_bits: u32,
            public_parameters: &Self::PublicParameters,
        ) -> Self {
            self.scale_randomized_public_base_bounded(
                &scalar.value(),
                scalar_bits,
                public_parameters,
            )
        }
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize> KnownOrderScalar<LIMBS>
        for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
    }

    impl<const LIMBS: usize, const WIDE_LIMBS: usize, const IS_PRIME: usize>
        KnownOrderGroupElement<LIMBS> for GroupElement<LIMBS, IS_PRIME>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
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

    impl<const LIMBS: usize, const WIDE_LIMBS: usize> PrimeGroupElement<LIMBS>
        for GroupElement<LIMBS, 1>
    where
        Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
        Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
    }
}
