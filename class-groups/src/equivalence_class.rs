// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::ops::{BitAnd, Deref};

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crypto_bigint::{
    Concat, ConstantTimeSelect, Encoding, Int, Integer, NonZero, NonZeroUint, Split, Uint, U64,
};
use serde::{Deserialize, Serialize};

pub use public_parameters::PublicParameters;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::helpers::{math, CtMinMax};
use crate::randomizer::{ExponentWithFormMask, ScalingRandomizer};
use crate::DEFAULT_ACCELERATOR_FOLDING_DEGREE;
use crate::{discriminant::Discriminant, ibqf::Ibqf, Error};

mod group_element;
pub(crate) mod public_parameters;

/// Class of equivalent [Ibqf]s.
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
///  Use [`CompactIbqf`] instead.
#[derive(Clone, Debug, Eq, Copy, Serialize, Deserialize)]
pub struct EquivalenceClass<const DISCRIMINANT_LIMBS: usize>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    representative: Ibqf<DISCRIMINANT_LIMBS>,
    discriminant: Discriminant<DISCRIMINANT_LIMBS>,
}

impl<const DISCRIMINANT_LIMBS: usize> EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    /// Constructs another element in the same class with `representative`.
    ///
    /// Note: does not verify whether `representative` belongs to the same class as `self`.
    fn element_with_representative(&self, representative: Ibqf<DISCRIMINANT_LIMBS>) -> Self {
        Self {
            representative,
            discriminant: self.discriminant,
        }
    }

    /// Read-only access to this class' representative.
    pub fn representative(&self) -> &Ibqf<DISCRIMINANT_LIMBS> {
        &self.representative
    }

    /// Read-only access to this class' discriminant.
    pub fn discriminant(&self) -> &Discriminant<DISCRIMINANT_LIMBS> {
        &self.discriminant
    }

    /// Get the unit element for the Class Group this equivalence class
    /// belongs to.
    pub fn unit(&self) -> Self {
        Self::unit_for_class(&self.discriminant)
    }

    /// Get the unit element for the Class Group identified by `discriminant`.
    pub fn unit_for_class(discriminant: &Discriminant<DISCRIMINANT_LIMBS>) -> Self {
        let unit = Ibqf::unit_for_discriminant(discriminant.deref())
            .expect("this unit exists; self.discriminant is a valid discriminant");

        Self {
            representative: unit,
            discriminant: *discriminant,
        }
    }

    /// Whether this is the `unit` element.
    /// Assumes `representative` is reduced.
    pub fn is_unit_vartime(&self) -> bool {
        self.representative.is_principal_vartime()
    }

    /// Whether this is the `unit` element.
    /// Assumes `representative` is reduced.
    pub fn is_unit(&self) -> Choice {
        self.representative.is_principal()
    }

    /// Whether `self` and `other` belong to the same class.
    /// This is the case when they have the same discriminant.
    pub(crate) fn is_from_the_same_class_as(&self, other: &Self) -> bool {
        self.discriminant.ct_eq(&other.discriminant).into()
    }

    /// Returns a negated copy of `self` if `c` is truthy, otherwise return `self`.
    pub(crate) fn wrapping_negate_if(&self, c: Choice) -> Self {
        self.element_with_representative(self.representative.inverse_if(c))
    }
}

/// A trait that captures the operations of an `EquivalenceClass`, to be used in order to avoid const-generic mess.
pub trait EquivalenceClassOps<const DISCRIMINANT_LIMBS: usize>: Sized
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    type MultiFoldNupowAccelerator;

    /// Compute `self^exp`.
    ///
    /// ### Randomized
    /// Assumes `self` to be a random form. With this assumption in place, a faster exponentation
    /// algorithm can be exploited. Might return `None` if the assumption proves incorrect.
    fn pow_randomized<const EXPONENT_LIMBS: usize>(&self, exp: &Uint<EXPONENT_LIMBS>) -> Self {
        self.pow_bounded_randomized(exp, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Compute `self^exp`.
    ///
    /// ### Randomized
    /// Assumes `self` to be a random form. With this assumption in place, a faster exponentation
    /// algorithm can be exploited. Might return `None` if the assumption proves incorrect.
    ///
    /// ### Public Base
    /// Assumes `self` is public, and can be leaked in the time-pattern during variable time acceleration.
    fn pow_public_base_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        self.pow_public_base_bounded_randomized(exp, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Compute `self^exp`.
    ///
    /// ### Randomized
    /// Assumes `self` to be a random form. With this assumption in place, a faster exponentation
    /// algorithm can be exploited. Might return `None` if the assumption proves incorrect.
    ///
    /// ### Public Base
    /// Assumes `self` is public, and can be leaked in the time-pattern during variable time acceleration.
    fn pow_public_base_integer_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Int<EXPONENT_LIMBS>,
    ) -> Self {
        self.pow_public_base_integer_bounded_randomized(exp, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Compute `self^e`, with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// ### Randomized
    /// Assumes `self` is a random form. With this assumption in place, a faster
    /// exponentation algorithm can be exploited. Will return an `Error` if the assumption proves
    /// incorrect.
    fn pow_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self;

    /// Compute `self^e`, with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    ///
    /// ### Public Base
    /// Assumes `self` is public, and can be leaked in the time-pattern during variable time acceleration.
    fn pow_public_base_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self;

    /// Compute `self^e`, with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// ### Randomized
    /// Assumes `self` is a random form. With this assumption in place, a faster
    /// exponentation algorithm can be exploited. Will return an `Error` if the assumption proves
    /// incorrect.
    ///
    /// ### Public Base
    /// Assumes `self` is public, and can be leaked in the time-pattern during variable time acceleration.
    fn pow_public_base_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self;

    /// Compute `self^e`, with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// ### Randomized
    /// Assumes `self` is a random form. With this assumption in place, a faster
    /// exponentation algorithm can be exploited. Will return an `Error` if the assumption proves
    /// incorrect.
    ///
    /// ### Public Base
    /// Assumes `self` is public, and can be leaked in the time-pattern during variable time acceleration.
    fn pow_public_base_integer_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Int<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self;

    /// Raise `self` to the `exp`, leveraging a [MultiFoldNupowAccelerator].
    fn pow_multifold_accelerated<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
    ) -> Self;

    /// Compute `self^e`, with `e` the integers represented by the `exp_bits` least significant bits
    /// of `exp`. This operation leverages a [MultiFoldNupowAccelerator].
    ///
    /// ### Randomized
    /// Assumes `self` is a random form. With this assumption in place, a faster
    /// exponentation algorithm can be exploited. Will return an `Error` if the assumption proves
    /// incorrect.
    fn pow_bounded_multifold_accelerated_randomized<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self;

    /// Compute `self^e`, with `e` the integers represented by the `exp_bits` least significant bits
    /// of `exp`. This operation leverages a [MultiFoldNupowAccelerator].
    fn pow_bounded_multifold_accelerated<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self;

    /// Compute `self^e`, where `e` is the integer represented by the `exp_bits` least significant
    /// bits of `exp` leveraging a [MultiFoldNupowAccelerator].
    ///
    /// ### Vartime
    /// This function executes in variable time w.r.t. `self.representative` and `exp`.
    fn pow_bounded_multifold_accelerated_vartime<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self;

    /// Raise `self` to the `exp`, leveraging a [MultiFoldNupowAccelerator].
    ///
    /// ### Vartime
    /// This function executes in variable time w.r.t. `self.representative` and `exp`.
    fn pow_multifold_accelerated_vartime<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
    ) -> Self;
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize>
    EquivalenceClassOps<DISCRIMINANT_LIMBS> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>;

    fn pow_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let exp_bits = u32::ct_min(&exp_bits, &Uint::<EXPONENT_LIMBS>::BITS);
        let representative = self.representative.nupow_bounded_randomized(exp, exp_bits);
        self.element_with_representative(representative)
    }

    fn pow_public_base_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let exp_bits = u32::ct_min(&exp_bits, &Uint::<EXPONENT_LIMBS>::BITS);
        let acc = self
            .get_multifold_accelerator_vartime(DEFAULT_ACCELERATOR_FOLDING_DEGREE, exp_bits)
            .expect("DEFAULT_ACCELERATOR_FOLDING_DEGREE is not too large");
        Self::pow_bounded_multifold_accelerated(&acc, exp, exp_bits)
    }

    fn pow_public_base_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let exp_bits = u32::ct_min(&exp_bits, &Uint::<EXPONENT_LIMBS>::BITS);
        let acc = self
            .get_multifold_accelerator_vartime(DEFAULT_ACCELERATOR_FOLDING_DEGREE, exp_bits)
            .expect("DEFAULT_ACCELERATOR_FOLDING_DEGREE is not too large");
        Self::pow_bounded_multifold_accelerated_randomized(&acc, exp, exp_bits)
    }

    fn pow_public_base_integer_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Int<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let (abs_exp, exp_is_negative) = exp.abs_sign();
        self.pow_public_base_bounded_randomized(&abs_exp, exp_bits)
            .wrapping_negate_if(exp_is_negative.into())
    }

    fn pow_multifold_accelerated<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        let encoding = accelerator.encode_exponent(exp);
        let representative = accelerator.pow(&encoding);
        accelerator
            .form()
            .element_with_representative(representative)
    }

    fn pow_bounded_multifold_accelerated_randomized<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let encoding = accelerator.encode_bounded_exponent(exp, exp_bits);
        let representative = accelerator.pow_randomized(&encoding);
        accelerator
            .form()
            .element_with_representative(representative)
    }

    fn pow_bounded_multifold_accelerated<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let encoding = accelerator.encode_bounded_exponent(exp, exp_bits);
        let representative = accelerator.pow(&encoding);
        accelerator
            .form()
            .element_with_representative(representative)
    }

    fn pow_bounded_multifold_accelerated_vartime<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let encoding = accelerator.encode_bounded_exponent(exp, exp_bits);
        let representative = accelerator.pow_vartime(&encoding);
        accelerator
            .form()
            .element_with_representative(representative)
    }

    fn pow_multifold_accelerated_vartime<const EXPONENT_LIMBS: usize>(
        accelerator: &MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>,
        exp: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        let encoding = accelerator.encode_exponent_vartime(exp);
        let representative = accelerator.pow_vartime(&encoding);
        accelerator
            .form()
            .element_with_representative(representative)
    }
}

impl<
        const HALF: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>:
        Encoding + Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Construct a new [EquivalenceClass] from an `a`, `b` and `discriminant`.
    pub fn new_from_coefficients(
        a: NonZeroUint<DISCRIMINANT_LIMBS>,
        b: Int<DISCRIMINANT_LIMBS>,
        discriminant: Discriminant<DISCRIMINANT_LIMBS>,
    ) -> CtOption<Self> {
        Ibqf::new(a, b, &discriminant).map(|representative| Self {
            representative,
            discriminant,
        })
    }

    /// Given discriminant `∆` and prime `p` s.t. `(∆|p) = 1` with `(·|·)` the Kronecker symbol,
    /// constructs the equivalence class for the form `f = (p, ..., ...)` in `CL(∆)`.
    /// Such a form is called a _prime form_.
    ///
    /// Executes in variable time w.r.t. `discriminant`.
    ///
    /// Ref: Section 5.5.1 in "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    ///
    /// Note: assumes `∆` and prime `p` s.t. Kronecker Symbol `(∆|p) = 1`; returns an error otherwise.
    pub(crate) fn prime_form_vartime_discriminant(
        discriminant: Discriminant<DISCRIMINANT_LIMBS>,
        p: NonZero<Uint<HALF>>,
    ) -> Result<EquivalenceClass<DISCRIMINANT_LIMBS>, Error> {
        let d_mod_p = discriminant.deref().get().normalized_rem(&p);
        let mut b = math::sqrt_mod(&d_mod_p, &p)?;

        // Ensure b mod p has the same parity as the discriminant
        // Otherwise, use -b mod p.
        let unequal_parity = b.is_odd().ct_ne(&discriminant.deref().is_odd().into());
        b = Uint::ct_select(&b, &p.wrapping_sub(&b), unequal_parity);

        let b = CtOption::from(b.try_into_int())
            .into_option()
            .ok_or(Error::InternalError)?;

        EquivalenceClass::new_from_coefficients_reduced_vartime_discriminant(p, b, discriminant)
            .into_option()
            .ok_or(Error::InternalError)
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize> EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Split<Output = Uint<HALF>>,
{
    /// Variant of [Self::new_from_coefficients] that assumes the constructed form will be reduced;
    /// returns a `None` if this assumption is invalid.
    ///
    /// Executes in variable time w.r.t. `self.discriminant`.
    pub fn new_from_coefficients_reduced_vartime_discriminant(
        a: NonZeroUint<HALF>,
        b: Int<HALF>,
        discriminant: Discriminant<DISCRIMINANT_LIMBS>,
    ) -> CtOption<Self> {
        Ibqf::new_is_reduced_vartime_discriminant(a, b, &discriminant).map(|representative| Self {
            representative,
            discriminant,
        })
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize>
    EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Construct the [MultiFoldAccelerator] for this form, with the given `folding_degree` and
    /// targeted at exponents of size ~`target_bits`.
    ///
    /// Runs in time variable in `target_bits` and `self.representative`.
    pub fn get_multifold_accelerator_vartime(
        self,
        folding_degree: u32,
        target_bits: u32,
    ) -> Result<MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>, Error> {
        MultiFoldNupowAccelerator::new_vartime(self, folding_degree, target_bits)
    }

    /// Multiply `self` with `rhs`.
    pub fn mul(&self, rhs: &Self) -> Result<Self, Error> {
        if !self.is_from_the_same_class_as(rhs) {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let res = self.representative.nucomp(rhs.representative);
        Ok(self.element_with_representative(res))
    }

    /// Multiply `self` with `rhs`.
    ///
    /// ### Randomized
    /// Assumes `self` to be a random form. With this assumption in place, a faster multiplication
    /// algorithm can be exploited. Might return `None` if the assumption proves incorrect.
    pub fn mul_randomized(&self, rhs: &Self) -> Result<Self, Error> {
        if !self.is_from_the_same_class_as(rhs) {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let res = self.representative.nucomp_randomized(rhs.representative);
        Ok(self.element_with_representative(res))
    }

    /// Multiply `self` with `rhs`.
    ///
    /// This function is executed in time variable in `self.representative` and
    /// `rhs.representative`.
    pub fn mul_vartime(&self, rhs: &Self) -> Result<Self, Error> {
        if !self.is_from_the_same_class_as(rhs) {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let res = self.representative.nucomp_vartime(rhs.representative);
        Ok(self.element_with_representative(res))
    }

    /// Divide `self` by `rhs`.
    pub fn div(&self, rhs: &Self) -> Result<Self, Error> {
        if !self.is_from_the_same_class_as(rhs) {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let res = self.representative.nucompinv(rhs.representative);
        Ok(self.element_with_representative(res))
    }

    /// Divide `self` by `rhs`.
    ///
    /// This function executes in variable time w.r.t. both `self.representative` and
    /// `rhs.representative`.
    pub fn div_vartime(&self, rhs: &Self) -> Result<Self, Error> {
        if !self.is_from_the_same_class_as(rhs) {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let res = self.representative.nucompinv_vartime(&rhs.representative);
        Ok(self.element_with_representative(res))
    }

    /// Square `self`
    pub fn square(&self) -> Self {
        let res = self.representative.nudupl();
        self.element_with_representative(res)
    }

    /// Square `self`
    ///
    /// ### Randomized
    /// Assumes `self` to be a random form. With this assumption in place, a faster squaring
    /// algorithm can be exploited. Might return `None` if the assumption proves incorrect.
    pub fn square_randomized(&self) -> Self {
        let res = self.representative.nudupl_randomized();
        self.element_with_representative(res)
    }

    /// Square `self`.
    ///
    /// Executes in variable time w.r.t. `self.representative`.
    pub fn square_vartime(&self) -> Self {
        let res = self.representative.nudupl_vartime();
        self.element_with_representative(res)
    }

    /// Compute `self^exp`.
    pub fn pow<const EXPONENT_LIMBS: usize>(&self, exp: &Uint<EXPONENT_LIMBS>) -> Self {
        self.pow_bounded(exp, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Compute `self^exp`.
    ///
    /// Executes in variable time w.r.t. both `self` and `exp`.
    pub fn pow_vartime<const EXPONENT_LIMBS: usize>(&self, exp: &Uint<EXPONENT_LIMBS>) -> Self {
        let res = self.representative.nupow_vartime(exp);
        self.element_with_representative(res)
    }

    /// Compute `self^{2^k}`
    ///
    /// Executes in variable time w.r.t. both `self` and `k`.
    pub fn pow_2k_vartime(&self, k: u32) -> Self {
        let res = self.representative.nupow2k_vartime(k);
        self.element_with_representative(res)
    }

    /// Compute `self^{2^k}`
    ///
    /// Executes in variable time w.r.t. `k` only.
    ///
    /// ### Randomized
    /// Assumes `self` is a random form. With this assumption in place, a faster exponentation
    /// algorithm can be exploited. Might return `None` if the assumption proves incorrect.
    pub fn pow_2k_randomized(&self, k: u32) -> Self {
        let res = self.representative.nupow2k_randomized(k);
        self.element_with_representative(res)
    }

    /// Compute `base^{2^b} * self^exp`, with `b = exp.bits()`.
    ///
    /// Executes in variable time w.r.t. `self`, `base` and `exp`.
    pub fn pow_with_base_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exp: &Uint<EXPONENT_LIMBS>,
    ) -> Self {
        let res = self
            .representative
            .nupow_with_base_vartime(base.representative, exp);
        self.element_with_representative(res)
    }

    /// Compute `self^e`, with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    pub fn pow_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let exp_bits = u32::ct_min(&exp_bits, &Uint::<EXPONENT_LIMBS>::BITS);

        let representative = self.representative.nupow_bounded(exp, exp_bits);
        self.element_with_representative(representative)
    }

    /// Compute `base^{2^exp_bits} * self^e`, where `e` is the integer represented by the `exp_bits`
    /// least significant bits of `exp`.
    ///
    /// ### Bounded
    /// Requires `exp_bits ≤ Uint::<EXPONENT_LIMBS>::BITS`; will return `None` otherwise.
    /// Executes in variable time w.r.t. `exp_bits`.
    ///
    /// ### Randomized
    /// Assumes `self` is a random form. With this assumption in place, a faster
    /// exponentation algorithm can be exploited. Will return an `Error` if the assumption proves
    /// incorrect.
    pub fn pow_bounded_with_base_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Result<Self, Error> {
        if exp_bits > Uint::<EXPONENT_LIMBS>::BITS {
            return Err(Error::InvalidParameters);
        }

        let res = self.representative.nupow_bounded_randomized_with_base(
            base.representative,
            exp,
            exp_bits,
        );
        Ok(self.element_with_representative(res))
    }

    /// Variation to [Self::pow_bounded_randomized_with_base] that accepts an [Int] exponent.
    pub fn pow_bounded_int_randomized_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exp: &Int<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Result<Self, Error> {
        let (abs_exp, exp_is_negative) = exp.abs_sign();
        let mut res = self.pow_bounded_with_base_randomized(base, &abs_exp, exp_bits)?;
        res.representative = res.representative.inverse_if(exp_is_negative.into());
        Ok(res)
    }

    /// Compute `self^e`, where `e` is the integer represented by the `exp_bits` least significant
    /// bits of `exp`.
    ///
    /// Executes in variable time w.r.t. `self.representative` and `exp`.
    pub fn pow_bounded_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let res = self.representative.nupow_bounded_vartime(exp, exp_bits);
        self.element_with_representative(res)
    }

    /// Compute `base^{2^exp_bits} * self^e` with `e` is the integer represented by the `exp_bits`
    /// least significant bits of `exp`.
    ///
    /// ### Bounded
    /// Requires `exp_bits ≤ Uint::<EXPONENT_LIMBS>::BITS`; will return an
    /// [Error::ScalarBoundTooLarge] otherwise.
    ///
    /// ### Vartime
    /// Executes in variable time w.r.t. `self.representative` and `exp`, but not in `exp_bits`.
    pub fn pow_bounded_with_base_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Result<Self, Error> {
        if exp_bits > Uint::<EXPONENT_LIMBS>::BITS {
            return Err(Error::ScalarBoundTooLarge);
        }

        let res = self
            .representative
            .nupow_bounded_with_base_vartime_ibqf_and_exponent(base.representative, exp, exp_bits);
        Ok(self.element_with_representative(res))
    }

    /// Compute `self^e` with `e` the exponent represented by `exponent_with_mask`.
    ///
    /// ### Exponent with Form-Mask
    /// This exponentiation operation does not compute `self^exponent` directly, but instead
    /// masks `self` before, and de-masks the result after the exponentation.
    ///
    /// In addition to the `exponent` value, `exponent_with_mask` contains the masking elements
    /// `m1`, `m2`, and `m3 = m2^exponent_bits · m1^exponent`. With these masks in place, we can
    /// now compute `self^exponent` as
    ///
    /// ```text
    /// (self·m1·m2).pow(complement=m2, exponent) / m3
    /// ```
    ///
    /// Because of the masking, it is now possible to perform the `pow` operation with variable
    /// time `nucomp` and `nudupl` operations.
    ///
    /// ### Variable time.
    /// This function executes in variable time w.r.t. `self·m1·m2`, `m2` and
    /// `exponent_mask.exponent_bits`.
    ///
    /// ### Variable-Time — Safe Only Against Naive Timing Attacks
    /// The total execution time for two different exponents, `T(mask * self, exponent₀)` and
    /// `T(mask * self, exponent₁)`, is indistinguishable to an adversary who does not know the
    /// value of the `mask`.
    /// This implies that, provided that `mask` is sampled correctly and the adversary only observes
    /// the total computation time, the operation is safe under certain assumptions about class
    /// groups. See [link](docs/Bounds on information leakage in class groups encryption.md)
    /// for further details.
    pub(crate) fn masked_pow_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent_with_mask: ExponentWithFormMask<DISCRIMINANT_LIMBS, EXPONENT_LIMBS>,
    ) -> Result<Self, Error> {
        let ExponentWithFormMask {
            m1,
            m2,
            m3,
            exponent,
            exponent_bits,
        } = exponent_with_mask;

        if !self.is_from_the_same_class_as(&m1)
            || !self.is_from_the_same_class_as(&m2)
            || !self.is_from_the_same_class_as(&m3)
        {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let res = self
            .representative
            .nucomp(m1.representative)
            .nucomp(m2.representative)
            .nupow_bounded_with_complement_vartime_ibqf(
                &exponent,
                exponent_bits,
                &m1.representative,
            )
            .nucompinv(m3.representative);

        Ok(self.element_with_representative(res))
    }

    /// Compute `self^e` with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// ### Multiplicatively masked
    /// This function masks `self` before exponentation, and then performs the exponentation using
    /// randomized operations.
    ///
    /// Requires that `randomizer.scalar_bits_bound == min(exp_bits, Uint::<EXPONENT_LIMBS>::BITS)`;
    /// will return `None` otherwise.
    pub(crate) fn scale_bounded_multiplicatively_masked<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
        randomizer: ScalingRandomizer<DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = randomizer;

        if !self.is_from_the_same_class_as(&m1)
            || !self.is_from_the_same_class_as(&m2)
            || !self.is_from_the_same_class_as(&m3)
        {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let exp_bits = u32::ct_min(&exp_bits, &Uint::<EXPONENT_LIMBS>::BITS);
        let equal_target_bits = scalar_bits_bound.ct_eq(&exp_bits);
        if (!equal_target_bits).into() {
            return Err(Error::InvalidParameters);
        }

        let res = self
            .representative
            .nucomp(m1.representative)
            .nupow_bounded_randomized_with_base(m2.representative, exp, exp_bits)
            .nucompinv(m3.representative);

        Ok(self.element_with_representative(res))
    }

    /// Raise `self` to the `exp`.
    ///
    /// ### Multiplicatively masked
    /// This function masks `self` before exponentation, and then performs the exponentation using
    /// randomized operations.
    ///
    /// Requires that `randomizer.scalar_bits_bound == Uint::<EXPONENT_LIMBS>::BITS`; will return
    /// `None` otherwise.
    pub(crate) fn scale_multiplicatively_masked<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        randomizer: ScalingRandomizer<DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        self.scale_bounded_multiplicatively_masked(exp, Uint::<EXPONENT_LIMBS>::BITS, randomizer)
    }

    /// Compute `self^e` with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// ### Multiplicatively masked / vartime
    /// This function masks `self` before exponentation, and then performs the exponentation using
    /// **vartime** operations.
    ///
    /// Requires that `randomizer.scalar_bits_bound == min(exp_bits, Uint::<EXPONENT_LIMBS>::BITS)`;
    /// will return `None` otherwise.
    ///
    /// Executes in variable time w.r.t. `self` and `exp`.
    pub(crate) fn scale_bounded_multiplicatively_masked_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
        randomizer: ScalingRandomizer<DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        if !self.is_from_the_same_class_as(&randomizer.m1)
            || !self.is_from_the_same_class_as(&randomizer.m2)
            || !self.is_from_the_same_class_as(&randomizer.m3)
        {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = randomizer;

        let exp_bits = u32::ct_min(&exp_bits, &Uint::<EXPONENT_LIMBS>::BITS);
        let equal_target_bits = scalar_bits_bound.ct_eq(&exp_bits);
        if (!equal_target_bits).into() {
            return Err(Error::InvalidParameters);
        }

        let res = self
            .representative
            .nucomp(m1.representative)
            .nupow_bounded_with_base_vartime_ibqf_and_exponent(m2.representative, exp, exp_bits)
            .nucompinv(m3.representative);
        Ok(self.element_with_representative(res))
    }

    /// Raise `self` to the `exp`.
    ///
    /// ### Multiplicatively masked / vartime
    /// This function masks `self` before exponentation, and then performs the exponentation using
    /// **vartime** operations.
    ///
    /// Requires that `randomizer.scalar_bits_bound == exp.bits()`; will return `None` otherwise.
    pub(crate) fn scale_multiplicatively_masked_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        randomizer: ScalingRandomizer<DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        self.scale_bounded_multiplicatively_masked_vartime(exp, exp.bits(), randomizer)
    }
}

impl<const DISCRIMINANT_LIMBS: usize> ConstantTimeEq for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.representative
            .ct_eq(&other.representative)
            .bitand(self.discriminant.ct_eq(&other.discriminant))
    }
}

impl<const DISCRIMINANT_LIMBS: usize> ConditionallySelectable
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            representative: Ibqf::conditional_select(&a.representative, &b.representative, choice),
            discriminant: Discriminant::conditional_select(
                &a.discriminant,
                &b.discriminant,
                choice,
            ),
        }
    }
}

impl<const DISCRIMINANT_LIMBS: usize> PartialEq for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    fn eq(&self, other: &Self) -> bool {
        (self.representative == other.representative) && (self.discriminant == other.discriminant)
    }
}

impl<const DISCRIMINANT_LIMBS: usize> Default for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    fn default() -> Self {
        Self {
            representative: Ibqf::default(),
            discriminant: Discriminant::new(
                U64::from_u64(3).to_nz().unwrap(),
                0,
                U64::from_u64(5).to_nz().unwrap(),
            )
            .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Random, I128, I64, U128, U64};
    use group::OsCsRng;

    use super::*;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::{discriminant::Discriminant, ibqf::Ibqf};

    fn get_ec() -> EquivalenceClass<{ I128::LIMBS }> {
        let fd = Discriminant::new_u64(227, 0, 1).unwrap();
        EquivalenceClass::new_from_coefficients(
            U128::from_u64(23).to_nz().unwrap(),
            I128::from(7),
            fd,
        )
        .unwrap()
    }

    #[test]
    fn test_new_from_coefficients() {
        let a = U128::from_u64(213).to_nz().unwrap();
        let b = I128::from_i64(5);
        let discriminant = Discriminant::new_u64(2531, 0, 1).unwrap();

        let ec = EquivalenceClass::new_from_coefficients(a, b, discriminant).unwrap();
        let target = EquivalenceClass {
            representative: Ibqf::new_reduced_64(213, 5, (2531, 0, 1)).unwrap(),
            discriminant,
        };
        assert_eq!(ec, target);
    }

    #[test]
    fn test_new_from_coefficients_reduced() {
        let ec = get_ec();
        let form = ec.representative;

        let new = EquivalenceClass::new_from_coefficients_reduced_vartime_discriminant(
            form.a()
                .as_ref()
                .resize()
                .try_into_uint()
                .unwrap()
                .to_nz()
                .unwrap(),
            form.b().resize(),
            ec.discriminant,
        );
        assert!(bool::from(new.is_some()));
        assert_eq!(new.unwrap().representative, ec.representative);

        let invalid = EquivalenceClass::new_from_coefficients_reduced_vartime_discriminant(
            form.c()
                .as_ref()
                .resize()
                .try_into_uint()
                .unwrap()
                .to_nz()
                .unwrap(),
            form.b().resize(),
            ec.discriminant,
        );
        assert!(bool::from(invalid.is_none()));
    }

    #[test]
    fn test_unit() {
        let ec = get_ec();
        assert_eq!(ec.unit(), ec.unit().mul(&ec.unit()).unwrap());
    }

    #[test]
    fn test_unit_for_class() {
        let d = Discriminant::<{ U128::LIMBS }>::new_u64(5, 0, 11).unwrap();
        let unit = EquivalenceClass::unit_for_class(&d);
        assert_eq!(unit, unit.mul(&unit).unwrap());
    }

    #[test]
    fn test_is_from_the_same_class_as() {
        let d1 = Discriminant::new_u64(5, 0, 11).unwrap();
        let d2 = Discriminant::new_u64(227, 0, 1).unwrap();

        let a = EquivalenceClass::new_from_coefficients_reduced_vartime_discriminant(
            U128::from_u64(2).to_nz().unwrap(),
            I128::from(1i64),
            d1,
        )
        .unwrap();
        let b = EquivalenceClass::new_from_coefficients_reduced_vartime_discriminant(
            U128::from_u64(4).to_nz().unwrap(),
            I128::from(3i64),
            d1,
        )
        .unwrap();
        let c = EquivalenceClass::new_from_coefficients_reduced_vartime_discriminant(
            U128::from_u64(7).to_nz().unwrap(),
            I128::from(5i64),
            d2,
        )
        .unwrap();

        assert!(a.is_from_the_same_class_as(&b));
        assert!(!a.is_from_the_same_class_as(&c));
    }

    #[test]
    fn test_wrapping_negate_if() {
        let ec = get_ec();
        assert_eq!(ec.wrapping_negate_if(Choice::from(0)), ec);
        let inv = ec.wrapping_negate_if(Choice::from(1));
        let target = EquivalenceClass {
            representative: Ibqf::new_reduced_64(23, -7, (227, 0, 1)).unwrap(),
            discriminant: ec.discriminant,
        };
        assert_eq!(inv, target);
    }

    #[test]
    fn test_pow() {
        let ec = get_ec();
        assert_eq!(
            ec.pow(&Uint::<1>::from(2u64)).representative,
            ec.representative.nudupl()
        );
    }

    #[test]
    fn test_pow_multifold_accelerated() {
        let ec = get_setup_parameters_secp256k1_112_bits_deterministic().h;
        let exp = U64::from_be_hex("1C313AB9142F40CE");

        let acc = MultiFoldNupowAccelerator::new_vartime(ec, 11, 77).unwrap();
        assert_eq!(
            EquivalenceClass::pow_multifold_accelerated(&acc, &exp),
            ec.pow_vartime(&exp)
        );
    }

    #[test]
    fn test_pow_multifold_accelerated_vartime() {
        let ec = get_setup_parameters_secp256k1_112_bits_deterministic().h;
        let exp = U64::from_be_hex("4863CB5743DD8A34");

        let acc = MultiFoldNupowAccelerator::new_vartime(ec, 11, 77).unwrap();
        assert_eq!(
            EquivalenceClass::pow_multifold_accelerated_vartime(&acc, &exp),
            ec.pow_vartime(&exp)
        );
    }

    #[test]
    fn test_pow_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let ec = setup_parameters.h;
        let exp = U64::from_be_hex("6EB97BD162F3543F");
        assert_eq!(
            ec.pow_randomized(&exp).representative,
            ec.representative.nupow_vartime(&exp)
        );
    }

    #[test]
    fn test_pow_2k_vartime() {
        let ec = get_ec();
        assert_eq!(
            ec.pow_2k_vartime(72).representative,
            ec.pow_vartime(&U128::ONE.shl(72)).representative
        );
    }

    #[test]
    fn test_pow_2k_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let ec = setup_parameters.h;
        assert_eq!(ec.pow_2k_vartime(72), ec.pow_2k_randomized(72));
    }

    #[test]
    fn test_pow_with_base_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let ec = setup_parameters.h;
        let base = setup_parameters.h.square_vartime();
        let exp = U64::from_be_hex("000000001a1a1b1b");

        let target = base
            .pow_2k_vartime(29)
            .mul_vartime(&ec.pow_vartime(&exp))
            .unwrap();
        assert_eq!(ec.pow_with_base_vartime(base, &exp), target);
    }

    #[test]
    fn test_prime_form() {
        let d = Discriminant::<{ U128::LIMBS }>::new_u64(71, 0, 1).unwrap();
        let prime =
            EquivalenceClass::prime_form_vartime_discriminant(d, U64::from(3u32).to_nz().unwrap())
                .unwrap();
        let target = Ibqf::new(U128::from_u64(3).to_nz().unwrap(), I128::ONE, &d).unwrap();
        assert_eq!(prime.representative, target);
    }

    #[test]
    fn test_prime_form_composed() {
        let target = Ibqf::new_reduced_64(2, 1, (19, 0, 37)).unwrap();

        let d = Discriminant::new_u64(19, 0, 37).unwrap();
        let prime =
            EquivalenceClass::prime_form_vartime_discriminant(d, U64::from(2u32).to_nz().unwrap())
                .unwrap();
        assert_eq!(prime.representative, target);
    }

    #[test]
    fn test_mul() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let lhs = setup_parameters.h;
        let rhs = setup_parameters.h.square_vartime().square_vartime();
        let target = EquivalenceClass {
            representative: lhs
                .representative
                .nudupl()
                .nudupl()
                .nucomp(lhs.representative),
            discriminant: lhs.discriminant,
        };
        assert_eq!(lhs.mul(&rhs).unwrap(), target);
    }

    #[test]
    fn test_mul_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let lhs = setup_parameters.h;
        let rhs = setup_parameters.h.square_vartime().square_vartime();
        let target = lhs
            .representative
            .nudupl_vartime()
            .nudupl_vartime()
            .nucomp_vartime(lhs.representative);
        assert_eq!(lhs.mul_randomized(&rhs).unwrap().representative, target);
    }

    #[test]
    fn test_mul_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let lhs = setup_parameters.h;
        let rhs = setup_parameters.h.square_vartime().square_vartime();

        assert_eq!(lhs.mul(&rhs).unwrap(), lhs.mul_vartime(&rhs).unwrap());
    }

    #[test]
    fn test_div() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let elt = setup_parameters.h;
        let square = setup_parameters.h.square_vartime();

        assert_eq!(square.div(&elt).unwrap(), elt);
    }

    #[test]
    fn test_div_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let elt = setup_parameters.h;
        let square = setup_parameters.h.square_vartime();

        assert_eq!(square.div_vartime(&elt).unwrap(), elt);
    }

    #[test]
    fn test_square() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let target = EquivalenceClass {
            representative: form.representative.nudupl(),
            discriminant: form.discriminant,
        };
        assert_eq!(form.square(), target);
    }

    #[test]
    fn test_square_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let target = EquivalenceClass {
            representative: form.representative.nudupl_vartime(),
            discriminant: form.discriminant,
        };
        assert_eq!(form.square_randomized(), target);
    }

    #[test]
    fn test_square_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        assert_eq!(form.square(), form.square_vartime());
    }

    #[test]
    fn test_pow_bounded() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exponent = U64::from_be_hex("3B7844EE0C2EC0C1");
        let bound = 53;

        let bounded_exponent = exponent.bitand(U64::MAX.shr_vartime(11));
        let target = form.pow_vartime(&bounded_exponent);
        assert_eq!(form.pow_bounded(&exponent, bound), target);
    }

    #[test]
    fn test_pow_bounded_multifold_accelerated() {
        let ec = get_setup_parameters_secp256k1_112_bits_deterministic().h;
        let exp = U64::from_be_hex("5BA664C67277DA78");
        let bound = 53;

        let acc = MultiFoldNupowAccelerator::new_vartime(ec, 11, 77).unwrap();
        assert_eq!(
            EquivalenceClass::pow_bounded_multifold_accelerated(&acc, &exp, bound),
            ec.pow_bounded_vartime(&exp, bound)
        );
    }

    #[test]
    fn test_pow_bounded_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exponent = U64::from_be_hex("38B6EC8FD4353EFD");
        let bound = 53;

        let bounded_exponent = exponent.bitand(U64::MAX.shr_vartime(11));
        let target = form.pow_vartime(&bounded_exponent);
        assert_eq!(form.pow_bounded_vartime(&exponent, bound), target);
    }

    #[test]
    fn test_pow_bounded_int_randomized_with_base() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exponent = I64::MIN;
        let (abs_exp, exp_sgn) = exponent.abs_sign();
        let bound = 53;

        let mut target = form
            .pow_bounded_vartime(&abs_exp, bound)
            .mul(&form.pow_2k_vartime(bound))
            .unwrap();
        target.representative = target.representative.inverse_if(exp_sgn.into());

        assert_eq!(
            form.pow_bounded_int_randomized_with_base(form, &exponent, bound)
                .unwrap(),
            target
        );
    }

    #[test]
    fn test_pow_bounded_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exponent = U64::random(&mut OsCsRng);
        let bound = 53;
        let target = form.pow_bounded_vartime(&exponent, bound);
        assert_eq!(form.pow_bounded_randomized(&exponent, bound), target);
    }

    #[test]
    fn test_pow_bounded_multifold_accelerated_randomized() {
        let ec = get_setup_parameters_secp256k1_112_bits_deterministic().h;
        let exp = U64::from_be_hex("0460CAE40059E151");
        let bound = 53;

        let target = ec.pow_bounded_vartime(&exp, bound);

        let acc = MultiFoldNupowAccelerator::new_vartime(ec, 11, 77).unwrap();
        assert_eq!(
            EquivalenceClass::pow_bounded_multifold_accelerated_randomized(&acc, &exp, bound),
            target
        );
    }

    #[test]
    fn test_pow_bounded_with_base_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let base = form.pow_vartime(&U64::from(12345u64));

        let exp = U64::from_be_hex("00001111abcd2345");
        let exp_bits = 35;

        let target = base
            .pow_vartime(&U64::ONE.shl(exp_bits))
            .mul_vartime(&form.pow_bounded_vartime(&exp, exp_bits))
            .unwrap();
        assert_eq!(
            form.pow_bounded_with_base_randomized(base, &exp, exp_bits)
                .unwrap(),
            target
        );

        // Excessively large exp_bits
        let exp_bits = 73;
        assert!(form
            .pow_bounded_with_base_randomized(base, &exp, exp_bits)
            .is_err());
    }

    #[test]
    fn test_pow_bounded_with_base_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let base = form.pow_vartime(&U64::from(12345u64));

        let exp = U64::from_be_hex("00001111abcd2345");
        let exp_bits = 35;

        let target = base
            .pow_vartime(&U64::ONE.shl(exp_bits))
            .mul_vartime(&form.pow_bounded_vartime(&exp, exp_bits))
            .unwrap();
        assert_eq!(
            form.pow_bounded_with_base_vartime(base, &exp, exp_bits)
                .unwrap(),
            target
        );

        // Excessively large exp_bits
        let exp_bits = 73;
        assert!(form
            .pow_bounded_with_base_vartime(base, &exp, exp_bits)
            .is_err());
    }

    #[test]
    fn test_masked_pow_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exp = U64::from_be_hex("00001111abcd2345");
        let bound = 45;
        let mask = ExponentWithFormMask::new::<{ U64::LIMBS }>(form, 64, exp, bound, &mut OsCsRng)
            .unwrap();

        assert_eq!(
            form.masked_pow_vartime(mask).unwrap(),
            form.pow_bounded_vartime(&exp, bound)
        );
    }

    #[test]
    fn test_scale_bounded_multiplicatively_masked() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exp = U64::from_be_hex("00001111abcd2345");

        // Basic input
        let exp_bits = exp.bits();
        let target = form.pow_bounded_vartime(&exp, exp_bits);
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_multiplicatively_masked(&exp, exp_bits, randomizer)
                .unwrap(),
            target
        );

        // Bits bound smaller than exponent
        let exp_bits = 25;
        let target = form.pow_bounded_vartime(&exp, exp_bits);
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_multiplicatively_masked(&exp, exp_bits, randomizer)
                .unwrap(),
            target
        );

        // Bits bound larger than exponent
        let exp_bits = 127;
        let target = form.pow_bounded_vartime(&exp, exp_bits);
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_multiplicatively_masked(&exp, exp_bits, randomizer)
                .unwrap(),
            target
        );
    }

    #[test]
    fn test_scale_multiplicatively_masked() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let exp = U64::from_be_hex("00ffa3b4abcd2345");

        let target = form.pow_vartime(&exp);
        let randomizer = setup_parameters
            .sample_scaling_randomizer(exp, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_multiplicatively_masked(&exp, randomizer)
                .unwrap(),
            target
        );
    }

    #[test]
    fn test_scale_bounded_multiplicatively_masked_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exp = U64::from_be_hex("00001111abcd2345");
        let exp_bits = exp.bits();

        // Basic input
        let target = form.pow_bounded_vartime(&exp, exp_bits);
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_multiplicatively_masked_vartime(&exp, exp_bits, randomizer)
                .unwrap(),
            target
        );

        // Bits bound smaller than exponent
        let exp_bits = 25;
        let target = form.pow_bounded_vartime(&exp, exp_bits);
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_multiplicatively_masked_vartime(&exp, exp_bits, randomizer)
                .unwrap(),
            target
        );

        // Bits bound larger than exponent
        let exp_bits = 127;
        let target = form.pow_bounded_vartime(&exp, exp_bits);
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_multiplicatively_masked_vartime(&exp, exp_bits, randomizer)
                .unwrap(),
            target
        );
    }

    #[test]
    fn test_scale_randomized_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let exp = U64::from_be_hex("00ffa3b4abcd2345");

        let target = form.pow_vartime(&exp);
        let randomizer = setup_parameters
            .sample_vartime_scaling_randomizer(exp, &mut OsCsRng)
            .unwrap();
        assert_eq!(
            form.scale_multiplicatively_masked_vartime(&exp, randomizer)
                .unwrap(),
            target
        );
    }
}
