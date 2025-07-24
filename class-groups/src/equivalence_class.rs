// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::cmp::min;
use std::ops::{BitAnd, Deref, Neg};

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crypto_bigint::{
    CheckedAdd, CheckedMul, Concat, ConstantTimeSelect, Encoding, Gcd, Int, Integer, InvMod,
    NonZero, Split, Uint,
};
use serde::{Deserialize, Serialize};

pub use public_parameters::PublicParameters;

use crate::helpers::math;
use crate::ibqf::accelerator::NupowAccelerator;
use crate::randomizer::ScalingRandomizer;
use crate::{discriminant::Discriminant, ibqf::Ibqf, Error};

mod group_element;
pub(crate) mod public_parameters;

/// Class of equivalent [Ibqf]s.
#[derive(Clone, Debug, Eq, Serialize, Deserialize, Copy)]
pub struct EquivalenceClass<const DISCRIMINANT_LIMBS: usize>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    representative: Ibqf<DISCRIMINANT_LIMBS>,
    discriminant: Discriminant<DISCRIMINANT_LIMBS>,
    accelerator: Option<NupowAccelerator<DISCRIMINANT_LIMBS>>,
}

impl<const DISCRIMINANT_LIMBS: usize> TryFrom<Ibqf<DISCRIMINANT_LIMBS>>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    type Error = Error;

    fn try_from(form: Ibqf<DISCRIMINANT_LIMBS>) -> Result<Self, Self::Error> {
        let discriminant = form
            .discriminant()
            .and_then(|d| NonZero::new(d).into_option().ok_or(Error::InternalError))
            .and_then(|d| d.try_into())?;
        // TODO(#46): make const-time; remove `_vartime` operations.
        let representative = form.normalize_vartime()?.reduce_vartime()?;
        Ok(Self {
            representative,
            discriminant,
            accelerator: None,
        })
    }
}

impl<const DISCRIMINANT_LIMBS: usize> TryFrom<NupowAccelerator<DISCRIMINANT_LIMBS>>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    type Error = Error;

    fn try_from(accelerator: NupowAccelerator<DISCRIMINANT_LIMBS>) -> Result<Self, Self::Error> {
        let mut ec = Self::try_from(*accelerator.form())?;
        ec.accelerator = Some(accelerator);
        Ok(ec)
    }
}

impl<const DISCRIMINANT_LIMBS: usize> EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    /// Read-only access to this class' representative.
    pub fn representative(&self) -> &Ibqf<DISCRIMINANT_LIMBS> {
        &self.representative
    }

    /// Get the unit element for the Class Group this equivalence class
    /// belongs to.
    pub fn unit(&self) -> Self {
        // safe to unwrap; we know this discriminant to be valid.
        Self::unit_for_class(&self.discriminant).unwrap()
    }

    /// Get the unit element for the Class Group identified by `discriminant`.
    pub fn unit_for_class(discriminant: &Discriminant<DISCRIMINANT_LIMBS>) -> Result<Self, Error> {
        Ok(Self {
            representative: Ibqf::unit_for_discriminant(discriminant.deref())?,
            discriminant: *discriminant,
            accelerator: None,
        })
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
        self.discriminant == other.discriminant
    }
}

impl<const DISCRIMINANT_LIMBS: usize, const DOUBLE_DISCRIMINANT_LIMBS: usize>
    EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding
        + InvMod<Modulus = NonZero<Uint<DISCRIMINANT_LIMBS>>, Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>> + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding
        + InvMod<
            Modulus = NonZero<Uint<DOUBLE_DISCRIMINANT_LIMBS>>,
            Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>,
        >,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<DISCRIMINANT_LIMBS>> + Gcd<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>,
{
    /// Compute a representative of this class in `(Ok / lOk)* / (Z/qZ)*`, where `q` is the
    /// `conductor`.
    ///
    /// Assumes `CONDUCTOR_LIMBS <= DISCRIMINANT_LIMBS`.
    pub fn kernel_representative<const CONDUCTOR_LIMBS: usize>(
        &self,
        conductor: &NonZero<Uint<CONDUCTOR_LIMBS>>,
        discriminant: &Discriminant<DISCRIMINANT_LIMBS>,
    ) -> Result<Uint<CONDUCTOR_LIMBS>, Error> {
        let mut ft = self.representative.to_maximal_order(
            &conductor.resize::<DISCRIMINANT_LIMBS>().to_nz().unwrap(),
            discriminant,
        )?;

        // g = 1 + 0 sqrt(DeltaK)
        let mut g0 = Int::<DOUBLE_DISCRIMINANT_LIMBS>::ONE;
        let mut g1 = Int::<DOUBLE_DISCRIMINANT_LIMBS>::ZERO;

        let conductor_ = conductor
            .resize::<DOUBLE_DISCRIMINANT_LIMBS>()
            .to_nz()
            .unwrap();

        // Reduce `ft` and build g while doing it.
        // Each time we apply rho to the form (a, b, c), g is multiplied by (b + √(∆))/2a.
        // We do not care about the 2a in the denominator, as at the end we are going
        // to compute a representative of g^(-1) in the kernel as -g1/g0 mod `conductor`:
        // We just have to remove the common factor in g0 and g1 before taking the inverse.
        let disc_value = discriminant.deref().get();
        ft = ft
            .resize::<DOUBLE_DISCRIMINANT_LIMBS>()?
            .normalize()?
            .resize::<DISCRIMINANT_LIMBS>()?;
        // TODO(#46): make constant time. How many iterations will we need?
        while ft.a() > ft.c() {
            // map (g0, g1) -> (g0 * b + g1 * ∆, g1 * b + g0)
            let g1_delta = g1
                .checked_mul(&disc_value)
                .into_option()
                .ok_or(Error::InternalError)?;
            g1 = g1
                .checked_mul(ft.b())
                .and_then(|g1b| g1b.checked_add(&g0))
                .into_option()
                .ok_or(Error::InternalError)?;
            g0 = g0
                .checked_mul(ft.b())
                .and_then(|g0b| g0b.checked_add(&g1_delta))
                .into_option()
                .ok_or(Error::InternalError)?;

            // Reduce by the gcd to prevent g0 and g1 from growing out of control.
            // safe to unwrap; gcd is always non-zero
            let gcd = g0.abs().gcd(&g1.abs()).to_nz().unwrap();
            g0 /= gcd;
            g1 /= gcd;

            ft = ft.rho()?;
        }

        if ft.a().get() != Int::ONE || *ft.b() != Int::ONE {
            return Err(Error::InternalError);
        }

        // Compute representative as -g1/g0 mod `conductor`
        let inv = g0
            .inv_mod(&conductor_)
            .into_option()
            .ok_or(Error::InternalError)?;

        // safe to resize; result fits in CONDUCTOR_LIMBS
        Ok(CtOption::from((g1 * inv).checked_neg())
            .into_option()
            .ok_or(Error::InternalError)?
            .normalized_rem(&conductor_)
            .resize::<CONDUCTOR_LIMBS>())
    }
}

impl<const DISCRIMINANT_LIMBS: usize, const DOUBLE_DISCRIMINANT_LIMBS: usize>
    EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>> + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Given discriminant `∆` and prime `p` s.t. `(∆|p) = 1` with `(·|·)` the Kronecker symbol,
    /// constructs the equivalence class for the form `f = (p, ..., ...)` in `CL(∆)`.
    /// Such a form is called a _prime form_.
    ///
    /// Ref: Section 5.5.1 in "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    ///
    /// Note: assumes `∆` and prime `p` s.t. Kronecker Symbol `(∆|p) = 1`; returns an error otherwise.
    pub(crate) fn prime_form(
        discriminant: &Discriminant<DISCRIMINANT_LIMBS>,
        p: &NonZero<Uint<DISCRIMINANT_LIMBS>>,
    ) -> Result<EquivalenceClass<DISCRIMINANT_LIMBS>, Error> {
        let d_mod_p = discriminant.deref().get().normalized_rem(p);
        let mut b = math::sqrt_mod(&d_mod_p, p)?;

        // Ensure b mod p has the same parity as the discriminant
        // Otherwise, use -b mod p.
        let unequal_parity = b.is_odd().ct_ne(&discriminant.deref().is_odd().into());
        b = Uint::ct_select(&b, &p.wrapping_sub(&b), unequal_parity);

        // safe to unwrap; p is given as non-zero input.
        let p = CtOption::from(p.to_int())
            .into_option()
            .ok_or(Error::InternalError)?
            .to_nz()
            .unwrap();
        let b = CtOption::from(b.to_int())
            .into_option()
            .ok_or(Error::InternalError)?;

        let form = Ibqf::new(p, b, discriminant)?;
        EquivalenceClass::try_from(form)
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    /// Construct the nupow accelerator for this form, targeted at exponents of size ~`target_bits`.
    ///
    /// Runs in time variable in `target_bits`, `self.representative`, and `self.reduction_bound`.
    ///
    /// Sets `self.accelerator = None` when accelerator construction fails.
    pub fn accelerate_vartime(&mut self, target_bits: u32) -> Result<(), Error> {
        let accelerator = NupowAccelerator::new_vartime(self.representative, target_bits)?;
        self.accelerator = Some(accelerator);

        Ok(())
    }

    /// Multiply `self` with `rhs`.
    pub fn mul(&self, rhs: &Self) -> Result<Self, Error> {
        if self.discriminant != rhs.discriminant {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        // Safe to unwrap, since nucomp always succeeds on operands that have the
        // same discriminant.
        Ok(Self {
            representative: self.representative.nucomp(&rhs.representative).unwrap(),
            discriminant: self.discriminant,
            accelerator: None,
        })
    }

    /// Multiply `self` with `rhs`.
    ///
    /// This function is executed in time variable in `self.representative` and
    /// `rhs.representative`.
    pub fn mul_vartime(&self, rhs: &Self) -> Result<Self, Error> {
        if self.discriminant != rhs.discriminant {
            return Err(Error::CombiningRequiresSameDiscriminant);
        }

        // Safe to unwrap, since nucomp always succeeds on operands that have the
        // same discriminant.
        Ok(Self {
            representative: self
                .representative
                .nucomp_vartime(&rhs.representative)
                .unwrap(),
            discriminant: self.discriminant,
            accelerator: None,
        })
    }

    /// Square `self`
    pub fn square(&self) -> Self {
        // nudupl cannot fail since this form has a negative discriminant.
        Self {
            representative: self.representative.nudupl().unwrap(),
            discriminant: self.discriminant,
            accelerator: None,
        }
    }

    /// Square `self`.
    ///
    /// This function is executed in time variable in `self.representative`.
    pub fn square_vartime(&self) -> Self {
        // nudupl cannot fail since this form has a negative discriminant.
        Self {
            representative: self.representative.nudupl_vartime().unwrap(),
            discriminant: self.discriminant,
            accelerator: None,
        }
    }

    /// Raise `self` to the `exp`.
    pub fn pow<const EXPONENT_LIMBS: usize>(&self, exp: &Uint<EXPONENT_LIMBS>) -> Self {
        // nupow cannot fail since this form has a negative discriminant.
        // safe to unwrap
        Self {
            representative: self.representative.nupow(exp).unwrap(),
            discriminant: self.discriminant,
            accelerator: None,
        }
    }

    /// Raise `self` to the `exp`.
    ///
    /// This function is executed in time variable in `self.representative` and `exp`.
    pub fn pow_vartime<const EXPONENT_LIMBS: usize>(&self, exp: &Uint<EXPONENT_LIMBS>) -> Self {
        let result = if let Some(accelerator) = self.accelerator {
            accelerator.pow_vartime(exp)
        } else {
            self.representative.nupow_vartime(exp)
        };

        // nupow_vartime cannot fail since this form has a negative discriminant.
        // safe to unwrap
        Self {
            representative: result.unwrap(),
            discriminant: self.discriminant,
            accelerator: None,
        }
    }

    /// Raise `self^{2^k}`
    ///
    /// This function is executed in time variable in both `self.representative` and `k`.
    pub fn pow_2k_vartime(&self, k: u32) -> Result<Self, Error> {
        Ok(Self {
            representative: self.representative.nupow2k_vartime(k)?,
            discriminant: self.discriminant,
            accelerator: None,
        })
    }

    /// Map `(self, base)` to `base^{2^b} * self^exp`, with `b = Uint::<EXPONENT_LIMBS>::BITS`.
    ///
    /// Executes in variable time w.r.t. `self`, `base` and `exp`.
    pub fn pow_with_base_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exp: &Uint<EXPONENT_LIMBS>,
    ) -> Result<Self, Error> {
        let result = self
            .representative
            .nupow_with_base_vartime(base.representative, exp);

        Ok(Self {
            representative: result?,
            discriminant: self.discriminant,
            accelerator: None,
        })
    }

    /// Compute `self^e`, with `e` the integers represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// Note: this operation cannot make use of the accelerator.
    pub fn pow_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let result = self
            .representative
            .nupow_bounded(exp, exp_bits)
            .expect("cannot fail; this form has a negative discriminant");

        Self {
            representative: result,
            discriminant: self.discriminant,
            accelerator: None,
        }
    }

    /// Map `(base, self)` to `base^{2^exp_bits} * self^e`, where `e` is the integer represented
    /// by the `exp_bits` least significant bits of `exp`.
    ///
    /// Assumes `self` is a random form. With this assumption in place, a faster
    /// exponentation algorithm can be exploited. Will return an `Error` if the assumption proves
    /// incorrect.
    ///
    /// Requires `exp_bits ≤ Uint::<EXPONENT_LIMBS>::BITS`; will return an
    /// [Error::ScalarBoundTooLarge] otherwise.
    ///
    /// Note: this operation cannot make use of the accelerator.
    pub fn pow_randomized_bounded_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Result<Self, Error> {
        if exp_bits > Uint::<EXPONENT_LIMBS>::BITS {
            return Err(Error::ScalarBoundTooLarge);
        }

        // nupow_bounded cannot fail since this form has a negative discriminant.
        // safe to unwrap
        let representative = self
            .representative
            .nupow_randomized_bounded_with_base(base.representative, exp, exp_bits)
            .unwrap();
        Ok(Self {
            representative,
            discriminant: self.discriminant,
            accelerator: None,
        })
    }

    /// Compute `self^e`, where `e` is the integer represented by the `exp_bits` least significant
    /// bits of `exp`.
    ///
    /// This function is executed in time variable in `self.representative` and `exp`.
    pub fn pow_bounded_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Self {
        let result = if let Some(accelerator) = self.accelerator {
            accelerator.pow_bounded_vartime(exp, exp_bits)
        } else {
            self.representative.nupow_bounded_vartime(exp, exp_bits)
        };

        // nupow_bounded cannot fail since this form has a negative discriminant.
        // safe to unwrap
        Self {
            representative: result.unwrap(),
            discriminant: self.discriminant,
            accelerator: None,
        }
    }

    /// Map `(self, base)` to `base^{2^exp_bits} * self^e` where `e` is the integer represented
    /// by the `exp_bits` least significant bits of `exp`.
    ///
    /// Requires `exp_bits ≤ Uint::<EXPONENT_LIMBS>::BITS`; will return an
    /// [Error::ScalarBoundTooLarge] otherwise.
    ///
    /// Executes in variable time w.r.t. `self.representative` and `exp`.
    ///
    /// Note: this operation cannot make use of the accelerator.
    pub fn pow_bounded_with_base_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exp: &Uint<EXPONENT_LIMBS>,
        exp_bits: u32,
    ) -> Result<Self, Error> {
        if exp_bits > Uint::<EXPONENT_LIMBS>::BITS {
            return Err(Error::ScalarBoundTooLarge);
        }

        // nupow_bounded cannot fail since this form has a negative discriminant.
        // safe to unwrap
        let representative = self
            .representative
            .nupow_bounded_with_base_vartime(base.representative, exp, exp_bits)
            .unwrap();
        Ok(Self {
            representative,
            discriminant: self.discriminant,
            accelerator: None,
        })
    }

    /// Compute `self^e` with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// This function randomizes `self` before executing the exponentation operation, allowing
    /// for faster exponentiation.
    pub(crate) fn scale_bounded_randomized<const EXPONENT_LIMBS: usize>(
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

        let exp_bits = min(exp_bits, Uint::<EXPONENT_LIMBS>::BITS);
        if scalar_bits_bound != exp_bits {
            return Err(Error::InvalidRandomizer);
        }

        let randomized_self = self.mul(&m1)?;
        let randomized_self_exp =
            randomized_self.pow_randomized_bounded_with_base(m2, exp, exp_bits);
        let self_exp = randomized_self_exp?.mul(&m3.neg())?;

        Ok(self_exp)
    }

    /// Raise `self` to the `exp`.
    ///
    /// This function randomizes `self` before executing the exponentation operation, allowing
    /// for faster exponentiation.
    pub(crate) fn scale_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        randomizer: ScalingRandomizer<DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        self.scale_bounded_randomized(exp, Uint::<EXPONENT_LIMBS>::BITS, randomizer)
    }

    /// Compute `self^e` with `e` the integer represented by the `exp_bits` least significant bits
    /// of `exp`.
    ///
    /// This function randomizes `self` before executing the exponentation operation, allowing
    /// for faster exponentiation.
    ///
    /// Executes in variable time w.r.t. `self` and `exp`.
    pub(crate) fn scale_bounded_randomized_vartime<const EXPONENT_LIMBS: usize>(
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

        let exp_bits = min(exp_bits, Uint::<EXPONENT_LIMBS>::BITS);
        if scalar_bits_bound != exp_bits {
            return Err(Error::InvalidRandomizer);
        }

        let randomized_self = self.mul(&m1)?;
        let randomized_self_exp = randomized_self.pow_bounded_with_base_vartime(m2, exp, exp_bits);
        let self_exp = randomized_self_exp?.mul(&m3.neg())?;

        Ok(self_exp)
    }

    /// Raise `self` to the `exp`.
    ///
    /// This function randomizes `self` before executing the exponentation operation, allowing
    /// for faster exponentiation.
    ///
    /// Executes in variable time w.r.t. `self` and `exp` only.
    pub(crate) fn scale_randomized_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exp: &Uint<EXPONENT_LIMBS>,
        randomizer: ScalingRandomizer<DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = randomizer;
        if scalar_bits_bound != exp.bits_vartime() {
            return Err(Error::InvalidRandomizer);
        }

        let randomized_self = self.mul(&m1)?;
        let randomized_self_exp = randomized_self.pow_with_base_vartime(m2, exp);
        let self_exp = randomized_self_exp?.mul(&m3.neg())?;

        Ok(self_exp)
    }
}

impl<const DISCRIMINANT_LIMBS: usize> ConstantTimeEq for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
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
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            representative: Ibqf::conditional_select(&a.representative, &b.representative, choice),
            discriminant: Discriminant::conditional_select(
                &a.discriminant,
                &b.discriminant,
                choice,
            ),
            accelerator: None,
        }
    }
}

impl<const DISCRIMINANT_LIMBS: usize> PartialEq for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    fn eq(&self, other: &Self) -> bool {
        // We can ignore `accelerator` and `reduction_bound`; both values are irrelevant for
        // comparing equivalence classes.
        (self.representative == other.representative) && (self.discriminant == other.discriminant)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Sub;

    use crypto_bigint::{Gcd, InvMod, Random, I128, I512, U128, U512, U64};
    use rand_core::OsRng;

    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::{discriminant::Discriminant, ibqf::Ibqf};

    use super::*;

    fn get_ec() -> EquivalenceClass<{ I128::LIMBS }> {
        let fd = Discriminant::new(I128::from(-227).to_nz().unwrap()).unwrap();
        let form = Ibqf::new(I128::from(23).to_nz().unwrap(), I128::from(7), &fd).unwrap();
        EquivalenceClass::try_from(form).unwrap()
    }

    #[test]
    fn test_new_normalizes_representative() {
        let ec = get_ec();
        assert!(ec.representative.is_normal_vartime());
    }

    #[test]
    fn test_new_reduces_representative() {
        let ec = get_ec();
        assert!(ec.representative.is_reduced_vartime());
    }

    #[test]
    fn test_unit() {
        let ec = get_ec();
        assert_eq!(ec.unit(), ec.unit().mul(&ec.unit()).unwrap());
    }

    #[test]
    fn test_unit_for_discriminant() {
        let d = Discriminant::new(I128::from(-55).to_nz().unwrap()).unwrap();
        let unit = EquivalenceClass::unit_for_class(&d).unwrap();
        assert_eq!(unit, unit.mul(&unit).unwrap());
    }

    #[test]
    fn test_pow() {
        let ec = get_ec();
        assert_eq!(
            ec.pow(&Uint::<1>::from(2u64)).representative,
            ec.representative.nudupl().unwrap()
        );
    }

    #[test]
    fn test_pow_2k_vartime() {
        let ec = get_ec();
        assert_eq!(
            ec.pow_2k_vartime(72).unwrap().representative,
            ec.pow_vartime(&U128::ONE.shl(72)).representative
        );
    }

    #[test]
    fn test_prime_form() {
        let d = Discriminant::new(I128::from(-71i32).to_nz().unwrap()).unwrap();
        let prime = EquivalenceClass::prime_form(&d, &U128::from(3u32).to_nz().unwrap()).unwrap();
        let target = Ibqf::new_reduced(I128::from(3).to_nz().unwrap(), I128::ONE, &d).unwrap();
        assert_eq!(prime.representative, target);
    }

    #[test]
    fn test_prime_form_composed() {
        let d = Discriminant::new(I128::from(-703).to_nz().unwrap()).unwrap();
        let prime = EquivalenceClass::prime_form(&d, &U128::from(2u32).to_nz().unwrap()).unwrap();

        let target = Ibqf::new(I128::from(2).to_nz().unwrap(), I128::ONE, &d).unwrap();
        assert_eq!(prime.representative, target);
    }

    #[test]
    fn test_kernel_representative_one() {
        let conductor = U512::from(304992319192948457214838904939572129787u128);
        let message = I512::from(461106818110004318359i128);
        kernel_test(conductor, message);
    }

    #[test]
    fn test_kernel_representative_two() {
        let conductor = U512::from(652593934400167378858294238219u128);
        let message = I512::from(461106818113183135159i128);
        kernel_test(conductor, message);
    }

    fn kernel_test<const LIMBS: usize, const DOUBLE_LIMBS: usize>(
        conductor: Uint<LIMBS>,
        message: Int<LIMBS>,
    ) where
        Int<LIMBS>: Encoding + InvMod<Modulus = NonZero<Uint<LIMBS>>, Output = Uint<LIMBS>>,
        Uint<LIMBS>: Encoding + Gcd<Output = Uint<LIMBS>> + Concat<Output = Uint<DOUBLE_LIMBS>>,

        Int<DOUBLE_LIMBS>:
            Encoding + InvMod<Modulus = NonZero<Uint<DOUBLE_LIMBS>>, Output = Uint<DOUBLE_LIMBS>>,
        Uint<DOUBLE_LIMBS>: Gcd<Output = Uint<DOUBLE_LIMBS>> + Split<Output = Uint<LIMBS>>,
    {
        let conductor_ = conductor.to_int().unwrap();
        let d = Discriminant::new(
            (conductor_ * conductor_ * conductor_)
                .checked_neg()
                .unwrap()
                .to_nz()
                .unwrap(),
        )
        .unwrap();

        let mut inv = message
            .inv_mod(&conductor.to_nz().unwrap())
            .unwrap()
            .to_int()
            .unwrap();
        if inv.rem_uint(&U64::from(2u32).to_nz().unwrap()) == Int::ZERO {
            inv = inv.sub(&conductor_);
        }

        let form = Ibqf::new(
            (conductor_ * conductor_).to_nz().unwrap(),
            inv * conductor_,
            &d,
        )
        .unwrap()
        .resize();

        let ec = EquivalenceClass {
            representative: form.unwrap(),
            discriminant: d,
            accelerator: None,
        };

        let maximal_order_discriminant =
            Discriminant::new(conductor_.checked_neg().unwrap().to_nz().unwrap()).unwrap();
        let x = ec.kernel_representative(&conductor.to_nz().unwrap(), &maximal_order_discriminant);
        assert_eq!(x.unwrap().to_int().unwrap(), message)
    }

    #[test]
    fn test_mul_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let lhs = setup_parameters.h;
        let rhs = setup_parameters.f;

        assert_eq!(lhs.mul(&rhs).unwrap(), lhs.mul_vartime(&rhs).unwrap());
    }

    #[test]
    fn test_square_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        assert_eq!(form.square(), form.square_vartime());
    }

    #[test]
    fn test_pow_bounded_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exponent = U64::random(&mut OsRng);
        let bound = 53;
        assert_eq!(
            form.pow_bounded(&exponent, bound),
            form.pow_bounded_vartime(&exponent, bound)
        );
    }

    #[test]
    fn test_pow_bounded_with_base() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let base = form.pow(&U64::from(12345u64));

        let exp = U64::from_be_hex("00001111abcd2345");
        let exp_bits = 35;
        assert_eq!(
            form.pow_randomized_bounded_with_base(base, &exp, exp_bits)
                .unwrap(),
            base.pow(&U64::ONE.shl(exp_bits))
                .mul(&form.pow_bounded(&exp, exp_bits))
                .unwrap()
        );

        // Excessively large exp_bits
        let exp_bits = 73;
        assert!(form
            .pow_randomized_bounded_with_base(base, &exp, exp_bits)
            .is_err());
    }

    #[test]
    fn test_pow_bounded_with_base_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let base = form.pow(&U64::from(12345u64));

        let exp = U64::from_be_hex("00001111abcd2345");
        let exp_bits = 35;
        assert_eq!(
            form.pow_bounded_with_base_vartime(base, &exp, exp_bits)
                .unwrap(),
            base.pow_vartime(&U64::ONE.shl(exp_bits))
                .mul(&form.pow_bounded_vartime(&exp, exp_bits))
                .unwrap()
        );

        // Excessively large exp_bits
        let exp_bits = 73;
        assert!(form
            .pow_bounded_with_base_vartime(base, &exp, exp_bits)
            .is_err());
    }

    #[test]
    fn test_scale_bounded_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exp = U64::from_be_hex("00001111abcd2345");
        let exp_bits = exp.bits();

        // Basic input
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_randomized(&exp, exp_bits, randomizer)
                .unwrap(),
            form.pow_bounded(&exp, exp_bits)
        );

        // Bits bound smaller than exponent
        let exp_bits = 25;
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_randomized(&exp, exp_bits, randomizer)
                .unwrap(),
            form.pow_bounded(&exp, exp_bits)
        );

        // Bits bound larger than exponent
        let exp_bits = 127;
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_randomized(&exp, exp_bits, randomizer)
                .unwrap(),
            form.pow_bounded(&exp, exp_bits)
        );
    }

    #[test]
    fn test_scale_randomized() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let exp = U64::from_be_hex("00ffa3b4abcd2345");

        let randomizer = setup_parameters
            .sample_scaling_randomizer(exp, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_randomized(&exp, randomizer).unwrap(),
            form.pow(&exp)
        );
    }

    #[test]
    fn test_scale_bounded_randomized_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        let exp = U64::from_be_hex("00001111abcd2345");
        let exp_bits = exp.bits();

        // Basic input
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_randomized_vartime(&exp, exp_bits, randomizer)
                .unwrap(),
            form.pow_bounded(&exp, exp_bits)
        );

        // Bits bound smaller than exponent
        let exp_bits = 25;
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_randomized_vartime(&exp, exp_bits, randomizer)
                .unwrap(),
            form.pow_bounded(&exp, exp_bits)
        );

        // Bits bound larger than exponent
        let exp_bits = 127;
        let randomizer = setup_parameters
            .sample_bounded_scaling_randomizer(exp, exp_bits, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_bounded_randomized_vartime(&exp, exp_bits, randomizer)
                .unwrap(),
            form.pow_bounded(&exp, exp_bits)
        );
    }

    #[test]
    fn test_scale_randomized_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;
        let exp = U64::from_be_hex("00ffa3b4abcd2345");

        let randomizer = setup_parameters
            .sample_vartime_scaling_randomizer(exp, &mut OsRng)
            .unwrap();
        assert_eq!(
            form.scale_randomized_vartime(&exp, randomizer).unwrap(),
            form.pow(&exp)
        );
    }
}
