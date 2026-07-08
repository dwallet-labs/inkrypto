// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::{Error, ErrorKind};
use crypto_bigint::{Uint, U64};
use group::{CsRng, Samplable};
use std::{
    iter,
    ops::{Add, Mul},
};

pub mod known_order;
pub mod over_the_integers;

/// Polynomial of some degree $n$
///
/// Polynomial has a form: $f(x) = a_0 + a_1 x^1 + \dots{} + a_{n-1} x^{n-1} + a_n x^n$
///
/// Coefficients $a_i$ and indeterminate $x$ are within a ring,
/// and this type is generic for any concrete type that implements ring arithmetic operations.
pub struct Polynomial<T> {
    coefficients: Vec<T>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl<T: Clone> TryFrom<Vec<T>> for Polynomial<T> {
    type Error = Error;

    fn try_from(coefficients: Vec<T>) -> std::result::Result<Self, Self::Error> {
        if coefficients.is_empty() {
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

        Ok(Self { coefficients })
    }
}

impl<T: Clone> Polynomial<T> {
    /// Returns a reference to the polynomial coefficients.
    ///
    /// The coefficients are ordered from lowest to highest degree:
    /// $[a_0, a_1, \dots, a_n]$ for polynomial $f(x) = a_0 + a_1 x + \dots + a_n x^n$.
    pub fn coefficients(&self) -> &[T] {
        &self.coefficients
    }

    /// Samples random polynomial of degree `degree` with a fixed constant term (i.e. $a_0 =
    /// \text{constant\\_term}$). In SSS, the constant term is the shared secret, and the other
    /// coefficients are used as randomizers to hide the secret.
    ///
    /// The resulting polynomial has `degree + 1` coefficients: the constant term plus `degree`
    /// random coefficients.
    ///
    /// ## Polynomial degree
    ///
    /// Note that it's not guaranteed that constructed polynomial degree equals to
    /// `degree` as it's allowed to end with zero coefficients. Actual polynomial
    /// degree equals to index of the last non-zero coefficient or zero if all the coefficients are
    /// zero.
    pub fn sample_with_constant_term(
        degree: u16,
        constant_term: T,
        public_parameters: &T::PublicParameters,
        rng: &mut impl CsRng,
    ) -> Result<Self>
    where
        T: Samplable,
    {
        let coefficients = T::sample_batch(public_parameters, usize::from(degree), rng)
            .map_err(|_| Error::from(ErrorKind::InternalError))?;
        let coefficients: Vec<T> = iter::once(constant_term).chain(coefficients).collect();

        Self::try_from(coefficients)
    }
}

impl<T: Clone + Add<T, Output = T>> Polynomial<T> {
    /// Takes point $x$ and evaluates $f(x)$ using Horner's method.
    ///
    /// The degree type `D` can differ from the coefficient type `T`, which is useful for
    /// evaluating commitment polynomials where coefficients are group elements and
    /// the evaluation point is a scalar.
    pub fn evaluate<D>(&self, x: &D) -> T
    where
        D: Copy + Mul<T, Output = T>,
    {
        // Horner's method: iterate through the coefficients from highest to lowest degree,
        // multiplying by `x` and adding the coefficient at each step.
        let mut reversed_coefficients = self.coefficients.iter().rev();
        let last_coefficient = reversed_coefficients.next().unwrap();

        reversed_coefficients.fold(
            last_coefficient.clone(),
            |partially_evaluated_polynomial, coefficient| {
                (*x) * partially_evaluated_polynomial + coefficient.clone()
            },
        )
    }
}

impl<T: Clone + group::GroupElement> Polynomial<T> {
    /// Takes a *public* point $x$ as `Uint<LIMBS>` and evaluates $f(x)$ using Horner's method.
    /// The number of bits of `x` is leaked in the time pattern.
    /// `constant_time` controls whether the scalar multiplication is constant-time.
    pub fn evaluate_public_point<const LIMBS: usize>(
        &self,
        x: &Uint<LIMBS>,
        x_bits: u32,
        constant_time: bool,
        public_parameters: &T::PublicParameters,
    ) -> T {
        let mut reversed_coefficients = self.coefficients.iter().rev();
        let last_coefficient = reversed_coefficients.next().unwrap();

        reversed_coefficients.fold(
            last_coefficient.clone(),
            |partially_evaluated_polynomial, coefficient| {
                let partially_evaluated_polynomial_by_x = if constant_time {
                    partially_evaluated_polynomial.scale_bounded(x, x_bits, public_parameters)
                } else {
                    partially_evaluated_polynomial.scale_bounded_vartime(
                        x,
                        x_bits,
                        public_parameters,
                    )
                };

                if constant_time {
                    partially_evaluated_polynomial_by_x
                        .add_constant_time(coefficient, public_parameters)
                } else {
                    partially_evaluated_polynomial_by_x.add_vartime(coefficient, public_parameters)
                }
            },
        )
    }

    /// Takes a *public* degree $x$ (u16) and evaluates $f(x)$ using Horner's method.
    /// The number of bits of `x` is leaked in the time pattern.
    /// Delegates to `evaluate_public_point`.
    pub fn evaluate_degree(
        &self,
        x: u16,
        constant_time: bool,
        public_parameters: &T::PublicParameters,
    ) -> T {
        let x = U64::from(x);
        self.evaluate_public_point(&x, x.bits(), constant_time, public_parameters)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Wrapping, U64};

    use super::*;

    #[test]
    fn evaluates() {
        let polynomial = Polynomial::try_from(vec![
            Wrapping(U64::from(1u8)),
            Wrapping(U64::from(2u8)),
            Wrapping(U64::from(3u8)),
        ])
        .unwrap();

        assert_eq!(
            polynomial.evaluate(&Wrapping(U64::from(0u8))),
            Wrapping(U64::from(1u8))
        );

        assert_eq!(
            polynomial.evaluate(&Wrapping(U64::from(5u8))),
            Wrapping(U64::from(86u8))
        );
    }

    /// Simple polynomial evaluation test: f(x) = 1 + 3x + 2x², f(2) = 1 + 6 + 8 = 15
    #[test]
    fn evaluates_simple_polynomial() {
        // Polynomial: f(x) = 1 + 3x + 2x² (coefficients: [1, 3, 2])
        let polynomial = Polynomial::try_from(vec![
            Wrapping(U64::from(1u8)),
            Wrapping(U64::from(3u8)),
            Wrapping(U64::from(2u8)),
        ])
        .unwrap();

        // f(2) = 1 + 3*2 + 2*4 = 1 + 6 + 8 = 15
        assert_eq!(
            polynomial.evaluate(&Wrapping(U64::from(2u8))),
            Wrapping(U64::from(15u8))
        );
    }
}
