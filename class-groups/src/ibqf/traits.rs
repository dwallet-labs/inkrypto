// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Traits for [Ibqf].

use std::ops::BitAnd;

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use crypto_bigint::{Encoding, Int, NonZero};

use crate::ibqf::Ibqf;

impl<const LIMBS: usize> ConstantTimeEq for Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.a
            .ct_eq(&other.a)
            .bitand(self.b.ct_eq(&other.b))
            .bitand(self.c.ct_eq(&other.c))
    }
}

impl<const LIMBS: usize> ConditionallySelectable for Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn conditional_select(lhs: &Self, rhs: &Self, choice: Choice) -> Self {
        Self {
            a: NonZero::<Int<LIMBS>>::conditional_select(&lhs.a, &rhs.a, choice),
            b: Int::conditional_select(&lhs.b, &rhs.b, choice),
            c: NonZero::<Int<LIMBS>>::conditional_select(&lhs.c, &rhs.c, choice),
            discriminant_bits: u32::conditional_select(
                &lhs.discriminant_bits,
                &rhs.discriminant_bits,
                choice,
            ),
        }
    }
}

impl<const LIMBS: usize> Default for Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self {
            a: NonZero::<Int<LIMBS>>::new(Int::ONE).unwrap(),
            b: Int::ZERO,
            c: NonZero::<Int<LIMBS>>::new(Int::ONE).unwrap(),
            discriminant_bits: 2,
        }
    }
}
