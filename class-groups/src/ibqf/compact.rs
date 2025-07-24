// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::BitAnd;

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use crypto_bigint::{Concat, Encoding, Gcd, Int, NonZero, Split, Uint};
use serde::{Deserialize, Serialize};

use crate::discriminant::Discriminant;
use crate::ibqf::Ibqf;
use crate::Error;

/// Compact variant to [Ibqf].
/// Together with a [Discriminant], this can be converted to an [Ibqf]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompactIbqf<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
{
    a: NonZero<Int<LIMBS>>,
    b: Int<LIMBS>,
}

impl<const LIMBS: usize> CompactIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    pub(crate) fn new(a: NonZero<Int<LIMBS>>, b: Int<LIMBS>) -> Self {
        Self { a, b }
    }
}

impl<const LIMBS: usize> TryFrom<Ibqf<LIMBS>> for CompactIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Error = Error;

    // TODO: optimization; only store half of the a and b limb; when reduced, they are half-empty.
    fn try_from(value: Ibqf<LIMBS>) -> Result<Self, Self::Error> {
        if value.is_reduced_vartime() {
            Ok(Self::new(value.a, value.b))
        } else {
            Err(Error::Unreduced)
        }
    }
}

impl<const LIMBS: usize, const DOUBLE_LIMBS: usize>
    TryFrom<(CompactIbqf<LIMBS>, Discriminant<LIMBS>)> for Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>> + Gcd<Output = Uint<LIMBS>>,
    Int<DOUBLE_LIMBS>: Encoding,
    Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Error = Error;

    fn try_from(value: (CompactIbqf<LIMBS>, Discriminant<LIMBS>)) -> Result<Self, Self::Error> {
        let (form, discriminant) = value;
        Ibqf::new(form.a, form.b, &discriminant)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for CompactIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            a: NonZero::<Int<LIMBS>>::conditional_select(&a.a, &b.a, choice),
            b: Int::<LIMBS>::conditional_select(&a.b, &b.b, choice),
        }
    }
}

impl<const LIMBS: usize> ConstantTimeEq for CompactIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.a.ct_eq(&other.a).bitand(self.b.ct_eq(&other.b))
    }
}

impl<const LIMBS: usize> Default for CompactIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self {
            // safe to unwrap; one is a non-zero constant
            a: Int::ONE.to_nz().unwrap(),
            b: Int::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::I128;

    use crate::discriminant::Discriminant;
    use crate::ibqf::compact::CompactIbqf;
    use crate::ibqf::Ibqf;

    #[test]
    fn test_from_ibqf() {
        let d = Discriminant::try_from(I128::from(-46579631i32).to_nz().unwrap()).unwrap();
        let form = Ibqf::new_reduced(I128::from(1877).to_nz().unwrap(), I128::ONE, &d).unwrap();
        let compact = CompactIbqf::<{ I128::LIMBS }>::try_from(form).unwrap();

        let reconstructed = Ibqf::try_from((compact, d)).unwrap();
        assert_eq!(reconstructed, form);
    }

    #[test]
    fn test_from_compactibqf_discriminant() {
        let a = I128::from(1877).to_nz().unwrap();
        let b = I128::ONE;
        let c = CompactIbqf::new(a, b);
        let d = Discriminant::try_from(I128::from(-46579631i32).to_nz().unwrap()).unwrap();

        let f = Ibqf::try_from((c, d)).unwrap();
        assert_eq!(f.a, a.resize().to_nz().unwrap());
        assert_eq!(f.b, b.resize());
        assert_eq!(f.discriminant().unwrap(), (*d).get());
    }
}
