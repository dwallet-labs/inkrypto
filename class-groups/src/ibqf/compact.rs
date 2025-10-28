// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::BitAnd;

use crate::discriminant::Discriminant;
use crate::ibqf::Ibqf;
use crate::Error;
use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crypto_bigint::{Concat, Encoding, Int, Split, Uint};
use serde::{Deserialize, Serialize};

/// Compact representation of [Ibqf].
/// Together with a [Discriminant], this can be converted back into an [Ibqf].
///
/// This is a new-type around a `Uint`; internally, this `Uint` is used to represent the
/// concatenation of a form's `a` and `b` coefficient, where
/// - `a` is represented using the `Uint::<LIMBS>::BITS/2` least significant bits, and
/// - `b` is represented using the `Uint::<LIMBS>::BITS/2` most significant bits.
///
/// E.g.,
/// ```
/// use crypto_bigint::U64;
/// U64::from_be_hex("FFFF76540000ABCD");
/// ```
/// represents
/// ```
/// use crypto_bigint::{I64, U64};
/// let a = U64::from_be_hex("000000000000ABCD");
/// let b = I64::from_be_hex("FFFFFFFFFFFF7654");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompactIbqf<const LIMBS: usize>(Uint<LIMBS>)
where
    Uint<LIMBS>: Encoding;

impl<const LIMBS: usize> CompactIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    const HALF_BITS: u32 = Int::<LIMBS>::BITS / 2;

    const MASK: Uint<LIMBS> = Uint::<LIMBS>::MAX.shr_vartime(Self::HALF_BITS);

    /// Attempt to capture `form` into a [CompactIbqf].
    ///
    /// See [CompactIbqf] for more information.
    ///
    /// ### No information loss on `form.b`
    /// We prove why this compression step does NOT lose any information on `form.b`.
    ///
    /// To this end, let `x := Int::<LIMBS>::BITS`. It follows that `Int<LIMBS>` can represent all
    /// values in the range `[-2^{x-1}, 2^{x-1} - 1]`. Because a [Discriminant] is always negative,
    /// the largest discriminant `Δ` that can be represented by an `Int<LIMBS>` is `-2^{x-1}`.
    ///
    /// During compression, we assume to be operating on an [Ibqf] `(a, b, c)` that is reduced.
    /// The fact that it is reduced implies three things:
    /// 1. `a > 0`,
    /// 2. `b ∈ (-a, a]`, and
    /// 3. `a < √(|Δ|/3)`.
    ///
    /// Rewriting 3. yields `a < √(1/6) * 2^{x/2} < 2^{x/2-1}` and thus `a ≤ 2^{x/2-1} - 1`.
    /// Combined with 1. and 2., this implies that `b ∈ (-2^{x/2-1} + 1, 2^{x/2-1} - 1]`. Note that
    /// all the values in this range can be represented by an `Int<HALF>`.
    ///
    /// Given that `Int` uses a two-complement representation, this implies that the `x/2` least
    /// significant bits of `b` already capture the entire value of `b`; the most significant `x/2`
    /// bits are just copies of the bit at index `x/2-1`. Thus, shifting these bits off leads to no
    /// information loss.
    ///
    /// In decompression, we make sure to place back the correct `x/2` most significant bits,
    /// since `Int::shr` is implemented as the [arithmetic right shift](https://en.wikipedia.org/wiki/Arithmetic_shift),
    /// shifting in copies of the `x/2-1`th bit.
    fn try_compress(form: Ibqf<LIMBS>) -> Result<Self, Error> {
        CtOption::from(form.a().try_into_uint())
            .map(|a| {
                let a = a.bitand(Self::MASK);
                Self(form.b().shl_vartime(Self::HALF_BITS).as_uint().bitor(&a))
            })
            .into_option()
            .ok_or(Error::Unreduced)
    }
}

impl<const HALF: usize, const LIMBS: usize> CompactIbqf<LIMBS>
where
    Uint<HALF>: Concat<Output = Uint<LIMBS>>,
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding + Split<Output = Uint<HALF>>,
{
    /// Decompose `self` into two [Int]'s.
    ///
    /// See [CompactIbqf] for more information.
    fn decompose(&self) -> (Uint<HALF>, Int<HALF>) {
        let (a, b) = self.0.split();
        (a, *b.as_int())
    }
}

impl<const LIMBS: usize> TryFrom<Ibqf<LIMBS>> for CompactIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    type Error = Error;

    fn try_from(value: Ibqf<LIMBS>) -> Result<Self, Self::Error> {
        Self::try_compress(value)
    }
}

impl<const HALF: usize, const LIMBS: usize> TryFrom<(CompactIbqf<LIMBS>, Discriminant<LIMBS>)>
    for Ibqf<LIMBS>
where
    Uint<HALF>: Concat<Output = Uint<LIMBS>>,
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding + Split<Output = Uint<HALF>>,
{
    type Error = Error;

    fn try_from(value: (CompactIbqf<LIMBS>, Discriminant<LIMBS>)) -> Result<Self, Self::Error> {
        let (form, discriminant) = value;

        let (a, b) = form.decompose();
        CtOption::from(a.to_nz())
            .and_then(|a| Ibqf::new_is_reduced_vartime_discriminant(a, b, &discriminant))
            .into_option()
            .ok_or(Error::CompactFormDiscriminantMismatch)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for CompactIbqf<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Uint::conditional_select(&a.0, &b.0, choice))
    }
}

impl<const LIMBS: usize> ConstantTimeEq for CompactIbqf<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const LIMBS: usize> Default for CompactIbqf<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self(Uint::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Encoding, Int, Uint, I128, U128};

    use crate::discriminant::Discriminant;
    use crate::ibqf::compact::CompactIbqf;

    use crate::ibqf::Ibqf;

    /// For testing purposes only (!)
    impl<const LIMBS: usize> CompactIbqf<LIMBS>
    where
        Uint<LIMBS>: Encoding,
    {
        pub(crate) fn new_unchecked(value: Uint<LIMBS>) -> Self {
            Self(value)
        }
    }

    #[test]
    fn test_try_from_ibqf() {
        let d = Discriminant::new_u64(9829, 0, 4739).unwrap();
        let form = Ibqf::new(U128::from_u64(1877).to_nz().unwrap(), I128::ONE, &d).unwrap();
        let compact = CompactIbqf::<{ I128::LIMBS }>::try_from(form).unwrap();

        let reconstructed = Ibqf::try_from((compact, d)).unwrap();
        assert_eq!(reconstructed, form);
    }

    #[test]
    fn test_try_from_compact_discriminant() {
        let discriminant = Discriminant::<{ U128::LIMBS }>::new_u64(101111111111, 0, 1).unwrap();
        let compact = CompactIbqf(U128::from_be_hex("0000000000000005000000000000244D"));

        let reconstructed = Ibqf::try_from((compact, discriminant)).unwrap();
        assert_eq!(reconstructed.a, Int::from_i64(9293i64).to_nz().unwrap());
        assert_eq!(reconstructed.b, Int::from_i64(5));
        assert_eq!(reconstructed.c, Int::from_i64(2720088i64).to_nz().unwrap());
    }

    #[test]
    fn test_compact_reconstruct() {
        let form = Ibqf::<{ U128::LIMBS }>::new_reduced_64(2677, -13, (46579631, 0, 1)).unwrap();
        let compact = CompactIbqf::try_from(form).unwrap();

        let d = Discriminant::new_u64(9829, 0, 4739).unwrap();
        let reconstructed = Ibqf::try_from((compact, d)).unwrap();
        assert_eq!(reconstructed, form);
    }
}
