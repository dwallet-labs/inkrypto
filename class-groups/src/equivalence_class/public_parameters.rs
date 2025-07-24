// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{Encoding, Int, NonZero};
use serde::{Deserialize, Serialize};

use crate::discriminant::Discriminant;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicParameters<const DISCRIMINANT_LIMBS: usize>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    pub(crate) discriminant: NonZero<Int<DISCRIMINANT_LIMBS>>,
}

impl<const DISCRIMINANT_LIMBS: usize> PublicParameters<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    pub fn new(discriminant: Discriminant<DISCRIMINANT_LIMBS>) -> Self {
        Self {
            discriminant: *discriminant,
        }
    }

    pub(crate) fn discriminant(&self) -> Discriminant<DISCRIMINANT_LIMBS> {
        // safe to unwrap, since this value was passed in as a valid Discriminant.
        Discriminant::try_from(self.discriminant).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::I128;

    use crate::discriminant::Discriminant;
    use crate::equivalence_class::public_parameters::PublicParameters;

    #[test]
    fn test_new() {
        let value = I128::from(-775).to_nz().unwrap();
        let d = Discriminant::try_from(value).unwrap();
        let pp = PublicParameters::new(d);
        assert_eq!(pp.discriminant(), d)
    }
}
