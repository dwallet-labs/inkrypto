// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{Encoding, Int};
use serde::{Deserialize, Deserializer};

use crate::ibqf::Ibqf;
use crate::EquivalenceClass;

impl<'de, const DISCRIMINANT_LIMBS: usize> Deserialize<'de> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let representative = Ibqf::<DISCRIMINANT_LIMBS>::deserialize(deserializer)?;
        Ok(Self::from(representative))
    }
}
