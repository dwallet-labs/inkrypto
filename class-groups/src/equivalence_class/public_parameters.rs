// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::discriminant::Discriminant;
use crate::ibqf::Ibqf;
use crate::Error;
use crypto_bigint::{Encoding, Int, NonZeroInt};
use group::Transcribeable;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;

/// TODO(#300): the serialization of this object should not be sent over a wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicParameters<const DISCRIMINANT_LIMBS: usize>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    pub(crate) discriminant: Discriminant<DISCRIMINANT_LIMBS>,
    form_to_accelerators:
        HashMap<Ibqf<DISCRIMINANT_LIMBS>, Vec<MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>>>,
}

impl<const DISCRIMINANT_LIMBS: usize> PublicParameters<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    pub(crate) fn new_unaccelerated(discriminant: Discriminant<DISCRIMINANT_LIMBS>) -> Self {
        Self::new(discriminant, HashMap::new())
    }

    /// Note: the forms in `form_to_accelerators` must be public, as they will be leaked in the time-pattern.
    pub(crate) fn new_accelerated(
        discriminant: Discriminant<DISCRIMINANT_LIMBS>,
        form_to_accelerators: HashMap<
            Ibqf<DISCRIMINANT_LIMBS>,
            Vec<MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>>,
        >,
    ) -> crate::Result<Self> {
        if form_to_accelerators.is_empty() || form_to_accelerators.values().any(|v| v.is_empty()) {
            return Err(Error::InvalidParameters);
        }

        Ok(Self::new(discriminant, form_to_accelerators))
    }

    /// Note: the forms in `form_to_accelerators` must be public, as they will be leaked in the time-pattern.
    fn new(
        discriminant: Discriminant<DISCRIMINANT_LIMBS>,
        form_to_accelerators: HashMap<
            Ibqf<DISCRIMINANT_LIMBS>,
            Vec<MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>>,
        >,
    ) -> Self {
        let form_to_accelerators: HashMap<_, _> = form_to_accelerators
            .into_iter()
            .map(|(form, mut accelerators)| {
                // Store the form as the key to the hash-map to ensure canonical representations.
                accelerators.sort_by(|accelerator1, accelerator2| {
                    accelerator1.target_bits.cmp(&accelerator2.target_bits)
                });

                (form, accelerators)
            })
            .collect();

        Self {
            discriminant,
            form_to_accelerators,
        }
    }

    /// Read-only access to this public parameters `discriminant`
    pub(crate) fn discriminant(&self) -> &Discriminant<DISCRIMINANT_LIMBS> {
        &self.discriminant
    }

    pub(crate) fn insert_accelerators_for(
        &mut self,
        form: Ibqf<DISCRIMINANT_LIMBS>,
        accelerators: Vec<MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>>,
    ) {
        assert!(!self.form_to_accelerators.is_empty());
        assert!(self.form_to_accelerators.values().all(|v| !v.is_empty()));
        assert!(!accelerators.is_empty());

        // Store the form as the key to the hash-map to ensure canonical representations.
        let mut accelerators = accelerators;
        accelerators.sort_by(|accelerator1, accelerator2| {
            accelerator1.target_bits.cmp(&accelerator2.target_bits)
        });

        self.form_to_accelerators.insert(form, accelerators);
    }

    /// Obtain read-only access to the `accelerator` for `form`, or `None` if it does not exist.
    pub(crate) fn get_accelerator_for(
        &self,
        form: &Ibqf<DISCRIMINANT_LIMBS>,
        exp_bits: u32,
    ) -> Option<&MultiFoldNupowAccelerator<DISCRIMINANT_LIMBS>> {
        self.form_to_accelerators
            .get(form)
            .and_then(|accelerators| {
                // `accelerators` is guaranteed to be sorted in ascending order by the `.target_bits` field,
                // as we sort it in both `new()` and `insert_accelerators_for()`.
                accelerators
                    .iter()
                    .find_or_last(|accelerator| exp_bits <= accelerator.target_bits)
            })
    }
}

#[derive(Serialize)]
pub struct CanonicalPublicParameters<const DISCRIMINANT_LIMBS: usize>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    discriminant: NonZeroInt<DISCRIMINANT_LIMBS>,
}

impl<const DISCRIMINANT_LIMBS: usize> From<PublicParameters<DISCRIMINANT_LIMBS>>
    for CanonicalPublicParameters<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    fn from(value: PublicParameters<DISCRIMINANT_LIMBS>) -> Self {
        Self {
            discriminant: *value.discriminant.deref(),
        }
    }
}

impl<const DISCRIMINANT_LIMBS: usize> Transcribeable for PublicParameters<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    type CanonicalRepresentation = CanonicalPublicParameters<DISCRIMINANT_LIMBS>;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crypto_bigint::I128;

    use crate::discriminant::Discriminant;
    use crate::equivalence_class::public_parameters::PublicParameters;

    #[test]
    fn test_new() {
        let value = I128::from(-775).to_nz().unwrap();
        let d = Discriminant::try_from(value).unwrap();
        let pp = PublicParameters::new(d, HashMap::default());
        assert_eq!(*pp.discriminant(), d)
    }
}
