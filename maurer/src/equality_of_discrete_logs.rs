// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use serde::Serialize;

use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
use group::helpers::{const_generic_array_serialization, FlatMapResults};
use group::{self_product, Samplable, Scale, Transcribeable};
use proof::{
    CanonicalGroupsPublicParameters, GroupsPublicParameters, GroupsPublicParametersAccessors,
};

use crate::{Result, SOUND_PROOFS_REPETITIONS};

/// Equality of Discrete Logs Maurer Language.
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However, knowledge-soundness proofs are group-dependent, and thus we can only assure security
/// for groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
pub type Language<const BATCH_SIZE: usize, Scalar, GroupElement> =
    private::Language<BATCH_SIZE, SOUND_PROOFS_REPETITIONS, Scalar, GroupElement>;

impl<
        const BATCH_SIZE: usize,
        const REPETITIONS: usize,
        Scalar: group::GroupElement + Samplable + Copy,
        GroupElement: group::GroupElement + Scale<group::Value<Scalar>>,
    > crate::Language<REPETITIONS> for Language<BATCH_SIZE, Scalar, GroupElement>
{
    type WitnessSpaceGroupElement = Scalar;
    type StatementSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, GroupElement>;

    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        group::Value<GroupElement>,
    >;

    const NAME: &'static str = "Equality of Discrete Logs";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        is_randomizer: bool,
        is_verify: bool,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let bases = language_public_parameters
            .bases
            .clone()
            .map(|base| {
                GroupElement::new(
                    base,
                    &language_public_parameters
                        .groups_public_parameters
                        .statement_space_public_parameters
                        .0,
                )
            })
            .flat_map_results()?;

        let bases_by_discrete_log = bases.map(|base| {
            if is_verify {
                base.scale_vartime_by(
                    &witness.value(),
                    &language_public_parameters
                        .statement_space_public_parameters()
                        .0,
                )
            } else if let Some(discrete_log_upper_bound_bits) = language_public_parameters
                .discrete_log_sample_bits
                .map(|discrete_log_upper_sample_bits| {
                    if is_randomizer {
                        discrete_log_upper_sample_bits + MAURER_RANDOMIZER_DIFF_BITS
                    } else {
                        discrete_log_upper_sample_bits
                    }
                })
            {
                base.scale_randomized_public_base_bounded_by(
                    &witness.value(),
                    discrete_log_upper_bound_bits,
                    &language_public_parameters
                        .statement_space_public_parameters()
                        .0,
                )
            } else {
                base.scale_randomized_public_base_by(
                    &witness.value(),
                    &language_public_parameters
                        .statement_space_public_parameters()
                        .0,
                )
            }
        });

        Ok(bases_by_discrete_log.into())
    }
}

/// The Public Parameters of Equality of Discrete Logs Maurer Language.
#[derive(Clone, Debug, PartialEq, Serialize, Eq)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    ScalarPublicParameters,
    GroupPublicParameters,
    GroupElementValue,
> where
    GroupElementValue: Serialize,
{
    pub groups_public_parameters: GroupsPublicParameters<
        ScalarPublicParameters,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    >,
    #[serde(with = "const_generic_array_serialization")]
    pub bases: [GroupElementValue; BATCH_SIZE],
    pub discrete_log_sample_bits: Option<u32>,
}

impl<const BATCH_SIZE: usize, ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    PublicParameters<BATCH_SIZE, ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
where
    GroupElementValue: Serialize,
{
    pub fn new<Scalar, GroupElement>(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        bases: [GroupElementValue; BATCH_SIZE],
        discrete_log_sample_bits: Option<u32>,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + group::GroupElement
            + Samplable
            + Copy,
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + Scale<group::Value<Scalar>>,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: scalar_group_public_parameters,
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<BATCH_SIZE, GroupElement>,
                >::new(group_public_parameters),
            },
            bases,
            discrete_log_sample_bits,
        }
    }
}

impl<const BATCH_SIZE: usize, ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    AsRef<
        GroupsPublicParameters<
            ScalarPublicParameters,
            self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
        >,
    >
    for PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
    >
where
    GroupElementValue: Serialize,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        ScalarPublicParameters,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

/// The Canonical Representation of the Public Parameters of Equality of Discrete Logs Maurer Language.
#[derive(Serialize)]
pub struct CanonicalPublicParameters<
    const BATCH_SIZE: usize,
    ScalarPublicParameters: Transcribeable + Serialize,
    GroupPublicParameters: Transcribeable + Serialize,
    GroupElementValue: Serialize,
> {
    canonical_groups_public_parameters: CanonicalGroupsPublicParameters<
        ScalarPublicParameters,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    >,
    #[serde(with = "const_generic_array_serialization")]
    bases: [GroupElementValue; BATCH_SIZE],
    discrete_log_sample_bits: Option<u32>,
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
        GroupElementValue: Serialize,
    >
    From<
        PublicParameters<
            BATCH_SIZE,
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
        >,
    >
    for CanonicalPublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
    >
{
    fn from(
        value: PublicParameters<
            BATCH_SIZE,
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
        >,
    ) -> Self {
        Self {
            canonical_groups_public_parameters: value.groups_public_parameters.into(),
            bases: value.bases,
            discrete_log_sample_bits: value.discrete_log_sample_bits,
        }
    }
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
        GroupElementValue: Serialize,
    > Transcribeable
    for PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
    >
{
    type CanonicalRepresentation = CanonicalPublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
    >;
}

pub type Proof<const BATCH_SIZE: usize, Scalar, GroupElement, ProtocolContext> = crate::Proof<
    SOUND_PROOFS_REPETITIONS,
    Language<BATCH_SIZE, Scalar, GroupElement>,
    ProtocolContext,
>;

pub(super) mod private {
    use std::marker::PhantomData;

    use serde::{Deserialize, Serialize};

    #[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
    pub struct Language<const BATCH_SIZE: usize, const REPETITIONS: usize, Scalar, GroupElement> {
        _scalar_choice: PhantomData<Scalar>,
        _group_element_choice: PhantomData<GroupElement>,
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use crypto_bigint::U256;
    use rstest::rstest;

    use group::{secp256k1, CyclicGroupElement, GroupElement, OsCsRng};

    use crate::language::StatementSpaceGroupElement;
    use crate::test_helpers::{batch_verifies, generate_valid_proof, sample_witnesses};
    use crate::{language, test_helpers};

    use super::*;

    pub type Lang = Language<2, secp256k1::Scalar, secp256k1::GroupElement>;

    pub fn language_public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
    {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let second_base =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsCsRng).unwrap()
                * secp256k1::GroupElement::generator_from_public_parameters(
                    &secp256k1_group_public_parameters,
                )
                .unwrap();

        PublicParameters::new::<secp256k1::Scalar, secp256k1::GroupElement>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters.clone(),
            [
                secp256k1_group_public_parameters.generator,
                second_base.value(),
            ],
            None,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            batch_size,
            &mut OsCsRng,
        );
    }

    #[rstest]
    #[case(1, 1)]
    #[case(2, 2)]
    #[case(3, 1)]
    fn valid_proofs_verifies_batch(#[case] number_of_proofs: usize, #[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        let (proofs, statements): (
            Vec<crate::Proof<SOUND_PROOFS_REPETITIONS, Lang, _>>,
            Vec<Vec<StatementSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>>>,
        ) = iter::repeat_with(|| {
            let witnesses = sample_witnesses::<SOUND_PROOFS_REPETITIONS, Lang>(
                &language_public_parameters,
                batch_size,
                &mut OsCsRng,
            );

            generate_valid_proof(&language_public_parameters, witnesses, &mut OsCsRng)
        })
        .take(number_of_proofs)
        .unzip();

        batch_verifies(
            proofs,
            statements,
            &language_public_parameters,
            &mut OsCsRng,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
            None,
            None,
            &language_public_parameters,
            batch_size,
            &mut OsCsRng,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_over_invalid_public_parameters_fails_verification(#[case] batch_size: usize) {
        let verifier_public_parameters = language_public_parameters();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        prover_public_parameters.bases[0] = secp256k1::GroupElement::new(
            prover_public_parameters.bases[0],
            &secp256k1_group_public_parameters,
        )
        .unwrap()
        .generator()
        .neutral()
        .value();

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsCsRng,
        );

        let mut prover_public_parameters = verifier_public_parameters.clone();
        prover_public_parameters
            .groups_public_parameters
            .statement_space_public_parameters
            .0
            .curve_equation_a = U256::from(42u8);

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsCsRng,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_with_incomplete_transcript_fails(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::proof_with_incomplete_transcript_fails::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            batch_size,
            &mut OsCsRng,
        )
    }
}
