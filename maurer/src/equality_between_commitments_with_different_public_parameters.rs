// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use commitment::{GroupsPublicParametersAccessors, HomomorphicCommitmentScheme};
use group::{direct_product, self_product, Samplable};
use proof::GroupsPublicParameters;

use crate::{Result, SOUND_PROOFS_REPETITIONS};

/// Equality Between Two Commitments With Different Public Parameters Maurer Language.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
> {
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
    > crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>
where
    CommitmentScheme::MessageSpaceGroupElement: Samplable,
    CommitmentScheme::RandomnessSpaceGroupElement: Samplable,
{
    type WitnessSpaceGroupElement = direct_product::GroupElement<
        CommitmentScheme::MessageSpaceGroupElement,
        self_product::GroupElement<2, CommitmentScheme::RandomnessSpaceGroupElement>,
    >;
    type StatementSpaceGroupElement =
        self_product::GroupElement<2, CommitmentScheme::CommitmentSpaceGroupElement>;

    type PublicParameters = PublicParameters<
        group::PublicParameters<CommitmentScheme::MessageSpaceGroupElement>,
        group::PublicParameters<CommitmentScheme::RandomnessSpaceGroupElement>,
        group::PublicParameters<CommitmentScheme::CommitmentSpaceGroupElement>,
        CommitmentScheme::PublicParameters,
    >;

    const NAME: &'static str = "Equality Between Two Commitments With Different Public Parameters";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let first_commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.first_commitment_scheme_public_parameters,
        )?;

        let second_commitment_scheme = CommitmentScheme::new(
            &language_public_parameters.second_commitment_scheme_public_parameters,
        )?;

        let [first_randomness, second_randomness] = (*witness.commitment_randomnesses()).into();

        Ok([
            first_commitment_scheme.commit(witness.commitment_message(), &first_randomness),
            second_commitment_scheme.commit(witness.commitment_message(), &second_randomness),
        ]
        .into())
    }
}

pub trait WitnessAccessors<
    CommitmentSchemeMessageSpaceGroupElement,
    CommitmentSchemeRandomnessSpaceGroupElement,
>
{
    fn commitment_message(&self) -> &CommitmentSchemeMessageSpaceGroupElement;

    fn commitment_randomnesses(
        &self,
    ) -> &self_product::GroupElement<2, CommitmentSchemeRandomnessSpaceGroupElement>;
}

impl<CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement>
    WitnessAccessors<
        CommitmentSchemeMessageSpaceGroupElement,
        CommitmentSchemeRandomnessSpaceGroupElement,
    >
    for direct_product::GroupElement<
        CommitmentSchemeMessageSpaceGroupElement,
        self_product::GroupElement<2, CommitmentSchemeRandomnessSpaceGroupElement>,
    >
{
    fn commitment_message(&self) -> &CommitmentSchemeMessageSpaceGroupElement {
        let value: (&_, &_) = self.into();

        value.0
    }

    fn commitment_randomnesses(
        &self,
    ) -> &self_product::GroupElement<2, CommitmentSchemeRandomnessSpaceGroupElement> {
        let value: (&_, &_) = self.into();

        value.1
    }
}

/// The Public Parameters of the Equality Between Two Commitments With Different Public Parameters
/// Maurer Language.
#[derive(Clone, Debug, PartialEq, Serialize, Eq)]
pub struct PublicParameters<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::PublicParameters<
            MessageSpacePublicParameters,
            self_product::PublicParameters<2, RandomnessSpacePublicParameters>,
        >,
        self_product::PublicParameters<2, CommitmentSpacePublicParameters>,
    >,
    pub first_commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub second_commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
}

impl<
        MessageSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
        CommitmentSchemePublicParameters,
    >
    PublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    >
{
    pub fn new<const MESSAGE_SPACE_SCALAR_LIMBS: usize, CommitmentScheme>(
        first_commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
        second_commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    ) -> Self
    where
        CommitmentScheme::MessageSpaceGroupElement:
            group::GroupElement<PublicParameters = MessageSpacePublicParameters>,
        CommitmentScheme::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentScheme::CommitmentSpaceGroupElement:
            group::GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        CommitmentScheme: HomomorphicCommitmentScheme<
            MESSAGE_SPACE_SCALAR_LIMBS,
            PublicParameters = CommitmentSchemePublicParameters,
        >,
        CommitmentSchemePublicParameters: AsRef<
            commitment::GroupsPublicParameters<
                MessageSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: direct_product::PublicParameters(
                    first_commitment_scheme_public_parameters
                        .message_space_public_parameters()
                        .clone(),
                    group::PublicParameters::<
                        self_product::GroupElement<
                            2,
                            CommitmentScheme::RandomnessSpaceGroupElement,
                        >,
                    >::new(
                        first_commitment_scheme_public_parameters
                            .randomness_space_public_parameters()
                            .clone(),
                    ),
                ),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, CommitmentScheme::CommitmentSpaceGroupElement>,
                >::new(
                    first_commitment_scheme_public_parameters
                        .commitment_space_public_parameters()
                        .clone(),
                ),
            },
            first_commitment_scheme_public_parameters,
            second_commitment_scheme_public_parameters,
        }
    }
}

impl<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                MessageSpacePublicParameters,
                self_product::PublicParameters<2, RandomnessSpacePublicParameters>,
            >,
            self_product::PublicParameters<2, CommitmentSpacePublicParameters>,
        >,
    >
    for PublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            MessageSpacePublicParameters,
            self_product::PublicParameters<2, RandomnessSpacePublicParameters>,
        >,
        self_product::PublicParameters<2, CommitmentSpacePublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use super::*;
    use crate::language;
    use commitment::{pedersen, Pedersen};
    use group::{secp256k1, CyclicGroupElement, GroupElement};

    pub type Lang<const BATCH_SIZE: usize> = Language<
        { secp256k1::SCALAR_LIMBS },
        Pedersen<
            BATCH_SIZE,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >,
    >;

    pub fn language_public_parameters<const BATCH_SIZE: usize>(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang<BATCH_SIZE>> {
        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::group_element::GroupElement::generator_from_public_parameters(
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let first_commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive_default::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
            >()
            .unwrap();

        let second_commitment_scheme_public_parameters = first_commitment_scheme_public_parameters
            .with_altered_randomness_generator((generator + generator).value());

        PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            Pedersen<
                BATCH_SIZE,
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
            >,
        >(
            first_commitment_scheme_public_parameters,
            second_commitment_scheme_public_parameters,
        )
    }
}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::iter;

    use rand_core::OsRng;
    use rstest::rstest;

    use group::PartyID;
    use mpc::Weight;

    use super::test_helpers::*;
    use crate::language::StatementSpaceGroupElement;
    use crate::test_helpers::{batch_verifies, generate_valid_proof, sample_witnesses};
    use crate::{test_helpers, SOUND_PROOFS_REPETITIONS};

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(1, 1)]
    #[case(2, 2)]
    #[case(3, 1)]
    fn valid_proofs_verifies_batch(#[case] number_of_proofs: usize, #[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<1>();

        let (proofs, statements): (
            Vec<crate::Proof<SOUND_PROOFS_REPETITIONS, Lang<1>, _>>,
            Vec<Vec<StatementSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang<1>>>>,
        ) = iter::repeat_with(|| {
            let witnesses = sample_witnesses::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
                &language_public_parameters,
                batch_size,
                &mut OsRng,
            );

            generate_valid_proof(&language_public_parameters, witnesses, &mut OsRng)
        })
        .take(number_of_proofs)
        .unzip();

        batch_verifies(proofs, statements, &language_public_parameters, &mut OsRng);
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<1>();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
            None,
            None,
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_over_invalid_public_parameters_fails_verification(#[case] batch_size: usize) {
        let verifier_public_parameters = language_public_parameters::<1>();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        prover_public_parameters
            .first_commitment_scheme_public_parameters
            .message_generators[0] = prover_public_parameters
            .first_commitment_scheme_public_parameters
            .randomness_generator;

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang<1>,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_with_incomplete_transcript_fails(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::proof_with_incomplete_transcript_fails::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
            &language_public_parameters,
            number_of_parties,
            batch_size,
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), 1)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), 2)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), 1)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), 2)]
    fn statement_aggregates_asynchronously(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::statement_aggregates_asynchronously::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
            &language_public_parameters,
            threshold,
            party_to_weight,
            batch_size,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 1)]
    #[case(5, 2)]
    fn unresponsive_parties_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::unresponsive_parties_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang<1>,
        >(&language_public_parameters, number_of_parties, batch_size);
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 1)]
    #[case(5, 2)]
    fn wrong_decommitment_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::wrong_decommitment_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang<1>,
        >(&language_public_parameters, number_of_parties, batch_size);
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 1)]
    #[case(5, 2)]
    fn failed_proof_share_verification_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang<1>,
        >(&language_public_parameters, number_of_parties, batch_size);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;

    use crate::{
        equality_between_commitments_with_different_public_parameters::test_helpers::{
            language_public_parameters, Lang,
        },
        test_helpers, SOUND_PROOFS_REPETITIONS,
    };

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let language_public_parameters = language_public_parameters::<1>();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
            &language_public_parameters,
            None,
            false,
            None,
        );

        test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, Lang<1>>(
            &language_public_parameters,
            None,
            false,
            None,
        );
    }
}
