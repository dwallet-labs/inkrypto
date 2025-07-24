// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::{marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use commitment::HomomorphicCommitmentScheme;
use group::{self_product, BoundedGroupElement, CyclicGroupElement, Samplable};
use proof::GroupsPublicParameters;

use crate::{Result, SOUND_PROOFS_REPETITIONS};

/// Commitment of Discrete Log Maurer Language:
// $$ (x,r) \mapsto (\textsf{Com}(x; r), g^x) $$
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However knowledge-soundness proofs are group dependent, and thus we can only assure security for
/// groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<
        const SCALAR_LIMBS: usize,
        Scalar: BoundedGroupElement<SCALAR_LIMBS>
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: CyclicGroupElement,
        CommitmentScheme: HomomorphicCommitmentScheme<
            SCALAR_LIMBS,
            MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
            RandomnessSpaceGroupElement = Scalar,
            CommitmentSpaceGroupElement = GroupElement,
        >,
    > crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
{
    type WitnessSpaceGroupElement = self_product::GroupElement<2, Scalar>;
    type StatementSpaceGroupElement = self_product::GroupElement<2, GroupElement>;

    type PublicParameters = PublicParameters<
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        CommitmentScheme::PublicParameters,
        GroupElement::Value,
    >;

    const NAME: &'static str = "Commitment of Discrete Log";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let base = GroupElement::new(
            language_public_parameters.base,
            &language_public_parameters
                .groups_public_parameters
                .statement_space_public_parameters
                .public_parameters,
        )?;

        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok([
            commitment_scheme.commit(
                &[*witness.commitment_message()].into(),
                witness.commitment_randomness(),
            ),
            *witness.commitment_message() * base,
        ]
        .into())
    }
}

pub trait WitnessAccessors<Scalar: group::GroupElement> {
    fn commitment_message(&self) -> &Scalar;

    fn commitment_randomness(&self) -> &Scalar;
}

impl<Scalar: group::GroupElement> WitnessAccessors<Scalar>
    for self_product::GroupElement<2, Scalar>
{
    fn commitment_message(&self) -> &Scalar {
        let value: &[Scalar; 2] = self.into();

        &value[0]
    }

    fn commitment_randomness(&self) -> &Scalar {
        let value: &[Scalar; 2] = self.into();

        &value[1]
    }
}

pub trait StatementAccessors<GroupElement: group::GroupElement> {
    fn committment_of_discrete_log(&self) -> &GroupElement;

    fn base_by_discrete_log(&self) -> &GroupElement;
}

impl<GroupElement: group::GroupElement> StatementAccessors<GroupElement>
    for self_product::GroupElement<2, GroupElement>
{
    fn committment_of_discrete_log(&self) -> &GroupElement {
        let value: &[_; 2] = self.into();

        &value[0]
    }

    fn base_by_discrete_log(&self) -> &GroupElement {
        let value: &[_; 2] = self.into();

        &value[1]
    }
}

/// The Public Parameters of the Commitment of Discrete Log Maurer Language
#[derive(Debug, PartialEq, Serialize, Clone, Eq)]
pub struct PublicParameters<
    ScalarPublicParameters,
    GroupPublicParameters,
    CommitmentSchemePublicParameters,
    GroupElementValue,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<2, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupPublicParameters>,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    pub base: GroupElementValue,
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<2, ScalarPublicParameters>,
            self_product::PublicParameters<2, GroupPublicParameters>,
        >,
    >
    for PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<2, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
    PublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    pub fn new<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
        base: GroupElementValue,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + BoundedGroupElement<SCALAR_LIMBS>
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
        CommitmentScheme: HomomorphicCommitmentScheme<
                SCALAR_LIMBS,
                PublicParameters = CommitmentSchemePublicParameters,
            > + HomomorphicCommitmentScheme<
                SCALAR_LIMBS,
                MessageSpaceGroupElement = self_product::GroupElement<1, Scalar>,
                RandomnessSpaceGroupElement = Scalar,
                CommitmentSpaceGroupElement = GroupElement,
            >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, Scalar>,
                >::new(
                    scalar_group_public_parameters
                ),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, GroupElement>,
                >::new(group_public_parameters),
            },
            commitment_scheme_public_parameters,
            base,
        }
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use commitment::{pedersen, pedersen::Pedersen};
    use group::secp256k1;

    use crate::language;

    use super::*;

    pub type Lang = Language<
        { secp256k1::SCALAR_LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        Pedersen<1, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
    >;

    pub fn language_public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
    {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let pedersen_public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        let generator = secp256k1_group_public_parameters.generator;

        PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Pedersen<1, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            pedersen_public_parameters,
            generator,
        )
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::U256;
    use rand_core::OsRng;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::iter;

    use group::PartyID;
    use group::{secp256k1, GroupElement};
    use mpc::Weight;

    use crate::commitment_of_discrete_log::test_helpers::language_public_parameters;
    use crate::commitment_of_discrete_log::test_helpers::Lang;
    use crate::language::StatementSpaceGroupElement;
    use crate::test_helpers;
    use crate::test_helpers::{batch_verifies, generate_valid_proof, sample_witnesses};

    use super::*;

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
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
        let language_public_parameters = language_public_parameters();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let verifier_public_parameters = language_public_parameters();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();
        prover_public_parameters.base = secp256k1::GroupElement::new(
            prover_public_parameters.base,
            &secp256k1_group_public_parameters,
        )
        .unwrap()
        .neutral()
        .value();

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );

        let mut prover_public_parameters = verifier_public_parameters.clone();
        prover_public_parameters
            .groups_public_parameters
            .statement_space_public_parameters
            .public_parameters
            .curve_equation_a = U256::from(42u8);

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );

        let mut prover_public_parameters = verifier_public_parameters.clone();
        prover_public_parameters
            .commitment_scheme_public_parameters
            .message_generators[0] = prover_public_parameters
            .commitment_scheme_public_parameters
            .randomness_generator;

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
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
        let language_public_parameters = language_public_parameters();

        test_helpers::proof_with_incomplete_transcript_fails::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let language_public_parameters = language_public_parameters();

        test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let language_public_parameters = language_public_parameters();

        test_helpers::statement_aggregates_asynchronously::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let language_public_parameters = language_public_parameters();

        test_helpers::unresponsive_parties_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
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
        let language_public_parameters = language_public_parameters();

        test_helpers::wrong_decommitment_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
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
        let language_public_parameters = language_public_parameters();

        test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(&language_public_parameters, number_of_parties, batch_size);
    }
}

#[cfg(feature = "benchmarking")]
pub mod benches {
    use criterion::Criterion;

    use crate::{
        commitment_of_discrete_log::test_helpers::{language_public_parameters, Lang},
        test_helpers,
    };

    use super::*;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let language_public_parameters = language_public_parameters();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            None,
            false,
            None,
        );
        test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            None,
            false,
            None,
        );
    }
}
