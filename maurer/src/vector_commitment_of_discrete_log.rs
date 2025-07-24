// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::{marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use commitment::{GroupsPublicParametersAccessors, HomomorphicCommitmentScheme};
use group::{
    direct_product, helpers::FlatMapResults, self_product, BoundedGroupElement, CyclicGroupElement,
    Samplable, Transcribeable,
};
use proof::{CanonicalGroupsPublicParameters, GroupsPublicParameters};

use crate::{Error, Result, SOUND_PROOFS_REPETITIONS};

/// Vector Commitment of Discrete Log Maurer Language
///
/// $$ (\vec{m}, \vec{\rho}) \mapsto (C_{\mainIndex}=\Com_\pp(m_{\mainIndex}; \rho_{\mainIndex})
/// \wedge Y = \sum_\mainIndex m_\mainIndex\cdot G_\mainIndex) $$
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However, knowledge-soundness proofs are group-dependent, and thus we can only assure security
/// for groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const BATCH_SIZE: usize,
    const SCALAR_LIMBS: usize,
    Scalar,
    GroupElement,
    CommitmentScheme,
> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<
        const BATCH_SIZE: usize,
        const SCALAR_LIMBS: usize,
        Scalar: BoundedGroupElement<SCALAR_LIMBS>
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: CyclicGroupElement,
        CommitmentScheme: HomomorphicCommitmentScheme<
            SCALAR_LIMBS,
            MessageSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>,
        >,
    > crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement, CommitmentScheme>
{
    type WitnessSpaceGroupElement = direct_product::GroupElement<
        self_product::GroupElement<BATCH_SIZE, Scalar>,
        CommitmentScheme::RandomnessSpaceGroupElement,
    >;
    type StatementSpaceGroupElement =
        direct_product::GroupElement<CommitmentScheme::CommitmentSpaceGroupElement, GroupElement>;

    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        commitment::RandomnessSpacePublicParameters<SCALAR_LIMBS, CommitmentScheme>,
        commitment::CommitmentSpacePublicParameters<SCALAR_LIMBS, CommitmentScheme>,
        CommitmentScheme::PublicParameters,
        GroupElement::Value,
    >;

    const NAME: &'static str = "Vector Commitment of Discrete Log";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        _is_randomizer: bool,
        _is_verify: bool,
    ) -> Result<Self::StatementSpaceGroupElement> {
        if BATCH_SIZE == 0 {
            return Err(Error::InvalidPublicParameters);
        }

        let bases = language_public_parameters
            .bases
            .map(|base| {
                GroupElement::new(base, language_public_parameters.group_public_parameters())
            })
            .flat_map_results()?;

        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        let neutral = bases[0].neutral();

        let vector_commitment_of_discrete_logs = commitment_scheme.commit(
            witness.commitment_message(),
            witness.commitment_randomness(),
        );

        let linear_combination_of_discrete_logs = bases
            .iter()
            .zip::<&[Scalar; BATCH_SIZE]>(witness.commitment_message().into())
            .fold(neutral, |acc, (base, message)| acc + (*message * base));

        Ok((
            vector_commitment_of_discrete_logs,
            linear_combination_of_discrete_logs,
        )
            .into())
    }
}

pub trait WitnessAccessors<
    MessageSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn commitment_message(&self) -> &MessageSpaceGroupElement;

    fn commitment_randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        MessageSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<MessageSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::GroupElement<MessageSpaceGroupElement, RandomnessSpaceGroupElement>
{
    fn commitment_message(&self) -> &MessageSpaceGroupElement {
        let (message, _): (&_, &_) = self.into();

        message
    }

    fn commitment_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness): (&_, &_) = self.into();

        randomness
    }
}

pub trait StatementAccessors<
    CommitmentSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    fn vector_commitment_of_discrete_logs(&self) -> &CommitmentSpaceGroupElement;

    fn linear_combination_of_discrete_logs(&self) -> &GroupElement;
}

impl<CommitmentSpaceGroupElement: group::GroupElement, GroupElement: group::GroupElement>
    StatementAccessors<CommitmentSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<CommitmentSpaceGroupElement, GroupElement>
{
    fn vector_commitment_of_discrete_logs(&self) -> &CommitmentSpaceGroupElement {
        let (commitment, _): (&_, &_) = self.into();

        commitment
    }

    fn linear_combination_of_discrete_logs(&self) -> &GroupElement {
        let (_, combination): (&_, &_) = self.into();

        combination
    }
}

/// The Public Parameters of the Vector Commitment of Discrete Log Maurer Language.
#[derive(Clone, Debug, PartialEq, Serialize, Eq)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    ScalarPublicParameters,
    GroupPublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
    GroupElementValue: Serialize,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::PublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CommitmentSpacePublicParameters, GroupPublicParameters>,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub bases: [GroupElementValue; BATCH_SIZE],
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue: Serialize,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CommitmentSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
    >
    for PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CommitmentSpacePublicParameters, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
        CommitmentSchemePublicParameters,
        GroupElementValue: Serialize,
    >
    PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    pub fn new<const SCALAR_LIMBS: usize, Scalar, GroupElement, CommitmentScheme>(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
        bases: [GroupElementValue; BATCH_SIZE],
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
        CommitmentScheme::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentScheme::CommitmentSpaceGroupElement:
            group::GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        CommitmentScheme: HomomorphicCommitmentScheme<
            SCALAR_LIMBS,
            MessageSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>,
            PublicParameters = CommitmentSchemePublicParameters,
        >,
        CommitmentSchemePublicParameters: AsRef<
            commitment::GroupsPublicParameters<
                self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: direct_product::PublicParameters(
                    group::PublicParameters::<self_product::GroupElement<BATCH_SIZE, Scalar>>::new(
                        scalar_group_public_parameters,
                    ),
                    commitment_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                ),
                statement_space_public_parameters: direct_product::PublicParameters(
                    commitment_scheme_public_parameters
                        .commitment_space_public_parameters()
                        .clone(),
                    group_public_parameters,
                ),
            },
            commitment_scheme_public_parameters,
            bases,
        }
    }

    fn group_public_parameters(&self) -> &GroupPublicParameters {
        &self
            .groups_public_parameters
            .statement_space_public_parameters
            .1
    }
}

/// The Canonical Representation of the Public Parameters of the Vector Commitment of Discrete Log Maurer Language.
#[derive(Serialize)]
pub struct CanonicalPublicParameters<
    const BATCH_SIZE: usize,
    ScalarPublicParameters: Transcribeable + Serialize,
    GroupPublicParameters: Transcribeable + Serialize,
    RandomnessSpacePublicParameters: Transcribeable + Serialize,
    CommitmentSpacePublicParameters: Transcribeable + Serialize,
    CommitmentSchemePublicParameters: Transcribeable + Serialize,
    GroupElementValue: Serialize,
> {
    pub(super) canonical_groups_public_parameters: CanonicalGroupsPublicParameters<
        direct_product::PublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CommitmentSpacePublicParameters, GroupPublicParameters>,
    >,
    pub(super) canonical_commitment_scheme_public_parameters:
        CommitmentSchemePublicParameters::CanonicalRepresentation,
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super) bases: [GroupElementValue; BATCH_SIZE],
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CommitmentSpacePublicParameters: Transcribeable + Serialize,
        CommitmentSchemePublicParameters: Transcribeable + Serialize,
        GroupElementValue: Serialize,
    >
    From<
        PublicParameters<
            BATCH_SIZE,
            ScalarPublicParameters,
            GroupPublicParameters,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
            CommitmentSchemePublicParameters,
            GroupElementValue,
        >,
    >
    for CanonicalPublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    fn from(
        value: PublicParameters<
            BATCH_SIZE,
            ScalarPublicParameters,
            GroupPublicParameters,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
            CommitmentSchemePublicParameters,
            GroupElementValue,
        >,
    ) -> Self {
        Self {
            canonical_groups_public_parameters: value.groups_public_parameters.into(),
            canonical_commitment_scheme_public_parameters: value
                .commitment_scheme_public_parameters
                .into(),
            bases: value.bases,
        }
    }
}

impl<
        const BATCH_SIZE: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CommitmentSpacePublicParameters: Transcribeable + Serialize,
        CommitmentSchemePublicParameters: Transcribeable + Serialize,
        GroupElementValue: Serialize,
    > Transcribeable
    for PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >
{
    type CanonicalRepresentation = CanonicalPublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        GroupElementValue,
    >;
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use commitment::{pedersen, MultiPedersen, Pedersen};
    use group::{secp256k1, GroupElement};

    use crate::language;

    use super::*;

    pub type Lang = Language<
        2,
        { secp256k1::SCALAR_LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        Pedersen<2, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
    >;

    pub type VectorLang = Language<
        2,
        { secp256k1::SCALAR_LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        MultiPedersen<2, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
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

        let generator = secp256k1::group_element::GroupElement::generator_from_public_parameters(
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Pedersen<2, { secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            pedersen_public_parameters,
            [generator.value(), (generator + generator).value()],
        )
    }

    pub fn vector_language_public_parameters(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, VectorLang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let multi_pedersen_public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap()
        .into();

        let generator = secp256k1_group_public_parameters.generator;

        PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            MultiPedersen<
                2,
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
            >,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            multi_pedersen_public_parameters,
            [generator; 2],
        )
    }
}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::iter;

    use crypto_bigint::U256;
    use rstest::rstest;

    use group::{secp256k1, GroupElement, OsCsRng, PartyID};
    use mpc::Weight;

    use crate::language::StatementSpaceGroupElement;
    use crate::test_helpers::batch_verifies;
    use crate::{
        test_helpers,
        test_helpers::{generate_valid_proof, sample_witnesses},
    };

    use super::test_helpers::*;
    use super::*;

    #[test]
    fn generates_correct_statement() {
        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::group_element::GroupElement::generator_from_public_parameters(
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let language_public_parameters = language_public_parameters();

        let witnesses = sample_witnesses::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            1,
            &mut OsCsRng,
        );

        let (_, statements) = generate_valid_proof::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            witnesses.clone(),
            &mut OsCsRng,
        );

        let [first_message, second_message] = (*witnesses[0].commitment_message()).into();

        assert_eq!(
            *statements[0].linear_combination_of_discrete_logs(),
            first_message * generator + second_message * (generator + generator)
        );
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

        let language_public_parameters = vector_language_public_parameters();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, VectorLang>(
            &language_public_parameters,
            batch_size,
            &mut OsCsRng,
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

        // No invalid values as secp256k1 statically defines a group,
        // `k256::AffinePoint` assures deserialized values are on the curve,
        // and `Value` can only be instantiated through deserialization.
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
            None,
            None,
            &language_public_parameters,
            batch_size,
            &mut OsCsRng,
        );

        let language_public_parameters = vector_language_public_parameters();

        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, VectorLang>(
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
            .1
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
            &mut OsCsRng,
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
        test_helpers,
        vector_commitment_of_discrete_log::test_helpers::{
            language_public_parameters, vector_language_public_parameters, Lang, VectorLang,
        },
    };

    use super::*;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let language_public_parameters = language_public_parameters();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            Some("pedersen of 2".to_string()),
            false,
            None,
        );

        test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            Some("pedersen of 2".to_string()),
            false,
            None,
        );

        let vector_language_public_parameters = vector_language_public_parameters();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, VectorLang>(
            &vector_language_public_parameters,
            Some("multi-pedersen of 2".to_string()),
            false,
            None,
        );

        test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, VectorLang>(
            &vector_language_public_parameters,
            Some("multi-pedersen of 2".to_string()),
            false,
            None,
        );
    }
}
