// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::Uint;

use group::{bounded_natural_numbers_group, GroupElement, PrimeGroupElement};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use maurer::scaling_of_discrete_log::*;
use maurer::SOUND_PROOFS_REPETITIONS;

use crate::{language::DecomposableWitness, EnhanceableLanguage};

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        SOUND_PROOFS_REPETITIONS,
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        tiresias::RandomnessSpaceGroupElement,
    >
    for Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        GroupElement,
        tiresias::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR],
        randomness: tiresias::RandomnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<Self::WitnessSpaceGroupElement> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            tiresias::RandomnessSpaceGroupElement,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        let discrete_log = <tiresias::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            &decomposed_witness,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        let discrete_log = bounded_natural_numbers_group::GroupElement::new(
            discrete_log.value(),
            language_public_parameters.message_group_public_parameters(),
        )?;

        Ok((discrete_log, randomness).into())
    }

    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR],
        tiresias::RandomnessSpaceGroupElement,
    )> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            tiresias::RandomnessSpaceGroupElement,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        let discrete_log = tiresias::PlaintextSpaceGroupElement::new(
            witness.discrete_log().value(),
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;

        Ok((
            discrete_log.decompose(range_claim_bits)?,
            *witness.randomness(),
        ))
    }
}

pub type Proof<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    ProtocolContext,
> = crate::Proof<
    SOUND_PROOFS_REPETITIONS,
    NUM_RANGE_CLAIMS,
    MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

#[cfg(test)]
pub(crate) mod tests {
    use core::iter;
    use crypto_bigint::{Random, U256, U64};
    use rand_core::OsRng;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use class_groups::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use class_groups::{
        Secp256k1DecryptionKey, Secp256k1EncryptionKey, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };
    use group::{
        secp256k1, ComputationalSecuritySizedNumber, PartyID, Samplable,
        StatisticalSecuritySizedNumber,
    };
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
    use maurer::language;
    use mpc::Weight;
    use proof::range::bulletproofs::RANGE_CLAIM_BITS;
    use tiresias::test_helpers::N;

    use crate::{
        aggregation::tests::setup_aggregation,
        language::tests::{generate_scalar_plaintext, RANGE_CLAIMS_PER_SCALAR},
    };

    use super::*;

    pub type Lang = Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { U256::LIMBS },
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        secp256k1::GroupElement,
        tiresias::EncryptionKey,
    >;

    const MESSAGE_LIMBS: usize = {
        U256::LIMBS
            + ComputationalSecuritySizedNumber::LIMBS
            + StatisticalSecuritySizedNumber::LIMBS
            + ComputationalSecuritySizedNumber::LIMBS
            + U64::LIMBS
            + U64::LIMBS
    };

    pub type ClassGroupsLang = Language<
        { U256::LIMBS },
        { U256::LIMBS },
        MESSAGE_LIMBS,
        secp256k1::GroupElement,
        Secp256k1EncryptionKey,
    >;

    pub(crate) fn public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
    {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            tiresias::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let plaintext = tiresias::PlaintextSpaceGroupElement::new(
            (&U256::random(&mut OsRng)).into(),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext = paillier_encryption_key
            .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
            .unwrap()
            .1
            .value();

        let upper_bound = Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(
            u64::try_from(RANGE_CLAIMS_PER_SCALAR * RANGE_CLAIM_BITS).unwrap(),
        );

        PublicParameters::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
        >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, tiresias::EncryptionKey>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            paillier_public_parameters,
            ciphertext,
            upper_bound,
        )
        .unwrap()
    }

    pub(crate) fn class_groups_language_public_parameters(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, ClassGroupsLang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (encryption_scheme_public_parameters, _) =
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

        let encryption_key = <Secp256k1EncryptionKey as AdditivelyHomomorphicEncryptionKey<
            { secp256k1::SCALAR_LIMBS },
        >>::new(&encryption_scheme_public_parameters)
        .unwrap();
        let message_to_encrypt =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();
        let (_, ciphertext) = encryption_key
            .encrypt(
                &message_to_encrypt,
                &encryption_scheme_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        let upper_bound = secp256k1::ORDER;

        PublicParameters::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            MESSAGE_LIMBS,
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, Secp256k1EncryptionKey>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            encryption_scheme_public_parameters,
            ciphertext.into(),
            Uint::from(&upper_bound),
        )
        .unwrap()
    }

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let discrete_log = generate_scalar_plaintext();
            let discrete_log = bounded_natural_numbers_group::GroupElement::new(
                discrete_log.value(),
                language_public_parameters.message_group_public_parameters(),
            )
            .unwrap();

            let randomness = tiresias::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (discrete_log, randomness).into()
        })
        .take(batch_size)
        .collect()
    }

    fn generate_witnesses_class_groups(
        language_public_parameters: &language::PublicParameters<
            SOUND_PROOFS_REPETITIONS,
            ClassGroupsLang,
        >,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>> {
        iter::repeat_with(|| {
            let discrete_log = secp256k1::Scalar::sample(
                &language_public_parameters.scalar_group_public_parameters,
                &mut OsRng,
            )
            .unwrap();

            let discrete_log = bounded_natural_numbers_group::GroupElement::new(
                Uint::<MESSAGE_LIMBS>::from(&U256::from(&discrete_log.value())),
                language_public_parameters.message_group_public_parameters(),
            )
            .unwrap();

            let randomness = class_groups::RandomnessSpaceGroupElement::<
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (discrete_log, randomness).into()
        })
        .take(batch_size)
        .collect()
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::proof::tests::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn valid_proof_verifies_class_groups(#[case] batch_size: usize) {
        let language_public_parameters = class_groups_language_public_parameters();

        let witnesses = generate_witnesses_class_groups(&language_public_parameters, batch_size);

        let (proof, statements) =
            maurer::Proof::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang, PhantomData<()>>::prove(
                &PhantomData,
                &language_public_parameters,
                witnesses,
                &mut OsRng,
            )
            .unwrap();

        assert!(
            proof
                .verify(&PhantomData, &language_public_parameters, statements)
                .is_ok(),
            "valid proofs should verify"
        );
    }

    #[rstest]
    #[case(1, 1)]
    #[case(2, 1)]
    #[case(2, 2)]
    #[case(3, 1)]
    fn valid_proofs_verifies_batch(#[case] number_of_proofs: usize, #[case] batch_size: usize) {
        let language_public_parameters = class_groups_language_public_parameters();

        let (proofs, statements): (Vec<_>, Vec<_>) = iter::repeat_with(|| {
            let witnesses =
                generate_witnesses_class_groups(&language_public_parameters, batch_size);

            maurer::Proof::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang, PhantomData<()>>::prove(
                &PhantomData,
                &language_public_parameters,
                witnesses,
                &mut OsRng,
            )
            .unwrap()
        })
        .take(number_of_proofs)
        .unzip();

        maurer::test_helpers::batch_verifies(
            proofs,
            statements,
            &language_public_parameters,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_out_of_range_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        )
    }
    #[rstest]
    #[case(1)]
    #[case(2)]
    fn proof_with_valid_range_proof_over_wrong_witness_fails(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_valid_range_proof_over_wrong_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        )
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::aggregation::tests::aggregates::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
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
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(party_to_weight.len())
                .collect();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::proof::tests::statement_aggregates_asynchronously::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
            threshold,
            party_to_weight,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 3)]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: MismatchingRangeProofMaurerCommitments([2])"
    )]
    fn party_mismatching_maurer_range_proof_statements_aborts_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::aggregation::tests::party_mismatching_maurer_range_proof_statements_aborts_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn wrong_decommitment_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::wrong_decommitment_aborts_session_identifiably(
            commitment_round_parties,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn failed_proof_share_verification_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters.clone(),
            witnesses,
        );

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let wrong_commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::failed_proof_share_verification_aborts_session_identifiably(
            commitment_round_parties, wrong_commitment_round_parties,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn unresponsive_parties_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = language_public_parameters
            .encryption_scheme_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::unresponsive_parties_aborts_session_identifiably(
            commitment_round_parties,
        );
    }
}
