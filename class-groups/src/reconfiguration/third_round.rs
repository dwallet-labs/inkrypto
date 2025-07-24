// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};
use itertools::Itertools;

use commitment::CommitmentSizedNumber;
use group::helpers::{DeduplicateAndSort, FlatMapResults, TryCollectHashMap};
use group::{bounded_integers_group, CsRng, GroupElement, PartyID, PrimeGroupElement};
use homomorphic_encryption::AdditivelyHomomorphicDecryptionKeyShare;
use mpc::{AsynchronousRoundResult, HandleInvalidMessages, WeightedThresholdAccessStructure};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::{
    prove_equality_of_discrete_log, verify_encryptions_of_secrets_per_crt_prime,
    ProveEqualityOfDiscreteLog, ProveEqualityOfDiscreteLogMessage,
};
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeDecryptionKeyShare,
    SecretKeyShareCRTPrimeDecryptionKeySharePublicParameters,
    SecretKeyShareCRTPrimeDecryptionShare, SecretKeyShareCRTPrimeGroupElement,
    SecretKeyShareCRTPrimePartialDecryptionProof, NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{BaseProtocolContext, DealtSecretShare};
use crate::reconfiguration::party::RoundResult;
use crate::reconfiguration::RANDOMIZER_WITNESS_LIMBS;
use crate::reconfiguration::{Message, Party, PublicInput};
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use crate::{
    equivalence_class, publicly_verifiable_secret_sharing, CiphertextSpaceGroupElement,
    CompactIbqf, EquivalenceClass, Error, Result, SecretKeyShareSizedInteger,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    Party<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: DeriveFromPlaintextPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    GroupElement::Scalar: Default,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_third_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        randomizer_contribution_to_threshold_encryption_key_base_protocol_context: BaseProtocolContext,
        current_access_structure: &WeightedThresholdAccessStructure,
        knowledge_of_discrete_log_base_protocol_context: BaseProtocolContext,
        setup_parameters: &SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        deal_randomizer_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        verified_dealers_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        current_decryption_key_share_bits: u32,
        randomizer_contribution_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<
        RoundResult<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    > {
        // Round 3
        let (
            first_round_malicious_parties,
            _,
            commitments_to_randomizer_contribution,
            reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming,
            encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming,
            threshold_encryption_of_randomizer_contribution_and_proof,
        ) = Self::handle_first_round_messages(
            tangible_party_id,
            public_input,
            deal_randomizer_messages.clone(),
            randomizer_contribution_to_upcoming_pvss_party,
            true,
        )?;

        let (second_round_malicious_parties, verified_dealers_to_upcoming) =
            Self::handle_second_round_messages(public_input, verified_dealers_messages)?;

        let malicious_parties: Vec<_> = first_round_malicious_parties
            .into_iter()
            .chain(second_round_malicious_parties)
            .deduplicate_and_sort();

        let malicious_dealers_to_upcoming = randomizer_contribution_to_upcoming_pvss_party
            .verify_encryptions_of_secret_shares(
                encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming.clone(),
                verified_dealers_to_upcoming,
                malicious_parties.clone(),
                reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming.clone(),
                rng,
            )?
            .deduplicate_and_sort();

        let commitments_to_randomizer_contribution = commitments_to_randomizer_contribution
            .into_iter()
            .filter(|(dealer_tangible_party_id, _)| {
                !malicious_dealers_to_upcoming.contains(dealer_tangible_party_id)
            })
            .collect();

        // Adapt the encryptions and proofs to the structure expected by the verification function
        let threshold_encryptions_of_randomizer_and_proofs_for_verification =
            threshold_encryption_of_randomizer_contribution_and_proof
                .clone()
                .into_iter()
                .filter(|(dealer_tangible_party_id, _)| {
                    !malicious_dealers_to_upcoming.contains(dealer_tangible_party_id)
                })
                .map(|(dealer_tangible_party_id, dealt_secret_share_message)| {
                    (
                        dealer_tangible_party_id,
                        HashMap::from([(
                            None,
                            HashMap::from([(None, dealt_secret_share_message)]),
                        )]),
                    )
                })
                .collect();

        let threshold_encryption_scheme_public_parameters_per_crt_prime: [_;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES] = public_input
            .dkg_output
            .threshold_encryption_scheme_public_parameters_per_crt_prime(
                &public_input.setup_parameters_per_crt_prime,
            )?;

        let parties_sending_invalid_threshold_encryption_of_randomizer_contribution_proofs =
            verify_encryptions_of_secrets_per_crt_prime::<
                NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                RANDOMIZER_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >(
                None,
                session_id,
                threshold_encryption_scheme_public_parameters_per_crt_prime.clone(),
                commitments_to_randomizer_contribution,
                threshold_encryptions_of_randomizer_and_proofs_for_verification,
                setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
                setup_parameters.h,
                randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                randomizer_contribution_bits,
                rng,
            )?;

        let malicious_parties = malicious_dealers_to_upcoming
            .clone()
            .into_iter()
            .chain(parties_sending_invalid_threshold_encryption_of_randomizer_contribution_proofs)
            .deduplicate_and_sort();

        // Note: `sum_threshold_encryptions_of_randomizer_contributions()` also checks that the honest subset is authorized.
        let threshold_encryption_of_randomizer =
            Self::sum_threshold_encryptions_of_randomizer_contributions(
                current_access_structure,
                &malicious_parties,
                threshold_encryption_of_randomizer_contribution_and_proof,
            )?;

        let threshold_encryption_of_decryption_key_per_crt_prime = public_input
            .dkg_output
            .threshold_encryption_of_decryption_key_per_crt_prime(
                &public_input.setup_parameters_per_crt_prime,
            )?;

        let masked_decryption_key_decryption_shares_and_proofs = decryption_key_shares
            .clone()
            .into_iter()
            .map(|(dealer_virtual_party_id, decryption_key_share)| {
                array::from_fn(|i| {
                    let decryption_key_share_public_parameters =
                        SecretKeyShareCRTPrimeDecryptionKeySharePublicParameters::new::<
                            SecretKeyShareCRTPrimeGroupElement,
                        >(
                            current_access_structure.threshold,
                            current_access_structure.number_of_virtual_parties(),
                            public_input.setup_parameters_per_crt_prime[i].h.value(),
                            // During proof generation, we also generate the verification keys in the same round. We do so in order to have verification keys which live in the same group as the threshold encryption scheme. While possible to use a verification key from a different group this would demand changes to the threshold decryption functions which we want to avoid.
                            //This works since these keys are not required for generating the proof, only for verifying it. However we must provide a placeholder value to satisfy the function's parameters.
                            // The actual verification of the proof will use the newly generated verification keys.
                            HashMap::new(),
                            threshold_encryption_scheme_public_parameters_per_crt_prime[i].clone(),
                        )?;

                    let decryption_key_share = SecretKeyShareCRTPrimeDecryptionKeyShare::new(
                        dealer_virtual_party_id,
                        decryption_key_share,
                        &decryption_key_share_public_parameters,
                        rng,
                    )?;

                    // The parties add the encryptions of the mask to the encryptions of the key per CRT prime.
                    let threshold_encryption_of_masked_decryption_key =
                        threshold_encryption_of_randomizer[i]
                            + threshold_encryption_of_decryption_key_per_crt_prime[i];

                    let (decryption_shares, proof) =
                        Option::from(decryption_key_share.generate_decryption_shares(
                            vec![threshold_encryption_of_masked_decryption_key],
                            &decryption_key_share_public_parameters,
                            rng,
                        ))
                        .ok_or(Error::InternalError)?;

                    match &decryption_shares[..] {
                        [decryption_share] => Ok((*decryption_share, proof)),
                        _ => Err(Error::InternalError),
                    }
                })
                .flat_map_results()
                .map(|decryption_shares_and_proofs| {
                    (dealer_virtual_party_id, decryption_shares_and_proofs)
                })
            })
            .try_collect_hash_map()?;

        // Generating public verification keys for threshold encryptions:
        //
        // In order for us to maintain the structure of the code we do not use $h_{q}$ as a verification key to the threshold encryptions defined by the different CRT primes.
        // Instead, each virtual current party compute $\textsf{vk}_{Q'_{m'}}^{i_{T}}=h_{Q'_{m'}}^{[s]_{i_{T}}}$ and prove equality of discrete log between this new verification per CRT prime to the original verification key.
        // Then they use this verification key to prove correct decryption as typicaly happens in threshold decryption.
        let discrete_log_public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound(
                current_decryption_key_share_bits,
            )?;

        let prove_public_verification_keys_messages = decryption_key_shares
            .into_iter()
            .sorted_by(|(virtual_party_id, _), (other_virtual_party_id, _)| {
                virtual_party_id.cmp(other_virtual_party_id)
            })
            .map(|(dealer_virtual_party_id, decryption_key_share)| {
                let decryption_key_share = bounded_integers_group::GroupElement::new(
                    Int::from(&decryption_key_share),
                    &discrete_log_public_parameters,
                )?;

                let share_crt_public_verification_key_message = prove_equality_of_discrete_log::<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    SECRET_KEY_SHARE_WITNESS_LIMBS,
                    GroupElement,
                >(
                    tangible_party_id,
                    Some(dealer_virtual_party_id),
                    session_id,
                    knowledge_of_discrete_log_base_protocol_context.clone(),
                    discrete_log_public_parameters.clone(),
                    decryption_key_share,
                    &public_input.setup_parameters_per_crt_prime,
                    setup_parameters,
                    current_decryption_key_share_bits,
                    rng,
                )?;

                Ok::<_, Error>((
                    dealer_virtual_party_id,
                    ProveEqualityOfDiscreteLogMessage(share_crt_public_verification_key_message),
                ))
            })
            .try_collect_hash_map()?;

        Ok(AsynchronousRoundResult::Advance {
            malicious_parties,
            message: Message::ThresholdDecryptShares {
                masked_decryption_key_decryption_shares_and_proofs,
                prove_public_verification_keys_messages,
            },
        })
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn handle_third_round_messages(
        current_access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        threshold_decrypt_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        HashMap<
            PartyID,
            [(
                SecretKeyShareCRTPrimeDecryptionShare,
                SecretKeyShareCRTPrimePartialDecryptionProof,
            ); NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
        >,
        HashMap<
            PartyID,
            HashMap<
                PartyID,
                ProveEqualityOfDiscreteLog<
                    SECRET_KEY_SHARE_WITNESS_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        >,
    )> {
        // First make sure everyone sent the third round message.
        let (parties_sending_invalid_third_round_messages, threshold_decrypt_messages) =
            threshold_decrypt_messages
                .into_iter()
                .map(|(dealer_tangible_party_id, message)| {
                    let res = match message {
                        Message::ThresholdDecryptShares {
                            masked_decryption_key_decryption_shares_and_proofs,
                            prove_public_verification_keys_messages,
                        } => {
                            if let Ok(virtual_subset) = current_access_structure
                                .virtual_subset(HashSet::from([dealer_tangible_party_id]))
                            {
                                if masked_decryption_key_decryption_shares_and_proofs
                                    .keys()
                                    .copied()
                                    .collect::<HashSet<PartyID>>()
                                    == virtual_subset
                                    && prove_public_verification_keys_messages
                                        .keys()
                                        .copied()
                                        .collect::<HashSet<PartyID>>()
                                        == virtual_subset
                                {
                                    Ok((
                                        masked_decryption_key_decryption_shares_and_proofs,
                                        prove_public_verification_keys_messages,
                                    ))
                                } else {
                                    Err(Error::InvalidMessage)
                                }
                            } else {
                                Err(Error::InvalidMessage)
                            }
                        }
                        _ => Err(Error::InvalidMessage),
                    };

                    (dealer_tangible_party_id, res)
                })
                .handle_invalid_messages_async();

        let (
            masked_decryption_key_decryption_shares_and_proofs,
            prove_public_verification_keys_messages,
        ): (HashMap<_, _>, HashMap<_, _>) = threshold_decrypt_messages
            .into_iter()
            .map(
                |(
                    dealer_tangible_party_id,
                    (
                        masked_decryption_key_decryption_shares_and_proofs,
                        prove_public_verification_keys_messages,
                    ),
                )| {
                    (
                        (
                            dealer_tangible_party_id,
                            masked_decryption_key_decryption_shares_and_proofs,
                        ),
                        (
                            dealer_tangible_party_id,
                            prove_public_verification_keys_messages,
                        ),
                    )
                },
            )
            .unzip();

        let (parties_sending_invalid_prove_public_verification_keys_messages, threshold_public_verification_keys_and_proofs) = prove_public_verification_keys_messages.into_iter()
            .map(
                |(dealer_tangible_party_id, prove_public_verification_keys_messages)| {
                    let public_verification_keys_and_proofs = prove_public_verification_keys_messages.into_iter()
                        .map(
                            |(dealer_virtual_party_id, prove_public_verification_keys_messages)| {
                                array::from_fn(|i| {
                                    let (proof, public_verification_key) =
                                        prove_public_verification_keys_messages.0[i].clone();

                                    EquivalenceClass::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                                        public_verification_key,
                                        public_input.setup_parameters_per_crt_prime[i].equivalence_class_public_parameters(),
                                    )
                                        .map(|encryption_key_contribution| (proof, encryption_key_contribution))
                                })
                                    .flat_map_results().map(|public_verification_key_and_proof_per_crt_prime| (dealer_virtual_party_id, public_verification_key_and_proof_per_crt_prime))
                            }).try_collect_hash_map();

                    (dealer_tangible_party_id, public_verification_keys_and_proofs)
                },
            )
            .handle_invalid_messages_async();

        let third_round_malicious_parties: Vec<_> = parties_sending_invalid_third_round_messages
            .into_iter()
            .chain(parties_sending_invalid_prove_public_verification_keys_messages)
            .deduplicate_and_sort();

        Ok((
            third_round_malicious_parties,
            masked_decryption_key_decryption_shares_and_proofs
                .into_values()
                .flatten()
                .collect(),
            threshold_public_verification_keys_and_proofs,
        ))
    }

    pub(crate) fn sum_threshold_encryptions_of_randomizer_contributions(
        current_access_structure: &WeightedThresholdAccessStructure,
        malicious_randomizer_dealers: &[PartyID],
        threshold_encryptions_of_randomizer_and_proofs: HashMap<
            PartyID,
            DealtSecretShare<
                NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                RANDOMIZER_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    ) -> Result<
        [CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
    > {
        let threshold_encryptions_of_randomizer_and_proofs: HashMap<_, _> =
            threshold_encryptions_of_randomizer_and_proofs
                .into_iter()
                .filter(|(dealer_tangible_party_id, _)| {
                    !malicious_randomizer_dealers.contains(dealer_tangible_party_id)
                })
                .collect();

        let honest_dealers: HashSet<_> = threshold_encryptions_of_randomizer_and_proofs
            .keys()
            .copied()
            .collect();

        current_access_structure.is_authorized_subset(&honest_dealers)?;

        array::from_fn(|i| {
            threshold_encryptions_of_randomizer_and_proofs
                .values()
                .map(|encryptions_and_proof| {
                    let (_, ct) = encryptions_and_proof[i].clone();

                    ct
                })
                .reduce(|a, b| a + b)
                .ok_or(Error::InternalError)
        })
        .flat_map_results()
    }
}
