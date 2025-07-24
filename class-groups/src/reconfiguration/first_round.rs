// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::manual_filter)]

use std::array;
use std::collections::{HashMap, HashSet};

use crypto_bigint::{ConstChoice, Encoding, Int, Uint};

use commitment::CommitmentSizedNumber;
use group::helpers::{DeduplicateAndSort, FlatMapResults};
use group::{
    bounded_integers_group, bounded_natural_numbers_group, CsRng, GroupElement, PartyID,
    PrimeGroupElement, Samplable,
};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::{AsynchronousRoundResult, HandleInvalidMessages};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::prove_encryption_of_discrete_log_per_crt_prime;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
    NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{
    BaseProtocolContext, DealtSecretShare, DealtSecretShareMessage,
};
use crate::reconfiguration::party::RoundResult;
use crate::reconfiguration::{
    Message, Party, PublicInput, RANDOMIZER_LIMBS, RANDOMIZER_WITNESS_LIMBS,
};
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use crate::{
    equivalence_class, publicly_verifiable_secret_sharing, CiphertextSpaceGroupElement,
    CompactIbqf, EquivalenceClass, Error, Result,
};
use crate::{SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS};

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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    GroupElement::Scalar: Default,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_first_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        randomizer_contribution_to_threshold_encryption_key_base_protocol_context: BaseProtocolContext,
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        setup_parameters: &SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
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
        randomizer_contribution_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<
        RoundResult<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    > {
        let public_parameters =
            group::bounded_natural_numbers_group::PublicParameters::<RANDOMIZER_LIMBS>::new(
                randomizer_contribution_bits,
                randomizer_contribution_bits + 1,
            )
            .map_err(|_| Error::InvalidPublicParameters)?;

        // Sample a randomizer contribution $r_{i}$ which will be used to statistically mask the secret key.
        let randomizer_contribution =
            bounded_natural_numbers_group::GroupElement::sample(&public_parameters, rng)?.value();
        let randomizer_contribution =
            Int::new_from_abs_sign(randomizer_contribution, ConstChoice::FALSE).unwrap();

        let current_parties_with_valid_encryption_keys: HashSet<_> = public_input
            .decryption_key_share_public_parameters
            .public_verification_keys
            .keys()
            .copied()
            .collect();
        let upcoming_parties_with_valid_encryption_keys: HashSet<_> =
            current_parties_with_valid_encryption_keys
                .iter()
                .flat_map(|current_tangible_party_id| {
                    if let Some(upcoming_tangible_party_id) = public_input
                        .current_tangible_party_id_to_upcoming
                        .get(current_tangible_party_id)
                        .unwrap_or(&None)
                    {
                        // If the current tangible party is also an upcoming party, and its using the same encryption key as in the previous DKG/Reconfiguration protocol,
                        // and it was dealt shares (we know because it has a public verification key), then we know this key was verified. Otherwise, it must be verified.
                        // Note that we support the case of a party replacing its encryption key here, it just requires verification.
                        if public_input
                            .current_encryption_key_values_and_proofs_per_crt_prime
                            .get(current_tangible_party_id)
                            == public_input
                                .upcoming_encryption_key_values_and_proofs_per_crt_prime
                                .get(upcoming_tangible_party_id)
                        {
                            Some(upcoming_tangible_party_id)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .copied()
                .collect();

        // Each party uses PVSS to share $r_{i}$ to the upcoming parties.
        let (
            malicious_dealers_to_upcoming,
            deal_randomizer_contribution_to_upcoming_parties_message,
        ) = randomizer_contribution_to_upcoming_pvss_party
            .deal_and_encrypt_shares_to_valid_encryption_key_holders(
                None,
                randomizer_contribution,
                upcoming_parties_with_valid_encryption_keys,
                true,
                rng,
            )?;

        // Prepare to encrypt & prove the randomizer contribution under the threshold encryption key.
        let public_parameters = bounded_integers_group::PublicParameters::<
            RANDOMIZER_WITNESS_LIMBS,
        >::new_with_randomizer_upper_bound(randomizer_contribution_bits)
            .map_err(|_| Error::InvalidPublicParameters)?;

        let randomizer_contribution = bounded_integers_group::GroupElement::new(
            Int::from(&randomizer_contribution),
            &public_parameters,
        )?;

        let threshold_encryption_key_per_crt_prime: [_; NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES] =
            public_input
                .dkg_output
                .threshold_encryption_scheme_public_parameters_per_crt_prime(
                    &public_input.setup_parameters_per_crt_prime,
                )?
                .map(|public_parameters| public_parameters.encryption_key);

        let threshold_encryption_of_randomizer_contribution_and_proof =
            prove_encryption_of_discrete_log_per_crt_prime::<
                NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                RANDOMIZER_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >(
                tangible_party_id,
                None,
                None,
                None,
                session_id,
                randomizer_contribution,
                setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
                setup_parameters.h,
                &threshold_encryption_key_per_crt_prime,
                &public_input.setup_parameters_per_crt_prime,
                randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                randomizer_contribution_bits,
                rng,
            )?;

        let malicious_parties = malicious_dealers_to_upcoming.deduplicate_and_sort();

        Ok(AsynchronousRoundResult::Advance {
            malicious_parties,
            message: Message::DealRandomizer {
                deal_randomizer_contribution_to_upcoming_parties_message,
                threshold_encryption_of_randomizer_contribution_and_proof: DealtSecretShareMessage(
                    threshold_encryption_of_randomizer_contribution_and_proof,
                ),
            },
        })
    }

    /// Make sure everyone sent the first round message.
    /// Check that the coefficient at `0`, i.e. the free coefficient (which is the `first`)
    /// had a discrete log which equals to the message under the threshold keys $\textsf{pk_{Q'_{m'}}}$
    #[allow(clippy::type_complexity)]
    pub(crate) fn handle_first_round_messages(
        tangible_party_id: PartyID,
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
        reconstruct_all: bool,
    ) -> Result<(
        Vec<PartyID>,
        HashSet<PartyID>,
        HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<Option<PartyID>, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShare<
                            NUM_SECRET_SHARE_PRIMES,
                            SECRET_KEY_SHARE_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
        HashMap<
            PartyID,
            DealtSecretShare<
                NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                RANDOMIZER_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    )> {
        // First make sure everyone sent the first round message.
        let (parties_sending_invalid_deal_secret_messages, deal_randomizer_messages) =
            deal_randomizer_messages
                .into_iter()
                .map(|(dealer_party_id, message)| {
                    let res = match message {
                        Message::DealRandomizer {
                            deal_randomizer_contribution_to_upcoming_parties_message,
                            threshold_encryption_of_randomizer_contribution_and_proof,
                        } => Ok((
                            deal_randomizer_contribution_to_upcoming_parties_message,
                            threshold_encryption_of_randomizer_contribution_and_proof,
                        )),
                        _ => Err(Error::InvalidParameters),
                    };

                    (dealer_party_id, res)
                })
                .handle_invalid_messages_async();

        let (
            deal_randomizer_contribution_to_upcoming_parties_messages,
            threshold_encryptions_of_randomizer_contributions_and_proofs,
        ): (HashMap<_, _>, HashMap<_, _>) = deal_randomizer_messages
            .into_iter()
            .map(
                |(
                    dealer_tangible_party_id,
                    (
                        deal_randomizer_contribution_to_upcoming_parties_message,
                        threshold_encryption_of_randomizer_contribution_and_proof,
                    ),
                )| {
                    (
                        (
                            dealer_tangible_party_id,
                            HashMap::from([(
                                None,
                                deal_randomizer_contribution_to_upcoming_parties_message,
                            )]),
                        ),
                        (
                            dealer_tangible_party_id,
                            threshold_encryption_of_randomizer_contribution_and_proof,
                        ),
                    )
                },
            )
            .unzip();

        let (
            upcoming_first_round_malicious_parties,
            upcoming_parties_that_were_dealt_randomizer_shares,
            coefficients_contribution_commitments_to_upcoming,
            encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming,
        ) = randomizer_contribution_to_upcoming_pvss_party.handle_deal_secret_messages(
            deal_randomizer_contribution_to_upcoming_parties_messages,
        )?;

        let upcoming_virtual_parties_that_were_dealt_randomizer_shares = public_input
            .upcoming_access_structure
            .virtual_subset(upcoming_parties_that_were_dealt_randomizer_shares.clone())?;

        let commitments_to_randomizer_contribution =
            coefficients_contribution_commitments_to_upcoming
                .iter()
                .map(|(&dealer_tangible_party_id, commitments)| {
                    let commitments = commitments
                        .iter()
                        .map(|(&dealer_virtual_party_id, commitments)| {
                            // Safe to `unwrap` since we checked the size of commitments is the threshold.
                            // We adapt to the structure the verification function expects,
                            // i.e. dealer tangible party id -> dealer virtual party id -> participating virtual party id -> commitment.
                            // In practice both the dealer and participating virtual parties would be `None`.
                            (
                                dealer_virtual_party_id,
                                HashMap::from([(None, commitments.first().copied().unwrap())]),
                            )
                        })
                        .collect();

                    (dealer_tangible_party_id, commitments)
                })
                .collect();

        let virtual_subset = if reconstruct_all {
            upcoming_virtual_parties_that_were_dealt_randomizer_shares
        } else if let Some(upcoming_tangible_party_id) = public_input
            .current_tangible_party_id_to_upcoming
            .get(&tangible_party_id)
            .unwrap_or(&None)
        {
            public_input
                .upcoming_access_structure
                .virtual_subset(HashSet::from([*upcoming_tangible_party_id]))?
        } else {
            HashSet::new()
        };

        let reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming =
            randomizer_contribution_to_upcoming_pvss_party.reconstruct_commitment_to_sharing(
                coefficients_contribution_commitments_to_upcoming.clone(),
                virtual_subset,
            );

        let (
            parties_sending_invalid_encryptions,
            threshold_encryption_of_randomizer_contribution_and_proof,
        ) = threshold_encryptions_of_randomizer_contributions_and_proofs
            .into_iter()
            .map(|(dealer_tangible_party_id, deal_secret_message)| {
                // Safe to dereference, same sized arrays.
                let encryptions_of_shares_and_proofs = array::from_fn(|i| {
                    let (proof, encryption_of_share) = deal_secret_message.0[i].clone();

                    CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                        encryption_of_share,
                        public_input.setup_parameters_per_crt_prime[i]
                            .ciphertext_space_public_parameters(),
                    )
                    .map(|ct| (proof, ct))
                })
                .flat_map_results();

                (dealer_tangible_party_id, encryptions_of_shares_and_proofs)
            })
            .handle_invalid_messages_async();

        let first_round_malicious_parties: Vec<_> = parties_sending_invalid_deal_secret_messages
            .into_iter()
            .chain(upcoming_first_round_malicious_parties)
            .chain(parties_sending_invalid_encryptions)
            .deduplicate_and_sort();

        Ok((
            first_round_malicious_parties,
            upcoming_parties_that_were_dealt_randomizer_shares,
            commitments_to_randomizer_contribution,
            reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming,
            encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming,
            threshold_encryption_of_randomizer_contribution_and_proof,
        ))
    }
}
