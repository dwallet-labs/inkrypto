// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};

use commitment::CommitmentSizedNumber;
use group::helpers::{DeduplicateAndSort, FlatMapResults, TryCollectHashMap};
use group::{bounded_integers_group, CsRng, GroupElement as _, PartyID, PrimeGroupElement};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::secret_sharing::shamir::over_the_integers::secret_key_share_size_upper_bound;
use mpc::{AsynchronousRoundResult, HandleInvalidMessages, WeightedThresholdAccessStructure};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::party::RoundResult;
pub use crate::dkg::public_output::PublicOutput;
use crate::dkg::{
    prove_encryption_of_discrete_log_per_crt_prime, verify_equality_of_discrete_log_proofs,
    Message, Party, PublicInput,
};
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeSetupParameters, CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES, NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
    NUM_SECRET_SHARE_PRIMES, SECRET_SHARE_CRT_COEFFICIENTS, SECRET_SHARE_CRT_PRIMES_PRODUCT,
};
use crate::publicly_verifiable_secret_sharing::{
    BaseProtocolContext, DealtSecretShare, DealtSecretShareMessage,
};
use crate::setup::DeriveFromPlaintextPublicParameters;
use crate::setup::SetupParameters;
use crate::{
    equivalence_class, publicly_verifiable_secret_sharing, CiphertextSpaceGroupElement,
    CompactIbqf, EquivalenceClass, Error, Result, SECRET_KEY_SHARE_LIMBS,
    SECRET_KEY_SHARE_WITNESS_LIMBS,
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
    /// The output of this round is an agreed upon subset of honest dealears along with the private shares gained by decrypting and summing over the agreed subset.
    /// In addition, the parties agree on the therhold keys $\textsf{pk}_{Q'_{m'}}$ for $m'\in[1,M']$ along with the Elliptic Curve public key $\textsf{pk_{q}}$
    /// This round essentially finishes the implementation of $\mathcal{F}_{\textaf{ACS}}$.
    /// Namely, it is responsible for the local derivation of the secret key share $[\textsf{sk}]_i$, after reaching agreement on the subset $S$ of honestly participating parties in the previous rounds.
    /// $[\textsf{sk}]_{i}=\sum_{j\in S}[s_{j}]_{i}$
    #[allow(clippy::too_many_arguments)]
    pub(in crate::dkg) fn advance_third_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        knowledge_of_discrete_log_base_protocol_context: BaseProtocolContext,
        encryption_of_decryption_key_base_protocol_context: BaseProtocolContext,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_decryption_key_contribution_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        verified_dealers_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
        decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<
        RoundResult<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    > {
        let (
            first_round_malicious_parties,
            parties_that_were_dealt_shares,
            coefficients_contribution_commitments,
            reconstructed_commitments_to_sharing,
            encryptions_of_shares_and_proofs,
            threshold_encryption_key_shares_and_proofs,
        ) = Self::handle_first_round_messages(
            tangible_party_id,
            access_structure,
            &public_input.setup_parameters_per_crt_prime,
            pvss_party,
            deal_decryption_key_contribution_messages,
            true,
        )?;

        let (second_round_malicious_parties, verified_dealers) =
            Self::handle_second_round_messages(verified_dealers_messages)?;

        let malicious_parties: Vec<_> = first_round_malicious_parties
            .into_iter()
            .chain(second_round_malicious_parties)
            .deduplicate_and_sort();

        let malicious_parties = pvss_party.verify_encryptions_of_secret_shares(
            encryptions_of_shares_and_proofs.clone(),
            verified_dealers,
            malicious_parties,
            reconstructed_commitments_to_sharing.clone(),
            rng,
        )?;

        // Reach consensus on the encryption key used during sign $(h_{q},\textsf{pk}_{q})$
        // and the threshold encryption keys used for re-configuration $(h_{Q'_{m'},\textsf{pk}_{Q'_{m'},)$ for $m'\in [1,M']$.
        let encryption_key_contributions: HashMap<_, _> = coefficients_contribution_commitments
            .clone()
            .into_iter()
            .filter(|(dealer_party_id, _)| !malicious_parties.contains(dealer_party_id))
            .map(
                |(dealer_party_id, deal_decryption_key_contribution_message)| {
                    // Safe to unwrap by construction.
                    let coefficients_contribution_commitments =
                        deal_decryption_key_contribution_message.get(&None).unwrap();

                    // Safe to unwrap - we validated this vector is of size `t`, which is non-zero.
                    (
                        dealer_party_id,
                        HashMap::from([(
                            None,
                            *coefficients_contribution_commitments.first().unwrap(),
                        )]),
                    )
                },
            )
            .collect();

        let threshold_encryption_key_shares_and_proofs_for_verification =
            threshold_encryption_key_shares_and_proofs
                .clone()
                .into_iter()
                .filter(|(dealer_party_id, _)| !malicious_parties.contains(dealer_party_id))
                .map(|(dealer_party_id, prove_equality_of_discrete_log)| {
                    (
                        dealer_party_id,
                        HashMap::from([(None, prove_equality_of_discrete_log)]),
                    )
                })
                .collect();

        let discrete_log_public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound(
                public_input.setup_parameters.decryption_key_bits(),
            )?;

        let parties_sending_invalid_proofs = verify_equality_of_discrete_log_proofs::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >(
            session_id,
            access_structure,
            knowledge_of_discrete_log_base_protocol_context,
            discrete_log_public_parameters,
            &public_input.setup_parameters_per_crt_prime,
            &public_input.setup_parameters,
            encryption_key_contributions,
            &threshold_encryption_key_shares_and_proofs_for_verification,
            public_input.setup_parameters.decryption_key_bits(),
            rng,
        )?;

        let malicious_parties: HashSet<_> = parties_sending_invalid_proofs
            .into_iter()
            .chain(malicious_parties)
            .collect();

        let threshold_encryption_key_per_crt_prime: [_; NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES] =
            PublicOutput::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::compute_threshold_encryption_keys(
                malicious_parties.clone(),
                threshold_encryption_key_shares_and_proofs,
            )?;

        let encryptions_of_shares_per_crt_prime = PublicOutput::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::sum_encryptions_of_shares::<GroupElement>(
            access_structure,
            malicious_parties.clone(),
            parties_that_were_dealt_shares,
            encryptions_of_shares_and_proofs,
        )?;

        let virtual_subset = access_structure.virtual_subset(HashSet::from([tangible_party_id]))?;

        let decryption_key_shares = publicly_verifiable_secret_sharing::Party::<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::decrypt_secrets(
            public_input.setup_parameters_per_crt_prime.clone(),
            SECRET_SHARE_CRT_COEFFICIENTS,
            SECRET_SHARE_CRT_PRIMES_PRODUCT,
            encryptions_of_shares_per_crt_prime
                .into_iter()
                .filter(|(virtual_party_id, _)| virtual_subset.contains(virtual_party_id))
                .collect(),
            decryption_key_per_crt_prime,
        )?;

        let decryption_key_bits = public_input.setup_parameters.decryption_key_bits();
        let sample_bits = secret_key_share_size_upper_bound(
            u32::from(access_structure.number_of_virtual_parties()),
            u32::from(access_structure.threshold),
            decryption_key_bits,
        );

        let public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound(sample_bits)?;

        // We decrypted the PVSS encryptions and got our secret key shares $[\textsf{sk}]_{i}$.
        // Now we encrypt them under the public key $\textsf{pk}_{Q'_{m'}}$
        // along with a proof of encryption of discrete log with regards to their computed verification key.
        //
        // This encryption is denoted by $\textsf{ct}_{\textsf{share},Q'_{m'}}^{i}$ and the proof by $\pi_{\textsf{EncDL}}^{i}$.
        let encryptions_of_decryption_key_shares_and_proofs = decryption_key_shares
            .clone()
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                let decryption_key_share = bounded_integers_group::GroupElement::new(
                    Int::from(&decryption_key_share),
                    &public_parameters,
                )?;

                let encryptions_of_decryption_key_share_and_proofs_per_crt_prime =
                    prove_encryption_of_discrete_log_per_crt_prime::<
                        NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                        SECRET_KEY_SHARE_WITNESS_LIMBS,
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    >(
                        tangible_party_id,
                        Some(virtual_party_id),
                        None,
                        None,
                        session_id,
                        decryption_key_share,
                        public_input
                            .setup_parameters
                            .equivalence_class_public_parameters()
                            .clone(),
                        public_input.setup_parameters.h,
                        &threshold_encryption_key_per_crt_prime,
                        &public_input.setup_parameters_per_crt_prime,
                        encryption_of_decryption_key_base_protocol_context.clone(),
                        decryption_key_share_bits,
                        rng,
                    )?;

                Ok::<_, Error>((
                    virtual_party_id,
                    DealtSecretShareMessage(
                        encryptions_of_decryption_key_share_and_proofs_per_crt_prime,
                    ),
                ))
            })
            .try_collect_hash_map()?;

        let malicious_parties = malicious_parties.deduplicate_and_sort();

        Ok(AsynchronousRoundResult::Advance {
            malicious_parties,
            message: Message::EncryptDecryptionKeyShares {
                encryptions_of_decryption_key_shares_and_proofs,
            },
        })
    }

    #[allow(clippy::type_complexity)]
    pub(in crate::dkg) fn handle_third_round_messages(
        access_structure: &WeightedThresholdAccessStructure,
        setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        encrypt_decryption_key_shares_messages: HashMap<
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
            HashMap<
                PartyID,
                DealtSecretShare<
                    NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                    SECRET_KEY_SHARE_WITNESS_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        >,
    )> {
        // Make sure everyone sent the third round message.
        // Each party sends $(\textsf{ct}_{\textsf{share},Q'_{m'}^{i},\pi_{\textsf{EncDL},Q'_{m'}}^{i})$ for $m'\in [1,M']$.
        let (parties_sending_invalid_messages, encryptions_of_decryption_key_shares) =
            encrypt_decryption_key_shares_messages
                .into_iter()
                .map(|(dealer_party_id, message)| {
                    let res = match message {
                        Message::EncryptDecryptionKeyShares {
                            encryptions_of_decryption_key_shares_and_proofs:
                                encryptions_of_decryption_key_shares,
                        } => {
                            if let Ok(virtual_subset) =
                                access_structure.virtual_subset(HashSet::from([dealer_party_id]))
                            {
                                if encryptions_of_decryption_key_shares
                                    .keys()
                                    .copied()
                                    .collect::<HashSet<PartyID>>()
                                    == virtual_subset
                                {
                                    Ok(encryptions_of_decryption_key_shares)
                                } else {
                                    Err(Error::InvalidMessage)
                                }
                            } else {
                                Err(Error::InvalidMessage)
                            }
                        }
                        _ => Err(Error::InvalidParameters),
                    };

                    (dealer_party_id, res)
                })
                .handle_invalid_messages_async();

        let (parties_sending_invalid_encryptions, encryptions_of_decryption_key_shares_and_proofs) =
            encryptions_of_decryption_key_shares
                .into_iter()
                .map(
                    |(
                        dealer_tangible_party_id,
                        encryptions_of_decryption_key_shares_and_proofs,
                    )| {
                        let encryptions_of_shares_and_proofs: Result<HashMap<_, _>> =
                            encryptions_of_decryption_key_shares_and_proofs
                                .into_iter()
                                .map(|(dealer_virtual_party_id, dealt_secret_share_message)| {
                                    // Safe to dereference, same sized arrays.
                                    array::from_fn(|i| {
                                        let (proof, encryption_of_share) =
                                            dealt_secret_share_message.0[i].clone();

                                        CiphertextSpaceGroupElement::<
                                            CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                        >::new(
                                            encryption_of_share,
                                            setup_parameters_per_crt_prime[i]
                                                .ciphertext_space_public_parameters(),
                                        )
                                        .map(|ct| (proof, ct))
                                    })
                                    .flat_map_results()
                                    .map(
                                        |proofs_and_encryptions_of_share_per_crt_prime| {
                                            (
                                                dealer_virtual_party_id,
                                                proofs_and_encryptions_of_share_per_crt_prime,
                                            )
                                        },
                                    )
                                })
                                .try_collect_hash_map()
                                .map_err(Error::from);

                        (dealer_tangible_party_id, encryptions_of_shares_and_proofs)
                    },
                )
                .handle_invalid_messages_async();

        let third_round_malicious_parties: Vec<_> = parties_sending_invalid_messages
            .into_iter()
            .chain(parties_sending_invalid_encryptions)
            .deduplicate_and_sort();

        Ok((
            third_round_malicious_parties,
            encryptions_of_decryption_key_shares_and_proofs,
        ))
    }
}
