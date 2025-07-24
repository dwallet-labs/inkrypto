// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::collections::{HashMap, HashSet};

use crate::dkg::{verify_equality_of_discrete_log_proofs, ProveEqualityOfDiscreteLog};
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeDecryptionKeyShare,
    SecretKeyShareCRTPrimeDecryptionKeySharePublicParameters,
    SecretKeyShareCRTPrimeEncryptionSchemePublicParameters, SecretKeyShareCRTPrimeGroupElement,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, ENCRYPTION_OF_DECRYPTION_KEY_CRT_COEFFICIENTS,
    ENCRYPTION_OF_DECRYPTION_KEY_CRT_PRIMES_PRODUCT, NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
    NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{
    chinese_remainder_theorem, BaseProtocolContext, DealtSecretShare,
};
use crate::reconfiguration::party::RoundResult;
use crate::reconfiguration::{
    Message, Party, PublicInput, PublicOutput, RANDOMIZER_LIMBS, RANDOMIZER_WITNESS_LIMBS,
};
use crate::setup::SetupParameters;
use crate::{
    equivalence_class, publicly_verifiable_secret_sharing, CiphertextSpaceGroupElement,
    CompactIbqf, EquivalenceClass, Error, Result,
};
use crate::{SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS};
use commitment::CommitmentSizedNumber;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{Encoding, Int, Uint};
use group::helpers::{DeduplicateAndSort, FlatMapResults, GroupIntoNestedMap};
use group::{bounded_integers_group, GroupElement, PartyID, PrimeGroupElement};
use homomorphic_encryption::AdditivelyHomomorphicDecryptionKeyShare;
use mpc::secret_sharing::shamir::over_the_integers::factorial;
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};

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
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    GroupElement::Scalar: Default,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_fourth_round(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        session_id: CommitmentSizedNumber,
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
        deal_masked_decryption_key_share_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        secret_key_share_upper_bound_bits: u32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        RoundResult<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    > {
        let (
            first_round_malicious_parties,
            upcoming_parties_that_were_dealt_randomizer_shares,
            _,
            reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming,
            encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming,
            threshold_encryption_of_randomizer_contribution_and_proof,
        ) = Self::handle_first_round_messages(
            public_input,
            deal_randomizer_messages.clone(),
            randomizer_contribution_to_upcoming_pvss_party,
        )?;

        let (
            third_round_malicious_parties,
            malicious_randomizer_dealers,
            masked_decryption_key_decryption_shares_and_proofs,
            threshold_public_verification_keys_and_proofs,
        ) = Self::handle_third_round_messages(
            current_access_structure,
            public_input,
            deal_masked_decryption_key_share_messages,
        )?;

        // Instantiate the current public verification keys and adapt them to the structure used by the verification function.
        // Note that we verify proofs of the public verfication keys used for threshold decryption for each crt-prime in the threshold encryption key
        // against the current public verification key.
        // One could initiate this proof more efficiently using a single zk proof in the product group but we do not have an instantiation for product group of size larger than two in this code base.
        let current_public_verification_keys = public_input
            .decryption_key_share_public_parameters
            .public_verification_keys
            .clone()
            .into_iter()
            .map(|(dealer_virtual_party_id, public_verification_key)| {
                let public_verification_key = EquivalenceClass::new(
                    public_verification_key,
                    setup_parameters.equivalence_class_public_parameters(),
                )?;

                current_access_structure
                    .to_tangible_party_id(dealer_virtual_party_id)
                    .map(|dealer_tangible_party_id| {
                        (
                            dealer_tangible_party_id,
                            (Some(dealer_virtual_party_id), public_verification_key),
                        )
                    })
                    .ok_or(Error::InternalError)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .group_into_nested_map();

        let threshold_public_verification_keys_and_proofs_for_verification =
            threshold_public_verification_keys_and_proofs
                .clone()
                .into_iter()
                .map(
                    |(dealer_tangible_party_id, prove_public_verification_keys)| {
                        let public_verification_keys_and_proofs = prove_public_verification_keys
                            .into_iter()
                            .map(
                                |(dealer_virtual_party_id, prove_public_verification_keys)| {
                                    (
                                        Some(dealer_virtual_party_id),
                                        prove_public_verification_keys,
                                    )
                                },
                            )
                            .collect();

                        (
                            dealer_tangible_party_id,
                            public_verification_keys_and_proofs,
                        )
                    },
                )
                .collect();

        let discrete_log_public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound(
                secret_key_share_upper_bound_bits,
            )?;

        let parties_sending_invalid_threshold_public_verification_keys_proofs =
            verify_equality_of_discrete_log_proofs::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                SECRET_KEY_SHARE_WITNESS_LIMBS,
                GroupElement,
            >(
                session_id,
                current_access_structure,
                knowledge_of_discrete_log_base_protocol_context,
                discrete_log_public_parameters,
                &public_input.setup_parameters_per_crt_prime,
                setup_parameters,
                current_public_verification_keys,
                &threshold_public_verification_keys_and_proofs_for_verification,
                secret_key_share_upper_bound_bits,
                rng,
            )?;

        let threshold_encryption_scheme_public_parameters_per_crt_prime: [_;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES] = public_input
            .dkg_output
            .threshold_encryption_scheme_public_parameters_per_crt_prime()?;

        let malicious_parties: Vec<_> = first_round_malicious_parties
            .into_iter()
            .chain(third_round_malicious_parties)
            .chain(malicious_randomizer_dealers.clone())
            .chain(parties_sending_invalid_threshold_public_verification_keys_proofs)
            .deduplicate_and_sort();

        let (
            threshold_encryption_of_randomizer_per_crt_prime,
            threshold_decryption_key_share_public_parameters_per_crt_prime,
        ) = Self::compute_threshold_decryption_key_share_public_parameters_per_crt_prime(
            current_access_structure,
            public_input,
            &malicious_randomizer_dealers,
            &malicious_parties,
            threshold_encryption_scheme_public_parameters_per_crt_prime,
            threshold_encryption_of_randomizer_contribution_and_proof,
            threshold_public_verification_keys_and_proofs,
        )?;

        let threshold_encryption_of_decryption_key_per_crt_prime = public_input
            .dkg_output
            .threshold_encryption_of_decryption_key_per_crt_prime()?;

        // We sum the encryptions of the secret key and the randomizer for each CRT prime. This is then used for verification of the proofs of correct decryptions.
        // Valid decryption shares are collected to produce the value of $r+s\mod Q'_{m'}$ for each CRT prime.
        let mut malicious_decrypters: HashSet<PartyID> = HashSet::new();
        let masked_decryption_key_per_crt_prime = array::from_fn(|i| {
            let decryption_shares_and_proofs = masked_decryption_key_decryption_shares_and_proofs
                .iter()
                .filter(|(dealer_tangible_party_id, _)| {
                    // Filter the threshold masked decryption key decryption shares and proofs using the malicious provers from this round,
                    // to guarantee we don't verify proofs over invalid public verification keys.
                    !malicious_parties.contains(dealer_tangible_party_id)
                })
                .map(
                    |(&dealer_virtual_party_id, decryption_shares_and_proofs_per_crt_prime)| {
                        let (decryption_share, proof) =
                            decryption_shares_and_proofs_per_crt_prime[i].clone();
                        (dealer_virtual_party_id, (vec![decryption_share], proof))
                    },
                )
                .collect();

            let threshold_encryption_of_masked_decryption_key =
                threshold_encryption_of_randomizer_per_crt_prime[i]
                    + threshold_encryption_of_decryption_key_per_crt_prime[i];

            let (current_malicious_decrypters, masked_decryption_key) =
                SecretKeyShareCRTPrimeDecryptionKeyShare::combine_decryption_shares(
                    vec![threshold_encryption_of_masked_decryption_key],
                    decryption_shares_and_proofs,
                    &threshold_decryption_key_share_public_parameters_per_crt_prime[i],
                    rng,
                )?;

            let masked_decryption_key = masked_decryption_key
                .first()
                .copied()
                .ok_or(Error::InternalError)?
                .value();

            malicious_decrypters.extend(&current_malicious_decrypters);

            Ok::<_, Error>(masked_decryption_key)
        })
        .flat_map_results()?;

        // The parties reconstruct $r+s$ over the integers using CRT. This works as the CRT primes are chosen to have a large enough multiplication.
        let masked_decryption_key = chinese_remainder_theorem::reconstruct_integer::<
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
            RANDOMIZER_LIMBS,
        >(
            ENCRYPTION_OF_DECRYPTION_KEY_CRT_COEFFICIENTS,
            ENCRYPTION_OF_DECRYPTION_KEY_CRT_PRIMES_PRODUCT,
            masked_decryption_key_per_crt_prime,
        )?;
        // The masked decryption key is multiplied by $n_{new}!$ which is the values that will be used both for generation of the new shares and the new public keys.
        let upcoming_parties_n_factorial =
            factorial(upcoming_access_structure.number_of_virtual_parties());

        // Filter the commitments and encryptions of the PVSS dealt randomizer to upcoming parties
        // using the same (majority voted) malicious parties that were used to filter it in the third round
        // prior to decryption share generation,
        // to guarantee we will give the upcoming parties the encryptions of the same randomizer we used to mask the decryption key.
        let reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming =
            reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming
                .into_iter()
                .filter(|(dealer_tangible_party_id, _)| {
                    !malicious_randomizer_dealers.contains(dealer_tangible_party_id)
                })
                .collect();

        let encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming =
            encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming
                .into_iter()
                .filter(|(dealer_tangible_party_id, _)| {
                    !malicious_randomizer_dealers.contains(dealer_tangible_party_id)
                })
                .collect();

        let public_output = PublicOutput::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::new::<GroupElement>(
            upcoming_access_structure,
            upcoming_parties_that_were_dealt_randomizer_shares,
            masked_decryption_key,
            reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming,
            encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming,
            public_input
                .decryption_key_share_public_parameters
                .encryption_scheme_public_parameters
                .encryption_key
                .value(),
            setup_parameters.h,
            public_input.setup_parameters_per_crt_prime.clone(),
            upcoming_parties_n_factorial,
        )?;

        let malicious_parties: Vec<_> = malicious_parties
            .into_iter()
            .chain(malicious_decrypters)
            .deduplicate_and_sort();

        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties,
            private_output: (),
            public_output,
        })
    }

    fn compute_threshold_decryption_key_share_public_parameters_per_crt_prime(
        current_access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        malicious_randomizer_dealers: &[PartyID],
        malicious_public_verification_key_provers: &[PartyID],
        threshold_encryption_scheme_public_parameters_per_crt_prime: [SecretKeyShareCRTPrimeEncryptionSchemePublicParameters;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
        threshold_encryptions_of_randomizer_and_proofs: HashMap<
            PartyID,
            DealtSecretShare<
                NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                RANDOMIZER_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        public_verification_keys_and_proofs: HashMap<
            PartyID,
            HashMap<
                PartyID,
                ProveEqualityOfDiscreteLog<
                    SECRET_KEY_SHARE_WITNESS_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        >,
    ) -> Result<(
        [CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
        [SecretKeyShareCRTPrimeDecryptionKeySharePublicParameters;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
    )> {
        // Filter the threshold encryption of randomizer contributions
        // using the same (majority voted) malicious parties that were used to filter it in the third round
        // prior to decryption share generation, to guarantee we are verifying the decryption proofs over the same statements.
        let threshold_encryption_of_randomizer_per_crt_prime =
            Self::sum_threshold_encryptions_of_randomizer_contributions(
                current_access_structure,
                malicious_randomizer_dealers,
                threshold_encryptions_of_randomizer_and_proofs,
            )?;

        // Filter the threshold public verification keys and proofs using the malicious provers from this round,
        // to guarantee we don't create invalid public verification keys for malicious parties.
        let threshold_public_verification_keys: HashMap<_, _> = public_verification_keys_and_proofs
            .into_iter()
            .filter(|(dealer_tangible_party_id, _)| {
                !malicious_public_verification_key_provers.contains(dealer_tangible_party_id)
            })
            .flat_map(|(_, public_verification_keys_and_proofs)| {
                public_verification_keys_and_proofs
            })
            .map(
                |(dealer_virtual_party_id, public_verification_key_and_proof_per_crt_prime)| {
                    (
                        dealer_virtual_party_id,
                        public_verification_key_and_proof_per_crt_prime
                            .map(|(_, public_verification_key)| public_verification_key),
                    )
                },
            )
            .collect();

        let threshold_decryption_key_share_public_parameters_per_crt_prime = array::from_fn(|i| {
            let threshold_public_verification_keys = threshold_public_verification_keys
                .iter()
                .map(
                    |(&dealer_virtual_party_id, public_verification_key_per_crt_prime)| {
                        (
                            dealer_virtual_party_id,
                            public_verification_key_per_crt_prime[i].value(),
                        )
                    },
                )
                .collect();

            SecretKeyShareCRTPrimeDecryptionKeySharePublicParameters::new::<
                SecretKeyShareCRTPrimeGroupElement,
            >(
                current_access_structure.threshold,
                current_access_structure.number_of_virtual_parties(),
                public_input.setup_parameters_per_crt_prime[i].h.value(),
                threshold_public_verification_keys,
                threshold_encryption_scheme_public_parameters_per_crt_prime[i].clone(),
            )
        })
        .flat_map_results()?;

        Ok((
            threshold_encryption_of_randomizer_per_crt_prime,
            threshold_decryption_key_share_public_parameters_per_crt_prime,
        ))
    }
}
