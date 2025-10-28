// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};

use commitment::CommitmentSizedNumber;
use group::helpers::{DeduplicateAndSort, FlatMapResults, GroupIntoNestedMap};
use group::{CsRng, PartyID, PrimeGroupElement};
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::party::RoundResult;
pub use crate::dkg::public_output::PublicOutput;
use crate::dkg::{verify_encryptions_of_secrets_per_crt_prime, Message, Party, PublicInput};
use crate::encryption_key::public_parameters::Instantiate;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES, NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{
    compute_adjusted_lagrange_coefficients, BaseProtocolContext,
};
use crate::setup::DeriveFromPlaintextPublicParameters;
use crate::setup::SetupParameters;
use crate::{
    encryption_key, equivalence_class, publicly_verifiable_secret_sharing, CompactIbqf,
    EquivalenceClass, Result, SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
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
    /// This round essentially finishes the implementation of $\mathcal{F}_{\textaf{ACS}}$.
    /// In addition, this allows the parties to compute the encryption of the secret key under itself per CRT prime $\textsf_{ct}_{\textsf{sk},Q'_{m'}}$ using interpolation.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::dkg) fn advance_fourth_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
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
        encrypt_decryption_key_shares_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<
        RoundResult<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    > {
        let (malicious_parties, public_output) = Self::advance_fourth_round_internal(
            tangible_party_id,
            session_id,
            encryption_of_decryption_key_base_protocol_context,
            access_structure,
            public_input,
            pvss_party,
            deal_decryption_key_contribution_messages,
            encrypt_decryption_key_shares_messages,
            decryption_key_share_bits,
            rng,
        )?;

        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties,
            private_output: (),
            public_output,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn advance_fourth_round_internal(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
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
        encrypt_decryption_key_shares_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<(
        Vec<PartyID>,
        PublicOutput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    )> {
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

        let (
            third_round_malicious_parties,
            malicious_decryption_key_contribution_dealers,
            threshold_encryptions_of_decryption_key_shares_and_proofs,
        ) = Self::handle_third_round_messages(
            access_structure,
            &public_input.setup_parameters_per_crt_prime,
            encrypt_decryption_key_shares_messages,
        )?;

        let public_verification_keys = PublicOutput::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::compute_public_verification_keys(
            access_structure,
            malicious_decryption_key_contribution_dealers.clone(),
            reconstructed_commitments_to_sharing,
        );

        let threshold_encryption_key_per_crt_prime: [_; NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES] =
            PublicOutput::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::compute_threshold_encryption_keys(
                malicious_decryption_key_contribution_dealers.clone(),
                threshold_encryption_key_shares_and_proofs,
            )?;

        let threshold_encryption_scheme_public_parameters_per_crt_prime = array::from_fn(|i| {
            encryption_key::PublicParameters::new(
                public_input.setup_parameters_per_crt_prime[i].clone(),
                threshold_encryption_key_per_crt_prime[i],
            )
        })
        .flat_map_results()?;

        // Adapt the public verification keys to the commitments structure expected by the verification function
        let commitments = public_verification_keys
            .clone()
            .into_iter()
            .flat_map(|(virtual_party_id, public_verification_key)| {
                access_structure
                    .to_tangible_party_id(virtual_party_id)
                    .map(|tangible_party_id| {
                        (
                            tangible_party_id,
                            (
                                Some(virtual_party_id),
                                HashMap::from([(None, public_verification_key)]),
                            ),
                        )
                    })
            })
            .group_into_nested_map();

        // Adapt the encryptions and proofs to the structure expected by the verification function
        let threshold_encryptions_of_decryption_key_shares_and_proofs_for_verification =
            threshold_encryptions_of_decryption_key_shares_and_proofs
                .clone()
                .into_iter()
                .map(
                    |(
                        dealer_tangible_party_id,
                        encryptions_of_decryption_key_shares_and_proofs,
                    )| {
                        let encryptions_of_decryption_key_shares_and_proofs =
                            encryptions_of_decryption_key_shares_and_proofs
                                .into_iter()
                                .map(|(dealer_virtual_party_id, dealt_secret_share_message)| {
                                    (
                                        Some(dealer_virtual_party_id),
                                        HashMap::from([(None, dealt_secret_share_message)]),
                                    )
                                })
                                .collect();

                        (
                            dealer_tangible_party_id,
                            encryptions_of_decryption_key_shares_and_proofs,
                        )
                    },
                )
                .collect();

        let parties_sending_invalid_proofs = verify_encryptions_of_secrets_per_crt_prime::<
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >(
            None,
            session_id,
            threshold_encryption_scheme_public_parameters_per_crt_prime,
            commitments,
            threshold_encryptions_of_decryption_key_shares_and_proofs_for_verification,
            public_input
                .setup_parameters
                .equivalence_class_public_parameters()
                .clone(),
            public_input.setup_parameters.h,
            encryption_of_decryption_key_base_protocol_context,
            decryption_key_share_bits,
            rng,
        )?;

        let honest_encryptions_of_decryption_key_shares_sharers: HashSet<_> =
            threshold_encryptions_of_decryption_key_shares_and_proofs
                .keys()
                .copied()
                .filter(|dealer_tangible_party_id| {
                    !parties_sending_invalid_proofs.contains(dealer_tangible_party_id)
                })
                .collect();

        access_structure
            .is_authorized_subset(&honest_encryptions_of_decryption_key_shares_sharers)?;

        let (interpolation_subset, adjusted_lagrange_coefficients) =
            compute_adjusted_lagrange_coefficients(
                access_structure,
                honest_encryptions_of_decryption_key_shares_sharers,
                &public_input.binomial_coefficients,
            )?;

        let public_output = PublicOutput::new::<GroupElement>(
            access_structure,
            public_input.setup_parameters_per_crt_prime.clone(),
            malicious_decryption_key_contribution_dealers.clone(),
            interpolation_subset,
            adjusted_lagrange_coefficients,
            parties_that_were_dealt_shares,
            threshold_encryption_key_per_crt_prime,
            public_verification_keys,
            coefficients_contribution_commitments,
            encryptions_of_shares_and_proofs,
            threshold_encryptions_of_decryption_key_shares_and_proofs,
            public_input.n_factorial,
        )?;

        let malicious_parties: Vec<_> = first_round_malicious_parties
            .into_iter()
            .chain(third_round_malicious_parties)
            .chain(malicious_decryption_key_contribution_dealers)
            .chain(parties_sending_invalid_proofs)
            .deduplicate_and_sort();

        Ok((malicious_parties, public_output))
    }
}
