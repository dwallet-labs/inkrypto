// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;
use std::marker::PhantomData;

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{ristretto, secp256k1, PartyID, PrimeGroupElement, StatisticalSecuritySizedNumber};
use mpc::secret_sharing::shamir::over_the_integers::secret_key_share_size_upper_bound;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use crate::publicly_verifiable_secret_sharing::BaseProtocolContext;
use crate::reconfiguration::{Message, PublicInput, PublicOutput};
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use crate::{
    equivalence_class, publicly_verifiable_secret_sharing, CompactIbqf, EquivalenceClass, Error,
    Result, SecretKeyShareSizedInteger,
};
use crate::{
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS, SECRET_KEY_SHARE_LIMBS,
    SECRET_KEY_SHARE_WITNESS_LIMBS,
};

pub type Secp256k1Party = Party<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;

pub type RistrettoParty = Party<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;

/// The Reconfiguration party,
/// used to generate a distributed class-groups decryption key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(PhantomData<GroupElement>);

pub type RoundResult<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = AsynchronousRoundResult<
    Message<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    (),
    PublicOutput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
>;

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > mpc::Party
    for Party<
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
{
    type Error = Error;
    type PublicInput = PublicInput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = PublicOutput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >;
    type PublicOutput = Self::PublicOutputValue;
    type Message = Message<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >;
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > AsynchronouslyAdvanceable
    for Party<
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
    type PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;

    fn advance(
        session_id: CommitmentSizedNumber,
        tangible_party_id: PartyID,
        current_access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CryptoRngCore,
    ) -> Result<AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>>
    {
        let decryption_key_shares = private_input.ok_or(Error::InvalidParameters)?;

        let upcoming_party_id = public_input
            .current_tangible_party_id_to_upcoming
            .get(&tangible_party_id)
            .cloned()
            .ok_or(Error::InvalidParameters)?;

        let setup_parameters =
            SetupParameters::derive_from_plaintext_parameters::<GroupElement::Scalar>(
                public_input.plaintext_space_public_parameters.clone(),
                public_input.computational_security_parameter,
            )?;

        let decryption_key_bits = setup_parameters.decryption_key_bits();
        let decryption_key_share_bits = secret_key_share_size_upper_bound(
            u32::from(current_access_structure.number_of_virtual_parties()),
            u32::from(current_access_structure.threshold),
            decryption_key_bits,
        );

        // Mask the decryption key statistically.
        let randomizer_contribution_bits =
            setup_parameters.decryption_key_bits() + StatisticalSecuritySizedNumber::BITS;
        // The secret share generated in DKG is actually smaller then the secret key share after the first re-configuration and thereafter.
        // We take decryption_key_share_bits to already include the size after the first re-configuration to avoid introducing new sizes.
        // That being said when actually sampling the key it is in fact sampled form the correct range therefore the randomizer_share_bits is large enough.
        let randomizer_share_bits = decryption_key_share_bits;

        let protocol_name = format!(
            "Class Groups Reconfiguration: {}-out-of-{} to {}-out-of-{}",
            current_access_structure.threshold,
            current_access_structure.number_of_virtual_parties(),
            public_input.upcoming_access_structure.threshold,
            public_input
                .upcoming_access_structure
                .number_of_virtual_parties()
        );

        let knowledge_of_discrete_log_base_protocol_context = BaseProtocolContext {
            protocol_name: protocol_name.clone(),
            round: 1,
            proof_name: "Proof of Valid Threshold Encryption Public Verification Key".to_string(),
        };

        let randomizer_contribution_to_upcoming_base_protocol_context = BaseProtocolContext {
            protocol_name: protocol_name.clone(),
            round: 1,
            proof_name: "Proof of valid shamir secret sharing over the integers of randomizer contribution to upcoming party set".to_string(),
        };

        // This message includes a publicly verifiable sharing on an additive randomizer contribution. The shares are encrypted under the public keys of the upcoming quorum.
        // In addition, it contains an encryption of said contribution under the CRT encryption keys.
        let randomizer_contribution_to_upcoming_pvss_party =
            publicly_verifiable_secret_sharing::Party::<
                NUM_SECRET_SHARE_PRIMES,
                SECRET_KEY_SHARE_LIMBS,
                SECRET_KEY_SHARE_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >::new(
                session_id,
                tangible_party_id,
                upcoming_party_id,
                current_access_structure.clone(),
                public_input.upcoming_access_structure.clone(),
                setup_parameters.clone(),
                public_input.setup_parameters_per_crt_prime.clone(),
                public_input
                    .upcoming_encryption_key_values_and_proofs_per_crt_prime
                    .clone(),
                randomizer_contribution_to_upcoming_base_protocol_context,
                public_input.decryption_key_share_public_parameters.base,
                randomizer_contribution_bits,
                randomizer_share_bits,
                false,
            )?;

        let randomizer_contribution_to_threshold_encryption_key_base_protocol_context =
            BaseProtocolContext {
                protocol_name: protocol_name.clone(),
                round: 1,
                proof_name:
                    "Proof of encryption of randomizer contribution to threshold encryption key"
                        .to_string(),
            };

        match &messages[..] {
            [] => Self::advance_first_round(
                tangible_party_id,
                session_id,
                randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                public_input,
                &setup_parameters,
                &randomizer_contribution_to_upcoming_pvss_party,
                randomizer_contribution_bits,
                rng,
            ),
            [deal_randomizer_messages] => Self::advance_second_round(
                public_input,
                deal_randomizer_messages.clone(),
                &randomizer_contribution_to_upcoming_pvss_party,
                rng,
            ),
            [deal_randomizer_messages, verified_dealers_messages] => Self::advance_third_round(
                tangible_party_id,
                session_id,
                randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                current_access_structure,
                knowledge_of_discrete_log_base_protocol_context,
                &setup_parameters,
                public_input,
                deal_randomizer_messages.clone(),
                &randomizer_contribution_to_upcoming_pvss_party,
                verified_dealers_messages.clone(),
                decryption_key_shares,
                decryption_key_share_bits,
                randomizer_contribution_bits,
                rng,
            ),
            [deal_randomizer_messages, _, deal_masked_decryption_key_share_messages] => {
                Self::advance_fourth_round(
                    current_access_structure,
                    &public_input.upcoming_access_structure,
                    session_id,
                    knowledge_of_discrete_log_base_protocol_context,
                    &setup_parameters,
                    public_input,
                    deal_randomizer_messages.clone(),
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_masked_decryption_key_share_messages.clone(),
                    decryption_key_share_bits,
                    rng,
                )
            }
            _ => Err(Error::InvalidParameters),
        }
    }

    fn round_causing_threshold_not_reached(failed_round: usize) -> Option<usize> {
        match failed_round {
            3 => Some(1),
            4 => Some(3),
            _ => None,
        }
    }
}
