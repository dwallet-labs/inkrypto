// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! MPC Party implementation for the SSS-based presign protocol.
//!
//! This module implements the `mpc::Party` and `mpc::AsynchronouslyAdvanceable` traits
//! for the presign protocol (Protocol 9.2), enabling integration with the MPC framework.

use super::{
    advance_accusation_round, advance_aggregation_round_with_blending, advance_dealing_round,
    AccusationMessage, DealingMessage, PrivateInput,
};
use crate::schnorr::vss::presign::PrivatePresignOutput;
use crate::schnorr::vss::Presign;
use crate::schnorr::VerifyingKey;
use crate::{Error, ErrorKind};
use commitment::CommitmentSizedNumber;
use crypto_bigint::{Encoding, Int, Uint};
use group::{helpers::DeduplicateAndSort, CsRng, PartyID, PrimeGroupElement};
use mpc::secret_sharing::shamir::known_order::EncryptionPublicKey;
use mpc::{
    AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages,
    WeightedThresholdAccessStructure,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;

use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, EncryptionKey, EquivalenceClass,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;

/// Public input for the SSS-based presign protocol.
///
/// Uses the same ProtocolPublicParameters from DKG (class groups based).
/// The protocol public parameters must provide access to scalar and group public parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<ProtocolPublicParameters> {
    /// Protocol public parameters wrapped in Arc for efficient sharing.
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
    /// Encryption public keys for all parties (for VSS share encryption).
    pub party_encryption_keys: HashMap<PartyID, EncryptionPublicKey>,
    /// Set of party IDs whose encryption keys have been UC-verified.
    /// Parties NOT in this set will be excluded from dealing and marked as having invalid keys.
    pub parties_with_uc_verified_public_keys: HashSet<PartyID>,
}

impl<ProtocolPublicParameters> AsRef<ProtocolPublicParameters>
    for PublicInput<ProtocolPublicParameters>
{
    fn as_ref(&self) -> &ProtocolPublicParameters {
        &self.protocol_public_parameters
    }
}

impl<ProtocolPublicParameters, DKGOutput> From<(Arc<ProtocolPublicParameters>, Option<DKGOutput>)>
    for PublicInput<ProtocolPublicParameters>
{
    fn from(
        (protocol_public_parameters, _dkg_output): (
            Arc<ProtocolPublicParameters>,
            Option<DKGOutput>,
        ),
    ) -> Self {
        Self {
            protocol_public_parameters,
            party_encryption_keys: HashMap::new(),
            parties_with_uc_verified_public_keys: HashSet::new(),
        }
    }
}

impl<ProtocolPublicParameters, DKGOutput>
    From<(
        Arc<ProtocolPublicParameters>,
        Option<DKGOutput>,
        HashMap<PartyID, EncryptionPublicKey>,
        HashSet<PartyID>,
    )> for PublicInput<ProtocolPublicParameters>
{
    fn from(
        (
            protocol_public_parameters,
            _dkg_output,
            party_encryption_keys,
            parties_with_uc_verified_public_keys,
        ): (
            Arc<ProtocolPublicParameters>,
            Option<DKGOutput>,
            HashMap<PartyID, EncryptionPublicKey>,
            HashSet<PartyID>,
        ),
    ) -> Self {
        Self {
            protocol_public_parameters,
            party_encryption_keys,
            parties_with_uc_verified_public_keys,
        }
    }
}

/// Extracts dealing messages from a round's messages, identifying parties who sent wrong message types.
fn extract_dealing_messages<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    round_messages: &HashMap<PartyID, Message<SCALAR_LIMBS, GroupElement>>,
) -> (
    Vec<PartyID>,
    HashMap<PartyID, DealingMessage<SCALAR_LIMBS, GroupElement>>,
) {
    round_messages
        .iter()
        .map(|(&dealer_party_id, message)| {
            let dealing_message = match message {
                Message::Dealing(message) => Ok(message.clone()),
                Message::Accusation(_) => Err(Error::from(ErrorKind::InvalidMessage)),
            };
            (dealer_party_id, dealing_message)
        })
        .handle_invalid_messages_async()
}

/// Party struct for the presign protocol.
///
/// Generic parameters:
/// - `SCALAR_LIMBS`: Number of limbs for scalar representation
/// - `FUNDAMENTAL_DISCRIMINANT_LIMBS`: Number of limbs for fundamental discriminant (class groups)
/// - `NON_FUNDAMENTAL_DISCRIMINANT_LIMBS`: Number of limbs for non-fundamental discriminant (class groups)
/// - `GroupElement`: The group element type (e.g., secp256k1::GroupElement)
pub struct Party<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>)
where
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding;

/// Message type for the presign protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "GroupElement::Value: Serialize",
    deserialize = "GroupElement::Value: Deserialize<'de>"
))]
pub enum Message<const SCALAR_LIMBS: usize, GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy> {
    /// Dealing round: Broadcast VSS shares for both nonce components.
    Dealing(DealingMessage<SCALAR_LIMBS, GroupElement>),
    /// Accusation round: Broadcast accusations (revealed keys for malicious dealers).
    Accusation(AccusationMessage),
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > mpc::Party
    for Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
{
    type Error = Error;
    type PublicInput = PublicInput<
        crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;
    type PrivateOutput =
        Vec<PrivatePresignOutput<group::Value<GroupElement::Scalar>, GroupElement::Value>>;
    type PublicOutputValue = Vec<Presign<group::Value<GroupElement>>>;
    type PublicOutput = Self::PublicOutputValue;
    type Message = Message<SCALAR_LIMBS, GroupElement>;
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > AsynchronouslyAdvanceable
    for Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    GroupElement: group::Scale<group::Value<GroupElement::Scalar>>,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + group::Samplable
        + Copy
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    group::Value<GroupElement::Scalar>: Into<Uint<SCALAR_LIMBS>> + From<Uint<SCALAR_LIMBS>>,
{
    type PrivateInput = PrivateInput;

    fn advance(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let protocol_public_parameters = &public_input.protocol_public_parameters;

        // Get the party's encryption secret key from private input
        let secret_key = private_input.ok_or_else(|| Error::from(ErrorKind::InvalidParameters))?;

        if !public_input.party_encryption_keys.contains_key(&party_id) {
            // We must hold an encryption key to participate in this protocol, otherwise no one would deal shares to us.
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

        if !public_input
            .parties_with_uc_verified_public_keys
            .contains(&party_id)
        {
            // We must have a UC-verified encryption key to participate, otherwise we'll be excluded as malicious.
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

        // VSS requires a "naive" access structure where each party has exactly weight 1.
        // This is because VSS deals exactly one share per party, and reconstruction
        // assumes that each party contributes one share. If a party has weight > 1,
        // the protocol would need to deal multiple shares per party to maintain correctness.
        if !access_structure
            .party_to_weight
            .values()
            .all(|&weight| weight == 1)
        {
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

        match &messages[..] {
            // Dealing round: Generate VSS shares
            [] => {
                let dealing_output = advance_dealing_round::<SCALAR_LIMBS, GroupElement>(
                    session_id,
                    party_id,
                    access_structure.threshold,
                    &protocol_public_parameters.scalar_group_public_parameters,
                    &protocol_public_parameters.group_public_parameters,
                    &public_input.party_encryption_keys,
                    &public_input.parties_with_uc_verified_public_keys,
                    rng,
                )?;

                Ok(AsynchronousRoundResult::Advance {
                    malicious_parties: dealing_output.parties_with_invalid_encryption_keys,
                    message: Message::Dealing(dealing_output.message),
                })
            }

            // Accusation round: Decrypt, verify, and message accusations
            [dealing_round_messages] => {
                // Extract dealing messages, identifying parties who sent wrong message types
                let (malicious_parties_wrong_message_type, dealing_messages) =
                    extract_dealing_messages(dealing_round_messages);

                let my_encryption_key = public_input
                    .party_encryption_keys
                    .get(&party_id)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))?;
                let message = advance_accusation_round::<SCALAR_LIMBS, GroupElement>(
                    session_id,
                    party_id,
                    &secret_key.0,
                    my_encryption_key,
                    &dealing_messages,
                    &protocol_public_parameters.scalar_group_public_parameters,
                    &protocol_public_parameters.group_public_parameters,
                    rng,
                )?;

                Ok(AsynchronousRoundResult::Advance {
                    // For consistency, we report the malicious players from the accusation in the final round after taking into account all accusations.
                    // At the current point in time, different players might report different parties, so it is unsafe to report them.
                    // Instead, report only those who sent a wrong message type.
                    malicious_parties: malicious_parties_wrong_message_type,
                    message: Message::Accusation(message),
                })
            }

            // Aggregation round: Verify accusations, apply majority vote, finalize
            [dealing_round_messages, accusation_round_messages] => {
                // Extract dealing messages, identifying parties who sent wrong message types
                let (malicious_parties_wrong_dealing_message, dealing_messages) =
                    extract_dealing_messages(dealing_round_messages);

                // Extract accusation messages, identifying parties who sent wrong message types
                let (malicious_parties_wrong_accusation_message, accusation_messages) =
                    accusation_round_messages
                        .iter()
                        .map(|(&accuaser_party_id, message)| {
                            let res = match message {
                                Message::Accusation(message) => Ok(message.clone()),
                                Message::Dealing(_) => Err(Error::from(ErrorKind::InvalidMessage)),
                            };
                            (accuaser_party_id, res)
                        })
                        .handle_invalid_messages_async();

                // Run aggregation round with blending to finalize
                let my_encryption_key = public_input
                    .party_encryption_keys
                    .get(&party_id)
                    .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))?;
                let (malicious_dealers_and_accusers, private_output, public_output) =
                    advance_aggregation_round_with_blending::<SCALAR_LIMBS, GroupElement>(
                        session_id,
                        party_id,
                        &secret_key.0,
                        my_encryption_key,
                        &dealing_messages,
                        &accusation_messages,
                        &protocol_public_parameters.scalar_group_public_parameters,
                        &protocol_public_parameters.group_public_parameters,
                        &public_input.party_encryption_keys,
                        &public_input.parties_with_uc_verified_public_keys,
                        access_structure,
                        rng,
                    )?;

                let malicious_parties = malicious_parties_wrong_dealing_message
                    .into_iter()
                    .chain(malicious_parties_wrong_accusation_message)
                    .chain(malicious_dealers_and_accusers)
                    .deduplicate_and_sort();

                Ok(AsynchronousRoundResult::Finalize {
                    malicious_parties,
                    private_output,
                    public_output,
                })
            }

            _ => Err(Error::from(ErrorKind::InvalidParameters)),
        }
    }

    fn round_causing_threshold_not_reached(current_round: u64) -> Option<u64> {
        // Aggregation round verifies shares from dealing round and accusations,
        // so if threshold not reached in aggregation round, it's because of malicious parties in earlier rounds
        match current_round {
            3 => Some(1),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::advance_dealing_round;
    use super::super::{advance_accusation_round, advance_aggregation_round_with_blending};
    use super::*;
    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, GroupElement as _, OsCsRng};
    use mpc::secret_sharing::shamir::known_order::{
        generate_encryption_keypair, EncryptionSecretKey,
    };

    fn generate_party_encryption_keys(
        party_ids: &[PartyID],
        rng: &mut impl CsRng,
    ) -> (
        HashMap<PartyID, EncryptionPublicKey>,
        HashMap<PartyID, EncryptionSecretKey>,
    ) {
        let mut public_keys = HashMap::new();
        let mut secret_keys = HashMap::new();

        for &party_id in party_ids {
            let (secret_key, public_key) = generate_encryption_keypair(rng).unwrap();
            public_keys.insert(party_id, public_key);
            secret_keys.insert(party_id, secret_key);
        }

        (public_keys, secret_keys)
    }

    #[test]
    fn test_dealing_round() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let session_id = CommitmentSizedNumber::from(1u64);

        let threshold = 2;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];

        let (party_public_keys, _party_secret_keys) =
            generate_party_encryption_keys(&party_ids, &mut rng);

        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Party 1 executes Round 1
        let dealing_output =
            advance_dealing_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                session_id,
                1,
                threshold,
                &scalar_group_public_parameters,
                &group_params,
                &party_public_keys,
                &parties_with_uc_verified_public_keys,
                &mut rng,
            )
            .unwrap();

        // No parties should have invalid keys in this test
        assert!(
            dealing_output
                .parties_with_invalid_encryption_keys
                .is_empty(),
            "No parties should have invalid encryption keys"
        );

        let message = &dealing_output.message;
        assert_eq!(
            message.coefficient_commitments.len(),
            2,
            "Should have 2 nonces"
        );
        for nonce_commitments in &message.coefficient_commitments {
            assert_eq!(
                nonce_commitments.len(),
                threshold as usize,
                "Each nonce should have threshold coefficients"
            );
        }
        assert_eq!(
            message.encrypted_shares.len(),
            party_public_keys.len(),
            "Should have one encrypted share pair per party"
        );
    }

    #[test]
    fn test_full_protocol() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let session_id = CommitmentSizedNumber::from(1u64);

        let threshold = 2;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];

        let (party_public_keys, party_secret_keys) =
            generate_party_encryption_keys(&party_ids, &mut rng);

        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Create access structure for blending
        let party_weights: HashMap<PartyID, u16> = party_ids.iter().map(|&id| (id, 1u16)).collect();
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_weights).unwrap();

        // Round 1: Each party deals
        let dealing_messages: HashMap<
            PartyID,
            DealingMessage<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
        > = party_ids
            .iter()
            .map(|&party_id| {
                let dealing_output = super::super::advance_dealing_round::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    session_id,
                    party_id,
                    threshold,
                    &scalar_group_public_parameters,
                    &group_params,
                    &party_public_keys,
                    &parties_with_uc_verified_public_keys,
                    &mut rng,
                )
                .unwrap();
                (party_id, dealing_output.message)
            })
            .collect();

        // Round 2: Each party accuses
        let mut accusation_messages: HashMap<PartyID, AccusationMessage> = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let message =
                advance_accusation_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                )
                .unwrap();

            accusation_messages.insert(party_id, message);
        }

        // Round 3: Aggregation with blending
        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let (malicious_parties, private_outputs, public_outputs) =
                advance_aggregation_round_with_blending::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &accusation_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &party_public_keys,
                    &parties_with_uc_verified_public_keys,
                    &access_structure,
                    &mut rng,
                )
                .unwrap();

            // No malicious parties in honest run
            assert!(malicious_parties.is_empty());

            // Use the first blended output
            let private_output = &private_outputs[0];
            let public_output = &public_outputs[0];

            // Verify output is non-trivial
            let neutral =
                secp256k1::GroupElement::neutral_from_public_parameters(&group_params).unwrap();
            assert_ne!(
                public_output.decentralized_party_nonce_public_share_first_part,
                neutral.value(),
                "K_B,0 should not be identity"
            );
            assert_ne!(
                public_output.decentralized_party_nonce_public_share_second_part,
                neutral.value(),
                "K_B,1 should not be identity"
            );

            // Check private output has valid shares
            assert_ne!(
                private_output.nonce_share_first_part,
                secp256k1::Scalar::neutral_from_public_parameters(
                    &secp256k1::scalar::PublicParameters::default()
                )
                .unwrap()
                .value(),
                "Private share should not be zero"
            );
        }
    }
}
