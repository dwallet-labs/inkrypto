// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Signature finalization logic for the decentralized party VSS sign protocol.

use super::{finalize_signature, verify_signature_share, PublicInput};
use crate::dkg::decentralized_party::VersionedOutput as DecentralizedVersionedOutput;
use crate::schnorr::sign::derive_normalized_public_nonce;
use crate::schnorr::vss::presign::Presign;
use crate::schnorr::{PartialSignature, VerifyingKey};
use crate::{Error, ErrorKind};
use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, DecryptionKey, EncryptionKey, EquivalenceClass,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use class_groups::MultiFoldNupowAccelerator;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use group::helpers::DeduplicateAndSort;
use group::{PartyID, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
};
use itertools::Itertools;
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Advances the signature finalization round (Round 2).
///
/// This function handles the reconstruction of the final signature from signature shares,
/// with DOS protection to identify and exclude malicious parties if needed.
#[allow(clippy::too_many_arguments)]
pub fn advance_signature_finalization_round<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy + group::Scale<Uint<SCALAR_LIMBS>>,
>(
    signature_shares: &HashMap<PartyID, group::Value<GroupElement::Scalar>>,
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    public_input: &PublicInput<
        DecentralizedVersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        Presign<GroupElement::Value>,
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
        crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        GroupElement::Value,
    >,
    dkg_output: &crate::dkg::decentralized_party::Output<
        GroupElement::Value,
        group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    >,
    first_key_public_randomizer: Uint<SCALAR_LIMBS>,
    second_key_public_randomizer: Uint<SCALAR_LIMBS>,
    free_coefficient_key_public_randomizer: Uint<SCALAR_LIMBS>,
    protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    first_nonce_polynomial_commitments: &[GroupElement::Value],
    second_nonce_polynomial_commitments: &[GroupElement::Value],
) -> Result<
    AsynchronousRoundResult<group::Value<GroupElement::Scalar>, (), GroupElement::Signature>,
    Error,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
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
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: DeriveFromPlaintextPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
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
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + group::Samplable
        + group::Invert
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    group::Value<GroupElement::Scalar>:
        Into<Uint<SCALAR_LIMBS>> + From<Uint<SCALAR_LIMBS>> + Serialize + for<'a> Deserialize<'a>,
    group::PublicParameters<GroupElement::Scalar>: Default,
    GroupElement::Value: Serialize + for<'a> Deserialize<'a>,
    GroupElement::PublicParameters: Clone + Serialize + for<'a> Deserialize<'a> + PartialEq + Eq,
    <GroupElement::Scalar as group::GroupElement>::PublicParameters:
        Clone + Serialize + for<'a> Deserialize<'a> + PartialEq + Eq,
{
    if signature_shares.len() < access_structure.threshold as usize {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Resolve the SignData enum into a concrete PartialSignature.
    let (centralized_party_partial_signature, _verify) =
        crate::schnorr::sign::decentralized_party::resolve_sign_data::<SCALAR_LIMBS, GroupElement>(
            public_input.centralized_party_partial_signature.clone(),
            &dkg_output.centralized_party_public_key_share,
            &protocol_public_parameters.group_public_parameters,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

    let optimistic_signature_shares_for_interpolation: HashMap<_, _> = signature_shares
        .clone()
        .into_iter()
        .sorted_by(|(party_id, _), (other_party_id, _)| party_id.cmp(other_party_id))
        .take(access_structure.threshold as usize)
        .collect();

    // Try optimistic reconstruction first (fast path for honest parties)
    let signature_result = finalize_signature::<SCALAR_LIMBS, GroupElement>(
        session_id,
        &public_input.message,
        public_input.hash_scheme,
        &public_input.hash_context,
        &optimistic_signature_shares_for_interpolation,
        access_structure.threshold,
        centralized_party_partial_signature
            .public_nonce_share_prenormalization
            .clone(),
        public_input
            .presign
            .decentralized_party_nonce_public_share_first_part
            .clone(),
        public_input
            .presign
            .decentralized_party_nonce_public_share_second_part
            .clone(),
        dkg_output.public_key.clone(),
        &protocol_public_parameters.scalar_group_public_parameters,
        &protocol_public_parameters.group_public_parameters,
    );

    match signature_result {
        Ok(signature) => {
            // Fast path succeeded - all initial shares were honest
            Ok(AsynchronousRoundResult::Finalize {
                malicious_parties: vec![],
                private_output: (),
                public_output: signature,
            })
        }
        Err(_) => {
            // Optimistic reconstruction failed - DOS protection needed
            // Verify each share individually to identify malicious parties

            let normalized_public_nonce_result =
                derive_normalized_public_nonce::<SCALAR_LIMBS, GroupElement>(
                    session_id,
                    &public_input.message,
                    public_input.hash_scheme,
                    public_input
                        .presign
                        .decentralized_party_nonce_public_share_first_part
                        .clone(),
                    public_input
                        .presign
                        .decentralized_party_nonce_public_share_second_part
                        .clone(),
                    &centralized_party_partial_signature.public_nonce_share_prenormalization,
                    &dkg_output.public_key,
                    &protocol_public_parameters.group_public_parameters,
                )?;
            let nonce_normalized = normalized_public_nonce_result.nonce_normalized;
            let presign_public_randomizer =
                normalized_public_nonce_result.presign_public_randomizer;
            let public_nonce =
                normalized_public_nonce_result.decentralized_party_nonce_public_share;

            // Similarly check key negation
            let public_key = GroupElement::new(
                dkg_output.public_key.clone(),
                &protocol_public_parameters.group_public_parameters,
            )?;
            let key_normalized = !public_key.is_taproot_normalized();

            // Compute challenge
            let challenge = public_key.derive_challenge(
                &public_nonce,
                &public_input.message,
                public_input.hash_scheme,
                &public_input.hash_context,
            )?;

            let first_nonce_polynomial_commitments: Vec<GroupElement> =
                first_nonce_polynomial_commitments
                    .iter()
                    .map(|commitment_value| {
                        GroupElement::new(
                            commitment_value.clone(),
                            &protocol_public_parameters.group_public_parameters,
                        )
                    })
                    .collect::<group::Result<Vec<_>>>()?;

            let second_nonce_polynomial_commitments: Vec<GroupElement> =
                second_nonce_polynomial_commitments
                    .iter()
                    .map(|commitment_value| {
                        GroupElement::new(
                            commitment_value.clone(),
                            &protocol_public_parameters.group_public_parameters,
                        )
                    })
                    .collect::<group::Result<Vec<_>>>()?;

            let first_secret_key_polynomial_commitments: Vec<GroupElement> = public_input
                .first_secret_key_polynomial_commitments
                .iter()
                .map(|commitment_value| {
                    GroupElement::new(
                        commitment_value.clone(),
                        &protocol_public_parameters.group_public_parameters,
                    )
                })
                .collect::<group::Result<Vec<_>>>()?;

            let second_secret_key_polynomial_commitments: Vec<GroupElement> = public_input
                .second_secret_key_polynomial_commitments
                .iter()
                .map(|commitment_value| {
                    GroupElement::new(
                        commitment_value.clone(),
                        &protocol_public_parameters.group_public_parameters,
                    )
                })
                .collect::<group::Result<Vec<_>>>()?;

            let malicious_parties = signature_shares
                .iter()
                .filter(|(&party_id, &signature_share)| {
                    verify_signature_share::<SCALAR_LIMBS, GroupElement>(
                        party_id,
                        signature_share,
                        first_nonce_polynomial_commitments.clone(),
                        second_nonce_polynomial_commitments.clone(),
                        first_secret_key_polynomial_commitments.clone(),
                        second_secret_key_polynomial_commitments.clone(),
                        presign_public_randomizer,
                        first_key_public_randomizer,
                        second_key_public_randomizer,
                        free_coefficient_key_public_randomizer,
                        challenge,
                        centralized_party_partial_signature.partial_response,
                        nonce_normalized,
                        key_normalized,
                        &protocol_public_parameters.scalar_group_public_parameters,
                        &protocol_public_parameters.group_public_parameters,
                    )
                    .is_err()
                })
                .map(|(&party_id, _)| party_id)
                .deduplicate_and_sort();

            // Check if we still have enough honest shares
            let verified_signature_shares: HashMap<_, _> = signature_shares
                .clone()
                .into_iter()
                .filter(|(party_id, _)| !malicious_parties.contains(party_id))
                .collect();
            let honest_signature_sharers: HashSet<PartyID> =
                verified_signature_shares.keys().copied().collect();

            if access_structure
                .is_authorized_subset(&honest_signature_sharers)
                .is_err()
            {
                // Not enough honest parties to reach threshold
                return Err(Error::from(ErrorKind::MPC(mpc::Error::from(
                    mpc::ErrorKind::ThresholdNotReached,
                ))));
            }

            // Select first threshold verified shares for reconstruction
            let verified_signature_shares_for_interpolation: HashMap<
                PartyID,
                group::Value<GroupElement::Scalar>,
            > = verified_signature_shares
                .into_iter()
                .sorted_by(|(party_id, _), (other_party_id, _)| party_id.cmp(other_party_id))
                .take(access_structure.threshold as usize)
                .collect();

            // Reconstruct from honest shares
            let signature = finalize_signature::<SCALAR_LIMBS, GroupElement>(
                session_id,
                &public_input.message,
                public_input.hash_scheme,
                &public_input.hash_context,
                &verified_signature_shares_for_interpolation,
                access_structure.threshold,
                centralized_party_partial_signature
                    .public_nonce_share_prenormalization
                    .clone(),
                public_input
                    .presign
                    .decentralized_party_nonce_public_share_first_part
                    .clone(),
                public_input
                    .presign
                    .decentralized_party_nonce_public_share_second_part
                    .clone(),
                dkg_output.public_key.clone(),
                &protocol_public_parameters.scalar_group_public_parameters,
                &protocol_public_parameters.group_public_parameters,
            )
            .map_err(|_| Error::from(ErrorKind::InternalError))?;

            Ok(AsynchronousRoundResult::Finalize {
                malicious_parties,
                private_output: (),
                public_output: signature,
            })
        }
    }
}
