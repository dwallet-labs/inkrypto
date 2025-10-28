// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use commitment::CommitmentSizedNumber;
use group::{bounded_natural_numbers_group, CsRng, GroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::{encryption_of_tuple, extended_encryption_of_tuple};

use crate::ecdsa::presign::decentralized_party::PublicInput;
use crate::ecdsa::VerifyingKey;
use crate::Party::DecentralizedParty;
use crate::{ProtocolContext, ProtocolPublicParameters};

mod class_groups;

pub struct Party {}

impl Party {
    pub(crate) fn sample_mask_and_nonce_share_and_encryption_randomness<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> crate::Result<(
        bounded_natural_numbers_group::GroupElement<MESSAGE_LIMBS>,
        homomorphic_encryption::RandomnessSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
        homomorphic_encryption::RandomnessSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
    )>
    where
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        // === 1(a) Sample $\gamma_it\gets\mathbb{Z}_q$ ===
        let mask_share = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )?;

        // === 1(a) Sample $\eta^i_{1},\gets\mathcal{R}_{\textsf{pk}}$ ===
        let mask_share_encryption_randomness = EncryptionKey::RandomnessSpaceGroupElement::sample(
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            rng,
        )?;

        // === 1(a) Sample $\eta^i_{2}\gets\mathcal{R}_{\textsf{pk}}$ ===
        let masked_key_share_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample(
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                rng,
            )?;

        let message_group_public_parameters =
            bounded_natural_numbers_group::PublicParameters::new_with_randomizer_upper_bound(
                Uint::<SCALAR_LIMBS>::BITS,
            )?;

        let mask_shares_witness = bounded_natural_numbers_group::GroupElement::new(
            Uint::<MESSAGE_LIMBS>::from(&Into::<Uint<SCALAR_LIMBS>>::into(mask_share)),
            &message_group_public_parameters,
        )?;

        Ok((
            mask_shares_witness,
            mask_share_encryption_randomness,
            masked_key_share_encryption_randomness,
        ))
    }

    /// This function implements step (a) in Round 1 of the Presign Protocol:
    /// Samples \gamma_i and prepares computation of $\textsf{ct}_{\gamma}^i$,
    /// and $\textsf{ct}_{\gamma\cdot\textsf{key}}^i$, and their zk-proofs.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428>
    pub(crate) fn sample_mask_and_nonce_share_and_initialize_proof_aggregation<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> crate::Result<
        encryption_of_tuple::WitnessSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            EncryptionKey,
        >,
    >
    where
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        let (
            mask_shares_witness,
            mask_share_encryption_randomness,
            masked_key_share_encryption_randomness,
        ) = Self::sample_mask_and_nonce_share_and_encryption_randomness::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
            EncryptionKey,
        >(protocol_public_parameters, rng)?;

        // Create (\gamma_i, \eta_{1}^{i}, \eta_{2}^{i}) tuples
        let witness = (
            mask_shares_witness,
            mask_share_encryption_randomness,
            masked_key_share_encryption_randomness,
        )
            .into();

        Ok(witness)
    }

    // This function generates an encryption of a multiplicative mask $gamma$ denoted by $\ct_{\gamma}$ along with encryptions of the masked secret key parts $\textsf{ct}_{\gamma\cdot\textsf{key}_0}, $\textsf{ct}_{\gamma\cdot\textsf{key}_1}.
    // This step constitutes the main difference between the universal and targeted pre-sign as have the the encryption of both masked key parts allow to apply the public affine transformation during signing.
    /// This function implements step (a) in Round 1 of the Universal Presign Protocol:
    /// Samples \gamma_i and prepares computation of $\textsf{ct}_{\gamma}^i$,
    /// and $\textsf{ct}_{\gamma\cdot\textsf{key}_0}^i$ and $\textsf{ct}_{\gamma\cdot\textsf{key}_1}^i$, and their zk-proofs.
    /// Note that since the universal presign is generated before knowing the future client consumer and independently of any client, the two parts of the decentralised party are acted independently, and will be aggregated in the online signing phase by the consuming client.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428>
    pub(crate) fn sample_mask_and_nonce_share_and_initialize_extended_proof_aggregation<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> crate::Result<
        extended_encryption_of_tuple::WitnessSpaceGroupElement<
            2,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            EncryptionKey,
        >,
    >
    where
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        // === 1(a) Sample $\gamma_i \gets \mathbb{Z}_q$ and $\eta^i_{0},\eta^i_{1}\gets\mathcal{R}_{\textsf{pk}}$ ===
        let (
            mask_shares_witness,
            mask_share_encryption_randomness,
            masked_key_share_first_part_encryption_randomness,
        ) = Self::sample_mask_and_nonce_share_and_encryption_randomness::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
            EncryptionKey,
        >(protocol_public_parameters, rng)?;

        // === 1(a) Sample $\eta^i_{2}\gets\mathcal{R}_{\textsf{pk}}$ ===
        let masked_key_share_second_part_encryption_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::sample(
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                rng,
            )?;

        // Create $(\gamma_i, \eta_{0}^{i}, (\eta_{1}^{i}, \eta_{2}^{i}))$ tuples
        let witness = (
            mask_shares_witness,
            mask_share_encryption_randomness,
            [
                masked_key_share_first_part_encryption_randomness,
                masked_key_share_second_part_encryption_randomness,
            ]
            .into(),
        )
            .into();

        Ok(witness)
    }
}

impl<
        GroupElementValue: Serialize + Clone,
        CiphertextSpaceValue: Clone,
        ProtocolPublicParameters: Clone,
    > PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
{
    pub(super) fn encryption_of_mask_and_masked_key_share_round_protocol_context_v1(
        &self,
        session_id: CommitmentSizedNumber,
    ) -> ProtocolContext {
        let public_key = self
            .dkg_output
            .as_ref()
            .and_then(|dkg_output| serde_json::to_vec(&dkg_output.public_key).ok());

        ProtocolContext {
            party: DecentralizedParty,
            session_id,
            protocol_name: "2PC-MPC Presign".to_string(),
            round_name: "1 - Encryption of Mask and Masked Key Share".to_string(),
            proof_name: "Encryption of Mask and Masked Key Share Proof".to_string(),
            public_key,
        }
    }
}
