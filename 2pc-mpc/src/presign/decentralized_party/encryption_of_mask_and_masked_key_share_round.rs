// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::fmt::Debug;

use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{bounded_natural_numbers_group, GroupElement, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::encryption_of_tuple;

use crate::presign::decentralized_party::PublicInput;
use crate::Party::DecentralizedParty;
use crate::{ProtocolContext, ProtocolPublicParameters};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party {}

impl Party {
    /// This function implements step (a) in Round 1 of the Presign Protocol:
    /// Samples \gamma_i and prepares computation of $\textsf{ct}_{\gamma}^i$,
    /// and $\textsf{ct}_{\gamma\cdot\textsf{key}^i$, and their zk-proofs.
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    pub(crate) fn sample_mask_and_nonce_share_and_initialize_proof_aggregation<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
        rng: &mut impl CryptoRngCore,
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

        // Create (\gamma_i, \eta_{1}^{i}, \eta_{2}^{i}) tuples
        let witness = (
            mask_shares_witness,
            mask_share_encryption_randomness,
            masked_key_share_encryption_randomness,
        )
            .into();

        Ok(witness)
    }
}

impl<GroupElementValue: Serialize, CiphertextSpaceValue, ProtocolPublicParameters>
    PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
{
    pub(super) fn encryption_of_mask_and_masked_key_share_round_protocol_context(
        &self,
        session_id: CommitmentSizedNumber,
    ) -> ProtocolContext {
        ProtocolContext {
            party: DecentralizedParty,
            session_id,
            protocol_name: "2PC-MPC Presign".to_string(),
            round_name: "1 - Encryption of Mask and Masked Key Share".to_string(),
            proof_name: "Encryption of Mask and Masked Key Share Proof".to_string(),
            public_key: serde_json::to_vec(&self.dkg_output.public_key).ok(),
        }
    }
}
