// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

mod class_groups;

use crypto_bigint::{Encoding, Uint};
use serde::Serialize;

use commitment::CommitmentSizedNumber;
use group::{bounded_natural_numbers_group, direct_product, CsRng, GroupElement as _, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::scaling_of_discrete_log;

use crate::ecdsa::presign::decentralized_party::PublicInput;
use crate::ecdsa::VerifyingKey;
use crate::Party::DecentralizedParty;
use crate::{ProtocolContext, ProtocolPublicParameters, Result};

pub struct Party {}

impl Party {
    /// This function implements step (a) in Round 2 of the Presign protocol:
    /// Prepares computation of $$\textsf{ct}_{\gamma\cdot k_{0}}^{i}$ and $\textsf{ct}_{\gamma\cdot k_{1}}^{i}$ and
    /// their zk-proof.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428>
    ///
    /// Note: this function operates on batches; the annotations are written as
    /// if the batch size equals 1.
    pub fn initialize_proof_aggregation<
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
    ) -> Result<
        Vec<
            scaling_of_discrete_log::WitnessSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                MESSAGE_LIMBS,
                EncryptionKey,
            >,
        >,
    >
    where
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        // Sample $k_0^i,k_1^i\gets\mathbb{Z}_q$
        let nonce_share_parts = GroupElement::Scalar::sample_batch(
            &protocol_public_parameters.scalar_group_public_parameters,
            2,
            rng,
        )?;

        let message_group_public_parameters =
            bounded_natural_numbers_group::PublicParameters::new_with_randomizer_upper_bound(
                Uint::<SCALAR_LIMBS>::BITS,
            )?;

        let nonce_share_witnesses = nonce_share_parts
            .into_iter()
            .map(|nonce_share_part| {
                bounded_natural_numbers_group::GroupElement::new(
                    Uint::<MESSAGE_LIMBS>::from(&Into::<Uint<SCALAR_LIMBS>>::into(
                        nonce_share_part,
                    )),
                    &message_group_public_parameters,
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        // Sample $\eta^{i}_{3,0},\eta^{i
        // i}_{3,1}\gets\mathcal{R}_{\textsf{pk}}$
        let encryption_randomnesses = EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            2,
            rng,
        )?;

        Ok(nonce_share_witnesses
            .into_iter()
            .zip(encryption_randomnesses)
            .map(direct_product::GroupElement::from)
            .collect())
    }
}

impl<
        GroupElementValue: Serialize + Clone,
        EncryptionOfMaskAndMaskedNonceShare: Clone,
        ProtocolPublicParameters: Clone,
    >
    PublicInput<GroupElementValue, EncryptionOfMaskAndMaskedNonceShare, ProtocolPublicParameters>
{
    pub(super) fn nonce_public_share_and_encryption_of_masked_nonce_round_protocol_context_v1(
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
            round_name: "2 - Nonce Public Share and Encryption of Masked Nonce".to_string(),
            proof_name: "Nonce Public Share and Encryption of Masked Nonce Proof".to_string(),
            public_key,
        }
    }
}
