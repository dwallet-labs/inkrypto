// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::schnorr::VerifyingKey;
use crate::Party::DecentralizedParty;
use crate::{ProtocolContext, ProtocolPublicParameters, Result};
use commitment::CommitmentSizedNumber;
use crypto_bigint::Uint;
use group::{CsRng, GroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use homomorphic_encryption::GroupsPublicParametersAccessors;
use maurer::encryption_of_discrete_log;

pub mod class_groups;

pub struct Party {}

impl Party {
    /// This function implements step 1 the Schnorr Presign protocol:
    /// Samples $(k_0, k_1)$ and prepares computation of $(\textsf{ct}_{k_{0}}^{i},\textsf{ct}_{k_{1}}^{i})$ & its zk-proof.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428> - Protocol C.4, Round 1, step 1.(a)
    fn sample_nonce_share_parts<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
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
            encryption_of_discrete_log::WitnessSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                homomorphic_encryption::PlaintextSpaceGroupElement<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    EncryptionKey,
                >,
                EncryptionKey,
            >,
        >,
    > {
        // === 1(a) Sample $k_{0}^{i},k_{1}^{i} \gets \mathbb{Z}_q $ ====

        // === Sample k_{0}^i,k_{1}^i ====
        // Protocol C.4, step 1(a)
        let share_of_nonce_share_parts = GroupElement::Scalar::sample_batch(
            &protocol_public_parameters.scalar_group_public_parameters,
            2,
            rng,
        )?;

        let share_of_nonce_share_witnesses = share_of_nonce_share_parts
            .into_iter()
            .map(|share_of_nonce_share_part| {
                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&Into::<Uint<SCALAR_LIMBS>>::into(
                        share_of_nonce_share_part,
                    ))
                    .into(),
                    protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        // === Sample \eta_0^i,\eta_1^i\gets/mathcal{R}_{\textsf{pk}} ===
        // Protocol C.4, step 1(a)
        let encryption_randomnesses = EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            2,
            rng,
        )?;

        let witnesses = share_of_nonce_share_witnesses
            .into_iter()
            .zip(encryption_randomnesses)
            .map(<_>::from)
            .collect();

        Ok(witnesses)
    }
}

fn protocol_context(session_id: CommitmentSizedNumber) -> ProtocolContext {
    ProtocolContext {
        party: DecentralizedParty,
        session_id,
        protocol_name: "2PC-MPC Schnorr Presign".to_string(),
        round_name: "1 - Encryption of Nonce Share".to_string(),
        proof_name: "Encryption of Nonce Share and Public Nonce Share Proof".to_string(),
        public_key: None,
    }
}
