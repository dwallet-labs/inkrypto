// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::fmt::Debug;

use crypto_bigint::Uint;
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement as _, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::encryption_of_discrete_log;

use crate::Party::DecentralizedParty;
use crate::{ProtocolContext, ProtocolPublicParameters, Result};

#[cfg(feature = "class_groups")]
pub mod class_groups;
#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
pub mod paillier;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party {}

impl Party {
    /// This function implements step 1 the DKG protocol:
    /// Samples $(x_1, x_2)$ and prepares computation of $(\textsf{ct}_1,\textsf{ct}_2)$ & its zk-proof.
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    fn sample_secret_key_share_parts<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
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
        // === 1(a) Sample $x_{0}^{i},x_{1}^{j} \gets \mathbb{Z}_q $ ====

        // === Sample x_{0}^I,x_{1}^i ====
        // Protocol C.1, step 1(a)
        let share_of_secret_key_share_parts = GroupElement::Scalar::sample_batch(
            &protocol_public_parameters.scalar_group_public_parameters,
            2,
            rng,
        )?;

        let share_of_secret_key_share_witnesses = share_of_secret_key_share_parts
            .into_iter()
            .map(|share_of_secret_key_share_part| {
                EncryptionKey::PlaintextSpaceGroupElement::new(
                    Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&Into::<Uint<SCALAR_LIMBS>>::into(
                        share_of_secret_key_share_part,
                    ))
                    .into(),
                    protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        // === Sample \eta_0^I,\eta_0^I\gets/mathcal{R}_{\textsf{pk}} ===
        // Protocol C.1, step 1(a)
        let encryption_randomnesses = EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters(),
            2,
            rng,
        )?;

        let witnesses = share_of_secret_key_share_witnesses
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
        protocol_name: "2PC-MPC DKG".to_string(),
        round_name: "1 - Encryption of Secret Key Share".to_string(),
        proof_name: "Encryption of Secret Key Share and Public Key Share Proof".to_string(),
        public_key: None,
    }
}
