// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crypto_bigint::Uint;
use group::{CsRng, GroupElement as _, PrimeGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use maurer::encryption_of_discrete_log;
use serde::{Deserialize, Serialize};

use crate::{BaseProtocolContext, ProtocolContext, Result};

pub mod class_groups;

pub struct Party {}

impl Party {
    /// This function implements step 1 the DKG protocol:
    /// Samples $(x_0, x_1)$ and prepares computation of $(\textsf{ct}_{0,\textsf{key}},\textsf{ct}_{1,\textsf{key}})$ & its zk-proof.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428>
    fn sample_secret_key_share_parts<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        public_input: &PublicInput<
            group::PublicParameters<GroupElement::Scalar>,
            group::PublicParameters<GroupElement>,
            homomorphic_encryption::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
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
            &public_input.scalar_group_public_parameters,
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
                    public_input
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        // === Sample \eta_0^I,\eta_0^I\gets/mathcal{R}_{\textsf{pk}} ===
        // Protocol C.1, step 1(a)
        let encryption_randomnesses = EncryptionKey::RandomnessSpaceGroupElement::sample_batch(
            public_input
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<
    ScalarPublicParameters,
    GroupPublicParameters,
    EncryptionSchemePublicParameters,
> {
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub group_public_parameters: GroupPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionSchemePublicParameters,
    pub base_protocol_context: BaseProtocolContext,
}

impl<ScalarPublicParameters, GroupPublicParameters, EncryptionSchemePublicParameters>
    PublicInput<ScalarPublicParameters, GroupPublicParameters, EncryptionSchemePublicParameters>
{
    /// The backward-compatible instantiation function used for two-round targeted dkg.
    pub fn new_targeted_dkg(
        scalar_group_public_parameters: ScalarPublicParameters,
        group_public_parameters: GroupPublicParameters,
        encryption_scheme_public_parameters: EncryptionSchemePublicParameters,
    ) -> Self {
        let base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC DKG".to_string(),
            round_name: "1 - Encryption of Secret Key Share".to_string(),
            proof_name: "Encryption of Secret Key Share and Public Key Share Proof".to_string(),
        };

        Self {
            scalar_group_public_parameters,
            group_public_parameters,
            encryption_scheme_public_parameters,
            base_protocol_context,
        }
    }
}
