// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::collections::HashSet;
use std::fmt::Debug;

use group::PartyID;
use serde::{Deserialize, Serialize};

pub mod signature_partial_decryption_round;
pub mod signature_threshold_decryption_round;

#[cfg(feature = "class_groups")]
pub mod class_groups;

#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
pub mod paillier;

/// The public input of the decentralized party's Sign protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<
    Scalar,
    DKGOutput,
    Presign,
    SignMessage,
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub hashed_message: Scalar,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub sign_message: SignMessage,
    pub decryption_key_share_public_parameters: DecryptionKeySharePublicParameters,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

impl<
        Scalar,
        DKGOutput,
        Presign,
        SignMessage,
        DecryptionKeySharePublicParameters,
        ProtocolPublicParameters,
    >
    From<(
        HashSet<PartyID>,
        ProtocolPublicParameters,
        Scalar,
        DKGOutput,
        Presign,
        SignMessage,
        DecryptionKeySharePublicParameters,
    )>
    for PublicInput<
        Scalar,
        DKGOutput,
        Presign,
        SignMessage,
        DecryptionKeySharePublicParameters,
        ProtocolPublicParameters,
    >
{
    fn from(
        (
            expected_decrypters,
            protocol_public_parameters,
            hashed_message,
            dkg_output,
            presign,
            sign_message,
            decryption_key_share_public_parameters,
        ): (
            HashSet<PartyID>,
            ProtocolPublicParameters,
            Scalar,
            DKGOutput,
            Presign,
            SignMessage,
            DecryptionKeySharePublicParameters,
        ),
    ) -> Self {
        Self {
            expected_decrypters,
            hashed_message,
            dkg_output,
            presign,
            sign_message,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        }
    }
}
