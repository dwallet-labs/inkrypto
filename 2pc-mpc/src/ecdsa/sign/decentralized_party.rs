// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use group::{HashContext, HashScheme, PartyID};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;

pub mod signature_partial_decryption_round;
pub mod signature_threshold_decryption_round;

pub mod class_groups;

/// The public input of the decentralized party's Sign protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<
    DKGOutput,
    Presign,
    SignMessage,
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_type: HashScheme,
    pub hash_context: HashContext,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub sign_message: SignMessage,
    pub decryption_key_share_public_parameters: Arc<DecryptionKeySharePublicParameters>,
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
}

/// The public input of the decentralized party's DKG followed by a Sign protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DKGSignPublicInput<
    DKGPublicInput,
    Presign,
    SignMessage,
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_type: HashScheme,
    pub hash_context: HashContext,
    pub dkg_public_input: DKGPublicInput,
    pub presign: Presign,
    pub sign_message: SignMessage,
    pub decryption_key_share_public_parameters: Arc<DecryptionKeySharePublicParameters>,
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
}
