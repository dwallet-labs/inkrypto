// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use serde::{Deserialize, Serialize};

pub mod chinese_remainder_theorem;
// todo(offir): what naming here
pub mod small_prime;

/// The base, protocol-dependent context used to prove encryption of shares.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BaseProtocolContext {
    pub protocol_name: String,
    pub round: u8,
    pub proof_name: String,
}
