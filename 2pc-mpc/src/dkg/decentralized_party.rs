// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use serde::{Deserialize, Serialize};

use group::direct_product;

pub mod encryption_of_secret_key_share_round;
pub mod proof_verification_round;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Output<GroupElementValue, CiphertextSpaceValue> {
    pub public_key_share: GroupElementValue,
    pub public_key: GroupElementValue,
    pub encryption_of_secret_key_share: CiphertextSpaceValue,
    pub centralized_party_public_key_share: GroupElementValue,
}

pub type EncryptionOfSecretKeyShareAndPublicKeyShare<GroupElementValue, CiphertextSpaceValue> =
    direct_product::Value<CiphertextSpaceValue, GroupElementValue>;
