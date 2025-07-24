// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::dkg;
use serde::{Deserialize, Serialize};

#[cfg(feature = "class_groups")]
pub mod class_groups;
pub mod encryption_of_mask_and_masked_key_share_round;
pub mod nonce_public_share_and_encryption_of_masked_nonce_round;
#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
pub mod paillier;

/// The public input of the Presign Protocol.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters> {
    pub dkg_output: dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Message<
    EncryptionOfMaskAndMaskedKeyShareAndProof,
    EncryptionOfMaskAndMaskedKey,
    NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof,
> {
    EncryptionOfMaskAndMaskedKeyShareAndProof(EncryptionOfMaskAndMaskedKeyShareAndProof),
    EncryptionOfMaskAndMaskedKey(EncryptionOfMaskAndMaskedKey),
    NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof(
        NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof,
    ),
}

impl<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
    From<(
        ProtocolPublicParameters,
        dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>,
    )> for PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
{
    fn from(
        (protocol_public_parameters, dkg_output): (
            ProtocolPublicParameters,
            dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>,
        ),
    ) -> Self {
        Self {
            dkg_output,
            protocol_public_parameters,
        }
    }
}

impl<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
    AsRef<ProtocolPublicParameters>
    for PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
{
    fn as_ref(&self) -> &ProtocolPublicParameters {
        &self.protocol_public_parameters
    }
}
