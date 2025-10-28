// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::dkg;
use serde::{Deserialize, Serialize};

pub mod class_groups;
pub mod encryption_of_mask_and_masked_key_share_round;
pub mod nonce_public_share_and_encryption_of_masked_nonce_parts_round;

/// The public input of the Presign Protocol.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters> {
    pub dkg_output:
        Option<dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>>,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Message<
    EncryptionOfMaskAndMaskedKeyShareAndProof,
    EncryptionOfMaskAndMaskedKeySharePartsAndProof,
    EncryptionOfMaskAndMaskedKeyShare,
    EncryptionOfMaskAndMaskedKeyShareParts,
    NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof,
> {
    EncryptionOfMaskAndMaskedKeyShareAndProof(EncryptionOfMaskAndMaskedKeyShareAndProof),
    EncryptionOfMaskAndMaskedKeyShare(EncryptionOfMaskAndMaskedKeyShare),
    NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof(
        NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof,
    ),
    EncryptionOfMaskAndMaskedKeySharePartsAndProof(EncryptionOfMaskAndMaskedKeySharePartsAndProof),
    EncryptionOfMaskAndMaskedKeyShareParts(EncryptionOfMaskAndMaskedKeyShareParts),
}

impl<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
    From<(
        ProtocolPublicParameters,
        Option<dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>>,
    )> for PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>
{
    fn from(
        (protocol_public_parameters, dkg_output): (
            ProtocolPublicParameters,
            Option<dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>>,
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
