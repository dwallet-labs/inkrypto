// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::sync::Arc;

pub mod encryption_of_nonce_share_round;

/// The public input of the Presign Protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<ProtocolPublicParameters> {
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
}

impl<ProtocolPublicParameters> AsRef<ProtocolPublicParameters>
    for PublicInput<ProtocolPublicParameters>
{
    fn as_ref(&self) -> &ProtocolPublicParameters {
        &self.protocol_public_parameters
    }
}
