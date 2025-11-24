// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::sync::Arc;

pub mod encryption_of_nonce_share_round;

/// The public input of the Presign Protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<ProtocolPublicParameters> {
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
}

impl<ProtocolPublicParameters, DKGOutput> From<(Arc<ProtocolPublicParameters>, Option<DKGOutput>)>
    for PublicInput<ProtocolPublicParameters>
{
    fn from(
        (protocol_public_parameters, _dkg_output): (
            Arc<ProtocolPublicParameters>,
            Option<DKGOutput>,
        ),
    ) -> Self {
        Self {
            protocol_public_parameters,
        }
    }
}

impl<ProtocolPublicParameters> AsRef<ProtocolPublicParameters>
    for PublicInput<ProtocolPublicParameters>
{
    fn as_ref(&self) -> &ProtocolPublicParameters {
        &self.protocol_public_parameters
    }
}
