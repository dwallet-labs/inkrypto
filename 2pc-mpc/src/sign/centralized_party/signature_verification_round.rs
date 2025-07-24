// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use serde::{Deserialize, Serialize};

use group::{AffineXCoordinate, PrimeGroupElement};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;

use crate::{dkg, sign::verify_signature, ProtocolPublicParameters, Result};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party {}

impl Party {
    pub fn verify_signature<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        // $m$
        hashed_message: GroupElement::Scalar,
        // $r$
        nonce_x_coordinate: GroupElement::Scalar,
        // $s$
        signature_s: GroupElement::Scalar,
        dkg_output: dkg::centralized_party::PublicOutput<GroupElement::Value>,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
    ) -> Result<()> {
        // = X
        let public_key = GroupElement::new(
            dkg_output.public_key,
            &protocol_public_parameters.group_public_parameters,
        )?;

        verify_signature(nonce_x_coordinate, signature_s, hashed_message, public_key)?;

        Ok(())
    }
}
