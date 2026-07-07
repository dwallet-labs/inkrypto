// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::fmt::Debug;

use crate::presign::Protocol;
use crate::ProtocolPublicParameters;
use commitment::CommitmentSizedNumber;
use group::{direct_product, Transcribeable};
use serde::{Deserialize, Serialize};

pub mod decentralized_party;

pub mod class_groups;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presign<GroupElementValue, CiphertextValue> {
    // The session ID of the Presign protocol $sid$ to be used in the corresponding Sign session.
    pub(crate) session_id: CommitmentSizedNumber,
    // $ \textsf{ct}_{k_{0}} $
    pub(crate) encryption_of_decentralized_party_nonce_share_first_part: CiphertextValue,
    // $\textsf{ct}_{k_{1}} $
    pub(crate) encryption_of_decentralized_party_nonce_share_second_part: CiphertextValue,
    // $ K_{B,0} $
    pub(crate) decentralized_party_nonce_public_share_first_part: GroupElementValue,
    // $ K_{B,1} $
    pub(crate) decentralized_party_nonce_public_share_second_part: GroupElementValue,
    pub(crate) global_decentralized_party_output_commitment: CommitmentSizedNumber,
}

impl<
        GroupElementValue: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq,
        CiphertextValue: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq,
    > Presign<GroupElementValue, CiphertextValue>
{
    fn new(
        session_id: CommitmentSizedNumber,
        nonce_public_share_and_encryption_of_nonce_share_parts: [direct_product::Value<CiphertextValue, GroupElementValue>;
            2],
        global_decentralized_party_output_commitment: CommitmentSizedNumber,
    ) -> Self {
        let [nonce_public_share_and_encryption_of_nonce_share_first_part, nonce_public_share_and_encryption_of_nonce_share_second_part] =
            nonce_public_share_and_encryption_of_nonce_share_parts;

        let (
            encryption_of_decentralized_party_nonce_share_first_part,
            decentralized_party_nonce_public_share_first_part,
        ) = nonce_public_share_and_encryption_of_nonce_share_first_part.into();

        let (
            encryption_of_decentralized_party_nonce_share_second_part,
            decentralized_party_nonce_public_share_second_part,
        ) = nonce_public_share_and_encryption_of_nonce_share_second_part.into();

        Presign {
            session_id,
            encryption_of_decentralized_party_nonce_share_first_part,
            encryption_of_decentralized_party_nonce_share_second_part,
            decentralized_party_nonce_public_share_first_part,
            decentralized_party_nonce_public_share_second_part,
            global_decentralized_party_output_commitment,
        }
    }
}

impl<
        GroupElementValue: PartialEq + Serialize,
        CiphertextSpaceValue: Serialize,
        ScalarPublicParameters,
        GroupPublicParameters,
        EncryptionSchemePublicParameters: Transcribeable + Clone,
    >
    PartialEq<
        ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            CiphertextSpaceValue,
            EncryptionSchemePublicParameters,
        >,
    > for Presign<GroupElementValue, CiphertextSpaceValue>
{
    fn eq(
        &self,
        protocol_public_parameters: &ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            CiphertextSpaceValue,
            EncryptionSchemePublicParameters,
        >,
    ) -> bool {
        if let Ok(protocol_global_decentralized_party_output_commitment) =
            protocol_public_parameters.global_decentralized_party_output_commitment()
        {
            self.global_decentralized_party_output_commitment
                == protocol_global_decentralized_party_output_commitment
        } else {
            // this is only in the case of a bug
            false
        }
    }
}
