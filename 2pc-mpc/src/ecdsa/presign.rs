// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crypto_bigint::{Encoding, Uint};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::class_groups::DKGCentralizedPartyVersionedOutput;
use crate::ecdsa::VerifyingKey;
use crate::presign::Protocol;
use crate::{Error, ProtocolPublicParameters};
use commitment::CommitmentSizedNumber;
use group::{direct_product, self_product, GroupElement, Scale, Transcribeable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};

pub mod decentralized_party;

pub mod class_groups;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presign<GroupElementValue, CiphertextValue> {
    // The session ID of the Presign protocol $sid$ to be used in the corresponding Sign session.
    pub(crate) session_id: CommitmentSizedNumber,
    // $ \textsf{ct}_\gamma $
    pub(crate) encryption_of_mask: CiphertextValue,
    // $ \textsf{ct}_{\gamma\cdot x_{B}} $
    pub(crate) encryption_of_masked_decentralized_party_key_share: CiphertextValue,
    // $ \textsf{ct}_{\gamma \cdot k_{0}} $
    pub(crate) encryption_of_masked_decentralized_party_nonce_share_first_part: CiphertextValue,
    // $\textsf{ct}_{\gamma \cdot k_{1}} $
    pub(crate) encryption_of_masked_decentralized_party_nonce_share_second_part: CiphertextValue,
    // $ R_{B,0} $
    pub(crate) decentralized_party_nonce_public_share_first_part: GroupElementValue,
    // $ R_{B,1} $
    pub(crate) decentralized_party_nonce_public_share_second_part: GroupElementValue,
    // The public key to which this Presign belongs,
    // used as an extra verification to assure a presign corresponds to the same key during Sign.
    pub(crate) public_key: GroupElementValue,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UniversalPresign<GroupElementValue, CiphertextValue> {
    // The session identifier (SID) of the Presign protocol $\textsf{sid}$ to be used in the corresponding Sign session.
    // A universal presign can be consumed by any client and is managed in a common pool.
    // SECURITY NOTICE: the same presign cannot be used twice ever, not even with two different keys.
    pub(crate) session_id: CommitmentSizedNumber,
    // $ \textsf{ct}_\gamma $
    pub(crate) encryption_of_mask: CiphertextValue,
    // $ \textsf{ct}_{\gamma\cdot x_{B,0}} $
    pub(crate) encryption_of_masked_decentralized_party_key_share_first_part: CiphertextValue,
    // $ \textsf{ct}_{\gamma\cdot x_{B,1}} $
    pub(crate) encryption_of_masked_decentralized_party_key_share_second_part: CiphertextValue,
    // $ \textsf{ct}_{\gamma \cdot k_{0}} $
    pub(crate) encryption_of_masked_decentralized_party_nonce_share_first_part: CiphertextValue,
    // $\textsf{ct}_{\gamma \cdot k_{1}} $
    pub(crate) encryption_of_masked_decentralized_party_nonce_share_second_part: CiphertextValue,
    // $ R_{B,0} $
    pub(crate) decentralized_party_nonce_public_share_first_part: GroupElementValue,
    // $ R_{B,1} $
    pub(crate) decentralized_party_nonce_public_share_second_part: GroupElementValue,
    global_decentralized_party_output_commitment: CommitmentSizedNumber,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum VersionedPresign<GroupElementValue, CiphertextSpaceValue> {
    TargetedPresign(Presign<GroupElementValue, CiphertextSpaceValue>),
    UniversalPresign(UniversalPresign<GroupElementValue, CiphertextSpaceValue>),
}

impl<GroupElementValue, CiphertextSpaceValue> From<Presign<GroupElementValue, CiphertextSpaceValue>>
    for VersionedPresign<GroupElementValue, CiphertextSpaceValue>
{
    fn from(targeted_presign: Presign<GroupElementValue, CiphertextSpaceValue>) -> Self {
        VersionedPresign::TargetedPresign(targeted_presign)
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
    > for VersionedPresign<GroupElementValue, CiphertextSpaceValue>
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
        match self {
            VersionedPresign::TargetedPresign(_) => {
                // Nothing to compare to
                true
            }
            VersionedPresign::UniversalPresign(universal_presign) => {
                if let Ok(protocol_global_decentralized_party_output_commitment) =
                    protocol_public_parameters.global_decentralized_party_output_commitment()
                {
                    universal_presign.global_decentralized_party_output_commitment
                        == protocol_global_decentralized_party_output_commitment
                } else {
                    // this is only in the case of a bug
                    false
                }
            }
        }
    }
}

impl<const SCALAR_LIMBS: usize, GroupElementValue: PartialEq, CiphertextSpaceValue>
    PartialEq<
        crate::dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElementValue,
            CiphertextSpaceValue,
        >,
    > for VersionedPresign<GroupElementValue, CiphertextSpaceValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn eq(
        &self,
        other: &crate::dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElementValue,
            CiphertextSpaceValue,
        >,
    ) -> bool {
        match self {
            VersionedPresign::TargetedPresign(targeted_presign) => {
                match other {
                    crate::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(dkg_output) => {
                        targeted_presign.public_key == dkg_output.public_key
                    }
                    // Cannot use targeted presign with universal dkg output.
                    crate::dkg::decentralized_party::VersionedOutput::UniversalPublicDKGOutput { .. } => false,
                }
            }
            VersionedPresign::UniversalPresign(universal_presign) => {
                match other {
                    // Cannot use universal presign with targeted dkg output.
                    crate::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(_) => false,
                    crate::dkg::decentralized_party::VersionedOutput::UniversalPublicDKGOutput {
                        global_decentralized_party_output_commitment,
                        ..
                    } => {
                        universal_presign.global_decentralized_party_output_commitment
                            == *global_decentralized_party_output_commitment
                    }
                }
            }
        }
    }
}

impl<const SCALAR_LIMBS: usize, GroupElementValue: PartialEq, CiphertextSpaceValue>
    PartialEq<crate::dkg::centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElementValue>>
    for VersionedPresign<GroupElementValue, CiphertextSpaceValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn eq(
        &self,
        other: &crate::dkg::centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElementValue>,
    ) -> bool {
        match self {
            VersionedPresign::TargetedPresign(targeted_presign) => {
                match other {
                    crate::dkg::centralized_party::VersionedOutput::TargetedPublicDKGOutput(
                        dkg_output,
                    ) => targeted_presign.public_key == dkg_output.public_key,
                    // Cannot use targeted presign with universal dkg output.
                    crate::dkg::centralized_party::VersionedOutput::UniversalPublicDKGOutput {
                        ..
                    } => false,
                }
            }
            VersionedPresign::UniversalPresign(universal_presign) => {
                match other {
                    // Cannot use universal presign with targeted dkg output.
                    crate::dkg::centralized_party::VersionedOutput::TargetedPublicDKGOutput(_) => {
                        false
                    }
                    crate::dkg::centralized_party::VersionedOutput::UniversalPublicDKGOutput {
                        global_decentralized_party_output_commitment,
                        ..
                    } => {
                        universal_presign.global_decentralized_party_output_commitment
                            == *global_decentralized_party_output_commitment
                    }
                }
            }
        }
    }
}

impl<GroupElementValue: Copy, CiphertextSpaceValue: Copy>
    UniversalPresign<GroupElementValue, CiphertextSpaceValue>
{
    /// Derives a targeted `Presign` from the universal presign `self`,
    /// for the corresponding decentralized party share parameterized by the linear combination of the two shares of $x_{B,0}, x_{B,1}$
    /// using the randomizers $\mu_{x}^{0},\mu_{x}^{1},\mu_{x}^{G} $ (`first_key_public_randomizer`, `second_key_public_randomizer` and `free_coefficient_key_public_randomizer` respectively.)
    ///
    /// Note: The above randomizers must be the same ones that were used in DKG to derive the decentralized party key share $X_{B}$ from $X_{B,0},X_{B,1}$, during the computation of `public_key`.
    pub(crate) fn derive_targeted<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
        encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
        first_key_public_randomizer: Uint<SCALAR_LIMBS>,
        second_key_public_randomizer: Uint<SCALAR_LIMBS>,
        free_coefficient_key_public_randomizer: Uint<SCALAR_LIMBS>,
        public_key: GroupElementValue,
    ) -> crate::Result<Presign<GroupElementValue, CiphertextSpaceValue>>
    where
        EncryptionKey::CiphertextSpaceGroupElement:
            group::GroupElement<Value = CiphertextSpaceValue> + Scale<Uint<SCALAR_LIMBS>>,
    {
        let encryption_of_masked_decentralized_party_key_share_first_part =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                self.encryption_of_masked_decentralized_party_key_share_first_part,
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
            )?;
        let encryption_of_masked_decentralized_party_key_share_second_part =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                self.encryption_of_masked_decentralized_party_key_share_second_part,
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
            )?;

        let encryption_of_mask = EncryptionKey::CiphertextSpaceGroupElement::new(
            self.encryption_of_mask,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        //  Compute $\textsf{ct}_{\gamma\cdot x_{B}}=(\mu_{x}^{0}\odot \textsf{ct}_{\gamma\cdot x_{B,0})\oplus (\mu_{x}^{1}\odot\textsf{ct}_{\gamma\cdot x_{B,1})\oplus \mu_{x}^{G}$
        let encryption_of_masked_decentralized_party_key_share =
            ((encryption_of_masked_decentralized_party_key_share_first_part
                .scale_vartime_accelerated(
                    &first_key_public_randomizer,
                    encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
                ))
            .add_vartime(
                &(encryption_of_masked_decentralized_party_key_share_second_part
                    .scale_vartime_accelerated(
                        &second_key_public_randomizer,
                        encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
                    )),
            ))
            .add_vartime(
                &(encryption_of_mask.scale_vartime_accelerated(
                    &free_coefficient_key_public_randomizer,
                    encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
                )),
            );

        Ok(Presign {
            session_id: self.session_id,
            encryption_of_mask: self.encryption_of_mask,
            encryption_of_masked_decentralized_party_key_share:
                encryption_of_masked_decentralized_party_key_share.value(),
            encryption_of_masked_decentralized_party_nonce_share_first_part: self
                .encryption_of_masked_decentralized_party_nonce_share_first_part,
            encryption_of_masked_decentralized_party_nonce_share_second_part: self
                .encryption_of_masked_decentralized_party_nonce_share_second_part,
            decentralized_party_nonce_public_share_first_part: self
                .decentralized_party_nonce_public_share_first_part,
            decentralized_party_nonce_public_share_second_part: self
                .decentralized_party_nonce_public_share_second_part,
            public_key,
        })
    }
}

impl<GroupElementValue: PartialEq + Serialize + Copy, CiphertextSpaceValue: Serialize + Copy>
    VersionedPresign<GroupElementValue, CiphertextSpaceValue>
{
    /// Derives a targeted `Presign` from `VersionedPresign::UniversalPresign`;
    /// simply returns the inner targeted `Presign` for `VersionedPresign::TargetedPresign`.
    pub(crate) fn derive_targeted<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: group::GroupElement<Value = GroupElementValue> + VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
        dkg_output: DKGCentralizedPartyVersionedOutput<SCALAR_LIMBS, GroupElement>,
    ) -> crate::Result<Presign<GroupElementValue, CiphertextSpaceValue>>
    where
        Uint<SCALAR_LIMBS>: Encoding,
        EncryptionKey::CiphertextSpaceGroupElement:
            group::GroupElement<Value = CiphertextSpaceValue> + Scale<Uint<SCALAR_LIMBS>>,
    {
        if &dkg_output != protocol_public_parameters
            || self != protocol_public_parameters
            || self != &dkg_output
        {
            return Err(Error::InvalidParameters);
        }

        match self {
            VersionedPresign::TargetedPresign(targeted_presign) => Ok(targeted_presign.clone()),
            VersionedPresign::UniversalPresign(universal_presign) => {
                match dkg_output {
                    crate::dkg::centralized_party::VersionedOutput::TargetedPublicDKGOutput(_) => {
                        // Cannot use universal presign with targeted dkg output.
                        Err(Error::InvalidParameters)
                    }
                    crate::dkg::centralized_party::VersionedOutput::UniversalPublicDKGOutput {
                        output,
                        first_key_public_randomizer,
                        second_key_public_randomizer,
                        free_coefficient_key_public_randomizer,
                        ..
                    } => {
                        universal_presign.derive_targeted::<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>(
                            &protocol_public_parameters.encryption_scheme_public_parameters,
                            first_key_public_randomizer,
                            second_key_public_randomizer,
                            free_coefficient_key_public_randomizer,
                            output.public_key,
                        )
                    }
                }
            }
        }
    }
}

impl<
        GroupElementValue: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq,
        CiphertextValue: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq,
    > Presign<GroupElementValue, CiphertextValue>
{
    fn new(
        session_id: CommitmentSizedNumber,
        encryption_of_mask_and_masked_key_share: self_product::Value<2, CiphertextValue>,
        nonce_public_share_and_encryption_of_masked_nonce_share_parts: [direct_product::Value<CiphertextValue, GroupElementValue>;
            2],
        public_key: GroupElementValue,
    ) -> Self {
        let [nonce_public_share_and_encryption_of_masked_nonce_share_first_part, nonce_public_share_and_encryption_of_masked_nonce_share_second_part] =
            nonce_public_share_and_encryption_of_masked_nonce_share_parts;

        let [encryption_of_mask, encryption_of_masked_decentralized_party_key_share] =
            encryption_of_mask_and_masked_key_share.into();
        let (
            encryption_of_masked_decentralized_party_nonce_share_first_part,
            decentralized_party_nonce_public_share_first_part,
        ) = nonce_public_share_and_encryption_of_masked_nonce_share_first_part.into();

        let (
            encryption_of_masked_decentralized_party_nonce_share_second_part,
            decentralized_party_nonce_public_share_second_part,
        ) = nonce_public_share_and_encryption_of_masked_nonce_share_second_part.into();

        Presign {
            session_id,
            encryption_of_mask,
            encryption_of_masked_decentralized_party_key_share,
            encryption_of_masked_decentralized_party_nonce_share_first_part,
            encryption_of_masked_decentralized_party_nonce_share_second_part,
            decentralized_party_nonce_public_share_first_part,
            decentralized_party_nonce_public_share_second_part,
            public_key,
        }
    }
}

impl<
        GroupElementValue: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq,
        CiphertextValue: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq,
    > UniversalPresign<GroupElementValue, CiphertextValue>
{
    fn new(
        session_id: CommitmentSizedNumber,
        encryption_of_mask_and_masked_key_share_parts: direct_product::Value<
            CiphertextValue,
            self_product::Value<2, CiphertextValue>,
        >,
        nonce_public_share_and_encryption_of_masked_nonce_share_parts: [direct_product::Value<CiphertextValue, GroupElementValue>;
            2],
        global_decentralized_party_output_commitment: CommitmentSizedNumber,
    ) -> Self {
        let [nonce_public_share_and_encryption_of_masked_nonce_share_first_part, nonce_public_share_and_encryption_of_masked_nonce_share_second_part] =
            nonce_public_share_and_encryption_of_masked_nonce_share_parts;

        let (encryption_of_mask, encryption_of_masked_decentralized_party_key_share_parts) =
            encryption_of_mask_and_masked_key_share_parts.into();

        let [encryption_of_masked_decentralized_party_key_share_first_part, encryption_of_masked_decentralized_party_key_share_second_part] =
            encryption_of_masked_decentralized_party_key_share_parts.into();

        let (
            encryption_of_masked_decentralized_party_nonce_share_first_part,
            decentralized_party_nonce_public_share_first_part,
        ) = nonce_public_share_and_encryption_of_masked_nonce_share_first_part.into();

        let (
            encryption_of_masked_decentralized_party_nonce_share_second_part,
            decentralized_party_nonce_public_share_second_part,
        ) = nonce_public_share_and_encryption_of_masked_nonce_share_second_part.into();

        UniversalPresign {
            session_id,
            encryption_of_mask,
            encryption_of_masked_decentralized_party_key_share_first_part,
            encryption_of_masked_decentralized_party_key_share_second_part,
            encryption_of_masked_decentralized_party_nonce_share_first_part,
            encryption_of_masked_decentralized_party_nonce_share_second_part,
            decentralized_party_nonce_public_share_first_part,
            decentralized_party_nonce_public_share_second_part,
            global_decentralized_party_output_commitment,
        }
    }
}
