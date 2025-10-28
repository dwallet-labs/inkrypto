// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::dkg::centralized_party::SecretKeyShare;
use crate::schnorr::sign::{
    derive_randomized_decentralized_party_public_nonce_share, generate_partial_schnorr_response,
};
use crate::schnorr::{Presign, VerifyingKey};
use crate::{dkg, Error, Result};
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::GroupElement as _;
use group::{CsRng, HashScheme, Samplable, StatisticalSecuritySizedNumber};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::two_party::RoundResult;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Neg;

pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    ProtocolPublicParameters,
>(
    PhantomData<GroupElement>,
    PhantomData<EncryptionKey>,
    PhantomData<ProtocolPublicParameters>,
);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature<GroupElementValue, ScalarValue> {
    // The public nonce share value before is sent pre-normalization for consistency in coefficients derivation.
    pub public_nonce_share_prenormalization: GroupElementValue,
    pub partial_response: ScalarValue,
}

/// The public input of the decentralized party's Schnorr Sign protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<DKGOutput, Presign, ProtocolPublicParameters> {
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
    >
where
    ProtocolPublicParameters: AsRef<
        crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    >,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    pub fn generate_partial_signature(
        secret_key_share: group::Value<GroupElement::Scalar>,
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        dkg_output: dkg::centralized_party::Output<GroupElement::Value>,
        presign: Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters,
        rng: &mut impl CsRng,
    ) -> Result<PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>> {
        let session_id = presign.session_id;
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        let mut secret_key_share = GroupElement::Scalar::new(
            secret_key_share,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        // === 1(a) Sample $k_A\gets\mathbb{Z}_q$ ====
        let mut nonce_share = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )?;

        // === 1(a) Set $K_{A}=k_{A}\cdot G$ ===
        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )?;
        let public_nonce_share_prenormalization = nonce_share * generator;

        // === 2(b) $K_{B} = K_{B,0}+\mu_{k}K_{B,1}$ where $\mu_{k}\gets \mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,K_A,K_{B,0},K_{B,1})$
        // The hash includes a fixed prefix and the group public parameters (omitted in the paper) and the ordered is changed.
        // Group elements are hashed in their original form, before any negation for Taproot normalization.
        let decentralized_party_nonce_public_share =
            derive_randomized_decentralized_party_public_nonce_share(
                session_id,
                message,
                hash_scheme,
                presign.decentralized_party_nonce_public_share_first_part,
                presign.decentralized_party_nonce_public_share_second_part,
                &public_nonce_share_prenormalization.value(),
                &dkg_output.public_key,
                &protocol_public_parameters.group_public_parameters,
            )?;

        // $ K $
        let mut public_nonce = public_nonce_share_prenormalization
            .add_vartime(&decentralized_party_nonce_public_share);

        // If a group element is not Taproot-normalized, its negation will be.
        // Continue signing using the negated public_nonce and public_nonce_share (now Taproot-normalized)
        // and the corresponding negated nonce share.
        if !public_nonce.is_taproot_normalized() {
            nonce_share = nonce_share.neg();
            public_nonce = public_nonce.neg();
        }

        // $ X $
        let mut public_key = GroupElement::new(
            dkg_output.public_key,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // If a group element is not taproot normalized then its negation will be.
        // We then continue to sign according to the negated public_key (which is now taproot normalized) and the negated secret share.
        if !public_key.is_taproot_normalized() {
            // No need to normalize the public key share, as its not used here. The decentralized party will normalize it in this case.
            secret_key_share = secret_key_share.neg();
            public_key = public_key.neg();
        }

        let partial_response = generate_partial_schnorr_response(
            secret_key_share,
            public_key,
            nonce_share,
            public_nonce,
            message,
            hash_scheme,
        )?;

        let partial_signature = PartialSignature {
            public_nonce_share_prenormalization: public_nonce_share_prenormalization.value(),
            partial_response: partial_response.value(),
        };

        Ok(partial_signature)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
    > mpc::two_party::Round
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
    >
where
    ProtocolPublicParameters: AsRef<
        crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    >,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    type Error = Error;
    type PrivateInput = SecretKeyShare<group::Value<GroupElement::Scalar>>;
    type PublicInput = PublicInput<
        dkg::centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElement::Value>,
        Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
        ProtocolPublicParameters,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = Self::PublicOutput;
    type PublicOutput = ();

    type IncomingMessage = ();

    type OutgoingMessage =
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>;

    fn advance(
        _message: Self::IncomingMessage,
        secret_key_share: &Self::PrivateInput,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> std::result::Result<
        RoundResult<Self::OutgoingMessage, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        if &public_input.dkg_output != public_input.protocol_public_parameters.as_ref()
            || &public_input.presign != public_input.protocol_public_parameters.as_ref()
        {
            return Err(Error::InvalidParameters);
        }

        let dkg_output = dkg::centralized_party::Output::from(public_input.dkg_output.clone());

        Self::generate_partial_signature(
            secret_key_share.0,
            &public_input.message,
            public_input.hash_scheme,
            dkg_output,
            public_input.presign.clone(),
            &public_input.protocol_public_parameters,
            rng,
        )
        .map(|partial_signature| RoundResult {
            outgoing_message: partial_signature,
            private_output: (),
            public_output: (),
        })
    }
}

impl<DKGOutput, Presign, ProtocolPublicParameters>
    From<(
        Vec<u8>,
        HashScheme,
        DKGOutput,
        Presign,
        ProtocolPublicParameters,
    )> for PublicInput<DKGOutput, Presign, ProtocolPublicParameters>
{
    fn from(
        (message, hash_scheme, dkg_output, presign, protocol_public_parameters): (
            Vec<u8>,
            HashScheme,
            DKGOutput,
            Presign,
            ProtocolPublicParameters,
        ),
    ) -> Self {
        Self {
            message,
            hash_scheme,
            dkg_output,
            presign,
            protocol_public_parameters,
        }
    }
}
