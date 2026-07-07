// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::dkg::centralized_party::SecretKeyShare;
use crate::schnorr::sign::centralized_party::sign;
use crate::schnorr::{PartialSignature, Presign, VerifyingKey};
use crate::{dkg, Error, ErrorKind, Result};
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::{CsRng, HashContext, HashScheme, StatisticalSecuritySizedNumber};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::two_party::RoundResult;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;

pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    ProtocolPublicParameters,
>(
    PhantomData<GroupElement>,
    PhantomData<EncryptionKey>,
    PhantomData<ProtocolPublicParameters>,
);

/// The public input of the decentralized party's Schnorr Sign protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<DKGOutput, Presign, ProtocolPublicParameters> {
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub hash_context: HashContext,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

impl<DKGOutput, Presign, ProtocolPublicParameters>
    From<(
        Vec<u8>,
        HashScheme,
        HashContext,
        DKGOutput,
        Presign,
        ProtocolPublicParameters,
    )> for PublicInput<DKGOutput, Presign, ProtocolPublicParameters>
{
    fn from(
        (message, hash_scheme, hash_context, dkg_output, presign, protocol_public_parameters): (
            Vec<u8>,
            HashScheme,
            HashContext,
            DKGOutput,
            Presign,
            ProtocolPublicParameters,
        ),
    ) -> Self {
        Self {
            message,
            hash_scheme,
            hash_context,
            dkg_output,
            presign,
            protocol_public_parameters,
        }
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
        message: &[u8],
        hash_scheme: HashScheme,
        hash_context: &HashContext,
        dkg_output: dkg::centralized_party::Output<GroupElement::Value>,
        presign: Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters,
        rng: &mut impl CsRng,
    ) -> Result<PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>> {
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        sign::<SCALAR_LIMBS, GroupElement>(
            secret_key_share,
            message,
            hash_scheme,
            hash_context,
            presign.session_id,
            dkg_output.public_key,
            presign.decentralized_party_nonce_public_share_first_part,
            presign.decentralized_party_nonce_public_share_second_part,
            &protocol_public_parameters.scalar_group_public_parameters,
            &protocol_public_parameters.group_public_parameters,
            rng,
        )
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

        let dkg_output = dkg::centralized_party::Output::from(public_input.dkg_output.clone());

        Self::generate_partial_signature(
            secret_key_share.0,
            &public_input.message,
            public_input.hash_scheme,
            &public_input.hash_context,
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
