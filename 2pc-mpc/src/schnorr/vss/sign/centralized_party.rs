// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Centralized Party Signing for VSS
//!
//! This module provides VSS-specific wrappers around the shared centralized party
//! sign implementation, plus VSS-specific functionality like signature verification.
//!
//! The VSS protocol uses a different `Presign` type than AHE (no ciphertext fields),
//! so we need VSS-specific `Party` and `PublicInput` types that delegate to the
//! shared signing implementation.

use crate::dkg::centralized_party::VersionedOutput;
use crate::schnorr::vss::presign::Presign;
use crate::schnorr::VerifyingKey;
use crate::{Error, ErrorKind, Result};
use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, DecryptionKey, EncryptionKey, EquivalenceClass,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use class_groups::MultiFoldNupowAccelerator;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use group::{CsRng, HashContext, HashScheme, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
};
use mpc::two_party::RoundResult;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
// Import the shared sign function for internal use
use crate::schnorr::sign::centralized_party::sign;
pub use crate::schnorr::PartialSignature;

/// Wrapper around the shared sign function that accepts VSS-specific types.
///
/// This function extracts the necessary fields from the VSS Presign struct
/// and delegates to the shared signing implementation.
///
/// VSS Schnorr requires `UniversalPublicDKGOutput` because the decentralized party's
/// share is computed as a linear combination using the key randomizers.
pub fn sign_with_vss_presign<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    secret_key_share: group::Value<GroupElement::Scalar>,
    message: &[u8],
    hash_scheme: HashScheme,
    hash_context: &HashContext,
    dkg_output: &VersionedOutput<SCALAR_LIMBS, GroupElement::Value>,
    presign: &Presign<GroupElement::Value>,
    scalar_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    // VSS Schnorr only supports UniversalPublicDKGOutput
    let output = match dkg_output {
        VersionedOutput::UniversalPublicDKGOutput { output, .. } => output,
        VersionedOutput::TargetedPublicDKGOutput(_) => {
            return Err(Error::from(ErrorKind::InvalidParameters));
        }
    };

    sign::<SCALAR_LIMBS, GroupElement>(
        secret_key_share,
        message,
        hash_scheme,
        hash_context,
        presign.session_id,
        output.public_key.clone(),
        presign
            .decentralized_party_nonce_public_share_first_part
            .clone(),
        presign
            .decentralized_party_nonce_public_share_second_part
            .clone(),
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )
}

/// Public input for the VSS centralized party's sign protocol.
///
/// This uses the VSS-specific `Presign` type (without ciphertext fields).
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

/// Centralized party for the VSS-based sign protocol.
///
/// This implements `two_party::Round` using the shared `sign` function internally.
pub struct Party<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > mpc::two_party::Round
    for Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    SetupParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: DeriveFromPlaintextPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + group::Samplable
        + group::Invert
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    group::Value<GroupElement::Scalar>:
        Into<Uint<SCALAR_LIMBS>> + From<Uint<SCALAR_LIMBS>> + Serialize + for<'a> Deserialize<'a>,
    group::PublicParameters<GroupElement::Scalar>: Default,
    GroupElement::Value: Serialize + for<'a> Deserialize<'a>,
    GroupElement::PublicParameters: Clone + Serialize + for<'a> Deserialize<'a> + PartialEq + Eq,
    <GroupElement::Scalar as group::GroupElement>::PublicParameters:
        Clone + Serialize + for<'a> Deserialize<'a> + PartialEq + Eq,
{
    type Error = Error;
    type PrivateInput =
        crate::dkg::centralized_party::SecretKeyShare<group::Value<GroupElement::Scalar>>;
    type PublicInput = PublicInput<
        crate::dkg::centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElement::Value>,
        Presign<GroupElement::Value>,
        crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = ();
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
        let protocol_public_parameters = public_input.protocol_public_parameters.as_ref();

        // Use the shared sign function via the VSS wrapper
        // VSS requires UniversalPublicDKGOutput - the function will validate this
        let partial_signature = sign_with_vss_presign::<SCALAR_LIMBS, GroupElement>(
            secret_key_share.0,
            &public_input.message,
            public_input.hash_scheme,
            &public_input.hash_context,
            &public_input.dkg_output,
            &public_input.presign,
            &protocol_public_parameters.scalar_group_public_parameters,
            &protocol_public_parameters.group_public_parameters,
            rng,
        )?;

        Ok(RoundResult {
            outgoing_message: partial_signature,
            private_output: (),
            public_output: (),
        })
    }
}
