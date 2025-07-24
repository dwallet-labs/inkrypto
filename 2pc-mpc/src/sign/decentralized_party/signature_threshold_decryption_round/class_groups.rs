// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Signature Threshold Decryption round party for Class Groups

use crypto_bigint::{Encoding, Int};

use ::class_groups::equivalence_class;
use ::class_groups::{encryption_key, CompactIbqf, EquivalenceClass};
use ::class_groups::{CiphertextSpaceGroupElement, DecryptionKeyShare, EncryptionKey};
use ::class_groups::{
    CiphertextSpacePublicParameters, RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use ::class_groups::{DecryptionKey, DiscreteLogInF};
use group::{GroupElement, HashToGroup};
use homomorphic_encryption::GroupsPublicParametersAccessors;

use crate::class_groups::DecryptionShare;
use crate::class_groups::{
    DKGDecentralizedPartyOutput, DecryptionKeySharePublicParameters, PartialDecryptionProof,
};
use crate::sign::centralized_party::message::class_groups::Message;

use super::*;

impl Party {
    /// This function implements round 2 of Protocol C.3 (Sign):
    /// Computes signature (r, s) for (m, X).
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    pub fn decrypt_signature_semi_honest_class_groups<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >(
        expected_decrypters: HashSet<PartyID>,
        decryption_shares: HashMap<
            PartyID,
            Vec<DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        hashed_message: GroupElement::Scalar,
        dkg_output: DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        decryption_key_share_public_parameters: &DecryptionKeySharePublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)>
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
        >,
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        let encryption_of_partial_signature =
            CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                sign_message.encryption_of_partial_signature,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        let encryption_of_displaced_decentralized_party_nonce_share =
            CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                sign_message.encryption_of_displaced_decentralized_party_nonce_share,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        Self::decrypt_signature_semi_honest::<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            DecryptionKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >(
            expected_decrypters,
            hashed_message,
            dkg_output,
            decryption_shares,
            encryption_of_partial_signature,
            encryption_of_displaced_decentralized_party_nonce_share,
            sign_message.public_signature_nonce,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
            access_structure,
        )
    }

    /// This function implements round 2 of Protocol C.3 (Sign):
    /// Computes signature (r, s) for (m, X).
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    ///
    /// This function is only called in the malicious flow, in case the semi-honest decryption failed.
    pub fn decrypt_signature_class_groups<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >(
        expected_decrypters: HashSet<PartyID>,
        invalid_semi_honest_decryption_shares: HashMap<
            PartyID,
            Vec<DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (
                Vec<DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
                PartialDecryptionProof<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            ),
        >,
        hashed_message: GroupElement::Scalar,
        dkg_output: DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        decryption_key_share_public_parameters: &DecryptionKeySharePublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        access_structure: &WeightedThresholdAccessStructure,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(Vec<PartyID>, (GroupElement::Scalar, GroupElement::Scalar))>
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
        >,
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        let encryption_of_partial_signature =
            CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                sign_message.encryption_of_partial_signature,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        let encryption_of_displaced_decentralized_party_nonce_share =
            CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                sign_message.encryption_of_displaced_decentralized_party_nonce_share,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        Self::decrypt_signature::<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            DecryptionKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >(
            expected_decrypters,
            hashed_message,
            dkg_output,
            invalid_semi_honest_decryption_shares,
            decryption_shares_and_proofs,
            encryption_of_partial_signature,
            encryption_of_displaced_decentralized_party_nonce_share,
            sign_message.public_signature_nonce,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
            access_structure,
            rng,
        )
    }

    /// The lightweight $$ O(1) $$ threshold decryption logic, which simply verifies the output of
    /// the decryption sent by the designated decrypting party. Blames it in case of an invalid
    /// signature, and accepts otherwise.
    pub fn verify_decrypted_signature_class_groups<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >(
        hashed_message: GroupElement::Scalar,
        signature_s: GroupElement::Scalar,
        designated_decrypting_party_id: PartyID,
        dkg_output: DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)>
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        Self::verify_decrypted_signature::<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            ::class_groups::EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >(
            hashed_message,
            sign_message.public_signature_nonce,
            signature_s,
            designated_decrypting_party_id,
            dkg_output,
            protocol_public_parameters,
        )
    }
}
