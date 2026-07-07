// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crate::dkg;
use mpc::AsynchronouslyAdvanceable;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// An instantiation of the 2PC-MPC Presign protocol.
pub trait Protocol {
    /// The associated DKG protocol.
    type DKGProtocol: dkg::Protocol;

    /// The Presign protocol's output.
    type Presign: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq;

    /// The HPKE encryption key type for VSS-based protocols.
    /// For AHE-based protocols, this is typically `()`.
    type HPKEEncryptionKey: Clone + Debug + PartialEq + Eq + Send + Sync;

    /// The public input of the (decentralized party's) Presign protocol.
    type PresignPublicInput: AsRef<<Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The private input of the (decentralized party's) Presign protocol.
    /// For VSS-based protocols, this is the encryption secret key.
    /// For AHE-based protocols, this is typically `()`.
    type PresignPrivateInput: Clone + PartialEq + Eq + Send + Sync;

    /// The party of the (decentralized party's) Presign protocol.
    type PresignParty: mpc::Party<
            PublicInput = Self::PresignPublicInput,
            PublicOutput = Vec<Self::Presign>,
            PublicOutputValue = Vec<Self::Presign>,
        > + AsynchronouslyAdvanceable<PrivateInput = Self::PresignPrivateInput>
        + Send
        + Sync;
}

#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
#[allow(dead_code)]
pub(crate) mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::Duration;

    use class_groups::{
        CiphertextSpaceValue, Curve25519EncryptionKey, RistrettoEncryptionKey,
        Secp256k1EncryptionKey, Secp256r1EncryptionKey,
    };
    use commitment::CommitmentSizedNumber;
    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::{Encoding, Random, Uint};
    use group::{
        curve25519, ristretto, secp256k1, secp256r1, GroupElement as _, OsCsRng, PartyID,
        PrimeGroupElement, Samplable,
    };
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };
    use maurer::encryption_of_discrete_log::StatementAccessors;
    use mpc::test_helpers::{
        asynchronous_session_terminates_successfully_internal,
        asynchronous_session_terminates_successfully_internal_with_private_outputs,
    };
    use mpc::{Weight, WeightedThresholdAccessStructure};
    use rand::prelude::IteratorRandom;
    use rstest::rstest;

    use crate::dkg::tests::mock_targeted_dkg_output;
    use crate::schnorr::vss::presign::decentralized_party::{
        PrivateInput as VssPrivateInput, PublicInput as VssPublicInput,
    };
    use crate::test_helpers::{
        setup_class_groups_curve25519, setup_class_groups_ristretto, setup_class_groups_secp256k1,
        setup_class_groups_secp256r1,
    };
    use crate::ProtocolPublicParameters;
    use mpc::secret_sharing::shamir::known_order::{
        generate_encryption_keypair, EncryptionPublicKey, EncryptionSecretKey,
    };

    use super::*;

    /// Setup function for VSS presign protocol.
    ///
    /// VSS uses HPKE encryption for share encryption, so we need to:
    /// 1. Generate encryption keypairs for all parties
    /// 2. Set party_encryption_keys (all public keys) in each party's public input
    /// 3. Return each party's secret key as private input
    pub(crate) fn setup_vss_presign<ProtocolPublicParameters: Clone>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        protocol_public_parameters: ProtocolPublicParameters,
    ) -> (
        CommitmentSizedNumber,
        WeightedThresholdAccessStructure,
        HashMap<PartyID, VssPublicInput<ProtocolPublicParameters>>,
        HashMap<PartyID, VssPrivateInput>,
    ) {
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();
        let parties: Vec<PartyID> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .collect();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        // NOTE: This is TEST HELPER code that generates encryption keypairs for ALL parties.
        // In production, each party generates their own keypair privately:
        // - Each party generates their own (secret_key, public_key) pair
        // - Each party broadcasts only their public_key
        // - Each party keeps their secret_key private
        // - Each party collects all public keys into party_encryption_keys
        let (party_encryption_keys, party_secret_keys): (
            HashMap<PartyID, EncryptionPublicKey>,
            HashMap<PartyID, VssPrivateInput>,
        ) = parties
            .iter()
            .map(|&party_id| {
                let (secret_key, public_key) = generate_encryption_keypair(&mut OsCsRng).unwrap();
                (
                    (party_id, public_key),
                    (party_id, VssPrivateInput::new(secret_key)),
                )
            })
            .unzip();

        let protocol_public_parameters = Arc::new(protocol_public_parameters);

        // All parties are UC-verified in this test setup
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            parties.iter().copied().collect();

        // Create PublicInput for each party with encryption keys
        let public_inputs = parties
            .iter()
            .map(|&party_id| {
                (
                    party_id,
                    VssPublicInput {
                        protocol_public_parameters: protocol_public_parameters.clone(),
                        party_encryption_keys: party_encryption_keys.clone(),
                        parties_with_uc_verified_public_keys: parties_with_uc_verified_public_keys
                            .clone(),
                    },
                )
            })
            .collect();

        (
            session_id,
            access_structure,
            public_inputs,
            party_secret_keys,
        )
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(2, HashMap::from([(1, 1), (2, 1), (3, 1)]))]
    #[case(3, HashMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]))]
    fn generates_vss_schnorr_presignatures_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_vss_presignatures_secp256k1_internal::<crate::secp256k1::vss::TaprootVSSProtocol>(
            threshold,
            party_to_weight,
            HashMap::new(),
            "VSS Asynchronous Schnorr secp256k1 (Taproot)",
        );
    }

    pub(crate) fn generates_vss_presignatures_secp256k1_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        parties_by_round: HashMap<u64, HashSet<PartyID>>,
        description: &str,
    ) -> Vec<P::Presign>
    where
        P: Protocol<
            PresignPublicInput = VssPublicInput<
                crate::class_groups::ProtocolPublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::GroupElement,
                >,
            >,
            PresignPrivateInput = VssPrivateInput,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
                >,
                group::PublicParameters<secp256k1::GroupElement>,
                group::Value<secp256k1::GroupElement>,
                CiphertextSpaceValue<
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let (protocol_public_parameters, _) = setup_class_groups_secp256k1();

        let (session_id, access_structure, public_inputs, private_inputs) = setup_vss_presign(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
        );

        let (presigns, _private_outputs) = generates_presignatures_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            3, // VSS presign has 3 rounds: dealing, accusation, aggregation
            parties_by_round,
            description.to_string(),
        );
        presigns
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(2, HashMap::from([(1, 1), (2, 1), (3, 1)]))]
    #[case(3, HashMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]))]
    fn generates_vss_schnorr_presignatures_curve25519(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_vss_presignatures_curve25519_internal::<crate::curve25519::vss::EdDSAVSSProtocol>(
            threshold,
            party_to_weight,
            HashMap::new(),
            "VSS Asynchronous Schnorr curve25519 (EdDSA)",
        );
    }

    pub(crate) fn generates_vss_presignatures_curve25519_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        parties_by_round: HashMap<u64, HashSet<PartyID>>,
        description: &str,
    ) -> Vec<P::Presign>
    where
        P: Protocol<
            PresignPublicInput = VssPublicInput<
                crate::class_groups::ProtocolPublicParameters<
                    { curve25519::SCALAR_LIMBS },
                    { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    curve25519::GroupElement,
                >,
            >,
            PresignPrivateInput = VssPrivateInput,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
            DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
            DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ curve25519::SCALAR_LIMBS }, curve25519::GroupElement>,
                >,
                group::PublicParameters<curve25519::GroupElement>,
                group::Value<curve25519::GroupElement>,
                CiphertextSpaceValue<
                    { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { curve25519::SCALAR_LIMBS },
                    { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    curve25519::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let (protocol_public_parameters, _) = setup_class_groups_curve25519();

        let (session_id, access_structure, public_inputs, private_inputs) = setup_vss_presign(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
        );

        let (presigns, _private_outputs) = generates_presignatures_internal::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            3, // VSS presign has 3 rounds: dealing, accusation, aggregation
            parties_by_round,
            description.to_string(),
        );
        presigns
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(2, HashMap::from([(1, 1), (2, 1), (3, 1)]))]
    #[case(3, HashMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]))]
    fn generates_vss_schnorr_presignatures_ristretto(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_vss_presignatures_ristretto_internal::<
            crate::ristretto::vss::SchnorrkelVSSProtocol,
        >(
            threshold,
            party_to_weight,
            "VSS Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)",
        );
    }

    pub(crate) fn generates_vss_presignatures_ristretto_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        description: &str,
    ) where
        P: Protocol<
            PresignPublicInput = VssPublicInput<
                crate::class_groups::ProtocolPublicParameters<
                    { ristretto::SCALAR_LIMBS },
                    { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    ristretto::GroupElement,
                >,
            >,
            PresignPrivateInput = VssPrivateInput,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
            DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
            DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ ristretto::SCALAR_LIMBS }, ristretto::GroupElement>,
                >,
                group::PublicParameters<ristretto::GroupElement>,
                group::Value<ristretto::GroupElement>,
                CiphertextSpaceValue<
                    { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { ristretto::SCALAR_LIMBS },
                    { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    ristretto::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let (protocol_public_parameters, _) = setup_class_groups_ristretto();

        let (session_id, access_structure, public_inputs, private_inputs) = setup_vss_presign(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
        );

        generates_presignatures_internal::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            3, // VSS presign has 3 rounds: dealing, accusation, aggregation
            HashMap::new(),
            description.to_string(),
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), false)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), true)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), false)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), true)]
    fn generates_ecdsa_presignatures_async_class_groups_secp256r1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] is_universal: bool,
    ) {
        generates_presignatures_async_class_groups_secp256r1_internal::<
            crate::secp256r1::class_groups::ECDSAProtocol,
        >(
            threshold,
            party_to_weight,
            is_universal,
            "Class Groups Asynchronous ECDSA secp256r1",
        )
    }

    pub(crate) fn generates_presignatures_async_class_groups_secp256r1_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        is_universal: bool,
        description: &str,
    ) where
        P: Protocol<
            PresignPrivateInput = (),
            PresignPublicInput = crate::ecdsa::presign::decentralized_party::PublicInput<
                group::Value<secp256r1::GroupElement>,
                CiphertextSpaceValue<
                    { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                crate::class_groups::ProtocolPublicParameters<
                    { secp256r1::SCALAR_LIMBS },
                    { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256r1::GroupElement,
                >,
            >,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { secp256r1::SCALAR_LIMBS },
                { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256r1::GroupElement,
            >,
            DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                { secp256r1::SCALAR_LIMBS },
                { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256r1::GroupElement,
            >,
            DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                { secp256r1::SCALAR_LIMBS },
                { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256r1::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ secp256r1::SCALAR_LIMBS }, secp256r1::GroupElement>,
                >,
                group::PublicParameters<secp256r1::GroupElement>,
                group::Value<secp256r1::GroupElement>,
                CiphertextSpaceValue<
                    { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { secp256r1::SCALAR_LIMBS },
                    { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256r1::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let description = format!(
            "{} {}",
            description,
            if is_universal {
                "Universal"
            } else {
                "Targeted"
            }
        );

        let (protocol_public_parameters, _) = setup_class_groups_secp256r1();

        let dkg_output = if is_universal {
            None
        } else {
            let (_, _, dkg_output) = mock_targeted_dkg_output::<
                { secp256r1::SCALAR_LIMBS },
                { secp256r1::SCALAR_LIMBS },
                secp256r1::GroupElement,
                Secp256r1EncryptionKey,
            >(&protocol_public_parameters);

            let crate::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(
                dkg_output,
            ) = dkg_output
            else {
                panic!("mock_targeted_dkg_output() should mock targeted public DKG outputs only")
            };

            Some(dkg_output)
        };

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone()).unwrap();
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let protocol_public_parameters = Arc::new(protocol_public_parameters);

        let public_inputs: HashMap<PartyID, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| {
                (
                    party_id,
                    crate::ecdsa::presign::decentralized_party::PublicInput {
                        protocol_public_parameters: protocol_public_parameters.clone(),
                        dkg_output: dkg_output.clone(),
                    },
                )
            })
            .collect();

        let private_inputs: HashMap<_, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        generates_presignatures_internal::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            4, // ECDSA presign has 4 rounds
            HashMap::new(),
            description,
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn generates_schnorr_presignatures_async_class_groups_curve25519(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_presignatures_async_class_groups_curve25519_internal::<
            crate::curve25519::class_groups::EdDSAProtocol,
        >(
            threshold,
            party_to_weight,
            HashMap::new(),
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)",
        );
    }

    // INSECURE `unsafe_mock`: the blended-presign count semantics (how many presigns survive
    // adversarial weight control) are a real-protocol property; the mock emits a single dummy
    // presign per session.
    #[cfg(not(feature = "unsafe_mock"))]
    #[test]
    fn blends_presigns() {
        let threshold = 67;
        let party_to_weight: HashMap<_, _> = (1..=30)
            .map(|i| (i, 1))
            .chain((31..=55).map(|i| (i, 2)))
            .chain((56..60).map(|i| (i, 5)))
            .collect();

        let parties_by_round = HashMap::from([(
            1,
            (1..=59)
                .collect::<HashSet<_>>()
                .difference(&HashSet::from([
                    2, 3, 4, 6,
                    7, // remove 5 parties with weight 1 -> 25 left (weight 25 * 1)
                    40, 42, 45, 48,
                    39, // remove 5 parties with weight 2 -> 20 left (weight 20 * 2 = 40, including above 65)
                    56, 57,
                    58, // remove 3 parties with weight 5 -> 1 left (weight 1 * 5 = 10, including above 70)
                ]))
                .copied()
                .collect(),
        )]);

        let presigns = generates_presignatures_async_class_groups_curve25519_internal::<
            crate::curve25519::class_groups::EdDSAProtocol,
        >(
            threshold,
            party_to_weight.clone(),
            parties_by_round,
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)",
        );

        // We expect the adversary to be able to control all parties -> one presign.
        assert_eq!(presigns.len(), 1);

        let parties_by_round = HashMap::from([(
            1,
            (1..=59)
                .collect::<HashSet<_>>()
                .difference(&HashSet::from([
                    2, 3, 4, 6,
                    7, // remove 5 parties with weight 1 -> 25 left (weight 25 * 1)
                    40, 42, 45, 48,
                    39, // remove 5 parties with weight 2 -> 20 left (weight 20 * 2 = 40, including above 65)
                    57,
                    58, // remove 2 parties with weight 5 -> 2 left (weight 2 * 5 = 10, including above 75)
                ]))
                .copied()
                .collect(),
        )]);

        let presigns = generates_presignatures_async_class_groups_curve25519_internal::<
            crate::curve25519::class_groups::EdDSAProtocol,
        >(
            threshold,
            party_to_weight.clone(),
            parties_by_round,
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)",
        );

        // We expect the adversary to be able to control up until and including the second party of weight 5, so only two left outside of it control -> two presigns.
        assert_eq!(presigns.len(), 2);

        let parties_by_round = HashMap::from([(
            1,
            (1..=59)
                .collect::<HashSet<_>>()
                .difference(&HashSet::from([
                    2, 3, 4, 6,
                    7, // remove 5 parties with weight 1 -> 25 left (weight 25 * 1)
                    40,
                    42, // remove 2 parties with weight 2 -> 23 left (weight 23 * 2 = 46, including above 71 -> need < 67, which is 20 parties of weight 2)
                    57, // remove 1 party with weight 5 -> 3 left (weight 3 * 5 = 15)
                ]))
                .copied()
                .collect(),
        )]);

        let presigns = generates_presignatures_async_class_groups_curve25519_internal::<
            crate::curve25519::class_groups::EdDSAProtocol,
        >(
            threshold,
            party_to_weight,
            parties_by_round,
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)",
        );

        // We expect the adversary to be able to control all remaining 25 parties with weight 1
        // 20 of the 23 parties of weight 2 (at least three honest)
        // and none of the remaining 3 parties of weight 3 -> 6 presigns.
        assert_eq!(presigns.len(), 6);
    }

    pub(crate) fn generates_presignatures_async_class_groups_curve25519_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        parties_by_round: HashMap<u64, HashSet<PartyID>>,
        description: &str,
    ) -> Vec<P::Presign>
    where
        P: Protocol<
            PresignPrivateInput = (),
            PresignPublicInput = crate::schnorr::ahe::presign::decentralized_party::PublicInput<
                crate::class_groups::ProtocolPublicParameters<
                    { curve25519::SCALAR_LIMBS },
                    { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    curve25519::GroupElement,
                >,
            >,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
            DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
            DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ curve25519::SCALAR_LIMBS }, curve25519::GroupElement>,
                >,
                group::PublicParameters<curve25519::GroupElement>,
                group::Value<curve25519::GroupElement>,
                CiphertextSpaceValue<
                    { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { curve25519::SCALAR_LIMBS },
                    { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    curve25519::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let (protocol_public_parameters, _) = setup_class_groups_curve25519();

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone()).unwrap();
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let protocol_public_parameters = Arc::new(protocol_public_parameters);

        let public_inputs: HashMap<PartyID, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| {
                (
                    party_id,
                    crate::schnorr::ahe::presign::decentralized_party::PublicInput {
                        protocol_public_parameters: protocol_public_parameters.clone(),
                    },
                )
            })
            .collect();

        let private_inputs: HashMap<_, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        let (presigns, _private_outputs) = generates_presignatures_internal::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            2, // Schnorr presign has 2 rounds
            parties_by_round,
            description.to_string(),
        );
        presigns
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn generates_schnorr_presignatures_async_class_groups_ristretto(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_presignatures_async_class_groups_ristretto_internal::<
            crate::ristretto::class_groups::SchnorrkelProtocol,
        >(
            threshold,
            party_to_weight,
            "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)",
        )
    }

    pub(crate) fn generates_presignatures_async_class_groups_ristretto_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        description: &str,
    ) where
        P: Protocol<
            PresignPrivateInput = (),
            PresignPublicInput = crate::schnorr::ahe::presign::decentralized_party::PublicInput<
                crate::class_groups::ProtocolPublicParameters<
                    { ristretto::SCALAR_LIMBS },
                    { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    ristretto::GroupElement,
                >,
            >,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
            DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
            DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ ristretto::SCALAR_LIMBS }, ristretto::GroupElement>,
                >,
                group::PublicParameters<ristretto::GroupElement>,
                group::Value<ristretto::GroupElement>,
                CiphertextSpaceValue<
                    { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { ristretto::SCALAR_LIMBS },
                    { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    ristretto::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let (protocol_public_parameters, _) = setup_class_groups_ristretto();

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone()).unwrap();
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let protocol_public_parameters = Arc::new(protocol_public_parameters);

        let public_inputs: HashMap<PartyID, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| {
                (
                    party_id,
                    crate::schnorr::ahe::presign::decentralized_party::PublicInput {
                        protocol_public_parameters: protocol_public_parameters.clone(),
                    },
                )
            })
            .collect();

        let private_inputs: HashMap<_, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        generates_presignatures_internal::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            2, // Schnorr presign has 2 rounds
            HashMap::new(),
            description.to_string(),
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn generates_schnorr_presignatures_async_class_groups_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_schnorr_presignatures_async_class_groups_secp256k1_internal::<
            crate::secp256k1::class_groups::TaprootProtocol,
        >(
            threshold,
            party_to_weight,
            "Class Groups Asynchronous Schnorr secp256k1",
        )
    }

    pub(crate) fn generates_schnorr_presignatures_async_class_groups_secp256k1_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        description: &str,
    ) where
        P: Protocol<
            PresignPrivateInput = (),
            PresignPublicInput = crate::schnorr::ahe::presign::decentralized_party::PublicInput<
                crate::class_groups::ProtocolPublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::GroupElement,
                >,
            >,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
                >,
                group::PublicParameters<secp256k1::GroupElement>,
                group::Value<secp256k1::GroupElement>,
                CiphertextSpaceValue<
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let (protocol_public_parameters, _) = setup_class_groups_secp256k1();

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone()).unwrap();
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let protocol_public_parameters = Arc::new(protocol_public_parameters);

        let public_inputs: HashMap<PartyID, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| {
                (
                    party_id,
                    crate::schnorr::ahe::presign::decentralized_party::PublicInput {
                        protocol_public_parameters: protocol_public_parameters.clone(),
                    },
                )
            })
            .collect();

        let private_inputs: HashMap<_, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        generates_presignatures_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            2, // Schnorr presign has 2 rounds
            HashMap::new(),
            description.to_string(),
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), false)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), true)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), false)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), true)]
    fn generates_ecdsa_presignatures_async_class_groups_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] is_universal: bool,
    ) {
        generates_presignatures_async_class_groups_secp256k1_internal::<
            crate::secp256k1::class_groups::ECDSAProtocol,
        >(
            threshold,
            party_to_weight,
            is_universal,
            4, // ECDSA presign has 4 rounds
            "Class Groups Asynchronous ECDSA secp256k1",
        )
    }

    pub(crate) fn generates_presignatures_async_class_groups_secp256k1_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        is_universal: bool,
        number_of_rounds: usize,
        description: &str,
    ) where
        P: Protocol<
            PresignPrivateInput = (),
            PresignPublicInput = crate::ecdsa::presign::decentralized_party::PublicInput<
                group::Value<secp256k1::GroupElement>,
                CiphertextSpaceValue<
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                crate::class_groups::ProtocolPublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::GroupElement,
                >,
            >,
        >,
        P::DKGProtocol: dkg::Protocol<
            ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
        >,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<
                    group::Scalar<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
                >,
                group::PublicParameters<secp256k1::GroupElement>,
                group::Value<secp256k1::GroupElement>,
                CiphertextSpaceValue<
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
                ::class_groups::encryption_key::PublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::scalar::PublicParameters,
                >,
            >,
        >,
    {
        let description = format!(
            "{} {}",
            description,
            if is_universal {
                "Universal"
            } else {
                "Targeted"
            }
        );

        let (protocol_public_parameters, _) = setup_class_groups_secp256k1();

        let dkg_output = if is_universal {
            None
        } else {
            let (_, _, dkg_output) = mock_targeted_dkg_output::<
                { secp256k1::SCALAR_LIMBS },
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                Secp256k1EncryptionKey,
            >(&protocol_public_parameters);

            let crate::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(
                dkg_output,
            ) = dkg_output
            else {
                panic!("mock_targeted_dkg_output() should mock targeted public DKG outputs only")
            };

            Some(dkg_output)
        };

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone()).unwrap();
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let protocol_public_parameters = Arc::new(protocol_public_parameters);

        let public_inputs: HashMap<PartyID, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| {
                (
                    party_id,
                    crate::ecdsa::presign::decentralized_party::PublicInput {
                        protocol_public_parameters: protocol_public_parameters.clone(),
                        dkg_output: dkg_output.clone(),
                    },
                )
            })
            .collect();

        let private_inputs: HashMap<_, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        generates_presignatures_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            private_inputs,
            number_of_rounds,
            HashMap::new(),
            description,
        );
    }

    #[allow(dead_code)]
    pub fn generates_presignatures_internal<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        P,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: WeightedThresholdAccessStructure,
        presign_public_inputs: HashMap<PartyID, P::PresignPublicInput>,
        private_inputs: HashMap<PartyID, P::PresignPrivateInput>,
        number_of_rounds: usize,
        parties_by_round: HashMap<u64, HashSet<PartyID>>,
        description: String,
    ) -> (
        Vec<P::Presign>,
        HashMap<PartyID, <P::PresignParty as mpc::Party>::PrivateOutput>,
    )
    where
        P: Protocol,
        <P::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
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
    {
        let measurement = WallTime;
        let mut decentralized_party_total_time = Duration::ZERO;

        let (presign_time, times, presign_private_outputs, presigns) =
            asynchronous_session_terminates_successfully_internal_with_private_outputs::<
                P::PresignParty,
            >(
                session_id,
                &access_structure,
                private_inputs.clone(),
                presign_public_inputs.clone(),
                number_of_rounds,
                parties_by_round,
                false,
                false,
            );

        decentralized_party_total_time =
            measurement.add(&decentralized_party_total_time, &presign_time);

        let number_of_tangible_parties = access_structure.number_of_tangible_parties();
        let number_of_virtual_parties = access_structure.number_of_virtual_parties();
        let threshold = access_structure.threshold;

        // Print one column per round that actually ran — under `unsafe_mock` the party finalizes
        // in round one, so fewer rounds than `number_of_rounds` may have been recorded.
        let per_round_times = times
            .iter()
            .map(|time| time.as_millis().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let protocol_label = if number_of_rounds == 2 {
            "Universal Presign"
        } else {
            "Presign"
        };
        println!(
            "{description} {protocol_label}, {number_of_tangible_parties}, {number_of_virtual_parties}, {threshold}, {:?}, {per_round_times}",
            decentralized_party_total_time.as_millis(),
        );

        (presigns, presign_private_outputs)
    }

    pub(crate) fn mock_schnorr_presign<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        session_id: CommitmentSizedNumber,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            group::PublicParameters<GroupElement>,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    ) -> crate::schnorr::Presign<
        GroupElement::Value,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
    > {
        let encryption_key =
            EncryptionKey::new(&protocol_public_parameters.encryption_scheme_public_parameters)
                .unwrap();

        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let nonce_share_first_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let nonce_share_second_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let nonce_share_first_part_value: Uint<SCALAR_LIMBS> = nonce_share_first_part.into();
        let nonce_share_first_part_value =
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&nonce_share_first_part_value);
        let nonce_share_first_part_plaintext = EncryptionKey::PlaintextSpaceGroupElement::new(
            nonce_share_first_part_value.into(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )
        .unwrap();
        let (_, encryption_of_decentralized_party_nonce_share_first_part) = encryption_key
            .encrypt(
                &nonce_share_first_part_plaintext,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();

        let nonce_share_second_part_value: Uint<SCALAR_LIMBS> = nonce_share_second_part.into();
        let nonce_share_second_part_value =
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&nonce_share_second_part_value);
        let nonce_share_second_part_plaintext = EncryptionKey::PlaintextSpaceGroupElement::new(
            nonce_share_second_part_value.into(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )
        .unwrap();
        let (_, encryption_of_decentralized_party_nonce_share_second_part) = encryption_key
            .encrypt(
                &nonce_share_second_part_plaintext,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();

        let decentralized_party_nonce_public_share_first_part = nonce_share_first_part * generator;
        let decentralized_party_nonce_public_share_second_part =
            nonce_share_second_part * generator;

        let global_decentralized_party_output_commitment = protocol_public_parameters
            .global_decentralized_party_output_commitment()
            .unwrap();

        crate::schnorr::Presign {
            session_id,
            encryption_of_decentralized_party_nonce_share_first_part:
                encryption_of_decentralized_party_nonce_share_first_part.value(),
            encryption_of_decentralized_party_nonce_share_second_part:
                encryption_of_decentralized_party_nonce_share_second_part.value(),
            decentralized_party_nonce_public_share_first_part:
                decentralized_party_nonce_public_share_first_part.value(),
            decentralized_party_nonce_public_share_second_part:
                decentralized_party_nonce_public_share_second_part.value(),
            global_decentralized_party_output_commitment,
        }
    }

    pub(crate) fn mock_ecdsa_presign<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        session_id: CommitmentSizedNumber,
        dkg_output: crate::dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            group::PublicParameters<GroupElement>,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    ) -> crate::ecdsa::VersionedPresign<
        GroupElement::Value,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
    >
    where
        Uint<SCALAR_LIMBS>: Encoding,
    {
        let dkg_output = crate::dkg::decentralized_party::Output::from(dkg_output);

        let encryption_key =
            EncryptionKey::new(&protocol_public_parameters.encryption_scheme_public_parameters)
                .unwrap();

        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let mask = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let mask: Uint<SCALAR_LIMBS> = mask.into();

        let encryption_of_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            dkg_output.encryption_of_secret_key_share,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext_space_public_parameters = protocol_public_parameters
            .encryption_scheme_public_parameters
            .ciphertext_space_public_parameters();

        let encryption_of_masked_decentralized_party_key_share =
            encryption_of_secret_key_share.scale(&mask, ciphertext_space_public_parameters);

        let mask_value = Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&mask);
        let mask_plaintext = EncryptionKey::PlaintextSpaceGroupElement::new(
            mask_value.into(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )
        .unwrap();
        let (_, encryption_of_mask) = encryption_key
            .encrypt(
                &mask_plaintext,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();

        let nonce_share_first_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let nonce_share_second_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let encryption_of_masked_decentralized_party_nonce_share_first_part = encryption_of_mask
            .scale(
                &<GroupElement::Scalar as Into<Uint<SCALAR_LIMBS>>>::into(nonce_share_first_part),
                ciphertext_space_public_parameters,
            );
        let encryption_of_masked_decentralized_party_nonce_share_second_part = encryption_of_mask
            .scale(
                &<GroupElement::Scalar as Into<Uint<SCALAR_LIMBS>>>::into(nonce_share_second_part),
                ciphertext_space_public_parameters,
            );

        let decentralized_party_nonce_public_share_first_part = nonce_share_first_part * generator;
        let decentralized_party_nonce_public_share_second_part =
            nonce_share_second_part * generator;

        let targeted_presign = crate::ecdsa::Presign {
            session_id,
            encryption_of_mask: encryption_of_mask.value(),
            encryption_of_masked_decentralized_party_key_share:
                encryption_of_masked_decentralized_party_key_share.value(),
            encryption_of_masked_decentralized_party_nonce_share_first_part:
                encryption_of_masked_decentralized_party_nonce_share_first_part.value(),
            encryption_of_masked_decentralized_party_nonce_share_second_part:
                encryption_of_masked_decentralized_party_nonce_share_second_part.value(),
            decentralized_party_nonce_public_share_first_part:
                decentralized_party_nonce_public_share_first_part.value(),
            decentralized_party_nonce_public_share_second_part:
                decentralized_party_nonce_public_share_second_part.value(),
            public_key: dkg_output.public_key,
        };

        targeted_presign.into()
    }

    /// Deterministic version of `mock_ecdsa_presign` that uses a seeded RNG and returns
    /// the plaintext secrets (mask γ, nonce shares k_0, k_1) alongside the presign.
    pub(crate) fn mock_ecdsa_presign_deterministic<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        session_id: CommitmentSizedNumber,
        dkg_output: crate::dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            group::PublicParameters<GroupElement>,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
        rng: &mut impl group::CsRng,
    ) -> (
        crate::ecdsa::VersionedPresign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        GroupElement::Scalar, // mask (γ)
        GroupElement::Scalar, // nonce_share_first_part (k_0)
        GroupElement::Scalar, // nonce_share_second_part (k_1)
    )
    where
        Uint<SCALAR_LIMBS>: Encoding,
    {
        let dkg_output = crate::dkg::decentralized_party::Output::from(dkg_output);

        let encryption_key =
            EncryptionKey::new(&protocol_public_parameters.encryption_scheme_public_parameters)
                .unwrap();

        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let mask = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )
        .unwrap();

        let mask_uint: Uint<SCALAR_LIMBS> = mask.into();

        let encryption_of_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            dkg_output.encryption_of_secret_key_share,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext_space_public_parameters = protocol_public_parameters
            .encryption_scheme_public_parameters
            .ciphertext_space_public_parameters();

        let encryption_of_masked_decentralized_party_key_share =
            encryption_of_secret_key_share.scale(&mask_uint, ciphertext_space_public_parameters);

        let mask_plaintext_value = Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&mask_uint);
        let mask_plaintext = EncryptionKey::PlaintextSpaceGroupElement::new(
            mask_plaintext_value.into(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )
        .unwrap();
        let (_, encryption_of_mask) = encryption_key
            .encrypt(
                &mask_plaintext,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                true,
                rng,
            )
            .unwrap();

        let nonce_share_first_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )
        .unwrap();

        let nonce_share_second_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )
        .unwrap();

        let encryption_of_masked_decentralized_party_nonce_share_first_part = encryption_of_mask
            .scale(
                &<GroupElement::Scalar as Into<Uint<SCALAR_LIMBS>>>::into(nonce_share_first_part),
                ciphertext_space_public_parameters,
            );
        let encryption_of_masked_decentralized_party_nonce_share_second_part = encryption_of_mask
            .scale(
                &<GroupElement::Scalar as Into<Uint<SCALAR_LIMBS>>>::into(nonce_share_second_part),
                ciphertext_space_public_parameters,
            );

        let decentralized_party_nonce_public_share_first_part = nonce_share_first_part * generator;
        let decentralized_party_nonce_public_share_second_part =
            nonce_share_second_part * generator;

        let targeted_presign = crate::ecdsa::Presign {
            session_id,
            encryption_of_mask: encryption_of_mask.value(),
            encryption_of_masked_decentralized_party_key_share:
                encryption_of_masked_decentralized_party_key_share.value(),
            encryption_of_masked_decentralized_party_nonce_share_first_part:
                encryption_of_masked_decentralized_party_nonce_share_first_part.value(),
            encryption_of_masked_decentralized_party_nonce_share_second_part:
                encryption_of_masked_decentralized_party_nonce_share_second_part.value(),
            decentralized_party_nonce_public_share_first_part:
                decentralized_party_nonce_public_share_first_part.value(),
            decentralized_party_nonce_public_share_second_part:
                decentralized_party_nonce_public_share_second_part.value(),
            public_key: dkg_output.public_key,
        };

        (
            targeted_presign.into(),
            mask,
            nonce_share_first_part,
            nonce_share_second_part,
        )
    }
}

#[cfg(all(test, feature = "benchmarking"))]
mod benches {
    use group::OsCsRng;
    use mpc::WeightedThresholdAccessStructure;
    use std::collections::{HashMap, HashSet};

    #[test]
    #[ignore]
    #[allow(clippy::single_element_loop)]
    fn benchmark() {
        println!("\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Decentralized Party Total Time (ms), Decentralized Party First Round Time (ms), Decentralized Party Second Round Time (ms)", );

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_schnorr_presignatures_async_class_groups_secp256k1_internal::<
                crate::secp256k1::class_groups::TaprootProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                "Class Groups Asynchronous Schnorr secp256k1 (Taproot)",
            );
        }

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            let parties_by_round = HashMap::from([(1, (1..=67).collect::<HashSet<_>>())]);

            super::tests::generates_presignatures_async_class_groups_curve25519_internal::<
                crate::curve25519::class_groups::EdDSAProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight.clone(),
                parties_by_round,
                "Class Groups Asynchronous Schnorr curve25519 (EdDSA) [67 participating parties]",
            );

            let parties_by_round = HashMap::from([(1, (1..=75).collect::<HashSet<_>>())]);

            super::tests::generates_presignatures_async_class_groups_curve25519_internal::<
                crate::curve25519::class_groups::EdDSAProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight.clone(),
                parties_by_round,
                "Class Groups Asynchronous Schnorr curve25519 (EdDSA) [75 participating parties]",
            );

            let parties_by_round = HashMap::from([(1, (1..=97).collect::<HashSet<_>>())]);

            super::tests::generates_presignatures_async_class_groups_curve25519_internal::<
                crate::curve25519::class_groups::EdDSAProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight.clone(),
                parties_by_round,
                "Class Groups Asynchronous Schnorr curve25519 (EdDSA) [97 participating parties]",
            );
        }

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_presignatures_async_class_groups_ristretto_internal::<
                crate::ristretto::class_groups::SchnorrkelProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)",
            );
        }

        println!("\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Decentralized Party Total Time (ms), Decentralized Party First Round Time (ms), Decentralized Party Second Round Time (ms), Decentralized Party Third Round Time (ms), Decentralized Party Fourth Round Time (ms)", );

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_presignatures_async_class_groups_secp256k1_internal::<
                crate::secp256k1::class_groups::ECDSAProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                true,
                4, // ECDSA presign has 4 rounds
                "Class Groups Asynchronous ECDSA secp256k1",
            );
        }

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_presignatures_async_class_groups_secp256r1_internal::<
                crate::secp256r1::class_groups::ECDSAProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                true,
                "Class Groups Asynchronous ECDSA secp256r1",
            );
        }

        // VSS-based Schnorr presign benchmarks
        println!("\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Decentralized Party Total Time (ms), Decentralized Party First Round Time (ms), Decentralized Party Second Round Time (ms), Decentralized Party Third Round Time (ms)");

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_vss_presignatures_secp256k1_internal::<
                crate::secp256k1::vss::TaprootVSSProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                HashMap::new(),
                "VSS Asynchronous Schnorr secp256k1 (Taproot)",
            );
        }

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_vss_presignatures_curve25519_internal::<
                crate::curve25519::vss::EdDSAVSSProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                HashMap::new(),
                "VSS Asynchronous Schnorr curve25519 (EdDSA)",
            );
        }

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_vss_presignatures_ristretto_internal::<
                crate::ristretto::vss::SchnorrkelVSSProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                "VSS Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)",
            );
        }
    }
}
