// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crate::dkg;
use mpc::AsynchronouslyAdvanceable;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// An instantiation of the 2PC-MPC Presign protocol.
pub trait Protocol: dkg::Protocol {
    /// The Presign protocol's output.
    type Presign: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq;

    /// The public input of the (decentralized party's) Presign protocol.
    type PresignPublicInput: AsRef<Self::ProtocolPublicParameters>
        + From<(
            Self::ProtocolPublicParameters,
            Option<Self::DecentralizedPartyTargetedDKGOutput>,
        )> + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The party of the (decentralized party's) Presign protocol.
    type PresignParty: mpc::Party<
            PublicInput = Self::PresignPublicInput,
            PublicOutput = Self::Presign,
            PublicOutputValue = Self::Presign,
        > + AsynchronouslyAdvanceable<PrivateInput = ()>
        + Send
        + Sync;
}

#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
#[allow(dead_code)]
pub(crate) mod tests {
    use std::collections::HashMap;
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
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;
    use mpc::{Weight, WeightedThresholdAccessStructure};
    use rand::prelude::IteratorRandom;
    use rstest::rstest;

    use crate::dkg::tests::mock_targeted_dkg_output;
    use crate::ecdsa::presign::decentralized_party::PublicInput;
    use crate::test_helpers::{
        setup_class_groups_curve25519, setup_class_groups_ristretto, setup_class_groups_secp256k1,
        setup_class_groups_secp256r1,
    };
    use crate::ProtocolPublicParameters;

    use super::*;

    fn setup_presign<
        GroupElementValue: Clone,
        CiphertextSpaceValue: Clone,
        ProtocolPublicParameters: Clone,
        PublicInput: From<(
            ProtocolPublicParameters,
            Option<dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>>,
        )>,
    >(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        protocol_public_parameters: ProtocolPublicParameters,
        dkg_output: Option<
            dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>,
        >,
    ) -> (
        CommitmentSizedNumber,
        WeightedThresholdAccessStructure,
        HashMap<PartyID, PublicInput>,
    ) {
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();
        let parties: Vec<PartyID> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .collect();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        let public_inputs = parties
            .iter()
            .map(|&party_id| {
                (
                    party_id,
                    PublicInput::from((protocol_public_parameters.clone(), dkg_output.clone())),
                )
            })
            .collect();

        (session_id, access_structure, public_inputs)
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
        P::ProtocolPublicParameters: AsRef<
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

        let (session_id, access_structure, public_inputs) = setup_presign(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
            dkg_output,
        );

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
            description.to_string(),
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
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)",
        )
    }

    pub(crate) fn generates_presignatures_async_class_groups_curve25519_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        description: &str,
    ) where
        P: Protocol<
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
        P::ProtocolPublicParameters: AsRef<
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

        let (session_id, access_structure, public_inputs) = setup_presign(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
            None,
        );

        generates_presignatures_internal::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
            P,
        >(
            session_id,
            access_structure,
            public_inputs,
            description.to_string(),
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn generates_schnorr_presignatures_async_class_groups_ristretto(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_presignatures_async_class_groups_ristretto_internal::<
            crate::ristretto::class_groups::SchnorrkelSubstrateProtocol,
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
        P::ProtocolPublicParameters: AsRef<
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

        let (session_id, access_structure, public_inputs) = setup_presign(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
            None,
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
        generates_presignatures_async_class_groups_secp256k1_internal::<
            crate::secp256k1::class_groups::TaprootProtocol,
        >(
            threshold,
            party_to_weight,
            true,
            "Class Groups Asynchronous Schnorr secp256k1",
        )
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
            "Class Groups Asynchronous ECDSA secp256k1",
        )
    }

    pub(crate) fn generates_presignatures_async_class_groups_secp256k1_internal<P>(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        is_universal: bool,
        description: &str,
    ) where
        P: Protocol<
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
        P::ProtocolPublicParameters: AsRef<
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

        let (session_id, access_structure, public_inputs) = setup_presign(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
            dkg_output,
        );

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
            description.to_string(),
        );
    }

    #[allow(dead_code)]
    pub fn generates_presignatures_internal<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        P,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: WeightedThresholdAccessStructure,
        presign_public_inputs: HashMap<PartyID, P::PresignPublicInput>,
        description: String,
    ) -> P::Presign
    where
        P: Protocol,
        P::ProtocolPublicParameters: AsRef<
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

        let parties: Vec<PartyID> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .collect();
        let private_inputs: HashMap<_, _> = parties
            .iter()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        let number_of_rounds = if description.contains("Schnorr") {
            2
        } else {
            4
        };
        let (presign_time, times, presign) =
            asynchronous_session_terminates_successfully_internal::<P::PresignParty>(
                session_id,
                &access_structure,
                private_inputs.clone(),
                presign_public_inputs.clone(),
                number_of_rounds,
                HashMap::new(),
                false,
                false,
            );

        decentralized_party_total_time =
            measurement.add(&decentralized_party_total_time, &presign_time);

        let number_of_tangible_parties = access_structure.number_of_tangible_parties();
        let number_of_virtual_parties = access_structure.number_of_virtual_parties();
        let threshold = access_structure.threshold;

        if number_of_rounds == 2 {
            println!(
                "{description} Presign, {number_of_tangible_parties}, {number_of_virtual_parties}, {threshold}, {:?}, {:?}, {:?}",
                decentralized_party_total_time.as_millis(),
                times[0].as_millis(),
                times[1].as_millis(),
            );
        } else {
            println!(
                "{description} Presign, {number_of_tangible_parties}, {number_of_virtual_parties}, {threshold}, {:?}, {:?}, {:?}, {:?}, {:?}",
                decentralized_party_total_time.as_millis(),
                times[0].as_millis(),
                times[1].as_millis(),
                times[2].as_millis(),
                times[3].as_millis(),
            );
        }

        presign
    }

    pub(crate) fn mock_schnorr_presign<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
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
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
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

        let encryption_of_masked_decentralized_party_key_share =
            encryption_of_secret_key_share.scale(&mask);

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
            .scale(&<GroupElement::Scalar as Into<Uint<SCALAR_LIMBS>>>::into(
                nonce_share_first_part,
            ));
        let encryption_of_masked_decentralized_party_nonce_share_second_part = encryption_of_mask
            .scale(&<GroupElement::Scalar as Into<Uint<SCALAR_LIMBS>>>::into(
                nonce_share_second_part,
            ));

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
}

#[cfg(all(test, feature = "benchmarking"))]
mod benches {
    use group::OsCsRng;
    use mpc::WeightedThresholdAccessStructure;

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

            super::tests::generates_presignatures_async_class_groups_secp256k1_internal::<
                crate::secp256k1::class_groups::TaprootProtocol,
            >(
                access_structure.threshold,
                access_structure.party_to_weight,
                true,
                "Class Groups Asynchronous Schnorr secp256k1 (Taproot)",
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
                "Class Groups Asynchronous ECDSA secp256k1",
            );
        }
    }
}
