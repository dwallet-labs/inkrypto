// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{direct_product, self_product, PrimeGroupElement};

use mpc::AsynchronouslyAdvanceable;

use crate::dkg;

pub mod decentralized_party;

#[cfg(feature = "class_groups")]
pub mod class_groups;

#[cfg(feature = "paillier")]
pub mod paillier;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presign<GroupElementValue, CiphertextValue> {
    // The session ID of the Presign protocol $sid$ to be used in the corresponding Sign session.
    pub(crate) session_id: CommitmentSizedNumber,
    // $ \textst{ct}_\gamma $
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
        }
    }
}

/// An instantiation of the 2PC-MPC Presign protocol.
pub trait Protocol: dkg::Protocol {
    /// The Presign protocol's output.
    type Presign: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq;

    /// The public input of the (decentralized party's) Presign protocol.
    type PresignPublicInput: AsRef<Self::ProtocolPublicParameters>
        + From<(
            Self::ProtocolPublicParameters,
            Self::DecentralizedPartyDKGOutput,
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

#[cfg(all(
    any(test, feature = "benchmarking"),
    feature = "secp256k1",
    feature = "paillier",
    feature = "bulletproofs",
))]
#[allow(unused_imports)]
#[allow(dead_code)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::{Random, Uint};
    use rand::prelude::IteratorRandom;
    use rand_core::OsRng;
    use rstest::rstest;

    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, GroupElement as _, PartyID, Samplable};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };
    use maurer::encryption_of_discrete_log::StatementAccessors;
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;
    use mpc::{Weight, WeightedThresholdAccessStructure};

    use crate::dkg::tests::mock_dkg_output;
    use crate::paillier::EncryptionKey;
    use crate::presign::decentralized_party::PublicInput;
    use crate::test_helpers::{setup_class_groups_secp256k1, setup_paillier_secp256k1};
    use crate::ProtocolPublicParameters;

    use super::*;

    fn setup_encryption_of_mask_and_masked_key_share_round<
        GroupElementValue: Clone,
        CiphertextSpaceValue: Clone,
        ProtocolPublicParameters: Clone,
    >(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        protocol_public_parameters: ProtocolPublicParameters,
        dkg_output: dkg::decentralized_party::Output<GroupElementValue, CiphertextSpaceValue>,
    ) -> (
        CommitmentSizedNumber,
        WeightedThresholdAccessStructure,
        HashMap<
            PartyID,
            PublicInput<GroupElementValue, CiphertextSpaceValue, ProtocolPublicParameters>,
        >,
    ) {
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();
        let parties: Vec<PartyID> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .collect();

        let session_id = CommitmentSizedNumber::random(&mut OsRng);

        let encryption_of_mask_and_masked_key_share_round_public_inputs = parties
            .iter()
            .map(|&party_id| {
                (
                    party_id,
                    PublicInput {
                        protocol_public_parameters: protocol_public_parameters.clone(),
                        dkg_output: dkg_output.clone(),
                    },
                )
            })
            .collect();

        (
            session_id,
            access_structure,
            encryption_of_mask_and_masked_key_share_round_public_inputs,
        )
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    #[cfg(feature = "class_groups")]
    fn generates_presignatures_async_class_groups_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_presignatures_async_class_groups_secp256k1_internal(threshold, party_to_weight)
    }

    #[cfg(feature = "class_groups")]
    pub(crate) fn generates_presignatures_async_class_groups_secp256k1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let (protocol_public_parameters, _) = setup_class_groups_secp256k1();

        let (_, _, dkg_output) = mock_dkg_output::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            ::class_groups::EncryptionKey<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
        >(&protocol_public_parameters);

        let (
            session_id,
            access_structure,
            encryption_of_mask_and_masked_key_share_round_public_inputs,
        ) = setup_encryption_of_mask_and_masked_key_share_round(
            threshold,
            party_to_weight.clone(),
            protocol_public_parameters,
            dkg_output,
        );

        generates_presignatures_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            ::class_groups::EncryptionKey<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            crate::secp256k1::class_groups::AsyncProtocol,
        >(
            session_id,
            access_structure,
            encryption_of_mask_and_masked_key_share_round_public_inputs,
            "Class Groups Asynchronous secp256k1".to_string(),
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    fn generates_presignatures_async_paillier_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_presignatures_async_paillier_secp256k1_internal(threshold, party_to_weight)
    }

    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    pub(crate) fn generates_presignatures_async_paillier_secp256k1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let (paillier_protocol_public_parameters, _) = setup_paillier_secp256k1();

        let (_, _, dkg_output) =
            mock_dkg_output::<
                { secp256k1::SCALAR_LIMBS },
                { crate::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
                secp256k1::GroupElement,
                EncryptionKey,
            >(&paillier_protocol_public_parameters.protocol_public_parameters);

        let (
            session_id,
            access_structure,
            encryption_of_mask_and_masked_key_share_round_public_inputs,
        ) = setup_encryption_of_mask_and_masked_key_share_round(
            threshold,
            party_to_weight.clone(),
            paillier_protocol_public_parameters,
            dkg_output,
        );

        generates_presignatures_internal::<
            { secp256k1::SCALAR_LIMBS },
            { crate::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            crate::secp256k1::paillier::bulletproofs::AsyncProtocol,
        >(
            session_id,
            access_structure,
            encryption_of_mask_and_masked_key_share_round_public_inputs,
            "Paillier Asynchronous secp256k1".to_string(),
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
        P: Protocol<
            Presign = Presign<
                GroupElement::Value,
                group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            >,
        >,
        P::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
                group::PublicParameters<GroupElement>,
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

        let (presign_time, _, presign) =
            asynchronous_session_terminates_successfully_internal::<P::PresignParty>(
                session_id,
                &access_structure,
                private_inputs.clone(),
                presign_public_inputs.clone(),
                4,
                HashMap::new(),
                false,
                false,
            );

        decentralized_party_total_time =
            measurement.add(&decentralized_party_total_time, &presign_time);

        let number_of_tangible_parties = access_structure.number_of_tangible_parties();
        let number_of_virtual_parties = access_structure.number_of_virtual_parties();
        let threshold = access_structure.threshold;

        println!(
            "{description} Presign, {number_of_tangible_parties}, {number_of_virtual_parties}, {threshold}, {:?}",
            decentralized_party_total_time.as_millis()
        );

        presign
    }

    pub(crate) fn mock_presign<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        session_id: CommitmentSizedNumber,
        dkg_output: crate::dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            group::PublicParameters<GroupElement>,
            EncryptionKey::PublicParameters,
        >,
    ) -> Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>
    {
        let encryption_key =
            EncryptionKey::new(&protocol_public_parameters.encryption_scheme_public_parameters)
                .unwrap();

        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let mask = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
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
                &mut OsRng,
            )
            .unwrap();

        let nonce_share_first_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        let nonce_share_second_part = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsRng,
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

        Presign {
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
        }
    }
}

#[cfg(all(test, feature = "benchmarking"))]
mod benches {
    use rand_core::OsRng;

    use mpc::WeightedThresholdAccessStructure;

    #[test]
    #[ignore]
    fn benchmark() {
        println!("\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Decentralized Party Total Time (ms)", );

        for (threshold, number_of_tangible_parties, total_weight) in
            [(10, 5, 15), (20, 10, 30), (67, 50, 100), (67, 100, 100)]
        {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsRng,
            )
            .unwrap();

            super::tests::generates_presignatures_async_paillier_secp256k1_internal(
                access_structure.threshold,
                access_structure.party_to_weight.clone(),
            );
            super::tests::generates_presignatures_async_class_groups_secp256k1_internal(
                access_structure.threshold,
                access_structure.party_to_weight,
            );
        }
    }
}
