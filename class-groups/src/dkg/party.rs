// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use crypto_bigint::{Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement, PartyID, PrimeGroupElement};
use mpc::secret_sharing::shamir::over_the_integers::secret_key_share_size_upper_bound;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use crate::accelerator::MultiFoldNupowAccelerator;
pub use crate::dkg::public_output::PublicOutput;
use crate::dkg::{Message, PublicInput};
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES, NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::BaseProtocolContext;
use crate::setup::DeriveFromPlaintextPublicParameters;
use crate::setup::SetupParameters;
use crate::{
    equivalence_class, publicly_verifiable_secret_sharing, CompactIbqf, EquivalenceClass, Error,
    Result,
};
use crate::{SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS};

pub type RoundResult<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = AsynchronousRoundResult<
    Message<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    (),
    PublicOutput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
>;

/// The Distributed Key Generation (DKG) party,
/// used to generate a distributed class-groups decryption key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(PhantomData<GroupElement>);

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > mpc::Party
    for Party<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

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
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: DeriveFromPlaintextPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
{
    type Error = Error;
    type PublicInput = PublicInput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = PublicOutput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >;
    type PublicOutput = Self::PublicOutputValue;
    type Message = Message<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >;
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > AsynchronouslyAdvanceable
    for Party<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

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
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: DeriveFromPlaintextPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    GroupElement::Scalar: Default,
{
    type PrivateInput = [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES];

    fn advance(
        session_id: CommitmentSizedNumber,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        decryption_key_per_crt_prime: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>>
    {
        let decryption_key_per_crt_prime =
            decryption_key_per_crt_prime.ok_or(Error::InvalidParameters)?;

        let setup_parameters =
            SetupParameters::derive_from_plaintext_parameters::<GroupElement::Scalar>(
                public_input.plaintext_space_public_parameters.clone(),
                public_input.computational_security_parameter,
            )?;

        let decryption_key_bits = setup_parameters.decryption_key_bits();
        let decryption_key_share_bits = secret_key_share_size_upper_bound(
            u32::from(access_structure.number_of_virtual_parties()),
            u32::from(access_structure.threshold),
            decryption_key_bits,
        );

        let knowledge_of_discrete_log_base_protocol_context = BaseProtocolContext {
            protocol_name: "Class Groups Distributed Key Generation (DKG)".to_string(),
            round: 1,
            proof_name: "Proof of Valid Threshold Encryption Key".to_string(),
        };

        let base_protocol_context = BaseProtocolContext {
            protocol_name: "Class Groups Distributed Key Generation (DKG)".to_string(),
            round: 1,
            proof_name: "Proof of valid shamir secret sharing over the integers of decryption key contribution share".to_string(),
        };

        // In the DKG, dealers deal shares to themselves, i.e. the participating parties are the same as the dealers.
        let pvss_party = publicly_verifiable_secret_sharing::Party::<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::new(
            session_id,
            tangible_party_id,
            Some(tangible_party_id),
            access_structure.clone(),
            access_structure.clone(),
            public_input.setup_parameters.clone(),
            public_input.setup_parameters_per_crt_prime.clone(),
            public_input
                .encryption_key_values_and_proofs_per_crt_prime
                .clone(),
            base_protocol_context,
            public_input.setup_parameters.h.value(),
            decryption_key_bits,
            decryption_key_share_bits,
            true,
        )?;

        let encryption_of_decryption_key_base_protocol_context = BaseProtocolContext {
            protocol_name: "Class Groups Distributed Key Generation (DKG)".to_string(),
            round: 3,
            proof_name: "Proof of encryption of decryption key share to threshold encryption key"
                .to_string(),
        };

        match &messages[..] {
            [] => Self::advance_first_round(
                tangible_party_id,
                session_id,
                knowledge_of_discrete_log_base_protocol_context,
                &public_input.setup_parameters_per_crt_prime,
                &public_input.setup_parameters,
                &pvss_party,
                rng,
            ),
            [deal_decryption_key_contribution_messages] => Self::advance_second_round(
                tangible_party_id,
                access_structure,
                &public_input.setup_parameters_per_crt_prime,
                &pvss_party,
                deal_decryption_key_contribution_messages.clone(),
                rng,
            ),
            [deal_decryption_key_contribution_messages, verified_dealers_messages] => {
                Self::advance_third_round(
                    tangible_party_id,
                    session_id,
                    knowledge_of_discrete_log_base_protocol_context,
                    encryption_of_decryption_key_base_protocol_context,
                    access_structure,
                    public_input,
                    &pvss_party,
                    deal_decryption_key_contribution_messages.clone(),
                    verified_dealers_messages.clone(),
                    decryption_key_per_crt_prime,
                    decryption_key_share_bits,
                    rng,
                )
            }
            [deal_decryption_key_contribution_messages, _, encrypt_decryption_key_shares_messages] =>
            {
                let malicious_third_round_parties = malicious_parties_by_round
                    .get(&3)
                    .ok_or(Error::InvalidParameters)?
                    .clone();

                Self::advance_fourth_round(
                    tangible_party_id,
                    session_id,
                    encryption_of_decryption_key_base_protocol_context,
                    access_structure,
                    public_input,
                    &pvss_party,
                    deal_decryption_key_contribution_messages.clone(),
                    encrypt_decryption_key_shares_messages.clone(),
                    malicious_third_round_parties,
                    decryption_key_share_bits,
                    rng,
                )
            }
            _ => Err(Error::InvalidParameters),
        }
    }

    fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
        match failed_round {
            3 => Some(1),
            4 => Some(3),
            _ => None,
        }
    }
}
