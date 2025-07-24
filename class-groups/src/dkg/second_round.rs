// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};

use group::{CsRng, PartyID, PrimeGroupElement};
use mpc::{AsynchronousRoundResult, HandleInvalidMessages, WeightedThresholdAccessStructure};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::party::RoundResult;
use crate::dkg::{Message, Party};
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeSetupParameters, MAX_PRIMES, NUM_SECRET_SHARE_PRIMES,
};
use crate::setup::DeriveFromPlaintextPublicParameters;
use crate::setup::SetupParameters;
use crate::{
    equivalence_class, publicly_verifiable_secret_sharing, CompactIbqf, EquivalenceClass, Error,
    Result, SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    Party<
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
    pub(in crate::dkg) fn advance_second_round(
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_decryption_key_contribution_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<
        RoundResult<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    > {
        let (
            first_round_malicious_parties,
            _,
            _,
            reconstructed_commitments_to_sharing,
            encryptions_of_shares_and_proofs,
            _,
        ) = Self::handle_first_round_messages(
            tangible_party_id,
            access_structure,
            setup_parameters_per_crt_prime,
            pvss_party,
            deal_decryption_key_contribution_messages.clone(),
            false,
        )?;

        let verified_dealers = pvss_party
            .verify_dealt_shares(
                encryptions_of_shares_and_proofs,
                reconstructed_commitments_to_sharing,
                rng,
            )?
            .ok_or(Error::InternalError)?;

        // We don't report those that sent invalid shares, because for consistency they will be validated in the next round regardless.
        Ok(AsynchronousRoundResult::Advance {
            malicious_parties: first_round_malicious_parties,
            message: Message::VerifiedDealers(verified_dealers),
        })
    }

    #[allow(clippy::type_complexity)]
    pub(in crate::dkg) fn handle_second_round_messages(
        verified_dealers_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    ) -> Result<(Vec<PartyID>, HashMap<PartyID, HashSet<PartyID>>)> {
        // Make sure everyone sent the second round message - weather or not they recieved a valid share.
        // This yields a mapping `PartyID -> HashSet<PartyID>` of parties that self-reportedly verified their shares from the set of parties.
        let (second_round_malicious_parties, verified_dealers) = verified_dealers_messages
            .clone()
            .into_iter()
            .map(|(party_id, message)| {
                let res = match message {
                    Message::VerifiedDealers(verified_dealers) => Ok(verified_dealers),
                    _ => Err(Error::InvalidParameters),
                };

                (party_id, res)
            })
            .handle_invalid_messages_async();

        Ok((second_round_malicious_parties, verified_dealers))
    }
}
