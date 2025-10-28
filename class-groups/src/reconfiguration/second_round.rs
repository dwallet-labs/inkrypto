// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};

use group::{CsRng, PartyID, PrimeGroupElement};
use mpc::{AsynchronousRoundResult, HandleInvalidMessages};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use crate::reconfiguration::party::RoundResult;
use crate::reconfiguration::{Message, Party, PublicInput};
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    GroupElement::Scalar: Default,
{
    pub(crate) fn advance_second_round(
        tangible_party_id: PartyID,
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        deal_randomizer_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        rng: &mut impl CsRng,
    ) -> Result<
        RoundResult<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    > {
        let (malicious_parties, verified_dealers_to_upcoming) =
            Self::advance_second_round_internal(
                tangible_party_id,
                public_input,
                deal_randomizer_messages,
                randomizer_contribution_to_upcoming_pvss_party,
                rng,
            )?;

        Ok(AsynchronousRoundResult::Advance {
            malicious_parties,
            message: Message::VerifiedRandomizerDealers(verified_dealers_to_upcoming),
        })
    }

    pub fn advance_second_round_internal(
        tangible_party_id: PartyID,
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        deal_randomizer_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Option<HashSet<PartyID>>)> {
        let (
            first_round_malicious_parties,
            _,
            _,
            reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming,
            encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming,
            _,
        ) = Self::handle_first_round_messages(
            tangible_party_id,
            public_input,
            deal_randomizer_messages.clone(),
            randomizer_contribution_to_upcoming_pvss_party,
            false,
        )?;

        let verified_dealers_to_upcoming = randomizer_contribution_to_upcoming_pvss_party
            .verify_dealt_shares(
                encryptions_of_randomizer_contribution_shares_and_proofs_to_upcoming,
                reconstructed_commitments_to_randomizer_contribution_sharing_to_upcoming,
                rng,
            )?;

        // We don't report those that sent invalid shares, because for consistency they will be validated in the next round.
        Ok((first_round_malicious_parties, verified_dealers_to_upcoming))
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn handle_second_round_messages(
        public_input: &PublicInput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        verified_dealers_messages: HashMap<
            PartyID,
            Message<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    ) -> Result<(Vec<PartyID>, HashMap<PartyID, HashSet<PartyID>>)> {
        // Make sure everyone sent the second round message.
        // This yields a mapping `PartyID -> HashSet<PartyID>` of parties that self-reportedly verified their shares from the set of parties.
        let (second_round_malicious_parties, verified_dealers_to_upcoming) =
            verified_dealers_messages
                .into_iter()
                .map(|(dealer_tangible_party_id, message)| {
                    let res = match message {
                        Message::VerifiedRandomizerDealers(verified_dealers_to_upcoming) => {
                            // Verify that one only verified dealers if they are also an upcoming party, and therefore were dealt shares.
                            if public_input
                                .current_tangible_party_id_to_upcoming
                                .get(&dealer_tangible_party_id)
                                .unwrap_or(&None)
                                .is_some()
                            {
                                if verified_dealers_to_upcoming.is_some() {
                                    Ok(verified_dealers_to_upcoming)
                                } else {
                                    Err(Error::InvalidMessage)
                                }
                            } else if verified_dealers_to_upcoming.is_none() {
                                Ok(verified_dealers_to_upcoming)
                            } else {
                                Err(Error::InvalidMessage)
                            }
                        }
                        _ => Err(Error::InvalidParameters),
                    };

                    (dealer_tangible_party_id, res)
                })
                .handle_invalid_messages_async();

        // Map the dealer (current) party IDs to participating (upcoming) party IDs.
        // This is because `finalize_sharing()` skips proofs of verified dealers,
        // but the proofs are sent to upcoming parties and not current ones.
        let verified_dealers_to_upcoming: HashMap<_, _> = verified_dealers_to_upcoming
            .into_iter()
            .flat_map(|(dealer_tangible_party_id, verified_dealers_to_upcoming)| {
                // This maps dealer -> participating party ID. while keeping the verified dealers.
                public_input
                    .current_tangible_party_id_to_upcoming
                    .get(&dealer_tangible_party_id)
                    .unwrap_or(&None)
                    .zip(verified_dealers_to_upcoming)
            })
            .collect();

        Ok((second_round_malicious_parties, verified_dealers_to_upcoming))
    }
}
