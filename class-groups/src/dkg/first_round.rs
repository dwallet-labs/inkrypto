// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::collections::{HashMap, HashSet};

use crypto_bigint::{ConstChoice, Encoding, Int, Uint};

use commitment::CommitmentSizedNumber;
use group::helpers::{DeduplicateAndSort, FlatMapResults};
use group::{
    bounded_integers_group, bounded_natural_numbers_group, CsRng, GroupElement, PartyID,
    PrimeGroupElement, Samplable,
};
use mpc::{AsynchronousRoundResult, HandleInvalidMessages, WeightedThresholdAccessStructure};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::party::RoundResult;
use crate::dkg::{
    prove_equality_of_discrete_log, Message, Party, ProveEqualityOfDiscreteLog,
    ProveEqualityOfDiscreteLogMessage,
};
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeSetupParameters, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{BaseProtocolContext, DealtSecretShare};
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
    pub(in crate::dkg) fn advance_first_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        knowledge_of_discrete_log_base_protocol_context: BaseProtocolContext,
        setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        setup_parameters: &SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        pvss_party: &publicly_verifiable_secret_sharing::Party<
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
        // Safe to sample positive as long as $g^{s}$ is statistically indistinguishable from a random element.
        // This is indeed the case for any uniform distribution from $\mathbb{Z}\cap (a, b)$ where $\log_{2}(|b-a|)$ is large enough.
        let decryption_key_contribution = bounded_natural_numbers_group::GroupElement::sample(
            setup_parameters.decryption_key_group_public_parameters(),
            rng,
        )?;

        let decryption_key_contribution =
            Int::new_from_abs_sign(decryption_key_contribution.value(), ConstChoice::FALSE)
                .unwrap();

        let preverified_parties = HashSet::default();
        let (malicious_parties, deal_secret_message) = pvss_party
            .deal_and_encrypt_shares_to_valid_encryption_key_holders(
                None,
                decryption_key_contribution,
                preverified_parties,
                true,
                rng,
            )?;

        // Generating Public Keys for Threshold Encryptions:
        //
        // Each party $i$ samples a secret key contribution $s_{i}\gets \mathcal{D}$
        // and generates public key distribution $\textsf{pk}_{Q'_{m'}}^{i}= h_{Q'\_{m'}}^{s_{i}}$
        // for the re-configuration threshold encryptions ($m' \in [1,M']$ and $\textsf{pk}_{q}^{i}=h_{q}^{s_{i}}$
        // the public key contribution to the public key of the threshold encryption used for sign, i.e. with order of the elliptic curve.
        //
        // The parties prove that the discrete log of all public key contributions are equal
        // via M' equalities of discrete log proofs $\pi_{\textsf{EncDL},Q'_{m'}}^{i}$ between $(h_{q},h_{Q'_{m'},\textsf{pk}_{q},\textsf{pk}_{Q'_{m'};s)$.
        let discrete_log_public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound(
                setup_parameters.decryption_key_bits(),
            )?;

        let decryption_key_contribution = bounded_integers_group::GroupElement::new(
            decryption_key_contribution,
            &discrete_log_public_parameters,
        )?;

        let share_threshold_encryption_key_message = prove_equality_of_discrete_log::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >(
            tangible_party_id,
            None,
            session_id,
            knowledge_of_discrete_log_base_protocol_context,
            discrete_log_public_parameters,
            decryption_key_contribution,
            setup_parameters_per_crt_prime,
            setup_parameters,
            setup_parameters.decryption_key_bits(),
            rng,
        )?;

        Ok(AsynchronousRoundResult::Advance {
            malicious_parties,
            message: Message::DealDecryptionKeyContribution(
                deal_secret_message,
                ProveEqualityOfDiscreteLogMessage(share_threshold_encryption_key_message),
            ),
        })
    }

    #[allow(clippy::type_complexity)]
    pub(in crate::dkg) fn handle_first_round_messages(
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
        reconstruct_all: bool,
    ) -> Result<(
        Vec<PartyID>,
        HashSet<PartyID>,
        HashMap<
            PartyID,
            HashMap<Option<PartyID>, Vec<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        >,
        HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShare<
                            NUM_SECRET_SHARE_PRIMES,
                            SECRET_KEY_SHARE_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
        HashMap<
            PartyID,
            ProveEqualityOfDiscreteLog<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    )> {
        // Make sure everyone sent the first round message - $(\{\textsf{ct}^{i,j}_{\textsf{Share}}\}_{i\in[n]},\{C_{\textsf{Share}^{i,\ell}}\}_{\ell\in[t]},\pi_{\Share}^{i},\{\textsf{pk}^{i}_{Q'_{m'}},\pi^{EqDL,i}_{Q'_{m'}}\}_{1,M'})$.
        // Note that the proof $\pi_{\Share}^{i}$ includes many proofs for each share. The terminology remains as it can be viewed as a single proof of correctness of all shares. A different instantiation for a PVSS scheme could switch to generate a single batched proof for all shares. The downside is that then parties that verify their shares cannot be exploited to boost the verification process.
        let (
            parties_sending_invalid_deal_secret_messages,
            deal_decryption_key_contribution_messages,
        ) = deal_decryption_key_contribution_messages
            .into_iter()
            .map(|(dealer_party_id, message)| {
                let res = match message {
                    Message::DealDecryptionKeyContribution(
                        deal_secret_message,
                        share_threshold_encryption_key_message,
                    ) => Ok((
                        HashMap::from([(None, deal_secret_message)]),
                        share_threshold_encryption_key_message,
                    )),
                    _ => Err(Error::InvalidParameters),
                };

                (dealer_party_id, res)
            })
            .handle_invalid_messages_async();

        let (deal_decryption_key_contribution_messages, share_threshold_encryption_key_messages): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = deal_decryption_key_contribution_messages
            .into_iter()
            .map(
                |(
                    dealer_party_id,
                    (deal_secret_message, share_threshold_encryption_key_message),
                )| {
                    (
                        (dealer_party_id, deal_secret_message),
                        (dealer_party_id, share_threshold_encryption_key_message),
                    )
                },
            )
            .unzip();

        let (
            parties_sending_invalid_share_threshold_encryption_key_messages,
            threshold_encryption_key_shares_and_proofs,
        ) = share_threshold_encryption_key_messages
            .into_iter()
            .map(
                |(dealer_party_id, share_threshold_encryption_key_message)| {
                    let share_threshold_encryption_key = array::from_fn(|i| {
                        let (proof, encryption_key_contribution) =
                            share_threshold_encryption_key_message.0[i].clone();

                        EquivalenceClass::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                            encryption_key_contribution,
                            setup_parameters_per_crt_prime[i].equivalence_class_public_parameters(),
                        )
                        .map(|encryption_key_contribution| (proof, encryption_key_contribution))
                    })
                    .flat_map_results();

                    (dealer_party_id, share_threshold_encryption_key)
                },
            )
            .handle_invalid_messages_async();

        let (
            first_round_malicious_parties,
            parties_that_were_dealt_shares,
            coefficients_contribution_commitments,
            encryptions_of_shares_and_proofs,
        ) = pvss_party.handle_deal_secret_messages(deal_decryption_key_contribution_messages)?;

        let virtual_subset = if reconstruct_all {
            access_structure.virtual_subset(parties_that_were_dealt_shares.clone())?
        } else {
            access_structure.virtual_subset(HashSet::from([tangible_party_id]))?
        };

        let reconstructed_commitments_to_sharing = pvss_party.reconstruct_commitment_to_sharing(
            coefficients_contribution_commitments.clone(),
            virtual_subset,
        );

        let first_round_malicious_parties: Vec<_> = parties_sending_invalid_deal_secret_messages
            .into_iter()
            .chain(parties_sending_invalid_share_threshold_encryption_key_messages)
            .chain(first_round_malicious_parties)
            .deduplicate_and_sort();

        Ok((
            first_round_malicious_parties,
            parties_that_were_dealt_shares,
            coefficients_contribution_commitments,
            reconstructed_commitments_to_sharing,
            encryptions_of_shares_and_proofs,
            threshold_encryption_key_shares_and_proofs,
        ))
    }
}
