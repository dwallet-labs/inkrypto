// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};

use crypto_bigint::subtle::{Choice, CtOption};
use crypto_bigint::{Concat, Encoding, Int, InvertMod, NonZero, Split, Uint};
#[cfg(feature = "parallel")]
use rayon::iter::IntoParallelIterator;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use group::helpers::{DeduplicateAndSort, TryCollectHashMap};
use group::{self_product, CsRng, GroupElement as _, PartyID, PrimeGroupElement};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use mpc::secret_sharing::shamir;
use mpc::secret_sharing::shamir::over_the_integers::{
    identify_malicious_semi_honest_decrypters, interpolate_decryption_shares,
    secret_key_share_size_upper_bound, AdjustedLagrangeCoefficientSizedNumber,
    BinomialCoefficientSizedNumber, FactorialSizedNumber, PrecomputedValues, MAX_PLAYERS,
    MAX_THRESHOLD,
};
use mpc::HandleInvalidMessages;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::decryption_key::{DecryptionKey, DiscreteLogInF};
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::ibqf::compact::CompactIbqf;
use crate::{encryption_key, Error, SecretKeyShareSizedInteger, SECRET_KEY_SHARE_WITNESS_LIMBS};
use crate::{equivalence_class, Result};
use crate::{CiphertextSpaceGroupElement, EncryptionKey};

/// An instance of a decryption key share of a class-groups threshold encryption scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKeyShare<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> where
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    // The party's index in the protocol $P_j$
    pub party_id: PartyID,
    // The corresponding encryption key
    encryption_key: EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    // The decryption key share $ d_j $
    pub decryption_key_share: SecretKeyShareSizedInteger,
}

pub type PartialDecryptionProof<const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize> = Vec<
    maurer::equality_of_discrete_logs::Proof<
        2,
        group::bounded_integers_group::GroupElement<SECRET_KEY_SHARE_WITNESS_LIMBS>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        (),
    >,
>;

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    AsRef<
        EncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >
    for DecryptionKeyShare<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > {
        &self.encryption_key
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    AdditivelyHomomorphicDecryptionKeyShare<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >
    for DecryptionKeyShare<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: InvertMod<
        NonZero<Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + InvertMod<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

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
    EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    DecryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: DiscreteLogInF<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    group::PublicParameters<GroupElement::Scalar>: Eq,
{
    type SecretKeyShare = SecretKeyShareSizedInteger;
    type DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
    type PartialDecryptionProof = PartialDecryptionProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
    type LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber;
    type PublicParameters = PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >;

    type Error = Error;

    fn new(
        party_id: PartyID,
        decryption_key_share: Self::SecretKeyShare,
        public_parameters: &Self::PublicParameters,
        _rng: &mut impl CsRng,
    ) -> Result<Self> {
        let encryption_key =
            EncryptionKey::new(&public_parameters.encryption_scheme_public_parameters)?;

        Ok(DecryptionKeyShare {
            party_id,
            encryption_key,
            decryption_key_share,
        })
    }

    fn party_id(&self) -> PartyID {
        self.party_id
    }

    fn threshold(public_parameters: &Self::PublicParameters) -> PartyID {
        public_parameters.threshold
    }

    fn number_of_parties(public_parameters: &Self::PublicParameters) -> PartyID {
        public_parameters.number_of_parties
    }

    fn generate_decryption_share_semi_honest(
        &self,
        ciphertext: &CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> CtOption<Self::DecryptionShare> {
        let [decryption_share_base, _]: &[_; 2] = ciphertext.into();

        let decryption_share = shamir::over_the_integers::generate_decryption_share_semi_honest(
            self.decryption_key_share,
            decryption_share_base,
            expected_decrypters,
            self.party_id,
            public_parameters.threshold,
            public_parameters.number_of_parties,
            public_parameters.n_factorial,
            &public_parameters.binomial_coefficients,
            public_parameters
                .encryption_scheme_public_parameters
                .setup_parameters
                .equivalence_class_public_parameters(),
            public_parameters
                .encryption_scheme_public_parameters
                .setup_parameters
                .decryption_key_bits(),
        );

        decryption_share
    }

    fn generate_decryption_shares(
        &self,
        ciphertexts: Vec<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> CtOption<(Vec<Self::DecryptionShare>, Self::PartialDecryptionProof)> {
        let decryption_key_share_upper_bound_bits = secret_key_share_size_upper_bound(
            u32::from(public_parameters.number_of_parties),
            u32::from(public_parameters.threshold),
            public_parameters
                .encryption_scheme_public_parameters
                .setup_parameters
                .decryption_key_bits(),
        );

        let witness_group_public_parameters = group::bounded_integers_group::PublicParameters::<
            SECRET_KEY_SHARE_WITNESS_LIMBS,
        >::new_with_randomizer_upper_bound(
            decryption_key_share_upper_bound_bits
        );

        if witness_group_public_parameters.is_err()
            || !public_parameters
                .binomial_coefficients
                .contains_key(&self.party_id)
        {
            return CtOption::new(
                (vec![], Self::PartialDecryptionProof::default()),
                Choice::from(0u8),
            );
        }

        // Safe to unwrap due to sanity check.
        let witness_group_public_parameters = witness_group_public_parameters.unwrap();
        let binomial_coefficient = *public_parameters
            .binomial_coefficients
            .get(&self.party_id)
            .unwrap();

        let ciphertexts: Vec<_> = ciphertexts
            .into_iter()
            .map(|ciphertext| {
                let [first_ciphertext, _]: [_; 2] = ciphertext.into();

                first_ciphertext
            })
            .collect();

        #[cfg(not(feature = "parallel"))]
        let iter = ciphertexts.iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts.par_iter();

        let decryption_share_bases: Vec<_> = iter
            .map(|ciphertext| {
                ciphertext
                    .scale_vartime(&public_parameters.n_factorial)
                    .scale_vartime(&binomial_coefficient)
            })
            .collect();

        let witness = group::bounded_integers_group::GroupElement::new(
            Int::from(&self.decryption_key_share),
            &witness_group_public_parameters,
        )
        .ok();

        let decryption_shares_and_proofs: Option<Vec<_>> = witness.and_then(|witness| {
            decryption_share_bases
                .into_iter()
                .map(|decryption_share_base| {
                    let discrete_log_sample_bits =
                        Some(witness_group_public_parameters.sample_bits);
                    let language_public_parameters =
                        maurer::equality_of_discrete_logs::PublicParameters::new::<
                            group::bounded_integers_group::GroupElement<
                                SECRET_KEY_SHARE_WITNESS_LIMBS,
                            >,
                            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                        >(
                            witness_group_public_parameters.clone(),
                            public_parameters
                                .encryption_scheme_public_parameters
                                .setup_parameters
                                .equivalence_class_public_parameters()
                                .clone(),
                            [public_parameters.base, decryption_share_base.value()],
                            discrete_log_sample_bits,
                        );

                    maurer::equality_of_discrete_logs::Proof::prove(
                        &(),
                        &language_public_parameters,
                        vec![witness],
                        rng,
                    )
                    .ok()
                    .and_then(|(proof, statements)| {
                        if let [statement] = &statements[..] {
                            let [_, decryption_share] = (*statement).into();
                            Some((decryption_share, proof))
                        } else {
                            None
                        }
                    })
                })
                .collect()
        });

        if let Some(decryption_shares_and_proofs) = decryption_shares_and_proofs {
            let (decryption_shares, proofs): (Vec<_>, Vec<_>) =
                decryption_shares_and_proofs.into_iter().unzip();
            return CtOption::new(
                (
                    decryption_shares
                        .iter()
                        .map(group::GroupElement::value)
                        .collect(),
                    proofs,
                ),
                Choice::from(1u8),
            );
        }

        CtOption::new(
            (vec![], Self::PartialDecryptionProof::default()),
            Choice::from(0u8),
        )
    }

    fn combine_decryption_shares_semi_honest(
        ciphertexts: Vec<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        decryption_shares: HashMap<PartyID, Vec<Self::DecryptionShare>>,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> Result<Vec<GroupElement::Scalar>> {
        let batch_size = ciphertexts.len();

        // Filter out invalid decryption shares.
        let decryption_shares = decryption_shares
            .into_iter()
            .flat_map(|(party_id, decryption_shares)| {
                    decryption_shares
                        .into_iter()
                        .map(|decryption_share| {
                            <EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> as group::GroupElement>::new(
                                decryption_share,
                                public_parameters
                                    .encryption_scheme_public_parameters
                                    .setup_parameters.equivalence_class_public_parameters(),
                            )
                        })
                        .collect::<group::Result<Vec<_>>>().map(|decryption_shares| {
                        (party_id, decryption_shares)
                    })
            }).collect();

        let (have_enough_expected_decrypters, combined_decryption_shares) =
            interpolate_decryption_shares(
                decryption_shares,
                expected_decrypters,
                0,
                public_parameters.threshold,
                public_parameters.number_of_parties,
                public_parameters.n_factorial,
                batch_size,
            )?;

        // We have two modes of decryptions, the expected case and unexpected case. In the unexpected case the parties have to "divide" in the exponent to fix the computation, which in a group of unknown order demands another multiplication by n!.
        let decryption_factor_n_factorial_degree = if have_enough_expected_decrypters {
            3
        } else {
            4
        };

        let decryption_factor = if decryption_factor_n_factorial_degree == 3 {
            public_parameters.n_factorial_cubed_inverse
        } else {
            public_parameters.n_factorial_quad_inverse
        };

        ciphertexts
            .into_iter()
            .zip(combined_decryption_shares)
            .map(|(ciphertext, combined_decryption_share)| {
                let [_, second_ciphertext]: [_; 2] = ciphertext.into(); // $ct_2$

                // Raise `ciphertext` by `n!^3` or `n!^4` based on whether we are in the expected or unexpected case
                let second_ciphertext_by_delta_cubed = (1..=decryption_factor_n_factorial_degree)
                    .fold(second_ciphertext, |acc, _| {
                        acc.scale_vartime(&public_parameters.n_factorial)
                    });

                // $ \bar{M} = ct_2^{\delta^3} \cdot W^{-1} = f^{\delta^3 \cdot m}$
                let message_by_decryption_factor_in_the_exponent =
                    second_ciphertext_by_delta_cubed - combined_decryption_share;

                let solved_message = DecryptionKey::<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >::discrete_log_in_F(
                    &message_by_decryption_factor_in_the_exponent,
                    &public_parameters
                        .encryption_scheme_public_parameters
                        .setup_parameters,
                )
                .into_option()
                .ok_or(Error::InternalError); // $ CLSolve(PP_{cl}, \bar{M}) $

                solved_message.and_then(|m| {
                    let message_by_delta_cubed = GroupElement::Scalar::new(
                        m.into(),
                        public_parameters
                            .encryption_scheme_public_parameters
                            .plaintext_space_public_parameters(),
                    );

                    // $ CLSolve(PP_{cl}, \bar{M}) \cdot \delta^{-3} mod q $
                    Ok(message_by_delta_cubed.map(|m| m.scale(&decryption_factor))?)
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    fn identify_malicious_decrypters(
        ciphertexts: Vec<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (Vec<Self::DecryptionShare>, Self::PartialDecryptionProof),
        >,
        public_parameters: &Self::PublicParameters,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<Vec<PartyID>, Self::Error> {
        let batch_size = ciphertexts.len();

        #[cfg(not(feature = "parallel"))]
        let iter = ciphertexts.clone().into_iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts.into_par_iter();

        let (decrypters_sending_invalid_number_of_decryption_shares, decryption_shares_and_proofs) =
            decryption_shares_and_proofs
                .into_iter()
                .map(|(party_id, (decryption_shares, proof))| {
                    let res = if decryption_shares.len() != batch_size || proof.len() != batch_size
                    {
                        Err(Error::InvalidMessage)
                    } else {
                        Ok((decryption_shares, proof))
                    };

                    (party_id, res)
                })
                .handle_invalid_messages_async();

        // The set $S$ of parties participating in the threshold decryption sessions
        let decrypters: Vec<PartyID> = decryption_shares_and_proofs.clone().into_keys().collect();

        let decryption_share_bases: Vec<_> = iter
            .map(|ciphertext| {
                let [first_ciphertext, _]: [_; 2] = ciphertext.into();

                first_ciphertext.scale_vartime(&public_parameters.n_factorial)
            })
            .collect();

        let decryption_key_share_upper_bound_bits = secret_key_share_size_upper_bound(
            u32::from(public_parameters.number_of_parties),
            u32::from(public_parameters.threshold),
            public_parameters
                .encryption_scheme_public_parameters
                .setup_parameters
                .decryption_key_bits(),
        );

        let witness_group_public_parameters = group::bounded_integers_group::PublicParameters::<
            SECRET_KEY_SHARE_WITNESS_LIMBS,
        >::new_with_randomizer_upper_bound(
            decryption_key_share_upper_bound_bits
        )?;

        let (parties_sending_invalid_statements, proofs_and_statements) = decrypters
            .iter()
            .map(|party_id| {
                // If the decrypting party has no public verification key, we cannot verify the proof, and it will be reported as malicious.
                let public_verification_key =
                    public_parameters.public_verification_keys.get(party_id);

                let binomial_coefficient = public_parameters.binomial_coefficients.get(party_id);

                // Safe to `unwrap` here, `decrypters` are the keys of `decryption_shares_and_proofs`
                let (decryption_shares, proofs) =
                    decryption_shares_and_proofs.get(party_id).unwrap().clone();

                (
                    *party_id,
                    public_verification_key
                        .zip(binomial_coefficient)
                        .ok_or(Error::InvalidParameters)
                        .and_then(|(public_verification_key, binomial_coefficient)| {
                            decryption_share_bases
                                .clone()
                                .into_iter()
                                .map(|decryption_share_base| {
                                    decryption_share_base.scale_vartime(binomial_coefficient)
                                })
                                .zip(decryption_shares.into_iter().zip(proofs))
                                .map(|(decryption_share_base, (decryption_share, proof))| {
                                    let discrete_log_sample_bits =
                                        Some(witness_group_public_parameters.sample_bits);
                                    let language_public_parameters =
                                        maurer::equality_of_discrete_logs::PublicParameters::new::<
                                            group::bounded_integers_group::GroupElement<
                                                SECRET_KEY_SHARE_WITNESS_LIMBS,
                                            >,
                                            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                                        >(
                                            witness_group_public_parameters.clone(),
                                            public_parameters
                                                .encryption_scheme_public_parameters
                                                .setup_parameters
                                                .equivalence_class_public_parameters()
                                                .clone(),
                                            [public_parameters.base, decryption_share_base.value()],
                                            discrete_log_sample_bits,
                                        );

                                    let statement = self_product::GroupElement::<
                                        2,
                                        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                                    >::new(
                                        [*public_verification_key, decryption_share].into(),
                                        public_parameters
                                            .encryption_scheme_public_parameters
                                            .ciphertext_space_public_parameters(),
                                    )
                                    .map_err(Error::from);

                                    statement.map(|statement| {
                                        (proof, language_public_parameters, statement)
                                    })
                                })
                                .collect::<Result<Vec<_>>>()
                        }),
                )
            })
            .handle_invalid_messages_async();

        let malicious_decrypters: Vec<PartyID> = proofs_and_statements
            .clone()
            .into_iter()
            .filter(|(_, proofs_and_statements)| {
                proofs_and_statements.iter().any(
                    |(proof, language_public_parameters, statement)| {
                        proof
                            .verify(&(), language_public_parameters, vec![*statement])
                            .is_err()
                    },
                )
            })
            .map(|(party_id, _)| party_id)
            .chain(decrypters_sending_invalid_number_of_decryption_shares)
            .chain(parties_sending_invalid_statements)
            .deduplicate_and_sort();

        Ok(malicious_decrypters)
    }

    fn identify_malicious_semi_honest_decrypters(
        invalid_semi_honest_decryption_shares: HashMap<PartyID, Vec<Self::DecryptionShare>>,
        valid_maliciously_secure_decryption_shares: HashMap<PartyID, Vec<Self::DecryptionShare>>,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> std::result::Result<Vec<PartyID>, Self::Error> {
        let batch_size = valid_maliciously_secure_decryption_shares
            .values()
            .next()
            .map(|shares| shares.len())
            .ok_or(Error::InvalidParameters)?;

        // Instantiate decryption shares.
        let (parties_sending_invalid_decryption_shares, invalid_semi_honest_decryption_shares) = invalid_semi_honest_decryption_shares
            .into_iter()
            .map(|(party_id, decryption_shares)| {
                let decryption_shares: Result<Vec<_>> =
                    if decryption_shares.len() == batch_size {
                        decryption_shares
                        .into_iter()
                        .map(|decryption_share| {
                            <EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> as group::GroupElement>::new(
                                decryption_share,
                                public_parameters
                                    .encryption_scheme_public_parameters
                                    .setup_parameters.equivalence_class_public_parameters(),
                            ).map_err(Error::from)
                        })
                        .collect()
                } else {
                    Err(Error::InvalidMessage)
                };

                (party_id, decryption_shares)
            })
            .handle_invalid_messages_async();

        let valid_maliciously_secure_decryption_shares = valid_maliciously_secure_decryption_shares
            .into_iter()
            .map(|(party_id, decryption_shares)| {
                let decryption_shares: Result<Vec<_>> =
                    if decryption_shares.len() == batch_size {
                        decryption_shares
                        .into_iter()
                        .map(|decryption_share| {
                            <EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> as group::GroupElement>::new(
                                decryption_share,
                                public_parameters
                                    .encryption_scheme_public_parameters
                                    .setup_parameters.equivalence_class_public_parameters(),
                            ).map_err(Error::from)
                        })
                        .collect()
                } else {
                    Err(Error::InvalidMessage)
                };

                decryption_shares.map(|decryption_shares| (party_id, decryption_shares))
            })
            .try_collect_hash_map().map_err(|_| Error::InvalidParameters)?;

        let malicious_decrypters = identify_malicious_semi_honest_decrypters(
            invalid_semi_honest_decryption_shares,
            valid_maliciously_secure_decryption_shares,
            expected_decrypters,
            public_parameters.threshold,
            public_parameters.number_of_parties,
            public_parameters.binomial_coefficients.clone(),
            public_parameters.n_factorial,
            batch_size,
        )?;

        Ok(parties_sending_invalid_decryption_shares
            .into_iter()
            .chain(malicious_decrypters)
            .deduplicate_and_sort())
    }
}

/// The Public Parameters used for Threshold Decryption in Tiresias.
///
/// This struct holds precomputed values that are computationally expensive to compute, but do not
/// change with the decrypter set (unlike the adjusted lagrange coefficients), besides public
/// outputs from the DKG process (e.g., `base` and `public_verification_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters,
> where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    // The threshold $t$.
    pub threshold: PartyID,
    // The number of parties $n$.
    pub number_of_parties: PartyID,
    // The base $g$ for proofs of equality of discrete logs.
    pub base: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    // The public verification keys ${{v_i}}_i$ for proofs of equality of discrete logs.
    pub public_verification_keys: HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    // A precomputed mapping of the party-id $j$ to the binomial coefficient ${n\choose j}$.
    pub(crate) binomial_coefficients: HashMap<PartyID, BinomialCoefficientSizedNumber>,
    // The precomputed value $(\delta^3)^{-1} mod(q)$ when $\delta = n!$. Used for threshold_decryption (saved for
    // optimization reasons).
    pub(crate) n_factorial_cubed_inverse: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    // The precomputed value $(\delta^4)^{-1} mod(q)$ when $\delta = n!$. Used for threshold_decryption (saved for
    // optimization reasons).
    pub(crate) n_factorial_quad_inverse: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    // The precomputed value $n!$.
    pub(crate) n_factorial: FactorialSizedNumber,
    pub encryption_scheme_public_parameters: encryption_key::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    pub fn new<GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>>(
        threshold: PartyID,
        number_of_parties: PartyID,
        base: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        public_verification_keys: HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        encryption_scheme_public_parameters: encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
    ) -> crate::Result<Self>
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
        >,
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
    {
        if u32::from(threshold) > MAX_THRESHOLD || u32::from(number_of_parties) > MAX_PLAYERS {
            return Err(crate::Error::InvalidParameters);
        }

        let precomputed_values = PrecomputedValues::<group::Value<GroupElement::Scalar>>::new::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement::Scalar,
        >(
            number_of_parties,
            encryption_scheme_public_parameters.plaintext_space_public_parameters(),
        )?;

        Ok(PublicParameters {
            threshold,
            number_of_parties,
            base,
            public_verification_keys,
            binomial_coefficients: precomputed_values.binomial_coefficients,
            n_factorial_cubed_inverse: precomputed_values.n_factorial_cubed_inverse.into(),
            n_factorial_quad_inverse: precomputed_values.n_factorial_quad_inverse.into(),
            n_factorial: precomputed_values.n_factorial,
            encryption_scheme_public_parameters,
        })
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    AsRef<
        encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
    >
    for PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &encryption_key::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    > {
        &self.encryption_scheme_public_parameters
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use crypto_bigint::ConstChoice;

    use group::helpers::NormalizeValues;
    use group::GroupElement;

    use crate::{equivalence_class, SecretKeyShareSizedNumber};

    use super::*;

    pub fn deal_trusted_shares<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        threshold: PartyID,
        number_of_parties: PartyID,
        encryption_scheme_public_parameters: encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        secret_key: Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        base: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secret_key_bits: u32,
    ) -> (
        PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        HashMap<PartyID, SecretKeyShareSizedInteger>,
    )
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
    {
        let (base, public_verification_keys, decryption_key_shares) =
            mpc::test_helpers::deal_trusted_shares(
                threshold,
                number_of_parties,
                Int::new_from_abs_sign(
                    SecretKeyShareSizedNumber::from(&secret_key),
                    ConstChoice::FALSE,
                )
                .unwrap(),
                base,
                encryption_scheme_public_parameters
                    .setup_parameters
                    .equivalence_class_public_parameters(),
                secret_key_bits,
            );

        let public_parameters = PublicParameters::new::<GroupElement>(
            threshold,
            number_of_parties,
            base.value(),
            public_verification_keys.normalize_values(),
            encryption_scheme_public_parameters,
        )
        .unwrap();

        let decryption_key_shares = decryption_key_shares
            .into_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    Int::new_from_abs_sign(share, ConstChoice::FALSE).unwrap(),
                )
            })
            .collect();

        (public_parameters, decryption_key_shares)
    }
}

#[cfg(test)]
mod tests {
    use rayon::prelude::*;
    use rstest::rstest;

    use group::{ristretto, secp256k1, OsCsRng};
    use test_helpers::deal_trusted_shares;

    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };
    use crate::{
        RistrettoDecryptionKey, RistrettoDecryptionKeyShare, Secp256k1DecryptionKey,
        Secp256k1DecryptionKeyShare, RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_SCALAR_LIMBS,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_SCALAR_LIMBS,
    };

    use super::*;

    #[rstest]
    #[case(2, 2, 1)]
    #[case(2, 3, 2)]
    fn decrypts_ed25519(
        #[case] threshold: PartyID,
        #[case] number_of_parties: PartyID,
        #[case] batch_size: usize,
    ) {
        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let base = setup_parameters.h;
        let secret_key_bits = setup_parameters.decryption_key_bits();
        let (encryption_scheme_public_parameters, decryption_key) =
            RistrettoDecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

        let (public_parameters, decryption_key_shares) = deal_trusted_shares::<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::GroupElement,
        >(
            threshold,
            number_of_parties,
            encryption_scheme_public_parameters,
            decryption_key.decryption_key,
            base,
            secret_key_bits,
        );

        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_par_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    RistrettoDecryptionKeyShare::new(
                        party_id,
                        share,
                        &public_parameters,
                        &mut OsCsRng,
                    )
                    .unwrap(),
                )
            })
            .collect();

        homomorphic_encryption::test_helpers::threshold_decrypts(
            threshold,
            batch_size,
            decryption_key_shares,
            &public_parameters,
            &mut OsCsRng,
        );
    }

    #[rstest]
    #[case(2, 2, 1)]
    #[case(2, 3, 2)]
    fn decrypts_secp256k1(
        #[case] threshold: PartyID,
        #[case] number_of_parties: PartyID,
        #[case] batch_size: usize,
    ) {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let base = setup_parameters.h;
        let secret_key_bits = setup_parameters.decryption_key_bits();
        let (encryption_scheme_public_parameters, decryption_key) =
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

        let (public_parameters, decryption_key_shares) = deal_trusted_shares::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >(
            threshold,
            number_of_parties,
            encryption_scheme_public_parameters,
            decryption_key.decryption_key,
            base,
            secret_key_bits,
        );

        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_par_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    Secp256k1DecryptionKeyShare::new(
                        party_id,
                        share,
                        &public_parameters,
                        &mut OsCsRng,
                    )
                    .unwrap(),
                )
            })
            .collect();

        homomorphic_encryption::test_helpers::threshold_decrypts(
            threshold,
            batch_size,
            decryption_key_shares,
            &public_parameters,
            &mut OsCsRng,
        );
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;
    use rayon::prelude::*;

    use group::{ristretto, secp256k1, OsCsRng};

    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };
    use crate::{
        test_helpers::deal_trusted_shares, RistrettoDecryptionKey, RistrettoDecryptionKeyShare,
        Secp256k1DecryptionKey, Secp256k1DecryptionKeyShare,
        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
    };

    use super::*;

    pub(crate) fn benchmark_decryption_key_share_secp256k1(c: &mut Criterion) {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let base = setup_parameters.h;
        let secret_key_bits = setup_parameters.decryption_key_bits();

        for (threshold, number_of_parties) in [(10, 15), (20, 30), (67, 100), (77, 115)] {
            let (encryption_scheme_public_parameters, decryption_key) =
                Secp256k1DecryptionKey::generate(setup_parameters.clone(), &mut OsCsRng).unwrap();

            let (public_parameters, decryption_key_shares) = deal_trusted_shares::<
                SECP256K1_SCALAR_LIMBS,
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                secp256k1::GroupElement,
            >(
                threshold,
                number_of_parties,
                encryption_scheme_public_parameters,
                decryption_key.decryption_key,
                base,
                secret_key_bits,
            );

            let decryption_key_shares: HashMap<_, _> = decryption_key_shares
                .into_par_iter()
                .map(|(party_id, share)| {
                    (
                        party_id,
                        Secp256k1DecryptionKeyShare::new(
                            party_id,
                            share,
                            &public_parameters,
                            &mut OsCsRng,
                        )
                        .unwrap(),
                    )
                })
                .collect();

            homomorphic_encryption::test_helpers::benchmark_decryption_key_share(
                threshold,
                number_of_parties,
                1,
                decryption_key_shares,
                &public_parameters,
                "class groups secp256k1",
                c,
                &mut OsCsRng,
            );
        }
    }

    pub(crate) fn benchmark_decryption_key_share_semi_honest_secp256k1(c: &mut Criterion) {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let base = setup_parameters.h;
        let secret_key_bits = setup_parameters.decryption_key_bits();

        for (threshold, number_of_parties, deltas) in [(67, 100, vec![1, 5, 10, 20])] {
            let decryption_key_share_upper_bound_bits = secret_key_share_size_upper_bound(
                u32::from(number_of_parties),
                u32::from(threshold),
                secret_key_bits,
            );

            let (encryption_scheme_public_parameters, decryption_key) =
                Secp256k1DecryptionKey::generate(setup_parameters.clone(), &mut OsCsRng).unwrap();

            let (public_parameters, decryption_key_shares) = deal_trusted_shares::<
                SECP256K1_SCALAR_LIMBS,
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                secp256k1::GroupElement,
            >(
                threshold,
                number_of_parties,
                encryption_scheme_public_parameters,
                decryption_key.decryption_key,
                base,
                secret_key_bits,
            );

            println!("{threshold}-out-of-{number_of_parties}: secp256k1 secret key bits {secret_key_bits} secret key share bits {decryption_key_share_upper_bound_bits}");

            let decryption_key_shares: HashMap<_, _> = decryption_key_shares
                .into_par_iter()
                .map(|(party_id, share)| {
                    (
                        party_id,
                        Secp256k1DecryptionKeyShare::new(
                            party_id,
                            share,
                            &public_parameters,
                            &mut OsCsRng,
                        )
                        .unwrap(),
                    )
                })
                .collect();

            for delta in deltas {
                homomorphic_encryption::test_helpers::benchmark_decryption_key_share_semi_honest(
                    threshold,
                    number_of_parties,
                    delta,
                    1,
                    decryption_key_shares.clone(),
                    &public_parameters,
                    true,
                    "class groups secp256k1",
                    c,
                    &mut OsCsRng,
                );

                if (number_of_parties - (delta + 1)) >= threshold {
                    homomorphic_encryption::test_helpers::benchmark_decryption_key_share_semi_honest(
                        threshold,
                        number_of_parties,
                        delta,
                        1,
                        decryption_key_shares.clone(),
                        &public_parameters,
                        false,
                        "class groups secp256k1",
                        c,
                        &mut OsCsRng
                    );
                }
            }
        }
    }

    pub(crate) fn benchmark_decryption_key_share_ristretto(c: &mut Criterion) {
        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let base = setup_parameters.h;
        let secret_key_bits = setup_parameters.decryption_key_bits();

        for (threshold, number_of_parties) in [(10, 15), (20, 30), (67, 100), (77, 115)] {
            let (encryption_scheme_public_parameters, decryption_key) =
                RistrettoDecryptionKey::generate(setup_parameters.clone(), &mut OsCsRng).unwrap();

            let (public_parameters, decryption_key_shares) = deal_trusted_shares::<
                RISTRETTO_SCALAR_LIMBS,
                RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                ristretto::GroupElement,
            >(
                threshold,
                number_of_parties,
                encryption_scheme_public_parameters,
                decryption_key.decryption_key,
                base,
                secret_key_bits,
            );

            let decryption_key_shares: HashMap<_, _> = decryption_key_shares
                .into_par_iter()
                .map(|(party_id, share)| {
                    (
                        party_id,
                        RistrettoDecryptionKeyShare::new(
                            party_id,
                            share,
                            &public_parameters,
                            &mut OsCsRng,
                        )
                        .unwrap(),
                    )
                })
                .collect();

            homomorphic_encryption::test_helpers::benchmark_decryption_key_share(
                threshold,
                number_of_parties,
                1,
                decryption_key_shares,
                &public_parameters,
                "class groups ristretto",
                c,
                &mut OsCsRng,
            );
        }
    }

    pub(crate) fn benchmark_decryption_key_share_semi_honest_ristretto(c: &mut Criterion) {
        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let base = setup_parameters.h;
        let secret_key_bits = setup_parameters.decryption_key_bits();

        for (threshold, number_of_parties, deltas) in [(67, 100, vec![1, 5, 10, 20])] {
            let decryption_key_share_upper_bound_bits = secret_key_share_size_upper_bound(
                u32::from(number_of_parties),
                u32::from(threshold),
                secret_key_bits,
            );

            let (encryption_scheme_public_parameters, decryption_key) =
                RistrettoDecryptionKey::generate(setup_parameters.clone(), &mut OsCsRng).unwrap();

            let (public_parameters, decryption_key_shares) = deal_trusted_shares::<
                RISTRETTO_SCALAR_LIMBS,
                RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                ristretto::GroupElement,
            >(
                threshold,
                number_of_parties,
                encryption_scheme_public_parameters,
                decryption_key.decryption_key,
                base,
                secret_key_bits,
            );

            println!("{threshold}-out-of-{number_of_parties}: ristretto secret key bits {secret_key_bits} secret key share bits {decryption_key_share_upper_bound_bits}");

            let decryption_key_shares: HashMap<_, _> = decryption_key_shares
                .into_par_iter()
                .map(|(party_id, share)| {
                    (
                        party_id,
                        RistrettoDecryptionKeyShare::new(
                            party_id,
                            share,
                            &public_parameters,
                            &mut OsCsRng,
                        )
                        .unwrap(),
                    )
                })
                .collect();

            for delta in deltas {
                homomorphic_encryption::test_helpers::benchmark_decryption_key_share_semi_honest(
                    threshold,
                    number_of_parties,
                    delta,
                    1,
                    decryption_key_shares.clone(),
                    &public_parameters,
                    true,
                    "class groups ristretto",
                    c,
                    &mut OsCsRng,
                );

                if (number_of_parties - (delta + 1)) >= threshold {
                    homomorphic_encryption::test_helpers::benchmark_decryption_key_share_semi_honest(
                        threshold,
                        number_of_parties,
                        delta,
                        1,
                        decryption_key_shares.clone(),
                        &public_parameters,
                        false,
                        "class groups ristretto",
                        c,
                        &mut OsCsRng
                    );
                }
            }
        }
    }
}
