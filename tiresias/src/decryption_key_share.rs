// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::collections::{HashMap, HashSet};

use crypto_bigint::{ConstChoice, Int};
use crypto_bigint::{NonZero, U64};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use subtle::{Choice, CtOption};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::{
    benchmark_decryption_key_share, benchmark_decryption_key_share_semi_honest,
};
use group::helpers::{DeduplicateAndSort, TryCollectHashMap};
use group::{CsRng, GroupElement, PartyID};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use mpc::secret_sharing::shamir;
use mpc::secret_sharing::shamir::over_the_integers::{
    identify_malicious_semi_honest_decrypters, interpolate_decryption_shares,
    AdjustedLagrangeCoefficientSizedNumber, BinomialCoefficientSizedNumber, FactorialSizedNumber,
    PrecomputedValues, MAX_PLAYERS,
};
use mpc::HandleInvalidMessages;

use crate::{
    encryption_key, error::SanityCheckError, proofs::ProofOfEqualityOfDiscreteLogs,
    AsNaturalNumber, AsRingElement, CiphertextSpaceGroupElement, CiphertextSpaceValue,
    EncryptionKey, Error, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber,
    PlaintextSpaceGroupElement, PlaintextSpaceValue, Result, SecretKeyShareSizedNumber,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
};

/// An instance of a decryption key share of a Paillier threshold encryption scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKeyShare {
    // The party's index in the protocol $P_j$
    pub party_id: PartyID,
    // The corresponding encryption key
    encryption_key: EncryptionKey,
    // The decryption key share $ d_j $
    decryption_key_share: SecretKeyShareSizedNumber,
}

impl AsRef<EncryptionKey> for DecryptionKeyShare {
    fn as_ref(&self) -> &EncryptionKey {
        &self.encryption_key
    }
}

impl AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>
    for DecryptionKeyShare
{
    type SecretKeyShare = SecretKeyShareSizedNumber;
    type DecryptionShare = PaillierModulusSizedNumber;
    type PartialDecryptionProof = ProofOfEqualityOfDiscreteLogs;
    type LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber;
    type PublicParameters = PublicParameters;
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
        ciphertext: &CiphertextSpaceGroupElement,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> CtOption<Self::DecryptionShare> {
        let decryption_share_base = ciphertext.scale_bounded_vartime(&U64::from(2u8), 2);

        // The only way the generate_decryption_share_semi_honst may fail is if the size of the decryption key share is out of the specified bounds. This is never the case as the DKG and Reconfiguration protocols guarantee that the outputted decryption key shares are bounded by the correct values.
        // Thus this check may never fail for a honest party and as such cannot reveal information on the secret share.
        if let Some(decryption_key_share) = self.decryption_key_share.try_into_int().into() {
            shamir::over_the_integers::generate_decryption_share_semi_honest(
                decryption_key_share,
                &decryption_share_base,
                expected_decrypters,
                self.party_id,
                public_parameters.threshold,
                public_parameters.number_of_parties,
                public_parameters.n_factorial,
                &public_parameters.binomial_coefficients,
                public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
                PaillierModulusSizedNumber::BITS,
            )
        } else {
            CtOption::new(Self::DecryptionShare::default(), Choice::from(0u8))
        }
    }

    fn generate_decryption_shares(
        &self,
        ciphertexts: Vec<CiphertextSpaceGroupElement>,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> CtOption<(Vec<Self::DecryptionShare>, Self::PartialDecryptionProof)> {
        let n2 = *public_parameters
            .encryption_scheme_public_parameters
            .ciphertext_space_public_parameters()
            .params
            .modulus();

        let public_verification_key = public_parameters
            .public_verification_keys
            .get(&self.party_id)
            .copied();

        if public_verification_key.is_none()
            || !public_parameters
                .binomial_coefficients
                .contains_key(&self.party_id)
        {
            return CtOption::new(
                (vec![], ProofOfEqualityOfDiscreteLogs::default()),
                Choice::from(0u8),
            );
        }

        // Safe to unwrap due to sanity check.
        let binomial_coefficient = *public_parameters
            .binomial_coefficients
            .get(&self.party_id)
            .unwrap();
        let public_verification_key = public_verification_key.unwrap();

        let (decryption_share_bases, decryption_shares) = self
            .generate_decryption_shares_semi_honest_internal(
                ciphertexts,
                binomial_coefficient,
                public_parameters,
            );

        let decryption_shares_and_bases: Vec<(
            PaillierModulusSizedNumber,
            PaillierModulusSizedNumber,
        )> = decryption_share_bases
            .into_iter()
            .zip(decryption_shares.clone())
            .collect();

        if decryption_shares_and_bases.len() == 1 {
            let (decryption_share_base, decryption_share) =
                decryption_shares_and_bases.first().unwrap();

            let proof = ProofOfEqualityOfDiscreteLogs::prove(
                *n2,
                public_parameters.number_of_parties,
                public_parameters.threshold,
                self.decryption_key_share,
                public_parameters.base,
                *decryption_share_base,
                public_verification_key,
                *decryption_share,
                rng,
            );

            return CtOption::new((decryption_shares, proof), Choice::from(1u8));
        }

        if let Ok(proof) = ProofOfEqualityOfDiscreteLogs::batch_prove(
            *n2,
            public_parameters.number_of_parties,
            public_parameters.threshold,
            self.decryption_key_share,
            public_parameters.base,
            public_verification_key,
            decryption_shares_and_bases,
            rng,
        ) {
            CtOption::new((decryption_shares, proof), Choice::from(1u8))
        } else {
            CtOption::new(
                (vec![], ProofOfEqualityOfDiscreteLogs::default()),
                Choice::from(0u8),
            )
        }
    }

    fn combine_decryption_shares_semi_honest(
        ciphertexts: Vec<CiphertextSpaceGroupElement>,
        decryption_shares: HashMap<PartyID, Vec<Self::DecryptionShare>>,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> Result<Vec<PlaintextSpaceGroupElement>> {
        let paillier_associate_bi_prime = *public_parameters
            .encryption_scheme_public_parameters
            .plaintext_space_public_parameters()
            .modulus;

        let batch_size = ciphertexts.len();

        // Filter out invalid decryption shares.
        let decryption_shares = decryption_shares
            .into_iter()
            .flat_map(|(party_id, decryption_shares)| {
                let decryption_shares: Result<Vec<_>> = decryption_shares
                    .into_iter()
                    .map(|decryption_share| {
                        let value = CiphertextSpaceValue::new(
                            decryption_share,
                            public_parameters
                                .encryption_scheme_public_parameters
                                .ciphertext_space_public_parameters(),
                        );

                        value
                            .and_then(|value| {
                                CiphertextSpaceGroupElement::new(
                                    value,
                                    public_parameters
                                        .encryption_scheme_public_parameters
                                        .ciphertext_space_public_parameters(),
                                )
                            })
                            .map_err(Error::from)
                    })
                    .collect();

                decryption_shares.map(|decryption_shares| (party_id, decryption_shares))
            })
            .collect();

        let (have_enough_expected_decrypters, combined_decryption_shares) =
            interpolate_decryption_shares(
                decryption_shares,
                expected_decrypters.clone(),
                0,
                public_parameters.threshold,
                public_parameters.number_of_parties,
                public_parameters.n_factorial,
                batch_size,
            )?;

        let decryption_factor = if have_enough_expected_decrypters {
            public_parameters.four_n_factorial_cubed_inverse_mod_n
        } else {
            public_parameters.four_n_factorial_quad_inverse_mod_n
        }
        .as_ring_element(&paillier_associate_bi_prime);

        let plaintexts = combined_decryption_shares
            .into_iter()
            .map(|c_prime| {
                let paillier_associate_bi_prime_for_division = NonZero::new(
                    (*public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters()
                        .modulus)
                        .resize::<{ PaillierModulusSizedNumber::LIMBS }>(),
                )
                .unwrap();

                // Shared functionality computes $\left[\prod_{j\in T} \ct_j^{\Delta_n\lambda_{T,j}^0} \mod N^2 \right]$,
                // we need  $\left[\prod_{j\in T} \ct_j^{2\Delta_n\lambda_{T,j}^0} \mod N^2 \right]$ so we multiply by 2.
                let c_prime: PaillierModulusSizedNumber = c_prime
                    .scale_bounded_vartime(&PaillierModulusSizedNumber::from(2u8), 2)
                    .into();

                // $c` >= 1$ so safe to perform a `.wrapping_sub()` here which will not overflow
                // After dividing a number $ x < N^2 $ by $N$2
                // we will get a number that is smaller than $N$, so we can safely `.split()`
                // and take the low part of the result.
                let (lo, _) = ((c_prime.wrapping_sub(&PaillierModulusSizedNumber::ONE))
                    / paillier_associate_bi_prime_for_division)
                    .split();

                PlaintextSpaceGroupElement::new(
                    (lo.as_ring_element(&paillier_associate_bi_prime) * decryption_factor)
                        .as_natural_number(),
                    public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )
                .unwrap()
            })
            .collect();

        Ok(plaintexts)
    }

    fn identify_malicious_decrypters(
        ciphertexts: Vec<CiphertextSpaceGroupElement>,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (Vec<Self::DecryptionShare>, Self::PartialDecryptionProof),
        >,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> std::result::Result<Vec<PartyID>, Self::Error> {
        let n2 = *public_parameters
            .encryption_scheme_public_parameters
            .ciphertext_space_public_parameters()
            .params
            .modulus();

        let batch_size = ciphertexts.len();

        let (decrypters_sending_invalid_number_of_decryption_shares, decryption_shares_and_proofs) =
            decryption_shares_and_proofs
                .into_iter()
                .map(|(party_id, (decryption_shares, proof))| {
                    let res = if decryption_shares.len() != batch_size {
                        Err(Error::SanityCheckError(SanityCheckError::InvalidParameters))
                    } else {
                        Ok((decryption_shares, proof))
                    };

                    (party_id, res)
                })
                .handle_invalid_messages_async();

        // The set $S$ of parties participating in the threshold decryption sessions
        let decrypters: Vec<PartyID> = decryption_shares_and_proofs.clone().into_keys().collect();

        #[cfg(not(feature = "parallel"))]
        let iter = ciphertexts.into_iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts.into_par_iter();

        let decryption_share_bases: Vec<_> = iter
            .map(|ciphertext| {
                ciphertext
                    .0
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                    .pow_bounded_exp(
                        &public_parameters.n_factorial,
                        public_parameters.n_factorial.bits_vartime(),
                    )
            })
            .collect();

        if decrypters.iter().any(|party_id| {
            !public_parameters
                .public_verification_keys
                .contains_key(party_id)
                || !public_parameters
                    .binomial_coefficients
                    .contains_key(party_id)
        }) {
            return Err(Error::SanityCheckError(SanityCheckError::InvalidParameters));
        }

        let malicious_decrypters: Vec<PartyID> = decrypters
            .clone()
            .into_iter()
            .filter(|party_id| {
                // Safe to `unwrap` here, we did a sanity check.
                let public_verification_key = *public_parameters
                    .public_verification_keys
                    .get(party_id)
                    .unwrap();

                let binomial_coefficient = *public_parameters
                    .binomial_coefficients
                    .get(party_id)
                    .unwrap();

                // Safe to `unwrap` here, `decrypters` are the keys of `decryption_shares_and_proofs`
                let (decryption_shares, proof) =
                    decryption_shares_and_proofs.get(party_id).unwrap();

                if batch_size == 1 {
                    let decryption_share_base = decryption_share_bases
                        .first()
                        .unwrap()
                        .pow_bounded_exp(&binomial_coefficient, binomial_coefficient.bits_vartime())
                        .as_natural_number();

                    let decryption_share = *decryption_shares.first().unwrap();

                    proof
                        .verify(
                            *n2,
                            public_parameters.number_of_parties,
                            public_parameters.threshold,
                            public_parameters.base,
                            decryption_share_base,
                            public_verification_key,
                            decryption_share,
                            rng,
                        )
                        .is_err()
                } else {
                    let decryption_shares_and_bases: Vec<(
                        PaillierModulusSizedNumber,
                        PaillierModulusSizedNumber,
                    )> = decryption_share_bases
                        .clone()
                        .into_iter()
                        .map(|decryption_share_base| {
                            decryption_share_base
                                .pow_bounded_exp(
                                    &binomial_coefficient,
                                    binomial_coefficient.bits_vartime(),
                                )
                                .as_natural_number()
                        })
                        .zip(decryption_shares.clone())
                        .collect();

                    proof
                        .batch_verify(
                            *n2,
                            public_parameters.number_of_parties,
                            public_parameters.threshold,
                            public_parameters.base,
                            public_verification_key,
                            decryption_shares_and_bases,
                            rng,
                        )
                        .is_err()
                }
            })
            .chain(decrypters_sending_invalid_number_of_decryption_shares)
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
            .ok_or(Error::SanityCheckError(SanityCheckError::InvalidParameters))?;

        // Instantiate decryption shares.
        let (parties_sending_invalid_decryption_shares, invalid_semi_honest_decryption_shares) =
            invalid_semi_honest_decryption_shares
                .into_iter()
                .map(|(party_id, decryption_shares)| {
                    let decryption_shares: Result<Vec<_>> = if decryption_shares.len() == batch_size
                    {
                        decryption_shares
                            .into_iter()
                            .map(|decryption_share| {
                                let value = CiphertextSpaceValue::new(
                                    decryption_share,
                                    public_parameters
                                        .encryption_scheme_public_parameters
                                        .ciphertext_space_public_parameters(),
                                );

                                value
                                    .and_then(|value| {
                                        CiphertextSpaceGroupElement::new(
                                            value,
                                            public_parameters
                                                .encryption_scheme_public_parameters
                                                .ciphertext_space_public_parameters(),
                                        )
                                    })
                                    .map_err(Error::from)
                            })
                            .collect()
                    } else {
                        Err(Error::SanityCheckError(SanityCheckError::InvalidParameters))
                    };

                    (party_id, decryption_shares)
                })
                .handle_invalid_messages_async();

        let valid_maliciously_secure_decryption_shares = valid_maliciously_secure_decryption_shares
            .into_iter()
            .map(|(party_id, decryption_shares)| {
                let decryption_shares: Result<Vec<_>> = if decryption_shares.len() == batch_size {
                    decryption_shares
                        .into_iter()
                        .map(|decryption_share| {
                            let value = CiphertextSpaceValue::new(
                                decryption_share,
                                public_parameters
                                    .encryption_scheme_public_parameters
                                    .ciphertext_space_public_parameters(),
                            );

                            value
                                .and_then(|value| {
                                    CiphertextSpaceGroupElement::new(
                                        value,
                                        public_parameters
                                            .encryption_scheme_public_parameters
                                            .ciphertext_space_public_parameters(),
                                    )
                                })
                                .map_err(Error::from)
                        })
                        .collect()
                } else {
                    Err(Error::SanityCheckError(SanityCheckError::InvalidParameters))
                };

                decryption_shares.map(|decryption_shares| (party_id, decryption_shares))
            })
            .try_collect_hash_map()
            .map_err(|_| Error::SanityCheckError(SanityCheckError::InvalidParameters))?;

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

impl DecryptionKeyShare {
    fn generate_decryption_shares_semi_honest_internal(
        &self,
        decryption_share_bases: Vec<CiphertextSpaceGroupElement>,
        binomial_coefficient: BinomialCoefficientSizedNumber,
        public_parameters: &PublicParameters,
    ) -> (
        Vec<PaillierModulusSizedNumber>,
        Vec<PaillierModulusSizedNumber>,
    ) {
        let decryption_share_bases: Vec<CiphertextSpaceGroupElement> = decryption_share_bases
            .into_iter()
            .map(|decryption_share_base| {
                decryption_share_base.scale_bounded_vartime(&U64::from(2u8), 2)
            })
            .collect();

        let (decryption_share_bases, decryption_shares): (
            Vec<CiphertextSpaceGroupElement>,
            Vec<CiphertextSpaceGroupElement>,
        ) = shamir::over_the_integers::generate_decryption_shares(
            Int::new_from_abs_sign(self.decryption_key_share, ConstChoice::FALSE).unwrap(),
            decryption_share_bases,
            public_parameters.threshold,
            public_parameters.number_of_parties,
            public_parameters.n_factorial,
            binomial_coefficient,
            public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
            PaillierModulusSizedNumber::BITS,
        );

        let decryption_share_bases = decryption_share_bases
            .into_iter()
            .map(|decryption_share_base| decryption_share_base.into())
            .collect();

        let decryption_shares = decryption_shares
            .into_iter()
            .map(|decryption_share| decryption_share.into())
            .collect();

        (decryption_share_bases, decryption_shares)
    }
}

/// The Public Parameters used for Threshold Decryption in Tiresias.
///
/// This struct holds precomputed values that are computationally expensive to compute, but do not
/// change with the decrypter set (unlike the adjusted lagrange coefficients), besides public
/// outputs from the DKG process (e.g., `base` and `public_verification_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicParameters {
    // The threshold $t$.
    pub threshold: PartyID,
    // The number of parties $n$.
    pub number_of_parties: PartyID,
    // The base $g$ for proofs of equality of discrete logs.
    pub base: PaillierModulusSizedNumber,
    // The public verification keys ${{v_i}}_i$ for proofs of equality of discrete logs.
    pub public_verification_keys: HashMap<PartyID, PaillierModulusSizedNumber>,
    // A precomputed mapping of the party-id $j$ to the binomial coefficient ${n\choose j}$.
    pub(crate) binomial_coefficients: HashMap<PartyID, BinomialCoefficientSizedNumber>,
    // The precomputed value $(4n!^3)^{-1} mod(N)$ used for threshold_decryption (saved for
    // optimization reasons).
    pub(crate) four_n_factorial_cubed_inverse_mod_n: LargeBiPrimeSizedNumber,
    // The precomputed value $(4n!^4)^{-1} mod(N)$ used for threshold_decryption (saved for
    // optimization reasons).
    pub(crate) four_n_factorial_quad_inverse_mod_n: LargeBiPrimeSizedNumber,
    // The precomputed value $n!$.
    pub(crate) n_factorial: FactorialSizedNumber,
    pub encryption_scheme_public_parameters: encryption_key::PublicParameters,
}

impl PublicParameters {
    pub fn new(
        threshold: PartyID,
        number_of_parties: PartyID,
        base: PaillierModulusSizedNumber,
        public_verification_keys: HashMap<PartyID, PaillierModulusSizedNumber>,
        encryption_scheme_public_parameters: encryption_key::PublicParameters,
    ) -> crate::Result<PublicParameters> {
        if u32::from(number_of_parties) > MAX_PLAYERS {
            return Err(crate::Error::SanityCheckError(
                crate::SanityCheckError::InvalidParameters,
            ));
        }

        let paillier_associate_bi_prime = *encryption_scheme_public_parameters
            .plaintext_space_public_parameters()
            .modulus;

        let precomputed_values = PrecomputedValues::<PlaintextSpaceValue>::new::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PlaintextSpaceGroupElement,
        >(
            number_of_parties,
            encryption_scheme_public_parameters.plaintext_space_public_parameters(),
        )?;

        // safe to invert here if the smallest factor of the plaintext space is larger than the number of virtual parties
        let four_inverse = LargeBiPrimeSizedNumber::from(4u8)
            .as_ring_element(&paillier_associate_bi_prime)
            .invert()
            .unwrap();

        let four_n_factorial_cubed_inverse_mod_n = (four_inverse
            * precomputed_values
                .n_factorial_cubed_inverse
                .as_ring_element(&paillier_associate_bi_prime))
        .as_natural_number();

        let four_n_factorial_quad_inverse_mod_n = (four_inverse
            * precomputed_values
                .n_factorial_quad_inverse
                .as_ring_element(&paillier_associate_bi_prime))
        .as_natural_number();

        Ok(PublicParameters {
            threshold,
            number_of_parties,
            base,
            public_verification_keys,
            binomial_coefficients: precomputed_values.binomial_coefficients,
            four_n_factorial_cubed_inverse_mod_n,
            four_n_factorial_quad_inverse_mod_n,
            n_factorial: precomputed_values.n_factorial,
            encryption_scheme_public_parameters,
        })
    }
}

impl AsRef<encryption_key::PublicParameters> for PublicParameters {
    fn as_ref(&self) -> &encryption_key::PublicParameters {
        &self.encryption_scheme_public_parameters
    }
}

#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub mod test_helpers {
    use std::iter;

    use crypto_bigint::{CheckedMul, NonZero, RandomMod};
    use rand::seq::IteratorRandom;
    use rstest::rstest;

    use group::OsCsRng;
    use mpc::secret_sharing::shamir::over_the_integers::{
        secret_key_share_size_upper_bound, SecretKeyShareSizedInteger,
    };

    use crate::{
        test_helpers::{CIPHERTEXT, N2},
        CiphertextSpaceValue, LargeBiPrimeSizedNumber,
    };

    use super::*;

    pub const N: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    pub const SECRET_KEY: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
    pub const BASE: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");

    pub fn deal_trusted_shares(
        threshold: PartyID,
        number_of_parties: PartyID,
        paillier_associate_bi_prime: LargeBiPrimeSizedNumber,
        secret_key: PaillierModulusSizedNumber,
        base: PaillierModulusSizedNumber,
    ) -> (
        PublicParameters,
        HashMap<PartyID, SecretKeyShareSizedNumber>,
    ) {
        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new(paillier_associate_bi_prime).unwrap();

        let base = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                base,
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
            )
            .unwrap(),
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

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
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
                PaillierModulusSizedNumber::BITS,
            );

        let base = base.into();

        let public_verification_keys = public_verification_keys
            .into_iter()
            .map(|(party_id, key)| (party_id, key.into()))
            .collect();

        let public_parameters = PublicParameters::new(
            threshold,
            number_of_parties,
            base,
            public_verification_keys,
            encryption_scheme_public_parameters,
        )
        .unwrap();

        (public_parameters, decryption_key_shares)
    }

    #[test]
    fn generates_decryption_share() {
        let n = 3;
        let t = 2;
        let j = 1;

        let (public_parameters, decryption_key_shares) =
            deal_trusted_shares(t, n, N, SECRET_KEY, BASE);
        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    DecryptionKeyShare::new(party_id, share, &public_parameters, &mut OsCsRng)
                        .unwrap(),
                )
            })
            .collect();
        let decryption_key_share = decryption_key_shares.get(&j).unwrap().clone();
        let public_verification_key = *public_parameters.public_verification_keys.get(&j).unwrap();

        let ciphertext = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                CIPHERTEXT,
                public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )
            .unwrap(),
            public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )
        .unwrap();

        let (decryption_shares, proof) = decryption_key_share
            .generate_decryption_shares(vec![ciphertext], &public_parameters, &mut OsCsRng)
            .unwrap();

        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&N2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
            .pow(public_parameters.binomial_coefficients.get(&1).unwrap())
            .as_natural_number();

        let decryption_share = *decryption_shares.first().unwrap();

        let expected_decryption_share = decryption_share_base
            .as_ring_element(&N2)
            .pow_bounded_exp(
                &decryption_key_share.decryption_key_share,
                secret_key_share_size_upper_bound(
                    u32::from(n),
                    u32::from(t),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();

        assert_eq!(expected_decryption_share, decryption_share);

        assert!(proof
            .verify(
                N2,
                n,
                t,
                public_parameters.base,
                decryption_share_base,
                public_verification_key,
                decryption_share,
                &mut OsCsRng,
            )
            .is_ok());
    }

    #[test]
    fn generates_decryption_shares() {
        let t = 2;
        let n = 3;

        let (public_parameters, decryption_key_shares) =
            deal_trusted_shares(t, n, N, SECRET_KEY, BASE);
        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    DecryptionKeyShare::new(party_id, share, &public_parameters, &mut OsCsRng)
                        .unwrap(),
                )
            })
            .collect();
        let encryption_key =
            EncryptionKey::new(&public_parameters.encryption_scheme_public_parameters).unwrap();

        let decryption_key_share = decryption_key_shares.get(&1).unwrap().clone();
        let public_verification_key = *public_parameters.public_verification_keys.get(&1).unwrap();

        let batch_size = 3;

        let plaintexts: Vec<_> = iter::repeat_with(|| {
            PlaintextSpaceGroupElement::new(
                LargeBiPrimeSizedNumber::random_mod(&mut OsCsRng, &NonZero::new(N).unwrap()),
                public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            )
            .unwrap()
        })
        .take(batch_size)
        .collect();

        let ciphertexts: Vec<_> = plaintexts
            .iter()
            .map(|m| {
                let (_, ciphertext) = encryption_key
                    .encrypt(
                        m,
                        &public_parameters.encryption_scheme_public_parameters,
                        false,
                        &mut OsCsRng,
                    )
                    .unwrap();
                ciphertext
            })
            .collect();

        let (decryption_shares, proof) = decryption_key_share
            .generate_decryption_shares(ciphertexts.clone(), &public_parameters, &mut OsCsRng)
            .unwrap();

        let decryption_share_bases: Vec<PaillierModulusSizedNumber> = ciphertexts
            .iter()
            .map(|ciphertext| {
                ciphertext
                    .0
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
                    .pow(public_parameters.binomial_coefficients.get(&1).unwrap())
                    .as_natural_number()
            })
            .collect();

        let expected_decryption_shares: Vec<PaillierModulusSizedNumber> = decryption_share_bases
            .iter()
            .map(|decryption_share_base| {
                decryption_share_base
                    .as_ring_element(&N2)
                    .pow_bounded_exp(
                        &decryption_key_share.decryption_key_share,
                        secret_key_share_size_upper_bound(
                            u32::from(n),
                            u32::from(t),
                            PaillierModulusSizedNumber::BITS,
                        ),
                    )
                    .as_natural_number()
            })
            .collect();

        assert_eq!(decryption_shares, expected_decryption_shares);

        assert!(proof
            .batch_verify(
                N2,
                n,
                t,
                public_parameters.base,
                public_verification_key,
                decryption_share_bases
                    .into_iter()
                    .zip(decryption_shares)
                    .collect(),
                &mut OsCsRng,
            )
            .is_ok());
    }

    #[rstest]
    #[case(2, 2, 1)]
    #[case(2, 3, 1)]
    #[case(2, 4, 1)]
    #[case(3, 7, 2)]
    #[case(5, 5, 1)]
    #[case(6, 10, 5)]
    fn decrypts(#[case] t: PartyID, #[case] n: PartyID, #[case] batch_size: usize) {
        let (public_parameters, decryption_key_shares) =
            deal_trusted_shares(t, n, N, SECRET_KEY, BASE);

        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    DecryptionKeyShare::new(party_id, share, &public_parameters, &mut OsCsRng)
                        .unwrap(),
                )
            })
            .collect();

        homomorphic_encryption::test_helpers::threshold_decrypts(
            t,
            batch_size,
            decryption_key_shares,
            &public_parameters,
            &mut OsCsRng,
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;

    use group::OsCsRng;

    use crate::{test_helpers::deal_trusted_shares, LargeBiPrimeSizedNumber};

    use super::*;

    pub(crate) fn benchmark_decryption_key_share(c: &mut Criterion) {
        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let secret_key = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
        let base: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");

        for (threshold, number_of_parties) in
            [(10, 15), (20, 30), (67, 100), (100, 150), (200, 300)]
        {
            let (public_parameters, decryption_key_shares) =
                deal_trusted_shares(threshold, number_of_parties, n, secret_key, base);

            let decryption_key_shares: HashMap<_, _> = decryption_key_shares
                .into_iter()
                .map(|(party_id, share)| {
                    (
                        party_id,
                        DecryptionKeyShare::new(party_id, share, &public_parameters, &mut OsCsRng)
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
                "tiresias",
                c,
                &mut OsCsRng,
            );
        }
    }

    pub(crate) fn benchmark_decryption_key_share_semi_honest(c: &mut Criterion) {
        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let secret_key = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
        let base: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");

        for (threshold, number_of_parties, deltas) in [
            (10, 15, vec![1, 3]),
            (20, 30, vec![2, 5]),
            (67, 100, vec![1, 5, 10, 20]),
        ] {
            let (public_parameters, decryption_key_shares) =
                deal_trusted_shares(threshold, number_of_parties, n, secret_key, base);

            let decryption_key_shares: HashMap<_, _> = decryption_key_shares
                .into_iter()
                .map(|(party_id, share)| {
                    (
                        party_id,
                        DecryptionKeyShare::new(party_id, share, &public_parameters, &mut OsCsRng)
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
                    "tiresias",
                    c,
                    &mut OsCsRng,
                );

                homomorphic_encryption::test_helpers::benchmark_decryption_key_share_semi_honest(
                    threshold,
                    number_of_parties,
                    delta,
                    1,
                    decryption_key_shares.clone(),
                    &public_parameters,
                    false,
                    "tiresias",
                    c,
                    &mut OsCsRng,
                );
            }
        }
    }
}
