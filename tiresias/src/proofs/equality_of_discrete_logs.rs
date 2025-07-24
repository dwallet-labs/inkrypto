// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{
    modular::MontyParams, rand_core::CryptoRngCore, MultiExponentiateBoundedExp, NonZero, Odd,
    RandomMod,
};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_proof_of_equality_of_discrete_logs;
use mpc::secret_sharing::shamir::over_the_integers::secret_key_share_size_upper_bound;

use crate::{
    batch_verification::batch_verification,
    proofs::{Error, Result, TranscriptProtocol},
    AsNaturalNumber, AsRingElement, ComputationalSecuritySizedNumber, PaillierModulusSizedNumber,
    PaillierRingElement, ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
    SecretKeyShareSizedNumber,
};

/// A proof of equality of discrete logarithms, utilized to validate threshold
/// decryption performed by the parties.
///
/// This proves the following language:
///         $L_{\EDL^2}[N,\tilde g,a;x] = \{(\tilde h,b) \mid \tilde h\in \ZZ_{N^2}^* \wedge
/// a=\tilde g^{2x} \wedge b=\tilde h^{2x} \}$
///
/// Where, for the usecase of threshold Paillier:
///     - $g'\gets\ZZ_{N^2}^*$ is a random element sampled and published in the setup, and we set
///       $\tilde{g}={g'}^{\Delta_n}$
///     - For prover $P_j$, $a$ is the public verification key $v_j=g^{n!d_j}$.
///     - For prover $P_j$, the witness $x$ is simply its secret key share $d_j$.
///     - $\tilde{h}=\ct^{2n!}\in\ZZ_{N^2}^*$ where $\ct$ is the ciphertext to be decrypted.
///     - For prover $P_j$, $b$ is set to the decryption share of $\ct$, namely,
///       $\ct_j=\ct^{2n!d_j}$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfEqualityOfDiscreteLogs {
    // Base randomizer $u=g^r \in \mathbb{Z}_{N^2}^*$.
    base_randomizer: PaillierModulusSizedNumber,
    // Decryption share base randomizer $v=h^r \in \mathbb{Z}_{N^2}^*$.
    decryption_share_base_randomizer: PaillierModulusSizedNumber,
    // Response $z \in \mathbb{Z}$.
    response: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
}

impl ProofOfEqualityOfDiscreteLogs {
    /// Create a `ProofOfEqualityOfDiscreteLogs` that proves the equality of the discrete logs of $a
    /// a = g^x$ and $b = h^x$ in zero-knowledge (i.e. without revealing the witness `x`).
    /// Implements PROTOCOL 4.1 from Section 4.2. of the paper.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // Witness $x$ (the secret key share $d_j$ in threshold decryption)
        witness: SecretKeyShareSizedNumber,
        // Base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // Decryption share base $\tilde{h}=\ct^{2n!}\in\ZZ_{N^2}^*$ where $\ct$ is the
        // ciphertext to be decrypted
        decryption_share_base: PaillierModulusSizedNumber,
        // Public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // Decryption share $\ct_j=\ct^{2n!d_j}$
        decryption_share: PaillierModulusSizedNumber,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let (base, _, decryption_shares_and_bases, mut transcript) = Self::setup_protocol(
            n2,
            base,
            public_verification_key,
            vec![(decryption_share_base, decryption_share)],
        );

        let (decryption_share_base, _) = decryption_shares_and_bases.first().unwrap();

        Self::prove_inner(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            *decryption_share_base,
            &mut transcript,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_inner(
        n2: PaillierModulusSizedNumber,
        number_of_parties: u16,
        threshold: u16,
        witness: SecretKeyShareSizedNumber,
        base: PaillierModulusSizedNumber,
        decryption_share_base: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let witness_size_upper_bound = secret_key_share_size_upper_bound(
            u32::from(number_of_parties),
            u32::from(threshold),
            PaillierModulusSizedNumber::BITS,
        );

        let randomizer = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::random_mod(
            rng,
            &NonZero::new(
                ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ONE.shl_vartime(
                    witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
                ),
            )
            .unwrap(),
        );

        let base_randomizer = base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &randomizer,
                witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
            )
            .as_natural_number();

        let decryption_share_base_randomizer = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &randomizer,
                witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
            )
            .as_natural_number();

        let challenge = Self::compute_challenge(
            base_randomizer,
            decryption_share_base_randomizer,
            transcript,
        );

        // No overflow can happen here by the choice of sizes in types. See lib.rs
        let challenge: SecretKeyShareSizedNumber = challenge.resize();
        let challenge_multiplied_by_witness: SecretKeyShareSizedNumber =
            witness.wrapping_mul(&challenge);
        let challenge_multiplied_by_witness: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber =
            challenge_multiplied_by_witness.resize();
        let response = randomizer.wrapping_sub(&challenge_multiplied_by_witness);

        ProofOfEqualityOfDiscreteLogs {
            base_randomizer,
            decryption_share_base_randomizer,
            response,
        }
    }

    /// Verify that `self` proves the equality of the discrete logs of $a = g^d$ and $b = h^d$.
    /// Implements PROTOCOL 4.1 from Section 4.2. of the paper.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // The base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // The decryption share base $\tilde{h}=\ct^{2n!}\in\ZZ_{N^2}^*$ where $\ct$ is the
        // ciphertext to be decrypted
        decryption_share_base: PaillierModulusSizedNumber,
        // The public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // The decryption share $\ct_j=\ct^{2n!d_j}$
        decryption_share: PaillierModulusSizedNumber,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let (base, public_verification_key, decryption_shares_and_bases, mut transcript) =
            Self::setup_protocol(
                n2,
                base,
                public_verification_key,
                vec![(decryption_share_base, decryption_share)],
            );

        let (decryption_share_base, decryption_share) =
            decryption_shares_and_bases.first().unwrap();

        self.verify_inner(
            n2,
            number_of_parties,
            threshold,
            base,
            *decryption_share_base,
            public_verification_key,
            *decryption_share,
            &mut transcript,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_inner(
        &self,
        n2: PaillierModulusSizedNumber,
        number_of_parties: u16,
        threshold: u16,
        base: PaillierModulusSizedNumber,
        decryption_share_base: PaillierModulusSizedNumber,
        public_verification_key: PaillierModulusSizedNumber,
        decryption_share: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let witness_size_upper_bound = secret_key_share_size_upper_bound(
            u32::from(number_of_parties),
            u32::from(threshold),
            PaillierModulusSizedNumber::BITS,
        );

        // Every square number except for zero that is not co-primed to $N^2$ yields factorization
        // of $N$, Therefore checking that a square number is not zero sufficiently assures
        // they belong to the quadratic-residue group.
        //
        // Note that if we'd have perform this check prior to squaring, it wouldn't have suffice;
        // take e.g. g = N != 0 -> g^2 = N^2 mod N^2 = 0 (accepting this value would have allowed
        // bypassing of the proof).
        //
        // For self.decryption_share_base_randomizer and self.base_randomizer checking it
        // is non-zero is sufficient and we don't have to check their in the
        // quadratic-residue group otherwise the proof verification formula will fail
        if base == PaillierModulusSizedNumber::ZERO
            || decryption_share_base == PaillierModulusSizedNumber::ZERO
            || public_verification_key == PaillierModulusSizedNumber::ZERO
            || decryption_share == PaillierModulusSizedNumber::ZERO
            || self.base_randomizer == PaillierModulusSizedNumber::ZERO
            || self.decryption_share_base_randomizer == PaillierModulusSizedNumber::ZERO
        {
            return Err(Error::InvalidParameters);
        }

        let challenge: ComputationalSecuritySizedNumber = Self::compute_challenge(
            self.base_randomizer,
            self.decryption_share_base_randomizer,
            transcript,
        )
        .resize();

        // We resize the challenge to be of equal size of the other exponent, the response, so we
        // can use batched_verification().
        let challenge: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber = challenge.resize();

        let bases_lhs = vec![
            vec![base, public_verification_key],
            vec![decryption_share_base, decryption_share],
        ];

        let bases_rhs = vec![
            vec![self.base_randomizer],
            vec![self.decryption_share_base_randomizer],
        ];

        let exponents_lhs = vec![
            (
                self.response,
                witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
            ),
            (challenge, ComputationalSecuritySizedNumber::BITS),
        ];

        if batch_verification::<
            { PaillierModulusSizedNumber::LIMBS },
            { ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::LIMBS },
            { ComputationalSecuritySizedNumber::LIMBS },
        >(
            bases_lhs,
            bases_rhs,
            exponents_lhs,
            vec![],
            MontyParams::new(Odd::new(n2).unwrap()),
            rng,
        )
        .is_ok()
        {
            return Ok(());
        }
        Err(Error::ProofVerificationError())
    }

    fn setup_protocol(
        n2: PaillierModulusSizedNumber,
        base: PaillierModulusSizedNumber,
        public_verification_key: PaillierModulusSizedNumber,
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
    ) -> (
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
        Transcript,
    ) {
        // The paper requires that $a, b, g, h\in QR_{N}$, which is enforced by obtaining their
        // square roots as parameters to begin with. Therefore we perform the squaring to
        // assure it is in the quadratic residue group.
        let base = base
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();

        let public_verification_key = public_verification_key
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();

        let decryption_shares_and_bases: Vec<(
            PaillierModulusSizedNumber,
            PaillierModulusSizedNumber,
        )> = decryption_shares_and_bases
            .iter()
            .map(|(decryption_share_base, decryption_share)| {
                (
                    decryption_share_base
                        .as_ring_element(&n2)
                        .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                        .as_natural_number(),
                    decryption_share
                        .as_ring_element(&n2)
                        .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                        .as_natural_number(),
                )
            })
            .collect();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");

        transcript.append_statement(b"The Paillier modulus $N^2$", &n2);
        transcript.append_statement(b"The base $g$", &base);
        transcript.append_statement(
            b"The public verification key $a=g^x$",
            &public_verification_key,
        );

        decryption_shares_and_bases
            .iter()
            .for_each(|(decryption_share_base, decryption_share)| {
                transcript
                    .append_statement(b"The decryption share base $h$", decryption_share_base);
                transcript.append_statement(b"The decryption share $b=h^x$", decryption_share);
            });

        (
            base,
            public_verification_key,
            decryption_shares_and_bases,
            transcript,
        )
    }

    fn compute_challenge(
        base_randomizer: PaillierModulusSizedNumber,
        decryption_share_base_randomizer: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
    ) -> ComputationalSecuritySizedNumber {
        transcript.append_statement(b"The base randomizer $u=g^r$", &base_randomizer);
        transcript.append_statement(
            b"The decryption share base randomizer $v=h^r$",
            &decryption_share_base_randomizer,
        );

        let challenge: ComputationalSecuritySizedNumber =
            transcript.challenge(b"The challenge $e$");

        challenge
    }

    /// Create a `ProofOfEqualityOfDiscreteLogs` that proves the equality of the discrete logs
    /// of $a = g^x$ and $b=\prod_{i}{b_i^{t_i}}$ where ${{b_i}}_i = {{h_i^x}}_i$
    /// with respects to the bases $g$ and $h_i$ respectively in zero-knowledge (i.e. without
    /// revealing the witness `x`) for every (`decryption_share_base`, `decryption_share`) in
    /// `decryption_shares_and_bases`.
    ///
    /// Implements PROTOCOL 4.2 from Section 4.4. of the paper.
    #[allow(clippy::too_many_arguments)]
    pub fn batch_prove(
        // Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // Witness $d$ (the secret key share in threshold decryption)
        witness: SecretKeyShareSizedNumber,
        // Base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // Public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // Decryption share bases ${\tilde{h_i}}_i={\ct^i^{2n!}\in\ZZ_{N^2}^*}$ where ${\ct^i}$
        // are the ciphertexts to be decrypted and their matching decryption shares
        // ${\ct^i_j}_i = {{\tilde{h_i}^x}}_i$
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ProofOfEqualityOfDiscreteLogs> {
        let (base, _, batched_decryption_share_base, _, mut transcript) =
            Self::setup_batch_protocol(
                n2,
                base,
                public_verification_key,
                decryption_shares_and_bases,
            )?;

        Ok(Self::prove_inner(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            batched_decryption_share_base,
            &mut transcript,
            rng,
        ))
    }

    /// Verify that `self` proves the equality of the discrete logs
    /// of $a = g^x$ and $b=\prod_{i}{b_i^{t_i}}$ where ${{b_i}}_i = {{h_i^x}}_i$
    /// with respects to the bases $g$ and $h_i$ for every (`decryption_share_base`,
    /// `decryption_share`) in `decryption_shares_and_bases`.
    ///
    /// Implements PROTOCOL 4.2 from Section 4.4. of the paper.
    #[allow(clippy::too_many_arguments)]
    pub fn batch_verify(
        &self,
        // Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // Base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // Public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // Decryption share bases ${\tilde{h_i}}_i={\ct^i^{2n!}\in\ZZ_{N^2}^*}$ where ${\ct^i}$
        // are the ciphertexts to be decrypted and their matching decryption shares
        // ${\ct^i_j}_i = {{\tilde{h_i}^d}}_i$
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let (
            base,
            public_verification_key,
            batched_decryption_share_base,
            batched_decryption_share,
            mut transcript,
        ) = Self::setup_batch_protocol(
            n2,
            base,
            public_verification_key,
            decryption_shares_and_bases,
        )?;

        self.verify_inner(
            n2,
            number_of_parties,
            threshold,
            base,
            batched_decryption_share_base,
            public_verification_key,
            batched_decryption_share,
            &mut transcript,
            rng,
        )
    }

    fn setup_batch_protocol(
        n2: PaillierModulusSizedNumber,
        base: PaillierModulusSizedNumber,
        public_verification_key: PaillierModulusSizedNumber,
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
    ) -> Result<(
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        Transcript,
    )> {
        if decryption_shares_and_bases.is_empty() {
            return Err(Error::InvalidParameters);
        }

        let (base, public_verification_key, decryption_shares_and_bases, mut transcript) =
            Self::setup_protocol(
                n2,
                base,
                public_verification_key,
                decryption_shares_and_bases,
            );

        let randomizers: Vec<ComputationalSecuritySizedNumber> = (1..=decryption_shares_and_bases
            .len())
            .map(|_| {
                // The `.challenge` method mutates `transcript` by adding the label to it.
                // Although the same label is used for all values,
                // each value will be a digest of different values
                // (i.e. it will hold different `multiple` of the label inside the digest),
                // and will therefore be unique.
                transcript.challenge(b"challenge")
            })
            .collect();

        let bases_and_exponents: Vec<_> = decryption_shares_and_bases
            .iter()
            .zip(randomizers.iter())
            .map(|((a, _), c)| (a.as_ring_element(&n2), *c))
            .collect();

        let batched_decryption_share_base: PaillierModulusSizedNumber =
            PaillierRingElement::multi_exponentiate_bounded_exp(
                bases_and_exponents.as_slice(),
                ComputationalSecuritySizedNumber::BITS,
            )
            .as_natural_number();

        let bases_and_exponents: Vec<_> = decryption_shares_and_bases
            .iter()
            .zip(randomizers.iter())
            .map(|((_, b), c)| (b.as_ring_element(&n2), *c))
            .collect();

        let batched_decryption_share: PaillierModulusSizedNumber =
            PaillierRingElement::multi_exponentiate_bounded_exp(
                bases_and_exponents.as_slice(),
                ComputationalSecuritySizedNumber::BITS,
            )
            .as_natural_number();

        Ok((
            base,
            public_verification_key,
            batched_decryption_share_base,
            batched_decryption_share,
            transcript,
        ))
    }
}

// This implementation yields invalid proofs, its just so the proof would be usable within a
// `CtOption`.
impl Default for ProofOfEqualityOfDiscreteLogs {
    fn default() -> Self {
        ProofOfEqualityOfDiscreteLogs {
            base_randomizer: PaillierModulusSizedNumber::ZERO,
            decryption_share_base_randomizer: PaillierModulusSizedNumber::ZERO,
            response: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{BASE, CIPHERTEXT, N, WITNESS};
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn valid_proof_verifies() {
        let n2 = N.square();
        let number_of_parties = 3;
        let threshold = 2;
        let n_factorial: u8 = 2 * 3;

        let witness = WITNESS;

        let base = BASE
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();

        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let public_verification_key = base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();
        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();

        let proof = ProofOfEqualityOfDiscreteLogs::prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            decryption_share_base,
            public_verification_key,
            decryption_share,
            &mut OsRng,
        );

        assert!(proof
            .verify(
                n2,
                number_of_parties,
                threshold,
                base,
                decryption_share_base,
                public_verification_key,
                decryption_share,
                &mut OsRng,
            )
            .is_ok());
    }

    #[test]
    fn valid_batched_proof_verifies() {
        let n2 = N.square();
        let number_of_parties = 3;
        let threshold = 2;
        let n_factorial: u8 = 2 * 3;

        let witness = WITNESS;

        let base = BASE
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let public_verification_key = base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();
        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();

        let decryption_shares_and_bases = vec![(decryption_share_base, decryption_share)];

        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            public_verification_key,
            decryption_shares_and_bases.clone(),
            &mut OsRng,
        )
        .unwrap();

        assert!(proof
            .batch_verify(
                n2,
                number_of_parties,
                threshold,
                base,
                public_verification_key,
                decryption_shares_and_bases,
                &mut OsRng,
            )
            .is_ok());

        let ciphertext2: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("07B839504B9E1D94DE3A0B72BB60C6DD17038E493876994B9C7753593368B2FD3D193883852121C127DAF4E575988FA731F52A6AD7617F13F4826EEBD25E278C0E462787D9FFC96B424C2843930C13E61A3B1C2505BF8EDE86FC3E2DBCA31B193ABE12F3840FCFBF8505145A94A794825B8EBE48DF25066997C2C4261925FEE83308EED9FCE8F5CE6E9E9074E7EC145608EED32F5D7FA00E65E63A3879F1B4B63FFEAA71A9E7F531F0A399F25E684A11B3F826680623599B9E1AA7EA00AC9326E1FE6826B7DE7457DF6CDCD94451268D474B412F821217322B77F8ECAB2ADA6EDE7BA4DF9355B13A3D71158F82AFCF16C8A4180BF59BB0CA1C59DC1E884D66DA3F8AA85D65EE9D9C32721843CAC4DCB7DFA83304FFD96280C8CCE464870BF1F5065699A61006011631EBD937B19BAAECD05CE11DA410265878049CFB3E2D1428B10D9C81B6239E221020166A4B72C41EDAA88E340002525B1DF67A7CC4BE21F62D17EEA266DAC7319044AD89BEC39DD77863E936499DCD1D787882939023402B5F5AD440DA8195679672E7E82C9FD0AF40B5184C97C3FBC626B4A32E3C8311492A0D105B7DB49BA39C225C9EB274790D2C40B6B461372CCE8516635D4D65955612A4CBEAE915E2C651282093213624466DF2901E3DF626A0935F1998E532AB01DB56678FD1D49EBEE51B75A31858DA87827A87E7D2FE858B92897B1F748CB27D");
        let decryption_share_base2 = ciphertext2
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let decryption_share2 = decryption_share_base2
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();

        let decryption_shares_and_bases = vec![
            (decryption_share_base, decryption_share),
            (decryption_share_base2, decryption_share2),
        ];

        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            public_verification_key,
            decryption_shares_and_bases.clone(),
            &mut OsRng,
        )
        .unwrap();

        assert!(proof
            .batch_verify(
                n2,
                number_of_parties,
                threshold,
                base,
                public_verification_key,
                decryption_shares_and_bases,
                &mut OsRng,
            )
            .is_ok());
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let n2 = N.square();
        let number_of_parties = 3;
        let threshold = 2;
        let n_factorial: u8 = 2 * 3;

        let base = BASE
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();

        // generate a random proof and make sure it fails
        let wrong_base = PaillierModulusSizedNumber::from_be_hex("391875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_decryption_share_base = PaillierModulusSizedNumber::from_be_hex("458884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_public_verification_key = PaillierModulusSizedNumber::from_be_hex("891875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_decryption_share = PaillierModulusSizedNumber::from_be_hex("058884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_response = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::from_be_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002E8B8B2E3021C0797DA11EC2328DBD27AC756B7244084977EDF04B4F3E5A961173B9E0A61C88A5B5F28A9CCC09662C7465F09E500C7EFD5F901CA266D4FE000371D1C155D5A6A3E8B6CF7285D8FC9DFC28B5A514E61BE42C72387A90071E0DE61EE2EAD808978F02AED94AE02F51192C7A074A726EB19066FC76162054BD1D2BAEAB9C8B0914E8BD4DDB11E62F23634E3D2A33C3DFDD846C68A0A583F0BA1C72AAF090D7E8F04BB2F4E4B71B95339D3B7A936E170CF87BB0CE09C01852CA4438F2903A6D321768839CBAE020AC8112575C7B5C0927F14F717827FC83D030725CEE33E93799D407F8C946310311D3AD00276C9518BBA49C49A13B126496EEA3F50F3979681849DB27767499B99CFAD93CBA5EDCFFED2C4517E659E3812FF07239F403D64E86A99FFCF0DE3D807FE3122A6186B39FFC072D48036626F6ED57D0DE55A267D88AE33B2202F770EB212ED95A6014C2D649182AB48B8A9377192556A2B428D0F3E2300462BFE77D4A8617540665ECB8C25599D5151470DE53ECD4F841FCB7CEF6A5AA8258A278A075245A6AC6B68D319FF97D16BDF10055015E2E4A578559CE7E69ECDCB640D9601D1E0E222F5FC8BD598F1238D1D37EF6B954F151F54168F233F3F996AD630FEAD0B3B4FE33A1A9C82D304F2B47DA3E543586FD3678ACFD731C23622730F1D201312C6F2F64A4523DC73A6EBD48E031D8D5C844A5B7B916817BFF784562591F6F74511DBFFAF8FB");
        let wrong_base_randomizer = PaillierModulusSizedNumber::from_be_hex("1B8DC8C817CAF6ABF6B3BE337E6D723BABFC968213DFC5BE5E9B524B380A58BE0ADB12576177AFC3604D6DC28303D5F5A0B54303B033AA73C10DA59008C6B5806CE3C781096BBB32CBC3E5FF70B62A1D6F0525152E70F8FA5751249EF7B3E21DBB6DD735C11CA6282863B4FDA8FE2C993F03C3D5E008F28218FA57647F0526BCF355CB2D589DA8D2CEED3E2013B55A803300544368AF573184CC7472C9B33CB39B541E2D388384BA86E913A62B6C61D65755FD75CD79B7ACBF41EF8755E8C50C1E9D5D01B0FFCAEA990194EA41FC4591032C79517B10F2DBB23868300B222BE6DFA7B974A7BCAC395CAE72D655F2EDBFF6D6407DF874600CE7688EBFE440336681EA1A44395F67D1CC9D1C092B889D3049465D0FC21C74FA3642018A73C9510FDF6C89CE0AAC3DCC089A3092BC029F518548B2D158FBBDCEA4634D0EEDBA32E2A095886F995F5C3D6C146371F633145823DA4AAA022A62CF7F9D76597F6A550F41FEA5EC7310ED59E1134F5F86B84AFAD4911270361370B3313CD46F01CEDDCAEA1A580F5A4D3C58888F5802BEC2FED81AC7733D3399A5E6D9D3EF8B136906694709E0C0348EF083A0106AC41979289A41B0356362A85BA40A6AEA0191A83E5C48CE580FAA9AE1DE8462E8CEBDCB3BC879C5F5AFB4F2B136E057BFB314AB19CC64018F933647FA18BD4CB6F75BE614708EF748EDBA2A1BEDB115E8BBEB2B96CC");
        let wrong_decryption_share_randomizer = PaillierModulusSizedNumber::from_be_hex("2EAA0D625BD67781CFFCC4563365C37CDCEC8782B451703D4130F7B05E4D080EFF1668E8E96125EE991C45076AB92EFA40232A2C150A96A8DB72F9FB1E7EC57924A13465113ECF9CA575C312C11841C83935B81137B3172C5AB86CCF7EE400D525F5FDA24194F6BCEB4ECDA99EDCE509DDA1B5106EECE1962FFA65FE6B359E5524685ECB5C785B8B0F91744BB2B50EBEE981099AC4B66F6CCF01B1D16F6611D0846EAA44E20C4895CC77CC4CECD1A2AA34CCC97AE0D91C9438FBD0A59A66AB669BD35D78869DD9801C0B13CBBF202F8E21C21B4B76C006DE01A93DC708DE5777B1F305598DEC6552F92DB4166D10B784C6E897579265CA6C48721947F5CF0FC2B65C1EF15A0A62AF54478DD2E3275942A6D2E628C7FD56F1522DD6B251ECD129B93CDC76167A16B52711AB02315EA7D53C0F5F15403AC7BDC1DB3D65D714DA38ED350590D4ACB2B8CC6F4597C4CBCE311F8EA71B3B5783A3C57BACAA7D065EA12190DD982ADC78ECBE0F864016EDB59E9097D6D0DBECAA5F9E8272F1204246059AE42348DC978AF8F0E82BC13940559A7900AE10F343253F97611493EFA673FF74C695476A90FAD5AE734885C86C895F1CFF3E4731A3569F2295B119A46D48632BEB2576D0C0435E49C61FDFA0960C31E79D6BEFF0A1676F8F15A45B3E74B1905035DC3414B812B4253896CB04EDD6C9C4B9822FC2A2A567DEDB3F8730BBD2BD");

        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            base_randomizer: wrong_base_randomizer,
            decryption_share_base_randomizer: wrong_decryption_share_randomizer,
            response: wrong_response,
        };

        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    wrong_public_verification_key,
                    wrong_decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            invalid_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    wrong_public_verification_key,
                    vec![(decryption_share_base, wrong_decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        let witness = WITNESS;

        let public_verification_key = base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();

        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    PaillierModulusSizedNumber::BITS,
                ),
            )
            .as_natural_number();

        // Try to fool verification with zeroed out fields
        let crafted_proof = ProofOfEqualityOfDiscreteLogs {
            base_randomizer: PaillierModulusSizedNumber::ZERO,
            decryption_share_base_randomizer: PaillierModulusSizedNumber::ZERO,
            response: wrong_response,
        };

        assert_eq!(
            crafted_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    PaillierModulusSizedNumber::ZERO,
                    PaillierModulusSizedNumber::ZERO,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::InvalidParameters
        );

        assert_eq!(
            crafted_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    PaillierModulusSizedNumber::ZERO,
                    vec![(decryption_share_base, PaillierModulusSizedNumber::ZERO)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::InvalidParameters
        );

        let two_n: PaillierModulusSizedNumber = N
            .resize()
            .wrapping_mul(&PaillierModulusSizedNumber::from(2u8));

        // Try to fool verification with fields that their square is zero mod N^2 (e.g. N)
        let crafted_proof = ProofOfEqualityOfDiscreteLogs {
            base_randomizer: two_n,
            decryption_share_base_randomizer: two_n,
            response: wrong_response,
        };

        assert_eq!(
            crafted_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    two_n,
                    two_n,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::InvalidParameters
        );

        assert_eq!(
            crafted_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    two_n,
                    vec![(decryption_share_base, two_n)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::InvalidParameters
        );

        // Now generate a valid proof, and make sure that if we change any field it fails
        let valid_proof = ProofOfEqualityOfDiscreteLogs::prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            decryption_share_base,
            public_verification_key,
            decryption_share,
            &mut OsRng,
        );

        let valid_batched_proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            public_verification_key,
            vec![(decryption_share_base, decryption_share)],
            &mut OsRng,
        )
        .unwrap();

        // Assure that verification fails for random values
        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    wrong_base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    wrong_base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    wrong_decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(wrong_decryption_share_base, decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    wrong_public_verification_key,
                    decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    wrong_public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    wrong_decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, wrong_decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.base_randomizer = wrong_base_randomizer;
        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        let mut invalid_batched_proof = valid_batched_proof.clone();
        invalid_batched_proof.base_randomizer = wrong_base_randomizer;
        assert_eq!(
            invalid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_proof = valid_proof.clone();
        invalid_proof.decryption_share_base_randomizer = wrong_decryption_share_randomizer;
        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_batched_proof = valid_batched_proof.clone();
        invalid_batched_proof.decryption_share_base_randomizer = wrong_decryption_share_randomizer;
        assert_eq!(
            invalid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_proof = valid_proof;
        invalid_proof.response = wrong_response;
        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_batched_proof = valid_batched_proof;
        invalid_batched_proof.response = wrong_response;
        assert_eq!(
            invalid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::iter;

    use criterion::Criterion;
    use rand_core::OsRng;

    use crate::LargeBiPrimeSizedNumber;

    use super::*;

    pub(crate) fn benchmark_proof_of_equality_of_discrete_logs(c: &mut Criterion) {
        let mut g = c.benchmark_group("equality of discrete logs");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let n2 = n.square();

        for (threshold, number_of_parties) in [(6, 10), (67, 100), (667, 1000)] {
            let witness_size_upper_bound = secret_key_share_size_upper_bound(
                u32::from(number_of_parties),
                u32::from(threshold),
                PaillierModulusSizedNumber::BITS,
            );
            let witness = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::random_mod(
                &mut OsRng,
                &NonZero::new(
                    ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ONE
                        .shl_vartime(witness_size_upper_bound),
                )
                .unwrap(),
            );

            let base =
                PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
            let ciphertext =
                PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
            let decryption_share_base = ciphertext
                .as_ring_element(&n2)
                .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                .as_natural_number();
            let public_verification_key = base
                .as_ring_element(&n2)
                .pow_bounded_exp(&witness, witness_size_upper_bound)
                .as_natural_number();

            let decryption_share = decryption_share_base
                .as_ring_element(&n2)
                .pow_bounded_exp(&witness, witness_size_upper_bound)
                .as_natural_number();

            g.bench_function(
                format!("prove() for {number_of_parties} parties"),
                |bench| {
                    bench.iter(|| {
                        ProofOfEqualityOfDiscreteLogs::prove(
                            n2,
                            number_of_parties,
                            threshold,
                            witness,
                            base,
                            decryption_share_base,
                            public_verification_key,
                            decryption_share,
                            &mut OsRng,
                        )
                    });
                },
            );

            let proof = ProofOfEqualityOfDiscreteLogs::prove(
                n2,
                number_of_parties,
                threshold,
                witness,
                base,
                decryption_share_base,
                public_verification_key,
                decryption_share,
                &mut OsRng,
            );

            g.bench_function(
                format!("verify() for {number_of_parties} parties"),
                |bench| {
                    bench.iter(|| {
                        assert!(proof
                            .verify(
                                n2,
                                number_of_parties,
                                threshold,
                                base,
                                decryption_share_base,
                                public_verification_key,
                                decryption_share,
                                &mut OsRng,
                            )
                            .is_ok());
                    });
                },
            );

            for batch_size in [10, 100, 1000] {
                let decryption_share_bases = iter::repeat_with(|| {
                    PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap())
                        .as_ring_element(&n2)
                        .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                        .as_natural_number()
                })
                .take(batch_size);

                let decryption_shares_and_bases: Vec<(
                    PaillierModulusSizedNumber,
                    PaillierModulusSizedNumber,
                )> = decryption_share_bases
                    .map(|decryption_share_base| {
                        (
                            decryption_share_base,
                            decryption_share_base
                                .as_ring_element(&n2)
                                .pow_bounded_exp(&witness, witness_size_upper_bound)
                                .as_natural_number(),
                        )
                    })
                    .collect();

                g.bench_function(
                    format!("batch_prove() for {batch_size} decryptions and {number_of_parties} parties"),
                    |bench| {
                        bench.iter(|| {
                            ProofOfEqualityOfDiscreteLogs::batch_prove(
                                n2,
                                number_of_parties,
                                threshold,
                                witness,
                                base,
                                public_verification_key,
                                decryption_shares_and_bases.clone(),
                                &mut OsRng,
                            )
                        });
                    },
                );

                let batched_proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
                    n2,
                    number_of_parties,
                    threshold,
                    witness,
                    base,
                    public_verification_key,
                    decryption_shares_and_bases.clone(),
                    &mut OsRng,
                )
                .unwrap();

                g.bench_function(
                    format!(
                        "batch_verify() for {batch_size} decryptions and {number_of_parties} parties"
                    ),
                    |bench| {
                        bench.iter(|| {
                            assert!(batched_proof
                                .batch_verify(
                                    n2,
                                    number_of_parties,
                                    threshold,
                                    base,
                                    public_verification_key,
                                    decryption_shares_and_bases.clone(),
                                    &mut OsRng,
                                )
                                .is_ok());
                        });
                    },
                );
            }
        }

        g.finish();
    }
}
