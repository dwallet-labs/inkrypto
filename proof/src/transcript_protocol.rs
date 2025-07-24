// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{ConcatMixed, Encoding, Limb, NonZero, Uint};
use group::StatisticalSecuritySizedNumber;
use merlin::Transcript;
use serde::Serialize;

/// A transcript protocol for fiat-shamir transforms of interactive to non-interactive proofs.
pub trait TranscriptProtocol {
    fn serialize_to_transcript_as_json<T: Serialize>(
        &mut self,
        label: &'static [u8],
        message: &T,
    ) -> serde_json::Result<()>;

    fn append_uint<const LIMBS: usize>(&mut self, label: &'static [u8], value: &Uint<LIMBS>)
    where
        Uint<LIMBS>: Encoding;

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS>;

    /// Commit the transcript to a challenge big enough to be reduced uniformly modulo `modulus`.
    /// We use statistical security extra data before reducing to assure uniformity.
    fn uniformly_reduced_challenge<const LIMBS: usize>(
        &mut self,
        label: &'static [u8],
        modulus: &NonZero<Uint<LIMBS>>,
    ) -> Uint<LIMBS>
    where
        Uint<LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
            + for<'a> From<
                &'a <Uint<LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
            >;
}

impl TranscriptProtocol for Transcript {
    fn serialize_to_transcript_as_json<T: Serialize>(
        &mut self,
        label: &'static [u8],
        message: &T,
    ) -> serde_json::Result<()> {
        let serialized_message = serde_json::to_string_pretty(message)?;

        self.append_message(label, serialized_message.as_bytes());

        Ok(())
    }

    fn append_uint<const LIMBS: usize>(&mut self, label: &'static [u8], value: &Uint<LIMBS>)
    where
        Uint<LIMBS>: Encoding,
    {
        self.append_message(label, Uint::<LIMBS>::to_le_bytes(value).as_ref());
    }

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS> {
        let mut buf: Vec<u8> = vec![0u8; LIMBS * Limb::BYTES];
        self.challenge_bytes(label, buf.as_mut_slice());

        Uint::<LIMBS>::from_le_slice(&buf)
    }

    fn uniformly_reduced_challenge<const LIMBS: usize>(
        &mut self,
        label: &'static [u8],
        modulus: &NonZero<Uint<LIMBS>>,
    ) -> Uint<LIMBS>
    where
        Uint<LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
            + for<'a> From<
                &'a <Uint<LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
            >,
    {
        let lo: Uint<LIMBS> = self.challenge(label);
        let hi: StatisticalSecuritySizedNumber =
            self.challenge(b"statistically secure sized challenge used to mask challenge");

        let challenge = lo.concat_mixed(&hi);

        // Resize the modulus to the statistically-masked size by padding with zeros for the high bits.
        let modulus = (*modulus).concat_mixed(&StatisticalSecuritySizedNumber::ZERO);
        let modulus: NonZero<_> = NonZero::new(modulus).unwrap();

        // Now reduce and convert back. `into()` simply takes the low bytes (all high bytes will be zero following the reduction.)
        let reduced_challenge: <Uint<LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput = challenge % modulus;

        (&reduced_challenge).into()
    }
}
