// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::{Error, Result};
use serde::Serialize;

/// A transcribeable struct is one which can be transcribed into bytes that uniquely and deterministically capture its value.
/// These bytes should include all required information, e.g. they should perfectly describe the group in the case of implementing this for the public parameters,
/// but should never include optional information, so that two different representations of the same struct will always transcribe to the same bytes.
///
/// Used in cryptographic protocols where public information should be inserted into the transcript.
pub trait Transcribeable: Sized {
    /// The canonical representation of `Self`.
    /// In the case of implementing `Transcribeable` for the public parameters of a group, it perfectly describe the group.
    /// Should never include optional information, so that two different representations of the same struct will always transcribe to the same bytes.
    /// Should never include platform-dependent types, like `usize`, as serializing this from two different targets (including running on different OS & hardware) should equal.
    type CanonicalRepresentation: Serialize + From<Self>;

    /// Transcribe this instance into bytes.
    /// Used in cryptographic protocols where public information should be inserted into the transcript.
    fn transcribe(self) -> Result<Vec<u8>> {
        let canonical_representation: Self::CanonicalRepresentation = self.into();
        let serialized = serde_json::to_string_pretty(&canonical_representation)
            .map_err(|_| Error::Transcription)?;

        Ok(serialized.into_bytes())
    }
}

// Since exporting rust `#[cfg(test)]` is impossible, these test helpers exist in a dedicated feature-gated
// module.
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    pub const SECP256K1_GROUP_PP: &str = "{\n  \"name\": \"Secp256k1\",\n  \"curve_type\": \"Weierstrass\",\n  \"order\": \"414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff\",\n  \"modulus\": \"2ffcfffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\n  \"generator\": \"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\",\n  \"curve_equation_a\": \"0000000000000000000000000000000000000000000000000000000000000000\",\n  \"curve_equation_b\": \"0700000000000000000000000000000000000000000000000000000000000000\"\n}";
    pub const SECP256K1_SCALAR_GROUP_PP: &str = "{\n  \"name\": \"The finite field of integers modulo prime q $\\\\mathbb{Z}_q$\",\n  \"order\": \"414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff\",\n  \"generator\": \"0000000000000000000000000000000000000000000000000000000000000001\"\n}";

    pub const RISTRETTO_GROUP_PP: &str = "{\n  \"name\": \"Ristretto\",\n  \"curve_type\": \"Montgomery\",\n  \"order\": \"edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010\",\n  \"modulus\": \"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f\",\n  \"generator\": [\n    226,\n    242,\n    174,\n    10,\n    106,\n    188,\n    78,\n    113,\n    168,\n    132,\n    169,\n    97,\n    197,\n    0,\n    81,\n    95,\n    88,\n    227,\n    11,\n    106,\n    165,\n    130,\n    221,\n    141,\n    182,\n    166,\n    89,\n    69,\n    224,\n    141,\n    45,\n    118\n  ],\n  \"curve_equation_a\": \"066d070000000000000000000000000000000000000000000000000000000000\",\n  \"curve_equation_b\": \"0100000000000000000000000000000000000000000000000000000000000000\"\n}";
    pub const RISTRETTO_SCALAR_GROUP_PP: &str = "{\n  \"name\": \"The finite field of integers modulo prime q $\\\\mathbb{Z}_q$\",\n  \"order\": \"edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010\",\n  \"generator\": [\n    1,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0,\n    0\n  ]\n}";

    pub fn generate_expected_transcribed_self_product_public_parameters(
        group_public_parameters: &str,
        size: usize,
    ) -> String {
        format!("{{\"canonical_public_parameters\": {group_public_parameters}, \"size\": {size}}}")
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use crate::{direct_product, ristretto, secp256k1, self_product, Transcribeable};

    #[test]
    fn transcribes_secp256k1() {
        let group_public_parameters = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let expected_transcribed_group_pp: Vec<u8> = SECP256K1_GROUP_PP.as_bytes().to_vec();
        let expected_transcribed_scalar_group_pp: Vec<u8> =
            SECP256K1_SCALAR_GROUP_PP.as_bytes().to_vec();

        let transcribed_group_pp = group_public_parameters.transcribe().unwrap();
        let transcribed_scalar_group_pp = scalar_group_public_parameters.transcribe().unwrap();

        assert_eq!(transcribed_group_pp, expected_transcribed_group_pp);
        assert_eq!(
            transcribed_scalar_group_pp,
            expected_transcribed_scalar_group_pp
        );
    }

    #[test]
    fn transcribes_ristretto() {
        let group_public_parameters = ristretto::group_element::PublicParameters::default();
        let scalar_group_public_parameters = ristretto::scalar::PublicParameters::default();

        let expected_transcribed_group_pp: Vec<u8> = RISTRETTO_GROUP_PP.as_bytes().to_vec();
        let expected_transcribed_scalar_group_pp: Vec<u8> =
            RISTRETTO_SCALAR_GROUP_PP.as_bytes().to_vec();

        let transcribed_group_pp = group_public_parameters.transcribe().unwrap();
        let transcribed_scalar_group_pp = scalar_group_public_parameters.transcribe().unwrap();

        assert_eq!(transcribed_group_pp, expected_transcribed_group_pp);
        assert_eq!(
            transcribed_scalar_group_pp,
            expected_transcribed_scalar_group_pp
        );
    }

    #[test]
    fn transcribes_direct_product() {
        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();
        let ristretto_group_public_parameters =
            ristretto::group_element::PublicParameters::default();

        let direct_product_group_public_parameters = direct_product::PublicParameters(
            secp256k1_group_public_parameters,
            ristretto_group_public_parameters,
        );

        let transcribed_pp = direct_product_group_public_parameters.transcribe().unwrap();
        let expected_transcribed_pp =
            format!("[{SECP256K1_GROUP_PP}, {RISTRETTO_GROUP_PP}]").into_bytes();

        assert_eq!(
            transcribed_pp
                .into_iter()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<Vec<_>>(),
            expected_transcribed_pp
                .into_iter()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn transcribes_self_product() {
        let ristretto_group_public_parameters =
            ristretto::group_element::PublicParameters::default();

        let self_product_group_public_parameters =
            self_product::PublicParameters::<42, _>(ristretto_group_public_parameters);

        let transcribed_pp = self_product_group_public_parameters.transcribe().unwrap();
        let expected_transcribed_pp =
            generate_expected_transcribed_self_product_public_parameters(RISTRETTO_GROUP_PP, 42)
                .into_bytes();

        assert_eq!(
            transcribed_pp
                .into_iter()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<Vec<_>>(),
            expected_transcribed_pp
                .into_iter()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<Vec<_>>()
        );
    }
}
