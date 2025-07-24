// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use crypto_bigint::{Concat, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};
use serde::{Deserialize, Serialize};

use homomorphic_encryption::GroupsPublicParameters;

use crate::equivalence_class::EquivalenceClass;
use crate::setup::SetupParameters;
use crate::Error;
use crate::{CiphertextSpacePublicParameters, RandomnessSpacePublicParameters};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub setup_parameters: SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >,
    pub encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    /// Construct new encryption key public parameters, given
    /// - the setup parameters, and
    /// - an encryption key.
    pub(crate) fn new(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        if encryption_key.is_from_the_same_class_as(&setup_parameters.h) {
            Ok(Self {
                setup_parameters,
                encryption_key,
            })
        } else {
            Err(Error::InvalidEncryptionKey)
        }
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
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

    Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + InvMod<
            Modulus = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Construct new encryption key public parameters, given
    /// - the setup parameters, and
    /// - a secret key.
    pub(crate) fn new_from_secret_key(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        secret_key: Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        // Construct the public key
        // TODO(#46): make const-time; replace pow_vartime by pow_bounded(..., secret_key_max_bits)
        let mut encryption_key = setup_parameters.power_of_h_vartime(&secret_key);
        // safe to vartime; `encryption_key` and `scalar_bits` are public information.
        encryption_key.accelerate_vartime(setup_parameters.scalar_bits())?;

        Ok(Self {
            encryption_key,
            setup_parameters,
        })
    }

    /// Verify whether `self` contains the public key counterpart to `decryption_key`.
    pub(crate) fn belongs_to_secret_key(
        &self,
        decryption_key: &Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> bool {
        self.encryption_key_for_decryption_key(decryption_key) == self.encryption_key
    }

    /// Given a `decryption_key`, construct the `encryption_key` for this ciphertext space.
    pub(crate) fn encryption_key_for_decryption_key(
        &self,
        decryption_key: &Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        // TODO(#46): make const-time; replace pow_vartime by pow
        self.setup_parameters.power_of_h_vartime(decryption_key)
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            ScalarPublicParameters,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    ) -> &GroupsPublicParameters<
        ScalarPublicParameters,
        RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >
    where
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    {
        self.setup_parameters.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{I1024, I2048, U1536, U2048, U320};

    use crate::discriminant::Discriminant;
    use crate::encryption_key::public_parameters::PublicParameters;
    use crate::equivalence_class::EquivalenceClass;
    use crate::ibqf::Ibqf;
    use crate::setup::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::Error;

    #[test]
    fn test_new() {
        const DISCRIMINANT_LIMBS: usize = U2048::LIMBS;
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let pk = EquivalenceClass::try_from(
            Ibqf::new_reduced(
                I1024::from_be_hex(concat![
                    "000000000000000000000000FCB56648A6E9C0C5D16A4A9748C3004489A3DE4A",
                    "32DB0B58C80B800338C2073658709F0B5DA04BB2CEAFD7ABA10C5217118D53D9",
                    "11CD45592BF5E5282609A33EA6C184210840B84CB8D40D03531F4A96415D14EB",
                    "6E69D22313F8F07F97F8B720A6A83DD52AA584C62AA75A485C1D6FC36227AEAB",
                ])
                .resize::<DISCRIMINANT_LIMBS>()
                .to_nz()
                .unwrap(),
                I1024::from_be_hex(concat![
                    "0000000000000000000000001D7A22F94AA507CCABC3472CDBD7882BF1E2767B",
                    "CC36A7B319DD2156EA0CC115B0EA89E20035444F4944BF3BD8571F7A2F8F68D5",
                    "0B5584403815FF9CCD336B1A365B2751941475B2C2BB3A5F421E78B0FECA7838",
                    "18ABD6187472E537C1937A3AEB6D2170D15242ADBCA023AEA5B91B5AD94E5A47",
                ])
                .resize()
                .checked_neg()
                .unwrap(),
                &Discriminant::try_from(
                    I2048::from_be_hex(concat![
                        "00000000000000000000000000000000000000000000001EDEDF5FAD2F9DE421",
                        "30493425D52F867C77B4A43EE225D36DAD1D47A4BB7863A0302F84FADE83C01F",
                        "A7B76FC983273237B800AD535BC47FAFFE49D078F3C44292101450057CDDF2F5",
                        "4EF2C7742952088A20CDBDE03A79E1B320F89690E350176343DB3ABE543A04B3",
                        "E40DF00206E25940BB2D13EDF0230A00ABF5C44A713308301B200CEF2CDEDD90",
                        "CCEA62AF6CB5B3A844B6FB476031A057B4D9B9E824175251A67923411DB48F52",
                        "70410BBB3159CCA561A222BF11CAE1DD79A6993E88774B8F5A8C5BC1FA27AC6B",
                        "C8A97A601381CB32383D9F004E4A7B8AC6D49E2EFAF038F9142319CC247F5C33"
                    ])
                    .resize()
                    .checked_neg()
                    .unwrap()
                    .to_nz()
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let _ = PublicParameters::new(setup_parameters, pk);
    }

    #[test]
    fn test_new_rejects_pk_with_incorrect_discriminant() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();

        let pk = EquivalenceClass::try_from(
            Ibqf::new_reduced(
                I2048::from(5).to_nz().unwrap(),
                I2048::ONE,
                &Discriminant::try_from(I2048::from(-139i32).to_nz().unwrap()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let pp = PublicParameters::new(setup_parameters, pk);

        assert!(pp.is_err());
        matches!(pp.unwrap_err(), Error::InvalidEncryptionKey);
    }

    #[test]
    fn test_new_from_secret_key() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();

        let sk = U320::from_be_hex(
            "2B3C901E8F2016B01DD917911C4EA3FD48EA06668EB7D2DAB2E051B9D82FB2D55D7B3F8471A2622D",
        )
        .resize::<{ U1536::LIMBS }>();
        let pp = PublicParameters::new_from_secret_key(setup_parameters.clone(), sk).unwrap();

        assert_eq!(
            pp.encryption_key.representative(),
            setup_parameters.h.pow(&sk).representative()
        );
    }

    #[test]
    #[ignore]
    fn test_new_from_secret_key_too_large() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();

        let pp = PublicParameters::new_from_secret_key(setup_parameters.clone(), U1536::MAX);
        assert!(pp.is_err());
        matches!(pp.unwrap_err(), Error::InvalidSecretKeySize);
    }

    #[test]
    /// regression test
    fn test_encryption_key_for_decryption_key() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let sk = U320::from_be_hex(
            "2B3C901E8F2016B01DD917911C4EA3FD48EA06668EB7D2DAB2E051B9D82FB2D55D7B3F8471A2622D",
        )
        .resize::<{ U1536::LIMBS }>();

        let pp = PublicParameters::new_from_secret_key(setup_parameters.clone(), sk).unwrap();
        let pk = pp.encryption_key_for_decryption_key(&sk);

        assert_eq!(pk, setup_parameters.h.pow(&sk));
    }
}
