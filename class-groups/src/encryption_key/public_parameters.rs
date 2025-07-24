// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use crypto_bigint::subtle::ConstantTimeEq;
use crypto_bigint::{Concat, Encoding, Int, Split, Uint};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::setup::{CanonicalSetupParameters, SetupParameters};
use crate::{
    CiphertextSpacePublicParameters, CompactIbqf, RandomnessSpacePublicParameters,
    HIGHEST_ACCELERATOR_FOLDING_DEGREE,
};
use crate::{Error, DEFAULT_ACCELERATOR_FOLDING_DEGREE};
use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
use group::Transcribeable;
use homomorphic_encryption::{GroupsPublicParameters, GroupsPublicParametersAccessors};
use serde::{Deserialize, Serialize};

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

pub trait Instantiate<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters,
>: Sized where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    /// Construct new encryption key public parameters, given
    /// - the setup parameters, and
    /// - an encryption key
    ///
    /// making sure to accelerate the encryption key with the default folding degree.
    fn new(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error>;

    /// Construct new encryption key public parameters, given
    /// - the setup parameters, and
    /// - an encryption key,
    ///
    /// making sure to accelerate the encryption key with the highest (default) folding degree.
    fn new_maximally_accelerated(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error>;

    /// Construct new encryption key public parameters, given
    /// - the setup parameters, and
    /// - an encryption key,
    ///
    /// making sure to accelerate the encryption key with the given `folding_degree`
    fn new_accelerated(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        folding_degree: u32,
    ) -> Result<Self, Error>;

    /// Construct new encryption key public parameters, given
    /// - the setup parameters, and
    /// - a secret key.
    fn new_from_secret_key(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        secret_key: Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error>;
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    Instantiate<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
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

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    fn new(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        Self::new_accelerated(
            setup_parameters,
            encryption_key,
            DEFAULT_ACCELERATOR_FOLDING_DEGREE,
        )
    }

    fn new_maximally_accelerated(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        Self::new_accelerated(
            setup_parameters,
            encryption_key,
            HIGHEST_ACCELERATOR_FOLDING_DEGREE,
        )
    }

    fn new_accelerated(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        folding_degree: u32,
    ) -> Result<Self, Error> {
        if !encryption_key.is_from_the_same_class_as(&setup_parameters.h) {
            return Err(Error::InvalidEncryptionKey);
        }

        let encryption_key_accelerators = [
            setup_parameters
                .randomness_space_public_parameters()
                .sample_bits,
            setup_parameters
                .randomness_space_public_parameters()
                .sample_bits
                + MAURER_RANDOMIZER_DIFF_BITS,
        ]
        .into_iter()
        .map(|target_bits| {
            encryption_key.get_multifold_accelerator_vartime(folding_degree, target_bits)
        })
        .collect::<crate::Result<_>>()?;

        // Insert the encryption key accelerators into the setup parameters.
        let mut setup_parameters = setup_parameters;
        let equivalence_class_public_parameters =
            setup_parameters.equivalence_class_public_parameters_mut();
        equivalence_class_public_parameters.insert_accelerators_for(
            *encryption_key.representative(),
            encryption_key_accelerators,
        );

        let pp = Self {
            setup_parameters,
            encryption_key,
        };

        Ok(pp)
    }

    /// Construct new encryption key public parameters, given
    /// - the setup parameters, and
    /// - a secret key.
    fn new_from_secret_key(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        secret_key: Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<Self, Error> {
        let encryption_key = setup_parameters.power_of_h_bounded_randomized(
            &secret_key,
            setup_parameters
                .decryption_key_public_parameters
                .sample_bits,
        );
        Self::new_maximally_accelerated(setup_parameters, encryption_key)
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

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Verify whether `self` contains the public key counterpart to `decryption_key`.
    pub(crate) fn belongs_to_secret_key(
        &self,
        decryption_key: &Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        decryption_key_bits: u32,
    ) -> bool {
        self.encryption_key_for_decryption_key(decryption_key, decryption_key_bits)
            .ct_eq(&self.encryption_key)
            .into()
    }

    /// Given a `decryption_key`, construct the `encryption_key` for this ciphertext space.
    pub(crate) fn encryption_key_for_decryption_key(
        &self,
        decryption_key: &Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        decryption_key_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.setup_parameters
            .power_of_h_bounded_randomized(decryption_key, decryption_key_bits)
    }

    /// Obtain read-only access to the `accelerator` for `pk`, or `None` if it does not exist.
    pub(crate) fn get_encryption_key_accelerator(
        &self,
        exp_bits: u32,
    ) -> &MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.setup_parameters
            .equivalence_class_public_parameters()
            .get_accelerator_for(self.encryption_key.representative(), exp_bits)
            .unwrap()
    }

    /// Compute `pk^exponent`
    pub(crate) fn power_of_pk<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let exponent_bits = Uint::<EXPONENT_LIMBS>::BITS;
        let acc = self.get_encryption_key_accelerator(exponent_bits);

        EquivalenceClass::pow_multifold_accelerated(acc, exponent)
    }

    /// Compute `pk^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`
    pub(crate) fn power_of_pk_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let acc = self.get_encryption_key_accelerator(exponent_bits);

        EquivalenceClass::pow_bounded_multifold_accelerated(acc, exponent, exponent_bits)
    }

    /// Compute `pk^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`
    ///
    /// ### Randomized
    /// Assumes `self.encryption_key` to be a random form, thus permitting the use of `*_randomized`
    /// operations during exponentiation.
    pub(crate) fn power_of_pk_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let acc = self.get_encryption_key_accelerator(exponent_bits);

        EquivalenceClass::pow_bounded_multifold_accelerated_randomized(acc, exponent, exponent_bits)
    }

    /// Compute `pk^exponent`
    ///
    /// ### Vartime
    /// This function executes in variable time w.r.t. the encryption key and the `exponent`.
    pub(crate) fn power_of_pk_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let exponent_bits = exponent.bits();
        let acc = self.get_encryption_key_accelerator(exponent_bits);

        EquivalenceClass::pow_multifold_accelerated_vartime(acc, exponent)
    }

    /// Compute `pk^exponent`
    ///
    /// ### Vartime
    /// This function executes in variable time w.r.t. the encryption key and the `exponent`.
    pub(crate) fn power_of_pk_bounded_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let acc = self.get_encryption_key_accelerator(exponent_bits);

        EquivalenceClass::pow_bounded_multifold_accelerated_vartime(acc, exponent, exponent_bits)
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

#[derive(Serialize)]
pub struct CanonicalPublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters: Transcribeable + Serialize,
> where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    canonical_setup_parameters: CanonicalSetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >,
    encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
    >
    From<
        PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
    >
    for CanonicalPublicParameters<
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
    fn from(
        value: PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
    ) -> Self {
        Self {
            canonical_setup_parameters: CanonicalSetupParameters {
                canonical_groups_public_parameters: value
                    .setup_parameters
                    .groups_public_parameters
                    .into(),
                canonical_decryption_key_public_parameters: value
                    .setup_parameters
                    .decryption_key_public_parameters,
                class_group_parameters: value.setup_parameters.class_group_parameters.into(),
                h: value.setup_parameters.h.into(),
                large_message_variant: value.setup_parameters.large_message_variant,
            },
            encryption_key: value.encryption_key.into(),
        }
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
    > Transcribeable
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
    type CanonicalRepresentation = CanonicalPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >;
}

#[cfg(any(test, feature = "test_helpers"))]
mod test_helpers {
    use crypto_bigint::U256;

    use crate::encryption_key::public_parameters::Instantiate;
    use crate::encryption_key::PublicParameters;
    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };
    use crate::{
        Error, RistrettoEncryptionSchemePublicParameters, Secp256k1EncryptionSchemePublicParameters,
    };

    pub(crate) fn get_public_parameters_secp256k1_112_bits_deterministic(
    ) -> Result<Secp256k1EncryptionSchemePublicParameters, Error> {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let sk =
            U256::from_be_hex("3210A845DA6EB09536B427273DB7A15E94A8DAFEEE55D7109C97F6F3CE7DB501");
        let key = sp.power_of_h_vartime(&sk);
        PublicParameters::new_accelerated(sp, key, 7)
    }

    pub(crate) fn get_public_parameters_ristretto_112_bits_deterministic(
    ) -> Result<RistrettoEncryptionSchemePublicParameters, Error> {
        let sp = get_setup_parameters_ristretto_112_bits_deterministic();
        let sk =
            U256::from_be_hex("759BE404D79ECFA35EEB9A06C97015ED3406EC9316E28FE08ABBCFB4AD995DDF");
        let key = sp.power_of_h_vartime(&sk);
        PublicParameters::new_accelerated(sp, key, 7)
    }
}

#[cfg(test)]
mod tests {
    use crate::discriminant::Discriminant;
    use crate::encryption_key::public_parameters::test_helpers::get_public_parameters_secp256k1_112_bits_deterministic;
    use crate::encryption_key::public_parameters::{Instantiate, PublicParameters};
    use crate::ibqf::Ibqf;
    use crate::setup::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::Error;
    use crypto_bigint::{I1024, I2048, U1024, U1536, U2048, U320, U64};
    use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
    use homomorphic_encryption::GroupsPublicParametersAccessors;

    #[test]
    fn test_new() {
        const DISCRIMINANT_LIMBS: usize = U2048::LIMBS;
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let pk = Ibqf::new_is_reduced(
            U1024::from_be_hex(concat![
                "000000000000000000000000DFBC37295A79EF845CB2D079041FD47EBFB24581",
                "11372E1AF9C5D134E0B0F11C0F0FB81110140DE2BD19F1C852083240CA025A32",
                "6F5DC5714D7B2463C7961056C2CF1E3636A536A0554CBEDFC3216225ED946E89",
                "670EAE43B18E2F53917C316B99345F43E793B7A5A515F84D81E5AD33FB1F0250"
            ])
            .to_nz()
            .unwrap(),
            I1024::from_be_hex(concat![
                "0000000000000000000000005058B30D0298471D2D7DA78F88C9B6F54580374F",
                "59880F05447472700705DDFFB45CE2012785DAB176AFCC22B90E75E32F9A51C3",
                "86F365E6ED1D854BB8162E63F23C67F38AADD0BA67E6A50ABD8D808DBDAB1E11",
                "F1C3BC0D4B0DC2826DF5CEEDF13E59478728F3D216201D1A479A9039A6CD71AF",
            ])
            .checked_neg()
            .unwrap(),
            &setup_parameters.class_group_parameters.delta_qk,
        )
        .unwrap()
        .into();

        let _ = PublicParameters::new(setup_parameters, pk).unwrap();
    }

    #[test]
    fn test_new_accelerated() {
        const DISCRIMINANT_LIMBS: usize = U2048::LIMBS;
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let sk = U64::from_be_hex("D949E524A523501A");
        let pk = setup_parameters.power_of_h_vartime(&sk);
        let pp = PublicParameters::new_accelerated(setup_parameters, pk, 10).unwrap();

        let acc =
            pp.get_encryption_key_accelerator(pp.randomness_space_public_parameters().sample_bits);

        let randomizer_acc = pp.get_encryption_key_accelerator(
            pp.randomness_space_public_parameters().sample_bits + MAURER_RANDOMIZER_DIFF_BITS,
        );
        assert!(acc.target_bits < randomizer_acc.target_bits);

        let exp = U64::from_be_hex("3E6E16338064C184");
        assert_eq!(pp.power_of_pk_vartime(&exp), pk.pow_vartime(&exp));
    }

    #[test]
    fn test_new_rejects_pk_with_incorrect_discriminant() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();

        let pk = Ibqf::new_is_reduced(
            U1024::from_u64(5).to_nz().unwrap(),
            I1024::ONE,
            &Discriminant::try_from(I2048::from(-139i32).to_nz().unwrap()).unwrap(),
        )
        .unwrap()
        .into();

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

        let target_key = setup_parameters.h.pow_vartime(&sk);

        let pp = PublicParameters::new_from_secret_key(setup_parameters, sk).unwrap();
        assert_eq!(pp.encryption_key, target_key);
    }

    #[test]
    #[ignore]
    fn test_new_from_secret_key_too_large() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();

        let pp = PublicParameters::new_from_secret_key(setup_parameters.clone(), U1536::MAX);
        assert!(pp.is_ok());
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
        let pk = pp.encryption_key_for_decryption_key(&sk, 320);

        let target = setup_parameters.h.pow_vartime(&sk);
        assert_eq!(pk, target);
    }

    #[test]
    fn test_power_of_pk() {
        let pp = get_public_parameters_secp256k1_112_bits_deterministic().unwrap();
        let exp = U64::from_be_hex("0A08FA96309441E6");

        assert_eq!(pp.power_of_pk(&exp), pp.encryption_key.pow_vartime(&exp));
    }

    #[test]
    fn test_power_of_pk_bounded() {
        let pp = get_public_parameters_secp256k1_112_bits_deterministic().unwrap();
        let exp = U64::from_be_hex("5D987544B1027206");
        let bound = 57;

        assert_eq!(
            pp.power_of_pk_bounded(&exp, bound),
            pp.encryption_key.pow_bounded_vartime(&exp, bound)
        );
    }

    #[test]
    fn test_power_of_pk_vartime() {
        let pp = get_public_parameters_secp256k1_112_bits_deterministic().unwrap();
        let exp = U64::from_be_hex("6FA154F98DD001A2");

        assert_eq!(
            pp.power_of_pk_vartime(&exp),
            pp.encryption_key.pow_vartime(&exp)
        );
    }
}
