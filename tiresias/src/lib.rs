// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#[cfg(feature = "benchmarking")]
use criterion::criterion_group;
use crypto_bigint::{
    modular::{MontyForm, MontyParams},
    Concat, Limb, Odd, Uint, U1024,
};

pub use ::group::ComputationalSecuritySizedNumber;
pub use decryption_key::DecryptionKey;
pub use decryption_key_share::DecryptionKeyShare;
pub use encryption_key::EncryptionKey;
pub use error::{Error, ProtocolError, Result, SanityCheckError};
pub use group::{
    CiphertextSpaceGroupElement, CiphertextSpacePublicParameters, CiphertextSpaceValue,
    PlaintextSpaceGroupElement, PlaintextSpacePublicParameters, PlaintextSpaceValue,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters, RandomnessSpaceValue,
    CIPHERTEXT_SPACE_SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, RANDOMNESS_SPACE_SCALAR_LIMBS,
};
use mpc::secret_sharing::shamir::over_the_integers::{
    find_closest_crypto_bigint_size, secret_key_share_size_upper_bound, MAX_PLAYERS,
};

mod batch_verification;
mod decryption_key;
pub mod decryption_key_share;
pub mod encryption_key;
mod error;
mod group;
pub mod proofs;

// Being overly-conservative here
pub type StatisticalSecuritySizedNumber = ComputationalSecuritySizedNumber;

/// A type alias for an unsigned integer of the size of the Paillier large prime factors.
/// Set to a U1024 for 112-bit security.
pub type LargePrimeSizedNumber = U1024;

/// A type alias for an unsigned integer of the size of the Paillier associated bi-prime `n` ($N$)
/// (double the size of the Paillier large prime factors). Set to a U2048 for 112-bit security.
pub type LargeBiPrimeSizedNumber = <LargePrimeSizedNumber as Concat>::Output;

/// A type alias for an unsigned integer of the size of the Paillier modulus ($N^2$) (double the
/// size of the Paillier associated bi-prime `n` ($N$)). Set to a U4096 for 112-bit security.
pub type PaillierModulusSizedNumber = <LargeBiPrimeSizedNumber as Concat>::Output;

pub(crate) type PaillierRingElement = MontyForm<{ PaillierModulusSizedNumber::LIMBS }>;
pub(crate) type PaillierPlaintextRingElement = MontyForm<{ LargeBiPrimeSizedNumber::LIMBS }>;

pub const SECRET_KEY_SHARE_SIZE_UPPER_BOUND: u32 =
    secret_key_share_size_upper_bound(MAX_PLAYERS, MAX_PLAYERS, PaillierModulusSizedNumber::BITS);

pub const SECRET_KEY_SHARE_LIMBS: usize =
    find_closest_crypto_bigint_size(SECRET_KEY_SHARE_SIZE_UPPER_BOUND as usize)
        / Limb::BITS as usize;

pub type SecretKeyShareSizedNumber = Uint<SECRET_KEY_SHARE_LIMBS>;

pub(crate) type ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber = Uint<
    {
        find_closest_crypto_bigint_size(
            (SECRET_KEY_SHARE_SIZE_UPPER_BOUND + 2 * (ComputationalSecuritySizedNumber::BITS))
                as usize,
        ) / (Limb::BITS as usize)
    },
>;

/// Retrieve the minimal natural number in the congruence class.
pub(crate) trait AsNaturalNumber<T> {
    fn as_natural_number(&self) -> T;
}

/// Represent this natural number as the minimal member of the congruence class.
/// I.e., as a member of the ring $\mathbb{Z}_{n}$
pub(crate) trait AsRingElement<T> {
    fn as_ring_element(&self, n: &Self) -> T;
}

impl AsNaturalNumber<PaillierModulusSizedNumber> for PaillierRingElement {
    fn as_natural_number(&self) -> PaillierModulusSizedNumber {
        self.retrieve()
    }
}

impl AsRingElement<PaillierRingElement> for PaillierModulusSizedNumber {
    fn as_ring_element(&self, n: &Self) -> PaillierRingElement {
        let ring_params = MontyParams::new(Odd::new(*n).unwrap());
        MontyForm::new(self, ring_params)
    }
}

impl AsNaturalNumber<LargeBiPrimeSizedNumber> for PaillierPlaintextRingElement {
    fn as_natural_number(&self) -> LargeBiPrimeSizedNumber {
        self.retrieve()
    }
}

impl AsRingElement<PaillierPlaintextRingElement> for LargeBiPrimeSizedNumber {
    fn as_ring_element(&self, n: &Self) -> PaillierPlaintextRingElement {
        let ring_params = MontyParams::new(Odd::new(*n).unwrap());
        MontyForm::new(self, ring_params)
    }
}

#[cfg(any(test, feature = "test_helpers"))]
#[allow(dead_code)]
#[allow(unused_imports)]
pub mod test_helpers {
    use crypto_bigint::NonZero;
    use rstest::rstest;

    pub use decryption_key_share::test_helpers::*;
    use mpc::secret_sharing::shamir::over_the_integers::{const_log, factorial_upper_bound};

    use super::*;

    pub(crate) const N2: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("5960383b5378ad0607f0f270ce7fb6dcaba6506f9fc56deeffaf605c9128db8ccf063e2e8221a8bdf82c027741a0303b08eb71fa6225a03df18f24c473dc6d4d3d30eb9c52a233bbfe967d04011b95e8de5bc482c3c217bcfdeb4df6f57af6ba9c6d66c69fb03a70a41fe1e87975c85343ef7d572ca06a0139706b23ed2b73ad72cb1b7e2e41840115651897c8757b3da9af3a60eebb6396ffd193738b4f04aa6ece638cef1bf4e9c45cf57f8debeda8598cbef732484752f5380737ba75ee00bf1b146817b9ab336d0ce5540395377347c653d1c9d272127ff12b9a0721b8ef13ecd8a8379f1b9a358de2af2c4cd97564dbd5328c2fc13d56ee30c8a101d333f5406afb1f4417b49d7a629d5076726877df11f05c998ae365e374a0141f0b99802214532c97c1ebf9faf6e277a8f29dbd8f3eab72266e60a77784249694819e42877a5e826745c97f84a5f37002b74d83fc064cf094be0e706a6710d47d253c4532e6aa4a679a75fa1d860b39085dab03186c67248e6c92223682f58bd41b67143e299329ce3a8045f3a0124c3d0ef9f0f49374d89b37d9c3321feb2ab4117df4f68246724ce41cd765326457968d848afcc0735531e5de7fea88cf2eb35ac68710c6e79d5ad25df6c0393c0267f56e8eac90a52637abe3e606769e70b20560eaf70e0d531b11dca299104fa933f887d85fb5f72386c196e40f559baee356b9");
    pub(crate) const PLAINTEXT: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("23f6379f4b0435dd50c0eb12454495c99db09aed97fe498c0dba7c51f6c52ab7b8d8ba47896ee0c43d567a1b3611cb2d53ee74574acc9c4520106c0f6e5d0376817febb477bb729405387b6ae6e213b3b34c0eb0cbe5dff49452979ab7f0b514560b5c9b659732efd0d67a3d7b7512a5d97f1bde1c2263f741838a7c62d78133396715c9568c0524e20a3147cda4510ef2f32cefa6fb92caf3a26da63aba3693efce706303fe399b6c86664b1ccaa9fe6e1505d82c4dd9b0a60ea29ec88a91bf2656a3927ad39d561bfe4009f94398a9a7782383f063adeb922275efd950ef3739dee7854bbf93f939a947e3aec7344135e6b0623aff35e802311c10ede8b0d4");
    pub(crate) const RANDOMNESS: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("4aba7692cfc2e1a30d46dc393c4d406837df82896da97268b377b8455ce9364d93ff7d0c051eed84f2335eeae95eaf5182055a9738f62d37d06cf4b24c663006513c823418d63db307a96a1ec6c4089df23a7cc69c4c64f914420955a3468d93087feedea153e05d94d184e823796dd326f8f6444405665b9a6af3a5fedf4d0e787792667e6e73e4631ea2cbcf7baa58fff7eb25eb739c31fadac1cd066d97bcd822af06a1e4df4a2ab76d252ddb960bbdc333fd38c912d27fa775e598d856a87ce770b1379dde2fbfce8d82f8692e7e1b33130d556c97b690d0b5f7a2f8652b79a8f07a35d3c4b9074be68daa04f13e7c54124d9dd4fe794a49375131d9c0b1");
    pub(crate) const CIPHERTEXT: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("0d1a2a781bf90133552b120beb2745bbe02b47cc4e5cc65b6eb5294770bd44b52ce581c4aec199687283360ab0c46bb3f0bb33733dbbf2d7e95a7c600ed20e990e8c3133f7ec238c0b47882363df7748757717443a3d1f9e85f0fb27e665844f591a0f922f42436688a72a71bdf7e93c764a84aff5b813c034787f5cf35a7102fe3be8c670ac26b83b08dabca47d9156ce09d7349ac73d269b7355d5266720654b83b09857add1a6c0be4677115f461ea15907e1472d3d7dcde351f9eff7e43968ae7012a67eeca940c25d3dd5694c5bbf1ed702bfd2094e424bb17bbf00270ded29320cd2e50af2283121ecf5f8593de49b18e465f3b1e1a39daca4d7382e4a610bdbd21dfd343108085b6e2c743f295df3785d3766b56c36efc0ea10ba3de8c16c43fcc051e7c27d835a481c0fdd48819ca9398043689027b00b275ca048018788a5133b280981afb0d6da7e64f3cf5f9e39e501fe7b80807b872ece22f6e4b6b0d8279656ceef614c87ce7ee314a339ef44c3adc4f5e5451b2649c215a358c0682095e19d52ed454d5f4e364397928996823cb02c61f8304561cb21e3bd0f4399f283b0b1ded686ace5dc653b240760c6437323fab45418b904d2eef8ab0639b4cba7cccee58f471413505ca0f8bb5a859769ad9465ddac949d22114cacaeadb72962816c49f50adc6338da7a54bdda29f8e6e667d832bd9c9f9841be8b18");
    pub(crate) const WITNESS: SecretKeyShareSizedNumber = SecretKeyShareSizedNumber::from_be_hex("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000442E59937C26CA8FB8304D9D033DD2BE802BE39CC2CBACEED490DC3BB3F11B601F7C5BF1355368E5BF32CFDD3BD2144CF05B0EDD727C5D406DBAC7B3B85C24F3A77AD9F234493D896ECF7AC88114EE23A25C74704CEEDCCB5835832C75395798584FC64F249CA32170CF269E1C109903331A22D3E797C1179A73A1A2CC92BA326D99CC55EEC865667138273355FC7D5984212FD2C1E08549AFA9CAB43417A58648EF7B0BDF86D6608E03D0BE3393C3D3D5A5B954E956F114D3D65851FF3CBFE62DD75FF18D1C9B776C67641A4F8719B84A2BB5754714F6EEDCCDD03D9E0FBC5B859E844B7AF305FC5F050FAC028E4C5D380B4E00DD1C9D6E4CDBFAA8B9258E0DDBE5880F9D4F50C9D319F3992DE7CE98F4A88208556F8114183CE76472DC19E1DB5AC3938A2A756EB73F381AD6537231FD69CEBE19DA221323A66A3DE24B30B2497F6BB56387CDABBC3F4BDCE0F1AC85DB0A4DDE540063E95A5C0AFD61BCAC2C9BE4C07A3F35D5BD3520013A624BA93C5954C0C2C0652B30C860403BBDE03B227183E97A02F3BA3F2E9769D8C0F5C23F1DA790CBBE7E441A5B3E48889E8079547B7A0D7BB0DEC0752EC839A1CC84DBC23CAA31C6F1C60367EB2D50616942AA84B42720C3E1A7F5F14FEAA49D9422936F89AB507EE5FED3462E9220A1219BDA559921D0950B9BC7ECD6746E10C8C4D3A32220AECAC99CCAD7D2369B56985F9E29D544F267EDD5B7B2");

    fn factorial(num: u16) -> u64 {
        (1u64..=u64::from(num)).product()
    }

    #[test]
    fn as_natural_number_and_as_natural_number_circles_correctly() {
        let x = PaillierModulusSizedNumber::from_be_hex("19BB1B2E0015AA04BEE4F8321819448A2C809DF799C6627668DAA936E3A367CF87BEC43C47551221E40724FE115FF8A4E72D5D46A0E98A934C45CD6904DA0F07499D798EE611497C9493354A9A48C35ECB6318CA55B8322E4295E67F8BC0BE1E0923685E1727B7925920D4F0E9CC30C2A10135DB447EDAD3BCE87C3416252C8B4DF32C24029E0269E7103E80D02DD5A42A99B69A613C6274255DF0599B0DED35A8969463636C6D56D67A05AE11F347A5D5B81896DF5F8A52E6EA7F05359A9FEFC90297BDD298DD77714D3557325DF1C52F42470606ECBFA5E964C0A782AE19CED2E20C73F0438EB597CAE4159B5E5333C97272D8EFEDB49CEB98078E92D990076E6E4101FD97588E4BBAA9DD5D19C671424108EE7FA5F2D74F9F3DEAB4A0AC89CF9833FD9BA1F66719978D7BD13DD2ECDE2BDC9628B1AC1E0A0C44B1408E8869A8B2245DF2A877E01730500AD15466A808E6D9636EEA7A7A0A06568413408E588C52451D189774D84547FBB4171255D6E0BFC9B63C56D582E02FA0F110EEAA2B728E51BC85F529805EBA5E1D6B7323597F1647B0A3DC6D61448C1C062CADE9831DB9E3029322D79D04BB3287B7C5D857AE11802B68921FBC403E390ED693DEAD66E1A728B7F7432408EB2ED9EB9BC3B2BCD8EB2CD44D41A5EBFB32F55BAF47D3AC048F5D1F60B2CB61C0F4E3C178DC7723B8298E9D52771DCF1DABA4088EF74B");
        let x = x % NonZero::new(N2).unwrap();

        assert_eq!(x.as_ring_element(&N2).as_natural_number(), x);
    }

    #[test]
    fn const_log_computes_correctly() {
        assert_eq!(const_log(1), 0);
        assert_eq!(const_log(2), 1);
        assert_eq!(const_log(3), 2);
        assert_eq!(const_log(4), 2);
        assert_eq!(const_log(5), 3);
        assert_eq!(const_log(6), 3);
        assert_eq!(const_log(7), 3);
        assert_eq!(const_log(8), 3);
        assert_eq!(const_log(9), 4);
    }

    #[rstest]
    #[case::n(1)]
    #[case::n(2)]
    #[case::n(5)]
    #[case::n(15)]
    fn n_factorial_is_bounded_correctly(#[case] n: u16) {
        assert!(factorial(n) < 2u64.pow(factorial_upper_bound(u32::from(n))))
    }
}

#[cfg(feature = "benchmarking")]
criterion_group!(
    benches,
    decryption_key_share::benchmark_decryption_key_share_semi_honest,
    decryption_key_share::benchmark_decryption_key_share,
    proofs::benchmark_proof_of_equality_of_discrete_logs,
    group::multiplicative::benches::benchmark
);
