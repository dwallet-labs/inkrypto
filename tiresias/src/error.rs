// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use group::PartyID;

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("the following protocol error occurred: {0}")]
    ProtocolError(ProtocolError),
    #[error("the following sanity-check error occurred: {0}")]
    SanityCheckError(SanityCheckError),
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
    #[error("homomorphic-encryption error")]
    HomomorphicEncryption(#[from] homomorphic_encryption::Error),
    #[error("mpc error")]
    MPC(#[from] mpc::Error),
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum ProtocolError {
    #[error("the following parties {:?} behaved maliciously by submitting invalid proofs", .0)]
    ProofVerificationError(Vec<PartyID>),
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum SanityCheckError {
    #[error("invalid parameters")]
    InvalidParameters,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::ProtocolError(ProtocolError::ProofVerificationError(malicious_parties)) => {
                mpc::Error::MaliciousMessage(malicious_parties)
            }
            Error::Group(e) => mpc::Error::Group(e),
            Error::InternalError => mpc::Error::InternalError,
            Error::SanityCheckError(SanityCheckError::InvalidParameters) => {
                mpc::Error::InvalidParameters
            }
            Error::MPC(e) => e,
            e => mpc::Error::Consumer(format!("tiresias error {e:?}")),
        }
    }
}
