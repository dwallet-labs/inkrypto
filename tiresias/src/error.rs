// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use group::PartyID;

/// Tiresias error wrapper that carries a backtrace captured at construction.
///
/// See `group::Error` for details.
#[derive(thiserror::Error, Clone, Debug)]
#[error("{kind}\n{backtrace}")]
pub struct Error {
    pub kind: ErrorKind,
    pub backtrace: std::sync::Arc<std::backtrace::Backtrace>,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl<E> From<E> for Error
where
    ErrorKind: From<E>,
{
    fn from(value: E) -> Self {
        Self {
            kind: ErrorKind::from(value),
            backtrace: std::sync::Arc::new(std::backtrace::Backtrace::capture()),
        }
    }
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum ErrorKind {
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
        match value.kind {
            ErrorKind::ProtocolError(ProtocolError::ProofVerificationError(malicious_parties)) => {
                mpc::Error::from(mpc::ErrorKind::MaliciousMessage(malicious_parties))
            }
            ErrorKind::Group(e) => mpc::Error::from(mpc::ErrorKind::Group(e)),
            ErrorKind::InternalError => mpc::Error::from(mpc::ErrorKind::InternalError),
            ErrorKind::SanityCheckError(SanityCheckError::InvalidParameters) => {
                mpc::Error::from(mpc::ErrorKind::InvalidParameters)
            }
            ErrorKind::MPC(e) => e,
            kind => mpc::Error::from(mpc::ErrorKind::Consumer(format!("tiresias error {kind:?}"))),
        }
    }
}
