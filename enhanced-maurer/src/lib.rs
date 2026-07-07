// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use group::PartyID;
pub use language::{
    EnhanceableLanguage, EnhancedLanguage, EnhancedPublicParameters, PublicParameters,
    StatementSpaceGroupElement, WitnessSpaceGroupElement,
};
pub use proof::Proof;

pub mod aggregation;
pub mod committed_linear_evaluation;
pub mod encryption_of_discrete_log;
pub mod encryption_of_tuple;
pub mod extended_encryption_of_tuple;
pub mod language;
pub mod proof;
pub mod scaling_of_discrete_log;

/// Enhanced-maurer error wrapper that carries a backtrace captured at construction.
///
/// See `group::Error` for details.
#[derive(thiserror::Error, Clone, Debug)]
#[error("{kind}\n{backtrace}")]
pub struct Error {
    pub kind: ErrorKind,
    pub backtrace: std::sync::Arc<std::backtrace::Backtrace>,
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

/// Enhanced-maurer error kind.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ErrorKind {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("mpc error")]
    MPC(#[from] ::mpc::Error),
    #[error("proof error")]
    ProofAggregation(#[from] proof_aggregation::Error),
    #[error("synchronous proof aggregation error")]
    SynchronousProofAggregation(#[from] proof_aggregation::synchronous::Error),
    #[error("maurer error")]
    Maurer(#[from] maurer::Error),
    #[error("maurer aggregation error")]
    MaurerAggregation(#[from] maurer_aggregation::Error),
    #[error("serialization/deserialization error: {0:?}")]
    Serialization(String),
    #[error("randomizer(s) out of range: proof verification failed")]
    OutOfRange,
    #[error(
        "parties {:?} sent mismatching range proof commitments in the Maurer aggregation and range proof aggregation protocols", .0
    )]
    MismatchingRangeProofMaurerCommitments(Vec<PartyID>),
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::from(ErrorKind::Serialization(e.to_string()))
    }
}

/// Maurer result.
pub type Result<T> = std::result::Result<T, Error>;

impl TryInto<::proof::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<::proof::Error, Self::Error> {
        match self.kind {
            ErrorKind::Proof(e) => Ok(e),
            kind => Err(Error {
                kind,
                backtrace: self.backtrace,
            }),
        }
    }
}

impl TryInto<proof_aggregation::synchronous::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<proof_aggregation::synchronous::Error, Self::Error> {
        match self.kind {
            ErrorKind::ProofAggregation(proof_aggregation::Error {
                kind: proof_aggregation::ErrorKind::SynchronousAggregation(e),
                ..
            }) => Ok(e),
            ErrorKind::SynchronousProofAggregation(e) => Ok(e),
            ErrorKind::MaurerAggregation(maurer_aggregation::Error {
                kind: maurer_aggregation::ErrorKind::Aggregation(e),
                ..
            }) => Ok(e),
            ErrorKind::MismatchingRangeProofMaurerCommitments(malicious_parties) => {
                Ok(mpc::Error::from(mpc::ErrorKind::MaliciousMessage(malicious_parties)).into())
            }
            kind => Err(Error {
                kind,
                backtrace: self.backtrace,
            }),
        }
    }
}

impl From<Error> for ::mpc::Error {
    fn from(value: Error) -> Self {
        match value.kind {
            ErrorKind::MPC(e) => e,
            ErrorKind::SynchronousProofAggregation(e) => e.into(),
            ErrorKind::ProofAggregation(proof_aggregation::Error {
                kind: proof_aggregation::ErrorKind::SynchronousAggregation(e),
                ..
            }) => e.into(),
            ErrorKind::MaurerAggregation(maurer_aggregation::Error {
                kind: maurer_aggregation::ErrorKind::Aggregation(e),
                ..
            }) => e.into(),
            ErrorKind::Group(e) => mpc::Error::from(mpc::ErrorKind::Group(e)),
            ErrorKind::InternalError => mpc::Error::from(mpc::ErrorKind::InternalError),
            ErrorKind::InvalidParameters => mpc::Error::from(mpc::ErrorKind::InvalidParameters),
            ErrorKind::InvalidPublicParameters => {
                mpc::Error::from(mpc::ErrorKind::InvalidParameters)
            }
            kind => mpc::Error::from(mpc::ErrorKind::Consumer(format!(
                "enhanced maurer error {kind:?}"
            ))),
        }
    }
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(
    benches,
    encryption_of_tuple::benches::benchmark,
    extended_encryption_of_tuple::benches::benchmark
);
