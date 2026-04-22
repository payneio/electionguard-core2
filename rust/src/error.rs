use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("value out of range: {0}")]
    OutOfRange(String),

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("invalid election parameters: {0}")]
    InvalidElection(String),

    #[error("invalid ballot: {0}")]
    InvalidBallot(String),

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("invalid guardian: {0}")]
    InvalidGuardian(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("arithmetic error: {0}")]
    Arithmetic(String),

    #[error("discrete log not found for element (max={0})")]
    DiscreteLogNotFound(u64),
}

pub type Result<T> = std::result::Result<T, Error>;
