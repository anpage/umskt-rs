//! Tools for working with more recent product keys
//!
//! These keys take the form:
//! ```text
//! XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
//! ```
use thiserror::Error;

use crate::key::KeyError;

pub mod bink1998;
pub mod bink2002;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum GenerationError {
    #[error("Something went wrong generating a key. Are the elliptic curve parameters correct?")]
    InvalidParameters,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VerificationError {
    #[error("Product key is in an incorrect format!")]
    BadFormat,
    #[error("Product key is not the correct length!")]
    WrongLength,
    #[error("Something went wrong validating the key. Are the elliptic curve parameters correct?")]
    InvalidParameters,
    #[error("Product key's hash does not match!")]
    HashMismatch,
}

impl From<KeyError> for VerificationError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::InvalidCharacter => VerificationError::BadFormat,
            KeyError::InvalidLength => VerificationError::WrongLength,
        }
    }
}

impl From<bitreader::BitReaderError> for VerificationError {
    fn from(_: bitreader::BitReaderError) -> Self {
        VerificationError::InvalidParameters
    }
}
