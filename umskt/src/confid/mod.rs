//! Code to generate a Confirmation ID for a given Installation ID
//!
//! ## History
//! The algorithm this uses was originally provided to the UMSKT project by diamondggg.
//! The history provided by diamondggg is that they are the originator of the code
//! and was created in tandem with an acquaintance who knows number theory.
//! The file dates suggest this code was written sometime in 2017/2018.
//!
//! The Rust version of the code was created by running the original through C2Rust
//! and then manually fixing up the result.
use thiserror::Error;

mod black_box;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("Installation ID is too short.")]
    TooShort,
    #[error("Installation ID is too long.")]
    TooLarge,
    #[error("Invalid character in installation ID.")]
    InvalidCharacter,
    #[error("Installation ID checksum failed. Please check that it is typed correctly.")]
    InvalidCheckDigit { indices: Vec<usize> },
    #[error("Unknown installation ID version.")]
    UnknownVersion(u32),
    #[error("Unable to generate valid confirmation ID.")]
    Unlucky,
}

pub type ConfidResult<T> = Result<T, Error>;

/// Generates a confirmation ID from the given installation ID
///
/// # Arguments
/// * `installation_id` - A string with 9 groups of 6 digits, with or without hyphens
pub fn generate(installation_id: &str) -> ConfidResult<String> {
    black_box::generate(installation_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        assert_eq!(
            generate("334481-558826-870862-843844-566221-823392-794862-457401-103810").unwrap(),
            "110281-200130-887120-647974-697175-027544-252733"
        );
        assert!(
            generate("334481-558826-870862-843844-566221-823392-794862-457401-1")
                .is_err_and(|err| err == Error::TooShort),
        );
        assert!(
            generate("334481-558826-870862-843844-566221-823392-794862-457401-1038100")
                .is_err_and(|err| err == Error::TooLarge),
        );
        assert!(
            generate("334481-558826-870862-843844-566221-823392-794862-457401-10381!")
                .is_err_and(|err| err == Error::InvalidCharacter),
        );
        assert!(
            generate("334481-558826-870862-843844-566221-823392-794862-457401-103811")
                .is_err_and(|err| err == Error::InvalidCheckDigit { indices: vec![8] }),
        );
        assert!(
            generate("334481-558826-870862-843840-566221-823392-794862-457401-103810")
                .is_err_and(|err| err == Error::InvalidCheckDigit { indices: vec![3] }),
        );
        assert!(
            generate("334481-558826-870862-843840-566221-823390-794862-457401-103810").is_err_and(
                |err| err
                    == Error::InvalidCheckDigit {
                        indices: vec![3, 5]
                    }
            ),
        );
    }

    #[test]
    fn test_v4() {
        assert_eq!(
            generate("140360-627153-508674-221690-171243-904021-659581-150052-92").unwrap(),
            "109062-530373-462923-856922-378004-297663-022353"
        );
    }
}
