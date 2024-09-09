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
use std::fmt::Display;

use num_bigint::BigUint;
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

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ConfirmationId([String; 7]);

impl ConfirmationId {
    /// Generates a confirmation ID from the given installation ID
    ///
    /// # Arguments
    /// * `installation_id` - A string with 9 groups of 6 digits, with or without hyphens
    pub fn generate(installation_id: &str) -> ConfidResult<Self> {
        black_box::generate(installation_id)
    }

    fn from_bytes_le(bytes: &[u8]) -> Self {
        let confirmation_id = BigUint::from_bytes_le(bytes)
            .to_radix_be(10)
            .chunks(5)
            .map(|digits| {
                let number = digits.iter().fold(0, |acc, &digit| acc * 10 + digit as u32);
                let checksum = digits
                    .iter()
                    .enumerate()
                    .fold(0, |acc, (i, x)| acc + x * (i as u8 % 2 + 1))
                    % 7;
                format!("{:06}", number * 10 + checksum as u32)
            })
            .collect::<Vec<_>>();
        Self(confirmation_id.try_into().unwrap())
    }

    pub fn group(&self, group: usize) -> &str {
        &self.0[group]
    }
}

impl Display for ConfirmationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let confirmation_id = self.0.join("-");
        write!(f, "{}", confirmation_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_generates_confirmation_ids() {
        assert_eq!(
            ConfirmationId::generate(
                "334481-558826-870862-843844-566221-823392-794862-457401-103810"
            )
            .unwrap()
            .to_string(),
            "110281-200130-887120-647974-697175-027544-252733"
        );

        assert_eq!(
            ConfirmationId::generate(
                "015376-811004-218111-392360-687140-576052-300430-580044-267525"
            )
            .unwrap()
            .to_string(),
            "181431-498050-981512-188303-121962-771530-007354"
        );
    }

    #[test]
    fn it_generates_confirmation_id_v4() {
        assert_eq!(
            ConfirmationId::generate("140360-627153-508674-221690-171243-904021-659581-150052-92")
                .unwrap()
                .to_string(),
            "109062-530373-462923-856922-378004-297663-022353"
        );
    }

    #[test]
    fn it_rejects_too_short() {
        assert!(ConfirmationId::generate(
            "334481-558826-870862-843844-566221-823392-794862-457401-1"
        )
        .is_err_and(|err| err == Error::TooShort),);
    }

    #[test]
    fn it_rejects_too_long() {
        assert!(ConfirmationId::generate(
            "334481-558826-870862-843844-566221-823392-794862-457401-1038100"
        )
        .is_err_and(|err| err == Error::TooLarge),);
    }

    #[test]
    fn it_rejects_invalid_characters() {
        assert!(ConfirmationId::generate(
            "334481-558826-870862-843844-566221-823392-794862-457401-10381!"
        )
        .is_err_and(|err| err == Error::InvalidCharacter),);
    }

    #[test]
    fn it_validates_check_digit_9th() {
        assert!(ConfirmationId::generate(
            "334481-558826-870862-843844-566221-823392-794862-457401-103811"
        )
        .is_err_and(|err| err == Error::InvalidCheckDigit { indices: vec![8] }),);
    }

    #[test]
    fn it_validates_check_digit_4th() {
        assert!(ConfirmationId::generate(
            "334481-558826-870862-843840-566221-823392-794862-457401-103810"
        )
        .is_err_and(|err| err == Error::InvalidCheckDigit { indices: vec![3] }),);
    }

    #[test]
    fn it_validates_check_digits() {
        assert!(ConfirmationId::generate(
            "334481-558826-870862-843840-566221-823390-794862-457401-103810"
        )
        .is_err_and(|err| err
            == Error::InvalidCheckDigit {
                indices: vec![3, 5]
            }),);
    }
}
