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
pub enum ConfirmationIdError {
    #[error("Installation ID is too short.")]
    TooShort,
    #[error("Installation ID is too long.")]
    TooLarge,
    #[error("Invalid character in installation ID.")]
    InvalidCharacter,
    #[error("Installation ID checksum failed. Please check that it is typed correctly.")]
    InvalidCheckDigit,
    #[error("Unknown installation ID version.")]
    UnknownVersion,
    #[error("Unable to generate valid confirmation ID.")]
    Unlucky,
}

/// Generates a confirmation ID from the given installation ID
///
/// # Arguments
/// * `installation_id` - A string with 7 groups of 6 digits, with or without hyphens
pub fn generate(installation_id: &str) -> Result<String, ConfirmationIdError> {
    if installation_id.len() < 54 {
        return Err(ConfirmationIdError::TooShort);
    }
    if installation_id.len() > 54 {
        return Err(ConfirmationIdError::TooLarge);
    }
    let inst_id = installation_id.as_bytes();
    let mut conf_id = [0u8; 48];
    let result = black_box::generate(inst_id, &mut conf_id);
    match result {
        0 => {}
        1 => return Err(ConfirmationIdError::TooShort),
        2 => return Err(ConfirmationIdError::TooLarge),
        3 => return Err(ConfirmationIdError::InvalidCharacter),
        4 => return Err(ConfirmationIdError::InvalidCheckDigit),
        5 => return Err(ConfirmationIdError::UnknownVersion),
        6 => return Err(ConfirmationIdError::Unlucky),
        _ => panic!("Unknown error code: {}", result),
    }
    Ok(String::from_utf8_lossy(&conf_id).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        assert_eq!(
            generate("334481558826870862843844566221823392794862457401103810").unwrap(),
            "110281-200130-887120-647974-697175-027544-252733"
        );
        assert!(
            generate("33448155882687086284384456622182339279486245740110381")
                .is_err_and(|err| err == ConfirmationIdError::TooShort),
        );
        assert!(
            generate("3344815588268708628438445662218233927948624574011038100")
                .is_err_and(|err| err == ConfirmationIdError::TooLarge),
        );
        assert!(
            generate("33448155882687086284384456622182339279486245740110381!")
                .is_err_and(|err| err == ConfirmationIdError::InvalidCharacter),
        );
        assert!(
            generate("334481558826870862843844566221823392794862457401103811")
                .is_err_and(|err| err == ConfirmationIdError::InvalidCheckDigit),
        );
    }
}
