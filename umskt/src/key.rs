use std::collections::VecDeque;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};
use thiserror::Error;

const PRODUCT_KEY_LENGTH: usize = 25;

/// The allowed character set in a product key.
///
/// Order is important.
pub(crate) const KEY_CHARSET: [char; 24] = [
    'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y', '2', '3',
    '4', '6', '7', '8', '9',
];

#[derive(Error, Debug, PartialEq, Eq)]
pub(crate) enum KeyError {
    #[error("Invalid character in key")]
    InvalidCharacter,
    #[error("Invalid key length")]
    InvalidLength,
}

pub(crate) fn base24_decode(cd_key: &str) -> BigUint {
    assert!(cd_key.len() == PRODUCT_KEY_LENGTH);

    let decoded_key: Vec<usize> = cd_key
        .chars()
        .filter_map(|c| KEY_CHARSET.iter().position(|&x| x == c))
        .collect();

    let mut y = BigUint::zero();

    for digit in decoded_key {
        y *= 24_u32;
        y += digit;
    }

    y
}

pub(crate) fn base24_encode(number: &BigUint) -> String {
    let mut z = number.clone();
    let mut out: VecDeque<char> = VecDeque::new();

    for _ in 0..=24 {
        let (quo, rem) = z.div_rem(&BigUint::from(24_u32));
        z = quo;
        out.push_front(KEY_CHARSET[rem.to_u32().unwrap() as usize]);
    }

    out.iter().collect()
}

pub(crate) fn strip_key(in_key: &str) -> Result<String, KeyError> {
    let out_key = in_key
        .chars()
        .filter_map(|c| match c {
            '-' | ' ' => None,
            _ => {
                let c = c.to_ascii_uppercase();
                if KEY_CHARSET.into_iter().any(|x| x == c) {
                    Some(Ok(c))
                } else {
                    Some(Err(KeyError::InvalidCharacter))
                }
            }
        })
        .collect::<Result<String, KeyError>>()?;
    if out_key.len() == PRODUCT_KEY_LENGTH {
        Ok(out_key)
    } else {
        Err(KeyError::InvalidLength)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_base24() {
        let input = "JTW3TJ7PFJ7V9CCMX84V9PFT8";
        let unbase24 = super::base24_decode(input);
        let base24 = super::base24_encode(&unbase24);
        assert_eq!(input, base24);
    }
}
