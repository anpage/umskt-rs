use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};

const PRODUCT_KEY_LENGTH: usize = 25;

/// The allowed character set in a product key.
///
/// Order is important.
pub(crate) const KEY_CHARSET: [char; 24] = [
    'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y', '2', '3',
    '4', '6', '7', '8', '9',
];

pub(crate) fn base24_decode(cd_key: &str) -> Result<BigUint> {
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

    Ok(y)
}

pub(crate) fn base24_encode(number: &BigUint) -> Result<String> {
    let mut z = number.clone();
    let mut out: VecDeque<char> = VecDeque::new();

    for _ in 0..=24 {
        let (quo, rem) = z.div_rem(&BigUint::from(24_u32));
        z = quo;
        out.push_front(KEY_CHARSET[rem.to_u32().unwrap() as usize]);
    }

    Ok(out.iter().collect())
}

pub(crate) fn strip_key(in_key: &str) -> Result<String> {
    let out_key: String = in_key
        .chars()
        .filter_map(|c| {
            let c = c.to_ascii_uppercase();
            if KEY_CHARSET.into_iter().any(|x| x == c) {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    if out_key.len() == PRODUCT_KEY_LENGTH {
        Ok(out_key)
    } else {
        Err(anyhow!("Invalid key length"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_base24() {
        let input = "JTW3TJ7PFJ7V9CCMX84V9PFT8";
        let unbase24 = super::base24_decode(input).unwrap();
        let base24 = super::base24_encode(&unbase24).unwrap();
        assert_eq!(input, base24);
    }
}
