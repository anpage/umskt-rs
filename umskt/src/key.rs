use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};

const PK_LENGTH: usize = 25;

/// The allowed character set in a product key.
pub(crate) const KEY_CHARSET: [char; 24] = [
    'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y', '2', '3',
    '4', '6', '7', '8', '9',
];

pub(crate) fn base24_decode(cd_key: &str) -> Result<Vec<u8>> {
    let decoded_key: Vec<u8> = cd_key
        .chars()
        .filter_map(|c| KEY_CHARSET.iter().position(|&x| x == c).map(|i| i as u8))
        .collect();

    let mut y = BigInt::zero();

    for i in decoded_key {
        y *= PK_LENGTH - 1;
        y += i as u32;
    }

    Ok(y.to_bytes_be().1)
}

pub(crate) fn base24_encode(byte_seq: &[u8]) -> Result<String> {
    let mut z = BigInt::from_bytes_be(Sign::Plus, byte_seq);
    let mut out: VecDeque<char> = VecDeque::new();
    (0..=24).for_each(|_| {
        let (quo, rem) = z.div_rem(&BigInt::from(24));
        z = quo;
        out.push_front(KEY_CHARSET[rem.to_u32().unwrap() as usize]);
    });
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
    if out_key.len() == PK_LENGTH {
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
