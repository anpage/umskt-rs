//! Structs to deal with newer BINK (>= `0x40`) product keys
use std::fmt::{Display, Formatter};

use bitreader::BitReader;
use num_bigint::{BigInt, BigUint, RandomBits};
use num_integer::Integer;
use num_traits::ToPrimitive;
use rand::{thread_rng, Rng};
use sha1::{Digest, Sha1};

use crate::{
    crypto::{mod_sqrt, EllipticCurve, Point, PrivateKey},
    key::{base24_decode, base24_encode, strip_key},
    math::{bitmask, extract_bits, extract_ls_bits},
};

use super::{GenerationError, VerificationError};

const FIELD_BITS: u64 = 512;
const FIELD_BYTES: usize = 64;
const SHA_MSG_LENGTH: usize = 3 + 2 * FIELD_BYTES;
const AUTH_INFO_MAX: u32 = 1023;

const SIGNATURE_LENGTH_BITS: u8 = 62;
const HASH_LENGTH_BITS: u8 = 31;
const CHANNEL_ID_LENGTH_BITS: u8 = 10;
const UPGRADE_LENGTH_BITS: u8 = 1;
const EVERYTHING_ELSE: u8 =
    SIGNATURE_LENGTH_BITS + HASH_LENGTH_BITS + CHANNEL_ID_LENGTH_BITS + UPGRADE_LENGTH_BITS;

/// A product key for a BINK ID `0x40` or higher
///
/// Every `ProductKey` contains a valid key for its given parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductKey {
    upgrade: bool,
    channel_id: u32,
    hash: u32,
    signature: u64,
    auth_info: u32,
}

impl ProductKey {
    /// Generates a new product key for the given parameters.
    ///
    /// The generated key is guaranteed to be valid.
    pub fn new(
        curve: &EllipticCurve,
        private_key: &PrivateKey,
        channel_id: u32,
        auth_info: Option<u32>,
        upgrade: Option<bool>,
    ) -> Result<Self, GenerationError> {
        // Generate random auth info if none supplied
        let auth_info = auth_info.unwrap_or_else(|| thread_rng().gen::<u32>() % AUTH_INFO_MAX);

        // Default to upgrade=false
        let upgrade = upgrade.unwrap_or(false);

        // Generate a new random key
        let product_key = Self::generate(
            curve,
            &curve.gen_point,
            &private_key.gen_order,
            &private_key.private_key,
            channel_id,
            auth_info,
            upgrade,
        )?;

        // Ship it
        Ok(product_key)
    }

    /// Validates an existing product key string and tries to create a new `ProductKey` from it.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve to use for verification.
    /// * `key` - Should be 25 characters long, not including the (optional) hyphens.
    pub fn from_key(curve: &EllipticCurve, key: &str) -> Result<Self, VerificationError> {
        let key = strip_key(key)?;
        let packed_key = base24_decode(&key);
        let product_key = Self::from_packed(&packed_key)?;
        product_key.verify(curve, &curve.gen_point, &curve.pub_point)?;
        Ok(product_key)
    }

    fn generate(
        e_curve: &EllipticCurve,
        base_point: &Point,
        gen_order: &BigInt,
        private_key: &BigInt,
        channel_id: u32,
        auth_info: u32,
        upgrade: bool,
    ) -> Result<Self, GenerationError> {
        let data = channel_id << 1 | upgrade as u32;

        let key = loop {
            let seed: BigUint = thread_rng().sample(RandomBits::new(FIELD_BITS));
            let mut seed: BigInt = seed.into();

            let hash = {
                let r = e_curve.multiply_point(&seed, base_point);

                let Point::Point { x, y } = r else {
                    return Err(GenerationError::InvalidParameters);
                };

                let x_bin = x.to_bytes_le().1;
                if x_bin.len() > FIELD_BYTES {
                    log::info!("x is too big somehow, retrying...");
                    continue;
                }

                let y_bin = y.to_bytes_le().1;
                if y_bin.len() > FIELD_BYTES {
                    log::info!("y is too big somehow, retrying...");
                    continue;
                }

                let mut msg_buffer = [0; SHA_MSG_LENGTH];
                msg_buffer[0x00] = 0x79;
                msg_buffer[1..3].copy_from_slice(&data.to_le_bytes()[0..2]);
                msg_buffer[3..3 + x_bin.len()].copy_from_slice(&x_bin);
                msg_buffer[3 + FIELD_BYTES..3 + FIELD_BYTES + y_bin.len()].copy_from_slice(&y_bin);

                let msg_digest = {
                    let mut hasher = Sha1::new();
                    hasher.update(msg_buffer);
                    hasher.finalize()
                };

                extract_ls_bits(u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()), 31)
            };

            let mut msg_buffer = [0; 11];
            msg_buffer[0] = 0x5D;
            msg_buffer[1..3].copy_from_slice(&data.to_le_bytes()[0..2]);
            msg_buffer[3..7].copy_from_slice(&hash.to_le_bytes());
            msg_buffer[7..9].copy_from_slice(&auth_info.to_le_bytes()[0..2]);

            let msg_digest = {
                let mut hasher = Sha1::new();
                hasher.update(msg_buffer);
                hasher.finalize()
            };

            let i_signature = extract_bits(
                u32::from_le_bytes(msg_digest[4..8].try_into().unwrap()) as u64,
                30,
                2,
            ) << 32
                | u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()) as u64;

            let mut e = BigInt::from(i_signature);

            e = (e * private_key).mod_floor(gen_order);

            let mut s = e.clone();

            s = (&s * &s).mod_floor(gen_order);

            seed <<= 2;

            s = &s + &seed;

            let Some(mut s) = mod_sqrt(&s, gen_order) else {
                continue;
            };

            s = (s - e).mod_floor(gen_order);

            if s.is_odd() {
                s = &s + gen_order;
            }

            s >>= 1;

            let Some(signature) = s.to_u64() else {
                return Err(GenerationError::InvalidParameters);
            };

            if signature <= bitmask(SIGNATURE_LENGTH_BITS as u64) {
                break Self {
                    upgrade,
                    channel_id,
                    hash,
                    signature,
                    auth_info,
                };
            }
        };

        Ok(key)
    }

    fn verify(
        &self,
        e_curve: &EllipticCurve,
        base_point: &Point,
        public_key: &Point,
    ) -> Result<(), VerificationError> {
        let data = self.channel_id << 1 | self.upgrade as u32;

        let mut msg_buffer = [0; 11];
        msg_buffer[0] = 0x5D;
        msg_buffer[1..3].copy_from_slice(&data.to_le_bytes()[0..2]);
        msg_buffer[3..7].copy_from_slice(&self.hash.to_le_bytes());
        msg_buffer[7..9].copy_from_slice(&self.auth_info.to_le_bytes()[0..2]);

        let msg_digest = {
            let mut hasher = Sha1::new();
            hasher.update(msg_buffer);
            hasher.finalize()
        };

        let i_signature = extract_bits(
            u32::from_le_bytes(msg_digest[4..8].try_into().unwrap()) as u64,
            30,
            2,
        ) << 32
            | u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()) as u64;

        let p = {
            let e = BigInt::from(i_signature);
            let s = BigInt::from(self.signature);
            let t = e_curve.multiply_point(&s, base_point);
            let mut p = e_curve.multiply_point(&e, public_key);
            p = e_curve.add_points(&t, &p);
            e_curve.multiply_point(&s, &p)
        };

        let Point::Point { x, y } = p else {
            return Err(VerificationError::InvalidParameters);
        };

        let x_bin = x.to_bytes_le().1;
        if x_bin.len() > FIELD_BYTES {
            return Err(VerificationError::InvalidParameters);
        }

        let y_bin = y.to_bytes_le().1;
        if y_bin.len() > FIELD_BYTES {
            return Err(VerificationError::InvalidParameters);
        }

        let mut msg_buffer = [0; SHA_MSG_LENGTH];
        msg_buffer[0] = 0x79;
        msg_buffer[1..3].copy_from_slice(&data.to_le_bytes()[0..2]);
        msg_buffer[3..3 + x_bin.len()].copy_from_slice(&x_bin);
        msg_buffer[3 + FIELD_BYTES..3 + FIELD_BYTES + y_bin.len()].copy_from_slice(&y_bin);

        let msg_digest = {
            let mut hasher = Sha1::new();
            hasher.update(msg_buffer);
            hasher.finalize()
        };

        let hash = extract_ls_bits(u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()), 31);

        if hash != self.hash {
            Err(VerificationError::HashMismatch)
        } else {
            Ok(())
        }
    }

    fn from_packed(packed_key: &BigUint) -> Result<Self, VerificationError> {
        let packed_key = packed_key.to_bytes_be();
        let mut reader = BitReader::new(&packed_key);
        // The auth info length isn't known, but everything else is, so we can calculate it
        let auth_info_length_bits = (packed_key.len() * 8) as u8 - EVERYTHING_ELSE;

        let auth_info = reader.read_u32(auth_info_length_bits)?;
        let signature = reader.read_u64(SIGNATURE_LENGTH_BITS)?;
        let hash = reader.read_u32(HASH_LENGTH_BITS)?;
        let channel_id = reader.read_u32(CHANNEL_ID_LENGTH_BITS)?;
        let upgrade = reader.read_bool()?;

        Ok(Self {
            upgrade,
            channel_id,
            hash,
            signature,
            auth_info,
        })
    }

    fn pack(&self) -> BigUint {
        let mut packed_key: u128 = 0;

        packed_key |= (self.auth_info as u128)
            << (SIGNATURE_LENGTH_BITS
                + HASH_LENGTH_BITS
                + CHANNEL_ID_LENGTH_BITS
                + UPGRADE_LENGTH_BITS);
        packed_key |= (self.signature as u128)
            << (HASH_LENGTH_BITS + CHANNEL_ID_LENGTH_BITS + UPGRADE_LENGTH_BITS);
        packed_key |= (self.hash as u128) << (CHANNEL_ID_LENGTH_BITS + UPGRADE_LENGTH_BITS);
        packed_key |= (self.channel_id as u128) << UPGRADE_LENGTH_BITS;
        packed_key |= self.upgrade as u128;

        BigUint::from_bytes_be(&packed_key.to_be_bytes())
    }
}

impl Display for ProductKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk = base24_encode(&self.pack());
        let key = pk
            .chars()
            .enumerate()
            .fold(String::new(), |mut acc: String, (i, c)| {
                if i > 0 && i % 5 == 0 {
                    acc.push('-');
                }
                acc.push(c);
                acc
            });
        write!(f, "{}", key)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use num_traits::Num;
    use serde_json::from_reader;
    use std::{fs::File, io::BufReader};

    use crate::crypto::EllipticCurve;

    #[test]
    fn verify_test() {
        // Example product key and its BINK ID
        let product_key = "R882X-YRGC8-4KYTG-C3FCC-JCFDY";
        let bink_id = "54";

        // Load keys.json
        let path = "../keys.json";
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let keys: serde_json::Value = from_reader(reader).unwrap();

        let bink = &keys["BINK"][&bink_id];

        let p = bink["p"].as_str().unwrap();
        let a = bink["a"].as_str().unwrap();
        let gx = bink["g"]["x"].as_str().unwrap();
        let gy = bink["g"]["y"].as_str().unwrap();
        let kx = bink["pub"]["x"].as_str().unwrap();
        let ky = bink["pub"]["y"].as_str().unwrap();

        let p = BigInt::from_str_radix(p, 10).unwrap();
        let a = BigInt::from_str_radix(a, 10).unwrap();
        let gx = BigInt::from_str_radix(gx, 10).unwrap();
        let gy = BigInt::from_str_radix(gy, 10).unwrap();
        let kx = BigInt::from_str_radix(kx, 10).unwrap();
        let ky = BigInt::from_str_radix(ky, 10).unwrap();

        let curve = EllipticCurve::new(p, a, gx, gy, kx, ky);

        assert!(super::ProductKey::from_key(&curve, product_key).is_ok());
        assert!(super::ProductKey::from_key(&curve, "11111-YRGC8-4KYTG-C3FCC-JCFDY").is_err());
    }
}
