//! Structs to deal with older BINK (< `0x40`) product keys
use std::fmt::{Display, Formatter};

use anyhow::{bail, Result};
use bitreader::BitReader;
use num_bigint::{BigInt, BigUint, RandomBits};
use num_integer::Integer;
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{thread_rng, Rng};
use sha1::{Digest, Sha1};

use crate::{
    crypto::{EllipticCurve, Point, PrivateKey},
    key::{base24_decode, base24_encode, strip_key},
    math::{bitmask, extract_bits},
};

const FIELD_BITS: u64 = 384;
const FIELD_BYTES: usize = 48;
const SHA_MSG_LENGTH: usize = 4 + 2 * FIELD_BYTES;
const SEQUENCE_MAX: u32 = 999999;

const SIGNATURE_LENGTH_BITS: u8 = 55;
const HASH_LENGTH_BITS: u8 = 28;
const SERIAL_LENGTH_BITS: u8 = 30;
const UPGRADE_LENGTH_BITS: u8 = 1;
const EVERYTHING_ELSE: u8 = HASH_LENGTH_BITS + SERIAL_LENGTH_BITS + UPGRADE_LENGTH_BITS;

/// A product key for a BINK ID less than `0x40`
///
/// Every `ProductKey` contains a valid key for its given parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductKey {
    upgrade: bool,
    channel_id: u32,
    sequence: u32,
    hash: u32,
    signature: u64,
}

impl ProductKey {
    /// Generates a new product key for the given parameters.
    ///
    /// The generated key is guaranteed to be valid.
    pub fn new(
        curve: &EllipticCurve,
        private_key: &PrivateKey,
        channel_id: u32,
        sequence: Option<u32>,
        upgrade: Option<bool>,
    ) -> Result<Self> {
        // Generate random sequence if none supplied
        let sequence = sequence.unwrap_or_else(|| thread_rng().gen::<u32>() % SEQUENCE_MAX);

        // Default to upgrade=false
        let upgrade = upgrade.unwrap_or(false);

        let private = &private_key.gen_order - &private_key.private_key;

        // Generate a new random key
        let product_key = Self::generate(
            curve,
            &curve.gen_point,
            &private_key.gen_order,
            &private,
            channel_id,
            sequence,
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
    pub fn from_key(curve: &EllipticCurve, key: &str) -> Result<Self> {
        let key = strip_key(key)?;
        let Ok(packed_key) = base24_decode(&key) else {
            bail!("Product key is in an incorrect format!")
        };
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
        sequence: u32,
        upgrade: bool,
    ) -> Result<Self> {
        let serial = channel_id * 1_000_000 + sequence;
        let data = serial << 1 | upgrade as u32;

        let product_key: ProductKey = loop {
            let seed: BigUint = thread_rng().sample(RandomBits::new(FIELD_BITS));
            let seed: BigInt = seed.into();

            let hash = {
                let r = e_curve.multiply_point(&seed, base_point);

                let Point::Point{x, y} = r else {
                    bail!("Point at infinity! Are the elliptic curve parameters correct?")
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
                msg_buffer[0..4].copy_from_slice(&data.to_le_bytes());
                msg_buffer[4..4 + x_bin.len()].copy_from_slice(&x_bin);
                msg_buffer[4 + FIELD_BYTES..4 + FIELD_BYTES + y_bin.len()].copy_from_slice(&y_bin);

                let msg_digest = {
                    let mut hasher = Sha1::new();
                    hasher.update(msg_buffer);
                    hasher.finalize()
                };

                extract_bits(
                    u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()),
                    28,
                    4,
                )
            };

            let mut ek = private_key.clone();
            ek *= hash;

            let s = (ek + seed).mod_floor(gen_order);

            let Some(signature) = s.to_u64() else {
                bail!("Signature is more than 64 bits! Are the elliptic curve parameters correct?")
            };

            if signature <= bitmask(SIGNATURE_LENGTH_BITS as u64) {
                break Self {
                    upgrade,
                    channel_id,
                    sequence,
                    hash,
                    signature,
                };
            }
        };

        Ok(product_key)
    }

    fn verify(
        &self,
        e_curve: &EllipticCurve,
        base_point: &Point,
        public_key: &Point,
    ) -> Result<bool> {
        let p = {
            let e = BigInt::from_u32(self.hash).unwrap();
            let s = BigInt::from_u64(self.signature).unwrap();
            let t = e_curve.multiply_point(&s, base_point);
            let p = e_curve.multiply_point(&e, public_key);
            e_curve.add_points(&p, &t)
        };

        let Point::Point{x, y} = p else {
            bail!("Point at infinity! Are the elliptic curve parameters correct?")
        };

        let x_bin = x.to_bytes_le().1;
        if x_bin.len() > FIELD_BYTES {
            bail!("x is too big somehow! Are the elliptic curve parameters correct?");
        }

        let y_bin = y.to_bytes_le().1;
        if y_bin.len() > FIELD_BYTES {
            bail!("y is too big somehow! Are the elliptic curve parameters correct?");
        }

        let serial = self.channel_id * 1_000_000 + self.sequence;
        let data = serial << 1 | self.upgrade as u32;

        let mut msg_buffer: [u8; SHA_MSG_LENGTH] = [0; SHA_MSG_LENGTH];
        msg_buffer[0..4].copy_from_slice(&data.to_le_bytes());
        msg_buffer[4..4 + x_bin.len()].copy_from_slice(&x_bin);
        msg_buffer[4 + FIELD_BYTES..4 + FIELD_BYTES + y_bin.len()].copy_from_slice(&y_bin);

        let msg_digest = {
            let mut hasher = Sha1::new();
            hasher.update(msg_buffer);
            hasher.finalize()
        };

        let hash: u32 = extract_bits(
            u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()),
            28,
            4,
        );

        Ok(hash == self.hash)
    }

    fn from_packed(packed_key: &[u8]) -> Result<Self> {
        let mut reader = BitReader::new(packed_key);

        // The signature length isn't known, but everything else is, so we can calculate it
        let signature_length_bits = (packed_key.len() * 8) as u8 - EVERYTHING_ELSE;

        let signature = reader.read_u64(signature_length_bits)?;
        let hash = reader.read_u32(HASH_LENGTH_BITS)?;
        let serial = reader.read_u32(SERIAL_LENGTH_BITS)?;
        let upgrade = reader.read_bool()?;

        let sequence = serial % 1_000_000;
        let channel_id = serial / 1_000_000;

        Ok(Self {
            upgrade,
            channel_id,
            sequence,
            hash,
            signature,
        })
    }

    fn pack(&self) -> Vec<u8> {
        let mut packed_key: u128 = 0;

        let serial = self.channel_id * 1_000_000 + self.sequence;

        packed_key |= (self.signature as u128) << EVERYTHING_ELSE;
        packed_key |= (self.hash as u128) << (SERIAL_LENGTH_BITS + UPGRADE_LENGTH_BITS);
        packed_key |= (serial as u128) << UPGRADE_LENGTH_BITS;
        packed_key |= self.upgrade as u128;

        packed_key
            .to_be_bytes()
            .into_iter()
            .skip_while(|&x| x == 0)
            .collect()
    }
}

impl Display for ProductKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk = base24_encode(&self.pack()).unwrap();
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
    use std::{fs::File, io::BufReader};

    use num_bigint::BigInt;
    use num_traits::Num;
    use serde_json::from_reader;

    use crate::{crypto::EllipticCurve, pidgen3::bink1998};

    #[test]
    fn verify_test() {
        // Example product key and its BINK ID
        let product_key = "D9924-R6BG2-39J83-RYKHF-W47TT";
        let bink_id = "2E";

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

        let curve = EllipticCurve::new(p, a, gx, gy, kx, ky).unwrap();

        assert!(bink1998::ProductKey::from_key(&curve, product_key).is_ok());
        assert!(bink1998::ProductKey::from_key(&curve, "11111-R6BG2-39J83-RYKHF-W47TT").is_err());
    }

    #[test]
    fn pack_test() {
        let key = super::ProductKey {
            upgrade: false,
            channel_id: 640,
            sequence: 10550,
            hash: 39185432,
            signature: 6939952665262054,
        };

        assert_eq!(key.to_string(), "D9924-R6BG2-39J83-RYKHF-W47TT");
    }
}
