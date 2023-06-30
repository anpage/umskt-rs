//! Structs to deal with older BINK (< `0x40`) product keys
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

use anyhow::{bail, Result};
use bitreader::BitReader;
use num_bigint::{BigInt, BigUint, RandomBits};
use num_integer::Integer;
use num_traits::{FromPrimitive, ToPrimitive};
use rand::Rng;
use sha1::{Digest, Sha1};

use crate::{
    crypto::{EllipticCurve, Point, PrivateKey},
    key::{base24_decode, base24_encode, strip_key},
    math::bitmask,
};

const FIELD_BITS: u64 = 384;
const FIELD_BYTES: usize = 48;
const SHA_MSG_LENGTH: usize = 4 + 2 * FIELD_BYTES;

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
    /// The key is verified to be valid before being returned.
    pub fn new(
        curve: &EllipticCurve,
        private_key: &PrivateKey,
        channel_id: u32,
        sequence: Option<u32>,
        upgrade: Option<bool>,
    ) -> Result<Self> {
        // Generate random sequence if none supplied
        let sequence = match sequence {
            Some(serial) => serial,
            None => {
                let mut rng = rand::thread_rng();
                let random: u32 = rng.gen();
                random % 999999
            }
        };

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

        // Make sure the key is valid
        product_key.verify(curve, &curve.gen_point, &curve.pub_point)?;

        // Ship it
        Ok(product_key)
    }

    /// Validates an existing product key string and tried to create a new `ProductKey` from it.
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

        let mut rng = rand::thread_rng();

        let product_key = loop {
            let c: BigUint = rng.sample(RandomBits::new(FIELD_BITS));
            let c: BigInt = c.into();

            let r = e_curve.multiply_point(&c, base_point);

            let (x, y) = match r {
                Point::Point { x, y } => (x, y),
                Point::Infinity => bail!("Point at infinity!"),
            };

            let mut msg_buffer: [u8; SHA_MSG_LENGTH] = [0; SHA_MSG_LENGTH];

            let x_bin = x.to_bytes_le().1;
            let x_bin = match x_bin.len().cmp(&FIELD_BYTES) {
                Ordering::Less => (0..FIELD_BYTES - x_bin.len())
                    .map(|_| 0)
                    .chain(x_bin.into_iter())
                    .collect(),
                Ordering::Greater => continue,
                Ordering::Equal => x_bin,
            };
            let y_bin = y.to_bytes_le().1;
            let y_bin = match y_bin.len().cmp(&FIELD_BYTES) {
                Ordering::Less => (0..FIELD_BYTES - y_bin.len())
                    .map(|_| 0)
                    .chain(y_bin.into_iter())
                    .collect(),
                Ordering::Greater => continue,
                Ordering::Equal => y_bin,
            };

            msg_buffer[0..4].copy_from_slice(&data.to_le_bytes());
            msg_buffer[4..4 + FIELD_BYTES].copy_from_slice(&x_bin);
            msg_buffer[4 + FIELD_BYTES..4 + FIELD_BYTES * 2].copy_from_slice(&y_bin);

            let msg_digest = {
                let mut hasher = Sha1::new();
                hasher.update(msg_buffer);
                hasher.finalize()
            };

            let hash: u32 =
                u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()) >> 4 & bitmask(28) as u32;

            let mut ek = private_key.clone();
            ek *= hash;

            let s = (ek + c).mod_floor(gen_order);

            let signature = s.to_u64().unwrap_or(0);

            if signature <= bitmask(55) {
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
        let e = BigInt::from_u32(self.hash).unwrap();
        let s = BigInt::from_u64(self.signature).unwrap();

        let t = e_curve.multiply_point(&s, base_point);
        let mut p = e_curve.multiply_point(&e, public_key);

        p = e_curve.add_points(&p, &t);

        let (x, y) = match p {
            Point::Point { x, y } => (x, y),
            Point::Infinity => bail!("Point at infinity!"),
        };

        let mut msg_buffer: [u8; SHA_MSG_LENGTH] = [0; SHA_MSG_LENGTH];

        let x_bin = x.to_bytes_le().1;
        let x_bin = if x_bin.len() < FIELD_BYTES {
            (0..FIELD_BYTES - x_bin.len())
                .map(|_| 0)
                .chain(x_bin.into_iter())
                .collect()
        } else {
            x_bin
        };
        let y_bin = y.to_bytes_le().1;
        let y_bin = if y_bin.len() < FIELD_BYTES {
            (0..FIELD_BYTES - y_bin.len())
                .map(|_| 0)
                .chain(y_bin.into_iter())
                .collect()
        } else {
            y_bin
        };

        let serial = self.channel_id * 1_000_000 + self.sequence;
        let data = serial << 1 | self.upgrade as u32;

        msg_buffer[0..4].copy_from_slice(&data.to_le_bytes());
        msg_buffer[4..4 + FIELD_BYTES].copy_from_slice(&x_bin);
        msg_buffer[4 + FIELD_BYTES..4 + FIELD_BYTES * 2].copy_from_slice(&y_bin);

        let msg_digest = {
            let mut hasher = Sha1::new();
            hasher.update(msg_buffer);
            hasher.finalize()
        };

        let hash: u32 =
            u32::from_le_bytes(msg_digest[0..4].try_into().unwrap()) >> 4 & bitmask(28) as u32;

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

    use serde_json::from_reader;

    use crate::{bink1998, crypto::EllipticCurve};

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
