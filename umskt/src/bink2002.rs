//! Structs to deal with newer BINK (>= `0x40`) product keys
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

use anyhow::{bail, Result};
use bitreader::BitReader;
use num_bigint::{BigInt, BigUint, RandomBits};
use num_integer::Integer;
use num_traits::ToPrimitive;
use rand::Rng;
use sha1::{Digest, Sha1};

use crate::{
    crypto::{mod_sqrt, EllipticCurve, Point, PrivateKey},
    key::{base24_decode, base24_encode, strip_key},
    math::{bitmask, by_dword, next_sn_bits},
};

const FIELD_BITS: u64 = 512;
const FIELD_BYTES: usize = 64;
const SHA_MSG_LENGTH: usize = 3 + 2 * FIELD_BYTES;

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
    /// The key is verified to be valid before being returned.
    pub fn new(
        curve: &EllipticCurve,
        private_key: &PrivateKey,
        channel_id: u32,
        auth_info: Option<u32>,
        upgrade: Option<bool>,
    ) -> Result<Self> {
        // Generate random auth info if none supplied
        let auth_info = match auth_info {
            Some(auth_info) => auth_info,
            None => {
                let mut rng = rand::thread_rng();
                let random: u32 = rng.gen();
                random % (bitmask(10) as u32)
            }
        };

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
        let verified = product_key.verify(curve, &curve.gen_point, &curve.pub_point)?;
        if !verified {
            bail!("Product key is invalid! Wrong BINK ID?");
        }
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
    ) -> Result<Self> {
        let data = channel_id << 1 | upgrade as u32;

        let mut rng = rand::thread_rng();

        let mut no_square = false;
        let key = loop {
            let c: BigUint = rng.sample(RandomBits::new(FIELD_BITS));
            let mut c: BigInt = c.into();

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

            msg_buffer[0x00] = 0x79;
            msg_buffer[0x01] = (data & 0x00FF) as u8;
            msg_buffer[0x02] = ((data & 0xFF00) >> 8) as u8;

            msg_buffer[3..3 + FIELD_BYTES].copy_from_slice(&x_bin);
            msg_buffer[3 + FIELD_BYTES..3 + FIELD_BYTES * 2].copy_from_slice(&y_bin);

            let msg_digest = {
                let mut hasher = Sha1::new();
                hasher.update(msg_buffer);
                hasher.finalize()
            };

            let hash: u32 = by_dword(&msg_digest[0..4]) & bitmask(31) as u32;

            msg_buffer[0x00] = 0x5D;
            msg_buffer[0x01] = (data & 0x00FF) as u8;
            msg_buffer[0x02] = ((data & 0xFF00) >> 8) as u8;
            msg_buffer[0x03] = (hash & 0x000000FF) as u8;
            msg_buffer[0x04] = ((hash & 0x0000FF00) >> 8) as u8;
            msg_buffer[0x05] = ((hash & 0x00FF0000) >> 16) as u8;
            msg_buffer[0x06] = ((hash & 0xFF000000) >> 24) as u8;
            msg_buffer[0x07] = (auth_info & 0x00FF) as u8;
            msg_buffer[0x08] = ((auth_info & 0xFF00) >> 8) as u8;
            msg_buffer[0x09] = 0x00;
            msg_buffer[0x0A] = 0x00;

            let msg_digest = {
                let mut hasher = Sha1::new();
                hasher.update(&msg_buffer[..=0x0A]);
                hasher.finalize()
            };

            let i_signature = next_sn_bits(by_dword(&msg_digest[4..8]) as u64, 30, 2) << 32
                | by_dword(&msg_digest[0..4]) as u64;

            let mut e = BigInt::from(i_signature);

            e = (e * private_key).mod_floor(gen_order);

            let mut s = e.clone();

            s = (&s * &s).mod_floor(gen_order);

            c <<= 2;

            s = &s + &c;

            match mod_sqrt(&s, gen_order) {
                Some(res) => s = res,
                None => {
                    no_square = true;
                }
            }

            s = (s - e).mod_floor(gen_order);

            if s.is_odd() {
                s = &s + gen_order;
            }

            s >>= 1;

            let signature = s.to_u64().unwrap_or(0);

            let product_key = Self {
                upgrade,
                channel_id,
                hash,
                signature,
                auth_info,
            };

            if signature <= bitmask(62) && !no_square {
                break product_key;
            }

            no_square = false;
        };

        Ok(key)
    }

    fn verify(
        &self,
        e_curve: &EllipticCurve,
        base_point: &Point,
        public_key: &Point,
    ) -> Result<bool> {
        let data = self.channel_id << 1 | self.upgrade as u32;

        let mut msg_buffer: [u8; SHA_MSG_LENGTH] = [0; SHA_MSG_LENGTH];

        msg_buffer[0x00] = 0x5D;
        msg_buffer[0x01] = (data & 0x00FF) as u8;
        msg_buffer[0x02] = ((data & 0xFF00) >> 8) as u8;
        msg_buffer[0x03] = (self.hash & 0x000000FF) as u8;
        msg_buffer[0x04] = ((self.hash & 0x0000FF00) >> 8) as u8;
        msg_buffer[0x05] = ((self.hash & 0x00FF0000) >> 16) as u8;
        msg_buffer[0x06] = ((self.hash & 0xFF000000) >> 24) as u8;
        msg_buffer[0x07] = (self.auth_info & 0x00FF) as u8;
        msg_buffer[0x08] = ((self.auth_info & 0xFF00) >> 8) as u8;
        msg_buffer[0x09] = 0x00;
        msg_buffer[0x0A] = 0x00;

        let msg_digest = {
            let mut hasher = Sha1::new();
            hasher.update(&msg_buffer[..=0x0A]);
            hasher.finalize()
        };

        let i_signature = next_sn_bits(by_dword(&msg_digest[4..8]) as u64, 30, 2) << 32
            | by_dword(&msg_digest[0..4]) as u64;

        let e = BigInt::from(i_signature);
        let s = BigInt::from(self.signature);

        let t = e_curve.multiply_point(&s, base_point);
        let mut p = e_curve.multiply_point(&e, public_key);

        p = e_curve.add_points(&t, &p);
        p = e_curve.multiply_point(&s, &p);

        let (x, y) = match p {
            Point::Point { x, y } => (x, y),
            Point::Infinity => bail!("Point at infinity!"),
        };

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

        msg_buffer[0x00] = 0x79;
        msg_buffer[0x01] = (data & 0x00FF) as u8;
        msg_buffer[0x02] = ((data & 0xFF00) >> 8) as u8;

        msg_buffer[3..3 + FIELD_BYTES].copy_from_slice(&x_bin);
        msg_buffer[3 + FIELD_BYTES..3 + FIELD_BYTES * 2].copy_from_slice(&y_bin);

        let msg_digest = {
            let mut hasher = Sha1::new();
            hasher.update(msg_buffer);
            hasher.finalize()
        };

        let hash: u32 = by_dword(&msg_digest[0..4]) & bitmask(31) as u32;

        Ok(hash == self.hash)
    }

    fn from_packed(packed_key: &[u8]) -> Result<Self> {
        let mut reader = BitReader::new(packed_key);
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

    fn pack(&self) -> Vec<u8> {
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

        let curve = EllipticCurve::new(p, a, gx, gy, kx, ky).unwrap();

        assert!(super::ProductKey::from_key(&curve, product_key).is_ok());
        assert!(super::ProductKey::from_key(&curve, "11111-YRGC8-4KYTG-C3FCC-JCFDY").is_err());
    }
}
