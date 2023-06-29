//! Code that deals with elliptic curve cryptography
use anyhow::Result;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Num, One, Zero};

/// Represents a point (possibly) on an elliptic curve.
///
/// This is either the point at infinity, or a point with affine coordinates `x` and `y`.
/// It is not guaranteed to be on the curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Point { x: BigInt, y: BigInt },
}

/// Represents an elliptic curve of the form `y^2 = x^3 + ax + b (mod p)`
///
/// `b` is not used in any of the calculations, so is not stored.
///
/// This implements all the necessary elliptic curve arithmetic for verifying and generating
/// product keys.
pub struct EllipticCurve {
    a: BigInt,
    p: BigInt,
    pub gen_point: Point,
    pub pub_point: Point,
}

/// Stores the additional data necessary to generate product keys.
pub struct PrivateKey {
    pub gen_order: BigInt,
    pub private_key: BigInt,
}

impl PrivateKey {
    pub fn new(gen_order: &str, private_key: &str) -> Result<Self> {
        let gen_order = BigInt::from_str_radix(gen_order, 10)?;
        let private_key = BigInt::from_str_radix(private_key, 10)?;
        Ok(Self {
            gen_order,
            private_key,
        })
    }
}

impl EllipticCurve {
    /// Creates a new elliptic curve from the given parameters. `b` is not necessary.
    pub fn new(
        p: &str,
        a: &str,
        generator_x: &str,
        generator_y: &str,
        public_key_x: &str,
        public_key_y: &str,
    ) -> Result<Self> {
        let p = BigInt::from_str_radix(p, 10)?;
        let a = BigInt::from_str_radix(a, 10)?;
        let generator_x = BigInt::from_str_radix(generator_x, 10)?;
        let generator_y = BigInt::from_str_radix(generator_y, 10)?;
        let public_key_x = BigInt::from_str_radix(public_key_x, 10)?;
        let public_key_y = BigInt::from_str_radix(public_key_y, 10)?;

        let gen_point = Point::Point {
            x: generator_x,
            y: generator_y,
        };

        let pub_point = Point::Point {
            x: public_key_x,
            y: public_key_y,
        };

        Ok(Self {
            a,
            p,
            gen_point,
            pub_point,
        })
    }

    fn mod_inverse(a: &BigInt, p: &BigInt) -> BigInt {
        let egcd = a.extended_gcd(p);
        egcd.x.mod_floor(p)
    }

    fn double_point(&self, point: &Point) -> Point {
        match point {
            Point::Point { x, y } => {
                if y.is_zero() {
                    Point::Infinity
                } else {
                    let three = BigInt::from(3);
                    let two = BigInt::from(2);

                    let lambda = (three * x * x + &self.a) * Self::mod_inverse(&(two * y), &self.p);
                    let lamba_sqr = (&lambda * &lambda).mod_floor(&self.p);
                    let x3 = (&lamba_sqr - x - x).mod_floor(&self.p);
                    let y3 = (&lambda * (x - &x3) - y).mod_floor(&self.p);

                    Point::Point { x: x3, y: y3 }
                }
            }
            Point::Infinity => Point::Infinity,
        }
    }

    /// Adds two points on the curve together.
    ///
    /// If the points are the same, it doubles the point.
    ///
    /// If one of the points is the point at infinity, it returns the other point.
    ///
    /// If both points are the point at infinity, it returns the point at infinity.
    pub(crate) fn add_points(&self, point1: &Point, point2: &Point) -> Point {
        match (point1, point2) {
            (Point::Point { x: x1, y: y1 }, Point::Point { x: x2, y: y2 }) => {
                if point1 == point2 {
                    self.double_point(point1)
                } else {
                    let lambda = (y2 - y1) * Self::mod_inverse(&(x2 - x1), &self.p);
                    let x3 = ((&lambda * &lambda) - x1 - x2).mod_floor(&self.p);
                    let y3: BigInt = ((&lambda * (x1 - &x3)) - y1).mod_floor(&self.p);

                    Point::Point { x: x3, y: y3 }
                }
            }
            (Point::Point { x, y }, Point::Infinity) | (Point::Infinity, Point::Point { x, y }) => {
                Point::Point {
                    x: x.clone(),
                    y: y.clone(),
                }
            }
            (Point::Infinity, Point::Infinity) => Point::Infinity,
        }
    }

    /// Multiplies a point by a scalar.
    ///
    /// Uses the double-and-add algorithm.
    pub(crate) fn multiply_point(&self, s: &BigInt, point: &Point) -> Point {
        let mut res = Point::Infinity;
        let mut temp = point.clone();

        let mut s = s.clone();

        while s > BigInt::zero() {
            if (&s % BigInt::from(2)) == BigInt::one() {
                res = self.add_points(&res, &temp);
            }
            temp = self.double_point(&temp);

            s >>= 1;
        }

        res
    }
}

/// Calculates the legendre symbol of `p`: `1`, `0`, or `-1 mod p`
fn ls(a: &BigInt, p: &BigInt) -> BigInt {
    let exp = (p - BigInt::one()) / BigInt::from(2);
    a.modpow(&exp, p)
}

/// Calculates the modular square root of `n` such that `result^2 = n (mod p)`
/// using the Tonelli-Shanks algorithm. Returns `None` if `p` is not prime.
///
/// # Arguments
///
/// * `n` - The number to find the square root of
/// * `p` - The prime modulus (_must_ be prime)
pub(crate) fn mod_sqrt(n: &BigInt, p: &BigInt) -> Option<BigInt> {
    if !ls(n, p).is_one() {
        return None;
    }

    let mut q = p - 1;
    let mut s = BigInt::zero();
    while (&q & &BigInt::one()).is_zero() {
        s += 1;
        q >>= 1
    }

    if s.is_one() {
        let exp = (p + 1) / 4;
        let r1 = n.modpow(&exp, p);
        return Some(p - &r1);
    }

    let mut z = BigInt::from(2);
    while ls(&z, p) != p - 1 {
        z += 1
    }
    let mut c = z.modpow(&q, p);

    let mut r = n.modpow(&((&q + 1) / 2), p);
    let mut t = n.modpow(&q, p);
    let mut m = s;

    loop {
        if t.is_one() {
            return Some(p - &r);
        }

        let mut i = BigInt::zero();
        let mut z = t.clone();
        let mut b = c.clone();
        while !z.is_one() && i < &m - 1 {
            z = &z * &z % p;
            i += 1;
        }
        let mut e = &m - &i - 1;
        while e > BigInt::zero() {
            b = &b * &b % p;
            e -= 1;
        }
        r = &r * &b % p;
        c = &b * &b % p;
        t = &t * &c % p;
        m = i;
    }
}
