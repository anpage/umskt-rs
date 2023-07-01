//! Code that deals with elliptic curve cryptography
use anyhow::Result;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Zero};

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
    pub fn new(gen_order: BigInt, private_key: BigInt) -> Result<Self> {
        Ok(Self {
            gen_order,
            private_key,
        })
    }
}

impl EllipticCurve {
    /// Creates a new elliptic curve from the given parameters. `b` is not necessary.
    pub fn new(
        p: BigInt,
        a: BigInt,
        generator_x: BigInt,
        generator_y: BigInt,
        public_key_x: BigInt,
        public_key_y: BigInt,
    ) -> Result<Self> {
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

    fn mod_inverse(&self, a: &BigInt) -> BigInt {
        let mut s = (BigInt::zero(), BigInt::one());
        let mut r = (self.p.clone(), a.clone());

        while !r.0.is_zero() {
            let q = &r.1 / &r.0;
            std::mem::swap(&mut r.0, &mut r.1);
            r.0 -= &q * &r.1;
            std::mem::swap(&mut s.0, &mut s.1);
            s.0 -= &q * &s.1;
        }

        if r.1 >= BigInt::zero() {
            s.1 % &self.p
        } else {
            -s.1 % &self.p
        }
    }

    fn double_point(&self, point: &ProjectivePoint) -> ProjectivePoint {
        if point.y.is_zero() {
            return ProjectivePoint::infinity();
        }

        let three = BigInt::from(3);
        let two = BigInt::from(2);

        let t = (&point.x * &point.x * &three + &self.a * &point.z * &point.z).mod_floor(&self.p);
        let u = (&point.y * &point.z * &two).mod_floor(&self.p);
        let v = (&u * &point.x * &point.y * &two).mod_floor(&self.p);
        let w = (&t * &t - &v * &two).mod_floor(&self.p);
        let x = (&u * &w).mod_floor(&self.p);
        let y = (&t * (&v - &w) - &u * &u * &point.y * &point.y * &two).mod_floor(&self.p);
        let z = (&u * &u * &u).mod_floor(&self.p);

        ProjectivePoint { x, y, z }
    }

    /// Adds two points on the curve together.
    ///
    /// If the points are the same, it doubles the point.
    ///
    /// If one of the points is the point at infinity, it returns the other point.
    ///
    /// If both points are the point at infinity, it returns the point at infinity.
    pub(crate) fn add_points(&self, point1: &Point, point2: &Point) -> Point {
        let point1: ProjectivePoint = point1.into();
        let point2: ProjectivePoint = point2.into();
        self.projective_to_affine(self.add_points_proj(&point1, &point2))
    }

    fn add_points_proj(
        &self,
        point1: &ProjectivePoint,
        point2: &ProjectivePoint,
    ) -> ProjectivePoint {
        if point1.z.is_zero() {
            return point2.clone();
        } else if point2.z.is_zero() {
            return point1.clone();
        }

        let t0 = (&point1.y * &point2.z).mod_floor(&self.p);
        let t1 = (&point2.y * &point1.z).mod_floor(&self.p);
        let u0 = (&point1.x * &point2.z).mod_floor(&self.p);
        let u1 = (&point2.x * &point1.z).mod_floor(&self.p);
        if u0 == u1 {
            if t0 == t1 {
                return self.double_point(point1);
            } else {
                return ProjectivePoint::infinity();
            }
        }

        let t = (&t0 - &t1).mod_floor(&self.p);
        let u = (&u0 - &u1).mod_floor(&self.p);
        let u2 = (&u * &u).mod_floor(&self.p);
        let v = (&point1.z * &point2.z).mod_floor(&self.p);
        let w = (&t * &t * &v - &u2 * (&u0 + &u1)).mod_floor(&self.p);
        let u3 = (&u * &u2).mod_floor(&self.p);
        let x = (&u * &w).mod_floor(&self.p);
        let y = (&t * (&u0 * &u2 - &w) - &t0 * &u3).mod_floor(&self.p);
        let z = (&u3 * &v).mod_floor(&self.p);

        ProjectivePoint { x, y, z }
    }

    fn projective_to_affine(&self, point: ProjectivePoint) -> Point {
        if point.z.is_zero() {
            return Point::Infinity;
        }

        let z_inv = self.mod_inverse(&point.z);
        let x = (&point.x * &z_inv).mod_floor(&self.p);
        let y = (&point.y * &z_inv).mod_floor(&self.p);

        Point::Point { x, y }
    }

    /// Multiplies a point by a scalar.
    ///
    /// Uses the double-and-add algorithm.
    pub fn multiply_point(&self, n: &BigInt, point: &Point) -> Point {
        let mut result = ProjectivePoint::infinity();
        let mut temp: ProjectivePoint = point.into();

        let mut n = n.clone();
        while n > BigInt::zero() {
            if (&n % BigInt::from(2)) == BigInt::one() {
                result = self.add_points_proj(&result, &temp);
            }
            temp = self.double_point(&temp);
            n >>= 1;
        }

        self.projective_to_affine(result)
    }
}

#[derive(Clone, Debug)]
struct ProjectivePoint {
    x: BigInt,
    y: BigInt,
    z: BigInt,
}

impl ProjectivePoint {
    pub fn infinity() -> Self {
        ProjectivePoint {
            x: Zero::zero(),
            y: One::one(),
            z: Zero::zero(),
        }
    }
}

impl From<&Point> for ProjectivePoint {
    fn from(point: &Point) -> Self {
        match point {
            Point::Infinity => Self::infinity(),
            Point::Point { x, y } => ProjectivePoint {
                x: x.clone(),
                y: y.clone(),
                z: One::one(),
            },
        }
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
