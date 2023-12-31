use std::mem::{size_of, swap};

#[derive(Copy, Clone)]
struct TDivisor {
    u: [u64; 2],
    v: [u64; 2],
}

#[derive(Copy, Clone)]
struct Encoded {
    encoded_lo: u64,
    encoded_hi: u64,
}

#[derive(Copy, Clone)]
struct ParsedInstallationId {
    hardware_id: u64,
    product_id_low: u64,
    product_id_high: u8,
    key_sha1: u16,
}

static F: [u64; 6] = [
    0,
    0x21840136c85381,
    0x44197b83892ad0,
    0x1400606322b3b04,
    0x1400606322b3b04,
    1,
];

const MOD: u64 = 0x16A6B036D7F2A79;
const BAD: u64 = 0xffffffffffffffff;

fn residue_add(x: u64, y: u64) -> u64 {
    let mut z: u64 = x.wrapping_add(y);
    //z = z - (z >= MOD ? MOD : 0);
    if z >= MOD {
        z = z.wrapping_sub(MOD);
    }
    z
}

fn residue_sub(x: u64, y: u64) -> u64 {
    let mut z: u64 = x.wrapping_sub(y);
    //z += (x < y ? MOD : 0);
    if x < y {
        z = z.wrapping_add(MOD);
    }
    z
}

fn umul128(a: u64, b: u64, hi: &mut u64) -> u64 {
    let r: u128 = a as u128 * b as u128;
    *hi = (r >> 64) as u64;
    r as u64
}

fn ui128_quotient_mod(lo: u64, hi: u64) -> u64 {
    // hi:lo * ceil(2**170/MOD) >> (64 + 64 + 42)
    let mut prod1: u64 = 0;
    umul128(lo, 0x604fa6a1c6346a87_i64 as u64, &mut prod1);
    let mut part1hi: u64 = 0;
    let part1lo: u64 = umul128(lo, 0x2d351c6d04f8b_i64 as u64, &mut part1hi);
    let mut part2hi: u64 = 0;
    let part2lo: u64 = umul128(hi, 0x604fa6a1c6346a87_i64 as u64, &mut part2hi);
    let mut sum1: u64 = part1lo.wrapping_add(part2lo);
    let mut sum1carry: u32 = (sum1 < part1lo) as i32 as u32;
    sum1 = sum1.wrapping_add(prod1);
    sum1carry = sum1carry.wrapping_add((sum1 < prod1) as i32 as u32);
    let prod2: u64 = part1hi.wrapping_add(part2hi).wrapping_add(sum1carry as u64);
    let mut prod3hi: u64 = 0;
    let mut prod3lo: u64 = umul128(hi, 0x2d351c6d04f8b_i64 as u64, &mut prod3hi);
    prod3lo = prod3lo.wrapping_add(prod2);
    prod3hi = prod3hi.wrapping_add((prod3lo < prod2) as i32 as u64);
    prod3lo >> 42_i32 | prod3hi << 22_i32
}

fn residue_mul(x: u64, y: u64) -> u64 {
    // * ceil(2**170/MOD) = 0x2d351 c6d04f8b|604fa6a1 c6346a87 for (p-1)*(p-1) max
    let mut hi: u64 = 0;
    let lo: u64 = umul128(x, y, &mut hi);
    let quotient: u64 = ui128_quotient_mod(lo, hi);
    lo.wrapping_sub(quotient.wrapping_mul(MOD))
}

fn residue_pow(x: u64, mut y: u64) -> u64 {
    if y == 0_i32 as u64 {
        return 1_i32 as u64;
    }
    let mut cur: u64 = x;
    while y & 1_i32 as u64 == 0 {
        cur = residue_mul(cur, cur);
        y >>= 1_i32;
    }
    let mut res: u64 = cur;
    loop {
        y >>= 1_i32;
        if y == 0_i32 as u64 {
            break;
        }
        cur = residue_mul(cur, cur);
        if y & 1_i32 as u64 != 0 {
            res = residue_mul(res, cur);
        }
    }
    res
}

fn inverse(mut u: u64, mut v: u64) -> u64 {
    let mut tmp;
    let mut xu: i64 = 1_i32 as i64;
    let mut xv: i64 = 0_i32 as i64;
    let v0: u64 = v;
    while u > 1_i32 as u64 {
        let d: u64 = v.wrapping_div(u);
        let remainder: u64 = v.wrapping_rem(u);
        tmp = u as i64;
        u = remainder;
        v = tmp as u64;
        tmp = xu;
        xu = (xv as u64).wrapping_sub(d.wrapping_mul(xu as u64)) as i64;
        xv = tmp;
    }
    xu = (xu as u64).wrapping_add(if xu < 0_i32 as i64 { v0 } else { 0_i32 as u64 }) as i64;
    xu as u64
}

fn residue_inv(x: u64) -> u64 {
    inverse(x, MOD)
}

fn residue_sqrt(what: u64) -> u64 {
    if what == 0 {
        return 0_i32 as u64;
    }
    let g: u64 = 43_i32 as u64;
    let mut e: u64 = 0_i32 as u64;
    let mut q: u64 = MOD.wrapping_sub(1_i32 as u64);
    while q & 1_i32 as u64 == 0 {
        e = e.wrapping_add(1);
        q >>= 1_i32;
    }
    let z = residue_pow(g, q);
    let mut y = z;
    let mut r = e;
    let mut x = residue_pow(
        what,
        q.wrapping_sub(1_i32 as u64).wrapping_div(2_i32 as u64),
    );
    let mut b = residue_mul(residue_mul(what, x), x);
    x = residue_mul(what, x);
    while b != 1_i32 as u64 {
        let mut m: u64 = 0_i32 as u64;
        let mut b2: u64 = b;
        loop {
            m = m.wrapping_add(1);
            b2 = residue_mul(b2, b2);
            if b2 == 1_i32 as u64 {
                break;
            }
        }
        if m == r {
            return BAD;
        }
        let t = residue_pow(
            y,
            (1_i32 << r.wrapping_sub(m).wrapping_sub(1_i32 as u64)) as u64,
        );
        y = residue_mul(t, t);
        r = m;
        x = residue_mul(x, t);
        b = residue_mul(b, y);
    }
    if residue_mul(x, x) != what {
        return BAD;
    }
    x
}

fn find_divisor_v(d: &mut TDivisor) -> i32 {
    // u | v^2 - f
    // u = u0 + u1*x + x^2
    // f%u = f0 + f1*x
    let mut v1;
    let mut f2: [u64; 6] = [0; 6];
    let mut i: i32 = 0_i32;
    while i < 6_i32 {
        f2[i as usize] = F[i as usize];
        i += 1;
    }
    let u0: u64 = d.u[0_i32 as usize];
    let u1: u64 = d.u[1_i32 as usize];
    let mut j: i32 = 4_i32;
    loop {
        let fresh0 = j;
        j -= 1;
        if fresh0 == 0 {
            break;
        }
        f2[j as usize] = residue_sub(f2[j as usize], residue_mul(u0, f2[(j + 2_i32) as usize]));
        f2[(j + 1_i32) as usize] = residue_sub(
            f2[(j + 1_i32) as usize],
            residue_mul(u1, f2[(j + 2_i32) as usize]),
        );
        f2[(j + 2_i32) as usize] = 0_i32 as u64;
    }
    // v = v0 + v1*x
    // u | (v0^2 - f0) + (2*v0*v1 - f1)*x + v1^2*x^2 = u0*v1^2 + u1*v1^2*x + v1^2*x^2
    // v0^2 - f0 = u0*v1^2
    // 2*v0*v1 - f1 = u1*v1^2
    // v0^2 = f0 + u0*v1^2 = (f1 + u1*v1^2)^2 / (2*v1)^2
    // (f1^2) + 2*(f1*u1-2*f0) * v1^2 + (u1^2-4*u0) * v1^4 = 0
    // v1^2 = ((2*f0-f1*u1) +- 2*sqrt(-f0*f1*u1 + f0^2 + f1^2*u0))) / (u1^2-4*u0)
    let f0: u64 = f2[0_i32 as usize];
    let f1: u64 = f2[1_i32 as usize];
    let u0double: u64 = residue_add(u0, u0);
    let coeff2: u64 = residue_sub(residue_mul(u1, u1), residue_add(u0double, u0double));
    let coeff1: u64 = residue_sub(residue_add(f0, f0), residue_mul(f1, u1));
    if coeff2 == 0_i32 as u64 {
        if coeff1 == 0_i32 as u64 {
            if f1 == 0_i32 as u64 {
                // impossible
                panic!("bad f(), double root detected");
            }
            return 0_i32;
        }
        let sqr: u64 = residue_mul(
            residue_mul(f1, f1),
            residue_inv(residue_add(coeff1, coeff1)),
        );
        v1 = residue_sqrt(sqr);
        if v1 == BAD {
            return 0_i32;
        }
    } else {
        let mut d_0: u64 = residue_add(
            residue_mul(f0, f0),
            residue_mul(f1, residue_sub(residue_mul(f1, u0), residue_mul(f0, u1))),
        );
        d_0 = residue_sqrt(d_0);
        if d_0 == BAD {
            return 0_i32;
        }
        d_0 = residue_add(d_0, d_0);
        let inv: u64 = residue_inv(coeff2);
        let mut root: u64 = residue_mul(residue_add(coeff1, d_0), inv);
        v1 = residue_sqrt(root);
        if v1 == BAD {
            root = residue_mul(residue_sub(coeff1, d_0), inv);
            v1 = residue_sqrt(root);
            if v1 == BAD {
                return 0_i32;
            }
        }
    }
    let v0: u64 = residue_mul(
        residue_add(f1, residue_mul(u1, residue_mul(v1, v1))),
        residue_inv(residue_add(v1, v1)),
    );
    d.v[0_i32 as usize] = v0;
    d.v[1_i32 as usize] = v1;
    1_i32
}

fn polynomial_mul(
    adeg: i32,
    a: &[u64],
    bdeg: i32,
    b: &[u64],
    mut resultprevdeg: i32,
    result: &mut [u64],
) -> i32 {
    // generic short slow code
    if adeg < 0_i32 || bdeg < 0_i32 {
        return resultprevdeg;
    }
    let mut i = resultprevdeg + 1_i32;
    while i <= adeg + bdeg {
        result[i as usize] = 0_i32 as u64;
        i += 1;
    }
    resultprevdeg = i - 1_i32;
    i = 0_i32;
    while i <= adeg {
        let mut j = 0_i32;
        while j <= bdeg {
            result[(i + j) as usize] = residue_add(
                result[(i + j) as usize],
                residue_mul(a[i as usize], b[j as usize]),
            );
            j += 1;
        }
        i += 1;
    }
    while resultprevdeg >= 0_i32 && result[resultprevdeg as usize] == 0_i32 as u64 {
        resultprevdeg -= 1;
    }
    resultprevdeg
}

fn polynomial_div_monic(
    adeg: i32,
    a: &mut [u64],
    bdeg: i32,
    b: &[u64],
    mut quotient: Option<&mut [u64]>,
) -> i32 {
    let mut i = adeg - bdeg;
    while i >= 0_i32 {
        let q: u64 = a[(i + bdeg) as usize];
        if let Some(ref mut quotient) = quotient {
            quotient[i as usize] = q;
        }
        let mut j = 0_i32;
        while j < bdeg {
            a[(i + j) as usize] = residue_sub(a[(i + j) as usize], residue_mul(q, b[j as usize]));
            j += 1;
        }
        a[(i + j) as usize] = 0_i32 as u64;
        i -= 1;
    }
    i += bdeg;
    while i >= 0_i32 && a[i as usize] == 0_i32 as u64 {
        i -= 1;
    }
    i
}

#[allow(clippy::too_many_arguments)]
fn polynomial_xgcd(
    adeg: i32,
    a: &[u64],
    bdeg: i32,
    b: &[u64],
    pgcddeg: &mut i32,
    gcd: &mut [u64],
    pmult1deg: &mut i32,
    mult1: &mut [u64],
    pmult2deg: &mut i32,
    mult2: &mut [u64],
) {
    let mut sdeg: i32 = -1_i32;
    let mut s: [u64; 3] = [0_i32 as u64, 0_i32 as u64, 0_i32 as u64];
    let mut mult1deg: i32 = 0_i32;
    mult1[0] = 1_i32 as u64;
    mult1[1] = 0_i32 as u64;
    mult1[2] = 0_i32 as u64;
    let mut tdeg: i32 = 0_i32;
    let mut t: [u64; 3] = [1_i32 as u64, 0_i32 as u64, 0_i32 as u64];
    let mut mult2deg: i32 = -1_i32;
    mult2[0] = 0_i32 as u64;
    mult2[1] = 0_i32 as u64;
    mult2[2] = 0_i32 as u64;
    let mut rdeg: i32 = bdeg;
    let mut r: [u64; 3] = [b[0], b[1], b[2]];
    let mut gcddeg: i32 = adeg;
    gcd[0] = a[0];
    gcd[1] = a[1];
    gcd[2] = a[2];
    // s*u1 + t*u2 = r
    // mult1*u1 + mult2*u2 = gcd
    while rdeg >= 0_i32 {
        if rdeg > gcddeg {
            let tmp = rdeg as u32;
            rdeg = gcddeg;
            gcddeg = tmp as i32;
            swap(&mut sdeg, &mut mult1deg);
            swap(&mut tdeg, &mut mult2deg);
            swap(&mut r[0], &mut gcd[0]);
            swap(&mut r[1], &mut gcd[1]);
            swap(&mut r[2], &mut gcd[2]);
            swap(&mut s[0], &mut mult1[0]);
            swap(&mut s[1], &mut mult1[1]);
            swap(&mut s[2], &mut mult1[2]);
            swap(&mut t[0], &mut mult2[0]);
            swap(&mut t[1], &mut mult2[1]);
            swap(&mut t[2], &mut mult2[2]);
        } else {
            let delta: i32 = gcddeg - rdeg;
            let mult: u64 = residue_mul(gcd[gcddeg as usize], residue_inv(r[rdeg as usize]));
            // quotient = mult * x**delta
            let mut i: i32 = 0_i32;
            while i <= rdeg {
                gcd[(i + delta) as usize] =
                    residue_sub(gcd[(i + delta) as usize], residue_mul(mult, r[i as usize]));
                i += 1;
            }
            while gcddeg >= 0_i32 && gcd[gcddeg as usize] == 0_i32 as u64 {
                gcddeg -= 1;
            }
            let mut i_0: i32 = 0_i32;
            while i_0 <= sdeg {
                mult1[(i_0 + delta) as usize] = residue_sub(
                    mult1[(i_0 + delta) as usize],
                    residue_mul(mult, s[i_0 as usize]),
                );
                i_0 += 1;
            }
            if mult1deg < sdeg + delta {
                mult1deg = sdeg + delta;
            }
            while mult1deg >= 0_i32 && mult1[mult1deg as usize] == 0_i32 as u64 {
                mult1deg -= 1;
            }
            let mut i_1: i32 = 0_i32;
            while i_1 <= tdeg {
                mult2[(i_1 + delta) as usize] = residue_sub(
                    mult2[(i_1 + delta) as usize],
                    residue_mul(mult, t[i_1 as usize]),
                );
                i_1 += 1;
            }
            if mult2deg < tdeg + delta {
                mult2deg = tdeg + delta;
            }
            while mult2deg >= 0_i32 && mult2[mult2deg as usize] == 0_i32 as u64 {
                mult2deg -= 1;
            }
        }
    }
    // d1 = gcd, e1 = mult1, e2 = mult2
    *pgcddeg = gcddeg;
    *pmult1deg = mult1deg;
    *pmult2deg = mult2deg;
}

fn u2poly(src: &TDivisor, polyu: &mut [u64], polyv: &mut [u64]) -> i32 {
    if src.u[1_i32 as usize] != BAD {
        polyu[0_i32 as usize] = src.u[0_i32 as usize];
        polyu[1_i32 as usize] = src.u[1_i32 as usize];
        polyu[2_i32 as usize] = 1_i32 as u64;
        polyv[0_i32 as usize] = src.v[0_i32 as usize];
        polyv[1_i32 as usize] = src.v[1_i32 as usize];
        return 2_i32;
    }
    if src.u[0_i32 as usize] != BAD {
        polyu[0_i32 as usize] = src.u[0_i32 as usize];
        polyu[1_i32 as usize] = 1_i32 as u64;
        polyv[0_i32 as usize] = src.v[0_i32 as usize];
        polyv[1_i32 as usize] = 0_i32 as u64;
        return 1_i32;
    }
    polyu[0_i32 as usize] = 1_i32 as u64;
    polyv[0_i32 as usize] = 0_i32 as u64;
    polyv[1_i32 as usize] = 0_i32 as u64;
    0_i32
}

fn divisor_add(src1: &TDivisor, src2: &TDivisor, dst: &mut TDivisor) {
    let mut u1: [u64; 3] = [0; 3];
    let mut u2: [u64; 3] = [0; 3];
    let mut v1: [u64; 2] = [0; 2];
    let mut v2: [u64; 2] = [0; 2];
    let u1deg: i32 = u2poly(src1, &mut u1, &mut v1);
    let u2deg: i32 = u2poly(src2, &mut u2, &mut v2);
    // extended gcd: d1 = gcd(u1, u2) = e1*u1 + e2*u2
    let mut d1deg: i32 = 0;
    let mut e1deg: i32 = 0;
    let mut e2deg: i32 = 0;
    let mut d1: [u64; 3] = [0; 3];
    let mut e1: [u64; 3] = [0; 3];
    let mut e2: [u64; 3] = [0; 3];
    polynomial_xgcd(
        u1deg, &u1, u2deg, &u2, &mut d1deg, &mut d1, &mut e1deg, &mut e1, &mut e2deg, &mut e2,
    );
    // extended gcd again: d = gcd(d1, v1+v2) = c1*d1 + c2*(v1+v2)
    let b: [u64; 3] = [
        residue_add(v1[0_i32 as usize], v2[0_i32 as usize]),
        residue_add(v1[1_i32 as usize], v2[1_i32 as usize]),
        0_i32 as u64,
    ];
    let bdeg: i32 = if b[1_i32 as usize] == 0_i32 as u64 {
        if b[0_i32 as usize] == 0_i32 as u64 {
            -1_i32
        } else {
            0_i32
        }
    } else {
        1_i32
    };
    let mut ddeg: i32 = 0;
    let mut c1deg: i32 = 0;
    let mut c2deg: i32 = 0;
    let mut d: [u64; 3] = [0; 3];
    let mut c1: [u64; 3] = [0; 3];
    let mut c2: [u64; 3] = [0; 3];
    polynomial_xgcd(
        d1deg, &d1, bdeg, &b, &mut ddeg, &mut d, &mut c1deg, &mut c1, &mut c2deg, &mut c2,
    );
    let dmult: u64 = residue_inv(d[ddeg as usize]);
    let mut i = 0_i32;
    while i < ddeg {
        d[i as usize] = residue_mul(d[i as usize], dmult);
        i += 1;
    }
    d[i as usize] = 1_i32 as u64;
    i = 0_i32;
    while i <= c1deg {
        c1[i as usize] = residue_mul(c1[i as usize], dmult);
        i += 1;
    }
    i = 0_i32;
    while i <= c2deg {
        c2[i as usize] = residue_mul(c2[i as usize], dmult);
        i += 1;
    }
    let mut u: [u64; 5] = [0; 5];
    let mut udeg: i32 = polynomial_mul(u1deg, &u1, u2deg, &u2, -1_i32, &mut u);
    // u is monic
    let mut v: [u64; 7] = [0; 7];
    let mut tmp: [u64; 7] = [0; 7];
    // c1*(e1*u1*v2 + e2*u2*v1) + c2*(v1*v2 + f)
    // c1*(e1*u1*(v2-v1) + d1*v1) + c2*(v1*v2 + f)
    v[0_i32 as usize] = residue_sub(v2[0_i32 as usize], v1[0_i32 as usize]);
    v[1_i32 as usize] = residue_sub(v2[1_i32 as usize], v1[1_i32 as usize]);
    let mut tmpdeg = polynomial_mul(e1deg, &e1, 1_i32, &v, -1_i32, &mut tmp);
    let mut vdeg = polynomial_mul(u1deg, &u1, tmpdeg, &tmp, -1_i32, &mut v);
    vdeg = polynomial_mul(d1deg, &d1, 1_i32, &v1, vdeg, &mut v);
    i = 0_i32;
    while i <= vdeg {
        v[i as usize] = residue_mul(v[i as usize], c1[0_i32 as usize]);
        i += 1;
    }
    tmp[0] = F[0];
    tmp[1] = F[1];
    tmp[2] = F[2];
    tmp[3] = F[3];
    tmp[4] = F[4];
    tmp[5] = F[5];
    tmpdeg = 5_i32;
    tmpdeg = polynomial_mul(1_i32, &v1, 1_i32, &v2, tmpdeg, &mut tmp);
    vdeg = polynomial_mul(c2deg, &c2, tmpdeg, &tmp, vdeg, &mut v);
    if ddeg > 0_i32 {
        let mut udiv: [u64; 5] = [0; 5];
        polynomial_div_monic(udeg, &mut u, ddeg, &d, Some(&mut udiv));
        udeg -= ddeg;
        polynomial_div_monic(udeg, &mut udiv, ddeg, &d, Some(&mut u));
        udeg -= ddeg;
        if vdeg >= 0_i32 {
            polynomial_div_monic(vdeg, &mut v, ddeg, &d, Some(&mut udiv));
            vdeg -= ddeg;
            for i in 0..=vdeg {
                v[i as usize] = udiv[i as usize];
            }
        }
    }
    vdeg = polynomial_div_monic(vdeg, &mut v, udeg, &u, None);
    while udeg > 2_i32 {
        // u' = monic((f-v^2)/u), v'=-v mod u'
        tmpdeg = polynomial_mul(vdeg, &v, vdeg, &v, -1_i32, &mut tmp);
        i = 0_i32;
        while i <= tmpdeg && i <= 5_i32 {
            tmp[i as usize] = residue_sub(F[i as usize], tmp[i as usize]);
            i += 1;
        }
        while i <= tmpdeg {
            tmp[i as usize] = residue_sub(0_i32 as u64, tmp[i as usize]);
            i += 1;
        }
        while i <= 5_i32 {
            tmp[i as usize] = F[i as usize];
            i += 1;
        }
        tmpdeg = i - 1_i32;
        let mut udiv_0: [u64; 5] = [0; 5];
        polynomial_div_monic(tmpdeg, &mut tmp, udeg, &u, Some(&mut udiv_0));
        udeg = tmpdeg - udeg;
        let mult: u64 = residue_inv(udiv_0[udeg as usize]);
        i = 0_i32;
        while i < udeg {
            u[i as usize] = residue_mul(udiv_0[i as usize], mult);
            i += 1;
        }
        u[i as usize] = 1_i32 as u64;
        i = 0_i32;
        while i <= vdeg {
            v[i as usize] = residue_sub(0_i32 as u64, v[i as usize]);
            i += 1;
        }
        vdeg = polynomial_div_monic(vdeg, &mut v, udeg, &u, None);
    }
    if udeg == 2_i32 {
        dst.u[0_i32 as usize] = u[0_i32 as usize];
        dst.u[1_i32 as usize] = u[1_i32 as usize];
        dst.v[0_i32 as usize] = if vdeg >= 0_i32 {
            v[0_i32 as usize]
        } else {
            0_i32 as u64
        };
        dst.v[1_i32 as usize] = if vdeg >= 1_i32 {
            v[1_i32 as usize]
        } else {
            0_i32 as u64
        };
    } else if udeg == 1_i32 {
        dst.u[0_i32 as usize] = u[0_i32 as usize];
        dst.u[1_i32 as usize] = BAD;
        dst.v[0_i32 as usize] = if vdeg >= 0_i32 {
            v[0_i32 as usize]
        } else {
            0_i32 as u64
        };
        dst.v[1_i32 as usize] = BAD;
    } else {
        dst.u[0_i32 as usize] = BAD;
        dst.u[1_i32 as usize] = BAD;
        dst.v[0_i32 as usize] = BAD;
        dst.v[1_i32 as usize] = BAD;
    };
}

fn divisor_mul128(src: &TDivisor, mut mult_lo: u64, mut mult_hi: u64, dst: &mut TDivisor) {
    if mult_lo == 0_i32 as u64 && mult_hi == 0_i32 as u64 {
        dst.u[0_i32 as usize] = BAD;
        dst.u[1_i32 as usize] = BAD;
        dst.v[0_i32 as usize] = BAD;
        dst.v[1_i32 as usize] = BAD;
        return;
    }
    let mut cur: TDivisor = *src;
    while mult_lo & 1_i32 as u64 == 0 {
        {
            let tmp = cur;
            divisor_add(&tmp, &tmp, &mut cur);
        }
        mult_lo >>= 1_i32;
        if mult_hi & 1_i32 as u64 != 0 {
            mult_lo |= 1_u64 << 63_i32;
        }
        mult_hi >>= 1_i32;
    }
    *dst = cur;
    loop {
        mult_lo >>= 1_i32;
        if mult_hi & 1_i32 as u64 != 0 {
            mult_lo |= 1_u64 << 63_i32;
        }
        mult_hi >>= 1_i32;
        if mult_lo == 0_i32 as u64 && mult_hi == 0_i32 as u64 {
            break;
        }
        {
            let tmp = cur;
            divisor_add(&tmp, &tmp, &mut cur);
        }
        if mult_lo & 1_i32 as u64 != 0 {
            divisor_add(&(dst.clone()), &cur, dst);
        }
    }
}

fn rol(x: u32, shift: i32) -> u32 {
    x << shift | x >> (32_i32 - shift)
}

fn sha1_single_block(input: &[u8], output: &mut [u8]) {
    let mut a = 0x67452301_i32 as u32;
    let mut b = 0xefcdab89_u32;
    let mut c = 0x98badcfe_u32;
    let mut d = 0x10325476_i32 as u32;
    let mut e = 0xc3d2e1f0_u32;
    let mut w: [u32; 80] = [0; 80];
    let mut i = 0_i32 as usize;
    while i < 16 {
        w[i] = ((input[4_usize.wrapping_mul(i)] as i32) << 24_i32
            | (input[4_usize.wrapping_mul(i).wrapping_add(1)] as i32) << 16_i32
            | (input[4_usize.wrapping_mul(i).wrapping_add(2)] as i32) << 8_i32
            | input[4_usize.wrapping_mul(i).wrapping_add(3)] as i32) as u32;
        i = i.wrapping_add(1);
    }
    i = 16_i32 as usize;
    while i < 80 {
        w[i] = rol(
            w[i.wrapping_sub(3)]
                ^ w[i.wrapping_sub(8)]
                ^ w[i.wrapping_sub(14)]
                ^ w[i.wrapping_sub(16)],
            1_i32,
        );
        i = i.wrapping_add(1);
    }
    i = 0_i32 as usize;
    while i < 20 {
        let tmp: u32 = (rol(a, 5_i32))
            .wrapping_add(b & c | !b & d)
            .wrapping_add(e)
            .wrapping_add(w[i])
            .wrapping_add(0x5a827999_i32 as u32);
        e = d;
        d = c;
        c = rol(b, 30_i32);
        b = a;
        a = tmp;
        i = i.wrapping_add(1);
    }
    i = 20_i32 as usize;
    while i < 40 {
        let tmp_0: u32 = (rol(a, 5_i32))
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(w[i])
            .wrapping_add(0x6ed9eba1_i32 as u32);
        e = d;
        d = c;
        c = rol(b, 30_i32);
        b = a;
        a = tmp_0;
        i = i.wrapping_add(1);
    }
    i = 40_i32 as usize;
    while i < 60 {
        let tmp_1: u32 = (rol(a, 5_i32))
            .wrapping_add(b & c | b & d | c & d)
            .wrapping_add(e)
            .wrapping_add(w[i])
            .wrapping_add(0x8f1bbcdc_u32);
        e = d;
        d = c;
        c = rol(b, 30_i32);
        b = a;
        a = tmp_1;
        i = i.wrapping_add(1);
    }
    i = 60_i32 as usize;
    while i < 80 {
        let tmp_2: u32 = (rol(a, 5_i32))
            .wrapping_add(b ^ c ^ d)
            .wrapping_add(e)
            .wrapping_add(w[i])
            .wrapping_add(0xca62c1d6_u32);
        e = d;
        d = c;
        c = rol(b, 30_i32);
        b = a;
        a = tmp_2;
        i = i.wrapping_add(1);
    }
    a = a.wrapping_add(0x67452301_i32 as u32);
    b = b.wrapping_add(0xefcdab89_u32);
    c = c.wrapping_add(0x98badcfe_u32);
    d = d.wrapping_add(0x10325476_i32 as u32);
    e = e.wrapping_add(0xc3d2e1f0_u32);
    output[0] = (a >> 24_i32) as u8;
    output[1] = (a >> 16_i32) as u8;
    output[2] = (a >> 8_i32) as u8;
    output[3] = a as u8;
    output[4] = (b >> 24_i32) as u8;
    output[5] = (b >> 16_i32) as u8;
    output[6] = (b >> 8_i32) as u8;
    output[7] = b as u8;
    output[8] = (c >> 24_i32) as u8;
    output[9] = (c >> 16_i32) as u8;
    output[10] = (c >> 8_i32) as u8;
    output[11] = c as u8;
    output[12] = (d >> 24_i32) as u8;
    output[13] = (d >> 16_i32) as u8;
    output[14] = (d >> 8_i32) as u8;
    output[15] = d as u8;
    output[16] = (e >> 24_i32) as u8;
    output[17] = (e >> 16_i32) as u8;
    output[18] = (e >> 8_i32) as u8;
    output[19] = e as u8;
}

fn mix(buffer: &mut [u8], buf_size: usize, key: &[u8], key_size: usize) {
    let mut sha1_input: [u8; 64] = [0; 64];
    let mut sha1_result: [u8; 20] = [0; 20];
    let half: usize = buf_size.wrapping_div(2);
    let mut external_counter = 0_i32;
    while external_counter < 4_i32 {
        for n in &mut sha1_input {
            *n = 0;
        }
        sha1_input[..half].copy_from_slice(&buffer[half..]);
        sha1_input[half..half.wrapping_add(key_size)].copy_from_slice(key);
        sha1_input[half.wrapping_add(key_size)] = 0x80_i32 as u8;
        sha1_input[(size_of::<[u8; 64]>() as u64).wrapping_sub(1_i32 as u64) as usize] =
            half.wrapping_add(key_size).wrapping_mul(8) as u8;
        sha1_input[(size_of::<[u8; 64]>() as u64).wrapping_sub(2_i32 as u64) as usize] =
            half.wrapping_add(key_size)
                .wrapping_mul(8)
                .wrapping_div(0x100) as u8;
        sha1_single_block(&sha1_input, &mut sha1_result);
        let mut i = half & !3;
        while i < half {
            sha1_result[i] = sha1_result[i.wrapping_add(4).wrapping_sub(half & 3)];
            i = i.wrapping_add(1);
        }
        i = 0_i32 as usize;
        while i < half {
            let tmp: u8 = buffer[i.wrapping_add(half)];
            buffer[i.wrapping_add(half)] = (buffer[i] as i32 ^ sha1_result[i] as i32) as u8;
            buffer[i] = tmp;
            i = i.wrapping_add(1);
        }
        external_counter += 1;
    }
}

fn unmix(buffer: &mut [u8], buf_size: usize, key: &[u8], key_size: usize) {
    let mut sha1_input: [u8; 64] = [0; 64];
    let mut sha1_result: [u8; 20] = [0; 20];
    let half: usize = buf_size.wrapping_div(2);
    let mut external_counter = 0_i32;
    while external_counter < 4_i32 {
        for n in &mut sha1_input {
            *n = 0;
        }
        sha1_input[..half].copy_from_slice(&buffer[..half]);
        sha1_input[half..half.wrapping_add(key_size)].copy_from_slice(key);
        sha1_input[half.wrapping_add(key_size)] = 0x80_i32 as u8;
        sha1_input[(size_of::<[u8; 64]>() as u64).wrapping_sub(1_i32 as u64) as usize] =
            half.wrapping_add(key_size).wrapping_mul(8) as u8;
        sha1_input[(size_of::<[u8; 64]>() as u64).wrapping_sub(2_i32 as u64) as usize] =
            half.wrapping_add(key_size)
                .wrapping_mul(8)
                .wrapping_div(0x100) as u8;
        sha1_single_block(&sha1_input, &mut sha1_result);
        let mut i = half & !3;
        while i < half {
            sha1_result[i] = sha1_result[i.wrapping_add(4).wrapping_sub(half & 3)];
            i = i.wrapping_add(1);
        }
        i = 0_i32 as usize;
        while i < half {
            let tmp: u8 = buffer[i];
            buffer[i] = (buffer[i.wrapping_add(half)] as i32 ^ sha1_result[i] as i32) as u8;
            buffer[i.wrapping_add(half)] = tmp;
            i = i.wrapping_add(1);
        }
        external_counter += 1;
    }
}

pub fn generate(installation_id_str: &[u8], confirmation_id: &mut [u8]) -> i32 {
    let mut installation_id: [u8; 19] = [0; 19]; // 10**45 < 256**19
    let mut installation_id_len: usize = 0_i32 as usize;
    let mut count: usize = 0_i32 as usize;
    let mut total_count: usize = 0_i32 as usize;
    let mut check: u32 = 0_i32 as u32;
    let mut installation_id_str = installation_id_str.iter().peekable();
    while let Some(p) = installation_id_str.next() {
        let p_curr = *p as i8;
        if !(p_curr as i32 == ' ' as i32 || p_curr as i32 == '-' as i32) {
            let d: i32 = p_curr as i32 - '0' as i32;
            if !(0_i32..=9_i32).contains(&d) {
                return 3_i32;
            }
            if count == 5 || installation_id_str.peek().is_none() {
                if d as u32 != check.wrapping_rem(7_i32 as u32) {
                    return if count < 5 { 1_i32 } else { 4_i32 };
                }
                check = 0_i32 as u32;
                count = 0_i32 as usize;
            } else {
                check = check.wrapping_add(
                    (if count.wrapping_rem(2) != 0 {
                        d * 2_i32
                    } else {
                        d
                    }) as u32,
                );
                count = count.wrapping_add(1);
                total_count = total_count.wrapping_add(1);
                if total_count > 45 {
                    return 2_i32;
                }
                let mut carry: u8 = d as u8;
                let mut i = 0_i32 as usize;
                while i < installation_id_len {
                    let x: u32 = (installation_id[i] as i32 * 10_i32 + carry as i32) as u32;
                    installation_id[i] = (x & 0xff_i32 as u32) as u8;
                    carry = (x >> 8_i32) as u8;
                    i = i.wrapping_add(1);
                }
                if carry != 0 {
                    let fresh1 = installation_id_len;
                    installation_id_len = installation_id_len.wrapping_add(1);
                    installation_id[fresh1] = carry;
                }
            }
        }
    }
    if total_count != 41 && total_count < 45 {
        return 1_i32;
    }
    while installation_id_len < size_of::<[u8; 19]>() {
        installation_id[installation_id_len] = 0_i32 as u8;
        installation_id_len = installation_id_len.wrapping_add(1);
    }
    const IID_KEY: [u8; 4] = [
        0x6a_i32 as u8,
        0xc8_i32 as u8,
        0x5e_i32 as u8,
        0xd4_i32 as u8,
    ];
    unmix(
        &mut installation_id,
        (if total_count == 41 { 17_i32 } else { 19_i32 }) as usize,
        &IID_KEY,
        4_i32 as usize,
    );
    if installation_id[18_i32 as usize] as i32 >= 0x10_i32 {
        return 5_i32;
    }
    let mut parsed = ParsedInstallationId {
        hardware_id: 0,
        product_id_low: 0,
        product_id_high: 0,
        key_sha1: 0,
    };

    let hardware_id_bytes: [u8; 8] = installation_id[0..8].try_into().unwrap();
    parsed.hardware_id = u64::from_le_bytes(hardware_id_bytes);

    let product_id_low_bytes: [u8; 8] = installation_id[8..16].try_into().unwrap();
    parsed.product_id_low = u64::from_le_bytes(product_id_low_bytes);

    parsed.product_id_high = installation_id[16];

    let key_sha1_bytes: [u8; 2] = installation_id[17..19].try_into().unwrap();
    parsed.key_sha1 = u16::from_le_bytes(key_sha1_bytes);

    let product_id_1: u32 = (parsed.product_id_low & ((1_i32 << 17_i32) - 1_i32) as u64) as u32;
    let product_id_2: u32 =
        (parsed.product_id_low >> 17_i32 & ((1_i32 << 10_i32) - 1_i32) as u64) as u32;
    let product_id_3: u32 =
        (parsed.product_id_low >> 27_i32 & ((1_i32 << 25_i32) - 1_i32) as u64) as u32;
    let version: u32 = (parsed.product_id_low >> 52_i32 & 7_i32 as u64) as u32;
    let product_id_4: u32 = (parsed.product_id_low >> 55_i32
        | ((parsed.product_id_high as i32) << 9_i32) as u64) as u32;
    if version != (if total_count == 41 { 4_i32 } else { 5_i32 }) as u32 {
        return 5_i32;
    }
    let mut keybuf: [u8; 16] = [0; 16];
    keybuf[..8].copy_from_slice(&parsed.hardware_id.to_le_bytes()[..8]);
    let product_id_mixed: u64 = (product_id_1 as u64) << 41_i32
        | (product_id_2 as u64) << 58_i32
        | (product_id_3 as u64) << 17_i32
        | product_id_4 as u64;
    keybuf[8..16].copy_from_slice(&product_id_mixed.to_le_bytes()[..8]);
    let mut d_0: TDivisor = TDivisor {
        u: [0; 2],
        v: [0; 2],
    };
    let mut attempt = 0_i32 as u8;
    while attempt as i32 <= 0x80_i32 {
        let mut u: [u8; 14] = [0; 14];
        u[7_i32 as usize] = attempt;
        mix(&mut u, 14_i32 as usize, &keybuf, 16_i32 as usize);
        let u_lo = u64::from_le_bytes(u[0..8].try_into().unwrap());
        let u_hi = u64::from_le_bytes(
            u[8..14]
                .iter()
                .chain([0, 0].iter())
                .cloned()
                .collect::<Vec<u8>>()[..]
                .try_into()
                .unwrap(),
        );
        let mut x2: u64 = ui128_quotient_mod(u_lo, u_hi);
        let x1: u64 = u_lo.wrapping_sub(x2.wrapping_mul(MOD));
        x2 = x2.wrapping_add(1);
        d_0.u[0_i32 as usize] = residue_sub(
            residue_mul(x1, x1),
            residue_mul(43_i32 as u64, residue_mul(x2, x2)),
        );
        d_0.u[1_i32 as usize] = residue_add(x1, x1);
        if find_divisor_v(&mut d_0) != 0 {
            break;
        }
        attempt = attempt.wrapping_add(1);
    }
    if attempt as i32 > 0x80_i32 {
        return 6_i32;
    }
    divisor_mul128(
        &(d_0.clone()),
        0x4e21b9d10f127c1_i64 as u64,
        0x40da7c36d44c_i64 as u64,
        &mut d_0,
    );
    let mut e = Encoded {
        encoded_lo: 0,
        encoded_hi: 0,
    };
    if d_0.u[0_i32 as usize] == BAD {
        // we can not get the zero divisor, actually...
        e.encoded_lo = umul128(MOD.wrapping_add(2_i32 as u64), MOD, &mut e.encoded_hi);
    } else if d_0.u[1_i32 as usize] == BAD {
        e.encoded_lo = umul128(
            MOD.wrapping_add(1_i32 as u64),
            d_0.u[0_i32 as usize],
            &mut e.encoded_hi,
        );
        e.encoded_lo = e.encoded_lo.wrapping_add(MOD);
        e.encoded_hi = e
            .encoded_hi
            .wrapping_add((e.encoded_lo < MOD) as i32 as u64);
    } else {
        let x1_0: u64 = (if d_0.u[1_i32 as usize] as i32 % 2_i32 != 0 {
            d_0.u[1_i32 as usize].wrapping_add(MOD)
        } else {
            d_0.u[1_i32 as usize]
        })
        .wrapping_div(2_i32 as u64);
        let x2sqr: u64 = residue_sub(residue_mul(x1_0, x1_0), d_0.u[0_i32 as usize]);
        let mut x2_0: u64 = residue_sqrt(x2sqr);
        if x2_0 == BAD {
            x2_0 = residue_sqrt(residue_mul(x2sqr, residue_inv(43_i32 as u64)));
            e.encoded_lo = umul128(
                MOD.wrapping_add(1_i32 as u64),
                MOD.wrapping_add(x2_0),
                &mut e.encoded_hi,
            );
            e.encoded_lo = e.encoded_lo.wrapping_add(x1_0);
            e.encoded_hi = e
                .encoded_hi
                .wrapping_add((e.encoded_lo < x1_0) as i32 as u64);
        } else {
            // points (-x1+x2, v(-x1+x2)) and (-x1-x2, v(-x1-x2))
            let mut x1a: u64 = residue_sub(x1_0, x2_0);
            let y1: u64 = residue_sub(
                d_0.v[0_i32 as usize],
                residue_mul(d_0.v[1_i32 as usize], x1a),
            );
            let mut x2a: u64 = residue_add(x1_0, x2_0);
            let y2: u64 = residue_sub(
                d_0.v[0_i32 as usize],
                residue_mul(d_0.v[1_i32 as usize], x2a),
            );
            if x1a > x2a {
                swap(&mut x1a, &mut x2a);
            }
            if (y1 ^ y2) & 1_i32 as u64 != 0 {
                swap(&mut x1a, &mut x2a);
            }
            e.encoded_lo = umul128(MOD.wrapping_add(1_i32 as u64), x1a, &mut e.encoded_hi);
            e.encoded_lo = e.encoded_lo.wrapping_add(x2a);
            e.encoded_hi = e
                .encoded_hi
                .wrapping_add((e.encoded_lo < x2a) as i32 as u64);
        }
    }
    let mut e_2 = [
        u32::from_le_bytes(e.encoded_lo.to_le_bytes()[0..4].try_into().unwrap()),
        u32::from_le_bytes(e.encoded_lo.to_le_bytes()[4..].try_into().unwrap()),
        u32::from_le_bytes(e.encoded_hi.to_le_bytes()[0..4].try_into().unwrap()),
        u32::from_le_bytes(e.encoded_hi.to_le_bytes()[4..].try_into().unwrap()),
    ];
    let mut decimal: [u8; 35] = [0; 35];
    let mut i = 0_i32 as usize;
    while i < 35 {
        let c: u32 = (e_2[3_i32 as usize]).wrapping_rem(10_i32 as u32);
        e_2[3_i32 as usize] = e_2[3_i32 as usize].wrapping_div(10_i32 as u32);
        let c2: u32 =
            ((c as u64) << 32_i32 | e_2[2_i32 as usize] as u64).wrapping_rem(10_i32 as u64) as u32;
        e_2[2_i32 as usize] =
            ((c as u64) << 32_i32 | e_2[2_i32 as usize] as u64).wrapping_div(10_i32 as u64) as u32;
        let c3: u32 =
            ((c2 as u64) << 32_i32 | e_2[1_i32 as usize] as u64).wrapping_rem(10_i32 as u64) as u32;
        e_2[1_i32 as usize] =
            ((c2 as u64) << 32_i32 | e_2[1_i32 as usize] as u64).wrapping_div(10_i32 as u64) as u32;
        let c4: u32 =
            ((c3 as u64) << 32_i32 | e_2[0_i32 as usize] as u64).wrapping_rem(10_i32 as u64) as u32;
        e_2[0_i32 as usize] =
            ((c3 as u64) << 32_i32 | e_2[0_i32 as usize] as u64).wrapping_div(10_i32 as u64) as u32;
        decimal[34_usize.wrapping_sub(i)] = c4 as u8;
        i = i.wrapping_add(1);
    }
    let q = confirmation_id;
    let mut i: usize = 0;
    let mut q_i = 0;
    while i < 7 {
        if i != 0 {
            q[q_i] = b'-';
            q_i += 1;
        }
        let p_0: &mut [u8] = &mut decimal[i.wrapping_mul(5)..];
        q[q_i] = (p_0[0] as i32 + '0' as i32) as u8;
        q[q_i + 1] = (p_0[1] as i32 + '0' as i32) as u8;
        q[q_i + 2] = (p_0[2] as i32 + '0' as i32) as u8;
        q[q_i + 3] = (p_0[3] as i32 + '0' as i32) as u8;
        q[q_i + 4] = (p_0[4] as i32 + '0' as i32) as u8;
        q[q_i + 5] = ((p_0[0] as i32
            + p_0[1] as i32 * 2_i32
            + p_0[2] as i32
            + p_0[3] as i32 * 2_i32
            + p_0[4] as i32)
            % 7_i32
            + '0' as i32) as u8;
        q_i = q_i.wrapping_add(6);
        i = i.wrapping_add(1);
    }
    0_i32
}
