use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use rand::{Rng, thread_rng};
use std::error::Error;
use lazy_static::lazy_static;
use num_integer::Integer;

#[derive(Debug)]
pub struct RabinUser {
    pub private_key_p: BigInt,
    pub private_key_q: BigInt,
    pub public_key_n: BigInt,
    pub public_key_b: BigInt,
}

lazy_static! {
    static ref Q_BBS: BigInt = BigInt::parse_bytes(b"CF5CF5C453454C321D21398A8DE197D5E742A3F88F27C5A3", 16).unwrap();
    static ref P_BBS: BigInt = BigInt::parse_bytes(b"E7E7E7E8ABCDEF0123456789ABCDEF0123456789ABCDEF012", 16).unwrap();
    static ref N_BBS: BigInt = BigInt::parse_bytes(b"B3C5D7E9F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9", 16).unwrap();
}

impl RabinUser {
    pub fn new() -> Self {
        RabinUser {
            private_key_p: BigInt::zero(),
            private_key_q: BigInt::zero(),
            public_key_n: BigInt::zero(),
            public_key_b: BigInt::zero(),
        }
    }

    pub fn generate_key_pair(&mut self, bit_size: u32, miller_rabin_iterations: u32) {
        let mut rng = thread_rng();

        loop {
            let p = generate_random_prime_with_bbs(bit_size, miller_rabin_iterations);
            if &p % 4 == 3.into() {
                self.private_key_p = p;
                break;
            }
        }

        loop {
            let q = generate_random_prime_with_bbs(bit_size, miller_rabin_iterations);
            if &q % 4 == 3.into() {
                self.private_key_q = q;
                break;
            }
        }

        self.public_key_n = &self.private_key_p * &self.private_key_q;
        self.public_key_b = rng.gen_bigint_range(&BigInt::zero(), &self.public_key_n);

        println!("Generated keys:");
        println!("Private key P: {}", self.private_key_p);
        println!("Private key Q: {}", self.private_key_q);
        println!("Public key N: {}", self.public_key_n);
        println!("Public key B: {}", self.public_key_b);
    }

    pub fn encrypt(&self, message: &BigInt) -> Result<(BigInt, (BigInt, BigInt)), Box<dyn Error>> {
        let x = format_message(message, &self.public_key_n)?;
        let y = (&x * (&x + &self.public_key_b)) % &self.public_key_n;

        let two = BigInt::from(2);
        let b_half = mod_inverse(&two, &self.public_key_n)? * &self.public_key_b % &self.public_key_n;
        let x_plus_b_half = (&x + &b_half) % &self.public_key_n;

        let c1 = &x_plus_b_half % &two;
        let c2 = if jacobi_symbol(&x_plus_b_half, &self.public_key_n) == 1 {
            BigInt::one()
        } else {
            BigInt::zero()
        };

        Ok((y, (c1, c2)))
    }

    pub fn decrypt(&self, ciphertext: &BigInt, indicators: &(BigInt, BigInt)) -> Result<BigInt, Box<dyn Error>> {
        let (c1, c2) = indicators;
        let four_inv = mod_inverse(&BigInt::from(4), &self.public_key_n)?;
        let y = (ciphertext + &four_inv * &self.public_key_b * &self.public_key_b) % &self.public_key_n;

        let roots = compute_square_roots(&y, &self.private_key_p, &self.private_key_q, &self.public_key_n)?;

        let two = BigInt::from(2);
        let b_half = mod_inverse(&two, &self.public_key_n)? * &self.public_key_b % &self.public_key_n;

        for x in roots {
            let xp = ((&x - &b_half) % &self.public_key_n + &self.public_key_n) % &self.public_key_n;
            let c1_calc = &x % &two;
            let c2_calc = if jacobi_symbol(&x, &self.public_key_n) == 1 {
                BigInt::one()
            } else {
                BigInt::zero()
            };

            if &c1_calc == c1 && &c2_calc == c2 {
                let l = (self.public_key_n.bits() as usize + 7) / 8;
                if &xp >> (8 * (l - 2)) == BigInt::from(255) {
                    return Ok((BigInt::from(255) << (8 * (l - 2)) ^ xp) >> 64);
                }
            }
        }

        Err("Failed to decrypt: no matching root found".into())
    }

    pub fn sign_message(&self, message: &BigInt) -> Result<BigInt, Box<dyn Error>> {
        let mut rng = thread_rng();
        
        loop {
            let formatted_message = format_message(message, &self.public_key_n)?;
            
            if jacobi_symbol(&formatted_message, &self.private_key_p) == 1 
               && jacobi_symbol(&formatted_message, &self.private_key_q) == 1 {
                
                let roots = compute_square_roots(
                    &formatted_message,
                    &self.private_key_p,
                    &self.private_key_q,
                    &self.public_key_n
                )?;
                
                return Ok(roots[rng.gen_range(0..roots.len())].clone());
            }
        }
    }

    pub fn verify_signature(&self, message: &BigInt, signature: &BigInt) -> bool {
        let x_prime = (signature * signature) % &self.public_key_n;
        let l = (self.public_key_n.bits() as usize + 7) / 8;

        if &x_prime >> (8 * (l - 2)) == BigInt::from(255) {
            let recovered = (BigInt::from(255) << (8 * (l - 2)) ^ x_prime) >> 64;
            return &recovered == message;
        }
        false
    }
}

fn bbs_bit(size: u32) -> BigInt {
    let mut rng = thread_rng();
    let mut result = BigInt::zero();
    let mut r = rng.gen_bigint_range(&BigInt::zero(), &P_BBS);

    if r == BigInt::one() || r == BigInt::zero() {
        r = rng.gen_bigint_range(&BigInt::zero(), &P_BBS);
    }

    for i in 0..size {
        r = r.modpow(&BigInt::from(2), &N_BBS);
        let x = &r % 2;
        result += x << i;
    }
    result
}

fn is_prime_trial_division(n: &BigInt) -> bool {
    if n < &BigInt::from(2) {
        return false;
    }
    if n == &BigInt::from(2) || n == &BigInt::from(3) {
        return true;
    }
    if n % 2 == BigInt::zero() {
        return false;
    }

    let small_primes = vec![2, 3, 5, 7, 11, 13, 17];
    for &prime in &small_primes {
        if n % prime == BigInt::zero() && n != &BigInt::from(prime) {
            return false;
        }
    }
    true
}

fn miller_rabin_test(p: &BigInt, k: u32) -> bool {
    if p < &BigInt::from(2) {
        return false;
    }
    if p == &BigInt::from(2) || p == &BigInt::from(3) {
        return true;
    }
    if p % 2 == BigInt::zero() {
        return false;
    }

    let mut d = p - 1;
    let mut s = 0;
    while &d % 2 == BigInt::zero() {
        d /= 2;
        s += 1;
    }

    'outer: for _ in 0..k {
        let x = bbs_bit(16) % p;
        if x.gcd(p) != BigInt::one() {
            return false;
        }

        let mut x_pow = x.modpow(&d, p);
        if x_pow == BigInt::one() || x_pow == p - 1 {
            continue;
        }

        for _ in 1..s {
            x_pow = x_pow.modpow(&BigInt::from(2), p);
            if x_pow == p - 1 {
                continue 'outer;
            }
            if x_pow == BigInt::one() {
                return false;
            }
        }
        return false;
    }
    true
}

fn generate_random_prime_with_bbs(bit_size: u32, miller_rabin_iterations: u32) -> BigInt {
    loop {
        let mut candidate = bbs_bit(bit_size);
        if &candidate % 2 == BigInt::zero() {
            candidate += 1;
        }

        if !is_prime_trial_division(&candidate) {
            continue;
        }

        if miller_rabin_test(&candidate, miller_rabin_iterations) {
            return candidate;
        }
    }
}

fn mod_inverse(a: &BigInt, n: &BigInt) -> Result<BigInt, Box<dyn Error>> {
    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = n.clone();
    let mut newr = a.clone();

    while newr != BigInt::zero() {
        let quotient = &r / &newr;
        let temp_t = t.clone();
        t = newt.clone();
        newt = temp_t - &quotient * &newt;
        let temp_r = r.clone();
        r = newr.clone();
        newr = temp_r - &quotient * &newr;
    }

    if r > BigInt::one() {
        return Err("a is not invertible".into());
    }
    if t < BigInt::zero() {
        t += n;
    }
    Ok(t)
}

fn jacobi_symbol(x: &BigInt, n: &BigInt) -> i32 {
    if x.gcd(n) != BigInt::one() {
        return 0;
    }

    let mut a = x.clone();
    let mut b = n.clone();
    let mut jacobi = 1;

    while a != BigInt::zero() {
        while &a % 2 == BigInt::zero() {
            a /= 2;
            if &b % 8 == BigInt::from(3) || &b % 8 == BigInt::from(5) {
                jacobi = -jacobi;
            }
        }

        std::mem::swap(&mut a, &mut b);
        if &a % 4 == BigInt::from(3) && &b % 4 == BigInt::from(3) {
            jacobi = -jacobi;
        }
        a %= &b;
    }

    if b == BigInt::one() { jacobi } else { 0 }
}

fn format_message(m: &BigInt, n: &BigInt) -> Result<BigInt, Box<dyn Error>> {
    let l = (n.bits() as usize + 7) / 8;
    
    if m >= &(BigInt::from(1) << (8 * (l - 10))) {
        return Err("Message is too large for formatting".into());
    }

    let mut rng = thread_rng();
    let r = rng.gen::<u64>();
    
    Ok((BigInt::from(255) << (8 * (l - 2))) + (m << 64) + r)
}

fn compute_square_roots(
    y: &BigInt,
    p: &BigInt,
    q: &BigInt,
    n: &BigInt
) -> Result<Vec<BigInt>, Box<dyn Error>> {
    let s1 = y.modpow(&((p + 1) / 4), p);
    let s2 = y.modpow(&((q + 1) / 4), q);

    let (u, v) = {
        let (gcd, x, y) = extended_gcd(p, q);
        (x, y)
    };

    let x1 = ((u.clone() * p * &s2 + v.clone() * q * &s1) % n + n) % n;
    let x2 = ((-u.clone() * p * &s2 + v.clone() * q * &s1) % n + n) % n;
    let x3 = ((u.clone() * p * &s2 - v.clone() * q * &s1) % n + n) % n;
    let x4 = ((-u * p * &s2 - v * q * &s1) % n + n) % n;

    Ok(vec![x1, x2, x3, x4])
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if *b == BigInt::zero() {
        (a.clone(), BigInt::one(), BigInt::zero())
    } else {
        let (d, x, y) = extended_gcd(b, &(a % b));
        (d, y.clone(), x - (a / b) * y)
    }
}
