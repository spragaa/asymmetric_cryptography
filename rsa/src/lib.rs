use num_bigint::{BigInt, RandomBits};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use std::str::FromStr;
use num_bigint::RandBigInt;
use num_traits::Num;

lazy_static::lazy_static! {
    static ref Q: BigInt = BigInt::from_str_radix("CF5CF5C453454C321D21398A8DE197D5E742A3F88F27C5A3", 16).unwrap();
    static ref P: BigInt = BigInt::from_str_radix("E7E7E7E8ABCDEF0123456789ABCDEF0123456789ABCDEF012", 16).unwrap();
    static ref N: BigInt = BigInt::from_str_radix("B3C5D7E9F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9", 16).unwrap();
}

pub fn hex_to_bigint(hex_str: &str) -> BigInt {
    BigInt::from_str_radix(&hex_str.replace("0x", ""), 16)
        .unwrap_or_else(|_| panic!("Invalid hex string: {}", hex_str))
}

pub fn bigint_to_hex(num: &BigInt) -> String {
    format!("{:x}", num)
}

pub struct RSA {
    pub private_key_d: BigInt,
    pub private_key_p: BigInt,
    pub private_key_q: BigInt,

    pub public_key_n: BigInt,
    pub public_key_e: BigInt,
}

impl RSA {
    pub fn new(bit_size: u32, miller_rabin_iterations: u32) -> Self {
        let mut rng = OsRng;

        let private_key_p = generate_random_prime(bit_size, miller_rabin_iterations);
        let private_key_q = generate_random_prime(bit_size, miller_rabin_iterations);

        let public_key_n = &private_key_p * &private_key_q;
        let public_key_e = BigInt::from(65537);

        let phi_n = (&private_key_p - 1) * (&private_key_q - 1);
        let private_key_d = mod_inverse(&public_key_e, &phi_n).unwrap();

        RSA {
            private_key_d,
            private_key_p,
            private_key_q,
            public_key_n,
            public_key_e,
        }
    }

    pub fn encrypt(&self, message: &BigInt, sender_public_key_e: &BigInt, sender_public_key_n: &BigInt) -> BigInt {
        mod_pow(message, sender_public_key_e, sender_public_key_n)
    }

    pub fn decrypt(&self, ciphertext: &BigInt, sender_private_key_d: &BigInt, sender_public_key_n: &BigInt) -> BigInt {
        mod_pow(ciphertext, sender_private_key_d, sender_public_key_n)
    }

    pub fn sign_message(&self, message: &BigInt, sender_private_key_d: &BigInt, sender_public_key_n: &BigInt) -> BigInt {
        mod_pow(message, sender_private_key_d, sender_public_key_n)
    }

    pub fn verify_signature(&self, message: &BigInt, signature: &BigInt, sender_public_key_e: &BigInt, sender_public_key_n: &BigInt) -> bool {
        let decrypted_signature = mod_pow(signature, sender_public_key_e, sender_public_key_n);
        decrypted_signature == *message
    }

    pub fn send_key(&self, key: &BigInt, rec_e: &BigInt, rec_n: &BigInt) -> (BigInt, BigInt) {
        let signature = self.sign_message(key, &self.private_key_d, &self.public_key_n);
        let encrypted_key = self.encrypt(key, rec_e, rec_n);
        let encrypted_signature = self.encrypt(&signature, rec_e, rec_n);

        println!("Encrypted key: {:x}", encrypted_key);
        println!("Encrypted signature: {:x}", encrypted_signature);

        (encrypted_key, encrypted_signature)
    }

    pub fn receive_key(
        &self,
        encrypted_key: &BigInt,
        encrypted_signature: &BigInt,
        sender_e: &BigInt,
        sender_n: &BigInt,
        d: &BigInt,
        n: &BigInt,
    ) -> bool {
        let decrypted_key = self.decrypt(encrypted_key, d, n);
        let decrypted_signature = self.decrypt(encrypted_signature, d, n);

        let is_signature_valid = self.verify_signature(
            &decrypted_key,
            &decrypted_signature,
            sender_e,
            sender_n,
        );

        if !is_signature_valid {
            eprintln!("Signature verification failed!");
            return false;
        }

        println!("Decrypted key: {}", decrypted_key);
        println!("Signature verified successfully!");

        true
    }
}

fn bbs_bit(q: &BigInt, p: &BigInt, n: &BigInt, size: u32) -> BigInt {
    let mut rng = rand::thread_rng();
    let mut result = BigInt::zero();

    let mut r = rng.gen_bigint_range(&BigInt::zero(), p);

    if r == BigInt::one() || r == BigInt::zero() {
        r = rng.gen_bigint_range(&BigInt::zero(), p);
    }

    for i in 0..size {
        r = mod_pow(&r, &BigInt::from(2), n);
        let x = &r % 2;
        result += x << i;
    }
    
    result
}

fn trial_division(n: &BigInt) -> bool {
    if n < &BigInt::from(2) {
        return false;
    }
    if n == &BigInt::from(2) || n == &BigInt::from(3) {
        return true;
    }
    if n % 2 == BigInt::zero() {
        return false;
    }

    let small_primes = vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
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

    for _ in 0..k {
        let x = bbs_bit(&Q, &P, &N, 16) % p;
        if gcd(&x, p) != BigInt::one() {
            return false;
        }

        let mut x_pow = mod_pow(&x, &d, p);
        if x_pow == BigInt::one() || x_pow == p - 1 {
            continue;
        }

        let mut is_pseudoprime = false;
        for r in 1..s {
            x_pow = mod_pow(&x_pow, &BigInt::from(2), p);
            if x_pow == p - 1 {
                is_pseudoprime = true;
                break;
            }
            
            if x_pow == BigInt::one() {
                return false;
            }
        }
        
        if !is_pseudoprime {
            return false;
        }
    }
    
    true
}

fn generate_random_prime(bit_size: u32, miller_rabin_iterations: u32) -> BigInt {
    let mut candidate = bbs_bit(&Q, &P, &N, bit_size);
    loop {
        candidate += 2;
        if &candidate % 2 == BigInt::zero() {
            candidate += 1;
        }

        if !trial_division(&candidate) {
            continue;
        }

        if miller_rabin_test(&candidate, miller_rabin_iterations) {
            break;
        }
    }
    
    candidate
}

fn mod_pow(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    let mut result = BigInt::one();
    let mut base = base.clone();
    let mut exp = exponent.clone();

    while exp > BigInt::zero() {
        if &exp % 2 == BigInt::one() {
            result = (result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp /= 2;
    }
    
    result
}

fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = m.clone();
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
        return None;
    }
    
    if t < BigInt::zero() {
        t += m;
    }
    
    Some(t)
}

fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let mut a = a.clone();
    let mut b = b.clone();
    while b != BigInt::zero() {
        let temp = b.clone();
        b = &a % &b;
        a = temp;
    }
    
    a
}