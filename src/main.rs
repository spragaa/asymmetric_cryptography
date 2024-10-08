use num_traits::Zero;
use rand::Rng;
use std::fs::File;
use rand::rngs::OsRng;
use num_traits::ToPrimitive;
use num_bigint::{BigUint, RandBigInt};
use statrs::distribution::{ChiSquared, ContinuousCDF};
use std::io::{self, Read, Result};

const N: usize = 1_000_000;
// const ALPHA: f64 = 0.01;
// const ALPHA: f64 = 0.05;
const ALPHA: f64 = 0.1;

fn bits_to_bytes(seq: &[u8]) -> Vec<u8> {
    seq.chunks(8)
        .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
        .collect()
}

fn uniformity_test(seq: &[u8], b: u32) {
    let n = seq.len();
    let n_s = n as f64 / 2f64.powi(b as i32);

    let mut counts = vec![0f64; 2usize.pow(b)];
    for &a in seq {
        if (a as usize) < counts.len() {
            counts[a as usize] += 1.0;
        }
    }

    let res: f64 = counts.iter().map(|&c| (c - n_s).powi(2) / n_s).sum();
    let val = ChiSquared::new((2u32.pow(b) - 1) as f64).unwrap().inverse_cdf(1.0 - ALPHA);
    println!(
        "Uniformity test:   Passed = {:<7}   Statistic = {:<12.10}",
        res <= val,
        res
    );
}

fn independence_test(seq: &[u8], b: u32) {
    let n = seq.len();
    let mut pair_counts = vec![vec![0f64; 2usize.pow(b)]; 2usize.pow(b)];
    for window in seq.windows(2) {
        if (window[0] as usize) < pair_counts.len() && (window[1] as usize) < pair_counts.len() {
            pair_counts[window[0] as usize][window[1] as usize] += 1.0;
        }
    }

    let mut s = 0.0;
    for i in 0..2usize.pow(b) {
        for j in 0..2usize.pow(b) {
            let d = pair_counts[i].iter().sum::<f64>() * pair_counts.iter().map(|row| row[j]).sum::<f64>();
            if d != 0.0 {
                s += pair_counts[i][j].powi(2) / d;
            }
        }
    }

    let res = (n as f64) * (s - 1.0);
    let val = ChiSquared::new(((2u32.pow(b) - 1).pow(2)) as f64).unwrap().inverse_cdf(1.0 - ALPHA);

    println!(
        "Independence test: Passed = {:<7}   Statistic = {:<12.10}",
        res <= val,
        res
    );
}

fn homogeneity_test(seq: &[u8], b: u32) {
    let n = seq.len();
    let r = 200;
    let mut interval_counts = vec![vec![0f64; 2usize.pow(b)]; r];

    for i in 0..r {
        for j in 0..(n / r) {
            let c = seq[r * i + j] as usize;
            if c < interval_counts[i].len() {
                interval_counts[i][c] += 1.0;
            }
        }
    }

    let mut s = 0.0;
    for i in 0..r {
        for j in 0..2usize.pow(b) {
            let d = interval_counts[i].iter().sum::<f64>() * interval_counts.iter().map(|row| row[j]).sum::<f64>();
            if d != 0.0 {
                s += interval_counts[i][j].powi(2) / d;
            }
        }
    }

    let res = (n as f64) * (s - 1.0);
    let val = ChiSquared::new(((2u32.pow(b) - 1) * (r as u32 - 1)) as f64).unwrap().inverse_cdf(1.0 - ALPHA);
    println!(
        "Homogeneity test:  Passed = {:<7}   Statistic = {:<12.10}",
        res <= val,
        res
    );
}

fn test(seq: &[u8], b: u32) {
    uniformity_test(seq, b);
    independence_test(seq, b);
    homogeneity_test(seq, b);
}

fn lehmer_low_generate_bytes(n: usize) -> Vec<u8> {
    let a = 2u32.pow(16) + 1;
    let c = 119;
    let x0 = 6;
    let mut seq = vec![0u32; n];
    seq[0] = x0;

    for i in 0..(n - 1) {
        seq[i + 1] = (a * seq[i] + c) % 256;
    }

    seq.into_iter().map(|x| x as u8).collect()
}

fn lehmer_high_generate_bytes(n: usize) -> Vec<u8> {
    let a = 2u32.pow(16) + 1;
    let c = 119;
    let x0 = 9;
    let mut seq = vec![0u32; n];
    seq[0] = x0;

    for i in 0..(n - 1) {
        seq[i + 1] = (a * seq[i] + c) >> 24;
    }

    seq.into_iter().map(|x| x as u8).collect()
}

fn l20_generate_bits(x_init: Vec<u8>, n: usize) -> Vec<u8> {
    let mut seq = vec![0u8; n];
    seq[..20].copy_from_slice(&x_init);

    for i in 20..n {
        seq[i] = seq[i - 3] ^ seq[i - 5] ^ seq[i - 9] ^ seq[i - 20];
    }

    seq
}

fn l89_generate_bits(x_init: Vec<u8>, n: usize) -> Vec<u8> {
    let mut seq = vec![0u8; n];
    seq[..89].copy_from_slice(&x_init);

    for i in 89..n {
        seq[i] = seq[i - 38] ^ seq[i - 89];
    }

    seq
}

fn geffe_generate_bits(mut x: Vec<u8>, mut y: Vec<u8>, mut s: Vec<u8>, n: usize) -> Vec<u8> {
    let mut seq = vec![0u8; n];

    for i in 0..n {
        seq[i] = (s[0] & x[0]) ^ ((!s[0]) & y[0]);
        
        x[0] ^= x[2];
        x.rotate_right(1);
        y[0] ^= y[1] ^ y[3] ^ y[4];
        y.rotate_right(1);
        s[0] ^= s[3];
        s.rotate_right(1);
    }

    seq
}

fn librarian_generate_bytes(filename: &str, n: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;

    let text_bytes = text.as_bytes();

    if text_bytes.len() < n {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Not enough text to generate requested number of bytes: requested {}, available {}",
                n, text_bytes.len()
            ),
        ));
    }

    let mut rng = rand::thread_rng();
    let start = rng.gen_range(0..=text_bytes.len() - n);

    Ok(text_bytes[start..start + n].to_vec())
}

fn wolfram_generate_bits(r0: u32, n: usize) -> Vec<u8> {
    let mut r_i = r0;
    let mut seq = vec![0u8; n];

    for i in 0..n {
        seq[i] = (r_i & 1) as u8;
        r_i = r_i.rotate_left(1) ^ (r_i | r_i.rotate_right(1));
    }

    seq
}

fn bm_generate_bits(p: BigUint, a: BigUint, n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut seq = vec![0u8; n];
    let mut x = rng.gen_biguint_below(&p);
    let half_p = &p / 2u32;

    for i in 0..n {
        seq[i] = if x < half_p { 0 } else { 1 };
        x = a.modpow(&x, &p).into();
    }

    seq
}

fn bm_generate_bytes(p: BigUint, a: BigUint, n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut seq = vec![0u8; n];
    let mut x = BigUint::from(rng.gen_range(0..p.to_u64().unwrap_or(u64::MAX)));

    for i in 0..n {
        seq[i] = ((&x * BigUint::from(256u32)) / &p).to_u8().unwrap_or(0);
        x = a.modpow(&x, &p).into();
    }

    seq
}

fn bbs_generate_bits(p: BigUint, q: BigUint, n: usize) -> Vec<u8> {
    let n_val = p * q;
    let mut rng = rand::thread_rng();
    let mut seq = vec![0u8; n];
    let mut x = BigUint::from(rng.gen_range(2..n_val.to_u64().unwrap_or(u64::MAX)));

    for i in 0..n {
        x = (&x * &x) % &n_val;
        seq[i] = if &x % 2u32 == BigUint::zero() { 0 } else { 1 };
    }

    seq
}

fn bbs_generate_bytes(p: BigUint, q: BigUint, n: usize) -> Vec<u8> {
    let n_val = p * q;
    let mut rng = rand::thread_rng();
    let mut seq = vec![0u8; n];
    let mut x = BigUint::from(rng.gen_range(2..n_val.to_u64().unwrap_or(u64::MAX)));

    for i in 0..n {
        x = (&x * &x) % &n_val;
        seq[i] = (&x % BigUint::from(256u32)).to_u8().unwrap_or(0);
    }

    seq
}

fn main() {
    let mut rng = rand::thread_rng();
    
    println!("\nBuilt-in generator (bits):");
    let mut os_rng = OsRng;
    let safe_bits_seq: Vec<u8> = (0..N).map(|_| os_rng.gen_range(0..2)).collect();
    test(&bits_to_bytes(&safe_bits_seq), 8);
    
    println!("\nBuilt-in generator (bytes):");
    let safe_bytes_seq: Vec<u8> = (0..N).map(|_| os_rng.gen()).collect();
    test(&safe_bytes_seq, 8);

    println!("\nLehmer Low generator:");
    test(&lehmer_low_generate_bytes(N), 8);

    println!("\nLehmer High generator:");
    test(&lehmer_high_generate_bytes(N), 8);

    println!("\nL20 generator (1M bits):");
    let x_init: Vec<u8> = (0..20).map(|_| rng.gen_range(0..2)).collect();
    println!("Initial state: {:?}", x_init);
    test(&bits_to_bytes(&l20_generate_bits(x_init.clone(), N)), 8);
    
    println!("\nL20 generator (16M bits):");
    println!("Initial state: {:?}", x_init);
    test(&bits_to_bytes(&l20_generate_bits(x_init, 16 * N)), 8);

    println!("\nL89 generator (1M bits):");
    let x_init: Vec<u8> = (0..89).map(|_| rng.gen_range(0..2)).collect();
    println!("Initial state: {:?}", x_init);
    test(&bits_to_bytes(&l89_generate_bits(x_init, N)), 8);

    println!("\nGeffe generator:");
    let x: Vec<u8> = (0..11).map(|_| rng.gen_range(0..2)).collect();
    let y: Vec<u8> = (0..9).map(|_| rng.gen_range(0..2)).collect();
    let s: Vec<u8> = (0..10).map(|_| rng.gen_range(0..2)).collect();
    println!("x = {:?}", x);
    println!("y = {:?}", y);
    println!("s = {:?}", s);
    test(&bits_to_bytes(&geffe_generate_bits(x, y, s, N)), 8);

    let filename = "/home/logi/myself/uni/TERM7/asym_crypto/asymmetric_cryptography/text/librarian.txt";
    println!("\nLibrarian generator:");
    if let Ok(bytes) = librarian_generate_bytes(filename, N) {
        test(&bytes, 8);
    } else {
        println!("Failed to open text/librarian.txt");
    }

    println!("\nWolfram generator:");
    test(&bits_to_bytes(&wolfram_generate_bits(1, N)), 8);

    println!("\nBM generator (bits):");
    let p = BigUint::parse_bytes(b"CEA42B987C44FA642D80AD9F51F10457690DEF10C83D0BC1BCEE12FC3B6093E3", 16).unwrap();
    let a = BigUint::parse_bytes(b"5B88C41246790891C095E2878880342E88C79974303BD0400B090FE38A688356", 16).unwrap();
    test(&bits_to_bytes(&bm_generate_bits(p.clone(), a.clone(), N)), 8);

    println!("\nBM generator (bytes):");
    test(&bm_generate_bytes(p, a, N), 8);

    println!("\nBBS generator (bits):");
    let p = BigUint::parse_bytes(b"D5BBB96D30086EC484EBA3D7F9CAEB07", 16).unwrap();
    let q = BigUint::parse_bytes(b"425D2B9BFDB25B9CF6C416CC6E37B59C1F", 16).unwrap();
    test(&bits_to_bytes(&bbs_generate_bits(p.clone(), q.clone(), N)), 8);

    println!("\nBBS generator (bytes):");
    test(&bbs_generate_bytes(p, q, N), 8);
}