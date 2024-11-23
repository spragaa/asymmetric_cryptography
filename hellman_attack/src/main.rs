use rand::{Rng, thread_rng};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use whirlpool::{Whirlpool, Digest};
use std::time::Instant;
use rayon::prelude::*;

fn whirhash(input: &[u8], bits: usize) -> Vec<u8> {
    let mut hasher = Whirlpool::new();
    hasher.update(input);
    let result = hasher.finalize();
    result[..bits/8].to_vec()
}

#[derive(Clone)]
struct RedundancyFunction {
    r: Vec<u8>,
    n: usize,
}

impl RedundancyFunction {
    fn new(n: usize) -> Self {
        let mut rng = thread_rng();
        let r_len = (128 - n) / 8;
        let mut r = vec![0u8; r_len];
        rng.fill(&mut r[..]);
    
        RedundancyFunction { r, n }
    }
    
    fn apply(&self, x: &[u8]) -> Vec<u8> {
        let mut result = self.r.clone();
        result.extend_from_slice(x);
        result
    }
}

fn generate_chain(start: Vec<u8>, length: usize, r_func: &RedundancyFunction, bits: usize) -> Vec<u8> {
    let mut current = start.clone();
    
    for _ in 0..length {
        let with_redundancy = r_func.apply(&current);
        current = whirhash(&with_redundancy, bits);
    }
    
    current
}

#[derive(Clone)]
struct PrecomputationTable {
    pairs: Arc<HashMap<Vec<u8>, Vec<u8>>>,
    r_func: RedundancyFunction,
}

impl PrecomputationTable {
    fn new(k: usize, l: usize, bits: usize) -> Self {
        let r_func = RedundancyFunction::new(bits);
        let pairs: HashMap<_, _> = (0..k)
            .into_par_iter()
            .map(|_| {
                let mut rng = thread_rng();
                let mut start = vec![0u8; bits/8];
                rng.fill(&mut start[..]);
                let end = generate_chain(start.clone(), l, &r_func, bits);
                (end, start)
            })
            .collect();
    
        PrecomputationTable { 
            pairs: Arc::new(pairs), 
            r_func 
        }
    }
}

fn find_prototype(
  tables: &[PrecomputationTable],
  hash: &[u8],
  l: usize,
  bits: usize
) -> Option<Vec<u8>> {
    let mut current = hash.to_vec();
    
    for j in 0..l {
        for table in tables {
            if let Some(start) = table.pairs.get(&current) {
                let mut x = start.clone();
                for _ in 0..(l-j) {
                    let with_redundancy = table.r_func.apply(&x);
                    x = whirhash(&with_redundancy, bits);
                }
                return Some(x);
            }
        }
    
        let with_redundancy = tables[0].r_func.apply(&current);
        current = whirhash(&with_redundancy, bits);
    }
    
    None
}

fn run_experiments(
    tables: &[PrecomputationTable],
    n_experiments: usize,
    l: usize,
    bits: usize
    ) -> usize {
    let success_count = Arc::new(Mutex::new(0usize));
    
    (0..n_experiments).into_par_iter().for_each(|_| {
        let mut rng = thread_rng();
        let mut random_input = vec![0u8; 32];
        rng.fill(&mut random_input[..]);
    
        let hash = whirhash(&random_input, bits);
    
        if find_prototype(tables, &hash, l, bits).is_some() {
            let mut count = success_count.lock().unwrap();
            *count += 1;
        }
    });
    
    let x = *success_count.lock().unwrap();
    x
}

fn main() {
    let bits = 32;
    let k_values = vec![1 << 20, 1 << 22, 1 << 24];
    let l_values = vec![1 << 10, 1 << 11, 1 << 12];
        
    // let bits = 16;
    // let k_values = vec![1 << 10, 1 << 12, 1 << 14];
    // let l_values = vec![1 << 5, 1 << 6, 1 << 7];
  
    let n_experiments = 1000;
    
    println!("\nSingle table experiments:");
    for &k in &k_values {
        for &l in &l_values {
            let start_time = Instant::now();
            let table = PrecomputationTable::new(k, l, bits);
    
            let success_count = run_experiments(&[table], n_experiments, l, bits);
    
            let success_rate = (success_count as f64 / n_experiments as f64) * 100.0;
            println!("K={}, L={}: Success rate: {:.2}%", k, l, success_rate);
            println!("Time taken: {:?}", start_time.elapsed());
        }
    }
    
    println!("\nMultiple tables experiments:");
    for &k in &k_values {
        for &l in &l_values {
            let start_time = Instant::now();
    
            let tables: Vec<PrecomputationTable> = (0..4)
                .into_par_iter()
                .map(|_| PrecomputationTable::new(k/4, l, bits))
                .collect();
    
            let success_count = run_experiments(&tables, n_experiments, l, bits);
    
            let success_rate = (success_count as f64 / n_experiments as f64) * 100.0;
            println!("K={}, L={}: Success rate: {:.2}%", k, l, success_rate);
            println!("Time taken: {:?}", start_time.elapsed());
        }
    }
}