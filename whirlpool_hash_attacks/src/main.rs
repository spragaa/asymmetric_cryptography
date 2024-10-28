use std::collections::HashMap;
use whirlpool::{Whirlpool, Digest};
use statrs::distribution::{Normal, ContinuousCDF};

#[derive(Default)]
struct AttackStats {
    attempts: Vec<u64>,
    mean: f64,
    std_dev: f64,
    confidence_interval: (f64, f64),
}

impl AttackStats {
    fn update(&mut self) {
        self.mean = self.attempts.iter()
            .map(|&x| x as f64)
            .sum::<f64>() / self.attempts.len() as f64;
        
        let variance = self.attempts.iter()
            .map(|&x| {
                let diff = x as f64 - self.mean;
                diff * diff
            })
            .sum::<f64>() / (self.attempts.len() - 1) as f64;
        // bullshit? always 0
        self.std_dev = variance.sqrt();
        
        let n = self.attempts.len() as f64;
        let standard_error = self.std_dev / n.sqrt();
        let normal = Normal::new(0.0, 1.0).unwrap();
        let z_score = normal.inverse_cdf(0.975);
        
        // bullshit? always (n ,n), where n is mean ............
        self.confidence_interval = (
            self.mean - z_score * standard_error,
            self.mean + z_score * standard_error
        );
    }
}

fn whirhash(input: &[u8], bits: usize) -> Vec<u8> {
    let mut hasher = Whirlpool::new();
    hasher.update(input);
    let result = hasher.finalize();
    result[..bits/8].to_vec()
}

fn preimage_attack(bits: usize, first_run: bool) -> (Vec<u8>, u64, Vec<String>) {
    let first_message = "xsiaomiredmi";
    let target = whirhash(first_message.as_bytes(), bits);
    
    let mut attempts = 0u64;
    let mut messages = Vec::new();
    
    loop {
        attempts += 1;
        let message = format!("xsiaomiredmi{}", attempts);
        
        if message == first_message {
            continue;
        }
        
        let input = message.as_bytes();
        let hash = whirhash(input, bits);
        
        if first_run && attempts <= 30 {
            messages.push(format!("{} -> {}", message, format_hash(&hash)));
        }
        
        if hash == target {
            if first_run {
                messages.push(format!("{} -> {}", message, format_hash(&hash)));
            }
            return (input.to_vec(), attempts, messages);
        }
    }
}

fn format_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn birthday_attack(bits: usize, first_run: bool) -> (Vec<u8>, Vec<u8>, u64, Vec<String>, (String, String, u64, u64, String)) {
    let mut seen: HashMap<Vec<u8>, (String, u64, Vec<u8>)> = HashMap::new();
    let mut attempts = 0u64;
    let mut messages = Vec::new();
    
    loop {
        attempts += 1;
        let message = format!("xsiaomiredminoteultra{}", attempts);
        let input = message.as_bytes();
        let hash = whirhash(input, bits);
        
        if first_run && attempts <= 30 {
            messages.push(format!("{} -> {}", message, format_hash(&hash)));
        }
        
        if let Some((prev_message, prev_attempt, _prev_hash)) = seen.get(&hash) {
            let hash_hex = format_hash(&hash);
            return (
                prev_message.as_bytes().to_vec(),
                input.to_vec(),
                attempts,
                messages,
                (prev_message.clone(), message, prev_attempt.clone(), attempts, hash_hex)
            );
        }
        
        seen.insert(hash.clone(), (message.clone(), attempts, hash.clone()));
    }
}

fn main() {
    let iterations = 100;
    let mut preimage_stats = AttackStats::default();
    let mut birthday_stats = AttackStats::default();
    
    println!("\n=== Preimage Attack (16 bits) ===");
    
    let xsiaomi = "xsiaomiredmi";
    let target = whirhash(xsiaomi.as_bytes(), 16);
    println!("target {} -> {}", xsiaomi, format_hash(&target));

    for i in 0..iterations {
        let first_run = i == 0;
        let (_, attempts, messages) = preimage_attack(16, first_run);
        
        if first_run {
            println!("\nFirst 10 messages with their hashes:");
            for (i, msg) in messages.iter().take(10).enumerate() {
                println!("{}. {}", i + 1, msg);
            }
            
            if let Some(last) = messages.last() {
                println!("\nLast message (attempt #{}): {}", attempts, last);
            }
        }
        
        preimage_stats.attempts.push(attempts);
    }
    preimage_stats.update();
    
    println!("\n=== Birthday Attack (32 bits) ===");
    for i in 0..iterations {
        let first_run = i == 0;
        let (_, _, attempts, messages, collision) = birthday_attack(32, first_run);
        
        if first_run {
            println!("\nFirst 10 messages with their hashes:");
            for (i, msg) in messages.iter().take(10).enumerate() {
                println!("{}. {}", i + 1, msg);
            }
            
            let (msg1, msg2, pos1, pos2, hash) = collision;
            println!("\nCollision found:");
            println!("Message 1 (position {}) -> {}", pos1, msg1);
            println!("Message 2 (position {}) -> {}", pos2, msg2);
            println!("Common hash value: {}", hash);
        }
        
        birthday_stats.attempts.push(attempts);
    }
    birthday_stats.update();
    
    println!("\n=== Statistical Results ===");
    println!("\nPreimage Attack Statistics (16 bits):");
    println!("Mean attempts: {:.2}", preimage_stats.mean);
    println!("Standard deviation: {:.2}", preimage_stats.std_dev);
    println!("95% Confidence Interval: ({:.2}, {:.2})", 
            preimage_stats.confidence_interval.0,
            preimage_stats.confidence_interval.1);
    
    println!("\nBirthday Attack Statistics (32 bits):");
    println!("Mean attempts: {:.2}", birthday_stats.mean);
    println!("Standard deviation: {:.2}", birthday_stats.std_dev);
    println!("95% Confidence Interval: ({:.2}, {:.2})", 
            birthday_stats.confidence_interval.0,
            birthday_stats.confidence_interval.1);
}