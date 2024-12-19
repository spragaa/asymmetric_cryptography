use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use rand::thread_rng;
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::io::{self, Write};

const BASE_URL: &str = "http://asymcryptwebservice.appspot.com/znp/";
const KEY_SIZE: u32 = 2048;

fn hex_to_bigint(hex_str: &str) -> BigInt {
    BigInt::parse_bytes(hex_str.trim().as_bytes(), 16)
        .unwrap_or_else(|| panic!("Invalid hex string: {}", hex_str))
}

fn bigint_to_hex(n: &BigInt) -> String {
    format!("{:X}", n)
}

fn pow_mod(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    base.modpow(exponent, modulus)
}

fn is_blum_number(p: &BigInt, q: &BigInt) -> bool {
    let four = BigInt::from(4);
    let three = BigInt::from(3);
    
    let p_mod_4 = p % &four;
    let q_mod_4 = q % &four;
    
    p_mod_4 == three && q_mod_4 == three
}

fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let mut x = a.clone();
    let mut y = b.clone();
    while !y.is_zero() {
        let temp = y.clone();
        y = x % &y;
        x = temp;
    }
    x
}

fn get_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

#[derive(Debug)]
struct CustomError(String);

impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for CustomError {}

fn generate_challenge(client: &Client) -> Result<(), Box<dyn Error>> {
    println!("\nGenerating Challenge");
    println!("-------------------");

    let response = client.get(&format!("{}serverKey", BASE_URL)).send()?;
    let json: Value = response.json()?;
    let n = hex_to_bigint(json["modulus"].as_str()
        .ok_or_else(|| CustomError("No modulus in response".to_string()))?);
    
    println!("Server's modulus (N): {}", bigint_to_hex(&n));

    let mut rng = thread_rng();
    let x = rng.gen_bigint(KEY_SIZE.into());
    let two = BigInt::from(2);
    let y = pow_mod(&x, &two, &n);

    println!("\nGenerated values:");
    println!("x (secret): {}", bigint_to_hex(&x));
    println!("y (public): {}", bigint_to_hex(&y));

    let response = client.get(&format!("{}challenge", BASE_URL))
        .query(&[("y", bigint_to_hex(&y))])
        .send()?;

    let json: Value = response.json()?;
    
    if let Some(root) = json.get("root").and_then(|v| v.as_str()) {
        let server_root = hex_to_bigint(root);
        println!("\nServer's response:");
        println!("Root: {}", bigint_to_hex(&server_root));
        
        if server_root == x {
            println!("Server found the correct root!");
        } else {
            println!("Server found a different root - this could be used to factor N!");
            let p = gcd(&(x + server_root), &n);
            let q = &n / &p;
            println!("p: {}", bigint_to_hex(&p));
            println!("q: {}", bigint_to_hex(&q));
            println!("p*q == n: {}", &p * &q == n);
        }
    } else {
        println!("Server didn't provide a valid root");
    }

    Ok(())
}

fn attack_rabin(client: &Client) -> Result<(), Box<dyn Error>> {
    println!("\nStarting Rabin Attack");
    println!("-------------------");

    let response = client.get(&format!("{}serverKey", BASE_URL)).send()?;
    
    let json: Value = response.json()?;
    let n = hex_to_bigint(json["modulus"].as_str()
        .ok_or_else(|| CustomError("No modulus in response".to_string()))?);
    
    println!("Received key: {}", bigint_to_hex(&n));

    let mut attempts = 1;
    let mut rng = thread_rng();
    
    loop {
        println!("\nAttempt {}", attempts);
        attempts += 1;

        let t = rng.gen_bigint(KEY_SIZE.into());
        let two = BigInt::from(2);
        let y = pow_mod(&t, &two, &n);

        println!("t = {}", bigint_to_hex(&t));
        println!("y = {}", bigint_to_hex(&y));

        let response = client.get(&format!("{}challenge", BASE_URL))
            .query(&[("y", bigint_to_hex(&y))])
            .send()?;
        
        let json: Value = response.json()?;
        
        let root = match json.get("root").and_then(|v| v.as_str()) {
            Some(root_str) => hex_to_bigint(root_str),
            None => {
                println!("No root in response, skipping attempt");
                continue;
            }
        };
        
        println!("root = {}", bigint_to_hex(&root));

        if root != t {
            println!("\nSuccess! Found different square root.");
            let p = gcd(&(t + root), &n);
            let q = &n / &p;
        
            println!("Factors found:");
            println!("p: {}", bigint_to_hex(&p));
            println!("q: {}", bigint_to_hex(&q));
            println!("Verification: p*q == n: {}", &p * &q == n);
            
            if is_blum_number(&p, &q) {
                println!("This is a Blum number! (both p and q ≡ 3 (mod 4))");
                println!("p mod 4 = {}", &p % BigInt::from(4));
                println!("q mod 4 = {}", &q % BigInt::from(4));
            } else {
                println!("This is NOT a Blum number");
                println!("p mod 4 = {}", &p % BigInt::from(4));
                println!("q mod 4 = {}", &q % BigInt::from(4));
            }
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}

fn main() {
    let client = Client::builder()
        .cookie_store(true)
        .build()
        .expect("Failed to create HTTP client");

    loop {
        println!("1. Generate Challenge");
        println!("2. Perform Attack");
        println!("3. Exit");

        match get_input("\nSelect option (1-3): ").as_str() {
            "1" => {
                if let Err(e) = generate_challenge(&client) {
                    eprintln!("Error generating challenge: {}", e);
                }
            },
            "2" => {
                if let Err(e) = attack_rabin(&client) {
                    eprintln!("Error during attack: {}", e);
                }
            },
            "3" => {
                println!("Goodbye!");
                break;
            },
            _ => println!("Invalid option. Please select 1-3."),
        }
    }
}