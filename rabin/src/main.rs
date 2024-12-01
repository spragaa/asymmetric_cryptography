use num_bigint::BigInt;
use num_traits::Num;
use rabin::Rabin;

fn hex_to_bigint(hex_str: &str) -> BigInt {
    BigInt::from_str_radix(&hex_str.replace("0x", ""), 16)
        .unwrap_or_else(|_| panic!("Invalid hex string: {}", hex_str))
}

fn print_separator() {
    println!("\n{}\n", "-".repeat(150));
}

fn main() {
    let bit_size = 256;
    let miller_rabin_iterations = 10;

    println!("Generating new Rabin key pair...");
    let rabin = Rabin::new(bit_size, miller_rabin_iterations);

    println!("PUBLIC KEY (n):");
    println!("0x{:X}", rabin.public_key_n);
    println!("\nPRIVATE KEYS:");
    println!("p: 0x{:X}", rabin.private_key_p);
    println!("q: 0x{:X}", rabin.private_key_q);
  
    print_separator();

    println!("\nENCRYPTION TEST:");
    let message = hex_to_bigint("ABC");
    println!("Original Message: 0x{:X}", message);

    let encrypted = rabin.encrypt(&message);
    println!("Encrypted Message: 0x{:X}", encrypted);

    print_separator();
    
    println!("\nDECRYPTION TEST:");
    let decrypted_roots = rabin.decrypt(&encrypted);
    println!("Possible decrypted messages:");
    for (i, root) in decrypted_roots.iter().enumerate() {
        println!("Root {}: 0x{:X}", i + 1, root);
    }
}