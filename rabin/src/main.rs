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

    println!("Generating Rabin key pairs for Alice and Bob...");
    let alice = Rabin::new(bit_size, miller_rabin_iterations);
    let bob = Rabin::new(bit_size, miller_rabin_iterations);

    print_separator();

    println!("ALICE'S KEYS:");
    println!("Public Key (n): {:X}", alice.public_key_n);
    println!("Private Keys:");
    println!("p: {:X}", alice.private_key_p);
    println!("q: {:X}", alice.private_key_q);

    print_separator();

    println!("BOB'S KEYS:");
    println!("Public Key (n): {:X}", bob.public_key_n);
    println!("Private Keys:");
    println!("p: {:X}", bob.private_key_p);
    println!("q: {:X}", bob.private_key_q);

    print_separator();

    println!("MESSAGE EXCHANGE TEST:");
    let message = hex_to_bigint("48656C6C6F20426F6221"); // "hello bob"
    println!("Original message: {:X}", message);

    let encrypted = alice.encrypt(&message);
    println!("Encrypted message: {:X}", encrypted);

    let decrypted_roots = bob.decrypt(&encrypted);
    println!("Possible decrypted messages:");
    for (i, root) in decrypted_roots.iter().enumerate() {
        println!("Root {}: {:X}", i + 1, root);
    }

    print_separator();

    println!("SIGNED MESSAGE TEST:");
    let secret = hex_to_bigint("5365637265742066726F6D20416C69636521"); // "secret from alice"
    println!("Original secret: {:X}", secret);

    let signature = alice.sign_message(&secret);
    println!("Signature: {:X}", signature);

    let is_valid = alice.verify_signature(&secret, &signature);
    println!("Signature verification: {}", if is_valid { "SUCCESS" } else { "FAILED" });

    print_separator();

    println!("KEY EXCHANGE TEST:");
    let session_key = hex_to_bigint("DEADBEEF");
    println!("Original session key: {:X}", session_key);

    let (encrypted_key, encrypted_signature) = alice.send_key(&session_key, &bob.public_key_n);
    println!("Encrypted key: {:X}", encrypted_key);
    println!("Encrypted signature: {:X}", encrypted_signature);

    if let Some(received_key) = bob.receive_key(&encrypted_key, &encrypted_signature, &alice.public_key_n) {
        println!("Received key: {:X}", received_key);
        println!("Key exchange: SUCCESS");
    } else {
        println!("Key exchange: FAILED");
    }

    print_separator();
}