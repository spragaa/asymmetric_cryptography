use num_bigint::BigInt;
use num_traits::Num;
use rsa::RSA;

fn hex_to_bigint(hex_str: &str) -> BigInt {
    BigInt::from_str_radix(&hex_str.replace("", ""), 16)
        .unwrap_or_else(|_| panic!("Invalid hex string: {}", hex_str))
}

fn print_separator() {
    println!("\n{}\n", "-".repeat(150));
}

fn main() {
    let bit_size = 256;
    let miller_rabin_iterations = 10;

    println!("Generating RSA key pairs for Alice and Bob...");
    let alice = RSA::new(bit_size, miller_rabin_iterations);
    let bob = RSA::new(bit_size, miller_rabin_iterations);

    print_separator();

    println!("ALICE'S KEY INFORMATION:");
    println!("Public Exponent (E):");
    println!("{:X}", alice.public_key_e);
    println!("\nPublic Modulus (N):");
    println!("{:X}", alice.public_key_n);
    println!("\nPrivate Key (D):");
    println!("{:X}", alice.private_key_d);

    print_separator();

    println!("BOB'S KEY INFORMATION:");
    println!("Public Exponent (E):");
    println!("{:X}", bob.public_key_e);
    println!("\nPublic Modulus (N):");
    println!("{:X}", bob.public_key_n);
    println!("\nPrivate Key (D):");
    println!("{:X}", bob.private_key_d);

    print_separator();

    println!("MESSAGE EXCHANGE TEST:");
    let message = hex_to_bigint("48656C6C6F20426F6221"); // "hello bob"
    println!("Alice's original message: {:X}", message);

    let encrypted = alice.encrypt(&message, &bob.public_key_e, &bob.public_key_n);
    println!("Encrypted message from Alice to Bob: {:X}", encrypted);

    let decrypted = bob.decrypt(&encrypted, &bob.private_key_d, &bob.public_key_n);
    println!("Bob's decrypted message: {:X}", decrypted);

    print_separator();

    println!("SIGNED MESSAGE EXCHANGE TEST:");
    let secret_message = hex_to_bigint("5365637265742066726F6D20416C69636521"); // "secret from aslice"
    println!("Original secret message: {:X}", secret_message);

    let signature = alice.sign_message(&secret_message, &alice.private_key_d, &alice.public_key_n);
    println!("Alice's signature: {:X}", signature);

    let encrypted_message = alice.encrypt(&secret_message, &bob.public_key_e, &bob.public_key_n);
    let encrypted_signature = alice.encrypt(&signature, &bob.public_key_e, &bob.public_key_n);
    println!("Encrypted message: {:X}", encrypted_message);
    println!("Encrypted signature: {:X}", encrypted_signature);

    let decrypted_message = bob.decrypt(&encrypted_message, &bob.private_key_d, &bob.public_key_n);
    let decrypted_signature = bob.decrypt(&encrypted_signature, &bob.private_key_d, &bob.public_key_n);

    println!("Bob's decrypted message: {:X}", decrypted_message);

    let is_valid = bob.verify_signature(
        &decrypted_message,
        &decrypted_signature,
        &alice.public_key_e,
        &alice.public_key_n
    );
    println!("Signature verification: {}", if is_valid { "SUCCESS" } else { "FAILED" });

    print_separator();

    println!("KEY EXCHANGE TEST:");
    let session_key = hex_to_bigint("DEADBEEF");
    println!("Original session key: {:X}", session_key);

    let (encrypted_key, encrypted_key_signature) = alice.send_key(
        &session_key,
        &bob.public_key_e,
        &bob.public_key_n
    );

    let key_verified = bob.receive_key(
        &encrypted_key,
        &encrypted_key_signature,
        &alice.public_key_e,
        &alice.public_key_n,
        &bob.private_key_d,
        &bob.public_key_n
    );

    println!("Key exchange verification: {}", if key_verified { "SUCCESS" } else { "FAILED" });

    print_separator();
}