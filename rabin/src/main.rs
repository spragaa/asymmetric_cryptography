use rabin::RabinUser;
use num_bigint::BigInt;
use num_traits::Num;

fn hex_to_bigint(hex_str: &str) -> BigInt {
    BigInt::from_str_radix(&hex_str.replace("", ""), 16)
        .unwrap_or_else(|_| panic!("Invalid hex string: {}", hex_str))
}

fn print_separator() {
    println!("\n{}\n", "-".repeat(150));
}

fn main() {
    let bit_size = 256;
    let miller_rabin_iterations = 100;

    println!("Generating Rabin key pairs for Alice and Bob...");
    let mut alice = RabinUser::new();
    let mut bob = RabinUser::new();
    
    alice.generate_key_pair(bit_size, miller_rabin_iterations);
    bob.generate_key_pair(bit_size, miller_rabin_iterations);

    print_separator();

    println!("ALICE'S KEY INFORMATION:");
    println!("Public Key N:");
    println!("{:X}", alice.public_key_n);
    println!("\nPublic Key B:");
    println!("{:X}", alice.public_key_b);
    println!("\nPrivate Key P:");
    println!("{:X}", alice.private_key_p);
    println!("\nPrivate Key Q:");
    println!("{:X}", alice.private_key_q);

    print_separator();

    println!("BOB'S KEY INFORMATION:");
    println!("Public Key N:");
    println!("{:X}", bob.public_key_n);
    println!("\nPublic Key B:");
    println!("{:X}", bob.public_key_b);
    println!("\nPrivate Key P:");
    println!("{:X}", bob.private_key_p);
    println!("\nPrivate Key Q:");
    println!("{:X}", bob.private_key_q);

    print_separator();

    println!("MESSAGE EXCHANGE TEST:");
    let message = hex_to_bigint("48656C6C6F20426F6221"); // "Hello Bob!"
    println!("Alice's original message: {:X}", message);

    match bob.encrypt(&message) {
        Ok((encrypted, indicators)) => {
            println!("Encrypted message from Alice to Bob: {:X}", encrypted);
            println!("Encryption indicators: ({:X}, {:X})", indicators.0, indicators.1);

            match bob.decrypt(&encrypted, &indicators) {
                Ok(decrypted) => {
                    println!("Bob's decrypted message: {:X}", decrypted);
                    assert_eq!(message, decrypted, "Decryption failed: messages don't match");
                }
                Err(e) => println!("Decryption error: {}", e),
            }
        }
        Err(e) => println!("Encryption error: {}", e),
    }

    print_separator();

    println!("SIGNED MESSAGE EXCHANGE TEST:");
    let secret_message = hex_to_bigint("5365637265742066726F6D20416C69636521"); // "Secret from Alice!"
    println!("Original secret message: {:X}", secret_message);

    match alice.sign_message(&secret_message) {
        Ok(signature) => {
            println!("Alice's signature: {:X}", signature);

            if let Ok((encrypted_message, msg_indicators)) = bob.encrypt(&secret_message) {
                if let Ok((encrypted_signature, sig_indicators)) = bob.encrypt(&signature) {
                    println!("Encrypted message: {:X}", encrypted_message);
                    println!("Encrypted signature: {:X}", encrypted_signature);

                    if let Ok(decrypted_message) = bob.decrypt(&encrypted_message, &msg_indicators) {
                        if let Ok(decrypted_signature) = bob.decrypt(&encrypted_signature, &sig_indicators) {
                            println!("Bob's decrypted message: {:X}", decrypted_message);
                            
                            let is_valid = alice.verify_signature(&decrypted_message, &decrypted_signature);
                            println!("Signature verification: {}", if is_valid { "SUCCESS" } else { "FAILED" });
                        }
                    }
                }
            }
        }
        Err(e) => println!("Signing error: {}", e),
    }

    print_separator();

    println!("KEY EXCHANGE TEST:");
    let session_key = hex_to_bigint("DEADBEEF");
    println!("Original session key: {:X}", session_key);

    match alice.sign_message(&session_key) {
        Ok(key_signature) => {
            if let Ok((encrypted_key, key_indicators)) = bob.encrypt(&session_key) {
                if let Ok((encrypted_signature, sig_indicators)) = bob.encrypt(&key_signature) {
                    if let Ok(decrypted_key) = bob.decrypt(&encrypted_key, &key_indicators) {
                        if let Ok(decrypted_signature) = bob.decrypt(&encrypted_signature, &sig_indicators) {
                            let key_verified = alice.verify_signature(&decrypted_key, &decrypted_signature);
                            println!("Key exchange verification: {}", if key_verified { "SUCCESS" } else { "FAILED" });
                        }
                    }
                }
            }
        }
        Err(e) => println!("Key exchange error: {}", e),
    }

    print_separator();
}