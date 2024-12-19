use rabin::RabinUser;
use num_bigint::BigInt;
use num_traits::Num;
use std::io::{self, Write};

fn hex_to_bigint(hex_str: &str) -> BigInt {
    BigInt::from_str_radix(&hex_str.replace(" ", ""), 16)
        .unwrap_or_else(|_| panic!("Invalid hex string: {}", hex_str))
}

fn get_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() {
    println!("Rabin Crypto CLI Tool");
    println!("--------------------");

    loop {
        println!("\nAvailable operations:");
        println!("1. Generate new key pair");
        println!("2. Encrypt message");
        println!("3. Decrypt message");
        println!("4. Sign message");
        println!("5. Verify signature");
        println!("6. Exit");

        let choice = get_input("Select operation (1-6): ");

        match choice.as_str() {
            "1" => {
                let bit_size = 256;
                let miller_rabin_iterations = 100;
                let mut user = RabinUser::new();
                user.generate_key_pair(bit_size, miller_rabin_iterations);

                println!("\nGenerated Key Pair:");
                println!("Public Key N:\n{:X}", user.public_key_n);
                println!("\nPublic Key B:\n{:X}", user.public_key_b);
                println!("\nPrivate Key P:\n{:X}", user.private_key_p);
                println!("\nPrivate Key Q:\n{:X}", user.private_key_q);
            },

            "2" => {
                let server_n = hex_to_bigint(&get_input("Enter server's modulus (N) in hex: "));
                let server_b = hex_to_bigint(&get_input("Enter server's public key (B) in hex: "));
                let message = hex_to_bigint(&get_input("Enter message to encrypt in hex: "));

                let mut temp_user = RabinUser::new();
                temp_user.public_key_n = server_n;
                temp_user.public_key_b = server_b;

                match temp_user.encrypt(&message) {
                    Ok((encrypted, indicators)) => {
                        println!("\nEncrypted message:\n{:X}", encrypted);
                        println!("Indicators (C1, C2):\n{:X}, {:X}", indicators.0, indicators.1);
                    },
                    Err(e) => println!("Encryption error: {}", e),
                }
            },

            "3" => {
                let private_p = hex_to_bigint(&get_input("Enter your private key (P) in hex: "));
                let private_q = hex_to_bigint(&get_input("Enter your private key (Q) in hex: "));
                let public_n = hex_to_bigint(&get_input("Enter your modulus (N) in hex: "));
                let public_b = hex_to_bigint(&get_input("Enter your public key (B) in hex: "));
                let encrypted_msg = hex_to_bigint(&get_input("Enter encrypted message in hex: "));
                let c1 = hex_to_bigint(&get_input("Enter indicator C1 in hex: "));
                let c2 = hex_to_bigint(&get_input("Enter indicator C2 in hex: "));

                let mut temp_user = RabinUser::new();
                temp_user.private_key_p = private_p;
                temp_user.private_key_q = private_q;
                temp_user.public_key_n = public_n;
                temp_user.public_key_b = public_b;

                match temp_user.decrypt(&encrypted_msg, &(c1, c2)) {
                    Ok(decrypted) => println!("\nDecrypted message:\n{:X}", decrypted),
                    Err(e) => println!("Decryption error: {}", e),
                }
            },

            "4" => {
                let private_p = hex_to_bigint(&get_input("Enter your private key (P) in hex: "));
                let private_q = hex_to_bigint(&get_input("Enter your private key (Q) in hex: "));
                let public_n = hex_to_bigint(&get_input("Enter your modulus (N) in hex: "));
                let public_b = hex_to_bigint(&get_input("Enter your public key (B) in hex: "));
                let message = hex_to_bigint(&get_input("Enter message to sign in hex: "));

                let mut temp_user = RabinUser::new();
                temp_user.private_key_p = private_p;
                temp_user.private_key_q = private_q;
                temp_user.public_key_n = public_n;
                temp_user.public_key_b = public_b;

                match temp_user.sign_message(&message) {
                    Ok(signature) => println!("\nSignature:\n{:X}", signature),
                    Err(e) => println!("Signing error: {}", e),
                }
            },

            "5" => {
                let signer_n = hex_to_bigint(&get_input("Enter signer's modulus (N) in hex: "));
                let signer_b = hex_to_bigint(&get_input("Enter signer's public key (B) in hex: "));
                let message = hex_to_bigint(&get_input("Enter original message in hex: "));
                let signature = hex_to_bigint(&get_input("Enter signature in hex: "));

                let mut temp_user = RabinUser::new();
                temp_user.public_key_n = signer_n;
                temp_user.public_key_b = signer_b;

                let is_valid = temp_user.verify_signature(&message, &signature);
                println!("\nSignature verification: {}", if is_valid { "SUCCESS" } else { "FAILED" });
            },

            "6" => {
                println!("Goodbye!");
                break;
            },

            _ => println!("Invalid choice. Please select a number between 1 and 6."),
        }
    }
}