use num_bigint::BigInt;  
use num_traits::Num;  
use rsa::RSA;  
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
    println!("RSA Crypto CLI Tool");  
    println!("------------------");  

    loop {  
        println!("\nAvailable operations:");  
        println!("1. Generate new key pair");  
        println!("2. Encrypt message");  
        println!("3. Decrypt message");  
        println!("4. Sign message");  
        println!("5. Verify signature");  
        println!("6. Send key");  
        println!("7. Receive key");  
        println!("8. Exit");  

        let choice = get_input("Select operation (1-8): ");  

        match choice.as_str() {  
            "1" => {  
                let bit_size = 256;  
                let miller_rabin_iterations = 25;  
                let keys = RSA::new(bit_size, miller_rabin_iterations);  

                println!("\nGenerated Key Pair:");  
                println!("Public Exponent (E):\n{:X}", keys.public_key_e);  
                println!("\nPublic Modulus (N):\n{:X}", keys.public_key_n);  
                println!("\nPrivate Key (D):\n{:X}", keys.private_key_d);  
            },  

            "2" => {  
                let server_n = hex_to_bigint(&get_input("Enter server's modulus (N) in hex: "));  
                let server_e = hex_to_bigint(&get_input("Enter server's exponent (E) in hex: "));  
                let message = hex_to_bigint(&get_input("Enter message to encrypt in hex: "));  

                let temp_rsa = RSA::new(256, 10);
                let encrypted = temp_rsa.encrypt(&message, &server_e, &server_n);  
                println!("\nEncrypted message:\n{:X}", encrypted);  
            },  

            "3" => {  
                let private_d = hex_to_bigint(&get_input("Enter your private key (D) in hex: "));  
                let public_n = hex_to_bigint(&get_input("Enter your modulus (N) in hex: "));  
                let encrypted_msg = hex_to_bigint(&get_input("Enter encrypted message in hex: "));  

                let temp_rsa = RSA::new(256, 10);  
                let decrypted = temp_rsa.decrypt(&encrypted_msg, &private_d, &public_n);  
                println!("\nDecrypted message:\n{:X}", decrypted);  
            },  

            "4" => {  
                let private_d = hex_to_bigint(&get_input("Enter your private key (D) in hex: "));  
                let public_n = hex_to_bigint(&get_input("Enter your modulus (N) in hex: "));  
                let message = hex_to_bigint(&get_input("Enter message to sign in hex: "));  

                let temp_rsa = RSA::new(256, 10);  
                let signature = temp_rsa.sign_message(&message, &private_d, &public_n);  
                println!("\nSignature:\n{:X}", signature);  
            },  

            "5" => {  
                let signer_e = hex_to_bigint(&get_input("Enter signer's public exponent (E) in hex: "));  
                let signer_n = hex_to_bigint(&get_input("Enter signer's modulus (N) in hex: "));  
                let message = hex_to_bigint(&get_input("Enter original message in hex: "));  
                let signature = hex_to_bigint(&get_input("Enter signature in hex: "));  

                let temp_rsa = RSA::new(256, 10);  
                let is_valid = temp_rsa.verify_signature(&message, &signature, &signer_e, &signer_n);  
                println!("\nSignature verification: {}", if is_valid { "SUCCESS" } else { "FAILED" });  
            },  

            "6" => {  
                let receiver_e = hex_to_bigint(&get_input("Enter receiver's public exponent (E) in hex: "));  
                let receiver_n = hex_to_bigint(&get_input("Enter receiver's modulus (N) in hex: "));  
                let key = hex_to_bigint(&get_input("Enter key to send in hex: "));  

                let temp_rsa = RSA::new(256, 10);  
                let (encrypted_key, encrypted_signature) = temp_rsa.send_key(&key, &receiver_e, &receiver_n);  
                println!("\nEncrypted key:\n{:X}", encrypted_key);  
                println!("\nEncrypted signature:\n{:X}", encrypted_signature);  
            },  

            "7" => {  
                let sender_e = hex_to_bigint(&get_input("Enter sender's public exponent (E) in hex: "));  
                let sender_n = hex_to_bigint(&get_input("Enter sender's modulus (N) in hex: "));  
                let private_d = hex_to_bigint(&get_input("Enter your private key (D) in hex: "));  
                let public_n = hex_to_bigint(&get_input("Enter your modulus (N) in hex: "));  
                let encrypted_key = hex_to_bigint(&get_input("Enter encrypted key in hex: "));  
                let encrypted_signature = hex_to_bigint(&get_input("Enter encrypted signature in hex: "));  

                let temp_rsa = RSA::new(256, 10);  
                let key_verified = temp_rsa.receive_key(  
                    &encrypted_key,  
                    &encrypted_signature,  
                    &sender_e,  
                    &sender_n,  
                    &private_d,  
                    &public_n  
                );  
                println!("\nKey exchange verification: {}", if key_verified { "SUCCESS" } else { "FAILED" });  
            },  

            "8" => {  
                println!("Goodbye!");  
                break;  
            },  

            _ => println!("Invalid choice. Please select a number between 1 and 8."),  
        }  
    }  
}  