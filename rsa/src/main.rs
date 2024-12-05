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

    println!("Generating new RSA key pair...");
    let user = RSA::new(bit_size, miller_rabin_iterations);

    println!("USER KEY INFORMATION:");
    println!("Public Exponent (E):");
    println!("{:X}", user.public_key_e);
    println!("\nPublic Modulus (N):");
    println!("{:X}", user.public_key_n);
    println!("\nPrivate Key (D):");
    println!("{:X}", user.private_key_d);

    print_separator();

    println!("SERVER PARAMETERS:");
    let server_e = BigInt::from(65537);
    let server_n = hex_to_bigint("95F964B34209E5616D806C33AE352C060EF68696FAD9692DCE59769937A8BDEF");
    println!("Server Public Exponent (E): {:X}", server_e);
    println!("Server Public Modulus (N): {:X}", server_n);

    print_separator();

    println!("MESSAGE ENCRYPTION TEST:");
    let message = hex_to_bigint("deadbee");
    println!("Original Message: {:X}", message);

    let encrypted = user.encrypt(&message, &server_e, &server_n);
    println!("Encrypted Message: {:X}", encrypted);

    print_separator();

    println!("MESSAGE DECRYPTION TEST:");
    let en_message = hex_to_bigint(
        "24CD96D1884D15835F5F00327269159C0D02F7706095A3B49CFD46DA2E2B813CF08B48C1D665B6566C5C7554A6073634D0E53CEACFCDC811D6B65F936224EDEB"
    );
    let d = hex_to_bigint(
        "230E6AB34F1C1B33CF989DF1363D279386E85730C0F236EF5EEAAB26948E92B81D013A31FB6140DEFA8D1E42355AFD411D865F8651665F3CCC32A8912ADA3C69"
    );
    let n = hex_to_bigint(
        "4AED4E114C13F4CFD7A0EFBA09D23F34CF7352B88F6C97983081CA983AE2B2ACC4FF4DA3C93106F3606213CBFB2775F2B60D61AD18E20AB5E91A04075B57BD0F"
    );

    println!("Encrypted Message to Decrypt:");
    println!("{:X}", en_message);

    let decrypted = user.decrypt(&en_message, &d, &n);
    println!("\nDecrypted Result:");
    println!("{:X}", decrypted);

    print_separator();

    println!("KEY EXCHANGE TEST:");
    let (sent_key, sent_signature) = user.send_key(&message, &server_e, &server_n);
    println!("Sent Key:");
    println!("{:X}", sent_key);
    println!("\nSent Signature:");
    println!("{:X}", sent_signature);

    print_separator();

    println!("KEY VERIFICATION TEST:");
    let encrypted_key = hex_to_bigint(
        "2F19DDD59D2515499B575F360CCE70F25DAA96A759B98459975E805A58DADC83CBCDDAF08CE1E7A44B10492577E8CC1D965D82AC47E152889D4BC67A55A6AF7D"
    );
    let sign_key = hex_to_bigint(
        "3106736A0FB968FD577C78034C32D5D871ADA9BA6F673C9BECF642ADED1A9856430A501FB22B591EDE52688892C4CC38C130BA01134E6A7EEC7705506A1C6130"
    );

    let rec_key = user.receive_key(&encrypted_key, &sign_key, &server_e, &server_n, &d, &n);
    println!("Key Verification Result: {}", if rec_key { "SUCCESS" } else { "FAILED" });

    print_separator();
}