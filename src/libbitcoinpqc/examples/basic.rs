use bitcoinpqc::{generate_keypair, sign, verify, Algorithm};
use rand::{rng, RngCore};
use std::time::Instant;

fn main() {
    println!("Bitcoin PQC Library Example");
    println!("==========================\n");
    println!("This example tests the post-quantum signature algorithms designed for BIP-360 and the Bitcoin QuBit soft fork.\n");

    // Generate random data for key generation
    let mut random_data = vec![0u8; 128];
    rng().fill_bytes(&mut random_data);

    // Test each algorithm
    test_algorithm(Algorithm::ML_DSA_44, "ML-DSA-44", &random_data);
    test_algorithm(Algorithm::SLH_DSA_128S, "SLH-DSA-Shake-128s", &random_data);
}

fn test_algorithm(algorithm: Algorithm, name: &str, random_data: &[u8]) {
    println!("Testing {name} algorithm:");
    println!("------------------------");

    // Get key and signature sizes
    let pk_size = bitcoinpqc::public_key_size(algorithm);
    let sk_size = bitcoinpqc::secret_key_size(algorithm);
    let sig_size = bitcoinpqc::signature_size(algorithm);

    println!("Public key size: {pk_size} bytes");
    println!("Secret key size: {sk_size} bytes");
    println!("Signature size: {sig_size} bytes");

    // Generate a key pair
    let start = Instant::now();
    let keypair = match generate_keypair(algorithm, random_data) {
        Ok(kp) => kp,
        Err(e) => {
            println!("Error generating key pair: {e}");
            return;
        }
    };
    let duration = start.elapsed();
    println!("Key generation time: {duration:?}");

    // Create a message to sign
    let message = b"This is a test message for PQC signature verification";

    // Sign the message deterministically
    let start = Instant::now();
    let signature = match sign(&keypair.secret_key, message) {
        Ok(sig) => sig,
        Err(e) => {
            println!("Error signing message: {e}");
            return;
        }
    };
    let duration = start.elapsed();
    println!("Signing time: {duration:?}");
    println!("Actual signature size: {} bytes", signature.bytes.len());

    // Verify the signature
    let start = Instant::now();
    match verify(&keypair.public_key, message, &signature) {
        Ok(()) => println!("Signature verified successfully!"),
        Err(e) => println!("Signature verification failed: {e}"),
    }
    let duration = start.elapsed();
    println!("Verification time: {duration:?}");

    // Try to verify with a modified message
    let modified_message = b"This is a MODIFIED message for PQC signature verification";
    match verify(&keypair.public_key, modified_message, &signature) {
        Ok(()) => println!("ERROR: Signature verified for modified message!"),
        Err(_) => println!("Correctly rejected signature for modified message"),
    }

    println!();
}
