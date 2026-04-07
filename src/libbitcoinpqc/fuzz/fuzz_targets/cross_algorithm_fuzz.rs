#![no_main]

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm, Signature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 150 {
        // Need sufficient bytes for all operations
        return;
    }

    // Use first 128 bytes for key generation
    let key_data = &data[0..128];

    // Generate two keypairs with different algorithms
    let alg1 = Algorithm::SECP256K1_SCHNORR;
    let alg2 = Algorithm::ML_DSA_44;

    let keypair1 = match generate_keypair(alg1, key_data) {
        Ok(kp) => kp,
        Err(_) => return, // Skip if key generation fails
    };

    let keypair2 = match generate_keypair(alg2, key_data) {
        Ok(kp) => kp,
        Err(_) => return, // Skip if key generation fails
    };

    // Use remaining bytes as message to sign
    let message = &data[128..];

    // Sign with both keys
    let signature1 = match sign(&keypair1.secret_key, message) {
        Ok(sig) => sig,
        Err(_) => return, // Skip if signing fails
    };

    let signature2 = match sign(&keypair2.secret_key, message) {
        Ok(sig) => sig,
        Err(_) => return, // Skip if signing fails
    };

    // Try to verify with correct key-signature pairs (should succeed)
    let _ = verify(&keypair1.public_key, message, &signature1);
    let _ = verify(&keypair2.public_key, message, &signature2);

    // Now try incorrect combinations (should fail)

    // Case 1: Use signature1 with public key2
    let sig1_with_wrong_alg = Signature {
        algorithm: keypair2.public_key.algorithm,
        bytes: signature1.bytes.clone(),
    };
    let _ = verify(&keypair2.public_key, message, &sig1_with_wrong_alg);

    // Case 2: Use signature2 with public key1
    let sig2_with_wrong_alg = Signature {
        algorithm: keypair1.public_key.algorithm,
        bytes: signature2.bytes.clone(),
    };
    let _ = verify(&keypair1.public_key, message, &sig2_with_wrong_alg);

    // Case 3: Use original signatures but with the wrong public key
    let _ = verify(&keypair1.public_key, message, &signature2);
    let _ = verify(&keypair2.public_key, message, &signature1);
});
