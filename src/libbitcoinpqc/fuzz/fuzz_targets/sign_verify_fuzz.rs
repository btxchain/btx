#![no_main]

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm};
use libfuzzer_sys::fuzz_target;

const NUM_ALGORITHMS: u8 = 3;

/// Map a fuzz-supplied byte to one of the supported algorithms.
fn algorithm_from_index(b: u8) -> Algorithm {
    match b % NUM_ALGORITHMS {
        0 => Algorithm::SECP256K1_SCHNORR,
        1 => Algorithm::ML_DSA_44,
        _ => Algorithm::SLH_DSA_128S,
    }
}

fuzz_target!(|data: &[u8]| {
    // Need sufficient bytes: 1 byte for algorithm + 128 bytes for key
    // generation seed + 32 bytes for the message (Secp256k1 signs a 32-byte
    // hash).
    if data.len() < 1 + 128 + 32 {
        return;
    }

    let algorithm = algorithm_from_index(data[0]);
    let key_data = &data[1..129];
    let message = &data[129..];

    // Key generation can legitimately fail for cryptographically-bad seeds
    // (e.g., SECP256K1 rejects out-of-range secret keys). Treat that as an
    // uninteresting input and exit without raising.
    let keypair = match generate_keypair(algorithm, key_data) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Sign the message. With a valid keypair this must succeed.
    let signature = match sign(&keypair.secret_key, message) {
        Ok(sig) => sig,
        Err(err) => panic!(
            "Signing a {}-byte message with a freshly generated {} keypair returned {:?}",
            message.len(),
            algorithm.debug_name(),
            err
        ),
    };

    // The signature must report the algorithm we asked for.
    assert_eq!(
        signature.algorithm, algorithm,
        "Signature algorithm mismatch! Signed with {}, signature reports {}",
        algorithm.debug_name(),
        signature.algorithm.debug_name(),
    );

    // Verification of a signature we just produced must succeed.
    if let Err(err) = verify(&keypair.public_key, message, &signature) {
        panic!(
            "Verification of a freshly produced {} signature failed: {:?}",
            algorithm.debug_name(),
            err
        );
    }

    let mut modified_msg = message.to_vec();
    modified_msg[0] ^= 0xFF;
    assert!(
        verify(&keypair.public_key, &modified_msg, &signature).is_err(),
        "Verification should fail with modified message for {}",
        algorithm.debug_name(),
    );

    let mut modified_sig = signature.clone();
    modified_sig.bytes[0] ^= 0xFF;
    assert!(
        verify(&keypair.public_key, message, &modified_sig).is_err(),
        "Verification should fail with modified signature for {}",
        algorithm.debug_name(),
    );
});
