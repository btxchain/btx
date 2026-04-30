#![no_main]

use bitcoinpqc::{generate_keypair, Algorithm};
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
    if data.len() < 130 {
        // Need at least 1 byte for algorithm + 129 bytes for key seed
        return;
    }

    // First byte selects algorithm
    let algorithm = algorithm_from_index(data[0]);

    // Rest is key generation data
    let key_data = &data[1..]; // Should be 129+ bytes

    // Try to generate a keypair. Note that key generation can legitimately
    // fail for cryptographically-bad seeds (for example, SECP256K1 rejects
    // secret keys at or above the curve order). The contract we assert is
    // weaker than "always succeeds": it must not panic, and on success the
    // returned keypair must report the algorithm we asked for.
    if let Ok(keypair) = generate_keypair(algorithm, key_data) {
        assert_eq!(
            keypair.public_key.algorithm, algorithm,
            "Public key algorithm mismatch! Asked for {}, got {}",
            algorithm.debug_name(),
            keypair.public_key.algorithm.debug_name(),
        );
        assert_eq!(
            keypair.secret_key.algorithm, algorithm,
            "Secret key algorithm mismatch! Asked for {}, got {}",
            algorithm.debug_name(),
            keypair.secret_key.algorithm.debug_name(),
        );
    }
});
