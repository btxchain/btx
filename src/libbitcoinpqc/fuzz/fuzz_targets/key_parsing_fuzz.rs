#![no_main]

use bitcoinpqc::{Algorithm, SecretKey};
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
    if data.len() < 2 {
        // Need at least 2 bytes: 1 for algorithm, 1+ for key data
        return;
    }

    // First byte selects algorithm
    let algorithm = algorithm_from_index(data[0]);

    // Rest of the data is treated as a potential key
    let key_data = &data[1..];

    // Try to interpret this as a secret key. The contract we assert is:
    //   - parsing must never panic on arbitrary input;
    //   - any input whose length does not match the expected secret-key
    //     size for the algorithm must be rejected.
    // We do *not* assert that length-correct input always parses, because
    // some algorithms (notably SECP256K1) impose additional bytewise
    // validity constraints (e.g., secret key in [1, n-1]).
    let sk_result = SecretKey::try_from_slice(algorithm, key_data);
    if key_data.len() != bitcoinpqc::secret_key_size(algorithm) {
        assert!(
            sk_result.is_err(),
            "Parsing should fail for invalid key length! Algorithm: {}, got {} bytes",
            algorithm.debug_name(),
            key_data.len(),
        );
    }
    // If it did parse, the returned key must report the algorithm we asked for.
    if let Ok(sk) = sk_result {
        assert_eq!(
            sk.algorithm, algorithm,
            "Parsed secret key algorithm mismatch! Asked for {}, got {}",
            algorithm.debug_name(),
            sk.algorithm.debug_name(),
        );
    }
});
