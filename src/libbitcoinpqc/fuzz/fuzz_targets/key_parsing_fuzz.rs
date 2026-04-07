#![no_main]

use bitcoinpqc::{algorithm_from_index, PublicKey, SecretKey};
use libfuzzer_sys::fuzz_target;

const NUM_ALGORITHMS: u8 = 3; // SECP256K1_SCHNORR, ML_DSA_44, SLH_DSA_128S

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        // Need at least 2 bytes: 1 for algorithm, 1+ for key data
        return;
    }

    // First byte selects algorithm
    let alg_byte = data[0];
    let algorithm = algorithm_from_index(alg_byte);

    // Rest of the data is treated as a potential key
    let key_data = &data[1..];

    // Try to interpret this as a secret key
    // The key_parsing should correctly validate this without crashing
    let sk_result = SecretKey::try_from_slice(algorithm, key_data);
    if key_data.len() == bitcoinpqc::secret_key_size(algorithm) {
        // If length matches, it should parse correctly
        // (assuming bytewise validation passes)
        let _ = sk_result.unwrap_or_else(|_| {
            panic!(
                "Secret key parsing failed! Algorithm: {}",
                algorithm.debug_name()
            )
        });
    } else {
        // Otherwise it should return an error
        assert!(
            sk_result.is_err(),
            "Parsing should fail for invalid key length!"
        );
    }
});
