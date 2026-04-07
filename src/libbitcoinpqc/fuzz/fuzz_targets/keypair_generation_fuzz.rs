#![no_main]

use bitcoinpqc::{algorithm_from_index, generate_keypair};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 130 {
        // Need at least 1 byte for algorithm + 129 bytes for key seed
        return;
    }

    // First byte selects algorithm
    let alg_byte = data[0];
    let algorithm = algorithm_from_index(alg_byte);

    // Rest is key generation data
    let key_data = &data[1..]; // Should be 129+ bytes

    // Try to generate a keypair
    let keypair_result = generate_keypair(algorithm, key_data);
    assert!(
        keypair_result.is_ok(),
        "Keypair generation failed! Algorithm: {}",
        algorithm.debug_name()
    );
    let _keypair = keypair_result.unwrap();
    // Success!
});
