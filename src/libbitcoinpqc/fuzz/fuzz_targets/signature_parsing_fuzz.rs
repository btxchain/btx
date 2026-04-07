#![no_main]

use bitcoinpqc::{algorithm_from_index, Signature};
use libfuzzer_sys::fuzz_target;

const NUM_ALGORITHMS: u8 = 3; // SECP256K1_SCHNORR, ML_DSA_44, SLH_DSA_128S

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return; // Need at least one byte for algorithm selection
    }

    // Use first byte to select an algorithm
    let alg_byte = data[0];
    let algorithm = algorithm_from_index(alg_byte);

    // Use remaining bytes as potential signature data
    let sig_data = &data[1..];

    // Attempt to parse as Signature
    let _ = Signature::try_from_slice(algorithm, sig_data);
});
