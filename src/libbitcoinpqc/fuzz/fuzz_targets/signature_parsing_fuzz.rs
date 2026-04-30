#![no_main]

use bitcoinpqc::{Algorithm, Signature};
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
    if data.is_empty() {
        return; // Need at least one byte for algorithm selection
    }

    // Use first byte to select an algorithm
    let algorithm = algorithm_from_index(data[0]);

    // Use remaining bytes as potential signature data
    let sig_data = &data[1..];

    // Attempt to parse as Signature
    let _ = Signature::try_from_slice(algorithm, sig_data);
});
