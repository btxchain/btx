#![no_main]

//! Determinism cross-check for `generate_keypair`.
//!
//! Invariant under test: `generate_keypair(alg, seed)` is deterministic
//! in its input — calling it twice with byte-identical seeds must produce
//! byte-identical keypairs (both public-key bytes and secret-key bytes).
//!
//! This catches RNG/seed-routing regressions: e.g., a refactor where
//! keygen accidentally mixes in non-deterministic per-process state, or
//! a code path that consumes some implicit additional randomness on top
//! of the supplied seed.
//!
//! Driven through `arbitrary` so the fuzzer can vary algorithm choice
//! and seed length naturally rather than slicing raw bytes.
//!
//! Note on what is **not** asserted here: we don't fuzz the contrapositive
//! (distinct seeds → distinct keys). For SECP256K1, secret keys k and
//! (n - k) mod n share the same x-only public key, so distinct-seed
//! collisions exist by construction at probability ~2⁻²⁵⁶ and an
//! aggressive fuzzer could conceivably surface one. For the PQC
//! algorithms the input-consumption contract of `bitcoin_pqc_keygen`
//! isn't publicly documented, so a "different seeds → different keys"
//! assertion could mislead the fuzzer if the implementation truncates
//! input. The Repeat invariant is universally safe and catches the
//! regression class we care about most (silent loss of determinism).

use arbitrary::Arbitrary;
use bitcoinpqc::{generate_keypair, Algorithm};
use libfuzzer_sys::fuzz_target;

const NUM_ALGORITHMS: u8 = 3;

fn algorithm_from_index(b: u8) -> Algorithm {
    match b % NUM_ALGORITHMS {
        0 => Algorithm::SECP256K1_SCHNORR,
        1 => Algorithm::ML_DSA_44,
        _ => Algorithm::SLH_DSA_128S,
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    algorithm_byte: u8,
    seed: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    if input.seed.len() < 128 {
        return;
    }
    let algorithm = algorithm_from_index(input.algorithm_byte);

    let kp1 = match generate_keypair(algorithm, &input.seed) {
        Ok(k) => k,
        Err(_) => return,
    };
    let kp2 = match generate_keypair(algorithm, &input.seed) {
        Ok(k) => k,
        Err(_) => return,
    };

    assert_eq!(
        kp1.public_key.bytes, kp2.public_key.bytes,
        "Non-deterministic public key for algorithm {} with identical seed",
        algorithm.debug_name(),
    );
    assert_eq!(
        kp1.secret_key.bytes, kp2.secret_key.bytes,
        "Non-deterministic secret key for algorithm {} with identical seed",
        algorithm.debug_name(),
    );
    assert_eq!(
        kp1.public_key.algorithm, algorithm,
        "Public key algorithm mismatch for {}",
        algorithm.debug_name(),
    );
    assert_eq!(
        kp1.secret_key.algorithm, algorithm,
        "Secret key algorithm mismatch for {}",
        algorithm.debug_name(),
    );
});
