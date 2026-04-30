#![no_main]

//! Verification robustness — `verify` must never panic on malformed input.
//!
//! `verify(pk, msg, sig)` sits on the deserialization hot path: it is the
//! first thing called when a peer-supplied transaction reaches consensus.
//! If a malicious peer can cause it to panic — even on cryptographically
//! impossible inputs — that's a denial-of-service vector at the very least
//! and potentially worse. This harness exercises three garbage-flavored
//! verification scenarios for every supported algorithm:
//!
//!   * `verify(real_pk, msg, random_sig_bytes)`
//!   * `verify(random_pk_bytes, msg, real_sig)`
//!   * `verify(random_pk_bytes, msg, random_sig_bytes)`
//!
//! Each must return `Err`, never panic, regardless of the byte values.
//! `try_from_slice` filters out any byte sequence whose length doesn't
//! match the algorithm's expected size — those inputs we silently skip,
//! they're well-defined parse failures, not the case under test.

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm, PublicKey, Signature};
use libfuzzer_sys::fuzz_target;

const NUM_ALGORITHMS: u8 = 3;

fn algorithm_from_index(b: u8) -> Algorithm {
    match b % NUM_ALGORITHMS {
        0 => Algorithm::SECP256K1_SCHNORR,
        1 => Algorithm::ML_DSA_44,
        _ => Algorithm::SLH_DSA_128S,
    }
}

fuzz_target!(|data: &[u8]| {
    // Layout: 1 byte alg + 128 bytes seed + 32 bytes message + remainder
    // is "garbage" reused for both pk-and-sig random byte injection.
    if data.len() < 1 + 128 + 32 {
        return;
    }
    let algorithm = algorithm_from_index(data[0]);
    let seed = &data[1..129];
    let message = &data[129..161];
    let garbage = &data[161..];

    // A valid keypair to use as the "real" half in the mixed scenarios.
    let keypair = match generate_keypair(algorithm, seed) {
        Ok(kp) => kp,
        Err(_) => return,
    };
    let real_sig = match sign(&keypair.secret_key, message) {
        Ok(s) => s,
        Err(_) => return,
    };

    // -- Scenario 1: real pk, garbage sig bytes ------------------------
    let sig_size = bitcoinpqc::signature_size(algorithm);
    if garbage.len() >= sig_size {
        if let Ok(sig) = Signature::try_from_slice(algorithm, &garbage[..sig_size]) {
            // Must return Err (signature is unrelated to keypair) and
            // must not panic.
            let _ = verify(&keypair.public_key, message, &sig);
        }
    }

    // -- Scenario 2: garbage pk bytes, real sig ------------------------
    let pk_size = bitcoinpqc::public_key_size(algorithm);
    if garbage.len() >= pk_size {
        if let Ok(garbage_pk) = PublicKey::try_from_slice(algorithm, &garbage[..pk_size]) {
            let _ = verify(&garbage_pk, message, &real_sig);
        }
    }

    // -- Scenario 3: garbage pk and garbage sig ------------------------
    if garbage.len() >= pk_size + sig_size {
        let pk_slice = &garbage[..pk_size];
        let sig_slice = &garbage[pk_size..pk_size + sig_size];
        if let (Ok(garbage_pk), Ok(garbage_sig)) = (
            PublicKey::try_from_slice(algorithm, pk_slice),
            Signature::try_from_slice(algorithm, sig_slice),
        ) {
            let _ = verify(&garbage_pk, message, &garbage_sig);
        }
    }
});
