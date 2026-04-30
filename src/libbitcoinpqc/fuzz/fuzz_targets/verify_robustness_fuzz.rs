#![no_main]

//! Verification robustness for the Rust wrapper API.
//!
//! This target exercises `verify(pk, msg, sig)` through typed `PublicKey`
//! and `Signature` wrapper values. External Rust callers can construct those
//! wrappers from arbitrary byte buffers, so the invariant here is: malformed
//! wrapper payloads must be rejected cleanly and must never panic.
//!
//! The harness exercises three garbage-flavored verification scenarios for
//! every supported algorithm:
//!
//!   * `verify(real_pk, msg, random_sig_bytes)`
//!   * `verify(random_pk_bytes, msg, real_sig)`
//!   * `verify(random_pk_bytes, msg, random_sig_bytes)`
//!
//! Each must return `Err`, never panic, regardless of the byte values.
//! We use correct-length slices so we exercise `verify` itself rather than
//! trivial wrapper-length rejections.

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

fn perturb_bytes(bytes: &mut [u8]) {
    if let Some(first) = bytes.first_mut() {
        *first ^= 0x01;
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
        let mut sig = Signature {
            algorithm,
            bytes: garbage[..sig_size].to_vec(),
        };
        // Avoid false positives if the fuzz bytes happen to recreate the
        // exact valid signature for this key/message pair.
        if sig.bytes == real_sig.bytes {
            perturb_bytes(&mut sig.bytes);
        }
        assert!(
            verify(&keypair.public_key, message, &sig).is_err(),
            "Garbage signature unexpectedly verified for {}",
            algorithm.debug_name(),
        );
    }

    // -- Scenario 2: garbage pk bytes, real sig ------------------------
    let pk_size = bitcoinpqc::public_key_size(algorithm);
    if garbage.len() >= pk_size {
        let mut garbage_pk = PublicKey {
            algorithm,
            bytes: garbage[..pk_size].to_vec(),
        };
        if garbage_pk.bytes == keypair.public_key.bytes {
            perturb_bytes(&mut garbage_pk.bytes);
        }
        assert!(
            verify(&garbage_pk, message, &real_sig).is_err(),
            "Garbage public key unexpectedly verified {} signature",
            algorithm.debug_name(),
        );
    }

    // -- Scenario 3: garbage pk and garbage sig ------------------------
    if garbage.len() >= pk_size + sig_size {
        let pk_slice = &garbage[..pk_size];
        let sig_slice = &garbage[pk_size..pk_size + sig_size];
        let mut garbage_pk = PublicKey {
            algorithm,
            bytes: pk_slice.to_vec(),
        };
        let mut garbage_sig = Signature {
            algorithm,
            bytes: sig_slice.to_vec(),
        };
        if garbage_pk.bytes == keypair.public_key.bytes {
            perturb_bytes(&mut garbage_pk.bytes);
        }
        if garbage_sig.bytes == real_sig.bytes {
            perturb_bytes(&mut garbage_sig.bytes);
        }
        assert!(
            verify(&garbage_pk, message, &garbage_sig).is_err(),
            "Garbage key/signature pair unexpectedly verified for {}",
            algorithm.debug_name(),
        );
    }
});
