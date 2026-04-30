#![no_main]

//! Algorithm-confusion resistance.
//!
//! When a transaction carries a post-quantum signature, the signature is
//! tagged with the algorithm it was produced under. An attacker could
//! attempt to confuse the verifier by submitting a signature whose payload
//! bytes were produced by algorithm A but whose tag claims algorithm B.
//! `verify` must reject all such mismatches cleanly:
//!
//!   * the claimed algorithm tag on the signature must match the public
//!     key's algorithm; if it does not, verification fails;
//!   * even if the tag matches the public key's algorithm, payload bytes
//!     produced under a different algorithm must not pass verification.
//!
//! This harness exercises both confusion vectors with every cross-algorithm
//! pairing across the three supported algorithms.

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm, Signature};
use libfuzzer_sys::fuzz_target;

const ALGS: [Algorithm; 3] = [
    Algorithm::SECP256K1_SCHNORR,
    Algorithm::ML_DSA_44,
    Algorithm::SLH_DSA_128S,
];

fuzz_target!(|data: &[u8]| {
    // Layout: 128 bytes seed + 32 bytes message + remainder unused.
    if data.len() < 128 + 32 {
        return;
    }
    let seed = &data[0..128];
    let message = &data[128..160];

    // Generate a keypair under each algorithm and sign the same message.
    // We need at least two algorithms to succeed before substitution
    // testing is meaningful.
    let mut signed: Vec<(Algorithm, _, _)> = Vec::with_capacity(ALGS.len());
    for alg in ALGS.iter().copied() {
        if let Ok(kp) = generate_keypair(alg, seed) {
            if let Ok(sig) = sign(&kp.secret_key, message) {
                signed.push((alg, kp, sig));
            }
        }
    }
    if signed.len() < 2 {
        return;
    }

    // For every ordered pair of distinct algorithms, attempt three
    // substitution variants. None of them should verify; none should
    // panic. Iterating ordered pairs ensures every directional
    // combination is exercised even though variants (1) and (3) are
    // structurally symmetric across the loop.
    for i in 0..signed.len() {
        for j in 0..signed.len() {
            if i == j {
                continue;
            }
            let (alg_i, kp_i, sig_i) = (signed[i].0, &signed[i].1, &signed[i].2);
            let (alg_j, kp_j, sig_j) = (signed[j].0, &signed[j].1, &signed[j].2);

            // (1) sig_i with i's bytes but j's algorithm tag, against j's pk
            let mistagged = Signature {
                algorithm: alg_j,
                bytes: sig_i.bytes.clone(),
            };
            assert!(
                verify(&kp_j.public_key, message, &mistagged).is_err(),
                "Signature bytes from {} accepted under {}'s tag/pk!",
                alg_i.debug_name(),
                alg_j.debug_name(),
            );

            // (2) sig_i unchanged, against j's pk (mismatched tag/pk)
            assert!(
                verify(&kp_j.public_key, message, sig_i).is_err(),
                "Signature from {} accepted against {} pk!",
                alg_i.debug_name(),
                alg_j.debug_name(),
            );

            // (3) sig_j's bytes carried under i's tag, against i's pk
            let crossed = Signature {
                algorithm: alg_i,
                bytes: sig_j.bytes.clone(),
            };
            assert!(
                verify(&kp_i.public_key, message, &crossed).is_err(),
                "Signature bytes from {} accepted under {}'s tag/pk!",
                alg_j.debug_name(),
                alg_i.debug_name(),
            );
        }
    }
});
