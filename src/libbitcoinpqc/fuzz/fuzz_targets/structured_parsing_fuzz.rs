#![no_main]

//! Structured parse fuzzing for `PublicKey`, `SecretKey`, and `Signature`.
//!
//! The original `key_parsing_fuzz` and `signature_parsing_fuzz` harnesses
//! drive `try_from_slice` from raw fuzz bytes only. That misses two
//! categories of input the fuzzer should be hitting on purpose:
//!
//!   * Inputs whose length **happens to equal** the expected size for the
//!     selected algorithm (so parsing reaches the post-length validation
//!     code path), and
//!   * Inputs of **deliberately mismatched** length (so the length check
//!     itself is exercised across every algorithm in turn).
//!
//! This harness uses an `arbitrary`-derived enum to tell the fuzzer which
//! invariant is under test on each iteration, and asserts the algorithm
//! tag round-trips through any successful parse.

use arbitrary::Arbitrary;
use bitcoinpqc::{Algorithm, PublicKey, SecretKey, Signature};
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
enum ParseTarget {
    PublicKey,
    SecretKey,
    Signature,
}

#[derive(Arbitrary, Debug)]
enum FuzzMode {
    /// Length-correct attempt: pad/truncate `bytes` to the algorithm's
    /// expected size before passing to `try_from_slice`. Exercises the
    /// post-length validation path.
    ExactSize {
        algorithm_byte: u8,
        target: ParseTarget,
        bytes: Vec<u8>,
    },
    /// Length-arbitrary attempt: pass `bytes` straight through. Exercises
    /// the length check itself.
    RawBytes {
        algorithm_byte: u8,
        target: ParseTarget,
        bytes: Vec<u8>,
    },
}

fn expected_size(algorithm: Algorithm, target: &ParseTarget) -> usize {
    match target {
        ParseTarget::PublicKey => bitcoinpqc::public_key_size(algorithm),
        ParseTarget::SecretKey => bitcoinpqc::secret_key_size(algorithm),
        ParseTarget::Signature => bitcoinpqc::signature_size(algorithm),
    }
}

fn try_parse_and_check(algorithm: Algorithm, target: &ParseTarget, bytes: &[u8]) {
    match target {
        ParseTarget::PublicKey => {
            if let Ok(pk) = PublicKey::try_from_slice(algorithm, bytes) {
                assert_eq!(pk.algorithm, algorithm);
            }
        }
        ParseTarget::SecretKey => {
            if let Ok(sk) = SecretKey::try_from_slice(algorithm, bytes) {
                assert_eq!(sk.algorithm, algorithm);
            }
        }
        ParseTarget::Signature => {
            if let Ok(sig) = Signature::try_from_slice(algorithm, bytes) {
                assert_eq!(sig.algorithm, algorithm);
            }
        }
    }
}

fuzz_target!(|mode: FuzzMode| {
    match mode {
        FuzzMode::ExactSize {
            algorithm_byte,
            target,
            mut bytes,
        } => {
            let algorithm = algorithm_from_index(algorithm_byte);
            let want = expected_size(algorithm, &target);
            if want == 0 {
                return;
            }
            // Resize to exactly the expected length, repeating the input
            // bytes as needed to fill (zero-padding if input is empty).
            if bytes.is_empty() {
                bytes.resize(want, 0);
            } else {
                let pattern_len = bytes.len();
                bytes.resize(want, 0);
                if pattern_len < want {
                    for i in pattern_len..want {
                        bytes[i] = bytes[i % pattern_len];
                    }
                }
            }
            try_parse_and_check(algorithm, &target, &bytes);
        }
        FuzzMode::RawBytes {
            algorithm_byte,
            target,
            bytes,
        } => {
            let algorithm = algorithm_from_index(algorithm_byte);
            let want = expected_size(algorithm, &target);
            if want == 0 {
                return;
            }
            if bytes.len() != want {
                let result = match target {
                    ParseTarget::PublicKey => PublicKey::try_from_slice(algorithm, &bytes).is_err(),
                    ParseTarget::SecretKey => SecretKey::try_from_slice(algorithm, &bytes).is_err(),
                    ParseTarget::Signature => Signature::try_from_slice(algorithm, &bytes).is_err(),
                };
                assert!(
                    result,
                    "Parse with wrong length succeeded! algorithm={} target={:?} got={} expected={}",
                    algorithm.debug_name(),
                    target,
                    bytes.len(),
                    want,
                );
            } else {
                try_parse_and_check(algorithm, &target, &bytes);
            }
        }
    }
});
