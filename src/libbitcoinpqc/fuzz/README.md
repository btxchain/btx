# Fuzz Testing for libbitcoinpqc

This directory contains fuzz testing for the libbitcoinpqc library using
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Prerequisites

You need a nightly Rust toolchain (cargo-fuzz uses unstable compiler
flags for libFuzzer integration) and the `cargo-fuzz` subcommand:

```
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Available Fuzz Targets

The harnesses are split by invariant under test. Each one is a separate
`cargo-fuzz` binary so it can be tracked, corpused, and crashed
independently.

| Target | What it asserts |
|---|---|
| `keypair_generation`      | `generate_keypair` does not panic on arbitrary input; on success the returned keypair reports the algorithm we asked for. (`Err` is allowed — some algorithms legitimately reject cryptographically-bad seeds.) |
| `key_parsing`             | `SecretKey::try_from_slice` rejects all wrong-length input cleanly; on success the returned key carries the requested algorithm tag. |
| `signature_parsing`       | `Signature::try_from_slice` does not panic on arbitrary bytes for any algorithm. |
| `sign_verify`             | A signature produced by `sign` always verifies under the matching public key, and the resulting signature carries the algorithm we signed under. |
| `cross_algorithm`         | Signatures from one algorithm do not verify under public keys from another, including when the algorithm tag is mismatched against the byte payload. |
| `determinism`             | `generate_keypair` is deterministic in its seed: calling it twice with byte-identical seeds produces byte-identical public-key and secret-key bytes, and the algorithm tag round-trips on the returned keypair. Catches RNG/seed-routing regressions where keygen would silently mix in non-deterministic state. |
| `verify_robustness`       | `verify` does not panic on garbage input — neither on a real public key paired with random signature bytes, nor on a random public key paired with a real signature, nor on both random. |
| `sig_substitution`        | A signature whose payload was produced under algorithm A but whose tag claims algorithm B is rejected by `verify`, regardless of which public key it is paired with. Closes the algorithm-confusion class. |
| `structured_parsing`      | Parses `PublicKey`, `SecretKey`, and `Signature` under both length-correct and length-mismatched scenarios across all algorithms; algorithm tag round-trips through any successful parse. Driven by an `arbitrary`-derived enum so the fuzzer hits each parse path on purpose rather than by chance. |

## Running the Fuzz Tests

To run a specific fuzz target:

```bash
cargo +nightly fuzz run keypair_generation
cargo +nightly fuzz run key_parsing
cargo +nightly fuzz run signature_parsing
cargo +nightly fuzz run sign_verify
cargo +nightly fuzz run cross_algorithm
cargo +nightly fuzz run determinism
cargo +nightly fuzz run verify_robustness
cargo +nightly fuzz run sig_substitution
cargo +nightly fuzz run structured_parsing
```

Or run all of them in parallel (one job per CPU core) with `run_all_fuzzers.sh`. The script requires GNU `parallel`.

To stop a fuzz run early use `-max_total_time=N` (seconds):

```bash
cargo +nightly fuzz run determinism -- -max_total_time=60
```

Crashes are persisted under `artifacts/<target>/`. To reproduce a saved
crash:

```bash
cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>
```

## CI

These harnesses are not currently exercised by any of the repository's
`workflow_dispatch`-only CI workflows. A future improvement is to add a
fuzz-build job that runs `cargo +nightly fuzz build` on every PR touching
`src/libbitcoinpqc/`, so future API drift cannot bit-rot the harnesses
silently. Until that lands, run the build manually before merging changes
to the `bitcoinpqc` crate API.
