# Fuzz Testing for libbitcoinpqc

This directory contains fuzz testing for the libbitcoinpqc library using
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Prerequisites

You need a nightly Rust toolchain (cargo-fuzz uses unstable compiler
flags for libFuzzer integration) and the `cargo-fuzz` subcommand. The
repository pins specific versions of both so local results match CI:

```
rustup toolchain install nightly-2026-05-01
cargo +nightly-2026-05-01 install cargo-fuzz --locked --version 0.13.1
```

Or, equivalently, from this directory:

```
make fuzz-toolchain
```

Linux developers can install the system build deps that the workflow
installs with:

```
make fuzz-deps-linux
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
| `verify_robustness`       | `verify` rejects arbitrary correct-length garbage wrapper payloads without panicking: a real public key paired with random signature bytes, a random public key paired with a real signature, or both random. |
| `sig_substitution`        | A signature whose payload was produced under algorithm A but whose tag claims algorithm B is rejected by `verify`, regardless of which public key it is paired with. This primarily hardens the Rust wrapper API surface against algorithm-tag confusion. |
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

Or run all of them in parallel (one job per CPU core) with `run_all_fuzzers.sh`. The script requires GNU `parallel` and invokes `cargo +nightly fuzz run` for each target.

To stop a fuzz run early use `-max_total_time=N` (seconds):

```bash
cargo +nightly fuzz run determinism -- -max_total_time=60
```

Crashes are persisted under `artifacts/<target>/`. To reproduce a saved
crash:

```bash
cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>
```

## Pre-merge smoke check (`make fuzz-smoke`)

The `Makefile` in this directory wraps the same recipe as
`.github/workflows/libbitcoinpqc-fuzz.yml`, so the workflow's checks
can be run locally with one command:

```
cd src/libbitcoinpqc/fuzz
make fuzz-smoke
```

This runs:

1. `cargo +nightly-2026-05-01 fuzz build`
2. Generates the deterministic `verify_robustness/secp_smoke` seed
3. `cargo +nightly fuzz run verify_robustness corpus/verify_robustness/secp_smoke`
4. `cargo +nightly fuzz run <target> -- -max_total_time=1` for each of the
   eight other targets in turn

It's the same byte-for-byte recipe the workflow encodes — pinned
nightly, pinned `cargo-fuzz`, same target order, same seed, same smoke
time — so a green local run is equivalent to a green CI run.

**For PRs touching `src/libbitcoinpqc/**`** — please include a pasted
`make fuzz-smoke` log in the PR description. The workflow YAML is the
versioned recipe; the local invocation is the enforcement.

## CI

`.github/workflows/libbitcoinpqc-fuzz.yml` defines a workflow that runs
the same `make fuzz-smoke` recipe on Linux runners. It is path-filtered
to trigger on PRs and pushes touching `.github/workflows/libbitcoinpqc-fuzz.yml`
or `src/libbitcoinpqc/**`. Whether or not GitHub-hosted runners are
active on this repository at any given time, the workflow YAML stays
in-tree as a versioned, executable recipe — `make fuzz-smoke` is the
local equivalent.
