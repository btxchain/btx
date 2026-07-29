> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# BTX MatMul Nonce-Bound Seed V2

Date: 2026-06-07
Branch: `audit/v2-rebalance-pool-credit-probe`
Activation: height `125000`

## Summary

This branch closes the e1 MatMul-PoW amortization issue for blocks at and above height
`125000`.

Before this rule, MatMul matrix seeds were derived as:

```text
H(prev_block_hash || height || which)
```

That made the expensive A/B matrix instance fixed across all nonce attempts for one parent
and height. The issue was economic rather than a shielded inflation bug, but it meant a miner
could amortize the generated instance across many mutable header attempts. That is different
from ordinary acceleration: making each required MatMul cheaper with better CPU/GPU code is
valid, while reusing one consensus work instance across many nonce attempts underprices the
intended work.

At and after `nMatMulNonceSeedHeight`, seeds are derived as:

```text
H("BTX_MATMUL_SEED_V2" || prev || height || version || merkle ||
  time || bits || nonce64 || matmul_dim || which)
```

This binds the instance to the mutable header and especially to `nNonce64`. Changing the nonce,
timestamp, merkle root, target bits, version, or dimension changes A/B.

## Consensus And Mining Changes

- `Consensus::Params::nMatMulNonceSeedHeight` is set to `125000` on mainnet, testnet,
  testnet4, and signet.
- Regtest has `-regtestmatmulnonceseedheight=<n>` for activation-boundary testing.
- `SetDeterministicMatMulSeeds(...)` selects the legacy derivation before activation and seed-v2
  at/after activation.
- Contextual block validation recomputes the expected seeds from the submitted header and
  rejects mismatches as `bad-matmul-seeds`.
- The post-activation solver uses a nonce-by-nonce path. It derives fresh seeds, A/B, sigma,
  digest input, and optional Freivalds payload for every attempted nonce.
- Metal and CUDA remain digest/matrix acceleration backends, not consensus seed-derivation engines.
  After activation, accelerated backends must carry candidate-specific `seed_a` and `seed_b` through
  the batch path so backend base-matrix caches cannot reuse a stale fixed instance across nonce
  attempts.
- The post-activation safety rule forbids shared-A/B nonce windows. It does not forbid GPU
  optimization that batches multiple nonce attempts while carrying distinct A/B for every attempt.
  CUDA and Metal now have nonce-seed-specific GPU scan and variable-base digest batch paths for this
  case; CPU and unsupported/fallback backends remain on the conservative nonce-by-nonce path.
- On Apple builds the Metal backend still builds by default, and macOS source builds again precompile
  MatMul/oracle kernels into `.metallib` files first with embedded source compilation only as fallback.
- RPC mining/work-profile reporting now marks fixed-instance reuse as unavailable when the
  consensus nonce-seed upgrade is active.

## Boundary Safety

The rule is deliberately height-gated rather than retroactive. Blocks below `125000` keep the
historical seed contract. Blocks at and above `125000` must satisfy seed-v2.

As of the local mainnet node check on 2026-06-07, mainnet was at height `122920`, so the
activation remained in the future. If mainnet reaches `125000` before this release is broadly
deployed, do not ship this exact activation unchanged; reassess the height first.

## Tests

Focused coverage added in this branch:

- `pow_tests/MatMulNonceSeedV2_binds_mutable_header_fields`
- `pow_tests/MatMulNonceSeed_activation_boundary_selects_legacy_then_v2`
- `pow_tests/MatMulNonceSeed_solver_mines_and_verifies_at_activation_boundary`
- `pow_tests/MatMulNonceSeed_solver_disables_shared_base_matrix_batching`
- `pow_tests/ChainParams_REGTEST_matmul_activation_override_options`
- `pow_tests/ChainParams_REGTEST_matmul_activation_override_args`
- `matmul_params_tests/matmul_params_defaults_mainnet`

The local `test_btx` target builds, and the focused MatMul nonce-seed tests pass.
