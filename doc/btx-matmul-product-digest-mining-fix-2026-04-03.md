# BTX MatMul Product-Digest Mining Fix

**Status**: Active fix document for the post-`61000` mining/validation contract
**Date**: 2026-04-03
**Branch**: `codex/fix-product-digest-mining-contract`

## Summary

The `60999 -> 61000` stall was caused by a consensus/mining contract mismatch.
At `nMatMulProductDigestHeight`, validation switched to the
**product-committed digest**, but the mining pipeline was still screening
nonces using the legacy **transcript digest**. Those digests are not
interchangeable. A nonce that satisfies one digest target does not, in
general, satisfy the other.

The correct fix is to make the mining backend target the same digest the
validator enforces at the activation height, while keeping the nonce-scanning
path on a compressed O(n^2) representation instead of rehashing the full
product matrix per candidate. This branch does that without rewriting
historical chain difficulty or adding a permanent O(n^3)-per-nonce fallback.

## What Actually Went Wrong

Two different issues were discovered during the post-`61000` review:

1. **Historical mainnet PoW schedule was accidentally rewritten**
   A PR 139 commit (`b312b082`, "Adjust BTX activation thresholds to 61,000")
   moved historical mainnet PoW transition values that should have remained at
   `50000`. That produced header-history and chainwork mismatches against the
   live network. This was already corrected separately by PR 140 and is not the
   bug fixed in this branch.

2. **The miner and validator used different digests at `61000`**
   The original product-digest rollout commit (`00556e7d`,
   "consensus: product-committed digest for O(n^2) block validation")
   correctly taught validation to enforce the product-committed digest, but the
   nonce scanning path in `SolveMatMul()` kept screening candidates on the
   transcript digest. On regtest this often went unnoticed because the target is
   so easy that either digest can pass immediately. On mainnet the mismatch made
   accepted solutions effectively vanish.

## Why PR 154 Was Not The Right Fix

PR 154 correctly identified that the miner eventually needed the
post-activation digest, but it fixed the problem by recomputing the full
canonical product path for **every nonce** inside `SolveMatMul()`.

That would have unblocked consensus at the cost of turning post-activation
mining into a permanent O(n^3)-per-nonce slow path, even on Metal-capable
systems. It also would not have established a clean backend contract for CPU,
Metal, batch submission, or future accelerators.

The proper long-term fix is to keep the post-activation digest aligned between
miners and validators while basing it on data both sides can derive in O(n^2).

## Why We Did Not Pivot To A Coinbase Commitment Fork

During the incident response, a tempting alternative was:

- keep mining on the legacy fast transcript digest
- bind `C'` separately through a coinbase / merkle commitment
- let validators check Freivalds plus that commitment

That sounds cleaner at first, but BTX's existing sigma derivation makes it a
much larger redesign than the emergency required.

Today sigma is derived from the block header **including `hashMerkleRoot`** and
excluding only `matmul_digest`:

`sigma = SHA256(header_without_matmul_digest)`

Because `hashMerkleRoot` is already part of sigma, a design that commits `C'`
through the coinbase transaction creates a circular dependency:

- coinbase would commit to `C'`
- merkle root would commit to coinbase
- sigma would depend on merkle root
- `A'`, `B'`, and therefore `C'` would depend on sigma

So the miner would need `C'` in order to finalize the merkle root, while also
needing the merkle root in order to derive the sigma that determines `C'`.

That circularity can be solved, but only by a broader consensus redesign, for
example:

- changing sigma derivation so it no longer commits to the merkle root, or
- introducing a separate non-circular header commitment structure, or
- using a more complex fixed-point / two-stage template protocol

Any of those would be a new fork design, not a simple correction of the broken
`61000` activation. For the live chain-rescue incident, the compressed-final-
block digest was the smallest correct fix that:

- removed the miner / validator mismatch
- preserved high-throughput nonce scanning
- avoided rewriting historical chain behavior
- and worked on the already-stalled live chain immediately

## Root Cause Detail

Before this branch:

- pre-activation miners scanned `transcript_hash <= target`
- post-activation validators enforced a different digest on the carried `C'`
  payload

Those were different hashes over different serialized material, so the old
post-activation miner was effectively solving the wrong proof of work.

The discarded PR 154 follow-up exposed a second design failure: directly
hashing the full `C'` matrix per nonce restores correctness, but collapses
throughput because candidate screening degenerates into near-canonical product
work.

## What This Branch Changes

### Digest contract

- Adds an explicit `DigestScheme` to the accelerated solver interface:
  - `TRANSCRIPT`
  - `PRODUCT_COMMITTED`
- Selects the scheme by height inside `SolveMatMul()`
  - `< 61000`: transcript digest
  - `>= 61000`: compressed-final-block product digest

### Post-61000 digest definition

At and above `61000`, the digest is now computed as:

- derive the compression vector from `sigma`
- compress each final `b x b` block of `C'`
- hash that `N x N` compressed image
- finalize with `sigma`, `dim`, and `b`

In code:

`SHA256d(PRODUCT_DIGEST_TAG || sigma || H(compressed_final_blocks(C')) || dim_le32 || b_le32)`

This keeps the PoW bound to the carried `C'` payload, but removes the need to
hash the full `n x n` matrix for every nonce candidate.

### Backend behavior

- CPU direct, prepared, and batched digest paths now support both schemes
- Metal single and batched digest submission paths now support both schemes
- Product-digest mode on Metal now reuses the same optimized
  `fused_prefix_compress` path as transcript mining and hashes only the
  `ell = N - 1` final-block slice of that compressed stream
- The new `product_compressed_sha256` kernel proves the product-committed
  digest can be derived from the final `N x N` slice of the transcript
  compression stream rather than from a separate slow-path kernel
- Validators rebuild the same compressed final block image from the carried `C'`
  payload, then run Freivalds to confirm `A' * B' == C'`
- Winning candidates only pay the full canonical recomputation cost when it is
  actually needed for:
  - CPU confirmation, or
  - Freivalds payload materialization

This preserves the main performance goal of the original optimization: the
mining path stays aligned with consensus without degenerating into the PR 154
slow path.

## Why Existing Tests Missed It

The original rollout tests were useful, but they did not assert the most
important contract:

1. Functional activation tests used regtest-style easy targets
   At minimum difficulty, a nonce can satisfy the product digest immediately, so
   a miner that is still screening on transcript digest may appear to work.

2. There was no explicit boundary proof for `60999 -> 61000`
   The suite did not include a case where:
   - `product_digest <= target`
   - `transcript_digest > target`

3. There was no backend parity coverage for product-digest mode
   CPU and Metal parity existed for transcript digest paths, but not for the
   post-activation product-digest contract.

4. Historical schedule and future schedule bugs were initially mixed together
   That made it too easy to treat the `61000` mining failure as a generic
   activation problem instead of a specific digest-contract bug.

## New Regression Coverage

This branch adds the checks that were missing:

- `pow_tests`
  - explicit `60999 -> 61000` solver boundary test
  - proves the winning `61000` nonce satisfies the product digest while failing
    the transcript digest target check
- `matmul_accelerated_solver_tests`
  - transcript and product digest parity for CPU direct, prepared, and batched
    paths
- `matmul_metal_tests`
  - transcript and product digest parity for Metal single and batched paths
- `matmul_transcript_tests`
  - proves the product digest is exactly the hash of the final-`ell` slice of
    the transcript compression stream
- `feature_matmul_61000_boundary.py`
  - short-height end-to-end activation test for payload rejection, activation,
    and post-activation mining continuation
- `feature_btx_matmul_consensus.py`
  - end-to-end activation and payload-requirement validation
- `feature_matmul_activation_rehearsal.py`
  - activation guard and work-profile rehearsal

## Performance Validation

Local tuned-profile checks on this branch show the post-activation contract
stays in the same throughput class on this Apple Silicon mining box instead of
falling into the double- or triple-digit NPS collapse seen in the discarded
full-`C'` design:

- tuned solve bench (`n=512`, `b=16`, `r=8`, 8 solver threads, 8 pool slots,
  5 prepare workers, 10x2048 tries)
  - height `60999`: about `87.6k` mean NPS
  - height `61000`: about `82.2k` mean NPS
- isolated Metal digest bench (`n=512`, `b=16`, `r=8`, 6-way parallel, 6 pool
  slots, 4 measured iterations)
  - transcript digest: about `340` digests/s mean request rate
  - product digest: about `192` digests/s mean request rate

Those numbers are still host-specific, but the critical result is that the live
post-`61000` solve path remains in the historical tens-of-thousands NPS regime.
The remaining isolated product-digest gap is a backend optimization question,
not the catastrophic chain-stall failure that originally blocked `61000`.

## Live Mainnet Proof

The fix is not just unit-test clean. It has already been used against the real
stalled mainnet datadir on this machine.

- The patched daemon reopened the live chain at height `60999`
- It mined the activation block `61000`:
  `ae9c6bf1f991ee564869cee52ef894de25c1dcb537638ed2926cc0a0ec7e3844`
- It then mined `61001`:
  `5cfb1931ad2ad87f31a3e821fd65441dd861e5e7f3b65374ecb041f139af478c`
- It then mined `61002`:
  `4f85fd0a4d32100d41590b239e53c07159da95d04a187534e2844e77c41ba2c5`
- All three blocks paid to the `b-raben` wallet address:
  `btx1zzp0acsm07xe56xu630m6522zt8x7typ8x6dd7hf8s0tf4euw8vhsrgf9w0`

That live run is the strongest evidence that this branch fixes the actual
failure mode rather than just constructing a synthetic local pass.

## Relationship To PRs 134 / 137 / 138 / 139

- **PR 134**: shielded hardening and related validation work. Not the source of
  the mining digest mismatch.
- **PR 137**: mining chain guard and solo connectivity hardening. Not the source
  of the digest mismatch.
- **PR 138**: PQ multisig and key-management work. Not related to MatMul mining.
- **PR 139**: introduced the product-digest activation work. This is where the
  mining/validation digest mismatch originated, and where the accidental
  historical `50000 -> 61000` PoW schedule rewrite also appeared.

## Operator Notes

- Historical mainnet PoW transitions remain frozen at `50000`
- New post-launch hardening activations remain at `61000`
- Existing blocks, headers, and mainnet history are not rewritten by this fix
- Existing miners must run code that targets the product digest at and above
  `61000`

## Validation Run For This Branch

Local validation for this branch included:

- `test_btx --run_test=matmul_accelerated_solver_tests`
- `test_btx --run_test=matmul_metal_tests`
- `test_btx --run_test=matmul_transcript_tests`
- `test_btx --run_test=matmul_params_tests`
- `test_btx --run_test=pow_tests`
- `feature_btx_matmul_consensus.py`
- `feature_matmul_activation_rehearsal.py`
- `feature_matmul_61000_boundary.py`

Additional local benchmark validation:

- `BTX_MATMUL_BACKEND=cpu ./build_codex_merge/bin/btx-matmul-solve-bench --iterations 4 --tries 4096 --n 512 --b 16 --r 8 --parallel 1`
- `BTX_MATMUL_BACKEND=cpu ./build_codex_merge/bin/btx-matmul-solve-bench --iterations 4 --tries 4096 --n 512 --b 16 --r 8 --parallel 1 --block-height 61000`
- `BTX_MATMUL_BACKEND=metal ./build_codex_metal_ready/bin/btx-matmul-solve-bench --iterations 4 --tries 4096 --n 512 --b 16 --r 8 --parallel 1`
- `BTX_MATMUL_BACKEND=metal ./build_codex_metal_ready/bin/btx-matmul-solve-bench --iterations 4 --tries 4096 --n 512 --b 16 --r 8 --parallel 1 --block-height 61000`
- `./build_codex_metal_ready/bin/btx-matmul-metal-bench --digest-mode transcript`
- `./build_codex_metal_ready/bin/btx-matmul-metal-bench --digest-mode product`

The boundary-specific acceptance criterion is now explicit:

> if the code cannot cross `60999 -> 61000`, it is not fixed
