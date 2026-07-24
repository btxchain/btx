> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# MatMul v3 / v0.32.11 Engineering Decision Record

Status: accepted for the v0.32.11 posture. This is a decision record, not a
replacement for the consensus specification in `doc/btx-matmul-pow-spec.md`.

## Decision

BTX keeps MatMul v3 as the canonical proof-of-work posture for v0.32.11. The
accepted `.11` hardening is narrow: preserve the existing MatMul v3 field,
dimension, transcript, product-digest, pre-hash gate, and validation model, while
closing the remaining template-precomputation gap with parent-MTP-bound seed v3.

At and above `nMatMulParentMtpSeedHeight` (mainline height `130500`), deterministic
matrix seeds are:

```text
sha256("BTX_MATMUL_SEED_V3" ||
       prev_block_hash ||
       parent_median_time_past ||
       height ||
       version ||
       merkle_root ||
       time ||
       bits ||
       nonce64 ||
       matmul_dim ||
       which)
```

Seed v3 supersedes seed v2 only from its activation height forward. Historical
blocks and pre-activation replay keep their already-defined derivation rules.
Mining and verification paths must fail closed when seed v3 is active but the
parent MTP context is unavailable.

## Accepted .11 Changes

- Parent-MTP seed binding is accepted as the canonical `.11` consensus hardening.
  It prevents one prepared template from being reused across alternate withheld
  parents while keeping the rule deterministic from committed parent context.
- CUDA and Metal nonce-seed pre-hash scans may support seed versions 2 and 3, but
  consensus remains the CPU-defined seed/digest contract. GPU paths must match
  CPU gate results or fall back/fail visibly.
- `getmatmulchallenge` work-profile metadata should report the active seed scope
  as `per_nonce_header_parent_mtp`, with no fixed instance reuse and no "winner
  knows next seeds first" assumption once seed v3 is active. It should separately
  disclose that a miner who withholds a valid parent can privately mine
  descendants until publication, which is standard proof-of-work selfish-mining
  surface rather than a public/template precomputation channel.
- Benchmark tooling may expose seed-v3 inputs, including parent MTP, so accepted
  measurements can be reproduced under the same height, seed version, epsilon,
  backend, and device conditions.
- MatMul service-challenge RPCs are accepted as application-side admission-control
  tools with local/shared replay registries. They are not block consensus, not
  fork-choice policy, and not a settlement-finality mechanism.

## Deferred Or Rejected v4 Ideas

No MatMul v4 consensus change is accepted in v0.32.11. The following remain
experimental until a later EDR and activation plan accept them explicitly:

- changing the MatMul field, dimension, transcript ordering, noise rank, digest
  rule, or validation model;
- arbitrary external-work / data-availability PoUW inputs;
- CUDA-only, Metal-only, or other hardware-specific consensus behavior;
- service-challenge proofs as mining shares, identity proofs, P2P admission, or
  chain finality;
- external finality feeds or service-specific anchors that influence BTX
  consensus or automatic fork choice;
- CUDA graphs, aggressive kernel layout rewrites, or larger-GPU heuristics as
  mandatory behavior rather than measured backend optimizations.

Experimental alternatives may be benchmarked and documented, but they do not
change what nodes accept as valid blocks.

## CUDA CI Requirement

CUDA changes that affect MatMul v3 mining, seed-v3 pre-hash scanning, or CUDA
benchmark claims require a real NVIDIA Linux lane, not CPU-only CI. The lane must:

- run on a self-hosted NVIDIA host with `nvidia-smi`, `nvcc`, and
  `BTX_CUDA_ARCHITECTURES` set;
- configure with `BTX_ENABLE_CUDA_EXPERIMENTAL=ON`, `BUILD_TESTS=ON`,
  `BUILD_UTIL=ON`, and `BUILD_BENCH=ON`;
- force CUDA selection during validation with `BTX_MATMUL_BACKEND=cuda`,
  `BTX_MATMUL_REQUIRE_BACKEND=cuda`, and the intended `BTX_MATMUL_CUDA_DEVICES`;
- run `scripts/ci/run_cuda_matmul_v3.sh` or an equivalent lane that captures
  backend info, `MatMulNonceSeed_cuda_prehash_scan_matches_cpu_gate`,
  `MatMulParentMtpSeed_cuda_prehash_scan_matches_cpu_gate`, strict CUDA solver
  regressions, `matmul_accelerated_solver_tests`, and seed-v3 solve/cost bench
  artifacts.

CPU and Metal tests remain required for general validation, but they do not
establish CUDA correctness or performance.

## Service-Challenge Decision

Service challenges use MatMul as a reusable cost primitive for API gating,
rate-limiting, agent admission, and similar application workflows. The accepted
posture is operational:

- challenges are domain-bound and replay-protected by redemption state;
- shared registry files may be used by service clusters;
- verification may be local, shared-registry-backed, or stateless depending on
  the caller's policy;
- successful redemption proves only that the submitted challenge met its target.

They must not be described as BTX finality, miner authorization, Sybil immunity,
identity, account ownership, or consensus participation.

`matmul_service_challenge_v1` remains compatible in `.11`, but it is not the
final adversarial service-gate shape. Its seeds are fixed per challenge, so a
solver can amortize A/B generation across nonce attempts inside one service
challenge. That is an off-chain admission-control economics gap, not a block
consensus flaw.

A later additive `matmul_service_challenge_v2` should use a new domain such as
`BTX_MATMUL_SERVICE_V2`, keep the challenge id nonce-independent for registry
and redemption identity, and derive proof seeds as:

```text
sha256("BTX_MATMUL_SERVICE_V2" ||
       "seed" ||
       challenge_id ||
       anchor_hash ||
       nonce64 ||
       label)
```

The v2 envelope should report `seed_derivation_scope =
per_service_challenge_nonce` and `fixed_instance_reuse_possible = false`. It
should be opt-in first; flipping the default would break existing service
solvers, examples, and issued v1 challenge semantics.

## Benchmark Interpretation

MatMul v3 benchmarks are hardware- and profile-specific engineering evidence.
Interpret them with the exact parameters attached: `n`, `b`, `r`, height, seed
version, parent MTP, epsilon bits, backend, device, attempts, thermal state, and
fallback policy.

Small median differences are not product claims. A CUDA or Metal number is not a
universal GPU number. A service-challenge solve target is an operator budget, not
network hashrate. The pre-hash gate reduces expensive MatMul invocations before
the final digest check; it does not replace the final proof-of-work target.

The repeatable red-team cost matrix is:

```sh
scripts/ci/run_matmul_v3_experiment_matrix.sh
```

That matrix records canonical v3 plus deferred variants such as smaller
dimensions, larger transcript block sizes, disabled pre-hash gating, and higher
noise rank. Only the canonical v3 case is a release guardrail; the other cases
exist to show which experimental knobs shift cost toward SHA/matrix expansion or
away from product-digest work.

## Claims We Must Not Make

Do not claim:

- "final ASIC-resistant";
- "ASIC-proof";
- "supersedes all public research";
- "proves useful work for arbitrary external workloads" for the canonical v3
  chain rule;
- "CUDA validated" unless the CUDA hardware lane passed;
- "service challenges provide finality" or "service challenges are consensus";
- "v4 is accepted" without a later EDR and activation plan.

The defensible claim is narrower: v0.32.11 keeps MatMul v3 canonical, adds
parent-MTP seed binding as forward-only hardening, and leaves broader v4 ideas
experimental.
