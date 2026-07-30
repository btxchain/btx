# MatMul v4.7 Profile 1 ExactReplay launch candidate

Status: local implementation and measurement candidate. This document is not
an activation recommendation. The canonical four-epoch transition and naming
rules are defined in
[`btx-matmul-v4.7-transition-roadmap.md`](btx-matmul-v4.7-transition-roadmap.md).

## Architecture decision

This document covers **Epoch A** of MatMul v4.7. The viable interim design
is Profile 1 with epsilon-zero ExactReplay:

- four sequential rounds;
- 16 FFN layers;
- `b_seq=16,384`;
- `T_leaf=1,024`; and
- one complete, header-derived replay before chainwork is authenticated.

Profile 2 remains the **Epoch D** datacenter-scale future workload: eight rounds, 24
layers, `b_seq=87,552`, and `T_leaf=4,096`. A measured single M4 Max needs
443.438 seconds to replay Profile 2, so it is not a 90-second-block
ExactReplay launch candidate. Profile 2 should become authoritative only with
a completed succinct proof system (or separately proven multi-host verifier),
not by silently requiring every validator to own a large Metal fleet.

The current source selects Profile 1 as the pre-activation default while every
public activation height remains disabled. Profile 2 stays explicitly
selectable for later-epoch regression measurements; it is not inherited into
Epoch A.

Merging this implementation activates nothing. A later activation PR must set
`nMatMulV4Height`, `nMatMulBMX4CHeight`, and `nMatMulRCHeight` to one identical
`H_A`. DRLT and coupled RC remain disabled; Profile 1 and production dimensions
remain selected; unfinished Stage-3 proof authority and HeaderPoW remain off.
The v4 and BMX4C ASERT ratios remain inert at `1/1`, while the live RC branch
owns the independently measured one-time v3-to-Epoch-A calibration. Explicit
L0 ratification is a separate requirement and is not implied by merging,
benchmarking, or setting a height.

Round `r` is derived from round `r-1`'s root, so rounds are not sampled or run
concurrently. The serialized block header remains 182 bytes and commits only
`matmul_digest`. Switching later from replay authority to a succinct proof
therefore does not change the work statement or add witness bytes to every
historical block.

Epochs B–D cannot be reached by flipping the current global Stage-3 readiness
value or changing `nMatMulRCProfile` in place. They require future,
height-versioned proof-required, proof-authority, and Profile-2 selectors so
historical Epoch-A blocks always retain their original workload and validity
rules.

## M4 Max loaded result

The corrected campaign used production-shaped headers with
`matmul_dim=4096`, 100 distinct nonces, one continuously saturated device
submitter, and no cooldown:

| Metric | Result |
|---|---:|
| Mean | 28.171553715 s |
| Nearest-rank p50 | 28.168290875 s |
| Nearest-rank p95 | 28.202504625 s |
| Nearest-rank p99 | **28.210448250 s** |
| Maximum | 28.362590458 s |
| Worst adjacent pair | **56.495303916 s** |
| Queue wait at 90-second arrivals | **0 s** |
| Ending queued work | **0 s** |
| Peak RSS | 6,972,688 KiB |

All 100 digests were distinct and 51 met the easy campaign target. The exact
14,114,980,521,574,400 expected MACs ran on Metal with
`full_metal_pipeline=true`; CPU calls and fallbacks were zero.

The actual consensus worker then accepted two valid golden winners queued with
zero arrival gap in 56.439502250 seconds total. In a three-branch reorg, two
stale jobs were canceled, the in-flight replay stopped in 0.023179917 seconds,
and a distinct valid canonical winner completed 28.101862542 seconds after the
tip change.

Raw evidence and reproduction commands are in
`doc/evidence/m4-max-profile1-loaded-2026-07-30/`.

## CUDA Blackwell-class loaded result

An independent Linux CUDA campaign on a sanitized Blackwell-class 16 GiB
consumer GPU (Xeon W-class host, 76 GiB RAM) measured 100 distinct
`matmul_dim=4096` production headers:

| Metric | Result |
|---|---:|
| Mean | 21.244 s |
| p50 | 21.240 s |
| p95 | 21.335 s |
| p99 | **21.386 s** |
| Maximum | 21.402 s |
| MACs / episode | 141,149,805,215,744 |
| CPU GEMM fallbacks | **0** |

Device path detail:
`cuda_resident_ffn_chain+triple_stream+persistent_ws`. Versus a 90-second
block interval the p99 occupies ~23.8% (~68.6 s headroom). Sanitized evidence:
`doc/evidence/cuda-blackwell-16gib-profile1-loaded-2026-07-30/`.

## Full-Metal requirement

A result is called `full_metal_pipeline` only when self-qualification and run
telemetry establish all of the following:

1. consensus operand SHA-XOF blocks execute on Metal and match the portable
   byte oracle;
2. Phase-1 and Phase-2 exact integer contractions execute on Metal;
3. both ExtractMX stages execute on Metal;
4. the complete 16-layer FFN chain remains device-resident, with immutable
   buffers reused and command buffers batched;
5. consensus 1,024-byte Merkle leaves and every subtree level are processed on
   Metal; and
6. no consensus MAC falls back to the CPU.

Normal consensus validation remains deterministic on the portable oracle when
an accelerator is unavailable. A device digest mismatch triggers a portable
retry before permanent rejection or peer punishment. That retry is a safety
path, not a viable routine validator path at production dimensions.

## Admission and near-tip policy

`rcadmit` is a 40-byte P2P-only sidecar containing the block hash and a 64-bit
nonce. It uses Poseidon2-GL12 over
`BTX_RC_ADMIT_P2_V1 || block_hash || nonce_le64`; it adds no blockchain bytes
and does not rent SHA256 ASIC capacity.

The policy target is explicit:

```text
raw = DecodeCompact(nBits) << 48
target = clamp(raw, target_for_20_bits, target_for_12_bits)
```

Tickets expire after 180 seconds, are single-use, and are bounded to four
pending entries per keyed netgroup and 256 node-wide. They are admission
policy, not consensus.

The verifier scheduler deduplicates a hash, joins a later full block to an
already-running header job, reserves priority for a direct child of the
authenticated tip, and cancels stale speculative work. A candidate receives
no validity, chainwork, fork-choice influence, or permission to mine on it
until ExactReplay succeeds.

## IBD and historical verification

Header-first speculation is disabled during IBD. Checkpoints remain
load-bearing for launch-era historical sync; near-tip performance does not
make checkpointed history trustless. The forward-compatible claim is narrower:
the statement is header-derived, so historical succinct proofs can be
backfilled later without miner cooperation or missing witness data.

Because `rcadmit` tickets are ephemeral relay policy, a node cannot require
the original ticket while fetching a historical block it explicitly requested
during IBD. That requested-body path bypasses only the ticket: it remains
subject to pending/global work budgets, still performs ExactReplay, and
receives no authenticated chainwork before ExactReplay succeeds. Unsolicited
IBD bodies continue to require admission. Peers also retain a bounded cache of
recent valid tickets and resend a matching ticket before a requested block, so
the near-tip handoff out of IBD does not depend on an expired relay timestamp
or make the serving node grind on demand.

Removing the checkpoint trust window requires a frozen proof format, completed
proof backfill, and sync verification of those proofs.

## Acceptance gate

Measured on this M4 Max:

- [x] Profile 1 loaded p99 is within the 25–30 second target.
- [x] Two zero-gap valid blocks drain inside one 90-second interval.
- [x] Three-branch reorg and stale-job cancellation remain bounded.
- [x] Full-Metal telemetry covers every consensus MAC with no CPU fallback.
- [x] Production headers bind `matmul_dim=4096`; the real consensus predicate,
  target check, verdict memo, and worker completion path accept the goldens.

Independent CUDA class (sanitized; see
[`doc/evidence/cuda-blackwell-16gib-profile1-loaded-2026-07-30/`](evidence/cuda-blackwell-16gib-profile1-loaded-2026-07-30/)):

- [x] Profile 1 loaded p99 **21.386 s** on a Blackwell-class 16 GiB NVIDIA
  discrete GPU (Linux x86_64, Xeon W-class host, 76 GiB RAM).
- [x] 100 distinct `matmul_dim=4096` headers / digests; zero CPU GEMM fallbacks.
- [x] CUDA ExactReplay attached via the Metal-parity `ExactGemmBackend`
  Launch* ABI (`rc_fused_ffn`, `rc_fused_ffn_chain`, `rc_phase1`).

Still required before activation:

- [ ] portable and independent Metal machines match the corrected golden
  vectors;
- [ ] invalid ticketed candidates cannot starve the authenticated-tip lane
  under sustained admission load;
- [ ] device mismatch retry is exercised and deterministic on a deliberately
  faulted device result;
- [ ] block/header serialization and `rcadmit` no-chain-byte invariants are
  rechecked in the final candidate build;
- [ ] checkpoint and IBD trust-window disclosures are frozen;
- [x] the disabled pre-activation consensus selector is Profile 1, with a
  construction invariant and regression coverage.
- [x] the disabled merge state and atomic Epoch-A tuple are construction
  invariants: equal v4/BMX4C/RC heights, withdrawn paths off, HeaderPoW off,
  v4/BMX4C ASERT inert, and RC as the sole calibrated branch.

Profile 1 now passes the three requested performance gates on the measured
Metal host, with corroborating CUDA loaded p99 well inside the 90-second
interval on a sanitized Blackwell-class validator class. Activation remains a
no-go until the remaining consensus, cross-machine, DoS, and IBD gates are
closed.
