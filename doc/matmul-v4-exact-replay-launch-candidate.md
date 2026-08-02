# MatMul v4.7 Profile 1 ExactReplay launch candidate

Status: launch-candidate gate record for Epoch A. **Epoch A has since been
activated on mainnet at block height 181'894** (`src/kernel/chainparams.cpp`);
the gate checklists below are annotated with what the committed activation
evidence closed and what was accepted as residual risk. The canonical
four-epoch transition and naming rules are defined in
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

The current source selects Profile 1 and sets the mainnet activation tuple:
`nMatMulV4Height = nMatMulBMX4CHeight = nMatMulRCHeight = 181'894`. Testnet
and signet heights remain disabled. Profile 2 stays explicitly selectable for
later-epoch regression measurements; it is not inherited into Epoch A.

The activation satisfied the atomic-tuple contract this document required:
one identical `H_A` (181'894) across the three heights; DRLT and coupled RC
disabled; Profile 1 and production dimensions selected; unfinished Stage-3
proof authority and HeaderPoW off. The v4 and BMX4C ASERT ratios remain
inert at `1/1`, while the live RC branch owns the installed one-time
v3-to-Epoch-A calibration (`4294967295/1`, the saturated uint32 ceiling of
the measured two-rig ratio — see `kRCEpochAAsertRescaleNum` in
`src/kernel/chainparams.cpp`). Explicit L0 ratification was recorded as the
flip of `BTX_MATMUL_NO_INVERSION_GATE_RATIFIED` and
`BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED` to true, with the basis and the
accepted residual risk documented at those flags (`src/consensus/params.h`).

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
zero arrival gap in 56.407940500 seconds total. A valid-ticket invalid-candidate
flood was preempted in 1.528641959 seconds and the honest verdict completed
30.207028375 seconds after the flood began, with no invalid completion or peer
punishment. In a three-branch reorg, two stale jobs were canceled, the
in-flight replay stopped in 1.566106083 seconds, and a distinct valid canonical
winner completed 29.708123583 seconds after the tip change.

Raw evidence and reproduction commands are in
`doc/evidence/m4-max-profile1-loaded-2026-07-30/`.

## CUDA Blackwell-class loaded result

An independent Linux CUDA campaign on a sanitized Blackwell-class 16 GiB
consumer GPU (Xeon W-class host, 76 GiB RAM) measured 100 distinct
`matmul_dim=4096` production headers on tip `c4ac2e43` (TU md5
`ed1e9477432b1766f549c039b6779632`):

| Metric | Result |
|---|---:|
| Mean | 32.273 s |
| p50 | 32.311 s |
| p95 | 32.527 s |
| p99 | **32.705 s** |
| Maximum | 32.709 s |
| MACs / episode | 141,149,805,215,744 |
| CPU GEMM fallbacks | **0** |

Device path detail:
`cuda_resident_ffn_chain+triple_stream+persistent_ws`. Versus a 90-second
block interval the p99 occupies ~36.3% (~57.3 s headroom). Tip-correlated
sanitized evidence:
`doc/evidence/cuda-blackwell-16gib-profile1-loaded-2026-08-01/`
(2026-07-30 retained as historical). L0 ratification was still false at the
date of this campaign; it has since been recorded for the height-181'894
activation.

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

The portable oracle remains available for explicit pre-activation testing and
offline dispute diagnosis. Production `strict-device` validation does not
invoke it inline: an unavailable accelerator or device digest mismatch is a
local failure and the block remains retryable without peer punishment or a
cached invalid verdict. A sole device disagreement does not quarantine the
provider (`IsUnconfirmedMismatch`); quarantine is reserved for a confirmed
execution/coverage failure (`IsQuarantinableExecutionFailure`,
`src/matmul/matmul_v4_rc_gkr.cpp`).

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

- [x] Profile 1 loaded p99 is within the 25–30 second target on this M4 Max
  (28.210 s). The independent CUDA-class result below does NOT meet this
  target (32.705 s); see that checklist for its verdict.
- [x] Two zero-gap valid blocks drain inside one 90-second interval.
- [x] Three-branch reorg and stale-job cancellation remain bounded.
- [x] Cryptographically ticketed invalid competing candidates cannot starve
  the authenticated-tip lane: preemption completed in 1.529 seconds and the
  honest verdict completed in 30.207 seconds with zero invalid completions.
- [x] An explicitly faulty exact-GEMM backend is covered under both policies:
  `strict-device` produces a retryable local failure and quarantines the
  provider without an inline CPU replay; pre-activation `auto-fallback`
  deterministically recovers an honest claim and still rejects a false claim.
- [x] Full-Metal telemetry covers every consensus MAC with no CPU fallback.
- [x] Production headers bind `matmul_dim=4096`; the real consensus predicate,
  target check, verdict memo, and worker completion path accept the goldens.

Independent CUDA class (sanitized; see
[`doc/evidence/cuda-blackwell-16gib-profile1-loaded-2026-08-01/`](evidence/cuda-blackwell-16gib-profile1-loaded-2026-08-01/)):

- [x] Profile 1 loaded p99 **32.705 s** measured on a Blackwell-class 16 GiB
  NVIDIA discrete GPU (Linux x86_64, Xeon W-class host, 76 GiB RAM).
  **This EXCEEDS the 25–30 s p99 target by 2.705 s** — the CUDA class does
  not pass that gate on this hardware; it stays within the 90-second block
  interval (p99 ≈ 36.3% of the interval, ~57.3 s headroom), which is the only
  bound this campaign clears. A CUDA-class within-target p99 remains
  unmet/open.
- [x] 100 distinct `matmul_dim=4096` headers / digests; zero CPU GEMM fallbacks.
- [x] CUDA ExactReplay attached via the Metal-parity `ExactGemmBackend`
  Launch* ABI (`rc_fused_ffn`, `rc_fused_ffn_chain`, `rc_phase1`).
- [x] Tip-correlated 100-run campaign recorded (`c4ac2e43`, TU md5
  `ed1e9477432b1766f549c039b6779632`); L0 ratification was still false at the
  campaign date (since recorded for the 181'894 activation).
- [x] Apple Silicon M4 Max-class Metal reproduced the same eight frozen
  production canary headers/dimensions/digests as CUDA at source revision
  `9dd88b8e54d92a848c4006aa9affca2ab3e0c91c`, with every consensus MAC on
  device and zero CPU GEMM calls/fallbacks.

Gate status at the shipped 181'894 activation:

- [ ] HIP/ROCm ExactReplay reproduction of the frozen production golden
  corpus: NOT done. Per the production-golden policy HIP is optional; it
  remains fail-closed and not production-authorized, and the committed
  manifest is CUDA+Metal only. The activation shipped without it.
- [ ] Multi-peer public testnet soak: NOT done — explicitly accepted as
  residual risk. The bounded two-peer regtest soak
  (`doc/evidence/cuda-profile1-soak-2026-08-02`, 45 minutes, 38 scenarios,
  zero failures) covered relay, competing branches, restart, cache
  persistence, and an IBD boundary on the final CUDA path, and its own
  summary refuses to claim the multi-day/multi-peer gate.
- [ ] Multi-day wall-clock soak and upgrade behavior across released
  binaries: NOT done — explicitly accepted as residual risk (recorded at
  `BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED`, `src/consensus/params.h`).
- [ ] Checkpoint and IBD trust-window disclosures frozen as a standalone
  artifact: not recorded in the committed activation evidence.
- [x] CUDA+Metal golden cohort reproduced byte-identically at ONE code
  freeze and committed as the production golden manifest
  (`doc/evidence/multi-gpu-profile1-goldens-cuda-metal-2026-08-03-sealed`;
  `CommittedRCProductionGoldenManifest()`).
- [x] One-time RC ASERT calibration measured same-silicon on two vendors and
  installed as `4294967295/1` (`asert-two-rig-calibration-2026-08-03`).
- [x] The consensus selector is Profile 1, with a construction invariant and
  regression coverage.
- [x] The atomic Epoch-A tuple is a construction invariant and is now
  INSTALLED on mainnet: equal v4/BMX4C/RC heights (181'894), withdrawn paths
  off, HeaderPoW off, v4/BMX4C ASERT inert, and RC as the sole calibrated
  branch.

Historical verdict: while the gates above were open, this document's verdict
was NO-GO. The operator activated Epoch A at mainnet height 181'894 on the
strength of the sealed one-freeze CUDA+Metal cohort, the zero-fallback
lifecycle soak, and the two-rig ASERT calibration, and explicitly accepted
the unmet gates listed above as residual risk. This document records that
decision; it does not retroactively claim those gates were closed.
