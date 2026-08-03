> **HISTORICAL DESIGN / AUDIT EVIDENCE — MatMul v4.7 roadmap takes precedence.**
> This document preserves version-local findings, names, and measurements; it is not
> the current activation plan. The proposed transition is defined by
> `doc/btx-matmul-v4.7-transition-roadmap.md`: Epoch A uses Profile 1 with
> ExactReplay authority and optional shadow proofs; Epoch B requires both a durable
> Profile-1 proof and ExactReplay; Epoch C makes the Profile-1 proof authoritative;
> and Epoch D separately moves to Profile 2 under proof authority. Mainnet Epoch A (v4 = BMX4C = RC) remains a release candidate pending exact-final CUDA+Metal evidence, reviewed ASERT calibration, ratification, and selection of a live activation height; all other transition heights remain disabled. Any older “production,” “default,” “shipping,” direct-fork,
> sampled-verifier, or coupled-profile recommendation below is historical unless the
> canonical roadmap expressly carries it forward.

# V3 packed-bank / time–memory audit

## Verdict (preliminary)

**CONDITIONAL GO on byte accounting; TMTO NO-GO risk OPEN.**

Exact sizes are settled:

- V2 768 pages @ W=8192: expanded **48 GiB**, packed **25.5 GiB** (×17/32)
- V3 1536 pages: expanded **96 GiB**, packed **51 GiB**

The previous claim that 768 pages are a “48 GiB packed floor” was **false** — a 32 GiB RTX 5090 can retain the entire V2 packed bank.

## Canonical layout

Implemented in `src/matmul/matmul_v4_rc_packed_bank.{h,cpp}`:

- 32 elements → 16 E2M1 nibble-bytes + 1 UE8M0 scale = 17 bytes
- Round-trip tests for W=32
- Provider padding is not counted

## Regeneration / compression

The bank is seed-derived (`DeriveCoupledBankPage`). Therefore it is **not** information-theoretically incompressible. A miner may:

1. Regenerate pages on demand from the template seed
2. Cache hot pages in 32 GiB
3. Stream remainder over PCIe
4. Apply general compression if pages are structured

Until wall-clock measurements show that regeneration+PCIe is strictly slower than Resident MXFP4 on B200 by enough margin to overcome rent ratios, **do not claim economic dominance**.

5060 Ti can measure regeneration vs GEMM at scaled W; it cannot validate 51 GiB Resident.

## Adversarial custom layouts

Miners may use tighter-than-CUTLASS packs. Consensus floor remains 17/32 B/elem of the canonical encoding, not library workspace.
