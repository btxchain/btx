# ENC_RC v7 — composed soundness bound (honest) — 2026-07-22

*Authoritative composed-budget writeup for the **v7 batched** construction
(batched-single-instance FRI + dual-OOD + dual-α LogUp). Companion numbers:
`doc/btx-matmul-v4.5-rc-gkr-soundness-table-2026-07-21.md` §Composed bound,
`doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md` §8.*

## Consensus posture (non-negotiable)

| Lever | Status |
|---|---|
| ExactReplay (`VerifyBoundedExactReplay` / int64 reference) | **Sole consensus authority** |
| `kRCGkrFormalSoundnessReady` | **`false`** — compile-time hard-disable |
| `EnvRCGkrArbiterEnabled()` | Always false while gate is false (**ignores** `BTX_RC_GKR_ARBITER`) |
| Heights `nMatMulRCHeight` / `nMatMulRCCoupledHeight` | **`INT32_MAX`** |
| G1–G5 (succinct PCS / Extract AIR bindings) | **OPEN/PARKED** — never claim CLOSED |
| External crypto audit | **Required** before any arbiter discussion |
| v7 independent-malicious defeat | By **grounding** against the int64 reference (native re-derivation in `VerifyWinnerProofV7` / Coupled V7), **not** by a compact in-circuit SNARK |

The formal bound below is the **target algebra** for a future succinct cutover.
It does **not** authorize proof-only consensus acceptance today.

## Method

Post-grind bits subtract the repo grinding convention **g = 40** (adversary RO
budget \(2^{40}\)), matching `FriSoundnessBoundBits()`.

Field: Goldilocks \(\mathbb{F}_{p^2}\) (\(|\mathbb{F}| \approx 2^{128}\)).
FRI ship point: unique-decoding **Q = 116**, \(\rho = 1/16\),
`FriSoundnessBoundBits() = 65`.

Union / product of independent failure events; dominant term is batched FRI.

## Legacy vs v7 (Codex / construction table)

| Configuration | Dominant post-grind term | Clears 64 bits? |
|---|---|---|
| **Legacy:** 7 separate FRI instances | \(7\cdot 2^{-65.85} \Rightarrow\) **≈ 63.05 bits** (≈ \(2^{-62.2}\)–\(2^{-63}\)) | **NO** |
| **Legacy:** single-OOD DEEP (worst column) | **≈ 59.6 bits** | **NO** |
| **Legacy:** single-α LogUp over Fp2 (full PRF AIR \(N_L\approx 2^{43}\)) | **≈ 45 bits** | **NO** |
| **Legacy:** single-α bare tile keys only | **≈ 59.6 bits** | **NO** |
| **v7 target:** batched-single FRI + dual-OOD + dual-α | **≈ 65.7 bits** (\(\varepsilon_{\mathrm{total}} \le 2^{-65.7}\)) | **YES** (margin < 1 bit) |

### v7 composed total (Theorem 8.1)

| Component | Value |
|---|---|
| FS subtotal (all rounds, pre-grind) | \(\le 2^{-112}\) |
| FS × \(2^{40}\) grinding | \(\le 2^{-72}\) |
| Batched FRI queries (already post-grind) | \(2^{-65.85}\) |
| SHA256d computational ( \(2^{40}\) -query adv.) | \(\le 2^{-88}\) |
| **Total \(\varepsilon\)** | **\(\le 2^{-65.7}\) ≈ 65.7 bits** |
| Target | \(2^{-64}\) — **CLEARED**, margin < 1 bit |
| Hardening recommendation | Q: 116 → 128 ⇒ FRI \(2^{-76.8}\), total ≈ \(2^{-71.9}\) |

**Preconditions (each necessary):**
1. single **batched** FRI instance (7-way union fails at ≈ 63 bits);
2. **dual-OOD** DEEP points (single fails at ≈ 59.6 bits);
3. **dual-α** LogUp over Fp2 (single fails at ≈ 45 bits) — or Fp3 single-α (unbuilt).

## What this bound is *not*

- **Not** a claim that G1–G5 are CLOSED. Succinct openings of A/B/Y at sumcheck
  points, verifier-defined Extract AIR, bank-page PCS under `bank_root`, and
  tile-tree / ChaCha–SHA AIRs remain OPEN/PARKED (see completeness + construction
  docs). Mutation-of-honest forge suites prove transcript integrity only.
- **Not** permission to flip the arbiter. `kRCGkrFormalSoundnessReady` stays
  `false` until formal bound + G1–G5 succinct bindings + external audit.
- **Not** a substitute for ExactReplay. v7’s practical soundness against
  independent malicious constructors today is **grounding**, which re-derives
  against the immutable int64 reference and is deliberately over-budget for
  succinct verify.

## Cross-links

- Construction §8: `doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`
- Soundness table: `doc/btx-matmul-v4.5-rc-gkr-soundness-table-2026-07-21.md`
- Completeness (G1–G5 OPEN/PARKED): `doc/btx-matmul-v4.5-rc-arithmetization-completeness-2026-07-20.md`
- FRI proximity / Q=116 ship: `doc/btx-matmul-v4.5-rc-fri-proximity-gap-m11-2026-07-20.md`
- V3 status: `doc/btx-matmul-v4.5-v3-gkr-soundness-status.md`
