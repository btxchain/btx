> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC_RC v7 — composed soundness bound (honest) — 2026-07-22

> **Corrected 2026-07-22 (v4.6):** superseded figures updated to the shipped Q=128/Fp2 ≈71.9-bit bound and V3-production default; see doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md.

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
| G1–G5 (succinct PCS / Extract AIR bindings) | Constructions I–IV **integrated & validated in-tree** (wired into `VerifyWinnerProofV7`; rack/unit tests pass) — external cryptographic audit pending; never claim CLOSED or audit-passed |
| External crypto audit | **Required** before any arbiter discussion |
| v7 independent-malicious defeat | By **grounding** against the int64 reference (native re-derivation in `VerifyWinnerProofV7` / Coupled V7), **not** by a compact in-circuit SNARK |

The formal bound below is the **target algebra** for a future succinct cutover.
It does **not** authorize proof-only consensus acceptance today.

## Method

Post-grind bits subtract the repo grinding convention **g = 40** (adversary RO
budget \(2^{40}\)), matching `FriSoundnessBoundBits()`.

Field: Goldilocks \(\mathbb{F}_{p^2}\) (\(|\mathbb{F}| \approx 2^{128}\)).
FRI ship point: unique-decoding **Q = 128**, \(\rho = 1/16\),
`FriSoundnessBoundBits() = 76` (real value 76.80; the earlier Q = 116 / 65.85
configuration was rejected as inadequate).

Union / product of independent failure events; the dominant term is the **Fp2
FS subtotal** (the Q = 128 batched-FRI floor of 76.80 sits above it — the bound
is FS-dominated, not FRI-dominated).

## Legacy vs v7 (Codex / construction table)

| Configuration | Dominant post-grind term | Clears 64 bits? |
|---|---|---|
| **Legacy:** 7 separate FRI instances | \(7\cdot 2^{-65.85} \Rightarrow\) **≈ 63.05 bits** (≈ \(2^{-62.2}\)–\(2^{-63}\)) | **NO** |
| **Legacy:** single-OOD DEEP (worst column) | **≈ 59.6 bits** | **NO** |
| **Legacy:** single-α LogUp over Fp2 (full PRF AIR \(N_L\approx 2^{43}\)) | **≈ 45 bits** | **NO** |
| **Legacy:** single-α bare tile keys only | **≈ 59.6 bits** | **NO** |
| **v7 shipped:** batched-single FRI (Q = 128) + dual-OOD + dual-α | **≈ 71.9 bits** (\(\varepsilon_{\mathrm{total}} \le 2^{-71.9}\), FS-dominated) | **YES** (margin ≈ 7.9 bits) |

### v7 composed total (Theorem 8.1)

| Component | Value |
|---|---|
| FS subtotal (all rounds, pre-grind) | \(\le 2^{-112}\) |
| FS × \(2^{40}\) grinding | \(\le 2^{-72}\) |
| Batched FRI queries (already post-grind, Q = 128) | \(2^{-76.80}\) |
| SHA256d computational ( \(2^{40}\) -query adv.) | \(\le 2^{-88}\) |
| **Total \(\varepsilon\)** | **\(\le 2^{-71.9}\) ≈ 71.9 bits (FS-dominated)** — this is what `RCGkrComposedSeparationBits()` returns |
| Target | \(2^{-64}\) — **CLEARED**, margin ≈ 7.9 bits (adequate; the rejected Q = 116 configuration gave only ≈ 65.7 bits, margin < 2 bits — inadequate) |
| Deferred follow-on (NOT shipped) | full Fp3 Fiat–Shamir cutover (proof-wire-format change, 16→24-byte challenges) ⇒ composed ≈ \(2^{-76.8}\) |

**Preconditions (each necessary):**
1. single **batched** FRI instance (7-way union fails at ≈ 63 bits);
2. **dual-OOD** DEEP points (single fails at ≈ 59.6 bits);
3. **dual-α** LogUp over Fp2 (single fails at ≈ 45 bits) — or Fp3 single-α (unbuilt).

## What this bound is *not*

- **Not** a claim that G1–G5 are CLOSED or audit-passed. The succinct openings
  of A/B/Y at sumcheck points, verifier-defined Extract AIR, bank-page PCS under
  `bank_root`, and tile-tree / ChaCha–SHA AIRs (Constructions I–IV) are
  **integrated and validated in-tree** (see completeness + construction docs),
  but the residual gate is an **external cryptographic audit** — validated-in-tree
  ≠ externally-audited, so never claim CLOSED.
- **Not** permission to flip the arbiter. `kRCGkrFormalSoundnessReady` stays
  `false` until formal bound + G1–G5 succinct bindings + external audit.
- **Not** a substitute for ExactReplay. v7’s practical soundness against
  independent malicious constructors today is **grounding**, which re-derives
  against the immutable int64 reference and is deliberately over-budget for
  succinct verify.

## Cross-links

- Construction §8: `doc/btx-matmul-v4.5-rc-gkr-arithmetization-construction.md`
- Soundness table: `doc/btx-matmul-v4.5-rc-gkr-soundness-table-2026-07-21.md`
- Completeness (G1–G5 integrated & validated in-tree; external audit pending): `doc/btx-matmul-v4.5-rc-arithmetization-completeness-2026-07-20.md`
- FRI proximity / Q=128 ship: `doc/btx-matmul-v4.5-rc-fri-proximity-gap-m11-2026-07-20.md`
- V3 status: `doc/btx-matmul-v4.5-v3-gkr-soundness-status.md`
