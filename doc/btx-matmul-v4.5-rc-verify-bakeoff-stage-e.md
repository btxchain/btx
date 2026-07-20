# ENC_RC Stage E — Verification bake-off (toy prototypes)

*Date: 2026-07-20. Tip base: `6b3f06b`. Status: **E5 DECIDED** — winner-only GKR/sumcheck.
Does **not** raise `nMatMulRCHeight` (remains `INT32_MAX`). Does **not** wire GKR into
`CheckMatMulProofOfWork_RC` / validation until Stage-I cutover.*

Binding decision: `doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md`.
Prior evidence: `doc/btx-matmul-v4.5-rc-validation-model-p2.1.md` (P2.1).

---

## E1 — Sole ε=0 consensus check

**Full exact STREAMED replay** (`RecomputeResidentCurriculumReference` →
`CheckMatMulProofOfWork_RC`) remains the **sole ε=0** consensus validity check
until Stage-I cutover. Bake-off prototypes + winner GKR measure alternatives;
none replace the validation path yet.

Code constant: `kBakeoffE1Statement` in `src/matmul/matmul_v4_rc_verify_bakeoff.h`.

---

## E2 — Merkle q=8 is DoS PREFILTER ONLY

`kRCSpotCheckQueries = 8` leaf sampling is a **bandwidth DoS prefilter only**.
It is **never** an O(1) consensus verifier (P2.1 §1.3: `f^q` grinding).

Code constant: `kBakeoffE2Statement`.

---

## E3 — Prototypes (toy trace, winner-only)

| ID | Prototype | Status |
|---|---|---|
| **A** | Exact bounded-memory replay baseline (wrap `RecomputeResidentCurriculumReference`) | Implemented; measured |
| **B** | Toy GKR/sumcheck-shaped (educational SHA256 FS; **NOT production crypto**) | Implemented; measured |
| **E / GKR** | **Winner-only Goldilocks GKR/sumcheck + Extract LogUp** (`matmul_v4_rc_gkr.*`) | **DECIDED path**; measured |
| **C** | STARK/AIR+FRI | **Stub only** |
| **D** | Structural spot-check + compact fraud-proof sketch | Sketch; **deferred** |

### E3-C why not fully implemented

A STARK/AIR+FRI for ENC_RC would need a finite-field AIR for int64 GEMM, a
lookup/permutation argument for non-affine ExtractMX, FRI commitments, and a
soundness write-up under the chosen FS hash. Out of scope; GKR is the selected path.

### E3-D deferred

Fraud-proof completion needs a **separate fork**. Deferred while GKR verify is priced.

---

## E4 — Measured numbers (TOY ONLY)

**Host:** measured on this box via `./build/bin/matmul-v4-rc-verify-bakeoff`.
**Launcher:** `contrib/matmul-v4/rc-verify-bakeoff.py`.

| Proto | Metric | Value | Evidence kind |
|---|---|---|---|
| **A** exact replay | wall_s | **0.00119 s** | toy_chrono_measured |
| **A** | rss_kib | **4732** | toy_rss |
| **A** | proof_bytes | 0 (recompute is the check) | — |
| **A** | digest | `b339d0ff…e43a` (V1 toy golden) | golden |
| **B** toy GKR | prove_wall_s | **0.000655 s** | toy_chrono_measured |
| **B** | verify_s | **0.000044 s** | toy_chrono_measured |
| **B** | proof_bytes | **9400** | toy_measured |
| **E winner GKR** | prove_s | **0.124 s** | toy_chrono_measured |
| **E** | verify_s | **0.122 s** | toy_chrono_measured |
| **E** | proof_bytes | **19320** | toy_measured |
| **E** | direction | **DECIDED** | owner decision |
| **C** STARK stub | implemented | **false** | stub |
| **D** fraud sketch | wall_s (honest) | **0.00090 s** | toy_chrono_measured |
| **D** | proof_bytes | **16448** | toy_measured |
| **D** | fault_detected (injected) | true | — |

### Production extrapolations — **NOT EVIDENCE**

Any scaling of these toy walls/RSS/proof sizes to epoch-0 consensus dims
(`n_ctx=786432`, …) is **NOT EVIDENCE** and MUST NOT gate `nMatMulRCHeight`.

---

## E5 — Decision (**BINDING: DECIDED**)

**DECIDED: winner-only GKR/sumcheck.**

- Fraud-proof deferred.
- Shrink is fallback if GKR verify cost fails Stage-I budget.
- Height stays `INT32_MAX`. Decision alone does **not** raise height.
- Magnitude path toward full HBM is directionally unlocked **if** verify ≤
  fraction of block interval (still need silicon for Stage G).

See `doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md`.

---

## E6 — Security notes

| Path | Soundness |
|---|---|
| A — exact replay | ε=0 (information-theoretic match of int64 oracle) |
| E — winner GKR | **Computational** soundness (hash / Goldilocks); **not** ε=0 |
| B — educational toy GKR | Educational only |
| D — fraud proofs | Deferred; requires separate fork |
| q=8 Merkle sample | DoS prefilter only — **not** sole validity |

---

## Pointers

- Decision: `doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md`
- Code: `src/matmul/matmul_v4_rc_gkr.{h,cpp}`, `matmul_v4_rc_verify_bakeoff.{h,cpp}`
- Harness: `matmul-v4-rc-harness --prove-winner-gkr`
- Python: `contrib/matmul-v4/rc-verify-bakeoff.py`
- P2.1: `doc/btx-matmul-v4.5-rc-validation-model-p2.1.md`
