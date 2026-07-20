# ENC_RC Stage E — Verification bake-off (toy prototypes)

*Date: 2026-07-20. Tip base: `3a3fb75`. Status: **evidence / prototypes only** — owner decides.
Does **not** raise `nMatMulRCHeight` (remains `INT32_MAX`). Does **not** wire any
prototype into `CheckMatMulProofOfWork_RC` / validation.*

Prior evidence: `doc/btx-matmul-v4.5-rc-validation-model-p2.1.md` (P2.1).

---

## E1 — Sole ε=0 consensus check

**Full exact STREAMED replay** (`RecomputeResidentCurriculumReference` →
`CheckMatMulProofOfWork_RC`) remains the **sole ε=0** consensus validity check.
Bake-off prototypes measure alternatives; none replace the validation path.

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
| **B** | Toy GKR/sumcheck-shaped over segment axis + Extract table-lookup (SHA256 Fiat–Shamir; **NOT production crypto**) | Implemented; measured |
| **C** | STARK/AIR+FRI | **Stub only** — see reason below |
| **D** | Structural spot-check + compact fraud-proof sketch (challenged segment recompute) | Sketch; **not** on validation path |

### E3-C why not fully implemented

A STARK/AIR+FRI for ENC_RC would need a finite-field AIR for int64 GEMM, a
lookup/permutation argument for non-affine ExtractMX, FRI commitments, and a
soundness write-up under the chosen FS hash. That is a research spike, not a
Stage E toy deliverable. Interface: `BakeoffC_StarkStub()`.

Even a complete STARK would change ε=0 to **computational soundness** (E6) and
requires a consensus fork — not a drop-in for today’s digest-only full recompute.

### E3-D fork requirements (document only)

Fraud-proof completion needs a **separate fork** from digest-only full recompute:

1. Challenge window (timeout → invalidate or force full recompute)
2. Data-availability for segment bodies / Merkle openings
3. Bonds / slash for unanswered or failed challenges
4. In-block `round_roots` (P2.1 §2)

**Do not** bolt the sketch onto the validation path without that fork.

---

## E4 — Measured numbers (TOY ONLY)

**Host:** `cymacpro-linux`, Intel Xeon W-3245 @ 3.20 GHz, 32 CPUs.
**Binary:** `./build/bin/matmul-v4-rc-verify-bakeoff` (`stub:false`).
**Launcher:** `contrib/matmul-v4/rc-verify-bakeoff.py`.

| Proto | Metric | Value | Evidence kind |
|---|---|---|---|
| **A** exact replay | wall_s | **0.00283 s** | toy_chrono_measured |
| **A** | rss_kib | **4648** (~4.5 MiB) | toy_rss |
| **A** | proof_bytes | 0 (recompute is the check) | — |
| **A** | digest | `b339d0ff…e43a` (V1 toy golden) | golden |
| **B** toy GKR | prove_wall_s | **0.00159 s** | toy_chrono_measured |
| **B** | verify_s | **0.000109 s** | toy_chrono_measured |
| **B** | proof_bytes | **9400** | toy_measured |
| **B** | rss_kib | **4916** | toy_rss |
| **B** | extract_in_table | true | — |
| **C** STARK stub | implemented | **false** | stub |
| **D** fraud sketch | wall_s (honest) | **0.00218 s** | toy_chrono_measured |
| **D** | proof_bytes | **16448** | toy_measured |
| **D** | fault_detected (injected) | true | — |
| Process (`/usr/bin/time -v`) | elapsed / Max RSS | **0.01 s / 4992 KiB** | process |

### Production extrapolations — **NOT EVIDENCE**

Any scaling of these toy walls/RSS/proof sizes to epoch-0 consensus dims
(`n_ctx=786432`, …) is **NOT EVIDENCE** and MUST NOT gate `nMatMulRCHeight`.

---

## E5 — Decision rule + provisional leaning (**NON-BINDING**)

**Decision rule (recorded):** owner chooses among (or sequences):

1. Keep **ε=0 full replay** as consensus (today’s code / bake-off **A**) — may require shrinking the episode for commodity verify (P2.1-a).
2. Target **fraud-proof protocol** (P2.1-b / bake-off **D**) if production-scale RC residency/capacity levers must be preserved.
3. Treat **GKR/STARK** (B/C) as research only until soundness + fork costs are priced.

**Provisional leaning (NON-BINDING — owner decides):**

- Near-term: keep **ε=0 full streamed replay (A)** as the consensus check.
- If ENC_RC must keep production-scale levers: lean toward **fraud-proof (D / P2.1-b)** as the *target* model (same leaning as P2.1 §5).
- **GKR/STARK (B/C):** research / educational only; not a consensus candidate without a fork and computational-soundness acceptance (E6).

Height stays `INT32_MAX`. Segment leaves / growth stay PARKED until the owner decides.

---

## E6 — Security notes

| Path | Soundness |
|---|---|
| A — exact replay | ε=0 (information-theoretic match of int64 oracle) |
| B/C — GKR/STARK | **Computational** soundness (hash / FRI assumptions); **not** ε=0 |
| D — fraud proofs | Optimistic accept + dispute; requires **separate fork** (challenge window, DA, bonds) |
| q=8 Merkle sample | DoS prefilter only — **not** sole validity |

---

## Stage D pointer (distributed bit-exactness)

Synthetic int64 GEMM simulation in `matmul_v4_rc_distributed.*`:

- Consensus segment IDs = `k0 / seg_len` — **independent of device count N**.
- N∈{1,2,4,8}; reduce with **integer sums only**; **one Extract** after combine.
- Tree L→R, R→L, pairwise butterfly → **identical** pre-Extract sums and digest.
- Canonical transcript: tag ‖ shape ‖ segs ascending ‖ Extracted int8 ‖ SHA256d.
- Unit tests: `matmul_v4_rc_distributed_tests` — **green**.

---

## Pointers

- Code: `src/matmul/matmul_v4_rc_verify_bakeoff.{h,cpp}`, `src/matmul-v4-rc-verify-bakeoff.cpp`
- Distributed: `src/matmul/matmul_v4_rc_distributed.{h,cpp}`
- Python: `contrib/matmul-v4/rc-verify-bakeoff.py`
- P2.1: `doc/btx-matmul-v4.5-rc-validation-model-p2.1.md`
