# C-15 vs ASERT/FMM calibration split (2026-07-19)

*Wave 1 calibration note. Separates **consensus-binding hardness** (C-15 /
MatExpand non-collapse) from **ASERT / efficiency calibration** under exact
FMM / Strassen-class algorithms.*

**Status:** OPEN calibration guidance — **not** a C-15 close; **not** a height
raise. Public nets stay fail-closed (`nMatMulDRLTHeight` / `nMatMulV4Height` =
`INT32_MAX`; ASERT rescale `1/1` until measured silicon JSON).

Companions:
- Packet §0.1 HonestMAC game: `doc/btx-matmul-v4.4-lt-external-c15-packet.md`
- Combine tournament: `doc/btx-matmul-v4.4-combine-algorithm-tournament.md`
- Leap checklist: `doc/btx-matmul-v4.4-lt-leap-checklist.md`
- Pre-review dual-track residual: `doc/btx-matmul-v4.4-lt-c15-prereview-synthesis-2026-07-19.md`

---

## 1. Two questions that must not be conflated

| Track | Question | Closed by |
|---|---|---|
| **Hardness (C-15)** | Can an adversary accept with non-negligible Freivalds advantage while paying **strictly fewer exact-int MACs** than `HonestMAC(n)` (shortcut / affine Extract / thin-panel reassociation)? | Independent cryptanalyst on packet §0.1; G5 ack |
| **Efficiency (ASERT)** | Given that honest miners may use **any exact** algorithm that reproduces canonical `Chat` bytes, what **measured wall-time / nonce/s** should difficulty price? | Silicon JSON + tournament vs **fastest known exact** path |

A PASS (or FAIL) on C-15 does **not** set `Num/Den`. A tournament win for
Strassen / adaptive-limb / Karatsuba does **not** close C-15. Mixing them
produces either false hardness claims (“naive GEMM is the floor”) or false
efficiency claims (“MAC count = ASERT input”).

---

## 2. Strassen–Winograd on the combine / sketch path

### 2.1 Where the exponent applies

Strassen–Winograd (and classical Strassen) multiply dense matrices in
**~O(n^{2.807})** arithmetic ops over rings that support the bilinear scheme —
including **ℤ** (exact integer GEMM with growth control) and **𝔽_q** with
`q = 2⁶¹−1` (the combine / sketch modulus).

Under ENC-DR-LT the **cubic-shaped** honest work that can absorb an exact FMM
is the deep-`m` path, not MatExpand:

| Stage | Shape (prod. `n=4096`) | Naive MAC order | Exact FMM eligible? |
|---|---|---|---|
| MatExpand-B (`G·W`, `Y·H`) | `n×w`, `w=1024` | `Θ(n²·w)` | Fatter panel vs Extract; still `O(n²·w)` vs cubic sketch floor |
| `B̂·V` | `n×n` × `n×m` | `Θ(n²·m)` | Yes in principle (exact int / mod-q lanes) |
| Combine `P·Q` | `m×m` sketch | `Θ(m²·n)`-class / limb-tensor variants | Yes — primary tournament target (`ComputeCombine*`) |

So: **~n^{2.807} is a real exact-algorithm option on sketch/combine (and
potentially `B̂·V`)**, not a claim that MatExpand itself becomes sub-cubic.

### 2.2 GPU realism (no invented silicon)

Frontier GPU tensor paths favor **regular GEMM / IMMA / MFMA / Cube** with high
occupancy. Strassen–Winograd on GPU is historically:

- bandwidth- and scheduling-hostile (7 recursive products, additive pre/post);
- awkward for thin / mixed-type ExactGemm panels;
- rarely the wall-time winner against a tuned vendor GEMM at production `n`.

**Calibration rule nonetheless:** ASERT must price against the **fastest known
exact miner path that reproduces consensus bytes**, not against schoolbook
GEMM MAC counts and not against “GPU probably won’t use Strassen.” If a CPU
Strassen / LCMA / adaptive-limb lane wins the public tournament on a reference
host, that lane is the calibration baseline until a faster **identity-PASS**
exact lane is measured. Invent no B200/5090/MI350 nonce/s in this note.

### 2.3 Consensus posture (retired claim)

“No cheaper exact mathematical path” and “≤12.5% Strassen cap” are **retired**
(audit F2 / leap checklist). Exact alternatives are **allowed**; they are
**efficiency**, not consensus-binding hardness. Verifier Freivalds does not
require classical GEMM — only correct dense sketch bytes.

---

## 3. MatExpand stays O(n²·w); cubic floor is deep-m

Load-bearing scoping (packet §1.1–§1.2):

- MatExpand ExactGemm is **`O(n²·w)`** with `w = kMatExpandPanelW = 1024`,
  **not** `O(n³)`.
- At `n=4096`: MatExpand-B ≈ `4n²w ≈ 8.59×10⁹` MACs; `B̂·V` ≈ `2n²m ≈ 6.87×10¹⁰`.
- The **cubic MAC floor** of one marginal nonce unit is deep-`m` sketch work
  (`B̂·V` + combine), not the thin-panel expand.

C-15 asks whether Extract prevents **cheaper-than-HonestMAC** Freivalds-linear
rewrites through `GWH`. It does **not** ask whether MatExpand is cubic. Treating
MatExpand as `n³` either overstates expand cost in ASERT proxies or understates
where exact FMM can bite (combine / `B̂·V`).

---

## 4. Interaction with packet §0.1 HonestMAC

### 4.1 Primary metric = exact-int MAC count

Packet §0.1 fixes:

> **HonestMAC(n)** = exact-int MAC count of one marginal nonce unit:
> MatExpand-B + `B̂·V` + combine `P·Q` (I1′ template A / `U`/`V`/`P` excluded).

C-15 **FAIL** requires advantage at **≤ (1−δ)·HonestMAC** in that MAC metric
(default `δ = 1/2`). This is intentional:

- MAC count is **algorithm-class invariant** for classical vs Strassen *only if*
  the adversary’s algorithm is counted in the same exact-int multiply-accumulate
  model (bilinear multiplications + necessary adds, not “GPU cycles”).
- An adversary who runs Strassen but still performs ≥ HonestMAC exact multiplies
  has **not** won the C-15 game — they found an efficiency path, not a shortcut.
- An adversary who accepts with a **linear Extract surrogate** and skips
  MatExpand GEMMs **has** won — fewer MACs, Freivalds-usable rewrite.

### 4.2 Secondary metric = same-machine wall-time

§0.1 allows optional **same-machine wall-time of CPU ExactGemm reference** as
secondary evidence. Rules:

| Use | Do |
|---|---|
| C-15 primary | Stick to MAC count vs `HonestMAC`; do not substitute invented silicon |
| ASERT / leap row 6 | Prefer measured nonce/s (or same-host wall-time) of the **fastest identity-PASS exact** lane |
| Cross-talk | A wall-time win for Strassen **updates the ASERT baseline**; it does **not** move C-15 from OPEN→closed |

### 4.3 Practical split

```
C-15 game:   Adv, ε, δ  vs  HonestMAC   (hardness)
Tournament:  identity-PASS lanes by wall-time     (efficiency)
ASERT:       Num/Den from measured R_fastest_exact (calibration)
lt-gate G5:  external packet ack                  (process)
lt-gate G1–G4: measured device JSON only          (silicon)
```

Never feed schoolbook `n³` into ASERT when the tournament shows a faster exact
combine; never treat a tournament speedup as a C-15 PASS.

---

## 5. Recommended tournament / lt-gate / leap wording

Use this language in checklists and operator notes (**no silicon invention**):

**Baseline (normative wording):**

> Calibrate ASERT and leap production benchmarks against the **fastest known
> exact** miner path that reproduces canonical sketch / digest bytes
> (public CPU combine tournament + measured ExactGemm / device lanes). Do **not**
> calibrate to naive schoolbook GEMM MAC counts. Exact Strassen / Winograd /
> LCMA / adaptive-limb edges are **efficiency** residuals, not C-15 hardness.

**lt-gate:**

- G1–G4: consume **measured** `bmx4c-lt` JSON only; missing rates ⇒ NO-GO.
- G5: independent C-15 packet completion ack; **orthogonal** to FMM calibration.
- Do not auto-derive G5 from tournament results.

**Leap checklist (rows 6–7):**

- Row 6 (≥4× nonce/s / nonce/$): baseline = **fastest known exact**, not naive GEMM.
- Row 7 (adversarial): C-15 packet game + tournament vs silicon as **separate**
  gates; Strassen remains open *efficiency* work under Explicitly NOT claimed.

**Explicit non-claims (keep):**

- C-15 closed
- Finite public activation heights
- Invented B200/5090/MI350 nonce/s in docs
- “Naive GEMM is the economic floor”
- “Strassen cannot apply mod q / over ℤ” (false — it can; GPU win is a separate empirical question)

---

## 6. Operator one-liner

> **C-15 prices shortcuts in MAC count; ASERT prices the fastest honest exact
> wall-clock path.** MatExpand is `O(n²·w)`; deep-m is the cubic floor;
> Strassen–Winograd ~n^{2.807} is an exact combine/sketch option that must be
> tournament-tracked, not assumed away, and not confused with hardness.

---

## 7. Explicitly not claimed

- External C-15 closed
- Rank-1 / K.2b GO
- Any raise of `nMatMulDRLTHeight` / `nMatMulV4Height`
- Any concrete silicon nonce/s or nonce/$ figure
- That Strassen is (or is not) the wall-time winner on frontier GPUs
- That HonestMAC equals optimal wall-time cost
