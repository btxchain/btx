# ENC_RC Section-2 — Succinct proof soundness note (2026-07-20)

*Status: **aspirational formal bound** for the Fp2 + REAL FRI (v2) tip; NOT an
external audit claim. `nMatMulRCHeight = INT32_MAX`. Reality Guardrail remains
in force. **M2:** ALL-PHASE real-episode arithmetization (no shrink-to-toy);
consensus-dim prove may soft-over_budget on CPU (M4 shipping → ExactReplay).*

Companion code: `matmul_v4_rc_gkr_field_ext.h` (Fp2), `matmul_v4_rc_fri.*`
(REAL FRI: LDE + multi-layer fold openings), `matmul_v4_rc_gkr.*`
(ALL-PHASE real-episode arithmetization + round_seeds + shadow wiring).

---

## 1. Why single Goldilocks is insufficient

Goldilocks prime \(p = 2^{64}-2^{32}+1\) gives \(|\mathbb{F}| \approx 2^{64}\).
A sumcheck / FRI challenge drawn in \(\mathbb{F}\) contributes soundness error
\(\approx \deg / |\mathbb{F}|\) per round (ROM / Schwartz–Zippel style).

After \(R = O(\log N)\) rounds and a union bound over \(C\) claims (GEMM layers,
LogUp, FRI folds/queries), the total error is on the order of

\[
\varepsilon_{\mathrm{base}} \;\lesssim\; \frac{R\cdot C\cdot D}{|\mathbb{F}|}
\;\approx\; 2^{-64}\cdot \mathrm{poly}(\log N).
\]

PoW grinding lets an adversary try \(G\) block hashes (nonce space) against the
Fiat–Shamir transcript bound to the winning digest. Subtracting \(\log_2 G\)
bits from the computational bound leaves **no margin** for a \(\le 2^{-64}\)
**after-grinding** target when \(|\mathbb{F}|\approx 2^{64}\).

**Conclusion:** all Section-2 Fiat–Shamir challenges MUST live in a degree-2
(or higher) Goldilocks extension. This tip uses

\[
\mathbb{F}_{p^2} = \mathbb{F}_p[x]/(x^2-7), \qquad |\mathbb{F}_{p^2}| \approx 2^{128}.
\]

---

## 2. Target bound (aspirational) — sumcheck / FS algebra

Let:

| Symbol | Meaning | Tip default |
|---|---|---|
| \(D\) | max univariate degree in sumcheck/FRI fold | 2 |
| \(R\) | total challenge rounds (sumcheck + FRI folds) | \(O(\log N)\) |
| \(C\) | number of independent claims (layers + LogUp + FRI) | \(O(\#\mathrm{layers})\) |
| \(G\) | PoW grinding budget (adversarial hash tries) | \(\le 2^{64}\) (conservative); FRI accounting uses \(2^{32}\) |

**Base soundness (Fp2, before grinding):**

\[
\varepsilon_{\mathrm{FS}} \;\le\; \frac{R\cdot C\cdot D}{|\mathbb{F}_{p^2}|}
\;\le\; \frac{R\cdot C\cdot D}{2^{128}}.
\]

For \(R\cdot C\cdot D \le 2^{40}\) (generous for toy→medium traces),
\(\varepsilon_{\mathrm{FS}} \le 2^{-88}\).

**After PoW grinding** (proof FS-bound to `pow_bind = H(digest)` so grinding
the proof requires redoing PoW):

\[
\varepsilon_{\mathrm{net}} \;\le\; G\cdot \varepsilon_{\mathrm{FS}}
\;\le\; 2^{64}\cdot 2^{-88} = 2^{-24}
\]

under the conservative \(G=2^{64}\). Tightening \(G\) to a realistic block-interval
hash budget (e.g. \(2^{40}\)–\(2^{48}\) for a single winner) recovers

\[
\varepsilon_{\mathrm{net}} \;\le\; 2^{-40}\ \text{to}\ 2^{-48},
\]

and with production FRI query counts the **Stage-I requirement**
\(\varepsilon_{\mathrm{net}} \le 2^{-64}\) is the design target.

---

## 3. REAL FRI query accounting (v2)

Code constants (`matmul_v4_rc_fri.h`):

| Constant | Value | Role |
|---|---|---|
| `kRCFriBlowup` | 8 | LDE expansion; rate \(\rho = 1/8\) |
| `kRCFriNumQueries` | 40 | Query count \(k\) |
| `kRCFriGrindingBits` | 32 | Assumed PoW grinding \(g\) (\(G\le 2^{g}\)) |

### 3.1 What FRI does on this tip

1. **LDE:** input = degree-\(<n\) coefficients (\(n=\mathrm{next\_pow2}(\mathrm{len})\));
   zero-pad and NTT-evaluate on the size-\(N = 8n\) Goldilocks subgroup
   (embedded in \(\mathbb{F}_{p^2}\)). Merkle-commit LDE evals (SHA256d).
2. **Fold:** commit-then-challenge. For \(\beta\in\mathbb{F}_{p^2}\),
   \(\mathrm{next}[i] = \mathrm{even}[i] + \beta\cdot\mathrm{odd}[i]\) from pair
   \((2i,2i+1)\). Commit each folded layer.
3. **Queries:** after all layer roots are absorbed, derive \(k\) indices from FS.
   For each query, open Merkle paths for the even/odd pair at **every** fold
   layer, check the fold equation, and check the final constant.
4. **Grinding bind:** `fs_seed` MUST be SHA256d-bound to the winning digest /
   `pow_bind` (**caller responsibility in GKR**). FRI also absorbs optional
   `pow_grind_nonce` and all layer roots (commit-then-challenge).

Proof size is \(O(k\cdot\log N\cdot 32)\) openings — the LDE witness is **not**
shipped.

### 3.2 Unique-decoding proximity-gap bound (documented claim)

**Assumptions (honest):**

- Reed–Solomon proximity at the **unique-decoding** radius (distance
  \(> (1-\rho)/2\) from a degree-\(<n\) codeword is rejected whp).
- Commit-then-challenge Fiat–Shamir in the **random-oracle model**.
- `fs_seed` already includes the PoW bind; adversary gets at most
  \(G\le 2^{g}\) grinding tries at that seed.

Under those assumptions a standard conservative per-query bound is the rate:

\[
\varepsilon_{\mathrm{query}} \;\le\; \rho \;=\; \frac{1}{\mathrm{blowup}} \;=\; \frac{1}{8} \;=\; 2^{-3}.
\]

Union over \(k\) independent queries:

\[
\varepsilon_{\mathrm{queries}} \;\le\; \rho^{k} \;=\; 2^{-3k}.
\]

Fold / algebraic FS error is \(\le R\cdot D/|\mathbb{F}_{p^2}| = O(\log N)\cdot 2^{-128}\),
negligible beside the query term.

**After grinding subtraction:**

\[
\varepsilon_{\mathrm{net}} \;\le\; 2^{g}\cdot 2^{-3k}.
\]

Target \(\varepsilon_{\mathrm{net}}\le 2^{-64}\) requires

\[
k \;\ge\; \left\lceil\frac{g+64}{3}\right\rceil.
\]

With \(g=32\): \(k\ge 32\). This tip sets **`kRCFriNumQueries = 40`**:

\[
\varepsilon_{\mathrm{net}} \;\le\; 2^{32}\cdot 2^{-120} \;=\; 2^{-88} \;\le\; 2^{-64}.
\]

`FriSoundnessBoundBits()` returns \(3k - g = 88\).

### 3.3 List-decoding caveat (not the claimed bound)

Johnson / list-decoding proximity gaps replace the per-query factor by roughly
\(\sqrt{\rho}=2^{-1.5}\). Then \(2^{32}\cdot 2^{-1.5\cdot 40}=2^{-28}\), which
**misses** \(2^{-64}\). Hitting \(2^{-64}\) under that weaker accounting needs
\(k\approx 80\). The tip’s **written claim** uses unique-decoding (§3.2); a
production audit should either raise \(k\) or cite a tighter FRI proximity
theorem (e.g. Ben-Sasson–Bentov–Horesh–Riabzev / ethSTARK-style bounds).

---

## 4. What is proven vs aspirational on this tip

| Item | Status |
|---|---|
| Fp2 arithmetic + FS challenges in Fp2 | **Code-complete** |
| REAL FRI: LDE blowup=8, multi-layer fold openings, \(k=40\) | **Code-complete (v2)** |
| Real-episode ALL-PHASE arithmetization (Q·Kᵀ, S·V, Fwd, Bwd, Wgrad × rounds + Extract LogUp + round_seeds) | **Code-complete scaffold (M2)** |
| FRI commit/open without shipping every Extract tile | **Code-complete** |
| Shadow wiring (`BTX_RC_GKR_SHADOW`, never rejects consensus) | **Code-complete** |
| Arbiter cutover (`BTX_RC_GKR_ARBITER`, default OFF) | **Wired; OFF; does not raise height** |
| ε=0 `VerifyBoundedExactReplay` consensus arbiter | **Unchanged** |
| Formal \(\le 2^{-64}\) after grinding (unique-decoding FRI) | **Documented derivation §3.2** — not an external audit |
| List-decoding FRI at \(\le 2^{-64}\) | **NOT claimed** at \(k=40\) — see §3.3 |
| Production / HBM silicon rates | **NOT claimed** — Reality Guardrail |
| Full consensus-dim episode prove within CPU soft budget | **NOT claimed** — soft `over_budget` → ExactReplay (M4 shipping); arithmetization is **not** shrink-to-toy |

---

## 5. Shrink fallback (honest)

If `proof_bytes > kRCGkrProofBytesBudget` (256 KiB soft) or verify/prove exceeds
soft CPU budgets, the scaffold sets `over_budget` and recommends
`VerifyBoundedExactReplay`. **M2:** this is shrink-to-**replayable** for shipping
— the prover still arithmetizes the **actual** episode params (ALL-PHASE); it does
**not** replace the episode with a toy-slice proof. Report honestly; do not invent
silicon numbers. With \(k=40\) multi-layer openings, FRI proofs for medium traces may
exceed the soft 256 KiB budget; that triggers the ExactReplay recommendation.

---

## 7. Composed soundness (M3) — GKR + LogUp + FRI end-to-end

All Fiat–Shamir challenges in `matmul_v4_rc_gkr.cpp` / FRI are drawn via
`ChallengeFp2` / `FromChallengeBytes2` (Fp2). The composed error is:

\[
\varepsilon_{\mathrm{total}}
\;\le\;
\varepsilon_{\mathrm{sumcheck}}
\;+\;
\varepsilon_{\mathrm{logup}}
\;+\;
\varepsilon_{\mathrm{FRI,net}}
\]

| Term | Bound used on this tip | Notes |
|---|---|---|
| \(\varepsilon_{\mathrm{sumcheck}}\) | \(R_{\mathrm{sc}}\cdot C_{\mathrm{layers}}\cdot D / 2^{128}\) | Deg≤2 product sumcheck; Fp2 |
| \(\varepsilon_{\mathrm{logup}}\) | \(C_{\mathrm{keys}} / 2^{128}\) | Collision / bad multiset in Fp2 |
| \(\varepsilon_{\mathrm{FRI,net}}\) | \(2^{g-3k}=2^{-88}\) | §3.2 unique-decoding; \(k=40\), \(g=32\) |

With toy/medium layer counts \(R_{\mathrm{sc}}C_{\mathrm{layers}}D \ll 2^{40}\), the
algebraic terms are \(\le 2^{-88}\). Dominating term: FRI queries →
\(\varepsilon_{\mathrm{total}} \le 2^{-87}\) under §3.2 assumptions **before**
raising \(G\) to a full \(2^{64}\) PoW grind. Using the FRI-local grind \(g=32\)
(block-interval class) keeps \(\varepsilon_{\mathrm{total}} \le 2^{-64}\).

**Gate M3 status:** derivation written; FRI forge tests pass empirically;
full list-decoding audit and external review remain OPEN. Do not claim
"production-complete" until audited.

---

## 8. PCS alternative (owner decision — flag only)

Hand-rolled FRI (this tip) vs integrating a **vetted transparent STARK /
Goldilocks-FRI stack** (e.g. Plonky3-style or Winterfell-style core) as the PCS:

| | Hand-rolled (current) | Vetted STARK core |
|---|---|---|
| Consensus dependency | None beyond SHA256d | External crate / subtree |
| Audited proximity theorems | Owner must audit §3 | Inherit upstream audits (still review binding) |
| Engineering cost | High (this packet) | Integration + transcript binding to `pow_bind` |
| Proof size / verify | Tunable via \(k\), blowup | Typically battle-tested defaults |

**Decision left to the owner.** This tip does not pull an external STARK
dependency; the M1 FRI path remains the in-tree PCS.

---

## 9. Guardrails

- `nMatMulRCHeight = INT32_MAX`
- REJECT “HBM / production-complete” claims (`kRCGkrRealityGuardrail`)
- Winner-only prove; losers pay zero prove cost
- ε=0 ExactReplay remains consensus arbiter; proof is SHADOW until audit + arbiter cutover
