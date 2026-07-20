# ENC_RC Section-2 — Succinct proof soundness note (2026-07-20)

*Status: **aspirational formal bound** for the Fp2+FRI scaffold; NOT an external
audit claim. `nMatMulRCHeight = INT32_MAX`. Reality Guardrail remains in force.*

Companion code: `matmul_v4_rc_gkr_field_ext.h` (Fp2), `matmul_v4_rc_fri.*`,
`matmul_v4_rc_gkr.*` (real-episode toy arithmetization + shadow wiring).

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

## 2. Target bound (aspirational)

Let:

| Symbol | Meaning | Scaffold default |
|---|---|---|
| \(D\) | max univariate degree in sumcheck/FRI fold | 2 |
| \(R\) | total challenge rounds (sumcheck + FRI folds + queries) | \(O(\log N)\) |
| \(C\) | number of independent claims (layers + LogUp + FRI) | \(O(\#\mathrm{layers})\) |
| \(G\) | PoW grinding budget (adversarial hash tries) | \(\le 2^{64}\) (conservative) |

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

and with production FRI query counts + larger extension / more queries the
**Stage-I requirement** \(\varepsilon_{\mathrm{net}} \le 2^{-64}\) is the design
target — **not** a claim that the current SHA256-Merkle FRI scaffold achieves it.

---

## 3. What is proven vs aspirational on this tip

| Item | Status |
|---|---|
| Fp2 arithmetic + FS challenges in Fp2 | **Code-complete** |
| Real-episode toy arithmetization (Q·Kᵀ, S·V, fwd GEMM + Extract LogUp) | **Code-complete scaffold** |
| FRI-style commit/open without shipping every Extract tile | **Code-complete scaffold** (SHA256 Merkle fold) |
| Shadow wiring (`BTX_RC_GKR_SHADOW`, never rejects consensus) | **Code-complete** |
| Arbiter cutover (`BTX_RC_GKR_ARBITER`, default OFF) | **Wired; OFF; does not raise height** |
| ε=0 `VerifyBoundedExactReplay` consensus arbiter | **Unchanged** |
| Formal \(\le 2^{-64}\) after grinding | **Aspirational derivation above** — requires audited FRI proximity + query params |
| Production / HBM silicon rates | **NOT claimed** — Reality Guardrail |
| Full consensus-dim episode prove | **NOT claimed** — shrink-to-toy + ExactReplay fallback when over budget |

---

## 4. Shrink fallback (honest)

If `proof_bytes > kRCGkrProofBytesBudget` (256 KiB soft) or verify/prove exceeds
soft CPU budgets, the scaffold sets `over_budget` and invokes
`VerifyBoundedExactReplay` / toy-slice arithmetization. This is the fail-closed
path when the HBM proof cannot close budget — **report**, do not invent silicon
numbers.

---

## 5. Guardrails

- `nMatMulRCHeight = INT32_MAX`
- REJECT “HBM / production-complete” claims (`kRCGkrRealityGuardrail`)
- Winner-only prove; losers pay zero prove cost
