> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC_RC Section-2 — Succinct proof soundness note (AUDIT-READY, M6/M8 + Fable)

> **Corrected 2026-07-22 (v4.6):** superseded figures updated to the shipped Q=128/Fp2 ≈71.9-bit bound and V3-production default; see doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md.

*Status: formal derivation for shipped parameters; **NOT** an external audit sign-off.
`nMatMulRCHeight = INT32_MAX`. Reality Guardrail rejects “production-complete.”
Arbiter OFF; ExactReplay is consensus.*

Companions: `matmul_v4_rc_fri.h` (M6/Fable params), `matmul_v4_rc_gkr.*` (ALL-PHASE),
`doc/btx-matmul-v4.5-rc-arithmetization-completeness-2026-07-20.md` (M7),
`doc/btx-matmul-v4.5-rc-succinct-proof-pcs-alternative-2026-07-20.md` (M10),
`doc/btx-matmul-v4.5-rc-fri-proximity-gap-m11-2026-07-20.md` (M11).

**Parameter oracle:** an independent Fable verifiable-IOP reference (scratchpad only;
NOT merged) cross-checked unique-decoding query counts. Shipped numbers below
match that oracle’s k=40 / Fp2 / blowup-16 tier.

---

## 1. Why single Goldilocks is insufficient

\(|\mathbb{F}_p|\approx 2^{64}\) cannot absorb union-bound + PoW grinding for a
net \(\le 2^{-64}\) target. All FS challenges live in
\(\mathbb{F}_{p^2}=\mathbb{F}_p[x]/(x^2-7)\) (\(|\mathbb{F}_{p^2}|\approx 2^{128}\)).

**Fp3 lever (unbuilt):** for grinding \(g\ge 64\), the FRI fold-collision term
\(2N/|E|\) forces a larger extension. Fable: Fp3 (\(v^3-2\), \(|E|\approx 2^{192}\))
for \(g=64\) (Q=142) / \(g=80\) (Q=159). **Ship decision:** stay on **g=40 / Fp2**;
do **not** build Fp3 speculatively.

---

## 2. M6 — FRI parameter reconciliation (Fable targets)

### 2.1 Bugs removed

Prior tip claimed \(\varepsilon\le\rho^{40}=(1/8)^{40}\) and/or “~80 queries.”
Both are wrong under unique decoding. Conjectured \(\rho^Q\) is gated
`BTX_RC_FRI_CONJECTURED_BOUND` (default **OFF**, never consensus).

### 2.2 Fable composed-error table (authoritative for shipping)

Target: \(\log_2(T\cdot\varepsilon)\le -64\), \(T=2^g\),
\(\alpha=(1+\rho)/2\) (proven unique decoding), \(\rho=1/\mathrm{blowup}\),
\(Q=\lceil(65+g)/(-\log_2\alpha)\rceil\).

| Grinding \(g\) | Field | Blowup | Required \(Q\) | \(\log_2(T\cdot\varepsilon)\) | Status |
|---:|---|---:|---:|---:|---|
| **40** | **Fp2** | **16** | **116 (formula minimum)** | **≈ −65.85** (Fable ≈ −65.26) | **superseded — SHIPPED Q = 128** (⇒ ≈ −76.80; the Q=116 point left the composed bound at ≈ 65.7 with < 2 bits of margin and was rejected as inadequate) |
| 64 | Fp3 | 16 | 142 | ~−65 | future lever (needs Fp3) |
| 80 | Fp3 | 16 | 159 | ~−65 | future lever (needs Fp3) |

### 2.3 Shipped constants (`matmul_v4_rc_fri.h`)

| Constant | Value |
|---|---|
| `kRCFriBlowup` | 16 |
| `kRCFriGrindingBits` | 40 |
| `kRCFriNumQueries` | 128 |
| `FriSoundnessBoundBits()` | 76 (= \(\lfloor Q\log_2(32/17)-40\rfloor\); real value 76.80) |

Test `fri_constants_and_soundness_bits` asserts bits == 76 and
`FriClaimedBitsMeetTarget()`.

### 2.4 Theorems (proven vs conjectured)

| Citation | Role | Proven / conjectured |
|---|---|---|
| Ben-Sasson–Bentov–Horesh–Riabzev, FRI (2018) | Protocol | Protocol |
| Ben-Sasson–Kopparty–Saraf (2018) | WC→AC proximity | Proven |
| **BCIKS20** ePrint 2020/654 | Proximity gaps; FRI \(t\approx 2\lambda/\log(1/\rho)\) for \(q\gg n^2\) | Proven (M11 option) |
| ethSTARK / Plonky “blowup·Q” tables | Engineering | **Conjectured** — not shipped |

### 2.5 Fold / collision algebraic error (Fp2)

Fold-collision style term \(\le 2N/|\mathbb{F}_{p^2}|\). At \(g=40\) with
\(|E|\approx 2^{128}\) this stays under budget for toy→medium \(N\) (Fable).
At \(g\ge 64\), Fp3 is required — see §1.

---

## 3. DEEP / OOD — exact-evaluation binding (CLOSED in FRI v3)

FRI v3 implements DEEP/OOD (ePrint 2019/336 practice): after committing P, draw
`z`, claim `v=P(z)`, FRI-commit `Q=(P−v)/(X−z)` on the same LDE domain, and at
each query site check `P(x)=Q(x)·(x−z)+v`.

This closes proximity-only PCS for **univariate** evaluation claims. MLE layer
claims are additionally bound by commit-then-challenge (proof v5+). Haböck LogUp
(G3, proof v6) uses forced DEEP at `z=1` to bind `I(1)=Σ inv_i` and commits
`R≡0`. Arbiter remains OFF pending external audit of the composition.


---

## 4. Composed soundness (M8)

\[
\varepsilon_{\mathrm{total}}
\;\le\;
\varepsilon_{\mathrm{sumcheck}}
+
\varepsilon_{\mathrm{logup}}
+
\varepsilon_{\mathrm{FRI,net}}
+
\varepsilon_{\mathrm{fold}}.
\]

| Term | Bound on this tip | Source |
|---|---|---|
| \(\varepsilon_{\mathrm{sumcheck}}\) | \(R_{\mathrm{sc}} C_{\mathrm{layers}} D / 2^{128}\) | Deg≤2 product; Fable agrees \(n\cdot\deg/|E|\) |
| \(\varepsilon_{\mathrm{logup}}\) | \((m+K+5n)/2^{128}\) style | Haböck ePrint 2022/1530; Fable agrees |
| \(\varepsilon_{\mathrm{FRI,net}}\) | \(2^{40}\cdot(17/32)^{128}\le 2^{-76}\) | §2.2 unique decoding (shipped Q = 128) |
| \(\varepsilon_{\mathrm{fold}}\) | \(O(N)\cdot 2^{-128}\) at g=40/Fp2 | §2.5 |

**Dominant term:** the Fiat–Shamir union subtotal (post-grind ≈ 72 bits) — at the
shipped Q = 128 the FRI query term (≈ 76.8) sits above it, so the composed bound
is FS-dominated at ≈ 71.9 bits (see
`doc/btx-matmul-v4.5-v7-composed-soundness-bound-2026-07-22.md`). Net
\(\varepsilon_{\mathrm{total}}\le 2^{-64}\) under
§2 assumptions **for proximity**. Exact-eval PCS completeness awaits §3.

**Fiat–Shamir / ROM / PoW grinding:** challenges are bind to committed layer
roots (commit-then-challenge). The durable PoW anchor is the
`round_roots → claimed_digest` SHA256d check together with the
`round_seed` chain (`seed[0]` from episode σ, then `seed[r]` from prior
`round_roots`). The field `pow_bind = tagged_hash(claimed_digest)` is only an
additional FS tag absorbed before FRI seed — it is **not** by itself the
grinding binding an auditor should chase.

---

## 5. EXTERNAL AUDITOR CHECKLIST (M8)

1. [ ] Shipped point is **g=40 / Fp2 / blowup=16 / Q=128** unique decoding
      (the Q=116 formula minimum was rejected as inadequate), not conjectured \(\rho^Q\).
2. [ ] `kRCFriNumQueries`, `FriSoundnessBoundBits()`, `kRCFriSoundnessStatement`
      agree (CI test).
3. [ ] `BTX_RC_FRI_CONJECTURED_BOUND` is OFF in consensus builds.
4. [ ] Commit-then-challenge ordering; `round_roots`/`round_seed` digest anchor
      (plus optional `pow_bind` FS tag — not the sole grinding binding).
5. [ ] Batching: two FRI instances (trace + lookup) — union bound accounted.
6. [ ] **DEEP/OOD:** confirm proximity-only vs exact-eval; do not sign off PCS
      completeness without OOD (or equivalent).
7. [ ] Fp3: confirm “not required at g=40”; do not require Fp3 for this tier.
8. [ ] Arithmetization completeness (M7): G1–G5 constructions integrated & validated in-tree; the external audit (this checklist) is what still blocks the arbiter.
9. [ ] LogUp binds `(extract_in, extract_out)` (C1).
10. [ ] Shadow ON / arbiter OFF / ExactReplay consensus until checklist signed.

---

## 6. Arithmetization completeness pointer (M7)

See `doc/btx-matmul-v4.5-rc-arithmetization-completeness-2026-07-20.md`.
**Decision:** ship k=40/Fp2/Q=128 (the Q=116 point was rejected as inadequate); Fp3 documented as a deferred future lever only.

---

## 7. Shrink / shipping (M4/M9)

Soft over_budget → ExactReplay. Enable off-CI cost with
`BTX_RC_GKR_MEASURE_LADDER=1` / `BTX_RC_GKR_MEASURE_MEDIUM=1`.

---

## 8. Guardrails

- `nMatMulRCHeight = INT32_MAX`
- REJECT HBM / production-complete (`kRCGkrRealityGuardrail`)
- Winner-only prove; losers pay 0
- ε=0 ExactReplay remains consensus arbiter
- Fable IOP reference stays **scratchpad only** — never merge as consensus
