# ENC_RC succinct proof — emulated multi-persona crypto audit (2026-07-21)

*Status: **emulated** auditor memos inspired by public STARK/FRI audit practice
(Trail of Bits / Least Authority / Spearbit style). **NOT** a signed independent
human engagement. Shadow ON / arbiter OFF / ExactReplay consensus /
`nMatMulRCHeight=INT32_MAX`.*

Personas: (A) FRI/PCS specialist, (B) Arithmetization / under-constraint
specialist, (C) Composition & deployment gatekeeper. Research anchors: DEEP-FRI
ePrint 2019/336; BCIKS20 ePrint 2020/654; Haböck LogUp ePrint 2022/1530; Fable
IOP parameter oracle (scratchpad); Plonky3/Stwo DEEP-quotient practice.

---

## Persona A — FRI / PCS (DEEP/OOD)

### Findings (pre-remediation)

| ID | Sev | Finding |
|---|---|---|
| F-A1 | **CRITICAL** | FRI proved proximity only; claimed evaluations unbound (no OOD). |
| F-A2 | HIGH | Prior ρ^Q / Q=40 marketing contradicted unique decoding. |
| F-A3 | MEDIUM | Nested quotient FRI must share LDE domain with P. |

### Remediation landed (code)

- FRI **v3**: DEEP/OOD — `deep_z`, `deep_eval`, quotient FRI, identity
  `P(x)=Q(x)(x−z)+v` at every query site (`matmul_v4_rc_fri.*`).
- Fable operating point: **g=40 / Fp2 / blowup=16 / Q=116**, bits=65.
- Conjectured bound compile-gated OFF.

### Residual (honest)

- DEEP binds **univariate** evaluation of the committed coeff poly; MLE(claim)
  binding is via commit-then-challenge FS (Persona B), not a full multilinear PCS.
- Nested quot FRI doubles prove cost / proof bytes (soft budgets raised).

### Non-claims

Not ε=0. Not production-complete. Not a substitute for external audit sign-off.

---

## Persona B — Arithmetization / under-constraint (G1–G5)

### Findings (pre-remediation)

| ID | Sev | Gap |
|---|---|---|
| F-B1 | **CRITICAL** | G1: A,B not committed before challenges. |
| F-B2 | **CRITICAL** | G2: claim vs FRI-Y unbound (challenge-then-commit). |
| F-B3 | HIGH | G3: LogUp sum not tied to Extract table check. |
| F-B4 | HIGH | G4: cross-layer extract wiring prove-only. |
| F-B5 | HIGH | G5: `Y_acc = Y_gemm + X` not algebraically checked. |

### Remediation landed (proof **v5**)

| Gap | Close |
|---|---|
| G1 | Batched `a_fri` / `b_fri` + per-layer `a_root`/`b_root` absorbed **before** `(ri,rj)`. |
| G2 | Commit-then-challenge: `trace_fri` (+DEEP) absorbed before claims; claims FS-bound to roots. |
| G3 | LogUp keys FRI+DEEP; `(in,out)` hashed (C1); sum FS-bound. Full Haböck table IOP still aspirational. |
| G4 | `extract_out_commit` chain absorbed across layers. |
| G5 | Verifier checks `acc_claim = claim + residual_mle`; non-Fwd residual must be 0. |

### Residual (honest)

- G1: A/B FRI binds concatenations; per-layer eq-fold into `ah`/`bh` still via sumcheck messages (not separate A(r) openings).
- G3: no fixed Extract lookup table IOP — relation soundness is key commitment + DEEP + HashLookupKey, not full Haböck multiplicity check.
- G4: commit chain binds digests of extract_out, not algebraic equality of SV.A = QKt.extract_out as field vectors inside the PCS.

These residuals **still counsel against arbiter ON** until an external auditor signs the composition.

---

## Persona C — Composition & deployment gatekeeper

### Checklist

1. [x] Unique-decoding Q=116 / B=16 / g=40 matches Fable table.
2. [x] DEEP/OOD present and tested (`fri_deep_ood_tamper_rejects`).
3. [x] Commit-then-challenge ordering in prove/verify.
4. [x] G5 residual algebra enforced.
5. [ ] External human audit sign-off — **OPEN**.
6. [ ] Consensus-dim prover cost on silicon — **OPEN** (OUT OF SCOPE).
7. [x] Arbiter OFF; ExactReplay consensus; height INT32_MAX.

### Verdict

**Ship as hardened shadow scaffold.** Do **not** flip `BTX_RC_GKR_ARBITER`.
Do **not** raise `nMatMulRCHeight`. Do **not** claim HBM/production-complete.

---

## Citations

- Ben-Sasson–Goldberg–Kopparty–Saraf, DEEP-FRI, ePrint 2019/336
- Ben-Sasson–Carmon–Ishai–Kopparty–Saraf, Proximity Gaps for RS, ePrint 2020/654
- Haböck, Multivariate lookups based on logarithmic derivatives, ePrint 2022/1530
- Fable verifiable-IOP reference (scratchpad parameter oracle; not merged)
