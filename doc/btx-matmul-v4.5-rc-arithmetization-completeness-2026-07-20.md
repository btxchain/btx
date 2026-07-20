# ENC_RC — Arithmetization completeness audit (M7) — 2026-07-20

*Status: under-constraint / free-wire audit for ALL-PHASE GKR proof v4.
Companion: `doc/btx-matmul-v4.5-rc-succinct-proof-soundness-2026-07-20.md`.
Code: `matmul_v4_rc_gkr.{h,cpp}`. FRI PCS is separate (`matmul_v4_rc_fri.*`).
**Does not** flip arbiter / raise `nMatMulRCHeight`. Reality Guardrail stands.*

Goal: every wire/column class that the prover materializes must be fixed by a
named constraint the verifier checks (or listed as an honest OPEN gap that
blocks arbiter cutover).

---

## 1. Wire → constraint table

| Wire / column class | Where materialized | Constraint that fixes it | Verifier check |
|---|---|---|---|
| Public episode params `(rounds,d_head,n_q,n_ctx,L_lyr,d_model,b_seq,T_leaf)` | `RCGkrProof.episode` | Absorbed into FS domain; layer dims must match | `AbsorbEpisode` + per-layer dim check (M7) |
| `claimed_digest` | proof header | `EpisodeDigestFromRoots(round_roots)` equality | `VerifyWinnerProof` digest check |
| `pow_bind` | proof header | `pow_bind = DerivePowBind(claimed_digest)` + FS absorb | equality + FS re-derive |
| `episode_sigma` | proof header | Seed of round-0: `seed[0]=Sha256TaggedU32(ROUND,σ,0)` | round_seed chain |
| `round_seeds[r]` | proof vector | `seed[0]←σ`; `seed[r]←Sha256TaggedU32(ROUND,round_roots[r-1],r)` | full chain check |
| `round_roots[r]` | proof vector | Digest binding + seed chain; tile-tree of episode | digest + chain |
| Layer kind completeness | `layers[]` | ALL-PHASE: ≥1 of QKt, SV, Fwd, Bwd, Wgrad; count = `rounds·(2+3L)` | kind set + count |
| Layer `(m,n,k)` / `(round,layer)` | each `RCGkrLayerClaim` | Must match episode shape for that kind | M7 dim + index checks |
| Phase-1 QKt `A=Q`, `B=Kᵀ`, `Y=Q·Kᵀ` | prove wires | Product sumcheck: claim = MLE(Y) and claim = Σₜ Â(t)·B̂(t) | sumcheck algebra + round count = log₂(pad(k)) |
| Phase-1 SV `A=S`, `B=V`, `Y=S·V` | prove wires | Same product sumcheck | same |
| Phase-2 Fwd `A=X[l]`, `B=Wᵀ`, `Y_gemm=X·Wᵀ` | prove wires | Product sumcheck on `Y_gemm` | same |
| Phase-2 Bwd `A=G[l+1]`, `B=W`, `Y=G·W` | prove wires | Product sumcheck | same |
| Phase-2 Wgrad `A=Gᵀ`, `B=X`, `Y=Gᵀ·X` | prove wires | Product sumcheck | same |
| GEMM claim `lc.claim` | layer claim | Absorbed into FS before sumcheck; starts product | absorb + sumcheck `g(0)+g(1)=claim` |
| Sumcheck msgs / `final_eval` | layer claim | Deg-2 product fold; FS challenges in Fp2 | `VerifyProductK` + `final_eval` match |
| Trace wire `Y` (concat all layers) | `trace_fri` | REAL FRI commit/open of GEMM `Y` evals | `FriVerify(trace_fri)` |
| Extract **input** block (pre-Extract acc) | LogUp key | Hashed into `HashLookupKey` with output (M7 close) | via `lookup_fri` commitment |
| Extract **output** block `extract_out` | LogUp key | Same key: `(row,block,prf,scale,in64,out8)` | via `lookup_fri` |
| H5 residual (Fwd) | prove-time `Y_acc = Y_gemm + X[l]` | Residual inside single Extract; LogUp keys use `Y_acc` as input | key binding only (see OPEN) |
| `lookup_logup_sum` | proof scalar | FS-absorbed (binds `fri_seed`); honest = Σ 1/(α−key) | FS bind; **no** key recompute (OPEN) |
| LogUp / Extract keys poly | `lookup_fri` | REAL FRI of key vector | `FriVerify(lookup_fri)` |
| `transcript_hash` | proof footer | `fs.Digest()` after all absorbs | equality |

---

## 2. Phase coverage notes

### Phase-1 QKt / SV
- Operands expanded from `round_seeds` tags (`BTX_RC_Q_V1`, …) at **prove** time.
- Sumcheck fixes the relation claim ↔ A·B in the MLE/product sense **given** the prover’s A,B witnesses.
- Extract S / Z: LogUp keys bind `(Y_block, extract_out_block)` under PRF/scale (M7).

### Phase-2 Fwd / Bwd / Wgrad
- Same product-sumcheck pattern for each layer index `l ∈ [0,L)`.
- **H5 (residual-inside-Extract):** Fwd Extract runs on `Y_acc = Y_gemm + X[l]`. Sumcheck still proves `Y_gemm = A·B`. LogUp keys hash `Y_acc` (not bare `Y_gemm`) so the residual is inside the committed Extract input. Algebraic constraint `Y_acc = Y_gemm + X` is **not** separately sumchecked (OPEN).

### Public binding
- `claimed_digest` / `pow_bind` / `episode_sigma` / `round_seeds` / episode params are all verifier-checked as above.
- Succinct verify does **not** take the block header; callers that have a header should additionally check `episode_sigma == DeriveSigma(header)` (consensus dual-path does digest/header binding separately).

---

## 3. Adversarial coverage (tests)

Honest toy ALL-PHASE proof; each mutation must make `VerifyWinnerProof` return false:

| ID | Mutation | Expected |
|---|---|---|
| (a) | Flip layer `claim` byte / corrupt `sumcheck[0].eval0` | reject |
| (b) | Drop one layer | reject (`layer count` / kinds) |
| (c) | Wrong `round_seeds[0]` | reject (`round_seed chain`) |
| (d) | Wrong `pow_bind` or `claimed_digest` | reject |
| (e) | Corrupt `lookup_logup_sum` | reject (FS → FRI seed mismatch) |
| (f) | Mutate `trace_fri.final_value` or a query leaf | reject (`FriVerify`) |
| (g) | Corrupt `lookup_fri` opening (proxy for flipped Extract / wrong LogUp keys) | reject |

**(g) gap note:** Verifier does **not** recompute `Extract(Y)` from A,B,Y. Cheating by changing extract without updating committed `lookup_fri` fails Merkle/FRI. Rebuilding layers with flipped `extract_out` but same A,B,Y **would** change LogUp keys at prove time; a verifier that only sees the old FRI would reject if keys diverge — but the succinct verifier never re-derives keys from Y. Remaining gap: no algebraic check `out = ExtractMX(in)`.

---

## 4. KNOWN residual gaps (honest) — block arbiter cutover

| ID | Gap | Severity | Blocks arbiter? |
|---|---|---|---|
| **G1** | A,B matrices are **not** PCS-committed / opened; only sumcheck messages are checked. A cheating prover can invent A,B consistent with a forged claim without binding to public operand expansion. | High | **YES** |
| **G2** | Layer `claim` is not opened as an MLE evaluation of the `trace_fri`-committed Y poly at the FS point `(ri,rj)`. Claim ↔ trace binding is only indirect via FS/`fri_seed`. | High | **YES** |
| **G3** | `lookup_logup_sum` is not recomputed from opened keys; no fixed-table LogUp check that `(in,out)` is a valid Extract row. | High | **YES** |
| **G4** | Cross-layer wire equality (QKt `extract_out` = SV `A`; Fwd `X[l+1]` chaining; etc.) is prove-time only. | High | **YES** |
| **G5** | H5 residual: `Y_acc = Y_gemm + X` not sumchecked; only LogUp input uses `Y_acc`. | Medium | **YES** (Fwd integrity) |
| **G6** | `episode_sigma` vs header not checked inside `VerifyWinnerProof` (no header arg). | Low (caller) | if dual-path omits it |
| **G7** | Coupled barrier all-to-all product layers not arithmetized (`kRCGkrCoupledArithStatement`). | Medium | for coup profile |
| **G8** | List-decoding FRI / external audit (see soundness note). | Meta | **YES** |

### Closed in M7 (cheap)

| Close | What |
|---|---|
| **C1** | LogUp keys hash **(extract_in, extract_out)** pairs (was output-only). |
| **C2** | Fwd LogUp uses H5 `Y_acc` as `extract_in`. |
| **C3** | Verifier rejects wrong layer dims / indices vs episode. |
| **C4** | Verifier requires sumcheck round count = log₂(pad(k)). |
| **C5** | Verifier requires non-empty `trace_fri` / `lookup_fri` on real-episode proofs. |
| **C6** | Existing: round_seeds chain, layer-kind completeness, FRI verify, pow_bind/digest. |

---

## Decision (M7 / Fable)

Ship **g=40 / Fp2 / blowup=16 / Q=116**. Fp3 (`v³−2`) is an available-but-unbuilt
lever for grinding tiers g≥64 only — do not build it for this tip.

## Verdict

Succinct scaffold is **not** free of under-constrained wires. M7 closes the cheap
LogUp (input,output) binding and completeness checks, and locks adversarial
reject tests (a)–(g). **G1–G5 remain OPEN** and **block** `BTX_RC_GKR_ARBITER`
cutover until A/B openings + claim↔trace MLE + Extract table LogUp (or ExactReplay
oracle) land. Keep shadow ON / arbiter OFF / ExactReplay consensus.
