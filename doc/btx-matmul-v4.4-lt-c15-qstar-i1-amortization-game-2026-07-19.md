# Q* / I1′ multi-instance amortization game (Wave 3 Gap #9)

*Date: 2026-07-19. Branch: `feat/bmx4c-exact-accel-lanes`.*  
*Wave 3 Gap #9 deliverable. Sources: crypto survey §3 (BRSV as vocabulary
only); packet §§0.1, 3, 5; fold rank **9**; shortcut/TMTO S9/S10; GAP-D8.*  
***Do not claim C-15 cryptographically closed. Do not raise `nMatMulDRLTHeight`.***  
***Gap #10 (KW / transcript redesign) is out of scope — skipped.***

---

## 0. Why this note exists

Crypto survey §3 forbids citing Ball–Rosen–Sabin–Vasudevan (BRSV) fine-grained
PoW theorems as MatExpand hardness: those theorems price OV/3SUM/APSP
polynomials, not `(W_B ↦ digest)`. What *is* transferable is the **desired
theorem shape** — an average-case **direct-sum / non-amortization** statement
for many mining instances.

This note states that shape explicitly for BTX LT under **I1′** and **Q*
Phase A skinny grind**, marks it **heuristic / unproved**, and ties it to the
packet reviewer surfaces (I1-A/B/C, BA-C, SB annex). It does **not** prove
C-15 and does **not** import BRSV as a cited assumption.

---

## 1. Objects (pinned to packet §0.1)

| Symbol | Meaning |
|---|---|
| `HonestMAC(n)` | Exact-int MAC of one **marginal** nonce unit: MatExpand-B (`G·W`+`Y·H`) + `B̂·V` + combine `P·Q` |
| `C_tmpl(n)` | One-time template cost under I1′: MatExpand-A + `U`/`V`/`P=U·Â` (and cacheable `G`/`H` expand) — **excluded** from each marginal unit |
| `MineSlot(σ, nonce)` | Honest Phase-A path producing accepting digest `H(σ‖Ĉ)` (ENC-DR auth intact) |
| `Q* ∈ {64,128}` | Consensus window size (miner schedule Phase A; seal object Phase B) |
| Phase A | Lottery object = **per-nonce** digest (default when LT live; seal-as-PoW off) |
| Phase B | Lottery = `SealWindowCommit(σ, Merkle(leaves), Q*)` — **inert** on public nets (`nMatMulDRLTHeight=INT32_MAX`) |

I1′ *intentionally* amortizes `C_tmpl` once per template. The priced
non-amortization claim is about **nonce-fresh MatExpand-B** (and the sketch
path), not about forbidding template reuse.

---

## 2. Game: `BTX-I1p-QStar-DirectSum-v1` (shape only)

### 2.1 Multi-instance / direct-sum game (Phase A)

| Item | Definition |
|---|---|
| **Params** | Same as packet §0.1 (`n∈{64,256,4096}`, `w=128`, `b=2`, `m=n/2`, normative Extract) |
| **Challenger** | Samples a template (header / seeds) and allows the adversary poly-many honest `MineSlot` transcripts |
| **Adversary input** | Public template; may fix `Â,U,V,P` (I1′); must produce **fresh** nonce-bound `W_B` / digests |
| **Instance count** | Integer `t ≥ 1` (skinny grind: `t=1`; fat miner schedule: `t=Q*` or arbitrary batch) |
| **Honest multi-cost** | `Cost★(t) ≜ C_tmpl(n) + t · HonestMAC(n)` |
| **Win** | Output `t` accepting Phase-A digests (distinct nonces / slot ids under the same template) with exact-int MatExpand+BV+combine MAC total `≤ (1−δ)·Cost★(t)`, and Freivalds advantage `≥ ε` over false-accept (defaults: `δ=1/2`, `ε=2⁻⁴⁰` as in §0.1) |
| **Primary FAIL subclass** | Sublinear-in-`t` reuse of MatExpand-B / `B̂` / Expand tables across nonces (TMTO, cross-nonce Expand reuse, related-nonce GEMM skip) while digests still accept |

**Direct-sum *shape* (desired, not proved):**

```
Cost_A(t)  ≥  C_tmpl(n) + t · HonestMAC(n) − o(t · HonestMAC(n))
```

for classical PPT adversaries in the §0.1 class that output `t` accepting
Phase-A digests. Equivalently: after paying `C_tmpl` once, each additional
accepting nonce costs ≈ one full `HonestMAC` — **no** `o(t)` amortization of
the marginal B path.

### 2.2 What Phase A skinny grind means for the game

Under Phase A, consensus does **not** force the miner to evaluate a fat `Q*`
window for the lottery object (lottery = one digest). A “skinny” adversary
may set `t=1` repeatedly. The direct-sum claim still applies across many
independent grinds: `t` accepting headers / digests over time (same or fresh
templates) must not collapse to sublinear total MatExpand-B work.

| Mode | Lottery object | Honest work for one lottery win | Direct-sum pressure |
|---|---|---|---|
| **Phase A (live default)** | Per-nonce `H(σ‖Ĉ)` | `≈ HonestMAC` (after `C_tmpl`) | Multi-header / multi-nonce batch over time |
| **Phase B (inert)** | Seal over `Q*` leaves | `≈ C_tmpl + Q*·HonestMAC` per seal | Single-seal multi-instance (`t=Q*`); see packet §5 / SB-* |

Phase B would *instantiate* the `t=Q*` case inside one lottery object; it does
**not** prove the inequality, and it remains inactive on public nets.

### 2.3 Explicitly allowed vs forbidden amortization

| Class | Status in this game |
|---|---|
| Amortize MatExpand-A / `U`/`V`/`P` once per template (I1′) | **Allowed** — folded into `C_tmpl`, not a win |
| Cache template `G`/`H` panels | **Allowed** — still pay per-nonce `G·W`/`Y·H` |
| Reuse one MatExpand-B / `B̂` across many nonces or templates | **Win if** digests accept at `< (1−δ)·Cost★(t)` (I1-A) |
| Solve fresh `B̂` from fixed-`Â` sketch eqs cheaper than GEMM | **Win** (I1-B) |
| Q* windowing / batching that linearizes Extract | **Win** (BA-C) |
| Cross-anchor leaf reuse under Phase B seal | SB annex (packet §5) — separate surface |

---

## 3. Status: heuristic, not a theorem

| Claim | Verdict |
|---|---|
| BRSV CRYPTO’18 direct-sum applies to MatExpand | **No** — wrong task family (crypto survey §3.3) |
| Explicit game shape written for I1′ / Q* Phase A | **Yes** — this note (§2) |
| Direct-sum inequality proved for `(W_B ↦ digest)` | **No** — **HEURISTIC / UNPROVED** |
| Engineering boundary “marginal = MatExpand-B + BV + combine” | **Spec posture** under I1′; stress-tested via packet I1-*/BA-*/§0.1 |
| Closes C-15 / authorizes height raise | **No** |

**Name for firm SOWs (optional):** `BTX-I1p-QStar-DirectSum-Heuristic-v1` —
the §2 game treated as an **unproved multi-instance strengthening** sitting
beside `BTX-C15-NonCollapse-v1` (single-instance §0.1). A §0.1 FAIL at `t=1`
already breaks NonCollapse; a multi-instance-only FAIL (amortize across `t`
without beating single-instance HonestMAC) breaks this heuristic without
necessarily being the primary NonCollapse break mode.

**Relation to GAP-D8:** I1′, batch algebra, and Phase-B seal remain **separate
surfaces** (packet §§3–5). This game formalizes the I1′/Q* multi-instance
*shape*; it does not collapse those surfaces into a single named-problem
reduction.

---

## 4. Reviewer checklist (falsifiable)

| ID | Question | Artifact |
|---|---|---|
| DS-A | For `t∈{1,Q*,poly}` under one template, is total Expand-B+BV+combine MAC `≥ (1−δ)·Cost★(t)` for known attacks? | MAC accounting table vs `HonestMAC` |
| DS-B | Does any TMTO / cross-nonce Expand table beat linear `t`? (packet §0.2 attack #4) | Attack or resource lower-bound argument |
| DS-C | Does related-nonce Mant/Scale XOR yield cross-nonce GEMM skip? | Related-nonce note — expected **no** for MatExpand floor |
| DS-D | Phase A skinny: confirm lottery underprices fat-window *intent* (strategy text) while still pricing `HonestMAC` per digest | Normative + adversarial Q* sections |
| DS-E | Phase B (if in SOW): does seal force `t=Q*` leaf digests with slot-id bind? | SB-A..D — inert today |

Return **HEURISTIC-HOLD** / **HEURISTIC-BREAK** / **INCONCLUSIVE** for
`BTX-I1p-QStar-DirectSum-Heuristic-v1`. Do **not** translate HEURISTIC-HOLD
into C-15 PASS or a height raise.

---

## 5. Cross-links

- Packet: `doc/btx-matmul-v4.4-lt-external-c15-packet.md` §§0.1, 3, 5, 6.1
- Crypto survey §3: `doc/btx-matmul-v4.4-lt-c15-reduction-survey-crypto-2026-07-19.md`
- Fold rank 9: `doc/btx-matmul-v4.4-lt-c15-reduction-research-synthesis-2026-07-19.md`
- Drafts GAP-D8: `doc/btx-matmul-v4.4-lt-c15-reduction-drafts-2026-07-19.md`
- Related-nonce (no MatExpand amortize): `doc/btx-matmul-v4.4-lt-c15-related-nonce-reduction-note-2026-07-19.md`

---

## 6. Explicit non-claims

- C-15 closed — **NO**
- BRSV cited as MatExpand assumption — **NO**
- Direct-sum proved — **NO** (heuristic shape only)
- Gap #10 KW redesign — **skipped / out of scope**
- Finite public `nMatMulDRLTHeight` — **NO**

*End Gap #9. C-15 remains OPEN.*
