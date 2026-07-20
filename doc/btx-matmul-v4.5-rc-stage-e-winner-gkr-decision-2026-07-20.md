# ENC_RC Stage E — Winner-only GKR/sumcheck DECISION (2026-07-20)

*Tip base: `6b3f06b`. Status: **BINDING direction** for Stage E.*
Does **not** raise `nMatMulRCHeight` (remains `INT32_MAX`).

---

## Decision (BINDING)

**DECIDED: winner-only GKR/sumcheck** is the Stage E verification path.

| Alternative | Status |
|---|---|
| Winner-only GKR/sumcheck | **SELECTED** |
| Fraud-proof protocol (P2.1-b / bake-off D) | **Deferred** (not near-term) |
| Shrink episode for commodity ε=0 replay | **Fallback** if GKR verify cost fails Stage-I budget |

Code constant: `kRCGkrE5Decision` in `src/matmul/matmul_v4_rc_gkr.h`.

---

## Rationale

1. **Magnitude path:** Full HBM-scale residency/capacity levers require a verify path cheaper than full episode replay. Winner-only prove keeps miner overhead on rare winners; verify is the commodity-node budget.
2. **Fraud proofs** need a separate fork (challenge window, DA, bonds) — deferred until GKR verify is priced against Stage I.
3. **Shrink** preserves ε=0 digest-only recompute but dilutes the hardware-economics thesis; keep as fallback if GKR verify ≫ fraction of block interval.

---

## Soundness (computational)

Winner-only GKR/sumcheck provides **computational** soundness under:

- SHA256d Fiat–Shamir (domain-tagged ROM)
- Goldilocks field sumcheck bounds (~deg/|F| per round)
- Extract LogUp-style table openings via `ExtractMXTileInt64` oracle

This is **NOT ε=0**. Full exact STREAMED replay (`RecomputeResidentCurriculumReference` /
`CheckMatMulProofOfWork_RC`) remains the dispute/oracle until Stage-I cutover.

Constant: `kRCGkrSoundnessStatement`.

---

## Winner-only cost model

| Path | Prove cost | Verify cost |
|---|---|---|
| Losing nonce (digest > target) | **Zero** — never call `Prove*` | N/A |
| Winner / share (digest ≤ target) | After CPU reseal: `ProveWinner*` | Local / future consensus verify |
| Consensus today | No GKR on validation path | ε=0 full replay only |

Harness: `matmul-v4-rc-harness --prove-winner-gkr`  
Optional miner: env `BTX_RC_WINNER_GKR=1` inside `SolveMatMulV4RC` (default off).

---

## Cutover plan

1. **Now → Stage I gates:** ε=0 full replay remains sole consensus check. GKR is measurement + miner-optional only. Height stays `INT32_MAX`.
2. **Stage I (verify ≤ fraction of block interval + silicon G):** enable GKR verify as the happy-path check; keep optional challenge → full replay for disputes.
3. **Do not** unpark segment leaves / growth / three-axis enable solely from this decision — still need Stage G silicon and Stage I checklist.

**Decision alone does NOT raise height.** Magnitude path toward full HBM is *unlocked as a direction* once verify cost clears Stage I; G remains silicon-gated.

---

## Pointers

- Protocol: `src/matmul/matmul_v4_rc_gkr.{h,cpp}`, `matmul_v4_rc_gkr_field.h`
- Bake-off: `doc/btx-matmul-v4.5-rc-verify-bakeoff-stage-e.md`, `matmul-v4-rc-verify-bakeoff`
- Prior evidence: `doc/btx-matmul-v4.5-rc-validation-model-p2.1.md` (addendum)
- Master index: `doc/btx-matmul-v4.5-enc-rc-final-form-spec-2026-07-20.md`
