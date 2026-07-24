## Status: superseded framing — current design is ENC_RC v4.6 (two-stage: profile-2 episode + profile-3 coupled)

This document is an earlier v4.5 design stage; its framing and numbers are
superseded. The shipping design is **ENC_RC v4.6**, a two-stage proof of
work: Stage/profile 2 is the **ENC_RC datacenter episode**
(`nMatMulRCProfile = 2`, default) — an exact-int64 AI-training episode
(attention + micro-training + Merkle); Stage/profile 3 is the
**ENC_RC_COUPLED V3 production puzzle** (`nMatMulRCCoupledProfile = 3`,
default), HBM-resident, entangled with the episode via a shared transcript.
At relay time, accept/reject for the profile-2 carrier is decided by an
FS-sampled sublinear carrier verifier — an honest **work-skipping soundness**
bound, not a claim that every wrong tile is caught — while the **int64 CPU
ExactReplay reference** remains the asynchronous dispute-path arbiter and the
ultimate consensus authority. Activation is **disabled** on every public
network (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`). For the
current, canonical description see
`doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. The body below is
retained unchanged for historical/provenance purposes.

---

# BTX MatMul v4.5 (ENC_RC) — FINAL-FORM Specification

*Date: 2026-07-20. Branch: `claude/matmul-v4-design-spec-af23sj` (PR #89).*
*Status: final-form Stages A–F/H scaffolding + Stage E bake-off landed; Stage C multi-backend probe + parametric medium scaffolding this wave. **Public activation remains NO-GO** (`nMatMulRCHeight = INT32_MAX`). Stage G: CPU campaigns measured on this box; GPU still SILICON-GATED. **Stage E DECIDED: winner-only GKR/sumcheck** (see decision doc).*

This document is the master index for the FINAL-FORM build (Stages A–I). It
restates the committed design, records what landed this wave, and keeps
activation policy fail-closed. It supersedes treating the §R.7 two-dial growth
push as the final scale model; Stage F’s three-axis schedule is the redesign
surface (still PROVISIONAL and inert).

---

## 1. WHAT v4.5 IS (committed design — packet §0)

v4.5 replaces the single-GEMM workload with a per-nonce **coupled puzzle** that
jointly demands three resources:

1. low-precision tensor **COMPUTE**,
2. large high-bandwidth resident **MEMORY**,
3. fast coherent **INTERCONNECT**.

A per-nonce episode is a short recurrent loop of **mixing barriers**:

local exact low-precision matmuls on many parallel lobes → a nonce-derived
balanced permutation → an exact integer all-to-all exchange over the whole
state → one non-affine integer Extract → feed forward with a sequential
backward/checkpoint dependency. The final digest is compared to the difficulty
target.

**Difficulty behaves exactly like Bitcoin:** ASERT auto-retargets so blocks
arrive on a fixed schedule regardless of total network power; block reward
unchanged. The novelty is only in the **workload** that produces the digest,
never in the difficulty mechanism.

**Outcome:** reward flows to the strongest coherent datacenter node
(compute × memory × interconnect together); a PCIe cluster of cheap cards pays
the interconnect penalty and is uneconomic; old / loosely-connected / small
machines **complete** the identical episode by paging / checkpointing /
streaming — valid, never rejected, just slow and uneconomic; owner-operated
cheap-power hardware always keeps marginal profitability.

**The Stage E direction is locked (winner-only GKR),** which sets magnitude:

| Stage E outcome | Puzzle scale | Separation (order of magnitude) |
|---|---|---|
| cheap sound winner-only proof works | full HBM-scale | ~14–28× |
| it does not | shrink to full-node-replayable (same structure) | ~5–10× |

Either way the character is identical: coupled puzzle, Bitcoin difficulty,
biggest-brain-wins, nobody excluded.

### Global invariants

- **ε = 0** exact integer. The plain-C int64 CPU reference is the **sole**
  consensus ground truth.
- Consensus DAG, dimensions, dependencies, reductions, and digest are
  **identical** on every machine and every device count. Residency / paging /
  sharding / checkpointing are **non-consensus** execution policies that MUST
  NOT change any committed byte.
- Every execution mode (**Resident / Checkpointed / Streamed**) → byte-identical
  digest.
- **No hard gate:** the smallest machine (8 GiB) always **completes** the
  identical nonce.
- `nMatMulRCHeight = INT32_MAX` on all public networks until every Stage-I gate
  passes.
- Do not run the full unit suite on a compute-limited box; build targeted test
  binaries.

---

## 2. Stage A–I status (this wave + honest residuals)

| Stage | Status | What landed / pointer |
|---|---|---|
| **A** — consensus hazards | **PARTIAL** | V1 golden `b339d0ff…` + `kRCTranscriptVersion` / `ENC_RC_V1` (`matmul_v4_rc.h`); segment leaves + §R.7 growth **PARKED**; int64 Extract; golden gate `contrib/matmul-v4/rc-golden-gate.py`. Brake omitted from Stage F three-axis path (F6). |
| **B** — bounded-memory transcript + planners | **PARTIAL** | `RoundMerkleStream` + `matmul_v4_rc_transcript.{h,cpp}` Resident/Streaming sinks (`matmul_v4_rc_transcript_tests`). Full planner surface may still grow. |
| **C** — coupled puzzle | **DONE (inert)** | `matmul_v4_rc_coupled.*` toy+medium; 4 modes digest-identical; ExactGemm inject; `ENC_RC_COUPLED` + `nMatMulRCCoupledHeight=INT32_MAX` + `CheckMatMulProofOfWork_RCCoupled` / `SolveMatMulV4RCCoupled` (regtest-only enable). **Public activation NO-GO.** GPU SILICON-GATED. |
| **D** — distributed bit-exactness | **PARTIAL** | `matmul_v4_rc_distributed.{h,cpp}` + `matmul_v4_rc_distributed_tests` (topology parity scaffold). |
| **E** — verification bake-off | **DECIDED** | **Winner-only GKR/sumcheck** (`matmul_v4_rc_gkr.*`). Fraud-proof deferred; shrink is fallback if verify fails Stage-I budget. Decision doc: `doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md`. Does **not** raise height. |
| **F** — three-axis schedule | **DONE (PROVISIONAL, inert)** | `src/matmul/matmul_v4_rc_scale_axes.{h,cpp}`: dials `W_state`, `C_local`, `X_exchange`; O(1) memoized epoch eval; **no chainwork brake (F6 omitted)**; checked prior-dim fallback (no assert); hard caps; pause-only growth; `kRCThreeAxisScheduleEnabled = false`. **Ratios freeze only after Stage G silicon evidence.** |
| **G** — numeric hardware gates | **SILICON-GATED** (CPU PARTIAL) | CPU toy/medium/coupled campaign walls measurable on this host (`rc-gate.py` / harness `--coupled`). GPU B200/MI355X/5090 / NVLink-vs-PCIe still **unmeasured** — nonempty reports never PASS without numeric G2/G3/G4 silicon. Net-cost software model is SIMULATED / NOT EVIDENCE. |
| **H** — required tests | **PARTIAL** (scaffolding) | Extended `src/test/matmul_v4_rc_tests.cpp`: V1 golden; Resident/Checkpointed/Streamed digest equiv; topology pointer → Stage D; soft memory-budget; golden-diff gate (+ `rc-golden-gate.py`). Full production-size / cross-vendor / proof-malformed suites remain OPEN with C/D/E/G. |
| **I** — activation policy | **DONE (policy)** | `nMatMulRCHeight` remains `INT32_MAX` (`params.h`, chainparams assert). Checklist below — do not encode a finite height until every gate passes. |

### Honest residuals (do not paper over)

1. **Stage G needs real hardware for GPU / interconnect gates.** CPU campaign walls on this box are PARTIAL evidence only; MAC/heuristic curves and simulated net-cost are NOT EVIDENCE for Stage-I gate 4.
2. **Stage E is DECIDED (winner-only GKR/sumcheck).** Fraud-proof deferred; shrink is fallback if GKR verify fails Stage-I budget. Decision alone does not unpark segment leaves / growth / three-axis enable, and does not raise height — Stage I + G silicon still required.
3. **Stage C toy/medium ≠ HBM-scale.** Digest/oracle correctness at toy or CI medium dims does not prove 8 GiB Streamed production or interconnect separation. GPU ExactGemm for coupled remains SILICON-GATED.

---

## 3. Stage I — activation checklist

Keep `nMatMulRCHeight = INT32_MAX` and all growth / three-axis constants
**PROVISIONAL**. Activation is considered **ONLY** after **all** of:

1. Stage A consensus hazards closed (goldens versioned; Extract int64; no half-wired brake).
2. An **8 GiB** bounded-memory (Streamed / Checkpointed) run succeeds on the
   identical consensus episode.
3. Native accelerator paths proven without CPU masking (A5 / Stage C / Stage D).
4. Coupled communication has a **measured** lower-bound / performance effect
   (Stage G: ≥7× NVLink-vs-PCIe on the same chips).
5. Verification security **and** cost independently reviewed (**Stage E decision
   made** — winner-only GKR; still need measured verify ≤ fraction of block
   interval before treating magnitude as production-ready).
6. Same-tip silicon + economic gates pass (**Stage G**; `rc-gate.py` GO offline
   tally only — still not an automatic height raise).

**Only then** encode a finite height-only three-axis schedule (enable Stage F
after ratios freeze) and set an activation height via a clean flag-day cutover
(all other MatMul heights stay `INT32_MAX` unless already live by prior policy).

This document **never** recommends raising `nMatMulRCHeight` from scaffolding,
toy measurements, or §R.7 / three-axis projections.

---

## 4. Definition of Done (packet)

A B200 / MI355X-class coherent node behaves as the “higher-powered brain”: full
expert/state bank + multiple evolving contexts resident, all lobes concurrent,
state exchanged over coherent fabric — winning reward-per-dollar. A 32 GiB or
8 GiB machine solves the **identical** puzzle by time-multiplexing,
checkpointing, and paging — much slower, likely uneconomic, but **never** made
consensus-invalid merely because its memory is smaller. Difficulty
auto-retargets exactly as in Bitcoin; block reward unchanged; the only thing
that changed is which hardware can afford the attempts.

---

## 5. File index (this wave)

| Path | Role |
|---|---|
| `src/matmul/matmul_v4_rc_scale_axes.h` | Stage F three-axis dials + enable flag (default false) |
| `src/matmul/matmul_v4_rc_scale_axes.cpp` | Memoized O(1) epoch eval; checked fallback; no brake |
| `src/matmul/matmul_v4_rc_transcript.*` | Stage B Resident/Streaming sinks |
| `src/matmul/matmul_v4_rc_coupled.*` | Stage C coupled puzzle (toy + medium params; ExactGemm inject) |
| `src/matmul/matmul_v4_rc_coupled_device.*` | Stage C `ProbeRCCoupledDevice` (CUDA/HIP/Metal readiness; skip without GPU) |
| `src/matmul/matmul_v4_rc_coupled_netcost.h` | Stage G software interconnect model (SIMULATED / NOT EVIDENCE) |
| `src/matmul/matmul_v4_rc_distributed.*` | Stage D distributed bit-exactness scaffold |
| `src/matmul/matmul_v4_rc_verify_bakeoff.*` | Stage E verification bake-off prototypes |
| `src/matmul/matmul_v4_rc_gkr.*` | Stage E DECIDED winner-only GKR/sumcheck |
| `doc/btx-matmul-v4.5-rc-stage-e-winner-gkr-decision-2026-07-20.md` | Stage E BINDING decision |
| `src/test/matmul_v4_rc_tests.cpp` | Stage H scaffolding cases + Stage F inert checks |
| `contrib/matmul-v4/rc-golden-gate.py` | Frozen V1 golden-diff gate (A1 / H) |
| `contrib/matmul-v4/rc-gate.py` | GO/NO-GO; nonempty reports need numeric thresholds |
| `doc/btx-matmul-v4.4-resident-curriculum-unified-proposal-2026-07-20.md` | §R normative substrate (status table points here) |
| `doc/btx-matmul-v4.5-rc-validation-model-p2.1.md` | Stage E evidence + DECIDED addendum |
| `doc/btx-matmul-v4.5-rc-phase-split-evidence-p2.2.md` | Phase-split measurement evidence |

---

*End of final-form master spec. Tip `91a687b` + this wave’s scaffolding; height unchanged.*
