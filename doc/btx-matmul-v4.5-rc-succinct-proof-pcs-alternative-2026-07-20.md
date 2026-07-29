> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# ENC_RC succinct proof — PCS alternative decision research (M10) — 2026-07-20

*Recommend, don't decide. `nMatMulRCHeight = INT32_MAX`. Arbiter OFF.*
*Companions: soundness note (M6/M8), arithmetization completeness (M7).*

## Question

Keep hand-rolled REAL FRI (`matmul_v4_rc_fri.*`) as the PCS, or integrate a
vetted transparent Goldilocks STARK stack (Plonky3, Winterfell, RISC0-style)?

## Criteria matrix

| Criterion | Hand-rolled FRI (in-tree) | Plonky3 | Winterfell | RISC0 zkVM-style |
|---|---|---|---|---|
| **Proven vs conjectured soundness** | Unique-decoding shipped (M6); BCIKS20 optional (M11) — bound owned in-tree | Upstream FRI params; often mix of proven-gap + engineering tables | Similar; Rust STARK core | Full zkVM stack; FRI/hash choices upstream |
| **Query-count regime** | Q=116 unique-dec (ρ=1/16,g=40) → 65 bits claimed | Can use higher blowup / fewer queries under their tables | Configurable | Not a drop-in PCS for our GKR wire |
| **Consensus dependency** | **None** — hashes/FS already BTX | **Yes** if linked into consensus verify | **Yes** if linked | **Unacceptable** as consensus verify dependency (zkVM + toolchain) |
| **License** | MIT (BTX) | Apache-2.0 / MIT (typical) | Apache-2.0 / MIT | Apache-2.0 |
| **Goldilocks / Fp2** | Native (`matmul_v4_rc_gkr_field_ext.h`) | First-class Goldilocks | Generic field; Goldilocks used in practice | Own ISA; not our Fp2 transcript |
| **Audit surface** | Small FRI+GKR (~few KLoC) + our binding | Large crate graph + our glue | Large crate + FFI | Enormous (zkVM) |
| **Maintenance** | Own every FRI bug / param fix | Track upstream releases / CVEs | Same | Same + guest toolchain |
| **pow_bind / FS bind** | Full control | Must re-bind carefully | Must re-bind carefully | Harder (host/guest) |

## Consensus-dependency argument (decisive)

ENC_RC verify sits next to `CheckMatMulProofOfWork_RC`. Pulling Plonky3/Winterfell/
RISC0 into **consensus** means every node builds and trusts that stack forever —
supply-chain, ABI, and soundness-claim churn become consensus risk. That is
**likely unacceptable** for BTX until (a) the PCS is frozen as a reviewed
subtree with pinned commits and (b) an independent audit covers both the
vendored core **and** BTX FS/`pow_bind` glue.

A **shadow-only** or **research harness** vendor is fine; consensus ExactReplay
must remain the arbiter until then.

## Recommendation for the owner

1. **Default: hand-rolled-but-audited FRI** — keep M6 unique-decoding params;
   close M7 G1–G5; commission human audit of M6/M8 before any arbiter ON.
2. **Do not** introduce Plonky3/Winterfell/RISC0 as a consensus dependency for
   the first arbiter cutover.
3. **Optional later:** if audit prefers a named STARK core, vendor a **pinned
   subtree** behind the same GKR/LogUp arithmetization and the same
   shadow/ExactReplay wiring — treat as a PCS swap, not a product rewrite.
4. **Never** claim either path production-complete without Gate M3 external
   audit + real M4 silicon cost (OUT OF SCOPE here).

## Non-goals

- Flipping `BTX_RC_GKR_ARBITER`
- Raising `nMatMulRCHeight`
- Inventing silicon prove rates from vendor blogs
