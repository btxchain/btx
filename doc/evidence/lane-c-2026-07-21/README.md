# Lane C evidence — 2026-07-21 (PR #89)

> **Historical PR89 evidence.** Preserve the artifacts and measurements below,
> but do not interpret its profile/default or proof-carrier conclusions as the
> MatMul v4.7 launch plan. Epoch A now targets Profile 1 ExactReplay; proofs
> transition through mandatory dual validation and Profile 1 authority before
> a separate Profile 2 fork. See
> [`../../btx-matmul-v4.7-transition-roadmap.md`](../../btx-matmul-v4.7-transition-roadmap.md).

Tip: `bf36b7d`. Device: RTX 5060 Ti 16 GB sm_120 (Linux test host).
Height/arbiter unchanged. Gate: **NO-GO**.

| Section | Artifact | Status |
|---|---|---|
| C0 | `c0/c0-confirmations.json` | done |
| C1 | `c1/c1-production-episode.json` | ExactReplay **IN PROGRESS** (≥8416 s LB) |
| C2 | `c2/c2-validator-matrix.json` | done (toy/medium; production GKR deferred) |
| C3 | `c3/c3-coupled-production.json` | done (TBD-1 closed) |
| C4 | `c4/c4-stageg-kgate.json` | done (k≈1.23 < 1.3) |

The private full campaign archive is not committed; the reviewable subset is
contained in this directory.
