# 0.34.8 requirement disposition — method and reading guide

Reviewer `r-disposition-20260917`. Companion to `audit/requirement-traceability.csv`.

## What was audited

| Item | Value |
|---|---|
| Tree | `/home/administrator/btx-0.34.7-private` |
| Branch | `feat/0.34.8-modelnet-first-run` |
| Freeze HEAD | `573b4aa41f26ea6c61a00ee6096c5ff4de319335` plus uncommitted 0.34.8 work (295 dirty tracked, 246 untracked at freeze, see `final-convergence-baseline.md`) |
| Primary spec | `.0348-expanded-package.local/BTX_0348_Expanded_Package/BTX_0.34.8_Expanded_Implementation_Spec.md`, read in full including appendices A, D and E |
| Also read | package `START_HERE.md`, `audit/BASELINE_FINDINGS.md`, `schemas/rpc-catalog.json` (54 methods), `audit/acceptance-matrix-0.34.8.csv`, `audit/0348-remaining-unique-todos.md`, `audit/performance-0.34.8.md`, `audit/r9-compat.md`, the r1–r11 independent reviews, and the HCP/CEX, CR11/CRF, JIT and AHP packages under `.0348-*.local` |
| Build | none. No compile, no C++/CMake edit, no test execution in this round. Statuses cite runs already recorded in the tree |
| Exclusive write | `audit/requirement-traceability.csv` (plus this notes file) |

## Row model

1537 rows, one per requirement or subrequirement, every row carrying one of the six mandated statuses. No blank status, no duplicate `requirement_id`, and **no implicit parent coverage**: a section-level row never stands in for its bullets, and no bullet inherits a parent's status. Where a section has twenty bullets it has twenty rows.

| Section group | Rows | Source of the requirement text |
|---|---:|---|
| Release-blocking findings `V-01..V-08` | 8 | spec 3.2 |
| Package baseline findings `AUD-01..AUD-12` | 12 | spec 3.3 / `BASELINE_FINDINGS.md` |
| Spec sections 1–24 (`S-*`) | 600 | spec body, per bullet |
| References register and appendix A adoption (`S-REF-*`, `S-A-R01..R32`) | 35 | spec references and per-source adoption consequence |
| Appendix D RPC contracts (`S-D-<method>`) | 54 | `schemas/rpc-catalog.json`, one row per catalogued method |
| Appendix E protocol detail (`S-E.*`) | 153 | E.1 limit table row by row, then E.2–E.15 |
| HCP / CEX family | 139 | `audit/hcp-requirement-traceability.csv` |
| CR11 / CRF family | 240 | `audit/cr11-requirement-traceability.csv` |
| AHP family | 114 | `audit/agent-package-acceptance-native.csv` |
| JIT capability family | 182 | JIT package spec ids, enumerated natively by `jit_all_182_ids_enumerated` |

## Status distribution

| Status | Spec rows | Family rows | Total |
|---|---:|---:|---:|
| IMPLEMENTED_AND_PROVEN | 472 | 500 | 972 |
| IMPLEMENTED_WITH_GAP | 275 | 64 | 339 |
| DEFERRED_WITH_EVIDENCE | 31 | 82 | 113 |
| IMPLEMENTED_NOT_YET_PROVEN | 50 | 29 | 79 |
| MISSING | 27 | 0 | 27 |
| INCOMPATIBLE_BY_DESIGN | 7 | 0 | 7 |

## How each status was applied

- **IMPLEMENTED_AND_PROVEN** — code exists and a run recorded in this tree asserts the requirement's effect, not merely the presence of a name. Every such row names the case. The tier is native unit, in-process integration, or a loopback multi-process functional. It never means WAN, live cloud, live CEX, GUI or accelerator.
- **IMPLEMENTED_NOT_YET_PROVEN** — the code path exists and was read, but nothing asserts it. Typical causes: no sanitizer tree, no second peer, no injected failure.
- **IMPLEMENTED_WITH_GAP** — the requirement is partly satisfied and the missing part is named in the row. This is the status for "the behaviour exists but under a different name or without one required element", e.g. the error taxonomy codes that exist as `BUDGET_EXCEEDED` rather than `BUDGET_EXHAUSTED`.
- **MISSING** — no implementation, alias or registration anywhere in the tree. An honest `NOT_RUN` never justifies MISSING and MISSING is never used where a run is merely absent.
- **DEFERRED_WITH_EVIDENCE** — deliberately not done this round, with the reason and the blocking condition recorded in the tree (operator-gated, hardware absent, disk pressure, or a recorded refusal such as the 64 MiB release-wrap ceiling).
- **INCOMPATIBLE_BY_DESIGN** — the spec text asks for something the design refuses on purpose (no remote inference, no FastTrack source, no decompression path to validate).

## Honest NOT_RUN, carried as such

These are recorded as gaps or deferrals and are never counted as proof: F2 wallet signing, `-modelindex`, `BUILD_GUI` (Qt journeys), live R2 and live Hugging Face WAN legs, sustained 400 GiB payload I/O, uTP/QUIC (NONSHIPPING), the `btx-torrentd` worker process, CUDA/ROCm/Metal execution, retargeting the catalogue onto PieceStore/S3, Package Core v4, and a second `HcpEngine`. HCP and CR11 native cases plus the process functionals are classified as proven **at native/process lab tier only**; no row upgrades them to WAN or live CEX.

## Correction of the previous ledger

The previous `requirement-traceability.csv` had 241 rows and 118 `IMPLEMENTED_AND_PROVEN`, including parent `S-*` rows that claimed proof for whole sections whose bullets were not individually evidenced. That over-claim is removed: parents no longer carry section-wide proof, each bullet is dispositioned on its own evidence, and the parent-level rows that remain describe only what their own row asserts.

Findings re-checked at this HEAD: ten of the twelve package findings (`AUD-01..AUD-12`) are fixed and retested against the private tree; `AUD-08` (streaming release wrapping) stands as a recorded refusal above 64 MiB and `AUD-12` (doc/registry reconciliation) stands as a gap because one catalogued method has no implementation.

Two claims found elsewhere in the tree are **not** accepted as evidence here:

- The agent-package review's claim of a built `WITH_MODELNET=OFF` tree with 31/31 passing is unsubstantiated. `contrib/modelnet/check-with-modelnet-off.sh` performs source gating checks and explicitly does not build. `S-1.2-d` is therefore DEFERRED_WITH_EVIDENCE, not proven.
- A stale note that monetary RPC dies with the helper is wrong at this HEAD; `feature_modelnet_0348_ops.py` shows `getblockcount`/`getblockchaininfo` surviving a stopped helper on an isolated regtest node, which is why `S-1.2-c` is proven.

## Load-bearing gaps a reader should look at first

1. **Idempotency is absent on the write surface** (`S-21-g`, and the 27 `S-D-*` rows for idempotency-required methods). The catalogue requires a caller-scoped `idempotency_key`, an expected generation and an `authorization_ref` on costly writes. Only the capability and bounty paths read a key, and only `capability_ensure` reads an expected generation; the NETWORK-02 write handlers accept and ignore all three, so a client retry can start a second import.
2. **No signed-metadata equivocation or tombstone floor** (`S-18.1-b`, `S-18.3-g`, `S-E.12-d`, `S-E.12-f`, `S-E.12-h`). Reconciliation messages carry no snapshot generation, so there is no restart/rebase behaviour, an old signed record can reappear after compaction, and an aged-out event cursor cannot be reported to a watch consumer.
3. **The torrent plane has no worker and no library** (`S-5.1-e`, `S-4.3-c`, `S-12.4-*`, `S-E.8-d`, `S-E.8-e`, `S-A-R07`, `S-20.4-c`). The in-tree bridge is an offset mapper over fixtures; there is no `btx-torrentd`, no pinned libtorrent, and therefore no disk or hash callback contract to satisfy.
4. **The multipart journal cannot reconcile a crash** (`S-E.6-a`, `S-E.6-b`, `S-E.6-d`). Five phases instead of seven, no planned-versus-sent distinction, no `REMOTE_OUTCOME_UNKNOWN`, and no `ListParts` call, so a crash between dispatch and receipt is not resolvable against the provider.
5. **No cloud budget object and no measured performance** (`S-10.4-a`, `S-E.1-lim-cloud-ops`, `S-22.3-f`, `S-22.3-g`). `OperationBudget` does not exist as a type; estimates are advisory. The performance ledger names each required metric and records every one as NOT_RUN, with 7.9 G free disk as the stated blocker.
6. **Capability negotiation exchanges bare names** (`S-E.2-*`, `S-E.1-b`). `HelloCapabilityArray` advertises version-suffixed strings with no min/max version and no numeric caps, so a peer cannot learn a feature's limits and there are no minima to intersect. Host limits are compile-time constants, so the safety-critical half — a remote cannot raise a limit — does hold.
7. **`getsubscriptionactivity` does not exist** (`S-D-getsubscriptionactivity`, `AUD-12`). 53 of 54 catalogued methods resolve, several through documented aliases; this one has no implementation, alias or registration.
8. **Evaluated-work items remain written results** (`S-E.15-*`). uTP, QUIC, one-hop search privacy, content-defined dedup, the 64/80 erasure profile and 10M catalog scaling are each recorded NONSHIPPING or NOT_RUN with an owner and rationale, but E.15 requires a prototype or a minimal reproducer, and no operator approval has been recorded for any of them.

## Family rows: how the mapping was made

Family `requirement_id` values are inherited verbatim from their source ledgers and prefixed (`HCP-`, `CR11-CASE-`, `CR11-OP-`, `AHP-`), so an HCP row id can be a phrase rather than a code; that is how the HCP ledger names its requirements and the row points back at the exact source line.

- **HCP** — status from `evidence_tier` plus `live_gap`: a row with no live gap is proven at its recorded tier; a row with a gap (live CEX IdP, live HSM, live conversion, partner ledger, real browser) is DEFERRED_WITH_EVIDENCE with that gap quoted.
- **CR11** — status from the `quality` column that the CR11 audit already assigned: `REAL` proven, `WEAK` gap with the reviewer's own remark, `TAUTOLOGY` and `STUB` (`BOOST_CHECK(true)` only) not yet proven, `UNHIT` (handler exists, no case reaches it) not yet proven. 29 rows carry tier `NOT_RUN`.
- **AHP** — `PASS` proven at native tier; the single `AHP-J03` remains deferred for lack of an independent-organisation lab.
- **JIT** — all 182 ids are enumerated and asserted natively; 17 are DEFERRED_WITH_EVIDENCE because their leg needs hardware or a live runtime that this host lacks (CUDA, ROCm, Metal, GPUDirect Storage, NIXL/UCX, CXL, macOS FUSE, kernel isolation).

## Reproducing this file

`audit/.gen-disposition.py` writes the CSV deterministically and asserts that no status is blank and no `requirement_id` repeats. It reads the three family CSVs from `audit/` and the JIT id titles from the JIT package spec. Re-running it regenerates `audit/requirement-traceability.csv` byte for byte.
