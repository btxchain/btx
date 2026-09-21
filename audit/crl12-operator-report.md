# CRL/1.2 operator report — 2026-09-17

**Status: NOT_READY** (no push, no merge, no tag, `IS_RELEASE` false, `CLIENT_VERSION` 0.34.8-dev).  
Production GPU attestor / `btxd` on the signer host: **untouched**. Isolated-regtest only.

## Tree

| Item | Value |
|---|---|
| Path | `/home/administrator/btx-0.34.7-private` |
| Branch | `feat/0.34.8-modelnet-first-run` |
| HEAD (git) | `573b4aa41f26ea6c61a00ee6096c5ff4de319335` |
| Package | `BTX_Cognitive_Reserve_Layer_v1_2` → `contrib/modelnet/crl12/` + `doc/modelnet/crl12/` |
| Isolated prefix | `$HOME/.local/opt/btx-0.34.8-regtest` (not recopied this round; process tests used `build-gcc13/bin/btx-hcpd`) |

## Fingerprints (this prove)

| Binary | SHA-256 |
|---|---|
| `build-gcc13/bin/test_btx` | `1db735409990b2ed12012fbd8824b7aac96d66fed424da3f59a18aff5e6b6a09` |
| `build-gcc13/bin/btx-hcpd` | `08036869281c09a6bc52e4a25fd385222d6837bbfc412b53e6fde04e80e263c4` |
| `contrib/modelnet/crl12/schemas/operations-v1.2.json` | `98a4e5005f078a9bba59bb8972103674642c427ec06b90dfdc8cc9ea86c94651` |
| `src/modelnet/hcp_crl12_engine.inc.cpp` | `36cc02a672dc066234883edc24c25fb82bf28268911d86791eb5562fec9956ac` |

## Contract

- Preserved HCP/1 + CR11 operations: **84**
- New CRL/1.2 operations: **43** (all registered on the same `HcpEngine`)
- Combined: **127**
- New signed types: **18** V1_2 (engine names + package aliases in `kTypes`)
- Discovery: `GET /extensions/cognitive-reserve` unchanged; v1.2 at `GET /extensions/cognitive-reserve/v1.2`
- Money path: still `POST /capital/allocations/{id}/execute` after v1.1 approvals
- `translatePortfolioInstruction`: draft-only `CapitalPlan` / `AllocationPlan`
- Import commit: `custody_credit=false`, `spendable_created=false`
- `automatic_spend_atoms`: **0**
- Brand dispatch: `BRAND_DISPATCH` on `/layer/` POST
- Core v4: `CORE_V4_FORBIDDEN`
- QUIC: still NONSHIPPING
- No second engine / ledger / downloader

## Tests by tier

| Tier | Result |
|---|---|
| Native `modelnet_cr12_*` + `modelnet_cr11_comp_tests` | **211 cases, PASS** (`./bin/test_btx --run_test=modelnet_cr12_*,modelnet_cr11_comp_tests`) |
| Native 100k-row `Crl12LoadSynthetic` | **PASS** (J17 / CR12-PROJECTION-07) |
| Native 10m-row | **HONEST_NOT_RUN** (`BTX_CR12_10M_LAB` unset) |
| Process J01–J20 `feature_modelnet_cr12.py` | **PASS** (loopback `btx-hcpd`, `num_nodes=0`, no production `btxd`) |
| Process scale `feature_modelnet_cr12_scale.py` | **PASS** (32-row HTTP batch 0.0037s) |
| Package `test_reference.py` | **82 PASS** (package-only; not native) |
| Python SDK | **26 PASS** |
| TypeScript SDK | **16 PASS** |
| Portal static a11y | **PASS**; Playwright **HONEST_NOT_RUN** (module not installed) |
| `validate_package.py` | **HONEST_NOT_RUN** in-tree (writes `qa/` which is not copied) |
| OAUTH_LAB / NATIVE_CHAIN / CUSTODY_LAB / GPU fabric | **HONEST_NOT_RUN** |
| In-flight async job cancel | **HONEST_NOT_RUN** (jobs commit immediately; `JOB_PENDING` unused) |

Process HONEST_NOT_RUN (by design, not faked PASS): PlanLocal/EnsureLocal HTTP, unique beneficial_id AUC collapse, family-view HTTP setter, DisconnectProvider HTTP, 100k/10m over 1 MiB hcpd body, `Crl12SetEnabled(false)` HTTP flag.

## Code map

| Piece | Location |
|---|---|
| Types / errors | `src/modelnet/hcp_types.h` |
| Helpers | `src/modelnet/hcp_crl12.cpp` |
| 43 routes | `src/modelnet/hcp_crl12_engine.inc.cpp` (included from `hcp_engine.cpp`) |
| Dispatch | `HandleLocked` v1.2 **before** CR11 |
| Persist | `PersistObj` / `Restore` CR12 maps; daemon persist after Handle |
| Walletless CR12 | `btx-hcpd -cr12=1` |
| Native TUs | `src/test/modelnet_cr12_*_tests.cpp` (19 files) |
| Process | `test/functional/feature_modelnet_cr12.py`, `_scale.py` |
| SDK / portal | `contrib/modelnet/crl12-sdk/`, `contrib/modelnet/crl12-portal/` |
| Spec copy | `doc/modelnet/crl12/`, `contrib/modelnet/crl12/` |

## Independent audits

| Review | File | Outcome this round |
|---|---|---|
| R1 authority | `audit/crl12-r1-authority.md` | Boundaries hold (draft-only, no custody credit, spend=0). Open: outbound type-name drift, GET not tenant-scoped, bindings always ACTIVE, no Idempotency-Key. |
| R2 metrics | `audit/crl12-r2-metrics.md` | Eligibility + `no_grand_total` hold. Open: Aggregate does not sum priced money (counts/`0`). |
| R3 recovery | `audit/crl12-r3-recovery.md` | Persist/Restore **fixed** after this review (`cr12_recovery_11`). Jobs still SUCCEEDED immediately. |
| R4 privacy | `audit/crl12-r4-privacy.md` | no-store on daemon; no tokens in export lab. |
| R5 neutrality | `audit/crl12-r5-neutrality.md` | Brand denylist + generic roles. |
| R6 portability | `audit/crl12-r6-portability.md` | Package type names accepted inbound; outbound still engine names. |
| R7 call-path | `audit/crl12-r7-callpath.md` | **43/43 handlers present.** 9 ops return envelope instead of Job. |
| R8 UX | `audit/crl12-r8-ux.md` | SDK/portal closed at Python/TS/HTML. |
| Remaining | `audit/crl12-remaining-gaps.md` | Ranked fillable vs HONEST_NOT_RUN. Persist item 1/10 **closed**. |

## Role conformance

`contrib/modelnet/crl12/deploy/conformance-lab.yaml` — nine generic roles, `not_central_certification: true`. Self-attestation only.

## Migration / rollback

Disable `cr12_enabled` (native `Crl12SetEnabled(false)` or hcpd `-cr12=0`): layer/institutional → `PROFILE_UNSUPPORTED`. CR11 capital/reserve remains. No schema rewrite of stored v1.1 envelopes.

## Unresolved (do not relabel PASS)

1. Outbound signed type strings vs `TYPE_CONTRACTS.md` (inbound aliases only).
2. Async catalogue `Job` bodies (engine returns typed envelopes; jobs SUCCEEDED).
3. GET/list tenant isolation; binding PROPOSED/consent; `Idempotency-Key` header.
4. Aggregate does not sum position valuations (prevents invented AUM; also prevents a priced AUM total).
5. Inbound ML-DSA on institutional observations (responses are signed).
6. 10m-row lab, Playwright, live IdP, chain/custody labs.
7. `test_runner.py` `create_cache` still mines 199 blocks if CR12 tests are launched that way — run the scripts **directly** (`num_nodes=0`) as in this prove.

## Operator next actions

- Do **not** push, merge, tag, or set `IS_RELEASE`.
- Do **not** replace production `btxd` / `btxd.real`.
- Recopy isolated-regtest prefix only if you want process-tier against `$HOME/.local/opt/btx-0.34.8-regtest` instead of `build-gcc13`.
- Optional later: priced Aggregate, Job HTTP bodies, outbound type rename + SDK, 10m lab under `BTX_CR12_10M_LAB`, Playwright.
- Independent R1–R8 files are in `audit/`. Evidence stubs: `evidence/CR12/`.
