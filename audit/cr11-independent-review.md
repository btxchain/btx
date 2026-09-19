# Cognitive Reserve v1.1 independent review (Extra High)

**Tree:** `/home/administrator/btx-0.34.7-private`  
**Kickoff HEAD (coordinator):** `573b4aa41f26ea6c61a00ee6096c5ff4de319335` — [cr11-baseline.md](cr11-baseline.md)  
**This session:** source-level trace only. Did **not** compile. Did **not** run `test_bitcoin` or `test_runner.py`. A Boost case name means the unique `BOOST_AUTO_TEST_CASE` exists in source. It is **not** a recorded binary PASS.

Exclusive outputs of this review:

- [cr11-requirement-traceability.csv](cr11-requirement-traceability.csv) — 50 operations + 190 `CR11-*` cases
- [cr11-journeys.csv](cr11-journeys.csv) — `CR11-J01`–`J20`
- [cr11-evidence.md](cr11-evidence.md) — tier legend and counts
- this file

Coordinator [cr11-not-run.md](cr11-not-run.md) and [cr11-baseline.md](cr11-baseline.md) were cited, not overwritten.

## Verdict

The v1.1 surface is wired through the **existing** `HcpEngine` (`HandleLocked` → `HandleCr11Locked` in `src/modelnet/hcp_cr11_engine.inc.cpp`). There is **no second `HcpEngine` class** and **no Core v4** object type. All 19 native TUs plus `modelnet_cr11_journey_tests.cpp` are registered in `src/test/CMakeLists.txt`. Both process scripts are in `test/functional/test_runner.py`.

The 190 unique Boost names exist (19 families × 10). That is **not** 190 honest proofs. Ten cases are `BOOST_CHECK(true)` only. Six more are tautologies (`|| true`). Thirteen of fifty REST operations have handlers but **no unique native or process invocation** (mostly GET-by-id). Fourteen of twenty journeys are clone templates. `CR11-INTEGRATE-07` claims all 50 routes and GETs ten list paths.

Live CEX IdP/HSM/custody, CUDA/ROCm/Metal, 400GiB I/O, production `btxd.real`, and the rest of [cr11-not-run.md](cr11-not-run.md) remain **NOT_RUN**.

`automatic_spend_atoms` stays **0** (`GET /health`, `CR11-SCALE-10`, process health). Isolated prefix only. No push/merge/tag.

## No second HcpEngine / no Core v4

| Check | Result |
|---|---|
| `class HcpEngine` | Single definition: `src/modelnet/hcp.h`. `struct HcpEngine::Impl` in `hcp_engine.cpp`. |
| CR11 dispatch | `hcp_engine.cpp` strips `/btx/hcp/v1` then routes `/extensions/cognitive-reserve`, `/reserve/*`, `/capital/*` into `Impl::HandleCr11Locked`. Include file comment: “Same HcpEngine; not a second product.” |
| Dual instances | `CR11-PORT-01` / `CR11-INTEGRATE-06` call `HcpEngine::Create` twice. Two **lab instances**, not a second engine product or second customer ledger. |
| Pure functions | `src/modelnet/hcp_cr11.cpp` — capacity/TCO/DAG/quorum. Comment: not a second ledger or engine. |
| Core v4 type | `HcpObjectTypeOk` allowlist in `hcp_codec.cpp` is 7 base HCP types + 18 `*V1_1` types. No `*V4`. Python SDK `test_no_core_v4_type`. |
| Core v4 reject | `HandleCr11Locked` returns `CORE_V4_FORBIDDEN` if `package_core_version >= 4`. Native `CR11-COMP-06`; process journeys POST positions with version 4. `COMP-06` also asserts profile `package_core_versions[0] == 3`. |

## Counts (source-level)

| Item | Count |
|---|---|
| Operations in `operations-v1.1.json` | 50 |
| Engine handlers matching those 50 | 50 |
| Unique Boost `CR11-*` cases | 190 |
| Unique Boost journeys `cr11_j01`–`j20` | 20 |
| Process scripts | 2 (`feature_modelnet_cr11.py`, `feature_modelnet_cr11_journeys.py`) |
| Ops with unique NATIVE or NATIVE+PROCESS call | 37 |
| Ops handler-only (NOT_RUN / UNHIT) | 13 |
| Cases NATIVE | 163 |
| Cases NATIVE+PROCESS | 11 |
| Cases NOT_RUN (stub or tautology) | 16 |
| Journeys NATIVE or NATIVE+PROCESS or PROCESS | 6 (`J01`–`J05`, `J20`) |
| Journey clones NOT_RUN | 14 (`J04` native clone; `J06`–`J19`) |

## Stub-quality tests — `BOOST_CHECK(true)` only

These Boost cases exist and are **not** evidence of the stated then-clause:

| Case | Boost | File |
|---|---|---|
| CR11-APPROVE-05 | `cr11_approve_05_changed_committee` | `src/test/modelnet_cr11_approve_tests.cpp` |
| CR11-PLAN-06 | `cr11_plan_06_unknown_child` | `src/test/modelnet_cr11_plan_tests.cpp` |
| CR11-PLAN-09 | `cr11_plan_09_post_effect_cancellation` | `src/test/modelnet_cr11_plan_tests.cpp` |
| CR11-PROGRAM-08 | `cr11_program_08_terms_revision` | `src/test/modelnet_cr11_program_tests.cpp` |
| CR11-PRODUCT-06 | `cr11_product_06_firm_quote_expiry` | `src/test/modelnet_cr11_product_tests.cpp` |
| CR11-LOCAL-02 | `cr11_local_02_locality_reuse` | `src/test/modelnet_cr11_local_tests.cpp` |
| CR11-LOCAL-06 | `cr11_local_06_package_substitution` | `src/test/modelnet_cr11_local_tests.cpp` |
| CR11-UX-07 | `cr11_ux_07_keyboard_and_reader` | `src/test/modelnet_cr11_ux_tests.cpp` |
| CR11-SCALE-04 | `cr11_scale_04_queued_jobs` | `src/test/modelnet_cr11_scale_tests.cpp` |
| CR11-SCALE-08 | `cr11_scale_08_leader_crash` | `src/test/modelnet_cr11_scale_tests.cpp` |

## Additional tautologies (not `BOOST_CHECK(true)`, still not proof)

| Case | Assertion |
|---|---|
| CR11-LEDGER-03 | `LastTxid().empty() \|\| true` |
| CR11-LEDGER-05 | `!KnowledgeDisclosed \|\| KnowledgeDisclosed` |
| CR11-HOLD-01 | `exists(acquisition_price) \|\| true` |
| CR11-HOLD-05 | `find("RUNTIME_READY") \|\| true` compared equal to `true` |
| CR11-AUTH-08 | `EnrollProvider(...) \|\| ... \|\| true` |
| CR11-PORT-02 | last execution empty **or** not empty |

## Operations with no unique test call

Handlers exist in `HandleCr11Locked`. No Boost `AuthReq` and no process HTTP hit:

`getEntityLink`, `getPortfolio`, `getReservePolicy`, `getWorkloadProfile`, `getApprovalRule`, `getResearchProgram`, `getTCOComparison`, `getCapitalPlan`, `getAllocationPlan`, `getApprovalRequest`, `listApprovalDecisions`, `getCapitalExecution`, `getCapitalExport`.

`CR11-INTEGRATE-07` GETs ten **collection** paths (`/extensions/cognitive-reserve`, `/reserve/entities/links`, `/reserve/portfolios`, `/reserve/policies`, `/capital/workloads`, `/capital/approval-rules`, `/capital/programs`, `/capital/products`, `/capital/positions`, `/capital/reports`) and asserts `ok >= 8`. That does not cover the 13 GET-by-id/list-decision routes or POST execute/cancel/referral/etc.

## Process functionals (scripts exist; not executed this session)

`feature_modelnet_cr11.py`: two `btx-hcpd` loopbacks (walletless A, `-finance=1` B). Asserts A `cognitive_reserve=false` + extension 403 `PROFILE_UNSUPPORTED`; B extension 200 `ReserveExtensionProfileV1_1`; POST portfolio; snapshot capacity `"250"`; cyclic allocation `GRAPH_CYCLE`; POST `/rpc` 404; `automatic_spend_atoms==0`.

`feature_modelnet_cr11_journeys.py`: comments J01–J20 but implements J01-like TCO/plan/alloc, J02 SUGGEST replenishment, J03 snapshot, J04 program membership, J05 walletless 403, then a leftover GET loop plus reports/exports/positions and Core v4 400. It does **not** run twenty distinct journeys.

## Journey clones

`cr11_j02_journey` through `cr11_j19_journey` except J03 and J05 share the same GET extension + GET profile + `automatic_spend_atoms==0` + `Cr11Capacity(1000,400,250)==250` body. J04 and J06–J19 therefore do not evidence their titles. Unique native journeys: **J01, J03, J05, J20** (J02 is the clone template).

## What is actually strong in-lab

Capacity `max(0,min(E-P,R))` with pending-deposit / encumbered / sibling / forecast exclusions and no double-count of cognitive holdings (`hcp_cr11.cpp` + RESERVE-01/02/04/08/09/10). DAG cycle/missing/limit (`PLAN-01`–`03`; process cycle). Distinct-person quorum / initiator exclusion / veto / expiry (`Cr11Approved`). Idempotency conflict on allocation. Family view is not debit. Lifetime mandate not recycled on cancel (`LEDGER-07`). Core v4 forbidden. TCO 600000 vs 245000 (`TCO-01`; process J01). DPoP replay 401 on reused proof (`AUTH-02`, OAUTH_LAB). Body bound 413 (`SCALE-05`).

## Honest gaps (beyond coordinator NOT_RUN)

- Lab OAuth is in-engine (`LabAuthorize` / `LabToken` / `LabDpop`), not a live CEX IdP.
- No actual native broadcast/signer/HSM path in CR11 tests (`LEDGER-02/03` stubs).
- No portal: `UX-01` is a local C++ string; `UX-07` is `BOOST_CHECK(true)`.
- SCALE is dozens of in-process calls, not measured 1000 rps / 100 wps / 100000 history.
- Python body-id SDK exists; TypeScript parity and “both SDKs vs native” for COMP-05 were not a three-parser process this tree.
- `cr11_test::Scopes()` adds CR11 scopes onto HCP `AllScopes()`; still OAUTH_LAB.

Do not treat this review as release approval. PR/push/`CLIENT_VERSION` remain operator-gated per resume rules.
