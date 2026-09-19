# Extra High review R1 — authority

Tree: `/home/administrator/btx-0.34.7-private`  
Branch: `feat/0.34.8-modelnet-first-run`  
Method: implementation vs package spec only. No compile, ninja, `test_btx`, production `btxd`, commit, or push.  
Spec: `doc/modelnet/crl12/02_Neutral_Provider_and_Institutional_Spec.md` §§4, 9, 10, 14, 16; `contrib/modelnet/crl12/schemas/OPERATIONS.md`; `TYPE_CONTRACTS.md`; `crl_reference.py` `TYPES`.  
Engine: `src/modelnet/hcp_crl12_engine.inc.cpp`, `hcp_crl12.cpp`, `hcp_types.h`, dispatch/Auth/persist in `hcp_engine.cpp`.  
Native tests: `src/test/modelnet_cr12_*_tests.cpp`. Boost cases exist; they are not evidence-tier PASS. Process, browser, OAuth-IdP, and chain labs are **HONEST_NOT_RUN**.

## Verdict

Several hard authority boundaries hold in-process: `capital:prepare` cannot `executeAllocation`; translate writes v1.1 **DRAFT** plans; import does not credit `accounts`; `automatic_spend_atoms` is forced to 0; Core v4 body field is rejected; money still goes through `POST /capital/allocations/{id}/execute` on the same `HcpEngine`. Those are real, and native tests cover them.

They are not enough. Domain-separated type names do not match the 18 signed types; tenant/entity checks are missing on almost every GET; bindings activate without owner consent; mutating requests ignore `Idempotency-Key`; async operations do not return owner-scoped Jobs. Treat those as **fix now**. Do not call CR12-SECURITY, CR12-BIND, or CR12-UX PASS.

---

## Findings

### R1-01 BLOCKER — signed type names are not the 18 spec types

**File:line:** `src/modelnet/hcp_types.h:58-75`; registry `src/modelnet/hcp_codec.cpp:24-68`.  
**Expected:** `TYPE_CONTRACTS.md` and `crl_reference.py` `TYPES`: `AdapterCapabilityManifestV1_2`, `InstitutionalAssetRecordV1_2`, `RightsStatementV1_2`, `InteroperabilityReceiptV1_2`, `ScenarioDefinitionV1_2`, `ScenarioResultV1_2`, `ConformanceStatementV1_2`. Body domain is `BTX/HCP/<exact type>/v1`.  
**Actual:** engine registers `AdapterCapabilityReportV1_2`, `InstitutionalAssetV1_2`, `AssetRightsV1_2`, `ImportManifestV1_2`, `InstitutionalScenarioResultV1_2`, `LayerConformanceClaimV1_2`, plus extra `LayerJobV1_2`. `InteroperabilityReceiptV1_2` and `ScenarioDefinitionV1_2` are absent, so `HcpObjectTypeOk` would reject spec envelopes.  
**Native tests:** `cr12_compat_10` / `cr12_negotiate_07` assert `HcpObjectTypeOk` on the **engine** names, not the spec names. `cr12_import_01` expects `HCP_TYPE_IMPORT_MANIFEST`. Tests encode the mismatch. Not covered as a spec-conformance failure.

### R1-02 BLOCKER — GET/list paths are not tenant- or entity-scoped

**File:line:** `hcp_crl12_engine.inc.cpp:236-252` (bindings), `305-310` (jobs), `379-389` (assets), `464-491` (positions), `761-774` (projections: only optional `cursor_tenant` query). Spec §14: every request checks tenant, legal entity, portfolio, actor, binding. OPERATIONS: `getLayerJob` is owner-scoped; `getServiceBinding` is caller-scoped.  
**Actual:** `Need()` sets `cr11.authed_account` then `PageOf` / map lookup returns any id. Bindings store `account` on create and never compare it on GET. Positions/jobs/assets/imports (GET) are global to the process. `cursor_tenant` is a client-supplied query, not a MAC-bound cursor.  
**Native tests:** `cr12_import_03` covers chunk ownership only. `cr12_instruction_02` / `cr12_ux_02` cover **prepare** `legal_entity_id` vs hard-coded `cr11.legal_entity` (`le-demo`), not token entity claims and not GET isolation. `cr12_bind_02` is `role=UNKNOWN`, not CR12-BIND-02 (token A / binding B). **Not covered.**

### R1-03 MAJOR — `createServiceBinding` always ACTIVE; no owner consent

**File:line:** `hcp_crl12_engine.inc.cpp:209-226`. OPERATIONS: propose or activate only after owner policy, remote identity, and allowed role/effects agree. Status enum includes `PROPOSED`. CR12-BIND-01: no owner consent → remains inactive.  
**Actual:** copies body, forces `status=ACTIVE`, increments generation. No consent, remote profile, effect intersection, or network check. `unbound_role` / `role==UNKNOWN` is a client flag, not a registry lookup.  
**Native tests:** `cr12_bind_01` **expects 201** on a bare POST. Catalogue BIND-01 is not the Boost case. Not covered.

### R1-04 MAJOR — mutating CR12 requests do not require `Idempotency-Key`

**File:line:** `hcp_engine.cpp:583-653` (`Auth`); no header read in `HandleCrl12Locked`. Spec §16 and OpenAPI `Idempotency-Key` `required: true` on POSTs. Server must scope key to tenant/entity and body digest.  
**Actual:** ignored. Instruction idempotency is `instruction_id` + `HashBody()` of the HTTP envelope (`hcp_crl12_engine.inc.cpp:961-964`), not the header.  
**Native tests:** none assert the header. `cr12_instruction_04` covers changed `instruction_id` body only.

### R1-05 MAJOR — async creates return typed bodies, not owner-scoped Jobs

**File:line:** adapter validate `256-271`; projection `715-759`; import validate `861-888`; export `778-825`; scenario `1020-1033`; `NewJob` `93-105`. Spec §16 / OPERATIONS: those POSTs return `Job`; poll `GET /layer/jobs/{id}`; pending typed GET is `JOB_PENDING`.  
**Actual:** `NewJob(..., "SUCCEEDED")` immediately; HTTP response is a signed capability/projection/import/scenario object. Client never receives `job_id` (`J17` says so). `last_job` is process state only.  
**Native tests:** `cr12_j17` HonestNotRun: “adapter/projection jobs commit immediately and do not return job_id”. `cr12_recovery_02/03` cancel `job-running` / `job-committed` (404). Not covered.

### R1-06 MAJOR — identifier collision is opt-in (`force_collision`)

**File:line:** `hcp_crl12_engine.inc.cpp:321-332`. Spec §5.1 / CR12-ASSET-02: contradictory same namespace/value opens `IDENTIFIER_COLLISION` and must not merge.  
**Actual:** loop only fires when the **new** body sets `force_collision=true`. Two identical identifiers without the flag both `201`.  
**Native tests:** `cr12_asset_02` sets `force_collision`. Does not cover unsolicited collision.

### R1-07 MAJOR — translate/commit/adapter responses are the wrong object types

**File:line:** translate `975-1009` (`SignedObj(HCP_TYPE_PORTFOLIO_INSTRUCTION)`); import commit `890-909` (`HCP_TYPE_IMPORT_MANIFEST`); adapter validate `271` (`HCP_TYPE_ADAPTER_CAPABILITY`). OPERATIONS: translate and commit return `InteroperabilityReceiptV1_2Envelope`; adapter validate returns `Job`.  
**Actual:** no `InteroperabilityReceiptV1_2` type exists. Translate does create `cr11.plans` / `cr11.allocations` with `state=DRAFT` (that part is correct).  
**Native tests:** `cr12_instruction_01` checks draft `CapitalPlanV1_1` via GET `/capital/plans/{id}` — **covers draft-only money effect**, not receipt type.

### R1-08 NOTE — DPoP on POST; GET is bearer-only (same as HCP/1 `Auth`)

**File:line:** `hcp_engine.cpp:613-650`; CR12 `Need(..., financial=false)` at `hcp_crl12_engine.inc.cpp:74-78`. Spec §14: reuse sender-constrained access.  
**Actual:** DPoP required when `financial || method==POST`. All CR12 `Need` pass `financial=false`, so GET `/institutional/*` and GET `/layer/*` accept Bearer without DPoP. Execute uses CR11 `Need("capital:execute", true)` (`hcp_cr11_engine.inc.cpp:655-657`) — DPoP plus finance.  
**Native tests:** `cr12_security_03` POST `/layer/bindings` without `dpop` → `DPOP_BINDING`. GET-without-DPoP not asserted. Do not upgrade this to PASS for CR12-SECURITY-03 production OAuth.

### R1-09 — scopes on the 43 routes match OPERATIONS.md (native, limited)

**File:line:** each `Need("<scope>", false)` in `hcp_crl12_engine.inc.cpp`.  
**Expected vs actual:** catalogue scopes (`catalog:read`, `layer:admin`, `bindings:*`, `assets:*`, `positions:*`, `valuations:*`, `exposures:*`, `metrics:*`, `projections:*`, `exports:*`, `imports:*`, `reconciliation:*`, `capital:prepare|read`, `scenarios:*`, `jobs:read|cancel`) are wired. `account:admin` remains a wildcard in `Auth` (`hcp_engine.cpp:606`). Lab tokens usually do not include it.  
**Native tests:** `cr12_role_10` `catalog:read` cannot POST roles; `cr12_instruction_07` / `cr12_sdk_03` analytics token (`capital:prepare` without `capital:execute`) is `SCOPE_DENIED` on execute. **Covered for those two pairs.** Binding-effect least privilege (CR12-BIND-03) is not implemented (no permitted_effects check) and not tested.

### R1-10 — translate is draft-only; execute stays on `/capital/allocations/{id}/execute`

**File:line:** translate `975-1009`; no `/institutional/**/execute`. CR11 execute `hcp_cr11_engine.inc.cpp:655-657`. Spec §9.2 / OPERATIONS `translatePortfolioInstruction`.  
**Actual:** writes `CapitalPlanV1_1` / `AllocationPlanV1_1` `DRAFT`, `no_reservation=true`, `execute=false`. Money path is the old execute route with `capital:execute` + `financial=true`. `HCP_ERR_INSTRUCTION_NOT_EXECUTE` is defined (`hcp_types.h:161`) and **never returned**.  
**Native tests:** `cr12_instruction_01`, `06`, `07`; `cr12_j05`, `cr12_compat_08`. **Covered in-process.** Isolated chain / committee-on-translated-draft (CR12-COMPAT-08 catalogue) is not a chain lab.

### R1-11 — import never custody-credits; no second ledger

**File:line:** commit `904-907` (`custody_credit=false`, `spendable_created=false`); no `accounts[].available` writes in `HandleCrl12Locked`. Same `HcpEngine` / `accounts` map. Spec §10.2.  
**Actual:** validate/commit are flags on an in-memory import row. They do not ingest positions into the native wallet.  
**Native tests:** `cr12_import_10`, `cr12_sdk_09`. **Covered in-process.** Process restart atomic publication (CR12-IMPORT-07) is **HONEST_NOT_RUN** (see R3).

### R1-12 — `automatic_spend_atoms=0`

**File:line:** `hcp_engine.cpp:466-472` Create rejects non-zero; `472` forces 0; health `690`. `hcp_types.h:21` `HCP_AUTOMATIC_SPEND_ATOMS=0`.  
**Native tests:** `cr12_sdk_05`, `cr12_j01`, `cr12_compat_04`. **Covered.**

### R1-13 — Core v4 forbidden on CR12 bodies; not a Core v3 byte-identity proof

**File:line:** `hcp_crl12_engine.inc.cpp:22-25`; extension body `package_core_version=3` at `149`. Spec CR12-NEGOTIATE-08: exact Core v3 package bytes unchanged.  
**Actual:** numeric field `>=4` → `CORE_V4_FORBIDDEN`. No package lockfile/hash comparison.  
**Native tests:** `cr12_neutral_09`, `cr12_j19`. Field covered. Package-byte identity: **HONEST_NOT_RUN**.

### R1-14 MINOR — “no brand dispatch” is a denylist on `/layer/` dumps only

**File:line:** `hcp_crl12.cpp:16-27`; gate `hcp_crl12_engine.inc.cpp:29-33` (`req.path.rfind("/layer/", 0)==0`). Spec §§3, 18: no operational brand branches; generic fixtures.  
**Actual:** substring match on a fixed institution list. `/institutional/` bodies are not checked (a “BlackRock” asset label is accepted). No brand-based routing table exists (good). Denylist is itself a brand special case.  
**Native tests:** `cr12_neutral_02` Goldman on `/layer/roles`. Institutional brand strings not covered.

### R1-15 MINOR — extension digests are filler, not contract hashes

**File:line:** `hcp_crl12_engine.inc.cpp:141-142` (`std::string(96,'a')` / `'b'`). Spec CR12-NEGOTIATE-01: schema/operation digests match the registered contract.  
**Native tests:** `cr12_negotiate_01` only checks object type `LayerExtensionProfileV1_2`.

---

## What native tests actually prove (do not over-claim)

| Claim | Native coverage |
|---|---|
| Analytics cannot execute | Yes (`instruction_07`, `sdk_03`) |
| Translate creates DRAFT v1.1 plan | Yes (`instruction_01`) |
| Execute is CR11 `/capital/allocations/{id}/execute` | Yes (`instruction_06`, `j05`) |
| Import does not change `AccountAvailable` | Yes (`import_10`) |
| `automatic_spend_atoms==0` | Yes |
| Core v4 **field** rejected | Yes |
| DPoP required on POST | Partial (`security_03`) |
| Entity isolation on GET | No |
| Owner consent on bind | No (test expects ACTIVE) |
| Spec type names / receipts | No (tests use engine aliases) |
| Real ML-DSA production keys, live OAuth, browser | **HONEST_NOT_RUN** (`security_01` signs lab op key only; `ux_*` HTML string search, no browser) |

## Fix now vs HONEST_NOT_RUN

**Fix now**

1. Rename/register the 18 spec types; emit `InteroperabilityReceiptV1_2` from translate and import commit; drop or stop signing `ImportManifestV1_2` / `LayerJobV1_2` as if they were the catalogue.  
2. Filter every GET/list by authenticated account (and legal entity once the token carries it). Stop trusting `cursor_tenant`.  
3. Binding create → `PROPOSED` until owner policy + remote role/effects match; CAS on generation.  
4. Require `Idempotency-Key` on mutating CR12 POSTs.  
5. Collision without `force_collision`.  
6. Return Job (with `job_id`) from async creates; keep execute off institutional routes (already true).

**HONEST_NOT_RUN (do not invent PASS)**

- CR12-SECURITY-01 production key ceremony; CR12-SECURITY-03 live OAuth sender-binding.  
- CR12-UX-01…10 browser/WCAG.  
- CR12-NEGOTIATE-08 Core v3 package **bytes**.  
- CR12-COMPAT-08/10 process + independent closeout.  
- Two-provider network roundtrip (J02/J20 are in-process dual `HcpEngine`).
