# CRL/1.2 R7 — 43 operation call paths

**Tree:** `/home/administrator/btx-0.34.7-private`  
**HEAD:** `573b4aa41f26ea6c61a00ee6096c5ff4de319335`  
**Catalogue:** `contrib/modelnet/crl12/schemas/operations-v1.2.json` (`new_operations: 43`)  
**Handler:** `src/modelnet/hcp_crl12_engine.inc.cpp` — single function `HcpEngine::Impl::HandleCrl12Locked` (included from `hcp_engine.cpp`). There are no per-operation C++ symbols; each row is an `if` / `MatchPath` branch.  
**This audit:** source review only. Did not compile, ninja, or run tests.

Paths below are engine-relative (after `/btx/hcp/v1`). `Need(scope, financial=false)` is the Auth gate at `hcp_crl12_engine.inc.cpp:76-81`.

## Verdict

**Missing handlers: none.** All 43 `operation_id`s have a matching method+path branch.

**Contract gaps (handler present, response/type/async disagree with the catalogue):** 9 operations return a typed envelope (or an unsigned JSON object) where the catalogue requires `Job` or `InteroperabilityReceiptV1_2Envelope`. `NewJob` (`:95-107`) inserts `SUCCEEDED` immediately and does not become the HTTP body.

Type-name drift vs package TYPES is recorded under the affected rows; it is not a missing route.

---

## All 43 operation_ids

| # | operation_id | method + engine path | Need scope | Handler | HTTP body actually returned | Catalogue response | Gap |
|---|---|---|---|---|---|---|---|
| 1 | getLayerExtension | GET `/extensions/cognitive-reserve/v1.2` | catalog:read | `:136-155` | `SignedObj(HCP_TYPE_LAYER_EXTENSION)` → `LayerExtensionProfileV1_2` | LayerExtensionProfileV1_2Envelope | none |
| 2 | publishProviderRoles | POST `/layer/roles` | layer:admin | `:158-196` | `SignedObj(HCP_TYPE_PROVIDER_ROLE)` 201 | ProviderRoleManifestV1_2Envelope | none (route). Sequence rollback / role-effect vs advertised funding READ is behavioral, not a missing path |
| 3 | getProviderRoles | GET `/layer/roles/{id}` | catalog:read | `:197-203` | signed role or 404 | ProviderRoleManifestV1_2Envelope | none |
| 4 | listProviderRoles | GET `/layer/roles` | catalog:read | `:204-208` | `PageOf` signed roles | Page | none |
| 5 | createServiceBinding | POST `/layer/bindings` | bindings:admin | `:211-229` | `SignedObj(HCP_TYPE_SERVICE_BINDING)` 201, `status=ACTIVE` | ServiceBindingV1_2Envelope | none (route). Always ACTIVE; no owner-consent / PROPOSED |
| 6 | getServiceBinding | GET `/layer/bindings/{id}` | bindings:read | `:238-250` | signed binding; token/key nulled | ServiceBindingV1_2Envelope | none (route). No caller-entity compare |
| 7 | listServiceBindings | GET `/layer/bindings` | bindings:read | `:251-255` | `PageOf` | Page | none |
| 8 | revokeServiceBinding | POST `/layer/bindings/{id}/revoke` | bindings:admin | `:230-237` | signed binding `REVOKED` | ServiceBindingV1_2Envelope | none (route). Later RECORD/PLAN not blocked (`BINDING_REVOKED` unenforced) |
| 9 | validateAdapterCapabilities | POST `/layer/adapters/validate` | layer:admin | `:258-274` | `NewJob` then **`SignedObj(HCP_TYPE_ADAPTER_CAPABILITY)` 200** | **Job** | **GAP:** body is capability report, not Job. Type `AdapterCapabilityReportV1_2` vs package `AdapterCapabilityManifestV1_2` |
| 10 | getAdapterCapabilityReport | GET `/layer/adapters/{id}` | bindings:read | `:275-281` | signed adapter or 404 | AdapterCapabilityManifestV1_2Envelope | type name as above |
| 11 | registerInstitutionalAsset | POST `/institutional/assets` | assets:write | `:316-351` | `SignedObj(HCP_TYPE_INSTITUTIONAL_ASSET)` 201 | InstitutionalAssetRecordV1_2Envelope | type `InstitutionalAssetV1_2` vs package `InstitutionalAssetRecordV1_2`. Collision only if `force_collision` / `contradictory_claim` |
| 12 | getInstitutionalAsset | GET `/institutional/assets/{id}` | assets:read | `:381-387` | signed asset or 404 | InstitutionalAssetRecordV1_2Envelope | type name as above |
| 13 | listInstitutionalAssets | GET `/institutional/assets` | assets:read | `:388-392` | `PageOf` | Page | none |
| 14 | recordAssetRights | POST `/institutional/assets/{id}/rights` | assets:write | `:352-380` | `SignedObj(HCP_TYPE_ASSET_RIGHTS)` 201 or 403 unaccepted issuer | RightsStatementV1_2Envelope | type `AssetRightsV1_2` vs package `RightsStatementV1_2` |
| 15 | ingestPositionBatch | POST `/institutional/positions/batches` | positions:write | `:395-465` | **`JsonStatus(201, {accepted, watermark_advanced})`** — **no `NewJob`** | **Job** | **GAP:** unsigned JSON, not Job. Exact-replay / conflict / gap logic is in-process |
| 16 | getPositionObservation | GET `/institutional/positions/{id}` | positions:read | `:466-472` | signed `PositionObservationV1_2` | PositionObservationV1_2Envelope | none |
| 17 | getPositionSnapshot | GET `/institutional/positions` | positions:read | `:473-494` | unsigned page `{items, as_of, observed_cutoff}` | Page | **GAP (query):** missing `as_of` / `observed_cutoff` default to `cfg.clock_ms` instead of reject |
| 18 | recordValuationObservation | POST `/institutional/valuations` | valuations:write | `:497-526` | signed `ValuationObservationV1_2` 201 | ValuationObservationV1_2Envelope | none (route) |
| 19 | getValuationObservation | GET `/institutional/valuations/{id}` | valuations:read | `:527-533` | signed valuation or 404 | ValuationObservationV1_2Envelope | none |
| 20 | recordExposureLinks | POST `/institutional/exposures` | exposures:write | `:536-602` | signed `ExposureLinkV1_2` 201 | ExposureLinkV1_2Envelope | cycle/depth/limit use `GRAPH_*` names, not spec `LOOKTHROUGH_CYCLE` |
| 21 | listExposureLinks | GET `/institutional/exposures` | exposures:read | `:603-607` | `PageOf` | Page | none |
| 22 | defineInstitutionalMetric | POST `/institutional/metrics` | metrics:admin | `:610-623` | signed `MetricDefinitionV1_2` 201 | MetricDefinitionV1_2Envelope | none |
| 23 | listInstitutionalMetrics | GET `/institutional/metrics` | metrics:read | `:624-628` | `PageOf` | Page | none |
| 24 | createPortfolioProjection | POST `/institutional/projections` | projections:create | `:717-762` | `NewJob` then **`SignedObj(HCP_TYPE_PORTFOLIO_PROJECTION)` 201** | **Job** | **GAP:** typed envelope, job already SUCCEEDED |
| 25 | getPortfolioProjection | GET `/institutional/projections/{id}` | projections:read | `:763-777` | signed projection; optional `cursor_tenant` / `filter` | PortfolioProjectionV1_2Envelope | none (route). Tenant check is a client query, not a MAC cursor |
| 26 | createInstitutionalExport | POST `/institutional/exports` | exports:create | `:780-828` | `NewJob` then **`SignedObj(HCP_TYPE_EXPORT_MANIFEST)` 201** | **Job** | **GAP:** typed envelope, not Job |
| 27 | getInstitutionalExport | GET `/institutional/exports/{id}` | exports:read | `:840-846` | signed export manifest | ExportManifestV1_2Envelope | none |
| 28 | downloadInstitutionalExportChunk | GET `/institutional/exports/{id}/chunks/{chunk_id}` | exports:read | `:829-838` | `application/octet-stream` | BINARY | none |
| 29 | validateInstitutionalImport | POST `/institutional/imports/validate` | imports:write | `:863-891` | `NewJob` then **`SignedObj(HCP_TYPE_IMPORT_MANIFEST)` 200** | **Job** | **GAP:** typed envelope, not Job. Type `ImportManifestV1_2` vs package receipt on later commit |
| 30 | commitInstitutionalImport | POST `/institutional/imports/{id}/commit` | imports:write | `:892-912` | **`SignedObj(HCP_TYPE_IMPORT_MANIFEST)`** | **InteroperabilityReceiptV1_2Envelope** | **GAP:** wrong type; CAS is `mapping_digest` only (`HCP_ERR_MAPPING_CAS` vs spec `MAPPING_MISMATCH`) |
| 31 | getInstitutionalImport | GET `/institutional/imports/{id}` | imports:read | `:913-919` | signed import object | InteroperabilityReceiptV1_2Envelope | type as commit |
| 32 | listReconciliationBreaks | GET `/institutional/breaks` | reconciliation:read | `:922-926` | `PageOf` | Page | none |
| 33 | getReconciliationBreak | GET `/institutional/breaks/{id}` | reconciliation:read | `:935-941` | signed break or 404 | ReconciliationBreakV1_2Envelope | none |
| 34 | resolveReconciliationBreak | POST `/institutional/breaks/{id}/resolve` | reconciliation:write | `:927-934` | signed break `RESOLVED` | ReconciliationBreakV1_2Envelope | none (route). No native-ledger overwrite |
| 35 | preparePortfolioInstruction | POST `/institutional/instructions` | capital:prepare | `:944-976` | signed `PortfolioInstructionV1_2` 201 `DRAFT` | PortfolioInstructionV1_2Envelope | none (route). Idempotency is `instruction_id`+body hash, not `Idempotency-Key` |
| 36 | getPortfolioInstruction | GET `/institutional/instructions/{id}` | capital:read | `:1013-1019` | signed instruction or 404 | PortfolioInstructionV1_2Envelope | none |
| 37 | translatePortfolioInstruction | POST `/institutional/instructions/{id}/translate` | capital:prepare | `:977-1012` | **`SignedObj(HCP_TYPE_PORTFOLIO_INSTRUCTION)`**; writes v1.1 DRAFT plan+allocation | **InteroperabilityReceiptV1_2Envelope** | **GAP:** wrong response type. Draft-only money effect is otherwise on the old execute route |
| 38 | runInstitutionalScenario | POST `/institutional/scenarios` | scenarios:create | `:1022-1036` | `NewJob` then **`SignedObj(HCP_TYPE_SCENARIO_RESULT)` 201** | **Job** | **GAP:** typed envelope, not Job. Type `InstitutionalScenarioResultV1_2` vs package `ScenarioResultV1_2`. No shock application |
| 39 | getInstitutionalScenario | GET `/institutional/scenarios/{id}` | scenarios:read | `:1037-1043` | signed scenario or 404 | ScenarioResultV1_2Envelope | type name as above |
| 40 | getLayerConformance | GET `/layer/conformance/{id}` | catalog:read | `:283-293` | `SignedObj(HCP_TYPE_LAYER_CONFORMANCE)` with `not_central_certification=true` | ConformanceStatementV1_2Envelope | type `LayerConformanceClaimV1_2` vs package `ConformanceStatementV1_2` |
| 41 | getLayerJob | GET `/layer/jobs/{id}` | jobs:read | `:307-313` | `SignedObj(HCP_TYPE_LAYER_JOB)` or 404 | Job | type `LayerJobV1_2` (Job is not in package TYPES). Owner scope not compared |
| 42 | cancelLayerJob | POST `/layer/jobs/{id}/cancel` | jobs:cancel | `:295-306` | CANCELLED or 409 `JOB_COMMITTED` if already SUCCEEDED | Job | none (route). In-flight PENDING never occurs because creates commit immediately |
| 43 | stageInstitutionalImportChunk | POST `/institutional/imports/chunks` | imports:write | `:849-862` | **`JsonStatus(201, {chunk_id, digest, length, …})`** unsigned | **StagedChunk** | **GAP:** unsigned JSON. Declared digest/length not checked at stage (`CHUNK_MISMATCH` is validate-time `CHUNK_DIGEST`) |

Unknown method+path falls through to `:1045` `Err(404, "NOT_FOUND", req.path)`.

Disabled extension (`cfg.cr12_enabled == false`) returns `:5-7` `403 PROFILE_UNSUPPORTED` before any of the 43 branches.

---

## 43-op gap summary (not missing routes)

| Class | operation_ids |
|---|---|
| **Missing handler** | **none** |
| Catalogue `Job`, HTTP body is typed envelope or unsigned JSON | `validateAdapterCapabilities`, `ingestPositionBatch`, `createPortfolioProjection`, `createInstitutionalExport`, `validateInstitutionalImport`, `runInstitutionalScenario` |
| Catalogue `InteroperabilityReceiptV1_2Envelope`, engine `ImportManifestV1_2` / instruction envelope | `commitInstitutionalImport`, `getInstitutionalImport`, `translatePortfolioInstruction` |
| Unsigned JSON where a typed/staged object is specified | `ingestPositionBatch`, `stageInstitutionalImportChunk`, `getPositionSnapshot` (page) |
| Package type name ≠ `HCP_TYPE_*` | adapter, asset, rights, import/receipt, scenario result, conformance (see `audit/crl12-remaining-gaps.md`) |

Scopes on the 43 routes match `operations-v1.2.json` (`catalog:read`, `layer:admin`, `bindings:*`, `assets:*`, `positions:*`, `valuations:*`, `exposures:*`, `metrics:*`, `projections:*`, `exports:*`, `imports:*`, `reconciliation:*`, `capital:prepare|read`, `scenarios:*`, `jobs:read|cancel`).
