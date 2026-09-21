# New API operations — CRL/1.2

All paths below are under `/btx/hcp/v1`. Existing 84 contract operations remain unchanged. POST scopes never replace entity, source, policy and expected-version checks.

## getLayerExtension

`GET /btx/hcp/v1/extensions/cognitive-reserve/v1.2`

Scope: `catalog:read`. Effect: `READ`. Request: `path/query only`. Response: `LayerExtensionProfileV1_2Envelope`.

Read the pinned extension. No support inferred from a provider name.

## publishProviderRoles

`POST /btx/hcp/v1/layer/roles`

Scope: `layer:admin`. Effect: `RECORD`. Request: `ProviderRoleManifestV1_2`. Response: `ProviderRoleManifestV1_2Envelope`.

Provider administration only; endpoints must map to registered supported operations.

## getProviderRoles

`GET /btx/hcp/v1/layer/roles/{id}`

Scope: `catalog:read`. Effect: `READ`. Request: `path/query only`. Response: `ProviderRoleManifestV1_2Envelope`.

Read exact signed role manifest by ID; expired claims remain inspectable, not usable for new effects.

## listProviderRoles

`GET /btx/hcp/v1/layer/roles`

Scope: `catalog:read`. Effect: `READ`. Request: `path/query only`. Response: `Page`.

Local configured directory view only; no canonical global provider registry.

## createServiceBinding

`POST /btx/hcp/v1/layer/bindings`

Scope: `bindings:admin`. Effect: `BIND`. Request: `ServiceBindingV1_2`. Response: `ServiceBindingV1_2Envelope`.

Propose or activate only after owner policy, remote identity and allowed role/effects agree.

## getServiceBinding

`GET /btx/hcp/v1/layer/bindings/{id}`

Scope: `bindings:read`. Effect: `READ`. Request: `path/query only`. Response: `ServiceBindingV1_2Envelope`.

Return caller-scoped binding, without credentials.

## listServiceBindings

`GET /btx/hcp/v1/layer/bindings`

Scope: `bindings:read`. Effect: `READ`. Request: `path/query only`. Response: `Page`.

Snapshot-bound listing of the entity bindings.

## revokeServiceBinding

`POST /btx/hcp/v1/layer/bindings/{id}/revoke`

Scope: `bindings:admin`. Effect: `BIND`. Request: `BindingRevokeRequest`. Response: `ServiceBindingV1_2Envelope`.

Stop new effects; retain reconciliation access to already accepted financial actions.

## validateAdapterCapabilities

`POST /btx/hcp/v1/layer/adapters/validate`

Scope: `layer:admin`. Effect: `RECORD`. Request: `AdapterValidateRequest`. Response: `Job`.

Bounded test job; requires configured test environment and never probes arbitrary URLs.

## getAdapterCapabilityReport

`GET /btx/hcp/v1/layer/adapters/{id}`

Scope: `bindings:read`. Effect: `READ`. Request: `path/query only`. Response: `AdapterCapabilityManifestV1_2Envelope`.

Actual supported interface and evidence, not a brand-to-feature mapping.

## registerInstitutionalAsset

`POST /btx/hcp/v1/institutional/assets`

Scope: `assets:write`. Effect: `RECORD`. Request: `InstitutionalAssetRecordV1_2`. Response: `InstitutionalAssetRecordV1_2Envelope`.

Register namespaced identity; collisions open a break rather than merging.

## getInstitutionalAsset

`GET /btx/hcp/v1/institutional/assets/{id}`

Scope: `assets:read`. Effect: `READ`. Request: `path/query only`. Response: `InstitutionalAssetRecordV1_2Envelope`.

Scoped exact asset; a record does not establish title or a tradable instrument.

## listInstitutionalAssets

`GET /btx/hcp/v1/institutional/assets`

Scope: `assets:read`. Effect: `READ`. Request: `path/query only`. Response: `Page`.

List supported financial and operational categories separately.

## recordAssetRights

`POST /btx/hcp/v1/institutional/assets/{id}/rights`

Scope: `assets:write`. Effect: `RECORD`. Request: `RightsStatementV1_2`. Response: `RightsStatementV1_2Envelope`.

Rights assertion bound to issuer and evidence; no change to native ownership.

## ingestPositionBatch

`POST /btx/hcp/v1/institutional/positions/batches`

Scope: `positions:write`. Effect: `RECORD`. Request: `PositionBatchRequest`. Response: `Job`.

Validate entire bounded batch and source sequence; atomically stage/apply observations.

## getPositionObservation

`GET /btx/hcp/v1/institutional/positions/{id}`

Scope: `positions:read`. Effect: `READ`. Request: `path/query only`. Response: `PositionObservationV1_2Envelope`.

Return effective/recorded times, source authority and supersession.

## getPositionSnapshot

`GET /btx/hcp/v1/institutional/positions`

Scope: `positions:read`. Effect: `READ`. Request: `path/query only`. Response: `Page`.

Requires as_of and observed_cutoff; continuation pinned to both.

## recordValuationObservation

`POST /btx/hcp/v1/institutional/valuations`

Scope: `valuations:write`. Effect: `RECORD`. Request: `ValuationObservationV1_2`. Response: `ValuationObservationV1_2Envelope`.

A source mark is distinct from accepted accounting/metric policy.

## getValuationObservation

`GET /btx/hcp/v1/institutional/valuations/{id}`

Scope: `valuations:read`. Effect: `READ`. Request: `path/query only`. Response: `ValuationObservationV1_2Envelope`.

Preserve stale/unavailable state; no zero substitution.

## recordExposureLinks

`POST /btx/hcp/v1/institutional/exposures`

Scope: `exposures:write`. Effect: `RECORD`. Request: `ExposureLinkV1_2`. Response: `ExposureLinkV1_2Envelope`.

Typed financial lookthrough or operational dependencies; bounded graph validation.

## listExposureLinks

`GET /btx/hcp/v1/institutional/exposures`

Scope: `exposures:read`. Effect: `READ`. Request: `path/query only`. Response: `Page`.

Snapshot-filtered graph edges; financial and operational views stay distinct.

## defineInstitutionalMetric

`POST /btx/hcp/v1/institutional/metrics`

Scope: `metrics:admin`. Effect: `RECORD`. Request: `MetricDefinitionV1_2`. Response: `MetricDefinitionV1_2Envelope`.

Versioned policy configuration, not arbitrary formula code.

## listInstitutionalMetrics

`GET /btx/hcp/v1/institutional/metrics`

Scope: `metrics:read`. Effect: `READ`. Request: `path/query only`. Response: `Page`.

Display definitions, roles and eligibility beside each reported total.

## createPortfolioProjection

`POST /btx/hcp/v1/institutional/projections`

Scope: `projections:create`. Effect: `RECORD`. Request: `ProjectionRequest`. Response: `Job`.

Asynchronous consistent snapshot; unresolved inputs produce partial/unavailable metrics.

## getPortfolioProjection

`GET /btx/hcp/v1/institutional/projections/{id}`

Scope: `projections:read`. Effect: `READ`. Request: `path/query only`. Response: `PortfolioProjectionV1_2Envelope`.

Separate financial totals, commitments and operational capability inventory.

## createInstitutionalExport

`POST /btx/hcp/v1/institutional/exports`

Scope: `exports:create`. Effect: `EXPORT`. Request: `ExportRequest`. Response: `Job`.

Build redacted snapshot package under exact mapping and policy.

## getInstitutionalExport

`GET /btx/hcp/v1/institutional/exports/{id}`

Scope: `exports:read`. Effect: `READ`. Request: `path/query only`. Response: `ExportManifestV1_2Envelope`.

Manifest only; original financial and package envelopes remain exact.

## downloadInstitutionalExportChunk

`GET /btx/hcp/v1/institutional/exports/{id}/chunks/{chunk_id}`

Scope: `exports:read`. Effect: `READ`. Request: `path/query only`. Response: `BINARY`.

Authenticated chunk fetch; tenant-bound endpoint, no public bearer URL.

## validateInstitutionalImport

`POST /btx/hcp/v1/institutional/imports/validate`

Scope: `imports:write`. Effect: `RECORD`. Request: `ImportValidateRequest`. Response: `Job`.

Staged chunks, exact digests and mapping checks. No automatic ledger or financial action.

## commitInstitutionalImport

`POST /btx/hcp/v1/institutional/imports/{id}/commit`

Scope: `imports:write`. Effect: `RECORD`. Request: `ImportCommitRequest`. Response: `InteroperabilityReceiptV1_2Envelope`.

CAS over manifest and validation; publish read projection only, no custody mutation.

## getInstitutionalImport

`GET /btx/hcp/v1/institutional/imports/{id}`

Scope: `imports:read`. Effect: `READ`. Request: `path/query only`. Response: `InteroperabilityReceiptV1_2Envelope`.

Replayed identical import returns the same outcome.

## listReconciliationBreaks

`GET /btx/hcp/v1/institutional/breaks`

Scope: `reconciliation:read`. Effect: `READ`. Request: `path/query only`. Response: `Page`.

Prioritize by affected metric, scope and age; hidden error is not an empty position.

## getReconciliationBreak

`GET /btx/hcp/v1/institutional/breaks/{id}`

Scope: `reconciliation:read`. Effect: `READ`. Request: `path/query only`. Response: `ReconciliationBreakV1_2Envelope`.

Source comparison, responsibility and evidence without secret material.

## resolveReconciliationBreak

`POST /btx/hcp/v1/institutional/breaks/{id}/resolve`

Scope: `reconciliation:write`. Effect: `RECORD`. Request: `ResolveBreakRequest`. Response: `ReconciliationBreakV1_2Envelope`.

Resolve by accepted new evidence; never overwrite the native ledger to clear the UI.

## preparePortfolioInstruction

`POST /btx/hcp/v1/institutional/instructions`

Scope: `capital:prepare`. Effect: `PLAN`. Request: `InstructionRequest`. Response: `PortfolioInstructionV1_2Envelope`.

Read portfolio intent into a bounded proposal, not a financial instruction already approved.

## getPortfolioInstruction

`GET /btx/hcp/v1/institutional/instructions/{id}`

Scope: `capital:read`. Effect: `READ`. Request: `path/query only`. Response: `PortfolioInstructionV1_2Envelope`.

Immutable request and provenance; no token forwarding.

## translatePortfolioInstruction

`POST /btx/hcp/v1/institutional/instructions/{id}/translate`

Scope: `capital:prepare`. Effect: `TRANSLATE_TO_DRAFT`. Request: `IdRequest`. Response: `InteroperabilityReceiptV1_2Envelope`.

Create existing v1.1 CapitalPlan/AllocationPlan drafts; execution stays on executeAllocation after ordinary approvals.

## runInstitutionalScenario

`POST /btx/hcp/v1/institutional/scenarios`

Scope: `scenarios:create`. Effect: `RECORD`. Request: `ScenarioRequest`. Response: `Job`.

Deterministic bounded shocks, not unstated forecast or statistical VaR.

## getInstitutionalScenario

`GET /btx/hcp/v1/institutional/scenarios/{id}`

Scope: `scenarios:read`. Effect: `READ`. Request: `path/query only`. Response: `ScenarioResultV1_2Envelope`.

Return financial change separately from operational impacts and unpriced exposures.

## getLayerConformance

`GET /btx/hcp/v1/layer/conformance/{id}`

Scope: `catalog:read`. Effect: `READ`. Request: `path/query only`. Response: `ConformanceStatementV1_2Envelope`.

Per-role test scope and issuer; self-attestation is not centrally granted certification.

## getLayerJob

`GET /btx/hcp/v1/layer/jobs/{id}`

Scope: `jobs:read`. Effect: `READ`. Request: `path/query only`. Response: `Job`.

Owner-scoped durable job status; result_ref points to the typed resource getter. No poll URL from untrusted metadata.

## cancelLayerJob

`POST /btx/hcp/v1/layer/jobs/{id}/cancel`

Scope: `jobs:cancel`. Effect: `RECORD`. Request: `IdRequest`. Response: `Job`.

Cancel bounded projection/import/scenario work before commit or return the already committed result; no finance cancellation implied.

## stageInstitutionalImportChunk

`POST /btx/hcp/v1/institutional/imports/chunks`

Scope: `imports:write`. Effect: `RECORD`. Request: `BINARY`. Response: `StagedChunk`.

Stream an authenticated quota-bounded chunk, verify its declared hash, and return a tenant-owned opaque staged handle.

