# BTX 0.34.8
## Cognitive Reserve Layer v1.2
### Provider neutrality, institutional interoperability and whole-portfolio integration

**Document ID:** BTX-CRL-012 · **Revision:** 1.2 · **Date:** 17 September 2026  
**Canonical edition:** Markdown. This specification, its API and object schemas, and the acceptance catalogue form one implementation contract.  
**Execution target:** the existing private v1.1 implementation after its coordinated handoff.

> One neutral layer connects financial reserves, cognitive assets and the institutions that serve them. Providers implement roles. Portfolio systems exchange attributable records. Customers retain authority over capital and local capability.

# 1. Assignment and release boundary

## 1.1 Deliver the neutral layer

Extend the existing HCP/1 and Cognitive Reserve v1.1 implementation with provider-role composition and institutional asset interoperability. Deliver the registered gateway routes, native record verification, projection and reconciliation services, portable exports, external portfolio instruction adapter, SDKs, neutral portal, desktop-context integration and executable acceptance programme described here. This is 0.34.8 work following v1.1, not a new coin or separate market.

The extension adds 18 signed object types and 43 operations. Preserve the 84 preceding contract operations, their signed bodies and their semantics. Preserve every additional regression case present in the actual private tree, not merely a count from the document package. The earlier 120 HCP and 190 v1.1 cases remain inherited requirements. The 160 cases and 20 journeys in this package are additional.

The product must work for an incumbent institution, a specialist providing only one role, and a company launching a new venue. No legal requirement to be a centralized exchange is encoded in the protocol. Service eligibility belongs to the operator's existing policy and applicable product contracts, not a brand allowlist.

## 1.2 What changes and what stays

Reuse provider enrollment, financial account authority, finite reserve policies, capital comparisons, allocation DAGs, committees, existing finance intents, custodial signing, native settlement and local capability handoff. Extend the existing HCP engine and persistence tier. Add focused modules only where there is no equivalent implementation.

Do not create a second ledger, second downloader, second runtime manager, second provider identity system or second capital execution engine. The institutional projection is a read model of accepted observations; it does not replace custody books or investment-accounting books. No monetary consensus, issuance, chain choice, ExactReplay, funded terms or wallet ownership change is authorized. `.btx` Core v3 remains unchanged. Account and institutional records do not enter a portable model core.

## 1.3 Neutrality is executable behavior

Normative code, routes, schemas, shipped profiles, default providers, sample tenants, SDK dispatch and fixtures must be organized by function rather than by a financial company's name. Tests generate provider identities and run the same journeys with interchangeable providers. Generic fixture names such as `provider-a`, `portfolio-system-b` and `tenant-c` carry no special behavior.

Source attributions in research are not protocol dependencies. Existing third-party license notices are retained. A neutrality check targets operational configuration and dispatch, not legitimate citations or dependency copyright notices. Remove a company-specific integration shortcut only after replacing its behavior with the generic interface and a regression test.

# 2. Baseline, audit and implementation sequence

Record branch, HEAD, tracked diff digest, relevant untracked hashes, build flags, tested binary hashes, active production processes and previous evidence. Read the v1.1 operator handoff and carry unresolved prerequisites forward. Do not reset shared work, overwrite an active binary, access production wallet data or restart a service to test this extension.

Write `audit/crl12-baseline.md`, `audit/crl12-contract-map.csv` and `audit/crl12-migration.md`. Map every new operation and object to REUSED, EXTENDED or NEW production call sites. Inspect the actual HCP engine, codec, type validator, RPC/REST registration, state journal, provider enrollment, local connector, SDK and portal. The path names in this document are integration suggestions, not claims about an unseen private tree.

Freeze common contracts in this order: exact type and route names; authority and role matrix; observation identity and temporal rules; metric eligibility and duplicate handling; export/import format; instruction-to-v1.1 translation. Parallel workers then implement against those contracts. Coordinator owns shared headers, schema aggregation, registrars and builds.

# 3. Architecture: roles rather than company profiles

## 3.1 Advertised provider roles

A ProviderRoleManifest declares one or more of the following roles. A role describes a tested service, not the legal nature of an institution and not a grant from a customer.

| Role | Service supplied | Authoritative boundary |
|---|---|---|
| DISCOVERY | Attributed catalogues and exact packages | Does not determine model truth or spending |
| CUSTODY | Supported custody accounts and recovery | Actual custody arrangement and native signer |
| EXECUTION | Existing venue conversion/execution | Exact venue orders and customer approval |
| FUNDING | Native release/bounty lifecycle | Existing native terms, intents and settlement |
| TREASURY | Reserve policies and capital planning | Existing legal-entity ledger and authority |
| DEVICE_HANDOFF | Exact package delivery to paired clients | Owner-local grants and runtime readiness |
| ASSET_SERVICING | Positions, rights, valuations and reconciliation | Declared record source and accepted policy |
| PORTFOLIO_ANALYTICS | Projections, scenarios and decision context | Read/plan only unless separately authorized |
| FIAT_RAIL | Existing approved fiat transfer interfaces | The actual provider and product agreement |

A role can be offered alone. An analytics service need not hold coins. A discovery service need not run custody. A full-service venue can implement all applicable roles. Product role composition does not confer regulatory permission or financial authority by itself; enforce the existing eligibility adapter at each consequential boundary.

## 3.2 Role manifest contract

Bind manifest to the enrolled ProviderProfile, native network identifiers, exact operations, registered relative paths, effects, evidence references, monotonic sequence and expiry. Every advertised endpoint must exist in the operation registry with the same effect and required dependencies. An endpoint cannot advertise READ while executing an existing financial action.

Resolve identities and endpoint origins through existing enrollment. A model package cannot select a custodian or install a provider root. Do not add a central role registry. A local directory is a view of configured or explicitly discovered providers with timestamps and coverage. Brand, website popularity or catalogue size does not alter trust or role admission.

Manifest update validation rejects sequence rollback, network mismatch, unrecognized critical role behavior and changes requiring new consent. A missing role returns ROLE_UNAVAILABLE. It does not silently fall back to a more powerful service.

## 3.3 Service bindings

A ServiceBinding maps one tenant/entity/portfolio and role to an independently enrolled provider profile and role manifest. It binds owner policy, allowed effects, generation, state and expiry. Activation requires exact owner authority and accepted remote identity. A binding is not an OAuth credential container. Secret references remain in the existing protected credential store.

Permit separate discovery, custody and analytics providers. A hosted client can obtain candidates from A, use finance at B and export approved portfolio observations to C. Existing intents remain attached to their original provider. Switching a discovery binding never replays an unresolved funding intent at a new venue.

Bindings support PROPOSED, ACTIVE and REVOKED. Revocation blocks new work. A separate restricted recovery context retains access needed to reconcile original financial obligations; it does not preserve general spending authority. A provider outage must not prevent existing local public capability from operating.

# 4. Versioning and cryptographic contract

Keep the base `/btx/hcp/v1`. Publish v1.2 discovery at `/extensions/cognitive-reserve/v1.2`; leave the original v1.1 discovery route unchanged. LayerExtensionProfileV1_2 binds the original ProviderProfile and accepted v1.1 extension body IDs, new schema and operation digests, supported features and expiry. Clients do not infer support from software version alone.

Every new signed type has its explicit `V1_2` suffix and `schema_revision: "1.2"`. Use the unchanged HCP domain formula with that exact object type:

```text
body_id = SHA384(
    UTF8("BTX/HCP/" + object_type + "/v1") || 0x00 ||
    LE64(length(canonical_body)) || BTX-PJSON1(body)
)
```

Use the existing native pure ML-DSA-44 application signature path and enrolled provider-role keys. Do not substitute a wallet signature, software release key, JSON Web Token or ordinary JSON serialization for the record signature. Native schema/signature checks precede accepting externally supplied financial observations. The supplied example bodies are structural fixtures, not cryptographic evidence.

Preserve strict canonicalization, duplicate-key rejection, numeric limits and unknown-field failure from existing HCP. UInt quantities and monetary atoms use canonical decimal strings. Decimal Quantity uses coefficient plus scale; Money uses currency, exponent and integer minor units. Production semantics enforce the native MoneyRange and unit registry independently of the broad structural string cap.

Downgrading a v1.2 request cannot discard role restrictions, valuation basis or mandate requirements. Old requests remain valid under old rules; new unsupported requests return PROFILE_UNSUPPORTED. Persisted new data retains a read/reconcile path even when new v1.2 effects are disabled.

# 5. Institutional identity and rights

## 5.1 Asset classes and identifiers

InstitutionalAssetRecord supports five categories: NATIVE_RESERVE, FINANCIAL_INSTRUMENT, CONTRACT_RIGHT, CAPABILITY_RESOURCE and RESEARCH_COMMITMENT. Category and `financial_status` are separate. Native BTX units can be financial holdings; a fund instrument has its actual external rights; a model resource can be operationally useful without being a tradable financial instrument.

An asset ID is scoped to its record authority. Identifiers contain namespace, value and authority reference. Native resource references bind exact package/model/recipe IDs; network references bind the actual genesis identifier. An external security identifier is accepted only from the institution's approved source. Do not manufacture an ISIN, ticker, legal-entity identifier, exchange listing or fund share because a model exists.

The same display name across two authorities is not an identity match. Alias mappings require accepted evidence and a versioned institutional mapping. A collision opens IDENTIFIER_COLLISION and blocks merging. Importing an asset record does not transfer ownership or modify monetary balances.

## 5.2 Rights statements

RightsStatement binds an asset, holder entity, rights type, issuer, validity and contract commitment. Types distinguish public use, license, ownership, contract claim, fund share and sponsor commitment. Transferability is separate and can remain undetermined. A signature authenticates the issuer's assertion; local acceptance depends on its role and evidence.

A native public-release contribution remains a contribution under its terms, not a share of a company's revenues. A licensed model may be usable but not transferable. A public capability can remain usable after an exchange relationship ends. A proposed pooled financial product must come from an actual separately approved instrument, not this record system.

Corporate parent relationships and external legal identifiers aid reconciliation. They do not grant access or debit authority. Existing EntityLink, legal-entity segregation and committee rules continue to govern. Public parent data can describe accounting consolidation without proving ultimate beneficial ownership or instruction authority. [T07]

# 6. Position observation and temporal model

## 6.1 Append-only observations

A PositionObservation binds scope, asset reference, economic position key, custodian position reference, exact quantity, view, status, source authority, effective time, recorded time, sequence and optional superseded record. The source key includes provider identity and stream generation. Store original canonical bytes and signature alongside indexed fields.

Effective time states when the observation applies; recorded time states when it entered the accepted observation history. The receiving service records its own ingestion timestamp and sequence as well. It never trusts a supplied earlier recorded time to rewrite what it knew historically. Retain both source and receipt provenance for cross-provider corrections.

Construct a projection for `(as_of, observed_cutoff)`. Only records effective by `as_of` and accepted by `observed_cutoff` can participate. Within an accepted source stream, select the latest applicable sequence under the source's ordering contract. A higher sequence that is future-effective does not displace the current position prematurely.

## 6.2 Replays, corrections and gaps

Same source/generation/sequence with identical body ID is a replay. Same key with a different body ID is a conflict; quarantine it and open a break. Corrections append and explicitly supersede. Never overwrite an original receipt or change a past signed report.

A source sequence gap reduces coverage. A reconnect either supplies missing records or a signed accepted snapshot with a new watermark and documented replacement scope. An empty response is not proof that positions disappeared. CLOSED positions remain in historical queries and disappear from current included holdings only according to their effective state.

Batch ingestion is atomic for one bounded source batch. Validate account access, envelope, source binding, previous watermark, sequence and row limits before publishing the new watermark. Partial staging can resume; no partial batch masquerades as a complete snapshot. Use the existing transactional database and durable outbox.

## 6.3 Economic deduplication

An economic position can appear in a custody statement, a treasury view and an external portfolio book. Those are observations of one position, not three assets. An accepted mapping links their economic position keys and record authorities. Select the authoritative source for the requested metric and retain corroborating records.

Do not deduplicate solely by asset ID: two customers can each own distinct BTX quantities. Do not deduplicate solely by network address: an omnibus address can represent many beneficial accounts. Conversely, do not add customer liabilities to the custodian's backing assets when producing the same customer total. Unresolved mapping becomes DUPLICATE_CLAIM, not an optimistic sum.

# 7. Valuation and metric eligibility

## 7.1 Valuation observations

Value observations specify asset, exact position, purpose, current/stale/unavailable state, nullable monetary value, policy, evidence, effective/recorded time and validity. The value is the total accepted value of the referenced position, not a unit price. A unit-price adapter multiplies quantity once using an explicit versioned calculation and records the resulting position valuation.

Accepted purposes are MARKET_VALUE, COST_BASIS, REPLACEMENT_SCENARIO and UTILITY. Only the appropriate purpose feeds each metric. A replacement estimate for a useful model never becomes a liquid reserve mark. A missing or stale market input remains unavailable; it is not zero. Preserve actual zero values distinctly from missing values.

Currency conversion records source amount, rate source, observation time, quote convention and rounding policy in evidence. Aggregate with decimal/integer arithmetic. Apply final reporting-currency rounding once at the defined level; do not infer an FX rate from a display label. Financial values used for execution remain subject to the original quote and native policies, not this reporting service.

## 7.2 MetricDefinition

Metrics are versioned policies, not arbitrary user code. Define kind, institutional role, inclusion kinds, direct/look-through/operational basis, valuation purpose and required mandate reference. Supported kinds are AUM, AUC, AUA, PLATFORM_ASSETS, FINANCIAL_NAV, CAPABILITY_COUNT, ACTUAL_COST and SCENARIO_VALUE.

AUM requires an accepted management mandate for that owner/entity/portfolio and as-of date. AUC requires an accepted custody role. AUA requires the actual administration relationship. Platform assets follow the provider's published definition. The same client assets can meet more than one institutional metric; display each separately rather than add them into an invented combined balance.

Financial NAV requires eligible financial positions and valuation policy. Capability count and actual cost are adjacent operational measures. A model duplicated across 50 devices remains one selected capability position with 50 deployments, not 50 purchased assets. A free public resource can count as a capability without receiving a fabricated price.

MetricResult carries a nullable Money value or nullable count, never both. Count is used only by CAPABILITY_COUNT. Missing inputs produce PARTIAL with a labeled priced subtotal or UNAVAILABLE where no value can be formed, including eligible/unpriced/excluded counts. A zero-position complete book can return an actual zero. A source outage that might conceal positions cannot.

## 7.3 Direct holdings and look-through

A direct fund position and its underlying holdings are alternate views. FINANCIAL_NAV/AUM defaults to DIRECT_ONLY. A look-through exposure report replaces each applicable parent with its children at the accepted weights; it never adds parent and child market values. Missing coverage is retained as an unresolved residual.

ExposureLink distinguishes FINANCIAL_LOOKTHROUGH, CAPABILITY_DEPENDENCY and RIGHTS_DEPENDENCY. Financial weights use exact quantities, bounded ranges and declared leverage policy. Operational edges have no financial allocation weight. Reject cyclic financial expansions, conflicting parents and depth/edge overflow. Do not multiply a token holding by a model utility score.

# 8. Whole-portfolio projection

The projection combines financial holdings, commitments and operational capability in one navigable view without combining their units. Inputs include accepted position/valuation records, v1.1 reserve and commitment references, rights, metric policies, exposure links and permitted coarse capability positions. Exact private runtime inventory remains local unless separately shared.

Capture a source-watermark vector, `as_of`, `observed_cutoff`, policy digests and source bindings before reading. All pages share that vector. Use snapshot transactions or a versioned read model with explicit cutoffs. Background source updates must not duplicate or skip rows across pages.

A projection includes per-metric results, canonical record references, reconciliation breaks and coverage. Large projections are partitioned: signed page objects bind the same root snapshot and policy. Do not place ten million rows inside a one-MiB signed body. Cursor tokens are opaque, bounded and MAC-bound to tenant, entity, filters, snapshot and expiration.

Provide a refresh action that creates a new projection. A historical projection remains reproducible after a correction or reorganization. For a chain-dependent commitment, an economic correction updates the new view while preserving earlier observation history and native recovery responsibility.

# 9. Portfolio instructions and the existing capital engine

## 9.1 Read-to-plan bridge

An external portfolio system can send a PortfolioInstruction for one of four actions: draft a reserve allocation, draft a research commitment, draft a capability acquisition, or draft an existing-product referral. The instruction includes exact source projection, entity scope, targets, maximum exposure, objective, business operation ID and expiry.

Preparation checks provenance, entity binding, source snapshot age, rights, role and limits. It does not reserve, sign or broadcast. `translatePortfolioInstruction` produces existing v1.1 CapitalPlan and AllocationPlan drafts and an InteroperabilityReceipt. It has no financial execution effect.

## 9.2 Authorization and translation

The translation is deterministic for an exact instruction and mapping version. Same business ID and body returns the same drafts; a changed body is IDEMPOTENCY_CONFLICT. Draft IDs retain the original provider and instruction mapping. A cross-provider handoff does not reset idempotency or silently redirect money.

Execution remains the existing `executeAllocation` route after ordinary reserve, committee, account, quote and native checks. Changing a reporting mark, device state, portfolio scenario or recommendation cannot update an already approved allocation. A new quote can require a new exact approval under the existing policy.

The v1.1 reserve formula remains authoritative: `max(0, min(E - P, R))`, with E already net of holds. The reporting projection cannot enlarge E or R. Imported positions, forecast savings, pending refunds and sibling-entity holdings cannot fund an instruction.

## 9.3 Local capability outcome

A local acquisition child continues to use CapabilityHandoff, exact Core v3 verification and LocalCapabilityGrant. The local resolver selects resident state, LAN sources and other eligible paths. An institutional system can observe an approved coarse result; it cannot issue arbitrary loader commands or overwrite a local lockfile.

Financial state and local readiness are independent. A public model remains usable after provider loss. A custody balance remains subject to its actual custodian. Copying the portfolio export changes neither fact.

# 10. Interchange package and import safety

## 10.1 Export forms

Deliver JSONL as the canonical interchange stream, CSV as a human/legacy-system projection, and a small desktop-context form for application interoperability. Each export has a signed ExportManifest binding source projection, mapping digest, format, chunk hashes/lengths/row counts, total rows, privacy policy and expiry.

A JSONL record is one original signed envelope or a typed projection record retaining the exact original envelope reference. Preserve legacy signed bytes as bytes where reserialization would change identity. Each newline delimits a complete UTF-8 record; embedded newlines are escaped. Record and chunk limits are checked during streaming, not after loading the entire export into memory.

CSV columns are versioned by a mapping manifest. Use explicit UTF-8, quoted RFC-style fields, exact decimal strings, UTC timestamps, authority/identity columns and status columns. Spreadsheet-formula prefixes in text are escaped in the presentation export; retain the original signed value in the JSONL representation. Do not claim the CSV's presentation transformation preserves the original signature.

## 10.2 Staged ingress

`stageInstitutionalImportChunk` accepts an authenticated binary upload, declared length, SHA-384 and stable idempotency key. Stream to tenant-owned quarantine storage under a reserved quota. Maximum chunk length is 16 MiB. Verify length/hash before returning StagedChunk; incomplete upload leaves no accepted handle. No arbitrary URL or server filesystem path is accepted.

Import validation accepts a signed ExportManifest, opaque staged chunk handles and an approved source binding. Each handle must belong to the same tenant, have the expected digest, remain unexpired and appear only where the manifest permits. Enforce total rows, unique chunk IDs, mapping digest, source authority, exact signature conventions and allowed fields.

Validation creates a durable receipt and a staged projection generation. Commit uses compare-and-swap over manifest, mapping and validation receipt. It publishes read-model observations only. It never credits custody, changes native funds, imports executable code or copies foreign login authority. Repeated commit returns the same result.

## 10.3 Cancellation and expiry

A job can be canceled before publication. Once the atomic publication marker exists, return the committed result rather than claim no effect. A canceled import releases staging leases after active reads finish. Unexpired export readers retain their exact snapshot even when a new projection is available.

Downloads are authenticated, tenant-scoped and no-store when private. Do not issue public bearer URLs containing account identifiers or secrets. A configured object store may back the service internally; source credentials never enter export data or local model packages.

# 11. Adapter contracts for institutional systems

Use generic adapters with versioned manifests: AssetMasterAdapter, PositionSourceAdapter, ValuationSourceAdapter, MandateEvidenceAdapter, ExposureGraphAdapter, PortfolioProjectionSink and PortfolioInstructionSource. Reuse Identity, Eligibility, Ledger, Quote, Custody, ChainObserver, NativeEconomy, Audit and Reporting interfaces from prior work.

Every adapter declares supported operations, schema/mapping digest, source ordering, time semantics, consistency scope, idempotency and ambiguity behavior. An `IMPLEMENTED` manifest must point to a registered production path and conformance evidence. DISABLED and UNAVAILABLE are distinct from an empty successful book.

For a proprietary external portfolio system, the provider implements the adapter using its licensed documented interface. The BTX repository contains the generic contract and a vendor-neutral mock/system fixture, not guessed proprietary API calls. Mapping may use institutional APIs, a data warehouse, signed batch files or existing message infrastructure. Product names and private endpoint assumptions stay outside protocol code.

An upstream outage reduces coverage and raises a source break. A parser error does not become a zero balance. A timeout during an external write returns ambiguity under that adapter's contract; do not retry a financial operation through an alternate institution.

# 12. Desktop and agent interoperability

Support an application-defined FDC3-compatible context under a clearly custom namespace such as `btx.cognitiveReserve.v1_2`. It contains permitted exact references and purpose, not money authority, access tokens, private prompts or the full local inventory. A standard desktop context can correlate an existing external instrument identifier where the host accepts it. Do not label a BTX-specific context as a newly standardized FDC3 type. [T05, T06]

Context selection, opening a capability page and viewing a portfolio are read actions. “Create capital plan” opens an explicit draft. Desktop intent delivery does not authorize a trade, bounty or runtime. A malicious workspace must not gain an execution token by broadcasting context.

Expose matching typed SDK and MCP tools for discovery, scoped projection, scenario, export and draft preparation. Financial execution stays in the existing separately authorized tool. Reuse the owner-controlled local tool for ensure, status and lease release. The new API should never require agents to scrape UI text.

# 13. Scenario analysis

Deliver a transparent deterministic scenario engine over a frozen projection. Supported shocks are reserve price, FX price, provider outage, capability retirement, cost multiplier and loading delay. Each specifies exact target, value, unit and assumptions. A positive price multiplier is dimensionless; a loading-delay increment is milliseconds. Reject mismatched units, negative implied prices and unbounded graph expansion.

Report monetary changes only for eligible priced financial positions and accepted financial weights. Report operational impacts separately: unavailable dependency, increased expected load time, replacement requirement or loss of a rights source. Source coverage and unpriced references accompany every result.

A provider-outage scenario should distinguish loss of new hosted financial access from loss of already acquired local capability. A capability-retirement scenario identifies affected recipes and approved alternatives; it does not imply the native currency price changes by a fixed percentage.

Do not invent a covariance matrix, VaR, liquidity score or model valuation. An external institutional analytics adapter may perform its own licensed analysis using the exported facts and explicitly identify its methodology. This release's core method is DETERMINISTIC_SHOCK_V1.

# 14. Security, permissions and privacy

Reuse HCP OAuth and sender-constrained access; follow the existing public/confidential client profiles. Scope is necessary but not sufficient. Every request checks tenant, legal entity, portfolio, actor, provider binding, role and object authority. Body-supplied provider IDs and creation times cannot override authenticated context. The server signs only a fully validated statement attributed to its accepted role. [T01–T04]

Separate read, import/record, binding administration, metric-policy administration, planning, authorization and execution. Institutional analytics credentials cannot open a custody wallet. Source tokens remain with their adapter; audience-specific tokens are acquired independently, never passed through between providers.

Apply strict outbound origin/redirect policy, DNS rebinding protection, bounded content parsing, prepared database queries and rate limits. Names, rights prose and scenario descriptions are untrusted data. Do not execute formulas, templates, shell strings, model-card instructions or customer-supplied code in the gateway.

Local reporting defaults OFF. Share only approved package/recipe references and coarse outcomes. Prompts, completions, KV, raw memory/fabric keys, local paths, complete inventory and private hardware fingerprints stay local. Financial record retention and product analytics consent remain separate. A whole-portfolio view must not make one managed client's private model estate visible to another.

# 15. Durability, reconciliation and resource control

Use existing transaction/outbox patterns. Unique keys include tenant, entity, source identity, generation and business operation ID. Persist accepted import manifests and immutable records before publishing cursors. No database transaction spans a network fetch, signer call or external system callback.

ReconciliationBreak records source refs, discrepancy kind, current generation, accountable role and evidence. Supported categories include duplicate claim, quantity mismatch, missing price, unknown rights, stale source, identifier collision and sequence gap. Acknowledging a break does not resolve it. Resolution requires accepted superseding evidence; never alter native custody balances to clear a red dashboard.

Default limits: signed body 1 MiB; ingress batch 1,000 rows and 1 MiB total; export chunk 16 MiB; manifest 2,048 chunks; page 100 default/1,000 maximum; provider sources 32; projection metrics 32; dependency fanout 256 and traversal depth 16; scenario shocks 64. Limit database, export and parsing jobs independently from financial executors. Schema maxima are ceilings, not permission to ignore configured memory and disk budgets.

Large-book acceptance runs 100,000 real synthetic rows in the standard process lab and a separately measured 10-million-row workload where resources permit. Record elapsed time, peak memory, disk amplification, export throughput, source lag and cancellation cleanup. Streaming work must not require memory proportional to total book size. Tests must not equate synthetic rows with live client assets.

# 16. API contract and error behavior

The complete 43-operation catalogue is appended and is machine-readable in `schemas/operations-v1.2.json`. `schemas/openapi-v1.2.yaml` combines the new routes with the preceding 84 operations. Compare parsed old operation definitions and schemas during validation; do not quietly edit them while generating the combined file.

All mutating requests require Idempotency-Key and the operation's stable business ID where specified. The server scopes both to authenticated tenant/entity and request body digest. Same key/different body returns conflict. GET requests never reserve, sign, broadcast or prepare money.

Asynchronous creates return Job with an owner-scoped `/layer/jobs/{id}` status path. Polling returns state, nullable typed result reference, error and cancellation disposition. The corresponding typed result getter is used only after success; while pending it returns 409 JOB_PENDING with the same job reference in the safe next-action field. Cancellation affects only the bounded layer job, not an existing capital execution.

Return stable errors including PROFILE_UNSUPPORTED, ROLE_UNAVAILABLE, ROLE_EFFECT_MISMATCH, BINDING_REVOKED, SOURCE_NOT_AUTHORIZED, IDENTIFIER_COLLISION, OBSERVATION_CONFLICT, SNAPSHOT_INCOMPLETE, PRICE_UNAVAILABLE, METRIC_INELIGIBLE, LOOKTHROUGH_CYCLE, MAPPING_MISMATCH, CHUNK_MISMATCH, IMPORT_NOT_VALIDATED, STALE_PROJECTION, DRAFT_ONLY, IDEMPOTENCY_CONFLICT and JOB_PENDING. Retain underlying HCP errors without lossy relabeling.

# 17. User experience and neutral distribution

Keep v1.1's six primary destinations: Overview, Reserves, Capabilities, Build, Approvals and Activity. Add role connections under settings and an institutional workspace within Reserves/Overview. Do not create separate branded variants of the application. Customer journeys vary by permissions and declared service capabilities.

A whole-portfolio screen presents financial reserve, managed/custodied/administered views, research commitments and cognitive holdings in adjacent sections. Each financial number names its definition, scope, currency, as-of and coverage. A missing price says “Valuation needed”; a source gap says “Partial view.” Neither appears as a reassuring zero.

Provider connection uses progressive disclosure: choose needed service, choose or enter provider, inspect exact roles and requested data, confirm one finite binding. No default preference for an incumbent. A new generic provider with conformance evidence receives the same workflow as any other provider.

Keyboard, screen-reader and focus behavior meet WCAG 2.2 AA. Preserve 44-pixel preferred action targets. Charts have tables and labels. An analyst can navigate from a number to its included positions and source evidence without CLI use. A customer can export and change discovery/analytics provider while original financial recovery remains visible. [T09]

# 18. Code integration, packaging and documentation

Extend actual existing HCP modules. Suggested focused areas are `provider_roles`, `service_binding`, `institutional_asset`, `position_projection`, `valuation_policy`, `metric_policy`, `exposure_graph`, `institutional_exchange`, `portfolio_instruction` and `scenario`. Place neutral adapters and desktop integrations outside monetary consensus targets. Reuse one schema registry, one SDK generator and the existing typed client.

Add versioned SQL migrations or equivalent storage migrations. Backfill only from known v1.1 facts; unpriced or unknown rights remain explicit. Legacy reserve snapshots continue to use their original formula and body ID. New read-model tables never imply a new customer monetary balance. Test rollback with accepted imports, open breaks and unresolved older funding.

Update README, HUMANS, AGENTS, API help, neutral integration guide and portal terminology to Cognitive Reserve Layer. Explain provider roles, walletless local use, independent custody, asset/metric definitions and institutional mapping. Do not rewrite the chain's security or monetary purpose to fit a marketing label.

Ship generic deployment templates, Python/TypeScript SDK, data-mapping template, role conformance matrix, two-provider lab and whole-portfolio demo. Research may cite named companies; code and deployment behavior remain generic. A new operator should implement adapter contracts and run conformance rather than request bespoke protocol changes.

# 19. Parallel implementation and completion

Run four to six Grok 4.6 Extra High workers through the actual available Cursor task mechanism. Confirm the exact worker choice and record dispatch; do not invent flags or silently substitute. Use exclusive files or isolated worktrees. Coordinator retains shared headers, route/schema registry, CMake, build scheduling and final integration.

Lanes: A neutrality/version/roles; B assets/rights/temporal positions; C valuation/metrics/exposure; D projection/import/export/reconciliation; E instruction/scenario/adapters; F portal/SDK/desktop; G independent native/process tests. Fresh security and accounting reviewers follow integration and do not certify their own implementation.

Every required case starts NOT_RUN and advances only with its actual evidence. Reference Python tests validate selected semantics; they do not satisfy native signature, custody, process, browser or external institutional-system acceptance. Preserve previous native tests. Run the new cases through registered production routes, not a second in-memory engine hidden in tests.

Final report: initial/final fingerprints, unchanged v1.1 contract comparison, new type/operation registry, migrations, per-role conformance, native test results, process/chain/browser evidence, unresolved failures, actual generic partner demo, privacy observations and operator handoff. Do not commit, push, merge, tag, publish, flip release flags, move live funds or restart production without separate instruction.

# 20. Required acceptance outcomes

The complete acceptance catalogue and journeys are supplied as a separate reading volume and machine-readable CSV. The release-level outcomes are: a new provider can join without source-code branding; roles can be split without token forwarding; institutional records round-trip without inventing ownership; asset metrics are correctly scoped; corrections and gaps remain auditable; portfolio instructions produce governed v1.1 drafts; and the customer's local capability remains independent of a gateway heartbeat.

A particularly important end-to-end proof is a portfolio analyst receiving a signed reserve projection, proposing a new capability allocation, obtaining real v1.1 approvals, completing an isolated native funding/handoff path, then observing the new commitment and usable capability as separate records. That is the bridge from financial capital to cognitive capital, made interoperable without centralizing the underlying system.

<!-- CONTRACT_APPENDICES -->

# Appendix A. Complete operation contract

All paths are under the existing `/btx/hcp/v1` base. Every POST is idempotency-bound; every operation also enforces the entity, source, role and policy checks described in the specification. Job results are polled through getLayerJob.

## getLayerExtension

`GET /btx/hcp/v1/extensions/cognitive-reserve/v1.2`

**Scope:** `catalog:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `LayerExtensionProfileV1_2Envelope`.

Read the pinned extension. No support inferred from a provider name.

## publishProviderRoles

`POST /btx/hcp/v1/layer/roles`

**Scope:** `layer:admin`. **Effect:** `RECORD`. **Request:** `ProviderRoleManifestV1_2`. **Result:** `ProviderRoleManifestV1_2Envelope`.

Provider administration only; endpoints must map to registered supported operations.

## getProviderRoles

`GET /btx/hcp/v1/layer/roles/{id}`

**Scope:** `catalog:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `ProviderRoleManifestV1_2Envelope`.

Read exact signed role manifest by ID; expired claims remain inspectable, not usable for new effects.

## listProviderRoles

`GET /btx/hcp/v1/layer/roles`

**Scope:** `catalog:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Page`.

Local configured directory view only; no canonical global provider registry.

## createServiceBinding

`POST /btx/hcp/v1/layer/bindings`

**Scope:** `bindings:admin`. **Effect:** `BIND`. **Request:** `ServiceBindingV1_2`. **Result:** `ServiceBindingV1_2Envelope`.

Propose or activate only after owner policy, remote identity and allowed role/effects agree.

## getServiceBinding

`GET /btx/hcp/v1/layer/bindings/{id}`

**Scope:** `bindings:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `ServiceBindingV1_2Envelope`.

Return caller-scoped binding, without credentials.

## listServiceBindings

`GET /btx/hcp/v1/layer/bindings`

**Scope:** `bindings:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Page`.

Snapshot-bound listing of the entity bindings.

## revokeServiceBinding

`POST /btx/hcp/v1/layer/bindings/{id}/revoke`

**Scope:** `bindings:admin`. **Effect:** `BIND`. **Request:** `BindingRevokeRequest`. **Result:** `ServiceBindingV1_2Envelope`.

Stop new effects; retain reconciliation access to already accepted financial actions.

## validateAdapterCapabilities

`POST /btx/hcp/v1/layer/adapters/validate`

**Scope:** `layer:admin`. **Effect:** `RECORD`. **Request:** `AdapterValidateRequest`. **Result:** `Job`.

Bounded test job; requires configured test environment and never probes arbitrary URLs.

## getAdapterCapabilityReport

`GET /btx/hcp/v1/layer/adapters/{id}`

**Scope:** `bindings:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `AdapterCapabilityManifestV1_2Envelope`.

Actual supported interface and evidence, not a brand-to-feature mapping.

## registerInstitutionalAsset

`POST /btx/hcp/v1/institutional/assets`

**Scope:** `assets:write`. **Effect:** `RECORD`. **Request:** `InstitutionalAssetRecordV1_2`. **Result:** `InstitutionalAssetRecordV1_2Envelope`.

Register namespaced identity; collisions open a break rather than merging.

## getInstitutionalAsset

`GET /btx/hcp/v1/institutional/assets/{id}`

**Scope:** `assets:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `InstitutionalAssetRecordV1_2Envelope`.

Scoped exact asset; a record does not establish title or a tradable instrument.

## listInstitutionalAssets

`GET /btx/hcp/v1/institutional/assets`

**Scope:** `assets:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Page`.

List supported financial and operational categories separately.

## recordAssetRights

`POST /btx/hcp/v1/institutional/assets/{id}/rights`

**Scope:** `assets:write`. **Effect:** `RECORD`. **Request:** `RightsStatementV1_2`. **Result:** `RightsStatementV1_2Envelope`.

Rights assertion bound to issuer and evidence; no change to native ownership.

## ingestPositionBatch

`POST /btx/hcp/v1/institutional/positions/batches`

**Scope:** `positions:write`. **Effect:** `RECORD`. **Request:** `PositionBatchRequest`. **Result:** `Job`.

Validate entire bounded batch and source sequence; atomically stage/apply observations.

## getPositionObservation

`GET /btx/hcp/v1/institutional/positions/{id}`

**Scope:** `positions:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `PositionObservationV1_2Envelope`.

Return effective/recorded times, source authority and supersession.

## getPositionSnapshot

`GET /btx/hcp/v1/institutional/positions`

**Scope:** `positions:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Page`.

Requires as_of and observed_cutoff; continuation pinned to both.

## recordValuationObservation

`POST /btx/hcp/v1/institutional/valuations`

**Scope:** `valuations:write`. **Effect:** `RECORD`. **Request:** `ValuationObservationV1_2`. **Result:** `ValuationObservationV1_2Envelope`.

A source mark is distinct from accepted accounting/metric policy.

## getValuationObservation

`GET /btx/hcp/v1/institutional/valuations/{id}`

**Scope:** `valuations:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `ValuationObservationV1_2Envelope`.

Preserve stale/unavailable state; no zero substitution.

## recordExposureLinks

`POST /btx/hcp/v1/institutional/exposures`

**Scope:** `exposures:write`. **Effect:** `RECORD`. **Request:** `ExposureLinkV1_2`. **Result:** `ExposureLinkV1_2Envelope`.

Typed financial lookthrough or operational dependencies; bounded graph validation.

## listExposureLinks

`GET /btx/hcp/v1/institutional/exposures`

**Scope:** `exposures:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Page`.

Snapshot-filtered graph edges; financial and operational views stay distinct.

## defineInstitutionalMetric

`POST /btx/hcp/v1/institutional/metrics`

**Scope:** `metrics:admin`. **Effect:** `RECORD`. **Request:** `MetricDefinitionV1_2`. **Result:** `MetricDefinitionV1_2Envelope`.

Versioned policy configuration, not arbitrary formula code.

## listInstitutionalMetrics

`GET /btx/hcp/v1/institutional/metrics`

**Scope:** `metrics:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Page`.

Display definitions, roles and eligibility beside each reported total.

## createPortfolioProjection

`POST /btx/hcp/v1/institutional/projections`

**Scope:** `projections:create`. **Effect:** `RECORD`. **Request:** `ProjectionRequest`. **Result:** `Job`.

Asynchronous consistent snapshot; unresolved inputs produce partial/unavailable metrics.

## getPortfolioProjection

`GET /btx/hcp/v1/institutional/projections/{id}`

**Scope:** `projections:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `PortfolioProjectionV1_2Envelope`.

Separate financial totals, commitments and operational capability inventory.

## createInstitutionalExport

`POST /btx/hcp/v1/institutional/exports`

**Scope:** `exports:create`. **Effect:** `EXPORT`. **Request:** `ExportRequest`. **Result:** `Job`.

Build redacted snapshot package under exact mapping and policy.

## getInstitutionalExport

`GET /btx/hcp/v1/institutional/exports/{id}`

**Scope:** `exports:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `ExportManifestV1_2Envelope`.

Manifest only; original financial and package envelopes remain exact.

## downloadInstitutionalExportChunk

`GET /btx/hcp/v1/institutional/exports/{id}/chunks/{chunk_id}`

**Scope:** `exports:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `BINARY`.

Authenticated chunk fetch; tenant-bound endpoint, no public bearer URL.

## validateInstitutionalImport

`POST /btx/hcp/v1/institutional/imports/validate`

**Scope:** `imports:write`. **Effect:** `RECORD`. **Request:** `ImportValidateRequest`. **Result:** `Job`.

Staged chunks, exact digests and mapping checks. No automatic ledger or financial action.

## commitInstitutionalImport

`POST /btx/hcp/v1/institutional/imports/{id}/commit`

**Scope:** `imports:write`. **Effect:** `RECORD`. **Request:** `ImportCommitRequest`. **Result:** `InteroperabilityReceiptV1_2Envelope`.

CAS over manifest and validation; publish read projection only, no custody mutation.

## getInstitutionalImport

`GET /btx/hcp/v1/institutional/imports/{id}`

**Scope:** `imports:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `InteroperabilityReceiptV1_2Envelope`.

Replayed identical import returns the same outcome.

## listReconciliationBreaks

`GET /btx/hcp/v1/institutional/breaks`

**Scope:** `reconciliation:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Page`.

Prioritize by affected metric, scope and age; hidden error is not an empty position.

## getReconciliationBreak

`GET /btx/hcp/v1/institutional/breaks/{id}`

**Scope:** `reconciliation:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `ReconciliationBreakV1_2Envelope`.

Source comparison, responsibility and evidence without secret material.

## resolveReconciliationBreak

`POST /btx/hcp/v1/institutional/breaks/{id}/resolve`

**Scope:** `reconciliation:write`. **Effect:** `RECORD`. **Request:** `ResolveBreakRequest`. **Result:** `ReconciliationBreakV1_2Envelope`.

Resolve by accepted new evidence; never overwrite the native ledger to clear the UI.

## preparePortfolioInstruction

`POST /btx/hcp/v1/institutional/instructions`

**Scope:** `capital:prepare`. **Effect:** `PLAN`. **Request:** `InstructionRequest`. **Result:** `PortfolioInstructionV1_2Envelope`.

Read portfolio intent into a bounded proposal, not a financial instruction already approved.

## getPortfolioInstruction

`GET /btx/hcp/v1/institutional/instructions/{id}`

**Scope:** `capital:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `PortfolioInstructionV1_2Envelope`.

Immutable request and provenance; no token forwarding.

## translatePortfolioInstruction

`POST /btx/hcp/v1/institutional/instructions/{id}/translate`

**Scope:** `capital:prepare`. **Effect:** `TRANSLATE_TO_DRAFT`. **Request:** `IdRequest`. **Result:** `InteroperabilityReceiptV1_2Envelope`.

Create existing v1.1 CapitalPlan/AllocationPlan drafts; execution stays on executeAllocation after ordinary approvals.

## runInstitutionalScenario

`POST /btx/hcp/v1/institutional/scenarios`

**Scope:** `scenarios:create`. **Effect:** `RECORD`. **Request:** `ScenarioRequest`. **Result:** `Job`.

Deterministic bounded shocks, not unstated forecast or statistical VaR.

## getInstitutionalScenario

`GET /btx/hcp/v1/institutional/scenarios/{id}`

**Scope:** `scenarios:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `ScenarioResultV1_2Envelope`.

Return financial change separately from operational impacts and unpriced exposures.

## getLayerConformance

`GET /btx/hcp/v1/layer/conformance/{id}`

**Scope:** `catalog:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `ConformanceStatementV1_2Envelope`.

Per-role test scope and issuer; self-attestation is not centrally granted certification.

## getLayerJob

`GET /btx/hcp/v1/layer/jobs/{id}`

**Scope:** `jobs:read`. **Effect:** `READ`. **Request:** `path/query only`. **Result:** `Job`.

Owner-scoped durable job status; result_ref points to the typed resource getter. No poll URL from untrusted metadata.

## cancelLayerJob

`POST /btx/hcp/v1/layer/jobs/{id}/cancel`

**Scope:** `jobs:cancel`. **Effect:** `RECORD`. **Request:** `IdRequest`. **Result:** `Job`.

Cancel bounded projection/import/scenario work before commit or return the already committed result; no finance cancellation implied.

## stageInstitutionalImportChunk

`POST /btx/hcp/v1/institutional/imports/chunks`

**Scope:** `imports:write`. **Effect:** `RECORD`. **Request:** `BINARY`. **Result:** `StagedChunk`.

Stream an authenticated quota-bounded chunk, verify its declared hash, and return a tenant-owned opaque staged handle.

# Appendix B. Signed object fields

All new types require `schema_revision=1.2`, `provider_id` and `created_at`. The complete strict field types and nested structures are in CognitiveReserveLayer.schema.json. Nullable fields explicitly represent unavailable values; cross-field and authority checks are mandatory.

## LayerExtensionProfileV1_2

`extension_id`; `parent_profile_ref`; `base_extension_ref`; `schema_digest`; `operations_digest`; `supported_features`; `expires_at`.

## ProviderRoleManifestV1_2

`manifest_id`; `profile_ref`; `roles`; `endpoints`; `network_refs`; `conformance_refs`; `sequence`; `expires_at`.

## ServiceBindingV1_2

`binding_id`; `scope`; `role`; `remote_profile_ref`; `remote_role_ref`; `permitted_effects`; `owner_policy_ref`; `generation`; `status`; `expires_at`.

## AdapterCapabilityManifestV1_2

`adapter_id`; `interface_name`; `interface_revision`; `schema_digest`; `operations`; `support`; `ambiguity_contract_ref`; `evidence_refs`.

## InstitutionalAssetRecordV1_2

`asset_id`; `asset_kind`; `identifiers`; `native_resource_refs`; `rights_ref`; `quantity_unit`; `financial_status`; `record_authority_ref`; `effective_at`; `generation`.

## RightsStatementV1_2

`rights_id`; `asset_ref`; `holder_entity_id`; `rights_kind`; `transferability`; `contract_digest`; `issuer_ref`; `valid_from`; `valid_until`.

## PositionObservationV1_2

`observation_id`; `scope`; `asset_ref`; `economic_position_key`; `custodian_position_ref`; `quantity`; `view`; `status`; `authority_ref`; `effective_at`; `recorded_at`; `sequence`; `supersedes`.

## ValuationObservationV1_2

`valuation_id`; `asset_ref`; `position_ref`; `purpose`; `status`; `value`; `valuation_policy_ref`; `evidence_refs`; `effective_at`; `recorded_at`; `valid_until`.

## ExposureLinkV1_2

`link_id`; `scope`; `source_ref`; `links`; `financial_leverage_policy_ref`; `effective_at`; `coverage_bps`.

## PortfolioProjectionV1_2

`projection_id`; `scope`; `as_of`; `observed_cutoff`; `watermarks`; `metric_results`; `position_refs`; `operational_refs`; `reconciliation_refs`; `next_cursor`.

## MetricDefinitionV1_2

`metric_id`; `metric_kind`; `scope_role`; `inclusion_kinds`; `basis`; `valuation_purpose`; `mandate_required`; `policy_ref`; `generation`.

## ExportManifestV1_2

`export_id`; `scope`; `projection_ref`; `format`; `mapping_digest`; `chunks`; `total_rows`; `privacy_policy_ref`; `expires_at`.

## PortfolioInstructionV1_2

`instruction_id`; `scope`; `source_projection_ref`; `source_system_id`; `requested_action`; `objective`; `maximum_exposure`; `target_refs`; `client_operation_id`; `expires_at`.

## InteroperabilityReceiptV1_2

`receipt_id`; `scope`; `operation_id`; `request_body_id`; `state`; `result_refs`; `original_provider_ref`; `sequence`.

## ScenarioDefinitionV1_2

`scenario_id`; `scope`; `projection_ref`; `shocks`; `method`; `assumption_refs`; `expires_at`.

## ScenarioResultV1_2

`result_id`; `scope`; `scenario_ref`; `financial_change`; `unpriced_refs`; `operational_impacts`; `source_coverage_bps`; `calculation_version`.

## ConformanceStatementV1_2

`statement_id`; `role_manifest_ref`; `candidate_fingerprint`; `test_manifest_digest`; `evidence_level`; `passed_case_ids`; `unrun_case_ids`; `issuer_class`; `expires_at`.

## ReconciliationBreakV1_2

`break_id`; `scope`; `kind`; `source_refs`; `state`; `assigned_role`; `resolution_refs`; `generation`.

# Appendix C. Typed value rules

Quantity is coefficient plus scale; Money is currency, exponent and integer minor units. ExactRef contains the exact signed object type and SHA-384 body ID. Scope is tenant/entity/portfolio. MetricResult uses either money or count, with source completeness and explicit unpriced/excluded counts. Export chunks bind ID, digest, byte length and rows. No generic text field creates financial or runtime authority.

<!-- READING_REFERENCES -->

# Research and design references

Primary-source links below support the attributed facts and precedents. The scenario calculations and proposed BTX contracts are the document’s analysis. Full publisher attribution and research notes are in the accompanying research register.

**[T01] FAPI 2.0 Security Profile.** final edition, reviewed 2026-09-17. [Source](https://openid.net/specs/fapi-security-profile-2_0-final.html).

**[T02] OAuth 2.0 security best current practice, RFC 9700.** 2025-01. [Source](https://www.rfc-editor.org/rfc/rfc9700.html).

**[T03] OAuth DPoP, RFC 9449.** 2023-09. [Source](https://www.rfc-editor.org/rfc/rfc9449.html).

**[T04] OAuth Rich Authorization Requests, RFC 9396.** 2023-05. [Source](https://www.rfc-editor.org/rfc/rfc9396.html).

**[T05] FDC3 Context Data 2.2.** 2.2. [Source](https://fdc3.finos.org/docs/context/spec).

**[T06] FDC3 2.2 standard.** 2025-04. [Source](https://fdc3.finos.org/docs/fdc3-standard).

**[T07] Level 2 LEI data: who owns whom.** accessed 2026-09-17. [Source](https://www.gleif.org/en/lei-data/access-and-use-lei-data/level-2-data-who-owns-whom).

**[T09] WCAG 2.2.** 2.2. [Source](https://www.w3.org/TR/WCAG22/).

