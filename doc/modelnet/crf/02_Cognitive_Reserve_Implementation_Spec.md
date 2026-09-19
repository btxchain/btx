# BTX 0.34.8
## Cognitive Reserve Framework v1.1
### Treasury, capital allocation and institutional hosted integration

**Document ID: BTX-HCP-011 · Revision 1.1 · 17 September 2026**  
**Canonical edition: Markdown. Execution target: the existing private HCP/1 implementation, after its current coordinated handoff.**

> Turn the hosted control plane into a complete Cognitive Reserve product. Reuse the existing financial and capability boundaries. Add the institutional objects, allocation logic, customer experience and evidence needed to operate a capital business.

# 1. Assignment and precedence

## 1.1 Build on the current implementation

The previous HCP/1 round establishes provider enrollment, seven signed object types, 34 REST operations, custody and native-economy adapters, finance intents, ledger reconciliation, walletless handoff, events and 120 native acceptance cases. Preserve those contracts and actual implementation unless a recorded defect requires a compatible correction. Do not create another HcpEngine, downloader, wallet policy, local runtime manager or customer ledger.

This round adds legal-entity portfolios, reserve policies and snapshots, workload economics, cognitive holdings, capital plans, approval committees, research programmes, existing-product referrals, reports, a coherent portal and SDK contracts. The external strategy and guide are standalone documents. Engineering uses both versions: the old specification remains the base for unchanged financial, security, device and recovery behavior; this document supplies the additive Cognitive Reserve layer.

## 1.2 Core product invariant

Financial capital, cognitive holdings and funding commitments remain separate objects. BTX reserve balances are money. A model, adapter or capability recipe is a productive resource with declared rights and observed readiness. A release or bounty contribution is a commitment under its native terms. A UI must not combine their nominal values into one invented net asset value.

Public acquisition has no compulsory BTX toll. The local connector does not require a funded wallet or full monetary synchronization for public capability. CEX account policies govern financial actions; LocalCapabilityGrant governs device effects. A committee approval is not a runtime grant. An acquired public capability remains usable when a hosted subscription or provider session ends.

## 1.3 Authorized scope

Implement every new operation and acceptance family in this package. Existing exchange identity, trading, custody, credit, compliance and legal-product systems remain adapters, not replacements. No monetary consensus, issuance, ExactReplay, wallet ownership or native funded terms change is authorized. No new revenue-share security, pool token, yield promise, global matching engine or public inference service is introduced.

The capital comparison can evaluate an external-service route, but it does not route prompts or execute API consumption. Credit, derivatives, equipment finance and other partner opportunities are represented through existing eligible products and their actual contracts. Product discovery or referral is not execution or funding.

# 2. Additive protocol and compatibility

## 2.1 HCP/1 remains the base

Keep `/btx/hcp/v1` and the seven original signed object schemas unchanged. Publish the negotiated extension at `GET /extensions/cognitive-reserve` beneath that base. Its ReserveExtensionProfileV1_1 binds the enrolled ProviderProfile body ID, protocol revision, supported feature names, schema digest, operation catalogue digest and limits. A provider profile alone does not imply extension support.

Use explicit new object types ending in `V1_1`; do not append unknown fields to old strict signed bodies. Continue the existing HCP body-domain formula with the exact new object type. The old type's bytes, hash and signature semantics remain identical. Extend the object-type validator with an exact reviewed allowlist; do not simply relax it to arbitrary names because the suffix contains underscores.

Existing `.btx` Core v3 and CAPABILITY_HANDOFF_V1 remain the portable capability format. This round needs no Core v4. Account-specific portfolios, approvals, economic assumptions and reserve policies stay outside portable package cores.

## 2.2 Negotiation and rollback

An old server returns a clear unsupported result for extension routes. A new client still performs old discovery/handoff when permitted but does not silently approximate a reserve or committee operation with unrestricted old funding. An old client continues using unchanged base operations.

Disabling the extension prevents new capital effects. It does not abandon already accepted intents, refunds, ledger holds, customer exports or physical runtime cleanup. A schema rollback preserves a read/reconcile path for each accepted new operation. Key rotation binds old and new profile identity under the existing enrollment rules.

# 3. Baseline audit and contract freeze

Record branch, HEAD, tracked diff digest, relevant untracked hashes, binary hashes, build flags, local services and disk/RAM headroom. Read the current HCP handoff and carry each FAIL or NOT_RUN prerequisite forward. Public repository content and screenshots do not establish private production behavior.

Map each new operation to actual code symbols with REUSE, EXTEND or NEW. Trace an existing finance intent through account policy, reservation, signer, native broadcast and receipt; trace handoff through package verification, local grant, ensure, readiness and retirement. Preserve existing regression tests.

Coordinator owns schema aggregation, route registration, CMake and shared headers. Freeze the entity key, intent-child binding, reserve formula, approval digest and event contracts before parallel workers edit dependent modules. A module is complete only when a registered call path reaches it and executable tests establish its behavior.

# 4. Architecture and trust zones

The hosted product comprises six application services: entity/portfolio, reserve, workload/planning, approval/programme, existing financial execution, and reporting/portal. These may share a process only where the existing architecture permits; authority remains explicit.

| Service | Authoritative inputs | Permitted effects |
|---|---|---|
| Entity and portfolio | CEX legal-account registry and accepted delegation | Scoped management views and policy references |
| Reserve | Ledger availability, encumbrances, policy and dated prices | Snapshot; proposal; bounded allocation reservation |
| Capital planner | Workload evidence, local feasibility summary, rights and quotes | Immutable alternatives and exact child-leg plan |
| Approval | Distinct authorized people, rule generation and plan digest | Financial authorization record |
| Financial executor | Existing HCP intents, native terms and custody policy | Existing approved venue/native operations |
| Local capability service | Package, local trust and finite local grant | Acquisition, materialization and local readiness |

Catalogue and model services cannot reach custody signing. Public browser/explorer routes remain read-only. No arbitrary RPC passthrough is added. Conventional HTTPS, OAuth and extension signatures have their declared roles; they do not convert the hosted edge into native PQ1 transport.

# 5. Legal entities, accounts and portfolios

## 5.1 Identity graph

Use separate tenant, legal_entity_id, account_id, portfolio_id, person_id, agent_principal_id and device_id. Obtain authenticated context from the identity adapter, then cross-check object references. A caller cannot select another account by editing JSON. Bind every stored object and uniqueness constraint to tenant and legal entity.

EntityLink records parent/child or adviser relationships, accepted parties, scope, generation and expiry. An aggregate family or corporate view is read authority only unless a separate exact delegation grants an action. No cross-entity pooling or debit is inferred. A transfer between entities uses existing properly authorized exchange rails, with both sides' requirements satisfied.

## 5.2 Roles and lifecycle

Support viewer, drafter, technical reviewer, financial approver, treasury operator, programme sponsor, auditor and administrator. Administrators cannot silently approve their own policy expansion through a lower-privilege path. Adviser access may draft and compare while execution remains disabled.

SCIM or an equivalent enterprise identity lifecycle can remove people and groups. Revocation invalidates future approvals where the accepted rule requires current membership; a stale cached group list cannot keep signing authority alive. Agents have distinct principals but do not manufacture additional human committee seats. [T09]

# 6. Reserve objects and accounting

## 6.1 Orthogonal purpose and state

A portfolio may label capital strategic reserve, current deployment, research or liquidity buffer. Those labels do not move funds or change title. Ledger state separately distinguishes available, held unsigned, broadcast pending, committed on chain, refund pending, returned and externally encumbered.

Define E as ledger-confirmed AVAILABLE BTX atoms after existing holds and encumbrances. Define P as the policy's protected reserve floor. Define R as remaining valid mandate capacity after settled lifetime spend and outstanding reservations. New allocation capacity is:

```text
capacity = max(0, min(E - P, R))
```

Do not subtract the same hold twice. Do not include pending deposits, expected refunds, sibling-entity funds, forecast savings or cognitive holdings in E. Soft departmental budgets are authority envelopes, not extra cash. Compute with checked integers; never float BTX balances.

## 6.2 ReserveSnapshot

A snapshot binds ledger sequence, portfolio, policy generation, observed time and all component amounts. Reporting-currency values use an explicit dated price observation and currency exponent. Native atoms remain authoritative. A stale or unavailable price produces unavailable valuation, not zero and not permission to execute.

ReservePolicy specifies protected floor, per-plan maximum, total lifetime capacity, outstanding exposure, permitted native actions, permitted source assets, expiry and replenishment mode. Every monetary mutation atomically checks ledger and policy under a consistent lock order.

# 7. Replenishment and reserve formation

Default replenishment mode is SUGGEST. It produces a plan and never submits a trade. An explicitly authorized AUTO policy can replenish within lower/target bands, a cooldown, maximum order size, cumulative turnover, source-asset ceiling, quote age, slippage and fee caps. Only one live replenishment owner exists per policy generation.

A reporting-currency floor is converted to atoms with conservative upward rounding from an eligible price; a configured stress haircut reduces the accepted price before conversion. Reject zero, negative, non-finite or stale prices. Never trade merely because a chart's mark changed.

Conversion and funding are separate legs. After a conversion succeeds and funding fails, retain the acquired BTX and report partial success. No automatic reverse trade follows without prior exact authority. A refund restores actual account balance but does not replenish lifetime authorization unless a separately approved policy defines that recycling rule.

# 8. Cognitive holdings

CapabilityPosition binds exact package core, recipe/lock, resource IDs, acquisition/funding references, rights reference, allocation of actual costs, holder entity and current evidence. Track lifecycle ACQUIRED, DEPLOYING, USABLE, SUPERSEDED or RETIRED separately from financial state. Runtime readiness is an expiring local observation or lease, not a permanent property of the portfolio entry.

Count a shared base's acquisition cost once under the selected cost-allocation method. Device replicas are deployments, not repeated ownership claims. Do not assign a market price to a free public model because it is large or useful. Rights can be public, licensed or contract-specific; a contribution does not imply exclusive IP or revenue rights.

The CEX receives only owner-approved coarse holding information. Private inventories, prompts, KV state, exact hardware layouts and local paths remain local by default. Retirement removes a management selection; it cannot remotely delete public files or interrupt an active generation without the owner's local policy.

# 9. Workload and ownership comparison

## 9.1 Input contract

WorkloadProfile records objective, accepted-task definition, quality/evidence minimum, volume range, horizon, data boundary, latency/throughput needs, eligible runtime profiles and assumptions. Use exact currency/minor-unit fields, decimal rates and dated sources. Missing costs remain unknown. Unknown quality is not treated as equivalence.

Compare routes REUSE_LOCAL, ACQUIRE_PUBLIC, COMPOSE_LOCAL, ACQUIRE_LICENSED where supported, FUND_RELEASE, FUND_CREATION and RETAIN_EXTERNAL_SERVICE. The last is a planning alternative only. Include acquisition, hardware allocation, energy, operations, maintenance, updates, replacement, network and external-service costs without double counting owned hardware in both upfront and annual lines.

## 9.2 Economics and selection

Calculate cash flows per period and, when requested, discounted values under an explicit rate. Report break-even volume only when the assumptions support a solution. Rank feasible alternatives with a Pareto view over task evidence, time to capability, total cost, memory and rights. A user can prioritize cost or latency; no opaque universal score claims scientific truth.

Bind TCOComparison to workload version, recipe candidates, input observations, local feasibility summary and calculation version. Recalculation creates a new ID. Approval of one comparison is not authority to accept a worse quality threshold or stale quote. Estimated savings are displayed separately from measured post-deployment savings.

# 10. Capital plans and bounded allocation DAGs

CapitalPlan records the objective, comparison, preferred route, reasons, maximum exposure, expected useful outcome and exact dependencies. AllocationPlan expands it into at most 32 legs with depth at most 16. Reject cycles, missing dependencies, duplicate leg IDs and ambiguous recipients.

Leg kinds include existing venue conversion, existing native FUND_RELEASE/FUND_BOUNTY/CLAIM/REFUND, separately authorized partner referral or execution reference, package handoff, local preparation and reporting. Each financial leg binds entity, portfolio, native terms or venue quote, maximum amounts, fees, effect, child operation ID and compensation policy.

A parent plan is not a new consensus contract. Financial children reuse existing HCP FinanceIntent and native settlement semantics. A local child reuses CapabilityHandoff and LocalCapabilityGrant. Cross-entity legs require distinct authorizations. Discovery failure does not spawn a funded bounty without an approved leg.

# 11. Human committees and agent mandates

ApprovalRule binds legal entity, eligible roles, distinct-person quorum, initiator exclusion, thresholds, veto policy, expiry and generation. ApprovalRequest binds the immutable allocation digest, rule digest, reserve policy generation, exact maximum financial effects and attached decision packet.

ApprovalDecision binds a verified person or authorized principal to that request and a monotonic decision sequence. Count the latest valid decision once per distinct person. Two sessions or keys controlled by the same person are one seat. An adviser or agent cannot count as a human approver unless the exact accepted rule deliberately defines a non-human authority class.

Changes to plan, payer, policy, terms, recipients, quote limits or approval rule invalidate mismatched decisions. Split submissions cannot avoid cumulative thresholds. Final submission rechecks quorum and role validity atomically with reservation. One UI review can collect both financial and local permissions, but stores and validates them as separate authorities. Use rich authorization details where appropriate, not an all-purpose `approve=true`. [T02]

# 12. Research programmes and co-funding

ResearchProgram aggregates an objective, evidence requirements, timetable, eligible native bounties/releases and participating entities. It provides a management view and programme budget; it does not create a fungible pool token or override native award/refund conditions.

ProgramMembership binds a member entity's accepted role and ceiling. Programme participation is not debit authority. Each commitment maps to the participant's exact native lot and refund controller. An aggregate progress bar must not fabricate on-chain pooling, independent evaluator votes or rights to another sponsor's funds.

Supplier submissions, evaluation records and awards reuse the current native bounty machinery. The programme can expose public or private evidence according to terms, but never executes arbitrary submitted code in the gateway. A newly useful output joins the capability portfolio through verified package and handoff routes, not through an award label alone.

# 13. Durable financial execution

Preserve the existing HCP state machine and exact signed transaction journal. A parent allocation has PLANNED, APPROVAL_PENDING, AUTHORIZED, EXECUTING, PARTIAL, COMPLETED, RECONCILIATION_REQUIRED and CANCELED_WHERE_SAFE. Child states remain authoritative.

Use durable uniqueness over provider, tenant, legal entity and client_operation_id, with a stored body digest. Same ID/same body returns the existing outcome; same ID/different body is a conflict. A cross-CEX retry is not idempotent globally and cannot automatically replay an uncertain spend.

Persist the exact signed native bytes before broadcast. Signer timeout is UNKNOWN until reconciled. Keep holds through ambiguous external outcomes. Cancellation stops new uncommitted work; it cannot undo a signature, trade or broadcast. Reorganizations correct observations and pause dependent unsent work without pretending a known release secret was forgotten.

No SQL transaction spans a network call or HSM operation. The existing durable outbox and fencing owner dispatch each child. Source and destination accounting is reconciled independently, with fee/principal separation. Recovery tests must restart all gateway replicas, not just one function.

# 14. Existing financial and infrastructure products

ProductOffer identifies the actual provider, product class, eligibility policy, rights/contract reference, cost disclosure, supported action and expiry. Classes can include custody, spot/OTC execution, treasury credit, hedging, infrastructure finance and research administration. Product labels do not establish legal eligibility or an executable contract.

A referral creates an attributable handoff to an existing approved product service. Execution requires that service's exact quote, authorization and contract. An encumbered asset cannot simultaneously count as free capability-funding liquidity. No protocol staking yield is invented for BTX.

Hardware and compute partners receive only the approved deployment requirement, not customer prompts or secrets. The framework links physical-capital procurement to cognitive-capital plans without building a GPU-hours exchange. Track referral, accepted application, executed contract and realized fee as different states.

# 15. Reports and spend capture

ReserveReport has three sections: financial reserves, active capital commitments and cognitive holdings. Currency valuation applies only to quantities with a defined eligible price or cost basis. Do not add duplicated devices, expected research outcomes or model estimates into liquid reserve NAV.

Produce CFO/committee reports, family-group read-only consolidation, legal-entity statements, research programme reports and operational deployment summaries. Bind report to snapshot sequences and source observations; paginate large holdings and export asynchronously. A new report correction supersedes rather than edits signed historical output.

Implement a version-pinned FOCUS 1.3 import/export mapping for compatible cost data. Validate against the chosen edition and extension rules. Preserve provider invoice IDs, periods, currencies, allocation method and duplicate-import keys. Accounting classification is a customer-controlled mapping of facts; do not hardcode every research payment as a capitalizable intangible. [T06, T08]

Spend capture is measured through actual customer baselines: service spend replaced, capability acquisition and maintenance, capital funded, reserve balances and executed financial fees. Infrastructure forecasts establish market context, not a ledger entry or an automatic addressable market.

# 16. Customer experience

Use six primary destinations: Overview, Reserves, Capabilities, Build, Approvals, Activity. Entity and portfolio selection are persistent and visible beside every financial action. Family/group views clearly display when the user is viewing multiple entities and require a payer choice before drafting effects.

One primary action starts a plan. The system gathers workload and local feasibility, shows alternatives, proposes an exact allocation and presents one decision packet. Use progressive disclosure for tensor, chain and custody details. Never require the user to understand native RPC names for an ordinary journey.

Financial execution and local readiness have separate timelines. Examples: “Capital committed; release awaiting disclosure,” “Conversion completed; funding needs review,” “Capability ready on this device,” “Outcome being reconciled; do not resubmit.” Do not display a single green Completed badge for a partly funded/partly deployed plan.

Free public acquisition remains a one-action happy path under an existing finite local policy. No hidden subscription, standing debit, public seeding or new software root is attached. Keyboard navigation, focus order, accessible status messages, non-color error cues and WCAG 2.2 AA are mandatory; prefer 44-pixel interaction targets. [T05]

# 17. Authentication and authorization

Reuse the current HCP OAuth resource-server boundary and the CEX's established identity provider. Confidential institutional clients use the supported FAPI 2.0 profile, sender constraints and pushed authorization where deployed. Public desktop/local connectors use their separate authorization-code/PKCE and supported sender-binding profile; do not embed a shared client secret or claim confidential-client conformance. [T01, T04, T10]

DPoP binds token use to method and target context, not the capital plan body. The immutable plan and intent digests bind authorization content. Generate proof per request using the exact method and URL. Deny audience mismatch, replay, wrong tenant and privilege escalation. [T03]

The operation catalogue is the authority for scopes. New scopes include entities:admin, reserve:read, capital:read, capital:prepare, capital:approve, capital:execute, holdings:write, products:read, products:refer, reports:create and reports:read, plus existing base scopes. Scope never replaces object, legal-entity, role and policy checks. A read GET cannot prepare, reserve, sign or execute money.

# 18. Privacy and portability

Reporting defaults OFF on the local connector. A customer may share a coarse feasibility or readiness summary, bound to the plan/device and expiry. Keep prompts, completions, KV, complete local inventories, absolute paths, secrets, memory addresses and private runtime traces off the hosted control plane.

Provider-specific device IDs are pairwise. Group/adviser access is explicitly scoped. Financial records follow the account's retention policy; catalogue analytics consent is separate. No automatic sale of identifiable capability-demand data is introduced.

Exports contain exact packages, locks, portfolio facts, policy snapshots, approval evidence, intent/receipt references and custody obligations. They contain no transferable login token, wallet private key or promise that custody rights migrate by copying a file. Provider exit preserves local public capability and continues reconciliation of the original provider's pending finances.

# 19. Persistence and concurrency

Use the existing transactional persistence tier. Tables or equivalent collections for entities, portfolios, policies, plans, approvals, programme members and positions include tenant/entity keys. Financial business IDs and tombstones outlive ordinary HTTP cache retention.

Reserve atomically against authoritative account availability and policy capacity. Lock in a stable tenant/entity/portfolio order. All replicas share unique constraints and fencing; a per-process mutex is insufficient. Use optimistic versions on drafts and immutable revisions on accepted statements.

Durable event records carry provider, tenant, entity, stream generation, sequence, stable event ID and exact object version. Delivery is at least once. Snapshot-bound pagination prevents changing state from duplicating or skipping financial rows. CURSOR_TOO_OLD initiates reconciliation. Slow exports, SSE clients and unavailable product adapters cannot exhaust signer capacity.

# 20. Resource limits and performance programme

Keep portable extension bodies at or below 1 MiB, candidate recipes at 64, allocation legs at 32, depth at 16 and exact resource references at 256. Default page size is 100; configured maximum is 1,000. Expensive reports and comparisons are bounded jobs with cancellation. Accepting a request does not promise an immediate financial or local outcome.

Run a declared test environment with 1,000 read requests/second, 100 plan/approval writes/second, 10,000 queued jobs and 100,000 history rows as initial engineering workloads. These are acceptance workloads, not published service benchmarks. Report latency distributions, queue occupancy, memory, database contention and recovery. Never count synthetic sparse data as transferred model payload or simulated custody as native settlement.

# 21. API contract and errors

The accompanying catalogue defines 50 additive operations under `/btx/hcp/v1`. OpenAPI includes the unchanged 34 base operations where the baseline file is available. Each new request and response has a strict schema; decimal atom strings and exact IDs are preserved in both SDKs.

Every financial POST requires a stable business-operation ID and Idempotency-Key, expected immutable digests and appropriate policy context. A decision endpoint obtains person identity from authentication, not a user-entered name. An execution endpoint receives an approved allocation reference; it does not accept replacement amounts at submit time.

Errors include ENTITY_SCOPE_DENIED, RESERVE_FLOOR_BREACH, MANDATE_EXHAUSTED, PRICE_STALE, QUALITY_UNPROVEN, INPUT_UNKNOWN, PLAN_CHANGED, QUORUM_REQUIRED, SELF_APPROVAL_DENIED, POLICY_REVOKED, PRODUCT_INELIGIBLE, ENCOUNTERED_UNKNOWN_EFFECT, IDEMPOTENCY_CONFLICT and PROFILE_UNSUPPORTED. Return stage, retryability, exact reference, cleanup/reconciliation state and the next permitted action. UNKNOWN is not “nothing happened.”

# 22. Local connector integration

Extend the current hosted connector with a capital-plan correlation and optional feasibility-summary exchange. It still imports the exact Core v3 package through the native codec and calls the existing local planner. A CEX estimate cannot override a more current local memory, locality or runtime decision.

A local plan can combine a resident base, LAN adapter, local tokenizer and compatible runtime cache. Preserve private-fabric and execution grants, generation leases and cancellation fences. Finishing financial approval does not reclaim memory, start arbitrary code or make a runtime ready.

A portal can send a handoff to a paired outbound-only device. Browser code never discovers an unauthenticated local wallet or unrestricted runtime port. The user can complete the same workflow through the typed SDK/MCP tools without scraping presentation text.

# 23. Adapter interfaces and code integration

Reuse Identity, Eligibility, Ledger, Quote, Custody, ChainObserver, NativeEconomy, Package, Audit and Reporting adapters. Add or extend EntityDirectory, ReserveView, ApprovalDirectory, WorkloadEvidence, HoldingsView, Programme and ProductCatalogue interfaces. Each declares timeout, ambiguity, expected-version and idempotency behavior.

Proposed focused modules are `hcp/reserve`, `hcp/entities`, `hcp/capital_plan`, `hcp/approvals`, `hcp/programmes`, `hcp/holdings` and `hcp/reports`; reconcile those names to the actual private source. Do not create another public financial gateway inside `btx-modeld`. Model transfer and local runtime modules consume only narrow sanitized plan references.

# 24. Commercial instrumentation

Record actual customer assets, executed notional, principal committed, fees earned and customer outcomes separately. Custody revenue uses a defined time-weighted fee base. Execution revenue uses executed orders and actual fees. Programme administration uses the contracted basis and recognized events. Product referrals use the provider's accepted/executed status, not the click count.

No revenue is booked from a model download, reserve mark change, deposited principal or speculative future programme success. Multi-currency reports retain original units and valuation observations. Disclose sponsored discovery and affiliated suppliers as presentation metadata, not protocol truth.

# 25. Documentation and partner kit

Replace external v1.0 strategy and integration reading editions with the standalone v1.1 documents. Retain v1.0 protocol artifacts and base acceptance history under compatibility. Update README, HUMANS, AGENTS, help, SDK examples and the partner portal around Cognitive Reserve, without changing effects by renaming them.

Provide a reproducible two-provider lab, local walletless acquisition, an entity/committee demonstration, reserve-floor concurrency, a partial conversion failure, a native funding/refund round trip and provider exit. Publish exact adapter mappings, supported profiles, schema digests, source attribution and deployment prerequisites. A second partner should map adapters and run conformance rather than fork BTX.

# 26. Parallel Cursor execution

Use Grok 4.6 Extra High workers through the actual supported Cursor task mechanism. Confirm dispatch and record worker ownership; never fabricate an unavailable model identifier. Four to six concurrent implementation workers are appropriate when host resources permit. Coordinator retains shared headers, routes, schemas, CMake, build scheduling and integration.

Suggested lanes: A contracts/compatibility; B entities/reserves; C workload/plans; D approvals/programmes; E holdings/products/reports; F portal/SDK/local connector; G native process/chain tests. Fresh reviewers audit authority, ledger, portability, privacy and economic claims after implementation. A test author does not inherit a PASS from a reference example.

# 27. Acceptance and evidence

The new catalogue defines 190 individually specified cases across 19 families, plus 20 whole-system journeys. Preserve and rerun the old 120 native HCP cases and the relevant AHP/JIT regressions. The reference implementation supplied here tests selected arithmetic and state invariants; it is not a production ledger, OAuth implementation, signer or native blockchain verifier.

Record SPECIFIED, REFERENCE_PASS, NATIVE_UNIT_PASS, PROCESS_E2E_PASS, NATIVE_CHAIN_PASS, CUSTODY_LAB_PASS, BROWSER_PASS and OPERATOR_PILOT separately. Each case stores candidate fingerprint, commands, binaries, exact assertions and sanitized evidence. A missing environment remains NOT_RUN. All mandatory implemented call paths must be exercised at their required evidence level before that profile is advertised.

# 28. Final handoff

Return one consolidated report: starting/final fingerprints, preserved base contracts, added types/routes, actual native implementations, migration results, old/new test counts, every failure/unrun case, privacy observations, ledger recovery outcomes, portal journeys and partner integration instructions. Do not push, merge, publish, change release flags or restart production without separate operator approval.

The completed product lets a customer retain BTX reserves, make a governed capital decision, finance or acquire exact cognitive assets and deploy them locally—while preserving legal-entity ownership, native settlement rules, local execution authority and the ability to leave a hosted provider.


# Appendix A. Additive operation map

| Operation | Endpoint | Effect |
|---|---|---|
| getCognitiveReserveExtension | `GET /extensions/cognitive-reserve` | READ |
| createEntityLink | `POST /reserve/entities/links` | DRAFT_OR_POLICY |
| listEntityLink | `GET /reserve/entities/links` | READ |
| getEntityLink | `GET /reserve/entities/links/{id}` | READ |
| createPortfolio | `POST /reserve/portfolios` | DRAFT_OR_POLICY |
| listPortfolio | `GET /reserve/portfolios` | READ |
| getPortfolio | `GET /reserve/portfolios/{id}` | READ |
| createReservePolicy | `POST /reserve/policies` | DRAFT_OR_POLICY |
| listReservePolicy | `GET /reserve/policies` | READ |
| getReservePolicy | `GET /reserve/policies/{id}` | READ |
| createWorkloadProfile | `POST /capital/workloads` | DRAFT_OR_POLICY |
| listWorkloadProfile | `GET /capital/workloads` | READ |
| getWorkloadProfile | `GET /capital/workloads/{id}` | READ |
| createApprovalRule | `POST /capital/approval-rules` | DRAFT_OR_POLICY |
| listApprovalRule | `GET /capital/approval-rules` | READ |
| getApprovalRule | `GET /capital/approval-rules/{id}` | READ |
| createResearchProgram | `POST /capital/programs` | DRAFT_OR_POLICY |
| listResearchProgram | `GET /capital/programs` | READ |
| getResearchProgram | `GET /capital/programs/{id}` | READ |
| assignEntityRoles | `POST /reserve/entities/roles` | POLICY |
| revokeEntityLink | `POST /reserve/entities/links/{id}/revoke` | POLICY |
| getReserveSnapshot | `GET /reserve/portfolios/{id}/snapshot` | READ |
| revokeReservePolicy | `POST /reserve/policies/{id}/revoke` | POLICY |
| planReserveReplenishment | `POST /reserve/replenishment/plans` | PLAN |
| createTCOComparison | `POST /capital/comparisons` | PLAN |
| getTCOComparison | `GET /capital/comparisons/{id}` | READ |
| createCapitalPlan | `POST /capital/plans` | PLAN |
| getCapitalPlan | `GET /capital/plans/{id}` | READ |
| createAllocationPlan | `POST /capital/allocations` | PLAN |
| getAllocationPlan | `GET /capital/allocations/{id}` | READ |
| createApprovalRequest | `POST /capital/approvals` | PLAN |
| getApprovalRequest | `GET /capital/approvals/{id}` | READ |
| recordApprovalDecision | `POST /capital/approvals/{id}/decisions` | AUTHORIZE |
| listApprovalDecisions | `GET /capital/approvals/{id}/decisions` | READ |
| executeAllocation | `POST /capital/allocations/{id}/execute` | EXECUTE_APPROVED |
| getCapitalExecution | `GET /capital/executions/{id}` | READ |
| cancelCapitalExecution | `POST /capital/executions/{id}/cancel` | CANCEL_SAFE_ONLY |
| listCapabilityPositions | `GET /capital/positions` | READ |
| getCapabilityPosition | `GET /capital/positions/{id}` | READ |
| createCapabilityPosition | `POST /capital/positions` | RECORD |
| updateCapabilityLifecycle | `POST /capital/positions/{id}/lifecycle` | RECORD |
| joinResearchProgram | `POST /capital/programs/{id}/memberships` | MEMBERSHIP_ONLY |
| prepareProgramCommitment | `POST /capital/programs/{id}/commitments` | PLAN |
| listProductOffers | `GET /capital/products` | READ |
| getProductOffer | `GET /capital/products/{id}` | READ |
| createProductReferral | `POST /capital/products/{id}/referral` | REFERRAL_ONLY |
| createReserveReport | `POST /capital/reports` | REPORT |
| getReserveReport | `GET /capital/reports/{id}` | READ |
| createCapitalExport | `POST /capital/exports` | EXPORT |
| getCapitalExport | `GET /capital/exports/{id}` | READ |

# Appendix B. Signed object field contracts



## ReserveExtensionProfileV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `extension_id`, `parent_profile_body_id`, `schema_digest`, `operations_digest`, `supported_features`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## EntityLinkV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `link_id`, `parent_entity_id`, `child_entity_id`, `relationship`, `scopes`, `accepted_by`, `generation`, `expires_at`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## PortfolioV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `portfolio_id`, `account_ref`, `label`, `purpose`, `reporting_currency`, `generation`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ReservePolicyV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `scope`, `policy_id`, `generation`, `protected_atoms`, `per_plan_cap_atoms`, `lifetime_cap_atoms`, `outstanding_cap_atoms`, `permitted_actions`, `replenishment_mode`, `expires_at`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ReserveSnapshotV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `scope`, `snapshot_id`, `ledger_sequence`, `policy_ref`, `available_atoms`, `protected_atoms`, `remaining_authority_atoms`, `allocation_capacity_atoms`, `existing_hold_atoms`, `committed_atoms`, `refund_pending_atoms`, `observed_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## WorkloadProfileV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `workload_id`, `generation`, `objective`, `accepted_task_definition`, `evidence_minimum`, `annual_accepted_tasks`, `horizon_months`, `data_policy`, `runtime_profiles`, `assumptions`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## TCOComparisonV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `comparison_id`, `workload_ref`, `calculation_version`, `quality_equivalent`, `route`, `candidate_refs`, `cost_lines`, `unknown_inputs`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## CapitalPlanV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `plan_id`, `objective`, `comparison_ref`, `route`, `maximum_exposure`, `expected_outcome`, `observation_refs`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## AllocationPlanV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `allocation_id`, `capital_plan_ref`, `policy_ref`, `network`, `legs`, `maximum_exposure`, `client_operation_id`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ApprovalRuleV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `rule_id`, `generation`, `eligible_roles`, `distinct_person_quorum`, `exclude_initiator`, `veto_enabled`, `threshold_atoms`, `expires_at`, `status`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ApprovalRequestV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `request_id`, `allocation_ref`, `allocation_body_id`, `rule_ref`, `rule_body_id`, `policy_ref`, `policy_generation`, `initiator_person_id`, `maximum_exposure`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ApprovalDecisionV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `decision_id`, `request_ref`, `request_body_id`, `allocation_body_id`, `policy_generation`, `rule_body_id`, `actor`, `decision`, `sequence`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## CapabilityPositionV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `position_id`, `portfolio_id`, `package_core_id`, `recipe_id`, `lock_id`, `resource_refs`, `rights_ref`, `acquisition_refs`, `lifecycle`, `generation`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ResearchProgramV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `program_id`, `objective`, `evidence_refs`, `native_terms_refs`, `programme_ceiling_atoms`, `visibility`, `deadline`, `generation`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ProgramMembershipV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `membership_id`, `program_ref`, `member_entity_id`, `role`, `ceiling_atoms`, `accepted_terms_ref`, `status`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ProductOfferV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `offer_id`, `product_provider_id`, `product_class`, `rights_ref`, `eligibility_policy_ref`, `fee_disclosure_ref`, `supported_action`, `expires_at`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## CapitalExecutionReceiptV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `execution_id`, `allocation_ref`, `allocation_body_id`, `child_refs`, `state`, `observation`, `sequence`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.

## ReserveReportV1_1

Required body fields: `schema_revision`, `provider_id`, `created_at`, `legal_entity_id`, `report_id`, `snapshot_refs`, `position_refs`, `commitment_refs`, `reporting_currency`, `report_type`, `period_start`, `period_end`, `as_of`.

Strict canonicalization and domain-separated identity apply. Cross-field validation follows the normative specification.



# Research references

**[T01] OpenID Foundation — FAPI 2.0 Security Profile.** [Primary source](https://openid.net/specs/fapi-security-profile-2_0-final.html).

**[T02] IETF RFC 9396 — OAuth Rich Authorization Requests.** [Primary source](https://www.rfc-editor.org/rfc/rfc9396.html).

**[T03] IETF RFC 9449 — DPoP.** [Primary source](https://www.rfc-editor.org/rfc/rfc9449.html).

**[T04] IETF RFC 9700 — OAuth security best current practice.** [Primary source](https://www.rfc-editor.org/rfc/rfc9700.html).

**[T05] W3C — WCAG 2.2.** [Primary source](https://www.w3.org/TR/WCAG22/).

**[T06] FinOps Foundation — FOCUS 1.3.** [Primary source](https://focus.finops.org/docs/specification/v1-3/).

**[T08] IFRS — IAS 38 Intangible Assets.** [Primary source](https://www.ifrs.org/issued-standards/list-of-standards/ias-38-intangible-assets/).

**[T09] IETF RFC 7644 — SCIM protocol.** [Primary source](https://www.rfc-editor.org/rfc/rfc7644.html).

**[T10] IETF RFC 9126 — Pushed Authorization Requests.** [Primary source](https://www.rfc-editor.org/rfc/rfc9126.html).

