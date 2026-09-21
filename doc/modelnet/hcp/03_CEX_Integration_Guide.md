# Integrating an Exchange with BTX
## The operator guide to a hosted cognitive-capital business

**BTX-HCP-001 Integration Guide · Revision 1.0 · 17 September 2026**  
**Audience:** Exchange platform, custody, identity, product, security, operations and partner engineering teams.

> Integrate once at the control plane. Return portable packages and explicit financial outcomes. Let the customer's BTX client verify, source and prepare capability locally.

# 1. What you are integrating

This guide accompanies the Hosted Control Plane implementation specification. The protocol and endpoints are proposed contracts to implement on top of the completed private BTX 0.34.8 work; they are not existing public CEX endpoints. The reference kit demonstrates contract and failure-state logic with synthetic data. It is not a custody system, exchange connector or native BTX implementation.

The exchange supplies an authenticated catalogue, treasury and financial-workflow service. A hosted connector on the customer's machine receives a narrow capability handoff, independently checks the package, asks the existing local resolver for a plan and executes only under the customer's local grant. Native peers supply model bytes. Local runtime workers supply execution. No agent needs to maintain a full monetary node merely to discover or acquire public capability. [B01, B02]

A CEX can provide a useful first product without custody integration: publish exact `.btx` packages and let users acquire free assets. Native finance is a separate supported profile, gated by its own signing and reconciliation proof. Do not claim that a catalogue-only integration is a fully operational cognitive-capital market.

## 1.1 Three deliverables for a partner

| Partner deliverable | What it contains | What it must not imply |
|---|---|---|
| Hosted service | Profile, catalogue, quotes, intents, handoffs, events and exports | Authority to replace model identity or local runtime policy |
| Native adapter layer | BTX package, chain observer, custody signer and economy interfaces | An EVM wallet automatically supports BTX scripts or keys |
| Local handoff integration | Paired client connector, package verification and existing capability-service calls | Browser access to wallet keys, local shell or unrestricted localhost RPC |

The common profile is `HCP/1`. The initial endpoint prefix is `/btx/hcp/v1`. The vendor may use its own hostname and account system. Profile discovery uses an explicitly configured HTTPS URL; this document does not register an IANA well-known URI or invent a universal list of approved exchanges.

# 2. Choose a launch profile

Launch a smaller complete service rather than a larger nominal one.

**DISCOVERY** provides signed profile, bounded capability search, immutable package retrieval and public economic observations. No account is necessary for genuinely public catalogue data unless the venue deliberately applies its own policy. State that policy rather than calling venue login a BTX requirement.

**HANDOFF** adds authenticated account/device pairing, immutable handoffs, optional progress and portable exports. The local node remains walletless and owner-controlled. This is the first meaningful enterprise deployment product.

**CUSTODY** adds real BTX deposit/withdrawal, native-key/script support, customer-ledger reconciliation and treasury reporting. It does not automatically include bounty or release signing.

**FUNDING** adds exact native release/bounty terms, quotes, controlled intent authorization, signing, broadcast, observation, claims and refunds. Funded native outputs must reconcile to customer liabilities and native recovery obligations.

**FLEET** adds multi-device routing, finite subscriptions, tenant controls and aggregate readiness reporting. It is layered on proven handoff and, where money is enabled, proven funding profiles.

A ProviderProfile advertises only supported profiles and lists native versions, custody mode, financial evidence mode, security metadata, limits and exports. Disabled features return an explicit `PROFILE_UNSUPPORTED`, not an apparently successful empty response.

# 3. Prerequisites and work ownership

Before implementation, appoint an accountable owner for each of identity, ledger, custody, native chain/economics, local client, privacy, legal product eligibility and operations. The exchange's existing internal interfaces are the integration boundary; do not replace its financial core with the demonstration code.

Freeze the tested BTX candidate fingerprint: HEAD, tracked diff digest, relevant untracked-file digests, build configuration and binary hashes. Obtain the completed JIT/package handoffs and retain every prerequisite marked FAIL or NOT_RUN. In particular, a simulated wallet or plan-only runtime cannot satisfy a production capability profile. [B01, §§2, 26]

Create a native-operation mapping from each hosted action to its tested BTX call path. For example, release preparation maps to the release funding interfaces; a bounty must follow the actual round/lot freeze and funding sequence. A release is not funded by calling a generic address-transfer RPC with a displayed amount. The inspected public funding interface binds exact scripts, refund keys, heights and fee caps. [G04]

## 3.1 Integration adapter checklist

| Adapter | Required contract | Failure distinction |
|---|---|---|
| Identity | Stable tenant/account/actor IDs, scopes, token introspection or validation | Invalid token vs temporarily unavailable issuer |
| Eligibility | Action/customer/jurisdiction decision and auditable policy version | Denied vs manual review vs unknown |
| Ledger | Atomic available/held balances, journal entries, holds and release | Definitive rejection vs uncertain write |
| Quote | Firm conversion/execution quote with expiry and itemized fees | Expired quote vs executed conversion |
| Custody | Inspect/sign exact native transaction; retrieve by stable signing operation | Not signed vs signed vs unknown |
| Chain observer | Transaction/outpoint status, anchor, confirmation and reorg observations | Absent in current view vs proven conflicting spend |
| Native economy | Terms, frozen round/lot, funding, award, claim and refund builders | Terms conflict vs awaiting native conditions |
| Package | Exact Core v3 bytes, recipe/resource commitments, public source hints | Missing package vs corrupt/untrusted package |
| Audit | Append-only business events and correlation IDs | Durable append vs unavailable sink |
| Reporting | Customer statements, fees, commitments, exports and redaction | Current state vs stale snapshot |

An adapter returning UNKNOWN must not be coerced to false or treated as a safe retry. Unknown signing and broadcast outcomes retain reservations until reconciled.

# 4. Deploy the trust zones

Separate the HTTPS edge, application services, native model helpers, financial executor, custody signer, chain observer and customer devices. The edge holds no native spending key. The model helper has no exchange ledger-administration or custody credential. The local capability daemon is not publicly reachable. [G02, G03; B01, §4]

A useful topology is:

```text
Customer agent / browser
    → CEX HTTPS API + identity
        → catalogue and package adapter
        → handoff and event service
        → finance-intent service → ledger adapter
                               → isolated native executor → custody signer
                               → independent chain observer

Customer-local hosted connector
    → owner-only capability service
        → verified native BTX acquisition
        → local storage / LAN / approved private fabric
        → trusted local runtime
```

All financial execution is a typed translation into native methods. Keep the existing browser/explorer bridge read-only; adding a second authenticated business service does not justify exposing a generic `rpc(method, params)` endpoint. Conventional HTTPS at the exchange edge must be described as conventional HTTPS, not end-to-end native PQ1. [G02, G03]

The supplied `deploy/trust-zones.md` and `deploy/config.example.yaml` are deployment checklists/templates, not a working Kubernetes installation. Production container images, keys, database migrations and native binaries must come from the partner's verified build process.

# 5. Publish a provider profile and enroll clients

Publish a signed ProviderProfile from a stable configured URL. Include `provider_id`, `profile_sequence`, service origin, API base, network identity, supported profiles, keyset reference, OAuth metadata, limits, privacy policy reference and export support. The HTTPS origin and signing identity must be accepted through the user's installation or organization policy; a self-signed profile alone cannot appoint a trusted exchange.

Pin the provider identity and allowed origins in local configuration. Sign operational key rotation under the already trusted provider root with monotonic sequence and an overlap window. Replacing the root is a distinct explicit enrollment action. Expired/revoked profiles stop new hosted operations while leaving existing public local capabilities usable.

The local connector keeps provider credentials in an owner-controlled secret reference. Do not place tokens in `.btx`, query strings, callback URLs, model metadata, shell history, logs or runtime environments. A model-package author and provider signer are separate identities even when the same organization operates both.

# 6. Authentication and agent authorization

Reuse the exchange's standards-based OAuth service. Interactive clients use authorization-code plus PKCE and exact redirect validation. Financial resource access uses sender-constrained tokens through DPoP or mTLS under the declared security profile. Headless organization agents use an approved workload identity and short-lived credentials, not a shared employee password. [R12–R15]

Issue separate scopes for catalogue, handoff creation, account reading, quote preparation, financial authorization and submission, subscriptions, device administration and exports. A `catalog:read` token cannot create a transfer. A `handoff:create` token cannot authorize local process execution. A device token cannot authorize another device. Scope is necessary, but exact account/object/policy checks are still required.

DPoP binds possession of a key to token use and request context; it is not a substitute for binding the actual finance-intent body to approval. Use the immutable intent digest and authorization details for that purpose. Do not invent a custom OAuth implementation from scratch. [R13, R14]

For ordinary users, one deliberate enrollment can grant a finite local policy covering repeated free acquisition and runtime preparation. For enterprise agents, one hosted policy can cover an approved finite class of financial actions. These are two grants, evaluated by two different authorities. This produces a short happy path without a universal approval bypass.

# 7. Build the catalogue and capability front end

Connect the Package adapter to the native verified object store and current discovery view. Map human labels to exact recipe/package/resource references. Preserve issuer provenance, evaluation claims, unavailable information and the scope/time of availability observations. Imported records do not become exchange-authored models.

The front end should display purpose, supported implementations, compatibility claims, verification status, source availability and public economic opportunities. It can offer sponsored ranking or curation, but label those choices separately from cryptographic validity and measured evidence.

Return candidate recipes rather than pretending the exchange knows the device's complete private residency. A coarse user-approved compatibility profile may help filter results. Final memory admission, compatibility and time-to-capability choice happens locally using the actual device and current grants. [B01, §§3, 6–7]

Use exact package hashes as cache keys. Dynamic availability and economic status have separate timestamps/anchors. A CDN may cache immutable package bytes; it must not serve another user's custody state or claim that old economic observations are fresh.

# 8. Free capability handoff: the first customer journey

The local client first creates a nonce for the current account/device session and requests a handoff for an exact selected recipe. The provider returns a signed CapabilityHandoff bound to provider, account, device, nonce, expiry, package core and recipe. Only reviewed public source hints are included. No local path, shell command, raw runtime endpoint, wallet credential or cloud secret belongs in the handoff.

The following HTTP shapes illustrate the proposed API; IDs are synthetic and the production request must satisfy OAuth and sender-binding policy.

```http
POST /btx/hcp/v1/handoffs
Authorization: <sender-constrained access token>
Idempotency-Key: <stable key for this request>
Content-Type: application/json

{
  "client_operation_id": "op-demo-acquire-01",
  "device_id": "dev-demo-01",
  "package_core_id": "<96 lowercase hex characters>",
  "recipe_id": "<96 lowercase hex characters>",
  "request_nonce": "<fresh device-generated nonce>",
  "readiness_target": "RUNTIME_READY"
}
```

On receipt, the local connector verifies the enrolled provider signature, binding/expiry, exact package and recipe. It passes the candidate into the existing local planner. The device owner grants or already has a finite LocalCapabilityGrant. Only then does it call the tested `ensurebtxcapability` path.

If a base is already resident and the missing adapter is on the LAN, the local planner uses that path. The CEX's source hint is not a command to download from its CDN. If no recipe is eligible, return the local reason; do not silently change the capability, install a new runtime or buy access.

A readiness report is optional and minimal: handoff correlation, coarse state, exact generation-bound result identity and error code. Full local paths, prompts, KV state, source peer inventory and hardware fingerprint remain local. A report is a device observation; it does not prove model quality to the exchange.

# 9. Native finance: connect custody before exposing the button

A BTX listing alone does not establish native bounty/release support. The partner must support the relevant BTX keys, scripts, signing policies, transaction builders and recovery workflows. An HSM or MPC product supporting EVM transactions is not evidence that it supports this chain or its scripts.

For custodial funding, the exchange is the signing controller and the customer is the beneficial account. The customer ledger must record which native output/lot corresponds to that customer's authorized principal, fee reserve, deadline and refund beneficiary. A CEX recovery statement cannot give unilateral key recovery unless the protocol/output actually grants it. State that limitation plainly.

Preserve one native funding lot per customer business action in the initial implementation. An optimized batch may combine inputs or transactions only when it preserves exact output attribution, per-lot consent, native round membership and recovery. Never manufacture evaluator seats or apparent independent funders from custodial subaccounts. [B04]

Before enabling production, run test-network deposits, withdrawals, funding, claim, refund, reorg, backup recovery and unknown-result reconciliation. Record exact native build, signing backend and policy version. Custody metadata and accounting backups are as important as key backups.

# 10. Quote, authorize and submit

A FundingQuote binds native network, action, target object, signed terms digest, any frozen round/lot identity, principal, network fee cap, service fee, reserve total, refund control and expiry. Where fiat conversion is needed, attach a separate firm conversion quote with its own terms. Display the maximum total debit and what does and does not count toward the native pool.

Use a stable client business-operation ID across retries. Prepare an immutable FinanceIntent, then authorize its exact digest under explicit approval or a finite HostedAccountPolicy. At submission, recheck current eligibility, policy revision, balance reservation and native terms. Persist the exact signed transaction before dispatch. An HTTP 202 means processing, not funded.

```http
POST /btx/hcp/v1/finance/intents
Idempotency-Key: <stable request key>

{"client_operation_id":"op-demo-fund-01",
 "quote_id":"quote-demo-01",
 "expected_quote_id":"<96 lowercase hex characters>"}
```

```http
POST /btx/hcp/v1/finance/intents/intent-demo-01/authorize
Idempotency-Key: <authorization request key>

{"expected_body_id":"<immutable intent digest>",
 "policy_id":"policy-demo-01","policy_revision":"3"}
```

```http
POST /btx/hcp/v1/finance/intents/intent-demo-01/submit
Idempotency-Key: <submission request key>

{"expected_body_id":"<same immutable intent digest>"}
```

The server returns a job/intention state and a retrieval URL within its configured origin. The SDK polls the existing intent; it does not create another intent on a timeout. A conflict between one business ID and two different bodies returns 409. Request-level idempotency retention is not the only defense: a durable unique business constraint remains after the HTTP cache expires.

## Native workflows and existing exchange rails

The HCP quote/intent routes normalize FUND_RELEASE, FUND_BOUNTY, CLAIM and REFUND. Ordinary deposits, withdrawals and stand-alone trading remain the exchange's existing regulated account APIs, documented in its integration map. A parent HCP workflow may reference a firm conversion leg through the QuoteAdapter. The signed FundingQuote then includes both its immutable venue reference and exact source asset/amount/exponent, target BTX, slippage cap and expiry. Authorization to fund does not silently authorize that conversion. Do not fabricate a native terms ID or template for an ordinary currency trade. The HostedAccountPolicy may contain CONVERT/WITHDRAW permissions, but the executor must bind those to their actual separately approved exchange operation.

# 11. Reconcile balances and native transactions

Use a journaled double-entry implementation in the partner's real ledger. Available, held, escrow/committed, paid fee, refundable and returned states must reconcile. Do not add the same BTX output to both available cash and funded commitments. Do not call service fees native funding principal.

The reference simulator uses a locked in-memory state model to test selected invariants. Production requires transactional persistence, unique constraints, an outbox and one fenced executor per native action. A database transaction cannot atomically commit a public-chain broadcast; design for that boundary rather than promise exactly-once network delivery.

A signing timeout is not proof that no signature exists. A broadcast timeout is not proof that no transaction propagated. Keep the hold, record UNKNOWN and reconcile using the signing operation ID, exact transaction bytes, input reservations and chain/mempool observer. Identical rebroadcast is permitted under policy; creating a new spend with different inputs is not an automatic retry.

Reorgs correct native observation state without pretending a disclosed secret is unknown again. Refunds are credited only after the committed conditions and confirmation policy hold. Outstanding exposure can fall after a proven refund, but lifetime authorization capacity does not automatically reset unless a separately approved policy explicitly defines replenishment.

# 12. Events, subscriptions and unattended operation

Expose account/device-scoped server-sent events or bounded polling with a durable cursor. Delivery is at least once. Clients deduplicate by event ID and reconcile after a CURSOR_TOO_OLD response. Ordering is meaningful only within the declared generation/stream; no globally authoritative event sequence is claimed. [B03, §15]

For financial subscriptions, bind exact publisher/delegation scope, object kinds, maximum per-action principal, lifetime principal and fee limits, outstanding exposure, action count, expiry, refund control and allowed native conditions. A watch can notify or prepare a quote without funding authority. A funding policy does not automatically authorize local model execution.

Use a unique business key over policy revision, logical event and action. Reindexing an old catalogue must not rediscover chargeable history as new demand. A new model's natural-language urgency cannot widen limits. Revoke prevents new signing; already dispatched financial effects require reconciliation rather than deletion.

Webhook destinations are separately verified operator configuration. Sign deliveries with expiry/replay context and redact secrets. Apply network egress rules, DNS rebinding defenses, restricted schemes and internal-address policy. A package-supplied callback URL must never gain access to the CEX's metadata service or private network.

# 13. Browser, mobile and fleet integration

The portal offers Search, Capabilities, Releases, Bounties, Treasury, Approvals, Devices and Activity. Reuse the same typed SDK for UI and agents. Build one comprehensive package preview rather than many bespoke publisher installers.

Pair devices through an explicit user flow. The device creates its own key and short-lived pairing challenge. The authenticated account approves the exact device; the device establishes an outbound connection or polls for addressed handoffs. Avoid browser-to-unrestricted-localhost requests. Do not embed tokens in a custom URL scheme. The normal local daemon stays owner-only.

An enterprise fleet can preapprove finite acquisition/runtime policies centrally through its separate organization management system. HCP may reference that policy's ID but cannot silently create it. A CEX-owned handoff is not an operating-system management entitlement.

A web portal may report Ready only after receiving an authorized coarse device report. It cannot infer readiness from a funding receipt, model download count or a live socket. Device READY can later expire; the local generation lease is the definitive operational handle.

# 14. Privacy, competition and customer exit

Hosted convenience means the CEX observes account activity and the queries/actions it handles. It may observe conversions, commitments and handoff targets. BTX does not make these records anonymous to the provider. Privacy value comes from keeping prompts, inference results, private cache state and unnecessary hardware inventory off that service, and from permitting a direct alternative.

Separate product analytics consent from required financial records. Apply configurable retention to catalogue queries. Do not sell identifiable customer capability demand as a hidden consequence of use. Aggregate reporting needs minimum cohorts and a documented reidentification review; it is not automatically anonymous because identifiers were removed.

Export exact packages, locks, public records, policy snapshots, quotes, receipts, intent status and documented custody obligations. Disconnecting a CEX stops new hosted work, not the validity of already acquired public bytes. Pending custodial transactions remain the original exchange's responsibility. Moving discovery to another CEX must not duplicate an unresolved financial intent.

# 15. Integration testing and certification

Run `python scripts/validate_package.py` and the reference tests to check this kit's examples and logic. These checks are not certification of OAuth, native signatures, custody, chain settlement or local runtime. They merely demonstrate that the supplied contracts and selected state invariants are internally consistent.

Implement the 120 individual native cases in the specification, plus J01–J12 whole-system journeys. Test profile-specific production call paths. A DISCOVERY launch need not claim a hardware runtime lab, but a HANDOFF launch requires actual local client acquisition; FUNDING requires native-chain and custody evidence.

At minimum, the launch packet contains candidate fingerprint, protocol/schema digests, supported profiles, native operation map, issuer/key rotation plan, custody capability record, test matrix, security review, privacy/data-flow inventory, recovery drill, rate limits, SLOs and rollback runbook. An exchange may self-attest conformance under a public test suite, but BTX must not imply independent certification where none occurred.

# 16. A practical staged rollout

**Stage A — Internal discovery sandbox.** Populate a small authorized catalogue, serve exact packages, authenticate test users and demonstrate a portable export. No money and no live native broadcast.

**Stage B — Partner handoff pilot.** Pair a small fleet on two supported local platforms. Exercise free download, local cache/LAN reuse, explicit execution, cancellation and provider exit. Measure first useful result, not just package fetch.

**Stage C — Native economic lab.** Run only test-network custody and native release/bounty conditions. Inject timeouts after signing/broadcast; prove holds and retries; test refunds and accounting. Complete legal product eligibility review.

**Stage D — Limited customer funding.** Apply low explicit limits, approved terms and controlled counterparties. Monitor every native/output reconciliation and handle support manually. Do not auto-expand the eligible market based on user demand.

**Stage E — Generalized CEX integration.** Publish SDKs, reference UI, conformance results and a partner operation map. Introduce finite future-event policies only after concurrency and revocation evidence. Each venue retains its own licensing, risk and customer responsibilities.

These stages are gates, not calendar promises. The objective is to make a second CEX integration primarily adapter mapping and conformance, not another BTX fork.

# 17. Production runbook essentials

On **provider outage**, keep local public capability running. Pause new hosted financial action; do not fail over pending finance to another exchange.

On **custody signer ambiguity**, block new replacement spends for that intent, retain reservation and reconcile operation IDs. Preserve exact signed material according to secret-handling policy.

On **chain reorganization**, downgrade affected observations, pause dependent unsent work and recalculate output exposure; do not erase intent history or replenishing lifetime grants automatically.

On **provider signing-key compromise**, revoke new handoffs/receipts under the compromised operational key through the established root procedure. Preserve past evidence, stop trust expansion and require revalidation. A provider-key compromise must not reveal spending keys because those systems are separate.

On **package/runtime compromise**, quarantine affected exact versions under local/organization software policy. A catalogue delisting cannot remotely erase customer files; an active safety action is separately authorized local policy. Recovery continues respecting generation leases and in-flight transfers.

On **customer exit**, export portable state, revoke credentials/device pairing and continue custodial settlement/refund obligations. Provide the customer with the limits of any watch-only recovery material.

# 18. The partner acceptance statement

A conforming partner should be able to state:

> We provide hosted discovery and governed financial access to BTX. Our customers retain exact package and resource identities. Public model bytes can be acquired without our CDN. Local execution remains under the customer's authority. Financial outcomes are attributable to our account ledger and observed native transactions, and their trust level is explicit. Customers can move their discovery interface without losing already acquired public capabilities.

That statement is the actual integration product. The collection of APIs is how it is delivered.

<!-- SOURCE_REGISTER_APPEND -->

# Source register

Research reviewed 17 September 2026. Supplied BTX specifications establish design requirements, not native implementation proof. External sources establish only the facts attributed to them; the strategy and HCP design are this package’s analysis and proposals.

**[B01] BTX JIT Capability Development Spec, rev 1.0. Supplied file: `BTX_0348_JIT_Capability_Development_Spec.md`.** User-supplied design baseline; sections 1, 3–7, 21–27. Defines Core v3, local grants, three authority planes and no-account acquisition. Not executed code evidence.

**[B02] BTX Agent-readable Package Spec, rev 1.0. Supplied file: `BTX_0348_Agent_Readable_Package_Spec.md`.** User-supplied design baseline. BTXPKG1 framing, authorship/software/wallet distinctions. Core v2 is superseded by JIT Core v3 where allocated.

**[B03] BTX Expanded Implementation Spec. Supplied file: `BTX_0.34.8_Expanded_Implementation_Spec.md`.** User-supplied design baseline. Origin/storage, events, mandates, escrow and package responsibilities.

**[B04] BTX Model Bounties and Discovery Hardening. Supplied file: `BTX_0.34.7_Model_Bounties_and_Discovery_Hardening.md`.** User-supplied design baseline. Frozen rounds, per-contributor lots, council judgement, refund deadlines and no return-bearing security.

**[G02] [BTX web bridge boundary](https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/doc/modelnet/web-bridge-boundary.md).** Static inspection. Conventional HTTPS is a separately deployed compatibility edge. Native helper PQ1 remains separate; bridge is not wallet proxy.

**[G03] [BTX HTTP bridge implementation](https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/src/modelnet/http_bridge.cpp).** Inspected lines 1–240; blob 86199b1a512ccf923e28b5835cb47d150c0a70c6. BRIDGE_NOTE, PushDisclosure, WalletLikePath and read-RPC boundary. Not a full security audit.

**[G04] [BTX wallet funding interface](https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/src/wallet/model_funding.h).** Static inspection; blob 4bcc279cd27492ae9345312309ae8bd244c8c5dd. FrozenFundingQuote, MatchFrozenTemplate, CreateUnsignedFunding, SignFrozenFunding, ObserveReleaseFunding.

**[R10] [FATF seventh targeted VA/VASP update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html).** 16 July 2026; compliance remains jurisdiction-specific; protocol decentralization does not remove operator duties.

**[R11] [IFRS IAS 38 overview](https://www.ifrs.org/issued-standards/list-of-standards/ias-38-intangible-assets/).** Research is expensed; development/other intangible costs require recognition conditions. Economic capital formation is not automatic balance-sheet capitalization.

**[R12] [RFC 9700 OAuth security BCP](https://www.rfc-editor.org/info/rfc9700/).** Security basis for delegated access. HCP choices are a proposed application profile, not certification.

**[R13] [RFC 9449 DPoP](https://www.rfc-editor.org/info/rfc9449/).** Sender-constrained tokens; DPoP does not bind the complete request body and does not replace authorization.

**[R14] [RFC 9396 Rich Authorization Requests](https://www.rfc-editor.org/info/rfc9396/).** Structured authorization details are a precedent for finite account policies.

**[R15] [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html).** Final high-value API security profile; use established implementations and independent conformance.

**[R16] [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html).** Signed HTTP components and content digest binding; separate from native model signatures.

**[R17] [The Update Framework specification](https://theupdateframework.github.io/specification/latest/).** Independent software-release trust, expiry, version floors and key rotation principles.

**[R18] [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).** Pinned published revision; audience binding and no token passthrough; re-audit newer version before shipping.

**[R19] [Coinbase Exchange API-key permissions](https://help.coinbase.com/en/exchange/managing-my-account/how-to-create-an-api-key).** View/trade/transfer/manage separation; transfer permission is consequential and can bypass 2FA.

**[R20] [Coinbase Advanced Trade portfolios](https://docs.cdp.coinbase.com/coinbase-app/advanced-trade-apis/guides/portfolios).** Portfolio-scoped API credentials are an integration precedent, not proof of BTX support.

