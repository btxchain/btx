# BTX 0.34.8
## Hosted Control Plane and Exchange Integration
### Normative implementation specification · BTX-HCP-001 · Revision 1.0

**Date:** 17 September 2026  
**Canonical edition:** Markdown. The Word and PDF editions reproduce this specification and its acceptance catalogue.  
**Execution order:** after the current NETWORK-02, agent-package and JIT capability work has stopped with a candidate fingerprint and an explicit handoff. Preserve unresolved prerequisites.

> Make discovery and finance available through any conforming exchange API. Keep exact package verification, local policy, source selection, memory management and runtime execution under the customer's control.

# 1. Assignment, delivered product and non-goals

## 1.1 What this round must deliver

Build the HCP/1 hosted-control contract, an exchange gateway implementation, exchange-adapter interfaces, a walletless local hosted-client mode, device handoff and optional fleet-management interfaces, finance intent/receipt handling, SDKs, a web integration component library, tests and the CEX onboarding guide. A CEX should integrate its existing identity, compliance, ledger, quote and custody systems through a bounded adapter surface rather than reimplement BTX's package and economic semantics.

The same contract must support exchanges, enterprise gateways and independent managed providers. There is no required BTX-operated gateway or provider directory. Native self-hosted operation remains valid. Ordinary public packages and model bytes do not acquire a mandatory fee because they are discovered through a hosted service. [B01–B03]

The final demonstration must use two independently configured gateway instances and one local client. It must show public acquisition without a local monetary node, a test-network funding lifecycle, operation after one gateway fails, and export to a second gateway without re-addressing model bytes.

## 1.2 Boundary of the work

No monetary-consensus, issuance, chain-selection or wallet-ownership change is authorized. No new token, staking yield, revenue-share security, generic smart contract or mandatory exchange toll is introduced. This work does not implement a public inference marketplace, a prompt-routing service, an exchange's matching engine, or a replacement for its legal/compliance systems.

Existing Core v3 capability packages, BTXPKG1 framing, recipes, lockfiles, signatures, native transport and local runtime APIs are the integration substrate. Use separate hosted-control objects rather than placing custodial credentials or customer-specific authorization into portable `.btx` cores. A new `.btx` version is unnecessary unless the private-tree audit proves a specific incompatibility; any allocation requires one recorded schema decision. [B01, §§4–6; B02, §§3–5]

## 1.3 Delivery is not a list of names

Every advertised profile requires registered production call paths and executable conformance evidence. A mocked custody adapter is not live funding. An accepted handoff is not completed acquisition. A generated OpenAPI file is not an implemented gateway. Hardware-specific JIT support remains governed by the preceding JIT release matrix.

The local reference code supplied with this package demonstrates contract validation and failure semantics only. It neither signs BTX transactions nor validates monetary consensus. All native HCP acceptance cases begin NOT_RUN.

# 2. Baseline and implementation audit

## 2.1 Evidence inspected for this assignment

The public repository ref returned `42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b`. Static inspection of `doc/modelnet/web-bridge-boundary.md` and `src/modelnet/http_bridge.cpp` confirms that the conventional web edge is separate from native PQ1 and that existing browser paths exclude wallet-like mutations. `src/wallet/model_funding.h` separates preparation, matching frozen templates, signing and local chain observation. These are useful seams, not proof that the private HCP implementation exists. [G01–G04]

The supplied AHP specification explicitly requires free native acquisition without a funded wallet or full chain synchronization. The JIT specification provides local `resolvebtxcapability`, `planbtxcapability`, `ensurebtxcapability`, grant, residency and readiness contracts. HCP should connect to those instead of adding a second local runtime manager. [B01, §21; B02, §1.3]

## 2.2 Mandatory audit output

Before editing, record branch, HEAD, tracked-diff SHA-256, hashes of relevant untracked files, build flags, binary hashes, running processes and disk/memory headroom. Read every prior handoff. Do not overwrite a current production executable or reset the working tree. Produce `audit/hcp-baseline.md` and `audit/hcp-contract-map.csv` with REUSE, EXTEND, REPLACE or NEW for each proposed component.

Trace package inspection to the current codec; local ensure to the resource broker and runtime; financial preparation to the native wallet validator; browser paths to their allowlist; and native discovery to actual model helpers. Confirm that no current process startup forces wallet opening, mining or chain synchronization for public acquisition. Fix a discovered packaging dependency rather than hiding it behind a flag that still starts the monetary service.

## 2.3 Precedence

Monetary rules and the owner's grants remain authoritative. This document defines the hosted-control boundary. Existing JIT rules govern local realization and physical lifetime. Existing funding terms govern a committed release or bounty. Older model-plane interoperability promises may be superseded by the explicit 0.34.8 cutover; funded commitments and immutable byte identities may not be rewritten.

# 3. Reference architecture

## 3.1 Separate services and authorities

| Component | Owns | Must not own or infer |
|---|---|---|
| CEX web/API edge | Customer sessions, API access, presentation, rate limits | Native package truth, arbitrary local execution |
| Hosted gateway | Typed catalogue, quote, intent, handoff and receipt orchestration | Raw wallet keys or consensus validity by assertion |
| Exchange adapters | Identity, compliance, ledger, conversion, signer access and reporting | Customer authorization from model-card text |
| Native monetary service | BTX transaction validation, wallet templates, chain observations | Model quality, local runtime readiness |
| Native model service | Signed records, packages, discovery and verified payload service | Exchange balances or private runtime memory |
| Customer hosted connector | Provider enrollment, HTTPS access, handoff import and outbound status | Local spending keys unless separately self-custodied |
| Customer capability service | Local grants, exact plans, TTC, acquisition, residency and runtime leases | Authority to spend because the CEX says a model is desirable |

Conventional HTTPS terminates at the separate CEX/gateway edge. Public `btx-modeld` remains PQ1 under the native contract. Use authenticated local IPC or native PQ1 on the internal BTX hop. The hosted HTTPS/OAuth hop is not described as native end-to-end PQ merely because the downstream model hop is PQ1. [G02, G03]

![Figure 3. The gateway coordinates; the local client verifies and realizes.](../assets/control_data_planes.png)

## 3.2 No raw RPC proxy

Do not add a public `/rpc` passthrough accepting method names. The gateway translates a fixed typed operation into a server-owned native call sequence. Keep existing explorer/browser routes read-only. Finance lives in a separate authenticated business service with narrow signer permissions and no path into runtime execution. Local memory/loader APIs remain owner-local.

The catalogue service cannot reach the signer network. The signer executor cannot fetch model descriptions or follow URLs during signing. It receives an already validated exact transaction and sufficient immutable terms for an independent final check. An application restart must not turn the gateway into an unbounded wallet client.

## 3.3 Adoption profiles

Define cumulative conformance profiles: DISCOVERY (catalogue and packages), HANDOFF (portable acquisition), CUSTODY (balances and test-proven custody integration), FUNDING (native release/bounty lifecycle), and FLEET (opt-in device jobs and reports). Each advertised profile lists exact operations and evidence. A venue can deploy discovery before custody; it cannot advertise FUNDING merely because it lists a BTX market.

Implement all requested profiles in this engineering round. An operator's deployment can selectively disable them. Optional services must not leak into the free-public-acquisition baseline.

# 4. Walletless local deployment

## 4.1 Installed shape

Provide a supported `hosted-client` installation preset using existing model/capability binaries or a thin launcher. It needs a local model-service identity for peer authentication, store access, the package verifier and the capability service. It does not open a monetary wallet, mine, maintain a global index or perform a full monetary sync by default. Identity keys for model transport are not CEX credentials or spending keys.

A launcher may supervise required helpers, but must use one existing supervisor implementation. Local downloading, verification and runtime preparation continue under the same resource broker as ordinary native use. The hosted connector is not a second downloader.

## 4.2 Local policy remains decisive

Enrolling a CEX authorizes communication, not every action it proposes. The owner creates or selects a finite LocalCapabilityGrant once for the intended workflow. It can permit acquiring public assets and using an independently trusted runtime within exact memory, disk, bandwidth, concurrency and expiry limits. Public seeding, installation, private-fabric access, local execution and reporting are separate effects.

A CEX's software requirement may produce SOFTWARE_TRUST_REQUIRED. It cannot appoint itself as trusted client distributor. An API response containing shell commands, environment variables, plugin paths or an arbitrary runtime download URL is rejected as an unsupported instruction. [B01, §§6, 11; B02, §§3, 8–10]

## 4.3 Observing money without a local full node

The user selects an economic observation mode: HOSTED_ATTESTED or INDEPENDENT_VERIFIER. In HOSTED_ATTESTED mode the client knows what its enrolled provider attests and displays that scope. In INDEPENDENT_VERIFIER mode a separately configured trusted verifier reports the relevant native chain state. Disagreement freezes dependent financial actions and is surfaced.

No new light-client proof system is implied. A transaction inclusion proof does not alone prove full chain validity or ExactReplay. Public artifact acquisition can proceed without economic observation. A release secret, once obtained, is checked against its committed key hash; a CEX success label is not a substitute.

# 5. Identities, portable objects and cryptography

## 5.1 Keep identities distinct

Use distinct references for provider, legal customer account, agent principal, device, package core, recipe/lock, native model/artifact, economic terms, finance intent, receipt and local runtime generation. Public model IDs are not payment addresses. Custodial account IDs are not BTX addresses. A device identity does not prove the customer's legal identity.

Represent monetary amounts as canonical unsigned decimal atom strings. Native maximums, decimals and transaction rules are taken from the actual supported BTX network, not arbitrary remote metadata. Currency conversion values identify currency and exponent separately; do not mix USD minor units with BTX atoms. JSON schemas are structural checks; native validation enforces MoneyRange and chain rules.

## 5.2 HCP object envelope

For portable HCP statements define a proposed HCP/1 envelope with `object_type`, `body`, `body_id`, `signer_key_id` and `signature`. Canonical body bytes reuse BTX-PJSON1; do not silently substitute ordinary JSON or JCS. Compute:

```text
body_id = SHA384(
  UTF8("BTX/HCP/" + object_type + "/v1") || 0x00 ||
  LE64(body_byte_length) || canonical_body_bytes
)
```

Native HCP statement signatures use the existing pure ML-DSA-44 application-signature convention over the 48-byte body ID. Validate fixed key/signature sizes before expensive verification. Keys are independently enrolled provider-role keys, not wallet keys. The control signer can authenticate an offer or receipt but cannot sign funding transactions. The request's chain identifier and profile are inside every economically material signed body.

REST serialization may be ordinary bounded JSON around exact signed bytes. Canonicalization is required only where identities or signatures require it. Production signatures are not generated by the reference harness; unsigned examples are explicitly non-authoritative.

## 5.3 Seven different statements

ProviderProfile authenticates an endpoint and its supported contract. CapabilityOffer binds a catalogue candidate to exact package and recipe references. FundingQuote binds costs and native terms. FinanceIntent binds a requested financial action. FinancialReceipt attests the state of that action. CapabilityHandoff binds an exact package transfer to a device or caller. LocalReadinessReport reports an optional client-observed outcome.

No statement subsumes the others. A FinancialReceipt cannot sign a package; a CapabilityOffer cannot grant local runtime authority; a LocalReadinessReport cannot prove research quality or trigger an award outside committed evaluation terms.

## 5.4 Key enrollment and rotation

Enrollment starts from an operator-chosen HTTPS provider origin and a pinned expected issuer/provider identity. Fetch the profile with strict redirect and origin checks, display requested effects, and bind accepted control keys to that provider and role. Do not accept keys discovered in a model package as provider roots.

Rotation requires an enrolled root's authenticated transition plus version/expiry floors or a new owner approval. Record issuer, key ID, algorithm, validity window, status and accepted profile. On compromise block new privileged effects; historical valid receipts remain evidence with revocation context, not retroactively proof of false statements. Software-update roots use their independent release mechanism, following TUF-style trust and rollback protection where adopted. [R17]

# 6. Authentication and bounded delegation

## 6.1 Use the CEX identity system

HCP is a resource-server profile, not a new password database. Reuse the CEX's established identity provider. Interactive clients use authorization code with PKCE and exact registered redirect URIs. Confidential enterprise clients use approved client authentication and sender-constrained credentials. Avoid password grants and implicit-flow designs. Financial endpoints require DPoP-bound or mutually authenticated TLS access tokens and appropriate step-up or finite policy. [R12–R15]

Do not claim that DPoP signs the request body; it binds a proof to token/method/URI. The immutable intent digest and explicit authorization below bind the financial content. TLS and established message-signature mechanisms provide additional transport integrity where required. [R13, R16]

## 6.2 Fine-grained scopes

Use `catalog:read`, `packages:read`, `account:read`, `quotes:create`, `intents:create`, `intents:authorize`, `intents:submit`, `intents:cancel`, `policies:admin`, `subscriptions:write`, `handoffs:create`, `devices:enroll`, `devices:report`, `events:read`, `research:publish` and `exports:create`. CONVERT and WITHDRAW require separate action permissions in the policy even when the API scope permits submitting intents.

A read token cannot prepare a transaction by exploiting a GET route. A write token cannot administer its own higher budget. Every request is bound to tenant, legal account, agent principal, API audience and environment. Obtain account context from the verified token/session, not a caller-selected body account ID. CEX-native keys with broad transfer permissions must never be handed to the model helper. [R19, R20]

## 6.3 Finite account policy

The gateway's HostedAccountPolicy is separate from the local LocalCapabilityGrant and from the native custodian's wallet policy. It binds authorized actions; exact terms IDs or an approved bounded publisher subscription rule; per-action principal; lifetime principal and fees; outstanding exposure; action and concurrency counts; allowed custody mode; refund ownership; expiry; and revocation generation.

Amounts and recipient/scripts are checked at preparation and rechecked at submission. A future-publisher subscription fixes each discovered terms ID before financial authorization. Model descriptions, trending ranks and package AGENTS.md never expand these limits. A policy change creates a new generation and invalidates prepared authorizations that no longer match.

## 6.4 Token and secret isolation

Use OS secret references or approved agent credential stores. Do not place CEX tokens, customer identifiers, wallet keys or cloud credentials into `.btx`, source hints, P2P messages, runtime environments, command-line arguments or public logs. The hosted connector passes only sanitized packages and opaque local handles to the capability service.

MCP wrappers use tool-specific audience tokens and explicit effects. They must not forward a customer's exchange token to another server. A remote MCP tool may search or prepare; local tools separately ensure capabilities. Tool descriptions do not confer financial or execution authority. [R18]

# 7. Catalogue, offers and local resolution

## 7.1 Hosted catalogue semantics

Query the existing signed-object/search store through an allowlisted adapter. Preserve original package authorship, model publisher, evaluation issuer and imported-source provenance. CEX ranking and curation are separate annotations. Results carry `observed_at`, coverage scope, freshness and the advertised evidence tier. Provider counts are observations, not a complete global census.

Support capability labels, exact package/recipe lookup, model families, public/release/bounty status and coarse runtime profiles. Return bounded candidate sets, not a promise that a text tag proves task suitability. User text is data, never a native RPC method or query-language program.

## 7.2 Locality and TTC

The CEX returns eligible candidates and exact packages; the local resolver applies its private constraints and live residency. Prefer no unnecessary payload movement, but do not impose a fixed disk/LAN/GPU ordering. A plan can combine a local resident base, LAN adapter and local tokenizer. An overloaded rack GPU is not automatically preferable to verified local storage. [B01, §§3, 6–8]

Send a coarse hardware/profile claim to the CEX only with owner permission. Raw memory layouts, private capability inventory, prompts, KV state, RDMA keys and exact runtime traces remain local. The CEX may show an estimated source-side download time, clearly distinguished from local TTC.

## 7.3 Packages and cache

Serve exact signed `.btx` bytes with their file SHA-384 and package core ID. Cache immutable package bodies publicly when the packages themselves are public. Customer-specific handoffs, quotes, receipts and policies are private, never shared-cacheable. Conditional requests use byte identity, not a mutable model label.

A mutable channel is resolved to an exact signed target before planning. `--locked` cannot silently take a CEX-recommended newer model. Funding terms referencing one artifact are not retargeted because a channel changes.

# 8. Portable capability handoff

## 8.1 Required handoff fields

A CapabilityHandoff contains protocol version, provider and issuer role, random handoff ID, target caller/device binding, nonce, creation/expiry, chain/environment, exact package core ID and file digest, exact recipe or lock reference, requested readiness, allowed non-authoritative source hints, optional financial-receipt references and declared reporting requirements. It has no shell, arbitrary argv, privileged installation request or grant.

Transfer package bytes inline as a bounded separate body or via a configured HTTPS package endpoint. A URL is a location, not identity. Validate length/hash, disable credential forwarding on redirects, cap redirects and timeouts, prevent DNS rebinding/SSRF, and reject metadata-service or private destinations unless explicitly configured as approved internal infrastructure.

## 8.2 Acceptance sequence

The local connector verifies provider enrollment, signature, body ID, caller/device, nonce, expiry and replay status. It obtains and verifies the package using the existing package codec and local package-author trust. It resolves/locks the recipe, produces an immutable local plan, intersects that plan with the owner's finite grant, then calls `ensurebtxcapability`.

The CEX's handoff ID is mapped to a local job and generation. A duplicate accepted handoff returns that mapping; it must not start another download or runtime. A changed package under the same handoff is a conflict. On expiry no new effects begin; already approved running jobs use the local grant and cancellation policy, not a remote timestamp that forcibly frees memory.

## 8.3 Progress and return values

Separate RECEIVED, LOCALLY_REJECTED, PLANNED, ACQUIRING, VERIFIED_FILES, LOADING, RUNTIME_READY and FAILED from all financial states. A local READY report is created only after the JIT readiness contract is satisfied. Preserve physical cleanup state for canceled transfers and memory leases. A hosted UI must never turn `finance=CONFIRMED` into `runtime=READY`.

The local agent receives opaque lease/generation handles and approved local access information. The exchange receives only opt-in coarse reports: handoff ID, stage, error class and optionally aggregate timing. Absolute paths and private model lists are excluded.

# 9. Custody modes and account-to-chain meaning

## 9.1 Three supported modes

CUSTODIAL means the exchange controls the relevant native keys and the customer relies on its account ledger and recovery service. SELF_CUSTODY means the gateway can prepare or display an intent but the user's wallet signs independently. DISCOVERY_ONLY has no finance dependency. Do not imply one mode's guarantees apply to another.

The initial custodial funding profile uses one native funding lot per customer action, even when one legal CEX controls several lots. This preserves traceability between a ledger debit, terms and outpoint. Transaction batching is permitted only when each customer's exact output, fees and refund mapping remain explicit and the native protocol permits it. No single pooled unallocated escrow is a substitute.

## 9.2 Legal account and agent identity

A human or legal entity owns the exchange account under its terms. An agent is an authorized principal/subaccount, not an assumed new legal person. Custodial on-chain contributor identity belongs to the actual signer arrangement. Do not multiply council votes or pretend independent contributors exist by splitting one custodian's keys; apply the committed native terms and disclose aggregation.

## 9.3 Balance vocabulary

Expose AVAILABLE, RESERVED_UNSIGNED, BROADCAST_PENDING, COMMITTED_ONCHAIN, REFUND_PENDING and RETURNED with separate principal and fee amounts. Deposit finality, customer liabilities, custodied assets and protocol commitments are separate ledgers/views. Define which liabilities remain under the custody agreement when funds are committed on chain.

A CEX credit is not proof of a native output. A signed funding transaction is not confirmation. A refund deadline is not already-returned money. A recovery file without the necessary private signing authority does not give a custodial user unilateral recovery.

## 9.4 Custody readiness gate

Before CUSTODY/FUNDING is advertised, demonstrate native key generation, address handling, signing, backup/restore, withdrawal and each supported HTLC/escrow spend path on a test network. An existing secp256k1/EVM HSM connector is not presumed to support BTX's current key/script requirements. Use the actual native wallet or a separately audited compatible signer and verify the exact transaction independently.

Document key ownership, cold/hot policy, hot-wallet limits, segregation, operator dual control, customer ledger mapping, fee reserves, recovery schedules and disaster recovery. No new custody product ships on mock signing evidence.

# 10. Quotes, immutable intents and authorization

## 10.1 Quotes

A FundingQuote binds provider, customer context, native chain, action, terms ID, target amount, principal, network-fee ceiling, exchange fee, tax if applicable, total debit, refund-control mode, confirmation requirement, expiry and native-template digest. Where conversion is needed, include a separate firm or indicative conversion quote with currency, size, rate, spread, slippage and expiration.

The quote must state whether it merely estimates costs, reserves liquidity or fixes an executable offer. Indicative prices cannot be silently executed. Unknown native amounts remain unknown. No percent-funded display is accepted as a funding input. [B03, B04; G04]

## 10.2 Intent digest

FinanceIntent binds the exact quote/terms/template, action, account policy generation, principal/fees/recipient and refund commitments, client operation ID and expiration. Canonical hashing excludes mutable execution status. Authorization refers to the exact intent digest. Re-preparing changed terms creates a new intent requiring a fresh matching authorization.

A single finite user instruction may authorize conversion plus funding when both legs and maximum exposure are specified. No generic `auto_pay=true` switch exists. A catalogue recommendation cannot initiate a financial saga.

## 10.3 Prepare, authorize, submit

Create/prepare constructs a proposal and may perform bounded read-only chain checks. Authorize consumes a step-up approval or a finite preapproved policy and records the immutable digest. Submit rechecks policy generation, compliance eligibility, expiry, quote validity and native terms, atomically reserves ledger/policy capacity, and creates an execution outbox record.

No database transaction remains open across network calls or HSM signing. The executor uses the durable outbox, a per-intent ownership/fencing token and a native UTXO lock. Before broadcast, persist the exact signed transaction bytes and their native ID. Crash recovery rebroadcasts those same bytes rather than constructing a second spend.

## 10.4 Idempotency

Use `(provider_id, tenant, account, client_operation_id)` as the durable financial idempotency domain. The request body digest is stored at first acceptance. Same key/same body returns the same intent/outcome; same key/different body returns IDEMPOTENCY_CONFLICT. A new HTTP retry may have a new DPoP proof but retains the same business operation ID.

Financial operation IDs and completion tombstones survive the ordinary API cache lifetime. Keep at least the full active workflow and configured financial retention period; purging must not permit a late retry to spend again. A retry across two CEXs is not globally idempotent: the client must not automatically resubmit an uncertain financial action to another provider.

## Native workflows and existing exchange rails

The HCP quote/intent routes normalize FUND_RELEASE, FUND_BOUNTY, CLAIM and REFUND. Ordinary deposits, withdrawals and stand-alone trading remain the exchange's existing regulated account APIs, documented in its integration map. A parent HCP workflow may reference a firm conversion leg through the QuoteAdapter. The signed FundingQuote then includes both its immutable venue reference and exact source asset/amount/exponent, target BTX, slippage cap and expiry. Authorization to fund does not silently authorize that conversion. Do not fabricate a native terms ID or template for an ordinary currency trade. The HostedAccountPolicy may contain CONVERT/WITHDRAW permissions, but the executor must bind those to their actual separately approved exchange operation.

# 11. Financial state machine and crash recovery

```text
PREPARED → AUTHORIZED → RESERVED → SIGNING → SIGNED
    → BROADCAST_UNKNOWN or BROADCAST → CONFIRMED
    → NATIVE_OUTCOME_OBSERVED → SETTLED

Unsigned safe branches: EXPIRED / CANCELED / REJECTED
Uncertain branches: RECONCILIATION_REQUIRED
Confirmed branch after reorg: CONFIRMATION_REVERTED
Refund branch: REFUND_ELIGIBLE → REFUND_SUBMITTED → REFUNDED
```

## 11.1 Cancellation and expiry

Before any signature or external economic effect, release a reservation atomically when cancellation is safe. Once signing may have occurred, obtain the signer's exact status and signed bytes. A timeout is not proof of no signature. Once broadcast is possible, do not tell the customer the commitment was canceled merely because the API request was canceled.

An expired quote stops new signing. Expiration does not undo a valid transaction. Native refund conditions, not a hosted cancel button, determine escrow recovery after commitment.

## 11.2 Reconciliation

Reconcile exchange liabilities/reservations, signer journals, native UTXOs/transactions and workflow state. Use explicit discrepancy classes with owner and age. Chain observation comes from the CEX's configured native verifier; pending/broadcast/confirmed labels include block and confirmation context. Reorganizations reverse observations, not append-only history.

A reorg does not automatically replenish a spending budget or make a broadcast transaction safe to replace. A disclosed release secret remains known after confirmation changes. Restore financial and knowledge state separately.

## 11.3 Budget accounting

Reserve principal and worst-case authorized fees under per-action, lifetime and outstanding-exposure ceilings across all concurrent workers. Settled principal consumes lifetime spend even if a later refund credits the account, unless the owner separately authorizes a clearly defined recycling policy. Default refund behavior restores balance, not lifetime mandate capacity.

Fees settle to actual amounts no greater than authorization; unused fee reservations release only after uncertainty closes. Do not count one same-currency conversion as a bounty contribution or treat it as revenue twice.

## 11.4 Conversion is a separate leg

Fiat/stablecoin-to-BTX conversion and native funding are not an atomic cross-system transaction. Persist leg states and returned assets. If conversion succeeds but terms expire or funding fails, retain BTX in the customer account and report the result. Reverse conversion requires explicit prior policy or new consent; it may incur spread and price risk.

The UI must show an intelligible partial outcome instead of generic FAILED. This is essential for agents that otherwise retry the whole workflow.

# 12. Release, bounty, refund and claim workflows

## 12.1 Release financing

Inspect exact publisher terms and currently observed funding. Prepare the native frozen quote. Present contributor amount, fees, key commitment, claim/refund conditions and funding round. After authorization, use the native validator/signing sequence. Report economic commitment independently from model-release availability. A release can be funded but not yet disclosed, and the protocol does not prove useful model quality simply by unlocking bytes. [B04; G04]

## 12.2 Bounty funding and research operations

Provide create/validate/publish/follow surfaces through role-scoped adapters to existing signed bounty records. Show council/evaluation rules, immutable terms, submission window, contribution lot and refund path before funding. Support submissions and evaluation-record browsing without giving the CEX unilateral scientific authority.

Actual benchmark execution remains a separately authorized isolated worker under the existing evaluation contract. Do not expose arbitrary evaluation scripts as a generic public gateway action. A sponsor competing for its own bounty must follow the same committed eligibility and conflict rules; do not promise the sponsor can always win back its funds.

## 12.3 Refund and claim

A native observer determines eligibility. Prepare and authorize exact refund/claim transactions, including recipient ownership and fee policy. A custodial exchange credits the correct beneficiary when the native result is sufficiently confirmed; a self-custody mode returns preparation material to the user's wallet. Preserve exact recovery artifacts and deadlines without exposing private keys to customers who do not own them.

A customer must be able to export the native terms, outpoint and custody/refund responsibility even if platform service ends. This export makes obligations visible; it is not a substitute for actual signing rights.

## 12.4 No invented entitlements

Public packages remain public. A release contribution does not automatically buy exclusivity, IP ownership, investment returns or early access. Any paid-access entitlement must reuse an actually implemented native or separately contracted access mechanism with exact terms. Unsupported modes return UNSUPPORTED_ECONOMIC_MODE, never a fabricated receipt that bypasses provider policy.

# 13. Receipts and independently meaningful status

A FinancialReceipt is a signed provider statement containing intent ID/digest, account-scoped reference, action, native terms, quote, amounts, fee disposition, custody/refund controller, current state, evidence basis, native transaction/outpoint and block context where known, observation time, receipt sequence and supersedes reference. Omit unavailable chain facts instead of inventing zeros.

Use evidence bases CEX_LEDGER, NATIVE_NODE_OBSERVED and EXTERNAL_VERIFIER_OBSERVED. This describes how the issuer obtained the information; a remote recipient still receives the issuer's attestation unless it independently verifies. Never label an ordinary provider receipt as a consensus proof.

Receipts are immutable and versioned; corrections produce a new signed receipt. State machines reject impossible transitions and account mismatches. Application truth remains multi-axis: authorization, ledger reservation, transaction state, release knowledge, payload verification and runtime readiness are separate.

# 14. Subscriptions, events and bounded agent autonomy

Hosted subscriptions can follow publisher, package channel, release, bounty or bounded query. Events are provider-scoped observations with generation, sequence, stable event ID, exact object/version, time and optional chain anchor. Delivery is at-least-once. SSE and bounded polling share one cursor scheme, bound to provider, tenant, account and filter digest. CURSOR_TOO_OLD requires reconciliation, not silent loss.

NOTIFY and PREPARE are default actions. Financial automation requires a finite account policy plus the native custodian's independently enforced authorization. Local auto-acquisition requires a separate local grant. One event can legitimately produce a funding preparation and a later local acquisition, but neither is permission for the other.

Webhooks use authenticated destination enrollment, allowlisted HTTPS endpoints, SSRF controls, delivery IDs, timestamps and established signature verification. Retries back off and dead-letter. No raw tokens or model blobs in webhook bodies. A webhook consumer must fetch/validate the current immutable object before action, not trust a short summary as full terms.

# 15. Browser handoff, device enrollment and fleet UX

## 15.1 Browser to device

Prefer downloading the `.btx` plus signed handoff and opening it through the installed client, or a paired outbound device queue. Do not place tokens or commands in URI query strings. The browser must not discover an unauthenticated localhost wallet or send cross-origin runtime RPCs.

Pairing uses a local random challenge, short-lived displayed code, account-authenticated approval, device-key proof and explicit comparison of the device/provider identities. Rate-limit guesses and expire unused requests. Pairing grants transport/report access only; financial and runtime effects need their own policies.

## 15.2 Outbound-only fleet connector

Managed devices poll or subscribe outbound to approved providers. The queue carries proposed exact handoffs, not executable commands. Local policy verifies each handoff before planning. Revocation stops accepting new provider work and follows safe local retirement semantics; it never forcibly reuses in-flight GPU buffers.

A device is not globally tracked by a shared public account ID. Use pairwise identifiers per provider and retain a local audit mapping. Reports are minimal and opt-in. A CEX cannot delete public model files merely because a subscription ended.

## 15.3 Interface states

Show Funding separately from Installation. Explain when money is reserved, when signing/broadcast is uncertain, when a release awaits disclosure and when local work needs approval. A single normal user journey can be one approved intent plus one finite local plan; it does not need a confirmation dialog for every internal packet or tensor.

# 16. Privacy, telemetry and customer choice

Public model identity, provider discovery and locally possessed bytes remain portable. Hosted account and query activity is visible to the CEX. Disclose that fact at enrollment; do not call custodial hosted mode anonymous or fully decentralized at every layer.

Default reporting is OFF. Optional coarse reports contain no prompts, completions, KV/prefix state, private inventory, absolute paths, wallet/cloud secrets, detailed hardware fingerprint or raw memory/fabric identifiers. Retain customer audit data under explicit policy, separate from public event logs and analytics. Do not train or sell cross-customer capability-demand data by default.

The customer can use one provider for finance and another for discovery, or local discovery with CEX custody. Provide a zero-external-search mode. Switching providers requires new authentication and consent; it does not replay financial intents or export credentials.

# 17. Availability, scale and outage behavior

Design the catalogue/API edge stateless behind the CEX's standard load balancer. Durable intentions, authorization, reservations and outbox records reside in the exchange's transactional persistence tier. Signer execution is single-owner per intent with fencing. A per-process mutex alone is insufficient across replicas.

Separate caches for public immutable packages, attributed catalogue observations and private account state. User-specific responses carry `Cache-Control: no-store`. Never share a cache key that omits tenant/account. Bound body sizes, dependency counts, search result pages, pending SSE clients, webhook retries and native RPC concurrency.

An outage may block new finance or hosted discovery. Already acquired public models and local readiness leases do not depend on a periodic CEX heartbeat. Pending actions retain their durable status and are reconciled after recovery. A local client can switch read discovery providers explicitly; it must not duplicate an uncertain financial submission.

Establish operator-specific SLOs from benchmarks. Suggested planning targets—not performance claims—are 99.9% read API availability, 99.95% durable intent-state availability and recovery-point objective zero for accepted financial intents. Test the claimed durability across failover before publishing such objectives.

# 18. API and error contract

The base path is `/btx/hcp/v1`. Do not claim a registered IANA well-known name; profile discovery uses the explicitly configured endpoint. `schemas/openapi.yaml` and `schemas/HCPObjects.schema.json` accompany this document. Private implementation names are reconciled against existing code before registration.

All errors contain stable code, stage, retryability, correlation ID and safe next action. Errors include AUTH_REQUIRED, SCOPE_DENIED, POLICY_DENIED, QUOTE_EXPIRED, IDEMPOTENCY_CONFLICT, TERMS_CHANGED, INSUFFICIENT_AVAILABLE_BALANCE, CUSTODY_UNSUPPORTED, BROADCAST_UNKNOWN, NATIVE_VERIFIER_UNAVAILABLE, PACKAGE_MISMATCH, LOCAL_GRANT_REQUIRED, SOFTWARE_TRUST_REQUIRED, NO_ELIGIBLE_RECIPE, CURSOR_TOO_OLD, RATE_LIMITED and PROVIDER_REVOKED.

HTTP 202 means accepted asynchronous work, not success. 409 represents conflict/state mismatch. 422 represents invalid semantic input. 429 includes bounded retry guidance. 503 identifies temporary dependency failure. Unknown monetary state is returned as a state, not converted into a retryable “nothing happened” error.

| API group | Mandatory operations | Responsibility |
|---|---|---|
| Profile/catalogue | profile; search; exact package; economy view | Attributable read results |
| Identity/device | enrollment; confirmation; paired jobs; reports | Pairing and narrow access |
| Treasury | balances; quotes; intents; authorize; submit; cancel; receipts | Explicit CEX-to-native lifecycle |
| Policies | create/read/revoke; subscriptions | Finite account delegation |
| Handoffs | create/read; exact package attachment | Portable local proposal |
| Research | draft/validate/publish; submissions/evidence views | Existing native signed objects |
| Events/export | polling/SSE; export create/status | Recovery and portability |

# 19. Native integration and code map

| Area | Reuse inspected or supplied seam | Additional work |
|---|---|---|
| Web boundary | `src/modelnet/http_bridge.cpp`, boundary documentation | Keep read-only; add separate HCP gateway, not a wallet proxy |
| Financial templates | `src/wallet/model_funding.h`; native bounty RPCs | Typed executor adapter, exact template verification, signer journal |
| Model discovery | Private signed-object store and network search | HCP catalogue projection and query limits |
| Package verification | Private BTXPKG1/Core v3 codec | Handoff importer calling the same parser |
| Local orchestration | `planbtxcapability`, `ensurebtxcapability`, generation leases | Walletless preset and hosted connector |
| Resources/runtime | JIT broker, ranges, runtime ABI | Preserve local priority, grants and privacy |
| Events | Existing durable journal/cursors | Provider/account partitioning, financial outbox and SSE |
| CEX systems | Existing IDP, ledger, quote, compliance and custody services | Bounded interfaces and conformance adapters |

Proposed new modules are `src/hosted/{profile,enrollment,handoff,receipt,connector,policy_view}.cpp` and headers; `contrib/hcp-gateway/` or a separately packaged service for the web/control implementation; `contrib/hcp-sdk/`; `doc/hosted/`; and native tests. These are proposals, not evidence those paths exist. Prefer actual equivalent private modules where present.

The gateway may use the exchange's approved service language and persistence system. The standardized contract is more important than mandating a new language runtime in monetary binaries. Do not link HTTP/OAuth libraries or exchange SDKs into consensus-critical targets.

# 20. Exchange adapter interfaces

Define narrow interfaces: IdentityAdapter resolves verified caller context; EligibilityAdapter evaluates product/jurisdiction actions; LedgerAdapter reserves/settles/releases atomically; QuoteAdapter obtains explicit conversion offers; CustodyAdapter validates/signs exact supported native transactions; ChainObserver reports native facts; NativeEconomyAdapter prepares/inspects committed workflows; PackageAdapter exports exact package bytes; AuditAdapter records immutable events; and ReportingAdapter exports customer-approved records.

Each interface defines timeout, idempotency, retry and ambiguity semantics. Signer timeout returns UNKNOWN unless a lookup proves NOT_SIGNED. Ledger calls carry intent and fencing IDs. Native adapters return capability support rather than guessing. The supplied Python interface sketch documents these contracts and deliberately refuses production signing.

Exchange-specific implementations must prove the supported native transaction/script family. A generic `send_coin(address, amount)` adapter is not sufficient for frozen release funding, bounty trees, refund paths and signer consent.

# 21. Reusable SDKs, reference portal and integration assets

Deliver Python and TypeScript client SDKs generated from the same OpenAPI contract. They must preserve decimal atom strings, immutable IDs, client-operation IDs and ambiguous outcomes. Implement typed catalogue/quote/handoff calls and polling; do not auto-submit financial mutations on timeouts. Provide an MCP wrapper with declared effects and no token passthrough.

Deliver a reference portal with catalogue, package detail, release/bounty terms, treasury, approval, activity and paired-device views. Public ranking annotations must be clearly separate from protocol facts. Browser code cannot possess custody-signing keys or call native wallet RPC. Use the same SDK in the portal and example agent.

The package delivered here includes a safe reference simulator and contract assets; Cursor must implement and test the production service, SDKs and portal. Demo fixtures are not production credentials or financial evidence. Every example must run against the local simulator or explicitly identify its native/operator prerequisites.

# 22. Compliance, rights and business controls

Maintain a product eligibility matrix by legal customer, venue, action and jurisdiction. Protocol portability does not remove custody, AML/CFT, sanctions, transfer or market-conduct duties. Route restricted actions to explicit denial or an approved manual review. Preserve records needed by the operator without putting personal data on public model records. [R10]

A capability contribution is not inherently an investment security, ownership interest or tax-capitalizable asset; actual rights govern classification. Do not turn a bounty or public release into a tradable yield product in this engineering round. Procurement, research, software and custody fees are disclosed separately. Auditors receive the facts rather than an automatic CAPEX label. [R11]

Conflict controls cover sponsored ranking, the CEX's own BTX positions, affiliated model suppliers, evaluator relationships and conversion execution. A compliant customer exit includes usable exports and documented custody/refund obligations. A cryptographic proof of assets does not, by itself, prove liabilities, solvency or customer title.

# 23. Migration, cutover and rollback

First deploy read-only profile/catalogue/package paths. Then enable paired handoff with finance disabled. Enable custody and funding only after native test-network signing, reconciliation and recovery gates. Enable subscriptions/fleet automation after duplicate, replay, policy-revocation and privacy tests pass.

No old browser wallet route is opened as a shortcut. No funded native term is rewritten. Existing package cores remain exact; HCP envelopes wrap them externally. Back up local provider enrollments and CEX data; schema migrations are versioned, restartable and tested against partial failure.

Rollback disables new gateway effects while preserving durable intent reconciliation, refunds, public acquired bytes and local lease safety. An application rollback cannot erase an already broadcast transaction. Feature flags disable new work, not historical financial accountability.

# 24. Parallel-agent execution and evidence

Use one coordinator and disjoint workers for contracts/SDK, native hosted connector, identity/security, ledger/intents, native custody/economics, device/portal, events/export, conformance/performance and independent audit. Request Grok 4.6 Extra High workers as in the preceding programme; confirm the actual available dispatch mechanism. Do not invent a model flag or claim parallel execution if it did not occur.

Freeze object schemas, effect taxonomy, adapter contracts and authority boundaries first. Assign one owner to CMake, shared registration and schema aggregation. Use exclusive file ownership or separate worktrees with controlled integration. No worker may reset a shared tree, touch production wallets, push, merge, publish, change release flags or restart live services.

Track SPECIFIED, STATIC_REVIEW, REFERENCE_PASS, NATIVE_UNIT_PASS, PROCESS_E2E_PASS, NATIVE_CHAIN_PASS, CUSTODY_LAB_PASS and OPERATOR_PILOT separately. The same test may need multiple evidence levels. Source grep is never runtime evidence. Candidate fingerprints include dirty state and binary hashes.

# 25. Whole-system journeys

**J01 — Free hosted discovery.** A fresh walletless client enrolls a discovery provider, obtains an exact package, uses an owner grant, acquires from the native network and reaches a real local readiness target. Confirm no monetary wallet/sync, no CEX fee transaction and no provider-supplied software trust.

**J02 — Locality wins.** CEX recommends a candidate with an internet source; the client has an exact resident base and LAN adapter. The local resolver chooses the permitted lower-TTC path, without reporting private inventory or changing the locked recipe.

**J03 — Release funding.** A customer obtains a firm quote, authorizes exact terms, funds via a real test-network native transaction, then acquires only after valid release disclosure. Financial receipt, knowledge and runtime states are independent.

**J04 — Conversion partial success.** Conversion succeeds, but funding terms expire. The customer retains converted BTX; no unauthorized reverse trade or second funding occurs. An agent retry retrieves the existing multi-leg outcome.

**J05 — Unknown broadcast.** Lose the response after native broadcast and restart every gateway worker. Reconcile and rebroadcast only identical signed bytes. No second debit, new transaction or auto-failover spend is created.

**J06 — No award and refund.** A funded bounty receives no qualifying award. Reach the committed native refund condition, prepare/authorize/refund and credit the correct custodial beneficiary. Prior lifetime policy spend is not silently restored.

**J07 — Subscription under concurrency.** Deliver duplicate release events to many workers under one finite policy. Exactly one business intent is created per permitted logical event, bounds remain intact and revocation stops new signing.

**J08 — Malicious provider.** A valid provider signature carries a changed package, wrong account, executable URL or forged READY state. Local verification/policy rejects each without opening a wallet or executing code.

**J09 — Provider exit.** Acquire using provider A, disconnect A, export lock/package and reconnect to B for new discovery. Public local use persists. Pending finance on A remains explicitly unresolved rather than being replayed to B.

**J10 — Custody failure drill.** Restore signer/ledger state in an isolated lab from documented backups, reconcile existing outputs and execute an eligible refund. Prove that exported public recovery data alone does not claim customer signing power.

**J11 — Fleet browser journey.** Pair a clean device, create a handoff in the portal, approve the finite local policy, obtain minimal progress and revoke pairing. No inbound runtime port, browser token in URI or cross-account device command is accepted.

**J12 — Privacy and service independence.** Capture network traffic through catalogue, funding and local execution. Prompts, KV, local paths and CEX tokens remain in their intended domains. Gateway loss does not interrupt an already-ready public local capability.

# 26. Completion and operator handoff

Completion requires all mandatory contract, native, process and custody tests appropriate to advertised profiles. Missing hardware or credentials must be recorded, not called PASS. The package must include exact deployment prerequisites, supported native versions, operation map, schemas, SDK builds, integration guide, portal demonstration and reproducible conformance evidence.

Return candidate fingerprint, changes, tests by evidence tier, every FAIL/NOT_RUN, unresolved native prerequisites, security findings, privacy defaults, key/custody support and suggested rollout profile. Stop for operator approval before any production change, public push, merge, tag or release-flag update.

The product is complete when a CEX can attach its existing financial systems once and safely offer portable cognitive-capital workflows—while a customer can retain local control and leave without losing already acquired public capability.

# Appendix A. Full acceptance catalogue

The following cases are normative. The execution ledger is `tests/native-acceptance.csv`; all entries start NOT_RUN. Each evidence record includes candidate fingerprint, tested binary hashes, environment, commands, assertions and retained logs. Reference simulator tests do not satisfy native-chain, OAuth, PQ, custody, browser or runtime gates.

## HCP-FRM — Framing, signatures and provider enrollment

Required test environment: native codec + real ML-DSA provider keys.

### HCP-FRM-01 — Canonical statement round trip

**Given:** A ProviderProfile with canonical body and a native provider signature. **When:** Encode, decode and independently re-encode it. **Then:** Identical body bytes and body_id; native signature verifies; field roles remain distinct.

**Evidence:** evidence/HCP-FRM-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-02 — Parser differential rejection

**Given:** Raw bodies containing duplicate keys, float/exponent numbers, lone surrogates or trailing bytes. **When:** Feed the same vectors to API, native verifier and SDK readers. **Then:** All reject before privileged effects; no parser selects a different meaning.

**Evidence:** evidence/HCP-FRM-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-03 — Domain separation

**Given:** The same semantic fields signed as CapabilityOffer. **When:** Relabel the envelope as FinancialReceipt without resigning. **Then:** Body domain mismatch fails; no economic observation is accepted.

**Evidence:** evidence/HCP-FRM-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-04 — Unknown provider self-signature

**Given:** A syntactically valid profile signed by a new unaccepted root. **When:** Attempt automatic enrollment through a model package. **Then:** Preview may display the claim; no trusted provider or account connection is installed.

**Evidence:** evidence/HCP-FRM-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-05 — Operational key rotation

**Given:** An enrolled root, old key and valid sequence-bound rotation. **When:** Rotate during active handoffs and replay an older keyset. **Then:** Permitted overlap works; stale sequence and expired/revoked keys cannot authorize new effects.

**Evidence:** evidence/HCP-FRM-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-06 — Origin rebinding

**Given:** A trusted provider profile whose next fetch redirects to a different origin. **When:** Fetch profile and token metadata through the redirect. **Then:** No credential is forwarded; unapproved origin change requires enrollment.

**Evidence:** evidence/HCP-FRM-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-07 — Size and structural bounds

**Given:** Oversized body, enormous arrays and nesting above configured limits. **When:** Submit before expensive schema and signature verification. **Then:** Bounded rejection, memory ceiling and no CPU-amplification loop.

**Evidence:** evidence/HCP-FRM-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FRM-08 — Role separation across signatures

**Given:** Accepted provider key and independently trusted package/software keys. **When:** Use provider signature as package author, client distributor or wallet signature. **Then:** Every inappropriate role is rejected; correct provider receipt remains only an attestation.

**Evidence:** evidence/HCP-FRM-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-AUTH — Authentication and tenant isolation

Required test environment: real configured OAuth test identity provider.

### HCP-AUTH-01 — Authorization code PKCE

**Given:** Two browser sessions and separate PKCE challenges. **When:** Swap code, redirect, state or verifier across sessions. **Then:** Code is rejected; no account session/token leaks; exact legitimate session succeeds.

**Evidence:** evidence/HCP-AUTH-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-02 — Sender-constrained token theft

**Given:** A DPoP-bound or mTLS-bound financial token. **When:** Use it with a different key/certificate or replay proof ID. **Then:** Access is denied; no financial preparation/signing effect occurs.

**Evidence:** evidence/HCP-AUTH-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-03 — Audience enforcement

**Given:** Tokens for catalogue and a distinct MCP/resource service. **When:** Present each to finance and local capability endpoints. **Then:** Audience mismatch is rejected; no token passthrough to downstream services.

**Evidence:** evidence/HCP-AUTH-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-04 — Scope escalation

**Given:** catalog:read token and a valid private account. **When:** Attempt quote, authorization, submit and policy creation through GET/POST variants. **Then:** All writes fail; read-only responses reveal no account-private data.

**Evidence:** evidence/HCP-AUTH-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-05 — Tenant object isolation

**Given:** Accounts A and B with similarly named intents/devices. **When:** A requests B objects by guessed IDs and cursor. **Then:** Response denies access without leaking existence, balances or metadata.

**Evidence:** evidence/HCP-AUTH-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-06 — DPoP is not body approval

**Given:** A sender-valid token and previously approved intent body. **When:** Change principal or terms while retaining request proof. **Then:** Immutable intent digest check rejects content mutation despite valid token possession.

**Evidence:** evidence/HCP-AUTH-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-07 — Refresh and revocation

**Given:** Active agent token and revoked refresh/policy context. **When:** Attempt reuse across renewal and in-flight new authorization. **Then:** Revoked authority blocks new effects; existing dispatched effects remain reconcilable.

**Evidence:** evidence/HCP-AUTH-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-AUTH-08 — Secret leakage sweep

**Given:** Sentinel OAuth tokens, cloud credentials and wallet secret fixtures. **When:** Exercise failure, export, runtime, logs and source-hint paths. **Then:** Sentinels occur only in approved secret stores; no child runtime environment or public payload contains them.

**Evidence:** evidence/HCP-AUTH-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-GRANT — Local and hosted authority

Required test environment: native local grant service + gateway policy adapter.

### HCP-GRANT-01 — Handoff without local grant

**Given:** Valid signed handoff and no LocalCapabilityGrant. **When:** Ask the connector to acquire and run. **Then:** Returns LOCAL_GRANT_REQUIRED without model network/runtime side effects.

**Evidence:** evidence/HCP-GRANT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-02 — Finite first-use convenience

**Given:** Owner grants acquire/load for exact recipes and finite budgets. **When:** Complete several covered local steps unattended. **Then:** No repeated per-step approval; every effect and reservation stays within the original scope.

**Evidence:** evidence/HCP-GRANT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-03 — Financial policy cannot launch

**Given:** Valid HostedAccountPolicy allowing release funding. **When:** Present it as authority for runtime execution. **Then:** Rejected by local service; no executable or memory allocation is authorized.

**Evidence:** evidence/HCP-GRANT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-04 — Local grant cannot spend

**Given:** Valid local acquisition/run policy and funded customer account. **When:** Try finance authorize/submit using local grant ID. **Then:** Rejected by gateway/custody policy; balances unchanged.

**Evidence:** evidence/HCP-GRANT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-05 — Revocation race

**Given:** Authorized local job and account policy revision near expiry. **When:** Revoke as another worker attempts a new signature or local effect. **Then:** New effects fail; already in-flight buffers/signatures follow safe reconciliation.

**Evidence:** evidence/HCP-GRANT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-06 — Resource ceilings

**Given:** Two concurrent ensure jobs each fitting isolated memory budget. **When:** Run both under one shared host ceiling. **Then:** Atomic admission prevents combined oversubscription; no duplicate broker creates fictitious capacity.

**Evidence:** evidence/HCP-GRANT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-07 — Future issuer scope

**Given:** Finite subscription for publisher P. **When:** Deliver signed release by Q and P after root rotation. **Then:** Q denied; P rotation follows exact delegation policy rather than arbitrary same display name.

**Evidence:** evidence/HCP-GRANT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-GRANT-08 — Deadline does not relax policy

**Given:** Fast untrusted source and slow approved source. **When:** Set an unreachable TTC deadline. **Then:** Returns explicit unmet deadline; no verification, software trust or privacy rule is disabled.

**Evidence:** evidence/HCP-GRANT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-DISC — Catalogue and package discovery

Required test environment: native signed-object store + hosted projection.

### HCP-DISC-01 — Exact package preservation

**Given:** Native Core v3 descriptor with documents and recipes. **When:** Fetch it through two independent hosted providers. **Then:** Same package_core_id and byte hash; provider wrappers do not mutate the signed core.

**Evidence:** evidence/HCP-DISC-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-02 — Curation versus truth

**Given:** Sponsored entry with limited availability evidence. **When:** Render search and export machine response. **Then:** Sponsorship/rank, signature status, quality claims and observed availability are separate fields.

**Evidence:** evidence/HCP-DISC-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-03 — No invented capacity

**Given:** Source reports unknown memory compatibility and incomplete provider view. **When:** Search with strict memory/evidence requirements. **Then:** Unknown remains unknown; does not become compatible or globally complete.

**Evidence:** evidence/HCP-DISC-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-04 — Catalogue caching isolation

**Given:** Public immutable package and account-private funding view. **When:** Exercise shared caches across accounts and stale versions. **Then:** Immutable bytes cache safely; private responses no-store and no cross-account cache hit.

**Evidence:** evidence/HCP-DISC-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-05 — Bounded natural-language input

**Given:** Query containing native RPC text or SQL-like syntax. **When:** Search and paginate through gateway. **Then:** Text stays data; query budget enforced; no native mutation or expression execution.

**Evidence:** evidence/HCP-DISC-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-06 — Economic freshness

**Given:** Old percent-funded label and current different chain state. **When:** Read economy view before planning finance. **Then:** Dated observation displayed separately; current terms/anchor required for financial plan.

**Evidence:** evidence/HCP-DISC-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-07 — Capability equivalence guard

**Given:** Two similarly named recipes with different evidence/outputs. **When:** Select under a minimum capability contract. **Then:** Only qualifying recipe eligible; same keyword is not substitution authority.

**Evidence:** evidence/HCP-DISC-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-DISC-08 — Independent provider alternative

**Given:** Provider A offline, provider B has same exact package. **When:** Explicitly switch discovery configuration. **Then:** Read discovery succeeds without changing package/resource identity or migrating financial intent.

**Evidence:** evidence/HCP-DISC-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-HAND — Handoff delivery

Required test environment: hosted connector + native package verifier.

### HCP-HAND-01 — Device and nonce binding

**Given:** Valid handoff for device A nonce N. **When:** Replay to B or to A with a different pending nonce. **Then:** Rejected before planning; no transfer or execution job created.

**Evidence:** evidence/HCP-HAND-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-02 — Expiry and clock policy

**Given:** Handoff at boundary of allowed skew and a stale one. **When:** Verify with deterministic clock fixtures. **Then:** Only policy-valid handoff accepted; no unlimited grace caused by malformed timestamp.

**Evidence:** evidence/HCP-HAND-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-03 — Package substitution

**Given:** Handoff binds one exact package/recipe. **When:** Serve another validly signed package at the same URL. **Then:** PACKAGE_MISMATCH; neither author signature nor HTTPS hides substitution.

**Evidence:** evidence/HCP-HAND-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-04 — Durable duplicate handoff

**Given:** Accepted handoff and interrupted response. **When:** Deliver repeatedly after client restart. **Then:** One local business job/generation or explicit previous outcome; no duplicate resource reservation.

**Evidence:** evidence/HCP-HAND-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-05 — Malicious instruction fields

**Given:** Valid provider signature over unsupported shell/env/path fields. **When:** Import handoff into local connector. **Then:** Strict schema/effect boundary rejects; no shell evaluation or runtime trust expansion.

**Evidence:** evidence/HCP-HAND-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-06 — Free path

**Given:** Public capability available natively and empty CEX balance. **When:** Acquire through hosted handoff. **Then:** No wallet sync, monetary signature or compulsory platform payment occurs.

**Evidence:** evidence/HCP-HAND-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-07 — Optional reporting

**Given:** Owner disables readiness reporting. **When:** Finish acquisition and inference. **Then:** No report leaves device; local result remains usable.

**Evidence:** evidence/HCP-HAND-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-HAND-08 — Provider disconnect

**Given:** Ready public capability with provider subsequently unreachable. **When:** Run local workload, release lease and use local cache later. **Then:** No mandatory CEX heartbeat; fresh hosted actions fail clearly without killing acquired data.

**Evidence:** evidence/HCP-HAND-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-LOCAL — Locality and runtime sovereignty

Required test environment: real capability runtime + local/LAN sources.

### HCP-LOCAL-01 — Resident base reuse

**Given:** Exact base resident, compatible adapter on LAN and remote source hint. **When:** Ensure the selected recipe. **Then:** No base re-download; local TTC plan chooses permitted missing components and native result matches baseline.

**Evidence:** evidence/HCP-LOCAL-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-02 — Faster path not fixed rank

**Given:** Slow local disk and faster authorized LAN source. **When:** Plan using measured inputs then execute. **Then:** Planner can choose LAN; explains confidence and stage costs without a rigid category hierarchy.

**Evidence:** evidence/HCP-LOCAL-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-03 — Runtime trust

**Given:** Provider recommends unsupported executable URL. **When:** Plan client/runtime preparation. **Then:** SOFTWARE_TRUST_REQUIRED or unsupported profile; no automatic untrusted install.

**Evidence:** evidence/HCP-LOCAL-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-04 — Sparse missing extent

**Given:** Partially materialized model with an absent required piece. **When:** Attempt loading through hosted journey. **Then:** Verified reader blocks/fails; missing bytes never become zero-valued trusted weights.

**Evidence:** evidence/HCP-LOCAL-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-05 — Readiness distinction

**Given:** Transfer complete but runtime warmup fails. **When:** Report hosted/local statuses. **Then:** Download completion is not RUNTIME_READY; financial success remains separate.

**Evidence:** evidence/HCP-LOCAL-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-06 — Cancel under DMA

**Given:** Active GPU transfer with remote CEX cancel request. **When:** Authorize local cancellation while physical transfer remains active. **Then:** Lease retained until fence; no stale write to reused generation.

**Evidence:** evidence/HCP-LOCAL-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-07 — Private state containment

**Given:** Active prompt/KV/prefix cache and hosted reporting enabled. **When:** Send allowed coarse report and export handoff state. **Then:** No prompts, completions, KV, pointers or private paths leave local trust domain.

**Evidence:** evidence/HCP-LOCAL-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LOCAL-08 — No remote inference shortcut

**Given:** Local runtime unavailable and provider has a remote inference API. **When:** Ensure a LOCAL_ONLY recipe. **Then:** Returns explicit unsupported/not ready; never forwards a prompt to the provider.

**Evidence:** evidence/HCP-LOCAL-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-CUST — Custody and native template support

Required test environment: isolated native chain + actual supported signer.

### HCP-CUST-01 — Native key capability

**Given:** Custody backend advertising only generic EVM support. **When:** Enable FUNDING profile. **Then:** Profile remains disabled with CUSTODY_UNSUPPORTED; no fabricated BTX signature path.

**Evidence:** evidence/HCP-CUST-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-02 — Frozen script validation

**Given:** Prepared release/bounty tree and approved refund key. **When:** Change claimant, script, amount or refund height before signing. **Then:** Custody independent validation rejects exact mismatch.

**Evidence:** evidence/HCP-CUST-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-03 — Customer lot attribution

**Given:** Two custodial users co-fund one native round. **When:** Prepare/sign/broadcast and reconcile lots. **Then:** Each contribution maps to its own authorized lot and beneficiary; no principal counted twice.

**Evidence:** evidence/HCP-CUST-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-04 — No synthetic council seats

**Given:** One custodian with many customer subaccounts. **When:** Project participants and evaluator rights. **Then:** Native rules used; subaccounts do not create independent control or votes by UI fiction.

**Evidence:** evidence/HCP-CUST-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-05 — Signer timeout ambiguity

**Given:** Custody creates signature but response is lost. **When:** Retry caller and restart executor. **Then:** Lookup same signing operation; no new independent spend or automatic hold release.

**Evidence:** evidence/HCP-CUST-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-06 — Recovery drill

**Given:** Encrypted backups of keys, native transaction state and customer ledger. **When:** Restore into isolated lab and perform eligible refund. **Then:** Correct beneficiary recovers; evidence includes native transactions and accounting reconciliation.

**Evidence:** evidence/HCP-CUST-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-07 — Watch-only export honesty

**Given:** Customer exports receipts and public refund paths without keys. **When:** Inspect/export recovery explanation. **Then:** No claim of unilateral refund; custody controller and deadline obligations explicit.

**Evidence:** evidence/HCP-CUST-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CUST-08 — Signer network isolation

**Given:** Malformed native candidate and compromised model helper. **When:** Probe custody endpoint through model/public bridge. **Then:** No route or credential; signer accepts only authenticated typed executor operations.

**Evidence:** evidence/HCP-CUST-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-INTENT — Financial intent lifecycle

Required test environment: transactional gateway + native executor fault injection.

### HCP-INTENT-01 — Idempotent creation

**Given:** Stable client_operation_id and one signed quote. **When:** Create twice with same body and then altered amount/terms. **Then:** Same outcome for same body; 409 for conflict; no second reservation.

**Evidence:** evidence/HCP-INTENT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-02 — Authorization binds intent

**Given:** Prepared immutable intent approved at policy revision N. **When:** Mutate body or raise fees before submit. **Then:** Expected digest/revision validation rejects before signing.

**Evidence:** evidence/HCP-INTENT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-03 — Expired quote

**Given:** Firm quote expires before authorized submission. **When:** Submit with valid OAuth token. **Then:** QUOTE_EXPIRED; no native effect; hold handled under proven unsigned state.

**Evidence:** evidence/HCP-INTENT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-04 — Terms change

**Given:** Approved terms digest differs from current frozen round. **When:** Submit the previously prepared intent. **Then:** TERMS_CHANGED; reprepare requires new explicit authorization.

**Evidence:** evidence/HCP-INTENT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-05 — Crash before broadcast

**Given:** Signed bytes durably recorded and worker dies before dispatch. **When:** Restart and resume execution. **Then:** Recover exact bytes and native input reservations; at most identical dispatch.

**Evidence:** evidence/HCP-INTENT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-06 — Crash after broadcast

**Given:** Native accepts transaction but gateway loses response. **When:** Restart all API/executor replicas and retry client. **Then:** BROADCAST_UNKNOWN until reconciled; same bytes only; no second debit.

**Evidence:** evidence/HCP-INTENT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-07 — Cancel boundary

**Given:** One unsigned prepared intent and one ambiguously broadcast intent. **When:** Cancel both. **Then:** Unsigned cancellation releases safe holds; ambiguous one enters reconciliation without false refund.

**Evidence:** evidence/HCP-INTENT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-INTENT-08 — Conversion partial success

**Given:** Fiat conversion executed, native target becomes ineligible. **When:** Continue composite intent. **Then:** Retain actual converted balance and explicit failed funding leg; no unauthorized reverse trade.

**Evidence:** evidence/HCP-INTENT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-LEDGER — Ledger, exposure and fees

Required test environment: real partner ledger adapter or transactional native test ledger.

### HCP-LEDGER-01 — Concurrent funds reservation

**Given:** One account balance and many simultaneous valid intents. **When:** Race reservations across service replicas. **Then:** Committed holds never exceed available balance; database uniqueness/fencing demonstrated.

**Evidence:** evidence/HCP-LEDGER-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-02 — Principal versus fees

**Given:** Quote principal, network reserve and service fee. **When:** Authorize and render pool/account statements. **Then:** Only principal enters native funding sum; all debit components itemized.

**Evidence:** evidence/HCP-LEDGER-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-03 — Lifetime limit

**Given:** Policy has limited lifetime principal plus separate outstanding cap. **When:** Spend, refund and attempt another action. **Then:** Exposure may decrease after proven refund; lifetime budget does not silently replenish.

**Evidence:** evidence/HCP-LEDGER-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-04 — Overlapping batch outputs

**Given:** Native batch contains output referenced by two ledger entries. **When:** Reconcile funded commitments. **Then:** Duplicate attribution rejected; ledger cannot credit two customers for one economic output.

**Evidence:** evidence/HCP-LEDGER-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-05 — Native money bounds

**Given:** Amount string exceeds native range or has leading zero/exponent. **When:** Prepare quote/intent. **Then:** Reject before integer overflow or native signing; native MoneyRange still enforced.

**Evidence:** evidence/HCP-LEDGER-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-06 — Fee change

**Given:** Network fee required exceeds approved fee cap. **When:** Executor attempts replacement/rebuild. **Then:** Fresh authority required; no hidden principal reduction or fee overrun.

**Evidence:** evidence/HCP-LEDGER-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-07 — Reservation persistence

**Given:** Accepted intent and held funds before database/process crash. **When:** Restore and reconcile. **Then:** Financial intent and hold durably coupled; no orphan release or missing liability.

**Evidence:** evidence/HCP-LEDGER-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-LEDGER-08 — Statements

**Given:** Available, held, escrow, claimed and refunded positions coexist. **When:** Generate customer and aggregate reconciliation report. **Then:** No double-counted available capital; ledger balances and native output attribution reconcile.

**Evidence:** evidence/HCP-LEDGER-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-CHAIN — Chain observation and knowledge

Required test environment: native BTX test network with controllable reorgs.

### HCP-CHAIN-01 — 202 is not settlement

**Given:** Native submission accepted asynchronously. **When:** Read API receipt immediately. **Then:** State is pending/accepted; not funded or final until evidence threshold.

**Evidence:** evidence/HCP-CHAIN-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-02 — Confirmation policy

**Given:** One valid transaction progresses through configured confirmations. **When:** Observe at each anchor. **Then:** Threshold applied; anchor/hash/count exposed as observation, not absolute finality.

**Evidence:** evidence/HCP-CHAIN-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-03 — Reorg correction

**Given:** Confirmed funding falls out of active chain. **When:** Reorganize and deliver observer update. **Then:** Corrective receipt/event, no budget reset or duplicate funding; dependent unsent work paused.

**Evidence:** evidence/HCP-CHAIN-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-04 — Disclosed secret survives reorg

**Given:** Valid release secret observed before claim reorg. **When:** Revert chain anchor. **Then:** Knowledge state remains disclosed; settlement state reverts independently.

**Evidence:** evidence/HCP-CHAIN-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-05 — Observer outage

**Given:** Native node temporarily unavailable. **When:** Query finance state and attempt dependent action. **Then:** NATIVE_VERIFIER_UNAVAILABLE/unknown; absence not claimed and no automatic respend.

**Evidence:** evidence/HCP-CHAIN-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-06 — Verifier disagreement

**Given:** CEX observer and configured independent verifier disagree. **When:** Evaluate required financial prerequisite. **Then:** Explicit conflict; no merged fake certainty; free public data remains separately acquirable.

**Evidence:** evidence/HCP-CHAIN-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-07 — Refund conditions

**Given:** Unawarded bounty before and after native refund height. **When:** Try refund with exact stored template. **Then:** Early attempt denied; eligible refund follows native verification and correct beneficiary credit.

**Evidence:** evidence/HCP-CHAIN-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-CHAIN-08 — Receipt authority label

**Given:** Provider receipt reports a native-node observation. **When:** Import on walletless local client. **Then:** Displayed as HOSTED_ATTESTED unless independently checked; no SPV/full validation claim from signature alone.

**Evidence:** evidence/HCP-CHAIN-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-EVENT — Events and subscriptions

Required test environment: durable outbox + stream/webhook clients.

### HCP-EVENT-01 — At-least-once duplicate

**Given:** One native transition delivered repeatedly through SSE. **When:** Restart client between deliveries. **Then:** One logical local action; event duplicate retained safely without promise of exactly-once transport.

**Evidence:** evidence/HCP-EVENT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-02 — Cursor retention

**Given:** Client cursor predates retained history. **When:** Request events. **Then:** CURSOR_TOO_OLD plus reconciliation route, not empty success.

**Evidence:** evidence/HCP-EVENT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-03 — Account cursor binding

**Given:** Cursor for account A and filter F. **When:** Use with B or altered filter. **Then:** Rejected; no cross-tenant event leakage.

**Evidence:** evidence/HCP-EVENT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-04 — Future subscription race

**Given:** Many workers see same publisher event under finite policy. **When:** Create action concurrently. **Then:** One durable policy/event/action business key; no duplicate debit.

**Evidence:** evidence/HCP-EVENT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-05 — Catalogue restore

**Given:** Restore old records after index rebuild. **When:** Replay discovery into subscriptions. **Then:** Historical matches not counted as new chargeable events.

**Evidence:** evidence/HCP-EVENT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-06 — Outbox crash

**Given:** State committed but event delivery interrupted. **When:** Recover worker. **Then:** Event eventually delivered from durable outbox without losing accepted transition.

**Evidence:** evidence/HCP-EVENT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-07 — Webhook SSRF

**Given:** Callback targets loopback, private metadata address or rebinding host. **When:** Register and trigger callback. **Then:** Configuration policy/DNS/network controls block; no credentials or internal response disclosed.

**Evidence:** evidence/HCP-EVENT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-EVENT-08 — Revoked subscription

**Given:** Policy revoked with queued events. **When:** Process queue after revocation. **Then:** No new signatures; dispatched intents remain reconcilable and visible.

**Evidence:** evidence/HCP-EVENT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-FLEET — Browser and device pairing

Required test environment: real browser + owner-only client connector.

### HCP-FLEET-01 — Pair exact device

**Given:** Device key and short-lived pairing challenge. **When:** Approve from authenticated account. **Then:** Device/account binding confirmed on both ends; wrong/expired challenge rejected.

**Evidence:** evidence/HCP-FLEET-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-02 — No ambient localhost API

**Given:** Malicious web page probes local daemon. **When:** Try GET/POST/CORS/custom URI calls. **Then:** No unrestricted privileged route; no finance token in URI or local process launch.

**Evidence:** evidence/HCP-FLEET-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-03 — Outbound-only handoff

**Given:** Paired device behind NAT/firewall. **When:** Queue capability handoff. **Then:** Device retrieves through authorized outbound session without opening inbound execution port.

**Evidence:** evidence/HCP-FLEET-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-04 — Device revocation

**Given:** Paired device with pending handoff. **When:** Revoke pair then poll/report. **Then:** New handoffs/reports rejected as configured; already local public model stays under owner policy.

**Evidence:** evidence/HCP-FLEET-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-05 — Cross-device replay

**Given:** Handoff for one fleet device. **When:** Replay to another device in same account. **Then:** Device/nonce binding rejects without changing selected recipe.

**Evidence:** evidence/HCP-FLEET-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-06 — Coarse progress

**Given:** Transfer complete, runtime not ready and later ready. **When:** Render portal updates. **Then:** Correct stages; no private paths/prompts; readiness only after valid device observation.

**Evidence:** evidence/HCP-FLEET-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-07 — CEX cannot administer local grant

**Given:** CEX fleet admin attempts to broaden execution policy. **When:** Send remote grant mutation disguised as handoff. **Then:** Local owner/organization policy authority required; hosted credential insufficient.

**Evidence:** evidence/HCP-FLEET-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-FLEET-08 — Mixed platform fleet

**Given:** Two genuinely supported local platforms and different recipes. **When:** Launch same capability request via portal. **Then:** Each local resolver selects eligible exact implementation; unsupported runtime fails explicitly.

**Evidence:** evidence/HCP-FLEET-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-PRIV — Privacy and data minimization

Required test environment: packet capture + logs/export fixtures.

### HCP-PRIV-01 — Prompts stay local

**Given:** Real local inference after hosted handoff. **When:** Capture all provider traffic. **Then:** No prompts, completions, KV or prefix-state identifiers in provider requests.

**Evidence:** evidence/HCP-PRIV-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-02 — Inventory off by default

**Given:** Local residency contains private models/hardware identifiers. **When:** Search and ensure using default reporting policy. **Then:** No full inventory/fingerprint exfiltration; coarse capability constraints only if approved.

**Evidence:** evidence/HCP-PRIV-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-03 — Private URL redaction

**Given:** Source origin includes bearer query credential. **When:** Generate package, receipt, logs and export. **Then:** Secret URL excluded/redacted; public hints contain no access capability.

**Evidence:** evidence/HCP-PRIV-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-04 — Tenant analytics

**Given:** Two tenants with low-volume distinctive capability requests. **When:** Produce analytics views. **Then:** No customer-identifying cross-tenant exposure; cohort policy or suppression applied.

**Evidence:** evidence/HCP-PRIV-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-05 — Required versus optional records

**Given:** Owner disables product analytics. **When:** Fund a permitted native action. **Then:** Optional analytics off; required financial records retained under declared policy without public broadcast.

**Evidence:** evidence/HCP-PRIV-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-06 — Read token in runtime

**Given:** Connector authenticated to CEX. **When:** Spawn local loader worker and inspect environment/FDs. **Then:** No provider/custody/cloud token inherited.

**Evidence:** evidence/HCP-PRIV-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-07 — Native-only acquisition

**Given:** Enrolled hosted metadata provider but model policy NATIVE_ONLY. **When:** Return external cloud URL as source hint. **Then:** External payload fetch denied unless separately approved; metadata permission not origin permission.

**Evidence:** evidence/HCP-PRIV-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PRIV-08 — No inference billing

**Given:** Model runs repeatedly after free or funded acquisition. **When:** Inspect exchange/network events. **Then:** No mandatory per-inference BTX debit or usage heartbeat introduced.

**Evidence:** evidence/HCP-PRIV-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-PORT — Portability, migration and exit

Required test environment: two independent test providers + client export.

### HCP-PORT-01 — Discovery switch

**Given:** Exact package/lock acquired using A. **When:** Export and import under B. **Then:** Identity preserved; new provider authentication explicit; no software trust migration.

**Evidence:** evidence/HCP-PORT-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-02 — Uncertain finance across providers

**Given:** A has BROADCAST_UNKNOWN intent. **When:** Switch discovery to B. **Then:** No automatic equivalent funding at B; unresolved A obligation remains visible.

**Evidence:** evidence/HCP-PORT-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-03 — Free use after exit

**Given:** Public assets and runtime lease local. **When:** Revoke CEX enrollment and disconnect network. **Then:** Local permitted use persists; no origin/issuer heartbeat dependency.

**Evidence:** evidence/HCP-PORT-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-04 — Custody exit statement

**Given:** Pending lots and refunds under custodial keys. **When:** Export customer state. **Then:** Native references, controller and conditions explicit; not falsely called self-custody.

**Evidence:** evidence/HCP-PORT-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-05 — Schema evolution

**Given:** HCP/1 client sees unknown critical profile capability. **When:** Attempt action. **Then:** Fail closed with version error; no unsafe downcast into generic RPC.

**Evidence:** evidence/HCP-PORT-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-06 — Migration interruption

**Given:** Local connector/account schema migration mid-write. **When:** Crash/restart using backed-up fixtures. **Then:** Atomic/restartable migration; enrollments and financial histories not silently dropped.

**Evidence:** evidence/HCP-PORT-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-07 — Independent SDK parity

**Given:** Python and TypeScript serializations of same intent. **When:** Hash and compare canonical signed body. **Then:** Identical body_id and decimal values; unsupported encodings rejected consistently.

**Evidence:** evidence/HCP-PORT-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-PORT-08 — No native core rewrite

**Given:** Hosted wrapper of existing Core v3 package. **When:** Remove wrapper and use native client. **Then:** Original native package and recipe remain exact and usable.

**Evidence:** evidence/HCP-PORT-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

## HCP-OPS — Isolation, release evidence and operations

Required test environment: isolated integration environment + operator runbooks.

### HCP-OPS-01 — Public bridge isolation

**Given:** Existing read-only explorer/browser bridge. **When:** Try all hosted finance method names and path variants. **Then:** Remains read-only; new API service is not a native wallet proxy.

**Evidence:** evidence/HCP-OPS-01/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-02 — Money-only regression

**Given:** WITH_MODELNET=OFF build and helper-kill fixture. **When:** Build/run monetary regression and stop model/capability helper. **Then:** Money unaffected; hosted model operations fail safely.

**Evidence:** evidence/HCP-OPS-02/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-03 — Replica fencing

**Given:** Two finance executors race ownership lease. **When:** Force lease expiry/network partition during submit. **Then:** Only fenced owner initiates new signing; reconciliation prevents replacement spend.

**Evidence:** evidence/HCP-OPS-03/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-04 — Scale within limits

**Given:** Configured concurrent SSE/search/intents beyond capacity. **When:** Load test with held-down native dependency. **Then:** Backpressure/rate limits, bounded memory and durable accepted intents; no false success.

**Evidence:** evidence/HCP-OPS-04/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-05 — No production side effects

**Given:** Live process/keys alongside isolated test prefix. **When:** Run conformance and recovery scripts. **Then:** No production binary replacement, wallet mutation or restart; record evidence paths.

**Evidence:** evidence/HCP-OPS-05/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-06 — Provider compromise drill

**Given:** Revoke operational control key during active account session. **When:** Recover with independently enrolled root. **Then:** New unsafe actions stop; native spending keys remain separate; historical receipts retain context.

**Evidence:** evidence/HCP-OPS-06/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-07 — Claimed profile evidence

**Given:** Backend flag is enabled but native signer or runtime test unavailable. **When:** Generate go-live manifest. **Then:** Profile support not reported proven; specific NOT_RUN/blocker exposed.

**Evidence:** evidence/HCP-OPS-07/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

### HCP-OPS-08 — Full audit closure

**Given:** All individual cases and J01–J12 have evidence rows. **When:** Independent reviewers reconcile final candidate. **Then:** PASS only for executed relevant tier; unresolved mandatory failures block advertised profile.

**Evidence:** evidence/HCP-OPS-08/ contains the exact candidate fingerprint, test command, observed before/after state, asserted failures and sanitized logs. A simulation can supplement, but cannot replace, the environment above. **Initial status: NOT_RUN.**

# Appendix B. Complete hosted operation map

All routes below use `/btx/hcp/v1`. Names are proposed HCP operations, not claims that public BTX exposes them. A finance action REFUND or CLAIM uses the same exact quote/intent flow, not a bypass endpoint.

| Method / route | Minimum scope | Effect / profile |
|---|---|---|
| GET `/profile` | public profile | READ / DISCOVERY |
| POST `/capabilities/search` | catalog:read | READ / DISCOVERY |
| GET `/packages/{package_core_id}` | packages:read | READ / DISCOVERY |
| GET `/economy/{target_id}` | catalog:read | READ / DISCOVERY |
| POST `/handoffs` | handoffs:create | PROPOSE_LOCAL / HANDOFF |
| GET `/handoffs/{handoff_id}` | handoffs:create | READ / HANDOFF |
| POST `/devices/enroll` | devices:enroll | PAIR / HANDOFF |
| POST `/devices/{device_id}/confirm` | devices:enroll | PAIR / HANDOFF |
| POST `/devices/{device_id}/revoke` | devices:enroll | REVOKE / HANDOFF |
| GET `/devices/{device_id}/handoffs` | events:read | READ / HANDOFF |
| POST `/devices/{device_id}/reports` | devices:report | REPORT / FLEET |
| GET `/treasury/balances` | account:read | READ / CUSTODY |
| POST `/finance/quotes` | quotes:create | PREPARE / FUNDING |
| POST `/finance/intents` | intents:create | PREPARE / FUNDING |
| GET `/finance/intents/{intent_id}` | account:read | READ / FUNDING |
| POST `/finance/intents/{intent_id}/authorize` | intents:authorize | AUTHORIZE / FUNDING |
| POST `/finance/intents/{intent_id}/submit` | intents:submit | SUBMIT / FUNDING |
| POST `/finance/intents/{intent_id}/cancel` | intents:cancel | CANCEL / FUNDING |
| GET `/finance/intents/{intent_id}/receipts` | account:read | READ / FUNDING |
| GET `/finance/receipts/{receipt_id}` | account:read | READ / FUNDING |
| POST `/policies` | policies:admin | POLICY / FUNDING |
| GET `/policies/{policy_id}` | account:read | READ / FUNDING |
| POST `/policies/{policy_id}/revoke` | policies:admin | REVOKE / FUNDING |
| POST `/subscriptions` | subscriptions:write | POLICY / FLEET |
| POST `/subscriptions/{subscription_id}/revoke` | subscriptions:write | REVOKE / FLEET |
| GET `/events` | events:read | READ / HANDOFF |
| GET `/events/stream` | events:read | READ / HANDOFF |
| POST `/exports` | exports:create | EXPORT / HANDOFF |
| GET `/exports/{export_id}` | exports:create | READ / HANDOFF |
| POST `/research/drafts` | research:publish | PREPARE / FUNDING |
| POST `/research/drafts/{draft_id}/validate` | research:publish | READ / FUNDING |
| POST `/research/drafts/{draft_id}/publish` | research:publish | PUBLISH / FUNDING |
| GET `/research/submissions/{submission_id}` | catalog:read | READ / DISCOVERY |
| GET `/operations/{operation_id}` | account:read | READ / HANDOFF |

# Appendix C. Default bounds and partner delivery contract

## C.1 Bounded operation defaults

Use these initial implementation limits unless a measured, versioned provider profile deliberately lowers or raises them: HCP JSON body 1 MiB; JSON depth 32; JSON nodes 65,536; catalogue page 100 items; handoff source hints 16; local candidate recipes 64 and dependency resources 256 under existing JIT rules; financial request idempotency keys 128 ASCII-safe characters; opaque cursors 2 KiB; event pages 100; long-poll wait at most 30 seconds. Bound parked clients through a shared pool rather than one unbounded thread per request.

An exact `.btx` binary response has the existing 4 MiB payload plus 68-byte framing ceiling, independent from the HCP JSON limit. Use streamed binary retrieval, not giant JSON-hex conversion. Validate digest and size before parser allocation. A peer's payload limit cannot raise the local runtime's resource grant.

Handoff default expiry is five minutes with a bounded, configurable clock-skew policy. It is delivery freshness, not a lease on public model use. Financial quote expiry comes from the quote/native commitments and can be shorter. Native refund conditions never derive from those API TTLs. Cursor/event and durable business-idempotency retention are different policies; financial history must survive the retry-cache TTL.

## C.2 State assertions are not proofs

The schema rejects CONFIRMED/SETTLED/REFUNDED receipts that lack the declared native observation fields or use only CEX_LEDGER evidence. This is an anti-confusion structural guard, not cryptographic validation of those claims. A malicious provider can still lie in correctly shaped signed fields; HOSTED_ATTESTED clients must show that trust model. Independent verification requires actual configured native evidence checking.

## C.3 Production partner deliverables

Deliver a tested adapter matrix for actual native methods, signing keys/scripts, coin/network identity, fee/refund policies, user-ledger mappings and conversion rails. Produce SDK conformance vectors from the final native canonical codec. Include a reference portal backed by the same gateway/API used by agents, plus approved deployment manifests, schema migrations, identity-provider setup, secrets inventory and recovery jobs.

Define financial executor ownership in persistent storage with fencing. The supplied reference simulator's process-local lock is insufficient for replicated production. Key-generation/signing backups, financial journals and native-output recovery metadata must be recoverable together. No passing JSON test substitutes for this integration.

<!-- SOURCE_REGISTER_APPEND -->

# Source register

Research reviewed 17 September 2026. Supplied BTX specifications establish design requirements, not native implementation proof. External sources establish only the facts attributed to them; the strategy and HCP design are this package’s analysis and proposals.

**[B01] BTX JIT Capability Development Spec, rev 1.0. Supplied file: `BTX_0348_JIT_Capability_Development_Spec.md`.** User-supplied design baseline; sections 1, 3–7, 21–27. Defines Core v3, local grants, three authority planes and no-account acquisition. Not executed code evidence.

**[B02] BTX Agent-readable Package Spec, rev 1.0. Supplied file: `BTX_0348_Agent_Readable_Package_Spec.md`.** User-supplied design baseline. BTXPKG1 framing, authorship/software/wallet distinctions. Core v2 is superseded by JIT Core v3 where allocated.

**[B03] BTX Expanded Implementation Spec. Supplied file: `BTX_0.34.8_Expanded_Implementation_Spec.md`.** User-supplied design baseline. Origin/storage, events, mandates, escrow and package responsibilities.

**[B04] BTX Model Bounties and Discovery Hardening. Supplied file: `BTX_0.34.7_Model_Bounties_and_Discovery_Hardening.md`.** User-supplied design baseline. Frozen rounds, per-contributor lots, council judgement, refund deadlines and no return-bearing security.

**[G01] [BTX public main ref](https://api.github.com/repos/btxchain/btx/git/ref/heads/main).** Read via GitHub connector: public main 42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b. Private 0.34.8 not independently audited in this assignment.

**[G02] [BTX web bridge boundary](https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/doc/modelnet/web-bridge-boundary.md).** Static inspection. Conventional HTTPS is a separately deployed compatibility edge. Native helper PQ1 remains separate; bridge is not wallet proxy.

**[G03] [BTX HTTP bridge implementation](https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/src/modelnet/http_bridge.cpp).** Inspected lines 1–240; blob 86199b1a512ccf923e28b5835cb47d150c0a70c6. BRIDGE_NOTE, PushDisclosure, WalletLikePath and read-RPC boundary. Not a full security audit.

**[G04] [BTX wallet funding interface](https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/src/wallet/model_funding.h).** Static inspection; blob 4bcc279cd27492ae9345312309ae8bd244c8c5dd. FrozenFundingQuote, MatchFrozenTemplate, CreateUnsignedFunding, SignFrozenFunding, ObserveReleaseFunding.

**[G05] [BTX bounty RPC bindings](https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/src/rpc/modelnet.cpp).** Search-located signbountyfunding; exact private call paths require execution-time audit.

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

