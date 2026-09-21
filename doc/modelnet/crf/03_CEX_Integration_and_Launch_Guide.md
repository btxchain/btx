# Build the Cognitive Reserve Exchange
## CEX integration and launch guide

**BTX 0.34.8 · Framework v1.1 · September 2026**

> One capital relationship. Open cognitive supply. Local productive capability.

# 1. The business you are integrating

The Cognitive Reserve business connects financial reserves to reusable machine capability. Customers hold BTX, allocate funds to capabilities and research, retain the resulting resources and deploy them on their own infrastructure. The exchange provides familiar accounts, custody, liquidity, approvals and reporting. BTX provides exact capability packages, distributed supply and the local preparation path.

This is not an API-billing feature. It is a capital desk for corporations, institutions, family offices and agents. Your existing financial platform remains the system of record for legal accounts and custody. HCP/1 supplies common hosted contracts; the Cognitive Reserve v1.1 extension adds portfolios, reserve policies, capital plans, committees, holdings and programmes.

The customer sees three separate things: financial capital available for future decisions, commitments already made, and cognitive capability already acquired. That structure makes a reserve relationship understandable and operational.

# 2. Customer propositions

## Corporate

Start with a recurring workload. Compare continued service expenditure with reuse, local acquisition or commissioned capability. Give the CFO an exposure and reserve-impact view; give the technical owner exact requirements and a device-readiness view. Keep subsidiary funds separate while allowing group oversight.

## Institutional

Provide an explicit BTX reserve mandate, custody and execution policies, bounded capital programmes, reportable commitments and recovery. Use your existing prime/OTC/credit services through their actual product controls. Capability finance is an additional purpose for the institutional relationship, not a substitute for asset servicing.

## Family office

Combine group visibility with separate company, trust, foundation and personal portfolios. Let advisers draft and principals approve. Connect strategic BTX reserves to portfolio-company AI adoption and separately authorized research sponsorship. Never infer transfer authority from a family relationship.

# 3. Six screens, one operating model

| Screen | Primary question | Primary action |
|---|---|---|
| Overview | What capital and capability do we have? | Start a capital plan |
| Reserves | How much can this entity allocate? | Propose reserve policy or replenishment |
| Capabilities | What can we use, acquire or replace? | Prepare a selected capability |
| Build | What capability should the market create? | Draft a research or release programme |
| Approvals | What exact decision needs authority? | Review the immutable packet |
| Activity | What happened to money and deployment? | Inspect or reconcile the existing outcome |

Entity and portfolio remain visible throughout. A family-group overview does not silently choose the payer. Users can start from a capability, workload, reserve mandate or research objective and still arrive at the same plan and approval framework.

# 4. Architecture

```text
Customer browser / agent
    → CEX identity and hosted API
        → entity, portfolio and reserve services
        → capability discovery and capital planning
        → approval committee and finite account policy
        → existing financial executor
            → venue conversion / custody / native BTX settlement

Customer-local connector
    → package verification and local policy
    → local/LAN/native peer acquisition
    → residency and runtime preparation
    → generation-bound capability readiness
```

The exchange is the control and financial interface. The customer's client remains the verification and realization boundary. Model weights do not have to transit your API servers. Your portal can coordinate a fleet while the local planner chooses the fastest eligible path.

# 5. Partner onboarding

First, assign accountable owners for product, legal-entity identity, custody, ledger, security, local integration and customer operations. Second, map existing HCP base operations to your actual native interfaces. Third, advertise the Cognitive Reserve extension and its schema/operation digests under your enrolled provider profile. Fourth, connect the new portfolio and planning services. Fifth, run the complete customer journeys with two providers and a walletless local client.

The extension is additive. Keep the existing `/btx/hcp/v1` base and original signed objects. Fetch extension discovery from `/btx/hcp/v1/extensions/cognitive-reserve`. New signed objects have explicit `V1_1` types; account-specific data does not belong inside portable `.btx` cores.

Deploy DISCOVERY and HANDOFF for public acquisition, CUSTODY and FUNDING for native financial activity, and the advertised reserve/committee/programme features for institutional use. Enable an advertised profile only with its corresponding production call paths and evidence.

# 6. Connect identity and legal ownership

Map the CEX's tenant, legal entity, account and portfolio identifiers. Map human person identity separately from sessions, API keys and agent principals. Support group visibility with EntityLink, but retain explicit payer approval at the legal-entity boundary.

For institutional committees, map current eligible roles and revocation. A person logged into two devices is one committee member. SCIM/group changes update future eligibility without rewriting historical evidence. An adviser can be a drafter without financial approval power.

Confidential institutional clients use the supported FAPI/OAuth profile; public desktop connectors use the supported public-client flow. Sender-constrained tokens and exact intent digests protect different aspects of authorization. Do not forward exchange tokens into model or runtime workers. [T01–T04, T09]

# 7. Reuse your financial core

| Adapter | Supply from the exchange | BTX boundary |
|---|---|---|
| Identity/eligibility | Legal account, actor, scopes and approved products | Object-level authorization |
| Ledger | Available/held balances, journal and fenced reservations | Exact customer-to-native attribution |
| Quote | Firm or indicative conversion/execution offers | Explicit separate conversion leg |
| Custody | Native supported keys, templates and signer operation lookup | Independent final transaction validation |
| Chain observer | Native outpoint, transaction and confirmation state | Receipts retain observation basis |
| Native economy | Frozen release/bounty terms and recovery interfaces | No generic send-coin approximation |
| Audit/reporting | Append-only history and scoped export | No invented readiness or ownership |

Add entity, reserve, approval, holdings, programme and product-catalogue adapters where equivalent services already exist. Implement transactional behavior in your production persistence tier; the included simulator is an integration aid, not your financial system.

# 8. Establish the reserve policy

A portfolio's allocation capacity is the smaller of spendable funds above its protected floor and remaining authorized capacity. Ledger AVAILABLE must already exclude existing holds and collateral. Do not subtract those again or include expected refunds before they are returned.

```text
available after existing holds       1,000 BTX
protected reserve                     400 BTX
remaining approved capacity           250 BTX
new allocation capacity               250 BTX
```

The product offers policies for strategic reserve, current capability deployment and research. Purpose labels do not change ownership. SUGGEST replenishment is the default. AUTO requires explicit source assets, bands, cooldown, order cap, lifetime turnover, quote freshness and execution authority.

Use the exchange's ordinary deposit, withdrawal and trading rails. A reserve plan links to those operations; it does not fabricate a native bounty term for a currency trade. Conversion success followed by funding failure leaves the BTX in the account until the customer or a prior finite rule authorizes another action.

# 9. Build the workload-to-capital journey

Ask the customer for the outcome, accepted-task definition, quality minimum, annual demand, horizon and data boundary. Obtain an owner-approved local feasibility summary. Compare available implementations and include all costs required to deliver equivalent accepted work.

The customer can choose reuse, public acquisition, a compatible adapter, supported licensed access, release funding, research commissioning or continued external service. Show unknown inputs as missing, not free. Explain the selected route using task evidence, total cost, readiness and resource constraints.

Preserve exact IDs from comparison to plan. A channel update, different model or changed adapter scale creates a new implementation and requires the appropriate re-evaluation. The CEX does not know current local memory merely because a customer once registered a GPU model.

# 10. One decision packet

The packet shows legal payer, portfolio, objective, chosen implementation, source of evidence, maximum financial debit, conversion terms, native commitment/refund conditions, expected local effects and projected ongoing costs. It includes current reserve impact and the identities required to approve.

The UI can collect two approvals in one coherent interaction: financial approval by the authorized payer and local execution consent by the device owner or organization policy. They remain separately stored and validated. A financial committee cannot appoint a model author as a trusted software distributor.

After plan, policy, recipient, quote or committee changes, invalidate mismatched approval records. Distinct-person quorum and initiator exclusion apply across sessions and keys. Final execution rechecks current authority; an old green badge is not sufficient.

# 11. Execute, reconcile and deploy

Allocation legs reuse the existing HCP financial saga. Persist the exact child intent, business ID, authorization and signed native bytes. A timeout can mean that a trade, signature or broadcast occurred. Preserve uncertainty and reconcile; never create another spend to make the interface appear responsive.

The local handoff carries exact package and recipe references. The device verifies them, intersects the local plan with its grant and calls the normal capability service. A resident base plus LAN adapter should win over unnecessary internet acquisition when it satisfies the plan.

Activity shows two timelines. Financial state can be committed while a release remains undisclosed. A runtime can be ready while an unrelated research commitment is still open. “Ready” comes from the local readiness contract, not the CEX's payment status.

# 12. Operate a research capital desk

A ResearchProgram states a capability objective, evidence requirements, eligible native terms and sponsor limits. It can coordinate multiple independent customers without consolidating their keys or replacing native escrow. Each sponsor authorizes its own contribution and retains its own recorded refund responsibility.

Suppliers browse objectives, submit under native rules and receive proceeds through actual settlement. A successful output is independently imported as a capability package. The exchange can support technical due diligence and administration without claiming unilateral scientific authority.

Public-good sponsorship, commercial acquisition and investment exposure have different rights. Keep the actual instrument and contract visible. A programme progress bar does not create an ownership interest or future revenue claim.

# 13. Retain a cognitive portfolio

After acquisition, record the exact recipe, rights reference, actual cost allocation and deployment state. A base shared by several recipes is counted once under the selected allocation method. A public free model can be operationally valuable without a fabricated cash valuation.

A customer can retain, replace, update or retire the holding. Local runtime leases remain generation-bound. A provider session ending does not erase public model files. Export packages, locks and factual holding records so another provider or native client can continue the workflow.

# 14. Connect partner financial products

Expose relevant existing custody, OTC, credit, hedging, equipment-finance and research-administration offers under the customer's eligibility. A product card names the actual provider, rights, costs, term and action. A referral is clearly a referral; accepted application, executed contract and realized fee are later separate events.

When a product encumbers BTX, update the authoritative available balance before capability allocation. Reuse the exchange's actual execution and collateral controls. Do not add generic derivatives or pooled investment issuance to BTX merely because the product shelf can describe an opportunity.

# 15. Report to boards and investment committees

A corporate packet joins workload comparison, approved capital, deployment outcome and the updated reserve position. An institutional packet includes mandate compliance, execution, custody, commitments and recovery. A family-office packet offers group visibility with legal-entity subtotals and adviser access clearly bounded.

Export compatible cost data using the version-pinned FOCUS mapping. Preserve original invoice IDs, periods and currencies. Distinguish forecasts, actual spend and observed savings. Let accounting systems classify factual payments according to the customer's applicable policy rather than assigning every cognitive expenditure one accounting treatment. [T06, T08]

Never add model sizes, future research success or downloaded-copy counts to financial reserve NAV. Keep financial and productive scorecards adjacent, not arithmetically merged.

# 16. Customer experience requirements

Make every ordinary journey possible without terminal navigation. Use progressive disclosure, persistent entity selection and a clear primary action. Product labels say “Reserve policy,” “Capital plan” and “Capability ready”; chain and cryptographic details remain available in the exact evidence view.

Support keyboard-only use, screen readers, visible focus, accessible status updates and WCAG 2.2 AA. Amounts include currency and unit; Japanese and other localized layouts must not reinterpret native decimal strings. Use the same typed SDK for browser, mobile and agents.

A normal user should not approve every packet or tensor. One finite grant covers a defined acquisition/runtime journey. A recurring financial programme uses a distinct finite account policy. Neither is an unlimited permission disguised as convenience.

# 17. Launch and operating packet

Run the base HCP suite and the new reserve suite, followed by the 20 whole-system journeys. At minimum demonstrate a real native funding/refund lifecycle, family/entity isolation, simultaneous reserve requests, changed-approval rejection, unknown broadcast recovery, local capability after gateway outage and a second-provider handoff.

The partner packet includes schema digests, exact operation mapping, custody support, identity profile, approval policy, privacy inventory, fees, statement examples, SLOs, recovery drills and customer exit instructions. A second exchange should implement adapters and conformance, not a separate BTX fork.

Operational ownership includes signer ambiguity, reorganization, stale prices, key compromise, committee revocation and device failure. Disable new effects when needed while preserving accepted financial obligations and local lease safety. Service availability is not permission to weaken transaction or model verification.

# 18. Commercial launch

Sell the product through three anchor offers: a corporate ownership plan, an institutional reserve mandate and a family-office group programme. Bring one concrete workload and one supplier objective to the first demonstration. Show the financial reserve, the governed capital decision and the resulting usable capability in one workspace.

The recurring relationship is custody, liquidity, treasury and capital formation. The portal and SDK make that relationship easy. The customer retains the cognitive asset and the choice of future provider.

**Integrate once. Become the capital interface for machine capability.**


# Research references

**[T01] OpenID Foundation — FAPI 2.0 Security Profile.** [Primary source](https://openid.net/specs/fapi-security-profile-2_0-final.html).

**[T02] IETF RFC 9396 — OAuth Rich Authorization Requests.** [Primary source](https://www.rfc-editor.org/rfc/rfc9396.html).

**[T03] IETF RFC 9449 — DPoP.** [Primary source](https://www.rfc-editor.org/rfc/rfc9449.html).

**[T04] IETF RFC 9700 — OAuth security best current practice.** [Primary source](https://www.rfc-editor.org/rfc/rfc9700.html).

**[T06] FinOps Foundation — FOCUS 1.3.** [Primary source](https://focus.finops.org/docs/specification/v1-3/).

**[T08] IFRS — IAS 38 Intangible Assets.** [Primary source](https://www.ifrs.org/issued-standards/list-of-standards/ias-38-intangible-assets/).

**[T09] IETF RFC 7644 — SCIM protocol.** [Primary source](https://www.rfc-editor.org/rfc/rfc7644.html).

