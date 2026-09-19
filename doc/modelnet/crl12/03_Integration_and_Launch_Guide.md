# Connect to the Cognitive Reserve Layer
## A neutral integration and launch guide
### BTX 0.34.8 · Framework v1.2

**Audience:** Product leaders, exchange and fintech engineers, custody operators, institutional service teams and new market entrants.  
**Edition:** 17 September 2026.

> Build the customer relationship. Connect your financial systems. Let the shared layer deliver cognitive capability.

# 1. The business you are launching

A Cognitive Reserve service gives customers a place to hold financial reserves, decide which capabilities to acquire, finance desired research and retain the resulting productive resources. It connects the balance sheet to the machine. The opportunity is to become a capital institution for an economy in which software increasingly chooses and assembles its own capabilities.

BTX supplies the shared money and capability infrastructure. HCP/1 supplies hosted discovery, finance and handoff. The v1.1 framework supplies reserve policies, portfolios, capital plans, committee approvals and research programmes. The v1.2 layer makes those services independently composable and adds institutional records and whole-portfolio integration.

A partner does not need to be an established exchange. It may offer a complete venue, custody, treasury, discovery, asset servicing, analytics or a local deployment interface. Each implements the relevant role contract. Customers can combine several providers without changing the identity of their money or model resources.

The strongest commercial proposition is not another paid API endpoint. It is a lasting reserve and capital-allocation relationship. Customer assets, executed orders, governed funding and institutional services generate revenue. Portable capability makes that relationship useful even when no token or inference payment occurs during a particular task.

# 2. Choose services, not a branded profile

Start with the services your organization can operate. Advertise only the associated registered operations and evidence. No provider name is privileged, and no generic role assumes an institution's licenses or customer authority.

| Launch model | Roles to implement or source | Customer result |
|---|---|---|
| Full-service reserve venue | Treasury, custody, execution, funding, discovery, handoff | One financial interface to acquire and finance capability |
| Institutional custodian | Custody and asset servicing | Safekeeping, attributable balances and recovery |
| Business treasury platform | Treasury, analytics and handoff; approved custody/execution partners | Company budgets become capability portfolios |
| Portfolio technology provider | Asset servicing and portfolio analytics | Cognitive exposure in a whole-portfolio workflow |
| Capability gateway | Discovery and device handoff | Easy verified local acquisition |
| New specialist venue | Chosen customer UX plus independently bound services | A focused business without rebuilding every layer |

A role manifest binds exact provider identity, endpoint origins, supported networks and conformance evidence. A customer service binding names the legal entity, role, provider and permitted effects. A discovery connection cannot inherit custody authority. A portfolio analytics connection cannot authorize money because it can display a balance.

# 3. Customer propositions

## Corporations and operating businesses

Lead with a recurring workload. The technical owner defines accepted output, privacy requirements and eligible runtimes. The finance owner reviews total cost, reserve impact and future commitments. BTX resolves reuse, acquisition, composition or research funding into exact capability and capital plans. The customer's own machines acquire and run the resources.

Keep subsidiary money separate. Group visibility does not permit the parent, adviser or agent to debit every subsidiary. A one-screen approval packet can collect the correct financial and local permissions without collapsing their authorities.

## Institutions and family offices

Offer a reserve mandate, custody and liquidity relationship, independent research allocations and factual reporting. Family groups can view several entities together while retaining separate personal, trust, foundation and company books. Advisers draft; authorized principals approve. A family relationship never substitutes for an accepted financial mandate.

## Asset managers and portfolio platforms

Represent actual BTX positions and approved financial instruments in the investment book. Represent research commitments and capability resources with their own rights and measurement bases. Connect operational capability to the portfolio as a dependency and productive resource, not as a fabricated tradable security. The whole-portfolio guide provides the mapping and reconciliation model.

# 4. Deployment architecture

The hosted gateway attaches to existing identity, eligibility, ledger, quote, custody, chain observation and reporting interfaces. Native BTX model services supply signed packages and verified resources. The owner-local capability service performs source selection, materialization and runtime preparation.

```text
Customer browser or agent
    → Your hosted interface and identity
        → Reserve policies, portfolios and capital plans
        → Existing financial execution and custody
        → Signed package and capability handoff

Customer-local BTX
    → Independent package and resource verification
    → Local storage, LAN and eligible native peers
    → Memory/residency management and local runtime

Institutional portfolio system
    ↔ Attributed positions, rights and valuation observations
    ↔ Snapshot projections and governed draft instructions
```

The gateway carries metadata and capital workflow. It is not required to proxy model weights or customer prompts. A local client can remain walletless while the customer uses hosted finance. It can also use independent self-custody. Those choices do not change model identity.

# 5. Implement the common adapters

Reuse your production systems rather than importing the reference simulator as a financial core. Map each adapter's timeout, version, idempotency and unknown-outcome semantics before exposing a customer action.

| Adapter | Required integration | Acceptance question |
|---|---|---|
| Identity and eligibility | Legal account, actor, roles and permitted products | Can another tenant or adviser gain an unintended effect? |
| Ledger | Actual available/held funds and durable journals | Are holds and native commitments counted once? |
| Quote and execution | Firm/indicative quotes and existing venue orders | What survives a timeout after execution? |
| Custody and native economy | Exact BTX templates, signing, claim and refund | Can the actual signer perform and recover every advertised native path? |
| Package and local handoff | Exact Core v3 package and paired-device delivery | Can the client verify and choose a local source independently? |
| Asset/position/valuation | Attributed institutional observations | Are source identity, dates and basis preserved? |
| Mandate and projection | Accepted management/custody roles and snapshot view | Does every total have the right scope and source coverage? |

A generic send-coin connector is not sufficient for funded release and bounty transactions. Use the native committed terms and transaction validation. A generic position CSV is also not sufficient for institutional aggregation unless ownership scope, source identity and valuation basis are preserved.

# 6. A repeatable onboarding sequence

First, configure the institution's enrolled origin and role keys. Second, publish HCP, v1.1 and v1.2 schema and operation digests. Third, connect the selected financial and data adapters. Fourth, create a generic provider-role manifest from registered capabilities. Fifth, run the role-specific conformance suite and publish the resulting scoped evidence. Sixth, onboard a customer through the standard role-binding flow.

The first demonstration should not depend on private brand-specific code. Use two independently configured providers, an external portfolio-system fixture and a clean local client. Replacing either provider must not require recompiling protocol logic.

A production partner configuration contains origins, secret references, accepted networks, role manifests, mappings, quotas and support evidence. It does not contain public wallet keys, arbitrary native RPC method forwarding, hardcoded privileged institutions or public model metadata masquerading as authorization.

# 7. The easiest acquisition journey

The customer starts with a capability or workload, not a wallet address. The hosted interface returns compatible exact package candidates. The local planner determines what is already resident, what can be reused and where missing bytes can be found. A finite owner policy covers the ordinary acquisition and preparation journey.

The main action says “Prepare capability.” Its detail shows selected implementation, new bytes required, expected readiness, source policy and ongoing local resource requirement. A free public acquisition does not trigger currency conversion or a reserve debit. An already-ready capability is presented as ready only under a current local lease.

When money is required, the same journey shows a separate capital packet: payer, reserve policy, maximum principal and fees, native terms, refund responsibility and selected outcome. The finance and local preparation timelines stay distinct.

# 8. The reserve relationship

Reserve policies protect capital for future capability decisions. Existing v1.1 accounting remains unchanged: spendable capacity is the smaller of funds above the protected reserve floor and remaining authority. Pending deposits, expected research outputs and operational model holdings cannot expand that capacity.

Customers can start with suggestions and later approve finite replenishment rules. Automatic conversion requires explicit source assets, price freshness, slippage, turnover, order and exposure limits. A completed conversion followed by failed funding leaves BTX in the account; it does not authorize an automatic reversal.

Asset-gathering reporting should distinguish new external money from reallocations inside your platform. For example, a $1 billion reserve programme funded with $700 million already at the venue and $300 million of external deposits adds $300 million of new platform assets, not $1 billion. All $1 billion may contribute to the programme relationship, subject to actual custody and fee arrangements.

# 9. Funding productive supply

The Build area supports creation and release programmes. A customer identifies a missing capability and defines measurable outputs. The existing bounty or release mechanism supplies terms, funding, evaluation and recovery. The institution supplies a clear decision interface and accountable capital administration.

Co-funding remains a programme view over independent participant commitments. Each legal entity authorizes its own native lot and refund controller. A programme does not create a pooled investment token or additional rights by displaying an aggregate progress bar.

An awarded model becomes an acquired capability only after exact package, rights and local verification. The workflow should make that productive outcome visible alongside financial settlement.

# 10. Connect institutional portfolio systems

Expose asset master, position observations, rights, valuation and exposure records through the neutral interfaces. Consumers can use a signed JSONL export, a mapped CSV view, APIs or a desktop context. The institutional platform chooses its own approved mapping and source hierarchy.

Read integration is independent from execution. A portfolio system may propose a reserve allocation or research commitment. Translation produces normal v1.1 drafts. Existing committee, reserve, quote and custody checks decide whether the capital is deployed.

A platform that processes client assets does not thereby manage them. Management, custody and administration are separate roles and metrics. This separation increases the credibility of the integration with investment committees and financial reporting teams.

# 11. Interface and agent tools

Use six primary destinations: Overview, Reserves, Capabilities, Build, Approvals and Activity. Keep entity and portfolio visible. Put Connections and Data Definitions in settings or the institutional workspace. Do not force ordinary users to select protocol versions or parse native RPCs.

Use the same operation catalogue for portal, mobile and agent SDKs. Tools for reading a portfolio, comparing alternatives or preparing a draft do not carry execution authority. A local tool performs ensure/status/release through the existing owner-local service. An external agent receives scoped tokens for each intended audience, not a master exchange credential.

The user should see simple, accurate messages: “Capability ready,” “Awaiting capital approval,” “Funds committed; release pending,” “Source statement missing,” or “Outcome under reconciliation.” A single generic failure must not cause an agent to repeat an uncertain financial action.

# 12. Commercial instrumentation

Track assets by their actual definition: managed assets, custodied assets, administered assets and platform balances. Track new external flows separately from internal product allocations and market-price changes. Track executed notional and realized fees separately from deposits and commitments.

The customer outcome scorecard records actual capability preparation, approved coarse deployment success, recurring accepted work and observed costs. Forecast savings and measured savings stay separate. This lets the institution show how capital relates to useful cognition without fabricating investment performance from a model benchmark.

Fee products remain your contracts: custody, execution, administration, analytics and service support. BTX public acquisition and local execution do not acquire a compulsory per-token toll.

# 13. Launch and operations

Use four gates: neutral sandbox; real local capability handoff; native financial recovery; institutional projection and draft round trip. A specialist can launch its supported role after its gate passes. A full-service venue must demonstrate all the roles it advertises.

On outage, preserve existing local capability and original-provider financial reconciliation. On stale data, display incomplete coverage. On source correction, append new evidence and regenerate projections. On key compromise, revoke new effects through the enrolled root while retaining historical records. On customer exit, export portable facts and retain responsibility for unresolved custody and native outcomes.

The launch packet includes role manifests, schema and operation digests, exact adapter map, keys and rotation procedures, customer authority, native signing support, data policy, supported metrics, conformance evidence, recovery results and service limits. No institution's name is required in BTX's production decision logic.

**The integration becomes repeatable when providers agree on roles, evidence and handoff—not when every provider copies the same business model.**
