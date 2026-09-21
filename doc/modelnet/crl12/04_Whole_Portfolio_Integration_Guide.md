# Cognitive Capital in the Whole Portfolio
## An institutional data, risk and workflow integration guide
### BTX Cognitive Reserve Layer v1.2

**Audience:** Asset managers, investment-platform operators, asset servicers, custodians, CIO offices and institutional integration teams.  
**Edition:** 17 September 2026.

> Bring machine reserves and productive capability into the same decision environment as the rest of the portfolio—without confusing what is money, what is a right and what is useful technology.

# 1. The new institutional opportunity

An investment institution can participate in the Cognitive Reserve economy in two ways. It can serve clients holding BTX or actual related financial instruments under investment mandates. It can also help institutions organize the cognitive assets and research commitments that support their own operations and portfolio companies.

These businesses reinforce each other. A client can hold a financial reserve for future capability, govern a research allocation and see the productive result on its own systems. A portfolio platform can connect these facts to treasury, investment, operations and risk views. The technology relationship expands from reporting existing assets to supporting a new category of productive capital decisions.

Current whole-portfolio platforms already combine public and private holdings, an investment book, exposure, performance and operational workflows. Public platform descriptions also show API and data-cloud integration as a practical route to adding external data and services. BTX v1.2 uses that pattern through neutral interfaces; the institution maps them to its licensed portfolio system. [M13–M15]

# 2. Four books, one customer view

The integration joins four books without pretending they are one ledger.

**Financial positions.** Actual quantities of BTX, fiat and properly constituted financial instruments, with beneficial account, custodian, mandate and market-value evidence.

**Capital commitments.** Native release and bounty commitments, refunds and other actual contractual obligations. Their status derives from original terms, custody records and native observations.

**Cognitive holdings.** Exact models, adapters, recipes and use rights; cost allocations and supported deployment records. A useful public model may have no market price.

**Operational dependencies.** Runtime, source, local readiness and other approved coarse dependencies. These describe how productive capability can be materialized, not additional financial positions.

The interface links these books by immutable references and scopes. A research commitment can point to a later acquired capability. A fund instrument can have financial look-through holdings. A capability can depend on a model and runtime. Only the appropriate edges participate in each metric.

# 3. Asset-master mapping

The institution's asset master remains its accepted classification system. BTX records provide exact identifiers and attributable facts. The adapter maps rather than invents financial rights.

| Source object | Institutional representation | Important mapping rule |
|---|---|---|
| Native BTX balance | Native digital-asset position | Network and quantity unit are explicit |
| Existing financial product | Instrument record with accepted external identifier | Rights come from the actual instrument |
| Model or adapter | Capability-resource record | Content identity is not a security identifier |
| License or claim | Contract-right record | Transferability and holder are explicit |
| Release/bounty lot | Commitment record | Do not double count against a deducted cash balance |
| Local preparation receipt | Operational observation | Expiring state, not ownership or valuation |

Identifiers use namespace plus value plus authority. A public legal identifier can help match the institution's entity directory, but acceptance still requires its identity and mandate controls. Corporate parent data is not a customer instruction or beneficial-title proof. [T07]

# 4. Position ingestion and source hierarchy

A position row identifies owner entity, account/portfolio, asset, economic position key, custodian reference, exact quantity, source authority, effective time, recorded time and source sequence. The same position arriving from two connected systems is corroboration or a reconciliation problem—not automatically two positions.

Define an accepted source hierarchy per metric. For a custody report, the custody statement may be authoritative. For managed-asset reporting, the institution may require its investment book plus a current management mandate. A ledger or chain observer can corroborate quantities without authorizing a change to the reporting policy.

A batch importer validates the entire bounded batch before advancing its watermark. Replay is safe, conflicting sequence reuse is quarantined, and missing source data creates a visible coverage break. Customer reports can then answer both “What applies at this date?” and “What did we know when we produced the report?”

# 5. Historical reproducibility

Use two cutoffs: effective as-of and observation cutoff. Suppose a custodian's position effective at month end is corrected two days later. The original month-end report remains reproducible using its earlier observation cutoff. A corrected report uses the later cutoff and points to the superseding evidence.

This matters for market-price corrections, late custody statements, reorganized native transactions, new rights evidence and portfolio mandate changes. Do not mutate signed history. Every revised projection states the source watermark vector and metric-policy versions used.

A current view may become partial after a source outage. The system should distinguish a known zero holding from an unavailable source that may hold assets. A missing price is not a zero-valued asset.

# 6. AUM, custody and platform assets

The portfolio integration supports familiar institutional measures by making their definitions explicit.

**AUM** requires an actual management mandate and eligible holdings. **AUC** follows a custody relationship. **AUA** follows an administration relationship. **Platform assets** follows the provider's defined customer-asset measure. **Technology coverage** describes assets processed by software; it is not automatically any of the preceding measures.

A $100 million customer portfolio may be managed by one institution, custodied by another and reported by a third. Each can accurately describe its role. Adding the three measures to claim $300 million of underlying economic assets would be wrong. The shared layer carries sufficient scope and identity to prevent that error.

The commercial growth bridge is equally important. A new $5 billion strategy containing $3 billion reallocated from the manager's existing products and $2 billion of external inflows has $5 billion of product assets but adds $2 billion of firmwide net new assets before performance and other flows. The strategy's fee base may follow its actual average assets; that is separate from the net-new-asset measure.

![Figure 3. Product assets and new firm assets are different measures.](../assets/asset_growth_bridge.png)

*Illustrative asset-growth bridge. Figures are scenario assumptions, not an actual product or allocation.*

# 7. Direct and look-through exposures

A direct book might hold a share in a real fund whose underlying assets include BTX. A direct NAV report values the fund share. A look-through exposure view replaces the parent position with proportional underlying exposure; it does not add both.

Use a frozen mapping with position ownership and accepted weights. Missing look-through coverage remains residual exposure. Leverage, short positions and derivative representations require the external instrument's actual model and policy; the core reference implementation does not invent them from a fund label.

Operational capability dependencies belong to a different graph. A model used by five portfolio companies can be one common dependency, but that does not mean each company has an equal financial ownership share in the model. Typed edges keep those relationships meaningful.

# 8. Valuation discipline that enables a credible asset class

Native reserve assets and actual financial instruments can use accepted market-value sources. Contract rights may use an approved accounting policy and evidence. Cognitive resources can use actual cost, deployment counts and utility evidence. These measures sit beside each other rather than being blended into one artificial NAV.

An asset class becomes institutionally useful when identifiers, rights, valuation, custody, liquidity and reporting are clear. Calling a model an asset does not remove that work. BTX supplies exact digital resource identities and native capital-workflow references, which make the institutional mapping more rigorous.

The product can therefore track a new cognitive-capital domain immediately: liquid reserves, genuine investment instruments where issued, commitments to create supply and productive capability holdings. Formal financial treatment follows the actual rights and institution's accepted policies. This is a classification requirement, not a limitation on the size of the opportunity. [T08]

# 9. Worked record set

Consider a hypothetical institutional client with the following records. Values are illustrative and the exact units and dates belong in the exported data.

| Record | Measurement | Treatment |
|---|---|---|
| Direct BTX reserve | 10,000 units; accepted value $1,000,000 | Eligible financial position under the relevant role |
| Same reserve in a second feed | Corroborating custody reference | Reconcile; do not add another $1,000,000 |
| Research commitment | $100,000 equivalent, already removed from available funds | Show separately with native terms and valuation policy |
| Public coding capability | One exact recipe; 20 device deployments | One cognitive holding, 20 deployments; no market value invented |
| Licensed capability | $40,000 actual acquisition cost | Contract-right/cost view; not automatically liquid NAV |
| Existing fund interest | $500,000 direct value | Include direct value or authorized look-through, not both |

The customer can see financial reserve, committed capital and productive capability in one workspace. The investment platform can analyze native-asset and fund exposure while the operating team sees readiness and supplier dependence. The management company's own AUM includes only positions actually covered by its mandate.

# 10. From portfolio insight to capital allocation

A portfolio analyst notices that several operating units depend on recurring external cognition. The analyst opens the approved workload view, compares local acquisition and research alternatives, and creates a capital proposal. The portfolio system transmits a signed, scoped PortfolioInstruction into BTX's hosted layer.

The instruction is translated into an existing v1.1 draft. Treasury and investment committee approvals bind the exact exposure, payer, terms and reserve policy. The original HCP executor performs the authorized financial legs. A local handoff prepares the capability on the selected devices.

The closed loop returns financial receipts, commitment changes and permitted coarse capability outcome. It does not expose prompts or make the institutional system a remote inference controller.

```text
Portfolio insight
    → Capital proposal
    → Existing reserve and committee approval
    → Existing financial execution
    → Verified capability handoff
    → Local productive capability
    → Attributed portfolio and outcome records
```

# 11. Technical integration patterns

## API and event integration

Use role-scoped HCP/CRL operations for exact records, projections, exports and draft preparation. Event cursors retain provider, tenant, stream generation and sequence. Consumers deduplicate, detect retention gaps and request an accepted snapshot. No globally authoritative event order is implied.

## Data warehouse and batch integration

A JSONL export preserves exact signed objects and typed projection data. A signed manifest fixes chunk hashes, row counts, source snapshot and mapping version. CSV is a compatibility view with explicit schema, exact decimals and formula-safe presentation. Imports stage, validate and commit into a read model; they do not mutate custody balances.

## Desktop context

An application-defined desktop context can open the matching portfolio, asset or capability view. It carries exact references and purpose, not authentication secrets. An analyst selecting a position does not authorize a capital allocation. Draft preparation and financial approval remain separate actions. [T05, T06]

## Proprietary-system adapter

The institution implements the final mapping against its licensed portfolio APIs and data model. The common repository contains a generic adapter contract and test system. It does not encode vendor names, guess private endpoints or claim certification by a particular platform.

# 12. Operational and financial scenarios

The default scenario engine applies explicit deterministic shocks. A BTX price change affects eligible financial positions. An FX shock affects translated values. A service outage affects new hosted access. A capability retirement affects selected operational dependencies. A load-delay shock affects expected preparation time.

Keep these channels separate. An outage at a discovery provider does not destroy a model already acquired locally. A higher capability benchmark does not automatically increase the native asset's price. A model retirement can create a replacement need without creating a realized investment loss on an unrelated financial position.

External institutional systems can apply their own richer analytics to the exported data. The useful BTX contribution is reliable identity, rights, timing, quantity and dependency facts—not an unverified statistical risk model.

# 13. Client value and commercial expansion

For asset owners, the integration adds visibility over machine reserves and a governed route to expanding productive capability. For asset managers, it supports actual new mandates and capital programmes alongside their existing portfolios. For technology providers, it adds data coverage and a workflow domain valued by customers already using their operating platform.

Revenue can come from actual managed assets, custody, execution, administration and technology contracts. These are different fee bases. A technology customer importing a $10 billion book does not create $10 billion of the software supplier's managed assets. Keeping the definitions clean makes the opportunity more investable and easier to explain.

The most compelling client demonstration starts with a real decision: retain a recurring service, acquire an existing capability, or fund an improved one. The platform shows capital, evidence, approval and deployment together. That is an extension of the institution's decision system, not another disconnected model catalogue.

# 14. Conformance and operating ownership

Assign owners for identity/mandates, custody reconciliation, pricing, corporate actions or instrument updates, operational capability evidence, data privacy and adapter recovery. The test programme must show duplicate-source handling, historical correction, missing prices, correct AUM/AUC definitions, direct/look-through exclusion, safe import, draft-only instructions and provider exit.

The acceptance packet includes field mappings, source hierarchy, metric definitions, temporal policy, rights evidence, sample statements, failure handling, data retention and exact conformance results. A proprietary-platform integration adds that platform's own acceptance and contractual requirements; a generic BTX conformance test does not impersonate them.

**The whole-portfolio opportunity is to make cognitive capital legible, governable and actionable alongside financial capital—while preserving the distinctions that make institutional reporting trustworthy.**

<!-- READING_REFERENCES -->

# Research and design references

Primary-source links below support the attributed facts and precedents. The scenario calculations and proposed BTX contracts are the document’s analysis. Full publisher attribution and research notes are in the accompanying research register.

**[M13] Whole Portfolio product overview.** accessed 2026-09-17. [Source](https://www.blackrock.com/aladdin/platforms/products/whole-portfolio).

**[M14] Studio API solutions.** accessed 2026-09-17. [Source](https://www.blackrock.com/aladdin/platforms/products/apis).

**[M15] Studio and data-cloud overview.** accessed 2026-09-17. [Source](https://www.blackrock.com/aladdin/platforms/products/aladdin-studio).

**[T05] FDC3 Context Data 2.2.** 2.2. [Source](https://fdc3.finos.org/docs/context/spec).

**[T06] FDC3 2.2 standard.** 2025-04. [Source](https://fdc3.finos.org/docs/fdc3-standard).

**[T07] Level 2 LEI data: who owns whom.** accessed 2026-09-17. [Source](https://www.gleif.org/en/lei-data/access-and-use-lei-data/level-2-data-who-owns-whom).

**[T08] IAS 38 Intangible Assets overview.** accessed 2026-09-17. [Source](https://www.ifrs.org/issued-standards/list-of-standards/ias-38-intangible-assets/).

