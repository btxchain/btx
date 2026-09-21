# The Exchange for Machine Capability
## How centralized exchanges can build their 2030s businesses on BTX 0.34.8

**Strategy paper · 17 September 2026 · Revision 1.0**  
**Audience:** Exchange leadership, product, institutional business, engineering, risk and strategic partners.

> The next AI business for an exchange need not be a chatbot that trades existing assets. It can be the financial and discovery interface through which organizations and their agents acquire, commission and maintain productive machine capability.

## Executive decision

Centralized exchanges should evaluate a BTX cognitive-capital business as a distinct product line, not merely as a token listing. The proposed service combines a familiar exchange account, controlled agent budgets and institutional custody with a capability catalogue, model-release funding, research bounties and a portable handoff to the customer's own machines. The exchange handles discovery and financial operations. BTX handles exact resource identity, distribution and verification. A local capability service handles memory, runtime preparation and use. [B01–B04]

That division lets the exchange enter AI's productive economy without becoming a frontier-model developer or operating every customer's inference. A customer can arrive to obtain a capability rather than to speculate on a token. Researchers can arrive to earn a reward for producing one. Enterprises can maintain controlled financial reserves and repeat procurement programmes. The exchange can earn from software, custody, execution and optional managed services while public model acquisition remains free of a compulsory exchange toll.

The business case should work before BTX becomes a global reserve currency. Reserve adoption, deep secondary markets and machine treasury balances are upside scenarios. The first test is more concrete: can the exchange help customers reach useful local capability, finance desired outputs and account for those commitments better than a collection of unrelated tools?

This paper assumes the functionality defined in the supplied 0.34.8 capability and package specifications is implemented and verified. It does not assert that all private development has shipped. The accompanying implementation specification supplies the missing hosted-control contract. All commercial examples and 2030s outcomes below are proposed strategies or illustrative scenarios, not forecasts.

# 1. From financial access to productive capability

A trading platform helps a customer exchange financial assets. An agent-payment platform helps software buy a service. A cognitive-capital platform helps a customer obtain the means to perform future work.

Those categories overlap, but they are not interchangeable. An agent may pay a weather service repeatedly because fresh observations are the product. It may instead obtain a reusable model and compatible adapter for a recurring internal classification task. It may co-fund the public release of a specialist model. When the required capability does not exist, it may propose a research bounty for its owner to authorize. The underlying need changes from access to an answer to access to an enduring productive implementation.

BTX's proposed unit is a capability recipe: exact models, adapters, tokenizer or other components, compatibility requirements, evidence and a supported local runtime contract. A lockfile pins the implementation. The local resolver can reuse a resident base, fetch only missing assets and prepare a generation-bound runtime. The exchange does not have to manage those mechanics; it needs to deliver portable, verifiable inputs to them. [B01, §§5–7, 21]

The result is a new customer journey:

```text
Need a capability
    → discover eligible implementations
    → reuse what is available locally
    → acquire missing public assets
    → or authorize release / creation funding
    → verify and prepare locally
    → use, update and reuse
```

The first commercial opportunity is not to charge for every arrow. It is to make the whole journey dependable and easy to govern.

# 2. Why exchanges should take this seriously

Exchange strategy is already expanding beyond one trading asset or fee pool. Coinbase reported that subscription and services represented 48% of Q2 2026 net revenue, at $555 million, and that 88% of net revenue excluded Bitcoin spot trading. Those are company-specific figures, but they demonstrate that a major exchange is already building a broader financial-infrastructure business. [R01]

Agent infrastructure is also becoming real product work. Coinbase's agent wallet documentation describes CLI and MCP paths for guarded wallet and payment access; its AgentCore integration describes service discovery and programmatic payments. x402 provides an open HTTP-based payment mechanism for APIs and content. These are useful precedents for distribution and integration, not failed alternatives that BTX must displace. [R02–R04]

BTX adds a different object of demand. Instead of making an AI the operator of an existing financial product, the exchange makes reusable AI capability the subject of procurement and funding. The exchange can use its existing identity, custody, conversion, reporting and permissions stack while adding a purpose-built catalogue and workflow layer.

The opportunity is particularly attractive where customers already combine a financial budget with a local deployment estate: enterprise agents, engineering teams, research organizations, appliance fleets and managed IT providers. These customers need a reliable bridge between money and a working result, not another isolated wallet.

# 3. A differentiated opportunity, not a claim that other markets are finished

Tokenized equities, derivatives and predictions can remain substantial businesses. Kraken reported more than $25 billion of combined xStocks CEX, DEX, mint and redemption activity in February 2026; Reuters reported Nasdaq's $100 million investment in Kraken parent Payward in September. Those measures are not exchange revenue and do not prove ultimate profitability, but they do not support declaring the category exhausted. [R05, R06]

The useful strategic distinction is the source of customer demand.

| Opportunity | Customer is principally acquiring | Exchange advantage | What BTX adds or changes |
|---|---|---|---|
| Spot and derivatives | Exposure, liquidity or a hedge | Execution, market depth, custody | A possible new underlying asset and customer activity; volume is not guaranteed |
| Tokenized securities | A representation of existing financial rights | Distribution, regulated access, settlement | A separate capability-procurement business, not a replacement for securities |
| Prediction markets | An outcome-contingent financial contract | Liquidity, market operation, distribution | Funding productive outputs rather than only taking an outcome position |
| Agentic payments | A way for software to pay for goods or services | Authorization, wallets, acceptance | Exact capability recipes, acquisition and local preparation surrounding the payment |
| Model hubs and managed AI | Repositories, APIs or deployment services | AI tooling and developer relationships | A neutral handoff that can use many sources and local runtimes |
| BTX cognitive-capital services | Reusable capability and the creation or release of new supply | Treasury, procurement workflow, custody, reporting | Financial decisions joined to an independently verifiable local outcome |

The recommendation is not to abandon profitable products. It is to build an additional engine of demand that does not require customers to arrive with a trading thesis. A procurement customer can become a treasury customer; a successful research supplier can become a liquidity customer; a deployed agent fleet can become a recurring software customer.

# 4. The product: a Cognitive Capital desk

The new navigation should look like a useful AI business, not a token promotion page. A Capabilities area shows verified package identities, the purpose of each recipe, compatible variants and attributable evaluation evidence. Releases shows existing outputs whose public release is being financed. Research shows creation bounties. Treasury shows balances, finite agent allocations and commitments. Activity joins financial receipts to local acquisition status without confusing them.

A capability page should answer four questions clearly. What is this intended to do? What exact assets and runtime implement it? What must this customer do or pay to obtain it? Can the customer's own machine make it usable?

The exchange can provide coarse compatibility filters, but the last answer belongs to the local resolver. Only that service has reliable current information about memory pressure, resident models, local network sources and runtime generations. A cloud catalogue must not claim a model will be ready in two seconds merely because it knows the advertised size of a GPU. [B01, §§3, 6–7]

A free public capability should have a direct Acquire action. A release campaign should show committed terms and separately observed funding state. A bounty should show who evaluates, what passes, when submissions close and how unused funding can be recovered. A financed output should not be presented as an equity investment or a claim on future model revenue unless a separate legally defined instrument actually provides those rights. [B04]

# 5. One familiar account; independent local capability

The hosted design removes the operational burden that otherwise makes distributed systems difficult for ordinary customers. An agent can use the exchange API for catalogue search, account balances, approvals, conversion and funding. It does not need to synchronize a monetary node or keep spending keys on its inference machine.

The local installation is still more than a download utility. It verifies package authorship and resource identities, applies the owner's software and resource policies, discovers local sources, acquires missing ranges, manages residency and hands an authorized capability to a local runtime. The exchange cannot turn its API response into permission to run arbitrary commands or replace the user's trusted software sources. [B01, B02]

![Figure 1. A hosted interface without a hosted model monopoly.](../assets/control_data_planes.png)

**Figure 1.** The exchange operates discovery and finance. The customer retains the verification and execution boundary. Native BTX providers carry payloads; a CEX need not proxy model weights.

The practical flow is: search at the exchange; receive exact `.btx` bytes and a handoff; inspect and authorize locally; acquire from local caches, LAN or the native swarm; report only the minimal outcome the customer has chosen to share. A signed handoff is an authenticated request, not a runtime grant. The customer's local policy can authorize a complete ordinary journey once, avoiding repeated prompts while retaining finite limits.

This is convenient in the same way managed infrastructure is convenient, but with an exit. The portable package, lockfile and already acquired public bytes remain useful after the customer leaves the exchange.

# 6. The economics: productive capital, not perpetual metering

The strongest BTX proposition is not that every inference becomes a financial transaction. Public retrieval and warm-cache reuse do not inherently require a BTX balance. Money enters at scarce events: committing a creation reward, funding an existing model's release, or paying for a specifically supported paid service. [B01, §23]

A useful economic description is capital formation: an organization deploys funds to obtain something that can produce value repeatedly. But CAPEX is not an automatic accounting classification. IAS 38 distinguishes identifiable controlled assets and recognition criteria, and research expenditure is generally expensed. A contribution to a public-good release does not automatically become a customer-owned intangible asset. The interface must preserve factual receipts and let the customer's accountants apply the relevant rules. [R11]

The same discipline applies to the word reserve. BTX is not a claim redeemable against model inventories, a deposit guarantee or a stable-value instrument. Cognitive Reserve describes the system's intended role. Holding BTX is exposure to the currency; obtaining a model is obtaining a separate usable resource; funding a bounty is committing to its specific conditions. The three must not be displayed as the same asset.

A customer might retain BTX for future commitments, or convert from fiat or stablecoins just before funding. An exchange can serve both. A sound business should not require customers to accept more token-price exposure than their operations warrant.

# 7. Revenue that does not depend on a token-price story

There are four initial revenue lines with clear customer value.

**Enterprise software.** Charge for multi-agent budget controls, approval chains, evidence records, audit exports, catalogue governance and fleet handoff orchestration. A predictable subscription can be the most durable early revenue because it is tied to operations rather than speculative turnover.

**Treasury and custody.** Charge for services that customers actually select: secured custody, institutional reporting, segregated operational portfolios, approval policies and recovery administration. Customer balances remain liabilities or safeguarded assets under the applicable custody arrangement, not free exchange working capital.

**Execution and conversion.** Customers may convert fiat, stablecoins or other assets into BTX and suppliers may convert proceeds out. Quotes should show net principal, spread, explicit exchange charges and network fees. Best execution and conflicts matter especially when the same venue recommends a campaign and benefits from the resulting conversion.

**Managed procurement and research operations.** An exchange can offer optional campaign administration, procurement support, evidence organization and service-level support. It must disclose its fees separately and avoid presenting evaluator judgement as a guarantee of scientific or commercial success.

Additional products—premium infrastructure, compliant financing, data services and derivatives—can follow proven demand and separate approval. They are not required to make the initial service coherent. In particular, a proof-of-work coin does not produce staking yield simply because customers deposit it.

# 8. A revenue model with visible assumptions

The following scenarios are arithmetic illustrations for annual business planning. They are not BTX forecasts, prices, adoption estimates or endorsed fee schedules. They exclude operating expenses, rebates, capital requirements, fraud losses and taxes. Subscription and custody products are assumed to be separately contracted so revenue is not counted twice.

| Annual input or output | Focused business | Expanded business | Large ecosystem |
|---|---:|---:|---:|
| Paying organizations | 1,000 | 5,000 | 20,000 |
| Annual software fee per organization | $12,000 | $30,000 | $60,000 |
| Software revenue | $12.0m | $150.0m | $1,200.0m |
| Executed BTX trading notional | $1bn | $25bn | $250bn |
| Effective fee capture | 5 basis points | 5 basis points | 5 basis points |
| Trading revenue | $0.5m | $12.5m | $125.0m |
| Average separately billed custody assets | $0.2bn | $3bn | $20bn |
| Annual custody fee | 20 basis points | 15 basis points | 10 basis points |
| Custody revenue | $0.4m | $4.5m | $20.0m |
| Administered funding principal | $50m | $1bn | $10bn |
| Separately billed administration fee | 50 basis points | 25 basis points | 15 basis points |
| Administration revenue | $0.25m | $2.5m | $15.0m |
| **Illustrative gross revenue** | **$13.15m** | **$169.5m** | **$1,360.0m** |

![Figure 2. Revenue can begin with operating services rather than speculative turnover.](../assets/revenue_scenarios.png)

**Figure 2.** Calculated from the assumptions above. The largest scenario requires very substantial enterprise adoption. It is a sensitivity case, not a forecast.

The trading equation is executed notional multiplied by realized fee capture. Deposits, model downloads and bounty principal must not be substituted for trading volume. A customer can hold a large reserve for a long time and generate little turnover. A customer can use free capabilities extensively and never trade BTX. Conversely, suppliers receiving BTX may create conversion flow even when consumers use released models without payment.

The correct planning model therefore separates accounts, balances, commitments, executed trades and recognized fees. It should stress-test a low-trading case, a low-reserve case and a case in which software subscriptions—not exchange fees—carry the business.

# 9. Reserve adoption is upside, not the first milestone

A mature cognitive economy could generate meaningful treasury balances: enterprises retain funds for procurement; research suppliers keep working capital; agents operate under finite account policies. An exchange that serves those workflows can become a preferred custody and liquidity venue.

That does not establish that BTX must appreciate with aggregate AI output. Models may become more useful while remaining free, users may prefer just-in-time conversion, and successful distributed infrastructure can create value that is not captured proportionally by its monetary asset. The exchange should underwrite service adoption, not a promise that model growth guarantees currency returns.

The opportunity becomes stronger when customers repeatedly return for productive tasks. Measure the proportion of accounts that commission a second useful capability, complete a release-to-deployment cycle, or renew an agent-governance subscription. Those behaviors offer a more durable foundation than a short burst of speculative listing volume.

# 10. Neutrality as a distribution advantage

NVIDIA's September acquisition agreement for Hugging Face highlights why hardware and model ecosystems may value an independent distribution option. The announced transaction is expected to close in the first half of 2027 subject to conditions, and NVIDIA has stated that Hugging Face will remain open with hardware choice. The strategic concern is concentration and optionality, not an unsupported allegation that private information has been misused. [R07, R08]

BTX can let a publisher remain on Hugging Face while offering portable packages and independently served bytes. Different exchanges can catalogue the same package and execute different financial services around it. Hardware vendors can publish supported variants without controlling the namespace. The customer can change the service provider without changing the resource's immutable identity. [B01–B03]

A CEX integration does reintroduce an observation point: the exchange sees the searches, account activity and handoffs sent to it. Decentralization does not magically conceal that data. The product should keep raw prompts, KV state, detailed local inventory and runtime traces off the exchange by default. Customers should be able to use local or alternate discovery and export portable records. Competitive neutrality must include those operational choices.

# 11. Trust is the service, not an exemption

The customer-facing promise should be clear: the exchange is accountable for its custody and service decisions; the local client independently checks the content it can check. A platform receipt proves what that platform attests. It does not by itself prove a chain is valid, a refund is presently spendable, a model has been released or a local runtime has finished loading.

The implementation must distinguish a CEX balance from an on-chain funding output, a spending approval from a signed transaction, and a download receipt from a readiness lease. A contribution can remain locked after the customer changes their mind. A payment can be confirmed while a release is still unavailable. An exchange outage need not stop already acquired public models, but it may prevent access to custodial funds. [B02–B04]

The regulatory posture should also remain factual. Reuters reported the September procedural defeat of CLARITY, but the strategy does not rely on either the bill's passage or a resulting absence of rules. FATF continues to assess VA/VASP regulation and supervision. Each operator needs product- and jurisdiction-specific review of custody, transfers, sanctions, research procurement, marketing and any investment instrument. Agent accounts remain attributable to a legally responsible customer. [R09, R10]

# 12. A market that rewards competition rather than captivity

Multiple CEXs should be able to enter with the same integration contract. One may specialize in institutional research finance, another in retail acquisition, another in enterprise agent treasuries or regional support. They should compete on operating service, curation, execution and reliability—not incompatible model identities.

The shared stack needs public schemas, reproducible package verification, clear custody disclosures, a portable handoff object, machine-readable events and a conformance suite. The exchange-specific adapter supplies customer identity, compliance policy, ledger operations, quotes, custody signing and settlement observation. BTX supplies the protocol-side logic rather than requiring every exchange to independently reimplement it.

The exit test is essential. Disconnect provider A; keep the verified model and lockfile; resolve equivalent public resources through provider B or local discovery; establish new consent before any new financial action. Existing custodial balances and escrow refund authority do not teleport to B. Those require actual withdrawals, settlement or completion under A's original terms. Portability must be honest at both the software and money layers.

# 13. Launch with a narrow customer wedge, a complete architecture

The first customer offer should be a capable procurement-and-deployment console for organizations that already run local models. Begin with public capability discovery and verified handoff. Add accountable release and bounty participation once custody signing, recovery and the account-to-chain reconciliation path are proven. Then add recurring finite budgets and fleet policy.

A proposed pilot has three gates rather than a promised calendar. Gate one demonstrates a no-wallet local acquisition from the hosted catalogue and survival of gateway outage. Gate two demonstrates a real test-network financial round trip, including ambiguous submission and refund. Gate three demonstrates two independent gateway implementations consuming the same packages with interoperable portable objects and distinct customer consent.

A model-publisher partnership can supply a concrete release. A systems integrator can supply an enterprise fleet. A research sponsor can supply a measurable bounty. An exchange supplies identity, treasury and interface. The product is strongest when those roles do not have to be the same company.

# 14. Measure success at the boundary between money and useful work

The primary product metric is a completed capability outcome: the customer acquired and verified the intended recipe and, where authorized, reached the requested local readiness target. Track median and tail time to capability, bytes reused, external traffic avoided, failed handoffs and compatibility errors.

Financial metrics are separate: funded principal, open commitments, refund latency, reconciliation exceptions, repeat sponsor behavior, realized conversion fees and revenue per governed organization. Treasury assets are not revenue. An aggregate reserve balance is not proof of sufficient liquidity. A green transaction status is not a useful model result.

Risk metrics include prevented unauthorized effects, unresolved broadcast outcomes, stale provider keys, recovery drill completion, ledger-to-chain reconciliation breaks and privacy incidents. No customer prompt or complete local capability inventory needs to be collected to measure basic success.

The board-level decision is whether the exchange can become a trusted place to allocate financial resources toward machine capability while customers retain local control. That is a distinct business from another asset wrapper or an AI trading assistant.

# Conclusion: finance what machines can become

BTX gives an exchange a route into an AI business whose defining output is not a trade or an API response, but a more capable customer system. The exchange can make discovery, treasury and funding familiar; portable packages and the BTX network can make acquisition resilient; the local capability service can make the result usable without turning the exchange into the runtime owner.

The recommendation is to build a Cognitive Capital desk on an open integration contract. Make public acquisition easy. Make funding deliberate. Make receipts precise. Make departure possible. Earn by reducing operational friction and improving outcomes rather than by manufacturing a toll on every inference.

**The strategic opportunity is to become the financial interface to reusable machine capability—not merely the payment instrument used by an AI.**

<!-- SOURCE_REGISTER_APPEND -->

# Source register

Research reviewed 17 September 2026. Supplied BTX specifications establish design requirements, not native implementation proof. External sources establish only the facts attributed to them; the strategy and HCP design are this package’s analysis and proposals.

**[B01] BTX JIT Capability Development Spec, rev 1.0. Supplied file: `BTX_0348_JIT_Capability_Development_Spec.md`.** User-supplied design baseline; sections 1, 3–7, 21–27. Defines Core v3, local grants, three authority planes and no-account acquisition. Not executed code evidence.

**[B02] BTX Agent-readable Package Spec, rev 1.0. Supplied file: `BTX_0348_Agent_Readable_Package_Spec.md`.** User-supplied design baseline. BTXPKG1 framing, authorship/software/wallet distinctions. Core v2 is superseded by JIT Core v3 where allocated.

**[B03] BTX Expanded Implementation Spec. Supplied file: `BTX_0.34.8_Expanded_Implementation_Spec.md`.** User-supplied design baseline. Origin/storage, events, mandates, escrow and package responsibilities.

**[B04] BTX Model Bounties and Discovery Hardening. Supplied file: `BTX_0.34.7_Model_Bounties_and_Discovery_Hardening.md`.** User-supplied design baseline. Frozen rounds, per-contributor lots, council judgement, refund deadlines and no return-bearing security.

**[R01] [Coinbase Q2 2026 earnings announcement](https://investor.coinbase.com/news/news-details/2026/Coinbase-Q2-Earnings-Everything-Exchange-Drives-3rd-Consecutive-Quarter-of-Record-Crypto-Trading-Volume-Market-Share-Revenue-Diversification-and-Resilience/default.aspx).** Company-reported: subscription/services $555m and 48% of net revenue; 88% of net revenue excluding Bitcoin spot trading. Not sector-wide evidence.

**[R02] [Coinbase Agentic Wallet overview](https://docs.cdp.coinbase.com/agentic-wallet/welcome).** Official product documentation: agent CLI and MCP wallet/payment interfaces.

**[R03] [Coinbase AgentCore payments GA](https://www.coinbase.com/en-es/developer-platform/discover/launches/agentcore-ga).** 18 August 2026; official integration example for service discovery, guarded spending and payment rails.

**[R04] [x402 introduction](https://docs.x402.org/introduction).** Open HTTP payment standard; API/content access, not confined to a legal expense category. Does not implement BTX.

**[R05] [Kraken xStocks transaction-volume announcement](https://blog.kraken.com/product/xstocks/25-billion-in-total-transaction-volume).** 19 February 2026; reported $25bn combined CEX/DEX/mint/redemption volume. Not market cap, revenue or comparable spot-only volume.

**[R06] [Reuters: Nasdaq investment in Kraken parent](https://www.reuters.com/legal/government/nasdaq-invest-100-million-kraken-parent-deepen-tokenization-push-2026-09-10/).** 10 September 2026; $100m investment announcement. Evidence other growth categories remain actively funded.

**[R07] [NVIDIA acquisition agreement filing](https://www.sec.gov/Archives/edgar/data/1045810/000104581026000078/nvda-20260902.htm).** Definitive agreement, not completed acquisition; anticipated H1 2027 close subject to conditions. $11.9bn shareholder price plus up to ~$1bn retention program.

**[R08] [NVIDIA: to acquire Hugging Face](https://blogs.nvidia.com/blog/nvidia-to-acquire-hugging-face/).** 3 September 2026; announced open/interoperable and hardware-choice commitments. Source for ownership-concentration scenario, not proof of misuse.

**[R09] [Reuters: crypto bill defeat](https://www.reuters.com/legal/transactional/crypto-bills-defeat-shows-limits-industrys-political-machine-2026-09-16/).** 16 September 2026 report on procedural failure to advance CLARITY. Not a legal exemption for this business.

**[R10] [FATF seventh targeted VA/VASP update](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html).** 16 July 2026; compliance remains jurisdiction-specific; protocol decentralization does not remove operator duties.

**[R11] [IFRS IAS 38 overview](https://www.ifrs.org/issued-standards/list-of-standards/ias-38-intangible-assets/).** Research is expensed; development/other intangible costs require recognition conditions. Economic capital formation is not automatic balance-sheet capitalization.

