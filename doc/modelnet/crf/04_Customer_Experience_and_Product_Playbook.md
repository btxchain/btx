# A Capital Desk for Machine Capability
## Customer experience and product playbook

**BTX–CEX Framework v1.1 · Product and design edition**

# 1. Product promise

The interface helps a customer answer four questions: What capital do we hold? What capability can we use? What should we acquire or create next? Who can authorize that decision?

The product is not a trading screen with model thumbnails. It is a capital workspace. The default view combines reserve capacity, current commitments and cognitive holdings without merging their meanings. An agent, CFO, engineer or family principal should recognize the same underlying decision in a role-appropriate form.

# 2. Personas and default landing views

| Persona | First view | Primary responsibility |
|---|---|---|
| Corporate CFO | Reserves and approvals | Protect liquidity and authorize allocation |
| Technical owner | Workloads and capabilities | Establish evidence and useful deployment |
| Institutional treasury operator | Mandates and execution | Manage reserve position within authority |
| Investment committee member | Decision packet | Review exact economic effects |
| Family principal | Group overview | Direct separate entities without blending assets |
| Adviser | Draft workspace | Prepare recommendations, not self-authorize money |
| Research supplier | Build programmes | Respond to objectives and track proceeds |
| Agent operator | Policies and activity | Maintain bounded unattended workflows |

A role changes what is emphasized, not who owns funds. The entity selector is always visible. A group view says “Viewing 4 entities”; a financial action asks for one authorized payer or distinct approvals for each leg.

# 3. Information architecture

Use six main destinations: Overview, Reserves, Capabilities, Build, Approvals, Activity. Put Devices, Reports and Settings in secondary navigation. Do not create separate retail and institutional protocol forks.

Overview contains three primary cards: **Financial reserve**, **Capital committed**, **Cognitive holdings**. Each card has an as-of time and a clear scope. The holdings card shows usable recipes or deployments, not a monetary estimate added to cash.

The default primary action is “Create capital plan.” An empty state offers three starting points: evaluate a recurring workload, obtain a capability, or commission a missing one. A user who already knows the exact `.btx` package can open it directly.

# 4. Reserve workspace

Show available funds, existing holds, protected floor and remaining allocation authority separately. Explain the resulting capacity in one sentence: “This portfolio can allocate up to 250 BTX while retaining its protected reserve.”

Reserve editing opens a preview, not immediate trading. The preview shows affected entity, policy generation, new capacity, expiry and approval requirement. SUGGEST replenishment says “Prepare a top-up proposal.” AUTO is a separately reviewed policy with visible limits, allowed source assets, cooldown and aggregate turnover.

Do not display “Earn” or a yield rate simply because BTX is deposited. Existing eligible financial products have their own product card and contract.

# 5. Capability pages

Lead with the task, evidence and local suitability. Show exact implementation, alternative recipes, required resources, rights, estimated preparation and current economic route. A package signature and a quality claim are separate badges with separate details.

A public available resource says “Acquire.” A financed unreleased model says “Fund release.” A missing capability says “Create research objective.” A local adequate recipe says “Use available capability.” None of those actions silently implies the others.

Where a shared base is already resident, show the practical improvement: “Base already available; acquire the missing adapter.” Use measured or locally estimated amounts. Do not fabricate a readiness time from the advertised GPU name.

# 6. Workload comparison

The wizard asks outcome, accepted-task definition, expected demand, horizon and data policy before price. It then shows eligible routes in comparable terms: task evidence, upfront cost, ongoing cost, time to readiness, hardware footprint and operational responsibility.

Unknown input uses “Needed to complete comparison.” Do not rank it as a zero-cost option. A quality mismatch blocks a claimed cost saving. An illustrative model is labeled “Planning assumptions”; a measured result identifies its baseline and observation period.

The preferred route is explained with a short reason and expandable evidence. The user can change priorities and regenerate the plan. A new assumption or recipe creates a new immutable comparison; it does not overwrite an approved decision.

# 7. One approval packet

The packet should fit its decision summary on one screen: payer, objective, implementation, maximum debit, reserve remaining, conversion terms, commitment/refund condition and local effect. Expand sections reveal exact digests, native terms, evidence and fees.

Distinct approvers see the same packet. Approval count uses distinct eligible people, not logins. The initiator cannot count where separation of duties is required. A changed plan clearly says “Review required again—financial effects changed.”

A device owner may approve local effects in the same journey, but the UI identifies it as a separate permission: “Allow this device to acquire and prepare the selected capability within this policy.” Financial approval cannot override the device's software trust.

# 8. Build and programme pages

The Build page organizes objectives, not speculative model tokens. A programme card shows intended capability, evidence threshold, native bounty/release terms, sponsor commitments and supplier progress. Co-sponsor views preserve each entity's contribution and refund responsibility.

The action “Join programme” accepts membership conditions; it does not debit money. “Prepare commitment” creates the exact native funding proposal. Progress displays management aggregates alongside chain-observed commitments without inventing pooled assets or votes.

Supplier pages distinguish submitted, evaluated, awarded, claimed and paid. A positive evaluator result is not a completed financial claim, and a claim is not proof that every customer runtime is ready.

# 9. Two timelines in Activity

Every capital execution has a financial lane and a local capability lane. Each can progress or fail independently. Partial success gets a specific explanation and the next permitted action.

| Situation | User-facing message | Safe action |
|---|---|---|
| Conversion completed; terms expired | BTX acquired. Funding needs a new review. | Review updated plan |
| Broadcast response lost | Transaction outcome is being reconciled. | View existing operation |
| Funds committed; secret absent | Capital committed. Waiting for release disclosure. | Follow release |
| Download done; runtime still loading | Files verified. Preparing local capability. | View preparation |
| Gateway unavailable; local ready | Local capability remains ready. Hosted finance is unavailable. | Use locally |
| Refund deadline reached | Refund can be prepared under the native terms. | Prepare refund |
| Refund confirmed | Funds returned. Previous lifetime approval is unchanged. | Review reserve |
| Committee changed | Approval eligibility changed. Review is required. | Reopen packet |
| Provider changed | New provider connected. Prior financial obligations remain with A. | View outstanding items |
| Reserve would be breached | This plan would cross the protected reserve. | Reduce plan or request policy change |

Never offer a generic “Retry payment” button for an unknown external effect.

# 10. Family and institutional separation

Family views group companies, trusts and foundations visually while preserving each payer's authority and statements. Advisers can prepare shared objectives and compare deployments. They cannot move assets merely because they can see them.

Institutional views emphasize mandates, approval thresholds, encumbrance, execution and report snapshots. Corporate views emphasize workload ownership, deployment and cost allocation. The same exact objects support all three.

A multi-entity plan shows each leg and required approver before submission. A consolidated chart does not sum protected capital twice or convert a soft programme budget into cash.

# 11. Partner products

Show relevant existing custody, OTC, credit, hedge and infrastructure-finance offers in a contextual panel. A plan requiring new hardware can introduce a financing partner. A large reserve acquisition can introduce the OTC desk. The product card names who provides the service and what action follows.

“Request introduction” creates a referral. “Review quote” opens exact terms. “Execute” exists only where the user's accepted product and permission support it. Sponsored placement and affiliated counterparties remain visible annotations.

# 12. Browser and agent parity

The portal and agent SDK use the same schemas, scopes and state transitions. The agent can prepare a capital comparison, read a reserve snapshot and submit an already authorized allocation without parsing human prose. Tool output returns stable IDs and safe next actions.

The browser hands off to a paired outbound local connector. No custody key enters JavaScript; no exchange token enters a `.btx` URI. A desktop public client is not shipped with a shared OAuth secret.

# 13. Accessibility and localization

Meet WCAG 2.2 AA; prefer 44-pixel touch targets, visible keyboard focus, text equivalents for state colors and screen-reader announcements for progress. Financial reviews remain navigable without a mouse. Modal focus returns to the initiating control.

Use locale-aware display while retaining canonical machine amounts. Show BTX and reporting currency explicitly. Do not use ambiguous “tokens” for money or inference units. Japanese layouts support longer labels and native line breaking without truncating the payer or maximum amount.

# 14. Reports as a relationship product

Provide a one-page executive summary with financial reserves, commitments and productive outcomes, then detailed entity schedules. Let a CFO answer whether a capital programme delivered the expected workload economics. Let a family principal see which businesses acquired capability. Let an institution see mandate compliance and execution.

Keep projected savings separate from measured savings. Include observation times and baseline versions. Reports should explain the decision rather than expose private prompts, memory addresses or complete device inventories.

# 15. Product acceptance

A first-time customer completes public acquisition without a terminal. A CFO and technical owner complete a two-authority plan through one coherent review. A family adviser cannot debit a subsidiary. An institutional committee cannot double count one person. A duplicate click cannot create another financial effect. A provider outage does not end local public capability.

The accompanying offline portal is a visual workflow prototype using synthetic data. Production behavior is implemented through the typed SDK, actual identity system and native acceptance journeys—not by promoting its browser state into financial authority.

**The interface should make capital allocation feel simple because the system is precise.**
