# One Layer. Many Institutions.
## Cognitive Reserve customer experience and product playbook
### BTX 0.34.8 · Framework v1.2

**Audience:** Product, design, accessibility, partner implementation and agent-interface teams.  
**Edition:** 17 September 2026.

> Ask what the customer wants to become capable of doing. Make the capital, rights and preparation path understandable. Keep the infrastructure interchangeable.

# 1. Experience principles

The product begins with an outcome, a reserve or a portfolio—not with a protocol identifier. The first screen explains the customer's available capital, commitments and capability. Advanced evidence remains one step away, but it does not dominate the happy path.

Providers are chosen for the services they supply. The interface does not display a permanent hierarchy of approved brands. A new conforming provider uses the same connection and consent flow as an incumbent. Accounts, legal entities and roles remain visible wherever money or private data is involved.

Ordinary work should require one clear decision packet, not a confirmation for every internal action. Store financial approval, local execution grant and data-sharing consent separately even when the screen collects them together. The user gains simplicity without granting a provider unbounded power.

# 2. Navigation

Retain six destinations: **Overview, Reserves, Capabilities, Build, Approvals and Activity**. Place Connections, Data Definitions and Export under settings or the relevant institutional workspace. The selected entity and portfolio stay in the header. A group view is visibly read-only until a payer is deliberately selected.

| Destination | Primary content | Main action |
|---|---|---|
| Overview | Financial reserve, commitments, useful capability and next decisions | Start a capital plan |
| Reserves | Available funds, protected floor, mandates and whole-portfolio view | Plan an allocation |
| Capabilities | Purpose, exact recipes, local readiness and alternatives | Prepare capability |
| Build | Missing capability, funded releases and research programmes | Define an objective |
| Approvals | Immutable decision packets and distinct-person progress | Approve or return for revision |
| Activity | Financial, data and local-preparation timelines | Inspect or reconcile |

A role-limited provider can hide unavailable actions without hiding why they are unavailable. “Connect a funding provider” is better than a dead Fund button or an error that pretends no release exists.

# 3. Connect a provider

The connection flow has five stages: choose service; select or enter provider; verify identity and supported roles; review data/effects; confirm the binding. The UI offers roles, not company-specific templates.

The review card shows endpoint origin, pinned provider identity, declared native network, actual conformance evidence, data categories requested and expiration. More detail reveals signatures, schemas and operation digests. A self-attestation is labeled as such; it is not a centrally granted badge.

Customer consent can bind discovery to one provider and custody to another. Credentials remain audience-specific. The summary says which provider sees searches, financial records and coarse outcomes. It never implies that hosted activity is hidden from the host.

Failure messages are actionable: “Provider identity changed,” “This service does not support funding,” “Role manifest expired,” or “Owner approval required.” Do not fall back silently to a broader permission set.

# 4. The whole-portfolio workspace

The workspace has three adjacent panels: **Financial capital**, **Commitments**, and **Cognitive holdings**. Financial capital offers tabs for the institution's valid AUM, AUC, AUA or platform definition. Every total displays currency, scope, date and coverage.

A card may read “Managed assets: $5.0bn” and another “Custodied assets: $3.2bn.” A small definition link explains overlapping scope. Do not place a plus sign between them or show an unlabeled combined total. The cognitive panel can show “148 exact capabilities; 39 ready on permitted devices” without assigning their utility a cash price.

A source correction creates an Activity entry. A partial projection shows the priced subtotal and number of unpriced/incomplete positions. A completely unavailable view says “Data unavailable,” not $0.00.

Drill-down order: number → included positions → chosen source/valuation/mandate → exact record. The analyst can reach the original evidence without navigating a terminal or reading raw JSON by default.

# 5. Capability acquisition

A capability card answers purpose, evidence, local compatibility, new resources required, rights and preparation estimate. A package's friendly description is not an evaluation result. The agent receives the same typed facts and exact references used by the screen.

Primary action “Prepare” creates or selects the local plan. An existing finite grant can cover acquisition and preparation. The local client chooses a resident base plus LAN adapter when that is the appropriate route; the exchange's cloud hint is not a command.

The state strip distinguishes **Plan ready → Acquiring → Verified → Preparing runtime → Ready**. Readiness refers to the device's current generation and lease. A funded campaign is not a prepared runtime. An offline device does not become ready because its funding transaction confirmed.

# 6. Capital decisions

A comparison shows reuse, acquire, compose, finance release, commission research and retained external service where relevant. It compares equivalent accepted work and lists missing inputs. A calculation is not hidden behind a single star rating.

The decision packet shows payer/entity, objective, selected route, exact recipe or research terms, maximum debit, protected reserve impact, native recovery conditions and expected local effects. A changed plan invalidates mismatched approvals. The UI explains the change rather than silently moving the approval to a new object.

Agent requests use the same immutable packet and finite rules. Tool descriptions and model prose cannot increase an allocation or change the recipient. A portfolio system's “send to reserve desk” action produces a draft; it does not execute money.

# 7. Institutional desktop flow

An analyst selects a financial or capability position in a portfolio application. A custom application context opens the corresponding BTX view. The payload contains scoped exact references and display purpose. It contains no login token, wallet key, local path or customer prompt.

The receiving app may offer “Inspect,” “Compare,” or “Draft capital plan.” A separate action and normal authority are needed to approve or execute. Context broadcasts from other windows cannot trigger financial side effects.

The neutral desktop integration belongs to the reference kit. Proprietary desktop adapters are implemented by the participating institution against its actual licensed interface, not compiled as privileged cases in BTX.

# 8. Eight customer scenarios

## Institutional reserve desk

A treasury operator reviews reserve coverage, opens a new capability allocation and routes the packet to a two-person committee. The operator sees exact holds and fees. The analyst sees the resulting position and mandate-linked metric after settlement. No source's estimate overwrites custody facts.

## Global agent venue

A company delegates small finite capability budgets to many agents. Each agent can read, prepare and execute only the existing authorized workflows. The new role layer makes discovery and analytics optional separate services. Concurrent agents cannot overspend a shared reserve floor.

## Wholesale platform

A service provider serves many downstream institutions. Tenant branding is a presentation theme, not protocol behavior. The same source position can appear in service and client views with documented scope; it is not counted twice in an underlying-asset total.

## Business treasury app

A CFO compares recurring service spend with local capability acquisition. The platform creates a department-specific plan, obtains technical acceptance and financial approval, and deploys through the local client. Group visibility never crosses subsidiary financial authority.

## Retail and adviser experience

A retail user sees an understandable reserve balance and capability library. An adviser can draft for an authorized client, but separate client consent is required for financial action. The product distinguishes investments from software/resource use rights.

## Asset manager and whole-portfolio platform

An analyst sees direct reserve exposure, approved instrument look-through and operational cognitive dependencies in separate views. A new mandate adds actual managed assets. Imported technology-client assets extend reporting coverage without becoming the platform vendor's AUM.

## New specialist exchange

A new entrant connects existing custody and execution providers, implements its own discovery/treasury UX and runs the same conformance suite. No code recognizes its brand. Its service can be small and focused while using the entire neutral capability network.

## Research foundation

A foundation funds an openly released capability for its beneficiaries. It records the grant/commitment and later capability access with their actual rights. It does not receive fictional investment returns or exclusive model ownership from its sponsorship.

# 9. Content and accessibility

Use complete, direct labels. Prefer “Funds committed; release pending” over a generic “Success.” Prefer “Outcome under reconciliation; do not resubmit” over a retry button that could duplicate money. Errors explain the affected layer and next permitted action.

WCAG 2.2 AA is the interaction baseline. All controls support keyboard use, visible focus, accessible names and status announcements. Charts have table equivalents. Avoid color-only status, ambiguous units and tiny targets. Prefer 44-pixel actions and responsive layouts. Preserve exact monetary strings in localizations; translated labels must not alter native precision. [T09]

# 10. Privacy and export UX

Data sharing is purpose-specific. A portfolio projection, financial audit record and local readiness report have different audiences. Default local reporting is off. Show a concise list of shared categories before activation and an accessible record of current bindings.

Export selection names the scope, as-of, observation cutoff, format, redaction policy and destination. Downloaded files have a manifest and source definitions. A customer switching analytics providers can reuse those records. Pending custody and financial commitments remain with their original controller until actually settled or transferred.

# 11. Required UI evidence

Exercise onboarding, role mismatch, legal-entity selection, a complete and partial whole-portfolio view, historical correction, a local capability preparation, a draft from desktop context, a changed approval, import rejection and provider exit. Test keyboard-only and screen-reader paths. Validate that every visible state corresponds to a registered API result and exact source.

The included offline prototype demonstrates layout and vocabulary with synthetic records. Production UI work binds those screens to the existing SDK and actual state transitions. A clickable mockup does not satisfy custody, runtime or native acceptance.

**Make the customer experience simple by standardizing the boundary—not by concealing who holds the money, what was acquired or which authority approved the action.**

<!-- READING_REFERENCES -->

# Research and design references

Primary-source links below support the attributed facts and precedents. The scenario calculations and proposed BTX contracts are the document’s analysis. Full publisher attribution and research notes are in the accompanying research register.

**[T09] WCAG 2.2.** 2.2. [Source](https://www.w3.org/TR/WCAG22/).

