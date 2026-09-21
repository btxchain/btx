# Native Acceptance and Customer Journeys
## Cognitive Reserve v1.1 · execution companion

**190 new cases and 20 whole-system journeys.** Preserve the 120 base HCP cases as separate regression coverage. Initial native status is NOT_RUN.

# Cognitive Reserve v1.1 — individual native acceptance catalogue

190 cases; the 120 base HCP cases remain additional regression requirements. Each case begins NOT_RUN. Native assertions must run against registered production paths. Reference tests prove only their stated offline invariants.

# CR11-COMP — Native codec + base/new gateway

## CR11-COMP-01 — Base route preservation

**Given:** The original 34 route contracts and seven statement schemas.
**When:** load v1.1 alongside an existing HCP client.
**Then:** old requests, responses and signed golden bytes remain unchanged.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-02 — Negotiated extension binding

**Given:** An enrolled base ProviderProfile and signed extension.
**When:** substitute a different parent profile digest.
**Then:** reject before any new extension effect.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-03 — Unknown extension

**Given:** An old server or unknown required feature.
**When:** request a reserve or committee operation.
**Then:** return PROFILE_UNSUPPORTED without unrestricted funding fallback.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-04 — Domain separation

**Given:** The same body signed under one new object type.
**When:** relabel it as an approval or receipt.
**Then:** reject the body ID/signature mismatch.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-05 — Strict parser parity

**Given:** Duplicate keys, float values and invalid Unicode vectors.
**When:** parse with native codec and both SDKs.
**Then:** all reject the same forbidden representations.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-06 — No package version inflation

**Given:** A valid Core v3 capability package.
**When:** complete hosted reserve-funded acquisition.
**Then:** preserve exact package bytes and avoid creating Core v4.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-07 — Safe downgrade

**Given:** A new approved allocation using committees.
**When:** disable the extension at the provider.
**Then:** stop new effects and retain reconciliation of accepted children.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-08 — Key rotation

**Given:** An extension signed by an expired or revoked role key.
**When:** request a new financial action.
**Then:** reject while retaining historical receipts as dated evidence.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-09 — Migration restart

**Given:** Existing base intents and partially migrated new records.
**When:** crash and restart schema migration.
**Then:** resume without lost holds, duplicate records or orphaned exports.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-COMP-10 — Rollback accountability

**Given:** Accepted v1.1 financial children.
**When:** roll back the application deployment.
**Then:** keep read/reconcile/refund paths and prohibit duplicate execution.

**Environment:** Native codec + base/new gateway. **Evidence:** `evidence/CR11-COMP-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-ENTITY — Native API + identity/ledger lab

## CR11-ENTITY-01 — Group view is not debit authority

**Given:** A parent with read access to a subsidiary.
**When:** submit a subsidiary debit using only parent scope.
**Then:** deny without reserving funds.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-02 — Family segregation

**Given:** Company, trust and foundation accounts in one overview.
**When:** query and allocate from one selected entity.
**Then:** other entities remain outside the payer balance and mandate.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-03 — Adviser draft only

**Given:** An adviser authorized to prepare plans.
**When:** approve or execute the prepared plan.
**Then:** deny the higher effect while preserving the draft.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-04 — Forged request account

**Given:** A valid token for entity A.
**When:** submit a body naming entity B.
**Then:** reject account mismatch instead of trusting the body.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-05 — Self-escalation

**Given:** An operator below policy-admin privilege.
**When:** assign a larger role or spending limit to itself.
**Then:** deny and emit a scoped audit event.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-06 — Membership expiry

**Given:** A committee member removed through enterprise identity.
**When:** reuse an old active session to approve.
**Then:** recheck current role and reject when no longer eligible.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-07 — Scoped export

**Given:** An adviser scoped to two portfolios.
**When:** request a group-wide capital export.
**Then:** exclude unauthorized entities and records.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-08 — Cross-entity legs

**Given:** A plan containing payments by two subsidiaries.
**When:** approve with only one entity authority.
**Then:** leave the other leg unapproved and unexecuted.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-09 — Independent currencies

**Given:** A group with USD and JPY reporting accounts.
**When:** aggregate the management view.
**Then:** retain original amounts and use explicit dated FX observations.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-ENTITY-10 — Relationship revocation

**Given:** An active group/adviser link.
**When:** revoke and immediately submit new work.
**Then:** deny future actions without rewriting prior ownership history.

**Environment:** Native API + identity/ledger lab. **Evidence:** `evidence/CR11-ENTITY-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-RESERVE — Native service + transactional multi-replica ledger

## CR11-RESERVE-01 — Capacity formula

**Given:** Available 1000, protected 400 and remaining authority 250 atoms.
**When:** compute allocation capacity.
**Then:** return exactly 250 atoms.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-02 — Protected floor

**Given:** A plan exceeding available less protected funds.
**When:** attempt atomic reservation.
**Then:** reject with no partial hold or policy consumption.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-03 — Existing hold counted once

**Given:** AVAILABLE already excludes an existing hold.
**When:** compute snapshot and new reservation.
**Then:** avoid subtracting that hold twice.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-04 — Mandate exhaustion

**Given:** Cash above the floor but only 10 atoms of authority.
**When:** request 11 atoms.
**Then:** deny despite sufficient cash.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-05 — Concurrent allocation

**Given:** One account with capacity for 20 equal plans.
**When:** submit 100 distinct plans through multiple replicas.
**Then:** accept at most 20 and preserve nonnegative capacity.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-06 — Duplicate operation

**Given:** One stable operation ID with identical body.
**When:** retry concurrently after response loss.
**Then:** return one existing reservation.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-07 — Conflicting duplicate

**Given:** One existing operation ID.
**When:** reuse it with changed amount or destination.
**Then:** return IDEMPOTENCY_CONFLICT with no new effect.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-08 — Pending deposit exclusion

**Given:** A pending deposit below required confirmation.
**When:** plan a reserve allocation.
**Then:** exclude the deposit from AVAILABLE.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-09 — Encumbered capital exclusion

**Given:** A balance pledged to an existing product.
**When:** plan capability funding.
**Then:** exclude encumbered funds through the authoritative ledger.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-RESERVE-10 — Soft budget is not money

**Given:** Two departments share one actual portfolio balance.
**When:** reserve under both soft budgets.
**Then:** enforce the common financial ceiling rather than summing budgets.

**Environment:** Native service + transactional multi-replica ledger. **Evidence:** `evidence/CR11-RESERVE-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-VALUE — Native calculator + quote adapter lab

## CR11-VALUE-01 — Stale reserve price

**Given:** A reporting-currency floor and expired quote.
**When:** calculate executable reserve capacity.
**Then:** return PRICE_STALE rather than a spendable valuation.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-02 — Conservative atom rounding

**Given:** A conversion yielding fractional native atoms.
**When:** derive a required protected floor.
**Then:** round upward without floating-point drift.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-03 — Invalid market inputs

**Given:** Zero, negative, NaN or infinite prices.
**When:** calculate or replenish.
**Then:** reject before creating a trade.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-04 — Bounded stress haircut

**Given:** An accepted price and configured haircut.
**When:** derive the protected floor.
**Then:** use the approved conservative price and exact rounding.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-05 — Replenishment cooldown

**Given:** An AUTO policy with a recent accepted top-up.
**When:** trigger many new observations.
**Then:** create no second active replenishment within the limit.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-06 — Source asset restriction

**Given:** An AUTO policy authorizing one source asset.
**When:** propose conversion from another asset.
**Then:** deny without an order.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-07 — Lifetime turnover

**Given:** Repeated top-ups within individual caps.
**When:** cross the cumulative authorized turnover.
**Then:** stop even when the new order alone is small.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-08 — Quote expiry before execution

**Given:** An approved plan with a stale firm quote.
**When:** submit after expiration.
**Then:** require renewed matching approval or an explicitly valid bound.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-09 — Unknown conversion

**Given:** A venue times out after possible execution.
**When:** trigger retry and reserve recomputation.
**Then:** retain uncertainty and do not duplicate or reverse the trade.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-VALUE-10 — Suggest is read/plan only

**Given:** A SUGGEST policy under its lower band.
**When:** run the scheduled evaluator.
**Then:** produce a proposal with zero executed orders.

**Environment:** Native calculator + quote adapter lab. **Evidence:** `evidence/CR11-VALUE-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-TCO — Native Decimal calculator + evidence fixtures

## CR11-TCO-01 — Worked ownership case

**Given:** 20m tasks/year, $0.01/task, three years; $50k plus $65k/year local.
**When:** calculate comparison.
**Then:** return $600000 versus $245000 and the defined break-even.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-02 — Quality equivalence

**Given:** A cheaper recipe below the workload acceptance threshold.
**When:** rank acquisition alternatives.
**Then:** exclude it from an equivalent-savings claim.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-03 — Unknown cost

**Given:** A route missing an operating or hardware cost.
**When:** calculate total cost.
**Then:** preserve unknown instead of silently using zero.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-04 — Unit separation

**Given:** BTX atoms, USD cents and task units.
**When:** import cost lines.
**Then:** reject ambiguous or mismatched unit arithmetic.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-05 — Hardware counted once

**Given:** An upfront hardware purchase plus annual allocated costs.
**When:** produce total cost.
**Then:** detect duplicated hardware allocation or require explicit allocation policy.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-06 — Utilization sensitivity

**Given:** Same hardware with low and high accepted-task utilization.
**When:** compare ownership cases.
**Then:** recalculate per-task results without fixed universal savings.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-07 — Horizon boundaries

**Given:** A malformed, zero or excessive planning horizon.
**When:** submit a workload.
**Then:** reject or enforce the finite supported horizon.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-08 — Forecast versus actual

**Given:** A predicted saving and later measured report.
**When:** aggregate a board statement.
**Then:** keep assumptions and actual observations separate.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-09 — Private workload inputs

**Given:** A local feasibility summary without raw prompts.
**When:** run hosted comparison.
**Then:** complete without collecting private prompt or KV state.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-TCO-10 — External route stays planning

**Given:** An external-service route wins the comparison.
**When:** accept its plan preview.
**Then:** do not route inference calls or purchase service automatically.

**Environment:** Native Decimal calculator + evidence fixtures. **Evidence:** `evidence/CR11-TCO-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-APPROVE — Native approval service + real identity lab

## CR11-APPROVE-01 — Distinct-person quorum

**Given:** A two-person rule and two sessions of one person.
**When:** approve through both sessions.
**Then:** count one person and keep quorum pending.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-02 — Initiator exclusion

**Given:** An initiator-excluded committee rule.
**When:** have the initiator approve.
**Then:** record or reject as specified but never count toward quorum.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-03 — Changed allocation

**Given:** An approved immutable plan.
**When:** change amount, payer, recipient or recipe dependency.
**Then:** invalidate the old matching approval before execution.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-04 — Changed policy

**Given:** A prepared decision under an older reserve policy.
**When:** revoke or replace policy generation.
**Then:** deny submit until authority matches.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-05 — Changed committee

**Given:** An approval under a superseded rule.
**When:** execute with that decision.
**Then:** recheck rule digest and current accepted membership.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-06 — Veto

**Given:** A veto-enabled rule with approvals plus a valid rejection.
**When:** attempt execution.
**Then:** deny while veto remains active.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-07 — Decision withdrawal

**Given:** A previously counted approver withdraws.
**When:** execute afterward.
**Then:** count only the latest valid decision.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-08 — Decision expiration

**Given:** Quorum assembled from expired decisions.
**When:** submit the allocation.
**Then:** return approval required.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-09 — Two authorities

**Given:** A valid financial committee approval but no local device grant.
**When:** request runtime preparation.
**Then:** keep finance authorization separate and request local permission.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-APPROVE-10 — Role-body mismatch

**Given:** A token for one person/role.
**When:** submit an ApprovalDecision naming another.
**Then:** reject forged actor before counting.

**Environment:** Native approval service + real identity lab. **Evidence:** `evidence/CR11-APPROVE-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-PLAN — Native DAG planner + process executor

## CR11-PLAN-01 — Cycle rejection

**Given:** An allocation graph with a dependency cycle.
**When:** plan execution.
**Then:** reject without reserving or dispatching a child.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-02 — Missing dependency

**Given:** A leg naming a nonexistent prerequisite.
**When:** validate allocation.
**Then:** reject the inconsistent graph.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-03 — Finite graph

**Given:** More than 32 legs or depth greater than 16.
**When:** submit a plan.
**Then:** reject before expensive expansion.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-04 — Stable child identities

**Given:** An authorized parent retried after coordinator restart.
**When:** resume children.
**Then:** reuse each exact child operation ID and intent.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-05 — Partial conversion

**Given:** Conversion succeeds and funding terms expire.
**When:** continue the parent saga.
**Then:** retain BTX and return explicit PARTIAL without auto-reversal.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-06 — Unknown child

**Given:** One child may have signed or broadcast.
**When:** cancel or retry the parent.
**Then:** retain its hold and enter reconciliation.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-07 — Fenced execution

**Given:** Two replicas contend for the same accepted allocation.
**When:** dispatch simultaneously.
**Then:** one valid fenced owner controls each financial child.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-08 — Pre-effect cancellation

**Given:** No child has any external effect.
**When:** cancel the allocation.
**Then:** release only safe reservations atomically.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-09 — Post-effect cancellation

**Given:** A child already converted or broadcast.
**When:** cancel the allocation.
**Then:** stop new work but preserve completed and uncertain effects.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PLAN-10 — Separate entity approvals

**Given:** A multi-entity graph with incomplete authorization.
**When:** execute eligible branches.
**Then:** never use one entity approval for another entity funds.

**Environment:** Native DAG planner + process executor. **Evidence:** `evidence/CR11-PLAN-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-LEDGER — Actual native regtest + custody + database fault lab

## CR11-LEDGER-01 — Customer lot mapping

**Given:** Two customers fund the same programme.
**When:** execute native funding.
**Then:** preserve one exact customer-action-to-lot/outpoint mapping.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-02 — Signer crash

**Given:** Signer persists a signature then response is lost.
**When:** restart gateway and signer client.
**Then:** recover exact signed bytes without a second spend.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-03 — Broadcast ambiguity

**Given:** Native broadcast succeeds but response is lost.
**When:** retry after all workers restart.
**Then:** rebroadcast identical bytes or reconcile the original transaction.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-04 — Reorg correction

**Given:** A confirmed funding transaction is reorganized.
**When:** observe chain change.
**Then:** correct status without granting duplicate spend capacity.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-05 — Known secret persists

**Given:** A release secret was learned before reorg.
**When:** reconcile financial rollback.
**Then:** retain knowledge while updating settlement state.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-06 — Refund beneficiary

**Given:** A custodial contribution becomes natively refundable.
**When:** execute refund and customer credit.
**Then:** credit the exact original beneficiary under terms.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-07 — No lifetime recycling

**Given:** A spent allocation is later refunded.
**When:** request another spend beyond lifetime cap.
**Then:** deny until new authority is explicitly approved.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-08 — Fee conservation

**Given:** Fee cap exceeds actual settled fees.
**When:** settle the child.
**Then:** release unused reservation and recognize actual fees once.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-09 — Database/signing boundary

**Given:** Database outage occurs during external signer call.
**When:** recover outbox ownership.
**Then:** avoid assuming a database transaction rolled back the signature.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LEDGER-10 — Backup recovery

**Given:** Restore custody and ledger backups in an isolated lab.
**When:** reconcile and refund a valid lot.
**Then:** preserve native signing rights, customer attribution and history.

**Environment:** Actual native regtest + custody + database fault lab. **Evidence:** `evidence/CR11-LEDGER-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-PROGRAM — Native programme + bounty/release process lab

## CR11-PROGRAM-01 — Outcome-defined objective

**Given:** A programme references a workload and evidence threshold.
**When:** publish programme.
**Then:** retain exact objective without selecting a mandatory model brand.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-02 — Independent sponsors

**Given:** Two entities join and fund.
**When:** observe progress and native outputs.
**Then:** show separate commitments and refund controllers.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-03 — Membership not consent

**Given:** A member joins without financial authorization.
**When:** request programme debit.
**Then:** require a separate approved allocation.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-04 — No invented pool

**Given:** A programme has a large aggregate budget.
**When:** generate API and UI views.
**Then:** do not create pooled escrow or transferable security rights.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-05 — Native evaluation authority

**Given:** A supplier reports a successful benchmark.
**When:** attempt award from the report alone.
**Then:** retain the committed native evaluator/award rules.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-06 — Evidence privacy

**Given:** Private sponsor evidence under member access.
**When:** query from another member or public scope.
**Then:** enforce declared visibility.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-07 — Refund terms

**Given:** A programme closes without success.
**When:** request refunds.
**Then:** use each native lot condition rather than a programme button guarantee.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-08 — Terms revision

**Given:** A new programme objective changes native references.
**When:** fund under old approvals.
**Then:** require exact renewed terms/authority.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-09 — Supplier proceeds

**Given:** An actual claim completes.
**When:** generate treasury and fee report.
**Then:** recognize actual proceeds and fees, not nominal bounty size.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PROGRAM-10 — Replicated deployment

**Given:** A funded output reaches 100 devices.
**When:** record programme impact.
**Then:** count deployments without multiplying acquired rights or principal.

**Environment:** Native programme + bounty/release process lab. **Evidence:** `evidence/CR11-PROGRAM-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-HOLD — Native holdings + local runtime fixture

## CR11-HOLD-01 — Public free holding

**Given:** A public model acquired without payment.
**When:** record portfolio holding.
**Then:** show zero acquisition cost or defined allocation, no fabricated price.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-02 — Exact recipe identity

**Given:** Same weights with different adapter scales.
**When:** record positions.
**Then:** keep distinct recipe/lock identities.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-03 — Rights independence

**Given:** A release contribution and public resource.
**When:** display acquired position.
**Then:** do not infer exclusive IP or model revenue rights.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-04 — Shared base allocation

**Given:** Three recipes reuse one paid base.
**When:** report aggregate acquisition cost.
**Then:** count the base once under the chosen allocation method.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-05 — Ready is local evidence

**Given:** Finance is confirmed but model is not loaded.
**When:** read position status.
**Then:** do not report local runtime READY.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-06 — Lock update

**Given:** A channel points to a new model.
**When:** reuse a locked position.
**Then:** retain exact old lock until authorized update.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-07 — Retirement is not deletion

**Given:** A user retires the hosted management position.
**When:** observe local files and active session.
**Then:** preserve public files and lease-safe local behavior.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-08 — Provider exit

**Given:** A customer disconnects the CEX.
**When:** use acquired public capability.
**Then:** continue locally without a provider heartbeat.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-09 — Cost not liquid mark

**Given:** A useful private capability has an acquisition cost.
**When:** calculate reserve NAV.
**Then:** exclude cognitive cost from spendable reserve.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-HOLD-10 — Private inventory

**Given:** A local client keeps reporting disabled.
**When:** inspect hosted holdings.
**Then:** do not infer or enumerate its private local inventory.

**Environment:** Native holdings + local runtime fixture. **Evidence:** `evidence/CR11-HOLD-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-PRODUCT — Native catalogue + existing product adapter lab

## CR11-PRODUCT-01 — Eligibility

**Given:** A product exists but customer is ineligible.
**When:** request referral or execution.
**Then:** return explicit eligibility result before effects.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-02 — Referral is not execution

**Given:** An approved introduction request.
**When:** complete referral.
**Then:** do not create a trade, loan or funded contract.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-03 — Actual rights

**Given:** A partner offer references a credit or hedge contract.
**When:** display product.
**Then:** show actual provider/contract not a BTX-created security.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-04 — Fee state

**Given:** A product card is clicked but no contract executes.
**When:** run revenue reporting.
**Then:** book no execution/referral fee without its contracted event.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-05 — Encumbrance

**Given:** Partner credit places a hold on BTX.
**When:** request native capability funding.
**Then:** observe reduced actual availability.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-06 — Firm quote expiry

**Given:** A partner quote expires after draft approval.
**When:** execute through its adapter.
**Then:** enforce quote/authorization bounds.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-07 — Data sharing consent

**Given:** A hardware partner needs deployment details.
**When:** create referral.
**Then:** send only the customer-approved bounded data.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-08 — Adapter outage

**Given:** One external product service is unavailable.
**When:** browse public capability and query balances.
**Then:** isolate failure from core discovery and finance state.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-09 — Existing engine

**Given:** A capital plan references OTC conversion.
**When:** execute eligible order.
**Then:** use actual venue execution rather than fabricated native terms.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRODUCT-10 — No phantom yield

**Given:** A customer deposits BTX.
**When:** show reserve page.
**Then:** do not invent staking yield or automatic rehypothecation.

**Environment:** Native catalogue + existing product adapter lab. **Evidence:** `evidence/CR11-PRODUCT-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-REPORT — Native reporting + export validators

## CR11-REPORT-01 — Snapshot consistency

**Given:** Balances change during a large report.
**When:** paginate and export.
**Then:** bind to a consistent snapshot or explicit per-source observations.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-02 — Separate values

**Given:** Cash, research commitments and capability costs.
**When:** render an executive report.
**Then:** keep three dimensions separate without invented NAV.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-03 — Entity scope

**Given:** A family adviser lacks one entity entitlement.
**When:** export a group report.
**Then:** exclude unauthorized data.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-04 — FX freshness

**Given:** A missing or stale reporting-currency rate.
**When:** generate valuation.
**Then:** show unavailable valuation without substituting zero.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-05 — FOCUS edition

**Given:** Compatible cost records under pinned FOCUS1.3.
**When:** export and validate.
**Then:** match that edition and its supported extension rules.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-06 — Duplicate invoice

**Given:** Same vendor invoice/period imported twice.
**When:** rebuild cost allocation.
**Then:** deduplicate or explicitly flag duplicate records.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-07 — Assumption provenance

**Given:** Forecast savings later differ from observed spend.
**When:** produce performance comparison.
**Then:** retain original assumption version and actual period.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-08 — Actual revenue

**Given:** Deposits, funding principal and one executed fee.
**When:** compute revenue.
**Then:** include only the actual earned fee on its proper basis.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-09 — History correction

**Given:** A receipt or report is corrected.
**When:** inspect prior links.
**Then:** retain immutable original and explicit superseding record.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-REPORT-10 — Spreadsheet injection

**Given:** Labels begin with formula-control characters.
**When:** export CSV for office tools.
**Then:** escape safely without changing canonical signed source data.

**Environment:** Native reporting + export validators. **Evidence:** `evidence/CR11-REPORT-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-LOCAL — Actual local client + native peers + runtime

## CR11-LOCAL-01 — Walletless acquisition

**Given:** A clean hosted client with no monetary node.
**When:** acquire public capability.
**Then:** verify and prepare without wallet funding or full chain sync.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-02 — Locality reuse

**Given:** Resident base and LAN adapter plus remote hint.
**When:** ensure approved capability.
**Then:** use eligible lower-TTC local path without needless full download.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-03 — Owner grant

**Given:** A handoff has valid CEX signature but missing local grant.
**When:** request preparation.
**Then:** ask for local approval without executing.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-04 — CFO not OS authority

**Given:** A financial approval requests an untrusted executable.
**When:** import handoff.
**Then:** retain independent software trust requirement.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-05 — Gateway outage

**Given:** Public capability is already ready.
**When:** disconnect hosted provider.
**Then:** continue local use and safe lease lifecycle.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-06 — Package substitution

**Given:** Provider returns changed bytes under the expected package ID.
**When:** import package.
**Then:** reject identity mismatch before load.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-07 — Device replay

**Given:** A handoff for device A is replayed to B.
**When:** accept on B.
**Then:** deny caller/device mismatch.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-08 — Physical cancellation

**Given:** A device transfer remains in flight after logical cancel.
**When:** release the hosted job.
**Then:** retain physical buffers until backend fence confirms safety.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-09 — Credential isolation

**Given:** CEX tokens and cloud sentinels are installed.
**When:** run acquisition and runtime.
**Then:** no token appears in model, package, process environment or peer traffic.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-LOCAL-10 — Coarse reporting

**Given:** Owner opts into readiness summary only.
**When:** complete deployment.
**Then:** send no raw prompts, KV, absolute paths or complete inventory.

**Environment:** Actual local client + native peers + runtime. **Evidence:** `evidence/CR11-LOCAL-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-AUTH — Actual OAuth profile + native gateway

## CR11-AUTH-01 — Wrong sender key

**Given:** A financial token bound to key A.
**When:** use it with key B proof.
**Then:** deny token use.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-02 — DPoP replay

**Given:** An already accepted proof.
**When:** reuse it as a new request.
**Then:** reject proof replay while business idempotency stays separate.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-03 — Body substitution

**Given:** A valid proof for route but altered plan body.
**When:** submit financial action.
**Then:** reject unmatched immutable approval digest.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-04 — Audience mismatch

**Given:** A catalogue token for another audience.
**When:** call reserve execution.
**Then:** deny.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-05 — Public client secrecy

**Given:** A desktop installer and configuration.
**When:** inspect distributed credentials.
**Then:** contain no confidential shared OAuth secret.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-06 — Read-only scope

**Given:** A catalogue/read token.
**When:** POST approval or execution.
**Then:** deny before state mutation.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-07 — Provider key compromise

**Given:** An operational signer is revoked.
**When:** create new signed handoff.
**Then:** reject new authority while preserving historic records.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-08 — Root enrollment

**Given:** A package includes a new provider root.
**When:** attempt automatic enrollment.
**Then:** require independently accepted provider policy.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-09 — Browser request forgery

**Given:** Cross-origin malicious page targets local/gateway effects.
**When:** trigger browser request.
**Then:** enforce session/origin/profile protections.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-AUTH-10 — SSRF boundary

**Given:** A remote object references private metadata endpoint.
**When:** fetch or refer.
**Then:** deny unless explicitly approved infrastructure under safe policy.

**Environment:** Actual OAuth profile + native gateway. **Evidence:** `evidence/CR11-AUTH-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-PRIV — Packet capture + multi-tenant process lab

## CR11-PRIV-01 — Reporting default

**Given:** Fresh local connector enrollment.
**When:** prepare and run capability.
**Then:** no local telemetry is sent by default.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-02 — Private response cache

**Given:** Two customers request account state.
**When:** exercise cache paths.
**Then:** never serve one customer data to another.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-03 — Event partition

**Given:** An event cursor belongs to another entity/filter.
**When:** resume stream.
**Then:** deny mismatch.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-04 — Secret sentinels

**Given:** Known fake secrets appear in private configuration.
**When:** export/log all public surfaces.
**Then:** find no sentinel in unauthorized outputs.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-05 — Prompt and KV

**Given:** A real local runtime uses private input.
**When:** exercise hosted reporting.
**Then:** no input or cached state reaches the hosted service.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-06 — Aggregate analytics

**Given:** A tiny identifiable cohort.
**When:** publish analytics.
**Then:** enforce explicit policy and minimum cohort controls.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-07 — Export credential exclusion

**Given:** A customer exports provider records.
**When:** inspect archive.
**Then:** exclude login tokens, private keys and bearer capabilities.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-08 — Adviser revocation

**Given:** An adviser loses rights mid-export.
**When:** continue a queued job.
**Then:** stop unauthorized new disclosure under explicit snapshot policy.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-09 — Financial retention distinction

**Given:** A user opts out of product analytics.
**When:** process an existing transaction.
**Then:** honor analytics choice while retaining required authorized financial history.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PRIV-10 — Pairwise device identity

**Given:** One device connects to two CEXs.
**When:** inspect provider-visible identifiers.
**Then:** use distinct pairwise identifiers and no global private tracking ID.

**Environment:** Packet capture + multi-tenant process lab. **Evidence:** `evidence/CR11-PRIV-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-UX — Built portal + browser accessibility lab

## CR11-UX-01 — Six primary screens

**Given:** A new customer account.
**When:** complete the main navigation.
**Then:** find Overview, Reserves, Capabilities, Build, Approvals and Activity without terminal use.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-02 — Persistent payer

**Given:** A user moves from group overview to funding.
**When:** review final packet.
**Then:** show exact legal payer and portfolio.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-03 — One decision packet

**Given:** A normal approved workflow.
**When:** review and authorize.
**Then:** present all effects coherently without per-packet prompts.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-04 — Independent local permission

**Given:** Finance approval succeeds before device authorization.
**When:** continue browser journey.
**Then:** identify the remaining local permission separately.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-05 — Duplicate click

**Given:** User clicks execute twice during delay.
**When:** observe financial executor.
**Then:** one business operation occurs.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-06 — Unknown outcome copy

**Given:** A broadcast response is lost.
**When:** view Activity.
**Then:** show reconciliation and no unsafe retry-new-payment CTA.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-07 — Keyboard and reader

**Given:** Keyboard-only and screen-reader user.
**When:** complete acquisition and approval.
**Then:** meet WCAG2.2AA focus, labels and status requirements.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-08 — Session reauthentication

**Given:** Login expires during review.
**When:** reauthenticate and return.
**Then:** retain draft but recheck current plan and permissions.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-09 — Localized units

**Given:** Japanese and English locales.
**When:** display and submit money.
**Then:** preserve canonical atom/currency values without truncating payer or amount.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-UX-10 — Free public journey

**Given:** A public capability is selected.
**When:** acquire under finite local grant.
**Then:** no compulsory exchange payment, new wallet or forced subscription.

**Environment:** Built portal + browser accessibility lab. **Evidence:** `evidence/CR11-UX-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-SCALE — Measured multi-process load + persistence lab

## CR11-SCALE-01 — Read load

**Given:** Declared hardware and catalogue snapshot.
**When:** run 1000 read requests per second.
**Then:** report latency, errors and resource use honestly.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-02 — Write load

**Given:** Real transactional policy/planning service.
**When:** run 100 writes per second.
**Then:** preserve consistency and publish measured queue behavior.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-03 — History scale

**Given:** 100000 mixed history records.
**When:** query/report with pagination.
**Then:** maintain bounded memory and snapshot integrity.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-04 — Queued jobs

**Given:** 10000 bounded background jobs.
**When:** cancel and recover subsets.
**Then:** keep resource limits and fairness.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-05 — Body bound

**Given:** A body exceeding 1MiB or graph limits.
**When:** submit it.
**Then:** reject before unbounded allocation or signature work.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-06 — Failure isolation

**Given:** Product/report service is slow.
**When:** serve native finance reconciliation.
**Then:** prevent auxiliary starvation of critical work.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-07 — Slow export consumer

**Given:** A client stops reading a large export.
**When:** hold the connection.
**Then:** bound buffers and detach safely.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-08 — Leader crash

**Given:** Current fenced financial owner dies.
**When:** elect/recover another worker.
**Then:** do not duplicate external effects.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-09 — Cursor expiry

**Given:** Retention truncates a consumer position.
**When:** resume cursor.
**Then:** return CURSOR_TOO_OLD and reconciliation route.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-SCALE-10 — Evidence truth

**Given:** Reference fixtures, simulations and native runs coexist.
**When:** generate final matrix.
**Then:** keep evidence tiers distinct and never infer hardware PASS.

**Environment:** Measured multi-process load + persistence lab. **Evidence:** `evidence/CR11-SCALE-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-PORT — Two gateways + local client + native economics

## CR11-PORT-01 — Dual provider

**Given:** A package served by A and B.
**When:** switch new discovery to B.
**Then:** preserve exact resource identity.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-02 — No spend failover

**Given:** A has an uncertain financial intent.
**When:** switch discovery to B.
**Then:** do not recreate the uncertain spend on B.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-03 — No key export

**Given:** A customer exports portable capital records.
**When:** import at B.
**Then:** require new authentication and never transfer secret authority.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-04 — Custody obligations

**Given:** A user leaves with pending custodial refund.
**When:** complete customer exit.
**Then:** keep original custodian responsibility visible and recoverable.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-05 — Old client

**Given:** A base HCP client connects to new server.
**When:** perform old public handoff.
**Then:** work without extension fields.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-06 — Old server

**Given:** A new client connects to base-only server.
**When:** request reserve committee workflow.
**Then:** refuse unsupported extension clearly.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-07 — Extension rollback

**Given:** New extension disabled after accepted operations.
**When:** reconcile existing state.
**Then:** keep recovery/exports while blocking new effects.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-08 — Revoked provider

**Given:** A provider is unenrolled locally.
**When:** send another handoff.
**Then:** deny new effects without deleting acquired public models.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-09 — Exact export

**Given:** Customer packages/locks are exported and imported.
**When:** verify digests.
**Then:** retain exact immutable commitments and attribution.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-PORT-10 — Actual cross-venue money

**Given:** Customer elects to move custodial BTX.
**When:** execute permitted withdrawal/deposit.
**Then:** use real rails; metadata export alone never creates a balance.

**Environment:** Two gateways + local client + native economics. **Evidence:** `evidence/CR11-PORT-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

# CR11-INTEGRATE — Full registered application + financial/runtime lab

## CR11-INTEGRATE-01 — Custody fee basis

**Given:** A time-varying separately billed balance.
**When:** calculate custody charge.
**Then:** use declared time-weighted base without including commitments twice.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-01/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-02 — Trading fees

**Given:** Actual executed orders plus unfilled proposals.
**When:** report execution revenue.
**Then:** use fills and actual fees only.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-02/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-03 — Funding principal

**Given:** A large funded programme.
**When:** report CEX revenue.
**Then:** exclude principal except a separately contracted earned fee.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-03/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-04 — Family purpose separation

**Given:** Strategic reserve, company deployment and foundation programme.
**When:** consolidate overview.
**Then:** retain legal payer, rights and instrument distinctions.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-04/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-05 — Measured savings

**Given:** A deployed workload with a versioned baseline.
**When:** record outcome.
**Then:** separate measurement from forecast and eliminate duplicate cost allocation.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-05/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-06 — Second partner onboarding

**Given:** A new CEX maps existing adapters.
**When:** run conformance.
**Then:** integrate without a BTX protocol fork.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-06/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-07 — Real route coverage

**Given:** Every new operation is registered.
**When:** invoke all 50 through the running gateway.
**Then:** reach actual validators/handlers rather than empty success stubs.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-07/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-08 — SDK parity

**Given:** Native/Python/TypeScript share canonical vectors.
**When:** hash/validate all new object types.
**Then:** match exact body IDs and rejection rules; real signatures are separate tests.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-08/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-09 — No remote inference

**Given:** A completed capital plan prepares local capability.
**When:** inspect network routes.
**Then:** expose no public prompt router or per-token payment path.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-09/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.

## CR11-INTEGRATE-10 — Regression closure

**Given:** Integrated v1.1 candidate.
**When:** run original120HCP plus relevant AHP/JIT cases.
**Then:** retain previous safety and behavior or record exact real blockers.

**Environment:** Full registered application + financial/runtime lab. **Evidence:** `evidence/CR11-INTEGRATE-10/` contains candidate fingerprint, actual commands, binary hashes, before/after state, assertions and sanitized logs. **Initial status:** NOT_RUN.


# Whole-system journeys — v1.1

Use isolated native test networks and actual registered services. Each journey records the full candidate and separate finance, package and local-runtime outcomes.

## CR11-J01 — Corporate workload to capital

**Setup:** A technical owner defines an accepted workload; finance holds a protected BTX reserve.
**Run:** Compare equivalent alternatives, select a local recipe, create allocation, obtain distinct approvals, fund where required, hand off and verify a useful local result.
**Required result:** Separate actual money, forecast/actual cost, local authorization and readiness; preserve the reserve floor.
**Evidence:** `evidence/CR11-J01/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J02 — Institutional reserve mandate

**Setup:** An institutional legal account with existing custody and OTC adapters.
**Run:** Establish a reserve policy, approve bounded replenishment, execute an actual test order and allocate to a native capability release.
**Required result:** Mandate and quote limits hold, reporting reconciles and no inference hot-path charge is created.
**Evidence:** `evidence/CR11-J02/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J03 — Family operating companies

**Setup:** A principal, adviser, two companies and foundation with separate accounts.
**Run:** Draft a group programme, choose each payer, obtain separate authority and deploy the output to permitted company devices.
**Required result:** Group visibility never pools funds or authorizes an adviser debit.
**Evidence:** `evidence/CR11-J03/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J04 — Foundation research

**Setup:** A foundation has a finite research allocation and committed native bounty terms.
**Run:** Join a programme, approve one lot, process submission/evaluation under native rules and claim or refund as appropriate.
**Required result:** No equity, revenue right or indefinite spend is inferred from the sponsorship.
**Evidence:** `evidence/CR11-J04/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J05 — Free cold acquisition

**Setup:** A clean walletless client and a public capability.
**Run:** Discover via hosted catalogue, pair device, accept finite local grant, verify package and acquire from native peers.
**Required result:** No wallet synchronization, CEX toll or untrusted software installation occurs.
**Evidence:** `evidence/CR11-J05/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J06 — Resident base and LAN adapter

**Setup:** A base is resident and an exact compatible adapter is on LAN.
**Run:** Receive a CEX internet source hint, resolve locally, fetch only missing verified data and prepare runtime.
**Required result:** The same locked recipe completes with recorded reuse and no private inventory upload.
**Evidence:** `evidence/CR11-J06/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J07 — Reserve replenishment concurrency

**Setup:** Multiple replicas receive repeated low-reserve events.
**Run:** Run SUGGEST then separately authorized AUTO mode through cooldown, turnover and price changes.
**Required result:** One owned order at a time, no unintended trade in SUGGEST and safe ambiguous-order handling.
**Evidence:** `evidence/CR11-J07/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J08 — Committee changes mid-plan

**Setup:** A multi-person approval packet has nearly reached quorum.
**Run:** Change amount, revoke a role, expire a quote and retry final approval/submit.
**Required result:** No stale authority is accepted and the UI explains the specific new review.
**Evidence:** `evidence/CR11-J08/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J09 — Conversion partial success

**Setup:** A conversion is executed before native funding.
**Run:** Expire the funding terms, lose one response, restart workers and resume the parent allocation.
**Required result:** BTX remains in the account; no automatic reverse or duplicated conversion/funding.
**Evidence:** `evidence/CR11-J09/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J10 — Unknown native broadcast

**Setup:** Actual isolated native transaction dispatch loses its response.
**Run:** Restart all gateways, recover signer/outbox and reconcile the original bytes and outpoint.
**Required result:** One debit, one authorized native transaction and correct eventual receipt.
**Evidence:** `evidence/CR11-J10/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J11 — Independent co-sponsors

**Setup:** Three independent entities contribute to one programme.
**Run:** Aggregate progress, complete one claim and one refund branch under native terms.
**Required result:** Every customer lot and beneficiary remains independently attributed.
**Evidence:** `evidence/CR11-J11/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J12 — Refund and reserve authority

**Setup:** A funded lot reaches a valid native refund condition.
**Run:** Prepare, authorize, execute, confirm and credit refund; submit a new allocation.
**Required result:** Balance restores but lifetime mandate remains consumed unless explicitly renewed.
**Evidence:** `evidence/CR11-J12/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J13 — Infrastructure partner

**Setup:** A capital plan requires additional approved hardware.
**Run:** Request a partner offer and referral, then record actual separately authorized product progression.
**Required result:** Referral is not a loan, GPU purchase or funded BTX output; fees follow real events.
**Evidence:** `evidence/CR11-J13/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J14 — Collateral interaction

**Setup:** Existing partner product encumbers portfolio BTX.
**Run:** Run concurrent funding and collateral updates through the real account adapter.
**Required result:** Funds cannot be allocated twice and reserve snapshot states remain intelligible.
**Evidence:** `evidence/CR11-J14/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J15 — Board reporting

**Setup:** Multiple currencies, invoices, holdings and commitments exist.
**Run:** Import cost data, generate consistent entity/group reports, export pinned FOCUS fields and correct an observation.
**Required result:** No false NAV, double fees, stale zero valuation or forecast-as-actual saving.
**Evidence:** `evidence/CR11-J15/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J16 — Adviser revocation

**Setup:** An adviser has access to drafts and reports across selected entities.
**Run:** Revoke access during a queued export and attempted approval.
**Required result:** No new unauthorized disclosure or execution; historical audit remains intact.
**Evidence:** `evidence/CR11-J16/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J17 — Two-provider customer exit

**Setup:** Customer has acquired public capability and pending finance at provider A.
**Run:** Export exact packages/locks/receipts, disconnect A and enroll B for new discovery.
**Required result:** Local capability persists; A obligations stay attributed; no financial replay at B.
**Evidence:** `evidence/CR11-J17/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J18 — Accessible browser and agent parity

**Setup:** A first-time user and a scoped agent access the built portal and SDK.
**Run:** Complete workload, reserve review, approval, handoff and progress with keyboard/reader and typed APIs.
**Required result:** Both use identical immutable contracts and no terminal or unsafe token handoff.
**Evidence:** `evidence/CR11-J18/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J19 — Outage and load

**Setup:** Measured API/job load with one slow auxiliary product service.
**Run:** Fail gateway leader, database connections, report consumer and hosted connectivity while a local model is active.
**Required result:** Financial recovery remains fenced, resources bounded and local public use continues.
**Evidence:** `evidence/CR11-J19/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.

## CR11-J20 — Integrated candidate

**Setup:** Final fingerprint, baseline contract artifacts and all supported backends.
**Run:** Run50newoperations,190newcases,120basecases and relevant AHP/JIT journeys; obtain independent review.
**Required result:** Report actual evidence tiers, fix real blockers and stop for operator release approval.
**Evidence:** `evidence/CR11-J20/`; packet captures where relevant, exact native transaction/receipt references, local readiness trace, UI/SDK output and recovery logs. **Initial status:** NOT_RUN.
