# Adapter and operations contract

## Existing interfaces

Reuse identity, eligibility, ledger, quote, custody, chain observer, native economics, package, audit and reporting. Each maps to an existing account/native operation rather than a generic method-name passthrough. Unknown outcomes are typed.

## Added interfaces

EntityDirectory resolves current legal relationships and distinct-person roles. ReserveView reads availability and encumbrance at a ledger sequence. ApprovalDirectory validates current role/rule generations. WorkloadEvidence supplies versioned quality/cost assumptions. HoldingsView records exact resources and rights. Programme maps independent sponsor lots. ProductCatalogue exposes actual provider offers and eligible actions.

## Reserve transaction

Authenticate → scope/legal-entity check → lock account/policy in stable order → load authoritative AVAILABLE and remaining mandate → check protected floor/exposure → persist idempotent reservation and outbox → commit → dispatch through fenced existing executor. No DB transaction spans a remote API or signer.

## Failure handling

**Stale prices:** stop valuation-dependent new effects; keep native balances visible. **Committee revocation:** invalidate new execution that no longer matches authority. **Signer/broadcast unknown:** retain hold and retrieve exact original operation. **Conversion partial:** retain acquired BTX; do not reverse without authority. **Reorg:** correct observations without forgetting release knowledge. **Gateway outage:** local public capability continues. **Customer exit:** export exact records, revoke future access, retain original custody/refund responsibility. **Provider compromise:** revoke new authority via accepted roots, not package-supplied keys.

## Deployment and recovery

Separate catalogue, authenticated business gateway, executor, custody and local-runtime trust zones. Use existing supervised services. Test multiple replicas, database failover, backup restoration, native refunds and extension rollback. Production rollout and release flags remain separate operator actions.

## Offline reference (not a ledger)

`contrib/modelnet/crf-reference/reference/reserve.py` models capacity, exact TCO decimals, allocation DAG validation and distinct-person quorum with synthetic amounts. SQLite there is an executable invariant model, not the exchange financial core, signer or OAuth server.

```bash
python3 contrib/modelnet/crf-reference/test_reference.py
```
