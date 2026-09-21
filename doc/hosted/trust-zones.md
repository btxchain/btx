# Deployment and recovery checklist

## Required isolation

| Zone | Permitted access | Forbidden access |
|---|---|---|
| Public web/API | IDP validation, catalogue, typed business services | Native wallet RPC, private keys, local runtimes |
| Catalogue | Verified public object store, package cache | Customer financial ledger writes, signing |
| Finance orchestrator | Ledger reservation, typed executor, outbox | Model runtime execution, arbitrary source fetch |
| Native executor | Exact terms/template, custody backend, native observer | Caller-supplied shell/RPC names, unknown URLs |
| Signer | Audited native signing operation and lookup | Catalogue crawling, user prompts, internet metadata |
| Customer connector | Enrolled provider, owner-local capability API | Spending keys, unrestricted machine control |
| Local runtime | Verified model handles, local grant and approved device | CEX/OAuth/cloud credentials, public wallet API |

Production key references are provisioned locally/through approved secret infrastructure. Never store live keys in the YAML example. Conventional HTTPS at a hosted edge is not native end-to-end PQ.

## Preproduction evidence

Attach exact candidate/binary hashes, SBOM, native network identity, tested signer/script support, OAuth security profile, schema/API digest, independent audit, privacy inventory, per-profile conformance and recovery drill. No custody/FUNDING deployment from a simulated signer.

## Failure drills

Kill API before reply; kill executor after signing; lose broadcast response; reorganize test chain; exhaust ledger balance concurrently; revoke control signer; expire token; revoke paired device; remove gateway while public capability runs; restore custody and accounting backups together.

The runbook records the owner, authoritative state, safe retry, unsafe retry and customer-visible status for each fault. UNKNOWN signing or broadcast retains reservations. Rollback stops new work but keeps refund and reconciliation obligations alive.

## Launch approval record

Provider / legal venue: ____
Candidate fingerprint: ____
Profiles enabled and evidence: ____
Native network/genesis: ____
Custody/refund controller: ____
Independent security reviewer: ____
Incident contact: ____
Customer exit/export procedure: ____
Operator approval / date: ____
