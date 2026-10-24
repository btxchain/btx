# BTX Swarm 0.35 — Wire protocol and records

Document: **BTX-SWARM-SPEC-03**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** Strict JSON, ML-DSA envelopes, typed command validators and pagination are implemented. Schemas distinguish executable contracts from target-only records.

## Encoding profile

**WIR-001.** `BTX-SWARM/1` uses canonical UTF-8 JSON with sorted keys, no insignificant whitespace, NFC strings, exact integers, booleans, null, arrays and objects. Floats, duplicate keys, surrogate code points, excessive nesting and oversized messages are rejected. This is the package's strict profile, not a claim of RFC 8785 compatibility. Numeric telemetry requiring fractions uses scaled integers with a declared unit, such as micro-loss or parts per million.

**WIR-002.** Immutable native-style object references are 96 lowercase hexadecimal characters. The package uses SHA-384 and domain-separated typed-object derivation; exact derivation is `codec.digest`, not a guessed formula. A byte digest and a typed-object digest are different namespaces. Monetary amounts on the wire are canonical non-negative decimal atom strings. Their parser's hard bound is an application safety limit, not an assertion about BTX issuance.

**WIR-003.** A peer envelope consists of `body` and base64 `signature`. Body contains `protocol`, `suite`, `sender`, `created_ms`, `expires_ms`, 48-character nonce and payload. The signing preimage is the literal domain `BTX-SWARM/1\0` followed by canonical body bytes. ML-DSA-44 signatures must have the expected 2,420-byte length. Public keys are checked as ML-DSA-44 and their DER bytes determine identity.

Live authentication accepts at most five seconds of future creation skew and a maximum sixty-second envelope lifetime. Authentication expiry is not an expiry of already committed research evidence. Archival evaluation verification checks the original signature and current evaluator eligibility independently of transport TTL.

## Commands and idempotency

Client command shape:

```json
{"kind":"work.claim","id":"stable-client-operation-id","body":{"realm":"<id96>","job":"task-1","generation":"<process-generation>","nonce":"<fresh-attempt-nonce>"}}
```

The server binds `actor` to verified signature identity, adds its committed time and retains original authorization. Semantic idempotency excludes transport signatures and timestamps; a retried request can receive a fresh authentication envelope without becoming a new mutation. Reusing one operation ID with different semantic content yields `IDEMPOTENCY_CONFLICT`. Both successful outcomes and typed rejections are durable.

A timeout after submission may mean unknown commit status. Clients must use the same semantic ID and consult `/result/{id}` or the committed record; they must not assume failure and create a second paid obligation or external action. Exactly-once effect execution is not promised for arbitrary tools. The current executors are bounded model/data operations, not arbitrary side-effecting shell commands.

The exact implemented method list and required fields are generated into `schemas/implemented-operations.json` from the reducers. `schemas/swarm.schema.json` describes structural wire constraints. Cross-object authority, term, generation, capacity and lineage checks remain semantic validations in code. A successful JSON Schema check is insufficient authorization.

## Read semantics and pagination

**WIR-004.** `/query` returns committed local materialized state and reports that it may lag the leader. It is not a linearizable quorum read and not a multi-page snapshot. Results include `next_cursor`; callers follow only returned cursors. The cursor binds kind, realm, parent scope and the final key. It is an opaque position, not a credential.

Public pages are limited to 1–1,000 records, default 256. Workers follow pages and enforce a 100,000-record bound. Internal invariant scans refuse truncation with `SCAN_RANGE_INCOMPLETE`; they must never calculate free capacity from an incomplete allocation set. Pagination may observe changes between pages; critical decisions must still pass an authoritative committed mutation with expected state/term checks.

## First-class records

| Record | Immutable or mutable reference | Meaning |
|---|---|---|
| ModelLineage | Immutable genesis identity | Family ancestry and licensing origin |
| Artifact | Immutable exact bytes | Model representation, dataset, KV payload or result |
| SwarmRealm | Genesis plus sequenced policies | Scope and authority, not a global scheduler |
| SwarmPresence | Signed expiring advertisement | Measured/capped availability, not hardware proof |
| WorkLease | Attempt/term/generation-bound | Executable ownership and finite resources |
| TrainingCohort | Sequenced compatible rounds | Base checkpoint, recipe and eligible islands |
| CandidateCheckpoint | Immutable proposed descendant | Parents, niche, recipe and provenance references |
| EvaluationReport | Immutable signed evidence | Fixed sample scope and measured paired outcomes |
| PromotionCertificate | Immutable report set | Policy-scoped graduation, not universal quality proof |
| EvolutionChannel | Monotonic local/realm pointer | Canary, activation and rollback state |
| SwarmPool | Immutable economic objective identity | Terms and funding/accounting scope |
| WorkReservation | Idempotent obligation | Bounded accepted terms, not automatically a payment |

Native Lab record enums do not yet accept all these new record families. A versioned bridge must register corresponding native records and provenance links without substituting the sidecar digest for an existing native record ID.

## Compatibility and error rules

Unknown methods, extra fields, unexpected suites and incompatible object versions fail closed. Do not silently reinterpret an old checkpoint, a different tensor layout or a financial accounting voucher as a stronger current protocol. Preserve immutable IDs through migration or create an explicit new representation/derivation relationship.

The generated error inventory records literal error codes in implementation. It is not proof that every code is reachable through every endpoint. Transport errors, absence, permission errors and cache misses should be normalized at privacy boundaries. Current private/absent metadata distinctions require further public-surface review.
