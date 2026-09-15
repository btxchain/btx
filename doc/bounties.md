# Model bounties (0.34.7)

Proposed demand-side market on the model plane: fund creation and evaluation of
a model that matches published requirements **before** a winning `model_id`
exists. Release campaigns (supply-side: disclose an already-encrypted model)
remain a separate product path — see [modelnet/model-economy.md](modelnet/model-economy.md).

`CLIENT_VERSION_IS_RELEASE` is **false** in this tree. Schemas and RPC names
document the frozen product contract; implementation gates and evidence rows in
[contrib/modelnet/bounty/tests/acceptance-matrix.csv](../contrib/modelnet/bounty/tests/acceptance-matrix.csv)
decide readiness. This page is not a release announcement.

## Lifecycle

```
Requester                          Contributors / creators
    |                                      |
    v                                      v
 draft terms ──► validate ──► publish     inspect terms + council
    |              (signed)                    |
    v                                          v
 freeze funding round ◄── nominations/appointments
    |
    v
 wallet: prepare/sign/submit per-lot funding (escrow on chain)
    |
    v
 creator: commit ──► reveal submission
    |
    v
 evaluator: prepare ──► run (isolated) ──► publish report
    |
    v
 challenges (optional) ──► council policy approve award
    |
    v
 wallet: council sign/submit award ──► public payout or staged HTLC
    |
    +──► contributor refund path after refund_height if lot still unspent
    +──► swarm distribution of released model bytes (existing model network)
```

Coordination states (`OPEN`, funding progress, submission windows) are helper
views over signed records plus read-only chain attribution. They are not
consensus flags. There is **no** automatic on-chain award when a benchmark
passes.

## Two-leaf contributor escrow

Each contributor funds a **lot** with its own principal, fee reserve, and
**refund public key**. The wallet builds only supported P2MR trees (no new
opcode, council size n ≤ 8, heights < 500000000):

**Award branch:** `cltv_multi_pq(locktime, m, council_keys…)` — council
threshold signatures after the award locktime.

**Refund branch:** `refund(refund_height, contributor_refund_key)` — spendable
by the contributor after the disclosed height if the output is still unspent.

The wallet derives and checks the contributor’s refund key; the helper must not
substitute keys or mutate outputs after `freezebountyfundinground`. Refund
recovery does **not** require council cooperation, helper uptime, or indexers
— only maturity, unspent UTXO, and the contributor’s signing keys.

Round and lot identifiers are deterministic: terms id = SHA-384 of the signed
terms body; round id after appointments; lot id = D384(round_id ‖ ordinal). See
[contrib/modelnet/bounty/reference/CODEC.md](../contrib/modelnet/bounty/reference/CODEC.md).

## Staged HTLC (sealed / delayed release)

When terms require staged release, winner outputs use the existing SHA-256 HTLC
template layered on the **original** contributor refund lineage:

`mr(htlc_sha256(hash, claimant), refund(height, original_refund_key))`

Staging must not extend refund height or replace the contributor refund key
(BOUNTY-WALLET-016/017). Creator claims with preimage via
`preparebountyclaim` / `signbountyclaim` / `submitbountyclaim`. Same race
rules as 0.34.6 release HTLCs: one UTXO, one winning spend path.

## Trust and authority

Economy cards expose trust label
`COUNCIL_CUSTODIAL_AUTHORITY_WITH_INDIVIDUAL_REFUND_PATHS`:

| Party | What you trust | What you do not trust |
|---|---|---|
| Council M-of-N | Award-branch signatures if they act | Honesty, collusion resistance, liveness |
| Evaluators | Reports signed after local execution | Reports as chain truth or payment |
| Benchmarks | Repeatable checks under stated harness | Automatic enforcement by consensus |
| Contributors | Own refund keys after locktime | Council to return principal early |

Sealed review additionally trusts authorized reviewers with confidentiality.
Metadata authority on public objects is `SIGNED_PUBLICATION_REQUIRES_VERIFICATION`
— verify ML-DSA signatures and delegation before trusting tombstones or updates.

## Search and record AUTH

Bounty and capability objects enter the model search plane as signed envelopes
([schemas/SignedEnvelope.schema.json](../contrib/modelnet/bounty/schemas/SignedEnvelope.schema.json)).
Indexing must **verify** signatures and semantic checks before `Put`; never
accept `signed_ok` from untrusted input, tombstone before verify, or unsigned
overrides. `ModelSearchRecordV2` uses domain `BTX/ModelSearchRecord/v2`.

Network search is bounded, cancellable, and incomplete (`coverage.global_complete:
false`). `scope: LOCAL` sends no network requests. Query text may be visible to
peers consulted — same privacy model as [modelnet/search.md](modelnet/search.md).

## HTTP bridge (read-only)

Optional browser-facing `GET` routes expose **allowlisted read views** of search
and bounty state (for example normalized list pages with `items[]` and
`next_cursor`). They must not proxy wallet RPCs, evaluation execution,
`importbountyrecovery`, mandate creation, or any `sign*` / `submit*` method.

Authoritative interface remains JSON-RPC on `btxd` (proxy) or the helper unix
socket. See [modelnet/web-bridge-boundary.md](modelnet/web-bridge-boundary.md).

Reference static client (bounties list/detail only):
[contrib/modelnet/explorer-bounties](../contrib/modelnet/explorer-bounties/).

## Desktop GUI

The Qt client adds a **Bounties** tab parallel to Models: search and inspect
terms, fund a lot with explicit confirmation (amount, fees, council, refund
height/key), watch progress, export recovery material, and run recovery flows
without requiring terminal RPC for the primary journeys. GUI actions call the
same wallet boundaries as CLI (`prepare*` → user confirm → `sign*` →
`submit*`).

## Evaluation profiles

Installed profiles only:

| Profile | Execution |
|---|---|
| `EXACT_CHECKS` | Isolated process: hashes, sizes, formats, required files, caps |
| `REPRODUCIBLE_BENCHMARK` | Pinned local harness subprocess when installed |
| `STATISTICAL_BENCHMARK` | Pinned harness when installed |
| `REVIEWED_RESEARCH` | Review workflow when installed |

`getbountycapabilities` lists only profiles with real harness support.
`runbountyevaluation` is asynchronous, without wallet keys or arbitrary network.

## Contracts and RPCs

| Artifact | Path |
|---|---|
| JSON schemas | [contrib/modelnet/bounty/schemas/](../contrib/modelnet/bounty/schemas/) |
| Semantic checks | [contrib/modelnet/bounty/schemas/semantic-checks.json](../contrib/modelnet/bounty/schemas/semantic-checks.json) |
| RPC inventory | [contrib/modelnet/bounty/schemas/rpc-catalog.json](../contrib/modelnet/bounty/schemas/rpc-catalog.json) |
| RPC reference (this tree) | [bounty-rpc.md](bounty-rpc.md) |
| Example read API shape | [contrib/modelnet/bounty/docs/API_EXAMPLE.json](../contrib/modelnet/bounty/docs/API_EXAMPLE.json) |
| Native test contract | [contrib/modelnet/bounty/tests/TEST_CONTRACTS.md](../contrib/modelnet/bounty/tests/TEST_CONTRACTS.md) |

Agent rules: [AGENTS.md](../AGENTS.md).
