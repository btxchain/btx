# BTX MatMul v4/v4.2 — Provisional vs. Authenticated Chainwork

Audit finding: **P0.1 / C1** — the top activation blocker for the MatMul (v4/v4.2)
upgrade.

Status: design + implemented consensus-accounting core + chain-selection routing +
unit tests. Networking-layer follow-ups are enumerated with exact call sites and
are explicitly **not** unit-tested here (they require a live multi-node network).
The whole MatMul upgrade remains activation-disabled (all activation heights are
`INT32_MAX`); every behavioral change is gated behind `IsMatMulV4Active(height)`
and is therefore inert on mainnet and all public testnets today.

> Line numbers below track the branch base (this worktree). They are anchors, not
> contracts — grep the named symbol if a number has drifted.

---

## 1. The vulnerability

At MatMul heights a block header carries a **self-declared** `matmul_digest`
field. Header-level PoW acceptance is `CheckMatMulProofOfWork_Phase1`
(`src/pow.cpp`), which only checks

```
UintToArith256(block.matmul_digest) <= target(nBits)
```

`matmul_digest` is *not* proven to correspond to real MatMul work at the header
stage. The proof that the digest is the output of a genuine MatMul computation
lives in the product-committed verifier (`CheckMatMulProofOfWork_V4ProductCommitted`
/ `CheckMatMulProofOfWork_ProductCommitted` / `CheckMatMulProofOfWork_Freivalds` →
`matmul::v4::bmx4::VerifySketchBMX4C`, `src/pow.cpp`), which needs the **full block
body** (the committed sketch/product payload) and runs from `ContextualCheckBlock`
(`src/validation.cpp`).

Yet a header index is credited the **full** `GetBlockProof(nBits)` chainwork into
`CBlockIndex::nChainWork` the moment the header is accepted
(`BlockManager::AddToBlockIndex`, `src/node/blockstorage.cpp:357`), long before any
body arrives.

Consequence: an attacker with **no MatMul hardware** can pick `matmul_digest = 0`
(`<=` any target), supply contextually-correct dimensions / seeds / timestamps /
ASERT `nBits`, and withhold every body. Each header index then receives the same
authenticated-looking chainwork as a fully-verified block. That forged chainwork
poisons:

- `m_best_header` and everything derived from it;
- IBD state, `MinimumChainWork` decisions;
- direct-fetch / download selection (`FindNextBlocksToDownload`,
  `pindexBestKnownBlock`);
- header-lag / mining-readiness reporting;
- peer eviction/protection that compares peer chainwork;
- the assumevalid script-verification budget.

The SHA "header spam" gate (`CheckMatMulHeaderSpamGate`) is only a **rate
limiter**; it does not authenticate MatMul-calibrated chainwork.

---

## 2. Where chainwork lives today (findings)

### 2.1 Accumulation

`GetBlockProof(const CBlockIndex&)` (`src/chain.cpp:140`) converts `nBits` to an
expected-hash count. `nChainWork` is a **memory-only** field
(`CBlockIndex::nChainWork`, `src/chain.h:169`) — it is *not* serialized in
`CDiskBlockIndex`. It is (re)computed at exactly two sites, both with the same
recurrence `pprev->nChainWork + GetBlockProof(self)`:

- `BlockManager::AddToBlockIndex` (`src/node/blockstorage.cpp:357`) — header accept.
- `BlockManager::LoadBlockIndex` (`src/node/blockstorage.cpp:658`) — startup
  recompute from the on-disk index, walking indices in height order.

Because `nChainWork` is memory-only and recomputed from persisted `nBits`, its
"persistence" is really deterministic recomputation. We reuse that exact property
for authenticated work.

### 2.2 Validity tracking — the central invariant

`enum BlockStatus` (`src/chain.h:92`): `BLOCK_VALID_TREE` (2),
`BLOCK_VALID_TRANSACTIONS` (3), `BLOCK_VALID_CHAIN` (4), `BLOCK_VALID_SCRIPTS` (5),
plus `BLOCK_FAILED_VALID`/`BLOCK_FAILED_CHILD`. `nStatus` **is** persisted
(`CDiskBlockIndex::SERIALIZE_METHODS`, `src/chain.h:410`).

Ordering fact in `AcceptBlock` (`src/validation.cpp`, ≈10586→10615):

```
CheckBlock(...) && ContextualCheckBlock(...)   // <-- verifies the MatMul body proof
   ...then...
ReceivedBlockTransactions(...)                 // <-- RaiseValidity(BLOCK_VALID_TRANSACTIONS)
```

`ContextualCheckBlock` (`src/validation.cpp:10170`, MatMul proof at 10203) runs the MatMul body
verification when `consensusParams.fMatMulPOW && IsMatMulV4Active(nHeight)`. A block
only reaches `BLOCK_VALID_TRANSACTIONS` **after** its body's MatMul proof verifies.

> **Central invariant:** at a MatMul height,
> `pindex->IsValid(BLOCK_VALID_TRANSACTIONS)` is true **iff** the body arrived and
> its MatMul product-committed proof verified. This signal is already persisted in
> `nStatus`, and is already propagated across descendants by
> `ReceivedBlockTransactions` (`src/validation.cpp:9542-9576`, the
> `m_blocks_unlinked` walk).

### 2.3 Best-header selection

Three sites choose `m_best_header`, all keyed on raw `nChainWork`:

- `AddToBlockIndex` (`src/node/blockstorage.cpp:359`).
- `ChainstateManager::LoadBlockIndex` loop (`src/validation.cpp`, `CBlockIndexWorkComparator`).
- `ChainstateManager::RecalculateBestHeader` (`src/validation.cpp`).

### 2.4 Best-*chain* selection is already body-gated

`setBlockIndexCandidates` (ordered by `CBlockIndexWorkComparator`,
`src/node/blockstorage.cpp:254`) feeds `FindMostWorkChain`. Entries are inserted
**only** through `TryAddBlockIndexCandidate` (`src/validation.cpp:9412`), whose
callers all require `IsValid(BLOCK_VALID_TRANSACTIONS)` + `HaveNumChainTxs()`.
**A header-only forged block can never enter `setBlockIndexCandidates`.** Hence the
active tip and the best-*chain* computation are already immune to the forged-header
attack, and among the candidate blocks `nChainWork == authenticated work` (all
ancestors are `BLOCK_VALID_TRANSACTIONS`). This is why the active tip needs no
change.

### 2.5 Chainwork consumers, classified

| Consumer | Site | Fed by forged headers? | Action |
|---|---|---|---|
| IBD exit `chain.Tip()->nChainWork < MinimumChainWork()` | `validation.cpp:6116` | **No** — active tip body-gated | none needed (already authenticated); documented |
| best-*chain* `setBlockIndexCandidates`/`FindMostWorkChain` | `validation.cpp:8620` | **No** — body-gated | none needed; documented |
| assumevalid script-check budget `m_best_header->nChainWork >= MinimumChainWork()` | `validation.cpp:6884` | **Yes** | route → authenticated |
| header presync gate `m_best_header->nChainWork >= nMinimumChainWork` | `validation.cpp:10497` | **Yes** | route → authenticated |
| best-header selection (3 sites) | see 2.3 | **Yes** (pointer) | see §3.4 |
| per-peer `pindexBestKnownBlock` work compares | `net_processing.cpp` (many) | **Yes** | networking follow-up (§5) |
| peer protect-from-disconnect | `net_processing.cpp:3535` | **Yes** | networking follow-up (§5) |
| anti-DoS work threshold | `net_processing.cpp:3208,5602` | **Yes** | networking follow-up (§5) |
| chain-sync timeout / eviction | `net_processing.cpp:6496-6535` | **Yes** | networking follow-up (§5) |
| direct fetch `CanDirectFetch` compares | `net_processing.cpp:3432,3504` | **Yes** | networking follow-up (§5) |

---

## 3. Design: separate provisional from authenticated chainwork

### 3.1 New per-index quantity

Add a memory-only field mirroring `nChainWork`:

```cpp
arith_uint256 CBlockIndex::nAuthenticatedChainWork{};
```

Per-index **authenticated contribution**:

```cpp
bool IsBlockAuthenticated(const CBlockIndex& b, const Consensus::Params& p) {
    if (!p.IsMatMulV4Active(b.nHeight)) return true;          // pre-fork: header work authenticated on sight
    if (b.nStatus & BLOCK_FAILED_MASK) return false;          // failed body can never authenticate
    return (b.nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS; // body + MatMul proof verified
}
arith_uint256 GetBlockAuthenticatedProof(const CBlockIndex& b, const Consensus::Params& p) {
    return IsBlockAuthenticated(b, p) ? GetBlockProof(b) : arith_uint256{};
}
```

Accumulator recurrence (single source of truth, called from every maintenance
site):

```cpp
void UpdateAuthenticatedChainWork(CBlockIndex& b, const Consensus::Params& p) {
    b.nAuthenticatedChainWork =
        (b.pprev ? b.pprev->nAuthenticatedChainWork : arith_uint256{})
        + GetBlockAuthenticatedProof(b, p);
}
```

Properties:

- **Pre-fork byte-identical.** For any block at height `< nMatMulV4Height` the
  contribution is `GetBlockProof` unconditionally, so
  `nAuthenticatedChainWork == nChainWork`. All activation heights are `INT32_MAX`
  today ⇒ `IsMatMulV4Active` false everywhere ⇒ the field equals `nChainWork`
  identically on every existing network. The upgrade is inert until activation.
- **Connected chains byte-identical.** For any block whose entire ancestry is
  `BLOCK_VALID_TRANSACTIONS` (the active tip and every `setBlockIndexCandidates`
  member), every contribution is `GetBlockProof`, so
  `nAuthenticatedChainWork == nChainWork`. Routing the active-tip/candidate
  consumers is therefore a behavioral no-op.
- **Forged headers contribute zero.** A MatMul header-only block is
  `BLOCK_VALID_TREE` (< `BLOCK_VALID_TRANSACTIONS`), no `BLOCK_FAILED` bit ⇒
  contribution 0 ⇒ `nAuthenticatedChainWork(child) == nAuthenticatedChainWork(parent)`.
  A chain of thousands of forged headers is flat in authenticated work while its
  `nChainWork` climbs.

### 3.2 Maintenance sites (all hold `cs_main`)

1. `AddToBlockIndex` (`blockstorage.cpp`): right after `nChainWork`. New MatMul
   header ⇒ contribution 0 ⇒ authenticated work = parent's. Pre-fork ⇒ full.
2. `ReceivedBlockTransactions` (`validation.cpp`): after
   `RaiseValidity(BLOCK_VALID_TRANSACTIONS)` for the block itself, and for every
   block dequeued in the existing `m_blocks_unlinked` descendant walk. This is the
   **promotion** path — a MatMul block's contribution flips `0 → GetBlockProof` the
   instant its body's MatMul proof verifies, and the same walk that propagates
   `m_chain_tx_count` to now-connected descendants re-derives their authenticated
   work (parents dequeued before children ⇒ recurrence exact).
3. `BlockManager::LoadBlockIndex` (`blockstorage.cpp`): in the height-ordered
   recompute loop, right after `nChainWork`. This is the **restart/reindex** path;
   deterministic because it reads only persisted `nStatus` + `nBits` + topology.

No serialization change: like `nChainWork`, `nAuthenticatedChainWork` is derived,
never written to disk. Restart rebuilds it via the LoadBlockIndex recompute from
persisted `nStatus`; `-reindex` rebuilds it via the normal accept path re-running
bodies and promotions.

### 3.3 Routed security gates (implemented, testable in-process)

- `validation.cpp:6884` — assumevalid script-check budget: read
  `m_best_header->nAuthenticatedChainWork`. A forged `m_best_header` can no longer
  push authenticated work over `MinimumChainWork` to relax script verification.
- `validation.cpp:10497` — header-presync DoS/log gate: same substitution.

The IBD-exit gate (`6116`) and best-chain selection (§2.4) are unchanged because
they read the active tip / body-gated candidates, for which
`nAuthenticatedChainWork == nChainWork` by construction (§3.1). This is a
deliberate minimal-change decision, documented so reviewers can confirm the active
tip is inherently authenticated.

### 3.4 `m_best_header` pointer: intentionally left provisional

Headers are, by the nature of this attack, indistinguishable at the header level
from "legitimate headers whose bodies we have not yet downloaded." `m_best_header`
must keep pointing at the longest valid **header** chain because header-sync and
the download scheduler use it as a *sync hint* (locators, presync height). Making
the pointer itself "authenticated" would stall headers-first sync at the last
downloaded body.

The fix is therefore **not** to move the pointer but to stop *trusting its work*:
every security/chainwork decision reads `nAuthenticatedChainWork` (a property of
the block *and its ancestry*). Even when `m_best_header` points at a forged tip,
`m_best_header->nAuthenticatedChainWork` is flat at the last genuinely
authenticated ancestor — so the value consulted by the gates is correct without
touching the pointer. This is the key structural insight that keeps the change
small and sync-safe.

Reporting surfaces that specifically mean "verified progress" (mining readiness,
`getblockchaininfo`/`getmininginfo` headers-vs-blocks lag) should present
authenticated work/height; these are §5 follow-ups because they are observational,
not consensus-critical, and several live in `net_processing`/RPC where they are not
unit-testable in-process without a live peer.

---

## 4. Threat analysis

- **Forged-header cost.** Producing authenticated work now requires a valid body
  whose product/Freivalds proof passes — genuine MatMul computation.
  `matmul_digest=0` headers cost nothing but yield zero authenticated work, so they
  cannot move any authenticated-work decision.
- **Chain selection.** Unchanged and already safe: only `BLOCK_VALID_TRANSACTIONS`
  blocks enter `setBlockIndexCandidates`; the active tip is authenticated by
  construction.
- **IBD.** IBD-exit reads the active tip; a forged header flood cannot advance the
  active tip and now cannot advance any authenticated-work gate either.
- **Eclipse resistance.** An eclipsing peer feeding a forged high-`nChainWork`
  header chain gains no authenticated work; the victim's authenticated-work view
  and IBD state are unmoved. (Peer-level download/eviction consequences are §5.)
- **Reorg handling.** Authenticated work is monotonic along a fixed chain and only
  increases on promotion; a promoted body deterministically raises the whole
  descendant prefix via the existing `m_blocks_unlinked` walk. A body that fails
  validation sets `BLOCK_FAILED_VALID` and can never contribute (predicate returns
  false permanently).
- **Orphan/header storage.** Unchanged; headers are still stored and still drive
  sync hints, they simply carry zero authenticated work until a body validates.
- **Proof availability.** Authenticated work depends only on locally verified
  bodies; never on a remote promise.
- **Worst-case CPU/memory/bandwidth.** Memory: one extra `arith_uint256` (32 B) per
  index. CPU: one add + one predicate per maintenance call; the promotion walk
  reuses an existing traversal (no new asymptotic cost). Bandwidth: none.

### 4.1 Fully implemented + unit-tested here

- Per-index authenticated-contribution predicate and accumulator recurrence.
- Forged-header floods (thousands of `matmul_digest=0` header-only indices) adding
  **zero** authenticated work while `nChainWork` climbs.
- Deterministic promotion when a body validates; permanent non-promotion when a
  body fails.
- Restart/reindex determinism (recompute-from-`nStatus` reproduces the incremental
  result exactly).
- A competing genuinely-authenticated chain selected by authenticated work over a
  longer forged chain.
- The predicate's byte-identical behavior at pre-fork heights.

### 4.2 Needs a live multi-node network to verify

- Per-peer download scheduling / staller detection under a forged-header flood.
- Peer protect-from-disconnect and chain-sync eviction using authenticated work.
- Anti-DoS work threshold and direct-fetch decisions under forged headers.
- End-to-end "node stays in IBD / refuses to relax budgets while eclipsed by a
  forged header chain."

---

## 5. Networking-layer follow-ups (exact call sites, not unit-tested here)

All read raw `nChainWork` (directly or via `pindexBestKnownBlock`, whose selection
is `net_processing.cpp:1487-1506`). Each should switch to authenticated work,
gated so pre-fork behavior is byte-identical (reading `nAuthenticatedChainWork`
already provides that gating). Deferred because they cannot be exercised without a
live peer/socket.

1. `PeerManagerImpl::FindNextBlocksToDownload` freshness/target checks —
   `net_processing.cpp:1527`.
2. Per-peer best-known-block selection — `net_processing.cpp:1487-1489`,
   `1503-1506` (track a separate authenticated best per peer).
3. Direct fetch — `net_processing.cpp:3432`, `3504`.
4. Anti-DoS work threshold — `net_processing.cpp:3208-3210`, used at `5602`, `6014`.
5. Peer protect-from-disconnect — `net_processing.cpp:3535`.
6. Chain-sync timeout / stale-chain eviction — `net_processing.cpp:6496`, `6503`.
7. IBD-gated header handling / min-chain-work disconnect — `net_processing.cpp:3513`,
   `5253`.
8. Reporting — `getblockchaininfo`/`getmininginfo` "headers"
   (`rpc/blockchain.cpp:1943,4349`, `rpc/mining.cpp:1035`), `node/interfaces.cpp:295`
   header tip — present authenticated height/work when `IsMatMulV4Active`.

Recommended approach: give `CNodeState` a `pindexBestAuthenticatedBlock` (updated
with the same authenticated-work compare) and switch the
DoS/eviction/protection/fetch comparisons to it, keeping provisional
`pindexBestKnownBlock` only as a sync hint — mirroring the split applied to
`m_best_header` in §3.4.

---

## 6. Files changed by the implemented core

- `src/chain.h` — `nAuthenticatedChainWork` field; `IsBlockAuthenticated`,
  `GetBlockAuthenticatedProof`, `UpdateAuthenticatedChainWork` declarations.
- `src/chain.cpp` — implementations.
- `src/node/blockstorage.cpp` — maintain in `AddToBlockIndex` and `LoadBlockIndex`.
- `src/validation.cpp` — maintain in `ReceivedBlockTransactions`; route gates at
  `6884` and `10497`.
- `src/test/matmul_chainwork_auth_tests.cpp` — unit tests.
- `src/test/CMakeLists.txt` — register the test.
</content>
