# R4 — Search / Discovery independent review

Lane: **R4 (Search / Discovery)**
Tree: `/home/administrator/btx-0.34.7-private`
Reviewer: independent review lane R4 (non-implementing pass over the shipped
source; **no build, no run** — see [Evidence status](#evidence-status)).

Files read: `src/modelnet/provider_route.{h,cpp}`, `src/modelnet/router.{h,cpp}`,
`src/modelnet/query_router.{h,cpp}`, `src/modelnet/lan_discovery.{h,cpp}`,
`src/modelnet/metadata_gossip.{h,cpp}`, `src/modelnet/search.{h,cpp}`,
`src/modelnet/helper.cpp` (read-only), `src/modelnet/helper_network02.cpp`,
`src/modelnet/http_bridge.{h,cpp}`, `doc/modelnet/provider-routing.md`,
`doc/modelnet/search.md`, `doc/modelnet/rpc.md`, `src/test/*`.

Written by this lane: this file and **new**
`src/test/modelnet_r4_route_tests.cpp`. Nothing else was modified; in
particular `src/modelnet/helper.cpp` and every `CMakeLists.txt` are untouched.

---

## Headline

The mandated check **passes**: `RoutingBucketIndex` is a leading-XOR-**bit**
index over the full 384-bit keyspace, and `ROUTE_BUCKETS` is `Digest48::SIZE *
8` = 384. There is no first-differing-**byte** logic anywhere in the routing
path. The byte-vs-bit confusion survives in exactly one place — the shipped
document `doc/modelnet/provider-routing.md` still says "48 buckets".

The larger and more consequential finding is that most of the section-17
discovery machinery is **library-only**. `RoutingTable` is never populated in a
running node, `QueryRouter::Plan` has no production caller, and `QuerySummary`
never crosses the wire. What actually runs is a flat, hard-capped 8-peer
fan-out in `helper.cpp` that ignores peer summaries entirely. That is safe
against the amplification attacks this lane was asked to check — a hostile
all-ones summary cannot widen fan-out, because summaries are not consulted —
but it means the early-stop/expand, cumulative-budget, and summary-freshness
behaviour is unexercised by anything a user can reach.

Two defects are worth fixing before this lane can be signed off:
`ProviderCache::Put` refuses new provider records at its 256-entry cap without
first expiring dead ones (a cheap remote denial of provider discovery), and
both live delegated-router call sites pass `peers.back()` as the "independent"
router, so the A/B diversity reservation never happens.

---

## Findings

| ID | Subject | Class | Severity |
|---|---|---|---|
| R4-01 | `RoutingBucketIndex` uses XOR leading bit, not first differing byte | FALSE_POSITIVE | — |
| R4-02 | `doc/modelnet/provider-routing.md` still documents "48 buckets" | REAL | low (doc) |
| R4-03 | `RoutingTable` is never populated in a running helper | REAL | high |
| R4-04 | `RoutingBucketIndex(self, self) == 0` aliases the most-distant bucket | REAL | low |
| R4-05 | QRP query summaries never cross the wire | DEFERRED | medium |
| R4-06 | Dynamic-query early-stop / expand has no production caller | DEFERRED | medium |
| R4-07 | Live search fan-out has no global deadline (`QUERY_DEADLINE_MS` unused) | REAL | medium |
| R4-08 | All-ones summary cannot cause unbounded fan-out | FALSE_POSITIVE | — |
| R4-09 | No summary freshness or negative feedback on a lying "likely" peer | REAL | medium |
| R4-10 | `ProviderCache::Put` rejects at cap without expiring first | REAL | high |
| R4-11 | `QueryDedupe::seen` grows without bound from remote `query_id` | REAL | medium |
| R4-12 | Delegated routers A/B: "independent" contact is drawn from the preferred set | REAL | medium |
| R4-13 | LAN discovery exposes no wallet RPC | FALSE_POSITIVE | — |
| R4-14 | `m_pub_window` is a lifetime counter, not a window; null publisher bypasses it | REAL | medium |
| R4-15 | `QUERY_SAMPLE_MAX` = 32 sample cap | DESIGN_CHOICE | — |
| R4-16 | `signed_ok` is restored from `records.json` without re-verification | REAL | low |
| R4-17 | Spec "section 17" could not be located in this tree | OPTIONAL | — |
| R4-18 | Regression coverage lived only inside `modelnet_convergence_tests.cpp` | REAL (now addressed) | — |

---

### R4-01 — `RoutingBucketIndex` is XOR bit, not byte — FALSE_POSITIVE

`BucketIndex` walks the 48 XOR bytes, skips zero bytes, then finds the leading
set bit inside the first non-zero byte and returns `i * 8 + bit`:

```41:55:src/modelnet/provider_route.cpp
int BucketIndex(const Digest48& self, const Digest48& other)
{
    for (size_t i = 0; i < Digest48::SIZE; ++i) {
        const unsigned char x = self.data[i] ^ other.data[i];
        if (x == 0) continue;
        int bit = 0;
        unsigned char mask = 0x80;
        while ((x & mask) == 0 && mask != 0) {
            mask >>= 1;
            ++bit;
        }
        return static_cast<int>(i * 8 + static_cast<size_t>(bit));
    }
    return 0;
}
```

The return range is 0–383, i.e. a Kademlia leading-zero-count bucket index.
`ROUTE_BUCKETS` is derived, not hard-coded, so it cannot drift from
`Digest48`:

```25:25:src/modelnet/provider_route.h
constexpr size_t ROUTE_BUCKETS = Digest48::SIZE * 8; // 384 bit-prefix buckets, not 48 byte buckets
```

`RoutingTable` allocates `m_buckets(ROUTE_BUCKETS)` and `Closest()` sorts by
the full 48-byte XOR comparison (`XorCloser`), not by bucket. Nothing in
`src/` selects a bucket by byte position. Verified: 384.

### R4-02 — the shipped doc still says 48 buckets — REAL (low)

```28:29:doc/modelnet/provider-routing.md
Separate from monetary AddrMan. 48 buckets, k=8, netgroup cap 2 per
bucket. Routing id is a stable hash of the model service identity.
```

This is the byte-count wording the code was corrected away from. `k=8` and
netgroup cap 2 are right; the bucket count is off by 8×. A reader auditing the
routing table against this document would conclude the code is wrong. Fixing
it is a one-line documentation edit, outside this lane's write scope
(`audit/r4-search.md` + the new test only), so it is handed off. Suggested
wording: "384 bit-prefix buckets (48-byte id × 8), k=8, netgroup cap 2".

### R4-03 — `RoutingTable` is never populated in a running helper — REAL (high)

`g_swarm.routes` is declared at `src/modelnet/helper.cpp:1203`, but across all
of `src/` (tests excluded) there is **no** call to `RoutingTable::SetSelf`,
`RoutingTable::Insert`, or `LoadPersistedContacts`. Consequences in the live
node:

- `routing_table_size` (`helper.cpp:4856`) is always 0.
- `bootstrap_dependency` at `helper.cpp:4859` evaluates
  `!BootstrapIndependent(true, 0) && 0 == 0`, i.e. always **true** — the node
  permanently reports itself bootstrap-dependent.
- `lookupmodelproviders` (`helper.cpp:4958`) calls `LookupStep`, whose
  `table.Closest(...)` result is discarded anyway, so the lookup is a
  cache-only read of `ProviderCache`. The 16-query / parallelism-3 / 8 s
  budget in `LookupBudget` can never advance past one query.

The provider *cache* side is genuinely live: `ext/provider` inserts through
`ProviderCache::Put` at `helper.cpp:2044`, which enforces ML-DSA-44
verification, `service_id == ProviderId(pubkey)`, expiry, and sequence
rollback. So provider records work; iterative routing does not. This matches
`audit/requirement-traceability.csv` CONV-35 ("two-router e2e NOT_RUN"), but
the row understates it: it is not merely unproven end to end, the table has no
writer at all.

### R4-04 — self/identical id aliases bucket 0 — REAL (low)

`BucketIndex` returns 0 when the two digests are equal, which is the same
bucket as "differs in the most significant bit" — the bucket that holds half
the keyspace. There is no self-id guard in `RoutingTable::Insert`, so a node
that learns its own contact would consume one of the eight slots in its widest
bucket. Latent while R4-03 holds. A distinct sentinel (or an explicit
`if (c.id == m_self) return false;`) would remove the ambiguity.

### R4-05 — QRP summaries never cross the wire — DEFERRED (medium)

`QuerySummary` (`hit_count`, `truncated`, `sample_ids`) and
`SummarizeQueryHits` are correct and bounded, but the only consumers are
`QueryRouter::SummarizeIds/SummarizeHits` and one local diagnostic RPC,
`querymodelsummary` (`helper_network02.cpp:817`), which summarises **this
node's own** catalog. The peer-facing response builder emits full result cards
and full records instead:

```1225:1241:src/modelnet/search.cpp
UniValue SearchResponseJson(const std::string& query_id, const std::string& responder,
                            const std::vector<SearchHit>& hits, bool truncated)
{
    // ... "results" = SearchResultCard per hit, "records" = SearchRecordToJson per hit
    o.pushKV("truncated", truncated);
    o.pushKV("coverage_hint", "incomplete");
    return o;
}
```

No `hit_count` / `sample_ids` field appears in `ext/search` in either
direction, and `QueryPeerHint::summary_likely` is never populated from a peer
reply. `doc/modelnet/search.md` does not claim otherwise — it documents exactly
what ships (TTL 2/max 4, `SEARCH_FANOUT_MAX` 8, dedupe, 100k index cap) — so
this is an unwired capability, not doc drift. Classified DEFERRED rather than
REAL for that reason, but it should not be described as "QRP summaries" in any
release note.

### R4-06 — early-stop / expand has no production caller — DEFERRED (medium)

`QueryRouter::Plan` implements the section-17 behaviour correctly (see the
verification in R4-08 and R4-09). It has no caller outside tests. Grepping the
budget constants outside `query_router.*` yields exactly one hit —
`probe_max` echoed as a diagnostic in `getmodelroutingstatus`. So
`QUERY_USEFUL_TARGET_DEFAULT` (25), `QUERY_CUMULATIVE_TASKS_MAX` (32) and
`QUERY_DEADLINE_MS` (8000) are inert.

The live path is a flat loop in the `searchmodels` handler
(`helper.cpp:5541-5628`): build `fanout` from
index peers, catalog peers and recent PEX up to `SEARCH_FANOUT_MAX` = 8, then
query every one of them. It breaks only on job cancellation — never because
enough unique useful results have arrived. `QueryRouter::NoteRemoteTasks` has
no caller either, so `m_remote_tasks` is permanently 0 and the cumulative cap
would not bind even if `Plan` were wired.

Because nothing user-visible claims the planner is live, this is DEFERRED. The
consequence that *is* live is R4-07.

### R4-07 — no global deadline on the live search fan-out — REAL (medium)

Each peer gets `SEARCH_PEER_TIMEOUT_MS` = 1500 ms for handshake **and** 1500 ms
for I/O (`QueryExtPeer`, `helper.cpp:1068-1069`). Eight peers with no overall
budget is up to ~24 s inside one `searchmodels` call, and the only escape is
`cancelmodelsearch` from another thread. `QUERY_DEADLINE_MS` (8000) exists for
precisely this and is unused. The per-peer timeout does bound each hop, so this
is latency and thread occupancy, not an unbounded hang.

### R4-08 — an all-ones summary cannot cause unbounded fan-out — FALSE_POSITIVE

The previous lane recorded this as DESIGN_CHOICE / "not e2e". It is bounded by
three independent mechanisms, two of which are live:

1. **Planner (library).** In `QueryRouter::Plan`,
   `active = min(ClampActive(budget), remaining_tasks)` and `ClampActive`
   clamps to `QUERY_PROBE_MAX` = 8 regardless of what the caller's budget
   says. `probe_peers` ≤ `likely_slots`, `exploration_peers` ≤
   `explore_slots`, `likely_slots + explore_slots == active`, and the top-up
   loop adds at most `active - taken.size()`. So with 200 peers all claiming a
   match the plan is exactly 8 endpoints, and `all_match_capped` is set to
   record that the claim set was truncated. Also verified: `throughput_bps` is
   explicitly discarded (`(void)p.throughput_bps`) and
   `ProviderThroughputIsRankingAuthority()` is `false`, so a peer cannot buy
   slots by advertising bandwidth.
2. **Live fan-out.** `add_ep` refuses to grow past `SEARCH_FANOUT_MAX` = 8 and
   deduplicates endpoints, and it skips our own bind address.
3. **No reflection.** The inbound handler forces the query local before
   executing it, so a remote query can never make us fan out:

```2113:2115:src/modelnet/helper.cpp
        q.scope = SearchScope::LOCAL;
        const auto hits = g_search_idx.Search(q, ConnNowMs());
```

   Combined with `ttl` clamped to `SEARCH_TTL_MAX` = 4, `ShouldForwardSearch`,
   and `query_id` dedupe, there is no amplification path. Query bodies over
   `SEARCH_QUERY_BYTES_MAX` = 4096 are rejected 413.

The all-ones case is now pinned by a unit regression
(`r4_all_ones_summary_cannot_widen_fanout`). A multi-node hostile-summary
end-to-end run remains **DEFERRED** — but as R4-05 notes, there is no wire
format for a hostile summary to arrive in yet, so that e2e is not meaningful
until R4-05 is wired.

### R4-09 — stale summary fallback is only half present — REAL (medium)

What is correct: a peer whose summary is absent, unknown or saturated is
routed to `unknown` and still probed, so a stale summary never silences a
query. `QueryPeerHint::summary_unknown` **defaults to true**, which is the safe
default. When `likely` is empty every slot becomes exploration
(`explore_slots = min(active, unknown.size())`), and when both sets are
non-empty at least one exploration slot is always reserved
(`else if (active >= 2) explore_slots = 1`). On the provider side,
`ProviderCache::Get` filters on `expiry_ms > now_ms`, `LookupStep` calls
`Expire` first, `StaleCacheIsNotAuthority()` is `true`, and
`LivePieceRangesRequireDirectQuery()` is `true`.

What is missing: neither `QuerySummary` nor `QueryPeerHint` carries any
freshness signal — no generation timestamp, no network epoch, no TTL. A
*stale positive* (`summary_likely = true` for content the peer no longer has)
is indistinguishable from a fresh one, and `Plan` is `const` with no
per-peer state, so a peer that repeatedly claims a match and returns nothing
is never demoted. It keeps winning the 7 probe slots ahead of honest unknown
peers. A `summary_generated_ms` (or reuse of `NetworkEpoch::epoch`) plus a
miss counter that pushes a peer to `summary_unknown` would close this.

### R4-10 — `ProviderCache::Put` rejects at cap without expiring — REAL (high)

```309:316:src/modelnet/provider_route.cpp
    size_t n = 0;
    for (const auto& kv : m_by_resource) n += kv.second.size();
    if (n >= m_cap) {
        err = "cache cap";
        return false;
    }
    vec.push_back(r);
    return true;
```

`m_cap` is 256 for the whole node, across all resources. Three problems
compound:

- **No `Expire` before the cap check.** Expired records still occupy the
  budget, so once 256 records have ever been accepted, new ones are refused
  until something else calls `Expire` — and on the live `ext/provider` path
  (`helper.cpp:2044`) nothing does. Compare `RouterCache::Insert`, which does
  `Expire(now)` and retries before failing. This asymmetry looks like an
  oversight, not a decision.
- **No per-resource quota and no eviction.** First come, first served. There is
  no LRU and no reservation for resources the node actually wants.
- **Cheap to fill remotely.** `VerifyProviderRecord` proves possession of an
  ML-DSA-44 key, which is free to generate; it does not prove scarcity. 256
  self-signed records for junk resources deny provider caching for up to the
  1-hour `PROVIDER_TTL_MS`.

Minimal fix: call `Expire(now_ms)` before the cap test, and cap per resource
(e.g. 8 records) in addition to the global cap.

### R4-11 — unbounded dedupe set — REAL (medium)

`QueryDedupe::seen` is a plain `std::set<std::string>` with no cap and no
eviction:

```1179:1185:src/modelnet/search.cpp
bool QueryDedupe::Admit(const std::string& query_id)
{
    if (query_id.empty()) return false;
    if (seen.count(query_id)) return false;
    seen.insert(query_id);
    return true;
}
```

`g_search_dedupe` (`helper.cpp:1226`) is process-lifetime, and the inbound
`ext/search` handler feeds it `body["query_id"]` — remote, attacker-chosen,
bounded only by the 4096-byte query limit. Every distinct id is retained
forever, so memory grows with inbound query volume and never returns. A
bounded structure (rolling set with a time or count horizon) is needed. Overlaps
lane R10; recorded here because the growth is reached through the search path.

### R4-12 — delegated routers A/B is not actually independent — REAL (medium)

`PlanRouterQueries` itself is right: preferred first, cap
`MAX_ROUTER_CONTACTS` = 8, `max_concurrent` ≤ 4, and if the list is already
full it evicts the last preferred entry to make room for an independent
contact. Both live call sites, however, supply the "independent" list from the
preferred list itself:

```605:607:src/modelnet/helper.cpp
    PlanRouterQueries(cat.Peers(),
                       cat.Peers().size() >= 2 ? std::vector<std::string>{cat.Peers().back()} : std::vector<std::string>{},
                       plan);
```

and identically at `helper.cpp:6585`. Two outcomes, both wrong:

- **≤ 8 peers:** `peers.back()` is already in `seen`, the loop `continue`s, and
  `reserved_independent` reports **false** even when the operator does have a
  diverse peer set. The A/B second lane never opens.
- **> 8 peers:** `peers.back()` was dropped by the 8-contact cap so it is not
  in `seen`; the full-list branch fires, evicts a real contact, and reports
  `reserved_independent = true` — while every contact still comes from the same
  `cat.Peers()` community. The flag claims diversity that does not exist, and
  `getmodelresolve` surfaces it as `reserved_independent`.

The fix belongs at the call sites (pass a peer source that is genuinely outside
the preferred community, e.g. configured independent routers or PEX-learned
endpoints not in `cat.Peers()`), which is in `helper.cpp` and therefore outside
this lane's write scope. The new test pins the library contract in both
directions, including the degenerate shape the live path currently passes.

### R4-13 — LAN discovery exposes no wallet RPC — FALSE_POSITIVE

`lan_discovery.cpp` contains only classification and ordering:
`EndpointLooksLan` (RFC1918 / `169.254` / `127.` / `fe80:` / `::1` / `.local`,
with a correct 16–31 second-octet test for `172.`) and `PreferLanPeer`, which
is a strict "candidate is LAN and other is not" preference. Neither is
consulted for authorisation anywhere: the only non-test callers are two
diagnostic RPCs, `getmodelroutingstatus` and `getmodellandiscovery`
(`helper_network02.cpp:1025,1057`), and `DelegatedRoutingMutatesConsensus()`
and `LanDiscoveryRequiresPublicAddress()` are hard `false`. There is no
"treat LAN peers as trusted" branch to abuse.

The HTTP surface a LAN client could reach is the browser bridge, which refuses
wallet surface unconditionally rather than by source address:
`WalletLikePath` → 403 on GET and 405 on any mutation; `WalletLikeBody`
inspects the JSON `method` plus a literal needle list; every mutating method is
405 regardless of path; `PushDisclosure` stamps `wallet: false` on every JSON
body; `/health` reports `bind_default: 127.0.0.1`. The bridge is also a
separate loopback process, not the helper. Pinned by
`r4_lan_discovery_grants_no_wallet_authority`.

### R4-14 — publisher "window" is a lifetime counter — REAL (medium)

```922:929:src/modelnet/search.cpp
    const std::string pub = r.publisher_identity.Hex();
    if (!pub.empty() && !r.publisher_identity.IsNull()) {
        if (m_pub_window[pub] > 64) {
            err = "publisher spam";
            return false;
        }
        if (it == m_by_model.end()) m_pub_window[pub] += 1;
    }
```

`m_pub_window` is only ever cleared by `SearchIndex::Clear()` (helper-dir
reset). There is no time window and no decrement on tombstone, so a legitimate
publisher's 66th model is rejected as `publisher spam` permanently — a
correctness bug for any real model publisher, not just an anti-spam knob. A
record with a null `publisher_identity` skips the check entirely, so the quota
does not bind the case it was written for.

The surrounding admission logic is otherwise sound and worth recording as
verified: signature required for tombstones, `VerifySearchRecord` for anything
carrying a signature, "unsigned cannot override signed", signer pinning on
update, sequence-rollback rejection, same-sequence conflict detection, and a
100k `index cap`. Unsigned records *are* accepted for previously unseen
model ids, including via remote search replies (`helper.cpp:5635`), which is
what makes the null-publisher bypass reachable from the network.

### R4-16 — `signed_ok` survives a round trip unverified — REAL (low)

`PersistRecords` writes `signed_ok` into the helper's `records.json`, and the
loader restores it as a plain boolean without re-verifying the signature
(`helper.cpp:293`), while `TypedResolveJson` gates on it
(`if (!h.signed_ok) continue;`). `RouterCache::Insert` does not check it
either. The trust boundary is the helper datadir, so this is low severity, but
`signed_ok` should be recomputed on load rather than believed.

### R4-17 — spec "section 17" not locatable in this tree — OPTIONAL

The task names "SPEC section 17". This lane could not find a numbered spec
section 17 covering search/discovery anywhere in the tree. Nearest candidates,
none of which match: `.0347-model-economy-discovery.spec.local.md` §17 is
"NEWEST FEED SEMANTICS" (feed, not routing);
`audit/requirement-traceability.csv` row `CONV-17` is "source diversity
correlated origin" in `piece_picker.cpp` (lane R1);
`doc/design/btx-decentralized-frontier-ai-lab.md` §17 is about financing.
This review was therefore conducted against the named files plus
`doc/modelnet/provider-routing.md`, `doc/modelnet/search.md` and
`doc/modelnet/rpc.md` as the requirement source. If a different section 17
exists outside this tree, the coordinator should supply it so the mapping can
be re-checked.

### R4-18 — regression independence — REAL, addressed here

Before this pass the only assertions on bucket geometry lived in
`src/test/modelnet_convergence_tests.cpp` (`conv_routing_bucket_is_xor_bit_not_byte`,
lines 76–88) and a weaker pair in `modelnet_vstar_regression_tests.cpp:104-105`
with no `ROUTE_BUCKETS` check. The convergence case exercises only bits 0 and 7
of byte 0. That does discriminate bit-from-byte, but it says nothing about
cross-byte indices, so an implementation that special-cased byte 0 and fell
back to byte indexing afterwards would pass. Delete or retarget that one file
and the whole property is unpinned.

`src/test/modelnet_r4_route_tests.cpp` (new) is self-contained and pins:

| Case | Pins |
|---|---|
| `r4_bucket_index_is_leading_xor_bit_over_384_bits` | all 384 single-bit distances map to 384 distinct buckets (a byte-based index yields 48); spot checks at bits 0, 7, 43, 383; trailing bits ignored; symmetry |
| `r4_routing_table_has_384_buckets_and_no_byte_collisions` | 384 peers at distinct bit distances all insert without hitting `ROUTE_K`; `StatusJson().buckets == 384`; `addrman` false; `Closest` is XOR-ordered; `PersistSubset` ≤ 32 |
| `r4_query_summary_never_dumps_catalog` | `QUERY_SAMPLE_MAX` truncation; an oversized budget cannot raise the cap |
| `r4_all_ones_summary_cannot_widen_fanout` | 200 all-claiming peers ⇒ exactly 8 slots, no duplicates, `all_match_capped` set; throughput is not authority; cumulative cap closes the plan |
| `r4_dynamic_query_early_stop_and_expand` | stop at the useful target, expand one below it, `scope=LOCAL` stays local, cancellation blocks plan and forward |
| `r4_stale_or_unknown_summary_still_gets_probed` | all-unknown peers still probed; mixed sets always keep an exploration slot; preference ordering |
| `r4_delegated_routers_reserve_a_genuinely_independent_slot` | independent contact reserved and present; 8-contact / 4-concurrent caps under a 40-peer list; an "independent" from the preferred set does **not** count (R4-12); 60 s negative cache, keyed by kind, never "does not exist" |
| `r4_lan_discovery_grants_no_wallet_authority` | LAN classification incl. the `172.16–31` boundary; asymmetric preference; wallet path 403, wallet body 405, any mutation 405, `wallet: false` disclosed, loopback default bind |

**The new file is not registered in `src/test/CMakeLists.txt`.** That list is
explicit (no glob) and CMake edits are outside this lane's write scope. One
line is required before it runs — insert `modelnet_r4_route_tests.cpp` beside
`modelnet_convergence_tests.cpp` (`src/test/CMakeLists.txt:589`).

---

## Evidence status

**NOT_RUN.** This lane read source and wrote a test; it did **not** configure,
compile, or execute anything, per the task constraints and the tree's
disk/memory rule. The new test is unregistered and therefore unexecuted — every
assertion in it is derived by reading the implementation, and it must be built
and run before any of it counts as evidence. Do not treat this file as R4
sign-off.

Ownership boundaries respected: `src/modelnet/helper.cpp`,
`src/modelnet/helper_network02.cpp` and all `CMakeLists.txt` were read only.
R4-11 overlaps lane R10 (DoS) and R4-14/R4-16 touch lane R5 (gossip/index
admission); they are recorded here because they are reached through the search
and discovery path.

## Handoff

1. `src/test/CMakeLists.txt` — register `modelnet_r4_route_tests.cpp`, build,
   run. Any failure invalidates the corresponding row above.
2. R4-10 — `Expire(now_ms)` before the cap check in `ProviderCache::Put`, plus
   a per-resource quota.
3. R4-12 — feed `PlanRouterQueries` an independent source at both call sites,
   or stop reporting `reserved_independent`.
4. R4-02 — correct "48 buckets" to 384 in `doc/modelnet/provider-routing.md`.
5. R4-03 — either wire a `RoutingTable` writer or stop reporting
   `routing_table_size` and `bootstrap_dependency` as if the table were live.
6. R4-11 — bound `QueryDedupe`.
7. R4-14 — make the publisher window a real window; do not exempt null
   publishers.
