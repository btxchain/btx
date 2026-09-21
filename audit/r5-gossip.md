# R5 independent review — Gossip / Events (SPEC 15, SPEC 18)

Tree: `/home/administrator/btx-0.34.7-private` @ `573b4aa4`.
Lane: R5. Scope: `src/modelnet/event_journal.{h,cpp}`,
`src/modelnet/model_watch.{h,cpp}`, `src/modelnet/metadata_gossip.{h,cpp}`,
`src/modelnet/index_reconcile.{h,cpp}`, `doc/modelnet/watches.md`
(+ `doc/modelnet/events.md`).

SPEC section names are taken from `audit/requirement-traceability.csv`
(`S-15.1` journal contract, `S-15.2` watch identity and actions, `S-15.3`
subscription authorization, `S-15.4` reorganizations and corrections;
`S-18.1` one signed-object store, `S-18.2` live gossip, `S-18.3`
anti-entropy, `S-18.4` optional private search experiment). The upstream
spec document itself is not in this tree; the section titles in that CSV are
the only in-tree definition of SPEC 15/18 and are what this review judges
against.

**Nothing was compiled and nothing was executed for this lane.** No
`cmake`, no `ninja`, no `test_bitcoin`, no `test_runner.py`. Every claim
below is source reading. Every measurement claim is `NOT_RUN`.

## Verdict

| Check | Result |
|---|---|
| 20-peer mesh | **NOT_RUN** — and no mesh code path exists to run (see N-1) |
| IHAVE / IWANT | **PARTIAL** — in-process structs and one local RPC, no wire messages (N-2) |
| Dedupe | **REAL** — proven in-process and across restart, with three defects (F-3, F-4, F-5) |
| Replay | **REAL** — bounded 100-event pages, cursor persisted; silent loss past the cap (F-6) |
| Invalid signature | **REAL** — record, channel and announce signatures are genuinely verified; verified state is then dropped (F-1) and one watch kind is ungated (F-2) |
| Graft / prune | **ABSENT** — no mesh membership state machine anywhere in scope (N-3) |
| Local peer score only | **VACUOUS** — no gossip peer score exists at all (N-4) |
| No monetary mutation | **REAL in scope**; one peer-writable economic field just outside it (F-12) |
| Anti-entropy 100k / 1m / 10m | **NOT_RUN** — largest executed compare is 1 000 ids (N-5) |
| Offline recovery | **PARTIAL** — journal survives restart; queued actions and gap detection do not (F-6, F-7) |
| Watch fire-once | **PARTIAL** — holds inside the retention cap, breaks past it (F-5) |
| No shell callbacks from untrusted events | **REAL** — clean (see "Confirmed sound") |

Lane classification: **REAL with gaps**. Not a sign-off. SPEC 18.2 "live
gossip" and 18.3 "anti-entropy" are not demonstrated as a network protocol;
they exist as local functions plus one operator-driven RPC.

## What the gossip surface actually is

There is no autonomous metadata mesh. The pieces are:

- `GossipMessage` / `GossipDigest` / `IndexReconciler` are in-process types.
  Their only non-test caller is `reconcilemodelindex`
  (`src/modelnet/helper_network02.cpp:830-849`), a **local unix JSON-RPC**
  whose `remote_ids` come from the caller, not from a peer.
- The real peer-to-peer surface is the PQ1-TLS native HTTP handler
  (`src/modelnet/helper.cpp:1421` onward): `records/announce`,
  `ext/objects/announce`, `records/get`, `ext/objects/get`, `ext/search`,
  `ext/feed`. That is announce/fetch of signed objects — not digest
  reconciliation, and it never constructs a `GossipMessage`.
- Peer-sourced metadata reaches the event journal only indirectly:
  `ext/search` / `ext/feed` replies → `SearchRecordFromJson` →
  `SearchIndex::Put` → `AfterIndexPut` (`helper.cpp:1356`) →
  `JournalObserveSearchRecord` → `ModelWatchStore::NoteEvent` → queued
  action → `ExecuteQueuedFreeDownloads` (`helper.cpp:4374`, invoked from the
  `getmodelwatchactions` dispatch at `helper.cpp:4523`).

That last chain is the one that matters for this lane: it is the path by
which a remote peer's bytes cause local automatic work. F-1 and F-2 are both
on it.

## Findings

### F-1 — Verified peer records are journalled as unverified, so most watches can never fire (HIGH, REAL, SPEC 15.3 / 18.1)

`SearchIndex::Put` verifies the ML-DSA signature and stores the verified
copy, but it writes the verified flag into the index entry, not back into
the caller's record:

```929:932:src/modelnet/search.cpp
    m_by_model[key] = r;
    m_by_model[key].signed_ok = verified;
    if (r.tombstone) m_by_model[key].tombstone = true;
    ++m_seq;
```

Every call site then journals the **caller's** record, which still has
`signed_ok == false` after `SearchRecordFromJson` (`search.cpp:502`):

```5633:5636:src/modelnet/helper.cpp
            ModelSearchRecord rec;
            std::string ierr;
            if (!SearchRecordFromJson(recj, rec, ierr)) continue;
            if (g_search_idx.Put(rec, ConnNowMs(), ierr)) AfterIndexPut(rec, ConnNowMs());
```

`ModelEventFromSearchRecord` maps that flag straight to
`verification_state` (`event_journal.cpp:269`), and `VerifiedEnough`
(`model_watch.cpp:233`) admits only `SIGNED_OK` / `CHAIN_OBSERVED`.

Consequence: a correctly signed record received from a peer produces a
`LOCAL_OBSERVED` event, and PUBLISHER, COLLECTION and QUERY watches are
gated off it. Those three watch kinds are effectively dead for all remote
metadata. The only records that reach `SIGNED_OK` are the ones this node
signed itself (`helper.cpp:3504`, where
`SignSearchRecordWithDefaultIdentity` sets `rec.signed_ok = true` on the
local object). The same bug appears at `helper.cpp:5779`, `5867`, `6826`
and `7694`.

Fix shape: have `Put` return the stored record (or re-read
`g_search_idx.Get(rec.model_id)`) and journal that.

### F-2 — MODEL watches have no verification gate and drive an automatic fetch (MEDIUM-HIGH, DESIGN_CHOICE as written, SPEC 15.3)

```525:529:src/modelnet/model_watch.cpp
    case WatchKind::MODEL: {
        const std::string want = watch.model_id;
        if (want.empty()) return false;
        return ev.model_id == want || ev.object_id == want;
    }
```

Unlike the other three kinds this returns without consulting
`VerifiedEnough`. The existing suite pins the behaviour deliberately
(`src/test/modelnet_watch_tests.cpp:145` asserts an `UNVERIFIED` event still
matches a MODEL watch), so this is a design choice, not an oversight — but
combined with `ExecuteQueuedFreeDownloads` it means an **unsigned**
peer-supplied search record (accepted by `Put` with `verified == false`
because it carries no signature at all) can cause the node to start a
`getmodel FREE_ONLY` without operator action. No spend is possible
(`FREE_ONLY`, `spends=false`, `automatic_spend_atoms=0`) and the fetched id
is the one the operator already chose to watch, which bounds the damage to
unsolicited bandwidth. It should still either be gated like the other kinds
or documented in `watches.md` as the one unverified-input action path;
`watches.md` currently says watches fire "when a **signed** object changes".

### F-3 — Reorg corrections for different originals collide (MEDIUM, REAL, SPEC 15.4)

`ObserveReorgCorrection` copies `object_id` and `record_sequence` from the
original and sets the type to the mapped `*_REVERTED`
(`event_journal.cpp:695-717`). The dedupe key is
`object_id|record_sequence|transition` (`event_journal.cpp:200`). Because
`RevertedEventType` folds `RELEASE_CREATED`, `RELEASE_FUNDING_CHANGED` and
`RELEASE_FUNDED` onto the single type `RELEASE_FUNDING_REVERTED`
(`event_journal.cpp:182-198`), two corrections for two **different**
originals that share an object and a record sequence produce the same key.
The second one returns `duplicate=true` carrying the first correction's
`event_id`, and the journal's only `corrected_from` provenance points at the
wrong original. A consumer replaying the journal cannot tell that the second
transition was reverted at all.

The existing test only covers correcting the *same* original twice
(`modelnet_event_tests.cpp:114-118`), which is the case where dedupe is
wanted. Characterisation test: `r5_reorg_correction_collision_swallows_second`.

Fix shape: include `original_event_id` in the correction's dedupe key.

### F-4 — Dedupe key has no state component, so a repeated transition is swallowed forever (MEDIUM, REAL, SPEC 15.1)

The key carries no timestamp and no old→new state. Any producer that emits
the same transition twice for an unchanged `record_sequence` loses the
second occurrence permanently. This is concrete for availability flapping:
`ModelEventFromFeed` sets
`record_sequence = metadata_sequence > 0 ? metadata_sequence : fe.sequence`
(`event_journal.cpp:221`), and `metadata_sequence` does not change when a
model goes fragile and then becomes reconstructable again. So
`MODEL_RECONSTRUCTABLE → MODEL_NO_LONGER_RECONSTRUCTABLE →
MODEL_RECONSTRUCTABLE` journals only the first and second events.

Latent today: nothing in-tree emits `MODEL_BECAME_AVAILABLE` /
`MODEL_BECAME_FRAGILE` (they appear only in feed filters and parsers), and
nothing emits `MODEL_PROVIDER_AVAILABLE` / `_LOST`. It is still reachable
through the public `JournalObserve` contract, which is what SPEC 15.1
specifies. Characterisation test:
`r5_repeat_transition_same_sequence_is_swallowed`.

### F-5 — Compaction breaks both `event_id` uniqueness and watch fire-once (MEDIUM, REAL, SPEC 15.1 / 15.2)

`CompactLocked` erases from the front and rebuilds both indices
(`event_journal.cpp:512-519`), which drops the evicted entries from
`m_by_dedupe`. Re-observing an evicted logical event therefore creates a
second journal entry. Because `event_id = H(dedupe_key)`
(`event_journal.cpp:205`), that second entry carries the **same
`event_id`** with a different `local_sequence`, and `m_by_id` silently
rebinds to the newer one. Any watch matching it is enqueued a second time,
with a second `job_id` and — for `FREE_DOWNLOAD` — a second automatic fetch.

So "one logical occurrence has one `dedupe_key`" (`events.md:36`) and
fire-once hold only within the retention window. Characterisation test:
`r5_recycled_event_after_compaction_refires_watch`.

### F-6 — `getmodelevents` reports `"gap": false` unconditionally (MEDIUM, REAL, SPEC 15.1, offline recovery)

```970:973:src/modelnet/model_watch.cpp
        result.pushKV("events", arr);
        result.pushKV("cursor", std::to_string(journal.Cursor()));
        result.pushKV("gap", false);
        result.pushKV("automatic_spend_atoms", 0);
```

`ReplayAfter` simply skips everything with `local_sequence <= cursor` over
whatever survived compaction. A client that was offline long enough for the
cap (100 000 by default) to roll past its cursor gets a page that begins
mid-stream, with `gap=false` and no way to detect the loss. The field exists
in the response, so the contract intends gap reporting; it is just never
computed. Fix shape: track the lowest retained `local_sequence` and set
`gap = cursor < floor`.

### F-7 — Watch actions are unbounded in memory and lost on restart (MEDIUM, REAL, SPEC 15.2, offline recovery)

`EnqueueLocked` pushes onto `m_actions` with no cap
(`model_watch.cpp:694-709`); the queue drains only when someone calls
`getmodelwatchactions`. A QUERY watch with a broad filter plus a chatty peer
grows it without bound.

It is also never persisted. `ModelWatchStore` writes `watches.json` and
`channels.json` only (`model_watch.cpp:544-569`), and on load the journal is
**not** replayed into the watch store — the listener fires only from a live
`Observe` (`event_journal.cpp:657`). So a restart between "event observed"
and "actions drained" loses every pending action with no recovery path,
while the journal still shows the event as processed. Either persist the
queue or persist a per-watch cursor and re-derive on load.

### F-8 — Gossip admission bounds count, not size (MEDIUM, REAL, SPEC 18.2)

```13:24:src/modelnet/metadata_gossip.cpp
bool GossipMessageAllowed(const GossipMessage& msg, std::string& err)
{
    if (msg.secret_bearing) {
        err = "secret-bearing gossip forbidden";
        return false;
    }
    if (msg.want_ids.size() > 256) {
        err = "want cap";
        return false;
    }
    return true;
}
```

No per-id length bound, no id format check, no bound or format check on
`catalog_digest_hex`, no sanity check on `entry_count`.
`IndexReconciler::AdmitInbound` adds nothing. 256 want-ids of arbitrary
length are admitted, and `MissingRemoteIds` then builds a
`std::set<std::string>` of the local ids plus a copy of the accepted ones.
The count cap is genuinely enforced and tested; the size dimension is
simply absent. Characterisation test: `r5_gossip_admits_unbounded_want_id_size`.

### F-9 — `CompareSets` reports EQUAL when the local set is a strict superset (MEDIUM, REAL, SPEC 18.3)

`MissingRemoteIds` only collects remote ids we lack
(`index_reconcile.cpp:61-75`). When we hold everything the peer holds plus
more, `want_ids` is empty and the status falls through to `EQUAL`
(`index_reconcile.cpp:177-181`) even though the two digests differ. A caller
looping "reconcile until EQUAL" concludes convergence while the peer is
still missing entries. Anti-entropy here is strictly one-directional and
only converges if both sides independently initiate; nothing in the code
arranges that, and there is no reciprocal push. Characterisation test:
`r5_superset_reports_equal_despite_digest_mismatch`.

### F-10 — The recursive split is unrepresentable on the wire (MEDIUM, REAL, SPEC 18.3)

`Compare` and `CompareRange` return `ReconcileStatus::DIVIDE` with
`left` / `right` `ReconcileRange` values and honour a depth limit of 32
(`index_reconcile.cpp:137-141`, `191-227`). But `GossipMessage` has no range
field (`metadata_gossip.h:19-23`), and `reconcilemodelindex` serialises only
`status`, `want_ids`, `want_truncated`, `digest_authorizes_insert`,
`want_cap`. The ranges are dropped at the RPC boundary, so the range-split
half of anti-entropy cannot be driven by a remote party. `RECONCILE_IN_FLIGHT_MAX`
and `RECONCILE_FULL_OBJECTS_MAX` are declared and never referenced anywhere
in the tree.

### F-11 — Every accepted announce rewrites the entire record store (HIGH for a 20-peer mesh, REAL, adjacent file)

Outside the five scoped files but directly on the live gossip admission path
and decisive for the 20-peer question. `ext/objects/announce` and
`records/announce` call `PersistRecords` on every accepted message
(`helper.cpp:2489-2494`, `2335-2341`), and `PersistRecords` serialises the
whole cache, including hex-encoded payloads, to `records.json`
(`helper.cpp:301-319`). With a 4 096-entry cache (`router.h:61`) and an
80 KiB envelope cap, one inbound announce can trigger a multi-hundred-MB
write. `RouterCache::Insert` also has no eviction beyond expiry and no
per-signer or per-peer quota (`router.cpp:86-92`) — once full it returns
"router cache full" and rejects everyone, so a single peer minting signed
records can wedge the store. Any real 20-peer mesh test should be expected
to hit this first.

### F-12 — Unauthenticated peers can mutate persisted campaign pledges (MEDIUM, REAL, adjacent file)

```2370:2388:src/modelnet/helper.cpp
        if (action == "pledges") {
            std::vector<ReleaseCampaign> campaigns;
            LoadCampaigns(HelperDir(cat), campaigns, err);
            bool found = false;
            const int64_t atoms = body.exists("amount_atoms") ? body["amount_atoms"].getInt<int64_t>() : 0;
            for (auto& c : campaigns) {
                if (c.release_id == id) {
                    c.pledged_atoms += atoms;
```

`POST …/releases/{id}/pledges` is reachable by any peer that completes the
PQ1 handshake. There is no signature on the body, no ACL, no rate limit, no
cap, and negative `amount_atoms` is accepted. This is **not** a spend and
not chain-confirmed funding: `pledged_atoms` feeds only
`pledged_percent_milli` (`economy.cpp:273-274`), which is kept separate from
`funded_percent_milli` (derived from confirmed atoms) and is documented as
nonbinding (`release.cpp:150`). So the "no monetary mutation" bar is not
breached in the strict sense, but a peer can freely move a persisted
economic display field on this node. It belongs in the R5 notes because the
gossip/announce surface is how it is reached.

### F-13 — Channel trust on reload, and a startup abort on corrupt local JSON (LOW, REAL)

`ModelWatchStore::LoadLocked` restores `signature_ok` from the file rather
than re-verifying (`model_watch.cpp:604-620`), so a locally tampered
`channels.json` is surfaced as `signature_ok=true` by `getmodelchannel`.
The same loader calls `wj["kind"].get_str()`, `wj["created_at"].getInt`,
`cj["signature_ok"].get_bool()` and friends without type checks; on a
type-confused local file these throw. From RPC that is contained — the outer
`DispatchHelperRpc` wraps everything in `try`/`catch` and returns
`INTERNAL "malformed rpc fields"` (`helper.cpp:4476`, `7770-7776`). At
startup it is not: `BindModelEventLayer(cfg.modeldir)` at `helper.cpp:8997`
runs outside any handler, so a corrupt `watches.json` aborts `btx-modeld`
instead of skipping the bad entry.

### F-14 — Non-exception-safe drain guard (LOW)

`ExecuteQueuedFreeDownloads` sets a `thread_local bool in_drain` and clears
it only on the normal exit path (`helper.cpp:4376-4413`). If the nested
`DispatchHelperRpc` throws, the flag stays set for the life of that worker
thread and all later drains on it silently no-op. Use a scope guard.

## Confirmed sound

- **No shell callback from untrusted events.** `EventTextMayBecomeCommand` /
  `Rpc` / `Path` / `Mandate` are unconditionally `false`
  (`event_journal.cpp:427-430`); `SanitizeUntrustedEventText` strips NULs and
  caps at `SEARCH_DESC_MAX`; untrusted text is stored and used only for
  relevance scoring (`model_watch.cpp:300-302`). The only execution an event
  can cause is an in-process `getmodel FREE_ONLY`. The three process-spawn
  sites in modelnet — `capability_runtime.cpp:87`, `pq1_runtime.cpp:68`,
  `helper.cpp:7786` — take hardcoded or env-derived commands, and the last
  one single-quotes via `QuoteShellArg`. No event field reaches any of them.
  One residue: the sanitiser keeps other control bytes, so ANSI escapes in
  publisher text survive into logs and terminals. Log-injection only, not
  execution.
- **No monetary mutation in scope.** `ReconcileDigestAuthorizesInsert()`
  returns false and is asserted in three suites; `GossipMessage` carries no
  economic field and rejects `secret_bearing`; every queued action stamps
  `spends=false` and `automatic_spend_atoms=0`; `FUND_WITH_MANDATE` refuses
  to be created without a `mandate_id` and stays unsigned with `wallet=false`.
- **Signature handling is real where it is applied.** `SearchRecordFromJson`
  forces `signed_ok=false` (`search.cpp:502`) so a peer cannot assert the
  flag; `SearchIndex::Put` re-derives it and enforces
  unsigned-cannot-override-signed, wrong-signer and sequence-rollback
  (`search.cpp:880-931`); `VerifySearchRecord` binds pubkey→`signer_id`
  before checking ML-DSA-44. `VerifySignedChannel` checks expiry, name
  charset, `btx://`-only target, pubkey→`publisher_id` binding and the
  signature; `ApplySignedChannel` additionally requires a strictly
  increasing sequence. `AcceptSignedAnnounce` rejects any envelope lacking
  `payload_hex`/`sig_hex`/`pubkey_hex` and cross-checks a claimed
  `record_id`.
- **Dedupe and restart.** Identical `(object_id, record_sequence,
  transition)` collapses in-process and across restart; the sequence file is
  written via temp+rename and the load path takes `max(seq_file, max event
  sequence)`, so a lost journal tail cannot hand out a colliding cursor.
- **Replay bounds.** Pages are hard-capped at 100 (`ReplayAfterLocked`), the
  RPC clamps any caller limit, and `WaitAfter` clamps the timeout to 24 h,
  polls in 50 ms slices and honours the shutdown flag.

Durability caveat on the above: `AppendLineLocked` flushes but never
`fsync`s, and `Observe` mutates `m_events` and `m_seq` *before* the append
succeeds, returning false on write failure with the in-memory state already
advanced. A power loss or a full disk can therefore leave memory and journal
disagreeing until the next restart.

## NOT_RUN — not executed, not extrapolated

- **N-1 — 20-peer mesh.** No test, and no mesh to test. There is no
  autonomous metadata gossip loop: `reconcilemodelindex` is operator-driven
  over the unix socket with caller-supplied `remote_ids`. A 20-peer claim
  cannot be derived from anything in this tree.
- **N-2 — IHAVE / IWANT.** No wire encoding exists. What is proven is that a
  want list truncates at `RECONCILE_WANT_MAX` for 300 and 400 remote ids
  (`modelnet_network02_tests.cpp:323-328`,
  `modelnet_scale_sparse_tests.cpp:43-49`) and that `secret_bearing` is
  refused. Nothing about exchange, timing, or duplicate suppression between
  hosts.
- **N-3 — Graft / prune.** Absent. No mesh membership, degree target, backoff
  or eviction state machine exists in the five files or on the peer HTTP
  surface. Nothing to review, nothing run.
- **N-4 — Local peer score only.** Vacuously satisfied: there is no gossip
  peer score to keep local. `ReciprocityLedger` is local useful-byte
  accounting on the transfer plane, not a gossip mesh score, and no peer
  score is serialised into any gossip or announce message. Treat "local peer
  score only" as unimplemented rather than proven.
- **N-5 — Anti-entropy at 100k / 1m / 10m.** NOT_RUN, and nothing in the
  executed evidence supports extrapolation. The largest compare exercised
  anywhere is 1 000 ids (`modelnet_convergence_tests.cpp:320-334`); the
  "sparse scale" suite uses 300/400 ids and a fabricated `entry_count` of
  10 000 000 with a two-character digest, which tests only the DIVIDE
  branch, not scale. Cost structure argues against extrapolating: every
  `Compare`/`CompareSets` copies and sorts the full id vector
  (`SortedUniqueIds`) and `MissingRemoteIds` builds a full
  `std::set<std::string>` of the local ids on each call, so a 10M-entry
  catalog allocates the whole set per reconcile round. Unmeasured.
- **N-6 — Offline recovery.** Single-process journal restart is proven at
  unit level (`modelnet_event_tests.cpp:36-71`). Multi-node reconnect and
  catch-up: NOT_RUN. Independent of execution, F-6 and F-7 mean recovery is
  incomplete by construction — a returning client cannot detect a gap, and a
  restarting node silently drops pending actions.
- **N-7 — The characterisation tests written for this lane were not run.**
  `src/test/modelnet_r5_gossip_tests.cpp` is new and is deliberately **not**
  registered in `src/test/CMakeLists.txt` (this lane was instructed not to
  touch CMake and not to compile). It has never been compiled or executed.

## Doc deltas

- `events.md:33` states "Missing fields stay **JSON null**".
  `ModelEventToJson` omits absent optional fields entirely rather than
  emitting null (`event_journal.cpp:334-338`, `328`). Agents parsing for
  null keys will see missing keys.
- `watches.md:24` describes a watch as firing when "a **signed** object
  changes". Per F-2 the MODEL kind fires on unverified observations, and per
  F-1 the other kinds fire on essentially nothing that came from a peer.

## Suggested priority

1. F-1 — otherwise SPEC 15.2 watches do not work at all on a real network.
2. F-11 — first thing a 20-peer mesh test will hit.
3. F-6, F-7 — offline recovery is claimed and is not sound.
4. F-3, F-5 — journal contract correctness (`event_id` uniqueness, fire-once).
5. F-9, F-10 — anti-entropy cannot converge as specified.
6. F-2, F-12, F-13 — authorisation boundaries.
7. F-4, F-8, F-14 — latent / hardening.
