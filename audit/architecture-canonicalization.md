# Architecture canonicalization (0.34.8 convergence)

Restamped 2026-09-17 against private tree `feat/0.34.8-modelnet-first-run`
(HEAD `573b4aa4`, working tree dirty, 0.34.8 work uncommitted). This is a
duplicate-abstraction audit, not a claim that every subsystem is proven at
scale. Read by file:line, not by memory: most of the 0.34.8 tree is
untracked, so `git log` does not describe it — and because it is untracked,
line numbers move under you. Every reference below was re-resolved against
the working tree at this restamp.

**0.34.8 is NOT_READY.** One canonical interface per subsystem is a
necessary property, not a release verdict: a subsystem can be perfectly
canonical and still unproven or unwired. Three REAL duplicates and two
wiring gaps are open below, and `audit/acceptance-matrix-0.34.8.csv` carries
7 `WITH_GAP` and 1 `IN_PROGRESS` row. `CLIENT_VERSION_IS_RELEASE` stays
`false`.

**Not compiled this round.** No edit below was build-verified.

Native HCP/CR11 is the one tier that is executed rather than read: 381
HCP/CR11/PRIV-08/unique-todo Boost cases with 0 failures plus six loopback
functionals at exit 0 (`audit/0348-remaining-unique-todos.md`). That
evidence is what lets the HCP/CR11 section below say "confirmed by
construction" instead of "believed". It proves nothing about the
multi-node, scale, MinIO, GUI, or mixed-0.34.7 conditions that the
acceptance matrix leaves NOT_RUN.

## Rule

One canonical interface per subsystem. A compatibility alias is allowed.
A second live object that independently admits work is not.

Corollary added this round: a second *byte-level parser of the same wire
format* is a duplicate even when both parsers are correct, because the two
can diverge silently.

## Subsystems

| Subsystem | Canonical interface | Canonical implementation | Compatibility adapter | Deprecated / duplicate |
|---|---|---|---|---|
| Piece storage | `PieceStore` (`piece_store.h:74`) | **contested** — library `LocalPieceStore` vs live helper path | `TieredPieceStore` (`piece_store.h:154`), PIECE_OBJECTS only | **REAL DUP-1**: live tiering is open-coded in `helper.cpp:4029` `TryHydrateFromCloud`; hierarchy is test-only |
| Cloud storage | `CloudObjectStore` (`piece_store.h:47`) | `S3PieceStore` (`s3_store.h:45`) over `S3Client` | `FakeS3` (`s3_client.h:92`) is a backend *under* `S3Client`, not a second store | no duplicate; MinIO is unproven rather than unavailable — see the MinIO note below |
| Origin layout | two distinct planners, both canonical | `cloud_layout.cpp` (provider key policy) and `object_layout.cpp` (swarm object arithmetic) | `CloudObjectLayout` SOURCE_FILES/PIECE_OBJECTS | none; `ObjectLayoutPlan::replaces_source_files` is hard-false |
| Provider routing | `RoutingTable` / `RoutingBucketIndex` (`provider_route.h:59,76`) | `provider_route.cpp:70` XOR leading **bit**, `ROUTE_BUCKETS = 384` | none | previous byte-index (48 buckets) is gone |
| Event journals | `ModelEventJournal` (`event_journal.h:139`) | `event_journal.cpp`, single bound instance | watches consume the journal via `BindJournal` | no second journal; see "journal" name overload below |
| Watch/subscription | `ModelWatchStore` + `SubscriptionStore` | `model_watch.h:112`, `subscription_mandate.h:174` | unsigned mandate; wallet sign NOT_RUN | not duplicates: RPC method sets are disjoint |
| `.btx` encoding | **contested** — one magic, two bodies | `package_bundle.cpp` (JSON body) and `package_core.cpp` (PJSON-1 body) | `EncodeMagnetAnalog` (`package_export.h:39`) is a *link*, not a container | **REAL DUP-2**: both emit `BTXPKG_MAGIC` + identical 68-byte header, incompatible payloads, no discriminator |
| Upload scheduling | `UploadSchedulerDrr` (`upload_scheduler_drr.h:75`) | `g_drr` (`helper_network02.cpp:67`), the only live gate | `UploadAdmission` (`upload_scheduler.h:32`) is the shared config type | `UploadScheduler::Admit/Release` is unit-test-only; header must stay for `UploadAdmission` |
| Piece picking | `PickRarestFirst` (`piece_picker.h:121`) | `piece_picker.cpp` | live `TransferSession` metrics | no second picker — but the one picker is only weakly wired; see GAP-2 |
| Erasure manifests | `ErasureManifest` (`erasure_manifest.h:35`) | `erasure_manifest.cpp` + per-stripe health | `erasure_store.cpp` is GF arithmetic + repair; forward-declares the manifest | `VerifiedManifest` is request verification, unrelated; global shard count is not sufficiency; SPEC 14 rework in progress, see the erasure note below |
| Source diversity | `DiversityKey` + `NetgroupKey` (`piece_picker.h:95,96`) | `piece_picker.cpp:65,71` | `DirectSeedNetgroup` (`direct_seed.cpp:125`) is the only real /24 derivation | **REAL DUP-3**: the live retrieve path sets `pid.netgroup = <host>`, so `max_per_netgroup` caps per-host, not per-/24 |
| Cloud credentials | `CredentialRef` / `CredentialRefKind` (`s3_client.h:27,32`) | `setcloudstorage` / `source_policy` indirection | argv secrets forbidden | no second credential type; torrent worker never receives S3 keys |
| Transfer jobs | `TransferSession` (`transfer_session.h:63`) | `transfer_session.cpp`; one `GlobalTransferCredits()` (`:50`) | none remaining | `request_ledger.h` alias **deleted this round** |
| Torrent import | `ByteSource` (`byte_source.h:21`) | `TorrentByteSource` (`source_torrent.h:32`) | subprocess `btx-torrentd` OPERATOR_GATED | `ReverseTorrentBridge` is accounting, not a second source; `reverse_bridge_live=false` |
| Hugging Face import | `ByteSource` | `HuggingFaceByteSource` + `XetByteSource` | local fixture; live HTTP NOT_RUN | one interface, several implementations is polymorphism, not duplication; hashes ≠ authorship |
| Anti-entropy | `IndexReconciler` (`index_reconcile.h:55`) | `index_reconcile.cpp` | `LocalDigest` / `AdmitInbound` are thin delegations (`:105,110`) | digest is not insert authority; no second reconciler |
| Gossip | `GossipMessage` + `GossipMessageAllowed` (`metadata_gossip.h:19,25`) | `metadata_gossip.cpp:13`, bounded IHAVE/IWANT | `MakeCatalogDigest` → `CatalogDigestHex` (single hasher) | `SearchIndex` is a local inverted index, not a gossip mesh |
| Mandate enforcement | `SubscriptionMandate` (`subscription_mandate.h:58`) | prepare-only without wallet keys | `AgentMandate` exact-terms preserved | helper never holds wallet keys; see gap below |

## HCP / CR11 / JIT

| Subsystem | Canonical interface | Canonical implementation | Compatibility adapter | Deprecated / duplicate |
|---|---|---|---|---|
| HCP engine | `HcpEngine` (`hcp.h:115`) | one `HcpEngine::Impl` (`hcp_engine.cpp:215`), one accessor `HelperEngine` (`:2738`) | `btx-hcpd` loopback (`src/hcpd.cpp`) fronts the same engine | **no second HcpEngine** anywhere in tree |
| Package core version | `PackageCoreVersion { V1, V2, V3 }` (`package_core.h:25`) | `package_core.cpp` v1/v2/v3 paths (`:666,673`), strict v2 gate (`:527`) | — | **no Core v4**: `package_core_version >= 4` → `HCP_ERR_CORE_V4` = `CORE_V4_FORBIDDEN` (`hcp_cr11_engine.inc.cpp`, `hcp_types.h:126`) |
| Customer ledger | none by design | `HCP_AUTOMATIC_SPEND_ATOMS = 0` (`hcp_types.h:20`) | — | **no second customer ledger**; only `ReciprocityLedger` (`policy.h:55`), which is peer reciprocity, not billing |
| CR11 cognitive reserve | negotiated extension `HCP_EXT_COGNITIVE_RESERVE` = `"cognitive-reserve"` (`hcp_types.h:56`) | `hcp_cr11.cpp` pure functions + `hcp_cr11_engine.inc.cpp` `#include`d into `hcp_engine.cpp:446` | gated on `cfg.cr11_enabled`, default **false** (`hcp.h:64`); 403 `PROFILE_UNSUPPORTED` when off | **not a fifth plane**: same `HcpEngine::Impl`, same lock, no separate process, state, or port |
| JIT capability tier | `HostResourceBroker` + `LeaseTable` (`capability.h:150,191`) | one `GlobalCapabilityBroker()` / `GlobalCapabilityLeases()`, both defined only in `capability_residency.cpp:63,68` | `CapabilityClient` (`capability_sdk.h:61`) is a client, not an engine | **no second credit broker**: JIT ensure uses `TransferSession(GlobalTransferCredits())` (`capability_ensure.cpp:6,603`) |

CR11 verdict: negotiated extension, confirmed by construction. The `.inc.cpp`
is textually included inside the single engine's `Impl`, so it cannot hold
independent state. It is off unless negotiated.

Unlike the rest of this document, the HCP/CR11 table is backed by an
executed run: the 381-case native tier (132 HCP, 190 CR11 plus J01–J20, and
the PRIV-08 / unique-todo cases) entered with 0 failures, and
`feature_modelnet_hcp{,_journeys}.py` and `feature_modelnet_cr11{,_journeys}.py`
exit 0 against loopback `btx-hcpd`. Two caveats that the case count hides:
`modelnet_cr11_ux_tests.cpp:163` and `:175` are counted as passes while
being respectively a literal searching itself and a character-for-character
duplicate of `modelnet_cr11_reserve_tests.cpp:14`, and every OAUTH_LAB /
CUSTODY_LAB tier is a loopback preset rather than a live CEX IdP or HSM.

## REAL duplicates found

### DUP-1 — Piece storage: two tiered-access implementations (COORDINATOR-REQUIRED)

`PieceStore` / `LocalPieceStore` / `TieredPieceStore` exist and are unit
tested, but **no live code constructs them**: `LocalPieceStore` and
`TieredPieceStore` appear only in `piece_store.cpp` and tests. The live
helper instead holds a raw `S3PieceStore` (`helper.cpp:1233 g_cloud`) beside
`ModelCatalog::Store()`, and open-codes local-then-cloud in
`TryHydrateFromCloud` (`helper.cpp:4029`) with its own quarantine
`ModelStore`, stampede gate, and `FileStreamHydration`.

These are two implementations of one policy, and they are **not
interchangeable today**: `TieredPieceStore` fetches PIECE_OBJECTS keys only,
while the live path streams SOURCE_FILES whole-file objects. So this is not
a drop-in substitution — consolidating means either teaching
`TieredPieceStore` the SOURCE_FILES strategy or admitting it is a
PIECE_OBJECTS-only special case.

Requires `helper.cpp`. **Not edited.**

### DUP-2 — `.btx` container: one magic, two incompatible bodies (COORDINATOR-REQUIRED)

Two independent byte-level codecs share the identical framing:

- `EncodeBtxBundle` / `DecodeBtxBundle` (`package_bundle.cpp:47,73`) — body is `UniValue::write()` JSON text, cap `MAX_BUNDLE_PAYLOAD`, ad-hoc `err` strings.
- `EncodeBtxPackage` / `DecodeBtxPackage` (`package_core.cpp:433,461`) — body is canonical BTX-PJSON1, cap `BTX_PACKAGE_MAX_PAYLOAD`, structured `err_code`.

Both write the same `BTXPKG_MAGIC` and the same 68-byte header
(magic[8] | flags LE32 | len LE64 | SHA-384 of body[48]), and both force
`flags == 0`. **There is no discriminator byte**, so the header alone cannot
tell a reader which body encoding follows; a caller must already know. The
caps agree at 4 MiB today but are separate constants.

This was previously recorded as "two *formats* (JSON analog vs binary), not
two engines." That was wrong on both halves: `EncodeMagnetAnalog` is a link
encoder, not a container, and the two container codecs genuinely are two
engines over one format identifier.

Callers are split and cross-cutting:
`package_export.cpp:185,191` → bundle; `helper_network02.cpp:339,393,500,1143`,
`hcp_engine.cpp:2203`, `package_channel.cpp:311` → package.

Consolidation would require `hcp_engine.cpp` and the helper TUs.
**Not edited.** Documented in both headers instead (see below).

### DUP-3 — Source diversity: two netgroup semantics (COORDINATOR-REQUIRED)

`DirectSeedNetgroup` (`direct_seed.cpp:125`) is the tree's only real netgroup
derivation: it strips the port, handles bracketed IPv6, and collapses IPv4 to
a /24. `NetgroupKey` (`piece_picker.cpp:71`) by contrast just returns
`peer.netgroup` as supplied by the caller.

The live caller supplies a bare host: the retrieve path sets
`pid.netgroup = eh` and both picker passes set `max_per_netgroup = 8`
(cited by symbol — `helper.cpp` moved during this restamp), which caps
**per-host, not per-/24**, so a single
operator on eight addresses in one /24 satisfies the picker's diversity cap.
Direct-seed admission, on the same tree, does enforce /24.

The inbound limiter is a third semantics again: it derives a numeric
netgroup from the address (`PQ1_MAX_INBOUND_PER_NETGROUP`). So the same word means a /24 on the
direct-seed path, a bare host on the picker path, and an address-derived
number on the inbound path. R1 records the consequence in both directions:
two addresses in one /16 are distinct netgroups to the picker, while every
peer in a loopback or single-host swarm collapses into one bucket where the
cap of 8 throttles the whole swarm per pass.

The fix is one line in helper.cpp (`pid.netgroup = DirectSeedNetgroup(...)`)
but it changes live admission behaviour and must be measured, not guessed.
Requires `helper.cpp`. **Not edited.**

## GAP-2 — one canonical picker, weakly wired (COORDINATOR-REQUIRED)

This is not a duplicate and it is not a missing implementation. There is
exactly one picker and it is a good one. The problem is that production
barely consults it, which means the canonicalization recorded in the table
above buys less than it appears to.

`helper.cpp` was also being edited while this restamp was written, so cite
by symbol; state observed 2026-09-17T16:26Z, and `audit/r1-swarm.md`'s line
numbers are stale.

Closed since that review:

- The whole-file shortcut is taken only when `extras` is empty, so a
  multi-peer retrieve enters the piece path. A single-peer retrieve of a
  file ≤ 64 MiB still never reaches the picker — which is every e2e fixture
  in `contrib/modelnet`.
- `ObservePeer` now has seven call sites, including the success path
  (`ObservePeer(winner, okm)`), so the leftover pass sees populated
  `PeerMetrics` rather than defaults.
- `CancelAfterCommit` has a production call site.
- `piece_rid` keeps a vector of request ids per piece, and the commit path
  `NoteCommitted`s the winner and `NoteFailed`s the rest. An endgame loser's
  reservation is released instead of being overwritten and stranded until
  the session destructor.

Still open:

- **No rescheduling loop.** There are two `PickRarestFirst` passes (main and
  leftover), not a loop driven by arrival, loss, progress, timeout or
  pressure. The first pass still reads `Metrics()` from a session with no
  requests in flight, so its window is `min_inflight_bytes` per peer. The
  multi-round loop exists only inside
  `modelnet_convergence_tests.cpp:182-208`.
- `ClassifyPeer` (the `piece_picker.h` one, not the unrelated
  `policy.h:116` trust label) and `SummarizeSwarm` have **zero** production
  callers, so no peer is ever classified SLOW or SNUBBED and the swarm
  snapshot is never produced.
- `service_id` is never populated on the retrieve path, so `DiversityKey`
  falls back to the endpoint and N helper ports on one host count as N
  independent sources.
- `pid.netgroup` is a bare host with `max_per_netgroup = 8` — DUP-3 above.

The reason this belongs in a canonicalization audit is that "no second
picker" and "the picker decides" are different claims, and only the first is
fully true today. `audit/acceptance-matrix-0.34.8.csv` records the second as
`R1-picker-production-wiring` / `WITH_GAP`, and the 45-byte loopback swarm as
`CONV-05-swarm-live` / `WITH_GAP` for the same reason: a 1-piece artifact
cannot exercise a scheduler, so none of the fixes above has been observed
either.

Requires `helper.cpp`. **Not edited here.**

## Erasure: SPEC 14 per-stripe record is mid-rework

`src/modelnet/erasure_manifest.cpp`, `src/modelnet/erasure_store.cpp` and
`src/test/modelnet_r6_erasure_tests.cpp` are all **untracked and were being
edited while this restamp was written** — the manifest TU changed twice in
the span of it. So `audit/r6-erasure.md`'s `FAIL for SPEC 14` verdict is
stale, and so is every line number in it. Cited by symbol below for the same
reason; state observed 2026-09-17T16:26Z.

- `ErasureHealthJson` emits all four required per-stripe fields —
  `k_required`, `independent_shards`, `distinct_failure_domains`,
  `reconstructable` — plus `distinct_stored`, `distinct_effective`,
  `deficit`, a `preservation_reconstructable` gated on
  `RequiredFailureDomains`, and a `repair_target` handle on every deficit
  stripe.
- `independent_shards` counts distinct **stored** positions only. Dummy
  zeros are excluded by construction, which was the core objection.
- `ErasureEffectivePositionSets` credits tail padding through
  `ErasureStripeIndexSetOk` + `TailStripeOffset`, so credit follows
  `stripe_index` rather than array order and a manifest author can no longer
  choose which stripe receives it. `final_real_piece_count` is cross-checked
  against `file_size_bytes` / `shard_bytes` / `stripe_count` in the parser.
- `RepairCanonicalFromShards` verifies `shard_hash_hex` when present, writes
  via tmp + `O_EXCL` + `fsync` + `rename`, and bounds each shard read by
  `shard_bytes`. `RepairStripeFromFiles` gives repair a single-stripe
  target.
- The profile allowlist now admits only `ERASURE_PROFILE_CAUCHY_16_20_V1`;
  the review-only `r6-review-k-n` escape hatch is gone. `field_polynomial`
  is enforced.
- Repair has a production caller: `ErasureFromObject`
  (`helper_network02.cpp`) runs a real GF decode and reports
  `recovered_data_shards` when the request carries `shards` + `positions`.

Why this is `IN_PROGRESS` and not done:

1. **Nothing was compiled.** Every property above is read off the page.
2. `src/test/modelnet_r6_erasure_tests.cpp` is registered in
   `src/test/CMakeLists.txt:663`, but registered is not built: the suite
   written specifically to pin these properties has never executed once.
   The only *executed* erasure cases
   (`conv_erasure_global_n_is_not_reconstructable`,
   `erasure_per_stripe_not_global_count`) predate the rework and cover the
   old record.
3. The source is moving under the audit. Anything asserted about these two
   TUs has a shelf life measured in minutes until a build pins it.

Repair still requires the caller to hand in shard bytes; nothing fetches
shards or spends, so CONV-19 stays a deliberate deferral on the
*autonomous* repair question.

This is a reporting-record and build question, not a duplicate: there is
one manifest type, one health evaluator, one GF codec.

## MinIO: unproven, not unavailable

The previous stamp said "no MinIO process in this environment". That
understated what is possible: `docker` 29.5.2 is installed and `/` has 165G
free, so a MinIO service **can** be stood up here. The `minio` binary is
absent from `PATH`, and — the actual blocker — no harness exists: no compose
file, no service unit, no functional test. `rg -i minio` hits only config
parsing (`CloudProvider::MINIO`, name parsing, loopback-http validation) and
`r2s_07_minio_is_config_only_not_run`, which honestly records the gap.

`FakeS3` is not a substitute and is not a duplicate store — it sits *below*
`S3Client` as an in-process backend. `CONV-10-minio` stays `NOT_RUN` until a
docker-based MinIO e2e is written and executed across all four layouts.

## Consolidated this round (no coordinator file touched)

- **Deleted `src/modelnet/request_ledger.h`.** Verified dead before removal: included by zero translation units, referenced nowhere in `src/` or the wider tree, untracked by git, and not named in `src/modelnet/CMakeLists.txt` (which lists `.cpp` only, 174 lines, no globs). It held only `using RequestLedger = TransferSession;`. Removing it deletes the last thing in the tree advertising a second ledger name.
- **`package_bundle.h`** — comment on `BTXPKG_MAGIC` recording that the magic and 68-byte header are shared with the `package_core.h` pair, that the bodies do not decode across, that `flags` is 0 in both so the header is not a discriminator, and that the two must not be "unified" by pointing one decoder at the other's bytes.
- **`package_core.h`** — comment on `EncodeBtxPackage` stating the shared header, the body divergence, and that new callers should prefer the PJSON-1 pair.
- **`metadata_gossip.cpp`** — comment on the bare `256` want cap in `GossipMessageAllowed` recording that it must stay equal to `RECONCILE_WANT_MAX` (`index_reconcile.h:18`), that it is a literal only to keep this file below `index_reconcile` in include order, and that raising one without the other makes `IndexReconciler` emit want lists its own `AdmitInbound` rejects.

Still true at this restamp: `src/modelnet/request_ledger.h` is absent from
the tree and no translation unit references `RequestLedger`.

## Fixed elsewhere since the previous stamp (verified here, not authored here)

Recorded so this document is not read as a standing complaint about code
that has since changed:

- The whole-file shortcut is now skipped when extra peers are known, so a
  multi-peer retrieve enters the piece path. GAP-2 narrows accordingly; it
  does not close.
- Leftover pieces stay on the main pool, and `pieces_committed` no longer
  double-counts a 1-piece file.
- `ObservePeer` is now called on the success path as well as on failure, and
  `CancelAfterCommit` gained a production caller. Endgame losers release
  their credit.
- `cr11_ux_01_six_primary_screens` was rewritten to resolve six real engine
  objects instead of searching a string literal for its own substring. Its
  siblings at `modelnet_cr11_ux_tests.cpp:163` and `:175` were not.
- `src/test/modelnet_gap_hunt_tests.cpp`,
  `src/test/modelnet_r1_swarm_tests.cpp` and
  `src/test/modelnet_r6_erasure_tests.cpp` are now registered in
  `src/test/CMakeLists.txt` (658, 659, 663). Registered is not compiled and
  not run.
- The erasure SPEC 14 rework described above, including the removal of the
  review-only profile from the allowlist and a production repair caller.

All four consolidations listed above this section are documentation or
dead-code removal. None changes behaviour.

The gossip cap would be better fixed by moving the constant into
`metadata_gossip.h` and aliasing it from `index_reconcile.h`, but that is a
cross-header change and this round does not compile.

## Verified NOT duplicates (recorded so nobody merges them)

- **"Journal" is overloaded across three unrelated roles.** `ModelEventJournal` is the append-only observable event log; `MultipartJournal` (`multipart_journal.h:32`) is an S3 multipart-upload resume state machine whose `etag` is explicitly *not* SHA-384 identity; `PaymentJournal` (`transfer.h:32`) is a per-quote row struct, not an engine. Shared noun only.
- **Three routing caches, three jobs.** `ProviderCache` keys `ProviderRecord` by resource digest (who has what); `RouterCache` (`router.h:61`) keys `SignedRecordHint` by record id (signed metadata); `QueryRouter` (`query_router.h:67`) produces routing summaries. Different keys, different payloads.
- **Watch vs subscription RPC sets are disjoint.** `IsModelWatchHelperMethod` (`model_watch.cpp:818`) owns 15 `*model*watch*`/`*event*`/`*channel*` methods; `IsSubscriptionHelperMethod` (`subscription_mandate.cpp:967`) owns 4 `*subscriptionmandate` methods. No method is claimed twice.
- **Anti-entropy delegates rather than reimplements.** `IndexReconciler::AdmitInbound` is a one-line call to `GossipMessageAllowed`; `IndexReconciler::LocalDigest` is a one-line call to `MakeCatalogDigest`, which calls the single `CatalogDigestHex` hasher. One implementation of each rule.
- **Cloud storage is properly layered.** One interface, one real implementation, and `FakeS3` sits *below* `S3Client` as an in-process backend rather than beside `S3PieceStore` as a second store.
- **Two layout modules are two problems.** `cloud_layout.h` decides provider key policy and read strategy (R2 AUTO → SOURCE_FILES + STREAM_FILE); `object_layout.h` does swarm object arithmetic (pieces / 256 MiB extents / 64 MiB multipart parts). They share the enumerator *names* `AUTO` and `PIECE_OBJECTS` in two distinct enums, which is a naming hazard, not a second store.
- **Import sources are polymorphic, not duplicated.** One `ByteSource` interface with `TorrentByteSource`, `HuggingFaceByteSource`, `XetByteSource`, and the local source as implementations.
- **JIT introduces no second engine.** `capability_ensure.cpp:6` states the invariant and `:603` honours it by constructing `TransferSession(GlobalTransferCredits())`. `GlobalCapabilityBroker` and `GlobalCapabilityLeases` each have exactly one definition.

## Remaining honest gaps (not silently canonical)

- **Mandate enforcement is not wired to the watch action queue.** `SubscriptionMandate` and `EvaluateAndReserve` are referenced only inside `subscription_mandate.*`; `AgentMandate` appears in the tree only as a canonical-codec type name (`canonical_codec.cpp:377`). `ModelWatchStore::DrainActions` therefore hands out queued actions without consulting a mandate. That is a **gap**, not a duplicate — there is no competing enforcer, there is no enforcer.
- **The one canonical picker is weakly wired** (GAP-2). Live piece-range super-seeding still uses complete helper catalogs; overlapping ranges are proven in-process only, and the only executed swarm evidence is a 45-byte 1-piece loopback fixture that never invokes `PickRarestFirst`.
- **The SPEC 14 per-stripe erasure record is mid-rework and unbuilt**, and its repair engine has no production caller.
- `g_drr` is process-global and mutexed; it is not persisted across helper restart.
- `SearchIndex` and `QueryRouter` are different jobs (local index vs routing summary) and must not be merged.
- `UploadScheduler::Admit` / `Release` is dead runtime logic reachable only from `modelnet_network02_tests.cpp:276`. The header cannot be deleted because `DrrConfig::admission` depends on `UploadAdmission` from it. Deleting only the two dead methods is a live-file edit and was not attempted without a compile.

## Honest NOT_RUN (canonical in source; never exercised here)

Each of these has exactly one canonical interface in the tree, so none is a
duplication finding. They are listed because "one implementation" plus
"never run" must not read as "proven". Full reasons live in
`audit/acceptance-matrix-0.34.8.csv`, `audit/hcp-not-run.md` and
`audit/cr11-not-run.md`.

| Area | Canonical surface exists | Why NOT_RUN |
|---|---|---|
| `BUILD_GUI=ON` | `src/qt/modelnetpage.*`, `forms/modelnetpage.ui` | no Qt6 on this host and a second cmake tree is forbidden; source was read and is clean, which is not a build |
| F2 wallet-signed | `caps.wallet_sign`, `wallet_signed` | the helper never holds wallet keys; both flags are asserted **false**, which is the honest shape |
| Live Hugging Face / Xet HTTP | `HuggingFaceByteSource`, `XetByteSource` under one `ByteSource` | operator did not authorize internet HF; `live_hf_http=false` and the SSRF pin asserts no live HTTP is attempted |
| CUDA / ROCm / Metal / NIXL / GDS / CXL | `qualification.cpp`, `capability_moe.cpp`, `capability_fuse.cpp` | no accelerator on this host; the guards exist specifically to refuse a faked GPU PASS, and the live CUDA attestor on the signer host is not test hardware |
| uTP / QUIC | none — NONSHIPPING by design | PQ1 over TCP is the shipped transport; there is no second transport to duplicate and no path to exercise |
| `btx-torrentd` process | `TorrentByteSource` + subprocess, OPERATOR_GATED | NONSHIPPING as a separate process (`torrentd_process=false` with the reverse bridge mapped inside the helper), so no daemon exists to isolate |
| `WITH_MODELNET=OFF` second tree | `src/modelnet/disabled_stub.h` | a real OFF build needs a second cmake tree that the disk/memory policy forbids; the `ENABLE_MODELNET`-unset probe is a script check, not a rebuild |

Wallet-signed mandates remain NOT_RUN for the same reason as F2: the helper
holds no wallet keys, so `SubscriptionMandate` can only ever be prepared
here.

## Coordinator-required queue

| ID | Subsystem | Action | Blocking file |
|---|---|---|---|
| DUP-1 | Piece storage | Route live piece access through `PieceStore`, or record `TieredPieceStore` as PIECE_OBJECTS-only and stop calling it canonical | `helper.cpp` |
| DUP-2 | `.btx` encoding | Pick one container body, or add a real discriminator in `flags` instead of forcing 0 | `hcp_engine.cpp`, `helper_network02.cpp` |
| DUP-3 | Source diversity | `pid.netgroup = DirectSeedNetgroup(endpoint)` so `max_per_netgroup` caps per-/24, and reconcile the third (inbound, address-derived) semantics | `helper.cpp` |
| GAP-1 | Mandate enforcement | Decide whether `DrainActions` must consult `SubscriptionStore` before release | `helper.cpp` |
| GAP-2 | Piece scheduling | Feed `ObservePeer` from the success path and reschedule in a loop, or stop describing the picker as the production scheduler | `helper.cpp` |
| SPEC14 | Erasure | **Build and run** `modelnet_r6_erasure_tests.cpp` (registration and the allowlist/repair-caller items are done); then decide whether repair may ever fetch its own shards | one incremental `build-gcc13` compile |
| TIDY-1 | Upload scheduling | Delete `UploadScheduler::Admit/Release`, keep `UploadAdmission` | `upload_scheduler.{h,cpp}` + test |
| TIDY-2 | Gossip | Move the want cap to `metadata_gossip.h`; alias from `index_reconcile.h` | needs a compile |
