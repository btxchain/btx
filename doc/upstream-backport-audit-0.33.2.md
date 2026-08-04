# Bitcoin Core and Bitcoin Knots catch-up audit for BTX 0.33.2

## Decision

This branch is the comprehensive 0.33.2 catch-up candidate. It contains the
earlier generic Core/Knots safety backports, the parallel-prevout architecture
from the supplied screenshot, and a second pass over merged and open upstream
work for release-relevant correctness, storage, wallet, networking, and
performance changes.

The result is recommended for review and CI as a release candidate, not as an
already-approved public release. BTX still has no published `v0.33.2` tag. The
integration base is local `main` at `0a623914277028391352eb4bd1634c91828c2445`,
whose release notes still describe 0.33.2 as being prepared. Platform CI,
reproducible builds, the production activation gates, and final integration
with BTX-local work remain required before cutting the tag.

The parallel-prevout work also remains independently reviewable as a focused
patch set. The aggregate release change does not replace that compatibility-
boundary review.

## Audit boundary

Cutoff: 2026-07-17.

| Source | Audited point | Scope |
| --- | --- | --- |
| BTX integration base | `0a623914277028391352eb4bd1634c91828c2445` | Intended 0.33.2 base |
| Bitcoin Knots fork point | `v29.2.knots20251110` / `7b009f5531b9641f3fe5456f668638c5ddd5929a` | Point from which BTX diverged |
| Bitcoin Knots 29.x | `f41f01e1e6de7025d52a865bef97f2a67277f0f3` | 1,164 post-fork commits screened |
| Bitcoin Core master | `70d9ec7f3d452789d04dce81dc02db0b3b778bb5` | Landed v32-era work and later fixes |
| Bitcoin Core maintained releases | 30.3 and 31.1 tips at the cutoff | Release-fix cross-check |
| Bitcoin Core open work | 343 open pull requests at the cutoff | Unmerged correctness/performance candidates |
| Bitcoin Knots open work | 54 open pull requests at the cutoff | Knots-only fixes and platform candidates |

BTX was published as a squashed source snapshot, so its Git history is not a
descendant of Knots. The source boundary is nevertheless exact: 2,806 of
Knots' 2,829 blobs are present byte-identically at the same paths in BTX's
2,913-blob import root `c742979d8ec3c33fcd5c51a183bbdf1778f1afb8`; 107
shared paths changed for the initial BTX chain, proof-of-work, mining, and
project work, and BTX added its own files. This also establishes that the
pre-boundary Knots changes are source inherited even though `git merge-base`
cannot express the relationship.

The exhaustive commit sets at the cutoff are:

| Set | Commits | Disposition |
| --- | ---: | --- |
| Core history already present in the Knots source boundary | 44,111 | Inherited baseline; no re-port |
| Knots-only ancestors of the BTX source boundary | 2,554 | Inherited baseline; BTX-sensitive paths checked by tree comparison |
| Core commits absent from the BTX source boundary through the audited tip | 5,595 | Screened by subsystem, release notes, fix keywords, patch equivalence, and invariant review |
| Knots commits after the BTX source boundary | 1,164 | All 327 non-merge changes plus 837 merge/backport records screened |

The histories therefore do not have ancestry suitable for blind cherry-picking
into BTX. Changes were selected by invariant and adapted to BTX's MatMul headers,
Freivalds payloads, shielded state, P2MR-only policy, PQ wallet, and existing
database contracts. “Comprehensive” here means every plausible release-relevant
candidate was classified; it does not mean Bitcoin-specific consensus or
policy features were imported.

For reproducibility, the sorted inventories have SHA-256 digests
`7fb98dcb2a9f662650fe236da8ed4fd843fe064b6cf48117fbdd22feeb1220ff`
(inherited Core),
`7e092bc0c283ff24fd238efc43b1084001bc72247c25f6377db5fd1b351c558d`
(pre-boundary Knots-only),
`9e2f4ab5fc9383e91b7cd2480e495173448b390a03d45bb8ea5cdb19e567b77d`
(Core absent from the source boundary), and
`698b3fc132c58a8cb161141e219cd687cab629f66d1050b039c2f18740eca292`
(post-boundary Knots). The open-PR inventories have digests
`02217574119397478d6ba5de2ec0ade78434dd7f263e02fe82d3a207bb425628`
(Core) and
`e46b3e84ec90ed151a393e9c093ad6c72f53b1b253ee4f62ed678faa2da4b7f3`
(Knots). Stable patch IDs additionally identified 193 topology-absent Core
patches and 56 post-boundary Knots patches as exact content already present in
the source snapshot, BTX history, or the other upstream.

`contrib/devtools/upstream-catchup-audit.sh` regenerates the four immutable
commit inventories from the pinned objects, records hashes, and, when GitHub's
CLI is available, snapshots the current open-PR metadata for comparison with
the cutoff. This preserves the set construction rather than relying on the
digests alone; open PRs remain time-varying and must be re-screened if their
heads move before the release cut.

## Included work

### Baseline Core/Knots safety set

The reviewed 33-commit upstream-backport baseline remains intact.
It includes:

- chain-tip reconstruction, block-file bounds, transaction-precompute lifetime,
  `m_blocks_unlinked`, reindex shutdown, and scheduler/client teardown fixes;
- BDB recovery bounds, wallet null-dereference, fee-bump, pruned-funds,
  scan-position persistence, callback draining, and load-time abandonment fixes;
- settings-write, REST parsing, file-descriptor limit, `-lowmem`, Tor control,
  terminal echo, RPC initialization, and local-address score hardening;
- Codex32, EllSwift, Miniscript, PSBT proprietary-field, LevelDB initialization,
  background compaction, and seek-compaction fixes.

### Chainstate, indexes, database, and block storage

| Upstream | BTX result |
| --- | --- |
| Core #34897 | Index commits are capped at the last durably flushed UTXO block; the actual durable locator is signalled. |
| Core #35307 (open) | Snapshot-base block classification, cursor flushing, restart unlinked recovery, historical-chain selection, and VerifyDB boundaries are fixed with BTX shielded-state assertions. |
| Core #33512, #33680 | Dirty-UTXO accounting and force-sync versus force-flush semantics are ported without wiping statistics/scan/snapshot state. |
| Core #35620 | LevelDB block-cache allocation is avoided for 64-bit mmap/uncompressed databases and reassigned to write buffering. |
| Core #35714, #34931, #35654, #35003, #35731, #35354, #35621, #35498 | Relevant database, flat-file, block-storage, filter-index, cursor, and compact-block read/write hardening is ported, including BTX shielded-data request handling. |
| Core #34743 | Manual-peer reconnects respect a bounded cooldown without bypass through direct header fetching. |
| Core #35728 | Transaction-not-found is distinguished from block-file I/O failure through txindex, RPC, REST, txoutproof, and PSBT lookup paths. |
| Core #34521, #34786 | Candidate sets are populated only after shared sequence IDs stabilize, and snapshot-base candidates are isolated to the assumed-valid chainstate. |
| Core #30469 | CoinStats lifetime-volume counters use 256-bit arithmetic; the corrected index rebuilds in versioned `indexes/coinstatsindex` storage while the old index remains available for downgrade cleanup. |
| Core `335a098a`, `5e77072f`, `3e5dc610` | `gettxoutsetinfo` takes the UTXO cursor and its identifying tip atomically and reports the block associated with the completed scan. |
| Core `d7c9d6c2` | A failed coins-cache flush retains correct memory accounting and cached entries for retry. |
| Core #33604 | Block download from competing peers resumes after background snapshot validation completes. |
| Knots `4a4e4e25` | Pruned block-filter, CoinStats, and transaction indexes fail with an actionable rebuild-or-disable message. |

### Validation and mempool correctness

| Upstream | BTX result |
| --- | --- |
| Core #35026 | Stale BIP68 lockpoints are recomputed after a reorg; BTX P2MR functional coverage is included. |
| Core #31682 | Duplicate-input detection uses the sorted-vector algorithm with BTX-aware transaction handling. |
| Core #33602 | Coins-cache propagation uses a single `try_emplace` path. |
| Core #34320 | `HaveCoin()` takes the corruption-aware `GetCoin()` path. |
| Core #35017 | Failed and later package members are removed consistently. |
| Core #35657 | Transaction inputs are traversed once in the adapted validation path. |
| Core #33956, #34054, #33553 | Reconnection lifetime, IBD transaction-task, and invalid-chain warning fixes are included. |
| Core #35218, #35295, #35738 | UTXO overlay offset/fuzz fixes and the merged parallel-prevout implementation plus open lifecycle hardening are included. |
| Core #31835, #30479 | Invalid descendants receive consistent failure flags, dirty-index persistence, and reset handling. |

### Networking, compact blocks, privacy, and parsing

| Upstream | BTX result |
| --- | --- |
| Core #35550 | `SENDCMPCT` announce is strictly parsed as uint8 `0` or `1`. |
| Core #32606 | Compact blocks are ignored in blocks-only mode, require negotiation, and reject unsolicited non-high-bandwidth messages, while preserving BTX's full Freivalds payload path. |
| Core #35727 | Compact-block extra-transaction accounting is corrected. |
| Core #34162, #34997 | `getaddr` underfill is fixed and feelers no longer participate in address relay. |
| Core #35600 | Duplicate manual connections are prevented and regression-tested. |
| Core #35578 | Proxy/private-network address handling avoids unintended disclosure. |
| Core #33414 | Tor control enables proof-of-work defences with a compatibility fallback and fuzz coverage. |
| Core #35696 | I2P lease-set encryption preference is updated to `6,4`. |
| Core #35281 (open) | UniValue input parsing is bounded, with unit and fuzz coverage. |
| Core #34538 | Explicit `-externalip` entries are honored even when `-onlynet` makes their network unreachable, preserving the existing Tor exception. |
| Core #32757 | Explicit wildcard `-bind` and `-whitebind` configurations retain local-address discovery. |
| Core #34028 | Both `AddLocal` and `SeenLocal` saturate address scores instead of overflowing. |
| Core `fabd4d2e`, `316a0c51`, `0448a19b` | SpanReader bounds, invalid `addpeeraddress`, and IPC path/`ENOTDIR` handling are hardened. |
| Core `e49a7274` | RPC usernames and passwords are kept as separate values, allowing colons in credentials and avoiding a plaintext join/split cycle. |
| Knots `2da7001d`, `838fe961`, `9a4431e0` | Bans expire at the exact boundary and GUI consumers receive a scheduled expiry sweep. |

### Wallet correctness and privacy

| Upstream | BTX result |
| --- | --- |
| Core #34698 | MiniMiner failures propagate as `util::Result` through coin listing, selection, transaction creation, `sendall`, interfaces, and BTX PQ sweeping. |
| Core #34759 | Wallet database encryption hashes private-key material directly instead of creating an avoidable copy. |
| Core #33268 | `sendall` returns a useful error when transaction size is not available. |
| Core #34872, #34176, #34379, #34544, #35092, #35224, #35294 | Wallet load, dump, descriptor, transaction, backup, and SQLite correctness fixes are adapted. |
| Core #35317, #35440, #35492, #35512, #35579, #35633, #35665 | Later wallet persistence, rescan, RPC, descriptor, and transaction fixes are adapted with PQ/P2MR behavior retained. |
| Core #33014, #34358, most of #34370 | Equivalent behavior was already present and was verified rather than duplicated. |
| Core #31774, #35254, #35688 (open) | AES state, HMAC temporaries, and BIP32 chain codes use cleansed storage; empty HMAC keys are accepted and tested. |
| Knots open #249 | BDB writability, exception, refcount, checkpoint, LSN, cleanup, and file-ownership handling is hardened. |
| Core `0f602c56`, `fd44d48b`, `fefa3be7` | Empty/ancient wallet migration and optional effective-value totals are corrected. |
| Core wallet migration series | Direct-file backup placement, safe generated-file cleanup, watch-only-only migration, and zero-value owned-input `IsFromMe` behavior are adapted to BTX mixed-input fee reporting. |

### RPC, process, platform, ZMQ, and performance

| Upstream | BTX result |
| --- | --- |
| Core #31298 | `combinerawtransaction` requires at least two mutually compatible transactions. |
| Core #35303 | Negative fee rates format correctly. |
| Core #35613 | ZMQ bind/setup failure tears down cleanly. |
| Knots `163d3e5c` | Fee-estimator scale multiplication cannot overflow. |
| Knots `012a5fa384` | Windows exclusive `wbx` file creation uses `_wsopen_s`; obsolete MinGW workarounds are removed. |
| Core #35215 | SipHash-1-3-UJ and the salted coins-cache hasher are ported. |
| Knots open #298 | Integer option narrowing and multiplication are bounded for ancestor/descendant sizes, script size, and bytes-per-sigop. |
| Knots open #309, #330, #331, #332 | ARM crypto probing, NetWatch allocation/thread/teardown safety, RPC wallet selection, and translated receive-label handling are fixed. |
| Core #34914, #35068, #35617 | macOS nested signing, depends CMake discovery, and `btx-tx` error formatting are corrected. |
| Core `b6b1d065`, PR #29678 | Benchmark counters are initialized correctly and the first-run disk estimate rounds upward. |

Measured microbenchmarks on the audit host:

- SipHash: 11.93–13.29 ns to 4.14–4.32 ns, a 2.76–3.21x speedup.
- Coins-cache insertion: 228.29 ns to 194.88–199.79 ns, 12–15% lower.
- Maximum-block duplicate-input rejection: 164.86 ms to 35.54–36.76 ms,
  a 4.5–4.6x speedup.

## Parallel-prevout result from the screenshot

The screenshot refers to Core PR #35295, merged as `c0e91efdb3`, plus its UTXO
overlay and reusable thread-pool prerequisites. The aggregate contains that
architecture, not merely the final validation-loop diff. It also incorporates
the applicable open #35738 hardening and retains BTX's `bool Flush()` error
contract, transparent/shielded queue ordering, and Freivalds/P2MR behavior.

Correctness is confirmed: overlay/thread-pool unit tests pass; serial and
parallel P2MR functional nodes accept the same external-prevout block and reach
the same tip; every benchmark trial ended with identical serial, parallel, and
generator tips.

End-to-end persisted-UTXO measurements used the same release binary,
`-dbcache=4`, `-par=1`, a restart before each submission, alternating submission
order, and median-of-six connect times:

| Prevout layout | Serial | Parallel | Result |
| --- | ---: | ---: | ---: |
| 20,000 contiguous, 2 workers | 47.31 ms | 39.79 ms | 1.19x faster |
| 20,000 scattered transaction IDs, 2 workers | 52.39 ms | 39.72 ms | **1.32x faster** |
| 50,000 contiguous, 8 workers | 129.39 ms | 153.07 ms | 0.85x; slower |
| 20,000 scattered transaction IDs, 8 workers | 51.91 ms | 57.10 ms | 0.91x; slower |

This confirms that the mechanism can deliver the screenshot's 30–40% range,
but also that an eight-worker default regresses fast storage on this host. BTX's
default is therefore reduced to two; `-prevoutfetchthreads=0` remains the serial
control and values through 16 remain available for slower/high-latency storage.
These tests establish block-connect improvement, not a blanket whole-IBD
guarantee for every device.

## Classified but not ported

No further release-critical fix identified in the audited ranges is silently
outstanding. The remaining candidates are intentionally deferred or excluded:

- Core #34400 parallel wallet scanning is still draft work and needs a separate
  PQ/shielded scanner design and benchmark.
- Core #34864 cache redesign, #35071 resumable reindex, and broad refactors such
  as #34254/#33854 are useful future projects, not bounded 0.33.2 bug fixes.
- Core #35113's unmerged BlockRequestTracker/RPC behavior and #33854's
  reindex/header-sync redesign are large state-machine changes that require
  dedicated BTX branches and functional matrices.
- Core #35730, #35614, and #34577 target Core's newer HTTP server architecture;
  BTX still uses libevent, so direct patches would not address the equivalent
  resource-management boundary.
- Core #35616's 32-bit cache-size plumbing is not required by BTX's existing
  caps; widening the full cache interface is deferred to a 32-bit platform CI
  project. Core #35704 likewise requires a dedicated Windows/C++26 lane.
- Core #35692 is invariant-only AddrMan cleanup with no current BTX behavior
  change. Core #32df's cross-category option-registration assertion is omitted
  because BTX deliberately re-registers server arguments in reusable test
  fixtures; the existing same-category duplicate assertion remains.
- Core #35195's outpoint-hash cache trades a reported small speed gain for
  additional libstdc++ node memory. It remains benchmark-gated on BTX Linux.
- Index initial-sync parallelism (#26966/#34489) remains a separate durability
  project rather than a point-release patch.
- Core #35676 takes a competing filesystem-error strategy; mixing it with the
  selected flat-file and Expected-based I/O changes would enlarge risk without
  a demonstrated BTX defect.
- Bitcoin consensus parameters, checkpoints, AssumeUTXO constants, seeds,
  service bits, and deployment changes are incompatible with BTX.
- Knots RDTS/BIP110, sub-dust, OP_RETURN, and other Bitcoin-specific relay
  policy changes conflict with BTX financial-only/P2MR policy.
- Wallet/address changes that assume only Bitcoin descriptors remain excluded
  unless their PQ, shielded-note, bridge, and auto-shielding behavior is defined.
- Automatic RAM-derived `-dbcache` retuning remains deferred until BTX's custom
  indexes and shielded/PQ memory profile are measured in containers and on
  release hardware.

The audit must be refreshed if Core or Knots moves after the cutoff.

## Verification

Completed on macOS/Apple Silicon:

- Full CMake build passed for daemon, CLI/tools, wallet, GUI, benchmarks, unit
  tests, secp256k1, and BTX PQ/shielded helpers.
- CTest's isolated-suite matrix passed all 275 selected targets in 790.62
  seconds, including the high-priority benchmark sanity job. The separately
  tested Cocoa GUI target and unrelated exhaustive secp256k1 job were excluded
  from that matrix invocation.
- 162 focused high-risk unit cases passed across indexes, chainstate writes,
  coins/overlay, database/flat-file, txindex, streams, MiniMiner, wallet,
  Tor, fee estimator, amounts, compact blocks, filters, hashing, transactions,
  and chainstate-manager/AssumeUTXO behavior. Agent-local focused runs also
  passed their added suites.
- All 42 chainstate-manager/AssumeUTXO cases passed, including successful and
  failed delayed shielded snapshot activation; all 12 blockchain/CoinStats
  cases and concurrent indexed/non-indexed `gettxoutsetinfo` checks passed.
- Networking, streams, ban, RPC, and wallet focused suites passed. Both v1 and
  v2 `rpc_setban` functional transports passed after making BTX's intentional
  `noban` permission explicit in the fixture.
- Cocoa App, Options, URI, and nested-RPC Qt suites passed. A real `btx-qt`
  regtest process autonomously removed a two-second ban at exact expiry without
  a polling RPC, then shut down cleanly.
- `feature_prevoutfetch.py`, the serial/parallel benchmark, strict SENDCMPCT,
  BIP68 stale-lockpoint, duplicate-manual-peer, address-relay, and IBD-stalling
  regressions passed.
- The new AssumeUTXO stored-base/restart/checklevel-4/shielded-state subtest
  passed twice end-to-end.
- `feature_io_errors.py --descriptors` passed with a BTX-valid P2MR fixture.
- A separate `WITH_ZMQ=ON` configuration compiled the daemon and unit binary;
  the occupied-address startup regression passed at runtime.
- A separate fuzz configuration compiled the complete fuzz binary, including
  every modified fuzz target.

Environment limitations still requiring release CI:

- Berkeley DB is unavailable in this environment, so BDB-specific recovery and
  wallet-chain reprocessing need a BDB-enabled Linux/CI job.
- Windows exclusive-file behavior is compile-reviewed but needs Windows CI.
- Multiprocess/IPC is disabled by this build configuration, so the small IPC
  auto-connect error adaptation still needs a `WITH_MULTIPROCESS` build lane.
- The aggregate Cocoa WalletTests target waits indefinitely in native modal
  dialog handling on this host; its non-modal App/Options/URI/RPC suites and
  focused wallet unit tests pass.
- USDT tracing is disabled in the local build.
- The broader ZMQ functional test reached its later pre-existing MiniWallet
  `scriptpubkey` incompatibility after the new bind regression and normal
  TCP/IPC notification cases had passed.
- Several broad upstream functional suites have pre-existing BTX P2MR fixture
  incompatibilities after the new regression being exercised; these are
  recorded separately and are not evidence that the new paths failed.
- The complete long MiniMiner functional stress case was stopped after 63 of
  501 normal PQ transactions because P2MR signing makes it impractically slow;
  its unit coverage and error propagation paths pass, and its fuzz target
  compiles.

## Release recommendation

Review the generic catch-up and PR #289 independently, run Linux/macOS/Windows,
BDB, ZMQ, fuzz, and reproducible-build CI, then integrate onto the final BTX
0.33.2 base. Cut and publish `v0.33.2` only after those checks and BTX's existing
consensus/activation gates pass.
