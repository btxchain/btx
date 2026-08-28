# STOP: 0.34.1 partitions nodes. 0.34.2 deadlocks. 0.34.3 stalls with
# headers below blocks. 0.34.4 closed that header gap. 0.34.5 is the
# sealed binary that actually bootstraps.
#
# Do not load assumeutxo-199300 or assumeutxo-199299. Those compiled
# bases (ff80e629 / f12a27d0) sit on the withdrawn 0.34.1 branch, not
# the majority chain (issue 127). A node that already loaded one will
# not start on 0.34.5; wipe the datadir and sync from genesis (or load
# assumeutxo-191266 on a fresh datadir). There is no invalidateblock
# rescue.

**Do not `invalidateblock` 33c834f8.** The live chain **descends from**
`33c834f8056aca85a8591a304fe52affebe2770d6027e79845765547f8dfae82` at
height 199295. Walked 2026-08-28 from headers-only 199384
(`2e6394bc0ad6a055…`): ancestor at 199295 **is** 33c834f8; ancestor at
199294 is the still-common `0ca79e602f1b44d4…`. Invalidating that hash
strands the node permanently on the `8b5da5a5` island (confirmations −1
on every 33c834f8 descendant; no error; looks like a sync bug). If you
already ran it:

```
btx-cli reconsiderblock 33c834f8056aca85a8591a304fe52affebe2770d6027e79845765547f8dfae82
```

`33c834f8` is **not** a recommended invalidate target. The old Case A
"invalidate the first post-fork block" is wrong whenever that block is
an ancestor of the current chain. See Case A.

**v0.34.4** closed the headers-below-blocks stall (live: `blocks=199310`,
`headers=199024` → both 199310). That is independent of Case A. If
33c834f8 is locally invalid, run `reconsiderblock` regardless of binary
version. An earlier reconsider on 0.34.4 did not always climb the tip
(GETDATA of the competing fork was still skipped); the recovery command
is still `reconsiderblock`, not another invalidate.

**v0.34.1 is an accidental consensus hard fork.** Commit `1c87fcd6`
(PR 119) set `consensus.nMatMulStallRecoveryHeight = 199299` in
`CMainParams` after that height had already been mined. The comment
above that line said any reachable height is a hard fork. 0.34.1
recomputes a different ASERT target for every majority header after
199299, `CalculateClaimedHeadersWork` returns `nullopt`, and
`net_processing.cpp` disconnects the peer. Measured at the original
split: majority 199299 `a71e0c1c` claims `1e27264f` (plain ASERT);
0.34.1 carries `1e2b22b5` (re-anchored). About 21 of 94 reachable peers
ran 0.34.1 and were stranded; 73 never left the real chain. The
**longer advertised chain now uses those re-anchored bits** (walked
199299 `f12a27d0` claims `1e2b22b5`).

**v0.34.2 withdraws that re-anchor** but shipped without the
ExactReplay admission fix, so every `-matmulvalidation=consensus` node
froze exactly one block past the last attested height. **v0.34.3
unsticks that deadlock** but left `m_best_header` on the last
fully-authenticated ancestor, so getheaders never asked for tip+1.
**v0.34.4 is the headers-below-blocks fix.** This follow-up is the
heavier competing-fork GETDATA / probe fix.

This split was made visible by per-peer byte tables and chaintips from
**MendeMatthias**, **jarekpiot**, **Jpp-matata**, and **dixonping**.
The 0.34.2 deadlock was read off tag `v0.34.2` by **jarekpiot** and
independently confirmed on macpro2; **dixonping** asked for the
regression test that 0.34.2 lacked. **jarekpiot** then carried the
tip-child / RC-slot deadlock through to a proposed fix (PR 126).

When miners or operators find a problem on this line, the expectation
is a **full fix and a proposed solution**, not a report alone. This
line is meant to be maintained by whoever runs it. Several of you have
already been doing exactly that.

---

BTX 0.34 is the decentralization release: consensus miners ExactReplay,
public DNS hosts are not chain-tip oracles, and a node with no pin
membership, no attestor key, and no trusted-mirror pin must be able to
reach tip and keep advancing on ExactReplay alone.

`CLIENT_VERSION` in this tree is **0.34.5** once the freeze lands.
The `v0.34` tag and 0.34.0 seal remain the pool-close cut. 0.34.1 is
withdrawn: it partitions nodes from mainnet. 0.34.2 is withdrawn for
consensus nodes: it deadlocks one block past the last attestation.
0.34.3 is withdrawn for the headers-below-blocks stall. 0.34.4 closed
that header gap but compiled-in seeds were disconnected for missing
`NODE_NETWORK`, and a CPU tarball / source build **exited** instead of
starting. 0.34.5 is the sealed follow-up: keep discovery relays, answer
GETADDR, start without a diagnostic flag, fetch a heavier fork without
following it past park depth 6.

Please report bugs using the issue tracker at GitHub, and when you
have a diagnosis, bring the patch:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

Install 0.34.4 (or a later binary). Three different `invalidateblock`
situations exist. Same RPC, three outcomes. One of them used to abort
the node. Do not mix them. **Case A changed:** do not `invalidateblock`
33c834f8. If you already did, `reconsiderblock` it.

## Case A — 199295 split: do **not** invalidate an ancestor of the live chain

`invalidateblock` of "the first post-fork block" is **wrong** when that
block is an ancestor of the chain hashpower is extending. Height 199295
`33c834f8056aca85a8591a304fe52affebe2770d6027e79845765547f8dfae82` **is**
such an ancestor. Walked 2026-08-28 from a live headers-only tip at
199384: that tip's ancestor at 199295 is 33c834f8, and its ancestor at
199294 is the still-common
`0ca79e602f1b44d4c9f3acec7659cb9735a5fad6a888fd2e4c70ababf1e5cec9`.

**`33c834f8` is not a recommended `invalidateblock` target.** Invalidating
it forks you off the live chain onto the `8b5da5a5…` sibling at the same
height. The node then correctly refuses every 33c834f8 descendant. That
refusal is permanent until you undo it. It is not a download-pipeline
bug.

**If you already ran `invalidateblock 33c834f8…`, recover with:**

```
btx-cli reconsiderblock 33c834f8056aca85a8591a304fe52affebe2770d6027e79845765547f8dfae82
```

**Look at `getblockhash 199295` before touching anything else.**

- If it is **33c834f8**, you are already on the live line. Do nothing
  with `invalidateblock`.
- If it is **8b5da5a5…** (`8b5da5a571ab2b0afb2942c9e28ee44bb0ab825a2a1aeb7d3d241c75cfded962`)
  or 33c834f8 shows `confirmations: -1`, you already invalidated the
  live ancestor: run `reconsiderblock` as above. Do **not** invalidate
  33c834f8 again.
- If `getblockhash 199295` errors, this node is below the split. No
  invalidate is required.

Do not invalidate from a still-running 0.34.1 binary: that binary still
rejects plain-ASERT 199299. Upgrade first.

```
btx-cli getblockhash 199295
btx-cli getchaintips
```

If you never ran 0.34.1 and never invalidated 33c834f8, skip Case A.

## Case B — fork-rejoin, AssumeUTXO snapshot: do **not** `invalidateblock`

If this node loaded the compiled AssumeUTXO snapshot at height 199300
(`ff80e629…`) or 199299 (`f12a27d0…`), you are on the withdrawn 0.34.1
branch. 0.34.3 refuses `invalidateblock` of that snapshot base (no undo
data). **0.34.5 removes those compiled entries** and will refuse to start
if `chainstate_snapshot/` still names those hashes.

**There is no in-place rescue.** Wipe the datadir and sync from genesis,
or load [assumeutxo-191266](https://github.com/btxchain/btx/releases/tag/assumeutxo-191266)
on a **fresh** chainstate. Do not keep `chainstate_snapshot/` from the
bad pin. Do not `invalidateblock`.

Old 0.34.3 workaround (stop, remove `chainstate_snapshot/`, start twice)
only helps if the background chainstate never connected the withdrawn
fork. Treat it as unreliable; a full resync is the supported recovery.

## Case C — unauthenticated suffix (0.34.2 deadlock): `invalidateblock` is harmful

If you ran 0.34.2 (or 0.34.3 before the admission fix) in
`-matmulvalidation=consensus` and froze **exactly one block past the
last attested height**, do **not** `invalidateblock` that unauthenticated
suffix. **jarekpiot** measured that this reorgs onto shorter competing
forks, the original chain will not reconnect, and the suffix then hits
a second pending-cap at occupancy 8/8. A **clean restart** recovers to
the stuck-but-stable tip; the 0.34.3 binary then ExactReplays the
linear child and walks forward. Same command as Case A, opposite
outcome.

## After replacing the binary

Shut down cleanly, wait for exit, install a binary that includes this
competing-fork follow-up (0.34.4 closed the header gap; it did not
request the heavier 33c834f8 fork). Keep Metal `.metallib` files next
to `btxd`. Back up wallets and configuration before upgrading.

**Building 0.34.5 from source is how a fork is supposed to work.**
Compile, self-qualify ExactGemmS8S8 on *your* GPU (CPU-versus-device
must be byte-identical), and participate. Consensus judges your
blocks. **Build provenance is advisory:** a source-tree fingerprint
mismatch warns and continues; it does not exit and it does not skip
verification. A Metal-only (or HIP-only) golden cohort is valid; CUDA
hardware is not required to ship a manifest.
`-allowunverifiablematmulconsensus` is a deprecated no-op. Remove it.

Tarball SHA256s are filled in when the three assets are staged (Linux
CPU, Linux CUDA, macOS arm64 Metal). Every shipped `btxd` is linked
with ZMQ. **Verify `libexec/btxd.real`, not `bin/btxd`.** Since 0.34.1
`bin/btxd` is a `#!/bin/sh` wrapper: `ldd bin/btxd` and
`otool -L bin/btxd` return nothing and look like a clean pass while
meaning nothing at all. The real binary is `libexec/btxd.real` on both
Linux and macOS. `python3 scripts/release/verify_release_btxd.py`
follows the wrapper; `ldd libexec/btxd.real` must show `libzmq` on
Linux. See [#111](https://github.com/btxchain/btx/issues/111) and
[#122](https://github.com/btxchain/btx/issues/122) below.

# Compatibility

Same platform and epoch matrix as 0.33.4.2: Linux, macOS 13+, Windows
10+. Mainnet remains on MatMul v3 below height 185000; Epoch-A Profile 1
ExactReplay applies at and above height 185000. Compact `F`, `powLimit`,
the 191714 `nBits` dump floor, and the compiled AssumeUTXO pin at 191266
are unchanged. **EncDr stall recovery at 199299 is withdrawn** — that
flag day shipped in 0.34.1 after the height was already mined and
partitioned the network. `nMatMulStallRecoveryHeight` is `INT_MAX`;
`num/den` stay `1/1`.

# Notable Changes

## 0.34.5: sealed bootstrap (this release)

This is the sealed binary. 0.34.4 tarballs did not let a third party
join: compiled seeds advertised `NODE_MATMUL_DISCOVERY` without
`NODE_NETWORK`, consensus nodes disconnected them, and GETADDR on the
relays was ~157 received / 30 answered. A CPU tarball and any source
build then **exited** at startup, which looked like the same failure.

**Kept (genuine):**

- Initial-sync peer selection (**MendeMatthias**, sealed v0.34.4, network
  healthy at 200131): a fresh node sat at `headers=0 blocks=0` for 45
  minutes with 7 low-work disconnects because the scarce `nSyncStarted`
  slot went to peers parked at 128530 / 185109 / 189611 (23–29 MB of
  headers) while the peer advertising the actual tip received 90 bytes
  of `getheaders` and one request. Presync ended below the height-186000
  `nMinimumChainWork` checkpoint. IBD now prefers peers whose VERSION
  height is at or above that checkpoint, and de-prioritizes any address
  that already failed a low-work headers sync.
- `RecalculateBestHeader` for independent validators (**MendeMatthias**).
  Both production call sites (startup after `LoadBlockIndex`, and
  `ActivateSnapshot`) were gated on `matmul_trusted::IsConfigured()`,
  which is false for the recommended `-matmulvalidation=consensus` with
  no `-matmultrustedpubkey`. The only path that can lower `m_best_header`
  therefore never ran on the configuration we tell people to use. It is
  always invoked when there is an active tip.
- `must_probe` hoist (`8b0b0425`) plus BestKnown must **extend the tip**
  (`0fdd8739`).
- Best-header **floor**, not pin (`EnsureBestHeaderNotBehindConnectedTip`).
  Never sit below the connected tip (0.34.3 headers-below-blocks). **Must**
  sit on a heavier valid disconnected fork above it. 0.34.4 collapsed
  those: **jarekpiot** reproduced on sealed v0.34.4 with no
  `invalidateblock` — GPU authority on `8b5da5a5@199326`, ingested
  `33c834f8` tower `0d5ffded@199398` (work `030b4fd9e7bfad` vs
  `030b4fd97ff51b`), `getchaintips` showed the branchtip,
  `headers==blocks`, `best_header_ahead=0`,
  `competing_not_active_tip_chain`. The IsConfigured overlay was undoing
  every competing promotion. `getblockfrompeer` cannot override a pin.
- Snapshot `loadtxoutset` closed loop (**MendeMatthias**, line-level on
  v0.34.4, no fork, no invalid blocks): `ShouldFetchBackgroundSnapshotBlocks`
  required `active >= best_header-1` (199300 vs 199303 never assigned
  background capacity), so `MaybeCompleteSnapshotValidation` stayed SKIPPED,
  `IsSnapshotValidated` stayed false, and `snapshot_base_missing` skipped
  GETDATA. Height gap, not invalidity. Background fetch no longer waits on
  that one-block proximity; a peer whose BestKnown extends the active tip
  is not skipped. Fast-start docs recommend `loadtxoutset`.
- Park split (`ed52178e`): GETDATA of a heavier fork is not follow.
  Depth-6 park stays wired. Stale-heavier is **not** `recovery_escape`.
- Discovery-relay retention and GETADDR (`ab15f616`):
  `HandshakeKeepsDiscoveryPeer` keeps `NODE_MATMUL_DISCOVERY` on full
  outbound, not only ADDR_FETCH; relays `Good` recent inbound NETWORK
  peers, answer GETADDR immediately, extra-push connected useful peers.
- Doc correction: do **not** `invalidateblock` 33c834f8. Recover with
  `reconsiderblock` if you already did.
- Consensus/CPU/source-build **starts** without
  `-allowunverifiablematmulconsensus` (deprecated no-op).
- **Build provenance is advisory.** `build_provenance_mismatch` warns
  and continues. Runtime ExactGemmS8S8 CPU-versus-GPU self-qual stays
  fail-closed; that is the real protection. The fingerprint is an
  authorship claim, not a correctness property. A clone that self-
  qualifies on its own hardware validates; consensus judges the blocks.
  Case provenance *would* have caught that self-qual at toy/medium
  shape can miss a production-shape digest bug: the production canary
  episode still runs when a golden row exists and still fail-closes on
  `digest_mismatch`. It no longer fail-closes on fingerprint alone.
- **CUDA is not required to ship a manifest.**
  `RCProductionGoldenManifestCohortValid` accepts a Metal-only or
  HIP-only cohort. Rows in one cohort still share `source_revision`,
  fingerprint, and digest. Requiring Nvidia silicon to publish goldens
  was a vendor dependency; MendeMatthias could not self-seal an
  Apple-only fork without either buying CUDA hardware or rebinding a
  CUDA row he had not measured.

**Dropped (invalidateblock workarounds, never shipped):**

- Uncommitted island-skip / reserved RC lane / retained-body GETDATA
  fallthrough. Those existed to drag bodies of a chain we had marked
  invalid. After `reconsiderblock`, park either refuses (correct) or
  the hole is ordinary IBD. Not in this tree.

Measured after deploying `ab15f616` to both seeds (still local
binaries — this release replaces them with tarballs): inbound GETADDR
answered 160/160 and 132/132. A fresh datadir with `dnsseed=0
fixedseeds=1` kept both compiled seeds, processed 943+941 addresses
from them, and committed headers off genesis.

## 0.34.4 follow-up: heavier competing fork (33c834f8 / 199523)

0.34.4 snapped `m_best_header` up to the connected tip. Measured:
macpro2 `blocks=199310 headers=199024` → `199310/199310`. Peers then
advertised 199523. The node still sent zero getheaders;
`reconsiderblock 33c834f8` left the tip at 199310 after two minutes.

Two independent defects, one loop:

1. `HeaderSyncMustProbe` treated a BestKnown **height** above the tip as
   "already ahead" even when that BestKnown did not extend the active
   tip (199382 on 33c834f8 vs 199310 on 8b5da5a5).
2. `FindNextBlocksToDownload` skipped `competing_not_active_tip_chain`
   for any competing fork deeper than the EncDr short-reorg window
   (1–6). The live fork's LCA is 199294 (depth 16).
   `HeadersDirectFetchBlocks` was already closed because
   `CanDirectFetch` requires a tip younger than 20×spacing; the 199310
   tip was ~91 hours old. Unauthenticated header lead is 72, so the
   headers-only tip sat at 199382 = 199310+72 and never moved.

Fix: probe when BestKnown does not extend the tip; GETDATA a competing
fork whose claimed `nChainWork` is **strictly** above the active tip
(equal-work EncDr twins stay skipped). Tests:
`header_sync_tests/must_probe_table`,
`peerman_tests/heavier_competing_fork_probes_and_getdata_past_short_reorg`.

Default EMERGENCY park depth 6 still refuses an automatic 16-block
reorg onto that fork. If 33c834f8 is marked invalid locally, the
operator path is Case A `reconsiderblock`, not another invalidate.

**jarekpiot** (PR 126, tip-child / RC-slot deadlock), **dixonping**,
**MendeMatthias**, and **Jpp-matata** diagnosed the earlier 0.34.x
stalls; this follow-up is the remaining catch-up hole they pointed at
from chaintips and per-peer bytes.

## 0.34.5: provenance is advisory; a single-family cohort is valid

0.34.4 treated `build_provenance_mismatch` as a hard canary failure:
the episode never ran, GEMM was cleared, and consensus startup
`InitError`'d unless `-allowunverifiablematmulconsensus=1`. A source
build and a CPU tarball looked like a dead node. That is not
decentralized.

0.34.5:

- **Starts.** No diagnostic flag. CPU without a GPU warns
  `MatMul RC DEGRADED START`, withholds `NODE_MATMUL_CONSENSUS`, and
  stalls at the RC body boundary (it cannot ExactReplay Profile-1).
- **Provenance warns.** Fingerprint miss logs `build provenance is
  advisory` and continues. Self-qual and (when a golden row exists)
  the production-shape digest check still fail closed.
- **One family is enough.** Metal-only and HIP-only manifests are
  valid. CUDA is not a gate.

Remove `allowunverifiablematmulconsensus` from every `btx.conf`. If a
legitimately built node still needs that flag, that is a bug in this
change.

## 0.34.3: consensus ExactReplay deadlock (tag v0.34.2)

Every `-matmulvalidation=consensus` node on v0.34.2 froze exactly one
block past the last attested height. The stall survived a clean restart.
GPU sat at 0%. Logs looped `Re-admitting budget-deferred body` then
`MatMul pending verification cap reached` about once a second.

Cause, read off the tag by **jarekpiot** and confirmed on macpro2:
`IsBlockAuthenticated` only via `BLOCK_EXACT_REPLAY_VERIFIED` or
`BLOCK_TRUSTED_REPLAY_ATTESTED`; with signers retired, ExactReplay is
the only authenticator left. `direct_authenticated_tip_child` required
`active_tip->nAuthenticatedChainWork == active_tip->nChainWork`, which
is false forever once the tip is past the last attested block. The
default pending cap is 1 job and the competing lane reserved 1
*work-unit* from a cap denominated in work-units, so
`CanStartCompetingMatMulRCVerification` never returned true. The sole
linear tip-child was classed competing, never ExactReplayed, never
earned `VERIFIED`, and the child stayed competing forever.

0.34.3:

- A linear child of the active ExactReplay-connected tip qualifies as
  `direct_authenticated_tip_child` even when authenticated work lags
  (`TRUSTED` mode unchanged). This is the fix **jarekpiot** independently
  proposed.
- Competing ExactReplay reserves one *job*, not one work-unit, and
  shares the single-job cap when idle.
- Authority-mode nodes parse inbound `BLOCK` / `CMPCTBLOCK` /
  `BLOCKTXN` / `INV` again. `TX` / `MEMPOOL` / `FEEFILTER` stay dropped.
- Budget-deferred bodies retry on the refill schedule, not at 1–2 Hz;
  repeated deferral is terminal-with-requeue.
- `peerman_tests/linear_tip_child_replays_when_authenticated_work_lags`
  is the shape **dixonping** asked for: one linear child, no sibling,
  authenticated work strictly less than chain work. It fails against
  tag v0.34.2 and passes here.

## 0.34.3: assumeutxo `invalidateblock` no longer aborts the node

A miner who rejoined the majority chain reported that
`invalidateblock` of the first post-fork block (199299) on a node
that had loaded the AssumeUTXO snapshot at 199300 crashed the
process: `DisconnectBlock: ReadBlockUndo nFile=-1`, then `Failed to
disconnect block`, then abort. The snapshot base has a body but no
undo because it was never connected. `reconsiderblock` of the
majority chain hit the same wall.

0.34.3 refuses that reorg with a clear RPC error and leaves the node
running. Regression:
`validation_chainstatemanager_tests/snapshot_chainstate_refuses_invalidate_below_base`.
The working recovery is Case B above: remove `chainstate_snapshot/`,
let the background chainstate take over, shielded rebuild if
prompted, then a clean start.

## 0.34.3: CUDA provenance

**MendeMatthias** independently verified the source seals. They are
intact: `build_relevant_tree` over `CMakeLists.txt cmake src
contrib/matmul-v4` excluding the manifest `.data` matches v0.34
`68bc97a7…`, v0.34.1 `5773990f…`, v0.34.2 `187e19ba…`. The manifest
correctly describes the tag. A `build_provenance_mismatch` from the
shipped 0.34.2 linux-x86_64-cuda tarball means **that binary was not
compiled from the tag** (dirty worktree, wrong commit, or stale object
dir). The remedy is a rebuild from a clean checkout of the tag in a
fresh build directory, not a manifest edit. 0.34.3 CUDA is linked
after the seal so `canary=passed`.

## 0.34.3: verify `libexec/btxd.real`, never the wrapper

Since 0.34.1, packaged `bin/btxd` is a `#!/bin/sh` wrapper.
`otool -L bin/btxd` and `ldd bin/btxd` return nothing and read as a
clean pass while meaning nothing at all. **MendeMatthias** showed this;
we made the same mistake. The real binary is `libexec/btxd.real` on
Linux and macOS. `scripts/release/verify_release_btxd.py` follows the
wrapper and fails if `.real` is missing.

## Notice to trusted-mirror operators: repoint or move to consensus

If you run `-matmulvalidation=trusted`, read this before upgrading to
v0.34.1.

**The pin is your choice, not ours.** There is no compiled-in signer key
anywhere in this tree — `grep` `chainparams.cpp` and you will not find one.
Your `-matmultrustedpubkey` entries and your `-matmultrustedthreshold` are
config lines you own. They point at whichever GPU nodes *you* decided to
trust. If that is currently the original operator's keys, it is because those
were the keys that existed, not because the software prefers them.

**We are stepping back.** After v0.34.1 the original operator no longer
commits to running attestation signers. Nodes in `trusted` mode follow a pin;
if the keys you have listed stop signing, your node stops advancing. That is
not a defect, it is what delegated validation means.

**Your options, in order of preference:**

1. **Move to `-matmulvalidation=consensus`.** This is the real fix. A consensus
   node needs no pin, no signers, and no threshold — it accepts a block because
   *this node* ExactReplay'd it. It requires a GPU that passes the byte-exact
   TensorOps self-test. No permission from anyone is involved.
2. **Repoint the pin at signers you actually trust.** Any GPU node running a
   local signing key can attest. Configure two independent ones and keep
   `-matmultrustedthreshold=2`. Mainnet refuses a 1-of-1 quorum for good
   reason: a single stolen key would be sole proof-of-work authority for your
   node.
3. **Revoke specific keys without changing your pin** using
   `-matmulattestationblocklist=<hex>`. Attestations from a blocked key are
   never counted, even if the key is still listed. It is fail-closed: a block
   that would leave you below your own threshold is refused.

**What a trusted mirror is not.** The startup banner says it plainly — a
trusted mirror performs ordinary block, body, and script validation but
delegates the Profile-1 ExactReplay verdict to a configured quorum. It is not
an independently validating full node. That is a reasonable trade for a
CPU-only machine. It should be a deliberate choice, not an inherited default.

Consensus miners and GPU full nodes are unaffected by any of this. They never
consult a pin.

## ExactReplay is the gold standard

`-matmulvalidation=consensus` (the default) accepts and produces
blocks because **this node** ExactReplay'd them. Pin quorum may skip
GPU work and steer FMWC/GBT **only** on trusted CPU archives
(`-matmulvalidation=trusted`). Heard `MMATTEST` never moves BestKnown,
the signed frontier, or GETDATA on a consensus miner.

Public DNS / `addnode` hosts become ADDR-only discovery relays
(`-matmulvalidation=relay`): not MatMul authority, not a chain-tip
oracle, not GETMMATTEST. Independent consensus miners no longer treat
archive GETMMATTEST or a competing pin quorum as a validity or
GPU-admission oracle. Unique unattested tip-children ExactReplay.

The unprivileged-node rule replaces the old operator-fleet gate: a
node holding no pin membership, no attestor key, and no trusted-mirror
pin must reach tip from a cold start on ExactReplay, keep advancing
across a signed-frontier stall without operator action, and recover
without a restart, with every privileged peer absent or hostile.

## Archives validate independently; relays are the pointers

Public DNS / `addnode` hosts (`node.btx.dev`, `node.btxchain.org`,
`node.btx.tools`) run `-matmulvalidation=relay`: ADDR-only discovery,
not MatMul authority, not a chain-tip oracle. `init.cpp` hard-`InitError`s
if a relay is given a pin, signing key, GETMMATTEST serve, attestation
blocklist, or open attestors.

CPU archives with a full chain run `-matmulvalidation=consensus`. They
ExactReplay independently. They need no pin, no signers, and no
threshold. That is the decentralized outcome: archives are independent
validators, not pin followers.

`MatMulModeIsChainAuthority()` returns true **only** for `CONSENSUS`
and `TRUSTED`. `RELAY` is excluded
(`src/kernel/chainstatemanager_opts.h`). That predicate is the
`chain_oracle` field on `getblockchaininfo` and `getpeerinfo`, so an
operator can verify a discovery relay reports `chain_oracle: false`.

## Validators are optional, not required

A consensus node with **no** `-matmultrustedpubkey` gets an INFO log,
not a warning or error: it cannot see or follow the attested tip, and
`ExactReplay is unchanged`. It validates fully and independently with
zero validator config. That is corroborated three ways: the
gold-standard litmus passes; `SkipExactReplayForGpuAttestation` is
`trusted_mirror && has_valid_gpu_attestation`, so consensus never
skips; and production accepted blocks network-wide while the signer
had attested nothing past 199300.

## Trusted-mirror M=2 is a guard against single-key oracles

`MainnetTrustedMirrorRefusesSingleKey` fires **only** when
`-matmulvalidation=trusted` on mainnet
(`src/node/matmul_trusted_attestations.h`). A consensus node is never
refused. A relay node is never refused. On
`-matmulvalidation=consensus` the pin is telemetry and never skips
ExactReplay. This is the existing mainnet rule, not a 0.34 deadlock
on archives.

It exists because in trusted mode the quorum **replaces** the MatMul
proof-of-work check above the Profile-1 activation height, so a 1-of-1
quorum makes a single WIF that node's sole PoW authority: steal the
key and the node accepts MatMul-invalid blocks. The M=2 floor is a
guard **against** single-key oracles, not a requirement to run a
trusted mirror, and it does not deadlock an archive that validates
with ExactReplay.

Do not pass `-allowsinglekeytrustedmirror=1` to start a public
archive. If a host refuses because it is configured trusted with
threshold 1, switch it to `-matmulvalidation=consensus`. The override
is the single-stolen-key hijack surface this rule removes.

A CPU host with no qualified ExactReplay provider **starts**
`-matmulvalidation=consensus` in 0.34.5: it warns, withholds
`NODE_MATMUL_CONSENSUS`, and cannot cross the RC body boundary. That is
degraded discovery, not independent validation. Profile-1 still needs a
self-qualified accelerator to advertise consensus or to mine. Public DNS
seeds on CPU run `-matmulvalidation=relay`. A trusted archive still
needs an M-of-N pin, which is not this M=2 startup guard's job to
invent.

The one honest limit: `-matmulvalidation=trusted` nodes still depend
on the pin. The startup warning already says they are **not an
independent full consensus validator**. That is a hardware limit
(CPU-only machines that physically cannot ExactReplay), not a
governance one. After v0.34.1 that pin is yours to keep, repoint, or
leave: see [Notice to trusted-mirror operators](#notice-to-trusted-mirror-operators-repoint-or-move-to-consensus).

## Shielded pool closed at height 199300

At height **199300** (the live tip at this freeze) the shielded pool is
closed in both directions. That is a consensus flag-day
(`nShieldedPoolDisableHeight`), the same idiom as
`nShieldedSmileRiceCodecDisableHeight` /
`nShieldedMatRiCTDisableHeight`. Blocks **below** 199300 validate
exactly as they do today — rewriting history would fail IBD. At and
after 199300:

* shielded **egress** (unshield / spend) is rejected — the remaining
  pool balance (~9,688.79 BTX) is treated as burned, after public
  warning;
* shielded **ingress** (new shielded output) is also rejected, so
  nobody can deposit into a pool they can never leave.

This release closes the pool immediately rather than at a future
height. Ingress has already been consensus-disabled for tens of
thousands of blocks (`nShieldedPoolCreditDisableHeight` follows
`BTX_SHIELDED_SUNSET_HEIGHT`; `nShieldedDirectSendPublicFlowDisableHeight`
is 128000). Egress over the 960-block window 198341–199301 was
**zero** (`getshieldedstateinfo.velocity_window_egress`). The pool is
inert; 0.34 makes that consensus and drops the dormant-pool attack
surface.

Once egress is disabled, shielded state is no longer needed for
**consensus going forward**. The nullifier set exists to stop
double-spends of shielded notes: if no note can ever be spent, no
nullifier can ever be presented. The commitment tree exists to prove
membership for a spend: no spends, no membership proofs. A dormant
pool is pure attack surface, and shielded counterfeiting is invisible
until exit.

Nodes therefore **stop opening** the three shielded LevelDB stores
(`nullifiers`, `commitments`, `account_registry`) by default once the
active tip is at or past 199300. That is the startup saving: no
rebuild, no wasted disk. Explorers and indexers that still want the
historical view pass `-shieldedstate=1`. The code paths are not
deleted; they still validate history below the flag-day.

A local attestor WIF used to be turned into a pubkey in
`AppInitParameterInteraction`, which runs before `ECC_Start`. That
null-dereferenced `secp256k1_context_sign` (~1.2s kernel SEGV, not
shielded warmup / RPC `-28`). The WIF is now staged and derived in
`FinalizeConfiguration` after ECC exists.

## Fork self-sufficiency (goldens are a local mining belt)

The production golden manifest is how **this binary** refuses to mine
on a backend it has not measured. It is not a hardware-approval
registry and it is not consensus. Forks that want a new mining backend
add a row to **their** manifest, rebuild, and reseal. Other nodes
ExactReplay the resulting blocks. Do not send golden JSON to this
repository for blessing. See
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md).

## Header availability, BestKnown `-1`, and IBD (three fixes, one symptom)

A reporter showed archive `getpeerinfo` rows with `sync_height=-1`,
`common_height=-1`, `sync_lag=-1`, and
`counts_as_synced_outbound=false`, and concluded the node was in IBD
and therefore not broadcasting. The effect is right; the cause is one
step off, and it matters because **three different 0.34 fixes** are
involved.

`nSyncHeight` / `nCommonHeight` are filled from
`pindexBestKnownBlock` / `pindexLastCommonBlock`
(`net_processing.cpp` around the getpeerinfo stats). **`-1` means
BestKnown is null** — `UpdateBlockAvailability` never ran for that
peer because we never accepted a header from it. IBD and those `-1`s
are **parallel symptoms** of headers never being learned, not cause
and effect. `counts_as_synced_outbound=false` follows from the same
null BestKnown.

This class was already measured: `net_processing.cpp` documents
**2026-08-11, 26 of 66 peers at `synced_headers=-1`, 11 advertising
heights above our tip**, and already has a rate-limited `getheaders`
probe when BestKnown is null. 0.34 closes the holes that left that
probe as the only recovery path.

1. **`ShouldIgnoreNonAuthorityInboundHeaders` (`1de42d67`).** A trusted
   mirror was dropping non-authority `HEADERS`, so BestKnown never got
   set. Header acquisition during weak-subjectivity bootstrap is not a
   body-trust decision; `BLOCK` / `CMPCTBLOCK` stay authority-only.
2. **Raise-only BestKnown seeding (`1de42d67`).**
   `MaybeSeedGpuSignedFrontierBestKnown` used to overwrite a peer's
   real BestKnown with the lower local signed frontier, pinning
   `peer_best_ahead == best_header_ahead` with `in_flight=0`. Seeding
   may only fill a null or raise.
3. **`DEFAULT_MAX_TIP_AGE` 24h → `30 * 24h` (IBD-LIVE-01).** A node
   whose validated tip is canonical but older than a day used to
   re-enter IBD after every restart. Production confirmed it the same
   day: a GPU signer reported `initialblockdownload=true` on a
   55-hour-old tip at height 199300 while peers were ahead. False IBD
   is not an RPC cosmetic: it suppresses tx announcement, Dandelion,
   and self-advertisement; it also disarms the cadence hold, exempts
   the unauthenticated-header-lead cap, and trips the mining chain
   guard (`after initial_block_download`). Operators who want a
   stricter window still set `-maxtipage`. `btxd -help-debug` reports
   `default: 2592000`. The functional test does **not** mine 30 days in
   the past and does **not** wait on P2P `sync_all` for mocktime-offset
   blocks (that timestamp gap does not converge: node1 receives
   headers and never advances). The compiled default is the help-debug
   string. Stay/leave IBD is exercised with explicit 1- and 2-hour
   `-maxtipage` values by `submitblock` onto the IBD node.

**Raising `maxtipage` alone does not populate `sync_height` /
`common_height`.** That is the header-availability fix (1–2). The
IBD-LIVE-01 audit says the same: increasing `maxtipage` must not be
treated as a substitute for validated header exchange and block-body
request handling. If you deploy expecting the 30-day default to clear
`-1` rows and headers are still dropped for some other reason, the
release did not fail — you are looking at the wrong fix.

Tip age is node policy, not consensus. It becomes a weaker standalone
freshness signal. That is the intended tradeoff under a high-cost
MatMul stall, mitigated by minimum chainwork, validated headers,
authenticated MatMul chainwork, and peer diversity.

## ZMQ on by default (issues 111 and 122)

jarekpiot reported this twice. [#111](https://github.com/btxchain/btx/issues/111)
was the v0.33.3 Linux tarball: `zmqpub*` accepted and ignored,
`getzmqnotifications` absent, no startup failure, a block-explorer
indexer stalled while `btxd` looked healthy. That issue was **closed by
recutting one tarball** with `-DWITH_ZMQ=ON`. CMake's default stayed
OFF. There was no package-time `ldd`/`otool` gate. So the same class of
miss shipped again as [#122](https://github.com/btxchain/btx/issues/122)
in the v0.33.4.2 Linux CPU tarball (`btx-0.33.4.2-linux-x86_64-cpu.tar.gz`,
SHA256 `aecd0725…`, matching our `SHA256SUMS`). CUDA and Metal 0.33.4.2
trees had passed `-DWITH_ZMQ=ON`; the CPU tree had not.

0.34's durable fix, not another one-off recut:

- `option(WITH_ZMQ … ON)` so a forgotten `-DWITH_ZMQ=ON` is no longer
  silent compile-out (`e5cd937a`).
- `find_package(ZeroMQ … REQUIRED)` when the option is on.
- `scripts/release/verify_release_btxd.py` refuses a `btxd` whose help
  text advertises ZMQ without a real libzmq link, and on macOS refuses
  any `/opt/homebrew` load command. Since 0.34.1 it also refuses to
  treat the packaged `bin/btxd` shell wrapper as the binary: it
  verifies `libexec/btxd.real`. Since 0.34.5 the same script is a
  fail-non-zero step of Guix `build.sh`, native `package_release_archive.py`,
  `collect_release_assets.py`, `cut_release.py`, `cut_local_release.py`,
  and `publish_github_release.py`. An unrecognized file is FAIL, not a
  skip. `--archive` unpacks the tarball users download and gates the
  real binary. `test/util/verify_release_btxd_test.py` proves the gate
  exits non-zero on a `btxd` built without ZMQ (the 0.33.4.2 CPU shape).
- [release-process.md](release-process.md) makes that `ldd`/`otool`
  check mandatory before a tarball is staged.

Issue 122 stays open until a published 0.34 artifact demonstrates
`getzmqnotifications` and a live `zmqpubhashblock` notification. Do not
treat this notes file as that demonstration.

## SLH-DSA keygen vs libsodium Ed25519

`ecf3ca9f` fixed a **macOS-only silent PQ-to-classical keygen downgrade**
introduced by statically linking `libsodium.a` for ZMQ portability.
SPHINCS+ used the SUPERCOP name `crypto_sign_seed_keypair`; sodium
exports the same name as a 4-byte tail-call into Ed25519. Wallet
`CPQKey::MakeNewKey` → `bitcoin_pqc_keygen` →
`slh_dsa_shake_128s_keygen` called that name and expected a
post-quantum keypair. Linux resolved SPHINCS from `libbitcoinpqc.a`;
macOS kept sodium first. 0.34 prefixes the SPHINCS / `slh_dsa` TUs
(`btx_spx_*`). Dilithium was already `pqcrystals_*`. Reordering the
link to put PQC first would steal ZMQ Curve; do not do that.

**Consensus was never affected.** Mainnet
`GetBlockScriptFlags` sets `SCRIPT_VERIFY_REJECT_LEGACY_SIGS` whenever
`fEnforceP2MROnlyOutputs` is true (it is, from genesis).
`EvalChecksig` then returns `SCRIPT_ERR_BAD_OPCODE` for
BASE / WITNESS_V0 / TAPSCRIPT. PQ signing is
`OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA` under `SigVersion::P2MR`.
libsodium is not a consensus or signing primitive; it arrives
transitively via libzmq for CurveZMQ transport.

If you generated SLH-DSA keys on a macOS `btxd`/`btx-qt` built before
`ecf3ca9f` with static libsodium, treat those keys as **not**
post-quantum and generate new ones on a prefixed binary. Linux
keygen was already SPHINCS. Existing chain signatures were never
Ed25519.

## Trusted-mirror bootstrap deadlock (PR 124)

This is not an operator nicety. Without `1de42d67`, ordinary users on
**new Apple Silicon** get a node that never syncs.

**MendeMatthias** (easyNode / easyBTX) found and reproduced it on
2026-08-26 against v0.33.4.2, and then explained *why* it showed up
for their users at all: easyNode tries `-matmulvalidation=consensus`
on every start and only falls back to a trusted mirror when `btxd`
itself refuses. That refuse happens when Apple silicon self-qualifies
but matches no golden row — today, **M5**. M1 through M4 stay in
consensus mode and never hit the deadlock. The causal chain is:

M5 self-qualifies → no `m5_class` manifest row → `btxd` refuses
consensus → the app falls back to trusted mirror → a **fresh datadir**
hits the bootstrap deadlock and parks at height 0 forever.

Their words: the population this deadlock was hitting is **fresh
installs, not operators**. The M5 golden gap and the bootstrap
deadlock are the same incident, not two unrelated reports. An
`m5_class` row in a fork's own manifest would also remove the fallback
that triggers the deadlock; we will not add that row here (see
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md)).

A fresh `-matmulvalidation=trusted` datadir parked at height 0: archive
peers answered `getheaders` with zero bytes, `NODE_MATMUL_CONSENSUS`
peers offered the only headers and those were dropped as non-authority,
and `MaybeSeedGpuSignedFrontierBestKnown` then pinned BestKnown to the
local signed-frontier height (2000) while peers advertised 199300+.
The stall log was:

```text
Seeded GPU peer=7 best-known to signed frontier height=2000 (tip=0 HEADER_ONLY catch-up)
Block fetch stall detected: tip=0 best_header_ahead=2000 peer_best_ahead=2000 in_flight=0
```

`loadtxoutset` cannot rescue that: the snapshot base header must
already be in the index.

0.34 accepts inbound **HEADERS** from any peer while the active tip is
below `max(last checkpoint, highest AssumeUTXO pin)` (mainnet 199300),
and the frontier seed only *raises* BestKnown. Bodies stay
authority-only. You do not need an operator-controlled archive to
learn the header chain. See
[btx-matmul-trusted-rpc-mirrors.md](btx-matmul-trusted-rpc-mirrors.md)
§ Bootstrapping a new mirror.

## Metal mining is a row you add

Admission is the byte-exact TensorOps self-test
(`IsLtTensorOpsGemmAvailable` / `SelfTestTensorOpsOnce`), not a
device-name string. Mining then requires a golden row for **your**
reported class (`m4_class`, `m5_class`, …). This tree publishes the
classes **we** measured (CUDA `sm_120`). To mine on Metal, add a row
to your copy of
`src/matmul/matmul_v4_rc_production_golden_manifest.data`, rebuild,
and reseal — about four minutes with
[`contrib/matmul-v4/multi-gpu-golden-corpus.sh`](../contrib/matmul-v4/multi-gpu-golden-corpus.sh)
`--backends metal`. Step-by-step:
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md).

easyNode / easyBTX (and any other installer) ships its own `m5_class`
row in **its** freeze. Users get M5 Metal mining without waiting on
this repository. That is the design, not a pending caveat.

## 0.34 is the reference release

Further releases should be **built by the community from this code**,
not requested from us. We are not the gate for goldens, hardware
classes, or future versions. How to freeze, measure, seal, and ship:
[release-process.md](release-process.md) and
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md).

# Fast-start snapshot

**Withdrawn:** [assumeutxo-199300](https://github.com/btxchain/btx/releases/tag/assumeutxo-199300)
(`ff80e629…`) and [assumeutxo-199299](https://github.com/btxchain/btx/releases/tag/assumeutxo-199299)
(`f12a27d0…`) are on the withdrawn 0.34.1 branch. Do not load them.
0.34.5 no longer compiles those bases (`loadtxoutset` will reject them).
Issue [#127](https://github.com/btxchain/btx/issues/127).

Still compiled and on the majority chain (below the 199299 split):

- [assumeutxo-191266](https://github.com/btxchain/btx/releases/tag/assumeutxo-191266)
  (`snapshot.dat` SHA256 `6ca84f9ce0bde6d0e4c17503f544bf293743c67b37881833f9a0e1f3adee504e`)
- height **191266**, blockhash `de6e3c9db527970c13b2ba834c19ff8f4d8829aee0c93ba6cde3a5039504efa8`

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset snapshot.dat
```

Use `loadtxoutset`, not `loadtxoutsetattested`. Fresh chainstate only.
Or sync from genesis. A replacement pin near 199300 will not ship until
that height is checkpointed on the majority hash.

# Included public work

- btxchain/btx #123 — 0.34 ExactReplay gold standard, discovery relays,
  archive-authority split
- btxchain/btx #124 — trusted-mirror bootstrap deadlock (HEADERS during
  weak-subjectivity sync; seed-raises-only BestKnown). Credit:
  MendeMatthias
- prior `main` line: #105, #112, #113, #117, #119, #120, #121
  (0.33.3–0.33.4.2)

# Consensus

Mainnet EncDr stall recovery at height **199299** is **withdrawn**.
0.34.1 set `nMatMulStallRecoveryHeight = 199299` after that height was
already mined; that is a hard fork. 0.34.2 sets it to `INT_MAX` with
`num/den = 1/1`. Do not retune `F` or `powLimit` in this release. The
five recovery knobs stay bound into `replay_authority_context`
(schema 4). ExactReplay remains consensus; the canary is not.
