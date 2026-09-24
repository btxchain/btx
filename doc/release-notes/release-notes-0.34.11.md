# BTX 0.34.11rc1 — Per-tower GETDATA and honest-tip header probes

**Status:** **rc1**. `CLIENT_VERSION` is **0.34.11** with
`CLIENT_VERSION_RC=1` and `CLIENT_VERSION_IS_RELEASE=false`. P2P
subversion is `/BTX:0.34.11rc1/`. `btxd -version` prints `v0.34.11rc1`
plus a git suffix. Last shipping tag remains **v0.34.10**. Do not recut
`v0.34.10`, `v0.34.9`, or `v0.34.9-dev.pr198*`.

Not a consensus change relative to 0.34.10. `automatic_spend_atoms` stays
0.

## What this release is (and is not)

- **No consensus / ASERT / header-PoW / issuance change.**
- Fixes a local **GETDATA / getheaders** stall on the acquisition-escape
  path. An unavailable honest HEADER_ONLY tip-child must not be a global
  1-wide return that starves another registered heavier fork. Catch-up
  successor reclaim and cadence-hold window clamps are per-peer /
  per-tower, not height-global. Getheaders from a long competing
  HEADER_ONLY tower start **at the connected tip**, not `tip->pprev`.
- GPU ExactReplay is unchanged: unique-frontier CPU-pending /
  HEADER_ONLY still does not occupy the RC slot (`3130a8c2` in 0.34.10).

A node with **no** pin membership, **no** attestor key, and **no**
trusted-mirror pin must still reach tip from ExactReplay alone, keep
advancing across a signed-frontier stall without operator action, and
recover **without a restart**. Restart-only recovery is still a failure.

## The bug

0.34.10 GETDATA already 1-wides the unique HEADER_ONLY acquisition
frontier and asks every peer for an honest HEADER_ONLY tip-child. That
honest-suffix path **returned** after queueing the tip-child, so a peer
whose BestKnown is another registered heavier fork never requested its
own missing root. The control without that unavailable header passed.

Related global gates that produce the same stall:

1. **`CatchUpOneWideFetch`** applied unique-frontier 1-wide to every
   peer, not only peers whose BestKnown contains that frontier.
2. **`ReclaimCatchupSuccessorRequests(..., "catchup-root-only")`**
   cancelled inflight **across all peers** by height, so one 1-wide
   unique-frontier pass could drop another tower's root or an honest
   suffix request.
3. **Cadence hold** clamped the GETDATA window to `tip + burst` even
   for a registered competing tower whose missing root sits above that
   horizon.
4. **Getheaders `pprev` walk** after `HeaderSyncLocatorStart` snapped
   to the connected tip: a competing-only peer answers from the fork
   LCA and replays headers the node already has. Honest tip+1 is never
   requested. `HeaderSyncMustProbe` also skipped when VERSION equals
   tip, the tip is less than 24h old, and BestKnown is a competing
   tower above tip.

Physical limit that remains: GETDATA cannot invent a header that no
connected peer has. The honest-tip locator and competing-BestKnown
probe are how the node asks for it.

## What 0.34.11 does

| Gate | Behavior |
|---|---|
| Honest HEADER_ONLY tip-child | Still GETDATA from every peer. Return only for peers that are **not** a registered competing acquisition tower. Extra inflight slot so the tower root is requested too. |
| Unique-frontier 1-wide | Only peers whose BestKnown contains that HEADER_ONLY frontier. |
| Other registered tower | Clamp / GETDATA that tower's missing root (`last_common+1`), not unique-frontier descendants. |
| Successor reclaim | Honest-suffix reclaim does not drop competing-tower inflight. Catch-up-root-only reclaim is **per-peer** and, on a competing tower, **descendants of that root only**. |
| Cadence hold | Does not clamp a registered competing-tower GETDATA window, and does not skip competing direct-fetch holes above the cadence horizon. |
| Getheaders locator | Long competing HEADER_ONLY tower: first locator hash is the connected tip, not `pprev`. Competing BestKnown above tip still probes even when VERSION equals tip and the tip is fresh. |

ExactReplay, CPU confirmation, and `-matmulrcexecution=strict-device`
are unchanged from 0.34.10.

## Tests

- Original 0.34.10 peerman regressions: missing acquisition-frontier
  GETDATA is the root; honest HEADER_ONLY tip-child GETDATA under
  competing headers; missing-frontier does not block another registered
  tower.
- Review reproducers: unavailable active-tip child does not block
  another registered tower; does not starve unique-frontier GETDATA.
- Competing-tower getheaders locator starts at the connected tip.
- Header-sync unit: `HeaderSyncMustProbe` when VERSION equals tip and
  BestKnown is competing; `HeaderSyncKeepLocatorAtConnectedTip`.
- Shutdown: `protected_running_body_observes_shutdown`,
  `protected_scheduler_wait_observes_shutdown`,
  `rc_cpu_confirmation_bounded_shutdown_and_failure`.
