# BTX 0.34.10 — Acquisition-escape ExactReplay ordering

**Status:** **PR / not shipping.** `CLIENT_VERSION` is **0.34.10** with
`CLIENT_VERSION_RC=0` and `CLIENT_VERSION_IS_RELEASE=false`. P2P
subversion is `/BTX:0.34.10/`. `btxd -version` prints `v0.34.10` plus a
git suffix. Last shipping tag remains **v0.34.9**. Do not recut
`v0.34.9` or `v0.34.9-dev.pr198*`.

Not a consensus change relative to 0.34.9. `automatic_spend_atoms` stays
0.

## What this release is (and is not)

- **No consensus / ASERT / header-PoW / issuance change.**
- Fixes a local ExactReplay **admission** bug on the RB-16
  acquisition-escape path. An unprivileged node that is stale under a
  strictly-heavier competing header tower must ExactReplay **one** body
  at a time (the unique parent-connectable frontier) and must not spend
  GPU on its own retained tip-child while that frontier exists.
- `-acquisitionstallseconds` is ignored on mainnet even in `-dev`
  binaries. `DEBUG_ONLY` does not strip conf-file keys from
  `IS_RELEASE` builds; a short override re-armed competing-tower work
  on every restart.

A node with **no** pin membership, **no** attestor key, and **no**
trusted-mirror pin must still reach tip from ExactReplay alone, keep
advancing across a signed-frontier stall without operator action, and
recover **without a restart**. Restart-only recovery is still a failure.

## The bug

`AcquisitionEscapeCoversBlock` is a **tower** predicate: every body on a
registered exempt competing fork is "covered" so fetch, parked-bypass,
and retain can see it. Comments already said ExactReplay admits **one
frontier body at a time**. The code admitted every covered
parent-connectable body.

That is wrong for two independent reasons:

1. The exempt root is the fork **LCA** (on the active chain). A
   HEADER_ONLY / retained child of the **active tip** is not
   `Contains()` yet, so a descendant-of-LCA test treated our own
   tip-child as competing-tower work.
2. Every direct child of the LCA is parent-connectable. Admitting all
   of them, plus the followed tip-child (`pprev == tip`) on the
   progress RC lane (`nMatMulRCMaxPendingVerifications=1`), filled the
   accelerator scheduler (~5 GiB per workspace). `AcceptBlock` then
   failed retryable (`queue full, waiter deadline, or workspace
   capacity`) forever. A restart of the same binary re-armed the same
   set.

The unique lowest unverified parent-connectable body on the heaviest
registered tower (`FindAcquisitionEscapeFrontier`) is the only ExactReplay
candidate. Fetch lookahead is unchanged (bounded GETDATA above that
frontier). Migration stays park / `deepforkautoresolve`-gated.

## What landed

| Surface | Change |
|---|---|
| `AcquisitionEscapeCoversBlock` | Active-chain blocks and tip-extending HEADER_ONLY / retained children are never covered. |
| `FindAcquisitionEscapeFrontier` | Unique lowest unverified parent-connectable body on the heaviest registered tower, or `nullptr`. |
| ExactReplay admission | `MatMulMaySpendExactReplayGpu`, AcceptBlock reverify, RC progress-lane, NextRetry, and the 1 Hz replay driver spend GPU **only** on that frontier. A live HEADER_ONLY hole yields the followed tip-child rather than filling the scheduler. |
| `-acquisitionstallseconds` | Ignored on mainnet. Regtest/testnet still honor it with a warning. |

## Precompiled archives

Not a shipping cut. Archives, if built from this PR, advertise
`/BTX:0.34.10/` and `IS_RELEASE=false`. Use
`python3 scripts/release/verify_release_btxd.py` on `libexec/btxd.real`.
