# BTX 0.34.12rc1 — Available-chain recovery

**Status:** release candidate. `CLIENT_VERSION` is **0.34.12** with
`CLIENT_VERSION_RC=1` and `CLIENT_VERSION_IS_RELEASE=false`. `btxd -version`
prints `v0.34.12rc1` plus a git suffix. P2P subversion is `/BTX:0.34.12/`.
Last shipping tag remains **v0.34.10**. Do not recut `v0.34.10`.

Not a consensus change. ExactReplay arithmetic, chainwork, issuance, and
bans are unchanged. An unavailable header tower is not marked invalid.
`automatic_spend_atoms` stays 0. Local automatic-reorg policy gains a
bounded mode (below). It does not make a deep valid chain invalid, and it
does not require a signer or a trusted peer.

## What this candidate fixes

A node can stop moving while another chain is available. 0.34.12rc1 keeps
the scarce recovery and replay resources on work that can actually be
checked:

- A definitive body rejection retires that header tower. A mutated body
  stays retryable.
- A competing body that has passed ExactReplay and been written to disk
  releases its in-memory retention slot before script validation, so the
  next body can be held.
- A trusted mirror can connect the body-complete prefix below a header-only
  hole on the signed frontier. A consensus node still refuses that suffix
  until the hole is filled.
- ExactReplay can run a ready body on one registered tower while another
  tower is still waiting for a block.
- If acquisition recovery is active, a second and third peer can be asked
  for the lowest missing body. One silent owner cannot keep it.
- A retained body whose original delivery was not force-processed is
  retried by the scheduler without a new admission ticket. Cancellation
  does not mark the block invalid. A duplicate unsolicited delivery still
  does not start replay.
- Two recovery registrations remain the limit. A higher-work tower with no
  body cannot hide a ready sibling or evict a frontier that can be
  replayed. A failed block drops only the registration that descends from it.
- A ready child of the active tip is replayed before competing acquisition.
  Among ready registered forks, the shallower reorg is preferred. After
  eight new ExactReplay verdicts on that fork, another ready fork gets one
  turn. Claimed header work does not keep a deep ready fork in front of a
  nearby ready one.
- `-reorgpolicy=bounded` is the default. While the followed chain is
  progressing, automatic reorgs stay within 6 blocks. After 900 seconds
  without a forward connection, recovery may go to the closest checked
  branch within 72 blocks. A heavier valid chain beyond that ceiling, or
  below the persisted protected ancestor, is parked rather than adopted.
  `preparereorg` / `executereorg` authorize one exact deeper transition and
  do not raise the standing ceiling. `-reorgpolicy=legacy` keeps the
  previous park and deep-fork auto-resolve behavior. `-parkdeepreorg=0`
  conflicts with bounded mode and the node will not start until one of
  them is changed.
- Quiet outbound peers whose recorded height is behind the tip are asked
  for headers on a slow background timer (one request per peer each five
  minutes, one across the node each 30 seconds). The locator starts at
  that peer's last known header. This discovers a competing chain. It
  does not download bodies or reorganize.
- A trusted mirror can keep requesting the next header page from a
  recognized authority after a solicited full batch, even when that
  prefix still has less work than the local tip. A solicited full
  authority batch that is already strictly heavier can register the
  existing acquisition tower before the 72-header lead cap is applied.
  Parked branches, ordinary peers, and unsolicited batches do not get
  either exception. Learning those headers does not raise the reorg
  ceiling or make the authority the fork-choice referee.
- Bounded mode parks one historical fork root, the 228146 block
  `8240c62e…` that a warn-only node followed for 3461 blocks. A fresh
  node does not sync that island. The block is not marked invalid, a
  node already on that chain is left there, and `-reorgpolicy=legacy`
  does not park it. `reconsiderblock` does not clear it while bounded
  mode is on.

A fast-start snapshot is pinned at height 228000, on the shared ancestor
below the 228145 fork. It does not choose either child of that fork.

## What it does not do

- No new peer ban for an old-body refusal, including a limited-history
  node answering `NOTFOUND` outside its service window.
- No automatic `invalidateblock` for a missing body.
- No change to which chain has more work. A parked deep branch is still
  a valid chain; this node simply does not disconnect for it while
  bounded mode is on.
- Probe backoff timers and `getforkavailability` /
  `setforkacquisitionpolicy` are not part of this candidate.

A node with no pin membership, no attestor key, and no trusted-mirror pin
still reaches a tip from ExactReplay alone. Inside the configured recovery
ceiling it can leave a stalled tip without an operator. Past that ceiling
it keeps the chain it has checked until an operator authorizes one
transition, or until it is started with `-reorgpolicy=legacy`. Peer count
and attestations do not choose the chain or widen the ceiling.
