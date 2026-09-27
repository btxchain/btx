# BTX 0.34.12rc1 — Available-chain recovery

**Status:** release candidate. `CLIENT_VERSION` is **0.34.12** with
`CLIENT_VERSION_RC=1` and `CLIENT_VERSION_IS_RELEASE=false`. `btxd -version`
prints `v0.34.12rc1` plus a git suffix. P2P subversion is `/BTX:0.34.12/`.
Last shipping tag remains **v0.34.10**. Do not recut `v0.34.10`.

Not a consensus change. ExactReplay arithmetic, chainwork, fork choice,
issuance, bans, and reorg policy are unchanged. An unavailable header tower
is not marked invalid. `automatic_spend_atoms` stays 0.

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

A fast-start snapshot is pinned at height 228000, on the shared ancestor
below the 228145 fork. It does not choose either child of that fork.

## What it does not do

- No new peer ban for an old-body refusal, including a limited-history
  node answering `NOTFOUND` outside its service window.
- No automatic `invalidateblock` for a missing body.
- No change to which chain has more work. Header work still ranks two
  towers that are equally unable to supply a body.
- Probe backoff timers and `getforkavailability` /
  `setforkacquisitionpolicy` are not part of this candidate.

A node with no pin membership, no attestor key, and no trusted-mirror pin
must still reach tip from ExactReplay alone, keep advancing across a
signed-frontier stall without operator action, and recover without a
restart.
