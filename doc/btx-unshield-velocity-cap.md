# Shielded unshield velocity cap (v0.32.0-v0.32.12)

Defense-in-depth consensus rule that bounds the **rate** at which value can leave the shielded pool
(shielded→transparent / "unshield"), so a stolen spend key or a future inner-proof soundness
regression becomes a **slow, observable leak** rather than an instantaneous drain. Mirrors the
velocity-limit recommendation from the Zcash Orchard disclosure; complements (does not replace) the
turnstile and the C-002 per-tx bindings.

As of v0.32.12, this quota fully exits at height **135,000**. Blocks 125,000 through 134,999 remain
subject to the historical cap. Blocks 132,000 through 134,999 also have the v0.32.11 10,000 BTX
minimum-cap floor, so legitimate recovery traffic can keep moving while the quota is still active.
Blocks 135,000 and later are no longer rate-limited; shielded exits are bounded by ordinary
consensus validity, fees, and block resource limits. Nodes retain the persisted velocity log through
the configured reorg horizon after 135,000 so rollback validation of historical capped blocks remains
deterministic.

## Where it sits in the defense stack

| Layer | Guarantee | Mechanism |
|---|---|---|
| C-002 v3 bindings | per-tx soundness — forgery non-constructible | `ct_proof.cpp:3503-3509` (serial↔key), `:3847-3890` (balance) |
| Turnstile | net transparent supply inflation = 0; total loss ≤ pool | `ShieldedPoolBalance` (`turnstile.cpp`), enforced `validation.cpp:1082/6122` |
| **Velocity cap (this)** | egress **rate** bounded; drain is slow + detectable | `ShieldedUnshieldVelocity` leaky bucket |

The cap is *not* a substitute for the first two — it is the early-warning / blast-radius layer for
the residual no-one can rule out by code review alone (e.g. the open `f3` reduction failing
post-activation).

## Parameters (consensus)

`src/consensus/params.h`:
- `nShieldedUnshieldVelocityActivationHeight` — **125,000** (`BTX_SHIELDED_SUNSET_HEIGHT`, all networks);
  INT_MAX (inert) on regtest unless overridden. Aligned to the 125,000 sunset so the cap is active from
  the first block where a transparent-outflow exit is the only permitted shielded operation (no uncapped
  window). Self-serve unshield does not exist before the C-002 fork (123,000) anyway.
- `nShieldedUnshieldVelocityEndHeight` — **135,000** (all production networks in v0.32.12). The end height
  is exclusive: block 134,999 is capped, block 135,000 is uncapped. Regtest defaults INT_MAX unless
  overridden with `-regtestshieldedunshieldvelocityendheight`.
- `nShieldedUnshieldVelocityMinCapHeight` — **132,000**. The 10,000 BTX minimum-cap floor applies only
  while the quota remains active, so it covers blocks 132,000 through 134,999 on production networks.
- `nShieldedUnshieldVelocityWindowBlocks` — **960** (~1 day at 90 s).
- `nShieldedUnshieldVelocityCapBps` — **5000** (50% of the pool may be unshielded per window).

%-of-pool means the cap auto-scales with the live pool while active. During the historical capped
window, 50%/day let legitimate large legacy holders exit progressively while still throttling a
stolen-key/residual drain to half the pool per day. After height 135,000 the quota is intentionally
removed to let the remaining legacy exits clear without causing capacity-aware block template retries.

## Mechanism (`src/shielded/unshield_velocity.{h,cpp}` — implemented + unit-tested)

Leaky bucket, all derived from the live pool balance:
- `capacity B = cap_bps/10000 · pool` (max burst)
- `refill R = B / window` per block (sustained rate)
- per block `h`: `bucket = min(B, bucket + R·(h−last)); if net_unshield(h) > 0: bucket −= net_unshield(h);`
  **block invalid iff `bucket < 0`** (`shielded-unshield-velocity-exceeded`).

`net_unshield(h)` = the block's net positive `value_balance` (Σ value_balance over the block; shields
in the same block offset unshields). Deterministic: pool, height, params only — no wall-clock, no I/O.
Reorg-safe: `Apply()` returns the pre-update `Snapshot`; the caller stashes it and hands it to
`Restore()` on disconnect (no lossy inverse). Serializable for persistence.

Unit tests (`src/test/shielded_unshield_velocity_tests.cpp`, green): capacity = %-of-pool + auto-scale;
burst-to-capacity then reject; full-window refill; net-ingress neither consumes nor overfills;
exact reorg restore; serialization round-trip.

## Consensus integration — IMPLEMENTED

The rule is implemented as a window SUM over a persisted per-block net-egress log (chosen over the
leaky bucket precisely because it is a pure function of recent egress, hence trivially reorg-safe):

1. **Member.** `ChainstateManager::m_shielded_unshield_velocity` (`validation.h`), beside
   `m_shielded_pool_balance`.
2. **ConnectBlock** (`validation.cpp`, at the shielded-state commit, before the pool-balance DB
   write): block net egress = `max(0, pool_at_start - pool_at_end)` (the pool's net decrease this
   block). When `IsShieldedUnshieldVelocityCapActive(nHeight)`: `RecordBlock`, reject with
   `shielded-unshield-velocity-exceeded` if `!WithinCap(...)`, `Prune` to 2·window, persist via
   `WriteUnshieldVelocity`, and commit the member alongside the pool balance.
3. **DisconnectBlock** (`validation.cpp`, beside the pool rollback): `UndoBlock(nHeight)` erases the
   block's entry exactly, then persists — exact reorg undo, no lossy inverse.
4. **Persistence** (`NullifierSet`, `DB_UNSHIELD_VELOCITY` key): the log is persisted (not recomputed
   from blocks a pruned node lacks), so every node — pruned or full — evaluates the rule identically.
   Loaded at `EnsureShieldedStateInitialized` (`finish_success`).
5. **Activation/end:** active from 125,000 (`BTX_SHIELDED_SUNSET_HEIGHT`) through 134,999; inactive at
   and after 135,000. Regtest defaults INT_MAX (inert), overridable via
   `-regtestshieldedunshieldvelocityactivationheight` and
   `-regtestshieldedunshieldvelocityendheight`.

### Tests (green)
- `shielded_unshield_velocity_tests` (C++): window-cap %-of-pool + auto-scale, window sum + cap
  enforcement, exclusive lower boundary, net-ingress records zero, exact reorg undo, prune, serialize.
- `wallet_shielded_velocity_cap.py` (functional): cap active from genesis on regtest; autoshield
  (pool grows -> never capped); restart reloads the persisted log + `verifychain`; reorg
  (invalidate/reconsider) exercises `UndoBlock`; chain keeps advancing.

### Known regtest limitation (rejection path)
End-to-end *rejection* needs pool egress (an unshield), but self-serve z->t unshield is gated to the
C-002 height (123,000), unreachable in regtest. So the cap-exceeded path is covered at the unit level
(`window_sum_and_cap_enforcement` -> `WithinCap` returns false), which the ConnectBlock check calls
directly. A full end-to-end rejection test will be runnable once C-002 activation is a regtest-
lowerable consensus param (the existing `#10` TODO), which would also enable the C-002 cross-activation
E2E.
