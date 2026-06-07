# Shielded Sunset Plan at Height 125000

This plan freezes the shielded state machine after block 125000. The goal is to
stop new shielded balances, deferred shielded credits, note refreshes, bridge
machinery, and shielded control-plane changes with the smallest consensus
exception surface.

The 125000 sunset is **outflow-only** (legacy-balance preservation): the only shielded transaction
permitted at/after the sunset height is a V2_SEND **real unshield** -- value actually LEAVING the pool to
transparent, i.e. `state value_balance > fee` (since `value_balance == transparent_out + fee`). A normal
unshield with a shielded change output (funded by the spender's own legacy value) qualifies, so no
special no-output encoding is required and legacy holders can always withdraw. Everything else is
rejected: credits (`< 0`), **pool-neutral z->z private transfers** (`value_balance == fee` -- the audited
"value_balance > 0 is not enough" case), rollover, bridge, control ops, AND -- for now --
**V2_SPEND_PATH_RECOVERY** (it re-shields rather than unshields, `value_balance == fee`, and is DS-4
unbound; re-enable it once the DS-4 nullifier binding lands). A genuine z->t unshield is only buildable
at C-002 height >= 123000 (<= the sunset height), so a `value_balance > fee` V2_SEND at the sunset is
genuinely a public unshield.

Detailed vulnerability analysis and docker-validated PoCs:
`redteam/findings/post-123000-double-spend-surface.md`; residual-risk verdict and hardening bundle:
`redteam/findings/superseded-shielding-sunset-pre-v032-plan.md`; executable invariant model:
`contrib/devtools/shielded_sunset_sim.py`. The June 6 external-report reassessment is
`doc/btx-security-audit-report-2026-06-06-reassessment.md`.

## Framework: constrain-and-preserve

The objective is **strong protection** (constrain every inflation/double-spend path) **plus
preservation of legacy shielded balances** (existing notes can always exit). Five pillars deliver it;
shipping them together turns an unbounded-mint catastrophe into a hard cap that drains soundly to zero:

1. **Fix the active inflation bugs.** DS-5 (V2_REBALANCE unbacked credit) is **IMPLEMENTED**: the
   rebalance state value_balance is now the NET of all reserve deltas (= 0 by conservation) instead of
   `-sum(positive)` (`src/shielded/bundle.cpp`, `CheckedSumAllReserveDeltas`). DS-1 (settlement-anchor
   replay), DS-2 (forged-receipt egress), DS-4 (MatRiCT recovery) get their fixes per the findings doc.
2. **Sunset entry gates (this doc):** no new shielded value may ENTER at height ≥ 125000 — fail-closed
   on credits, new commitments, manifests, and value-bearing anchors.
3. **Monotone-decrease clamp:** at height ≥ 125000 the turnstile rejects any net pool CREDIT, so
   `pool(h+1) ≤ pool(h)` is a hard invariant. The pool can only shrink.
4. **Pin the frozen ceiling (DS-3):** consensus-pin the snapshot pool/nullifier/commitment roots in
   `AssumeutxoData`; reject any snapshot that doesn't match. Without this, an assumeutxo-synced node
   accepts an attacker-supplied pool balance + nullifier set and the freeze is cosmetic. **The
   mechanism** (`ComputeShieldedSnapshotStatePin()`, emitted by `dumptxoutset`, verified by
   `ActivateSnapshot`) **ships in the same fork as the gates.** The pin *values* are filled per shipped
   snapshot height by an operator on a synced node (they hash the real shielded state at that height and
   cannot be precomputed); a null pin is a safe legacy-skip until filled. A dedicated `AssumeutxoData`
   entry *at* 125000 — the frozen-ceiling snapshot — can only be produced once the chain reaches 125000,
   so it is added in a follow-up release via the same emit. See `doc/ds3_snapshot_pin_runbook.md`.
5. **Preserve legacy exits:** strict pure `V2_SEND` transparent unshield (`value_balance > fee` and zero
   shielded outputs) is always allowed, so spendable legacy holders can withdraw for the entire wind-down
   without appending new commitments. `V2_SPEND_PATH_RECOVERY` is NOT allowed (it re-shields and is DS-4
   unbound). Stranded-note rescue is preserved by `V2_RECOVERY_EXIT` at the same 125000 boundary: it
   reveals the note, pays out transparent, and retires both the commitment and the canonical SMILE2
   nullifier. See `doc/recovery_exit_125000_spec.md`.
6. **Rate-limit the exit (velocity cap aligned to the sunset):** the unshield velocity cap (5000 bps = 50%
   of the pool over a 960-block ~1-day trailing window) activates at `nShieldedSunsetHeight` (125000), the
   same block the outflow-only rule engages, so there is no uncapped window between the sunset and the
   cap. This bounds the *rate* of
   any residual leakage or run on the pool; it is defense-in-depth on top of pillars 1–5, not a validity
   gate.

**Blast-radius guarantee:** with pillars 1–4 in place, the maximum value ever extractable from the
shielded pool equals the consensus-pinned 125000 balance, monotone-decreasing to zero. With the
spend-side fixes (DS-4 + the already-live C-002 binding) it is not even over-drainable. Residual =
Module-SIS hardness (formally reduced, Tier 1–3) + correct pin + correct patches.

## Consensus Rule

Add:

- `Consensus::Params::nShieldedPoolCreditDisableHeight = 123000`
- `Consensus::Params::nShieldedSunsetHeight = 125000`
- `IsShieldedPoolCreditDisabled(height)`
- `IsShieldedSunsetActive(height)`

At `height >= nShieldedPoolCreditDisableHeight`:

1. Reject any shielded transaction whose `TryGetShieldedStateValueBalance()` is
   negative. In current turnstile accounting, negative state value balance
   increases the shielded pool.
2. Reject V2 settlement anchors that carry reserve deltas or anchor a netting
   manifest, because they are deferred bridge-credit machinery even when their
   immediate state value balance is zero.

At `height >= nShieldedSunsetHeight` (outflow-only):

1. Accept ONLY a V2_SEND real unshield: state `value_balance > fee` (value actually leaves to
   transparent; `value_balance == transparent_out + fee`). A shielded change output is permitted because
   it is funded by the spender's own consumed legacy value.
2. Reject every other shielded bundle (`bad-shielded-sunset-non-exit`): credits (`value_balance < 0`),
   z->z private transfers (`value_balance == fee`), V2_SPEND_PATH_RECOVERY (re-shield, `== fee`, DS-4
   unbound), control ops, and all rollover/bridge families.
3. Keep historical shielded blocks valid below the sunset height.

This disables private rollover, reshielding, bridge settlement, rebalance, ingress, egress credits, and
lifecycle controls after sunset, while PRESERVING legacy exits: the pool is strictly monotone-decreasing
and can never be re-credited, yet no balance is trapped -- holders can unshield out for the entire
wind-down.

## Required Gates

Implement one shared helper near the existing shielded contextual gates in
`src/validation.cpp`:

`RejectShieldedHeightGateViolation(bundle, consensus, height, reject_reason)`

The helper should run in mempool and block validation before pool state is
projected, commitments are appended, manifests are recorded, or settlement
anchors are recorded.

Required call sites:

- Mempool path after `TryGetShieldedStateValueBalance()` and before projected
  pool application.
- `ConnectBlock()` before shielded tree/appended-output handling and before
  `next_pool_balance.ApplyValueBalance()`.
- Chainstate replay/rollforward paths before shielded state reconstruction
  applies value balances or appends commitments.
- Shielded state rebuild and proof-audit replay before
  `ApplyShieldedStateEffects()`.
- Mempool stale-entry removal when the next block height crosses either gate.

## Family Policy

`V2_REBALANCE`: rejected at 123000 STRUCTURALLY (the family is disabled in the pool-credit gate). After
the DS-5 fix a rebalance is pool-neutral (state value_balance == 0), so the negative-value-balance
predicate no longer catches it; it is rejected as `bad-shielded-v2-rebalance-disabled`.

`V2_EGRESS_BATCH`: rejected at 123000 through the negative state value balance
predicate (an egress credit has state value_balance < 0).

`V2_SETTLEMENT_ANCHOR`: rejected at 123000 when it carries reserve deltas or an
anchored netting manifest.

At 125000 (outflow-only): ONLY a `V2_SEND` whose state `value_balance > fee` (a real transparent
outflow exit; `value_balance == transparent_out + fee`) is accepted. **`V2_SPEND_PATH_RECOVERY` is
REJECTED** — it re-shields (`value_balance == fee`, no transparent payout) and is DS-4 unbound, so it is
never an outflow exit and stays disabled post-sunset (re-enable only once the DS-4 key-image binding
lands and a bound pure-exit recovery encoding exists). `V2_INGRESS_BATCH`, `V2_EGRESS_BATCH`,
`V2_REBALANCE`, `V2_LIFECYCLE`, `V2_GENERIC`, legacy bundles, pool-neutral z->z `V2_SEND`
(`value_balance == fee`), credit `V2_SEND` (`value_balance < 0`), and future/unknown families are
rejected (`bad-shielded-sunset-non-exit`).

Historical blocks below the configured gates remain valid.

## Does This Eliminate Inflation and Double-Spend Risk?

The 123000 gate eliminates known post-C002 pool-credit mint paths that rely on
negative shielded state balance or deferred settlement-anchor credit machinery.
The 125000 outflow-only sunset eliminates the largest remaining class: any bug that requires creating
or value-neutral-spending shielded state after sunset, while still letting legacy holders unshield out.

It does not eliminate all possible shielded-related risk. Residual areas remain:

- Historical nullifier uniqueness and rollback correctness below sunset.
- Pool-balance accounting on disconnect/reorg/replay of historical blocks.
- Legacy proof verification for historical blocks during reindex and audit.
- Wallet/RPC construction bugs that could produce transactions miners reject.
- Snapshot, index, and cache drift around nullifiers, pool balance, manifests,
  and settlement anchors.
- Any future exception for exits, settlement anchors, or bridge operations.
  Exceptions must be narrower than an entire shielded family and must have their
  own proof/accounting tests.

The sunset is therefore fail-closed except for strict outflow exits: at or after height 125000 the only
valid shielded transactions are pure `V2_SEND` transparent unshield and `V2_RECOVERY_EXIT` transparent
claim. Both append zero shielded outputs, so the pool can only drain and never re-credit, the commitment
tree is frozen, and no spendable legacy balance is trapped.

### Verdict and required hardening bundle

On its own the entry-gate sunset is **PARTIAL**: it root-cause-kills the credit-side inflation class
(DS-1/DS-2/DS-5) but leaves the residuals above, two of which (DS-3 snapshot trust, DS-4 recovery
double-spend) are orthogonal to entry-gating and survive it. To make the sunset actually close the
class, ship it as a bundle — the residuals above become **required gates**, not future work:

1. **DS-3 snapshot pin (CRITICAL, ship in the same fork).** Add hardcoded
   `kShieldedSunsetPoolBalance` / `kShieldedSunsetNullifierRoot` / `kShieldedSunsetCommitmentRoot` to
   `AssumeutxoData` and validate any snapshot with tip ≥ 125000 against them at the load sites. This is
   what makes the frozen ceiling real on fast-synced nodes; without it the freeze is cosmetic.
2. **Monotone-decrease clamp.** Thread `sunset_active` into `ShieldedPoolBalance::ApplyValueBalance`
   (NOT `UndoValueBalance` — reorgs legitimately restore a higher balance) so any net credit at
   height ≥ 125000 is rejected. Hard aggregate backstop in case a credit family is missed/added.
3. **DS-1 permanent consumed-anchor tombstone.** Make consumed settlement anchors a monotone record
   (mirror the netting-manifest `HasShieldedNettingManifest` guard) so a consumed settlement cannot be
   re-created and re-egressed. (Modeled in `shielded_sunset_sim.py::settlement_anchor_tombstone_blocks_replay`.)
4. **DS-4 recovery binding (preserve legacy exits).** Keep the stranded-note recovery path live — legacy
   holders depend on it — but make its nullifier note-deterministic and bound the input value, then
   retire the path once the legacy pool is drained.

With the bundle, the blast radius is hard-capped at the pinned 125000 balance and drains soundly to
zero; the only residual is Module-SIS hardness (formally reduced) plus correct pin/patch implementation.
Crucially, the legacy-exit path (V2_SEND no-output unshield) is untouched by every gate above, so
**legacy shielded balances are always recoverable** for the life of the wind-down.

## Regression Tests

Add tests around lowered regtest gate heights:

- Rebalance and egress pool credits rejected at and after the 123000-equivalent
  gate.
- Settlement anchor with reserve/manifest credit machinery rejected at and after
  the 123000-equivalent gate.
- V2_SEND private transfer rejected at and after the 125000-equivalent gate.
- V2 lifecycle/control rejected at and after the 125000-equivalent gate.
- Mempool entries accepted before sunset are evicted when sunset becomes the
  next block height.
- Reorg across sunset restores pool balance, nullifiers, manifests, and anchors.
- Chainstate replay/rebuild/proof-audit replay fails closed if a gated block
  contains shielded state that normal validation would reject.
