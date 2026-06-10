# DS-3 — operator runbook: filling the assumeutxo shielded-state pins

**What DS-3 is.** The assumeutxo snapshot's shielded section (pool balance + nullifier set +
commitment tree) is attacker-supplied and was otherwise never validated against consensus. Without a
pin, a malicious snapshot could set an arbitrary pool balance and omit spent nullifiers, enabling a
double-spend on a node that bootstrapped from it. The fix pins the shielded state to a consensus
commitment per snapshot height (`AssumeutxoData.shielded_state_commitment`) and rejects any load whose
reconstructed shielded state does not hash to that pin.

**Compatibility default until pins ship.** When a snapshot carries a shielded section but its height has
no consensus pin, strict mode (`-allowunpinnedshieldedsnapshot=0`) refuses to load it
(`validation.cpp` ActivateSnapshot: pinned → verify against the pin; unpinned +
`!allow_unpinned_shielded_snapshot` → reject `BTX shielded snapshot section has no consensus pin for
this height`). This is the DS-3 hardening: an unpinned shielded section is attacker-supplied and
otherwise unvalidated. Current shipped mainnet snapshots do not yet carry shielded pins, so v0.32
defaults to bootstrap compatibility (`-allowunpinnedshieldedsnapshot=1`) and logs a warning when such a
snapshot is loaded. Filling the pins (below) is what lets fail-closed bootstrap become the default for
everyone.

**Why the mainnet pins are not hardcoded in this commit.** The pin is
`SHA256("BTX_ShieldedSnapshotStatePin_V1" || note_commitment_root || account_registry_root ||
nullifier_root || bridge_settlement_root || shielded_pool_balance)` over the *real shielded state at
the snapshot height*. Those roots only exist on a node synced to mainnet at that exact height; they
cannot be computed offline or from a regtest chain. Writing a guessed value is strictly worse than
null — it would reject *legitimate* snapshot loads at that height. So the value must be produced by an
operator on a synced node, by the procedure below, and copied verbatim.

## Procedure (per snapshot height)

The pin is now emitted by `dumptxoutset` (single source of truth: `WriteUTXOSnapshot` computes it via
`ChainstateManager::ComputeShieldedSnapshotStatePin()` — the exact function ActivateSnapshot verifies
against, so the emitted and verified pins cannot drift).

1. Sync a trusted node to (at least) the target snapshot height `H` on mainnet.
2. Produce the snapshot at `H`:
   ```
   btx-cli dumptxoutset /path/to/utxo-H.dat rollback=H
   ```
3. Read `shielded_state_pin` from the RPC result (also logged as
   `[snapshot] BTX shielded_state_pin at height H = <hex>`).
4. Paste it into the matching `AssumeutxoData` entry in `src/kernel/chainparams.cpp`:
   ```cpp
   .height = H,
   ...
   .shielded_state_commitment = uint256{"<hex>"},
   ```
5. Rebuild. From then on, any `loadtxoutset` of a snapshot at `H` whose shielded section does not hash
   to that pin is rejected (`BTX shielded snapshot state does not match the consensus-pinned
   commitment`).

**Verification of a filled pin.** On a second independent synced node, repeat steps 1–3 and confirm
the emitted hex matches what was committed. Two independent nodes agreeing is the consensus check; a
single node's value should not be trusted blindly.

## Status of the shipped entries

| Network | Heights | Pin status |
|---|---|---|
| main | 55'000 … 126'800 (12 entries) | **null — operator must fill** per above (safe legacy-skip until then) |
| main | 125'000 (exact frozen-ceiling snapshot) | **no entry yet** — add it in a follow-up release if an exact-ceiling bootstrap asset is published |
| testnet/signet/etc. | — | no assumeutxo entries |
| regtest | 110, 299, 61'010 | null — filled on demand by test/dev tooling |

The first 11 existing mainnet snapshot heights predate the 125'000 pool-credit-disable/sunset boundary;
the 126'800 entry is post-boundary. The pin protects bootstrapping nodes from a forged shielded section
regardless of which side of the pool-credit-disable gate the snapshot height is on.

**Frozen-ceiling pin at 125'000.** Sunset pillar 4 calls for pinning the 125'000 pool/nullifier/
commitment roots — the consensus snapshot of the frozen ceiling. If an exact 125'000 bootstrap asset is
published, run `dumptxoutset rollback=125000` on a synced node, add a new `AssumeutxoData` entry at
height 125'000 with the emitted `shielded_state_pin`, and ship it in a follow-up release. Until then the
freeze is enforced by the consensus gates (pillars 2–3); the 125'000 pin only adds
assumeutxo-bootstrap protection for that exact height.
