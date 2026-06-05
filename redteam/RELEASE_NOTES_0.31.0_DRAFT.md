# BTX Core v0.31.0 — Release Notes (DRAFT, public-facing)

**Consensus activation: block height 123,000 (estimated early-to-mid June 2026 — confirm the exact ETA
against the live tip and the 90s block target before publishing). This is a mandatory upgrade — every
node and miner must run v0.31.0 before block 123,000.** Nodes still on older versions will diverge from
the network at activation.

---

## Headline: self-service, privacy-preserving shielded → transparent ("unshield")

You can now move shielded BTX to a transparent address **directly from your own wallet/node**, with no
bridge operator and no verifier set in the loop.

- New wallet RPC (and GUI flow) builds the unshield statement and proof **locally** — your node produces
  everything the network needs.
- **Privacy improvement:** because no operator is involved, no third party learns the link between your
  shielded source and your transparent destination. Unshielding is now self-custodial.
- This unblocks exchange/OTC funding flows that settle into transparent BTX.

See the updated *Shielded Guide* for `unshield` usage.

## Usability

- **Rebuild progress, finally visible.** Shielded-note rebuild and chain reindex now show a live progress
  bar, percentage, throughput, and **estimated time remaining** — no more silent multi-minute startups.
- **Clearer startup logging** is on by default (loading index → verifying → rebuilding shielded state →
  loading wallet → syncing), so you always know what the node is doing.
- **Easier builds.** Fixed test/compile issues on current Alpine/Linux toolchains; a reliable fully-static
  portable Linux binary; one-command build and a regtest `docker-compose` for developers.

## Protocol, mining & stability

This release includes a coordinated protocol upgrade at block 123,000:

- **Mining seed-derivation refinement** for the MatMul proof-of-work (improves per-attempt determinism and
  keeps mining squarely raw-GPU-bound, brand-agnostic — no architecture-specific or memory-hard behavior).
- **Shielded protocol upgrade** hardening the confidential-transaction proof system.
- **Timestamp & difficulty hardening** — bounds future-dated timestamps relative to median-time-past and
  smooths difficulty response; fixes a timestamp edge case around rule-activation boundaries.
- **Network & resource hardening** — additional anti-DoS limits in block/transaction relay and shielded
  state handling.
- **Dependency & build-integrity updates.**

## Upgrade instructions

1. Download v0.31.0, stop your node gracefully, replace the binaries, restart. Your datadir is reused —
   no resync required (startup will show the rebuild progress bar if applicable).
2. **Miners/pools:** upgrade all mining nodes before block 123,000.
3. **Exchanges/services/explorers:** upgrade all validating nodes before block 123,000.
4. Verify with `btx-cli getnetworkinfo` (subversion `/BTX:0.31.0/`) and
   `btx-cli getblockchaininfo`.

## Looking ahead: canonical wBTX

This release also publishes the **canonical wBTX specification** (`docs/wBTX.md`) — the authoritative standard
for a wrapped, EVM-native (18-decimal) representation of BTX, so bridges and integrators can build to one
canonical wrapper ahead of its introduction. **No on-chain change** — BTX remains an 8-decimal chain; all
decimal handling lives in the EVM-side bridge/contracts (10¹⁰ scaling, round-down on redeem). Reference
contracts and the production bridge will follow in a later milestone.

## Notes

- v0.31.0 is consensus-incompatible with earlier versions from block 123,000 onward. Do not delay the upgrade.
- Full changelog and developer docs: <link>.
