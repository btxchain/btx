# BTX KAWPOW + DGW Scaling Analysis

This note records the primary-source basis for BTX PoW scaling controls and the
simulation coverage tied to those risks.

## Primary-source baseline

- Ravencoin DGW/KAWPOW difficulty logic:
  - [Ravencoin `src/pow.cpp` (DGW 180-block window, 3x clamp)](https://github.com/RavenProject/Ravencoin/blob/master/src/pow.cpp)
  - [Ravencoin `src/primitives/block.h` (`nNonce64`, `mix_hash` header fields)](https://github.com/RavenProject/Ravencoin/blob/master/src/primitives/block.h)
  - [Ravencoin `src/rpc/mining.cpp` (template + KAWPOW mining RPC paths)](https://github.com/RavenProject/Ravencoin/blob/master/src/rpc/mining.cpp)
- Bitcoin historical difficulty/timewarp hardening:
  - [BIP94: Testnet4 block-storm + timewarp mitigation](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki)
  - [Bitcoin Core `src/pow.cpp` (`enforce_BIP94`, first-block retarget base)](https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp)
  - [Bitcoin Core 28.0 release notes (Testnet4 + BIP94)](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-28.0.md)

## BTX risk model and controls

1. Hashrate step changes (up/down) must not destabilize long-run block cadence.
2. Alternating hashrate patterns (oscillation behavior) must not cause unbounded
   drift, hangs, or invalid compact targets.
3. Timestamp-drift style pressure must still preserve recoverability and valid
   target encoding.
4. KAWPOW header semantics (`nonce64`, `mixhash`) and template fields must stay
   mining-compatible with GPU miner/pool workflows.

Consensus controls in BTX:
- `src/pow.cpp` uses Ravencoin-style DGW with the 180-block rolling target and
  clamped timespan bounds.
- `src/validation.cpp` performs contextual KAWPOW PoW checks against
  `mix_hash` and compact target.
- `src/kernel/chainparams.cpp` keeps KAWPOW active from height 0 on BTX
  networks with strict regtest mode available for operator verification.

## Simulation suite

Long-horizon deterministic simulations are implemented in
`src/test/pow_tests.cpp`:
- `GetNextWorkRequired_kawpow_dgw_long_horizon_scaling`
- `GetNextWorkRequired_kawpow_dgw_oscillation_resilience`
- `GetNextWorkRequired_kawpow_dgw_timestamp_drift_recovery`

The production gate wrapper is:
- `scripts/m8_pow_scaling_suite.sh`

This wrapper runs the scenarios above, emits per-scenario logs, and writes a
machine-readable JSON artifact consumed by production readiness checks.
