# BTX Peer Sync Hardening Tracker (2026-03-09)

Scope: mainnet bootstrap reliability, peer connectivity diagnostics, and operator
runbook clarity for new-node synchronization.

## Findings from field reports

1. Fresh-node presync failures at `height=50181` with
   `invalid MatMul schedule nBits` are consistent with synthetic index pruning
   removing ASERT anchor ancestry required by `GetNextWorkRequired(...)`.
2. Tor log lines:
   `resolve failed ... No more HSDir available to query`
   are transport/bootstrap failures in Tor reachability, not evidence of BTX
   consensus failure.

## Changes in this branch

- Preserve MatMul ASERT anchor ancestry during header presync/redownload
  synthetic index trimming (`src/headerssync.cpp`).
- Add richer nBits mismatch diagnostics (expected/received nBits, phase,
  retained synthetic floor, window range).
- Add regression coverage for long MatMul presync chains crossing ASERT anchor
  boundaries (`src/test/headers_sync_chainwork_tests.cpp`).
- Expand operator docs for Tor HSDir failures and clearnet bootstrap fallback:
  - `doc/tor.md`
  - `doc/btx-public-node-bootstrap.md`

## Action backlog

1. Add deterministic memory envelope metrics for synthetic header ancestry
   retention under long-horizon mainnet presync.
2. Add an integration test that simulates bootstrap from clean datadir using
   published public peers and validates non-zero `headers`/`blocks` progress.
3. Add clearer startup log hints when onion connectivity is enabled but Tor
   bootstrap is unavailable.
4. Add a release-gate check that scans docs for network bootstrap drift
   (ports, seed hostnames, shielded RPC naming).
