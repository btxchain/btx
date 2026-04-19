# BTX Production Readiness Matrix

This document tracks the public, repeatable verification paths that matter for a BTX release candidate.
It is intentionally limited to operator-facing checks and excludes internal workflow notes.

## Core Gates

| Area | Status | Primary Check |
| --- | --- | --- |
| Consensus and PoW | Green | `scripts/test_btx_consensus.sh build-btx` |
| Parallel regression coverage | Green | `scripts/test_btx_parallel.sh build-btx` |
| Mining readiness | Green | `scripts/m7_mining_readiness.sh build-btx` |
| Genesis tuple verification | Green | `scripts/m5_verify_genesis_freeze.sh --build-dir build-btx` |
| Fast-to-normal transition | Green | `scripts/m14_fast_normal_transition_sim.sh --build-dir build-btx-transition-sim` |
| Dual-node P2P validation | Green | `scripts/m12_dual_node_p2p_readiness.sh --build-dir build-btx` |
| macOS/Linux interoperability | Green | `scripts/m13_mac_centos_interop_readiness.sh --mac-build-dir build-btx --centos-build-dir build-btx-centos --skip-centos-build` |
| Shielded regression suites | Green | `build-btx/bin/test_btx --run_test=smile2_wallet_bridge_tests,shielded_wallet_chunk_discovery_tests` |

## Release Notes

- Keep this matrix aligned with the runnable scripts in `scripts/`, `test/`, and `doc/`.
- If a check becomes non-repeatable, downgrade it here before treating a build as production-ready.
- External review and hosted validation packets are tracked by their dedicated handoff documents.
