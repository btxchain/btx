# BTX Continuous Execution Tracker

This tracker is used during continuous parallel execution across milestones.

## Current focus

- [x] Finalize BTX KAWPOW-native block-hash semantics.
- [x] Complete production genesis nonce64/mixhash search for main/test networks.
- [x] Validate external `kawpowminer` and pool submission path on BTX testnet/regtest.
- [x] Integrate long-horizon DGW/KAWPOW scaling simulations.
- [x] Integrate anti-hang guards for swarm and M7 workflows.
- [x] Add benchmark suite and consolidated validation checklist tooling.
- [x] Add Apple Silicon optional Metal mining acceleration path + validation workflow.

## Execution checklist

Run these commands from repository root:

```bash
scripts/build_btx.sh build-btx -DBUILD_BENCH=ON
scripts/test_btx_parallel.sh build-btx
scripts/test_btx_consensus.sh build-btx
scripts/m9_btx_benchmark_suite.sh --build-dir build-btx --artifact /tmp/btx-benchmark-suite.json --log-dir /tmp/btx-benchmark-suite-logs --iterations 1
scripts/m8_pow_scaling_suite.sh --build-dir build-btx --artifact /tmp/btx-pow-scaling-suite.json --log-dir /tmp/btx-pow-scaling-suite-logs
scripts/verify_btx_production_readiness.sh --build-dir build-btx --artifact /tmp/btx-production-readiness-report.json
scripts/m10_validation_checklist.sh --build-dir build-btx --artifact-json /tmp/btx-validation-checklist.json --checklist-md /tmp/btx-validation-checklist.md
scripts/generate_validation_checklist.sh --build-dir build-btx --artifact /tmp/btx-deep-validation-checklist.json --log-dir /tmp/btx-deep-validation-logs
```

## Artifact map

- Benchmark suite: `/tmp/btx-benchmark-suite.json`
- PoW scaling suite: `/tmp/btx-pow-scaling-suite.json`
- Production readiness: `/tmp/btx-production-readiness-report.json`
- Validation checklist (JSON): `/tmp/btx-validation-checklist.json`
- Validation checklist (Markdown): `/tmp/btx-validation-checklist.md`
- Deep validation checklist (JSON): `/tmp/btx-deep-validation-checklist.json`

## Parallel swarm templates

Use the swarm launcher for task fan-out:

```bash
scripts/codex_swarm.sh --tasks-file /tmp/btx_full_parallel_tasks.txt --max-agents 3 --agent-timeout-seconds 1800 --test-cmd "true"
```

Recommended task buckets:
- Benchmarking + performance regression scripts.
- Validation/readiness gate expansion.
- Documentation and operator runbook updates.

## Launch blocker closure

Verified green on February 8, 2026 via:

```bash
scripts/verify_btx_launch_blockers.sh --build-dir build-btx
scripts/test_btx_parallel.sh build-btx
scripts/verify_btx_production_readiness.sh --build-dir build-btx
```
