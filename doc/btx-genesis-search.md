# BTX Genesis Search Swarm

This document covers the M5 helper for parallel KAWPOW genesis nonce64 search.

## Script

- `scripts/m5_genesis_search_swarm.sh`

The script partitions nonce64 search space into round-sized chunks and runs
multiple `btx-genesis` workers in parallel. It persists progress in a state
file and writes the successful worker output into an artifact file.

## Example

```bash
scripts/m5_genesis_search_swarm.sh \
  --build-dir build-btx \
  --network main \
  --workers 8 \
  --chunk-tries 500000 \
  --state-file .codex-swarm/m5-main.state \
  --artifact .codex-swarm/m5-main-found.txt
```

## Key Behaviors

1. Resumes from `--state-file` by default.
2. Supports deterministic restarts via `--reset-state`.
3. Marks expected misses (`no valid nonce found within max tries`) as normal.
4. Fails fast on unexpected worker errors.
5. Supports non-mutating planning runs with `--dry-run`.

## Validation

- `test/util/m5_genesis_search_swarm_test.sh` exercises:
  - parallel round partitioning,
  - state-file progression,
  - successful artifact capture,
  - dry-run behavior.
