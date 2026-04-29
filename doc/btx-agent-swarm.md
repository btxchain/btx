# BTX Codex Swarm Runner

This repository includes a swarm runner that can launch multiple non-interactive
Codex agents in parallel worktrees, then gate each round with BTX tests.

## Scripts

- `scripts/codex_swarm.sh`: orchestrates parallel Codex agents using `codex exec`.
- `scripts/codex_swarm_tasks.txt`: default task queue (`task_id|prompt`).
- `scripts/test_btx_parallel.sh`: parallel test gate used by default by the swarm.

## Quick Start

1. Ensure BTX binaries/tests are built:

```bash
scripts/build_btx.sh build-btx
```

2. Run one swarm round:

```bash
scripts/codex_swarm.sh --repo "$(pwd)" --max-agents 3
```

3. Run continuously until a round passes the test gate:

```bash
scripts/codex_swarm.sh --repo "$(pwd)" --max-agents 3 --continuous
```

4. Enforce per-agent timeout to prevent hanging rounds:

```bash
scripts/codex_swarm.sh --repo "$(pwd)" --max-agents 3 --agent-timeout-seconds 600
```

## Notes

- Each agent runs in a dedicated git worktree under `.codex-swarm/worktrees/`.
- Each agent gets its own branch named `codex/swarm-<task>-<timestamp>`.
- Agent output is written to `.codex-swarm/logs/`.
- Worker timeouts are enforced by default (`--agent-timeout-seconds 600`).
- Timeout behavior is regression-tested by `test/util/codex_swarm_timeout_test.sh`.
- Use `--dry-run` to validate orchestration logic without launching Codex.
