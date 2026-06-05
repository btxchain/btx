# BTX Comprehensive Adversarial Hardening — Red-Team Lab

Branch: `redteam/comprehensive-hardening` (off `pr-214`).
Goal: exhaustively find evil-miner / consensus / DoS / economic attacks against BTX
(MatMul PoW + ASERT difficulty, shielded tx), then implement *correct* mitigations and
ship a comprehensive hardening PR. "Resolve all evil potential."

## How the swarm works (READ THIS IF YOU ARE AN AGENT)
1. **Before attacking**, read `redteam/ATTACK_CATALOG.md` (the taxonomy of vectors + deep
   code-analysis seeds) and `redteam/LEARNINGS.md` (everything confirmed/refuted so far).
   Build on prior learnings — do NOT repeat refuted attacks; instead try *variations* and
   *combinations* that the learnings suggest.
2. **Write your findings** to `redteam/findings/<your-agent-id>.md` (unique path). Use the
   template at the bottom. Do NOT `git commit` (the orchestrator commits to avoid index
   races) — just write/overwrite your file.
3. Be **empirical**: regtest repros with exact commands + observed output. Quantify. If you
   can only reason from code, say so explicitly. NEVER fabricate a result.
4. Think like an out-of-the-box adversary: every parameter, every out-of-bounds field, every
   proposed-block mutation, every known attack from other chains adapted to MatMul/ASERT.

## Shared assets
- Honest PR node (rule disabled in regtest): image `btx-node:pr214`
- Honest node, timestamp rule ENABLED in regtest @ height 200 / drift 3600: `btx-node:pr214-regtest-ruleon`
- Unmodified baseline: build from `main` (`git archive main | tar -x -C /tmp/<ns>-main && docker build ...`)
- Build a variant: `git archive pr-214 | tar -x -C /tmp/<ns>-src`, patch, `docker build -f /tmp/<ns>-src/contrib/docker/Dockerfile -t <tag> /tmp/<ns>-src`
- Regtest mining is instant: `createwallet w; getnewaddress; generatetoaddress N addr`. Use `-mocktime` to control the clock.

## STRICT SAFETY (violating = critical failure)
- NEVER touch the production node: systemd `btxd.service`, datadir `/home/administrator/.btx`, binaries in `/home/administrator/.local/bin`.
- NEVER touch containers/images named `pf3-*`, `bft-*`, `evx*`, `btxn*`, or anything you didn't create.
- Operate ONLY in regtest, in your own `<agent-id>-` namespace; temp under `/tmp/<agent-id>/`.
- Limit build parallelism (you share 32 cores with other agents). Clean up all your containers/networks/temp on exit.

## Findings file template
```
# <agent-id> — <topic>
## Vectors attempted
- <name>: <method, exact steps/commands>
  RESULT: ACCEPTED / REJECTED(reason) / CRASH / NO-EFFECT  — <evidence/numbers>
## NEW / unmitigated findings
- <title> | severity crit/high/med/low | repro: <minimal steps> | proposed mitigation: <idea>
## Refuted / robust (so others don't repeat)
- <attack> — why it does not work (evidence)
## Open questions / leads for next wave
- <lead>
```
