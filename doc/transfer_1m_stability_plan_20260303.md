# 1M BTX Migration Stabilization Plan (2026-03-03)

## Goal
Complete the 1,000,000 BTX migration to 8 destinations (125,000 each) with deterministic behavior, restart safety, and reproducible review artifacts.

## Observed Failure Modes
1. Deterministic policy rejection: `bad-txns-too-many-sigops` for oversized input batches.
2. Expensive full-wave retries: 8-lane runs launched before validating current sigops/input envelope.
3. Runtime drift risk: source edits not always guaranteed to match running binaries/scripts.
4. Low reviewability of ops logic: active transfer scripts currently live under a git-ignored runtime path.

## Execution Plan (Gate-Based)
1. **Code/Binary Integrity Gate**
   - Require fresh build before supervisor start.
   - Abort startup if `src/script/sign.cpp` or `src/wallet/wallet.cpp` is newer than `btxd`.
2. **Sigops Admission Gate (Canary)**
   - Before every new full run-root, execute a single-lane, single-job canary.
   - If canary fails with sigops policy, decrement `MAX_INPUTS` override and restart node.
   - Only launch full 8-lane wave after canary success.
3. **Main Transfer Gate**
   - Launch 8-lane run with current validated `MAX_INPUTS`.
   - Persist per-run logs, done ledger, and failures for postmortem and resume.
4. **Hang/Recovery Gate**
   - Continue watchdog checks (`walletprocesspsbt` load, RPC age, stagnation, CPU).
   - Force restart only on explicit failure/hang criteria; avoid productive-wave false positives.
5. **Completion Gate**
   - Verify destination aggregate >= 1,000,000 BTX.
   - Verify miner sidecar remains active and coordinator continues normal mining flow.

## Acceptance Criteria
- No repeated full-wave sigops failures once canary has passed.
- Sustained progression in `done.csv` and destination totals.
- Clean recovery from interruptions without losing completed work.
- Review branch includes all core node code changes and this plan document.

## Notes
- Active runtime transfer scripts are currently under `/runtime/tx-migrations`, which is ignored by the top-level repo. They should be moved into a tracked ops path in a follow-up if full script-level code review is required directly in Git.
