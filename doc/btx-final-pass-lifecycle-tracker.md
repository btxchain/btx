# BTX Final Pass Lifecycle Tracker (macOS + CentOS + Bridge)

Last updated: 2026-02-20  
Owner branch: `codex/apple-metal-strict-readiness-fix-20260220`  
Scope: startup, wallet creation, mining, block verification, mining rewards, send/receive, wallet locking, cross-platform bridging.

## Milestones

| Milestone | Task List | Acceptance Criteria | Dependencies | Current Status |
|---|---|---|---|---|
| M15-1 | Define final-pass lifecycle matrix and artifact contract | Matrix explicitly includes macOS host, CentOS container, and macOS↔CentOS bridge lifecycles | Existing M13 interop harness, build outputs | Completed |
| M15-2 | Add fail-first TDD coverage for matrix runner behavior | New util test fails before implementation and passes after implementation with pass/fail scenarios | `test/util` harness conventions | Completed |
| M15-3 | Implement strict single-node lifecycle validator | Script validates startup, wallet creation, mining, block verification, lock/unlock failure paths, send/receive success paths, and emits JSON artifact | `build-btx/bin/btxd`, `build-btx/bin/btx-cli` | Completed |
| M15-4 | Implement full matrix runner (host + container + bridge) | Script runs all three lifecycle checks, emits JSON artifact, and returns non-zero on any failed phase | Docker daemon, CentOS image, M13 script | Completed |
| M15-5 | Integrate new util tests into parallel script test gate | `scripts/test_btx_parallel.sh` schedules and passes `m15_single_node_wallet_lifecycle_test.sh` and `m15_full_lifecycle_matrix_test.sh` | Existing parallel gate scheduler | Completed |
| M15-6 | Run production-grade local lifecycle matrix on this host (real execution, no overrides) | `scripts/m15_full_lifecycle_matrix.sh` returns pass and generates artifacts/logs for all phases | Working Docker + build trees | Completed |
| M15-7 | Update root + node READMEs and docs with exact commands and expected outputs | Both READMEs and supporting docs contain actionable runbook for full lifecycle flows and expected success lines/artifact paths | Completed M15 scripts and validation evidence | Completed |
| M15-8 | Final report and readiness assessment | Report includes completed tasks, exact test/benchmark outputs, blockers, and next actions | M15-1 through M15-7 | Completed |

## Validation Evidence Log

- `2026-02-20`: Fail-first confirmed for missing matrix runner (`m15_full_lifecycle_matrix_test.sh` -> missing script).
- `2026-02-20`: Implemented:
  - `scripts/m15_single_node_wallet_lifecycle.sh`
  - `scripts/m15_full_lifecycle_matrix.sh`
  - `test/util/m15_full_lifecycle_matrix_test.sh`
- `2026-02-20`: TDD pass:
  - `bash test/util/m15_full_lifecycle_matrix_test.sh` -> pass
  - Includes forced-pass and forced-fail artifact assertions.
- `2026-02-20`: Integrated `m15_lifecycle_matrix_tests` into `scripts/test_btx_parallel.sh`.
- `2026-02-20`: Additional fail-first lifecycle depth coverage:
  - fail-first check for missing util test: `bash test/util/m15_single_node_wallet_lifecycle_test.sh` -> missing file (expected)
  - added `test/util/m15_single_node_wallet_lifecycle_test.sh`
  - `bash test/util/m15_single_node_wallet_lifecycle_test.sh` -> pass
  - integrated `m15_single_node_lifecycle_tests` into `scripts/test_btx_parallel.sh`
- `2026-02-20`: Real execution pass (no override hooks):
  - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --artifact /tmp/btx-m15-full-matrix-real.json --log-dir /tmp/btx-m15-full-matrix-logs --timeout-seconds 900 --skip-centos-build`
  - Result: `Overall status: pass`
  - Artifacts:
    - `/tmp/btx-m15-full-matrix-real.json`
    - `/tmp/btx-m15-full-matrix-logs/mac-host-single-node-artifact.json`
    - `/Users/admin/Documents/btxchain/btx-node/.btx-validation/m15-centos-container-single-node-artifact.json`
    - `/tmp/btx-m15-full-matrix-logs/mac-centos-bridge-artifact.json`
- `2026-02-20`: Documentation coverage completed:
  - `/Users/admin/Documents/btxchain/README.md`
  - `/Users/admin/Documents/btxchain/btx-node/README.md`
  - `/Users/admin/Documents/btxchain/btx-node/doc/m15-full-lifecycle-runbook.md`
  - Added docs gate: `test/util/m15_docs_sync_test.sh` and integrated into `scripts/test_btx_parallel.sh`.
- `2026-02-20`: Post-update gates re-run:
  - `bash test/util/m15_full_lifecycle_matrix_test.sh` -> pass
  - `bash test/util/m15_docs_sync_test.sh` -> pass
  - `BTX_PARALLEL_SKIP_RECURSIVE_JOBS=1 scripts/test_btx_parallel.sh build-btx` -> pass
- `2026-02-20`: Additional continuous-validation cycle (post-`fe140f59e5`):
  - `bash test/util/m15_single_node_wallet_lifecycle_test.sh` -> pass
  - `bash test/util/m15_full_lifecycle_matrix_test.sh` -> pass
  - real execution pass (no override hooks):
    - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --artifact /tmp/btx-m15-full-matrix-real-20260220-cycle2.json --log-dir /tmp/btx-m15-full-matrix-logs-cycle2 --timeout-seconds 900 --skip-centos-build`
    - Result: `Overall status: pass`
    - Artifact: `/tmp/btx-m15-full-matrix-real-20260220-cycle2.json`
    - Logs: `/tmp/btx-m15-full-matrix-logs-cycle2`
- `2026-02-20`: CI monitoring checkpoint for current head `fe140f59e536f999a67c208ccf8bcd2653fc2cba`:
  - `22214840011` (`CI`, pull_request): `in_progress`
  - `22214840010` (`BTX Readiness CI`, pull_request): `in_progress`
  - `22214839261` (`BTX Readiness CI`, push): `in_progress`
  - `22214839259` (`CI`, push): `in_progress`
- `2026-02-20`: Documentation hardening cycle (fail-first TDD):
  - strengthened `test/util/m15_docs_sync_test.sh` with explicit checks for:
    - parent README single-node lifecycle command and expected output lines
    - parent/node README `Overall status: pass` expectations
    - runbook bridge and triage sections
  - fail-first result before doc update:
    - `bash test/util/m15_docs_sync_test.sh` -> fail (expected)
  - docs update:
    - `/Users/admin/Documents/btxchain/README.md` now includes single-node lifecycle command and expected output lines
  - post-fix validation:
    - `bash test/util/m15_docs_sync_test.sh` -> pass
    - `bash test/util/m15_single_node_wallet_lifecycle_test.sh` -> pass
    - `bash test/util/m15_full_lifecycle_matrix_test.sh` -> pass
- `2026-02-20`: No-skip artifact schema hardening cycle (fail-first TDD):
  - updated util tests first:
    - `test/util/m15_single_node_wallet_lifecycle_test.sh` now requires:
      - `"skipped_steps": []`
      - `"phase_coverage"` for all single-node lifecycle phases
    - `test/util/m15_full_lifecycle_matrix_test.sh` now requires:
      - `"skipped_phases": []`
      - `"phase_coverage"` map matching lifecycle check statuses
  - fail-first results (expected):
    - `bash test/util/m15_single_node_wallet_lifecycle_test.sh` -> `KeyError: 'skipped_steps'`
    - `bash test/util/m15_full_lifecycle_matrix_test.sh` -> `KeyError: 'skipped_phases'`
  - implemented minimal schema updates:
    - `scripts/m15_single_node_wallet_lifecycle.sh` now emits `skipped_steps` + `phase_coverage`
    - `scripts/m15_full_lifecycle_matrix.sh` now emits `skipped_phases` + `phase_coverage`
  - runbook sync:
    - `doc/m15-full-lifecycle-runbook.md` now documents `skipped_steps`/`skipped_phases` artifact expectations
  - post-fix validation:
    - `bash test/util/m15_docs_sync_test.sh` -> pass
    - `bash test/util/m15_single_node_wallet_lifecycle_test.sh` -> pass
    - `bash test/util/m15_full_lifecycle_matrix_test.sh` -> pass
    - `BTX_PARALLEL_SKIP_RECURSIVE_JOBS=1 scripts/test_btx_parallel.sh build-btx` -> pass
    - real execution pass (no override hooks):
      - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --artifact /tmp/btx-m15-full-matrix-real-20260220-cycle4.json --log-dir /tmp/btx-m15-full-matrix-logs-cycle4 --timeout-seconds 900 --skip-centos-build`
      - Result: `Overall status: pass`
      - Artifact includes `"skipped_phases": []` and pass `phase_coverage` for all matrix checks
- `2026-02-20`: Parent README no-skip artifact documentation sync (fail-first TDD):
  - strengthened `test/util/m15_docs_sync_test.sh` to require parent README mentions:
    - `"skipped_steps": []`
    - `"skipped_phases": []`
  - fail-first result before docs update:
    - `bash test/util/m15_docs_sync_test.sh` -> fail (expected)
  - docs update:
    - `/Users/admin/Documents/btxchain/README.md` now includes lifecycle artifact no-skip highlights for:
      - `/tmp/btx-m15-single-node.json`
      - `/tmp/btx-m15-full-matrix.json`
  - post-fix validation:
    - `bash test/util/m15_docs_sync_test.sh` -> pass
    - `bash test/util/m15_single_node_wallet_lifecycle_test.sh` -> pass
    - `bash test/util/m15_full_lifecycle_matrix_test.sh` -> pass
    - `BTX_PARALLEL_SKIP_RECURSIVE_JOBS=1 scripts/test_btx_parallel.sh build-btx` -> pass
    - real execution pass (no override hooks):
      - `scripts/m15_full_lifecycle_matrix.sh --build-dir build-btx --centos-build-dir build-btx-centos --artifact /tmp/btx-m15-full-matrix-real-20260220-cycle5.json --log-dir /tmp/btx-m15-full-matrix-logs-cycle5 --timeout-seconds 900 --skip-centos-build`
      - Result: `Overall status: pass`

## Open Items (must be closed before sign-off)

1. None.
