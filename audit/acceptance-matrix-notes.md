# Acceptance matrix 0.34.8 — status vocabulary and reproduction

Companion to `audit/acceptance-matrix-0.34.8.csv`. Restamped 2026-09-17 against tree
`/home/administrator/btx-0.34.7-private`, branch `feat/0.34.8-modelnet-first-run`,
`build-gcc13` (Release, GCC 13, `WITH_MODELNET=ON`, `BUILD_GUI=OFF`).
No compile was performed for this restamp; the already-built `test_btx`, `btxd`, and
`btx-modeld` were executed as-is.

## Status vocabulary

| Status | Bar |
|---|---|
| `PASS` | `evidence_path` is executable and was executed. Native rows name the Boost case so a reviewer can re-run exactly that case. Process rows name the functional script. Log rows name the script that regenerates the log. |
| `FAIL` | An executed run contradicted the row. **No row is FAIL** in this matrix. |
| `NOT_RUN` | Never executed. The `reason` states the specific blocker (missing binary, missing lab, disk, policy, or absent authorization) — not a vague word. |
| `DEFERRED_WITH_EVIDENCE` | The behaviour is deliberately not shipped. The `reason` gives the design rationale and `evidence_path` points at the code plus the test that pins the shipped disposition. |

Counts: **34 PASS / 0 FAIL / 27 NOT_RUN / 4 DEFERRED_WITH_EVIDENCE** (65 rows).

## Reproduction

Native rows. `evidence_path` uses `file.cpp::case_name`; run a case with:

```
./build-gcc13/bin/test_btx --run_test=<suite>/<case>
```

All eight cited suites were re-run together for this restamp:

```
./build-gcc13/bin/test_btx --run_test=modelnet_convergence_tests,modelnet_cloud_tests,\
modelnet_network02_tests,modelnet_network02_import_tests,modelnet_network02_audit_tests,\
modelnet_watch_tests,modelnet_event_tests,modelnet_submandate_tests
```

Result: **118 cases entered, `*** No errors detected`, exit 0.**

Process rows. Run from `build-gcc13/test/functional` (each script is a symlink to
`test/functional`, so the build copy is the source):

```
python3 ./feature_modelnet_0348_ops.py --timeout-factor=1 \
  --configfile=<tree>/build-gcc13/test/config.ini --tmpdir=/tmp/<scratch>
```

Re-run today, all exit 0: `feature_modelnet_0348_ops.py`, `feature_modelnet_0348.py`,
`feature_modelnet_jit_capability.py`, `feature_modelnet_helper.py`.

Loopback swarm row:

```
bash contrib/modelnet/e2e-swarm-live.sh    # rewrites audit/e2e/swam-live.log
```

Re-run 2026-09-17T06:36Z → `e2e-swarm-live: PASS`.

`test_runner.py` was **not** used as the harness: its `create_cache.py` step fails in
this tree (exit 1 after ~5 min). Every functional above uses `setup_clean_chain`, so
running the script directly needs no cache. The `create_cache.py` failure is a
separate defect and is not evidence for or against any row here.

Scratch hygiene: `/tmp/btx-conv37` removed after the runs (`/tmp` is tmpfs).
Disk on `/` unchanged at 165G free.

## Restamps in this pass

| Row | Was | Now | Why |
|---|---|---|---|
| `CONV-37-helper-down` | `NOT_RUN` "would require local btxd; production btxd not used" | `PASS` | The old reason was factually wrong. Four functionals spawn their **own** isolated regtest `btxd` plus a real `btx-modeld`, SIGTERM the helper, and then assert monetary RPC still serves. All four were re-run today and exited 0. Production `btxd` is never involved. |
| `CONV-05-swarm-live` | `PASS` on a log from the 2026-09-16 binary (25 037 120 bytes) | `PASS` on a fresh run | The freeze required a re-run; the log now matches the current `btx-modeld` (26 897 416 bytes). |
| `CONV-13-torrentd` | `NOT_RUN` "OPERATOR_GATED; reverse_bridge_live=false" | `DEFERRED_WITH_EVIDENCE` | The stated flag value was wrong. `n02_healer_and_execute_migration_are_not_stubs` asserts `reverse_bridge_live=true` with `torrentd_process=false`. There is no daemon to isolate because torrentd is NONSHIPPING by design, which is a deferral not an unrun lab. |
| `CONV-10-400gib-io` | `NOT_RUN` "disk 7.9G free" | `NOT_RUN` with current figures | The host now has 165G free. The row still cannot run because 400 GiB exceeds it and policy forbids the write. |
| `CONV-28-ae-100k/1m/10m` | `NOT_RUN` "disk" | `NOT_RUN` with exact blocker | Disk is no longer the binding constraint; the real blocker is that no catalog fixture generator exists at those scales. |
| `CONV-35-delegated` | `NOT_RUN`, reason blank | `NOT_RUN` with exact reason | A blank reason cannot be audited. |
| `CONV-14-local-cloud-cli` | `NOT_RUN` "no CLI e2e this round" | `NOT_RUN` with exact reason | `contrib/modelnet/btx-model` has no `host --storage` flag at all; it exposes `cloud add|test|status` and a local `host <dir>`. The row as titled describes a surface that does not exist. |
| All PASS rows | whole-file `evidence_path` | `file::case` | A file path is not executable evidence for a specific claim; a named Boost case is. |
| `CONV-30`, `V-01`–`V-04`, `V-08`, `CONV-28-ae-1k` | reason blank | reason filled | Same auditability bar. |

`CONV-19-healer`, `CONV-33-cdc`, and `V-07` keep `DEFERRED_WITH_EVIDENCE` with their
rationale spelled out: `setmodelswarmhealer` reports endangered pieces but never
executes repair; `ContentDefinedDedupShipped()` and `CrossTenantDedupAllowed()` both
return `false` so only exact-digest dedup ships; `ReleaseWrapAllowed` refuses over
64 MiB so a streaming wrap is bounded away rather than built.

## Rows that must not become PASS

Not from a grep, an arithmetic result, or a unit test at another scale. Each needs the
operator to run the real lab:

MinIO (`CONV-10-minio`) · GUI build and Qt journeys (`CONV-39-*`) · live Hugging Face
HTTP (`CONV-12-hf-live`, `CONV-15-hf-stream-s3`) · 400 GiB object I/O
(`CONV-10-400gib-io`) · 400 GiB with 1000 downloaders (`CONV-41-stampede`) · 1000 real
clients (`CONV-09-1000-clients`) · `WITH_MODELNET=OFF` second tree
(`CONV-37-modelnet-off`) · ASan UAF (`V-06`).

Adjacent results exist for several of these and are **not** substitutes:
`CONV-09-get-arithmetic` is planner arithmetic and does not cover `CONV-41` or
`CONV-09-1000-clients`; `CONV-10-fakes3` is an in-process fake and does not cover
MinIO; `CONV-18-erasure-stripe` is per-stripe and does not cover `CONV-42-decay`.

## Scope not covered by any PASS row

The matrix contains no multi-node adversarial, WAN, mixed-0.34.7, or 20-peer gossip
PASS. `CLIENT_VERSION_IS_RELEASE` stays `false` and no push, merge, or tag was made.
