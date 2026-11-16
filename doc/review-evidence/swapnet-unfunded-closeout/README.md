# Atomic unfunded cancellation and decline recovery

Qualified against release-0.34.17 `1e2f8b5f12295002334d3390c12cac0bb4ae2aff` on macOS ARM64, Python3.12.14, pytest8.4.2. **Actual SQLite/coordinator; chains and signing simulated.**

## Problem and repair

Cancellation and decline previously released their budget reservation before separately saving the terminal session state. A real SQLite abort on that final write left the reservation closed but the session committed/proposed. After reopening without the fault, retry failed RESERVATION_FINAL. Budget was released once; no funds-loss or double-release claim.

The two-file repair uses one Journal transaction for revision validation, safe reservation release, unused-grant revocation and cancelled/rejected save. If an old version already committed release, the guarded recovery finishes the terminal session without touching mandate counters again. Global Store settlement guards, Authority, drivers and the existing verified-responder-refund close helper are unchanged.

## Executed results

| Selection | Stock | Candidate |
| --- | --- | --- |
| Same four atomic rollback/retry and legacy partial-recovery cases | 4 failures,23 deselected,0.46s | All4included in final27pass |
| Final closeout/refusal suite | Only the four core cases selected for stock comparison | 27 passes,2.15s |
| Selected compatibility tests | Existing tests reused | 9 passes,3.60s: 7 distinct existing controls plus2imported-BTC cases also included in final27 |

[Before](before.log), [after](after.log), [compatibility](controls.log), [hashes](MANIFEST.json). Do not count the two imported-BTC cases twice or describe this as a full SwapNet suite.

The same SQLite TEMP trigger aborts the exact cancelled/rejected update. Candidate rolls back release, grant change and session together; reopening removes the trigger and retry closes exactly once. Separate legacy-state tests reconstruct the actual old closed-reservation/nonterminal state and finish it without changing unrelated held or previously used budget. Audit validates; no new operation or funding.

Refusal controls include prepared/funded state, known own-leg payment reference, durable operation, coinlock, consumed grant, funded reservation, wrong owner/peer, stale revision and imported/observation-only payment state. Healthy cancellation works for both roles, including the responder's reverse budget quote. A counterparty reference alone does not prevent a legitimately unfunded responder cancelling. Candidate uses persisted reservation ID/owner and durable evidence, not only caller flags or a misleading quote-ID equality.

Selected existing controls cover ordinary two-party settlement, restart without duplicate funding, missing-counterparty refund, early refund refusal, two rejected-proposal rollback cases and rejected-start rollback. Those results preceded the final own-reference guard; their unaffected call paths and unchanged responder-close helper were reviewed for reuse. Final27includes the reference guard and its legitimate counterpart.

## Reproduction

Dependencies: Python3.12, pytest, cryptography. Maintained `test_atomic_closeout.py` reuses existing `test_execution_v2.Pair`. Original local launchers selected exact stock/candidate packages and isolated temp directories. Equivalent checkout reconstruction recipe (not the original launcher):

```sh
PYTHONPATH=contrib/swapnet python3 -m pytest -q contrib/swapnet/tests/test_atomic_closeout.py
```

For the identical stock comparison, retain the same new test but restore coordinator.py and journal.py to the named base and select `-k 'atomic_rollback_and_retry or legacy_partial_recovery'`. The four failures are expected. The standalone patch has no dependency on777or782.

## Limits

Real: production Store/Journal/Coordinator/Authority, SQLite trigger abort/rollback/reopen, reservation/grant/accounting and audit behavior. Simulated: Pair ledger, chain calls and signing; funded-refusal tests use fixture transactions. No native BTX/Bitcoin, GUI, embedded helper, Linux/Windows execution, concurrent signing matrix, process SIGKILL/power-loss or release qualification. This makes local budget/session closure atomic; peer cancellation notification remains a separate post-commit step.

No native funds, wallets, build or dependency installation used. Internal bounded review challenged design and final source/evidence; it is not an independent native-platform ACK.
