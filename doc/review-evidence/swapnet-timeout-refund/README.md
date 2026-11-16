# Timeout extension to original BTX refund recovery

**Mac qualification of the timeout extension to PR782**, based on its original head `19e3a8ce5ae8dec78d2a46bfe3bdc11a68eeaf78` (release ancestor `1e2f8b5f12295002334d3390c12cac0bb4ae2aff`). Python3.12.14, pytest8.4.2. Chains/signing remain simulated; this is not native-chain or release qualification.

## Before/after and preserved recovery

| Exact selection | Before (original782) | Candidate |
| --- | --- | --- |
| Same maintained timeout suite | 8 failures / 8 passes,17.10s | 16 passes,30.52s |
| Selected compatibility controls | Reuse original782 evidence for unchanged behavior | 15 passes,5.68s |

The eight expected baseline failures are three automatic-recovery failures (connection, response headers, response body), three internal classification assertions and two guard-path assertions. The last two mean baseline exits with generic unavailable before reaching the intended original-reference/script conflict check; they do not indicate unsafe spending. Candidate reaches the conflict check and refuses those states.

The coordinator automatically broadcasts the original durably prepared refund, preserves exact operation IDs/txids/raw across reopen, reaches refunded while Bitcoin RPC is still timing out, and remains refunded after another reopen and restoration of healthy RPC. No direct private-helper intervention in these repair regressions. One original funding and original refund; no Bitcoin funding, secret exposure or signing again. Audit checks pass.

[Before](before.log), [after](after.log), [compatibility controls](controls.log), [manifest](MANIFEST.json). Original refusal qualification is retained at [the exact original782 commit](https://github.com/sunnyriverr/btx/blob/19e3a8ce5ae8dec78d2a46bfe3bdc11a68eeaf78/doc/review-evidence/swapnet-refused-rpc-refund/README.md); it is historical evidence of that version, not a claim the current full test suite ran.

## Narrow implementation

LocalRPC distinguishes typed timeouts only during request open or normal response read, retaining public RPC_UNAVAILABLE. Coordinator accepts that internal class alongside the existing missing-cookie and782refused-connection cases, then invokes the same original-refund helper. The whole helper and drivers are unchanged. No deadline, permission, maturity, funding, signing or accounting rule changes.

Actual HTTP400/404/500 response bodies that time out remain generic errors, not timeout recovery authority. Cookie errors, HTTP authentication, malformed/invalid data, chain rejection, redirects, resets, untyped reasons and arbitrary generic unavailable errors stay excluded. Timeouts outside transport open/read also stay generic.

Automatic refusal cases: immature local lock, incoming reference, exposed secret, prior foreign conflict, changed original payment reference and changed script. Selected compatibility cases cover real HTTP/auth/data failures, generic/reset/untyped errors, missing-cookie/refused recovery, observation-only behavior, read-timeout classification and normal settlement/restart without double funding. Other unchanged original helper gates reuse previous782qualification. Existing test expectations explicitly move timeout classification to positive tests; no safety assertion was removed.

## What was real, injected or simulated

- **Real on Mac:** HTTP server accepting/authenticating the request, stalling response headers or part of its body; LocalRPC error behavior; production coordinator/SQLite/Journal/Vault and database reopening.
- **Injected in the maintained connection case:** URLError(TimeoutError) at the opener only; real cookie/request/client/coordinator still execute. The injection is removed for the healthy responder. This avoids assuming that a bound non-listening socket times out on every OS.
- **Earlier real Mac connection probe:** bound non-listening socket produced actual connection timeout; same product bytes passed15cases (baseline7fail/8pass), including body stalls. [Probe fixture](mac-probe-fixture.py), [before](mac-probe-before.log), [after](mac-probe-after.log). This is scoped Darwin evidence, not the maintained portable fixture.
- **Simulated throughout:** BTC/BTX chains, signing, local clocks, UTXO/tip/script, refund confirmations and foreign observation/clock wrapper. Healthy Bitcoin RPC is an HTTP fixture; requests are read-only getblockcount.

No native Bitcoin/BTX daemon, Linux/Windows execution, default10s timing, full embedded-helper integration, live-chain or release qualification. Internal bounded source/test review found no remaining blocker after correcting test portability; it is not an independent platform ACK.

## Reproduction

Python3.12, pytest and cryptography required. Tests reuse the existing Pair and funded_pair/wire/identity fixtures. Original executed local launchers selected the exact candidate/before packages first on sys.path with isolated temporary directories. No build or dependency installation.

Equivalent checkout reconstruction command (not the original launcher):

```sh
PYTHONPATH=contrib/swapnet python3 -m pytest -q contrib/swapnet/tests/test_timeout_refund_recovery.py
```

For the matched before comparison, retain the same new regression and restore only the three production files to original782. Baseline failures above are expected. The 15 compatibility cases were a selected invocation of the two original refusal-test files plus normal settlement/restart from test_execution_v2; this was not a full SwapNet test run.
