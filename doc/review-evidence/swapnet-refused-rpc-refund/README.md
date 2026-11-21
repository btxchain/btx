# Refused Bitcoin connection: original BTX refund recovery

Qualified on macOS ARM64, Python 3.12.14 / pytest 8.4.2, against release-0.34.17 `1e2f8b5f12295002334d3390c12cac0bb4ae2aff`. **Real LocalRPC and coordinator/SQLite reopen; BTX/BTC chains and signing simulated.**

A retained valid Bitcoin cookie plus a refused loopback RPC connection leaves an otherwise eligible original mature BTX refund blocked. Missing-cookie recovery already exists. The fix distinguishes actual connection refusal internally, keeps public `RPC_UNAVAILABLE`, and invokes the unchanged local-refund helper. Authentication, malformed responses, timeouts and generic unavailable errors do not gain recovery authority.

## Executed results

| Check | Stock | Candidate |
| --- | --- | --- |
| Same 28-case recovery/error suite | 2 expected failures, 26 passes; 5.02s | 28 passes; 5.01s |
| Additional controls and ordinary settlement/restart | Not rerun for this auxiliary selection | 7 passes; 1.97s |

Stock failures are the actual refused-connection recovery assertion and the internal classification assertion. Candidate reuses the original durable refund through reopen, confirmation and another reopen, with identical operation IDs, transaction IDs and raw bytes and no new funding. Both missing-cookie and refused-connection positive paths execute. See [before](before.log), [after](after.log), [additional controls](controls.log), [hash manifest](MANIFEST.json).

Refusals cover maturity, incoming funding reference, exposed secret, prior conflict, missing recovery record/readiness, local terms/canonical state/confirmations, stale clock, saved funding reference, spent output, current tip and script. Actual HTTP authentication, invalid JSON, chain rejection, response-ID/result and redirect errors remain excluded. Injected timeout/reset/untyped reason and read timeout remain generic. Additional checks execute the existing observation-only routine, normal two-party settlement and restart without double funding. The entire original refund helper and drivers are unchanged.

## Reproduction

Dependencies: Python 3.12, pytest, cryptography. Maintained tests reuse `test_execution_v2.Pair`. The original executed launchers selected these exact files/cases with the candidate or stock package at the front of sys.path and isolated temporary directories. Existing runtime/dependencies were reused; no node build occurred.

Equivalent checkout recipe (not the exact original launcher):

```sh
PYTHONPATH=contrib/swapnet python3 -m pytest -q \
  contrib/swapnet/tests/test_refused_connection_recovery.py \
  contrib/swapnet/tests/test_refused_connection_controls.py \
  contrib/swapnet/tests/test_execution_v2.py::test_full_two_party_settlement \
  contrib/swapnet/tests/test_execution_v2.py::test_restart_each_phase_no_double_funding
```

For stock comparison, retain the same new tests and restore only the three changed production files to the named base. The two documented failures are expected; candidate selection totals 35 passes.

## Limits and fixture correction

An initial bound-but-not-listening Darwin socket timed out; it was incorrectly described as refusing. That pilot did not qualify the repair. The final matched fixture uses a closed port and explicitly verifies `URLError.reason` is `ConnectionRefusedError` before testing the coordinator. Port reuse fails the precondition rather than being accepted as refusal. No product error classification was broadened to make the pilot pass.

No native Bitcoin/BTX daemon, real signing, embedded-helper integration, Windows/Linux execution, live-chain, timeout recovery or release qualification is claimed. Local clocks and UTXO/script values are fixture data; HTTP is a protocol responder. The repair adds no signing, funding, deadline or permission rule and preserves every existing helper fence. Internal bounded source/evidence review found no remaining blocker; this is not an independent native-platform ACK.
