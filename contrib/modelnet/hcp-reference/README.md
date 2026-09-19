# Offline reference kit

`contracts.py` models canonical body hashing, conservative parsing, amount arithmetic and handoff binding. `simulator.py` models selected financial states with a process-local lock. `demo.py` shows a lost-response retry using the same simulated transaction reference. `adapter_contracts.py` sketches integration seams; its production signer always refuses. `sdk.py` and `sdk.ts` demonstrate retry-safe typed client patterns through a caller-supplied authenticated transport.

This code does not implement OAuth, DPoP, ML-DSA, native consensus, native spending, production double-entry persistence, multi-replica fencing, a web portal, runtime loading or any live CEX connection. A per-process lock is not a production ledger. It is intentionally not a turnkey production deployment.

Run from the package root:

```bash
python -m reference.demo
python -m unittest discover -s tests -p test_reference.py -v
```

The production implementation assignment requires those real integrations. Its conformance ledger remains NOT_RUN until exercised against the integrated private system.
