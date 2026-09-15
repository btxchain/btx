# New v1.1 reference checks

A BTX node already has compute; BTX gives it models and money — inference is
local after acquire, not a remote inference marketplace.

Run `python -m unittest -v test_v11` in this directory. Standard Python 3.10+ is sufficient.

`reference_v11.py` implements the specified compact URI wrapper, canonical extension-body codec, domain hashes and small local-policy examples. `record-layouts.json` is a machine-readable ordered field register. `test_v11.py` checks these examples, including every single-symbol mutation of one 85-character token.

There is no PQ signing/verification implementation, socket transport, wallet, mining logic, OS URI registration or production scheduler here. Synthetic keys/roots are format fixtures. These tests do NOT establish BTX production interoperability, storage independence, global fairness or cryptographic security. Production criteria remain NOT_RUN in the separate acceptance matrix.

The copied `baseline/reference/` and `baseline/evidence/` belong to the prior package and are not re-executed or relabeled as new evidence.

`check_schemas.py` additionally requires Python's `jsonschema` package and reproduces the separate 40-check schema/fixture report. It is a development check, not a dependency proposed for the BTX node. The canonical codec and its 57 test methods use the standard library only.

The reciprocal-ledger and lane functions are small explanatory examples, not a bounded persistent production database. Implementations must add the root document's durability, quotas, expiry, monotonic time and crash-recovery requirements. No test of these examples certifies a live scheduler.
