# Offline reference implementation

The Python module demonstrates capacity arithmetic, exact decimal comparisons, strict canonical JSON, new body IDs, bounded allocation graphs, distinct-person approval and selected transactional hold/uncertainty invariants. SQLite is an executable reference model, not the exchange's financial core.

It does not authenticate OAuth, verify ML-DSA signatures, sign native transactions, evaluate custody title or run a model. Synthetic all-zero example signatures must be rejected by a real verifier. Native testing remains separate.

This directory is **not** `contrib/modelnet/reference` (URI/record codecs). Import `reference.reserve` only after putting this directory on `sys.path`.

```bash
python3 contrib/modelnet/crf-reference/test_reference.py
python3 -m unittest -v contrib.modelnet.crf-reference.test_reference
```

Worked offline checks: capacity `1000/400/250 == 250`, TCO `$600000` vs `$245000`, DAG cycle → `GRAPH_CYCLE`, two sessions of one person do not meet a two-person quorum.
