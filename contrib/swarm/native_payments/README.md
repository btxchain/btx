# Native payment recovery

`watchtower.py` is a bounded owner-presigned SHA-256 HTLC refund recovery tool for
isolated BTX regtest. It uses the native `getmodelfundingsettlement` RPC added by
this patch. It never signs a transaction or accepts a peer's settlement flag.

The implementation and exact scope are documented in
[`doc/modelnet/swarm/20_NATIVE_PAYMENT_INTEGRATION.md`](../../../doc/modelnet/swarm/20_NATIVE_PAYMENT_INTEGRATION.md).

Run component tests with:

```sh
python3 -m unittest discover -s contrib/swarm/native_payments/tests -v
```

Run `test/functional/feature_swarm_funded_objective.py` against the rebuilt node
for actual native funding, claim, reorg, refund and recovery evidence. The
component tests use an injected node fixture and are not native qualification.
