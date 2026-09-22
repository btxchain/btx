# src/modelnet

Implementation of the Native Model Network helper library (`bitcoin_modelnet`)
and the `btx-modeld` / `btx-modelcheck` / `btx-open` binaries.

Operator and researcher documentation lives in [doc/modelnet/](../../doc/modelnet/README.md):

- [architecture.md](../../doc/modelnet/architecture.md)
- [rpc.md](../../doc/modelnet/rpc.md) — JSON-RPC (also `btx-cli help`)
- [generate.md](../../doc/modelnet/generate.md) — host-profile local generate
- [http.md](../../doc/modelnet/http.md) — PQ1 `/btx-model/2/` peer API
- [economics.md](../../doc/modelnet/economics.md)

Library sources include `generate.cpp` (`generatemodel` /
`getmodelhostprofile`). This plane does not change ExactReplay, fork choice,
issuance, or BanMan. Inference is local after acquire (`generatemodel` when
the replica matches this host; CUDA smoke is not generate). Automatic spend
default is 0. Demand-seed is the default once a storage budget is allocated
(v1.1 D11).
