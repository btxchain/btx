# src/modelnet

Implementation of the Native Model Network library (`bitcoin_modelnet`).
This tree is **0.35.0rc1**. The process map is
[doc/modelnet/swarm/00_THIS_TREE.md](../../doc/modelnet/swarm/00_THIS_TREE.md).

Programs built from this library include `btx-modeld`, `btx-modelcheck`,
`btx-open`, `btx-capability`, `btx-capabilityd`, `btx-hcpd`, and
`btx-hosted`. `btx-guardd` is built with the node. By default `btxd`
starts `btx-modeld` and the swarm observer in-process. That thread is the
swarm. The hosted gateway, capability tools, and guard are optional.

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
