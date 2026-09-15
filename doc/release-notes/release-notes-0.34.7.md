# BTX 0.34.7 — Native Model Network

**Status:** 0.34.7. `CLIENT_VERSION` is **0.34.7** with
`CLIENT_VERSION_IS_RELEASE=true`. The remaining operator step is merge of
PR #156 to `main`.

A BTX node already has compute. 0.34.7 gives it **models and money** on an
isolated plane, including **decentralized model search**, a **model
directory**, a **network model feed**, **release-campaign discovery**,
**campaign funding state in search**, **description/use-case search**,
and a **third-party explorer API**. Inference is **local after
acquisition**. Remote/paid inference is removed from the roadmap (v1.1 D01).

Search is **not** local-only. `searchmodels` default scope is `NETWORK`.
`getmodelfeed` is the preferred newest/campaign/unlocked feed. Peer counts
are this node's observations.

`CLIENT_VERSION` is **0.34.7** with
`CLIENT_VERSION_IS_RELEASE=true`. Fast-start pin is assumeutxo height
**219000** (`dc51220b…`).

CUDA runtime qualification is an **isolated worker** (`cuda_qual_worker`),
never `cudaSetDevice` inside `btxd`. Default `-modelruntimecheck=0` is
`NOT_RUN_CUDA_ISOLATION`.

## What landed in this tree

- Compact `btx://` Bech32m URIs (SHA-384, kinds 0–8)
- Isolated `btx-modeld` / `btx-modelcheck` / `btx-open`
- Strict PQ1 TLS (ML-KEM-768, ML-DSA-44, AES-256-GCM-SHA384)
- Streaming import, 4 MiB verified pieces, free-first retrieve
- Demand-seed default once a storage budget is allocated (D11); unsolicited fetch remains opt-in
- Default automatic spend **0**; paid funding RPCs freeze `htlc_sha256`
- HTLC reuse of 0.34.6 `htlc_sha256` / `buildhtlcclaim` / `buildhtlcrefund`
- Install-and-forget resource governor (`AUTO` default): spare GPU/network/disk
  with yield to foreground AI and ExactReplay. See
  [doc/resource-governor/README.md](../resource-governor/README.md).

## What did not change

- ExactReplay, fork choice, issuance, BanMan, AddrMan
- No new HTLC opcode; HASH160 `htlc_tx` remains recovery-only

## Compatibility

Build: `-DWITH_MODELNET=ON` (default). OpenSSL 3.5+ required for the
helper. See [doc/modelnet/README.md](../modelnet/README.md).

macOS arm64 ships as `macos-arm64-metal`: `-DBTX_ENABLE_METAL=ON`,
static OpenSSL 3.5+, Qt 6 GUI, and every precompiled `.metallib` next to
`libexec/btxd.real`. See [doc/build-osx.md](../build-osx.md) and
[doc/release-process.md](../release-process.md).

## Upgrade notes

`btxd` does not replace a running signer. OpenSSL 3.5.8 is a **second
process** wrap (`contrib/modelnet/relink-openssl-358.sh` →
`build-gcc13/openssl358-second`). Never install over production
`libexec/btxd.real`. Run `btx-modeld` with its own `-modeldir`. Helper crash
leaves monetary BTX up.
