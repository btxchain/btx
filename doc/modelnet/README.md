# BTX Native Model Network (0.34.7)

**A BTX node already has compute. BTX gives it models and money.**

The canonical share form is `btx://<resource-token>`. The client resolves it,
retrieves it **free where possible**, verifies it, and makes it available for
**local** use. Optional BTX payments settle scarce delivery or public
release. They are not an admission charge to research participation, not a
remote-inference tariff, and not a consensus privilege.

This is **not** a remote inference marketplace. There is no inference seller,
inference endpoint, inference tariff, or cloud fallback. A model that does
not fit the local device yields an explicit compatibility result, not a
paid remote run.

## Authority

**Start with the v1.1 root addendum**, then this directory. This README
is an in-tree operator index (addendum §13.2), not a replacement for the
specification and not a rewrite of B0.

| Document | Role |
|---|---|
| **Root addendum** `BTX_Model_Network_v1.1_Root_Addendum.md` (`BTX-SPEC-0347-MODELNET-ROOT-1.1`, v1.1.1) | **Entry point.** §1.3 overrides win. Packaged with the 1.1 spec, not copied into this tree. |
| **B0** `BTX_0.34.7_PQ_Native_Model_Network_Specification.md` (`BTX-SPEC-0347-MODELS-PQ` rev **2.0**) | Unchanged baseline. Actual ID/revision as locked; “base 1.0” is only the dependency label. **Do not rewrite B0 bytes.** |
| Operator override | Reuse 0.34.6 `htlc_sha256` / `buildhtlcclaim` / `buildhtlcrefund`. Do **not** add `htlc_sha256_tx`. |

B0 SHA-384 (two lines concatenate with no whitespace):

```text
dcc94d534964bca13fccb9a87c2b78808608d0a6bdcf3a72d3c22203bee5cb4b
a8039f650a05e25730ec55c24c285e1c
```

**Precedence:** explicit 1.1 overrides, then B0. Conversation drafts have no
authority. D01: local use is the end of acquisition; paid/remote inference
is removed from the product language, not deferred.

This tree reports partial features through a **capabilities** object. Those
bits are **not** a substitute for `planning/acceptance-matrix.csv`. That file
is the packaged production bar: **PASS** only where this tree has a Boost
test or e2e script. Qt Models-first pages ship in `src/qt` (`btx:`
never enters the payment parser). `btx-qt` needs Qt 6 headers in the same
compile tree. CLI / `btx-modeld` / `btx-open` remain the no-Qt surfaces.

Truncated explanatory URIs (`btx://…`) in these pages are **placeholders**.
Complete format vectors are in the spec package `examples/resource-uris.txt`.

## Product contract

| Participant | Immediate useful activity | Not required |
|---|---|---|
| Researcher | Download an immutable model, keep a reproducibility reference, use it locally | Coins, mining, public identity, public upload |
| Community member | Capped disk/egress for selected collections | A GPU, a paid plan, a storage token |
| Lab / publisher | Signed collections and exact checkpoints | A BTX-operated account |
| Router operator | Introduce hosts; resolve signed records | Monetary validation or payload storage |
| Commercial mirror | Optional paid delivery where free supply is insufficient | Influence over free ranking, consensus, or collection policy |

Fresh-install defaults: payload storage **0**, automatic spending **0**,
runtime execution **off**. Unsolicited fetch of arbitrary advertised models
is **off**. After the operator allocates a storage budget, **demand-seed is
the default** (`-modelseed=auto`): an intentional import or `getmodel`
retains and re-advertises that qualified public model inside the budget.
Preserve-rare (fetch under-replicated models into spare space) is explicit.
See [propagation.md](propagation.md).

## Architecture (two processes)

```
  researcher / CLI / btx-qt
           |  unix JSON-RPC (fail-closed if helper down)
           v
      btx-modeld                 btxd (monetary)
      catalog, pieces, PQ1      ExactReplay, mempool, wallet
      /btx-model/2/              sendmodels hints only
           |                     |
           +-- never BanMan, AddrMan, cs_main, fork choice, issuance
```

- `btxd` — monetary node. Optional `-modelnet` introduction bridge. Model
  methods proxy to the helper; they do not execute models.
- `btx-modeld` — isolated helper. Strict **PQ1** or fail closed. If this
  process dies, monetary BTX stays up.
- `btx-modelcheck` — header-only SafeTensors/GGUF structure check. Never
  executes pickle, `.pt`, Python, `.so`, or CUDA kernels.
- `btx-open` — preview-only URI dispatcher (exactly one argument, no shell).

Build with `-DWITH_MODELNET=ON` (default). A monetary-only binary uses
`-DWITH_MODELNET=OFF`. That OFF tree is money only: no `bitcoin_modelnet`
library, no `btx-modeld` / `btx-modelcheck` / `btx-open`, and no model-plane
args or RPCs in `btxd`. Prove it without configuring a second cmake tree:

```bash
contrib/modelnet/check-with-modelnet-off.sh
```

The script grep-checks that `src/modelnet/CMakeLists.txt` returns immediately
when `WITH_MODELNET` is off, that `src/init.cpp` and `src/rpc/modelnet.cpp`
wrap model-plane code in `#ifdef ENABLE_MODELNET` (the `#cmakedefine` from
`cmake/bitcoin-build-config.h.in`), and compiles a throwaway translation unit
with `ENABLE_MODELNET` unset so those guarded excerpts are dropped.

## Economic framework (free-first, market-second)

Default retrieval mode is **`FREE_ONLY`**. Automatic BTX spend is **zero**.

| Mode | Behavior |
|---|---|
| `FREE_ONLY` | Zero-price grants only. Never becomes paid because a deadline expires. |
| `FREE_FIRST_APPROVAL` | Keep free work; a marginal paid plan needs a fresh exact quote. |
| `FREE_FIRST_BUDGET` | Automate only under a preapproved finite budget. |
| `EXPLICIT_PAID` | User deliberately selects a paid provider. |

There are **no** protocol emissions for hosting, no rewards for advertised
capacity, no compulsory staking, and no privileged release-pool commission.
Providers are paid by buyers or voluntary sponsors in ordinary BTX.
Hosting revenue is storage/egress, not GPU mining, and must not be
scheduled as if serving files consumed the ExactReplay GPU.

HTLC success proves a 32-byte preimage was revealed. It does **not** prove
the model is useful, safe, aligned, or the file the publisher described.

Paid **wallet funding** RPCs freeze an exact `htlc_sha256` round
(`preparemodelfunding` / `signmodelfunding` / `submitmodelfunding`).
`buildmodelhtlcclaim` / `buildmodelhtlcrefund` build unsigned 0.34.6
SHA-256 templates. HASH160 `htlc_tx` is recovery-only. Automatic spend is 0.
`capabilities.paid_retrieval=true` with `paid_chain_verify=false`.

## What this tree actually implements

Honest capabilities (`getmodelnetworkinfo` → `capabilities`):

| Capability | In this tree |
|---|---|
| Compact `btx://` URI, decode/encode | yes |
| Streaming import, 4 MiB pieces, SHA-384, chunk proofs | yes |
| Structure qualification (SafeTensors/GGUF) | yes |
| `FREE_ONLY` retrieve over PQ1 `/hello`, manifests, pieces | yes (octet-stream piece body) |
| Seed / pin / list / manifest | yes |
| `btx-open` preview | yes |
| Paid retrieve, quotes, campaign RPCs | **quotes + campaign objects yes**; helper `preparemodelfunding` / `sign` / `submit` / `buildmodelhtlcclaim` implemented (no auto-spend; `paid_chain_verify=false`) |
| CUDA qualification | **isolated worker** (`BTX_CUDA_QUAL_WORKER`); default `-modelruntimecheck=0` is `NOT_RUN_CUDA_ISOLATION`; capability `cuda_qualification=true` for the worker path |
| Browser bridge | **false** (optional, never native PQ fallback) |
| Remote inference | **false** — removed from the roadmap (v1.1 D01) |
| Worker pool / connection ceilings / cert pin | yes (8/32 workers/queue; 16 inbound; 8 outbound; 2/netgroup; TOFU SPKI pin) |

In-tree capability bits are not CSV PASS and not a B0 rewrite. The bar is
[planning/acceptance-matrix.csv](../../planning/acceptance-matrix.csv).

## Docs in this directory

| File | Topic |
|---|---|
| [howto.md](howto.md) | **How to test and use** every hosting scenario (fail-fast) |
| [architecture.md](architecture.md) | Process split, sockets, data dirs |
| [economics.md](economics.md) | What is paid, what is not, metrics |
| [free-first-policy.md](free-first-policy.md) | Retrieval modes and planner |
| [reciprocity-v1.1.md](reciprocity-v1.1.md) | Local observed-service accounting |
| [resource-uri-v1.md](resource-uri-v1.md) | `btx://` Bech32m token |
| [pq-transport.md](pq-transport.md) | Strict PQ1 TLS |
| [htlc-reuse.md](htlc-reuse.md) | 0.34.6 HTLC reuse |
| [isolation.md](isolation.md) | Monetary / model plane boundary |
| [research-identities.md](research-identities.md) | ML-DSA identities, not wallet keys |
| [model-access-policy.md](model-access-policy.md) | ACL never BanMan |
| [collections-and-circles.md](collections-and-circles.md) | Signed community objects |
| [community-router.md](community-router.md) | CPU introducers, not consensus |
| [web-bridge-boundary.md](web-bridge-boundary.md) | Optional browser edge |
| [propagation.md](propagation.md) | Demand-seed default, preserve-rare, release (D11) |
| [rpc.md](rpc.md) | JSON-RPC catalogue — includes search/directory/indexer methods |
| [../bounties.md](../bounties.md) | Model bounties lifecycle, escrow, bridge, GUI |
| [../bounty-rpc.md](../bounty-rpc.md) | Bounty RPC names and contracts |
| [http.md](http.md) | PQ1 `/btx-model/2/` peer API |
| [swarm.md](swarm.md) | Rarest-first swarm, endgame, partial serve |
| [connectivity.md](connectivity.md) | NAT, relay, hole punch, provider routing |
| [reachability.md](reachability.md) | AutoNAT-style dial-back, host advertisement |
| [relay.md](relay.md) | Bounded model relay, PQ1 through-forward |
| [hole-punching.md](hole-punching.md) | DCUtR-inspired direct upgrade |
| [provider-routing.md](provider-routing.md) | Signed provider records, not a generic DHT |
| [search.md](search.md) | Search vs identity vs availability vs trust; `ModelSearchRecord`; query privacy |
| [directory.md](directory.md) | Observed directory entries, swarm health, reconstructability |
| [indexers.md](indexers.md) | Optional `NODE_MODEL_INDEX` explorers; import/export |
| [bootstrap.md](bootstrap.md) | Introduction only; survive bootstrap loss |
| [network-roaming.md](network-roaming.md) | Address/sleep epochs |
| [connectivity-test-lab.md](connectivity-test-lab.md) | Namespace NAT lab |
| [cuda-not-run.md](cuda-not-run.md) | Isolated CUDA worker; default runtime check is NOT_RUN_CUDA_ISOLATION |
| [examples.md](examples.md) | DOC-01 executable CLI examples |
| [recovery.md](recovery.md) | DOC-03 helper / campaign / HTLC recovery |

Reference codecs and schema checks: [contrib/modelnet/](../../contrib/modelnet/README.md).
`contrib/modelnet/validate-doc-examples.sh` runs the examples. Dependency pin:
`contrib/modelnet/dependency-lock.md` (DOC-02; not an SPDX dump, not CSV PASS).
