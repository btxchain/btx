# Researcher quickstart

Standalone entry for the zero-wallet path (root addendum §2, §11.4, §13.2).
Inference is **local after acquisition**. This path needs **no wallet, no
coins, no mining, and no chain sync** if you run `btx-modeld` alone.

Qt Models-first pages (first-run GUI, Models tab) are specified in
addendum §2.3 / D10 and are **out of scope** for this tree. Use CLI flags
below. Desktop `btx-qt` is not a documented shipped surface here.

Truncated URIs (`btx://…`) in the command examples are **placeholders**,
not complete tokens. A complete synthetic MODEL format vector (not a
hosted model):

```text
btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25
```

## First-run storage consent

A fresh packaged install participates in the model network with **automatic
bounded storage**. `-modelstorage=0` stores no payload. Financial controls
are not a prerequisite.

- **CLI:** `-modelstorage=auto` (packaged default) or `-modelstorage=80GiB`.
  `-modelseed=auto` demand-seeds after import/getmodel. Preserve-rare stays
  off unless `-modelpreserverare`. Automatic spend stays 0.
- **Keep / pin:** `pinmodel` / `unpinmodel`. Pinned models are never
  automatically evicted.
- **btx-open:** still one URI argument, preview only, never opens the
  wallet. Prints `storage_consent_required=true` when `BTX_MODEL_STORAGE`
  is unset, empty, or zero.

Same methods (`getmodelnetworkinfo`, `listmodels`, …) are on the
restricted local endpoint for CLI. This quickstart does not add a web
UI, MCP, or inference proxy.

## 1. Build

OpenSSL 3.5+ with `MLKEM768` and `mldsa44` is required for PQ1. System
OpenSSL 3.0 cannot host. `-DWITH_MODELNET=ON` is the default.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF -DBUILD_BENCH=OFF
cmake --build build --target btx-modeld btx-modelcheck btx-open
```

## 2. Qualify a file (no execution)

```bash
build/bin/btx-modelcheck /path/to/model.safetensors
```

Pickle / `.pt` / `.py` / `.so` are refused. A `STRUCTURE_VERIFIED` result
is not a claim that the model is useful or safe.

## 3. Import and optionally seed

```bash
build/bin/btx-modeld \
  -modeldir=./modelnet-data \
  -modelcache=85899345920 \
  -modelbind=127.0.0.1:29447 \
  -modelhost
```

Unix RPC (one JSON line):

```json
{"jsonrpc":"1.0","id":1,"method":"importmodel","params":["/path/to/dir",{"pin":true}]}
```

Then `getmodel` / `listmodels`. With `-modelseed=auto` (the default once
quota is positive) the imported model is **already seeded**; `seedmodel` is
only required for `-modelseed=manual`. Default quota is **0**;
import refuses until `-modelstorage` / `-modelcache` is a positive size
(`80GiB` or raw bytes).

## 4. Retrieve free from a peer

On a second helper (no `-modelhost` required):

```json
{"jsonrpc":"1.0","id":1,"method":"addmodelnode","params":["127.0.0.1:29447"]}
{"jsonrpc":"1.0","id":1,"method":"getmodel","params":["btx://…","FREE_ONLY"]}
```

(`btx://…` is a placeholder. Substitute a complete 91-character URI.)

`automatic_spend_atoms` stays 0. Paid modes return `APPROVAL_REQUIRED` in
this tree.

Smoke: `python3 contrib/modelnet/two_helper_retrieve.py build/bin`

Full local suite (fail-fast): `contrib/modelnet/e2e-all.sh`.
Two machines (isolated regtest, not production): `contrib/modelnet/e2e-regtest-two-host.sh`.
How to use and test every scenario: [howto.md](howto.md).

## 5. Open a URI (preview only)

```bash
build/bin/btx-open 'btx://…'   # placeholder: use a complete 91-character URI
```

Exactly one argument. No shell, no inference, no upload, no wallet.

## 6. Use the model locally

Point a **local** runtime at the verified files. BTX does not start that
runtime and does not expose it to the network.
