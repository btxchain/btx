# Researcher quickstart

Standalone entry for the zero-wallet path (root addendum §2, §11.4, §13.2).
Inference is **local after acquisition**. This path needs **no wallet, no
coins, no mining, and no chain sync** if you run `btx-modeld` alone.
People: [first-run.md](first-run.md). Agents: [agent-recipes.md](agent-recipes.md).

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

## 3. Doctor, then host (pin + publish + seed)

First helper start creates `identities.json` (ML-DSA research publisher and
a secret under `tls/`). You do not call `createmodelidentity` first. That
identity is **not** a wallet key.

```bash
build/bin/btx-modeld \
  -modeldir=./modelnet-data \
  -modelstorage=auto \
  -modelbind=127.0.0.1:29447 \
  -modelhost
```

Unix RPC (one JSON line). Doctor first, then host. `hostmodel` is the
happy-path alias of `importmodel` (pin + signed search card + demand-seed):

```json
{"jsonrpc":"1.0","id":1,"method":"checkmodelsetup","params":[]}
{"jsonrpc":"1.0","id":1,"method":"hostmodel","params":["/path/to/dir"]}
{"jsonrpc":"1.0","id":1,"method":"showmodel","params":["alias-or-btx://"]}
{"jsonrpc":"1.0","id":1,"method":"exportmodellink","params":["alias-or-btx://"]}
{"jsonrpc":"1.0","id":1,"method":"unhostmodel","params":["alias-or-btx://"]}
{"jsonrpc":"1.0","id":1,"method":"importmodel","params":["/path/to/dir"]}
```

Read-only inspect before or after hosting (no fetch, no runtime):
`getmodelmanifest` (per-file `path`/`role`/`size`/`sha384`),
`qualifymodel` (static structure check of a local path), and `listmodels`
filtered by `pinned`/`seeded`. `exportmodelpath` reports the verified local
store root and source path (`hf download --local-dir` analog). CLI:
`btx-model files` / `path` / `check` / `pins`. `btx-model ls --incomplete`
is the huggingface-cli resume analog (this node's downloads only; resume
is still an explicit `pull` / `getmodel FREE_ONLY`). `btx-model bounty-draft
--validate` is the Gitcoin checklist (`validatebountyterms`); it never
publishes and never spends.

`searchmodels` filters (`format`, `quantization`, `family`, `architecture`,
`min_size_bytes` / `max_size_bytes`, `min_provider_count`, `pinned`, `seeded`)
are named on the CLI, e.g.
`btx-model search --format gguf --max-size-bytes 8000000000 --sort size_asc`.
`--fits` keeps only hits inside this node's remaining storage quota. It is
storage only: BTX does not run inference, so it is not a RAM/VRAM claim.

Defaults: `pin=true`, `publish=true` (signed search card; family / format /
quantization inferred from filenames). Pass `{"publish":false}` to skip the
card. The result includes `share` (`uri`, `copy_text`, …) and
`next_actions`. Unix RPC waits up to 24h for large imports (`importmodel` /
`hostmodel` / `getmodel` / `waitformodelevent` / `scanmodelwatch`); other helper
methods use a 120s reply timeout.

Then `getmodel` / `listmodels` / `getmodeltransfers`. With `-modelseed=auto`
(the default once quota is positive) the hosted model is **already seeded**;
`seedmodel` is only required for `-modelseed=manual`. Packaged /
`-modelstorage=auto` allocates a bounded budget. `-modelstorage=0` stores no
payload; import refuses until quota is positive (`auto`, `80GiB`, or raw
bytes).

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
