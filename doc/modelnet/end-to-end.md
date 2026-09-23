# Use BTX for models — host, search, run, bounty

**Status:** 0.34.9-dev. `CLIENT_VERSION_IS_RELEASE=false`. Last shipping tag
is **v0.34.8**. This is the **people** copy-paste path. Agents:
[agent-recipes.md](agent-recipes.md). Generate contract: [generate.md](generate.md).
Bounties: [../bounties.md](../bounties.md). Tests: [howto.md](howto.md).

Nothing here spends BTX. `automatic_spend_atoms` stays **0**. Paid release
or bounty settlement is a later **prepare → sign → submit** wallet path, not
a first-run timer. BTX is **not** a remote inference marketplace.

You need the isolated helper (`btx-modeld`). Packaged `btxd` starts it when
`-modelnet=1` (the default). Standalone: `contrib/modelnet/btx-model init`.
CLI wrapper: [../../contrib/modelnet/btx-model](../../contrib/modelnet/btx-model)
(people: stderr hints; agents: `--json`).

Truncated `btx://…` strings below are **placeholders**. Substitute a complete
token from `btx-model link` / `share.copy_text`.

## 0. Doctor

```bash
contrib/modelnet/btx-model doctor
# or, with packaged btxd supervising the helper:
btx-cli getsetupstatus
btx-cli checkmodelsetup
```

Ask once: can this machine host, and is quota positive? `-modelstorage=0`
stores no payload. Packaged default is `-modelstorage=auto`. Pickle / `.pt`
/ `.py` / `.so` are refused.

## 1. Host a local model

Pin a GGUF or SafeTensors directory (or a single file). Demand-seed is on
once quota is positive; you do **not** need `seedmodel`.

```bash
contrib/modelnet/btx-model host /path/to/model.gguf
# or a SafeTensors checkout:
contrib/modelnet/btx-model host /path/to/safetensors-dir
contrib/modelnet/btx-model ls
contrib/modelnet/btx-model show NAME
```

`hostmodel` is an alias of `importmodel`: pin + signed search card +
demand-seed. A `.btx` file or `copy_text` is a **share card**, not weights:
`btx-model host foo.btx` retrieves `FREE_ONLY`.

## 2. Share it

```bash
contrib/modelnet/btx-model link NAME ./model.btx     # magnet analog; never weights
contrib/modelnet/btx-model share NAME                # uri + copy_text
contrib/modelnet/btx-model open ./model.btx          # preview only
```

Give a peer the `.btx` file or the `btx://` URI. The URI has **no** query
string; display names stay on `copy_text`.

## 3. Search

Default CLI scope is **LOCAL** (this node’s catalog). Network search may be
visible to peers you query.

```bash
contrib/modelnet/btx-model search
contrib/modelnet/btx-model search "coding agent" --scope NETWORK
contrib/modelnet/btx-model search --format gguf --fits --sort size_asc
```

`--fits` is **storage quota**, not RAM/VRAM and not a generate-profile
match. Cards can be public (retrieve now), a release campaign (fund
disclosure), or a bounty (inspect terms first). Peer counts are this node’s
observations, not a census.

RPC / agents:

```json
{"jsonrpc":"1.0","id":1,"method":"searchmodels","params":[]}
{"jsonrpc":"1.0","id":1,"method":"searchmodels","params":[{"text":"coding agent","scope":"NETWORK"}]}
{"jsonrpc":"1.0","id":1,"method":"searchbounties","params":[]}
```

## 4. Retrieve (usually free)

On the same helper, or on a second helper after `addmodelnode`:

```bash
contrib/modelnet/btx-model get NAME
contrib/modelnet/btx-model get ./model.btx
contrib/modelnet/btx-model get 'btx://…'
contrib/modelnet/btx-model ls --incomplete
```

Unix `getmodel` is **async**: first reply is `status=running` + `job_id`.
Poll `getmodeljob` / `ls` until complete. `FREE_ONLY` never becomes paid
because a timer expired. Paid modes return `APPROVAL_REQUIRED` in this tree.

Watch folder: drop GGUF/SafeTensors into `-modelwatch=` and `watch-scan`. A
dropped `.btx` is opened and starts `FREE_ONLY` retrieve (quota applies to
the model, not the card bytes). That folder is **not** a publisher follow.

## 5. Run it locally (checkout, load, generate)

```bash
export BTX_MODEL_GENERATE="$PWD/contrib/modelnet/generate_local.py"
# GGUF only, extra:
# export BTX_LLAMA_CLI=/path/to/llama-cli
# optional GPU hold (SafeTensors; not generate):
# export BTX_MODEL_CUDA_LOADER="$PWD/contrib/modelnet/cuda_safetensors_load"

contrib/modelnet/btx-model path NAME                 # checkout / usable_runtime_root
contrib/modelnet/btx-model host-profile              # what this helper can generate
contrib/modelnet/btx-model load NAME                 # inventory; optional CUDA hold
contrib/modelnet/btx-model generate NAME "Hello" --max-new-tokens 32
contrib/modelnet/btx-model unload NAME               # helper-spawned CUDA loader only
```

Compatible means: **GGUF + llama.cpp**, or **allowlisted SafeTensors +
`BTX_MODEL_GENERATE`**. Unknown architecture, pickle, and missing adapters
fail closed (`INCOMPATIBLE_HOST_PROFILE` / `NOT_RUN`). CUDA `--hold --smoke`
is **not** generate. `trust_remote_code` stays **false**. Prompt ≤ 64 KiB;
`max_new_tokens` 1..512 (default 32). Helper wait for generate is **24h**.

Full contract: [generate.md](generate.md).

## 6. Bounties (create, find, complete)

Search and inspect **before** any spend:

```bash
btx-cli searchbounties
btx-cli getbounty '<bounty_id>'
btx-cli getbountyeconomy '<bounty_id>'
btx-cli getbountyterms '<bounty_id>'
```

Draft terms stay **local and unpublished** until the recipe is complete.
`--validate` is a Gitcoin-style checklist; it never publishes and never
spends.

```bash
contrib/modelnet/btx-model bounty-draft "coding agent"
contrib/modelnet/btx-model bounty-draft @./terms.json
contrib/modelnet/btx-model bounty-draft --validate '<draft_id>'
contrib/modelnet/btx-model bounty-draft --update '<draft_id>' @./terms.json
```

Create → find → complete on one node (wallet spends only at fund):

```bash
# complete BountyTerms object; title-only drafts will not publish
btx-cli createbountydraft '{"terms": ...}'
btx-cli publishbounty '{"draft_id":"<draft_id>"}'
btx-cli searchbounties '{"text":"coding agent","scope":"LOCAL"}'
# wallet: preparebountyfunding → inspect → signbountyfunding → submitbountyfunding
# mine ≥ minimum_confirmations, then observebountychain with the real txid:vout
btx-cli commitbountysubmission '{"bounty_id":"<id>","commitment":{"artifact_digest":"…"}}'
btx-cli revealbountysubmission '{"commitment_id":"…","submission":{"artifact_dir":"/path"}}'
btx-cli preparebountyevaluation '{"submission_id":"…","profile_id":"EXACT_CHECKS","required_files":["weights.bin"]}'
btx-cli runbountyevaluation '{"plan_id":"…","execution_approval_ref":"operator"}'
btx-cli publishbountyevaluation '{"job_id":"…"}'   # is_award=false
btx-cli proposebountyaward '{"bounty_id":"<id>","submission_id":"…"}'   # paid=false
btx-cli approvebountyaward '{"award_id":"…","decision":"APPROVE"}'      # no tx signature
```

`observebountychain` is operator-supplied: use the **mined funding
outpoint**, not a placeholder. Helper approve is policy only. On-chain
award is still `inspectbountyaward` → `signbountyaward` →
`submitbountyaward` of a tx you built; there is no `preparebountyaward`
auto-payout. Isolated-regtest proof:
`test/functional/feature_modelnet_bounty_lifecycle.py`.

Funding, award, and refund are ordinary wallet spends:
`prepare` → `sign` → `submit`. The helper never auto-spends. The chain does
**not** run the benchmark. Council M-of-N authorizes an award; each lot
still has the contributor’s own refund key. Lifecycle:
[../bounties.md](../bounties.md), RPCs: [../bounty-rpc.md](../bounty-rpc.md).

Release campaigns (pay to open an **existing** private model) are a
different product: [model-economy.md](model-economy.md).

## End-to-end map

```text
doctor
  → host PATH                    pin + search card + demand-seed
  → search / show / files
  → link NAME.btx  |  share      magnet analog
  → get URI|.btx|NAME            FREE_ONLY retrieve (async on unix)
  → path → load → generate       local run if host profile matches
  → bounty-draft / publishbounty / searchbounties
  → wallet prepare/sign/submit funding, observebountychain (real outpoint)
  → commit/reveal → EXACT_CHECKS eval → propose/approve (no auto-spend)
```

| Want | Command / RPC | Spends? |
|---|---|---|
| Host weights | `btx-model host PATH` / `hostmodel` | no |
| Host a share | `btx-model host FILE.btx` / `getmodel FREE_ONLY` | no |
| Search models | `btx-model search` / `searchmodels` | no |
| Search bounties | `btx-cli searchbounties` | no |
| Retrieve | `btx-model get` / `getmodel FREE_ONLY` | no (`FREE_ONLY`) |
| Checkout | `btx-model path` / `exportmodelpath` | no |
| GPU hold | `btx-model load` / `loadmodel` | no |
| Tokens | `btx-model generate` / `generatemodel` | no |
| Draft a bounty | `btx-model bounty-draft` / `createbountydraft` | no |
| Publish / find | `publishbounty` / `searchbounties` | no |
| Fund a lot | wallet `preparebountyfunding` / `sign` / `submit` | **yes**, only after you confirm |
| Complete (helper) | commit/reveal/eval/propose/approve | no auto-spend |
| Award on chain | `inspectbountyaward` / `sign` / `submit` | **yes**, operator-built tx |

## Hard no

- Do not paste model cards, bounty text, or `btx://` commentary into a wallet.
- Do not treat `STRUCTURE_VERIFIED` or `execution_profile=0` as “it is useful.”
- Do not start a network inference server. `inference=false`.
- Do not `SIGKILL` production `btxd`. `unloadmodel` SIGTERMs the helper-spawned
  CUDA loader child only.
- Do not recut `v0.34.8`. This tree is 0.34.9-dev.
