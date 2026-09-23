# Local generate (host-profile match)

**Status:** 0.34.9. `CLIENT_VERSION_IS_RELEASE=true`. Shipping tag
**v0.34.9**. This page is the operator contract for **local one-shot
generate** after a replica is complete. It is **not** a remote inference
marketplace, not a network server, and not CUDA `--hold --smoke`.

People: [end-to-end.md](end-to-end.md), [first-run.md](first-run.md) §6.
Agents: [agent-recipes.md](agent-recipes.md).
RPC catalogue: [rpc.md](rpc.md). Adapter: [../../contrib/modelnet/generate_local.py](../../contrib/modelnet/generate_local.py).

`automatic_spend_atoms` stays **0**. `execution_profile` stays **0**
(unqualified identity, not a PASS). `trust_remote_code` stays **false**.

## What “compatible with this host” means

`getmodelhostprofile` reports what **this helper process** can generate.
`generatemodel` then fail-closes unless the checkout matches that profile.

| Artifact | This host must have | Adapter |
|---|---|---|
| **GGUF** | `BTX_LLAMA_CLI` executable, **or** `BTX_MODEL_GENERATE` | llama.cpp, or `generate_local.py` wrapping it |
| **Allowlisted SafeTensors** | `BTX_MODEL_GENERATE` pointing at a stdin-JSON adapter | typically `generate_local.py` (`transformers`, `local_files_only=True`) |

Allowlisted `config.json` `architectures[]` include Llama, Mistral, Mixtral,
Qwen2/Qwen3, Gemma, Phi, GPT-2 / GPT-Neo, Bloom, Granite / GraniteMoe /
**GraniteMoeHybrid**, Mamba, and a short related set. `custom_auto_map` and
unknown class names fail closed (`unknown_architecture`).

Pickle / `.pt` / `.pkl` / `.so` fail closed (`unsafe_format`). Missing
weights fail closed (`no_weights`). SafeTensors without an adapter fails
closed (`no_generate_adapter`). GGUF without llama.cpp or a generate adapter
fails closed (`no_gguf_backend`).

CUDA xor-smoke (`BTX_MODEL_CUDA_LOADER --hold --smoke`) is **not** generate.
`getmodelhostprofile` sets `cuda_smoke_is_not_generate=true`. `generatemodel`
SIGTERMs a helper-spawned CUDA loader child for that replica before the
adapter runs (never production `btxd`).

## Operator env

| Env | Role |
|---|---|
| `BTX_MODEL_GENERATE` | Executable adapter. Helper writes one JSON line on stdin (`prompt`, `max_new_tokens`) and expects one JSON line on stdout (`ok`, `text`, `backend`). |
| `BTX_LLAMA_CLI` | GGUF path when no generate adapter is set. Helper runs `-m` `-p` `-n` `--no-display-prompt`. |
| `BTX_MODEL_CUDA_LOADER` | Optional resident smoke on `loadmodel`. Not used as a generate backend. |
| `BTX_LLAMA_NGL` | Optional offload layers for `generate_local.py` GGUF path (default `99`). |
| `BTX_GENERATE_TIMEOUT_S` | Optional adapter timeout for `generate_local.py` (default `600`). |

Do not pip into `/tmp` (tmpfs). Do not enable `trust_remote_code`. Missing
torch/transformers/llama-cli must return `ok=false` / `NOT_RUN`, not a fake
completion.

## People path

Replica must be **complete** (`getmodel` `FREE_ONLY` first if it is a share).

```bash
export BTX_MODEL_GENERATE="$PWD/contrib/modelnet/generate_local.py"
# GGUF also:
# export BTX_LLAMA_CLI=/path/to/llama-cli

contrib/modelnet/btx-model host-profile
contrib/modelnet/btx-model path NAME          # checkout / usable_runtime_root
contrib/modelnet/btx-model generate NAME "Hello" --max-new-tokens 32
```

Unix RPC (one JSON line). `generatemodel` shares the **24h** helper wait with
`importmodel` / `getmodel` / `loadmodel`.

```json
{"jsonrpc":"1.0","id":1,"method":"getmodelhostprofile","params":[]}
{"jsonrpc":"1.0","id":1,"method":"generatemodel","params":["<id-or-btx://>",{"prompt":"Hello","max_new_tokens":32}]}
```

Success flags: `generated=true`, `local_generate=true`, `compatible=true`,
`inference=false`, `remote_inference=false`, `network_server=false`.
Incompatible unix replies use `error.code=INCOMPATIBLE_HOST_PROFILE` and
`error.message` is the reason (`unknown_architecture`, `no_generate_adapter`,
`unsafe_format`, …).

Prompt max **64 KiB**. `max_new_tokens` is clamped **1..512** (default 32).

## Load vs generate

| RPC | Does | Does not |
|---|---|---|
| `exportmodelpath` | Materialize checkout; hardlink from `source_path` when SHA-384 still matches | Start a runtime |
| `loadmodel` | Inventory SafeTensors; optional CUDA `--hold --smoke` when `BTX_MODEL_CUDA_LOADER` is set | Start a network inference server |
| `unloadmodel` | SIGTERM the helper-spawned CUDA loader child | Touch production `btxd` |
| `generatemodel` | One-shot local tokens for a host-compatible replica | Listen on a TCP inference port |

Granite-4.0-h-tiny is SafeTensors **hybrid MoE/Mamba**
(`GraniteMoeHybridForCausalLM`). It is on the generate allowlist. llama.cpp
cannot open that checkout without GGUF conversion. CUDA smoke on those
tensors is still not generate. Real tokens need `transformers` that can load
the architecture with `trust_remote_code=False`. Missing deps stay `NOT_RUN`.

## Honesty

- `STRUCTURE_VERIFIED` is not usefulness, safety, or alignment.
- A fake unit-test adapter proves the RPC path. It is not a model quality claim.
- Live Hugging Face / R2 WAN is still operator-gated (`live_wan`).
- This page is not CSV PASS.
