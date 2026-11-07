# Private worker, native UI and existing generate adapter

## Worker protocol

The entry point is `contrib/atlas/neuronlab/worker.py`. Invoke a reviewed
interpreter with isolation and no bytecode output:

```sh
python3 -I -B /path/to/btx/contrib/atlas/neuronlab/worker.py \
  --store /absolute/operator-owned/neuronlab-store
```

One newline-terminated JSON request enters stdin; one response exits stdout.
There is no listening socket. `--serve` is an explicit local CLI mode, not a
swarm daemon. Logs/diagnostics go to stderr.

```json
{"action":"status","payload":{},"operation_id":"unique-semantic-operation-id"}
```

Responses are `{ "ok":true, "result":... }` or
`{ "ok":false, "error":{ "code":..., "message":... } }`.
No command accepts arbitrary code, shell commands, network URLs or wallet RPCs.

| Actions | Payload / behavior |
|---|---|
| `status`, `models`, `events`, `list`, `receipts` | Bounded local metadata and evidence; pagination for capsule/events. |
| `initialize` | Create explicit local research key and local-owner trust; never a wallet key. |
| `register` | Native-selected local model directory; byte/config/tokenizer binding and separate config declarations. |
| `binding` | `model_id`; exact recorded binding. |
| `create` | Exact draft with model ID, title, description, operations, tensors, training_recipe, privacy, license, claims, parent_profiles. Signs a new immutable capsule, not activation. |
| `profile` | `profile_id`; optional `include_tensors:true` is bounded to 65,536 coefficients for editing. |
| `import`, `export` | Native-selected file; full capsule validation; export refuses overwrite. |
| `trust`, `revoke` | Exact publisher and operator-assigned domain label. Local scope only. |
| `activate` | `profile_id`, `model_id`, `expected_generation`; exact match plus trust. |
| `deactivate` | `model_id`; increment local fence. |
| `compare` | `profile_id`, `model_id`, `prompt`, `max_new_tokens`, `layer`, `units`; actual three-arm local generation. |
| `generate` | Exact profile/model/prompt/output budget; local request only. |
| `direction` | Positive/reference and optional neutral matrices; normalized output plus signed extraction receipt. |
| `lens` | `model_id`, `layer`, `unit`; static down-column projection. |
| `study_plan` | Bounded factor lists and steps; immutable sharded work descriptions. |
| `study_run` | One exact `work` unit; real local synthetic-model training and signed result. |
| `evaluate` | Unique task/seed paired rows, suite/profile IDs, trial budget and bootstrap settings. |
| `import_evidence` | Signature verification/import only; does not grant trust or claim evaluator independence. |
| `save_router`, `router_preview`, `run_router` | Fixed numeric feature policy, locally trusted profile IDs or baseline. No new authority. |
| `publish_plan`, `import_checkout` | Internal fixed native transport plan / completed exact-capsule import. |

`create`, import, trust and activation use durable semantic operation IDs.
A reused ID with different content is refused. Scientific reruns are new explicit
experiments; there is no claim of exactly-once external side effects. A timeout
may leave outcome unknown; inspect the original ID/evidence before a new action.

## Native commands

`atlas_neuronlab(action,payloadJson,operationId)` and
`atlas_neuronlab_cancel()` are registered for the same trusted main window as the
existing Atlas commands. Additional native actions are `configure`, `publish`,
`acquire`, and `finish_acquire`. The renderer never receives the RPC cookie,
research private key, or an arbitrary native process handle.

Path-taking commands use native file dialogs instead of trusting renderer paths.
Read-only commands do not acquire mutation authority. Computation and mutation
have native review. Native review is not controlled by a profile's display text.

## Optional existing BTX generate integration

An operator may explicitly configure the supervised model helper environment:

```sh
export BTX_MODEL_GENERATE=/absolute/path/to/btx/contrib/atlas/neuronlab/generate_adapter.py
export BTX_NEURONLAB_STORE=/absolute/operator-owned/neuronlab-store
export BTX_NEURONLAB_DEVICE=cpu
```

Ensure the executable shebang resolves a reviewed Python interpreter/environment;
review service startup/environment handling instead of injecting these into a
running daemon. The source installer does not alter any production node config.

The adapter implements the existing `--dir` / `--max-new-tokens` + stdin JSON
contract. It loads a registered-compatible local model and consults exact local
activation. No active profile means ordinary unmodified local generation. A
revoked or changed in-flight profile causes a refusal rather than release of
unverified partially steered output. This reference does not handle GGUF/EXL3;
select it only for an explicitly qualified SafeTensors architecture.

The existing Atlas assistant can then use the same `generatemodel` path. The
assistant still cannot sign, activate its own profile, spend, execute arbitrary
tools, or pass its own approval. Independent host authorization remains necessary.
