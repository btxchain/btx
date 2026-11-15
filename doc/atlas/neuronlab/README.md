# BTX Atlas NeuronLab — source add-on

**Status: implemented source candidate, with scoped execution evidence. Not a qualified native BTX release.**

This add-on extends the previously delivered framework-free Atlas application with
checkpoint-bound neuron/feature interventions, signed data capsules, local
counterfactual runs, training-recipe studies, and source integration with BTX's
existing public byte transport. It does not replace consensus, the wallet, the
swarm observer or the node's own authorization decisions.

## What is included

- Seven real tensor operator families: MLP-coordinate add/scale/clamp, attention
  head scaling, residual-direction add/project-out, and error-preserving ReLU-SAE
  feature addition. Explicit prefill/decode and token-interval semantics.
- Actual local PyTorch execution, bounded pre/post captures, three-arm comparisons,
  static down-column lenses, contrastive/PCA direction extraction, and private
  per-request caches. No weight mutation, pickle, downloaded executable code,
  arbitrary user hooks or remote inference fallback.
- Data-only SafeTensors intervention capsules with actual ML-DSA-44 signatures,
  domain-separated SHA-384 identities, exact checkpoint/tokenizer/config binding,
  reviewed adapter/framework fingerprint, parent-profile references, training
  history, rights labels, claim/evidence links and strict bounds.
- Private artifact store, signature verification, quarantine, local publisher
  trust, expected-generation activation, local revocation, and in-flight output
  fences. Cryptographic validity is not behavioral safety or authorization.
- Rust/Tauri source bridge: native confirmations, native file selections, reviewed
  source/interpreter hashes, private stdio, concurrency/output/time bounds,
  cancellation, fixed existing BTX transport methods, and no wallet credentials
  in the research process.
- New Atlas workspace with seven tabs, a bounded perspective layer viewer,
  linked exact-coordinate editor, baseline/positive/reversed comparison, capsule
  sharing/trust, training history, directions/lenses, cohort studies, receipts and
  numeric context routing. Existing Atlas workspaces remain in place.
- Factorial study harness: dropout, GELU/SwiGLU, optimizer and weight decay across
  seeds on actual small causal transformers. Sharded work IDs, saved trained
  checkpoints and measured results. No claim that toy results transfer to LLMs.
- Existing `BTX_MODEL_GENERATE` contract adapter. An operator can explicitly make
  the same local model used by BTX/Atlas honor locally approved profiles. It is not
  enabled by installing this source and does not affect other inference engines.

## Apply on TOP of the previous Atlas source

Prerequisite: the previous `BTX_Atlas_Native_Source_PR245.zip` has been integrated
and committed on a descendant of PR #245. This is not a replacement ZIP and it is
not sufficient by itself on the bare PR #245 tree.

```sh
python3 apply.py --repo /absolute/path/to/btx
python3 apply.py --repo /absolute/path/to/btx \
  --branch btx-035/atlas-neuronlab --apply
```

The first command is a dry run. The installer checks the clean Git checkout,
PR #245 ancestry, exact existing Atlas file hashes, all overlay hashes, path
safety and conflicts before writing. It refuses to overwrite newer edits. It
creates a branch only when `--apply --branch` is supplied; no commit, push or PR
is performed. Five existing Atlas files are deliberately changed. All other
source additions are under `contrib/atlas/neuronlab`, `gui/atlas`, and
`doc/atlas/neuronlab`.

Pinned BTX ancestor: `18ea826ee3d82edf65a274c00316bd118ed731d2`.
The appropriate PR base is the agent's already-integrated Atlas branch. Preserve
both that ancestry and the source/evidence records; do not start again at the bare
swarm branch and lose Atlas.

## Run tests in the integrated checkout

Install scientific dependencies only through your reviewed environment/package
policy. No installer in this add-on downloads dependencies or models at runtime.
OpenSSL must actually implement ML-DSA-44 (the executed environment used 3.5.5).

```sh
cd /path/to/btx
PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest contrib/atlas/neuronlab/tests
(cd gui/atlas && npm test)

# Reproduce the 48-case synthetic CPU experiment and fresh private signatures.
python3 -B /path/to/addon/tools/run_scientific_validation.py \
  --source-root "$PWD" --reports /tmp/neuronlab-validation

# Native: resolve/audit the inherited dependency graph first.
(cd gui/atlas/src-tauri && cargo test)
```

The last command was **not** run here: no Cargo/Rust toolchain was available.
The inherited Atlas native package also remains an unqualified source candidate.

## Native UI setup

Build the native application through the existing Atlas instructions. Open
**Neuron Lab → Configure worker**, select the trusted Python interpreter and the
installed `contrib/atlas/neuronlab/worker.py`. The source manifest and interpreter
hash appear in the native review. Use a clean source tree with no generated
bytecode inside `btx_neuronlab`. Configuration is intentionally session-local;
a restart asks you to select/review the runner again.

Then initialize a research identity, register a local SafeTensors checkpoint,
review the exact binding and available adapter, build a profile, sign it, and run
a controlled comparison. A third-party profile must be verified and locally
trusted before it can be applied. Native execution still needs its own approval.

The browser preview has **no native execution or transport**. Its optional
recorded fixture contains real measurements from the authoring CPU experiment,
clearly labelled synthetic-model data; it is not a fake live node.

## Native transport scope

The Rust bridge uses `hostmodel`, `getmodel` with `FREE_ONLY`, and
`exportmodelpath`. It reconstructs those fixed requests itself; neither a capsule
nor a model may supply an arbitrary RPC call. It carries the capsule as a
SafeTensors **data artifact**, not trained model weights. Native search-card
publication is disabled; share the exact returned resource URI and profile ID.
This is a compatibility carrier, not a newly registered first-class global
ModelNet intervention registry. Actual BTX transport/checkout needs the native
integration test; only the matching source and local transfer tests are delivered.

Private and realm capsules cannot be published through this public path. There
is no implied private-encrypted swarm transport, automatic peer trust, remote
activation, global adoption vote, independent evaluator quorum or financial
settlement. Those remain governed by separately qualified BTX capabilities.

## Read next

- `AGENT_HANDOFF.md`: integration and qualification instructions.
- `VALIDATION.md`: exact executed checks and NOT_RUN gates.
- `overlay/doc/atlas/neuronlab/DESIGN.md`: artifact, math, GUI and swarm contract.
- `overlay/doc/atlas/neuronlab/SECURITY.md`: boundaries, failures and remaining risks.
- `overlay/doc/atlas/neuronlab/API.md`: private worker and native action contracts.
- `overlay/doc/atlas/neuronlab/MODEL_SUPPORT.md`: tested versus source-only adapters.
- `overlay/doc/atlas/neuronlab/SOURCES.md`: primary references and license posture.

No broad superiority, behavioral-safety guarantee, formal security proof, full
Lyra feature parity, production performance guarantee or native release claim is
made by the existence of these files.
