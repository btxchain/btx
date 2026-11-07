# BTX Atlas — scientific workbench expansion (NeuronLab 0.2)

**Delivery:** independently authored source overlay on the previously delivered Atlas native application and NeuronLab add-on. It is not a fork of Lyra's unlicensed source, a replacement BTX monetary runtime, or a production-qualified release.

This package implements six additional scientific tabs: **Embeddings, Causal tracing, Multi-turn steering, Model qualification, Live inspection, and Dose sweeps**. The previous seven NeuronLab tabs and the rest of Atlas remain available. No React, Three.js, Electron or external web asset is introduced.

## What this adds

- A chunk-verified embedding store and original-space neighbour queries, Incremental PCA, real optional UMAP, and bounded t-SNE; custom WebGL2 scatter code with Canvas fallback, category colouring/filtering, pan/zoom, row picking, lasso, exact-row navigation and accessible tables. Up to one million loaded points; fallback rendering has an explicit 20,000-point display cap.
- Real activation patching across embedding, residual, attention and MLP sites: denoising/restoration, reverse/noising, zero ablation, head/group selection, explicit token alignment, receiver-mediated effects with frozen controls, and joint-intervention nonadditivity. Resumable immutable experiment grids preserve negative/null/missing outcomes.
- Durable independent baseline/positive/negative conversations with actual sampling, token probabilities, provisional streaming, per-arm transcripts, dose changes, forks, expected-revision checks, stable operation IDs and explicit interrupted-turn recovery. The local model is used; there is no cloud fallback.
- Exact-checkpoint qualification probes and a local matrix runner. Fourteen adapter entries include the small test model and thirteen pretrained architecture families. **Adapter source is not qualification:** only eight locally trained small CPU checkpoints were qualified in this environment.
- Actual activation ranking, measured steering lenses, explicitly noncausal static connection projections, feature annotations, model-representation extraction and resumable dose sweeps.
- A bounded native JSONL progress bridge and all relevant source changes to integrate these features into the prior Atlas application. Native Rust/Tauri compilation and platform validation remain required.

## Apply

Start from a clean, committed checkout already containing both prior deliveries. The pinned BTX ancestor is `18ea826ee3d82edf65a274c00316bd118ed731d2` (PR #245, `btx-035/swarm`). The new PR must be based on your integrated NeuronLab branch, not directly on a branch lacking Atlas.

```sh
python3 apply.py --repo /absolute/path/to/btx
python3 apply.py --repo /absolute/path/to/btx --branch btx-035/atlas-science --apply
```

The first command is read-only. The installer verifies ancestry, clean state, overlay hashes and exact hashes of modified baseline files; it refuses conflicts. The second creates a branch and installs source. Neither commits, pushes nor opens a PR. If prior work has advanced, reconcile the source changes explicitly; do not bypass hashes to overwrite another agent's work.

**Important binding change:** the reviewed execution fingerprint has changed. Existing registered models and old intervention profiles are not silently rebound. Re-register the exact local checkpoint, review the new adapter/runtime, and explicitly fork/re-test/re-sign any old profile for the new binding. Keep old signed evidence with its original binding.

## Tests

Use a reviewed environment containing the dependencies recorded in `contrib/atlas/neuronlab/requirements-tested.txt`. Installation is an explicit operator/build task; the running worker never downloads code or weights.

```sh
cd /absolute/path/to/btx/contrib/atlas/neuronlab
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 python3 -m pytest tests
cd /absolute/path/to/btx/gui/atlas
node --test tests/*.test.mjs
node tests/static-audit.mjs
```

Run all web modules through `node --check`; the provided offline bundle tool now does this before test-only transformation. Two actual syntax errors inherited from the previous NeuronLab view have been corrected. A transpiler's recovery is not valid evidence of JavaScript syntax correctness.

For scientific reproduction and browser execution see `VALIDATION.md`. For native compilation, real checkpoint qualification and release gates see `AGENT_HANDOFF.md`. For definitions of causal effects, limits and model semantics see `SCIENTIFIC_CONTRACT.md`. `LYRA_COVERAGE.md` distinguishes implementation, execution evidence and remaining parity.

## Package layout

- `overlay/`: exact new/changed repository files.
- `BASELINE.json`: parent, prior delivery hashes and expected existing file hashes.
- `MANIFEST.json`: exact overlay byte hashes.
- `apply.py`: guarded dry-run/apply installer.
- `tools/`: reproduction, browser, qualification and manifest tools.
- `reports/`: actual unit tests, CPU experiments, public signed receipts, browser tests and installer checks.

No private signing key, model weight, font, credential or live-user prompt is included. Sample conversations and coordinates are from deliberately synthetic local CPU experiments. Supplied public receipts prove signatures over those records, not independent scientific validation, hardware population coverage, or behavioral safety.

## Non-claims

There is no measured pretrained LLM/GPU qualification, native Tauri build, physical BTX peer test, universal causal-circuit reconstruction, full remote swarming implementation, wallet/Qt parity closure, or end-to-end formal security/performance proof. UMAP is a real optional implementation but was unavailable for execution here. The browser ran Canvas2D, not WebGL2; a million loaded points is not a million drawn points per frame. Existing native and wallet gates remain unchanged.
