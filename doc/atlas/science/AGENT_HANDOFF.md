# Agent integration handoff — Atlas Science / NeuronLab 0.2

## Objective

Apply the supplied scientific expansion to the already integrated Atlas + NeuronLab branch. Preserve the independent framework-free Atlas interface, BTX native authority and existing monetary/wallet behavior. Keep the black spatial scientific design and all new workspaces. Do not substitute mocked model data for the actual executed numerical paths.

## Exact parent and installation

Pinned BTX ancestor: `18ea826ee3d82edf65a274c00316bd118ed731d2` (PR #245, `btx-035/swarm`, rechecked during this delivery). Suggested branch: `btx-035/atlas-science`. PR base: your committed NeuronLab integration branch. This delivery made no GitHub mutation.

The add-on compares exact changed-source hashes to `BASELINE.json`. Run `apply.py --repo ...` first, then `--branch btx-035/atlas-science --apply`. A conflict means review/rebase, not permission to disable the guards. Do not lose upstream fixes or remove Qt merely to advertise completion.

## Mandatory binding migration

Scientific runtime source changed. Model registration and profile compatibility bind the execution fingerprint. Existing signed capsules from the previous implementation deliberately do not authorize the new runtime. Re-register the checkpoint, review/fork the intended profile, remeasure and re-sign it; never rewrite a signed profile, remove the fingerprint field or silently convert old evidence into a new pass.

The rebuilt `code-manifest.json` covers all 25 worker/source modules. It is local source-integrity input, not an external security certificate. The scientific Python dependency tree and interpreter still require review and reproducible version pinning.

## Implemented source

Read `SCIENCE_ACTIONS` in `contrib/atlas/neuronlab/btx_neuronlab/science.py`, the exact numerical contracts in `runtime_io.py`, `tracing.py`, `decoding.py`, `conversations.py`, `embeddings.py`, `qualification.py`, and `inspection.py`, then the six-tab `gui/atlas/web/neuronlab/science/view.js` and its custom renderer/worker. The existing native `neuronlab.rs` now parses bounded operation-bound progress frames. New fields must not become authority or an arbitrary RPC/script bridge.

## Integration / qualification order

1. Inspect the full overlay diff, retain the existing signed source notices, and run all 123 Python tests, all 96 integrated JS tests and the 13 textual/syntax checks. These counts record this delivery, not a target to fake. Preserve raw failures and actual test counts after upstream changes.
2. Resolve/audit Cargo dependencies, compile and format Rust, run native tests and repair actual API/compiler defects. No Rust compiler or native Tauri app was available here. Review emit-to-main/window authorization, command capabilities, final-frame cardinality, cancellation races, output caps and child cleanup against the compiled app.
3. Exercise the native app with an explicit authorized local interpreter and immutable scientific source. Browser tests used an explicit test bridge and are not native IPC/CSP/sandbox evidence. Keep remote/nested windows without capabilities, prompts/traces private, and all capsule activation decisions outside model authority.
4. Install reviewed Transformers/UMAP dependencies only as an explicit build/operator step. The runtime must remain local-only and fail closed; never add automatic pip/model downloads or remote code trust to make tests pass.
5. Use `tools/qualify_local_matrix.py` on actual locally installed exact pretrained checkpoints. Start with GPT-2 and a modern dense Llama/Qwen, then evaluate the other architecture mappings separately. Pin `expected_weights_hash`, actual tokenizer/config/chat template, device, precision, package versions and source revision. Missing runtime/checkpoint is NOT_RUN, not a skipped pass. Extend prompts and intervention operator coverage beyond the compact one-prompt qualification probe.
6. Test real cached multi-turn generation with different arm histories, EOS, Unicode/token decoding, long-context refusal, sample seeds, dose changes, profile revocation, cancellation during streaming, process crash, stale session revisions and operation recovery. Provisional tokens cannot be recalled; a denied final fence must prevent successful transcript commit.
7. Validate causal patching against trusted independent reference runs on each model. Confirm exact hook locations, full-attention head layout and token alignment. Keep denoising/noising/zero-ablation normalizations distinct. A receiver-mediated trace must never be relabelled proof of an exclusive path or universal circuit.
8. Run native WebGL2 and actual Web Workers on Windows/macOS/Linux. Test context loss, display scaling, lasso visibility, stale results, teardown, memory during inference and large dataset paging. A one-million-point index test is not a one-million-points-per-frame hardware performance claim. The Canvas fallback cap must stay visible.
9. Execute actual UMAP, including small full-fit and larger landmark/transform paths. Record version, seed, fit rows, transform policy and memory. Check original-space neighbours independently; do not evaluate scientific proximity using a visualization alone.
10. Run native capsule/peer transport and other prior release gates independently. This expansion neither adds public intervention discovery nor qualifies real multi-host scientific work, native activation, evaluator independence, monetary settlement or old Qt parity. Do not remove those gates from documentation.

## Agent allocation

Use nonoverlapping owners: (A) Rust/private streaming + OS isolation; (B) model adapters/real checkpoint qualification; (C) causal semantics and independent reference comparisons; (D) embedding/graphics/browser worker/GPU; (E) conversation durability/cancellation; (F) integration and adversarial review. Shared DTO/source fingerprint changes require coordinator review. Keep the fixed action list in Python and Rust aligned.

## Explicit failures to preserve

Malformed/duplicate JSON, nonfinite/oversized tensors, pickle/object arrays, wrong chunk hash, missing original vectors, stale worker results, unsupported module/head layout, nonbijective alignment, overlapping factors, near-zero restoration denominator, missing chat template, context exhaustion, stale revision, duplicate operation with altered content, interrupted turn, revoked profile and source/checkpoint mismatch must refuse or remain explicit—not fall back to baseline while claiming an intervention.

## Suggested PR description

“Adds independently authored Atlas scientific workspaces: large embedding navigation, precise causal experiments, durable three-arm steering, live inspection/sweeps and per-checkpoint qualification. Parent [actual SHA]; source overlay digest [manifest]. Executed: [actual tests]. Unrun: [exact native/pretrained/GPU/UMAP/peer gates]. No consensus/wallet authority changes, automatic profile migration, remote code, universal causal-circuit claim or production qualification.”
