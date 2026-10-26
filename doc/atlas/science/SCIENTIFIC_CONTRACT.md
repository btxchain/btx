# Scientific contract and architecture

## 1. Evidence is an execution record, not a picture

Every model operation binds exact checkpoint/config/tokenizer identity and a reviewed execution fingerprint. Model names, identical tensor dimensions, training recipe labels and signed publisher descriptions cannot establish compatibility. Scientific outputs carry the declared inputs, metric, hook point, controls, provenance and negative outcomes. The previous training-recipe and capsule policies continue unchanged: unknown historical dropout, optimizer, weight decay or dataset stays unknown; a config default is not measured training history.

The graphical projection remains derived state. It does not authorize local model execution, peer admission, a tool, software installation, model activation, or spending. The unmodified BTX native runtime and existing Atlas authority rules remain authoritative.

## 2. Embedding data and the scatter interface

`embeddings.py` accepts bounded regular numeric NPY input only: no pickle, object dtype, remote URL, archive or arbitrary executable loader. It validates 2..1,000,000 rows, 2..8,192 features, finite float32/float64, C layout, declared metadata and a 512 MiB input bound. Source precision is preserved for original-space queries. The store has a separate 2 GiB ceiling; this is not a whole-process RSS guarantee.

Projection choices are not interchangeable:

- Incremental PCA uses a bounded fit/transform pass and records actual parameters.
- t-SNE is a separate bounded operation, limited to 20,000 rows and the declared intermediate/input budgets. It does not pretend to be PCA or UMAP.
- UMAP calls the actual optional `umap-learn` implementation. For larger inputs it explicitly records landmark fitting plus transform; this is not equivalent to a full million-row UMAP fit. Missing UMAP produces `UMAP_NOT_INSTALLED`, not a substituted scatterplot labelled UMAP.

The immutable dataset ID binds the actual input and projection parameters. Chunk hashes are checked before pages are returned. Pages use compact float32 plot coordinates and integer source/category IDs; imported original vectors remain separately available for chunked exact cosine or Euclidean queries. Original-space neighbours are never inferred from 2D display distance. Zero vectors and undefined normalizations remain explicit.

The renderer uses typed arrays, an explicit spatial index, event-driven drawing, fixed category IDs and bounded labels. It supports pan/zoom, keyboard fit/focus, picking, Shift-lasso, source-row navigation, colouring by neuron/prompt/dose/kind, category filtering and accessible paged rows. At most one million points are materialized. The WebGL2 path uploads packed attributes and draws GPU points; Canvas fallback displays a deterministic maximum of 20,000 points and says so. Its fallback lasso is scoped to that sample. When supported, a separate worker computes lasso against the loaded population, obeys visibility, caps returned IDs and reports the full match count. Generation/request IDs reject stale worker replies. Context loss and unmount release buffers, listeners, workers and animation work.

One million points can therefore be *stored/indexed* without claiming all were *drawn*. The browser validation used Canvas fallback. The unchanged lasso worker code was separately run in a Node worker thread at one million points; this does not qualify native WebView worker/CSP behavior.

## 3. Causal experiment estimands

A trace design commits clean/corrupted token sequences, an explicit one-to-one alignment, target and optional foil token, metric, selected cells, model and control policy. Token coordinates in source and destination are not assumed equal merely because strings look similar. Hook sites are trusted adapter declarations, not caller-supplied Python module names.

Supported sites are embedding output, block input/output residual, attention pre-output projection and post-attention output, post-activation MLP and post-MLP output. On supported full-attention layouts a cell may select query-head blocks; it cannot simultaneously select heads and arbitrary units. Actual tensor width is checked. Unsupported or hybrid linear-attention layouts refuse rather than map to a plausible-looking head.

A restoration/denoising intervention copies selected clean activations into a corrupted run. A reverse/noising intervention copies the corresponding corrupted activations into a clean run. Zero ablation supplies zeros and reports the effect without calling it clean restoration. Effects use the declared next-token probability, log probability or target-minus-foil logit difference.

For restoration the reported fraction is `(patched_metric - destination_baseline) / (source_baseline - destination_baseline)`. It is not clipped: negative effects and values above one are retained. Near-zero baseline gaps produce null normalized values with a reason, not infinity or zero. The raw effect remains available. Millionth-scaled numbers have a JavaScript-safe bound.

Gaussian embedding corruption records the noise generation seed and actual noise identity. A noise seed is not evidence that a corruption distribution is representative. Research conclusions remain dependent on metric, prompt, corruption, layer, token, intervention strength, training recipe and implementation.

Each trace chunk operates on bounded cells (up to 64 per resumable chunk; a recorded plan up to 4,096). Capture memory is bounded; only relevant site values are held, never an uncontrolled complete-model activation dump. Hooks are removed after normal, failed and cancelled forwards. A final-residual replacement at the measured token is a useful exact restoration regression, not a demonstration of a meaningful semantic circuit.

### Receiver-mediated paths

A path experiment patches a sender into the destination run, optionally freezes declared intermediate sites to the destination baseline, captures a later receiver, then patches only that receiver into a fresh destination run. It estimates the declared receiver-mediated sender effect under those controls. A receiver must be later than the sender. Frozen controls and receiver tokens are destination-token coordinates.

This does **not** prove a unique graph edge, isolate every alternative computational path or reconstruct a complete causal explanation. The output explicitly sets `exclusive_graph_path_proven: false`. GUI labels preserve this distinction from static connection geometry.

### Joint interactions

The factorial experiment executes baseline, A, B, and A+B, and records `metric(A+B) - metric(A) - metric(B) + metric(baseline)`. Overlapping factor definitions are refused. Nonadditivity is evidence under that experiment, not automatically synergy, mediation or a universal feature decomposition.

### Resumption and evidence

Plans, cells and requests have stable semantic IDs; completed cells remain completed on retry and conflicts fail. Results and failures are preserved in local storage. The UI distinguishes NOT_RUN from a measured zero. The system never calls a partially completed grid complete. Signed receipts authenticate a record and its author; independent administration, hidden-test protection and source truth still require external evidence.

## 4. Multi-turn steering

A session pins a model, exact profile, formatting contract and independent baseline/positive/negative histories. Every completed turn records the exact inputs and all three actual outputs. The next turn uses each arm's own prior responses. Users can share a user message across arms or supply different messages explicitly.

The model's actual chat template is required for chat mode. A missing template does not silently become a homemade template. Plain transcript formatting is an explicit option. The synthetic test model instead uses token-ID prompts and has no pretrained conversational ability; its output does not constitute a human-quality chat demonstration.

Sampling includes deterministic greedy mode and bounded temperature, top-k, top-p and seed settings. Token IDs, finish reasons, measured model versus sampling probabilities and optional top-k log-probabilities are recorded. Additive and multiplicative dose semantics retain the prior profile contract; sign reversal is not assumed to reverse meaning.

Every request has private caches. A conversation turn rebuilds the prompt from its full retained history, and then uses incremental caching only when the engine supports it. Caches are not shared between arms, profiles, requests or turns. This favors correctness and explicit context changes over an unqualified resident-cache optimization. Context/token/text limits cause an explicit refusal; no silent context truncation occurs.

Durability uses a revision check, a stable operation ID, one running turn per session and atomic transcript commit. A duplicate operation is reconciled rather than creating another turn. Changing a completed prompt means forking, preserving the original history. An interrupted RUNNING record requires explicit recovery and stays an interruption, not an invented result.

Streaming is explicitly provisional. Once a token has been displayed it cannot be recalled, so trust/revocation/cancellation checks run during decoding and before durable completion. A failed final fence prevents successful commit and final result release. A transcript never turns incomplete provisional output into a completed scientific observation.

## 5. Live inspection and dose studies

The activation scanner uses actual forward measurements to rank selected coordinates and show per-token values. Its ranking is descriptive activation magnitude, not semantic selectivity or monosemanticity. The steering lens runs the model with and without an intervention and compares next-token distributions/KL. The static connection view projects down columns through later read directions and is labelled static/noncausal; it does not ignore gates or normalization while claiming to have measured their effect.

Representation extraction pools actual measured residuals by last/mean/token policy, commits provenance, and feeds the embedding pipeline. Prompt privacy remains local. An annotation is a human hypothesis attached to an exact coordinate, not a verified intrinsic feature name. Dose sweeps use immutable designs, bounded cells and retained results; choosing an attractive slider after inspecting many trials still requires a separately declared evaluation budget before scientific claims.

## 6. Qualification rather than model-name badges

Fourteen architecture entries are included as source adapters. The local qualification runner loads the actual checkpoint through local-only allowlisted classes, binds exact model bytes, probes every supported layer/site, checks raw versus instrumented no-op logits, performs an actual coordinate zeroing, checks finite results and restored baseline, checks hook cleanup and weight immutability, tests incremental cache equivalence where applicable, and generates actual tokens.

A successful record is `LOCAL_CHECKPOINT_PROBE_PASS`, not `RELEASE_QUALIFIED`. It is scoped to the prompt, tolerance, source/adapter fingerprint, framework version, precision, device and exact checkpoint. It does not certify every operation, all prompts, unrelated models or other GPUs. Numerical operator tests are separate.

Only eight deliberately small trained `BTXTinyLM` CPU checkpoints were executed here. The thirteen pretrained-family adapters remain source-only. Transformers/checkpoints were unavailable; GGUF, EXL3, vLLM fused kernels, routed MoE and arbitrary remote model code remain unsupported. The matrix runner does not download anything or promote NOT_RUN to PASS.

## 7. Native integration and boundaries

The expanded Rust broker preserves the inherited native source/interpreter checks and fixed action allowlist. It invokes the reviewed worker over private stdio, parses bounded JSONL, binds every frame to the operation ID, caps individual and cumulative progress output, requires exactly one final response and refuses frames after it. Progress is emitted to the existing main window as data, not commands. Cancellation epochs suppress later delivery; native approvals remain separate from model-generated content. The native process model remains bounded per-operation workers rather than a second BTX daemon.

The code is supplied but Rust/Tauri was not available to compile or execute here. A reviewed interpreter/source path is not a complete OS sandbox, a dependency audit or a defense against an already compromised OS user. Cross-platform IPC permissions, descendant process handling, Windows ACLs, native resource pressure and source/model TOCTOU protection remain release gates.

All raw prompts, activations, embeddings and transcripts remain private by default. Existing explicit capsule sharing does not imply publication of these datasets. No native peer registry, independent evaluator network, realm encryption, remote activation, monetary signing or settlement is added by this expansion.

## 8. Binding migration and reproducibility

The execution fingerprint includes the changed model/runtime code. Old profiles therefore fail closed against the new registration. There is no automatic compatibility rewrite. An operator must re-register, re-test and explicitly sign a fork. Previous evidence stays tied to previous code. `code-manifest.json` must be rebuilt only after reviewing source changes; it is a local integrity record, not a publisher certificate.

The recorded training runs use eight actual small models (two activations, two dropout recipes, two seeds). They validate machinery, not claims about modern LLM dropout, redundancy, polysemanticity or superposition. Record exact recipes, data, seeds, negative effects and missing histories when extending these studies to actual modern models.
