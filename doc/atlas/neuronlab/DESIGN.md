# NeuronLab design and exact semantics

## 1. Product decision: distribute an intervention, not another vaguely named model

The core object is a signed, immutable **intervention profile**: an exact base
checkpoint plus fixed numerical operations, calibration, evidence, and execution
semantics. A human may draft a profile, compare it with baseline, share it, fork
it, and opt into a specific version locally. The original weights are not edited.
A trained adapter or baked modified checkpoint is a different artifact and must
use the native training/provenance/admission lifecycle; this add-on does not
quietly relabel an inference-time hook as a trained model.

A whole runtime configuration is therefore:

```
exact model bytes + tokenizer/config + reviewed adapter semantics
+ immutable intervention profile + local authority + per-request context
```

The profile's semantic hash is different from its capsule byte hash and from the
native BTX artifact/resource ID. These identifiers must never be substituted for
one another. The native model ID, when available, is an origin reference; it is
not a replacement for byte identity.

## 2. What the paper and Lyra contribute

The referenced paper, *The Psychology of an AI Hacker* (arXiv:2610.30361), studies
residual-direction steering and a context-dependent selector on one model/task
setting. The useful general pattern is controlled, reversible interventions with
baseline comparisons—not a claim that a named emotion is a universal neuron or
that the reported improvement transfers to BTX. Lyra's explorer supplies the
scientific interaction reference: layer inspection, selected neurons, static
lenses, activation reading and positive/baseline/negative comparison.

This implementation is independently authored. It neither copies the unlicensed
Neuron Explorer implementation nor incorporates offensive task presets, datasets,
exploit tools, or the paper's empirical results as BTX results.

## 3. Coordinates have a model and a training history

A coordinate is identified by checkpoint, configuration, tokenizer, architecture,
adapter and execution fingerprint, layer, site and unit. A number such as
`L12 N814` alone is not portable. Fine-tuning, quantization, architecture changes,
MLP reparameterization, or an updated adapter/framework can invalidate an
intervention; the compatibility checker refuses to silently remap it.

The execution fingerprint binds the scientific adapter modules, PyTorch version,
Transformers version when used, and the reference fp32 intervention policy.
It does not prove all transitive dependency bytes or cross-GPU bitwise behavior.
Hardware/driver/precision qualification belongs in deployment evidence.

Training-recipe facts are independent of those coordinates. The profile records
pretraining dropout, fine-tuning dropout, optimizer, weight decay, training token
count, dataset provenance, normalization, activation and post-training. Each fact
is `unknown`, `reported`, or `measured_in_this_study`, with a source reference.
Unknown means null. A publisher cannot convert a library default into measured
training history merely by importing a configuration file. The status is still
a signed assertion until independently verified; the signature does not validate
its scientific truth.

Dropout/redundancy/polysemanticity/superposition relationships are hypotheses for
controlled study. They are not hardcoded inference rules. Nor is “all modern
LLMs use no dropout” a supported product assumption. Inference uses `eval()`;
switching dropout on during inference is not equivalent to changing training.

## 4. Numerical operations

All operations are data, not Python expressions, executable hooks, arbitrary
module paths or remote plugins. Signed coefficients are integer millionths.
Control tensors are finite little-endian float32 with exact tensor hashes.

| Operator | Site and interpretation |
|---|---|
| `neuron_add` | Add to selected post-activation MLP coordinates; absolute units or supplied residual-median/down-column calibration. |
| `neuron_scale` | Multiply selected MLP coordinates. Zero is ablation; negative reverses the coordinate's contribution. |
| `neuron_clamp` | Clamp selected MLP coordinates to explicit bounds; a negative arm does not invert a clamp. |
| `head_scale` | Scale explicitly selected full-attention head blocks before the output projection. |
| `residual_add` | Add a signed unit direction after a decoder block, optionally scaled by that token's original residual norm. |
| `residual_project_out` | Remove a specified fraction of the projection onto a signed unit direction. |
| `sae_feature_add` | Rectified-affine SAE feature edit with exact encoder/decoder/bias identity and preserved reconstruction residual. |

For token-normalized residual additions:

```
h_after = h_before + s * ||h_before||_2 * v_hat
```

All normalized additions at one hook use the original pre-site norm. Listed
operations still execute in order: an add followed by a scale is not equivalent
to a scale followed by an add. Projection/removal and other operations likewise
must not be silently commuted. The composition version is
`ordered/pre-site-norm/v1`.

GELU MLP hooks target the input to the down projection after GELU. SwiGLU hooks
target the post-product activation `silu(gate) * up`, not just the gate or up
branch. Head scaling requires a known layout: Qwen3.5 linear-attention value
heads are explicitly refused by the generic full-attention path.

Token phase is determined from the original prompt length and explicit absolute
token offsets, including incremental-cache decoding. Prefill/decode and bounded
intervals are signed in the profile. Every request has a private cache and a
namespace containing the profile, exact model, runtime, precision, tokenization
and scheduling policy. KV state is never shared across distinct profiles.

FP32 operations restore the original activation dtype after finite/delta checks.
The local maximum activation delta is a numerical guard, not behavioral safety.
No model parameter tensor is mutated. One request owns a model instance's hooks;
cleanup occurs on normal completion, exceptions, cancellation and revocation.

## 5. Data capsules and signatures

The carrier is a bounded SafeTensors file. It contains vector/matrix data and
metadata with the canonical profile and its ML-DSA-44 signature. A scalar marker
makes profiles with only scalar settings valid nonempty tensor containers.

The signed profile includes each tensor's dtype, shape and typed byte hash.
The reader checks schema, exact tensor set, offsets, contiguity, total file size,
finite values, vector normalization, dimensions and signature before import.
Unknown fields, duplicate JSON keys, floating-point signed coefficients, unknown
versions, executable payloads, trailing bytes and unexpected tensors fail closed.
The canonical JSON profile is BTX-NeuronLab-specific; it is not a claim of RFC
8785 or an existing native BTX consensus record format.

Limits include 16 MiB capsules, 1 MiB metadata JSON, 128 tensors, 64 operators,
256 selected coordinates per scalar operator and 8 MiB per numeric tensor.
Private worker responses are at most 8 MiB; native requests at most 256 KiB.
The graphical vector editor materializes at most 65,536 coefficients. Larger
reviewed matrices use the offline capsule API, not an unbounded text editor.

The add-on uses real ML-DSA-44 signatures through an installed OpenSSL binary.
No algorithm downgrade is accepted. The local research publisher identity is
separate from wallet keys and is **not automatically an admitted BTX PIT root**.
A future native identity binding needs its own signed delegation and admission
implementation; merely displaying the same name is insufficient.

## 6. Receive, inspect, experiment, activate, revoke

```
RECEIVED BYTES
  -> STRUCTURE + CONTENT + SIGNATURE VERIFIED
  -> QUARANTINED / UNTRUSTED PUBLISHER
  -> LOCALLY TRUSTED PUBLISHER (operator decision)
  -> COMPATIBLE EXACT MODEL + REVIEWED LOCAL EXPERIMENT
  -> OPTIONAL GENERATION-BOUND LOCAL ACTIVATION
```

Download, signature validity, publisher trust, scientific effect, and activation
are separate facts. A valid signature from an unknown publisher is not a grant.
A model's suggestion is not a confirmation. Editing/forking makes a new immutable
profile and parent reference; it does not overwrite a published setting.

Activation uses an expected generation to reject stale approvals. Revoking a
publisher disables its active profiles and increments the local fence. The
inference worker checks trust/activation before, during and immediately before
releasing the result. The GUI cancellation epoch also prevents releasing a
cancelled result. This is local revocation; the package does not claim a globally
propagated PIT revocation service. An application-only hash-chain journal detects
some accidental/local edits but is not externally anchored tamper-proof storage.

## 7. BTX distribution and swarm research

The native bridge carries the signed data through existing verified BTX retrieval:

```
local signed public capsule
 -> native-confirmed hostmodel(path, {pin:true,publish:false})
 -> explicit native resource URI + independent expected profile ID
 -> native-confirmed getmodel(uri, {mode:FREE_ONLY})
 -> native verified checkout via exportmodelpath
 -> exact capsule verification and private quarantine
 -> separate local trust / experiment / activation
```

No unknown metadata or model-generated command becomes an RPC. The bridge
reconstructs only these fixed operations. Native search publication is disabled;
this is a compatibility carrier, not a global intervention search service or a
new ModelNet artifact registry. The node may display the carrier in its ordinary
catalogue; it must not be advertised as a useful model checkpoint. Unknown model
architectures remain unrunnable. Native transport success still needs real BTX
integration and physical-host tests.

A sharded study plan contains immutable work-unit IDs for every factor/seed
combination. Each authorized participant can execute a unit and return a signed
receipt. The aggregator rejects duplicate work IDs and different study designs.
The implementation provides plans, execution and receipts; **it does not add a
swarm scheduler or automatically admit remote workers**. Assignment can be
integrated with native BTX leases only after those native interfaces qualify.
Two local signing keys or processes are not two independently operated machines.

Private/realm capsule export to the public transport path is refused. Files may
be exported privately under explicit user control, but encryption, private realm
routing, independence proofs, trusted-evaluator admission, automatic promotion,
paid work, L2 settlement and remote activation are not synthesized here.

## 8. Experiments and causal caution

A comparison runs the same exact model under baseline, selected profile and a
sign-reversed profile. It records output tokens, actual selected pre/post
activations, timing and cache identity. Sign reversal means `x(-s)` for scaling,
not `x(1-s)` and not a guaranteed reversal of semantic behavior. Baseline examples
are not quality benchmarks. Negative results remain evidence.

Direction extraction computes a declared mean contrast, optionally removes
neutral principal components, then normalizes. It binds input matrices and the
result vector to hashes and signs an extraction receipt. A contrast corpus and
a grand mean are different estimators; the caller must describe the actual
experiment. Static down-column/unembedding projections are explicitly not causal
circuits or complete logit-lens analysis.

Paired evaluations use task-clustered bootstrap: multiple seeds for one task
remain in the same cluster. Duplicate task/seed rows are refused. Trial budgets
apply an explicit familywise adjustment; BH adjustment is also implemented.
A receipt cannot establish real preregistration or holdout protection. Repeated
signatures over identical samples cannot manufacture extra sample size.

The included factorial harness controls the synthetic data generator/order,
seed, dropout, activation, optimizer and weight decay. GELU and SwiGLU parameter
counts are approximately matched, not identical compute. Optimizers use distinct
fixed learning rates, so results are recipes—not a clean isolated optimizer-law
estimate. The tiny model uses the same dropout rate at its implemented sites;
it does not isolate attention, embedding and residual dropout effects separately.

Reported selectivity/label entropy and participation-ratio rank are descriptive
proxies on synthetic labels. They do not measure universal monosemanticity,
polysemanticity, diffused redundancy, or superposition. Full-scale studies need
held-out concepts, ablation/redundancy curves, random-direction and matched-dose
controls, multiple checkpoints, independent seeds and task-specific quality
metrics before drawing those conclusions.

## 9. Atlas experience and local assistant

The new workspace preserves the near-black spatial/inspector language. The
perspective layer scene shows the registered model's real dimensions. Unmeasured
bins are structural, not invented neurons/activations. It renders at most 48
layers and 96 bins per layer, labels aggregation, and exposes exact coordinates
in ordinary controls/tables. The scene is an event-driven Canvas2D perspective
projection; it does not claim a new native 3D/WebGL engine.

Seven tabs cover editing/comparison, distribution/trust, recipe facts,
directions/lenses, factorial studies, evidence and bounded routing. A native
local model may use the same approved settings through the explicitly installed
`BTX_MODEL_GENERATE` adapter. This does not retrofit hooks into arbitrary already
running agents or vLLM/llama.cpp processes. Ordinary Atlas and monetary functions
remain available without an LLM or this worker.

Context routing is a fixed numerical policy over operator-declared features.
It chooses only locally approved exact profile IDs or baseline; no code or new
capabilities can be emitted. Feature extraction and automatic per-agent dispatch
are explicit integration work. Current routes execute at request boundaries;
there is no hidden mid-request profile change or shared cache reuse.

## 10. Performance and qualification boundaries

Inspection runs separately from the renderer and monetary node. Scalar edits
copy only request activations, never model weight tensors. Captures transfer only
selected coordinates from accelerator to CPU and enforce explicit record caps.
Old scenes/listeners are disposed, drawing is event-driven, and diagnostic data
is paginated/bounded.

This is a reference scientific PyTorch implementation. Per-token numerical
checks can synchronize a GPU; FP32 loading and repeated processes/model loading
can be expensive. A verified file tree is rehashed before model loading.
Production throughput, shared-resident models, optimized fused kernels, GPU
memory quotas and preverified immutable model snapshots require separate
engineering and measured hardware tests. The 48-case CPU experiment and browser
smoke are not production latency, memory or GPU-performance proofs.

Independent tests are required before enabling a native shipped release: compile
Rust/Tauri; qualify each actual engine/architecture; verify native prompts and
IPC; test native peer transport on physical hosts; check process sandbox/ACLs;
measure shared GPU/renderer resource pressure; and preserve all previous Atlas
wallet/parity gates. The package intentionally does not retire Qt or weaken any
existing BTX release gate.
