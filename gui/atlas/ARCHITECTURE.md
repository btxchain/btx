# Architecture and implementation decisions

## 1. Independent app, existing authoritative node

`web/` is a local static application, not a network site. Tauri's native app hosts
it and exposes enumerated commands only to the packaged main window. The Rust
core makes bounded HTTP JSON-RPC calls to a literal loopback node. It neither
schedules swarm work nor stores wallet keys. `btxd` and its existing helpers
remain authoritative. Closing the app does not terminate the node.

The frontend has no runtime packages. The rendering component uses WebGL2
buffers/shaders directly and Canvas2D when no GPU context is available. Standard
DOM provides accessible lists, forms, dialogs and tables alongside the canvas.
This reduces the app's JS dependency surface; it does not remove browser, Rust
crate, operating-system or graphics-driver dependencies.

## 2. Authority and effects

Read observations use a native allowlist. Some apparently harmless methods (new
address generation, network searches, imports and model acquisition) mutate or
disclose state, and therefore use prepared operations. Arbitrary operator RPC
commands require an immutable prepared body and native OS review. Known raw-key
exports are denied. Unknown new native methods still need human review; a complete
future-proof secret classification is not claimed.

Prepared approvals expire, bind connection epoch and exact method/wallet/body,
and are consumed before the native confirmation is shown. A durable intent is
written before submitting a mutation. Lost responses become unknown; the app
never silently submits a second operation. The audit journal is local evidence,
not an authoritative blockchain receipt and not tamper-proof against the same user.

The payment composer has a stronger separate path: exact draft; native funded
PSBT; recipient script, change ownership, fee and coin selection checks; canonical
unsigned transaction skeleton; unchanged skeleton after signing/finalization;
separate broadcast confirmation. Wallet state remains on the node. Watch-only or
multisignature flows may require exported PSBTs and external signatures.

## 3. Evidence projection

The graph contains local observations only. Node peers, ModelNet transport pins,
byte verification, observer membership and independently verified ancestry are
separate fields. No relationship is inferred from model names. Source timestamps,
expiry, unavailable helpers and partial coverage remain visible.

Polling is bounded, non-overlapping and paused in hidden windows. Reconnection
changes the epoch. A snapshot is marked local/non-atomic; results from separate
RPCs are never promoted to a transactionally consistent global snapshot.

## 4. Local LLM

The human selects a complete byte-verified local model and grants a bounded
session. Native `generatemodel` receives the actual parameter shape documented by
BTX, up to 512 output tokens. Context contains compact redacted node/model status;
wallet information, peer endpoints, credentials and private source paths are
excluded. At most two generations and bounded extra read calls occur per turn.

Responses are text or validated read-only surface proposals. Suggestions may
name an operation; a human opens its normal form and supplies/reviews arguments.
No model output becomes a wallet transaction, raw RPC request, shell program or
approval. Revocation stops future turns, not an already running native generation.
There is no cloud execution fallback. Missing runtime or model profile is an error.

## 5. Adaptive interfaces and research

Surface documents are a restricted AST, not JSX, HTML or JavaScript. Supported
components include stacks, text, source-bound metrics/tables/sparklines and fixed
navigation actions. Node/depth/UTF-8 budgets, source allowlists and revision checks
are enforced. Persistent revisions are local UI preferences, not signed native
protocol objects. There is no privileged custom-code extension escape hatch.

Workflow DAGs are local drafts, with cycle checks; exporting a draft does not
schedule it. Research accepts actual bounded capture documents and evaluation
records with visible unverified provenance. SafeTensors inspection reads headers,
not the full model or its quality. The manual CPU capture tool records specific
Linear outputs from local SafeTensors without remote code, but requires separate
runtime provisioning and security review.

## 6. Resource bounds

Source graph: 100,000 entities / 200,000 edges. GPU scene: at most 10,000 visible
entities / 30,000 edges; excess is disclosed as sampling. Canvas fallback: 3,000
points and a bounded edge subset. DPR at most 2. Event-driven frames only. Typed
array worker transfer; old generations dropped; worker/event/GPU resources released.

RPC: request at most 256 KiB, response at most 4 MiB; finite connect/read/write
budgets. Four concurrent read slots; serialized mutation path. Prepared operations
at most sixteen, money plans at most eight. Generated surfaces at most 64 KiB,
depth 12 and 256 nodes. Audit file at most 16 MiB, failing closed at its limit.

These are implementation bounds, not whole-process heap or worst-case-time proofs.
Browser IPC, native dialogs, graphics stacks and upstream dependencies have their
own allocations. Profile them on each target platform and measure simultaneous
local model workloads before choosing final release budgets.
