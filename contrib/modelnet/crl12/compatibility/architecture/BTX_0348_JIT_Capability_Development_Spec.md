# BTX 0.34.8
## Just-in-Time Modular Capability
### Default architecture, implementation contract and release verification

**Document ID:** BTX-SPEC-0348-CAPABILITY-01  
**Revision:** 1.0 · **Research date:** 17 September 2026  
**Canonical edition:** Markdown. Word and PDF contain the same specification and acceptance catalogue.  
**Execution target:** the private 0.34.8 tree after the current NETWORK-02 and agent-package convergence work hands off.

> An agent asks for a capability. BTX resolves an exact implementation, acquires only the missing verified assets, places them in the appropriate local memory tier, prepares a compatible runtime, and returns a generation-bound readiness lease. The result is usable local intelligence, not merely a completed download.

# 1. Assignment and scope decision

## 1.1 Deliver the framework in 0.34.8

Implement capability resolution, dependency locking, tensor-aware acquisition, verified materialization, streaming loading, tiered residency, adapter composition, predictive prefetch, compiled-artifact reuse, private prefix/KV caching, peer-accelerator transfers, MoE expert paging and CXL/NUMA-aware placement as this release's engineering scope. They are not a future-roadmap appendix. The new capability framework becomes the normal installed control path for supported local-model workflows.

A feature is delivered only when a registered production call path uses it and its acceptance tests execute. A class declaration, mocked adapter, source grep or configuration flag is not an implemented backend. Hardware-dependent paths must have real implementation and a reproducible hardware test recipe; absent hardware is recorded as NOT_RUN, never as PASS or an excuse to silently delete the requirement. Release support is advertised per tested backend/platform. The overall requested scope is not complete while a mandatory delivery is merely a stub.

The integrated system supports both deliberate full-model installation and just-in-time composition. It does not require every task to download a different model. Reusing a resident base, adding an exact compatible adapter, recovering a warm runtime, or choosing an adequate already-local specialist can be better than moving a larger checkpoint.

## 1.2 Breaking model-plane changes are authorized

The operator explicitly does not require compatibility with the 0.34.7 model network. Remove legacy compatibility as a release gate where it obstructs the design. Breaking model protocols, package profiles, API contracts and local metadata schemas are allowed with explicit versioning, export/migration tools and a documented cutover. Do not run a second old/new stack indefinitely merely to preserve obsolete behavior.

This is a model-platform cutover, not an implicit instruction to alter BTX monetary consensus. Capability resolution does not require changing existing funds, issuance, transaction validity, ExactReplay, chain selection or wallet ownership. No such monetary change is specified here. If implementation discovers a genuine need for one, produce a separate proposed consensus change with activation, fund-safety and rollback analysis before making it. Do not interpret the word compatibility as permission to corrupt a ledger.

Existing immutable resources retain their byte identities unless a new canonical resource format is deliberately introduced. A renamed schema or faster loader must not assign different bytes to an old digest. When a representation changes, produce a distinct representation ID and an exact source relationship. Bounties and funded release terms continue referring to the resources and commitments actually authorized.

## 1.3 A default framework is not blanket authority

Default distribution includes the resolver, local capability service, verified range reader, memory broker, lockfile handling and eligible runtime adapters. The first-run journey offers a finite local capability policy once rather than asking for permission at every internal step. After approval, an agent can acquire and prepare covered capabilities unattended within exact storage, bandwidth, memory, runtime and expiry bounds.

Installation, process execution, public seeding, external-origin access, private-fabric sharing, private state caching and monetary spending remain separately identified effects. Automatic BTX spending stays zero unless an existing independently approved wallet mandate authorizes a specific action. A package does not authorize its own installer, executable cache, RDMA access, or next-generation agent goals.

## 1.4 Preserve the useful product boundary

BTX remains the identity, acquisition, preservation, capital and local provisioning system. It does not become a public prompt router, token-metering service or inference marketplace. Local runtimes may expose a user-authorized loopback or private application interface; the public model network never forwards inference calls. An agent state can use the same system, but this release does not add governance, generic messaging or compute procurement.

# 2. Evidence, baseline and research method

## 2.1 What was inspected

The public BTX baseline inspected through the GitHub connector is commit `42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b`. Its model store exposes verified pieces, indexes/proofs, quota and pinning; it is not evidence that the private capability layer already exists. The supplied NETWORK-02 and AHP-001 documents are design baselines, and the user's private screenshots are progress reports, not independently executed runtime evidence. [B01–B03]

Source-level research for this specification includes ModelExpress loading strategies, vLLM's sleep allocator, llama.cpp's lazy/mapped loader, SafeTensors metadata validation, MLX's reader-backed tensor construction, NIXL registration/transfer examples, LMCache's engine, Mooncake transfer lifetime contracts and MoE-Infinity's expert residency interface. Exact inspected commits or blob identifiers, paths, scope and adoption decisions appear in the research register. These are static observations; no upstream benchmark was reproduced for this package. [R01–R09]

## 2.2 Important consequences of the source review

ModelExpress distinguishes an ordinary source miss from a failure that has already mutated the destination model, and it avoids marking a healthy source stale because the destination ran out of memory. BTX must make the same distinction in fallback and rollback. Error tracebacks or callbacks can retain tensor allocations after an apparent failure; destroying the visible plan object is not proof that memory was released. [R01]

vLLM sleep can preserve selected allocations in CPU memory while discarding other allocations. Wake-up remaps memory, but discarded allocations are not thereby restored. BTX readiness must distinguish mapped, populated, verified, and runnable states. The reviewed allocator also synchronizes before unsafe unmapping and handles ROCm placeholder lifetimes separately. [R02]

SafeTensors and MLX describe tensors using bounded headers and byte ranges; this makes range-aware loading practical. It does not make a sparse incomplete file safe to hand to an ordinary reader. Missing regular-file extents may read as zeros, and model loaders can prefetch beyond the application's intended tensor order. BTX must gate reads and use explicit streaming adapters or a verified virtual filesystem. [R03–R05]

Mooncake's transfer interface explicitly documents that a wait timeout does not cancel the physical transfer. NIXL requires transfer handles and registered memory to survive until completion and cleanup. BTX must retain buffer leases after logical cancellation until the underlying backend is quiescent. A stale callback must not write into memory reassigned to a new model generation. [R06, R07]

MoE-Infinity separates variant generations, demand/prefetch/transfer/execution leases, workspace reservations and retirement. BTX uses those principles for expert residency rather than treating a loaded expert as an unqualified cache entry. LMCache's runtime-specific GPU connectors demonstrate that KV state is not a portable blob independent of model/runtime geometry. [R08, R09]

## 2.3 First private-tree audit

Record branch, HEAD, tracked diff hash, relevant untracked-file hashes, compiler/build configuration, binary hashes and test environment. A dirty tree is not identified by HEAD alone. Read the completed NETWORK-02/AHP handoffs and retain every unresolved prerequisite. Discover existing implementations before creating modules.

Trace these actual paths: package inspection → variant resolution → VerifiedManifest → transfer credits → committed pieces → local export; runtime plan → executable trust → worker launch → allocation → load → readiness; sleep/cancel → fence → reclamation. Reproduce previously found manifest-binding, unknown-artifact, hard-credit, diversity, staging-ID and commit-race regressions. No parent checklist can hide an unexecuted child requirement.

Write `audit/capability-baseline.md`, `audit/capability-contract-map.csv` and `audit/capability-cutover.md`. Tag each proposed symbol as REUSED, EXTENDED, REPLACED or NEW, with actual path and call site. Carry a distinct status for static implementation, native execution, real runtime, real hardware and WAN evidence.

# 3. Performance objective: time to useful capability

## 3.1 Define the metric precisely

Define TTC as elapsed monotonic time from an authorized `ensure` request to the declared readiness target. Targets include VERIFIED_FILES, RUNTIME_LOADED, RUNTIME_READY and FIRST_USEFUL_RESULT. A process listening on a socket is not first useful result. The latter requires a bounded workload-specific check, whose input, expected properties and quality threshold are recorded.

Record discovery, resolution, source wait, network read, proof verification, storage commit, tensor materialization, host/device copies, transformation, compilation, warmup and first result as a trace DAG. Overlapped stages are not added as if serial. TTC is the critical path through prerequisites and resource waits. Report wall time and stage occupancy separately; concurrency can make their sum exceed wall time.

For a serial path, a diagnostic estimate can sum stages. For a saturated streaming pipeline, throughput is limited by the slowest sustained stage plus fill/drain and non-overlappable barriers. Never claim speedup by counting bytes in each overlapping stage as independent completed work. Attach estimate confidence, sample count and configuration fingerprint to predictions.

## 3.2 Optimize movement before inventing faster movement

The default candidate order is not a fixed storage hierarchy. Evaluate eligible alternatives against the request: already-ready local runtime; compatible resident base plus missing adapter; reusable host representation; verified local files; verified local peer; private-fabric representation; native regional/global peers; explicitly allowed external origin. A GPU source may be slower than local NVMe if its layout is incompatible or its links are congested.

A 40-GiB payload needs about 34.36 seconds on an ideal 10-Gbit/s link; a 400-MiB adapter needs about 0.336 seconds. These are payload-only arithmetic bounds, not BTX measurements. Avoiding a full checkpoint can matter more than improving a loader by a modest percentage. Dense inference still requires every tensor its execution graph reads; sharding does not remove that dependency.

## 3.3 Measurement contract

Benchmark identical model, quantization, context, batch, runtime build, hardware and correctness target. Separate cold source, warm disk, warm page cache, warm host, warm device, resident adapter and warm prefix cases. Flush only controlled test caches; never drop host-wide caches on production. Measure useful throughput, first-result latency, peak committed RAM/VRAM, pinned bytes, storage/network amplification, prefetch waste, cache hit accuracy, energy where available and failure recovery.

Initial engineering success gates are relative: no correctness regression; bounded resources at configured limits; no unexpected external traffic; and a measured reduction in at least one relevant TTC bottleneck without a hidden unacceptable regression. The package does not promise a universal millisecond cold start.

# 4. Architecture and authority planes

## 4.1 Three planes

**Monetary plane — `btxd`.** Owns chain consensus and wallet authorization. It receives only explicitly authorized economic requests through existing interfaces. No tensors, KV state, model rankings or runtime outcomes change monetary rules.

**Public model plane — `btx-modeld`.** Owns canonical model identity, signed discovery, provider routing, native transfers, durable model stores, packages, public preservation and economic coordination records. It serves verified bytes, not arbitrary pointers or execution requests.

**Local capability plane — proposed `btx-capabilityd`.** Owns local resolution policy, residency, finite memory/resource reservations, local workers, prefetch and readiness leases. Bind to an owner-only Unix socket or authenticated equivalent. It is not reachable through public model RPC, relay, explorer or gossip. Reuse an existing equivalent local service if private code already supplies one.

Runtimes execute in narrowly scoped workers or connect through authenticated local adapters. Optional private-fleet coordination is separately enabled and authenticated under an organization trust domain. It shares approved immutable representations or private state; it is not the public directory.

## 4.2 Common components, not parallel stacks

Reuse VerifiedManifest, TransferSession, origin broker, import coordinator, package codec, events and existing finite wallet policies. Add a range-consumer interface and scheduling hints to the existing transfer path rather than a capability-only downloader. Reuse the existing storage journal for canonical bytes; store runtime-derived state separately with references to canonical objects.

One host resource broker arbitrates disk, RAM, pinned RAM, device memory, fabric credits, compilation workspace, network and concurrent jobs. Existing transfer reservations and new runtime reservations must share its host-level ceilings. Separate processes may have local sub-budgets, but cannot each assume ownership of all available memory.

## 4.3 Trust domains

Use explicit scopes PUBLIC_MODEL, LOCAL_USER, ORGANIZATION and RUNTIME_PROCESS. Immutable public model bytes can be shared according to local policy. Runtime executables and compiled caches require independently accepted software authority. KV/prefix state is LOCAL_USER by default; approved ORGANIZATION sharing requires tenant-specific keys and policy. Memory addresses, registration keys, prompts and hardware fingerprints never enter public model records.

The operator can permit one integrated plan to acquire and run a capability. That plan binds resource versions, runtime identity, maximum effects and expiry. It does not authorize arbitrary tool calls produced by the loaded model. Package AGENTS.md remains scoped explanatory data, not a replacement for user or coding-agent policy.

# 5. Capability identity, package profile and lockfile

## 5.1 Separate identities

Maintain distinct identifiers for canonical model, transport artifact, package core, capability recipe, runtime representation, session generation and private prefix state. A capability is not merely a display label attached to a model. A recipe can reference a base, adapters, tokenizer, projector, runtime profile and evidence claims. Two recipes using the same weights with different tokenizer or adapter scale are different executable configurations.

Capability claims are signed statements by an issuer, not global consensus facts. Evidence binds the exact recipe digest, evaluation harness/version, dataset commitment or permitted private reference, runtime fingerprint, metric definition and observation date. A high benchmark score cannot authorize execution or override a resource limit.

## 5.2 Next package core

Propose Package Core v3 with critical extension `CAPABILITY_HANDOFF_V1`, retaining the bounded BTXPKG1 outer framing unless the private-tree audit demonstrates a concrete need to replace it. Core v3 becomes the default writer for this release. Do not emit different incompatible schemas under an already allocated version: reconcile private assignments first.

Add `capability_recipes`, `runtime_requirements`, `verification_profiles` and optional `prefetch_hints` to the signed core. Retain embedded AGENTS.md, README, exact resources, economic references and channel references. Private residency measurements, leases, actual hardware details and user authorization do not belong in the portable core. Large tensor maps and manifests are separate exact digest-bound objects, not millions of entries inside a 4-MiB thin descriptor.

The core digest domain is `BTX/PackageCore/v3`, using the existing length-prefixed application digest convention. Recipe, tensor-map, lockfile and derived-representation domains are distinct. Continue existing pure ML-DSA application-signature conventions where used. New signatures do not replace software-release trust or wallet signatures. Keep unknown critical fields fail-closed.

## 5.3 Capability recipe

A recipe declares an immutable recipe ID; one or more provided capability labels; exact component references; required versus optional dependencies; typed composition rules; supported runtime profiles; minimum readiness contract; compatibility predicates; and evidence references. Bound one resolved plan to at most 256 distinct resources, dependency depth 16 and 64 candidate recipes. Reject cycles, conflicting IDs, ambiguous provider selection and unsupported critical composition rules.

Kinds include FULL_MODEL, BASE_WITH_ADAPTERS, PIPELINE and EXPERT_RESIDENT_MODEL. A PIPELINE describes bounded typed local stages with schemas and exact component dependencies; it is not a general scripting language. Tools used by the application remain outside the recipe's authority. Tokenizer replacement, vocabulary resizing or projector changes require an explicitly supported transform recipe and validation, not an implied interchangeable accessory.

## 5.4 Lockfile

`btx.lock` pins package core, recipe, all exact component IDs, runtime adapter ABI, runtime distribution/build hash, required transforms, optional evidence profile, policy profile ID and supported feature set. Store local paths, secrets, actual device placement and transient leases outside the portable lock. Generate a lock digest over canonical bytes.

`ensure --locked` performs no semantic re-resolution or channel upgrade. `update` produces a separate proposed lock and diff, including changed runtime and quality assumptions. A concurrent process retains its old generation until a deliberate switch. A modified lock cannot reuse a previous authorization merely because the filename is unchanged.

# 6. Resolver and admission policy

## 6.1 Resolution stages

Parse exact package/recipe or a bounded structured capability query. Verify metadata and local issuer trust; intersect runtime/hardware support; resolve mandatory dependencies; inspect current residency; estimate memory/latency/cost; present eligible plans. Local selection runs without sending a machine fingerprint to a central service. Natural-language search may discover candidate claims, but a typed exact plan is required before side effects.

Apply hard constraints before ranking: source policy, executable trust, context limit, required output schema, licenses/publisher restrictions supplied by the operator, memory reserve, deadline, economic authority and evidence minimum. Distinguish unknown compatibility from false compatibility. A deadline is an objective, not authority to disable verification or use a remote API.

## 6.2 Candidate comparison

Return a Pareto set with estimated TTC interval, quality evidence, bytes missing, memory peak, transformation work, privacy exposure and support level. Do not collapse uncertain model quality and latency into a supposedly universal truth score. Deterministic tie-breaks use explicit user preference, supported local recipe, estimates and stable recipe IDs; no hardcoded CUDA preference or anti-CUDA penalty.

An already-ready lower-capacity model may satisfy the task faster, but selecting it requires the request's minimum capability/evidence contract. If no candidate satisfies it, return NO_ELIGIBLE_RECIPE with reasons. A separate operator action can relax constraints or create/fund a bounty; the resolver cannot spend or silently weaken the task.

## 6.3 Finite LocalCapabilityGrant

Bind grant to caller, policy domain, permitted package/recipe set or narrowly scoped publisher/channel rule, exact executable trust policy, effects, resource ceilings, maximum concurrent sessions and expiry. Monetary policy remains separate. Reserve host/device memory and expected storage/network exposure atomically across all jobs.

The grant can authorize resolve/acquire/materialize/load/warm/run-smoke/prefetch/sleep/release in one workflow. It cannot authorize privileged installation, arbitrary endpoints, access to wallet/SSH/cloud directories or unlimited future models. Revoke blocks new effects and retires existing sessions according to the caller's stop policy; never immediately free in-flight DMA buffers.

# 7. Residency and memory lifecycle

## 7.1 Multi-axis residency

Represent residency as a set of locations and conditions, not a single ascending enum. One model can have durable verified files, some hot pages, a sleeping CPU copy and two device generations simultaneously. Track content verification, persistence, placement, transformation, runtime readiness, privacy scope and freshness independently.

Locations include LOCAL_FILE, PAGE_CACHE, HOST_PAGEABLE, HOST_PINNED, DEVICE, CXL_NUMA, PEER_HOST and PEER_DEVICE. Some are observations, not guarantees: a page-cache hint can be evicted immediately, and a remote offer can disappear. A readiness lease names exact resources, representation fingerprint, process generation and device placement it protects.

## 7.2 Generation-bound leases

Every allocation, mapping, registration and runtime instance has an unrepeatable generation ID. Lease classes include LOAD, EXECUTE, TRANSFER, PREFETCH, COMPILE and PRIVATE_STATE. Mutation/replacement creates a new generation. Immutable canonical bytes may be shared by references, but writable runtime buffers and adapter states are never silently aliased between tenants.

Lifecycle: RESERVED → ALLOCATED → POPULATING → VERIFIED → ACTIVE → RETIRING → QUIESCENT → RELEASED. A failed or canceled population enters RETIRING/QUARANTINED, not immediately RELEASED. Reclamation requires zero logical users and a completed device/transport fence. Persist durable reservations; reconstruct transient process/device claims after restart rather than treating a stale journal as live GPU memory.

## 7.3 Physical cancellation

Logical cancellation stops new work and suppresses obsolete completions. It does not imply physical cancellation. Each backend returns a cancellation disposition: NOT_DISPATCHED, STOPPED_QUIESCENT, STILL_IN_FLIGHT or UNKNOWN. Retain registered buffers for the last two states. Use watchdog isolation and backend-supported teardown; if a process must be killed, confirm device/transport quiescence before recycling shared memory.

Never reuse a pointer solely because its plan expired. Completion includes operation ID, generation and fence token; stale-generation completion can release only its own retained references, never update the successor's READY state. Tests inject cancellation at every async boundary.

## 7.4 Capacity accounting

Reserve aligned weights, transformed copies, KV cache, activations, compilation scratch, tensor staging and DMA registration overhead. Track resident, reserved, retired-awaiting-fence and reusable cache separately. A resident-but-idle model still occupies physical memory until the backend offloads/releases it.

On Apple unified memory, host and Metal allocations can share one physical budget. Do not add virtual mappings as independent RAM copies or reserve all RAM once per device. On discrete GPUs, pageable host, pinned host and each device have separate ceilings plus global safety reserve. Reserve per-rank peaks for tensor/pipeline parallel loads, not just aggregate fleet free bytes.

# 8. Tensor maps and verified range delivery

## 8.1 Derive a TensorRangeMap

Read and verify the canonical pieces covering format headers before interpreting them. Parse SafeTensors with its exact data section offset, dtypes, shape products and `[start,end)` offsets; parse GGUF with its alignment, tensor types, quantization blocks, split-file metadata and tensor offsets. Use checked arithmetic and format-specific validation. A file's declared length alone is not evidence that its payload exists.

The map binds canonical manifest ID, file index/digest, parser profile/version and tensor names/roles, byte ranges, byte counts, dtype/quantization, optional layer/expert group and canonical piece spans. Tensor aliases/tied weights have explicit shared ranges; unexpected overlaps are rejected. Layer/expert labels derived heuristically are scheduling hints unless the adapter validates architecture semantics.

## 8.2 Authority and map storage

A publisher-supplied map is only a proposed acceleration hint until locally checked against verified headers and runtime expectations. Do not accept an offset because the map signature is valid. Persist maps as content-addressed derived data with a recipe/parser fingerprint. Unsupported formats use full-file verified loading rather than guessing offsets.

Keep range maps outside the thin package. Query them through paginated APIs; cap names, dimensions, tensor count, recursion and map bytes. A safe default is 1,000,000 tensor entries and 256 MiB parsed metadata under an explicitly reserved budget; smaller profiles can be selected. Header caps derive from the parser profile and configured resources, never unchecked remote values.

## 8.3 VerifiedRangeReader

Expose `ReadVerified(manifest, range, consumer, deadline, generation)` returning bytes plus a lease and verification provenance. Expand requested ranges to all covering canonical pieces, acquire/verify those pieces, then return the exact slice. Transport subpieces do not become trusted tensors before their canonical piece proof succeeds.

Read requests carry priority and deadline hints, not permission to bypass existing hard credits. Coalesce overlaps across compatible privacy domains. Account actual overfetch and expose it in TTC traces. Persist verified bytes once, avoid copying to an intermediate “capability store” unnecessarily, and let active readers pin the backing generation.

# 9. Canonical materialization and virtual files

## 9.1 Complete-file fast path

Create a generation-specific destination, reserve capacity, and write each verified canonical piece at its exact offset with bounded pwrite-equivalent I/O. Persist verification bitmap and generation consistently with data durability. A sparse allocation can reduce physical allocation during arrival, but its holes are not verified zeros.

Only a complete selected-file set can be exported as ordinary runtime paths. Mark immutable generations read-only and hold a materialization lease. Eliminate a second full reconstruction copy by using this verified destination as canonical source-file backing, with piece-index views for native serving. Use reflinks or safe immutable shared storage where supported; never writable hardlinks to operator-controlled originals.

## 9.2 Streaming readers and FUSE

Implement the explicit VerifiedRangeReader integration first. Add a Linux read-only virtual filesystem adapter for unmodified runtimes where practical. Every read or mmap page fault must either return verified bytes, wait within a bounded policy, or fail; it must never return zeros for missing model data. Handle reads spanning pieces, readahead, cancellation, truncation, helper death and fault-time errors.

A FUSE failure can become EIO/SIGBUS in a mapped consumer. The runtime worker must fail safely and offer a fully materialized retry. Do not present this as transparent universal reliability. No custom kernel module or unrestricted userfaultfd permission is a prerequisite for baseline use. On macOS, use the explicit reader adapter and fully materialized mmap path rather than claiming Linux fault mechanisms exist.

## 9.3 Cache and TOCTOU

Bind every view to immutable content and generation. A mutable `latest` channel never rewrites an open file. GC respects reader/execution leases. Validate existing files by durable identity and mutation detection, not just name or size. On unclean restart reverify uncertain extents before visibility; a bit in a damaged sidecar is not sufficient.

# 10. Pipelined loading and execution barriers

## 10.1 Loader pipeline

Implement bounded stages: RANGE_REQUESTED → CANONICAL_VERIFIED → STAGED → DEVICE_COPY_SUBMITTED → DEVICE_COPY_COMPLETE → TRANSFORMED → RUNTIME_BOUND. Device copies can overlap later network and verification work. Use shared buffer pools with explicit ownership; never allocate a full extra model by accident when enabling overlap.

Backpressure propagates from device/workspace availability to range requests and origin reads. One fast source cannot fill all pinned RAM while a slow GPU transforms tensors. Prioritize metadata, mandatory embeddings/early loading groups and required runtime geometry, while maintaining swarm rarity floors within total credits.

## 10.2 Readiness barrier

For a dense model, beginning load early does not mean it can produce correct output before all tensors that its graph will read are ready. A runtime declares its supported execution contract: FULL_REQUIRED_SET, VERIFIED_DEMAND_PAGING, or a specifically validated partitioned mode. Do not infer support from a format name.

Runtime readiness requires all mandatory weights and transforms, correct tokenizer/config, allocation/collective completion, required compilation and a bounded smoke test where requested. A demand-paged MoE contract may leave cold experts on host/NVMe, but they remain available under a bounded local loading policy; it must not silently skip experts or use zeros.

## 10.3 Failed strategy rollback

Each loading strategy reports CLEAN_MISS, FAILED_UNMUTATED, FAILED_MUTATED, or READY. After mutation, destroy or reinitialize destination state under a verified fence before trying a different source/representation. Do not combine partly transformed FP8 weights from one strategy with raw tensors from another. Target OOM is not evidence that a peer served corrupt data. [R01]

# 11. Runtime adapter ABI and platform delivery

## 11.1 Local adapter contract

Define a versioned adapter ABI with `probe`, `plan`, `reserve`, `begin_load`, `supply_verified_range`, `finalize_load`, `warm`, `readiness`, `sleep`, `wake`, `attach_adapter`, `detach_adapter`, `cancel`, and `retire`. Not every method is available on every runtime; capability reporting is exact, and unsupported operations use an explicitly planned full-file or reload strategy.

A worker receives only approved model handles, runtime parameters, device IDs and a finite local grant. It receives no wallet or cloud-source credentials. Resolve executables/plugins from an independently trusted runtime catalogue. Reject arbitrary environment injection, loader paths, shell strings, dynamic repository code and package-supplied remote endpoints. Public RPC has no runtime-launch route.

## 11.2 Required runtime integrations

Deliver a real llama.cpp integration for supported CPU/CUDA/HIP/Metal backends, with verified-file loading and a bounded range-reader/loader hook where supported. Deliver a vLLM integration for CUDA/ROCm capable environments with native loader, LoRA and sleep/wake handling. Deliver MLX/MLX-LM integration for Apple Silicon using its reader-backed/lazy arrays and explicit evaluation/readiness barriers. Use version-pinned runtime patches or plugins with automated rebase/conformance tests; do not claim one untested adapter name covers all versions.

Treat Ollama as a local lifecycle/import adapter where its public API supports the required semantics; do not invent internal zero-copy or expert-paging support. Intel, Cerebras and other site-specific runtimes can expose the same ABI through tested backend packages, but no universal artifact compatibility is claimed. The default portable baseline is CPU verified-file execution plus eligible locally installed acceleration, not a cloud fallback.

## 11.3 Sleep/wake

Record which memory classes were preserved versus discarded. A sleeping GPU may have released its weights to host; it is not a still-GPU-resident model. Wake reloads preserved bytes, reconstructs discarded state, checks generation and performs required barriers before READY. Never advertise empty remapped pages as valid tensors. New grants cannot change the preservation policy of an already sleeping generation without an explicit transition. [R02]

## 11.4 ABI compatibility

Fingerprint runtime distribution digest, adapter ABI, model layout, tensor-parallel/pipeline/expert-parallel geometry, quantization recipe, dtype, device architecture, relevant driver/runtime ABI, kernel library versions and required shape/config options. Distinguish exact compatibility, reproducible conversion and incompatible. Same model name is insufficient for GPU-to-GPU or compiled-cache reuse.

# 12. First-class modular adapters and composition

## 12.1 Base reuse is the primary fast path

Represent adapters as exact resources with an explicit base commitment and compatibility metadata. Required fields include base model/config fingerprint, target tensor names/shapes, adapter type, rank, scale convention, dtype, tokenizer/vocabulary assumptions and runtime support. Verify every target against the loaded base before attachment. A matching architecture label is not sufficient.

Support multiple simultaneous logical capabilities over one resident base when the runtime guarantees isolation. Each request/session pins its adapter set and generation. Adapter replacement occurs at a quiescent session boundary or through a runtime's explicitly supported per-request selection, never by mutating shared weights mid-kernel.

## 12.2 Composition rules

Do not assume two independently trained LoRAs compose correctly. Recipes can specify an ordered adapter set with exact scales and a validation profile; absent such a contract, treat compositions as separate unverified candidates. Projectors, control vectors and tokenizer extensions each require format-specific validation. A tokenizer change can invalidate embeddings, output heads and prefix caches.

Separate merged representations from unmerged adapters. A merge creates a derived artifact keyed by base, adapters, order/scales, precision and transformation implementation. Never label the merged bytes as the original base. Prefer non-destructive attachment where supported to preserve shared-base reuse.

## 12.3 Tests and useful evidence

Compare base-only and adapter-enabled outputs against the same runtime's trusted local baseline. Test wrong-base rejection, rank/layout mismatch, conflicting vocabulary, concurrent adapters, detach during active execution, cancellation and memory reclamation. A successful load proves compatibility; task-quality claims require the recipe's independent evaluation evidence. [R10, R11]

# 13. Prefetch and locality-aware caching

## 13.1 Typed intent, not an agent scratchpad

Accept finite prefetch hints containing exact recipe/resource references or bounded candidate sets, deadline, probability/confidence, maximum speculative bytes and desired tier. Do not ingest the agent's full reasoning transcript or expose prompts to public peers. Free-form planning text cannot schedule downloads or allocate memory by itself.

Compute expected benefit from probability of use multiplied by avoided critical-path time, minus transfer/placement cost, eviction cost and interference. This is a local heuristic, not a monetary valuation oracle. Record actual usefulness and cancel wasted speculative jobs promptly. Failed predictions consume their real bytes/costs; do not erase accounting because the model was never used.

## 13.2 Scheduling and anti-thrashing

Demand outranks prefetch. Bound speculative RAM, pinned memory, disk and network separately; start with at most 10% of the user-approved residency budget and two concurrent prefetch loads, configurable after measurement. Do not evict executing or leased generations. Use minimum residency time, admission hysteresis and reuse-distance estimates to avoid alternating two large models forever.

A task can prefetch a small adapter to RAM while a base stays in device memory; it need not promote all dependencies to the hottest tier. Before a deadline, replan using current throughput and runtime load estimates. Return DEADLINE_UNACHIEVABLE if necessary rather than skipping verification.

## 13.3 Cache policy

Maintain separate durable retention and transient warmth. Pins preserve local canonical data; warm reservations preserve expensive runtime placement for a bounded time. Use byte-aware admission and measured reload cost rather than raw item count. Tenant quotas and fair scheduling prevent one agent from keeping all GPU memory by repeatedly touching entries.

A cached representation is eligible only after its fingerprint and trust domain match. Exact physical-byte reuse across model versions is allowed when independently checked against each destination commitment. Content-defined dedup remains an implementation optimization, never a substitute identity. It is part of the current engineering audit; ship it where measured worthwhile rather than requiring it for capability correctness.

# 14. Compiled and transformed runtime artifacts

## 14.1 Separate representations

Create RuntimeRepresentation records binding canonical inputs, transformation recipe, output tensor/file digest map, runtime/adapter fingerprint, target hardware and trust provenance. Examples include runtime-sharded weights, repacked quantized tensors, compiled kernels, autotuning results and safe precomputed metadata. These do not change the canonical model ID.

Transformed weights must be reproducibly derived locally or accepted under a separately trusted representation producer policy. An original model checksum alone does not authenticate the result of a lossy or opaque transformation. Record validation method: EXACT_RECOMPUTE, TRUSTED_BUILD_ATTESTATION or LOCAL_BUILD; do not merge these into one ambiguous verified flag.

## 14.2 Executable cache security

Compiler/kernel caches can contain executable code. Default acceptance is local generation. Organization sharing requires an independently trusted builder, exact input/runtime/compiler/hardware keys, signed digest manifest and artifact bounds. Public model publisher signatures do not authorize executable cache use. Unknown cache formats are opaque and rejected from execution paths.

Use atomic generation directories, no path traversal or unsafe deserialization, and a build sandbox where supported. Never load Python pickle, arbitrary shared libraries or startup hooks supplied inside an AGENTS.md package. A compatible cache miss triggers local compilation within budget; it does not download arbitrary replacement code.

## 14.3 Runtime cache reuse

Separate kernel-binary compatibility from autotune measurements. Hardware-specific tuning from another topology may be suboptimal even when binary-compatible. Validate shapes, dtype, compiler options, driver/runtime requirements, world size and graph-capture assumptions. Captured GPU graphs containing live pointers are generally process-generation-bound; do not serialize and replay them as portable kernels.

Record cache load time, compile time avoided, correctness checks and fallback reason. Do not claim a warm-start improvement when the warm run used fewer layers, a different quantization or omitted required initialization.

# 15. Private KV and prefix-state cache

## 15.1 Scope and key

KV state is derived from user/application inputs. Default scope is the same local tenant and exact execution configuration. It never joins public BTX discovery, erasure preservation or torrent bridges. Organization sharing is explicitly enabled, authenticated and encrypted where required.

A cache key binds model/representation generation, adapter set/order/scales, tokenizer and chat-template fingerprints, position/rope/attention settings, runtime version, KV layout/dtype, tensor/pipeline geometry, exact token prefix and multimodal inputs. Use a tenant-keyed digest for lookup so common prompt hashes are not public dictionary-testable identifiers. A digest does not authorize access to the underlying state.

## 15.2 Correctness and lifecycle

Reuse only prefixes whose tokenization and positional semantics match exactly under the adapter contract. A plain-text prefix match is not enough. Keep per-layer completeness and sequence length consistent; a partially written cache object is not available. On model, adapter, tokenizer or rope change invalidate the incompatible entries.

Cancellation, eviction and runtime retirement obey the same lease/fence rules as weights. Encrypt persistent private cache objects with tenant-managed keys and bounded expiry where local policy requires persistence. Best-effort deletion on SSD is not a secure-erasure guarantee; encryption key retirement is the relevant mechanism. Do not export private cache IDs or hit rates in public telemetry.

## 15.3 Integration

Implement local LMCache adapter support or equivalent through the runtime connector, with explicit telemetry/controller/network configuration. The inspected LMCache engine includes usage-telemetry integration; BTX must disable non-approved remote reporting and test the resulting network trace, not assume a library is private because it is open source. Runtime-specific connectors validate KV geometry. [R08]

# 16. Private peer-accelerator weight transfer

## 16.1 Eligibility and offer

A peer-GPU source is an optional organization/local-fabric accelerator, not a public internet memory server. An offer binds exact representation, device/runtime geometry, immutable generation, available tensor ranges, finite transfer lease, endpoint and expiry. Authenticate organization membership independently of public model service identity. Do not publish raw pointers, rkeys or device inventory globally.

Require an exact compatible representation or an explicitly approved conversion. Postprocessed tensors may have renamed fields, extra buffers or altered layouts; discover the complete runtime weight set before publication and freeze it. A successful transfer does not mean the destination has completed its own initialization/warmup. [R01]

## 16.2 Data-plane security

PQ1 control authentication does not automatically protect raw RDMA traffic. Define transport assurance as NATIVE_PQ1, TRUSTED_FABRIC or VERIFIED_EXTERNAL, and display it accurately. Private RDMA requires approved isolation and backend protection; deployments requiring encrypted data transport must use an appropriate supported path or fall back to native encrypted transfer. Integrity checks and tenancy authorization remain required even on a trusted fabric.

Register only dedicated immutable weight buffers or narrow approved regions. Default remote access is disabled until a bounded capability grant is created. Use least-privilege registration, expiry and revocation; drain transfers before deregistration. Do not register an entire process heap that also contains KV state, prompts or credentials. [R06, R07]

## 16.3 Destination verification

Transfer into a quarantined destination generation. Verify exact tensor/representation digests before exposing pointers to compute. For canonical raw ranges, check canonical commitments; for transformed tensors, use the independently accepted representation manifest and transformation trust policy. GPU-side verification may avoid a host round trip if implemented and conformance-tested; otherwise the verified host path remains correct.

A remote pointer becoming invalid, a partial transfer, wrong rank, target OOM or timeout produces explicit cleanup/fallback. Retain source/destination leases until physical completion. Never mark the source malicious for a target-local initialization error.

## 16.4 Backend implementations

Implement NIXL/UCX backend on supported Linux CUDA/ROCm builds, with real capability probing and no stub-library fallback advertised as hardware support. Keep backend libraries outside monetary-only builds. Add a portable authenticated host-buffer transfer backend for testing and non-RDMA environments. On Apple, use local shared-memory/Metal or native peer-file acquisition; do not pretend Linux NIXL is a macOS path. [R06]

# 17. Direct storage-to-device and verified zero-copy

## 17.1 Correct fast paths

GPUDirect Storage-style APIs can move supported local/storage data directly to device memory. They are not automatically a native BTX network transport. Use them for immutable verified local objects or a staging destination whose bytes are checked before execution. Preserve alignment requirements, cancellation fences, I/O error handling and device ownership.

Implement host-staged asynchronous baseline on every supported runtime. Add CUDA GDS where genuinely available; add the corresponding tested HIP/ROCm transfer path without renaming a CPU copy as direct storage. On unified-memory systems, avoid needless copies by sharing verified immutable buffers where the runtime permits, while respecting actual CPU/Metal coherency and lifetime rules.

## 17.2 Accounting and fallback

Report actual path, copy count and bytes at each boundary. The presence of a GDS library is not proof a particular file read bypassed host staging. A fallback is allowed within policy and must be visible in traces. Fallback cannot reintroduce unverified memory, undisclosed external origins or a second full model allocation beyond the reserved budget.

# 18. MoE expert residency as current release work

## 18.1 A real runtime integration, not a diagram

Deliver an expert-residency manager and at least one actual supported MoE runtime/model profile in 0.34.8. Integrate at expert-dispatch and load points, not only through an offline map generator. Pin router/shared weights and maintain exact mappings from layer/expert to tensor ranges and runtime representation. Include quantization-specific scales and companion tensors in the expert unit.

Use HOST_READY, LOADING, DEVICE_READY, EXECUTING, RETIRING and FAILED state per expert generation. Reserve aligned payload plus dequantization/workspace. Demand, prefetch, transfer and execution each hold leases. Do not replace an expert while its previous generation is referenced by an in-flight batch. [R09]

## 18.2 Safe paging

Token-critical expert misses may page from approved local host/NVMe/CXL tiers with a bounded wait. Public WAN lookup inside every token is not a viable default and is prohibited for the normal expert-dispatch path. Network acquisition happens as prefetch or a deliberate paused-capability preparation step. If a required expert is unavailable, wait/fail according to policy; never skip it, substitute zeros or change routing to preserve a misleading throughput number.

Layer-wise prefetch can use recently observed expert selections and workload phase, but prediction must not alter the model's mathematical routing. Keep access traces private. Distinguish prefill and decode policies and measure miss stalls, transfer bytes, cache hit rate and output correctness against an all-resident baseline.

## 18.3 Thrashing control

Protect active experts, cap speculation, reserve a demand slot/workspace and use admission hysteresis. Track working-set size versus available memory. If the workload cannot fit an acceptable active working set, return a planned slower offload mode or capacity error; do not advertise a fast profile that swaps the entire model repeatedly per token.

Use deterministic micro-models for correctness and a real supported MoE checkpoint for integration. Inject wrong-generation completion, eviction under execution, stale expert map, hot-set shift, batch fanout and CXL/host-tier loss. Real-hardware performance evidence is required before advertising throughput for a profile.

# 19. CXL, NUMA and emerging fabrics

## 19.1 Discover what the operating system exposes

Implement topology discovery now using documented OS/runtime interfaces: NUMA nodes, memory classes, local/remote CPU distance, available device memory and supported transfer links. CXL memory that appears as OS-managed memory is a distinct placement tier with measured bandwidth/latency, not an automatic HBM substitute. Do not configure host fabric switches or hotplug memory without explicit operator action.

On Linux, use a narrowly scoped NUMA placement adapter and supported memory-tier information; where a persistent/DAX mapping is configured, apply its own durability and mapping contract. On macOS, report unified memory rather than fake NUMA/CXL capabilities. Unsupported topology information is UNKNOWN, not zero cost.

## 19.2 Placement planner

Choose placements using measured paths and runtime accessibility: device → host pinned → host pageable/NUMA/CXL → local file → local peer. The ordering is a graph, not a hard universal ladder. Some CXL paths may be slower than local DRAM; a local GPU peer may require expensive layout conversion. Reserve the real physical pool once and account competing users.

Implement tier failure and offline handling: cancel new placements, drain active leases, migrate approved generations if possible, otherwise fail affected runtime safely. Do not dereference a disappeared mapping or silently reload private state from a public source.

## 19.3 Fabric evolution

Expose backend capabilities rather than hardcoding future product names or advertised link rates. UALink, NVLink, PCIe and vendor fabrics become useful only through supported runtime/driver transport contracts. BTX should consume such backends, not invent a new interconnect driver. Deliver the abstraction, real supported backends, topology tests and hardware recipes in this release; do not label simulated future hardware as a completed hardware test.

# 20. Generation switching, rollback and recovery

## 20.1 Atomic capability updates

Prepare a new package/recipe/runtime generation without changing the active one. Resolve and validate dependencies, reserve memory, acquire missing bytes, build transforms, load and smoke-test. Atomically switch the application's capability handle only after its chosen readiness barrier passes. Old generation remains leased until requests drain.

A latest-channel update is a candidate, not an instruction to replace a running agent. Rollback reselects a previously verified generation under the same software and model trust floor; it does not authorize a vulnerable client downgrade. Persist the exact old/new lock IDs and switch transaction.

## 20.2 Crash behavior

Journal plans, approved effects, reservation ownership, verified range commits, representation builds and generation switches. Runtime/device state is volatile. On service restart reconcile process liveness and backend registrations before adopting or retiring it. An orphan worker is not automatically trusted because its socket still exists.

Idempotency binds caller, plan ID and generation. Duplicate ensure joins compatible acquisition work but retains separate runtime/tenant grants. Canceling one subscriber cannot cancel another user's active shared model or release shared buffers early. Use crash injection between every durable transition.

# 21. API, SDK and agent experience

## 21.1 Operations

The public model server remains read-only/byte-serving under its existing contract. The following operations are local capability-plane contracts. Reconcile names against private code before registration; extend existing planners rather than create aliases with conflicting authority.

| Operation | Required input | Output and effect |
|---|---|---|
| resolvebtxcapability | Exact package/recipe or bounded query; constraints | Eligible candidates, evidence and rejection reasons; read/declared metadata fetch |
| planbtxcapability | Candidate, lock or constraints; policy reference | Immutable plan, TTC estimate, resource and exposure requirements |
| ensurebtxcapability | Plan ID, expected digest, local grant, idempotency key | Job/lease handle; executes covered acquisition and local preparation |
| getbtxcapability | Job or lease, expected generation | Multi-axis state, readiness target, error and trace cursor |
| cancelbtxcapability | Job/generation and caller | Logical cancel plus physical cleanup disposition |
| releasebtxcapability | Lease/generation | Releases caller reference; drains before physical reclamation |
| prefetchbtxcapability | Typed hint, resource cap and expiry | Low-priority job; never opens wallet |
| sleepbtxcapability / wakebtxcapability | Lease, exact preservation policy/grant | Runtime-managed transition with readiness revalidation |
| getbtxresidency | Authorized local scope/filter | Tier/lease/physical-budget facts, no public pointers |
| inspectbtxtensormap | Exact verified artifact and parser profile | Bounded tensor/range descriptors |
| exportbtxlock / importbtxlock | Exact lock and expected digest | Reproducible dependency state, no automatic update |
| planbtxcapabilityupdate | Current lease/lock and candidate | Generation switch proposal and rollback prerequisites |
| switchbtxcapability | Approved switch transaction | Atomic handle switch after tested readiness |
| getbtxcapabilityevents | Owner-scoped cursor/limit | Durable local lifecycle events |
| getbtxruntimecapabilities | Installed trusted adapters | Actual supported operations/platforms and evidence tier |
| getbtxttctrace | Authorized job/run ID | Stage DAG, timings, bytes, path and confidence |

Private-cache administration and private-fabric registration use separate privileged local interfaces. Do not expose raw memory addresses through generic get-residency output. Most clients need opaque leases and content identities, not backend registration details.

## 21.2 CLI and SDK

Proposed UX: `btx capability ensure ./legal.btx --policy personal --ready first-useful-result`; `btx capability prefetch --lock ./btx.lock --recipe legal --deadline 30s`; `btx capability status JOB --json`; `btx capability sleep LEASE`; `btx capability update --preview`; `btx capability release LEASE`. Generate final help/examples from the registered contract, not hypothetical commands.

Provide a local typed SDK with cancellation, event streaming, stable errors and explicit lifetime management. A readiness handle is a leased capability reference, not a naked path that can be garbage-collected. Keep the small ordinary file inspector usable without BTX, preserving the original one-link agent handoff.

## 21.3 Errors and progress

Errors include NO_ELIGIBLE_RECIPE, UNSUPPORTED_RUNTIME_PROFILE, MEMORY_RESERVATION_FAILED, UNVERIFIED_RANGE, STALE_GENERATION, DEADLINE_UNACHIEVABLE, REPRESENTATION_MISMATCH, SOFTWARE_TRUST_REQUIRED, FABRIC_POLICY_REQUIRED, TRANSFER_STILL_IN_FLIGHT, EXPERT_UNAVAILABLE, PREFIX_INCOMPATIBLE and HELPER_DOWN. Return stage, retryability, affected exact ID, cleanup status and next permitted action.

Progress separates canonical bytes verified, tensors placed, transforms complete, runtime readiness and first result. Do not show 100% ready when only a download finished. Never expose prompts, credentials, complete private filesystem paths or raw bearer capabilities in ordinary diagnostics.

# 22. UI, defaults and operational integration

## 22.1 A simple front door

The normal UI shows Capabilities, Available now, Preparing, Following and Storage/Memory. A package preview shows purpose/evidence, exact implementation, hardware fit, estimated readiness, privacy/source policy and a single appropriately scoped Prepare/Use action. Advanced pages expose cache tiers and transfer paths without requiring ordinary users to understand them.

Default selection is hardware-neutral. Reuse a warm exact recipe first when it satisfies the task. Explain whether an adapter or full model will be acquired. A task's requested capabilities do not become proven merely because the package includes a friendly description.

## 22.2 Host resource coexistence

Model loading, mining, ExactReplay, user applications and background preservation share real hardware. Respect operator priorities and reserve headroom for monetary validation and foreground work. Do not stop a production signer to benchmark a GPU. Compilation, repair, cache scrubbing and speculative prefetch yield under pressure.

Expose configured ceilings, effective hardware availability, reservations, active/retiring bytes, warmed representations and limiting reason. CPU memory pressure must be able to trigger safe sleep/eviction before OOM. Never disable limits to make a demonstration pass.

## 22.3 Privacy profiles

NATIVE_ONLY, EXTERNAL_ALLOWED and OFFLINE continue for acquisition. Add PRIVATE_FABRIC_DISABLED/APPROVED and PRIVATE_STATE_DISABLED/LOCAL/ORGANIZATION. Hardware discovery, capability selection, expert traces and prefix identifiers stay local by default. A native-only cold client installation may contact independently approved software infrastructure; disclose installation traffic separately from model traffic.

# 23. Economics and research feedback

Capability requests can expose unmet demand as explicit optional proposals for model creation bounties, adapter bounties, compatibility work or public-release funding. Reuse existing bounty/release semantics and evaluation profiles. A performance bounty must name the exact workload, hardware class, correctness target and measurement method.

No automatic conversion from a failed resolution or missed deadline into spending. Free public model transfer and warm-cache reuse do not inherently require BTX balances. The productive monetary use is in deliberately financed creation/release and settlement, not a fabricated per-read charge. Model performance and runtime residency never enter monetary consensus or generate new issuance.

# 24. Migration and new-default cutover

## 24.1 One migration path

Inventory package/profile versions and local database schemas. Assign unambiguous new identifiers before writing. Ship an offline inspector/migrator that can read prior descriptors and produce a newly signed capability package when sufficient metadata is available. Missing runtime semantics remain missing; the migrator cannot invent trust, compatibility or approval.

Preserve old immutable model bytes and manifests as content inputs. New runtime representations and recipes receive new IDs. No funded old terms are silently rewritten. Back up local metadata and require a dry-run migration report with disk estimate, objects affected and resumability before commit.

## 24.2 Default activation

The new resolver/service becomes the supported default API path in 0.34.8. Old model wire/API peers may be explicitly rejected with version/capability error where no longer supported. Documentation must not promise mixed 0.34.7 interoperability as a prerequisite. Monetary-only operation and existing financial state remain unaffected.

Keep previous application binaries until the operator approves cutover; never overwrite an in-use production executable. Release flag, tags, public artifacts, pushes and production restart are separate operator actions. A staged model-network cutover is not a monetary hard fork.

# 25. Code integration map and ownership

| Area | Existing integration to inspect | Required implementation |
|---|---|---|
| Package/lock | Private AHP codec, schemas and channels | Core v3 capability recipes, lockfile, migration, generated docs |
| Canonical ranges | VerifiedManifest, store, TransferSession | VerifiedRangeReader and consumer-priority interface |
| Materialization | exportmodelpath/current store backend | Immutable source-file backing, complete-path export, gated streaming view |
| Local control | Existing acquisition/runtime planners | Single capability orchestrator, caller grants, jobs, readiness leases |
| Memory | Resource governor/current reservations | Shared tier broker, UMA accounting, retired-fence accounting |
| Runtimes | Existing typed runtime handoff | Pinned real llama.cpp, vLLM, MLX adapters; actual load/warm/sleep hooks |
| Adapter assets | Existing resource/variant graph | Exact base binding, composition recipes, per-session isolation |
| Private fabric | New narrowly scoped worker/backend | NIXL/UCX/host transfer, scoped registration, destination verification |
| Derived cache | Existing safe local storage/journal | Representation/build cache, independent software trust |
| Private KV | New runtime-side connector | Tenant keys, full configuration fingerprint, secure lifecycle |
| MoE | Runtime expert dispatch/load hook | Residency tickets, demand/prefetch leases, exact expert paging |
| Topology | Resource probe/platform layer | NUMA/CXL memory tiers and hardware capability evidence |
| UI/API | Current CLI, Qt, local RPC | Ensure/status/prefetch/lock/leases, actual readiness/exposure |
| Tests | Native test/CMake registrars | Deterministic fixtures, runtime workers, GPU/fabric/CXL labs |

Suggested focused modules are `src/capability/{resolver,recipe,lockfile,grant,residency,range_reader,tensor_map,loader,prefetch,representation,private_state,expert_manager,topology}.cc` with matching headers, plus external runtime adapters under a dedicated integration directory. These are proposed paths, not permission to duplicate existing private modules. Keep common codecs and monetary code dependency-light.

Freeze shared contracts before workers edit dependent modules. Coordinator owns shared CMake/registrars/schema aggregation. Each worker uses a disjoint worktree or exclusive file ownership; no concurrent resets or unreviewed shared-file edits. The agent instructions specify the exact worker model and dispatch procedure.

# 26. Parallel implementation and release gates

## 26.1 Work sequence

Run contract/migration and verification work first; resolver and memory broker follow in parallel. Then integrate materialization, runtime streaming and adapter composition. Private fabric, derived cache, KV, expert paging and topology lanes can proceed against frozen interfaces. UX and tests run concurrently but cannot mark mock interfaces as runtime success.

Use Grok 4.6 Extra High workers as explicitly requested. Confirm that exact model is available through the actual Cursor worker mechanism; do not fabricate a CLI flag or silently substitute another model. If unavailable, produce the specific dispatch blocker for the operator while completing non-dispatch planning. Coordinator remains responsible for architecture and integration, not merely collecting optimistic worker summaries.

## 26.2 Evidence tiers

Distinguish reference checks, native unit tests, actual local process tests, actual runtime execution, real CUDA/ROCm/Metal hardware, real RDMA/GDS/CXL, WAN and production observations. A 400-GiB sparse fixture validates addressing and resource accounting, not sustained payload transfer. A simulated CXL node is not a CXL hardware measurement.

All native cases start NOT_RUN. A real missing prerequisite is recorded with the precise platform capability it blocks. The release can publish a truthful supported-platform matrix, but it cannot claim completion of every requested feature when a mandatory production call path is missing. Every plan-only, prototype or disabled-by-build result must be explicit.

## 26.3 Independent audits

Fresh reviewers audit verification/fault reads; GPU lifetime; resource accounting; package/software/wallet authority; executable/KV privacy; runtime/MoE correctness; migration; and benchmark validity. A reviewer should not own the implementation being reviewed. Reconcile each finding as REAL, STALE, FALSE_POSITIVE or DESIGN_DECISION_WITH_EVIDENCE; fix every real release blocker and rerun dependent journeys.

The final operator report identifies candidate fingerprint, all changed contracts, native test counts, every failed/unrun capability, actual runtime support, memory/transfer/correctness results, data exposure, unresolved migration steps and exact next operator action. Do not push, tag, publish or restart production automatically.

# 27. Required whole-system journeys

**J01 — Cold one-link capability.** A clean user environment with ordinary HTTPS/file tools reads an agent-ready package, obtains separately trusted tooling, resolves an exact recipe, acquires native model bytes, prepares a real supported local runtime and passes a bounded first-useful-result test. No funded wallet, source-platform login or remote inference is required for public native data.

**J02 — Resident base, new specialization.** A real base stays resident while two exact adapters are acquired/attached under separate sessions. Prove the base was not re-downloaded/reloaded unnecessarily, outputs match the runtime baseline and no adapter state leaks across requests.

**J03 — Streaming without sparse-zero reads.** Serve canonical pieces out of order to a range-aware loader. Block a needed piece and corrupt another. Prove the runtime never reads an absent hole as zeros or executes unverified tensors, then complete acquisition and compare outputs with full-file loading.

**J04 — Sleep, pressure and wake.** Load two recipes, induce controlled memory pressure, offload the inactive one, use the other, and wake the first. Verify discarded KV/workspace is rebuilt, actual VRAM falls, host budget remains bounded and readiness is not premature.

**J05 — Trusted peer-device startup.** A private peer holds an exact compatible representation. Load a target through the actual fabric backend; verify destination before compute. Cancel mid-transfer, revoke source access, and retry through safe local/native fallback without use-after-free or source misclassification.

**J06 — Runtime-cache trust.** Reuse an organization-approved compiled representation under an exact compatibility key. Reject a cache with the wrong driver/compiler/model identity and a valid signature from an untrusted model author. Measure compile work avoided and output parity.

**J07 — Private prefix reuse.** Reuse a long exact prefix within one tenant and invalidate it after adapter/tokenizer changes. An unauthorized second tenant cannot infer or retrieve cache state. Packet capture proves no public KV publication or unauthorized usage telemetry.

**J08 — MoE demand paging.** Run a supported MoE model with a working set larger than device capacity but feasible local tiering. Compare against an all-resident reference, shift expert popularity, inject misses and cancellation, and report latency/throughput rather than hiding stalls.

**J09 — CXL/NUMA placement.** On actual supported hardware place approved host representations into a selected memory tier, measure the path and recover from a controlled tier loss. A portable topology-emulation test is additional evidence, not a replacement for this hardware case.

**J10 — Atomic update and rollback.** Prepare a new recipe while old sessions execute, change a signed channel, switch only after readiness, then roll back an application generation while preserving software trust floors and active leases. No model bytes change under an existing handle.

**J11 — Predictive prefetch under competition.** Two agents issue conflicting future hints while foreground work continues. Demonstrate demand priority, finite speculation, useful-hit and waste counters, fair memory allocation and no thrashing/OOM.

**J12 — Default cutover.** Migrate prior package/cache state, reject unsupported old model APIs cleanly, run monetary-only binaries and helper-failure tests, and prove no ledger/fund/issuance change. The capability framework is the ordinary new path, not an opt-in prototype hidden behind an unregistered command.

# 28. Definition of completion

Completion means the new default resolves, materializes, loads, warms, leases and safely retires actual local capabilities through the existing decentralized model substrate. Full models, adapters, resident representations and private state have explicit identities and lifetimes. No absent bytes reach a loader as valid data. No canceled DMA targets recycled memory. No package appoints its own software authority. No private prompt state enters public storage.

All requested feature families are current-release work. The evidence matrix states which hardware/platform combinations genuinely executed. Missing hardware does not justify inventing results, and a successful mock does not turn an unimplemented backend into a delivered one. The final bar is a reproducible first-useful-result journey and safe failure/recovery, not the number of source files or green checklist headings.

# Sources and design provenance

The companion `research/RESEARCH_REGISTER.md` lists exact inspected code paths, commit/blob identifiers, official documentation and papers. References [B01–B03] are BTX baseline/specification evidence; [R01–R09] are direct source observations; [R10 onward] provide independent systems and interface precedents. New fields and algorithms in this specification are proposed BTX contracts, not claims that those upstream projects already implement BTX.

**[B01] BTX public model store.** https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/src/modelnet/store.h

**[B02] BTX network expansion baseline.** BTX_0.34.8_Expanded_Implementation_Spec.md

**[B03] BTX agent package baseline.** BTX_0348_Agent_Readable_Package_Spec.md

**[R01] ModelExpress loading strategy lifetime.** https://github.com/ai-dynamo/modelexpress/blob/23ffebf7b8504927f912e1693537b54affb49e25/modelexpress_client/python/modelexpress/load_strategy/base.py

**[R02] vLLM sleep allocator.** https://github.com/vllm-project/vllm/blob/main/vllm/device_allocator/cumem.py

**[R03] llama.cpp model loader.** https://github.com/ggml-org/llama.cpp/blob/2f3fd02526682adbd3ba771d929d271e477a35c5/src/llama-model-loader.cpp

**[R04] SafeTensors metadata parser.** https://github.com/safetensors/safetensors/blob/main/safetensors/src/tensor.rs

**[R05] MLX reader-backed SafeTensors.** https://github.com/ml-explore/mlx/blob/main/mlx/io/safetensors.cpp

**[R06] NIXL backends and transfer lifecycle.** https://github.com/ai-dynamo/nixl/blob/d24959417cefb5ab5bfb8d132020da010a323684/examples/python/nixl_gds_example.py

**[R07] Mooncake asynchronous transfer contract.** https://github.com/kvcache-ai/Mooncake/blob/ffe013517eaafa8f33e5e0ee034fd6b8f5561e92/mooncake-transfer-engine/include/transfer_engine.h

**[R08] LMCache cache engine.** https://github.com/LMCache/LMCache/blob/dev/lmcache/v1/cache_engine.py

**[R09] MoE-Infinity expert residency.** https://github.com/EfficientMoE/MoE-Infinity/blob/4b94d3d6e1762f8831099746aaf1212a1272a816/core/prefetch/expert_residency.h

**[R10] vLLM: LoRA adapters.** https://docs.vllm.ai/en/latest/features/lora/

**[R11] vLLM: Sleep mode.** https://docs.vllm.ai/en/latest/features/sleep_mode/

**[R12] ServerlessLLM: Low-Latency Serverless Inference for Large Language Models.** https://arxiv.org/abs/2401.14351

**[R13] S-LoRA: Serving Thousands of Concurrent LoRA Adapters.** https://arxiv.org/abs/2311.03285

**[R14] Punica: Multi-Tenant LoRA Serving.** https://arxiv.org/abs/2310.18547

**[R15] NVIDIA GPUDirect Storage overview.** https://docs.nvidia.com/gpudirect-storage/overview-guide/

**[R16] Linux kernel: CXL documentation.** https://docs.kernel.org/driver-api/cxl/index.html

**[R17] PyTorch: Tips for Loading an nn.Module from a Checkpoint.** https://docs.pytorch.org/tutorials/recipes/recipes/module_load_state_dict_tips.html

**[R18] The Update Framework specification.** https://theupdateframework.github.io/specification/latest/

**[R19] MLX documentation.** https://ml-explore.github.io/mlx/build/html/index.html

**[R20] Run:ai Model Streamer.** https://github.com/run-ai/runai-model-streamer


# Appendix A. Full native acceptance catalogue

All 182 cases are implementation requirements. Initial status is NOT_RUN. Each requires the exact candidate/diff/build/binary fingerprint, fixture hashes, command, start/end time, exit status, assertions and evidence artifacts. Static inspection and the supplied Python reference tests do not satisfy native or hardware cases.

## BASE — Baseline and cutover

**Common fixture:** A clean and a dirty private-tree fixture; backed-up prior package/catalogue data; isolated money-only node.

### JIT-BASE-01 — Candidate identity

**Action.** Change an untracked source and rebuild without changing HEAD.

**Pass condition.** The candidate fingerprint changes and evidence cannot be attributed to the previous binary.

**Evidence.** `evidence/base/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-BASE-02 — No duplicate acquisition stack

**Action.** Trace ensure from package to completed piece while existing transfer jobs run.

**Pass condition.** The registered path uses the same VerifiedManifest/store/credit broker; no unmetered capability downloader exists.

**Evidence.** `evidence/base/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-BASE-03 — Legacy model cutover

**Action.** Present a deliberately unsupported 0.34.7 model handshake after activation.

**Pass condition.** The peer receives an explicit version failure; no ambiguous interpretation or silent downgrade occurs.

**Evidence.** `evidence/base/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-BASE-04 — Monetary invariance

**Action.** Compare consensus configuration, fixed transaction/block vectors and wallet state before and after capability installation.

**Pass condition.** Existing ledger semantics and funds are unchanged; no capability data enters consensus inputs.

**Evidence.** `evidence/base/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-BASE-05 — Migration restart

**Action.** Crash the local metadata migrator between every journal phase and restart.

**Pass condition.** It resumes or rolls back without deleting the last verified representation or duplicating authority.

**Evidence.** `evidence/base/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-BASE-06 — Version allocation collision

**Action.** Prepopulate a private Core-v3 allocation with a different schema.

**Pass condition.** Coordinator detects conflict before serialization and allocates an unambiguous reviewed version.

**Evidence.** `evidence/base/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-BASE-07 — Production untouched

**Action.** Run all installation/cutover fixtures with sentinel production process paths and wallet files.

**Pass condition.** Sentinels, process start times and live executable hashes are unchanged; only isolated test paths are modified.

**Evidence.** `evidence/base/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## IDENT — Identity and representation

**Common fixture:** Exact synthetic canonical manifests, two same-name resources, signed recipe fixtures and trusted local parser.

### JIT-IDENT-01 — Wrong requested resource

**Action.** Supply a self-consistent manifest Y in response to request X.

**Pass condition.** Admission fails before visible payload commitment; signing Y does not make it X.

**Evidence.** `evidence/ident/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-IDENT-02 — Representation distinction

**Action.** Repack one canonical model into two device layouts.

**Pass condition.** Both representations name the same canonical input but have distinct representation IDs and layout fingerprints.

**Evidence.** `evidence/ident/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-IDENT-03 — Capability label is not evidence

**Action.** Offer a model tagged with an unsupported capability but no qualifying evaluation.

**Pass condition.** Resolver does not treat the tag as proof or bypass the requested evidence threshold.

**Evidence.** `evidence/ident/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-IDENT-04 — Recipe changes

**Action.** Change tokenizer, adapter scale, adapter order and runtime profile independently.

**Pass condition.** Each material execution configuration produces a distinct recipe or lock commitment.

**Evidence.** `evidence/ident/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-IDENT-05 — Source independence

**Action.** Retrieve identical canonical assets from a local peer and a configured external fixture.

**Pass condition.** Canonical identity matches; source provenance and transport assurance remain separate.

**Evidence.** `evidence/ident/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-IDENT-06 — Imported authorship

**Action.** Import a third-party model with a local mirror signature.

**Pass condition.** The importer is reported as mirror/packager, never automatically as original author.

**Evidence.** `evidence/ident/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-IDENT-07 — Equivocation

**Action.** Supply two valid issuer records at the same signed sequence with different digests.

**Pass condition.** Conflict is retained/reported; last-arrival timestamp does not silently choose authority.

**Evidence.** `evidence/ident/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## PKG — Capability package and lock

**Common fixture:** Core-v3 unsigned REGTEST structure, native signing keys for crypto cases, prior descriptor fixtures.

### JIT-PKG-01 — Default capability writer

**Action.** Export an ordinary agent-ready capability from the new UI/CLI.

**Pass condition.** The default is the reviewed new profile with generated typed guidance, not an opt-in legacy download path.

**Evidence.** `evidence/pkg/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PKG-02 — Canonical framing

**Action.** Encode/reparse header boundaries, trailing data, duplicate keys and invalid number forms.

**Pass condition.** Golden bytes match; malformed or noncanonical forms are rejected before actionable use.

**Evidence.** `evidence/pkg/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PKG-03 — Document consistency

**Action.** Change typed recipe then regenerate AGENTS.md; inject conflicting author notes.

**Pass condition.** Generated content matches signed fields; prose cannot override plan authority.

**Evidence.** `evidence/pkg/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PKG-04 — Locked reproducibility

**Action.** Resolve a lock with latest-channel and search results changed.

**Pass condition.** Exact dependencies remain pinned; no hidden latest selection or runtime upgrade occurs.

**Evidence.** `evidence/pkg/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PKG-05 — Dependency graph

**Action.** Create missing dependencies, cycles, duplicate conflicting nodes and depth-limit overflow.

**Pass condition.** Resolution rejects each without unbounded recursion or partial execution.

**Evidence.** `evidence/pkg/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PKG-06 — Separate large maps

**Action.** Attach a tensor-map reference whose payload exceeds the thin descriptor ceiling.

**Pass condition.** The descriptor stays bounded and resolves an exact separate map object; no silent truncation occurs.

**Evidence.** `evidence/pkg/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PKG-07 — Independent software trust

**Action.** Put a binary URL and self-signed client key in an otherwise valid package.

**Pass condition.** Installation requires independently accepted distribution trust; package signature alone is insufficient.

**Evidence.** `evidence/pkg/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## RESOLVE — Resolver and time-to-capability

**Common fixture:** Three recipes with distinct readiness, quality evidence, byte size and supported runtime constraints.

### JIT-RESOLVE-01 — Hard filters first

**Action.** Rank a very fast recipe that violates required memory or evidence constraints.

**Pass condition.** It is excluded before ranking; low TTC does not override a hard requirement.

**Evidence.** `evidence/resolve/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RESOLVE-02 — Warm adapter selection

**Action.** Keep an exact base ready and offer a compatible small adapter versus a cold full model.

**Pass condition.** The resolver exposes both costs and selects according to explicit policy, recording why.

**Evidence.** `evidence/resolve/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RESOLVE-03 — Unknown compatibility

**Action.** Remove device capability and peak-memory information for a candidate.

**Pass condition.** The result is UNKNOWN or a bounded test proposal, not a fabricated compatible state.

**Evidence.** `evidence/resolve/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RESOLVE-04 — Pipeline timing

**Action.** Run overlapping copy/hash/load stages with known fixture timing.

**Pass condition.** TTC follows critical path; the sum of stage occupancy is not reported as elapsed latency.

**Evidence.** `evidence/resolve/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RESOLVE-05 — Deadline impossibility

**Action.** Request a deadline below a measured minimum acquisition bound.

**Pass condition.** Return DEADLINE_UNACHIEVABLE or a permitted alternative; no verification bypass.

**Evidence.** `evidence/resolve/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RESOLVE-06 — Vendor neutrality

**Action.** Provide equivalently eligible CUDA/HIP/Metal fixtures with stable tie-break inputs.

**Pass condition.** Selection follows constraints and evidence, not a hardcoded vendor preference.

**Evidence.** `evidence/resolve/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RESOLVE-07 — No-result economics

**Action.** Resolve a capability unavailable under policy.

**Pass condition.** Return unmet demand/optional proposal only; no bounty publication or spending occurs.

**Evidence.** `evidence/resolve/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## GRANT — Finite local authority

**Common fixture:** Owner-local policy store, two callers, revoked and expiring grants, wallet sentinel.

### JIT-GRANT-01 — One finite journey

**Action.** Approve acquisition/load/warm/smoke once for exact plan.

**Pass condition.** Covered stages run without repeated arbitrary prompts; effects never exceed the grant.

**Evidence.** `evidence/grant/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-GRANT-02 — Wrong caller

**Action.** Reuse another caller's grant or plan ID.

**Pass condition.** Authorization fails without disclosing private residency or state.

**Evidence.** `evidence/grant/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-GRANT-03 — Changed plan

**Action.** Change selected resource, runtime executable or destination after approval.

**Pass condition.** Digest mismatch requires new authorization and prevents reuse of the old grant.

**Evidence.** `evidence/grant/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-GRANT-04 — Concurrent ceilings

**Action.** Start many jobs that individually fit but jointly exceed approved memory/network limits.

**Pass condition.** Atomic global reservations admit only the feasible set; no race multiplies limits.

**Evidence.** `evidence/grant/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-GRANT-05 — Revoked prefetch

**Action.** Revoke a grant while speculative jobs wait for allocation.

**Pass condition.** No new effects start; existing physical operations drain under the original cleanup contract.

**Evidence.** `evidence/grant/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-GRANT-06 — Wallet isolation

**Action.** Embed funding urgency in AGENTS.md and trigger a failed acquisition.

**Pass condition.** No wallet unlock, signature, broadcast or new mandate is requested implicitly.

**Evidence.** `evidence/grant/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-GRANT-07 — Expiry cleanup

**Action.** Expire authorization during a device copy.

**Pass condition.** New work stops, but allocated buffers remain protected until safe reclamation.

**Evidence.** `evidence/grant/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## MEM — Physical memory accounting

**Common fixture:** Fake device allocator plus real host allocator; UMA and discrete topology fixtures; pressure injector.

### JIT-MEM-01 — Peak not payload

**Action.** Load weights that fit alone but require additional KV and transformation scratch beyond capacity.

**Pass condition.** Admission rejects or chooses a feasible plan before OOM; all peak components are counted.

**Evidence.** `evidence/mem/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MEM-02 — UMA accounting

**Action.** Map shared host/Metal-style buffers under one physical pool.

**Pass condition.** Physical bytes are counted once while virtual aliases and active leases remain visible.

**Evidence.** `evidence/mem/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MEM-03 — Pinned cap

**Action.** Start parallel streaming loads that would exhaust pinned RAM.

**Pass condition.** Backpressure precedes allocation; pinned budget is never exceeded.

**Evidence.** `evidence/mem/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MEM-04 — Per-rank feasibility

**Action.** Provide ample aggregate memory but insufficient capacity on one required parallel rank.

**Pass condition.** The distributed load is rejected/replanned rather than trusting the global sum.

**Evidence.** `evidence/mem/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MEM-05 — Retiring memory

**Action.** Cancel a load with a pending device fence and request a new large allocation.

**Pass condition.** Retired-but-not-quiescent bytes remain charged and cannot be reused prematurely.

**Evidence.** `evidence/mem/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MEM-06 — Pressure eviction

**Action.** Induce controlled host pressure with active and idle generations.

**Pass condition.** Only eligible idle generations are evicted/offloaded; foreground and active lease guarantees hold.

**Evidence.** `evidence/mem/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MEM-07 — Budget recovery

**Action.** Inject allocation and transform failures repeatedly.

**Pass condition.** Every reservation is either released exactly once or retained as documented physical exposure.

**Evidence.** `evidence/mem/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## LEASE — Generation and transfer lifetime

**Common fixture:** Deterministic async backend with delayed completion, reused pointer addresses and worker crash injection.

### JIT-LEASE-01 — Late completion

**Action.** Cancel generation A, create B, then deliver A's completion.

**Pass condition.** A cannot mutate B readiness or references even if an allocator reuses the address.

**Evidence.** `evidence/lease/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LEASE-02 — Timeout is not cancel

**Action.** Return timeout while the backend is still writing.

**Pass condition.** The operation reports STILL_IN_FLIGHT and retains source/destination registrations.

**Evidence.** `evidence/lease/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LEASE-03 — Reference drain

**Action.** Two consumers share immutable data; one releases its lease.

**Pass condition.** The other consumer remains valid and no backing is garbage-collected.

**Evidence.** `evidence/lease/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LEASE-04 — Deregister order

**Action.** Attempt deregistration before the final transfer fence.

**Pass condition.** It is delayed/rejected; completion, deregistration and free occur in safe order.

**Evidence.** `evidence/lease/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LEASE-05 — Orphan worker

**Action.** Crash local control while a runtime remains alive.

**Pass condition.** Restart authenticates generation/liveness or retires safely; an old socket alone is not adopted.

**Evidence.** `evidence/lease/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LEASE-06 — Double cancel

**Action.** Cancel/release the same lease repeatedly across restart.

**Pass condition.** Operations are idempotent; reference counts and budgets do not underflow.

**Evidence.** `evidence/lease/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LEASE-07 — Quiescence unknown

**Action.** Backend cannot prove cancellation or completion.

**Pass condition.** The buffers are quarantined/retained and a specific cleanup error is returned, not unsafe reuse.

**Evidence.** `evidence/lease/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## MAP — Tensor map validation

**Common fixture:** Valid tiny SafeTensors/GGUF fixtures plus malformed headers and a native format parser.

### JIT-MAP-01 — Verified header first

**Action.** Withhold or corrupt a canonical piece covering the tensor header.

**Pass condition.** No tensor metadata is trusted before the covering piece verifies.

**Evidence.** `evidence/map/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAP-02 — Offset overflow

**Action.** Use huge header lengths, offset additions and shape products.

**Pass condition.** Checked arithmetic rejects overflow before allocation or read.

**Evidence.** `evidence/map/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAP-03 — Overlap and aliases

**Action.** Supply overlapping tensors without permitted alias semantics, then a valid tied-weight case.

**Pass condition.** Invalid overlaps fail; valid aliases retain explicit shared backing and correct sizes.

**Evidence.** `evidence/map/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAP-04 — Wrong map signer

**Action.** Provide a signed tensor map with offsets inconsistent with canonical file metadata.

**Pass condition.** Map is rejected despite a valid signature; derived byte geometry remains authoritative.

**Evidence.** `evidence/map/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAP-05 — Quantized geometry

**Action.** Map quantized GGUF blocks and scale tensors across piece boundaries.

**Pass condition.** Byte sizes/alignment and companion ranges match the format and runtime requirements.

**Evidence.** `evidence/map/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAP-06 — Split checkpoint

**Action.** Resolve a multi-file checkpoint with missing or conflicting shard references.

**Pass condition.** Required shard set fails closed; no file index is silently substituted.

**Evidence.** `evidence/map/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAP-07 — Metadata ceiling

**Action.** Exceed tensor count/name/header/map byte limits independently.

**Pass condition.** Parser stops within the reserved memory/work budget and returns a bounded error.

**Evidence.** `evidence/map/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## RANGE — Verified range reader

**Common fixture:** A known manifest, out-of-order pieces, corrupt provider, cancellation and overlapping reader fixtures.

### JIT-RANGE-01 — Piece-spanning slice

**Action.** Request a tensor range crossing three canonical pieces.

**Pass condition.** All covering pieces verify; returned slice exactly matches the trusted full-file reference.

**Evidence.** `evidence/range/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RANGE-02 — Subpiece trust

**Action.** Receive all but one unverified transport subpiece.

**Pass condition.** No range depending on that canonical piece is exposed as verified.

**Evidence.** `evidence/range/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RANGE-03 — Coalesced consumers

**Action.** Two same-domain readers request overlapping extents.

**Pass condition.** Backend work coalesces while separate leases, offsets and cancellation remain correct.

**Evidence.** `evidence/range/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RANGE-04 — Tenant boundary

**Action.** Request identical private range keys from distinct tenants.

**Pass condition.** No unauthorized cross-tenant coalescing or cache-existence disclosure occurs.

**Evidence.** `evidence/range/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RANGE-05 — Rarity versus load priority

**Action.** Issue urgent tensor reads and rare-piece preservation under a hard cap.

**Pass condition.** Priorities change service order without bypassing total memory/inflight ceilings.

**Evidence.** `evidence/range/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RANGE-06 — Corrupt provider fallback

**Action.** One provider supplies a bad complete piece.

**Pass condition.** Corrupt bytes never reach the runtime; eligible alternate acquisition proceeds with bounded retries.

**Evidence.** `evidence/range/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RANGE-07 — Reader cancellation

**Action.** Cancel one range wait while another waits for shared data.

**Pass condition.** Only the caller is canceled; shared acquisition and surviving consumer remain valid.

**Evidence.** `evidence/range/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## MAT — Materialized and virtual files

**Common fixture:** Sparse backing store, complete-file exporter, Linux virtual-file fixture and portable explicit reader.

### JIT-MAT-01 — No zero holes

**Action.** Attempt ordinary export and mapped reads before a required extent exists.

**Pass condition.** Ordinary export refuses; streaming view blocks/fails instead of returning sparse zeros.

**Evidence.** `evidence/mat/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAT-02 — Final offset writes

**Action.** Deliver verified pieces randomly and complete the file.

**Pass condition.** Final bytes and digest match without a second full-size reconstruction copy.

**Evidence.** `evidence/mat/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAT-03 — Fault failure

**Action.** Kill helper during a fault-gated runtime read.

**Pass condition.** Read fails safely; worker stops or retries materialized mode, never fabricates data.

**Evidence.** `evidence/mat/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAT-04 — Immutable generation

**Action.** Update latest while a runtime maps the old model.

**Pass condition.** The open generation remains byte-identical; replacement occurs through a new handle.

**Evidence.** `evidence/mat/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAT-05 — Unsafe hardlink

**Action.** Modify an operator source after attempted zero-copy import.

**Pass condition.** Mutation cannot change verified active backing; implementation uses safe snapshot/copy/reverification.

**Evidence.** `evidence/mat/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAT-06 — Crash bitmap

**Action.** Crash after data write but before metadata commit, then after metadata attempt.

**Pass condition.** Recovery never promotes uncertain extents solely because a file or bit exists.

**Evidence.** `evidence/mat/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MAT-07 — Cross-platform path

**Action.** Run Linux FUSE and macOS/portable reader tests independently.

**Pass condition.** Unsupported fault mechanisms are explicit; safe complete-file/reader baseline remains functional.

**Evidence.** `evidence/mat/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## LOAD — Streaming loader

**Common fixture:** Small real runtime model and a deterministic staged loader with verified buffer instrumentation.

### JIT-LOAD-01 — Stage overlap

**Action.** Introduce network, hash and device-copy delays.

**Pass condition.** Stages overlap within budget; trace shows actual wall-time critical path and no hidden full duplicate.

**Evidence.** `evidence/load/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LOAD-02 — Dense readiness

**Action.** Finish early layers but withhold a mandatory late layer.

**Pass condition.** Runtime never reports full readiness or produces a misleading successful dense result.

**Evidence.** `evidence/load/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LOAD-03 — Backpressure

**Action.** Slow device transform while network remains fast.

**Pass condition.** Upstream credits throttle before pinned/host buffers exceed their ceilings.

**Evidence.** `evidence/load/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LOAD-04 — Mutation fallback

**Action.** Fail a strategy after partial transformation then try a different strategy.

**Pass condition.** Destination is safely reset; no mixed raw/repacked tensors survive into the result.

**Evidence.** `evidence/load/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LOAD-05 — Error classification

**Action.** Inject target OOM and source corruption separately.

**Pass condition.** Only demonstrated source error affects source health; target OOM yields local replan.

**Evidence.** `evidence/load/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LOAD-06 — Device verification gate

**Action.** Complete DMA with deliberately wrong bytes.

**Pass condition.** Compute never consumes the buffer before destination verification rejects it.

**Evidence.** `evidence/load/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LOAD-07 — Whole-file parity

**Action.** Run streamed and fully materialized paths under identical runtime settings.

**Pass condition.** Outputs satisfy the declared numerical/correctness tolerance and exact component identity.

**Evidence.** `evidence/load/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## RUN — Real runtime adapters

**Common fixture:** Pinned CPU, CUDA, ROCm and MLX environments where available; unavailable hardware remains NOT_RUN.

### JIT-RUN-01 — CPU baseline

**Action.** Use the packaged local adapter to load and run a tiny supported model.

**Pass condition.** Actual outputs pass the declared fixture; no remote endpoint or funded wallet is used.

**Evidence.** `evidence/run/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RUN-02 — CUDA path

**Action.** Execute the real CUDA loader, warmup and readiness path.

**Pass condition.** Trace and device allocation prove the backend ran; a mock cannot satisfy this case.

**Evidence.** `evidence/run/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RUN-03 — ROCm path

**Action.** Execute HIP/ROCm loading and sleep/wake on supported hardware.

**Pass condition.** Backend-specific lifecycle is correct with numerical parity and no CUDA-only assumption.

**Evidence.** `evidence/run/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RUN-04 — Metal/MLX path

**Action.** Load through MLX/Metal reader or verified mmap path and evaluate lazy tensors.

**Pass condition.** Readiness follows real evaluation; unified memory and lease accounting match observed allocations.

**Evidence.** `evidence/run/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RUN-05 — Unknown adapter parameters

**Action.** Supply arbitrary executable path, LD_PRELOAD and unrecognized runtime flags.

**Pass condition.** Typed adapter rejects them; package data cannot choose process authority.

**Evidence.** `evidence/run/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RUN-06 — Sleep discarded state

**Action.** Sleep with weights preserved but KV/workspace discarded; wake.

**Pass condition.** Discarded state is rebuilt before readiness; remapping alone is not success.

**Evidence.** `evidence/run/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-RUN-07 — Plugin ABI mismatch

**Action.** Install an adapter built for a different runtime ABI.

**Pass condition.** Probe refuses incompatible use and offers an explicitly supported path, not undefined behavior.

**Evidence.** `evidence/run/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## LORA — Adapter composition

**Common fixture:** One real supported base, two valid adapters and malformed/wrong-base fixtures.

### JIT-LORA-01 — Exact base binding

**Action.** Attach an adapter trained for another exact base or incompatible target shape.

**Pass condition.** It fails before mutation, even when display names/architecture match.

**Evidence.** `evidence/lora/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LORA-02 — No base reload

**Action.** Activate a valid new adapter over a resident base.

**Pass condition.** Measurements show missing adapter work only; base bytes are not unnecessarily refetched.

**Evidence.** `evidence/lora/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LORA-03 — Concurrent isolation

**Action.** Alternate two sessions with distinct adapter sets.

**Pass condition.** Outputs match isolated baselines and no session inherits another adapter configuration.

**Evidence.** `evidence/lora/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LORA-04 — Detach while active

**Action.** Request detach during an in-flight adapter kernel.

**Pass condition.** Old generation remains leased until quiescent; no use-after-free or mixed output.

**Evidence.** `evidence/lora/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LORA-05 — Ordered composition

**Action.** Reverse adapter order or change scale in a recipe.

**Pass condition.** Plan identity changes and outputs are validated under that exact composition.

**Evidence.** `evidence/lora/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LORA-06 — Tokenizer conflict

**Action.** Attach a component requiring an incompatible vocabulary or tokenizer.

**Pass condition.** Recipe fails or uses an explicitly validated transform; it cannot silently resize semantics.

**Evidence.** `evidence/lora/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-LORA-07 — Merged representation

**Action.** Build merged weights from a base and adapter then acquire the original base.

**Pass condition.** Merged identity is separate and original immutable content remains intact.

**Evidence.** `evidence/lora/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## PREFETCH — Predictive prefetch

**Common fixture:** Two agent workloads, bounded speculative budgets, shaped network and tier pressure.

### JIT-PREFETCH-01 — Demand preemption

**Action.** Queue speculative loads then issue an urgent demand request.

**Pass condition.** Demand gets priority without violating existing active/fence leases.

**Evidence.** `evidence/prefetch/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PREFETCH-02 — Speculation ceiling

**Action.** Submit hundreds of high-probability hints.

**Pass condition.** Global speculative bytes/concurrency remain finite and actor labels cannot multiply caps.

**Evidence.** `evidence/prefetch/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PREFETCH-03 — Hint expiry

**Action.** Expire hints before they begin and while they run.

**Pass condition.** Queued work is canceled; dispatched cost and pending physical operations remain accurately charged.

**Evidence.** `evidence/prefetch/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PREFETCH-04 — Useful hit metric

**Action.** Use one prefetched recipe and abandon another.

**Pass condition.** Hit/avoided-latency and wasted-byte counters reflect real use rather than all downloads as success.

**Evidence.** `evidence/prefetch/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PREFETCH-05 — No thrashing

**Action.** Alternate predictions for two models exceeding available hot memory.

**Pass condition.** Hysteresis/admission policy avoids unbounded swap cycles and preserves foreground latency.

**Evidence.** `evidence/prefetch/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PREFETCH-06 — Private intent

**Action.** Include sensitive planning context outside typed fields.

**Pass condition.** API rejects/discards it appropriately; no reasoning transcript enters public discovery.

**Evidence.** `evidence/prefetch/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PREFETCH-07 — Tier-specific prefetch

**Action.** Prefetch an adapter to host RAM without promoting the base again.

**Pass condition.** Only requested tier transitions occur and measured costs match the plan.

**Evidence.** `evidence/prefetch/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## CACHE — Derived and executable caches

**Common fixture:** Trusted builder keys, untrusted model-author key, multiple runtime/hardware fingerprints.

### JIT-CACHE-01 — Cache fingerprint

**Action.** Change compiler, runtime, dtype, shape or model digest independently.

**Pass condition.** Incompatible entries miss/refuse; matching a friendly name is insufficient.

**Evidence.** `evidence/cache/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CACHE-02 — Untrusted executable cache

**Action.** Supply a kernel cache signed only by an accepted model publisher.

**Pass condition.** Execution is denied unless independent software-builder policy accepts it.

**Evidence.** `evidence/cache/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CACHE-03 — Local compile fallback

**Action.** Corrupt a cached runtime artifact.

**Pass condition.** Reject it and compile locally within budget when authorized; do not silently fetch arbitrary code.

**Evidence.** `evidence/cache/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CACHE-04 — Transformed tensor proof

**Action.** Use canonical checkpoint hash to label a wrong repacked tensor set.

**Pass condition.** The representation fails its own verification/trust contract.

**Evidence.** `evidence/cache/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CACHE-05 — Graph pointer portability

**Action.** Attempt to reuse a graph artifact containing another process generation's pointers.

**Pass condition.** It is rejected or rebuilt; a compiled binary cache is not treated as a live graph snapshot.

**Evidence.** `evidence/cache/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CACHE-06 — Concurrent builder commit

**Action.** Two workers build the same exact representation and one crashes.

**Pass condition.** Atomic promotion yields one valid immutable result and no partial visible cache.

**Evidence.** `evidence/cache/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CACHE-07 — Measured warm benefit

**Action.** Compare cold compilation and compatible cache reuse at equal workload.

**Pass condition.** Report actual startup savings, correctness and cache source, not a synthetic PASS claim.

**Evidence.** `evidence/cache/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## KV — Private prefix state

**Common fixture:** Runtime-specific KV connector, two tenant keys and exact token/config fixtures.

### JIT-KV-01 — Exact prefix hit

**Action.** Repeat an exact token prefix under identical configuration.

**Pass condition.** Reuse output matches fresh prefill and the saved prefill work is measured.

**Evidence.** `evidence/kv/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-KV-02 — Adapter invalidation

**Action.** Change adapter set/order/scale with same prompt text.

**Pass condition.** Old KV is not reused under an incompatible execution configuration.

**Evidence.** `evidence/kv/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-KV-03 — Tokenizer/position invalidation

**Action.** Change tokenizer, rope/position settings or chat template.

**Pass condition.** Key changes and incompatible cache entries miss rather than corrupting attention state.

**Evidence.** `evidence/kv/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-KV-04 — Cross-tenant denial

**Action.** Second tenant probes an identical common prefix.

**Pass condition.** No state or unauthorized hit information is revealed; lookup keys are tenant-scoped.

**Evidence.** `evidence/kv/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-KV-05 — Incomplete write

**Action.** Crash during layer/chunk cache persistence.

**Pass condition.** Partial state is unavailable after restart until complete and validated.

**Evidence.** `evidence/kv/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-KV-06 — Telemetry isolation

**Action.** Run actual integration with packet capture and telemetry sinks blocked.

**Pass condition.** No nonapproved LMCache/controller/analytics traffic or public KV announcement occurs.

**Evidence.** `evidence/kv/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-KV-07 — Retire persistent state

**Action.** Expire a private cache and rotate tenant key under active leases.

**Pass condition.** New access fails, active operations drain safely, and persistence/deletion guarantees are accurately reported.

**Evidence.** `evidence/kv/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## PEER — Private peer-device transfer

**Common fixture:** Two approved fabric peers, denied peer, exact representation map and delayed transfer backend.

### JIT-PEER-01 — Private membership

**Action.** An ordinary public model peer requests device memory access.

**Pass condition.** No address/registration capability is returned without organization authorization.

**Evidence.** `evidence/peer/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PEER-02 — Exact geometry

**Action.** Source and target differ in TP/PP layout or postprocessing version.

**Pass condition.** Fast path refuses or explicitly converts; no tensor-name-only matching.

**Evidence.** `evidence/peer/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PEER-03 — Destination checks

**Action.** Transfer wrong tensor bytes through a successful backend operation.

**Pass condition.** Target remains quarantined and never reaches runtime-ready.

**Evidence.** `evidence/peer/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PEER-04 — Memory registration scope

**Action.** Inspect the exported region around approved weight buffers.

**Pass condition.** No KV/prompt/credential or unrelated heap range is registered for remote access.

**Evidence.** `evidence/peer/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PEER-05 — Timeout buffer lifetime

**Action.** Timeout a scatter/RDMA operation and request allocator reuse.

**Pass condition.** Buffers remain reserved until physical completion or proven teardown.

**Evidence.** `evidence/peer/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PEER-06 — Assurance labeling

**Action.** Use PQ1 control with an unencrypted approved fabric payload.

**Pass condition.** Trace labels TRUSTED_FABRIC, not end-to-end native PQ encryption.

**Evidence.** `evidence/peer/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PEER-07 — Real backend startup

**Action.** Load a compatible target via actual NIXL/UCX hardware and run the smoke test.

**Pass condition.** Device/fabric evidence confirms transfer and readiness; absent hardware leaves this case NOT_RUN.

**Evidence.** `evidence/peer/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## DIRECT — Storage-to-device paths

**Common fixture:** Verified immutable file, corrupted backing, alignment variants and actual GDS/HIP/host adapters.

### JIT-DIRECT-01 — Verified source fast path

**Action.** Load a leased immutable verified file through direct storage.

**Pass condition.** Actual backend reports copy path and destination becomes ready only after required checks.

**Evidence.** `evidence/direct/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-DIRECT-02 — Unverified origin

**Action.** Offer a public unverified range directly to a device loader.

**Pass condition.** It cannot bypass canonical proof/destination quarantine merely because DMA succeeds.

**Evidence.** `evidence/direct/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-DIRECT-03 — Alignment fallback

**Action.** Request nonaligned tensor ranges unsupported by the fast path.

**Pass condition.** A bounded verified fallback is explicit; no truncated or widened unauthorized reads.

**Evidence.** `evidence/direct/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-DIRECT-04 — No false zero-copy

**Action.** Force backend compatibility fallback to host staging.

**Pass condition.** Metrics identify actual copies and do not report zero-copy from library presence.

**Evidence.** `evidence/direct/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-DIRECT-05 — Cancel GDS

**Action.** Cancel an asynchronous direct read before completion.

**Pass condition.** Memory and file leases survive until completion/quiescence.

**Evidence.** `evidence/direct/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-DIRECT-06 — ROCm/Metal distinction

**Action.** Probe GDS on non-CUDA hardware and run eligible alternative.

**Pass condition.** Unsupported backend is not relabeled; real host/HIP/UMA route is reported accurately.

**Evidence.** `evidence/direct/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-DIRECT-07 — Fast-path parity

**Action.** Compare direct and verified-host loading of the same exact model.

**Pass condition.** Outputs meet tolerance and resource peaks/copy counts are recorded.

**Evidence.** `evidence/direct/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## MOE — Expert demand paging

**Common fixture:** Supported real MoE profile plus tiny deterministic model, limited device capacity and host-tier fixture.

### JIT-MOE-01 — Expert map completeness

**Action.** Omit scale/companion tensors from one quantized expert.

**Pass condition.** Admission fails rather than loading a mathematically incomplete expert.

**Evidence.** `evidence/moe/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MOE-02 — All-resident parity

**Action.** Run the same workload all-resident and demand-paged.

**Pass condition.** Output correctness meets declared tolerance and routing decisions are not altered by cache policy.

**Evidence.** `evidence/moe/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MOE-03 — Missing expert

**Action.** Remove a required expert from eligible local tiers.

**Pass condition.** Execution waits/fails within policy; no zero substitution or expert skipping.

**Evidence.** `evidence/moe/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MOE-04 — Working-set shift

**Action.** Change the workload's hot expert distribution under tight memory.

**Pass condition.** Demand progress remains possible, prefetch is bounded and thrashing is measured/controlled.

**Evidence.** `evidence/moe/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MOE-05 — Execution eviction race

**Action.** Evict expert generation A while its batch executes and B loads.

**Pass condition.** A remains leased/fenced; B cannot overwrite it before quiescence.

**Evidence.** `evidence/moe/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MOE-06 — No WAN token paging

**Action.** Disable local expert data while public source exists.

**Pass condition.** Normal token-critical path does not silently issue WAN retrieval; pause/preparation policy is explicit.

**Evidence.** `evidence/moe/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-MOE-07 — Real runtime hook

**Action.** Exercise actual expert-dispatch/load callbacks and measure stalls.

**Pass condition.** The runtime uses the manager; standalone cache tests cannot satisfy this integration case.

**Evidence.** `evidence/moe/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## CXL — NUMA and CXL placement

**Common fixture:** Portable topology fixture plus real Linux NUMA/CXL hardware when present.

### JIT-CXL-01 — Topology truth

**Action.** Probe unavailable CXL/fabric properties.

**Pass condition.** They remain UNKNOWN/UNSUPPORTED; no assumed future link rate or pool capacity.

**Evidence.** `evidence/cxl/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CXL-02 — Physical pool uniqueness

**Action.** Expose one physical memory pool through several logical devices.

**Pass condition.** Reservations share its capacity and never multiply apparent free memory.

**Evidence.** `evidence/cxl/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CXL-03 — NUMA placement

**Action.** Allocate approved host staging under an explicit NUMA policy.

**Pass condition.** Actual placement and bandwidth/latency are measured using supported OS interfaces.

**Evidence.** `evidence/cxl/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CXL-04 — CXL real tier

**Action.** Place a model representation in real exposed CXL memory.

**Pass condition.** Hardware evidence distinguishes the case from emulation and reports actual cost.

**Evidence.** `evidence/cxl/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CXL-05 — Tier loss

**Action.** Offline a controlled test memory tier during a leased workload.

**Pass condition.** New allocations stop and active use drains/migrates/fails safely; no stale dereference.

**Evidence.** `evidence/cxl/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CXL-06 — No privileged configuration

**Action.** Ask a normal user package to configure fabric or hotplug memory.

**Pass condition.** It is refused; topology discovery does not confer host administration authority.

**Evidence.** `evidence/cxl/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-CXL-07 — Placement comparison

**Action.** Provide measured paths where local NVMe beats a remote tier.

**Pass condition.** Planner selects based on eligibility and measurements, not fixed tier mythology.

**Evidence.** `evidence/cxl/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## UPDATE — Generation updates

**Common fixture:** Active old runtime, newly signed package, failing update and rollback trust floor.

### JIT-UPDATE-01 — Prepare alongside active

**Action.** Acquire/load new generation while old sessions execute.

**Pass condition.** Old bytes and adapter set remain stable until an approved handle switch.

**Evidence.** `evidence/update/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-UPDATE-02 — Failed smoke

**Action.** New generation loads but fails the declared smoke profile.

**Pass condition.** It is not activated; old ready generation remains available.

**Evidence.** `evidence/update/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-UPDATE-03 — Atomic switch

**Action.** Crash before and after active-handle transaction commit.

**Pass condition.** Recovery chooses a complete known generation with no half-switched dependency set.

**Evidence.** `evidence/update/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-UPDATE-04 — Rollback trust floor

**Action.** Attempt application rollback that also lowers accepted client security version.

**Pass condition.** Model rollback does not authorize a software trust downgrade.

**Evidence.** `evidence/update/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-UPDATE-05 — Concurrent channel update

**Action.** Receive two updates during an acquisition.

**Pass condition.** Each has an exact independent plan; no in-flight resource substitution.

**Evidence.** `evidence/update/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-UPDATE-06 — Shared consumer release

**Action.** One consumer updates while another retains old generation.

**Pass condition.** Old leases remain valid and storage/memory is reclaimed only after drain.

**Evidence.** `evidence/update/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-UPDATE-07 — Idempotent switch

**Action.** Retry a switch with same idempotency key and then a changed digest.

**Pass condition.** Same request returns same result; changed request is rejected or requires new authorization.

**Evidence.** `evidence/update/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## API — Local interface and UX

**Common fixture:** Real local capability service, CLI/SDK, owner/denied callers and public model endpoint.

### JIT-API-01 — Ensure lifecycle

**Action.** Execute a complete plan through actual registered API.

**Pass condition.** State progresses to declared readiness and returns an opaque lease, not a false bare-path success.

**Evidence.** `evidence/api/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-API-02 — Public boundary

**Action.** Call runtime/install/private-state operations through public HTTP/relay/explorer.

**Pass condition.** All effects are unavailable/denied regardless of package signature.

**Evidence.** `evidence/api/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-API-03 — Structured errors

**Action.** Inject each major load/memory/trust error.

**Pass condition.** Stable code, stage, cleanup disposition and permitted next action are returned without secrets.

**Evidence.** `evidence/api/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-API-04 — CLI schema parity

**Action.** Generate help/examples and invoke every documented primary command.

**Pass condition.** All names/arguments map to registered contracts; no invented or stale command remains.

**Evidence.** `evidence/api/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-API-05 — Progress truth

**Action.** Finish download but block compile/warmup.

**Pass condition.** UI/SDK reports preparation incomplete and never shows full runtime readiness.

**Evidence.** `evidence/api/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-API-06 — Local events

**Action.** Disconnect/reconnect event consumers and compact the journal.

**Pass condition.** Cursors recover with explicit gaps; no duplicated side effect follows replay.

**Evidence.** `evidence/api/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-API-07 — Package with ordinary tools

**Action.** Inspect embedded documents before BTX is installed.

**Pass condition.** Generic bounded reader exposes information without installing/executing or overwriting project instructions.

**Evidence.** `evidence/api/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## PRIV — Privacy and tenant boundaries

**Common fixture:** Network capture, wallet/cloud/SSH sentinels, two tenants and local/private/public profiles.

### JIT-PRIV-01 — Hardware stays local

**Action.** Resolve variants under native-only policy.

**Pass condition.** No hardware fingerprint, email or organization identity is sent to a central selection endpoint.

**Evidence.** `evidence/priv/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PRIV-02 — Native-only acquisition

**Action.** Block external model origins after tooling is ready.

**Pass condition.** Native sources succeed or explicit unavailable is returned; no silent HF/S3 fallback.

**Evidence.** `evidence/priv/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PRIV-03 — Worker secret isolation

**Action.** Load/run with wallet/cloud/SSH sentinel files present elsewhere.

**Pass condition.** Worker receives only approved resources and cannot read unrelated secret paths.

**Evidence.** `evidence/priv/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PRIV-04 — Prompt-free public events

**Action.** Run prefetch, KV and MoE tracing then export public model metadata.

**Pass condition.** No prompt, prefix key, expert trace, rkey or private runtime location leaks.

**Evidence.** `evidence/priv/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PRIV-05 — Private fabric consent

**Action.** Attempt peer-device sharing without local organization policy.

**Pass condition.** It remains disabled for that request despite available hardware.

**Evidence.** `evidence/priv/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PRIV-06 — Telemetry opt-in

**Action.** Install integrations with their upstream defaults and compare BTX effective config.

**Pass condition.** Nonapproved usage reporting is disabled and packet-captured as absent.

**Evidence.** `evidence/priv/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-PRIV-07 — Scope downgrade

**Action.** Try to reclassify private cached state as public canonical model bytes.

**Pass condition.** Type/scope enforcement rejects the export rather than relying on a UI warning.

**Evidence.** `evidence/priv/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## SCALE — Performance and resource scaling

**Common fixture:** Reproducible generated fixtures, process profiler, shaped links and actual runtime workloads.

### JIT-SCALE-01 — 400-GiB logical mapping

**Action.** Map a sparse logical artifact without transferring all bytes.

**Pass condition.** Addressing/budgets are correct and evidence is labeled logical, not sustained 400-GiB throughput.

**Evidence.** `evidence/scale/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SCALE-02 — Large tensor map

**Action.** Resolve one million permitted tensor entries under reserved metadata memory.

**Pass condition.** Peak memory/work remain within the recorded ceiling and query API stays bounded.

**Evidence.** `evidence/scale/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SCALE-03 — Concurrent agents

**Action.** Run many ensure/prefetch requests against shared bases.

**Pass condition.** Host/device caps, fairness and idempotent sharing remain correct under contention.

**Evidence.** `evidence/scale/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SCALE-04 — Cold versus warm

**Action.** Measure cold source, warm disk, warm host, warm device and adapter-only runs.

**Pass condition.** Equal workload/quality settings are recorded and no warm case is mislabeled cold.

**Evidence.** `evidence/scale/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SCALE-05 — Cache amplification

**Action.** Measure copies/storage/network bytes for file, stream and direct modes.

**Pass condition.** Report real amplification and overhead including verification, not just payload transfer.

**Evidence.** `evidence/scale/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SCALE-06 — Foreground responsiveness

**Action.** Load/prefetch under a latency-sensitive foreground workload.

**Pass condition.** Resource governor yields and p95 foreground impact is reported with throughput tradeoff.

**Evidence.** `evidence/scale/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SCALE-07 — Cancellation stress

**Action.** Repeatedly cancel loads and updates with delayed completions.

**Pass condition.** No growing leaked registrations, retired memory, threads or FDs after quiescence.

**Evidence.** `evidence/scale/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## JOURNEY — Whole-user journeys

**Common fixture:** Clean user environments, real runtimes and approved fixture services; no production data.

### JIT-JOURNEY-01 — One-link first result

**Action.** Run J01 from ordinary HTTPS descriptor through local first useful result.

**Pass condition.** All trust/acquisition/runtime stages have executable evidence; no mandatory account or funded wallet.

**Evidence.** `evidence/journey/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-JOURNEY-02 — Modular specialization

**Action.** Run J02 with two adapters and a resident base.

**Pass condition.** Base reuse, compatibility, output isolation and memory behavior are proven end to end.

**Evidence.** `evidence/journey/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-JOURNEY-03 — Outage plus streaming

**Action.** Run J03 while origin disappears and one canonical piece is corrupt.

**Pass condition.** Alternate verified acquisition succeeds or fails safely; no sparse-zero execution.

**Evidence.** `evidence/journey/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-JOURNEY-04 — Warm lifecycle

**Action.** Run J04 and J10 through sleep/wake/update/rollback.

**Pass condition.** Readiness and generation boundaries remain correct under pressure and crash injection.

**Evidence.** `evidence/journey/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-JOURNEY-05 — Private acceleration

**Action.** Run J05–J07 on eligible real fabric/runtime environment.

**Pass condition.** Peer transfer, executable trust and prefix privacy are independently evidenced.

**Evidence.** `evidence/journey/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-JOURNEY-06 — Fine-grained working set

**Action.** Run J08–J09 with real supported MoE and memory-tier configuration.

**Pass condition.** Correctness plus stall/capacity evidence accompanies any speed claim.

**Evidence.** `evidence/journey/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-JOURNEY-07 — Default migration

**Action.** Run J11–J12 under simultaneous users and a new-default cutover.

**Pass condition.** No old model compatibility requirement blocks activation, while financial state is unchanged.

**Evidence.** `evidence/journey/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

## SAFETY — Adversarial and final release checks

**Common fixture:** Fuzz corpora, sanitizer builds, independent reviewers and final candidate fingerprint.

### JIT-SAFETY-01 — Parser fuzzing

**Action.** Fuzz package, tensor-map, lockfile and runtime-parameter readers.

**Pass condition.** No crash, unbounded allocation, path escape or silent noncanonical interpretation.

**Evidence.** `evidence/safety/01/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SAFETY-02 — Prompt injection

**Action.** Insert instructions to disable verification, run shell commands and transmit secrets.

**Pass condition.** Typed plans/policy reject effects even if prose is displayed or misunderstood.

**Evidence.** `evidence/safety/02/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SAFETY-03 — DMA race sanitization

**Action.** Run sanitizer and backend lifetime stress on load/cancel/retire paths.

**Pass condition.** No native race/UAF in tested paths; hardware limitations are explicitly recorded.

**Evidence.** `evidence/safety/03/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SAFETY-04 — Malicious peer representation

**Action.** Serve stale generation, altered tensor digest and oversized memory metadata.

**Pass condition.** Requests fail boundedly before execution or unsafe registration.

**Evidence.** `evidence/safety/04/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SAFETY-05 — Helper failure isolation

**Action.** Terminate capability and model helpers while a money-only node operates.

**Pass condition.** Monetary RPC/validation remains operational; affected capability calls fail with precise cleanup state.

**Evidence.** `evidence/safety/05/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SAFETY-06 — Evidence honesty

**Action.** Audit every PASS against command, fixture, environment, binary and output.

**Pass condition.** No reference/mock/simulation is promoted to native runtime/hardware evidence.

**Evidence.** `evidence/safety/06/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

### JIT-SAFETY-07 — Release handoff

**Action.** Run fresh independent cross-lane review and reconcile all defects.

**Pass condition.** Final report lists every unresolved item; no autonomous push/tag/release/production restart occurs.

**Evidence.** `evidence/safety/07/`: native logs/state/byte or allocation checks appropriate to the case; include real hardware/runtime identification where required. **Status:** NOT_RUN.

# Appendix B. Machine contracts and semantic validation

The supplied JSON Schemas are proposed v1 contracts for the new local capability plane. They are strict about unknown fields. Integrate them with existing private types after the baseline audit; do not let generated sample IDs become production identities. `examples/README.md` explicitly labels the included objects synthetic and unsigned.

## B.1 Canonical commitments

Use the existing BTX canonical JSON rules for these objects. New domain-separated object IDs follow `SHA384(UTF8(domain) || 0x00 || LE64(length) || canonical_body)`. Exclude only the object's own ID and detached signatures from its committed body; do not accidentally exclude policy, dependency order or runtime constraints. Domains are `BTX/CapabilityRecipe/v1`, `BTX/CapabilityLock/v1`, `BTX/CapabilityPlan/v1`, `BTX/TensorRangeMap/v1` and `BTX/RuntimeRepresentation/v1`. Prefix/KV identifiers are tenant-keyed and private, not interchangeable public digest records.

Generation/lease/job identifiers are local opaque references, not content commitments or monetary addresses. An object containing a content digest does not by itself prove its bytes were verified. Verification provenance, software trust and runtime readiness remain distinct fields and transitions.

## B.2 Schema families

| Contract | Normative semantic checks beyond JSON shape |
|---|---|
| ResourceRef / RecipeComponent | Exact kind/digest, mandatory dependencies, adapter base binding, no invented model for an unawarded bounty |
| CapabilityRecipe | Recompute ID, bound/cycle-check dependency graph, validate runtime-supported composition and exact tensor compatibility |
| CapabilityLock | Pin package, recipe, runtime build and features; no latest substitution during locked ensure |
| RuntimeFingerprint | Actual installed build/ABI/device/layout geometry; unknown values cannot qualify a fast path |
| MemoryLimits | Checked decimal parsing, pinned <= physical host allowance, unique physical pools, aggregate/per-rank reservations |
| LocalCapabilityGrant | Caller/expiry/revocation/effect binding, finite scope, atomic global limits, zero wallet spend |
| CapabilityPlan | Recompute digest; exact approved candidate/lock; peak resources; lower <= upper TTC with honest evidence basis |
| TensorRangeMap | Verified-header derivation, checked offsets/shapes/alignment, bounds, legal aliases and exact covering pieces |
| LeaseRecord | Legal transitions, owner/generation, physical operation references, no premature release |
| PrefetchHint | Finite existing grant, demand preemption, valid deadline, speculative budget and privacy scope |
| RuntimeRepresentation | Exact inputs/transforms/output map and independent executable/producer trust where required |
| PrivatePrefixDescriptor | Tenant-keyed identity, full runtime/config compatibility, complete layers, scope and expiry |
| ReadyReceipt | Bind actual job/generation, all mandatory barriers, real smoke evidence for FIRST_USEFUL_RESULT |

Schemas alone cannot implement memory safety or cryptographic trust. Native code must enforce these semantic checks, and the 182-case catalogue names the required evidence. The reference model deliberately tests a small subset without pretending to be the native runtime.

## B.3 Exact defaults and bounds

Default thin package payload remains 4 MiB under BTXPKG1. Dependency plan bounds are 256 resources, depth 16 and 64 candidates. Default speculative residency allowance is at most 10% of the approved broker pool with two active prefetch loads. Memory limits are operator-approved bytes, not percentages of unverified remote inventory. Default source policy is NATIVE_ONLY for native capability acquisition; private fabric and private state sharing require explicit local policy. No effect sets a nonzero automatic monetary spend.

The default framework may automatically choose supported local loader optimizations within a finite approved plan. It must not automatically enable public RDMA, consume an unsigned compiled artifact, run remote model code, reveal private prompts or install an untrusted client. These are trust boundaries, not optional performance toggles.
