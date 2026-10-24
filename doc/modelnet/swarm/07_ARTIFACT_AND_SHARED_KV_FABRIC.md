# BTX Swarm 0.35 — Artifact and shared KV fabric

Document: **BTX-SWARM-SPEC-07**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** A piece is accepted only when its SHA-384 matches the id and the body is at most 32 MiB. A ciphertext body is `REALM_SEALED` and is not decrypted. A KV prefix mismatch is `PREFIX_MISMATCH`. A prefetch without an engine is `ENGINE_ABSENT` and moves no bytes. An invalid eviction deletes nothing, and the index is committed before an orphan delete. Incomplete bytes are `INCOMPLETE` and are not trusted. GPU zero-copy, NIXL, Mooncake, and RDMA are `ENGINE_ABSENT`. Approximate cross-model KV reuse is not enabled.

## Object transport and storage

**KV-001.** Durable artifacts are exact immutable byte objects, divided into bounded 4 MiB pieces with SHA-384 verification. Manifests bind artifact identity, length and ordered piece identities. Transfer may resume from verified pieces; a manifest is not usable until required pieces have been verified. Paths from peers are never storage keys or shell arguments.

A ciphertext piece is `REALM_SEALED`. This process does not apply AES-GCM and does not decrypt it. An eviction plan must be valid before any referenced piece is removed. `SwarmCommitCas` marks the index committed before it records an orphan deletion. Unverified bytes are `INCOMPLETE` and are not trusted. Acceptance of a plaintext piece does not transfer bytes.

**KV-002.** Cross-realm plaintext deduplication must not reveal membership or content equality. An untrusted storage source can be used for authenticated ciphertext, but the producer's correctness is a separate trust decision. The current store is local to the sidecar or worker, not a native ModelNet CAS replacement. Native acquisition and retention must be reconciled through an explicit bridge.

Current flat manifests allow at most 16,384 pieces, corresponding to 64 GiB at full piece size. Large frontier checkpoints, optimizer states and datasets need hierarchical manifests, streaming indexing and bounded metadata roots. Do not claim support for arbitrarily large models merely because payload pieces are individually small.

## Exact KV compatibility

**KV-003.** A compatible KV handle binds exact checkpoint, architecture, tokenizer, ordered adapters, runtime build, dtype, layout, position encoding, attention mask, quantization profile and tenant epoch. It also binds the exact token-prefix identity, page ranges, layers, KV-head geometry, lengths, producer and expiry. Sharing a family ID is not sufficient.

The reference layout is `[batch, heads, tokens, head_dimension]` for each layer's K and V. Prefix identities are keyed in the realm; no private plaintext prefix digest is published globally. Pages are complete immutable tensors. Suffix branches use copy-on-write semantics: an existing prefix's bytes do not change when a new continuation appends tokens.

**KV-004.** Appending a causal token does not invalidate existing prefix KV. Altering an earlier token or any compatibility-bound model parameter invalidates dependent state. The consumer must either recompute or use a specifically validated transformation; it may not reinterpret incompatible tensors as memory.

The specified transfer moves SafeTensors KV pages over authenticated network endpoints and validates geometry before use. A reuse check recomputes the final input token because the portable handle does not include trusted final logits. That check is a correctness target for a later release. It is a design for reuse correctness, and it is not a throughput benchmark.

## Producer assurance and privacy

A content hash proves byte identity, not that those bytes were computed from the promised weights and prefix. A malicious producer can publish a self-consistent poisoned tensor. A worker accepts exact caches only from explicitly trusted producer identities, and locator assurance stays producer-asserted. A model author's signature does not by itself authorize executable compiler caches or runtime software.

**KV-005.** Cache pages do not replace Lab replay/admission, work evidence, a fresh execution grant or independent evaluation. A cache is disposable. Missing, expired, corrupted or incompatible pages cause recomputation, not reduced admission assurance.

Treat KV as potentially prompt-revealing data. Prevent cross-tenant lookup oracles, normalize unauthorized cache responses and scope encryption/lookup keys. Revocation blocks new accesses but cannot undo already copied tensors. Production key-epoch rotation, hit/miss timing defenses and endpoint metadata indistinguishability require additional review.

## Placement and prefetch

Compare three alternatives: execute near an already resident compatible cache, transfer needed pages to a suitable runtime, or recompute locally. Include queueing, transfer setup, useful bandwidth, missing page fraction, memory pressure, CPU/GPU copies and expected continuation probability. Prefer an uncached idle worker over an overloaded cached worker when total completion time is lower.

A model-independent cost estimate for conventional attention KV is `2 × layers × KV_heads × head_dim × prefix_tokens × bytes_per_element`, excluding replication, allocator padding and quantization metadata. It is a sizing tool, not a performance result. Do not multiply unrelated published speedups together.

Work graphs should provide next-use hints: retain a parent context while a tool runs, prefetch for known children, demote inactive branches, and preferentially retain shared ancestors. Runtime allocators retain authority over actual memory residency. Exact reuse, placement, and engine-integrated workflow prefetch remain design.

## Production acceleration profiles

| Profile | Required integration | Current delivery |
|---|---|---|
| Exact local/shared prefix | Runtime-compatible pages, complete fingerprint | Prefix mismatch is `PREFIX_MISMATCH`. No engine is `ENGINE_ABSENT` and moves no bytes |
| vLLM / SGLang prefix and host tiers | Version-pinned launch/config and live output checks | `ENGINE_ABSENT`. This process does not start those engines |
| LMCache distributed tier | Qualified current connector/backend contract | `ENGINE_ABSENT`. No bytes are moved |
| NIXL / Mooncake / RDMA | Registered-memory lifetime, connection auth, data ownership, completion fencing | `ENGINE_ABSENT`. No bytes are moved |
| LoRA/base decomposition | Proven shared subgraph, adapter ordering and quality checks | Adapter mismatch is `PREFIX_MISMATCH`. Silent decomposition is refused |
| Cross-model transformed KV | Pair-specific converter plus held-out equivalence/error policy | Refused. A different fingerprint is `PREFIX_MISMATCH` and is never silently enabled |
| Compiled/runtime caches | Trusted builder, exact runtime/compiler/shape and source binding | A signed model is not a builder. Incomplete bytes are `INCOMPLETE` |

A high-performance feature is automatically eligible only when a compatible, locally authorized and empirically qualified implementation exists. Availability of an importable module is discovery, not qualification.

## What btxd runs now

The swarm thread inside `btxd`, once, publishes and pulls one local snapshot body and refuses a second host. KV movement in this pass is the 8-byte memory echo. A named remote engine returns `ENGINE_ABSENT` and moves no remote bytes.

Two ranks exchange 4 bytes on one host through a loopback socket. `physical_hosts()` is 1. This is not a second machine and not a shared-memory fabric across a network. Piece checks, realm sealing, prefix mismatch, and an absent prefetch stay on this host. They do not acquire a verified model from another participant, and they do not move compatible state to an admitted machine.

## Later releases

Toward a fully autonomous network, a participant acquires a verified model from another participant. Compatible state can move to an admitted machine. A qualified machine trains an authorized recipe and a second machine checks it. Evaluated descendants can be staged and adopted under a local policy. A private defensive case runs under an explicit customer grant.

Verifications required first: two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. The 8-byte memory echo and the one-host 4-byte exchange are not those verifications. KV-001 through KV-005 and the acceleration profiles above stay design until that catalogue accepts them.
