# BTX Swarm 0.35 — Security adversarial evolution and operations

Document: **BTX-SWARM-SPEC-13**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** Threat model and concrete mitigation contract; included controls have focused tests, not a complete security audit.

## Assets and adversaries

Protect operator resources, private model membership, prompts and datasets, credential custody, software integrity, current execution authority, model lineage, reproducible evidence, earned obligations and native monetary safety. Consider malicious discovered peers, admitted but dishonest workers, colluding evaluators, a compromised controller, corrupted disks, rollback snapshots, faulty GPU transfers, supply-chain packages and unavailable payment counterparties.

**SEC-001.** Never treat an endpoint signature as proof of honest work. Native artifact hashes prove identity, not quality. Shared KV producers, aggregators and evaluators require independent accountability. A malicious producer can generate valid hashes over poisoned results; a malicious controller majority can rewrite its own claimed decisions. Current crash-fault Raft is not Byzantine defense.

## Confidentiality and authority

**SEC-002.** Private family IDs, prompt prefixes, work details and data grants must not enter public discovery. Private data storage uses realm-scoped encryption. Membership revocation stops future access but cannot erase previously delivered plaintext; key rotation and compartmentalization must minimize future exposure. The current shared realm key does not provide per-recipient cryptographic revocation.

**SEC-003.** Native wallet/private keys never cross into swarm workers. Child environments use allowlists. Payment administration has a distinct local token/socket and no default scheduler bridge. Source patches do not change monetary consensus, native wallet behavior or transaction broadcast rules.

**SEC-004.** Every consequential stage rechecks its relevant authority: task claim, lease renewal, artifact access, derivative/cache release, candidate certification, channel activation and any eventual payment. Cached authorization is not perpetual authority. Cross-host instantaneous revocation is impossible during arbitrary partitions; production policies must define bounded leases, freshness requirements and a fail-closed response rather than promise instantaneous global deletion.

## Model and data poisoning

The target must limit untrusted update influence, preserve provenance, validate data rights, reject nonfinite/oversized/incompatible tensors, use independent evaluations, retain negative results, monitor broad regressions and quarantine suspect descendants. Clipping alone is not Byzantine-robust aggregation. A trusted admin's attestation labels are not Sybil-proof organizational identities.

Benchmark suites need controlled access, precommitted procedures, sample deduplication and trial-budget accounting. Shared labels between training and evaluation can contaminate evidence even if files have different hashes. Repeated testing and cherry-picking can invalidate naïve confidence claims. The implemented bound addresses a declared maximum trial count; it does not prove that publishers did not test privately or leak holdouts elsewhere.

**SEC-005.** A candidate's independence closure must include training, data, aggregate and controller contributors, not only the named publisher. The current author exclusion is a useful local rule but insufficient public independence proof. Hidden contributor collusion and independently executed challenge tests remain audit requirements.

## Execution and memory safety

Bound request sizes, tensor headers, offsets, dimensions, token counts, task fan-out, queues, verification concurrency and subprocess work. Do not load pickle or `trust_remote_code`. Canonical paths and per-process private directories reject symlink inputs; same-UID compromise remains outside that isolation boundary. Strong multi-user protection needs audited `openat`/descriptor-relative operations and OS enforcement.

The reference tensor validator bounds bytes and checks dtype/shape/finite values. It is not a universal defense against every resource-exhausting model configuration. Hard resident memory, disk, power and accelerator limits require OS/runtime integration. A Python process with a finite step count can still consume too much memory within one step.

## Transport and cryptography

Current mTLS pins certificates and signing identities. OpenSSL ML-DSA signing and ML-KEM invitation protection are exercised. Do not advertise native PQ1 interoperability, negotiated post-quantum TLS key exchange, FIPS qualification or cryptographic zeroization from these tests. Python-managed key material and temporary files have limitations even when filesystem permissions are private.

LAN cards are bounded/rate-limited but signatures invoke a local crypto process and cards may fragment. CPU exhaustion, TLS handshakes, peer certificate churn, HTTP connection pools and per-role upload budgets need hostile-network tests. Existing private/absent distinctions must be audited for membership or content inference.

## Supply chain and software provenance

**SEC-006.** Pin production engine versions and wheels by hashes; build an offline package with a reviewed source/dependency manifest. Installed-module detection is not a qualification certificate. Do not download code at startup or auto-run source files from an imported model. A signed model is not a signed executable builder.

The handoff wheel, if included, contains only this project's code. Third-party runtime wheels, OpenSSL, GPU drivers and pretrained models are not bundled. All runtime-specific qualifications must identify exact versions/builds, hardware and functional tests.

## Operational incident response

On suspected poisoning: freeze the affected candidate/channel, retain evidence, halt newly scheduled work from implicated grants, preserve prior admitted checkpoints and investigate scope. On key compromise: revoke the principal, rotate dependent realm keys where possible, invalidate future leases and stage reviewed replacements; do not silently remap identity history. On backing reorg or spend: freeze new financial commitments without erasing earned obligations.

Backups must include metadata, evidence, active claim material, identity recovery material under separate custody and retained checkpoint availability. A backup without the last enforceable payment state can be financially unsafe. Current payment models do not have such enforceable state; that is a release blocker, not a backup shortcut.

## Audit standard

The coordinator must record every new failure and its independent regression test. No known issue is closed solely by renaming a flag, reducing evidence requirements, mocking a backend or increasing a timeout. Static source review, isolated compilation, unit execution, native node execution, real hardware, WAN and independent audit are separate evidence classes.

## Capability and page copies

Advertised capability is separate from qualified capability. A local model can run with an empty provider key. A KV page is copied only when fingerprints match. Recovery of a recorded balance does not stop a device and does not spend.

`btxd` is the control plane. A missing catalog does nothing. Automatic spend atoms stay 0. `preparefundmodelrelease` builds an unsigned plan and does not spend.

Two physical hosts, three peers, a second GPU, Windows, macOS, offline images, and the release gates remain later work.
