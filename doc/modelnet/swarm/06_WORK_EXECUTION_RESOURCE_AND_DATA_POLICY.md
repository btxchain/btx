# BTX Swarm 0.35 — Work execution resource and data policy

Document: **BTX-SWARM-SPEC-06**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** A normal `btxd` start runs one latched in-process work pass. It does not launch a trusted subprocess, collect a private prompt, or spend. General sandboxing and hard host-memory/power controls remain blockers. The subprocess and private-grant path below is later work and is not enabled.

## Executable operations

A normal `btxd` start does not launch the reference executors. The reference package names `torch.train`, `torch.rollout`, `torch.evaluate`, `dataset.verify` and the reference `inference` operation. `btxd` does not start that package. `sandbox` is not accepted as an implemented executor. Uploaded Python, pickle, dynamic model code and arbitrary shell commands are not execution inputs.

**EXE-001.** A model artifact never grants permission to install or execute software. Workers invoke a local installed interpreter and trusted module with explicit arguments; model-provided environment, command names and import paths are not honored. Engine processes use allowlisted inherited environment variables. Cloud credentials, model-hub tokens, wallet variables, RPC cookies, private keys, loader injection and Python path injection are not inherited.

**EXE-002.** Local contribution requires a persistent finite policy. A realm may reduce the operator's ceiling but may not increase it. A device-wide SQLite governor prevents independently joined realm workers from each assuming that the entire GPU is free. Concurrent tasks acquire reservations atomically; compatible ready tasks may run in parallel up to the shared budget.

The mesh record can store slot, VRAM, CPU thread, and optimizer-step fields from a local device file. A normal `btxd` start does not acquire a task reservation or start a worker from those fields. It does not measure actual idle state, battery condition, power, thermal state, metered bandwidth or enforce a cgroup memory ceiling. The setting named `idle_contribution` is authorization to run background work, not a claim of an implemented idle detector. Those missing governors are mandatory for unattended general-purpose desktop deployment.

## Input and output handling

Checkpoint and dataset bytes are acquired by immutable references, checked through the artifact store, and exported into a private task/lease directory. SafeTensors replaces pickle for tensor state. Model inputs cannot choose arbitrary absolute output filenames. Child result paths must remain within the managed task directory.

**EXE-003.** Secret-bearing control fields are rejected. Raw token arrays in replicated jobs require an explicit `PUBLIC_SYNTHETIC` declaration; private prompts are not routed through the control log. That classification is an authorized submitter assertion, not a content-based proof that no secret exists. There is no generic classifier that can safely infer permission from prompt contents.

For private data, use a local capability bound to realm, immutable data artifact, purpose, expiry and revocation state. `TRAIN` and `RELEASE_DERIVATIVE` are distinct permissions. Cache reuse and cache publication are likewise distinct. Model gradients and trained weights may themselves leak sensitive data; keeping raw files local is not a universal privacy guarantee.

**EXE-004.** Re-read local data authorization before execution, after child completion, before uploading derivative bytes/checkpoint state, and before completion publication. Expired or revoked grants fail the release gate. A revoked worker must also fail current peer membership and lease renewal at the coordinator. Already delivered plaintext cannot be recalled; transport and grant revocation are forward-looking.

The reference package rechecks each release stage. A normal `btxd` start does not export a private derivative and does not collect a private prompt. Chunk-by-chunk private derivative export and a fully independent credential-owner release service are not yet integrated. Until those boundaries are qualified, do not advertise a general private-data training exchange.

## Result semantics

A worker result includes a digest, executor/version-scoped evidence and logical completion state. It is not a proof of correct computation, a guarantee of improved model quality, or an irrevocable financial receipt. A trusted evaluator may accept it under a separate work contract. Negative experiments remain publishable and may earn contractually agreed base compensation rather than only winner bonuses.

## Process lifecycle

The reference worker describes managed children in their own process groups. A normal `btxd` start does not start those children; the latched pass leaves `launched` false. The worker renews leases while waiting; stopping contribution, lease rejection or shutdown triggers termination, a bounded wait, escalation if necessary, and a final wait for exit. Reservations are released only after this physical boundary. Controller and local worker failure can leave conservative held resources, which recovery must reconcile rather than hide.

The portable runner suppresses child stdout/stderr rather than logging arbitrary prompts; structured error details are bounded. Production observability must add privacy-preserving diagnostics and sanitized failure traces without introducing prompt/credential logging through monitoring agents.

## Required sandbox profile

A general coding or sysadmin executor must name its sandbox boundary. A remote manifest that selects a host interpreter or a provider credential is `EXECUTOR`. Without a sandbox the request is `SANDBOX_ABSENT`. `SwarmAdmitExecutor` does not start a child. `launched` stays false.

## Acceptance

Reference tests cover provider-secret exclusion, permission-revoked derivative release, expired/current work leases, physical cancellation accounting, fresh observer onboarding, actual finite training and inference subprocesses, and shared-cache reuse. Those checks are not a normal `btxd` start. Mandatory remaining tests include hard RAM/disk exhaustion, thermal and battery transitions, task starvation, external-tool authorization, multiple real GPUs competing across realms and arbitrary malicious model-format inputs under production runtimes.

## What btxd runs now

The swarm thread inside `btxd` records catalog entries as observers only. There is no compute grant, no seeding, and no spend. Automatic spend is "0". Private prompts are not collected.

`SwarmFormPlane` forms in-process. It does not open a socket, add a DNS seed, broadcast, or spend. Unknown neighbors are not contacted.

The latched work pass is a fixed public 8-byte memory echo, one small CPU training step, a one-host loopback exchange, an integer replay, one snapshot, and one realm seat. A remote engine name returns `ENGINE_ABSENT`. A second host is refused. Two local ranks are not two hosts. The pass does not start a child process.

## Later releases

Later releases, on the path to a fully autonomous network, are where a person submits a task or prompt and receives model work, training runs on an authorized recipe and a second machine checks it, and a private case runs only under an explicit grant. On that same path peers find each other and admit a local group, a participant acquires a verified model from another participant, and accepted work settles in BTX only under an operator-signed mandate.

Verifications still required: two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. Two local ranks are not two hosts.

These later behaviors are not enabled.
