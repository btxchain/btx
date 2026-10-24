# BTX Swarm 0.35 — Performance scale and acceptance methodology

Document: **BTX-SWARM-SPEC-14**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** Measurable target and failure-test contract. Included tests establish mechanics on one CPU host, not competitive throughput or internet-scale model training.

## Performance objectives

**PER-001.** Optimize accepted useful work per elapsed time and total resource cost at a stated quality level. Measure end-to-end task completion, time to first useful token, p50/p95/p99 latency, useful tokens/second, accepted rollouts, time to target validation quality, recovery loss and energy where available. Cache hit rate and optimistic generated-token count are diagnostic metrics, not final value measures.

**PER-002.** Compare the same model weights/quantization, tokenizer, context distribution, task population, hardware, software build, quality threshold and total resource budget. A larger swarm should not claim an algorithmic speedup merely because it received more GPUs or an easier evaluation suite. Report scaling efficiency separately from aggregate throughput.

Do not multiply independent upstream benchmark maxima. Cross-model approximation must report quality loss and its uncertainty. A transferred cache may cost more than prefill on a weak link; cache-aware scheduling must include transfer/queue/memory overhead and choose recomputation when faster.

## Benchmark matrix

| Dimension | Required cases |
|---|---|
| State temperature | Cold source, warm disk, warm host, resident device, warm prefix |
| Agent work | Shared common prefix, divergent suffixes, tool pauses, nested subagents, no reusable context |
| Placement | One runtime, same host, same LAN, independent WAN islands |
| Training | Local baseline, local DDP, compatible outer rounds, asynchronous WAN profile |
| Evolution | Multiple candidates, negative results, specialist trade-offs, policy exhaustion, revoked evaluator |
| Faults | Worker kill, leader kill, stalled transfer, partition, stale cache, disk full, corrupted snapshot |
| Economy | Duplicate reservations, collateral spend/reorg, unavailable payer, stale states, mass exits |
| Privacy | Cross-realm lookup, stale membership, private family advertising, revoked derivative release |

Tests must include worst-case or adversarial inputs, not only cache-friendly workloads. Record controls and sample sizes; repeated runs are necessary for latency/throughput claims. A deterministic correctness test's wall-clock duration is not a statistically qualified benchmark.

## Hierarchical scale architecture

**PER-003.** Keep fast execution local and global information sparse. Global family discovery should carry immutable summaries and bounded peer hints, not every task or tensor. Execution neighborhoods prefer resident context. Training islands use local collectives; global cohorts exchange qualified slower updates. Scoped economic budgets share a reusable payment network rather than proliferating channel openings per model.

The delivered reducer has bounded jobs, pages, scans and a single serialized SQLite writer per committee. Internal scans fail closed instead of silently ignoring excess records. These limits make resource use visible; they do not prove scalability beyond existing systems. Production needs indexes for live allocations, retention/compaction, hierarchical artifact manifests, per-realm control sharding, stable cursors, bounded replication streams and admission backpressure.

## Reference-package qualification dimensions

The optional `contrib/swarm` Python reference suite uses real cryptographic operations, encrypted disk objects, real mutual-TLS HTTP connections, separately identified workers, trusted child-process training/inference, two-process Gloo gradient synchronization and actual synthetic model evolution. Some tests use in-memory message routing or direct reducer calls for deterministic fault schedules; those are marked as protocol/state tests, not WAN experiments.

The original reference handoff described a native supervisor/launcher fixture and a CMake fixture with a dummy `btx-modeld` target. Those fixture results did not establish a complete BTX node build. This checkout now integrates the observer directly into `btxd`; see [INTEGRATION.md](INTEGRATION.md). Native verification uses the real CMake build and `test_btx` suites, with functional tests against the resulting daemon. Reference-package results cannot be inherited as native PASS.

## Required large-system experiments

For LAN qualification use a declared set of real independent machines and a pinned production inference engine. Run three configurations: independent agents; coordinated agents without cross-host cache; coordinated agents with shared cache. Separately measure work-graph benefits and KV benefits. Test engine cache pollution and transfer overhead under both friendly and unfriendly workloads.

For WAN training use independently administered islands, measured bandwidth/RTT distributions, bounded outages and a declared convergence target. Compare identical total training compute and data. Report staleness, update rejection, optimizer-state recovery and statistical quality. Do not infer success from a four-step toy update.

For evolution demonstrate a real eligible open model with data rights, multiple candidate descendants, independent evaluations on unseen tasks, preserved specialist forks, failure of at least one coordinator and actual local channel adoption. For economics demonstrate native unilateral recovery and real payer/worker ownership on regtest before any significant funds are used.

## Acceptance evidence format

Every result must include requirement ID, source commit/diff hash, executable hashes, platform, runtime versions, hardware/topology, exact command, start/end time, outcome, raw evidence locations and limitations. Valid outcomes include PASS, FAIL, NOT_RUN, NOT_IMPLEMENTED and BLOCKED. Documentation of an acceptance recipe is not PASS.

The reference handoff names `evidence/execution.json`, JUnit XML and `IMPLEMENTATION_STATUS.json` as its evidence outputs. Those names are not proof that such artifacts are present or current in this checkout. Each new run must retain its own commands, source and binary hashes, outcomes and raw logs; scope blockers must be recorded independently. Passing tests cannot turn an absent GPU backend or absent native payment transaction builder into a release-qualified capability.

## What this tree runs

The objectives, matrix, and large-system experiments above are the measurement contract. This section records the runs this tree has completed. A recipe written here is not a PASS.

`btxd` starts `StartSwarmObserver` in-process after the model helper. The branch includes the 0.35 lab tip through merge commit `ee9648fd` on top of `b35d1b9d`.

Two process-local suites have already exited 0:

- In-process bind suites on `b35d1b9d`: 14 cases, exit 0.
- Earlier journal and requirement suites on `56f00405`: 62 cases, exit 0.

The live pass is latched: an 8-byte memory echo of `abcdefgh`, vllm `ENGINE_ABSENT`, one CPU AdamW step, a one-host two-rank loopback exchange, 8 integer replay pairs, one snapshot, one realm seat, then the requirement and cycle checks. Spend is `0`. Release is `UNQUALIFIED`. `passed()`, `gpu_passed()`, and `windows_passed()` stay false.

A one-GPU two-process script on one machine has exchanged two ranks and reported `RELEASE_QUALIFIED 0`. That run is one machine. A release requires two hosts, so the release stays `UNQUALIFIED`. The outcome of that script is not a PASS for a multi-host or GPU-scale claim.

## Later releases

Later releases move toward a fully autonomous network. Until the verification named with a claim has been completed, that claim stays `NOT_RUN`.

- Peer discovery and local admission require two physical hosts, with every privileged peer absent.
- Acquiring a verified model from another participant requires a signed artifact moving between two processes that are not the same snapshot object.
- A submitted task or prompt returning model work requires a user-supplied prompt on a linked execution engine. The latched echo is the fixed internal text `abcdefgh`, and that text does not meet this claim.
- Authorized training checked by a second machine requires a second physical host and, for a GPU claim, a second GPU. One device and two ranks do not qualify.
- A private defensive case requires an explicit customer grant. Private prompts stay off until that grant exists.
- Settlement requires an operator-signed mandate and an isolated-regtest payment. Until then spend stays `0`.
- Windows, macOS, an offline release image, the hardware profiles, and the sealed acceptance catalogue stay unverified.

### Later-release acceptance checks

Later releases add these acceptance runs. A recipe in this section is not a PASS. Until a named run is complete, that run stays `NOT_RUN`.

- Separate advertised capability from qualified capability.
- Run a second research cycle rather than latching the first.
- Recover a recorded balance while the model runtime is down, without stopping the device and without an automatic spend.
- Compare a fixed local corpus against a single-agent score and a combined score.
- Run a local model when no provider key is set.
- Copy a KV page between workers when fingerprints match.
- Keep local discovery, assignment, and inference working when optional cloud integration is off.
- Treat an unsigned funding plan as not yet a settlement.
- Qualify two physical hosts, three peers, a second GPU, Windows, macOS, offline images, and the release gates before calling the network release-ready.
