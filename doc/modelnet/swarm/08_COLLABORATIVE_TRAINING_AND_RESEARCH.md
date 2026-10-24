# BTX Swarm 0.35 — Collaborative training and research

Document: **BTX-SWARM-SPEC-08**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** The swarm thread runs one CPU AdamW step on a sequence-4 hidden-8 network. The GPU step returns `ENGINE_ABSENT`. `qualified_v41()` stays false. Two ranks exchange 4 bytes on one host. An integer replay checks 8 pairs in-process. Full-state resume, a second training process, cohort aggregation, grouped REINFORCE, and wide-area training remain design.

## Training profiles and exact identity

**TRN-001.** Every run binds exact input checkpoint, recipe, model/optimizer configuration, admitted dataset artifacts, data order/cursor, random state, software environment, precision and contribution authority. A final weight hash alone is not a resumable training state. A change to any bound training component creates a new run or an explicit migration/derivation record.

The specified reference decoder is a causal model, deliberately bounded below 100 million approximate parameters. Its purpose is portable correctness and lifecycle qualification. It is a qualification target, not a new frontier model, and not a replacement for production serving kernels.

The specified trainer applies gradient updates with SGD momentum, finite checks, and clipping. Training-state SafeTensors include model parameters, momentum buffers, sampling RNG, cursor, step, and observed token count. Restore reconstructs the optimizer state without pickle. SafeTensors headers are canonicalized for deterministic identity. Exact uninterrupted versus resumed training is a qualification target on one CPU and software profile. That profile remains design.

Cross-hardware floating-point execution is not generally bit-identical. The target Lab bridge must distinguish byte-exact replay, numerically bounded recomputation and independently reproducible quality. Do not weaken an existing native strict-admission requirement by calling nondeterministic output “replayed.”

## Fast local training islands

**TRN-002.** Tightly coupled collectives belong inside a measured high-bandwidth island. `btxd` does not start `torchrun` or a collective. Compatible nearby peers may share a cohort only when the checkpoint and recipe match. An incompatible branch forks.

A missing GPU or collective library is `ENGINE_ABSENT` and moves no bytes. This process does not start `torchrun`, NCCL, FSDP, or ZeRO, and it does not open a collective port to a public peer. Incompatible branches fork. A merge stays unaccepted until an independent evaluation accepts it.

## Cooperative outer rounds

**TRN-003.** A `TrainingCohort` pins family, current base checkpoint, recipe, eligible island identities, minimum island count, contribution token ceiling, clipping policy and round. A contribution must reference a COMPLETE matching worker job, the current base/recipe, exact worker generation, output artifact and measured token count. Contributions from a different round or incompatible job are rejected.

The specified `aggregate_round` retrieves SafeTensors updates, validates tensor schema and finite values, clips contributions, weights compatible updates by approved token counts, applies an outer momentum step, and persists both new weights and outer optimizer state. It uploads the new artifacts before advancing the round with exact accepted update IDs. A later qualification runs that path on two workers. Fabricated vectors passed into an unconnected API do not satisfy it. The one-host 4-byte exchange does not satisfy it.

This is compatible local-SGD aggregation. It is **not** an implementation or reproduction of Decoupled DiLoCo. It does not safely average unrelated fine-tunes, arbitrary architectures, inconsistent tokenizers or independently initialized adapter bases. Incompatible branches remain forks or require separately evaluated merge/distillation experiments.

## Wide-area asynchronous training contract

The target profile should allow islands to perform multiple local steps between bounded global exchanges, overlap communication, tolerate limited staleness and survive individual island failure. The recipe must declare optimizer ownership, update weighting, staleness limits, compression/quantization error feedback, clipping, accepted membership changes and convergence metrics. A stale worker must not overwrite a newer baseline by presenting a valid hash for an old update.

A production integration with Hivemind, DiLoCo-derived systems or another chosen framework must preserve its actual algorithm, not merely borrow the name. Pin the upstream revision and record supported topology, tested model size, update volume and time-to-quality. WAN parameter exchange must not be mistaken for low-latency expert dispatch on each token.

## Experience generation and reinforcement learning

**TRN-004.** Rollout workers use an exact frozen checkpoint and produce bounded trajectories under explicit data consent. Independent tests/verifiers provide rewards. Reward generation is not automatically trusted because it came from the same model that produced the answer.

The specified trajectory store binds checkpoint and group, consented visibility, prompt and completion lengths, and reward scale. Grouped REINFORCE recomputes log probabilities with gradients, centers and scales group rewards, rejects off-policy checkpoint mixing, and skips zero-variance groups. That update is the specified policy-gradient profile. PPO and GRPO remain separate algorithms. Full distributed experience ingestion, reward-server isolation, off-policy correction, KL and reference models, and adaptive learner scheduling remain required for a production RL profile.

**TRN-005.** Private prompts and proprietary source are not automatically training examples. A trajectory requires explicit dataset permission and derivative-release policy. A model update can leak information even when raw data stays local. Differential privacy, secure aggregation or confidential execution require explicit mechanisms and measured privacy/utility bounds; none is implied by encrypted transport.

## Research diversity and reuse

Model work may include candidate generation, adapter specialization, recipe search, distillation, data curation, independent replication, negative experiments and challenger generation. Research records preserve failed results and source provenance. Sharing findings and tool results can improve the community without changing base weights; the four timescales of knowledge, strategies, specializations and new generations remain distinct processes.

A challenger task must be valid, informative and independently verifiable. Rewarding only hard or unsolved tasks can degrade training. Synthetic tasks need a generator identity, generator policy and independent validity checks before entering fitness measurements.

## Required training qualification

For each profile: check full-state resume, cancelled collective cleanup, duplicate and stale updates, corrupt shards, NaNs, dropout, heterogeneous steps, changed datasets, authority revocation before release, and failed aggregation recovery. Report time to a predefined quality threshold and total compute and communication, not just optimizer steps per second. Those checks remain the qualification for a later release.

## What btxd runs now

The swarm thread inside `btxd` runs one CPU AdamW step on a sequence-4 hidden-8 network. The GPU step returns `ENGINE_ABSENT`. `qualified_v41()` stays false.

Two ranks exchange 4 bytes on one host through a loopback socket. `physical_hosts()` is 1. This is not a second machine and not a shared-memory fabric across a network. An integer replay checks 8 pairs in-process. It is not a second process replaying a trained model. That CPU step and that exchange do not train an authorized recipe on a qualified machine, and they do not give a second machine a result to check.

## Later releases

Toward a fully autonomous network, a participant acquires a verified model from another participant. Compatible state can move to an admitted machine. A qualified machine trains an authorized recipe and a second machine checks it. Evaluated descendants can be staged and adopted under a local policy. A private defensive case runs under an explicit customer grant.

Verifications required first: two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. The one CPU AdamW step and the one-host 4-byte exchange are not those verifications. TRN-001 through TRN-005 stay design until a second machine has checked an authorized recipe.
