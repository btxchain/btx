# Parallel implementation plan

The coordinator owns the integration branch and all shared contracts. Each specialist uses a separate worktree and returns small tested commits. Separate agents are engineering parallelism and review, not proof of independent real-world bounty evaluators.

| Lane | Exclusive responsibilities | Interfaces consumed | Review partner |
|---|---|---|---|
| C0 | Baseline/delta, contract registry, helper/RPC/CMake integration, release gate | All | A8 |
| A1 | Complete signed records, authorization/tombstones, canonical codec and URI registry | Existing crypto/identity | A8, A7 |
| A2 | Exact supported escrow trees, PSBT, funding/award/staging/claim/refund | Terms, chain snapshot | A3, A7, A8 |
| A3 | Registered outpoint index, confirmation provenance, reorg undo and recovery | Existing validation notifications, lot lineage | A2, A8 |
| A4 | Installed evaluation profiles, isolated processes, reports/challenges | Submission/spec IDs, governor | A8 |
| A5 | Search/feed/index/cursors/jobs/economy joins and health correctness | A1 records, A3 economic snapshots | A6, A8 |
| A6 | Qt workflows, safe public API, external explorer | Frozen RPC/response contracts | A7, A8 |
| A7 | Roles, finite agent mandates, signer approvals/idempotency | Wallet plans, verified terms | A2, A8 |
| A8 | Regression/property/fuzz/functional/chaos and independent patch review | All production entrypoints | C0 |
| A9 | README/AGENTS, API/schema docs, source pins/license/evidence manifest | Integrated actual code and commands | C0, A8 |

## Wave gates

0. Preserve work, freeze actual starting SHA and compare the current PR to the reviewed head. Produce a per-gap disposition before editing.
1. Fix critical metadata/wallet boundaries and demonstrate exact old/new monetary script compatibility. Schemas and ID derivation must have no circular commitments.
2. Implement domain state, council/funding/lot logic, chain index, evaluation and authorization in parallel.
3. Integrate discovery/feed/economic joins and GUI/public API. Shared helper and RPC registrations receive one integrator.
4. Run real public-award, sealed-stage, failed-bounty-refund, reorg and agent-concurrency scenarios.
5. Run scale/soak/chaos, supported builds, docs examples and final requirement-evidence reconciliation.

## Shared-file protocol

Before changing a shared header/schema, propose the change to C0. C0 increments contract version, reviews affected callers and assigns one patch owner. Never keep two diverging implementations of the same API. No force reset or clean on another worker's changes. No automated merge merely because a subagent says complete.

## Resource controls

Default at most two native builds and one isolated GPU evaluation job, adjusted to observed memory/storage. Unique datadirs, ports, sockets, temp directories and PIDs per worktree/test. Pin references outside BTX. Never use the live attestor GPU, manipulate a production service or run unsafe test code with monetary credentials.

## Evidence handoff

Every lane returns commits, exact implemented symbols/paths, tests and commands, environment and log/digest references, interface changes, remaining issues and negative-case results. A9 prepares documentation; it cannot manufacture test PASS. C0 is responsible for ensuring each test actually exercised the new live code path rather than a constant helper, mock-only substitute or unused library.
