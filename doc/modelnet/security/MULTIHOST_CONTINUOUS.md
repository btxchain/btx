# BTX model security v2: enrolled multi-host continuous protection

This document describes **new code supplied in this PR descendant**, not a claim
that existing PR #245 is production-ready. The in-process `btxd` observer retains
its usual lifecycle and continues to supervise a private, separately isolated
`btx-guardd`. Existing `btx-modeld` PQ1 sessions carry the bounded signed
mesh exchange; there is no second daemon, bootstrap server, wallet requirement,
or new public security socket. Existing monetary consensus is not changed.

## Operational trust and safety boundaries

- A model download and a signed artifact do not authorize execution or permission
  upgrades. Artifacts are immutable SHA-384 composition records with explicit
  tokenizer, chat template, runtime and tool-schema bindings.
- Owner-provisioned root pins and a signed, versioned realm policy authorize a
  precise list of `peer`, `evaluator`, `worker`, `coordinator`, `publisher`,
  `release` and `owner` key identities. Roles are not inherited from LAN discovery.
- Every peer additionally has an out-of-band pinned transport identity; receiving
  a valid ML-DSA envelope over the *wrong PQ1 session* fails closed.
- Research participation, authorized compute, data rights, tool permissions,
  security evidence, channel promotion, release signing and money are **separate
  authorizations**. No peer record contains private workspace grants, wallet
  material, unbounded shell instructions, network URLs or raw prompts.
- Signed evaluator domains and physical-host labels are assertions under owner
  policy, not independent evidence of real machine/operator independence. A
  physical acceptance reviewer must inspect the actual inventory and evidence.
- A second machine's signature does not prove the model has no hidden backdoor.
  A failed or unknown model still cannot run privileged actions through the
  security-v2 broker without a currently valid, independently checked grant.

## New native source and data flow

```
 btxd (money + native observer)                    peer B: btxd (money + observer)
    |                                                        |
    +--> btx-modeld -- existing authenticated PQ1 ----------+--> btx-modeld
    |      /btx-model/2/security/mesh (256 KiB max packet)   |
    |                                                        |
    +--> btx-guardd (owned private STDIO)                     +--> btx-guardd
            |                                                         |
      SQLite local policy                                         SQLite local policy
      signed campaigns & leases                                   pinned worker packages
      challenge coordinator                                       local sandbox execution
      remote results / negative reports                           signed receipts/results
      live quorum and channel safety                              remote challenge tests
            |                                                         |
      tool/activation denied if peer evidence stale   <--signed--+-- sandboxed report
```

The node-owned guard's first handshake waits up to five seconds while the
private directory and database open. Later health checks keep the short
exchange budget. A guard that does not answer fails closed and does not stop
money.

The mesh transmits signed `campaign`, `challenge`, `evaluation`, `receipt`,
`composition`, `capsule`, `work`, `result`, `channel`, `revocation` and `anchor`
records only under strict per-realm identities and explicit export rules.
It does **not** transmit raw model checkpoint data; model bytes must be acquired
from the normal verified ModelNet store and locally admitted before execution.

`src/modelnet/security_v2/mesh.{h,cpp}` implements the signed exchange,
nonces, rate limits, packet bounds, 30-second peer leases, cursor/want evidence
convergence and scheduled campaign rounds. `work.{h,cpp}` implements pinned
bounded remote static-worker execution and cross-signer result quorum checks.
`service.cpp` runs the scheduler every ~2 seconds and queues approved local
challenge and work executions. `broker.cpp` and `lifecycle.cpp` require the
continuous evidence quorum before protected actions/activation once enrolled.

## Owner enrollment (not permission to run remote executable code)

1. On each machine, install the same separately authorized root pins and
   versioned signed realm policy with the appropriate independently created
   ML-DSA identity. Record peer PQ1 transport pins out of band.
2. Ensure `modeldir/security/local.json` is only owner-writable. Its
   `BTX/SecurityLocal/v1` includes `host`, `identity`, explicit resident
   artifacts and approved packages, plus (for enrolled nodes):

```json
"continuous_security": {
  "enabled": true,
  "max_evidence_age_ms": 25000,
  "allowed_campaigns": ["<SHA-384 campaign IDs>"],
  "allow_private_evidence": false
}
```

   A campaign is a signed `BTX/SecurityEnvelope/v1` with kind `campaign` and
   body binding realm, policy epoch, exact composition, approved package,
   security gate, suite, sample commitment, interval (at least 2000ms),
   maximum rounds and expiry. The six gates are external-controls, outcome,
   revocation, rollback, privacy and adversarial. No arbitrary peer can add a
   campaign to another operator's local allowlist.
3. Import the owner-signed campaigns and publish them with the local
   `modelsecurity` `mesh-export` command. On any intended protected host, use a
   fresh one-time owner-signed `control` record with `operation=mesh-enroll` via
   `modelsecurity {"op":"mesh-enroll","record":...}`. This permanently
   establishes the local `mesh_required` gate until a separately reviewed
   recovery or new policy migration; the mesh cannot be bypassed by removing
   the config or hiding evidence.
4. For bounded remote work, the host must *additionally* opt in with:

```json
"remote_work": {
  "enabled": true,
  "packages": ["<owner-installed static plan ID>"],
  "compositions": ["<complete immutable composition ID>"]
}
```

   The work record must contain a signed exact composition and capsule, plan
   digest, input and expected output digests, purpose (`verification`, `inference`
   or `training`), target host, fresh nonce, short expiry and max output bytes.
   Despite the purpose names, **this version runs only approved deterministic
   static native workers**, not real neural inference, gradient training, model
   refinement or remote checkpoint publication. Results return signed hashes
   and limited metadata rather than private output or generated text.

## Continuous activation and failures

For each gate, the coordinator schedules recurring bound challenges. Locally
approved evaluator nodes run the actual pinned sandbox probe and produce
signed evaluations and execution receipts. Peers gossip them across existing
native PQ1 connections. The coordinator requires enough distinct **enrolled**
evaluator domains and host labels, plus current live peer leases, for the most
recent campaign round; the full current six-gate set must be covered. An older
pass does not authorize a new untested descendant.

Once `mesh_required` is set, missing signed campaigns, negative reports,
expired leases, stale evidence, revocation, a stopped guard or a nonexistent
sandbox blocks protected authorization and model adoption. Monetary processing
continues. A stopped evaluator does not silently count as an online evaluator.
As with all distributed leases, partitions do not instantly revoke work on
remote machines; local fail-closed behavior is bounded by the explicit lease
and evidence-validity windows. Retained plaintext cannot be cryptographically
recalled after release. A fresh positive report must not erase a negative
incident; incident policy should freeze affected channels pending review.

## Implementation acceptance: the tests that actually ran

The test suite constructs one coordinator and two independent evaluator/worker
**databases**, using distinct ML-DSA identities and pinned transport identities.
It sends real signed messages through `MeshRequest`, `MeshHandle` and `MeshAccept`,
proves convergence, schedules and runs all six real Linux static-worker probes,
checks signed output receipts and two-worker work quorum, and verifies failures
when peer leases expire. It also checks peer replay and wrong PQ1 pins.

All these fixture identities ran **on one physical Linux host**. They establish
component execution and inter-node protocol logic, **not** live WAN, distinct
machine hardware, separate independent operators, useful LLM inference or
production security qualification. A Release build of `btxd`, `btx-modeld`, and
`btx-guardd` on that same host also ran `feature_model_security_v2.py`: the
default owner status has no policy, no automatic spend, continuous protection
off, and both production and physical-host qualification flags false. The
private guard IPC checks completed their handshake. Neither run is a second
physical host, a GPU pass, or a Windows or macOS result.

## Real deployment qualification that must still be performed

1. Build and execute the entire `btxd`/`btx-modeld`/`btx-guardd` tree on the
   exact parent commit, plus Linux/macOS/Windows-supported profiles, preserving
   the usual consensus and wallet tests. Validate that real PQ1 sessions carry
   the signed mesh and that no arbitrary peer can open owner RPCs.
2. Enroll at least **three physically separate systems** and independent operator
   accounts. Establish genuine separate trust roots and collect network-path,
   host-inventory and identity evidence. Verify absence of loopback/shared-
   machine shortcuts and independently review operators' administrative control.
3. Use `contrib/model-security/physical_acceptance.py` as a **read-only
   status precheck**, with 3–12 SSH host aliases in `{"hosts":[{"ssh_alias":
   "alice"},... ]}`. It uses strictly checked known SSH host keys, gathers
   locally hashed machine IDs and runs the `btx-cli modelsecurity` status query.
   Identifiers are not hardware attestation and never substitute for reviewer
   approval. The script deliberately cannot report qualified production.
4. Run a full model on a remote GPU and a fresh local host. Test real model
   retrieval and generation, authorized training with a second-host checkpoint
   verification, remote private-work boundaries, actual model-engine adoption,
   protected tool effects and rollback. Those bindings are *not implemented* by
   this package, so this test is blocked until the missing source is delivered.
5. Partition peers and revoke evaluator credentials while actual work and model
   upgrade requests are pending. Confirm external effects are denied under
   the configured lease bound, outputs are withheld, and monetary operation
   continues. Repeat after node restart and offline-image installation.
6. Record binary hashes, source-tree commit, OS versions, drivers, real hardware
   identity, physical network faults, signed evidence and **negative** findings.
   Require every repository release qualification profile to pass before any
   shipping or independently protected ModelNet claim. Do not flip qualification
   booleans or reduce the required evidence.

## CLI and monitoring

Use the existing authenticated local RPC, e.g.:

```sh
btx-cli modelsecurity '{"op":"status"}'
btx-cli modelsecurity '{"op":"mesh-status"}'
btx-cli modelsecurity '{"op":"mesh-export","id":"<96-hex model evidence ID>"}'
btx-cli modelsecurity '{"op":"work-quorum","id":"<96-hex work ID>"}'
```

`btx-security` signs policy and campaign records offline using a separately
provisioned secret file. It never generates wallet authorities. Local diagnostic
CLI requests must not be used simultaneously with the node-owned guard.

The critical status fields include `continuous_protection_required`,
`multi_host_security.authenticated_recent_peer_sessions`, `journal_valid`,
`maintenance_error`, `legacy_generatemodel_mediated=false`, and
`general_gpu_runtime_qualified=false`. The correct current claim is a tested
native component with real sandboxed static-worker executions and a signed,
continuously enforced protocol—not a fully protected multi-host LLM release.
