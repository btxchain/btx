# BTX Swarm 0.35 — Product and default lifecycle

Document: **BTX-SWARM-SPEC-01**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** This tree is **0.35.0rc1**. With ModelNet on, `btxd` runs the swarm as a thread in the monetary process. The thread records observers. It does not spend, and it does not admit a second host. The candidate is not release-qualified. The process map is [00_THIS_TREE.md](00_THIS_TREE.md).

## Mission and boundaries

A model is a persistent evolutionary lineage, not merely a download. The product goal is that ModelNet, the lab records, the swarm, and the payment templates live inside `btxd`, and that monetary consensus stays unchanged. The running thread meets the placement goal and does not meet the rest of the lifecycle below. `Spend` returns `"0"`. There is no spend key on this path.

**LIF-001.** A successfully acquired, byte-verified, complete model MUST cause local observer subscription and model-family discovery without an additional feature switch. Discovery MUST NOT require a GPU, a wallet, a paid account, or a training-capable representation. The running observer reconciles active rows to catalog entries with `bytes_verified: true` and `incomplete: false`; removal, loss of verification, or unknown completeness removes the subscription. A missing catalog clears active subscriptions. This snapshot is not follow history. That write is not a grant to seed, train, or spend.

**LIF-002.** A known immutable artifact-to-lineage mapping MUST retain its lineage through packaging, quantization and eligible specialization. Without independently verified mapping, create a private provisional topic from `model_id` and mark it `PROVISIONAL_NOT_AUTHORITATIVE`. Do not assert common ancestry merely because labels, tensor dimensions or repository names match. Provisional topics stay unpublished. Observer and contribution views share the local mapping resolver, including private visibility on fallback and economy identity derived from the resolved lineage. See [INTEGRATION.md](INTEGRATION.md) for snapshot freshness and invalid-input handling.

**LIF-003.** Observer subscription is update awareness, public research metadata, and eligible discovery. It does not authorize public seeding, execution, private prompt routing, third-party credentials, data contribution, monetary spending, or automatic admission of untrusted software. There is no implicit training-data collection on ordinary inference.

**LIF-004.** A persistent operator contribution policy is what will control device-wide slots, CPU threads, VRAM reservation, and maximum work per job. Budget and consent are authority. Battery, temperature, metered-network, and hard host-memory governors remain required before a general desktop release. The running thread does not schedule contribution work.

**LIF-005.** Improvements MAY coexist as general, specialist, experimental, and hardware-specific descendants. A family maintains a frontier, not one universally forced checkpoint. A community can continue to evolve while an individual remains an observer or pins an older generation. The running 12-step cycle stays at generation 0 with `passed()` false.

## Lifecycle

| Event | Required default |
|---|---|
| Model download incomplete | No usable subscription or runtime |
| Verified download completes | Establish family observer subscription |
| Public mapped family appears locally | Advertise bounded family presence |
| Operator accepts invitation | Join exactly the signed realm and roles |
| Operator grants idle contribution | Schedule permitted work automatically |
| Compatible cached state exists | Compare safe reuse options |
| Candidate obtains sufficient evidence | Graduate for its stated niche |
| Channel passes canaries | Stage and optionally locally adopt |
| A regression is detected | Retain or revert the previous eligible generation |
| Objective is funded | Show backing and payable liquidity separately |

## Current behavior

Modelnet defaults on. `src/init.cpp` starts the supervised `btx-modeld` and then `modelnet::StartSwarmObserver` in the `btxd` process. That thread is the default swarm membership. `-modelnet=0` is the off switch. A failure is logged and the monetary node continues. Shutdown joins the thread. There is no extra swarm startup flag; model and guard helpers are supervised by the node. `btx-swarmd` and `btx-paynetd` are not used, because a separate daemon would make participation something the operator has to turn on. The reference Python package is not the control plane.

About every two seconds the thread checks catalog generations, reconciles changed observer/contribution views, refreshes expiring peer observations and publishes eligible live state. Observer membership grants no computation or spending authority. `FormationPlane` does not exec a sidecar, open a socket, add a DNS seed, broadcast, or spend.

The observer owns a real `btx-guardd` child through private inherited pipes.
Each poll supervises that process and publishes a bounded heartbeat in
`swarm/guard-process.json`; clean shutdown publishes `STOPPED` and reaps the
child. A guard permit records authorization consumption, not completed work.

The helper performs bounded private-LAN discovery and strict-PQ1 peer
observation. Its expiring `native-participation.json` snapshot feeds observer
membership and locally verified shared-model families. Fresh headless implicit
`auto` storage uses a bounded 1 GiB cache; explicit zero, saved refusal and
owner-selected limits take precedence. Eligible first-model acquisition uses
the existing verified download worker. Acquiring bytes and observing a family
do not authorize computation, private data access or spending.

Production observer startup no longer calls `NifObserve::Tick`,
`SwarmBoundProbe::Pass` or `TickBind::Pass` to latch in-process acceptance
records. Those library probes remain available for explicit tests. Native
qualification uses finite commands and actual execution evidence described in
[NATIVE EXECUTION AND RELEASE EVIDENCE](16_NATIVE_EXECUTION_AND_RELEASE_EVIDENCE.md).
Automatic spend stays zero, unavailable engines remain explicit, and the
candidate and all unqualified profiles remain unqualified. Local process tests
do not establish physical multi-host, GPU or independent-organization results.

## Explicit non-goals and compatibility

Do not alter BTX block validity, proof of work, issuance, transaction serialization, chain selection, or wallet ownership. Do not infer that a qualified research object is qualified software. Do not infer that an open download grants unrestricted rights to train or redistribute derivatives. Do not promise that an open model manifest can tax all independent uses of the weights. Other artifact origins remain compatible import and export destinations subject to independently checked provenance and permissions.

## Product acceptance

A release demonstration begins with a clean install and an eligible model acquisition, not a preseeded test database. It shows the joined family, remaining permissions, the active device budget, and the followed channel. At least three independently administered machines maintain the community after one coordinator disappears. The measured local process tests do not meet that physical deployment demonstration. One machine and two local ranks are not two hosts.

## Later releases

Follow-on work toward a fully autonomous network:

- Physical multi-host qualification of the implemented peer discovery and observer admission.
- Physical multi-host qualification of verified acquisition and continued service after peer loss.
- Submitting a task or prompt and receiving model work.
- Authorized training checked by a second machine.
- A private defensive case under an explicit customer grant.
- Settlement of accepted work in BTX only under an operator-signed mandate.

Those claims wait on verification with two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. One machine and two local ranks are not two hosts. Spend stays 0 until a mandate exists.

### Later-release lifecycle checks

Later releases add the following.

- They separate advertised capability from qualified capability.
- They run a second research cycle rather than latching the first.
- They recover a recorded balance while the model runtime is down, without stopping the device and without an automatic spend.
- They compare a fixed local corpus against a single-agent score and a combined score.
- They run a local model when no provider key is set.
- They copy a KV page between workers when fingerprints match.
- They keep local discovery, assignment, and inference working when optional cloud integration is off.
- They treat an unsigned funding plan as not yet a settlement.
- They qualify two physical hosts, three peers, a second GPU, Windows, macOS, offline images, and the release gates before calling the network release-ready.
