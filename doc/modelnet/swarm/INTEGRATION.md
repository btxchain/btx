# Swarm integration in this tree

This tree is **0.35.0rc1**. The process map, the public contract, and the in-process records are in [00_THIS_TREE.md](00_THIS_TREE.md).

The swarm is the default. With Modelnet compiled, `-modelnet` is on and `btxd` starts the helper and the observer thread. Participation is that thread, not a second daemon.

The swarm is integrated as a thread inside `btxd`.

`src/init.cpp` calls `modelnet::StartSwarmObserver` after the model helper when `-modelnet` defaults on. `-modelnet=0` skips that call and logs that the model network is disabled. The monetary node still starts. The observer runs on a `std::thread` owned by the `btxd` process. Shutdown calls `StopSwarmObserver` and joins that thread. If a step throws or returns an error, the thread logs the error with the monetary node continuing. A swarm failure does not stop consensus.

## Current behavior

About every two seconds, while the thread is running:

1. Verified, explicitly complete catalog entries are reconciled into `modeldir/swarm/observers.json`. Removed, unverified or incomplete entries lose their active subscription; an empty or missing catalog clears existing subscriptions. The file is observers only. It records no grant, no seed, and no spend. `automatic_spend_atoms` in that file is the string `"0"`, and payment authority is false.
2. The local mesh is refreshed.
3. The catalog is integrated into `swarm/contribution.json` using the same bounded reader and lineage resolver as the observer.
4. `SwarmFormPlane` runs. `FormationPlane` does not exec a sidecar, open a socket, add a DNS seed, broadcast, or spend.
5. `SwarmPublishLive` runs. A missing contribution file succeeds and spends nothing.

Both views use `swarm/lineage-mappings.json` when an artifact has a local mapping; otherwise they derive a private `PROVISIONAL_NOT_AUTHORITATIVE` topic from `model_id`. Contribution economy IDs derive from that resolved lineage. Catalog `visibility: public` alone cannot publish a provisional topic or set its contribution `seed` flag. Removing a mapping restores the private provisional identity. The existing `VERIFIED_MAPPING` label records trust in local operator policy: this reader does not cryptographically authenticate an external mapping file.

`observers.json` is the last successful catalog snapshot, not a durable follow-history list. Malformed catalog or mapping input fails without replacing that snapshot, and the observer skips live publication for that poll. A failed contribution integration also skips formation and live publication. Retained files alone do not prove current eligibility or authorize work. Successful polls refresh the views; separate file replacements are not an atomic transaction across all swarm files.

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

## Control plane bounds

`btxd` is the control plane. A missing catalog clears stale observer/contribution entries and grants no work authority. Automatic spend atoms stay 0. `preparefundmodelrelease` builds an unsigned plan and does not spend.

Advertised capability is separate from qualified capability. A local model can run with an empty provider key. A KV page is copied only when fingerprints match. Recovery of a recorded balance does not stop a device and does not spend.

Physical multi-host and GPU qualification, native Windows/macOS execution, disconnected runtime-image tests, and the complete release gates remain outstanding. The implemented Linux image workflow and local native tests do not close those gates.

## Later releases

Follow-on work toward a fully autonomous network:

- Physical multi-host qualification of the implemented peer discovery and observer admission.
- Physical multi-host qualification of verified acquisition and continued service after peer loss.
- Submitting a task or prompt and receiving model work.
- Authorized training checked by a second machine.
- A private defensive case under an explicit customer grant.
- Settlement of accepted work in BTX only under an operator-signed mandate.

Those claims wait on verification with two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. One machine and two local ranks are not two hosts. Spend stays 0 until a mandate exists.
