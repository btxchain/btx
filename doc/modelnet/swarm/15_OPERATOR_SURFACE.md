# Operator surface

The swarm an operator is running is a thread inside `btxd`. ModelNet defaults on. `-modelnet=0` turns the thread off. There is no separate swarm startup command; the node supervises its model helper and guard child.

Modelnet defaults on. `src/init.cpp` starts the supervised helper and then `modelnet::StartSwarmObserver` with the node model directory. That thread is the default swarm membership. `StopSwarmObserver` runs at shutdown and joins the thread. A failure inside the thread is logged. The monetary node continues. `btx-swarmd` and `btx-paynetd` are not used, because participation is this thread rather than another program. The reference Python package is not the running control plane.

## Current behavior

About every two seconds the thread checks catalog generations, reconciles changed views into `observers.json` and contribution state, refreshes expiring native peer observations, calls `SwarmFormPlane` when needed, and publishes eligible live state. `observers.json` is observers only: no grant, no seed, and no spend. `FormationPlane` does not exec a sidecar, open a socket, add a DNS seed, broadcast, or spend.

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

## Engine probe

`SwarmProbeEngine` and `SwarmQualifyEngine` are in-process library calls. The observer thread does not use them to qualify a release, and it does not start vLLM. On the observer path, vLLM stays `ENGINE_ABSENT`.

`SwarmProbeEngine` checks a runtime name and a filesystem path.

- An empty name or path is `ENGINE`.
- A missing path, or a path that is not a regular file, is `ENGINE_ABSENT`. `present`, `advertised`, and `qualified` stay false. The call does not start a process.
- A regular file is `INSTALLED`. It is not advertised.

`SwarmQualifyEngine` may set `advertised` and `qualified` only when the probe already returned `INSTALLED`, the caller sets `measurement_supplied`, and `tokens_per_sec` is finite and greater than zero. That caller-supplied rate is not a hardware benchmark. The function does not start an execution engine or a GPU. A missing engine stays `ENGINE_ABSENT`.

No latency, tokens per second, VRAM, or bandwidth figure belongs on this page. None was measured here.

## Direct invoice book

`SwarmInvoiceBook` is an in-process ledger for one direct invoice. The observer thread does not open it, and a row in the book is not a mandate.

- `Open` once. A second open is `REOPEN`.
- `Create` stores a beneficiary, an objective, a positive atom count, and a hashlock. It does not spend.
- `Reserve` binds one liquidity id. A second owner is `DOUBLE_RESERVE`.
- `Reveal` settles one matching 32-byte preimage inside the book. A SHA256 mismatch is `HASHLOCK`.

`MultiHopQualified` stays false. A hashlock is not a qualified routed network. The book has no broadcast flag. `Spend` on the observer path returns `"0"`. Settlement of accepted work stays in [Later releases](#later-releases).

## What this page does not claim

Windows, macOS, a second GPU, a second physical host, and a linked remote execution engine are not operational here. An advertised pool balance is not spendable. Local component checks do not qualify the node.

## Local model and balance recovery

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
