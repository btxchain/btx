# Swarm

The swarm is a thread inside `btxd`. `src/init.cpp` calls `modelnet::StartSwarmObserver` after the model helper when `-modelnet` defaults on. `-modelnet=0` turns the thread off. A failure is logged and the monetary node continues. `btxd` does not launch `btx-swarmd` or `btx-paynetd`. The reference Python package under `contrib/swarm` is not the running control plane.

## Current behavior

About every two seconds the thread checks catalog generations, reconciles changed views into `observers.json` and contribution state, refreshes expiring native peer observations, calls `SwarmFormPlane` when needed, and publishes eligible live state. `observers.json` holds observers only: no grant, no seed, and no spend. `FormationPlane` does not exec a sidecar, open a socket, add a DNS seed, broadcast, or spend.

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
[NATIVE EXECUTION AND RELEASE EVIDENCE](swarm/16_NATIVE_EXECUTION_AND_RELEASE_EVIDENCE.md).
Automatic spend stays zero, unavailable engines remain explicit, and the
candidate and all unqualified profiles remain unqualified. Local process tests
do not establish physical multi-host, GPU or independent-organization results.

Piece selection, endgame, peer exchange, and partial piece serving are design notes in [libtorrent-parts-bin-audit.md](libtorrent-parts-bin-audit.md), [piece-selection.md](piece-selection.md), [provider-exchange.md](provider-exchange.md), and [nat-traversal.md](nat-traversal.md). libtorrent and qBittorrent were studied as parts bins and were not vendored. qBittorrent is GPL, so the study is interface only and the code was never copied. The observer thread does not carry out that sharing design.

## Later releases

Follow-on work toward a fully autonomous network:

- Physical multi-host qualification of the implemented peer discovery and observer admission.
- Physical multi-host qualification of verified acquisition and continued service after peer loss.
- Submitting a task or prompt and receiving model work.
- Authorized training checked by a second machine.
- A private defensive case under an explicit customer grant.
- Settlement of accepted work in BTX only under an operator-signed mandate.

Those claims wait on verification with two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. One machine and two local ranks are not two hosts. Spend stays 0 until a mandate exists.
