# BTX swarm observer

When ModelNet is compiled, `-modelnet` defaults on. `btxd` supervises the model helper, then calls `modelnet::StartSwarmObserver` in `src/init.cpp`. The observer is a thread inside `btxd`. `-modelnet=0` turns it off. A swarm failure does not stop the monetary node.

About every two seconds the thread reads `catalog.json` into `modeldir/swarm/observers.json` when the catalog is usable. Those rows are observers only: no compute grant, no seeding, and no spend. A missing catalog changes nothing.

The thread refreshes the local mesh, integrates the catalog, runs `SwarmFormPlane`, and publishes the live record. `FormationPlane` does not exec a sidecar, open a socket, add a DNS seed, broadcast, or spend.

Once, then latched: a memory decode of the fixed public text `abcdefgh` for 8 bytes; a vllm pull returns `ENGINE_ABSENT`; one CPU AdamW step on a sequence-4 hidden-8 network; a loopback exchange of two ranks on one host; an integer replay of 8 pairs; one snapshot; one realm seat. A second host is refused.

Once, then latched: `TickBind` runs the in-process requirement, the 12-step node cycle, the module check, and the safe-slice check. `passed()`, `gpu_passed()`, and `windows_passed()` stay false. Spend returns the string `0`. Release returns `UNQUALIFIED`.

`btx-swarmd` and `btx-paynetd` are not started by `btxd`. Model RPCs still go to the model helper. Retrieval is `FREE_ONLY` and automatic spend atoms stay `0`.

This branch also contains the current 0.35 lab tip, including the wallet balance-watch RPCs `getbalancewatch` and `getbalanceatheight`, model and bounty funding updates, and the `htlc_sha256` presign path.

## Later releases

The next releases are the path to a fully autonomous network.

- Peers find each other and admit a local group.
- A participant acquires a verified model from another participant.
- A person submits a task or a prompt and receives work from a model on an admitted machine.
- A qualified machine trains on an authorized recipe, and a second machine checks the result.
- A private defensive case runs under an explicit customer grant.
- Accepted work settles in BTX only under a mandate the operator signed.

Before any of those are claimed, the verifications still required are two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. Two local ranks on one machine are not two hosts. Spend stays 0 until a mandate exists.
