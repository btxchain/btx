# This tree — 0.35.0rc1

`CLIENT_VERSION_MAJOR` is 0, `CLIENT_VERSION_MINOR` is 35, `CLIENT_VERSION_BUILD` is 0, `CLIENT_VERSION_RC` is 1, and `CLIENT_VERSION_IS_RELEASE` is true. `btxd -version` prints `v0.35.0rc1`. P2P subversion is `/BTX:0.35.0/` (no rc).

This branch is the 0.35 release candidate. It is not a qualified release and it is not the shipping tag `v0.35.0`. The last shipping tag remains **v0.34.15**. Do not recut `v0.34.15`, `v0.34.14`, `v0.34.13`, `v0.34.12`, or `v0.34.10`.

`automatic_spend_atoms` stays 0. `passed()`, `release_qualified()`, `gpu_passed()`, and `windows_passed()` stay false. A unit suite or a regtest script is not a native deployment.

## Two pillars

BTX is the monetary node and the Native Model Network in one repository. The money keeps MatMul proof of work, ExactReplay, post-quantum witness signatures, and the existing wallet. The model plane covers discovery, source and artifact identity, research records, admission, local execution evidence, and distribution inside a realm the operator chose.

A research record, a model score, a promotion, or an admission decision does not change block validity, issuance, difficulty, fork choice, BanMan, or AddrMan. `WITH_MODELNET=OFF` still builds and runs the monetary node. A failure on the model plane is logged. Consensus continues.

There is no mandatory network-wide scheduler, no agent owner, and no remote inference marketplace. Training, evaluation, and inference run on machines the participant chose. A missing execution engine returns `ENGINE_ABSENT` and moves no model bytes. No new transferable compute token is introduced. A person can read permitted public resources without a wallet balance.

The same mechanisms apply to one person, a community, and a larger site. Differences are policy, keys, and scale. They are not separate product binaries.

## Processes

| Program | Place in this tree | What it owns |
|---|---|---|
| `btxd` | `src/bitcoind.cpp`, `src/init.cpp` | Money, and by default the model helper plus the swarm observer |
| `btx-cli`, `btx-tx`, `btx-wallet`, `btx-util` | `src/` | Monetary tools |
| `btx-modeld` | `src/modeld.cpp` | Local model metadata, retrieval, admission policy, distribution state |
| `btx-modelcheck`, `btx-open` | `src/` | Check and open helpers for model artifacts |
| `btx-hcpd`, `btx-hosted` | `src/hcpd.cpp`, `src/hosted.cpp` | Typed hosted gateway. No raw arbitrary RPC passthrough |
| `btx-capability`, `btx-capabilityd` | `src/` | Capability tools |
| `btx-guardd` | `src/btx-guardd.cpp` | Local action mediator. The observer thread does not start it |

Modelnet is the default. When it is compiled, `-modelnet` is on unless the operator passes `-modelnet=0`. `btxd` then starts a supervised `btx-modeld` and `modelnet::StartSwarmObserver` in the same process. That thread is how the node takes part in the swarm. There is no extra swarm flag and no swarm program to launch. Shutdown joins the thread. A failure there is logged and the monetary node continues.

`btx-swarmd` and `btx-paynetd` are not part of this default. A second daemon would be a swarm the operator has to start, which is the opposite of every node participating as it comes up. `contrib/swarm` is a reference package. It is not the control plane, and `btxd` does not need it in order to run the observer.

The default this network is built for is a node that holds a verified model and joins that model's family with no separate join step. Starting nodes is how the swarm gains participants, replicates work, and evolves. The observer already subscribes a verified, complete catalog entry without another switch. A missing catalog still changes nothing: this candidate does not yet fetch that first model or enter a live family on an empty store. Closing that gap is part of the default, not an optional mode. Spend stays 0. There is still no network-wide scheduler assigning work.

`btx-hcpd`, `btx-hosted`, the capability tools, and `btx-guardd` are optional programs for a hosted gateway, capability checks, and a local action mediator. The default path does not ask the operator to start them.

Signing roots and wallet credentials stay out of the model helper. The money datadir and `modeldir` are separate. Observer files live under `modeldir/swarm/`, including `observers.json`, `contribution.json`, and lineage mappings. Those files record observers and local views. They are not a spend key and not a grant to seed or train.

## Public contract

The swarm contract for this candidate is the set below. Each document states the product rule and the behavior this tree actually runs.

| Document | Subject |
|---|---|
| [01_PRODUCT_AND_DEFAULT_LIFECYCLE.md](01_PRODUCT_AND_DEFAULT_LIFECYCLE.md) | Lifecycle, current observer, later releases |
| [02_ARCHITECTURE_AND_TRUST_BOUNDARIES.md](02_ARCHITECTURE_AND_TRUST_BOUNDARIES.md) | Processes, stores, authority |
| [03_WIRE_PROTOCOL_AND_RECORDS.md](03_WIRE_PROTOCOL_AND_RECORDS.md) | Records on the wire |
| [04_DISCOVERY_MEMBERSHIP_AND_MODEL_IDENTITY.md](04_DISCOVERY_MEMBERSHIP_AND_MODEL_IDENTITY.md) | Discovery and identity |
| [05_COORDINATION_LEASES_AND_RECOVERY.md](05_COORDINATION_LEASES_AND_RECOVERY.md) | Leases and recovery |
| [06_WORK_EXECUTION_RESOURCE_AND_DATA_POLICY.md](06_WORK_EXECUTION_RESOURCE_AND_DATA_POLICY.md) | Work, resources, data policy |
| [07_ARTIFACT_AND_SHARED_KV_FABRIC.md](07_ARTIFACT_AND_SHARED_KV_FABRIC.md) | Artifacts and shared KV |
| [08_COLLABORATIVE_TRAINING_AND_RESEARCH.md](08_COLLABORATIVE_TRAINING_AND_RESEARCH.md) | Training and research |
| [09_EVOLUTION_EVALUATION_AND_ADOPTION.md](09_EVOLUTION_EVALUATION_AND_ADOPTION.md) | Evaluation and adoption |
| [10_SWARM_ECONOMY_AND_FUNDED_OBJECTIVES.md](10_SWARM_ECONOMY_AND_FUNDED_OBJECTIVES.md) | Economy and funded objectives |
| [11_DIRECT_POST_QUANTUM_PAYMENT_CHANNEL_CONTRACT.md](11_DIRECT_POST_QUANTUM_PAYMENT_CHANNEL_CONTRACT.md) | Direct payment channel |
| [12_ROUTED_PAYMENT_MESH_AND_HTLC_SAFETY.md](12_ROUTED_PAYMENT_MESH_AND_HTLC_SAFETY.md) | Routed payments and HTLC checks |
| [13_SECURITY_ADVERSARIAL_EVOLUTION_AND_OPERATIONS.md](13_SECURITY_ADVERSARIAL_EVOLUTION_AND_OPERATIONS.md) | Security and operations |
| [14_PERFORMANCE_SCALE_AND_ACCEPTANCE_METHODOLOGY.md](14_PERFORMANCE_SCALE_AND_ACCEPTANCE_METHODOLOGY.md) | Acceptance methodology |
| [15_OPERATOR_SURFACE.md](15_OPERATOR_SURFACE.md) | Operator surface |
| [INTEGRATION.md](INTEGRATION.md) | How the observer thread is wired |

## Code layout

`src/modelnet/` is the `bitcoin_modelnet` library. The running control plane is the observer thread described in [INTEGRATION.md](INTEGRATION.md). Other translation units in that library are in-process records and helpers. A test can call them without the observer calling them.

In-process records compiled into the library, each with a unit suite, include:

- Acceptance journals `acc01` through `acc09`.
- Profile and qualification records `prf01` through `prf09`, `qat01` through `qat06`, and `rel01`.
- Process checks `proc01` through `proc09`, plus `set01` and `host01`.
- One verified checkpoint (`load01`), a manifest check (`cap02`), hire and release gates (`hire01`), a funding record (`pay02`), a local node count (`p2p03`), a funded-objective note (`set02`), and a discovery note (`lan01`).
- The observer record `obs01`. The thread that runs is `StartSwarmObserver`, not a call into every record above.

`src/modelnet/swarm_confine.cpp` and `src/modelnet/swarm_fsjail.cpp` confine a helper with Linux user, network, and mount namespaces. A macOS build with Modelnet still needs a confinement path that runs on that platform. Returning unsupported, or compiling those files only on Linux, is not that path.

Wallet work already on this branch includes `getbalancewatch`, `getbalanceatheight`, model and bounty funding updates, and presign of the `htlc_sha256` claim leaf. Those calls do not change `automatic_spend_atoms`.

## Later releases

The candidate does not yet find peers by itself, acquire a verified model from another participant, return model work for a submitted task, check training on a second machine, run a private defensive case under an explicit grant, or settle accepted work under an operator-signed mandate. Those are the later releases in [01_PRODUCT_AND_DEFAULT_LIFECYCLE.md](01_PRODUCT_AND_DEFAULT_LIFECYCLE.md) and [14_PERFORMANCE_SCALE_AND_ACCEPTANCE_METHODOLOGY.md](14_PERFORMANCE_SCALE_AND_ACCEPTANCE_METHODOLOGY.md).

The verifications those claims wait on are two physical hosts, a second GPU, Windows, macOS, a linked remote execution engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue. One machine and two local ranks are not two hosts. Spend stays 0 until a mandate exists.
