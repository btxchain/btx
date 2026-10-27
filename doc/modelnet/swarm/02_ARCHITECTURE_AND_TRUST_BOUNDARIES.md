# BTX Swarm 0.35 — Architecture and trust boundaries

Document: **BTX-SWARM-SPEC-02**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** Modelnet defaults on. The swarm runs inside `btxd` as the observer thread, together with the supervised `btx-modeld`. That is the default participation path. `btx-swarmd` and `btx-paynetd` are not a second product the operator starts. A missing GPU or transfer engine is `ENGINE_ABSENT` and moves no bytes.

## Process model

```text
btxd                         monetary consensus, wallet, UTXO state, and the swarm observer
  └─ ModelNet                catalog join, lineage, pieces, and the in-process swarm records
```

There is no second swarm binary and no extra startup flag. Payment templates are built in-process. `SwarmBroadcastFunding` returns `BROADCAST_FORBIDDEN`. The scheduler has no spend key.

**ARC-001.** Control, tensor movement, and durable research artifacts stay separate logical planes. No generated token, optimizer step, or cache hit needs an L1 transaction. A model-plane failure does not mutate monetary consensus state.

**ARC-002.** `StartSwarmObserver` runs from `btxd` startup. It does not spawn a sidecar. A missing dependency is not downloaded at startup.

**ARC-003.** The in-process command log is one committee in one process. It is not a network Raft cluster and it does not open a socket. Do not place mutually private realms under one shared key.

The target architecture MUST shard committees, logs, encryption and read authority by realm or explicitly co-governed realm group. A global family index may contain public lineage/frontier metadata, but private work graphs, dataset grants and KV directories must stay in their realm. Checkpoint references can cross boundaries only through approved promotion/export.

## Identities, authorities and capabilities

Presence cards verify an ML-DSA signature over a public artifact-to-lineage mapping. That signature is not a wallet spend key. Copying a wallet seed or returning a native private key is forbidden.

A transport pin proves the endpoint associated with a configured key. A role grant authorizes specific protocol operations. A resource policy permits local machine use. A data grant permits specified input and derivative release. An evaluation report supplies bounded evidence. A payment mandate limits financial authority. None of these substitutes for any other.

**ARC-004.** Trust-domain labels come from the realm's admitted policy, not from a participant's self-declared location. The code enforces label diversity but does not independently prove organizational independence. Public deployment requires an explicit trust registry, auditable owner changes and defenses against root multiplication.

## Data stores and crash domains

Swarm records that this process persists are files under the model directory, including the catalog join, the command log, mandates, attempts, and watchtower appointments. There is no `control.sqlite3` swarm database and no public rendezvous socket. A ciphertext piece is `REALM_SEALED` and is not decrypted here. Incomplete bytes stay untrusted.

## Service interfaces and authority flow

Discovery is the local catalog observer. `SwarmOpenPublicRendezvous` does not bind a socket. Peer control is not a mutual-TLS server in this process. The transfer path does not move KV tensors; a missing engine is `ENGINE_ABSENT`.

Workers cannot become voters by publishing presence. They cannot grant themselves resource budgets or access to another realm's cache. Controller election cannot transfer realm ownership. A new leader receives authority to sequence the existing journal, not authority to rewrite policies or spend funds.

## Distributed scale target

Use a sparse global public discovery overlay, bounded neighborhood caches, realm-local committees and hierarchical training cohorts. Do not replicate every experiment, KV page or participant presence to every BTX node. Control shards should reference content-addressed artifacts rather than embedding tensors. Scale claims require measured workload curves, adversarial churn and loss tests; the current single-host tests do not establish global throughput.

A missing engine is advertised as `ENGINE_ABSENT` and moves no bytes. A transport pin does not authorize a role, a resource policy, a data grant, an evaluation, or a payment. A self-declared location does not replace the realm policy label. Scale claims in this tree are single-host unit tests. They are not a measured global throughput.
