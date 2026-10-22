# How the nodes you run share lab research

This is the lab contract on the 0.35 branch. It is not a release qualification. Windows and macOS are not covered by this note.

You run several nodes. On each node you obtain work from the contributions already stored, train on that node, and pass the public result to a peer you also run. The calls below are local RPC on the node you are talking to:

```text
btx-cli lab035 <method> '<json>'
```

Ids in the examples are 96 lowercase hex characters. Replace them with the ids that node returned. Text in angle brackets is a slot: replace the slot, brackets included, before you run the call. `idempotency_key` is a string of at least 16 characters, unique per call. Every lab result includes `automatic_spend_atoms` as the string `"0"`. There is no wallet spend in this flow.

## Create the research key

`lab.identity_create` keeps the research key on the node. It does not spend. The result returns `record_id` for that principal and `state` `ACTIVE`. It does not return the key, and the key is not part of a later export.

```bash
btx-cli lab035 lab.identity_create '{
  "label": "lab-node-a",
  "recovery_key_ids": [],
  "recovery_threshold": 1,
  "recovery_delay_ms": "0",
  "idempotency_key": "identity-create-node-a",
  "expected_state": null
}'
```

Repeat this on each node you run. Each node keeps its own key.

## Store a contribution

`lab.identity_sign` then `lab.record_import` stores a `ResearchContribution`. The payload has `kind`, `physical_parent_ids`, and `informed_by`.

`kind` may be `NEGATIVE_RESULT`. `physical_parent_ids` are the contributions this one started from. `informed_by` names other contributions it used, including a negative result on another branch. Putting an id in `informed_by` does not merge that branch and does not make the cited work a parent.

The payload also carries the other `ResearchContribution` fields the signer requires: `objective_id`, `source_snapshot_id`, `capsule_id`, `claim_refs`, `evidence_refs`, and `summary`. `realm_id` is 96 lowercase hex.

```bash
btx-cli lab035 lab.identity_sign '{
  "record_type": "ResearchContribution",
  "realm_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "delegation_id": null,
  "expires_ms": "86400000",
  "idempotency_key": "sign-contribution-branch-a",
  "expected_state": null,
  "payload": {
    "objective_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "kind": "NEGATIVE_RESULT",
    "source_snapshot_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "physical_parent_ids": [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ],
    "informed_by": [
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ],
    "capsule_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "claim_refs": [],
    "evidence_refs": [],
    "summary": "this branch stopped on the check that failed"
  }
}'
```

In that payload the contribution itself is the negative result. It started from `aaa…a`. It cited `bbb…b` through `informed_by`. `bbb…b` stays on its own branch. It is not a parent of this contribution.

`lab.record_import` stores that signed envelope. Pass the `envelope` object from the sign result unchanged (`record_id`, `body`, and `signature_hex`). `publish` here is false. The following section is what makes the contribution visible.

```bash
btx-cli lab035 lab.record_import '{
  "envelope": <envelope object from lab.identity_sign>,
  "publish": false,
  "idempotency_key": "import-contribution-branch-a",
  "expected_state": null
}'
```

## Publish, including a second branch

`lab.research_publish` makes the contribution visible. Pass the envelope `record_id` and the topic ids you want peers to find it under.

```bash
btx-cli lab035 lab.research_publish '{
  "record_id": "<envelope record_id>",
  "topic_ids": [
    "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
  ],
  "visibility": "PUBLIC",
  "idempotency_key": "publish-contribution-branch-a",
  "expected_state": null
}'
```

A second publish of a different branch does not overwrite the first branch's parents. Sign and import that second `ResearchContribution` with its own `physical_parent_ids`, then call `lab.research_publish` on its `record_id`. The first contribution still starts from the parents you stored on it.

A row you publish with `visibility` `PRIVATE` stays on this node. That private row is not in the export in the snapshot section below.

## Read what this contribution retains

`lab.research_context` on a contribution id returns the retained ids reachable through both lists. `DERIVED_FROM` follows `physical_parent_ids`. `INFORMED_BY` follows `informed_by`. Put that contribution id in `root_ids`.

```bash
btx-cli lab035 lab.research_context '{
  "root_ids": [
    "<contribution record_id>"
  ],
  "relations": ["DERIVED_FROM", "INFORMED_BY"],
  "max_depth": 8,
  "max_records": 64
}'
```

`coverage.selection_is_proof` is false. A count of nominations or announcements is not evidence the work is correct. You still read the stored contributions and decide what this node will sign next.

## Say what this node is doing

An `ActivityAnnouncement` is signed and imported the same way, then published. `lab.identity_sign` uses `record_type` `ActivityAnnouncement`. `lab.record_import` stores that envelope. `lab.research_publish` makes it visible.

```bash
btx-cli lab035 lab.identity_sign '{
  "record_type": "ActivityAnnouncement",
  "realm_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "delegation_id": null,
  "expires_ms": "86400000",
  "idempotency_key": "sign-activity-node-a",
  "expected_state": null,
  "payload": {
    "objective_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "base_contribution_ids": [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ],
    "intent": "training the next contribution on this node",
    "expires_ms": "86400000",
    "collaboration": "OPEN",
    "contact_binding_id": "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
  }
}'
```

It tells peers what this node is doing. It does not assign anyone else's next action. It does not appear in the context closure. `lab.research_context` on a contribution id does not return the announcement.

## Pass the public lab to another node

`lab.snapshot_export`, then on another node `lab.snapshot_pull` from `127.0.0.1` with the one-use fetch ticket. Pass `fetch_ticket` on the export. The ticket works once. On the other node, `host` is `127.0.0.1`.

```bash
btx-cli lab035 lab.snapshot_export '{
  "repository_id": "<repository id held on this node>",
  "fetch_ticket": "<one-use fetch ticket>",
  "idempotency_key": "snapshot-export-node-a",
  "expected_state": null
}'
```

```bash
btx-cli lab035 lab.snapshot_pull '{
  "host": "127.0.0.1",
  "port": <rpc port>,
  "rpc_user": "<rpc user of the exporting node>",
  "rpc_password": "<rpc password of the exporting node>",
  "repository_id": "<same repository id>",
  "idempotency_key": "snapshot-pull-node-b",
  "expected_state": null
}'
```

The pulled lab can see the same public contributions and the lineage objects. A private row is not in the export. The research key stays on the node that created it.

## Train on this node

`lab.research_execute` with recipe `INTEGER_LINEAR` trains on this node only. Set `recipe_id` to `INTEGER_LINEAR`. `local_capability_grant_id` is a grant this node already holds. The call does not enqueue work on a peer. When the grant is present, the result `state` is `COMPLETE` and `operation_id` is the trajectory id.

```bash
btx-cli lab035 lab.research_execute '{
  "input_capsule_id": "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
  "recipe_id": "INTEGER_LINEAR",
  "runtime_binding_id": "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333",
  "research_grant_id": "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
  "local_capability_grant_id": "<grant id held on this node>",
  "idempotency_key": "execute-integer-linear-node-a",
  "expected_state": null
}'
```

Set `BTX035_LAB_DIR` to a directory you choose before you start the node, and use the same value after a restart. `lab.audit_coverage` reads the trajectory after that restart. Pass the execute `operation_id` as `trajectory_id`.

```bash
btx-cli lab035 lab.audit_coverage '{
  "trajectory_id": "<operation_id from lab.research_execute>",
  "policy_id": "555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"
}'
```

The audit result is still a lab result: `automatic_spend_atoms` is `"0"`.

## Record a reproduction

A later `ResearchContribution` of kind `REPRODUCTION` can list the earlier contribution in `informed_by`. Sign and import it the same way, then publish it. The earlier contribution is cited. The citation does not move it into `physical_parent_ids` unless you also place that id there.

```bash
btx-cli lab035 lab.identity_sign '{
  "record_type": "ResearchContribution",
  "realm_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "delegation_id": null,
  "expires_ms": "86400000",
  "idempotency_key": "sign-reproduction-node-b",
  "expected_state": null,
  "payload": {
    "objective_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "kind": "REPRODUCTION",
    "source_snapshot_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "physical_parent_ids": [],
    "informed_by": [
      "<earlier contribution record_id>"
    ],
    "capsule_id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "claim_refs": [],
    "evidence_refs": [],
    "summary": "reran the earlier contribution on this node"
  }
}'
```

## Move an integer model to a peer

`INTEGER_MODEL` is the same frozen integer fixture as `INTEGER_LINEAR`: eight pairs, each input mapped to its double. It is not a language-model file, a tokenizer, or a dependency lock. `lab.research_execute` with `recipe_id` `INTEGER_MODEL` writes the final trainer line as bytes, splits those bytes into 32-byte pieces, and returns `artifact_digest`. A later `lab.artifact_acquire` for that digest serves the bytes only when the digest still matches the stored bytes and the pieces join back to those same bytes. A mismatch fails with `BTX035_ID_MISMATCH`.

`BTX035-LAUNCH-DECODER-2x64` is the frozen CPU launch profile: vocabulary 256, context 64, width 64, four heads, feed-forward 128, no dropout, 1,024 steps, SGD without momentum. The byte tokenizer and the authored corpus are separate blob ids. `next_byte_hits` and `miss_mass` are measurements; admission does not read them. A second execute whose `input_capsule_id` is an existing launch trajectory continues for 64 steps and names that trajectory as `previous_state`. A stored cursor or optimizer that does not replay is `BTX035_RNG` or `BTX035_ID_MISMATCH`. This lane is CPU serial. It does not claim a GPU backend.

A workspace event that carries a `hook` is `BTX035_SCOPE_DENIED` and is not journaled. A contribution whose summary asks for a wallet spend is `BTX035_PERMIT` and is not published. After `lab.identity_revoke`, that identity cannot sign. A migration whose backup sequence is below the current channel is `BTX035_ROLLBACK` and leaves the channel where it was. Two promotion attestations are different records, and an attestation for another realm is `BTX035_REALM`. Repeating one attestation id does not raise the threshold. A rollout with two rings stays `CANARY` until a `GovernanceApproval` names that plan and says `APPROVE`. A joined piece set that does not hash to the requested model is `BTX035_ID_MISMATCH` and is not stored. A bundle import whose `minimum_policy_epoch` is above the realm generation is `BTX035_POLICY`. Peer `research/query` takes the lab query fields and answers only `LOCAL`. A live git ticket returns an `OPEN` frame and an `END` frame and does not speak a pack. A piece answer is `OPEN`, then `DATA`, then `END`. `artifacts/manifest` refuses a record that is not a manifest. `trust/state` reports `public_connectivity` `DISABLED`.

`lab.snapshot_export` carries the model object, each piece, each train line, and a replay line `v1|<trajectory_id>|<author>`. The same pieces are written under the lab directory's `pieces` tree. A later process drops the model if those files do not join back to the stored bytes. `lab.snapshot_pull` on `127.0.0.1` checks those objects before it keeps them. After the author process exits, a node that still has the snapshot can serve it. A third node pulls from that retained node, not from the author.

A published channel sequence, the realm threshold, a revocation, and the rollout state are reloaded with the lab directory. Publishing the same sequence again is rejected. `lab.promotion_verify` accepts an attestation only when that stored record names the same promotion. A record that does not is `FAILED`, and the threshold stays where it was. `lab.rollout_rollback` publishes the higher channel sequence, so the same update cannot roll the channel back a second time. A channel update whose `valid_until_ms` is not still in the future is `BTX035_EXPIRED` and does not become current or mark an endpoint active. A piece larger than the caller's byte cap is refused. A loopback peer also answers `/btx-model/3/artifacts/piece`. Any other source address is `BTX035_SCOPE_DENIED`. Every `/btx-model/3/` route takes the node's RPC credential, as the `lab035` RPC does: a request without it is HTTP 401, and an `-rpcwhitelist` user needs `lab035` in its list. `lab.artifact_acquire` reads those pieces in order and joins them before it falls back to a snapshot. Two healthy rings stage that rollout as the active generation. A later process reloads the generation pointer, the training operation, a journal checkpoint, and the workspace journal. Private notes stay in the process that wrote them. `lab.git_attest` accepts a build closure only when those bytes or that record are retained. `lab.capsule_resolve` reports the retained byte count.

`lab.research_query` with `scope` `PEERS` reads this node's public records and, when `BTX035_LAB_PEER` is `127.0.0.1:<port>` or `BTX035_LAB_PEERS` is a comma-separated list of the same form, with `BTX035_LAB_PEER_USER` and `BTX035_LAB_PEER_PASSWORD` set in the node process, one loopback call to each peer's `LOCAL` query. A transport failure tries the next peer. Any other host is `BTX035_SCOPE_DENIED`. With both variables unset, `coverage.complete` stays false, `queried_peers` is `"0"`, and `omissions` includes `BTX035_SCOPE_DENIED`. Private observation ids are omitted. There is no DNS seed and no address gossip in this path. `lab.git_publish_ref` refuses an `old_target` that is not the stored commit (`BTX035_STALE`) and reloads that commit with the lab directory.

`contrib/modelnet/lab035_chapter26.py` is the sovereign laboratory journey: two Git origins, two agent identities, and a retained replica. The publisher trains `BTX035-LAUNCH-DECODER-2x64`, and admission stays failed until a second identity reproduces that trajectory. A changed cursor is `BTX035_RNG`. A changed optimizer or checkpoint is `BTX035_ID_MISMATCH`. Those quality fields are not admission inputs. After the origin, the publisher, and the bootstrap process stop, a new process reconstructs the snapshot and the negative result from the replica. `contrib/modelnet/lab035_chapter27.py` is the WAN journey: one ingress, one attestor, one private controller, two mirrors, and three endpoints in two rings. The attestor's pin is a signed `ModelTrustAttestation` imported by the controller. A pin for another realm does not verify. Revoking that attestor leaves the threshold in place. Endpoints rehash the admitted model, stay `CANARY` until a `GovernanceApproval` names the plan, and a private record does not appear in the ingress peer query. The same binaries then run a one-attestor personal realm at threshold `1`. Both journeys require `btx-qt` and a `btxd` linked with ZeroMQ.

`lab.admission_evaluate` for a model digest admits only when the bytes rehash and at least two identities each ran the fixture over the same path. One author returns `FAILED`. `lab.model_host` then accepts `model_ref` as an object `{"digest":"<artifact_digest>"}` only after that admission and another rehash.

A signed `RolloutPlan` with two rings starts `STAGED`. A signed `DeploymentReceipt` in state `ACTIVE` counts a ring only when `observed_closure_root` rehashes to the retained bytes. One ring is `CANARY`. Two rings are `ACTIVE`. A receipt in state `UNKNOWN`, and a receipt that is not a signed `DeploymentReceipt`, stays `UNKNOWN` and does not count as healthy. `lab.rollout_rollback` accepts a stored `ChannelUpdate` only when its sequence is higher than the sequence already published on that channel. `lab.promotion_verify` pins the attestation set as the realm threshold. `lab.promotion_attest` with `checks_ref.revoke_attestor` removes that attestor and leaves the threshold unchanged.

## What this note leaves in place

`automatic_spend_atoms` is the string `"0"` on every lab result. There is no wallet spend in this flow.

Quarantine and `RESEARCH_ONLY` still fail closed before a model is served. Windows and macOS are not run by the journey script. This note does not mark the sealed acceptance catalogue.
