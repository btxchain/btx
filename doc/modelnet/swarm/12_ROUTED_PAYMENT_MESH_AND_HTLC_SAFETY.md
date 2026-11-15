# BTX Swarm 0.35 — Routed payment mesh and HTLC safety

Document: **BTX-SWARM-SPEC-12**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** Routing, fees, expiry slack, hashlock binding, and the watchtower appointment are executable. `secp_penalty` is refused. A stale state is `HASHLOCK_REMEDY` when the prior secret is released and `STALE_STATE_ALERT` otherwise. A native penalty remedy is `NATIVE_REMEDY`. Nothing in this path broadcasts.

## One reusable mesh

**PAY-101.** The eventual BTX-PAY network is reusable across model families and objectives. Channels belong to counterparties and collateral, while pools reserve scoped portions of capacity. Do not open an independent financial chain or duplicate full collateral for every model swarm. Payment routing uses liquidity and reliability, not the inference-cache neighborhood.

**PAY-102.** Routed HTLCs bind chain, invoice, payment hash, recipient, amount, objective/terms, route limits and expiry. Preimages are fresh 32-byte secrets, never reused across unrelated payments. Reservation capacity must include in-flight HTLCs, locked fees and required exit reserves. A verified work record can authorize release only under the explicitly agreed financial mechanism.

## Atomic hop contract

Before forwarding, the incoming conditional obligation must be irrevocably committed in a native channel state. The forwarder reserves outgoing liquidity and creates the outgoing obligation. A valid preimage lets the downstream party complete its claim and lets the upstream forwarder recover its incoming claim. Off-chain acknowledgment and native fallback must have compatible ordering.

**PAY-103.** Incoming expiry is later than outgoing expiry by a tested safety delta. The delta covers reaction, observation, block production variability, reorganization, fee escalation, connectivity loss and native transaction sequencing. Reject routes with insufficient slack, too many hops, excessive aggregate fees or insufficient residual liquidity. Prefer short reliable routes, but do not equate a short route with a proof of safety.

The implementation's reverse bounded search includes per-hop fees rounded upward in atoms, liquidity, maximum hops and expiry bounds. It preserves path state rather than discarding alternatives solely by vertex cost. Its result is `ROUTE_PLAN_ONLY`. No funds are locked by calculating a route.

## Bidirectional stale-state safety

Lightning's familiar elliptic-curve revocation-key derivation cannot be assumed to work by replacing secp256k1 signatures with ML-DSA. A specific native P2MR construction must enforce the replacement or punishment of an old balance commitment without elliptic-curve key tweaks.

Candidate construction for review: explicit per-state revocation hash, counterparty ML-DSA authorization and delayed owner spending. A superseded owner's delayed output can be spent by the counterparty when the corresponding revocation secret is released. This is a construction requirement, not a statement that the required native leaf templates or witness serialization already exist in this branch.

**PAY-104.** The state exchange protocol must ensure neither participant loses a valid unilateral claim while advancing. Persist the newly enforceable state before revealing any secret that invalidates the previous one. Bind revocation secrets to channel/direction/state and avoid reuse. Tests must enumerate each message loss/crash point, crossed updates, conflicting signatures and intentional stale broadcasts.

Replacement-state designs using CTV/CSFS are an alternative research/engineering track. The existence of these opcodes does not imply ANYPREVOUT/eltoo semantics. A chosen design needs a complete transaction graph, native interpreter proof, unilateral exit argument and adversarial tests before becoming a supported profile.

## HTLC lifecycle and financial finality

```text
INVOICE -> ROUTE_RESERVED -> INCOMING_COMMITTED -> FORWARDED
        -> FULFILLED -> CHANNEL_CLAIM_ENFORCEABLE -> optional L1 settlement
        -> FAILED / EXPIRED -> liquidity released only when legally safe
```

`ConditionalModel` tests abstract hashlock, amount, expiry and conservation transitions. It is not a native HTLC output. Its modeled refusal to resolve after expiry does not change the actual native script fact that a valid claim and mature refund can race. Production financial finality depends on the precise transaction construction and chain state, not the Python state label.

**PAY-105.** The sender must not treat an evaluation certificate, preimage observed in an unrelated context, or a forwarding node's promise as completed payment. A recipient must receive an enforceable native channel claim under the agreed protocol. Reorgs and lost watcher connectivity require explicit risk states, not unbounded optimistic credit.

## Watchtowers and mass exits

A watchtower needs authenticated appointment data, minimal confidential state, fresh channel identifiers, reliable chain observation and a native remedy it can actually exercise. The package's watch function reports stale-state alerts and drain warnings with `native_remedy_available=false`. It is not a theft-preventing watchtower.

Mass exits must be modeled with measured native transaction sizes and dependency graphs. Maximum block bytes alone do not establish exit capacity: post-quantum signature costs, script/sigop limits, mempool rules, parent/child dependencies and competing traffic matter. Each fee/resolution transaction contributes to the workload. Choose contest/refund windows large enough for severe congestion, not nominal-block-time averages.

## Cross-pool liquidity and accounting

A single channel's available balance cannot be reserved for two pools. Reservation ownership must be crash-recoverable, idempotent and atomically linked to committed payment states. A reorg cannot turn a now-unfunded channel into spendable capacity while its prior obligations remain outstanding. Liquidity supplied against locked escrow creates separate counterparty obligations; it is not the same money twice.

## Qualification gates

A routed release requires a complete audited native channel class, persistent two-party commitment exchange, safe HTLC add/fulfill/fail ordering, routing reservations, invoices, watchtower appointments, exit fee handling and native regtest/malicious-peer tests. Run failed-hop, expired-hop, route probing, replayed preimage, stale-state, simultaneous close, prolonged partition and reorg scenarios. None of this can be marked PASS because the abstract route/HTLC unit tests pass.

## What btxd runs now

The swarm thread inside btxd returns Spend as the string "0". `automatic_spend_atoms` stays 0. Release returns `UNQUALIFIED`. btxd does not start `btx-paynetd`. The reference paynet program, if someone runs it by hand, reports `ACCOUNTING_ONLY`, payment signing false, and automatic spend 0.

No channel is opened by the observer. No mainnet broadcast is made. The research path and the scheduler do not receive a spend key. Wallet work already on this branch includes `getbalancewatch`, `getbalanceatheight`, model and bounty funding updates, and presign of the `htlc_sha256` claim leaf. Helper approval is not a chain spend. Presign of that claim leaf does not lock liquidity, does not release a preimage, and does not move a route out of `ROUTE_PLAN_ONLY`. Nothing in this path broadcasts. `native_remedy_available` stays false.

## Later releases

Toward a fully autonomous network, accepted work can settle in BTX only under a mandate the operator signed. A funded objective can pay a bounded amount through the existing payment facilities. A routed payment still has to pass the hash-locked claim checks, including the 32-byte preimage pin on the claim leaf. Currency remains BTX.

Verifications required before a payment claim: an operator-signed mandate, isolated-regtest settlement, and no change to the rule that an unsigned or absent mandate spends nothing. Two physical hosts, a second GPU, Windows, macOS, a linked remote engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue remain separate qualifications and are not implied by a zero spend result. The qualification gates above stay closed. A Spend value of "0" does not mark a routed release PASS, and it does not relax the 32-byte preimage pin on the claim leaf.
