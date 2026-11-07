# BTX Swarm 0.35 — Direct post quantum payment channel contract

Document: **BTX-SWARM-SPEC-11**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** The monotonic voucher, the 2-of-2 funding template, the PSBT refund template, and the worker payout template are constructed in this process. Funding counts only after the refund is bound to the same outpoint. This process does not sign with a spend key and does not broadcast. A broadcast attempt is `BROADCAST_FORBIDDEN`.

## Channel class and threat model

`PQ_MONOTONIC_V1` is the proposed first native channel: one sponsor repeatedly increases one worker's cumulative entitlement against a fixed funding output. It is not bidirectional, not multi-hop, and not a proof of work quality. The rationale is to minimize stale-state machinery before deploying a routed financial network.

**PAY-001.** Funding spends require both sponsor and worker under an audited native P2MR construction. Before funding is broadcast, a fully signed and verified refund transaction must be durably retained by the sponsor. It must spend the exact intended outpoint, satisfy the intended height lock, and return funds to the originally authorized sponsor after its explicit maturity. Descriptors alone are insufficient; the actual scripts, sighashes, witnesses and transaction validity must pass the BTX interpreter.

Use existing native primitives only after source/interpreter verification. `src/wallet/model_payment.h` confirms native SHA-256 HTLC claim/refund facilities; it does not establish a completed channel API. `bcp1.h` is a custody/external-signing profile, not a payment-channel implementation. Do not invent native RPC names or treat BCP/1 as PAY/1.

## Immutable channel terms

Bind chain genesis, protocol version, payer/recipient principals, funding outpoint and script, capacity atoms, beneficiary scripts, refund height, funding confirmation policy, fee/close reserves, accepted sighash modes, unilateral close margin, permitted update direction and dispute terms. Channel identity is domain-separated over these immutable terms plus a nonce.

**PAY-002.** The sponsor cannot extend a refund deadline, substitute a refund beneficiary, change the funding outpoint or reduce an acknowledged recipient allocation by updating a metadata record. Changed material terms require a distinct channel or a jointly secured transition. No decimal floating-point arithmetic is allowed in payment construction or verification.

## Native opening state machine

```text
PROPOSED
  -> TERMS_ACCEPTED
  -> FUNDING_TRANSACTION_FIXED
  -> REFUND_SIGNED_AND_INTERPRETER_VERIFIED
  -> FUNDING_BROADCAST
  -> FUNDING_CONFIRMED
  -> OPEN
  -> DRAINING / COOPERATIVE_CLOSE / UNILATERAL_CLOSE / REFUND
  -> CLOSED_CONFIRMED
```

**PAY-003.** Before REFUND_SIGNED_AND_INTERPRETER_VERIFIED, broadcasting funding is prohibited. The final funding transaction ID must be stable under the approved witness/input profile. Any replacement changing that ID invalidates dependent refund and payout transactions and requires a new complete opening sequence. Unconfirmed funding is not secured worker capacity.

Opening must persist the raw funding transaction, refund package, verified scripts, UTXO inputs, chain binding and both parties' terms acknowledgments atomically before exposure. A crash in each opening transition needs a deterministic recovery path. If funding never confirms, no work should be booked against it.

## Cumulative payout updates

**PAY-004.** Each proposed payout spends the same original funding output and pays the worker cumulative amount `C`, with the remainder after approved fees to the sponsor. The sponsor provides its valid native transaction signature; the worker verifies the complete transaction and retains the greatest valid cumulative payout it can finalize independently.

Required invariants: `0 <= previous_C <= C`, strictly increasing state sequence, `C + close_reserve <= capacity`, exact beneficiary scripts, exact funding input, immutable refund height and no unexpected outputs/sighash modes. Transport signatures bind update metadata but do not replace transaction signatures. A signed JSON object that names `C` is not a native claim.

The worker MUST NOT give the sponsor enough signatures to unilaterally broadcast an old, lower payment while further work continues. A fully signed cooperative close seals the channel against additional work/updates before either party receives the final package. Test this distinction explicitly: possession of a funding public key or a separately signed refund must not enable signing another payout.

**PAY-005.** Acknowledgment follows fsync of the newest valid native claim, not receipt in memory. Replays with identical terms are idempotent; conflicting sequences and decreasing cumulative amounts are rejected. The delivered `MonotonicChannel` checks the metadata/signature/conservation rules but never creates the native transaction or refund.

## Closing, deadlines and fees

The worker can complete the latest valid payout and broadcast it without another sponsor signature. The sponsor's pre-signed refund becomes usable only after the agreed native lock conditions. An already valid claim may compete with a mature refund; the channel must drain and close well before maturity, not assume the claim becomes impossible at expiry.

**PAY-006.** Stop accepting work before the refund height minus a conservatively tested close margin. Block-height validity is authoritative; a ninety-second nominal interval is not a clock guarantee. Choose confirmation, reorg and congestion margins from actual chain tests. The prototype's 160-block margin is a protocol-model default, not a qualified production safety value.

Fee recovery requires actual native support. Fixed-fee pre-signed transactions need tested child-pays-for-parent, fee-reserve outputs or a secured replacement procedure. Do not assume inherited Bitcoin mempool/replacement behavior without testing this BTX branch. An external signer must refuse outputs or fees outside the immutable mandate.

## Work delivery fairness

A sponsor can refuse to issue a higher payout after receiving work unless an independent conditional mechanism already commits it. Use small batches and explicit limited credit exposure, or a separately enforceable escrow/conditional acceptance construction. Quorum acceptance records alone do not force a native spend. Do not display “HTLC secured” where a single claimant already knows a preimage and can take the funds irrespective of work acceptance.

## Mandatory implementation and test packet

Implement native funding/refund builders, full PSBT checks, payer/worker signing services with separate custody, transaction interpreter tests, persistent latest-claim storage, confirmation monitoring, unilateral exit, fee rescue and refund handling. Test malformed scripts, wrong keys, mixed networks, replacement funding IDs, signer refusal, restart before acknowledgment, sponsor disappearance, premature refund, stale payout attempts and mass exits on regtest.

Until these pass and are independently reviewed, the package advertises accounting/model status only. Mainnet exit code is absent, not disabled by a hidden feature switch. This document specifies what must be built; it must not be presented as evidence that it already exists.

## What btxd runs now

The swarm thread inside btxd returns Spend as the string "0". `automatic_spend_atoms` stays 0. Release returns `UNQUALIFIED`. btxd does not start `btx-paynetd`. The reference paynet program, if someone runs it by hand, reports `ACCOUNTING_ONLY`, payment signing false, and automatic spend 0.

No channel is opened by the observer. No mainnet broadcast is made. The research path and the scheduler do not receive a spend key. Wallet work already on this branch includes `getbalancewatch`, `getbalanceatheight`, model and bounty funding updates, and presign of the `htlc_sha256` claim leaf. Helper approval is not a chain spend. Presign of that claim leaf does not advance the opening state machine, does not satisfy `REFUND_SIGNED_AND_INTERPRETER_VERIFIED`, and does not authorize `FUNDING_BROADCAST`. A broadcast attempt remains `BROADCAST_FORBIDDEN`. This process still does not sign with a spend key.

## Later releases

Toward a fully autonomous network, accepted work can settle in BTX only under a mandate the operator signed. A funded objective can pay a bounded amount through the existing payment facilities. A routed payment still has to pass the hash-locked claim checks, including the 32-byte preimage pin on the claim leaf. Currency remains BTX.

Verifications required before a payment claim: an operator-signed mandate, isolated-regtest settlement, and no change to the rule that an unsigned or absent mandate spends nothing. Two physical hosts, a second GPU, Windows, macOS, a linked remote engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue remain separate qualifications and are not implied by a zero spend result. PAY-001 through PAY-006 and the mandatory test packet above remain in force. Mainnet exit code stays absent until that packet passes independent review. A Spend value of "0" is not that review.
