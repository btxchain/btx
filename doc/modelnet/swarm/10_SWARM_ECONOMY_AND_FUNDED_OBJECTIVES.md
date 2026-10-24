# BTX Swarm 0.35 — Swarm economy and funded objectives

Document: **BTX-SWARM-SPEC-10**, revision **0.1.0**, 19 October 2026.

**Implementation scope:** Durable local SEP accounting, bounded mandates, read-only UTXO observations and conservative balances are implemented. No implemented function creates an enforceable L2 payment.

## Economic architecture

**SEP-001.** Each model lineage may have a persistent economic identity, and each work objective has its own pool. These are logical budget/governance domains on one reusable payment network, not a separate blockchain or fresh channel network for every model. Model, compute and payment topologies remain independent.

A pool manifest binds lineage, objective, chain genesis, policy, owner, nonce, work policy and refund terms. Material contractual changes create a new policy epoch or objective; they must not rewrite existing beneficiaries, earned obligations, sponsor refund keys or deadlines. Pools may exist while unfunded. Unfunded existence must not be displayed as economic backing.

## Funding classes and enforceability

**SEP-002.** Distinguish at least: a sponsor's advertised promise; a fresh observation of an unspent UTXO; an escrow with enforceable claimant/refund conditions; spendable collateralized channel capacity; a reserved conditional claim; earned but unsecured work; an enforceable settled channel claim; and confirmed L1 settlement.

The delivered service supports the first two observational/accounting classes plus explicit unsecured obligations. `observed_unspent_atoms` is not proof that the sponsor pledged the UTXO exclusively to this pool. `accounting_available_atoms` is a local budget estimate, not immediately spendable liquidity. `immediately_payable_l2_atoms` and `enforceable_channel_claim_atoms` are always zero in this version.

**SEP-003.** A work lease, ML-DSA voucher, model-evaluation certificate or ledger receipt is never automatically money. The settlement method raises `NATIVE_CHANNEL_BACKEND_UNQUALIFIED`. No command in this service signs or broadcasts a transaction. There is no operator switch that converts the protocol model into a qualified native financial channel.

## Confirmed backing observations

The optional native adapter is read-only. It pins a chain genesis, queries UTXO status and confirmations, checks the exact expected script, and converts exact decimal amounts to atom strings. It does not accept arbitrary wallet or broadcast methods. Network activation height, expected script, output index and transaction identities must be verified against the intended chain before native escrow use.

The local ledger uses unique outpoints across all its pools, preventing one observed output from being allocated twice in that ledger. It does not prevent a malicious sponsor from advertising the same UTXO to another independent ledger. An exclusive pledge or enforceable channel reservation is required before workers can treat it as secured capacity.

Observations expire conservatively. A reorganization, spend, stale observation or conflict freezes new commitments. Pending and earned liabilities remain recorded: invalid backing never erases work already accepted. Refund maturity and fee reserves must be accounted for even when a gross output remains unspent.

## Conservation and authorization

**SEP-004.** For an actually secured channel class, the eventual invariant is:

```text
available + reserved/inflight + irrevocably assigned + required exit reserves
    <= confirmed, uniquely controlled eligible collateral
```

For the current accounting-only class, the ledger enforces the analogous local budget bound without asserting on-chain enforceability. It exposes a deficit when eligible observations disappear. All arithmetic is exact integers, and transaction fee reserves are excluded from allocatable work budget.

**SEP-005.** A mandate binds pool, authorized actor, recipient set, atom ceiling, expiry and nonce. Revocation blocks new reservations but cannot retroactively cancel earned obligations. Repeated work IDs return the original reservation only when worker, amount, mandate and terms match; semantic conflicts fail.

A reservation requires `accept_unsecured_credit=true` and a nonempty immutable terms ID in this build. This is an explicit warning-bearing contract choice, not an “enable payments” feature flag. It must not become the default for public paid work. Ordinary swarm agents do not possess the local payment-administration token.

## Work acceptance

Reservation → RESERVED → EARNED_UNSECURED, or RESERVED → CANCELLED. Earned work cannot be cancelled through the reserve-release API. A receipt is idempotently bound to one accepted work item; a different receipt cannot overwrite the original. Work acceptance currently occurs through a trusted local policy service, not an implemented decentralized payment dispute court.

The target verification layer must bind actual task, lease/attempt, worker, evaluation policy, evidence and amount before authorizing secured payment. Base compensation can reward valid compute, data preparation, reproducibility and negative results; milestone bonuses can reward qualified improvements. Do not use a universal unproven formula claiming perfect scientific credit attribution.

## Opportunity selection

Pool size alone is not an appropriate ranking score. A target opportunity score should incorporate executable compatible work, conditional acceptance probability, reliable paid history, fresh usable liquidity, total resource cost, deadline/interruptibility, exit fees and the best alternative use of the device. Mining opportunity cost must be measured rather than inferred from nominal GPU specifications.

The current scheduler provides cost/placement helpers, not a live mining-profitability oracle or a production economic marketplace. It does not switch mining resources automatically or promise better returns.

## Commercial revenue and model development

Service revenue may be allocated by explicit contracts to operators, evaluation and further research. An unpaid dollar promise is not funded BTX; record actual conversion, fees and counterparty responsibility before claiming collateral. Open weights do not make every independent deployment payable to the network. Passive ownership/profit-share instruments are not part of the default work-payment contract and require separate operational/legal analysis.

## Required release qualification

Before accepting secured work: independently audit collateral control, cross-pool reservations, reorg handling, native unilateral exits, withheld acceptance, reused preimages, stale states, watcher outages and simultaneous exits. Verify that a disappeared coordinator cannot confiscate an already enforceable worker claim. The current randomized conservation and restart tests qualify local accounting only.

## What btxd runs now

The swarm thread inside btxd returns Spend as the string "0". `automatic_spend_atoms` stays 0. Release returns `UNQUALIFIED`. btxd does not start `btx-paynetd`. The reference paynet program, if someone runs it by hand, reports `ACCOUNTING_ONLY`, payment signing false, and automatic spend 0.

No channel is opened by the observer. No mainnet broadcast is made. The research path and the scheduler do not receive a spend key. Wallet work already on this branch includes `getbalancewatch`, `getbalanceatheight`, model and bounty funding updates, and presign of the `htlc_sha256` claim leaf. Helper approval is not a chain spend. Those wallet calls leave `immediately_payable_l2_atoms` and `enforceable_channel_claim_atoms` at zero. A local budget reservation remains an accounting record. SEP-003 still applies: no command in this service signs or broadcasts a transaction.

## Unsigned plans and recorded balances

`btxd` is the control plane. A missing catalog does nothing. Automatic spend atoms stay 0. `preparefundmodelrelease` builds an unsigned plan and does not spend. Recovery of a recorded balance does not stop a device and does not spend.

Advertised capability is separate from qualified capability. A local model can run with an empty provider key. A KV page is copied only when fingerprints match.

Two physical hosts, three peers, a second GPU, Windows, macOS, offline images, and the release gates remain later work.

## Later releases

Toward a fully autonomous network, accepted work can settle in BTX only under a mandate the operator signed. A funded objective can pay a bounded amount through the existing payment facilities. A routed payment still has to pass the hash-locked claim checks, including the 32-byte preimage pin on the claim leaf. Currency remains BTX.

Verifications required before a payment claim: an operator-signed mandate, isolated-regtest settlement, and no change to the rule that an unsigned or absent mandate spends nothing. Two physical hosts, a second GPU, Windows, macOS, a linked remote engine, an offline release image, the hardware profiles, and the sealed acceptance catalogue remain separate qualifications and are not implied by a zero spend result. The release qualification above still binds before secured work is accepted. A Spend value of "0" does not retire that qualification.
