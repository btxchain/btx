# Native HTLC payment integration on PR 245

This patch connects funded swarm objectives to the existing monetary wallet. It
implements an unsigned transaction preparation path, strict wallet validation,
a native chain observer, and bounded recovery of an owner-presigned refund.
It does not establish that every proposed swarm payment mode is implemented or
that a generic revocable routed L2 channel is qualified.

## Current code and evidence

| Screenshot requirement | Implemented path | Verification and remaining condition |
| --- | --- | --- |
| P2P-SCN-M | `preparefundmodelrelease(release_id, options)` now uses the native wallet `preparemodelfunding` path, even when `btx-modeld` is unavailable. | The native funded-objective test passed with a complete signature, broadcast, exact funded output, confirmed claim and confirmed refund. A missing plan fails the test. Rerun for each integration candidate. |
| DS-PAY-002 | `getmodelfundingsettlement` rebuilds the SHA-256 HTLC from the terms and observes funding and spending transactions on the local active chain. `Pay02::ObserveNative` is the corresponding C++ core. | The receipt includes the funding outpoint, branch, destination check, principal, actual settlement fee, confirmation depths and chain tip. It is not a permanent release qualification. |
| DS-PAY-003 | `contrib/swarm/native_payments/watchtower.py` persists an exact owner-presigned refund, rejects stale replacement sequences, waits for block-height maturity, checks consensus acceptance and reconciles crashes/reorgs. | Eight component tests and the native funded-objective restart/expiry/refund path passed during package development. This covers the SHA-256 HTLC refund profile, not every generic L2 exit mechanism. |
| ASR-PAY-004 | Native SHA-256 claim and refund paths have explicit executable acceptance. | All other claimed payment modes must independently pass native acceptance. Do not infer routed-channel safety from these HTLC tests. |
| DS-OPS-006 | Payment receipts can be independently queried by a second organization against the chain. | No independent organization or physical deployment has been supplied by this source patch. |
| DS-REC-006 | Recovery handles unavailable transactions, RPC failures, restart, consensus rejection and reorganization without inventing a settlement. | Cross-host partitions, clock faults, response failure and liquidity loss together still require the deployment runner and actual hosts. |

The old boolean-only record APIs remain record APIs. `Pay02::ProveExit`,
`Federate` and `ExerciseFaults` do not accept asserted flags as proof. `Set02::Note`
is bookkeeping; it is not an authoritative native chain observation. The new
observer never signs, broadcasts, starts a helper, grants a model authority, or
marks a release qualified.

## Wallet preparation and authorization boundary

Use a complete explicit options object for an actionable unsigned funding
transaction:

```json
{
  "key_hash": "<32-byte SHA-256 hex>",
  "claimant": "<claimant PQ public key>",
  "refund_pubkey": "<public key owned by the funding wallet>",
  "refund_height": 1200,
  "amount_atoms": "10000000",
  "fee_cap_atoms": "1000000",
  "auto_pay": false,
  "automatic_spend_atoms": "0"
}
```

The sequence is:

1. `preparefundmodelrelease(release_id, options)` returns `plan_stage=WALLET_PREPARED`
   and `unsigned_hex`. No transaction is signed or submitted.
2. An explicit owner action invokes `signmodelfunding(unsigned_hex, prepared)`.
3. An explicit owner action invokes `submitmodelfunding(signed_hex, prepared)`.
4. `getmodelfundingsettlement(funding_txid, prepared)` reports chain-observed
   funding state, including whether an exact matching output has confirmed.
5. `buildhtlcclaim` or `buildhtlcrefund` creates the selected settlement using the
   existing native SHA-256 HTLC implementation and the authorized wallet.
6. `getmodelfundingsettlement(funding_txid, expectation, settlement_txid)` checks
   the exact settlement. `expectation` extends the frozen quote with
   `destination` and `max_settlement_fee_atoms`.

Omitting `refund_pubkey` at preparation asks the wallet to generate a concrete
refund key that it can sign. Supplying a foreign refund key is rejected.
Campaign metadata does not supply an amount, claimant, refund owner or locktime
authority. A legacy scalar amount or release-id-only call remains a helper
preview; it is labelled `HELPER_PREVIEW` and is not a prepared wallet plan.

All auto-spend aliases are checked independently. `auto_pay=false` cannot mask
`automatic_spend_atoms="1"`. Atom strings must be canonical nonnegative decimal
integers; legacy integral JSON numbers are accepted. Fractions, exponents,
leading zeroes, signs and out-of-range values are rejected. An explicitly zero
fee cap means zero, not an unlimited fee. When a fee cap is omitted, preparation
freezes the wallet-estimated fee as the maximum accepted by later signing and
submission.

The signer and submitter rebuild the script from the actual terms, check wallet
ownership of inputs and the refund key, require wallet-owned change, enforce the
fee ceiling from actual input/output values, and reject expired funding.
`submitmodelfunding` now requires the frozen quote and the funding wallet. General
raw transaction broadcasting remains a separate RPC.

## What a native receipt proves

The current settlement profile has exactly one HTLC input and one named output.
This restriction makes its fee and payout arithmetic unambiguous. Multi-input
or multi-output settlements are rejected by this observer until their accounting
has a separate defined profile.

A receipt can report:

| State | Meaning |
| --- | --- |
| `FUNDING_UNCONFIRMED` | Matching funding bytes exist, but active-chain depth is insufficient. |
| `FUNDED` | The exact principal/script output is confirmed and unspent. |
| `SPENT_UNRESOLVED` | The funding output is spent, but an explicit validated settlement has not been resolved. This is not a payout claim. |
| `SETTLEMENT_UNCONFIRMED` | Matching spending bytes exist, but the spending transaction or funding is not sufficiently confirmed in the active chain. |
| `CLAIMED` | The confirmed spend uses the exact expected claim leaf and pays the named destination within the fee ceiling. |
| `REFUNDED` | The confirmed spend uses the exact refund leaf, non-final sequence and correct CLTV, and pays the named destination within the fee ceiling. |

The chain tip is read before and after observation. A changed tip invalidates the
observation and requires retry. Transactions in orphaned blocks have no positive
confirmation credit. Reobserving a reorg clears a prior settled result and resets
`paid_atoms` to zero. A network peer's `settled=true`, a helper receipt, a submitted
transaction identifier or a mempool result is never accepted as native settlement.

The RPC can locate transactions in the selected wallet, mempool or txindex. When
needed, supply `funding_blockhash` and `settlement_blockhash` in the expectation
object. Those are locations only: the node reads the actual block and verifies
membership in its active chain. The receipt also exposes the locally rebuilt
funding output script and claim/refund leaves. Recovery checks its witness
against this refund leaf before accepting an appointment.

## Owner-presigned refund recovery

`watchtower.py` is an explicit isolated-regtest operator tool, not a default
fourth BTX daemon. It never calls a signing RPC, stores no wallet keys, and rejects
other networks. A registration binds the exact signed bytes, funding outpoint,
contract terms, owner-controlled destination, fee cap and refund height.

The SQLite journal uses a unique outpoint key, `BEGIN IMMEDIATE`, full synchronous
writes and owner-only file permissions. Exact registration is idempotent; a new
fee variant needs a strictly higher sequence and cannot change the owner,
principal, contract or timelock. The journal is checked before use. A crash after
broadcast but before commit is reconciled from the deterministic transaction ID.

`poll` uses the node's block height, not wall-clock time. At expiry it checks the
funding output and chain tip, asks `testmempoolaccept`, then broadcasts only the
already-authorized bytes. Later passes distinguish mempool submission, confirmed
refund, unknown spend and reorganization. An old confirmation is rechecked on
every pass.

```sh
python3 contrib/swarm/native_payments/watchtower.py \
  --rpc http://127.0.0.1:18443/wallet/funder \
  --cookie /absolute/regtest/.cookie \
  --database /absolute/private/refunds.sqlite3 register \
  --funding-txid <txid> --frozen /absolute/prepared.json \
  --destination <owner-address> --signed-refund /absolute/refund.hex \
  --fee-cap-atoms 1000000
```

Run `poll` under the same explicit operator authority to execute eligible
presigned recovery, or `status` to read the journal. The source currently does
not implement remote appointment exchange, generic channel revocation,
penalty claims, autonomous signing or mainnet enablement.

## Native test and integration gate

Run the component suite:

```sh
python3 -m unittest discover -s contrib/swarm/native_payments/tests -v
```

Run the native C++ regressions, including the policy and peer callback cases:

```sh
/absolute/build/bin/test_btx \
  --run_test=peerman_first_body_and_reorg_tests,pay02_tests,modelnet_funding_tests,native_discovery_tests \
  --report_level=short --log_level=test_suite --catch_system_errors=no
```

The package also verifies the full peer-manager selection together with those
payment and discovery suites:

```sh
/absolute/build/bin/test_btx \
  '--run_test=peerman*,pay02_tests,modelnet_funding_tests,native_discovery_tests' \
  --report_level=short --log_level=test_suite --catch_system_errors=no
```

Then run:

```sh
python3 test/functional/feature_swarm_funded_objective.py \
  --configfile=/absolute/build/test/config.ini --descriptors --timeout-factor=1
python3 test/functional/wallet_modelnet_funding.py \
  --configfile=/absolute/build/test/config.ini --descriptors --timeout-factor=1
```

The funded-objective test writes `native-payment-evidence.json` inside its
isolated test directory only after every required native assertion succeeds.
Retain the source commit, binary hashes, command, full output, transaction
receipts and chain identity with that evidence. It records one physical host;
it must never satisfy a two-host or independent-organization gate.

The development run on 22 October 2026 used a rebuilt Linux `btxd` and
`--timeout-factor=1`. The final `feature_swarm_funded_objective.py` run completed in
11.559 seconds, including a real 10,000,000-atom funding output, a 9,000,000-atom
claimant payout with a 1,000,000-atom settlement fee, and a separate refund with
the same principal/proceeds. It also passed claim reorganization/reconsideration,
zero-fee-cap rejection at prepare/sign/submit, expired-quote rejection, early
refund rejection, persistent watch restart, maturity and confirmation checks.
The existing `wallet_modelnet_funding.py` compatibility test passed in
10.106 seconds with the same timeout factor and legacy result types.
These timings describe one local run, not performance guarantees.

The four focused native C++ suites first passed all 40 cases and all 535
assertions. On the final rebuilt test binary, the complete selection above
passed all 175 cases and all 14,746 assertions in 220.121 seconds, with no
command-line activation overrides. Its separate 54-case suffix check passed
all 2,137 assertions. The suffix overlaps the complete selection; these counts
must not be added. The package retains the commands, binary hashes, logs and
earlier failed or bounded attempts. This is a focused local result, not a pass
of every test in the codebase.

The separate `feature_matmul_heard_serve.py` native run passed in 10.758 seconds
with its original MatMul, trust, pacing and 60-second synchronization gates.
Its first-block regression exercises the supplied body before its disk-available
flag is set, and a completed genesis header exchange before a peer has announced
an inventory item. A VERSION message alone is insufficient for that relay path.

The reorganization test exposed an existing `ActiveTipChange` assertion:
`InvalidateBlock` notifies listeners outside `cs_main`, while the peer manager
assumed the lock was held. The callback now takes that recursive lock itself.
`peerman_first_body_and_reorg_tests` includes an actual invalidation notification
regression; the native funded-objective test verifies the end-to-end behavior.

Ten pre-existing peer scheduling tests use long header-only forks. Nine build an
82-block active chain and a 102-header competing fork; the pagination test
generates 2,056 remote headers and checks the 2,000-header page and 2,048-header
permission boundaries. Their dedicated fixture reuses the existing
`TestChain100Setup` activation profile and enables strict MatMul validation.
This keeps real legacy MatMul proof solving and native header validation while
deferring later v4/BMX4C/DRLT/RC activations beyond the maximum fixture height of
2,057. It does not
change fork heights, scheduling assertions, v4-specific tests, production
consensus or the heard-serve functional test. The strict profile control passed
all nine original cases and 4,083 assertions before the fixture was integrated.
The separate pagination control passed its original 2,108 assertions in 73.789
seconds with strict MatMul validation and the same deferred activation profile.

The pending-cap release regression also waits for the validation-interface
queue after its original connected-chain predicate succeeds. Retained-body
cleanup occurs in the queued `BlockConnected` callback; chain membership alone
does not prove that callback has run. The test drains it while holding neither
`cs_main` nor the message-processing mutex, then keeps its original cleanup and
peer-disconnection assertions.

The compact-invalid-body fetch regression now holds the message-processing
mutex before invoking its native peer handshake, matching the production
`SendMessages` caller contract. The production lock assertion and the original
fetch-suppression assertions remain in place. Its former missing-lock failure
is retained as historical evidence; the final complete selection passes it.

## Payment-mode qualification boundary

| Mode or capability | Source in this patch | Current acceptance boundary |
| --- | --- | --- |
| Explicit SHA-256 release/objective funding | Native wallet path | Passed local native functional execution; rerun for the exact integrated candidate. |
| SHA-256 claimant payout | Existing native builder plus new exact chain observer | Passed confirmed destination/amount/fee assertions and reorg revocation. |
| Owner SHA-256 CLTV refund | Existing native builder plus new observer and recovery tool | Passed early-refund rejection, expiry, owner proceeds and restart assertions. |
| Routed HTLC path planning | Existing library code | Planning does not establish enforceable off-chain settlement. |
| Monotonic two-party native channel | Existing records and plans | Persistent native commitment exchange and unilateral safety remain to be implemented/qualified separately. |
| Stale-state punishment/revocation | No new generic remedy | Not implemented by the presigned refund watch. |
| Mainnet autonomous settlement | Disabled | No new wallet authority or automatic spend is granted. |
| Every claimed ASR payment mode | Not inferred | Claim only modes supported by independently retained native evidence. |
