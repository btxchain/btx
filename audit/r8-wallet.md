# R8 — Wallet / Mandates (independent review lane)

- **Lane:** R8, SPEC 15.3 (wallet plane, `SubscriptionMandate`, helper spend paths)
- **Tree:** `/home/administrator/btx-0.34.7-private` @ `573b4aa4` (`0.34.8-dev`, `CLIENT_VERSION_IS_RELEASE=false`)
- **Date:** 2026-09-17
- **Primary sources:** `src/modelnet/subscription_mandate.{h,cpp}`, `src/modelnet/helper.cpp` (watch-action drain + dispatch), `src/modelnet/model_watch.cpp`, `src/wallet/model_funding.cpp`, `src/rpc/modelnet.cpp` (`prepare/sign/submitmodelfunding`), `test/functional/wallet_modelnet_funding.py`, `src/test/modelnet_submandate_tests.cpp`
- **Compiled:** no. No CMake, `helper.cpp`, or `hcp_engine.cpp` edits were made.
- **Executed:** one functional test against the already-built `build-gcc13/bin/btxd` (no compile). See §4.

## 0. Verdict

`SubscriptionMandate` **is shipped**: the type, the budget, and four helper RPCs
(`create/get/revoke/reservesubscriptionmandate`) exist and are reachable through
`DispatchHelperRpc`. So the "if NOT shipped, document the alternate workflow"
branch does not apply to the mandate object itself.

What is **not** shipped is the link from a mandate to money. A reservation is a
bookkeeping record with no transaction, no script, and no binding to the HTLC that
`preparemodelfunding` later freezes. The wallet plane never reads a mandate, and
the mandate plane never produces anything a wallet can sign. `automatic_spend_atoms`
is therefore genuinely 0 — not because spending is gated, but because the two halves
are not connected at all. The prepare-only workflow is documented in §5 because that
is the only workflow that actually exists end to end.

Classification: **DESIGN_CHOICE with real defects.** The unsigned/prepare-only posture
is deliberate and holds. Eight of the defects below are not covered by that posture and
are genuine gaps in the caps/binding logic itself.

| Requirement | Status | Where |
|---|---|---|
| Exact publisher binding | **HOLDS** | §2.1 |
| Exact object-kind binding | **DEFECT** — empty kind bypasses | F-R8-01 |
| Exact action binding | **HOLDS** | §2.1 |
| Caps (per-action, total principal, fee, exposure) | **HOLDS in-process**; not durable | F-R8-06, F-R8-07 |
| Expiry | **HOLDS** (inclusive boundary) | §2.2 |
| Revocation | **HOLDS in-process**; not durable | F-R8-06 |
| Refund ownership | **DEFECT** — never enforced | F-R8-02 |
| Wrong network | **DEFECT** — skipped when field absent | F-R8-03 |
| Duplicate submit | **HOLDS** (wallet plane, proven live) | §4 |
| Reorg | **HOLDS** (budget not refunded); no recovery path | F-R8-08 |
| Nested recipient | **MOSTLY HOLDS**; `recipient_id` unchecked | F-R8-02 |
| Concurrent triggers | **HOLDS** | §2.3 |
| Atomic budget | **HOLDS in-process** | §2.3 |
| Helper never holds wallet keys | **HOLDS** | §3 |

## 1. What is actually wired

`DispatchHelperRpc` routes the four subscription methods to a process-global
`SubscriptionStore` singleton:

```4528:4530:src/modelnet/helper.cpp
    if (IsSubscriptionHelperMethod(method)) {
        return DispatchSubscriptionRpc(method, params, result, err_code, err);
    }
```

There is a second, automatic entry point. When `getmodelwatchactions` drains a queued
watch action whose policy is `FUND_WITH_MANDATE`, the helper calls
`reservesubscriptionmandate` itself, without an operator RPC. That sounds alarming and
is worth stating plainly: **it cannot currently succeed.** `QueuedWatchAction` has no
terms field and `ActionToJson` never emits `signed_terms`, so the drain always builds
`SignedTerms{known=false}`, and `Evaluate` rejects every such action with
`"unknown terms"` before any budget is touched. The automatic path is fail-closed today
by absence of data, not by an explicit guard. If anyone later adds terms to
`QueuedWatchAction`, remote-triggered events will begin consuming mandate budget with no
operator in the loop — see F-R8-05.

The wallet plane is entirely separate: `preparemodelfunding` → `signmodelfunding` →
`submitmodelfunding` in `src/rpc/modelnet.cpp`, backed by `src/wallet/model_funding.cpp`.
Neither the RPCs nor `FrozenFundingQuote` mention a mandate. `MergeHelperCampaign` is a
deliberate no-op (`GAP-12: helper cannot supply amount, refund key, claimant, or locktime`),
which is the right call for helper-supplied money terms but leaves nothing on the wallet
side that could consult a mandate.

## 2. What holds

### 2.1 Publisher and action binding

Publisher binding is checked before terms are examined, so unknown/absent terms cannot be
used to sidestep it, and it is re-checked against `terms.publisher_id` on the spend path.
Wildcards are rejected at parse time by `IsWildcardToken`, which covers `*`, `all`, `any`,
`unlimited`, the `all_publishers`/`all_recipients` spellings, and any embedded `*`.
`MandateFromJson` also rejects the boolean forms `all_publishers`, `all_recipients`,
`unlimited`, and `no_expiry` before parsing anything else. Unknown JSON keys are ignored
rather than merged, so untrusted model-card text cannot widen a mandate
(`mandate_sub_11` covers this).

Action binding requires both a parseable `WatchAction` and membership in
`allowed_actions`, and `EvaluateAndReserve` additionally hard-requires the literal string
`"FUND_WITH_MANDATE"` — a mandate that only allows `NOTIFY` cannot reserve.

### 2.2 Expiry

`expires_at_ms` is mandatory, must be positive, and is re-checked under the budget lock
after the snapshot evaluation, so an expiry that lands mid-call is caught. The comparison
is `now_ms > expires_at_ms`, i.e. expiry is inclusive of the final millisecond. That is a
defensible choice, not a defect, but it is undocumented.

### 2.3 Atomicity and concurrency

`EvaluateAndReserve` takes `m_mu` once and performs the duplicate check, all four cap
checks, and the mutation of `m_used_principal`/`m_used_fees`/`m_action_count`/`m_concurrent`
inside that single critical section. There is no check-then-act window. `ExposureWithinCeiling`
rejects negatives and guards the addition against `MAX_MONEY_ATOMS` overflow before comparing.

The pre-lock `Evaluate` call operates on a snapshot taken under the lock, which is safe
because every mandate field except `revoked`/`revocation_counter` is immutable after `Bind`,
and both mutable fields are re-checked under the lock afterwards.

`mandate_sub_03` exercises 8 concurrent distinct events. The stronger case — N threads
racing on the *same* `event_id* — is not covered; see §6 for the test I wrote for it.

## 3. Helper never holds wallet keys — holds

This is the strongest part of the lane. `subscription_mandate.cpp` includes no key, signing,
or wallet header; the only crypto it touches is `GetStrongRandBytes` for reservation ids.
`Reservation::wallet_signed` and `contains_wallet_material` are hardcoded `false` at
construction, on the idempotent-replay return path, and again in `ReservationToJson`.
`MandateToJson`, `ReservationToJson`, `StatusJson`, and `PrepareFundingPlan` all stamp
`private_keys=false`, `wallet_signed=false`, and `automatic_spend_atoms=0`.

`SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS` is `constexpr int64_t 0` and is the only value ever
emitted. HCP is consistent: `hcp_engine.cpp` rejects any config with a non-zero
`automatic_spend_atoms` at two separate points (config validation and the profile path) and
stamps 0 on every response. The `btx-model` CLI refuses `fund`/`fund-with-mandate` for
`follow`, accepting only `notify`, `free-download`, and `prepare-funding`. The HTTP browser
bridge returns 403 for all four subscription methods.

## 4. F2 wallet sign — **RUN** for model funding, **HONEST_NOT_RUN** for mandate-driven signing

This needs to be split in two, because the existing `unique_todo_f2_wallet_sign` label
conflates them.

**A live wallet sign path exists and I executed it.** `signmodelfunding` calls
`wallet::SignFrozenFunding`, which calls `EnsureWalletIsUnlocked`, `chain().findCoins`, and
`wallet.SignTransaction(mtx, coins, SIGHASH_DEFAULT, input_errors)`. That is a real wallet
signature over real wallet UTXOs, not a stub.

Evidence (single functional test, prebuilt binary, no compile):

```
cd build-gcc13 && python3 test/functional/wallet_modelnet_funding.py --descriptors --tmpdir=<dir>
```

The node debug log shows the complete sequence executed in order:
`preparemodelfunding` → `signmodelfunding` → `submitmodelfunding` → `getrawmempool` →
`generatetoaddress` (tip height 102) → `getblock` → `preparemodelfunding` →
`signmodelfunding` → `submitmodelfunding`. Funding transaction
`6751ad9d170dbdf8c843400b91c3453ba0434be456090be43b8b5a87345f2d2e` entered the mempool and
was mined. None of the test's early-return branches logged, which means `complete` was
`true`, the mempool and mined-block assertions passed, and the duplicate resubmit returned
`duplicate=true, submitted=false`. Duplicate-submit protection is therefore proven live at
the wallet plane.

**The run did not exit 0**, and I am not relabelling it a pass. `stop_nodes` failed on an
unexpected stderr line: `btx-modeld: PQ1 bind 0.0.0.0:29447 failed`. A stray `btx-modeld`
from another lane's functional run (pid 1294607, tmpdir
`Documents/btxchain/.tmp-agent/bitcoin_func_test_jvy1mt3r`) holds that port. This is host
contention, not a wallet or mandate defect, and I did not kill another lane's process. The
test body completed before shutdown; re-run it on a host with 29447 free for a clean exit.

**Mandate-driven wallet signing remains HONEST_NOT_RUN — there is nothing to run.** No code
path takes a `Reservation` to a signature. The reservation carries `reservation_id`,
`mandate_id`, `event_id`, `principal_atoms`, `fee_atoms` and nothing else: no `terms_id`, no
`object_id`, no `recipient_id`, no output script, no descriptor, no unsigned hex. Nothing a
wallet could match against a `FrozenFundingQuote`. Conversely `signmodelfunding` validates
only against the frozen quote passed by the caller and never looks up a mandate, so a signed
funding transaction is neither authorized nor limited by any mandate. The helper capability
flag `wallet_sign` is `false` and correctly so.

## 5. Prepare-only workflow (the workflow that actually exists)

Because the mandate and the wallet are unlinked, the honest end-to-end flow is operator-driven
and crosses the gap by hand. Each numbered step is a separate human or agent decision; nothing
chains automatically.

1. **Watch** — `watchmodelpublisher` / `watchmodelcollection` / `watchmodelquery` / `watchmodel`
   with action `NOTIFY` (default), `FREE_DOWNLOAD`, or `PREPARE_FUNDING`. `btx-model follow`
   refuses `fund`.
2. **Observe** — `getmodelwatchactions`. `PREPARE_FUNDING` actions carry an unsigned
   `prepare_funding` plan with `unsigned=true`, `wallet_signed=false`, `wallet=false`,
   `automatic_spend_atoms=0`. `FREE_DOWNLOAD` actions are executed as `getmodel FREE_ONLY`
   in the same drain; funding actions are not.
3. **Optional policy record** — `createsubscriptionmandate` then `reservesubscriptionmandate`
   with an explicit `event_id` and a `signed_terms` object. This records intent and consumes
   local budget. It produces **no transaction** and has **no effect** on step 4. Treat it as a
   local spending journal, not an authorization.
4. **Freeze** — `preparemodelfunding` on a wallet-enabled `btxd`. Builds the
   `mr(htlc_sha256(<key_hash>,<claimant>),refund(<height>,<refund_pubkey>))` descriptor and an
   unsigned transaction via `CreateTransaction(..., sign=false)`. `auto_pay` is refused;
   HASH160 `htlc_tx` is refused; `fee_cap_atoms` is enforced against the wallet's computed fee.
5. **Sign** — `signmodelfunding(hex, frozen)`. `MatchFrozenTemplate` rejects a mutated skeleton
   txid or a changed HTLC output script/amount before the wallet is asked to sign.
6. **Broadcast** — `submitmodelfunding(signed_hex, frozen)`. Re-validates against the frozen
   quote, reports `duplicate` for a known txid or an already-in-UTXO-set result rather than
   double-spending.
7. **Claim / refund** — `buildhtlcclaim` / `buildhtlcrefund` (0.34.6 corpus). Out of R8 scope.

An operator who wants mandate caps to actually bound spending must enforce them **outside**
the software, by refusing to run step 4 unless step 3 succeeded first. The code does not do
this for them, and no error is raised if steps 3 and 4 disagree.

## 6. Findings

Severity is relative to the shipped prepare-only posture: nothing here lets software spend
money on its own, because no software path spends money at all. These are gaps that would
become exploitable the moment steps 3 and 4 above are connected, plus defects that already
misreport safety today.

**F-R8-01 — Empty `object_kind` bypasses object-kind binding entirely. (High)**
`Evaluate` guards both kind checks with a non-empty test:
`if (!event.object_kind.empty() && !HasStr(mandate.allowed_kinds, ...))` and the same for
`terms.object_kind`. An event and terms that both omit the field satisfy a mandate restricted
to `allowed_kinds=["RELEASE"]`. `allowed_kinds` is mandatory and wildcard-rejected at parse
time, so the intent is clearly exact binding; omission defeats it. Fix: require a non-empty
`object_kind` on the `FUND_WITH_MANDATE` path.

**F-R8-02 — Refund ownership and recipient are never enforced. (High)**
`owner_identity` is validated as 96-hex and then never read again — it appears in
`ValidateMandate`, `MandateFromJson`, and `MandateToJson`, and nowhere else. The single
refund check is dead code:

```657:660:src/modelnet/subscription_mandate.cpp
        if (!terms.refund_key.empty() && mandate.refund_key_policy != SUBSCRIPTION_REFUND_POLICY) {
            err = "refund_key_policy";
            return false;
        }
```

`ValidateMandate` already rejects any `refund_key_policy` other than `OWNER_CONTROLLED_ONLY`,
so the second conjunct is always false and the branch can never fire. Nothing compares
`terms.refund_key` to `owner_identity`. Separately, `terms.recipient_id` is parsed into
`SignedTerms` and then never checked by anything — `NestedTrick` only rejects *multiple*
recipients, so a single attacker-controlled `recipient_id` is accepted. A mandate today will
happily authorize terms whose refund key and recipient both belong to the publisher.

**F-R8-03 — Wrong-network check is skipped when the field is absent. (High)**
`if (!terms.network_id_hex.empty() && terms.network_id_hex != mandate.network_id.Hex())`.
Terms that simply omit `network_id` pass. `SubscriptionEvent` has no network field at all, and
nothing anywhere compares `mandate.network_id` to the network the node is actually on — so a
mandate minted for a different chain is accepted and usable. Fix: require `network_id` on the
spend path and compare the mandate's network to the local chain.

**F-R8-04 — `SignedTerms` are never signature-checked; `mandate_id` may be empty. (Medium)**
Nothing in the mandate plane verifies a publisher signature. `TermsFromJson` sets
`known = !terms_id.empty() && !publisher_id.empty()` — presence of two strings is the entire
"signed" test. The type name overstates what is guaranteed and will mislead the next
implementer. Related: `ValidateMandate` never requires a non-empty `mandate_id`, and
`Evaluate` guards the cross-check with `if (!mandate.mandate_id.empty() && ...)`, so a mandate
constructed directly through the library (not via `SubscriptionStore`, which always assigns an
id) accepts an arbitrary `event.mandate_id`. The RPC surface is unaffected; embedders are not.

**F-R8-05 — Budget is consumed by remote-triggered events with no operator in the loop. (Medium)**
The `getmodelwatchactions` drain calls `reservesubscriptionmandate` automatically. It is
fail-closed today only because no terms reach it (§1). There is also no way to release a
reservation: `MarkBroadcast` frees the concurrency slot but never the principal, fee, or action
count, and there is no cancel or expiry for a stale reservation. A publisher who can emit N
matching events can therefore permanently exhaust `total_principal_limit_atoms` and
`max_actions` with reservations that are never broadcast, and the only recovery is to create a
new mandate. Fix: add a cancel/expire path, and gate the automatic drain behind an explicit
operator opt-in before terms are ever plumbed into `QueuedWatchAction`.

**F-R8-06 — Mandates, budgets, and revocations are not persisted. (Medium)**
`SubscriptionStore` is a process-global singleton over two in-memory maps.
`subscription_mandate.cpp` performs no file I/O — compare `ModelWatchStore`, which does call
`PersistWatchesLocked`. Consequences: a helper restart resets `used_principal`, `used_fees`,
and `action_count` to zero, so `total_principal_limit_atoms` is a per-process-lifetime cap
rather than a lifetime cap; and a revocation does not survive restart, after which the same
`mandate_id` can be recreated unrevoked with a full budget. The duplicate-id guard
(`if (m_mandates.count(m.mandate_id)) fail`) is likewise process-local.

**F-R8-07 — `outstanding_exposure_limit_atoms` is a lifetime total, not outstanding exposure. (Low)**
The check is `ExposureWithinCeiling(m_used_principal + m_used_fees, principal + fee, ceiling)`,
and neither `m_used_principal` nor `m_used_fees` ever decreases. So the field behaves as a
third cumulative cap rather than a measure of currently-unsettled exposure. Note the
inconsistency: `m_concurrent` *is* released by `MarkBroadcast`, so concurrency settles while
exposure does not. Either rename the field or track settled versus outstanding separately.

**F-R8-08 — Reorg leaves no recovery path, and the reorg hook is never called. (Low)**
The documented invariant (reserved stays reserved across a reorg) is correct and tested. The
consequence is not addressed: if a reorg drops a funding transaction, the event stays in
`m_by_event` marked `broadcast`, so re-reserving the same `event_id` returns the old
reservation rather than a fresh authorization, and re-funding requires a new `event_id` and a
second charge against the budget. Separately, `NoteChainReorg` and `MarkBroadcast` have **no
production callers** — the only call sites in the tree are `modelnet_submandate_tests.cpp`.
`reorg_count` is therefore always 0 in a running node and `m_concurrent` is never released,
so `max_concurrent_reservations` is in practice a second `max_actions`.

**F-R8-09 — Event-id collision returns a reservation for a different object. (Low)**
`m_by_event` is keyed on the caller-supplied `event_id` alone. Two genuinely different objects
submitted under the same `event_id` with identical `principal_atoms`/`fee_atoms` return the
*first* reservation. Because the reservation records no `object_id` or `terms_id` (§4), nothing
downstream can detect the mismatch. The mismatched amounts case is handled correctly
(`idempotency conflict`). Fix: include `terms_id`/`object_id` in the idempotency key and in
`Reservation`.

**F-R8-10 — Process-tier reservation coverage is a silent no-op. (Low, test-quality)**
`feature_modelnet_0348_ops.py` calls
`self._rpc_or_skip(node.reservesubscriptionmandate, {"mandate_id": ..., "atoms": "1"})`. There
is no `event_id`, so `EventFromJson` rejects it; the helper failure surfaces as
`RPC_MISC_ERROR` with `"model helper unavailable: ..."`, and `_rpc_or_skip` tolerates both the
code and the string and records a skip. The suite therefore never exercises a successful
reservation at the process tier, while reading as if it does. `feature_modelnet_unique_todos.py`
likewise only creates a mandate and asserts `wallet_signed` is not `true`.

## 7. Proposed unit test (written, **not** compiled, **not** registered)

`src/test/modelnet_r8_mandate_tests.cpp` accompanies this report. It is **not** built:
`src/test/CMakeLists.txt` uses an explicit source list (`modelnet_submandate_tests.cpp` at line
576), not a glob, and this lane is forbidden from editing CMake. To build it, the owning lane
adds one line next to `modelnet_submandate_tests.cpp`. **Until then these assertions are
unverified** — I wrote them from source reading and did not execute them. Do not cite them as
evidence.

The cases are chosen not to duplicate `modelnet_submandate_tests.cpp`: they pin F-R8-01
(empty-kind bypass), F-R8-02 (refund key and recipient unbound to owner), F-R8-03 (absent
network accepted), F-R8-04 (empty `mandate_id` accepts any event id), F-R8-06 (restart resets
budget and clears revocation), F-R8-07 (exposure never settles), F-R8-08 (no post-reorg
re-authorization; broadcast is idempotent), F-R8-09 (event-id collision across objects), and
one atomicity case the existing suite lacks: N threads racing on the *same* `event_id`, which
must charge the budget exactly once.

Several of those cases assert the **current, defective** behaviour so the defect is pinned
rather than hidden. They are named `r8_*_documents_gap` and must be inverted when the
corresponding finding is fixed.

## 8. Not run / out of scope

- **HONEST_NOT_RUN — mandate-driven wallet signing.** No code path exists (§4). Not a schedule
  gap; a missing feature.
- **HONEST_NOT_RUN — reorg against a real chain.** `NoteChainReorg` has no production caller,
  so there is nothing to drive from a regtest reorg. Unit-level only.
- **HONEST_NOT_RUN — helper restart budget persistence.** F-R8-06 is established by source
  reading and is asserted in the proposed unit test via `SubscriptionStore::Reset()`; a real
  `btx-modeld` restart cycle was not performed.
- **NOT RUN — clean exit of `wallet_modelnet_funding.py`.** Body completed; shutdown failed on
  a foreign port holder (§4). Needs a host with 29447 free.
- **Not executed:** `test_btx --run_test=modelnet_submandate_tests` (no compile permitted this
  lane). The existing suite was reviewed by reading, not by running.
- **Not touched:** `helper.cpp`, `hcp_engine.cpp`, any `CMakeLists.txt`, the production
  attestor.
