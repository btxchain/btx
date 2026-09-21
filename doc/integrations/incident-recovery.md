# BCP/1 incident / recovery runbook

Operational runbook for **BTX Custody Profile 1 (BCP/1)** watch-only coordinators. Confirmation and reorg *semantics* are in [bcp1.md](bcp1.md). This page is what to **do**.

Hard rules (every incident):

- **Restart-only recovery is a failure.** A bounce that “looks fine afterward” does not prove the ledger un-credited, the deposit pool is intact, or the signer is healthy. Reconcile from disk + RPC + ZMQ while the node stays up, then confirm the same after any crash restart.
- **Never** point this runbook, certification, or a test harness at a production datadir (including `/var/lib/btxd`). Isolated regtest only.
- **Never SIGKILL** production `btxd`. Do not `kill -9`. Graceful stop only when the operator has already chosen to stop that process; BCP/1 recovery must not require a production stop.
- **Never** treat any confirmation depth as irreversible. BCP/1 never claims finality.
- `automatic_spend_atoms` is unused. Do not invent automatic wallet spends as a recovery action.

Related: [exchange-custody.md](exchange-custody.md) · [bcp1.md](bcp1.md) · [external-sign.md](external-sign.md) · [key-link.md](key-link.md) · [../zmq.md](../zmq.md)

---

## `getdepositstatus` states

Poll `getdepositstatus(txid, vout)` on every relevant ZMQ event and on a timer. Deposit keys are **`txid` + `vout`** (not `wtxid`).

| Status | Meaning | Credit action |
|---|---|---|
| `MEMPOOL` | In mempool, 0 confirmations | Do not credit. Track. |
| `CONFIRMED` | In a **connected** block; `confirmations >= 1` (depth 1 = included in a block on the active chain tip) | Credit only when depth ≥ the venue's own policy. |
| `REORGED` | Previously confirmed; confirming block(s) disconnected (typically back in the mempool) | **Un-credit immediately.** Hold until `CONFIRMED` again at policy depth. |
| `CONFLICTED` | Another tx spending the same prevout is in the active chain or mempool | **Un-credit.** Treat as lost unless the original txid re-enters the active chain. |
| `SPENT` | This output has been spent | Stop treating as a receivable. Internal ledger follows the spend. |
| `UNKNOWN` | Not in wallet / not indexed | Do not credit. Check `txindex`, wallet load, and deposit-pool import. |

Also returned: `confirmations`, `block_hash`, `block_height`. Coinbase maturity (`COINBASE_MATURITY = 100`) is separate from confirmation count.

`deposit.finalized` is a **policy alias** only (depth ≥ the venue's configured threshold). It is not chain finality.

---

## ZMQ `sequence` `C` / `D`

Subscribe to `-zmqpubsequence`. Hashes on ZMQ are **little-endian**; RPC hashes are display (byte-reversed) hex.

| Body | Meaning | BCP/1 name |
|---|---|---|
| `<32-byte hash>C` | Block **connected** to the active chain | `block.connected` |
| `<32-byte hash>D` | Block **disconnected** from the active chain | `block.disconnected` |
| `<32-byte hash>A` + mempool seq | Tx added to mempool | `transaction.mempool` |
| `<32-byte hash>R` + mempool seq | Tx removed from mempool for a non-block reason | — |

`hashblock` / `rawblock` fire on **tip** update only. A reorg may emit only the new tip there; walk from the last known block. **`sequence` is the complete connect/disconnect feed** — use it for credit/un-credit.

After `invalidateblock`, `hashblock` / `rawblock` may emit **nothing** if the new tip was already in the active chain. `sequence` still publishes the disconnects/connects. See [../zmq.md](../zmq.md).

On `D`: for every deposit whose `block_hash` is that block (or a descendant that also disconnected), `getdepositstatus` must become `REORGED` or `CONFLICTED`. Un-credit **without restarting** `btxd`. Pair with wallet reorg hold: `-walletreorgsafetydepth`, `-walletreorgholdblocks`, `-walletreorgholdseconds` so `settlement_safe=false` until the hold clears. That is service policy, not consensus.

---

## Reorg un-credit (no restart)

1. Receive `sequence` `D` (and/or wallet notify). Do not wait for a process bounce.
2. `getdepositstatus` for affected `txid`/`vout`. Expect `REORGED` or `CONFLICTED`.
3. Un-credit the internal ledger for anything that was credited off the disconnected block.
4. Leave the node running. Wallet reorg hold should already zero settlement-safe balances.
5. On later `C`, re-read status. Credit again only if `CONFIRMED` and depth ≥ policy.
6. If ZMQ was down, **poll** `getdepositstatus` / `getblockchaininfo` and walk blocks from the last persisted hash — still without restarting. A restart that happens to resync is **not** the success criterion.

Certification: disconnect → `REORGED` → un-credit with the process still up is PASS. Restart-only is FAIL.

---

## Node crash

A crash is a different incident from a reorg. After a **graceful or crash** start of the **same isolated** node:

1. Wait until not IBD (`getexchangereadiness` / `getblockchaininfo`).
2. Confirm the watch-only wallet is loaded (`listwallets`). If not, `loadwallet` — see below.
3. Re-subscribe to ZMQ. Catch up: last persisted block hash → current tip (RPC), not “assume the gap was empty.”
4. Re-scan deposit keys: `getdepositstatus` for every in-flight `txid`/`vout` and `listdepositutxos`.
5. Re-check signer `Health()` before any withdrawal.

Status and UTXOs must survive on disk (`txindex` as required for `getrawtransaction` after restart). Surviving a crash is necessary; it does **not** excuse restart-only reorg handling.

Do not recover by pointing a new process at `/var/lib/btxd` or any other production datadir.

---

## Wallet reload

`unloadwallet` / `loadwallet` (or a node start with `load_on_startup`) must restore a **watch-only** descriptor wallet: `disable_private_keys`, descriptors, `-exchange-watchonly` still refusing in-process private signing.

After reload:

1. `getexchangereadiness` — not ready if private keys are enabled under `-exchange-watchonly`, or if there is no deposit material.
2. Confirm deposit addresses still resolve (`deriveexchangeaddress` / pool entries).
3. `listdepositutxos` and a sample of `getdepositstatus` match the pre-unload ledger.
4. Do **not** recreate the wallet with private keys as a “fix.”

If the wallet file is gone, that is restore-from-backup: descriptors + `importdepositpool` (and/or signer `getp2mrpubkeys`), then rescan. It is not a reason to import a seed into the coordinator.

---

## Deposit pool re-import

ML-DSA-44 cannot do public-child derivation (`DerivePublicKey` → `PUBLIC_CHILD_UNSUPPORTED`). Watch-only addresses come from the pool or signer-exported pubkeys. If the pool is missing or truncated after a restore:

1. `importdepositpool` with the **same** pre-generated P2MR addresses / pubkeys (same `m/87h/…` indices the signer will use on `SignDigest`).
2. Rescan as required so historical deposits reappear.
3. `deriveexchangeaddress(index)` must return the same address as before for each index. Never mint from a fake xpub.

A pool re-import that changes an index's address is an incident: freeze new deposits at that index until signer and coordinator agree.

---

## Signer health failure

`SignerProvider.Health()` / `getexchangereadiness` signer field.

| Symptom | Action |
|---|---|
| Unreachable, timeout, or adapter fail-closed (`PKCS11_UNAVAILABLE`, `KMIP_UNAVAILABLE`, `HTTPS_UNAVAILABLE`, …) | Stop constructing withdrawals that need `SignDigest`. Do not fall back to in-process keys. Do not enable `-bcp1software` off regtest. |
| `pq_algorithms` lacks ML-DSA-44 | Not ready for a normal P2MR withdrawal. ECDSA/EdDSA-only is insufficient. |
| `PUBLIC_CHILD_UNSUPPORTED` on `DerivePublicKey` | **Expected.** Not a health failure. Use `GetPublicKey` or the deposit pool. |
| Health recovers | Re-run `getexchangereadiness`. Drain the unsigned queue with `prepareexternalsign` → `SignDigest` → `finalizeexternalsign` → `testmempoolaccept` → `sendrawtransaction`. Do not skip accept. |

A signer outage is not cured by restarting `btxd`. Leave the coordinator up; it should keep observing deposits watch-only.

---

## `invalidateblock` / `reconsiderblock`

These RPCs rewrite **local** chainstate. They are not a deposit credit tool and not a substitute for `sequence` + `getdepositstatus`.

| RPC | Effect | Runbook |
|---|---|---|
| `invalidateblock` | Marks a block invalid locally; disconnects it and descendants | Expect `sequence` `D`. Un-credit as a reorg. **Do not** assume `hashblock` fired. Do not use this to “undo a credit” in production policy — un-credit from status, not by invalidating blocks. |
| `reconsiderblock` | Clears a local invalidation so the block may be selected again | Expect `sequence` `C` if it reconnects. Re-read `getdepositstatus`. Credit only at policy depth. |

Do **not** `invalidateblock` as a workaround for a listing incident, a parked fork, or a production stall. Wrong targets can strand the local node. If a block was invalidated in error, `reconsiderblock` that hash; do not stack further invalidates.

BCP/1 does not publish a maximum historical reorg depth. Implement policy with `getdepositstatus`, wallet reorg hold, and `sequence` — see [bcp1.md](bcp1.md).

---

## Checklist (every incident)

1. Node still running? If yes, recover **in place**. If it crashed, start the **same isolated** datadir only — never `/var/lib/btxd`, never SIGKILL a production process to “free” the machine.
2. ZMQ `sequence` subscribed? If not, poll RPC until it is.
3. For each in-flight deposit: `getdepositstatus` → ledger action from the table above.
4. Signer `Health()` before any `SignDigest`.
5. `getexchangereadiness` before declaring the incident closed.
6. Restart-only is FAIL even if balances happen to match after the bounce.
