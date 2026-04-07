#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal, ROUND_DOWN

from test_framework.authproxy import JSONRPCException


SHIELDED_WALLET_PASSPHRASE = "pass"
SHIELDED_WALLET_UNLOCK_TIMEOUT = 999000


def encrypt_and_unlock_wallet(
    node,
    wallet_name,
    *,
    passphrase=SHIELDED_WALLET_PASSPHRASE,
    timeout=SHIELDED_WALLET_UNLOCK_TIMEOUT,
):
    """Prepare a freshly created functional-test wallet for shielded key use."""
    wallet = node.get_wallet_rpc(wallet_name)
    if not wallet.getwalletinfo()["private_keys_enabled"]:
        raise AssertionError(
            f"{wallet_name} has private keys disabled; use an encrypted blank wallet for shielded viewing keys"
        )
    wallet.encryptwallet(passphrase)
    wallet = node.get_wallet_rpc(wallet_name)
    wallet.walletpassphrase(passphrase, timeout)
    return wallet


def unlock_wallet(
    node,
    wallet_name,
    *,
    passphrase=SHIELDED_WALLET_PASSPHRASE,
    timeout=SHIELDED_WALLET_UNLOCK_TIMEOUT,
):
    wallet = node.get_wallet_rpc(wallet_name)
    wallet.walletpassphrase(passphrase, timeout)
    return wallet


def ensure_ring_diversity(test, node, wallet, mine_addr, zaddr, min_notes=16, topup_amount=Decimal("0.5"), sync_fun=None):
    """Seed shielded notes until the wallet has at least min_notes spendable notes.

    This avoids small-tree ring-signature creation failures when tests attempt
    shielded spends before enough commitments exist.
    """
    if sync_fun is None:
        sync_fun = test.no_op

    note_count = int(wallet.z_getbalance()["note_count"])
    notes_needed = max(0, min_notes - note_count)
    if notes_needed == 0:
        return

    added = 0
    for _ in range(notes_needed):
        try:
            tx = wallet.z_shieldfunds(topup_amount, zaddr)
        except JSONRPCException as e:
            if (
                e.error.get("code") == -4
                and "post-fork direct transparent shielding is disabled; use bridge ingress"
                in e.error.get("message", "")
            ):
                tx = wallet.z_sendmany([{"address": zaddr, "amount": topup_amount}])
            else:
                if e.error.get("code") == -6:
                    break
                raise
        txid = tx["txid"] if isinstance(tx, dict) else tx
        if txid not in node.getrawmempool():
            # Tests with -walletbroadcast=0 keep wallet-originated txs local
            # until explicitly broadcast. Broadcast here so mined topups are
            # available to satisfy the note-count target.
            tx_hex = wallet.gettransaction(txid)["hex"]
            try:
                node.sendrawtransaction(tx_hex)
            except JSONRPCException as e:
                if e.error.get("code") != -27:
                    raise
        assert txid in node.getrawmempool()
        added += 1

    if added:
        test.generatetoaddress(node, 1, mine_addr, sync_fun=sync_fun)

    final_notes = int(wallet.z_getbalance()["note_count"])
    if final_notes < min_notes:
        raise AssertionError(f"insufficient shielded note diversity: have {final_notes}, need {min_notes}")


def fund_trusted_transparent_balance(
    test,
    node,
    wallet,
    mine_addr,
    amount,
    *,
    maturity_blocks=130,
    fee=Decimal("0.00010000"),
    sync_fun=None,
):
    """Create trusted wallet funds by spending matured coinbase outputs directly.

    Wallet trusted-balance accounting can lag generated coinbase outputs on BTX.
    This helper mines maturity blocks, then builds a direct raw transaction from
    matured coinbase outputs back into the same wallet, producing standard trusted
    UTXOs that z_shieldfunds can consume deterministically in functional tests.
    """
    if sync_fun is None:
        sync_fun = test.no_op

    send_amount = Decimal(str(amount))
    if send_amount <= Decimal("0"):
        raise AssertionError("fund_trusted_transparent_balance amount must be positive")

    test.generatetoaddress(node, maturity_blocks, mine_addr, sync_fun=sync_fun)

    required_total = send_amount + fee
    funded_addr = wallet.getnewaddress()
    candidates = []

    # Prefer wallet-selected mature UTXOs first to avoid accidental mempool
    # conflicts when functional tests keep non-broadcast wallet txs around.
    for utxo in wallet.listunspent(101):
        if not utxo.get("spendable", False):
            continue
        value = Decimal(str(utxo["amount"]))
        if value < required_total:
            continue
        candidates.append((utxo["txid"], int(utxo["vout"]), value))

    # Fallback to direct chain scan if the wallet does not expose any mature
    # spendable output even after mining.
    if not candidates:
        tip_height = int(node.getblockcount())
        for height in range(1, tip_height + 1):
            spend_block_hash = node.getblockhash(height)
            spend_block = node.getblock(spend_block_hash, 2)
            coinbase_txid = spend_block["tx"][0]["txid"]
            txout = node.gettxout(coinbase_txid, 0, True)
            if txout is None:
                continue
            value = Decimal(str(txout["value"]))
            if value < required_total:
                continue
            candidates.append((coinbase_txid, 0, value))

    if not candidates:
        raise AssertionError(
            f"no unspent mature coinbase output found for required amount {required_total}"
        )

    last_error = None
    for selected_txid, selected_vout, selected_total in candidates:
        inputs = [{"txid": selected_txid, "vout": selected_vout}]
        change_amount = (selected_total - required_total).quantize(
            Decimal("0.00000001"), rounding=ROUND_DOWN
        )
        outputs = {funded_addr: float(send_amount)}
        if change_amount > Decimal("0"):
            outputs[mine_addr] = float(change_amount)

        raw_tx = node.createrawtransaction(inputs, outputs)
        signed = wallet.signrawtransactionwithwallet(raw_tx)
        if not signed["complete"]:
            last_error = f"failed to sign direct coinbase funding transaction: {signed.get('errors')}"
            continue

        try:
            txid = node.sendrawtransaction(signed["hex"])
            test.generatetoaddress(node, 1, mine_addr, sync_fun=sync_fun)
            return txid, funded_addr
        except JSONRPCException as e:
            last_error = str(e)
            message = e.error.get("message", "")
            code = e.error.get("code")
            if code == -26 and (
                "rejecting replacement" in message
                or "txn-mempool-conflict" in message
            ):
                continue
            raise

    raise AssertionError(
        f"failed to create trusted transparent funding tx from mature outputs: {last_error}"
    )
