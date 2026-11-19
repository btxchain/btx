#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MiniWallet."""
import random
import string

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)


class FeatureFrameworkMiniWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def test_tx_padding(self):
        """Verify that MiniWallet's transaction padding (`target_vsize` parameter)
           works accurately with all modes."""
        for mode_name, wallet in self.wallets:
            self.log.info(f"Test tx padding with MiniWallet mode {mode_name}...")
            utxo = wallet.get_utxo(mark_as_spent=False)
            # Padding cannot make a transaction smaller than it is. An
            # ADDRESS_P2MR spend of its own output (the child) is 3842 vB, so
            # each target is checked only where it is at least the unpadded size.
            parent = wallet.create_self_transfer(utxo_to_spend=utxo)
            min_parent_vsize = parent['tx'].get_vsize()
            min_child_vsize = wallet.create_self_transfer_multi(utxos_to_spend=[parent["new_utxo"]])['tx'].get_vsize()
            for target_vsize in [250, 500, 1250, 2500, 5000, 12500, 25000, 50000, 1000000,
                                 248, 501, 1085, 3343, 5805, 12289, 25509, 55855,  999998]:
                tx = wallet.create_self_transfer(utxo_to_spend=utxo, target_vsize=max(target_vsize, min_parent_vsize))
                if target_vsize >= min_parent_vsize:
                    assert_equal(tx['tx'].get_vsize(), target_vsize)
                if target_vsize >= min_child_vsize:
                    child_tx = wallet.create_self_transfer_multi(utxos_to_spend=[tx["new_utxo"]], target_vsize=target_vsize)
                    assert_equal(child_tx['tx'].get_vsize(), target_vsize)


    def test_wallet_tagging(self):
        """Verify that tagged wallet instances are able to send funds."""
        self.log.info("Test tagged wallet instances...")
        node = self.nodes[0]
        # ADDRESS_P2MR, the default on a node that enforces standardness; the
        # tagged wallets below get that default too, so every send is standard.
        untagged_wallet = self.wallets[0][1]
        for i in range(10):
            tag = ''.join(random.choice(string.ascii_letters) for _ in range(20))
            self.log.debug(f"-> ({i}) tag name: {tag}")
            tagged_wallet = MiniWallet(node, tag_name=tag)
            # Enough for a 3842 vB P2MR self-transfer at the default fee rate.
            untagged_wallet.send_to(from_node=node, scriptPubKey=tagged_wallet.get_output_script(), amount=2_000_000)
            tagged_wallet.rescan_utxos()
            tagged_wallet.send_self_transfer(from_node=node)
        self.generate(node, 1)  # clear mempool

    def test_default_mode(self):
        """Verify that the default mode follows -acceptnonstdtxn."""
        self.log.info("Test the default MiniWallet mode...")
        p2mr_script = self.wallets[0][1].get_output_script()
        op_true_script = self.wallets[1][1].get_output_script()
        assert_equal(MiniWallet(self.nodes[0]).get_output_script(), p2mr_script)
        self.restart_node(0, extra_args=["-acceptnonstdtxn=1"])
        assert_equal(MiniWallet(self.nodes[0]).get_output_script(), op_true_script)
        self.restart_node(0, extra_args=[])
        assert_equal(MiniWallet(self.nodes[0]).get_output_script(), p2mr_script)

    def run_test(self):
        node = self.nodes[0]
        self.wallets = [
            ("ADDRESS_P2MR", MiniWallet(node, mode=MiniWalletMode.ADDRESS_P2MR)),
            ("ADDRESS_OP_TRUE", MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)),
            ("RAW_OP_TRUE",     MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)),
            ("RAW_P2PKH",        MiniWallet(node, mode=MiniWalletMode.RAW_P2PKH)),
        ]
        for _, wallet in self.wallets:
            self.generate(wallet, 10)
        self.generate(wallet, COINBASE_MATURITY)

        self.test_tx_padding()
        self.test_wallet_tagging()
        self.test_default_mode()


if __name__ == '__main__':
    FeatureFrameworkMiniWalletTest(__file__).main()
