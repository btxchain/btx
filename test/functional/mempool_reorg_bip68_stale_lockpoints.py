#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that removeForReorg correctly handles stale BIP68 lockpoints."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

SEQ_BIP68_DISABLE = 0xFFFFFFFE
SEQ_BIP68_ZERO = 0x00000000


class MempoolReorgBip68StaleLocksTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def find_output(wallet, txid, address):
        tx = wallet.gettransaction(txid=txid, verbose=True)["decoded"]
        for output in tx["vout"]:
            if output["scriptPubKey"].get("address") == address:
                return {
                    "txid": txid,
                    "vout": output["n"],
                    "value": output["value"],
                }
        raise AssertionError(f"Missing output to {address} in {txid}")

    @staticmethod
    def spend(wallet, inputs, *, sequence=SEQ_BIP68_DISABLE):
        destination = wallet.getnewaddress(address_type="p2mr")
        selected = [
            {
                "txid": txin["txid"],
                "vout": txin["vout"],
                "sequence": sequence,
            }
            for txin in inputs
        ]
        result = wallet.send(
            outputs={destination: sum(txin["value"] for txin in inputs)},
            options={
                "add_inputs": False,
                "inputs": selected,
                "locktime": 0,
                "replaceable": sequence <= 0xFFFFFFFD,
                "subtract_fee_from_outputs": [0],
            },
        )
        assert result["complete"]
        return result["txid"], MempoolReorgBip68StaleLocksTest.find_output(wallet, result["txid"], destination)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="reorg")
        wallet = node.get_wallet_rpc("reorg")
        mine_address = wallet.getnewaddress(address_type="p2mr")
        self.generatetoaddress(node, 200, mine_address)

        # Confirm a UTXO one block below the block we will invalidate, so the
        # mixed spend below keeps a confirmed input through the reorg.
        mixed_address = wallet.getnewaddress(address_type="p2mr")
        mixed_txid = wallet.sendtoaddress(mixed_address, Decimal("1"))
        self.generatetoaddress(node, 1, mine_address)
        mixed_funding = self.find_output(wallet, mixed_txid, mixed_address)

        funding_addresses = [wallet.getnewaddress(address_type="p2mr") for _ in range(2)]
        funding_txid = wallet.send(
            outputs={address: Decimal("1") for address in funding_addresses},
        )
        assert funding_txid["complete"]
        block_setup = self.generatetoaddress(node, 1, mine_address)[0]
        funding = [self.find_output(wallet, funding_txid["txid"], address) for address in funding_addresses]

        height = node.getblockcount()
        _, parent_a = self.spend(wallet, [funding[0]])
        _, parent_b = self.spend(wallet, [funding[1]])
        child_a_txid, child_a = self.spend(wallet, [parent_a], sequence=SEQ_BIP68_DISABLE)
        child_b_txid, child_b = self.spend(wallet, [parent_b], sequence=SEQ_BIP68_ZERO)

        # This spends one confirmed and one unconfirmed input. Its cached
        # maxInputBlock is not the genesis sentinel, so the complete sequence
        # lock check must trigger recalculation after the reorg.
        child_mixed_txid, _ = self.spend(wallet, [mixed_funding, child_b], sequence=SEQ_BIP68_ZERO)

        node.invalidateblock(block_setup)
        assert_equal(node.getblockcount(), height - 1)

        mempool = node.getrawmempool()
        assert child_a_txid in mempool
        assert child_b_txid in mempool
        assert child_mixed_txid in mempool


if __name__ == "__main__":
    MempoolReorgBip68StaleLocksTest(__file__).main()
