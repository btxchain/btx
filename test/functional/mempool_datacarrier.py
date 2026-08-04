#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that BTX's financial-only relay policy cannot be bypassed by datacarrier settings."""
from test_framework.messages import (
    CTxOut,
    MAX_OP_RETURN_RELAY,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet

from random import randbytes


class DataCarrierTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [
            [],
            ["-datacarrier=0"],
            ["-datacarrier=1", f"-datacarriersize={MAX_OP_RETURN_RELAY - 1}"],
            ["-datacarrier=1", "-datacarriersize=2"],
        ]

    def test_null_data_transaction(self, node: TestNode, data, success: bool) -> None:
        tx = self.wallet.create_self_transfer(fee_rate=0)["tx"]
        data = [] if data is None else [data]
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN] + data)))
        tx.vout[0].nValue -= tx.get_vsize()  # simply pay 1sat/vbyte fee

        tx_hex = tx.serialize().hex()

        if success:
            self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_hex)
            assert tx.rehash() in node.getrawmempool(True), f'{tx_hex} not in mempool'
        else:
            assert_raises_rpc_error(-26, "scriptpubkey", self.wallet.sendrawtransaction, from_node=node, tx_hex=tx_hex)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        # BTX rejects null-data outputs independent of the inherited
        # -datacarrier/-datacarriersize knobs.
        default_size_data = randbytes(MAX_OP_RETURN_RELAY - 3)
        too_long_data = randbytes(MAX_OP_RETURN_RELAY - 2)
        small_data = randbytes(MAX_OP_RETURN_RELAY - 4)
        one_byte = randbytes(1)
        zero_bytes = randbytes(0)

        for node in self.nodes:
            for data in (default_size_data, too_long_data, small_data, None, zero_bytes, one_byte):
                self.test_null_data_transaction(node=node, data=data, success=False)


if __name__ == '__main__':
    DataCarrierTest(__file__).main()
