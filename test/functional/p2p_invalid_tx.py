#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test node responses to invalid transactions.

In this test we connect to one node over p2p, and test tx requests."""
import os

from test_framework.messages import (
    CBlock,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    from_hex,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.util import (
    assert_equal,
)
from data import invalid_txs


class InvalidTxRequestTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-acceptnonstdtxn=1",
        ]]
        self.setup_clean_chain = True

    def bootstrap_p2p(self, *, num_connections=1):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        for i in range(num_connections):
            self.nodes[0].add_outbound_p2p_connection(P2PDataStore(), p2p_idx=i)

    def reconnect_p2p(self, **kwargs):
        """Tear down and bootstrap the P2P connection to the node.

        The node gets disconnected several times in this test. This helper
        method reconnects the p2p and restarts the network thread."""
        self.nodes[0].disconnect_p2ps()
        self.bootstrap_p2p(**kwargs)

    def run_test(self):
        os.environ["BTX_PY_BLOCK_SOLVE_STRICT"] = "1"
        os.environ.setdefault("BTX_PY_BLOCK_SOLVE_MAX_TRIES", "300000")
        node = self.nodes[0]  # convenience reference to the node

        self.log.info("Mine blocks with anyone-can-spend coinbases")
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)
        mined_blocks = self.generate(wallet, 101)
        block1 = from_hex(CBlock(), node.getblock(mined_blocks[0], 0))
        for tx in block1.vtx:
            tx.calc_sha256()

        self.bootstrap_p2p()  # Add one p2p connection to the node

        # Iterate through a list of known invalid transaction types, ensuring each is
        # rejected. Some are consensus invalid and some just violate policy.
        for BadTxTemplate in invalid_txs.iter_all_templates():
            self.log.info("Testing invalid transaction: %s", BadTxTemplate.__name__)
            template = BadTxTemplate(spend_block=block1)
            tx = template.get_tx()
            node.p2ps[0].send_txs_and_test(
                [tx], node, success=False,
                reject_reason=template.reject_reason,
            )

        # Make two p2p connections to provide the node with orphans
        # * p2ps[0] will send valid orphan txs (one with low fee)
        # * p2ps[1] will send an invalid orphan tx (and is later disconnected for that)
        self.reconnect_p2p(num_connections=2)

        self.log.info('Test orphan transaction handling ... ')
        # Create a root transaction that we withhold until all dependent transactions
        # are sent out and in the orphan cache
        SCRIPT_PUB_KEY_OP_TRUE = b'\x51\x75' * 15 + b'\x51'
        relay_fee = 12_000
        coinbase_value = block1.vtx[0].vout[0].nValue
        tx_withhold_value = (coinbase_value - relay_fee) // 2
        tx_withhold = CTransaction()
        tx_withhold.vin.append(CTxIn(outpoint=COutPoint(block1.vtx[0].sha256, 0)))
        tx_withhold.vout = [CTxOut(nValue=tx_withhold_value, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE)] * 2
        tx_withhold.calc_sha256()

        # Our first orphan tx with some outputs to create further orphan txs
        tx_orphan_1_value = (tx_withhold_value - relay_fee) // 3
        tx_orphan_1 = CTransaction()
        tx_orphan_1.vin.append(CTxIn(outpoint=COutPoint(tx_withhold.sha256, 0)))
        tx_orphan_1.vout = [CTxOut(nValue=tx_orphan_1_value, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE)] * 3
        tx_orphan_1.calc_sha256()

        # A valid transaction with low fee
        tx_orphan_2_no_fee = CTransaction()
        tx_orphan_2_no_fee.vin.append(CTxIn(outpoint=COutPoint(tx_orphan_1.sha256, 0)))
        tx_orphan_2_no_fee.vout.append(CTxOut(nValue=tx_orphan_1_value, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))

        # A valid transaction with sufficient fee
        tx_orphan_2_valid = CTransaction()
        tx_orphan_2_valid.vin.append(CTxIn(outpoint=COutPoint(tx_orphan_1.sha256, 1)))
        tx_orphan_2_valid.vout.append(CTxOut(nValue=tx_orphan_1_value - relay_fee, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))
        tx_orphan_2_valid.calc_sha256()

        # An invalid transaction with negative fee
        tx_orphan_2_invalid = CTransaction()
        tx_orphan_2_invalid.vin.append(CTxIn(outpoint=COutPoint(tx_orphan_1.sha256, 2)))
        tx_orphan_2_invalid.vout.append(CTxOut(nValue=tx_orphan_1_value + relay_fee, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))
        tx_orphan_2_invalid.calc_sha256()

        self.log.info('Send the orphans ... ')
        # Send valid orphan txs from p2ps[0]
        node.p2ps[0].send_txs_and_test([tx_orphan_1, tx_orphan_2_no_fee, tx_orphan_2_valid], node, success=False)
        # Send invalid tx from p2ps[1]
        node.p2ps[1].send_txs_and_test([tx_orphan_2_invalid], node, success=False)

        assert_equal(0, node.getmempoolinfo()['size'])  # Mempool should be empty
        assert_equal(2, len(node.getpeerinfo()))  # p2ps[1] is still connected

        self.log.info('Send the withhold tx ... ')
        with node.assert_debug_log(expected_msgs=["bad-txns-in-belowout"]):
            node.p2ps[0].send_txs_and_test([tx_withhold], node, success=True)

        # Transactions that should end up in the mempool
        expected_mempool = {
            t.hash
            for t in [
                tx_withhold,  # The transaction that is the root for all orphans
                tx_orphan_1,  # The orphan transaction that splits the coins
                tx_orphan_2_valid,  # The valid transaction (with sufficient fee)
            ]
        }
        # Transactions that do not end up in the mempool:
        # tx_orphan_2_no_fee, because it has too low fee (p2ps[0] is not disconnected for relaying that tx)
        # tx_orphan_2_invalid, because it has negative fee (p2ps[1] is disconnected for relaying that tx)

        assert_equal(expected_mempool, set(node.getrawmempool()))

        self.log.info('Test orphan pool overflow')
        orphan_tx_pool = [CTransaction() for _ in range(101)]
        for i in range(len(orphan_tx_pool)):
            orphan_tx_pool[i].vin.append(CTxIn(outpoint=COutPoint(i, 333)))
            orphan_tx_pool[i].vout.append(CTxOut(nValue=11 * COIN, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))

        with node.assert_debug_log(['orphanage overflow, removed 1 tx']):
            node.p2ps[0].send_txs_and_test(orphan_tx_pool, node, success=False)

        self.log.info('Test orphan with rejected parents')
        rejected_parent = CTransaction()
        rejected_parent.vin.append(CTxIn(outpoint=COutPoint(tx_orphan_2_invalid.sha256, 0)))
        rejected_parent.vout.append(CTxOut(nValue=11 * COIN, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))
        rejected_parent.rehash()
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(rejected_parent.hash)]):
            node.p2ps[0].send_txs_and_test([rejected_parent], node, success=False)

        self.log.info('Test that a peer disconnection causes erase its transactions from the orphan pool')
        with node.assert_debug_log(['Erased 100 orphan transaction(s) from peer=']):
            self.reconnect_p2p(num_connections=1)

        self.log.info('Test that a transaction in the orphan pool is included in a new tip block causes erase this transaction from the orphan pool')
        tx_withhold_until_block_A_value = (tx_withhold_value - relay_fee) // 2
        tx_withhold_until_block_A = CTransaction()
        tx_withhold_until_block_A.vin.append(CTxIn(outpoint=COutPoint(tx_withhold.sha256, 1)))
        tx_withhold_until_block_A.vout = [CTxOut(nValue=tx_withhold_until_block_A_value, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE)] * 2
        tx_withhold_until_block_A.calc_sha256()

        tx_orphan_include_by_block_A = CTransaction()
        tx_orphan_include_by_block_A.vin.append(CTxIn(outpoint=COutPoint(tx_withhold_until_block_A.sha256, 0)))
        tx_orphan_include_by_block_A.vout.append(CTxOut(nValue=tx_withhold_until_block_A_value - relay_fee, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))
        tx_orphan_include_by_block_A.calc_sha256()

        self.log.info('Send the orphan ... ')
        node.p2ps[0].send_txs_and_test([tx_orphan_include_by_block_A], node, success=False)

        self.log.info('Send the block that includes the previous orphan ... ')
        with node.assert_debug_log(["Erased 1 orphan transaction(s) included or conflicted by block"]):
            self.generateblock(node, self.nodes[0].get_deterministic_priv_key().address,
                               [tx_withhold.serialize().hex(),
                                tx_withhold_until_block_A.serialize().hex(),
                                tx_orphan_include_by_block_A.serialize().hex()])

        self.log.info('Test that a transaction in the orphan pool conflicts with a new tip block causes erase this transaction from the orphan pool')
        tx_withhold_until_block_B_value = tx_withhold_until_block_A_value - relay_fee
        tx_withhold_until_block_B = CTransaction()
        tx_withhold_until_block_B.vin.append(CTxIn(outpoint=COutPoint(tx_withhold_until_block_A.sha256, 1)))
        tx_withhold_until_block_B.vout.append(CTxOut(nValue=tx_withhold_until_block_B_value, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))
        tx_withhold_until_block_B.calc_sha256()

        tx_orphan_include_by_block_B = CTransaction()
        tx_orphan_include_by_block_B.vin.append(CTxIn(outpoint=COutPoint(tx_withhold_until_block_B.sha256, 0)))
        tx_orphan_include_by_block_B.vout.append(CTxOut(nValue=tx_withhold_until_block_B_value - relay_fee, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))
        tx_orphan_include_by_block_B.calc_sha256()

        tx_orphan_conflict_by_block_B = CTransaction()
        tx_orphan_conflict_by_block_B.vin.append(CTxIn(outpoint=COutPoint(tx_withhold_until_block_B.sha256, 0)))
        tx_orphan_conflict_by_block_B.vout.append(CTxOut(nValue=tx_withhold_until_block_B_value - 2 * relay_fee, scriptPubKey=SCRIPT_PUB_KEY_OP_TRUE))
        tx_orphan_conflict_by_block_B.calc_sha256()
        self.log.info('Send the orphan ... ')
        node.p2ps[0].send_txs_and_test([tx_orphan_conflict_by_block_B], node, success=False)

        self.log.info('Send the block that includes a transaction which conflicts with the previous orphan ... ')
        with node.assert_debug_log(["Erased 1 orphan transaction(s) included or conflicted by block"]):
            self.generateblock(node, self.nodes[0].get_deterministic_priv_key().address,
                               [tx_withhold_until_block_B.serialize().hex(),
                                tx_orphan_include_by_block_B.serialize().hex()])


if __name__ == '__main__':
    InvalidTxRequestTest(__file__).main()
