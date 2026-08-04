#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the scanblocks RPC call."""
from test_framework.address import address_to_scriptpubkey
from test_framework.blockfilter import (
    bip158_basic_element_hash,
    bip158_relevant_scriptpubkeys,
)
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


class ScanblocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-blockfilterindex=1"], []]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        # Use deterministic private PQHD descriptors so the test remains
        # wallet-module independent while producing policy-standard P2MR
        # destinations and change.
        seed = "01" * 32
        receive_desc = descsum_create(
            f"mr(pqhd({seed}/1h/0h/0/*),pk_slh(pqhd({seed}/1h/0h/0/*)))"
        )
        change_desc = descsum_create(
            f"mr(pqhd({seed}/1h/0h/1/*),pk_slh(pqhd({seed}/1h/0h/1/*)))"
        )
        receive_addresses = node.deriveaddresses(receive_desc, [0, 5])
        change_addresses = iter(node.deriveaddresses(change_desc, [0, 1]))

        def send_to_p2mr(script_pub_key, amount, fee=1000):
            """Spend a MiniWallet coin using only standard P2MR outputs."""
            tx = wallet.create_self_transfer(fee_rate=0)["tx"]
            assert_greater_than_or_equal(tx.vout[0].nValue, amount + fee)
            tx.vout[0].nValue -= amount + fee
            tx.vout[0].scriptPubKey = address_to_scriptpubkey(next(change_addresses))
            tx.vout.append(CTxOut(amount, script_pub_key))
            wallet.sendrawtransaction(from_node=node, tx_hex=tx.serialize().hex())

        # send 1.0, mempool only
        addr_1 = receive_addresses[0]
        send_to_p2mr(address_to_scriptpubkey(addr_1), 1 * COIN)

        # send 1.0, mempool only
        # child 5 of the ranged P2MR descriptor
        ranged_addr = receive_addresses[5]
        send_to_p2mr(address_to_scriptpubkey(ranged_addr), 1 * COIN)

        # mine a block and assure that the mined blockhash is in the filterresult
        blockhash = self.generate(node, 1)[0]
        height = node.getblockheader(blockhash)['height']
        self.wait_until(lambda: all(i["synced"] for i in node.getindexinfo().values()))

        out = node.scanblocks("start", [f"addr({addr_1})"])
        assert blockhash in out['relevant_blocks']
        assert_equal(height, out['to_height'])
        assert_equal(0, out['from_height'])
        assert_equal(True, out['completed'])

        # mine another block
        blockhash_new = self.generate(node, 1)[0]
        height_new = node.getblockheader(blockhash_new)['height']

        # make sure the blockhash is not in the filter result if we set the start_height
        # to the just mined block (unlikely to hit a false positive)
        assert blockhash not in node.scanblocks(
            "start", [f"addr({addr_1})"], height_new)['relevant_blocks']

        # make sure the blockhash is present when using the first mined block as start_height
        assert blockhash in node.scanblocks(
            "start", [f"addr({addr_1})"], height)['relevant_blocks']
        for v in [False, True]:
            assert blockhash in node.scanblocks(
                action="start",
                scanobjects=[f"addr({addr_1})"],
                start_height=height,
                options={"filter_false_positives": v})['relevant_blocks']

        # also test the stop height
        assert blockhash in node.scanblocks(
            "start", [f"addr({addr_1})"], height, height)['relevant_blocks']

        # use the stop_height to exclude the relevant block
        assert blockhash not in node.scanblocks(
            "start", [f"addr({addr_1})"], 0, height - 1)['relevant_blocks']

        # make sure the blockhash is present when using the first mined block as start_height
        assert blockhash in node.scanblocks(
            "start", [{"desc": receive_desc, "range": [0, 100]}], height)['relevant_blocks']

        # check that false-positives are included in the result now; note that
        # finding a false-positive at runtime would take too long, hence we simply
        # use a pre-calculated one that collides with the regtest genesis block's
        # coinbase output and verify that their BIP158 ranged hashes match
        genesis_blockhash = node.getblockhash(0)
        genesis_spks = bip158_relevant_scriptpubkeys(node, genesis_blockhash)
        assert_equal(len(genesis_spks), 1)
        genesis_coinbase_spk = list(genesis_spks)[0]
        # Precomputed collision for BTX regtest genesis blockhash:
        # 521ad0951ed299e9c56aeb7db8188972772067560351b8e55adf71dbed532360
        false_positive_spk = bytes.fromhex("001400000000000000000000000000000000000bc25f")

        genesis_coinbase_hash = bip158_basic_element_hash(genesis_coinbase_spk, 1, genesis_blockhash)
        false_positive_hash = bip158_basic_element_hash(false_positive_spk, 1, genesis_blockhash)
        assert_equal(genesis_coinbase_hash, false_positive_hash)

        assert genesis_blockhash in node.scanblocks(
            "start", [{"desc": f"raw({genesis_coinbase_spk.hex()})"}], 0, 0)['relevant_blocks']
        assert genesis_blockhash in node.scanblocks(
            "start", [{"desc": f"raw({false_positive_spk.hex()})"}], 0, 0)['relevant_blocks']

        # check that the filter_false_positives option works
        assert genesis_blockhash in node.scanblocks(
            "start", [{"desc": f"raw({genesis_coinbase_spk.hex()})"}], 0, 0, "basic", {"filter_false_positives": True})['relevant_blocks']
        assert genesis_blockhash not in node.scanblocks(
            "start", [{"desc": f"raw({false_positive_spk.hex()})"}], 0, 0, "basic", {"filter_false_positives": True})['relevant_blocks']

        # test node with disabled blockfilterindex
        assert_raises_rpc_error(-1, "Index is not enabled for filtertype basic",
                                self.nodes[1].scanblocks, "start", [f"addr({addr_1})"])

        # test unknown filtertype
        assert_raises_rpc_error(-5, "Unknown filtertype",
                                node.scanblocks, "start", [f"addr({addr_1})"], 0, 10, "extended")

        # test invalid start_height
        assert_raises_rpc_error(-1, "Invalid start_height",
                                node.scanblocks, "start", [f"addr({addr_1})"], 100000000)

        # test invalid stop_height
        assert_raises_rpc_error(-1, "Invalid stop_height",
                                node.scanblocks, "start", [f"addr({addr_1})"], 10, 0)
        assert_raises_rpc_error(-1, "Invalid stop_height",
                                node.scanblocks, "start", [f"addr({addr_1})"], 10, 100000000)

        # test accessing the status (must be empty)
        assert_equal(node.scanblocks("status"), None)

        # test aborting the current scan (there is no, must return false)
        assert_equal(node.scanblocks("abort"), False)

        # test invalid command
        assert_raises_rpc_error(-8, "Invalid action 'foobar'", node.scanblocks, "foobar")


if __name__ == '__main__':
    ScanblocksTest(__file__).main()
