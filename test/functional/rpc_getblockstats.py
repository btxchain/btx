#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import COIN
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    getnewdestination,
)
import json
import os

TESTSDIR = os.path.dirname(os.path.realpath(__file__))
UPSTREAM_REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

class GetblockstatsTest(BitcoinTestFramework):

    start_height = 101
    max_stat_pos = 2

    def add_options(self, parser):
        parser.add_argument('--gen-test-data', dest='gen_test_data',
                            default=False, action='store_true',
                            help='Generate test data')
        parser.add_argument('--test-data', dest='test_data',
                            default='data/rpc_getblockstats.json',
                            action='store', metavar='FILE',
                            help='Test data file')

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False

    def get_stats(self):
        return [self.nodes[0].getblockstats(hash_or_height=self.start_height + i) for i in range(self.max_stat_pos+1)]

    def send_to_script(self, wallet, script_pub_key, *, amount_sats, fee_sats, subtract_fee):
        amount_out = amount_sats - fee_sats if subtract_fee else amount_sats
        assert amount_out > 0
        wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=script_pub_key,
            amount=amount_out,
            fee=fee_sats,
        )

    def generate_test_data(self, filename):
        mocktime = 1525107225
        self.nodes[0].setmocktime(mocktime)
        wallet = MiniWallet(self.nodes[0])
        self.generatetodescriptor(self.nodes[0], COINBASE_MATURITY + 1, wallet.get_descriptor())
        wallet.rescan_utxos()

        _, recipient_script, _ = getnewdestination()

        self.send_to_script(wallet, recipient_script, amount_sats=10 * COIN, fee_sats=1_000, subtract_fee=True)
        self.generatetodescriptor(self.nodes[0], 1, wallet.get_descriptor())
        wallet.rescan_utxos()

        self.send_to_script(wallet, recipient_script, amount_sats=10 * COIN, fee_sats=1_000, subtract_fee=True)
        self.send_to_script(wallet, recipient_script, amount_sats=10 * COIN, fee_sats=1_000, subtract_fee=False)
        self.send_to_script(wallet, recipient_script, amount_sats=1 * COIN, fee_sats=300_000, subtract_fee=True)
        # Send to OP_RETURN output to test its exclusion from statistics
        wallet.send_to(from_node=self.nodes[0], scriptPubKey=CScript([OP_RETURN, b"\x21"]), amount=0, fee=1_000)
        self.sync_all()
        self.generate(self.nodes[0], 1)

        self.expected_stats = self.get_stats()

        blocks = []
        tip = self.nodes[0].getbestblockhash()
        blockhash = None
        height = 0
        while tip != blockhash:
            blockhash = self.nodes[0].getblockhash(height)
            blocks.append(self.nodes[0].getblock(blockhash, 0))
            height += 1

        to_dump = {
            'blocks': blocks,
            'mocktime': int(mocktime),
            'stats': self.expected_stats,
        }
        with open(filename, 'w', encoding="utf8") as f:
            json.dump(to_dump, f, sort_keys=True, indent=2)

    def load_test_data(self, filename):
        with open(filename, 'r', encoding="utf8") as f:
            d = json.load(f)
            blocks = d['blocks']
            mocktime = d['mocktime']
            self.expected_stats = d['stats']

        # Set the timestamps from the file so that the nodes can get out of Initial Block Download
        self.nodes[0].setmocktime(mocktime)
        self.sync_all()

        for b in blocks:
            self.nodes[0].submitblock(b)


    def run_test(self):
        test_data = os.path.join(TESTSDIR, self.options.test_data)
        if self.options.gen_test_data:
            self.generate_test_data(test_data)
        else:
            if self.nodes[0].getblockhash(0) == UPSTREAM_REGTEST_GENESIS:
                self.load_test_data(test_data)
            else:
                # The precomputed fixture contains upstream regtest block hex.
                # Regenerating keeps the assertions chain-specific and avoids
                # submitblock decode failures on BTX/KAWPOW networks.
                generated = os.path.join(self.options.tmpdir, 'rpc_getblockstats.generated.json')
                self.generate_test_data(generated)

        self.sync_all()
        stats = self.get_stats()

        # Make sure all valid statistics are included but nothing else is
        expected_keys = self.expected_stats[0].keys()
        assert_equal(set(stats[0].keys()), set(expected_keys))

        assert_equal(stats[0]['height'], self.start_height)
        assert_equal(stats[self.max_stat_pos]['height'], self.start_height + self.max_stat_pos)

        for i in range(self.max_stat_pos+1):
            self.log.info('Checking block %d' % (i))
            assert_equal(stats[i], self.expected_stats[i])

            # Check selecting block by hash too
            blockhash = self.expected_stats[i]['blockhash']
            stats_by_hash = self.nodes[0].getblockstats(hash_or_height=blockhash)
            assert_equal(stats_by_hash, self.expected_stats[i])

        # Make sure each stat can be queried on its own
        for stat in expected_keys:
            for i in range(self.max_stat_pos+1):
                result = self.nodes[0].getblockstats(hash_or_height=self.start_height + i, stats=[stat])
                assert_equal(list(result.keys()), [stat])
                if result[stat] != self.expected_stats[i][stat]:
                    self.log.info('result[%s] (%d) failed, %r != %r' % (
                        stat, i, result[stat], self.expected_stats[i][stat]))
                assert_equal(result[stat], self.expected_stats[i][stat])

        # Make sure only the selected statistics are included (more than one)
        some_stats = {'minfee', 'maxfee'}
        stats = self.nodes[0].getblockstats(hash_or_height=1, stats=list(some_stats))
        assert_equal(set(stats.keys()), some_stats)

        # Test invalid parameters raise the proper json exceptions
        tip = self.start_height + self.max_stat_pos
        assert_raises_rpc_error(-8, 'Target block height %d after current tip %d' % (tip+1, tip),
                                self.nodes[0].getblockstats, hash_or_height=tip+1)
        assert_raises_rpc_error(-8, 'Target block height %d is negative' % (-1),
                                self.nodes[0].getblockstats, hash_or_height=-1)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            [inv_sel_stat],
            ['minfee', inv_sel_stat],
            [inv_sel_stat, 'minfee'],
            ['minfee', inv_sel_stat, 'maxfee'],
        ]
        for inv_stat in inv_stats:
            assert_raises_rpc_error(-8, f"Invalid selected statistic '{inv_sel_stat}'",
                                    self.nodes[0].getblockstats, hash_or_height=1, stats=inv_stat)

        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_rpc_error(-8, f"Invalid selected statistic 'aaa{inv_sel_stat}'",
                                self.nodes[0].getblockstats, hash_or_height=1, stats=['minfee', f'aaa{inv_sel_stat}'])
        # Mainchain's genesis block shouldn't be found on regtest
        assert_raises_rpc_error(-5, 'Block not found', self.nodes[0].getblockstats,
                                hash_or_height='000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')

        # Invalid number of args
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats )', self.nodes[0].getblockstats, '00', 1, 2)
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats )', self.nodes[0].getblockstats)

        self.log.info('Test block height 0')
        genesis_stats = self.nodes[0].getblockstats(0)
        assert_equal(genesis_stats["blockhash"], self.nodes[0].getblockhash(0))
        assert_equal(genesis_stats["utxo_increase"], 1)
        assert genesis_stats["utxo_size_inc"] > 0
        assert_equal(genesis_stats["utxo_increase_actual"], 0)
        assert_equal(genesis_stats["utxo_size_inc_actual"], 0)

        self.log.info('Test tip including OP_RETURN')
        tip_stats = self.nodes[0].getblockstats(tip)
        assert_equal(tip_stats["utxo_increase"], self.expected_stats[self.max_stat_pos]["utxo_increase"])
        assert_equal(tip_stats["utxo_size_inc"], self.expected_stats[self.max_stat_pos]["utxo_size_inc"])
        assert tip_stats["utxo_increase_actual"] < tip_stats["utxo_increase"]
        assert tip_stats["utxo_size_inc_actual"] < tip_stats["utxo_size_inc"]

        self.log.info("Test when only header is known")
        block = self.generateblock(self.nodes[0], output="raw(55)", transactions=[], submit=False)
        self.nodes[0].submitheader(block["hex"])
        assert_raises_rpc_error(-1, "Block not available (not fully downloaded)", lambda: self.nodes[0].getblockstats(block['hash']))

        self.log.info('Test when block is missing')
        (self.nodes[0].blocks_path / 'blk00000.dat').rename(self.nodes[0].blocks_path / 'blk00000.dat.backup')
        assert_raises_rpc_error(-1, 'Block not found on disk', self.nodes[0].getblockstats, hash_or_height=1)
        (self.nodes[0].blocks_path / 'blk00000.dat.backup').rename(self.nodes[0].blocks_path / 'blk00000.dat')


if __name__ == '__main__':
    GetblockstatsTest(__file__).main()
