#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining on an alternate mainnet

Test mining related RPCs that involve difficulty adjustment, which
regtest doesn't have.

It uses an alternate mainnet chain. See data/README.md for how it was generated.

Mine one retarget period worth of blocks with a short interval in
order to maximally raise the difficulty. Verify this using the getmininginfo RPC.

"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.blocktools import (
    DIFF_1_N_BITS,
    DIFF_1_TARGET,
    DIFF_4_N_BITS,
    DIFF_4_TARGET,
    create_coinbase,
    nbits_str,
    target_str
)

from test_framework.messages import (
    CBlock,
)

import json
import os

# See data/README.md
COINBASE_SCRIPT_PUBKEY="76a914eadbac7f36c37e39361168b7aaee3cb24a25312d88ac"

class MiningMainnetTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = "" # main

    def add_options(self, parser):
        parser.add_argument(
            '--datafile',
            default='data/mainnet_alt.json',
            help='Block data file (default: %(default)s)',
        )

        self.add_wallet_options(parser)

    def build_block(self, height, prev_hash, blocks):
        self.log.debug(f"height={height}")
        block = CBlock()
        block.nVersion = 0x20000000
        block.hashPrevBlock = int(prev_hash, 16)
        block.nTime = blocks['timestamps'][height - 1]
        block.nBits = DIFF_1_N_BITS if height < 2016 else DIFF_4_N_BITS
        block.nNonce = blocks['nonces'][height - 1]
        block.vtx = [create_coinbase(height=height, script_pubkey=bytes.fromhex(COINBASE_SCRIPT_PUBKEY), halving_period=210000)]
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        return block

    def mine(self, height, prev_hash, blocks, node, expected_result=None):
        block = self.build_block(height=height, prev_hash=prev_hash, blocks=blocks)
        block_hex = block.serialize(with_witness=False).hex()
        self.log.debug(block_hex)
        assert_equal(node.submitblock(block_hex), expected_result)
        if expected_result is None:
            prev_hash = node.getbestblockhash()
            assert_equal(prev_hash, block.hash)
        return prev_hash


    def run_test(self):
        node = self.nodes[0]
        # Clear disk space warning
        node.stderr.seek(0)
        node.stderr.truncate()
        self.log.info("Load alternative mainnet blocks")
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.options.datafile)
        prev_hash = node.getbestblockhash()
        blocks = None
        with open(path, encoding='utf-8') as f:
            blocks = json.load(f)
            n_blocks = len(blocks['timestamps'])
            assert_equal(n_blocks, 2016)

        probe = self.build_block(height=1, prev_hash=prev_hash, blocks=blocks)
        probe_result = node.submitblock(probe.serialize(with_witness=False).hex())
        if probe_result == "high-hash":
            self.log.info("Run KAWPOW mainnet mining checks")

            # Historical SHA256 precomputed block data must be rejected under KAWPOW.
            assert_equal(node.getbestblockhash(), prev_hash)
            assert_equal(node.getblockcount(), 0)

            mining_info = node.getmininginfo()
            assert_equal(mining_info['next']['height'], 1)
            assert mining_info['difficulty'] > 0
            assert mining_info['next']['difficulty'] > 0
            assert len(mining_info['next']['bits']) == 8
            assert len(mining_info['next']['target']) == 64

            # Submit an unsolved candidate on top of genesis and require strict PoW rejection.
            best_header = node.getblockheader(prev_hash)
            candidate = CBlock()
            candidate.nVersion = best_header["version"]
            candidate.hashPrevBlock = int(prev_hash, 16)
            candidate.nTime = best_header["time"] + 1
            candidate.nBits = int(mining_info["next"]["bits"], 16)
            candidate.nNonce = 0
            candidate.nNonce64 = 0
            candidate.mixHash = 0
            candidate.vtx = [create_coinbase(height=1, script_pubkey=bytes.fromhex(COINBASE_SCRIPT_PUBKEY), halving_period=210000)]
            candidate.hashMerkleRoot = candidate.calc_merkle_root()
            candidate.rehash()
            assert_equal(node.submitblock(candidate.serialize(with_witness=False).hex()), 'high-hash')
            return
        assert_equal(probe_result, None)
        prev_hash = node.getbestblockhash()
        assert_equal(prev_hash, probe.hash)

        # Mine up to the last block of the first retarget period
        for i in range(1, 2015):
            prev_hash = self.mine(i + 1, prev_hash, blocks, node)

        assert_equal(node.getblockcount(), 2015)

        self.log.info("Check difficulty adjustment with getmininginfo")
        mining_info = node.getmininginfo()
        assert_equal(mining_info['difficulty'], 1)
        assert_equal(mining_info['bits'], nbits_str(DIFF_1_N_BITS))
        assert_equal(mining_info['target'], target_str(DIFF_1_TARGET))

        assert_equal(mining_info['next']['height'], 2016)
        assert_equal(mining_info['next']['difficulty'], 4)
        assert_equal(mining_info['next']['bits'], nbits_str(DIFF_4_N_BITS))
        assert_equal(mining_info['next']['target'], target_str(DIFF_4_TARGET))

        # Mine first block of the second retarget period
        height = 2016
        prev_hash = self.mine(height, prev_hash, blocks, node)
        assert_equal(node.getblockcount(), height)

        mining_info = node.getmininginfo()
        assert_equal(mining_info['difficulty'], 4)

        self.log.info("getblock RPC should show historical target")
        block_info = node.getblock(node.getblockhash(1))

        assert_equal(block_info['difficulty'], 1)
        assert_equal(block_info['bits'], nbits_str(DIFF_1_N_BITS))
        assert_equal(block_info['target'], target_str(DIFF_1_TARGET))


if __name__ == '__main__':
    MiningMainnetTest(__file__).main()
