#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with -reindex and -reindex-chainstate options.

- Start a single node and generate 3 blocks.
- Stop the node and restart it with -reindex. Verify that the node has reindexed up to block 3.
- Stop the node and restart it with -reindex-chainstate. Verify that the node has reindexed up to block 3.
- Verify that out-of-order blocks are correctly processed, see LoadExternalBlockFile()
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import MAGIC_BYTES
from test_framework.util import (
    assert_equal,
    util_xor,
)


class ReindexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # Whether the currently-running node was started with -reindex-chainstate,
        # which makes it emit MATMUL_REINDEX_CHAINSTATE_WARNING on shutdown.
        self.started_with_reindex_chainstate = False

    # BTX emits a MatMul-specific warning on -reindex-chainstate (init.cpp):
    # that mode does not rerun the contextual Phase-2 checks, which matters on a
    # chain whose PoW is re-executed rather than re-hashed. stop_nodes() asserts
    # stderr is empty, so the expectation has to be declared or this test fails
    # on every BTX build.
    MATMUL_REINDEX_CHAINSTATE_WARNING = (
        "Warning: Using -reindex-chainstate on MatMul chains does not rerun all "
        "contextual Phase 2 checks. Use -reindex for full historical re-validation."
    )

    def stop_expecting_matmul_warning(self):
        self.stop_node(0, expected_stderr=(
            self.MATMUL_REINDEX_CHAINSTATE_WARNING
            if self.started_with_reindex_chainstate else ''))
        self.started_with_reindex_chainstate = False

    def reindex(self, justchainstate=False):
        self.generatetoaddress(self.nodes[0], 3, self.nodes[0].get_deterministic_priv_key().address)
        blockcount = self.nodes[0].getblockcount()
        self.stop_expecting_matmul_warning()
        extra_args = [["-reindex-chainstate" if justchainstate else "-reindex"]]
        self.start_nodes(extra_args)
        self.started_with_reindex_chainstate = justchainstate
        assert_equal(self.nodes[0].getblockcount(), blockcount)  # start_node is blocking on reindex
        self.log.info("Success")

    # Check that blocks can be processed out of order
    def out_of_order(self):
        # The previous test created 12 blocks
        assert_equal(self.nodes[0].getblockcount(), 12)
        self.stop_expecting_matmul_warning()

        # In this test environment, blocks will always be in order (since
        # we're generating them rather than getting them from peers), so to
        # test out-of-order handling, swap blocks 1 and 2 on disk.
        blk0 = self.nodes[0].blocks_path / "blk00000.dat"
        xor_dat = self.nodes[0].read_xor_key()

        with open(blk0, 'r+b') as bf:
            # Read at least the first few blocks (including genesis).
            #
            # Upstream reads 2000 bytes, which covers genesis plus three blocks
            # on a Bitcoin regtest chain (~350 bytes each). A BTX regtest block
            # is ~16.75 KB because the header carries the MatMul fields, so 2000
            # bytes holds only genesis and part of block 2: find_block then
            # returned -1 for blocks 3 and 4 and the swap silently operated on a
            # 355-byte slice. Read enough to span genesis + 4 blocks.
            b = util_xor(bf.read(256 * 1024), xor_dat, offset=0)

            # Find the offsets of blocks 2, 3, and 4 (the first 3 blocks beyond genesis)
            # by searching for the regtest marker bytes (see pchMessageStart).
            def find_block(b, start):
                return b.find(MAGIC_BYTES["regtest"], start)+4

            genesis_start = find_block(b, 0)
            assert_equal(genesis_start, 4)
            b2_start = find_block(b, genesis_start)
            b3_start = find_block(b, b2_start)
            b4_start = find_block(b, b3_start)

            # Swap the second and third blocks (don't disturb the genesis block).
            # Rebuild the whole [b2_start, b4_start) span rather than assuming
            # the two blocks are equal-sized: the concatenation occupies exactly
            # the same extent either way, and the XOR pad is positional so the
            # destination offset is what matters.
            swapped = b[b3_start:b4_start] + b[b2_start:b3_start]
            assert_equal(len(swapped), b4_start - b2_start)
            bf.seek(b2_start)
            bf.write(util_xor(swapped, xor_dat, offset=b2_start))

        # The reindexing code should detect and accommodate out of order blocks.
        with self.nodes[0].assert_debug_log([
            'LoadExternalBlockFile: Out of order block',
            'LoadExternalBlockFile: Processing out of order child',
        ]):
            extra_args = [["-reindex"]]
            self.start_nodes(extra_args)

        # All blocks should be accepted and processed.
        assert_equal(self.nodes[0].getblockcount(), 12)

    def continue_reindex_after_shutdown(self):
        node = self.nodes[0]
        self.generate(node, 1500)

        # Restart node with reindex and stop reindex as soon as it starts reindexing
        self.log.info("Restarting node while reindexing..")
        node.stop_node()
        with node.busy_wait_for_debug_log([b'initload thread start']):
            node.start(['-blockfilterindex', '-reindex'])
            node.wait_for_rpc_connection(wait_for_import=False)
        node.stop_node()

        # Start node without the reindex flag and verify it does not wipe the indexes data again
        db_path = node.chain_path / 'indexes' / 'blockfilter' / 'basic' / 'db'
        with node.assert_debug_log(expected_msgs=[f'Opening LevelDB in {db_path}'], unexpected_msgs=[f'Wiping LevelDB in {db_path}']):
            node.start(['-blockfilterindex'])
            node.wait_for_rpc_connection(wait_for_import=False)
        node.stop_node()

    def run_test(self):
        self.reindex(False)
        self.reindex(True)
        self.reindex(False)
        self.reindex(True)

        self.out_of_order()
        self.continue_reindex_after_shutdown()


if __name__ == '__main__':
    ReindexTest(__file__).main()
