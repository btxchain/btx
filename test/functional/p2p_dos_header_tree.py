#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test header-tree anti-DoS behavior with BTX KAWPOW-compatible headers."""

from test_framework.messages import (
    CBlockHeader,
    from_hex,
)
from test_framework.p2p import (
    P2PInterface,
    msg_headers,
)
from test_framework.test_framework import BitcoinTestFramework


class RejectLowDifficultyHeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = "regtest"
        self.num_nodes = 2
        self.extra_args = [["-minimumchainwork=0x0", "-prune=550"]] * self.num_nodes

    def run_test(self):
        self.log.info("Generate a short valid source chain on node1")
        source_hashes = self.generate(self.nodes[1], 8, sync_fun=self.no_op)
        headers = [from_hex(CBlockHeader(), self.nodes[1].getblockheader(h, False)) for h in source_hashes]

        self.log.info("Feed contiguous headers to node0")
        peer = self.nodes[0].add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
        peer.send_and_ping(msg_headers(headers))
        assert {
            "height": len(headers),
            "hash": source_hashes[-1],
            "branchlen": len(headers),
            "status": "headers-only",
        } in self.nodes[0].getchaintips()

        self.log.info("Feed a non-continuous headers sequence and expect disconnect")
        bad_headers = [CBlockHeader(header) for header in headers]
        bad_headers[1].hashPrevBlock = headers[0].hashPrevBlock
        bad_headers[1].rehash()
        with self.nodes[0].assert_debug_log(["non-continuous headers sequence"]):
            peer.send_message(msg_headers(bad_headers))
            peer.wait_for_disconnect()

        self.log.info("Verify accepted header tip is unchanged after bad sequence")
        assert {
            "height": len(headers),
            "hash": source_hashes[-1],
            "branchlen": len(headers),
            "status": "headers-only",
        } in self.nodes[0].getchaintips()


if __name__ == '__main__':
    RejectLowDifficultyHeadersTest(__file__).main()
