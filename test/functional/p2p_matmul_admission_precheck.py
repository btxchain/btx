#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""Malformed complete bodies must not enter expensive MatMul admission."""

from test_framework.messages import CBlock, CBlockHeader, from_hex, msg_block, msg_headers
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class CBlockWithForbiddenSketch(CBlock):
    """Serialize an ENC-DR body with empty A/B vectors and one C word."""

    def serialize(self, with_witness=True):
        # CBlock's Python wire model intentionally stops after transactions.
        # The C++ extension is three CompactSize-prefixed uint32 vectors; ENC-DR
        # requires all three to be empty, so make only C non-empty here.
        return super().serialize(with_witness) + b"\x00\x00\x01\x01\x00\x00\x00"


class BTXMatMulAdmissionPrecheckTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmulstrict",
            "-debug=net",
            "-regtestmatmulrequireproductpayload=0",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4dimension=64",
            "-regtestmatmulltsealaspow=0",
            "-regtestmatmulltmaxpending=1",
        ]
        self.extra_args = [common, common]

    def run_test(self):
        source, receiver = self.nodes

        self.generate(source, 99)
        self.disconnect_nodes(0, 1)
        [block_hash] = self.generate(source, 1, sync_fun=self.no_op)
        block = from_hex(CBlock(), source.getblock(block_hash, 0))
        block.rehash()

        peer = receiver.add_p2p_connection(P2PInterface())
        peer.send_message(msg_headers(headers=[CBlockHeader(block)]))
        peer.wait_for_getdata([block.sha256], timeout=30)

        # ENC-DR forbids body-carried sketch words. The payload is not header
        # committed, so appending one keeps the same block hash and is rejected
        # contextually without needing the expensive digest recomputation.
        # Repeat it to model a relayer replaying cheaply noncanonical bodies.
        malformed = CBlockWithForbiddenSketch(block)
        malformed.vtx = block.vtx
        assert_equal(malformed.sha256, block.sha256)

        expected = ["validated block does not require recomputation"] * 3
        with receiver.assert_debug_log(expected_msgs=expected):
            for _ in range(3):
                peer.send_message(msg_block(malformed))
                # Local test peers tolerate the mutation DoS score. A ping
                # gives validation/punishment and its no-recompute admission
                # log time to complete before the next relay.
                peer.sync_with_ping(timeout=30)
                assert peer.is_connected

        # BLOCK_MUTATED bodies are deliberately not cached as permanent header
        # failures. The canonical empty body with the same header must still
        # enter the one-slot exact path and become the active tip.
        peer.send_message(msg_block(block))
        receiver.wait_until(lambda: receiver.getbestblockhash() == block_hash, timeout=120)
        assert_equal(receiver.getblockcount(), 100)
        assert peer.is_connected


if __name__ == "__main__":
    BTXMatMulAdmissionPrecheckTest(__file__).main()
