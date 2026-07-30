#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit-license.php.
"""A complete compact block consumes exactly one MatMul verification slot."""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    HeaderAndShortIDs,
    MSG_CMPCT_BLOCK,
    from_hex,
    msg_cmpctblock,
    msg_headers,
    msg_sendcmpct,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMulCompactAdmissionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Phase A keeps the fixture cheap. A one-job LT cap makes the former
        # double reservation deterministic: CMPCTBLOCK occupied the only slot,
        # then the zero-missing BLOCKTXN shim tried to reserve another and
        # silently deferred the otherwise-valid block.
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

        # Share the pre-activation chain, then create the first LT block only
        # on the source so the receiver must validate the compact delivery.
        self.generate(source, 99)
        self.disconnect_nodes(0, 1)
        [block_hash] = self.generate(source, 1, sync_fun=self.no_op)
        block = from_hex(CBlock(), source.getblock(block_hash, 0))
        block.rehash()

        compact = HeaderAndShortIDs()
        compact.initialize_from_block(
            block,
            prefill_list=list(range(len(block.vtx))),
            use_witness=True,
        )

        peer = receiver.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
        # Put the block in flight as a requested compact block. An unsolicited
        # CMPCTBLOCK may correctly fall back to a full GETDATA before attempting
        # optimistic reconstruction, which would not exercise this boundary.
        peer.send_message(msg_headers(headers=[CBlockHeader(block)]))
        peer.wait_for_getdata([block.sha256], timeout=30)
        with p2p_lock:
            assert_equal(peer.last_message["getdata"].inv[0].type, MSG_CMPCT_BLOCK)
        peer.send_message(msg_cmpctblock(compact.to_p2p()))
        receiver.wait_until(
            lambda: receiver.getbestblockhash() == block_hash,
            timeout=120,
        )
        assert_equal(receiver.getblockcount(), 100)
        with p2p_lock:
            assert "getblocktxn" not in peer.last_message
        assert peer.is_connected


if __name__ == "__main__":
    BTXMatMulCompactAdmissionTest(__file__).main()
