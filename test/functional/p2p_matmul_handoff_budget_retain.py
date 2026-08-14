#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Competing near-tip sibling stays HEADER_ONLY; getdata stays bounded.

Handoff peer-budget miss retain/skip-fetch is covered by peerman_tests
(handoff_peer_budget_miss_retains_tip_child_body) because live RC on
regtest unthrottles nMatMulRCPeerVerifyBudgetPerMin. This functional
lock is the signer/mirror competing-sibling policy: do not steal miner
GPU, do not re-getdata until the tip moves, and do not disconnect the
honest peer (DoS-F2 shape).
"""

import re

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    from_hex,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
MAX_REQUESTS_PER_HASH = 20
REQUESTING_BLOCK_RE = re.compile(
    r"Requesting block ([0-9a-f]{64})(?: \(\d+\))? from\s+peer=\d+"
)


class MatMulHandoffBudgetRetainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        self.signer_pub = signer_pub.hex()
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            "-debug=net",
            "-regtestmatmulbindingheight=2",
            "-regtestmatmulproductdigestheight=2",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={ACTIVATION_HEIGHT}",
            f"-regtestbmx4cheight={ACTIVATION_HEIGHT}",
            f"-regtestdrltheight={DISABLED_HEIGHT}",
            f"-regtestrcheight={ACTIVATION_HEIGHT}",
            f"-regtestrccoupledheight={DISABLED_HEIGHT}",
            "-regtestrcprofile=1",
            "-regtestrctoydims=1",
            "-regtestmatmulltsealaspow=0",
            "-regtestmatmulv4dimension=128",
            f"-matmultrustedpubkey={self.signer_pub}",
            "-matmultrustedthreshold=1",
            "-matmultrustedwaitms=30000",
        ]
        self.extra_args = [
            common
            + [
                "-matmulvalidation=consensus",
                f"-matmulattestationsignerkey={signer_wif}",
                "-matmulattestationserve=1",
            ],
            common
            + [
                "-matmulvalidation=trusted",
                "-matmulattestationserve=0",
            ],
        ]

    def run_test(self):
        archive, mirror = self.nodes
        self.generate(archive, ACTIVATION_HEIGHT + 2)
        self.sync_blocks()
        tip_hash = archive.getbestblockhash()
        self.disconnect_nodes(0, 1)

        competing_hash = self.generate(archive, 1, sync_fun=self.no_op)[0]
        competing_hex = archive.getblock(competing_hash, 0)
        archive.invalidateblock(competing_hash)
        followed_hash = self.generate(archive, 1, sync_fun=self.no_op)[0]
        assert followed_hash != competing_hash
        assert_equal(archive.getbestblockhash(), followed_hash)

        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(mirror.getbestblockhash(), followed_hash)

        competing_block = from_hex(CBlock(), competing_hex)
        competing_block.rehash()
        peer = mirror.add_p2p_connection(P2PInterface())
        peer.send_message(msg_headers(headers=[CBlockHeader(competing_block)]))
        peer.sync_with_ping(timeout=20)
        peer.send_message(msg_block(competing_block))
        peer.sync_with_ping(timeout=20)

        tips = {tip["hash"]: tip for tip in mirror.getchaintips()}
        assert competing_hash in tips
        assert_equal(tips[competing_hash]["status"], "headers-only")
        assert peer.is_connected

        for _ in range(8):
            peer.sync_with_ping(timeout=20)
        assert peer.is_connected
        assert_equal(mirror.getbestblockhash(), followed_hash)

        log_path = mirror.debug_log_path
        with open(log_path, "r", encoding="utf-8") as log_file:
            log_text = log_file.read()
        requests = REQUESTING_BLOCK_RE.findall(log_text)
        competing_requests = sum(1 for h in requests if h == competing_hash)
        assert_greater_than(MAX_REQUESTS_PER_HASH, competing_requests)

        self.stop_node(
            0,
            expected_stderr=(
                "Warning: -matmulattestationsignerkey exposes an online signing key "
                "through process/config surfaces; use a permission-restricted "
                "-matmulattestationsignerkeyfile."
            ),
        )
        self.stop_node(
            1,
            expected_stderr=(
                "Warning: TRUSTED MATMUL MIRROR ACTIVE: this node delegates Profile-1 "
                "ExactReplay to a configured threshold of 1 signer(s). It validates "
                "block bodies and scripts but is not an independent full consensus "
                "validator."
            ),
        )


if __name__ == "__main__":
    MatMulHandoffBudgetRetainTest(__file__).main()
