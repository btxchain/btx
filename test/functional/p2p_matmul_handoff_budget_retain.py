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
    msg_generic,
    msg_headers,
    ser_compact_size,
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
        self.num_nodes = 3
        self.setup_clean_chain = True
        archive_wif, archive_pub = generate_keypair(wif=True)
        competitor_wif, competitor_pub = generate_keypair(wif=True)
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
            f"-matmultrustedpubkey={archive_pub.hex()}",
            f"-matmultrustedpubkey={competitor_pub.hex()}",
            "-matmultrustedthreshold=1",
            "-matmultrustedwaitms=30000",
        ]
        self.extra_args = [
            common
            + [
                "-matmulvalidation=consensus",
                f"-matmulattestationsignerkey={archive_wif}",
                "-matmulattestationserve=1",
            ],
            common
            + [
                "-matmulvalidation=trusted",
                "-matmulattestationserve=0",
            ],
            common
            + [
                "-matmulvalidation=consensus",
                f"-matmulattestationsignerkey={competitor_wif}",
                "-matmulattestationserve=1",
            ],
        ]

    def run_test(self):
        archive, mirror, competitor = self.nodes
        self.generate(archive, ACTIVATION_HEIGHT + 2)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)

        competing_hash = self.generate(competitor, 1, sync_fun=self.no_op)[0]
        competing_hex = competitor.getblock(competing_hash, 0)
        competing_atts = competitor.getmatmulattestations(competing_hash)
        assert_greater_than(len(competing_atts), 0)
        followed_hash = self.generate(archive, 1, sync_fun=self.no_op)[0]
        assert followed_hash != competing_hash
        assert_equal(archive.getbestblockhash(), followed_hash)

        self.connect_nodes(1, 0)
        self.sync_blocks(nodes=(archive, mirror))
        assert_equal(mirror.getbestblockhash(), followed_hash)

        competing_block = from_hex(CBlock(), competing_hex)
        competing_block.rehash()
        followed_header = from_hex(
            CBlockHeader(), archive.getblockheader(followed_hash, False)
        )
        peer = mirror.add_p2p_connection(P2PInterface())
        # A valid public attestation must not become a reusable peer-wide
        # HEADERS capability. An unrelated first response consumes the grant;
        # the signed target sent afterward on the same connection stays out of
        # the index.
        peer.send_and_ping(
            msg_generic(
                b"mmattest",
                ser_compact_size(len(competing_atts))
                + b"".join(bytes.fromhex(att) for att in competing_atts),
            )
        )
        peer.send_and_ping(msg_headers(headers=[followed_header]))
        peer.send_message(msg_headers(headers=[CBlockHeader(competing_block)]))
        peer.sync_with_ping(timeout=20)
        tips = {tip["hash"]: tip for tip in mirror.getchaintips()}
        assert competing_hash not in tips
        peer.peer_disconnect()
        mirror.disconnect_p2ps()

        # A fresh exact-stop request on a new peer authorizes precisely one
        # contiguous response ending at the signed hash. It still does not
        # authorize a BLOCK body from that inbound peer.
        peer = mirror.add_p2p_connection(P2PInterface())
        peer.send_and_ping(
            msg_generic(
                b"mmattest",
                ser_compact_size(len(competing_atts))
                + b"".join(bytes.fromhex(att) for att in competing_atts),
            )
        )
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
        self.stop_node(
            2,
            expected_stderr=(
                "Warning: -matmulattestationsignerkey exposes an online signing key "
                "through process/config surfaces; use a permission-restricted "
                "-matmulattestationsignerkeyfile."
            ),
        )


if __name__ == "__main__":
    MatMulHandoffBudgetRetainTest(__file__).main()
