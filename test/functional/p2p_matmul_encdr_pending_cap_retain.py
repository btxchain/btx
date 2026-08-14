#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""EncDr pending-cap miss retains a followed-chain body (no HEADER_ONLY drop).

Legacy EncDr admission disconnected the delivering peer and HEADER_ONLY-dropped
the body when nMatMulMaxPendingVerifications was exhausted. That discarded a
body that already paid bandwidth and re-opened unbounded getdata. Profile-1 RC
already RETAIN_FOR_RETRY'd; EncDr now matches that invariant.

This test:
  - exhausts the EncDr pending cap on a followed-chain body
  - requires the honest peer to stay connected
  - bounds getdata per hash well below the live livelock (150–301)
  - keeps competing EncDr siblings HEADER_ONLY on a local signer (miner GPU)
  - re-checks the RC cap path still defers without disconnect
"""

import collections
import re
import time

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    from_hex,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from test_framework.wallet_util import generate_keypair


V4_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
MAX_REQUESTS_PER_HASH = 20
REQUESTING_BLOCK_RE = re.compile(
    r"Requesting block ([0-9a-f]{64})(?: \(\d+\))? from\s+peer=\d+"
)


def encdr_args(extra=None, *, receiver=False):
    args = [
        "-test=matmulstrict",
        "-debug=net",
        "-matmulasyncverify=1",
        "-regtestmatmulbindingheight=2",
        "-regtestmatmulproductdigestheight=2",
        "-regtestmatmulrequireproductpayload=0",
        f"-regtestmatmulv4height={V4_HEIGHT}",
        f"-regtestbmx4cheight={V4_HEIGHT}",
        f"-regtestdrltheight={DISABLED_HEIGHT}",
        f"-regtestrcheight={DISABLED_HEIGHT}",
        f"-regtestrccoupledheight={DISABLED_HEIGHT}",
        "-regtestmatmulltsealaspow=0",
        "-regtestmatmulv4dimension=64",
    ]
    if receiver:
        # Stay in IBD so HEADERS skip the EncDr pending-slot reservation, and
        # force every ExactReplay body through RETAIN_FOR_RETRY. A full cap
        # no longer disconnects an honest header source; IBD still keeps
        # header accounting off the ExactReplay cap.
        args += ["-regtestmatmulmaxpending=0", "-minimumchainwork=0x1000"]
    if extra:
        args.extend(extra)
    return args


def rc_args(extra=None, *, receiver=False):
    args = [
        "-test=matmulstrict",
        "-debug=net",
        "-matmulasyncverify=1",
        "-regtestmatmulbindingheight=2",
        "-regtestmatmulproductdigestheight=2",
        "-regtestmatmulrequireproductpayload=0",
        f"-regtestmatmulv4height={V4_HEIGHT}",
        f"-regtestbmx4cheight={V4_HEIGHT}",
        f"-regtestdrltheight={DISABLED_HEIGHT}",
        f"-regtestrcheight={V4_HEIGHT}",
        f"-regtestrccoupledheight={DISABLED_HEIGHT}",
        "-regtestrcprofile=1",
        "-regtestrctoydims=1",
        "-regtestmatmulltsealaspow=0",
        "-regtestmatmulv4dimension=64",
    ]
    if receiver:
        args += ["-regtestrcmaxpending=0", "-minimumchainwork=0x1000"]
    if extra:
        args.extend(extra)
    return args


def count_requests(log_text, hashes):
    wanted = set(hashes)
    counts = collections.Counter()
    for match in REQUESTING_BLOCK_RE.finditer(log_text):
        block_hash = match.group(1)
        if block_hash in wanted:
            counts[block_hash] += 1
    return counts


class MatMulEncDrPendingCapRetainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        self.signer_wif = signer_wif
        self.signer_pub = signer_pub.hex()
        source = encdr_args()
        receiver = encdr_args(receiver=True)
        miner = encdr_args(
            extra=[
                "-matmulvalidation=consensus",
                f"-matmultrustedpubkey={self.signer_pub}",
                "-matmultrustedthreshold=1",
                f"-matmulattestationsignerkey={self.signer_wif}",
                "-matmulattestationserve=0",
            ]
        )
        rc_source = rc_args()
        rc_receiver = rc_args(receiver=True)
        self.extra_args = [source, receiver, miner, rc_source, rc_receiver]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(3, 4)

    def _deliver_followed_bodies(self, source, receiver, hashes):
        blocks = []
        for block_hash in hashes:
            block = from_hex(CBlock(), source.getblock(block_hash, 0))
            block.rehash()
            blocks.append(block)

        peer = receiver.add_p2p_connection(P2PInterface())
        log_start = receiver.debug_log_size(encoding="utf-8")
        with receiver.assert_debug_log(
            expected_msgs=[
                "Deferring peer=",
                "MatMul pending verification cap reached",
                "Stored budget-deferred body",
            ],
        ):
            for block in blocks:
                peer.send_message(msg_headers(headers=[CBlockHeader(block)]))
                peer.wait_for_getdata([block.sha256], timeout=30)
                peer.send_message(msg_block(block))
                assert peer.is_connected
            peer.sync_with_ping(timeout=30)
        assert peer.is_connected
        # Skip-fetch must hold across a few scheduler/send cycles. Do not wait
        # long enough for a HEADER_ONLY livelock (150–301) to look green.
        time.sleep(3)
        with open(receiver.debug_log_path, encoding="utf-8", errors="replace") as dl:
            dl.seek(log_start)
            log_text = dl.read()
        hex_hashes = [block.hash for block in blocks]
        counts = count_requests(log_text, hex_hashes)
        for block_hash in hex_hashes:
            n = counts.get(block_hash, 0)
            assert n < MAX_REQUESTS_PER_HASH, (
                f"{block_hash} requested {n} times "
                f"(limit {MAX_REQUESTS_PER_HASH}); unbounded HEADER_ONLY re-getdata"
            )
            assert_greater_than(n, 0)
        # Header is indexed; body is retained (cap=0 never ExactReplays).
        for block_hash in hashes:
            header = receiver.getblockheader(block_hash)
            assert_equal(header["confirmations"], -1)
        peer.peer_disconnect()
        peer.wait_for_disconnect()

    def _test_encdr_pending_cap_retain(self):
        source, receiver, miner = self.nodes[0], self.nodes[1], self.nodes[2]
        self.log.info("Mine the pre-EncDr prefix onto source, receiver, and miner")
        self.generate(source, V4_HEIGHT - 1)
        self.sync_blocks(self.nodes[:3])
        self.split_parent = miner.getbestblockhash()
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)

        self.log.info("Mine a followed-chain EncDr body on the source only")
        self.encdr_source_child = self.generate(source, 1, sync_fun=self.no_op)[0]
        self._deliver_followed_bodies(source, receiver, [self.encdr_source_child])

    def _test_competing_sibling_skips_miner_gpu(self):
        source, miner = self.nodes[0], self.nodes[2]
        self.log.info("Local-signer miner mines its own EncDr child of the shared parent")
        [miner_child] = self.generate(miner, 1, sync_fun=self.no_op)
        assert miner_child != self.encdr_source_child
        assert_equal(miner.getblockheader(miner_child)["previousblockhash"], self.split_parent)
        assert_equal(
            source.getblockheader(self.encdr_source_child)["previousblockhash"],
            self.split_parent,
        )

        competing = from_hex(CBlock(), source.getblock(self.encdr_source_child, 0))
        competing.rehash()
        peer = miner.add_p2p_connection(P2PInterface())
        with miner.assert_debug_log(
            expected_msgs=[
                "skipped ExactReplay GPU (competing near-tip P2P sibling",
            ],
            unexpected_msgs=[
                "Stored budget-deferred body",
                "MatMul pending verification cap reached",
            ],
        ):
            peer.send_message(msg_headers(headers=[CBlockHeader(competing)]))
            peer.send_message(msg_block(competing))
            peer.sync_with_ping(timeout=30)
        assert peer.is_connected
        assert_equal(miner.getbestblockhash(), miner_child)
        peer.peer_disconnect()
        peer.wait_for_disconnect()

    def _test_rc_pending_cap_still_retains(self):
        source, receiver = self.nodes[3], self.nodes[4]
        self.log.info("Mine the pre-RC prefix and exhaust the RC pending cap")
        self.generate(source, V4_HEIGHT - 1)
        self.sync_blocks(self.nodes[3:5])
        self.disconnect_nodes(3, 4)
        hashes = self.generate(source, 1, sync_fun=self.no_op)
        self._deliver_followed_bodies(source, receiver, hashes)

    def run_test(self):
        self._test_encdr_pending_cap_retain()
        self._test_competing_sibling_skips_miner_gpu()
        self._test_rc_pending_cap_still_retains()


if __name__ == "__main__":
    MatMulEncDrPendingCapRetainTest(__file__).main()
