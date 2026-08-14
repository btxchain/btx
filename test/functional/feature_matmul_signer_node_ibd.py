#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A consensus node that holds a signing key must still sync from the network.

This is the production Authority's role: -matmulvalidation=consensus with a
local attestation signing key. It mines and signs, but it must also follow the
chain like any other node. If it cannot complete initial block download, it
cannot be an authority for anything.

The admission path treats a local signer's inbound P2P bodies as competing
work, so they are dropped HEADER_ONLY to leave the device free for candidate
mining. Two of the persist escapes do not cover a syncing signer:

  - persist_unattested_tip_child was gated on IsTrustedMirror()
  - MatMulFollowedHistoricalHole needs the block to be at or below the active
    tip's height, which is never true for the next block in IBD

so the body is dropped, and nothing else brings it back. On 1eb8caf3
m_header_only_competing then suppressed re-getdata until a tip move that
needs the suppressed body — a quiet stall at height 0.

  S1 peer      the signer node has a peer and learns the chain's headers
  S2 sync      it reaches the producer's tip
  S3 bounded   it does not spin while failing to do so

S2 is the assertion. S1 exists so a networking failure cannot masquerade as a
sync failure.

CheckBlockIndex stays on (-checkblockindex=1). Do not disable it.
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
CHAIN_HEIGHT = ACTIVATION_HEIGHT + 4

MAX_NODE_LOG_BYTES = 64 * 1024 * 1024
# A node that cannot fetch anything logs this on every scheduler pass. It is a
# spin, not progress.
STALL_MARKER = "no_fetchable_in_window"
MAX_STALL_LINES = 500

INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


class MatMulSignerNodeIbdTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        self.signer_wif = signer_wif
        self.signer_pub = signer_pub.hex()
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
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
            "-regtestrccoupledtoydims=0",
            "-regtestmatmulltsealaspow=0",
            "-regtestmatmulv4dimension=128",
            f"-matmultrustedpubkey={self.signer_pub}",
            "-matmultrustedthreshold=1",
            "-matmultrustedwaitms=30000",
            "-checkblockindex=1",
            "-debug=net",
            "-debug=validation",
        ]
        # Both nodes are configured exactly like the production Authority:
        # consensus validation plus a local signing key, serving attestations.
        producer = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]
        follower = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]
        self.extra_args = [producer, follower]

    def setup_network(self):
        self.setup_nodes()

    def _log_path(self, n=1):
        return os.path.join(self.nodes[n].datadir_path, self.chain, "debug.log")

    def _log_size(self, n=1):
        try:
            return os.path.getsize(self._log_path(n))
        except OSError:
            return 0

    def _count_marker(self, marker, n=1):
        count = 0
        try:
            with open(self._log_path(n), "r", encoding="utf-8",
                      errors="replace") as handle:
                read = 0
                for line in handle:
                    read += len(line)
                    if read > MAX_NODE_LOG_BYTES:
                        break
                    if marker in line:
                        count += 1
        except OSError:
            pass
        return count

    def _wait_bounded(self, predicate, what, timeout):
        follower = self.nodes[1]
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            if self._log_size() > MAX_NODE_LOG_BYTES:
                raise AssertionError(
                    f"{what}: follower debug.log exceeded "
                    f"{MAX_NODE_LOG_BYTES // (1024 * 1024)} MiB "
                    f"(blocks={follower.getblockcount()})"
                )
            time.sleep(0.5)
        return False

    def run_test(self):
        producer, follower = self.nodes

        self.log.info("S1: connect the signer follower to the producer")
        self.connect_nodes(1, 0)
        peered = self._wait_bounded(
            lambda: len(follower.getpeerinfo()) >= 1,
            "S1 follower has a peer",
            timeout=60 * self.options.timeout_factor,
        )
        assert peered, "the follower never established a peer connection"

        self.log.info(f"Produce {CHAIN_HEIGHT} blocks across activation "
                      f"{ACTIVATION_HEIGHT}")
        self.generate(producer, CHAIN_HEIGHT, sync_fun=self.no_op)
        producer_tip = producer.getbestblockhash()
        assert_equal(producer.getblockcount(), CHAIN_HEIGHT)

        # Headers must arrive even if bodies do not; this separates a
        # networking failure from an admission failure.
        got_headers = self._wait_bounded(
            lambda: follower.getblockchaininfo()["headers"] >= CHAIN_HEIGHT,
            "S1 follower learns the headers",
            timeout=180 * self.options.timeout_factor,
        )
        info = follower.getblockchaininfo()
        assert got_headers, (
            f"the follower never received headers (headers="
            f"{info['headers']}, peers={len(follower.getpeerinfo())}); this is "
            f"a networking failure, not an admission failure"
        )
        self.log.info(f"S1 headers={info['headers']} blocks={info['blocks']}")

        # S2: the assertion.
        self.log.info("S2: the signer follower must reach the producer's tip")
        synced = self._wait_bounded(
            lambda: follower.getbestblockhash() == producer_tip,
            "S2 follower syncs",
            timeout=300 * self.options.timeout_factor,
        )
        if not synced:
            info = follower.getblockchaininfo()
            stalls = self._count_marker(STALL_MARKER)
            raise AssertionError(
                f"a consensus node with a local signing key did not complete "
                f"IBD. It has {len(follower.getpeerinfo())} peer(s) and "
                f"{info['headers']} headers, but its tip is still "
                f"{info['blocks']} ({follower.getbestblockhash()[:16]}) after "
                f"300s; the producer is at {CHAIN_HEIGHT} "
                f"({producer_tip[:16]}). '{STALL_MARKER}' appears {stalls} "
                f"times, so the download scheduler is running and finding "
                f"nothing it is allowed to fetch. The Authority role cannot "
                f"follow the chain in this state."
            )
        assert_equal(follower.getblockcount(), CHAIN_HEIGHT)
        self.log.info(f"S2 follower synced to {follower.getblockcount()}")

        # S3: and it must not have spun to get there.
        stalls = self._count_marker(STALL_MARKER)
        log_mib = self._log_size() / (1024 * 1024)
        self.log.info(
            f"S3 {STALL_MARKER}={stalls} follower debug.log={log_mib:.1f} MiB"
        )
        assert_greater_than_or_equal(MAX_STALL_LINES, stalls)
        assert_greater_than_or_equal(MAX_NODE_LOG_BYTES, self._log_size())

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=INLINE_SIGNER_WARNING)


if __name__ == "__main__":
    MatMulSignerNodeIbdTest(__file__).main()
