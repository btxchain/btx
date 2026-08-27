#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""An authority-mode node (local signer) must serve headers to ANY peer.

Regression test for the 0.34.1 release blocker measured 2026-08-27 on the
BTX main network: a node with a local attestation signer dispatched inbound
messages only for peers advertising MATMUL_TRUSTED_MIRROR or
MATMUL_ATTESTATION_ARCHIVE. SkipMinerProcessMessagesDuringArchiveGetData
discarded its archive_getdata_pending argument, turning a "yield while an
archive fetch is pending" into an unconditional skip of every fully
handshaked non-archive peer, so plain MATMUL_CONSENSUS peers and peers with
no matmul service bits received ZERO header bytes (getpeerinfo:
recv.getheaders > 0, sent.headers == 0). A fresh community node could not
bootstrap, synced_headers stayed -1 network-wide, and the mining chain
guard blocked block production with insufficient_peer_consensus.

Serving headers is a read: authority rules govern which BODIES a node
TRUSTS, never who may ask it questions.

Asserts by received messages and getpeerinfo byte counters, never by
debug.log strings (LogDebug lines are invisible without -debug=net).
"""

from test_framework.messages import (
    NODE_NETWORK,
    NODE_WITNESS,
    msg_getheaders,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.wallet_util import generate_keypair

CHAIN_HEIGHT = 10

INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


class AuthorityServesHeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        # Configured exactly like the production Authority: consensus
        # validation plus a local attestation signing key.
        self.extra_args = [[
            "-matmulvalidation=consensus",
            f"-matmultrustedpubkey={signer_pub.hex()}",
            "-matmultrustedthreshold=1",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]]

    def assert_headers_served(self, services, label):
        node = self.nodes[0]
        tip = int(node.getbestblockhash(), 16)
        genesis = int(node.getblockhash(0), 16)

        kwargs = {} if services is None else {"services": services}
        peer = node.add_p2p_connection(P2PInterface(), **kwargs)

        req = msg_getheaders()
        req.locator.vHave = [genesis]
        req.hashstop = 0
        peer.send_message(req)

        # A non-empty HEADERS message must arrive, ending at the tip.
        peer.wait_until(
            lambda: peer.last_message.get("headers") is not None
            and len(peer.last_message["headers"].headers) > 0,
            timeout=30,
        )
        headers = peer.last_message["headers"].headers
        assert_greater_than(len(headers), 0)
        assert_equal(headers[-1].rehash(), tip)
        assert_equal(len(headers), CHAIN_HEIGHT)

        # Cross-check with the same counters used to measure the live bug.
        info = node.getpeerinfo()[-1]
        assert_greater_than(
            info["bytesrecv_per_msg"].get("getheaders", 0), 0)
        assert_greater_than(
            info["bytessent_per_msg"].get("headers", 0), 0)

        self.log.info(
            "%s: served %d headers, sent.headers=%d bytes",
            label, len(headers), info["bytessent_per_msg"]["headers"])
        node.disconnect_p2ps()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, CHAIN_HEIGHT)
        assert_equal(node.getmatmultrustedstatus()["local_signer"], True)

        # An inbound peer with NO matmul service bits and NO permissions.
        self.assert_headers_served(
            NODE_NETWORK | NODE_WITNESS, "no-matmul-bits peer")
        # An inbound peer with only MATMUL_CONSENSUS (the framework
        # default services) and NO permissions.
        self.assert_headers_served(None, "consensus-only peer")

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)


if __name__ == "__main__":
    AuthorityServesHeadersTest(__file__).main()
