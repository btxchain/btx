#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Trusted mirror: selection runs again when the stall window opens.

The mirror holds the heavier branch's headers, attestations, and bodies
before -reorgstallseconds elapses. No later submitblock is sent. The
recovery worker must activate that branch once the window arms.

The topology is the one in feature_matmul_trusted_mirror_convergence.py.
"""

import threading
import time

from test_framework.authproxy import AuthServiceProxy
from test_framework.messages import (
    CBlockHeader,
    NODE_MATMUL_CONSENSUS,
    NODE_NETWORK,
    NODE_WITNESS,
    from_hex,
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
REORG_PROTECTION_START = 5
NORMAL_DEPTH = 6
LOSING_LEN = NORMAL_DEPTH + 1
WINNING_LEN = LOSING_LEN + 5
NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31
ARCHIVE_SERVICES = (
    NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE
)
# A no-progress park must return promptly (well under a second when fixed).
# The unfixed selector never returns, and logs heavily while it loops.
SUBMIT_TIMEOUT = 10
TRUST_WARNING = (
    "Warning: TRUSTED MATMUL MIRROR ACTIVE: this node delegates Profile-1 "
    "ExactReplay to a configured threshold of 1 signer(s). It validates "
    "block bodies and scripts but is not an independent full consensus "
    "validator."
)
INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


class MatMulTrustedMirrorBoundedStallOpenTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
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
            f"-matmultrustedpubkey={signer_pub.hex()}",
            "-matmultrustedthreshold=1",
            "-matmultrustedwaitms=30000",
            f"-regtestreorgprotectionstartheight={REORG_PROTECTION_START}",
            "-reorgprotectionprofile=emergency",
            "-parkdeepreorg=1",
            f"-maxreorgdepthpark={NORMAL_DEPTH}",
            "-checkblockindex=1",
            # Do not start btx-modeld. A sibling helper would fight the default PQ1 port.
            "-modelnet=0",
        ]
        archive = common + [
            "-reorgpolicy=legacy",
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]
        mirror = common + [
            "-reorgpolicy=bounded",
            f"-reorgnormaldepth={NORMAL_DEPTH}",
            "-reorgrecoverymaxdepth=72",
            "-reorgstallseconds=45",
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
        ]
        # node0 = authority (winning branch), node1 = mirror, node2 = loser
        # (same signer, so the mirror can follow the losing branch first).
        self.extra_args = [archive, mirror, archive]

    def setup_network(self):
        self.setup_nodes()

    def _disconnect_all(self):
        for i in range(self.num_nodes):
            for j in range(i + 1, self.num_nodes):
                try:
                    self.disconnect_nodes(i, j)
                except Exception:
                    pass

    def _rejected_reorgs(self, node):
        return node.getdifficultyhealth(5)["reorg_protection"]["rejected_reorgs"]

    def _submit_with_timeout(self, node, raw, timeout):
        """submitblock on its own connection; returns (finished, result_or_error)."""
        box = {}

        def run():
            try:
                box["result"] = AuthServiceProxy(node.url, timeout=timeout + 30).submitblock(raw)
            except Exception as exc:  # surfaced through the assertion below
                box["result"] = f"{type(exc).__name__}: {exc}"

        th = threading.Thread(target=run, daemon=True)
        th.start()
        th.join(timeout)
        return (not th.is_alive()), box.get("result")

    def _push_headers_and_attestations(self, authority, mirror, fork_hash, tip_hash):
        hashes = []
        blockhash = tip_hash
        while blockhash != fork_hash:
            hashes.append(blockhash)
            blockhash = authority.getblockheader(blockhash, True)["previousblockhash"]
        hashes.reverse()
        headers = [from_hex(CBlockHeader(), authority.getblockheader(h, False)) for h in hashes]
        mirror_height = mirror.getblockcount()
        proof_pos = next(i for i, h in enumerate(hashes)
                         if authority.getblockheader(h)["height"] >= mirror_height)
        peer = mirror.add_p2p_connection(P2PInterface(), services=ARCHIVE_SERVICES)
        peer.send_and_ping(msg_headers(headers=headers[: proof_pos + 1]))
        proof_atts = authority.getmatmulattestations(hashes[proof_pos])
        peer.send_and_ping(msg_generic(
            b"mmattest", ser_compact_size(len(proof_atts))
            + b"".join(bytes.fromhex(a) for a in proof_atts)))
        if proof_pos + 1 < len(headers):
            peer.send_and_ping(msg_headers(headers=headers[proof_pos + 1:]))
        remaining = []
        for i, h in enumerate(hashes):
            if i != proof_pos:
                remaining.extend(bytes.fromhex(a) for a in authority.getmatmulattestations(h))
        for i in range(0, len(remaining), 16):
            batch = remaining[i:i + 16]
            peer.send_and_ping(msg_generic(b"mmattest", ser_compact_size(len(batch)) + b"".join(batch)))
        peer.peer_disconnect()
        mirror.disconnect_p2ps()
        return hashes

    def run_test(self):
        try:
            self._run()
        except AssertionError:
            # Stop cleanly before the framework's failure cleanup: RPC stop
            # interrupts a reselecting activation within about a second.
            for node in self.nodes:
                try:
                    AuthServiceProxy(node.url, timeout=15).stop()
                except Exception:
                    pass
            expected = [INLINE_SIGNER_WARNING, TRUST_WARNING, INLINE_SIGNER_WARNING]
            for node, stderr in zip(self.nodes, expected):
                try:
                    node.wait_until_stopped(timeout=60, expected_stderr=stderr)
                except Exception:
                    pass
            raise

    def _run(self):
        authority, mirror, loser = self.nodes

        self.log.info("Shared chain through Profile-1 activation")
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        fork_height = ACTIVATION_HEIGHT + 2
        self.generate(authority, fork_height, sync_fun=self.no_op)
        self.wait_until(lambda: mirror.getbestblockhash() == authority.getbestblockhash()
                        and loser.getbestblockhash() == authority.getbestblockhash(), timeout=300)
        fork_hash = authority.getbestblockhash()
        self._disconnect_all()

        self.log.info(f"Partition: losing branch of {LOSING_LEN}, winning branch of {WINNING_LEN}")
        fork_child = self.generate(authority, 1, sync_fun=self.no_op)[0]
        losing = self.generate(loser, LOSING_LEN, sync_fun=self.no_op)
        self.generate(authority, WINNING_LEN - 1, sync_fun=self.no_op)
        winning_tip = authority.getbestblockhash()

        self.log.info("Mirror follows the losing branch")
        self.connect_nodes(1, 2)
        self.wait_until(lambda: mirror.getbestblockhash() == losing[-1], timeout=300)
        self.disconnect_nodes(1, 2)
        assert_equal(mirror.getblockcount() - fork_height, LOSING_LEN)

        self.log.info("Winning headers and attestations, no bodies")
        winning = self._push_headers_and_attestations(authority, mirror, fork_hash, winning_tip)
        assert_equal(winning[0], fork_child)
        self.wait_until(lambda: mirror.getblockchaininfo()["headers"] >= fork_height + WINNING_LEN,
                        timeout=180)
        assert_equal(mirror.getbestblockhash(), losing[-1])

        self.log.info("All winning bodies, while the stall window is still closed")
        for blockhash in winning:
            finished, result = self._submit_with_timeout(
                mirror, authority.getblock(blockhash, False), SUBMIT_TIMEOUT)
            assert finished, f"submitblock {blockhash} did not return: {result}"
        status = mirror.getreorgrecoverystatus()
        assert not status["stall_armed"], (
            f"stall already armed at age {status['progress_age_s']}s; "
            "the window closed before the bodies were all submitted")
        assert_equal(mirror.getbestblockhash(), losing[-1])

        self.log.info("No further submit: the open window must re-run selection")
        self.wait_until(lambda: mirror.getbestblockhash() == winning_tip, timeout=60)
        assert_greater_than(mirror.getblockcount(), fork_height + LOSING_LEN)

        self.stop_node(1, expected_stderr=TRUST_WARNING)
        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(2, expected_stderr=INLINE_SIGNER_WARNING)


if __name__ == "__main__":
    MatMulTrustedMirrorBoundedStallOpenTest(__file__).main()
