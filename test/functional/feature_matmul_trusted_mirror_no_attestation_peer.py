#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Trusted mirror with no attestation-serving peer says so in the log.

After loadtxoutsetattested a trusted mirror needs a signer quorum for every
block above the snapshot. If its only peers run -matmulattestationserve=0 it
sits at the snapshot height. That is expected, but nothing in the log named the
cause: the periodic "matmul trusted mirror stall" warning reports slots and
counters only. The mirror now logs a rate-limited warning naming the cause, and
stays quiet once a serving peer is connected.

node0: consensus signer, serves attestations.
node1: fresh trusted mirror that loads the snapshot.
node2: trusted mirror with -matmulattestationserve=0 that follows node0.
"""

import shutil
import time

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
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
)
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
SNAPSHOT_HEIGHT = ACTIVATION_HEIGHT + 4
BLOCKS_AFTER_SNAPSHOT = 5

# NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31 (src/protocol.h).
NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31
ARCHIVE_SERVICES = (
    NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_CONSENSUS | NODE_MATMUL_ATTESTATION_ARCHIVE
)
NO_PEER_MSG = "matmul trusted mirror: no attestation-serving peer connected"
# CheckForStaleTipAndEvictPeers runs every 45 s; the warning needs a 60 s grace.
SCHEDULER_STEP = 50

TRUST_WARNING = (
    "Warning: TRUSTED MATMUL MIRROR ACTIVE: this node delegates Profile-1 "
    "ExactReplay to a configured threshold of {} signer(s). It validates "
    "block bodies and scripts but is not an independent full consensus "
    "validator."
)
INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


class MatMulTrustedMirrorNoAttestationPeerTest(BitcoinTestFramework):
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
            "-checkblockindex=1",
            "-modelnet=0",
        ]
        archive = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]
        mirror = common + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
        ]
        self.extra_args = [archive, mirror, mirror]

    def setup_network(self):
        self.setup_nodes()
        # node1 stays isolated until it has loaded the snapshot. Mirrors
        # dial the archive, as real mirrors do.
        self.connect_nodes(2, 0)

    def sync_0_2(self):
        self.sync_blocks([self.nodes[0], self.nodes[2]], timeout=300)

    def push_headers_with_attestations(self, dest, src, hashes):
        """Give dest the headers through the snapshot base, as the backfill test does."""
        headers = [from_hex(CBlockHeader(), src.getblockheader(h, False)) for h in hashes]
        peer = dest.add_p2p_connection(P2PInterface(), services=ARCHIVE_SERVICES)
        proof_pos = next(
            i for i, h in enumerate(hashes)
            if src.getblockheader(h)["height"] >= ACTIVATION_HEIGHT
        )
        peer.send_and_ping(msg_headers(headers=headers[: proof_pos + 1]))
        atts = []
        for h in hashes[proof_pos:]:
            atts.extend(bytes.fromhex(a) for a in src.getmatmulattestations(h))
        for i in range(0, len(atts), 16):
            batch = atts[i:i + 16]
            peer.send_and_ping(msg_generic(
                b"mmattest", ser_compact_size(len(batch)) + b"".join(batch)))
        if proof_pos + 1 < len(headers):
            peer.send_and_ping(msg_headers(headers=headers[proof_pos + 1:]))
        peer.peer_disconnect()
        dest.disconnect_p2ps()

    def step_scheduler(self, node, mock, steps):
        for _ in range(steps):
            mock += SCHEDULER_STEP
            node.setmocktime(mock)
            node.mockscheduler(SCHEDULER_STEP)
        return mock

    def run_test(self):
        archive, mirror, quiet_peer = self.nodes

        self.log.info("Chain through the snapshot height, followed by the non-serving mirror")
        self.generate(archive, SNAPSHOT_HEIGHT, sync_fun=self.sync_0_2)
        base_hash = archive.getbestblockhash()
        dump = archive.dumptxoutsetattested("utxo.dat", "utxo.manifest")
        assert_equal(dump["base_height"], SNAPSHOT_HEIGHT)
        self.generate(archive, BLOCKS_AFTER_SNAPSHOT, sync_fun=self.sync_0_2)
        tip_height = SNAPSHOT_HEIGHT + BLOCKS_AFTER_SNAPSHOT
        assert_equal(quiet_peer.getblockcount(), tip_height)
        assert "MATMUL_ATTESTATION_ARCHIVE" not in quiet_peer.getnetworkinfo()["localservicesnames"]

        self.log.info("Fresh mirror loads the snapshot (headers first, no peers yet)")
        self.push_headers_with_attestations(
            mirror, archive, [archive.getblockhash(h) for h in range(1, SNAPSHOT_HEIGHT + 1)])
        self.wait_until(lambda: mirror.getblockchaininfo()["headers"] >= SNAPSHOT_HEIGHT)
        shutil.copyfile(dump["path"], mirror.chain_path / "snapshot.dat")
        shutil.copyfile(dump["manifest_path"], mirror.chain_path / "snapshot.manifest")
        loaded = mirror.loadtxoutsetattested("snapshot.dat", "snapshot.manifest")
        assert_equal(loaded["base_height"], SNAPSHOT_HEIGHT)
        assert_equal(mirror.getblockcount(), SNAPSHOT_HEIGHT)

        self.log.info("Only peer serves no attestations: the mirror stays at the snapshot and says why")
        self.connect_nodes(1, 2)
        self.wait_until(lambda: mirror.getblockchaininfo()["headers"] >= tip_height, timeout=120)
        assert all(
            "MATMUL_ATTESTATION_ARCHIVE" not in (p.get("servicesnames") or [])
            for p in mirror.getpeerinfo()
        )
        mock = int(time.time())
        with mirror.assert_debug_log(
            expected_msgs=[NO_PEER_MSG, f"tip_height={SNAPSHOT_HEIGHT} header_height={tip_height}"],
            timeout=10,
        ):
            mock = self.step_scheduler(mirror, mock, 3)
        assert_equal(mirror.getblockcount(), SNAPSHOT_HEIGHT)

        self.log.info("Rate limit: no repeat inside ten minutes")
        with mirror.assert_debug_log(expected_msgs=[], unexpected_msgs=[NO_PEER_MSG], timeout=2):
            mock = self.step_scheduler(mirror, mock, 6)
        self.log.info("... and one repeat after it")
        with mirror.assert_debug_log(expected_msgs=[NO_PEER_MSG], timeout=10):
            mock = self.step_scheduler(mirror, mock, 7)
        assert_equal(mirror.getblockcount(), SNAPSHOT_HEIGHT)

        self.log.info("A serving peer fixes it and the warning stops")
        # Keep the mirror's clock moving forward from the mocked time. Jumping
        # back to real time would leave its attestation requests stamped in
        # the future and stretch the catch-up by the mocked interval.
        offset = mock - int(time.time())

        def caught_up():
            mirror.setmocktime(int(time.time()) + offset)
            return mirror.getbestblockhash() == archive.getbestblockhash()

        self.connect_nodes(1, 0)
        self.wait_until(caught_up, timeout=300)
        assert_greater_than_or_equal(mirror.getblockcount(), tip_height)
        with mirror.assert_debug_log(expected_msgs=[], unexpected_msgs=[NO_PEER_MSG], timeout=2):
            self.step_scheduler(mirror, int(time.time()) + offset, 3)
        mirror.setmocktime(0)
        assert_equal(base_hash, archive.getblockhash(SNAPSHOT_HEIGHT))

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(1))


if __name__ == "__main__":
    MatMulTrustedMirrorNoAttestationPeerTest(__file__).main()
