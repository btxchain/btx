#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Issue 116: observe an ExactReplay attestation on the wire.

PersistMatMulExactReplayVerdict used to SignAuthoritative and return without
a push, so a GETMMATTEST-triggered ExactReplay was stored and never sent.
Log-string counting has produced false results on this project; this harness
uses getpeerinfo bytessent_per_msg only.

A trusted-mirror IBD pair stalls requesting height-1 GETMMATTEST
(not_profile1) and never reaches a Profile-1 hash. Drive the archive with a
P2P GETMMATTEST for a Profile-1 tip hash instead:

  1. One consensus archive with a local signing key, serving GETMMATTEST.
  2. Mine through toy Profile-1 (RPC generate = ProcessNewBlock / AcceptBlock,
     no ProcessBlockSync gossip).
  3. Handshake a P2P peer at protocol 800001 advertising
     NODE_MATMUL_TRUSTED_MIRROR, send getmmattest for the tip, and require
     bytessent_per_msg['mmattest'] to increase.

That is cache-empty GETMMATTEST: RPC generate left accepted=0, the handler
must mint and push. getpeerinfo bytessent_per_msg['mmattest'] must rise.
Do not weaken the counter assertion to make a case pass.
"""

from test_framework.messages import (
    NODE_NETWORK,
    NODE_WITNESS,
    msg_generic,
    ser_uint256,
)
from test_framework.p2p import MESSAGEMAP, P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
NODE_MATMUL_TRUSTED_MIRROR = 1 << 25


class _MsgMmAttest:
    """P2PInterface must decode mmattest or it drops the connection on the reply."""
    msgtype = b"mmattest"

    def deserialize(self, f):
        self.payload = f.read()


class MmAttestPeer(P2PInterface):
    def on_mmattest(self, message):
        pass


MESSAGEMAP[b"mmattest"] = _MsgMmAttest
INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


def peer_msg_bytes(node, sent, msg):
    key = "bytessent_per_msg" if sent else "bytesrecv_per_msg"
    return sum((peer.get(key) or {}).get(msg, 0) for peer in node.getpeerinfo())


class Issue116MmAttestWireTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        self.extra_args = [[
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
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]]

    def setup_network(self):
        self.setup_nodes()

    def dump_counters(self, label):
        peers = self.nodes[0].getpeerinfo()
        sent = [p.get("bytessent_per_msg") for p in peers]
        recv = [p.get("bytesrecv_per_msg") for p in peers]
        self.log.info(f"{label} sent={sent} recv={recv}")

    def run_test(self):
        archive = self.nodes[0]
        status = archive.getmatmultrustedstatus()
        assert status["local_signer"] is True
        assert status["serves_attestations"] is True

        self.log.info("Mine through toy Profile-1 with no peer connected")
        self.generate(archive, ACTIVATION_HEIGHT + 2, sync_fun=self.no_op)
        assert_equal(archive.getblockcount(), ACTIVATION_HEIGHT + 2)
        status = archive.getmatmultrustedstatus()
        self.log.info(
            "after generate accepted=" + str(status.get("accepted"))
        )
        assert_equal(peer_msg_bytes(archive, True, "mmattest"), 0)

        self.log.info(
            "Handshake a trusted-mirror P2P peer and GETMMATTEST the Profile-1 tip"
        )
        peer = archive.add_p2p_connection(
            MmAttestPeer(),
            services=NODE_NETWORK | NODE_WITNESS | NODE_MATMUL_TRUSTED_MIRROR,
        )
        before = peer_msg_bytes(archive, True, "mmattest")
        self.dump_counters("after-handshake")
        assert_equal(before, 0)

        tip_hex = archive.getbestblockhash()
        tip = int(tip_hex, 16)
        self.log.info(f"GETMMATTEST {tip_hex} height={archive.getblockcount()}")
        peer.send_and_ping(msg_generic(b"getmmattest", ser_uint256(tip)))

        def archive_sent_mmattest():
            return peer_msg_bytes(archive, True, "mmattest") > before

        self.wait_until(archive_sent_mmattest, timeout=120)
        self.dump_counters("after-getmmattest")
        sent = peer_msg_bytes(archive, True, "mmattest")
        asked = peer_msg_bytes(archive, False, "getmmattest")
        self.log.info(
            f"archive bytessent_per_msg mmattest={sent} "
            f"bytesrecv_per_msg getmmattest={asked} (before={before})"
        )
        assert_greater_than(sent, before)
        assert_greater_than(asked, 0)

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)


if __name__ == "__main__":
    Issue116MmAttestWireTest(__file__).main()
