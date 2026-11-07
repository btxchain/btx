#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A serving node with -matmulopenattestors=1 answers GETMMATTEST with the
heard (valid, unpinned) statements it holds, after its pinned ones.

  A  consensus signer KA, serving.
  B  consensus signer KB, serving, pins KX (never signs) at M=2, so it never
     reaches quorum and keeps pulling; open attestors on. KA is heard on B.
  C  trusted mirror pinning KA, connected only to B.
  B0 / C0  the same pair with the directory off (the default): C0 must stay
     frozen at the last pre-Profile-1 block.

C gets KA's votes only through B's heard answer. Nothing about B's trust
moves. All assertions use RPC state and getpeerinfo byte counters, never
log-line counts.
"""

from io import BytesIO
import time

from test_framework.messages import (
    NODE_NETWORK,
    NODE_WITNESS,
    deser_compact_size,
    deser_string,
    msg_generic,
    ser_uint256,
)
from test_framework.p2p import MESSAGEMAP, P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
HEARD_PER_ANSWER = 4
HEARD_TOKEN_REFILL_SECONDS = 4
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


class _MsgMmAttest:
    """P2PInterface must decode mmattest or it drops the connection."""
    msgtype = b"mmattest"

    def deserialize(self, f):
        self.payload = f.read()


MESSAGEMAP[b"mmattest"] = _MsgMmAttest


def mmattest_items(payload):
    """(block hash hex, signer pubkey hex) for each attestation in one
    mmattest payload: compact count, then V2 statement, signer, signature."""
    f = BytesIO(payload)
    items = []
    for _ in range(deser_compact_size(f)):
        version = f.read(1)[0]
        f.read(32)  # chain_id
        block_hash = f.read(32)[::-1].hex()
        f.read(4 + 1 + 1)  # height, matmul_major, profile
        if version >= 2:
            f.read(32)  # replay_authority_context
        signer = deser_string(f).hex()
        deser_string(f)  # signature
        items.append((block_hash, signer))
    assert_equal(f.read(), b"")
    return items


class MmAttestProbe(P2PInterface):
    def __init__(self):
        super().__init__()
        self.mmattest = []

    def on_mmattest(self, message):
        self.mmattest.append(mmattest_items(message.payload))


def peer_msg_bytes(node, sent, msg):
    key = "bytessent_per_msg" if sent else "bytesrecv_per_msg"
    return sum((peer.get(key) or {}).get(msg, 0) for peer in node.getpeerinfo())


class MatMulHeardServeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        self.setup_clean_chain = True
        ka_wif, ka_pub = generate_keypair(wif=True)
        kb_wif, kb_pub = generate_keypair(wif=True)
        kb0_wif, kb0_pub = generate_keypair(wif=True)
        _, kx_pub = generate_keypair(wif=True)
        self.ka = ka_pub.hex()
        self.kb = kb_pub.hex()
        self.kb0 = kb0_pub.hex()
        self.kx = kx_pub.hex()
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
            "-matmultrustedwaitms=30000",
            # Not a model-network test (see feature_matmul_trusted_mirrors).
            "-modelnet=0",
        ]
        signer_a = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={ka_wif}",
            "-matmulattestationserve=1",
            f"-matmultrustedpubkey={self.ka}",
            "-matmultrustedthreshold=1",
        ]

        def serving_b(wif, open_attestors):
            # KX never signs: M=2 is unreachable, so B keeps asking A and
            # never stops pulling on its own quorum. KB seeds into the pin
            # because the pin (KX) has fewer than M keys.
            args = common + [
                "-matmulvalidation=consensus",
                f"-matmulattestationsignerkey={wif}",
                "-matmulattestationserve=1",
                f"-matmultrustedpubkey={self.kx}",
                "-matmultrustedthreshold=2",
            ]
            return args + ["-matmulopenattestors=1"] if open_attestors else args

        mirror = common + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
            f"-matmultrustedpubkey={self.ka}",
            "-matmultrustedthreshold=1",
        ]
        self.extra_args = [
            signer_a,
            serving_b(kb_wif, open_attestors=True),
            mirror,
            # Directory off by default: no -matmulopenattestors at all.
            serving_b(kb0_wif, open_attestors=False),
            mirror,
        ]

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        for i in range(self.num_nodes):
            self.start_node(i)
        # Only the serving nodes see A. The mirrors join later and only
        # through them.
        self.connect_nodes(1, 0)
        self.connect_nodes(3, 0)

    def run_test(self):
        a, b, c, b0, c0 = self.nodes

        assert_equal(b.getmatmulattestors()["open_attestors"], True)
        assert_equal(b0.getmatmulattestors()["open_attestors"], False)
        for node in (b, b0):
            services = node.getnetworkinfo()["localservicesnames"]
            assert "MATMUL_ATTESTATION_ARCHIVE" in services
        trusted_b = sorted(b.getmatmultrustedstatus()["trusted_signer_pubkeys"])
        assert_equal(trusted_b, sorted([self.kx, self.kb]))

        # Finish both genesis getheaders exchanges before mining. Otherwise a
        # late initial request can accidentally deliver block 1 and hide a
        # broken first-body announcement behind a handshake race. Each peer's
        # two-minute getheaders send window is now occupied by an empty reply.
        self.wait_until(lambda: all(
            any(peer["bytesrecv_per_msg"].get("headers", 0) > 0
                for peer in node.getpeerinfo())
            for node in (b, b0)
        ))
        assert_equal(a.getblockcount(), 0)
        assert_equal(b.getblockcount(), 0)
        assert_equal(b0.getblockcount(), 0)

        self.log.info("Mine through the toy Profile-1 activation on A")
        # One block at a time. In a burst, A announces only the next body a
        # behind peer needs, and a B that does not pin KA does not fetch a
        # header from KA's vote, so B can be left one header short.
        for _ in range(ACTIVATION_HEIGHT + 2):
            self.generate(a, 1, sync_fun=self.no_op)
            self.sync_blocks([a, b, b0], timeout=60)
        tip = a.getbestblockhash()
        tip_height = a.getblockcount()
        assert_equal(tip_height, ACTIVATION_HEIGHT + 2)
        attested = tip_height - ACTIVATION_HEIGHT + 1

        self.log.info("B hears KA's votes; B0 (directory off) drops them")
        self.wait_until(
            lambda: b.getmatmultrustedstatus()["heard_attestations"] >= attested,
            timeout=60,
        )
        assert_equal(b.getmatmulattestors()["heard_pubkeys"], [self.ka])
        assert_equal(b0.getmatmultrustedstatus()["heard_attestations"], 0)
        assert_equal(b0.getmatmulattestors()["heard_pubkeys"], [])

        self.log.info("Mirrors dial their serving node (bodies need a manual peer)")
        self.connect_nodes(2, 1)
        self.connect_nodes(4, 3)

        self.log.info("C reaches A's tip through B's heard answers")
        self.wait_until(lambda: c.getbestblockhash() == tip, timeout=120)
        status_c = c.getmatmultrustedstatus()
        assert_greater_than_or_equal(status_c["accepted"], attested)
        assert_greater_than_or_equal(status_c["blocks_with_quorum"], attested)
        assert_greater_than(peer_msg_bytes(c, True, "getmmattest"), 0)
        assert_greater_than(peer_msg_bytes(c, False, "mmattest"), 0)

        self.log.info("C0 behind B0 asks, is answered, and stays frozen")
        self.wait_until(
            lambda: c0.getblockchaininfo()["headers"] == tip_height
            and c0.getblockcount() == ACTIVATION_HEIGHT - 1,
            timeout=120,
        )
        self.wait_until(
            lambda: peer_msg_bytes(c0, False, "mmattest") > 0, timeout=60
        )
        assert_greater_than(peer_msg_bytes(c0, True, "getmmattest"), 0)
        assert_equal(c0.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert_equal(c0.getmatmultrustedstatus()["accepted"], 0)
        assert_equal(c0.getmatmultrustedstatus()["blocks_with_quorum"], 0)

        self.log.info("Nothing about B's trust moved")
        status_b = b.getmatmultrustedstatus()
        assert_equal(sorted(status_b["trusted_signer_pubkeys"]), trusted_b)
        assert_equal(status_b["blocks_with_quorum"], 0)
        assert_equal(b.getmatmulattestors()["admitted_open_pubkeys"], [])

        self.log.info("B's heard answer: own message, after the pinned one, paced")
        # Frozen clock on B: the per-requester allowance cannot refill
        # between asks, so the count below is exact.
        now = int(time.time())
        b.setmocktime(now)
        probe = b.add_p2p_connection(
            MmAttestProbe(), services=NODE_NETWORK | NODE_WITNESS
        )
        asks = HEARD_PER_ANSWER + 2
        for _ in range(asks):
            probe.send_and_ping(msg_generic(b"getmmattest", ser_uint256(int(tip, 16))))
        with p2p_lock:
            answers = list(probe.mmattest)
        self.log.info(f"probe answers: {answers}")
        for items in answers:
            assert all(h == tip for h, _ in items), items
        pinned = [items for items in answers if any(s == self.kb for _, s in items)]
        heard = [items for items in answers if any(s == self.ka for _, s in items)]
        # Never mixed: pinned and heard ride in separate messages.
        assert_equal([m for m in pinned if m in heard], [])
        assert_equal(len(pinned), asks)
        assert_equal(len(heard), HEARD_PER_ANSWER)
        assert all(items == [(tip, self.ka)] for items in heard), heard
        # Each heard message directly follows a pinned one.
        for i, items in enumerate(answers):
            if items in heard:
                assert i > 0 and answers[i - 1] in pinned, answers

        b.setmocktime(now + HEARD_TOKEN_REFILL_SECONDS)
        probe.send_and_ping(msg_generic(b"getmmattest", ser_uint256(int(tip, 16))))
        with p2p_lock:
            answers = list(probe.mmattest)[len(answers):]
        assert_equal(len(answers), 2)
        assert_equal(answers[1], [(tip, self.ka)])
        probe.peer_disconnect()
        probe.wait_for_disconnect()
        b.setmocktime(0)

        for node in self.nodes:
            assert_equal(node.listbanned(), [])

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(3, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(4, expected_stderr=TRUST_WARNING.format(1))


if __name__ == "__main__":
    MatMulHeardServeTest(__file__).main()
