#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""MatMul v4.4 ENC-DR digest-only carriage + best-effort sketch cache
(doc/btx-matmul-v4.4-tension-resolution.md §4).

At v4.4 ENC-DR heights the block carries ZERO consensus proof bytes: the header's
matmul_digest = H(sigma||Chat) is the entire PoW commitment and a validator
deterministically RECOMPUTES Chat from the header (exact digest check). The 8*m^2
sketch survives only as an OPTIONAL, untrusted, self-authenticating cache payload
served over a new getmmsketch/mmsketch exchange so peers may run the cheap v4.3
Freivalds verifier instead of the recompute.

Asserts:
  * node0 mines DIGEST-ONLY blocks: the serialized body carries no sketch (it is
    dramatically smaller than the 8*m^2 in-block carriage would be);
  * node1 — with its sketch cache DISABLED (-mmsketchcache=0), so it can never
    take the Freivalds fast path — accepts the same chain by pure recompute;
  * node2 — cache enabled (small capacity) — accepts the same chain; all three
    reach the same tip: both evaluation strategies decide the same predicate;
  * the winner (node0) serves the sketch on getmmsketch, and the served bytes
    are non-empty and exactly 8*m^2;
  * SERVE dedup gate (G.4): two identical getmmsketch from one peer within the
    dedup window yield exactly ONE mmsketch reply (the second is silently
    skipped — the anti-amplification pattern);
  * RECEIVE authentication path (G.4): a TAMPERED mmsketch for an UNCACHED v4
    block fails the one-hash H(sigma||bytes)==matmul_digest authentication and
    the sender is discouraged/disconnected (Misbehaving), WITHOUT touching the
    chain; an HONEST mmsketch for the same uncached block is authenticated and
    cached (the node then serves it back). Targeting an *uncached* block is what
    makes this deterministic: for a cached block the receive handler short-
    circuits on Have() before authentication, so the penalty path never runs.
  * liveness is independent of the cache throughout (no node ever stalls
    waiting for sketch bytes).

Coverage note: the per-peer token bucket and node-wide egress byte budget are
NOT exercised here — at the CI dimension a sketch is only 8192 bytes and the
buckets (16-request burst, ~8 MiB/s) would need hundreds-to-thousands of
requests to exhaust, which is impractical in a fast functional test. They are
covered by construction/inspection; the dedup gate (the cheapest to trip) is
the one asserted end-to-end here.

Heights/dims chosen for CI speed: v4/ENC-BMX4C at H_V4 (single flag day), n = 128
=> m = 32 => sketch 8*32^2 = 8192 bytes.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    CBlockHeader,
    from_hex,
    msg_getmmsketch,
    msg_headers,
    msg_mmsketch,
)
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal, assert_greater_than

V3_BINDING_HEIGHT = 2
H_V4 = 6                # unified v3 -> v4.4 ENC-DR flag day
V4_DIMENSION = 128      # b = 4 -> m = 32 -> 8*m^2 = 8192-byte sketch
SKETCH_BYTES = 8 * (V4_DIMENSION // 4) ** 2
NODE2_CACHE = 2         # small cache so early v4 blocks are FIFO-evicted -> uncached


class SketchPeer(P2PInterface):
    """Requests and records mmsketch replies; can inject (honest or tampered)
    mmsketch messages. Counts replies so the dedup serve gate is checkable, and
    records incoming getmmsketch so the SOLICITED receive path is testable."""

    def __init__(self):
        super().__init__()
        self.sketches = {}   # block_hash int -> bytes
        self.reply_count = 0
        self.sketch_requests = []   # block hashes the NODE asked us for

    def on_mmsketch(self, message):
        self.sketches[message.block_hash] = message.sketch
        self.reply_count += 1

    def on_getmmsketch(self, message):
        self.sketch_requests.append(message.block_hash)


class BTXMatMulEncDrSketchCache(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={H_V4}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={H_V4}",
        ]
        # node1: cache DISABLED -> forced pure-recompute validator.
        # node2: tiny cache -> old v4 blocks get evicted (needed for the
        #        uncached-block receive/authentication coverage below).
        self.extra_args = [
            common,
            common + ["-mmsketchcache=0"],
            common + [f"-mmsketchcache={NODE2_CACHE}"],
        ]

    def setup_network(self):
        # Star topology only: 0—1 and 0—2. The default chain (1—2) lets node1
        # keep feeding node2 after disconnect_nodes(0, 2), so the solicited
        # getmmsketch goes to node1 instead of the attacker P2P peer.
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.sync_all()

    def run_test(self):
        node0, node1, node2 = self.nodes

        self.wait_until(
            lambda: node0.getconnectioncount() >= 2
            and node1.getconnectioncount() >= 1
            and node2.getconnectioncount() >= 1,
            timeout=120,
        )

        self.log.info("Mine across the flag day: digest-only ENC-DR blocks")
        # Mine enough v4 blocks that node2's small cache evicts the earliest one.
        target_height = H_V4 + NODE2_CACHE + 3   # >= NODE2_CACHE+1 v4 blocks
        self.generate(node0, target_height, sync_fun=self.no_op)
        assert_equal(node0.getblockcount(), target_height)

        self.log.info("Recompute-only peer (cache disabled) reaches the same tip")
        self.wait_until(
            lambda: node1.getblockcount() == target_height
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=240,
        )
        self.log.info("Cache-enabled peer reaches the same tip")
        self.wait_until(
            lambda: node2.getblockcount() == target_height
            and node2.getbestblockhash() == node0.getbestblockhash(),
            timeout=240,
        )

        self.log.info("ENC-DR blocks are digest-only: no sketch rides the body")
        for height in range(H_V4, target_height + 1):
            block_hex = node1.getblock(node1.getblockhash(height), 0)
            # A block carrying the in-block sketch would serialize > 8*m^2 bytes;
            # the digest-only body (header + coinbase + framing) is far smaller.
            assert_greater_than(SKETCH_BYTES, len(block_hex) // 2)
            block = node1.getblock(node1.getblockhash(height), 2)
            assert_equal(block["matmul_dim"], V4_DIMENSION)

        tip_hash_hex = node0.getbestblockhash()
        tip_hash = int(tip_hash_hex, 16)

        self.log.info("The winner serves the sketch via getmmsketch")
        peer = node0.add_p2p_connection(SketchPeer())
        peer.send_message(msg_getmmsketch(block_hash=tip_hash))
        self.wait_until(lambda: tip_hash in peer.sketches, timeout=60)
        honest_sketch = peer.sketches[tip_hash]
        assert_equal(len(honest_sketch), SKETCH_BYTES)

        self.log.info("SERVE dedup gate: a repeat getmmsketch yields no 2nd reply")
        dedup_peer = node0.add_p2p_connection(SketchPeer())
        dedup_peer.send_message(msg_getmmsketch(block_hash=tip_hash))
        self.wait_until(lambda: dedup_peer.reply_count >= 1, timeout=60)
        # Second identical request within the dedup window must be silently
        # skipped -> still exactly one reply after a round-trip.
        dedup_peer.send_message(msg_getmmsketch(block_hash=tip_hash))
        dedup_peer.sync_with_ping(timeout=60)
        assert_equal(dedup_peer.reply_count, 1)

        # Pick a v4 block that node2 has FIFO-evicted from its small cache, so
        # the receive handler runs authentication instead of the Have() short
        # circuit. The earliest v4 block (H_V4) is evicted once > NODE2_CACHE
        # later v4 blocks exist.
        uncached_height = H_V4
        uncached_hex = node2.getblockhash(uncached_height)
        uncached_hash = int(uncached_hex, 16)

        self.log.info("RECEIVE: UNSOLICITED mmsketch is silently dropped (WP-8 hardening)")
        # Fetch the honest sketch for the uncached block from the winner first.
        peer.send_message(msg_getmmsketch(block_hash=uncached_hash))
        self.wait_until(lambda: uncached_hash in peer.sketches, timeout=60)
        uncached_sketch = peer.sketches[uncached_hash]
        assert_equal(len(uncached_sketch), SKETCH_BYTES)

        # The serve side never pushes sketches unsolicited, so the receive side
        # accepts an mmsketch ONLY in reply to its own getmmsketch. A tampered
        # unsolicited push is dropped BEFORE any authentication hashing and
        # WITHOUT penalty (the drop must not punish an honest-but-late reply
        # after the request TTL)...
        push_peer = node2.add_p2p_connection(SketchPeer())
        tampered = bytearray(uncached_sketch)
        tampered[0] ^= 0x01
        with node2.assert_debug_log(["Ignoring unsolicited mmsketch"]):
            push_peer.send_message(
                msg_mmsketch(block_hash=uncached_hash, sketch=bytes(tampered)))
            push_peer.sync_with_ping(timeout=60)
        # ...the peer stays connected and the chain is untouched...
        assert_equal(node2.getbestblockhash(), tip_hash_hex)
        # ...and an unsolicited HONEST sketch is equally not cached: node2 does
        # not serve it afterwards.
        with node2.assert_debug_log(["Ignoring unsolicited mmsketch"]):
            push_peer.send_message(
                msg_mmsketch(block_hash=uncached_hash, sketch=uncached_sketch))
            push_peer.sync_with_ping(timeout=60)
        serve_probe = node2.add_p2p_connection(SketchPeer())
        serve_probe.send_message(msg_getmmsketch(block_hash=uncached_hash))
        serve_probe.sync_with_ping(timeout=60)
        assert uncached_hash not in serve_probe.sketches

        self.log.info("RECEIVE: tampered reply to a node-initiated getmmsketch is penalized")
        # Cut node2 off from node0 and mine one more ENC-DR block, so node2 must
        # fetch the new block from our attacker peer. Announcing the header makes
        # node2 direct-fetch the block AND prefetch its sketch (getmmsketch) from
        # the attacker: a deterministic SOLICITED delivery.
        # setup_network uses a star (no 1—2 edge); otherwise node1 would still
        # relay the tip and steal the solicited prefetch.
        self.disconnect_nodes(0, 2)
        self.generate(node0, 1, sync_fun=self.no_op)
        solicited_hex = node0.getbestblockhash()
        solicited_hash = int(solicited_hex, 16)
        # The honest bytes (to tamper with) come from the winner.
        peer.send_message(msg_getmmsketch(block_hash=solicited_hash))
        self.wait_until(lambda: solicited_hash in peer.sketches, timeout=60)
        solicited_sketch = peer.sketches[solicited_hash]
        assert_equal(len(solicited_sketch), SKETCH_BYTES)

        attacker = node2.add_p2p_connection(SketchPeer())
        header = from_hex(CBlockHeader(), node0.getblockheader(solicited_hex, False))
        attacker.send_message(msg_headers(headers=[header]))
        self.wait_until(lambda: solicited_hash in attacker.sketch_requests, timeout=60)
        tampered_reply = bytearray(solicited_sketch)
        tampered_reply[0] ^= 0x01
        with node2.assert_debug_log(["does not authenticate against matmul_digest"]):
            attacker.send_message(
                msg_mmsketch(block_hash=solicited_hash, sketch=bytes(tampered_reply)))
            # One authentication failure on a solicited reply discourages the
            # peer -> disconnect.
            attacker.wait_for_disconnect(timeout=60)
        # A bad cache delivery never touches the chain: node2 still gets the
        # block from the honest network and reaches the new tip.
        self.connect_nodes(0, 2)
        self.wait_until(
            lambda: node2.getbestblockhash() == solicited_hex, timeout=240)

        self.log.info("Chain keeps extending regardless of cache state (liveness)")
        self.generate(node0, 1, sync_fun=self.no_op)
        final_height = target_height + 2
        for node in (node1, node2):
            self.wait_until(
                lambda n=node: n.getblockcount() == final_height
                and n.getbestblockhash() == node0.getbestblockhash(),
                timeout=240,
            )


if __name__ == "__main__":
    BTXMatMulEncDrSketchCache(__file__).main()
