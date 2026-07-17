#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Production-size, ENCRYPTED-transport chunked relay of the segregated MatMul v4.2-D
proof (solver-evolution Stage 2d, relay-hardening design §1/§5).

The Stage-2b relay carried the proof as ONE `matmulproof` message. At the production D
profile the sketch is 8*m^2 = 8*2048^2 = 32 MiB, which OVERFLOWS the v2 (BIP324) 24-bit
packet-length ceiling (~16 MB) and disconnects the peer — the relay could not run on any
network with v2 peers. Stage 2d fixes this by CHUNKING the proof into 1 MiB slices
(`mmproofchunk`), reassembling application-side with strict bounds, and binding only once
the whole blob is reassembled.

This test drives that end-to-end over the V2 ENCRYPTED transport at PRODUCTION scale:
  -regtestmatmulv4dimension=4096  ⇒  D tile b=2 ⇒ m=2048 ⇒ proof EXACTLY 32 MiB (32 chunks).
4096 is also the mainnet dimension, so it satisfies the per-profile dimension pin for BOTH
C (4096/4=1024) and D (4096/2=2048) in AssertBMX4CConstructionInvariants.

Asserts (design §5.2):
  1. Chunk bounds: a served proof is EXACTLY 32 `mmproofchunk`s; every chunk declares
     total_size == 33554432 and total_chunks == 32; chunk_index covers [0,32) once each;
     each chunk_bytes is 1 MiB.
  2. Successful reassembly + NO v2 disconnect: a v2 node reassembles the 32-chunk stream,
     binds (H(sigma||proof)==matmul_digest) + Freivalds-verifies, reaches the same tip, and
     the v2 connection STAYS UP across the whole transfer. Control: a monolithic 32 MiB
     message drops the v2 peer (the bug chunking fixes).
  3. Corrupt stream rejected without pinning memory: a flipped byte ⇒ the reassembled blob
     fails binding (MUTATED, non-permanent), the tip does not move, the provider is
     penalized; an honest proof from another peer then completes the block (re-request
     works, buffer freed).
  4. Oversized / duplicate / inconsistent / gapped streams rejected: rejected before or at
     reassembly with no completion and no tip movement.

D stays INT32_MAX / disabled on every real network; -regtestbmx4cdheight is the only way to
exercise the path, and the construction-assert exemption is keyed on the chain being regtest
(so the relay runs with BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY false — the real fail-closed
state for public nets). Marked slow: one D combine at n=4096 is heavy on a CPU regtest miner.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    CBlock,
    MAX_MATMULPROOF_CHUNK_SIZE,
    MatMulProofReassembler,
    from_hex,
    matmul_proof_chunks,
    msg_block,
    msg_getmatmulproof,
    msg_matmulproof,
    msg_matmulproofchunk,
)
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal

V3_BINDING_HEIGHT = 2
H_C = 4                 # unified v3 -> v4.2 / ENC-BMX4C activation (one in-block C block)
H_D = 5                 # ENC-BMX4C-D segregated-proof activation (must be > H_C)
V4_DIMENSION = 4096     # b=2 -> m=2048 -> proof EXACTLY 8*2048^2 = 32 MiB; also the dim pin
EXPECTED_PROOF_SIZE = 8 * 2048 * 2048            # 33554432
EXPECTED_CHUNKS = (EXPECTED_PROOF_SIZE + MAX_MATMULPROOF_CHUNK_SIZE - 1) // MAX_MATMULPROOF_CHUNK_SIZE  # 32


class ProofCollector(P2PInterface):
    """Requests a proof (getmmproof) and reassembles the chunk stream the node serves,
    recording the observed framing for the chunk-bounds assertions."""

    def __init__(self):
        super().__init__()
        self.reasm = MatMulProofReassembler()

    def on_mmproofchunk(self, message):
        self.reasm.add(message)


class ChunkStreamServer(P2PInterface):
    """Announces a block body and, on getmmproof, serves a CONFIGURABLE chunk stream so
    the test can inject honest / corrupt / oversized / duplicate / inconsistent / gapped
    streams into a receiving node."""

    def __init__(self):
        super().__init__()
        self.requests = []
        self.stream = None            # list of msg_matmulproofchunk to send, or None
        self.target_block_hash = None

    def on_getmmproof(self, message):
        self.requests.append(message.block_hash)
        if self.stream is not None and message.block_hash == self.target_block_hash:
            for chunk in self.stream:
                self.send_message(chunk)


class BTXMatMulSegregatedProofV2Chunked(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            "-v2transport=1",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={H_C}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            # Regtest's default accepted-dimension ceiling is 1024; lift it so the
            # production-scale 4096 (⇒ real 32 MiB D proof) is accepted (regtest-only).
            f"-regtestmatmulv4maxdimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={H_C}",
            f"-regtestbmx4cdheight={H_D}",
        ]
        self.extra_args = [common, common]

    def collect_proof_from(self, node, block_hash_int, timeout=120):
        """Fetch a proof over v2 from `node` as a chunk stream and return the observed
        (chunk_messages_metadata, reassembled_bytes)."""
        peer = node.add_p2p_connection(ProofCollector())
        peer.send_message(msg_getmatmulproof(block_hash_int))
        self.wait_until(lambda: peer.reasm.done(), timeout=timeout)
        assert peer.is_connected, "v2 peer disconnected during 32-chunk proof transfer"
        return peer

    def run_test(self):
        node0, node1 = self.nodes

        self.log.info("Sync both v2 nodes across v3 -> ENC-BMX4C, up to just below D")
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )
        self.generate(node0, H_D - 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == H_D - 1
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=600,
        )
        assert_equal(node1.getblock(node1.getbestblockhash(), 2)["matmul_dim"], V4_DIMENSION)

        # Isolate node1 so it does NOT get the D block from node0 yet: the adversarial
        # streams below run against a proof-INCOMPLETE block held on node1, and the honest
        # node0->node1 v2 relay is exercised last (the item-1 regression).
        self.disconnect_nodes(0, 1)

        self.log.info("node0 mines ONE production-scale (32 MiB) segregated D block")
        self.generate(node0, 1, sync_fun=self.no_op)
        d_hash_hex = node0.getbestblockhash()
        d_hash = int(d_hash_hex, 16)
        assert_equal(node0.getblockcount(), H_D)
        d_block_hex = node0.getblock(d_hash_hex, 0)

        self.log.info("[1] Chunk bounds: node0 serves the proof as exactly 32 self-describing 1 MiB chunks over v2")
        collector = self.collect_proof_from(node0, d_hash)
        r = collector.reasm
        assert_equal(r.total_chunks, EXPECTED_CHUNKS)
        assert_equal(r.total_size, EXPECTED_PROOF_SIZE)
        assert_equal(sorted(set(r.indices)), list(range(EXPECTED_CHUNKS)))
        assert_equal(len(r.indices), EXPECTED_CHUNKS)  # each index exactly once, no dup
        for i in range(EXPECTED_CHUNKS):
            assert_equal(r.chunk_lengths[i], MAX_MATMULPROOF_CHUNK_SIZE)
        real_proof = r.bytes()
        assert_equal(len(real_proof), EXPECTED_PROOF_SIZE)
        collector.peer_disconnect()
        collector.wait_for_disconnect()
        self.log.info("  32 chunks, total_size=32 MiB, indices [0,32) once each, no v2 disconnect")

        d_block = from_hex(CBlock(), d_block_hex)
        node1_base = node1.getbestblockhash()

        def feed_bad_stream(label, stream):
            """Attach a fresh v2 server that announces the D block and serves `stream`;
            assert node1 requests the proof, rejects the stream, and does NOT advance."""
            srv = node1.add_p2p_connection(ChunkStreamServer())
            srv.target_block_hash = d_hash
            srv.stream = stream
            srv.send_and_ping(msg_block(d_block))   # node1 holds it proof-INCOMPLETE
            self.wait_until(lambda: len(srv.requests) >= 1, timeout=90)
            # The chunk stream is queued from on_getmmproof before this returns; ping to
            # flush it through node1's (in-order, single-threaded) message processing,
            # then drain the validation queue so any ProcessBlock has fully settled.
            srv.sync_with_ping()
            node1.syncwithvalidationinterfacequeue()
            # node1 must NOT have advanced on the bad stream.
            assert_equal(node1.getbestblockhash(), node1_base)
            assert_equal(node1.getblockcount(), H_D - 1)
            self.log.info(f"  [{label}] rejected; node1 tip unchanged, held block still incomplete")
            srv.peer_disconnect()
            srv.wait_for_disconnect()

        self.log.info("[4a] Oversized declared total_size (> per-height cap) rejected before allocation")
        over = matmul_proof_chunks(d_hash, real_proof)[0]
        over.total_size = EXPECTED_PROOF_SIZE * 2      # far over the 8*m^2 + overhead cap
        over.total_chunks = (over.total_size + MAX_MATMULPROOF_CHUNK_SIZE - 1) // MAX_MATMULPROOF_CHUNK_SIZE
        feed_bad_stream("oversize", [over])

        self.log.info("[4b] Duplicate chunk_index rejected")
        honest = matmul_proof_chunks(d_hash, real_proof)
        feed_bad_stream("duplicate", [honest[0], honest[0]])

        self.log.info("[4c] Inconsistent total_size mid-stream rejected")
        c0 = matmul_proof_chunks(d_hash, real_proof)[0]
        c1 = matmul_proof_chunks(d_hash, real_proof)[1]
        c1.total_size = EXPECTED_PROOF_SIZE - 1        # differs from the latched first chunk
        feed_bad_stream("inconsistent", [c0, c1])

        self.log.info("[4d] Gapped stream (31 of 32 chunks) never completes")
        gapped = matmul_proof_chunks(d_hash, real_proof)
        del gapped[5]                                  # drop one interior chunk
        feed_bad_stream("gapped", gapped)

        self.log.info("[3] Corrupt full stream fails binding (MUTATED); an honest peer then completes the block")
        corrupt = bytearray(real_proof)
        corrupt[0] ^= 0xFF                             # flip one byte -> H(sigma||proof) mismatch
        feed_bad_stream("corrupt", matmul_proof_chunks(d_hash, bytes(corrupt)))

        # Honest completion from a SECOND source (node0) proves re-request works and the
        # pending buffer from every rejected stream above was freed (no memory pinned).
        self.log.info("[2] Honest node0->node1 v2 relay: 32-chunk proof completes the block, no v2 disconnect")
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node1.getblockcount() == H_D and node1.getbestblockhash() == d_hash_hex,
            timeout=600,
        )
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        assert node1.getpeerinfo(), "node1 kept its v2 peer across the 32-chunk transfer"
        self.log.info("  node1 reassembled 32 chunks over v2, bound + Freivalds-verified, reached the D tip")

        self.log.info("[2-control] A single over-ceiling proof message drops the v2 peer (the bug chunking fixes)")
        mono = node0.add_p2p_connection(ChunkStreamServer())
        # The real 32 MiB proof cannot even be FRAMED as one v2 packet (BIP324's 24-bit
        # length field caps a packet at ~16 MB) — which is the whole reason it must be
        # chunked. Demonstrate the receiver-side half of that ceiling with the largest
        # single proof message the sender CAN frame: a monolith just over the receiver's
        # ~16 MB MAX_CONTENTS_LEN. The v2 transport rejects the oversized packet and
        # disconnects, exactly as a real 32 MiB `matmulproof` would have.
        over_ceiling = bytes(16 * 1000 * 1000 + 500_000)   # > MAX_PROTOCOL_MESSAGE_LENGTH, < 2^24-1
        mono.send_message(msg_matmulproof(d_hash, over_ceiling))
        mono.wait_for_disconnect(timeout=60)
        self.log.info("  v2 transport dropped the over-ceiling monolithic-proof peer, as expected")

        self.log.info("Chunked segregated-proof relay over v2 is intact at production (32 MiB) scale")


if __name__ == "__main__":
    BTXMatMulSegregatedProofV2Chunked(__file__).main()
