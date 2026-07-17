#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Multi-node relay of the segregated MatMul v4.2-D proof (solver-evolution Stage 2b).

At ENC-BMX4C-D (segregated-proof) heights the ~32 MiB sketch is NOT carried in the
block body (design §3): the block commits only the 32-byte header matmul_digest and
the sketch travels out-of-band over a new getmatmulproof/matmulproof request-response
exchange. This test drives that relay end-to-end on regtest with D activated at a low
height via -regtestbmx4cdheight (D stays INT32_MAX / disabled on every real network;
this override is the only way to exercise the path).

Asserts:
  * a node that receives a segregated D block finds it proof-INCOMPLETE, fetches the
    proof via getmatmulproof, completes validation, and reaches the SAME tip;
  * the relayed segregated block's serialized size EXCLUDES the sketch (it is much
    smaller than an in-block ENC-BMX4C block carrying its payload);
  * a peer that serves a CORRUPTED proof is rejected (the §3.3 binding
    H(sigma||proof)==matmul_digest fails), the block stays incomplete and the tip does
    not move, and an HONEST proof from another peer still completes the block.

Heights (chosen for CI speed): v3 -> ENC-BMX4C at H_C, then ENC-BMX4C-D at H_D > H_C.
n = 128 keeps n % 32 == 0 (E8M0 block scales) and, at D's tile b = 2, m = n/2 = 64,
so the per-nonce GEMM stays trivial on a CPU regtest miner and the D proof is a few
tens of KiB (well under the profile's 8*m^2 size cap).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    CBlock,
    from_hex,
    matmul_proof_chunks,
    msg_block,
)
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal, assert_greater_than

V3_BINDING_HEIGHT = 2
H_C = 6          # unified v3 -> v4.2 / ENC-BMX4C activation
H_D = 8          # ENC-BMX4C-D segregated-proof activation (must be > H_C)
V3_DIMENSION = 64
V4_DIMENSION = 128


class ProofServingPeer(P2PInterface):
    """A P2P peer that records getmatmulproof requests and answers them with a
    configurable (honest or corrupt) proof, served as the Stage-2d mmproofchunk
    sequence, and can serve a block body."""

    def __init__(self):
        super().__init__()
        self.getmatmulproof_requests = []
        self.proof_response = None       # bytes to reply with, or None to ignore
        self.target_block_hash = None    # int block hash we answer proofs for

    def on_getmmproof(self, message):
        self.getmatmulproof_requests.append(message.block_hash)
        if self.proof_response is not None and message.block_hash == self.target_block_hash:
            for chunk in matmul_proof_chunks(message.block_hash, self.proof_response):
                self.send_message(chunk)


class BTXMatMulSegregatedProofRelay(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={H_C}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={H_C}",
            f"-regtestbmx4cdheight={H_D}",
        ]
        self.extra_args = [common, common]

    def mine_d_block_on_node0_only(self):
        """Mine one ENC-BMX4C-D block on node0 while node1 is disconnected, so node1
        does not yet have it. Returns (block_hash_hex, block_hex)."""
        before = self.nodes[0].getblockcount()
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        assert_equal(self.nodes[0].getblockcount(), before + 1)
        bhash = self.nodes[0].getbestblockhash()
        return bhash, self.nodes[0].getblock(bhash, 0)

    def run_test(self):
        node0, node1 = self.nodes

        self.log.info("Sync both nodes across the v3 -> ENC-BMX4C fork, up to just below D")
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )
        # Mine through H_C .. H_D-1 (in-block ENC-BMX4C blocks) and sync node1.
        self.generate(node0, H_D - 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == H_D - 1
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=240,
        )
        assert_equal(node1.getblock(node1.getbestblockhash(), 2)["matmul_dim"], V4_DIMENSION)

        # Record the size of an in-block ENC-BMX4C block (carries its 8*m^2 sketch).
        c_block_hex = node0.getblock(node0.getblockhash(H_C), 0)

        self.log.info("Honest relay: node0 mines a segregated D block; node1 fetches the proof")
        self.generate(node0, 1, sync_fun=self.no_op)
        d_hash = node0.getbestblockhash()
        assert_equal(node0.getblockcount(), H_D)
        # node1 receives the segregated block (proof-INCOMPLETE), issues getmatmulproof
        # to node0, completes the §3.3 binding + Freivalds, and reaches the D tip.
        self.wait_until(
            lambda: node1.getblockcount() == H_D and node1.getbestblockhash() == d_hash,
            timeout=240,
        )
        d_block = node1.getblock(d_hash, 2)
        assert_equal(d_block["matmul_dim"], V4_DIMENSION)

        self.log.info("The relayed segregated block excludes the sketch from its serialized size")
        d_block_hex = node1.getblock(d_hash, 0)
        # The in-block ENC-BMX4C block carries an 8*m^2 payload; the segregated D block
        # carries none, so it is strictly (and, here, dramatically) smaller.
        assert_greater_than(len(c_block_hex), len(d_block_hex))
        self.log.info(f"  in-block C block hex={len(c_block_hex)//2}B, segregated D block hex={len(d_block_hex)//2}B")

        self.log.info("A corrupted proof is rejected; an honest proof from another peer completes the block")
        # Isolate node1 so the corrupt-serving mininode is the SOLE announcer/source of
        # the next D block (design: node1 requests the proof from the announcing peer).
        self.disconnect_nodes(0, 1)
        corrupt_hash_hex, corrupt_block_hex = self.mine_d_block_on_node0_only()
        assert_equal(node0.getblockcount(), H_D + 1)
        corrupt_hash_int = int(corrupt_hash_hex, 16)
        assert node1.getbestblockhash() != corrupt_hash_hex
        node1_tip_before = node1.getbestblockhash()

        bad_peer = node1.add_p2p_connection(ProofServingPeer())
        bad_peer.target_block_hash = corrupt_hash_int
        # Serve a WRONG proof (right ballpark size, well under the §3.4 cap, but not the
        # committed sketch), so the H(sigma||proof)==matmul_digest binding fails.
        bad_peer.proof_response = bytes([0xAB]) * 256

        # Feed node1 the segregated D block. It builds on node1's tip, so node1 accepts
        # the header + empty body, finds it proof-INCOMPLETE, and holds it with the
        # mininode as the announcing peer.
        d2_block = from_hex(CBlock(), corrupt_block_hex)
        bad_peer.send_and_ping(msg_block(d2_block))

        # node1 requests the proof from the mininode (its announcer); the mininode
        # serves the corrupt proof; node1 rejects it (binding fails) and does NOT
        # advance the tip.
        self.wait_until(lambda: len(bad_peer.getmatmulproof_requests) >= 1, timeout=60)
        self.log.info(f"  node1 requested the proof from the mininode ({len(bad_peer.getmatmulproof_requests)}x)")
        # Give node1 time to process (and reject) the corrupt proof.
        self.wait_until(
            lambda: node1.getbestblockhash() == node1_tip_before,
            timeout=30,
        )
        assert_equal(node1.getbestblockhash(), node1_tip_before)
        assert_equal(node1.getblockcount(), H_D)
        self.log.info("  corrupt proof rejected; block remains incomplete, tip unchanged")

        # Now provide an HONEST source: reconnect node0, which holds the block's proof.
        # node1 excludes the corrupt mininode and fetches the honest proof from node0,
        # completing the held block.
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node1.getblockcount() == H_D + 1
            and node1.getbestblockhash() == corrupt_hash_hex,
            timeout=240,
        )
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        self.log.info("  honest proof from node0 completed the previously-incomplete block")

        self.log.info("Both nodes agree on the D tip; the segregated-proof relay is intact")
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())


if __name__ == "__main__":
    BTXMatMulSegregatedProofRelay(__file__).main()
