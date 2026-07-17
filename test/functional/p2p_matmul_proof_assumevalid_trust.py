#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Assumevalid buried-proof TRUST boundary for segregated MatMul v4.2-D proofs
(design §3.5-2, validation.cpp segregated-proof gate).

At ENC-BMX4C-D heights the ~32 MiB sketch is segregated and relayed out-of-band.
Verifying every historical proof during sync would force a syncing / pruned node
to obtain all of history's ~32 MiB proofs. Instead, exactly as ConnectBlock
already TRUSTS buried scriptSigs below the assumevalid block, a node TRUSTS a
segregated block's proof once the block is a buried ancestor of the configured
`-assumevalid` block. A fully-verifying node (`-assumevalid=0`, the default here
for the control) NEVER trusts and fetches+verifies every proof.

This test exercises that consensus trust boundary directly — the reviewer flagged
it as a new trust surface with no functional coverage. It asserts the OBSERVABLE
consequence of trust: a node that TRUSTED a buried proof never fetched it, so it
cannot serve it back; a node that VERIFIED it did fetch it, so it can.

The 2-week equivalent-time burial guard (~13 000 regtest blocks at 90 s spacing)
is shrunk on the trusting node with the regtest-only
`-regtestmatmulproofassumevalidminage` so the boundary is reachable after burying
a D block by only a few blocks. The trust ALSO requires an assumed-valid ancestor
carrying >= MinimumChainWork of AUTHENTICATED work, so the knob never weakens a
real network; D itself stays INT32_MAX / disabled everywhere off regtest.

n = 128 -> D tile b = 2 -> m = 64, so each proof is a few tens of KiB and every
D solve is trivial on the CPU regtest miner.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import MatMulProofReassembler, msg_getmatmulproof
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal

V3_BINDING_HEIGHT = 2
H_C = 6            # unified v3 -> v4.2 / ENC-BMX4C (in-block) activation
H_D = 8            # ENC-BMX4C-D segregated-proof activation (must be > H_C)
V4_DIMENSION = 128
NUM_D_BLOCKS = 5   # earliest D block ends up buried by NUM_D_BLOCKS-1 blocks
# Tiny equivalent-time trust age: at 90 s regtest spacing a single buried block is
# ~90 s of equivalent time, comfortably over this, so every D block below the tip
# is trust-eligible while the un-buried tip still requires its proof.
ASSUMEVALID_MIN_AGE = 1


class ProofQueryPeer(P2PInterface):
    """Requests a proof (getmatmulproof) and reassembles any mmproofchunk stream
    the node serves back."""

    def __init__(self):
        super().__init__()
        self.received_proofs = {}   # block_hash_int -> reassembled proof bytes
        self._reasm = {}

    def on_mmproofchunk(self, message):
        r = self._reasm.setdefault(message.block_hash, MatMulProofReassembler())
        r.add(message)
        if r.done():
            self.received_proofs[message.block_hash] = r.bytes()


class BTXMatMulProofAssumevalidTrust(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
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
        # node0: archive miner (holds every proof, serves any on request).
        # node1: TRUSTING node (assumevalid set post-mining via restart) + shrunk
        #        burial-age guard.
        # node2: FULLY-VERIFYING control — no -assumevalid (AssumedValidBlock null),
        #        so it must fetch+verify every proof.
        self.archive_args = common + ["-matmulproofarchive"]
        self.trusting_args = common + [f"-regtestmatmulproofassumevalidminage={ASSUMEVALID_MIN_AGE}"]
        self.verifying_args = list(common)
        self.extra_args = [self.archive_args, self.trusting_args, self.verifying_args]

    def setup_network(self):
        # Bring nodes up but wire them later: the trusting node is restarted with
        # -assumevalid=<tip> once the tip is known, and each syncer connects to the
        # archive (its only proof source) after the chain is built.
        self.setup_nodes()

    def served(self, node, block_hash_hex, timeout=15):
        """True iff `node` serves the segregated proof for `block_hash_hex`."""
        peer = node.add_p2p_connection(ProofQueryPeer())
        try:
            h = int(block_hash_hex, 16)
            deadline = time.time() + timeout
            while time.time() < deadline:
                peer.send_message(msg_getmatmulproof(h))
                peer.sync_with_ping()
                if h in peer.received_proofs:
                    return True
                time.sleep(0.5)
            return False
        finally:
            peer.peer_disconnect()
            peer.wait_for_disconnect()

    def run_test(self):
        archive_node, trusting_node, verifying_node = self.nodes

        self.log.info("node0 (archive miner) builds v3 -> ENC-BMX4C -> a run of segregated D blocks")
        self.generate(archive_node, H_D - 1, sync_fun=self.no_op)
        self.generate(archive_node, NUM_D_BLOCKS, sync_fun=self.no_op)
        top_height = H_D - 1 + NUM_D_BLOCKS
        assert_equal(archive_node.getblockcount(), top_height)
        tip_hash = archive_node.getbestblockhash()
        first_d_hash = archive_node.getblockhash(H_D)          # earliest, most-buried D block
        assert_equal(archive_node.getblock(tip_hash, 2)["matmul_dim"], V4_DIMENSION)
        # Sanity: the archive miner holds every proof it produced.
        assert self.served(archive_node, first_d_hash), "archive miner must hold the buried D proof"
        assert self.served(archive_node, tip_hash), "archive miner must hold the tip D proof"

        # -------- TRUSTING node: assumevalid=tip, buried proofs TRUSTED ----------
        self.log.info("[trust] Restart node1 with -assumevalid=<tip>; it syncs trusting buried proofs")
        self.restart_node(1, extra_args=self.trusting_args + [f"-assumevalid={tip_hash}"])
        self.connect_nodes(1, 0)
        self.sync_blocks([archive_node, trusting_node], timeout=240)
        assert_equal(trusting_node.getblockcount(), top_height)
        assert_equal(trusting_node.getbestblockhash(), tip_hash)

        # The earliest D block is a BURIED ancestor of the assumevalid tip, so its
        # proof was TRUSTED — never fetched — and the trusting node cannot serve it.
        # The un-buried TIP is not trust-eligible, so its proof WAS fetched (and can
        # be served). This asymmetry is the observable signature of the trust path.
        self.log.info("[trust] buried proof was trusted (never fetched); tip proof was fetched")
        assert not self.served(trusting_node, first_d_hash), \
            "trusting node must NOT hold a buried proof it trusted under assumevalid"
        assert self.served(trusting_node, tip_hash), \
            "trusting node must still fetch the un-buried tip proof it could not trust"

        # -------- VERIFYING control: assumevalid null, EVERY proof fetched --------
        self.log.info("[verify] node2 has no -assumevalid: it fetches+verifies EVERY proof")
        self.connect_nodes(2, 0)
        self.sync_blocks([archive_node, verifying_node], timeout=240)
        assert_equal(verifying_node.getblockcount(), top_height)
        assert_equal(verifying_node.getbestblockhash(), tip_hash)
        # Having verified every block, it holds — and serves — the buried proof the
        # trusting node trusted away.
        assert self.served(verifying_node, first_d_hash), \
            "fully-verifying node must fetch+hold the buried proof (never trusts)"
        assert self.served(verifying_node, tip_hash)

        self.log.info("Assumevalid buried-proof trust boundary holds: "
                      "trust below assumevalid, full verification without it")


if __name__ == "__main__":
    BTXMatMulProofAssumevalidTrust(__file__).main()
