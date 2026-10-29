#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A requested tip-extending body from an archive or mirror peer that fails
ConnectBlock must not get that peer punished; anything else still does.

A trusted mirror persists a tip-extending block before the attestation quorum
and serves it on GETDATA before ConnectBlock has run on it. When such a body
fails ConnectBlock on the requesting node, the node used to treat it like any
unsolicited full block, score the sender 100 and drop it when it was an
automatic outbound peer. The sender had relayed on header validation only.

node0 (generic regtest):
  A  an archive peer serves a requested tip child whose coinbase overpays
     (valid header, fails only in ConnectBlock): rejected, peer kept.
  B  a plain peer serves the same kind of block: rejected, peer dropped.
  C  an archive peer serves a requested two-block fork whose second block
     overpays, child first: when it arrives its parent is not connected, so
     it does not extend node0's tip and the peer is dropped.

node1 mines v4 blocks, node2 follows by submitblock (not connected):
  D  an archive peer serves node1's next honest block with words appended to
     matrix_c_data (it sits outside the header hash and the merkle root, so
     the header and the hash stay valid). node2 rejects it as BLOCK_MUTATED
     and drops the peer: an honest archive never stores such a body.
  E  the honest body with the same hash is still accepted (BLOCK_MUTATED
     does not mark the header invalid).

Regtest only, loopback only.
"""

from test_framework.blocktools import (
    REGTEST_GENERIC_P2P_MATMUL_ARGS,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    COIN,
    CBlock,
    CBlockHeader,
    NODE_NETWORK,
    NODE_WITNESS,
    from_hex,
    msg_headers,
)
from test_framework.p2p import P2PDataStore, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

NODE_MATMUL_ATTESTATION_ARCHIVE = 1 << 31
PLAIN = NODE_NETWORK | NODE_WITNESS
ARCHIVE = PLAIN | NODE_MATMUL_ATTESTATION_ARCHIVE

V3_BINDING_HEIGHT = 2
H_V4 = 6
V4_DIMENSION = 128


class SilentHeadersStore(P2PDataStore):
    def on_getheaders(self, message):
        pass


class ChildFirstStore(SilentHeadersStore):
    """Serves the blocks of one getdata in reverse order, so a fork child
    arrives while its parent body is still missing."""
    def on_getdata(self, message):
        message.inv.reverse()
        super().on_getdata(message)


class ArchiveRequestedBodyNoPunishTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        generic = [
            *REGTEST_GENERIC_P2P_MATMUL_ARGS,
            "-debug=net",
            "-nomodelnet",
            "-modellandiscovery=0",
        ]
        encdr = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={H_V4}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={H_V4}",
            "-debug=net",
            "-nomodelnet",
            "-modellandiscovery=0",
        ]
        self.extra_args = [generic, encdr, encdr]

    def setup_network(self):
        self.setup_nodes()

    def bad_block(self, prev_hash, height, time):
        cb = create_coinbase(height)
        cb.vout[0].nValue += 1000 * COIN  # passes CheckBlock, fails ConnectBlock
        cb.rehash()
        block = create_block(prev_hash, cb, time)
        block.solve()
        return block

    def bad_tip_child(self, offset):
        # offset gives each case its own block hash; a hash already marked
        # invalid would not be requested again.
        node = self.nodes[0]
        tip = node.getblock(node.getbestblockhash())
        return self.bad_block(int(tip["hash"], 16), tip["height"] + 1, tip["time"] + offset)

    def connect(self, node, idx, services, store=None):
        # The node sends its first getheaders right after our announcement. If
        # we answer it after the node has rejected the block, the answer
        # carries a known-invalid header, which is punished on its own path,
        # whatever this test is about. The parent is always known here, so
        # the node fetches the block directly and needs no answer.
        peer = node.add_outbound_p2p_connection(
            store or SilentHeadersStore(),
            p2p_idx=idx, connection_type="outbound-full-relay", services=services)
        return peer

    def punished(self, i, before):
        return len(self.debug_lines(i)) > before

    def debug_lines(self, i):
        with open(self.nodes[i].debug_log_path, encoding="utf-8", errors="replace") as f:
            return [l for l in f if "got DoS score 100 on invalid block" in l]

    def run_test(self):
        self.consensus_cases()
        self.mutated_cases()

    def consensus_cases(self):
        node = self.nodes[0]
        self.generate(node, 10, sync_fun=self.no_op)

        self.log.info("A: archive peer, requested tip child fails ConnectBlock, peer is kept")
        archive = self.connect(node, 0, ARCHIVE)
        before = len(self.debug_lines(0))
        archive.send_blocks_and_test(
            [self.bad_tip_child(1)], node, success=False,
            reject_reason="bad-cb-amount", expect_disconnect=False)
        archive.sync_with_ping()
        assert archive.is_connected
        assert not self.punished(0, before)

        self.log.info("B: plain peer, the same delivery is still punished")
        plain = self.connect(node, 1, PLAIN)
        plain.send_blocks_and_test(
            [self.bad_tip_child(2)], node, success=False,
            reject_reason="bad-cb-amount", expect_disconnect=True)
        assert archive.is_connected

        self.log.info("C: archive peer, failing block on a fork below the tip is still punished")
        tip = node.getblock(node.getbestblockhash())
        parent = node.getblock(tip["previousblockhash"])
        sibling_cb = create_coinbase(tip["height"])
        sibling = create_block(int(parent["hash"], 16), sibling_cb, tip["time"] + 1)
        sibling.solve()
        bad = self.bad_block(sibling.sha256, tip["height"] + 1, tip["time"] + 2)
        fork_archive = self.connect(node, 2, ARCHIVE, store=ChildFirstStore())
        height = node.getblockcount()
        with node.assert_debug_log(["bad-cb-amount", "got DoS score 100 on invalid block"]):
            with p2p_lock:
                fork_archive.block_store[sibling.sha256] = sibling
                fork_archive.block_store[bad.sha256] = bad
            fork_archive.send_message(msg_headers([CBlockHeader(sibling), CBlockHeader(bad)]))
            fork_archive.wait_for_disconnect(timeout=60)
        # node0 may stay on the valid sibling or go back to the old tip; both
        # are at the same height, and the overpaying child is not active.
        assert_equal(node.getblockcount(), height)
        assert node.getbestblockhash() != bad.hash
        assert archive.is_connected

    def mutated_cases(self):
        miner, victim = self.nodes[1], self.nodes[2]
        self.generate(miner, H_V4 + 3, sync_fun=self.no_op)
        top = miner.getblockcount()
        for h in range(1, top):
            assert_equal(victim.submitblock(miner.getblock(miner.getblockhash(h), 0)), None)
        assert_equal(victim.getblockcount(), top - 1)
        honest_hex = miner.getblock(miner.getblockhash(top), 0)

        self.log.info("D: archive peer, requested v4 body with words appended to matrix_c_data is punished")
        mutated = from_hex(CBlock(), honest_hex)
        assert len(mutated.matrix_c_data) > 0
        mutated.matrix_c_data = mutated.matrix_c_data + [1, 2, 3, 4]
        mutated.rehash()
        assert_equal(mutated.hash, miner.getblockhash(top))
        archive = self.connect(victim, 3, ARCHIVE)
        archive.send_blocks_and_test(
            [mutated], victim, success=False,
            reject_reason="invalid-product-payload", expect_disconnect=True)
        assert_equal(victim.getblockcount(), top - 1)

        self.log.info("E: the honest body with the same hash is still accepted")
        assert_equal(victim.submitblock(honest_hex), None)
        assert_equal(victim.getbestblockhash(), miner.getbestblockhash())


if __name__ == "__main__":
    ArchiveRequestedBodyNoPunishTest(__file__).main()
