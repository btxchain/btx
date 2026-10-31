#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A signer killed after it attested a block must sign the block that replaced it.

The attestation store keeps a vote as soon as it is signed, while the block
index is flushed lazily. After a kill -9 the signer can be missing a block it
has already attested. Nothing disconnects that block then, so its vote kept the
height occupied and the signer refused the block the network chose instead.

node0 signs (M=1) and does not mine; node1 mines.
  A. node0 signs X, is killed, node1 replaces X with Y. After the restart
     node0 has to sign Y.
  B. node0 signs X2, is killed, node1 keeps X2. The restart releases the vote
     for X2; node0 then gets X2 back and still has an attestation for it and
     for the next block.
  C. A restart with -reindex releases no vote: the index is still empty when
     the check would run.
"""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair

ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
RELEASED = "local vote(s) for blocks missing from the block index"


class MatMulSignerUncleanRestartReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        self.signer_wif = signer_wif
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
            "-matmulvalidation=consensus",
            # The model helper plays no part here. On macOS a helper whose btxd
            # was killed keeps running and holds the P2P port, so the restart
            # would fail to bind.
            "-modelnet=0",
        ]
        self.signer_args = common + [
            "-matmulattestationsignerkeyfile=SIGNERKEYFILE",
            "-matmulattestationserve=1",
        ]
        self.miner_args = common + ["-matmulattestationserve=0"]

    def setup_network(self):
        # A key file keeps stderr empty, which kill_process expects.
        keyfile = os.path.join(self.options.tmpdir, "matmul-attestor.wif")
        with open(keyfile, "w", encoding="utf8") as f:
            f.write(self.signer_wif + "\n")
        os.chmod(keyfile, 0o600)
        self.signer_args = [a.replace("SIGNERKEYFILE", keyfile) for a in self.signer_args]
        self.extra_args = [self.signer_args, self.miner_args]
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def signed(self, node, block_hash):
        try:
            return len(node.getmatmulattestations(block_hash)) > 0
        except Exception as e:
            self.last_error = str(e)
            return False

    def wait_signed(self, node, block_hash):
        self.wait_until(lambda: self.signed(node, block_hash), timeout=60)

    def mine_signed(self, n):
        signer, miner = self.nodes
        hashes = self.generate(miner, n, sync_fun=lambda: self.sync_blocks([signer, miner]))
        for block_hash in hashes:
            if signer.getblockheader(block_hash)["height"] >= ACTIVATION_HEIGHT:
                self.wait_signed(signer, block_hash)
        return hashes

    def run_test(self):
        signer, miner = self.nodes
        self.mine_signed(ACTIVATION_HEIGHT + 2)

        self.log.info("A: the signer signs X, is killed, and the network replaces X with Y")
        x = self.mine_signed(1)[0]
        height = miner.getblockcount()
        signer.kill_process()
        miner.invalidateblock(x)
        y = self.generate(miner, 1, sync_fun=self.no_op)[0]
        self.generate(miner, 1, sync_fun=self.no_op)
        with signer.assert_debug_log([RELEASED]):
            self.start_node(0, extra_args=self.signer_args)
        self.connect_nodes(0, 1)
        self.sync_blocks([signer, miner])
        assert_equal(signer.getblockhash(height), y)
        self.wait_signed(signer, y)
        self.wait_signed(signer, signer.getbestblockhash())

        self.log.info("B: the signer signs X2, is killed, and gets X2 back")
        x2 = self.mine_signed(1)[0]
        signer.kill_process()
        self.generate(miner, 1, sync_fun=self.no_op)
        # X2 itself must be released here, or B would not exercise the
        # reconnect that lifts the release. The count line alone can come from
        # the vote for X.
        with signer.assert_debug_log([RELEASED, f"active-chain disconnect of {x2}"]):
            self.start_node(0, extra_args=self.signer_args)
        self.connect_nodes(0, 1)
        self.sync_blocks([signer, miner])
        assert_equal(signer.getblockhash(miner.getblockheader(x2)["height"]), x2)
        self.wait_signed(signer, x2)
        self.wait_signed(signer, signer.getbestblockhash())

        self.log.info("C: -reindex releases nothing, the index is rebuilt later")
        tip = signer.getbestblockhash()
        with signer.assert_debug_log([], unexpected_msgs=[RELEASED]):
            self.restart_node(0, extra_args=self.signer_args + ["-reindex"])
            self.wait_until(lambda: signer.getbestblockhash() == tip, timeout=120)
        self.wait_signed(signer, tip)


if __name__ == "__main__":
    MatMulSignerUncleanRestartReorgTest(__file__).main()
