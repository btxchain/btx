#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A forged RC block must not cost an honest provisional relayer its peers.

Topology: attacker -> node1 <- node2, and node0 -- node1 to feed the chain.
node2 reaches node1 over an ordinary outbound-full-relay connection (manual
connections are exempt from parts of the punishment logic) and selects it for
high-bandwidth compact relay.

The attacker takes a valid RC tip child, sets matmul_digest to 1 (Phase 1
still passes, nothing else in the header changes) and grinds the cheap RCADMIT
ticket. node1 admits the block and, because -matmulrcprovisionalrelay is on,
relays it to node2 before its own ExactReplay finishes. node2's ExactReplay
then rejects the block as a Phase-2 failure. node1 only forwarded what it was
sent, so node2 must keep it as a peer and keep following the chain through it.

--no-provisional-relay runs node1 with -matmulrcprovisionalrelay=0 as a
control: node1 then never forwards the forged block.
"""

from test_framework.matmul_rc_admission import grind_rc_admission_ticket, msg_rcadmit
from test_framework.messages import CBlock, from_hex, msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

# V4 and RC activate together, as on mainnet. A V4-only (EncDr) height is
# never ExactReplay-verified and would stall the miner's own tip.
RC_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647


def tip_status(node, block_hash):
    for tip in node.getchaintips():
        if tip["hash"] == block_hash:
            return tip["status"]
    return None


class MatMulRCProvisionalPunishTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument(
            "--no-provisional-relay",
            action="store_true",
            help="control: run node1 with -matmulrcprovisionalrelay=0",
        )

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            "-debug=net",
            "-regtestmatmulbindingheight=2",
            f"-regtestmatmulproductdigestheight={DISABLED_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={RC_HEIGHT}",
            "-regtestmatmulv4dimension=128",
            f"-regtestbmx4cheight={RC_HEIGHT}",
            f"-regtestdrltheight={DISABLED_HEIGHT}",
            "-regtestmatmulltsealaspow=0",
            f"-regtestrcheight={RC_HEIGHT}",
            f"-regtestrccoupledheight={DISABLED_HEIGHT}",
            "-regtestrcprofile=1",
            "-regtestrctoydims=1",
            "-regtestrccoupledtoydims=0",
        ]
        relay = 0 if self.options.no_provisional_relay else 1
        self.extra_args = [
            common + ["-matmulrcprovisionalrelay=1"],
            common + [f"-matmulrcprovisionalrelay={relay}"],
            common + ["-matmulrcprovisionalrelay=1"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.nodes[2].addconnection(f"127.0.0.1:{p2p_port(1)}", "outbound-full-relay", False)
        self.wait_until(lambda: len(self.nodes[2].getpeerinfo()) == 1)
        self.wait_until(lambda: len(self.nodes[1].getpeerinfo()) == 2)

    def run_test(self):
        node0, node1, node2 = self.nodes

        self.log.info("Reach RC and let node2 select node1 for high-bandwidth relay")
        for _ in range(RC_HEIGHT + 1):
            self.generate(node0, 1)
        self.wait_until(lambda: node2.getpeerinfo()[0]["bip152_hb_to"], timeout=60)
        node1_id_on_node2 = node2.getpeerinfo()[0]["id"]

        self.log.info("Forge an RC tip child and grind its RCADMIT ticket")
        address = node0.get_deterministic_priv_key().address
        valid = from_hex(CBlock(), self.generateblock(
            node0, output=address, transactions=[], submit=False, sync_fun=self.no_op)["hex"])
        valid.rehash()
        forged = from_hex(CBlock(), valid.serialize().hex())
        assert valid.matmul_digest != 1
        forged.matmul_digest = 1
        forged.rehash()
        nonce = grind_rc_admission_ticket(forged)

        self.log.info("Send it to node1 from an inbound attacker")
        attacker = node1.add_p2p_connection(P2PInterface())
        relayed = f"matmul: provisionally relayed paid compact block hash={forged.hash}"
        if self.options.no_provisional_relay:
            expected, unexpected = [], [relayed]
        else:
            expected, unexpected = [relayed], []
        with node1.assert_debug_log(expected_msgs=expected, unexpected_msgs=unexpected, timeout=60):
            attacker.send_message(msg_rcadmit(forged.sha256, nonce))
            attacker.send_message(msg_block(forged))
            self.wait_until(lambda: tip_status(node1, forged.hash) == "invalid", timeout=60)
        if not self.options.no_provisional_relay:
            self.wait_until(lambda: tip_status(node2, forged.hash) == "invalid", timeout=60)

        self.log.info("node2 must keep node1, the honest relayer")
        # A pending fDisconnect is applied by the socket thread shortly after
        # BlockChecked; give it a moment before reading the peer set.
        try:
            self.wait_until(lambda: not node2.getpeerinfo(), timeout=5)
            dropped = True
        except AssertionError:
            dropped = False
        with open(node2.debug_log_path, encoding="utf-8", errors="replace") as log:
            charged = any(f"peer={node1_id_on_node2} Phase1-pass/Phase2-fail" in line for line in log)
        assert not charged, "node2 charged node1 on the Phase-2 punishment ladder"
        assert not dropped, "node2 disconnected node1"

        self.log.info("The honest block still reaches node2 through node1")
        assert_equal(node0.submitblock(valid.serialize().hex()), None)
        self.wait_until(lambda: node2.getbestblockhash() == valid.hash, timeout=60)


if __name__ == "__main__":
    MatMulRCProvisionalPunishTest(__file__).main()
