#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BTX KAWPOW and reduced-data consensus coverage."""

from test_framework.messages import CBlock, CBlockHeader, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXKAWPOWConsensusTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Enable strict KAWPOW validation on regtest for consensus tests.
        self.extra_args = [["-test=matmulstrict"]]
        self.mining_output = "raw(51)"

    def _mine_block_hex(self, output):
        return self.generateblock(self.nodes[0], output, [], False, sync_fun=self.no_op)

    def _submit_generated_block(self, generated):
        assert_equal(self.nodes[0].submitblock(generated["hex"]), None)

    def test_header_serialization(self):
        node = self.nodes[0]
        generated = self._mine_block_hex(self.mining_output)
        self._submit_generated_block(generated)

        header_hex = node.getblockheader(generated["hash"], False)
        # BTX serializes an extended block header (182 bytes, 364 hex chars).
        # Keep this explicit so we notice accidental header format regressions.
        assert_equal(len(header_hex), 364)

        header = from_hex(CBlockHeader(), header_hex)
        header_json = node.getblockheader(generated["hash"], True)

        # nonce64 is part of the extended BTX header shape on MatMul chains.
        assert "nonce64" in header_json
        assert_equal(f"{header.nNonce64:016x}", header_json["nonce64"])

        # mixhash is only exposed when KAWPOW-related fields are active.
        if "mixhash" in header_json:
            assert_equal(f"{header.mixHash:064x}", header_json["mixhash"])
            return True
        return False

    def test_mixhash_rejection(self):
        node = self.nodes[0]
        generated = self._mine_block_hex(self.mining_output)

        bad_block = from_hex(CBlock(), generated["hex"])
        bad_block.mixHash = (bad_block.mixHash + 1) % (1 << 256)
        bad_block.rehash()

        assert_equal(node.submitblock(bad_block.serialize().hex()), "high-hash")
        self._submit_generated_block(generated)

    def test_reduced_data_limits(self):
        node = self.nodes[0]

        valid_script_34 = f"raw({'51' * 34})"
        self._submit_generated_block(self._mine_block_hex(valid_script_34))

        invalid_script_35 = f"raw({'51' * 35})"
        assert_equal(node.submitblock(self._mine_block_hex(invalid_script_35)["hex"]), "bad-txns-scriptpubkey-size")

        valid_opreturn_83 = f"raw(6a4c50{'11' * 80})"
        self._submit_generated_block(self._mine_block_hex(valid_opreturn_83))

        invalid_opreturn_85 = f"raw(6a4c52{'11' * 82})"
        assert_equal(node.submitblock(self._mine_block_hex(invalid_opreturn_85)["hex"]), "bad-txns-opreturn-size")

    def run_test(self):
        kawpow_fields_available = self.test_header_serialization()
        if kawpow_fields_available:
            self.test_mixhash_rejection()
        else:
            self.log.info("KAWPOW fields are disabled by consensus flags; skipping mixhash-specific rejection path.")
        self.test_reduced_data_limits()


if __name__ == "__main__":
    BTXKAWPOWConsensusTest(__file__).main()
