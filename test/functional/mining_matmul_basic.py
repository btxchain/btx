#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Basic MatMul mining RPC coverage."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MAX_BLOCK_SHIELDED_VERIFY_UNITS = 240_000
MAX_BLOCK_SHIELDED_SCAN_UNITS = 24_576
MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS = 24_576


class MiningMatMulBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-test=matmulstrict"]]

    def run_test(self):
        node = self.nodes[0]

        # TEST: mining_template_matmul_params
        # TEST: rpc_getblocktemplate_matmul
        # TEST: rpc_getblocktemplate_block_capacity
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["matmul_n"], 64)
        assert_equal(tmpl["matmul_b"], 8)
        assert_equal(tmpl["matmul_r"], 4)
        assert len(tmpl["seed_a"]) == 64
        assert len(tmpl["seed_b"]) == 64
        assert tmpl["seed_a"] != ("0" * 64)
        assert tmpl["seed_b"] != ("0" * 64)
        assert tmpl["matmul_b"] != tmpl["matmul_r"]
        assert_equal(tmpl["block_capacity"]["max_block_shielded_verify_units"], MAX_BLOCK_SHIELDED_VERIFY_UNITS)
        assert_equal(tmpl["block_capacity"]["max_block_shielded_scan_units"], MAX_BLOCK_SHIELDED_SCAN_UNITS)
        assert_equal(tmpl["block_capacity"]["max_block_shielded_tree_update_units"], MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS)
        assert_equal(tmpl["block_capacity"]["template_shielded_verify_units"], 0)
        assert_equal(tmpl["block_capacity"]["template_shielded_scan_units"], 0)
        assert_equal(tmpl["block_capacity"]["template_shielded_tree_update_units"], 0)

        # TEST: rpc_getmininginfo_algorithm
        # TEST: rpc_getmininginfo_reports_capacity
        info = node.getmininginfo()
        assert_equal(info["algorithm"], "matmul")
        assert_equal(info["powalgorithm"], "matmul")
        assert_equal(info["max_block_weight"], 24_000_000)
        assert_equal(info["policy_block_max_weight"], 24_000_000)
        assert_equal(info["max_block_shielded_verify_units"], MAX_BLOCK_SHIELDED_VERIFY_UNITS)
        assert_equal(info["max_block_shielded_scan_units"], MAX_BLOCK_SHIELDED_SCAN_UNITS)
        assert_equal(info["max_block_shielded_tree_update_units"], MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS)
        assert_equal(info["currentblockshieldedverifyunits"], 0)
        assert_equal(info["currentblockshieldedscanunits"], 0)
        assert_equal(info["currentblockshieldedtreeupdateunits"], 0)

        # TEST: mining_generate_block
        # TEST: rpc_getblock_matmul_verbose
        # TEST: mining_seeds_in_header
        mined = node.generateblock("raw(51)", [], called_by_framework=True)
        assert_equal(node.getbestblockhash(), mined["hash"])
        block = node.getblock(mined["hash"], 1)
        assert_equal(block["matmul_dim"], 64)
        assert len(block["matmul_digest"]) == 64
        assert len(block["seed_a"]) == 64
        assert len(block["seed_b"]) == 64
        header = node.getblockheader(mined["hash"], True)
        assert_equal(header["matmul_dim"], 64)
        assert len(header["matmul_digest"]) == 64
        assert len(header["seed_a"]) == 64
        assert len(header["seed_b"]) == 64
        assert header["seed_a"] != ("0" * 64)
        assert header["seed_b"] != ("0" * 64)

        # TEST: mining_chain_10_blocks
        start_height = node.getblockcount()
        for _ in range(10):
            seq = node.generateblock("raw(51)", [], called_by_framework=True)
            assert_equal(node.getbestblockhash(), seq["hash"])
        assert_equal(node.getblockcount(), start_height + 10)

        # TEST: submitblock_accepts_valid_matmul_block
        pending = node.generateblock("raw(51)", [], False, called_by_framework=True)
        assert_equal(node.submitblock(pending["hex"]), None)
        assert_equal(node.getbestblockhash(), pending["hash"])

        # TEST: mining_reject_tampered
        # TEST: rpc_submitblock_rejects_invalid
        invalid = node.generateblock("raw(51)", [], False, called_by_framework=True)
        bad_hex = invalid["hex"]
        digest_start = (4 + 32 + 32 + 4 + 4 + 8) * 2
        digest_end = digest_start + 64
        bad_hex = bad_hex[:digest_start] + ("f" * 64) + bad_hex[digest_end:]
        assert_equal(node.submitblock(bad_hex), "high-hash")
        assert node.getbestblockhash() != invalid["hash"]


if __name__ == "__main__":
    MiningMatMulBasicTest(__file__).main()
