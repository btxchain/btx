#!/usr/bin/env python3
# Copyright (c) 2026 The BTX Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end proof that validation-epoch self-heal works on a real datadir.

The in-process unit tests (validation_epoch_*) never restart a node. This
harness poisons a throwaway regtest datadir the way a 0.34.0–0.34.4 binary
did — BLOCK_FAILED_VALID on disk, persisted epoch older than the compiled
one — then restarts btxd and asserts the startup heal log and the resulting
tip. Three cases:

  1. Rescue: a valid heaviest-work block was marked FAILED (no MANUAL bit).
     Heal must clear the mark, re-validate, and ActivateBestChain must follow it.
  2. Safety: a genuinely invalid body (CheckBlock fails) is marked FAILED.
     Heal must re-mark it invalid. The active tip must not move onto it.
  3. Operator intent: invalidateblock set BLOCK_MANUALLY_INVALIDATED.
     Heal must leave it failed; the operator fork must not resurrect.

Do not weaken an assertion to make a case pass. A failure here is a
release blocker (PR 128 / 0.34.5).
"""

import re

from test_framework.messages import BLOCK_HEADER_SIZE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    util_xor,
)

HEAL_SUMMARY_RE = re.compile(
    r"validation epoch (\d+) -> (\d+): cleared (\d+) BLOCK_FAILED_\* mark\(s\) "
    r"on the heaviest-work lineage, re-checked headers/bodies, "
    r"re-marked (\d+), unparked (\d+), left (\d+) operator-invalid"
)


class ValidationEpochHealTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # Isolate the three cases. Zero hysteresis so a 1-block reorg back
        # onto the rescued tip is not deferred (unit tests do the same).
        common = [
            "-reorghysteresisdepth=0",
            "-reorghysteresisworkmargin=0",
        ]
        self.extra_args = [common, common, common]

    def setup_network(self):
        self.setup_nodes()

    def mine(self, node, n):
        addr = node.get_deterministic_priv_key().address
        self.generatetoaddress(node, n, addr, sync_fun=self.no_op)

    def chaintip(self, node, blockhash):
        for tip in node.getchaintips():
            if tip["hash"] == blockhash:
                return tip
        return None

    def parse_heal(self, log_chunk):
        matches = list(HEAL_SUMMARY_RE.finditer(log_chunk))
        if not matches:
            raise AssertionError(
                "validation-epoch heal summary missing from restart log:\n" + log_chunk
            )
        m = matches[-1]
        line = m.group(0)
        stats = {
            "line": line,
            "stored": int(m.group(1)),
            "compiled": int(m.group(2)),
            "cleared": int(m.group(3)),
            "remarked": int(m.group(4)),
            "unparked": int(m.group(5)),
            "left_manual": int(m.group(6)),
        }
        self.log.info("heal: " + line)
        return stats

    def restart_and_heal(self, node):
        """Stop, start, return (heal stats, new log text). Heal runs during init."""
        log_path = node.debug_log_path
        prev_size = log_path.stat().st_size if log_path.exists() else 0
        self.stop_node(node.index)
        self.start_node(node.index)
        with open(log_path, encoding="utf-8", errors="replace") as f:
            f.seek(prev_size)
            chunk = f.read()
        return self.parse_heal(chunk), chunk

    def corrupt_block_body(self, node, raw_hex):
        """Flip one byte in the first transaction of a serialized block on disk.

        The header (and therefore the index hash) is left intact so the heal
        still finds HAVE_DATA and CheckBlock fails the merkle check.
        """
        raw = bytes.fromhex(raw_hex)
        xor_key = node.read_xor_key()
        blk_path = node.blocks_path / "blk00000.dat"
        with open(blk_path, "r+b") as bf:
            on_disk = bf.read()
            decoded = bytearray(util_xor(on_disk, xor_key, offset=0))
            pos = decoded.find(raw)
            if pos < 0:
                raise AssertionError("serialized block not found in blk00000.dat")
            flip_at = pos + BLOCK_HEADER_SIZE + 20
            if flip_at >= len(decoded):
                raise AssertionError("corrupt offset past end of blk00000.dat")
            decoded[flip_at] ^= 0xFF
            bf.seek(0)
            bf.write(util_xor(bytes(decoded), xor_key, offset=0))
            bf.truncate()
        self.log.info(f"corrupted blk00000.dat byte at offset {flip_at}")

    def case_rescue(self, node):
        self.log.info("CASE 1 — rescue a valid heaviest-work block")
        self.mine(node, 6)
        original = node.getblockchaininfo()
        original_height = original["blocks"]
        original_hash = original["bestblockhash"]
        poison_hash = original_hash
        before = node.getblockindexstatus(poison_hash)
        assert_equal(before["failed_valid"], False)
        assert_equal(before["manually_invalidated"], False)
        assert_equal(before["have_data"], True)
        self.log.info(
            f"before poison: height={original_height} hash={original_hash} "
            f"nStatus={before['nStatus']}"
        )

        node.invalidateblock(poison_hash)
        after_invalidate = node.getblockindexstatus(poison_hash)
        disconnected = node.getblockchaininfo()
        assert_equal(after_invalidate["failed_valid"], True)
        assert_equal(after_invalidate["manually_invalidated"], True)
        assert_equal(disconnected["blocks"], original_height - 1)
        assert disconnected["bestblockhash"] != original_hash
        invalid_tip = self.chaintip(node, poison_hash)
        assert invalid_tip is not None
        assert_equal(invalid_tip["status"], "invalid")
        self.log.info(
            f"after invalidateblock: height={disconnected['blocks']} "
            f"hash={disconnected['bestblockhash']} "
            f"poison nStatus={after_invalidate['nStatus']} "
            f"manually_invalidated={after_invalidate['manually_invalidated']}"
        )

        mock = node.mockvalidationepoch(0, True)
        assert_greater_than(mock["stripped_manual"], 0)
        poisoned = node.getblockindexstatus(poison_hash)
        assert_equal(poisoned["failed_valid"], True)
        assert_equal(poisoned["manually_invalidated"], False)
        self.log.info(
            f"poisoned index (FAILED, no MANUAL), stored epoch=0, "
            f"stripped_manual={mock['stripped_manual']} nStatus={poisoned['nStatus']}"
        )

        heal, chunk = self.restart_and_heal(node)
        assert_equal(heal["stored"], 0)
        assert_greater_than(heal["compiled"], 0)
        assert_greater_than(heal["cleared"], 0)
        assert_equal(heal["remarked"], 0)
        if f"clearing failure flags for block {poison_hash}" not in chunk:
            raise AssertionError(
                f"heal did not log clearing {poison_hash}:\n{chunk}"
            )

        restored = node.getblockchaininfo()
        status = node.getblockindexstatus(poison_hash)
        self.log.info(
            f"after heal restart: height={restored['blocks']} "
            f"hash={restored['bestblockhash']} "
            f"failed_valid={status['failed_valid']} "
            f"manually_invalidated={status['manually_invalidated']}"
        )
        assert_equal(restored["blocks"], original_height)
        assert_equal(restored["bestblockhash"], original_hash)
        assert_equal(status["failed_valid"], False)
        assert_equal(status["failed_child"], False)
        assert_equal(status["manually_invalidated"], False)
        active = self.chaintip(node, original_hash)
        assert active is not None
        assert_equal(active["status"], "active")
        self.log.info("CASE 1 PASS")
        return heal

    def case_safety(self, node):
        self.log.info("CASE 2 — genuinely invalid body must be re-marked, tip must not follow")
        self.mine(node, 6)
        original = node.getblockchaininfo()
        original_height = original["blocks"]
        original_hash = original["bestblockhash"]
        parent_hash = node.getblockhash(original_height - 1)
        raw_hex = node.getblock(original_hash, 0)

        node.invalidateblock(original_hash)
        mock = node.mockvalidationepoch(0, True)
        assert_greater_than(mock["stripped_manual"], 0)
        poisoned = node.getblockindexstatus(original_hash)
        assert_equal(poisoned["failed_valid"], True)
        assert_equal(poisoned["manually_invalidated"], False)
        assert_equal(poisoned["have_data"], True)
        disconnected_height = node.getblockcount()
        assert_equal(disconnected_height, original_height - 1)
        self.log.info(
            f"poisoned valid-looking index for {original_hash} at height "
            f"{original_height}; body will be corrupted on disk"
        )

        self.stop_node(node.index)
        self.corrupt_block_body(node, raw_hex)
        log_path = node.debug_log_path
        prev_size = log_path.stat().st_size if log_path.exists() else 0
        self.start_node(node.index)
        with open(log_path, encoding="utf-8", errors="replace") as f:
            f.seek(prev_size)
            chunk = f.read()
        heal = self.parse_heal(chunk)
        assert_equal(heal["stored"], 0)
        assert_greater_than(heal["cleared"], 0)
        assert_greater_than(heal["remarked"], 0)
        if f"re-marked {original_hash}" not in chunk:
            raise AssertionError(
                f"heal did not re-mark genuinely invalid {original_hash}:\n{chunk}"
            )

        after = node.getblockchaininfo()
        status = node.getblockindexstatus(original_hash)
        invalid_tip = self.chaintip(node, original_hash)
        self.log.info(
            f"after heal restart: height={after['blocks']} "
            f"hash={after['bestblockhash']} "
            f"failed_valid={status['failed_valid']} "
            f"chaintip={invalid_tip}"
        )
        assert_equal(after["bestblockhash"], parent_hash)
        assert after["blocks"] < original_height
        assert_equal(status["failed_valid"], True)
        assert_equal(status["manually_invalidated"], False)
        assert invalid_tip is not None
        assert_equal(invalid_tip["status"], "invalid")
        self.log.info("CASE 2 PASS")
        return heal

    def case_operator(self, node):
        self.log.info("CASE 3 — operator invalidateblock must not resurrect")
        self.mine(node, 6)
        original = node.getblockchaininfo()
        original_height = original["blocks"]
        original_hash = original["bestblockhash"]
        parent_hash = node.getblockhash(original_height - 1)

        node.invalidateblock(original_hash)
        after_invalidate = node.getblockindexstatus(original_hash)
        assert_equal(after_invalidate["failed_valid"], True)
        assert_equal(after_invalidate["manually_invalidated"], True)
        self.log.info(
            f"operator invalidateblock {original_hash} "
            f"nStatus={after_invalidate['nStatus']} "
            f"manually_invalidated=True"
        )

        mock = node.mockvalidationepoch(0, False)
        assert_equal(mock["stripped_manual"], 0)
        still_manual = node.getblockindexstatus(original_hash)
        assert_equal(still_manual["manually_invalidated"], True)
        assert_equal(still_manual["failed_valid"], True)

        heal, chunk = self.restart_and_heal(node)
        assert_equal(heal["stored"], 0)
        assert_greater_than(heal["left_manual"], 0)
        if f"clearing failure flags for block {original_hash}" in chunk:
            raise AssertionError(
                f"heal cleared operator-invalid {original_hash}:\n{chunk}"
            )

        after = node.getblockchaininfo()
        status = node.getblockindexstatus(original_hash)
        invalid_tip = self.chaintip(node, original_hash)
        self.log.info(
            f"after heal restart: height={after['blocks']} "
            f"hash={after['bestblockhash']} "
            f"failed_valid={status['failed_valid']} "
            f"manually_invalidated={status['manually_invalidated']}"
        )
        assert_equal(after["bestblockhash"], parent_hash)
        assert_equal(after["blocks"], original_height - 1)
        assert_equal(status["failed_valid"], True)
        assert_equal(status["manually_invalidated"], True)
        assert invalid_tip is not None
        assert_equal(invalid_tip["status"], "invalid")
        self.log.info("CASE 3 PASS")
        return heal

    def run_test(self):
        heal1 = self.case_rescue(self.nodes[0])
        heal2 = self.case_safety(self.nodes[1])
        heal3 = self.case_operator(self.nodes[2])
        self.log.info("CASE 1 heal line: " + heal1["line"])
        self.log.info("CASE 2 heal line: " + heal2["line"])
        self.log.info("CASE 3 heal line: " + heal3["line"])


if __name__ == "__main__":
    ValidationEpochHealTest(__file__).main()
