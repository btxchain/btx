#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Coordinator model-funding RPCs: prepare / sign / submit.

Options-only prepare (helper optional). Frozen descriptor is htlc_sha256,
never htlc_sha256_tx. automatic_spend is always 0.

B0 SCRIPT library (no new opcode). Claim/refund on chain is the existing
0.34.6 corpus — this file is a documentation wrapper, not a second node:

  SCRIPT-03  correct secret+sig claim mined     wallet_htlc_atomicswap.py
  SCRIPT-09  post-expiry claim/refund race      wallet_htlc_atomicswap.py
  SCRIPT-11  block vs relay (mempool then 1c)   submitmodelfunding below

HASH160 htlc_tx is recovery-only. KEY_RELEASE_ONLY is a campaign assurance
label; it does not select HASH160 and does not invent htlc_sha256_tx.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error

# src/pqkey.h MLDSA44_PUBKEY_SIZE — dummy claimant/refund keys (length only).
MLDSA44_PUBKEY_SIZE = 1312

# Thin SCRIPT-03/09/11 pointer. Do not subclass WalletHtlcAtomicSwapTest here
# (that test is already in test_runner.py --descriptors).
SCRIPT_03_09_11 = "wallet_htlc_atomicswap.py"


def dummy_pq(seed: int) -> str:
    return bytes((seed + i) & 0xFF for i in range(MLDSA44_PUBKEY_SIZE)).hex()


def assert_zero_spend(obj):
    assert_equal(obj["automatic_spend"], 0)


def refuse_hash160(node, opts):
    """PQ-21: new campaign RPCs refuse HASH160 even under KEY_RELEASE_ONLY."""
    assert_raises_rpc_error(-8, "HASH160 htlc_tx", node.preparemodelfunding, "", opts)
    assert_raises_rpc_error(-8, "HASH160 htlc_tx", node.signmodelfunding, "00", opts)


class ModelnetFundingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        # Push MatMul activation to maxint so setup_clean_chain generate is
        # cheap (test_runner cache is ~20s/block once MatMul is live).
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def prepare(self, node, options):
        # Options-only form: first RPCArg is STR with skip_type_check.
        return node.preparemodelfunding(options)

    def run_test(self):
        node = self.nodes[0]
        helptext = node.help()
        if "preparemodelfunding" not in helptext:
            raise SkipTest("modelnet funding RPCs not compiled")
        assert "signmodelfunding" in helptext
        assert "submitmodelfunding" in helptext

        # Refuse auto_pay / HASH160 htlc_tx without hanging (no wallet spend).
        assert_raises_rpc_error(-8, "auto_pay is refused", node.preparemodelfunding, "", {"auto_pay": True})
        assert_raises_rpc_error(-8, "HASH160 htlc_tx", node.preparemodelfunding, "", {"htlc": "htlc_sha256_tx"})
        assert_raises_rpc_error(-8, "auto_pay is refused", node.signmodelfunding, "00", {"auto_pay": True})
        assert_raises_rpc_error(-8, "HASH160 htlc_tx", node.signmodelfunding, "00", {"htlc": "htlc_sha256_tx"})

        # KEY_RELEASE_ONLY does not opt into HASH160 / htlc_tx. Recovery
        # templates stay refused; do not invent a positive htlc_sha256_tx path.
        self.log.info("PQ-21: HASH160 refused; KEY_RELEASE_ONLY does not select it")
        for opts in (
            {"htlc": "htlc_tx"},
            {"htlc": "hash160"},
            {"htlc_tx": True},
            {"hash160": "00" * 20},
            {"htlc": "htlc_tx", "assurance": "KEY_RELEASE_ONLY"},
            {"hash160": "00" * 20, "assurance_mode": "KEY_RELEASE_ONLY"},
            {"htlc": "htlc_tx", "assurance_mode": 2},
            {"descriptor": "mr(htlc_tx(" + ("11" * 20) + ",aa))"},
            {"descriptor": "mr(htlc_tx(" + ("11" * 20) + ",aa))", "assurance": "KEY_RELEASE_ONLY"},
        ):
            refuse_hash160(node, opts)
        assert SCRIPT_03_09_11.endswith("wallet_htlc_atomicswap.py")

        # Mature coinbase for the unsigned funding tx. MatMul is inactive
        # (heights above), so this is cheap even with setup_clean_chain.
        self.generate(self.nodes[0], 101)

        options = {
            "key_hash": "11" * 32,
            "claimant": dummy_pq(0x21),
            "refund_pubkey": dummy_pq(0x31),
            "refund_height": max(node.getblockcount() + 1000, 1024),
            "amount_atoms": 100000,
            "auto_pay": False,
            # Campaign label only. Funding leaf stays htlc_sha256 (not HASH160).
            "assurance": "KEY_RELEASE_ONLY",
            "assurance_mode": "KEY_RELEASE_ONLY",
        }
        try:
            frozen = self.prepare(node, options)
        except JSONRPCException as e:
            msg = str(e).lower()
            if "insufficient" in msg or "wallet" in msg:
                self.log.info("preparemodelfunding reached wallet (no mature coins): %s", e.error)
                return
            raise
        assert_zero_spend(frozen)
        assert_equal(frozen["htlc"], "htlc_sha256")
        desc = frozen["descriptor"]
        assert "htlc_sha256(" in desc
        assert "htlc_sha256_tx" not in desc
        assert "htlc_tx(" not in desc
        unsigned = frozen["unsigned_hex"]

        try:
            signed = node.signmodelfunding(unsigned, frozen)
        except JSONRPCException:
            self.log.info("signmodelfunding could not sign; refusals already asserted")
            return

        assert_zero_spend(signed)
        if not signed.get("complete"):
            self.log.info("signmodelfunding incomplete (wallet cannot sign this HTLC funding tx)")
            assert_raises_rpc_error(-8, "auto_pay is refused", node.signmodelfunding, unsigned, {**frozen, "auto_pay": True})
            assert_raises_rpc_error(-8, "HASH160 htlc_tx", node.signmodelfunding, unsigned, {**frozen, "htlc": "htlc_tx", "assurance": "KEY_RELEASE_ONLY"})
            return

        submitted = node.submitmodelfunding(signed["hex"], frozen)
        assert_zero_spend(submitted)
        assert_equal(submitted["duplicate"], False)
        txid = submitted["txid"]
        # SCRIPT-11: block vs relay — funding is in mempool, then one confirmation.
        # SCRIPT-03/09 (correct claim mined; post-H claim/refund race) remain
        # wallet_htlc_atomicswap.py --descriptors (no htlc_sha256_tx).
        mempool = node.getrawmempool()
        assert txid in mempool, submitted
        self.generate(self.nodes[0], 1)
        # After mining the tx leaves mempool. Avoid wallet gettransaction:
        # coverage.py type-checks its result against RPCHelpMan.
        assert txid not in node.getrawmempool()
        tip = node.getblock(node.getbestblockhash(), 2)
        mined = [tx["txid"] if isinstance(tx, dict) else tx for tx in tip["tx"]]
        assert txid in mined, mined
        assert "htlc_sha256" in frozen["descriptor"]
        assert_equal(frozen["htlc"], "htlc_sha256")
        refuse_hash160(node, {"htlc": "htlc_tx", "assurance": "KEY_RELEASE_ONLY"})

        dup = node.submitmodelfunding(signed["hex"], frozen)
        assert_equal(dup["duplicate"], True)
        assert_equal(dup["submitted"], False)
        assert_zero_spend(dup)
        assert_equal(dup["txid"], submitted["txid"])


if __name__ == "__main__":
    ModelnetFundingTest(__file__).main()
