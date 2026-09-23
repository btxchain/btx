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

import hashlib
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error

# Thin SCRIPT-03/09/11 pointer. Do not subclass WalletHtlcAtomicSwapTest here
# (that test is already in test_runner.py --descriptors).
SCRIPT_03_09_11 = "wallet_htlc_atomicswap.py"


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
            "-modelbind=off",
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
        # These coins are mined block rewards: the same mature coinbase that
        # funds release-campaign HTLCs and bounty lots.
        funder = node.get_wallet_rpc(self.default_wallet_name)
        funding_addr = funder.getnewaddress()
        self.generatetoaddress(self.nodes[0], 101, funding_addr)

        node.createwallet(wallet_name="release_claimer")
        claimer = node.get_wallet_rpc("release_claimer")
        claimer_pk = claimer.exportpqkey(claimer.getnewaddress())["pubkey"]
        refund_pk = funder.exportpqkey(funder.getnewaddress())["pubkey"]
        preimage = bytes.fromhex("42" * 32)
        key_hash = hashlib.sha256(preimage).hexdigest()
        fee_sat = 1_000_000
        amount_atoms = 10_000_000

        options = {
            "key_hash": key_hash,
            "claimant": claimer_pk,
            "refund_pubkey": refund_pk,
            "refund_height": max(node.getblockcount() + 1000, 1024),
            "amount_atoms": amount_atoms,
            "auto_pay": False,
            "assurance": "KEY_RELEASE_ONLY",
            "assurance_mode": "KEY_RELEASE_ONLY",
        }
        frozen = self.prepare(funder, options)
        assert_zero_spend(frozen)
        assert_equal(frozen["htlc"], "htlc_sha256")
        desc = frozen["descriptor"]
        assert "htlc_sha256(" in desc
        assert "htlc_sha256_tx" not in desc
        assert "htlc_tx(" not in desc
        unsigned = frozen["unsigned_hex"]

        signed = funder.signmodelfunding(unsigned, frozen)
        assert_zero_spend(signed)
        if not signed.get("complete"):
            raise AssertionError(f"signmodelfunding incomplete: {signed}")

        submitted = funder.submitmodelfunding(signed["hex"], frozen)
        assert_zero_spend(submitted)
        assert_equal(submitted["duplicate"], False)
        txid = submitted["txid"]
        # SCRIPT-11: block vs relay — funding is in mempool, then one confirmation.
        # SCRIPT-03/09 (correct claim mined; post-H claim/refund race) remain
        # wallet_htlc_atomicswap.py --descriptors (no htlc_sha256_tx).
        mempool = node.getrawmempool()
        assert txid in mempool, submitted
        self.generatetoaddress(self.nodes[0], 1, funding_addr)
        # After mining the tx leaves mempool. Avoid wallet gettransaction:
        # coverage.py type-checks its result against RPCHelpMan.
        assert txid not in node.getrawmempool()
        tip = node.getblock(node.getbestblockhash(), 2)
        mined = [tx["txid"] if isinstance(tx, dict) else tx for tx in tip["tx"]]
        assert txid in mined, mined
        assert "htlc_sha256" in frozen["descriptor"]
        assert_equal(frozen["htlc"], "htlc_sha256")
        refuse_hash160(funder, {"htlc": "htlc_tx", "assurance": "KEY_RELEASE_ONLY"})

        dup = funder.submitmodelfunding(signed["hex"], frozen)
        assert_equal(dup["duplicate"], True)
        assert_equal(dup["submitted"], False)
        assert_zero_spend(dup)
        assert_equal(dup["txid"], submitted["txid"])

        info = node.getdescriptorinfo(frozen["descriptor"])
        desc_ck = frozen["descriptor"]
        if "#" not in desc_ck:
            desc_ck = f"{desc_ck}#{info['checksum']}"
        lock_addr = node.deriveaddresses(desc_ck)[0]
        decoded = node.decoderawtransaction(signed["hex"])
        vout_n = None
        for vout in decoded["vout"]:
            spk = vout.get("scriptPubKey") or {}
            if lock_addr in (spk.get("address"), spk.get("addresses", [None])[0] if spk.get("addresses") else None):
                vout_n = int(vout["n"])
                break
            if frozen.get("output_script") and spk.get("hex") == frozen.get("output_script"):
                vout_n = int(vout["n"])
                break
        if vout_n is None:
            raise AssertionError(f"HTLC vout missing in {decoded['vout']}")

        dest = claimer.getnewaddress()
        built = claimer.buildhtlcclaim(
            desc_ck, {"txid": txid, "vout": vout_n}, preimage.hex(), dest, fee_sat)
        assert_equal(built["complete"], True)
        claim_txid = node.sendrawtransaction(built["hex"])
        self.generatetoaddress(self.nodes[0], 1, funding_addr)
        assert claim_txid not in node.getrawmempool()
        got = Decimal(str(claimer.getreceivedbyaddress(dest)))
        expect = Decimal(amount_atoms - fee_sat) / Decimal(100000000)
        assert_equal(got, expect)

        # Second campaign lot: refund after CLTV without revealing the preimage.
        refund_preimage = bytes.fromhex("a5" * 32)
        refund_hash = hashlib.sha256(refund_preimage).hexdigest()
        refund_height = node.getblockcount() + 6
        refund_opts = {
            "key_hash": refund_hash,
            "claimant": claimer_pk,
            "refund_pubkey": refund_pk,
            "refund_height": refund_height,
            "amount_atoms": amount_atoms,
            "auto_pay": False,
            "assurance": "KEY_RELEASE_ONLY",
        }
        frozen_r = self.prepare(funder, refund_opts)
        assert_equal(frozen_r["htlc"], "htlc_sha256")
        signed_r = funder.signmodelfunding(frozen_r["unsigned_hex"], frozen_r)
        assert signed_r.get("complete"), signed_r
        sub_r = funder.submitmodelfunding(signed_r["hex"], frozen_r)
        self.generatetoaddress(self.nodes[0], 1, funding_addr)
        info_r = node.getdescriptorinfo(frozen_r["descriptor"])
        desc_r = frozen_r["descriptor"]
        if "#" not in desc_r:
            desc_r = f"{desc_r}#{info_r['checksum']}"
        addr_r = node.deriveaddresses(desc_r)[0]
        decoded_r = node.decoderawtransaction(signed_r["hex"])
        vout_r = None
        for vout in decoded_r["vout"]:
            spk = vout.get("scriptPubKey") or {}
            if addr_r in (spk.get("address"),):
                vout_r = int(vout["n"])
                break
        if vout_r is None:
            raise AssertionError("refund HTLC vout missing")
        refund_dest = funder.getnewaddress()
        early = funder.buildhtlcrefund(
            desc_r, {"txid": sub_r["txid"], "vout": vout_r},
            refund_dest, refund_height, fee_sat)
        assert_equal(early.get("complete"), True)
        decoded_early = node.decoderawtransaction(early["hex"])
        assert_equal(decoded_early["locktime"], refund_height)
        if decoded_early["vin"][0]["sequence"] == 0xffffffff:
            raise AssertionError("refund sequence must be non-final for CLTV")
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, early["hex"])
        while node.getblockcount() < refund_height:
            self.generatetoaddress(self.nodes[0], 1, funding_addr)
        refunded = funder.buildhtlcrefund(
            desc_r, {"txid": sub_r["txid"], "vout": vout_r},
            refund_dest, refund_height, fee_sat)
        assert_equal(refunded["complete"], True)
        refund_txid = node.sendrawtransaction(refunded["hex"])
        self.generatetoaddress(self.nodes[0], 1, funding_addr)
        assert refund_txid not in node.getrawmempool()
        got_r = Decimal(str(funder.getreceivedbyaddress(refund_dest)))
        assert_equal(got_r, expect)
        self.log.info("release-campaign HTLC fund+claim+refund ok")


if __name__ == "__main__":
    ModelnetFundingTest(__file__).main()
