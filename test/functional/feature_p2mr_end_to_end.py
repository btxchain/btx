#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal
import json

from test_framework.messages import (
    CTransaction,
    CTxInWitness,
    from_hex,
    ser_compact_size,
    sha256,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

import os


class P2MREndToEndTest(BitcoinTestFramework):
    P2MR_LEAF_VERSION = 0xC2
    OP_CHECKTEMPLATEVERIFY = 0xB3
    OP_CHECKSIG_MLDSA = 0xBB
    OP_CHECKSIGFROMSTACK = 0xBD

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]
        # P2MR signing can exceed default 60s RPC timeouts under parallel
        # functional load on slower hosts.
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_p2mr_address(self, address):
        assert address.startswith("btxrt1z")

    def sats_to_btc(self, sats):
        return Decimal(sats) / Decimal(100_000_000)

    def get_single_address_for_descriptor(self, node, descriptor_no_checksum):
        descriptor = node.getdescriptorinfo(descriptor_no_checksum)["descriptor"]
        return node.deriveaddresses(descriptor)[0]

    def find_vout_for_address(self, wallet, txid, address):
        decoded = wallet.decoderawtransaction(wallet.gettransaction(txid)["hex"])
        for vout in decoded.get("vout", []):
            if vout.get("scriptPubKey", {}).get("address") == address:
                value_sat = int(Decimal(str(vout["value"])) * Decimal(100_000_000))
                return vout["n"], value_sat
        raise AssertionError(f"address {address} not found in tx {txid}")

    @staticmethod
    def compute_ctv_hash(tx, n_in):
        preimage = b""
        preimage += (tx.version & 0xFFFFFFFF).to_bytes(4, "little")
        preimage += (tx.nLockTime & 0xFFFFFFFF).to_bytes(4, "little")

        has_scriptsigs = any(len(txin.scriptSig) > 0 for txin in tx.vin)
        if has_scriptsigs:
            scriptsigs_ser = b"".join(ser_compact_size(len(txin.scriptSig)) + txin.scriptSig for txin in tx.vin)
            preimage += sha256(scriptsigs_ser)

        preimage += (len(tx.vin) & 0xFFFFFFFF).to_bytes(4, "little")
        sequences_ser = b"".join((txin.nSequence & 0xFFFFFFFF).to_bytes(4, "little") for txin in tx.vin)
        preimage += sha256(sequences_ser)

        preimage += (len(tx.vout) & 0xFFFFFFFF).to_bytes(4, "little")
        outputs_ser = b"".join(txout.serialize() for txout in tx.vout)
        preimage += sha256(outputs_ser)
        preimage += (n_in & 0xFFFFFFFF).to_bytes(4, "little")
        return sha256(preimage)

    @staticmethod
    def tagged_hash(tag, payload):
        tag_hash = sha256(tag.encode("utf8"))
        return sha256(tag_hash + tag_hash + payload)

    def compute_p2mr_leaf_hash(self, leaf_script):
        payload = bytes([self.P2MR_LEAF_VERSION]) + ser_compact_size(len(leaf_script)) + leaf_script
        return self.tagged_hash("P2MRLeaf", payload)

    def build_mldsa_checksig_leaf_script(self, pubkey_bytes):
        assert_equal(len(pubkey_bytes), 1312)
        return bytes([0x4D, 0x20, 0x05]) + pubkey_bytes + bytes([self.OP_CHECKSIG_MLDSA])

    def raw_with_witness(self, raw_hex, witness_stack):
        tx = from_hex(CTransaction(), raw_hex)
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx.serialize_with_witness().hex()

    def load_csfs_vectors(self):
        if not hasattr(self, "_csfs_vectors"):
            path = os.path.join(os.path.dirname(__file__), "data", "pq_csfs_vectors.json")
            with open(path, encoding="utf8") as f:
                self._csfs_vectors = json.load(f)
        return self._csfs_vectors

    def build_mldsa_csfs_leaf_script(self):
        vectors = self.load_csfs_vectors()
        pubkey = bytes.fromhex(vectors["mldsa_pubkey_hex"])
        assert_equal(len(pubkey), 1312)
        return bytes([0x4D, 0x20, 0x05]) + pubkey + bytes([self.OP_CHECKSIGFROMSTACK])

    def assert_p2mr_wallet_tx(self, wallet, txid, *, expect_algo="any"):
        """Assert the happy-path P2MR witness_v2 spend format end-to-end.

        This validates that wallet signing produces a witness stack compatible
        with consensus and that decoded outputs remain witness_v2_p2mr.
        """
        tx = wallet.gettransaction(txid)
        assert tx.get("confirmations", 0) >= 1
        decoded = self.nodes[0].decoderawtransaction(tx["hex"])

        vins = decoded.get("vin", [])
        assert len(vins) >= 1
        for vin in vins:
            witness = vin.get("txinwitness", [])
            # P2MR spends always provide [sig, leaf_script, control_block].
            assert_equal(len(witness), 3)
            sizes = [len(bytes.fromhex(item)) for item in witness]
            sig_size, script_size, control_size = sizes

            if expect_algo == "mldsa":
                assert_equal(sig_size, 2420)
                # ML-DSA leaf script: push 1312-byte pubkey + opcode overhead.
                assert script_size >= 1316
            elif expect_algo == "slhdsa":
                assert_equal(sig_size, 7856)
                # SLH leaf script: push32 pubkey + opcode.
                assert script_size >= 34
            elif expect_algo == "any":
                assert sig_size in (2420, 7856)
                if sig_size == 2420:
                    assert script_size >= 1316
                else:
                    assert script_size >= 34
            else:
                raise AssertionError(f"unknown expect_algo: {expect_algo}")

            # Default wallet descriptor is 2-leaf, so control block includes sibling hash.
            assert_equal(control_size, 33)

        vouts = decoded.get("vout", [])
        assert len(vouts) >= 1
        for vout in vouts:
            spk = vout.get("scriptPubKey", {})
            assert_equal(spk.get("type"), "witness_v2_p2mr")
            addr = spk.get("address")
            if addr is not None:
                self.assert_p2mr_address(addr)

    def mine_to_wallet(self, node, wallet, blocks, *, sync_fun):
        mine_addr = wallet.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(mine_addr)
        self.generatetoaddress(node, blocks, mine_addr, sync_fun=sync_fun)
        return mine_addr

    def send_and_confirm(self, sender, receiver, amount, miner_node, miner_wallet):
        recv = receiver.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(recv)
        txid = sender.sendtoaddress(recv, Decimal(amount))
        self.mine_to_wallet(miner_node, miner_wallet, 1, sync_fun=self.sync_all)
        self.assert_p2mr_wallet_tx(sender, txid, expect_algo="any")
        # Regression: sender must still be able to derive new P2MR addresses after spending.
        # This previously triggered a deterministic node crash in getnewaddress.
        next_addr = sender.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(next_addr)
        return txid

    def test_mine_and_spend_p2mr(self, n0, n1, w0, w1):
        self.log.info("test_mine_and_spend_p2mr")
        # Mine enough blocks so many coinbase outputs are mature and usable for
        # later high-load spend tests.
        self.mine_to_wallet(n0, w0, 220, sync_fun=self.sync_all)

        txid01 = self.send_and_confirm(w0, w1, "5.0", n0, w0)
        txid10 = self.send_and_confirm(w1, w0, "1.0", n1, w1)

        assert w1.gettransaction(txid01)["confirmations"] >= 1
        assert w0.gettransaction(txid10)["confirmations"] >= 1
        assert len(w0.listunspent()) > 0
        assert len(w1.listunspent()) > 0

    def test_multiple_wallets_p2mr(self, n0, n1, w0):
        self.log.info("test_multiple_wallets_p2mr")
        n0.createwallet(wallet_name="w0_alt", descriptors=True)
        n1.createwallet(wallet_name="w1_alt", descriptors=True)
        w0_alt = n0.get_wallet_rpc("w0_alt")
        w1_alt = n1.get_wallet_rpc("w1_alt")

        txid01 = self.send_and_confirm(w0, w1_alt, "2.5", n0, w0)
        txid10 = self.send_and_confirm(w1_alt, w0_alt, "0.5", n1, w1_alt)

        assert w1_alt.gettransaction(txid01)["confirmations"] >= 1
        assert w0_alt.gettransaction(txid10)["confirmations"] >= 1

    def test_reorg_p2mr(self, n0, n1, w0, w1):
        self.log.info("test_reorg_p2mr")
        self.disconnect_nodes(0, 1)

        reorg_recv = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(reorg_recv)
        txid = w0.sendtoaddress(reorg_recv, Decimal("0.75"))

        # Confirm tx on node0's branch.
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.no_op)
        assert w0.gettransaction(txid)["confirmations"] >= 1

        # Mine a longer competing branch on node1 and reconnect.
        self.mine_to_wallet(n1, w1, 3, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks([n0, n1])

        # The transaction should be disconnected and returned to mempool.
        assert txid in n0.getrawmempool()
        assert w0.gettransaction(txid)["confirmations"] <= 0

        # Confirm again on the new active chain from the node that has the
        # resurrected mempool entry.
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        assert w0.gettransaction(txid)["confirmations"] >= 1
        assert w1.gettransaction(txid)["confirmations"] >= 1
        self.assert_p2mr_wallet_tx(w0, txid, expect_algo="any")

    def test_ctv_end_to_end_and_relay(self, n0, n1, w0, w1):
        self.log.info("test_ctv_end_to_end_and_relay")

        funding_sat = 5_000_000
        fee_sat = 2_000
        spend_sat = funding_sat - fee_sat
        primary_pubkey = bytes(1312)
        primary_leaf_script = self.build_mldsa_checksig_leaf_script(primary_pubkey)
        ctv_control = bytes([self.P2MR_LEAF_VERSION]) + self.compute_p2mr_leaf_hash(primary_leaf_script)

        spend_dest = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(spend_dest)
        wrong_dest = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(wrong_dest)

        # CTV commits only to template fields, not prevouts, so build hash from
        # a dummy tx with the same version/locktime/sequences/outputs.
        template_raw = n0.createrawtransaction(
            [{"txid": "00" * 32, "vout": 0, "sequence": 0xFFFFFFFF}],
            {spend_dest: self.sats_to_btc(spend_sat)},
        )
        template_tx = from_hex(CTransaction(), template_raw)
        ctv_hash = self.compute_ctv_hash(template_tx, 0)
        ctv_leaf_script = bytes([32]) + ctv_hash + bytes([self.OP_CHECKTEMPLATEVERIFY])
        ctv_lock_addr = self.get_single_address_for_descriptor(
            n0,
            f"mr({primary_pubkey.hex()},ctv({ctv_hash.hex()}))",
        )
        self.assert_p2mr_address(ctv_lock_addr)

        fund_txid = w0.sendtoaddress(ctv_lock_addr, self.sats_to_btc(funding_sat))
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        fund_vout, fund_amount_sat = self.find_vout_for_address(w0, fund_txid, ctv_lock_addr)
        assert_equal(fund_amount_sat, funding_sat)

        # Wrong template must fail CTV hash check.
        bad_raw = n0.createrawtransaction(
            [{"txid": fund_txid, "vout": fund_vout, "sequence": 0xFFFFFFFF}],
            {wrong_dest: self.sats_to_btc(spend_sat)},
        )
        bad_hex = self.raw_with_witness(bad_raw, [ctv_leaf_script, ctv_control])
        assert_raises_rpc_error(-26, "OP_CHECKTEMPLATEVERIFY hash mismatch", n0.sendrawtransaction, bad_hex)

        # Matching template should relay and confirm.
        good_raw = n0.createrawtransaction(
            [{"txid": fund_txid, "vout": fund_vout, "sequence": 0xFFFFFFFF}],
            {spend_dest: self.sats_to_btc(spend_sat)},
        )
        good_hex = self.raw_with_witness(good_raw, [ctv_leaf_script, ctv_control])
        good_txid = n0.sendrawtransaction(good_hex)
        self.sync_mempools([n0, n1])
        assert good_txid in n1.getrawmempool()
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        assert good_txid not in n0.getrawmempool()

    def test_csfs_end_to_end_and_policy_rejection(self, n0, n1, w0, w1):
        self.log.info("test_csfs_end_to_end_and_policy_rejection")

        vectors = self.load_csfs_vectors()
        csfs_pubkey_hex = vectors["mldsa_pubkey_hex"]
        csfs_sig = bytes.fromhex(vectors["mldsa_sig_hex"])
        csfs_msg = bytes.fromhex(vectors["csfs_msg_hex"])
        csfs_leaf_script = self.build_mldsa_csfs_leaf_script()
        primary_pubkey = bytes(1312)
        primary_leaf_script = self.build_mldsa_checksig_leaf_script(primary_pubkey)
        csfs_control = bytes([self.P2MR_LEAF_VERSION]) + self.compute_p2mr_leaf_hash(primary_leaf_script)
        csfs_lock_addr = self.get_single_address_for_descriptor(
            n0,
            f"mr({primary_pubkey.hex()},csfs({csfs_pubkey_hex}))",
        )
        self.assert_p2mr_address(csfs_lock_addr)

        funding_sat = 4_000_000
        fee_sat = 2_000
        spend_sat = funding_sat - fee_sat
        spend_dest = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(spend_dest)

        fund_txid = w0.sendtoaddress(csfs_lock_addr, self.sats_to_btc(funding_sat))
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        fund_vout, fund_amount_sat = self.find_vout_for_address(w0, fund_txid, csfs_lock_addr)
        assert_equal(fund_amount_sat, funding_sat)

        spend_raw = n0.createrawtransaction(
            [{"txid": fund_txid, "vout": fund_vout, "sequence": 0xFFFFFFFF}],
            {spend_dest: self.sats_to_btc(spend_sat)},
        )
        spend_hex = self.raw_with_witness(
            spend_raw,
            [csfs_sig, csfs_msg, csfs_leaf_script, csfs_control],
        )
        spend_txid = n0.sendrawtransaction(spend_hex)
        self.sync_mempools([n0, n1])
        assert spend_txid in n1.getrawmempool()
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)

        # Policy must reject CSFS messages over 520 bytes (consensus still permits them).
        fund2_sat = 3_000_000
        spend2_sat = fund2_sat - fee_sat
        fund2_txid = w0.sendtoaddress(csfs_lock_addr, self.sats_to_btc(fund2_sat))
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        fund2_vout, fund2_amount_sat = self.find_vout_for_address(w0, fund2_txid, csfs_lock_addr)
        assert_equal(fund2_amount_sat, fund2_sat)

        oversize_raw = n0.createrawtransaction(
            [{"txid": fund2_txid, "vout": fund2_vout, "sequence": 0xFFFFFFFF}],
            {spend_dest: self.sats_to_btc(spend2_sat)},
        )
        oversize_hex = self.raw_with_witness(
            oversize_raw,
            [csfs_sig, b"\x42" * 521, csfs_leaf_script, csfs_control],
        )
        result = n0.testmempoolaccept([oversize_hex])[0]
        assert_equal(result["allowed"], False)
        assert "p2mr-csfs-msg-size" in result["reject-reason"]

    def test_ctv_package_relay_cpfp(self, n0, w0, w1):
        self.log.info("test_ctv_package_relay_cpfp")

        # Zero-fee parent package relay requires minrelay=0 in this harness.
        self.restart_node(0, extra_args=["-minrelaytxfee=0"])
        self.restart_node(1, extra_args=["-minrelaytxfee=0"])
        self.connect_nodes(0, 1)
        self.sync_all()

        n0 = self.nodes[0]
        n1 = self.nodes[1]
        if "w0" not in n0.listwallets():
            n0.loadwallet("w0")
        if "w1" not in n1.listwallets():
            n1.loadwallet("w1")
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")

        funding_sat = 3_000_000
        anchor_sat = 1_000_000
        child_fee_sat = 50_000
        parent_spend_sat = funding_sat - anchor_sat
        child_spend_sat = anchor_sat - child_fee_sat

        assert parent_spend_sat > 0
        assert child_spend_sat > 0

        primary_pubkey = bytes(1312)
        primary_leaf_script = self.build_mldsa_checksig_leaf_script(primary_pubkey)

        parent_dest = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(parent_dest)
        anchor_dest = w0.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(anchor_dest)
        child_dest = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(child_dest)

        template_raw = n0.createrawtransaction(
            [{"txid": "00" * 32, "vout": 0, "sequence": 0xFFFFFFFF}],
            {
                parent_dest: self.sats_to_btc(parent_spend_sat),
                anchor_dest: self.sats_to_btc(anchor_sat),
            },
        )
        template_tx = from_hex(CTransaction(), template_raw)
        ctv_hash = self.compute_ctv_hash(template_tx, 0)
        ctv_leaf_script = bytes([32]) + ctv_hash + bytes([self.OP_CHECKTEMPLATEVERIFY])
        ctv_control = bytes([self.P2MR_LEAF_VERSION]) + self.compute_p2mr_leaf_hash(primary_leaf_script)

        ctv_lock_addr = self.get_single_address_for_descriptor(
            n0,
            f"mr({primary_pubkey.hex()},ctv({ctv_hash.hex()}))",
        )
        self.assert_p2mr_address(ctv_lock_addr)

        fund_txid = w0.sendtoaddress(ctv_lock_addr, self.sats_to_btc(funding_sat))
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        fund_vout, fund_amount_sat = self.find_vout_for_address(w0, fund_txid, ctv_lock_addr)
        assert_equal(fund_amount_sat, funding_sat)

        # Parent is zero-fee by construction: outputs sum to input value exactly.
        parent_raw = n0.createrawtransaction(
            [{"txid": fund_txid, "vout": fund_vout, "sequence": 0xFFFFFFFF}],
            {
                parent_dest: self.sats_to_btc(parent_spend_sat),
                anchor_dest: self.sats_to_btc(anchor_sat),
            },
        )
        parent_hex = self.raw_with_witness(parent_raw, [ctv_leaf_script, ctv_control])
        parent_decoded = n0.decoderawtransaction(parent_hex)
        parent_txid = parent_decoded["txid"]
        parent_wtxid = parent_decoded["hash"]

        parent_accept = n0.testmempoolaccept([parent_hex])[0]
        assert_equal(parent_accept["allowed"], True)

        anchor_vout = None
        anchor_spk = None
        for vout in parent_decoded.get("vout", []):
            spk = vout.get("scriptPubKey", {})
            if spk.get("address") == anchor_dest:
                anchor_vout = vout["n"]
                anchor_spk = spk["hex"]
                break
        assert anchor_vout is not None
        assert anchor_spk is not None

        child_raw = n0.createrawtransaction(
            [{"txid": parent_txid, "vout": anchor_vout, "sequence": 0xFFFFFFFD}],
            {child_dest: self.sats_to_btc(child_spend_sat)},
        )
        child_signed = w0.signrawtransactionwithwallet(
            child_raw,
            [
                {
                    "txid": parent_txid,
                    "vout": anchor_vout,
                    "scriptPubKey": anchor_spk,
                    "amount": self.sats_to_btc(anchor_sat),
                }
            ],
        )
        assert_equal(child_signed["complete"], True)
        child_hex = child_signed["hex"]
        child_decoded = n0.decoderawtransaction(child_hex)
        child_txid = child_decoded["txid"]
        child_wtxid = child_decoded["hash"]

        package_result = n0.submitpackage([parent_hex, child_hex])
        assert_equal(package_result["package_msg"], "success")
        assert parent_wtxid in package_result["tx-results"]
        assert child_wtxid in package_result["tx-results"]

        mempool = set(n0.getrawmempool())
        assert parent_txid in mempool
        assert child_txid in mempool

        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        best_block = n0.getblock(n0.getbestblockhash(), 1)
        assert parent_txid in set(best_block["tx"])
        assert child_txid in set(best_block["tx"])

    def test_p2mr_block_high_load(self, n0, w0, w1):
        self.log.info("test_p2mr_block_full_capacity")
        # Split funds into many confirmed outputs to avoid long unconfirmed
        # chains while constructing a high-load P2MR mempool.
        split_targets = {}
        for _ in range(120):
            split_addr = w0.getnewaddress(address_type="p2mr")
            self.assert_p2mr_address(split_addr)
            split_targets[split_addr] = Decimal("0.20")
        w0.sendmany("", split_targets)
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)

        # Fill mempool with many independent P2MR spends.
        txids = []
        for _ in range(80):
            recv = w1.getnewaddress(address_type="p2mr")
            self.assert_p2mr_address(recv)
            txids.append(w0.sendtoaddress(recv, Decimal("0.01")))

        mempool_info = n0.getmempoolinfo()
        assert mempool_info["size"] >= 80

        mine_addr = w0.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(mine_addr)
        block_hash = self.generatetoaddress(n0, 1, mine_addr, sync_fun=self.sync_all)[0]

        block = n0.getblock(block_hash, 1)
        block_txids = set(block["tx"])
        for txid in txids:
            assert txid in block_txids
        assert block["weight"] > 200_000

        # Sample one high-load spend and validate it still uses P2MR witness_v2 format.
        self.assert_p2mr_wallet_tx(w0, txids[0], expect_algo="any")

        # Validate capacity metadata remains at post-fork limits.
        tmpl = n0.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["weightlimit"], 24_000_000)
        assert_equal(tmpl["sizelimit"], 24_000_000)

    def test_p2mr_backup_spend_slhdsa(self, n0, w0, w1):
        self.log.info("test_p2mr_backup_spend_slhdsa")

        # Use a dedicated wallet so coin selection is deterministic.
        n0.createwallet(wallet_name="w_slh", descriptors=True)
        w_slh = n0.get_wallet_rpc("w_slh")

        # Build a P2MR descriptor where the primary ML-DSA leaf is an
        # unspendable fixed pubkey, forcing spending via the SLH-DSA leaf.
        descs = w_slh.listdescriptors(True)["descriptors"]
        assert len(descs) >= 1
        ext = next((d for d in descs if not d.get("internal", False)), descs[0])["desc"]

        # ext is of the form: mr(KEY,pk_slh(KEY))#checksum
        assert ext.startswith("mr(")
        ext_no_checksum = ext.split("#", 1)[0]
        inner = ext_no_checksum[len("mr("):-1]
        key_expr = inner.split(",pk_slh(", 1)[0]

        fixed_mldsa_hex = os.urandom(1312).hex()
        no_checksum = f"mr({fixed_mldsa_hex},pk_slh({key_expr}))"
        # getdescriptorinfo normalizes private descriptors to public form in the
        # returned "descriptor" field. Preserve the original expression and
        # append the returned checksum.
        info = n0.getdescriptorinfo(no_checksum)
        desc = f"{no_checksum}#{info['checksum']}"

        res = w_slh.importdescriptors([{
            "desc": desc,
            "active": False,
            "timestamp": "now",
            "range": [0, 0],
        }])[0]
        assert_equal(res["success"], True)

        recv = n0.deriveaddresses(desc, [0, 0])[0]
        self.assert_p2mr_address(recv)

        fund_txid = w0.sendtoaddress(recv, Decimal("1.0"))
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)
        dest = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(dest)
        spend_txid = w_slh.sendtoaddress(dest, Decimal("0.5"))
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)

        self.assert_p2mr_wallet_tx(w_slh, spend_txid, expect_algo="slhdsa")

    def test_watchonly_xpub_cannot_sign_p2mr(self, n0, w0, w1):
        self.log.info("test_watchonly_xpub_cannot_sign_p2mr")

        # Watch-only ranged P2MR descriptors cannot be expanded because
        # PQ public keys are derived from private key material.
        n0.createwallet(wallet_name="w_watch", descriptors=True, disable_private_keys=True)
        w_watch = n0.get_wallet_rpc("w_watch")

        pub_descs = w0.listdescriptors(False)["descriptors"]
        recv_desc = next(
            (d["desc"] for d in pub_descs if not d.get("internal", False) and d.get("desc", "").startswith("mr(")),
            None,
        )
        assert recv_desc is not None
        assert ("xpub" in recv_desc) or ("tpub" in recv_desc) or ("pqhd(" in recv_desc)
        assert "xprv" not in recv_desc
        assert "tprv" not in recv_desc

        # Guardrail: ranged mr() cannot be imported watch-only.
        res = w_watch.importdescriptors([{
            "desc": recv_desc,
            "active": False,
            "timestamp": "now",
            "range": [0, 0],
        }])[0]
        assert_equal(res["success"], False)
        assert "P2MR" in res["error"]["message"] or "p2mr" in res["error"]["message"].lower()

        # Non-ranged fixed-key P2MR descriptors should import, but still cannot
        # sign spends in a wallet with private keys disabled.
        fixed_mldsa_hex = os.urandom(1312).hex()
        fixed_slh_hex = os.urandom(32).hex()
        fixed_no_checksum = f"mr({fixed_mldsa_hex},pk_slh({fixed_slh_hex}))"
        fixed_info = n0.getdescriptorinfo(fixed_no_checksum)
        fixed_desc = f"{fixed_no_checksum}#{fixed_info['checksum']}"
        res2 = w_watch.importdescriptors([{
            "desc": fixed_desc,
            "active": False,
            "timestamp": "now",
        }])[0]
        assert_equal(res2["success"], True)

        recv = n0.deriveaddresses(fixed_desc)[0]
        self.assert_p2mr_address(recv)
        fund_txid = w0.sendtoaddress(recv, Decimal("0.5"))
        self.mine_to_wallet(n0, w0, 1, sync_fun=self.sync_all)

        rawfund_hex = w0.gettransaction(fund_txid)["hex"]
        rawfund = n0.decoderawtransaction(rawfund_hex)
        vout = next(
            i for i, v in enumerate(rawfund.get("vout", []))
            if v.get("scriptPubKey", {}).get("address") == recv
        )
        dest = w1.getnewaddress(address_type="p2mr")
        self.assert_p2mr_address(dest)
        raw = n0.createrawtransaction([{"txid": fund_txid, "vout": vout}], {dest: 0.1})

        signed = w_watch.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], False)

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        n0.createwallet(wallet_name="w0", descriptors=True)
        n1.createwallet(wallet_name="w1", descriptors=True)
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")

        self.test_mine_and_spend_p2mr(n0, n1, w0, w1)
        self.test_ctv_end_to_end_and_relay(n0, n1, w0, w1)
        self.test_ctv_package_relay_cpfp(n0, w0, w1)
        n0 = self.nodes[0]
        n1 = self.nodes[1]
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")
        self.test_csfs_end_to_end_and_policy_rejection(n0, n1, w0, w1)
        self.test_p2mr_backup_spend_slhdsa(n0, w0, w1)
        self.test_watchonly_xpub_cannot_sign_p2mr(n0, w0, w1)
        self.test_multiple_wallets_p2mr(n0, n1, w0)
        self.test_reorg_p2mr(n0, n1, w0, w1)
        self.test_p2mr_block_high_load(n0, w0, w1)


if __name__ == "__main__":
    P2MREndToEndTest(__file__).main()
