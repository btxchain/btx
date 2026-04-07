#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end 2-of-3 PQ multisig flow using watch-only descriptor wallets and PSBT."""

from decimal import Decimal

from test_framework.messages import SEQUENCE_FINAL
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class FeaturePQMultisigTest(BitcoinTestFramework):
    @staticmethod
    def _assert_cltv_sequence(sequence: int) -> None:
        assert sequence != SEQUENCE_FINAL
        assert sequence & 0x80000000

    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-keypool=100"]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    @staticmethod
    def _render_key_from_leaf_script_hex(leaf_script_hex: str) -> str:
        leaf = bytes.fromhex(leaf_script_hex)
        assert leaf, "leaf script is empty"
        opcode = leaf[-1]

        # <PUSHDATA2 1312B> <pubkey> OP_CHECKSIG_MLDSA
        if opcode == 0xBB:
            assert len(leaf) >= 4
            assert leaf[0] == 0x4D
            key_len = leaf[1] + (leaf[2] << 8)
            assert key_len == 1312
            pubkey = leaf[3 : 3 + key_len]
            assert len(pubkey) == 1312
            return pubkey.hex()

        # <PUSHDATA(32B)> <pubkey> OP_CHECKSIG_SLHDSA
        if opcode == 0xBC:
            assert len(leaf) >= 2
            key_len = leaf[0]
            assert key_len == 32
            pubkey = leaf[1 : 1 + key_len]
            assert len(pubkey) == 32
            return f"pk_slh({pubkey.hex()})"

        raise AssertionError(f"unexpected leaf opcode 0x{opcode:02x}")

    def _extract_signer_multisig_key(self, signer_wallet, funding_utxo):
        destination = signer_wallet.getnewaddress()
        funding_amount = Decimal(str(funding_utxo["amount"]))
        amount = min(Decimal("0.10"), funding_amount - Decimal("0.02"))
        assert amount > Decimal("0.0")

        psbt = signer_wallet.walletcreatefundedpsbt(
            inputs=[{"txid": funding_utxo["txid"], "vout": funding_utxo["vout"]}],
            outputs={destination: amount},
            options={"add_inputs": False, "fee_rate": 10},
        )["psbt"]
        signed = signer_wallet.walletprocesspsbt(psbt)
        assert_equal(signed["complete"], True)
        finalized = signer_wallet.finalizepsbt(signed["psbt"])
        assert_equal(finalized["complete"], True)

        decoded = signer_wallet.decoderawtransaction(finalized["hex"])
        witness = decoded["vin"][0]["txinwitness"]
        leaf_script_hex = witness[-2]
        return self._render_key_from_leaf_script_hex(leaf_script_hex)

    def _import_watchonly_descriptor(self, node, wallet_name, descriptor_expr):
        node.createwallet(wallet_name=wallet_name, blank=True, descriptors=True, disable_private_keys=True)
        wallet = node.get_wallet_rpc(wallet_name)
        descriptor = node.getdescriptorinfo(descriptor_expr)["descriptor"]
        result = wallet.importdescriptors([{"desc": descriptor, "timestamp": "now"}])
        assert_equal(result[0]["success"], True)
        address = node.deriveaddresses(descriptor)[0]
        return wallet, address

    def _exercise_timelocked_descriptor_flow(
        self,
        *,
        coordinator,
        address,
        signer_a,
        signer_b,
        receiver_wallet,
        miner_wallet,
        expected_sequence=None,
        expected_locktime=None,
        extra_blocks_before_spend=0,
    ):
        deposit_amount = Decimal("2.0")
        miner_wallet.sendtoaddress(address, deposit_amount)
        self.generate(self.nodes[0], 1)
        self.sync_all()

        if extra_blocks_before_spend:
            self.generate(self.nodes[0], extra_blocks_before_spend)
            self.sync_all()

        spend_utxo = next(u for u in coordinator.listunspent() if u["address"] == address)
        destination = receiver_wallet.getnewaddress()
        spend_amount = Decimal("0.8")
        psbt = coordinator.walletcreatefundedpsbt(
            inputs=[{"txid": spend_utxo["txid"], "vout": spend_utxo["vout"]}],
            outputs={destination: spend_amount},
            options={"add_inputs": False, "changeAddress": address, "fee_rate": 25},
        )["psbt"]
        updated = coordinator.walletprocesspsbt(psbt, sign=False, bip32derivs=True, finalize=False)
        assert_equal(updated["complete"], False)

        decoded = self.nodes[0].decodepsbt(updated["psbt"])
        if expected_sequence is not None:
            assert_equal(decoded["tx"]["version"], 2)
            assert_equal(decoded["tx"]["vin"][0]["sequence"], expected_sequence)
        if expected_locktime is not None:
            assert_equal(decoded["tx"]["locktime"], expected_locktime)
            self._assert_cltv_sequence(decoded["tx"]["vin"][0]["sequence"])

        processed_a = signer_a.walletprocesspsbt(updated["psbt"], finalize=False)
        processed_b = signer_b.walletprocesspsbt(updated["psbt"], finalize=False)
        assert_equal(processed_a["complete"], False)
        assert_equal(processed_b["complete"], False)

        combined = signer_a.combinepsbt([processed_a["psbt"], processed_b["psbt"]])
        finalized = signer_a.finalizepsbt(combined)
        assert_equal(finalized["complete"], True)

        tx = signer_a.decoderawtransaction(finalized["hex"])
        if expected_sequence is not None:
            assert_equal(tx["version"], 2)
            assert_equal(tx["vin"][0]["sequence"], expected_sequence)
        if expected_locktime is not None:
            assert_equal(tx["locktime"], expected_locktime)
            self._assert_cltv_sequence(tx["vin"][0]["sequence"])

        signer_a.sendrawtransaction(finalized["hex"])
        self.generate(self.nodes[0], 1)
        self.sync_all()
        assert receiver_wallet.getbalance() >= spend_amount

    def run_test(self):
        self.log.info("Create signer wallets")
        signers = []
        for i, node in enumerate(self.nodes):
            node.createwallet(wallet_name=f"pq_signer_{i}", descriptors=True)
            signers.append(node.get_wallet_rpc(f"pq_signer_{i}"))

        miner = signers[0]
        self.generatetoaddress(self.nodes[0], 101, miner.getnewaddress(), sync_fun=self.no_op)
        self.sync_all()

        self.log.info("Export one deterministic PQ key from each signer (no witness parsing)")
        pq_keys = []
        for signer in signers:
            source_addr = signer.getnewaddress()
            exported = signer.exportpqkey(source_addr)
            assert_equal(exported["algorithm"], "ml-dsa-44")
            pq_keys.append(exported["key"])

        self.log.info("Also fund each signer with one UTXO and extract one concrete PQ key from each signer")
        signer_funding_addrs = []
        for signer in signers:
            addr = signer.getnewaddress()
            signer_funding_addrs.append(addr)
            miner.sendtoaddress(addr, Decimal("0.6"))
        self.generate(self.nodes[0], 1)
        self.sync_all()

        pq_keys_from_witness = []
        for signer, funding_addr in zip(signers, signer_funding_addrs):
            utxo = next(u for u in signer.listunspent() if u["address"] == funding_addr)
            pq_keys_from_witness.append(self._extract_signer_multisig_key(signer, utxo))

        self.log.info("Each node creates the same watch-only 2-of-3 PQ multisig wallet entry")
        multisigs = []
        multisig_addresses = []
        for i, node in enumerate(self.nodes):
            node.createwallet(wallet_name=f"pq_multisig_{i}", blank=True, descriptors=True, disable_private_keys=True)
            msig = node.get_wallet_rpc(f"pq_multisig_{i}")
            info = msig.addpqmultisigaddress(2, pq_keys, "", True)
            multisigs.append(msig)
            multisig_addresses.append(info["address"])
        assert all(addr == multisig_addresses[0] for addr in multisig_addresses)
        multisig_address = multisig_addresses[0]

        self.log.info("Fund multisig, create PSBT, sign on two nodes, combine/finalize/broadcast")
        deposit_amount = Decimal("3.0")
        miner.sendtoaddress(multisig_address, deposit_amount)
        self.generate(self.nodes[0], 1)
        self.sync_all()

        spend_utxo = next(u for u in multisigs[0].listunspent() if u["address"] == multisig_address)
        destination = signers[2].getnewaddress()
        spend_amount = Decimal("1.0")
        psbt = multisigs[0].walletcreatefundedpsbt(
            inputs=[{"txid": spend_utxo["txid"], "vout": spend_utxo["vout"]}],
            outputs={destination: spend_amount},
            # PQ multisig witnesses are large; use a higher explicit feerate so the
            # funded PSBT remains relayable after final witness material is added.
            options={"add_inputs": False, "changeAddress": multisig_address, "fee_rate": 25},
        )["psbt"]
        psbt = multisigs[0].walletprocesspsbt(psbt, sign=False, bip32derivs=True, finalize=False)["psbt"]

        processed_a = signers[0].walletprocesspsbt(psbt)
        processed_b = signers[1].walletprocesspsbt(psbt)
        self.log.info("Signer A complete=%s", processed_a["complete"])
        self.log.info("Signer B complete=%s", processed_b["complete"])
        psbt_a = processed_a["psbt"]
        psbt_b = processed_b["psbt"]
        combined = signers[0].combinepsbt([psbt_a, psbt_b])
        self.log.info("Combined input decode: %s", signers[0].decodepsbt(combined)["inputs"][0])
        finalized = signers[0].finalizepsbt(combined)
        assert_equal(finalized["complete"], True)
        signers[0].sendrawtransaction(finalized["hex"])
        self.generate(self.nodes[0], 1)
        self.sync_all()

        assert signers[2].getbalance() >= spend_amount

        self.log.info("Import BTX-native CSV timelocked multisig descriptor and verify PSBT normalization end to end")
        csv_wallet, csv_address = self._import_watchonly_descriptor(
            self.nodes[0],
            "pq_csv_multisig_0",
            f"mr(csv_multi_pq(1,2,{pq_keys[0]},{pq_keys[1]}))",
        )
        self._exercise_timelocked_descriptor_flow(
            coordinator=csv_wallet,
            address=csv_address,
            signer_a=signers[0],
            signer_b=signers[1],
            receiver_wallet=signers[2],
            miner_wallet=miner,
            expected_sequence=1,
            extra_blocks_before_spend=1,
        )

        self.log.info("Import BTX-native CLTV timelocked multisig descriptor and verify PSBT normalization end to end")
        cltv_height = self.nodes[0].getblockcount() + 2
        cltv_wallet, cltv_address = self._import_watchonly_descriptor(
            self.nodes[0],
            "pq_cltv_multisig_0",
            f"mr(cltv_multi_pq({cltv_height},2,{pq_keys[0]},{pq_keys[1]}))",
        )
        self._exercise_timelocked_descriptor_flow(
            coordinator=cltv_wallet,
            address=cltv_address,
            signer_a=signers[0],
            signer_b=signers[1],
            receiver_wallet=signers[2],
            miner_wallet=miner,
            expected_locktime=cltv_height,
            extra_blocks_before_spend=1,
        )


if __name__ == "__main__":
    FeaturePQMultisigTest(__file__).main()
