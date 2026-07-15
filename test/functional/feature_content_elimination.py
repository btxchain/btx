#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Functional coverage for the BTX content-elimination hard fork.

See doc/btx-inscription-elimination-plan.md (Section 8 test plan). The fork
removes the data-carriage channels that inscription/NFT/token meta-protocols
depend on, flag-day gated on nContentEliminationHeight. Regtest activates it via
-regtestcontenteliminationheight=<n>.

This test exercises the height-gated *block consensus* rules and the immediate
*relay* hardening (Pillar 6):

  - Pillar 1: a non-coinbase OP_RETURN output is accepted in a block below the
    activation height and rejected (bad-txns-opreturn-forbidden) at/above it.
  - Pillars 2 & 3: a P2MR spend revealing a non-financial (data-stuffed) leaf is
    rejected (bad-txns-nonfinancial-witness) at/above the activation height.
  - Post-activation sanity: a normal P2MR payment still confirms and the
    coinbase (carrying the witness commitment) is still valid.
  - Relay: createrawtransaction {"data":...} is rejected outright, and OP_RETURN
    txs are non-standard at relay by default (datacarrier off).

Because relay policy rejects these txs before they reach a block, the consensus
rules are exercised by mining the tx directly into a block via generateblock
(regtest is MatMul proof-of-work, so generateblock skips the template validity
check) and submitting the resulting block with submitblock.

Pillar 5 (coinbase scriptSig > 40 bytes -> bad-cb-scriptsig-content) and the
coinbase-extra-OP_RETURN rule (bad-cb-opreturn) require a custom coinbase, which
the Python framework cannot mine under MatMul proof-of-work. Those two rules are
covered by the C++ unit test src/test/content_elimination_tests.cpp instead.
"""

from decimal import Decimal

from test_framework.address import program_to_witness
from test_framework.messages import (
    CTransaction,
    CTxInWitness,
    CTxOut,
    from_hex,
    ser_compact_size,
    sha256,
)
from test_framework.script import (
    CScript,
    OP_DROP,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

# Flag-day activation height for the regtest run. Chosen above coinbase maturity
# so there is a comfortable pre-activation window in which to fund and exercise
# the "accepted below H" cases.
ACTIVATION_HEIGHT = 130

# P2MR committed-leaf version byte (interpreter.cpp P2MR_LEAF_VERSION / the
# 0xC2 used by feature_p2mr_end_to_end.py).
P2MR_LEAF_VERSION = 0xC2

# A representative OP_RETURN meta-protocol marker: a short magic/version/op
# prefix plus a 32-byte off-chain content hash (see doc Section 2 for the
# technique). Well under 83 bytes, so it is a valid OP_RETURN below the
# activation height and forbidden at/above it. The exact bytes are illustrative;
# the rule keys off the OP_RETURN output type, not the payload contents.
OP_RETURN_MARKER_PAYLOAD = (
    b"META"                      # magic/version/op prefix (illustrative)
    + b"\x00\x01"
    + b"\xa1" * 32               # 32-byte off-chain content hash
)


class ContentEliminationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # P2MR signing / repeated block solving can exceed the default 60s RPC
        # timeout on slower hosts.
        self.rpc_timeout = 240
        self.extra_args = [[f"-regtestcontenteliminationheight={ACTIVATION_HEIGHT}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # --- P2MR leaf helpers (mirrors feature_p2mr_end_to_end.py) ---------------

    @staticmethod
    def _tagged_hash(tag, payload):
        tag_hash = sha256(tag.encode("utf8"))
        return sha256(tag_hash + tag_hash + payload)

    def _p2mr_leaf_hash(self, leaf_script):
        payload = bytes([P2MR_LEAF_VERSION]) + ser_compact_size(len(leaf_script)) + bytes(leaf_script)
        return self._tagged_hash("P2MRLeaf", payload)

    # --- tx construction helpers ---------------------------------------------

    def _pick_utxo(self, wallet):
        utxos = sorted(wallet.listunspent(1), key=lambda u: u["amount"], reverse=True)
        assert utxos, "no spendable outputs"
        return utxos[0]

    def _find_vout(self, wallet, txid, address):
        decoded = wallet.decoderawtransaction(wallet.gettransaction(txid)["hex"])
        for out in decoded["vout"]:
            if out.get("scriptPubKey", {}).get("address") == address:
                return out["n"], Decimal(str(out["value"]))
        raise AssertionError(f"address {address} not found in tx {txid}")

    def _build_opreturn_tx(self, node, wallet, data):
        """A financial P2MR spend with an appended data OP_RETURN output.

        The createrawtransaction {"data":...} builder is disabled on BTX
        (Pillar 6), so the OP_RETURN output is attached to the serialized tx
        directly and then signed by the wallet (the P2MR sighash commits to the
        outputs, so the OP_RETURN must be present before signing).
        """
        utxo = self._pick_utxo(wallet)
        change_addr = wallet.getnewaddress(address_type="p2mr")
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {change_addr: utxo["amount"] - Decimal("0.0001")},
        )
        tx = from_hex(CTransaction(), raw)
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, data])))
        signed = wallet.signrawtransactionwithwallet(tx.serialize().hex())
        assert_equal(signed["complete"], True)
        return signed["hex"]

    def _build_nonfinancial_leaf_spend(self, node, wallet, fund_txid, fund_vout,
                                       fund_amount, leaf_script, control):
        """Spend a P2MR output whose revealed leaf is a data-stuffed script.

        The leaf `<data> OP_DROP OP_TRUE` executes to true (so it is a valid
        spend below the activation height) but classifies as non-financial, so
        the consensus leaf allowlist rejects it at/above the activation height.
        No signature is required.
        """
        dest = wallet.getnewaddress(address_type="p2mr")
        raw = node.createrawtransaction(
            [{"txid": fund_txid, "vout": fund_vout}],
            {dest: fund_amount - Decimal("0.0001")},
        )
        tx = from_hex(CTransaction(), raw)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf_script), bytes(control)]
        return tx.serialize_with_witness().hex()

    def _mine_block_with_tx(self, node, wallet, tx_hex):
        """Mine tx_hex directly into a block (bypasses relay) and submit it.

        Returns the submitblock result: None on acceptance, else the block-level
        reject reason string.
        """
        block_addr = wallet.getnewaddress(address_type="p2mr")
        candidate = node.generateblock(block_addr, [tx_hex], False, called_by_framework=True)
        return candidate["hash"], node.submitblock(candidate["hex"])

    # --- test ----------------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w0", descriptors=True)
        wallet = node.get_wallet_rpc("w0")

        self.log.info("Mining past coinbase maturity while staying below the activation height")
        mine_addr = wallet.getnewaddress(address_type="p2mr")
        self.generatetoaddress(node, 120, mine_addr)
        assert_greater_than(ACTIVATION_HEIGHT - 1, node.getblockcount())

        # Fund a non-financial P2MR leaf output (single-leaf tree: the witness
        # program equals the leaf hash and the control block is just the leaf
        # version byte).
        self.log.info("Funding a non-financial P2MR leaf output for the Pillars 2 & 3 spend")
        leaf_script = CScript([b"\x42" * 64, OP_DROP, OP_TRUE])
        leaf_hash = self._p2mr_leaf_hash(leaf_script)
        control = bytes([P2MR_LEAF_VERSION])
        leaf_addr = program_to_witness(2, leaf_hash)
        leaf_fund_txid = wallet.sendtoaddress(leaf_addr, Decimal("1.0"))
        self.generate(node, 1)
        leaf_vout, leaf_amount = self._find_vout(wallet, leaf_fund_txid, leaf_addr)

        # --- Relay layer (Pillar 6, effective immediately) -------------------

        self.log.info('Relay: createrawtransaction {"data":...} is rejected outright')
        assert_raises_rpc_error(
            -8, "OP_RETURN \"data\" outputs are disabled",
            node.createrawtransaction, [], [{"data": "00"}],
        )

        self.log.info("Relay: OP_RETURN txs are non-standard by default (datacarrier off)")
        relay_hex = self._build_opreturn_tx(node, wallet, OP_RETURN_MARKER_PAYLOAD)
        assert_raises_rpc_error(-26, "scriptpubkey", node.sendrawtransaction, relay_hex)

        # --- Pillar 1: OP_RETURN below vs at the activation height ------------

        self.log.info("Pillar 1: a non-coinbase OP_RETURN is accepted in a block below the activation height")
        pre_hex = self._build_opreturn_tx(node, wallet, OP_RETURN_MARKER_PAYLOAD)
        pre_txid = node.decoderawtransaction(pre_hex)["txid"]
        # Candidate block height (tip + 1) must be below the activation height.
        assert_greater_than(ACTIVATION_HEIGHT - 1, node.getblockcount() + 1)
        block_addr = wallet.getnewaddress(address_type="p2mr")
        pre_block = node.generateblock(block_addr, [pre_hex], called_by_framework=True)
        assert pre_txid in node.getblock(pre_block["hash"], 1)["tx"]

        self.log.info("Mining up to one block below the activation height")
        self.generate(node, (ACTIVATION_HEIGHT - 1) - node.getblockcount())
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)

        self.log.info("Pillar 1: a non-coinbase OP_RETURN is rejected at the activation height")
        post_hex = self._build_opreturn_tx(node, wallet, OP_RETURN_MARKER_PAYLOAD)
        _, reject = self._mine_block_with_tx(node, wallet, post_hex)
        assert_equal(reject, "bad-txns-opreturn-forbidden")
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)  # rejected block did not advance the tip

        # --- Pillars 2 & 3: non-financial P2MR witness leaf ------------------

        self.log.info("Pillars 2 & 3: a non-financial P2MR leaf spend is rejected at the activation height")
        leaf_spend_hex = self._build_nonfinancial_leaf_spend(
            node, wallet, leaf_fund_txid, leaf_vout, leaf_amount, leaf_script, control)
        _, reject = self._mine_block_with_tx(node, wallet, leaf_spend_hex)
        assert_equal(reject, "bad-txns-nonfinancial-witness")
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)

        # --- Post-activation financial surface still works -------------------

        self.log.info("Post-activation sanity: a normal P2MR payment confirms and the coinbase stays valid")
        pay_dest = wallet.getnewaddress(address_type="p2mr")
        pay_txid = wallet.sendtoaddress(pay_dest, Decimal("1.0"))
        # Mining this block requires a valid coinbase (with witness commitment)
        # and a financial P2MR spend, both at height >= the activation height.
        self.generate(node, 1)
        assert_greater_than(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert pay_txid in node.getblock(node.getbestblockhash(), 1)["tx"]
        assert_greater_than(wallet.gettransaction(pay_txid)["confirmations"], 0)

        # End-to-end post-quantum: a 2-of-3 ML-DSA PQ multisig custody spend must
        # still relay AND confirm above the activation height. Pillars 2 & 3
        # promote the P2MR financial leaf allowlist to consensus by reusing the
        # exact IsWitnessStandard classifier, so a MULTISIG leaf must pass both
        # relay and the new ConnectBlock rule. This is the definitive check that
        # the fork preserves the PQ custody surface end to end.
        self._assert_pq_multisig_spends_post_activation(node, wallet)

    def _assert_pq_multisig_spends_post_activation(self, node, funder):
        self.log.info("End-to-end PQ: a 2-of-3 ML-DSA multisig custody spend relays and confirms above the fork height")
        assert_greater_than(node.getblockcount(), ACTIVATION_HEIGHT - 1)

        signers = []
        pq_keys = []
        for i in range(3):
            node.createwallet(wallet_name=f"ce_signer_{i}", descriptors=True)
            signer = node.get_wallet_rpc(f"ce_signer_{i}")
            exported = signer.exportpqkey(signer.getnewaddress())
            assert_equal(exported["algorithm"], "ml-dsa-44")
            signers.append(signer)
            pq_keys.append(exported["key"])

        node.createwallet(wallet_name="ce_multisig", blank=True, descriptors=True, disable_private_keys=True)
        msig = node.get_wallet_rpc("ce_multisig")
        multisig_address = msig.addpqmultisigaddress(2, pq_keys, "", True)["address"]

        funder.sendtoaddress(multisig_address, Decimal("3.0"))
        self.generate(node, 1)

        spend_utxo = next(u for u in msig.listunspent() if u["address"] == multisig_address)
        destination = signers[2].getnewaddress(address_type="p2mr")
        psbt = msig.walletcreatefundedpsbt(
            inputs=[{"txid": spend_utxo["txid"], "vout": spend_utxo["vout"]}],
            outputs={destination: Decimal("1.0")},
            options={"add_inputs": False, "changeAddress": multisig_address, "fee_rate": 25},
        )["psbt"]
        psbt = msig.walletprocesspsbt(psbt, sign=False, bip32derivs=True, finalize=False)["psbt"]
        psbt_a = signers[0].walletprocesspsbt(psbt)["psbt"]
        psbt_b = signers[1].walletprocesspsbt(psbt)["psbt"]
        finalized = signers[0].finalizepsbt(signers[0].combinepsbt([psbt_a, psbt_b]))
        assert_equal(finalized["complete"], True)

        # Relay path (IsWitnessStandard) accepts the PQ multisig witness...
        msig_txid = signers[0].sendrawtransaction(finalized["hex"])
        # ...and the consensus path (ConnectBlock IsWitnessStandard) confirms it
        # in a block above the activation height.
        self.generate(node, 1)
        assert_greater_than(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert msig_txid in node.getblock(node.getbestblockhash(), 1)["tx"]
        assert_greater_than(signers[2].getbalance(), 0)


if __name__ == "__main__":
    ContentEliminationTest(__file__).main()
