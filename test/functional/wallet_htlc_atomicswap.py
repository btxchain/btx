#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Full HTLC atomic-swap lifecycle on the BTX leg (wBTX Model B).

Exercises the post-quantum P2MR HTLC descriptor
    mr(<internal>, {htlc(<H160>, <claimerPubkey>), refund(<locktime>, <senderPubkey>)})
where H160 = RIPEMD160(SHA256(preimage)) (byte-identical to BTX OP_HASH160 and to the
EVM WBTXAtomicSwapHTLC hashlock), using ONLY node RPCs:

  getdescriptorinfo -> deriveaddresses -> importdescriptors  (assemble + import the lock)
  buildhtlcclaim  "<desc#cksum>" {"txid","vout"} "<preimage_hex>" "<dest>" <fee_sat>
  buildhtlcrefund "<desc#cksum>" {"txid","vout"} "<dest>" <locktime> <fee_sat>

Scenarios:
  1. CLAIM a funded HTLC output with the correct preimage -> destination receives funds,
     and the preimage is revealed on-chain in the claim witness.
  2. (negative) CLAIM with a wrong preimage must fail.
  3. REFUND a second funded output after mining past the refund locktime -> refund
     destination receives funds.
"""

import hashlib
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from test_framework.bridge_utils import create_bridge_wallet, find_output, mine_block


def hash160(preimage: bytes) -> bytes:
    """RIPEMD160(SHA256(preimage)) — the 20-byte hashlock shared by both chains."""
    return hashlib.new("ripemd160", hashlib.sha256(preimage).digest()).digest()


class WalletHtlcAtomicSwapTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    # ----------------------------- helpers -----------------------------

    def pq_pubkey(self, wallet):
        """A fresh ML-DSA P2MR pubkey owned by `wallet`."""
        addr = wallet.getnewaddress(address_type="p2mr")
        return wallet.exportpqkey(addr)["pubkey"]

    def build_htlc_descriptor(self, node, internal_pk, h160_hex, claimer_pk,
                              locktime, sender_pk):
        """Assemble the mr() HTLC descriptor and return (desc_with_checksum, address)."""
        desc = (f"mr({internal_pk},"
                f"{{htlc({h160_hex},{claimer_pk}),"
                f"refund({locktime},{sender_pk})}})")
        info = node.getdescriptorinfo(desc)
        desc_ck = f"{desc}#{info['checksum']}"
        # Round-trip: the canonical descriptor the node echoes back must checksum-match.
        addr = node.deriveaddresses(desc_ck)[0]
        return desc_ck, addr

    def fund_lock(self, wallet, node, mine_addr, address, amount):
        """Pay `amount` to the HTLC `address`; mine 1 conf; return (txid, vout, value)."""
        txid = wallet.sendtoaddress(address, amount)
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, txid, address, wallet)
        return txid, vout, value

    # ----------------------------- test body -----------------------------

    def run_test(self):
        node = self.nodes[0]

        # Funder wallet (holds the BTX, builds and broadcasts the lock + spends).
        sender, mine_addr = create_bridge_wallet(self, node, wallet_name="htlc_sender",
                                                 amount=Decimal("12"))

        # Counterparty/recipient keys live in their own wallet so the CLAIM leaf needs
        # *both* the preimage and the claimer's PQ signature (CSFS oracle key == recipient).
        node.createwallet(wallet_name="htlc_claimer", descriptors=True)
        claimer = node.get_wallet_rpc("htlc_claimer")

        internal_pk = self.pq_pubkey(sender)     # key-path internal key
        claimer_pk = self.pq_pubkey(claimer)     # claims with preimage + their sig
        sender_pk = self.pq_pubkey(sender)       # refunds after locktime

        fee = 1000  # satoshis, matches the RPC fee_sat argument
        fee_btx = Decimal(fee) / Decimal("100000000")

        # === Scenario 1: successful CLAIM with the correct preimage ===========
        self.log.info("HTLC CLAIM: lock, claim with correct preimage, assert payout + reveal")
        preimage = bytes.fromhex("42" * 32)
        h160_hex = hash160(preimage).hex()

        claim_locktime = node.getblockcount() + 100  # far in the future; claim ignores it
        claim_desc, claim_addr = self.build_htlc_descriptor(
            node, internal_pk, h160_hex, claimer_pk, claim_locktime, sender_pk)

        # Both wallets watch the lock so each side can see / spend the deposit.
        for w in (sender, claimer):
            w.importdescriptors([
                {"desc": claim_desc, "timestamp": "now", "internal": False}
            ])

        claim_amount = Decimal("3.0")
        c_txid, c_vout, c_value = self.fund_lock(sender, node, mine_addr, claim_addr, claim_amount)

        dest_addr = claimer.getnewaddress(address_type="p2mr")

        # Negative: a wrong preimage must not produce a valid/complete claim.
        self.log.info("HTLC CLAIM negative: wrong preimage must fail")
        wrong_preimage = bytes.fromhex("13" * 32)
        assert wrong_preimage != preimage
        try:
            bad = claimer.buildhtlcclaim(
                claim_desc, {"txid": c_txid, "vout": c_vout},
                wrong_preimage.hex(), dest_addr, fee)
            # If the RPC returns instead of raising, it must not yield a broadcastable tx.
            assert_equal(bad.get("complete", False), False)
            if bad.get("hex"):
                assert_raises_rpc_error(-26, None, node.sendrawtransaction, bad["hex"])
        except Exception as e:  # noqa: BLE001 - RPC raising on a bad preimage is the happy outcome
            self.log.info(f"wrong-preimage claim correctly rejected: {e}")

        # Correct preimage: build, broadcast, and confirm.
        built = claimer.buildhtlcclaim(
            claim_desc, {"txid": c_txid, "vout": c_vout},
            preimage.hex(), dest_addr, fee)
        assert_equal(built["complete"], True)
        claim_txid = node.sendrawtransaction(built["hex"])
        mine_block(self, node, mine_addr)

        # Destination received the locked value minus fee.
        assert_equal(claimer.gettransaction(claim_txid)["confirmations"] >= 1, True)
        assert_equal(Decimal(str(claimer.getreceivedbyaddress(dest_addr))),
                     claim_amount - fee_btx)

        # The preimage is now revealed on-chain in the claim witness (so the EVM leg
        # can be claimed). Scan the witness stack for the matching item.
        # No -txindex on this node: scope the lookup to the block that confirmed it.
        claim_tx = node.getrawtransaction(claim_txid, True, node.getbestblockhash())
        revealed = False
        want = hash160(preimage)
        for vin in claim_tx["vin"]:
            for item_hex in vin.get("txinwitness", []) or []:
                try:
                    if hash160(bytes.fromhex(item_hex)) == want:
                        revealed = True
                except ValueError:
                    continue
        assert_equal(revealed, True)

        # === Scenario 2: REFUND after the locktime =============================
        self.log.info("HTLC REFUND: lock, refund after locktime, assert payout")
        refund_preimage = bytes.fromhex("a5" * 32)  # never revealed; refund ignores it
        refund_h160_hex = hash160(refund_preimage).hex()

        refund_locktime = node.getblockcount() + 6
        refund_desc, refund_addr = self.build_htlc_descriptor(
            node, internal_pk, refund_h160_hex, claimer_pk, refund_locktime, sender_pk)
        sender.importdescriptors([
            {"desc": refund_desc, "timestamp": "now", "internal": False}
        ])

        refund_amount = Decimal("2.0")
        r_txid, r_vout, r_value = self.fund_lock(sender, node, mine_addr, refund_addr, refund_amount)

        refund_dest = sender.getnewaddress(address_type="p2mr")

        # Before the locktime the refund leaf is not yet spendable.
        self.log.info("HTLC REFUND negative: refund before locktime must fail")
        assert_greater_than(refund_locktime, node.getblockcount())
        try:
            early = sender.buildhtlcrefund(
                refund_desc, {"txid": r_txid, "vout": r_vout},
                refund_dest, refund_locktime, fee)
            assert_equal(early.get("complete", False), False)
            if early.get("hex"):
                assert_raises_rpc_error(-26, None, node.sendrawtransaction, early["hex"])
        except Exception as e:  # noqa: BLE001 - RPC raising before locktime is acceptable
            self.log.info(f"early refund correctly rejected: {e}")

        # Mine past the locktime, then refund.
        blocks_needed = max(0, refund_locktime - node.getblockcount())
        if blocks_needed:
            mine_block(self, node, mine_addr, blocks_needed)

        refunded = sender.buildhtlcrefund(
            refund_desc, {"txid": r_txid, "vout": r_vout},
            refund_dest, refund_locktime, fee)
        assert_equal(refunded["complete"], True)
        refund_txid = node.sendrawtransaction(refunded["hex"])
        mine_block(self, node, mine_addr)

        assert_equal(sender.gettransaction(refund_txid)["confirmations"] >= 1, True)
        assert_equal(Decimal(str(sender.getreceivedbyaddress(refund_dest))),
                     refund_amount - fee_btx)


if __name__ == "__main__":
    WalletHtlcAtomicSwapTest(__file__).main()
