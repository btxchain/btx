#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Live prefork v2 transaction-family benchmark and privacy analysis test.

Tests the current wallet-visible prefork v2 send surface:
1. Transparent-to-shielded deposit (proofless v2_send)
2. Shielded-to-shielded direct send (Smile v2_send proof)
3. Shielded-to-transparent unshield (mixed v2_send, prefork compatibility)
4. Verify wallet privacy/view semantics
5. Benchmark serialized size, weight, and block-fit capacity

Post-`61000` readiness is tracked separately by the explicit runtime reports and
postfork functional suites, because mixed direct unshield is intentionally
disabled after the fork in favor of bridge/egress settlement.
"""

import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.util import assert_equal, assert_greater_than


class WalletSmileV2BenchmarkTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-noautoshieldcoinbase", "-txindex", "-regtestshieldedmatrictdisableheight=500"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def capture_tx_metrics(self, wallet, txid):
        raw_hex = self.nodes[0].getrawtransaction(txid)
        raw_decoded = self.nodes[0].getrawtransaction(txid, 2)
        view = wallet.z_viewtransaction(txid)
        return {
            "family": view["family"],
            "bundle_type": raw_decoded.get("shielded", {}).get("bundle_type", "none"),
            "bytes": len(raw_hex) // 2,
            "weight": raw_decoded["weight"],
            "vsize": raw_decoded["vsize"],
            "transparent_inputs": len(raw_decoded["vin"]),
            "transparent_outputs": len(raw_decoded["vout"]),
        }

    def log_capacity(self, label, metrics, prove_time):
        block_size_limit = 24_000_000
        max_txs_per_block = block_size_limit // metrics["bytes"]
        tps = max_txs_per_block / 90.0
        self.log.info(
            "%s: family=%s bundle=%s bytes=%d weight=%d vsize=%d prove=%.3fs tx_per_block=%d tps=%.2f",
            label,
            metrics["family"],
            metrics["bundle_type"],
            metrics["bytes"],
            metrics["weight"],
            metrics["vsize"],
            prove_time,
            max_txs_per_block,
            tps,
        )

    def run_test(self):
        node = self.nodes[0]

        # Create sender and receiver wallets
        node.createwallet(wallet_name="sender", descriptors=True)
        node.createwallet(wallet_name="receiver", descriptors=True)
        sender = encrypt_and_unlock_wallet(node, "sender")
        receiver = encrypt_and_unlock_wallet(node, "receiver")

        mine_addr = sender.getnewaddress()
        z_sender = sender.z_getnewaddress()
        z_receiver = receiver.z_getnewaddress()

        self.log.info("Fund sender with transparent coins and shield")
        fund_trusted_transparent_balance(
            self, node, sender, mine_addr, Decimal("10.0"), sync_fun=self.no_op
        )
        t0 = time.time()
        shield_result = sender.z_shieldfunds(Decimal("5.0"), z_sender)
        t1 = time.time()
        shield_prove_time = t1 - t0
        shield_metrics = self.capture_tx_metrics(sender, shield_result["txid"])
        assert_equal(shield_metrics["family"], "v2_send")
        self.log_capacity("deposit_v2_send", shield_metrics, shield_prove_time)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        # Build ring diversity
        ensure_ring_diversity(
            self, node, sender, mine_addr, z_sender,
            min_notes=20, topup_amount=Decimal("0.5")
        )

        balance = Decimal(sender.z_getbalance()["balance"])
        self.log.info(f"Shielded balance: {balance} BTX")
        assert_greater_than(balance, Decimal("1.0"))

        # ===== BENCHMARK: First v2_send =====
        self.log.info("BENCHMARK: First shielded send (0.1 BTX)")
        t0 = time.time()
        result1 = sender.z_sendmany([{"address": z_receiver, "amount": Decimal("0.1")}])
        t1 = time.time()
        prove_time_1 = t1 - t0
        txid1 = result1["txid"]
        self.log.info(f"  txid: {txid1}")
        self.log.info(f"  prove_time: {prove_time_1:.3f}s")
        self.log.info(f"  spends: {result1['spends']}, outputs: {result1['outputs']}")
        self.log.info(f"  fee: {result1['fee']}")

        # Check mempool entry for size
        direct_metrics = self.capture_tx_metrics(sender, txid1)
        assert_equal(direct_metrics["family"], "v2_send")
        self.log.info(f"  tx_weight: {direct_metrics['weight']} WU")
        self.log.info(f"  tx_vsize: {direct_metrics['vsize']} vB")
        self.log.info(f"  tx_bytes: {direct_metrics['bytes']} B")
        self.log_capacity("direct_v2_send", direct_metrics, prove_time_1)

        # Confirm
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        tx_info = sender.gettransaction(txid1)
        assert_equal(tx_info["confirmations"], 1)

        # Check receiver got funds
        recv_balance = Decimal(receiver.z_getbalance()["balance"])
        assert_equal(recv_balance, Decimal("0.1"))
        self.log.info(f"  receiver_balance: {recv_balance} BTX")

        # Check sender change detected
        sender_balance = Decimal(sender.z_getbalance()["balance"])
        assert_greater_than(sender_balance, Decimal("0"))
        sender_notes = sender.z_listunspent()
        self.log.info(f"  sender_balance: {sender_balance} BTX ({len(sender_notes)} notes)")

        # ===== PRIVACY ANALYSIS =====
        self.log.info("PRIVACY ANALYSIS: Inspect transaction on-chain")
        raw_tx = node.getrawtransaction(txid1, 2)
        shielded = raw_tx.get("shielded", {})

        # What's visible
        visible_inputs = shielded.get("shielded_input_count", 0)
        visible_outputs = shielded.get("shielded_output_count", 0)
        value_balance = shielded.get("value_balance", 0)
        bundle_type = shielded.get("bundle_type", "unknown")

        self.log.info(f"  bundle_type: {bundle_type}")
        self.log.info(f"  visible_inputs: {visible_inputs}")
        self.log.info(f"  visible_outputs: {visible_outputs}")
        self.log.info(f"  value_balance: {value_balance}")
        self.log.info(f"  transparent_in: {len(raw_tx['vin'])}")
        self.log.info(f"  transparent_out: {len(raw_tx['vout'])}")

        # Privacy assertions
        assert_equal(len(raw_tx["vin"]), 0)
        assert_equal(len(raw_tx["vout"]), 0)
        assert_equal(bundle_type, "v2")

        # Verify sender and receiver see different amounts
        sender_view = sender.z_viewtransaction(txid1)
        receiver_view = receiver.z_viewtransaction(txid1)

        # Sender sees: spend amount + change amount
        sender_sees_spend = any(s["is_ours"] for s in sender_view["spends"])
        sender_sees_change = any(o["is_ours"] and o["amount"] > 0 for o in sender_view["outputs"])
        assert sender_sees_spend, "Sender should see their spend"
        assert sender_sees_change, "Sender should see their change"

        # Receiver sees: received amount (check with Decimal for precision)
        receiver_sees_output = any(o["is_ours"] and Decimal(str(o["amount"])) == Decimal("0.1") for o in receiver_view["outputs"])
        receiver_sees_any_output = any(o["is_ours"] for o in receiver_view["outputs"])
        receiver_no_spend = not any(s["is_ours"] for s in receiver_view["spends"])
        self.log.info(f"  receiver_sees_output (0.1): {receiver_sees_output}")
        self.log.info(f"  receiver_sees_any_output: {receiver_sees_any_output}")
        for o in receiver_view["outputs"]:
            self.log.info(f"    output: is_ours={o['is_ours']} amount={o['amount']}")
        assert receiver_sees_any_output or receiver_sees_output, "Receiver should see their output"
        assert receiver_no_spend, "Receiver should not see the spend"

        self.log.info("  PRIVACY: Sender/receiver views are correctly segregated")

        # ===== BENCHMARK: Mixed unshield =====
        self.log.info("BENCHMARK: Shielded-to-transparent unshield (0.2 BTX)")
        t_dest = sender.getnewaddress()
        t0 = time.time()
        unshield_result = sender.z_sendmany([{"address": t_dest, "amount": Decimal("0.2")}])
        t1 = time.time()
        unshield_prove_time = t1 - t0
        unshield_metrics = self.capture_tx_metrics(sender, unshield_result["txid"])
        assert_equal(unshield_metrics["family"], "v2_send")
        self.log_capacity("mixed_unshield_v2_send", unshield_metrics, unshield_prove_time)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(sender.getreceivedbyaddress(t_dest), Decimal("0.2"))

        # ===== BENCHMARK: Chain of sends =====
        self.log.info("BENCHMARK: Chain of 3 sequential sends")
        times = []
        sizes = []
        for i in range(3):
            t0 = time.time()
            result = sender.z_sendmany([{"address": z_receiver, "amount": Decimal("0.01")}])
            t1 = time.time()
            times.append(t1 - t0)
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

            entry = node.getmempoolentry(result["txid"]) if node.getrawmempool() else None
            if entry:
                sizes.append(entry["weight"])
            else:
                # Already confirmed, get from block
                tx_raw = node.getrawtransaction(result["txid"], 2)
                sizes.append(tx_raw["weight"])

            self.log.info(f"  send[{i}]: prove={times[-1]:.3f}s weight={sizes[-1]} WU txid={result['txid'][:16]}...")

        avg_prove = sum(times) / len(times)
        avg_weight = sum(sizes) / len(sizes)
        self.log.info(f"  avg_prove_time: {avg_prove:.3f}s")
        self.log.info(f"  avg_tx_weight: {avg_weight} WU ({avg_weight/1000:.1f} kWU)")

        # ===== SCALABILITY METRICS =====
        self.log.info("SCALABILITY METRICS:")
        block_weight_limit = 24_000_000
        max_smile_txs_per_block = block_weight_limit // int(avg_weight)
        target_block_time = 90  # seconds
        tps = max_smile_txs_per_block / target_block_time

        self.log.info(f"  avg_tx_weight: {avg_weight} WU")
        self.log.info(f"  block_weight_limit: {block_weight_limit} WU")
        self.log.info(f"  max_smile_txs_per_block: {max_smile_txs_per_block}")
        self.log.info(f"  target_block_time: {target_block_time}s")
        self.log.info(f"  theoretical_tps: {tps:.2f}")
        self.log.info(f"  avg_prove_time: {avg_prove:.3f}s")

        # Final balance check
        final_sender = Decimal(sender.z_getbalance()["balance"])
        final_recv = Decimal(receiver.z_getbalance()["balance"])
        self.log.info(f"  final_sender_balance: {final_sender} BTX")
        self.log.info(f"  final_receiver_balance: {final_recv} BTX")

        # Receiver should have 0.1 + 3*0.01 = 0.13 BTX
        assert_equal(final_recv, Decimal("0.13"))
        self.log.info("All v2_send benchmark tests passed")


if __name__ == "__main__":
    WalletSmileV2BenchmarkTest(__file__).main()
