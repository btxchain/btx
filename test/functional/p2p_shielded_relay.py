#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test shielded transaction P2P relay gating and message handling."""

from decimal import Decimal
import time

from test_framework.bridge_utils import (
    bridge_hex,
    build_signed_shielded_relay_fixture_tx,
    build_unsigned_shielded_relay_fixture_tx,
    build_ingress_batch_tx,
    build_ingress_statement,
    build_proof_policy,
    build_proof_profile,
    build_proof_receipt,
)
from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_WTX,
    NODE_NETWORK,
    NODE_WITNESS,
    deser_uint256,
    msg_generic,
    msg_getdata,
    msg_mempool,
    ser_uint256,
)
from test_framework.p2p import MESSAGEMAP, P2PInterface
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


NODE_SHIELDED = (1 << 8)
MAX_BLOCKTXN_DEPTH = 10
MAX_SHIELDED_TX_SIZE = 6_500_000
MAX_INITIAL_BROADCAST_DELAY = 15 * 60
INBOUND_INVENTORY_BROADCAST_INTERVAL = 5
HIGH_SHIELDED_FEE_DELTA = 100_000_000
# `setmocktime` is second-granular, while peers track their next inventory slot
# at microsecond precision. Overshoot a full extra interval so the test never
# lands just short of the scheduled send time.
INBOUND_INVENTORY_BROADCAST_OVERSHOOT = INBOUND_INVENTORY_BROADCAST_INTERVAL * 2 + 1


class msg_shieldedtx:
    __slots__ = ("data",)
    msgtype = b"shieldedtx"

    def __init__(self, data=b""):
        self.data = data

    def deserialize(self, f):
        self.data = f.read()

    def serialize(self):
        return self.data

    def __repr__(self):
        return "msg_shieldedtx()"


class msg_getshlddata:
    __slots__ = ("block_hash",)
    msgtype = b"getshlddata"

    def __init__(self, block_hash=0):
        self.block_hash = block_hash

    def deserialize(self, f):
        self.block_hash = deser_uint256(f)

    def serialize(self):
        return ser_uint256(self.block_hash)

    def __repr__(self):
        return f"msg_getshlddata(block_hash={self.block_hash:#x})"


class msg_shieldeddata:
    __slots__ = ("payload",)
    msgtype = b"shieldeddata"

    def __init__(self, payload=b""):
        self.payload = payload

    def deserialize(self, f):
        self.payload = f.read()

    def serialize(self):
        return self.payload

    def __repr__(self):
        return f"msg_shieldeddata(payload_len={len(self.payload)})"


class msg_rawblock:
    __slots__ = ("payload",)
    msgtype = b"block"

    def __init__(self, payload=b""):
        self.payload = payload

    def deserialize(self, f):
        # Functional message parser does not understand BTX shielded tx
        # serialization inside blocks. Keep the raw payload to avoid parser
        # crashes while this test validates shielded relay message behavior.
        self.payload = f.read()

    def serialize(self):
        return self.payload


class VersionedP2PInterface(P2PInterface):
    def __init__(self, protocol_version, **kwargs):
        super().__init__(**kwargs)
        self.protocol_version = protocol_version

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.nVersion = self.protocol_version


class ShieldedObserverPeer(VersionedP2PInterface):
    def __init__(self, protocol_version, **kwargs):
        super().__init__(protocol_version=protocol_version, **kwargs)
        self.tx_count = 0
        self.shieldedtx_count = 0
        self.shieldeddata_count = 0
        self.last_shieldeddata_payload_len = 0
        self.last_shieldeddata_payload = b""
        self.notfound_count = 0

    def on_tx(self, message):
        self.tx_count += 1

    def on_shieldedtx(self, message):
        self.shieldedtx_count += 1

    def on_shieldeddata(self, message):
        self.shieldeddata_count += 1
        self.last_shieldeddata_payload_len = len(message.payload)
        self.last_shieldeddata_payload = message.payload

    def on_notfound(self, message):
        # test_framework.msg_notfound stores inventory entries in `vec`.
        self.notfound_count += len(message.vec)


class ShieldedInvPeer(ShieldedObserverPeer):
    def __init__(self, protocol_version, **kwargs):
        super().__init__(protocol_version=protocol_version, **kwargs)
        self.announced_tx_hashes = set()

    def on_inv(self, message):
        self.announced_tx_hashes.update(
            entry.hash for entry in message.inv if entry.type in (MSG_TX, MSG_WTX)
        )
        super().on_inv(message)


class P2PShieldedRelayTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0", "-dandelion=0"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def set_mocktime_and_sync(self, node, peers, seconds):
        self.mocktime += seconds
        node.setmocktime(self.mocktime)
        for peer in peers:
            peer.sync_with_ping(timeout=120)

    def build_v2_ingress_batch_tx(self, node, source_wallet, mine_addr, ingress_wallet_name, seed):
        node.createwallet(wallet_name=ingress_wallet_name, descriptors=True)
        ingress_wallet = encrypt_and_unlock_wallet(node, ingress_wallet_name)
        ingress_taddr = ingress_wallet.getnewaddress()
        source_wallet.sendtoaddress(ingress_taddr, Decimal("1.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        ingress_funding_addr = ingress_wallet.z_getnewaddress()
        ingress_shield = ingress_wallet.z_shieldfunds(Decimal("0.40"), ingress_funding_addr)
        assert ingress_shield["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        proof_profile = build_proof_profile(
            ingress_wallet,
            family="shieldedegress",
            proof_type="receipt",
            claim_system="settlement",
        )
        descriptor = {
            "proof_system_id": proof_profile["proof_system_id"],
            "verifier_key_hash": bridge_hex(seed + 0x01),
        }
        proof_policy = build_proof_policy(ingress_wallet, [descriptor], required_receipts=1, targets=[descriptor])
        intents = [
            {
                "wallet_id": bridge_hex(seed + 0x02),
                "destination_id": bridge_hex(seed + 0x03),
                "amount": Decimal("0.19"),
                "authorization_hash": bridge_hex(seed + 0x04),
                "l2_id": bridge_hex(seed + 0x05),
                "fee": Decimal("0.01"),
            },
        ]
        reserve_outputs = [{"address": ingress_wallet.z_getnewaddress(), "amount": Decimal("0.20")}]
        statement = build_ingress_statement(
            ingress_wallet,
            intents,
            bridge_id=bridge_hex(seed + 0x06),
            operation_id=bridge_hex(seed + 0x07),
            domain_id=bridge_hex(seed + 0x08),
            source_epoch=22,
            data_root=bridge_hex(seed + 0x09),
            proof_policy=proof_policy["proof_policy"],
        )
        proof_receipt = build_proof_receipt(
            ingress_wallet,
            statement["statement_hex"],
            proof_profile_hex=proof_profile["profile_hex"],
            verifier_key_hash=descriptor["verifier_key_hash"],
            public_values_hash=bridge_hex(seed + 0x0A),
            proof_commitment=bridge_hex(seed + 0x0B),
        )
        proof_receipt_policy = {
            "min_receipts": 1,
            "required_proof_system_ids": [descriptor["proof_system_id"]],
            "required_verifier_key_hashes": [descriptor["verifier_key_hash"]],
            "descriptor_proofs": [proof_policy["proofs"][0]["proof_hex"]],
        }
        return build_ingress_batch_tx(
            ingress_wallet,
            statement["statement_hex"],
            intents,
            reserve_outputs,
            {
                "proof_receipts": [proof_receipt["proof_receipt_hex"]],
                "proof_receipt_policy": proof_receipt_policy,
            },
        )

    def wait_for_tx_relay(self, peer, txids, expected_shieldedtx_count):
        expected = {int(txid, 16) for txid in txids}

        def relay_observed():
            return expected.issubset(peer.announced_tx_hashes) and peer.shieldedtx_count >= expected_shieldedtx_count

        peer.wait_until(
            relay_observed,
            timeout=120,
        )
        peer.sync_with_ping(timeout=120)

    def run_test(self):
        # Register local decoder so test peers can parse shieldedtx responses.
        MESSAGEMAP[msg_shieldedtx.msgtype] = msg_shieldedtx
        MESSAGEMAP[msg_shieldeddata.msgtype] = msg_shieldeddata
        MESSAGEMAP[msg_rawblock.msgtype] = msg_rawblock

        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        protocol_version = node.getnetworkinfo()["protocolversion"]
        self.mocktime = int(time.time())
        node.setmocktime(self.mocktime)

        self.log.info("Create a shielded transaction in mempool for P2P relay tests")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("10.0"), sync_fun=self.no_op
        )

        z_from = wallet.z_getnewaddress()
        z_to = wallet.z_getnewaddress()
        shield_res = wallet.z_shieldfunds(Decimal("2.0"), z_from)
        assert shield_res["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(
            self, node, wallet, mine_addr, z_from, min_notes=16, topup_amount=Decimal("0.25")
        )
        peer_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        send = wallet.z_sendmany([{"address": z_to, "amount": Decimal("0.5")}])
        txid = send["txid"]
        self.wait_until(lambda: txid in node.getrawmempool(), timeout=60)
        raw_hex = node.getrawtransaction(txid, False)
        payload = bytes.fromhex(raw_hex)

        self.log.info("Shielded-capable peers should receive shieldedtx responses for getdata requests")
        self.set_mocktime_and_sync(node, [peer_shielded], MAX_INITIAL_BROADCAST_DELAY)
        def shielded_inv_announced():
            inv = peer_shielded.last_message.get("inv")
            if inv is None:
                return False
            return txid in {
                f"{entry.hash:064x}"
                for entry in inv.inv
                if entry.type in (MSG_TX, MSG_WTX)
            }

        self.wait_until(shielded_inv_announced, timeout=120)
        initial_getdata = msg_getdata()
        initial_getdata.inv = [CInv(MSG_TX, int(txid, 16))]
        peer_shielded.send_message(initial_getdata)
        peer_shielded.wait_until(lambda: peer_shielded.shieldedtx_count > 0)
        assert_greater_than(peer_shielded.shieldedtx_count, 0)

        self.log.info("Non-shielded peers sending shieldedtx must be disconnected")
        peer_non_shielded = node.add_p2p_connection(
            VersionedP2PInterface(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        with node.assert_debug_log(expected_msgs=["unexpected shielded tx from non-shielded peer"]):
            peer_non_shielded.send_message(msg_generic(b"shieldedtx", payload))
            peer_non_shielded.wait_for_disconnect()

        self.log.info("Non-shielded peers sending shielded bundles via legacy tx must be disconnected")
        peer_non_shielded_legacy = node.add_p2p_connection(
            VersionedP2PInterface(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        with node.assert_debug_log(expected_msgs=["unexpected shielded tx from non-shielded peer"]):
            peer_non_shielded_legacy.send_message(msg_generic(b"tx", payload))
            peer_non_shielded_legacy.wait_for_disconnect()

        self.log.info("Shielded-capable peers may send shieldedtx without disconnect")
        peer_shielded.send_and_ping(msg_generic(b"shieldedtx", payload))
        assert peer_shielded.is_connected

        self.log.info("Oversized shieldedtx payloads must be rejected early")
        peer_oversized_shieldedtx = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        oversized_payload = b"\x00" * (MAX_SHIELDED_TX_SIZE + 1)
        with node.assert_debug_log(expected_msgs=["oversized shieldedtx payload"]):
            peer_oversized_shieldedtx.send_message(msg_generic(b"shieldedtx", oversized_payload))
            peer_oversized_shieldedtx.wait_for_disconnect()

        def get_shielded_peer_stats():
            shielded_peers = [p for p in node.getpeerinfo() if "SHIELDED" in p["servicesnames"]]
            assert shielded_peers, "Expected at least one shielded-capable peer"
            # Newly connected peers have the highest id.
            return max(shielded_peers, key=lambda p: p["id"])

        def trigger_rate_limit_counter(peer, send_message_factory, counter_key, baseline_value, label):
            # v2 transport has materially higher per-message overhead. Send in
            # bounded batches and stop once the counter increments.
            batch_size = 4 if self.options.v2transport else 64
            max_batches = 48 if self.options.v2transport else 40
            for _ in range(max_batches):
                for _ in range(batch_size):
                    peer.send_message(send_message_factory())
                peer.sync_with_ping(timeout=120)
                if int(get_shielded_peer_stats()[counter_key]) > baseline_value:
                    return
            raise AssertionError(f"did not observe {counter_key} increment for {label}")

        self.log.info("Trigger inbound shieldedtx rate limiting counter")
        peer_inbound_rate_limit_tx = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        baseline_inbound_tx_limited = int(get_shielded_peer_stats()["shieldedtx_rate_limited"])
        trigger_rate_limit_counter(
            peer_inbound_rate_limit_tx,
            lambda: msg_generic(b"shieldedtx", payload),
            "shieldedtx_rate_limited",
            baseline_inbound_tx_limited,
            "inbound shieldedtx",
        )

        self.log.info("Trigger inbound shielded payload rate limiting over legacy tx transport")
        peer_inbound_rate_limit_legacy_tx = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        baseline_legacy_tx_limited = int(get_shielded_peer_stats()["shieldedtx_rate_limited"])
        trigger_rate_limit_counter(
            peer_inbound_rate_limit_legacy_tx,
            lambda: msg_generic(b"tx", payload),
            "shieldedtx_rate_limited",
            baseline_legacy_tx_limited,
            "legacy-tx shielded payload",
        )

        self.log.info("Trigger shieldedtx relay rate limiting counter")
        peer_rate_limit_tx = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        rate_limit_send = wallet.z_sendmany([{"address": wallet.z_getnewaddress(), "amount": Decimal("0.5")}])
        rate_limit_txid = rate_limit_send["txid"]
        self.wait_until(lambda: rate_limit_txid in node.getrawmempool(), timeout=60)
        self.set_mocktime_and_sync(node, [peer_rate_limit_tx], MAX_INITIAL_BROADCAST_DELAY)

        def rate_limit_inv_announced():
            inv = peer_rate_limit_tx.last_message.get("inv")
            if inv is None:
                return False
            return rate_limit_txid in {
                f"{entry.hash:064x}"
                for entry in inv.inv
                if entry.type in (MSG_TX, MSG_WTX)
            }

        self.wait_until(rate_limit_inv_announced, timeout=120)
        rate_limit_getdata = msg_getdata()
        rate_limit_getdata.inv = [CInv(MSG_TX, int(rate_limit_txid, 16))]
        baseline_tx_limited = int(get_shielded_peer_stats()["shieldedtx_rate_limited"])
        trigger_rate_limit_counter(
            peer_rate_limit_tx,
            lambda: rate_limit_getdata,
            "shieldedtx_rate_limited",
            baseline_tx_limited,
            "shieldedtx getdata relay",
        )

        self.log.info("Non-shielded peers must not receive shielded tx payloads over getdata")
        peer_non_shielded_fetch = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        peer_non_shielded_fetch.send_and_ping(rate_limit_getdata)
        assert peer_non_shielded_fetch.shieldedtx_count == 0

        self.log.info("Mine a block containing shielded transaction for getshlddata/shieldeddata checks")
        shielded_block = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]
        shielded_block_hash = int(shielded_block, 16)

        self.log.info("Non-shielded peers sending getshlddata must be disconnected")
        peer_non_shielded_data = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        with node.assert_debug_log(expected_msgs=["unexpected getshieldeddata from non-shielded peer"]):
            peer_non_shielded_data.send_message(msg_getshlddata(block_hash=shielded_block_hash))
            peer_non_shielded_data.wait_for_disconnect()

        self.log.info("Shielded-capable peers should receive shieldeddata responses")
        peer_shielded.send_message(msg_getshlddata(block_hash=shielded_block_hash))
        peer_shielded.wait_until(lambda: peer_shielded.shieldeddata_count > 0)
        assert_greater_than(peer_shielded.last_shieldeddata_payload_len, 0)

        self.log.info("Requests for shielded data deeper than policy window should be ignored")
        self.generatetoaddress(node, MAX_BLOCKTXN_DEPTH + 1, mine_addr, sync_fun=self.no_op)
        stale_count_before = peer_shielded.shieldeddata_count
        peer_shielded.send_and_ping(msg_getshlddata(block_hash=shielded_block_hash))
        assert peer_shielded.shieldeddata_count == stale_count_before

        self.log.info("Flooded getshlddata requests should be rate-limited before expensive reads")
        empty_tip_block_hash = int(node.getbestblockhash(), 16)
        peer_request_rate_limit = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        baseline_request_limited = int(get_shielded_peer_stats()["shieldeddata_rate_limited"])
        trigger_rate_limit_counter(
            peer_request_rate_limit,
            lambda: msg_getshlddata(block_hash=empty_tip_block_hash),
            "shieldeddata_rate_limited",
            baseline_request_limited,
            "getshlddata request",
        )

        self.log.info("Reject getshlddata with null block hash")
        peer_null_request = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        with node.assert_debug_log(expected_msgs=["getshieldeddata with null block hash"]):
            peer_null_request.send_message(msg_getshlddata(block_hash=0))
            peer_null_request.wait_for_disconnect()

        self.log.info("Reject unsolicited inbound shieldeddata payloads")
        peer_unsolicited_shieldeddata = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        with node.assert_debug_log(expected_msgs=["unexpected shieldeddata (no outstanding request)"]):
            peer_unsolicited_shieldeddata.send_message(msg_shieldeddata(b""))
            peer_unsolicited_shieldeddata.wait_for_disconnect()

        self.log.info("Non-shielded peers sending shieldeddata must be disconnected")
        peer_non_shielded_unsolicited = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        with node.assert_debug_log(expected_msgs=["unexpected shieldeddata from non-shielded peer"]):
            peer_non_shielded_unsolicited.send_message(msg_shieldeddata(b""))
            peer_non_shielded_unsolicited.wait_for_disconnect()

        self.log.info("Expose shielded relay counters and trigger shieldeddata rate limiting")
        # Use a fresh shielded block within the policy depth window.
        z_rate_limit = wallet.z_getnewaddress()
        ensure_ring_diversity(self, node, wallet, mine_addr, z_from)
        wallet.z_sendmany([{"address": z_rate_limit, "amount": Decimal("0.01")}])
        rate_limit_block_hash = int(self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0], 16)

        peer_rate_limit = node.add_p2p_connection(
            ShieldedObserverPeer(protocol_version=protocol_version),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )

        initial_stats = get_shielded_peer_stats()
        assert "shieldedtx_rate_limited" in initial_stats
        assert "shieldeddata_rate_limited" in initial_stats
        baseline_limited = int(initial_stats["shieldeddata_rate_limited"])

        # A sustained burst should consume the peer's shielded block-data relay budget.
        trigger_rate_limit_counter(
            peer_rate_limit,
            lambda: msg_getshlddata(block_hash=rate_limit_block_hash),
            "shieldeddata_rate_limited",
            baseline_limited,
            "shieldeddata relay",
        )

        self.log.info("Unsolicited shieldeddata must still disconnect after budget exhaustion")
        with node.assert_debug_log(expected_msgs=["unexpected shieldeddata (no outstanding request)"]):
            peer_rate_limit.send_message(msg_shieldeddata(b""))
            peer_rate_limit.wait_for_disconnect()

        self.log.info("Disconnect legacy relay peers before exercising shielded_v2 announcement behavior")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

        self.log.info("Build deterministic v2_ingress_batch transaction for mixed-family relay tests")
        v2_ingress_tx_a = self.build_v2_ingress_batch_tx(node, wallet, mine_addr, "relay_ingress_a", 0x2A0)
        assert_equal(v2_ingress_tx_a["family"], "v2_ingress_batch")

        self.log.info("Shielded-capable peers should receive inv announcements and shieldedtx fetches for mixed v2_send and v2_ingress_batch families")
        peer_v2_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_v2_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        mixed_v2_send = wallet.z_sendmany([{"address": wallet.z_getnewaddress(), "amount": Decimal("0.13")}])
        mixed_v2_send_txid = mixed_v2_send["txid"]
        self.wait_until(lambda: mixed_v2_send_txid in node.getrawmempool(), timeout=60)
        assert_equal(node.sendrawtransaction(v2_ingress_tx_a["tx_hex"]), v2_ingress_tx_a["txid"])
        self.set_mocktime_and_sync(node, [peer_v2_shielded, peer_v2_non_shielded], MAX_INITIAL_BROADCAST_DELAY)
        self.wait_for_tx_relay(
            peer_v2_shielded,
            [mixed_v2_send_txid, v2_ingress_tx_a["txid"]],
            expected_shieldedtx_count=2,
        )
        assert_equal(peer_v2_non_shielded.message_count["inv"], 0)
        assert_equal(peer_v2_non_shielded.shieldedtx_count, 0)

        self.log.info("Fresh peers requesting mempool should only receive mixed shielded families when they advertise NODE_SHIELDED")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        peer_v2_mempool_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_v2_mempool_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        peer_v2_mempool_shielded.send_message(msg_mempool())
        peer_v2_mempool_non_shielded.send_message(msg_mempool())
        self.set_mocktime_and_sync(
            node,
            [peer_v2_mempool_shielded, peer_v2_mempool_non_shielded],
            INBOUND_INVENTORY_BROADCAST_OVERSHOOT,
        )
        # Re-issue the mempool request after overshooting the scheduled inventory
        # slot so the response does not depend on when the first request arrived
        # relative to peer inventory scheduling.
        peer_v2_mempool_shielded.send_message(msg_mempool())
        peer_v2_mempool_non_shielded.send_message(msg_mempool())
        peer_v2_mempool_shielded.sync_with_ping(timeout=120)
        peer_v2_mempool_non_shielded.sync_with_ping(timeout=120)
        self.wait_for_tx_relay(
            peer_v2_mempool_shielded,
            [mixed_v2_send_txid, v2_ingress_tx_a["txid"]],
            expected_shieldedtx_count=2,
        )
        assert_equal(peer_v2_mempool_non_shielded.message_count["inv"], 0)
        assert_equal(peer_v2_mempool_non_shielded.shieldedtx_count, 0)

        self.log.info("Fresh shielded-capable peers should see the same mixed v2_send and v2_ingress_batch families re-announced after a mine/reorg cycle")
        mined_block = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]
        assert_equal(node.getrawmempool(), [])

        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        node.invalidateblock(mined_block)
        self.wait_until(
            lambda: set(node.getrawmempool()) == {mixed_v2_send_txid, v2_ingress_tx_a["txid"]},
            timeout=60,
        )
        peer_v2_reorg_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_v2_reorg_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_v2_reorg_shielded, peer_v2_reorg_non_shielded],
            MAX_INITIAL_BROADCAST_DELAY,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_v2_reorg_shielded, peer_v2_reorg_non_shielded],
            INBOUND_INVENTORY_BROADCAST_OVERSHOOT,
        )
        self.wait_for_tx_relay(
            peer_v2_reorg_shielded,
            [mixed_v2_send_txid, v2_ingress_tx_a["txid"]],
            expected_shieldedtx_count=2,
        )
        assert_equal(peer_v2_reorg_non_shielded.message_count["inv"], 0)
        assert_equal(peer_v2_reorg_non_shielded.shieldedtx_count, 0)

        self.log.info("Mine the resurrected mixed v2_send/v2_ingress mempool before exercising rebalance and settlement-anchor relay")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Build live wallet-signed v2_rebalance and reserve-bound v2_settlement_anchor relay fixtures")
        relay_utxos = [
            utxo
            for utxo in wallet.listunspent(101)
            if utxo.get("spendable", False) and Decimal(str(utxo["amount"])) > Decimal("0.001")
        ]
        assert len(relay_utxos) >= 2, relay_utxos
        rebalance_fixture = build_signed_shielded_relay_fixture_tx(
            self, node, wallet, "rebalance", relay_utxos[0], require_mempool_accept=True
        )
        settlement_fixture = build_signed_shielded_relay_fixture_tx(
            self, node, wallet, "settlement_anchor_receipt", relay_utxos[1]
        )
        assert_equal(
            rebalance_fixture["netting_manifest_id"],
            settlement_fixture["netting_manifest_id"],
        )

        self.log.info("Shielded-capable peers should receive live v2_rebalance announcements")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        peer_rebalance_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_rebalance_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        assert_equal(
            node.sendrawtransaction(
                hexstring=rebalance_fixture["signed_tx_hex"],
                maxfeerate=0,
            ),
            rebalance_fixture["txid"],
        )
        self.wait_until(lambda: rebalance_fixture["txid"] in node.getrawmempool(), timeout=60)
        self.set_mocktime_and_sync(
            node,
            [peer_rebalance_shielded, peer_rebalance_non_shielded],
            MAX_INITIAL_BROADCAST_DELAY,
        )
        self.wait_for_tx_relay(
            peer_rebalance_shielded,
            [rebalance_fixture["txid"]],
            expected_shieldedtx_count=1,
        )
        assert_equal(peer_rebalance_non_shielded.message_count["inv"], 0)
        assert_equal(peer_rebalance_non_shielded.shieldedtx_count, 0)

        self.log.info("Mine v2_rebalance so the netting manifest becomes anchorable")
        rebalance_block = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]
        assert_equal(node.getrawmempool(), [])

        self.log.info("Shielded-capable peers should receive live reserve-bound v2_settlement_anchor announcements once the manifest is anchored")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        peer_settlement_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_settlement_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        assert_equal(
            node.sendrawtransaction(
                hexstring=settlement_fixture["signed_tx_hex"],
                maxfeerate=0,
            ),
            settlement_fixture["txid"],
        )
        self.wait_until(
            lambda: set(node.getrawmempool()) == {settlement_fixture["txid"]},
            timeout=60,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_settlement_shielded, peer_settlement_non_shielded],
            MAX_INITIAL_BROADCAST_DELAY,
        )
        self.wait_for_tx_relay(
            peer_settlement_shielded,
            [settlement_fixture["txid"]],
            expected_shieldedtx_count=1,
        )
        assert_equal(peer_settlement_non_shielded.message_count["inv"], 0)
        assert_equal(peer_settlement_non_shielded.shieldedtx_count, 0)

        self.log.info("Fresh shielded-capable peers should see the settlement-anchor family re-announced after reorg while the manifest anchor stays active")
        settlement_block = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]
        assert_equal(node.getrawmempool(), [])
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        node.invalidateblock(settlement_block)
        self.wait_until(
            lambda: set(node.getrawmempool()) == {settlement_fixture["txid"]},
            timeout=60,
        )
        peer_settlement_reorg_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_settlement_reorg_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_settlement_reorg_shielded, peer_settlement_reorg_non_shielded],
            MAX_INITIAL_BROADCAST_DELAY,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_settlement_reorg_shielded, peer_settlement_reorg_non_shielded],
            INBOUND_INVENTORY_BROADCAST_OVERSHOOT,
        )
        self.wait_for_tx_relay(
            peer_settlement_reorg_shielded,
            [settlement_fixture["txid"]],
            expected_shieldedtx_count=1,
        )
        assert_equal(peer_settlement_reorg_non_shielded.message_count["inv"], 0)
        assert_equal(peer_settlement_reorg_non_shielded.shieldedtx_count, 0)

        self.log.info("Re-mine the reserve-bound settlement anchor so live v2_egress_batch relay can bind to an active anchor")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Build deterministic bare v2_egress_batch relay fixture and prioritise it for mempool admission")
        egress_fixture = build_unsigned_shielded_relay_fixture_tx(
            self, node, "egress_receipt"
        )
        assert_equal(egress_fixture["family"], "v2_egress_batch")
        assert_equal(
            egress_fixture["settlement_anchor_digest"],
            settlement_fixture["settlement_anchor_digest"],
        )
        node.prioritisetransaction(txid=egress_fixture["txid"], fee_delta=HIGH_SHIELDED_FEE_DELTA)

        self.log.info("Shielded-capable peers should receive live v2_egress_batch announcements once the settlement anchor is active")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        peer_egress_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_egress_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        assert_equal(node.sendrawtransaction(hexstring=egress_fixture["tx_hex"], maxfeerate=0), egress_fixture["txid"])
        self.wait_until(lambda: set(node.getrawmempool()) == {egress_fixture["txid"]}, timeout=60)
        self.set_mocktime_and_sync(
            node,
            [peer_egress_shielded, peer_egress_non_shielded],
            MAX_INITIAL_BROADCAST_DELAY,
        )
        self.wait_for_tx_relay(
            peer_egress_shielded,
            [egress_fixture["txid"]],
            expected_shieldedtx_count=1,
        )
        assert_equal(peer_egress_non_shielded.message_count["inv"], 0)
        assert_equal(peer_egress_non_shielded.shieldedtx_count, 0)

        self.log.info("Fresh shielded-capable peers should see live v2_egress_batch re-announced after a mine/reorg cycle while the settlement anchor stays active")
        egress_block = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]
        assert_equal(node.getrawmempool(), [])
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        # Bare v2_egress_batch relay uses a local fee delta rather than a
        # transparent fee carrier. Re-seed that delta before invalidation so
        # the disconnected-block reaccept path evaluates the same effective
        # feerate it used for the original live relay.
        node.prioritisetransaction(txid=egress_fixture["txid"], fee_delta=HIGH_SHIELDED_FEE_DELTA)
        node.invalidateblock(egress_block)
        self.wait_until(
            lambda: set(node.getrawmempool()) == {egress_fixture["txid"]},
            timeout=60,
        )
        peer_egress_reorg_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_egress_reorg_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_egress_reorg_shielded, peer_egress_reorg_non_shielded],
            MAX_INITIAL_BROADCAST_DELAY,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_egress_reorg_shielded, peer_egress_reorg_non_shielded],
            INBOUND_INVENTORY_BROADCAST_OVERSHOOT,
        )
        self.wait_for_tx_relay(
            peer_egress_reorg_shielded,
            [egress_fixture["txid"]],
            expected_shieldedtx_count=1,
        )
        assert_equal(peer_egress_reorg_non_shielded.message_count["inv"], 0)
        assert_equal(peer_egress_reorg_non_shielded.shieldedtx_count, 0)

        self.log.info("Mine the resurrected v2_egress_batch before dropping the rebalance anchor")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Dropping the rebalance anchor should evict the settlement-anchor family and only resurrect v2_rebalance")
        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)
        node.invalidateblock(rebalance_block)
        self.wait_until(
            lambda: set(node.getrawmempool()) == {rebalance_fixture["txid"]},
            timeout=60,
        )
        peer_rebalance_reorg_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS | NODE_SHIELDED,
        )
        peer_rebalance_reorg_non_shielded = node.add_p2p_connection(
            ShieldedInvPeer(protocol_version=protocol_version, wtxidrelay=False),
            services=NODE_NETWORK | NODE_WITNESS,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_rebalance_reorg_shielded, peer_rebalance_reorg_non_shielded],
            MAX_INITIAL_BROADCAST_DELAY,
        )
        self.set_mocktime_and_sync(
            node,
            [peer_rebalance_reorg_shielded, peer_rebalance_reorg_non_shielded],
            INBOUND_INVENTORY_BROADCAST_OVERSHOOT,
        )
        self.wait_for_tx_relay(
            peer_rebalance_reorg_shielded,
            [rebalance_fixture["txid"]],
            expected_shieldedtx_count=1,
        )
        assert int(settlement_fixture["txid"], 16) not in peer_rebalance_reorg_shielded.announced_tx_hashes
        assert_equal(peer_rebalance_reorg_non_shielded.message_count["inv"], 0)
        assert_equal(peer_rebalance_reorg_non_shielded.shieldedtx_count, 0)


if __name__ == "__main__":
    P2PShieldedRelayTest(__file__).main()
