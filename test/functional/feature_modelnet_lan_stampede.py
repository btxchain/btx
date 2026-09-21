#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Delegated discovery, LAN authority, and the origin stampede budget.

Three claims the model plane makes about routing, none of which had
functional coverage:

  * delegated discovery is a typed root-authorized record with a bounded
    fan-out. It can never be granted a money scope, and issuing or revoking
    one does not move the chain (src/modelnet/helper.cpp
    delegatemodelservice, src/modelnet/identity.h DELEGATE_KNOWN_MASK).
  * LAN preference is an observation, not an authority. Every RFC1918 /
    link-local / loopback / .local class classifies with no public address,
    no wallet, and no spend, and a LAN model contact never becomes a
    monetary peer or an AddrMan entry (src/modelnet/lan_discovery.cpp).
  * the origin stampede budget is a finite per-peer and per-netgroup cap,
    so a thousand clients behind one netgroup cannot each buy their own
    origin budget (src/modelnet/file_stream.h OriginStampedeGuard).

feature_modelnet_0348_ops.py already asserts the routing/discovery consensus
and ranking flags; this file does not repeat them. Isolated regtest only.
Never production btxd.real. No wallet is loaded at any point.

  python3 test/functional/feature_modelnet_lan_stampede.py \\
    --configfile=build-gcc13/test/config.ini --timeout-factor=1
"""

import os
import subprocess
from pathlib import Path

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-autoshieldcoinbase=0",
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

# src/modelnet/identity.h
DELEGATE_SERVE = 2
DELEGATE_ANNOUNCE = 4
DELEGATE_KNOWN_MASK = 31
MONEY_SCOPE_BIT = 1 << 20
ROOT_SCOPE_BIT = 1 << 31

# src/modelnet/lan_discovery.cpp EndpointLooksLan.
LAN_ENDPOINTS = (
    ("10.0.0.5:29447", "rfc1918 /8"),
    ("192.168.77.5:29447", "rfc1918 /16"),
    ("172.16.0.1:29447", "rfc1918 /12 low edge"),
    ("172.31.255.254:29447", "rfc1918 /12 high edge"),
    ("169.254.13.7:29447", "ipv4 link-local"),
    ("127.0.0.1:29447", "loopback"),
    ("[::1]:29447", "ipv6 loopback"),
    ("[fe80::1%en0]:29447", "ipv6 link-local"),
    ("helper.local:29447", "mdns"),
    ("MacPro.LOCAL:29447", "mdns uppercase"),
)
WAN_ENDPOINTS = (
    ("8.8.8.8:29447", "public resolver"),
    ("203.0.113.9:29447", "TEST-NET-3"),
    ("172.15.0.1:29447", "below rfc1918 /12"),
    ("172.32.0.1:29447", "above rfc1918 /12"),
    ("1.10.0.5:29447", "public, not the 10/8 prefix"),
    ("example.com:29447", "public name"),
)

# Keys that would mean the model plane had grown a wallet or a signing path.
WALLET_AUTHORITY_KEYS = frozenset({
    "psbt",
    "hex",
    "txid",
    "signed_tx",
    "privkey",
    "private_key",
    "wallet_seed",
    "xprv",
    "mnemonic",
    "spend_authorization",
})
WALLET_CLAIM_KEYS = frozenset({
    "wallet_sign",
    "wallet_signed",
    "requires_wallet",
    "wallet_authority",
    "may_wallet_spend",
})
SECRET_NEEDLES = ("aws_secret_access_key", "secret_access_key", "id_ed25519", "hf_token")


class ModelNetLanStampedeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.skipped = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        candidates = []
        for env_name in ("BTXMODELD", "BTX_MODELD"):
            env_val = os.environ.get(env_name)
            if env_val:
                candidates.append(Path(env_val))
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            candidates.append(Path(builddir) / "bin" / name)
        bitcoind = getattr(self.options, "bitcoind", None)
        if bitcoind:
            candidates.append(Path(bitcoind).resolve().parent / name)
        for cand in candidates:
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def _start_helper(self):
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = datadir / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        if self.modeld_socket.exists():
            self.modeld_socket.unlink()
        argv = [
            str(self._modeld_path()),
            f"-modeldir={self.modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        self.log.info("starting %s", " ".join(argv))
        self.modeld_log = open(self.modeldir / "modeld.log", "w", encoding="utf-8")
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir)
        )

    def _stop_helper(self):
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                self.log.warning("test helper SIGTERM timeout; SIGKILL test child only")
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(f"btx-modeld exited {self.modeld_proc.returncode}")
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.modeld_socket}",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    def _missing_rpc(self, exc):
        err = exc.error if isinstance(exc.error, dict) else {}
        if err.get("code") == -32601:
            return True
        blob = str(exc).lower()
        return "method_not_found" in blob or "unknown method" in blob

    def _rpc_or_skip(self, name, fn, *args):
        try:
            return fn(*args)
        except JSONRPCException as exc:
            if self._missing_rpc(exc):
                self.skipped.append(f"{name}: {exc.error}")
                return None
            raise

    def _no_wallet_authority(self, obj, where):
        """Zero spend, no signing material, no claimed wallet authority."""
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} not an object: {obj}")
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

        def walk(node, path):
            if isinstance(node, dict):
                for key, value in node.items():
                    low = key.lower()
                    if low in WALLET_AUTHORITY_KEYS:
                        raise AssertionError(f"{where} carries signing material {path}{key}: {obj}")
                    if low in WALLET_CLAIM_KEYS and value is True:
                        raise AssertionError(f"{where} claims wallet authority {path}{key}: {obj}")
                    walk(value, f"{path}{key}.")
            elif isinstance(node, list):
                for item in node:
                    walk(item, path)

        walk(obj, "")
        blob = str(obj).lower()
        for needle in SECRET_NEEDLES:
            if needle in blob and "***" not in blob:
                raise AssertionError(f"{where} leaked secret needle {needle}")

    def _chain_fingerprint(self, node):
        info = node.getblockchaininfo()
        return (
            info["bestblockhash"],
            info["blocks"],
            info["chainwork"],
            node.getmempoolinfo()["size"],
        )

    def run_test(self):
        node = self.nodes[0]

        def helper_ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(f"btx-modeld died {self.modeld_proc.returncode}")
            try:
                return bool(node.getmodelnetworkinfo().get("helper_ready"))
            except JSONRPCException:
                return False

        self.wait_until(helper_ready, timeout=30)

        # A loaded wallet would make "no wallet authority" unfalsifiable.
        try:
            loaded = node.listwallets()
        except JSONRPCException as exc:
            if not self._missing_rpc(exc):
                raise
            loaded = []
        if loaded:
            raise AssertionError(f"no wallet may be loaded for this test: {loaded}")

        # Give the chain something to lose before touching the model plane.
        self.generatetoaddress(node, 2, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        before = self._chain_fingerprint(node)

        self.delegated_discovery_is_bounded_and_moneyless(node)
        self.lan_discovery_has_no_wallet_authority(node)
        self.lan_contact_is_not_a_monetary_peer(node)
        self.origin_stampede_budget_is_finite(node)

        after = self._chain_fingerprint(node)
        if before != after:
            raise AssertionError(f"model plane moved the chain {before} -> {after}")
        self.log.info("chain untouched across delegation/LAN/origin work: %s", after)

        # Absent RPCs are honest not-runs; a new one is a regression.
        honest_rpc = frozenset({"origin_stampede", "addmodelnode_rpcdoccheck"})
        unexpected = []
        for entry in self.skipped:
            name = str(entry).split(":", 1)[0].strip()
            self.log.info("HONEST_NOT_RUN %s: %s", name, entry)
            if name not in honest_rpc:
                unexpected.append(name)
        if unexpected:
            raise AssertionError(
                f"NEW skip not in HONEST_NOT_RUN allowlist: {unexpected}; skipped={self.skipped}"
            )
        self.log.info("LAN / delegated discovery / origin stampede passed skipped=%s", self.skipped)

    def delegated_discovery_is_bounded_and_moneyless(self, node):
        """A delegate may announce and serve. It may never hold a money scope."""
        route = self._rpc_or_skip("getmodelroutingstatus", node.getmodelroutingstatus, {})
        if isinstance(route, dict):
            self._no_wallet_authority(route, "getmodelroutingstatus")
            sample_cap = route.get("sample_cap")
            probe_max = route.get("probe_max")
            if not isinstance(sample_cap, int) or not isinstance(probe_max, int):
                raise AssertionError(f"delegated discovery fan-out not numeric: {route}")
            if not 1 <= probe_max <= sample_cap <= 256:
                raise AssertionError(
                    f"delegated discovery fan-out unbounded probe_max={probe_max} sample_cap={sample_cap}"
                )
            if route.get("lan_requires_public_address") is not False:
                raise AssertionError(f"routing demands a public address: {route}")
            self.log.info(
                "delegated discovery bounded: probe_max=%s sample_cap=%s", probe_max, sample_cap
            )

        for scopes, label in (
            (MONEY_SCOPE_BIT, "money"),
            (DELEGATE_KNOWN_MASK | MONEY_SCOPE_BIT, "known+money"),
            (ROOT_SCOPE_BIT, "root"),
        ):
            try:
                granted = node.delegatemodelservice({"scopes": scopes})
            except JSONRPCException as exc:
                if self._missing_rpc(exc):
                    self.skipped.append(f"delegatemodelservice: {exc.error}")
                    return
                blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
                if "money" not in blob and "scope" not in blob:
                    raise AssertionError(f"{label} scope refusal text: {exc}") from exc
                self.log.info("delegatemodelservice refused %s scope %s: %s", label, scopes, blob[:160])
                continue
            raise AssertionError(f"delegatemodelservice granted a {label} scope: {granted}")

        granted = self._rpc_or_skip(
            "delegatemodelservice",
            node.delegatemodelservice,
            {"scopes": DELEGATE_ANNOUNCE | DELEGATE_SERVE, "all_models": True},
        )
        if not isinstance(granted, dict):
            return
        self._no_wallet_authority(granted, "delegatemodelservice")
        if granted.get("recorded") is not True:
            raise AssertionError(f"announce+serve delegation not recorded: {granted}")
        record_id = granted.get("record_id")
        if not isinstance(record_id, str) or len(record_id) != 96:
            raise AssertionError(f"delegation record_id is not a Digest48: {granted}")
        note = str(granted.get("note", "")).lower()
        if "never a money signature" not in note:
            raise AssertionError(f"delegation note dropped the money disclaimer: {granted}")
        self.log.info("delegated discovery record %s (announce+serve)", record_id)

        revoked = self._rpc_or_skip(
            "revokemodelservice", node.revokemodelservice, {"target_id": record_id}
        )
        if not isinstance(revoked, dict):
            return
        self._no_wallet_authority(revoked, "revokemodelservice")
        if revoked.get("recorded") is not True:
            raise AssertionError(f"revocation not recorded: {revoked}")
        if revoked.get("record_id") == record_id:
            raise AssertionError(f"revocation reused the delegation record id: {revoked}")
        self.log.info("delegated discovery revoked by record %s", revoked.get("record_id"))

    def lan_discovery_has_no_wallet_authority(self, node):
        """Every LAN class answers without a public address, a wallet, or a spend."""
        for endpoint, label in LAN_ENDPOINTS + WAN_ENDPOINTS:
            want_lan = (endpoint, label) in LAN_ENDPOINTS
            seen = self._rpc_or_skip(
                "getmodellandiscovery", node.getmodellandiscovery, {"endpoint": endpoint}
            )
            if not isinstance(seen, dict):
                return
            self._no_wallet_authority(seen, f"getmodellandiscovery {endpoint}")
            if seen.get("lan") is not want_lan:
                raise AssertionError(f"{label} {endpoint} classified {seen.get('lan')}: {seen}")
            if seen.get("requires_public_address") is not False:
                raise AssertionError(f"LAN discovery demands a public address: {seen}")
        self.log.info(
            "LAN classification: %s LAN classes, %s public endpoints, none wallet-bearing",
            len(LAN_ENDPOINTS), len(WAN_ENDPOINTS),
        )

        # The .local test is a substring match, so a hostile name can be read
        # as LAN. That is survivable only because the answer grants nothing.
        spoof = "attacker.localdomain.example.com:29447"
        seen = self._rpc_or_skip(
            "getmodellandiscovery", node.getmodellandiscovery, {"endpoint": spoof}
        )
        if isinstance(seen, dict):
            self._no_wallet_authority(seen, f"getmodellandiscovery {spoof}")
            if seen.get("requires_public_address") is not False:
                raise AssertionError(f"spoofed LAN name changed the address rule: {seen}")
            self.log.info("spoofable LAN name %s reads lan=%s and still grants nothing", spoof, seen.get("lan"))

        info = node.getmodelnetworkinfo()
        self.log.info(
            "LAN discovery answered while nat_limited=%s public_host_reachable=%s",
            info.get("nat_limited"), info.get("public_host_reachable"),
        )
        if info.get("public_host_reachable") is True and info.get("nat_limited") is True:
            raise AssertionError(f"reachability self-contradiction: {info}")

    def lan_contact_is_not_a_monetary_peer(self, node):
        """A LAN discovery contact lands in the model plane, never in AddrMan."""
        endpoint = "192.168.77.5:29447"
        peers_before = len(node.getpeerinfo())
        added_before = len(node.getaddednodeinfo())
        addrman_before = len(node.getnodeaddresses(0))

        indexed = self._rpc_or_skip("addmodelindex", node.addmodelindex, endpoint)
        if not isinstance(indexed, dict):
            return
        self._no_wallet_authority(indexed, "addmodelindex")
        if indexed.get("addrman") is not False:
            raise AssertionError(f"delegated index peer reached AddrMan: {indexed}")
        if not isinstance(indexed.get("index_peers"), int) or indexed["index_peers"] < 1:
            raise AssertionError(f"LAN index peer was not recorded: {indexed}")

        found = self._rpc_or_skip("getsearchpeers", node.getsearchpeers)
        if isinstance(found, dict):
            self._no_wallet_authority(found, "getsearchpeers")
            listed = [
                p for p in found.get("peers", [])
                if isinstance(p, dict) and p.get("endpoint") == endpoint
            ]
            if not listed:
                raise AssertionError(f"LAN index peer missing from the model plane: {found}")
            for entry in listed:
                if entry.get("monetary_service_bit") is not False:
                    raise AssertionError(f"LAN discovery peer claims a monetary bit: {entry}")
                if entry.get("capability") != "NODE_MODEL_INDEX":
                    raise AssertionError(f"LAN discovery peer capability: {entry}")

        self._add_model_contact(node, endpoint)

        if len(node.getpeerinfo()) != peers_before:
            raise AssertionError(f"model contact opened a monetary connection: {node.getpeerinfo()}")
        if len(node.getaddednodeinfo()) != added_before:
            raise AssertionError(f"model contact behaved like addnode: {node.getaddednodeinfo()}")
        if len(node.getnodeaddresses(0)) != addrman_before:
            raise AssertionError(f"model contact wrote to AddrMan: {node.getnodeaddresses(0)}")
        self.log.info(
            "LAN contact %s is model-plane only (peers=%s addnode=%s addrman=%s)",
            endpoint, peers_before, added_before, addrman_before,
        )

    def _add_model_contact(self, node, endpoint):
        """addmodelnode adds a model-plane contact and returns an object (not addnode)."""
        try:
            result = node.addmodelnode(endpoint)
        except JSONRPCException as exc:
            if self._missing_rpc(exc):
                self.skipped.append(f"addmodelnode: {exc.error}")
                return
            raise
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise AssertionError(f"addmodelnode must return an object with ok=true: {result}")
        if result.get("added") != endpoint:
            raise AssertionError(f"addmodelnode added mismatch: {result}")
        self._no_wallet_authority(result, "addmodelnode")

    def origin_stampede_budget_is_finite(self, node):
        """The origin cap is per-peer and per-netgroup, not per-client."""
        info = node.getmodelnetworkinfo()
        budget = info.get("origin_stampede")
        if not isinstance(budget, dict):
            self.skipped.append(f"origin_stampede: absent from getmodelnetworkinfo keys={sorted(info)[:12]}")
            return
        self._no_wallet_authority(budget, "origin_stampede")

        fields = ("window_ms", "max_per_peer", "max_per_netgroup", "errors_to_open", "circuit_open_ms")
        for field in fields:
            value = budget.get(field)
            if not isinstance(value, int) or value < 1:
                raise AssertionError(f"origin budget {field} is not a positive bound: {budget}")
        if budget["max_per_netgroup"] < budget["max_per_peer"]:
            raise AssertionError(f"netgroup cap below the per-peer cap: {budget}")
        if budget.get("circuits_open") != 0:
            raise AssertionError(f"circuit already open on an idle node: {budget}")
        if not isinstance(budget.get("tracked_peers"), int) or budget["tracked_peers"] < 0:
            raise AssertionError(f"tracked_peers: {budget}")

        # CONV-41 shape: a thousand clients in one netgroup still share one
        # netgroup budget, so the origin sees a fraction of the demand.
        clients = 1000
        amplification = budget["max_per_netgroup"] / clients
        if amplification >= 1.0:
            raise AssertionError(
                f"{clients} clients in one netgroup would each get an origin GET: {budget}"
            )
        self.log.info(
            "origin budget peer=%s netgroup=%s per %sms; %s clients amplify %.3fx",
            budget["max_per_peer"], budget["max_per_netgroup"], budget["window_ms"],
            clients, amplification,
        )

        # Adding LAN contacts must not widen the budget or open a circuit.
        again = node.getmodelnetworkinfo().get("origin_stampede")
        if not isinstance(again, dict):
            raise AssertionError(f"origin budget vanished on re-read: {again}")
        for field in fields:
            if again.get(field) != budget[field]:
                raise AssertionError(f"origin budget {field} moved {budget[field]} -> {again.get(field)}")
        if again.get("circuits_open") != 0:
            raise AssertionError(f"idle re-read opened a circuit: {again}")
        self.log.info("origin budget stable after LAN discovery and a LAN contact")


if __name__ == "__main__":
    ModelNetLanStampedeTest(__file__).main()
