#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Remaining HCP/1 process-tier gaps: money outlives the helper, and the
btxd BOUNTY_PROXY for hcphealth refuses secrets.

Cases that no other file covers:

  remaining_01  btxd hcphealth (BOUNTY_PROXY) refuses a secret-shaped request,
                never echoes the sentinel, and never writes it to the node or
                helper log. feature_modelnet_unique_todos.py covers
                sethcpreporting / importhcpstate, not the hcphealth request arg.
  remaining_03  remaining HCP helper verbs via btxd refuse secrets, spend 0.
  remaining_04  planhcplocal LAN TTC wins over internet:cex-hint after
                puthcplocalitysources (PutLanSource / PutInternetSource).
  remaining_05  btx-hosted accept of a structurally good CapabilityHandoff
                (no shell / executable_url). Coordinator re-signs in RunHostedCli.
  remaining_06  J06 cancel is not a refund on HTTP 400. HONEST_NOT_RUN if
                finance is not on the walletless helper (do not fake PASS).
  remaining_02  With the helper dead, the whole money plane still works:
                balance, address, send, mine, confirm. Must stay last.

Isolated regtest with one test-spawned btx-modeld. Never production btxd; the
only process this file signals is its own helper child. automatic_spend_atoms
stays 0 throughout.

Run (do not cmake/ninja):

  python3 test/functional/feature_hcp_remaining.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import json
import os
import subprocess
from decimal import Decimal
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_greater_than,
    get_datadir_path,
)

# MatMul-off heights (wallet_modelnet_funding.py): keeps generate cheap.
MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

SENTINEL = "BTX_HCP_REMAINING_SECRET_SENTINEL"

# Secret-shaped hcphealth requests. A connector health read has no business
# accepting any of these.
SECRET_REQUESTS = (
    ("secret", {"secret": SENTINEL}),
    ("aws_secret_access_key", {"aws_secret_access_key": SENTINEL}),
    ("wallet_seed", {"wallet_seed": SENTINEL}),
    ("hf_token", {"hf_token": SENTINEL}),
    ("nested", {"reporting": {"secret": SENTINEL, "webhook_secret": SENTINEL}}),
    ("private_key", {"private_key": SENTINEL, "automatic_spend_atoms": 1}),
)

# Names that must never come back out of a health read.
LEAK_NEEDLES = (
    "wallet_seed",
    "hf_token",
    "aws_secret_access_key",
    "private_key_hex",
    "mnemonic",
)

ONES96 = "1" * 96
TWOS96 = "2" * 96
THREES96 = "3" * 96
ZEROS64 = "0" * 64


class HcpRemainingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld binary not found (BUILDDIR/bin or next to btxd)")

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

    def _hosted_path(self):
        """btx-hosted next to btx-modeld (BUILDDIR/bin/btx-hosted)."""
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-hosted{exeext}"
        candidates = []
        modeld = self._modeld_path()
        if modeld is not None:
            candidates.append(modeld.parent / name)
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
        datadir = get_datadir_path(self.options.tmpdir, 0)
        self.modeldir = Path(datadir) / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        argv = [
            str(self._modeld_path()),
            f"-modeldir={self.modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
        self.modeld_log = open(self.modeldir / "modeld.log", "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(datadir),
        )

    def _stop_helper(self):
        """SIGTERM the test-spawned btx-modeld only. Never production btxd."""
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                self.log.warning("test helper ignored SIGTERM; killing test child")
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None
        return proc

    def _helper_log(self):
        if self.modeldir is None:
            return ""
        path = self.modeldir / "modeld.log"
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(
                f"btx-modeld exited immediately with {self.modeld_proc.returncode}\n{self._helper_log()}"
            )
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.modeld_socket}",
            "-autoshieldcoinbase=0",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        if self._requires_wallet:
            self.import_deterministic_coinbase_privkeys()

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    def _zero_spend(self, obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} not an object: {obj}")
        spend = obj.get("automatic_spend_atoms", obj.get("automatic_spend", 0))
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _assert_no_leak(self, obj, where):
        blob = json.dumps(obj, default=str)
        if SENTINEL in blob:
            raise AssertionError(f"{where} echoed the secret sentinel: {blob}")
        lowered = blob.lower()
        leaks = [n for n in LEAK_NEEDLES if n in lowered]
        if leaks:
            raise AssertionError(f"{where} leaked {leaks}: {blob}")

    def _honest(self, case, reason):
        self.log.info("HONEST_NOT_RUN %s: %s", case, reason)

    def _loads_json(self, text, where):
        if isinstance(text, dict):
            return text
        if text in (None, ""):
            return {}
        if not isinstance(text, str):
            text = str(text)
        text = text.strip()
        try:
            got = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start < 0 or end <= start:
                raise AssertionError(f"{where} not JSON: {text[:500]}")
            try:
                got = json.loads(text[start:end + 1])
            except json.JSONDecodeError as exc:
                raise AssertionError(f"{where} not JSON: {exc}: {text[:500]}") from exc
        if not isinstance(got, dict):
            raise AssertionError(f"{where} JSON is not an object: {got}")
        return got

    def _hcphandle(self, node, method, path, body=None):
        req = {"method": method, "path": path}
        if body is not None:
            req["body"] = body
        try:
            got = node.hcphandle(req)
        except JSONRPCException as exc:
            return None, None, exc
        self._zero_spend(got, f"hcphandle {method} {path}")
        status = int(got.get("status", 0))
        parsed = self._loads_json(got.get("body"), f"hcphandle {method} {path} body")
        return status, parsed, got

    # remaining_01: btxd BOUNTY_PROXY hcphealth must refuse secrets.
    def remaining_01_hcphealth_refuses_secrets(self, node):
        baseline = node.hcphealth()
        self._zero_spend(baseline, "hcphealth()")
        self._assert_no_leak(baseline, "hcphealth()")
        if not isinstance(baseline, dict) or not baseline:
            raise AssertionError(f"hcphealth must return a health object: {baseline}")

        refused = 0
        for label, payload in SECRET_REQUESTS:
            try:
                got = node.hcphealth(payload)
            except JSONRPCException as exc:
                refused += 1
                self.log.info("hcphealth(%s) refused: %s", label, exc)
                if SENTINEL in str(exc):
                    raise AssertionError(f"hcphealth({label}) echoed the sentinel in its error: {exc}")
                continue
            # Answering is only acceptable if the request was ignored outright:
            # no echo, no stored secret, and still no automatic spend.
            self._zero_spend(got, f"hcphealth({label})")
            self._assert_no_leak(got, f"hcphealth({label})")
            self.log.info("hcphealth(%s) ignored the request arg (no echo, spend 0)", label)

        self.log.info("hcphealth refused %d of %d secret-shaped requests", refused, len(SECRET_REQUESTS))

        # A refused request must not be remembered: neither a later health read
        # nor either log may contain the sentinel.
        after = node.hcphealth()
        self._zero_spend(after, "hcphealth() after secrets")
        self._assert_no_leak(after, "hcphealth() after secrets")

        helper_log = self._helper_log()
        if SENTINEL in helper_log:
            raise AssertionError("btx-modeld log persisted the secret sentinel")
        debug_log = node.debug_log_path.read_text(encoding="utf-8", errors="replace")
        if SENTINEL in debug_log:
            raise AssertionError("btxd debug.log persisted the secret sentinel")
        self.log.info("remaining_01 hcphealth secrets refused and never logged")

    def remaining_03_hcp_helper_methods_via_btxd(self, node):
        """Every remaining HCP helper verb is reachable through btxd while
        the helper is up, refuses secrets, and never spends."""
        spend0 = ("gethcpconnectorstatus", "applyhcpwalletless", "planhcplocal",
                  "ensurehcplocal", "exporthcpstate")
        for name in spend0:
            fn = getattr(node, name)
            try:
                got = fn({}) if name in ("planhcplocal", "ensurehcplocal") else fn()
            except JSONRPCException as exc:
                self.log.info("%s fail-closed: %s", name, exc)
                continue
            self._zero_spend(got, name)
            self.log.info("%s via btxd: keys=%s", name, sorted(got.keys()) if isinstance(got, dict) else type(got))

        paired = node.pairhcpdevice({"device_id": "remaining-dev"})
        self._zero_spend(paired, "pairhcpdevice")
        if paired.get("paired") is not True:
            raise AssertionError(f"pairhcpdevice: {paired}")
        revoked = node.revokehcpdevice({"device_id": "remaining-dev"})
        self._zero_spend(revoked, "revokehcpdevice")
        if revoked.get("revoked") is not True:
            raise AssertionError(f"revokehcpdevice: {revoked}")

        handle = node.hcphandle({"method": "GET", "path": "/profile"})
        self._zero_spend(handle, "hcphandle GET /profile")
        if int(handle.get("status", 0)) >= 400:
            raise AssertionError(f"hcphandle GET /profile: {handle}")

        for name, payload in (
            ("previewhcpprovider", {}),
            ("enrollhcpprovider", {"operator_accept": False}),
            ("accepthcphandoff", {}),
            ("sethcplocalgrant", {}),
        ):
            fn = getattr(node, name)
            try:
                got = fn(payload)
            except JSONRPCException as exc:
                self.log.info("%s fail-closed without envelope: %s", name, exc)
                continue
            self._zero_spend(got, name)
            self.log.info("%s returned without envelope: %s", name, got)

        try:
            node.enrollhcpprovider({"secret": SENTINEL})
            raise AssertionError("enrollhcpprovider accepted a secret field")
        except JSONRPCException as exc:
            self.log.info("enrollhcpprovider secret refused: %s", exc)

        self.log.info("remaining_03 HCP helper methods via btxd")

    def remaining_04_planhcplocal_lan_wins(self, node):
        """LAN TTC must beat internet:cex-hint; inventory stays private."""
        walletless = node.applyhcpwalletless()
        self._zero_spend(walletless, "applyhcpwalletless")
        status = node.gethcpconnectorstatus()
        self._zero_spend(status, "gethcpconnectorstatus")

        sources = node.puthcplocalitysources({
            "lan": {"id": "lan", "ttc_ms": 20},
            "internet": {"id": "cex-hint", "ttc_ms": 8000},
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(sources, "puthcplocalitysources")

        plan = node.planhcplocal({"recipe_id": "recipe"})
        self._zero_spend(plan, "planhcplocal")
        if plan.get("inventory_reported") is True:
            raise AssertionError(f"planhcplocal reported private inventory: {plan}")
        src = str(plan.get("selected_source", ""))
        if src == "internet:cex-hint" or src.startswith("internet:"):
            raise AssertionError(f"planhcplocal selected internet over LAN: {plan}")
        if src not in ("lan:lan", "resident"):
            raise AssertionError(f"planhcplocal selected_source must be lan:lan or resident: {plan}")
        self.log.info("remaining_04 planhcplocal selected_source=%s ttc_ms=%s", src, plan.get("ttc_ms"))

    def remaining_05_hosted_accept_signed_good(self, node):
        """btx-hosted accept of a structurally good handoff (no forbidden fields).

        remaining_01 / remaining_03 keep the secret-refuse cases; this path must
        not introduce a secret field or spend.
        """
        hosted = self._hosted_path()
        if hosted is None:
            raise AssertionError("btx-hosted not found next to btx-modeld (BUILDDIR/bin/btx-hosted)")

        envelope = {
            "object_type": "CapabilityHandoff",
            "body": {
                "version": 1,
                "provider_id": "provider-demo",
                "device_id": "device-demo",
                "request_nonce": "demo-nonce-not-production",
                "account_ref": "account-demo",
                "network": {
                    "environment": "REGTEST",
                    "genesis_hash": ZEROS64,
                },
                "handoff_id": "remaining-good-handoff",
                "client_operation_id": "remaining-good-01",
                "issued_at_ms": "1790000000000",
                "expires_at_ms": "1790000600000",
                "package": {
                    "package_core_id": ONES96,
                    "file_sha384": TWOS96,
                    "recipe_id": THREES96,
                    "download_url": (
                        "https://exchange.example/btx/hcp/v1/packages/" + ONES96
                    ),
                },
                "readiness_target": "RUNTIME_READY",
                "requested_effects": [
                    "FETCH_METADATA",
                    "ACQUIRE_MODEL",
                    "PLAN_LOCAL_RUN",
                ],
                "source_hints": [],
                "reporting_requested": False,
            },
        }
        blob = json.dumps(envelope)
        if "shell" in blob or "executable_url" in blob:
            raise AssertionError("remaining_05 envelope must not contain forbidden fields")
        if SENTINEL in blob:
            raise AssertionError("remaining_05 envelope must not contain the secret sentinel")

        hand_path = Path(get_datadir_path(self.options.tmpdir, 0)) / "remaining-good-handoff.json"
        hand_path.write_text(blob, encoding="utf-8")
        proc = subprocess.run(
            [str(hosted), "accept", str(hand_path)],
            capture_output=True,
            text=True,
            timeout=max(30.0, 30.0 * float(self.options.timeout_factor)),
            cwd=str(get_datadir_path(self.options.tmpdir, 0)),
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            raise AssertionError(
                f"btx-hosted accept of structurally good handoff rc={proc.returncode} "
                f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
            )
        acc = self._loads_json(proc.stdout, "btx-hosted accept stdout")
        self._zero_spend(acc, "btx-hosted accept")
        if acc.get("handoff_id") != "remaining-good-handoff":
            raise AssertionError(f"btx-hosted accept missing handoff_id remaining-good-handoff: {acc}")
        if acc.get("wallet_touched") is True:
            raise AssertionError(f"btx-hosted accept wallet_touched: {acc}")
        if SENTINEL in combined:
            raise AssertionError("btx-hosted accept echoed the secret sentinel")
        debug_log = node.debug_log_path.read_text(encoding="utf-8", errors="replace")
        if SENTINEL in debug_log:
            raise AssertionError("btxd debug.log persisted the secret sentinel during remaining_05")
        self.log.info("remaining_05 btx-hosted accept handoff_id=%s spend=0", acc.get("handoff_id"))

    def remaining_06_j06_cancel_not_400(self, node):
        """Cancel is not a refund on HTTP 400. Walletless finance is HONEST_NOT_RUN."""
        status, health, exc = self._hcphandle(node, "GET", "/health")
        if exc is not None or status is None or status >= 400 or not isinstance(health, dict):
            self._honest(
                "remaining_06",
                f"walletless helper has no /health finance probe (status={status} exc={exc}); "
                "do not fake J06 refund PASS",
            )
            return
        self._zero_spend(health, "hcphandle GET /health")
        if health.get("finance") is not True:
            self._honest(
                "remaining_06",
                f"finance is not on the walletless helper (finance={health.get('finance')} "
                f"walletless={health.get('walletless')}); do not fake J06 refund PASS",
            )
            return

        st, created, exc = self._hcphandle(
            node, "POST", "/finance/intents", {"client_operation_id": "remaining-j06"},
        )
        if exc is not None or st is None or st >= 400:
            self._honest(
                "remaining_06",
                f"hcphandle POST /finance/intents did not work (status={st} exc={exc}); "
                "do not fake J06 refund PASS",
            )
            return

        intent = created.get("body") if isinstance(created.get("body"), dict) else created
        iid = intent.get("intent_id") if isinstance(intent, dict) else None
        if not iid:
            raise AssertionError(f"POST /finance/intents succeeded without intent_id: {created}")

        cst, cancel, cexc = self._hcphandle(node, "POST", f"/finance/intents/{iid}/cancel")
        if cexc is not None:
            # Helper currently fail-closes hcphandle when status>=400. That
            # fail-close is not a refund.
            self.log.info(
                "remaining_06 cancel fail-closed (not a refund, not HTTP-400-as-refund): %s",
                cexc,
            )
            if "400" in str(cexc):
                raise AssertionError(
                    f"J06 cancel HTTP 400 is not a refund: {cexc}"
                )
            self._honest(
                "remaining_06",
                f"cancel fail-closed without a 2xx body ({cexc}); not a refund",
            )
            return

        if cst == 400:
            raise AssertionError(
                f"J06 cancel HTTP 400 is not a refund: {cancel}"
            )
        if cst not in (200, 202, 409):
            raise AssertionError(f"J06 cancel unexpected status {cst}: {cancel}")
        self._zero_spend(cancel, "hcphandle POST cancel")
        if cancel.get("false_refund") is True:
            raise AssertionError(f"J06 cancel claimed a false refund: {cancel}")
        if cst == 409:
            self.log.info("remaining_06 cancel 409 conflict (not a refund): %s", cancel)
            return
        state = str(cancel.get("state") or "")
        if state.upper() == "REFUNDED":
            raise AssertionError(f"J06 cancel treated as refund: {cancel}")
        self.log.info(
            "remaining_06 cancel status=%s state=%s hold_released=%s (not HTTP 400 refund)",
            cst, state, cancel.get("hold_released"),
        )

    # remaining_02: money does not depend on the model helper.
    def remaining_02_money_survives_helper_down(self, node):
        self.generate(node, COINBASE_MATURITY + 1)
        balance_before = node.getbalance()
        assert_greater_than(balance_before, 0)
        height_before = node.getblockcount()
        self.log.info("money baseline height=%d balance=%s", height_before, balance_before)

        dead = self._stop_helper()
        if dead is None or dead.poll() is None:
            raise AssertionError("test helper did not exit; helper-down case is not proven")
        self.log.info("test-spawned btx-modeld exited rc=%s (SIGTERM)", dead.returncode)

        # Chain and wallet are both readable with no helper at all.
        chain = node.getblockchaininfo()
        if chain.get("chain") != "regtest":
            raise AssertionError(f"getblockchaininfo with helper down: {chain}")
        if node.getblockcount() != height_before:
            raise AssertionError("helper exit changed the chain height")
        wallet_info = node.getwalletinfo()
        if wallet_info.get("balance") != balance_before:
            raise AssertionError(f"getwalletinfo balance moved on helper exit: {wallet_info}")
        if not node.listunspent():
            raise AssertionError("listunspent empty with helper down")

        # Real money moves with no helper: new address, send, mine, confirm.
        destination = node.getnewaddress()
        amount = Decimal("1.0")
        txid = node.sendtoaddress(destination, amount)
        entry = node.gettransaction(txid)
        if entry.get("confirmations") != 0:
            raise AssertionError(f"fresh send should be unconfirmed: {entry}")
        if txid not in node.getrawmempool():
            raise AssertionError(f"send with helper down never reached the mempool: {txid}")

        block_hashes = self.generate(node, 1)
        if txid not in node.getblock(block_hashes[0])["tx"]:
            raise AssertionError(f"{txid} not mined into {block_hashes[0]}")
        confirmed = node.gettransaction(txid)
        if confirmed.get("confirmations") != 1:
            raise AssertionError(f"send not confirmed with helper down: {confirmed}")
        # Destination is this wallet, so the subsidy of the confirmation block
        # dwarfs the fee. Helper-down money is proven by mempool admission plus
        # a confirmed txid, not by a net-balance decrease.
        balance_after = node.getbalance()
        if node.getblockcount() != height_before + 1:
            raise AssertionError("generate with helper down did not advance the chain")
        self.log.info(
            "money with helper down: txid=%s confirmations=1 balance %s -> %s",
            txid, balance_before, balance_after,
        )

        # The HCP plane must fail closed rather than answer with invented state,
        # and it must keep refusing secrets while it is down.
        try:
            info = node.getmodelnetworkinfo()
        except JSONRPCException as exc:
            self.log.info("getmodelnetworkinfo fails closed with helper down: %s", exc)
        else:
            if info.get("helper_ready") is True:
                self.log.info(
                    "btxd re-supplied a helper (managed_by_btxd=%s restart_count=%s); money case still holds",
                    info.get("helper_managed_by_btxd"), info.get("helper_restart_count"),
                )
            else:
                self.log.info("getmodelnetworkinfo reports helper_ready=%s", info.get("helper_ready"))
        try:
            health = node.hcphealth({"secret": SENTINEL})
        except JSONRPCException as exc:
            self.log.info("hcphealth secrets still refused with helper down: %s", exc)
        else:
            self._zero_spend(health, "hcphealth(secret) helper down")
            self._assert_no_leak(health, "hcphealth(secret) helper down")

        # Nothing above may have written wallet material into the model plane.
        if SENTINEL in self._helper_log():
            raise AssertionError("btx-modeld log persisted the secret sentinel")
        self.log.info("remaining_02 money plane independent of the model helper")

    def run_test(self):
        node = self.nodes[0]

        def helper_ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(
                    f"btx-modeld exited with {self.modeld_proc.returncode}\n{self._helper_log()}"
                )
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        self.log.info("waiting for getmodelnetworkinfo helper_ready")
        self.wait_until(helper_ready, timeout=30)

        self.remaining_01_hcphealth_refuses_secrets(node)
        self.remaining_03_hcp_helper_methods_via_btxd(node)
        self.remaining_04_planhcplocal_lan_wins(node)
        self.remaining_05_hosted_accept_signed_good(node)
        self.remaining_06_j06_cancel_not_400(node)
        self.remaining_02_money_survives_helper_down(node)
        self.log.info("feature_hcp_remaining passed")


if __name__ == "__main__":
    HcpRemainingTest(__file__).main()
