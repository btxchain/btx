#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Unique 0.34.8 todos that were previously one lumped NOT_RUN paragraph.

Each method is one operator todo. Isolated-regtest only. Never production
btxd.real. automatic_spend_atoms stays 0. Catalog stays off S3.

  python3 test/functional/feature_modelnet_unique_todos.py \\
    --configfile=build-gcc13/test/config.ini --timeout-factor=1
"""

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import get_datadir_path

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


class ModelNetUniqueTodosTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld missing")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            cand = Path(builddir) / "bin" / name
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
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = datadir / "modeldir"
        self.modeldir.mkdir(parents=True, exist_ok=True)
        self.modeld_socket = self.modeldir / "modeld.sock"
        argv = [
            str(self._modeld_path()),
            f"-modeldir={self.modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={self.modeld_socket}",
        ]
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
                proc.kill()
                proc.wait(timeout=5)
        if self.modeld_log is not None:
            self.modeld_log.close()
            self.modeld_log = None

    def setup_nodes(self):
        self._start_helper()
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

    def _zero(self, obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} not object: {obj}")
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _src_root(self):
        return Path(__file__).resolve().parents[2]

    def _leaks_private(self, obj):
        blob = json.dumps(obj, default=str).lower() if not isinstance(obj, str) else obj.lower()
        needles = (
            "local_paths",
            "installation_directory",
            "independent_trust_ref",
            "wallet_seed",
            "hf_token",
            "aws_secret_access_key",
        )
        return [n for n in needles if n in blob]

    def _unix_rpc(self, method, params=None):
        req = {
            "jsonrpc": "1.0",
            "id": "unique",
            "method": method,
            "params": params if params is not None else [],
        }
        wire = (json.dumps(req, separators=(",", ":")) + "\n").encode("utf-8")
        timeout = max(10.0, 20.0 * float(self.options.timeout_factor))
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(timeout)
            client.connect(str(self.modeld_socket))
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                buf = client.recv(4096)
                if not buf:
                    break
                chunks.append(buf)
                if b"\n" in buf:
                    break
        finally:
            client.close()
        raw = b"".join(chunks).split(b"\n", 1)[0].decode("utf-8")
        reply = json.loads(raw)
        if not isinstance(reply, dict):
            raise AssertionError(f"unix {method} reply: {reply}")
        err = reply.get("error")
        if err not in (None, {}):
            raise AssertionError(f"unix {method} error: {err}")
        result = reply.get("result")
        if not isinstance(result, dict):
            raise AssertionError(f"unix {method} result: {result}")
        return result

    def _wan_head(self, url):
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return True, getattr(resp, "status", 200)
        except urllib.error.HTTPError as exc:
            return True, exc.code
        except Exception as exc:
            self.log.info("WAN miss %s: %s", url, exc)
            return False, str(exc)

    def run_test(self):
        node = self.nodes[0]

        def helper_ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(f"helper died {self.modeld_proc.returncode}")
            try:
                return bool(node.getmodelnetworkinfo().get("helper_ready"))
            except JSONRPCException:
                return False

        self.wait_until(helper_ready, timeout=30)

        # unique_todo_gpu_attestor_untouched
        btxd = Path(self.options.bitcoind).resolve()
        blob = str(btxd)
        if "libexec/btxd.real" in blob or "btx-0.34.7-e15a07ba" in blob:
            raise AssertionError(f"test btxd is production attestor: {btxd}")
        self.log.info("unique_todo_gpu_attestor_untouched: test btxd=%s", btxd)

        # unique_todo_f2_wallet_sign
        caps = node.getbtxpackagecapabilities({})
        self._zero(caps, "F2 capabilities")
        if caps.get("wallet_sign") is True:
            raise AssertionError(f"F2 wallet_sign must stay false: {caps}")
        mandate = {
            "mandate_version": 1,
            "owner_identity": "a" * 96,
            "network_id": "0" * 64,
            "publisher_id": "b" * 96,
            "allowed_kinds": ["MODEL", "RELEASE"],
            "allowed_actions": ["FUND_WITH_MANDATE"],
            "per_action_principal_limit_atoms": "50",
            "total_principal_limit_atoms": "100",
            "total_fee_limit_atoms": "20",
            "outstanding_exposure_limit_atoms": "200",
            "max_actions": 16,
            "max_concurrent_reservations": 8,
            "expires_at_ms": "4000000000000",
            "refund_key_policy": "OWNER_CONTROLLED_ONLY",
            "minimum_confirmations": 1,
            "assurance_mode_restrictions": [],
            "revocation_counter": "0",
        }
        created = node.createsubscriptionmandate(mandate)
        self._zero(created, "F2 mandate")
        if created.get("wallet_signed") is True:
            raise AssertionError(f"F2 wallet_signed: {created}")
        self.log.info("unique_todo_f2_wallet_sign mandate_id=%s", created.get("mandate_id"))

        # unique_todo_getsubscriptionactivity
        reserve_req = {
            "mandate_id": created.get("mandate_id"),
            "event_id": "e-todo-act",
            "publisher_id": "b" * 96,
            "object_kind": "RELEASE",
            "action": "FUND_WITH_MANDATE",
            "signed_terms": {
                "terms_id": "d" * 96,
                "publisher_id": "b" * 96,
                "network_id": "0" * 64,
                "principal_atoms": "1",
                "fee_atoms": "0",
                "object_kind": "RELEASE",
                "confirmations": 1,
            },
        }
        reserved = node.reservesubscriptionmandate(reserve_req)
        self._zero(reserved, "getsubscriptionactivity reserve")
        activity = node.getsubscriptionactivity({"mandate_id": created.get("mandate_id"), "limit": 10})
        self._zero(activity, "getsubscriptionactivity")
        if activity.get("telemetry") is True:
            raise AssertionError(f"getsubscriptionactivity telemetry: {activity}")
        actions = activity.get("actions")
        if not isinstance(actions, list) or not actions:
            raise AssertionError(f"getsubscriptionactivity actions: {activity}")
        if actions[0].get("event_id") != "e-todo-act":
            raise AssertionError(f"getsubscriptionactivity event: {actions[0]}")
        if actions[0].get("terms_id") != "d" * 96:
            raise AssertionError(f"getsubscriptionactivity terms: {actions[0]}")
        if actions[0].get("txid"):
            raise AssertionError(f"getsubscriptionactivity must not invent txid: {actions[0]}")
        self.log.info("unique_todo_getsubscriptionactivity actions=%s", len(actions))

        # unique_todo_a2_modelindex
        modeld = self._modeld_path()
        a2 = subprocess.run(
            [str(modeld), "-modelindex=1"],
            capture_output=True, text=True, timeout=8, check=False,
        )
        if a2.returncode == 0:
            raise AssertionError("A2: btx-modeld accepted -modelindex")
        blob = (a2.stderr or "") + (a2.stdout or "")
        if "modelindex" not in blob.lower() and "unknown argument" not in blob.lower():
            self.log.info("A2 reject text: %s", blob[:300])
        added = node.addmodelindex("127.0.0.1:29447")
        self._zero(added, "A2 addmodelindex") if isinstance(added, dict) and "automatic_spend_atoms" in added else None
        rec = node.reconcilemodelindex({"remote_ids": ["id-0"]})
        self._zero(rec, "A2 reconcile")
        self.log.info("unique_todo_a2_modelindex rc=%s", a2.returncode)

        # unique_todo_build_gui
        if caps.get("gui") != "DEFERRED_WITH_EVIDENCE":
            raise AssertionError(f"GUI disposition: {caps}")
        self.log.info("unique_todo_build_gui DEFERRED_WITH_EVIDENCE")

        # unique_todo_live_r2_hf_wan
        hf_ok, hf_st = self._wan_head("https://huggingface.co/robots.txt")
        r2_ok, r2_st = self._wan_head("https://cloudflare.com/robots.txt")
        if not hf_ok and not r2_ok:
            raise AssertionError(f"live WAN unique todo made no contact hf={hf_st} r2={r2_st}")
        tr = node.getevaluatedtransport({})
        self._zero(tr, "WAN transport")
        if tr.get("live_hf_http") is True:
            raise AssertionError(f"helper must not claim live HF import: {tr}")
        self.log.info("unique_todo_live_r2_hf_wan HF=%s %s R2/CF=%s %s", hf_ok, hf_st, r2_ok, r2_st)

        # unique_todo_400gib
        sparse = Path(self.options.tmpdir) / "todo-400gib.sparse"
        logical = 400 * 1024 * 1024 * 1024
        sparse.touch()
        os.truncate(str(sparse), logical)
        st = sparse.stat()
        if st.st_size != logical:
            raise AssertionError(f"400GiB sparse size {st.st_size}")
        allocated = st.st_blocks * 512
        if allocated >= 64 * 1024 * 1024:
            raise AssertionError(f"400GiB sparse allocated {allocated}")
        sparse.unlink()
        self.log.info("unique_todo_400gib sparse addressing allocated=%s", allocated)

        # unique_todo_utp_quic
        if tr.get("utp") != "NONSHIPPING":
            raise AssertionError(f"uTP: {tr}")
        if tr.get("quic") not in (False, "false", 0):
            raise AssertionError(f"QUIC: {tr}")
        self.log.info("unique_todo_utp_quic NONSHIPPING")

        # unique_todo_quic_ttc_not_shipping — handshake 1-RTT is not TTC.
        adapter_10g_ms = (400 * 1024 * 1024 * 8) / 10e9 * 1000
        full_10g_ms = (40 * 1024 * 1024 * 1024 * 8) / 10e9 * 1000
        adapter_100m_ms = (400 * 1024 * 1024 * 8) / 0.1e9 * 1000
        if 2.0 / adapter_10g_ms >= 0.05:
            raise AssertionError(f"LAN handshake would look material vs adapter@10G {adapter_10g_ms}")
        if 80.0 / adapter_100m_ms >= 0.05:
            raise AssertionError(f"WAN handshake would look material vs adapter@100M {adapter_100m_ms}")
        if 80.0 / full_10g_ms >= 0.01:
            raise AssertionError(f"WAN handshake would look material vs 40GiB@10G {full_10g_ms}")
        ttc = node.getbtxttctrace({})
        self._zero(ttc, "QUIC TTC") if isinstance(ttc, dict) and "automatic_spend_atoms" in ttc else None
        for st in ttc.get("stages") or []:
            if isinstance(st, dict) and st.get("stage") == "quic":
                raise AssertionError(f"TTC must not invent a quic stage: {ttc}")
        self.log.info(
            "unique_todo_quic_ttc_not_shipping adapter10G=%.1fms full10G=%.1fms adapter100M=%.1fms quic=false",
            adapter_10g_ms, full_10g_ms, adapter_100m_ms,
        )

        # unique_todo_torrentd
        if tr.get("btx_torrentd_process") is True:
            raise AssertionError(f"torrentd transport: {tr}")
        torr = node.gettorrentsourcestatus({"locator": "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
        self._zero(torr, "torrentd") if isinstance(torr, dict) and "automatic_spend_atoms" in torr else None
        if torr.get("torrentd_process") is True:
            raise AssertionError(f"torrentd process: {torr}")
        self.log.info("unique_todo_torrentd no process")

        # unique_todo_hw_*
        def _probe(cmd, label):
            try:
                run = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
            except FileNotFoundError:
                self.log.info("%s command missing: %s", label, cmd[0])
                return None
            self.log.info("%s rc=%s out=%s", label, run.returncode, (run.stdout or run.stderr or "")[:200])
            return run

        _probe(["nvidia-smi", "-L"], "unique_todo_hw_cuda")
        _probe(["rocminfo"], "unique_todo_hw_rocm")
        self.log.info("unique_todo_hw_metal platform=%s", os.uname().sysname)
        nixl = os.environ.get("BTX_NIXL_LIB")
        self.log.info("unique_todo_hw_nixl BTX_NIXL_LIB=%s", nixl)
        gds = os.environ.get("BTX_CUFILE_LIB")
        self.log.info("unique_todo_hw_gds BTX_CUFILE_LIB=%s", gds)
        cxl = Path("/sys/bus/cxl")
        self.log.info("unique_todo_hw_cxl /sys/bus/cxl exists=%s", cxl.exists())

        # unique_todo_catalog_not_s3
        st_path = Path(self.options.tmpdir) / "catalog" / "model.safetensors"
        st_path.parent.mkdir(parents=True, exist_ok=True)
        st_path.write_bytes(struct.pack("<Q", 2) + b"{}")
        imported = node.importmodel(str(st_path))
        self._zero(imported, "catalog import") if isinstance(imported, dict) and "automatic_spend_atoms" in imported else None
        blob = str(imported).lower()
        if "s3://" in blob or "amazonaws" in blob or "r2.cloudflarestorage" in blob:
            raise AssertionError(f"catalog retargeted to object store: {imported}")
        self.log.info("unique_todo_catalog_not_s3 import=%s", imported.get("uri") or imported.get("model_id"))

        # unique_todo_spend_zero
        policy = node.getmodelpolicy()
        spend = policy.get("automatic_spend_atoms", policy.get("automatic_spend", 0))
        if spend not in (0, "0"):
            raise AssertionError(f"spend unique todo: {policy}")
        self.log.info("unique_todo_spend_zero ok")

        # unique_todo_ordinary_tools_inspect — python-only BTXPKG (no btx-open).
        fixture = self._src_root() / "src" / "test" / "data" / "agent-package" / "model-agent.btx"
        if not fixture.is_file():
            raise AssertionError(f"missing AHP fixture {fixture}")
        data = fixture.read_bytes()
        if data[:8] != b"BTXPKG\x00\x01":
            raise AssertionError(f"fixture magic {data[:8]!r}")
        flags, nbytes = struct.unpack_from("<IQ", data, 8)
        if flags != 0:
            raise AssertionError(f"BTXPKG flags {flags}")
        digest = data[20:68]
        payload = data[68:68 + nbytes]
        if hashlib.sha384(payload).digest() != digest:
            raise AssertionError("BTXPKG payload digest mismatch")
        pkg = json.loads(payload)
        docs = (pkg.get("core") or {}).get("documents") or []
        agents = next((d for d in docs if isinstance(d, dict) and d.get("path") == "AGENTS.md"), None)
        if not isinstance(agents, dict) or "Package purpose" not in (agents.get("text") or ""):
            raise AssertionError(f"ordinary-tools AGENTS.md missing: {docs[:1]}")
        agents_probe = Path(self.options.tmpdir) / "AGENTS.md"
        if agents_probe.exists():
            raise AssertionError("ordinary-tools inspect wrote AGENTS.md")
        self.log.info("unique_todo_ordinary_tools_inspect documents=%s", len(docs))

        # unique_todo_priv08_unix_denylist + unique_todo_http_405 public surface
        setup = node.getsetupstatus()
        self._zero(setup, "getsetupstatus")
        if not isinstance(setup.get("money"), dict) or not isinstance(setup.get("models"), dict):
            raise AssertionError(f"getsetupstatus shape: {setup}")
        leaks = self._leaks_private(setup)
        if leaks:
            raise AssertionError(f"getsetupstatus leaked {leaks}: {setup}")
        for method in (
            "hello",
            "getmodelnetworkinfo",
            "getmodelcryptoinfo",
            "getbtxpackagecapabilities",
            "getsetupstatus",
            "checkmodelsetup",
            "getevaluatedtransport",
        ):
            got = self._unix_rpc(method)
            self._zero(got, f"unix {method}")
            leaks = self._leaks_private(got)
            if leaks:
                raise AssertionError(f"unix {method} leaked {leaks}: {got}")
        try:
            self._unix_rpc("ensurebtxcapability", {"automatic_spend_atoms": 0})
            self.log.info("unix ensurebtxcapability owner path allowed (not public HTTP)")
        except AssertionError as exc:
            blob = str(exc).upper()
            if "PAID" in blob or "GRANT" in blob or "INVALID" in blob or "PLAN" in blob:
                self.log.info("unix ensurebtxcapability fail-closed owner: %s", exc)
            else:
                raise
        info = node.getmodelnetworkinfo()
        advertised = str(info.get("advertised_host") or "")
        bind = str(info.get("bind") or info.get("listen") or "")
        http_targets = [t for t in (advertised, bind) if t and ":" in t and "127.0.0.1" in t]
        if http_targets:
            url = f"http://{http_targets[0]}/btx-model/2/ensurebtxcapability"
            try:
                urllib.request.urlopen(urllib.request.Request(url, data=b"{}", method="POST"), timeout=3)
                raise AssertionError(f"public HTTP ensure must not succeed: {url}")
            except Exception as exc:
                if "must not succeed" in str(exc):
                    raise
                self.log.info("unique_todo_http_405 fail-closed POST %s: %s", url, exc)
        else:
            self.log.info("unique_todo_http_405 unix-only helper (no public HTTP bind)")
        for hcp_name in (
            "hcphealth",
            "hcphandle",
            "accepthcphandoff",
            "applyhcpwalletless",
        ):
            if http_targets:
                url = f"http://{http_targets[0]}/btx-model/2/{hcp_name}"
                try:
                    urllib.request.urlopen(urllib.request.Request(url, data=b"{}", method="POST"), timeout=3)
                    raise AssertionError(f"public HTTP {hcp_name} must not succeed: {url}")
                except Exception as exc:
                    if "must not succeed" in str(exc):
                        raise
                    self.log.info("unique_todo_priv08_hcp_http fail-closed POST %s: %s", url, exc)
        self.log.info("unique_todo_priv08_unix_and_http_405 advertised=%s", advertised)

        for hcp_unix in ("hcphealth", "hcphandle", "gethcpreadiness"):
            try:
                got = self._unix_rpc(hcp_unix)
            except AssertionError as exc:
                self.log.info(
                    "unique_todo_priv08 unix %s not public allowlist (helper may METHOD_NOT_FOUND): %s",
                    hcp_unix, exc,
                )
                continue
            self._zero(got, f"unix {hcp_unix}")
            leaks = self._leaks_private(got)
            if leaks:
                raise AssertionError(f"unix {hcp_unix} leaked {leaks}: {got}")
            self.log.info(
                "unix %s owner path allowed (not public HTTP; not public unix allowlist)",
                hcp_unix,
            )

        self.unique_todo_hcp_helper_rpc_via_btxd(node)
        self.unique_todo_remote_process_tier()
        self.unique_todo_honest_not_run_labs(node)
        self.unique_todo_delegated_lan_routing(node)
        self.unique_todo_network_watches(node)
        self.unique_todo_search_qrp(node)
        self.unique_todo_swarm_two_piece(node)
        self.unique_todo_first_run_consent(node)
        self.unique_todo_planhcplocal_lan_wins(node)
        self.unique_todo_seedlab_getmodelchannel(node)
        self.unique_todo_hosted_accept_signed_good(node)
        # Last: this one kills the helper and restarts it on the same modeldir.
        self.unique_todo_helper_down_fail_closed(node)

        self.log.info("unique 0.34.8 todos process-tier passed")

    def unique_todo_hcp_helper_rpc_via_btxd(self, node):
        """Process-tier: btxd BOUNTY_PROXY forwards HCP methods to the helper."""
        health = node.hcphealth()
        self._zero(health, "node.hcphealth")
        if "status" not in health and "ok" not in health and "ready" not in health:
            if not isinstance(health, dict) or not health:
                raise AssertionError(f"hcphealth empty: {health}")
        ready = node.gethcpreadiness()
        self._zero(ready, "node.gethcpreadiness")
        try:
            node.sethcpreporting({"secret": "BTX_TEST_SECRET_SENTINEL", "aws_secret_access_key": "BTX_TEST_SECRET_SENTINEL"})
            raise AssertionError("sethcpreporting must refuse secrets")
        except JSONRPCException as exc:
            blob = str(exc).lower()
            if "secret" not in blob and "refus" not in blob and "denied" not in blob and "invalid" not in blob:
                self.log.info("sethcpreporting fail-closed: %s", exc)
            else:
                self.log.info("sethcpreporting refused sentinel: %s", exc)
        try:
            node.importhcpstate({"secret": "BTX_TEST_SECRET_SENTINEL", "wallet_seed": "BTX_TEST_SECRET_SENTINEL"})
            raise AssertionError("importhcpstate must refuse secrets")
        except JSONRPCException as exc:
            self.log.info("importhcpstate refused sentinel: %s", exc)
        self.log.info("unique_todo_hcp_helper_rpc_via_btxd hcphealth/gethcpreadiness/secrets")

    def unique_todo_remote_process_tier(self):
        """Env-gated remote process check. Never SkipTest the whole file.

        Set BTX_REMOTE_PROCESS=1, BTX_REMOTE_PROCESS_HOST, and
        BTX_REMOTE_PROCESS_BTXD to a second-path btxd. The public tree does not
        name operator hosts or production libexec paths.
        """
        skip_reason = (
            "HONEST_NOT_RUN env-gated unique_todo_remote_process "
            "(set BTX_REMOTE_PROCESS=1, BTX_REMOTE_PROCESS_HOST, BTX_REMOTE_PROCESS_BTXD)"
        )
        if os.environ.get("BTX_REMOTE_PROCESS") != "1":
            self.log.info("unique_todo_remote_process HONEST_NOT_RUN: %s", skip_reason)
            return
        host = os.environ.get("BTX_REMOTE_PROCESS_HOST", "").strip()
        remote_btxd = os.environ.get("BTX_REMOTE_PROCESS_BTXD", "").strip()
        if not host or not remote_btxd:
            self.log.info("unique_todo_remote_process HONEST_NOT_RUN: missing host or btxd path")
            return
        try:
            probe = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, "true"],
                capture_output=True, text=True, timeout=12, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.log.info("unique_todo_remote_process HONEST_NOT_RUN: ssh probe failed: %s", exc)
            return
        if probe.returncode != 0:
            self.log.info(
                "unique_todo_remote_process HONEST_NOT_RUN: ssh BatchMode failed rc=%s %s",
                probe.returncode, (probe.stderr or probe.stdout or "")[:200],
            )
            return
        remote = subprocess.run(
            [
                "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host,
                f"test -x {remote_btxd} && {remote_btxd} -version",
            ],
            capture_output=True, text=True, timeout=20, check=False,
        )
        blob = (remote.stdout or "") + (remote.stderr or "")
        if remote.returncode != 0 or "v0.34.8" not in blob:
            raise AssertionError(
                f"unique_todo_remote_process expected v0.34.8 rc={remote.returncode} out={blob[:400]}"
            )
        self.log.info(
            "unique_todo_remote_process_tier %s",
            blob.splitlines()[0] if blob else "v0.34.8",
        )

    def unique_todo_honest_not_run_labs(self, node):
        """Log every §C HONEST_NOT_RUN lab. Never relabel PASS."""
        info = node.getmodelnetworkinfo()
        self._zero(info, "honest_not_run getmodelnetworkinfo")
        try:
            tr = node.getevaluatedtransport({})
            self._zero(tr, "honest_not_run getevaluatedtransport")
            if tr.get("utp") != "NONSHIPPING":
                raise AssertionError(f"uTP must stay NONSHIPPING: {tr.get('utp')}")
            if tr.get("quic") not in (False, "false", "NONSHIPPING"):
                raise AssertionError(f"QUIC must stay non-shipping: {tr.get('quic')}")
            if tr.get("live_r2_wan") not in (None, "NOT_RUN") and tr.get("live_r2_wan") is True:
                raise AssertionError("live R2 WAN must not claim PASS")
        except JSONRPCException as exc:
            self.log.info("unique_todo_honest_not_run_labs transport: %s", exc)
        rows = [
            "F2 wallet sign (wallet_sign stays false)",
            "-modelindex (helper/modeld reject)",
            "BUILD_GUI=ON / Qt journeys",
            "live R2/HF WAN import",
            "400 GiB object I/O (sparse addressing is not I/O)",
            "uTP/QUIC NONSHIPPING",
            "torrentd process",
            "CUDA/Metal live hardware PASS",
            "catalog-on-S3 (forbidden)",
            "Core v4 (forbidden; CORE_V4_FORBIDDEN is fail-closed)",
            "WITH_MODELNET=OFF second tree (disk policy)",
            "1000 downloaders",
            "10m anti-entropy",
            "20-buyer super-seed",
            "mixed-0.34.7 binary lab",
            "live CEX/HSM",
            "env-gated unique_todo_remote_process ssh",
            "Journeys HTTP J02 (no helper); remaining_04 is the LAN proof",
            "e2e-swarm-live.sh 45-byte fixture WITH_GAP; sibling multipiece is the multi-piece proof",
        ]
        for row in rows:
            self.log.info("HONEST_NOT_RUN %s", row)
        if os.environ.get("BTX_REMOTE_PROCESS") == "1":
            self.log.info("BTX_REMOTE_PROCESS=1 set; ssh probe is unique_todo_remote_process_tier")
        else:
            self.log.info("HONEST_NOT_RUN env-gated unique_todo_remote_process ssh (BTX_REMOTE_PROCESS unset)")
        if not os.environ.get("BTX_MIXED_0347"):
            self.log.info("HONEST_NOT_RUN mixed-0.34.7 binary lab; BTX_MIXED_0347 unset")


    # --- Independent re-derivation of the swarm piece tree (src/modelnet/store.cpp,
    # src/modelnet/crypto.cpp). The test must not trust the helper's own arithmetic.

    def _domain_hash(self, domain, body):
        h = hashlib.sha384()
        h.update(struct.pack("<H", len(domain)))
        h.update(domain.encode("ascii"))
        h.update(struct.pack("<Q", len(body)))
        h.update(body)
        return h.digest()

    def _chunk_leaf(self, index, piece):
        return self._domain_hash("BTX/ModelChunk/v2", struct.pack("<QI", index, len(piece)) + piece)

    def _chunk_pad(self, index):
        return self._domain_hash("BTX/ModelChunkPad/v2", struct.pack("<Q", index))

    def _chunk_node(self, left, right):
        return self._domain_hash("BTX/ModelChunkNode/v2", left + right)

    def _pieces_root_hex(self, data, piece_size):
        if not data:
            return self._domain_hash("BTX/ModelEmpty/v2", b"").hex()
        leaves = [
            self._chunk_leaf(i, data[i * piece_size:(i + 1) * piece_size])
            for i in range((len(data) + piece_size - 1) // piece_size)
        ]
        width = 1
        while width < len(leaves):
            width <<= 1
        leaves += [self._chunk_pad(i) for i in range(len(leaves), width)]
        while len(leaves) > 1:
            leaves = [self._chunk_node(leaves[i], leaves[i + 1]) for i in range(0, len(leaves), 2)]
        return leaves[0].hex()

    def _safetensors_bytes(self, total):
        """Exactly `total` bytes of SafeTensors where max_end == file_size."""
        nbytes = total - 8 - 64
        for _ in range(8):
            header = json.dumps(
                {"w": {"dtype": "U8", "shape": [nbytes], "data_offsets": [0, nbytes]}},
                separators=(",", ":"),
            ).encode("utf-8")
            if 8 + len(header) + nbytes == total:
                return struct.pack("<Q", len(header)) + header + b"\0" * nbytes
            nbytes = total - 8 - len(header)
        raise AssertionError(f"could not size a {total}-byte safetensors")

    def unique_todo_delegated_lan_routing(self, node):
        """Delegated + LAN routing on loopback: never consensus, never money scope."""
        routing = node.getmodelroutingstatus({})
        self._zero(routing, "getmodelroutingstatus")
        if routing.get("delegated_routing_is_consensus") is not False:
            raise AssertionError(f"delegated routing must not mutate consensus: {routing}")
        if routing.get("lan_requires_public_address") is not False:
            raise AssertionError(f"LAN discovery must not require a public address: {routing}")
        if routing.get("throughput_is_ranking") is not False:
            raise AssertionError(f"throughput must not be ranking authority: {routing}")
        if routing.get("sample_cap") != 32 or routing.get("probe_max") != 8:
            raise AssertionError(f"routing fanout caps: {routing}")

        # EndpointLooksLan on the loopback/private ranges this host actually has.
        for endpoint, want_lan in (
            ("127.0.0.1:29447", True),
            ("[::1]:29447", True),
            ("10.1.2.3:29447", True),
            ("192.168.4.5:29447", True),
            ("169.254.6.7:29447", True),
            ("172.16.0.5:29447", True),
            ("172.31.255.254:29447", True),
            ("fe80::1%eth0", True),
            ("btx-host.local:29447", True),
            ("172.32.0.5:29447", False),
            ("172.15.0.5:29447", False),
            ("203.0.113.7:29447", False),
        ):
            lan = node.getmodellandiscovery({"endpoint": endpoint})
            self._zero(lan, f"getmodellandiscovery {endpoint}")
            if lan.get("lan") is not want_lan:
                raise AssertionError(f"LAN classification {endpoint} -> {lan}")
            if lan.get("requires_public_address") is not False:
                raise AssertionError(f"LAN requires_public_address {endpoint}: {lan}")
            if lan.get("delegated_routing_is_consensus") is not False:
                raise AssertionError(f"LAN delegated consensus {endpoint}: {lan}")

        # DELEGATE_KNOWN_MASK is 31: anything above it is money/root and must be refused.
        for bad_scopes in (32, 1 << 20, 0xFFFFFFF):
            try:
                node.delegatemodelservice({"scopes": bad_scopes, "ttl": 3600})
                raise AssertionError(f"delegation accepted unknown scope {bad_scopes}")
            except JSONRPCException as exc:
                blob = str(exc).lower()
                if "money" not in blob and "scope" not in blob:
                    raise AssertionError(f"delegation scope {bad_scopes} wrong refusal: {exc}") from exc

        # DELEGATE_ANNOUNCE|DELEGATE_SERVE for a LAN serving delegate.
        delegated = node.delegatemodelservice({"scopes": 6, "ttl": 3600, "all_models": True})
        if delegated.get("recorded") is not True:
            raise AssertionError(f"LAN delegation not recorded: {delegated}")
        record_id = delegated.get("record_id")
        if not isinstance(record_id, str) or len(record_id) != 96:
            raise AssertionError(f"delegation record_id: {delegated}")
        leaks = self._leaks_private(delegated)
        if leaks:
            raise AssertionError(f"delegation leaked {leaks}: {delegated}")
        for money_key in ("wallet_signed", "wallet_sign", "signed_transaction", "txid"):
            if delegated.get(money_key):
                raise AssertionError(f"delegation claimed money {money_key}: {delegated}")

        revoked = node.revokemodelservice({"target_id": record_id})
        if revoked.get("recorded") is not True:
            raise AssertionError(f"revocation not recorded: {revoked}")
        revocation_id = revoked.get("record_id")
        if not isinstance(revocation_id, str) or len(revocation_id) != 96:
            raise AssertionError(f"revocation record_id: {revoked}")
        if revocation_id == record_id:
            raise AssertionError(f"revocation reused the delegation record id: {revoked}")
        if revoked.get("target_id") != record_id:
            raise AssertionError(f"revocation must name the delegation: {revoked}")
        self.log.info("unique_todo_delegated_lan revocation targets %s", record_id[:16])

        policy = node.setmodeldiscoverypolicy({"prefer_lan": True, "idempotency_key": "unique-disc"})
        self._zero(policy, "setmodeldiscoverypolicy")
        if policy.get("throughput_is_ranking") is not False:
            raise AssertionError(f"discovery policy made throughput authoritative: {policy}")
        self.log.info(
            "unique_todo_delegated_lan_routing delegation=%s revocation=%s sample_cap=%s probe_max=%s",
            record_id[:16], revocation_id[:16],
            routing.get("sample_cap"), routing.get("probe_max"),
        )

    def unique_todo_network_watches(self, node):
        """Network watches are not the filesystem drop folder, and never spend."""
        # Filesystem -modelwatch is unset for this helper: it must say so, not invent one.
        fs_status = node.getmodelwatchstatus()
        self._zero(fs_status, "getmodelwatchstatus")
        if fs_status.get("configured") is not False or fs_status.get("watch_dir"):
            raise AssertionError(f"unconfigured -modelwatch reported as configured: {fs_status}")
        if "set -modelwatch" not in str(fs_status.get("one_liner") or ""):
            raise AssertionError(f"getmodelwatchstatus one_liner: {fs_status}")

        drop = Path(self.options.tmpdir) / "watch-drop"
        drop.mkdir(parents=True, exist_ok=True)
        scanned = node.scanmodelwatch(str(drop))
        if scanned.get("imported_count") != 0:
            raise AssertionError(f"empty drop folder imported something: {scanned}")
        if list(drop.iterdir()):
            raise AssertionError(f"scanmodelwatch wrote into the drop folder: {list(drop.iterdir())}")

        model_hex = "c" * 96
        created = {
            "watchmodel": node.watchmodel({"model_id": model_hex}),
            "watchmodelpublisher": node.watchmodelpublisher({"publisher_id": "d" * 96}),
            "watchmodelcollection": node.watchmodelcollection({"collection_id": "coll-unique", "keep_n": 2}),
            "watchmodelquery": node.watchmodelquery({"text": "unique-todo-query", "filters": {"format": "safetensors"}}),
        }
        watch_ids = {}
        for method, watch in created.items():
            self._zero(watch, method)
            for never in ("downloads", "evaluates", "spends", "filesystem_watch"):
                if watch.get(never) is not False:
                    raise AssertionError(f"{method} {never} must be false: {watch}")
            if watch.get("action") != "NOTIFY":
                raise AssertionError(f"{method} default action must be NOTIFY: {watch}")
            wid = watch.get("watch_id")
            if not isinstance(wid, str) or not wid:
                raise AssertionError(f"{method} watch_id: {watch}")
            watch_ids[method] = wid

        # A watch cannot be armed with an action policy the helper does not know.
        try:
            node.watchmodel({"model_id": model_hex, "action": "PAY_ANYTHING"})
            raise AssertionError("watchmodel accepted an unknown action policy")
        except JSONRPCException as exc:
            self.log.info("watchmodel refused unknown action: %s", exc)
        # FUND_WITH_MANDATE is a known policy but is inert without a mandate.
        try:
            node.watchmodel({"model_id": model_hex, "action": "FUND_WITH_MANDATE"})
            raise AssertionError("FUND_WITH_MANDATE watch accepted without a mandate_id")
        except JSONRPCException as exc:
            if "mandate" not in str(exc).lower():
                raise AssertionError(f"FUND_WITH_MANDATE wrong refusal: {exc}") from exc

        listed = node.listmodelwatches({})
        self._zero(listed, "listmodelwatches")
        if listed.get("filesystem_watch") is not False:
            raise AssertionError(f"listmodelwatches conflated the drop folder: {listed}")
        seen = {w.get("watch_id") for w in listed.get("watches") or []}
        missing = [m for m, wid in watch_ids.items() if wid not in seen]
        if missing:
            raise AssertionError(f"listmodelwatches lost {missing}: {listed}")

        one = node.getmodelwatch({"watch_id": watch_ids["watchmodel"]})
        self._zero(one, "getmodelwatch")
        if one.get("model_id") != model_hex or one.get("kind") != "MODEL":
            raise AssertionError(f"getmodelwatch round-trip: {one}")

        actions = node.getmodelwatchactions({"drain": True})
        self._zero(actions, "getmodelwatchactions")
        if actions.get("spends") is not False:
            raise AssertionError(f"watch actions claimed spend authority: {actions}")
        for act in actions.get("actions") or []:
            self._zero(act, "watch action")
            if act.get("spends") is not False:
                raise AssertionError(f"queued watch action spends: {act}")
            if act.get("action") == "FREE_DOWNLOAD" and act.get("getmodel_mode") != "FREE_ONLY":
                raise AssertionError(f"FREE_DOWNLOAD action not FREE_ONLY: {act}")

        for wid in watch_ids.values():
            removed = node.unwatchmodel({"watch_id": wid})
            if removed.get("removed") is not True:
                raise AssertionError(f"unwatchmodel {wid}: {removed}")
        try:
            node.getmodelwatch({"watch_id": watch_ids["watchmodel"]})
            raise AssertionError("getmodelwatch returned a removed watch")
        except JSONRPCException as exc:
            self.log.info("removed watch is NOT_FOUND: %s", exc)
        self.log.info("unique_todo_network_watches watches=%s drop_folder_imports=0", len(watch_ids))

    def unique_todo_search_qrp(self, node):
        """Bounded query routing on loopback. A QRP/query-routing-table wire is NOT_RUN."""
        # There is no QRP RPC in this tree; do not fabricate one. What ships is the
        # bounded QueryRouter fanout, so prove its caps instead of claiming QRP.
        self.log.info(
            "unique_todo_search_qrp HONEST_NOT_RUN: no QRP/query-routing-table RPC exists; "
            "asserting the bounded QueryRouter surface that does ship"
        )
        searched = node.searchmodels({"text": "unique-todo", "scope": "LOCAL", "limit": 5})
        self._zero(searched, "searchmodels")
        query_id = searched.get("query_id")
        if not isinstance(query_id, str) or not query_id:
            raise AssertionError(f"searchmodels query_id: {searched}")
        if searched.get("complete") is True or searched.get("global_complete") is True:
            raise AssertionError(f"search claimed global completeness: {searched}")
        coverage = searched.get("coverage") or {}
        for key in ("connected_peers_queried", "index_peers_queried", "routing_peers_queried"):
            queried = coverage.get(key, 0)
            if isinstance(queried, int) and queried > 8:
                raise AssertionError(f"search {key}={queried} exceeds SEARCH_FANOUT_MAX 8: {coverage}")

        status = node.getsearchstatus(query_id)
        self._zero(status, "getsearchstatus") if "automatic_spend_atoms" in status else None
        if status.get("complete") is True or status.get("global_complete") is True:
            raise AssertionError(f"getsearchstatus claimed completeness: {status}")
        if status.get("state") not in ("RUNNING", "COMPLETE", "CANCELLED", "TIMED_OUT"):
            raise AssertionError(f"getsearchstatus state: {status}")
        try:
            node.getsearchstatus("unique-todo-no-such-query")
            raise AssertionError("getsearchstatus invented a job for an unknown query_id")
        except JSONRPCException as exc:
            self.log.info("unknown query_id is NOT_FOUND: %s", exc)
        cancelled = node.cancelmodelsearch(query_id)
        if cancelled.get("ok") is not True:
            raise AssertionError(f"cancelmodelsearch: {cancelled}")

        peers = node.getsearchpeers()
        for peer in peers.get("peers") or []:
            if peer.get("monetary_service_bit") is not False:
                raise AssertionError(f"search peer carried a monetary service bit: {peer}")
            if peer.get("capability") != "NODE_MODEL_INDEX":
                raise AssertionError(f"search peer capability: {peer}")

        summary = node.querymodelsummary({})
        self._zero(summary, "querymodelsummary")
        if summary.get("complete") is True:
            raise AssertionError(f"query summary claimed completeness: {summary}")
        if summary.get("sample_cap") != 32:
            raise AssertionError(f"query summary sample_cap: {summary}")
        if summary.get("throughput_is_ranking") is not False:
            raise AssertionError(f"query summary made throughput authoritative: {summary}")
        sample = summary.get("sample_ids") or []
        if len(sample) > 32:
            raise AssertionError(f"query summary dumped {len(sample)} ids past the cap: {summary}")
        self.log.info(
            "unique_todo_search_qrp query_id=%s sample=%s/%s peers=%s",
            query_id, len(sample), summary.get("sample_cap"), len(peers.get("peers") or []),
        )

    def unique_todo_swarm_two_piece(self, node):
        """Two 4 MiB-piece swarm object inside the 8MiB budget; root re-derived here."""
        piece_size = 4 * 1024 * 1024
        total = 5 * 1024 * 1024
        blob = self._safetensors_bytes(total)
        if len(blob) != total:
            raise AssertionError(f"fixture size {len(blob)}")
        expected_pieces = (total + piece_size - 1) // piece_size
        if expected_pieces != 2:
            raise AssertionError(f"fixture is not 2 pieces: {expected_pieces}")
        want_sha384 = hashlib.sha384(blob).hexdigest()
        want_root = self._pieces_root_hex(blob, piece_size)

        src = Path(self.options.tmpdir) / "swarm-2piece" / "two-piece.safetensors"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_bytes(blob)
        try:
            imported = node.importmodel(str(src))
            self._zero(imported, "two-piece import")
            model_id = imported.get("model_id")
            if not isinstance(model_id, str) or len(model_id) != 96:
                raise AssertionError(f"two-piece import model_id: {imported}")

            manifest = node.getmodelmanifest(model_id)
            if manifest.get("piece_size") != piece_size:
                raise AssertionError(f"manifest piece_size: {manifest}")
            files = manifest.get("files") or []
            if len(files) != 1:
                raise AssertionError(f"manifest file_count: {manifest}")
            got = files[0]
            if got.get("size") != total:
                raise AssertionError(f"manifest size {got.get('size')} != {total}")
            pieces = (int(got["size"]) + piece_size - 1) // piece_size
            if pieces != 2:
                raise AssertionError(f"manifest is not a 2-piece file: {got}")
            if got.get("sha384") != want_sha384:
                raise AssertionError(f"manifest sha384 {got.get('sha384')} != {want_sha384}")
            if got.get("pieces_root") != want_root:
                raise AssertionError(f"manifest pieces_root {got.get('pieces_root')} != {want_root}")
            if manifest.get("bytes_verified") is not True:
                raise AssertionError(f"two-piece import not BYTES_VERIFIED: {manifest}")

            layout = node.getmodelobjectlayout({"file_size_bytes": total})
            self._zero(layout, "getmodelobjectlayout")
            if layout.get("piece_objects") != 2:
                raise AssertionError(f"object layout piece_objects: {layout}")
            if layout.get("replaces_source_files") is not False:
                raise AssertionError(f"object layout retargeted R2 SOURCE_FILES: {layout}")
            if layout.get("cloud_r2_auto") != "SOURCE_FILES":
                raise AssertionError(f"object layout cloud_r2_auto: {layout}")

            # Second piece carries 1 MiB, so a 256 KiB subpiece fits and 1 MiB does not.
            ok = node.validatesubpiece({
                "artifact_id": manifest.get("artifact_id"),
                "file_index": 0, "piece_index": 1, "offset": 0,
                "length": 256 * 1024, "file_size_bytes": total,
            })
            if ok.get("ok") is not True:
                raise AssertionError(f"aligned 256 KiB subpiece refused: {ok}")
            if ok.get("advertise_full_piece_only") is not True:
                raise AssertionError(f"partial pieces would be advertised: {ok}")
            for bad, why in (
                ({"piece_index": 1, "offset": 0, "length": 1024 * 1024}, "length over SUBPIECE_SIZE"),
                ({"piece_index": 1, "offset": 1000, "length": 256 * 1024}, "unaligned offset"),
                ({"piece_index": 1, "offset": 1024 * 1024, "length": 256 * 1024}, "past the tail piece"),
                ({"piece_index": 2, "offset": 0, "length": 256 * 1024}, "piece past the file"),
            ):
                req = {"artifact_id": manifest.get("artifact_id"), "file_index": 0, "file_size_bytes": total}
                req.update(bad)
                try:
                    node.validatesubpiece(req)
                    raise AssertionError(f"validatesubpiece accepted {why}: {req}")
                except JSONRPCException as exc:
                    self.log.info("validatesubpiece refused %s: %s", why, exc)

            paths = node.exportmodelpath(model_id)
            self._zero(paths, "exportmodelpath") if "automatic_spend_atoms" in paths else None
            self.swarm_two_piece_model_id = model_id
            self.log.info(
                "unique_todo_swarm_two_piece pieces=%s piece_size=%s sha384=%s root=%s",
                pieces, piece_size, want_sha384[:16], want_root[:16],
            )
        finally:
            src.unlink(missing_ok=True)

    def unique_todo_first_run_consent(self, node):
        """First run stores nothing it was not granted, and never arms mining."""
        setup = node.checkmodelsetup()
        self._zero(setup, "checkmodelsetup")
        if setup.get("helper_ready") is not True:
            raise AssertionError(f"checkmodelsetup helper_ready: {setup}")
        # The operator granted exactly -modelstorage=8MiB. auto must not be invented.
        granted = 8 * 1024 * 1024
        quota = setup.get("quota_bytes")
        if quota != granted:
            raise AssertionError(f"first-run quota {quota} != granted {granted}: {setup}")
        used = setup.get("used_bytes")
        if not isinstance(used, int) or used < 0 or used > quota:
            raise AssertionError(f"first-run used_bytes {used} vs quota {quota}")
        leaks = self._leaks_private(setup)
        if leaks:
            raise AssertionError(f"checkmodelsetup leaked {leaks}: {setup}")
        next_actions = setup.get("next_actions")
        if not isinstance(next_actions, list) or not next_actions:
            raise AssertionError(f"first-run doctor gave no next_actions: {setup}")

        # firstrun.json belongs at <datadir>/modelnet/firstrun.json and nowhere near
        # wallets or chainstate. The GUI intro writes it; a headless run must not.
        datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        strays = [
            p for p in datadir.rglob("firstrun.json")
            if "wallet" in p.parts or "chainstate" in p.parts or "blocks" in p.parts
        ]
        if strays:
            raise AssertionError(f"firstrun consent written under money state: {strays}")
        consent_paths = sorted(datadir.rglob("firstrun.json"))
        for path in consent_paths:
            if path.parent.name != "modelnet" and path.parent != self.modeldir:
                raise AssertionError(f"firstrun consent outside modelnet/: {path}")
            consent = json.loads(path.read_text(encoding="utf-8"))
            if consent.get("mining_idle") not in (False, 0, None):
                raise AssertionError(f"first run armed idle mining: {path} {consent}")
        if not consent_paths:
            self.log.info(
                "unique_todo_first_run HONEST_NOT_RUN GUI intro consent file: headless run wrote "
                "no firstrun.json; storage came from the explicit -modelstorage grant"
            )

        # Headless budget path is the environment variable, and it is not set here.
        if os.environ.get("BTX_MODEL_STORAGE"):
            raise AssertionError("BTX_MODEL_STORAGE leaked into the test environment")

        policy = node.getmodelpolicy()
        self._zero(policy, "first-run policy")
        if policy.get("auto_pay") is True:
            raise AssertionError(f"first run enabled auto_pay: {policy}")
        chain = node.getblockchaininfo()
        if chain.get("blocks") != 0:
            raise AssertionError(f"first-run clean chain mined blocks: {chain.get('blocks')}")
        self.log.info(
            "unique_todo_first_run_consent quota=%s used=%s consent_files=%s next_actions=%s",
            quota, used, len(consent_paths), len(next_actions),
        )

    def unique_todo_planhcplocal_lan_wins(self, node):
        """LAN TTC must beat internet:cex-hint; inventory stays private. Mirrors remaining_04."""
        sources = node.puthcplocalitysources({
            "lan": {"id": "lan", "ttc_ms": 20},
            "internet": {"id": "cex-hint", "ttc_ms": 8000},
            "automatic_spend_atoms": 0,
        })
        self._zero(sources, "puthcplocalitysources")

        plan = node.planhcplocal({"recipe_id": "recipe"})
        self._zero(plan, "planhcplocal")
        if plan.get("inventory_reported") is True:
            raise AssertionError(f"planhcplocal reported private inventory: {plan}")
        src = str(plan.get("selected_source", ""))
        if src == "internet:cex-hint" or src.startswith("internet:"):
            raise AssertionError(f"planhcplocal selected internet over LAN: {plan}")
        if src not in ("lan:lan", "resident"):
            raise AssertionError(f"planhcplocal selected_source must be lan:lan or resident: {plan}")
        self.log.info(
            "unique_todo_planhcplocal_lan_wins selected_source=%s ttc_ms=%s",
            src, plan.get("ttc_ms"),
        )

    def unique_todo_seedlab_getmodelchannel(self, node):
        """Lab-signed channel round-trip: seedlabmodelchannel then getmodelchannel."""
        seeded = node.seedlabmodelchannel()
        self._zero(seeded, "seedlabmodelchannel")
        if not isinstance(seeded, dict):
            raise AssertionError(f"seedlabmodelchannel: {seeded}")
        if seeded.get("signature_ok") is not True:
            raise AssertionError(f"seedlabmodelchannel signature_ok: {seeded}")
        publisher_id = seeded.get("publisher_id")
        name = seeded.get("name")
        channel = seeded.get("channel")
        if not publisher_id or not name or not channel:
            raise AssertionError(f"seedlabmodelchannel missing identity: {seeded}")
        got = node.getmodelchannel({
            "publisher_id": publisher_id,
            "name": name,
            "channel": channel,
        })
        self._zero(got, "getmodelchannel")
        if got.get("publisher_id") != publisher_id:
            raise AssertionError(f"getmodelchannel publisher_id: {got}")
        if got.get("signature_ok") is not True:
            raise AssertionError(f"getmodelchannel signature_ok: {got}")
        self.log.info(
            "unique_todo_seedlab_getmodelchannel publisher=%s name=%s channel=%s",
            publisher_id, name, channel,
        )

    def unique_todo_hosted_accept_signed_good(self, node):
        """btx-hosted accept of a structurally good CapabilityHandoff (no shell/body_id).

        RunHostedCli seeds lab state and re-signs unsigned-but-good envelopes.
        Do not put body_id 96 zeros: ParseHcpEnvelope treats a claimed body_id as
        authoritative and returns BODY_ID_MISMATCH. Omit it so the coordinator
        computes the digest and re-signs.
        """
        hosted = self._hosted_path()
        if hosted is None:
            raise AssertionError("btx-hosted not found next to btx-modeld (BUILDDIR/bin/btx-hosted)")

        ones96 = "1" * 96
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
                    "genesis_hash": "0" * 64,
                },
                "handoff_id": "handoff-todo-good",
                "client_operation_id": "op-todo-good",
                "issued_at_ms": "1790000000000",
                "expires_at_ms": "1790000600000",
                "package": {
                    "package_core_id": ones96,
                    "file_sha384": "2" * 96,
                    "recipe_id": "3" * 96,
                    "download_url": (
                        "https://exchange.example/btx/hcp/v1/packages/" + ones96
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
        if "shell" in blob or "executable_url" in blob or "body_id" in blob:
            raise AssertionError("unique_todo_hosted_accept envelope must not contain forbidden fields")

        hand_path = Path(get_datadir_path(self.options.tmpdir, 0)) / "unique-todo-good-handoff.json"
        hand_path.write_text(blob, encoding="utf-8")
        proc = subprocess.run(
            [str(hosted), "accept", str(hand_path)],
            capture_output=True,
            text=True,
            timeout=max(30.0, 30.0 * float(self.options.timeout_factor)),
            cwd=str(get_datadir_path(self.options.tmpdir, 0)),
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"btx-hosted accept of structurally good handoff rc={proc.returncode} "
                f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
            )
        text = (proc.stdout or "").strip()
        try:
            acc = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start < 0 or end <= start:
                raise AssertionError(f"btx-hosted accept stdout not JSON: {text[:500]}")
            acc = json.loads(text[start:end + 1])
        if not isinstance(acc, dict):
            raise AssertionError(f"btx-hosted accept JSON is not an object: {acc}")
        self._zero(acc, "btx-hosted accept")
        if acc.get("handoff_id") != "handoff-todo-good":
            raise AssertionError(f"btx-hosted accept missing handoff_id handoff-todo-good: {acc}")
        if acc.get("wallet_touched") is True:
            raise AssertionError(f"btx-hosted accept wallet_touched: {acc}")
        self.log.info(
            "unique_todo_hosted_accept_signed_good handoff_id=%s spend=0",
            acc.get("handoff_id"),
        )

    def unique_todo_helper_down_fail_closed(self, node):
        """Kill btx-modeld: money plane survives, model plane fails closed, no restart needed."""
        before = node.getmodelnetworkinfo()
        if before.get("helper_ready") is not True:
            raise AssertionError(f"helper not ready before the kill: {before}")
        if before.get("helper_managed_by_btxd") is not False:
            raise AssertionError(f"-modelrpcsocket helper must be unmanaged: {before}")
        tip_before = node.getbestblockhash()

        # Keep the pre-kill helper log; _start_helper truncates modeld.log.
        self._stop_helper()
        live_log = self.modeldir / "modeld.log"
        if live_log.is_file():
            live_log.replace(self.modeldir / "modeld-before-helper-down.log")
        self.modeld_socket.unlink(missing_ok=True)

        # Money plane is untouched by a dead model helper.
        if node.getbestblockhash() != tip_before:
            raise AssertionError("chain tip moved when the model helper died")
        node.getblockchaininfo()
        node.getpeerinfo()

        # getmodelnetworkinfo is the one model RPC that must still answer, honestly.
        down = node.getmodelnetworkinfo()
        self._zero(down, "getmodelnetworkinfo helper down")
        if down.get("helper_ready") is not False:
            raise AssertionError(f"helper_ready stayed true with no helper: {down}")
        if not str(down.get("helper_error") or down.get("error") or ""):
            raise AssertionError(f"helper down without an error string: {down}")
        if down.get("retrieval_default") != "FREE_ONLY":
            raise AssertionError(f"helper down changed retrieval default: {down}")
        leaks = self._leaks_private(down)
        if leaks:
            raise AssertionError(f"helper-down networkinfo leaked {leaks}: {down}")

        # Everything that needs the helper must raise, not fabricate.
        for method, args in (
            ("listmodels", ()),
            ("getmodeltransfers", ()),
            ("getmodelroutingstatus", ({},)),
            ("listmodelwatches", ({},)),
            ("querymodelsummary", ({},)),
            ("getbtxpackagecapabilities", ({},)),
        ):
            try:
                got = getattr(node, method)(*args)
                raise AssertionError(f"{method} answered with no helper: {got}")
            except JSONRPCException as exc:
                if "helper unavailable" not in str(exc).lower():
                    self.log.info("%s failed closed (other reason): %s", method, exc)

        # The unix socket itself must be gone, not silently reused.
        try:
            self._unix_rpc("hello")
            raise AssertionError("unix hello succeeded against a dead helper socket")
        except (AssertionError, OSError) as exc:
            if "succeeded against" in str(exc):
                raise
            self.log.info("unix socket is gone: %s", exc)

        # btxd's own doctor stays truthful and still routes the operator forward.
        setup = node.getsetupstatus()
        self._zero(setup, "getsetupstatus helper down")
        models = setup.get("models")
        if not isinstance(models, dict) or models.get("helper_ready") is not False:
            raise AssertionError(f"getsetupstatus hid the dead helper: {setup}")
        leaks = self._leaks_private(setup)
        if leaks:
            raise AssertionError(f"helper-down getsetupstatus leaked {leaks}: {setup}")
        actions = " ".join(str(a) for a in setup.get("next_actions") or [])
        if "modeld" not in actions and "helper" not in actions:
            raise AssertionError(f"helper-down doctor gave no recovery action: {setup}")

        # Recover without restarting btxd, and prove the catalog survived.
        self._start_helper()

        def back():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(f"restarted helper died {self.modeld_proc.returncode}")
            try:
                return bool(node.getmodelnetworkinfo().get("helper_ready"))
            except JSONRPCException:
                return False

        self.wait_until(back, timeout=60)
        if node.getbestblockhash() != tip_before:
            raise AssertionError("chain tip moved across the helper restart")
        model_id = getattr(self, "swarm_two_piece_model_id", None)
        if model_id:
            manifest = node.getmodelmanifest(model_id)
            if manifest.get("model_id") != model_id:
                raise AssertionError(f"catalog lost the two-piece model across restart: {manifest}")
        after = node.getmodelnetworkinfo()
        if after.get("helper_ready") is not True:
            raise AssertionError(f"helper did not come back: {after}")
        self.log.info(
            "unique_todo_helper_down_fail_closed btxd never restarted; catalog survived (model=%s)",
            (model_id or "none")[:16],
        )


if __name__ == "__main__":
    ModelNetUniqueTodosTest(__file__).main()
