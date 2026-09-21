#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest E2E for 0.34.8 AHP + NETWORK-02 helper RPCs.

One clean-chain regtest node + a test-spawned btx-modeld. Never production
btxd. Never SIGKILL the live GPU attestor. --timeout-factor=1.

  python3 test/functional/feature_modelnet_0348.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
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

CORE_ID = "73e72380ef4959614ec34e0796a12d59bf4abf483c044b55b66c167d6bb6670db8ec3dd7d26d0e455a072288606e7b58"


class ModelNet0348Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.n02_skipped = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")
        if not self._fixture().is_file():
            raise SkipTest(f"missing AHP fixture {self._fixture()}")

    def _modeld_path(self):
        exeext = self.config["environment"].get("EXEEXT", "")
        name = f"btx-modeld{exeext}"
        candidates = []
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

    def _src_root(self):
        return Path(__file__).resolve().parents[2]

    def _fixture(self):
        return self._src_root() / "src" / "test" / "data" / "agent-package" / "model-agent.btx"

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
        log_path = self.modeldir / "modeld.log"
        self.modeld_log = open(log_path, "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
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
        self.extra_args = [
            [
                "-modelnet=1",
                f"-modelrpcsocket={self.modeld_socket}",
                *MATMUL_OFF_ARGS,
            ],
            [
                "-modelnet=0",
                "-nomodelnet",
                *MATMUL_OFF_ARGS,
            ],
        ]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    def _zero_spend(self, obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} not an object: {obj}")
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _rpc_missing(self, exc):
        blob = exc.error if isinstance(exc.error, dict) else {}
        code = blob.get("code")
        msg = str(blob.get("message", exc)).lower()
        return code in (-32601, -32600) or "method not found" in msg or "unknown method" in msg

    def _skip_method_name(self, entry):
        text = str(entry).strip()
        head = text.split(":", 1)[0].strip().split()[0] if text else ""
        if head and head.replace("_", "").isalnum() and head[0].isalpha():
            return head
        return text or "unknown_rpc"

    def _call_or_skip(self, node, method, payload, where):
        try:
            got = getattr(node, method)(payload)
        except JSONRPCException as exc:
            if self._rpc_missing(exc):
                self.log.info("NETWORK-02 skip missing RPC %s: %s", method, exc)
                self.n02_skipped.append(f"{method}: {exc.error}")
                return None
            raise
        self._zero_spend(got, where)
        self._no_live_process(got, where)
        return got

    def _fail_closed_or_zero(self, node, method, payload, where):
        try:
            got = getattr(node, method)(payload)
        except JSONRPCException as exc:
            if self._rpc_missing(exc):
                self.log.info("NETWORK-02 skip missing RPC %s: %s", method, exc)
                self.n02_skipped.append(f"{method}: {exc.error}")
                return None
            self.log.info("%s fail-closed: %s", method, exc)
            return None
        self._zero_spend(got, where)
        if got.get("spends") is True or got.get("wallet_signed") is True:
            raise AssertionError(f"{where} must not spend: {got}")
        self._no_live_process(got, where)
        return got

    def _no_live_process(self, obj, where):
        if not isinstance(obj, dict):
            return
        for key in (
            "torrentd_process",
            "btx_torrentd_process",
            "live_http",
            "live_hf",
            "live_r2",
            "wan_live",
        ):
            if obj.get(key) is True:
                raise AssertionError(f"{where} must not claim live {key}: {obj}")

    def run_test(self):
        node = self.nodes[0]
        nomodel = self.nodes[1]
        fixture = str(self._fixture())

        def helper_ready():
            if self.modeld_proc.poll() is not None:
                raise AssertionError(f"btx-modeld died {self.modeld_proc.returncode}")
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        self.wait_until(helper_ready, timeout=30)
        info = node.getmodelnetworkinfo()
        if info.get("helper_ready") is not True:
            raise AssertionError(f"helper_ready: {info}")
        self._zero_spend(info, "getmodelnetworkinfo")

        nomodel_chain = nomodel.getblockchaininfo()
        if nomodel_chain.get("chain") != "regtest":
            raise AssertionError(f"nomodelnet node must be regtest: {nomodel_chain}")
        if not isinstance(nomodel.getblockcount(), int):
            raise AssertionError("nomodelnet getblockcount failed")

        caps = node.getbtxpackagecapabilities({})
        if caps.get("BTXPKG_CORE_V2") is not True or caps.get("AGENT_HANDOFF_V1") is not True:
            raise AssertionError(f"getbtxpackagecapabilities: {caps}")
        if caps.get("wallet_sign") is True or caps.get("remote_inference") is True:
            raise AssertionError(f"gated flags must stay false: {caps}")
        if caps.get("gui") != "DEFERRED_WITH_EVIDENCE":
            raise AssertionError(f"gui disposition: {caps}")
        self._zero_spend(caps, "capabilities")

        inspected = node.inspectbtxpackage({"path": fixture})
        if inspected.get("ok") is not True or inspected.get("core_id") != CORE_ID:
            raise AssertionError(f"inspectbtxpackage: {inspected}")
        if inspected.get("model_bytes_verified") is True:
            raise AssertionError(f"inspect must not claim file bytes: {inspected}")
        if inspected.get("signature_status") != "UNSIGNED":
            raise AssertionError(f"unsigned fixture: {inspected}")
        if inspected.get("executed_runtime") is True or inspected.get("installed_software") is True:
            raise AssertionError(f"inspect must not install/run: {inspected}")
        self._zero_spend(inspected, "inspect")

        # JIT-API-07 / AHP-DOC-09: ordinary-tools inspect. Does not write AGENTS.md.
        fixture_bytes = Path(fixture).read_bytes()
        if fixture_bytes[:8] != b"BTXPKG\x00\x01":
            raise AssertionError(f"fixture magic {fixture_bytes[:8]!r}")
        flags, nbytes = struct.unpack_from("<IQ", fixture_bytes, 8)
        if flags != 0:
            raise AssertionError(f"BTXPKG flags {flags}")
        digest = fixture_bytes[20:68]
        payload = fixture_bytes[68:68 + nbytes]
        if hashlib.sha384(payload).digest() != digest:
            raise AssertionError("ordinary-tools BTXPKG digest mismatch")
        pkg = json.loads(payload)
        docs = (pkg.get("core") or {}).get("documents") or []
        agents = next((d for d in docs if isinstance(d, dict) and d.get("path") == "AGENTS.md"), None)
        if not isinstance(agents, dict) or "Package purpose" not in (agents.get("text") or ""):
            raise AssertionError(f"ordinary-tools AGENTS.md missing from framing: {docs[:1]}")
        agents_probe = Path(self.options.tmpdir) / "AGENTS.md"
        if agents_probe.exists():
            raise AssertionError("tmpdir AGENTS.md must not exist before inspect")
        builddir = self.config["environment"].get("BUILDDIR")
        open_bin = None
        if builddir:
            cand = Path(builddir) / "bin" / "btx-open"
            if cand.is_file() and os.access(cand, os.X_OK):
                open_bin = cand
        if open_bin is None:
            raise AssertionError("btx-open missing from BUILDDIR/bin")
        opened = subprocess.run(
            [str(open_bin), fixture],
            capture_output=True,
            text=True,
            timeout=max(10.0, 20.0 * float(self.options.timeout_factor)),
            check=False,
        )
        if opened.returncode != 0:
            raise AssertionError(
                f"btx-open rc={opened.returncode} stderr={opened.stderr[:400]} stdout={opened.stdout[:400]}"
            )
        blob = opened.stdout or ""
        if "core_version=" not in blob and "documents=" not in blob:
            raise AssertionError(f"btx-open inspect missing fields: {blob[:400]}")
        if "automatic_spend_atoms=1" in blob:
            raise AssertionError(f"btx-open must not spend: {blob[:400]}")
        if agents_probe.exists():
            raise AssertionError("btx-open wrote AGENTS.md into tmpdir")

        try:
            node.verifybtxpackage({"path": fixture})
            raise AssertionError("verifybtxpackage must fail closed on unsigned fixture")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "unsigned" not in blob and "helper" not in blob:
                raise AssertionError(f"verify fail-closed text: {exc}") from exc

        doc = node.getbtxpackagedocument({"path": fixture, "document": "AGENTS.md"})
        if doc.get("path") != "AGENTS.md" or doc.get("workspace_written") is True:
            raise AssertionError(f"getbtxpackagedocument: {doc}")
        if doc.get("project_agents_md") is True or doc.get("untrusted_scoped_data") is not True:
            raise AssertionError(f"document flags: {doc}")
        if "cannot override" not in str(doc.get("text", "")):
            self.log.warning("AGENTS.md text missing expected phrase: %s", doc.get("text", "")[:120])
        self._zero_spend(doc, "document")

        dest = Path(self.options.tmpdir) / "acq-dest"
        dest.mkdir(parents=True, exist_ok=True)
        planned = node.planbtxacquisition({
            "path": fixture,
            "local_policy": {"destination": str(dest), "source_policy": "NATIVE_ONLY"},
        })
        plan_id = planned.get("plan_id")
        if not plan_id:
            raise AssertionError(f"plan missing plan_id: {planned}")
        if planned.get("retrieval_mode") != "FREE_ONLY":
            raise AssertionError(f"plan retrieval_mode: {planned}")
        self._zero_spend(planned, "plan")

        got = node.getbtxacquisition({"plan_id": plan_id})
        if got.get("state") not in ("PLANNED", "SELECTION_READY"):
            self.log.info("getbtxacquisition after plan: %s", got.get("state"))
        self._zero_spend(got, "getbtxacquisition")

        payload = b"regtest-0348-leased"
        src = Path(self.options.tmpdir) / "weights.bin"
        src.write_bytes(payload)
        digest = hashlib.sha384(payload).hexdigest()
        ready = node.executebtxacquisition({
            "plan_id": plan_id,
            "verified_local_files": [{
                "path": "weights.gguf",
                "sha384": digest,
                "source_path": str(src),
            }],
        })
        if ready.get("state") != "MODEL_READY":
            raise AssertionError(f"execute MODEL_READY expected: {ready}")
        if ready.get("file_bytes_verified") is not True:
            raise AssertionError(f"file_bytes_verified: {ready}")
        if ready.get("runtime_executed") is True:
            raise AssertionError(f"runtime must not execute: {ready}")
        self._zero_spend(ready, "execute")

        cancelled = node.cancelbtxacquisition({"plan_id": plan_id})
        if cancelled.get("cancelled") is not True:
            raise AssertionError(f"cancel: {cancelled}")
        self._zero_spend(cancelled, "cancel")

        install = node.planbtxclientinstall({"path": fixture})
        if install.get("trust_required") is not True or install.get("installs") is True:
            raise AssertionError(f"planbtxclientinstall: {install}")
        self._zero_spend(install, "install")

        runtime = node.planbtxruntime({
            "path": fixture,
            "trusted_adapter": {
                "adapter_id": "llama.cpp",
                "verified_executable_digest": "c" * 96,
                "executable_path": "llama-cli",
            },
        })
        if runtime.get("executes") is True:
            raise AssertionError(f"planbtxruntime must not execute: {runtime}")
        self._zero_spend(runtime, "runtime")

        transport = node.getevaluatedtransport({})
        if transport.get("utp") != "NONSHIPPING":
            raise AssertionError(f"utp: {transport}")
        if transport.get("quic") not in (False, "false", 0):
            raise AssertionError(f"quic: {transport}")
        if transport.get("catalog_10m") != "NOT_RUN":
            raise AssertionError(f"catalog_10m: {transport}")
        if transport.get("btx_torrentd_process") is True:
            raise AssertionError(f"torrentd: {transport}")
        self._zero_spend(transport, "transport")

        pkg = node.createbtxpackage({"kind": "btxbundle", "schema_version": 1, "idempotency_key": "0348-create-pkg"})
        hex_blob = pkg.get("hex")
        if not isinstance(hex_blob, str) or len(hex_blob) < 2:
            raise AssertionError(f"createbtxpackage hex: {pkg}")
        if pkg.get("magnet_analog") is not False:
            raise AssertionError(f"createbtxpackage magnet_analog: {pkg}")
        self._zero_spend(pkg, "createbtxpackage")

        bundle = node.exportbtxbundle({"kind": "btxbundle", "schema_version": 1, "idempotency_key": "0348-export-bundle"})
        if bundle.get("magnet_analog") is not False:
            raise AssertionError(f"exportbtxbundle magnet_analog: {bundle}")
        if bundle.get("wallet_signed") is True:
            raise AssertionError(f"exportbtxbundle must not wallet-sign: {bundle}")
        self._zero_spend(bundle, "exportbtxbundle")
        pkg_alias = node.exportbtxpackage({"kind": "btxbundle", "schema_version": 1, "idempotency_key": "0348-export-pkg"})
        if pkg_alias.get("magnet_analog") is not False:
            raise AssertionError(f"exportbtxpackage magnet_analog: {pkg_alias}")
        self._zero_spend(pkg_alias, "exportbtxpackage")
        if bundle.get("alias_of") not in (None, "exportbtxbundle") and pkg_alias.get("alias_of") not in (None, "exportbtxbundle"):
            self.log.info("exportbtxpackage alias_of=%s", pkg_alias.get("alias_of"))
        try:
            imported_pkg = node.importbtxpackage({"hex": hex_blob})
            if imported_pkg.get("imported_catalog") is True:
                raise AssertionError(
                    "importbtxpackage must not auto-install a bundle without VerifiedManifest: "
                    f"{imported_pkg}"
                )
            if imported_pkg.get("wallet_signed") is True:
                raise AssertionError(f"importbtxpackage must not wallet-sign: {imported_pkg}")
            self._zero_spend(imported_pkg, "importbtxpackage")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "manifest" not in blob and "invalid" not in blob and "unsigned" not in blob:
                raise

        erasure_obj = {
            "version": 1,
            "profile": "BTX-EC-Cauchy-16-20-v1",
            "canonical_artifact_id": "f" * 96,
            "canonical_manifest_id": "a" * 96,
            "file_index": 0,
            "file_size_bytes": 429496729600,
            "data_shards": 16,
            "total_shards": 20,
            "shard_bytes": 4194304,
            "field_polynomial": "0x11d",
            "stripe_count": 2,
            "final_real_piece_count": 16,
            "shard_index_root": "b" * 96,
            "idempotency_key": "0348-erasure",
            "stripes": [
                {"index": 0, "positions": list(range(16))},
                {"index": 1, "positions": list(range(15))},
            ],
        }
        prepared = node.preparemodelerasure(erasure_obj)
        if prepared.get("reconstructable") is not False:
            raise AssertionError(f"preparemodelerasure reconstructable: {prepared}")
        if prepared.get("global_n_is_sufficiency") is not False:
            raise AssertionError(f"preparemodelerasure global_n: {prepared}")
        self._zero_spend(prepared, "preparemodelerasure")

        health = node.getmodelerasurehealth(erasure_obj)
        if health.get("reconstructable") is not False:
            raise AssertionError(f"getmodelerasurehealth reconstructable: {health}")
        if health.get("global_n_is_sufficiency") is not False:
            raise AssertionError(f"getmodelerasurehealth global_n: {health}")
        self._zero_spend(health, "getmodelerasurehealth")

        torrent = node.gettorrentsourcestatus({
            "locator": "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        })
        if torrent.get("torrentd_process") is True:
            raise AssertionError(f"gettorrentsourcestatus torrentd_process: {torrent}")
        self._zero_spend(torrent, "gettorrentsourcestatus")

        offer = node.getmodeloriginoffer({
            "artifact_id": "local",
            "file_index": 0,
            "offset_bytes": 0,
            "length_bytes": 4096,
        })
        if offer.get("presigned_get_is_meter") is not False:
            raise AssertionError(f"getmodeloriginoffer presigned_get_is_meter: {offer}")
        self._zero_spend(offer, "getmodeloriginoffer")

        policy = node.getsourcepolicy({})
        if policy.get("torrent_worker_s3_credentials") is True:
            raise AssertionError(f"getsourcepolicy: {policy}")
        self._zero_spend(policy, "sourcepolicy")

        ioexec = node.getmodelioexecutor({})
        if not isinstance(ioexec, dict):
            raise AssertionError(f"getmodelioexecutor: {ioexec}")
        dumped = str(ioexec).lower()
        if "io_uring" in dumped and ioexec.get("io_uring") is True:
            raise AssertionError(f"io_uring must stay false: {ioexec}")

        summary = node.querymodelsummary({})
        if summary.get("sample_cap") not in (32, "32") or summary.get("complete") is True:
            raise AssertionError(f"querymodelsummary: {summary}")

        rec = node.reconcilemodelindex({"remote_ids": [f"id-{i}" for i in range(8)]})
        if rec.get("digest_authorizes_insert") is True:
            raise AssertionError(f"reconcile digest must not insert: {rec}")
        if rec.get("want_cap") not in (256, "256"):
            raise AssertionError(f"want_cap: {rec}")

        layout = node.getmodelobjectlayout({"file_size_bytes": 4096})
        if not isinstance(layout, dict):
            raise AssertionError(f"getmodelobjectlayout: {layout}")
        self._zero_spend(layout, "layout")

        sub = node.validatesubpiece({
            "offset": 0,
            "length": 256 * 1024,
            "piece_index": 0,
            "file_size_bytes": 4 * 1024 * 1024,
        })
        if sub.get("ok") is not True:
            raise AssertionError(f"validatesubpiece: {sub}")

        self.n02_skipped = []

        executed_erasure = self._call_or_skip(node, "executemodelerasure", erasure_obj, "executemodelerasure")
        if executed_erasure is not None:
            if executed_erasure.get("reconstructable") is not False:
                raise AssertionError(f"executemodelerasure reconstructable: {executed_erasure}")
            if executed_erasure.get("global_n_is_sufficiency") is not False:
                raise AssertionError(f"executemodelerasure global_n: {executed_erasure}")
            if executed_erasure.get("repair_executed") is True:
                raise AssertionError(f"executemodelerasure repair_executed: {executed_erasure}")

        repaired = self._call_or_skip(node, "repairmodel", erasure_obj, "repairmodel")
        if repaired is not None:
            if repaired.get("reconstructable") is not False:
                raise AssertionError(f"repairmodel reconstructable: {repaired}")
            if repaired.get("global_n_is_sufficiency") is not False:
                raise AssertionError(f"repairmodel global_n: {repaired}")
            if repaired.get("repair_executed") is True:
                raise AssertionError(f"repairmodel must not auto-repair: {repaired}")
            health_rep = repaired.get("health") if isinstance(repaired.get("health"), dict) else repaired
            if not isinstance(health_rep, dict):
                raise AssertionError(f"repairmodel deficit report: {repaired}")

        origst = self._call_or_skip(node, "getmodeloriginstatus", {}, "getmodeloriginstatus")
        if origst is not None:
            if origst.get("operator_allows_external") is True:
                raise AssertionError(f"getmodeloriginstatus must stay native proxy: {origst}")
            if origst.get("follow_redirects") is True:
                raise AssertionError(f"getmodeloriginstatus follow_redirects: {origst}")
            if origst.get("external_url"):
                raise AssertionError(f"getmodeloriginstatus leaked external_url: {origst}")
            if origst.get("presigned_get_is_meter") is True:
                raise AssertionError(f"getmodeloriginstatus presigned meter: {origst}")
            for key in origst:
                kl = str(key).lower()
                if kl in ("presigned_get_is_meter",):
                    continue
                if any(n in kl for n in (
                    "secret", "password", "credential", "authorization", "x-amz",
                    "hf_token", "aws_secret", "external_url",
                )):
                    raise AssertionError(f"getmodeloriginstatus leaked {key}: {origst}")
            mode = origst.get("origin_mode") or origst.get("mode") or origst.get("delivery")
            if mode is not None:
                blob = str(mode).upper()
                if "NATIVE" not in blob and "PROXY" not in blob and "PROXIED" not in blob:
                    raise AssertionError(f"getmodeloriginstatus not native proxy: {origst}")

        bulk = self._call_or_skip(node, "getmodelbulkstatus", {}, "getmodelbulkstatus")
        if bulk is not None:
            prio = bulk.get("interactive_priority")
            if prio is None:
                prio = bulk.get("interactive_has_priority")
            if prio is not True:
                raise AssertionError(f"getmodelbulkstatus interactive must keep priority: {bulk}")
            if bulk.get("ranking_authority") is True:
                raise AssertionError(f"getmodelbulkstatus ranking_authority: {bulk}")
            if bulk.get("starves_interactive") is True:
                raise AssertionError(f"getmodelbulkstatus must not starve interactive: {bulk}")

        import_src = Path(self.options.tmpdir) / "n02-import-src"
        import_src.mkdir(parents=True, exist_ok=True)
        st_bytes = struct.pack("<Q", 2) + b"{}"
        if len(st_bytes) != 10:
            raise AssertionError(f"SafeTensors fixture size {len(st_bytes)}")
        (import_src / "model.safetensors").write_bytes(st_bytes)
        import_plan_id = "c" * 96
        import_plan = {
            "plan_id": import_plan_id,
            "source": {
                "kind": "LOCAL",
                "locator": str(import_src),
                "snapshot_token": "rev-local",
            },
            "files": [{
                "source_path": "model.safetensors",
                "destination_path": "model.safetensors",
                "size_bytes": len(st_bytes),
            }],
            "idempotency_key": "0348-import-local",
        }
        imported = self._call_or_skip(node, "executemodelimport", import_plan, "executemodelimport")
        if imported is not None:
            auth = str(imported.get("authorship", ""))
            if "not implied" not in auth.lower():
                raise AssertionError(f"executemodelimport authorship: {imported}")
            if "has_verified_manifest" in imported or "phase" in imported:
                ok_vm = imported.get("has_verified_manifest") is True
                ok_phase = imported.get("phase") == "PUBLISH_READY"
                if not (ok_vm or ok_phase):
                    raise AssertionError(f"executemodelimport verified/phase: {imported}")
            got_import = self._call_or_skip(node, "getmodelimport", {"plan_id": import_plan_id}, "getmodelimport")
            if got_import is not None:
                if got_import.get("publish_ready") is False:
                    raise AssertionError(f"getmodelimport publish_ready: {got_import}")
                if "authorship" in got_import and "not implied" not in str(got_import.get("authorship", "")).lower():
                    raise AssertionError(f"getmodelimport authorship: {got_import}")
        else:
            self._fail_closed_or_zero(node, "getmodelimport", {"plan_id": import_plan_id}, "getmodelimport")

        self._fail_closed_or_zero(node, "resumemodelimport", {"plan_id": import_plan_id}, "resumemodelimport")
        self._fail_closed_or_zero(node, "cancelmodelimport", {"plan_id": import_plan_id}, "cancelmodelimport")

        channels = self._call_or_skip(node, "listmodelchannels", {}, "listmodelchannels")
        if channels is not None:
            ch = channels.get("channels", [])
            if ch is None:
                ch = []
            if not isinstance(ch, list):
                raise AssertionError(f"listmodelchannels: {channels}")
        try:
            unsigned_ch = node.observemodelchannel({
                "publisher_id": "a" * 96,
                "name": "ops",
                "channel": "main",
                "target_uri": "btx://unsigned-channel",
            })
            if isinstance(unsigned_ch, dict) and unsigned_ch.get("signature_ok") is True:
                raise AssertionError(
                    f"unsigned observemodelchannel must not be signature_ok: {unsigned_ch}"
                )
            self._zero_spend(unsigned_ch, "observemodelchannel unsigned")
        except JSONRPCException as exc:
            blob = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "unsigned" in blob or "rejected" in blob or "signature" in blob or "reject" in blob:
                self.log.info("observemodelchannel unsigned fail-closed: %s", exc)
            elif self._rpc_missing(exc):
                self.n02_skipped.append(f"observemodelchannel: {exc.error}")
            else:
                raise

        acts = self._call_or_skip(node, "getmodelwatchactions", {}, "getmodelwatchactions")
        if acts is not None:
            if acts.get("spends") is not False:
                raise AssertionError(f"getmodelwatchactions spends: {acts}")
            queued = acts.get("actions")
            if queued is not None and not isinstance(queued, list):
                raise AssertionError(f"getmodelwatchactions actions: {acts}")
            if isinstance(queued, list):
                for act in queued:
                    if isinstance(act, dict) and act.get("spends") is True:
                        raise AssertionError(f"getmodelwatchactions action spends: {act}")

        # Currently skipped NETWORK-02 verbs (isolated-regtest). None: every
        # _call_or_skip / missing-RPC path is expected to exist on this helper.
        # Listed skips are HONEST_NOT_RUN. A NEW skip name fails the test.
        honest_rpc = frozenset()
        unexpected = []
        for s in self.n02_skipped:
            name = self._skip_method_name(s)
            self.log.info("HONEST_NOT_RUN %s: %s", name, s)
            if name not in honest_rpc:
                unexpected.append(name)
        if unexpected:
            raise AssertionError(
                f"NEW skip not in HONEST_NOT_RUN catalog allowlist: {unexpected}; skipped={self.n02_skipped}"
            )

        chain = node.getblockchaininfo()
        if chain.get("chain") != "regtest":
            raise AssertionError(f"must be regtest: {chain}")

        self.log.info("COMP-04: stop test helper; money RPC still works")
        self._stop_helper()
        again = node.getblockcount()
        if not isinstance(again, int):
            raise AssertionError(f"getblockcount after helper down: {again}")
        if not isinstance(nomodel.getblockcount(), int):
            raise AssertionError("nomodelnet getblockcount after helper down")
        try:
            node.executebtxacquisition({"plan_id": "aa" * 48})
            raise AssertionError("execute after helper down must fail closed")
        except JSONRPCException as exc:
            msg = str(exc.error if isinstance(exc.error, dict) else exc).lower()
            if "helper" not in msg and "unavailable" not in msg and "unix" not in msg:
                raise AssertionError(f"helper-down error text: {exc}") from exc

        two = self._src_root() / "contrib" / "modelnet" / "two_helper_retrieve.py"
        builddir = self.config["environment"].get("BUILDDIR")
        if two.is_file() and builddir:
            bin_dir = Path(builddir) / "bin"
            self.log.info("isolated two-helper PQ1 retrieve (origin off): %s", two)
            subprocess.check_call(
                [sys.executable, str(two), str(bin_dir)],
                timeout=max(90.0, 120.0 * float(self.options.timeout_factor)),
            )

        self.log.info("0.34.8 isolated-regtest e2e passed core_id=%s", CORE_ID)


if __name__ == "__main__":
    ModelNet0348Test(__file__).main()
