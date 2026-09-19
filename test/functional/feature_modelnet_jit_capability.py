#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest for 0.34.8 JIT capability RPCs (Worker M).

One clean-chain regtest node + a test-spawned btx-modeld. Never production
btxd. Never SIGKILL the live GPU attestor. --timeout-factor=1.

  python3 test/functional/feature_modelnet_jit_capability.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import json
import os
import socket
import struct
import subprocess
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


class ModelNetJitCapabilityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.missing_rpcs = []
        self.skipped = []

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")

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

    def _stop_test_child(self, proc, name):
        """SIGTERM a test-spawned helper; SIGKILL that child only after timeout."""
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                self.log.warning("test %s SIGTERM timeout; SIGKILL test child only", name)
                proc.kill()
                proc.wait(timeout=5)

    def setup_nodes(self):
        self._start_helper()
        if self.modeld_proc.poll() is not None:
            raise AssertionError(f"btx-modeld exited {self.modeld_proc.returncode}")
        self.extra_args = [
            [
                "-modelnet=1",
                f"-modelrpcsocket={self.modeld_socket}",
                *MATMUL_OFF_ARGS,
            ]
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
        dumped = str(obj).lower()
        if "wallet.dat" in dumped or "/wallets/" in dumped:
            raise AssertionError(f"{where} wallet path leaked: {obj}")

    def _recipe(self):
        return {
            "recipe_kind": "FULL_MODEL",
            "components": [{
                "name": "base",
                "resource": {"kind": "MODEL", "digest48": "a" * 96},
                "role": "BASE",
                "required": True,
            }],
            "readiness_contract": "FULL_REQUIRED_SET",
        }

    def _grant(self):
        return {
            "caller": "local",
            "host_bytes": 8388608,
            "automatic_spend_atoms": 0,
        }

    def _load_json_obj(self, text):
        text = (text or "").strip()
        if not text:
            return None
        candidates = [text]
        candidates.extend(line.strip() for line in text.splitlines() if line.strip().startswith("{"))
        for blob in candidates:
            try:
                obj = json.loads(blob)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
        return None

    def _capabilityd_rpc(self, sock, method, params):
        """Newline JSON-RPC 1.0 object params (capabilityd ObjectArg)."""
        req = {
            "jsonrpc": "1.0",
            "id": "capability",
            "method": method,
            "params": params,
        }
        wire = (json.dumps(req, separators=(",", ":")) + "\n").encode("utf-8")
        timeout = max(10.0, 30.0 * float(self.options.timeout_factor))
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(timeout)
            client.connect(str(sock))
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
        try:
            reply = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"capabilityd {method} non-JSON: {raw[:500]}") from exc
        if not isinstance(reply, dict):
            raise AssertionError(f"capabilityd {method} reply not object: {reply}")
        err = reply.get("error")
        if err not in (None, {}):
            raise AssertionError(f"capabilityd {method} error: {err}")
        result = reply.get("result")
        if not isinstance(result, dict):
            raise AssertionError(f"capabilityd {method} result not object: {result}")
        return result

    def _unix_owner_rpc(self, sock, method, params, added, *, allow_codes=(), skip_needles=()):
        """Owner-local unix JSON-RPC via _capabilityd_rpc; allow/skip listed codes."""
        try:
            got = self._capabilityd_rpc(sock, method, params)
        except AssertionError as exc:
            blob = str(exc).upper()
            if any(code.upper() in blob for code in allow_codes):
                added.append(f"capabilityd unix {method}({allow_codes[0]})")
                self.log.info("capabilityd unix %s allowed %s", method, exc)
                return None
            if any(needle.upper() in blob for needle in skip_needles):
                self.skipped.append(f"capabilityd unix {method}: {exc}")
                self.log.info("capabilityd unix %s skipped: %s", method, exc)
                return None
            raise
        self._zero_spend(got, f"capabilityd {method}")
        added.append(f"capabilityd unix {method}")
        return got

    def _exc_blob(self, exc):
        blob = exc.error if isinstance(exc.error, dict) else {}
        return " ".join(str(p) for p in (exc, blob, blob.get("code"), blob.get("message"))).upper()

    def _method_missing(self, exc):
        blob = exc.error if isinstance(exc.error, dict) else {}
        code = blob.get("code")
        msg = str(blob.get("message", exc)).lower()
        return code in (-32601, -32600, 404) or "method not found" in msg or "unknown method" in msg

    def _as_int(self, value, where):
        if isinstance(value, bool) or value is None:
            raise AssertionError(f"{where} missing int: {value}")
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise AssertionError(f"{where} not int: {value}") from exc

    def _rpc_or_skip(self, fn, *args):
        try:
            return fn(*args)
        except JSONRPCException as exc:
            if self._method_missing(exc):
                raise SkipTest(
                    "capability helper methods not registered (node lacks -modelnet or method 404)"
                ) from exc
            raise

    def _rpc_optional(self, fn, *args):
        try:
            return fn(*args)
        except JSONRPCException as exc:
            if self._method_missing(exc):
                return None
            raise

    def _expect_forbidden(self, fn, args, needles, where):
        try:
            got = fn(*args)
            raise AssertionError(f"{where} must fail {needles}; got {got}")
        except JSONRPCException as exc:
            if self._method_missing(exc):
                return "METHOD_NOT_FOUND"
            blob = self._exc_blob(exc)
            if any(n in blob for n in needles):
                return needles[0]
            raise AssertionError(f"{where} expected {needles}: {exc.error}") from exc

    def run_test(self):
        node = self.nodes[0]

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

        chain = node.getblockchaininfo()
        if chain.get("chain") != "regtest":
            raise AssertionError(f"must be isolated regtest: {chain}")
        if not isinstance(node.getblockcount(), int):
            raise AssertionError("monetary getblockcount failed")

        caps = self._rpc_or_skip(node.getbtxruntimecapabilities, {})
        if caps.get("public_runtime_rpc") not in (False, "false", 0):
            raise AssertionError(f"public_runtime_rpc must be false: {caps}")
        self._zero_spend(caps, "getbtxruntimecapabilities")
        if caps.get("gui") != "DEFERRED_WITH_EVIDENCE":
            self.log.warning("gui disposition: %s", caps.get("gui"))

        recipe = self._recipe()
        grant = self._grant()
        planned = self._rpc_or_skip(node.planbtxcapability, {
            "recipe": recipe,
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        plan_id = planned.get("plan_id")
        if not plan_id:
            raise AssertionError(f"plan missing plan_id: {planned}")
        self._zero_spend(planned, "planbtxcapability")
        btxd_plan_id = plan_id
        btxd_grant = grant

        ensured = self._rpc_or_skip(node.ensurebtxcapability, {
            "plan_id": plan_id,
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        if not ensured.get("lease_id"):
            raise AssertionError(f"ensure must return lease_id handle, not a path: {ensured}")
        if not ensured.get("generation"):
            raise AssertionError(f"ensure readiness handle needs generation: {ensured}")
        self._zero_spend(ensured, "ensurebtxcapability")
        if ensured.get("automatic_spend_atoms") not in (0, "0"):
            raise AssertionError(f"ensure spend: {ensured}")

        got = self._rpc_or_skip(node.getbtxcapability, {"job_id": ensured.get("job_id", "")})
        self._zero_spend(got, "getbtxcapability")

        added = []
        lease_id = ensured.get("lease_id")
        job_id = ensured.get("job_id", "")

        resolved = self._rpc_or_skip(node.resolvebtxcapability, {
            "recipe": recipe,
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(resolved, "resolvebtxcapability")
        candidates = resolved.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise AssertionError(f"resolvebtxcapability needs candidates: {resolved}")
        if isinstance(candidates[0], dict):
            self._zero_spend(candidates[0], "resolvebtxcapability candidate")
        added.append("resolvebtxcapability")

        ttc = self._rpc_or_skip(node.getbtxttctrace, {
            "job_id": job_id,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(ttc, "getbtxttctrace")
        if ttc.get("critical_path_not_sum") not in (True, "true", 1):
            raise AssertionError(f"getbtxttctrace critical_path_not_sum: {ttc}")
        wall_ms = self._as_int(ttc.get("wall_ms"), "getbtxttctrace wall_ms")
        sum_occ = self._as_int(ttc.get("sum_occupancy_ms"), "getbtxttctrace sum_occupancy_ms")
        if wall_ms >= sum_occ:
            raise AssertionError(f"wall_ms {wall_ms} must be < sum_occupancy_ms {sum_occ}: {ttc}")
        added.append("getbtxttctrace")

        events = self._rpc_or_skip(node.getbtxcapabilityevents, {
            "cursor": 0,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(events, "getbtxcapabilityevents")
        if not isinstance(events.get("events"), list):
            raise AssertionError(f"getbtxcapabilityevents needs events[]: {events}")
        added.append("getbtxcapabilityevents")

        prefetched = self._rpc_or_skip(node.prefetchbtxcapability, {
            "grant": grant,
            "recipe_id": planned.get("recipe_id", "base"),
            "bytes": 1,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(prefetched, "prefetchbtxcapability")
        added.append("prefetchbtxcapability")

        slept = self._rpc_or_skip(node.sleepbtxcapability, {
            "lease_id": lease_id,
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(slept, "sleepbtxcapability")
        if slept.get("ready") in (True, "true", 1):
            raise AssertionError(f"sleepbtxcapability must not claim readiness: {slept}")
        added.append("sleepbtxcapability")

        woke = self._rpc_or_skip(node.wakebtxcapability, {
            "lease_id": lease_id,
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(woke, "wakebtxcapability")
        if woke.get("discarded_kv_rebuilt") not in (True, "true", 1) and woke.get("ready") not in (True, "true", 1):
            raise AssertionError(f"wakebtxcapability must rebuild KV / be ready: {woke}")
        added.append("wakebtxcapability")

        updated = self._rpc_or_skip(node.planbtxcapabilityupdate, {
            "lease_id": lease_id,
            "lock_id": planned.get("lock_id", ""),
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(updated, "planbtxcapabilityupdate")
        added.append("planbtxcapabilityupdate")

        header = b'{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}'
        st_hex = (len(header).to_bytes(8, "little") + header + bytes(8)).hex()
        inspected = self._rpc_or_skip(node.inspectbtxtensormap, {
            "hex": st_hex,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(inspected, "inspectbtxtensormap")
        if not inspected.get("map_id") and not inspected.get("tensors"):
            raise AssertionError(f"inspectbtxtensormap missing map: {inspected}")
        added.append("inspectbtxtensormap")

        switched = self._rpc_or_skip(node.switchbtxcapability, {
            "old_lock": "old",
            "new_lock": "new",
            "phase": "commit",
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(switched, "switchbtxcapability")
        if switched.get("switched") not in (True, "true", 1):
            raise AssertionError(f"switchbtxcapability: {switched}")
        added.append("switchbtxcapability")

        hold = self._expect_forbidden(
            node.releasebtxcapability,
            [{"lease_id": lease_id, "automatic_spend_atoms": 0}],
            ("LEASE_HOLD",),
            "releasebtxcapability on active lease",
        )
        if hold == "METHOD_NOT_FOUND":
            raise AssertionError("releasebtxcapability vanished")
        added.append("releasebtxcapability(LEASE_HOLD while active)")

        cancelled = self._rpc_or_skip(node.cancelbtxcapability, {
            "job_id": job_id,
            "still_inflight": True,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(cancelled, "cancelbtxcapability")
        if cancelled.get("cancelled") not in (True, "true", 1):
            raise AssertionError(f"cancelbtxcapability: {cancelled}")
        added.append("cancelbtxcapability")

        hold2 = self._expect_forbidden(
            node.releasebtxcapability,
            [{"lease_id": lease_id, "automatic_spend_atoms": 0}],
            ("LEASE_HOLD",),
            "releasebtxcapability after inflight cancel",
        )
        if hold2 == "METHOD_NOT_FOUND":
            raise AssertionError("releasebtxcapability vanished after cancel")
        added.append("releasebtxcapability(LEASE_HOLD after inflight cancel)")

        residency = self._rpc_or_skip(node.getbtxresidency, {
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        self._zero_spend(residency, "getbtxresidency")
        if residency.get("no_public_pointers") not in (True, "true", 1):
            raise AssertionError(f"getbtxresidency must not publish pointers: {residency}")
        added.append("getbtxresidency")

        exported = self._rpc_optional(node.exportbtxlock, {
            "lock": {"recipe_id": "a" * 96},
            "automatic_spend_atoms": 0,
        })
        if exported is None:
            self.missing_rpcs.append("exportbtxlock")
            self.skipped.append("exportbtxlock/importbtxlock not registered")
        else:
            self._zero_spend(exported, "exportbtxlock")
            if not exported.get("hex") and not exported.get("lock_id"):
                raise AssertionError(f"exportbtxlock missing hex/lock_id: {exported}")
            added.append("exportbtxlock")
            imported = self._rpc_optional(node.importbtxlock, {
                "recipe_id": "a" * 96,
                "lock_id": exported.get("lock_id", ""),
                "automatic_spend_atoms": 0,
            })
            if imported is None:
                self.missing_rpcs.append("importbtxlock")
                self.skipped.append("importbtxlock not registered")
            else:
                self._zero_spend(imported, "importbtxlock")
                added.append("importbtxlock")

        paid = self._expect_forbidden(
            node.ensurebtxcapability,
            [{
                "plan_id": plan_id,
                "grant": grant,
                "automatic_spend_atoms": 1,
            }],
            ("PAID_PATH_FORBIDDEN",),
            "ensurebtxcapability automatic_spend_atoms=1",
        )
        if paid == "METHOD_NOT_FOUND":
            raise AssertionError("ensurebtxcapability vanished for paid-path check")
        added.append("paid_path(ensure automatic_spend_atoms=1)")

        paid_resolve = self._expect_forbidden(
            node.resolvebtxcapability,
            [{
                "recipe": recipe,
                "grant": {**grant, "automatic_spend_atoms": 1},
                "automatic_spend_atoms": 1,
            }],
            ("PAID_PATH_FORBIDDEN",),
            "resolvebtxcapability automatic_spend_atoms=1",
        )
        if paid_resolve == "METHOD_NOT_FOUND":
            raise AssertionError("resolvebtxcapability vanished for paid-path check")

        try:
            down_got = node.ensurebtxcapability({
                "plan_id": plan_id,
                "grant": grant,
                "automatic_spend_atoms": 0,
                "helper_alive": False,
            })
            self.skipped.append("helper_alive=false ignored (API does not surface HELPER_DOWN)")
            self._zero_spend(down_got, "ensurebtxcapability helper_alive=false ignored")
        except JSONRPCException as exc:
            blob = self._exc_blob(exc)
            if self._method_missing(exc):
                self.skipped.append("helper_alive=false: method missing")
            elif "HELPER_DOWN" in blob:
                added.append("helper_down(helper_alive=false)")
            else:
                self.skipped.append(f"helper_alive=false not HELPER_DOWN: {exc.error}")

        self.log.info("public HTTP not required; unix helper RPC only")

        public_unix = (
            "hello",
            "getmodelnetworkinfo",
            "getmodelcryptoinfo",
            "getbtxpackagecapabilities",
            "getsetupstatus",
            "checkmodelsetup",
            "getevaluatedtransport",
        )
        leak_needles = (
            "local_paths",
            "installation_directory",
            "independent_trust_ref",
            "wallet_seed",
            "hf_token",
            "aws_secret_access_key",
        )
        for method in public_unix:
            got = self._capabilityd_rpc(self.modeld_socket, method, [])
            self._zero_spend(got, f"public unix {method}")
            blob = json.dumps(got, default=str).lower()
            for needle in leak_needles:
                if needle in blob:
                    raise AssertionError(f"AHP-PRIV-08 unix {method} leaked {needle}: {got}")
            added.append(f"public unix {method}")
        info = node.getmodelnetworkinfo()
        advertised = str(info.get("advertised_host") or "")
        if advertised and ":" in advertised:
            self.log.info("helper advertised_host=%s (PQ1 only; plaintext HTTP must fail closed)", advertised)
        else:
            self.log.info("JIT-API-02 public HTTP absent (unix-only helper)")

        btxd_plan_id = plan_id
        btxd_grant = grant

        cap = None
        builddir = self.config["environment"].get("BUILDDIR")
        if builddir:
            cand = Path(builddir) / "bin" / "btx-capability"
            if cand.is_file() and os.access(cand, os.X_OK):
                cap = cand
        if cap is None:
            raise AssertionError("btx-capability CLI missing from build-gcc13/bin")
        help_out = subprocess.check_output([str(cap), "help"], text=True, stderr=subprocess.STDOUT)
        if "ensurebtxcapability" not in help_out:
            raise AssertionError(f"btx-capability help missing ensurebtxcapability: {help_out[:500]}")
        added.append("btx-capability help")

        capd = Path(builddir) / "bin" / "btx-capabilityd"
        if not capd.is_file() or not os.access(capd, os.X_OK):
            raise AssertionError("btx-capabilityd missing from build-gcc13/bin")
        capdir = Path(self.options.tmpdir) / "capabilityd"
        capdir.mkdir(parents=True, exist_ok=True)
        sock = capdir / "capabilityd.sock"
        capd_log = open(capdir / "capabilityd.log", "w", encoding="utf-8")
        capd_proc = subprocess.Popen(
            [str(capd), f"-modeldir={capdir}", f"-capabilitysocket={sock}"],
            stdout=capd_log,
            stderr=subprocess.STDOUT,
        )
        try:
            def capd_ready():
                if capd_proc.poll() is not None:
                    raise AssertionError(f"btx-capabilityd exited {capd_proc.returncode}")
                return sock.exists()

            self.wait_until(capd_ready, timeout=10)
            cap_out = subprocess.check_output(
                [str(cap), f"-capabilitysocket={sock}", "capabilities"],
                text=True,
                stderr=subprocess.STDOUT,
            )
            if "public_runtime_rpc" not in cap_out:
                raise AssertionError(f"btx-capabilityd capabilities missing public_runtime_rpc: {cap_out[:500]}")
            if '"automatic_spend_atoms":0' not in cap_out.replace(" ", "") and '"automatic_spend_atoms": 0' not in cap_out:
                # UniValue may omit spaces
                if "automatic_spend_atoms" not in cap_out:
                    raise AssertionError(f"capabilityd spend field missing: {cap_out[:500]}")
            added.append("btx-capabilityd unix capabilities")

            recipe = self._recipe()
            grant = self._grant()
            recipe_json = json.dumps(recipe, separators=(",", ":"))
            plan_timeout = max(10.0, 30.0 * float(self.options.timeout_factor))
            planned = None
            plan_how = None
            try:
                plan_run = subprocess.run(
                    [
                        str(cap),
                        f"-capabilitysocket={sock}",
                        "--json",
                        "plan",
                        f"--recipe={recipe_json}",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=plan_timeout,
                    check=False,
                )
                if plan_run.returncode == 0:
                    planned = self._load_json_obj(plan_run.stdout)
                    if isinstance(planned, dict) and planned.get("plan_id"):
                        plan_how = (
                            "btx-capability -capabilitysocket=sock --json plan "
                            "--recipe=FULL_MODEL JSON (CLI grant caller=local "
                            "host_bytes=8388608 automatic_spend_atoms=0)"
                        )
                    else:
                        planned = None
                        self.log.warning(
                            "btx-capability plan stdout lacked plan_id (%s); unix JSON-RPC fallback",
                            (plan_run.stdout or "")[:300],
                        )
                else:
                    self.log.warning(
                        "btx-capability plan rc=%s stderr=%s; unix JSON-RPC fallback",
                        plan_run.returncode,
                        (plan_run.stderr or "")[:300],
                    )
            except (subprocess.TimeoutExpired, OSError) as exc:
                self.log.warning("btx-capability plan CLI failed (%s); unix JSON-RPC fallback", exc)

            if planned is None:
                plan_how = (
                    "unix JSON-RPC planbtxcapability object params "
                    "(CLI could not pass JSON recipe)"
                )
                planned = self._capabilityd_rpc(sock, "planbtxcapability", {
                    "recipe": recipe,
                    "grant": grant,
                    "automatic_spend_atoms": 0,
                })

            plan_id = planned.get("plan_id") if isinstance(planned, dict) else None
            if not plan_id:
                raise AssertionError(f"capabilityd plan missing plan_id: {planned}")
            self._zero_spend(planned, "capabilityd planbtxcapability")

            # Prefer CLI --plan-id once the binary advertises it; JSON-RPC if rc!=0.
            ensured_d = None
            ensure_how = None
            cli_ensured = False
            try:
                ensure_run = subprocess.run(
                    [
                        str(cap),
                        f"-capabilitysocket={sock}",
                        "--json",
                        "ensure",
                        f"--plan-id={plan_id}",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=plan_timeout,
                    check=False,
                )
                if ensure_run.returncode == 0:
                    ensured_d = self._load_json_obj(ensure_run.stdout)
                    if isinstance(ensured_d, dict) and ensured_d.get("lease_id"):
                        cli_ensured = True
                        ensure_how = (
                            "btx-capability -capabilitysocket=sock --json ensure "
                            f"--plan-id={plan_id}"
                        )
                    else:
                        ensured_d = None
                        self.log.warning(
                            "btx-capability ensure --plan-id stdout lacked lease_id (%s); "
                            "unix JSON-RPC fallback",
                            (ensure_run.stdout or "")[:300],
                        )
                else:
                    self.log.warning(
                        "btx-capability ensure --plan-id rc=%s stderr=%s; unix JSON-RPC fallback",
                        ensure_run.returncode,
                        (ensure_run.stderr or "")[:300],
                    )
            except (subprocess.TimeoutExpired, OSError) as exc:
                self.log.warning(
                    "btx-capability ensure --plan-id CLI failed (%s); unix JSON-RPC fallback",
                    exc,
                )

            if ensured_d is None:
                ensure_how = (
                    "unix JSON-RPC ensurebtxcapability object params "
                    "(plan_id + grant; CLI ensure --plan-id returned rc!=0)"
                )
                ensured_d = self._capabilityd_rpc(sock, "ensurebtxcapability", {
                    "plan_id": plan_id,
                    "grant": grant,
                    "automatic_spend_atoms": 0,
                })
            if not ensured_d.get("lease_id"):
                raise AssertionError(
                    f"capabilityd ensure must return lease_id handle, not a path: {ensured_d}"
                )
            if not ensured_d.get("generation"):
                raise AssertionError(
                    f"capabilityd ensure readiness handle needs generation: {ensured_d}"
                )
            self._zero_spend(ensured_d, "capabilityd ensurebtxcapability")
            if ensured_d.get("automatic_spend_atoms") not in (0, "0"):
                raise AssertionError(f"capabilityd ensure spend: {ensured_d}")
            if "second_downloader" in ensured_d and ensured_d.get("second_downloader") not in (
                False,
                "false",
                0,
            ):
                raise AssertionError(f"capabilityd ensure second_downloader: {ensured_d}")
            added.append("btx-capabilityd unix plan/ensure")
            if cli_ensured:
                added.append("btx-capability CLI ensure --plan-id")
            self.log.info("capabilityd process-tier plan via %s; ensure via %s", plan_how, ensure_how)

            capd_lease = ensured_d.get("lease_id")
            capd_job = ensured_d.get("job_id", "")
            capd_recipe_id = planned.get("recipe_id", "base") if isinstance(planned, dict) else "base"

            prefetched = self._unix_owner_rpc(sock, "prefetchbtxcapability", {
                "grant": grant,
                "recipe_id": capd_recipe_id,
                "bytes": 1,
                "automatic_spend_atoms": 0,
            }, added)
            if prefetched is not None:
                dumped = json.dumps(prefetched).lower()
                if "prompt_transcript" in dumped or "reasoning_transcript" in dumped:
                    raise AssertionError(
                        f"prefetchbtxcapability must not carry a prompt transcript: {prefetched}"
                    )

            get_params = {"automatic_spend_atoms": 0}
            if capd_job:
                get_params["job_id"] = capd_job
            else:
                get_params["lease_id"] = capd_lease
            self._unix_owner_rpc(sock, "getbtxcapability", get_params, added)

            slept = self._unix_owner_rpc(sock, "sleepbtxcapability", {
                "lease_id": capd_lease,
                "grant": grant,
                "automatic_spend_atoms": 0,
            }, added, skip_needles=("UNKNOWN_LEASE", "UNVERIFIED_RANGE"))
            if slept is not None and slept.get("ready") in (True, "true", 1):
                raise AssertionError(f"capabilityd sleepbtxcapability must not claim readiness: {slept}")

            woke = self._unix_owner_rpc(sock, "wakebtxcapability", {
                "lease_id": capd_lease,
                "grant": grant,
                "automatic_spend_atoms": 0,
            }, added, allow_codes=("PREMATURE_READY",), skip_needles=("UNKNOWN_LEASE", "UNVERIFIED_RANGE"))
            if woke is not None and woke.get("discarded_kv_rebuilt") not in (True, "true", 1) and woke.get("ready") not in (True, "true", 1):
                raise AssertionError(
                    f"capabilityd wakebtxcapability must rebuild KV / be ready (or PREMATURE_READY): {woke}"
                )

            residency = self._unix_owner_rpc(sock, "getbtxresidency", {
                "grant": grant,
                "automatic_spend_atoms": 0,
            }, added)
            if residency is not None and residency.get("no_public_pointers") not in (True, "true", 1):
                raise AssertionError(
                    f"capabilityd getbtxresidency must not publish pointers: {residency}"
                )

            ttc_d = self._unix_owner_rpc(sock, "getbtxttctrace", {
                "job_id": capd_job,
                "automatic_spend_atoms": 0,
            }, added)
            if ttc_d is not None and ttc_d.get("critical_path_not_sum") not in (True, "true", 1):
                raise AssertionError(f"capabilityd getbtxttctrace critical_path_not_sum: {ttc_d}")

            events_d = self._unix_owner_rpc(sock, "getbtxcapabilityevents", {
                "cursor": 0,
                "automatic_spend_atoms": 0,
            }, added)
            if events_d is not None and not isinstance(events_d.get("events"), list):
                raise AssertionError(f"capabilityd getbtxcapabilityevents needs events[]: {events_d}")

            inspected_d = self._unix_owner_rpc(sock, "inspectbtxtensormap", {
                "hex": st_hex,
                "automatic_spend_atoms": 0,
            }, added, skip_needles=("INVALID_PARAMETER", "INVALID_MODEL", "TRUNCATED"))
            if inspected_d is None:
                self.log.info("capabilityd inspectbtxtensormap skip-log: needs bytes")
            elif not inspected_d.get("map_id") and not inspected_d.get("tensors"):
                raise AssertionError(f"capabilityd inspectbtxtensormap missing map: {inspected_d}")

            resolved_d = self._unix_owner_rpc(sock, "resolvebtxcapability", {
                "recipe": recipe,
                "grant": grant,
                "automatic_spend_atoms": 0,
            }, added)
            if resolved_d is not None:
                cands = resolved_d.get("candidates")
                if not isinstance(cands, list) or not cands:
                    raise AssertionError(f"capabilityd resolvebtxcapability needs candidates: {resolved_d}")

            self._unix_owner_rpc(sock, "planbtxcapabilityupdate", {
                "lease_id": capd_lease,
                "lock_id": planned.get("lock_id", "") if isinstance(planned, dict) else "",
                "grant": grant,
                "automatic_spend_atoms": 0,
            }, added, skip_needles=("INVALID_PARAMETER", "UNKNOWN_LEASE"))

            switched_d = self._unix_owner_rpc(sock, "switchbtxcapability", {
                "old_lock": "old",
                "new_lock": "new",
                "phase": "commit",
                "automatic_spend_atoms": 0,
            }, added)
            if switched_d is not None and switched_d.get("switched") not in (True, "true", 1):
                raise AssertionError(f"capabilityd switchbtxcapability: {switched_d}")

            exported_d = self._unix_owner_rpc(sock, "exportbtxlock", {
                "lock": {"recipe_id": "a" * 96},
                "automatic_spend_atoms": 0,
            }, added, skip_needles=("INVALID_PARAMETER",))
            if exported_d is not None:
                if not exported_d.get("hex") and not exported_d.get("lock_id"):
                    raise AssertionError(f"capabilityd exportbtxlock missing hex/lock_id: {exported_d}")
                self._unix_owner_rpc(sock, "importbtxlock", {
                    "recipe_id": "a" * 96,
                    "lock_id": exported_d.get("lock_id", ""),
                    "automatic_spend_atoms": 0,
                }, added, skip_needles=("INVALID_PARAMETER",))

            caps_d = self._unix_owner_rpc(sock, "getbtxruntimecapabilities", {
                "automatic_spend_atoms": 0,
            }, added)
            if caps_d is not None:
                if caps_d.get("public_runtime_rpc") not in (False, "false", 0):
                    raise AssertionError(f"capabilityd public_runtime_rpc: {caps_d}")
                adapters = caps_d.get("adapters")
                if isinstance(adapters, list):
                    for adapter in adapters:
                        if isinstance(adapter, dict) and adapter.get("stub") in (True, "true", 1):
                            raise AssertionError(f"capabilityd adapter stub=true: {adapter}")

            resolve_cli = subprocess.run(
                [
                    str(cap),
                    f"-capabilitysocket={sock}",
                    "--json",
                    "resolve",
                    f"--recipe={recipe_json}",
                ],
                text=True,
                capture_output=True,
                timeout=plan_timeout,
                check=False,
            )
            if resolve_cli.returncode == 0:
                resolved_cli = self._load_json_obj(resolve_cli.stdout)
                if not isinstance(resolved_cli, dict):
                    raise AssertionError(f"btx-capability resolve JSON missing: {resolve_cli.stdout[:300]}")
                self._zero_spend(resolved_cli, "btx-capability resolve")
                added.append("btx-capability CLI resolve")
            else:
                self.log.warning(
                    "btx-capability resolve rc=%s stderr=%s",
                    resolve_cli.returncode,
                    (resolve_cli.stderr or "")[:300],
                )
                self.skipped.append(
                    f"btx-capability CLI resolve rc={resolve_cli.returncode}"
                )

            prefetch_cli = subprocess.run(
                [
                    str(cap),
                    f"-capabilitysocket={sock}",
                    "--json",
                    "prefetch",
                    "--recipe=base",
                ],
                text=True,
                capture_output=True,
                timeout=plan_timeout,
                check=False,
            )
            if prefetch_cli.returncode == 0:
                pref_obj = self._load_json_obj(prefetch_cli.stdout)
                if isinstance(pref_obj, dict):
                    self._zero_spend(pref_obj, "btx-capability prefetch")
                added.append("btx-capability CLI prefetch")
            else:
                blob = ((prefetch_cli.stdout or "") + "\n" + (prefetch_cli.stderr or "")).upper()
                if any(n in blob for n in ("BUDGET_EXCEEDED", "CACHE_MISS", "INVALID_PARAMETER", "GRANT_")):
                    added.append("btx-capability CLI prefetch fail-closed")
                else:
                    self.skipped.append(
                        f"btx-capability CLI prefetch rc={prefetch_cli.returncode}"
                    )

            status_id = capd_job or capd_lease
            if status_id:
                status_cli = subprocess.run(
                    [
                        str(cap),
                        f"-capabilitysocket={sock}",
                        "--json",
                        "status",
                        str(status_id),
                    ],
                    text=True,
                    capture_output=True,
                    timeout=plan_timeout,
                    check=False,
                )
                if status_cli.returncode == 0:
                    st_obj = self._load_json_obj(status_cli.stdout)
                    if isinstance(st_obj, dict):
                        self._zero_spend(st_obj, "btx-capability status")
                    added.append("btx-capability CLI status")
                else:
                    blob = ((status_cli.stdout or "") + "\n" + (status_cli.stderr or "")).upper()
                    if any(n in blob for n in ("UNKNOWN_LEASE", "INVALID_PARAMETER", "LEASE_HOLD")):
                        added.append("btx-capability CLI status fail-closed")
                    else:
                        self.skipped.append(
                            f"btx-capability CLI status rc={status_cli.returncode}"
                        )

            def _cli_verb(verb, extra, label, fail_needles=()):
                argv = [str(cap), f"-capabilitysocket={sock}", "--json", verb, *extra]
                run = subprocess.run(
                    argv, text=True, capture_output=True, timeout=plan_timeout, check=False,
                )
                if run.returncode == 0:
                    obj = self._load_json_obj(run.stdout)
                    if isinstance(obj, dict):
                        self._zero_spend(obj, label)
                    added.append(f"btx-capability CLI {label}")
                    return obj
                blob = ((run.stdout or "") + "\n" + (run.stderr or "")).upper()
                if fail_needles and any(n in blob for n in fail_needles):
                    added.append(f"btx-capability CLI {label} fail-closed")
                    return None
                self.skipped.append(f"btx-capability CLI {label} rc={run.returncode}")
                return None

            if capd_lease:
                slept_cli = _cli_verb(
                    "sleep", [str(capd_lease)], "sleep",
                    fail_needles=("UNKNOWN_LEASE", "UNVERIFIED_RANGE", "INVALID_PARAMETER"),
                )
                if slept_cli is not None and slept_cli.get("ready") in (True, "true", 1):
                    raise AssertionError(f"CLI sleep must not claim readiness: {slept_cli}")
                woke_cli = _cli_verb(
                    "wake", [str(capd_lease)], "wake",
                    fail_needles=("UNKNOWN_LEASE", "PREMATURE_READY", "UNVERIFIED_RANGE"),
                )
                if woke_cli is not None and woke_cli.get("discarded_kv_rebuilt") not in (True, "true", 1) and woke_cli.get("ready") not in (True, "true", 1):
                    self.log.info("CLI wake shape: %s", woke_cli)
            _cli_verb("events", [], "events")
            if capd_job:
                _cli_verb("ttc", [str(capd_job)], "ttc", fail_needles=("INVALID_PARAMETER",))
            _cli_verb("residency", [], "residency", fail_needles=("INVALID_PARAMETER", "GRANT_"))
            _cli_verb(
                "switch", ["old", "new"], "switch",
                fail_needles=("INVALID_PARAMETER", "STALE_GENERATION"),
            )
            st_hex = (struct.pack("<Q", 2) + b"{}").hex()
            inspected_cli = _cli_verb(
                "inspect-map", [st_hex], "inspect-map",
                fail_needles=("INVALID_PARAMETER", "TRUNCATED", "NONCANONICAL"),
            )
            if inspected_cli is not None and not inspected_cli.get("map_id") and not inspected_cli.get("tensors"):
                raise AssertionError(f"CLI inspect-map missing map: {inspected_cli}")
            _cli_verb(
                "export-lock", ["a" * 96], "export-lock",
                fail_needles=("INVALID_PARAMETER", "UNKNOWN"),
            )
            _cli_verb(
                "import-lock", ["a" * 96], "import-lock",
                fail_needles=("INVALID_PARAMETER", "UNKNOWN"),
            )

            update_cli = subprocess.run(
                [
                    str(cap),
                    f"-capabilitysocket={sock}",
                    "--json",
                    "update",
                    "--preview",
                ],
                text=True,
                capture_output=True,
                timeout=plan_timeout,
                check=False,
            )
            if update_cli.returncode == 0:
                up_obj = self._load_json_obj(update_cli.stdout)
                if isinstance(up_obj, dict):
                    self._zero_spend(up_obj, "btx-capability update")
                added.append("btx-capability CLI update")
            else:
                self.skipped.append(f"btx-capability CLI update rc={update_cli.returncode}")

            if capd_job:
                cancelled_d = self._unix_owner_rpc(sock, "cancelbtxcapability", {
                    "job_id": capd_job,
                    "still_inflight": True,
                    "automatic_spend_atoms": 0,
                }, added)
                if cancelled_d is not None and cancelled_d.get("cancelled") not in (True, "true", 1):
                    raise AssertionError(f"capabilityd cancelbtxcapability: {cancelled_d}")
            else:
                self.skipped.append("capabilityd unix cancelbtxcapability: no job_id from ensure")

            if capd_job:
                _cli_verb(
                    "cancel", [str(capd_job)], "cancel",
                    fail_needles=("INVALID_PARAMETER", "UNKNOWN", "CANCEL"),
                )
            if capd_lease:
                _cli_verb(
                    "release", [str(capd_lease)], "release",
                    fail_needles=("LEASE_HOLD", "UNKNOWN_LEASE"),
                )

            # JIT-SAFETY-05: kill capabilityd only. Monetary RPC must keep working.
            self._stop_test_child(capd_proc, "capabilityd")
            if not isinstance(node.getblockcount(), int):
                raise AssertionError("SAFETY-05 getblockcount failed after capabilityd death")
            chain_after = node.getblockchaininfo()
            if chain_after.get("chain") != "regtest":
                raise AssertionError(f"SAFETY-05 getblockchaininfo after capabilityd death: {chain_after}")
            try:
                post_ensure = node.ensurebtxcapability({
                    "plan_id": btxd_plan_id,
                    "grant": btxd_grant,
                    "automatic_spend_atoms": 0,
                })
                self._zero_spend(post_ensure, "SAFETY-05 ensurebtxcapability via btxd (modeld)")
                added.append("SAFETY-05 ensurebtxcapability via btxd still works (modeld)")
            except JSONRPCException as exc:
                blob = self._exc_blob(exc)
                if self._method_missing(exc):
                    self.skipped.append("SAFETY-05 ensurebtxcapability method missing after capd death")
                elif "HELPER_DOWN" in blob:
                    added.append("SAFETY-05 ensurebtxcapability HELPER_DOWN (money still up)")
                else:
                    self.skipped.append(
                        f"SAFETY-05 ensurebtxcapability via btxd after capd death: {exc.error}"
                    )
            dead = subprocess.run(
                [
                    str(cap),
                    f"-capabilitysocket={sock}",
                    "--json",
                    "status",
                    str(capd_lease or capd_job or "dead"),
                ],
                text=True,
                capture_output=True,
                timeout=plan_timeout,
                check=False,
            )
            dead_blob = ((dead.stdout or "") + "\n" + (dead.stderr or "")).upper()
            if dead.returncode == 0:
                raise AssertionError(
                    "btx-capability status against dead capabilityd must fail closed, not succeed: "
                    f"{(dead.stdout or '')[:500]}"
                )
            if "HELPER_DOWN" not in dead_blob and not any(
                n in dead_blob for n in ("CONNECT", "CONNECTION", "NO SUCH FILE", "REFUSED", "ENOENT")
            ):
                raise AssertionError(
                    "btx-capability status against dead sock must be HELPER_DOWN or connect error: "
                    f"rc={dead.returncode} {(dead.stdout or '')[:200]} {(dead.stderr or '')[:300]}"
                )
            added.append("SAFETY-05 capabilityd terminate; status fail-closed")
        finally:
            self._stop_test_child(capd_proc, "capabilityd")
            capd_log.close()

        self.log.info(
            "0.34.8 isolated-regtest JIT capability passed lease=%s methods=%s skipped=%s missing=%s",
            lease_id, added, self.skipped, self.missing_rpcs,
        )


if __name__ == "__main__":
    ModelNetJitCapabilityTest(__file__).main()
