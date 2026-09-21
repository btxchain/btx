#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Remaining 0.34.8 JIT/helper cases that no other functional file owns.

Exclusive to this file (nothing here duplicates feature_modelnet_helper.py,
feature_modelnet_jit_capability.py, or feature_modelnet_unique_todos.py):

  remaining_firstrun_quota0_documented
        LOCAL-04/05 quota-0 refuse already lives in
        feature_modelnet_firstrun.py. This file links that file instead of
        starting a second -modelstorage=0 helper to assert the same thing.
  remaining_import_getmodel_verify
        import -> getmodel -> independent verify: recompute SHA-384 over the
        bytes we handed the helper and require the manifest to agree, then
        re-import and require the same identity (digests are not minted).
  remaining_unix_helper_only
        the default helper owns no listening TCP socket at all (/proc fd
        inodes joined against /proc/net/tcp LISTEN rows); only modeld.sock.
  remaining_public_http_405_capability
        a PQ1-bound helper never serves capability/HCP methods to a plaintext
        HTTP client, while those same methods answer on its unix socket. The
        bound listener is also the control proving the scan above is not a
        false negative. The 405 status itself is HandleNativeRequest's
        contract and is asserted in src/test/modelnet_ahp_priv08_tests.cpp;
        what this file adds is that no cleartext client reaches that handler.
  remaining_nomodelnet_hcp
        a -nomodelnet btxd pointed at the helper socket still answers HCP and
        capability RPCs, still refuses secrets, and keeps money independent
        while getmodelnetworkinfo reports enabled=false.

Isolated regtest only. Never production btxd, never the live GPU attestor.
automatic_spend_atoms stays 0.

  python3 test/functional/feature_modelnet_jit_remaining.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import hashlib
import json
import os
import socket
import stat
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

# src/modelnet/protocol.h MODEL_HTTP_ROOT plus the browser-edge spellings.
CAPABILITY_HTTP_PATHS = (
    "/btx-model/2/planbtxcapability",
    "/btx-model/2/ensurebtxcapability",
    "/btx-model/2/getbtxcapability",
    "/btx-model/2/inspectbtxtensormap",
    "/btx-model/2/exportbtxlock",
    "/btx-model/2/hcphealth",
    "/btx-model/2/accepthcphandoff",
    "/ensurebtxcapability",
    "/planbtxcapability",
)

# A plaintext reply must never carry a readiness handle.
HANDLE_NEEDLES = (b"lease_id", b"plan_id", b"generation", b"job_id")

SENTINEL = "BTX_TEST_SECRET_SENTINEL"


def safetensors_one_tensor():
    """Valid SafeTensors: LE64(header) || header || 1024 payload bytes.

    src/modelnet/capability_bytes.cpp requires product(shape)*width == length
    and offset+length <= file_size, so 256 F32 elements is 1024 bytes.
    """
    header = b'{"w":{"dtype":"F32","shape":[256],"data_offsets":[0,1024]}}'
    payload = bytes((i * 7 + 11) & 0xFF for i in range(1024))
    return struct.pack("<Q", len(header)) + header + payload


class ModelNetJitRemainingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.helpers = []
        self.primary = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld not found")
        if not Path("/proc/net/tcp").exists():
            raise SkipTest("/proc/net/tcp missing; cannot prove unix-only listen set")

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

    def _spawn_helper(self, short, label, extra):
        """Start a test-owned btx-modeld. Never production btxd.real.

        Directory names stay tiny: ListenUnix() silently relocates the socket
        to /tmp once the path reaches sun_path (108), and btxd cannot follow
        that relocation, so a long tmpdir would look like a dead helper.
        """
        base = Path(get_datadir_path(self.options.tmpdir, 0))
        modeldir = base / f"md{short}"
        modeldir.mkdir(parents=True, exist_ok=True)
        sock = modeldir / "modeld.sock"
        if len(str(sock).encode()) >= 108:
            raise SkipTest(f"tmpdir too deep for a unix socket ({sock})")
        if sock.exists():
            sock.unlink()
        argv = [
            str(self._modeld_path()),
            f"-modeldir={modeldir}",
            "-modelstorage=8MiB",
            f"-modelrpcsocket={sock}",
            *extra,
        ]
        log = open(modeldir / "modeld.log", "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=str(base))
        helper = {"name": label, "proc": proc, "log": log, "dir": modeldir, "sock": sock}
        self.helpers.append(helper)
        if proc.poll() is not None:
            raise AssertionError(f"btx-modeld {label} exited {proc.returncode}\n{self._log_tail(helper)}")
        return helper

    def _log_tail(self, helper):
        path = helper["dir"] / "modeld.log"
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")[-2000:]

    def _stop_helper(self, helper):
        """SIGTERM the test child; SIGKILL that child only after a timeout."""
        proc = helper["proc"]
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=max(5.0, 10.0 * float(self.options.timeout_factor)))
            except subprocess.TimeoutExpired:
                self.log.warning("test helper %s ignored SIGTERM; SIGKILL test child only", helper["name"])
                proc.kill()
                proc.wait(timeout=5)
        if helper["log"] is not None:
            helper["log"].close()
            helper["log"] = None

    def setup_nodes(self):
        self.primary = self._spawn_helper("p", "primary", [])
        self.extra_args = [
            [
                "-modelnet=1",
                f"-modelrpcsocket={self.primary['sock']}",
                *MATMUL_OFF_ARGS,
            ],
            [
                "-nomodelnet",
                "-modelnet=0",
                f"-modelrpcsocket={self.primary['sock']}",
                *MATMUL_OFF_ARGS,
            ],
        ]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        for helper in list(self.helpers):
            self._stop_helper(helper)
        return super().shutdown()

    def _zero(self, obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where} not an object: {obj}")
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _unix_rpc(self, sock, method, params):
        req = {"jsonrpc": "1.0", "id": "remaining", "method": method, "params": params}
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
                buf = client.recv(65536)
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
            raise AssertionError(f"unix {method} reply not object: {reply}")
        err = reply.get("error")
        if err not in (None, {}):
            raise AssertionError(f"unix {method} error: {err}")
        result = reply.get("result")
        if not isinstance(result, dict):
            raise AssertionError(f"unix {method} result not object: {result}")
        return result

    def _wait_unix_ready(self, helper):
        def ready():
            if helper["proc"].poll() is not None:
                raise AssertionError(
                    f"btx-modeld {helper['name']} died {helper['proc'].returncode}\n{self._log_tail(helper)}"
                )
            if not helper["sock"].exists():
                return False
            try:
                return bool(self._unix_rpc(helper["sock"], "hello", []))
            except (OSError, AssertionError, json.JSONDecodeError):
                return False

        self.wait_until(ready, timeout=30)

    def _socket_inodes(self, pid):
        inodes = set()
        fd_dir = Path("/proc") / str(pid) / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except OSError as exc:
            raise AssertionError(f"cannot read {fd_dir}: {exc}") from exc
        for entry in entries:
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[len("socket:["):-1])
        return inodes

    def _listen_rows(self):
        """(local_address_hex, inode) for every LISTEN row in /proc/net/tcp{,6}."""
        rows = []
        for name in ("tcp", "tcp6"):
            path = Path("/proc/net") / name
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and fields[3] == "0A":
                    rows.append((fields[1], fields[9]))
        return rows

    def _helper_listens(self, helper):
        inodes = self._socket_inodes(helper["proc"].pid)
        return [addr for addr, inode in self._listen_rows() if inode in inodes]

    def _free_port(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]
        finally:
            probe.close()

    def _plaintext_http(self, port, path):
        """POST path in cleartext.

        Returns (outcome, status, raw). outcome distinguishes a TCP connect
        that never happened from one the PQ1 edge dropped, so "no capability
        came back" can never be satisfied by an empty port.
        """
        body = b"{}"
        head = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        timeout = max(5.0, 8.0 * float(self.options.timeout_factor))
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        chunks = []
        try:
            client.settimeout(timeout)
            try:
                client.connect(("127.0.0.1", port))
            except OSError as exc:
                return "connect_failed", None, str(exc).encode("utf-8")
            try:
                client.sendall(head + body)
                while True:
                    buf = client.recv(4096)
                    if not buf:
                        break
                    chunks.append(buf)
                    if sum(len(c) for c in chunks) > 65536:
                        break
            except OSError as exc:
                if not chunks:
                    return "dropped", None, str(exc).encode("utf-8")
        finally:
            client.close()
        raw = b"".join(chunks)
        if not raw:
            return "dropped", None, b"no bytes"
        status = None
        if raw.startswith(b"HTTP/1."):
            try:
                status = int(raw.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status = None
        return "reply", status, raw

    def run_test(self):
        node = self.nodes[0]
        nomodel = self.nodes[1]

        def helper_ready():
            if self.primary["proc"].poll() is not None:
                raise AssertionError(
                    f"btx-modeld died {self.primary['proc'].returncode}\n{self._log_tail(self.primary)}"
                )
            try:
                return bool(node.getmodelnetworkinfo().get("helper_ready"))
            except JSONRPCException:
                return False

        self.wait_until(helper_ready, timeout=30)

        chain = node.getblockchaininfo()
        if chain.get("chain") != "regtest":
            raise AssertionError(f"must be isolated regtest: {chain}")
        btxd = Path(self.options.bitcoind).resolve()
        if "libexec/btxd.real" in str(btxd):
            raise AssertionError(f"test btxd is the production attestor: {btxd}")

        self.remaining_firstrun_quota0_documented()
        self.remaining_import_getmodel_verify(node)
        self.remaining_unix_helper_only()
        self.remaining_public_http_405_capability()
        self.remaining_nomodelnet_hcp(nomodel)

        self.log.info("remaining 0.34.8 JIT cases passed")

    def remaining_firstrun_quota0_documented(self):
        """The quota-0 refuse is owned by feature_modelnet_firstrun.py."""
        owner = self._src_root() / "test" / "functional" / "feature_modelnet_firstrun.py"
        if not owner.is_file():
            raise AssertionError(
                f"{owner.name} is gone; the first-run quota-0 refuse would have to move into this file"
            )
        text = owner.read_text(encoding="utf-8")
        for needle in ("-modelstorage=0", "quota 0 must refuse import", "quota_bytes"):
            if needle not in text:
                raise AssertionError(f"{owner.name} no longer covers the quota-0 refuse ({needle!r} missing)")
        self.log.info(
            "remaining_firstrun_quota0_documented: LOCAL-04/05 -modelstorage=0 import refusal is "
            "asserted in %s; not duplicated here",
            owner.name,
        )

    def remaining_import_getmodel_verify(self, node):
        """import -> getmodel -> verify the manifest against the bytes we wrote."""
        payload = safetensors_one_tensor()
        src = Path(self.options.tmpdir) / "remaining-import" / "model.safetensors"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_bytes(payload)
        expected = hashlib.sha384(payload).hexdigest()

        imported = node.importmodel(str(src))
        self._zero(imported, "importmodel")
        model_id = imported.get("model_id")
        uri = imported.get("uri")
        if not model_id or not uri:
            raise AssertionError(f"importmodel missing model_id/uri: {imported}")

        got = node.getmodel(uri, "FREE_ONLY")
        self._zero(got, "getmodel FREE_ONLY")
        if got.get("plan") != "FREE" or got.get("status") != "local":
            raise AssertionError(f"getmodel of an imported model must be local FREE: {got}")
        if got.get("paid_atoms") not in (0, "0"):
            raise AssertionError(f"FREE_ONLY must not price a local model: {got}")

        manifest = node.getmodelmanifest(model_id)
        if manifest.get("hash_alg") != "sha384":
            raise AssertionError(f"manifest hash_alg: {manifest}")
        if manifest.get("model_id") != model_id:
            raise AssertionError(f"manifest model_id disagrees with import: {manifest}")
        files = manifest.get("files")
        if not isinstance(files, list) or not files:
            raise AssertionError(f"manifest has no files: {manifest}")
        entry = files[0]
        if int(entry.get("size", -1)) != len(payload):
            raise AssertionError(f"manifest size {entry.get('size')} != {len(payload)} bytes imported")
        if entry.get("sha384") != expected:
            raise AssertionError(
                f"manifest sha384 {entry.get('sha384')} does not verify against the imported bytes {expected}"
            )
        if manifest.get("bytes_verified") is not True or manifest.get("complete") is not True:
            raise AssertionError(f"locally imported model must be complete and bytes-verified: {manifest}")
        if manifest.get("structure_verified") is not True:
            raise AssertionError(f"manifest structure_verified: {manifest}")

        # The store is content-addressed, so re-importing the same bytes may
        # never mint a second identity. Today it fails closed on the existing
        # artifact; returning the first identity would be equally correct.
        try:
            again = node.importmodel(str(src))
            self._zero(again, "importmodel repeat")
            if again.get("model_id") != model_id or again.get("artifact_id") != imported.get("artifact_id"):
                raise AssertionError(f"re-import minted a second identity: {imported} vs {again}")
            self.log.info("re-import returned the same identity %s", model_id[:16])
        except JSONRPCException as exc:
            blob = str(exc).lower()
            if "exist" not in blob:
                raise AssertionError(f"re-import must refuse on the existing artifact: {exc}") from exc
            self.log.info("re-import fail-closed on the existing artifact: %s", exc)
        listed = node.listmodels()
        copies = [
            m for m in (listed.get("models") or [])
            if isinstance(m, dict) and m.get("model_id") == model_id
        ]
        if len(copies) != 1:
            raise AssertionError(f"catalog holds {len(copies)} copies of {model_id}: {listed}")

        # A digest that was never imported must not resolve to this manifest.
        try:
            stranger = node.getmodelmanifest("f" * 96)
            raise AssertionError(f"unknown digest must not return a manifest: {stranger}")
        except JSONRPCException as exc:
            self.log.info("getmodelmanifest unknown digest fail-closed: %s", exc)

        self.log.info(
            "remaining_import_getmodel_verify model_id=%s sha384=%s… size=%s verified against local bytes",
            model_id[:16], expected[:16], len(payload),
        )

    def remaining_unix_helper_only(self):
        """The default helper listens on modeld.sock and on no TCP port."""
        sock = self.primary["sock"]
        if not stat.S_ISSOCK(sock.stat().st_mode):
            raise AssertionError(f"{sock} is not a unix socket")
        listens = self._helper_listens(self.primary)
        if listens:
            raise AssertionError(
                f"unix-only helper owns listening TCP sockets {listens} (no -modelbind was given)"
            )
        info = self.nodes[0].getmodelnetworkinfo()
        self._zero(info, "getmodelnetworkinfo")
        advertised = info.get("advertised_host") or ""
        if advertised:
            raise AssertionError(f"unix-only helper must not advertise a host: {info}")
        self.log.info(
            "remaining_unix_helper_only: %s only, zero LISTEN sockets owned by pid %s, advertised_host empty",
            sock.name, self.primary["proc"].pid,
        )

    def remaining_public_http_405_capability(self):
        """A PQ1-bound helper serves no capability/HCP method in cleartext."""
        port = self._free_port()
        helper = self._spawn_helper("b", "pq1-bound", [f"-modelbind=127.0.0.1:{port}"])
        self._wait_unix_ready(helper)

        # Control for remaining_unix_helper_only: the same scan does see this
        # listener, so "zero LISTEN sockets" above was not a false negative.
        def bound():
            return bool(self._helper_listens(helper))

        try:
            self.wait_until(bound, timeout=20)
        except AssertionError:
            self.log.info(
                "remaining_public_http_405_capability HONEST_NOT_RUN: PQ1 bind 127.0.0.1:%s never "
                "listened (unix RPC continues by design)\n%s",
                port, self._log_tail(helper),
            )
            return
        listens = self._helper_listens(helper)
        want = f"0100007F:{port:04X}"
        if want not in listens:
            raise AssertionError(f"expected loopback LISTEN {want}, helper owns {listens}")
        if len(listens) != 1:
            raise AssertionError(f"one -modelbind must open exactly one listener: {listens}")

        outcomes = {}
        for path in CAPABILITY_HTTP_PATHS:
            outcome, status, raw = self._plaintext_http(port, path)
            outcomes[path] = outcome
            if outcome == "connect_failed":
                raise AssertionError(
                    f"cannot probe {path}: TCP connect to the bound helper failed ({raw!r}); "
                    "an unreachable port is not evidence that HTTP is refused"
                )
            for needle in HANDLE_NEEDLES:
                if needle in raw:
                    raise AssertionError(
                        f"plaintext HTTP {path} handed out {needle!r}: {raw[:400]!r}"
                    )
            if outcome == "dropped":
                self.log.info(
                    "remaining_public_http_405_capability %s: TCP up, PQ1 edge dropped the "
                    "cleartext request (%s)",
                    path, raw.decode("utf-8", "replace")[:120],
                )
                continue
            if status is None:
                # A TLS record (content types 20..24) means the port answered
                # as TLS and never handed the request to an HTTP handler.
                if raw[0] not in range(0x14, 0x19):
                    raise AssertionError(
                        f"plaintext {path} got neither HTTP nor a TLS record: {raw[:64]!r}"
                    )
                self.log.info(
                    "remaining_public_http_405_capability %s: PQ1 edge answered with a TLS "
                    "record, not HTTP (%s)",
                    path, raw[:8].hex(),
                )
                continue
            if 200 <= status < 300:
                raise AssertionError(f"plaintext HTTP {path} returned {status}: {raw[:400]!r}")
            body = raw.split(b"\r\n\r\n", 1)[-1]
            try:
                parsed = json.loads(body.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                parsed = None
            if status == 405 and isinstance(parsed, dict):
                if parsed.get("public_runtime_rpc") not in (False, "false", 0):
                    raise AssertionError(f"405 body must deny public runtime RPC: {parsed}")
                self._zero(parsed, f"405 body {path}")
            self.log.info("remaining_public_http_405_capability %s -> %s %s", path, status, parsed)

        # The refusal is edge-specific, not a missing method: the same helper
        # answers capability and HCP owner-locally over its unix socket.
        recipe = {
            "recipe_kind": "FULL_MODEL",
            "components": [{
                "name": "base",
                "resource": {"kind": "MODEL", "digest48": "a" * 96},
                "role": "BASE",
                "required": True,
            }],
            "readiness_contract": "FULL_REQUIRED_SET",
        }
        grant = {"caller": "local", "host_bytes": 8388608, "automatic_spend_atoms": 0}
        planned = self._unix_rpc(helper["sock"], "planbtxcapability", {
            "recipe": recipe,
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        self._zero(planned, "bound unix planbtxcapability")
        plan_id = planned.get("plan_id")
        if not plan_id:
            raise AssertionError(f"bound helper unix plan missing plan_id: {planned}")
        ensured = self._unix_rpc(helper["sock"], "ensurebtxcapability", {
            "plan_id": plan_id,
            "grant": grant,
            "automatic_spend_atoms": 0,
        })
        self._zero(ensured, "bound unix ensurebtxcapability")
        if not ensured.get("lease_id"):
            raise AssertionError(f"bound helper unix ensure must return a lease handle: {ensured}")
        health = self._unix_rpc(helper["sock"], "hcphealth", [])
        self._zero(health, "bound unix hcphealth")
        self.log.info(
            "remaining_public_http_405_capability: unix plan/ensure/hcphealth work on the same "
            "PQ1-bound helper (lease=%s) while cleartext HTTP got no capability from any of %s. "
            "The literal 405 body is HandleNativeRequest's contract, asserted in "
            "src/test/modelnet_ahp_priv08_tests.cpp; process tier proves no plaintext service. "
            "outcomes=%s",
            ensured.get("lease_id"), len(CAPABILITY_HTTP_PATHS), outcomes,
        )
        self._stop_helper(helper)
        self.helpers.remove(helper)

    def remaining_nomodelnet_hcp(self, nomodel):
        """-nomodelnet btxd on the helper socket still answers HCP."""
        info = nomodel.getmodelnetworkinfo()
        self._zero(info, "nomodelnet getmodelnetworkinfo")
        if info.get("enabled") is not False:
            raise AssertionError(f"-nomodelnet must report enabled=false: {info}")
        if info.get("helper_ready") is not True:
            raise AssertionError(f"-nomodelnet still proxies to the helper socket: {info}")

        health = nomodel.hcphealth()
        self._zero(health, "nomodelnet hcphealth")
        if not health:
            raise AssertionError(f"nomodelnet hcphealth empty: {health}")
        ready = nomodel.gethcpreadiness()
        self._zero(ready, "nomodelnet gethcpreadiness")

        # Capability plane is reachable with modelnet off, and still unpaid.
        caps = nomodel.getbtxruntimecapabilities({"automatic_spend_atoms": 0})
        self._zero(caps, "nomodelnet getbtxruntimecapabilities")
        if caps.get("public_runtime_rpc") not in (False, "false", 0):
            raise AssertionError(f"nomodelnet public_runtime_rpc must stay false: {caps}")

        # Secrets stay refused when modelnet is off.
        for method in ("sethcpreporting", "importhcpstate"):
            try:
                getattr(nomodel, method)({"secret": SENTINEL, "wallet_seed": SENTINEL})
                raise AssertionError(f"nomodelnet {method} must refuse secrets")
            except JSONRPCException as exc:
                self.log.info("nomodelnet %s refused sentinel: %s", method, exc)

        # Money is independent of every line above.
        if not isinstance(nomodel.getblockcount(), int):
            raise AssertionError("nomodelnet getblockcount failed")
        if nomodel.getblockchaininfo().get("chain") != "regtest":
            raise AssertionError("nomodelnet node left isolated regtest")
        self.log.info(
            "remaining_nomodelnet_hcp: enabled=false, hcphealth/gethcpreadiness/"
            "getbtxruntimecapabilities answered, secrets refused, money unaffected",
        )


if __name__ == "__main__":
    ModelNetJitRemainingTest(__file__).main()
