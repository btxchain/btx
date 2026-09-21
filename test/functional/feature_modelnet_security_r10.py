#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""R10 (DoS / security) process-level evidence. Companion to audit/r10-security.md.

Four properties that only a running node plus a running btx-modeld can show,
because each one is about a process boundary rather than a pure function:

  1. sentinel grep      -- a credential offered to the helper is refused, and
                           the sentinel bytes are then absent from every file
                           under the node datadir and the modeldir.
  2. public HTTP 405    -- the public runtime-RPC surface is closed: the owner
                           path reports it closed, a URL path cannot address a
                           method, and no plaintext HTTP request to the model
                           plane is ever answered 2xx.
  3. helper-down money  -- SIGTERM the model helper and the monetary plane still
                           mines, spends and confirms. Money does not depend on
                           models being available.
  4. DoS oversized      -- an oversized request body and an oversized declared
                           Content-Length are both refused by the transport cap,
                           and the helper is still serving afterwards.

Isolated regtest only. The only process this test signals is the btx-modeld it
started itself; it never touches a production btxd. automatic_spend_atoms stays
0 throughout, and nothing here reaches a network outside the test tmpdir.

Skips if the btx-modeld binary is missing. Registration in test_runner.py is a
coordinator decision, so run it directly:

  python3 test/functional/feature_modelnet_security_r10.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

import json
import os
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, get_datadir_path
from test_framework.wallet import MiniWallet

# Recognised as credential sentinels by src/modelnet/hcp_engine.cpp, which
# refuses them by field name and by value. Never logged by this test: the whole
# point is to prove these bytes do not reach disk, so writing them into
# test_framework.log would make the on-disk search meaningless.
SENTINEL_SECRET = "BTX_TEST_SECRET_SENTINEL"
SENTINEL_ACCESS = "BTX_TEST_ACCESS_SENTINEL"

# src/modelnet/helper.cpp MAX_RPC_BODY: the unix control socket stops reading
# here, so it is the outermost body bound on the helper.
HELPER_MAX_RPC_BODY = 256 * 1024
# src/modelnet/hcp_types.h HCP_MAX_BODY_BYTES. Deliberately larger than the
# transport cap above; see check_dos_oversized.
HCP_MAX_BODY_BYTES = 1024 * 1024

# Matches wallet_modelnet_funding.py: keep MatMul binding off so plain regtest
# blocks are cheap to produce.
MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

# Every field name below is refused by src/modelnet/hcp_engine.cpp, either
# because the key names a credential or because the value is a sentinel. Both
# arms matter: a helper that only filtered key names would still persist a
# secret handed to it under an innocuous key.
SENTINEL_ATTEMPTS = (
    ("sethcpreporting", {"secret": SENTINEL_SECRET}, "secret-named key"),
    ("sethcpreporting", {"note": SENTINEL_SECRET}, "sentinel value under a plain key"),
    ("sethcpreporting", {"hf_token": SENTINEL_SECRET}, "hf_token key"),
    ("importhcpstate", {"aws_secret_access_key": SENTINEL_SECRET}, "cloud secret key"),
    ("importhcpstate", {"label": SENTINEL_ACCESS}, "sentinel access id under a plain key"),
    ("importhcpstate", {"include_secrets": True}, "explicit include_secrets"),
)

# Names that must never be reachable as a public runtime RPC.
PUBLIC_DENIED_METHODS = (
    "ensurebtxcapability",
    "runbtxcapability",
    "hcphandle",
    "accepthcphandoff",
    "applyhcpwalletless",
)


class ModelNetSecurityR10Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.modeld_proc = None
        self.modeld_log = None
        self.modeldir = None
        self.modeld_socket = None
        self.datadir = None

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        if self._modeld_path() is None:
            raise SkipTest("btx-modeld binary not found (BUILDDIR/bin)")

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

    # --- test-spawned helper lifecycle --------------------------------------

    def _start_helper(self):
        self.datadir = Path(get_datadir_path(self.options.tmpdir, 0))
        self.datadir.mkdir(parents=True, exist_ok=True)
        self.modeldir = self.datadir / "modeldir"
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
        self.modeld_log = open(self.modeldir / "modeld.log", "w", encoding="utf-8")
        self.log.info("starting %s", " ".join(argv))
        self.modeld_proc = subprocess.Popen(
            argv, stdout=self.modeld_log, stderr=subprocess.STDOUT, cwd=str(self.datadir)
        )

    def _stop_helper(self):
        proc = self.modeld_proc
        self.modeld_proc = None
        if proc is None:
            return
        if proc.poll() is None:
            # SIGTERM to the btx-modeld this test started. Never production btxd.
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

    def _helper_log_tail(self):
        if self.modeldir is None:
            return ""
        log_path = self.modeldir / "modeld.log"
        if not log_path.exists():
            return ""
        return log_path.read_text(encoding="utf-8", errors="replace")[-4000:]

    def _assert_helper_alive(self, where):
        if self.modeld_proc is None or self.modeld_proc.poll() is not None:
            rc = None if self.modeld_proc is None else self.modeld_proc.returncode
            raise AssertionError(
                f"{where}: btx-modeld exited with {rc}\n{self._helper_log_tail()}"
            )

    def setup_nodes(self):
        self._start_helper()
        self._assert_helper_alive("startup")
        self.extra_args = [[
            "-modelnet=1",
            f"-modelrpcsocket={self.modeld_socket}",
            "-acceptnonstdtxn=1",
            *MATMUL_OFF_ARGS,
        ]]
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def shutdown(self):
        self._stop_helper()
        return super().shutdown()

    # --- unix control socket ------------------------------------------------

    def _timeout(self):
        return max(10.0, 20.0 * float(self.options.timeout_factor))

    def _unix_send(self, payload: bytes, tolerate_reset=False):
        """Write raw bytes to the helper control socket, return the raw reply.

        Returns (reply_bytes, reset) so a caller testing an oversized write can
        tell "the helper answered and closed" from "the helper closed on us".
        Both are fail-closed; neither may be a success.
        """
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        reset = False
        chunks = []
        try:
            client.settimeout(self._timeout())
            client.connect(str(self.modeld_socket))
            try:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            except (BrokenPipeError, ConnectionResetError, OSError) as exc:
                if not tolerate_reset:
                    raise
                reset = True
                self.log.info("helper closed the socket mid-write: %s", exc)
            while True:
                try:
                    buf = client.recv(4096)
                except (ConnectionResetError, socket.timeout) as exc:
                    self.log.info("no reply after oversized write: %s", exc)
                    reset = True
                    break
                if not buf:
                    break
                chunks.append(buf)
                if b"\n" in buf:
                    break
        finally:
            client.close()
        return b"".join(chunks), reset

    def _unix_reply(self, method, params=None, tolerate_reset=False):
        """One JSON-RPC round trip. Returns the decoded reply object."""
        req = {
            "jsonrpc": "1.0",
            "id": "r10",
            "method": method,
            "params": params if params is not None else [],
        }
        wire = (json.dumps(req, separators=(",", ":")) + "\n").encode("utf-8")
        raw, _ = self._unix_send(wire, tolerate_reset=tolerate_reset)
        if not raw:
            raise AssertionError(f"unix {method}: helper sent no reply")
        reply = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
        if not isinstance(reply, dict):
            raise AssertionError(f"unix {method}: reply is not an object")
        return reply

    def _unix_result(self, method, params=None):
        reply = self._unix_reply(method, params)
        err = reply.get("error")
        if err not in (None, {}):
            raise AssertionError(f"unix {method} unexpected error: {err}")
        result = reply.get("result")
        if not isinstance(result, dict):
            raise AssertionError(f"unix {method}: result is not an object")
        self._assert_zero_spend(result, f"unix {method}")
        return result

    def _unix_error(self, method, params=None):
        """Assert the helper refused, and return the error object."""
        reply = self._unix_reply(method, params)
        err = reply.get("error")
        if err in (None, {}):
            raise AssertionError(
                f"unix {method} was accepted but must be refused: result={reply.get('result')}"
            )
        if reply.get("result") not in (None, {}):
            raise AssertionError(f"unix {method} refused but still returned a result: {reply}")
        return err

    @staticmethod
    def _assert_zero_spend(obj, where):
        if not isinstance(obj, dict):
            raise AssertionError(f"{where}: expected object")
        spend = obj.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise AssertionError(f"{where}: automatic_spend_atoms={spend}")

    # --- 1. sentinel grep ---------------------------------------------------

    def check_sentinel_never_persisted(self, node):
        self.log.info("R10 sentinel: offer credentials to the helper, then search every file it owns")

        # Control: the same method with no credential in it is accepted, so a
        # later refusal is a decision about the credential and not the method
        # being missing.
        ok = self._unix_result("sethcpreporting", [{"on": False}])
        if ok.get("reporting") is not False:
            raise AssertionError(f"sethcpreporting control call: {ok}")

        for method, params, why in SENTINEL_ATTEMPTS:
            err = self._unix_error(method, [params])
            code = str(err.get("code", ""))
            if code != "SECRETS":
                raise AssertionError(
                    f"{method} ({why}) refused with code {code!r}, expected SECRETS: {err}"
                )
            # The refusal itself must not quote the credential back at us.
            blob = json.dumps(err)
            for sentinel in (SENTINEL_SECRET, SENTINEL_ACCESS):
                if sentinel in blob:
                    raise AssertionError(f"{method} ({why}) echoed the credential in its error")
            self.log.info("%s refused %s with code SECRETS", method, why)

        # Same attempts through btxd's proxy, so the refusal is not a property of
        # talking to the socket directly. ProxyOrLocal has a local fallback only
        # for getmodelnetworkinfo / getmodelcryptoinfo, so a helper refusal of
        # these two methods must surface as an RPC error.
        for method, params, why in SENTINEL_ATTEMPTS:
            failure = None
            try:
                getattr(node, method)(params)
            except JSONRPCException as exc:
                blob = f"{exc} {exc.error}"
                for sentinel in (SENTINEL_SECRET, SENTINEL_ACCESS):
                    if sentinel in blob:
                        failure = f"btxd {method} echoed the credential in its error"
                if failure is None and "SECRETS" not in blob:
                    failure = f"btxd {method} refused {why} for the wrong reason: {blob}"
            else:
                failure = f"btxd {method} accepted {why}; it must be refused"
            if failure is not None:
                raise AssertionError(failure)

        # Give the helper a chance to flush anything it decided to keep, then
        # read every byte it owns.
        self._unix_result("getmodelnetworkinfo")
        self._assert_helper_alive("after sentinel attempts")
        self._search_for_sentinels("with the helper running")

    def _search_for_sentinels(self, when):
        """Fail if either sentinel appears in any file the node or helper owns.

        The node datadir contains the modeldir today, but both roots are walked
        in case that stops being true. The harness's own test_framework.log is
        out of scope on purpose: authproxy logs client-side request bodies there,
        so it records what this test sent, not what the node kept.
        """
        searched = 0
        for root in {self.datadir.resolve(), self.modeldir.resolve()}:
            for path in sorted(root.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                searched += 1
                for sentinel in (SENTINEL_SECRET, SENTINEL_ACCESS):
                    if sentinel.encode("ascii") in data:
                        raise AssertionError(
                            f"credential sentinel reached disk {when} at {path.relative_to(root)}"
                        )
        if searched == 0:
            raise AssertionError(
                f"searched no files under {self.datadir} {when}; the search proved nothing"
            )
        self.log.info("R10 sentinel: %d files searched %s, no credential on disk", searched, when)

    # --- 2. public HTTP 405 -------------------------------------------------

    def check_public_http_405(self, node):
        self.log.info("R10 public surface: runtime RPC closed, no URL-addressable method, no plaintext 2xx")

        # The owner path is allowed to run capability RPCs and still reports the
        # public runtime RPC as closed.
        caps = self._unix_result("getbtxruntimecapabilities")
        if caps.get("public_runtime_rpc") is not False:
            raise AssertionError(f"public_runtime_rpc must be false: {caps}")

        # A URL path cannot name a method. The helper parses the HTTP framing,
        # then dispatches the *body* only, so a REST-shaped request for a denied
        # method reaches no method at all. This is what makes the 405 surface in
        # HandleNativeRequest the only public entry point.
        for name in PUBLIC_DENIED_METHODS:
            body = b"{}"
            request = (
                f"POST /btx-model/2/{name} HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode("ascii") + body
            raw, _ = self._unix_send(request)
            if not raw:
                raise AssertionError(f"path-addressed {name}: helper sent no reply")
            reply = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
            err = reply.get("error")
            if err in (None, {}):
                raise AssertionError(
                    f"URL path addressed {name} and it ran: {reply}"
                )
            if reply.get("result") not in (None, {}):
                raise AssertionError(f"path-addressed {name} returned a result: {reply}")
            self.log.info("URL path /btx-model/2/%s addressed no method (%s)", name, err.get("code"))

        # Nothing on the model plane answers plaintext HTTP with a 2xx. The 405
        # in HandleNativeRequest is reached only from HandlePq1Fd, i.e. inside the
        # PQ1 tunnel, so a plaintext probe is expected to yield that 405 or no
        # HTTP service at all -- never a 200.
        #
        # Only endpoints this test's own helper advertises are probed. A fixed
        # well-known port is deliberately not probed: on a host that also runs a
        # real node, that would be a request at a process this test does not own.
        info = node.getmodelnetworkinfo()
        self._assert_zero_spend(info, "getmodelnetworkinfo")
        if info.get("public_runtime_rpc") is True:
            raise AssertionError(f"getmodelnetworkinfo reports public_runtime_rpc true: {info}")
        # advertised_host is a bool, so it names no endpoint; only values shaped
        # like host:port can be probed.
        targets = []
        for key in ("bind", "listen", "public_host", "model_host", "host"):
            value = info.get(key)
            if not isinstance(value, str) or ":" not in value:
                continue
            port = value.rsplit(":", 1)[1]
            if port.isdigit():
                targets.append(value)

        if not targets:
            # The default is the stronger outcome: there is no public bind, so
            # there is no plaintext surface for a 405 to defend. Say so instead of
            # silently probing nothing.
            self.log.info(
                "R10 public surface: helper exposes no host:port (advertised_host=%s), so the "
                "only entry points are the unix socket and the PQ1 listener",
                info.get("advertised_host"),
            )
        else:
            probed = 0
            for target in dict.fromkeys(targets):
                for name in PUBLIC_DENIED_METHODS:
                    url = f"http://{target}/btx-model/2/{name}"
                    try:
                        with urllib.request.urlopen(
                            urllib.request.Request(url, data=b"{}", method="POST"), timeout=3
                        ) as resp:
                            status = getattr(resp, "status", 200)
                    except urllib.error.HTTPError as exc:
                        status = exc.code
                    except Exception as exc:  # refused / reset / TLS on a plaintext read
                        self.log.info("%s -> no HTTP service (%s)", url, exc.__class__.__name__)
                        probed += 1
                        continue
                    if 200 <= status < 300:
                        raise AssertionError(f"plaintext HTTP {url} answered {status}")
                    if status not in (403, 404, 405):
                        raise AssertionError(
                            f"plaintext HTTP {url} answered {status}; expected 405 or no service"
                        )
                    self.log.info("%s -> HTTP %d", url, status)
                    probed += 1
            self.log.info("R10 public surface: %d plaintext probes, none answered 2xx", probed)
        self._assert_helper_alive("after public surface probes")

    # --- 3. DoS oversized ---------------------------------------------------

    def check_dos_oversized(self, node):
        self.log.info("R10 oversized: transport cap closes before any inner cap, helper survives")

        # A single JSON-RPC line twice the transport cap. The helper stops
        # reading at MAX_RPC_BODY, so what it parses is truncated and refused;
        # it never buffers the whole line.
        filler = "a" * (HELPER_MAX_RPC_BODY * 2)
        oversized = (
            json.dumps(
                {"jsonrpc": "1.0", "id": "r10", "method": "sethcpreporting",
                 "params": [{"note": filler}]},
                separators=(",", ":"),
            ) + "\n"
        ).encode("ascii")
        if len(oversized) <= HELPER_MAX_RPC_BODY:
            raise AssertionError("oversized fixture is not actually oversized")
        raw, reset = self._unix_send(oversized, tolerate_reset=True)
        if raw:
            reply = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
            err = reply.get("error")
            if err in (None, {}):
                raise AssertionError(f"oversized body was accepted: {reply}")
            if reply.get("result") not in (None, {}):
                raise AssertionError(f"oversized body returned a result: {reply}")
            self.log.info("oversized body refused with code %s", err.get("code"))
        elif not reset:
            raise AssertionError("oversized body got neither a refusal nor a closed socket")
        else:
            self.log.info("oversized body closed the connection without a reply")
        self._assert_helper_alive("after oversized body")

        # A declared Content-Length far past the cap is refused on the declared
        # length, so a peer cannot make the helper reserve a gigabyte by lying
        # in a header. HCP's own 1 MiB body cap is never consulted: the
        # transport cap is smaller, so it is the one that closes.
        if HCP_MAX_BODY_BYTES <= HELPER_MAX_RPC_BODY:
            raise AssertionError("this check assumes the transport cap is the tighter of the two")
        huge_declared = (
            "POST /btx-model/2/hello HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 1073741824\r\n\r\n"
            "{}"
        ).encode("ascii")
        raw, _ = self._unix_send(huge_declared)
        if not raw:
            raise AssertionError("declared 1 GiB body: helper sent no reply")
        reply = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
        err = reply.get("error")
        if err in (None, {}):
            raise AssertionError(f"declared 1 GiB body was accepted: {reply}")
        if reply.get("result") not in (None, {}):
            raise AssertionError(f"declared 1 GiB body returned a result: {reply}")
        self.log.info("declared 1 GiB body refused with code %s", err.get("code"))
        self._assert_helper_alive("after declared oversized body")

        # The helper is still serving, which is the whole point of a bound: it
        # refuses the request, not the process.
        info = self._unix_result("getmodelnetworkinfo")
        if info.get("helper_ready") is not True:
            raise AssertionError(f"helper not ready after oversized requests: {info}")
        node.getmodelnetworkinfo()
        self.log.info("R10 oversized: helper still ready after every oversized request")

    # --- 4. helper-down money ----------------------------------------------

    def check_helper_down_money(self, node):
        self.log.info("R10 helper-down: stop the model helper, then move money end to end")

        # This tree is often walletless (no BDB). MiniWallet anyone-can-spend
        # needs -acceptnonstdtxn=1 (scriptpubkey -26 otherwise).
        wallet = MiniWallet(node)
        self.generate(wallet, COINBASE_MATURITY + 1)
        funded = wallet.get_balance()
        if funded <= 0:
            raise AssertionError(f"no spendable value before the helper stops: {funded}")
        height_before = node.getblockcount()

        self._stop_helper()
        self.log.info("model helper stopped; monetary plane must be unaffected")

        # Chain and mempool are still answering.
        chain = node.getblockchaininfo()
        assert_equal(chain["chain"], "regtest")
        assert_equal(chain["blocks"], height_before)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Spend, relay, mine, confirm -- with no model helper anywhere.
        tx = wallet.send_self_transfer(from_node=node)
        if tx["txid"] not in node.getrawmempool():
            raise AssertionError("spend did not reach the mempool with the helper down")
        self.generate(wallet, 1)
        assert_equal(node.getblockcount(), height_before + 1)
        assert_equal(node.getmempoolinfo()["size"], 0)
        tip = node.getbestblockhash()
        if tx["txid"] not in node.getblock(tip)["tx"]:
            raise AssertionError("spend was not mined with the helper down")
        if wallet.get_balance() <= 0:
            raise AssertionError("wallet lost all value while the helper was down")
        self.log.info("money moved and confirmed at height %d with no helper", node.getblockcount())

        # The model plane degrades instead of taking the node with it, and still
        # never reports a spend.
        try:
            down = node.getmodelnetworkinfo()
        except JSONRPCException as exc:
            self.log.info("getmodelnetworkinfo fails cleanly with the helper down: %s", exc)
        else:
            self._assert_zero_spend(down, "getmodelnetworkinfo with helper down")
            if down.get("helper_ready") is True:
                raise AssertionError(f"helper_ready true after SIGTERM: {down}")
            self.log.info("getmodelnetworkinfo reports helper_ready=%s", down.get("helper_ready"))

        # And the node is still healthy afterwards, not merely alive.
        assert_equal(node.getblockchaininfo()["blocks"], height_before + 1)

    def run_test(self):
        node = self.nodes[0]

        def helper_ready():
            self._assert_helper_alive("waiting for readiness")
            try:
                info = node.getmodelnetworkinfo()
            except JSONRPCException:
                return False
            return bool(info.get("helper_ready"))

        self.log.info("waiting for getmodelnetworkinfo helper_ready")
        self.wait_until(helper_ready, timeout=30)

        self.check_sentinel_never_persisted(node)
        self.check_public_http_405(node)
        self.check_dos_oversized(node)
        # Last: this one stops the helper and does not restart it.
        self.check_helper_down_money(node)

        # Repeat the on-disk search now that the helper has run its shutdown
        # path. A process that buffered a credential in memory and only flushed
        # state on SIGTERM would pass the first search and fail this one.
        self._search_for_sentinels("after the helper exited")

        self.log.info("R10 security functional evidence passed")


if __name__ == "__main__":
    ModelNetSecurityR10Test(__file__).main()
