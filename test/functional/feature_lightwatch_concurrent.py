#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Concurrent lightwatch writers cannot overwrite a successful descriptor addition."""

import hashlib
import json
import subprocess
import threading
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class LightWatchConcurrentTest(BitcoinTestFramework):
    def set_test_params(self) -> None:
        self.num_nodes = 0
        self.setup_clean_chain = True

    def setup_network(self) -> None:
        # Exercise only the client; the HTTP fixture below supplies RPC replies.
        pass

    def skip_test_if_missing_module(self) -> None:
        self.skip_if_no_cli()

    def run_test(self) -> None:
        datadir = Path(self.options.tmpdir) / "client"
        datadir.mkdir()
        watchdir = datadir / "watch"
        waiting = threading.Event()
        release = threading.Event()
        failures: list[str] = []
        block_hash = "00" * 31 + "01"

        def hash256(value: bytes) -> bytes:
            return hashlib.sha256(hashlib.sha256(value).digest()).digest()

        # A consistent empty basic filter. No daemon, funds or mainnet peers
        # are needed to exercise the client's load / RPC / save transaction.
        filter_header = hash256(hash256(b"\x00") + bytes(32))[::-1].hex()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_POST(self) -> None:
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                try:
                    method, params = request["method"], request.get("params", [])
                    result: int | str | dict[str, str]
                    if method == "getblockcount":
                        if not waiting.is_set():
                            # Sync has loaded the watch before it asks for the
                            # tip. Hold it there while another writer runs.
                            waiting.set()
                            assert release.wait(30), "sync barrier timed out"
                        result = 0
                    elif method == "getblockhash":
                        assert_equal(params, [0])
                        result = block_hash
                    elif method == "getblockfilter":
                        assert_equal(params, [block_hash, "basic"])
                        result = {"filter": "00", "header": filter_header}
                    else:
                        raise AssertionError(f"Unexpected RPC: {method}")
                    response = {"result": result, "error": None, "id": request["id"]}
                except Exception as error:
                    failures.append(str(error))
                    response = {"result": None, "error": {"code": -1, "message": str(error)}, "id": request["id"]}
                body = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        command = [
            self.options.bitcoincli, "-regtest", f"-datadir={datadir}",
            "-rpcconnect=127.0.0.1", f"-rpcport={server.server_address[1]}",
            "-rpcuser=fixture", "-rpcpassword=fixture-only", "-rpcclienttimeout=10",
        ]

        def watch(*args: str, directory: Path = watchdir) -> subprocess.CompletedProcess[str]:
            return subprocess.run(command + [f"-lightwatchdir={directory}", "lightwatch", *args],
                                  capture_output=True, text=True, timeout=15)

        sync: subprocess.Popen[str] | None = None
        try:
            assert_equal(watch("init", "raw(51)", "0").returncode, 0)
            original = (watchdir / "watch.txt").read_bytes()
            sync = subprocess.Popen(command + [f"-lightwatchdir={watchdir}", "lightwatch", "sync"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert waiting.wait(15), "sync did not reach the RPC barrier"
            try:
                self.log.info("A second writer must refuse while sync owns the watch")
                for operation in [("add", "raw(52)"), ("sync",), ("init", "raw(53)")]:
                    other = watch(*operation)
                    assert other.returncode != 0, f"Concurrent writer succeeded: {operation}, {other.stdout}"
                    assert "BTX_LIGHTWATCH_BUSY" in other.stderr, other.stderr
                    assert_equal((watchdir / "watch.txt").read_bytes(), original)

                # Reads and different watch directories must remain usable.
                status = watch("status")
                assert_equal(status.returncode, 0)
                assert_equal(json.loads(status.stdout)["ready"], False)
                assert_equal(watch("init", "raw(53)", directory=datadir / "other-watch").returncode, 0)
            finally:
                release.set()
            stdout, stderr = sync.communicate(timeout=15)
            assert_equal(sync.returncode, 0)
            assert_equal(json.loads(stdout)["ready"], True)
            assert_equal(stderr, "")
            assert_equal(failures, [])

            self.log.info("After sync exits, the descriptor addition succeeds and survives another sync")
            assert_equal(watch("add", "raw(52)").returncode, 0)
            assert_equal(watch("sync").returncode, 0)
            status = watch("status")
            assert_equal(status.returncode, 0)
            assert_equal([d.split("#")[0] for d in json.loads(status.stdout)["descriptors"]],
                         ["raw(51)", "raw(52)"])

            # An error must also release the directory lock for the next process.
            assert watch("add", "not-a-descriptor").returncode != 0
            assert_equal(watch("add", "raw(53)").returncode, 0)
            assert_equal(failures, [])
        finally:
            release.set()
            if sync is not None and sync.poll() is None:
                sync.terminate()
                sync.communicate(timeout=15)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)


if __name__ == "__main__":
    LightWatchConcurrentTest(__file__).main()
