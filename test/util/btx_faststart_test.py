#!/usr/bin/env python3
"""Unit coverage for contrib/faststart/btx-faststart.py."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "contrib" / "faststart" / "btx-faststart.py"


def load_module():
    spec = importlib.util.spec_from_file_location("btx_faststart", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BTXFaststartTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_snapshot_from_args_reads_manifest_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            manifest_path = root / "snapshot.manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "chain": "main",
                        "url": "https://example.invalid/snapshot.dat",
                        "snapshot_sha256": "ab" * 32,
                        "height": 60760,
                        "blockhash": "11" * 32,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            args = argparse.Namespace(
                snapshot_url=None,
                snapshot_sha256=None,
                snapshot_name=None,
                snapshot_manifest=str(manifest_path),
                chain="main",
            )
            snapshot_url, snapshot_sha256, snapshot_name, snapshot_entry = self.module.snapshot_from_args(args)

            self.assertEqual(snapshot_url, "https://example.invalid/snapshot.dat")
            self.assertEqual(snapshot_sha256, "ab" * 32)
            self.assertEqual(snapshot_name, "snapshot.dat")
            self.assertEqual(snapshot_entry["height"], 60760)

    def test_write_preset_conf_scopes_non_main_networks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            conf_path = self.module.write_preset_conf(
                root,
                "service",
                "regtest",
                ["txindex=1"],
            )

            text = conf_path.read_text(encoding="utf-8")
            self.assertIn("[regtest]\n", text)
            self.assertIn("rpcbind=127.0.0.1", text)
            self.assertTrue(text.rstrip().endswith("txindex=1"))

    def test_faststart_presets_keep_independent_consensus_on_every_chain(self):
        chains = ("main", "regtest", "testnet", "testnet4", "signet")
        for preset in ("miner", "service"):
            for chain in chains:
                with self.subTest(preset=preset, chain=chain):
                    with tempfile.TemporaryDirectory() as tmpdir:
                        conf_path = self.module.write_preset_conf(
                            pathlib.Path(tmpdir), preset, chain
                        )
                        text = conf_path.read_text(encoding="utf-8")

                    self.assertNotIn("matmulvalidation=trusted", text)
                    self.assertEqual(text.count("matmulvalidation=consensus"), 1)
                    self.assertNotIn("matmultrustedpubkey=", text)
                    self.assertNotIn("matmultrustedthreshold=", text)

    def test_reject_authority_daemon_args_before_launch(self):
        for daemon_arg in (
            "-matmulvalidation=trusted",
            "-matmultrustedpubkey=02aa",
            "-matmultrustedthreshold=1",
        ):
            with self.subTest(daemon_arg=daemon_arg):
                with self.assertRaisesRegex(RuntimeError, "independent|signer authority"):
                    self.module.reject_authority_daemon_args([daemon_arg])

        self.module.reject_authority_daemon_args(["-matmulvalidation=consensus"])

    def test_reject_process_and_config_routing_overrides_before_launch(self):
        for daemon_arg in (
            "-conf=/tmp/other.conf",
            "-datadir=/tmp/other-node",
            "-includeconf=authority.conf",
            "-chain=regtest",
            "-regtest=1",
            "-noregtest",
            "-settings=/tmp/other-settings.json",
        ):
            with self.subTest(daemon_arg=daemon_arg):
                with self.assertRaisesRegex(RuntimeError, "process/config routing"):
                    self.module.reject_authority_daemon_args([daemon_arg])

    def test_verify_independent_policy_rejects_trusted_runtime_override(self):
        with mock.patch.object(
            self.module,
            "rpc_json",
            return_value={"matmulvalidationmode": "trusted"},
        ):
            with self.assertRaisesRegex(RuntimeError, "requires matmulvalidationmode=consensus"):
                self.module.verify_independent_matmul_policy(["btx-cli"])

    def test_verify_independent_policy_rejects_signers_in_consensus_mode(self):
        status = {
            "configured": True,
            "trusted_signer_pubkeys": ["02aa"],
            "threshold": 1,
        }
        with mock.patch.object(
            self.module,
            "rpc_json",
            side_effect=[{"matmulvalidationmode": "consensus"}, status],
        ):
            with self.assertRaisesRegex(RuntimeError, "signer quorums bypass local ExactReplay"):
                self.module.verify_independent_matmul_policy(["btx-cli"])

    def test_verify_independent_policy_accepts_unconfigured_consensus(self):
        status = {
            "configured": False,
            "trusted_signer_pubkeys": [],
            "threshold": 0,
        }
        output = io.StringIO()
        with mock.patch.object(
            self.module,
            "rpc_json",
            side_effect=[{"matmulvalidationmode": "consensus"}, status],
        ), contextlib.redirect_stdout(output):
            self.module.verify_independent_matmul_policy(["btx-cli"])
        self.assertIn("configured=False", output.getvalue())

    def test_main_stops_daemon_it_started_when_runtime_policy_is_unsafe(self):
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(
            self.module,
            "snapshot_from_args",
            return_value=(
                "https://example.invalid/snapshot.dat",
                "ab" * 32,
                "snapshot.dat",
                {},
            ),
        ), mock.patch.object(
            self.module, "require_snapshot_sha256"
        ), mock.patch.object(
            self.module, "run_quiet"
        ), mock.patch.object(
            self.module, "wait_for_rpc_ready"
        ), mock.patch.object(
            self.module,
            "verify_independent_matmul_policy",
            side_effect=RuntimeError("unsafe runtime policy"),
        ), mock.patch.object(
            self.module.subprocess, "run"
        ) as run:
            run.side_effect = [mock.Mock(returncode=1), mock.Mock(returncode=0)]

            with self.assertRaisesRegex(RuntimeError, "unsafe runtime policy"):
                self.module.main(
                    [
                        "service",
                        "--chain=main",
                        f"--datadir={pathlib.Path(tmpdir) / 'node'}",
                    ]
                )

            self.assertEqual(run.call_count, 2)
            cleanup_cmd = run.call_args_list[-1].args[0]
            self.assertEqual(cleanup_cmd[-1], "stop")
            self.assertIn("-rpcconnect=127.0.0.1", cleanup_cmd)

    def test_main_never_routes_started_daemon_cleanup_to_cli_rpc_target(self):
        remote_target = "-rpcconnect=203.0.113.10"
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(
            self.module,
            "snapshot_from_args",
            return_value=(
                "https://example.invalid/snapshot.dat",
                "ab" * 32,
                "snapshot.dat",
                {},
            ),
        ), mock.patch.object(
            self.module, "require_snapshot_sha256"
        ), mock.patch.object(
            self.module, "run_quiet"
        ), mock.patch.object(
            self.module, "wait_for_rpc_ready"
        ), mock.patch.object(
            self.module,
            "verify_independent_matmul_policy",
            side_effect=RuntimeError("unsafe runtime policy"),
        ), mock.patch.object(
            self.module.subprocess, "run"
        ) as run:
            run.side_effect = [mock.Mock(returncode=1), mock.Mock(returncode=0)]

            with self.assertRaisesRegex(RuntimeError, "unsafe runtime policy"):
                self.module.main(
                    [
                        "service",
                        "--chain=main",
                        f"--datadir={pathlib.Path(tmpdir) / 'node'}",
                        f"--cli-arg={remote_target}",
                    ]
                )

            self.assertEqual(run.call_count, 2)
            readiness_cmd = run.call_args_list[0].args[0]
            cleanup_cmd = run.call_args_list[-1].args[0]
            self.assertIn(remote_target, readiness_cmd)
            self.assertEqual(cleanup_cmd[-1], "stop")
            self.assertIn("-rpcconnect=127.0.0.1", cleanup_cmd)
            self.assertNotIn(remote_target, cleanup_cmd)

    def test_local_cleanup_discards_mirrored_rpcconnect(self):
        cleanup_cmd = self.module.local_daemon_cleanup_cmd(
            "btx-cli",
            pathlib.Path("/tmp/local-node"),
            pathlib.Path("/tmp/local-node/faststart/faststart.conf"),
            "main",
            [
                "-rpcconnect=198.51.100.20",
                "-rpcport=21934",
                "-rpcuser=local-user",
            ],
        )

        self.assertEqual(cleanup_cmd[-1], "-rpcconnect=127.0.0.1")
        self.assertIn("-rpcport=21934", cleanup_cmd)
        self.assertIn("-rpcuser=local-user", cleanup_cmd)
        self.assertNotIn("-rpcconnect=198.51.100.20", cleanup_cmd)

    def test_main_does_not_stop_existing_daemon_when_runtime_policy_is_unsafe(self):
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(
            self.module,
            "snapshot_from_args",
            return_value=(
                "https://example.invalid/snapshot.dat",
                "ab" * 32,
                "snapshot.dat",
                {},
            ),
        ), mock.patch.object(
            self.module, "require_snapshot_sha256"
        ), mock.patch.object(
            self.module,
            "verify_independent_matmul_policy",
            side_effect=RuntimeError("unsafe runtime policy"),
        ), mock.patch.object(
            self.module.subprocess, "run", return_value=mock.Mock(returncode=0)
        ) as run:
            with self.assertRaisesRegex(RuntimeError, "unsafe runtime policy"):
                self.module.main(
                    [
                        "service",
                        "--chain=main",
                        f"--datadir={pathlib.Path(tmpdir) / 'node'}",
                    ]
                )

            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args_list[0].args[0][-1], "getblockcount")

    def test_require_snapshot_sha256_rejects_missing_hash_by_default(self):
        with self.assertRaisesRegex(KeyError, "missing snapshot_sha256/sha256"):
            self.module.require_snapshot_sha256(
                "https://example.invalid/snapshot.dat",
                None,
                False,
            )

    def test_validate_snapshot_receipt_checks_base_height(self):
        self.module.validate_snapshot_receipt({"base_height": 60760}, {"height": 60760})

        with self.assertRaisesRegex(RuntimeError, "height mismatch"):
            self.module.validate_snapshot_receipt({"base_height": 60761}, {"height": 60760})

    def test_validate_snapshot_chainstates_checks_snapshot_blockhash(self):
        self.module.validate_snapshot_chainstates(
            {
                "chainstates": [
                    {"blocks": 1, "validated": True},
                    {"blocks": 60760, "snapshot_blockhash": "11" * 32, "validated": False},
                ]
            },
            {"blockhash": "11" * 32},
        )

        with self.assertRaisesRegex(RuntimeError, "blockhash mismatch"):
            self.module.validate_snapshot_chainstates(
                {
                    "chainstates": [
                        {"blocks": 60760, "snapshot_blockhash": "22" * 32, "validated": False},
                    ]
                },
                {"blockhash": "11" * 32},
            )

    def test_wait_for_snapshot_header_returns_when_anchor_blockhash_arrives(self):
        attempts: list[str] = []

        original_run = self.module.subprocess.run
        original_rpc_json = self.module.rpc_json
        original_sleep = self.module.time.sleep
        try:
            def fake_run(cmd, stdout=None, stderr=None, text=None):
                attempts.append(cmd[-1])

                class Result:
                    returncode = 0 if len(attempts) >= 2 else 1

                return Result()

            def fake_rpc_json(cmd, method, *params):
                self.assertEqual(method, "getblockchaininfo")
                return {"headers": 299}

            self.module.subprocess.run = fake_run
            self.module.rpc_json = fake_rpc_json
            self.module.time.sleep = lambda _: None

            self.module.wait_for_snapshot_header(
                ["btx-cli"],
                {"height": 299, "blockhash": "11" * 32},
                2,
            )
        finally:
            self.module.subprocess.run = original_run
            self.module.rpc_json = original_rpc_json
            self.module.time.sleep = original_sleep

        self.assertEqual(attempts, ["11" * 32, "11" * 32])

    def test_wait_for_snapshot_header_times_out_when_height_never_arrives(self):
        original_rpc_json = self.module.rpc_json
        original_time = self.module.time.time
        original_sleep = self.module.time.sleep
        try:
            now = {"value": 0}

            def fake_rpc_json(cmd, method, *params):
                self.assertEqual(method, "getblockchaininfo")
                return {"headers": 42}

            def fake_time():
                now["value"] += 1
                return now["value"]

            self.module.rpc_json = fake_rpc_json
            self.module.time.time = fake_time
            self.module.time.sleep = lambda _: None

            with self.assertRaisesRegex(TimeoutError, "snapshot anchor header"):
                self.module.wait_for_snapshot_header(
                    ["btx-cli"],
                    {"height": 299},
                    2,
                )
        finally:
            self.module.rpc_json = original_rpc_json
            self.module.time.time = original_time
            self.module.time.sleep = original_sleep

    def test_mirrored_cli_rpc_args_copies_rpc_connection_overrides(self):
        mirrored = self.module.mirrored_cli_rpc_args(
            [
                "-listen=0",
                "-rpcport=18445",
                "-rpcuser=alice",
                "-rpcpassword=secret",
                "-addnode=127.0.0.1:18444",
            ]
        )

        self.assertEqual(
            mirrored,
            [
                "-rpcport=18445",
                "-rpcuser=alice",
                "-rpcpassword=secret",
            ],
        )

    def test_snapshot_superseded_by_active_chain_matches_anchor_blockhash(self):
        original_run = self.module.subprocess.run
        try:
            def fake_run(cmd, capture_output=False, text=False):
                class Result:
                    if cmd[-2] == "getblockhash":
                        returncode = 0
                        stdout = "11" * 32 + "\n"
                    else:
                        returncode = 0
                        stdout = "319\n"

                return Result()

            self.module.subprocess.run = fake_run

            self.assertTrue(
                self.module.snapshot_superseded_by_active_chain(
                    ["btx-cli"],
                    {"height": 299, "blockhash": "11" * 32},
                )
            )
        finally:
            self.module.subprocess.run = original_run

    def test_snapshot_superseded_by_active_chain_falls_back_to_height(self):
        original_run = self.module.subprocess.run
        try:
            def fake_run(cmd, capture_output=False, text=False):
                class Result:
                    if cmd[-2] == "getblockhash":
                        returncode = 1
                        stdout = ""
                    else:
                        returncode = 0
                        stdout = "319\n"

                return Result()

            self.module.subprocess.run = fake_run

            self.assertTrue(
                self.module.snapshot_superseded_by_active_chain(
                    ["btx-cli"],
                    {"height": 299},
                )
            )
        finally:
            self.module.subprocess.run = original_run

    def test_github_token_from_env_prefers_btx_github_token(self):
        with mock.patch.dict(
            self.module.os.environ,
            {
                "GH_TOKEN": "gh-token",
                "GITHUB_TOKEN": "github-token",
                "BTX_GITHUB_TOKEN": "btx-token",
            },
            clear=False,
        ):
            self.assertEqual(self.module.github_token_from_env(), "btx-token")

    def test_snapshot_manifest_download_uses_github_asset_api_with_token(self):
        manifest_url = "https://github.com/example/btx/releases/download/v29.2/snapshot.manifest.json"
        release_url = "https://api.github.com/repos/example/btx/releases/tags/v29.2"
        asset_url = "https://api.github.com/repos/example/btx/releases/assets/1"
        recorded_requests: list[tuple[str, dict[str, str]]] = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        payloads = {
            release_url: json.dumps(
                {
                    "assets": [
                        {
                            "name": "snapshot.manifest.json",
                            "url": asset_url,
                            "browser_download_url": manifest_url,
                        }
                    ]
                }
            ).encode("utf-8"),
            asset_url: b'{"main":{"url":"https://example.invalid/snapshot.dat","sha256":"' + (b"ab" * 32) + b'"}}\n',
        }

        def fake_urlopen(request):
            if isinstance(request, str):
                url = request
                headers: dict[str, str] = {}
            else:
                url = request.full_url
                headers = {key.lower(): value for key, value in request.header_items()}
            recorded_requests.append((url, headers))
            return Response(payloads[url])

        original_urlopen = self.module.urllib.request.urlopen
        try:
            self.module.urllib.request.urlopen = fake_urlopen
            with mock.patch.dict(self.module.os.environ, {"GH_TOKEN": "test-token"}, clear=False):
                resolved_manifest_url, manifest_headers = self.module.github_release_headers(manifest_url)
                manifest = self.module.load_json_source(
                    resolved_manifest_url,
                    headers=manifest_headers,
                )
        finally:
            self.module.urllib.request.urlopen = original_urlopen

        self.assertEqual(manifest["main"]["url"], "https://example.invalid/snapshot.dat")
        self.assertEqual(recorded_requests[0][0], release_url)
        self.assertEqual(recorded_requests[0][1].get("authorization"), "Bearer test-token")
        self.assertEqual(recorded_requests[0][1].get("accept"), self.module.GITHUB_JSON_ACCEPT)
        self.assertEqual(recorded_requests[1][0], asset_url)
        self.assertEqual(recorded_requests[1][1].get("authorization"), "Bearer test-token")
        self.assertEqual(recorded_requests[1][1].get("accept"), self.module.GITHUB_BINARY_ACCEPT)

    def test_download_snapshot_uses_github_asset_api_with_token(self):
        snapshot_url = "https://github.com/example/btx/releases/download/v29.2/snapshot.dat"
        release_url = "https://api.github.com/repos/example/btx/releases/tags/v29.2"
        asset_url = "https://api.github.com/repos/example/btx/releases/assets/2"
        snapshot_bytes = b"snapshot-bytes\n"
        recorded_requests: list[tuple[str, dict[str, str]]] = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        payloads = {
            release_url: json.dumps(
                {
                    "assets": [
                        {
                            "name": "snapshot.dat",
                            "url": asset_url,
                            "browser_download_url": snapshot_url,
                        }
                    ]
                }
            ).encode("utf-8"),
            asset_url: snapshot_bytes,
        }

        def fake_urlopen(request):
            if isinstance(request, str):
                url = request
                headers: dict[str, str] = {}
            else:
                url = request.full_url
                headers = {key.lower(): value for key, value in request.header_items()}
            recorded_requests.append((url, headers))
            return Response(payloads[url])

        original_urlopen = self.module.urllib.request.urlopen
        try:
            self.module.urllib.request.urlopen = fake_urlopen
            with mock.patch.dict(self.module.os.environ, {"BTX_GITHUB_TOKEN": "test-token"}, clear=False):
                with tempfile.TemporaryDirectory() as tmpdir:
                    destination = pathlib.Path(tmpdir) / "snapshot.dat"
                    self.module.download_snapshot(
                        snapshot_url,
                        destination,
                        self.module.hashlib.sha256(snapshot_bytes).hexdigest(),
                    )
                    self.assertEqual(destination.read_bytes(), snapshot_bytes)
        finally:
            self.module.urllib.request.urlopen = original_urlopen

        self.assertEqual(recorded_requests[0][0], release_url)
        self.assertEqual(recorded_requests[0][1].get("accept"), self.module.GITHUB_JSON_ACCEPT)
        self.assertEqual(recorded_requests[1][0], asset_url)
        self.assertEqual(recorded_requests[1][1].get("accept"), self.module.GITHUB_BINARY_ACCEPT)

    def test_download_snapshot_falls_back_to_curl_for_github_asset_disconnect(self):
        original_open_url = self.module.open_url
        original_download_with_curl = self.module.download_with_curl
        original_github_release_headers = self.module.github_release_headers

        try:
            def fake_open_url(source, *, headers=None):
                raise http.client.RemoteDisconnected("closed")

            recorded: list[tuple[str, pathlib.Path, dict[str, str]]] = []

            def fake_download_with_curl(source, destination, headers):
                recorded.append((source, destination, headers))
                destination.write_bytes(b"snapshot-bytes\n")
                return destination

            self.module.open_url = fake_open_url
            self.module.download_with_curl = fake_download_with_curl
            self.module.github_release_headers = lambda _source: (
                "https://api.github.com/repos/example/btx/releases/assets/2",
                self.module.github_api_headers("test-token", accept=self.module.GITHUB_BINARY_ACCEPT),
            )
            with tempfile.TemporaryDirectory() as tmpdir:
                destination = pathlib.Path(tmpdir) / "snapshot.dat"
                self.module.download_snapshot(
                    "https://github.com/example/btx/releases/download/v29.2/snapshot.dat",
                    destination,
                    self.module.hashlib.sha256(b"snapshot-bytes\n").hexdigest(),
                )
                self.assertEqual(destination.read_bytes(), b"snapshot-bytes\n")
        finally:
            self.module.open_url = original_open_url
            self.module.download_with_curl = original_download_with_curl
            self.module.github_release_headers = original_github_release_headers

        self.assertEqual(len(recorded), 1)
        self.assertEqual(
            recorded[0][0],
            "https://api.github.com/repos/example/btx/releases/assets/2",
        )
        self.assertEqual(recorded[0][2]["Accept"], self.module.GITHUB_BINARY_ACCEPT)
        self.assertEqual(recorded[0][2]["Authorization"], "Bearer test-token")

    def test_snapshot_from_args_uses_logical_release_download_url_for_filename_only_manifest(self):
        manifest_url = "https://github.com/example/btx/releases/download/v29.2/snapshot.manifest.json"
        original_github_release_headers = self.module.github_release_headers
        original_load_json_source = self.module.load_json_source
        try:
            self.module.github_release_headers = lambda source: (
                "https://api.github.com/repos/example/btx/releases/assets/1",
                self.module.github_api_headers("test-token", accept=self.module.GITHUB_BINARY_ACCEPT),
            )
            self.module.load_json_source = lambda source, headers=None: {
                "chain": "main",
                "filename": "snapshot.dat",
                "sha256": "ab" * 32,
            }
            args = argparse.Namespace(
                snapshot_url=None,
                snapshot_sha256=None,
                snapshot_name=None,
                snapshot_manifest=manifest_url,
                chain="main",
            )
            snapshot_url, snapshot_sha256, snapshot_name, snapshot_entry = self.module.snapshot_from_args(args)
        finally:
            self.module.github_release_headers = original_github_release_headers
            self.module.load_json_source = original_load_json_source

        self.assertEqual(
            snapshot_url,
            "https://github.com/example/btx/releases/download/v29.2/snapshot.dat",
        )
        self.assertEqual(snapshot_sha256, "ab" * 32)
        self.assertEqual(snapshot_name, "snapshot.dat")
        self.assertEqual(snapshot_entry["filename"], "snapshot.dat")

    def test_main_skips_loadtxoutset_when_snapshot_is_already_superseded(self):
        original_run = self.module.subprocess.run
        original_snapshot_from_args = self.module.snapshot_from_args
        original_require_snapshot_sha256 = self.module.require_snapshot_sha256
        original_download_snapshot = self.module.download_snapshot
        original_wait_for_snapshot_header = self.module.wait_for_snapshot_header
        original_snapshot_superseded_by_active_chain = self.module.snapshot_superseded_by_active_chain
        original_monitor_chainstates = self.module.monitor_chainstates
        original_rpc_json = self.module.rpc_json
        original_verify_independent_matmul_policy = self.module.verify_independent_matmul_policy
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                datadir = pathlib.Path(tmpdir) / "node"
                seen_methods: list[str] = []

                class Result:
                    returncode = 0

                self.module.subprocess.run = lambda *args, **kwargs: Result()
                self.module.snapshot_from_args = (
                    lambda _args: (
                        "https://example.invalid/snapshot.dat",
                        "ab" * 32,
                        "snapshot.dat",
                        {"height": 299, "blockhash": "11" * 32},
                    )
                )
                self.module.require_snapshot_sha256 = lambda *args, **kwargs: None
                self.module.download_snapshot = (
                    lambda _url, destination, _sha256: destination.write_text("snapshot", encoding="utf-8")
                )
                self.module.wait_for_snapshot_header = lambda *args, **kwargs: None
                self.module.snapshot_superseded_by_active_chain = lambda *args, **kwargs: True
                self.module.monitor_chainstates = lambda *args, **kwargs: None
                self.module.verify_independent_matmul_policy = lambda *args, **kwargs: None

                def fake_rpc_json(_cmd, method, *params):
                    seen_methods.append(method)
                    return {}

                self.module.rpc_json = fake_rpc_json

                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = self.module.main(
                        [
                            "service",
                            "--chain=regtest",
                            f"--datadir={datadir}",
                        ]
                    )

                self.assertEqual(exit_code, 0)
                self.assertNotIn("loadtxoutset", seen_methods)
                self.assertIn("skipping loadtxoutset", stdout.getvalue())
                self.assertTrue((datadir / "faststart" / "snapshot.dat").exists())
        finally:
            self.module.subprocess.run = original_run
            self.module.snapshot_from_args = original_snapshot_from_args
            self.module.require_snapshot_sha256 = original_require_snapshot_sha256
            self.module.download_snapshot = original_download_snapshot
            self.module.wait_for_snapshot_header = original_wait_for_snapshot_header
            self.module.snapshot_superseded_by_active_chain = original_snapshot_superseded_by_active_chain
            self.module.monitor_chainstates = original_monitor_chainstates
            self.module.rpc_json = original_rpc_json
            self.module.verify_independent_matmul_policy = original_verify_independent_matmul_policy

    def test_main_treats_mid_load_snapshot_supersession_as_non_fatal(self):
        original_run = self.module.subprocess.run
        original_snapshot_from_args = self.module.snapshot_from_args
        original_require_snapshot_sha256 = self.module.require_snapshot_sha256
        original_download_snapshot = self.module.download_snapshot
        original_wait_for_snapshot_header = self.module.wait_for_snapshot_header
        original_snapshot_superseded_by_active_chain = self.module.snapshot_superseded_by_active_chain
        original_monitor_chainstates = self.module.monitor_chainstates
        original_rpc_json = self.module.rpc_json
        original_verify_independent_matmul_policy = self.module.verify_independent_matmul_policy
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                datadir = pathlib.Path(tmpdir) / "node"

                class Result:
                    returncode = 0

                self.module.subprocess.run = lambda *args, **kwargs: Result()
                self.module.snapshot_from_args = (
                    lambda _args: (
                        "https://example.invalid/snapshot.dat",
                        "ab" * 32,
                        "snapshot.dat",
                        {"height": 299, "blockhash": "11" * 32},
                    )
                )
                self.module.require_snapshot_sha256 = lambda *args, **kwargs: None
                self.module.download_snapshot = (
                    lambda _url, destination, _sha256: destination.write_text("snapshot", encoding="utf-8")
                )
                self.module.wait_for_snapshot_header = lambda *args, **kwargs: None
                self.module.snapshot_superseded_by_active_chain = lambda *args, **kwargs: False
                self.module.monitor_chainstates = lambda *args, **kwargs: None
                self.module.verify_independent_matmul_policy = lambda *args, **kwargs: None

                def fake_rpc_json(_cmd, method, *params):
                    if method == "loadtxoutset":
                        raise RuntimeError(
                            "loadtxoutset failed:\nerror code: -32603\nerror message:\n"
                            "Unable to load UTXO snapshot: Population failed: Work does not exceed active chainstate."
                        )
                    return {}

                self.module.rpc_json = fake_rpc_json

                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = self.module.main(
                        [
                            "service",
                            "--chain=regtest",
                            f"--datadir={datadir}",
                        ]
                    )

                self.assertEqual(exit_code, 0)
                self.assertIn("during loadtxoutset; continuing", stdout.getvalue())
                self.assertTrue((datadir / "faststart" / "snapshot.dat").exists())
        finally:
            self.module.subprocess.run = original_run
            self.module.snapshot_from_args = original_snapshot_from_args
            self.module.require_snapshot_sha256 = original_require_snapshot_sha256
            self.module.download_snapshot = original_download_snapshot
            self.module.wait_for_snapshot_header = original_wait_for_snapshot_header
            self.module.snapshot_superseded_by_active_chain = original_snapshot_superseded_by_active_chain
            self.module.monitor_chainstates = original_monitor_chainstates
            self.module.rpc_json = original_rpc_json
            self.module.verify_independent_matmul_policy = original_verify_independent_matmul_policy


if __name__ == "__main__":
    unittest.main()
