#!/usr/bin/env python3
"""Unit coverage for contrib/faststart/btx-agent-setup.py."""

from __future__ import annotations

import contextlib
import http.client
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "contrib" / "faststart" / "btx-agent-setup.py"


def load_module():
    spec = importlib.util.spec_from_file_location("btx_agent_setup", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BTXAgentSetupTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_detect_platform_id_maps_linux_x86_64(self):
        original_platform = self.module.sys.platform
        original_machine = self.module.platform.machine
        try:
            self.module.sys.platform = "linux"
            self.module.platform.machine = lambda: "x86_64"
            self.assertEqual(self.module.detect_platform_id(), "linux-x86_64")
        finally:
            self.module.sys.platform = original_platform
            self.module.platform.machine = original_machine

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

    def _build_fake_archive(self, root: pathlib.Path) -> pathlib.Path:
        package_root = root / "package"
        bin_dir = package_root / "btx-29.2" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "btxd").write_text("#!/bin/sh\n", encoding="utf-8")
        (bin_dir / "btx-cli").write_text("#!/bin/sh\n", encoding="utf-8")

        archive_path = root / "btx-29.2-x86_64-linux-gnu.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            archive.add(package_root / "btx-29.2", arcname="btx-29.2")
        return archive_path

    def _write_manifest(
        self,
        root: pathlib.Path,
        archive_path: pathlib.Path,
        *,
        include_snapshot_manifest: bool = True,
        include_signature: bool = False,
    ) -> pathlib.Path:
        manifest = {
            "release_tag": "v29.2",
            "checksum_file": "SHA256SUMS",
            "assets": [
                {
                    "name": archive_path.name,
                    "sha256": self.module.sha256_file(archive_path),
                    "size_bytes": archive_path.stat().st_size,
                    "source": "archive",
                },
            ],
            "platform_assets": {
                "linux-x86_64": {
                    "platform_id": "linux-x86_64",
                    "os": "linux",
                    "arch": "x86_64",
                    "asset_name": archive_path.name,
                    "archive_format": "tar.gz",
                    "kind": "primary_binary_archive",
                }
            },
        }
        if include_snapshot_manifest:
            snapshot_manifest = root / "snapshot.manifest.json"
            snapshot_manifest.write_text(
                json.dumps({"chain": "main", "url": "https://example.invalid/snapshot.dat"}),
                encoding="utf-8",
            )
            manifest["snapshot_manifest"] = snapshot_manifest.name
            manifest["assets"].append(
                {
                    "name": snapshot_manifest.name,
                    "sha256": self.module.sha256_file(snapshot_manifest),
                    "size_bytes": snapshot_manifest.stat().st_size,
                    "source": "snapshot_manifest",
                }
            )
        if include_signature:
            signature_path = root / "SHA256SUMS.asc"
            signature_path.write_text("signature\n", encoding="utf-8")
            manifest["signature_file"] = signature_path.name

        manifest_path = root / "btx-release-manifest.json"
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        checksum_lines = [
            f"{self.module.sha256_file(manifest_path)}  {manifest_path.name}",
            f"{self.module.sha256_file(archive_path)}  {archive_path.name}",
        ]
        if include_snapshot_manifest:
            snapshot_manifest = root / "snapshot.manifest.json"
            checksum_lines.append(
                f"{self.module.sha256_file(snapshot_manifest)}  {snapshot_manifest.name}"
            )
        (root / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        return manifest_path

    def _fake_urlopen(self, payloads, recorded_requests):
        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        def fake_urlopen(request):
            if isinstance(request, str):
                url = request
                headers = {}
            else:
                url = request.full_url
                headers = {key.lower(): value for key, value in request.header_items()}
            recorded_requests.append((url, headers))
            if url not in payloads:
                raise AssertionError(f"unexpected urlopen request: {url}")
            return Response(payloads[url])

        return fake_urlopen

    def test_install_from_local_release_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path)
            snapshot_manifest = root / "snapshot.manifest.json"

            install_dir = root / "install"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--release-manifest",
                        str(manifest_path),
                        "--platform",
                        "linux-x86_64",
                        "--install-dir",
                        str(install_dir),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["archive_asset"], archive_path.name)
            self.assertTrue(pathlib.Path(summary["btxd"]).is_file())
            self.assertTrue(pathlib.Path(summary["btx_cli"]).is_file())
            self.assertEqual(
                pathlib.Path(summary["cache_dir"]),
                install_dir.parent / f"{install_dir.name}-agent-setup-cache",
            )
            self.assertEqual(
                pathlib.Path(summary["snapshot_manifest"]).read_text(encoding="utf-8"),
                snapshot_manifest.read_text(encoding="utf-8"),
            )

    def test_cache_dir_help_mentions_sibling_default(self):
        parser = self.module.build_parser()
        cache_action = next(action for action in parser._actions if action.dest == "cache_dir")
        self.assertIn("sibling path next to install_dir", cache_action.help)

    def test_preset_requires_snapshot_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path, include_snapshot_manifest=False)

            with self.assertRaises(KeyError):
                self.module.main(
                    [
                        "--release-manifest",
                        str(manifest_path),
                        "--platform",
                        "linux-x86_64",
                        "--install-dir",
                        str(root / "install"),
                        "--preset",
                        "service",
                    ]
                )

    def test_preset_invokes_faststart_with_forwarded_options(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path)
            install_dir = root / "install"
            datadir = root / "datadir"
            shared_registry = root / "shared" / "matmul_service_challenges.dat"
            recorded: list[tuple[list[str], dict[str, object]]] = []

            original_run = self.module.subprocess.run
            try:
                def fake_run(cmd, check, **kwargs):
                    recorded.append((list(cmd), {"check": check, **kwargs}))
                    class Result:
                        returncode = 0
                        stdout = "boot progress\n"
                        stderr = "bootstrap warning\n"
                    return Result()

                self.module.subprocess.run = fake_run
                output = io.StringIO()
                errors = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    exit_code = self.module.main(
                        [
                            "--release-manifest",
                            str(manifest_path),
                            "--platform",
                            "linux-x86_64",
                            "--install-dir",
                            str(install_dir),
                            "--preset",
                            "service",
                            "--chain",
                            "testnet4",
                            "--datadir",
                            str(datadir),
                            "--matmul-service-challenge-file",
                            str(shared_registry),
                            "--follow",
                            "--keep-snapshot",
                            "--no-start-daemon",
                            "--daemon-arg=-dbcache=2048",
                            "--daemon-arg=-listen=0",
                            "--cli-arg=-rpcwait",
                            "--json",
                        ]
                    )
            finally:
                self.module.subprocess.run = original_run

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(recorded), 1)
            command, run_kwargs = recorded[0]
            self.assertTrue(run_kwargs["check"])
            self.assertTrue(run_kwargs["capture_output"])
            self.assertTrue(run_kwargs["text"])
            self.assertIn("btx-faststart.py", command[1])
            self.assertIn("service", command)
            self.assertIn("--chain=testnet4", command)
            self.assertIn(f"--datadir={datadir}", command)
            self.assertIn(f"--matmul-service-challenge-file={shared_registry}", command)
            self.assertIn("--follow", command)
            self.assertIn("--keep-snapshot", command)
            self.assertIn("--no-start-daemon", command)
            self.assertIn("--daemon-arg=-dbcache=2048", command)
            self.assertIn("--daemon-arg=-listen=0", command)
            self.assertIn("--cli-arg=-rpcwait", command)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["faststart_command"], command)
            self.assertEqual(summary["preset"], "service")
            self.assertEqual(summary["datadir"], str(datadir))
            self.assertEqual(summary["faststart_conf"], str(datadir / "faststart" / "faststart.conf"))
            self.assertEqual(errors.getvalue(), "boot progress\nbootstrap warning\n")

    def test_miner_json_summary_includes_direct_helper_commands(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path)
            install_dir = root / "install"
            datadir = root / "datadir"

            original_run = self.module.subprocess.run
            try:
                def fake_run(cmd, check, **kwargs):
                    class Result:
                        returncode = 0
                        stdout = ""
                        stderr = ""
                    return Result()

                self.module.subprocess.run = fake_run
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = self.module.main(
                        [
                            "--release-manifest",
                            str(manifest_path),
                            "--platform",
                            "linux-x86_64",
                            "--install-dir",
                            str(install_dir),
                            "--preset",
                            "miner",
                            "--chain",
                            "regtest",
                            "--datadir",
                            str(datadir),
                            "--json",
                        ]
                    )
            finally:
                self.module.subprocess.run = original_run

            self.assertEqual(exit_code, 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["preset"], "miner")
            self.assertEqual(summary["faststart_conf"], str(datadir / "faststart" / "faststart.conf"))
            self.assertEqual(summary["mining_results_dir"], str(datadir / "mining-ops"))
            self.assertEqual(
                summary["start_live_mining_command"],
                [
                    str(ROOT / "contrib" / "mining" / "start-live-mining.sh"),
                    f"--datadir={datadir}",
                    f"--conf={datadir / 'faststart' / 'faststart.conf'}",
                    "--chain=regtest",
                    str(f"--cli={pathlib.Path(summary['btx_cli'])}"),
                    str(f"--daemon={pathlib.Path(summary['btxd'])}"),
                    "--wallet=miner",
                    f"--results-dir={datadir / 'mining-ops'}",
                ],
            )
            self.assertEqual(
                summary["stop_live_mining_command"],
                [
                    str(ROOT / "contrib" / "mining" / "stop-live-mining.sh"),
                    f"--results-dir={datadir / 'mining-ops'}",
                ],
            )

    def test_remote_release_requires_signature_unless_overridden(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path)
            manifest_uri = manifest_path.as_uri()

            with self.assertRaisesRegex(KeyError, "signature_file"):
                self.module.main(
                    [
                        "--release-manifest",
                        manifest_uri,
                        "--platform",
                        "linux-x86_64",
                        "--install-dir",
                        str(root / "install"),
                    ]
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = self.module.main(
                    [
                        "--release-manifest",
                        manifest_uri,
                        "--platform",
                        "linux-x86_64",
                        "--install-dir",
                        str(root / "install-unsigned"),
                        "--allow-unsigned-release",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["archive_asset"], archive_path.name)

    def test_remote_release_verifies_signature_when_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path, include_signature=True)
            manifest_uri = manifest_path.as_uri()
            verified: list[tuple[str, str, str]] = []

            original_verify = self.module.verify_checksum_signature
            try:
                def fake_verify(checksum_path, signature_path, gpg_bin):
                    verified.append((checksum_path.name, signature_path.name, gpg_bin))

                self.module.verify_checksum_signature = fake_verify
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = self.module.main(
                        [
                            "--release-manifest",
                            manifest_uri,
                            "--platform",
                            "linux-x86_64",
                            "--install-dir",
                            str(root / "install"),
                            "--json",
                        ]
                    )
            finally:
                self.module.verify_checksum_signature = original_verify

            self.assertEqual(exit_code, 0)
            self.assertEqual(verified, [("SHA256SUMS", "SHA256SUMS.asc", "gpg")])

    def test_repo_release_uses_github_api_asset_downloads_with_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path)
            checksum_path = root / "SHA256SUMS"
            snapshot_manifest_path = root / "snapshot.manifest.json"
            api_prefix = "https://api.github.com/repos/btxchain/btx-node"
            release_url = f"{api_prefix}/releases/tags/v29.2"
            asset_urls = {
                manifest_path.name: f"{api_prefix}/releases/assets/1",
                checksum_path.name: f"{api_prefix}/releases/assets/2",
                archive_path.name: f"{api_prefix}/releases/assets/3",
                snapshot_manifest_path.name: f"{api_prefix}/releases/assets/4",
            }
            payloads = {
                release_url: json.dumps(
                    {
                        "assets": [
                            {"name": asset_name, "url": asset_url}
                            for asset_name, asset_url in asset_urls.items()
                        ]
                    }
                ).encode("utf-8"),
                asset_urls[manifest_path.name]: manifest_path.read_bytes(),
                asset_urls[checksum_path.name]: checksum_path.read_bytes(),
                asset_urls[archive_path.name]: archive_path.read_bytes(),
                asset_urls[snapshot_manifest_path.name]: snapshot_manifest_path.read_bytes(),
            }
            recorded_requests: list[tuple[str, dict[str, str]]] = []
            original_urlopen = self.module.urllib.request.urlopen

            try:
                self.module.urllib.request.urlopen = self._fake_urlopen(payloads, recorded_requests)
                with mock.patch.dict(self.module.os.environ, {"GH_TOKEN": "test-token"}, clear=False):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        exit_code = self.module.main(
                            [
                                "--repo",
                                "btxchain/btx-node",
                                "--release-tag",
                                "v29.2",
                                "--platform",
                                "linux-x86_64",
                                "--install-dir",
                                str(root / "install"),
                                "--allow-unsigned-release",
                                "--json",
                            ]
                        )
            finally:
                self.module.urllib.request.urlopen = original_urlopen

            self.assertEqual(exit_code, 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["archive_asset"], archive_path.name)
            self.assertTrue(pathlib.Path(summary["btxd"]).is_file())
            self.assertTrue(pathlib.Path(summary["snapshot_manifest"]).is_file())
            self.assertEqual(recorded_requests[0][0], release_url)
            self.assertEqual(
                recorded_requests[0][1].get("authorization"),
                "Bearer test-token",
            )
            self.assertEqual(
                recorded_requests[0][1].get("accept"),
                self.module.GITHUB_JSON_ACCEPT,
            )
            asset_requests = [entry for entry in recorded_requests[1:] if "/releases/assets/" in entry[0]]
            self.assertTrue(asset_requests)
            self.assertTrue(all(url.startswith(api_prefix) for url, _ in recorded_requests))
            for _, headers in asset_requests:
                self.assertEqual(headers.get("authorization"), "Bearer test-token")
                self.assertEqual(headers.get("accept"), self.module.GITHUB_BINARY_ACCEPT)
                self.assertEqual(headers.get("user-agent"), "btx-agent-setup.py")
                self.assertEqual(headers.get("x-github-api-version"), "2022-11-28")

    def test_manifest_download_url_infers_github_release_reference_for_private_assets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            manifest_path = self._write_manifest(root, archive_path)
            checksum_path = root / "SHA256SUMS"
            snapshot_manifest_path = root / "snapshot.manifest.json"
            api_prefix = "https://api.github.com/repos/btxchain/btx-node"
            manifest_url = (
                "https://github.com/btxchain/btx-node/releases/download/v29.2/"
                f"{manifest_path.name}"
            )
            release_url = f"{api_prefix}/releases/tags/v29.2"
            asset_urls = {
                manifest_path.name: f"{api_prefix}/releases/assets/11",
                checksum_path.name: f"{api_prefix}/releases/assets/12",
                archive_path.name: f"{api_prefix}/releases/assets/13",
                snapshot_manifest_path.name: f"{api_prefix}/releases/assets/14",
            }
            payloads = {
                release_url: json.dumps(
                    {
                        "assets": [
                            {"name": asset_name, "url": asset_url}
                            for asset_name, asset_url in asset_urls.items()
                        ]
                    }
                ).encode("utf-8"),
                asset_urls[manifest_path.name]: manifest_path.read_bytes(),
                asset_urls[checksum_path.name]: checksum_path.read_bytes(),
                asset_urls[archive_path.name]: archive_path.read_bytes(),
                asset_urls[snapshot_manifest_path.name]: snapshot_manifest_path.read_bytes(),
            }
            recorded_requests: list[tuple[str, dict[str, str]]] = []
            original_urlopen = self.module.urllib.request.urlopen

            try:
                self.module.urllib.request.urlopen = self._fake_urlopen(payloads, recorded_requests)
                with mock.patch.dict(self.module.os.environ, {"GITHUB_TOKEN": "test-token"}, clear=False):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        exit_code = self.module.main(
                            [
                                "--release-manifest",
                                manifest_url,
                                "--platform",
                                "linux-x86_64",
                                "--install-dir",
                                str(root / "install"),
                                "--allow-unsigned-release",
                                "--json",
                            ]
                        )
            finally:
                self.module.urllib.request.urlopen = original_urlopen

            self.assertEqual(exit_code, 0)
            self.assertEqual(recorded_requests[0][0], release_url)
            self.assertTrue(all(url.startswith(api_prefix) for url, _ in recorded_requests))

    def test_github_download_headers_include_binary_asset_headers(self):
        headers = self.module.github_download_headers("secret-token")
        self.assertEqual(headers["Authorization"], "Bearer secret-token")
        self.assertEqual(headers["User-Agent"], "btx-agent-setup.py")
        self.assertEqual(headers["Accept"], self.module.GITHUB_BINARY_ACCEPT)
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")

    def test_download_and_verify_asset_rejects_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source = root / "source.txt"
            source.write_text("hello\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                self.module.download_and_verify_asset(
                    str(source),
                    root / "copied.txt",
                    "00" * 32,
                )

    def test_github_asset_download_falls_back_to_curl_on_remote_disconnect(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            destination = root / "archive.tar.gz"
            recorded: list[list[str]] = []
            original_urlopen = self.module.urllib.request.urlopen
            original_which = self.module.shutil.which
            original_run = self.module.subprocess.run

            try:
                def fake_urlopen(request):
                    raise http.client.RemoteDisconnected("closed")

                def fake_which(name):
                    if name == "curl":
                        return "/usr/bin/curl"
                    return original_which(name)

                def fake_run(cmd, check, **kwargs):
                    recorded.append(list(cmd))
                    temp_path = pathlib.Path(cmd[cmd.index("--output") + 1])
                    temp_path.write_bytes(b"archive-bytes")
                    class Result:
                        returncode = 0
                    return Result()

                self.module.urllib.request.urlopen = fake_urlopen
                self.module.shutil.which = fake_which
                self.module.subprocess.run = fake_run
                output = self.module.download_to_path(
                    "https://api.github.com/repos/btxchain/btx-node/releases/assets/123",
                    destination,
                    headers={"Authorization": "Bearer token", "Accept": "application/octet-stream"},
                )
            finally:
                self.module.urllib.request.urlopen = original_urlopen
                self.module.shutil.which = original_which
                self.module.subprocess.run = original_run

            self.assertEqual(output, destination)
            self.assertEqual(destination.read_bytes(), b"archive-bytes")
            self.assertEqual(recorded[0][0], "/usr/bin/curl")
            self.assertIn("--location", recorded[0])
            self.assertIn("Authorization: Bearer token", recorded[0])

    def test_load_json_source_falls_back_to_curl_for_github_asset_api(self):
        recorded: list[list[str]] = []
        original_urlopen = self.module.urllib.request.urlopen
        original_which = self.module.shutil.which
        original_run = self.module.subprocess.run

        try:
            def fake_urlopen(request):
                raise http.client.RemoteDisconnected("closed")

            def fake_which(name):
                if name == "curl":
                    return "/usr/bin/curl"
                return original_which(name)

            def fake_run(cmd, check, **kwargs):
                recorded.append(list(cmd))
                temp_path = pathlib.Path(cmd[cmd.index("--output") + 1])
                temp_path.write_text('{"release_tag":"v29.2"}', encoding="utf-8")
                class Result:
                    returncode = 0
                return Result()

            self.module.urllib.request.urlopen = fake_urlopen
            self.module.shutil.which = fake_which
            self.module.subprocess.run = fake_run
            payload = self.module.load_json_source(
                "https://api.github.com/repos/btxchain/btx-node/releases/assets/999",
                headers=self.module.github_download_headers("token"),
            )
        finally:
            self.module.urllib.request.urlopen = original_urlopen
            self.module.shutil.which = original_which
            self.module.subprocess.run = original_run

        self.assertEqual(payload["release_tag"], "v29.2")
        self.assertEqual(recorded[0][0], "/usr/bin/curl")

    def test_load_json_source_falls_back_to_curl_for_github_release_api(self):
        recorded: list[list[str]] = []
        original_urlopen = self.module.urllib.request.urlopen
        original_which = self.module.shutil.which
        original_run = self.module.subprocess.run

        try:
            def fake_urlopen(request):
                raise http.client.RemoteDisconnected("closed")

            def fake_which(name):
                if name == "curl":
                    return "/usr/bin/curl"
                return original_which(name)

            def fake_run(cmd, check, **kwargs):
                recorded.append(list(cmd))
                temp_path = pathlib.Path(cmd[cmd.index("--output") + 1])
                temp_path.write_text('{"assets":[]}', encoding="utf-8")
                class Result:
                    returncode = 0
                return Result()

            self.module.urllib.request.urlopen = fake_urlopen
            self.module.shutil.which = fake_which
            self.module.subprocess.run = fake_run
            payload = self.module.load_json_source(
                "https://api.github.com/repos/btxchain/btx-node/releases/tags/v29.2",
                headers=self.module.github_api_headers("token", accept=self.module.GITHUB_JSON_ACCEPT),
            )
        finally:
            self.module.urllib.request.urlopen = original_urlopen
            self.module.shutil.which = original_which
            self.module.subprocess.run = original_run

        self.assertEqual(payload["assets"], [])
        self.assertEqual(recorded[0][0], "/usr/bin/curl")

    def test_extract_archive_supports_zip_and_rejects_unknown_formats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            package_root = root / "zip-package" / "btx-29.2" / "bin"
            package_root.mkdir(parents=True)
            (package_root / "btxd.exe").write_text("binary", encoding="utf-8")
            archive_path = root / "btx-29.2-win64.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.write(package_root / "btxd.exe", arcname="btx-29.2/bin/btxd.exe")

            install_dir = root / "install"
            self.module.extract_archive(archive_path, install_dir)
            self.assertTrue((install_dir / "btx-29.2" / "bin" / "btxd.exe").is_file())

            invalid_archive = root / "btx-29.2.unknown"
            invalid_archive.write_text("not an archive\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported archive format"):
                self.module.extract_archive(invalid_archive, root / "invalid")

    def test_extract_archive_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = root / "unsafe.tar.gz"
            payload = root / "payload.txt"
            payload.write_text("payload\n", encoding="utf-8")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(payload, arcname="../escape.txt")

            with self.assertRaisesRegex(ValueError, "unsafe path"):
                self.module.extract_archive(archive_path, root / "install")

    def test_install_archive_requires_force_to_replace_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            archive_path = self._build_fake_archive(root)
            install_dir = root / "install"
            install_dir.mkdir()
            stale_file = install_dir / "stale.txt"
            stale_file.write_text("old\n", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "Install directory is not empty"):
                self.module.install_archive(archive_path, install_dir, force=False)

            self.module.install_archive(archive_path, install_dir, force=True)
            self.assertFalse(stale_file.exists())
            self.assertTrue(any(path.name == "btxd" for path in install_dir.rglob("btxd")))


if __name__ == "__main__":
    unittest.main()
