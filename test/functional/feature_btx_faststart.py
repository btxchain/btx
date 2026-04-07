#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Functional coverage for BTX fast-start bootstrap and installer handoff."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
    rpc_port,
)


class BTXFaststartFunctionalTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.rpc_timeout = 120

    def sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def src_dir(self) -> Path:
        return Path(self.config["environment"]["SRCDIR"])

    def build_dir(self) -> Path:
        return Path(self.config["environment"]["BUILDDIR"])

    def exeext(self) -> str:
        return self.config["environment"]["EXEEXT"]

    def build_btxd(self) -> Path:
        return self.build_dir() / "bin" / f"btxd{self.exeext()}"

    def build_btx_cli(self) -> Path:
        return self.build_dir() / "bin" / f"btx-cli{self.exeext()}"

    def cli_cmd(
        self,
        cli_path: Path,
        datadir: Path,
        conf_path: Path,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        args = [
            str(cli_path),
            f"-datadir={datadir}",
            f"-conf={conf_path}",
            "-chain=regtest",
            "-rpcclienttimeout=0",
        ]
        if extra_args:
            args.extend(extra_args)
        return args

    def cli_json(
        self,
        cli_path: Path,
        datadir: Path,
        conf_path: Path,
        method: str,
        *params: str,
        extra_args: list[str] | None = None,
    ):
        output = subprocess.check_output(
            [*self.cli_cmd(cli_path, datadir, conf_path, extra_args), method, *params],
            text=True,
        )
        return json.loads(output)

    def stop_external_node(
        self,
        cli_path: Path,
        datadir: Path,
        conf_path: Path,
        extra_args: list[str] | None = None,
    ) -> None:
        subprocess.run(
            [*self.cli_cmd(cli_path, datadir, conf_path, extra_args), "stop"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.wait_until(
            lambda: subprocess.run(
                [*self.cli_cmd(cli_path, datadir, conf_path, extra_args), "getblockcount"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            ).returncode != 0
        )

    def wait_for_chainstate_blocks(
        self,
        cli_path: Path,
        datadir: Path,
        conf_path: Path,
        expected_blocks: int,
        extra_args: list[str] | None = None,
    ) -> dict[str, object]:
        self.wait_until(
            lambda: self.cli_json(
                cli_path,
                datadir,
                conf_path,
                "getchainstates",
                extra_args=extra_args,
            )["chainstates"][0]["blocks"] == expected_blocks
        )
        return self.cli_json(
            cli_path,
            datadir,
            conf_path,
            "getchainstates",
            extra_args=extra_args,
        )

    def detect_platform_id(self) -> str:
        machine = platform.machine().lower()
        if sys.platform.startswith("linux"):
            if machine in {"x86_64", "amd64"}:
                return "linux-x86_64"
            if machine in {"aarch64", "arm64"}:
                return "linux-arm64"
        if sys.platform == "darwin":
            if machine in {"x86_64", "amd64"}:
                return "macos-x86_64"
            if machine in {"arm64", "aarch64"}:
                return "macos-arm64"
        raise AssertionError(f"Unsupported functional-test platform: {sys.platform} {machine}")

    def build_release_archive(self, bundle_dir: Path, platform_id: str) -> Path:
        output = subprocess.check_output(
            [
                sys.executable,
                str(self.src_dir() / "scripts" / "release" / "package_release_archive.py"),
                f"--output-dir={bundle_dir}",
                "--version=29.2",
                f"--platform-id={platform_id}",
                f"--btxd={self.build_btxd()}",
                f"--btx-cli={self.build_btx_cli()}",
                f"--source-root={self.src_dir()}",
            ],
            text=True,
        )
        summary = json.loads(output)
        return Path(summary["archive_path"])

    def write_snapshot_manifest(self, manifest_path: Path, snapshot_path: Path, dump_output: dict[str, object]) -> None:
        manifest = {
            "format_version": 1,
            "chain": "regtest",
            "snapshot_type": "latest",
            "filename": snapshot_path.name,
            "published_name": snapshot_path.name,
            "url": snapshot_path.as_uri(),
            "asset_url": snapshot_path.as_uri(),
            "height": dump_output["base_height"],
            "blockhash": dump_output["base_hash"],
            "snapshot_sha256": self.sha256_file(snapshot_path),
            "sha256": self.sha256_file(snapshot_path),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    def stage_release_bundle(
        self,
        bundle_dir: Path,
        snapshot_path: Path,
        dump_output: dict[str, object],
        platform_id: str,
    ) -> Path:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        archive_path = self.build_release_archive(bundle_dir, platform_id)
        bundled_snapshot = bundle_dir / "snapshot.dat"
        bundled_snapshot.write_bytes(snapshot_path.read_bytes())
        snapshot_manifest_path = bundle_dir / "snapshot.manifest.json"
        self.write_snapshot_manifest(snapshot_manifest_path, bundled_snapshot, dump_output)

        manifest_path = bundle_dir / "btx-release-manifest.json"
        manifest = {
            "release_tag": "v29.2-faststart-test",
            "checksum_file": "SHA256SUMS",
            "snapshot_manifest": snapshot_manifest_path.name,
            "assets": [
                {
                    "name": archive_path.name,
                    "sha256": self.sha256_file(archive_path),
                    "size_bytes": archive_path.stat().st_size,
                    "source": "archive",
                },
                {
                    "name": snapshot_manifest_path.name,
                    "sha256": self.sha256_file(snapshot_manifest_path),
                    "size_bytes": snapshot_manifest_path.stat().st_size,
                    "source": "snapshot_manifest",
                },
                {
                    "name": bundled_snapshot.name,
                    "sha256": self.sha256_file(bundled_snapshot),
                    "size_bytes": bundled_snapshot.stat().st_size,
                    "source": "snapshot",
                },
            ],
            "platform_assets": {
                platform_id: {
                    "platform_id": platform_id,
                    "os": platform_id.split("-", 1)[0],
                    "arch": platform_id.split("-", 1)[1],
                    "asset_name": archive_path.name,
                    "archive_format": "tar.gz",
                    "kind": "primary_binary_archive",
                }
            },
        }
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        checksum_lines = [
            f"{self.sha256_file(manifest_path)}  {manifest_path.name}",
            f"{self.sha256_file(archive_path)}  {archive_path.name}",
            f"{self.sha256_file(snapshot_manifest_path)}  {snapshot_manifest_path.name}",
            f"{self.sha256_file(bundled_snapshot)}  {bundled_snapshot.name}",
        ]
        (bundle_dir / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        return manifest_path

    def test_faststart_wrapper(self, snapshot_path: Path, dump_output: dict[str, object], source_height: int) -> None:
        manifest_path = Path(self.options.tmpdir) / "faststart-wrapper-snapshot.manifest.json"
        self.write_snapshot_manifest(manifest_path, snapshot_path, dump_output)

        datadir = Path(self.options.tmpdir) / "faststart-wrapper-node"
        conf_path = datadir / "faststart" / "faststart.conf"
        wrapper_rpc_port = rpc_port(2)
        cmd = [
            sys.executable,
            str(self.src_dir() / "contrib" / "faststart" / "btx-faststart.py"),
            "service",
            "--chain=regtest",
            f"--datadir={datadir}",
            f"--snapshot-manifest={manifest_path}",
            f"--btxd={self.build_btxd()}",
            f"--btx-cli={self.build_btx_cli()}",
            "--poll-secs=1",
            "--rpc-wait-secs=60",
            "--header-wait-secs=60",
            f"--daemon-arg=-addnode=127.0.0.1:{p2p_port(0)}",
            "--daemon-arg=-listen=0",
            f"--daemon-arg=-rpcport={wrapper_rpc_port}",
        ]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        self.log.info(result.stdout)
        assert (
            "loadtxoutset result:" in result.stdout
            or "snapshot already superseded by active chainstate" in result.stdout
        )
        assert "chainstate bootstrap complete" in result.stdout
        assert not (datadir / "faststart" / snapshot_path.name).exists()
        conf_text = conf_path.read_text(encoding="utf-8")
        assert "txindex=1" in conf_text
        assert "retainshieldedcommitmentindex=1" in conf_text

        chainstates = self.wait_for_chainstate_blocks(
            self.build_btx_cli(),
            datadir,
            conf_path,
            source_height,
            extra_args=[f"-rpcport={wrapper_rpc_port}"],
        )
        assert_equal(len(chainstates["chainstates"]), 1)
        assert_equal(chainstates["chainstates"][0]["blocks"], source_height)
        self.stop_external_node(
            self.build_btx_cli(),
            datadir,
            conf_path,
            extra_args=[f"-rpcport={wrapper_rpc_port}"],
        )

    def test_agent_setup_handoff(self, snapshot_path: Path, dump_output: dict[str, object], source_height: int) -> None:
        platform_id = self.detect_platform_id()
        bundle_dir = Path(self.options.tmpdir) / "faststart-release-bundle"
        manifest_path = self.stage_release_bundle(bundle_dir, snapshot_path, dump_output, platform_id)

        install_dir = Path(self.options.tmpdir) / "agent-install"
        datadir = Path(self.options.tmpdir) / "agent-datadir"
        conf_path = datadir / "faststart" / "faststart.conf"
        agent_rpc_port = rpc_port(3)
        cmd = [
            sys.executable,
            str(self.src_dir() / "contrib" / "faststart" / "btx-agent-setup.py"),
            f"--release-manifest={manifest_path}",
            f"--asset-base-url={bundle_dir}",
            f"--platform={platform_id}",
            f"--install-dir={install_dir}",
            "--preset=service",
            "--chain=regtest",
            f"--datadir={datadir}",
            f"--daemon-arg=-addnode=127.0.0.1:{p2p_port(0)}",
            "--daemon-arg=-listen=0",
            f"--daemon-arg=-rpcport={agent_rpc_port}",
        ]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        self.log.info(result.stdout)
        assert (
            "loadtxoutset result:" in result.stdout
            or "snapshot already superseded by active chainstate" in result.stdout
        )
        assert "bootstrapped preset: service" in result.stdout
        assert install_dir.is_dir()
        cache_dir = install_dir.parent / f"{install_dir.name}-agent-setup-cache"
        assert cache_dir.is_dir()

        installed_cli = next(install_dir.rglob(f"btx-cli{self.exeext()}"))
        installed_btxd = next(install_dir.rglob(f"btxd{self.exeext()}"))
        assert installed_cli.is_file()
        assert installed_btxd.is_file()

        chainstates = self.wait_for_chainstate_blocks(
            installed_cli,
            datadir,
            conf_path,
            source_height,
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )
        assert_equal(len(chainstates["chainstates"]), 1)
        assert_equal(chainstates["chainstates"][0]["blocks"], source_height)
        self.stop_external_node(
            installed_cli,
            datadir,
            conf_path,
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )

    def test_miner_setup_handoff(self, snapshot_path: Path, dump_output: dict[str, object], source_height: int) -> None:
        platform_id = self.detect_platform_id()
        bundle_dir = Path(self.options.tmpdir) / "faststart-release-bundle-miner"
        manifest_path = self.stage_release_bundle(bundle_dir, snapshot_path, dump_output, platform_id)

        install_dir = Path(self.options.tmpdir) / "agent-install-miner"
        datadir = Path(self.options.tmpdir) / "agent-datadir-miner"
        conf_path = datadir / "faststart" / "faststart.conf"
        agent_rpc_port = rpc_port(4)
        cmd = [
            sys.executable,
            str(self.src_dir() / "contrib" / "faststart" / "btx-agent-setup.py"),
            f"--release-manifest={manifest_path}",
            f"--asset-base-url={bundle_dir}",
            f"--platform={platform_id}",
            f"--install-dir={install_dir}",
            "--preset=miner",
            "--chain=regtest",
            f"--datadir={datadir}",
            f"--daemon-arg=-addnode=127.0.0.1:{p2p_port(0)}",
            "--daemon-arg=-listen=0",
            f"--daemon-arg=-rpcport={agent_rpc_port}",
            "--daemon-arg=-miningminoutboundpeers=0",
            "--daemon-arg=-miningminsyncedoutboundpeers=0",
        ]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        self.log.info(result.stdout)
        assert "bootstrapped preset: miner" in result.stdout

        installed_cli = next(install_dir.rglob(f"btx-cli{self.exeext()}"))
        installed_btxd = next(install_dir.rglob(f"btxd{self.exeext()}"))
        assert installed_cli.is_file()
        assert installed_btxd.is_file()

        chainstates = self.wait_for_chainstate_blocks(
            installed_cli,
            datadir,
            conf_path,
            source_height,
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )
        assert_equal(len(chainstates["chainstates"]), 1)
        assert_equal(chainstates["chainstates"][0]["blocks"], source_height)

        mining_results = datadir / "mining-ops"
        allow_file = Path(self.options.tmpdir) / "allow-live-mining"
        gate_script = Path(self.options.tmpdir) / "should-mine.sh"
        gate_script.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"test -f '{allow_file}'\n",
            encoding="utf-8",
        )
        gate_script.chmod(0o755)

        env = os.environ.copy()
        env["BTX_MINING_CLI"] = str(installed_cli)
        env["BTX_MINING_DAEMON"] = str(installed_btxd)
        env["BTX_MINING_RPC_RESTART_THRESHOLD"] = "2"
        env["BTX_MINING_RESTART_COOLDOWN_SECS"] = "0"
        env["BTX_MINING_STARTUP_GRACE_SECS"] = "0"
        start_result = subprocess.run(
            [
                str(self.src_dir() / "contrib" / "mining" / "start-live-mining.sh"),
                f"--datadir={datadir}",
                f"--conf={conf_path}",
                "--chain=regtest",
                f"--rpcport={agent_rpc_port}",
                "--wallet=miner",
                f"--results-dir={mining_results}",
                f"--should-mine-command={gate_script}",
            ],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.log.info(start_result.stdout)
        assert "Provisioned mining wallet/address" in start_result.stdout
        assert "Started live mining loop" in start_result.stdout

        pidfile = mining_results / "live-mining-loop.pid"
        health_log = mining_results / "live-mining-health.log"
        address_file = mining_results / "miner-mining-address.txt"
        self.wait_until(lambda: pidfile.exists())
        self.wait_until(lambda: address_file.exists())
        self.wait_until(
            lambda: "miner" in self.cli_json(
                installed_cli,
                datadir,
                conf_path,
                "listwallets",
                extra_args=[f"-rpcport={agent_rpc_port}"],
            )
        )
        self.wait_until(
            lambda: health_log.exists() and "idle-gate-pause" in health_log.read_text(encoding="utf-8")
        )

        blocked_height = self.cli_json(
            installed_cli,
            datadir,
            conf_path,
            "getblockcount",
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )
        time.sleep(2)
        assert_equal(
            self.cli_json(
                installed_cli,
                datadir,
                conf_path,
                "getblockcount",
                extra_args=[f"-rpcport={agent_rpc_port}"],
            ),
            blocked_height,
        )

        allow_file.touch()
        self.wait_until(
            lambda: self.cli_json(
                installed_cli,
                datadir,
                conf_path,
                "getblockcount",
                extra_args=[f"-rpcport={agent_rpc_port}"],
            ) > blocked_height
        )
        mined_height = self.cli_json(
            installed_cli,
            datadir,
            conf_path,
            "getblockcount",
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )
        assert mined_height > blocked_height
        self.wait_until(lambda: "idle-gate-open" in health_log.read_text(encoding="utf-8"))

        subprocess.run(
            [*self.cli_cmd(installed_cli, datadir, conf_path, [f"-rpcport={agent_rpc_port}"]), "stop"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.wait_until(
            lambda: "restarting-node reason=rpc_unavailable" in health_log.read_text(encoding="utf-8")
        )
        self.wait_until(
            lambda: "restart-complete reason=rpc_unavailable" in health_log.read_text(encoding="utf-8")
        )
        self.wait_until(
            lambda: subprocess.run(
                [*self.cli_cmd(installed_cli, datadir, conf_path, [f"-rpcport={agent_rpc_port}"]), "getblockcount"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            ).returncode == 0
        )
        self.wait_until(
            lambda: "miner" in self.cli_json(
                installed_cli,
                datadir,
                conf_path,
                "listwallets",
                extra_args=[f"-rpcport={agent_rpc_port}"],
            )
        )
        self.wait_until(
            lambda: self.cli_json(
                installed_cli,
                datadir,
                conf_path,
                "getblockcount",
                extra_args=[f"-rpcport={agent_rpc_port}"],
            ) > mined_height
        )
        restarted_height = self.cli_json(
            installed_cli,
            datadir,
            conf_path,
            "getblockcount",
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )
        assert restarted_height > mined_height

        allow_file.unlink()
        self.wait_until(
            lambda: health_log.exists() and health_log.read_text(encoding="utf-8").count("idle-gate-pause") >= 2
        )
        time.sleep(2)
        paused_height = self.cli_json(
            installed_cli,
            datadir,
            conf_path,
            "getblockcount",
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )
        time.sleep(2)
        assert_equal(
            self.cli_json(
                installed_cli,
                datadir,
                conf_path,
                "getblockcount",
                extra_args=[f"-rpcport={agent_rpc_port}"],
            ),
            paused_height,
        )

        stop_result = subprocess.run(
            [
                str(self.src_dir() / "contrib" / "mining" / "stop-live-mining.sh"),
                f"--results-dir={mining_results}",
            ],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.log.info(stop_result.stdout)
        assert "Stopped live mining loop" in stop_result.stdout
        self.wait_until(lambda: not pidfile.exists())

        still_running_height = self.cli_json(
            installed_cli,
            datadir,
            conf_path,
            "getblockcount",
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )
        assert still_running_height >= paused_height

        self.stop_external_node(
            installed_cli,
            datadir,
            conf_path,
            extra_args=[f"-rpcport={agent_rpc_port}"],
        )

    def run_test(self):
        source = self.nodes[0]

        self.log.info("Extending cached regtest chain to the canned assumeutxo height")
        current_height = source.getblockcount()
        assert current_height < 299
        self.generate(source, 299 - current_height)
        assert_equal(source.getblockcount(), 299)

        self.log.info("Creating assumeutxo snapshot at height 299")
        dump_output = source.dumptxoutset("faststart-functional.dat", "latest")
        snapshot_path = Path(dump_output["path"])
        assert_equal(dump_output["base_height"], 299)

        self.log.info("Mining past the snapshot so bootstrap has background validation work")
        self.generate(source, 20, sync_fun=self.no_op)
        source_height = source.getblockcount()

        self.test_faststart_wrapper(snapshot_path, dump_output, source_height)
        self.test_agent_setup_handoff(snapshot_path, dump_output, source_height)
        self.test_miner_setup_handoff(snapshot_path, dump_output, source_height)


if __name__ == "__main__":
    BTXFaststartFunctionalTest(__file__).main()
