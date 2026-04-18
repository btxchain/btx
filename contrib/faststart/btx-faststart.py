#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Bootstrap a BTX node from a published snapshot and watch chainstate sync.

This script is intentionally practical rather than magical: it can either take
an explicit snapshot URL, or resolve one from a small JSON manifest keyed by
chain name. The manifest model is meant to let release operators publish a
single "matching snapshot" pointer for each supported network without baking
download locations into the binary tree.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.parse
import urllib.request


SCRIPT_DIR = Path(__file__).resolve().parent
GITHUB_TOKEN_ENV_VARS = ("BTX_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")
GITHUB_API_BASE = "https://api.github.com"
GITHUB_JSON_ACCEPT = "application/vnd.github+json"
GITHUB_BINARY_ACCEPT = "application/octet-stream"

PRESET_CONF = {
    "miner": [
        "server=1",
        "listen=1",
        "rpcbind=127.0.0.1",
        "rpcallowip=127.0.0.1",
        "prune=4096",
        "blockfilterindex=1",
        "coinstatsindex=1",
        "retainshieldedcommitmentindex=1",
        "miningminoutboundpeers=2",
        "miningminsyncedoutboundpeers=1",
        "miningmaxheaderlag=8",
    ],
    "service": [
        "server=1",
        "listen=1",
        "rpcbind=127.0.0.1",
        "rpcallowip=127.0.0.1",
        "prune=0",
        "txindex=1",
        "blockfilterindex=1",
        "coinstatsindex=1",
        "retainshieldedcommitmentindex=1",
    ],
}

MIRRORED_RPC_CONNECTION_ARGS = (
    "-rpcconnect",
    "-rpcport",
    "-rpcuser",
    "-rpcpassword",
    "-rpccookiefile",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_url(source: str) -> bool:
    return "://" in source


def github_token_from_env() -> str | None:
    for name in GITHUB_TOKEN_ENV_VARS:
        value = os.environ.get(name)
        if value:
            return value.strip()
    return None


def github_api_headers(token: str, *, accept: str) -> dict[str, str]:
    return {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "User-Agent": "btx-faststart.py",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def open_url(source: str, *, headers: dict[str, str] | None = None):
    if headers:
        return urllib.request.urlopen(urllib.request.Request(source, headers=headers))
    return urllib.request.urlopen(source)


def parse_github_release_reference(source: str) -> tuple[str, str] | None:
    if not is_url(source):
        return None
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 6 or parts[2:4] != ["releases", "download"]:
        return None
    owner, repo_name = parts[0], parts[1]
    return f"{owner}/{repo_name}", parts[4]


def github_release_asset_urls(repo: str, release_tag: str, token: str) -> dict[str, str]:
    release = load_json_source(
        f"{GITHUB_API_BASE}/repos/{repo}/releases/tags/{urllib.parse.quote(release_tag, safe='')}",
        headers=github_api_headers(token, accept=GITHUB_JSON_ACCEPT),
    )
    assets = release.get("assets", [])
    if not isinstance(assets, list):
        raise TypeError("GitHub release assets must be an array")
    resolved: dict[str, str] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        url = asset.get("url")
        if isinstance(name, str) and isinstance(url, str) and url:
            resolved[name] = url
    return resolved


def is_github_release_asset_api_url(source: str) -> bool:
    return source.startswith(f"{GITHUB_API_BASE}/repos/") and "/releases/assets/" in source


def download_with_curl(source: str, destination: Path, headers: dict[str, str]) -> Path:
    curl_bin = shutil.which("curl")
    if curl_bin is None:
        raise RuntimeError(
            "curl is required to download GitHub release assets when the Python HTTP client cannot"
        )
    command = [
        curl_bin,
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--output",
        str(destination),
    ]
    for header_name, header_value in headers.items():
        command.extend(["--header", f"{header_name}: {header_value}"])
    command.append(source)
    subprocess.run(command, check=True)
    return destination


def github_release_headers(source: str) -> tuple[str, dict[str, str] | None]:
    token = github_token_from_env()
    release_reference = parse_github_release_reference(source)
    if token is None or release_reference is None:
        return source, None

    repo, release_tag = release_reference
    asset_name = Path(urllib.parse.urlparse(source).path).name
    resolved_url = github_release_asset_urls(repo, release_tag, token).get(asset_name, source)
    return resolved_url, github_api_headers(token, accept=GITHUB_BINARY_ACCEPT)


def load_json_source(source: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    if is_url(source):
        with open_url(source, headers=headers) as handle:
            return json.load(handle)

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Snapshot manifest not found: {source}")
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_manifest_entry(manifest: dict[str, Any], chain: str) -> dict[str, Any]:
    if manifest.get("chain") == chain and (
        manifest.get("url")
        or manifest.get("asset_url")
        or manifest.get("published_name")
        or manifest.get("filename")
    ):
        return manifest

    for key in ("snapshots", "chains", "entries"):
        if isinstance(manifest.get(key), dict):
            manifest = manifest[key]
            break
    entry = manifest.get(chain)
    if entry is None:
        raise KeyError(f"No snapshot entry found for chain '{chain}'")
    if not isinstance(entry, dict):
        raise TypeError(f"Snapshot manifest entry for '{chain}' must be a JSON object")
    return entry


def default_snapshot_manifest() -> Path:
    return SCRIPT_DIR / "snapshot-manifest.json"


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_preset_conf(
    workdir: Path,
    preset: str,
    chain: str,
    extra_lines: list[str] | None = None,
) -> Path:
    conf_path = workdir / "faststart.conf"
    ensure_parent(conf_path)
    lines = [
        "# Generated by contrib/faststart/btx-faststart.py",
        f"# Preset: {preset}",
        "",
    ]
    if chain != "main":
        lines.append(f"[{chain}]")
    lines.extend(PRESET_CONF[preset])
    if extra_lines:
        lines.extend(extra_lines)
    conf_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return conf_path


def chain_arg(chain: str) -> list[str]:
    return [] if chain == "main" else [f"-chain={chain}"]


def rpc_base_cmd(cli: str, datadir: Path, conf: Path, chain: str, extra_args: list[str]) -> list[str]:
    return [
        cli,
        f"-datadir={datadir}",
        f"-conf={conf}",
        *chain_arg(chain),
        "-rpcclienttimeout=0",
        *extra_args,
    ]


def daemon_cmd(daemon: str, datadir: Path, conf: Path, chain: str, extra_args: list[str]) -> list[str]:
    return [
        daemon,
        "-daemon",
        f"-datadir={datadir}",
        f"-conf={conf}",
        *chain_arg(chain),
        *extra_args,
    ]


def mirrored_cli_rpc_args(daemon_args: list[str]) -> list[str]:
    mirrored: list[str] = []
    for arg in daemon_args:
        for key in MIRRORED_RPC_CONNECTION_ARGS:
            if arg == key or arg.startswith(f"{key}="):
                mirrored.append(arg)
                break
    return mirrored


def run_quiet(cmd: list[str], *, stdout=None, stderr=None) -> None:
    subprocess.run(cmd, check=True, stdout=stdout, stderr=stderr, text=True)


def rpc_json(cmd: list[str], method: str, *params: str) -> dict[str, Any]:
    try:
        output = subprocess.check_output([*cmd, method, *params], stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{method} failed:\n{exc.output}") from exc
    return json.loads(output)


def wait_for_rpc_ready(cli_cmd: list[str], timeout_secs: int) -> None:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        proc = subprocess.run([*cli_cmd, "getblockcount"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        if proc.returncode == 0:
            return
        time.sleep(1)
    raise TimeoutError("Timed out waiting for btxd RPC to become ready")


def download_snapshot(url: str, destination: Path, expected_sha256: str | None) -> Path:
    ensure_parent(destination)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".partial", dir=str(destination.parent))
    tmp_path = Path(tmp_name)
    os.close(tmp_fd)
    try:
        resolved_url, headers = github_release_headers(url)
        try:
            digest = hashlib.sha256()
            with open_url(resolved_url, headers=headers) as response, tmp_path.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    digest.update(chunk)
            actual_sha256 = digest.hexdigest()
        except (http.client.RemoteDisconnected, urllib.error.URLError, TimeoutError):
            if not headers or not is_github_release_asset_api_url(resolved_url):
                raise
            download_with_curl(resolved_url, tmp_path, headers)
            actual_sha256 = sha256_file(tmp_path)

        if expected_sha256 is not None and actual_sha256.lower() != expected_sha256.lower():
            raise ValueError(
                f"Snapshot SHA256 mismatch for {url}: expected {expected_sha256}, got {actual_sha256}"
            )
        tmp_path.replace(destination)
        return destination
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def snapshot_from_args(args: argparse.Namespace) -> tuple[str, str | None, str, dict[str, Any]]:
    if args.snapshot_url:
        snapshot_url = args.snapshot_url
        snapshot_sha256 = args.snapshot_sha256
        snapshot_name = args.snapshot_name or Path(urllib.parse.urlparse(snapshot_url).path).name or "snapshot.dat"
        return snapshot_url, snapshot_sha256, snapshot_name, {}

    manifest_source = args.snapshot_manifest or os.environ.get("BTX_FASTSTART_SNAPSHOT_MANIFEST")
    if not manifest_source:
        manifest_source = str(default_snapshot_manifest())
    try:
        resolved_manifest_source, manifest_headers = github_release_headers(manifest_source)
        manifest = load_json_source(resolved_manifest_source, headers=manifest_headers)
    except FileNotFoundError as exc:
        if manifest_source == str(default_snapshot_manifest()) and not args.snapshot_manifest and not os.environ.get("BTX_FASTSTART_SNAPSHOT_MANIFEST"):
            raise FileNotFoundError(
                "No snapshot URL or manifest was provided. Pass --snapshot-url directly or create "
                f"{default_snapshot_manifest()} from contrib/faststart/snapshot-manifest.example.json."
            ) from exc
        raise
    entry = resolve_manifest_entry(manifest, args.chain)
    snapshot_url = entry.get("url") or entry.get("asset_url")
    if not snapshot_url:
        raise KeyError(f"Snapshot manifest entry for '{args.chain}' is missing url")
    snapshot_sha256 = entry.get("sha256") or entry.get("snapshot_sha256")
    snapshot_name = (
        entry.get("filename")
        or entry.get("published_name")
        or Path(urllib.parse.urlparse(snapshot_url).path).name
        or "snapshot.dat"
    )
    return snapshot_url, snapshot_sha256, snapshot_name, entry


def require_snapshot_sha256(snapshot_url: str, snapshot_sha256: str | None, allow_missing: bool) -> None:
    if snapshot_sha256:
        return
    if allow_missing:
        print(
            f"warning: snapshot SHA256 not provided for {snapshot_url}; download was not authenticated",
            file=sys.stderr,
        )
        return
    raise KeyError(
        f"Snapshot metadata for {snapshot_url} is missing snapshot_sha256/sha256 "
        "(pass --allow-missing-snapshot-sha256 to override)"
    )


def validate_snapshot_receipt(load_result: dict[str, Any], manifest_entry: dict[str, Any]) -> None:
    expected_height = manifest_entry.get("height")
    if expected_height is None:
        return
    actual_height = load_result.get("base_height")
    if actual_height is None or int(actual_height) != int(expected_height):
        raise RuntimeError(
            f"Snapshot manifest height mismatch: expected base_height={expected_height}, got {actual_height}"
        )


def validate_snapshot_chainstates(chainstates_info: dict[str, Any], manifest_entry: dict[str, Any]) -> None:
    expected_blockhash = manifest_entry.get("blockhash")
    if expected_blockhash is None:
        return
    for state in chainstates_info.get("chainstates", []):
        snapshot_blockhash = state.get("snapshot_blockhash")
        if snapshot_blockhash is None:
            continue
        if str(snapshot_blockhash) != str(expected_blockhash):
            raise RuntimeError(
                f"Snapshot manifest blockhash mismatch: expected snapshot_blockhash={expected_blockhash}, "
                f"got {snapshot_blockhash}"
            )
        return
    raise RuntimeError(
        f"Snapshot manifest expected snapshot_blockhash={expected_blockhash}, "
        "but getchainstates did not report an active snapshot chainstate"
    )


def wait_for_snapshot_header(
    cli_cmd: list[str],
    manifest_entry: dict[str, Any],
    timeout_secs: int,
) -> None:
    expected_blockhash = manifest_entry.get("blockhash")
    expected_height = manifest_entry.get("height")
    if expected_blockhash is None and expected_height is None:
        return

    deadline = time.time() + timeout_secs
    last_progress: str | None = None
    while time.time() < deadline:
        headers = None
        try:
            blockchaininfo = rpc_json(cli_cmd, "getblockchaininfo")
            headers = blockchaininfo.get("headers")
        except RuntimeError:
            pass

        if expected_blockhash is not None:
            proc = subprocess.run(
                [*cli_cmd, "getblockheader", str(expected_blockhash)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            if proc.returncode == 0:
                return
        elif headers is not None and int(headers) >= int(expected_height):
            return

        if expected_height is not None:
            progress = f"headers={headers if headers is not None else 'unknown'}/{expected_height}"
            if progress != last_progress:
                print(f"waiting for snapshot anchor header: {progress}")
                last_progress = progress

        time.sleep(1)

    details = []
    if expected_height is not None:
        details.append(f"height={expected_height}")
    if expected_blockhash is not None:
        details.append(f"blockhash={expected_blockhash}")
    raise TimeoutError(
        "Timed out waiting for snapshot anchor header to reach the node "
        f"({' '.join(details)})"
    )


def snapshot_superseded_by_active_chain(
    cli_cmd: list[str],
    manifest_entry: dict[str, Any],
) -> bool:
    expected_height = manifest_entry.get("height")
    if expected_height is None:
        return False

    expected_blockhash = manifest_entry.get("blockhash")
    if expected_blockhash is not None:
        proc = subprocess.run(
            [*cli_cmd, "getblockhash", str(expected_height)],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip() == str(expected_blockhash):
            return True

    proc = subprocess.run(
        [*cli_cmd, "getblockcount"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return False
    try:
        return int(proc.stdout.strip()) >= int(expected_height)
    except ValueError:
        return False


def format_chainstate(state: dict[str, Any], index: int) -> str:
    bits = [
        f"idx={index}",
        f"blocks={state.get('blocks', 'unknown')}",
        f"validated={state.get('validated', 'unknown')}",
    ]
    snapshot_blockhash = state.get("snapshot_blockhash")
    if snapshot_blockhash:
        bits.append(f"snapshot_blockhash={snapshot_blockhash}")
    bestblock = state.get("best_block_hash") or state.get("bestblock")
    if bestblock:
        bits.append(f"best_block={bestblock}")
    return " ".join(bits)


def is_complete(chainstates: list[dict[str, Any]]) -> bool:
    return len(chainstates) == 1 and not chainstates[0].get("snapshot_blockhash")


def monitor_chainstates(cli_cmd: list[str], poll_secs: int, follow: bool) -> None:
    last_signature = None
    announced_complete = False
    while True:
        info = rpc_json(cli_cmd, "getchainstates")
        chainstates = list(info.get("chainstates", []))
        lines = [format_chainstate(state, idx) for idx, state in enumerate(chainstates)]
        signature = tuple(lines)
        if signature != last_signature:
            print("chainstates:")
            for line in lines:
                print(f"  {line}")
            last_signature = signature
        if is_complete(chainstates):
            if not announced_complete:
                print("chainstate bootstrap complete")
                announced_complete = True
            if not follow:
                return
        time.sleep(poll_secs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("preset", choices=sorted(PRESET_CONF), help="Node fast-start preset to apply")
    parser.add_argument("--chain", default=os.environ.get("BTX_FASTSTART_CHAIN", "main"), help="BTX chain name")
    parser.add_argument(
        "--datadir",
        default=os.environ.get("BTX_FASTSTART_DATADIR", str(Path.home() / ".btx")),
        help="BTX data directory",
    )
    parser.add_argument("--btxd", default=os.environ.get("BTX_FASTSTART_DAEMON", "btxd"), help="Path to btxd")
    parser.add_argument("--btx-cli", default=os.environ.get("BTX_FASTSTART_CLI", "btx-cli"), help="Path to btx-cli")
    parser.add_argument("--snapshot-url", default=os.environ.get("BTX_FASTSTART_SNAPSHOT_URL"), help="Direct snapshot URL")
    parser.add_argument("--snapshot-sha256", default=os.environ.get("BTX_FASTSTART_SNAPSHOT_SHA256"), help="Expected snapshot SHA256")
    parser.add_argument(
        "--snapshot-manifest",
        default=os.environ.get("BTX_FASTSTART_SNAPSHOT_MANIFEST"),
        help="Path or URL to a JSON manifest mapping chain names to snapshot metadata",
    )
    parser.add_argument("--snapshot-name", help="Override the downloaded filename")
    parser.add_argument(
        "--allow-missing-snapshot-sha256",
        action="store_true",
        help="Allow snapshot downloads that do not advertise snapshot_sha256/sha256.",
    )
    parser.add_argument(
        "--matmul-service-challenge-file",
        default=os.environ.get("BTX_FASTSTART_MATMUL_SERVICE_CHALLENGE_FILE"),
        help="Optional shared file path for MatMul service challenge redemption state",
    )
    parser.add_argument("--keep-snapshot", action="store_true", help="Keep the downloaded snapshot after loadtxoutset")
    parser.add_argument("--poll-secs", type=int, default=5, help="Seconds between getchainstates polls")
    parser.add_argument("--rpc-wait-secs", type=int, default=120, help="Seconds to wait for RPC readiness")
    parser.add_argument(
        "--header-wait-secs",
        type=int,
        default=120,
        help="Seconds to wait for the snapshot anchor header before loadtxoutset",
    )
    parser.add_argument("--follow", action="store_true", help="Keep watching getchainstates after bootstrap completes")
    parser.add_argument("--no-start-daemon", action="store_true", help="Do not launch btxd; attach to an already-running node")
    parser.add_argument("--daemon-arg", action="append", default=[], help="Extra argument passed to btxd")
    parser.add_argument("--cli-arg", action="append", default=[], help="Extra argument passed to btx-cli")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    datadir = Path(args.datadir).expanduser()
    workdir = datadir / "faststart"
    workdir.mkdir(parents=True, exist_ok=True)

    extra_conf: list[str] = []
    if args.matmul_service_challenge_file:
        shared_path = Path(args.matmul_service_challenge_file).expanduser().resolve()
        extra_conf.append(f"matmulservicechallengefile={shared_path}")

    conf_path = write_preset_conf(workdir, args.preset, args.chain, extra_conf)
    snapshot_url, snapshot_sha256, snapshot_name, snapshot_entry = snapshot_from_args(args)
    require_snapshot_sha256(
        snapshot_url,
        snapshot_sha256,
        args.allow_missing_snapshot_sha256,
    )
    snapshot_path = workdir / snapshot_name

    cli_cmd = rpc_base_cmd(
        args.btx_cli,
        datadir,
        conf_path,
        args.chain,
        [*mirrored_cli_rpc_args(list(args.daemon_arg)), *list(args.cli_arg)],
    )
    daemon = daemon_cmd(args.btxd, datadir, conf_path, args.chain, list(args.daemon_arg))

    if subprocess.run([*cli_cmd, "getblockcount"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True).returncode != 0:
        if args.no_start_daemon:
            raise RuntimeError("RPC is not ready and --no-start-daemon was provided")
        print(f"starting daemon with preset '{args.preset}'")
        run_quiet(daemon)
        wait_for_rpc_ready(cli_cmd, args.rpc_wait_secs)

    print(f"downloading snapshot: {snapshot_url}")
    download_snapshot(snapshot_url, snapshot_path, snapshot_sha256)
    print(f"snapshot saved to: {snapshot_path}")

    wait_for_snapshot_header(cli_cmd, snapshot_entry, args.header_wait_secs)
    load_result = None
    if snapshot_superseded_by_active_chain(cli_cmd, snapshot_entry):
        print("snapshot already superseded by active chainstate; skipping loadtxoutset")
    else:
        try:
            load_result = rpc_json(cli_cmd, "loadtxoutset", str(snapshot_path))
        except RuntimeError as exc:
            if "Work does not exceed active chainstate" in str(exc):
                print("snapshot already superseded by active chainstate during loadtxoutset; continuing")
            else:
                raise

    if load_result is not None:
        validate_snapshot_receipt(load_result, snapshot_entry)
        validate_snapshot_chainstates(rpc_json(cli_cmd, "getchainstates"), snapshot_entry)
        print("loadtxoutset result:")
        print(json.dumps(load_result, indent=2))

    if not args.keep_snapshot:
        snapshot_path.unlink(missing_ok=True)

    monitor_chainstates(cli_cmd, args.poll_secs, args.follow)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
