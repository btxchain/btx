#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Install a published BTX release bundle and optionally bootstrap a node.

This script is the "download a binary and go" companion to btx-faststart.py:

- fetch `btx-release-manifest.json` from a published release (or local path),
- select the matching binary archive for the current platform,
- verify and extract it,
- optionally invoke `btx-faststart.py` with the installed binaries.
"""

from __future__ import annotations

import argparse
import http.client
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RELEASE_MANIFEST_NAME = "btx-release-manifest.json"
DEFAULT_CHECKSUM_FILE_NAME = "SHA256SUMS"
GITHUB_TOKEN_ENV_VARS = ("BTX_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")
GITHUB_API_BASE = "https://api.github.com"
GITHUB_JSON_ACCEPT = "application/vnd.github+json"
GITHUB_BINARY_ACCEPT = "application/octet-stream"


def detect_platform_id() -> str:
    system = sys.platform
    machine = platform.machine().lower()

    if system.startswith("linux"):
        if machine in {"x86_64", "amd64"}:
            return "linux-x86_64"
        if machine in {"aarch64", "arm64"}:
            return "linux-arm64"
    if system == "darwin":
        if machine in {"x86_64", "amd64"}:
            return "macos-x86_64"
        if machine in {"arm64", "aarch64"}:
            return "macos-arm64"
    if system in {"win32", "cygwin", "msys"}:
        if machine in {"x86_64", "amd64"}:
            return "windows-x86_64"

    raise RuntimeError(f"Unsupported platform for automatic BTX install: sys.platform={system} machine={machine}")


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
        "User-Agent": "btx-agent-setup.py",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_download_headers(token: str) -> dict[str, str]:
    return github_api_headers(token, accept=GITHUB_BINARY_ACCEPT)


def open_url(source: str, *, headers: dict[str, str] | None = None):
    if headers:
        return urllib.request.urlopen(urllib.request.Request(source, headers=headers))
    return urllib.request.urlopen(source)


def load_json_source(source: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    if is_url(source):
        if headers and is_github_api_url(source):
            with tempfile.TemporaryDirectory(prefix="btx-agent-setup-json.") as tmpdir:
                downloaded = download_to_path(source, Path(tmpdir) / "payload.json", headers=headers)
                return json.loads(downloaded.read_text(encoding="utf-8"))
        try:
            with open_url(source, headers=headers) as handle:
                return json.load(handle)
        except (http.client.RemoteDisconnected, urllib.error.URLError, TimeoutError):
            if headers and is_github_api_url(source):
                with tempfile.TemporaryDirectory(prefix="btx-agent-setup-json.") as tmpdir:
                    downloaded = download_to_path(source, Path(tmpdir) / "payload.json", headers=headers)
                    return json.loads(downloaded.read_text(encoding="utf-8"))
            raise
    path = Path(source)
    return json.loads(path.read_text(encoding="utf-8"))


def default_release_manifest_source(
    repo: str | None,
    release_tag: str | None,
    manifest_name: str,
) -> str:
    if not repo or not release_tag:
        raise ValueError("either --release-manifest or both --repo and --release-tag are required")
    return f"https://github.com/{repo}/releases/download/{release_tag}/{manifest_name}"


def default_asset_base(source: str) -> str:
    if is_url(source):
        return source.rsplit("/", 1)[0]
    return str(Path(source).resolve().parent)


def resolve_asset_source(asset_base: str, asset_name: str) -> str:
    if is_url(asset_base):
        return asset_base.rstrip("/") + "/" + asset_name
    return str((Path(asset_base) / asset_name).resolve())


def parse_github_release_reference(
    *,
    repo: str | None,
    release_tag: str | None,
    source: str,
) -> tuple[str, str] | None:
    if repo and release_tag:
        return repo, release_tag
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


def is_github_api_url(source: str) -> bool:
    return source.startswith(f"{GITHUB_API_BASE}/")


def download_with_curl(source: str, destination: Path, headers: dict[str, str]) -> Path:
    curl_bin = shutil.which("curl")
    if curl_bin is None:
        raise RuntimeError(
            "curl is required to download GitHub API resources when the Python HTTP client cannot"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_destination = destination.with_suffix(destination.suffix + ".part")
    command = [
        curl_bin,
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--output",
        str(temp_destination),
    ]
    for header_name, header_value in headers.items():
        command.extend(["--header", f"{header_name}: {header_value}"])
    command.append(source)
    try:
        subprocess.run(command, check=True)
        temp_destination.replace(destination)
    finally:
        temp_destination.unlink(missing_ok=True)
    return destination


def download_to_path(source: str, destination: Path, *, headers: dict[str, str] | None = None) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if is_url(source):
        try:
            with open_url(source, headers=headers) as response, destination.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
        except (http.client.RemoteDisconnected, urllib.error.URLError, TimeoutError):
            if headers and is_github_api_url(source):
                return download_with_curl(source, destination, headers)
            raise
    else:
        shutil.copy2(Path(source), destination)
    return destination


def download_and_verify_asset(
    source: str,
    destination: Path,
    expected_sha256: str | None,
    *,
    headers: dict[str, str] | None = None,
) -> Path:
    download_to_path(source, destination, headers=headers)
    if expected_sha256 is not None:
        actual = sha256_file(destination)
        if actual.lower() != expected_sha256.lower():
            raise ValueError(
                f"SHA256 mismatch for {destination.name}: expected {expected_sha256}, got {actual}"
            )
    return destination


def parse_checksum_file(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid checksum line {line_number} in {path}")
        digest, asset_name = parts
        digest = digest.lower()
        asset_name = asset_name.lstrip("*")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError(f"Invalid SHA256 digest on line {line_number} in {path}")
        if asset_name in checksums and checksums[asset_name] != digest:
            raise ValueError(f"Conflicting checksum entries for {asset_name} in {path}")
        checksums[asset_name] = digest
    return checksums


def verify_checksum_signature(checksum_path: Path, signature_path: Path, gpg_bin: str) -> None:
    result = subprocess.run(
        [gpg_bin, "--verify", str(signature_path), str(checksum_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "gpg --verify failed"
        raise RuntimeError(f"Checksum signature verification failed for {signature_path.name}: {message}")


def verified_asset_sha256(
    asset_name: str,
    asset_metadata: dict[str, Any] | None,
    checksums: dict[str, str],
) -> str:
    checksum_sha256 = checksums.get(asset_name)
    if checksum_sha256 is None:
        raise KeyError(f"{asset_name} is missing from SHA256SUMS")
    manifest_sha256 = None
    if isinstance(asset_metadata, dict):
        raw_manifest_sha256 = asset_metadata.get("sha256")
        if isinstance(raw_manifest_sha256, str) and raw_manifest_sha256:
            manifest_sha256 = raw_manifest_sha256.lower()
    if manifest_sha256 is not None and manifest_sha256 != checksum_sha256:
        raise ValueError(
            f"Checksum mismatch between release manifest and SHA256SUMS for {asset_name}: "
            f"{manifest_sha256} != {checksum_sha256}"
        )
    return checksum_sha256


def asset_index(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assets = manifest.get("assets", [])
    if not isinstance(assets, list):
        raise TypeError("release manifest assets must be an array")
    return {
        asset["name"]: asset
        for asset in assets
        if isinstance(asset, dict) and isinstance(asset.get("name"), str)
    }


def resolve_platform_asset(manifest: dict[str, Any], platform_id: str) -> dict[str, Any]:
    platform_assets = manifest.get("platform_assets")
    if not isinstance(platform_assets, dict):
        raise KeyError("release manifest does not contain platform_assets")
    asset = platform_assets.get(platform_id)
    if not isinstance(asset, dict):
        raise KeyError(f"release manifest does not contain a platform asset for {platform_id}")
    return asset


def ensure_safe_extract_path(destination_root: Path, member_name: str) -> None:
    member_path = Path(member_name)
    if member_path.is_absolute() or ".." in member_path.parts:
        raise ValueError(f"archive contains unsafe path: {member_name}")
    resolved_root = destination_root.resolve()
    resolved_target = (destination_root / member_path).resolve()
    if resolved_target != resolved_root and resolved_root not in resolved_target.parents:
        raise ValueError(f"archive contains unsafe path: {member_name}")


def extract_archive(archive_path: Path, install_dir: Path) -> None:
    install_dir.mkdir(parents=True, exist_ok=True)
    suffix = archive_path.name.lower()
    if suffix.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2")):
        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive.getmembers():
                ensure_safe_extract_path(install_dir, member.name)
                if member.issym() or member.islnk():
                    raise ValueError(f"archive contains unsupported link entry: {member.name}")
            archive.extractall(install_dir)
        return
    if suffix.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                ensure_safe_extract_path(install_dir, member.filename)
            archive.extractall(install_dir)
        return
    raise ValueError(f"unsupported archive format: {archive_path.name}")


def install_archive(archive_path: Path, install_dir: Path, *, force: bool) -> None:
    parent_dir = install_dir.parent
    parent_dir.mkdir(parents=True, exist_ok=True)
    if install_dir.exists():
        if not install_dir.is_dir():
            raise NotADirectoryError(f"Install path is not a directory: {install_dir}")
        if any(install_dir.iterdir()):
            if not force:
                raise FileExistsError(
                    f"Install directory is not empty: {install_dir} (pass --force to replace it)"
                )
            shutil.rmtree(install_dir)
        else:
            install_dir.rmdir()

    temp_install_dir = Path(tempfile.mkdtemp(prefix=install_dir.name + ".", dir=str(parent_dir)))
    try:
        extract_archive(archive_path, temp_install_dir)
        temp_install_dir.replace(install_dir)
    except Exception:
        shutil.rmtree(temp_install_dir, ignore_errors=True)
        raise


def find_binary(install_dir: Path, names: tuple[str, ...]) -> Path:
    for name in names:
        matches = sorted(path for path in install_dir.rglob(name) if path.is_file())
        if matches:
            return matches[0]
    raise FileNotFoundError(f"could not find any of {', '.join(names)} under {install_dir}")


def run_bootstrap_subprocess(cmd: list[str], *, json_mode: bool) -> None:
    if not json_mode:
        subprocess.run(cmd, check=True)
        return

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        if exc.stdout:
            print(exc.stdout, end="", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, end="", file=sys.stderr)
        raise

    if result.stdout:
        print(result.stdout, end="", file=sys.stderr)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release-manifest",
        help="Path or URL to btx-release-manifest.json. If omitted, derive it from --repo/--release-tag.",
    )
    parser.add_argument("--repo", help="GitHub repository in owner/name form.")
    parser.add_argument("--release-tag", help="Release tag used in the GitHub Releases download URL.")
    parser.add_argument(
        "--manifest-name",
        default=DEFAULT_RELEASE_MANIFEST_NAME,
        help=f"Release manifest asset name (default: {DEFAULT_RELEASE_MANIFEST_NAME}).",
    )
    parser.add_argument(
        "--asset-base-url",
        help="Override the base URL or directory used to resolve asset names from the release manifest.",
    )
    parser.add_argument("--platform", help="Override detected platform id, for example linux-x86_64.")
    parser.add_argument(
        "--install-dir",
        help="Directory where the BTX archive will be extracted. Defaults to ~/.local/btx/<tag>/<platform>.",
    )
    parser.add_argument(
        "--cache-dir",
        help="Directory used to cache downloaded assets. Defaults to a sibling path next to install_dir.",
    )
    parser.add_argument(
        "--gpg",
        default="gpg",
        help="GPG binary used to verify SHA256SUMS.asc when present (default: gpg).",
    )
    parser.add_argument(
        "--allow-unsigned-release",
        action="store_true",
        help="Allow remote release manifests that do not advertise SHA256SUMS.asc.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing non-empty install directory.",
    )
    parser.add_argument(
        "--preset",
        choices=("miner", "service"),
        help="If set, run btx-faststart.py after install with the chosen preset.",
    )
    parser.add_argument("--chain", default="main", help="BTX chain name for optional bootstrap.")
    parser.add_argument(
        "--datadir",
        default=str(Path.home() / ".btx"),
        help="BTX data directory for optional bootstrap (default: ~/.btx).",
    )
    parser.add_argument(
        "--matmul-service-challenge-file",
        help="Optional shared file path for service challenge redemption state during bootstrap.",
    )
    parser.add_argument("--follow", action="store_true", help="Keep watching getchainstates after bootstrap completes.")
    parser.add_argument("--keep-snapshot", action="store_true", help="Keep the downloaded snapshot after loadtxoutset.")
    parser.add_argument("--no-start-daemon", action="store_true", help="Pass through to btx-faststart.py.")
    parser.add_argument("--daemon-arg", action="append", default=[], help="Extra argument passed to btxd during bootstrap.")
    parser.add_argument("--cli-arg", action="append", default=[], help="Extra argument passed to btx-cli during bootstrap.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable JSON summary; bootstrap progress is written to stderr.",
    )
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)

    manifest_reference_source = args.release_manifest or default_release_manifest_source(
        args.repo,
        args.release_tag,
        args.manifest_name,
    )
    github_token = github_token_from_env()
    github_asset_urls: dict[str, str] = {}
    github_asset_headers: dict[str, str] | None = None
    github_release_reference = parse_github_release_reference(
        repo=args.repo,
        release_tag=args.release_tag,
        source=manifest_reference_source,
    )
    manifest_source = manifest_reference_source
    manifest_filename = Path(urllib.parse.urlparse(manifest_reference_source).path).name or args.manifest_name
    if github_token and github_release_reference is not None:
        github_asset_urls = github_release_asset_urls(
            github_release_reference[0],
            github_release_reference[1],
            github_token,
        )
        manifest_source = github_asset_urls.get(manifest_filename, manifest_source)
        github_asset_headers = github_download_headers(github_token)
    manifest = load_json_source(manifest_source, headers=github_asset_headers)
    platform_id = args.platform or detect_platform_id()
    release_tag = args.release_tag or manifest.get("release_tag") or "current"
    install_dir = Path(args.install_dir).expanduser() if args.install_dir else (
        Path.home() / ".local" / "btx" / str(release_tag) / platform_id
    )
    cache_dir = Path(args.cache_dir).expanduser() if args.cache_dir else (
        install_dir.parent / f"{install_dir.name}-agent-setup-cache"
    )
    asset_base = args.asset_base_url or default_asset_base(manifest_reference_source)
    def resolved_asset_source(asset_name: str) -> str:
        return github_asset_urls.get(asset_name, resolve_asset_source(asset_base, asset_name))
    checksum_name = manifest.get("checksum_file") or DEFAULT_CHECKSUM_FILE_NAME
    checksum_path = download_to_path(
        resolved_asset_source(checksum_name),
        cache_dir / checksum_name,
        headers=github_asset_headers,
    )
    checksums = parse_checksum_file(checksum_path)
    manifest_path = download_and_verify_asset(
        manifest_source,
        cache_dir / manifest_filename,
        checksums.get(manifest_filename),
        headers=github_asset_headers,
    )
    signature_name = manifest.get("signature_file")
    if signature_name:
        signature_path = download_to_path(
            resolved_asset_source(signature_name),
            cache_dir / signature_name,
            headers=github_asset_headers,
        )
        verify_checksum_signature(checksum_path, signature_path, args.gpg)
    elif is_url(manifest_reference_source) and not args.allow_unsigned_release:
        raise KeyError(
            "release manifest does not advertise signature_file; refusing unsigned remote release "
            "(pass --allow-unsigned-release to override)"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    archive_info = resolve_platform_asset(manifest, platform_id)
    archive_name = archive_info["asset_name"]
    snapshot_manifest_name = manifest.get("snapshot_manifest")
    if args.preset and not snapshot_manifest_name:
        raise KeyError("release manifest does not advertise snapshot_manifest; cannot bootstrap with --preset")

    assets = asset_index(manifest)
    archive_asset = assets.get(archive_name, {})
    archive_sha256 = verified_asset_sha256(archive_name, archive_asset, checksums)
    archive_source = resolved_asset_source(archive_name)
    archive_path = download_and_verify_asset(
        archive_source,
        cache_dir / archive_name,
        archive_sha256,
        headers=github_asset_headers,
    )
    install_archive(archive_path, install_dir, force=args.force)

    btxd_path = find_binary(install_dir, ("btxd", "btxd.exe"))
    btx_cli_path = find_binary(install_dir, ("btx-cli", "btx-cli.exe"))

    snapshot_manifest_path: Path | None = None
    if snapshot_manifest_name:
        snapshot_manifest_asset = assets.get(snapshot_manifest_name, {})
        snapshot_manifest_path = download_and_verify_asset(
            resolved_asset_source(snapshot_manifest_name),
            cache_dir / snapshot_manifest_name,
            verified_asset_sha256(snapshot_manifest_name, snapshot_manifest_asset, checksums),
            headers=github_asset_headers,
        )

    summary: dict[str, Any] = {
        "manifest_source": manifest_source,
        "asset_base": asset_base,
        "release_tag": release_tag,
        "platform_id": platform_id,
        "archive_asset": archive_name,
        "archive_format": archive_info.get("archive_format"),
        "install_dir": str(install_dir),
        "cache_dir": str(cache_dir),
        "btxd": str(btxd_path),
        "btx_cli": str(btx_cli_path),
        "snapshot_manifest": str(snapshot_manifest_path) if snapshot_manifest_path else None,
    }

    if args.preset:
        datadir = Path(args.datadir).expanduser()
        faststart_conf = datadir / "faststart" / "faststart.conf"
        faststart_cmd = [
            sys.executable,
            str(SCRIPT_DIR / "btx-faststart.py"),
            args.preset,
            f"--chain={args.chain}",
            f"--datadir={datadir}",
            f"--btxd={btxd_path}",
            f"--btx-cli={btx_cli_path}",
            f"--snapshot-manifest={snapshot_manifest_path}",
        ]
        if args.matmul_service_challenge_file:
            faststart_cmd.append(
                f"--matmul-service-challenge-file={Path(args.matmul_service_challenge_file).expanduser()}"
            )
        if args.follow:
            faststart_cmd.append("--follow")
        if args.keep_snapshot:
            faststart_cmd.append("--keep-snapshot")
        if args.no_start_daemon:
            faststart_cmd.append("--no-start-daemon")
        faststart_cmd.extend(f"--daemon-arg={value}" for value in args.daemon_arg)
        faststart_cmd.extend(f"--cli-arg={value}" for value in args.cli_arg)
        summary["preset"] = args.preset
        summary["datadir"] = str(datadir)
        summary["faststart_conf"] = str(faststart_conf)
        summary["faststart_command"] = faststart_cmd
        if args.preset == "miner":
            results_dir = datadir / "mining-ops"
            summary["mining_results_dir"] = str(results_dir)
            summary["start_live_mining_command"] = [
                str(SCRIPT_DIR.parent / "mining" / "start-live-mining.sh"),
                f"--datadir={datadir}",
                f"--conf={faststart_conf}",
                f"--chain={args.chain}",
                f"--cli={btx_cli_path}",
                f"--daemon={btxd_path}",
                "--wallet=miner",
                f"--results-dir={results_dir}",
            ]
            summary["stop_live_mining_command"] = [
                str(SCRIPT_DIR.parent / "mining" / "stop-live-mining.sh"),
                f"--results-dir={results_dir}",
            ]
        run_bootstrap_subprocess(faststart_cmd, json_mode=args.json)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"installed {archive_name} to {install_dir}")
        print(f"btxd: {btxd_path}")
        print(f"btx-cli: {btx_cli_path}")
        if snapshot_manifest_path is not None:
            print(f"snapshot manifest: {snapshot_manifest_path}")
        if args.preset:
            print(f"bootstrapped preset: {args.preset}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
