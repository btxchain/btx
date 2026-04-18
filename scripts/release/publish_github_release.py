#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Create or update a GitHub release and upload BTX release assets.

The script uses the GitHub REST API through ``curl`` and accepts the token from
``BTX_GITHUB_TOKEN``, ``GITHUB_TOKEN`` or ``GH_TOKEN``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote
from typing import Any


API_VERSION = "2022-11-28"
TOKEN_ENV_VARS = ("BTX_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")
CHECKSUM_FILE_NAME = "SHA256SUMS"
RELEASE_MANIFEST_NAME = "btx-release-manifest.json"
OPTIONAL_UNSIGNED_ASSETS = {"SHA256SUMS.asc"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="GitHub repository in owner/name form.")
    parser.add_argument("--tag", required=True, help="Release tag to create or update.")
    parser.add_argument(
        "--bundle-dir",
        required=True,
        help="Directory containing the staged release assets.",
    )
    parser.add_argument(
        "--release-name",
        help="Optional release title. Defaults to the tag name.",
    )
    parser.add_argument(
        "--body-file",
        help="Optional markdown body file to use for the release notes.",
    )
    parser.add_argument(
        "--target-branch",
        default="main",
        help="Branch or commitish to associate with a newly created tag (default: main).",
    )
    parser.add_argument(
        "--draft",
        action="store_true",
        help="Create or keep the release as a draft.",
    )
    parser.add_argument(
        "--prerelease",
        action="store_true",
        help="Mark the release as a prerelease.",
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish the release immediately instead of leaving it as a draft.",
    )
    parser.add_argument(
        "--token-env",
        action="append",
        default=[],
        help="Additional token environment variable names to consult before publishing.",
    )
    parser.add_argument(
        "--token",
        help="Explicit GitHub API token to use for release publication.",
    )
    parser.add_argument(
        "--token-file",
        help="Path to a file containing the GitHub API token.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the bundle and print the planned API actions without calling GitHub.",
    )
    parser.add_argument(
        "--gpg",
        default="gpg",
        help="GPG binary used to verify SHA256SUMS.asc when the bundle advertises it (default: gpg).",
    )
    return parser.parse_args(argv)


def read_token(args: argparse.Namespace) -> str | None:
    if args.token:
        return args.token.strip()
    if args.token_file:
        return Path(args.token_file).read_text(encoding="utf-8").strip()
    return token_from_env(args.token_env)


def token_from_env(extra_names: list[str]) -> str | None:
    for name in [*extra_names, *TOKEN_ENV_VARS]:
        token = os.environ.get(name)
        if token:
            return token.strip()
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def load_release_manifest(bundle_dir: Path) -> dict[str, Any]:
    manifest_path = bundle_dir / RELEASE_MANIFEST_NAME
    if not manifest_path.is_file():
        raise FileNotFoundError(
            f"Bundle directory is missing {RELEASE_MANIFEST_NAME}: {bundle_dir}"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise TypeError(f"{RELEASE_MANIFEST_NAME} must contain a JSON object")
    checksum_file = manifest.get("checksum_file")
    if checksum_file is not None and checksum_file != CHECKSUM_FILE_NAME:
        raise ValueError(
            f"{RELEASE_MANIFEST_NAME} advertises checksum_file={checksum_file}, expected {CHECKSUM_FILE_NAME}"
        )
    return manifest


def validate_manifest_contract(manifest: dict[str, Any], checksums: dict[str, str]) -> None:
    referenced_assets: set[str] = set()

    manifest_assets = manifest.get("assets")
    if manifest_assets is not None:
        if not isinstance(manifest_assets, list):
            raise TypeError(f"{RELEASE_MANIFEST_NAME} field 'assets' must be a list")
        for entry in manifest_assets:
            if not isinstance(entry, dict):
                raise TypeError(f"{RELEASE_MANIFEST_NAME} field 'assets' entries must be objects")
            asset_name = entry.get("name")
            if not isinstance(asset_name, str) or not asset_name:
                raise ValueError(f"{RELEASE_MANIFEST_NAME} field 'assets' entries must include a non-empty name")
            referenced_assets.add(asset_name)
            if asset_name not in checksums:
                raise FileNotFoundError(
                    f"{RELEASE_MANIFEST_NAME} references asset not present in {CHECKSUM_FILE_NAME}: {asset_name}"
                )

    for field_name in ("snapshot_asset", "snapshot_manifest"):
        asset_name = manifest.get(field_name)
        if asset_name is None:
            continue
        if not isinstance(asset_name, str) or not asset_name:
            raise ValueError(f"{RELEASE_MANIFEST_NAME} field '{field_name}' must be a non-empty string when present")
        if asset_name not in checksums:
            raise FileNotFoundError(
                f"{RELEASE_MANIFEST_NAME} field '{field_name}' points to missing asset: {asset_name}"
            )

    platform_assets = manifest.get("platform_assets")
    if platform_assets is not None:
        if not isinstance(platform_assets, dict):
            raise TypeError(f"{RELEASE_MANIFEST_NAME} field 'platform_assets' must be an object")
        for platform_id, entry in platform_assets.items():
            if not isinstance(entry, dict):
                raise TypeError(
                    f"{RELEASE_MANIFEST_NAME} platform_assets[{platform_id!r}] must be an object"
                )
            asset_name = entry.get("asset_name")
            if not isinstance(asset_name, str) or not asset_name:
                raise ValueError(
                    f"{RELEASE_MANIFEST_NAME} platform_assets[{platform_id!r}] must include a non-empty asset_name"
                )
            if asset_name not in checksums:
                raise FileNotFoundError(
                    f"{RELEASE_MANIFEST_NAME} platform_assets[{platform_id!r}] points to missing asset: {asset_name}"
                )
            referenced_assets.add(asset_name)


def verify_checksum_signature(checksum_path: Path, signature_path: Path, gpg_bin: str) -> None:
    result = subprocess.run(
        [gpg_bin, "--verify", str(signature_path), str(checksum_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "gpg --verify failed"
        raise RuntimeError(f"Checksum signature verification failed for {signature_path.name}: {message}")


def verify_bundle_signature(bundle_dir: Path, manifest: dict[str, Any], gpg_bin: str) -> None:
    checksum_path = bundle_dir / CHECKSUM_FILE_NAME
    signature_file = manifest.get("signature_file")
    signature_path = bundle_dir / "SHA256SUMS.asc"

    if isinstance(signature_file, str) and signature_file:
        signature_path = bundle_dir / signature_file
        if not signature_path.is_file():
            raise FileNotFoundError(
                f"Bundle directory is missing declared signature file {signature_file}: {bundle_dir}"
            )
        verify_checksum_signature(checksum_path, signature_path, gpg_bin)
        return

    if signature_path.is_file():
        verify_checksum_signature(checksum_path, signature_path, gpg_bin)


def curl_json(method: str, url: str, token: str | None = None, payload: dict[str, Any] | None = None) -> Any:
    cmd = [
        "curl",
        "-sS",
        "--fail",
        "-X",
        method,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {API_VERSION}",
    ]
    if token:
        cmd.extend(["-H", f"Authorization: Bearer {token}"])
    if payload is not None:
        cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(payload)])
    cmd.append(url)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"curl failed for {url}")
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def curl_binary(method: str, url: str, source: Path, token: str | None = None, content_type: str | None = None) -> None:
    cmd = [
        "curl",
        "-sS",
        "--fail",
        "-X",
        method,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {API_VERSION}",
    ]
    if token:
        cmd.extend(["-H", f"Authorization: Bearer {token}"])
    if content_type:
        cmd.extend(["-H", f"Content-Type: {content_type}"])
    cmd.extend(["--data-binary", f"@{source}", url])
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"curl upload failed for {source.name}")


def ensure_bundle(bundle_dir: Path) -> tuple[list[Path], dict[str, Any]]:
    if not bundle_dir.is_dir():
        raise FileNotFoundError(f"Bundle directory does not exist: {bundle_dir}")
    manifest = load_release_manifest(bundle_dir)
    assets = sorted(path for path in bundle_dir.iterdir() if path.is_file())
    if not assets:
        raise FileNotFoundError(f"Bundle directory is empty: {bundle_dir}")
    checksum_path = bundle_dir / CHECKSUM_FILE_NAME
    if not checksum_path.is_file():
        raise FileNotFoundError(f"Bundle directory is missing {CHECKSUM_FILE_NAME}: {bundle_dir}")
    checksums = parse_checksum_file(checksum_path)
    if not checksums:
        raise FileNotFoundError(f"{CHECKSUM_FILE_NAME} does not list any bundle assets: {bundle_dir}")

    names = {path.name for path in assets}
    missing = sorted(name for name in checksums if name not in names)
    if missing:
        raise FileNotFoundError(
            f"Bundle directory is missing files listed in {CHECKSUM_FILE_NAME}: {', '.join(missing)}"
        )
    unexpected = sorted(name for name in names if name not in checksums and name not in {CHECKSUM_FILE_NAME, *OPTIONAL_UNSIGNED_ASSETS})
    if unexpected:
        raise RuntimeError(
            f"Bundle directory contains files not listed in {CHECKSUM_FILE_NAME}: {', '.join(unexpected)}"
        )
    validate_manifest_contract(manifest, checksums)
    for asset_name, expected_sha256 in checksums.items():
        actual_sha256 = sha256_file(bundle_dir / asset_name)
        if actual_sha256.lower() != expected_sha256.lower():
            raise RuntimeError(
                f"SHA256SUMS mismatch for {asset_name}: expected {expected_sha256}, got {actual_sha256}"
            )
    return assets, manifest


def get_release(repo: str, tag: str, token: str) -> dict[str, Any] | None:
    url = f"https://api.github.com/repos/{repo}/releases/tags/{quote(tag, safe='')}"
    result = subprocess.run(
        [
            "curl",
            "-sS",
            "-X",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"Authorization: Bearer {token}",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
            "-w",
            "\n%{http_code}",
            url,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"curl failed for {url}")
    body, _, http_code = result.stdout.rpartition("\n")
    if http_code == "404":
        return None
    if http_code != "200":
        raise RuntimeError(f"Unexpected HTTP {http_code} for {url}: {body.strip()}")
    return json.loads(body)


def create_release(repo: str, tag: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases"
    return curl_json("POST", url, token=token, payload=payload)


def update_release(repo: str, release_id: int, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases/{release_id}"
    return curl_json("PATCH", url, token=token, payload=payload)


def delete_asset(repo: str, asset_id: int, token: str) -> None:
    url = f"https://api.github.com/repos/{repo}/releases/assets/{asset_id}"
    result = subprocess.run(
        [
            "curl",
            "-sS",
            "--fail",
            "-X",
            "DELETE",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"Authorization: Bearer {token}",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
            url,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or result.stdout.strip() or f"curl delete failed for release asset {asset_id}"
        )


def upload_asset(repo: str, release: dict[str, Any], asset: Path, token: str) -> None:
    upload_url = str(release["upload_url"]).split("{", 1)[0]
    asset_url = f"{upload_url}?name={quote(asset.name, safe='')}"
    content_type = mimetypes.guess_type(asset.name)[0] or "application/octet-stream"
    curl_binary("POST", asset_url, asset, token=token, content_type=content_type)


def read_body(body_file: str | None) -> str | None:
    if not body_file:
        return None
    return Path(body_file).read_text(encoding="utf-8")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    bundle_dir = Path(args.bundle_dir)
    assets, manifest = ensure_bundle(bundle_dir)
    token = read_token(args)

    if args.publish and args.draft:
        raise ValueError("--publish and --draft are mutually exclusive")

    draft = not args.publish if not args.draft else True
    release_name = args.release_name or args.tag
    body = read_body(args.body_file)
    release_payload = {
        "tag_name": args.tag,
        "name": release_name,
        "draft": draft,
        "prerelease": args.prerelease,
        "target_commitish": args.target_branch,
    }
    if body is not None:
        release_payload["body"] = body

    verify_bundle_signature(bundle_dir, manifest, args.gpg)

    if args.dry_run:
        print(json.dumps(
            {
                "repo": args.repo,
                "tag": args.tag,
                "release_name": release_name,
                "draft": draft,
                "prerelease": args.prerelease,
                "assets": [asset.name for asset in assets],
                "signature_file": manifest.get("signature_file"),
            },
            indent=2,
        ))
        return 0

    if not token:
        raise RuntimeError(
            "No GitHub token found. Set BTX_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN."
        )

    release = get_release(args.repo, args.tag, token)
    if release is None:
        release = create_release(args.repo, args.tag, token, release_payload)
    else:
        release = update_release(args.repo, int(release["id"]), token, release_payload)

    existing_assets = {asset["name"]: asset for asset in release.get("assets", [])}
    for asset in assets:
        existing = existing_assets.get(asset.name)
        if existing is not None:
            delete_asset(args.repo, int(existing["id"]), token)
        upload_asset(args.repo, release, asset, token)

    print(release["html_url"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
