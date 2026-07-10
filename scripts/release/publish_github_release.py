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
import re
import subprocess
import sys
from urllib.parse import quote
from typing import Any


API_VERSION = "2022-11-28"
TOKEN_ENV_VARS = ("BTX_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")
CHECKSUM_FILE_NAME = "SHA256SUMS"
RELEASE_MANIFEST_NAME = "btx-release-manifest.json"
OPTIONAL_UNSIGNED_ASSETS = {"SHA256SUMS.asc"}
PUBLIC_RELEASE_REPOSITORY = "btxchain/btx"
HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")


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
        "--target-commit",
        help=(
            "Exact 40-character commit to associate with the release tag. "
            "Required for publication to btxchain/btx."
        ),
    )
    parser.add_argument(
        "--expected-signing-fingerprint",
        help=(
            "Expected 40-character OpenPGP fingerprint for SHA256SUMS. "
            "Required for publication to btxchain/btx."
        ),
    )
    parser.add_argument(
        "--validate-public-release",
        action="store_true",
        help="Apply the strict btxchain/btx provenance and signing gates during a dry run.",
    )
    parser.add_argument(
        "--allow-public-recovery",
        action="store_true",
        help=(
            "Explicitly allow replacing assets on an already-public release. "
            "Without this recovery flag, public releases are immutable."
        ),
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


def curl_auth_config(token: str | None) -> str | None:
    if token is None:
        return None
    if any(character in token for character in ('\r', '\n', '"', '\\')):
        raise ValueError("GitHub token contains characters unsafe for curl config input")
    return f'header = "Authorization: Bearer {token}"\n'


def run_curl(command: list[str], *, token: str | None = None) -> subprocess.CompletedProcess[str]:
    auth_config = curl_auth_config(token)
    if auth_config is not None:
        command[1:1] = ["--config", "-"]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        input=auth_config,
    )


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


def normalize_fingerprint(value: str) -> str:
    normalized = "".join(value.split()).upper()
    if not HEX40_RE.fullmatch(normalized):
        raise ValueError("OpenPGP fingerprint must contain exactly 40 hexadecimal characters")
    return normalized


def verify_checksum_signature(checksum_path: Path, signature_path: Path, gpg_bin: str) -> set[str]:
    result = subprocess.run(
        [gpg_bin, "--status-fd=1", "--verify", str(signature_path), str(checksum_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "gpg --verify failed"
        raise RuntimeError(f"Checksum signature verification failed for {signature_path.name}: {message}")
    fingerprints: set[str] = set()
    for line in result.stdout.splitlines():
        if not line.startswith("[GNUPG:] VALIDSIG "):
            continue
        for token in line.split()[2:]:
            if HEX40_RE.fullmatch(token):
                fingerprints.add(token.upper())
    if not fingerprints:
        raise RuntimeError(
            f"Checksum signature verification for {signature_path.name} returned no VALIDSIG fingerprint"
        )
    return fingerprints


def verify_bundle_signature(
    bundle_dir: Path,
    manifest: dict[str, Any],
    gpg_bin: str,
    *,
    required: bool = False,
    expected_fingerprint: str | None = None,
) -> set[str]:
    checksum_path = bundle_dir / CHECKSUM_FILE_NAME
    signature_file = manifest.get("signature_file")
    signature_path = bundle_dir / "SHA256SUMS.asc"

    if isinstance(signature_file, str) and signature_file:
        if signature_file != "SHA256SUMS.asc":
            raise ValueError(
                f"{RELEASE_MANIFEST_NAME} signature_file must be exactly SHA256SUMS.asc"
            )
        signature_path = bundle_dir / "SHA256SUMS.asc"
        if not signature_path.is_file():
            raise FileNotFoundError(
                f"Bundle directory is missing declared signature file {signature_file}: {bundle_dir}"
            )
        fingerprints = verify_checksum_signature(checksum_path, signature_path, gpg_bin) or set()
    elif signature_path.is_file():
        fingerprints = verify_checksum_signature(checksum_path, signature_path, gpg_bin) or set()
    elif required:
        raise FileNotFoundError("Public release bundles must include a declared SHA256SUMS signature")
    else:
        return set()

    if expected_fingerprint is not None:
        expected = normalize_fingerprint(expected_fingerprint)
        if expected not in fingerprints:
            actual = ", ".join(sorted(fingerprints)) or "none"
            raise RuntimeError(
                f"Checksum signature signer mismatch: expected {expected}, got {actual}"
            )
    return fingerprints


def validate_release_identity(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    *,
    strict_public_release: bool,
) -> str | None:
    manifest_tag = manifest.get("release_tag")
    if manifest_tag is not None and manifest_tag != args.tag:
        raise ValueError(
            f"Release tag mismatch: bundle manifest has {manifest_tag!r}, command requested {args.tag!r}"
        )

    target_commit = args.target_commit
    if target_commit is not None and not HEX40_RE.fullmatch(target_commit):
        raise ValueError("--target-commit must be exactly 40 hexadecimal characters")
    if not strict_public_release:
        return target_commit

    source_repository = manifest.get("source_repository")
    source_commit = manifest.get("source_commit")
    if source_repository != args.repo:
        raise ValueError(
            f"Public release source repository mismatch: expected {args.repo}, got {source_repository!r}"
        )
    if not isinstance(source_commit, str) or not HEX40_RE.fullmatch(source_commit):
        raise ValueError("Public release manifest must record an exact 40-character source_commit")
    if target_commit != source_commit:
        raise ValueError(
            "Public release --target-commit must exactly match the bundle manifest source_commit"
        )
    if manifest_tag != args.tag:
        raise ValueError("Public release manifest must record the exact requested release_tag")
    if not args.expected_signing_fingerprint:
        raise ValueError("Public releases require --expected-signing-fingerprint")
    return target_commit


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
    if payload is not None:
        cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(payload)])
    cmd.append(url)
    result = run_curl(cmd, token=token)
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
    if content_type:
        cmd.extend(["-H", f"Content-Type: {content_type}"])
    cmd.extend(["--data-binary", f"@{source}", url])
    result = run_curl(cmd, token=token)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"curl upload failed for {source.name}")


def ensure_bundle(bundle_dir: Path) -> tuple[list[Path], dict[str, Any]]:
    if not bundle_dir.is_dir():
        raise FileNotFoundError(f"Bundle directory does not exist: {bundle_dir}")
    manifest = load_release_manifest(bundle_dir)
    children = list(bundle_dir.iterdir())
    symlinks = sorted(path.name for path in children if path.is_symlink())
    if symlinks:
        raise RuntimeError(
            f"Bundle directory must not contain symbolic links: {', '.join(symlinks)}"
        )
    assets = sorted(path for path in children if path.is_file())
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
    result = run_curl(
        [
            "curl",
            "-sS",
            "-X",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            f"X-GitHub-Api-Version: {API_VERSION}",
            "-w",
            "\n%{http_code}",
            url,
        ],
        token=token,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"curl failed for {url}")
    body, _, http_code = result.stdout.rpartition("\n")
    if http_code == "404":
        return None
    if http_code != "200":
        raise RuntimeError(f"Unexpected HTTP {http_code} for {url}: {body.strip()}")
    return json.loads(body)


def require_repository_commit(repo: str, commit: str, token: str) -> None:
    result = curl_json(
        "GET",
        f"https://api.github.com/repos/{repo}/commits/{quote(commit, safe='')}",
        token=token,
    )
    actual = result.get("sha") if isinstance(result, dict) else None
    if actual != commit:
        raise RuntimeError(
            f"Target repository {repo} did not resolve the exact release commit {commit}"
        )


def resolve_repository_commit(repo: str, ref: str, token: str) -> str | None:
    url = f"https://api.github.com/repos/{repo}/commits/{quote(ref, safe='')}"
    result = run_curl(
        [
            "curl",
            "-sS",
            "-X",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            f"X-GitHub-Api-Version: {API_VERSION}",
            "-w",
            "\n%{http_code}",
            url,
        ],
        token=token,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"curl failed for {url}")
    body, _, http_code = result.stdout.rpartition("\n")
    if http_code == "404":
        return None
    if http_code != "200":
        raise RuntimeError(f"Unexpected HTTP {http_code} for {url}: {body.strip()}")
    payload = json.loads(body)
    commit = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(commit, str) or not HEX40_RE.fullmatch(commit):
        raise RuntimeError(f"GitHub returned an invalid commit for {repo}@{ref}")
    return commit


def validate_uploaded_assets(release: dict[str, Any], assets: list[Path]) -> None:
    expected = {asset.name: asset.stat().st_size for asset in assets}
    remote_assets = release.get("assets", [])
    if not isinstance(remote_assets, list):
        raise RuntimeError("GitHub release response did not include an asset list")
    actual: dict[str, int] = {}
    for entry in remote_assets:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        size = entry.get("size")
        if isinstance(name, str) and isinstance(size, int):
            actual[name] = size
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        wrong_size = sorted(
            name for name in set(expected) & set(actual) if expected[name] != actual[name]
        )
        raise RuntimeError(
            "Uploaded release asset verification failed "
            f"(missing={missing}, extra={extra}, wrong_size={wrong_size})"
        )


def create_release(repo: str, tag: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases"
    return curl_json("POST", url, token=token, payload=payload)


def update_release(repo: str, release_id: int, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/releases/{release_id}"
    return curl_json("PATCH", url, token=token, payload=payload)


def delete_asset(repo: str, asset_id: int, token: str) -> None:
    url = f"https://api.github.com/repos/{repo}/releases/assets/{asset_id}"
    result = run_curl(
        [
            "curl",
            "-sS",
            "--fail",
            "-X",
            "DELETE",
            "-H",
            "Accept: application/vnd.github+json",
            f"X-GitHub-Api-Version: {API_VERSION}",
            url,
        ],
        token=token,
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

    strict_public_release = args.repo.lower() == PUBLIC_RELEASE_REPOSITORY and (
        args.publish or args.validate_public_release
    )
    target_commit = validate_release_identity(
        args,
        manifest,
        strict_public_release=strict_public_release,
    )

    draft = not args.publish if not args.draft else True
    release_name = args.release_name or args.tag
    body = read_body(args.body_file)
    release_payload = {
        "tag_name": args.tag,
        "name": release_name,
        "draft": draft,
        "prerelease": args.prerelease,
        "target_commitish": target_commit or args.target_branch,
    }
    if body is not None:
        release_payload["body"] = body

    verified_fingerprints = verify_bundle_signature(
        bundle_dir,
        manifest,
        args.gpg,
        required=strict_public_release,
        expected_fingerprint=(
            args.expected_signing_fingerprint if strict_public_release else None
        ),
    )

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
                "verified_signing_fingerprints": sorted(verified_fingerprints),
                "target_commit": target_commit,
            },
            indent=2,
        ))
        return 0

    if not token:
        raise RuntimeError(
            "No GitHub token found. Set BTX_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN."
        )

    if strict_public_release:
        assert target_commit is not None
        require_repository_commit(args.repo, target_commit, token)

        existing_tag_commit = resolve_repository_commit(args.repo, args.tag, token)
        if existing_tag_commit is not None and existing_tag_commit != target_commit:
            raise RuntimeError(
                f"Existing tag {args.tag} resolves to {existing_tag_commit}, "
                f"not the authorized release commit {target_commit}"
            )

    release = get_release(args.repo, args.tag, token)
    if strict_public_release:
        if release is not None and release.get("draft", True) is False and not args.allow_public_recovery:
            raise RuntimeError(
                "Refusing to replace assets on an already-public release; "
                "use --allow-public-recovery only for an explicitly approved recovery"
            )
        staging_payload = dict(release_payload)
        staging_payload["draft"] = True
        if release is None:
            release = create_release(args.repo, args.tag, token, staging_payload)
        else:
            release = update_release(args.repo, int(release["id"]), token, staging_payload)
    elif release is None:
        release = create_release(args.repo, args.tag, token, release_payload)
    else:
        release = update_release(args.repo, int(release["id"]), token, release_payload)

    existing_assets = {asset["name"]: asset for asset in release.get("assets", [])}
    for asset in assets:
        existing = existing_assets.get(asset.name)
        if existing is not None:
            delete_asset(args.repo, int(existing["id"]), token)
        upload_asset(args.repo, release, asset, token)

    if strict_public_release:
        refreshed = get_release(args.repo, args.tag, token)
        if refreshed is None:
            raise RuntimeError("GitHub release disappeared while verifying staged assets")
        validate_uploaded_assets(refreshed, assets)
        release = refreshed
        if args.publish:
            final_payload = dict(release_payload)
            final_payload["draft"] = False
            release = update_release(args.repo, int(release["id"]), token, final_payload)

    print(release["html_url"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
