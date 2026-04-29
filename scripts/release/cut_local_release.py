#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Prepare and optionally publish a native-built BTX CLI release bundle.

This command is the non-Guix companion to cut_release.py. It packages one or
more locally-built platform binaries into the canonical BTX operator archives,
stages them into a release bundle, validates the bundle against the GitHub
publisher contract, and optionally publishes the result.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


PLATFORM_SEPARATOR = ";"


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


def derive_version_from_tag(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def default_smoke_install_dir(bundle_dir: Path, platform_id: str) -> Path:
    return bundle_dir.parent / f"{bundle_dir.name}-smoke-{platform_id}"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="btxchain/btx", help="GitHub repository in owner/name form.")
    parser.add_argument("--tag", required=True, help="Release tag to stage or publish, for example v0.29.7.")
    parser.add_argument("--release-name", help="Human-readable release title. Defaults to the tag name.")
    parser.add_argument(
        "--repo-root",
        default=str(repo_root_from_script()),
        help="Repository root containing contrib/, scripts/, and docs/.",
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        help="Fresh output directory where the final release bundle will be staged.",
    )
    parser.add_argument(
        "--platform-spec",
        action="append",
        default=[],
        help=(
            "Platform packaging spec in the form "
            "'<platform-id>;<path-to-btxd>;<path-to-btx-cli>'. "
            "Repeat once per included platform."
        ),
    )
    parser.add_argument(
        "--source-root",
        help="Optional source root used to stage helper scripts/docs into platform archives (defaults to repo-root).",
    )
    parser.add_argument("--snapshot", help="Optional snapshot.dat to publish with the release bundle.")
    parser.add_argument("--snapshot-manifest", help="Optional snapshot.manifest.json to publish with the release bundle.")
    parser.add_argument(
        "--release-source",
        action="append",
        default=[],
        help="Additional file or directory to include in the final release bundle.",
    )
    parser.add_argument(
        "--checksum-signature",
        help="Optional externally-produced SHA256SUMS.asc to stage in the bundle.",
    )
    parser.add_argument(
        "--sign-with",
        help="Optional GPG key name used to sign SHA256SUMS inside the bundle.",
    )
    parser.add_argument(
        "--gpg-passphrase-env",
        help=(
            "Optional environment variable name whose value should be piped to gpg via "
            "--pinentry-mode loopback when --sign-with is used."
        ),
    )
    parser.add_argument("--gpg", default="gpg", help="GPG binary used by the release helpers.")
    parser.add_argument("--body-file", help="Optional markdown file used as the GitHub Release body.")
    parser.add_argument("--token", help="Explicit GitHub API token passed to publish_github_release.py.")
    parser.add_argument("--token-file", help="Path to a file containing the GitHub API token.")
    parser.add_argument("--publish", action="store_true", help="Publish the bundle to GitHub Releases after staging and validation.")
    parser.add_argument("--prerelease", action="store_true", help="Mark the GitHub Release as a prerelease when publishing.")
    parser.add_argument("--draft", action="store_true", help="Keep the GitHub Release in draft state when publishing.")
    parser.add_argument("--smoke-platform", help="Optional platform id to smoke-install from the staged bundle with btx-agent-setup.py before publish.")
    parser.add_argument("--smoke-install-dir", help="Optional install directory used by the btx-agent-setup smoke install.")
    return parser.parse_args(argv)


def run_checked(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=str(cwd) if cwd else None, check=True)


def parse_platform_spec(raw_spec: str) -> dict[str, Path | str]:
    parts = raw_spec.split(PLATFORM_SEPARATOR)
    if len(parts) != 3:
        raise ValueError(
            f"Invalid --platform-spec {raw_spec!r}; expected "
            f"'<platform-id>{PLATFORM_SEPARATOR}<path-to-btxd>{PLATFORM_SEPARATOR}<path-to-btx-cli>'"
        )
    platform_id, btxd_raw, btx_cli_raw = (part.strip() for part in parts)
    if not platform_id or not btxd_raw or not btx_cli_raw:
        raise ValueError(f"Invalid --platform-spec {raw_spec!r}; no field may be empty")
    btxd = Path(btxd_raw).expanduser().resolve()
    btx_cli = Path(btx_cli_raw).expanduser().resolve()
    if not btxd.is_file():
        raise FileNotFoundError(f"Missing btxd for platform {platform_id}: {btxd}")
    if not btx_cli.is_file():
        raise FileNotFoundError(f"Missing btx-cli for platform {platform_id}: {btx_cli}")
    return {"platform_id": platform_id, "btxd": btxd, "btx_cli": btx_cli}


def resolve_platform_specs(raw_specs: list[str]) -> list[dict[str, Path | str]]:
    if not raw_specs:
        raise ValueError("At least one --platform-spec is required")
    specs = [parse_platform_spec(raw_spec) for raw_spec in raw_specs]
    platform_ids = [str(spec["platform_id"]) for spec in specs]
    duplicates = sorted(platform_id for platform_id in set(platform_ids) if platform_ids.count(platform_id) > 1)
    if duplicates:
        raise ValueError("Duplicate platform ids in --platform-spec: " + ", ".join(duplicates))
    return specs


def build_package_command(
    repo_root: Path,
    output_dir: Path,
    *,
    version: str,
    source_root: Path,
    spec: dict[str, Path | str],
) -> list[str]:
    return [
        sys.executable,
        str(repo_root / "scripts" / "release" / "package_release_archive.py"),
        "--output-dir",
        str(output_dir),
        "--version",
        version,
        "--platform-id",
        str(spec["platform_id"]),
        "--btxd",
        str(spec["btxd"]),
        "--btx-cli",
        str(spec["btx_cli"]),
        "--source-root",
        str(source_root),
    ]


def build_collect_command(
    args: argparse.Namespace,
    repo_root: Path,
    archive_dir: Path,
    platform_ids: list[str],
) -> list[str]:
    command = [
        sys.executable,
        str(repo_root / "scripts" / "release" / "collect_release_assets.py"),
        "--output-dir",
        args.bundle_dir,
        "--release-tag",
        args.tag,
        "--release-name",
        args.release_name or args.tag,
        "--gpg",
        args.gpg,
        "--source",
        str(archive_dir),
    ]
    if args.snapshot:
        command.extend(["--snapshot", args.snapshot])
    if args.snapshot_manifest:
        command.extend(["--snapshot-manifest", args.snapshot_manifest])
    if args.checksum_signature:
        command.extend(["--checksum-signature", args.checksum_signature])
    if args.sign_with:
        command.extend(["--sign-with", args.sign_with])
    if args.gpg_passphrase_env:
        command.extend(["--gpg-passphrase-env", args.gpg_passphrase_env])
    for platform_id in platform_ids:
        command.extend(["--required-platform", platform_id])
    for extra_source in args.release_source:
        command.extend(["--source", extra_source])
    return command


def build_publish_command(
    args: argparse.Namespace,
    repo_root: Path,
    *,
    dry_run: bool,
) -> list[str]:
    command = [
        sys.executable,
        str(repo_root / "scripts" / "release" / "publish_github_release.py"),
        "--repo",
        args.repo,
        "--tag",
        args.tag,
        "--bundle-dir",
        args.bundle_dir,
        "--gpg",
        args.gpg,
    ]
    if args.release_name:
        command.extend(["--release-name", args.release_name])
    if args.body_file:
        command.extend(["--body-file", args.body_file])
    if args.token:
        command.extend(["--token", args.token])
    if args.token_file:
        command.extend(["--token-file", args.token_file])
    if args.prerelease:
        command.append("--prerelease")
    if args.draft:
        command.append("--draft")
    if args.publish and not dry_run:
        command.append("--publish")
    if dry_run:
        command.append("--dry-run")
    return command


def build_smoke_install_command(args: argparse.Namespace, repo_root: Path) -> list[str] | None:
    if not args.smoke_platform:
        return None
    bundle_dir = Path(args.bundle_dir).resolve()
    install_dir = (
        Path(args.smoke_install_dir).resolve()
        if args.smoke_install_dir
        else default_smoke_install_dir(bundle_dir, args.smoke_platform)
    )
    return [
        sys.executable,
        str(repo_root / "contrib" / "faststart" / "btx-agent-setup.py"),
        "--release-manifest",
        str(bundle_dir / "btx-release-manifest.json"),
        "--platform",
        args.smoke_platform,
        "--install-dir",
        str(install_dir),
        "--force",
        "--gpg",
        args.gpg,
        "--json",
    ]


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    source_root = Path(args.source_root).resolve() if args.source_root else repo_root
    bundle_dir = Path(args.bundle_dir).resolve()
    platform_specs = resolve_platform_specs(list(args.platform_spec))
    platform_ids = [str(spec["platform_id"]) for spec in platform_specs]

    if (args.snapshot is None) != (args.snapshot_manifest is None):
        raise ValueError("snapshot.dat and snapshot.manifest.json must be provided together")

    with tempfile.TemporaryDirectory(prefix="btx-local-release-archives-") as archive_temp:
        archive_dir = Path(archive_temp)
        for spec in platform_specs:
            run_checked(
                build_package_command(
                    repo_root,
                    archive_dir,
                    version=derive_version_from_tag(args.tag),
                    source_root=source_root,
                    spec=spec,
                ),
                cwd=repo_root,
            )

        run_checked(build_collect_command(args, repo_root, archive_dir, platform_ids), cwd=repo_root)

    run_checked(build_publish_command(args, repo_root, dry_run=True), cwd=repo_root)

    smoke_install_command = build_smoke_install_command(args, repo_root)
    if smoke_install_command is not None:
        run_checked(smoke_install_command, cwd=repo_root)

    published = False
    if args.publish:
        run_checked(build_publish_command(args, repo_root, dry_run=False), cwd=repo_root)
        published = True

    summary = {
        "repo_root": str(repo_root),
        "source_root": str(source_root),
        "bundle_dir": str(bundle_dir),
        "release_tag": args.tag,
        "release_name": args.release_name or args.tag,
        "platform_ids": platform_ids,
        "snapshot": str(Path(args.snapshot).resolve()) if args.snapshot else None,
        "snapshot_manifest": str(Path(args.snapshot_manifest).resolve()) if args.snapshot_manifest else None,
        "smoke_platform": args.smoke_platform,
        "smoke_install_dir": (
            str(Path(args.smoke_install_dir).resolve())
            if args.smoke_install_dir
            else (
                str(default_smoke_install_dir(bundle_dir, args.smoke_platform))
                if args.smoke_platform
                else None
            )
        ),
        "published": published,
    }
    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
