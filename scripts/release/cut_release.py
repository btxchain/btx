#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Prepare and optionally publish a BTX GitHub release bundle.

This command ties together the existing BTX release helpers so operators can
run one release-cut command instead of manually coordinating Guix outputs,
assumeutxo snapshot generation, bundle staging, and GitHub publication.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


PRIMARY_GUIX_HOSTS = (
    "x86_64-linux-gnu",
    "aarch64-linux-gnu",
    "x86_64-w64-mingw32",
    "x86_64-apple-darwin",
    "arm64-apple-darwin",
)
PRIMARY_HOST_PATTERNS = {
    "x86_64-linux-gnu": ("*-x86_64-linux-gnu.tar.gz",),
    "aarch64-linux-gnu": ("*-aarch64-linux-gnu.tar.gz",),
    "x86_64-w64-mingw32": ("*-win64-pgpverifiable.zip",),
    "x86_64-apple-darwin": ("*-x86_64-apple-darwin-unsigned.tar.gz",),
    "arm64-apple-darwin": ("*-arm64-apple-darwin-unsigned.tar.gz",),
}


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


def derive_version_from_tag(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def default_guix_output_dir(repo_root: Path, tag: str) -> Path:
    return repo_root / f"guix-build-{derive_version_from_tag(tag)}" / "output"


def default_attestations_dir(repo_root: Path, tag: str) -> Path:
    return repo_root.parent / "guix.sigs" / derive_version_from_tag(tag)


def default_snapshot_dir(repo_root: Path, tag: str) -> Path:
    return repo_root / "release-artifacts" / derive_version_from_tag(tag) / "snapshot"


def default_smoke_install_dir(bundle_dir: Path, platform_id: str) -> Path:
    return bundle_dir.parent / f"{bundle_dir.name}-smoke-{platform_id}"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="btxchain/btx", help="GitHub repository in owner/name form.")
    parser.add_argument("--tag", required=True, help="Release tag to stage or publish, for example v0.29.6.")
    parser.add_argument("--release-name", help="Human-readable release title. Defaults to the tag name.")
    parser.add_argument(
        "--repo-root",
        default=str(repo_root_from_script()),
        help="Repository root containing contrib/, scripts/, and optional guix-build-* outputs.",
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        help="Fresh output directory where the final release bundle will be staged.",
    )
    parser.add_argument(
        "--body-file",
        help="Optional markdown file used as the GitHub Release body.",
    )
    parser.add_argument(
        "--build-with-guix",
        action="store_true",
        help="Run contrib/guix/guix-build before staging the bundle.",
    )
    parser.add_argument(
        "--guix-output-dir",
        help="Path to the Guix output directory containing per-host release archives.",
    )
    parser.add_argument(
        "--guix-host",
        action="append",
        default=[],
        help=(
            "Guix host triple to require and stage. Defaults to the BTX primary release set: "
            + ", ".join(PRIMARY_GUIX_HOSTS)
        ),
    )
    parser.add_argument(
        "--guix-jobs",
        type=int,
        help="Optional JOBS value exported while running contrib/guix/guix-build.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Additional file or directory to include in the final bundle.",
    )
    parser.add_argument(
        "--attestations-dir",
        action="append",
        default=[],
        help="Optional guix.sigs release directory containing signer attestations.",
    )
    parser.add_argument(
        "--snapshot",
        help="Existing snapshot.dat path to publish.",
    )
    parser.add_argument(
        "--snapshot-manifest",
        help="Existing snapshot.manifest.json path to publish.",
    )
    parser.add_argument(
        "--generate-snapshot",
        action="store_true",
        help="Generate snapshot.dat and snapshot.manifest.json with generate_assumeutxo.py.",
    )
    parser.add_argument(
        "--snapshot-out",
        help="Snapshot path used when --generate-snapshot is set. Defaults under release-artifacts/<version>/snapshot/.",
    )
    parser.add_argument(
        "--snapshot-manifest-out",
        help="Manifest path used when --generate-snapshot is set. Defaults under release-artifacts/<version>/snapshot/.",
    )
    parser.add_argument(
        "--snapshot-report-out",
        help="JSON report path used when --generate-snapshot is set. Defaults under release-artifacts/<version>/snapshot/.",
    )
    parser.add_argument("--btx-cli", default="btx-cli", help="Path to btx-cli for snapshot generation.")
    parser.add_argument("--chain", default="main", help="Human-readable chain label for snapshot generation.")
    parser.add_argument(
        "--snapshot-type",
        choices=("latest", "rollback"),
        default="rollback",
        help="Snapshot mode passed to generate_assumeutxo.py (default: rollback).",
    )
    parser.add_argument("--rollback", help="Rollback height or blockhash for rollback snapshots.")
    parser.add_argument(
        "--rpc-arg",
        action="append",
        default=[],
        help="Extra argument forwarded to btx-cli during snapshot generation.",
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
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish the bundle to GitHub Releases after staging and validation.",
    )
    parser.add_argument(
        "--token",
        help="Explicit GitHub API token passed to publish_github_release.py.",
    )
    parser.add_argument(
        "--token-file",
        help="Path to a file containing the GitHub API token.",
    )
    parser.add_argument(
        "--prerelease",
        action="store_true",
        help="Mark the GitHub Release as a prerelease when publishing.",
    )
    parser.add_argument(
        "--draft",
        action="store_true",
        help="Keep the GitHub Release in draft state when publishing.",
    )
    parser.add_argument(
        "--smoke-platform",
        help="Optional platform id to smoke-install from the staged bundle with btx-agent-setup.py before publish.",
    )
    parser.add_argument(
        "--smoke-install-dir",
        help="Optional install directory used by the btx-agent-setup smoke install.",
    )
    return parser.parse_args(argv)


def run_checked(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=str(cwd) if cwd else None, env=env, check=True)


def resolve_guix_hosts(args: argparse.Namespace) -> list[str]:
    return list(args.guix_host) if args.guix_host else list(PRIMARY_GUIX_HOSTS)


def resolve_guix_output_dir(args: argparse.Namespace, repo_root: Path) -> Path:
    if args.guix_output_dir:
        return Path(args.guix_output_dir)
    return default_guix_output_dir(repo_root, args.tag)


def resolve_attestation_dirs(args: argparse.Namespace, repo_root: Path) -> list[Path]:
    if args.attestations_dir:
        return [Path(path) for path in args.attestations_dir]
    default_dir = default_attestations_dir(repo_root, args.tag)
    return [default_dir] if default_dir.is_dir() else []


def ensure_source_dirs(guix_output_dir: Path, hosts: list[str]) -> list[Path]:
    missing: list[str] = []
    source_dirs: list[Path] = []
    for host in hosts:
        source_dir = guix_output_dir / host
        if not source_dir.is_dir():
            missing.append(str(source_dir))
            continue
        source_dirs.append(source_dir)
    if missing:
        raise FileNotFoundError(
            "Missing required Guix output directories: " + ", ".join(missing)
        )
    return source_dirs


def find_primary_archive_for_host(source_dir: Path, host: str) -> Path:
    patterns = PRIMARY_HOST_PATTERNS.get(host)
    if patterns is None:
        raise KeyError(f"Unsupported Guix host for primary archive selection: {host}")
    matches = sorted(
        {
            path.resolve()
            for pattern in patterns
            for path in source_dir.glob(pattern)
            if path.is_file()
        }
    )
    if not matches:
        raise FileNotFoundError(
            f"Could not find the canonical primary archive for {host} in {source_dir}"
        )
    if len(matches) != 1:
        raise FileExistsError(
            f"Expected exactly one canonical primary archive for {host} in {source_dir}, found: "
            + ", ".join(str(path.name) for path in matches)
        )
    return matches[0]


def resolve_primary_archives(source_dirs: list[Path], hosts: list[str]) -> list[Path]:
    if len(source_dirs) != len(hosts):
        raise ValueError("source_dirs and hosts must have the same length")
    return [
        find_primary_archive_for_host(source_dir, host)
        for source_dir, host in zip(source_dirs, hosts)
    ]


def maybe_run_guix_build(args: argparse.Namespace, repo_root: Path, hosts: list[str]) -> None:
    if not args.build_with_guix:
        return
    env = os.environ.copy()
    env["HOSTS"] = " ".join(hosts)
    if args.guix_jobs is not None:
        env["JOBS"] = str(args.guix_jobs)
    run_checked([str(repo_root / "contrib" / "guix" / "guix-build")], cwd=repo_root, env=env)


def maybe_generate_snapshot(args: argparse.Namespace, repo_root: Path) -> tuple[Path | None, Path | None, Path | None]:
    if not args.generate_snapshot:
        snapshot = Path(args.snapshot) if args.snapshot else None
        snapshot_manifest = Path(args.snapshot_manifest) if args.snapshot_manifest else None
        return snapshot, snapshot_manifest, None

    if args.snapshot or args.snapshot_manifest:
        raise ValueError(
            "--generate-snapshot cannot be combined with --snapshot or --snapshot-manifest"
        )
    if args.snapshot_type == "rollback" and not args.rollback:
        raise ValueError("--rollback is required when --snapshot-type=rollback")

    default_dir = default_snapshot_dir(repo_root, args.tag)
    snapshot_path = Path(args.snapshot_out) if args.snapshot_out else default_dir / "snapshot.dat"
    snapshot_manifest_path = (
        Path(args.snapshot_manifest_out)
        if args.snapshot_manifest_out
        else default_dir / "snapshot.manifest.json"
    )
    snapshot_report_path = (
        Path(args.snapshot_report_out)
        if args.snapshot_report_out
        else default_dir / "snapshot.report.json"
    )
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_report_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(repo_root / "contrib" / "devtools" / "generate_assumeutxo.py"),
        "--btx-cli",
        args.btx_cli,
        "--chain",
        args.chain,
        "--snapshot",
        str(snapshot_path),
        "--snapshot-type",
        args.snapshot_type,
        "--manifest-out",
        str(snapshot_manifest_path),
        "--json-out",
        str(snapshot_report_path),
    ]
    if args.rollback:
        command.extend(["--rollback", args.rollback])
    for rpc_arg in args.rpc_arg:
        command.extend(["--rpc-arg", rpc_arg])

    run_checked(command, cwd=repo_root)
    return snapshot_path, snapshot_manifest_path, snapshot_report_path


def build_collect_command(
    args: argparse.Namespace,
    repo_root: Path,
    primary_archives: list[Path],
    attestation_dirs: list[Path],
    snapshot: Path | None,
    snapshot_manifest: Path | None,
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
    ]
    for source_path in [*primary_archives, *(Path(path) for path in args.source)]:
        command.extend(["--source", str(source_path)])
    for attestation_dir in attestation_dirs:
        command.extend(["--attestations-dir", str(attestation_dir)])
    if snapshot is not None:
        command.extend(["--snapshot", str(snapshot)])
    if snapshot_manifest is not None:
        command.extend(["--snapshot-manifest", str(snapshot_manifest)])
    if args.checksum_signature:
        command.extend(["--checksum-signature", args.checksum_signature])
    if args.sign_with:
        command.extend(["--sign-with", args.sign_with])
    if args.gpg_passphrase_env:
        command.extend(["--gpg-passphrase-env", args.gpg_passphrase_env])
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
    bundle_dir = Path(args.bundle_dir).resolve()
    hosts = resolve_guix_hosts(args)

    maybe_run_guix_build(args, repo_root, hosts)
    guix_output_dir = resolve_guix_output_dir(args, repo_root)
    source_dirs = ensure_source_dirs(guix_output_dir, hosts)
    primary_archives = resolve_primary_archives(source_dirs, hosts)
    attestation_dirs = resolve_attestation_dirs(args, repo_root)
    snapshot, snapshot_manifest, snapshot_report = maybe_generate_snapshot(args, repo_root)

    if (snapshot is None) != (snapshot_manifest is None):
        raise ValueError(
            "snapshot.dat and snapshot.manifest.json must be provided together"
        )

    collect_command = build_collect_command(
        args,
        repo_root,
        primary_archives,
        attestation_dirs,
        snapshot,
        snapshot_manifest,
    )
    run_checked(collect_command, cwd=repo_root)

    dry_run_publish_command = build_publish_command(args, repo_root, dry_run=True)
    run_checked(dry_run_publish_command, cwd=repo_root)

    smoke_install_command = build_smoke_install_command(args, repo_root)
    if smoke_install_command is not None:
        run_checked(smoke_install_command, cwd=repo_root)

    published = False
    if args.publish:
        publish_command = build_publish_command(args, repo_root, dry_run=False)
        run_checked(publish_command, cwd=repo_root)
        published = True

    summary = {
        "repo_root": str(repo_root),
        "bundle_dir": str(bundle_dir),
        "release_tag": args.tag,
        "release_name": args.release_name or args.tag,
        "guix_output_dir": str(guix_output_dir),
        "guix_hosts": hosts,
        "primary_archives": [str(path) for path in primary_archives],
        "attestations_dir": [str(path) for path in attestation_dirs],
        "snapshot": str(snapshot) if snapshot else None,
        "snapshot_manifest": str(snapshot_manifest) if snapshot_manifest else None,
        "snapshot_report": str(snapshot_report) if snapshot_report else None,
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
