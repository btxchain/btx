#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Collect BTX release assets into a single publishable bundle.

The script is intentionally simple:

- copy one or more source files or directories into a fresh bundle directory
- add the fast-start snapshot artifacts as first-class release assets
- emit a release manifest and SHA256SUMS file for the final bundle

Directory sources are flattened into the bundle directory. Asset names must be
unique after flattening.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable


CHECKSUM_BASENAMES = {"SHA256SUMS", "SHA256SUMS.asc"}
CHECKSUM_PREFIXES = ("SHA256SUMS.part",)
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".zip")
GUIX_ATTESTATION_FILE_NAMES = (
    "noncodesigned.SHA256SUMS",
    "noncodesigned.SHA256SUMS.asc",
    "all.SHA256SUMS",
    "all.SHA256SUMS.asc",
)
PRIMARY_BINARY_EXCLUDE_TOKENS = (
    "codesign",
    "codesigning",
    "debug",
    "detached",
    "signature",
    "signatures",
    "src",
    "source",
)
PLATFORM_ALIASES = {
    "linux-x86_64": ("x86_64-linux-gnu",),
    "linux-arm64": ("aarch64-linux-gnu", "arm64-linux-gnu"),
    "windows-x86_64": ("x86_64-w64-mingw32", "win64"),
    "macos-x86_64": ("x86_64-apple-darwin",),
    "macos-arm64": ("arm64-apple-darwin", "aarch64-apple-darwin"),
}
DEFAULT_REQUIRED_PLATFORMS = tuple(PLATFORM_ALIASES.keys())


@dataclass(frozen=True)
class StagedAsset:
    name: str
    path: Path
    sha256: str
    size_bytes: int
    source: str


def detect_archive_format(name: str) -> str | None:
    lowered = name.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            return suffix.lstrip(".")
    return None


def classify_primary_platform_asset(name: str) -> dict[str, str] | None:
    archive_format = detect_archive_format(name)
    if archive_format is None:
        return None

    lowered = name.lower()
    if any(token in lowered for token in PRIMARY_BINARY_EXCLUDE_TOKENS):
        return None

    for platform_id, aliases in PLATFORM_ALIASES.items():
        if any(alias in lowered for alias in aliases):
            operating_system, arch = platform_id.split("-", 1)
            return {
                "platform_id": platform_id,
                "os": operating_system,
                "arch": arch,
                "asset_name": name,
                "archive_format": archive_format,
                "kind": "primary_binary_archive",
            }
    return None


def collect_platform_assets(staged_assets: list[tuple[str, Path]]) -> dict[str, dict[str, str]]:
    platforms: dict[str, dict[str, str]] = {}
    for _, asset_path in staged_assets:
        classification = classify_primary_platform_asset(asset_path.name)
        if classification is None:
            continue
        platform_id = classification["platform_id"]
        if platform_id in platforms:
            raise ValueError(
                f"Multiple primary binary archives detected for {platform_id}: "
                f"{platforms[platform_id]['asset_name']} and {asset_path.name}"
            )
        platforms[platform_id] = classification
    return platforms


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_object(path: Path, label: str) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"{label} must contain a JSON object: {path}")
    return payload


def validate_snapshot_inputs(snapshot_path: Path | None, manifest_path: Path | None) -> None:
    if snapshot_path is None or manifest_path is None:
        return

    manifest = load_json_object(manifest_path, "snapshot manifest")
    digest_candidates = [
        manifest.get("snapshot_sha256"),
        manifest.get("sha256"),
    ]
    digest_values = [value.strip().lower() for value in digest_candidates if isinstance(value, str) and value.strip()]
    if not digest_values:
        return
    if len(set(digest_values)) != 1:
        raise ValueError(
            f"Snapshot manifest advertises conflicting SHA256 values: {manifest_path}"
        )

    actual_sha256 = sha256_file(snapshot_path).lower()
    expected_sha256 = digest_values[0]
    if actual_sha256 != expected_sha256:
        raise ValueError(
            f"Snapshot manifest SHA256 mismatch for {snapshot_path.name}: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )


def is_release_checksum_artifact(path: Path) -> bool:
    name = path.name
    if name in CHECKSUM_BASENAMES:
        return True
    return any(name.startswith(prefix) for prefix in CHECKSUM_PREFIXES)


def iter_source_files(source: Path) -> Iterable[Path]:
    if source.is_file():
        yield source
        return
    if not source.is_dir():
        raise FileNotFoundError(f"Source path does not exist: {source}")

    for path in sorted(source.rglob("*")):
        if path.is_file():
            yield path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where the final release bundle will be staged.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="File or directory to copy into the bundle. Directories are flattened recursively.",
    )
    parser.add_argument(
        "--snapshot",
        help="Snapshot file to publish as snapshot.dat.",
    )
    parser.add_argument(
        "--snapshot-manifest",
        help="Compact snapshot manifest to publish as snapshot.manifest.json.",
    )
    parser.add_argument(
        "--attestations-dir",
        action="append",
        default=[],
        help=(
            "Optional guix.sigs release directory containing signer subdirectories. "
            "Matching attestation files are staged with signer-qualified names and "
            "recorded in attestation_assets."
        ),
    )
    parser.add_argument(
        "--release-manifest-name",
        default="btx-release-manifest.json",
        help="Filename for the generated release manifest (default: btx-release-manifest.json).",
    )
    parser.add_argument(
        "--checksum-name",
        default="SHA256SUMS",
        help="Filename for the generated checksum file (default: SHA256SUMS).",
    )
    parser.add_argument(
        "--checksum-signature",
        help="Optional signed checksum file to stage as SHA256SUMS.asc.",
    )
    parser.add_argument(
        "--gpg",
        default="gpg",
        help="GPG binary to use when signing SHA256SUMS (default: gpg).",
    )
    parser.add_argument(
        "--sign-with",
        help="Optional GPG key name used to produce SHA256SUMS.asc inside the bundle.",
    )
    parser.add_argument(
        "--gpg-passphrase-env",
        help=(
            "Optional environment variable name whose value should be piped to gpg via "
            "--pinentry-mode loopback when --sign-with is used."
        ),
    )
    parser.add_argument(
        "--release-tag",
        help="Optional release tag to embed in the generated manifest.",
    )
    parser.add_argument(
        "--release-name",
        help="Optional release name to embed in the generated manifest.",
    )
    parser.add_argument(
        "--required-platform",
        action="append",
        default=None,
        help=(
            "Platform id that must be present in platform_assets. "
            f"Defaults to all primary release platforms: {', '.join(DEFAULT_REQUIRED_PLATFORMS)}."
        ),
    )
    args = parser.parse_args(argv)
    if args.required_platform is None:
        args.required_platform = list(DEFAULT_REQUIRED_PLATFORMS)
    return args


def ensure_empty_dir(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(f"Output directory is not empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def stage_file(source: Path, dest_dir: Path, *, dest_name: str | None = None) -> Path:
    destination = dest_dir / (dest_name or source.name)
    if destination.exists():
        raise FileExistsError(f"Duplicate bundle asset name: {destination.name}")
    shutil.copy2(source, destination)
    return destination


def collect_sources(sources: list[str], dest_dir: Path) -> list[tuple[str, Path]]:
    staged: list[tuple[str, Path]] = []
    seen_names: set[str] = set()

    for raw_source in sources:
        source = Path(raw_source)
        for item in iter_source_files(source):
            if is_release_checksum_artifact(item):
                continue
            if item.name in seen_names:
                raise FileExistsError(
                    f"Duplicate asset name after flattening: {item.name} (from {item})"
                )
            seen_names.add(item.name)
            staged_path = stage_file(item, dest_dir)
            staged.append((str(item), staged_path))

    return staged


def stage_snapshot_artifacts(args: argparse.Namespace, dest_dir: Path) -> list[tuple[str, Path]]:
    staged: list[tuple[str, Path]] = []
    snapshot_path = Path(args.snapshot) if args.snapshot else None
    snapshot_manifest_path = Path(args.snapshot_manifest) if args.snapshot_manifest else None
    validate_snapshot_inputs(snapshot_path, snapshot_manifest_path)
    if args.snapshot:
        assert snapshot_path is not None
        staged.append((str(snapshot_path), stage_file(snapshot_path, dest_dir, dest_name="snapshot.dat")))
    if args.snapshot_manifest:
        assert snapshot_manifest_path is not None
        staged.append(
            (
                str(snapshot_manifest_path),
                stage_file(snapshot_manifest_path, dest_dir, dest_name="snapshot.manifest.json"),
            )
        )
    return staged


def build_attestation_asset_name(signer: str, file_name: str) -> str:
    return f"guix-attestations-{signer}-{file_name}"


def classify_attestation_kind(file_name: str) -> str:
    if file_name.startswith("noncodesigned."):
        return "noncodesigned"
    if file_name.startswith("all."):
        return "all"
    return "unknown"


def stage_attestation_artifacts(
    attestation_dirs: list[str],
    dest_dir: Path,
) -> tuple[list[tuple[str, Path]], list[dict[str, object]]]:
    staged: list[tuple[str, Path]] = []
    manifest_entries: list[dict[str, object]] = []

    for raw_root in attestation_dirs:
        root = Path(raw_root)
        if not root.is_dir():
            raise FileNotFoundError(f"Attestations directory does not exist: {root}")

        found_any = False
        for signer_dir in sorted(root.iterdir()):
            if not signer_dir.is_dir():
                continue
            signer = signer_dir.name
            for file_name in GUIX_ATTESTATION_FILE_NAMES:
                source_path = signer_dir / file_name
                if not source_path.is_file():
                    continue
                found_any = True
                staged_name = build_attestation_asset_name(signer, file_name)
                staged_path = stage_file(source_path, dest_dir, dest_name=staged_name)
                staged.append((str(source_path), staged_path))
                manifest_entries.append(
                    {
                        "signer": signer,
                        "kind": classify_attestation_kind(file_name),
                        "signed": file_name.endswith(".asc"),
                        "asset_name": staged_name,
                        "source_dir": str(signer_dir),
                    }
                )

        if not found_any:
            raise FileNotFoundError(
                f"No guix attestation files found under signer directories in {root}"
            )

    return staged, sorted(
        manifest_entries,
        key=lambda item: (
            str(item["signer"]),
            str(item["kind"]),
            str(item["asset_name"]),
        ),
    )


def build_manifest(
    args: argparse.Namespace,
    staged_assets: list[tuple[str, Path]],
    release_manifest_path: Path,
    checksum_name: str,
    attestation_assets: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    manifest_assets = []
    platform_assets = collect_platform_assets(staged_assets)
    for source, asset_path in staged_assets:
        if asset_path.name in {release_manifest_path.name, checksum_name}:
            continue
        if is_release_checksum_artifact(asset_path):
            continue
        manifest_assets.append(
            {
                "name": asset_path.name,
                "source": source,
                "sha256": sha256_file(asset_path),
                "size_bytes": asset_path.stat().st_size,
            }
        )

    return {
        "format_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "release_tag": args.release_tag,
        "release_name": args.release_name,
        "checksum_file": checksum_name,
        "signature_file": "SHA256SUMS.asc" if (args.checksum_signature or args.sign_with) else None,
        "snapshot_manifest": "snapshot.manifest.json" if args.snapshot_manifest else None,
        "snapshot_asset": "snapshot.dat" if args.snapshot else None,
        "platform_assets": platform_assets,
        "attestation_assets": attestation_assets or [],
        "assets": sorted(manifest_assets, key=lambda item: item["name"]),
    }


def validate_required_platforms(
    platform_assets: dict[str, dict[str, str]],
    required_platforms: Iterable[str],
) -> None:
    missing = sorted(platform_id for platform_id in required_platforms if platform_id not in platform_assets)
    if missing:
        raise ValueError(
            "Missing required platform assets: " + ", ".join(missing)
        )


def write_checksum_file(bundle_dir: Path, checksum_name: str) -> None:
    checksum_path = bundle_dir / checksum_name
    checksum_lines = []
    for path in sorted(bundle_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file():
            continue
        if path.name == checksum_name or path.name == "SHA256SUMS.asc":
            continue
        checksum_lines.append(f"{sha256_file(path)}  {path.name}")
    checksum_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")


def sign_checksum_file(
    checksum_path: Path,
    gpg_bin: str,
    sign_with: str,
    gpg_passphrase_env: str | None = None,
) -> Path:
    signature_path = checksum_path.with_suffix(checksum_path.suffix + ".asc")
    command = [
        gpg_bin,
        "--detach-sign",
        "--digest-algo",
        "sha256",
        "--local-user",
        sign_with,
        "--armor",
        "--output",
        str(signature_path),
        str(checksum_path),
    ]
    run_kwargs: dict[str, object] = {"check": True}
    if gpg_passphrase_env:
        passphrase = os.environ.get(gpg_passphrase_env)
        if not passphrase:
            raise RuntimeError(
                f"GPG passphrase environment variable is not set or empty: {gpg_passphrase_env}"
            )
        command[1:1] = ["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        run_kwargs["input"] = passphrase
        run_kwargs["text"] = True

    subprocess.run(command, **run_kwargs)
    return signature_path


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.checksum_signature and args.sign_with:
        raise ValueError("--checksum-signature and --sign-with are mutually exclusive")
    bundle_dir = Path(args.output_dir)
    ensure_empty_dir(bundle_dir)

    staged_assets: list[tuple[str, Path]] = []
    staged_assets.extend(collect_sources(list(args.source), bundle_dir))
    staged_assets.extend(stage_snapshot_artifacts(args, bundle_dir))
    attestation_staged, attestation_assets = stage_attestation_artifacts(
        list(args.attestations_dir),
        bundle_dir,
    )
    staged_assets.extend(attestation_staged)

    release_manifest_path = bundle_dir / args.release_manifest_name
    manifest = build_manifest(
        args,
        staged_assets,
        release_manifest_path,
        args.checksum_name,
        attestation_assets=attestation_assets,
    )
    validate_required_platforms(
        manifest["platform_assets"],
        args.required_platform,
    )
    release_manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    checksum_path = bundle_dir / args.checksum_name
    write_checksum_file(bundle_dir, args.checksum_name)
    if args.sign_with:
        sign_checksum_file(
            checksum_path,
            args.gpg,
            args.sign_with,
            gpg_passphrase_env=args.gpg_passphrase_env,
        )
    elif args.checksum_signature:
        stage_file(Path(args.checksum_signature), bundle_dir, dest_name="SHA256SUMS.asc")

    bundle_summary = {
        "bundle_dir": str(bundle_dir),
        "release_manifest": str(release_manifest_path),
        "checksum_file": str(checksum_path),
        "assets": [path.name for _, path in sorted(staged_assets, key=lambda item: item[1].name)],
        "attestation_assets": [entry["asset_name"] for entry in attestation_assets],
    }
    json.dump(bundle_summary, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
