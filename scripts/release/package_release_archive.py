#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Create a canonical BTX binary archive for one release platform.

The generated archive contains the release binaries plus the fast-start and
mining helper scripts needed for a download-and-go operator flow.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SUPPORT_FILES_MANIFEST = Path(__file__).with_name("support_files.txt")


def load_support_files(manifest_path: Path = SUPPORT_FILES_MANIFEST) -> list[str]:
    support_files: list[str] = []
    for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        support_files.append(line)
    return support_files


PLATFORM_CONFIGS = {
    "linux-x86_64": {
        "triple": "x86_64-linux-gnu",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "linux-arm64": {
        "triple": "aarch64-linux-gnu",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "windows-x86_64": {
        "triple": "x86_64-w64-mingw32",
        "archive_format": "zip",
        "exe_suffix": ".exe",
    },
    "macos-x86_64": {
        "triple": "x86_64-apple-darwin",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
    "macos-arm64": {
        "triple": "arm64-apple-darwin",
        "archive_format": "tar.gz",
        "exe_suffix": "",
    },
}
SUPPORT_FILES = load_support_files()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="Directory where the archive will be written.")
    parser.add_argument("--version", required=True, help="Release version string, for example 29.2.")
    parser.add_argument(
        "--platform-id",
        required=True,
        choices=sorted(PLATFORM_CONFIGS.keys()),
        help="Canonical release platform id.",
    )
    parser.add_argument("--btxd", required=True, help="Path to the btxd binary for this platform.")
    parser.add_argument("--btx-cli", required=True, help="Path to the btx-cli binary for this platform.")
    parser.add_argument(
        "--source-root",
        default=str(ROOT),
        help="Repository root used to source helper scripts and docs (default: repo root).",
    )
    parser.add_argument(
        "--archive-name",
        help="Optional output filename override. Defaults to btx-<version>-<target>.<ext>.",
    )
    return parser.parse_args(argv)


def ensure_input_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")
    return path


def archive_filename(version: str, platform_id: str, override: str | None) -> str:
    if override:
        return override
    config = PLATFORM_CONFIGS[platform_id]
    suffix = ".zip" if config["archive_format"] == "zip" else ".tar.gz"
    return f"btx-{version}-{config['triple']}{suffix}"


def stage_release_tree(
    *,
    version: str,
    platform_id: str,
    btxd_path: Path,
    btx_cli_path: Path,
    source_root: Path,
    temp_root: Path,
) -> tuple[Path, list[str]]:
    config = PLATFORM_CONFIGS[platform_id]
    release_root = temp_root / f"btx-{version}"
    included: list[str] = []

    bin_dir = release_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    binary_pairs = [
        (ensure_input_file(btxd_path, "btxd binary"), f"btxd{config['exe_suffix']}"),
        (ensure_input_file(btx_cli_path, "btx-cli binary"), f"btx-cli{config['exe_suffix']}"),
    ]
    for source, dest_name in binary_pairs:
        destination = bin_dir / dest_name
        shutil.copy2(source, destination)
        included.append(str(destination.relative_to(release_root)))

    for relative_path in SUPPORT_FILES:
        source = ensure_input_file(source_root / relative_path, relative_path)
        destination = release_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        included.append(str(destination.relative_to(release_root)))

    return release_root, sorted(included)


def write_tar_gz(archive_path: Path, release_root: Path) -> None:
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(release_root, arcname=release_root.name)


def write_zip(archive_path: Path, release_root: Path) -> None:
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(release_root.rglob("*")):
            if not path.is_file():
                continue
            archive.write(path, arcname=str(path.relative_to(release_root.parent)))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    source_root = Path(args.source_root).expanduser().resolve()
    archive_path = output_dir / archive_filename(args.version, args.platform_id, args.archive_name)

    with tempfile.TemporaryDirectory(prefix="btx-release-archive-") as temp_dir:
        temp_root = Path(temp_dir)
        release_root, included_paths = stage_release_tree(
            version=args.version,
            platform_id=args.platform_id,
            btxd_path=Path(args.btxd).expanduser().resolve(),
            btx_cli_path=Path(args.btx_cli).expanduser().resolve(),
            source_root=source_root,
            temp_root=temp_root,
        )
        if PLATFORM_CONFIGS[args.platform_id]["archive_format"] == "zip":
            write_zip(archive_path, release_root)
        else:
            write_tar_gz(archive_path, release_root)

    json.dump(
        {
            "archive_path": str(archive_path),
            "archive_name": archive_path.name,
            "platform_id": args.platform_id,
            "archive_format": PLATFORM_CONFIGS[args.platform_id]["archive_format"],
            "included_paths": included_paths,
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
