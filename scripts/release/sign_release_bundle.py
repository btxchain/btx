#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Sign a previously collected BTX release bundle with a pinned OpenPGP key."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import collect_release_assets as collector
import publish_github_release as publisher


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--sign-with", required=True)
    parser.add_argument("--expected-signing-fingerprint", required=True)
    parser.add_argument("--gpg-passphrase-env")
    parser.add_argument("--gpg", default="gpg")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    expected = publisher.normalize_fingerprint(args.expected_signing_fingerprint)
    bundle_dir = Path(args.bundle_dir).resolve()
    _, manifest = publisher.ensure_bundle(bundle_dir)
    manifest_path = bundle_dir / publisher.RELEASE_MANIFEST_NAME
    checksum_path = bundle_dir / publisher.CHECKSUM_FILE_NAME
    signature_path = bundle_dir / "SHA256SUMS.asc"

    if manifest.get("signature_file") is not None or signature_path.exists():
        raise FileExistsError("Release bundle is already signed")

    original_manifest = manifest_path.read_bytes()
    original_checksums = checksum_path.read_bytes()
    try:
        manifest["signature_file"] = "SHA256SUMS.asc"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        collector.write_checksum_file(bundle_dir, publisher.CHECKSUM_FILE_NAME)
        collector.sign_checksum_file(
            checksum_path,
            args.gpg,
            args.sign_with,
            gpg_passphrase_env=args.gpg_passphrase_env,
        )
        fingerprints = publisher.verify_checksum_signature(
            checksum_path,
            signature_path,
            args.gpg,
        )
        if expected not in fingerprints:
            actual = ", ".join(sorted(fingerprints)) or "none"
            raise RuntimeError(
                f"Checksum signature signer mismatch: expected {expected}, got {actual}"
            )
        publisher.ensure_bundle(bundle_dir)
    except BaseException:
        manifest_path.write_bytes(original_manifest)
        checksum_path.write_bytes(original_checksums)
        signature_path.unlink(missing_ok=True)
        raise

    print(json.dumps({
        "bundle_dir": str(bundle_dir),
        "signature_file": signature_path.name,
        "verified_signing_fingerprints": sorted(fingerprints),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
