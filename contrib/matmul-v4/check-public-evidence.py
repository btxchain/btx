#!/usr/bin/env python3
"""Fail closed when public MatMul evidence contains creator-machine details."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATHS = (
    REPO_ROOT / "doc/evidence",
    REPO_ROOT / "contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py",
    REPO_ROOT / "contrib/matmul-v4/cuda-profile1-soak.sh",
    REPO_ROOT / "contrib/matmul-v4/evidence-provenance-exclusions.json",
    REPO_ROOT / "contrib/matmul-v4/measure-hardware.sh",
    REPO_ROOT / "contrib/matmul-v4/measure-cuda-lifecycle-campaign.py",
    REPO_ROOT / "contrib/matmul-v4/measure-v3-regimes.cpp",
    REPO_ROOT / "contrib/matmul-v4/derive-epoch-a-asert.py",
    REPO_ROOT / "contrib/matmul-v4/assemble-epoch-a-asert-corpus.py",
    REPO_ROOT / "contrib/matmul-v4/multi-gpu-golden-corpus.sh",
    REPO_ROOT / "contrib/matmul-v4/sanitize-public-evidence.py",
    REPO_ROOT / "contrib/matmul-v4/verify-evidence-provenance.py",
    REPO_ROOT / "contrib/devtools/update-matmul-v47-doc-inventory.sh",
)

# Public evidence may name an OS and hardware *class*. It must not carry the
# creator's account, workspace, temporary directory, credentials, or network
# identity. Keep this list intentionally narrow enough that ordinary technical
# prose and example paths elsewhere in the repository are unaffected.
FORBIDDEN_TEXT = (
    ("macOS user path", re.compile(r"/Users/[^/\s]+/")),
    ("Unix home path", re.compile(r"/home/[^/\s]+/")),
    ("creator temporary path", re.compile(r"/(?:private/)?tmp/[^\s`\"']+")),
    ("mDNS hostname", re.compile(r"\b[A-Z0-9][A-Z0-9._-]*\.local\b", re.IGNORECASE)),
    ("Windows user path", re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+[\\/]", re.IGNORECASE)),
    ("email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("private key filename", re.compile(r"\b(?:github|porkbun|digitalocean|api|secret)\.(?:key|token)\b", re.IGNORECASE)),
    ("SSH private key filename", re.compile(r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b", re.IGNORECASE)),
)

FORBIDDEN_JSON_KEYS = {
    "cwd",
    "env",
    "environment",
    "home",
    "hostname",
    "ip_address",
    "mac_address",
    "output_path",
    "pwd",
    "source_path",
    "user",
    "username",
    "workdir",
    "workspace",
}

# The evidence rules above are intentionally strict and cannot be applied to
# every tracked file: ordinary documentation legitimately contains placeholder
# /tmp paths and token-file examples. These high-signal repository-wide rules
# enforce the separate public/private publication boundary without flagging
# documented placeholders.
FORBIDDEN_PUBLIC_TREE_TEXT = (
    # The public source repository is btxchain/btx. Any other repository slug
    # in that organization is a publication-boundary violation unless an
    # explicit future allowlist entry is reviewed here.
    ("non-public btxchain repository name", re.compile(
        # Match the organization slug at a token/path boundary. This catches
        # full URLs, scheme-less github.com links, scp-style remotes, and
        # filesystem/workspace paths without accidentally matching a longer
        # organization name such as `notbtxchain`.
        r"(?<![A-Z0-9_.-])"
        r"btxchain/(?!btx(?:\.git)?(?=$|[/#?\s`\"'.,;:()\[\]{}<>\\]))"
        r"[A-Z0-9._-]+\b",
        re.IGNORECASE)),
)

IPV4_TEXT = re.compile(r"(?<![A-Z0-9_.-])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Z0-9_.-])", re.IGNORECASE)
IPV6_TEXT = re.compile(
    r"(?<![A-Z0-9_.-])(?:[0-9A-F]{1,4}:){2,7}[0-9A-F]{1,4}(?![A-Z0-9_.-])",
    re.IGNORECASE,
)
FQDN_TEXT = re.compile(
    r"(?<![A-Z0-9_.-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"(?:com|org|net|io|dev|ai|co|jp|example|internal|local)\b",
    re.IGNORECASE,
)
PUBLIC_HOST_ALLOWLIST = {
    "btxprice.com",
    "gpu-archive.example",
    "github.com",
    "opensource.org",
    "raw.githubusercontent.com",
    "snapshot-manifest.example",
    "www.github.com",
    "www.opensource.org",
}
PUBLIC_IP_ALLOWLIST = {
    "0.0.0.0",
    "127.0.0.1",
    "::",
    "::1",
}

# Apply generic machine-home rules to BTX-authored publication and operations
# material. Upstream/vendored history legitimately contains old example and
# contributor paths, so scanning it would create a noisy identity allowlist.
BTX_PUBLICATION_PREFIXES = (
    "README.md",
    ".github/",
    "ci/",
    "contrib/devtools/",
    "contrib/matmul-",
    "doc/README.md",
    "doc/btx-",
    "doc/design/",
    "doc/evidence/",
    "doc/policy/",
    "doc/release-manifests/",
    "doc/release-notes.md",
    "doc/security/",
    "doc/tmp-",
    "docs/",
    "formal-verification/",
    "infra/",
    "scripts/",
    "share/",
    "test/util/",
)

FORBIDDEN_BTX_PUBLICATION_TEXT = (
    ("provider credential filename", re.compile(
        r"\b(?:digitalocean_api|porkbun_(?:api|secret))\.key\b",
        re.IGNORECASE)),
    ("machine-specific macOS home path", re.compile(
        r"/Users/(?!(?:you|username|<user>|\$USER|\$\{USER\})(?=/|$))"
        r"[A-Z0-9._${}-]+(?=/|\\|[\s`\"']|$)",
        re.IGNORECASE)),
    ("machine-specific Unix home path", re.compile(
        r"/home/(?!(?:example|user|username|<user>|yourname|\.\.\.|\*|"
        r"\$USER|\$\{USER\})(?=/|$))"
        r"[A-Z0-9._${}-]+(?=/|\\|[\s`\"']|$)",
        re.IGNORECASE)),
    ("machine-specific Windows home path", re.compile(
        r"[A-Z]:[\\/]+Users[\\/]+"
        r"(?!(?:you|user|username|<user>|\$USER|\$\{USER\}|%USERNAME%)"
        r"(?=[\\/]|$))[A-Z0-9._${}%<>-]+(?=[\\/]|[\s`\"']|$)",
        re.IGNORECASE)),
)


def tracked_public_files() -> Iterable[Path]:
    """Enumerate every publishable tracked or currently untracked file.

    Untracked files are often the next evidence/tooling additions to be
    committed; omitting them lets the default pre-publication check pass just
    before those files cross the public boundary.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    )
    for raw_path in result.stdout.split(b"\0"):
        if raw_path:
            yield REPO_ROOT / raw_path.decode("utf-8")


def is_btx_publication_path(path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        # Direct unit-test fixtures should exercise the full rule set.
        return True
    # Root-level files are project-owned release/build/publication material;
    # unlike vendored subtrees, there is no upstream identity corpus to exempt.
    return "/" not in relative or relative.startswith(BTX_PUBLICATION_PREFIXES)


def check_public_tree_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    failures: list[str] = []
    for label, pattern in FORBIDDEN_PUBLIC_TREE_TEXT:
        match = pattern.search(text)
        if match:
            failures.append(f"{path}: contains {label}: {match.group(0)!r}")
    if is_btx_publication_path(path):
        for label, pattern in FORBIDDEN_BTX_PUBLICATION_TEXT:
            match = pattern.search(text)
            if match:
                failures.append(f"{path}: contains {label}: {match.group(0)!r}")
    return failures


def check_network_identity(text: str, path: Path) -> list[str]:
    """Reject publication-machine addresses and hostnames.

    Loopback/wildcard literals used by local examples and a short reviewed set
    of public project hosts are the only exceptions. Even RFC documentation
    addresses are forbidden in evidence because they can mask a mechanically
    redacted real address and are not needed to establish accelerator results.
    """
    failures: list[str] = []
    for pattern in (IPV4_TEXT, IPV6_TEXT):
        for match in pattern.finditer(text):
            candidate = match.group(0).lower()
            try:
                normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if normalized not in PUBLIC_IP_ALLOWLIST:
                failures.append(f"{path}: contains network address: {candidate!r}")
                break
    for match in FQDN_TEXT.finditer(text):
        hostname = match.group(0).lower().rstrip(".")
        if hostname not in PUBLIC_HOST_ALLOWLIST:
            failures.append(f"{path}: contains non-allowlisted hostname: {hostname!r}")
            break
    return failures


def check_public_tree_path(path: Path) -> list[str]:
    try:
        relative = path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        relative = path.as_posix()
    failures: list[str] = []
    for label, pattern in FORBIDDEN_PUBLIC_TREE_TEXT:
        match = pattern.search(relative)
        if match:
            failures.append(f"{relative}: path contains {label}: {match.group(0)!r}")
    failures.extend(check_network_identity(relative, path))
    return failures


def evidence_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            yield path
        else:
            raise FileNotFoundError(path)


def walk_json_keys(value: Any, prefix: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            yield prefix, key_text
            yield from walk_json_keys(item, f"{prefix}.{key_text}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_json_keys(item, f"{prefix}[{index}]")


def check_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{path}: non-UTF-8 evidence is not reviewable as public text"]

    failures: list[str] = []
    for label, pattern in FORBIDDEN_TEXT:
        match = pattern.search(text)
        if match:
            failures.append(f"{path}: contains {label}: {match.group(0)!r}")
    failures.extend(check_network_identity(text, path))

    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            failures.append(f"{path}: malformed JSON: {error}")
        else:
            for prefix, key in walk_json_keys(payload):
                if key.lower() in FORBIDDEN_JSON_KEYS:
                    failures.append(f"{path}: forbidden identity/path key {prefix}.{key}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Evidence files or directories (defaults to every current evidence artifact and publication helper)",
    )
    args = parser.parse_args()

    failures: list[str] = []
    try:
        files = list(evidence_files(args.paths or DEFAULT_PATHS))
    except FileNotFoundError as error:
        print(f"missing evidence path: {error}", file=sys.stderr)
        return 1
    if not files:
        print("no evidence files selected", file=sys.stderr)
        return 1

    for path in files:
        failures.extend(check_file(path))
    try:
        tracked_files = list(tracked_public_files())
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as error:
        print(f"failed to enumerate tracked public files: {error}", file=sys.stderr)
        return 1
    for path in tracked_files:
        failures.extend(check_public_tree_path(path))
        failures.extend(check_public_tree_file(path))
    if failures:
        print("public MatMul evidence privacy check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"public MatMul evidence privacy check passed ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
