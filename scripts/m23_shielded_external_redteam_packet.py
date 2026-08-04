#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Build an operator/participant packet for an external BTX shielded red-team window."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_FILES = [
    "doc/btx-shielded-cryptographic-audit-handoff.md",
    "doc/btx-shielded-external-redteam-window.md",
    "doc/btx-shielded-external-review-closeout.md",
    "doc/btx-production-readiness-matrix.md",
    "doc/btx-shielded-v2-overhaul-tracker-2026-03-14.md",
    "infra/btx-seed-server-spec.md",
    "scripts/m20_shielded_audit_handoff_bundle.py",
    "scripts/m21_shielded_redteam_campaign.sh",
    "scripts/m22_remote_shielded_redteam_campaign.py",
    "scripts/m23_shielded_external_redteam_packet.py",
    "scripts/m24_shielded_external_findings_intake.py",
    "scripts/m25_shielded_external_closeout_check.py",
    "scripts/m26_remote_shielded_validation_suite.py",
]


def load_m22_module():
    script_path = REPO_ROOT / "scripts" / "m22_remote_shielded_redteam_campaign.py"
    spec = importlib.util.spec_from_file_location("m22_remote_shielded_redteam_campaign", script_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load m22 helper module: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M22_REMOTE_MODULE = load_m22_module()


def manifest_path_prefixes(path: Path) -> list[str]:
    prefixes: list[str] = []
    for candidate in (path, path.resolve()):
        text = str(candidate)
        if text not in prefixes:
            prefixes.append(text)
    return prefixes


def manifest_display_path(output_dir: Path, value: str) -> str:
    temp_dir = Path(tempfile.gettempdir())
    for root, label in (
        (output_dir, ""),
        (REPO_ROOT, "<repo>"),
        (REPO_ROOT.parent, "<workspace>"),
        (Path.home(), "~"),
        (temp_dir, "<tmp>"),
        (Path("/private/tmp"), "<tmp>"),
        (Path("/tmp"), "<tmp>"),
    ):
        for root_str in manifest_path_prefixes(root):
            if value == root_str:
                return label or "."
            prefix = root_str + os.sep
            if value.startswith(prefix):
                suffix = value[len(prefix):]
                if not label:
                    return suffix
                return f"{label}/{suffix}"
    return value


def sanitize_manifest_value(output_dir: Path, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_manifest_value(output_dir, item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_manifest_value(output_dir, item) for item in value]
    if isinstance(value, str):
        return manifest_display_path(output_dir, value)
    return value


def write_manifest(output_dir: Path, manifest_path: Path, manifest: dict[str, Any]) -> None:
    sanitized = sanitize_manifest_value(output_dir, manifest)
    write_text(manifest_path, json.dumps(sanitized, indent=2) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def copy_file(src: Path, dst: Path) -> dict[str, str]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {
        "source": str(src),
        "copied_to": str(dst),
        "sha256": sha256_file(dst),
    }


def copy_tree(src: Path, dst: Path) -> dict[str, object]:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    sanitize_hosted_run_manifests(dst)
    file_count = sum(1 for path in dst.rglob("*") if path.is_file())
    return {
        "source": str(src),
        "copied_to": str(dst),
        "file_count": file_count,
    }


def output_relative_path_for_source(rel: str) -> Path:
    rel_path = Path(rel)
    if not rel_path.parts:
        raise ValueError("empty source path")
    if rel_path.parts[0] == "..":
        if len(rel_path.parts) < 2 or rel_path.parts[1] != "infra":
            raise ValueError(f"unsupported source path outside repo root: {rel}")
        return Path("infra").joinpath(*rel_path.parts[2:])
    return rel_path


def legacy_hosted_output_root(manifest: dict[str, Any], fallback_root: Path) -> Path:
    artifacts = manifest.get("artifacts")
    if isinstance(artifacts, dict):
        source_archive = artifacts.get("source_archive")
        if isinstance(source_archive, dict):
            source_path = source_archive.get("path")
            if isinstance(source_path, str) and source_path.startswith("/"):
                return Path(source_path).expanduser().resolve().parent
        remote_bundle = artifacts.get("remote_bundle")
        if isinstance(remote_bundle, dict):
            bundle_path = remote_bundle.get("path")
            if isinstance(bundle_path, str) and bundle_path.startswith("/"):
                return Path(bundle_path).expanduser().resolve().parent.parent
        extract_dir = artifacts.get("remote_extract_dir")
        if isinstance(extract_dir, str) and extract_dir.startswith("/"):
            return Path(extract_dir).expanduser().resolve().parent.parent
    steps = manifest.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            log_path = step.get("log")
            if isinstance(log_path, str) and log_path.startswith("/"):
                candidate = Path(log_path).expanduser().resolve()
                if candidate.parent.name == "logs":
                    return candidate.parent.parent
    return fallback_root


def sanitize_hosted_run_manifests(root: Path) -> None:
    for manifest_path in root.rglob("manifest.json"):
        if not any(
            part in {"hosted_run", "m22_hosted_run", "hosted_validation", "m26_hosted_validation"}
            for part in manifest_path.parts
        ):
            continue
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        output_root = legacy_hosted_output_root(data, manifest_path.parent)
        sanitized = M22_REMOTE_MODULE.sanitize_manifest_value(output_root, data)
        write_text(manifest_path, json.dumps(sanitized, indent=2) + "\n")


def write_checksums(paths: list[Path], output_path: Path, root_dir: Path) -> None:
    lines = [
        f"{sha256_file(path)}  {path.relative_to(root_dir)}"
        for path in sorted(paths)
    ]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def tar_output_dir(output_dir: Path) -> Path:
    tarball = output_dir.parent / f"{output_dir.name}.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(output_dir, arcname=output_dir.name)
    return tarball


def git_output(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    )
    return proc.stdout.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an operator/participant packet for an external BTX shielded red-team window."
    )
    parser.add_argument("--output-dir", required=True, help="Output packet directory")
    parser.add_argument(
        "--audit-bundle",
        help="Existing m20 audit handoff bundle directory or tarball to include",
    )
    parser.add_argument(
        "--hosted-run-dir",
        help="Existing m22 hosted run directory to include",
    )
    parser.add_argument(
        "--hosted-validation-dir",
        help="Existing m26 hosted validation directory to include",
    )
    parser.add_argument(
        "--window-label",
        default="invited-external-redteam-window",
        help="Human-readable label for this campaign packet",
    )
    return parser.parse_args()


def build_participant_brief(
    window_label: str,
    audit_ref: str,
    hosted_redteam_ref: str,
    hosted_validation_ref: str,
) -> str:
    return f"""# BTX Shielded External Red-Team Window Packet

Window label: `{window_label}`

## Purpose
This packet is for an invited external proof-focused review or red-team window.
It packages the minimum repo-side materials needed to reproduce the BTX
shielded proof surfaces, understand the current known-good baselines, and
return actionable findings with machine-readable evidence.

## Included Baselines
- Audit handoff bundle: `{audit_ref}`
- Hosted malformed-proof baseline: `{hosted_redteam_ref}`
- Hosted simulated-testnet / proof-size / TPS baseline: `{hosted_validation_ref}`
- This packet preserves repo-relative `doc/`, `scripts/`, and `infra/` paths.
  Run the included helper commands from the unpacked packet root.

## What To Attack
- Proof forgery attempts against direct-send and batch-oriented flows
- Verifier disagreement attempts between independent transcript checking and
  production validation
- Transcript malleability and statement-binding edge cases
- Malformed-proof resource-exhaustion behavior
- Parser, serializer, and campaign-replay edge cases that could create mempool
  residue, inconsistent rejection, or consensus divergence

## Required Return Artifacts
- A concise narrative of the attack attempted and expected impact
- Exact commands and environment details
- Any malformed corpus or proof payloads generated
- Logs, traces, and consensus outcomes
- Clear pass/fail statement for whether the attack succeeded
- Findings should be returned through the documented intake path in
  `scripts/m24_shielded_external_findings_intake.py`
- Final closeout is checked with
  `scripts/m25_shielded_external_closeout_check.py`

## Reference Commands
- Local red-team wrapper: `scripts/m21_shielded_redteam_campaign.sh`
- Hosted disposable wrapper: `scripts/m22_remote_shielded_redteam_campaign.py`
- Hosted disposable full validation suite: `scripts/m26_remote_shielded_validation_suite.py`
- Audit handoff bundle: `scripts/m20_shielded_audit_handoff_bundle.py`
- Findings intake packet: `scripts/m24_shielded_external_findings_intake.py`
- Closeout validator: `scripts/m25_shielded_external_closeout_check.py`

## Disclosure Expectation
Report critical or high-severity findings privately with enough material to
reproduce them deterministically from this packet.
"""


def build_operator_checklist(window_label: str) -> str:
    return f"""# Operator Checklist For {window_label}

## Before Inviting Participants
- Regenerate the audit handoff bundle with `scripts/m20_shielded_audit_handoff_bundle.py`
- Confirm the hosted malformed-proof baseline still passes with `scripts/m22_remote_shielded_redteam_campaign.py`
- Confirm the hosted simulated-testnet / proof-size / TPS baseline still passes with `scripts/m26_remote_shielded_validation_suite.py`
- Review `doc/btx-shielded-external-redteam-window.md`
- Review `infra/btx-seed-server-spec.md`
- Verify all outbound materials have checksums recorded in `manifest.json` and `SHA256SUMS`

## During The Window
- Prefer short-lived disposable infrastructure over long-lived shared hosts
- Capture participant-reported corpora, logs, and traces without modification
- Record any consensus, mempool, or verifier disagreement events immediately
- If public DNS or peering behavior matters, use the seed-server spec rather
  than ad-hoc hostnames

## At Closeout
- Archive all returned artifacts alongside the packet manifest
- Normalize returned materials with `scripts/m24_shielded_external_findings_intake.py`
- Validate the populated intake packet with
  `scripts/m25_shielded_external_closeout_check.py`
- Run those commands from the unpacked packet root so the bundled `doc/`,
  `scripts/`, and `infra/` references resolve directly
- Confirm all cloud resources created for the window were torn down
- Add the resulting evidence back into the tracker and readiness matrix before
  considering any launch-status change
"""


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    artifacts_dir = output_dir / "artifacts"
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, object] = {
        "format_version": 1,
        "generated_at_unix": int(time.time()),
        "window_label": args.window_label,
        "repo_root": str(REPO_ROOT),
        "git": {
            "commit": git_output("rev-parse", "HEAD"),
            "branch": git_output("rev-parse", "--abbrev-ref", "HEAD"),
            "status": git_output("status", "--short"),
        },
        "included_sources": [],
        "included_artifacts": {},
    }

    copied_files: list[Path] = []
    for rel in DEFAULT_SOURCE_FILES:
        src = (REPO_ROOT / rel).resolve()
        if not src.exists():
            raise FileNotFoundError(f"required packet source missing: {src}")
        packet_path = output_relative_path_for_source(rel)
        dst = output_dir / packet_path
        entry = copy_file(src, dst)
        entry["packet_path"] = str(packet_path)
        manifest["included_sources"].append(entry)
        copied_files.append(dst)

    audit_ref = "not included"
    if args.audit_bundle:
        audit_src = Path(args.audit_bundle).resolve()
        if not audit_src.exists():
            raise FileNotFoundError(f"audit bundle not found: {audit_src}")
        audit_ref = "artifacts/audit_bundle/" if audit_src.is_dir() else f"artifacts/{audit_src.name}"
        audit_dst = artifacts_dir / "audit_bundle"
        if audit_src.is_dir():
            manifest["included_artifacts"]["audit_bundle_dir"] = copy_tree(audit_src, audit_dst)
        else:
            copied = copy_file(audit_src, artifacts_dir / audit_src.name)
            manifest["included_artifacts"]["audit_bundle_file"] = copied
            copied_files.append(Path(copied["copied_to"]))

    hosted_redteam_ref = "not included"
    if args.hosted_run_dir:
        hosted_src = Path(args.hosted_run_dir).resolve()
        if not hosted_src.is_dir():
            raise FileNotFoundError(f"hosted run dir not found: {hosted_src}")
        hosted_redteam_ref = "artifacts/hosted_run/"
        hosted_dst = artifacts_dir / "hosted_run"
        manifest["included_artifacts"]["hosted_run_dir"] = copy_tree(hosted_src, hosted_dst)

    hosted_validation_ref = "not included"
    if args.hosted_validation_dir:
        hosted_validation_src = Path(args.hosted_validation_dir).resolve()
        if not hosted_validation_src.is_dir():
            raise FileNotFoundError(f"hosted validation dir not found: {hosted_validation_src}")
        hosted_validation_ref = "artifacts/hosted_validation/"
        hosted_validation_dst = artifacts_dir / "hosted_validation"
        manifest["included_artifacts"]["hosted_validation_dir"] = copy_tree(
            hosted_validation_src, hosted_validation_dst
        )

    docs_dir = output_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    participant_brief = docs_dir / "participant_brief.md"
    operator_checklist = docs_dir / "operator_checklist.md"
    write_text(
        participant_brief,
        build_participant_brief(
            args.window_label,
            audit_ref,
            hosted_redteam_ref,
            hosted_validation_ref,
        ),
    )
    write_text(operator_checklist, build_operator_checklist(args.window_label))
    copied_files.extend([participant_brief, operator_checklist])

    manifest_path = output_dir / "manifest.json"
    write_manifest(output_dir, manifest_path, manifest)
    copied_files.append(manifest_path)

    checksums_path = output_dir / "SHA256SUMS"
    write_checksums(copied_files, checksums_path, output_dir)
    copied_files.append(checksums_path)

    tarball = tar_output_dir(output_dir)
    manifest["tarball"] = {
        "path": str(tarball),
        "sha256": sha256_file(tarball),
    }
    write_manifest(output_dir, manifest_path, manifest)

    print(
        json.dumps(
            {
                "overall_status": "pass",
                "output_dir": str(output_dir),
                "tarball": str(tarball),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
