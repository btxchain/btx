#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Build a reproducible intake/closeout packet for external BTX shielded findings."""

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
    "../infra/btx-seed-server-spec.md",
    "scripts/m20_shielded_audit_handoff_bundle.py",
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


def resolve_source_path(rel: str) -> Path:
    rel_path = Path(rel)
    candidates = [REPO_ROOT / rel_path]
    if rel_path.parts and rel_path.parts[0] == "..":
        if len(rel_path.parts) < 2 or rel_path.parts[1] != "infra":
            raise ValueError(f"unsupported source path outside repo root: {rel}")
        candidates.append(REPO_ROOT / "infra" / Path(*rel_path.parts[2:]))
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise FileNotFoundError(f"required intake source missing: {candidates[0]}")


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
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(REPO_ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unavailable"
    return proc.stdout.strip() or "unavailable"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an intake/closeout packet for external BTX shielded review findings."
    )
    parser.add_argument("--output-dir", required=True, help="Output intake packet directory")
    parser.add_argument(
        "--window-label",
        default="external-proof-review-closeout",
        help="Human-readable label for this intake packet",
    )
    parser.add_argument(
        "--source-packet",
        help="Existing m23 packet directory or tarball to include as reference input",
    )
    parser.add_argument(
        "--audit-bundle",
        help="Existing m20 audit handoff bundle directory or tarball to include as reference input",
    )
    parser.add_argument(
        "--hosted-run-dir",
        help="Existing m22 hosted run directory to include as reference input",
    )
    parser.add_argument(
        "--hosted-validation-dir",
        help="Existing m26 hosted validation directory to include as reference input",
    )
    return parser.parse_args()


def build_finding_template(window_label: str) -> str:
    return f"""# External Finding Template

Window label: `{window_label}`

## Metadata
- Report id:
- Finding title:
- Severity (`informational`, `low`, `medium`, `high`, `critical`):
- Review type (`cryptographic-review`, `redteam`, `testnet`, `other`):
- Reviewer / team:
- Date:

## Affected Surface
- Family / flow:
- Source files or components:
- Preconditions:

## Reproduction
- Exact commands:
- Required inputs / corpora:
- Environment / host details:

## Evidence
- Logs / traces:
- Artifact hashes:
- Corpus or malformed payload references:

## Observed Behavior
- What happened:
- Consensus / mempool / wallet / relay impact:
- Whether the issue is deterministic:

## Expected Behavior
- What should have happened:

## Resolution Tracking
- Suggested remediation:
- Current status (`open`, `triaged`, `fixed`, `duplicate`, `accepted-risk`):
- Follow-up validation command:
"""


def build_session_template(window_label: str) -> str:
    return f"""# External Session Report Template

Window label: `{window_label}`

## Session Summary
- Session id:
- Reviewer / team:
- Start time:
- End time:
- Overall result (`pass`, `findings`, `blocked`):

## Environment
- Host / provider details:
- Chain / topology:
- Baseline packet / bundle used:

## Commands Run
- Exact commands:

## Evidence Produced
- Logs:
- Corpora:
- Packet / bundle hashes:

## Findings Summary
- Number of findings:
- Critical / high unresolved:
- Medium / low unresolved:
- Informational:

## Notes
- Additional observations:
"""


def build_signoff_checklist(window_label: str) -> str:
    return f"""# DoD 8 Closeout Checklist For {window_label}

## External Cryptographic Review
- [ ] Independent reviewer identity and scope are recorded
- [ ] Returned report is attached in `received/`
- [ ] All critical findings are resolved or proven not applicable
- [ ] All high-severity findings are resolved or proven not applicable

## External Red-Team / Testnet Window
- [ ] Session reports are attached in `received/`
- [ ] Returned logs, corpora, and traces are preserved in `received/artifacts/`
- [ ] Any successful attack path has a linked fix and rerun result
- [ ] Any claimed disagreement or consensus issue has an attached reproduction

## Final Closeout
- [ ] `closeout/finding_resolution_log.md` summarizes every returned finding
- [ ] `closeout/signoff_record.md` records the final operator decision
- [ ] Tracker and readiness matrix are updated to reflect the actual external evidence
"""


def build_findings_json_template(window_label: str) -> str:
    payload = {
        "format_version": 1,
        "window_label": window_label,
        "overall_status": "pending_external_input",
        "reports": [
            {
                "report_id": "replace-me",
                "title": "replace-me",
                "severity": "medium",
                "review_type": "redteam",
                "reviewer": "replace-me",
                "status": "open",
                "exact_commands": [],
                "artifact_paths": [],
                "affected_paths": [],
                "summary": "replace-me",
                "remediation": "replace-me",
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def build_signoff_status_json(window_label: str) -> str:
    payload = {
        "format_version": 1,
        "window_label": window_label,
        "overall_status": "pending_external_input",
        "external_cryptographic_review_completed": False,
        "external_redteam_completed": False,
        "tracker_updated": False,
        "readiness_matrix_updated": False,
        "operator": "",
        "decision_date": "",
        "final_status": "pending",
        "notes": "",
    }
    return json.dumps(payload, indent=2) + "\n"


def build_signoff_record(window_label: str) -> str:
    return f"""# External Review Sign-Off Record

Window label: `{window_label}`

## Final Decision
- Status:
- Decision date:
- Operator:

## Inputs Reviewed
- External cryptographic review report:
- External red-team / testnet report:
- Supporting logs / corpora:

## Unresolved Findings
- Critical:
- High:
- Medium:
- Low / informational:

## Launch Decision Note
- Record the exact reason this does or does not satisfy DoD 8:
"""


def build_resolution_log(window_label: str) -> str:
    return f"""# Finding Resolution Log

Window label: `{window_label}`

| Report id | Title | Severity | Status | Fix commit / doc | Validation rerun |
| --- | --- | --- | --- | --- | --- |
| example-001 | Replace me | medium | open | n/a | n/a |
"""


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    templates_dir = output_dir / "templates"
    received_dir = output_dir / "received"
    closeout_dir = output_dir / "closeout"
    sources_dir = output_dir / "source_refs"

    for path in [output_dir, templates_dir, received_dir, closeout_dir, sources_dir]:
        path.mkdir(parents=True, exist_ok=True)
    (received_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (received_dir / "reports").mkdir(parents=True, exist_ok=True)
    (received_dir / "session_reports").mkdir(parents=True, exist_ok=True)

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
        "reference_inputs": {},
        "generated_templates": [],
    }

    copied_files: list[Path] = []
    for rel in DEFAULT_SOURCE_FILES:
        src = resolve_source_path(rel)
        packet_path = output_relative_path_for_source(rel)
        dst = output_dir / packet_path
        entry = copy_file(src, dst)
        entry["packet_path"] = str(packet_path)
        manifest["included_sources"].append(entry)
        copied_files.append(dst)

    if args.source_packet:
        packet_src = Path(args.source_packet).resolve()
        if not packet_src.exists():
            raise FileNotFoundError(f"source packet not found: {packet_src}")
        if packet_src.is_dir():
            manifest["reference_inputs"]["source_packet_dir"] = copy_tree(packet_src, sources_dir / "m23_packet")
        else:
            copied = copy_file(packet_src, sources_dir / packet_src.name)
            manifest["reference_inputs"]["source_packet_file"] = copied
            copied_files.append(Path(copied["copied_to"]))

    if args.audit_bundle:
        audit_src = Path(args.audit_bundle).resolve()
        if not audit_src.exists():
            raise FileNotFoundError(f"audit bundle not found: {audit_src}")
        if audit_src.is_dir():
            manifest["reference_inputs"]["audit_bundle_dir"] = copy_tree(audit_src, sources_dir / "m20_bundle")
        else:
            copied = copy_file(audit_src, sources_dir / audit_src.name)
            manifest["reference_inputs"]["audit_bundle_file"] = copied
            copied_files.append(Path(copied["copied_to"]))

    if args.hosted_run_dir:
        hosted_src = Path(args.hosted_run_dir).resolve()
        if not hosted_src.is_dir():
            raise FileNotFoundError(f"hosted run dir not found: {hosted_src}")
        manifest["reference_inputs"]["hosted_run_dir"] = copy_tree(hosted_src, sources_dir / "m22_hosted_run")

    if args.hosted_validation_dir:
        hosted_validation_src = Path(args.hosted_validation_dir).resolve()
        if not hosted_validation_src.is_dir():
            raise FileNotFoundError(f"hosted validation dir not found: {hosted_validation_src}")
        manifest["reference_inputs"]["hosted_validation_dir"] = copy_tree(
            hosted_validation_src, sources_dir / "m26_hosted_validation"
        )

    generated_templates = {
        templates_dir / "finding_template.md": build_finding_template(args.window_label),
        templates_dir / "session_report_template.md": build_session_template(args.window_label),
        templates_dir / "signoff_checklist.md": build_signoff_checklist(args.window_label),
        templates_dir / "findings_template.json": build_findings_json_template(args.window_label),
        received_dir / "findings.json": build_findings_json_template(args.window_label),
        received_dir / "reports" / "external_cryptographic_review.md": "# Place the returned external cryptographic review report here.\n",
        received_dir / "reports" / "external_redteam_report.md": "# Place the returned external red-team or adversarial testnet report here.\n",
        received_dir / "session_reports" / "README.md": "# Place returned session-level external reports here.\n",
        closeout_dir / "signoff_record.md": build_signoff_record(args.window_label),
        closeout_dir / "signoff_status.json": build_signoff_status_json(args.window_label),
        closeout_dir / "finding_resolution_log.md": build_resolution_log(args.window_label),
        received_dir / "README.md": "# Place external findings, reports, logs, corpora, and traces here.\n",
    }

    for path, text in generated_templates.items():
        write_text(path, text)
        manifest["generated_templates"].append(str(path.relative_to(output_dir)))
        copied_files.append(path)

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
                "window_label": args.window_label,
                "generated_template_count": len(manifest["generated_templates"]),
                "reference_input_count": len(manifest["reference_inputs"]),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
