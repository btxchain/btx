#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate a populated BTX external-review intake packet against DoD 8 closeout rules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


RESOLVED_STATUSES = {"fixed", "duplicate", "not_applicable", "proven_not_applicable"}
SEVERITIES = ["critical", "high", "medium", "low", "informational"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a populated external BTX findings-intake packet for DoD 8 closeout readiness."
    )
    parser.add_argument("--intake-dir", required=True, help="Path to a populated m24 intake directory")
    parser.add_argument(
        "--output",
        help="Optional summary JSON output path (default: <intake-dir>/closeout/closeout_summary.json)",
    )
    return parser.parse_args()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def unresolved_counts(reports: list[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for report in reports:
        severity = report.get("severity", "").lower()
        status = report.get("status", "").lower()
        if severity not in counts:
            continue
        if status not in RESOLVED_STATUSES:
            counts[severity] += 1
    return counts


def missing_or_placeholder_markdown(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    lines = {line.strip() for line in text.splitlines()}
    exact_placeholder_lines = {
        "- Status:",
        "- Decision date:",
        "- Operator:",
        "- External cryptographic review report:",
        "- External red-team / testnet report:",
        "- Supporting logs / corpora:",
        "- Critical:",
        "- High:",
        "- Medium:",
        "- Low / informational:",
    }
    if "Replace me" in text or "example-001" in text:
        return True
    return any(line in lines for line in exact_placeholder_lines)


def main() -> int:
    args = parse_args()
    intake_dir = Path(args.intake_dir).resolve()
    output_path = Path(args.output).resolve() if args.output else intake_dir / "closeout" / "closeout_summary.json"

    required_files = {
        "findings_json": intake_dir / "received" / "findings.json",
        "crypto_report": intake_dir / "received" / "reports" / "external_cryptographic_review.md",
        "redteam_report": intake_dir / "received" / "reports" / "external_redteam_report.md",
        "signoff_status": intake_dir / "closeout" / "signoff_status.json",
        "signoff_record": intake_dir / "closeout" / "signoff_record.md",
        "resolution_log": intake_dir / "closeout" / "finding_resolution_log.md",
    }

    missing_files = [name for name, path in required_files.items() if not path.exists()]
    findings = read_json(required_files["findings_json"]) if not missing_files else {}
    signoff = read_json(required_files["signoff_status"]) if not missing_files else {}

    reports = findings.get("reports", [])
    counts = unresolved_counts(reports) if reports else {severity: 0 for severity in SEVERITIES}

    blockers: list[str] = []
    if missing_files:
        blockers.append(f"missing required files: {', '.join(missing_files)}")

    if findings.get("overall_status") == "pending_external_input":
        blockers.append("findings.json still indicates pending external input")

    if signoff.get("overall_status") == "pending_external_input":
        blockers.append("signoff_status.json still indicates pending external input")

    if not signoff.get("external_cryptographic_review_completed", False):
        blockers.append("external cryptographic review not marked complete")
    if not signoff.get("external_redteam_completed", False):
        blockers.append("external red-team campaign not marked complete")
    if not signoff.get("tracker_updated", False):
        blockers.append("tracker update not marked complete")
    if not signoff.get("readiness_matrix_updated", False):
        blockers.append("readiness matrix update not marked complete")
    if signoff.get("final_status") != "pass":
        blockers.append("final_status is not pass")

    if counts["critical"] > 0:
        blockers.append(f"{counts['critical']} unresolved critical finding(s) remain")
    if counts["high"] > 0:
        blockers.append(f"{counts['high']} unresolved high-severity finding(s) remain")

    if required_files["signoff_record"].exists() and missing_or_placeholder_markdown(required_files["signoff_record"]):
        blockers.append("signoff_record.md still contains placeholder content")
    if required_files["resolution_log"].exists() and missing_or_placeholder_markdown(required_files["resolution_log"]):
        blockers.append("finding_resolution_log.md still contains placeholder content")

    summary = {
        "format_version": 1,
        "overall_status": "pass" if not blockers else "fail",
        "intake_dir": str(intake_dir),
        "missing_files": missing_files,
        "unresolved_counts": counts,
        "report_count": len(reports),
        "blockers": blockers,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if not blockers else 1


if __name__ == "__main__":
    raise SystemExit(main())
