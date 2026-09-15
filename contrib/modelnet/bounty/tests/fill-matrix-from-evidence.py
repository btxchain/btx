#!/usr/bin/env python3
"""Fill acceptance-matrix.csv from an evidence JSON produced after executed tests.

Never marks PASS without a matching evidence record. Unknown IDs stay NOT_RUN.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
CSV_PATH = Path(__file__).resolve().parent / "acceptance-matrix.csv"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: fill-matrix-from-evidence.py EVIDENCE.json", file=sys.stderr)
        return 2
    ev_path = Path(sys.argv[1])
    evidence = json.loads(ev_path.read_text())
    by_id = {row["test_id"]: row for row in evidence.get("rows", []) if "test_id" in row}

    with CSV_PATH.open(newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    updated = 0
    for row in rows:
        ev = by_id.get(row["test_id"])
        if not ev:
            continue
        status = ev.get("status")
        if status not in ("PASS", "FAIL", "UNSUPPORTED_ENVIRONMENT", "DEFERRED_WITH_APPROVAL"):
            continue
        row["status"] = status
        row["source_sha"] = ev.get("source_sha", "")
        row["command"] = ev.get("command", "")
        row["environment"] = ev.get("environment", "")
        row["evidence_path"] = ev.get("evidence_path", "")
        row["evidence_sha256"] = ev.get("evidence_sha256", "")
        row["executed_at_utc"] = ev.get("executed_at_utc", "")
        row["reviewer"] = ev.get("reviewer", "local-reconcile")
        row["notes"] = ev.get("notes", row.get("notes", ""))
        updated += 1

    with CSV_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"updated {updated} rows from {ev_path}")
    print(f"csv_sha256 {sha256_file(CSV_PATH)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
