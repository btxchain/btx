#!/usr/bin/env python3
"""Fail-closed installer signature check.

A missing path is NOT_RUN. An existing path is not treated as signed unless it
is a Windows installer and Windows Authenticode reports Status Valid.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

WINDOWS_INSTALLER_SUFFIXES = {".exe", ".msi", ".msix"}


def emit(payload: dict) -> None:
    print(json.dumps(payload, separators=(",", ":")), flush=True)


def is_windows_installer(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in WINDOWS_INSTALLER_SUFFIXES


def authenticode_status(path: Path) -> tuple[int, str]:
    literal = str(path).replace("'", "''")
    command = (
        "$sig = Get-AuthenticodeSignature -LiteralPath '{0}'; "
        "if ($null -eq $sig) {{ exit 1 }}; "
        "Write-Output $sig.Status"
    ).format(literal)
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    status = lines[-1] if lines else ""
    return completed.returncode, status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    args = parser.parse_args(argv)
    path = Path(args.path)
    if not path.exists():
        emit({"status": "NOT_RUN", "reason": "no installer"})
        return 2
    if is_windows_installer(path) and sys.platform.startswith("win"):
        try:
            code, status = authenticode_status(path)
        except (OSError, subprocess.SubprocessError):
            emit({"status": "FAIL"})
            return 1
        if code == 0 and status == "Valid":
            print("SIGNED", flush=True)
            return 0
        emit({"status": "FAIL"})
        return 1
    emit(
        {
            "status": "NOT_RUN",
            "reason": "signature check is not implemented for this host",
        }
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
