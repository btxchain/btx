#!/usr/bin/env python3
"""Compile and execute native component tests; preserve honest scoped evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--overlay", type=Path)
    p.add_argument("--integrated-source", type=Path)
    p.add_argument("--build", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    source = args.source.resolve(strict=True)
    overlay = (args.overlay or source).resolve(strict=True)
    integrated = (args.integrated_source or source).resolve(strict=True)
    build = args.build.resolve()
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # C++ private-file writer requires the final output directory to be private.
    if platform.system() != "Windows" and report.parent.stat().st_mode & 0o077:
        raise ValueError("report directory must already be private (chmod 700)")
    result = {"schema": "BTX/ModelSecurityBuildRun/v1", "platform": platform.platform(),
              "physical_hosts": 1, "independent_organizations_verified": False,
              "whole_daemon": "NOT_RUN", "gpu": "NOT_RUN", "release_qualified": False,
              "steps": []}
    def run(label, command, timeout):
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=timeout, check=False)
        log = report.parent / f"{label}.log"
        log.write_bytes(completed.stdout)
        result["steps"].append({"name": label, "exit_code": completed.returncode,
                                "log_sha384": hashlib.sha384(completed.stdout).hexdigest()})
        if completed.returncode:
            raise RuntimeError(f"{label} failed; see {log}")
    try:
        run("configure", ["cmake", "-S", str(overlay / "test/util/model_security"), "-B", str(build),
                          f"-DBTX_SOURCE_ROOT={source}", f"-DBTX_SECURITY_OVERLAY={overlay}",
                          f"-DBTX_INTEGRATED_SOURCE={integrated}"], 120)
        run("build", ["cmake", "--build", str(build), "--parallel", "3"], 600)
        suffix = ".exe" if platform.system() == "Windows" else ""
        command = [str(build / f"security-tests{suffix}")]
        if platform.system() == "Linux":
            command += [str(build / "security-probe"), str(report.parent / "component-results.json")]
        run("component-tests", command, 300)
        run("native-ipc", [str(build / f"security-native-ipc{suffix}"), str(build / f"btx-guardd-security{suffix}")], 60)
        result["status"] = "COMPONENT_TESTS_PASSED"
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["status"] = "FAILED_OR_BLOCKED"
        result["error"] = str(error)
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "COMPONENT_TESTS_PASSED" else 2


if __name__ == "__main__":
    sys.exit(main())
