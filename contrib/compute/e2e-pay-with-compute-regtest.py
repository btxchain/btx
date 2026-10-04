#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Run the isolated Pay With Compute regtest scenarios.

The functional tests start temporary btxd/btx-modeld datadirs. This script
does not touch a production datadir, a wallet, or a live node.
Toy profile results are REGTEST ONLY.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    build = os.environ.get("BTX_BUILDDIR", "")
    if not build and (ROOT / "build" / "test" / "config.ini").is_file():
        build = str(ROOT / "build")
    config = Path(build) / "test" / "config.ini" if build else Path()
    if not build or not config.is_file():
        sys.exit("set BTX_BUILDDIR to a configured build tree")
    runner = Path(__file__).with_name("reference-job-runner.py")
    sample = subprocess.run(
        [sys.executable, str(runner)],
        input='{"job_class":"REGTEST_DETERMINISTIC","input_commitment":"demo"}\n',
        text=True,
        check=True,
        capture_output=True,
    )
    if "output_commitment" not in sample.stdout:
        sys.exit("regtest job runner failed")
    rejected = subprocess.run(
        [sys.executable, str(runner)],
        input='{"job_class":"REGTEST_DETERMINISTIC","command":"uname"}\n',
        text=True,
        check=False,
        capture_output=True,
    )
    if rejected.returncode == 0:
        sys.exit("job runner accepted a command")
    tests = [
        "rpc_compute_qualification.py",
        "feature_modelnet_compute_economy.py",
        "feature_pay_with_compute.py",
    ]
    for name in tests:
        cmd = [
            sys.executable,
            str(ROOT / "test" / "functional" / name),
            f"--configfile={config}",
            "--timeout-factor=1",
        ]
        if name != "rpc_compute_qualification.py":
            cmd.append("--descriptors")
        print("RUN", name, flush=True)
        subprocess.check_call(cmd)
    print("PWC regtest scenarios passed")


if __name__ == "__main__":
    main()
