#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check a ComputeAccessGrant before an external service would allow access.

Signature verification is delegated to btx-cli verifycomputeaccessgrant.
This script does not execute a model and does not spend BTX.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="REGTEST/demo access gate for a ComputeAccessGrant")
    parser.add_argument("--btx-cli", default="btx-cli")
    parser.add_argument("--datadir")
    parser.add_argument("--regtest", action="store_true")
    parser.add_argument("--rpcuser")
    parser.add_argument("--rpcpassword")
    parser.add_argument("--rpcport")
    parser.add_argument("--grant", help="Path to a grant envelope JSON")
    parser.add_argument("--trusted-issuer", help="Resource provider application public key")
    parser.add_argument("--subject")
    parser.add_argument("--resource")
    parser.add_argument("--right", action="append", default=[])
    parser.add_argument("--now-ms", type=int)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.grant or not args.trusted_issuer:
        out = {"permitted": False, "reason": "COMPUTE_GRANT_INVALID"}
        print(json.dumps(out) if args.json else "DENIED")
        sys.exit(1)
    grant = json.loads(open(args.grant, encoding="utf-8").read())
    req = {"envelope": grant, "trusted_issuer_pubkey": args.trusted_issuer}
    if args.subject:
        req["subject_pubkey"] = args.subject
    if args.resource:
        req["resource_ref"] = args.resource
    if args.now_ms is not None:
        req["now_ms"] = args.now_ms
    cmd = [args.btx_cli]
    if args.regtest:
        cmd.append("-regtest")
    if args.datadir:
        cmd.append(f"-datadir={args.datadir}")
    if args.rpcuser is not None:
        cmd.append(f"-rpcuser={args.rpcuser}")
    if args.rpcpassword is not None:
        cmd.append(f"-rpcpassword={args.rpcpassword}")
    if args.rpcport is not None:
        cmd.append(f"-rpcport={args.rpcport}")
    cmd += ["verifycomputeaccessgrant", json.dumps(req)]
    proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if proc.returncode != 0:
        out = {"permitted": False, "reason": (proc.stderr or proc.stdout).strip()}
        print(json.dumps(out) if args.json else "DENIED")
        sys.exit(1)
    verdict = json.loads(proc.stdout)
    rights = verdict.get("rights") or []
    missing = [r for r in args.right if r not in rights]
    permitted = bool(verdict.get("valid")) and not missing
    out = {"permitted": permitted, "verdict": verdict, "missing_rights": missing}
    if args.json:
        print(json.dumps(out))
    else:
        print("ALLOWED" if permitted else "DENIED")
    sys.exit(0 if permitted else 1)


if __name__ == "__main__":
    main()
