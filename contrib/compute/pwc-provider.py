#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Provider orchestrator. Talks to local btxd only.

It does not read a wallet, sign a transaction, or execute job text.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


def rpc(args, method, *params):
    cmd = [args.btx_cli]
    if args.regtest:
        cmd.append("-regtest")
    if args.datadir:
        cmd.append(f"-datadir={args.datadir}")
    cmd.append(method)
    for param in params:
        cmd.append(param if isinstance(param, str) else json.dumps(param))
    proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr or proc.stdout)
        raise SystemExit(proc.returncode)
    text = proc.stdout.strip()
    if args.json:
        try:
            print(json.dumps(json.loads(text)))
        except json.JSONDecodeError:
            print(text)
    else:
        print(text)
    return text


def load(path):
    return json.loads(open(path, encoding="utf-8").read())


def main() -> None:
    parser = argparse.ArgumentParser(description="Pay With Compute provider steps")
    parser.add_argument("--btx-cli", default="btx-cli")
    parser.add_argument("--datadir")
    parser.add_argument("--regtest", action="store_true")
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)
    issue = sub.add_parser("issue-qualification")
    issue.add_argument("--subject", required=True)
    issue.add_argument("--profile", default="btx-rc-p1e-toy-v1")
    issue.add_argument("--episodes", type=int, default=1)
    issue.add_argument("--expires", type=int, default=300)
    redeem = sub.add_parser("redeem")
    redeem.add_argument("--challenge", required=True)
    redeem.add_argument("--response", required=True)
    agree = sub.add_parser("agree")
    agree.add_argument("--request", required=True)
    job = sub.add_parser("job")
    job.add_argument("--request", required=True)
    accept = sub.add_parser("accept")
    accept.add_argument("--request", required=True)
    bal = sub.add_parser("balance")
    bal.add_argument("--agreement", required=True)
    bal.add_argument("--now-ms", type=int)
    grant = sub.add_parser("grant")
    grant.add_argument("--agreement", required=True)
    grant.add_argument("--now-ms", type=int)
    args = parser.parse_args()
    if args.cmd == "issue-qualification":
        rpc(args, "issuecomputequalification", args.subject, args.profile, str(args.episodes), str(args.expires))
    elif args.cmd == "redeem":
        rpc(args, "redeemcomputequalification", json.dumps(load(args.challenge)), json.dumps(load(args.response)))
    elif args.cmd == "agree":
        rpc(args, "issuecomputeagreement", load(args.request))
    elif args.cmd == "job":
        rpc(args, "createcomputejob", load(args.request))
    elif args.cmd == "accept":
        rpc(args, "acceptcomputejobresult", load(args.request))
    elif args.cmd == "balance":
        req = {"agreement_id": args.agreement}
        if args.now_ms is not None:
            req["now_ms"] = args.now_ms
        rpc(args, "getcomputebalance", req)
    elif args.cmd == "grant":
        req = {"agreement_id": args.agreement}
        if args.now_ms is not None:
            req["now_ms"] = args.now_ms
        rpc(args, "issuecomputeaccessgrant", req)


if __name__ == "__main__":
    main()
