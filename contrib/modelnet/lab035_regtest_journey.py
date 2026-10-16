#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Three local regtest nodes, two Git origins, and a separate WAN quorum check.

Uses the private btxd only. Does not touch a production datadir or spend a wallet.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

TREE = Path(os.environ.get("BTX035_ROOT", Path(__file__).resolve().parents[3]))
BUILD = Path(os.environ.get("BTX035_BIN", TREE / "builds" / "gcc13-release" / "bin"))
BTXD = BUILD / "btxd"
CLI = BUILD / "btx-cli"
ROOT = TREE / "test-data" / "lab035-journey"
HELPER = Path(__file__).resolve().parent / "git-remote-btx"

MATMUL = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]

ROLES = ("researcher-a", "researcher-b", "researcher-c", "wan-attestor")


def rpc(datadir: Path, port: int, *args: str) -> dict:
    proc = subprocess.run(
        [str(CLI), "-regtest", f"-datadir={datadir}", f"-rpcport={port}", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    if not proc.stdout.strip():
        return {}
    return json.loads(proc.stdout)


def start_node(name: str, index: int) -> tuple[Path, int, subprocess.Popen]:
    datadir = ROOT / name
    datadir.mkdir(parents=True)
    rpcport = 29100 + index
    port = 29200 + index
    log = open(datadir / "stdout.log", "w")
    proc = subprocess.Popen(
        [
            str(BTXD),
            "-regtest",
            f"-datadir={datadir}",
            f"-port={port}",
            f"-rpcport={rpcport}",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-bind=127.0.0.1",
            "-listen=1",
            "-server=1",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-daemon=0",
            *MATMUL,
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited {proc.returncode}")
        try:
            rpc(datadir, rpcport, "getblockchaininfo")
            return datadir, rpcport, proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"{name} did not answer RPC")


def stop_node(datadir: Path, port: int, proc: subprocess.Popen) -> None:
    try:
        rpc(datadir, port, "stop")
    except Exception:
        proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()


def git_origin(name: str) -> str:
    env = os.environ.copy()
    env["PATH"] = str(HELPER.parent) + os.pathsep + env.get("PATH", "")
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    repo = ROOT / name
    state = ROOT / f"{name}-state"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
    (repo / "README").write_text(name + "\n", encoding="utf-8")
    base = ["git", "-C", str(repo), "-c", "user.email=lab@example.com", "-c", "user.name=lab", "-c", "protocol.btx.allow=always"]
    subprocess.run([*base, "add", "README"], check=True, env=env)
    subprocess.run([*base, "commit", "-q", "-m", name], check=True, env=env)
    url = "btx://local/" + str(state)
    pushed = subprocess.run([*base, "push", url, "HEAD:refs/heads/main"], check=False, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if pushed.returncode != 0:
        raise RuntimeError(pushed.stderr)
    return url


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    nodes = []
    try:
        origins = [git_origin("origin-a"), git_origin("origin-b")]
        if origins[0] == origins[1]:
            raise RuntimeError("git origins were not distinct")
        for index, name in enumerate(ROLES):
            nodes.append((name, *start_node(name, index)))
        report = {"origins": origins, "nodes": []}
        for name, datadir, port, _proc in nodes:
            info = rpc(datadir, port, "getblockchaininfo")
            if info.get("chain") != "regtest":
                raise RuntimeError(f"{name} is not regtest")
            generated = rpc(datadir, port, "lab035", "lab035.identity.generate", "{}")
            if generated.get("wallet_spend") is not False or generated.get("secret_returned") is not False:
                raise RuntimeError(f"{name} exposed spend or a secret")
            if not generated.get("root_id"):
                raise RuntimeError(f"{name} did not create an identity")
            refused = subprocess.run(
                [str(CLI), "-regtest", f"-datadir={datadir}", f"-rpcport={port}", "lab035", "lab035.not.a.method", "{}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if "BTX035_NOT_IMPLEMENTED" not in refused.stderr + refused.stdout:
                raise RuntimeError(refused.stderr or refused.stdout)
            quorum = rpc(
                datadir,
                port,
                "lab035",
                "lab035.wan.quorum",
                json.dumps(
                    {
                        "realm": "lab-realm" if name != "wan-attestor" else "other-realm",
                        "threshold": 2,
                        "pinned_ids": ["a", "b", "c"],
                        "signer_ids": ["a", "b"],
                    }
                ),
            )
            report["nodes"].append(
                {
                    "name": name,
                    "blocks": info.get("blocks"),
                    "root_id": generated["root_id"],
                    "quorum": quorum.get("quorum"),
                    "threshold": quorum.get("threshold"),
                }
            )
        roots = [row["root_id"] for row in report["nodes"]]
        if len(set(roots)) != len(roots):
            raise RuntimeError("nodes shared one research identity")
        if any(row["threshold"] != 2 for row in report["nodes"]):
            raise RuntimeError("revocation-independent threshold was not 2")
        out = TREE / "logs" / "lab035-journey.json"
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("PASS")
        print(out)
        return 0
    finally:
        for name, datadir, port, proc in nodes:
            stop_node(datadir, port, proc)
        shutil.rmtree(ROOT, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
