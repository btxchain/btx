#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Offline helper regression for local provider state, without a node or wallet.

Run: python3 test/util/modelnet_provider_state.py --modeld /absolute/path/btx-modeld
Requires a POSIX helper with its private Unix RPC available. All catalog files,
identities and tiny nonexecuted SafeTensors fixtures are temporary. External
listeners, discovery, model following and model execution are disabled.
"""
import argparse
import errno
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modeld", type=Path, required=True)
    parser.add_argument("--result", type=Path, help="Optional JSON result file")
    args = parser.parse_args()
    binary = args.modeld.resolve(strict=True)
    checks = []
    stops = []

    def check(label, actual, expected):
        passed = actual == expected
        checks.append(dict(label=label, actual=actual, expected=expected, passed=passed))
        print(f"{'PASS' if passed else 'FAIL'} {label}", flush=True)

    with tempfile.TemporaryDirectory(prefix="btx-provider-") as temporary:
        root = Path(temporary)
        modeldir = root / "models"
        modeldir.mkdir()
        endpoint = root / "rpc.sock"
        process = None
        log = (root / "helper.log").open("wb")

        def rpc(method, params=None):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(20)
                connection.connect(str(endpoint))
                connection.sendall((json.dumps(dict(id=1, method=method, params=params or [])) + "\n").encode())
                try:
                    connection.shutdown(socket.SHUT_WR)
                except OSError as error:
                    if error.errno != errno.ENOTCONN:
                        raise
                data = bytearray()
                while b"\n" not in data:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > 2 * 1024 * 1024:
                        raise RuntimeError("Unexpectedly large helper reply")
            reply = json.loads(data)
            if reply.get("error"):
                raise RuntimeError(f"{method}: {reply['error']}")
            return reply["result"]

        def start():
            nonlocal process
            process = subprocess.Popen([
                str(binary), f"-modeldir={modeldir}", f"-modelrpcsocket={endpoint}",
                "-modelstorage=16MiB", "-modelhost=0",
                "-modelseed=off", "-modelfollowpeers=0", "-modellandiscovery=0",
                "-modelnatpmp=0", "-pwcchain=regtest",
            ], stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Helper exited during startup")
                try:
                    if rpc("getmodelnetworkinfo").get("pq1_ready"):
                        return
                except (OSError, ValueError):
                    pass
                time.sleep(0.1)
            raise RuntimeError("Helper did not become ready")

        def stop():
            if process is not None and process.poll() is None:
                mode = "terminate"
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    mode = "kill_after_timeout"
                    process.kill()
                    process.wait(timeout=5)
                stops.append(dict(mode=mode, returncode=process.returncode))

        def local(mid):
            providers = rpc("getmodelproviders", [mid])["providers"]
            return sum(p["provider_id"] == "local" for p in providers)

        def refresh():
            return rpc("searchmodels", [dict(scope="LOCAL", text="", limit=10)])

        def positive_metadata(mid):
            return [dict(complete=p["complete"], direct=p["direct"], relayed=p["relayed"])
                    for p in rpc("getmodelproviders", [mid])["providers"] if p["provider_id"] == "local"]

        def search_counts(label, expected):
            rows = {row["model_id"]: row for row in refresh()["results"]}
            for mid, count in expected.items():
                actual = rows[mid]["availability"]["providers_complete"] if mid in rows else 0
                check(f"{label}: {mid[:8]}", actual, count)

        def seeded(mid):
            return next(m["seeded"] for m in rpc("listmodels")["models"] if m["model_id"] == mid)

        def fixture(tag):
            header = json.dumps({"weight": dict(dtype="F32", shape=[256], data_offsets=[0, 1024])}, separators=(",", ":")).encode()
            header += b" " * (-len(header) % 8)
            path = root / f"model-{tag}.safetensors"
            path.write_bytes(struct.pack("<Q", len(header)) + header + bytes([tag]) * 1024)
            return rpc("importmodel", [str(path)])["model_id"]

        try:
            start()
            target, other = fixture(1), fixture(2)
            for mid in [target, other]:
                rpc("seedmodel", [mid])
            search_counts("seeded search", {target: 1, other: 1})  # Populate the old cached-local path.
            check("seeded target visible", local(target), 1)
            check("unrelated seeded model visible", local(other), 1)
            check("seeded provider metadata", positive_metadata(target), [dict(complete=True, direct=True, relayed=False)])
            check("seeded availability complete count", rpc("getmodelavailability", [target])["providers_complete"], 1)
            check("seeded availability total count", rpc("getmodelavailability", [target])["providers_total"], 1)
            check("seeded peer complete count", rpc("getmodelpeercount", [target])["complete"], 1)
            check("directory preserves seeded provider", rpc("getmodeldirectoryentry", [other])["availability"]["providers_complete"], 1)
            rpc("unhostmodel", [target])
            check("unhost updates catalog", seeded(target), False)
            check("unhost clears local provider", local(target), 0)
            check("unhost preserves unrelated model", local(other), 1)
            rpc("seedmodel", [target])
            refresh()
            check("reseed restores local provider", local(target), 1)
            rpc("unseedmodel", [target])
            check("unseed updates catalog", seeded(target), False)
            check("unseed clears local provider", local(target), 0)
            search_counts("unseeded search", {target: 0, other: 1})
            check("refresh does not restore unseeded provider", local(target), 0)
            rpc("seedmodel", [target])
            refresh()
            check("second reseed restores provider", local(target), 1)
            rpc("removemodel", [target])
            check("remove clears local provider", local(target), 0)
            search_counts("removed search", {target: 0, other: 1})
            check("refresh does not restore removed provider", local(target), 0)
            check("remove preserves unrelated model", local(other), 1)
            check("catalog contains only the retained model", [m["model_id"] for m in rpc("listmodels")["models"]], [other])
            check("unknown provider list is empty", rpc("getmodelproviders", ["11" * 48])["providers"], [])
            availability = rpc("getmodelavailability", [target])
            check("availability remains UNKNOWN", availability["class"], "UNKNOWN")
            check("reconstructability remains unknown", availability["reconstructable_known"], False)
            flagged = fixture(3)
            rpc("seedmodel", [flagged])
            refresh()
            check("third fixture initially visible", local(flagged), 1)
            rpc("reportmodelmalicious", [flagged])
            check("catalog stops seeding reported fixture", next(m["seeded"] for m in rpc("listmodels")["models"] if m["model_id"] == flagged), False)
            check("catalog-owned unseed clears provider", local(flagged), 0)
            check("availability count follows catalog", rpc("getmodelavailability", [flagged])["providers_complete"], 0)
            check("peer count follows catalog", rpc("getmodelpeercount", [flagged])["complete"], 0)
            search_counts("reported search", {flagged: 0, other: 1})
            check("refresh does not restore reported fixture", local(flagged), 0)
            for method in ["getmodeldirectoryentry", "getmodeleconomyentry"]:
                check(f"{method} has no complete local provider", rpc(method, [flagged])["availability"]["providers_complete"], 0)
            check("other seeded model survives catalog unseed", local(other), 1)
            stop()
            start()
            search_counts("restarted search", {target: 0, other: 1, flagged: 0})
            check("restart keeps removed model absent", local(target), 0)
            check("restart preserves retained seeded model", local(other), 1)
            check("restart keeps reported model absent", local(flagged), 0)
        except Exception:
            log.flush()
            print((root / "helper.log").read_text(errors="replace"))
            raise
        finally:
            stop()
            log.close()
    result = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), checks=checks,
                  passed=all(c["passed"] for c in checks), helper_stopped=True, temporary_files_removed=True, stops=stops)
    if args.result:
        args.result.write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
