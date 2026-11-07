# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Ask two supplied RPC endpoints whether modelnet spend is still zero."""

import json
import os
import sys
import urllib.request


def zero_spend(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 0
    if isinstance(value, str):
        return value == "0"
    return False


def rpc(url, method):
    payload = json.dumps(
        {
            "jsonrpc": "1.0",
            "id": "host01",
            "method": method,
            "params": [],
        }
    ).encode("ascii")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read()
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict) or parsed.get("error") is not None:
        raise OSError("rpc")
    result = parsed.get("result")
    if not isinstance(result, dict):
        raise OSError("rpc")
    return result


def main():
    cpu = os.environ.get("BTX_CPU_RPC")
    gpu = os.environ.get("BTX_GPU_RPC")
    if not cpu or not gpu:
        print("TWO_HOST_ABSENT")
        return 2
    if "user:pass@" in cpu or "user:pass@" in gpu:
        print("TWO_HOST_REFUSED")
        return 3
    try:
        rpc(cpu, "getblockchaininfo")
        cpu_model = rpc(cpu, "getmodelnetworkinfo")
        rpc(gpu, "getblockchaininfo")
        gpu_model = rpc(gpu, "getmodelnetworkinfo")
    except Exception:
        print("TWO_HOST_UNREACHABLE")
        return 5
    cpu_spend = cpu_model.get("automatic_spend_atoms")
    gpu_spend = gpu_model.get("automatic_spend_atoms")
    if not zero_spend(cpu_spend) or not zero_spend(gpu_spend):
        print("SPEND_NONEMPTY")
        return 4
    print("CPU_OK")
    print("GPU_OK")
    print("SPEND 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
