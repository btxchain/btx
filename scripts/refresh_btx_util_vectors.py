#!/usr/bin/env python3
"""Refresh BTX utility test vectors for the current chain prefixes.

This tool updates `test/util/data/btx-util-test.json` arguments that still
use legacy Bitcoin mainnet address/WIF encodings and then regenerates all
referenced `output_cmp` artifacts by executing local BTX utility binaries.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def _load_test_framework(repo_root: Path):
    sys.path.insert(0, str((repo_root / "test" / "functional").resolve()))
    from test_framework.address import base58_to_byte, byte_to_base58  # type: ignore
    from test_framework.segwit_addr import decode_segwit_address, encode_segwit_address  # type: ignore

    return base58_to_byte, byte_to_base58, decode_segwit_address, encode_segwit_address


def convert_address(
    addr: str,
    base58_to_byte,
    byte_to_base58,
    decode_segwit_address,
    encode_segwit_address,
) -> str:
    if addr.startswith("bc1"):
        witver, prog = decode_segwit_address("bc", addr)
        if witver is not None:
            return encode_segwit_address("btx", witver, prog)
        return addr

    try:
        payload, version = base58_to_byte(addr)
    except Exception:
        return addr

    if version == 0:  # BTC P2PKH -> BTX P2PKH
        return byte_to_base58(payload, 25)
    if version == 5:  # BTC P2SH -> BTX P2SH
        return byte_to_base58(payload, 50)
    return addr


def convert_wif(wif: str, base58_to_byte, byte_to_base58) -> str:
    try:
        payload, version = base58_to_byte(wif)
    except Exception:
        return wif

    if version == 128:  # BTC secret key -> BTX secret key
        return byte_to_base58(payload, 153)
    return wif


def rewrite_args(testcases, converters) -> tuple[int, int]:
    base58_to_byte, byte_to_base58, decode_segwit_address, encode_segwit_address = converters
    addr_updates = 0
    wif_updates = 0

    for case in testcases:
        args = case.get("args", [])
        for i, arg in enumerate(args):
            if arg.startswith("outaddr="):
                payload = arg[len("outaddr=") :]
                parts = payload.split(":")
                if len(parts) >= 2:
                    old = parts[1]
                    new = convert_address(
                        old,
                        base58_to_byte,
                        byte_to_base58,
                        decode_segwit_address,
                        encode_segwit_address,
                    )
                    if new != old:
                        parts[1] = new
                        args[i] = "outaddr=" + ":".join(parts)
                        addr_updates += 1
            elif arg.startswith("set=privatekeys:"):
                raw_keys = arg[len("set=privatekeys:") :]
                keys = json.loads(raw_keys)
                new_keys = []
                changed = False
                for key in keys:
                    new_key = convert_wif(key, base58_to_byte, byte_to_base58)
                    changed = changed or (new_key != key)
                    if new_key != key:
                        wif_updates += 1
                    new_keys.append(new_key)
                if changed:
                    args[i] = "set=privatekeys:" + json.dumps(new_keys, separators=(",", ":"))

    return addr_updates, wif_updates


def validate_output(stdout: str, output_path: Path) -> None:
    ext = output_path.suffix.lower().lstrip(".")
    if ext == "json":
        json.loads(stdout)
    elif ext == "hex":
        bytes.fromhex(stdout.strip())
    else:
        raise ValueError(f"Unsupported output format: {output_path.name}")


def regenerate_outputs(repo_root: Path, build_dir: Path, testcases) -> list[str]:
    data_dir = repo_root / "test" / "util" / "data"
    bin_dir = build_dir / "bin"
    exeext = ".exe" if os.name == "nt" else ""
    failures = []

    for case in testcases:
        exec_name = case["exec"].replace("./", "")
        canonical_exec = {
            "bitcoind": "btxd",
            "bitcoin-cli": "btx-cli",
            "bitcoin-wallet": "btx-wallet",
            "bitcoin-tx": "btx-tx",
            "bitcoin-util": "btx-util",
        }.get(exec_name, exec_name)
        exec_path = bin_dir / f"{canonical_exec}{exeext}"
        if not exec_path.exists():
            exec_path = bin_dir / f"{exec_name}{exeext}"

        if not exec_path.exists():
            failures.append(f"Missing executable for testcase '{case.get('description', '')}': {exec_path}")
            continue

        cmd = [str(exec_path), *case.get("args", [])]
        input_data = None
        if "input" in case:
            input_data = (data_dir / case["input"]).read_text(encoding="utf8")

        res = subprocess.run(cmd, input=input_data, capture_output=True, text=True, check=False)
        expected_rc = case.get("return_code", 0)
        if res.returncode != expected_rc:
            failures.append(
                f"Return code mismatch for '{case.get('description', '')}': expected {expected_rc}, got {res.returncode}\n"
                f"stderr: {res.stderr.strip()}"
            )
            continue

        expected_error = case.get("error_txt")
        if expected_error and expected_error not in res.stderr:
            failures.append(
                f"Error text mismatch for '{case.get('description', '')}': expected to contain '{expected_error}', "
                f"got '{res.stderr.strip()}'"
            )
            continue

        output_cmp = case.get("output_cmp")
        if output_cmp:
            output_path = data_dir / output_cmp
            try:
                validate_output(res.stdout, output_path)
            except Exception as exc:
                failures.append(
                    f"Output validation failed for '{case.get('description', '')}' ({output_cmp}): {exc}"
                )
                continue
            output_path.write_text(res.stdout, encoding="utf8")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]), help="Path to btx-node repo")
    parser.add_argument("--build-dir", required=True, help="CMake build directory containing bin/btx-tx (legacy aliases accepted)")
    parser.add_argument(
        "--json-file",
        default="test/util/data/btx-util-test.json",
        help="Utility testcase JSON path relative to repo root",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    build_dir = Path(args.build_dir).resolve()
    json_file = repo_root / args.json_file

    base58_to_byte, byte_to_base58, decode_segwit_address, encode_segwit_address = _load_test_framework(repo_root)

    testcases = json.loads(json_file.read_text(encoding="utf8"))
    addr_updates, wif_updates = rewrite_args(
        testcases,
        (base58_to_byte, byte_to_base58, decode_segwit_address, encode_segwit_address),
    )
    json_file.write_text(json.dumps(testcases, indent=2) + "\n", encoding="utf8")

    failures = regenerate_outputs(repo_root, build_dir, testcases)
    if failures:
        print("refresh_btx_util_vectors failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print(
        "refresh_btx_util_vectors complete: "
        f"updated {addr_updates} outaddr entries and {wif_updates} WIF entries; regenerated outputs."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
