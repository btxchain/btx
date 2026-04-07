#!/usr/bin/env python3
#
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Detect accidental P2MR-only OP_SUCCESS opcodes in tapscript descriptor tests.

The check scans functional tests and test vectors for tr(..., raw(<hex>)) usage.
If the decoded script contains opcode 0xbb/0xbc/0xbd, an
INTENTIONAL_OP_SUCCESS_TEST annotation is required on the same or previous line.
"""

import subprocess
import sys
from pathlib import Path
import re


ANNOTATION = "INTENTIONAL_OP_SUCCESS_TEST"
TR_EXPR_RE = re.compile(r"tr\s*\((.*?)\)", re.DOTALL)
RAW_RE = re.compile(r"raw\s*\(\s*([0-9a-fA-F]+)\s*\)")
DISALLOWED_OPCODES = {0xBB, 0xBC, 0xBD}


def git_ls_files(pathspecs: list[str]) -> list[Path]:
    out = subprocess.check_output(
        ["git", "ls-files", "--", *pathspecs],
        text=True,
        encoding="utf8",
    )
    return [Path(line) for line in out.splitlines() if line]


def script_has_disallowed_opcode(script: bytes) -> bool:
    i = 0
    script_len = len(script)
    while i < script_len:
        opcode = script[i]
        i += 1
        if opcode in DISALLOWED_OPCODES:
            return True
        if opcode <= 75:
            i += opcode
            continue
        if opcode == 0x4C:  # OP_PUSHDATA1
            if i >= script_len:
                return False
            push_len = script[i]
            i += 1 + push_len
            continue
        if opcode == 0x4D:  # OP_PUSHDATA2
            if i + 1 >= script_len:
                return False
            push_len = script[i] | (script[i + 1] << 8)
            i += 2 + push_len
            continue
        if opcode == 0x4E:  # OP_PUSHDATA4
            if i + 3 >= script_len:
                return False
            push_len = (
                script[i]
                | (script[i + 1] << 8)
                | (script[i + 2] << 16)
                | (script[i + 3] << 24)
            )
            i += 4 + push_len
            continue
    return False


def line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def main() -> int:
    files = git_ls_files([
        "test/functional/**/*.py",
        "test/functional/data/**/*.json",
    ])
    violations: list[str] = []

    for path in files:
        text = path.read_text(encoding="utf8")
        lines = text.splitlines()
        for tr_match in TR_EXPR_RE.finditer(text):
            tr_body = tr_match.group(1)
            for raw_match in RAW_RE.finditer(tr_body):
                raw_hex = raw_match.group(1)
                if len(raw_hex) % 2 != 0:
                    continue
                script = bytes.fromhex(raw_hex)
                if not script_has_disallowed_opcode(script):
                    continue
                abs_pos = tr_match.start(1) + raw_match.start(1)
                ln = line_number(text, abs_pos)
                same_line = lines[ln - 1] if 0 < ln <= len(lines) else ""
                prev_line = lines[ln - 2] if ln - 2 >= 0 else ""
                if ANNOTATION in same_line or ANNOTATION in prev_line:
                    continue
                violations.append(
                    f"{path}:{ln}: tr(..., raw(...)) includes 0xbb/0xbc/0xbd without {ANNOTATION}"
                )

    if violations:
        print(
            "Found tapscript descriptor raw leaves containing P2MR-only OP_SUCCESS opcodes "
            "(0xbb-0xbd) without explicit annotation:"
        )
        for violation in violations:
            print(f"  - {violation}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
