#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Synthetic token files only; test real POSIX permissions / Windows ACLs."""
import csv
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    exe = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="btx-token-test-") as temp:
        root = Path(temp)
        token = root / "token"
        token.write_bytes(b"x" * 32)
        def acl(*args):
            subprocess.run(["icacls", str(token), *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if os.name == "nt":
            identity = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True)
            sid = next(csv.reader([identity.strip()]))[1]
            acl("/inheritance:r", "/grant:r", "*" + sid + ":(F)",
                "*S-1-5-18:(F)", "*S-1-5-32-544:(F)")
        else:
            token.chmod(0o600)
        def check(path, accept):
            subprocess.run([exe, str(path), "accept" if accept else "reject"], check=True, timeout=3)
        check(token, True)
        token.write_bytes(b"x" * 4096 + b"\r\n")
        check(token, True)
        token.write_bytes(b"x" * 31)
        check(token, False)
        token.write_bytes(b"x" * 4097)
        check(token, False)
        token.write_bytes(b"x" * 32)
        if os.name == "nt":
            acl("/grant", "*S-1-1-0:(R)")
            check(token, False)
            acl("/remove:g", "*S-1-1-0")
        else:
            token.chmod(0o644)
            check(token, False)
            token.chmod(0o600)
            link = root / "link"
            link.symlink_to(token)
            check(link, False)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            # An empty FIFO is also refused by the length check. Keep a reader
            # open, queue a valid-length token, then close the writer so a
            # loader with S_ISREG removed can read the bytes and reach EOF.
            reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            try:
                writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                try:
                    assert os.write(writer, b"x" * 32) == 32
                finally:
                    os.close(writer)
                check(fifo, False)
            finally:
                os.close(reader)
            if os.geteuid() == 0:
                # Root can read this 0600 file despite its different UID, so
                # neither DAC nor another guard can mask a missing owner check.
                # UID 1 is only a numeric file owner; no account is created.
                foreign = root / "foreign-owner"
                foreign.write_bytes(b"x" * 32)
                foreign.chmod(0o600)
                os.chown(foreign, 1, -1)
                assert foreign.read_bytes() == b"x" * 32, "fixture must be readable despite its foreign UID"
                check(foreign, False)
                print("foreign-owner rejection passed (privileged POSIX fixture)")
            else:
                print("SKIP: isolated POSIX owner check requires an effective UID of 0")
        check(token, True)
        check(root, False)
        check(root / "missing", False)
    print("private token loading, size limits and unsafe access rejection passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
