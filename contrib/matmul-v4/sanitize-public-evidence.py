#!/usr/bin/env python3
"""Redact creator-machine identity from text copied into public evidence."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


# Construct creator-path prefixes so this sanitizer can itself be covered by
# the publication privacy scan without its matching expressions being mistaken
# for leaked paths.
UNIX_HOME_PREFIX = "/" + "home" + "/"
MAC_HOME_PREFIX = "/" + "Users" + "/"


def redact_text(text: str, *, extra_hosts: tuple[str, ...] = ()) -> str:
    home = os.path.expanduser("~")
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    host = os.uname().nodename if hasattr(os, "uname") else ""

    if home and home != "~":
        text = text.replace(home, "<redacted-home>")
    for candidate in (host, *extra_hosts):
        if candidate:
            text = re.sub(re.escape(candidate), "<redacted-host>", text, flags=re.I)
    if user:
        text = re.sub(rf"\b{re.escape(user)}\b", "<redacted-user>", text)

    # Redact the complete path. Retaining a synthetic creator-home prefix with
    # only its account segment replaced still leaks path shape and is rejected
    # by the publication gate.
    terminator = r"[^\s\"']*"
    text = re.sub(
        re.escape(UNIX_HOME_PREFIX) + r"[^/\s\"']+(?:/" + terminator + r")?",
        "<redacted-path>",
        text,
    )
    text = re.sub(
        re.escape(MAC_HOME_PREFIX) + r"[^/\s\"']+(?:/" + terminator + r")?",
        "<redacted-path>",
        text,
    )
    text = re.sub(
        r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"']+(?:[\\/]" + terminator + r")?",
        "<redacted-path>",
        text,
        flags=re.I,
    )
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="input file (default: stdin)")
    args = parser.parse_args()
    text = args.input.read_text(encoding="utf-8") if args.input else sys.stdin.read()
    extra_hosts = tuple(
        item.strip()
        for item in os.environ.get("BTX_SANITIZE_EXTRA_HOSTS", "").split(",")
        if item.strip()
    )
    sys.stdout.write(redact_text(text, extra_hosts=extra_hosts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
