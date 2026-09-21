#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""CLI: map a desktop context JSON file to typed view/draft operations. No HTTP."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from desktop_context import DesktopContextError, apply_desktop_context  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: apply_desktop_context.py CONTEXT.json", file=sys.stderr)
        return 2
    ctx = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    try:
        out = apply_desktop_context(ctx)
    except DesktopContextError as e:
        print(json.dumps({"ok": False, "code": e.code, "error": str(e)}, separators=(",", ":")))
        return 1
    print(json.dumps({"ok": True, **out}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
