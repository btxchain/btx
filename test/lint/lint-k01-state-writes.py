#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Prevent new raw writers in the audited K01 files.

This lexical check catches common stream and literal-mode C writers. It cannot
infer path provenance, so the inventory scopes the files and explains each
existing exception. Check new state-writing components in the next inventory.
"""

from collections import Counter
from pathlib import Path
import re
import subprocess
import sys

# Exact statements, not file-level exemptions. Each occurrence consumes one
# exception, and the lint requires deleting exceptions for removed statements.
EXCEPTIONS = {
    "src/init.cpp": (
        "std::ofstream file{GetPidFile(args)};",  # Process marker, lifecycle scope.
    ),
    "src/modelnet/acc04/acc04.cpp": (
        "std::ofstream file(present);",  # Disposable acceptance fixture.
    ),
    "src/modelnet/capability_bytes.cpp": (
        "std::ofstream gf(gen_path);",  # Sidecar issue remains tracked.
    ),
    "src/modelnet/import_coordinator.cpp": (
        "std::ofstream out(marker);",  # Job-local status markers.
        "std::ofstream out(marker);",
        "std::ofstream out(outp, std::ios::binary);",  # Streamed import with separate close regression.
    ),
    "src/modelnet/obs01/obs01.cpp": (
        'std::ofstream out(PathToString(dir / "lab.json"), std::ios::binary);',  # Deliberate corruption fixture.
    ),
    "src/modelnet/package_channel.cpp": (
        "std::ofstream out(p, std::ios::binary | std::ios::trunc);",  # Current callers are tests.
    ),
    "src/modelnet/realm_channel.cpp": (
        "std::ofstream out(destination, std::ios::binary | std::ios::trunc);",  # Test archive writer.
    ),
    "src/modelnet/store.cpp": (
        "std::ofstream out(tmp, std::ios::binary | std::ios::trunc);",  # Existing staging paths.
        "std::ofstream out(tmp, std::ios::trunc);",
        "std::ofstream out(tmp, std::ios::trunc);",
    ),
    "src/modelnet/swarm_evolution.cpp": (
        "std::ofstream out(to, std::ios::binary | std::ios::trunc);",  # Current callers are tests.
    ),
    "src/modelnet/workspace_git.cpp": (
        "std::ofstream out(dest, std::ios::binary | std::ios::trunc);",  # Current callers are tests.
    ),
    "src/node/attested_utxo_snapshot.cpp": (
        'FILE* coins_file{fsbridge::fopen(coins_tmp, "wb")};',  # Checked scratch serialization, validation scope.
    ),
    "src/node/blockstorage.cpp": (
        'AutoFile xor_key_file{fsbridge::fopen(xor_key_path, "wbx")};',  # Exclusive key creation, node owner.
    ),
    "src/util/readwritefile.cpp": (
        'FILE *f = fsbridge::fopen(filename, "wb");',  # Legacy direct-write API.
        'FILE* file = fsbridge::fopen(tmp, "wbx");',  # Shared atomic writer.
    ),
    "src/wallet/dump.cpp": (
        'FILE* dump_fp = fsbridge::fopen(path, "wbx");',  # Checked exclusive creation.
    ),
    "src/wallet/rpc/labels.cpp": (
        'm_fp = fsbridge::fopen(path, "wbx");',  # Checked exclusive creation.
    ),
    "src/wallet/wallet.cpp": (
        'FilePtr output{fsbridge::fopen(wallet_file, "wbx"), std::fclose};',  # Checked exclusive restore.
    ),
}

RAW_WRITER = re.compile(
    r'\b(?:ofstream|wofstream)\b(?!\s*>)|\bfopen\s*\([^;]*?,\s*"(?:[wa][btx+]*|r[btx]*\+)\s*"'
)


def check(root):
    failures = []
    for name, allowed in EXCEPTIONS.items():
        remaining = Counter(allowed)
        source = (root / name).read_text(encoding="utf-8")
        for match in RAW_WRITER.finditer(source):
            start = source.rfind("\n", 0, match.start()) + 1
            end = source.find("\n", match.end())
            statement = source[start:end if end >= 0 else len(source)].strip()
            if remaining[statement]:
                remaining[statement] -= 1
            else:
                line = source.count("\n", 0, start) + 1
                failures.append(f"{name}:{line}: raw state writer: {statement}")
        for statement in remaining.elements():
            failures.append(f"{name}: remove stale K01 exception: {statement}")
    return failures


if __name__ == "__main__":
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    failures = check(root)
    if failures:
        print("\n".join(failures), file=sys.stderr)
    sys.exit(bool(failures))
