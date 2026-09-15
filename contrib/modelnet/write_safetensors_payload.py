#!/usr/bin/env python3
"""Write a valid SafeTensors payload of exactly N tensor bytes (U8)."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path


def write_u8(path: Path, n: int) -> None:
    header = json.dumps(
        {"t": {"dtype": "U8", "shape": [n], "data_offsets": [0, n]}},
        separators=(",", ":"),
    ).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", len(header)) + header + bytes(n))


if __name__ == "__main__":
    write_u8(Path(sys.argv[1]), int(sys.argv[2]))
