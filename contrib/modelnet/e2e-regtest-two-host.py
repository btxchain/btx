#!/usr/bin/env python3
"""Use e2e-regtest-two-host.sh. This file is a wrapper so old commands still fail-fast."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sh = Path(__file__).with_name("e2e-regtest-two-host.sh")
if not sh.is_file():
    sys.exit(f"missing {sh}")
os.execv("/bin/bash", ["bash", str(sh), *sys.argv[1:]])
