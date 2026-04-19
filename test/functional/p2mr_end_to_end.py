#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Compatibility entrypoint for the canonical plan filename.

The implementation lives in feature_p2mr_end_to_end.py.
"""

from feature_p2mr_end_to_end import P2MREndToEndTest


if __name__ == "__main__":
    P2MREndToEndTest(__file__).main()

