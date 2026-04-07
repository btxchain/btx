#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Metal-only MatMul mining consistency check (no divergence/fallback warnings)."""

import json
import os
import platform
import subprocess
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


class BTXMatMulMetalHighHashReproTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-test=matmulstrict"]]

        # Ensure bitcoind inherits metal backend settings before node startup.
        os.environ["BTX_MATMUL_BACKEND"] = "metal"
        os.environ["BTX_MATMUL_DIAG_COMPARE_CPU_METAL"] = "1"

    def skip_test_if_missing_module(self):
        if platform.system() != "Darwin":
            raise SkipTest("Metal repro test requires macOS")

        backend_info_bin = Path(self.config["environment"]["BUILDDIR"]) / "bin" / "btx-matmul-backend-info"
        if not backend_info_bin.exists():
            raise SkipTest(f"missing backend probe binary: {backend_info_bin}")

        try:
            result = subprocess.run(
                [str(backend_info_bin), "--backend", "metal"],
                check=True,
                capture_output=True,
                text=True,
            )
            payload = json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
            raise SkipTest(f"unable to probe metal backend: {exc}") from exc

        capabilities = payload.get("capabilities", {})
        metal_capability = capabilities.get("metal", {})
        if payload.get("active_backend") != "metal" or not metal_capability.get("available", False):
            reason = metal_capability.get("reason", "unavailable")
            raise SkipTest(f"metal backend unavailable: {reason}")

    def run_test(self):
        node = self.nodes[0]
        block_attempts = 6
        # Header layout prefix before MatMul digest:
        # version (4) + prev_hash (32) + merkle_root (32) + time (4) + bits (4) + nonce (8)
        digest_start = (4 + 32 + 32 + 4 + 4 + 8) * 2
        digest_end = digest_start + 64

        with node.assert_debug_log(
            expected_msgs=[],
            unexpected_msgs=[
                "MATMUL WARNING: cpu/metal digest divergence",
                "MATMUL WARNING: METAL backend fallback to CPU",
                "MATMUL WARNING: METAL-GPU-INPUTS backend fallback to CPU",
            ],
            timeout=30,
        ):
            for _ in range(block_attempts):
                candidate = node.generateblock("raw(51)", [], False, called_by_framework=True)
                tampered_hex = (
                    candidate["hex"][:digest_start]
                    + ("f" * 64)
                    + candidate["hex"][digest_end:]
                )
                submit_result = node.submitblock(tampered_hex)
                assert_equal(submit_result, "high-hash")


if __name__ == "__main__":
    BTXMatMulMetalHighHashReproTest(__file__).main()
