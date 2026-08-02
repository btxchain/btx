#!/usr/bin/env python3
"""Fail-closed tests for the CUDA+Metal production-golden comparator."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/multi-gpu-golden-corpus.sh"
REVISION = "1" * 40
DIGEST = "2" * 64
HEADER = "3" * (182 * 2)


def artifact(backend: str, *, digest: str = DIGEST, fallbacks: int = 0) -> dict:
    architecture = {"cuda": "sm_test", "metal": "m_test", "hip": "gfx_test"}[backend]
    return {
        "backend_requested": backend,
        "source_revision": REVISION,
        "all_consensus_macs_on_device": True,
        "production_provider_identity": {
            "provider_family": backend,
            "device_architecture": architecture,
            "driver_identity": "driver",
            "runtime_identity": "runtime",
            "complete": True,
            "reason": "complete",
        },
        "exact_replay_acceleration": {
            "provider": f"{backend}_test",
            "cpu_fallbacks": fallbacks,
        },
        "frozen_headers": [
            {
                "header_nonce": 1,
                "matmul_dim": 4096,
                "header_hex": HEADER,
                "exact_replay_digest": digest,
                "cpu_fallbacks": fallbacks,
            }
        ],
    }


class MultiGpuGoldenComparatorTest(unittest.TestCase):
    def run_compare(self, artifacts: dict[str, dict]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            for backend, payload in artifacts.items():
                (raw / f"profile1-{backend}-1.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )
            return subprocess.run(
                [
                    str(SCRIPT),
                    "--compare-only",
                    "--episodes",
                    "1",
                    "--source-revision",
                    REVISION,
                    "--out-dir",
                    str(root),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_cuda_metal_complete_cohort_passes(self) -> None:
        result = self.run_compare({"cuda": artifact("cuda"), "metal": artifact("metal")})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_metal_fails(self) -> None:
        result = self.run_compare({"cuda": artifact("cuda")})
        self.assertNotEqual(result.returncode, 0)

    def test_optional_divergent_hip_fails(self) -> None:
        result = self.run_compare(
            {
                "cuda": artifact("cuda"),
                "metal": artifact("metal"),
                "hip": artifact("hip", digest="4" * 64),
            }
        )
        self.assertNotEqual(result.returncode, 0)

    def test_cpu_fallback_fails(self) -> None:
        result = self.run_compare(
            {"cuda": artifact("cuda", fallbacks=1), "metal": artifact("metal")}
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
