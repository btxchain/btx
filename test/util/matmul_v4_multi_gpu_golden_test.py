#!/usr/bin/env python3
"""Fail-closed tests for the CUDA+Metal production-golden comparator."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/multi-gpu-golden-corpus.sh"


def _head_revision() -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


# Must stay in sync with FINGERPRINT_EXCLUDE in multi-gpu-golden-corpus.sh and
# EXCLUDED_FROM_FINGERPRINT in verify-evidence-provenance.py. This file holds
# the committed golden manifest literal and nothing else; it is excluded so a
# seal can describe the tree it ships in rather than its own parent commit.
EXCLUDED_FROM_FINGERPRINT = (
    b"src/matmul/matmul_v4_rc_production_golden_manifest.cpp",
)


def _head_tree_fingerprint() -> str:
    tree = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "-r", "--full-tree", "HEAD",
         "--", "CMakeLists.txt", "cmake", "src"],
        capture_output=True, check=True,
    ).stdout
    kept = [
        line
        for line in tree.splitlines(keepends=True)
        if not any(
            line.rstrip(b"\n").endswith(b"\t" + excluded)
            for excluded in EXCLUDED_FROM_FINGERPRINT
        )
    ]
    return hashlib.sha256(b"".join(kept)).hexdigest()


# The comparator now resolves the declared revision and cross-checks the
# declared fingerprint against it, so these can no longer be arbitrary hex --
# a synthetic "1"*40 is exactly the fabricated provenance the guard exists to
# reject. Bind the fixtures to this checkout instead, which also means the
# happy-path case exercises the real resolution path rather than bypassing it.
REVISION = _head_revision()
SOURCE_FINGERPRINT = _head_tree_fingerprint()
DIGEST = "2" * 64
HEADER = "3" * (182 * 2)
HARNESS_SHA256 = "6" * 64


def artifact(
    backend: str,
    *,
    digest: str = DIGEST,
    fallbacks: int = 0,
    revision: str = REVISION,
) -> dict:
    architecture = {"cuda": "sm_test", "metal": "m_test", "hip": "gfx_test"}[backend]
    return {
        "backend_requested": backend,
        "source_revision": revision,
        "source_tree_fingerprint": SOURCE_FINGERPRINT,
        "harness_sha256": HARNESS_SHA256,
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
            "resolution_reason": "test_self_qualified",
            "device_backend_present": True,
            "require_device": True,
            "fully_accelerated": True,
            "all_consensus_macs_on_device": True,
            "expected_macs": 10,
            "device_calls": 1,
            "device_macs": 10,
            "cpu_calls": 0,
            "cpu_macs": 0,
            "cpu_fallbacks": fallbacks,
            "first_failure": "",
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
                    "--source-tree-fingerprint",
                    SOURCE_FINGERPRINT,
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

    def test_cuda_artifact_relabeled_as_metal_fails(self) -> None:
        relabeled = artifact("cuda")
        relabeled["backend_requested"] = "metal"
        relabeled["production_provider_identity"]["provider_family"] = "metal"
        relabeled["production_provider_identity"]["device_architecture"] = "m_test"
        result = self.run_compare({"cuda": artifact("cuda"), "metal": relabeled})
        self.assertNotEqual(result.returncode, 0)

    def test_cuda_artifact_relabeled_as_hip_fails(self) -> None:
        relabeled = artifact("cuda")
        relabeled["backend_requested"] = "hip"
        relabeled["production_provider_identity"]["provider_family"] = "hip"
        relabeled["production_provider_identity"]["device_architecture"] = "gfx_test"
        result = self.run_compare(
            {"cuda": artifact("cuda"), "metal": artifact("metal"), "hip": relabeled}
        )
        self.assertNotEqual(result.returncode, 0)

    def test_stale_source_revision_fails(self) -> None:
        result = self.run_compare(
            {
                "cuda": artifact("cuda"),
                "metal": artifact("metal", revision="4" * 40),
            }
        )
        self.assertNotEqual(result.returncode, 0)

    def test_incomplete_provider_metadata_fails(self) -> None:
        malformed = artifact("metal")
        malformed["production_provider_identity"]["runtime_identity"] = ""
        result = self.run_compare({"cuda": artifact("cuda"), "metal": malformed})
        self.assertNotEqual(result.returncode, 0)

    def test_source_tree_fingerprint_mismatch_fails(self) -> None:
        stale = artifact("metal")
        stale["source_tree_fingerprint"] = "7" * 64
        result = self.run_compare({"cuda": artifact("cuda"), "metal": stale})
        self.assertNotEqual(result.returncode, 0)

    def test_missing_harness_binary_identity_fails(self) -> None:
        malformed = artifact("metal")
        malformed["harness_sha256"] = ""
        result = self.run_compare({"cuda": artifact("cuda"), "metal": malformed})
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
