#!/usr/bin/env python3
"""Fail-closed tests for the CUDA+Metal production-golden comparator."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "contrib/matmul-v4/multi-gpu-golden-corpus.sh"
SEAL_SCRIPT = REPO_ROOT / "contrib/matmul-v4/verify-production-golden-seal.py"
BUILD_INFO_SCRIPT = REPO_ROOT / "cmake/script/GenerateBuildInfo.cmake"


def _head_revision() -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


# Must stay in sync with FINGERPRINT_EXCLUDE in multi-gpu-golden-corpus.sh and
# EXCLUDED_FROM_FINGERPRINT in verify-evidence-provenance.py. Only inert data is
# excluded; all CMake conversion and C++ parsing logic remains fingerprinted.
EXCLUDED_FROM_FINGERPRINT = (
    b"src/matmul/matmul_v4_rc_production_golden_manifest.data",
)


def _head_tree_fingerprint() -> str:
    tree = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "-r", "--full-tree", "HEAD",
         "--", "CMakeLists.txt", "cmake", "src", "contrib/matmul-v4"],
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
HARNESS_SHA256 = "6" * 64
PER_EPISODE_MACS = 141_149_805_215_744
PRODUCTION_PARAMS = {
    "rounds": 4,
    "d_head": 128,
    "n_q": 512,
    "n_ctx": 786432,
    "L_lyr": 16,
    "d_model": 4096,
    "d_ff": 16384,
    "b_seq": 16384,
    "T_leaf": 1024,
}


def canonical_header(nonce: int) -> str:
    return b"".join((
        struct.pack("<I", 536870916),
        bytes.fromhex("91" * 32),
        bytes.fromhex("2d" * 32),
        struct.pack("<I", 1780000000),
        struct.pack("<I", 545259519),
        struct.pack("<Q", nonce),
        bytes(32),
        struct.pack("<H", 4096),
        bytes.fromhex("46" * 32),
        bytes.fromhex("b8" * 32),
    )).hex()


def artifact(
    backend: str,
    *,
    digest: str = DIGEST,
    fallbacks: int = 0,
    revision: str = REVISION,
    fingerprint: str = SOURCE_FINGERPRINT,
    episodes: int = 1,
) -> dict:
    architecture = {"cuda": "sm_120", "metal": "m4_class", "hip": "gfx1200"}[backend]
    provider = f"{backend}_test"
    return {
        "tool": "rc-episode-harness",
        "schema_version": 2,
        "stub": False,
        "device_id": f"{provider}:public-evidence",
        "public_evidence": True,
        "backend": provider,
        "backend_requested": backend,
        "backend_resolution_reason": "test_self_qualified",
        "profile": "episode",
        "toy": False,
        "medium": False,
        "production_dims": True,
        "rounds_override": 0,
        "episode_profile": 1,
        "header_matmul_dim": 4096,
        "header_family": "production_canary",
        "evidence_kind": "production_chrono_measured",
        "wall_clock_provenance": "chrono_steady_clock",
        "source_revision": revision,
        "git_tip": revision,
        "embedded_source_revision": revision,
        "embedded_source_dirty": False,
        "source_tree_fingerprint": fingerprint,
        "harness_sha256": HARNESS_SHA256,
        "all_consensus_macs_on_device": True,
        "params": dict(PRODUCTION_PARAMS),
        "production_provider_identity": {
            "provider_family": backend,
            "device_architecture": architecture,
            "driver_identity": "driver",
            "runtime_identity": "runtime",
            "complete": True,
            "reason": "complete",
        },
        "exact_replay_acceleration": {
            "provider": provider,
            "resolution_reason": "test_self_qualified",
            "device_backend_present": True,
            "require_device": True,
            "fully_accelerated": True,
            "all_consensus_macs_on_device": True,
            "expected_macs": PER_EPISODE_MACS * episodes,
            "device_calls": 1,
            "device_macs": PER_EPISODE_MACS * episodes,
            "cpu_calls": 0,
            "cpu_macs": 0,
            "cpu_fallbacks": fallbacks,
            "first_failure": "",
        },
        "episode_digests": [digest if episodes == 1 else f"{nonce:064x}" for nonce in range(1, episodes + 1)],
        "frozen_headers": [
            {
                "index": nonce - 1,
                "header_family": "production_canary",
                "header_nonce": nonce,
                "nVersion": 536870916,
                "nTime": 1780000000,
                "nBits": 545259519,
                "nNonce": nonce,
                "nNonce64": nonce,
                "matmul_dim": 4096,
                "hashPrevBlock": "91" * 32,
                "hashMerkleRoot": "2d" * 32,
                "matmul_digest": "00" * 32,
                "seed_a": "46" * 32,
                "seed_b": "b8" * 32,
                "header_wire_bytes": 182,
                "header_hex": canonical_header(nonce),
                "exact_replay_digest": digest if episodes == 1 else f"{nonce:064x}",
                "fully_accelerated": True,
                "require_device": True,
                "device_macs": PER_EPISODE_MACS,
                "cpu_calls": 0,
                "cpu_macs": 0,
                "cpu_fallbacks": fallbacks,
                "first_failure": "",
            }
            for nonce in range(1, episodes + 1)
        ],
    }


class MultiGpuGoldenComparatorTest(unittest.TestCase):
    def run_compare(
        self,
        artifacts: dict[str, dict],
        *,
        allow_partial: bool = False,
        episodes: int = 1,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            for backend, payload in artifacts.items():
                (raw / f"profile1-{backend}-{episodes}.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )
            command = [
                str(SCRIPT),
                "--compare-only",
                "--episodes",
                str(episodes),
                "--source-revision",
                REVISION,
                "--source-tree-fingerprint",
                SOURCE_FINGERPRINT,
                "--out-dir",
                str(root),
            ]
            if allow_partial:
                command.append("--allow-partial")
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_cuda_metal_complete_cohort_passes(self) -> None:
        result = self.run_compare({"cuda": artifact("cuda"), "metal": artifact("metal")})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cuda_only_cohort_passes(self) -> None:
        result = self.run_compare({"cuda": artifact("cuda")})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_metal_only_cohort_passes(self) -> None:
        result = self.run_compare({"metal": artifact("metal")})
        self.assertEqual(result.returncode, 0, result.stderr)

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

    def test_stale_embedded_binary_revision_fails(self) -> None:
        relabeled = artifact("metal")
        # The operator-facing revision is current, but the immutable metadata
        # proves this is an older binary. Relabeling must fail closed.
        relabeled["embedded_source_revision"] = "4" * 40
        result = self.run_compare({"cuda": artifact("cuda"), "metal": relabeled})
        self.assertNotEqual(result.returncode, 0)

    def test_dirty_embedded_binary_fails(self) -> None:
        dirty = artifact("metal")
        dirty["embedded_source_dirty"] = True
        result = self.run_compare({"cuda": artifact("cuda"), "metal": dirty})
        self.assertNotEqual(result.returncode, 0)

    def test_allow_partial_does_not_admit_dirty_binary(self) -> None:
        dirty = artifact("metal")
        dirty["embedded_source_dirty"] = True
        result = self.run_compare({"metal": dirty}, allow_partial=True)
        self.assertNotEqual(result.returncode, 0)

    def test_allow_partial_admits_one_clean_backend(self) -> None:
        result = self.run_compare({"metal": artifact("metal")}, allow_partial=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_embedded_binary_metadata_fails(self) -> None:
        unlabeled = artifact("metal")
        unlabeled.pop("embedded_source_revision")
        unlabeled.pop("embedded_source_dirty")
        result = self.run_compare({"cuda": artifact("cuda"), "metal": unlabeled})
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

    def test_toy_or_nonproduction_artifact_fails(self) -> None:
        toy = artifact("metal")
        toy["toy"] = True
        toy["production_dims"] = False
        result = self.run_compare({"cuda": artifact("cuda"), "metal": toy})
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_profile_fails(self) -> None:
        wrong = artifact("metal")
        wrong["episode_profile"] = 2
        result = self.run_compare({"cuda": artifact("cuda"), "metal": wrong})
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_header_dimension_fails(self) -> None:
        wrong = artifact("metal")
        wrong["header_matmul_dim"] = 2048
        wrong["frozen_headers"][0]["matmul_dim"] = 2048
        result = self.run_compare({"cuda": artifact("cuda"), "metal": wrong})
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_production_d_ff_fails(self) -> None:
        wrong = artifact("metal")
        wrong["params"]["d_ff"] = 8192
        result = self.run_compare({"cuda": artifact("cuda"), "metal": wrong})
        self.assertNotEqual(result.returncode, 0)

    def test_reencoded_fake_header_fails(self) -> None:
        fake = artifact("metal")
        fake["frozen_headers"][0]["header_hex"] = "00" + canonical_header(1)[2:]
        result = self.run_compare({"cuda": artifact("cuda"), "metal": fake})
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_per_episode_mac_count_fails(self) -> None:
        wrong = artifact("metal")
        wrong["frozen_headers"][0]["device_macs"] -= 1
        result = self.run_compare({"cuda": artifact("cuda"), "metal": wrong})
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_total_mac_count_fails(self) -> None:
        wrong = artifact("metal")
        wrong["exact_replay_acceleration"]["expected_macs"] -= 1
        wrong["exact_replay_acceleration"]["device_macs"] -= 1
        result = self.run_compare({"cuda": artifact("cuda"), "metal": wrong})
        self.assertNotEqual(result.returncode, 0)

    def test_per_record_strict_device_is_required(self) -> None:
        wrong = artifact("metal")
        wrong["frozen_headers"][0]["require_device"] = False
        result = self.run_compare({"cuda": artifact("cuda"), "metal": wrong})
        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_nonce_and_header_fails(self) -> None:
        duplicate = artifact("metal", episodes=2)
        duplicate["frozen_headers"][1] = dict(duplicate["frozen_headers"][0])
        duplicate["frozen_headers"][1]["index"] = 1
        result = self.run_compare(
            {"cuda": artifact("cuda", episodes=2), "metal": duplicate},
            episodes=2,
        )
        self.assertNotEqual(result.returncode, 0)


class ProductionGoldenSealTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "cmake").mkdir()
        manifest = self.root / "src/matmul/matmul_v4_rc_production_golden_manifest.data"
        manifest.parent.mkdir(parents=True)
        (self.root / "CMakeLists.txt").write_text("project(seal-test)\n")
        (self.root / "cmake/config.cmake").write_text("set(TEST 1)\n")
        (self.root / "src/value.cpp").write_text("int value = 1;\n")
        manifest.write_text("BTX_RC_PRODUCTION_GOLDEN_V1\npending\n")
        self.git("init", "-q")
        self.git("config", "user.name", "Golden Seal Test")
        self.git("config", "user.email", "golden-seal-test.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "freeze")
        self.freeze = self.git("rev-parse", "HEAD").stdout.strip()
        self.fingerprint = self.tree_fingerprint(self.freeze)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            capture_output=True,
            text=True,
            check=True,
        )

    def tree_fingerprint(self, revision: str) -> str:
        tree = subprocess.run(
            [
                "git", "-C", str(self.root), "ls-tree", "-r", "--full-tree",
                revision, "--", "CMakeLists.txt", "cmake", "src",
                "contrib/matmul-v4",
            ],
            capture_output=True,
            check=True,
        ).stdout
        kept = [
            line
            for line in tree.splitlines(keepends=True)
            if not line.rstrip(b"\n").endswith(
                b"\tsrc/matmul/matmul_v4_rc_production_golden_manifest.data"
            )
        ]
        return hashlib.sha256(b"".join(kept)).hexdigest()

    def build_seal(
        self,
        mutate=None,
        source_change: bool = False,
        non_documentation_change: bool = False,
    ) -> None:
        corpus = self.root / "doc/evidence/final-corpus"
        raw = corpus / "raw"
        raw.mkdir(parents=True)
        cuda = artifact(
            "cuda", revision=self.freeze, fingerprint=self.fingerprint, episodes=8
        )
        metal = artifact(
            "metal", revision=self.freeze, fingerprint=self.fingerprint, episodes=8
        )
        cuda_path = raw / "profile1-cuda-8.json"
        metal_path = raw / "profile1-metal-8.json"
        cuda_path.write_text(json.dumps(cuda))
        metal_path.write_text(json.dumps(metal))
        compare_path = corpus / "multi-gpu-digest-compare.json"
        compare = subprocess.run(
            [
                "python3", str(SEAL_SCRIPT), "compare",
                "--out", str(compare_path),
                "--revision", self.freeze,
                "--fingerprint", self.fingerprint,
                "--nonce-start", "1",
                "--episodes", "8",
                "--artifact", f"cuda={cuda_path}",
                "--artifact", f"metal={metal_path}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(compare.returncode, 0, compare.stdout + compare.stderr)

        manifest = self.root / "src/matmul/matmul_v4_rc_production_golden_manifest.data"
        manifest.write_text(
            "BTX_RC_PRODUCTION_GOLDEN_V1\n"
            "epoch-a-profile1-cuda-sm120-nonce1|cuda|sm_120|1|"
            f"{'1':0>64}|1|doc/evidence/final-corpus|{self.freeze}|"
            f"{self.fingerprint}|{HARNESS_SHA256}\n"
            "epoch-a-profile1-metal-m4-nonce1|metal|m4_class|1|"
            f"{'1':0>64}|1|doc/evidence/final-corpus|{self.freeze}|"
            f"{self.fingerprint}|{HARNESS_SHA256}\n"
        )
        if mutate is not None:
            mutate(corpus, cuda_path, metal_path, compare_path, manifest)
        if source_change:
            (self.root / "src/value.cpp").write_text("int value = 2;\n")
        if non_documentation_change:
            path = self.root / "scripts/operator.py"
            path.parent.mkdir()
            path.write_text("print('changed after freeze')\n")
        self.git("add", ".")
        self.git("commit", "-qm", "seal")

    def run_seal(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SEAL_SCRIPT), "seal", "--root", str(self.root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_exact_freeze_to_seal_passes(self) -> None:
        self.build_seal()
        result = self.run_seal()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_raw_artifact_tamper_after_comparison_fails(self) -> None:
        def mutate(corpus, cuda_path, metal_path, compare_path, manifest):
            payload = json.loads(metal_path.read_text())
            payload["unreviewed_post_compare_field"] = True
            metal_path.write_text(json.dumps(payload))

        self.build_seal(mutate)
        result = self.run_seal()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("raw artifact changed", result.stderr)

    def test_incomplete_comparison_fails(self) -> None:
        def mutate(corpus, cuda_path, metal_path, compare_path, manifest):
            payload = json.loads(compare_path.read_text())
            payload["complete_multi_gpu_match"] = False
            compare_path.write_text(json.dumps(payload))

        self.build_seal(mutate)
        result = self.run_seal()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("complete_multi_gpu_match", result.stderr)

    def test_manifest_stale_revision_fails(self) -> None:
        def mutate(corpus, cuda_path, metal_path, compare_path, manifest):
            manifest.write_text(manifest.read_text().replace(self.freeze, "a" * 40))

        self.build_seal(mutate)
        result = self.run_seal()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not resolve", result.stderr)

    def test_missing_raw_artifact_fails(self) -> None:
        self.build_seal()
        (self.root / "doc/evidence/final-corpus/raw/profile1-metal-8.json").unlink()
        result = self.run_seal()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from HEAD", result.stderr)

    def test_executable_change_after_freeze_fails(self) -> None:
        self.build_seal(source_change=True)
        result = self.run_seal()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("build-relevant code changed", result.stderr)

    def test_non_documentation_change_after_freeze_fails(self) -> None:
        self.build_seal(non_documentation_change=True)
        result = self.run_seal()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest and documentation only", result.stderr)

    def test_symbolic_link_raw_artifact_fails(self) -> None:
        def mutate(corpus, cuda_path, metal_path, compare_path, manifest):
            target = metal_path.with_name("profile1-metal-target.json")
            target.write_bytes(metal_path.read_bytes())
            metal_path.unlink()
            metal_path.symlink_to(target.name)

        self.build_seal(mutate)
        result = self.run_seal()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic links are not allowed", result.stderr)


class BuildInfoGenerationTest(unittest.TestCase):
    def test_full_revision_and_dirty_state_are_embedded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            script_path = source / "cmake/script/GenerateBuildInfo.cmake"
            script_path.parent.mkdir(parents=True)
            shutil.copy2(BUILD_INFO_SCRIPT, script_path)
            marker = source / "src/marker.cpp"
            marker.parent.mkdir()
            marker.write_text("clean\n", encoding="utf-8")

            def run(*args: str) -> str:
                return subprocess.run(
                    list(args), cwd=source, capture_output=True, text=True, check=True
                ).stdout.strip()

            run("git", "init", "-q")
            run("git", "config", "user.name", "Build Info Test")
            run("git", "config", "user.email", "build-info-test.invalid")
            run("git", "add", ".")
            run("git", "commit", "-qm", "fixture")
            revision = run("git", "rev-parse", "HEAD")
            header = Path(directory) / "bitcoin-build-info.h"

            subprocess.run(
                [
                    "cmake",
                    "-D",
                    f"BUILD_INFO_HEADER_PATH={header}",
                    "-D",
                    f"SOURCE_DIR={source}",
                    "-P",
                    str(BUILD_INFO_SCRIPT),
                ],
                check=True,
            )
            clean_info = header.read_text(encoding="utf-8")
            self.assertIn(f'#define BUILD_GIT_FULL_COMMIT "{revision}"', clean_info)
            self.assertIn("#define BUILD_GIT_DIRTY 0", clean_info)

            marker.write_text("dirty\n", encoding="utf-8")
            subprocess.run(
                [
                    "cmake",
                    "-D",
                    f"BUILD_INFO_HEADER_PATH={header}",
                    "-D",
                    f"SOURCE_DIR={source}",
                    "-P",
                    str(BUILD_INFO_SCRIPT),
                ],
                check=True,
            )
            dirty_info = header.read_text(encoding="utf-8")
            self.assertIn(f'#define BUILD_GIT_FULL_COMMIT "{revision}"', dirty_info)
            self.assertIn("#define BUILD_GIT_DIRTY 1", dirty_info)

            marker.write_text("clean\n", encoding="utf-8")
            run("git", "checkout", "--", "src/marker.cpp")
            (source / "src/untracked.cpp").write_text("untracked\n", encoding="utf-8")
            subprocess.run(
                [
                    "cmake",
                    "-D",
                    f"BUILD_INFO_HEADER_PATH={header}",
                    "-D",
                    f"SOURCE_DIR={source}",
                    "-P",
                    str(BUILD_INFO_SCRIPT),
                ],
                check=True,
            )
            untracked_info = header.read_text(encoding="utf-8")
            self.assertIn("#define BUILD_GIT_DIRTY 1", untracked_info)

    def test_only_inert_manifest_data_is_excluded_from_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            script_path = source / "cmake/script/GenerateBuildInfo.cmake"
            script_path.parent.mkdir(parents=True)
            shutil.copy2(BUILD_INFO_SCRIPT, script_path)
            (source / "CMakeLists.txt").write_text("# fixture\n", encoding="utf-8")
            manifest_cpp = source / "src/matmul/matmul_v4_rc_production_golden_manifest.cpp"
            manifest_cpp.parent.mkdir(parents=True)
            manifest_cpp.write_text("int fingerprinted_logic = 1;\n", encoding="utf-8")
            manifest_data = source / "src/matmul/matmul_v4_rc_production_golden_manifest.data"
            manifest_data.write_text("seal-one\n", encoding="utf-8")

            def run(*args: str) -> str:
                return subprocess.run(
                    list(args), cwd=source, capture_output=True, text=True, check=True
                ).stdout.strip()

            def fingerprint() -> str:
                header = Path(directory) / "bitcoin-build-info.h"
                subprocess.run(
                    [
                        "cmake", "-D", f"BUILD_INFO_HEADER_PATH={header}",
                        "-D", f"SOURCE_DIR={source}", "-P", str(BUILD_INFO_SCRIPT),
                    ],
                    check=True,
                )
                match = re.search(
                    r'BUILD_GIT_SOURCE_TREE_FINGERPRINT "([0-9a-f]{64})"',
                    header.read_text(encoding="utf-8"),
                )
                self.assertIsNotNone(match)
                return match.group(1)

            run("git", "init", "-q")
            run("git", "config", "user.name", "Build Info Test")
            run("git", "config", "user.email", "build-info-test.invalid")
            run("git", "add", ".")
            run("git", "commit", "-qm", "fixture")
            first = fingerprint()

            manifest_data.write_text("seal-two\n", encoding="utf-8")
            run("git", "add", str(manifest_data.relative_to(source)))
            run("git", "commit", "-qm", "change inert seal")
            self.assertEqual(fingerprint(), first)

            manifest_cpp.write_text("int fingerprinted_logic = 2;\n", encoding="utf-8")
            run("git", "add", str(manifest_cpp.relative_to(source)))
            run("git", "commit", "-qm", "change executable logic")
            self.assertNotEqual(fingerprint(), first)


if __name__ == "__main__":
    unittest.main()
