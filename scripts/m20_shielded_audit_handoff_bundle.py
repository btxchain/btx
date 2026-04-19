#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Build a reproducible BTX shielded cryptographic audit handoff bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]

SOURCE_FILES = [
    "doc/btx-shielded-cryptographic-audit-handoff.md",
    "doc/btx-shielded-external-redteam-window.md",
    "doc/btx-shielded-external-review-closeout.md",
    "doc/btx-production-readiness-matrix.md",
    "doc/btx-shielded-v2-overhaul-tracker-2026-03-14.md",
    "infra/btx-seed-server-spec.md",
    "src/test/generate_shielded_matrict_plus_transcript_corpus.cpp",
    "src/test/generate_shielded_v2_adversarial_proof_corpus.cpp",
    "src/test/shielded_matrict_plus_tests.cpp",
    "src/test/shielded_proof_adversarial_tests.cpp",
    "src/test/shielded_v2_adversarial_proof_corpus.h",
    "src/test/shielded_v2_adversarial_proof_corpus.cpp",
    "src/test/shielded_v2_adversarial_proof_corpus_tests.cpp",
    "test/reference/check_shielded_matrict_plus_transcripts.py",
    "test/functional/feature_shielded_v2_proof_redteam_campaign.py",
    "test/functional/test_runner.py",
    "test/reference/shielded_test_vectors.json",
    "scripts/m20_shielded_audit_handoff_bundle.py",
    "scripts/m21_shielded_redteam_campaign.sh",
    "scripts/m22_remote_shielded_redteam_campaign.py",
    "scripts/m23_shielded_external_redteam_packet.py",
    "scripts/m24_shielded_external_findings_intake.py",
    "scripts/m25_shielded_external_closeout_check.py",
    "scripts/m26_remote_shielded_validation_suite.py",
    "test/util/m20_shielded_audit_handoff_bundle_test.sh",
    "test/util/m22_remote_shielded_redteam_campaign_test.sh",
    "test/util/m23_shielded_external_redteam_packet_test.sh",
    "test/util/m24_shielded_external_findings_intake_test.sh",
    "test/util/m25_shielded_external_closeout_check_test.sh",
    "test/util/m26_remote_shielded_validation_suite_test.sh",
]


def manifest_path_prefixes(path: Path) -> list[str]:
    prefixes: list[str] = []
    for candidate in (path, path.resolve()):
        text = str(candidate)
        if text not in prefixes:
            prefixes.append(text)
    return prefixes


def manifest_display_path(output_dir: Path, value: str) -> str:
    temp_dir = Path(tempfile.gettempdir())
    for root, label in (
        (output_dir, ""),
        (REPO_ROOT, "<repo>"),
        (REPO_ROOT.parent, "<workspace>"),
        (Path.home(), "~"),
        (temp_dir, "<tmp>"),
        (Path("/private/tmp"), "<tmp>"),
        (Path("/tmp"), "<tmp>"),
    ):
        for root_str in manifest_path_prefixes(root):
            if value == root_str:
                return label or "."
            prefix = root_str + os.sep
            if value.startswith(prefix):
                suffix = value[len(prefix):]
                if not label:
                    return suffix
                return f"{label}/{suffix}"
    return value


def sanitize_manifest_value(output_dir: Path, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_manifest_value(output_dir, item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_manifest_value(output_dir, item) for item in value]
    if isinstance(value, str):
        return manifest_display_path(output_dir, value)
    return value


def write_manifest(output_dir: Path, manifest_path: Path, manifest: dict[str, Any]) -> None:
    sanitized = sanitize_manifest_value(output_dir, manifest)
    manifest_path.write_text(json.dumps(sanitized, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_command(cmd: list[str], *, cwd: Path, log_path: Path) -> dict[str, object]:
    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log_path.write_text(proc.stdout, encoding="utf-8")
    return {
        "command": cmd,
        "cwd": str(cwd),
        "log": str(log_path),
        "exit_code": proc.returncode,
        "duration_seconds": round(time.time() - started, 3),
    }


def resolve_source_path(rel: str) -> Path:
    rel_path = Path(rel)
    candidates = [REPO_ROOT / rel_path]
    if rel_path.parts and rel_path.parts[0] == "..":
        if len(rel_path.parts) < 2 or rel_path.parts[1] != "infra":
            raise ValueError(f"unsupported source path outside repo root: {rel}")
        candidates.append(REPO_ROOT.parent / "infra" / Path(*rel_path.parts[2:]))
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise FileNotFoundError(f"required handoff source missing: {candidates[0]}")


def output_relative_path_for_source(rel: str) -> Path:
    rel_path = Path(rel)
    if not rel_path.parts:
        raise ValueError("empty source path")
    if rel_path.parts[0] == "..":
        if len(rel_path.parts) < 2 or rel_path.parts[1] != "infra":
            raise ValueError(f"unsupported source path outside repo root: {rel}")
        return Path("infra").joinpath(*rel_path.parts[2:])
    return rel_path


def copy_sources(output_dir: Path) -> list[dict[str, str]]:
    copied: list[dict[str, str]] = []
    for rel in SOURCE_FILES:
        src = resolve_source_path(rel)
        dst = output_dir / "source_snapshot" / output_relative_path_for_source(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(
            {
                "path": rel,
                "copied_to": str(dst),
                "sha256": sha256_file(dst),
            }
        )
    return copied


def write_checksums(paths: Iterable[Path], output_path: Path) -> None:
    lines = [f"{sha256_file(path)}  {path.name}" for path in sorted(paths)]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def tar_output_dir(output_dir: Path) -> Path:
    tarball = output_dir.parent / f"{output_dir.name}.tar.gz"
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(output_dir, arcname=output_dir.name)
    return tarball


def resolve_binary(build_dir: Path, name: str) -> Path:
    exeext = ".exe" if sys.platform.startswith("win") else ""
    return build_dir / "bin" / f"{name}{exeext}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a reproducible BTX shielded audit handoff bundle."
    )
    parser.add_argument("--build-dir", required=True, help="BTX build directory")
    parser.add_argument("--output-dir", required=True, help="Output bundle directory")
    parser.add_argument(
        "--samples",
        type=int,
        default=2,
        help="Randomized transcript corpus sample count (default: 2)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip the CMake build step and use existing binaries",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    build_dir = Path(args.build_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    artifacts_dir = output_dir / "artifacts"
    logs_dir = output_dir / "logs"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, object] = {
        "format_version": 1,
        "generated_at_unix": int(time.time()),
        "repo_root": str(REPO_ROOT),
        "build_dir": str(build_dir),
        "output_dir": str(output_dir),
        "overall_status": "pass",
        "sample_count": args.samples,
        "git": {},
        "commands": [],
        "source_files": [],
        "artifacts": {},
    }

    def record_git(field: str, cmd: list[str]) -> None:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), text=True, stdout=subprocess.PIPE, check=True)
        manifest["git"][field] = proc.stdout.strip()

    try:
        record_git("commit", ["git", "rev-parse", "HEAD"])
        record_git("branch", ["git", "rev-parse", "--abbrev-ref", "HEAD"])
        record_git("status", ["git", "status", "--short"])

        test_btx = resolve_binary(build_dir, "test_btx")
        corpus_gen = resolve_binary(build_dir, "gen_shielded_matrict_plus_transcript_corpus")
        checker = REPO_ROOT / "test/reference/check_shielded_matrict_plus_transcripts.py"
        redteam_wrapper = REPO_ROOT / "scripts/m21_shielded_redteam_campaign.sh"

        if not args.skip_build:
            build_result = run_command(
                [
                    "cmake",
                    "--build",
                    str(build_dir),
                    "--target",
                    "test_btx",
                    "generate_shielded_matrict_plus_transcript_corpus",
                    "-j8",
                ],
                cwd=REPO_ROOT,
                log_path=logs_dir / "build.log",
            )
            manifest["commands"].append(build_result)
            if build_result["exit_code"] != 0:
                raise RuntimeError("build step failed")

        corpus_path = artifacts_dir / "matrict_plus_transcript_corpus.json"
        test_result = run_command(
            [
                str(test_btx),
                "--run_test=shielded_matrict_plus_tests,shielded_proof_adversarial_tests",
                "--catch_system_error=no",
                "--log_level=test_suite",
            ],
            cwd=REPO_ROOT,
            log_path=logs_dir / "proof_suites.log",
        )
        manifest["commands"].append(test_result)
        if test_result["exit_code"] != 0:
            raise RuntimeError("targeted proof suites failed")

        corpus_result = run_command(
            [
                str(corpus_gen),
                f"--samples={args.samples}",
                f"--output={corpus_path}",
            ],
            cwd=REPO_ROOT,
            log_path=logs_dir / "transcript_corpus_generation.log",
        )
        manifest["commands"].append(corpus_result)
        if corpus_result["exit_code"] != 0:
            raise RuntimeError("transcript corpus generation failed")

        checker_result = run_command(
            [sys.executable, str(checker), str(corpus_path)],
            cwd=REPO_ROOT,
            log_path=logs_dir / "transcript_checker.log",
        )
        manifest["commands"].append(checker_result)
        if checker_result["exit_code"] != 0:
            raise RuntimeError("transcript checker failed")

        redteam_artifact_path = artifacts_dir / "shielded_v2_proof_redteam_campaign.json"
        redteam_log_dir = logs_dir / "redteam_campaign"
        redteam_cmd = [
            "bash",
            str(redteam_wrapper),
            "--build-dir",
            str(build_dir),
            "--artifact",
            str(redteam_artifact_path),
            "--log-dir",
            str(redteam_log_dir),
            "--portseed",
            "35100",
        ]
        if args.skip_build:
            redteam_cmd.append("--skip-build")
        redteam_result = run_command(
            redteam_cmd,
            cwd=REPO_ROOT,
            log_path=logs_dir / "redteam_wrapper.log",
        )
        manifest["commands"].append(redteam_result)
        if redteam_result["exit_code"] != 0:
            raise RuntimeError("red-team campaign wrapper failed")

        redteam_inner_artifact = redteam_log_dir / "feature_shielded_v2_proof_redteam_campaign.artifact.json"
        redteam_corpus = redteam_log_dir / "feature_shielded_v2_proof_redteam_campaign.corpus.json"
        redteam_build_log = redteam_log_dir / "build.log"
        redteam_functional_log = redteam_log_dir / "feature_shielded_v2_proof_redteam_campaign.log"

        manifest["source_files"] = copy_sources(output_dir)
        manifest["artifacts"] = {
            "transcript_corpus": {
                "path": str(corpus_path),
                "sha256": sha256_file(corpus_path),
            },
            "proof_suites_log": {
                "path": str(logs_dir / "proof_suites.log"),
                "sha256": sha256_file(logs_dir / "proof_suites.log"),
            },
            "transcript_generation_log": {
                "path": str(logs_dir / "transcript_corpus_generation.log"),
                "sha256": sha256_file(logs_dir / "transcript_corpus_generation.log"),
            },
            "transcript_checker_log": {
                "path": str(logs_dir / "transcript_checker.log"),
                "sha256": sha256_file(logs_dir / "transcript_checker.log"),
            },
            "redteam_wrapper_log": {
                "path": str(logs_dir / "redteam_wrapper.log"),
                "sha256": sha256_file(logs_dir / "redteam_wrapper.log"),
            },
            "redteam_campaign_artifact": {
                "path": str(redteam_artifact_path),
                "sha256": sha256_file(redteam_artifact_path),
            },
            "redteam_campaign_inner_artifact": {
                "path": str(redteam_inner_artifact),
                "sha256": sha256_file(redteam_inner_artifact),
            },
            "redteam_campaign_corpus": {
                "path": str(redteam_corpus),
                "sha256": sha256_file(redteam_corpus),
            },
            "redteam_campaign_build_log": {
                "path": str(redteam_build_log),
                "sha256": sha256_file(redteam_build_log),
            },
            "redteam_campaign_functional_log": {
                "path": str(redteam_functional_log),
                "sha256": sha256_file(redteam_functional_log),
            },
        }

        manifest_path = output_dir / "manifest.json"
        write_manifest(output_dir, manifest_path, manifest)

        artifact_paths = [
            corpus_path,
            logs_dir / "proof_suites.log",
            logs_dir / "transcript_corpus_generation.log",
            logs_dir / "transcript_checker.log",
            logs_dir / "redteam_wrapper.log",
            redteam_artifact_path,
            redteam_inner_artifact,
            redteam_corpus,
            redteam_build_log,
            redteam_functional_log,
            manifest_path,
        ]
        checksum_path = output_dir / "SHA256SUMS"
        write_checksums(artifact_paths, checksum_path)
        manifest["artifacts"]["checksums"] = {
            "path": str(checksum_path),
            "sha256": sha256_file(checksum_path),
        }

        write_manifest(output_dir, manifest_path, manifest)
        tarball = tar_output_dir(output_dir)
        manifest["artifacts"]["tarball"] = {
            "path": str(tarball),
            "sha256": sha256_file(tarball),
        }
    except Exception as exc:  # noqa: BLE001
        manifest["overall_status"] = "fail"
        manifest["failure"] = str(exc)
        write_manifest(output_dir, output_dir / "manifest.json", manifest)
        print(f"m20_shielded_audit_handoff_bundle: {exc}", file=sys.stderr)
        return 1

    write_manifest(output_dir, output_dir / "manifest.json", manifest)
    print(json.dumps({"overall_status": "pass", "output_dir": str(output_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
