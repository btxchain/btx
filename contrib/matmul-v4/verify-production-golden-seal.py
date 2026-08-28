#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail-closed verification for the Profile-1 production-golden seal.

``compare`` validates raw harness artifacts and writes the provider comparison.
``seal`` validates the committed inert manifest against that comparison, the
raw artifacts, and the exact freeze -> seal git relationship.  The latter is a
release gate: it deliberately rejects evidence generated from a dirty binary,
a stale revision, a toy/partial run, or a commit that changed executable code
after the measured freeze.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


MANIFEST_MAGIC = "BTX_RC_PRODUCTION_GOLDEN_V1"
MANIFEST_RELATIVE = Path(
    "src/matmul/matmul_v4_rc_production_golden_manifest.data"
)
BUILD_RELEVANT = ("CMakeLists.txt", "cmake", "src", "contrib/matmul-v4")
FINGERPRINT_EXCLUDED = (MANIFEST_RELATIVE.as_posix().encode(),)
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
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_TOKEN = re.compile(r"[A-Za-z0-9_.-]+")
SAFE_EVIDENCE = re.compile(r"doc/evidence/[A-Za-z0-9_./-]+")
PROVIDER_PREFIX = {
    "cuda": "cuda_",
    "metal": "metal_",
    "hip": "hip_",
}
ARCHITECTURE = {
    "cuda": re.compile(r"sm_[0-9]+"),
    "metal": re.compile(r"m[0-9]+_class"),
    "hip": re.compile(r"gfx[0-9a-z]+"),
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{path}: unreadable JSON ({exc})") from exc
    require(isinstance(value, dict), f"{path}: JSON root must be an object")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=False
    )
    if check and result.returncode:
        raise VerificationError(
            f"git {' '.join(args)} failed: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result


def revision_exists(root: Path, revision: str) -> bool:
    return git(root, "cat-file", "-e", f"{revision}^{{commit}}", check=False).returncode == 0


def tree_fingerprint(root: Path, revision: str) -> str:
    result = git(
        root, "ls-tree", "-r", "--full-tree", revision, "--", *BUILD_RELEVANT
    )
    kept = [
        line
        for line in result.stdout.splitlines(keepends=True)
        if not any(
            line.rstrip(b"\n").endswith(b"\t" + excluded)
            for excluded in FINGERPRINT_EXCLUDED
        )
    ]
    require(kept, f"{revision}: build-relevant tree is empty")
    return hashlib.sha256(b"".join(kept)).hexdigest()


def canonical_header(nonce: int) -> bytes:
    require(0 <= nonce < (1 << 64), f"nonce {nonce}: outside uint64 range")
    return b"".join(
        (
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
        )
    )


@dataclass(frozen=True)
class Artifact:
    backend: str
    path: Path
    artifact_sha256: str
    source_revision: str
    source_tree_fingerprint: str
    harness_sha256: str
    provider: str
    provider_identity: dict
    records: tuple[dict, ...]


def _exact_string(value, label: str, pattern: re.Pattern[str] | None = None) -> str:
    require(isinstance(value, str) and value, f"{label}: missing string")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{label}: malformed value {value!r}")
    return value


def validate_artifact(
    backend: str,
    path: Path,
    revision: str,
    fingerprint: str,
    nonce_start: int,
    episodes: int,
) -> Artifact:
    require(backend in PROVIDER_PREFIX, f"unsupported backend {backend!r}")
    raw = load_json(path)
    label = f"{path} ({backend})"

    for field, expected in (
        ("tool", "rc-episode-harness"),
        ("schema_version", 2),
        ("stub", False),
        ("public_evidence", True),
        ("backend_requested", backend),
        ("profile", "episode"),
        ("toy", False),
        ("medium", False),
        ("production_dims", True),
        ("rounds_override", 0),
        ("episode_profile", 1),
        ("header_matmul_dim", 4096),
        ("header_family", "production_canary"),
        ("all_consensus_macs_on_device", True),
    ):
        require(raw.get(field) == expected, f"{label}: {field} must be {expected!r}")
    require(raw.get("params") == PRODUCTION_PARAMS, f"{label}: non-production episode parameters")
    require(raw.get("source_revision") == revision, f"{label}: source_revision mismatch")
    require(raw.get("git_tip") == revision, f"{label}: git_tip mismatch")
    require(
        raw.get("embedded_source_revision") == revision,
        f"{label}: embedded_source_revision mismatch",
    )
    require(raw.get("embedded_source_dirty") is False, f"{label}: dirty harness binary")
    require(
        raw.get("source_tree_fingerprint") == fingerprint,
        f"{label}: source_tree_fingerprint mismatch",
    )
    harness_sha256 = _exact_string(raw.get("harness_sha256"), f"{label}: harness_sha256", HEX64)

    provider = _exact_string(raw.get("backend"), f"{label}: backend")
    acceleration = raw.get("exact_replay_acceleration")
    require(isinstance(acceleration, dict), f"{label}: missing exact_replay_acceleration")
    require(acceleration.get("provider") == provider, f"{label}: provider fields disagree")
    require(provider.startswith(PROVIDER_PREFIX[backend]), f"{label}: provider family mismatch")
    require(
        raw.get("device_id") == f"{provider}:public-evidence",
        f"{label}: device_id is not public-evidence provider identity",
    )
    for field in (
        "backend_resolution_reason",
        "evidence_kind",
        "wall_clock_provenance",
    ):
        _exact_string(raw.get(field), f"{label}: {field}")
    require(
        acceleration.get("resolution_reason") == raw.get("backend_resolution_reason"),
        f"{label}: backend resolution reasons disagree",
    )
    for field in (
        "device_backend_present",
        "require_device",
        "fully_accelerated",
        "all_consensus_macs_on_device",
    ):
        require(acceleration.get(field) is True, f"{label}: {field} must be true")
    expected_total = PER_EPISODE_MACS * episodes
    require(acceleration.get("expected_macs") == expected_total, f"{label}: expected_macs mismatch")
    require(acceleration.get("device_macs") == expected_total, f"{label}: device_macs mismatch")
    require(
        isinstance(acceleration.get("device_calls"), int)
        and acceleration["device_calls"] > 0,
        f"{label}: no device calls",
    )
    for field in ("cpu_calls", "cpu_macs", "cpu_fallbacks"):
        require(acceleration.get(field) == 0, f"{label}: {field} must be zero")
    require(acceleration.get("first_failure") in (None, ""), f"{label}: device failure recorded")

    identity = raw.get("production_provider_identity")
    require(isinstance(identity, dict), f"{label}: missing provider identity")
    require(identity.get("complete") is True, f"{label}: provider identity incomplete")
    require(identity.get("provider_family") == backend, f"{label}: provider identity family mismatch")
    architecture = _exact_string(
        identity.get("device_architecture"), f"{label}: device architecture"
    )
    require(
        ARCHITECTURE[backend].fullmatch(architecture) is not None,
        f"{label}: invalid {backend} architecture {architecture!r}",
    )
    for field in ("driver_identity", "runtime_identity", "reason"):
        _exact_string(identity.get(field), f"{label}: provider {field}")

    frozen = raw.get("frozen_headers")
    require(isinstance(frozen, list) and len(frozen) == episodes, f"{label}: wrong frozen-header count")
    episode_digests = raw.get("episode_digests")
    require(
        isinstance(episode_digests, list) and len(episode_digests) == episodes,
        f"{label}: wrong episode-digest count",
    )
    records: list[dict] = []
    seen_nonces: set[int] = set()
    seen_headers: set[str] = set()
    for index, item in enumerate(frozen):
        record_label = f"{label}: frozen_headers[{index}]"
        require(isinstance(item, dict), f"{record_label}: not an object")
        nonce = nonce_start + index
        for field, expected in (
            ("index", index),
            ("header_family", "production_canary"),
            ("header_nonce", nonce),
            ("nVersion", 536870916),
            ("nTime", 1780000000),
            ("nBits", 545259519),
            ("nNonce", nonce),
            ("nNonce64", nonce),
            ("matmul_dim", 4096),
            ("hashPrevBlock", "91" * 32),
            ("hashMerkleRoot", "2d" * 32),
            ("matmul_digest", "00" * 32),
            ("seed_a", "46" * 32),
            ("seed_b", "b8" * 32),
            ("header_wire_bytes", 182),
            ("fully_accelerated", True),
            ("require_device", True),
            ("device_macs", PER_EPISODE_MACS),
            ("cpu_calls", 0),
            ("cpu_macs", 0),
            ("cpu_fallbacks", 0),
        ):
            require(item.get(field) == expected, f"{record_label}: {field} must be {expected!r}")
        require(item.get("first_failure") in (None, ""), f"{record_label}: device failure recorded")
        header_hex = _exact_string(item.get("header_hex"), f"{record_label}: header_hex")
        require(header_hex == canonical_header(nonce).hex(), f"{record_label}: noncanonical header bytes")
        digest = _exact_string(
            item.get("exact_replay_digest"), f"{record_label}: exact_replay_digest", HEX64
        )
        require(digest != "0" * 64, f"{record_label}: null digest")
        require(episode_digests[index] == digest, f"{record_label}: episode_digests mismatch")
        require(nonce not in seen_nonces, f"{record_label}: duplicate nonce")
        require(header_hex not in seen_headers, f"{record_label}: duplicate header")
        seen_nonces.add(nonce)
        seen_headers.add(header_hex)
        records.append(
            {
                "header_nonce": nonce,
                "matmul_dim": 4096,
                "header_hex": header_hex,
                "header_sha256": hashlib.sha256(bytes.fromhex(header_hex)).hexdigest(),
                "exact_replay_digest": digest,
            }
        )

    return Artifact(
        backend=backend,
        path=path,
        artifact_sha256=sha256_file(path),
        source_revision=revision,
        source_tree_fingerprint=fingerprint,
        harness_sha256=harness_sha256,
        provider=provider,
        provider_identity=identity,
        records=tuple(records),
    )


def comparison_payload(
    artifacts: list[Artifact],
    revision: str,
    fingerprint: str,
    nonce_start: int,
    episodes: int,
    allow_partial: bool,
) -> dict:
    require(artifacts, "no backend artifacts")
    require(len({artifact.backend for artifact in artifacts}) == len(artifacts), "duplicate backend artifact")
    reference = artifacts[0]
    mismatches: list[dict] = []
    for artifact in artifacts[1:]:
        for expected, observed in zip(reference.records, artifact.records):
            for field in ("header_nonce", "matmul_dim", "header_hex", "exact_replay_digest"):
                if expected[field] != observed[field]:
                    mismatches.append(
                        {"nonce": expected["header_nonce"], "backend": artifact.backend, "reason": f"{field}_mismatch"}
                    )
    present = {artifact.backend for artifact in artifacts}
    required = present
    complete = required.issubset(present) and not mismatches and bool(required)
    cuda_metal = {"cuda", "metal"}.issubset(present) and not mismatches
    payload = {
        "evidence_kind": "multi_gpu_profile1_exactreplay_golden_compare",
        "schema_version": 2,
        "tip_sha": revision,
        "source_tree_fingerprint": fingerprint,
        "canary_nonce_start": nonce_start,
        "episodes": episodes,
        "per_episode_consensus_macs": PER_EPISODE_MACS,
        "backends_requested": [artifact.backend for artifact in artifacts],
        "backends_succeeded": [artifact.backend for artifact in artifacts],
        "required_for_manifest": sorted(required),
        "complete_multi_gpu_match": complete,
        "cuda_metal_match": cuda_metal,
        "allow_partial": allow_partial,
        "mismatches": mismatches,
        "coverage_failures": [],
        "by_backend": {},
        "authorizes_activation": False,
        "authorizes_activation_reason": (
            "digest agreement across providers only; this tool does not read "
            "consensus parameters, ratification flags, or the committed manifest"
        ),
    }
    for artifact in artifacts:
        payload["by_backend"][artifact.backend] = {
            "n": episodes,
            "raw": artifact.path.name,
            "artifact_sha256": artifact.artifact_sha256,
            "all_consensus_macs_on_device": True,
            "cpu_gemm_fallbacks": 0,
            "source_revision": revision,
            "embedded_source_revision": revision,
            "embedded_source_dirty": False,
            "source_tree_fingerprint": fingerprint,
            "harness_sha256": artifact.harness_sha256,
            "provider": artifact.provider,
            "backend_requested": artifact.backend,
            "provider_identity": artifact.provider_identity,
            "digests_by_nonce": {
                str(record["header_nonce"]): record["exact_replay_digest"]
                for record in artifact.records
            },
            "header_sha256_by_nonce": {
                str(record["header_nonce"]): record["header_sha256"]
                for record in artifact.records
            },
        }
    return payload


def parse_artifact_arguments(values: list[str]) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    for value in values:
        backend, separator, path = value.partition("=")
        require(separator == "=" and backend in PROVIDER_PREFIX and path, f"invalid --artifact {value!r}")
        result.append((backend, Path(path)))
    return result


def compare_command(args: argparse.Namespace) -> int:
    require(HEX40.fullmatch(args.revision) is not None, "revision must be 40 lowercase hexadecimal characters")
    require(HEX64.fullmatch(args.fingerprint) is not None, "fingerprint must be 64 lowercase hexadecimal characters")
    pairs = parse_artifact_arguments(args.artifact)
    artifacts = [
        validate_artifact(backend, path, args.revision, args.fingerprint, args.nonce_start, args.episodes)
        for backend, path in pairs
    ]
    payload = comparison_payload(
        artifacts, args.revision, args.fingerprint, args.nonce_start, args.episodes, args.allow_partial
    )
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "wrote": str(args.out),
        "complete_multi_gpu_match": payload["complete_multi_gpu_match"],
        "mismatches": len(payload["mismatches"]),
        "coverage_failures": 0,
    }, indent=2))
    require(not payload["mismatches"], "header/digest mismatch across backends")
    require(
        payload["complete_multi_gpu_match"] or args.allow_partial,
        "incomplete production-golden set (measured backends must agree)",
    )
    return 0


@dataclass(frozen=True)
class ManifestEntry:
    identifier: str
    family: str
    architecture: str
    nonce: int
    digest: str
    evidence_path: str
    revision: str
    fingerprint: str
    harness_sha256: str


def parse_manifest(path: Path) -> list[ManifestEntry]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise VerificationError(f"{path}: unreadable manifest ({exc})") from exc
    require("\r" not in text, f"{path}: manifest must use LF line endings")
    lines = text.splitlines()
    require(lines and lines[0] == MANIFEST_MAGIC, f"{path}: wrong manifest magic")
    require(len(lines) >= 2, f"{path}: at least one provider entry is required")
    entries: list[ManifestEntry] = []
    for line_number, line in enumerate(lines[1:], 2):
        fields = line.split("|")
        require(len(fields) == 10, f"{path}:{line_number}: expected 10 fields")
        identifier, family, architecture, nonce_text, digest, profile, evidence, revision, fingerprint, harness = fields
        for name, value in (("id", identifier), ("family", family), ("architecture", architecture)):
            require(SAFE_TOKEN.fullmatch(value) is not None, f"{path}:{line_number}: invalid {name}")
        require(family in PROVIDER_PREFIX, f"{path}:{line_number}: unsupported provider family")
        require(ARCHITECTURE[family].fullmatch(architecture) is not None, f"{path}:{line_number}: invalid architecture")
        require(profile == "1", f"{path}:{line_number}: only Profile 1 is admissible")
        require(SAFE_EVIDENCE.fullmatch(evidence) is not None and ".." not in Path(evidence).parts, f"{path}:{line_number}: unsafe evidence path")
        require(HEX64.fullmatch(digest) is not None and digest != "0" * 64, f"{path}:{line_number}: invalid digest")
        require(HEX40.fullmatch(revision) is not None, f"{path}:{line_number}: invalid revision")
        require(HEX64.fullmatch(fingerprint) is not None, f"{path}:{line_number}: invalid fingerprint")
        require(HEX64.fullmatch(harness) is not None, f"{path}:{line_number}: invalid harness SHA-256")
        try:
            nonce = int(nonce_text)
        except ValueError as exc:
            raise VerificationError(f"{path}:{line_number}: invalid nonce") from exc
        require(0 <= nonce < 1 << 64, f"{path}:{line_number}: invalid nonce")
        entries.append(ManifestEntry(identifier, family, architecture, nonce, digest, evidence, revision, fingerprint, harness))
    require(len({entry.identifier for entry in entries}) == len(entries), f"{path}: duplicate entry id")
    require(len({entry.family for entry in entries}) == len(entries), f"{path}: duplicate provider family")
    families = {entry.family for entry in entries}
    require("cuda" in families, f"{path}: manifest must contain CUDA")
    require(families <= {"cuda", "metal", "hip"}, f"{path}: unsupported provider family in cohort")
    require(len({entry.evidence_path for entry in entries}) == 1, f"{path}: provider entries must name one corpus")
    require(len({entry.revision for entry in entries}) == 1, f"{path}: provider revisions disagree")
    require(len({entry.fingerprint for entry in entries}) == 1, f"{path}: provider fingerprints disagree")
    require(len({entry.nonce for entry in entries}) == 1, f"{path}: provider nonces disagree")
    require(len({entry.digest for entry in entries}) == 1, f"{path}: provider digests disagree")
    return entries


def require_tracked_clean(root: Path, relative: Path) -> None:
    require(not relative.is_absolute() and ".." not in relative.parts, f"unsafe repository path {relative}")
    require(not (root / relative).is_symlink(), f"{relative}: symbolic links are not allowed")
    require(git(root, "ls-files", "--error-unmatch", relative.as_posix(), check=False).returncode == 0, f"{relative}: file is not tracked")
    require(git(root, "diff", "--quiet", "HEAD", "--", relative.as_posix(), check=False).returncode == 0, f"{relative}: file differs from HEAD")


def require_build_tree_clean(root: Path) -> None:
    status = git(root, "status", "--porcelain", "--", *BUILD_RELEVANT).stdout
    require(
        not status.strip(),
        "build-relevant working tree is dirty: "
        + status.decode(errors="replace").strip().replace("\n", ", "),
    )


def seal_command(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    require_build_tree_clean(root)
    manifest_relative = args.manifest
    manifest_path = root / manifest_relative
    require_tracked_clean(root, manifest_relative)
    entries = parse_manifest(manifest_path)

    revision = entries[0].revision
    fingerprint = entries[0].fingerprint
    require(revision_exists(root, revision), f"manifest revision {revision} does not resolve to a commit")
    actual = tree_fingerprint(root, revision)
    require(actual == fingerprint, f"manifest fingerprint does not match freeze revision ({actual})")
    head = git(root, "rev-parse", "HEAD").stdout.decode().strip()
    require(git(root, "merge-base", "--is-ancestor", revision, head, check=False).returncode == 0, "freeze revision is not an ancestor of seal HEAD")
    require(head != revision, "manifest must be committed in a seal after the measured freeze")
    require(tree_fingerprint(root, head) == fingerprint, "build-relevant code changed after the measured freeze")
    changed = {
        line.decode().strip()
        for line in git(root, "diff", "--name-only", f"{revision}..{head}", "--", *BUILD_RELEVANT).stdout.splitlines()
        if line.strip()
    }
    require(changed == {manifest_relative.as_posix()}, f"freeze -> seal build changes must be exactly {manifest_relative}, got {sorted(changed)}")
    changed_all = {
        line.decode().strip()
        for line in git(root, "diff", "--name-only", f"{revision}..{head}").stdout.splitlines()
        if line.strip()
    }
    disallowed = {
        path
        for path in changed_all
        if path != manifest_relative.as_posix() and not path.startswith("doc/")
    }
    require(
        not disallowed,
        "freeze -> seal changes must be the manifest and documentation only, got "
        f"{sorted(disallowed)}",
    )

    corpus_relative = Path(entries[0].evidence_path)
    compare_relative = corpus_relative / "multi-gpu-digest-compare.json"
    require_tracked_clean(root, compare_relative)
    comparison = load_json(root / compare_relative)
    families = {entry.family for entry in entries}
    for field, expected in (
        ("evidence_kind", "multi_gpu_profile1_exactreplay_golden_compare"),
        ("schema_version", 2),
        ("tip_sha", revision),
        ("source_tree_fingerprint", fingerprint),
        ("canary_nonce_start", 1),
        ("episodes", 8),
        ("per_episode_consensus_macs", PER_EPISODE_MACS),
        ("complete_multi_gpu_match", True),
        ("allow_partial", False),
        ("mismatches", []),
        ("coverage_failures", []),
    ):
        require(comparison.get(field) == expected, f"{compare_relative}: {field} mismatch")
    succeeded = set(comparison.get("backends_succeeded", []))
    require(succeeded, f"{compare_relative}: no backends succeeded")
    require(
        set(comparison.get("required_for_manifest") or []) == succeeded,
        f"{compare_relative}: required_for_manifest must equal the measured backends",
    )
    require(families <= succeeded, f"{compare_relative}: manifest families missing from comparison")
    if "cuda" in families and "metal" in families:
        require(comparison.get("cuda_metal_match") is True, f"{compare_relative}: cuda_metal_match mismatch")
    by_backend = comparison.get("by_backend")
    require(isinstance(by_backend, dict), f"{compare_relative}: missing by_backend")

    for entry in entries:
        summary = by_backend.get(entry.family)
        require(isinstance(summary, dict), f"{compare_relative}: missing {entry.family} summary")
        raw_name = summary.get("raw")
        require(isinstance(raw_name, str) and Path(raw_name).name == raw_name, f"{compare_relative}: unsafe raw artifact name")
        raw_relative = corpus_relative / "raw" / raw_name
        require_tracked_clean(root, raw_relative)
        raw_path = root / raw_relative
        artifact = validate_artifact(entry.family, raw_path, revision, fingerprint, 1, 8)
        record = next((item for item in artifact.records if item["header_nonce"] == entry.nonce), None)
        require(record is not None, f"{raw_relative}: manifest nonce missing")
        require(record["exact_replay_digest"] == entry.digest, f"{raw_relative}: manifest digest mismatch")
        require(artifact.harness_sha256 == entry.harness_sha256, f"{raw_relative}: manifest harness mismatch")
        require(artifact.provider_identity.get("provider_family") == entry.family, f"{raw_relative}: provider family mismatch")
        require(artifact.provider_identity.get("device_architecture") == entry.architecture, f"{raw_relative}: architecture mismatch")
        require(summary.get("artifact_sha256") == artifact.artifact_sha256, f"{raw_relative}: raw artifact changed after comparison")
        for field, expected in (
            ("n", 8),
            ("source_revision", revision),
            ("embedded_source_revision", revision),
            ("embedded_source_dirty", False),
            ("source_tree_fingerprint", fingerprint),
            ("harness_sha256", entry.harness_sha256),
            ("provider", artifact.provider),
            ("backend_requested", entry.family),
            ("provider_identity", artifact.provider_identity),
        ):
            require(summary.get(field) == expected, f"{compare_relative}: {entry.family}.{field} mismatch")
        expected_digests = {str(item["header_nonce"]): item["exact_replay_digest"] for item in artifact.records}
        expected_headers = {str(item["header_nonce"]): item["header_sha256"] for item in artifact.records}
        require(summary.get("digests_by_nonce") == expected_digests, f"{compare_relative}: digest summary mismatch")
        require(summary.get("header_sha256_by_nonce") == expected_headers, f"{compare_relative}: header summary mismatch")

    print(
        "verify-production-golden-seal: PASS "
        f"freeze={revision} seal={head} corpus={corpus_relative} "
        f"providers={','.join(sorted(families))}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    compare = subparsers.add_parser("compare")
    compare.add_argument("--out", type=Path, required=True)
    compare.add_argument("--revision", required=True)
    compare.add_argument("--fingerprint", required=True)
    compare.add_argument("--nonce-start", type=int, required=True)
    compare.add_argument("--episodes", type=int, required=True)
    compare.add_argument("--allow-partial", action="store_true")
    compare.add_argument("--artifact", action="append", default=[], required=True)
    compare.set_defaults(handler=compare_command)

    seal = subparsers.add_parser("seal")
    seal.add_argument("--root", type=Path, required=True)
    seal.add_argument("--manifest", type=Path, default=MANIFEST_RELATIVE)
    seal.set_defaults(handler=seal_command)

    args = parser.parse_args()
    try:
        return args.handler(args)
    except VerificationError as exc:
        print(f"verify-production-golden-seal: FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
