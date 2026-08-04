#!/usr/bin/env python3
"""Assemble exact-build CUDA+Metal Epoch-A ASERT calibration evidence."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DERIVE_PATH = Path(__file__).with_name("derive-epoch-a-asert.py")
_SPEC = importlib.util.spec_from_file_location("derive_epoch_a_asert", DERIVE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"cannot load {DERIVE_PATH.name}")
DERIVE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(DERIVE)

RIG_TOOL = "btx_epoch_a_asert_rig"
RIG_SCHEMA_VERSION = 1
_MAC_HOME_PREFIX = "/" + "Users/"
_UNIX_HOME_PREFIX = "/" + "home/"
UNSAFE_PUBLIC_TEXT = re.compile(
    rf"(?:{re.escape(_MAC_HOME_PREFIX)}|{re.escape(_UNIX_HOME_PREFIX)}|"
    r"/Volumes/|[A-Za-z]:[\\/]Users[\\/]|"
    r"file://|ssh://|(?:^|\s)[^\s@]+@[^\s@]+\.[^\s@]+|"
    r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.]))",
    re.IGNORECASE,
)

IDENTITY_FIELDS = (
    "source_revision",
    "source_tree_fingerprint",
    "embedded_source_revision",
    "embedded_source_dirty",
)
PARENT_FIELDS = (
    *IDENTITY_FIELDS,
    "tool",
    "schema_version",
    "binary_sha256",
    "mode",
    "eps",
    "nBits",
    "matmul_dimension",
    "transcript_block_size",
    "noise_rank",
    "seed",
    "height",
    "parent_mtp",
    "tries",
    "attempts_done",
    "wall_s",
    "attempts_per_s",
    "solved",
    "solve_runtime_attempts",
    "solve_runtime_solved_attempts",
    "solve_runtime_failed_attempts",
    "requested_backend",
    "active_backend",
    "backend_selection_reason",
    "required_backend_enabled",
    "required_backend_satisfied",
    "digest_requests",
    "requested_cpu",
    "requested_unknown",
    "requested_cuda",
    "requested_metal",
    "cuda_successes",
    "metal_successes",
    "metal_digest_mismatches",
    "metal_fallbacks_to_cpu",
    "cuda_fallbacks_to_cpu",
    "cpu_fallbacks",
    "gpu_input_generation_attempts",
    "gpu_input_generation_successes",
    "gpu_input_generation_failures",
    "last_metal_fallback_error",
    "last_cuda_fallback_error",
    "last_gpu_input_error",
)
RC_FIELDS = (
    *IDENTITY_FIELDS,
    "tool",
    "schema_version",
    "harness_sha256",
    "backend_requested",
    "backend",
    "profile",
    "toy",
    "medium",
    "production_dims",
    "episode_profile",
    "header_matmul_dim",
    "rounds_override",
    "evidence_kind",
)
PROVIDER_IDENTITY_FIELDS = (
    "provider_family",
    "device_architecture",
    "driver_identity",
    "runtime_identity",
    "complete",
    "reason",
)
HEADER_FIELDS = (
    "header_family",
    "header_nonce",
    "matmul_dim",
    "exact_replay_digest",
    "wall_s",
    "fully_accelerated",
    "require_device",
    "device_macs",
    "cpu_calls",
    "cpu_macs",
    "cpu_fallbacks",
    "first_failure",
)
ACCELERATION_FIELDS = (
    "provider",
    "resolution_reason",
    "device_backend_present",
    "require_device",
    "fully_accelerated",
    "all_consensus_macs_on_device",
    "expected_macs",
    "device_calls",
    "device_macs",
    "cpu_calls",
    "cpu_macs",
    "cpu_fallbacks",
    "first_failure",
)


class AssemblyError(ValueError):
    pass


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: copy.deepcopy(obj[field]) for field in fields}


def _public_text(value: Any, field: str) -> str:
    value = DERIVE.require_nonempty_string(value, field)
    if any(ord(char) < 32 for char in value) or UNSAFE_PUBLIC_TEXT.search(value):
        raise AssemblyError(f"{field} contains non-public machine data")
    return value


def _canonical_parent(sample: dict[str, Any]) -> dict[str, Any]:
    _public_text(sample.get("backend_selection_reason"), "backend_selection_reason")
    return _pick(sample, PARENT_FIELDS)


def _canonical_rc(sample: dict[str, Any]) -> dict[str, Any]:
    result = _pick(sample, RC_FIELDS)
    identity = sample["production_provider_identity"]
    for field in ("driver_identity", "runtime_identity", "reason"):
        _public_text(identity.get(field), f"production_provider_identity.{field}")
    result["production_provider_identity"] = _pick(
        identity, PROVIDER_IDENTITY_FIELDS
    )
    result["params"] = copy.deepcopy(sample["params"])

    headers = [_pick(header, HEADER_FIELDS) for header in sample["frozen_headers"]]
    walls = sample["run_variance"]["episode_wall_samples_s"]
    paired = sorted(zip(headers, walls), key=lambda item: item[0]["header_nonce"])
    result["frozen_headers"] = [header for header, _ in paired]
    result["run_variance"] = {
        "n_runs": len(paired),
        "episode_wall_samples_s": [wall for _, wall in paired],
    }
    acceleration = sample["exact_replay_acceleration"]
    _public_text(acceleration.get("resolution_reason"), "resolution_reason")
    result["exact_replay_acceleration"] = _pick(
        acceleration, ACCELERATION_FIELDS
    )
    return result


def _common_hex(
    samples: list[dict[str, Any]], field: str, pattern: re.Pattern[str], label: str
) -> str:
    values = {
        DERIVE.require_hex(sample.get(field), pattern, f"{label}.{field}")
        for sample in samples
    }
    if len(values) != 1:
        raise AssemblyError(f"{label} do not share one exact {field}")
    return values.pop()


def assemble_rig(
    provider: str,
    parent_samples: list[dict[str, Any]],
    rc_artifacts: list[dict[str, Any]],
    *,
    expected_revision: str,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Validate and sanitize one provider's exact-build calibration inputs."""
    if provider not in DERIVE.REQUIRED_PROVIDERS:
        raise AssemblyError(f"unsupported provider: {provider}")
    revision = DERIVE.require_hex(expected_revision, DERIVE.HEX40, "source_revision")
    fingerprint = DERIVE.require_hex(
        expected_fingerprint, DERIVE.HEX64, "source_tree_fingerprint"
    )
    if len(parent_samples) < 5:
        raise AssemblyError("rig needs at least five mixed parent samples")
    if not rc_artifacts:
        raise AssemblyError("rig needs at least one RC episode artifact")
    if not all(isinstance(sample, dict) for sample in parent_samples + rc_artifacts):
        raise AssemblyError("every input artifact must be a JSON object")

    parent_binary = _common_hex(
        parent_samples, "binary_sha256", DERIVE.HEX64, "parent samples"
    )
    harness_binary = _common_hex(
        rc_artifacts, "harness_sha256", DERIVE.HEX64, "RC artifacts"
    )
    architectures: set[str] = set()
    for index, artifact in enumerate(rc_artifacts):
        identity = artifact.get("production_provider_identity")
        if not isinstance(identity, dict):
            raise AssemblyError(
                f"rc_artifacts[{index}].production_provider_identity is missing"
            )
        architecture = identity.get("device_architecture")
        if (not isinstance(architecture, str) or
                DERIVE.SAFE_TOKEN.fullmatch(architecture) is None):
            raise AssemblyError(f"rc_artifacts[{index}] has invalid architecture")
        architectures.add(architecture)
    if len(architectures) != 1:
        raise AssemblyError("RC artifacts do not share one exact architecture")
    architecture = architectures.pop()

    canonical_parents: list[dict[str, Any]] = []
    seeds: list[int] = []
    for index, sample in enumerate(parent_samples):
        _, _, seed = DERIVE.validate_parent_sample(
            sample,
            provider,
            f"mixed_mode_samples[{index}]",
            revision=revision,
            fingerprint=fingerprint,
            binary_sha256=parent_binary,
        )
        seeds.append(seed)
        canonical_parents.append(_canonical_parent(sample))
    if len(seeds) != len(set(seeds)):
        raise AssemblyError("mixed parent samples contain duplicate seeds")
    canonical_parents.sort(key=lambda sample: sample["seed"])

    canonical_rc: list[dict[str, Any]] = []
    nonces: list[int] = []
    for index, artifact in enumerate(rc_artifacts):
        runs = DERIVE.validate_rc_artifact(
            artifact,
            provider,
            architecture,
            f"rc_episode_samples[{index}]",
            revision=revision,
            fingerprint=fingerprint,
            harness_sha256=harness_binary,
        )
        nonces.extend(nonce for nonce, _ in runs)
        canonical_rc.append(_canonical_rc(artifact))
    if len(nonces) < 3:
        raise AssemblyError("rig needs at least three RC episode runs")
    if len(nonces) != len(set(nonces)):
        raise AssemblyError("RC episode artifacts contain duplicate nonces")
    canonical_rc.sort(
        key=lambda artifact: tuple(
            header["header_nonce"] for header in artifact["frozen_headers"]
        )
    )

    return {
        "tool": RIG_TOOL,
        "schema_version": RIG_SCHEMA_VERSION,
        "source_revision": revision,
        "source_tree_fingerprint": fingerprint,
        "embedded_source_revision": revision,
        "embedded_source_dirty": False,
        "provider_family": provider,
        "device_architecture": architecture,
        "parent_binary_sha256": parent_binary,
        "rc_harness_sha256": harness_binary,
        "mixed_mode_samples": canonical_parents,
        "rc_episode_samples": canonical_rc,
    }


def _derive_rig(rig: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in rig.items()
        if key not in ("tool", "schema_version")
    }


def merge_rigs(
    rigs: list[dict[str, Any]], *, expected_revision: str,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Revalidate exactly one CUDA and one Metal rig and emit derive input."""
    if len(rigs) != 2:
        raise AssemblyError("merge requires exactly two rig JSON objects")
    revision = DERIVE.require_hex(expected_revision, DERIVE.HEX40, "source_revision")
    fingerprint = DERIVE.require_hex(
        expected_fingerprint, DERIVE.HEX64, "source_tree_fingerprint"
    )
    canonical: dict[str, dict[str, Any]] = {}
    for index, rig in enumerate(rigs):
        if not isinstance(rig, dict):
            raise AssemblyError(f"rigs[{index}] must be a JSON object")
        if rig.get("tool") != RIG_TOOL or rig.get("schema_version") != RIG_SCHEMA_VERSION:
            raise AssemblyError(f"rigs[{index}] is not a canonical ASERT rig")
        provider = rig.get("provider_family")
        if provider not in DERIVE.REQUIRED_PROVIDERS or provider in canonical:
            raise AssemblyError("merge requires exactly one CUDA and one Metal rig")
        rebuilt = assemble_rig(
            provider,
            rig.get("mixed_mode_samples", []),
            rig.get("rc_episode_samples", []),
            expected_revision=revision,
            expected_fingerprint=fingerprint,
        )
        if rebuilt != rig:
            raise AssemblyError(f"{provider} rig is not canonical sanitized output")
        canonical[provider] = rebuilt
    if set(canonical) != set(DERIVE.REQUIRED_PROVIDERS):
        raise AssemblyError("merge requires exactly one CUDA and one Metal rig")

    ordered = [canonical[provider] for provider in DERIVE.REQUIRED_PROVIDERS]
    seed_sets = {
        tuple(sample["seed"] for sample in rig["mixed_mode_samples"])
        for rig in ordered
    }
    if len(seed_sets) != 1:
        raise AssemblyError("CUDA and Metal rigs do not share the same parent seed set")
    nonce_sets = {
        tuple(sorted(
            header["header_nonce"]
            for artifact in rig["rc_episode_samples"]
            for header in artifact["frozen_headers"]
        ))
        for rig in ordered
    }
    if len(nonce_sets) != 1:
        raise AssemblyError("CUDA and Metal rigs do not share the same RC nonce set")
    digest_maps = {
        tuple(sorted(
            (header["header_nonce"], header["exact_replay_digest"])
            for artifact in rig["rc_episode_samples"]
            for header in artifact["frozen_headers"]
        ))
        for rig in ordered
    }
    if len(digest_maps) != 1:
        raise AssemblyError(
            "CUDA and Metal rigs do not share byte-identical RC digests"
        )

    root = {
        "tool": DERIVE.ROOT_TOOL,
        "schema_version": DERIVE.ROOT_SCHEMA_VERSION,
        "source_revision": revision,
        "source_tree_fingerprint": fingerprint,
        "embedded_source_revision": revision,
        "embedded_source_dirty": False,
        "consensus_context": copy.deepcopy(DERIVE.EXPECTED_CONTEXT),
        "rigs": [_derive_rig(rig) for rig in ordered],
    }
    # The assembler and the consumer are intentionally coupled: never emit an
    # object the coefficient derivation would reject.
    DERIVE.derive(
        root,
        expected_revision=revision,
        expected_fingerprint=fingerprint,
    )
    return root


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssemblyError(f"cannot read a JSON object: {error}") from error
    if not isinstance(value, dict):
        raise AssemblyError("input JSON root must be an object")
    return value


def _write_object(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded, encoding="utf-8")
    except OSError as error:
        raise AssemblyError(f"cannot write output JSON: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    rig_parser = subparsers.add_parser("rig", help="sanitize one provider rig")
    rig_parser.add_argument("--provider", choices=DERIVE.REQUIRED_PROVIDERS, required=True)
    rig_parser.add_argument("--source-revision", required=True)
    rig_parser.add_argument("--parent-sample", action="append", type=Path, required=True)
    rig_parser.add_argument("--rc-artifact", action="append", type=Path, required=True)
    rig_parser.add_argument("--output", type=Path, required=True)

    merge_parser = subparsers.add_parser("merge", help="merge exact CUDA+Metal rigs")
    merge_parser.add_argument("--source-revision", required=True)
    merge_parser.add_argument("--rig", action="append", type=Path, required=True)
    merge_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        revision = DERIVE.resolve_commit(REPO_ROOT, args.source_revision)
        fingerprint = DERIVE.tree_fingerprint(REPO_ROOT, revision)
        if args.command == "rig":
            result = assemble_rig(
                args.provider,
                [_read_object(path) for path in args.parent_sample],
                [_read_object(path) for path in args.rc_artifact],
                expected_revision=revision,
                expected_fingerprint=fingerprint,
            )
        else:
            result = merge_rigs(
                [_read_object(path) for path in args.rig],
                expected_revision=revision,
                expected_fingerprint=fingerprint,
            )
        _write_object(args.output, result)
    except (AssemblyError, DERIVE.CalibrationError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
