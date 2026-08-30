#!/usr/bin/env python3
"""Derive Epoch-A ASERT from the exact-build strict launch-miner cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from decimal import Decimal, ROUND_CEILING, getcontext
from pathlib import Path
from typing import Any


getcontext().prec = 50
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = (
    REPO_ROOT
    / "doc/evidence/asert-two-rig-calibration-2026-08-03/raw/two-rig-v3-vs-rc.json"
)
ROOT_TOOL = "btx_epoch_a_asert_calibration"
ROOT_SCHEMA_VERSION = 4
PARENT_TOOL = "matmul-v3-asert-calibration"
PARENT_SCHEMA_VERSION = 3
RC_TOOL = "rc-episode-harness"
RC_SCHEMA_VERSION = 2
# Epoch-A difficulty calibration is bound to the CUDA launch cohort, deliberately
# and by policy -- not because Metal evidence was unavailable.
#
# The coefficient converts v3 parent nonce-attempt rate into RC episode cost, so
# it must describe the hardware that will actually mine the fork. That cohort is
# CUDA-dominated; an M4-class Metal provider is roughly 5x slower per RC episode,
# and including it in a "maximum required-provider envelope" would set network
# difficulty from a provider that will contribute a negligible share of hashrate.
#
# Metal remains a valid golden-corpus family (CUDA and Metal must derive
# byte-identical digests when both are present). See
# RCProductionGoldenManifestCohortValid: a single-family cohort is enough.
# This constant governs difficulty calibration only. Do not conflate the two
# gates -- widening this back to include Metal would silently reprice the fork.
REQUIRED_PROVIDERS = ("cuda",)
PROVIDER_PREFIXES = {"cuda": "cuda_", "metal": "metal_"}
CANONICAL_RC_EPISODE_MACS = 141_149_805_215_744
UINT64_MAX = (1 << 64) - 1
COEFFICIENT_POLICY_METHOD = (
    "max_observed_cross_product_plus_margin_quantized_up_v1"
)
FINGERPRINT_PATHS = ("CMakeLists.txt", "cmake", "src", "contrib/matmul-v4")
FINGERPRINT_EXCLUDE = (
    b"src/matmul/matmul_v4_rc_production_golden_manifest.data",
)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_TOKEN = re.compile(r"[a-z0-9_.-]+")
EXPECTED_CONTEXT = {
    "parent_mode": "mixed",
    "parent_matmul_dimension": 512,
    "parent_transcript_block_size": 16,
    "parent_noise_rank": 8,
    "parent_prehash_epsilon_bits": 18,
    "parent_height": 200000,
    "parent_mtp": 1779999910,
    "assumed_nbits": "1c487c56",
    "rc_profile": 1,
    "rc_matmul_dimension": 4096,
    "rc_execution": "strict-device",
    "rc_episode_macs": CANONICAL_RC_EPISODE_MACS,
}
EXPECTED_RC_PARAMS = {
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


class CalibrationError(ValueError):
    pass


def as_decimal(value: Any, field: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except Exception as error:  # Decimal has several input-specific errors.
        raise CalibrationError(f"{field} is not a decimal") from error
    if isinstance(value, bool) or not result.is_finite() or result <= 0:
        raise CalibrationError(f"{field} must be finite and positive")
    return result


def require_hex(value: Any, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CalibrationError(f"{field} is not canonical lowercase hex")
    return value


def require_int(value: Any, field: str, *, minimum: int = 0,
                maximum: int = UINT64_MAX) -> int:
    if (not isinstance(value, int) or isinstance(value, bool) or
            value < minimum or value > maximum):
        raise CalibrationError(
            f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CalibrationError(f"{field} must be a non-empty string")
    return value


def validate_coefficient_policy(value: Any) -> dict[str, int | str]:
    """Validate policy chosen by review/governance, never inferred from timing."""
    if not isinstance(value, dict):
        raise CalibrationError("coefficient_policy must be an object")
    expected_keys = {"method", "safety_margin_bps", "coefficient_quantum"}
    if set(value) != expected_keys:
        raise CalibrationError(
            "coefficient_policy must contain exactly method, safety_margin_bps, "
            "and coefficient_quantum"
        )
    if value.get("method") != COEFFICIENT_POLICY_METHOD:
        raise CalibrationError("coefficient_policy.method is unsupported")
    margin = require_int(
        value.get("safety_margin_bps"),
        "coefficient_policy.safety_margin_bps",
    )
    quantum = require_int(
        value.get("coefficient_quantum"),
        "coefficient_policy.coefficient_quantum",
        minimum=1,
    )
    return {
        "method": COEFFICIENT_POLICY_METHOD,
        "safety_margin_bps": margin,
        "coefficient_quantum": quantum,
    }


def require_zero(obj: dict[str, Any], fields: tuple[str, ...], prefix: str) -> None:
    for field in fields:
        if obj.get(field) != 0 or isinstance(obj.get(field), bool):
            raise CalibrationError(f"{prefix}.{field} must be zero")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_payload_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256_bytes(encoded)


def resolve_commit(root: Path, revision: str) -> str:
    revision = require_hex(revision, HEX40, "source_revision")
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{revision}^{{commit}}"],
        capture_output=True, text=True, check=False,
    )
    resolved = proc.stdout.strip().lower()
    if proc.returncode != 0 or resolved != revision:
        raise CalibrationError(f"source revision is not the exact commit {revision}")
    kind = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-t", revision],
        capture_output=True, text=True, check=False,
    )
    if kind.returncode != 0 or kind.stdout.strip() != "commit":
        raise CalibrationError(f"source revision is not a commit: {revision}")
    return revision


def tree_fingerprint(root: Path, revision: str) -> str:
    revision = resolve_commit(root, revision)
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-r", "--full-tree", revision,
         "--", *FINGERPRINT_PATHS],
        capture_output=True, check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise CalibrationError(f"cannot fingerprint source revision: {revision}")
    kept = [
        line for line in proc.stdout.splitlines(keepends=True)
        if not any(
            line.rstrip(b"\n").endswith(b"\t" + excluded)
            for excluded in FINGERPRINT_EXCLUDE
        )
    ]
    return sha256_bytes(b"".join(kept))


def validate_identity(
    obj: dict[str, Any], *, prefix: str, revision: str, fingerprint: str
) -> None:
    if require_hex(
        obj.get("source_revision"), HEX40, f"{prefix}.source_revision"
    ) != revision:
        raise CalibrationError(f"{prefix}.source_revision does not match the requested commit")
    if require_hex(
        obj.get("source_tree_fingerprint"), HEX64,
        f"{prefix}.source_tree_fingerprint",
    ) != fingerprint:
        raise CalibrationError(f"{prefix}.source_tree_fingerprint mismatch")
    if require_hex(
        obj.get("embedded_source_revision"), HEX40,
        f"{prefix}.embedded_source_revision",
    ) != revision:
        raise CalibrationError(f"{prefix}.embedded_source_revision mismatch")
    if obj.get("embedded_source_dirty") is not False:
        raise CalibrationError(f"{prefix}.embedded_source_dirty must be false")


def validate_parent_sample(
    sample: Any, provider: str, label: str, *, revision: str,
    fingerprint: str, binary_sha256: str,
) -> tuple[int, Decimal, int]:
    if not isinstance(sample, dict):
        raise CalibrationError(f"{label} must be an object")
    if sample.get("tool") != PARENT_TOOL or sample.get("schema_version") != PARENT_SCHEMA_VERSION:
        raise CalibrationError(
            f"{label} must be {PARENT_TOOL} schema {PARENT_SCHEMA_VERSION}"
        )
    validate_identity(sample, prefix=label, revision=revision, fingerprint=fingerprint)
    if require_hex(sample.get("binary_sha256"), HEX64, f"{label}.binary_sha256") != binary_sha256:
        raise CalibrationError(f"{label}.binary_sha256 mismatch")

    exact_context = {
        "mode": EXPECTED_CONTEXT["parent_mode"],
        "eps": EXPECTED_CONTEXT["parent_prehash_epsilon_bits"],
        "nBits": EXPECTED_CONTEXT["assumed_nbits"],
        "matmul_dimension": EXPECTED_CONTEXT["parent_matmul_dimension"],
        "transcript_block_size": EXPECTED_CONTEXT["parent_transcript_block_size"],
        "noise_rank": EXPECTED_CONTEXT["parent_noise_rank"],
        "height": EXPECTED_CONTEXT["parent_height"],
        "parent_mtp": EXPECTED_CONTEXT["parent_mtp"],
    }
    for field, expected in exact_context.items():
        if sample.get(field) != expected:
            raise CalibrationError(f"{label}.{field} does not match campaign context")
    seed = require_int(sample.get("seed"), f"{label}.seed")
    tries = require_int(sample.get("tries"), f"{label}.tries", minimum=1)
    attempts = require_int(
        sample.get("attempts_done"), f"{label}.attempts_done", minimum=1
    )
    if attempts != tries:
        raise CalibrationError(f"{label} must complete every requested attempt")
    if sample.get("solved") is not False:
        raise CalibrationError(f"{label}.solved must be false")
    if (sample.get("solve_runtime_attempts") != 1 or
            sample.get("solve_runtime_solved_attempts") != 0 or
            sample.get("solve_runtime_failed_attempts") != 1):
        raise CalibrationError(f"{label} has incomplete solve-runtime accounting")
    wall = as_decimal(sample.get("wall_s"), f"{label}.wall_s")
    reported_rate = as_decimal(sample.get("attempts_per_s"), f"{label}.attempts_per_s")
    measured_rate = Decimal(attempts) / wall
    if abs(reported_rate - measured_rate) / measured_rate > Decimal("0.00000001"):
        raise CalibrationError(f"{label}.attempts_per_s does not match raw attempts/wall")

    if (sample.get("requested_backend") != provider or
            sample.get("active_backend") != provider):
        raise CalibrationError(f"{label} did not select {provider}")
    require_nonempty_string(
        sample.get("backend_selection_reason"), f"{label}.backend_selection_reason"
    )
    if (sample.get("required_backend_enabled") is not True or
            sample.get("required_backend_satisfied") is not True):
        raise CalibrationError(f"{label} was not fail-closed")

    digest_requests = require_int(
        sample.get("digest_requests"), f"{label}.digest_requests", minimum=1
    )
    require_zero(sample, (
        "requested_cpu", "requested_unknown", "metal_digest_mismatches",
        "metal_fallbacks_to_cpu", "cuda_fallbacks_to_cpu", "cpu_fallbacks",
        "gpu_input_generation_failures",
    ), label)
    other = "metal" if provider == "cuda" else "cuda"
    if sample.get(f"requested_{provider}") != digest_requests:
        raise CalibrationError(f"{label}.requested_{provider} must equal digest_requests")
    if sample.get(f"{provider}_successes") != digest_requests:
        raise CalibrationError(f"{label}.{provider}_successes must equal digest_requests")
    if sample.get(f"requested_{other}") != 0 or sample.get(f"{other}_successes") != 0:
        raise CalibrationError(f"{label} contains requests for the other provider")
    for field in (
        "last_metal_fallback_error", "last_cuda_fallback_error",
        "last_gpu_input_error",
    ):
        if sample.get(field) != "":
            raise CalibrationError(f"{label}.{field} must be empty")
    gpu_attempts = require_int(
        sample.get("gpu_input_generation_attempts"),
        f"{label}.gpu_input_generation_attempts",
    )
    gpu_successes = require_int(
        sample.get("gpu_input_generation_successes"),
        f"{label}.gpu_input_generation_successes",
    )
    if gpu_successes != gpu_attempts:
        raise CalibrationError(f"{label} has incomplete GPU-input accounting")
    return attempts, wall, seed


def validate_rc_artifact(
    sample: Any, provider: str, architecture: str, label: str, *,
    revision: str, fingerprint: str, harness_sha256: str,
) -> list[tuple[int, Decimal]]:
    if not isinstance(sample, dict):
        raise CalibrationError(f"{label} must be an object")
    if sample.get("tool") != RC_TOOL or sample.get("schema_version") != RC_SCHEMA_VERSION:
        raise CalibrationError(f"{label} must be {RC_TOOL} schema {RC_SCHEMA_VERSION}")
    validate_identity(sample, prefix=label, revision=revision, fingerprint=fingerprint)
    if require_hex(sample.get("harness_sha256"), HEX64, f"{label}.harness_sha256") != harness_sha256:
        raise CalibrationError(f"{label}.harness_sha256 mismatch")
    if sample.get("backend_requested") != provider:
        raise CalibrationError(f"{label}.backend_requested is not {provider}")
    resolved = sample.get("backend")
    if not isinstance(resolved, str) or not resolved.startswith(PROVIDER_PREFIXES[provider]):
        raise CalibrationError(f"{label}.backend is not a {provider} provider")
    identity = sample.get("production_provider_identity")
    if not isinstance(identity, dict):
        raise CalibrationError(f"{label}.production_provider_identity is missing")
    if (identity.get("provider_family") != provider or
            identity.get("device_architecture") != architecture or
            identity.get("complete") is not True):
        raise CalibrationError(f"{label}.production_provider_identity mismatch")
    for field in ("driver_identity", "runtime_identity", "reason"):
        require_nonempty_string(identity.get(field), f"{label}.production_provider_identity.{field}")

    exact_context = {
        "profile": "episode",
        "toy": False,
        "medium": False,
        "production_dims": True,
        "episode_profile": EXPECTED_CONTEXT["rc_profile"],
        "header_matmul_dim": EXPECTED_CONTEXT["rc_matmul_dimension"],
        "rounds_override": 0,
        "evidence_kind": "production_chrono_measured",
    }
    for field, expected in exact_context.items():
        if sample.get(field) != expected:
            raise CalibrationError(f"{label}.{field} does not match Profile 1 production")
    if sample.get("params") != EXPECTED_RC_PARAMS:
        raise CalibrationError(f"{label}.params does not match frozen Profile 1")

    variance = sample.get("run_variance")
    headers = sample.get("frozen_headers")
    if not isinstance(variance, dict) or not isinstance(headers, list):
        raise CalibrationError(f"{label} is missing run_variance/frozen_headers")
    count = require_int(variance.get("n_runs"), f"{label}.run_variance.n_runs", minimum=1)
    walls = variance.get("episode_wall_samples_s")
    if not isinstance(walls, list) or len(walls) != count or len(headers) != count:
        raise CalibrationError(f"{label} run/header counts do not match n_runs")

    acceleration = sample.get("exact_replay_acceleration")
    if not isinstance(acceleration, dict):
        raise CalibrationError(f"{label}.exact_replay_acceleration is missing")
    if acceleration.get("provider") != resolved:
        raise CalibrationError(f"{label} resolved-provider fields disagree")
    require_nonempty_string(
        acceleration.get("resolution_reason"), f"{label}.acceleration.resolution_reason"
    )
    for field in (
        "device_backend_present", "require_device", "fully_accelerated",
        "all_consensus_macs_on_device",
    ):
        if acceleration.get(field) is not True:
            raise CalibrationError(f"{label}.acceleration.{field} must be true")
    expected_total_macs = CANONICAL_RC_EPISODE_MACS * count
    if (acceleration.get("expected_macs") != expected_total_macs or
            acceleration.get("device_macs") != expected_total_macs):
        raise CalibrationError(f"{label} does not report canonical TotalRCEpisodeMacs")
    require_int(
        acceleration.get("device_calls"), f"{label}.acceleration.device_calls", minimum=1
    )
    require_zero(acceleration, ("cpu_calls", "cpu_macs", "cpu_fallbacks"),
                 f"{label}.acceleration")
    if acceleration.get("first_failure") not in (None, ""):
        raise CalibrationError(f"{label}.acceleration.first_failure must be empty")

    result: list[tuple[int, Decimal]] = []
    for index, (header, wall_value) in enumerate(zip(headers, walls)):
        header_label = f"{label}.frozen_headers[{index}]"
        if not isinstance(header, dict):
            raise CalibrationError(f"{header_label} must be an object")
        nonce = require_int(header.get("header_nonce"), f"{header_label}.header_nonce")
        wall = as_decimal(wall_value, f"{label}.run_variance.episode_wall_samples_s[{index}]")
        header_wall = as_decimal(header.get("wall_s"), f"{header_label}.wall_s")
        if abs(wall - header_wall) > Decimal("0.000000001"):
            raise CalibrationError(f"{header_label}.wall_s does not match run_variance")
        if (header.get("header_family") != "production_canary" or
                header.get("matmul_dim") != 4096 or
                header.get("require_device") is not True or
                header.get("fully_accelerated") is not True or
                header.get("device_macs") != CANONICAL_RC_EPISODE_MACS):
            raise CalibrationError(f"{header_label} is not strict production Profile 1")
        require_zero(header, ("cpu_calls", "cpu_macs", "cpu_fallbacks"), header_label)
        if header.get("first_failure") not in (None, ""):
            raise CalibrationError(f"{header_label}.first_failure must be empty")
        require_hex(header.get("exact_replay_digest"), HEX64,
                    f"{header_label}.exact_replay_digest")
        result.append((nonce, wall))
    return result


def derive(
    payload: dict[str, Any], *, expected_revision: str,
    expected_fingerprint: str, input_file_sha256: str | None = None,
) -> dict[str, Any]:
    revision = require_hex(expected_revision, HEX40, "expected_revision")
    fingerprint = require_hex(expected_fingerprint, HEX64, "expected_fingerprint")
    if payload.get("schema_version") != ROOT_SCHEMA_VERSION or payload.get("tool") != ROOT_TOOL:
        raise CalibrationError(
            f"expected {ROOT_TOOL} schema_version={ROOT_SCHEMA_VERSION} evidence"
        )
    validate_identity(payload, prefix="root", revision=revision, fingerprint=fingerprint)
    if payload.get("consensus_context") != EXPECTED_CONTEXT:
        raise CalibrationError("consensus_context does not match the frozen Epoch-A campaign")
    coefficient_policy = validate_coefficient_policy(payload.get("coefficient_policy"))

    rigs = payload.get("rigs")
    if not isinstance(rigs, list) or not rigs:
        raise CalibrationError("rigs must be a non-empty array")

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    seed_sets: dict[str, tuple[int, ...]] = {}
    nonce_sets: dict[str, tuple[int, ...]] = {}
    digest_maps: dict[str, tuple[tuple[int, str], ...]] = {}
    for index, rig in enumerate(rigs):
        if not isinstance(rig, dict):
            raise CalibrationError(f"rigs[{index}] must be an object")
        provider = rig.get("provider_family")
        if provider not in REQUIRED_PROVIDERS:
            raise CalibrationError(f"rigs[{index}].provider_family is unsupported")
        if provider in seen:
            raise CalibrationError(f"duplicate required provider: {provider}")
        seen.add(provider)
        label = f"rigs[{index}]({provider})"
        validate_identity(rig, prefix=label, revision=revision, fingerprint=fingerprint)

        architecture = rig.get("device_architecture")
        if not isinstance(architecture, str) or SAFE_TOKEN.fullmatch(architecture) is None:
            raise CalibrationError(f"{label}.device_architecture is invalid")
        parent_binary_sha256 = require_hex(
            rig.get("parent_binary_sha256"), HEX64, f"{label}.parent_binary_sha256"
        )
        harness_sha256 = require_hex(
            rig.get("rc_harness_sha256"), HEX64, f"{label}.rc_harness_sha256"
        )

        parent_samples = rig.get("mixed_mode_samples")
        if not isinstance(parent_samples, list) or len(parent_samples) < 5:
            raise CalibrationError(f"{label}.mixed_mode_samples needs at least five runs")
        total_tries = 0
        total_parent_wall = Decimal(0)
        parent_rates: list[Decimal] = []
        seeds: list[int] = []
        for sample_index, sample in enumerate(parent_samples):
            attempts, wall, seed = validate_parent_sample(
                sample, provider, f"{label}.mixed_mode_samples[{sample_index}]",
                revision=revision, fingerprint=fingerprint,
                binary_sha256=parent_binary_sha256,
            )
            total_tries += attempts
            total_parent_wall += wall
            parent_rates.append(Decimal(attempts) / wall)
            seeds.append(seed)
        if len(set(seeds)) != len(seeds):
            raise CalibrationError(f"{label}.mixed_mode_samples contains duplicate seeds")
        seed_sets[provider] = tuple(sorted(seeds))

        rc_artifacts = rig.get("rc_episode_samples")
        if not isinstance(rc_artifacts, list) or not rc_artifacts:
            raise CalibrationError(f"{label}.rc_episode_samples must be a non-empty array")
        rc_runs: list[tuple[int, Decimal]] = []
        for sample_index, sample in enumerate(rc_artifacts):
            rc_runs.extend(validate_rc_artifact(
                sample, provider, architecture,
                f"{label}.rc_episode_samples[{sample_index}]",
                revision=revision, fingerprint=fingerprint,
                harness_sha256=harness_sha256,
            ))
        if len(rc_runs) < 3:
            raise CalibrationError(f"{label} needs at least three RC episode runs")
        nonces = [nonce for nonce, _ in rc_runs]
        if len(set(nonces)) != len(nonces):
            raise CalibrationError(f"{label}.rc_episode_samples contains duplicate nonces")
        nonce_sets[provider] = tuple(sorted(nonces))
        digest_maps[provider] = tuple(sorted(
            (
                require_int(
                    header.get("header_nonce"),
                    f"{label}.rc_episode_samples[{sample_index}].header_nonce",
                ),
                require_hex(
                    header.get("exact_replay_digest"), HEX64,
                    f"{label}.rc_episode_samples[{sample_index}].exact_replay_digest",
                ),
            )
            for sample_index, sample in enumerate(rc_artifacts)
            for header in sample["frozen_headers"]
        ))

        total_rc_wall = sum((wall for _, wall in rc_runs), Decimal(0))
        rc_mean_wall = total_rc_wall / Decimal(len(rc_runs))
        parent_attempts_per_s = Decimal(total_tries) / total_parent_wall
        coefficient_point_estimate = parent_attempts_per_s * rc_mean_wall
        max_parent_attempts_per_s = max(parent_rates)
        max_rc_wall_s = max(wall for _, wall in rc_runs)
        observed_upper_envelope = max_parent_attempts_per_s * max_rc_wall_s
        margin_adjusted = observed_upper_envelope * (
            Decimal(10_000 + coefficient_policy["safety_margin_bps"])
            / Decimal(10_000)
        )
        quantum = int(coefficient_policy["coefficient_quantum"])
        coefficient = (
            int(
                (margin_adjusted / Decimal(quantum)).to_integral_value(
                    rounding=ROUND_CEILING
                )
            )
            * quantum
        )
        if coefficient <= 0 or coefficient > UINT64_MAX:
            raise CalibrationError(f"{provider}: coefficient is outside uint64 range")
        results.append({
            "provider_family": provider,
            "device_architecture": architecture,
            "parent_binary_sha256": parent_binary_sha256,
            "rc_harness_sha256": harness_sha256,
            "parent_sample_count": len(parent_samples),
            "rc_sample_count": len(rc_runs),
            "parent_seeds": sorted(seeds),
            "rc_episode_nonces": sorted(nonces),
            "total_parent_attempts": total_tries,
            "total_parent_wall_s": str(total_parent_wall),
            "parent_attempts_per_s": str(parent_attempts_per_s),
            "total_rc_wall_s": str(total_rc_wall),
            "rc_mean_wall_s": str(rc_mean_wall),
            "coefficient_point_estimate": str(coefficient_point_estimate),
            "max_parent_attempts_per_s": str(max_parent_attempts_per_s),
            "max_rc_wall_s": str(max_rc_wall_s),
            "observed_upper_envelope": str(observed_upper_envelope),
            "margin_adjusted_upper_envelope": str(margin_adjusted),
            "coefficient_quantized_up": coefficient,
            "quantization_slack": str(Decimal(coefficient) - margin_adjusted),
        })

    missing = sorted(set(REQUIRED_PROVIDERS) - seen)
    if missing:
        raise CalibrationError(f"missing required providers: {', '.join(missing)}")
    if len(set(seed_sets.values())) != 1:
        raise CalibrationError("required providers did not measure the same parent seed set")
    if len(set(nonce_sets.values())) != 1:
        raise CalibrationError("required providers did not measure the same RC nonce set")
    if len(set(digest_maps.values())) != 1:
        raise CalibrationError(
            "required providers did not produce byte-identical RC digests"
        )

    selected = max(results, key=lambda item: item["coefficient_quantized_up"])
    file_hash = (require_hex(input_file_sha256, HEX64, "input_file_sha256")
                 if input_file_sha256 is not None else None)
    result = {
        "schema_version": ROOT_SCHEMA_VERSION,
        "coefficient_definition": (
            "C = max observed mixed-mode parent raw nonce rate * max observed "
            "strict Profile-1 RC episode wall time, then an explicit reviewed "
            "margin and upward quantum are applied"
        ),
        "selection_policy": (
            "maximum quantized required-provider envelope; the tool does not "
            "choose or imply a statistical confidence level"
        ),
        "coefficient_policy": coefficient_policy,
        "rounding": "decimal ROUND_CEILING to the reviewed positive quantum",
        "required_provider_families": list(REQUIRED_PROVIDERS),
        "source_revision": revision,
        "source_tree_fingerprint": fingerprint,
        "input_payload_sha256": canonical_payload_sha256(payload),
        "providers": results,
        "selected_provider_family": selected["provider_family"],
        "nMatMulRCAsertRescaleNum": selected["coefficient_quantized_up"],
        "nMatMulRCAsertRescaleDen": 1,
    }
    if file_hash is not None:
        result["input_file_sha256"] = file_hash
    return result


def parse_uint64(text: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", text):
        raise argparse.ArgumentTypeError("must be a canonical uint64 decimal")
    value = int(text)
    if value > UINT64_MAX:
        raise argparse.ArgumentTypeError("must fit uint64")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--source-revision", required=True,
        help="exact 40-character clean commit measured by every binary",
    )
    parser.add_argument("--expected-coefficient", type=parse_uint64)
    args = parser.parse_args()

    try:
        revision = resolve_commit(REPO_ROOT, args.source_revision)
        fingerprint = tree_fingerprint(REPO_ROOT, revision)
        input_bytes = args.input.read_bytes()
        payload = json.loads(input_bytes)
        if not isinstance(payload, dict):
            raise CalibrationError("input JSON root must be an object")
        result = derive(
            payload, expected_revision=revision,
            expected_fingerprint=fingerprint,
            input_file_sha256=sha256_bytes(input_bytes),
        )
        if (args.expected_coefficient is not None and
                result["nMatMulRCAsertRescaleNum"] != args.expected_coefficient):
            raise CalibrationError(
                f"derived coefficient {result['nMatMulRCAsertRescaleNum']} "
                f"does not match expected {args.expected_coefficient}"
            )
    except (OSError, json.JSONDecodeError, CalibrationError) as error:
        parser.error(str(error))

    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
        except OSError as error:
            parser.error(str(error))
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
