#!/usr/bin/env python3
"""Fail-closed binding of Epoch-A source authorization to exact evidence.

This tool does not choose an activation height, coefficient, or latency policy.
It verifies one reviewed policy record against the exact source tree, binaries,
CUDA-only ASERT calibration, CUDA+Metal correctness seal, and a correlated
strict-device CUDA lifecycle campaign.  A missing or stale field is a failure.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


TOOL = "btx_epoch_a_activation_gate"
SCHEMA_VERSION = 2
LIFECYCLE_TOOL = "btx_cuda_complete_lifecycle_campaign"
# Schema 2 is deliberately non-authorizing: it contains independent latest
# component counters, not a solve-RPC-to-receiving-tip record bound to
# one exact block. Schema 3 still timed its nominal contention sample only after
# the competing fork had converged. Schema 4 starts before concurrent sibling
# solve RPCs and carries monotonic checkpoints through reorg convergence and the
# final exact authenticated child. Missing any required keyed record or
# checkpoint makes an attempt incomplete.
LIFECYCLE_SCHEMA_VERSION = 4
INT64_MAX = (1 << 63) - 1
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_EVIDENCE = re.compile(r"doc/evidence/[A-Za-z0-9_./-]+")
EXPECTED_BINARY_KEYS = {
    "asert_parent_calibration",
    "asert_cuda_rc_harness",
    "golden_cuda_rc_harness",
    "golden_metal_rc_harness",
    "lifecycle_btxd",
    "lifecycle_btx_cli",
}
EXPECTED_ARTIFACT_SOURCE_KEYS = {
    "asert",
    "production_goldens",
    "lifecycle",
}
ARTIFACT_BINARY_KEYS = {
    "asert": {"parent_calibration", "cuda_rc_harness"},
    "production_goldens": {"cuda_rc_harness", "metal_rc_harness"},
    "lifecycle": {"btxd", "btx_cli"},
}
ARTIFACT_BINARY_ARGUMENTS = {
    "asert": {
        "parent_calibration": "asert_parent_calibration",
        "cuda_rc_harness": "asert_cuda_rc_harness",
    },
    "production_goldens": {
        "cuda_rc_harness": "golden_cuda_rc_harness",
        "metal_rc_harness": "golden_metal_rc_harness",
    },
    "lifecycle": {
        "btxd": "lifecycle_btxd",
        "btx_cli": "lifecycle_btx_cli",
    },
}
EXPECTED_EVIDENCE_KEYS = {
    "asert_root",
    "asert_derived",
    "golden_compare",
    "lifecycle",
}
EXPECTED_RATIFICATION_KEYS = {
    "BTX_MATMUL_NO_INVERSION_GATE_RATIFIED",
    "BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED",
}


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"{path}: unreadable JSON ({error})") from error
    require(isinstance(value, dict), f"{path}: JSON root must be an object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise GateError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def exact_hex(value: Any, pattern: re.Pattern[str], field: str) -> str:
    require(
        isinstance(value, str) and pattern.fullmatch(value) is not None,
        f"{field} must be canonical lowercase hex",
    )
    return value


def exact_int(value: Any, field: str, *, minimum: int = 0,
              maximum: int = INT64_MAX) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool)
        and minimum <= value <= maximum,
        f"{field} must be an integer in [{minimum}, {maximum}]",
    )
    return value


def exact_number(value: Any, field: str) -> float:
    require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{field} must be numeric",
    )
    result = float(value)
    require(math.isfinite(result) and result >= 0, f"{field} must be finite and non-negative")
    return result


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        raise GateError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def implementation_fingerprint(root: Path, revision: str) -> str:
    """Hash frozen executable source while normalizing release authorization.

    Evidence is measured before the final height/coefficient/ratification commit.
    Only the literal values of those five reviewed constants are normalized;
    every other byte in build-relevant source remains authoritative. The
    production golden manifest stays excluded for the same A -> B chronology
    reason as the ordinary source-tree fingerprint.
    """
    require(
        git(root, "rev-parse", "--verify", f"{revision}^{{commit}}") == revision,
        "implementation fingerprint revision does not resolve exactly",
    )
    tree = subprocess.run(
        [
            "git", "-C", str(root), "ls-tree", "-r", "--full-tree",
            revision, "--", "CMakeLists.txt", "cmake", "src",
            "contrib/matmul-v4",
        ],
        capture_output=True,
        check=False,
    )
    require(tree.returncode == 0 and tree.stdout,
            "cannot enumerate implementation fingerprint source")
    excluded = {
        b"src/matmul/matmul_v4_rc_production_golden_manifest.data",
    }
    normalization_rules: dict[bytes, tuple[tuple[bytes, bytes], ...]] = {
        b"src/kernel/chainparams.cpp": (
            (
                rb"(?:\[\[maybe_unused\]\] )?static constexpr int64_t "
                rb"kRCEpochAAsertRescaleNum\{[0-9][0-9']*\};",
                b"static constexpr int64_t kRCEpochAAsertRescaleNum{<AUTHORIZED>};",
            ),
            (
                rb"(?:\[\[maybe_unused\]\] )?static constexpr int64_t "
                rb"kRCEpochAAsertRescaleDen\{[0-9][0-9']*\};",
                b"static constexpr int64_t kRCEpochAAsertRescaleDen{<AUTHORIZED>};",
            ),
            (
                rb"(?:\[\[maybe_unused\]\] )?static constexpr int32_t "
                rb"BTX_MATMUL_V47_EPOCH_A_HEIGHT\{\s*"
                rb"(?:[0-9][0-9']*|std::numeric_limits<int32_t>::max\(\))"
                rb"\s*\};",
                b"static constexpr int32_t BTX_MATMUL_V47_EPOCH_A_HEIGHT{<AUTHORIZED>};",
            ),
        ),
        b"src/consensus/params.h": (
            (
                rb"static constexpr bool BTX_MATMUL_NO_INVERSION_GATE_RATIFIED\{(?:true|false)\};",
                b"static constexpr bool BTX_MATMUL_NO_INVERSION_GATE_RATIFIED{<AUTHORIZED>};",
            ),
            (
                rb"static constexpr bool BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED\{(?:true|false)\};",
                b"static constexpr bool BTX_MATMUL_V47_GPU_LIFECYCLE_GATE_RATIFIED{<AUTHORIZED>};",
            ),
        ),
    }
    normalized_entries: list[bytes] = []
    for line in tree.stdout.splitlines():
        metadata, separator, path = line.partition(b"\t")
        require(separator == b"\t", "malformed git tree entry")
        if path in excluded:
            continue
        if path in normalization_rules:
            content = subprocess.run(
                ["git", "-C", str(root), "show", f"{revision}:{path.decode()}"],
                capture_output=True,
                check=False,
            )
            require(content.returncode == 0,
                    f"cannot read authorization source {path.decode()}")
            normalized = content.stdout
            for pattern, replacement in normalization_rules[path]:
                normalized, count = re.subn(pattern, replacement, normalized)
                require(
                    count == 1,
                    f"authorization source {path.decode()} is not canonical",
                )
            fields = metadata.split()
            require(len(fields) == 3, "malformed git tree metadata")
            fields[2] = hashlib.sha256(normalized).hexdigest().encode()
            metadata = b" ".join(fields)
        normalized_entries.append(metadata + b"\t" + path + b"\n")
    return hashlib.sha256(b"".join(normalized_entries)).hexdigest()


def import_tool(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses and similar module-aware decorators consult sys.modules while
    # the module body executes. Register first, mirroring normal import
    # semantics; otherwise importing the golden verifier's dataclasses fails.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def require_clean_relevant_worktree(root: Path) -> None:
    """Reject worktree code that is not represented by the reviewed commit.

    The source fingerprint is computed from committed Git trees.  The gate also
    imports helpers and reads consensus source from the worktree, so allowing a
    staged, unstaged, or untracked relevant file would mix two source
    identities.  Include the production manifest even though it is excluded
    from the executable-source fingerprint because the golden verifier reads it
    directly from the worktree.
    """
    relevant = ("CMakeLists.txt", "cmake", "src", "contrib/matmul-v4")
    status = git(
        root, "status", "--porcelain=v1", "--untracked-files=all", "--",
        *relevant,
    )
    require(
        status == "",
        "build-relevant source, gate helpers, or production manifest is dirty",
    )


def validate_source_identity(root: Path, policy: dict[str, Any]) -> tuple[str, str]:
    # This must run before importing evidence_source_identity.py below.
    require_clean_relevant_worktree(root)
    revision = exact_hex(policy.get("source_revision"), HEX40, "source_revision")
    fingerprint = exact_hex(
        policy.get("source_tree_fingerprint"), HEX64, "source_tree_fingerprint"
    )
    require(git(root, "rev-parse", "--verify", f"{revision}^{{commit}}") == revision,
            "source_revision does not resolve to the exact commit")
    head = git(root, "rev-parse", "HEAD")
    subprocess_result = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", revision, head],
        capture_output=True, check=False,
    )
    require(subprocess_result.returncode == 0, "source_revision is not an ancestor of gate HEAD")

    identity = import_tool(
        root / "contrib/matmul-v4/evidence_source_identity.py",
        "epoch_a_gate_source_identity",
    )
    try:
        measured = identity.tree_fingerprint(root, revision)
        current = identity.tree_fingerprint(root, head)
    except Exception as error:
        raise GateError(str(error)) from error
    require(measured == fingerprint, "source_tree_fingerprint does not match source_revision")
    require(current == fingerprint, "build-relevant source changed after evidence freeze")
    return revision, fingerprint


def validate_implementation_identity(
    root: Path, policy: dict[str, Any], release_revision: str,
) -> str:
    expected = exact_hex(
        policy.get("implementation_fingerprint"), HEX64,
        "implementation_fingerprint",
    )
    require(
        implementation_fingerprint(root, release_revision) == expected,
        "implementation_fingerprint does not match release source",
    )
    return expected


def _require_ancestor(root: Path, ancestor: str, descendant: str, label: str) -> None:
    result = subprocess.run(
        [
            "git", "-C", str(root), "merge-base", "--is-ancestor",
            ancestor, descendant,
        ],
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0, f"{label} is not on the reviewed chronology")


def validate_artifact_sources(
    root: Path, policy: dict[str, Any], release_revision: str,
    release_implementation_fingerprint: str,
) -> tuple[dict[str, tuple[str, str]], dict[str, dict[str, str]]]:
    """Validate an honest evidence chronology without allowing stale code.

    Goldens and ASERT measurements necessarily predate the commit that seals
    their evidence into the production manifest; lifecycle measurement then
    uses the manifest-bearing daemon. Each role therefore names its own exact
    commit and binaries. Each role's full fingerprint must match its exact
    commit. Separately, every role must reproduce the release's
    authorization-normalized implementation fingerprint and be a reachable
    ancestor in the A -> B -> C chronology. This permits evidence, manifest,
    and final height/coefficient/ratification commits while rejecting every
    other executable-source change.
    """
    raw_sources = policy.get("artifact_sources")
    require(
        isinstance(raw_sources, dict)
        and set(raw_sources) == EXPECTED_ARTIFACT_SOURCE_KEYS,
        "artifact_sources must bind ASERT, production goldens, and lifecycle",
    )
    identity = import_tool(
        root / "contrib/matmul-v4/evidence_source_identity.py",
        "epoch_a_gate_artifact_source_identity",
    )
    sources: dict[str, tuple[str, str]] = {}
    expected_binaries: dict[str, dict[str, str]] = {}
    for role in sorted(EXPECTED_ARTIFACT_SOURCE_KEYS):
        source = raw_sources.get(role)
        require(
            isinstance(source, dict)
            and set(source) == {
                "source_revision", "source_tree_fingerprint", "binary_sha256",
            },
            f"artifact_sources.{role} schema mismatch",
        )
        revision = exact_hex(
            source.get("source_revision"), HEX40,
            f"artifact_sources.{role}.source_revision",
        )
        fingerprint = exact_hex(
            source.get("source_tree_fingerprint"), HEX64,
            f"artifact_sources.{role}.source_tree_fingerprint",
        )
        require(
            git(root, "rev-parse", "--verify", f"{revision}^{{commit}}")
            == revision,
            f"artifact_sources.{role} revision does not resolve exactly",
        )
        _require_ancestor(
            root, revision, release_revision,
            f"artifact_sources.{role}.source_revision",
        )
        try:
            measured = identity.tree_fingerprint(root, revision)
        except Exception as error:
            raise GateError(str(error)) from error
        require(
            measured == fingerprint,
            f"artifact_sources.{role} fingerprint does not match its revision",
        )
        require(
            implementation_fingerprint(root, revision)
            == release_implementation_fingerprint,
            f"artifact_sources.{role} implementation differs from release",
        )
        raw_binaries = source.get("binary_sha256")
        require(
            isinstance(raw_binaries, dict)
            and set(raw_binaries) == ARTIFACT_BINARY_KEYS[role],
            f"artifact_sources.{role}.binary_sha256 schema mismatch",
        )
        role_binaries: dict[str, str] = {}
        for name in sorted(ARTIFACT_BINARY_KEYS[role]):
            digest = exact_hex(
                raw_binaries.get(name), HEX64,
                f"artifact_sources.{role}.binary_sha256.{name}",
            )
            role_binaries[name] = digest
        expected_binaries[role] = role_binaries
        sources[role] = (revision, fingerprint)

    for role in ("asert", "production_goldens"):
        _require_ancestor(
            root, sources[role][0], sources["lifecycle"][0],
            f"artifact_sources.{role} before lifecycle",
        )
    _require_ancestor(
        root, sources["lifecycle"][0], release_revision,
        "artifact_sources.lifecycle before release",
    )
    return sources, expected_binaries


def parse_cpp_integer(text: str, name: str) -> int:
    match = re.search(
        rf"\b{name}\s*\{{\s*([0-9][0-9']*)\s*\}}\s*;", text
    )
    require(match is not None, f"cannot parse source constant {name}")
    return int(match.group(1).replace("'", ""))


def parse_cpp_bool(text: str, name: str) -> bool:
    match = re.search(rf"\b{name}\s*\{{\s*(true|false)\s*\}}\s*;", text)
    require(match is not None, f"cannot parse source flag {name}")
    return match.group(1) == "true"


def strip_cpp_comments(text: str) -> str:
    """Remove comments before matching consensus assignments.

    This is intentionally small rather than a C++ parser: the activation tuple
    uses simple assignments and integer constants.  Removing both comment forms
    prevents commented examples from satisfying the gate.
    """
    without_blocks = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", without_blocks)


def mainnet_chainparams_scope(text: str) -> str:
    clean = strip_cpp_comments(text)
    start = re.search(r"\bclass\s+CMainParams\b", clean)
    end = re.search(r"\bclass\s+CTestNetParams\b", clean)
    require(start is not None and end is not None and start.start() < end.start(),
            "cannot isolate CMainParams source scope")
    return clean[start.start():end.start()]


def validate_source_tuple(root: Path, policy: dict[str, Any]) -> None:
    tuple_policy = policy.get("activation_tuple")
    require(isinstance(tuple_policy, dict), "activation_tuple must be an object")
    require(
        set(tuple_policy) == {
            "height", "nMatMulRCAsertRescaleNum", "nMatMulRCAsertRescaleDen"
        },
        "activation_tuple has unexpected fields",
    )
    height = exact_int(tuple_policy.get("height"), "activation_tuple.height", minimum=1,
                       maximum=(1 << 31) - 2)
    coefficient = exact_int(
        tuple_policy.get("nMatMulRCAsertRescaleNum"),
        "activation_tuple.nMatMulRCAsertRescaleNum", minimum=1,
    )
    denominator = exact_int(
        tuple_policy.get("nMatMulRCAsertRescaleDen"),
        "activation_tuple.nMatMulRCAsertRescaleDen", minimum=1,
    )
    chainparams = (root / "src/kernel/chainparams.cpp").read_text(encoding="utf-8")
    clean_chainparams = strip_cpp_comments(chainparams)
    mainnet = mainnet_chainparams_scope(chainparams)
    params = strip_cpp_comments(
        (root / "src/consensus/params.h").read_text(encoding="utf-8")
    )
    require(
        parse_cpp_integer(clean_chainparams, "BTX_MATMUL_V47_EPOCH_A_HEIGHT") == height,
        "policy activation height does not match source",
    )
    require(
        parse_cpp_integer(clean_chainparams, "kRCEpochAAsertRescaleNum") == coefficient,
        "policy ASERT numerator does not match source",
    )
    require(
        parse_cpp_integer(clean_chainparams, "kRCEpochAAsertRescaleDen") == denominator,
        "policy ASERT denominator does not match source",
    )
    for field in ("nMatMulV4Height", "nMatMulBMX4CHeight", "nMatMulRCHeight"):
        require(
            re.search(
                rf"consensus\.{field}\s*=\s*BTX_MATMUL_V47_EPOCH_A_HEIGHT\s*;",
                mainnet,
            ) is not None,
            f"mainnet {field} is not bound to the atomic Epoch-A height",
        )
    require(
        re.search(
            r"consensus\.nMatMulRCAsertRescaleNum\s*=\s*"
            r"kRCEpochAAsertRescaleNum\s*;",
            mainnet,
        ) is not None,
        "mainnet ASERT numerator is not bound to the reviewed source constant",
    )
    require(
        re.search(
            r"consensus\.nMatMulRCAsertRescaleDen\s*=\s*"
            r"kRCEpochAAsertRescaleDen\s*;",
            mainnet,
        ) is not None,
        "mainnet ASERT denominator is not bound to the reviewed source constant",
    )

    ratification = policy.get("ratification")
    require(isinstance(ratification, dict), "ratification must be an object")
    require(set(ratification) == EXPECTED_RATIFICATION_KEYS,
            "ratification must name both source flags exactly")
    for name in sorted(EXPECTED_RATIFICATION_KEYS):
        require(ratification.get(name) is True, f"policy {name} must be true")
        require(parse_cpp_bool(params, name) is True, f"source {name} must be true")


def resolve_evidence(root: Path, entry: Any, field: str) -> Path:
    require(isinstance(entry, dict) and set(entry) == {"path", "sha256"},
            f"evidence.{field} must contain exactly path and sha256")
    relative = entry.get("path")
    require(
        isinstance(relative, str) and SAFE_EVIDENCE.fullmatch(relative) is not None
        and ".." not in Path(relative).parts,
        f"evidence.{field}.path is unsafe",
    )
    expected = exact_hex(entry.get("sha256"), HEX64, f"evidence.{field}.sha256")
    path = root / relative
    require(path.is_file() and not path.is_symlink(), f"evidence.{field} is not a regular file")
    require(sha256_file(path) == expected, f"evidence.{field} SHA256 mismatch")
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", relative],
        capture_output=True, check=False,
    )
    require(tracked.returncode == 0, f"evidence.{field} is not tracked")
    status = git(root, "status", "--porcelain", "--", relative)
    require(status == "", f"evidence.{field} is untracked or modified")
    return path


def validate_binaries(
    expected: dict[str, dict[str, str]], binaries: dict[str, Path],
) -> dict[str, dict[str, str]]:
    require(set(expected) == EXPECTED_ARTIFACT_SOURCE_KEYS,
            "artifact sources must bind every evidence role exactly")
    require(set(binaries) == EXPECTED_BINARY_KEYS, "all exact binary paths are required")
    result: dict[str, dict[str, str]] = {}
    for role in sorted(EXPECTED_ARTIFACT_SOURCE_KEYS):
        require(
            set(expected[role]) == ARTIFACT_BINARY_KEYS[role],
            f"artifact_sources.{role} does not bind its exact binaries",
        )
        role_result: dict[str, str] = {}
        for name in sorted(ARTIFACT_BINARY_KEYS[role]):
            argument_name = ARTIFACT_BINARY_ARGUMENTS[role][name]
            expected_hash = exact_hex(
                expected[role].get(name), HEX64,
                f"artifact_sources.{role}.binary_sha256.{name}",
            )
            path = binaries[argument_name]
            require(
                path.is_file() and not path.is_symlink(),
                f"{argument_name} is not a regular binary",
            )
            actual = sha256_file(path)
            require(
                actual == expected_hash,
                f"{argument_name} binary SHA256 mismatch",
            )
            role_result[name] = actual
        result[role] = role_result
    return result


def validate_provider_policy(policy: dict[str, Any]) -> None:
    providers = policy.get("provider_policy")
    require(isinstance(providers, dict), "provider_policy must be an object")
    require(
        set(providers) == {"asert_calibration", "production_goldens", "lifecycle"},
        "provider_policy has unexpected fields",
    )
    require(providers.get("asert_calibration") == ["cuda"],
            "ASERT launch-cohort policy must be CUDA-only")
    require(providers.get("production_goldens") == ["cuda", "metal"],
            "correctness-golden cohort must be CUDA+Metal")
    require(providers.get("lifecycle") == ["cuda"],
            "lifecycle launch-cohort policy must be CUDA")


def validate_asert(
    root: Path, root_path: Path, derived_path: Path, policy: dict[str, Any],
    revision: str, fingerprint: str, binaries: dict[str, str],
) -> None:
    deriver = import_tool(
        root / "contrib/matmul-v4/derive-epoch-a-asert.py",
        "epoch_a_gate_deriver",
    )
    raw = load_json(root_path)
    derived = load_json(derived_path)
    try:
        reproduced = deriver.derive(
            raw, expected_revision=revision, expected_fingerprint=fingerprint,
            input_file_sha256=sha256_file(root_path),
        )
    except Exception as error:
        raise GateError(f"ASERT evidence rejected: {error}") from error
    require(reproduced == derived, "ASERT derived artifact is not an exact re-derivation")
    require(derived.get("required_provider_families") == ["cuda"],
            "ASERT evidence is not the CUDA-only calibration cohort")
    activation = policy["activation_tuple"]
    require(
        derived.get("nMatMulRCAsertRescaleNum")
        == activation["nMatMulRCAsertRescaleNum"],
        "ASERT evidence does not derive the installed policy coefficient",
    )
    require(
        derived.get("nMatMulRCAsertRescaleDen")
        == activation["nMatMulRCAsertRescaleDen"],
        "ASERT evidence denominator does not match source",
    )
    providers = derived.get("providers")
    require(isinstance(providers, list) and len(providers) == 1,
            "ASERT derived artifact must contain exactly one CUDA provider")
    cuda = providers[0]
    require(cuda.get("provider_family") == "cuda", "ASERT provider must be CUDA")
    require(cuda.get("parent_binary_sha256") == binaries["parent_calibration"],
            "ASERT parent calibration binary is not the reviewed binary")
    require(cuda.get("rc_harness_sha256") == binaries["cuda_rc_harness"],
            "ASERT CUDA harness is not the reviewed binary")


def validate_golden(
    root: Path, comparison_path: Path, revision: str, fingerprint: str,
    binaries: dict[str, str],
) -> None:
    comparison = load_json(comparison_path)
    for field, expected in (
        ("evidence_kind", "multi_gpu_profile1_exactreplay_golden_compare"),
        ("schema_version", 2),
        ("tip_sha", revision),
        ("source_tree_fingerprint", fingerprint),
        ("required_for_manifest", ["cuda", "metal"]),
        ("complete_multi_gpu_match", True),
        ("cuda_metal_match", True),
        ("allow_partial", False),
        ("mismatches", []),
        ("coverage_failures", []),
    ):
        require(comparison.get(field) == expected, f"golden comparison {field} mismatch")
    require(set(comparison.get("backends_succeeded", [])) == {"cuda", "metal"},
            "golden comparison lacks the CUDA+Metal cohort")
    summaries = comparison.get("by_backend")
    require(isinstance(summaries, dict), "golden comparison missing by_backend")
    require(summaries.get("cuda", {}).get("harness_sha256") == binaries["cuda_rc_harness"],
            "golden CUDA harness is not the reviewed binary")
    require(summaries.get("metal", {}).get("harness_sha256") == binaries["metal_rc_harness"],
            "golden Metal harness is not the reviewed binary")

    verifier = import_tool(
        root / "contrib/matmul-v4/verify-production-golden-seal.py",
        "epoch_a_gate_golden_seal",
    )
    entries = verifier.parse_manifest(root / verifier.MANIFEST_RELATIVE)
    require(entries, "production golden manifest is empty")
    expected_comparison = (
        root / entries[0].evidence_path / "multi-gpu-digest-compare.json"
    ).resolve()
    require(
        comparison_path.resolve() == expected_comparison,
        "policy golden comparison is not the corpus named by the manifest",
    )
    try:
        result = verifier.seal_command(
            argparse.Namespace(root=root, manifest=verifier.MANIFEST_RELATIVE)
        )
    except Exception as error:
        raise GateError(f"production golden seal rejected: {error}") from error
    require(result == 0, "production golden seal did not pass")


def _validate_runtime_node(
    node: Any, label: str, revision: str, fingerprint: str,
    regtest_height: int, *, require_validation: bool,
) -> None:
    require(isinstance(node, dict), f"runtime_builds.{label} must be an object")
    provider = node.get("resolved_provider")
    require(isinstance(provider, str) and provider.startswith("cuda_"),
            f"runtime_builds.{label} did not resolve CUDA")
    canary = node.get("production_canary")
    require(isinstance(canary, dict), f"runtime_builds.{label} missing canary")
    for field in (
        "attempted", "passed", "manifest_has_reviewed_goldens",
        "build_provenance_matches", "exact_manifest_match",
    ):
        require(canary.get(field) is True, f"runtime_builds.{label}.canary.{field} must be true")
    require(canary.get("outcome") == "passed", f"runtime_builds.{label} canary did not pass")
    require(canary.get("build_source_dirty") is False, f"runtime_builds.{label} binary is dirty")
    require(canary.get("build_source_revision") == revision,
            f"runtime_builds.{label} revision mismatch")
    require(canary.get("build_source_tree_fingerprint") == fingerprint,
            f"runtime_builds.{label} fingerprint mismatch")
    require(canary.get("provider") == provider and canary.get("provider_family") == "cuda",
            f"runtime_builds.{label} canary provider mismatch")
    require(canary.get("epoch_activation_height") == regtest_height,
            f"runtime_builds.{label} canary activation height mismatch")
    require(canary.get("epoch_profile") == 1 and canary.get("epoch_matmul_dimension") == 4096,
            f"runtime_builds.{label} canary is not production Profile 1")
    for field in ("device_xof_fallbacks", "host_xof_calls", "cpu_fallbacks"):
        require(canary.get(field) == 0, f"runtime_builds.{label}.canary.{field} must be zero")
    require(isinstance(canary.get("device_macs"), int) and canary["device_macs"] > 0,
            f"runtime_builds.{label} canary has no device work")
    health = node.get("provider_health")
    require(isinstance(health, dict), f"runtime_builds.{label} missing provider health")
    require(health.get("quarantined") is False and health.get("validator_readiness_lost") is False,
            f"runtime_builds.{label} provider is unhealthy")
    if require_validation:
        validation = node.get("last_validation")
        require(isinstance(validation, dict), f"runtime_builds.{label} missing validation")
        for field, expected in (
            ("available", True), ("outcome", "valid"),
            ("execution_policy", "strict-device"), ("require_device", True),
            ("fully_accelerated", True), ("device_xof_fallbacks", 0),
            ("host_xof_calls", 0), ("cpu_gemm_calls", 0),
            ("cpu_gemm_fallbacks", 0), ("acceleration_failure", ""),
        ):
            require(validation.get(field) == expected,
                    f"runtime_builds.{label}.last_validation.{field} mismatch")
        require(isinstance(validation.get("provider"), str)
                and validation["provider"].startswith("cuda_"),
                f"runtime_builds.{label} validation provider is not CUDA")
        require(isinstance(validation.get("device_gemm_calls"), int)
                and validation["device_gemm_calls"] > 0,
                f"runtime_builds.{label} validation has no device GEMM")


def validate_lifecycle(
    lifecycle_path: Path, policy: dict[str, Any], revision: str,
    fingerprint: str, binaries: dict[str, str],
) -> None:
    artifact = load_json(lifecycle_path)
    require(artifact.get("tool") == LIFECYCLE_TOOL, "lifecycle tool mismatch")
    schema = exact_int(artifact.get("schema_version"), "lifecycle schema_version")
    require(
        schema == LIFECYCLE_SCHEMA_VERSION,
        "lifecycle schema lacks exact per-block correlation telemetry",
    )
    require(
        artifact.get("correlation") == {
            "model": "exact_per_block_v2_concurrent_contention",
            "activation_eligible": True,
        },
        "lifecycle artifact is not exact-block correlated",
    )
    require(artifact.get("evidence_kind") == "cuda_complete_lifecycle_asert_calibration",
            "lifecycle artifact is not production calibration")
    require(artifact.get("source_revision") == revision, "lifecycle revision mismatch")
    require(artifact.get("source_tree_fingerprint") == fingerprint,
            "lifecycle fingerprint mismatch")
    require(artifact.get("binary_sha256") == {
        "btxd": binaries["btxd"], "btx_cli": binaries["btx_cli"]
    }, "lifecycle daemon/CLI hashes mismatch")
    require(artifact.get("execution_policy") == "strict-device",
            "lifecycle execution policy must be strict-device")
    require(artifact.get("mode") == "production" and artifact.get("profile") == 1
            and artifact.get("matmul_dim") == 4096 and artifact.get("nodes") == 2,
            "lifecycle artifact is not two-node production Profile 1")
    ratification = artifact.get("ratification")
    require(isinstance(ratification, dict), "lifecycle ratification record missing")
    for field in (
        "campaign_authorizes_no_inversion_gate",
        "campaign_authorizes_gpu_lifecycle_gate",
        "installs_rc_asert_ratio", "operationally_ready_claim",
    ):
        require(ratification.get(field) is False,
                f"lifecycle measurement must not self-authorize {field}")

    lifecycle_policy = policy.get("lifecycle_policy")
    require(isinstance(lifecycle_policy, dict), "lifecycle_policy must be an object")
    expected_keys = {
        "regtest_activation_height", "minimum_complete_samples",
        "maximum_p99_s", "maximum_max_s", "maximum_incomplete_samples",
        "minimum_contention_samples", "required_phases",
    }
    require(set(lifecycle_policy) == expected_keys, "lifecycle_policy has unexpected fields")
    regtest_height = exact_int(
        lifecycle_policy.get("regtest_activation_height"),
        "lifecycle_policy.regtest_activation_height", minimum=1,
        maximum=(1 << 31) - 2,
    )
    require(artifact.get("activation_height_regtest") == regtest_height,
            "lifecycle regtest activation height mismatch")
    minimum = exact_int(
        lifecycle_policy.get("minimum_complete_samples"),
        "lifecycle_policy.minimum_complete_samples", minimum=1,
    )
    maximum_incomplete = exact_int(
        lifecycle_policy.get("maximum_incomplete_samples"),
        "lifecycle_policy.maximum_incomplete_samples",
    )
    minimum_contention = exact_int(
        lifecycle_policy.get("minimum_contention_samples"),
        "lifecycle_policy.minimum_contention_samples", minimum=1,
    )
    maximum_p99 = exact_number(lifecycle_policy.get("maximum_p99_s"),
                               "lifecycle_policy.maximum_p99_s")
    maximum_max = exact_number(lifecycle_policy.get("maximum_max_s"),
                               "lifecycle_policy.maximum_max_s")
    require(maximum_p99 <= maximum_max, "lifecycle p99 bound exceeds max bound")
    required_phases = lifecycle_policy.get("required_phases")
    require(required_phases == ["steady_mine_relay", "competing_tip"],
            "lifecycle required phases must include steady and competing-tip work")

    samples = artifact.get("samples")
    require(isinstance(samples, list), "lifecycle samples must be an array")
    count = exact_int(artifact.get("complete_sample_count"), "complete_sample_count")
    require(count == len(samples) and count >= minimum,
            "lifecycle complete sample threshold not met")
    core_samples = artifact.get("core_samples_without_authority")
    require(isinstance(core_samples, list),
            "lifecycle core_samples_without_authority must be an array")
    core_count = exact_int(
        artifact.get("core_sample_count_without_authority"),
        "core_sample_count_without_authority",
    )
    require(core_count == len(core_samples), "lifecycle core sample count mismatch")
    incomplete_samples = artifact.get("incomplete_samples")
    require(isinstance(incomplete_samples, list),
            "lifecycle incomplete_samples must be an array")
    incomplete_count = exact_int(
        artifact.get("incomplete_sample_count"), "incomplete_sample_count",
    )
    require(incomplete_count == len(incomplete_samples),
            "lifecycle incomplete sample count mismatch")
    attempts = exact_int(artifact.get("attempts"), "lifecycle attempts")
    require(attempts == count + core_count + incomplete_count,
            "lifecycle attempts do not reconcile with recorded outcomes")
    require(incomplete_count <= maximum_incomplete,
            "lifecycle incomplete sample bound exceeded")
    phases = {sample.get("phase") for sample in samples if isinstance(sample, dict)}
    require(set(required_phases).issubset(phases), "lifecycle required phases were not observed")
    contention_count = sum(
        1 for sample in samples
        if isinstance(sample, dict) and sample.get("phase") == "competing_tip"
    )
    require(contention_count >= minimum_contention,
            "lifecycle contention sample threshold not met")
    lifecycle_values: list[float] = []
    block_hashes: set[str] = set()
    component_definition = artifact.get("component_definition")
    expected_components = [
        "observer_solve_rpc_to_authenticated_tip_s",
        "solve_to_reseal_s", "reseal_to_consume_s",
        "authenticated_relay_s", "tip_validation_s",
    ]
    require(component_definition == expected_components,
            "lifecycle component definition mismatch")
    for index, sample in enumerate(samples):
        require(isinstance(sample, dict) and sample.get("complete") is True,
                f"lifecycle samples[{index}] is incomplete")
        phase = sample.get("phase")
        require(phase in required_phases,
                f"lifecycle samples[{index}] phase is not reviewed")
        wall = exact_number(sample.get("complete_lifecycle_s"),
                            f"lifecycle samples[{index}].complete_lifecycle_s")
        lifecycle_values.append(wall)
        observer_wall = exact_number(
            sample.get("observer_solve_rpc_to_authenticated_tip_s"),
            f"lifecycle samples[{index}].observer wall",
        )
        require(abs(observer_wall - wall) <= 1e-9,
                f"lifecycle samples[{index}] observer wall mismatch")
        observer_measurement = sample.get("observer_measurement")
        expected_start_event = (
            "before_concurrent_competing_sibling_rpc_submission"
            if phase == "competing_tip"
            else "before_generatetodescriptor_rpc"
        )
        require(
            isinstance(observer_measurement, dict)
            and set(observer_measurement) == {
                "clock", "start_event", "stop_event", "elapsed_ns",
            }
            and observer_measurement.get("clock") == "monotonic_ns"
            and observer_measurement.get("start_event") == expected_start_event
            and observer_measurement.get("stop_event") ==
                "both_nodes_exact_authenticated_tip",
            f"lifecycle samples[{index}] observer measurement schema mismatch",
        )
        observer_elapsed_ns = exact_int(
            observer_measurement.get("elapsed_ns"),
            f"lifecycle samples[{index}].observer elapsed_ns",
        )
        require(
            abs(observer_elapsed_ns / 1_000_000_000.0 - wall) <= 1e-9,
            f"lifecycle samples[{index}] observer elapsed_ns mismatch",
        )
        require(sample.get("authority_measured") is True,
                f"lifecycle samples[{index}] lacks winner-authority handoff")
        block_hash = exact_hex(
            sample.get("block_hash"), HEX64, f"lifecycle samples[{index}].block_hash"
        )
        require(block_hash not in block_hashes,
                f"lifecycle samples[{index}] duplicates a block hash")
        block_hashes.add(block_hash)
        require(sample.get("rpc_correlated_end_to_end_sample") is True,
                f"lifecycle samples[{index}] is not RPC block-correlated")
        require(sample.get("correlation_block_hash") == block_hash,
                f"lifecycle samples[{index}] correlation block hash mismatch")
        block_height = exact_int(
            sample.get("height"), f"lifecycle samples[{index}].height",
            minimum=1, maximum=(1 << 31) - 2,
        )
        authority = sample.get("miner_authority")
        authority_keys = {
            "block_hash", "block_height", "solve_attempts",
            "solve_to_reseal_s", "reseal_to_consume_s",
            "solve_to_consume_s", "provider",
        }
        require(
            isinstance(authority, dict) and set(authority) == authority_keys,
            f"lifecycle samples[{index}] authority schema mismatch",
        )
        require(authority.get("block_hash") == block_hash
                and authority.get("block_height") == block_height,
                f"lifecycle samples[{index}] authority block mismatch")
        exact_int(
            authority.get("solve_attempts"),
            f"lifecycle samples[{index}].solve_attempts", minimum=1,
        )
        solve_to_reseal = exact_number(
            authority.get("solve_to_reseal_s"),
            f"lifecycle samples[{index}].solve_to_reseal_s")
        reseal_to_consume = exact_number(
            authority.get("reseal_to_consume_s"),
            f"lifecycle samples[{index}].reseal_to_consume_s")
        solve_to_consume = exact_number(
            authority.get("solve_to_consume_s"),
            f"lifecycle samples[{index}].solve_to_consume_s")
        require(
            abs(solve_to_reseal + reseal_to_consume -
                solve_to_consume) <= 1e-6,
            f"lifecycle samples[{index}] authority timings do not reconcile",
        )

        relay = sample.get("authenticated_relay")
        require(
            isinstance(relay, dict) and set(relay) == {"block_hash", "relay_s"}
            and relay.get("block_hash") == block_hash,
            f"lifecycle samples[{index}] relay block mismatch",
        )
        relay_s = exact_number(
            relay.get("relay_s"), f"lifecycle samples[{index}].relay_s")

        validation = sample.get("validator_exact_replay")
        validation_keys = {
            "block_hash", "block_height", "outcome", "execution_policy",
            "require_device", "provider", "fully_accelerated",
            "device_gemm_calls", "device_gemm_macs",
            "device_xof_fallbacks", "host_xof_calls", "cpu_gemm_calls",
            "cpu_gemm_fallbacks", "wall_s",
        }
        require(
            isinstance(validation, dict) and set(validation) == validation_keys,
            f"lifecycle samples[{index}] validation schema mismatch",
        )
        require(validation.get("block_hash") == block_hash
                and validation.get("block_height") == block_height,
                f"lifecycle samples[{index}] validation block mismatch")
        validation_s = exact_number(
            validation.get("wall_s"),
            f"lifecycle samples[{index}].validation wall_s")
        require(max(solve_to_consume, relay_s, validation_s) <= wall + 1e-6,
                f"lifecycle samples[{index}] stage exceeds observer wall")
        require(
            abs(wall - (solve_to_consume + relay_s + validation_s)) > 1e-6,
            f"lifecycle samples[{index}] substitutes summed stages for observer wall",
        )

        competing = sample.get("competing_block_hashes")
        require(isinstance(competing, list),
                f"lifecycle samples[{index}] competing hashes must be an array")
        require(
            all(
                exact_hex(value, HEX64,
                          f"lifecycle samples[{index}].competing hash") != block_hash
                for value in competing
            ) and len(set(competing)) == len(competing),
            f"lifecycle samples[{index}] competing hashes are invalid",
        )
        if phase == "competing_tip":
            require(competing,
                    f"lifecycle samples[{index}] lacks a distinct competing block")
            reorg_tip = exact_hex(
                sample.get("contention_reorg_tip_hash"), HEX64,
                f"lifecycle samples[{index}].contention reorg tip",
            )
            require(
                reorg_tip != block_hash and reorg_tip not in competing,
                f"lifecycle samples[{index}] contention reorg tip is not distinct",
            )
            trace = sample.get("contention_trace")
            trace_keys = {
                "common_parent_hash", "winning_branch_hash",
                "winning_branch_parent_hash", "losing_branch_hash",
                "losing_branch_parent_hash", "reorg_tip_hash",
                "reorg_tip_parent_hash", "measured_block_parent_hash",
            }
            require(
                isinstance(trace, dict) and set(trace) == trace_keys,
                f"lifecycle samples[{index}] contention trace schema mismatch",
            )
            for key in trace_keys:
                exact_hex(
                    trace.get(key), HEX64,
                    f"lifecycle samples[{index}].contention trace {key}",
                )
            require(
                trace["winning_branch_parent_hash"] == trace["common_parent_hash"]
                and trace["losing_branch_parent_hash"] == trace["common_parent_hash"]
                and trace["reorg_tip_parent_hash"] == trace["winning_branch_hash"]
                and trace["measured_block_parent_hash"] == trace["reorg_tip_hash"]
                and trace["losing_branch_hash"] in competing
                and trace["reorg_tip_hash"] == reorg_tip,
                f"lifecycle samples[{index}] contention ancestry mismatch",
            )
            require(
                len({trace["common_parent_hash"], trace["winning_branch_hash"],
                     trace["losing_branch_hash"], trace["reorg_tip_hash"],
                     block_hash}) == 5,
                f"lifecycle samples[{index}] contention blocks are not distinct",
            )
            timing = sample.get("contention_timing")
            timing_keys = {
                "clock", "start_mode",
                "winning_sibling_local_accept_elapsed_ns",
                "losing_sibling_local_accept_elapsed_ns",
                "winning_extension_local_accept_elapsed_ns",
                "reorg_convergence_elapsed_ns",
                "measured_child_authenticated_elapsed_ns",
            }
            require(
                isinstance(timing, dict) and set(timing) == timing_keys
                and timing.get("clock") == "monotonic_ns"
                and timing.get("start_mode") ==
                    "concurrent_sibling_rpc_submission",
                f"lifecycle samples[{index}] contention timing schema mismatch",
            )
            winning_accept = exact_int(
                timing.get("winning_sibling_local_accept_elapsed_ns"),
                f"lifecycle samples[{index}] winning sibling elapsed_ns",
                minimum=1,
            )
            losing_accept = exact_int(
                timing.get("losing_sibling_local_accept_elapsed_ns"),
                f"lifecycle samples[{index}] losing sibling elapsed_ns",
                minimum=1,
            )
            extension_accept = exact_int(
                timing.get("winning_extension_local_accept_elapsed_ns"),
                f"lifecycle samples[{index}] winning extension elapsed_ns",
                minimum=1,
            )
            reorg_convergence = exact_int(
                timing.get("reorg_convergence_elapsed_ns"),
                f"lifecycle samples[{index}] reorg convergence elapsed_ns",
                minimum=1,
            )
            child_authenticated = exact_int(
                timing.get("measured_child_authenticated_elapsed_ns"),
                f"lifecycle samples[{index}] child authentication elapsed_ns",
                minimum=1,
            )
            require(
                max(winning_accept, losing_accept) < extension_accept
                < reorg_convergence < child_authenticated,
                f"lifecycle samples[{index}] contention checkpoints are not ordered",
            )
            require(
                child_authenticated == observer_elapsed_ns,
                f"lifecycle samples[{index}] contention observer endpoint mismatch",
            )
        else:
            require(not competing,
                    f"lifecycle samples[{index}] steady sample claims contention")
            require(sample.get("contention_reorg_tip_hash") is None,
                    f"lifecycle samples[{index}] steady sample claims a reorg tip")
            require(sample.get("contention_trace") is None,
                    f"lifecycle samples[{index}] steady sample claims a contention trace")
            require(sample.get("contention_timing") is None,
                    f"lifecycle samples[{index}] steady sample claims contention timing")
        require(isinstance(sample.get("miner_provider"), str)
                and sample["miner_provider"].startswith("cuda_"),
                f"lifecycle samples[{index}] miner provider is not CUDA")
        require(isinstance(sample.get("validator_provider"), str)
                and sample["validator_provider"].startswith("cuda_"),
                f"lifecycle samples[{index}] validator provider is not CUDA")
        for field, expected in (
            ("validator_execution_policy", "strict-device"),
            ("validator_fully_accelerated", True),
            ("validator_cpu_gemm_calls", 0),
            ("validator_cpu_gemm_fallbacks", 0),
        ):
            require(sample.get(field) == expected,
                    f"lifecycle samples[{index}].{field} mismatch")
        for field, expected in (
            ("outcome", "valid"), ("execution_policy", "strict-device"),
            ("require_device", True), ("fully_accelerated", True),
            ("device_xof_fallbacks", 0), ("host_xof_calls", 0),
            ("cpu_gemm_calls", 0), ("cpu_gemm_fallbacks", 0),
        ):
            require(validation.get(field) == expected,
                    f"lifecycle samples[{index}].validation.{field} mismatch")
        require(
            exact_int(
                validation.get("device_gemm_calls"),
                f"lifecycle samples[{index}].device_gemm_calls", minimum=1,
            ) >= 1,
            f"lifecycle samples[{index}] validation has no device GEMM",
        )
        require(validation.get("provider") == sample.get("validator_provider")
                and authority.get("provider") == sample.get("miner_provider"),
                f"lifecycle samples[{index}] provider binding mismatch")
    summary = artifact.get("complete_lifecycle_summary_s")
    require(isinstance(summary, dict) and summary.get("n") == count,
            "lifecycle summary count mismatch")
    ordered = sorted(lifecycle_values)
    def percentile(percent: int) -> float:
        index = max(1, math.ceil(percent * len(ordered) / 100)) - 1
        return ordered[min(len(ordered) - 1, index)]

    reproduced_summary = {
        "n": len(ordered),
        "min": ordered[0],
        "p50": percentile(50),
        "p95": percentile(95),
        "p99": percentile(99),
        "max": ordered[-1],
        "mean": sum(ordered) / len(ordered),
    }
    for field, expected in reproduced_summary.items():
        observed = summary.get(field)
        if field == "n":
            require(observed == expected, "lifecycle summary n mismatch")
        else:
            require(
                abs(exact_number(observed, f"lifecycle summary {field}") - expected)
                <= 1e-9,
                f"lifecycle summary {field} is not reproduced by samples",
            )
    require(exact_number(summary.get("p99"), "lifecycle p99") <= maximum_p99,
            "lifecycle p99 exceeds reviewed policy")
    require(exact_number(summary.get("max"), "lifecycle max") <= maximum_max,
            "lifecycle max exceeds reviewed policy")

    runtime = artifact.get("runtime_builds")
    require(isinstance(runtime, dict) and set(runtime) == {"miner", "validator"},
            "lifecycle must bind both runtime builds")
    _validate_runtime_node(
        runtime["miner"], "miner", revision, fingerprint, regtest_height,
        require_validation=False,
    )
    _validate_runtime_node(
        runtime["validator"], "validator", revision, fingerprint, regtest_height,
        require_validation=True,
    )


def verify(policy_path: Path, root: Path, binaries: dict[str, Path]) -> dict[str, Any]:
    root = root.resolve()
    policy_path = policy_path.resolve()
    try:
        policy_relative = policy_path.relative_to(root).as_posix()
    except ValueError as error:
        raise GateError("policy must be inside the source repository") from error
    require(
        SAFE_EVIDENCE.fullmatch(policy_relative) is not None
        and ".." not in Path(policy_relative).parts,
        "policy must be a safe path under doc/evidence",
    )
    require(policy_path.is_file() and not policy_path.is_symlink(),
            "policy must be a regular file")
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", policy_relative],
        capture_output=True, check=False,
    )
    require(tracked.returncode == 0, "policy must be tracked")
    require(git(root, "status", "--porcelain", "--", policy_relative) == "",
            "policy must be unmodified")
    policy = load_json(policy_path)
    require(policy.get("tool") == TOOL and policy.get("schema_version") == SCHEMA_VERSION,
            f"policy must be {TOOL} schema {SCHEMA_VERSION}")
    required_keys = {
        "tool", "schema_version", "source_revision", "source_tree_fingerprint",
        "implementation_fingerprint",
        "activation_tuple", "ratification", "provider_policy",
        "artifact_sources", "evidence", "lifecycle_policy",
    }
    require(set(policy) == required_keys, "policy has missing or unexpected fields")
    revision, fingerprint = validate_source_identity(root, policy)
    frozen_implementation = validate_implementation_identity(
        root, policy, revision,
    )
    validate_source_tuple(root, policy)
    validate_provider_policy(policy)
    artifact_sources, expected_binary_hashes = validate_artifact_sources(
        root, policy, revision, frozen_implementation,
    )
    binary_hashes = validate_binaries(expected_binary_hashes, binaries)

    evidence = policy.get("evidence")
    require(isinstance(evidence, dict) and set(evidence) == EXPECTED_EVIDENCE_KEYS,
            "evidence must bind every required artifact exactly")
    paths = {
        name: resolve_evidence(root, evidence[name], name)
        for name in sorted(EXPECTED_EVIDENCE_KEYS)
    }
    validate_asert(
        root, paths["asert_root"], paths["asert_derived"], policy,
        *artifact_sources["asert"], binary_hashes["asert"],
    )
    validate_golden(
        root, paths["golden_compare"],
        *artifact_sources["production_goldens"],
        binary_hashes["production_goldens"],
    )
    validate_lifecycle(
        paths["lifecycle"], policy, *artifact_sources["lifecycle"],
        binary_hashes["lifecycle"],
    )
    return {
        "source_revision": revision,
        "source_tree_fingerprint": fingerprint,
        "implementation_fingerprint": frozen_implementation,
        "artifact_source_revisions": {
            role: source[0] for role, source in sorted(artifact_sources.items())
        },
        "activation_height": policy["activation_tuple"]["height"],
        "coefficient": policy["activation_tuple"]["nMatMulRCAsertRescaleNum"],
        "asert_calibration_cohort": ["cuda"],
        "correctness_golden_cohort": ["cuda", "metal"],
        "lifecycle_complete_samples": load_json(paths["lifecycle"])["complete_sample_count"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--asert-parent-calibration-binary", type=Path, required=True)
    parser.add_argument("--asert-cuda-rc-harness", type=Path, required=True)
    parser.add_argument("--golden-cuda-rc-harness", type=Path, required=True)
    parser.add_argument("--golden-metal-rc-harness", type=Path, required=True)
    parser.add_argument("--lifecycle-btxd", type=Path, required=True)
    parser.add_argument("--lifecycle-btx-cli", type=Path, required=True)
    args = parser.parse_args()
    binaries = {
        "asert_parent_calibration": args.asert_parent_calibration_binary,
        "asert_cuda_rc_harness": args.asert_cuda_rc_harness,
        "golden_cuda_rc_harness": args.golden_cuda_rc_harness,
        "golden_metal_rc_harness": args.golden_metal_rc_harness,
        "lifecycle_btxd": args.lifecycle_btxd,
        "lifecycle_btx_cli": args.lifecycle_btx_cli,
    }
    try:
        result = verify(args.policy, args.root.resolve(), binaries)
    except (GateError, OSError) as error:
        print(f"verify-epoch-a-activation-gate: FAIL {error}", file=sys.stderr)
        return 1
    print("verify-epoch-a-activation-gate: PASS " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
