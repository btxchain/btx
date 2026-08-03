#!/usr/bin/env bash
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Multi-GPU Profile-1 ExactReplay golden corpus.
#
# Runs the same frozen production canary headers on one or more backends
# (cuda|metal|hip) and asserts byte-identical digests across backends that
# succeed. CPU is not an accepted independent reproduction path for Epoch-A
# production goldens on the GPU-optimized chain.
#
# Usage:
#   contrib/matmul-v4/multi-gpu-golden-corpus.sh \
#     --harness build-cuda/bin/matmul-v4-rc-harness \
#     --backends cuda \
#     --out-dir doc/evidence/multi-gpu-profile1-goldens-YYYY-MM-DD
#
# Optional: --backends cuda,metal,hip. CUDA+Metal are the required independent
# launch cohort; HIP is optional, but when supplied it must match exactly.
# Use --compare-only to rebuild a comparison from sanitized artifacts already
# present under OUT_DIR/raw without executing a backend on the current host.
set -euo pipefail

HARNESS=""
BACKENDS="cuda"
EPISODES=8
NONCE_START=1
OUT_DIR=""
SOURCE_REVISION=""
SOURCE_TREE_FINGERPRINT=""
ALLOW_PARTIAL=0
COMPARE_ONLY=0
TIP_SHA=""

die() { echo "multi-gpu-golden-corpus: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --harness) HARNESS="${2:-}"; shift 2 ;;
    --backends) BACKENDS="${2:-}"; shift 2 ;;
    --episodes) EPISODES="${2:-}"; shift 2 ;;
    --canary-nonce-start) NONCE_START="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --source-revision) SOURCE_REVISION="${2:-}"; shift 2 ;;
    --source-tree-fingerprint) SOURCE_TREE_FINGERPRINT="${2:-}"; shift 2 ;;
    --allow-partial) ALLOW_PARTIAL=1; shift ;;
    --compare-only) COMPARE_ONLY=1; shift ;;
    -h|--help)
      sed -n '1,30p' "$0"
      exit 0
      ;;
    *) die "unknown arg: $1" ;;
  esac
done

[[ -n "${OUT_DIR}" ]] || die "--out-dir required"
mkdir -p "${OUT_DIR}/raw"
if [[ ${COMPARE_ONLY} -eq 0 ]]; then
  [[ -n "${HARNESS}" && -x "${HARNESS}" ]] || die "--harness executable required"
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Portable SHA-256: coreutils exposes sha256sum, macOS/perl exposes shasum.
sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

sha256_file() {
  sha256_stdin < "$1"
}

# The one path excluded from the build-relevant fingerprint: the data-only TU
# that HOLDS the fingerprint. Without this exclusion sealing is a fixed-point
# problem -- writing the hash into the tree changes the tree -- so a manifest
# could only ever cite its own parent commit. The excluded file is a pure data
# literal by construction; see its header comment. Keep this list identical to
# EXCLUDED_FROM_FINGERPRINT in verify-evidence-provenance.py.
FINGERPRINT_EXCLUDE='src/matmul/matmul_v4_rc_production_golden_manifest.cpp'

build_relevant_tree() {
  git -C "${REPO_ROOT}" ls-tree -r --full-tree "$1" -- \
    CMakeLists.txt cmake src | grep -v "	${FINGERPRINT_EXCLUDE}\$"
}

build_relevant_fingerprint() {
  build_relevant_tree "$1" | sha256_stdin
}

# PROVENANCE GUARD (fail-closed).
#
# source_revision and source_tree_fingerprint are both derived from the
# COMMITTED tree at HEAD, while the harness is compiled from the WORKING tree.
# Without this check a build made from locally modified sources is recorded
# under a clean revision and a clean fingerprint, and the comparator — which
# only ever sees those two strings — cannot detect the substitution. Since the
# entire Epoch-A activation argument rests on that pair, a dirty build-relevant
# tree is refused outright rather than annotated. Commit to a scratch branch and
# pass --source-revision if you need evidence from work in progress.
if [[ ${COMPARE_ONLY} -eq 0 ]]; then
  if ! git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    die "not a git checkout: cannot establish source provenance"
  fi
  DIRTY="$(git -C "${REPO_ROOT}" status --porcelain -- \
    CMakeLists.txt cmake src 2>/dev/null || true)"
  if [[ -n "${DIRTY}" ]]; then
    echo "multi-gpu-golden-corpus: build-relevant working tree is dirty:" >&2
    echo "${DIRTY}" >&2
    die "refusing to record a corpus whose fingerprint would not describe the built sources"
  fi
fi

if [[ -z "${SOURCE_REVISION}" ]]; then
  SOURCE_REVISION="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
fi
[[ "${SOURCE_REVISION}" =~ ^[0-9a-fA-F]{40}$ ]] || \
  die "--source-revision must be a 40-character commit id (got: ${SOURCE_REVISION})"
TIP_SHA="${SOURCE_REVISION}"
if [[ -z "${SOURCE_TREE_FINGERPRINT}" ]]; then
  SOURCE_TREE_FINGERPRINT="$(build_relevant_fingerprint HEAD)"
fi
[[ "${SOURCE_TREE_FINGERPRINT}" =~ ^[0-9a-fA-F]{64}$ ]] || \
  die "--source-tree-fingerprint must be a 64-character SHA-256"

# An explicitly supplied revision/fingerprint pair is only admissible when it
# actually describes this checkout; otherwise the operator is asserting
# provenance the script cannot corroborate.
#
# These checks deliberately run in --compare-only mode too. They need only git,
# not a harness or a device, and compare-only still stamps tip_sha and
# source_tree_fingerprint into multi-gpu-digest-compare.json -- the file every
# downstream consumer reads. Gating them on the execution path left a mode in
# which an operator-supplied revision naming no commit produced
# complete_multi_gpu_match=true with exit 0, from a directory that need not even
# be a git checkout.
if true; then
  git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1 || \
    die "not a git checkout: cannot corroborate the declared provenance"
  # A 40-hex string is not a revision. Evidence has been recorded in this tree
  # under a well-formed but non-existent commit id, which every downstream
  # consumer accepted because they only ever length-checked the hex.
  git -C "${REPO_ROOT}" cat-file -e "${SOURCE_REVISION}^{commit}" 2>/dev/null || \
    die "source revision ${SOURCE_REVISION} does not resolve to a commit in this repository"
  ACTUAL_TREE_FINGERPRINT="$(build_relevant_fingerprint "${SOURCE_REVISION}" 2>/dev/null)"
  if [[ "${ACTUAL_TREE_FINGERPRINT}" != "${SOURCE_TREE_FINGERPRINT}" ]]; then
    die "source-tree-fingerprint ${SOURCE_TREE_FINGERPRINT} does not match revision ${SOURCE_REVISION} (${ACTUAL_TREE_FINGERPRINT})"
  fi
  HEAD_TREE_FINGERPRINT="$(build_relevant_fingerprint HEAD)"
  if [[ "${HEAD_TREE_FINGERPRINT}" != "${SOURCE_TREE_FINGERPRINT}" ]]; then
    die "checkout at HEAD does not carry the declared build-relevant tree; the harness was not built from ${SOURCE_REVISION}"
  fi
fi

IFS=',' read -r -a BACKEND_LIST <<< "${BACKENDS}"
declare -a OK_BACKENDS=()
declare -a RAW_JSONS=()

if [[ ${COMPARE_ONLY} -eq 1 ]]; then
  for be in cuda metal hip; do
    out_json="${OUT_DIR}/raw/profile1-${be}-${EPISODES}.json"
    if [[ -f "${out_json}" ]]; then
      OK_BACKENDS+=("${be}")
      RAW_JSONS+=("${out_json}")
    fi
  done
else
  for be in "${BACKEND_LIST[@]}"; do
    be="$(echo "${be}" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
    [[ -n "${be}" ]] || continue
    case "${be}" in
      cuda|metal|hip) ;;
      cpu) die "cpu is not an accepted production golden backend" ;;
      *) die "unsupported backend: ${be}" ;;
    esac
    out_json="${OUT_DIR}/raw/profile1-${be}-${EPISODES}.json"
    echo "multi-gpu-golden-corpus: running backend=${be} episodes=${EPISODES}"
    set +e
    env BTX_MATMUL_V4_BACKEND="${be}" BTX_MATMUL_BACKEND="${be}" \
      "${HARNESS}" \
        --base-production \
        --episodes "${EPISODES}" \
        --backend "${be}" \
        --canary-headers \
        --canary-nonce-start "${NONCE_START}" \
        --emit-frozen-headers \
        --public-evidence \
        --source-revision "${SOURCE_REVISION}" \
        --out "${out_json}"
    rc=$?
    set -e
    if [[ ${rc} -ne 0 ]]; then
      echo "multi-gpu-golden-corpus: backend ${be} failed (exit ${rc})" >&2
      if [[ ${ALLOW_PARTIAL} -eq 0 ]]; then
        exit "${rc}"
      fi
      continue
    fi
    harness_sha256="$(sha256_file "${HARNESS}")"
    python3 - "${out_json}" "${SOURCE_TREE_FINGERPRINT}" "${harness_sha256}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text())
payload["source_tree_fingerprint"] = sys.argv[2]
payload["harness_sha256"] = sys.argv[3]
path.write_text(json.dumps(payload, indent=2) + "\n")
PY
    OK_BACKENDS+=("${be}")
    RAW_JSONS+=("${out_json}")
  done
fi

[[ ${#OK_BACKENDS[@]} -ge 1 ]] || die "no backend succeeded"

MERGE_OUT="${OUT_DIR}/multi-gpu-digest-compare.json"
python3 - "${MERGE_OUT}" "${TIP_SHA}" "${SOURCE_TREE_FINGERPRINT}" "${NONCE_START}" "${EPISODES}" "${ALLOW_PARTIAL}" "${OK_BACKENDS[@]}" -- "${RAW_JSONS[@]}" <<'PY'
import json, sys
import re
from pathlib import Path

out_path = Path(sys.argv[1])
tip_sha = sys.argv[2]
source_tree_fingerprint = sys.argv[3]
nonce_start = int(sys.argv[4])
episodes = int(sys.argv[5])
allow_partial = int(sys.argv[6])
sep = sys.argv.index("--")
backends = sys.argv[7:sep]
raw_paths = [Path(p) for p in sys.argv[sep + 1:]]

def load_frozen(path: Path):
    d = json.loads(path.read_text())
    fhs = d.get("frozen_headers") or []
    if not fhs and d.get("episode_digests"):
        # Older CUDA-only evidence shape.
        digs = d["episode_digests"]
        fhs = [
            {
                "header_nonce": nonce_start + i,
                "exact_replay_digest": dig,
                "matmul_dim": d.get("header_matmul_dim") or d.get("matmul_dim") or 4096,
            }
            for i, dig in enumerate(digs)
        ]
    return d, fhs

by_backend = {}
for be, path in zip(backends, raw_paths):
    raw, fhs = load_frozen(path)
    if not fhs:
        raise SystemExit(f"backend {be}: missing frozen_headers in {path}")
    records = []
    for fh in fhs:
        dig = fh.get("exact_replay_digest") or fh.get("digest")
        if not dig:
            raise SystemExit(f"backend {be}: missing digest fields")
        records.append(
            {
                "header_nonce": int(fh.get("header_nonce") or fh.get("nonce") or 0),
                "matmul_dim": int(fh.get("matmul_dim") or 4096),
                "exact_replay_digest": dig,
                "header_hex": fh.get("header_hex"),
                "wall_s": fh.get("wall_s"),
                "cpu_fallbacks": fh.get("cpu_fallbacks", 0),
                "provider": (raw.get("exact_replay_acceleration") or {}).get("provider")
                or raw.get("provider"),
            }
        )
    by_backend[be] = {
        "raw": str(path.name),
        "n": len(records),
        "records": records,
        "all_consensus_macs_on_device": raw.get("all_consensus_macs_on_device"),
        "cpu_gemm_fallbacks": (raw.get("exact_replay_acceleration") or {}).get(
            "cpu_fallbacks", raw.get("cpu_gemm_fallbacks")
        ),
        "source_revision": raw.get("source_revision") or raw.get("git_tip") or "unknown",
        "source_tree_fingerprint": raw.get("source_tree_fingerprint"),
        "harness_sha256": raw.get("harness_sha256"),
        "provider": (raw.get("exact_replay_acceleration") or {}).get("provider")
        or raw.get("provider"),
        "backend_requested": raw.get("backend_requested"),
        "provider_identity": raw.get("production_provider_identity") or {},
        "acceleration": raw.get("exact_replay_acceleration") or {},
    }

# Compare the exact nonce set, frozen header bytes, dimension, and digest.
ref = backends[0]
ref_map = {r["header_nonce"]: r for r in by_backend[ref]["records"]}
mismatches = []
coverage_failures = []
expected_nonces = set(range(nonce_start, nonce_start + episodes))
provider_prefixes = {
    "cuda": ("cuda_",),
    "metal": ("metal_",),
    "hip": ("hip_",),
}
for be in backends:
    records = by_backend[be]["records"]
    observed_nonces = {r["header_nonce"] for r in records}
    if len(observed_nonces) != len(records):
        coverage_failures.append({"backend": be, "reason": "duplicate_nonce"})
    for nonce in sorted(expected_nonces - observed_nonces):
        coverage_failures.append({"backend": be, "nonce": nonce, "reason": "required_nonce_missing"})
    for nonce in sorted(observed_nonces - expected_nonces):
        coverage_failures.append({"backend": be, "nonce": nonce, "reason": "unexpected_nonce"})
    if by_backend[be]["all_consensus_macs_on_device"] is not True:
        coverage_failures.append({"backend": be, "reason": "consensus_macs_not_all_on_device"})
    if by_backend[be]["cpu_gemm_fallbacks"] != 0:
        coverage_failures.append({"backend": be, "reason": "cpu_gemm_fallbacks_nonzero"})
    if by_backend[be]["backend_requested"] != be:
        coverage_failures.append({"backend": be, "reason": "backend_identity_mismatch"})
    provider = by_backend[be]["provider"]
    if not isinstance(provider, str) or not provider.startswith(provider_prefixes[be]):
        coverage_failures.append({"backend": be, "reason": "raw_provider_family_mismatch"})
    identity = by_backend[be]["provider_identity"]
    if identity.get("complete") is not True:
        coverage_failures.append({"backend": be, "reason": "provider_identity_incomplete"})
    if identity.get("provider_family") != be:
        coverage_failures.append({"backend": be, "reason": "provider_family_mismatch"})
    if not identity.get("device_architecture"):
        coverage_failures.append({"backend": be, "reason": "provider_architecture_missing"})
    for field in ("driver_identity", "runtime_identity", "reason"):
        if not isinstance(identity.get(field), str) or not identity.get(field).strip():
            coverage_failures.append({"backend": be, "reason": f"provider_{field}_missing"})
    source_revision = by_backend[be]["source_revision"]
    if not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", source_revision):
        coverage_failures.append({"backend": be, "reason": "source_revision_invalid"})
    elif source_revision.lower() != tip_sha.lower():
        coverage_failures.append({"backend": be, "reason": "source_revision_mismatch"})
    if by_backend[be]["source_tree_fingerprint"] != source_tree_fingerprint:
        coverage_failures.append({"backend": be, "reason": "source_tree_fingerprint_mismatch"})
    if not isinstance(by_backend[be]["harness_sha256"], str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", by_backend[be]["harness_sha256"]
    ):
        coverage_failures.append({"backend": be, "reason": "harness_sha256_invalid"})
    acceleration = by_backend[be]["acceleration"]
    required_true = (
        "device_backend_present",
        "require_device",
        "fully_accelerated",
        "all_consensus_macs_on_device",
    )
    for field in required_true:
        if acceleration.get(field) is not True:
            coverage_failures.append({"backend": be, "reason": f"acceleration_{field}_not_true"})
    if not isinstance(acceleration.get("resolution_reason"), str) or not acceleration.get("resolution_reason").strip():
        coverage_failures.append({"backend": be, "reason": "acceleration_resolution_reason_missing"})
    expected_macs = acceleration.get("expected_macs")
    if not isinstance(expected_macs, int) or expected_macs <= 0:
        coverage_failures.append({"backend": be, "reason": "acceleration_expected_macs_invalid"})
    if acceleration.get("device_macs") != expected_macs:
        coverage_failures.append({"backend": be, "reason": "acceleration_device_macs_mismatch"})
    if not isinstance(acceleration.get("device_calls"), int) or acceleration.get("device_calls", 0) <= 0:
        coverage_failures.append({"backend": be, "reason": "acceleration_device_calls_invalid"})
    for field in ("cpu_calls", "cpu_macs", "cpu_fallbacks"):
        if acceleration.get(field) != 0:
            coverage_failures.append({"backend": be, "reason": f"acceleration_{field}_nonzero"})
    if acceleration.get("first_failure") not in (None, ""):
        coverage_failures.append({"backend": be, "reason": "acceleration_first_failure_present"})
    for record in records:
        header_hex = record.get("header_hex")
        if not isinstance(header_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{364}", header_hex):
            coverage_failures.append({"backend": be, "nonce": record["header_nonce"], "reason": "canonical_header_hex_invalid"})
        if record.get("provider") != provider:
            coverage_failures.append({"backend": be, "nonce": record["header_nonce"], "reason": "record_provider_mismatch"})

for be in backends[1:]:
    observed = {r["header_nonce"]: r for r in by_backend[be]["records"]}
    for n in sorted(set(ref_map) | set(observed)):
        if n not in ref_map or n not in observed:
            mismatches.append({"nonce": n, "backend": be, "reason": "nonce_set_mismatch"})
            continue
        ref_record = ref_map[n]
        record = observed[n]
        for field in ("matmul_dim", "header_hex", "exact_replay_digest"):
            if record.get(field) != ref_record.get(field) or record.get(field) is None:
                mismatches.append({"nonce": n, "backend": be, "reason": f"{field}_mismatch"})

required = {"cuda", "metal"}
present = set(backends)
cuda_metal_present = {"cuda", "metal"}.issubset(present)
cuda_metal_failures = [
    failure for failure in coverage_failures
    if failure.get("backend") in {"cuda", "metal"}
]
cuda_metal_mismatches = [
    mismatch for mismatch in mismatches
    if mismatch.get("backend") in {"cuda", "metal"}
]
cuda_metal_match = cuda_metal_present and not cuda_metal_failures and not cuda_metal_mismatches
complete_match = (
    required.issubset(present)
    and not mismatches
    and not coverage_failures
    and all(by_backend[b]["n"] == episodes for b in backends)
)

payload = {
    "evidence_kind": "multi_gpu_profile1_exactreplay_golden_compare",
    "tip_sha": tip_sha,
    "source_tree_fingerprint": source_tree_fingerprint,
    "canary_nonce_start": nonce_start,
    "backends_requested": backends,
    "backends_succeeded": backends,
    "required_for_manifest": sorted(required),
    "complete_multi_gpu_match": complete_match,
    "cuda_metal_match": cuda_metal_match,
    "allow_partial": bool(allow_partial),
    "mismatches": mismatches,
    "coverage_failures": coverage_failures,
    "by_backend": {
        be: {
            "n": by_backend[be]["n"],
            "raw": by_backend[be]["raw"],
            "all_consensus_macs_on_device": by_backend[be]["all_consensus_macs_on_device"],
            "cpu_gemm_fallbacks": by_backend[be]["cpu_gemm_fallbacks"],
            "source_revision": by_backend[be]["source_revision"],
            "source_tree_fingerprint": by_backend[be]["source_tree_fingerprint"],
            "harness_sha256": by_backend[be]["harness_sha256"],
            "provider": by_backend[be]["provider"],
            "backend_requested": by_backend[be]["backend_requested"],
            "provider_identity": by_backend[be]["provider_identity"],
            "digests_by_nonce": {
                str(r["header_nonce"]): r["exact_replay_digest"]
                for r in by_backend[be]["records"]
            },
        }
        for be in backends
    },
    "notes": [
        "Production goldens require byte-identical ExactReplay digests across CUDA and Metal for the same frozen canary headers.",
        "HIP remains an optional provider; any supplied HIP corpus must match the required cohort exactly.",
        "CPU ExactReplay is not an accepted independent reproduction path for Epoch-A production goldens.",
        "Every required artifact is bound to the exact requested source revision and a raw provider implementation consistent with its declared backend family.",
        "CommittedRCProductionGoldenManifest may be populated only from a reviewed corpus where complete_multi_gpu_match is true.",
        "Public evidence must remain machine-class only (no hostname/SKU/path identifiers).",
    ],
    # This comparator measures digest agreement between providers. It has no
    # visibility into consensus parameters or the ratification constants, so it
    # cannot report their state -- and a hard-coded False said "not ratified"
    # even in artifacts produced from a tree where those flags are true.
    # Renamed and restated so the field describes what this tool actually
    # establishes: agreement here does not by itself authorize activation.
    "authorizes_activation": False,
    "authorizes_activation_reason":
        "digest agreement across providers only; this tool does not read "
        "consensus parameters, ratification flags, or the committed manifest",
}
out_path.write_text(json.dumps(payload, indent=2) + "\n")
print(json.dumps({"wrote": str(out_path), "cuda_metal_match": cuda_metal_match, "complete_multi_gpu_match": complete_match, "mismatches": len(mismatches), "coverage_failures": len(coverage_failures)}, indent=2))
if (mismatches or coverage_failures) and not allow_partial:
    raise SystemExit("header/digest/coverage mismatch across backends")
if not complete_match and not allow_partial:
    raise SystemExit("incomplete multi-GPU set (need cuda+metal with matching digests)")
PY

# Sanitized README stub (no host paths). Preserve a reviewed evidence README on
# compare-only or repeat runs instead of replacing it with generic text.
if [[ ! -f "${OUT_DIR}/README.md" ]]; then
cat > "${OUT_DIR}/README.md" <<EOF
# Multi-GPU Profile-1 ExactReplay golden compare

Status: corpus runner output. Inspect \`multi-gpu-digest-compare.json\` for the
fail-closed result. Public Epoch-A heights remain disabled until a matching
CUDA+Metal corpus is committed to \`CommittedRCProductionGoldenManifest()\`.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA and Metal) ExactReplay on identical frozen canary headers. HIP is an
optional provider whose submitted evidence must also match. Portable CPU
oracle reproduction is not required for this GPU-optimized chain.

## Artifact

See \`multi-gpu-digest-compare.json\`.
EOF
fi

echo "multi-gpu-golden-corpus: wrote ${OUT_DIR}"
