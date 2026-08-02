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

if [[ -z "${SOURCE_REVISION}" ]]; then
  SOURCE_REVISION="$(git -C "$(dirname "$0")/../.." rev-parse HEAD 2>/dev/null || echo unknown)"
fi
TIP_SHA="${SOURCE_REVISION}"

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
    OK_BACKENDS+=("${be}")
    RAW_JSONS+=("${out_json}")
  done
fi

[[ ${#OK_BACKENDS[@]} -ge 1 ]] || die "no backend succeeded"

MERGE_OUT="${OUT_DIR}/multi-gpu-digest-compare.json"
python3 - "${MERGE_OUT}" "${TIP_SHA}" "${NONCE_START}" "${EPISODES}" "${ALLOW_PARTIAL}" "${OK_BACKENDS[@]}" -- "${RAW_JSONS[@]}" <<'PY'
import json, sys
from pathlib import Path

out_path = Path(sys.argv[1])
tip_sha = sys.argv[2]
nonce_start = int(sys.argv[3])
episodes = int(sys.argv[4])
allow_partial = int(sys.argv[5])
sep = sys.argv.index("--")
backends = sys.argv[6:sep]
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
        "provider": (raw.get("exact_replay_acceleration") or {}).get("provider")
        or raw.get("provider"),
        "backend_requested": raw.get("backend_requested"),
        "provider_identity": raw.get("production_provider_identity") or {},
    }

# Compare the exact nonce set, frozen header bytes, dimension, and digest.
ref = backends[0]
ref_map = {r["header_nonce"]: r for r in by_backend[ref]["records"]}
mismatches = []
coverage_failures = []
expected_nonces = set(range(nonce_start, nonce_start + episodes))
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
    identity = by_backend[be]["provider_identity"]
    if identity.get("complete") is not True:
        coverage_failures.append({"backend": be, "reason": "provider_identity_incomplete"})
    if identity.get("provider_family") != be:
        coverage_failures.append({"backend": be, "reason": "provider_family_mismatch"})
    if not identity.get("device_architecture"):
        coverage_failures.append({"backend": be, "reason": "provider_architecture_missing"})
    if by_backend[be]["source_revision"] in (None, "", "unknown"):
        coverage_failures.append({"backend": be, "reason": "source_revision_missing"})

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
        "CommittedRCProductionGoldenManifest may be populated only from a reviewed corpus where complete_multi_gpu_match is true.",
        "Public evidence must remain machine-class only (no hostname/SKU/path identifiers).",
    ],
    "ratification_gates": False,
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
