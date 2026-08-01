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
# Optional: --backends cuda,metal,hip  (comma-separated; missing backends fail
# closed unless --allow-partial is set for intermediate CUDA-only drafts).
set -euo pipefail

HARNESS=""
BACKENDS="cuda"
EPISODES=8
NONCE_START=1
OUT_DIR=""
SOURCE_REVISION=""
ALLOW_PARTIAL=0
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
    -h|--help)
      sed -n '1,30p' "$0"
      exit 0
      ;;
    *) die "unknown arg: $1" ;;
  esac
done

[[ -n "${HARNESS}" && -x "${HARNESS}" ]] || die "--harness executable required"
[[ -n "${OUT_DIR}" ]] || die "--out-dir required"
mkdir -p "${OUT_DIR}/raw"

if [[ -z "${SOURCE_REVISION}" ]]; then
  SOURCE_REVISION="$(git -C "$(dirname "$0")/../.." rev-parse HEAD 2>/dev/null || echo unknown)"
fi
TIP_SHA="${SOURCE_REVISION}"

IFS=',' read -r -a BACKEND_LIST <<< "${BACKENDS}"
declare -a OK_BACKENDS=()
declare -a RAW_JSONS=()

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

[[ ${#OK_BACKENDS[@]} -ge 1 ]] || die "no backend succeeded"

MERGE_OUT="${OUT_DIR}/multi-gpu-digest-compare.json"
python3 - "${MERGE_OUT}" "${TIP_SHA}" "${NONCE_START}" "${ALLOW_PARTIAL}" "${OK_BACKENDS[@]}" -- "${RAW_JSONS[@]}" <<'PY'
import json, sys
from pathlib import Path

out_path = Path(sys.argv[1])
tip_sha = sys.argv[2]
nonce_start = int(sys.argv[3])
allow_partial = int(sys.argv[4])
sep = sys.argv.index("--")
backends = sys.argv[5:sep]
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
    }

# Compare digests on intersecting nonces.
ref = backends[0]
ref_map = {r["header_nonce"]: r["exact_replay_digest"] for r in by_backend[ref]["records"]}
mismatches = []
for be in backends[1:]:
    for r in by_backend[be]["records"]:
        n = r["header_nonce"]
        if n not in ref_map:
            mismatches.append({"nonce": n, "backend": be, "reason": "nonce_missing_in_ref"})
            continue
        if r["exact_replay_digest"] != ref_map[n]:
            mismatches.append(
                {
                    "nonce": n,
                    "backend": be,
                    "reason": "digest_mismatch",
                    "ref": ref_map[n],
                    "observed": r["exact_replay_digest"],
                }
            )

required = {"cuda", "metal", "hip"}
present = set(backends)
complete_match = (
    required.issubset(present)
    and not mismatches
    and all(by_backend[b]["n"] >= 8 for b in backends)
)

payload = {
    "evidence_kind": "multi_gpu_profile1_exactreplay_golden_compare",
    "tip_sha": tip_sha,
    "canary_nonce_start": nonce_start,
    "backends_requested": backends,
    "backends_succeeded": backends,
    "required_for_manifest": sorted(required),
    "complete_multi_gpu_match": complete_match,
    "allow_partial": bool(allow_partial),
    "mismatches": mismatches,
    "by_backend": {
        be: {
            "n": by_backend[be]["n"],
            "raw": by_backend[be]["raw"],
            "all_consensus_macs_on_device": by_backend[be]["all_consensus_macs_on_device"],
            "cpu_gemm_fallbacks": by_backend[be]["cpu_gemm_fallbacks"],
            "digests_by_nonce": {
                str(r["header_nonce"]): r["exact_replay_digest"]
                for r in by_backend[be]["records"]
            },
        }
        for be in backends
    },
    "notes": [
        "Production goldens require byte-identical ExactReplay digests across CUDA, Metal, and HIP for the same frozen canary headers.",
        "CPU ExactReplay is not an accepted independent reproduction path for Epoch-A production goldens.",
        "Do not populate CommittedRCProductionGoldenManifest until complete_multi_gpu_match is true.",
        "Public evidence must remain machine-class only (no hostname/SKU/path identifiers).",
    ],
    "ratification_gates": False,
}
out_path.write_text(json.dumps(payload, indent=2) + "\n")
print(json.dumps({"wrote": str(out_path), "complete_multi_gpu_match": complete_match, "mismatches": len(mismatches)}, indent=2))
if mismatches and not allow_partial:
    raise SystemExit("digest mismatches across backends")
if not complete_match and not allow_partial:
    raise SystemExit("incomplete multi-GPU set (need cuda+metal+hip with matching digests)")
PY

# Sanitized README stub (no host paths)
cat > "${OUT_DIR}/README.md" <<EOF
# Multi-GPU Profile-1 ExactReplay golden compare

Status: draft corpus runner output. Ratification gates remain false.
Public Epoch-A heights remain disabled until CUDA+Metal+HIP digests match
and are committed to \`CommittedRCProductionGoldenManifest()\`.

## Policy

Independent reproduction for Epoch-A production goldens is **cross-GPU-backend**
(CUDA, Metal, HIP) ExactReplay on identical frozen canary headers. Portable CPU
oracle reproduction is not required for this GPU-optimized chain.

## Artifact

See \`multi-gpu-digest-compare.json\`.
EOF

echo "multi-gpu-golden-corpus: wrote ${OUT_DIR}"
