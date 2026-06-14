#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

usage() {
  cat <<'USAGE'
Usage: scripts/ci/run_matmul_v3_experiment_matrix.sh

Runs a repeatable MatMul v3 cost matrix for canonical and experimental parameter
sets. The script records the measurements and fails only on canonical v3 guardrail
regressions that would indicate the work has shifted away from the intended
GEMM/product-digest dominated profile.

Optional environment:
  BUILD_DIR                                      Build directory (default: build-btx)
  BTX_MATMUL_EXPERIMENT_ARTIFACT_DIR             Output directory (default: <BUILD_DIR>/matmul-v3-experiment-artifacts)
  BTX_MATMUL_EXPERIMENT_ITERATIONS               Iterations per normal case (default: 2)
  BTX_MATMUL_EXPERIMENT_FULL                     Include heavier n=1024 case when set to 1 (default: 0)
  BTX_MATMUL_MIN_CANONICAL_PRODUCT_SHARE         Minimum canonical product share (default: 0.45)
  BTX_MATMUL_MAX_CANONICAL_GATE_SHARE            Maximum canonical SHA/gate share (default: 0.02)
  BTX_MATMUL_MAX_CANONICAL_MATRIX_VS_PRODUCT     Maximum canonical matrix/product ratio (default: 1.0)
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required for MatMul experiment matrix summaries" >&2
  exit 1
fi

BUILD_DIR="${BUILD_DIR:-build-btx}"
ARTIFACT_DIR="${BTX_MATMUL_EXPERIMENT_ARTIFACT_DIR:-${BUILD_DIR}/matmul-v3-experiment-artifacts}"
ITERATIONS="${BTX_MATMUL_EXPERIMENT_ITERATIONS:-2}"
FULL="${BTX_MATMUL_EXPERIMENT_FULL:-0}"
MIN_CANONICAL_PRODUCT_SHARE="${BTX_MATMUL_MIN_CANONICAL_PRODUCT_SHARE:-0.45}"
MAX_CANONICAL_GATE_SHARE="${BTX_MATMUL_MAX_CANONICAL_GATE_SHARE:-0.02}"
MAX_CANONICAL_MATRIX_VS_PRODUCT="${BTX_MATMUL_MAX_CANONICAL_MATRIX_VS_PRODUCT:-1.0}"

BENCH="${BUILD_DIR}/bin/btx-matmul-cost-bench"
if [[ ! -x "${BENCH}" ]]; then
  echo "error: missing benchmark binary: ${BENCH}" >&2
  echo "hint: build with BUILD_UTIL=ON and target btx-matmul-cost-bench" >&2
  exit 1
fi

mkdir -p "${ARTIFACT_DIR}"
SUMMARY_NDJSON="${ARTIFACT_DIR}/summary.ndjson"
SUMMARY_JSON="${ARTIFACT_DIR}/summary.json"
: > "${SUMMARY_NDJSON}"

run_case() {
  local name="$1"
  local classification="$2"
  shift 2
  local out="${ARTIFACT_DIR}/cost-${name}.json"

  echo "MatMul experiment: ${name} (${classification})"
  "${BENCH}" "$@" | tee "${out}" >/dev/null
  jq -c --arg name "${name}" --arg classification "${classification}" \
    '{
      case: $name,
      classification: $classification,
      n: .options.n,
      b: .options.b,
      r: .options.r,
      epsilon_bits: .options.epsilon_bits,
      seed_version: .options.seed_version,
      pass_probability: .amortized_per_scanned_nonce.pre_hash_gate_pass_probability_estimate,
      gate_share: .amortized_per_scanned_nonce.gate_hash_share,
      matrix_share: .amortized_per_scanned_nonce.matrix_generation_share,
      product_share: .amortized_per_scanned_nonce.product_digest_share,
      matrix_vs_product: .ratios.matrix_generation_vs_product_digest,
      accepted_total_us: .timings.accepted_candidate_total.mean_us,
      matrix_us: .timings.matrix_generation_ab.mean_us,
      product_us: .timings.product_digest_dense.mean_us
    }' "${out}" | tee -a "${SUMMARY_NDJSON}"
}

common_v3_args=(
  --seed-version 3
  --block-height 130500
  --parent-mtp 1780000000
)

run_case canonical_mainnet_v3 accepted \
  --iterations "${ITERATIONS}" \
  --n 512 --b 16 --r 8 \
  --epsilon-bits 18 \
  "${common_v3_args[@]}"

run_case no_gate_v3 diagnostic \
  --iterations "${ITERATIONS}" \
  --n 512 --b 16 --r 8 \
  --epsilon-bits 0 \
  "${common_v3_args[@]}"

run_case small_n256_v3 deferred_cpu_bias_risk \
  --iterations "${ITERATIONS}" \
  --n 256 --b 8 --r 4 \
  --epsilon-bits 18 \
  "${common_v3_args[@]}"

run_case high_noise_r16 diagnostic \
  --iterations "${ITERATIONS}" \
  --n 512 --b 16 --r 16 \
  --epsilon-bits 18 \
  "${common_v3_args[@]}"

run_case block32_v3 deferred_digest_reduction_risk \
  --iterations "${ITERATIONS}" \
  --n 512 --b 32 --r 8 \
  --epsilon-bits 18 \
  "${common_v3_args[@]}"

if [[ "${FULL}" == "1" ]]; then
  run_case large_n1024_v3 deferred_cost_increase \
    --iterations 1 \
    --n 1024 --b 16 --r 8 \
    --epsilon-bits 18 \
    "${common_v3_args[@]}"
fi

jq -s '.' "${SUMMARY_NDJSON}" > "${SUMMARY_JSON}"

CANONICAL_JSON="${ARTIFACT_DIR}/cost-canonical_mainnet_v3.json"
jq -e \
  --argjson min_product "${MIN_CANONICAL_PRODUCT_SHARE}" \
  --argjson max_gate "${MAX_CANONICAL_GATE_SHARE}" \
  --argjson max_matrix_vs_product "${MAX_CANONICAL_MATRIX_VS_PRODUCT}" \
  '.amortized_per_scanned_nonce.product_digest_share >= $min_product and
   .amortized_per_scanned_nonce.gate_hash_share <= $max_gate and
   .ratios.matrix_generation_vs_product <= $max_matrix_vs_product' \
  "${CANONICAL_JSON}" >/dev/null

echo "MatMul v3 experiment matrix complete. Summary: ${SUMMARY_JSON}"
