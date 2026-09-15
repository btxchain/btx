#!/usr/bin/env bash
# NVIDIA workstation governor E2E. Read-only nvidia-smi if the driver answers.
# Never CUDA goldens, never production btxd, never mining on the live GPU.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}"
[[ -x "$TEST" ]] || { echo "missing $TEST" >&2; exit 1; }

if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
  echo "== read-only nvidia-smi (no kernels) =="
  nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits
else
  echo "nvidia-smi not talking to the driver; NVIDIA policy path still executes via injected type=NVIDIA samples"
fi

"$TEST" --run_test=resource_governor_tests/gov_e2e_nvidia_workstation
"$TEST" --run_test=resource_governor_tests/gov_pol_01_idle_gpu_permits_mining
"$TEST" --run_test=resource_governor_tests/gov_pol_02_foreground_gpu_blocks_mining
"$TEST" --run_test=resource_governor_tests/gov_mine_04_validation_signal_pauses
echo "GOV-NVIDIA-E2E PASS"
