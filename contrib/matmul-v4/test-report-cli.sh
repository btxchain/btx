#!/usr/bin/env bash
# Focused argument-validation checks for matmul-v4-report. The optional first
# argument is the built binary; otherwise use the ordinary in-tree build.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${1:-$ROOT/build/bin/matmul-v4-report}"
if [ ! -x "$BIN" ]; then
  echo "matmul-v4-report binary is not executable: $BIN" >&2
  exit 2
fi

clean_env=(env -u BTX_MATMUL_V4_REPORT_N -u BTX_MATMUL_V4_REPORT_WINDOW)

expect_rejected()
{
  local expected="$1"
  shift
  local output
  local code
  set +e
  output="$("${clean_env[@]}" "$BIN" "$@" 2>&1)"
  code=$?
  set -e
  if [ "$code" -ne 2 ] || ! grep -Fq "$expected" <<<"$output"; then
    echo "expected parser rejection containing '$expected': $*" >&2
    echo "exit=$code output=$output" >&2
    exit 1
  fi
}

# A fully consumed positive integer and finite, non-negative decimal are valid.
"${clean_env[@]}" "$BIN" --n 1 --window 1 --rounds 1 \
  --device-peak-int8-tops 0 --v3-hashrate 0.5 --help >/dev/null

expect_rejected "unknown --backend: typo" --backend typo
for backend in cpu cuda nvidia metal mlx apple hip rocm amd ascend huawei npu; do
  "${clean_env[@]}" "$BIN" --backend "$backend" --help >/dev/null
done

for value in 0 -1 +1 1x ' 1' 4294967296 18446744073709551616; do
  expect_rejected "invalid positive integer for --n" --n "$value"
done
for option in --window --rounds; do
  expect_rejected "invalid positive integer for $option" "$option" 0
  expect_rejected "invalid positive integer for $option" "$option" 12tail
done
for option in --device-peak-int8-tops --v3-hashrate; do
  expect_rejected "invalid non-negative finite number for $option" "$option" -1
  expect_rejected "invalid non-negative finite number for $option" "$option" +1
  expect_rejected "invalid non-negative finite number for $option" "$option" nan
  expect_rejected "invalid non-negative finite number for $option" "$option" inf
  expect_rejected "invalid non-negative finite number for $option" "$option" 0x1p2
  expect_rejected "invalid non-negative finite number for $option" "$option" 1tail
  expect_rejected "invalid non-negative finite number for $option" "$option" 1e9999
done

expect_env_rejected()
{
  local name="$1"
  local value="$2"
  local output
  local code
  set +e
  output="$(env -u BTX_MATMUL_V4_REPORT_N -u BTX_MATMUL_V4_REPORT_WINDOW \
    "$name=$value" "$BIN" 2>&1)"
  code=$?
  set -e
  if [ "$code" -ne 2 ] || ! grep -Fq "invalid positive integer for $name" <<<"$output"; then
    echo "expected environment parser rejection for $name=$value" >&2
    echo "exit=$code output=$output" >&2
    exit 1
  fi
}

expect_env_rejected BTX_MATMUL_V4_REPORT_N -1
expect_env_rejected BTX_MATMUL_V4_REPORT_N 0
expect_env_rejected BTX_MATMUL_V4_REPORT_N 4294967296
expect_env_rejected BTX_MATMUL_V4_REPORT_WINDOW 256tail
expect_env_rejected BTX_MATMUL_V4_REPORT_WINDOW ' 256'

# Explicit CLI values take precedence over stale environment overrides. Use a
# deliberate post-parse profile/mode error so --help cannot exit before the
# environment-precedence code is exercised.
expect_cli_overrides_env()
{
  local name="$1"
  shift
  local output
  local code
  set +e
  output="$(env -u BTX_MATMUL_V4_REPORT_N -u BTX_MATMUL_V4_REPORT_WINDOW \
    "$name=invalid" "$BIN" "$@" --telemetry-only --profile v41 2>&1)"
  code=$?
  set -e
  if [ "$code" -ne 2 ] ||
     ! grep -Fq "LT raw/telemetry mode requires --profile bmx4c-lt" <<<"$output" ||
     grep -Fq "invalid positive integer for $name" <<<"$output"; then
    echo "explicit CLI value did not override $name" >&2
    echo "exit=$code output=$output" >&2
    exit 1
  fi
}

expect_cli_overrides_env BTX_MATMUL_V4_REPORT_N --n 64
expect_cli_overrides_env BTX_MATMUL_V4_REPORT_WINDOW --window 128

echo "matmul-v4-report CLI validation: PASS"
