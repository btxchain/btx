#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

target="${1:-}"

if [[ -z "${target}" ]]; then
  echo "usage: scripts/ci/run_ci_target.sh <target>" >&2
  echo "targets: lint tidy ctest fuzz functional-matmul sanitizer-smoke launch-blockers production-readiness platform-*" >&2
  exit 1
fi

nproc_detect() {
  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN
    return
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
    return
  fi
  echo 4
}

have_core_binaries() {
  local build_dir="$1"
  [[ -x "${build_dir}/bin/btxd" && -x "${build_dir}/bin/btx-cli" ]] || \
  [[ -x "${build_dir}/bin/btxd" && -x "${build_dir}/bin/btx-cli" ]]
}

tmp_root_dir() {
  printf '%s\n' "${TMPDIR:-/tmp}"
}

tmp_free_kb() {
  local tmp_root
  tmp_root="$(tmp_root_dir)"
  df -Pk "${tmp_root}" | awk 'NR==2 {print $4}'
}

cleanup_stale_ci_roots() {
  local tmp_root
  tmp_root="$(tmp_root_dir)"
  if [[ ! -d "${tmp_root}" ]]; then
    return
  fi
  while IFS= read -r -d '' stale_dir; do
    rm -rf "${stale_dir}" || true
  done < <(find "${tmp_root}" -maxdepth 1 -type d -name 'btx-ci-root-*' -mmin +120 -print0 2>/dev/null)
}

ensure_platform_tmp_space() {
  local min_gb="${CI_TMP_MIN_FREE_GB:-15}"
  local min_kb=$((min_gb * 1024 * 1024))
  local free_kb
  free_kb="$(tmp_free_kb)"
  if [[ ! "${free_kb}" =~ ^[0-9]+$ ]]; then
    echo "warning: unable to determine free space in $(tmp_root_dir)" >&2
    return
  fi

  if (( free_kb < min_kb )); then
    echo "warning: low free space in $(tmp_root_dir): ${free_kb}KB < ${min_kb}KB, pruning stale CI roots and docker cache" >&2
    cleanup_stale_ci_roots
    if command -v docker >/dev/null 2>&1; then
      docker buildx prune --force --filter "until=24h" >/dev/null 2>&1 || true
      docker image prune --force >/dev/null 2>&1 || true
    fi
    free_kb="$(tmp_free_kb)"
  fi

  if [[ ! "${free_kb}" =~ ^[0-9]+$ ]] || (( free_kb < min_kb )); then
    echo "error: insufficient free space in $(tmp_root_dir): ${free_kb}KB available, ${min_kb}KB required for platform target '${target}'" >&2
    echo "hint: free host disk space or reduce CI_TMP_MIN_FREE_GB for constrained local runs" >&2
    exit 1
  fi
}

ensure_core_build() {
  local build_dir="${1:-build-btx}"
  if have_core_binaries "${build_dir}"; then
    return
  fi
  scripts/build_btx.sh "${build_dir}" -DWERROR=ON -DWITH_ZMQ=ON
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required for this platform target" >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "error: docker daemon is not reachable" >&2
    exit 1
  fi
}

ensure_macos_ci_host_deps() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    return
  fi
  if ! command -v brew >/dev/null 2>&1; then
    echo "error: brew is required for macOS host CI targets" >&2
    exit 1
  fi

  local required_pkgs=(
    coreutils
    ninja
    pkgconf
    gnu-getopt
    ccache
    boost
    libevent
    miniupnpc
    zeromq
    qt@5
    qrencode
    imagemagick
    libicns
    librsvg
  )
  local missing_pkgs=()
  local pkg=""
  for pkg in "${required_pkgs[@]}"; do
    if ! brew list --versions "${pkg}" >/dev/null 2>&1; then
      missing_pkgs+=("${pkg}")
    fi
  done

  if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
    HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew install --quiet "${missing_pkgs[@]}"
  fi

  if ! brew list --versions python@3 >/dev/null 2>&1; then
    HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew install --quiet python@3 || brew link --overwrite python@3
  fi
}

run_platform_ci_env() {
  local file_env="$1"
  local run_on_host="${2:-false}"
  local ci_suffix=""
  local should_cleanup_root="false"
  local rc=0

  if [[ ! -f "${file_env}" ]]; then
    echo "error: missing CI env file '${file_env}'" >&2
    exit 1
  fi

  export FILE_ENV="${file_env}"

  if [[ "${run_on_host}" == "true" ]]; then
    export BASE_ROOT_DIR="${ROOT_DIR}"
    ensure_macos_ci_host_deps
    export DANGER_RUN_CI_ON_HOST=1
    unset DANGER_CI_ON_HOST_FOLDERS
    if [[ -z "${MAKEJOBS:-}" ]]; then
      # Cap host parallelism for mac-native lanes to reduce runner OOM kills.
      local host_jobs
      host_jobs="$(nproc_detect)"
      if (( host_jobs > 4 )); then
        host_jobs=4
      fi
      export MAKEJOBS="-j${host_jobs}"
    fi
  else
    ensure_docker
    cleanup_stale_ci_roots
    ensure_platform_tmp_space
    unset DANGER_RUN_CI_ON_HOST
    export DANGER_CI_ON_HOST_FOLDERS=1
    ci_suffix="${target}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
    ci_suffix="$(printf '%s' "${ci_suffix}" | tr -cd 'A-Za-z0-9_.-')"
    export BASE_ROOT_DIR="${TMPDIR:-/tmp}/btx-ci-root-${ci_suffix}"
    rm -rf "${BASE_ROOT_DIR}"
    mkdir -p "${BASE_ROOT_DIR}"
    if [[ -z "${BTX_CI_KEEP_BASE_ROOT_DIR:-}" ]]; then
      should_cleanup_root="true"
    fi
  fi

  if ./ci/test_run_all.sh; then
    rc=0
  else
    rc=$?
  fi

  if [[ "${should_cleanup_root}" == "true" ]]; then
    rm -rf "${BASE_ROOT_DIR}" || true
  fi

  return "${rc}"
}

run_lint() {
  local venv_dir="${ROOT_DIR}/.ci-lint-venv311"
  local deps_marker="${venv_dir}/.deps-version"
  local deps_version="codespell-2.2.6_lief-0.13.2_mypy-1.4.1_pyzmq-25.1.0_ruff-0.5.5_vulture-2.6"

  if ! command -v python3.11 >/dev/null 2>&1; then
    echo "error: python3.11 is required for lint target" >&2
    exit 1
  fi

  if [[ ! -x "${venv_dir}/bin/python3" || ! -f "${deps_marker}" || "$(cat "${deps_marker}")" != "${deps_version}" ]]; then
    rm -rf "${venv_dir}"
    python3.11 -m venv "${venv_dir}"
    "${venv_dir}/bin/pip" install --upgrade pip
    "${venv_dir}/bin/pip" install \
      codespell==2.2.6 \
      lief==0.13.2 \
      mypy==1.4.1 \
      pyzmq==25.1.0 \
      ruff==0.5.5 \
      vulture==2.6
    printf '%s\n' "${deps_version}" > "${deps_marker}"
  fi

  export PATH="${venv_dir}/bin:${PATH}"
  python3 test/lint/lint-files.py
  python3 test/lint/lint-includes.py
  python3 test/lint/lint-include-guards.py
  python3 test/lint/lint-circular-dependencies.py
  python3 test/lint/lint-locale-dependence.py
  python3 test/lint/lint-shell-locale.py
  python3 test/lint/lint-submodule.py
  python3 test/lint/lint-python.py
  python3 test/lint/lint-python-dead-code.py
  python3 test/lint/lint-python-utf8-encoding.py
  python3 test/lint/lint-tests.py
  python3 test/lint/lint-op-success-p2tr.py
  python3 test/lint/lint-shell.py
  python3 test/lint/lint-ci-base-install.py
  python3 test/lint/lint-spelling.py
}

run_tidy() {
  local llvm_prefix=""
  if command -v brew >/dev/null 2>&1; then
    llvm_prefix="$(brew --prefix llvm)"
  elif command -v llvm-config >/dev/null 2>&1; then
    llvm_prefix="$(llvm-config --prefix)"
  fi

  if [[ -z "${llvm_prefix}" || ! -d "${llvm_prefix}/lib/cmake/llvm" ]]; then
    local candidate
    for candidate in /usr/lib/llvm-20 /usr/lib/llvm-19 /usr/lib/llvm-18 /usr/lib/llvm-17 /usr/local/opt/llvm; do
      if [[ -d "${candidate}/lib/cmake/llvm" ]]; then
        llvm_prefix="${candidate}"
        break
      fi
    done
  fi

  if [[ -z "${llvm_prefix}" || ! -d "${llvm_prefix}/lib/cmake/llvm" ]]; then
    echo "error: LLVM CMake config not found; expected <prefix>/lib/cmake/llvm" >&2
    exit 1
  fi

  local tidy_check_header="${llvm_prefix}/include/clang-tidy/ClangTidyCheck.h"
  if [[ ! -f "${tidy_check_header}" ]]; then
    echo "warning: clang-tidy plugin headers not found at ${tidy_check_header}; running tidy smoke path" >&2
    if command -v clang-tidy >/dev/null 2>&1; then
      clang-tidy --version
      return
    fi
    if command -v clang-tidy-18 >/dev/null 2>&1; then
      clang-tidy-18 --version
      return
    fi
    echo "error: no clang-tidy binary found for tidy smoke path" >&2
    exit 1
  fi

  export PATH="${llvm_prefix}/bin:${PATH}"
  cmake -S contrib/devtools/bitcoin-tidy -B build-btx-tidy -G Ninja -DLLVM_DIR="${llvm_prefix}/lib/cmake/llvm"
  # Build the plugin first to avoid racey load-path resolution on macOS.
  cmake --build build-btx-tidy --target bitcoin-tidy -j"$(nproc_detect)"
  cmake --build build-btx-tidy --target bitcoin-tidy-tests -j"$(nproc_detect)"
}

run_ctest() {
  ensure_core_build "build-btx"
  ctest --test-dir build-btx -j"$(nproc_detect)" --output-on-failure -R "^(pow_tests|matmul_.*|pq_.*|shielded_.*)$"
}

run_fuzz() {
  local build_dir="build-fuzz-ci"
  local corpus_dir=".ci-fuzz-corpus"
  local seed_url="https://raw.githubusercontent.com/bitcoin-core/qa-assets/master/fuzz_corpora/p2p_headers_presync/00023f09dc69205f114e1015b894621f04c813d4"
  local max_total_time="${FUZZ_MAX_TOTAL_TIME:-60}"
  local per_input_timeout="${FUZZ_TIMEOUT:-10}"
  mkdir -p "${corpus_dir}/p2p_headers_presync"
  curl -fsSL "${seed_url}" -o "${corpus_dir}/p2p_headers_presync/00023f09dc69205f114e1015b894621f04c813d4"
  cmake -S . -B "${build_dir}" -G Ninja \
    -DBUILD_FOR_FUZZING=ON \
    -DBUILD_FUZZ_BINARY=ON \
    -DBUILD_GUI=OFF \
    -DBUILD_TESTS=OFF \
    -DWITH_ZMQ=ON \
    -DWERROR=ON
  cmake --build "${build_dir}" -j"$(nproc_detect)" --target fuzz
  local links_without_main
  links_without_main="$(
    grep -E '^FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION:INTERNAL=' "${build_dir}/CMakeCache.txt" 2>/dev/null | head -n 1 | cut -d= -f2-
  )"

  if [[ -n "${links_without_main}" ]]; then
    # LibFuzzer mode: default execution is unbounded; add a time limit so CI can finish.
    FUZZ=p2p_headers_presync "${build_dir}/bin/fuzz" \
      -max_total_time="${max_total_time}" \
      -timeout="${per_input_timeout}" \
      "${corpus_dir}/p2p_headers_presync"
  else
    # File-mode fallback (no libFuzzer driver linked): run the target against the
    # corpus once. This path does not understand libFuzzer flags.
    FUZZ=p2p_headers_presync "${build_dir}/bin/fuzz" "${corpus_dir}/p2p_headers_presync"
  fi
}

run_functional_matmul() {
  ensure_core_build "build-btx"
  scripts/matmul_pow_readiness.sh
}

run_sanitizer_smoke() {
  local build_dir="build-btx-asan-ci"
  cmake -S . -B "${build_dir}" -G Ninja \
    -DWERROR=ON \
    -DWITH_ZMQ=ON \
    -DSANITIZERS=address,undefined
  cmake --build "${build_dir}" -j"$(nproc_detect)" --target test_btx
  "${build_dir}/bin/test_btx" --run_test=pow_tests,matmul_*
}

run_launch_blockers() {
  ensure_core_build "build-btx"
  scripts/matmul_pow_readiness.sh
}

run_production_readiness() {
  if ! have_core_binaries "build-btx" || [[ ! -x "build-btx/bin/bench_btx" ]]; then
    scripts/build_btx.sh "build-btx" -DWERROR=ON -DWITH_ZMQ=ON -DBUILD_BENCH=ON
  fi
  build-btx/bin/bench_btx -min-time=5 -filter="^(bench_mldsa_verify|bench_slhdsa_verify)$"
  scripts/matmul_pow_readiness.sh
  scripts/matmul_pow_benchmark.sh
}

run_platform_macos_native() {
  run_platform_ci_env "./ci/test/00_setup_env_mac_native.sh" "true"
}

run_platform_macos_native_fuzz() {
  run_platform_ci_env "./ci/test/00_setup_env_mac_native_fuzz.sh" "true"
}

run_platform_arm32() {
  run_platform_ci_env "./ci/test/00_setup_env_arm.sh"
}

run_platform_win64_cross() {
  run_platform_ci_env "./ci/test/00_setup_env_win64.sh"
}

run_platform_asan() {
  run_platform_ci_env "./ci/test/00_setup_env_native_asan.sh"
}

run_platform_macos_cross() {
  run_platform_ci_env "./ci/test/00_setup_env_mac_cross.sh"
}

run_platform_nowallet_libkernel() {
  run_platform_ci_env "./ci/test/00_setup_env_native_nowallet_libbitcoinkernel.sh"
}

run_platform_i686_multiprocess() {
  run_platform_ci_env "./ci/test/00_setup_env_i686_multiprocess.sh"
}

run_platform_native_fuzz() {
  run_platform_ci_env "./ci/test/00_setup_env_native_fuzz.sh"
}

run_platform_previous_releases() {
  run_platform_ci_env "./ci/test/00_setup_env_native_previous_releases.sh"
}

run_platform_native_centos() {
  run_platform_ci_env "./ci/test/00_setup_env_native_centos.sh"
}

run_platform_native_tidy() {
  run_platform_ci_env "./ci/test/00_setup_env_native_tidy.sh"
}

run_platform_native_tsan() {
  run_platform_ci_env "./ci/test/00_setup_env_native_tsan.sh"
}

run_platform_native_msan() {
  run_platform_ci_env "./ci/test/00_setup_env_native_msan.sh"
}

case "${target}" in
  lint)
    run_lint
    ;;
  tidy)
    run_tidy
    ;;
  ctest)
    run_ctest
    ;;
  fuzz)
    run_fuzz
    ;;
  functional-matmul)
    run_functional_matmul
    ;;
  sanitizer-smoke)
    run_sanitizer_smoke
    ;;
  launch-blockers)
    run_launch_blockers
    ;;
  production-readiness)
    run_production_readiness
    ;;
  platform-macos-native)
    run_platform_macos_native
    ;;
  platform-macos-native-fuzz)
    run_platform_macos_native_fuzz
    ;;
  platform-arm32)
    run_platform_arm32
    ;;
  platform-win64-cross)
    run_platform_win64_cross
    ;;
  platform-asan)
    run_platform_asan
    ;;
  platform-macos-cross)
    run_platform_macos_cross
    ;;
  platform-nowallet-libkernel)
    run_platform_nowallet_libkernel
    ;;
  platform-i686-multiprocess)
    run_platform_i686_multiprocess
    ;;
  platform-native-fuzz)
    run_platform_native_fuzz
    ;;
  platform-previous-releases)
    run_platform_previous_releases
    ;;
  platform-native-centos)
    run_platform_native_centos
    ;;
  platform-native-tidy)
    run_platform_native_tidy
    ;;
  platform-native-tsan)
    run_platform_native_tsan
    ;;
  platform-native-msan)
    run_platform_native_msan
    ;;
  *)
    echo "error: unknown target '${target}'" >&2
    exit 1
    ;;
esac
