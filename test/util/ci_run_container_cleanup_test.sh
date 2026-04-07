#!/usr/bin/env bash
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/ci/test/02_run_container.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-ci-container-cleanup-test.XX""XX""XX")"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

DOCKER_BIN_DIR="${TMP_DIR}/bin"
DOCKER_LOG="${TMP_DIR}/docker.log"
mkdir -p "${DOCKER_BIN_DIR}"

cat > "${DOCKER_BIN_DIR}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

log="${DOCKER_LOG:?missing DOCKER_LOG}"
printf '%s\n' "$*" >> "${log}"

case "${1:-}" in
  buildx|volume|network|image)
    exit 0
    ;;
  run)
    printf 'fakecid123\n'
    exit 0
    ;;
  exec)
    # Force an early failure path so trap-based cleanup must run.
    exit 1
    ;;
  container)
    if [ "${2:-}" = "kill" ]; then
      printf 'container-kill %s\n' "${3:-}" >> "${log}"
      exit 0
    fi
    ;;
esac

exit 0
EOF
chmod +x "${DOCKER_BIN_DIR}/docker"

export FILE_ENV="./ci/test/00_setup_env_native_tidy.sh"
export CONTAINER_NAME="ci-cleanup-test-$$"
export BASE_READ_ONLY_DIR="${ROOT_DIR}"
export BASE_ROOT_DIR="${TMP_DIR}/root"
export BASE_SCRATCH_DIR="${BASE_ROOT_DIR}/ci/scratch"
export BINS_SCRATCH_DIR="${BASE_SCRATCH_DIR}/bins"
export DEPENDS_DIR="${BASE_ROOT_DIR}/depends"
export CCACHE_DIR="${BASE_SCRATCH_DIR}/ccache"
export PREVIOUS_RELEASES_DIR="${BASE_ROOT_DIR}/prev_releases"
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export CI_IMAGE_PLATFORM="linux"
export CI_CONTAINER_CAP=""
export DOCKER_BUILD_CACHE_ARG=""
export DANGER_CI_ON_HOST_FOLDERS=1
export DANGER_CI_ON_HOST_CCACHE_FOLDER=""
export HAVE_CGROUP_CPUSET=""
export MAKEJOBS="-j2"
export CI_OS_NAME="linux"
export DOCKER_LOG
unset DANGER_RUN_CI_ON_HOST
unset RESTART_CI_DOCKER_BEFORE_RUN

env_prefix="/tmp/env-${USER}-${CONTAINER_NAME}-"
rm -f "${env_prefix}"* 2>/dev/null || true

set +e
PATH="${DOCKER_BIN_DIR}:$PATH" "${SCRIPT}" >"${TMP_DIR}/stdout.log" 2>"${TMP_DIR}/stderr.log"
rc=$?
set -e

if (( rc == 0 )); then
  echo "error: expected ${SCRIPT} to fail after mocked docker exec failure" >&2
  cat "${TMP_DIR}/stdout.log" >&2
  cat "${TMP_DIR}/stderr.log" >&2
  exit 1
fi

rg -q '^container-kill fakecid123$' "${DOCKER_LOG}"

if compgen -G "${env_prefix}*" > /dev/null; then
  echo "error: expected CI env files to be removed by trap cleanup" >&2
  ls -1 "${env_prefix}"* >&2
  exit 1
fi

echo "ci_run_container_cleanup_test: PASS"
